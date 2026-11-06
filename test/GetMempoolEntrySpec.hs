{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | getmempoolentry: chunkweight, fees.chunk, depends, spentby, weight.
--
-- Core (rpc/mempool.cpp entryToJSON, shared by getmempoolentry and
-- getrawmempool verbose=true) reports the entry's in-pool parents
-- (@depends@) and children (@spentby@), its chunk (@chunkweight@,
-- @fees.chunk@) and the transaction's real weight (GetTxWeight).  haskoin's
-- getmempoolentry hard-coded @spentby@ to [] and omitted the chunk fields.
--
-- TEETH: on the unfixed tree the parent's spentby is empty and the chunk
-- keys are absent, so these assertions fail.
module GetMempoolEntrySpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically, writeTVar)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))
import Data.Word (Word32, Word64)

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-rawmempool-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg liveNoopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
        action RpcServer
              { rsConfig = cfg, rsDB = db, rsHeaderChain = hc, rsPeerMgr = pm
              , rsMempool = mp, rsFeeEst = fe, rsUTXOCache = cache
              , rsNetwork = regtest, rsBlockStore = Nothing
              , rsThread = threadVar, rsMockTime = mockTimeVar
              , rsWalletMgr = Nothing, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }

mkTx :: Word32 -> [OutPoint] -> Tx
mkTx salt ins = Tx
  { txVersion = 2
  , txInputs  = [ TxIn op BS.empty 0xfffffffd | op <- ins' ]
  , txOutputs = [ TxOut 1_000 BS.empty, TxOut 2_000 BS.empty ]
  , txWitness = []
  , txLockTime = salt
  }
  where ins' | null ins  = [OutPoint (TxId (Hash256 (BS.replicate 32 0xee))) salt]
             | otherwise = ins

-- | adjusted weight, fee (sats)
mkEntry :: Tx -> Int -> Word64 -> MempoolEntry
mkEntry tx w fee = MempoolEntry
  { meTransaction = tx, meTxId = computeTxId tx
  , meWtxid = Wtxid (getTxIdHash (computeTxId tx))
  , meFee = fee, meFeeRate = FeeRate 0, meSize = (w + 3) `div` 4, meAdjWeight = w
  , meTime = 0, meHeight = 0
  , meAncestorCount = 1, meAncestorSize = 0, meAncestorFees = 0, meAncestorSigOps = 0
  , meDescendantCount = 1, meDescendantSize = 0, meDescendantFees = 0
  , meRBFOptIn = True }

load :: RpcServer -> [MempoolEntry] -> IO ()
load server es = atomically $ do
  writeTVar (mpEntries (rsMempool server)) (Map.fromList [ (meTxId e, e) | e <- es ])
  writeTVar (mpByOutpoint (rsMempool server))
    (Map.fromList [ (txInPrevOutput i, meTxId e)
                  | e <- es, i <- txInputs (meTransaction e) ])

hex :: TxId -> T.Text
hex (TxId (Hash256 bs)) = T.pack (concatMap byte (reverse (BS.unpack bs)))
  where byte b = [d (b `div` 16), d (b `mod` 16)]
        d n = "0123456789abcdef" !! fromIntegral n

-- | getmempoolentry result object for one txid
entryRpc :: RpcServer -> TxId -> IO (KM.KeyMap A.Value)
entryRpc server t = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getmempoolentry")
        , ("params", A.Array (V.fromList [A.String (hex t)])) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o | Just (A.Object r) <- KM.lookup "result" o -> return r
    other -> fail ("unexpected getmempoolentry response: " ++ show other)

key :: KM.KeyMap A.Value -> T.Text -> IO A.Value
key e k = maybe (fail ("missing key " ++ T.unpack k)) return (KM.lookup (Key.fromText k) e)

feesChunk :: KM.KeyMap A.Value -> IO A.Value
feesChunk e = do
  f <- key e "fees"
  case f of
    A.Object o -> key o "chunk"
    _ -> fail "fees is not an object"

spec :: Spec
spec = describe "getmempoolentry (chunk fields, depends, spentby, weight)" $ do
  let parent = mkTx 1 []
      child  = mkTx 2 [OutPoint (computeTxId parent) 0]
      loner  = mkTx 3 []
      pid = computeTxId parent
      cid = computeTxId child
      lid = computeTxId loner
      pool = [ mkEntry parent 400 100, mkEntry child 400 100_000
             , mkEntry loner 340 1_000 ]

  it "spentby lists in-pool children, depends in-pool parents" $
    withServer $ \server -> do
      load server pool
      p <- entryRpc server pid
      c <- entryRpc server cid
      l <- entryRpc server lid
      key p "spentby" >>= (`shouldBe` A.toJSON [hex cid])
      key p "depends" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))
      key c "depends" >>= (`shouldBe` A.toJSON [hex pid])
      key c "spentby" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))
      key l "depends" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))
      key l "spentby" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))

  it "CPFP package shares one chunk; loner has its own" $
    withServer $ \server -> do
      load server pool
      p <- entryRpc server pid
      c <- entryRpc server cid
      l <- entryRpc server lid
      key p "chunkweight" >>= (`shouldBe` A.Number 800)
      key c "chunkweight" >>= (`shouldBe` A.Number 800)
      feesChunk p >>= (`shouldBe` A.Number 0.001001)
      feesChunk c >>= (`shouldBe` A.Number 0.001001)
      key l "chunkweight" >>= (`shouldBe` A.Number 340)
      feesChunk l >>= (`shouldBe` A.Number 0.00001)

  it "weight is the transaction's real weight (GetTxWeight), not vsize*4" $
    withServer $ \server -> do
      -- 1 input, 2 empty-script outputs, non-witness: 69 bytes = 276 WU,
      -- while the fixture's vsize (from the 400 WU adjusted weight) is 100.
      load server pool
      p <- entryRpc server pid
      key p "weight" >>= (`shouldBe` A.Number 276)
      key p "vsize" >>= (`shouldBe` A.Number 100)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | getrawmempool verbose=true: chunkweight, fees.chunk, depends, spentby.
--
-- Core (rpc/mempool.cpp entryToJSON, bitcoin-core v31.1) emits for every
-- entry @chunkweight@ (sigop-adjusted weight of the entry's chunk),
-- @fees.chunk@ (fee of that chunk), @depends@ (in-pool parents) and
-- @spentby@ (in-pool children).  haskoin omitted both chunk fields and
-- hard-coded @depends@ / @spentby@ to [] in getrawmempool.
--
-- TEETH: on the unfixed tree the chunk keys are absent and the parent's
-- spentby / child's depends are empty, so every assertion below fails.
module GetRawMempoolVerboseSpec (spec) where

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

-- | getrawmempool verbose=true result object
verbose :: RpcServer -> IO (KM.KeyMap A.Value)
verbose server = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getrawmempool")
        , ("params", A.Array (V.fromList [A.Bool True])) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o | Just (A.Object r) <- KM.lookup "result" o -> return r
    other -> fail ("unexpected getrawmempool response: " ++ show other)

entryOf :: KM.KeyMap A.Value -> TxId -> IO (KM.KeyMap A.Value)
entryOf r t = case KM.lookup (Key.fromText (hex t)) r of
  Just (A.Object e) -> return e
  _ -> fail "tx not in result"

key :: KM.KeyMap A.Value -> T.Text -> IO A.Value
key e k = maybe (fail ("missing key " ++ T.unpack k)) return (KM.lookup (Key.fromText k) e)

feesChunk :: KM.KeyMap A.Value -> IO A.Value
feesChunk e = do
  f <- key e "fees"
  case f of
    A.Object o -> key o "chunk"
    _ -> fail "fees is not an object"

spec :: Spec
spec = describe "getrawmempool verbose (chunk fields, depends, spentby)" $ do
  let parent = mkTx 1 []
      child  = mkTx 2 [OutPoint (computeTxId parent) 0]
      loner  = mkTx 3 []
      pid = computeTxId parent
      cid = computeTxId child
      lid = computeTxId loner

  it "CPFP package: parent+child share one chunk; loner has its own" $
    withServer $ \server -> do
      -- parent 100 sat / 400 WU, child 100000 sat / 400 WU: the child pays
      -- for the parent, so linearization chunks them together (800 WU, 100100 sat).
      load server [ mkEntry parent 400 100, mkEntry child 400 100_000
                  , mkEntry loner 340 1_000 ]
      r <- verbose server
      p <- entryOf r pid
      c <- entryOf r cid
      l <- entryOf r lid
      key p "chunkweight" >>= (`shouldBe` A.Number 800)
      key c "chunkweight" >>= (`shouldBe` A.Number 800)
      feesChunk p >>= (`shouldBe` A.Number 0.001001)
      feesChunk c >>= (`shouldBe` A.Number 0.001001)
      key l "chunkweight" >>= (`shouldBe` A.Number 340)
      feesChunk l >>= (`shouldBe` A.Number 0.00001)

  it "depends lists in-pool parents and spentby in-pool children" $
    withServer $ \server -> do
      load server [ mkEntry parent 400 100, mkEntry child 400 100_000
                  , mkEntry loner 340 1_000 ]
      r <- verbose server
      p <- entryOf r pid
      c <- entryOf r cid
      l <- entryOf r lid
      key p "spentby" >>= (`shouldBe` A.toJSON [hex cid])
      key p "depends" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))
      key c "depends" >>= (`shouldBe` A.toJSON [hex pid])
      key c "spentby" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))
      key l "depends" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))
      key l "spentby" >>= (`shouldBe` A.toJSON ([] :: [T.Text]))

  it "control: a high-fee parent and low-fee child stay in separate chunks" $
    withServer $ \server -> do
      load server [ mkEntry parent 400 100_000, mkEntry child 400 100 ]
      r <- verbose server
      p <- entryOf r pid
      c <- entryOf r cid
      key p "chunkweight" >>= (`shouldBe` A.Number 400)
      key c "chunkweight" >>= (`shouldBe` A.Number 400)
      feesChunk p >>= (`shouldBe` A.Number 0.001)
      feesChunk c >>= (`shouldBe` A.Number 0.000001)

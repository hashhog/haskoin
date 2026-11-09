{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | getmempoolentry / getrawmempool verbose: the order of @spentby@.
--
-- Core (rpc/mempool.cpp entryToJSON) builds @spentby@ from
-- CTxMemPool::GetChildren (txmempool.cpp), which sorts the children with
-- CompareIteratorByHash: uint256 operator<, a memcmp of the txid's internal
-- bytes.  Displayed as hex that is the order of the LAST byte first, not the
-- alphabetical order of the hex text.  @depends@ is different: Core collects
-- it in a std::set<std::string> of hex, so it IS alphabetical by hex.
--
-- haskoin sorted @spentby@ by its hex text, so a parent with many children
-- (the core-regtest warden_e scenario: 64 children) listed them in another
-- order than Core.
--
-- TEETH: on the unfixed tree the parent's spentby is in hex order, which
-- the fixture checks differs from the internal-byte order, so the spentby
-- assertions fail; the depends assertion passes before and after.
module SpentbyOrderSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically, writeTVar)
import Data.IORef (newIORef)
import Data.List (sort, sortOn)
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

-- | Core's GetChildren order: memcmp of the internal txid bytes.
coreOrder :: [TxId] -> [T.Text]
coreOrder = map hex . sortOn (\(TxId (Hash256 bs)) -> bs)

childCount :: Int
childCount = 16

spec :: Spec
spec = describe "spentby order (Core GetChildren: CompareIteratorByHash)" $ do
  let parent   = mkTx 1 childCount []
      pid      = computeTxId parent
      children = [ mkTx (100 + fromIntegral i) 1 [OutPoint pid (fromIntegral i)]
                 | i <- [0 .. childCount - 1] ]
      cids     = map computeTxId children
      -- one transaction spending every child: many in-pool parents
      joiner   = mkTx 2 1 [ OutPoint c 0 | c <- cids ]
      jid      = computeTxId joiner
      pool     = mkEntry parent 400 1_000
               : mkEntry joiner 400 1_000
               : [ mkEntry c 400 (1_000 * fromIntegral i)
                 | (i, c) <- zip [1 :: Int ..] children ]

  it "the fixture separates the two orders (else the test proves nothing)" $
    coreOrder cids `shouldNotBe` sort (map hex cids)

  it "getmempoolentry spentby is in Core's internal-byte txid order" $
    withServer $ \server -> do
      load server pool
      p <- entryRpc server pid
      key p "spentby" >>= (`shouldBe` A.toJSON (coreOrder cids))

  it "getrawmempool verbose spentby is in Core's internal-byte txid order" $
    withServer $ \server -> do
      load server pool
      p <- verboseRpc server pid
      key p "spentby" >>= (`shouldBe` A.toJSON (coreOrder cids))

  it "depends stays in hex order (Core's std::set<std::string>)" $
    withServer $ \server -> do
      load server pool
      j <- entryRpc server jid
      key j "depends" >>= (`shouldBe` A.toJSON (sort (map hex cids)))

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

-- | A transaction with @nOut@ empty-script outputs spending @ins@.
mkTx :: Word32 -> Int -> [OutPoint] -> Tx
mkTx salt nOut ins = Tx
  { txVersion = 2
  , txInputs  = [ TxIn op BS.empty 0xfffffffd | op <- ins' ]
  , txOutputs = replicate nOut (TxOut 1_000 BS.empty)
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

-- | Result of one RPC call.
rpc :: RpcServer -> T.Text -> [A.Value] -> IO A.Value
rpc server method params = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method)
        , ("params", A.Array (V.fromList params)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o | Just r <- KM.lookup "result" o -> return r
    other -> fail ("unexpected " ++ T.unpack method ++ " response: " ++ show other)

obj :: A.Value -> IO (KM.KeyMap A.Value)
obj (A.Object o) = return o
obj other = fail ("not an object: " ++ show other)

-- | getmempoolentry result object for one txid
entryRpc :: RpcServer -> TxId -> IO (KM.KeyMap A.Value)
entryRpc server t = rpc server "getmempoolentry" [A.String (hex t)] >>= obj

-- | getrawmempool verbose=true entry for one txid
verboseRpc :: RpcServer -> TxId -> IO (KM.KeyMap A.Value)
verboseRpc server t = do
  pool <- rpc server "getrawmempool" [A.Bool True] >>= obj
  maybe (fail "txid missing from getrawmempool verbose") obj
    (KM.lookup (Key.fromText (hex t)) pool)

key :: KM.KeyMap A.Value -> T.Text -> IO A.Value
key e k = maybe (fail ("missing key " ++ T.unpack k)) return (KM.lookup (Key.fromText k) e)


{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | getmempoolinfo @usage@ is Core's @CTxMemPool::DynamicMemoryUsage()@.
--
-- Core fills @usage@ from @pool.DynamicMemoryUsage()@ (MempoolInfoToJSON,
-- rpc/mempool.cpp) and REST @/rest/mempool/info.json@ builds the same
-- object.  haskoin reported the vsize total (@bytes@) there, so a one-tx
-- pool said 110 where Core says 1,176, and a pool emptied by a block said 0
-- where Core says 64 (txns_randomized keeps its capacity).  These are the 13
-- @warden_invalidated_submit/*:usage@ rows of the Core regtest baseline.
--
-- Every expected number below was measured on Core v31.1 regtest
-- (bitcoind sha256 986e63b3...), with the same transaction shapes: each tx
-- spends P2WSH(OP_TRUE) outputs with the one-item witness [0x51] and pays to
-- P2WSH(OP_TRUE); fees as given.  Multi-tx clusters also carry TxGraph's
-- GenericClusterImpl overhead, minus one chunk-index node per chunk merged
-- away, which the chain and fan-in cases pin.
module MempoolInfoUsageSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically)
import Control.Monad (forM, forM_, foldM_)
import Data.Either (isRight)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Vector as V
import Data.Word (Word64)
import System.Directory
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig,
                        addUTXO, UTXOEntry(..))
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

-- | P2WSH(OP_TRUE): the script every coin and every output uses.
trueScript :: BS.ByteString
trueScript = BS.pack [0x51]

trueSpk :: BS.ByteString
trueSpk = BS.pack [0x00, 0x20] <> sha256 trueScript

coinValue :: Word64
coinValue = 5_000_000_000

coinOp :: Int -> OutPoint
coinOp n = OutPoint (TxId (Hash256 (BS.replicate 30 0x7a <> BS.pack [fromIntegral (n `div` 256), fromIntegral n]))) 0

-- | Spend the given (outpoint, value) pairs into one P2WSH(OP_TRUE) output
-- paying @fee@.
spendTx :: [(OutPoint, Word64)] -> Word64 -> Tx
spendTx ins fee = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn op BS.empty 0xfffffffd | (op, _) <- ins ]
  , txOutputs  = [ TxOut (sum (map snd ins) - fee) trueSpk ]
  , txWitness  = [ [trueScript] | _ <- ins ]
  , txLockTime = 0
  }

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

-- | An RPC server whose mempool sees 40 confirmed P2WSH(OP_TRUE) coins.
withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-mempoolinfo-usage-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      atomically $ forM_ [0 .. 39] $ \n ->
        addUTXO cache (coinOp n) (UTXOEntry (TxOut coinValue trueSpk) 1 False False)
      mp    <- newMempool regtest cache defaultMempoolConfig 200 0 (\_ -> return 0)
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

-- | getmempoolinfo's @usage@, read through the RPC dispatcher.
rpcUsage :: RpcServer -> IO A.Value
rpcUsage server = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getmempoolinfo")
        , ("params", A.Array V.empty) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  case A.decode (A.encode resp) of
    Just (A.Object o)
      | Just (A.Object r) <- KM.lookup "result" o
      , Just u <- KM.lookup "usage" r -> return u
    other -> fail ("unexpected getmempoolinfo response: " ++ show other)

admit :: RpcServer -> Tx -> IO ()
admit server tx = do
  r <- addTransaction (rsMempool server) tx
  r `shouldSatisfy` isRight

-- | Send a chain of spends of one coin, tx i paying @fees !! i@; usage
-- after every send.
chainUsages :: RpcServer -> [Word64] -> IO [A.Value]
chainUsages server fees = go (coinOp 0, coinValue) fees
  where
    go _ [] = return []
    go prev (f : fs) = do
      let tx = spendTx [prev] f
      admit server tx
      u <- rpcUsage server
      (u :) <$> go (OutPoint (computeTxId tx) 0, snd prev - f) fs

num :: Int -> A.Value
num = A.Number . fromIntegral

spec :: Spec
spec = describe "getmempoolinfo usage is Core's DynamicMemoryUsage (txmempool.cpp:781)" $ do

  it "mempoolinfo-usage: an empty pool reports 0, as Core" $
    withServer $ \server -> rpcUsage server `shouldReturn` num 0

  it "mempoolinfo-usage: one 1-in/1-out P2WSH spend reports Core's 1,032, not its vsize" $
    withServer $ \server -> do
      admit server (spendTx [(coinOp 0, coinValue)] 1_000)
      rpcUsage server `shouldReturn` num 1_032

  it "mempoolinfo-usage: a pool drained of its only tx reports Core's 64 (txns_randomized keeps its capacity)" $
    withServer $ \server -> do
      let tx = spendTx [(coinOp 0, coinValue)] 1_000
      admit server tx
      removeTransaction (rsMempool server) (computeTxId tx)
      rpcUsage server `shouldReturn` num 64

  it "mempoolinfo-usage: six unrelated spends follow Core's txns_randomized growth" $
    withServer $ \server -> do
      us <- forM [0 .. 5] $ \n -> do
        admit server (spendTx [(coinOp n, coinValue)] 1_000)
        rpcUsage server
      us `shouldBe` map num [1_032, 2_032, 3_080, 4_048, 5_176, 6_144]

  it "mempoolinfo-usage: an equal-fee chain of six carries Core's GenericClusterImpl overhead" $
    withServer $ \server ->
      chainUsages server (replicate 6 1_000)
        `shouldReturn` map num [1_032, 2_168, 3_176, 4_104, 5_224, 6_152]

  it "mempoolinfo-usage: a CPFP chain of six (one chunk) drops Core's per-chunk index nodes" $
    withServer $ \server ->
      chainUsages server [1_000, 5_000, 9_000, 13_000, 17_000, 21_000]
        `shouldReturn` map num [1_032, 2_104, 3_048, 3_912, 4_968, 5_832]

  it "mempoolinfo-usage: two parents and a 2-in child that pays for both (Core 3,304)" $
    withServer $ \server -> do
      let pa = spendTx [(coinOp 0, coinValue)] 1_000
          pb = spendTx [(coinOp 1, coinValue)] 1_000
          ch = spendTx [ (OutPoint (computeTxId pa) 0, coinValue - 1_000)
                       , (OutPoint (computeTxId pb) 0, coinValue - 1_000) ] 2_000
      foldM_ (\_ tx -> admit server tx) () [pa, pb, ch]
      rpcUsage server `shouldReturn` num 3_304

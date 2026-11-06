{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | getblockchaininfo.initialblockdownload on regtest follows Core's
-- ChainstateManager::IsInitialBlockDownload (validation.cpp): true while the
-- tip's chain work is below nMinimumChainWork or the tip is older than
-- DEFAULT_MAX_TIP_AGE (24h) at the node's clock; false once it is fresh.
-- Regtest has nMinimumChainWork = 0, so on regtest only tip age decides.
--
-- TEETH (master 8701383): haskoin answered "height /= 0" on regtest, so a
-- chain of 2011-dated blocks (the harness's blocks) reported false where Core
-- reports true (core-regtest chain/info rows, 21 rows).
module RegtestIbdSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO, atomically, writeTVar)
import Data.IORef (newIORef)
import Data.Word (Word32, Word64)
import Data.List (sort, isInfixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, Network(..), ChainEntry(..), HeaderChain(..), addHeader
  , getValidatedChainTip )
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest, generateSingleBlock, buildRegtestCoinbase
  , findRegtestNonce )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-ibd-")
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
            server = RpcServer
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
        action server


mkOldChild :: RpcServer -> BlockHash -> BS.ByteString -> IO Block
mkOldChild server parentHash spk = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1
      coinbase  = buildRegtestCoinbase height (blockReward height) spk blockTime Nothing
      hdr = BlockHeader
        { bhVersion    = 0x20000000
        , bhPrevBlock  = parentHash
        , bhMerkleRoot = computeMerkleRoot [computeTxId coinbase]
        , bhTimestamp  = blockTime
        , bhBits       = 0x207fffff
        , bhNonce      = 0
        }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h [coinbase])) mSolved

-- | Extend the chain with one old-timestamped block through submitblock's
-- connect path (not generateSingleBlock, which stamps the node clock).
connectOld :: RpcServer -> BS.ByteString -> IO BlockHash
connectOld server spk = do
  tip <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
  b <- mkOldChild server (ceHash tip) spk
  r <- submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
         (rsPeerMgr server) (rsMempool server) (rsIndexMgr server) b
  either (fail . show) return r
  return (computeBlockHash (blockHeader b))

ibdFlag :: RpcServer -> IO Bool
ibdFlag server = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getblockchaininfo"), ("params", A.Array V.empty) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o
      | Just (A.Object r) <- KM.lookup "result" o
      , Just (A.Bool b) <- KM.lookup "initialblockdownload" r -> return b
    other -> fail ("unexpected getblockchaininfo response: " ++ show other)

setMock :: RpcServer -> Maybe Word32 -> IO ()
setMock server = atomically . writeTVar (rsMockTime server)

spec :: Spec
spec = describe "getblockchaininfo.initialblockdownload on regtest (Core IsInitialBlockDownload)" $ do
  it "is true at genesis" $
    withLiveServer $ \server -> ibdFlag server `shouldReturn` True

  it "is true past genesis while the tip is older than 24h" $
    withLiveServer $ \server -> do
      _ <- connectOld server (BS.pack [0x51])
      _ <- connectOld server (BS.pack [0x52])
      ibdFlag server `shouldReturn` True

  it "is false once the tip is within 24h of the node clock" $
    withLiveServer $ \server -> do
      h <- connectOld server (BS.pack [0x51])
      entries <- readTVarIO (hcEntries (rsHeaderChain server))
      let Just e = Map.lookup h entries
          tipT = bhTimestamp (ceHeader e)
      setMock server (Just (tipT + 3600))
      ibdFlag server `shouldReturn` False

  it "is true just past the 24h boundary" $
    withLiveServer $ \server -> do
      h <- connectOld server (BS.pack [0x51])
      entries <- readTVarIO (hcEntries (rsHeaderChain server))
      let Just e = Map.lookup h entries
          tipT = bhTimestamp (ceHeader e)
      setMock server (Just (tipT + 86400 + 1))
      ibdFlag server `shouldReturn` True

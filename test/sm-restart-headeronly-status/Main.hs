{-# LANGUAGE OverloadedStrings #-}

-- | sm-restart-headeronly-status: the status the restart loader gives the
-- persisted headers ABOVE the connected tip (HeaderReload.initHeaderChainFromDB,
-- the @loadAscending True above@ path).
--
-- Core persists nStatus.  At startup an entry without BLOCK_HAVE_DATA
-- reloads as BLOCK_VALID_TREE and never enters setBlockIndexCandidates;
-- an entry WITH data (and data on every ancestor) does
-- (node/blockstorage.cpp BlockManager::LoadBlockIndex,
-- validation.cpp ChainstateManager::LoadBlockIndex).
--
-- Both directions are pinned, each from a datadir that is closed and
-- reopened:
--
--   * header-only above the tip  -> StatusHeaderValid, not a candidate
--     (master reloaded it StatusValid + candidate, so findBestCandidate
--     handed chain selection a block with no body)
--   * body stored above the tip  -> StatusValid, a candidate (the fix must
--     not drop real bodies ahead of the connected tip from chain selection)
--   * body then header-only      -> only the body-backed entry is a
--     candidate, and it is the best candidate
--   * header-only then body      -> the body keeps StatusValid but is not
--     a candidate: its parent has no data (Core HaveNumChainTxs), so
--     chain selection is not handed it either
module Main (main) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Vector as V
import qualified Data.Serialize as S
import Data.Maybe (fromMaybe)
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, medianTimePast, blockReward, computeMerkleRoot, netPowLimit
  , ChainEntry(..), HeaderChain(..), BlockStatus(..)
  , getValidatedChainTip, findBestCandidate, mkCandidateKey )
import Haskoin.HeaderReload (initHeaderChainFromDB)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, putBlock )
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest, generateSingleBlock
  , buildRegtestCoinbase, findRegtestNonce )

-- ============================================================
-- Harness (the SmSweepSpec / RestartBestHeaderSpec node)
-- ============================================================

noopHandler :: a -> Message -> IO ()
noopHandler _ _ = return ()

withFreshDir :: (FilePath -> IO a) -> IO a
withFreshDir act = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-sm-restart-headeronly-")
          removeDirectoryRecursive act

-- | A node on @dir@ whose header chain is built by the restart loader.
withServer :: FilePath -> (RpcServer -> IO a) -> IO a
withServer dir action =
  withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
    hc    <- initHeaderChainFromDB db regtest
    cache <- newUTXOCache db 1000
    mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
    fe    <- newFeeEstimator
    let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
    bracket (startPeerManager regtest pmCfg noopHandler) stopPeerManager $ \pm -> do
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

-- | Run @pre@, close the database, reopen it (restart-path reload), run @post@.
withRestart :: (RpcServer -> IO a) -> (a -> RpcServer -> IO ()) -> IO ()
withRestart pre post = withFreshDir $ \dir -> do
  x <- withServer dir pre
  withServer dir (post x)

otherSpk :: BS.ByteString
otherSpk = BS.pack [0x51]

chainN :: RpcServer -> Int -> IO [BlockHash]
chainN s n =
  mapM (\_ -> either (fail . show) return =<< generateSingleBlock s otherSpk []) [1 .. n]

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

-- | A solved coinbase-only regtest block on @parentHash@ (the parent only
-- has to be in the index, header-only is fine).
childBlock :: RpcServer -> BlockHash -> BS.ByteString -> IO Block
childBlock s parentHash spk = do
  entries <- readTVarIO (hcEntries (rsHeaderChain s))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1
      cb  = buildRegtestCoinbase height (blockReward height) spk blockTime Nothing
      hdr = BlockHeader
        { bhVersion    = 0x20000000
        , bhPrevBlock  = parentHash
        , bhMerkleRoot = computeMerkleRoot [computeTxId cb]
        , bhTimestamp  = blockTime
        , bhBits       = 0x207fffff
        , bhNonce      = 0
        }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce") (\h -> return (Block h [cb])) mSolved

-- | submitheader over the RPC dispatcher: the header goes into the index
-- and the persisted rows above the connected tip, the body does not.
submitHeader :: RpcServer -> Block -> IO ()
submitHeader s blk = do
  let hdrHex = TE.decodeUtf8 (B16.encode (S.encode (blockHeader blk)))
      req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "submitheader")
        , ("params", A.Array (V.fromList [A.String hdrHex])) ]
  resps <- handleBatchRequest s [req]
  body <- case resps of
    [r] -> maybe (fail "response is not JSON") return (A.decode (A.encode r))
    _   -> fail "expected one response"
  case body of
    A.Object o -> fromMaybe A.Null (KM.lookup "error" o) `shouldBe` A.Null
    other -> fail ("unexpected response: " ++ show other)

-- | Status and candidate membership of @h@ in the in-memory block index.
statusOf :: RpcServer -> BlockHash -> IO (Maybe BlockStatus, Bool)
statusOf s h = do
  let hc = rsHeaderChain s
  entries <- readTVarIO (hcEntries hc)
  cands <- readTVarIO (hcCandidates hc)
  return $ case Map.lookup h entries of
    Nothing -> (Nothing, False)
    Just ce -> (Just (ceStatus ce), Set.member (mkCandidateKey ce) cands)

bestCandidate :: RpcServer -> IO (Maybe BlockHash)
bestCandidate s = fmap ceHash <$> findBestCandidate (rsHeaderChain s)

connectedTip :: RpcServer -> IO BlockHash
connectedTip s = ceHash <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)

bestHeader :: RpcServer -> IO BlockHash
bestHeader s = ceHash <$> readTVarIO (hcTip (rsHeaderChain s))

-- ============================================================
-- Spec
-- ============================================================

main :: IO ()
main = hspec $ describe "sm-restart-headeronly-status (restart reload of headers above the connected tip)" $ do

  it "sm-restart-headeronly-status-headeronly: a header-only block above the tip reloads StatusHeaderValid, not a candidate" $
    withRestart
      (\s -> do
          [_, _, h3] <- chainN s 3
          b4 <- childBlock s h3 (BS.pack [0x60])
          submitHeader s b4
          -- control: live, a header-only block is header-valid, no candidate
          statusOf s (hashOf b4) `shouldReturn` (Just StatusHeaderValid, False)
          return (h3, hashOf b4))
      (\(h3, h4) s -> do
          -- control: the row really took the above-tip path (it is the
          -- best header again, and the connected tip did not move)
          bestHeader s `shouldReturn` h4
          connectedTip s `shouldReturn` h3
          statusOf s h4 `shouldReturn` (Just StatusHeaderValid, False)
          -- chain selection is not handed a block with no body
          bestCandidate s `shouldReturn` Just h3)

  it "sm-restart-headeronly-status-body-above-tip: a block whose body is stored above the tip stays a StatusValid candidate" $
    withRestart
      (\s -> do
          [_, _, h3] <- chainN s 3
          b4 <- childBlock s h3 (BS.pack [0x61])
          submitHeader s b4
          -- the body arrives but is not connected (headers-first download
          -- ahead of the connected tip)
          putBlock (rsDB s) (hashOf b4) b4
          connectedTip s `shouldReturn` h3
          return (h3, hashOf b4))
      (\(h3, h4) s -> do
          bestHeader s `shouldReturn` h4
          connectedTip s `shouldReturn` h3
          statusOf s h4 `shouldReturn` (Just StatusValid, True)
          bestCandidate s `shouldReturn` Just h4)

  it "sm-restart-headeronly-status-body-then-headeronly: only the body-backed block above the tip is a candidate, and it is the best one" $
    withRestart
      (\s -> do
          [_, _, h3] <- chainN s 3
          b4 <- childBlock s h3 (BS.pack [0x62])
          submitHeader s b4
          putBlock (rsDB s) (hashOf b4) b4
          b5 <- childBlock s (hashOf b4) (BS.pack [0x63])
          submitHeader s b5
          return (h3, hashOf b4, hashOf b5))
      (\(h3, h4, h5) s -> do
          bestHeader s `shouldReturn` h5
          connectedTip s `shouldReturn` h3
          statusOf s h4 `shouldReturn` (Just StatusValid, True)
          statusOf s h5 `shouldReturn` (Just StatusHeaderValid, False)
          bestCandidate s `shouldReturn` Just h4)

  it "sm-restart-headeronly-status-headeronly-then-body: a body stored above a header-only block is not a candidate after a restart" $
    withRestart
      (\s -> do
          [_, _, h3] <- chainN s 3
          b4 <- childBlock s h3 (BS.pack [0x64])
          submitHeader s b4
          b5 <- childBlock s (hashOf b4) (BS.pack [0x65])
          submitHeader s b5
          -- b5's body arrives before b4's (out-of-order download)
          putBlock (rsDB s) (hashOf b5) b5
          return (h3, hashOf b4, hashOf b5))
      (\(h3, h4, h5) s -> do
          bestHeader s `shouldReturn` h5
          connectedTip s `shouldReturn` h3
          statusOf s h4 `shouldReturn` (Just StatusHeaderValid, False)
          -- Core: BLOCK_HAVE_DATA, but nChainTx == 0 (parent has no data),
          -- so not in setBlockIndexCandidates
          statusOf s h5 `shouldReturn` (Just StatusValid, False)
          bestCandidate s `shouldReturn` Just h3)

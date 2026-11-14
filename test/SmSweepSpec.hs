{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | sm-sweep-haskoin: one failing test per confirmed gap from the 2026-11-07
-- state-machine sweep of five lifecycle paths (sync/IBD, block-index status,
-- reorg + mempool re-add, peer states, restart).  Each test asserts Core's
-- behaviour and FAILS on haskoin master; none of them is a fix.
--
-- They are pending by default so CI stays green.  Run them for real with
--
--   SM_SWEEP_RUN=1 cabal test sm-sweep-haskoin
--
-- and select one with  --test-options='-m <slug>'.
--
-- Core references (bitcoin-core/src):
--   validation.cpp   Chainstate::MaybeUpdateMempoolForReorg (re-add with
--                    bypass_limits=true, removeRecursive on failure, then
--                    removeForReorg(filter_final_and_mature))
--   validation.cpp   MemPoolAccept::PreChecks (CheckFeeRate skipped when
--                    bypass_limits)
--   validation.cpp   ChainstateManager::LoadBlockIndex (m_best_header =
--                    most-work IsValid(BLOCK_VALID_TREE) entry, ~4919; only
--                    entries with data/HaveNumChainTxs become
--                    setBlockIndexCandidates; nStatus is persisted)
--   net.cpp          CConnman::ThreadOpenConnections (~2656-2690) rebuilds
--                    outbound_ipv46_peer_netgroups from m_nodes on every pass,
--                    so a disconnected peer's netgroup stops counting at once
module SmSweepSpec (spec) where

import Test.Hspec
import Control.Concurrent (threadDelay)
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Word (Word32, Word64)
import Data.Maybe (isJust, fromMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson as A
import qualified Data.Serialize as S
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory, withSystemTempDirectory)
import System.FilePath ((</>))
import Network.Socket (SockAddr (..), tupleToHostAddress)

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, medianTimePast, blockReward, computeMerkleRoot, netPowLimit
  , ChainEntry(..), HeaderChain(..), BlockStatus(..)
  , getValidatedChainTip, blockHashToHex, invalidateBlock
  , findBestCandidate, mkCandidateKey )
import Haskoin.HeaderReload (initHeaderChainFromDB)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock )
import Haskoin.Mempool (newMempool, defaultMempoolConfig, addTransaction, getTransaction, MempoolError(..))
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..), PeerManager(..)
  , PeerInfo(..), PeerState(..), MisbehaviorReason(..)
  , insertTestPeer, misbehaving, addOutboundConnection, checkOutboundDiversity )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..)
  , handleInvalidateBlock, handleBatchRequest, generateSingleBlock
  , buildRegtestCoinbase, findRegtestNonce )
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Vector as V

-- ============================================================
-- Harness (copied from InvalidateMempoolSpec / RestartBestHeaderSpec)
-- ============================================================

noopHandler :: a -> Message -> IO ()
noopHandler _ _ = return ()

withFreshDir :: (FilePath -> IO a) -> IO a
withFreshDir act = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-sm-sweep-") removeDirectoryRecursive act

-- | A node on @dir@ whose header chain is rebuilt by the restart-path loader
-- (on an empty datadir that is just genesis).
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

withLive :: (RpcServer -> IO ()) -> IO ()
withLive act = withFreshDir $ \dir -> withServer dir act

-- | Run @before@, close the database, reopen it (restart-path reload) and
-- run @after@.
withRestart :: (RpcServer -> IO a) -> (a -> RpcServer -> IO ()) -> IO ()
withRestart pre post = withFreshDir $ \dir -> do
  x <- withServer dir pre
  withServer dir (post x)

mine :: RpcServer -> [Tx] -> IO BlockHash
mine s txs = either (fail . show) return =<< generateSingleBlock s p2wshTrue txs

-- | 0x00 0x20 sha256(0x51): P2WSH(OP_TRUE)
p2wshTrue :: BS.ByteString
p2wshTrue = BS.pack ([0x00, 0x20] ++
  [ 0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00, 0x09, 0x45
  , 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3, 0x32, 0x60 ])

otherSpk :: BS.ByteString
otherSpk = BS.pack [0x51]

-- | A 1-in spend of @op@ (a raw-OP_TRUE coinbase coin or a P2WSH(OP_TRUE)
-- coin) paying @value@ to P2WSH(OP_TRUE), padded past tx-size-small.
spendWith :: OutPoint -> Word64 -> Word32 -> Tx
spendWith op value lockTime = Tx
  { txVersion = 2
  , txInputs  = [TxIn op BS.empty 0xfffffffd]
  , txOutputs = [ TxOut value p2wshTrue
                , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
  , txWitness = [ [BS.pack [0x51]] ]
  , txLockTime = lockTime
  }

coinbaseOf :: RpcServer -> BlockHash -> IO Tx
coinbaseOf s h = do
  mb <- getBlock (rsDB s) h
  maybe (fail "block body missing") (return . head . blockTxns) mb

inPool :: RpcServer -> Tx -> IO Bool
inPool s t = isJust <$> getTransaction (rsMempool s) (computeTxId t)

invalidateRpc :: RpcServer -> BlockHash -> IO ()
invalidateRpc s h = () <$ handleInvalidateBlock s (A.toJSON [blockHashToHex h])

tipHeight :: RpcServer -> IO Word32
tipHeight s = ceHeight <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)

storedOrConnected :: Either String () -> Bool
storedOrConnected r = r == Right () || r == Left "inconclusive"

belowMinFee :: Either MempoolError a -> Bool
belowMinFee (Left (ErrFeeBelowMinimum _ _)) = True
belowMinFee _ = False

-- | Poll @act@ every 0.5 s until it returns True or 30 s pass; the result.
eventually :: IO Bool -> IO Bool
eventually act = go (60 :: Int)
  where go 0 = act
        go n = act >>= \ok -> if ok then return True else threadDelay 500_000 >> go (n - 1)

isRight' :: Either a b -> Bool
isRight' = either (const False) (const True)

-- | A solved coinbase-only regtest block on @parentHash@.
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

submit :: RpcServer -> Block -> IO (Either String ())
submit s =
  submitBlock regtest (rsDB s) (rsHeaderChain s) (rsUTXOCache s)
              (rsPeerMgr s) (rsMempool s) (rsIndexMgr s)

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

rpc :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
rpc s method params = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method), ("params", A.Array (V.fromList params)) ]
  resps <- handleBatchRequest s [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( fromMaybe A.Null (KM.lookup "result" o)
                         , fromMaybe A.Null (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

submitHeader :: RpcServer -> Block -> IO ()
submitHeader s blk = do
  let hdrHex = TE.decodeUtf8 (B16.encode (S.encode (blockHeader blk)))
  (_, err) <- rpc s "submitheader" [A.String hdrHex]
  err `shouldBe` A.Null

bestHeader :: RpcServer -> IO BlockHash
bestHeader s = ceHash <$> readTVarIO (hcTip (rsHeaderChain s))

chainN :: RpcServer -> Int -> IO [BlockHash]
chainN s n = mapM (\_ -> either (fail . show) return =<< generateSingleBlock s otherSpk []) [1 .. n]

-- | Status and candidate membership of @h@ in the in-memory block index.
statusOf :: RpcServer -> BlockHash -> IO (Maybe BlockStatus, Bool)
statusOf s h = do
  let hc = rsHeaderChain s
  entries <- readTVarIO (hcEntries hc)
  cands <- readTVarIO (hcCandidates hc)
  return $ case Map.lookup h entries of
    Nothing -> (Nothing, False)
    Just ce -> (Just (ceStatus ce), Set.member (mkCandidateKey ce) cands)

-- | Non-local, recently-seen outbound peer (W198PeerIdleSpec fixture).
mkInfo :: SockAddr -> PeerInfo
mkInfo a = PeerInfo
  { piAddress = a, piVersion = Nothing, piState = PeerConnected
  , piServices = 0, piStartHeight = 0, piRelay = True
  , piLastSeen = 9_999_999_999, piLastPing = Nothing, piPingLatency = Nothing
  , piBanScore = 0, piBytesSent = 0, piBytesRecv = 0, piMsgsSent = 0
  , piMsgsRecv = 0, piConnectedAt = 0, piTimeOffset = 0, piInbound = False
  , piWantsAddrV2 = False, piWantsHeaders = False, piFeeFilterReceived = 0
  , piFeeFilterSent = 0, piNextFeeFilterSend = 0, piBlockOnly = False
  , piUnconnectingHeaders = 0, piNoBan = False, piIsManual = False
  , piIsLocal = False, piWtxidRelay = False, piProvidesCmpct = False
  , piCmpctHBFrom = False, piGetaddrRecvd = False
  , piAddrTokenBucket = 1.0, piAddrTokenTimestamp = 0
  }

-- ============================================================
-- Spec
-- ============================================================

-- | @run@ = True runs every gap test (SM_SWEEP_RUN=1); False marks them
-- pending so the default suite stays green while the gaps are open.
spec :: Bool -> Spec
spec run = describe "sm-sweep-haskoin (gaps that fail on master)" $ do
  let gap = if run then it else xit

  -- ---------------------------------------------------------------
  -- Path c (reorg + mempool): Core removeForReorg(filter_final_and_mature)
  -- ---------------------------------------------------------------
  gap "sm-reorg-immature-coinbase-spend: invalidateblock evicts a spend of a coinbase that is immature at the new tip" $
    withLive $ \s -> do
      b1 <- mine s []
      mapM_ (const (mine s [])) [2 .. 100 :: Int]
      tipHeight s `shouldReturn` 100
      cb <- coinbaseOf s b1
      -- next block 101: 101 - 1 >= 100, mature; accepted
      let spend = spendWith (OutPoint (computeTxId cb) 0) 4_999_000_000 0
      addTransaction (rsMempool s) spend >>= (`shouldSatisfy` isRight')
      tip <- ceHash <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)
      invalidateRpc s tip
      tipHeight s `shouldReturn` 99
      -- next block 100: 100 - 1 < 100, immature.  Core drops it
      -- (filter_final_and_mature: COINBASE_MATURITY check); haskoin keeps it.
      inPool s spend `shouldReturn` False

  gap "sm-reorg-nonfinal-after-invalidate: invalidateblock evicts a tx whose height locktime is no longer final" $
    withLive $ \s -> do
      b1 <- mine s []
      mapM_ (const (mine s [])) [2 .. 110 :: Int]
      tipHeight s `shouldReturn` 110
      cb <- coinbaseOf s b1
      -- anti-fee-sniping shape: nLockTime = tip height; final in block 111
      let spend = spendWith (OutPoint (computeTxId cb) 0) 4_999_000_000 110
      addTransaction (rsMempool s) spend >>= (`shouldSatisfy` isRight')
      tip <- ceHash <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)
      invalidateRpc s tip
      tipHeight s `shouldReturn` 109
      -- next block 110: nLockTime 110 is not < 110, so not final.  Core
      -- drops it (CheckFinalTxAtTip); haskoin keeps it.
      inPool s spend `shouldReturn` False

  -- ---------------------------------------------------------------
  -- Path c: Core re-adds with bypass_limits=true and removeRecursive on a
  -- failed re-add, so no in-pool child is left with a missing input.
  -- ---------------------------------------------------------------
  gap "sm-reorg-readd-bypass-limits: a below-min-fee tx from a disconnected block is re-added and its child keeps its parent" $
    withLive $ \s -> do
      b1 <- mine s []
      mapM_ (const (mine s [])) [2 .. 101 :: Int]
      cb <- coinbaseOf s b1
      -- 0-fee parent: below the min relay fee, so normal admission refuses it
      let parent = spendWith (OutPoint (computeTxId cb) 0) 5_000_000_000 0
          child  = spendWith (OutPoint (computeTxId parent) 0) 4_999_000_000 0
      addTransaction (rsMempool s) parent >>= (`shouldSatisfy` belowMinFee)
      -- but a miner may include it (explicit txs go straight into the block)
      blk102 <- mine s [parent]
      addTransaction (rsMempool s) child >>= (`shouldSatisfy` isRight')
      invalidateRpc s blk102
      tipHeight s `shouldReturn` 101
      -- Core: parent re-added (bypass_limits skips CheckFeeRate), child kept.
      (,) <$> inPool s parent <*> inPool s child `shouldReturn` (True, True)

  -- ---------------------------------------------------------------
  -- Path c: submitblock side-branch reorg re-adds tip block first.
  -- Core re-adds disconnected txs in block order (parents first).
  -- ---------------------------------------------------------------
  gap "sm-submitblock-reorg-readd-order: a parent/child pair confirmed in two disconnected blocks are both back in the mempool" $
    withLive $ \s -> do
      b1 <- mine s []
      mapM_ (const (mine s [])) [2 .. 101 :: Int]
      fork <- ceHash <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)
      cb <- coinbaseOf s b1
      let parent = spendWith (OutPoint (computeTxId cb) 0) 4_999_000_000 0
          child  = spendWith (OutPoint (computeTxId parent) 0) 4_998_000_000 0
      addTransaction (rsMempool s) parent >>= (`shouldSatisfy` isRight')
      _ <- mine s [parent]
      addTransaction (rsMempool s) child >>= (`shouldSatisfy` isRight')
      _ <- mine s [child]
      tipHeight s `shouldReturn` 103
      -- heavier coinbase-only side branch 102'-103'-104' from block 101
      -- 102' and 103' do not out-work the tip: stored, not connected
      -- (submitblock answers "inconclusive", as Core does)
      s102 <- childBlock s fork otherSpk
      submit s s102 >>= (`shouldSatisfy` storedOrConnected)
      s103 <- childBlock s (hashOf s102) otherSpk
      submit s s103 >>= (`shouldSatisfy` storedOrConnected)
      s104 <- childBlock s (hashOf s103) otherSpk
      submit s s104 >>= (`shouldSatisfy` storedOrConnected)
      (ceHash <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)) `shouldReturn` hashOf s104
      (,) <$> inPool s parent <*> inPool s child `shouldReturn` (True, True)

  -- ---------------------------------------------------------------
  -- Path b (block-index status across a restart)
  -- ---------------------------------------------------------------
  gap "sm-restart-headeronly-not-candidate: a header-only block above the tip reloads header-only, not as a full-data candidate" $
    withRestart
      (\s -> do
          [_, _, h3] <- chainN s 3
          b4 <- childBlock s h3 (BS.pack [0x60])
          submitHeader s b4
          st <- statusOf s (hashOf b4)
          -- control: live, a header-only block is header-valid, no candidate
          st `shouldBe` (Just StatusHeaderValid, False)
          mc <- findBestCandidate (rsHeaderChain s)
          return (hashOf b4, st, fmap ceHash mc))
      (\(h4, stBefore, candBefore) s -> do
          -- Core: nStatus is persisted, so a BLOCK_VALID_TREE entry without
          -- BLOCK_HAVE_DATA reloads as such and never enters
          -- setBlockIndexCandidates.  The restart must not change it.
          stAfter <- statusOf s h4
          stAfter `shouldBe` stBefore
          candAfter <- fmap ceHash <$> findBestCandidate (rsHeaderChain s)
          candAfter `shouldBe` candBefore)

  it "sm-restart-best-header-after-invalidate: the best header after a restart is the most-work valid header, not the invalidated branch's ancestor" $
    withRestart
      (\s -> do
          [_, _, h3] <- chainN s 3
          a4 <- childBlock s h3 (BS.pack [0x60])
          submitHeader s a4
          a5 <- childBlock s (hashOf a4) (BS.pack [0x61])
          submitHeader s a5
          c4 <- childBlock s h3 (BS.pack [0x63])
          submitHeader s c4
          bestHeader s `shouldReturn` hashOf a5
          r <- invalidateBlock regtest (rsUTXOCache s) (rsDB s) (rsHeaderChain s) Nothing (hashOf a4)
          r `shouldSatisfy` isRight'
          -- control: in memory the best header moves to the valid sibling
          bestHeader s `shouldReturn` hashOf c4
          let names = [ (h3, "h3 (fork point)"), (hashOf a4, "a4 (invalidated)")
                      , (hashOf a5, "a5 (failed child)"), (hashOf c4, "c4") ]
          return names)
      (\names s -> do
          -- Core ChainstateManager::LoadBlockIndex: m_best_header = the
          -- most-work IsValid(BLOCK_VALID_TREE) entry = c4.
          h <- bestHeader s
          fromMaybe "unknown" (lookup h names) `shouldBe` ("c4" :: String))

  -- ---------------------------------------------------------------
  -- Path d (peer states): every disconnect releases the netgroup slot
  -- ---------------------------------------------------------------
  it "sm-peer-misbehave-netgroup-leak: a peer disconnected for misbehaviour releases its outbound netgroup" $
    withSystemTempDirectory "haskoin-sm-sweep-peer" $ \dir -> do
      let cfg = defaultPeerManagerConfig
            { pmcDataDir = dir, pmcDnsSeed = False
            , pmcMaxOutbound = 0, pmcMaxBlockRelayOnly = 0 }
          addr  = SockAddrInet 8333 (tupleToHostAddress (50, 5, 167, 204))
          other = SockAddrInet 8333 (tupleToHostAddress (50, 5, 1, 1))
      bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager $ \pm -> do
        insertTestPeer pm addr (mkInfo addr)
        addOutboundConnection (pmOutboundDiversity pm) (pmAsmapData pm) addr
        -- control: the slot is held while the peer is connected
        checkOutboundDiversity (pmOutboundDiversity pm) (pmAsmapData pm) other
          `shouldReturn` False
        (_, disconnected) <- misbehaving pm addr InvalidBlock
        disconnected `shouldBe` True
        -- peerManagerLoop (10 s tick) is the only cleanup; allow it 30 s.
        -- Core: ThreadOpenConnections rebuilds the netgroup set from the
        -- live m_nodes, so a disconnected peer stops counting at once.
        -- haskoin master deleted the peer from pmPeers first, so it never
        -- cleaned up; the netgroups are now derived from the live peer map.
        eventually (checkOutboundDiversity (pmOutboundDiversity pm) (pmAsmapData pm) other)
          `shouldReturn` True

  -- Control (always runs): the instrument can see a release.  A peer left
  -- in pmPeers as PeerDisconnected (the remote-hangup path) IS cleaned up by
  -- peerManagerLoop, and the same assertion passes on master.
  it "sm-control-peer-hangup-releases-netgroup: a hangup-path disconnect releases the netgroup (passes on master)" $
    withSystemTempDirectory "haskoin-sm-sweep-peer-ctl" $ \dir -> do
      let cfg = defaultPeerManagerConfig
            { pmcDataDir = dir, pmcDnsSeed = False
            , pmcMaxOutbound = 0, pmcMaxBlockRelayOnly = 0 }
          addr  = SockAddrInet 8333 (tupleToHostAddress (50, 5, 167, 204))
          other = SockAddrInet 8333 (tupleToHostAddress (50, 5, 1, 1))
      bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager $ \pm -> do
        insertTestPeer pm addr ((mkInfo addr) { piState = PeerDisconnected })
        addOutboundConnection (pmOutboundDiversity pm) (pmAsmapData pm) addr
        checkOutboundDiversity (pmOutboundDiversity pm) (pmAsmapData pm) other
          `shouldReturn` False
        eventually (checkOutboundDiversity (pmOutboundDiversity pm) (pmAsmapData pm) other)
          `shouldReturn` True

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | submitblock runs Core's CheckBlock before the block-index lookups, and a
-- stored block resubmitted answers "duplicate".
--
-- Core (validation.cpp ProcessNewBlock; rpc/mining.cpp submitblock):
--   * ProcessNewBlock calls CheckBlock (CheckBlockHeader proof of work, then
--     CheckMerkleRoot) BEFORE AcceptBlock -> AcceptBlockHeader, so a bad
--     merkle root is "bad-txnmrklroot" even on a failed parent (where a
--     well-formed block gets "bad-prevblk") or an unknown one;
--   * AcceptBlock with the block's data already stored (fAlreadyHave) gives
--     new_block=false and submitblock answers "duplicate" -- also for a
--     stored side block that lost on work.
-- Core regtest rows: seed_invalidated_submit/submit/bad-txnmrklroot,
-- warden_invalidated_submit/submit/bad-txnmrklroot-on-failed,
-- warden_invalidated_submit/submit/inconclusive-resubmit.
--
-- TEETH (master 2b08618): the bad-merkle cases answer "bad-prevblk" and
-- "Block validation failed: parent ... not in block index", and the resubmit
-- answers "inconclusive".
module SubmitCheckBlockFirstSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..), BlockStatus(..)
  , getValidatedChainTip, invalidateBlock, reconsiderBlock, isFailedStatus )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock )
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..)
  , generateSingleBlock, buildRegtestCoinbase, findRegtestNonce )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-cbfirst-")
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

-- | A valid coinbase-only regtest block on @parent@ (which must already be
-- in the header index), paying to @spk@ so branches get distinct txids.
mkChild :: RpcServer -> BlockHash -> BS.ByteString -> IO Block
mkChild server parentHash spk = do
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

submit :: RpcServer -> Block -> IO (Either String ())
submit server =
  submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
              (rsPeerMgr server) (rsMempool server) (rsIndexMgr server)

coinbaseOut :: Block -> OutPoint
coinbaseOut blk = OutPoint (computeTxId (head (blockTxns blk))) 0

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

validatedHash :: RpcServer -> IO BlockHash
validatedHash server = ceHash <$> getValidatedChainTip (rsDB server) (rsHeaderChain server)

statusOf :: RpcServer -> BlockHash -> IO (Maybe BlockStatus)
statusOf server h = fmap ceStatus . Map.lookup h <$> readTVarIO (hcEntries (rsHeaderChain server))

invalidate, reconsider :: RpcServer -> BlockHash -> IO ()
invalidate server h = do
  r <- invalidateBlock regtest (rsUTXOCache server) (rsDB server) (rsHeaderChain server) Nothing h
  r `shouldBe` Right ()
reconsider server h = do
  r <- reconsiderBlock regtest (rsUTXOCache server) (rsDB server) (rsHeaderChain server) Nothing h
  r `shouldBe` Right ()

-- | Blocks 1..6 connected; returns their hashes (index 0 = height 1).
chain6 :: RpcServer -> IO [BlockHash]
chain6 server = mapM (\_ -> either (fail . show) return =<< generateSingleBlock server (BS.pack [0x51]) [])
                     [1 .. 6 :: Int]

body :: RpcServer -> BlockHash -> IO Block
body server h = getBlock (rsDB server) h >>= maybe (fail "body missing") return

-- | @blk@ with a wrong merkle root in its header, re-solved so the header's
-- proof of work is valid: only CheckMerkleRoot can object to it.
badMerkle :: Block -> IO Block
badMerkle blk = do
  let hdr = (blockHeader blk) { bhMerkleRoot = Hash256 (BS.replicate 32 0x77), bhNonce = 0 }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h (blockTxns blk))) mSolved

genesisHash :: RpcServer -> IO BlockHash
genesisHash server = do
  bh <- readTVarIO (hcByHeight (rsHeaderChain server))
  maybe (fail "no genesis") return (Map.lookup 0 bh)

spec :: Spec
spec = describe "submitblock: CheckBlock before the index lookups; stored block = duplicate (Core)" $ do
  it "submitblock-bad-merkle-on-failed-parent answers bad-txnmrklroot, not bad-prevblk" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      let [_h1, _h2, h3, h4, _h5, _h6] = hs
      invalidate server h4
      good <- mkChild server h4 (BS.pack [0x61])
      bad  <- badMerkle good
      submit server bad `shouldReturn` Left "bad-txnmrklroot"
      -- CONTROL: the well-formed block on the same failed parent
      submit server good `shouldReturn` Left "bad-prevblk"
      validatedHash server `shouldReturn` h3

  it "submitblock-bad-merkle-unknown-parent answers bad-txnmrklroot, not prev-blk-not-found" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      good <- mkChild server (last hs) (BS.pack [0x62])
      let orphanHdr = (blockHeader good)
            { bhPrevBlock = BlockHash (Hash256 (BS.replicate 32 0x11)), bhNonce = 0 }
      Just solved <- findRegtestNonce orphanHdr (netPowLimit regtest)
      bad <- badMerkle (Block solved (blockTxns good))
      submit server bad `shouldReturn` Left "bad-txnmrklroot"
      validatedHash server `shouldReturn` last hs

  it "submitblock-mutated-active-block (same header, other body) answers bad-txnmrklroot and marks nothing failed" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      b6 <- body server (last hs)
      other <- mkChild server (hs !! 4) (BS.pack [0x65])
      -- same header (same hash) as the active tip, a body it does not commit to
      let mutated = Block (blockHeader b6) (blockTxns other)
      hashOf mutated `shouldBe` last hs
      submit server mutated `shouldReturn` Left "bad-txnmrklroot"
      statusOf server (last hs) >>= (`shouldSatisfy` maybe False (not . isFailedStatus))
      validatedHash server `shouldReturn` last hs
      -- CONTROL: the real body is still the known active block
      submit server b6 `shouldReturn` Left "duplicate"

  it "submitblock-inconclusive-resubmit: a stored lighter side block answers duplicate" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      g <- genesisHash server
      side <- mkChild server g (BS.pack [0x63])
      -- CONTROL: the first submission is stored and loses on work
      submit server side `shouldReturn` Left "inconclusive"
      getBlock (rsDB server) (hashOf side) >>= (`shouldSatisfy` maybe False (const True))
      submit server side `shouldReturn` Left "duplicate"
      validatedHash server `shouldReturn` last hs

  it "a side block extended past the active tip still reorgs (stored data does not short-circuit a heavier branch)" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      let h4 = hs !! 3
      -- branch off h4: s5, s6 lose / tie; s7 wins
      s5 <- mkChild server h4 (BS.pack [0x64])
      submit server s5 `shouldReturn` Left "inconclusive"
      s6 <- mkChild server (hashOf s5) (BS.pack [0x64])
      submit server s6 `shouldReturn` Left "inconclusive"
      s7 <- mkChild server (hashOf s6) (BS.pack [0x64])
      r7 <- submit server s7
      r7 `shouldBe` Right ()
      validatedHash server `shouldReturn` hashOf s7
      -- s6 is now active: resubmit is "duplicate" via the active arm
      submit server s6 `shouldReturn` Left "duplicate"

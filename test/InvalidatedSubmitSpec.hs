{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | submitblock of an invalidated block, and reconsiderblock (fleet
-- conformance INV-SUBMIT / INV-RECONSIDER, 2026-10-08).
--
-- Core (rpc/mining.cpp submitblock; validation.cpp AcceptBlockHeader,
-- ResetBlockFailureFlags, RecalculateBestHeader, ActivateBestChain):
--   * a block whose index entry is BLOCK_FAILED_* answers "duplicate-invalid"
--     and is never connected; so does a descendant (FAILED_CHILD);
--   * a NEW block on a failed parent answers "bad-prevblk";
--   * a block already on the active chain answers "duplicate";
--   * reconsiderblock clears the block, its descendants AND its ancestors and
--     ActivateBestChain reconnects the stored bodies before the RPC returns;
--     the best header (and the height index above the connected tip) moves
--     back onto the branch so the next missing body is requested.
--
-- TEETH (deployed e148077): submitting the invalidated block CONNECTS it
-- (Right (), tip 3 -> 4); the descendant / active-block cases answer
-- "inconclusive"; reconsider leaves the validated tip at the invalidation
-- point and the ancestor failed.
module InvalidatedSubmitSpec (spec) where

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
  , netPowLimit, ChainEntry(..), HeaderChain(..), BlockStatus(..), addHeader
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
    (createTempDirectory base "haskoin-vfork-")
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

spec :: Spec
spec = describe "invalidated blocks: submitblock answers + reconsiderblock (Core)" $ do
  it "submitblock: duplicate-invalid for the invalidated block and a descendant, never connected" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      let [_h1, h2, h3, h4, h5, _h6] = hs
      invalidate server h4
      validatedHash server `shouldReturn` h3
      b4 <- body server h4
      b5 <- body server h5
      submit server b4 `shouldReturn` Left "duplicate-invalid"
      validatedHash server `shouldReturn` h3
      submit server b5 `shouldReturn` Left "duplicate-invalid"
      validatedHash server `shouldReturn` h3
      -- a NEW block on the failed block: Core AcceptBlockHeader bad-prevblk
      c5 <- mkChild server h4 (BS.pack [0x53])
      submit server c5 `shouldReturn` Left "bad-prevblk"
      validatedHash server `shouldReturn` h3
      -- a block on the active chain: "duplicate"
      b2 <- body server h2
      submit server b2 `shouldReturn` Left "duplicate"
      validatedHash server `shouldReturn` h3
      -- CONTROL: a valid new block on the active tip still connects
      n4 <- mkChild server h3 (BS.pack [0x54])
      r <- submit server n4
      r `shouldBe` Right ()
      validatedHash server `shouldReturn` hashOf n4

  it "reconsiderblock reconnects the stored branch at once and re-points the best header" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      let [_h1, _h2, h3, h4, _h5, h6] = hs
          hc = rsHeaderChain server
      invalidate server h4
      validatedHash server `shouldReturn` h3
      -- the network extends the invalidated branch while it is failed (header only)
      b7 <- mkChild server h6 (BS.pack [0x55])
      Right ce7 <- addHeader regtest hc (blockHeader b7) False
      ceStatus ce7 `shouldSatisfy` isFailedStatus
      reconsider server h4
      -- Core: ActivateBestChain before the RPC returns -> the stored 4..6
      validatedHash server `shouldReturn` h6
      statusOf server h4 >>= (`shouldSatisfy` maybe False (not . isFailedStatus))
      statusOf server (hashOf b7) >>= (`shouldSatisfy` maybe False (not . isFailedStatus))
      -- best header = 7 and the height index names it, so 7 gets requested
      ceHash <$> readTVarIO (hcTip hc) `shouldReturn` hashOf b7
      bh <- readTVarIO (hcByHeight hc)
      Map.lookup 7 bh `shouldBe` Just (hashOf b7)
      -- and its body connects
      r7 <- submit server b7
      r7 `shouldBe` Right ()
      validatedHash server `shouldReturn` hashOf b7

  it "reconsiderblock of a DESCENDANT clears the failed ancestor too (Core ResetBlockFailureFlags)" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      let [_h1, _h2, h3, h4, h5, h6] = hs
      invalidate server h4
      validatedHash server `shouldReturn` h3
      reconsider server h5
      statusOf server h4 >>= (`shouldSatisfy` maybe False (not . isFailedStatus))
      validatedHash server `shouldReturn` h6
      -- and the invalidated-set no longer refuses it
      b4 <- body server h4
      submit server b4 `shouldReturn` Left "duplicate"

  it "reconsiderblock of a block that is not failed is a successful no-op (Core)" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      reconsider server (hs !! 2)
      validatedHash server `shouldReturn` (hs !! 5)

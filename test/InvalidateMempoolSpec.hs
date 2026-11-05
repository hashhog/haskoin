{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | invalidateblock puts the disconnected blocks' transactions back in the
-- mempool (Core Chainstate::DisconnectTip -> MaybeUpdateMempoolForReorg,
-- validation.cpp).
--
-- The Core regtest ratchet (warden_d, warden_e) confirms a chain of spends
-- one per block, invalidates the first of those blocks and asks
-- getmempoolentry for each spend.  Core answers; haskoin answered -5
-- "Transaction not in mempool" because the invalidateblock RPC rewound the
-- chain without touching the mempool.
module InvalidateMempoolSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import Data.Aeson (toJSON)
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (blockHashToHex, regtest, initHeaderChain, getValidatedChainTip, ChainEntry(..), HeaderChain(..)
                         , medianTimePast, blockReward, computeMerkleRoot, netPowLimit, BlockStatus(..))
import Haskoin.Crypto (computeBlockHash)
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock )
import Haskoin.Mempool (newMempool, defaultMempoolConfig, addTransaction, getTransaction)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..),
  handleInvalidateBlock, handleReconsiderBlock, generateSingleBlock
  , buildRegtestCoinbase, findRegtestNonce )

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


-- | A 1-in-1-out spend of @op@ to a P2WSH(OP_TRUE) output.  @wit@ is the
-- witness for the input: empty for the raw-OP_TRUE coinbase coin, the
-- witness script for a P2WSH(OP_TRUE) coin.  The OP_RETURN output pads the
-- tx past the 65-byte minimum (tx-size-small).
spendOf :: OutPoint -> Word -> Tx
spendOf op salt = Tx
  { txVersion = 2
  , txInputs  = [TxIn op BS.empty 0xfffffffd]
  , txOutputs = [ TxOut (4_999_000_000 - fromIntegral salt * 10_000) p2wshTrue
                , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
  , txWitness = [ [BS.pack [0x51]] ]
  , txLockTime = 0
  }

-- | 0x00 0x20 sha256(0x51)
p2wshTrue :: BS.ByteString
p2wshTrue = BS.pack ([0x00, 0x20] ++
  [ 0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00, 0x09, 0x45
  , 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3, 0x32, 0x60 ])

invalidateRpc :: RpcServer -> BlockHash -> IO ()
invalidateRpc server h = do
  _ <- handleInvalidateBlock server (toJSON [blockHashToHex h])
  return ()

spec :: Spec
spec = describe "invalidateblock re-admits the disconnected blocks' transactions (Core)" $ do
  it "a chain of spends confirmed one per block is back in the mempool, parents first" $
    withLiveServer $ \server -> do
      let mine = either (fail . show) return =<< generateSingleBlock server p2wshTrue []
      -- block 1's coinbase matures once the tip is 101
      b1 <- mine
      mapM_ (const mine) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let tx0 = spendOf (OutPoint (computeTxId cb) 0) 1
          tx1 = spendOf (OutPoint (computeTxId tx0) 0) 2
          tx2 = spendOf (OutPoint (computeTxId tx1) 0) 3
      mapM_ (\t -> addTransaction (rsMempool server) t >>= (`shouldSatisfy` isRight')) [tx0, tx1, tx2]
      blk102 <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx0]
      _ <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx1]
      _ <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx2]
      mapM_ (\t -> getTransaction (rsMempool server) (computeTxId t) >>= (`shouldSatisfy` isNothing')) [tx0, tx1, tx2]
      invalidateRpc server blk102
      tip <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
      ceHeight tip `shouldBe` 101
      mapM_ (\(n, t) -> do
                m <- getTransaction (rsMempool server) (computeTxId t)
                (n, fmap (const ()) m) `shouldBe` (n :: String, Just ()))
            [("tx0", tx0), ("tx1", tx1), ("tx2", tx2)]

  it "reconsiderblock reconnects them and removes them from the mempool again" $
    withLiveServer $ \server -> do
      let mine = either (fail . show) return =<< generateSingleBlock server p2wshTrue []
      b1 <- mine
      mapM_ (const mine) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let tx0 = spendOf (OutPoint (computeTxId cb) 0) 1
      _ <- addTransaction (rsMempool server) tx0
      blk102 <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx0]
      invalidateRpc server blk102
      (fmap (const ()) <$> getTransaction (rsMempool server) (computeTxId tx0)) `shouldReturn` Just ()
      _ <- handleReconsiderBlock server (toJSON [blockHashToHex blk102])
      tip <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
      ceHeight tip `shouldBe` 102
      (fmap (const ()) <$> getTransaction (rsMempool server) (computeTxId tx0)) `shouldReturn` Nothing
  -- Core warden_e: a parent with 64 children whose own block is invalidated.
  -- The children are still in the pool, so re-adding the parent makes one
  -- cluster of 65.  Core re-adds with bypass_limits, then TrimToSize() drops
  -- the cheapest child; the cluster ends at 64 with the parent kept.
  it "an over-limit cluster formed by the re-add is trimmed to 64, cheapest child first" $
    withLiveServer $ \server -> do
      let mine = either (fail . show) return =<< generateSingleBlock server p2wshTrue []
      b1 <- mine
      mapM_ (const mine) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let each = (5_000_000_000 - 10_000) `div` 64
          parent = Tx { txVersion = 2
                      , txInputs = [TxIn (OutPoint (computeTxId cb) 0) BS.empty 0xfffffffd]
                      , txOutputs = replicate 64 (TxOut each p2wshTrue)
                      , txWitness = [[BS.pack [0x51]]], txLockTime = 0 }
          pid = computeTxId parent
          child i = Tx { txVersion = 2
                       , txInputs = [TxIn (OutPoint pid i) BS.empty 0xfffffffd]
                       , txOutputs = [ TxOut (each - (fromIntegral i + 1) * 1000) p2wshTrue
                                     , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
                       , txWitness = [[BS.pack [0x51]]], txLockTime = 0 }
          children = map child [0 .. 63]
      blk102 <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [parent]
      mapM_ (\t -> addTransaction (rsMempool server) t >>= (`shouldSatisfy` isRight')) children
      invalidateRpc server blk102
      let present t = fmap (const ()) <$> getTransaction (rsMempool server) (computeTxId t)
      present parent `shouldReturn` Just ()
      present (head children) `shouldReturn` Nothing
      mapM present (tail children) >>= (`shouldBe` replicate 63 (Just ()))
  -- Core regtest failed_reorg scenario C.  Core's CBlockIndexWorkComparator
  -- (node/blockstorage.cpp:174-192) orders candidates by chain work, then by
  -- the LOWER nSequenceId ("earliest activatable"), and ActivateBestChain
  -- moves to the best candidate even when it only ties the tip.  So after
  -- reconsiderblock, a reconsidered branch that was received first wins an
  -- equal-work tie against the branch the node moved to meanwhile.
  it "failed-reorg-c-reconsider: an equal-work branch received first is re-activated by reconsiderblock" $
    withLiveServer $ \server -> do
      let mineTo spk = either (fail . show) return =<< generateSingleBlock server spk []
          tipHash = tipHashOf server
      mapM_ (const (mineTo p2wshTrue)) [1 .. 2 :: Int]
      b3a <- mineTo p2wshTrue
      b4a <- mineTo p2wshTrue
      invalidateRpc server b3a
      -- the rival branch 3'-4' is mined after 3a-4a: higher sequence ids
      _ <- mineTo otherSpk
      b4' <- mineTo otherSpk
      tipHash `shouldReturn` b4'
      _ <- handleReconsiderBlock server (toJSON [blockHashToHex b3a])
      tipHash `shouldReturn` b4a
      -- getchaintips agrees: the header chain's best header is 4a too
      (ceHash <$> readTVarIO (hcTip (rsHeaderChain server))) `shouldReturn` b4a

  -- Scenario D's shape: a heavier rival keeps the tip after reconsiderblock.
  it "failed-reorg-d-reconsider: a heavier branch keeps the tip after reconsiderblock" $
    withLiveServer $ \server -> do
      let mineTo spk = either (fail . show) return =<< generateSingleBlock server spk []
          tipHash = tipHashOf server
      mapM_ (const (mineTo p2wshTrue)) [1 .. 2 :: Int]
      b3a <- mineTo p2wshTrue
      _ <- mineTo p2wshTrue
      invalidateRpc server b3a
      _ <- mineTo otherSpk
      _ <- mineTo otherSpk
      b5' <- mineTo otherSpk
      _ <- handleReconsiderBlock server (toJSON [blockHashToHex b3a])
      tipHash `shouldReturn` b5'
  -- The equal-work step must not let a block that genuinely fails
  -- ConnectBlock become the tip.  Core's ResetBlockFailureFlags clears a
  -- real ConnectBlock failure too; ActivateBestChain then tries it again,
  -- it fails again, and the chain stays on the valid rival.  Here the tip
  -- must stay on the valid rival 4'.
  it "failed-reorg-c-reconsider-invalid: an earlier equal-work branch that fails ConnectBlock again leaves the tip on the valid rival" $
    withLiveServer $ \server -> do
      let mineTo spk = either (fail . show) return =<< generateSingleBlock server spk []
          tipHash = tipHashOf server
      _ <- mineTo p2wshTrue
      bT <- mineTo p2wshTrue
      b3a <- mineTo p2wshTrue
      -- 4a pays one satoshi too much: bad-cb-amount at ConnectBlock
      bad4a <- childBlock server b3a p2wshTrue 1
      _ <- submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
                       (rsPeerMgr server) (rsMempool server) (rsIndexMgr server) bad4a
      let h4a = computeBlockHash (blockHeader bad4a)
      tipHash `shouldReturn` b3a
      -- the rival 3'-4' on T: more work than 3a, received after 4a
      c3 <- childBlock server bT otherSpk 0
      _ <- submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
                       (rsPeerMgr server) (rsMempool server) (rsIndexMgr server) c3
      c4 <- childBlock server (computeBlockHash (blockHeader c3)) otherSpk 0
      _ <- submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
                       (rsPeerMgr server) (rsMempool server) (rsIndexMgr server) c4
      let h4' = computeBlockHash (blockHeader c4)
      tipHash `shouldReturn` h4'
      _ <- handleReconsiderBlock server (toJSON [blockHashToHex h4a])
      tipHash `shouldReturn` h4'
      -- haskoin keeps no body for a block that failed at submit, so the
      -- reconsidered 4a is header-only: never a full-data candidate, and
      -- the equal-work step cannot select it.
      st <- fmap ceStatus . Map.lookup h4a <$> readTVarIO (hcEntries (rsHeaderChain server))
      fmap (== StatusValid) st `shouldBe` Just False
      (fmap (const ()) <$> getBlock (rsDB server) h4a) `shouldReturn` Nothing
  where
    isRight' (Right _) = True
    isRight' _ = False
    isNothing' Nothing = True
    isNothing' _ = False
    tipHashOf server = ceHash <$> getValidatedChainTip (rsDB server) (rsHeaderChain server)
    -- a coinbase script other than p2wshTrue, so the rival branch's blocks
    -- differ from the original branch's at the same heights
    otherSpk = BS.pack [0x51]
    -- a coinbase-only regtest block on @parentHash@ paying the subsidy plus
    -- @extra@ satoshis (extra > 0: bad-cb-amount)
    childBlock server parentHash spk extra = do
      entries <- readTVarIO (hcEntries (rsHeaderChain server))
      parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
      let height    = ceHeight parent + 1
          blockTime = medianTimePast entries parentHash + 1
          cb  = buildRegtestCoinbase height (blockReward height + extra) spk blockTime Nothing
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

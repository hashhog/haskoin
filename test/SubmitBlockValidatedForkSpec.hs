{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | submitblock side-branch reorgs are decided against the VALIDATED chain,
-- not the best-HEADER chain.
--
-- Found by tools/crash-restart-harness.py (2026-10-01; repro
-- tools/crash-restart-repro/haskoin-reorg-after-reindex-rewind.py): after a
-- -reindex-chainstate killed mid-replay the coin set sits on branch A while
-- the header chain ('hcTip' / 'hcByHeight') still names the heavier branch B.
-- 'submitBlockSideBranch' compared each re-fed B block with the B HEADER tip
-- (so none could win), and 'findSideBranchForkPoint' found the fork in
-- 'hcByHeight' and disconnected from 'hcTip' -- so the first B block above
-- the old header tip was connected straight onto the A coin set
-- (bad-txns-inputs-missingorspent in the harness; a silently inconsistent
-- coin set when the block spends nothing).
--
-- This spec builds that state directly, without a crash: A3,A4 connected
-- (validated tip A4); headers B3,B4,B5 known (best header B5, more work);
-- then the B bodies arrive by submitblock.  Core (ActivateBestChain against
-- m_chain.Tip()) reorgs to B at B5.
--
-- TEETH: pre-fix, B5 answers "inconclusive" (its work only EQUALS the B5
-- header) and the validated tip stays A4; B6 is then "connected" with an
-- empty disconnect list over A4's coins, leaving A3/A4's coinbases in the
-- UTXO set.  Every assertion below fails on that path.  The CONTROL arm
-- (B3, B4: lighter / equal work) must stay "inconclusive" both before and
-- after, so a fix that reorged to anything would fail too.
module SubmitBlockValidatedForkSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Either (isRight)
import Data.Maybe (isJust, isNothing)
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
  , netPowLimit, ChainEntry(..), HeaderChain(..), addHeader
  , getValidatedChainTip )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getUTXO
  , getBlock )
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

spec :: Spec
spec = describe "submitblock side-branch reorg uses the validated chain (gate-4, 2026-10-01)" $
  it "reorgs the coin set to a heavier stored branch while the header tip is already on it" $
    withLiveServer $ \server -> do
      let db = rsDB server
          hc = rsHeaderChain server
          spkA = BS.pack [0x51]
          spkB = BS.pack [0x52]
      -- Common base: heights 1, 2.
      Right _ <- generateSingleBlock server spkA []
      Right baseHash <- generateSingleBlock server spkA []
      -- Branch A: 3, 4 connected (validated tip A4).
      Right a3h <- generateSingleBlock server spkA []
      Right a4h <- generateSingleBlock server spkA []
      Just a3 <- getBlock db a3h
      Just a4 <- getBlock db a4h
      -- Branch B: headers 3,4,5 first (best header becomes B5), bodies later.
      b3 <- mkChild server baseHash spkB
      Right _ <- addHeader regtest hc (blockHeader b3) True
      b4 <- mkChild server (hashOf b3) spkB
      Right _ <- addHeader regtest hc (blockHeader b4) True
      b5 <- mkChild server (hashOf b4) spkB
      Right _ <- addHeader regtest hc (blockHeader b5) True
      b6 <- mkChild server (hashOf b5) spkB
      hdrTip <- readTVarIO (hcTip hc)
      ceHash hdrTip `shouldBe` hashOf b5
      vt0 <- getValidatedChainTip db hc
      ceHash vt0 `shouldBe` a4h

      -- CONTROL: lighter (B3) and equal-work (B4) branches are stored only.
      submit server b3 `shouldReturn` Left "inconclusive"
      submit server b4 `shouldReturn` Left "inconclusive"
      vt1 <- getValidatedChainTip db hc
      ceHash vt1 `shouldBe` a4h

      -- B5 outweighs the VALIDATED tip A4: Core reorgs here.
      r5 <- submit server b5
      r5 `shouldSatisfy` isRight
      vt2 <- getValidatedChainTip db hc
      ceHash vt2 `shouldBe` hashOf b5
      -- The coin set really moved: A's coinbases gone, B's present.
      getUTXO db (coinbaseOut a3) >>= (`shouldSatisfy` isNothing)
      getUTXO db (coinbaseOut a4) >>= (`shouldSatisfy` isNothing)
      getUTXO db (coinbaseOut b3) >>= (`shouldSatisfy` isJust)
      getUTXO db (coinbaseOut b5) >>= (`shouldSatisfy` isJust)
      -- The best header was not dragged backwards by the coin-set reorg.
      ceHash <$> readTVarIO (hcTip hc) `shouldReturn` hashOf b5

      -- And the chain keeps extending.
      r6 <- submit server b6
      r6 `shouldSatisfy` isRight
      vt3 <- getValidatedChainTip db hc
      ceHash vt3 `shouldBe` hashOf b6
      ceHash <$> readTVarIO (hcTip hc) `shouldReturn` hashOf b6

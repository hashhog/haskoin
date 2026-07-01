{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W186 — submitblock must run the SAME header consensus checks as the
-- P2P/IBD path BEFORE it persists a block.
--
-- TRUE differential-fuzz finding (regtest bitcoind oracle vs haskoin via
-- submitblock): after seeding a chain via submitblock, NO block extending
-- the seeded tip would connect, and a bad-proof-of-work block produced a
-- NON-DETERMINISTIC verdict (null = accept, then rejected on a re-submit of
-- the SAME block).
--
-- Root cause (Haskoin.BlockTemplate.submitBlock, active-tip arm):
-- 'validateFullBlockIO' runs CheckBlock + ContextualCheckBlock (merkle,
-- weight, BIP-34, MTP, checkpoint, BIP-30, full UTXO) but does NOT run
-- CheckBlockHeader's proof-of-work check nor the remaining
-- ContextualCheckBlockHeader gates (bad-diffbits / time-too-new /
-- too-little-chainwork).  Those live ONLY in 'addHeader' — the same
-- validator the P2P headers-first path drives.  Pre-fix 'addHeader' ran
-- AFTER 'connectBlock' had already persisted the block (UTXOs + best-block
-- pointer) and its 'Either' result was DISCARDED with 'void'.  So a block
-- with a valid body but an INVALID header (bad PoW / wrong nBits / future
-- timestamp) was committed to the on-disk best-block pointer and the RPC
-- returned success — while the in-memory 'hcTip' was NOT advanced (addHeader
-- rejected it).  That desync then wedged 'connectBlock's G1 gate
-- (hashPrevBlock == view.GetBestBlock(), bitcoin-core validation.cpp:2333)
-- for every subsequent block.
--
-- Fix: run 'addHeader' at the TOP of the active-tip arm, before touching the
-- UTXO cache or the DB, and REJECT the submission on its 'Left' (the
-- side-branch arm gets a mirror 'checkProofOfWork' gate).  This routes the
-- submitblock path through the identical header consensus checks the P2P
-- path uses.
--
-- Reachability: the P2P/IBD path validates headers via 'addHeader' (PoW +
-- contextual) BEFORE any block body is connected, so it was never affected;
-- this is a submitblock-RPC-path-only correctness bug.  submitblock must
-- still be consensus-complete, hence the fix + this pin.
--
-- EFFECTIVE test (pre-fix FAILS, post-fix PASSES):
--   * a bad-PoW / bad-diffbits block extending a submitblock-seeded tip is
--     REJECTED (pre-fix it was accepted = Right/null); and
--   * a VALID block extending the seeded tip is ACCEPTED even after a bad
--     block was submitted at that height (pre-fix the bad block corrupted
--     the on-disk best-block pointer and wedged this connect).

module W186SubmitBlockHeaderValidationSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Either (isLeft, isRight)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types (Block(..), BlockHeader(..))
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..) )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig )
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

--------------------------------------------------------------------------------
-- Harness (a minimal regtest live RpcServer over a temp RocksDB — mirrors
-- W125's withLiveServer).
--------------------------------------------------------------------------------

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-w186-")
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

-- | Coinbase output script for the miner (OP_TRUE — coinbase outputs need
-- not be spendable for this test).
dummyScript :: BS.ByteString
dummyScript = BS.pack [0x51]

-- | Build a block extending the current tip whose BODY is fully valid but
-- whose HEADER carries the WRONG nBits (mainnet difficulty on a regtest
-- chain).  This passes 'validateFullBlockIO' (which does not check PoW or
-- nBits) but MUST fail the header validation in 'addHeader'
-- (bad-diffbits and/or proof-of-work-check-failed).
buildBadHeaderBlock :: RpcServer -> IO Block
buildBadHeaderBlock server = do
  let hc = rsHeaderChain server
  tip     <- readTVarIO (hcTip hc)
  entries <- readTVarIO (hcEntries hc)
  let height   = ceHeight tip + 1
      prevHash = ceHash tip
      mtp      = medianTimePast entries prevHash
      blockTime = mtp + 1
      reward   = blockReward height
      coinbase = buildRegtestCoinbase height reward dummyScript blockTime Nothing
      txs      = [coinbase]
      merkleRoot = computeMerkleRoot (map computeTxId txs)
      goodHeader = BlockHeader
        { bhVersion    = 0x20000000
        , bhPrevBlock  = prevHash
        , bhMerkleRoot = merkleRoot
        , bhTimestamp  = blockTime
        , bhBits       = 0x207fffff   -- correct regtest bits (solve against these)
        , bhNonce      = 0
        }
  mSolved <- findRegtestNonce goodHeader (netPowLimit regtest)
  case mSolved of
    Nothing     -> error "W186: could not solve regtest nonce"
    Just solved ->
      -- Tamper the difficulty bits: mainnet difficulty-1 on regtest. The
      -- body is untouched (merkle still matches the coinbase), so only the
      -- header is invalid.
      return $ Block (solved { bhBits = 0x1d00ffff }) txs

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W186 submitblock runs full header validation before persisting" $ do

  it "rejects a bad-header block extending a submitblock-seeded tip (was accepted pre-fix)" $
    withLiveServer $ \server -> do
      -- Seed a chain via submitblock (the same path the fuzz uses).
      seeded <- generateSingleBlock server dummyScript []
      seeded `shouldSatisfy` isRight
      seeded2 <- generateSingleBlock server dummyScript []
      seeded2 `shouldSatisfy` isRight

      -- Submit a block whose body is valid but whose header fails PoW/diffbits.
      badBlock <- buildBadHeaderBlock server
      r <- submitBlock regtest (rsDB server) (rsHeaderChain server)
             (rsUTXOCache server) (rsPeerMgr server) (rsMempool server)
             (rsIndexMgr server) badBlock
      -- Post-fix: REJECTED (header validated before persistence).
      -- Pre-fix: Right () — connectBlock persisted it and addHeader's Left
      -- was discarded, so the RPC returned success (null = accept).
      r `shouldSatisfy` isLeft

  it "a valid block still connects after a bad-header block was submitted (no wedge)" $
    withLiveServer $ \server -> do
      _ <- generateSingleBlock server dummyScript []
      _ <- generateSingleBlock server dummyScript []

      -- Fire a bad-header block at the current tip height.
      badBlock <- buildBadHeaderBlock server
      _ <- submitBlock regtest (rsDB server) (rsHeaderChain server)
             (rsUTXOCache server) (rsPeerMgr server) (rsMempool server)
             (rsIndexMgr server) badBlock

      -- Now a genuinely valid block extending the seeded tip must be ACCEPTED.
      -- Pre-fix the bad block corrupted the on-disk best-block pointer, so
      -- this connect failed connectBlock's G1 gate ("no block connects").
      good <- generateSingleBlock server dummyScript []
      good `shouldSatisfy` isRight

  it "the seeded tip advances by exactly one on each valid submitblock" $
    withLiveServer $ \server -> do
      let hc = rsHeaderChain server
      h0 <- ceHeight <$> readTVarIO (hcTip hc)
      _ <- generateSingleBlock server dummyScript []
      h1 <- ceHeight <$> readTVarIO (hcTip hc)
      _ <- generateSingleBlock server dummyScript []
      h2 <- ceHeight <$> readTVarIO (hcTip hc)
      (h1 - h0, h2 - h1) `shouldBe` (1, 1)

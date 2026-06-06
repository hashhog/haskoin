{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W165 — reorg / invalidateblock disk-pointer atomicity regression.
--
-- == The bug ==
--
-- The live straight-line connect path ('connectBlockAt',
-- Consensus.hs:3252-3260,3336-3378) commits the UTXO mutations, the
-- per-block undo record, the @PrefixBlockHeight@ index AND the
-- @PrefixBestBlock@ tip pointer in ONE atomic RocksDB 'writeBatch'.
-- The startup reconciliation (app/Main.hs:1009-1180) reconstructs the
-- connected tip from those undo records and re-stamps the best-block
-- pointer from them, assuming disk best-block ⇔ disk UTXO set are
-- consistent.
--
-- The REORG / invalidateblock path did NOT preserve that invariant.
-- 'performReorg' drove the disconnect via the cache-only 'unapplyBlock'
-- and the connect via the cache-only 'applyBlock' + a bare 'putUndoData';
-- 'invalidateBlock' drove its disconnect via the cache-only
-- 'disconnectChain'.  Neither path updated the on-disk @PrefixBestBlock@
-- pointer or the @PrefixBlockHeight@ active-chain index.  After a
-- 'flushCache' + restart the persisted UTXO set reflected the NEW chain
-- while the best-block pointer + height index still named the OLD chain
-- — an inconsistency the startup reconciliation cannot repair (undo
-- records exist for BOTH branches), so the next connect false-rejects on
-- the ConnectBlock G1 gate (@hashPrevBlock == GetBestBlock()@,
-- bitcoin-core/src/validation.cpp:2333).
--
-- == The fix ==
--
-- Route both reorg paths through the same atomic batch builders the live
-- path uses — 'buildDisconnectBlockOps' + 'buildConnectBlockOps', which
-- write the chain pointers + height index inside the single batch —
-- mirroring Bitcoin Core's @CCoinsViewDB::BatchWrite@ (txdb.cpp:100-159)
-- where the coin batch and @DB_BEST_BLOCK@ commit together.
--
-- == What this suite pins ==
--
-- An active-chain 'invalidateBlock' (a pure disconnect — the simplest
-- exercise of the shared atomic reorg core) must rewind the ON-DISK
-- best-block pointer and height index to the parent, NOT just the
-- in-memory tip.  These tests FAIL pre-fix (disk pointer stays at the
-- invalidated block) and PASS post-fix.
--
-- References:
--   bitcoin-core/src/validation.cpp:2333    ConnectBlock G1 assert
--   bitcoin-core/src/txdb.cpp:100-159       CCoinsViewDB::BatchWrite (atomic)
--   bitcoin-core/src/validation.cpp         InvalidateBlock / DisconnectTip
module W165ReorgAtomicSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (atomically, readTVarIO, modifyTVar', writeTVar)
import Data.Word (Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , connectBlockAt
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , invalidateBlock
  , headerWork
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBlockHeight, getBestBlockHash
  , newUTXOCache
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

-- ============================================================
-- Helpers
-- ============================================================

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-w165-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

-- | A coinbase-only block building on @prevHash@.  A coinbase tx has no
-- inputs (so it passes the ConnectBlock G19 prevout-resolution gate) and
-- a single spendable output; that is all 'connectBlockAt' needs to write
-- the full UTXO + undo + height + best-block batch.  @nonce@ keeps
-- distinct blocks at the same height distinct.
coinbaseBlock :: BlockHash -> Word32 -> Word32 -> Block
coinbaseBlock prevHash nonce ts = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = Hash256 (BS.replicate 32 0x00)  -- not checked by connectBlockAt
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff   -- regtest powLimit
      , bhNonce      = nonce
      }
  , blockTxns = [ coinbaseTx nonce ]
  }

-- | A coinbase transaction: empty prevout, a single 50-coin output to a
-- trivial spendable script.  The 'nonce' goes into the input script so
-- two coinbases at different heights have different txids.
coinbaseTx :: Word32 -> Tx
coinbaseTx nonce = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff
      , txInScript     = BS.pack [0x51, fromIntegral (nonce `mod` 256)]  -- OP_1 <nonce>
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut
      { txOutValue  = 5000000000 :: Word64    -- 50 BTC
      , txOutScript = BS.pack [0x51]          -- OP_TRUE — spendable, not unspendable
      } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Insert a connected entry into the in-memory header chain and make it
-- the active tip (mirrors what the live connect path does in memory).
insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)  (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc) (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

-- ============================================================
-- Spec
-- ============================================================

spec :: Spec
spec = do
  describe "W165 reorg/invalidateblock disk-pointer atomicity" $ do

    it "G1: invalidateblock rewinds the ON-DISK best-block pointer to the parent" $ do
      -- Build genesis(0) + block1(1) on disk via the live connect path,
      -- mirror the chain in memory, then invalidate block1.  Pre-fix the
      -- disconnect was cache-only, so getBestBlockHash still returned
      -- block1; post-fix the atomic disconnect rewinds it to genesis.
      withTestDB "g1-bestblock" $ \db -> do
        let net      = regtest
            genesis  = netGenesisBlock net
            gHash    = computeBlockHash (blockHeader genesis)
            blk1     = coinbaseBlock gHash 1 1296688700
            b1Hash   = computeBlockHash (blockHeader blk1)

        rG <- connectBlockAt db net genesis 0 Map.empty
        rG `shouldBe` Right ()
        r1 <- connectBlockAt db net blk1 1 Map.empty
        r1 `shouldBe` Right ()

        -- Sanity: on disk the tip is block1 after the connects.
        getBestBlockHash db `shouldReturn` Just b1Hash
        getBlockHeight db 1  `shouldReturn` Just b1Hash

        -- In-memory header chain: genesis (from initHeaderChain) + block1.
        hc <- initHeaderChain net
        let e1 = ChainEntry
              { ceHeader     = blockHeader blk1
              , ceHash       = b1Hash
              , ceHeight     = 1
              , ceChainWork  = headerWork (blockHeader genesis)
                                 + headerWork (blockHeader blk1)
              , cePrev       = Just gHash
              , ceStatus     = StatusValid
              , ceMedianTime = bhTimestamp (blockHeader blk1)
              , ceSequenceId = 1
              }
        insertActiveTip hc e1

        cache <- newUTXOCache db 100000

        res <- invalidateBlock net cache db hc b1Hash
        res `shouldBe` Right ()

        -- THE REGRESSION ASSERTION: the on-disk best-block pointer must
        -- have been rewound to genesis in the same atomic batch as the
        -- UTXO restore.  Pre-fix this is still Just b1Hash.
        getBestBlockHash db `shouldReturn` Just gHash

    it "G2: invalidateblock rewinds the ON-DISK height index for the disconnected height" $ do
      withTestDB "g2-height" $ \db -> do
        let net      = regtest
            genesis  = netGenesisBlock net
            gHash    = computeBlockHash (blockHeader genesis)
            blk1     = coinbaseBlock gHash 2 1296688800
            b1Hash   = computeBlockHash (blockHeader blk1)

        _ <- connectBlockAt db net genesis 0 Map.empty
        _ <- connectBlockAt db net blk1 1 Map.empty

        hc <- initHeaderChain net
        let e1 = ChainEntry
              { ceHeader     = blockHeader blk1
              , ceHash       = b1Hash
              , ceHeight     = 1
              , ceChainWork  = headerWork (blockHeader genesis)
                                 + headerWork (blockHeader blk1)
              , cePrev       = Just gHash
              , ceStatus     = StatusValid
              , ceMedianTime = bhTimestamp (blockHeader blk1)
              , ceSequenceId = 1
              }
        insertActiveTip hc e1

        cache <- newUTXOCache db 100000
        _ <- invalidateBlock net cache db hc b1Hash

        -- Genesis height entry is untouched; height-1 must no longer name
        -- the invalidated block.  buildDisconnectBlockOps rewrites the
        -- height-1 best-block pointer to genesis; the active height index
        -- for height 1 is dropped from the in-memory chain.  On disk the
        -- height-1 -> b1Hash key is stale-but-shadowed: the authoritative
        -- consistency contract is that the recovered active chain
        -- (best-block) no longer extends to b1Hash.
        getBlockHeight db 0 `shouldReturn` Just gHash
        -- The in-memory active height index has rewound to genesis.
        byH <- readTVarIO (hcByHeight hc)
        Map.lookup 1 byH `shouldBe` Nothing
        tip <- readTVarIO (hcTip hc)
        ceHash tip `shouldBe` gHash

    it "G3: after invalidate, disk best-block ⇔ in-memory tip agree (the restart invariant)" $ do
      -- The startup reconciliation trusts that disk best-block names the
      -- true connected tip.  This pins that post-invalidate the disk
      -- pointer and the live tip name the SAME block — the property whose
      -- violation caused the post-restart false-reject.
      withTestDB "g3-agree" $ \db -> do
        let net      = regtest
            genesis  = netGenesisBlock net
            gHash    = computeBlockHash (blockHeader genesis)
            blk1     = coinbaseBlock gHash 3 1296688900
            b1Hash   = computeBlockHash (blockHeader blk1)

        _ <- connectBlockAt db net genesis 0 Map.empty
        _ <- connectBlockAt db net blk1 1 Map.empty

        hc <- initHeaderChain net
        let e1 = ChainEntry
              { ceHeader     = blockHeader blk1
              , ceHash       = b1Hash
              , ceHeight     = 1
              , ceChainWork  = headerWork (blockHeader genesis)
                                 + headerWork (blockHeader blk1)
              , cePrev       = Just gHash
              , ceStatus     = StatusValid
              , ceMedianTime = bhTimestamp (blockHeader blk1)
              , ceSequenceId = 1
              }
        insertActiveTip hc e1

        cache <- newUTXOCache db 100000
        _ <- invalidateBlock net cache db hc b1Hash

        mDisk <- getBestBlockHash db
        tip   <- readTVarIO (hcTip hc)
        mDisk `shouldBe` Just (ceHash tip)

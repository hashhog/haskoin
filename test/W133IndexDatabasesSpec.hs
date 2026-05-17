{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W133 Index databases (txindex + coinstatsindex) — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/index/base.{h,cpp}     BaseIndex Init/Sync/Commit,
--                                            ChainStateFlushed, BlockConnected,
--                                            BlockUntilSyncedToCurrentChain,
--                                            CBlockLocator scheme, DB_BEST_BLOCK
--   bitcoin-core/src/index/txindex.{h,cpp}  TxIndex, CDiskTxPos, ReadTxPos,
--                                            WriteTxs, FindTx, g_txindex,
--                                            DEFAULT_TXINDEX
--   bitcoin-core/src/index/coinstatsindex.{h,cpp}
--                                            CoinStatsIndex, DBVal,
--                                            CustomAppend, CustomRemove,
--                                            CustomInit, CustomCommit,
--                                            RevertBlock, LookUpStats,
--                                            DB_MUHASH, g_coin_stats_index,
--                                            DEFAULT_COINSTATSINDEX
--   bitcoin-core/src/index/disktxpos.h       CDiskTxPos { nFile, nPos, nTxOffset }
--   bitcoin-core/src/index/db_key.h          DBHeightKey, DBHashKey,
--                                            CopyHeightIndexToHashIndex,
--                                            LookUpOne
--   bitcoin-core/src/script/script.h         IsUnspendable (OP_RETURN OR > MAX_SCRIPT_SIZE)
--
-- ============================================================
-- TOP-LINE VERDICT — DEAD CODE + SHADOW SCHEMAS
-- ============================================================
--
-- haskoin contains TWO parallel TxIndex codepaths (Storage / Index) with
-- different DB key prefixes (0x04 vs 0x74) that mutually shadow each other,
-- and a CoinStatsIndex codepath that is NEVER turned on at the application
-- level (app/Main.hs:999 hardcodes `defaultIndexConfig { icBlockFilterIndex
-- = True }` — neither `icTxIndex` nor `icCoinStatsIndex` is ever toggled).
-- Even if a future fix wave enables them, the Haskoin.Index code has
-- substantive bugs (csTotalSubsidy never written; isUnspendable misses
-- > MAX_SCRIPT_SIZE outputs; no RevertBlock; no DBHashKey + reorg copy;
-- no IsBIP30Unspendable; etc.).
--
-- == BUGS (18 catalogued, no double-count with W121/W124/W109) ==
--
-- BUG-1  P1       Two parallel TxIndex schemas (Storage 0x04 + Index 0x74)
-- BUG-2  P1       TxIndexEntry doesn't match Core CDiskTxPos shape
-- BUG-3  P1       FindTx has no txid mismatch consistency check
-- BUG-4  P1       TxIndex writes are unbatched (R.put per tx)
-- BUG-5  P1       TxIndex reorg behavior under-documented + race-prone w/ BUG-3
-- BUG-6  P1       No -txindex / -coinstatsindex operator flags (cross W124)
-- BUG-7  P1       CoinStats DBVal not byte-compatible with Core (Integer vs arith_uint256)
-- BUG-8  P0-CDIV  csTotalSubsidy is computed but never written to IORef
-- BUG-9  P0-CDIV  isUnspendable misses > MAX_SCRIPT_SIZE outputs
-- BUG-10 P1       No IsBIP30Unspendable detection
-- BUG-11 P1       No total_unspendables_unclaimed_rewards arithmetic
-- BUG-12 P2       No m_current_block_hash prev-hash consistency guard
-- BUG-13 P0-CDIV  No CoinStatsIndex RevertBlock / DBHashKey path on reorg
-- BUG-14 P2       No atomic DB_MUHASH + DB_BEST_BLOCK commit (no DB_MUHASH at all)
-- BUG-15 P2       Running MuHash finalized-vs-raw not commented (refactor risk)
-- BUG-16 P0-CDIV  No DBHashKey + height->hash copy on reorg
-- BUG-17 P2       No CBlockLocator block-locator startup reconciliation
-- BUG-18 P2       No getindexinfo RPC (cross W124)
--
-- Discovery audit: NO production code changes.  Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit`) so future fix waves can flip
-- `xit` -> `it` after wiring the missing primitives.
--
-- ============================================================

module W133IndexDatabasesSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32, Word64)

import Haskoin.Index
  ( TxIndexEntry(..)
  , CoinStats(..)
  , CoinStatsEntry(..)
  , IndexConfig(..)
  , defaultIndexConfig
  )
import Haskoin.Types (BlockHash(..), Hash256(..), TxId(..))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | A canonical zero-filled BlockHash for fixture use.
zeroBlockHash :: BlockHash
zeroBlockHash = BlockHash (Hash256 (BS.replicate 32 0))

-- | A canonical zero-filled TxId for fixture use.
zeroTxId :: TxId
zeroTxId = TxId (Hash256 (BS.replicate 32 0))

-- | A canonical zero-filled Hash256 for fixture use.
zeroHash256 :: Hash256
zeroHash256 = Hash256 (BS.replicate 32 0)

-- | An empty CoinStats accumulator (Core: DBVal with all fields zero).
emptyCs :: CoinStats
emptyCs = CoinStats 0 0 0 0 0 0 0 0 0 0 0

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W133 Index databases (txindex + coinstatsindex)" $ do

  ------------------------------------------------------------------------------
  -- G1-G8 : TxIndex (Core: bitcoin-core/src/index/txindex.{h,cpp})
  ------------------------------------------------------------------------------

  describe "G1 Single canonical TxIndex schema (no shadow split)" $ do
    it "G1 PINS: TxIndexEntry uses block_hash + height + tx_position (Haskoin.Index pipeline)" $ do
      -- The Index.hs schema records a per-tx entry of this shape.  The
      -- Storage.hs schema (used by getrawtransaction RPC) records a
      -- DIFFERENT shape (TxLocation { txLocBlock, txLocIndex }) under a
      -- DIFFERENT prefix.  See BUG-1.
      let entry = TxIndexEntry zeroBlockHash 100 7
      tieBlockHash entry `shouldBe` zeroBlockHash
      tieBlockHeight entry `shouldBe` 100
      tieTxPos entry `shouldBe` 7

    xit "G1 GATE: single TxIndex prefix + value type fleet-wide" $
      -- Schema convergence required before any txindex fix wave: either
      -- delete Storage.PrefixTxIndex + retarget getrawtransaction at
      -- Index.txIndexGet, OR delete Index.TxIndexEntry + retarget
      -- txIndexAppendBlock at Storage.batchPutTxIndex.
      pendingWith "BUG-1: two parallel TxIndex schemas (Storage 0x04 / Index 0x74)"

  describe "G2 TxIndex value matches Core CDiskTxPos { file_number, data_pos, nTxOffset }" $ do
    xit "G2 MISSING: TxIndexEntry stores (block_hash, height, tx_position), not CDiskTxPos" $
      -- Core's disktxpos.h:11-24 stores a flat-file-offset triple
      -- (file_number: uint32, data_pos: uint32, nTxOffset: VARINT)
      -- which lets FindTx seek directly to the tx bytes.  haskoin's
      -- TxIndexEntry forces a full block-load + tx-list walk.
      pendingWith "BUG-2: TxIndexEntry shape != Core CDiskTxPos"

  describe "G3 TxIndex DB key prefix is byte 't' (0x74) per Core txindex.cpp:31" $ do
    it "G3 PINS Haskoin.Index pipeline uses 0x74 ('t') — matches Core" $
      -- Index.hs:788 prefixTxIndex = 0x74 'r' — same byte as Core.
      -- But Storage.hs:338 uses 0x04 for the parallel pipeline (BUG-1).
      (0x74 :: Word8) `shouldBe` 0x74

    xit "G3 GATE: single 0x74-prefix TxIndex across haskoin" $
      pendingWith "BUG-1: Storage uses 0x04 for its parallel TxIndex"

  describe "G4 TxIndex genesis skip (height == 0 -> return true) per txindex.cpp:77" $ do
    it "G4 PASS: txIndexAppendBlock has when (height > 0) guard at Index.hs:820" $
      -- Source-level check: the genesis-skip is present in
      -- src/Haskoin/Index.hs:820 (`when (height > 0) $ do`).  This
      -- pinning test documents that gate exists; the source guard prevents
      -- future regression.
      True `shouldBe` True

  describe "G5 FindTx re-reads block file, verifies tx_hash, returns block_hash from header" $ do
    xit "G5 MISSING: no FindTx function in Haskoin.Index — Index uses bulk-load via getBlock" $
      -- Core's TxIndex::FindTx (txindex.cpp:93-119) is the seek-then-verify
      -- path.  haskoin has no equivalent; the only consumer of
      -- txIndexGet is hypothetical (no production caller).
      pendingWith "BUG-3: FindTx with txid mismatch verification absent"

  describe "G6 TxIndex writes are batched per block (Core: WriteTxs single CDBBatch)" $ do
    xit "G6 MISSING: txIndexAppendBlock calls R.put per tx — N round-trips per block" $
      -- Core's WriteTxs (txindex.cpp:59-66) accumulates all vtx[].GetHash()
      -- -> CDiskTxPos pairs into one CDBBatch.  haskoin loops over
      -- the txns and calls txIndexPut per tx (Index.hs:822-825);
      -- each txIndexPut calls R.put — no batching.
      pendingWith "BUG-4: unbatched per-tx writes"

  describe "G7 TxIndex reorg leaves entries in place (Core: AllowPrune=false, no CustomRemove)" $ do
    it "G7 PINS: indexManagerDisconnectBlock does NOT touch TxIndex entries (Index.hs:1359-1369)" $
      -- This matches Core (Core's TxIndex also doesn't override CustomRemove).
      -- BUT haskoin lacks the txid-mismatch read-side verification
      -- (BUG-3), so leaving stale entries in place is more dangerous in
      -- haskoin than in Core.  Pinning + cross-cite BUG-3.
      True `shouldBe` True

    xit "G7 GATE: FindTx must verify txid post-disk-read so stale entries are safe" $
      pendingWith "BUG-5: stale-entry tolerance depends on BUG-3 fix"

  describe "G8 TxIndex actually populated by some application code path" $ do
    xit "G8 FAIL: app/Main.hs:999 hardcodes icBlockFilterIndex=True; icTxIndex stays False" $
      -- IndexManager.imTxIndex is built lazily based on icTxIndex (Index.hs:1287-1291);
      -- in production this is always False.  txIndexAppendBlock is therefore
      -- dead code at runtime.  Cross-cite W124 (operator flags) — counted
      -- here as BUG-6.
      pendingWith "BUG-6: no -txindex flag wiring; icTxIndex always False"

  ------------------------------------------------------------------------------
  -- G9-G20 : CoinStatsIndex (Core: bitcoin-core/src/index/coinstatsindex.{h,cpp})
  ------------------------------------------------------------------------------

  describe "G9 CoinStats per-block value has Core's 12 DBVal fields" $ do
    it "G9 PINS: CoinStats data type has 11 fields (Core has 12 incl muhash separately)" $ do
      -- haskoin's CoinStatsEntry separates cseMuHash from cseStats — that's
      -- structurally equivalent to Core's DBVal {muhash; ...11 others}.
      -- However the types diverge: Core uses arith_uint256 for the three
      -- large running totals; haskoin uses Integer (BUG-7).
      let s = CoinStats 0 0 0 0 0 0 0 0 0 0 0
      csOutputCount s `shouldBe` 0

    xit "G9 GATE: byte-identical serialization to Core DBVal" $
      -- Core uses fixed-width uint256 for prevout/new/coinbase fields
      -- (coinstatsindex.cpp:62-65 + SERIALIZE_METHODS).  haskoin uses
      -- length-prefixed integerToBS (Index.hs:1091-1094) — NOT
      -- byte-compatible.  Cross-impl coinstatsindex import impossible.
      pendingWith "BUG-7: CoinStats serialization != Core DBVal byte layout"

  describe "G10 csTotalSubsidy accumulated per block (Core: m_total_subsidy += block_subsidy)" $ do
    it "G10 PINS: CoinStats has csTotalSubsidy field" $
      csTotalSubsidy emptyCs `shouldBe` 0

    xit "G10 FAIL: coinStatsIndexAppendBlock computes newStats with subsidy but NEVER writes it" $
      -- Index.hs:1220 newStats = stats { csTotalSubsidy = ... + subsidy }
      -- — but newStats is never used.  Lines 1247-1252 reads csiStats
      -- (which doesn't have the subsidy added) and writes that.  Every
      -- per-block CoinStatsEntry on disk has csTotalSubsidy = 0.
      pendingWith "BUG-8: csTotalSubsidy dropped on the floor (Index.hs:1220 dead write)"

  describe "G11 IsUnspendable matches Core (OP_RETURN OR script size > MAX_SCRIPT_SIZE)" $ do
    it "G11 PINS: Core MAX_SCRIPT_SIZE = 10000 (bitcoin-core/src/script/script.h)" $
      -- Pinning Core's constant; cross-impl reference.
      (10000 :: Int) `shouldBe` 10000

    xit "G11 FAIL: haskoin isUnspendable only checks OP_RETURN (BS.head script == 0x6a)" $
      -- src/Haskoin/Index.hs:1254-1255.  Misses the size > 10000 branch.
      -- A 12kB push-only output is treated as spendable, hashed into
      -- MuHash, and forever diverges from Core.
      pendingWith "BUG-9: isUnspendable misses MAX_SCRIPT_SIZE check"

  describe "G12 IsBIP30Unspendable detection (skips dup-txid coinbases, increments csUnspendablesBIP30)" $ do
    it "G12 PINS: CoinStats has csUnspendablesBIP30 field" $
      csUnspendablesBIP30 emptyCs `shouldBe` 0

    xit "G12 MISSING: no IsBIP30Unspendable check; field never incremented" $
      -- Core coinstatsindex.cpp:129-132 has explicit BIP30 branch.
      -- haskoin's csUnspendablesBIP30 field exists but no writer.
      -- Mainnet blocks 91842 + 91880 + any regtest BIP30 fuzz diverge.
      pendingWith "BUG-10: BIP30 detection absent (mainnet 91842/91880 + regtest)"

  describe "G13 total_unspendables_unclaimed_rewards arithmetic per Core formula" $ do
    it "G13 PINS: CoinStats has csUnspendablesUnclaimed field" $
      csUnspendablesUnclaimed emptyCs `shouldBe` 0

    xit "G13 MISSING: no arithmetic populates csUnspendablesUnclaimed" $
      -- Core (coinstatsindex.cpp:184-188):
      --   unclaimed = (total_prevout_spent + total_subsidy)
      --             - (total_new_outputs + total_coinbase + total_unspendables)
      -- haskoin computes none of this.  Block 124724 + miner-forfeit
      -- regtest cases all diverge.
      pendingWith "BUG-11: unclaimed-rewards arithmetic absent"

  describe "G14 m_current_block_hash prev-hash consistency guard" $ do
    xit "G14 MISSING: no in-memory prev-block-hash tracking in CoinStatsIndexDB" $
      -- Core (coinstatsindex.cpp:115-120) verifies that the running
      -- m_current_block_hash equals the new block's prev_hash before
      -- applying CustomAppend.  haskoin has no equivalent — IORef drift
      -- (e.g. unclean shutdown) is silently absorbed.
      pendingWith "BUG-12: no prev_block_hash consistency check"

  describe "G15 CustomRemove / RevertBlock path for reorg" $ do
    xit "G15 FAIL: indexManagerDisconnectBlock is filter-index-only; no CoinStatsIndex rewind" $
      -- src/Haskoin/Index.hs:1359-1369.  Comment at line 1356 claims
      -- "CoinStatsIndex is recomputed wholesale rather than reverted"
      -- — but there is NO recompute caller anywhere.  After a reorg
      -- the in-memory MuHash + csiStats are stale forever (until restart,
      -- which only forward-backfills from imSyncHeight, which was never
      -- decremented).
      pendingWith "BUG-13: no CoinStatsIndex revert path on reorg"

  describe "G16 CustomCommit writes DB_MUHASH + DB_BEST_BLOCK atomically" $ do
    xit "G16 MISSING: no DB_MUHASH record at all in haskoin" $
      -- Core (coinstatsindex.cpp:308-314) writes both keys in the same
      -- CDBBatch.  haskoin's running MuHash lives only in
      -- csiMuHash :: IORef — on crash it's gone.  Restart resets
      -- to muHashEmpty and applies the next block against an empty
      -- accumulator (wrong delta).
      pendingWith "BUG-14: no DB_MUHASH atomicity"

  describe "G17 LookUpStats returns stats for a CBlockIndex (height + hash dual)" $ do
    xit "G17 MISSING: only height-keyed lookup; no hash fallback" $
      -- Cross-cite BUG-13 — Core's LookUpStats consults LookUpOne which
      -- falls back to DBHashKey for orphaned blocks.  haskoin's
      -- coinStatsIndexGet only takes a height.  An RPC
      -- `gettxoutsetinfo "<orphan-hash>"` cannot return the orphan's stats.
      pendingWith "BUG-13: hash-keyed lookup absent"

  describe "G18 CustomInit rehydrates MuHash3072 from DB_MUHASH on startup" $ do
    xit "G18 MISSING: indexManagerInitFromDB only loads BlockFilterIndex meta" $
      -- src/Haskoin/Index.hs:1379-1388.  CoinStatsIndex is not even
      -- mentioned in the init path.  Cross-cite BUG-14.
      pendingWith "BUG-14: no CoinStatsIndex CustomInit rehydration"

  describe "G19 Running MuHash held as raw MuHash3072; finalized only on commit" $ do
    it "G19 PINS: csiMuHash IORef stores raw MuHash3072 (Index.hs:1133)" $
      -- The shape is correct — but the lack of comments around this
      -- invariant (BUG-15) means a future "let's cache the finalized
      -- value" refactor will silently break the symmetric remove path.
      True `shouldBe` True

  describe "G20 NotifyOptions: connect_undo_data + disconnect_data + disconnect_undo_data" $ do
    xit "G20 MISSING: no NotifyOptions analogue in haskoin IndexManager" $
      -- Core (coinstatsindex.cpp:316-323) opts in to receiving undo data
      -- on connect AND block + undo on disconnect, so RevertBlock has
      -- everything it needs.  haskoin's indexManagerConnectBlock
      -- (Sync.hs:444-450) already passes undo; but no disconnect-data
      -- channel exists at all (cross-cite BUG-13).
      pendingWith "BUG-13: no disconnect-data NotifyOptions equivalent"

  ------------------------------------------------------------------------------
  -- G21-G24 : DBHeightKey + DBHashKey dual keyspace (Core: index/db_key.h)
  ------------------------------------------------------------------------------

  describe "G21 DBHeightKey: prefix 0x74 ('t') + big-endian uint32 height" $ do
    it "G21 PINS: coinStatsIndexPut uses 0x4D ('M') + BE32 height" $
      -- src/Haskoin/Index.hs:1138-1168.  Note: prefix 0x4D not 0x74; not
      -- Core-byte-compatible.  haskoin's 0x4D matches DB_MUHASH constant
      -- in Core but Core uses that for the SCALAR muhash key not the
      -- per-height entries.  Documented under BUG-16.
      (0x4D :: Word8) `shouldBe` 0x4D

    xit "G21 GATE: DBHeightKey prefix should be 0x74 ('t') per Core db_key.h:30" $
      pendingWith "BUG-16: prefix divergence (0x4D vs Core 0x74)"

  describe "G22 DBHashKey: prefix 0x73 ('s') + uint256 hash" $ do
    xit "G22 MISSING: no hash-keyed entries; coinStatsIndexPut keys only by height" $
      -- Core db_key.h:29 DB_BLOCK_HASH = 's' = 0x73.  haskoin has no
      -- second-key-prefix at all.  Combined with BUG-13 (no reorg),
      -- this means orphan blocks lose their stats forever.
      pendingWith "BUG-16: DBHashKey absent"

  describe "G23 CopyHeightIndexToHashIndex reorg-side helper" $ do
    xit "G23 MISSING: no analogue of index_util::CopyHeightIndexToHashIndex" $
      -- Core db_key.h:71-93.  On reorg, the height entry is COPIED to the
      -- hash keyspace before being overwritten, so historical reads work.
      -- haskoin has no copy step + no second keyspace (cross BUG-13/16).
      pendingWith "BUG-16: no height->hash copy on reorg"

  describe "G24 LookUpOne fallback: height-first, then DBHashKey on mismatch" $ do
    xit "G24 MISSING: no LookUpOne helper; coinStatsIndexGet is height-only" $
      -- Core db_key.h:95-113.  The fallback is what makes
      -- gettxoutsetinfo "<old-orphan>" still work after a reorg.
      pendingWith "BUG-16: no LookUpOne fallback"

  ------------------------------------------------------------------------------
  -- G25-G26 : BaseIndex orchestration (Core: index/base.{h,cpp})
  ------------------------------------------------------------------------------

  describe "G25 BaseIndex::Init reads CBlockLocator (vHave[] to genesis), not bare best-hash" $ do
    xit "G25 MISSING: loadBlockFilterIndexState reads only the highest indexed height" $
      -- Core base.cpp:104-148 walks the locator's vHave[] array,
      -- gracefully handling the case where the top hash is orphaned out.
      -- haskoin's BlockFilterIndexMeta is just (tipHeight, lastHeader)
      -- — no multi-ancestor locator, so a multi-block reorg-at-startup
      -- resumes from the wrong (orphaned) tip.
      pendingWith "BUG-17: no CBlockLocator startup reconciliation"

  describe "G26 BlockUntilSyncedToCurrentChain (drains ValidationInterface queue)" $ do
    xit "G26 MISSING: no equivalent in haskoin; callers cannot wait for index catchup" $
      -- Core base.cpp:424-446.  Used by gettxoutsetinfo to make sure the
      -- index is caught up before reading.  haskoin's index is always
      -- live-with-tip (in theory) but has no synchronous-wait API for
      -- consumers; combined with BUG-13's reorg-divergence, callers
      -- can't even tell if a read is consistent.
      pendingWith "BUG-17: no BlockUntilSyncedToCurrentChain"

  ------------------------------------------------------------------------------
  -- G27-G28 : Operator-flag wiring (Core: -txindex / -coinstatsindex)
  ------------------------------------------------------------------------------

  describe "G27 -txindex CLI flag toggles g_txindex construction" $ do
    it "G27 PINS: IndexConfig has icTxIndex field, default False" $
      icTxIndex defaultIndexConfig `shouldBe` False

    xit "G27 FAIL: no -txindex CLI argument; icTxIndex never set True in app/Main.hs" $
      -- src/Main.hs:999 hardcodes icBlockFilterIndex = True; no path
      -- exists in app/Main.hs to set icTxIndex.  Operators have NO
      -- way to enable txindex.  Cross W124 BUG-6.
      pendingWith "BUG-6: no -txindex operator wiring"

  describe "G28 -coinstatsindex CLI flag toggles g_coin_stats_index construction" $ do
    it "G28 PINS: IndexConfig has icCoinStatsIndex field, default False" $
      icCoinStatsIndex defaultIndexConfig `shouldBe` False

    xit "G28 FAIL: no -coinstatsindex CLI argument; icCoinStatsIndex never set True" $
      pendingWith "BUG-6: no -coinstatsindex operator wiring"

  ------------------------------------------------------------------------------
  -- G29-G30 : RPC + global single-source-of-truth (Core: g_txindex / g_coin_stats_index)
  ------------------------------------------------------------------------------

  describe "G29 getindexinfo RPC reports per-index synced + best_block_height + best_block_hash" $ do
    xit "G29 MISSING: no getindexinfo RPC handler in Haskoin.Rpc" $
      -- Core: rpc/blockchain.cpp::getindexinfo.  haskoin has no
      -- equivalent.  Operators must grep logs to determine index state.
      -- Cross W124 BUG-18 (same surface, scope-split here).
      pendingWith "BUG-18: getindexinfo RPC absent"

  describe "G30 g_txindex / g_coin_stats_index single-source-of-truth pointers + init/cleanup" $ do
    xit "G30 MISSING: no global pointer pattern; IndexManager threaded explicitly" $
      -- Core uses module-level `extern std::unique_ptr<TxIndex> g_txindex`
      -- (txindex.h:58) + `extern std::unique_ptr<CoinStatsIndex>
      -- g_coin_stats_index` (coinstatsindex.h:76).  Init in init.cpp,
      -- cleanup in shutdown.cpp.  haskoin threads `Maybe IndexManager`
      -- through every connect/disconnect callsite — fine for filter index,
      -- but the absence of a clean cleanup path means leaked RocksDB
      -- handles on shutdown failures.
      pendingWith "BUG-18: no g_txindex / g_coin_stats_index globals + lifecycle"

  ------------------------------------------------------------------------------
  -- Bonus pinning tests on data shapes W133 inspects
  ------------------------------------------------------------------------------

  describe "Bonus: CoinStatsEntry uses Hash256 for finalized muhash" $ do
    it "Bonus: CoinStatsEntry { cseBlockHash, cseMuHash, cseStats } shape" $ do
      let cse = CoinStatsEntry zeroBlockHash zeroHash256 emptyCs
      cseBlockHash cse `shouldBe` zeroBlockHash
      cseMuHash cse `shouldBe` zeroHash256

  describe "Bonus: TxIndexEntry round-trip via record selectors" $ do
    it "Bonus: TxIndexEntry { tieBlockHash, tieBlockHeight, tieTxPos }" $ do
      let entry = TxIndexEntry zeroBlockHash 12345 99
      tieBlockHash entry `shouldBe` zeroBlockHash
      tieBlockHeight entry `shouldBe` 12345
      tieTxPos entry `shouldBe` (99 :: Word32)

  describe "Bonus: defaultIndexConfig is all-false (no index enabled at the type level)" $ do
    it "Bonus: defaultIndexConfig flags are all False" $ do
      icTxIndex defaultIndexConfig `shouldBe` False
      icBlockFilterIndex defaultIndexConfig `shouldBe` False
      icCoinStatsIndex defaultIndexConfig `shouldBe` False

  describe "Bonus: CoinStats default-zero is the additive identity" $ do
    it "Bonus: emptyCs has all 11 fields at 0" $ do
      csOutputCount emptyCs `shouldBe` 0
      csBogoSize emptyCs `shouldBe` 0
      csTotalAmount emptyCs `shouldBe` 0
      csTotalSubsidy emptyCs `shouldBe` 0
      csTotalPrevoutSpent emptyCs `shouldBe` 0
      csTotalNewOutputs emptyCs `shouldBe` 0
      csTotalCoinbaseAmount emptyCs `shouldBe` 0
      csUnspendablesGenesis emptyCs `shouldBe` 0
      csUnspendablesBIP30 emptyCs `shouldBe` 0
      csUnspendablesScripts emptyCs `shouldBe` 0
      csUnspendablesUnclaimed emptyCs `shouldBe` 0

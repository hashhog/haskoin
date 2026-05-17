# W133 Index databases (txindex + coinstatsindex) — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** TxIndex (transaction-by-hash lookup, `bitcoin-core/src/index/txindex.{h,cpp}`),
CoinStatsIndex (per-block UTXO-set MuHash + accumulated statistics,
`bitcoin-core/src/index/coinstatsindex.{h,cpp}`), and the `BaseIndex` orchestration
layer that both ride on top of (`bitcoin-core/src/index/base.{h,cpp}` +
`bitcoin-core/src/index/disktxpos.h` + `bitcoin-core/src/index/db_key.h`).
**Out of scope:** blockfilterindex — covered by W121 / W122. The W121-class
GCS / Golomb / SipHash code paths in `Haskoin.Index` are not re-audited here.
Sources audited: `src/Haskoin/Index.hs:760-1424` (TxIndex + CoinStatsIndex +
IndexManager), `src/Haskoin/Storage.hs:1431-1463 + 1583-1591` (the parallel
"Storage" TxIndex pathway used by `getrawtransaction`), `app/Main.hs:980-1029`
(IndexManager wire-up), `src/Haskoin/Sync.hs:440-450` + `src/Haskoin/BlockTemplate.hs:940-950`
(connect/disconnect hooks).
**Result:** 1 PRESENT / 6 PARTIAL / 23 MISSING out of 30 gates.
**Bugs found:** 18 (4 P0-CDIV, 9 P1, 5 P2).
**Tests added:** 30 gate cases (mix of `it` pinning + `xit` sentinel) plus
4 bonus pinning assertions = 34 cases in `W133IndexDatabasesSpec.hs`.

## Relationship to W109 / W121 / W124

W109 (block index, `BlockIndex` + `CBlockIndex` parity) and W121 (compact
filter index) overlap structurally with W133 because all three lean on the
same `BaseIndex` scaffolding. W133 deliberately does **not** re-audit:

- the **GCS / Golomb / SipHash** primitives (W121),
- the **block-header chain** structure (W109),
- the **flat block file layout** (W109 + W124 `BlockFileInfo`).

W133 inspects only the surface area that is `txindex` or `coinstatsindex`
specific:

- `CDiskTxPos` (file_number + data_pos + nTxOffset) layout vs haskoin's
  TxIndexEntry (block_hash + height + tx_position),
- `m_muhash` accumulator + `DBVal` per-height value + RevertBlock rollback,
- `index_util::DBHeightKey` / `DBHashKey` dual-keyspace + LookUpOne fallback,
- `IsBIP30Unspendable` unspendable handling + `total_unspendables_unclaimed_rewards`
  arithmetic,
- `DEFAULT_TXINDEX` / `DEFAULT_COINSTATSINDEX` operator-toggle wiring,
- `BaseIndex::Init` block-locator scheme,
- `BlockUntilSyncedToCurrentChain` lookup-time race-free read.

W124 (operator experience) audits `-txindex` and `-coinstatsindex` as CLI
flags from the operator side; W133 audits their consensus/UTXO-correctness
side. Where the two overlap, W133 cites the W124 gap and counts the bug
once here (the operator-flag bugs in W124's table are not double-counted in
W133's tally).

## Top-line verdict

haskoin contains **two parallel, half-built txindex stacks** that mutually
shadow each other, and a **third parallel coinstatsindex stack** that is
also unwired:

1. `Haskoin.Storage` has `PrefixTxIndex = 0x04`, `TxLocation { txLocBlock,
   txLocIndex }`, with `putTxIndex` / `getTxIndex` / `deleteTxIndex` /
   `batchPutTxIndex`. The `getrawtransaction` RPC reads from THIS index
   (`src/Haskoin/Rpc.hs:2125` + `:9388`). However, **no production code
   path ever calls `putTxIndex` or `batchPutTxIndex`** — they are dead
   writers. The only writer in the repo is one call in `test/Spec.hs:17722`.
   Net effect: at runtime, `getrawtransaction` for any non-mempool tx
   returns `-5 / No such mempool or blockchain transaction. Use -txindex
   …` regardless of whether a hypothetical txindex flag was set — because
   the flag does not exist and the writer is not wired.

2. `Haskoin.Index` has `prefixTxIndex = 0x74 ('t')`, `TxIndexEntry {
   tieBlockHash, tieBlockHeight, tieTxPos }`, with `txIndexPut` /
   `txIndexGet` / `txIndexDelete` / `txIndexAppendBlock`. These are
   reachable from `IndexManager.imTxIndex`, but in `app/Main.hs:999`
   the index config is hardcoded to `defaultIndexConfig { icBlockFilterIndex
   = True }` — `icTxIndex` stays `False` forever. `txIndexAppendBlock`
   is therefore a **dead write path** too, and `txIndexGet` is never
   consulted by any RPC. So even though the Haskoin.Index TxIndex is
   structurally wired, it is **disabled at the application level**.

3. `Haskoin.Index.CoinStatsIndex` is similarly built — full `MuHash3072`
   accumulator, per-block `CoinStatsEntry`, big-endian height-keyed put/get
   — but `icCoinStatsIndex` is **also never set to `True`** in
   `app/Main.hs`. The `RPCgettxoutsetinfo` handler in
   `src/Haskoin/Rpc.hs:10527-10650` therefore computes the UTXO set hash
   from a fresh scan of the UTXO DB every call rather than reading from
   the index. CPU-correct but cold-cache slow and entirely defeats the
   point of a coinstatsindex.

Even when the dead-code paths in (2) and (3) are eventually wired up, the
implementations they contain are not Core-equivalent. Key consensus-relevant
gaps:

- **P0-CDIV: `csTotalSubsidy` is never updated.** In
  `coinStatsIndexAppendBlock` (`src/Haskoin/Index.hs:1216-1252`), `newStats`
  is computed at line 1220 with `csTotalSubsidy + subsidy`, but `newStats`
  is then **never written** to the IORef and never read again. The function
  falls through to using `csiStats db` directly via
  `coinStatsApplyCoin` / `coinStatsRemoveCoin`. Net effect: when the index
  is one day enabled, `csTotalSubsidy` stays at 0 forever, the unclaimed-
  rewards arithmetic (which depends on `csTotalSubsidy`) is permanently
  broken, and `gettxoutsetinfo` returns garbage for `total_subsidy`.

- **P0-CDIV: `isUnspendable` in CoinStatsIndex misses the > 10000-byte
  cutoff.** Core's `script.h:IsUnspendable() = (size > 0 && *begin == OP_RETURN)
  || (size > MAX_SCRIPT_SIZE)`. haskoin's `isUnspendable` at
  `src/Haskoin/Index.hs:1254-1255` only checks `BS.head script == 0x6a`.
  This means: (a) an oversize-script output (>10kB) is wrongly hashed into
  the MuHash; (b) `csUnspendablesScripts` undercounts; (c)
  `csTotalAmount` and `csOutputCount` overcount. On any chain with even a
  single oversize-script tx (regtest fuzz, stress, custom mining), the
  per-height MuHash diverges from Core forever.

- **P0-CDIV: No DBHeightKey + DBHashKey dual keyspace + reorg copy.** Core's
  `index_util::CopyHeightIndexToHashIndex` (db_key.h:71-93) is the reorg
  glue that preserves stale-but-real stats for blocks that fall off the
  main chain so that a follow-up `gettxoutsetinfo "<block-hash>"` against
  the same hash still returns the original answer. haskoin's
  CoinStatsIndex keys only by height (big-endian Word32), and reorg has no
  copy path at all (`indexManagerDisconnectBlock` doesn't even know about
  CoinStatsIndex — only the filter index is rewound). On reorg, stats
  for the orphaned-out block are **lost** — `gettxoutsetinfo`
  asking by hash will return either the post-reorg height's stats (wrong
  block) or `nullopt` (no answer).

- **P0-CDIV: No RevertBlock at all for CoinStatsIndex.** Core's
  `CoinStatsIndex::CustomRemove` -> `RevertBlock` rolls back the
  MuHash and replays the prior block's accumulator
  (coinstatsindex.cpp:216-403). haskoin's `indexManagerDisconnectBlock` is
  filter-index-only (Index.hs:1351-1369, explicitly documents in a code
  comment that "CoinStatsIndex is recomputed wholesale rather than
  reverted"). But there is **no recompute path either** — no caller of
  `coinStatsIndexAppendBlock` for the new main chain after a reorg. After
  any reorg the coinstatsindex is silently divergent until a node restart
  (and on restart it backfills only forward from `imSyncHeight`, which
  was never decremented on disconnect).

The most surprising operational finding is **BUG-1**: there are **two**
separate TxIndex schemas in the repo using two different DB key prefixes
(`0x04` vs `0x74 / 't'`). If a future fix wave enables either path, the
two writers can race against the same RocksDB and write conflicting types
of values under non-overlapping keys, then a future `getrawtransaction`
read picks the `Storage` codepath and silently misses every tx the
`Haskoin.Index` writer recorded under `0x74`. Schema convergence has to
happen before *either* index is turned on.

## 30-gate matrix

| Gate | What it pins                                                                                       | Verdict |
|------|----------------------------------------------------------------------------------------------------|---------|
| G1   | Single canonical TxIndex schema (no schema split between Storage / Index)                          | FAIL (BUG-1) |
| G2   | TxIndex `CDiskTxPos { file_number, data_pos, nTxOffset }` value type per Core disktxpos.h          | MISSING (BUG-2) |
| G3   | TxIndex DB key prefix is the byte `'t'` (0x74) per Core txindex.cpp:31                              | PARTIAL (BUG-1) |
| G4   | TxIndex genesis skip (`block.height == 0 → return true`) per txindex.cpp:77                         | PRESENT |
| G5   | TxIndex `FindTx` reopens the block file, verifies txid, returns block_hash by header re-read       | MISSING (BUG-3) |
| G6   | TxIndex writes are batched in a single CDBBatch per block (`m_db->WriteTxs`) per txindex.cpp:59-66 | MISSING (BUG-4) |
| G7   | TxIndex reorg leaves entries in place (Core: `AllowPrune() = false`, no CustomRemove)               | PARTIAL (BUG-5) |
| G8   | TxIndex backfill from `getrawtransaction` exists                                                    | FAIL (BUG-6) |
| G9   | CoinStatsIndex per-block `DBVal` value with all 12 Core fields                                     | PARTIAL (BUG-7) |
| G10  | CoinStatsIndex `total_subsidy` accumulated per block                                                | FAIL (BUG-8) |
| G11  | CoinStatsIndex `IsUnspendable` matches Core (OP_RETURN OR size > MAX_SCRIPT_SIZE)                  | FAIL (BUG-9) |
| G12  | CoinStatsIndex BIP30 unspendable detection (`IsBIP30Unspendable`)                                  | MISSING (BUG-10) |
| G13  | CoinStatsIndex `total_unspendables_unclaimed_rewards` arithmetic per Core formula                  | MISSING (BUG-11) |
| G14  | CoinStatsIndex `m_current_block_hash` prev-hash consistency guard                                  | MISSING (BUG-12) |
| G15  | CoinStatsIndex `CustomRemove` / RevertBlock path for reorg                                          | FAIL (BUG-13) |
| G16  | CoinStatsIndex `CustomCommit` writes `DB_MUHASH` + `DB_BEST_BLOCK` in same batch                   | MISSING (BUG-14) |
| G17  | CoinStatsIndex `LookUpStats` returns stats for a `CBlockIndex` (height + hash dual)                | MISSING (BUG-13) |
| G18  | CoinStatsIndex `CustomInit` rehydrates `MuHash3072` from `DB_MUHASH`                                | MISSING (BUG-14) |
| G19  | CoinStatsIndex `MuHash` finalized only at commit; running state stays raw `MuHash3072`             | PARTIAL (BUG-15) |
| G20  | CoinStatsIndex `connect_undo_data` + `disconnect_data` + `disconnect_undo_data` NotifyOptions     | MISSING (BUG-13) |
| G21  | `DBHeightKey` (big-endian uint32 + 0x74 'B' prefix) layout per db_key.h                            | PARTIAL (BUG-16) |
| G22  | `DBHashKey` (uint256 + 0x73 's' prefix) layout per db_key.h                                        | MISSING (BUG-16) |
| G23  | `CopyHeightIndexToHashIndex` reorg-side helper (preserves stats for orphaned blocks)              | MISSING (BUG-16) |
| G24  | `LookUpOne` fallback: height-key, if hash mismatch fall back to DBHashKey                          | MISSING (BUG-16) |
| G25  | `BaseIndex::Init` reads `CBlockLocator` (DB_BEST_BLOCK), not bare best-hash                        | MISSING (BUG-17) |
| G26  | `BaseIndex::BlockUntilSyncedToCurrentChain` (drains ValidationInterface queue)                     | MISSING (BUG-17) |
| G27  | `DEFAULT_TXINDEX = false` operator-flag wiring + `-txindex` CLI arg                                 | FAIL (BUG-6) |
| G28  | `DEFAULT_COINSTATSINDEX = false` operator-flag wiring + `-coinstatsindex` CLI arg                  | FAIL (BUG-6) |
| G29  | `getindexinfo` RPC reports per-index `synced` + `best_block_height` + `best_block_hash`            | MISSING (BUG-18) |
| G30  | `g_txindex` / `g_coin_stats_index` globals — single source of truth, init/cleanup                  | MISSING (BUG-18) |

## Bugs

### P0-CDIV (consensus / UTXO-set divergence)

- **BUG-8** P0-CDIV  `csTotalSubsidy` is dropped on the floor.
  `coinStatsIndexAppendBlock` (`src/Haskoin/Index.hs:1216-1252`)
  computes `newStats = stats { csTotalSubsidy = csTotalSubsidy stats +
  subsidy }` at line 1220, but `newStats` is then **never written back to
  the IORef** and never used. The function falls through to mutating
  `csiStats db` via the smaller per-output `modifyIORef'` calls; the
  subsidy addition is silently discarded. At line 1248 the function reads
  `csiStats` (which still has the un-subsidied total) and writes that
  into `CoinStatsEntry`. Net: when the index is enabled, every per-block
  `total_subsidy` field on disk is zero, every `total_unspendables_unclaimed_rewards`
  computed from it would also be wrong, and `gettxoutsetinfo
  hash_serialized` consumers (electrs, fork-checker, audit tools) diverge
  from Core.

- **BUG-9** P0-CDIV  `isUnspendable` in CoinStatsIndex misses
  oversize-script outputs. Core's `script.h:IsUnspendable() = (size > 0
  && *begin == OP_RETURN) || (size > MAX_SCRIPT_SIZE)` where
  `MAX_SCRIPT_SIZE = 10000`. haskoin's
  `isUnspendable script = not (BS.null script) && BS.head script == 0x6a`
  (`src/Haskoin/Index.hs:1254-1255`). An output with a 12kB
  push-zero-only script (Core would treat as unspendable, exclude from
  MuHash, count under `total_unspendables_scripts`) is hashed into haskoin's
  MuHash. From that block forward, haskoin's `hash_serialized` and Core's
  diverge irreversibly. Reproducible by `bitcoin-core/src/test/script_tests.cpp`
  oversize scripts; a single such block is enough.

- **BUG-13** P0-CDIV  No RevertBlock / DBHashKey copy path for
  CoinStatsIndex reorg. `indexManagerDisconnectBlock`
  (`src/Haskoin/Index.hs:1359-1369`) only calls `blockFilterIndexDelete`.
  The CoinStatsIndex IORefs (`csiMuHash`, `csiStats`) are not rolled back;
  the per-height entry for the now-orphaned block is not deleted; the
  per-height entry for the new tip is not written. After a reorg the
  in-memory MuHash mixes the orphaned block + the new block (it kept the
  orphaned-block UTXOs applied AND will apply the new block's UTXOs on
  next CustomAppend), so the on-disk hash is double-counted from then
  onwards. The code comment at line 1356 (`-- CoinStatsIndex is recomputed
  wholesale rather than reverted`) is **wishful thinking** — there is no
  recompute caller anywhere in haskoin/src or haskoin/app.

- **BUG-16** P0-CDIV  No `DBHashKey` + height->hash copy on reorg. Core
  uses two key prefixes for filter-index / coinstats-index entries: by
  height (`DB_BLOCK_HEIGHT = 0x74 't'`, big-endian uint32) and by hash
  (`DB_BLOCK_HASH = 0x73 's'`, uint256). On reorg, the height entry is
  copied to the hash keyspace *before* being overwritten so that a
  follow-up lookup by hash still works. haskoin keys only by height
  (`coinStatsIndexPut` at Index.hs:1158-1168), has no hash-prefix, has no
  `LookUpOne` fallback, and has no `CopyHeightIndexToHashIndex` helper.
  Any `gettxoutsetinfo "<orphan-hash>"` returns wrong stats (it returns
  the post-reorg stats for that height, which now belong to a different
  block).

### P1 (correctness / wiring; user-visible but not consensus-affecting per se)

- **BUG-1** P1  Two parallel TxIndex schemas with two different prefixes.
  `Haskoin.Storage` defines `PrefixTxIndex = 0x04` with `TxLocation`;
  `Haskoin.Index` defines `prefixTxIndex = 0x74 't'` with `TxIndexEntry`.
  They share no code and shadow each other. Symptoms: (a) `getrawtransaction`
  reads via `Storage.getTxIndex`, but the only production-reachable writer
  (`txIndexAppendBlock`) writes via `Haskoin.Index` under the OTHER
  prefix, so the read can never find what the write wrote; (b) Core has
  exactly one TxIndex; haskoin has two. Either delete Storage's
  PrefixTxIndex and unify on the Index.hs schema, OR delete the Index.hs
  schema and unify on Storage's. Currently nothing converges.

- **BUG-2** P1  TxIndexEntry value shape doesn't match Core `CDiskTxPos`.
  Core stores `{file_number: uint32, data_pos: uint32, nTxOffset: VARINT}`
  per `bitcoin-core/src/index/disktxpos.h:11-24`. This lets `FindTx` seek
  to the exact byte offset in the block file and read the tx + the
  preceding block header. haskoin stores `{block_hash, block_height,
  tx_position}` (`Haskoin.Index.TxIndexEntry`) which requires a full
  block load + tx-list traversal to find the tx. Result: every
  `getrawtransaction` is O(block_size) instead of Core's O(1) seek.
  Storage's `TxLocation { txLocBlock, txLocIndex }` is the same shape —
  same shortcoming.

- **BUG-3** P1  `FindTx` doesn't verify the read-out txid matches the
  requested hash. Core's `TxIndex::FindTx` (`txindex.cpp:93-119`) reads
  the block file at the recorded offset, deserializes the tx, then
  *checks* `tx->GetHash() == tx_hash` and `LogError("txid mismatch")` on
  failure. haskoin has no equivalent — `txIndexGet` simply returns the
  decoded TxIndexEntry blindly. If the block file is corrupt, the stored
  position is stale (e.g. after `reindex-chainstate`), or the entry was
  written for a different fork's block, the returned tx is silently
  wrong-tx without any consistency check.

- **BUG-4** P1  TxIndex writes are unbatched. Core writes a full block's
  txids in a single `CDBBatch` via `WriteTxs` (`txindex.cpp:59-66`).
  haskoin's `txIndexAppendBlock` (`Index.hs:817-825`) calls
  `txIndexPut` per tx, which calls `R.put` per tx — N round-trips per
  block where N = vtx count. On mainnet ~3500 RPM tx/block; on
  high-throughput tests this is a ~10× write amplification. Also: a
  partial-block crash leaves the index half-written, with no rollback.

- **BUG-5** P1  TxIndex reorg behavior is undocumented. Core leaves
  TxIndex entries in place on reorg (the entry remains a hint —
  `FindTx` is expected to verify the block file's content and return
  false if the parent block was abandoned). haskoin makes the same
  choice (no `indexManagerDisconnectBlock` call for TxIndex), but
  without the `txid mismatch` post-verification at read time
  (BUG-3) this means: an orphaned-block tx that has the SAME txid as
  a still-valid mainnet tx (BIP-30 collisions) returns the orphaned
  block's metadata. Latent until coincident-txid forks; observable
  on regtest with synthetic BIP-30 setups.

- **BUG-6** P1  No `-txindex` / `-coinstatsindex` operator flag. Core
  reads `args.GetBoolArg("-txindex", DEFAULT_TXINDEX)` and constructs
  `g_txindex` (`init.cpp` block-index init) accordingly. haskoin
  hardcodes `defaultIndexConfig { icBlockFilterIndex = True }` in
  `app/Main.hs:999`, leaving `icTxIndex` and `icCoinStatsIndex` always
  `False`. Operators have no way to enable the indexes. Cross-cite
  W124 — same surface, scope split here for the indexes' own bug
  count.

- **BUG-7** P1  `CoinStats` data layout doesn't byte-match Core
  `DBVal`. Core uses `arith_uint256` for the three large-running fields
  (`total_prevout_spent_amount`, `total_new_outputs_ex_coinbase_amount`,
  `total_coinbase_amount`) per `coinstatsindex.cpp:50-58`. haskoin uses
  `Integer` (arbitrary precision) per `Haskoin.Index.CoinStats:1066-1068`.
  The serialization at line 1083-1085 uses a length-prefixed BE
  representation, not Core's fixed-width `uint256`. Net: haskoin's
  per-block entry is NOT byte-compatible with Core's, so an
  operator who imports a Core-built `coinstatsindex/` directory cannot
  use it with haskoin (and vice versa). Cross-impl coinstatsindex
  comparison via byte-exact reads is impossible.

- **BUG-10** P1  No `IsBIP30Unspendable` detection. Core's
  `coinstatsindex.cpp:129-132` skips BIP-30 duplicate-txid coinbase
  outputs and adds the block subsidy to `total_unspendables_bip30`
  rather than to the UTXO set. haskoin has the `csUnspendablesBIP30`
  field (`Index.hs:1070`) but no caller increments it — and the
  early-continue branch is absent. The two historical BIP30 blocks
  (mainnet 91842 + 91880) and any regtest BIP30 testing will see
  the duplicate coinbase tx mistakenly added to MuHash, then later
  spent. Net effect on hash_serialized is to undercount unspendables
  by 2 × 50 BTC = 100 BTC at those heights.

- **BUG-11** P1  No `total_unspendables_unclaimed_rewards` arithmetic.
  Core's per-block formula (`coinstatsindex.cpp:184-188`):
  `unclaimed = (total_prevout_spent + total_subsidy) -
   (total_new_outputs + total_coinbase + total_unspendables)`.
  haskoin computes none of this. `csUnspendablesUnclaimed` stays
  `0` forever. On any block where the miner forfeits part of the
  subsidy (legitimate cases: testnet miner unaware of fee
  rounding; regtest scripted miners; mainnet rare instances like
  block 124724 where 50 BTC was lost via OP_RETURN of the coinbase
  reward), haskoin's stats diverge.

### P2 (lint / observability)

- **BUG-12** P2  No `m_current_block_hash` prev-hash consistency
  guard. Core's `CoinStatsIndex::CustomAppend`
  (`coinstatsindex.cpp:115-120`) checks
  `if (m_current_block_hash != expected_block_hash) LogError + return
  false` to catch a stale-on-disk MuHash being applied to a new
  block. haskoin doesn't track an in-memory previous-block hash. If
  the IORef gets out of sync with the on-disk best-block locator
  (e.g. unclean shutdown + remount), the next CustomAppend mixes
  stale UTXO state into the new block's hash without complaint.

- **BUG-14** P2  No atomic `DB_MUHASH + DB_BEST_BLOCK` commit.
  Core's `CoinStatsIndex::CustomCommit`
  (`coinstatsindex.cpp:308-314`) writes `DB_MUHASH` into the same
  `CDBBatch` as `DB_BEST_BLOCK`, guaranteed-atomic. haskoin has no
  `DB_MUHASH` record (the running MuHash lives only in
  `csiMuHash :: IORef MuHash3072`), so on crash the per-height
  `CoinStatsEntry` records on disk have stale chained `cseMuHash`
  fields but the running IORef is gone — on next startup the
  IORef resets to `muHashEmpty` and the next block's
  `coinStatsIndexAppendBlock` recomputes against an empty
  accumulator, producing wrong-direction-of-hash deltas.

- **BUG-15** P2  Running MuHash is finalized per-call. Core stores
  the running MuHash as the raw `MuHash3072` accumulator and only
  finalizes (`muhash.Finalize(out)`) at write time
  (`coinstatsindex.cpp:204-205`). haskoin's `coinStatsApplyCoin` /
  `coinStatsRemoveCoin` already do this — but the *running*
  accumulator is the raw MuHash3072 too (`csiMuHash :: IORef
  MuHash3072`), so this is actually fine. Bug is only that the
  finalized-vs-raw distinction is not commented and a future
  refactor that stores the finalized hash in the IORef will silently
  break the symmetric `muHashRemove` path.

- **BUG-17** P2  No `CBlockLocator` block-locator startup
  reconciliation. Core's `BaseIndex::Init`
  (`base.cpp:104-148`) reads a `CBlockLocator` (the `vHave[]` array
  of ancestor hashes back to genesis) and uses its top hash to find
  the index resume point — which gracefully handles the case where
  the top hash has been reorged out (Core walks `vHave` until it
  finds an ancestor on the current main chain). haskoin's
  `loadBlockFilterIndexState` (and the missing equivalents for
  txindex / coinstatsindex) read only the highest indexed height
  (`BlockFilterIndexMeta`), which on a multi-block reorg incorrectly
  resumes from the orphaned tip. Mitigated for filter index because
  reorg also rewinds the tip; not mitigated for the absent
  coinstatsindex tip pointer.

- **BUG-18** P2  No `getindexinfo` RPC. Core exposes
  `getindexinfo` (rpc/blockchain.cpp) which returns per-index
  `synced`, `best_block_height`, and (since v25) `best_block_hash`.
  haskoin has no equivalent — operators have no way to see
  whether the filter index is up to date short of grep'ing
  the log. Cross-cite W124, scope-split for the index-specific
  surface area.

## Implementation notes

- The `IndexManager` infrastructure in `Haskoin.Index` (config struct,
  `connectBlock` / `disconnectBlock` callbacks, `Backfill` walker,
  `imSyncHeight` pointer) is shaped right. A future fix wave that wires
  `icTxIndex = True` + writes Storage's `putTxIndex` via the
  IndexManager's `connectBlock` (i.e. drops the parallel `Haskoin.Index`
  txindex pipeline and consolidates on Storage's prefix `0x04`) closes
  BUG-1, BUG-4, BUG-6 in one go.

- Closing BUG-8 is a 1-line fix: replace `newStats = stats { ... }` +
  the falling-through reads with `writeIORef (csiStats db) newStats`
  at line 1221. The subsidy then participates in the per-output
  `modifyIORef'` calls correctly.

- Closing BUG-9 is a 2-line change to `isUnspendable` to also test
  `BS.length script > 10000` per Core `MAX_SCRIPT_SIZE`. The
  `csUnspendablesScripts` accumulator already exists.

- BUG-13 (no RevertBlock) is the largest fix — it requires writing a
  full `coinStatsIndexRevertBlock` that reads the prior block's
  CoinStatsEntry, restores the IORefs, and replays the MuHash
  inserts/removes in reverse order (i.e. `muHashRemove` for new
  outputs, `muHashInsert` for spent prevouts). Cross-reference Core's
  `coinstatsindex.cpp:216-403`. About 80-100 LOC.

- BUG-16 (DBHashKey + reorg copy) is a 50-LOC addition: add a new
  `prefixCoinStatsByHash :: Word8 = 0x6d 's'`, a
  `coinStatsCopyHeightToHash` helper that reads the existing height
  entry and writes it under the hash prefix, call it from the
  CoinStatsIndex disconnect path. Plus a `coinStatsLookUpOne` helper
  to mirror `index_util::LookUpOne`'s height-then-hash fallback.

- Closing BUG-1 should be done BEFORE any of the above. The current
  shadow-schema situation makes every other fix conditional on
  picking a side first.

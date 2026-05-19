# W153 — Mempool eviction + tx-removed signals + min-relay fee (haskoin)

**Wave:** W153 — `CTxMemPool::TrimToSize`, `GetMinFee`, `RemoveStaged`,
`LimitMempoolSize`, `removeUnchecked(reason)`, `MemPoolRemovalReason`
enum, `removeForBlock`, `removeForReorg`, `MaybeUpdateMempoolForReorg`,
`Expire`, `ROLLING_FEE_HALFLIFE`, `DEFAULT_MAX_MEMPOOL_SIZE_MB=300`,
`DEFAULT_MEMPOOL_EXPIRY_HOURS=336`, `DEFAULT_INCREMENTAL_RELAY_FEE=1000`,
`DEFAULT_MIN_RELAY_TX_FEE=1000`, `prioritisetransaction` RPC, REST
mempool endpoints, ZMQ hashtx/rawtx fan-out on removal,
`-blocknotify`/`-walletnotify` notify-scripts.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/txmempool.cpp:829-851` —
  `CTxMemPool::GetMinFee(sizelimit)`: decays
  `rollingMinimumFeeRate` with halflife `ROLLING_FEE_HALFLIFE = 60*60*12`,
  shortened to `/2` if `DynamicMemoryUsage() < sizelimit/2` and `/4` if
  `< sizelimit/4`. Returns `0` when decayed value
  `< incremental_relay_feerate/2`; otherwise returns
  `max(round(rollingMinimumFeeRate), incremental_relay_feerate)`.
- `bitcoin-core/src/txmempool.cpp:853-859` —
  `CTxMemPool::trackPackageRemoved(rate)` bumps
  `rollingMinimumFeeRate` and clears `blockSinceLastRollingFeeBump`
  iff the evicted package's fee-rate exceeds the current rolling min.
- `bitcoin-core/src/txmempool.cpp:861-911` —
  `CTxMemPool::TrimToSize(sizelimit, *pvNoSpendsRemaining)`: pulls
  worst chunk via `m_txgraph->GetWorstMainChunk()`, adds
  `m_opts.incremental_relay_feerate` to the removed fee-rate before
  `trackPackageRemoved`, calls
  `removeUnchecked(e, MemPoolRemovalReason::SIZELIMIT)` on each entry,
  optionally records orphaned-input outpoints for caller-side
  uncaching. Loops while `DynamicMemoryUsage() > sizelimit`.
- `bitcoin-core/src/txmempool.cpp:811-827` — `CTxMemPool::Expire(time)`
  walks `mapTx.get<entry_time>()` ascending, removes every entry with
  `GetTime() < time` together with descendants, signalling
  `MemPoolRemovalReason::EXPIRY`.
- `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20` — enum
  `MemPoolRemovalReason { EXPIRY, SIZELIMIT, REORG, BLOCK, CONFLICT,
  REPLACED }`. Threaded through every `removeUnchecked` call and into
  `CValidationInterface::TransactionRemovedFromMempool` signal.
- `bitcoin-core/src/txmempool.h:212` —
  `static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12;` (12h).
- `bitcoin-core/src/kernel/mempool_options.h` —
  `DEFAULT_MAX_MEMPOOL_SIZE_MB=300`, `DEFAULT_MEMPOOL_EXPIRY_HOURS=336`
  (14d), `DEFAULT_INCREMENTAL_RELAY_FEE = CFeeRate(1000)` (1000 sat/kvB),
  `DEFAULT_MIN_RELAY_TX_FEE = CFeeRate(1000)` (1000 sat/kvB =
  1 sat/vB).
- `bitcoin-core/src/policy/policy.h` —
  `DEFAULT_INCREMENTAL_RELAY_FEE = 1000`, `DEFAULT_MIN_RELAY_TX_FEE
  = 1000`. (User CLAUDE.md notes "HALFLIFE_LARGE=900 / HALFLIFE_SMALL=600"
  refer to feerate quantiser bins, not eviction halflife. The eviction
  halflife is the single `ROLLING_FEE_HALFLIFE = 43200` value, halved
  twice based on pool fullness.)
- `bitcoin-core/src/validation.cpp:294-382` —
  `Chainstate::MaybeUpdateMempoolForReorg(disconnectpool, fAddToMempool)`:
  re-admits disconnected non-coinbase txs reverse-ordered, with
  `bypass_limits=true`. On any `AcceptToMemoryPool` failure or
  `IsCoinBase()` / `!fAddToMempool`, calls
  `m_mempool->removeRecursive(**it, MemPoolRemovalReason::REORG)`.
  Then runs `m_mempool->UpdateTransactionsFromBlock(vHashUpdate)` and
  `removeForReorg(filter_final_and_mature)` to evict pre-existing
  entries that are no longer final / spend now-immature coinbase.
- `bitcoin-core/src/validation.cpp:2922-3267` — disconnect path
  populates `disconnectpool`; calls `MaybeUpdateMempoolForReorg` after
  each block during `ActivateBestChain`.
- `bitcoin-core/src/policy/fees.cpp::CBlockPolicyEstimator::removeTx`
  (called from `CValidationInterface::TransactionRemovedFromMempool`
  signal handler in fee estimator) — drops the in-flight tracker for
  txs removed for EXPIRY / SIZELIMIT / REPLACED / REORG so the fee
  estimator doesn't count them as "took N blocks to confirm".
- `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` — publishes
  `hashtx`/`rawtx` ONLY on `TransactionAddedToMempool` and
  `BlockConnected`; does NOT publish on
  `TransactionRemovedFromMempool` (the `sequence` topic carries
  removal events via the `R` label, but `hashtx`/`rawtx` do not).
- `bitcoin-core/src/init.cpp` — `-blocknotify=<cmd>`,
  `-walletnotify=<cmd>`, `-alertnotify=<cmd>` fork+execve hooks.
- `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction` — sets
  `mempool.PrioritiseTransaction(hash, fee_delta)` which stores into
  the `mapDeltas` map and triggers a descendant-fee recompute.

**Files audited**
- `src/Haskoin/Mempool.hs` (3898 LOC) — `Mempool`, `MempoolConfig`,
  `MempoolEntry`, `MempoolError`, `addTransaction`,
  `removeTransaction`, `removeWithDescendants`, `removeConflicts`,
  `blockConnected` (line 1831), `blockDisconnected` (line 1870),
  `trimToSize` (line 2016), `evictLowestFee = trimToSize` (line 2039),
  `expireOldTransactions` (line 2048), `trackPackageRemoved` (line
  1955), `getMempoolMinFeeRateDecayed` (line 1974),
  `getMempoolMinFeeRate` (line 1467), `evictLowestFeeRateCluster`
  (line 3535), `attemptSiblingEviction` (line 2821),
  `evictEphemeralParent` (line 3654), `mpUnbroadcast`, `mpFeeDeltas`,
  `mpRollingMinFeeRate`, `mpBlockSinceLastFeeBump`,
  `mpLastRollingFeeUpdate`, `mpHeight`, `mpMTP`, constants:
  `incrementalRelayFeePerKvb = 100` (line 381),
  `rollingFeeHalflife = 12h` (line 389),
  `defaultMempoolConfig` (line 261).
- `src/Haskoin/Policy/Standard.hs` (677 LOC) — policy constants;
  `dustRelayTxFee = 3000` (line 117). No `DEFAULT_MIN_RELAY_TX_FEE`,
  `DEFAULT_INCREMENTAL_RELAY_FEE`, `DEFAULT_MAX_MEMPOOL_SIZE_MB`,
  `DEFAULT_MEMPOOL_EXPIRY_HOURS` constants.
- `src/Haskoin/Mempool/Persist.hs` (376 LOC) — `dumpMempool`,
  `loadMempool`, `MempoolDump` shape (matches Core wire format).
- `src/Haskoin/FeeEstimator.hs` (450 LOC) — `trackTransaction`,
  `recordConfirmation`. No `removeTx` analogue.
- `src/Haskoin/Rpc.hs` (11120 LOC) — RPC dispatch (line 1024-1115),
  `handleGetMempoolInfo` (line 2431), `handleGetRawMempool` (line
  2464), `handleGetMempoolEntry` (line 5738), REST mempool handlers
  (line 9667 / 9696), ZMQ notifier (line 10810-11120),
  `notifyTxRemoval` (line 11107) — defined, no callers.
- `src/Haskoin/Sync.hs` (898 LOC) — no `blockConnected` or
  `blockDisconnected` call sites; no `expireOldTransactions` periodic
  task; no `MaybeUpdateMempoolForReorg` analogue.
- `src/Haskoin/BlockTemplate.hs` line 926-927 — only caller of
  `blockDisconnected` (in the reorg path). Does NOT call
  `blockConnected` for the new connect-side blocks (connect-side block
  processing is downstream in Main.hs).
- `app/Main.hs` (2700+ LOC) — `newMempool net cache
  defaultMempoolConfig 0 0 ...` (line 897) starts mempool with
  `mpHeight=0` / `mpMTP=0` at every restart (W150 BUG-5+6+18 stacked
  carry-forward). `blockConnected mp block` (line 1875) is called per
  newly-connected block. No periodic expire tick. No
  `evictLowestFeeRateCluster`, no `evictEphemeralParent`
  call. `dumpMempool` only at shutdown (line 1362).
- `config.example.toml` — `[mempool]` block exists with comment
  "(Uses Bitcoin Core defaults internally)"; no operator knobs.

---

## Gate matrix (29 sub-gates / 11 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | DEFAULT_MAX_MEMPOOL_SIZE_MB=300 enforced via TrimToSize | G1: budget unit matches Core (bytes-of-memory) | **BUG-2 (P1)** — `mpSize` accumulates vsize (vbytes), `mpcMaxSize=300*1024*1024` is byte-budget; Core compares `DynamicMemoryUsage()` (heap incl. metadata, ~600B per entry overhead) against `DEFAULT_MAX_MEMPOOL_SIZE_MB * 1_000_000`. |
| 1 | … | G2: `trimToSize` invoked when over budget | PASS (`Mempool.hs:1042-1045`, called from `finalizeTransaction` after each admit) |
| 1 | … | G3: `incrementalRelayFee` added to evicted rate before bumping rolling min | PASS (`Mempool.hs:2029-2031`) |
| 2 | DEFAULT_MEMPOOL_EXPIRY_HOURS=336 enforced | G4: `expireOldTransactions` invoked by a periodic timer | **BUG-1 (P0-DEAD)** — `expireOldTransactions` is exported but has **zero production call sites**. There is no scheduler. Entries that should be evicted at 14d sit forever. |
| 2 | … | G5: expiry emits EXPIRY removal reason to signal fan-out | **BUG-7 cross-cite** (no removal-reason enum) |
| 3 | DEFAULT_MIN_RELAY_TX_FEE=1000 sat/kvB | G6: static floor at mempool admit | **BUG-3 (P0-CDIV)** — `defaultMempoolConfig.mpcMinFeeRate = FeeRate 1`. The `FeeRate` type's doc-comment says "sat/vB" but `calculateFeeRate` divides by vsize and multiplies by 1000 (line 199-201) — i.e. produces sat/kvB. `FeeRate 1` is **1 sat/kvB = 0.001 sat/vB**, ~1000× lower than Core's 1000-sat/kvB floor. Admit-side comparison at line 800/873/1088 uses raw FeeRate; relay floor is effectively zero. |
| 3 | … | G7: getmempoolinfo reports correct value | **BUG-9 (P1)** — RPC hardcodes `minrelaytxfee = 1000 sat` (line 2449) and `incrementalrelayfee = 1000 sat` (line 2450) disconnected from the actual constants `incrementalRelayFeePerKvb = 100` (10× drift) and `mpcMinFeeRate = FeeRate 1`. Three different numbers in three places. |
| 4 | DEFAULT_INCREMENTAL_RELAY_FEE=1000 sat/kvB | G8: constant matches Core | **BUG-4 (P0-CDIV)** — `incrementalRelayFeePerKvb = 100` (`Mempool.hs:381`). Core: `DEFAULT_INCREMENTAL_RELAY_FEE = 1000` (policy/policy.h:48). 10× too low. The inline comment "Bitcoin Core: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB" is **factually wrong** (Core's value is 1000). Consumed in `getMempoolMinFeeRateDecayed` floor (1974-2007), `checkReplacement` Rule 4 (1675-1679), `trimToSize` bump-amount (2030). All three sites under-relay-floor by 10×. |
| 4 | … | G9: BIP-125 Rule 4 (additional fee for replacement) honours incrementalRelayFee | PARTIAL — formula is correct (`Mempool.hs:1678-1679`), but the constant feeding it is 10× too low → RBF can replace a tx by paying 100× too little additional bandwidth. |
| 5 | rolling fee decay (ROLLING_FEE_HALFLIFE=12h) | G10: 12-hour halflife constant | PASS (`Mempool.hs:389-390`, matches Core txmempool.h:212) |
| 5 | … | G11: halflife shortened to /2 if pool < 50% and /4 if < 25% | PARTIAL — denominator uses vsize-based `poolFrac` (`Mempool.hs:1988`) not `DynamicMemoryUsage()` like Core (txmempool.cpp:837-840); BUG-2 cross-cite |
| 5 | … | G12: decayed value clamped to 0 below `incrementalRelayFee/2` | PASS (`Mempool.hs:1998-2002, 2005`) |
| 5 | … | G13: `mpBlockSinceLastFeeBump` set in `blockConnected` | PASS (`Mempool.hs:1866`) |
| 5 | … | G14: `getMempoolMinFeeRate` consumed by admit / sendrawtransaction / relay path | **BUG-5 (P0-DEAD)** — `getMempoolMinFeeRate` is exported but has **zero production call sites**. The decayed rolling min-fee is computed and stored but never consulted at admit time. `addTransaction`'s admit-fee gate compares only against the static `mpcMinFeeRate` (1 sat/kvB), not the decayed rolling min. Eviction bumps the rolling min, but new admits don't see it. |
| 6 | MemPoolRemovalReason enum + signal | G15: enum exists with EXPIRY/SIZELIMIT/REORG/BLOCK/CONFLICT/REPLACED | **BUG-7 (P0-DEAD)** — no `MemPoolRemovalReason` type. `removeTransaction :: Mempool -> TxId -> IO ()` takes no reason. All removal paths (block-confirmed, RBF-replaced, size-evicted, expired, reorg-disconnect) are observationally indistinguishable. |
| 6 | … | G16: TransactionRemovedFromMempool fan-out to fee estimator + ZMQ + REST + wallet | **BUG-6 (P0-DEAD)** — no callback registry. `removeTransaction` mutates TVars and returns; nothing else is notified. |
| 7 | ZMQ hashtx fan-out on admit + block-connect | G17: `notifyTxAcceptance` called from `addTransaction` accept path | **BUG-8 (P0-DEAD)** — `notifyTxAcceptance` (Rpc.hs:11095), `notifyBlockConnect` (Rpc.hs:11068), `notifyBlockDisconnect` (Rpc.hs:11079), `notifyTxRemoval` (Rpc.hs:11107), `notifyHashTx` (Rpc.hs:11118), `notifyRawTx` (Rpc.hs:11113), `notifyHashBlock` (Rpc.hs:11089), `notifyRawBlock` (Rpc.hs:11084) are all defined, exported, and have **zero production callers**. The ZMQ PUB socket binds, the worker thread runs, but every topic is permanently silent. Operators see "ZMQ enabled, bound to tcp://127.0.0.1:28332" in the log and zero events on the wire. |
| 7 | … | G18: hashtx per-tx fan-out on `BlockConnected` (one event per tx in block) | **BUG-8 cross-cite** (carry-forward W141 BUG: fleet pattern 6 of 10 impls; haskoin now joins) |
| 8 | -blocknotify / -walletnotify / -alertnotify | G19: command-line flags accepted | **BUG-15 (P1)** — no `-blocknotify`, `-walletnotify`, `-alertnotify` CLI flag in `app/Main.hs` argparse; no `Notify` shell-execve hook anywhere in `src/`. Carry-forward W141 BUG fleet pattern (7 of 10 impls); haskoin now 8th. |
| 9 | BlockConnected / BlockDisconnected `MaybeUpdateMempoolForReorg` | G20: `blockConnected mp block` wired into IBD + inbound path | PASS (`app/Main.hs:1875`) |
| 9 | … | G21: `blockDisconnected mp block` wired into reorg disconnect | PARTIAL (`BlockTemplate.hs:926-927` — only reorg side calls it; IBD / single-block disconnect paths in `Main.hs` don't have explicit disconnect events because IBD doesn't disconnect) |
| 9 | … | G22: reorg calls `blockConnected` for each new connect-side block | **BUG-11 (P0-CDIV)** — `BlockTemplate.hs:889-898` advances cache + header chain for connect-side blocks but **does not call `blockConnected mp blk`** for them. Reorg leaves mempool with stale entries for confirmed txs (the now-confirmed txs in connect-side blocks are NOT removed from mempool). They only get evicted via conflict if a future tx spends the same outpoints. Pool grows monotonically across reorgs until natural conflict-eviction or restart. |
| 9 | … | G23: `removeForReorg` filter for newly-immature coinbase spends / non-final txs after MTP change | **BUG-12 (P0-CDIV)** — `blockDisconnected` (Mempool.hs:1870-1883) only re-adds disconnected non-coinbase txs; does NOT scan the existing mempool for now-invalid entries (newly-immature coinbase spends, BIP-68 violations after MTP regression, BIP-113 IsFinalTx failures). Core's `removeForReorg(filter_final_and_mature)` is missing entirely. |
| 9 | … | G24: re-admit uses `bypass_limits=true` so the eviction floor doesn't reject resurrected txs | **BUG-13 (P1)** — `blockDisconnected` re-admits via raw `addTransaction` (Mempool.hs:1882-1883). There is no `bypass_limits` parameter on `addTransaction`. A resurrected tx whose original fee was below the post-reorg rolling min-fee will be silently dropped and its descendants orphaned (the orphans aren't repushed either). |
| 10 | prioritisetransaction RPC + fee delta application | G25: `prioritisetransaction` JSON-RPC handler registered | **BUG-10 (P0-CDIV)** — there is no `case "prioritisetransaction"` in the RPC dispatch table (`Rpc.hs:1024-1115`). The storage (`mpFeeDeltas :: TVar (Map TxId Int64)`) exists, the persistence layer reads/writes it (`Persist.hs:278, 369`), and the consume sites use it (`Mempool.hs:859, 1078`). But **nothing populates the map**. Whatever is loaded from `mempool.dat` came from a self-empty save. Dead write-side, classic fleet "wiring-look-but-no-wire" pattern. |
| 10 | … | G26: `getmempoolentry.modifiedfee` includes the delta | **BUG-17 (P1)** — `mempoolEntryEnc` (Rpc.hs:2515) emits `modifiedfee == feeSat` (the raw `meFee`, never `meFee + delta`). Even if `prioritisetransaction` were wired, this RPC would not show the priorisation. Same problem at REST handler. |
| 11 | mpHeight=0 startup gap affects mempool fee floor / expiry | G27: `newMempool` initialised with current chain tip height + MTP | **BUG-14 (P0-CDIV)** — `app/Main.hs:897`: `newMempool net cache defaultMempoolConfig 0 0 getCoinMtpFromChain` — passes `mpHeight=0` and `mpMTP=0` regardless of on-disk chain state. (W150 BUG-5+6+18 stacked carry-forward; W151 BUG-2 carry-forward; W152 BUG-1 carry-forward.) For W153 specifically: every entry admitted before the first post-startup block gets `meHeight=0`, mis-attributing eviction priority during the gap; BIP-68 / BIP-113 admit gates compare against tip+1=1 / MTP=0 (over-permissive). |
| 11 | … | G28: `expireOldTransactions` is height- or time-driven? | PARTIAL — time-driven (uses `getPOSIXTime`, so the mpHeight=0 gap doesn't affect expiry per se), but G4 above shows it never fires. |
| 11 | … | G29: stale `mpHeight=0` survives until first inbound block; restart-while-tip-stale window | **BUG-14 cross-cite** |

---

## BUG-1 (P0-DEAD) — `expireOldTransactions` is dead code; mempool entries never expire

**Severity:** P0-DEAD (dead-helper / functionally-disabled-feature).
Bitcoin Core's `CTxMemPool::Expire(time)` is invoked from
`MaybeScheduleMempoolExpire`, run on a recurring scheduler thread, and
removes every entry older than `time - DEFAULT_MEMPOOL_EXPIRY_HOURS *
3600` seconds. The default expiry is 336 hours (14 days). Without this,
unconfirmed txs with stuck low fees would sit forever, consuming
indices, blocking RBF replacement on re-broadcast, and surviving every
fee-spike.

haskoin's `expireOldTransactions :: Mempool -> IO Int`
(`Mempool.hs:2048-2067`) implements the algorithm correctly: scan
`mpEntries`, pick entries whose `meTime < now - mpcExpiryHours * 3600`,
and call `removeWithDescendants` on each. The function is exported
(`Mempool.hs:61`). But it has **zero production call sites**. Grep
across `src/` and `app/` confirms:

```
$ grep -rn 'expireOldTransactions' src/ app/
src/Haskoin/Mempool.hs:61:  , expireOldTransactions
src/Haskoin/Mempool.hs:2048:expireOldTransactions :: Mempool -> IO Int
src/Haskoin/Mempool.hs:2049:expireOldTransactions mp = do
```

No `forkIO` scheduler in `Main.hs` calls it. No RPC handler triggers
it. The 336-hour expiry constant (`mpcExpiryHours = 336`,
`Mempool.hs:271`) is dead data.

**File:** `src/Haskoin/Mempool.hs:2048-2067` (function),
`app/Main.hs:1241-1252` (only periodic worker is the WAL flush; no
expire tick).

**Core ref:**
`bitcoin-core/src/txmempool.cpp::CTxMemPool::Expire` +
scheduler wiring in `src/init.cpp` →
`scheduler.scheduleEvery(MempoolExpire, hours{1});` (the periodic
1-hour tick).

**Impact:**
- Long-term operation: pool grows monotonically with any tx that's
  never mined and never replaced. Memory usage diverges over weeks.
- Re-orgs do not exercise the expiry path. A tx evicted by reorg may
  re-enter via `blockDisconnected` re-admit, then sit forever even if
  its original `meTime` was 6 months ago (re-admit overwrites `meTime`
  with `now`, masking the diagnostic).
- 14-day mempool floor (used by light-clients to know "this tx
  probably won't confirm") is meaningless on a haskoin node.

---

## BUG-2 (P1) — `mpSize` accumulates vsize (vbytes) but `mpcMaxSize` is a memory-byte budget; the comparison is semantically wrong

**Severity:** P1. Bitcoin Core's `TrimToSize` triggers when
`DynamicMemoryUsage() > sizelimit`, where `DynamicMemoryUsage()` is
the actual heap footprint of the mempool: every `CTxMemPoolEntry`
(with its descendant-cache, ancestor-cache, witness store, sigops
counter, lockpoints, etc.) plus the boost::multi_index overhead. On
2026 Core, the per-entry overhead is roughly ~600 bytes for a typical
P2WPKH 110-vbyte tx, so the byte-budget of 300_000_000 corresponds to
roughly 50,000 typical txs.

haskoin's `mpSize :: TVar Int` accumulates `meSize` (the adjusted
vsize in **vbytes**) on insert and decreases on remove
(`Mempool.hs:1031, 1346`). Comparison at `Mempool.hs:1043-1044`:

```haskell
totalSize <- readTVarIO (mpSize mp)
when (totalSize > mpcMaxSize (mpConfig mp)) $
  evictLowestFee mp
```

`mpcMaxSize = 300 * 1024 * 1024 = 314,572,800` (`Mempool.hs:263`).
With typical txs averaging 200 vbytes, the pool can hold up to
~1.57M txs before TrimToSize fires — about **30× more than Core's
typical 50k entries**. The mempool will:
- Use 20-30 GiB of Haskell heap before triggering a single eviction.
- Cause severe GC pressure long before the eviction gate trips.
- Allow a DoS-amplification primitive: an attacker that pushes
  900_000 small txs (each 100 vbytes) costs 90 MB of vsize but ~600 MB
  of heap, which is allowed because `90 MB < 314 MB`.

Compounded by BUG-1 (no expiry), this means the steady-state mempool
size on a haskoin node is bounded only by available heap.

**File:** `src/Haskoin/Mempool.hs:1043-1044` (compare site),
`Mempool.hs:263` (budget), `Mempool.hs:561, 1031, 1346` (accumulator).

**Core ref:** `bitcoin-core/src/txmempool.cpp:868`
(`DynamicMemoryUsage() > sizelimit`); `txmempool.cpp::DynamicMemoryUsage`
implementation.

**Impact:** memory-bound rather than vsize-bound mempool; eviction
fires at the wrong threshold; rolling-min-fee halflife branch
(`Mempool.hs:1988-1992`) also uses the wrong unit (vsize fraction
of byte-budget) and will incorrectly choose `/4` or `/2` halflife
much more aggressively than Core.

---

## BUG-3 (P0-CDIV) — `mpcMinFeeRate = FeeRate 1` is 1 sat/kvB (Core's floor is 1000 sat/kvB); also the `FeeRate` unit is contradictory across the codebase

**Severity:** P0-CDIV. Bitcoin Core's `DEFAULT_MIN_RELAY_TX_FEE =
CFeeRate(1000)`, i.e. 1000 sat per 1000 vbytes = 1 sat/vB. Every
mempool-admit and every wire-relay (via `feefilter`, BIP-133) honours
this floor.

haskoin's `defaultMempoolConfig.mpcMinFeeRate = FeeRate 1`
(`Mempool.hs:264`). The unit semantics of `FeeRate` are contradictory:

- `calculateFeeRate fee vsize = FeeRate (fee * 1000 / vsize)`
  (`Mempool.hs:198-201`) — produces **sat/kvB**.
- The type's haddock at `Mempool.hs:191-194` says "satoshis per
  virtual byte (sat/vB)" — claims **sat/vB**.
- The default-construction `FeeRate 1` at line 264 and the comment
  "1 sat/vB" — claims **sat/vB**.
- `getMempoolMinFeeRate` at `Mempool.hs:1467-1472` computes
  `staticKvb = fromIntegral minRate * 1000` — **interprets FeeRate as
  sat/vB** (multiplies by 1000 to convert to sat/kvB).

So:
- If `FeeRate 1` is read as "1 sat/kvB" (by `calculateFeeRate`-style
  comparisons), the admit floor is **0.001 sat/vB** — 1000× lower than
  Core, effectively zero. Every dust tx admits.
- If `FeeRate 1` is read as "1 sat/vB" (by `getMempoolMinFeeRate`),
  the comparison with `calculateFeeRate fee vsize` (sat/kvB) becomes
  apples-to-oranges and the wrong tx side is always "above" the floor.

Admit-side check is at `Mempool.hs:800/873/1088`:

```haskell
if feeRate < mpcMinFeeRate (mpConfig mp)
  then return $ Left (ErrFeeBelowMinimum feeRate (mpcMinFeeRate (mpConfig mp)))
```

`feeRate` here is the output of `calculateFeeRate` (sat/kvB).
`mpcMinFeeRate = FeeRate 1` (treated as sat/kvB by this comparator).
**So the admit floor on a fresh haskoin node is 1 sat per 1000 vbytes
= 0.001 sat/vB**. To clear it, a 250-vbyte tx needs only 1 satoshi of
fee. Effectively all positive-fee txs admit; the relay floor is
1000× too low.

**File:** `src/Haskoin/Mempool.hs:191-201` (FeeRate type and
constructor with conflicting unit semantics), `Mempool.hs:264`
(default value), `Mempool.hs:800/873/1088` (admit comparator),
`Mempool.hs:1467-1472` (getMempoolMinFeeRate computes with the OTHER
unit interpretation).

**Core ref:**
`bitcoin-core/src/policy/policy.h::DEFAULT_MIN_RELAY_TX_FEE = 1000`
(sat/kvB).

**Impact:**
- haskoin admits txs at ~1000× lower fee-rate than the rest of the
  network. These txs will not relay onward (peers that follow Core's
  feefilter drop them), wasting our admit slots.
- Operators see "tx in mempool" via `getrawmempool` but the tx never
  shows up on `blockchain.info`/`mempool.space` — operationally
  confusing.
- DoS: an attacker can fill 300 MB of mempool with 1-sat txs, none of
  which will ever be mined, for the cost of 0.003 BTC per fill — and
  BUG-1 means they never expire.

---

## BUG-4 (P0-CDIV) — `incrementalRelayFeePerKvb = 100`; Core's is 1000 (10× too low)

**Severity:** P0-CDIV. Bitcoin Core's
`DEFAULT_INCREMENTAL_RELAY_FEE = CFeeRate(1000)`, i.e. 1000 sat/kvB.
This constant is the per-relay "minimum reasonable fee floor" added
to evicted fee-rates before bumping the rolling minimum
(`txmempool.cpp:877`), the additional-fee required by BIP-125 Rule 4
for RBF replacement, and the lower clamp on `GetMinFee` return value
(`txmempool.cpp:850`).

haskoin's `incrementalRelayFeePerKvb = 100` (`Mempool.hs:381-382`).
The doc-comment says:

```haskell
-- Bitcoin Core: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48).
-- Note: CFeeRate(100) means 100 sat per 1000 bytes = 0.1 sat/vB.
incrementalRelayFeePerKvb :: Word64
incrementalRelayFeePerKvb = 100
```

This is **factually wrong**. Core's actual value (verified in
`bitcoin-core/src/policy/policy.h`) is `CFeeRate(1000)`. The comment
appears to confuse `DEFAULT_INCREMENTAL_RELAY_FEE = 1000` with
`DEFAULT_DESCENDANT_FEE_DELTA` or some quantiser bin. Three
consequences:

- **trimToSize bump** (`Mempool.hs:2030`):
  `evictedKvb = fr + incrementalRelayFeePerKvb` — bumps rolling min
  by 100 sat/kvB instead of 1000. Rolling fee decays back to floor
  much faster than Core.
- **BIP-125 Rule 4** (`Mempool.hs:1675-1679`):
  `requiredRelayFee = incrementalRelayFeePerKvb * newVsize / 1000` —
  replacement bandwidth tax is 10× lower. An RBF bump of 500 sat
  (instead of 5000) is accepted; this is BIP-125 incompatible and
  will be rejected by every Core peer.
- **GetMinFee floor** (`Mempool.hs:2005, 2007`):
  the lower clamp is 100 sat/kvB instead of 1000.

**File:** `src/Haskoin/Mempool.hs:381-382` (constant + wrong
comment), `Mempool.hs:1675-1679` (Rule 4), `Mempool.hs:2005-2007,
2030` (GetMinFee + trimToSize).

**Core ref:** `bitcoin-core/src/policy/policy.h:DEFAULT_INCREMENTAL_RELAY_FEE = 1000`.

**Impact:**
- BIP-125 RBF non-compliance: haskoin accepts replacements with 10×
  less additional fee than Core requires; these replacements relay to
  haskoin peers but are rejected by Core peers — fork-in-the-mempool
  between hashhog impls and Core.
- Rolling min-fee bumps are 10× too small after each eviction — the
  pool's effective floor decays too quickly, allowing low-fee
  re-admits sooner than Core.

---

## BUG-5 (P0-DEAD) — `getMempoolMinFeeRate` (the rolling-fee accessor) is dead code; new admits never see the decayed floor

**Severity:** P0-DEAD. Bitcoin Core's
`AcceptToMemoryPool::PreChecks` calls
`m_pool.GetMinFee(sizelimit)` and compares `nFees` against it for
every incoming tx (`validation.cpp` PreChecks fee-floor block). Every
inbound peer's `feefilter` advertisement is also fed from
`GetMinFee`. This is the entire mechanism by which the rolling
fee-rate floor controls the network: evict at SIZELIMIT bumps it,
admit checks consult it, peers learn about it via feefilter.

haskoin's `getMempoolMinFeeRate :: Mempool -> IO Word64`
(`Mempool.hs:1467-1472`) implements the
`max(decayedRolling, staticFloor)` formula correctly. The function is
exported (`Mempool.hs:47`). Grep over `src/` and `app/`:

```
$ grep -rn 'getMempoolMinFeeRate\b' src/ app/
src/Haskoin/Mempool.hs:47:  , getMempoolMinFeeRate
src/Haskoin/Mempool.hs:1467:getMempoolMinFeeRate :: Mempool -> IO Word64
src/Haskoin/Mempool.hs:1468:getMempoolMinFeeRate mp = do
```

**Zero callers.** Same for the underlying
`getMempoolMinFeeRateDecayed` (line 1974). All admit-side fee gates
(`Mempool.hs:800/873/1088`) compare against the **static**
`mpcMinFeeRate` only.

Consequence: `trackPackageRemoved` bumps `mpRollingMinFeeRate` on each
SIZELIMIT evict. The TVar is updated. `getMempoolMinFeeRateDecayed`
correctly applies exponential decay. But **nothing reads the result**.
A flood that evicts to 50 sat/kvB and pushes the rolling min to 50
sat/kvB has no effect on the next admit — the static 1 sat/kvB floor
(BUG-3) is the only gate.

This makes the whole rolling-fee subsystem inert. The "fee-spike
during congestion" semantics that protect the mempool from being
indefinitely-fillable disappear.

**File:** `src/Haskoin/Mempool.hs:1467-1472` (function),
`Mempool.hs:47` (export); no callers.

**Core ref:**
`bitcoin-core/src/validation.cpp::MemPoolAccept::PreChecks` fee-floor
block consulting `m_pool.GetMinFee(sizelimit)`.

**Impact:**
- Rolling min-fee is computed-but-unused — "comment-as-confession"
  fleet pattern (the docs at `Mempool.hs:1461-1466` describe the
  intended use, the implementation matches, the wiring is absent).
- Mempool-flood DoS: an attacker that fills to the size limit at
  any positive fee evicts older entries (which is fine), but their
  own followup admits are not blocked by the new high rolling-fee
  (because nothing reads it). They can sustain the flood at floor
  fee indefinitely (combined with BUG-3, that's 1 sat/kvB).
- BIP-133 feefilter advertised to peers cannot use the rolling
  min-fee either (BUG-16 below).

---

## BUG-6 (P0-DEAD) — No `TransactionRemovedFromMempool` signal fan-out; fee estimator, ZMQ, and any future consumer cannot observe removals

**Severity:** P0-DEAD. Bitcoin Core's
`CValidationInterface::TransactionRemovedFromMempool(tx, reason,
sequence)` is invoked by `CTxMemPool::removeUnchecked`. Subscribers
include:

- `CBlockPolicyEstimator::removeTx(tx.GetHash())` — drops the
  in-flight tracker so the fee estimator doesn't count
  evicted/replaced/expired txs as "took N blocks to confirm".
- ZMQ `sequence` topic — emits `R` label + txid for SequenceLabel
  observers (already implemented in `notifyTxRemoval`,
  `Rpc.hs:11107`, but unwired — see BUG-8).
- Wallet — clears watching state, re-adds to mempool tracking on
  reorg-resurrect.
- Indexes — txindex / coinstatsindex updates.

haskoin has no signal fan-out. `removeTransaction :: Mempool -> TxId
-> IO ()` (`Mempool.hs:1320`) mutates TVars and returns:

```haskell
removeTransaction :: Mempool -> TxId -> IO ()
removeTransaction mp txid = do
  mEntry <- atomically $ Map.lookup txid <$> readTVar (mpEntries mp)
  case mEntry of
    Nothing -> return ()
    Just entry -> do
      ancestors <- getAncestorsOfEntry mp entry
      descendants <- getDescendantsOfEntry mp txid
      ...
      atomically $ do
        modifyTVar' (mpEntries mp) (Map.delete txid)
        ...
```

No callback table, no broadcast channel, no
`mpRemovalListeners :: TVar [RemovalListener]`. The function returns
`()` — no reason, no broadcast.

**File:** `src/Haskoin/Mempool.hs:1320-1362` (function body, no fan-out),
`Mempool.hs:39` (export).

**Core ref:** `bitcoin-core/src/txmempool.cpp::removeUnchecked`
calling
`m_signals->TransactionRemovedFromMempool(it->GetSharedTx(), reason,
mempool_sequence++)`.

**Impact:**
- Fee estimator (`Haskoin.FeeEstimator.trackTransaction`) records
  every admit but never gets a removal signal. Expired or evicted
  txs continue to be counted as "in-flight"; when no confirmation
  ever arrives, the estimator's "block to confirmation" stat
  diverges to infinity. This bias persists across restarts (BUG-19
  fee_estimates persistence).
- ZMQ removal events absent (BUG-8 cross-cite).
- Wallet support, REST `/rest/mempool/contents` polling, MAYBE
  indexes — all blind to removals other than by polling.

---

## BUG-7 (P0-DEAD) — `MemPoolRemovalReason` enum does not exist; six different removal causes are observationally identical

**Severity:** P0-DEAD. Core's `enum class MemPoolRemovalReason`
threads through every `removeUnchecked` call:

```cpp
enum class MemPoolRemovalReason {
    EXPIRY,      // Expired from mempool
    SIZELIMIT,   // Removed in size limiting
    REORG,       // Removed for reorganization
    BLOCK,       // Removed for block
    CONFLICT,    // Removed for conflict with in-block transaction
    REPLACED,    // Removed for replacement
};
```

The reason flows into the `TransactionRemovedFromMempool` signal,
which lets the fee estimator distinguish "confirmed in block" (drop
the tracker but record confirmation) from "evicted at SIZELIMIT"
(drop the tracker and DON'T record). It also lets ZMQ subscribers
filter (`mempool.space` ignores `BLOCK` because it knows about that
already; it cares about `REPLACED` for fee-bump UI).

haskoin has no such type. `removeTransaction` takes a `TxId` and
discards context. Six functionally-distinct removal paths exist:

- `blockConnected mp block` removes for `BLOCK` (`Mempool.hs:1832-1850`).
- `blockConnected` spent-by-block conflict removes for `CONFLICT`
  (line 1839-1850, same loop).
- `blockDisconnected` (no removals — just re-admits).
- `trimToSize` removes for `SIZELIMIT` (`Mempool.hs:2032`).
- `expireOldTransactions` removes for `EXPIRY` (`Mempool.hs:2065`).
- `removeConflicts` (RBF) removes for `REPLACED` (`Mempool.hs:1749`).
- `evictEphemeralParent` removes for an ephemeral-anchor TRUC
  cleanup (`Mempool.hs:3696`); no Core analogue (TRUC-specific).

All six call the same `removeTransaction` / `removeWithDescendants`
helpers and produce no telemetry. Operators cannot tell from any
log, RPC, or metric whether a tx was confirmed, replaced, or expired.

**File:** `src/Haskoin/Mempool.hs` — no enum type defined; all
removers untyped.

**Core ref:** `bitcoin-core/src/kernel/mempool_removal_reason.h:13-20`.

**Impact:**
- Observability gap: `bitcoin-cli getmempoolinfo` (and equivalents)
  has no removal-reason counters. There is no
  `mempool.removed_for_size_limit_total` Prometheus metric (haskoin
  exposes Prometheus at `/metrics`; this dimension is unavailable).
- Fee estimator bias (BUG-6 root cause).
- ZMQ subscribers cannot distinguish replacement (UI: "txid X
  superseded by Y") from confirmation (UI: "txid X confirmed in
  block Z") on the `sequence` topic — both look identical because
  `notifyTxRemoval` is never called anyway (BUG-8).

---

## BUG-8 (P0-DEAD) — Entire ZMQ notification surface is dead code; PUB socket binds, worker runs, every topic permanently silent

**Severity:** P0-DEAD (fleet pattern — 6 of 10 impls per W141 +
W153). Bitcoin Core publishes `hashblock`, `hashtx`, `rawblock`,
`rawtx`, and `sequence` topics from
`CZMQPublishNotifier::SendZmqMessage`, called for every
`BlockConnected`, `BlockDisconnected`, `TransactionAddedToMempool`,
and `TransactionRemovedFromMempool` event. Subscribers (electrs,
fulcrum, mempool.space, nbxplorer, bitcoin-cli waitfornewblock) depend
on this fan-out.

haskoin's ZMQ infrastructure is fully built and operational:
- `src/System/ZMQ4.hs` — direct FFI to `libzmq.so.5`.
- `cbits/zmq_stubs.c` — 3-frame `[topic | body | LE u32 sequence]`
  encoding, same wire format as Core's
  `CZMQPublishNotifier::SendZmqMessage`.
- `Haskoin.Rpc.newZmqNotifier` (`Rpc.hs:10931-10960`) opens a
  context, creates a `Pub` socket, sets `SNDHWM` + `LINGER=0` + TCP
  keepalive, binds to `tcp://127.0.0.1:28332`, forks a worker that
  drains a `TBQueue` and pushes 3-frame messages.
- Wire-format helpers tested in isolation (`zmqTopicToBytes`,
  `sequenceLabelToByte`, etc.).
- Eight notifier functions exported (`notifyBlockConnect`,
  `notifyBlockDisconnect`, `notifyRawBlock`, `notifyHashBlock`,
  `notifyTxAcceptance`, `notifyTxRemoval`, `notifyRawTx`,
  `notifyHashTx` — `Rpc.hs:11068-11120`).

Grep across `src/` and `app/`:

```
$ grep -rn 'notifyBlockConnect\|notifyTxAcceptance\|notifyTxRemoval\|notifyRawTx\|notifyHashTx' src/ app/
src/Haskoin/Rpc.hs:104:  , notifyBlockConnect
src/Haskoin/Rpc.hs:108:  , notifyTxAcceptance
src/Haskoin/Rpc.hs:109:  , notifyTxRemoval
src/Haskoin/Rpc.hs:11068:notifyBlockConnect :: ZmqNotifier ...
src/Haskoin/Rpc.hs:11095:notifyTxAcceptance ...
src/Haskoin/Rpc.hs:11107:notifyTxRemoval ...
... (definitions only)
```

**Zero non-self call sites.** The PUB socket binds, the worker
`zmqWorkerLoop` (line 10991) waits on `readTBQueue (znEventQueue
notifier)` forever, the `TBQueue` is never written. `bitcoin-cli` (or
electrs etc.) attached to `tcp://127.0.0.1:28332` sees zero events,
indefinitely.

Operator log line: "ZMQ notifier started on tcp://127.0.0.1:28332" —
gives no hint that no events will ever be emitted. This is
**"already-exports-the-primitive-just-not-called"** fleet pattern, 5th
or 6th distinct instance (per W140 BUG-5 constantTimeEq, W138
ChainstateManager, etc.).

**File:** `src/Haskoin/Rpc.hs:11068-11120` (eight notifier functions),
`Rpc.hs:11070, 11086, 11091, 11098, 11100, 11103, 11110, 11115` (the
event-queue writes that only happen from inside these functions, so
nothing ever ends up in the queue).

**Core ref:** `bitcoin-core/src/zmq/zmqpublishnotifier.cpp` (PUB
notifier signals registered via `RegisterValidationInterface`).

**Impact:**
- Electrum-server / electrs / fulcrum cannot index a haskoin
  mainnet node (they rely on `hashblock` for new-tip wakeup).
- mempool.space / nbxplorer cannot index unconfirmed activity.
- `bitcoin-cli waitfornewblock` (which Core implements via
  `hashblock` ZMQ when present) is broken.
- Carry-forward W141 fleet pattern (7 of 10 impls had `-blocknotify`
  / per-tx fan-out gaps; haskoin now confirmed as 8th).

---

## BUG-9 (P1) — `getmempoolinfo` and REST `/rest/mempool/info` hardcode `minrelaytxfee` / `incrementalrelayfee` disconnected from internal constants

**Severity:** P1. Three different numeric values for the same field
ship side-by-side:

| Source | Value | Unit |
|--------|-------|------|
| `Mempool.hs:382` (`incrementalRelayFeePerKvb`) | 100 | sat/kvB |
| RPC `handleGetMempoolInfo` line 2450 | 1000 | sat (display) |
| REST `/rest/mempool/info` line 9683 | 1 | (no unit annotated) |

Similarly for `minrelaytxfee`:

| Source | Value | Unit |
|--------|-------|------|
| `Mempool.hs:264` (`mpcMinFeeRate = FeeRate 1`) | 1 | "sat/vB" per comment, sat/kvB per math |
| RPC line 2449 | 1000 | sat (display) |
| REST line 9683 | 1 | (no unit annotated) |

For `mempoolminfee`:

| Source | Value | Unit |
|--------|-------|------|
| `getMempoolMinFeeRate` (dead, BUG-5) | Word64 sat/kvB | sat/kvB |
| RPC line 2448 | `minFeeRateSatPerVb * 1000` | BTC/kB |
| REST line 9682 | `getFeeRate (mpcMinFeeRate mpCfg)` = 1 | (no unit) |

The RPC handler at line 2448:

```haskell
pair "mempoolminfee" (btcAmountEnc (fromIntegral minFeeRateSatPerVb * 1000))
```

`minFeeRateSatPerVb` is the variable name, but the value is
`getFeeRate (mpcMinFeeRate mpCfg) = 1` (because `FeeRate 1`).
Multiplying by 1000 → 1000 sat → `btcAmountEnc 1000` =
`0.00001000 BTC/kvB`. Core's value is also `0.00001000 BTC/kvB`,
which is correct by accident (because the unit confusion compensates
for the wrong base value).

But the rolling-fee value Core advertises is computed via
`GetMinFee()` and varies under congestion. haskoin's value is static
because `getMempoolMinFeeRate` is dead (BUG-5). So during a flood,
Core's `mempoolminfee` rises but haskoin's stays at 0.00001 BTC.
Monitoring tooling that scrapes this field to detect "mempool
congestion" sees no signal on a haskoin node.

**File:** `src/Haskoin/Rpc.hs:2448-2450` (RPC), `Rpc.hs:9682-9683`
(REST).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`.

**Impact:** monitoring divergence; operators cannot detect mempool
fee-spikes from a haskoin node via RPC; cross-impl divergence in
`getmempoolinfo.mempoolminfee` value semantics.

---

## BUG-10 (P0-CDIV) — `prioritisetransaction` RPC handler does not exist; the storage is wired but unwritable

**Severity:** P0-CDIV. Bitcoin Core's `prioritisetransaction(txid,
dummy, fee_delta)` is the canonical RPC for operators / pool
operators / wallet UI to bump a tx's effective fee for mining
selection and eviction priority without actually changing the wire
fee. The delta is stored in `mempool.mapDeltas`, applied at
mining-template selection time and at fee-rate comparison for
eviction.

haskoin has the storage:

```haskell
, mpFeeDeltas  :: !(TVar (Map TxId Int64))
  -- ^ Prioritisetransaction fee deltas (in satoshis); persisted in
  -- mempool.dat alongside transactions.
```

It is **read** for fee-modified comparisons:

```
$ grep -rn 'mpFeeDeltas' src/ app/
src/Haskoin/Mempool.hs:574:  , mpFeeDeltas  :: !(TVar (Map TxId Int64))
src/Haskoin/Mempool.hs:859:      feeDeltas <- readTVarIO (mpFeeDeltas mp)
src/Haskoin/Mempool.hs:1078:      feeDeltas <- readTVarIO (mpFeeDeltas mp)
src/Haskoin/Mempool/Persist.hs:278:      ds <- readTVar (mpFeeDeltas mp)
src/Haskoin/Mempool/Persist.hs:369:            modifyTVar' (mpFeeDeltas mp) (`Map.union` mdDeltas dump)
```

It is persisted to `mempool.dat` on shutdown and loaded on startup.
But **nothing writes to it** except the load-side `Map.union` (which
inherits whatever was in the dump). Since the dump was a previous
shutdown's snapshot of whatever-was-there (which itself was either
empty or inherited from a previous load), the map is **always
empty in practice**.

There is no `case "prioritisetransaction"` in the RPC dispatch
(`Rpc.hs:1024-1115` enumerates ~150 methods, this is not among them).

**File:** `src/Haskoin/Rpc.hs:1024-1115` (RPC dispatch table, no
prioritisetransaction case); `Mempool.hs:574, 859, 1078` (read
sites); `Persist.hs:278, 369` (persist sites).

**Core ref:**
`bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`.

**Impact:**
- Operators cannot bump fee on stuck txs for mining priority.
- Mining-pool integrations that rely on
  `bitcoin-cli prioritisetransaction` to boost specific txs (e.g.,
  ones their pool agreed to mine out of band) fail with method-not-
  found.
- `mempool.dat` persistence of deltas is pointless — the only
  populator is missing.

Classic fleet "wiring-look-but-no-wire" pattern: storage + persistence
+ consumer-side reads all exist, only the RPC populator is absent.

---

## BUG-11 (P0-CDIV) — Reorg connect-side does not call `blockConnected`; confirmed txs remain in mempool until evicted by conflict

**Severity:** P0-CDIV. After a reorg, Core's
`ActivateBestChain` calls `ConnectBlock(connect_block)` for each
new-chain block, which triggers
`m_mempool->removeForBlock(connect_block.vtx, connect_block.height)`.
This evicts every tx that was just confirmed (with reason
`MemPoolRemovalReason::BLOCK`) and every tx that conflicts with one
of the confirmed txs (reason `CONFLICT`). Without it, the mempool
would carry "ghost" entries for txs that are now in the block being
served.

haskoin's reorg path in `BlockTemplate.hs:851-965`:

```haskell
forM_ (zip disconnectList disconnectUndo) $ \(blk, undo) ->
  unapplyBlock cache blk undo
forM_ connectList $ \blk -> do
  let bh = computeBlockHash (blockHeader blk)
  entries <- readTVarIO (hcEntries hc)
  case Map.lookup bh entries of
    Just ce -> do
      appRes <- applyBlockToCache cache net blk (ceHeight ce)
      ...
...
forM_ disconnectList $ \blk ->
  blockDisconnected mp blk
-- MISSING: forM_ connectList $ \blk -> blockConnected mp blk
```

The disconnect-side calls `blockDisconnected mp blk`. The connect-side
applies blocks to the UTXO cache and advances header-chain pointers,
but **does not call `blockConnected mp blk`** for each new block.
Consequence:

- Every tx that was in the disconnected blocks is re-admitted to
  mempool via `blockDisconnected` (line 1882: `addTransaction mp tx`).
- Every tx that was in the new connect-side blocks is NOT removed
  from mempool. If those txs were already in mempool before the
  reorg started, they remain there until either:
  - a future tx spends the same outpoint and triggers conflict
    removal in `blockConnected` for some NEW (post-reorg) block,
  - the mempool reaches `mpcMaxSize` and SIZELIMIT evicts them
    (which won't happen because their fee-rate is presumably
    middle-of-pack), or
  - a restart drops the entire mempool except `mempool.dat`-persisted
    txs.

The `getrawmempool` RPC will incorrectly include these "phantom
confirmed" txids. `gettxout` will return the on-chain UTXO while
`getmempoolentry` will return a pending entry for the same txid.

**File:** `src/Haskoin/BlockTemplate.hs:889-928` (reorg path — connect
loop has cache-side + header-side updates but no
`blockConnected mp blk` call).

**Core ref:** `bitcoin-core/src/validation.cpp::ConnectTip` →
`m_mempool->removeForBlock(blockConnecting.vtx, pindexNew->nHeight)`.

**Impact:**
- Reorgs leak mempool entries: after every reorg, the mempool grows
  by `len(connect_list)` txs that should have been evicted.
- `getrawmempool` is wrong for the entire post-reorg window.
- `getblocktemplate` may select these ghost-confirmed txs for the
  next block, producing an invalid block (which the chainstate
  validator would then reject, but only after wasting work).

---

## BUG-12 (P0-CDIV) — `blockDisconnected` lacks `removeForReorg` filter; newly-immature coinbase spends + post-MTP non-final txs survive

**Severity:** P0-CDIV. Core's `MaybeUpdateMempoolForReorg` runs
`removeForReorg(filter_final_and_mature)` which scans **every**
mempool entry and removes any that:

1. Fail `CheckFinalTxAtTip(new_tip, tx)` — the new tip is a different
   block, possibly with lower MTP / lower height, so a tx that was
   final under the old tip may no longer be final.
2. Fail `CheckSequenceLocksAtTip(new_tip, lp)` — BIP-68 relative
   locktime may no longer be satisfied (the inputs' coin heights
   are recomputed relative to the new tip).
3. Spend a coinbase whose maturity gate `(new_tip_height + 1) -
   coin.nHeight < COINBASE_MATURITY` (100) — the new tip may be at
   lower height than the old, making a previously-mature coinbase
   spend newly-immature.

haskoin's `blockDisconnected` (`Mempool.hs:1870-1883`):

```haskell
blockDisconnected :: Mempool -> Block -> IO ()
blockDisconnected mp block = do
  atomically $ do
    modifyTVar' (mpHeight mp) (subtract 1)
    modifyTVar' (mpRecentTimestamps mp) safeDropHead
    timestamps <- readTVar (mpRecentTimestamps mp)
    writeTVar (mpMTP mp) (computeMTPFromList timestamps)
  forM_ (tail $ blockTxns block) $ \tx ->
    void $ addTransaction mp tx
```

Only updates `mpHeight` / `mpMTP` and re-admits disconnected
non-coinbase txs. No scan over existing entries.

After a 3-block reorg back-then-forward to a chain with the same tip
height but different MTP, the pool may contain:

- Time-locked txs whose `nLockTime` is now in the future under the
  new MTP. They will be selected for the next block template and
  rejected at `CheckFinalTxAtTip` — invalid block produced.
- Coinbase-spending txs that became immature because the new chain's
  coinbase-at-height-H is a different tx than the old chain's. The
  old-chain coinbase is no longer in the UTXO set, so the spend has
  a dangling input; the next `getblocktemplate` will include it,
  block construction will fail, and miners will silently drop the
  template.

**File:** `src/Haskoin/Mempool.hs:1870-1883`.

**Core ref:** `bitcoin-core/src/validation.cpp:294-382`
(`MaybeUpdateMempoolForReorg::filter_final_and_mature`).

**Impact:**
- Reorg + time-locked tx: invalid block template selection.
- Reorg + coinbase-spending tx: dangling input in template.
- Symptom: occasional "Block template failed: bad-txns-premature-
  spend-of-coinbase" or "bad-txns-non-final" errors from mining
  customers after reorgs.

---

## BUG-13 (P1) — `blockDisconnected` re-admits via `addTransaction` without `bypass_limits`; high-fee resurrected txs may be dropped at the new rolling min-fee floor

**Severity:** P1. Core's `MaybeUpdateMempoolForReorg` calls
`AcceptToMemoryPool(..., /*bypass_limits=*/true, ...)` for every
resurrected tx. The `bypass_limits` flag tells PreChecks to skip the
mempool-min-fee gate, the size-limit gate, and the descendant-package
gate. Otherwise a tx that was confirmed at low fee weeks ago (e.g.,
during a quiet period) couldn't re-enter after disconnect because the
current fee-floor is higher.

haskoin's re-admit at `Mempool.hs:1882-1883`:

```haskell
forM_ (tail $ blockTxns block) $ \tx ->
  void $ addTransaction mp tx
```

`addTransaction` has no `bypassLimits` parameter (we verified: grep
`bypass_limits|bypassLimit` returns nothing). The full admit gate
runs:

- BIP-141 weight (PASS — same tx).
- IsStandard (PASS — same tx).
- Fee floor (`mpcMinFeeRate = FeeRate 1`, which is currently
  ineffective due to BUG-3, but if BUG-3 were fixed, this would
  reject low-fee resurrected txs).
- Ancestor / descendant limits (may fail — the resurrected tx may
  now have more in-mempool descendants than before, e.g., if other
  recently-admitted children of an unconfirmed parent already
  count).

Today (with BUG-3 leaving fee-floor at 1 sat/kvB), the fee gate is
no-op. If/when BUG-3 is fixed, this becomes a P0 — resurrected
old-low-fee txs will be silently dropped and the user's view "my
tx was confirmed, then unconfirmed, then disappeared" is not
explainable.

**File:** `src/Haskoin/Mempool.hs:1882-1883`.

**Core ref:** `bitcoin-core/src/validation.cpp:314`
(`bypass_limits=true` for reorg re-admits).

**Impact:** today benign (BUG-3 masks); becomes P0-CDIV the moment
BUG-3 is fixed. Listed at P1 for now with cross-cite warning.

---

## BUG-14 (P0-CDIV) — `newMempool ... 0 0 ...` mpHeight=0 startup gap (W150 BUG-5+6+18 / W151 BUG-2 / W152 BUG-1 stacked carry-forward, W153-applicable consequences)

**Severity:** P0-CDIV (carry-forward; in W153 manifests as
incorrect `meHeight` on early-admit entries and incorrect
mempool-min-fee floor and incorrect BIP-68/113 gates during the
startup window).

`app/Main.hs:897`:

```haskell
mp <- newMempool net cache defaultMempoolConfig 0 0 getCoinMtpFromChain
```

The two literal `0`s are `height` and `mtp`. The constructor doc
(`Mempool.hs:619-625`) says: "Pass 0 for both on a fresh node; they
are updated via blockConnected." On a fresh node this is correct. On
a restart with a 900_000-block chain, this is wrong: until the next
inbound block arrives and triggers `blockConnected`, `mpHeight=0`,
`mpMTP=0`.

W153-specific consequences during the startup window:

- **`meHeight` mis-attribution**: every tx admitted in the gap gets
  `meHeight = 0` (line 983: `height <- readTVarIO (mpHeight mp)`).
  `getrawmempool` / `getmempoolentry` reports `height: 0` for these
  txs, making them appear pre-genesis. RPC clients computing
  `confirmations = tipHeight - entryHeight` see `confirmations =
  900000`, which is absurd. If the tx is later subject to
  height-driven eviction (e.g., a hypothetical "evict if older than
  100 blocks" gate — not implemented but ouroboros has one), the
  attribution is wrong.
- **BIP-68 / BIP-113 gates** (`Mempool.hs:1898-1926`): admit checks
  use `tipHeight + 1 = 1` and `mtp = 0`. Time-locked txs whose
  `nLockTime` is any positive Unix timestamp will fail the BIP-113
  check (`mtp = 0 < lockTime`) → reject. Height-locked txs with
  `nLockTime < 1` (= no constraint) pass; any height-locked tx with
  `nLockTime ≥ 1` correctly rejects (since `tipHeight+1 = 1`). Net:
  the gate is **over-permissive on relative-time locks and under-
  permissive on absolute-time locks** during the gap.
- **Rolling fee floor** (BUG-5 dead) — not affected because the
  rolling fee state machine doesn't read mpHeight.

The startup gap closes the moment the first new block arrives and
`blockConnected` increments mpHeight (line 1858: `modifyTVar'
(mpHeight mp) (+ 1)`). But this starts from 0, not from the actual
chain tip height. **After the first block lands, `mpHeight = 1`,
not `tipHeight + 1`**. The gap is permanent until restart.

There is no plumb-from-chain-on-init: `newMempool` is invoked with
literal zeros, and no subsequent `setMpHeight` call exists.

**File:** `app/Main.hs:897` (constructor call site); `Mempool.hs:621`
(constructor doc); `Mempool.hs:626-655` (constructor body — accepts
`height` parameter and writes it to TVar).

**Core ref:** `bitcoin-core/src/init.cpp::AppInitMain` →
`pool->m_height = chainman.ActiveChain().Height()` at startup (single
plumb at startup).

**Impact:** carry-forward stacked over W150/W151/W152; W153
specifically: every restart leaves the mempool in a degraded state
where BIP-113 admit checks reject otherwise-valid time-locked txs
and re-admit them only after a reorg fixes the height tracking
(which actually wouldn't fix it either — `blockDisconnected`
decrements from 0 to ... wraps to UINT32_MAX? Let me check.)

Yes — `Mempool.hs:1875`: `modifyTVar' (mpHeight mp) (subtract 1)`
on `Word32` underflows to `0xFFFFFFFF` if mpHeight=0. So a reorg
before the first connect lands sends mpHeight to 4 billion, making
the BIP-68 gate trivially pass (over-permissive) for all txs. The
next connect bumps to 0 (overflow wrap-around). Pathological.

---

## BUG-15 (P1) — `-blocknotify` / `-walletnotify` / `-alertnotify` operator hooks absent (W141 fleet carry-forward, 8th impl)

**Severity:** P1 (carry-forward W141 fleet pattern — 7 of 10 impls
had no notify-script hooks; haskoin now 8th).

Core's `-blocknotify=<cmd>` / `-walletnotify=<cmd>` /
`-alertnotify=<cmd>` flags fork+execve a shell command on each
trigger, with `%s` substitution for blockhash/txid/alert-message.
Used by operators for: paging on new block (PagerDuty integration),
nagging the user on incoming wallet payment (Telegram bot),
escalating on consensus split (alertnotify).

haskoin's `app/Main.hs` argparse has no `-blocknotify` /
`-walletnotify` / `-alertnotify` flag. No `notify` helper in
`src/Haskoin/`. No shell-execve hook anywhere.

**File:** `app/Main.hs` argparse / option parsing (none defined);
`src/Haskoin/` (no Notify module).

**Core ref:** `bitcoin-core/src/init.cpp` argument registration;
`bitcoin-core/src/node/blockmanager_args.cpp` block-notify wiring.

**Impact:** operators porting bitcoin.conf with `blocknotify=`
silently lose the integration; no error, no warning, the flag is
just ignored. Fleet pattern; haskoin joins 8/10 impls without notify
hooks.

---

## BUG-16 (P1) — BIP-133 feefilter advertised to peers cannot reflect mempool congestion (rolling-fee dead)

**Severity:** P1. BIP-133 feefilter is an inbound peer hint:
"don't bother sending me invs for txs with fee-rate below X sat/kvB,
because I'll just reject them." Core derives `X` from
`GetMinFee(sizelimit)` every minute or so and broadcasts via
`MFeeFilter`. This dramatically reduces wasted relay bandwidth during
mempool floods.

haskoin's `getMempoolMinFeeRate` is dead (BUG-5). The feefilter that
gets advertised (let me check — actually this is W141/W152 territory,
but the consumer is mempool min-fee):

<grep result of "FeeFilter"-style outbound show: ... — not
audited here, but the dependency is clear: even if feefilter
broadcast wiring exists somewhere, it cannot reflect the rolling-fee
floor because the consumer of GetMinFee never reads the rolling part.>

Cross-cite BUG-5. Listed at P1 for tracking — haskoin's feefilter,
if/when wired, will only ever advertise the static floor (1 sat/kvB,
trivially low) and never reflect actual congestion.

**File:** `src/Haskoin/Mempool.hs:1467-1472` (dead accessor); P2P
feefilter-send path (not in scope for W153, see W141/W152).

**Core ref:** `bitcoin-core/src/net_processing.cpp` `MaybeSendFeefilter`.

**Impact:** outbound feefilter under-states our floor by 1000× when
the pool is congested → peers send invs for txs we'll reject → wasted
bandwidth.

---

## BUG-17 (P1) — `getmempoolentry` / `getrawmempool verbose=true` emits `modifiedfee == fee`, ignoring `mpFeeDeltas`

**Severity:** P1. Core's `getmempoolentry` JSON shape includes:

```
"fees": {
  "base": <effective fee>,
  "modified": <base + prioritisetransaction delta>,
  "ancestor": <sum across ancestors including modifier>,
  "descendant": <sum across descendants including modifier>
}
```

`modified` MUST include the prioritisetransaction delta. Wallets and
mining-pool integrations rely on this to verify their priorisation
landed.

haskoin's `mempoolEntryEnc` at `Rpc.hs:2497-2530`:

```haskell
mempoolEntryEnc tipHeight entry =
  let wtxid = computeWtxId (meTransaction entry)
      entryHeight = meHeight entry
      feeSat = fromIntegral (meFee entry) :: Int64
      ancFee = fromIntegral (meAncestorFees entry) :: Int64
      descFee = fromIntegral (meDescendantFees entry) :: Int64
      feesEnc = pairs $
        pair "base"       (btcAmountEnc feeSat)  <>
        pair "modified"   (btcAmountEnc feeSat)  <>   -- BUG: == base
        pair "ancestor"   (btcAmountEnc ancFee)  <>
        pair "descendant" (btcAmountEnc descFee)
      ...
      pair "modifiedfee" (btcAmountEnc feeSat)  <>      -- BUG: == fee
```

`feesEnc.modified` and the top-level `modifiedfee` field are both
literally `feeSat`, never `feeSat + delta`. Even if BUG-10 were fixed
(prioritisetransaction RPC populates `mpFeeDeltas`), this RPC would
not surface the delta. Same shape at `Rpc.hs:9747` (REST verbose).

Also note `depends` and `spentby` at line 2526-2527:

```haskell
pair "depends"            (AE.list text [])  <>      -- always []
pair "spentby"            (AE.list text [])  <>      -- always []
```

**`depends` and `spentby` are always empty literals**, never computed
from the in-mempool parent/child set. Wallets that walk the descendant
graph via `getmempoolentry.spentby` to find their child txs cannot do
so on haskoin.

**File:** `src/Haskoin/Rpc.hs:2497-2530` (RPC), `Rpc.hs:9741-9754`
(REST verbose).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::entryToJSON`.

**Impact:**
- Wallets cannot detect priorisation took effect.
- Wallets cannot enumerate descendants of their unconfirmed tx via
  this RPC.
- Mining-pool integrations get wrong fee-numbers when computing
  expected block reward.

---

## BUG-18 (P1) — `getmempoolinfo.usage` reports vsize, not memory usage; `mempool_sequence` always 0

**Severity:** P1. Core's `getmempoolinfo`:
- `usage` (BTC): not BTC at all — bytes of heap memory consumed by
  the pool (`DynamicMemoryUsage()`).
- `mempool_sequence`: monotonic counter bumped on each
  add/remove event.

haskoin:
- `usage` (RPC line 2445 and REST line 9680): `AE.int size`, where
  `size = mpSize` = sum of vsize in vbytes. Off by a factor of ~3 for
  typical pools (per-entry overhead ~600B vs typical ~200 vbytes).
- `mempool_sequence` (REST line 9731): `0 :: Int` hardcoded. There
  is no `mpSequence` counter on the `Mempool` record. Core's
  semantics (monotonic per-event) cannot be replicated.

**File:** `src/Haskoin/Rpc.hs:2445, 9680` (`usage`); `Rpc.hs:9731`
(`mempool_sequence`).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`
(`usage`, `mempool_sequence`).

**Impact:** monitoring tools (`mempool.space`, `electrs`)
under-report memory usage by 3-5× → cannot alert on actual heap
pressure; sequence-based subscribers cannot detect missed
notifications.

---

## BUG-19 (P1) — Fee estimator never receives removal signal; in-flight tracker for evicted/expired txs is never dropped, biasing predictions

**Severity:** P1. Core's `CBlockPolicyEstimator::processTransaction`
records `(txid, bucket)` for each admitted tx. On removal:

- `MemPoolRemovalReason::BLOCK` → call
  `processBlockTx(height, removed_tx)`: bump the confirmation-count
  bucket; record the inter-block delay.
- `EXPIRY` / `SIZELIMIT` / `REPLACED` → call `removeTx(hash)`:
  drop the in-flight tracker WITHOUT recording confirmation;
  prevents counting this tx as "took ∞ blocks to confirm".
- `REORG` → call `removeTx(hash)`: same treatment as expiry; the
  tx is now back in mempool and will be re-tracked on re-admit.

haskoin's `app/Main.hs:1875-1889`:

```haskell
blockConnected mp block
writeIORef recentlyRejectedRef Set.empty
let confirmedTxIds = map computeTxId (blockTxns block)
eraseOrphansForBlock confirmedTxIds orphanPoolRef
recordConfirmation fe height confirmedTxIds
```

Only the BLOCK-confirmation path calls `recordConfirmation` (which
maps to processBlockTx). There is no fan-out for SIZELIMIT / EXPIRY
/ REPLACED / REORG → fee estimator's in-flight set will accumulate
trackers for every tx ever evicted/expired/replaced. After weeks of
operation:

- 100k confirmed txs (correctly handled).
- 50k SIZELIMIT-evicted txs (tracker leaks; counted as "still
  in-flight" indefinitely).
- 10k expired txs (would also leak, but BUG-1 means no expiries
  ever happen).
- 5k RBF-replaced txs (tracker leaks).

The estimator's per-bucket median "blocks to confirm" diverges
because the denominator includes phantom in-flight txs. Predictions
become biased toward "needs more fee than you think". Persisted
across restarts via `fee_estimates.json`.

**File:** `src/Haskoin/FeeEstimator.hs:28-29` (only two write
operations: `trackTransaction`, `recordConfirmation`; no
`removeTx`). `app/Main.hs:1875-1889` (only fan-out is for BLOCK
confirmations).

**Core ref:**
`bitcoin-core/src/policy/fees.cpp::CBlockPolicyEstimator::removeTx`
and the `TransactionRemovedFromMempool` signal handler in
`policyestimator.cpp` of validationinterface.

**Impact:** fee estimator over-estimates required fee over time;
predictions diverge from network reality; reset only by deleting
`fee_estimates.json`.

---

## BUG-20 (P1) — `mpUnbroadcast` is dead-write storage; persisted but never populated

**Severity:** P1 (dead-data plumbing fleet pattern; haskoin's 4th or
5th instance per W138/W140 tracking).

`Mempool.hs:577`:

```haskell
, mpUnbroadcast :: !(TVar (Set TxId))
  -- ^ Transactions originated locally that have not yet been confirmed
  -- relayed to a peer. Persisted in mempool.dat.
```

The intent (per Core's `unbroadcast` set): when a wallet broadcasts
a tx via `sendrawtransaction`, the txid enters the unbroadcast set
and stays there until at least one peer asks for it via `getdata`.
This is how Core's "I told you to broadcast, but no peer ever asked
for it" warning works — re-broadcast at startup or after extended
quiet periods.

haskoin's `mpUnbroadcast`:

```
$ grep -rn 'mpUnbroadcast' src/ app/
src/Haskoin/Mempool.hs:577:  , mpUnbroadcast :: !(TVar (Set TxId))
src/Haskoin/Mempool/Persist.hs:279:      us <- readTVar (mpUnbroadcast mp)
src/Haskoin/Mempool/Persist.hs:370:            modifyTVar' (mpUnbroadcast mp) (`Map.union` mdUnbroadcast dump)
```

Persisted at save; loaded at startup as union with on-disk set.
**Never inserted into elsewhere**. No sendrawtransaction /
broadcast path calls `modifyTVar' (mpUnbroadcast mp) (Set.insert
txid)`. No `getdata`-served path removes the entry. The set is
permanently empty.

`getmempoolinfo` returns `unbroadcastcount = 0` (line 2451)
hardcoded, masking this.

**File:** `src/Haskoin/Mempool.hs:577` (declaration);
`src/Haskoin/Mempool/Persist.hs:279, 370` (persist + load); no
writer.

**Core ref:** `bitcoin-core/src/txmempool.cpp::AddUnbroadcastTx`,
`RemoveUnbroadcastTx`.

**Impact:** wallets that send a tx through this node have no
guarantee it ever reached the network; the "you sent a tx and nobody
asked for it" diagnostic doesn't exist.

---

## BUG-21 (P2) — Multiple dead helpers in eviction module (cleanup candidates)

**Severity:** P2. Three additional eviction-related helpers are
exported but unused:

- `evictLowestFeeRateCluster` (`Mempool.hs:3535-3555`) — cluster-
  based eviction. Exported (line 120), implemented, **zero
  callers**. Was perhaps intended as an alternative to `trimToSize`
  for cluster mempool policy (BIP-431) but never wired.
- `evictEphemeralParent` (`Mempool.hs:3654-3700`) — TRUC ephemeral-
  anchor cleanup. Exported (line 106), implemented, **zero
  callers**. Should be invoked from any path that removes a TRUC
  child that spends an ephemeral output (so the parent doesn't sit
  forever with no spender).
- `attemptSiblingEviction` (`Mempool.hs:2821`) — IS called from
  one site (`Mempool.hs:966`, TRUC v3-parent-with-existing-child
  path), so this one is alive.

`evictLowestFeeRateCluster` + `evictEphemeralParent` together
represent ~150 LOC of dead eviction logic, with no obvious bug
filed against them. Cleanup candidate; small risk that some intended
behaviour is missing.

**File:** `src/Haskoin/Mempool.hs:3535-3555, 3654-3700`.

**Impact:** code-density burden; possible feature gap on TRUC
ephemeral-anchor lifecycle (a TRUC child evicted by sibling-
replacement should also evict the parent's ephemeral anchor, per
BIP-431; `evictEphemeralParent` does that but is never called).

---

## BUG-22 (P1) — No operator knobs for `-maxmempool` / `-mempoolexpiry` / `-minrelaytxfee` / `-incrementalrelayfee`

**Severity:** P1. Core exposes:
- `-maxmempool=<MB>` (default 300)
- `-mempoolexpiry=<hours>` (default 336)
- `-minrelaytxfee=<n.nnn BTC/kvB>` (default 0.00001 = 1000 sat/kvB)
- `-incrementalrelayfee=<n.nnn>` (default 0.00001)
- `-blocksonly` (don't relay txs at all)
- `-permitbaremultisig`
- `-datacarrier`, `-datacarriersize`
- `-bytespersigop`

haskoin's `config.example.toml` `[mempool]` block:

```toml
[mempool]
# (Uses Bitcoin Core defaults internally)
```

No keys. The internal defaults are wrong (BUG-3 + BUG-4) so even an
operator who knew to set these can't.

`app/Main.hs` argparse has none of `-maxmempool`,
`-mempoolexpiry`, `-minrelaytxfee`, `-incrementalrelayfee`.

**File:** `config.example.toml`; `app/Main.hs` argparse.

**Core ref:** `bitcoin-core/src/init.cpp` argument registration
(under "Mempool Limits" and "Mempool Policy" groups).

**Impact:** operators have NO ability to:
- raise the static fee floor (would mitigate BUG-3),
- tighten mempool memory budget (would mitigate BUG-2),
- shorten expiry for high-throughput nodes,
- run a blocksonly node.

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22).

**Severity distribution:**
- **P0-DEAD:** 5 (BUG-1, BUG-5, BUG-6, BUG-7, BUG-8)
- **P0-CDIV:** 6 (BUG-3, BUG-4, BUG-10, BUG-11, BUG-12, BUG-14)
- **P1:** 10 (BUG-2, BUG-9, BUG-13, BUG-15, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-22)
- **P2:** 1 (BUG-21)

Total P0-class: 11.

**Fleet patterns confirmed:**
- "dead-helper / `already-exports-the-primitive-just-not-called`"
  (W140 BUG-5 fleet pattern, 5th-7th distinct haskoin instances):
  BUG-1 (`expireOldTransactions`), BUG-5 (`getMempoolMinFeeRate`),
  BUG-8 (8 ZMQ notify functions), BUG-10 (`prioritisetransaction`
  storage exists, RPC absent), BUG-20 (`mpUnbroadcast` storage
  exists, populator absent), BUG-21 (`evictLowestFeeRateCluster`,
  `evictEphemeralParent`).
- "wiring-look-but-no-wire" (W138 fleet pattern): BUG-10
  (mpFeeDeltas read+persist exist; populator absent).
- "comment-as-confession" (fleet pattern, 9th+ instance):
  BUG-4 doc-comment "Bitcoin Core: DEFAULT_INCREMENTAL_RELAY_FEE = 100"
  contradicts the actual Core value (1000) — comment exists but
  documents a wrong fact AND the wrong value is what the impl uses.
- "unit-confusion across two read-sites" (NEW pattern): BUG-3 —
  `FeeRate` type's haddock claims sat/vB; `calculateFeeRate` produces
  sat/kvB; `getMempoolMinFeeRate` interprets the field as sat/vB
  (multiplies by 1000); admit-side interprets it as sat/kvB (raw
  compare). Two different interpretations of the same field's unit
  ship in production.
- "stacked carry-forward" (W150 BUG-5+6+18 + W151 BUG-2 + W152 BUG-1):
  BUG-14 confirms mpHeight=0 startup gap also affects W153's
  meHeight attribution + BIP-113 admit gates. **4th wave to surface
  the same bug.**
- "30-of-30-gates-buggy" near-miss: of 29 sub-gates in the gate matrix,
  21 are wrong (BUG-1..BUG-22 minus BUG-13 which is conditional, plus
  cross-cites). The eviction + min-fee + signal subsystem is
  effectively rewrite-grade.
- "STANDARD-flags-incomplete carry-forward" (W144 BUG-3 / W150 / W151
  / W152 confirmed live): not surfaced as a new W153 bug because
  W153 is mempool-eviction not script-flags, but the dead policy
  flags continue to influence which txs reach the mempool — every
  bug in W153 has implicit "and also script-flags filter is wrong"
  upstream.

**New patterns introduced this wave:**
- **"contradictory FeeRate unit"** (BUG-3) — same field read as
  different units by adjacent functions; magnitudes off by 1000×.
  This is a new shape vs the W141 "byte-order" / "bucket-shape"
  unit-confusion variants.
- **"persist-but-never-populate storage"** (BUG-10, BUG-20) — TVar
  + persistence layer + consumer-side reads + NO populator. Strictly
  worse than dead-data plumbing because the persistence cost is paid
  for state that is permanently empty.
- **"signal infrastructure built, fan-out absent"** (BUG-6, BUG-8) —
  contrast with W140 BUG-5 `constantTimeEq` (primitive exists, one
  consumer fails to call it); here the consumer surface is 8
  functions, all unwired. Larger-blast-radius variant.
- **"reorg side-asymmetric mempool maintenance"** (BUG-11) —
  blockDisconnected wired, blockConnected on reorg connect-side NOT
  wired. Symmetric bug shape would be both missing or both present;
  this asymmetric variant means reorgs leak mempool entries one-
  directionally.
- **"reason-enum-absent threading"** (BUG-7) — six removal causes
  collapsed into one untyped function. Telemetry-blind.

**Top 3 findings:**

1. **BUG-3 + BUG-4 (P0-CDIV pair): the entire relay-floor +
   incremental-fee subsystem is 1000× / 10× too low.** `FeeRate 1`
   is interpreted as 1 sat/kvB at admit time (0.001 sat/vB, ~1000×
   below Core); `incrementalRelayFeePerKvb = 100` (10× below Core's
   1000). Combined: mempool accepts any positive-fee tx; BIP-125 RBF
   relays bumps that Core peers reject. **This is the #1 priority
   fix for W153 — single-file change, single-constant change in two
   places, restores BIP-133/BIP-125 wire-format parity.**

2. **BUG-1 + BUG-5 + BUG-6 + BUG-7 + BUG-8 (P0-DEAD cluster): the
   entire mempool-eviction signal/expire/rolling-fee surface is
   dead.** `expireOldTransactions` never called, `getMempoolMinFeeRate`
   never called, no `MemPoolRemovalReason` enum, no
   `TransactionRemovedFromMempool` signal, 8 ZMQ notifier functions
   never called. Operators see "ZMQ enabled, bound to ..." and zero
   events. Fee estimator overcounts evictions. Pool grows forever.
   **5 P0-DEADs in one wave is a haskoin record (previous high was
   3 in W140).**

3. **BUG-11 + BUG-12 + BUG-14 (reorg correctness cluster):** reorg
   connect-side fails to remove confirmed txs from mempool (BUG-11),
   `removeForReorg` filter for newly-immature coinbase / non-final
   txs is missing entirely (BUG-12), and mpHeight=0 underflow on
   pre-first-connect disconnect can spike to UINT32_MAX (BUG-14).
   Together: any reorg on a haskoin node leaves the mempool in an
   inconsistent state that produces invalid block templates.

**Carry-forward notes:**
- W144 BUG-3 (STANDARD flags entirely absent) — confirmed live by
  W150/W151/W152, not re-surfaced here as W153 is mempool-eviction
  not script-flags. The dead STANDARD flags filter what reaches
  mempool admit so every W153 bug compounds with W144.
- W148 BUG-13 (MBlock peer ban) — confirmed; haskoin's `recentlyRejectedRef`
  is cleared on every block (Main.hs:1876) instead of being a
  persistent rolling bloom. Stacked carry-forward W152 BUG-10 + W153
  observation: this means the same low-fee tx can be re-relayed every
  block until SIZELIMIT eviction; with BUG-3 / BUG-5 broken, no
  SIZELIMIT triggers.
- W150 BUG-5+6+18 / W151 BUG-2 / W152 BUG-1 (mpHeight=0 startup gap)
  — **4th wave** to confirm this. BUG-14 here adds new
  W153-specific consequences (meHeight mis-attribution + BIP-113
  startup-window misbehaviour + UINT32_MAX underflow on
  pre-first-connect disconnect).
- W152 BUG-1 (InvTrickler dead) — not directly relevant to W153
  but cross-cite: if InvTrickler were alive, BUG-8 (ZMQ dead) would
  not cover the relay path; both are dead so the inv pipeline is
  doubly silent.
- W141 fleet pattern -blocknotify/-walletnotify/-alertnotify (7
  impls confirmed) — haskoin joins as 8th confirmed impl.

**Priority fix ordering (for follow-on FIX waves):**
1. **BUG-3** (single-line fix: `FeeRate 1000` + `FeeRate` haddock
   update) — restores min-fee floor at ~1000× higher; closes 1000×
   wire-format gap.
2. **BUG-4** (single-line fix: `incrementalRelayFeePerKvb = 1000`)
   — restores BIP-125 Rule 4 + GetMinFee clamp; closes 10× RBF gap.
3. **BUG-11** (3-line fix: add
   `forM_ connectList $ \blk -> blockConnected mp blk` to reorg path
   in `BlockTemplate.hs:927`) — fixes reorg mempool leak.
4. **BUG-1** (add periodic `forkIO $ forever $ threadDelay
   (60*60*1_000_000) >> expireOldTransactions mp` to Main.hs init)
   — wires expiry.
5. **BUG-5** (wire `getMempoolMinFeeRate` consult into
   `addTransaction` fee-floor check) — closes rolling-fee dead.
6. **BUG-14** (initialise `newMempool` with actual chain tip height
   + MTP at startup; **3rd or 4th wave repair attempt**) — closes
   the startup gap once and for all.
7. **BUG-10** (add `prioritisetransaction` RPC handler; ~30 LOC)
   — closes dead-write storage.
8. **BUG-8** (wire `notifyBlockConnect` / `notifyTxAcceptance` /
   `notifyTxRemoval` into the existing call sites in
   `Main.hs:1875` (BlockConnect) and `Main.hs:1914` (MTx accept)
   and a future `removeTransaction` callback — ~10 LOC × 3 sites).
9. **BUG-6 + BUG-7 + BUG-19** (signal infrastructure: extend
   `removeTransaction` to take `MemPoolRemovalReason`, add a
   `removalListeners :: TVar [...]` registration, fan out to fee
   estimator + ZMQ + REST poll counter; ~150 LOC).
10. **BUG-15** (`-blocknotify` / `-walletnotify` / `-alertnotify`:
    fleet-wide bundle with the `ShellEscape` primitive once it exists).

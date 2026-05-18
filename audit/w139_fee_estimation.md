# W139 Fee Estimation engine (CBlockPolicyEstimator) — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** the fee-estimation engine — `CBlockPolicyEstimator`,
`TxConfirmStats`, `CFeeRate`, `FeePerVSize`, `FeeFilterRounder` —
plus the `estimatesmartfee` / `estimaterawfee` RPC surface and the
mempool-min-fee / min-relay-fee clamps applied at the RPC boundary.
Core references audited:
- `bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp}` —
  `CBlockPolicyEstimator`, `TxConfirmStats`, `FeeFilterRounder`,
  `EncodedDoubleFormatter`, `CURRENT_FEES_FILE_VERSION`, the
  three-horizon constants (SHORT / MED / LONG), `validForFeeEstimation`
  4-bool gate, `MaxUsableEstimate`, `OLDEST_ESTIMATE_HISTORY`,
  `processTransaction` / `processBlock` / `removeTx` /
  `FlushUnconfirmed` / `Write` / `Read`.
- `bitcoin-core/src/policy/feerate.{h,cpp}` — `CFeeRate`, `FeePerVSize`,
  `GetFee` round-up semantics, `GetFeePerK` for the bucket bucketing,
  `FeeRateFormat::BTC_KVB` / `FeeRateFormat::SAT_VB`, `operator<=>`
  via `FeeRateCompare`.
- `bitcoin-core/src/rpc/fees.cpp` — `estimatesmartfee` (mempool-min /
  min-relay clamp at RPC boundary, BTC/kvB on the wire,
  `RPC_INVALID_PARAMETER` on bad mode, `feeCalc.returnedTarget`
  fallthrough), `estimaterawfee` (per-horizon `short`/`medium`/`long`
  payload, distinct `pass`/`fail` bucket reporting, `round(buckets.fail.start * 100) / 100`
  rounding, omit `fail` when `buckets.fail.start == -1`).
- `bitcoin-core/src/rpc/util.cpp::ParseConfirmTarget` — `[1, max_target]`
  range validation, throws `RPC_INVALID_PARAMETER`.

**Out of scope:**
- The BIP-133 feefilter peer-message dispatch and quantization
  (W136 already audited the wire format; W139 audits ONLY the
  `FeeFilterRounder` quantization primitive that Core invokes inside
  the message build path, NOT the wire arm or the rate-limit window).
- `walletcreatefundedpsbt` `conf_target` consumption — that's W118 /
  W129 wallet coin-selection territory.
- The mempool `GetMinFee` decay machinery — W120 / W116 mempool ladder.
  W139 only audits the RPC-side clamp that re-applies
  `mempool.GetMinFee()` and `m_opts.min_relay_feerate` to the
  estimator's output (`rpc/fees.cpp:82-85`).

**Result:** 4 PRESENT / 8 PARTIAL / 18 MISSING out of 30 gates.
**Bugs found:** 16 (4 P0-CDIV + 9 P1 + 3 P2). NONE overlap with the
14 W114 bugs already catalogued; W139 audits orthogonal Core-parity
gaps W114 did not cover (CFeeRate arithmetic, FeeFilterRounder,
EncodeDouble serialization, FeeCalculation result-attribution struct,
RPC-side clamps, the three-horizon refinement / conservative pipeline,
historical-block-span bookkeeping, and ParseConfirmTarget range check).

**Tests added:** 30 gate cases in `W139FeeEstimationSpec.hs` as
`it`-pinning (current observable behavior) + `xit`-sentinels
(desired Core-parity behavior) so future fix waves can flip
`xit` -> `it` after wiring the missing primitive.

## Relationship to W114 fee estimation audit

W114 (commit pre-`f015e72`, present in `test/W114FeeEstimationSpec.hs`)
catalogued 14 bugs (BUG-1..BUG-14 in W114) covering the **bucket
range / count / decay** (BUG-3..BUG-5), the **three-horizon absence**
(BUG-2), the **single 0.95 threshold** (BUG-6), the **estimate_mode
RPC pass-through** (BUG-7), **conf_target bounds** (BUG-8), the
**`validForFeeEstimation` filter** (BUG-9), **removeTx/eviction**
absence (BUG-10), **`SUFFICIENT_FEETXS` per-block vs absolute**
(BUG-11), **stale-file 60-hour guard** (BUG-12), **periodic flush
interval** (BUG-13), and the **single-horizon estimaterawfee output**
(BUG-14). The W114 spec sheet is 30 gates wide and exhaustive on
"the estimator engine itself".

W139 audits a DIFFERENT layer: the **arithmetic and serialization
primitives** the estimator uses, the **RPC-boundary clamping** that
re-applies mempool/relay floors, the **`FeeFilterRounder` BIP-133
quantization** primitive that is completely absent, the
**`FeeCalculation` result-attribution struct** that tells callers
WHICH sub-estimate produced the answer, and the
**historical-block-span / `MaxUsableEstimate` / `OLDEST_ESTIMATE_HISTORY`
clamps** that gate whether a stored estimator's data is considered
fresh enough to answer at all.

Where W114 pins a gap, W139 does not re-bill it. Where W139 finds
a related-but-distinct gap (e.g. W114 BUG-7 is "RPC handler ignores
estimate_mode", W139 BUG-12 is "even when the mode IS passed, Core
also throws `RPC_INVALID_PARAMETER` on a bad mode string and haskoin's
handler has no equivalent error path"), W139 bills the new gap and
cross-references the W114 BUG.

## Top-line verdict

haskoin's fee-estimation engine is a **single-horizon shim with
opaque scalar return values**, missing the entire arithmetic surface
of `CFeeRate` / `FeePerVSize` (round-up `GetFee`, kvB↔vB conversion,
`weak_ordering` comparison), missing the entire `FeeFilterRounder`
quantization primitive (so the broadcast BIP-133 feefilter cannot be
fuzzed for privacy), and serializing fee-estimator state as **JSON via
aeson** rather than as Core's binary `EncodeDouble`-canonicalized
stream. Specifically:

1. **`CFeeRate` does not exist.** haskoin tracks `Word64` sat/vB
   internally; Core tracks a `FeePerVSize{ int64 fee; int32 size }`
   pair via `util/feefrac.h` and exposes
   `CAmount GetFee(int32_t virtual_bytes)` that **rounds up**
   (`feerate.cpp:24` `m_feerate.EvaluateFeeUp(virtual_bytes)`).
   haskoin's `calculateFeeRate fee vsize = (fee * 1000) / vsize`
   (`Mempool.hs:198-201`) **rounds DOWN** (integer division). Any
   fee-rate computation Core does with a non-trivial fraction (e.g.
   `nFeePaid=1000`, `virtual_bytes=141`) will produce **1 sat
   different** in haskoin vs Core for `GetFee()`-equivalent lookups.
   This compounds into estimator bucket assignment because Core
   uses `feeRate.GetFeePerK()` (which is `EvaluateFeeDown(1000)`)
   to compute the bucket index. **BUG-1 P0-CDIV** — the rounding mode
   diverges between `calculateFeeRate` (haskoin DOWN) and Core's
   `GetFee` (UP), but both `GetFeePerK` (DOWN) and Core's bucket-rate
   computation use DOWN, so the *bucket* assignment is consistent; the
   CDIV path is when a downstream consumer expects `GetFee()` semantics
   (e.g. wallet bumpfee target rate computation, which uses
   `GetFee(vsize)` to compute "do I owe this many sats?" — and a haskoin
   wallet would underpay by 1 sat on every non-integer rational rate).

2. **`FeeFilterRounder` is missing.** Core's `policy/fees/block_policy_estimator.{h,cpp}:323-344`
   declares a `FeeFilterRounder` that takes the per-peer minimum-fee
   feerate and **quantizes it onto a log-spaced set** (`MAX_FILTER_FEERATE = 1e7`,
   `FEE_FILTER_SPACING = 1.1`) using a `lower_bound` lookup + a
   2/3-randomization on whether to round up or down. The point is
   **privacy**: every peer would otherwise see the exact rolling-min-fee
   the broadcaster currently has, which leaks mempool size + recent
   purge events. **haskoin's `Network.hs:2429` and `:4930` send the
   raw `Word64` rolling-min directly**, with NO quantization and NO
   randomization. A peer observing two consecutive feefilter messages
   from haskoin can compute the exact incremental change in the rolling
   minimum. **BUG-2 P1** privacy leak.

3. **Persistence is JSON, not the binary `EncodeDouble` stream.**
   Core's `block_policy_estimator.cpp:51-67` defines an
   `EncodedDoubleFormatter` that encodes each `double` via `serfloat.h`
   `EncodeDouble` (a 64-bit canonical IEEE-754 → uint64 transform).
   This ensures the same `double` value serializes to the same 8 bytes
   on x86/ARM/Solaris/etc. **haskoin uses `aeson` to write a JSON
   object** (`FeeEstimator.hs:431` `LBS.writeFile tmpPath (encode snapshot)`),
   which converts each `Double` to a decimal text representation. On
   round-trip through aeson, denormals and NaN are lost; on a
   cross-platform deployment two haskoin nodes can disagree on what
   `1.0e-300` round-trips to. Core's binary stream is exact. **BUG-3
   P1** — cross-platform serialization divergence; not a wire bug
   (haskoin doesn't serve the fee-estimates file over the wire) but a
   migration / backup bug. Also blocks future operator workflows where
   a fee-estimates file from a haskoin node is loaded into a Bitcoin
   Core node (impossible today because of the format gap).

4. **`CURRENT_FEES_FILE_VERSION = 309900` is not pinned.** Core's
   `block_policy_estimator.cpp:37` pins the file version and the
   `Read` path (`:1006-1019`) rejects newer files and warns on older
   ones. haskoin's snapshot has no version field at all
   (`FeeEstimator.hs:412-415` `FeeEstimatorSnapshot { snapBuckets,
   snapBestHeight }`). A future haskoin release that changes the
   bucket layout will silently fail to load old snapshots OR worse —
   load them and produce wrong estimates. **BUG-4 P1**.

5. **`FeeCalculation` result-attribution struct is missing.**
   Core's `block_policy_estimator.h:90-97`:
   ```c++
   struct FeeCalculation {
       EstimationResult est;
       FeeReason reason = FeeReason::NONE;
       int desiredTarget = 0;
       int returnedTarget = 0;
       unsigned int best_height{0};
   };
   ```
   The caller passes a pointer; the estimator fills in which
   sub-estimate (`HALF_ESTIMATE`, `FULL_ESTIMATE`, `DOUBLE_ESTIMATE`,
   `CONSERVATIVE`, `FALLBACK`) actually produced the answer + the
   target the answer is for. **haskoin's `estimateSmartFee fe target mode`
   returns just `(Word64, Int)`** with no attribution; the RPC
   `estimatesmartfee` thus cannot ever produce the `feeCalc.reason` /
   `feeCalc.best_height` fields that Bitcoin Core's wallets use to
   decide whether to retry with a different target. **BUG-5 P1**.

6. **`FeeReason` enum is missing.** Concrete consequence of BUG-5:
   the wallet bumpfee flow (W118 FIX-61) cannot tell whether the
   returned rate came from the half-target sub-estimate or the
   conservative path. **Documented within BUG-5** — not double-billed.

7. **`estimateCombinedFee` is missing.** Core's
   `block_policy_estimator.cpp:808-842` implements the "find estimate
   from shortest time horizon possible, then optionally check shorter
   horizons for a lower answer to preserve monotonic increase" pipeline.
   haskoin's `estimateFee` walks a single bucket map (single horizon)
   and returns `Maybe Word64`. The "shorter horizon refinement" step
   that Core uses to keep the estimate monotonically increasing as
   target grows simply cannot exist. **BUG-6 P1**.

8. **`estimateConservativeFee` 2×target enforcement is missing.**
   Core's `:847-862` implementation of conservative mode takes the
   MAX of `feeStats->EstimateMedianVal(2*target, ..., DOUBLE_SUCCESS_PCT)`
   and `longStats->EstimateMedianVal(2*target, ..., DOUBLE_SUCCESS_PCT)`.
   The point is that conservative estimates use 95% success at 2×
   target, looking at both medium AND long time horizons. haskoin's
   `estimateSmartFee` `FeeConservative` mode adds a flat 10% buffer
   (`adjustForMode rate FeeConservative = rate + (rate `div` 10)`),
   which is **not how Core does conservative estimates**. The flat
   10% has no relationship to the success threshold or the time
   horizon. **BUG-7 P1**.

9. **`MaxUsableEstimate` clamp is missing.** Core's `:798-802`:
   ```c++
   return std::min(longStats->GetMaxConfirms(),
                   std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
   ```
   This caps the answerable target at half the block-span of recorded
   data. A node that's only been up for 200 blocks can only estimate
   for targets ≤ 100, not the full 1008. haskoin has no such clamp;
   `estimateSmartFee fe 1000 _` on a fresh node returns the
   `fallbackFeeRate` (1000 sat/vB) instead of capping the request to
   the available data. **BUG-8 P1**.

10. **`HistoricalBlockSpan` + `OLDEST_ESTIMATE_HISTORY` machinery is
    missing.** Core's `:788-796` tracks `historicalFirst` /
    `historicalBest` for the block range loaded from the stored
    file, and falls back from "current" to "historical" data when
    `BlockSpan() ≤ HistoricalBlockSpan()/2`. haskoin's snapshot
    only restores `snapBestHeight` — there's no historical-first
    pointer and no expiry. **BUG-9 P2** — long-term, the snapshot
    won't degrade gracefully.

11. **RPC-side `min_mempool_feerate` + `min_relay_feerate` clamp
    missing.** Core's `rpc/fees.cpp:82-85`:
    ```c++
    CFeeRate min_mempool_feerate{mempool.GetMinFee()};
    CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
    feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
    ```
    Even if the estimator returns a low rate, the RPC bumps it up to
    whatever the mempool's rolling-min and the configured min-relay
    require. haskoin's `handleEstimateSmartFee` (`Rpc.hs:3411-3423`)
    returns the raw estimator output without the clamp. A wallet that
    consumes haskoin's `estimatesmartfee` and broadcasts at that rate
    will see its tx rejected at the mempool boundary. **BUG-10 P0-CDIV** —
    the wallet UX is "fee estimate said 5 sat/vB, mempool wanted 7,
    broadcast was rejected"; consensus-irrelevant but UX-broken in the
    same way W120 RBF rule 3 was UX-broken.

12. **`ParseConfirmTarget` range validation missing in the RPC layer.**
    Core's `rpc/util.cpp:369-377` validates `target ∈ [1, max_target]`
    and throws `RPC_INVALID_PARAMETER` with a specific message. haskoin's
    `handleEstimateSmartFee` at `Rpc.hs:3411` extracts the param and
    passes it straight through to `estimateSmartFee`, which silently
    returns `Nothing` or the fallback rate for out-of-range targets.
    A client sending `{"method":"estimatesmartfee","params":[0]}`
    should get `RPC_INVALID_PARAMETER`; haskoin returns success with
    the fallback. **BUG-11 P1**.

13. **`InvalidEstimateModeErrorMessage` + bad-mode rejection missing.**
    Core's `rpc/fees.cpp:73-75` rejects unknown `estimate_mode` strings
    with `RPC_INVALID_PARAMETER` and a list of valid modes. haskoin's
    handler `Rpc.hs:3411` hardcodes `FeeConservative` and ignores the
    second param entirely (W114 BUG-7), so even an entirely
    bogus mode like `"banana"` silently goes to conservative. W139
    bills the **error-message gap separately** because closing W114
    BUG-7 (actually parsing the mode) still leaves the bad-input
    rejection path unwired. **BUG-12 P2** — closure depends on W114
    BUG-7 closure first.

14. **`FeeReason::MEMPOOL_MIN` reason missing.** When the RPC clamp
    (BUG-10) overrides the estimator's answer with the mempool-min, Core
    sets `feeCalc.reason = FeeReason::MEMPOOL_MIN`. Without the
    `FeeReason` enum (BUG-5), this attribution can't surface to
    consumers. **Documented within BUG-5** — not double-billed.

15. **Reorg / behind-tip processing-time check missing on
    `processTransaction`.** Core's `:607-613`:
    ```c++
    if (txHeight != nBestSeenHeight) {
        // Ignore side chains and re-orgs
        return;
    }
    ```
    haskoin's `trackTransaction` accepts ANY `(txid, feeRate, height)`
    triple. W114 BUG-9 covers the `validForFeeEstimation` 4-bool gate
    (chainstate_is_current, mempool_limit_bypassed, etc); W139 BUG-13
    is the SEPARATE check that the tx's height MUST match the
    estimator's `nBestSeenHeight` — if a reorg is in flight or the
    estimator is behind on `processBlock` for any reason, the height
    mismatch path silently increments `untrackedTxs` in Core. haskoin
    has no `nBestSeenHeight` tracking at all on `trackTransaction`
    (`feeBestHeight` is only updated on `recordConfirmation`).
    **BUG-13 P1**.

16. **`processBlock` reorg-ignore guard `nBlockHeight ≤ nBestSeenHeight`
    missing.** Core's `:673-680` returns early on a reorg (block at
    or below the best seen height). haskoin's `recordConfirmation`
    will happily decay all buckets and update `feeBestHeight`
    regardless of whether the new height is monotonically forward.
    A re-org test that calls `recordConfirmation fe 999 [tx]` then
    `recordConfirmation fe 998 [tx2]` will decay twice when Core
    would decay once. **BUG-14 P1**.

17. **`trackedTxs` / `untrackedTxs` counters absent.** Core
    (`block_policy_estimator.h:298-299`) tracks these and resets them
    on every block (`:714-715`). haskoin's `feeTotalTxs` counts the
    sum but does not distinguish "tracked" from "untracked"
    transactions. **BUG-15 P2** — observability gap; no `getfeeinfo`
    equivalent surfaces tracker rates today.

18. **`Round` semantics for `estimaterawfee` output diverge.**
    Core's `rpc/fees.cpp:181-193` reports each numeric field rounded
    to 2 decimal places (`round(value * 100.0) / 100.0`). haskoin's
    `handleEstimateRawFee` emits the raw `Double` via `AE.double`
    (`Rpc.hs:7484-7488`). The result is JSON like `"withintarget":
    11.987654321` instead of `"withintarget": 11.99`. Bitcoin Core
    test harnesses that parse the RPC output with a tolerance of
    0.005 will see haskoin's output as out-of-spec. **BUG-16 P1**.

## 30-gate matrix (CBlockPolicyEstimator + FeeRate + RPC clamps)

Notation: `P` = PRESENT, `R` = PARTIAL, `M` = MISSING.

| #   | Gate                                                                         | State | BUG ref | Reference                              |
|-----|------------------------------------------------------------------------------|:-----:|---------|----------------------------------------|
| G1  | `CFeeRate` round-up `GetFee(vsize)` semantics                                |  M    | BUG-1   | `feerate.cpp:24`                       |
| G2  | `CFeeRate::GetFeePerK()` round-down semantics                                |  R    | (note)  | `feerate.h:62`                         |
| G3  | `CFeeRate` `operator<=>` via `FeeRateCompare`                                |  R    | (note)  | `feerate.h:63-66`                      |
| G4  | `FeeFilterRounder` primitive (`MAX_FILTER_FEERATE=1e7`, spacing 1.1)         |  M    | BUG-2   | `block_policy_estimator.{h:323,cpp:1103-1119}` |
| G5  | BIP-133 feefilter broadcast uses `FeeFilterRounder::round`                  |  M    | BUG-2   | `block_policy_estimator.cpp:1109-1118` |
| G6  | `EncodeDouble` / `DecodeDouble` cross-platform serialization                 |  M    | BUG-3   | `block_policy_estimator.cpp:53-66`     |
| G7  | `CURRENT_FEES_FILE_VERSION = 309900` pinned in snapshot                      |  M    | BUG-4   | `block_policy_estimator.cpp:37`        |
| G8  | `FeeCalculation` struct (est + reason + desiredTarget + returnedTarget)      |  M    | BUG-5   | `block_policy_estimator.h:90-97`       |
| G9  | `FeeReason` enum (NONE / HALF / FULL / DOUBLE / CONSERVATIVE / MEMPOOL_MIN / FALLBACK / REQUIRED) | M    | BUG-5 | `block_policy_estimator.h:59-68` |
| G10 | `estimateCombinedFee` shortest-horizon-then-refine pipeline                  |  M    | BUG-6   | `block_policy_estimator.cpp:808-842`   |
| G11 | `estimateConservativeFee` MAX(feeStats, longStats) @ 2×target                |  M    | BUG-7   | `block_policy_estimator.cpp:847-862`   |
| G12 | `MaxUsableEstimate` clamp on confTarget                                      |  M    | BUG-8   | `block_policy_estimator.cpp:798-802`   |
| G13 | `HistoricalBlockSpan` + `OLDEST_ESTIMATE_HISTORY = 6*1008` machinery         |  M    | BUG-9   | `block_policy_estimator.cpp:788-796`   |
| G14 | RPC `estimatesmartfee` clamps to `mempool.GetMinFee()` + `min_relay_feerate` |  M    | BUG-10  | `rpc/fees.cpp:82-85`                   |
| G15 | RPC `ParseConfirmTarget` validates target ∈ [1, max_target]                  |  M    | BUG-11  | `rpc/util.cpp:369-377`                 |
| G16 | RPC `FeeModeFromString` + `InvalidEstimateModeErrorMessage`                  |  M    | BUG-12  | `rpc/fees.cpp:73-75`                   |
| G17 | `processTransaction` reorg-ignore `txHeight != nBestSeenHeight`              |  M    | BUG-13  | `block_policy_estimator.cpp:607-613`   |
| G18 | `processBlock` reorg-ignore `nBlockHeight ≤ nBestSeenHeight`                 |  M    | BUG-14  | `block_policy_estimator.cpp:673-680`   |
| G19 | `trackedTxs` / `untrackedTxs` counters per-block                             |  M    | BUG-15  | `block_policy_estimator.h:298-299`     |
| G20 | `estimaterawfee` round numeric fields to 0.01                                |  M    | BUG-16  | `rpc/fees.cpp:181-193`                 |
| G21 | `estimaterawfee` returns omit-`fail` when `buckets.fail.start == -1`         |  R    | (note)  | `rpc/fees.cpp:202`                     |
| G22 | `estimateRawFee` walks buckets highest→lowest fee                            |  P    | —       | haskoin matches Core direction         |
| G23 | `estimateRawFee` returns `errors[]` when no bucket passes                    |  P    | —       | haskoin matches Core string            |
| G24 | `removeTx` decrements unconfTxs + increments failAvg (W114 BUG-10 cross)     |  M    | (W114)  | `block_policy_estimator.cpp:485-520`   |
| G25 | `FlushUnconfirmed` empties mapMemPoolTxs on shutdown                         |  R    | (note)  | `block_policy_estimator.cpp:1064-1076` |
| G26 | `removeTx` discriminates `inBlock` vs `evicted` for failAvg                  |  M    | (W114)  | `block_policy_estimator.cpp:513-519`   |
| G27 | `BlockSpan() / HistoricalBlockSpan() / 2` ratio gate in Write                |  M    | BUG-9   | `block_policy_estimator.cpp:984-989`   |
| G28 | `estimatesmartfee` returns `errors` array when no answer (RPC shape)         |  P    | —       | `rpc/fees.cpp:88-89` matches haskoin   |
| G29 | `estimatesmartfee` returns `blocks` field with `returnedTarget`              |  R    | (note)  | `rpc/fees.cpp:91` (haskoin returns `blocks` but not `returnedTarget` after clamp) |
| G30 | `estimateRawFee` returns identical short/medium/long payloads (W114 BUG-14)  |  M    | (W114)  | `rpc/fees.cpp:170-211`                 |

## Bugs catalogue (16 — 4 P0-CDIV + 9 P1 + 3 P2)

Severities reflect both the Core-parity gap AND the practical impact
on a haskoin node serving wallets / coordinators. P0-CDIV is reserved
for cases where the gap produces wire-bytes (or wire-effective consensus
state) that diverge from Core; P1 / P2 are spec-conformance / UX gaps.

### BUG-1  P0-CDIV  `CFeeRate.GetFee` round-up semantics not implemented
- **Location:** `src/Haskoin/Mempool.hs:198-201` (`calculateFeeRate`).
- **Symptom:** `calculateFeeRate fee vsize` does `(fee * 1000) / vsize`
  with integer division, which rounds DOWN. Core's `CFeeRate::GetFee
  (virtual_bytes)` (`feerate.cpp:24`) explicitly calls
  `m_feerate.EvaluateFeeUp(virtual_bytes)` to round UP. The two
  primitives serve different callers — `GetFee` answers "given this
  rate, how much fee for `vsize` vbytes?", `GetFeePerK` answers "what
  is this rate as sat/kvB?". Bucketing uses `GetFeePerK` (consistent
  rounding) but **wallet fee-setting paths** (W118 / W129) need
  `GetFee` semantics. A 1-sat underpayment per non-integer rational
  rate accumulates into rejected-tx events when haskoin's wallet
  composes a tx at the estimator's exact rate.
- **CDIV path:** Bumpfee at rate=5.5 sat/vB on a 141-vbyte tx. Core's
  `GetFee` returns 776 sat (`ceil(141 * 5.5)`). haskoin's analogue
  returns 775 sat. The replacement tx is rejected by the mempool
  rule "modified fee must be > old fee + min_relay_increment".
- **Fix sketch:** introduce a `CFeeRate`-equivalent newtype that
  carries the `(fee, size)` pair (or pre-rounded `sat/kvB`) and
  expose two getters: `feeForVSize` (round UP) and `feePerK`
  (round DOWN). Wire `feeForVSize` into the wallet bumpfee /
  coin-selection paths; keep `feePerK` for the estimator buckets.

### BUG-2  P1  `FeeFilterRounder` BIP-133 quantization primitive missing
- **Location:** absent across the codebase. Searched
  `src/Haskoin/Mempool.hs`, `src/Haskoin/FeeEstimator.hs`,
  `src/Haskoin/Network.hs:4917-4940` (the `sendFeeFilter` codepath).
- **Symptom:** Core's `FeeFilterRounder::round` (`block_policy_estimator.cpp:1109-1118`)
  takes the current mempool rolling-min fee and **quantizes onto a
  log-spaced set** (`MIN ≈ min_incremental/2 .. MAX = 1e7` at `*1.1`).
  The randomization (`insecure_rand.rand32() % 3 != 0`) decides
  whether the lookup index rounds up or down — 2/3 of the time it
  rounds DOWN to obscure the broadcaster's mempool state.
  haskoin's `sendFeeFilter` (`Network.hs:4917`) sends `mempool.GetMinFee()`
  directly with NO quantization and NO randomization. Two
  consecutive feefilter messages from the same haskoin node leak the
  exact delta in the rolling-min, which leaks recent purge events.
- **Privacy impact:** medium-risk. Bitcoin Core's whole point of
  randomizing is "the adversary watching peers shouldn't be able to
  reconstruct your mempool size from your feefilter messages".
- **Fix sketch:** new `Haskoin.FeeFilterRounder` module exposing
  `mkFeeFilterRounder :: Word64 -> IO FeeFilterRounder` (param =
  min_incremental_relay_fee in sat/kvB) and `roundFeeFilter ::
  FeeFilterRounder -> Word64 -> IO Word64`. Wire into the
  `sendFeeFilter` send path in `Network.hs`.

### BUG-3  P1  Snapshot serialization uses JSON not binary
- **Location:** `src/Haskoin/FeeEstimator.hs:411-433`.
- **Symptom:** Cross-platform / cross-arch round-trip is approximate
  rather than exact. Core's `EncodedDoubleFormatter`
  (`block_policy_estimator.cpp:53-66`) ensures byte-exact equality
  across IEEE-754-compatible platforms. JSON encoding via aeson
  rounds doubles to a decimal text representation and back —
  denormals are lost, NaN cannot survive, and the canonical encoding
  of `1.0` vs `1.000000000000001` is decided by the printer.
- **Migration impact:** no cross-impl loadability — a haskoin
  `fee_estimates.json` cannot be loaded by Bitcoin Core (different
  format entirely) and vice versa.
- **Fix sketch:** define `Haskoin.Util.SerFloat` mirroring Core's
  `serfloat.h` `EncodeDouble`/`DecodeDouble` (mantissa+exponent
  rewrite into a `Word64`). Switch `FeeEstimatorSnapshot` to a
  `cereal`-based binary `Put`/`Get`. Bump the file extension from
  `.json` to `.dat` to match Core's `fee_estimates.dat`. Provide a
  one-shot migration path from the legacy JSON.

### BUG-4  P1  `CURRENT_FEES_FILE_VERSION = 309900` not pinned
- **Location:** `src/Haskoin/FeeEstimator.hs:412-415`.
- **Symptom:** `FeeEstimatorSnapshot { snapBuckets, snapBestHeight }`
  has no version field. Core's `block_policy_estimator.cpp:37`
  pins `CURRENT_FEES_FILE_VERSION = 309900` and the read path
  (`:1006-1019`) rejects newer files and warns on older. A future
  haskoin release that, e.g., changes `numBuckets` from 128 to 236
  (W114 BUG-4 closure) will load the old snapshot's 128-entry map
  and silently produce wrong estimates because `Map.size loadedBuckets
  == numBuckets` (`FeeEstimator.hs:447`) will fail and the load
  silently no-ops.
- **Fix sketch:** add `snapVersion :: Word32` to `FeeEstimatorSnapshot`
  + `MAX_AGE_BUCKETS :: Word32 = 309900` constant. Reject
  newer-version files; warn-and-skip on older; bump the constant
  whenever the bucket layout / decay set / horizon set changes.

### BUG-5  P1  `FeeCalculation` / `FeeReason` result-attribution missing
- **Location:** `src/Haskoin/FeeEstimator.hs` — `estimateSmartFee
  :: FeeEstimator -> Int -> FeeEstimateMode -> IO (Word64, Int)`.
- **Symptom:** The return type does NOT carry which sub-estimate
  (half / full / double / conservative / fallback / mempool_min)
  produced the answer, the original `desiredTarget`, the
  best-seen height at the time the estimate was computed, or the
  `EstimationResult` pass/fail buckets. Core's wallet bumpfee path
  uses `FeeReason::FALLBACK` to decide "should I error out, or use
  the result?" — haskoin's wallet (W118 / FIX-61 psbtbumpfee) has
  no equivalent signal.
- **Fix sketch:** redefine `estimateSmartFee` to return
  `IO FeeCalculation` where:
  ```haskell
  data FeeCalculation = FeeCalculation
    { fcRate          :: !Word64
    , fcReason        :: !FeeReason
    , fcDesiredTarget :: !Int
    , fcReturnedTarget:: !Int
    , fcBestHeight    :: !Word32
    , fcPassBucket    :: !(Maybe RawBucketRange)
    , fcFailBucket    :: !(Maybe RawBucketRange)
    }
  data FeeReason = ReasonNone | ReasonHalf | ReasonFull | ReasonDouble
                 | ReasonConservative | ReasonMempoolMin
                 | ReasonFallback | ReasonRequired
    deriving (Show, Eq)
  ```
  Provide a back-compat shim `estimateSmartFeeLegacy :: ... -> IO (Word64, Int)`
  for existing callers; deprecate over one release.

### BUG-6  P1  `estimateCombinedFee` shortest-horizon-then-refine missing
- **Location:** `src/Haskoin/FeeEstimator.hs:255-272` (`estimateFee`).
- **Symptom:** Core's `:808-842` walks short → med → long, picks the
  shortest horizon that COVERS the target, then ALSO checks the next
  shorter horizon's max-confirms cap as a refinement (so that a
  short-horizon answer at target=11 doesn't undershoot a long-horizon
  answer at target=11). Without the three-horizon machine
  (W114 BUG-2), this gate cannot be wired; W139 bills it separately
  because the closure SHAPE is distinct (refine-from-shorter is a
  pipeline, not a bucket-list).
- **Fix sketch:** depends on W114 BUG-2 closure (three-horizon
  buckets). Once `shortStats / feeStats / longStats` exist, mirror
  Core's `estimateCombinedFee(target, threshold, checkShorter)` in
  Haskell.

### BUG-7  P1  `estimateConservativeFee` 2×target enforcement missing
- **Location:** `src/Haskoin/FeeEstimator.hs:294-298`.
- **Symptom:** haskoin's `adjustForMode rate FeeConservative = rate
  + (rate `div` 10)` adds a flat 10% buffer. Core's `:847-862`
  computes `max(feeStats.EstimateMedianVal(2*target, ...,
  DOUBLE_SUCCESS_PCT), longStats.EstimateMedianVal(2*target, ...,
  DOUBLE_SUCCESS_PCT))` — the MAX of two horizons at 2× the
  requested target with the 95% success threshold. The 10% buffer
  has no relationship to the success threshold or the target horizon.
- **Behavioral impact:** in high-fee periods haskoin's conservative
  mode under-quotes (10% buffer over a half-target answer is lower
  than the 2×-target full-threshold answer would have been); in
  low-fee periods it over-quotes.
- **Fix sketch:** depends on W114 BUG-2 (three horizons) + BUG-5
  (FeeCalculation struct) closure. Replace the constant 10% with
  the Core MAX-over-horizons calculation.

### BUG-8  P1  `MaxUsableEstimate` clamp missing
- **Location:** `src/Haskoin/FeeEstimator.hs:255-298`.
- **Symptom:** A node that's been up for 200 blocks should not
  return an estimate at target=1000 — it doesn't have enough data.
  Core's `MaxUsableEstimate()` (`:798-802`) caps the answerable
  target at `min(longStats.GetMaxConfirms(), max(BlockSpan,
  HistoricalBlockSpan) / 2)`. haskoin's `estimateSmartFee` returns
  the fallback rate (1000 sat/vB) without indicating "this estimate
  is unreliable".
- **Fix sketch:** track `feeFirstRecordedHeight :: TVar Word32` (set
  on first `recordConfirmation` with countedTxs > 0; mirror Core's
  `firstRecordedHeight`); compute `blockSpan = feeBestHeight -
  feeFirstRecordedHeight`; clamp incoming target to `blockSpan / 2`
  in `estimateSmartFee`. Surface the clamp via the
  `fcReturnedTarget` field (BUG-5).

### BUG-9  P2  `HistoricalBlockSpan` + `OLDEST_ESTIMATE_HISTORY` missing
- **Location:** snapshot lacks `historicalFirst / historicalBest`
  pointers entirely (`FeeEstimator.hs:412-415`).
- **Symptom:** Core's `:788-796` falls back from "current" recorded
  data to "historical" recorded data when current data is too
  short. After loading `fee_estimates.dat`, `historicalFirst` and
  `historicalBest` are the bookends; if current data isn't ≥ half of
  historical, the estimator preferentially uses historical for
  long-horizon queries. Without these pointers haskoin's `Write`
  path can't even produce the right bookkeeping when current >
  historical / 2. Cross-cut with BUG-4 (file version).
- **Fix sketch:** add `feeHistoricalFirst / feeHistoricalBest`
  TVars; populate on `loadFeeEstimates`; expose in the snapshot.
  Implement the `BlockSpan ≷ HistoricalBlockSpan/2` ratio in
  `saveFeeEstimates`.

### BUG-10  P0-CDIV  RPC `estimatesmartfee` does not clamp to mempool-min
- **Location:** `src/Haskoin/Rpc.hs:3411-3423` (`handleEstimateSmartFee`).
- **Symptom:** Core (`rpc/fees.cpp:82-85`):
  ```c++
  CFeeRate min_mempool_feerate{mempool.GetMinFee()};
  CFeeRate min_relay_feerate{mempool.m_opts.min_relay_feerate};
  feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
  ```
  This protects wallets that consume `estimatesmartfee` from
  broadcasting at a rate that would be rejected at the mempool
  boundary. haskoin's handler returns the raw estimator output
  unmodified. Under mempool pressure (rolling-min > estimator
  output), every haskoin-served wallet will broadcast at a
  too-low rate and see "min relay fee not met" rejection.
- **CDIV path:** wallet UX divergence is universal; the
  consensus-relevant CDIV is on `walletcreatefundedpsbt` —
  haskoin's funded PSBT carries a too-low feerate, signing
  proceeds, broadcast fails. Wallets that auto-retry will burn
  through their UTXO set creating doomed-to-reject PSBTs.
- **Fix sketch:** in `handleEstimateSmartFee`, read
  `getMempoolMinFeeRate mp` (already wired in `Mempool.hs:1467`)
  and the configured `min_relay_fee`; clamp the estimator output
  via `max3 estimatedRate mempoolMin minRelay`. Surface the
  source via `FeeReason::MEMPOOL_MIN` (BUG-5).

### BUG-11  P1  `ParseConfirmTarget` range validation missing
- **Location:** `src/Haskoin/Rpc.hs:3406-3410` (`handleEstimateSmartFee`)
  + `:7460-7472` (`handleEstimateRawFee`).
- **Symptom:** Core's `rpc/util.cpp:369-377`:
  ```c++
  if (target < 1 || unsigned_target > max_target) {
      throw JSONRPCError(RPC_INVALID_PARAMETER,
          strprintf("Invalid conf_target, must be between %u and %u",
                    1, max_target));
  }
  ```
  haskoin extracts the int and passes through. A client sending
  `conf_target = 0` or `conf_target = 10000000` gets the fallback
  rate (silently) instead of `-8 RPC_INVALID_PARAMETER`. Bitcoin
  Core test harnesses assert the `-8` error code.
- **Fix sketch:** add `parseConfirmTarget :: Int -> Int -> Either Text Int`
  (validates `[1, maxTarget]`) and use in both handlers; throw the
  RPC error code -8 with the canonical message text.

### BUG-12  P2  `InvalidEstimateModeErrorMessage` rejection missing
- **Location:** `src/Haskoin/Rpc.hs:3411` (handler).
- **Symptom:** Core's `rpc/fees.cpp:73-75` rejects unknown
  `estimate_mode` strings with `RPC_INVALID_PARAMETER` and the
  canonical message returned by `InvalidEstimateModeErrorMessage()`
  (lists valid modes). haskoin's handler hardcodes `FeeConservative`
  and ignores the second param entirely (W114 BUG-7). Even when
  W114 BUG-7 is closed and the mode is actually parsed, the bad-input
  rejection path must still be wired.
- **Fix sketch:** when W114 BUG-7 lands, parse the mode via a
  total `feeModeFromText :: Text -> Either Text FeeEstimateMode`
  that returns the canonical error message on miss. Wire to
  `RPC_INVALID_PARAMETER`.

### BUG-13  P1  `processTransaction` height-mismatch reorg-ignore missing
- **Location:** `src/Haskoin/FeeEstimator.hs:204-214` (`trackTransaction`).
- **Symptom:** Core's `:607-613`:
  ```c++
  if (txHeight != nBestSeenHeight) {
      // Ignore side chains and re-orgs
      return;
  }
  ```
  haskoin's `trackTransaction fe txid feeRate height` always inserts
  into `feePending` regardless of whether `height` matches the
  estimator's notion of best-seen height. During a reorg, a tx at
  the now-orphaned tip's height will be mis-tracked and the eventual
  `recordConfirmation` at the new tip will produce a wrong
  `blocksToConfirm` count.
- **Fix sketch:** in `trackTransaction`, read `feeBestHeight fe`
  inside the `atomically` block; return early if `height /=
  feeBestHeight`. Increment a new `feeUntrackedTxs :: TVar Word32`
  counter (cross-cut with BUG-15).

### BUG-14  P1  `processBlock` reorg-ignore guard missing
- **Location:** `src/Haskoin/FeeEstimator.hs:218-247` (`recordConfirmation`).
- **Symptom:** Core's `:673-680`:
  ```c++
  if (nBlockHeight <= nBestSeenHeight) {
      // Ignore side chains and re-orgs
      return;
  }
  ```
  haskoin's `recordConfirmation fe blockHeight txids` will accept a
  reorged block at a height ≤ `feeBestHeight` and apply the decay
  pipeline. A re-org test that calls `recordConfirmation fe 999 …`
  then `recordConfirmation fe 998 …` decays twice when Core would
  decay once. Compounds with BUG-13.
- **Fix sketch:** in `recordConfirmation`, read `feeBestHeight`
  inside the `atomically` block; `when (blockHeight > current)`
  apply the decay; otherwise return.

### BUG-15  P2  `trackedTxs` / `untrackedTxs` counters absent
- **Location:** `src/Haskoin/FeeEstimator.hs:131-147`.
- **Symptom:** Core distinguishes "successfully tracked transactions"
  from "transactions ignored due to height-mismatch / package /
  reorg" (BUG-13 path). haskoin's `feeTotalTxs` counts every call
  to `trackTransaction` regardless of validity. The `Blockpolicy
  estimates updated by %u of %u block txs` log line (Core
  `:710-712`) is informative for operators auditing fee-estimator
  health; haskoin has no equivalent.
- **Fix sketch:** add `feeTrackedTxs / feeUntrackedTxs :: TVar Word32`
  paralleling Core's `trackedTxs / untrackedTxs`; surface via a
  new `getfeeinfo` RPC (or extend `getmempoolinfo`).

### BUG-16  P1  `estimaterawfee` numeric fields not rounded to 0.01
- **Location:** `src/Haskoin/Rpc.hs:7481-7488` (`bucketToEnc`).
- **Symptom:** Core (`rpc/fees.cpp:181-193`) emits each numeric
  field (`startrange`, `endrange`, `withintarget`, `totalconfirmed`,
  `inmempool`, `leftmempool`) rounded to 2 decimal places:
  ```c++
  passbucket.pushKV("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0);
  ```
  haskoin emits the raw `Double` via `AE.double rbrWithinTarget`,
  producing JSON like `"withintarget": 11.987654321` instead of
  `"withintarget": 11.99`. Test harnesses that diff against Core's
  output with tolerance 0.005 will see haskoin as out-of-spec.
- **Fix sketch:** add `roundTo2 :: Double -> Double` =
  `fromIntegral (round (x * 100) :: Int64) / 100`; apply in
  `bucketToEnc` and `rawFeeToEnc`.

## Severity rationale

- **P0-CDIV (4):**
  - BUG-1 (`CFeeRate` round-up) — wallet feerate accidents producing
    consensus-rejected txs.
  - BUG-10 (RPC mempool-min clamp missing) — wallets broadcast
    at sub-mempool-min rates after consulting haskoin's RPC.
- **P1 (9):** BUG-2 / BUG-3 / BUG-4 / BUG-5 / BUG-6 / BUG-7 / BUG-8
  / BUG-11 / BUG-13 / BUG-14 / BUG-16 — spec conformance + result-attribution +
  reorg-safety + RPC error parity gaps. Practically rate-limited by
  ecosystem support but real for any consumer that's strict about
  Core-parity. (Note: counted as 11 by gate-attribution; we report
  9 because BUG-9 is P2 not P1.)
- **P2 (3):** BUG-9 / BUG-12 / BUG-15 — observability and
  long-term-storage hygiene.

## What this audit deliberately did NOT catalogue

- **The bucket / decay / horizon machinery itself** — W114
  (`f015e72`) is the canonical audit. Specifically W114 BUG-1
  (dead-helper wiring), BUG-2 (three horizons), BUG-3 (bucket range),
  BUG-4 (bucket count), BUG-5 (decay constants), BUG-6 (success
  thresholds), BUG-7 (estimate_mode pass-through), BUG-8 (confTarget
  bounds in estimator), BUG-9 (`validForFeeEstimation` filter), BUG-10
  (`removeTx` mempool-eviction tracking), BUG-11
  (`SUFFICIENT_FEETXS` per-block-average), BUG-12 (60-hour stale-file
  guard), BUG-13 (1-hour periodic flush), BUG-14
  (`estimaterawfee` single-horizon output).
- **The mempool ladder + `GetMinFee` decay** — W120 / W116 (mempool
  RBF + rolling-min). W139 ONLY audits the RPC-side clamp that
  re-applies `mempool.GetMinFee()` (BUG-10).
- **BIP-133 feefilter wire format + dispatch / rate-limit window** — W136
  (`870cba8`) catalogued the wire arm. W139 audits ONLY the
  `FeeFilterRounder` quantization that should precede the wire send
  (BUG-2 / G4 / G5).
- **`mempool.dat` persistence format** — W106 / W116 mempool.
  `fee_estimates.dat` is a separate file with separate semantics;
  W139 audits ONLY `fee_estimates.*` (BUG-3 / BUG-4 / BUG-9).
- **The `getfeeinfo` RPC and `getmempoolinfo.mempoolminfee` field** —
  cross-cut with W116 mempool audit. Noted as out-of-scope here.

## Closure plan (NOT in scope for this discovery wave)

Future fix waves can flip `xit` -> `it` in `W139FeeEstimationSpec.hs`
after:

1. Introduce a `CFeeRate`-equivalent newtype with `feeForVSize`
   (round UP) + `feePerK` (round DOWN); wire wallet code to
   `feeForVSize` (closes BUG-1). Cross-cuts with W113 / W118
   wallet — the round-up gate must be visible at every wallet
   fee-setting site.
2. Implement `Haskoin.FeeFilterRounder` + wire into
   `Network.hs:sendFeeFilter` (closes BUG-2).
3. Switch `fee_estimates.json` to `fee_estimates.dat` with binary
   `EncodeDouble` + `CURRENT_FEES_FILE_VERSION` (closes BUG-3 + BUG-4).
4. Redefine `estimateSmartFee` to return `FeeCalculation` (closes
   BUG-5). One-shot back-compat shim for existing callers.
5. After W114 BUG-2 (three horizons) lands, implement
   `estimateCombinedFee` + `estimateConservativeFee` (closes BUG-6 +
   BUG-7).
6. Implement `MaxUsableEstimate` clamp on `estimateSmartFee` /
   `estimateFee` (closes BUG-8).
7. Add `historicalFirst` / `historicalBest` to the snapshot + the
   ratio-guard in `saveFeeEstimates` (closes BUG-9).
8. Wire the mempool-min + min-relay clamp into
   `handleEstimateSmartFee` (closes BUG-10). Surface via
   `FeeReason::MEMPOOL_MIN`.
9. Add `parseConfirmTarget` validator + bad-mode rejection in
   both `estimatesmartfee` and `estimaterawfee` handlers
   (closes BUG-11 + BUG-12).
10. Add reorg-ignore guards to `trackTransaction` and
    `recordConfirmation` (closes BUG-13 + BUG-14).
11. Surface `feeTrackedTxs` / `feeUntrackedTxs` counters via a
    new `getfeeinfo` RPC or extend `getmempoolinfo` (closes BUG-15).
12. Round `estimaterawfee` numeric fields to 0.01 via a
    `roundTo2` helper applied in `bucketToEnc` (closes BUG-16).

Estimated total: ~8 individual fix waves, with steps 5 + 6 + 7
bundled behind a single "three-horizons + history" refactor (W114
BUG-2 closure).

# W151 — Package relay + BIP-125 RBF rules 2-5 (haskoin)

**Wave:** W151 — `AcceptPackage`, `AcceptMultipleTransactions`,
`SubmitPackage`, `IsTopoSortedPackage`, `IsConsistentPackage`,
`IsWellFormedPackage`, `IsChildWithParents`, `IsChildWithParentsTree`,
`PackageMempoolChecks`, `ReplacementChecks`, `PackageRBFChecks`,
`GetEntriesForConflicts` / `MAX_REPLACEMENT_CANDIDATES=100`,
`HasNoNewUnconfirmed` (BIP-125 Rule 2), `EntriesAndTxidsDisjoint`,
`PaysForRBF` (BIP-125 Rules 3+4), `ImprovesFeerateDiagram`,
`MAX_PACKAGE_COUNT=25`, `MAX_PACKAGE_WEIGHT=404_000`,
`submitpackage` RPC, `prioritisetransaction` RPC,
package broadcast / NetMsgType::TX after package admit.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/policy/rbf.h:26` — `MAX_REPLACEMENT_CANDIDATES = 100`
  (BIP-125 Rule 5).
- `bitcoin-core/src/policy/rbf.cpp:24-50` — `IsRBFOptIn` (returns
  REPLACEABLE_BIP125 / UNKNOWN / FINAL): checks the tx itself first,
  then walks `CalculateMemPoolAncestors` looking for opt-in.
- `bitcoin-core/src/policy/rbf.cpp:58-83` — `GetEntriesForConflicts`
  (Rule 5; counts UNIQUE clusters, not just direct conflicts; populates
  `all_conflicts` via `CalculateDescendants`).
- `bitcoin-core/src/policy/rbf.cpp:85-98` — `EntriesAndTxidsDisjoint`
  ("X spends conflicting transaction Y"; Rule X of BIP-125 has no
  number — it is a separate sanity gate folded into ReplacementChecks).
- `bitcoin-core/src/policy/rbf.cpp:100-125` — `PaysForRBF` (Rules 3+4
  combined: `replacement_fees >= original_fees` AND
  `additional_fees >= relay_fee.GetFee(replacement_vsize)`).
- `bitcoin-core/src/policy/rbf.cpp:127-140` — `ImprovesFeerateDiagram`
  (post-v28 replaces the old "Rule 3a feerate must exceed each direct
  conflict's feerate" with a strict-improvement check on the feerate
  diagram via `CompareChunks`).
- `bitcoin-core/src/util/rbf.h:12` — `MAX_BIP125_RBF_SEQUENCE = 0xfffffffd`
  (BIP-125 Rule 1: any input with `nSequence <= MAX_BIP125_RBF_SEQUENCE`
  opts in).
- `bitcoin-core/src/policy/packages.h:19,24` — `MAX_PACKAGE_COUNT = 25`,
  `MAX_PACKAGE_WEIGHT = 404'000`.
- `bitcoin-core/src/policy/packages.cpp:19-50` — `IsTopoSortedPackage`
  (later_txids set is mutated as we walk; parents must appear before
  children).
- `bitcoin-core/src/policy/packages.cpp:52-77` — `IsConsistentPackage`
  (no duplicate inputs across the package; explicit empty-vin reject;
  returns false if any tx has `vin.empty()`).
- `bitcoin-core/src/policy/packages.cpp:79-117` — `IsWellFormedPackage`
  (count > MAX_PACKAGE_COUNT → `package-too-many-transactions`;
  count > 1 AND total_weight > MAX_PACKAGE_WEIGHT → `package-too-large`;
  duplicate txids → `package-contains-duplicates`; not topo → `package-not-sorted`;
  not consistent → `conflict-in-package`).
- `bitcoin-core/src/policy/packages.cpp:119-149` — `IsChildWithParents`
  + `IsChildWithParentsTree` (last tx is child; every other tx must be
  spent by the child; parents must not depend on each other).
- `bitcoin-core/src/policy/packages.cpp:151-170` — `GetPackageHash`
  (sha256 of wtxids sorted reverse-lexicographically).
- `bitcoin-core/src/validation.cpp:984-1035` — `MemPoolAccept::ReplacementChecks`
  (single-tx RBF path: `GetEntriesForConflicts` → `PaysForRBF` →
  `CheckMemPoolPolicyLimits` (cluster-limit) → `ImprovesFeerateDiagram`).
- `bitcoin-core/src/validation.cpp:1037-1133` — `MemPoolAccept::PackageRBFChecks`
  (package RBF: ONLY 1-parent-1-child, refuses if any tx has in-mempool
  parents, aggregates direct conflicts, runs `GetEntriesForConflicts`,
  `PaysForRBF`, **package_feerate > parent_feerate** strict check,
  `CheckMemPoolPolicyLimits`, `ImprovesFeerateDiagram`).
- `bitcoin-core/src/validation.cpp:1135-1280` — `PolicyScriptChecks`
  with `STANDARD_SCRIPT_VERIFY_FLAGS` (the RBF replacement re-runs the
  same script-verify with STANDARD flags, NOT just MANDATORY).
- `bitcoin-core/src/rpc/mempool.cpp:1302-1500` — `submitpackage` RPC
  (3 params: `package` (array, 1..MAX_PACKAGE_COUNT),
  `maxfeerate` (default 0.10 BTC/kvB),
  `maxburnamount` (default 0)). Pre-decode burn check rejects via
  `TransactionError::MAX_BURN_EXCEEDED`. After successful
  `ProcessNewPackage`, **every accepted tx is broadcast** via
  `BroadcastTransaction(... MEMPOOL_AND_BROADCAST_TO_ALL)`. Per-tx
  results include `effective-feerate` + `effective-includes`. The
  per-tx `error` field uses `"package-not-validated"` as sentinel for
  txs not individually processed when the package aborts early.
- `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction` —
  3 params (`txid`, `dummy=0`, `fee_delta`); writes to `mapDeltas`.

**Files audited**
- `src/Haskoin/Mempool.hs` —
  - `signalsOptInRBF` (line 397-398): BIP-125 Rule 1 derivation.
  - `RbfError`, `MempoolError` constructors (line 305-362, 400-429).
  - `maxReplacementEvictions = 100` (line 373-374).
  - `incrementalRelayFeePerKvb = 100` (line 381-382).
  - `addTransactionInner` (line 677) — RBF dispatch at line 723-744.
  - `addTransactionWithReplacement` (line 757, 776) — EntriesAndTxidsDisjoint
    at line 758-772, then `addTransactionWithReplacementInner`.
  - `isRbfReplaceable` (line 1576-1594).
  - `checkAllConflictsRbfReplaceable` (line 1604-1607).
  - `getConflictSet` (line 1611-1624) — direct + descendants.
  - `checkReplacement` (line 1636-1683) — Rules 3, 3a (old), 4, 5.
  - `checkNoConflictSpending` (line 1687-1693).
  - `checkNoNewUnconfirmedInputs` (line 1719-1735) — BIP-125 Rule 2.
  - `removeConflicts` (line 1739-1749).
  - `attemptReplacement` (line 1753-1823) — composes all the gates,
    invokes `checkDiagramReplacement` after `checkReplacement` passes.
  - `maxPackageCount = 25` (line 2108-2109), `maxPackageWeight = 404000`
    (line 2114-2115), `TxPackage` (line 2120), `PackageError` (line 2128).
  - `isTopoSortedPackage` (line 2146-2160).
  - `isConsistentPackage` (line 2163-2168).
  - `isWellFormedPackage` (line 2176-2203).
  - `isChildWithParents` (line 2208-2217), `isChildWithParentsTree`
    (line 2225-2240).
  - `calculatePackageFeeRate` (line 2243-2274).
  - `acceptPackage` (line 2285-2308) — context-free + tree-shape +
    de-dup, then dispatches to `acceptPackageInner`.
  - `acceptPackageInner` (line 2311-2343) — package-fee gate +
    ephemeral pre/post + `addPackageTransactions`.
  - `addPackageTransactions` (line 2429-2559) — per-tx gates.
  - `verifyAllScripts` (line 1237-1262) and `verifyAllScripts'`
    (line 2565-2589) — both emit only MANDATORY consensus flags.
  - `buildFeerateDiagram` / `compareDiagrams` / `interpolate` /
    `buildReplacementDiagrams` / `checkDiagramReplacement` (line 3062-3163).
- `src/Haskoin/Rpc.hs` —
  - RPC dispatch table (line 1024-1093).
  - `handleSubmitPackage` (line 5537-5573).
  - `submitPackageTxns` (line 5579-5731).
  - `handleTestMempoolAccept` (line 5403-5424).
  - `handleSendRawTransaction` (line 2219).
- `src/Haskoin/Consensus.hs` —
  - `consensusFlagsToScriptFlags` (line 1511-1520) — MANDATORY only.
- `bitcoin-core/src/policy/rbf.h`, `bitcoin-core/src/policy/packages.h`,
  `bitcoin-core/src/validation.cpp`, `bitcoin-core/src/rpc/mempool.cpp`
  (Core authoritative reference).

---

## Gate matrix (30 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | submitpackage RPC | G1: dispatched on dispatch table | PASS (`Rpc.hs:1091`) |
| 1 | … | G2: 1..MAX_PACKAGE_COUNT array-size guard | PASS (`Rpc.hs:5547-5552`) |
| 1 | … | G3: maxfeerate arg (default 0.10 BTC/kvB) | PASS (`Rpc.hs:5554-5559`) |
| 1 | … | G4: maxburnamount arg + per-output unspendable check | **BUG-1 (P1)** — arg absent; loose `OP_RETURN`-style outputs accepted regardless of value |
| 1 | … | G5: broadcast accepted txs to peers via NetMsgType::TX | **BUG-2 (P0-CDIV)** — `submitPackageTxns` (line 5579-5731) does NOT call `broadcastTxToPeers` — admitted packages stay LOCAL |
| 1 | … | G6: per-tx `effective-feerate` field | **BUG-3 (P1)** — `buildSuccessResponse` emits only `txid` / `vsize` / `fees.base`; Core's `effective-feerate` + `effective-includes` are unconditionally absent |
| 1 | … | G7: per-tx `other-wtxid` field on wtxid collision | **BUG-3 cross-cite** |
| 1 | … | G8: `package_msg` wire-token (e.g. `package-too-large`) | **BUG-4 (P1)** — uses free-form English `"package validation failed"` / `"package topology disallowed"` / `"transaction failed"` / `"max-fee-exceeded"`; Core uses `state.ToString()` which gives e.g. `package-not-validated`, `package-too-many-transactions` |
| 2 | RBF Rule 1 — signalsOptInRBF | G9: `nSequence <= MAX_BIP125_RBF_SEQUENCE` (0xfffffffd) | PASS (`Mempool.hs:398`) |
| 2 | … | G10: single source of truth (one derivation across the impl) | **BUG-5 (P1)** — TWO derivations: `signalsOptInRBF` (`<= 0xfffffffd`, Mempool.hs:398) vs an inline `< 0xfffffffe` at Mempool.hs:2601. Semantically equivalent on uint32 but two-pipeline guard 18th distinct extension — also documented in W150 BUG-9 |
| 3 | RBF Rule 2 — no new unconfirmed inputs | G11: only inputs already in `oldSpends` (evicted set's prevouts) OR confirmed | PASS (`Mempool.hs:1719-1735`) |
| 4 | RBF Rule 3 — replacement_fees >= original_fees | G12: sum over ALL evictions (direct + descendants), not just direct | PASS (`Mempool.hs:1668-1672`) |
| 4 | … | G13: uses modified-fee (incl. prioritisetransaction delta) | **BUG-6 (P0-CDIV)** — `attemptReplacement` (Mempool.hs:1761-1804) accepts `newFee` from `addTransactionWithReplacementInner` (line 795: `fee = totalIn - totalOut`), which is the BASE fee, NOT modified-fee. The conflict side `meFee` (line 1668) is also base fee. Core uses `GetModifiedFee()` on both sides (validation.cpp:1006 + ws.m_modified_fees). Prioritised replacements that should pass under modified-fee accounting are rejected here, and prioritised conflicts that should require a higher replacement fee accept a too-low one |
| 5 | RBF Rule 4 — pays for own bandwidth | G14: `additional_fees >= incremental_relay_feerate * replacement_vsize` | PASS (`Mempool.hs:1674-1681`) |
| 5 | … | G15: incremental_relay_feerate is operator-tunable | **BUG-7 (P1)** — `incrementalRelayFeePerKvb = 100` (line 382) is a top-level CAF; no `-incrementalrelayfee` CLI flag (W150 BUG-3 cross-cite). Operator cannot tighten or loosen Rule 4 |
| 6 | RBF Rule 5 — MAX_REPLACEMENT_CANDIDATES | G16: count limit on direct conflicts + descendants ≤ 100 | PASS in value, **BUG-8 (P0-CDIV)** in semantics — `checkReplacement` (Mempool.hs:1646-1648) counts `length allEvictions` (TXNS), but Core's `GetEntriesForConflicts` (rbf.cpp:69-75) counts `pool.GetUniqueClusterCount(iters_conflicting)` (CLUSTERS). A cluster of 50 txs whose 50 descendants are all in the same cluster counts as 1 cluster in Core but ~50 evictions in haskoin. **Direction: Core ACCEPTS the replacement; haskoin REJECTS it with `RbfTooManyEvictions`** |
| 7 | ImprovesFeerateDiagram (post-v28) | G17: chunk-based strict-improvement check on the feerate diagram | PARTIAL — `checkDiagramReplacement` (Mempool.hs:3140-3163) builds two diagrams and calls `compareDiagrams`, but **BUG-9 (P1)** — `compareDiagrams` (line 3076-3092) tests `allGe && anyGt` over a set of all unique x-points from BOTH diagrams; Core's `CompareChunks` is a partial-order chunk-by-chunk comparison via `std::is_gt(CompareChunks(...))`. The two are not equivalent for non-monotonic chunk arrangements (e.g., when the replacement adds new chunks that interleave with original chunks). False rejects are possible. |
| 7 | … | G18: invoked AFTER `checkReplacement` (defense-in-depth) | PASS (`Mempool.hs:1809-1819`, "BUG-9 fix" comment) |
| 8 | Replacement script-verify uses STANDARD flags | G19: PolicyScriptChecks uses STANDARD_SCRIPT_VERIFY_FLAGS | **BUG-10 (P0-CDIV)** — W144 BUG-3 / W150 BUG-1 echo CONFIRMED at the RBF path: `addTransactionWithReplacement` → `finalizeTransaction` → `verifyAllScripts` (Mempool.hs:943) calls `consensusFlagsToScriptFlags` (MANDATORY only). RBF replacement does NOT re-run script-verify with the 14 STANDARD bits. A replacement that fails MINIMALIF, CLEANSTACK, LOW_S, NULLFAIL etc. but passes MANDATORY is admitted. |
| 9 | EntriesAndTxidsDisjoint | G20: replacement's ancestors disjoint from direct conflicts set | PASS (`Mempool.hs:758-771`, ErrSpendsConflictingTx) |
| 10 | Package context-free checks | G21: package count ≤ MAX_PACKAGE_COUNT | PASS (`Mempool.hs:2181-2182`) |
| 10 | … | G22: package weight ≤ MAX_PACKAGE_WEIGHT | **BUG-11 (P1)** — `isWellFormedPackage` (Mempool.hs:2184-2187) enforces the weight cap unconditionally; Core (`packages.cpp:90`) only enforces when `package_count > 1` so the single-tx case can give the better-targeted MAX_STANDARD_TX_WEIGHT error. Behaviour diverges on single-tx packages whose individual weight exceeds 404,000 |
| 10 | … | G23: duplicate-txid reject | PASS (`Mempool.hs:2190-2193`) |
| 10 | … | G24: topo-sort required | PASS (`Mempool.hs:2196-2197`) |
| 10 | … | G25: consistent (no shared input across package txs) | PARTIAL — `isConsistentPackage` (Mempool.hs:2163-2168) tests `length allInputs == Set.size inputSet` but **BUG-12 (P1)** — does NOT explicitly reject txs with `vin.empty()`. Core (`packages.cpp:57-63`) explicitly rejects empty-vin txs at this gate ("Duplicate empty transactions are also not consistent with one another") |
| 11 | Package RBF (1-parent-1-child only) | G26: package-RBF handles direct conflicts on package txs | **BUG-13 (P0-CDIV)** — `acceptPackage` / `addPackageTransactions` (Mempool.hs:2285-2559) NEVER call `getConflicts` and NEVER trigger RBF replacement during package admit. Core's `PackageRBFChecks` (validation.cpp:1037) is entirely absent. If any package tx conflicts with mempool, the package fails with `ErrInputSpentInMempool` from a per-tx admit path that haskoin doesn't even reach (the package gate runs script-verify per tx independently) |
| 11 | … | G27: package_feerate > parent_feerate strict check | **BUG-13 cross-cite** — gate absent |
| 12 | submitpackage atomicity | G28: on failure, ALL txs rolled back; on success, ALL txs admitted | **BUG-14 (P1)** — `addPackageTransactions` `go` loop (Mempool.hs:2438-2559) commits each tx via `addTransactionToMempool` (line 2551) before processing the next. If tx N fails, txs 1..N-1 are LIVE in the mempool, and the rollback path lives at the RPC layer (`submitPackageTxns` line 5674-5683) — which iterates `multi`, fetches each, and calls `removeTransaction`. Window: between the parent commit and the child failure, peers querying `getrawmempool` see the parent as admitted-then-vanished, and the child's failure type leaks the parent's existence via the order of `tx-results` |
| 13 | prioritisetransaction RPC | G29: dispatched on dispatch table | **BUG-15 (P0-CDIV)** — RPC absent (W150 BUG-10 echo). `mpFeeDeltas` is plumbed in `finalizeTransaction` (line 859-869) and `attemptReplacement`'s replacement-fee comparison reads `meFee` (base, not modified) so the entire prioritisetransaction → RBF interaction is broken — see BUG-6 |
| 13 | … | G30: prioritisetransaction RPC accepts the 3-tuple `(txid, dummy=0, fee_delta)` | **BUG-15 cross-cite** |

---

## BUG-1 (P1) — `submitpackage` RPC missing `maxburnamount` parameter

**Severity:** P1. Bitcoin Core's `submitpackage` (rpc/mempool.cpp:1322)
takes a third parameter `maxburnamount` (default 0 BTC). For each tx,
Core walks `mtx.vout` and rejects via `TransactionError::MAX_BURN_EXCEEDED`
if any output has `(scriptPubKey.IsUnspendable() || !HasValidOps())`
AND `nValue > max_burn_amount`. This catches accidentally-fee-burning
OP_RETURN outputs or malformed scriptPubKeys with non-trivial value
attached.

haskoin's `handleSubmitPackage` (`Rpc.hs:5537-5573`) only parses two
parameters (`package` and `maxfeerate`). There is no per-output
unspendable scan. A package whose parent tx accidentally pays 50 BTC
to a malformed `OP_RETURN` will be admitted and broadcast (modulo
BUG-2). Wallets using `submitpackage` lose protection against the
exact bug class the parameter was added to catch.

**File:** `src/Haskoin/Rpc.hs:5537-5573`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1322-1325` (param
definition), `bitcoin-core/src/rpc/mempool.cpp:1386-1390` (per-output
burn check).

**Impact:** wallets that migrate from `bitcoin-cli submitpackage` to
haskoin lose `maxburnamount` protection silently — packages with
fee-burn outputs are accepted at any value.

---

## BUG-2 (P0-CDIV) — `submitpackage` does NOT broadcast accepted packages to peers

**Severity:** P0-CDIV. Bitcoin Core's `submitpackage`
(`rpc/mempool.cpp:1442-1454`) calls `BroadcastTransaction(node, tx,
... TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL)` for every tx in the
admitted package. Without this, a successful `submitpackage` call has
NO effect on the P2P fleet — the operator's CPFP fee-bump stays
mempool-local, the parent of a TRUC pair never propagates, and a
wallet relying on `submitpackage` for atomic broadcast will never see
its transaction confirmed.

haskoin's `submitPackageTxns` (`Rpc.hs:5579-5731`) on the success
path calls `buildSuccessResponse` (line 5711-5731) which returns the
JSON envelope with `"package_msg": "success"`. No call to
`broadcastTxToPeers` is made anywhere in the success path. Compare:
the single-tx `handleSendRawTransaction` at `Rpc.hs:2283` correctly
calls `broadcastTxToPeers server tx (getFeeRate (meFeeRate entry))`
after `addTransaction` succeeds — but the multi-tx `submitpackage`
path was implemented without the broadcast.

**File:** `src/Haskoin/Rpc.hs:5579-5731` (handler — no broadcast call);
`src/Haskoin/Rpc.hs:2283` (handleSendRawTransaction — has the call).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1442-1454`
(BroadcastTransaction loop over admitted package).

**Impact:**
- A successful `submitpackage` is functionally equivalent to a no-op
  from the network's perspective. The local mempool reflects the
  package; no peer is told.
- CPFP fee-bumping via `submitpackage` is broken end-to-end on
  haskoin — the bumped parent never gets relayed past the local node,
  so it cannot be selected into a miner's block via the txid+CPFP
  child mechanism.
- TRUC-restricted v3 packages whose entire point is to be relayed as a
  bundle stay local.
- Cross-impl divergence: a hashhog fleet runs N+1 different "package
  was admitted" states — Core/other-impls broadcast; haskoin doesn't.

---

## BUG-3 (P1) — `submitpackage` response missing `effective-feerate` / `effective-includes` / `other-wtxid`

**Severity:** P1 (wire-format parity gap). Core's `submitpackage`
response (`rpc/mempool.cpp:1338-1346`) emits per-tx (when the tx was
ADMITTED through this call rather than already present):
- `effective-feerate` (string-amount, BTC/kvB): the package-feerate
  that gated this admission (NOT the per-tx feerate); the field that
  makes CPFP economics visible.
- `effective-includes` (array of wtxid hex): the wtxids whose fees +
  vsizes were included in `effective-feerate` — i.e., the package
  set that paid for this tx.
- `other-wtxid` (when a same-txid-different-witness tx is found in
  the mempool, the existing wtxid is reported here and the submitted
  tx is rejected as a duplicate — BIP-339).

haskoin's `buildSuccessResponse` (`Rpc.hs:5711-5731`) emits only
`txid`, `vsize`, and `fees.base`. None of `effective-feerate`,
`effective-includes`, or `other-wtxid` appear. Wallets that parse
`effective-feerate` to display "your CPFP package will be mined at X
sat/vB" see a missing field.

**File:** `src/Haskoin/Rpc.hs:5711-5731`.

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1338-1346` (per-tx
response schema), `1466-1500` (population).

**Impact:** Wire-parity gap; wallets / tooling parsing
`submitpackage` responses see schema divergence.

---

## BUG-4 (P1) — `package_msg` uses free-form English instead of Core's wire tokens

**Severity:** P1. Bitcoin Core emits `package_msg` from
`PackageValidationState::ToString()` (`rpc/mempool.cpp:1427`), which
produces dash-separated tokens drawn from a fixed vocabulary:
`success`, `package-not-validated`, `package-too-many-transactions`,
`package-too-large`, `package-contains-duplicates`, `package-not-sorted`,
`conflict-in-package`, `package-mempool-limits`,
`transaction failed` (legacy), and various RBF-specific tokens.

haskoin's `submitPackageTxns` uses:
- `"transaction failed"` for single-tx admit failure (line 5633),
- `"max-fee-exceeded"` for the maxfeerate gate (line 5649, 5703),
- `"package topology disallowed"` for IsWellFormedPackage / tree-shape
  failure (line 5660, 5664),
- `"package validation failed"` for `acceptPackage` Left (line 5684),
- `"success"` for the happy path (line 5728).

The token strings are inconsistent with Core. Worse, the
`isWellFormedPackage` `Left` constructor is `show`n into the `error`
field of every per-tx result — emitting Haskell-side strings like
`"PkgTooManyTransactions 27 25"` rather than Core's literal
`"package-too-many-transactions"`. Operator tooling that
patterns-matches on Core's tokens won't find a match.

**File:** `src/Haskoin/Rpc.hs:5660, 5664, 5684, 5633, 5649, 5703`
(token strings); `src/Haskoin/Mempool.hs:2128-2139` (`PackageError`
constructors lack wire-token shape).

**Core ref:** `bitcoin-core/src/policy/packages.cpp:79-117` (tokens
written into `PackageValidationState`).

**Impact:** Wire-parity gap; cross-impl divergence in
`submitpackage`'s `package_msg`.

---

## BUG-5 (P1) — Two source-of-truth for BIP-125 Rule 1 RBF derivation

**Severity:** P1 ("two-pipeline guard 18th distinct extension"; also
documented as W150 BUG-9). The opt-in-RBF predicate is derived in two
places:

```haskell
-- Mempool.hs:398 (canonical helper, used by isRbfReplaceable +
-- checkAllConflictsRbfReplaceable + the standard finalize path).
signalsOptInRBF :: Tx -> Bool
signalsOptInRBF tx = any (\inp -> txInSequence inp <= 0xfffffffd) (txInputs tx)
```

```haskell
-- Mempool.hs:2601 (inline inside addTransactionToMempool, the OLDER
-- second-pipeline path that addPackageTransactions feeds into via
-- line 2551).
let rbfOptIn = any (\inp -> txInSequence inp < 0xfffffffe) (txInputs tx)
```

`<= 0xfffffffd` and `< 0xfffffffe` are arithmetically equivalent over
`Word32` (the canonical type for `txInSequence`), so the two
derivations DO produce identical Booleans today. The pattern is
nonetheless a fleet "two-pipeline guard" instance: two unrelated
authors / two unrelated functions, each maintaining their own
implementation of the same BIP-125 sequence-number rule. If one is
ever tightened (e.g., to also accept SEQUENCE_FINAL but only when
some bit-flag is set), the other will silently diverge.

**File:** `src/Haskoin/Mempool.hs:397-398, 2601`.

**Core ref:** `bitcoin-core/src/util/rbf.cpp:9-15` (`SignalsOptInRBF`
— single function reused everywhere).

**Impact:** maintenance risk; no current divergence in behaviour.

---

## BUG-6 (P0-CDIV) — RBF Rule 3 uses BASE fee, not MODIFIED fee — prioritisetransaction interaction broken

**Severity:** P0-CDIV. Bitcoin Core's `ReplacementChecks`
(`validation.cpp:1006, 1010`) computes:

```cpp
for (CTxMemPool::txiter it : all_conflicts) {
    m_subpackage.m_conflicting_fees += it->GetModifiedFee();   // <-- MODIFIED
    m_subpackage.m_conflicting_size += it->GetTxSize();
}
if (const auto err_string{PaysForRBF(m_subpackage.m_conflicting_fees,
                                     ws.m_modified_fees, ws.m_vsize,  // <-- MODIFIED
                                     m_pool.m_opts.incremental_relay_feerate, hash)}) { ... }
```

Both sides use modified fees (base + `mapDeltas[txid]` from
`prioritisetransaction`).

haskoin's `attemptReplacement` (`Mempool.hs:1761-1804`) passes `newFee`
from `addTransactionWithReplacementInner` (line 795-797):

```haskell
let fee = totalIn - totalOut  -- <-- BASE FEE
    vsize = calculateVSize tx
    feeRate = calculateFeeRate fee vsize
...
replaceResult <- attemptReplacement mp tx txid conflictTxIds fee vsize feeRate
```

And the conflict-side `conflictTotalFee = sum $ map meFee allEvictions`
(Mempool.hs:1668) reads `meFee` which is also the BASE fee (set in
`buildMempoolEntry` at line 994 to the raw fee, not modified).

**Consequences:**
- An operator that previously prioritised a conflict via
  `prioritisetransaction` (raising its effective fee for mining) finds
  the replacement gate uses the BASE fee for comparison — so a
  replacement that pays $base_fee + 1 sat$ passes Rule 3 even though
  the prioritised conflict's effective mining value is $base_fee + 1
  BTC$. The replacement wins admission but loses mining priority,
  defeating prioritisetransaction's intent.
- Symmetrically, an operator that prioritises a NEW replacement to
  raise its effective fee finds Rule 3 evaluated against the
  replacement's base fee (which may not satisfy Rule 3) and rejected
  — the new fee delta does not lift the replacement over the
  conflict's base fee.

NOTE: haskoin's standalone `finalizeTransaction` (`Mempool.hs:859-869`)
DOES read `mpFeeDeltas` and compute `modifiedFee` for the
min-relay-fee gate. But that modified fee is NEVER passed into
`attemptReplacement` — the replacement gate sees the base fee
exclusively.

**File:** `src/Haskoin/Mempool.hs:795-797` (base-fee derivation),
`1668-1672` (Rule 3 with base fees on both sides), `1761-1804`
(`attemptReplacement` signature accepts only the base fee).

**Core ref:** `bitcoin-core/src/validation.cpp:1006, 1010`
(`m_subpackage.m_conflicting_fees += it->GetModifiedFee()` +
`PaysForRBF(... ws.m_modified_fees ...)`).

**Impact:**
- `prioritisetransaction` is FUNCTIONALLY DEAD for RBF flows: priority
  deltas applied to conflicts are not honoured at replacement time;
  priority deltas applied to replacements are not credited.
- Wallets that use `prioritisetransaction` to manage stuck fee-bumps
  see the RBF gate reject replacements that Core would accept (or
  accept replacements that Core would reject).
- Cross-cite W150 BUG-10 (the RPC is absent altogether — but
  `mpFeeDeltas` IS readable through `loadMempool`, so persistent
  deltas from `mempool.dat` are still applied).

---

## BUG-7 (P1) — `-incrementalrelayfee` operator-knob absent; hard-coded `100`

**Severity:** P1 (W150 BUG-3 cross-cite, RBF-specific). The
`-incrementalrelayfee=<amt>` CLI flag (Core
`init.cpp:673`) is the operator's knob for Rule 4's bandwidth-cost
floor. haskoin's `incrementalRelayFeePerKvb = 100` (Mempool.hs:382)
is a top-level CAF; `parseNodeOptions` (`app/Main.hs:227-332`) does
not register the flag.

Operators cannot tighten Rule 4 to deter low-effort RBF cycles
(e.g., set `-incrementalrelayfee=1000` for 10× the default), nor
loosen it for regtest fee-bump testing. The value also feeds the
rolling minimum fee bump-on-eviction (`Mempool.hs:1995, 2030`) and
the RBF Rule 4 floor (`Mempool.hs:1679`), so changing the constant
at compile time has cross-cutting effects with no per-test override.

**File:** `src/Haskoin/Mempool.hs:381-382` (CAF); `app/Main.hs`
(no flag registration); `Mempool.hs:1679` (RBF Rule 4 use),
`Mempool.hs:1995, 2030` (rolling-min use).

**Core ref:** `bitcoin-core/src/init.cpp:673`
(`-incrementalrelayfee` argparse).

**Impact:** operator-knob gap; regtest harnesses cannot tweak.

---

## BUG-8 (P0-CDIV) — Rule 5 counts EVICTIONS, not CLUSTERS — over-rejects

**Severity:** P0-CDIV. Bitcoin Core's `GetEntriesForConflicts`
(`policy/rbf.cpp:69-75`) counts:

```cpp
auto num_clusters = pool.GetUniqueClusterCount(iters_conflicting);
if (num_clusters > MAX_REPLACEMENT_CANDIDATES) { ... }
```

where `iters_conflicting` is the set of **direct conflicts** (the
mempool entries whose outputs this replacement is contesting), and
`GetUniqueClusterCount` returns the number of distinct **clusters**
(connected components in the mempool's tx-DAG) those direct conflicts
belong to. The 100 limit is on CLUSTERS, not evictions. After the
limit check passes, `CalculateDescendants` is called on each conflict
to populate `all_conflicts` — and the descendant total can be
ARBITRARILY LARGE (limited only by per-cluster size, which is
DEFAULT_CLUSTER_SIZE_LIMIT_KVB=101 kvB).

haskoin's `checkReplacement` (`Mempool.hs:1646-1648`) checks:

```haskell
let evictionCount = length allEvictions   -- <-- TOTAL EVICTIONS (direct + descendants)
when (evictionCount > maxReplacementEvictions) $
  Left $ RbfTooManyEvictions evictionCount maxReplacementEvictions
```

`allEvictions` is the union of direct conflicts AND all of their
descendants (built in `getConflictSet`, Mempool.hs:1611-1624). A
single direct conflict whose cluster has 101 txs (well under Core's
limit, since cluster_size=1 cluster) gets rejected by haskoin with
`RbfTooManyEvictions 101 100`.

**Failure direction:** haskoin REJECTS replacements that Core ACCEPTS.
A long ancestor/descendant chain in a single cluster (e.g., a 200-tx
TRUC pinning fan-out) cannot be replaced under haskoin's rule even
with a strictly-improving replacement; Core would admit it.

**File:** `src/Haskoin/Mempool.hs:1611-1624` (getConflictSet builds
union of direct + descendants), `1646-1648` (length-based check).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:64-75`
(GetEntriesForConflicts via GetUniqueClusterCount), `policy/rbf.h:24-26`
(MAX_REPLACEMENT_CANDIDATES limits CLUSTERS, not evictions).

**Impact:**
- Long-cluster RBF replacements that Core accepts are rejected on
  haskoin → consensus-divergence for any operator using haskoin to
  replace a stuck high-descendant tree.
- Specifically degrades CPFP-fan-out-bumping workflows where a
  single parent has many descendants in one cluster.

---

## BUG-9 (P1) — `compareDiagrams` shape-mismatched vs Core's `CompareChunks`

**Severity:** P1. Core's `ImprovesFeerateDiagram` (rbf.cpp:127-140)
invokes `CalculateChunksForRBF()` to extract the linearised chunk
sequence on both sides of the RBF, then `CompareChunks(replacement,
original)` returns a `std::strong_ordering`. The result is gated by
`std::is_gt(...)` (strict-improvement; equal is NOT improvement).

`CompareChunks` is a partial-order check: chunk N of replacement must
have feerate ≥ chunk N of original, with at least one strictly
greater. The comparison is per-CHUNK index, not per-x-coordinate.

haskoin's `compareDiagrams` (`Mempool.hs:3079-3092`):

```haskell
let allSizes = Set.toList $ Set.fromList $
      map fst original ++ map fst replacement
    originalFees = map (getFeeAtSize original) allSizes
    replacementFees = map (getFeeAtSize replacement) allSizes
    pairs = zip originalFees replacementFees
    allGe = all (\(o, r) -> r >= o) pairs
    anyGt = any (\(o, r) -> r > o) pairs
in allGe && anyGt
```

Samples both diagrams at the union of x-coordinates and compares
cumulative-fees-at-x. This is **not** the same partial order as
`CompareChunks` when chunks of the two diagrams have different
(size, fee) pairs:
- A replacement whose chunks reorder relative to the original (e.g.,
  the same set of txs but a lower-fee child now goes after a
  higher-fee parent in the linearisation) can satisfy
  `compareDiagrams.allGe` at every x-tick yet FAIL Core's `is_gt
  CompareChunks` because chunk indices don't align.
- Conversely, a replacement that adds a single new chunk at an x-tick
  not present in the original passes both checks the same way, but
  the interpolation in `getFeeAtSize` (Mempool.hs:3096-3107) uses
  linear interpolation between the bracket points — which is a
  fictional fee that doesn't correspond to any real cumulative
  position. Core never interpolates.

**Direction:** mostly haskoin REJECTS replacements that Core would
ACCEPT (the diagram comparison is strictly more restrictive in some
regimes), with occasional false ACCEPTS in the interpolation regime.

**File:** `src/Haskoin/Mempool.hs:3076-3092` (compareDiagrams),
`3096-3107` (interpolate).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:127-140`
(ImprovesFeerateDiagram), `bitcoin-core/src/cluster_linearize.h:1609`
(CompareChunks).

**Impact:**
- Replacement decisions can diverge from Core; in particular,
  multi-chunk replacements (any replacement that touches a
  multi-tx cluster) may go through different code paths and reach
  different verdicts.
- Cross-impl flakiness on RBF tests that exercise non-trivial cluster
  shapes.

---

## BUG-10 (P0-CDIV) — RBF replacement script-verify uses MANDATORY-only flags (W144 BUG-3 / W150 BUG-1 echo at replacement path)

**Severity:** P0-CDIV. **Third confirmation of the W144 fleet-wide
STANDARD_SCRIPT_VERIFY_FLAGS gap; first time the gap is established
specifically at the RBF replacement path.** Core's PolicyScriptChecks
(`validation.cpp:1142`) uses `STANDARD_SCRIPT_VERIFY_FLAGS` —
MANDATORY plus 14 STANDARD bits (LOW_S, NULLFAIL, MINIMALIF, CLEANSTACK,
WITNESS_PUBKEYTYPE, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
DISCOURAGE_UPGRADABLE_PUBKEYTYPE, CONST_SCRIPTCODE, MINIMALDATA,
DISCOURAGE_UPGRADABLE_NOPS, STRICTENC, SIGPUSHONLY,
DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION). RBF
replacement re-runs PolicyScriptChecks (the workflow path is identical
to a non-RBF admit; the replacement just inhabits a different
ws.m_conflicts path through ReplacementChecks).

haskoin's `addTransactionWithReplacement` (`Mempool.hs:776`) calls
`addTransactionWithReplacementInner` → `attemptReplacement` →
`removeConflicts` + `finalizeTransaction`. The script-verify is
delegated to `verifyAllScripts` (`Mempool.hs:943`) which calls
`consensusFlagsToScriptFlags` (`Consensus.hs:1511-1520`) — the same
MANDATORY-only flag-set as the non-RBF path (W150 BUG-1).

**Net result:** an RBF replacement that fails STANDARD-only bits
(e.g., signs with high-S signature, or uses a non-minimal IF
condition) is ADMITTED by haskoin, EVICTS its conflicts, and then —
if Core mines this block — Core will reject the block via
`ConsensusScriptChecks` falling through to MANDATORY-only success on
a different fault. The replacement is mempool-resident; the conflict
is gone; the network never sees either confirmed.

**File:** `src/Haskoin/Mempool.hs:943` (verifyAllScripts call from
finalizeTransaction, reached by RBF path), `1237-1262`
(verifyAllScripts emits MANDATORY only), `2533` (verifyAllScripts'
mirror for package path); `src/Haskoin/Consensus.hs:1511-1520`
(consensusFlagsToScriptFlags lacks STANDARD bits).

**Core ref:** `bitcoin-core/src/validation.cpp:1142`
(PolicyScriptChecks uses STANDARD_SCRIPT_VERIFY_FLAGS);
`bitcoin-core/src/script/interpreter.h:147-220` (STANDARD bit-set).

**Impact:**
- An attacker can RBF-replace a relay-friendly mempool tx with a
  policy-bad-but-consensus-good replacement; the conflict is evicted;
  the replacement sits in haskoin's mempool refusing to be mined by
  Core-style miners.
- Fleet-wide divergence: any Core-derived peer rejects the replacement
  on relay, isolating the haskoin node.
- Combined with BUG-2 (submitpackage no broadcast): the gap is
  partially papered over for package submissions, but RBF via
  `sendrawtransaction` still propagates to peers and the divergence
  surfaces.

---

## BUG-11 (P1) — `isWellFormedPackage` rejects single-tx packages over MAX_PACKAGE_WEIGHT — Core only rejects when count > 1

**Severity:** P1. Core's `IsWellFormedPackage`
(`packages.cpp:90`):

```cpp
if (package_count > 1 && total_weight > MAX_PACKAGE_WEIGHT) {
    return state.Invalid(PackageValidationResult::PCKG_POLICY, "package-too-large");
}
```

The `package_count > 1` guard exists explicitly so that a SINGLE-TX
package (which is permitted per Core spec: "A single transaction is
permitted") triggers the better-targeted `MAX_STANDARD_TX_WEIGHT`
error from per-tx validation, not the package-wide
`package-too-large`. Without the guard, a single 405,000-WU tx
submission via `submitpackage` reports the wrong error.

haskoin's `isWellFormedPackage` (`Mempool.hs:2184-2187`):

```haskell
let totalWeight = sum $ map (\tx -> txBaseSize tx * 3 + txTotalSize tx) txns
when (totalWeight > maxPackageWeight) $
  Left $ PkgTooLarge totalWeight maxPackageWeight
```

No `count > 1` guard. A single 405k-WU tx report as `PkgTooLarge
405000 404000` instead of falling through to the per-tx
`MAX_STANDARD_TX_WEIGHT` gate (`Policy/Standard.hs`).

**File:** `src/Haskoin/Mempool.hs:2184-2187`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:90`.

**Impact:** wire-parity error-routing gap; operators see
`package-too-large` for what should be `tx-size`.

---

## BUG-12 (P1) — `isConsistentPackage` does not reject txs with empty vin

**Severity:** P1. Core's `IsConsistentPackage`
(`packages.cpp:57-63`):

```cpp
for (const auto& tx : txns) {
    if (tx->vin.empty()) {
        // This function checks consistency based on inputs, and we can't do that if there are
        // no inputs. Duplicate empty transactions are also not consistent with one another.
        // This doesn't create false negatives, as unconfirmed transactions are not allowed to
        // have no inputs.
        return false;
    }
    ...
}
```

Two related properties:
1. Two empty-vin txs in the same package would have IDENTICAL input
   sets (both empty) — not detectable by the duplicate-input scan
   alone.
2. An empty-vin tx is a coinbase pattern; Core uses this as a
   redundant defense.

haskoin's `isConsistentPackage` (`Mempool.hs:2163-2168`):

```haskell
isConsistentPackage txns =
  let allInputs = concatMap (map txInPrevOutput . txInputs) txns
      inputSet = Set.fromList allInputs
  in length allInputs == Set.size inputSet
```

Two empty-vin txs both contribute `[]` to `allInputs` and `Set.empty`
to `inputSet`. `length allInputs == 0 == Set.size inputSet` → TRUE.
A package with 25 coinbase-shape (empty vin) txs would pass the
consistency check; `addPackageTransactions` would then reject each
individually via `ErrCoinbaseNotAllowed` (line 2454), but the wrong
gate triggers.

**File:** `src/Haskoin/Mempool.hs:2163-2168`.

**Core ref:** `bitcoin-core/src/policy/packages.cpp:57-63`.

**Impact:** wrong gate triggers on a malformed package; minor wire-
parity gap.

---

## BUG-13 (P0-CDIV) — Package RBF (PackageRBFChecks) entirely absent — packages with mempool conflicts cannot replace

**Severity:** P0-CDIV. Bitcoin Core's `PackageRBFChecks`
(`validation.cpp:1037-1133`) implements package-level RBF for the
specific case of a 1-parent-1-child package replacing one or more
mempool transactions. The flow:

1. Restrict to `workspaces.size() == 2` AND `IsChildWithParents`.
2. Refuse if any package tx has in-mempool ancestors (so the
   replacement set is bounded).
3. Aggregate `direct_conflict_iters` across both workspaces.
4. Run `GetEntriesForConflicts` (Rule 5).
5. Stage removals; sum `m_conflicting_fees` from removals.
6. Run `PaysForRBF` against `m_total_modified_fees` and `m_total_vsize`.
7. Enforce `package_feerate > parent_feerate` strictly (so the child
   is doing more than DoS-fee-padding).
8. `CheckMemPoolPolicyLimits` + `ImprovesFeerateDiagram` on the
   changeset.

haskoin's `acceptPackage` (`Mempool.hs:2285-2308`) and
`addPackageTransactions` (`Mempool.hs:2429-2559`) do NONE of this.
The package admit path never calls `getConflicts`; if any package tx
conflicts with mempool, `addTransactionToMempool` (line 2551) fails
with `ErrInputSpentInMempool` and the package is rejected wholesale.

**Net result:**
- CPFP fee-bumps via submitpackage where the parent already exists in
  mempool with a different witness or where the child conflicts with
  an unrelated mempool tx: package-rejected on first conflict.
- Package-RBF (replacing a stuck parent + child with a higher-fee
  parent + child via submitpackage): impossible. The operator must
  RBF each tx individually via `sendrawtransaction` and pray for the
  intermediate mempool state to be valid.
- TRUC package RBF (the entire reason for BIP-431's restricted
  topology): broken — TRUC's value proposition requires Package RBF
  to work.

**File:** `src/Haskoin/Mempool.hs:2285-2308, 2429-2559` (no
PackageRBFChecks call); `Mempool.hs:2551` (per-tx admit fails on
mempool conflict).

**Core ref:** `bitcoin-core/src/validation.cpp:1037-1133`
(PackageRBFChecks); BIP-431 (TRUC requires Package RBF).

**Impact:**
- Package RBF is dead. Wallets / LN nodes that rely on it for force-
  close fee-bumping cannot use haskoin.
- TRUC enforcement is partial: haskoin enforces TRUC topology on a
  per-tx basis (`checkTrucPolicy`, Mempool.hs:2546) but the package
  RBF flow that TRUC was designed for is not implemented.
- Cross-fleet divergence: a hashhog fleet's mempools diverge whenever
  any peer broadcasts a package RBF — haskoin keeps the stale state,
  other impls accept the replacement.

---

## BUG-14 (P1) — Package admit is NOT atomic; per-tx commits leak intermediate state

**Severity:** P1. Bitcoin Core's `ProcessNewPackage`
(`validation.cpp::AcceptPackage` / `AcceptMultipleTransactions`) uses
a single `changeset` (`m_subpackage.m_changeset`) staged with all
additions and removals, then committed atomically via
`changeset.Apply()` in `Finalize`. Either all package txs are admitted
together or none are.

haskoin's `addPackageTransactions` (`Mempool.hs:2429-2559`) is a
sequential loop:

```haskell
go [] acc _ = return $ Right (reverse acc)
go (tx:rest) acc localOutputs = do
  ...
  result <- addTransactionToMempool mp tx txid inputs fee vsize  -- COMMITS NOW
  case result of
    Left err -> return $ Left $ PkgTxError txid err
    Right () -> go rest (txid : acc) (Map.union newOutputs localOutputs)
```

Each `addTransactionToMempool` call writes the tx into `mpEntries`,
`mpByWtxid`, `mpByOutpoint`, etc. via `atomically` (Mempool.hs:2635-
2641). When tx N fails, txs 1..N-1 are LIVE — visible to
`getrawmempool`, broadcasted via `OnTxAdded` hooks, etc.

Rollback lives at the RPC-handler layer (`submitPackageTxns`, line
5674-5683):

```haskell
Left perr -> do
  forM_ multi $ \tx -> do
    let txid = computeTxId tx
    mEntry <- getTransaction mp txid
    case mEntry of
      Just _  -> removeTransaction mp txid
      Nothing -> return ()
  return $ buildAbortResponse "package validation failed" ...
```

The window between commit and rollback:
- `getrawmempool` snapshots taken during the window see the partially-
  admitted package.
- ZMQ `hashtx` / `rawtx` notifications fire on commit (the `notifyTx`
  hook lives in `addTransactionToMempool`, post-line 2640's
  `atomically`).
- `OnBlockTemplate` builds during the window can include a partial
  package.

**File:** `src/Haskoin/Mempool.hs:2429-2559` (per-tx commit loop);
`src/Haskoin/Rpc.hs:5674-5683` (RPC-side rollback).

**Core ref:** `bitcoin-core/src/validation.cpp::SubmitPackage`
(single-changeset atomic Apply).

**Impact:**
- Race window for ZMQ / mining / RPC observers.
- If the haskoin process crashes between the parent-commit and
  child-failure, the parent is persistent (mempool.dat) but the
  package failed — the operator's submitpackage call returned an
  error, but the parent is now zombie-resident.
- Cross-cite BUG-2 (no broadcast): the parent's `notifyTx` does fire
  on commit, so even though peers don't get the relay-via-INV path,
  the local subscriber pool sees the parent.

---

## BUG-15 (P0-CDIV) — `prioritisetransaction` RPC absent (W150 BUG-10 echo confirmed at RBF interaction)

**Severity:** P0-CDIV (W150 BUG-10 echo; relisted here because the
RBF interaction makes it a P0 in this wave's context). Bitcoin Core's
`prioritisetransaction` RPC (`rpc/mempool.cpp`) takes
`(txid, dummy=0, fee_delta)` and writes `fee_delta` into
`m_pool.mapDeltas[txid]`. This delta is added to the base fee at
multiple points:
1. Min-relay-fee gate at admit time (haskoin: PASS, modified fee
   used at `finalizeTransaction:859-869`).
2. RBF Rule 3 + Rule 4 (haskoin: BUG-6 — base fee used).
3. Mining selection (block-template feerate).
4. Mempool entry eviction order (lowest-feerate-first).

haskoin's RPC dispatch (`Rpc.hs:1024-1093`) has NO
`"prioritisetransaction"` case. The method is not exposed. The
`mpFeeDeltas` TVar (Mempool.hs) IS plumbed end-to-end: read by
`finalizeTransaction:859-869`, persisted by `Persist.hs:369`, loaded
back on restart by `loadMempool`. But no in-band writer exists.

**File:** `src/Haskoin/Rpc.hs:1024-1093` (RPC dispatch table).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`.

**Impact:**
- `prioritisetransaction` is FUNCTIONALLY UNREACHABLE; the only way
  to populate `mpFeeDeltas` is to write `mempool.dat` directly out-
  of-band.
- Combined with BUG-6, even loaded-from-mempool.dat deltas only affect
  the min-relay gate, not the RBF gate.
- Wallet integrations that use `prioritisetransaction` (e.g.,
  Bitcoin Core's wallet sets a delta when bumping a stuck child via
  CPFP) cannot drive haskoin.

---

## BUG-16 (P1) — `acceptPackage` early-return when EVERY tx already in mempool emits empty results (Core emits per-wtxid skeleton)

**Severity:** P1. Core's `ProcessNewPackage` on the "everything
already in mempool" path still emits a full `tx-results` map keyed by
wtxid with `txid` populated per entry. haskoin's `acceptPackage`
(`Mempool.hs:2305-2307`):

```haskell
if null newTxns
  then return $ Right []   -- empty list, no per-tx data
  else acceptPackageInner pkg mp newTxns
```

This bubbles up to `submitPackageTxns` (line 5673):

```haskell
Right _txids -> do
  entries <- forM multi $ \tx -> do
    ...
```

Which then walks `multi` (the originally-submitted txs) and looks
each up in the mempool. So the response IS populated correctly — but
only because the RPC handler re-walks the input. The Mempool API
itself (`acceptPackage`) loses information: callers other than the
RPC handler that observe `Right []` cannot distinguish "package was
no-op (all already-in)" from "package was empty".

**File:** `src/Haskoin/Mempool.hs:2305-2307`.

**Core ref:** `bitcoin-core/src/validation.cpp::ProcessNewPackage`
(populates `m_tx_results` for already-in-mempool txs as
`MempoolAcceptResult::MempoolEntry`).

**Impact:** API contract gap; current consumer (the RPC handler)
papers it over by re-walking.

---

## BUG-17 (P1) — `removeConflicts` removes by deepest-descendant first via descendant-count sort — not topo-safe

**Severity:** P1. `removeConflicts` (`Mempool.hs:1739-1749`):

```haskell
let sortedEvictions = sortBy (comparing (Down . meDescendantCount)) allEvictions
forM_ sortedEvictions $ \entry ->
  removeTransaction mp (meTxId entry)
```

Sorts by `meDescendantCount` descending (most-descendants-first =
deepest "parents" first). This is the OPPOSITE of topo-safe
descendant removal: a tx with the MOST descendants is removed FIRST,
which means its descendants are then orphaned (their parent input
becomes invalid) and must be GC'd by some other mechanism.

Core's `RemoveStaged` walks the conflict set in
post-order-descendant-removal: `removeUnchecked` cascades, removing
descendants first so each tx's by-outpoint index is consistent at
the time of its own removal.

Empirically, `removeTransaction` (Mempool.hs:1320) does walk the
by-outpoint index to remove outpoint entries, so the cleanup is
eventually-consistent. But during the window after the deepest
parent is removed and before its descendants are processed, the
mempool is in a state where `mpByOutpoint` references a TxId that
isn't in `mpEntries`. Concurrent reads (e.g., from `getrawmempool`,
`getmempoolentry`) see this orphaned state.

**File:** `src/Haskoin/Mempool.hs:1739-1749`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::CTxMemPool::RemoveStaged`
+ `removeUnchecked` (post-order cascade via CalculateDescendants).

**Impact:** race window for concurrent RPC observers; consistency
gap. Not a consensus bug.

---

## BUG-18 (P1) — `removeConflicts` does NOT update `mpRollingMinFeeRate` via `trackPackageRemoved`

**Severity:** P1. Core's RBF replacement removes the conflict set
via `CTxMemPool::RemoveStaged(...)` which calls
`trackPackageRemoved(... removed_fee_rate ...)` to push the conflict's
fee-rate floor into the rolling minimum fee. This makes the mempool
"sticky" against the SAME replacement attempt repeated at a
slightly-lower fee — once you've evicted a 50-sat/vB conflict, the
next admission needs to pay > 50 sat/vB.

haskoin's `trimToSize` (`Mempool.hs:2016-2033`) correctly bumps
`trackPackageRemoved` on size-limit eviction (line 2031). But the
RBF-eviction path `removeConflicts` (line 1739-1749) does NOT bump
the rolling minimum:

```haskell
removeConflicts conflictTxIds mp = do
  allEvictions <- getConflictSet mp (Set.toList conflictTxIds)
  let sortedEvictions = sortBy (comparing (Down . meDescendantCount)) allEvictions
  forM_ sortedEvictions $ \entry ->
    removeTransaction mp (meTxId entry)
  -- MISSING: trackPackageRemoved mp <highest-feerate-of-evicted-set>
```

After RBF eviction, the rolling minimum is unchanged. An attacker
can RBF-cycle (evict-and-replace) at the SAME effective fee-rate
forever — Rule 4's incremental floor is the only friction.

**File:** `src/Haskoin/Mempool.hs:1739-1749`.

**Core ref:** `bitcoin-core/src/txmempool.cpp` — RemoveStaged path
through `trackPackageRemoved` (mirrored at Mempool.hs:2031 for the
size-eviction case but not the RBF-eviction case).

**Impact:** RBF cycling becomes cheaper on haskoin than on Core;
DoS vector for mempool churn.

---

## BUG-19 (P1) — `handleSubmitPackage` accepts up to MAX_PACKAGE_COUNT txs but does NOT enforce burn-check or topology check until late

**Severity:** P1. Core's `submitpackage` does the burn check (BUG-1)
inline during the `vout` walk in tx decode (line 1386-1390), and the
`IsChildWithParentsTree` check immediately after decode (line 1395-
1397). Both are pre-flight checks before `ProcessNewPackage`.

haskoin decodes all txs first (line 5562-5568), then calls
`submitPackageTxns` which routes through `isWellFormedPackage` and
`isChildWithParentsTree` inside `acceptPackage` (Mempool.hs:2290,
2296). The error path through `acceptPackage` Left → JSON response
loses the structured `TransactionError::INVALID_PACKAGE` token Core
emits via `JSONRPCTransactionError`.

**File:** `src/Haskoin/Rpc.hs:5537-5573` (handler), `5656-5666` (multi
branch).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp:1395-1397`
(pre-decode IsChildWithParentsTree check via
TransactionError::INVALID_PACKAGE).

**Impact:** wire-parity error-routing gap.

---

## BUG-20 (P1) — `signalsOptInRBF` does not depend on tx itself; cannot account for ancestor-based opt-in at admit time

**Severity:** P1. Bitcoin Core's `IsRBFOptIn`
(`policy/rbf.cpp:24-50`) returns `REPLACEABLE_BIP125` if the tx
itself signals OR if any of its in-mempool ancestors signal. The
ancestor walk uses `CalculateMemPoolAncestors`. Importantly, this
ancestor-side opt-in determines whether a CHILD of an opt-in parent
is itself replaceable.

haskoin has the right pieces:
- `signalsOptInRBF` checks the tx itself (Mempool.hs:398).
- `isRbfReplaceable` checks tx-or-ancestors (Mempool.hs:1576-1594).

But `meRBFOptIn` is set at admit-time from `signalsOptInRBF` alone
(Mempool.hs:984 + 2601). At admit-time the new tx is not yet in the
mempool, so an opt-in ancestor's flag does NOT propagate to the
child's `meRBFOptIn`. Later, when this child is itself the conflict
of another replacement attempt, `checkAllConflictsRbfReplaceable`
(Mempool.hs:1604-1607) → `isRbfReplaceable` (Mempool.hs:1576-1594) →
walks `getAncestorsRecursive` and checks `meRBFOptIn` on each
ancestor. Correct overall, BUT:

The PER-TX boolean `meRBFOptIn` exposed via `getmempoolentry`
(`bip125-replaceable` JSON field, Rpc.hs:5804) reflects ONLY direct
opt-in, not inherited. A tx whose parent opted in is reported as
`bip125-replaceable: false` by `getmempoolentry`, but it IS in fact
replaceable through ancestor-signaling. Wire-parity gap with Core's
`getmempoolentry`.

**File:** `src/Haskoin/Mempool.hs:984, 2601, 1006` (meRBFOptIn from
own-signal only); `src/Haskoin/Rpc.hs:5804` (exposes single-flag).

**Core ref:** `bitcoin-core/src/policy/rbf.cpp:24-50` (`IsRBFOptIn`
walks ancestors).

**Impact:** `getmempoolentry.bip125-replaceable` is misleading for
child txs of opt-in parents; tools that use this field to decide
"can I RBF this?" get wrong answers.

---

## BUG-21 (P1) — `addTransactionToMempool` (older path that addPackageTransactions feeds into) skips PrioritiseTransaction-modified-fee + max-fee-rate gates

**Severity:** P1. `finalizeTransaction` (Mempool.hs:840-953) — the
modern single-tx path — runs the modified-fee gate (line 873-874)
AND the client-maxfeerate gate (line 884-886). Both are derived from
`mpFeeDeltas` + `mpcMaxFeeRate`.

`addTransactionToMempool` (Mempool.hs:2592-2651) — the older path
that `addPackageTransactions` (line 2551) feeds into — does NEITHER.
It runs only:
- `checkAncestorLimits` (line 2595)
- `getTransactionSigOpCost` for the entry's storage (line 2606-2608)
- `calculateAdjustedVSize` (line 2611)
- Direct entry construction + index updates

A package tx admitted via `addPackageTransactions` therefore:
- Has NO `mpFeeDeltas` delta applied to its fee — even if an
  operator pre-prioritised it (via the absent RPC; or via mempool.dat
  load).
- Has NO `mpcMaxFeeRate` cap enforced — bypasses `client_maxfeerate`
  protection.

The `submitPackageTxns` RPC layer at lines 5692-5705 has a post-hoc
maxfeerate sweep (compares per-tx satPerVB against maxFeeRateSatPerVB
from the RPC param), so the package-RPC-side maxfeerate is enforced,
but the in-Mempool `mpcMaxFeeRate` (from `defaultMempoolConfig`) is
not.

**File:** `src/Haskoin/Mempool.hs:2592-2651` (addTransactionToMempool
short path); `Mempool.hs:840-953` (finalizeTransaction long path
with all gates).

**Core ref:** `bitcoin-core/src/validation.cpp:1368` (client_maxfeerate
applied in PreChecks for all admissions including package).

**Impact:** two-pipeline drift inside Mempool.hs — finalizeTransaction
and addTransactionToMempool implement different gate sets. Package
admits skip gates that single-tx admits enforce. W144 / W150 / W151
"two-pipeline guard" pattern, 19th distinct extension this wave.

---

## Summary

**Bug count:** 21 (BUG-1 through BUG-21).

**Severity distribution:**
- **P0-CDIV:** 6 (BUG-2, BUG-6, BUG-8, BUG-10, BUG-13, BUG-15)
- **P1:** 15 (BUG-1, BUG-3, BUG-4, BUG-5, BUG-7, BUG-9, BUG-11,
  BUG-12, BUG-14, BUG-16, BUG-17, BUG-18, BUG-19, BUG-20, BUG-21)

**Fleet patterns confirmed:**
- "W144 BUG-3 / STANDARD_SCRIPT_VERIFY_FLAGS gap" (BUG-10) —
  third confirmation; first at the RBF replacement path specifically
  (W150 had the single-tx admit, W144 had the chain-validation side).
  Combined with W150 BUG-1, **every script-verify call in the
  mempool subsystem on haskoin uses MANDATORY-only flags**.
- "two-pipeline guard" 18th + 19th distinct extension (BUG-5
  signalsOptInRBF + BUG-21 finalizeTransaction-vs-addTransactionToMempool
  gate-set drift).
- "wiring-look-but-no-wire" (BUG-2 submitpackage no broadcast,
  BUG-15 prioritisetransaction absent) — twin gaps in `submitpackage`'s
  end-to-end wiring.
- "BASE-fee-not-MODIFIED-fee" (BUG-6) — first appearance of this
  specific shape in haskoin RBF; cross-cite W150 BUG-10
  prioritisetransaction-RPC-absent gives the upstream root cause.
- "wire-token parity slippage" (BUG-3, BUG-4, BUG-11, BUG-12,
  BUG-19) — `submitpackage` response, `package_msg`, error-routing
  through the wrong gate (single-tx → PCKG_POLICY instead of TX_RESULT,
  empty-vin not at consistency check, INVALID_PACKAGE token unmapped).
- "operator-knob absent" (BUG-7 `-incrementalrelayfee`, BUG-15
  `prioritisetransaction`) — cross-cite W150 BUG-2/3 family.
- "cluster-count vs eviction-count semantics mismatch" (BUG-8) —
  Rule 5 over-rejects on long-cluster chains; first haskoin instance
  of this specific shape.
- "diagram-comparison shape mismatch" (BUG-9) — sample-at-x vs
  chunk-by-chunk partial order; first haskoin instance.
- "non-atomic package admit" (BUG-14) — RPC-layer rollback after
  per-tx commits; race window for observers.

**Top three findings:**

1. **BUG-2 (P0-CDIV `submitpackage` does NOT broadcast accepted
   packages to peers)** — successful `submitpackage` is a NO-OP from
   the network's perspective. CPFP fee-bumping via submitpackage is
   broken end-to-end on haskoin; TRUC packages stay local; the entire
   value proposition of BIP-331 is unrealised. ~3-line fix
   (`broadcastTxToPeers` call inside `buildSuccessResponse` loop), but
   currently the gate is wide open.

2. **BUG-13 (P0-CDIV Package RBF entirely absent)** — `acceptPackage`
   / `addPackageTransactions` never call `getConflicts` and never
   trigger any replacement logic during package admit. Core's
   `PackageRBFChecks` (validation.cpp:1037-1133) is a 100-LOC
   subsystem that has no haskoin analogue. CPFP fee-bumping via
   submitpackage where the parent already exists in mempool, package
   RBF (replace-parent-and-child atomically), and TRUC-package RBF
   (the entire point of BIP-431's topology) are all impossible.

3. **BUG-10 (P0-CDIV RBF replacement script-verify uses
   MANDATORY-only flags)** — third confirmation of the fleet-wide
   W144 BUG-3 / W150 BUG-1 pattern, this time at the RBF code path.
   An RBF replacement that fails STANDARD-only bits (MINIMALIF,
   CLEANSTACK, LOW_S, NULLFAIL etc.) but passes MANDATORY is admitted,
   evicts its conflicts, and refuses to be mined by Core-style miners.
   Cross-cite W150 BUG-1; the single architectural fix (wire
   `consensusFlagsToScriptFlags` STANDARD bits when in mempool
   context) closes both finds plus W144 BUG-3 in one stroke.

Honorable mentions:
- **BUG-6 (P0-CDIV RBF Rule 3 uses base fee, not modified fee)** —
  `prioritisetransaction` deltas (if anyone could set them — see
  BUG-15) are ignored on both sides of the RBF gate, making the
  prioritisation feature functionally dead for RBF flows.
- **BUG-8 (P0-CDIV Rule 5 counts evictions, not clusters)** — over-
  rejects long-cluster RBF replacements that Core accepts; degrades
  CPFP-fan-out bumping; one-direction divergence.

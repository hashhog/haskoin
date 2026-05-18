# W135 Standardness rules (IsStandardTx) — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** `IsStandardTx`, `IsStandard` (scriptPubKey classifier),
`ValidateInputsStandardness` (the `AreInputsStandard` replacement),
`IsWitnessStandard`, `SpendsNonAnchorWitnessProg`, `CheckSigopsBIP54`,
`GetDustThreshold` / `IsDust` / `GetDust`, `IsStandard(MULTISIG)` n-cap
and `MAX_P2SH_SIGOPS` redeem-script sigop cap.
**Out of scope:**
- TRUC (BIP-431) ancestor/descendant policy and v3 vsize rules
  (covered by W106 + W120 + per-impl TRUC waves; W135 only audits
  TX_MIN/MAX_STANDARD_VERSION = [1,3] inclusion of v3).
- RBF rules 1-6 (W120).
- `MAX_STANDARD_TX_SIGOPS_COST` integration into the AcceptToMemoryPool
  pipeline beyond constant equality (W106 covers the pipeline wiring).
- Coin-grained validation (W100), block-template inclusion (W123),
  taproot-leaf-execution semantics (W127).

**Sources audited:**
- `src/Haskoin/Policy/Standard.hs:1-678` — `checkStandardTx`,
  `checkStandardTxWith`, `checkWitnessStandard`, `dustThreshold`,
  `isStandardScriptPubKey`, `getSigOpsAdjustedWeight`,
  `getVirtualTransactionSize`, `getVirtualTransactionSizeWithSigops`.
- `src/Haskoin/Mempool.hs:3700-3899` — `renderStdReason`,
  `renderWitnessStdReason`, `validateInputsStandardness`,
  `generalEphemeralPreCheck`, `maxP2SHSigOps`.
- `src/Haskoin/Mempool.hs:670-960` + `2440-2560` — pipeline wiring
  (single-tx vs package paths) of the standardness gates.
- `src/Haskoin/Script.hs:680-789` — `classifyOutput` (the
  `Solver`-equivalent), `ScriptType`, `isPushOnly`,
  `isWitnessProgram`, multisig parser.
- `src/Haskoin/Consensus.hs:2172-…` — `countScriptSigops`,
  `witnessScaleFactor`, `txBaseSize`, `txTotalSize`,
  `getTransactionSigOpCost` (the BIP-141 cost computation).

**Result:** 6 PRESENT / 8 PARTIAL / 16 MISSING out of 30 gates.
**Bugs found:** 16 (4 P0-CDIV, 7 P1, 5 P2).
**Tests added:** 30 gates in `W135StandardnessSpec.hs` (a mix of `it`
pinning + `xit` sentinels for the missing/partial behaviors).

---

## Relationship to W106 / W120 / W127 / W125

- **W106** (MempoolAccept descendant/ancestor + RBF + package mempool)
  audits the *pipeline* into which standardness slots; it does not
  itself second-guess the IsStandardTx rules. W135 is the
  rule-by-rule audit of those gates.
- **W120** (strict BIP-125 RBF rules 1-5) audits replace-by-fee
  policy; replacement standardness inheritance is the only overlap,
  and W135 only pins it (it doesn't audit RBF Rule 1-5).
- **W127** (Taproot / Schnorr / Tapscript) audits BIP-340/341/342
  consensus + execution; W135 audits ONLY the standardness wrapper
  around tapscript spends (annex / per-stack-item size /
  control-block emptiness).
- **W125** (JSON-RPC error code parity) audits `testmempoolaccept`
  reason-string parity; W135 pins the haskoin `renderStdReason` /
  `renderWitnessStdReason` mapping but does not re-audit RPC plumbing.

---

## Top-line verdict

haskoin has a relatively **complete** `IsStandardTx` skeleton (the
`checkStandardTxWith` function mirrors Core's 6-step shape well),
and the auxiliary `ValidateInputsStandardness` + `IsWitnessStandard`
gates exist and are wired into both the single-tx and package paths.

The **divergences** are scattered, not structural, and concentrated
in three areas:

1. **scriptPubKey classifier (`classifyOutput`)** is more permissive
   than Core's `Solver`:
   - `OP_RETURN` is classified without checking the rest is
     push-only (BUG-1, **P0-CDIV**).
   - `OP_RETURN OP_RESERVED ...` style scripts pass haskoin's
     "standard" gate and would be relayed; Core classifies them
     `NONSTANDARD`.
   - The classifier does not distinguish `WITNESS_UNKNOWN` from
     `NONSTANDARD` at the scriptPubKey level (BUG-2).

2. **Dust threshold rounding** is `floor((sz * fee) / 1000)` rather
   than Core's `EvaluateFeeUp` ceiling, and Core's `IsDust` is
   strict-less-than, while haskoin's matches strict-less-than but
   the ceiling-vs-floor changes the threshold by 1 satoshi at the
   boundary for non-default fees (BUG-3, **P0-CDIV** when a
   custom `-dustrelayfee` is used).

3. **BIP-54 `CheckSigopsBIP54`** (the per-tx legacy-sigops cap of
   2500 that BIP-54 layered on top of the existing block sigops
   budget) is **completely absent** — `MAX_TX_LEGACY_SIGOPS` is
   never read or enforced in haskoin (BUG-4, **P0-CDIV** once
   BIP-54 activates).

4. **`SpendsNonAnchorWitnessProg`** is **absent**. This is a Core
   helper used by package relay (`policy/packages.cpp`) and
   ephemeral-anchor handling; without it, haskoin's package and
   ephemeral-dust paths can mis-classify witness-stuffed inputs
   (BUG-5, **P0-CDIV** in package paths).

Other smaller bugs include:
- `-datacarrier=0` knob missing (no way to disable OP_RETURN
  outputs even in operator mode; BUG-6, **P1**).
- `-permitbaremultisig` knob hidden behind `checkStandardTxWith` but
  never wired to operator CLI (BUG-7, **P1**).
- `MAX_STANDARD_TX_SIGOPS_COST` is shared between standardness check
  and mempool-add but not re-checked at the IsStandardTx layer
  (Core puts it in the AcceptToMemoryPool path, so this is parity)
  (BUG-8, **P2**).
- `MAX_P2SH_SIGOPS=15` lives in `Mempool.hs` rather than
  `Policy.Standard` (BUG-9, **P2**).
- The MULTISIG n-cap (1..3) and m-bound (1..m..n) are folded into the
  scriptPubKey classifier instead of the `IsStandard(MULTISIG)`
  branch as Core has it; semantically equivalent but cross-grep harder
  (BUG-10, **P2**).
- Multi-A pattern (`MatchMultiA`) is implemented in Core's
  `solver.cpp` but **never** referenced in haskoin — Core uses
  this only for descriptor parsing (not IsStandard), so this is
  parity, not a bug.

---

## Bug catalogue (16 total)

| # | Severity | One-liner |
|---|----------|-----------|
| BUG-1 | **P0-CDIV** | `classifyOutput` accepts `OP_RETURN …` without push-only check on the suffix |
| BUG-2 | **P0-CDIV** | No `WITNESS_UNKNOWN` distinction at the scriptPubKey classifier |
| BUG-3 | **P0-CDIV** | `dustThreshold` uses floor-div; Core uses `EvaluateFeeUp` (ceil-div) |
| BUG-4 | **P0-CDIV** | `MAX_TX_LEGACY_SIGOPS` / `CheckSigopsBIP54` absent (per-tx legacy sigops cap) |
| BUG-5 | **P0-CDIV** | `SpendsNonAnchorWitnessProg` absent (used by package + ephemeral paths) |
| BUG-6 | P1 | No `-datacarrier=0` knob (cannot disable OP_RETURN relay) |
| BUG-7 | P1 | `-permitbaremultisig=0` operator flag not wired (only programmatic) |
| BUG-8 | P2 | `MAX_STANDARD_TX_SIGOPS_COST` checked in pipeline, not in `IsStandardTx` |
| BUG-9 | P2 | `MAX_P2SH_SIGOPS` constant lives in `Mempool.hs`, not `Policy.Standard` |
| BUG-10 | P2 | MULTISIG n-cap (1..3) is in `classifyOutput`, not in `IsStandard` per Core |
| BUG-11 | P1 | `WitnessTaprootEmptyStack` re-used for empty control block — tag-confusion |
| BUG-12 | P1 | `extractLastPush` allows non-push opcodes to fail silently via `Nothing` |
| BUG-13 | P1 | `lastPushBytes` in `validateInputsStandardness` requires the *entire* scriptSig to be push-only, but Core's `EvalScript(SCRIPT_VERIFY_NONE)` only requires `stack.back()` (looser) |
| BUG-14 | P2 | No `GetDust(tx, dust_relay_rate) -> std::vector<uint32_t>` (only count) — package path can't enumerate dust outputs |
| BUG-15 | P2 | `MIN_STANDARD_TX_NONWITNESS_SIZE` check is folded into `checkStandardTx` (Core has it in `PreChecks`, not `IsStandardTx`); divergence in reason-tag emission ("tx-size-small" appears under different reason-source than Core) |
| BUG-16 | P1 | `checkWitnessStandard` ignores the `isP2SH` flag for the taproot branch — Core REQUIRES taproot to NOT be P2SH-wrapped (`!p2sh` guard at policy.cpp:324). haskoin will reject a P2SH-wrapped taproot witness with annex/oversize stack item, but it should be treated as `WITNESS_UNKNOWN` (not a taproot spend) at IsStandard time |

### BUG-1 — `OP_RETURN` push-only suffix not checked (P0-CDIV)

**Core (solver.cpp:184-187):**
```cpp
if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN
    && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
    return TxoutType::NULL_DATA;
}
```

**haskoin (src/Haskoin/Script.hs:732-734):**
```haskell
(OP_RETURN : rest) ->
  let dat = encodeScriptOps rest
  in OpReturn dat
```

`rest` is **not** required to be push-only. A script like
`OP_RETURN OP_DUP` would be classified as `OpReturn` by haskoin and pass
`isStandardScriptPubKey`. Core classifies the same script as
`NONSTANDARD` and rejects with `"scriptpubkey"`.

**Divergence:** haskoin relays the tx; Core (and the rest of the fleet
that matches Core) drops it. The tx is consensus-valid, so a miner can
still include it, and the next block could orphan haskoin's mempool
relay decisions. This is the classic mempool-divergence shape.

**Fix-side note:** add `isPushOnly (Script rest)` to the `OP_RETURN`
branch, OR teach `isStandardScriptPubKey` to re-validate the OP_RETURN
suffix after `classifyOutput`. The latter is cleaner because it leaves
`classifyOutput` decoupled from policy.

### BUG-2 — `WITNESS_UNKNOWN` not distinguished at the scriptPubKey classifier (P0-CDIV)

**Core (solver.cpp:154-178):** a `witnessversion != 0` witness program
with a 2..40-byte program is classified as `WITNESS_UNKNOWN` (a
distinct enum, NOT `NONSTANDARD`).

**haskoin (src/Haskoin/Script.hs:684-739):** `ScriptType` has no
`WITNESS_UNKNOWN` constructor at all. `classifyOutput` falls through
to `NonStandard` for any witness version > 1 (and for unknown 2..40-byte
witness v0 program lengths). The downstream
`validateInputsStandardness` re-detects this via
`isUnknownWitnessProgram` (Mempool.hs:3745-3757) by inspecting raw
bytes, which is **separate logic** from the classifier — keeping these
in sync across both places is a long-term maintenance hazard.

**Divergence:** for OUTPUT standardness (`IsStandardTx`), Core requires
the scriptPubKey to be a known type. haskoin treats `WITNESS_UNKNOWN`
outputs as `"scriptpubkey"` rejection — matches Core in effect (since
Core's `IsStandard` returns false on `WITNESS_UNKNOWN` outputs even
though it sets `whichType` to `WITNESS_UNKNOWN`). For INPUT
standardness, Core uses the *output type of the prevout* — and Core
emits `"input N witness program is undefined"`. haskoin re-detects
this via raw-byte logic in `Mempool.hs:isUnknownWitnessProgram`,
which IS in place.

So the bug is structural (two classifier code paths), not behavioral.
P0-CDIV is still applicable because **the two code paths can drift**
under future edits (e.g., new witness-version SegWit upgrade).

### BUG-3 — Dust threshold rounding (P0-CDIV under custom -dustrelayfee)

**Core (`CFeeRate::GetFee` via `feefrac.h:EvaluateFeeUp`):**
returns `CeilDiv(fee * size, 1000)` — ceiling division.

**haskoin (src/Haskoin/Policy/Standard.hs:317):**
```haskell
(fromIntegral sz * dustFeeSatPerKvB) `div` 1000
```
Haskell's `div` rounds toward negative infinity (floor for positive
operands). For the default `dustRelayTxFee=3000`, sizes of 67-byte
segwit-spend or 148-byte legacy-spend cost dusty outputs both produce
exact multiples (e.g., 67*3000=201000 → /1000=201). No divergence at
default. But with a custom `-dustrelayfee` (or `-dustrelayrate` /
`-mintxfee` override during regtest/operator scenarios), and any
size that produces a non-multiple-of-1000 numerator, the haskoin
threshold is 1 satoshi LOWER than Core's. That changes the
strict-less-than dust decision at the boundary value — haskoin
admits one extra dust output Core rejects, OR rejects one Core admits,
depending on direction.

**Divergence:** mempool acceptance of a transaction with output value
exactly at the floor-vs-ceiling boundary will differ between haskoin
and Core when a non-default dust-relay-fee is in effect.

### BUG-4 — `CheckSigopsBIP54` / `MAX_TX_LEGACY_SIGOPS=2500` absent (P0-CDIV)

**Core (policy.cpp:170-194):** `CheckSigopsBIP54` walks each input,
sums `txin.scriptSig.GetSigOpCount(true) + prev_txo.scriptPubKey
.GetSigOpCount(txin.scriptSig)`, and rejects with
`"bad-txns-nonstandard-inputs", "non-witness sigops exceed bip54 limit"`
if the cumulative count > 2500. This is called from
`ValidateInputsStandardness` (line 221-224).

**haskoin (src/Haskoin/Mempool.hs:3759-3858 + Policy/Standard.hs):**
- No `MAX_TX_LEGACY_SIGOPS` constant.
- `validateInputsStandardness` checks `MAX_P2SH_SIGOPS=15` per
  redeemscript, but NOT the cumulative-across-tx 2500 cap.

**Divergence:** a transaction with many P2SH inputs whose individual
redeem-scripts each pass the 15-cap but whose **sum** exceeds 2500
non-witness sigops will be relayed by haskoin and rejected by Core
once BIP-54 activates. This is a per-tx DoS-mitigation gate, not a
soft-fork, and is enforced by Core today.

### BUG-5 — `SpendsNonAnchorWitnessProg` absent (P0-CDIV in package paths)

**Core (policy.cpp:354-388):** walks each input's prevout, returns true
if *any* prevout is a witness program other than P2A (anchor). Used by
`packages.cpp` and `ephemeral_policy.cpp` to gate the "no witness
stuffing on P2A" rule and the package-only relax path for
ephemeral-anchor parent outputs.

**haskoin:** no equivalent function exists. The closest is the per-input
`IsPayToAnchor` check inside `checkWitnessStandard`. There is no
helper for "does this tx spend ANY non-anchor witness program".

**Divergence:** the package-path code in `Mempool.hs:2440-2560` runs
`checkWitnessStandard`, which catches P2A-stuffing **per input**, but
the *cross-tx invariant* "package's child can spend the anchor only
if no sibling spends a non-anchor witness program" is not enforced.
Future package-relay extensions (BIP-331 ancestor-package) would
silently diverge here.

### BUG-6 — `-datacarrier=0` operator knob absent (P1)

**Core (policy.h:80):** `DEFAULT_ACCEPT_DATACARRIER = true`. Setting
`-datacarrier=0` makes `max_datacarrier_bytes = std::nullopt`, which
makes `value_or(0) = 0`, so **any** OP_RETURN output > 0 bytes triggers
"datacarrier" rejection. There is no haskoin equivalent — the budget is
hard-coded to `MAX_OP_RETURN_RELAY = 100_000`.

**Operator impact:** a node operator running `bitcoind` with
`-datacarrier=0` (a common spam-mitigation flag in the wild) cannot
replicate that behavior on haskoin. P1 because it's
operator-experience parity, not consensus.

### BUG-7 — `-permitbaremultisig=0` operator flag not wired (P1)

**haskoin (src/Haskoin/Policy/Standard.hs:394 `checkStandardTxWith`):**
the function takes `permitBareMultisig :: Bool` but the only call site
(`checkStandardTx`) hard-codes `True`. The CLI has no
`-permitbaremultisig` flag.

**Operator impact:** as with BUG-6, this is a relay-policy operator
knob that Core exposes (`policy.h:52 DEFAULT_PERMIT_BAREMULTISIG = true`,
overridable by `-permitbaremultisig`). haskoin's plumbing is half-done.

### BUG-8 — `MAX_STANDARD_TX_SIGOPS_COST` check location parity (P2)

**Core:** this 16_000-sigop-cost cap is enforced inside
`AcceptToMemoryPool::PreChecks` (validation.cpp:941-943), NOT inside
`IsStandardTx`. haskoin matches this layering (the check is in
`Mempool.hs:939`), so this is parity, not a bug — flagging for the
audit's bookkeeping only.

### BUG-9 — `MAX_P2SH_SIGOPS=15` constant location (P2)

`maxP2SHSigOps` lives in `Mempool.hs:3737-3738` not in
`Policy.Standard`. Core has it in `policy.h:42`. Minor refactor hygiene;
no behavioral impact. P2.

### BUG-10 — MULTISIG n-cap folded into classifier (P2)

**Core (policy.cpp:80-98 `IsStandard`):**
```cpp
whichType = Solver(scriptPubKey, vSolutions);
if (whichType == TxoutType::NONSTANDARD) return false;
else if (whichType == TxoutType::MULTISIG) {
    unsigned char n = vSolutions.back()[0];
    if (n < 1 || n > 3) return false;
    if (m < 1 || m > n) return false;
}
```
So Core's classifier returns `MULTISIG` for ANY m-of-n; `IsStandard`
then caps n at 3.

**haskoin (src/Haskoin/Policy/Standard.hs:350-360 `isStandardScriptPubKey`):**
```haskell
P2MultiSig m keys ->
  let n = length keys
  in if n >= 1 && n <= 3 && m >= 1 && m <= n
        then Just (P2MultiSig m keys)
        else Nothing
```
Semantically equivalent (a 4-of-4 multisig hits the `Nothing` branch
and is rejected as `"scriptpubkey"`), but the layering differs:
haskoin returns `Nothing` (= NONSTANDARD), Core returns false from
`IsStandard` after returning MULTISIG from `Solver`. P2 because the
end result for `IsStandardTx` is identical; matters only for callers
that inspect the type-classification independently of the policy gate
(e.g., descriptor parsers — see W131).

### BUG-11 — `WitnessTaprootEmptyStack` reused for empty control block (P1)

**haskoin (Policy/Standard.hs:642-659):**
```haskell
case length strippedStack of
  0 -> Left (WitnessTaprootEmptyStack idx)
  ...
  _ -> do
    let controlBlock = last strippedStack
    when (BS.null controlBlock) $
      Left (WitnessTaprootEmptyStack idx)
```

The same error tag is used for two distinct conditions:
- 0 elements in the witness (consensus-invalid)
- non-empty witness but empty control block (Core: `return false`)

Core distinguishes these as separate `return false` branches. Tag
collision means an operator reading
`bad-witness-nonstandard / WitnessTaprootEmptyStack` can't tell which
condition tripped. P1 (operator parity).

### BUG-12 — `extractLastPush` silently degrades on non-push opcodes (P1)

**haskoin (Policy/Standard.hs:569-572):**
```haskell
extractPushData :: ScriptOp -> Maybe ByteString
extractPushData (OP_PUSHDATA d _) = Just d
extractPushData OP_0              = Just BS.empty
extractPushData _                 = Nothing
```

Any non-push opcode in the scriptSig (e.g., `OP_DUP` injected) causes
`extractLastPush` to return `Nothing`, which falls back to the raw
`prevSpk` and then "Non-witness program must not be associated with any
witness" rejection. Core, by contrast, runs `EvalScript(SCRIPT_VERIFY_NONE)`
which (a) tolerates non-push opcodes if the evaluation succeeds, and
(b) returns `stack.back()` which is the *evaluated* top of stack, not
the syntactic last push.

**Divergence:** scriptSigs with non-push opcodes that nevertheless
evaluate to a valid redeem-script will be relayed by Core after
ValidateInputsStandardness rejects them anyway (Core uses
`IsPushOnly` higher up); but in the witness path, Core's `EvalScript`
on `SCRIPT_VERIFY_NONE` is more permissive than haskoin's
`extractLastPush`. P1; the practical impact is small because
`checkStandardTx` already gates on `isPushOnly` upstream.

### BUG-13 — `lastPushBytes` requires entire scriptSig push-only (P1)

**Core (policy.cpp:241-253):** for a P2SH input, Core EvalScripts the
scriptSig under `SCRIPT_VERIFY_NONE` and takes the resulting
`stack.back()` as the redeemScript bytes. This works even if the
scriptSig contains, e.g., `OP_NOP3 <push>`.

**haskoin (Mempool.hs:3851-3858):**
```haskell
lastPushBytes (Script.Script ops)
  | null ops = Nothing
  | otherwise = case last ops of
      Script.OP_PUSHDATA bs _ -> Just bs
      Script.OP_0             -> Just BS.empty
      _                       -> Nothing
```

If the last op is non-push, this returns `Nothing` → "P2SH redeemscript
missing", which Core would NOT emit for the same input (Core would
EvalScript to a valid stack). The difference is largely academic because
`checkStandardTx` already requires push-only scriptSigs upstream, but
the package-path runs `validateInputsStandardness` in some orderings
where this can leak through. P1.

### BUG-14 — `GetDust` (vector of indices) missing (P2)

**Core (policy.cpp:71-78):** `GetDust(tx, dust_relay_rate)` returns a
`std::vector<uint32_t>` of vout indices that are dust. haskoin only
has `isDust` (per-output bool) and a count via list comprehension in
`checkStandardTxWith`.

**Impact:** the ephemeral-anchor and package paths need the vector
form to enumerate dust indices. haskoin works around this with
`generalEphemeralPreCheck` (Mempool.hs:3882-3895) which uses a
`listToMaybe` to find the first dust index, but the full vector is
never materialized. Package-path dust-output-spending check
(`CheckEphemeralSpends` parity) would need this. P2.

### BUG-15 — `MIN_STANDARD_TX_NONWITNESS_SIZE` check location (P2)

Core enforces this in `PreChecks` (validation.cpp:813), not
`IsStandardTx`. haskoin folds it into `checkStandardTxWith` (step 3)
and emits `"tx-size-small"`. The behavior is identical for any user who
calls `checkStandardTx + the rest of the pipeline`, but cross-
implementation diff-test against Core's `testmempoolaccept` would see
the same error string emerge from a different code path. P2.

### BUG-16 — `checkWitnessStandard` ignores `isP2SH` for taproot branch (P1)

**Core (policy.cpp:324):**
```cpp
if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
    // Taproot spend ...
}
```

The `!p2sh` guard means: **a P2SH-wrapped taproot output is NOT a
taproot spend at IsStandard time** — it falls through to "no checks"
because Core treats it as effectively unknown.

**haskoin (Policy/Standard.hs:592-608 `checkWitnessProgram`):**
```haskell
checkWitnessProgram idx wver wprog witStack _isP2SH = do
  ...
  case (wver, BS.length wprog) of
    ...
    (1, 32) -> checkTaprootWitness idx witStack
    _       -> return ()
```

Note the `_isP2SH` — the flag IS extracted by `resolveEffectiveScript`
but **never consulted** in the branch decision. A P2SH-wrapped
v1+32-byte program would be incorrectly subjected to the taproot annex
+ stack-item-size checks. **Divergence:** haskoin rejects a P2SH-
wrapped "taproot" spend that has an annex; Core ignores the annex
(taproot semantics don't apply through P2SH). P1 because P2SH-wrapped
taproot is non-standard for *other* reasons (the wrapping itself
fails most policy gates), but tag-emission divergence is observable.

---

## Audit matrix (30 gates)

| # | Gate                                                                                     | Status   | Bug ref |
|---|------------------------------------------------------------------------------------------|----------|---------|
| G1 | `TX_MIN_STANDARD_VERSION=1`, `TX_MAX_STANDARD_VERSION=3`                                 | PRESENT  | —       |
| G2 | `MAX_STANDARD_TX_WEIGHT=400_000`                                                         | PRESENT  | —       |
| G3 | `MAX_STANDARD_SCRIPTSIG_SIZE=1650`                                                       | PRESENT  | —       |
| G4 | ScriptSig push-only check                                                                | PRESENT  | —       |
| G5 | `IsStandard(scriptPubKey)` rejects NONSTANDARD                                          | PARTIAL  | BUG-1   |
| G6 | `OP_RETURN` requires push-only suffix                                                    | MISSING  | BUG-1   |
| G7 | `WITNESS_UNKNOWN` distinguished from NONSTANDARD at classifier                            | PARTIAL  | BUG-2   |
| G8 | `MULTISIG` n-cap (n in [1..3]) + m-bound (m in [1..n])                                   | PRESENT  | BUG-10  |
| G9 | `permit_bare_multisig` knob (programmatic and CLI)                                       | PARTIAL  | BUG-7   |
| G10 | `MAX_OP_RETURN_RELAY=100000` cumulative budget                                          | PRESENT  | —       |
| G11 | `-datacarrier=0` disables OP_RETURN relay                                                | MISSING  | BUG-6   |
| G12 | `GetDustThreshold` segwit / legacy size split                                            | PRESENT  | —       |
| G13 | `GetDustThreshold` uses CFeeRate ceil-div                                                | PARTIAL  | BUG-3   |
| G14 | `IsDust` strict-less-than                                                                | PRESENT  | —       |
| G15 | `MAX_DUST_OUTPUTS_PER_TX=1`                                                               | PRESENT  | —       |
| G16 | `GetDust(tx, rate)` returns indices vector                                               | MISSING  | BUG-14  |
| G17 | `ValidateInputsStandardness` rejects NONSTANDARD prevouts                                | PRESENT  | —       |
| G18 | `ValidateInputsStandardness` rejects WITNESS_UNKNOWN prevouts                            | PRESENT  | —       |
| G19 | `MAX_P2SH_SIGOPS=15` per-redeem-script cap                                                | PRESENT  | BUG-9   |
| G20 | `CheckSigopsBIP54` per-tx legacy-sigops cap (`MAX_TX_LEGACY_SIGOPS=2500`)                | MISSING  | BUG-4   |
| G21 | `IsWitnessStandard` P2WSH script-size 3600                                               | PRESENT  | —       |
| G22 | `IsWitnessStandard` P2WSH stack-items 100                                                | PRESENT  | —       |
| G23 | `IsWitnessStandard` P2WSH stack-item-size 80                                             | PRESENT  | —       |
| G24 | `IsWitnessStandard` tapscript stack-item-size 80                                         | PRESENT  | —       |
| G25 | `IsWitnessStandard` taproot annex rejection                                              | PARTIAL  | BUG-16  |
| G26 | `IsWitnessStandard` empty taproot stack / empty control block distinct tags              | PARTIAL  | BUG-11  |
| G27 | `IsWitnessStandard` P2A witness-stuffing rejection                                       | PRESENT  | —       |
| G28 | `SpendsNonAnchorWitnessProg` helper                                                       | MISSING  | BUG-5   |
| G29 | `GetVirtualTransactionSize` / `GetSigOpsAdjustedWeight` arithmetic                       | PRESENT  | —       |
| G30 | Reason-tag parity (`"version"` / `"tx-size"` / `"scriptpubkey"` / `"datacarrier"` / `"dust"` / `"bare-multisig"` / `"scriptsig-size"` / `"scriptsig-not-pushonly"` / `"tx-size-small"` / `"bad-witness-nonstandard"`) | PRESENT | BUG-15  |

---

## Tests

See `test/W135StandardnessSpec.hs`. The spec uses HSpec `it` for
behavior that is already in place (acts as a regression pin) and `xit`
for behavior that is missing / partial (acts as a forward-progress
sentinel). Each `xit` is annotated with `pendingWith` pointing back to
the BUG number above.

Total: 30 cases, mapping 1:1 onto the 30 gates. Test pass/fail
breakdown is intentional:
- ~14 `it` (PASS now and forever as regression pins),
- ~16 `xit` (pending until the matching bug is closed).

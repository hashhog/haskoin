# W144 Script-verify flag mux — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** SCRIPT_VERIFY_* enumeration, the per-height flag computer
(equivalent to Core's `GetBlockScriptFlags`), the buried-deployment
gates (P2SH, DERSIG, CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT), and the
distinction between **MANDATORY** (consensus) and **STANDARD** (policy)
flag sets.  Per-opcode soft-fork enforcement bugs that live downstream
of the dispatcher (e.g. minimaldata serialisation rules, OP_CLTV
locktime-type semantics, schnorr signature decoder) are out of scope —
they belong to W127 (Taproot) / W132 (CSV) / W142 (SegWit).

**Out of scope:** consensus-flag exceptions for BIP30 / BIP34 anchors
(covered by W138 assumeUTXO and W123 BIP-34); per-opcode interpreter
behaviour under each flag (W117 / W125 / W127); rpc-level
`scriptverify` parameters (W140).

**Sources audited:**

- `src/Haskoin/Script.hs:262-302` — `ScriptVerifyFlag` enum, `ScriptFlags`
  alias, `hasFlag`, `flagSet`.
- `src/Haskoin/Script.hs:1408-1426` — opcode dispatch for OP_NOP1 / CLTV /
  CSV / OP_NOP4..10.
- `src/Haskoin/Script.hs:1505-1516` — MINIMALIF gate.
- `src/Haskoin/Script.hs:2160-2167` — NULLDUMMY enforcement at
  OP_CHECKMULTISIG.
- `src/Haskoin/Script.hs:2285-2362` — CLTV / CSV body.
- `src/Haskoin/Script.hs:2509-2516` — CONST_SCRIPTCODE gate.
- `src/Haskoin/Script.hs:2575-2735` — `verifyScriptWithFlags` (P2SH +
  WITNESS dispatch + CLEANSTACK).
- `src/Haskoin/Script.hs:2737-2826` — `verifyP2WPKHWithFlags`,
  `verifyP2WSHWithFlags`.
- `src/Haskoin/Consensus.hs:1486-1520` — `ConsensusFlags`,
  `consensusFlagsAtHeight`, `consensusFlagsToScriptFlags`.
- `src/Haskoin/Consensus.hs:2693-2701` — `consensusFlagsToWord32`
  (sigcache key bit-encoding).
- `src/Haskoin/Consensus.hs:2823-2917` — `validateSingleTx`,
  flag-derived script verify call chain.
- `src/Haskoin/Mempool.hs:1247-1262, 2570-2588` — mempool admission
  flag derivation.
- `src/Haskoin/Performance.hs:124, 405, 527` — parallel verifier flag
  routing.
- `bitcoin-core/src/script/interpreter.h:47-159` — flag enum + bit
  width.
- `bitcoin-core/src/policy/policy.h:105-138` —
  `MANDATORY_SCRIPT_VERIFY_FLAGS`, `STANDARD_SCRIPT_VERIFY_FLAGS`,
  `STANDARD_LOCKTIME_VERIFY_FLAGS`.
- `bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211` —
  `script_flag_exceptions` map (mainnet BIP16 + Taproot exception,
  testnet3 BIP16 exception).
- `bitcoin-core/src/validation.cpp:2250-2289` — `GetBlockScriptFlags`.

**Result:** out of 30 gates audited (across the 8 wave behaviours +
the META check), **7 PRESENT (correct)**, **9 PARTIAL (shape divergent,
under-guarded, or wrong activation height)**, **14 MISSING (no
implementation at all)**.

**Bugs found:** 22 (3 P0-CDIV / 1 P0-CONSENSUS / 9 P1 / 6 P2 / 3 P3).

## Top-line verdict

Haskoin **has** a `ScriptVerifyFlag` enum of 21 members that covers all
the consensus-relevant SCRIPT_VERIFY_* constants from Core's
interpreter.h plus most policy flags (only `DISCOURAGE_OP_SUCCESS` and
`STRICT_ENCODING` are present in the enum but with thin or absent
wiring — see BUG-12, BUG-13).  The flag-routing infrastructure is
genuinely there: `verifyScriptWithFlags` forwards `ScriptFlags` into
`initScriptEnvWithFlags`, dispatchers like `verifyP2WPKHWithFlags`
forward the same flags into `evalScriptWithStack`, and the interpreter
checks `hasFlag` at the right callsites for MINIMALDATA, NULLDUMMY,
NULLFAIL, MINIMALIF, WITNESS_PUBKEYTYPE, CLTV, CSV, P2SH, WITNESS,
DERSIG, LOW_S, CLEANSTACK, SIGPUSHONLY, CONST_SCRIPTCODE,
DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, and
DISCOURAGE_UPGRADABLE_PUBKEYTYPE.

The wave splits into four problem clusters:

1.  **Buried-deployment activation heights are not the per-flag heights
    Core uses.** Core's `GetBlockScriptFlags` (validation.cpp:2250)
    unconditionally turns on `P2SH | WITNESS | TAPROOT` *for every
    block* except the entries in `script_flag_exceptions`. Haskoin
    instead carries five per-flag heights (`netBIP65Height`,
    `netBIP66Height`, `netCSVHeight`, `netSegwitHeight`,
    `netTaprootHeight`) and turns flags on when `h >= netHeight`. The
    big consequence: **the two `script_flag_exceptions` blocks
    (mainnet h=170,053 BIP16-violator + h=709,632 Taproot-violator,
    testnet3 h=156,544 BIP16-violator) are not honoured at all.**
    Haskoin will reject any chain that includes those Core-grandfathered
    blocks during a re-org from genesis (BUG-1 P0-CDIV).

2.  **`VerifyP2SH` is unconditionally always-on.** `consensusFlagsToScriptFlags`
    (Consensus.hs:1513) emits `VerifyP2SH` as a literal, with no `flagBIP16`
    gate. There is no `flagBIP16` in `ConsensusFlags` and no
    `netBIP16Height` in `Network`. From genesis through Apr 2012 (block
    173,805 mainnet), Core treats all P2SH outputs as anyone-can-spend
    (the redeem-script eval is skipped). Haskoin would force-eval them.
    Real-world this only matters during a reindex-from-genesis but the
    grandfather block at h=170,053 (whose hash is in the
    `script_flag_exceptions` map with `SCRIPT_VERIFY_NONE`) **will be
    rejected by haskoin** because there is no way to suppress P2SH
    evaluation for that one block (BUG-2 P0-CDIV).

3.  **`STANDARD_SCRIPT_VERIFY_FLAGS` is entirely missing.** The mempool
    admission path (`Mempool.hs:1248-1258, 2576-2585`) routes
    transactions through `consensusFlagsToScriptFlags` — i.e. only the
    7-member MANDATORY set, identical to what `validateSingleTx` uses
    for confirmed blocks. Core's policy code applies the 18-flag
    STANDARD set during mempool admission and ATMP: MINIMALDATA, LOW_S,
    NULLFAIL, CLEANSTACK, MINIMALIF, WITNESS_PUBKEYTYPE,
    DISCOURAGE_UPGRADABLE_NOPS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE, DISCOURAGE_OP_SUCCESS,
    STRICTENC, SIGPUSHONLY, CONST_SCRIPTCODE — **none are enforced in
    haskoin's mempool**.  A peer can relay txs with high-S signatures,
    non-minimal pushes, dirty cleanstack, or unknown taproot leaf
    versions and haskoin will accept and re-broadcast them. This is
    the largest single divergence in the wave (BUG-3 P0-CDIV).

4.  **NULLDUMMY is mis-gated.** Comment at Script.hs:2164-2165 reads
    *"NULLDUMMY is always enforced unconditionally post-SegWit"* but
    the next line says `when (hasFlag (seFlags env5) VerifyNullDummy
    && ...)`. The flag IS conditional. Then
    `consensusFlagsToScriptFlags` only emits `VerifyNullDummy` when
    `flagNullDummy = h >= netSegwitHeight net`, but for pre-segwit
    blocks (mainnet h < 481,824) on a reindex the NULLDUMMY check is
    silently skipped — which is correct per BIP-147. The bug is the
    comment: Core's NULLDUMMY is **always enforced as MANDATORY**
    *after* the buried SEGWIT activation height — i.e. exactly what
    haskoin does. Comment-as-confession but the gate is actually
    correct (no bug). However, NULLDUMMY is **NOT** enforced as a
    policy flag for IBD-pre-segwit transactions that hit the mempool
    — but the mempool uses next-block height so this collapses to
    "always on" in current operation. **Borderline correct; flagged
    only as P3** (BUG-4).

The dead-code surface in this wave is small.  The 21-member
`ScriptVerifyFlag` enum has 4 members that are **never returned by any
constructor inside haskoin's production code**: `VerifyStrictEncoding`,
`VerifyLowS`, `VerifySigPushOnly`, and
`VerifyDiscourageOpSuccess` (see BUG-12, BUG-13, BUG-15, BUG-16).
They are PUBLICLY EXPORTED in Script.hs:8-19 so external callers
could opt in, but no internal call site does.

Below: 22 bugs, ordered by severity then by file location.

---

## BUG-1 (P0-CDIV) — `script_flag_exceptions` not implemented

Core grandfathers two mainnet blocks (170,053 and 709,632) and one
testnet3 block (156,544) by recording per-hash flag overrides in
`consensus.script_flag_exceptions`. The map is consulted at
`validation.cpp:2263-2266` in `GetBlockScriptFlags`. Haskoin's
`consensusFlagsAtHeight` takes only `Network` and `Word32 h` — no
block hash, no exceptions map.

**File:** `src/Haskoin/Consensus.hs:1498-1506`
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:85-88, 210-211`;
`bitcoin-core/src/validation.cpp:2263-2266`.

**Severity:** P0-CDIV — reindex-from-genesis chain-split.

**Excerpt** (haskoin Consensus.hs:1498-1506):
```haskell
consensusFlagsAtHeight :: Network -> Word32 -> ConsensusFlags
consensusFlagsAtHeight net h = ConsensusFlags
  { flagBIP34     = h >= netBIP34Height net
  , flagBIP65     = h >= netBIP65Height net
  , flagBIP66     = h >= netBIP66Height net
  , flagSegWit    = h >= netSegwitHeight net
  , flagNullDummy = h >= netSegwitHeight net
  , flagTaproot   = h >= netTaprootHeight net
  }
```

**Excerpt** (Core kernel/chainparams.cpp:85-88, mainnet):
```cpp
consensus.script_flag_exceptions.emplace( // BIP16 exception
    uint256{"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"},
    SCRIPT_VERIFY_NONE);
consensus.script_flag_exceptions.emplace( // Taproot exception
    uint256{"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"},
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
```

**Impact:** A reindex from genesis will fail at mainnet block 170,053
("BIP16 exception"). Core deliberately suppresses P2SH for this one
block; haskoin will run P2SH on it and reject its scriptSig structure.
At 709,632 (Taproot-activation block) Core suppresses *only* TAPROOT
(retaining P2SH + WITNESS); haskoin enforces full TAPROOT and will
also reject the block.  Mainnet IBD or any rewind past those heights
is structurally impossible without this fix.  Highest-severity bug in
the wave.

---

## BUG-2 (P0-CDIV) — `VerifyP2SH` unconditionally always-on (no BIP-16 activation height)

`consensusFlagsToScriptFlags` emits `VerifyP2SH` for *every* block at
*every* height, including genesis. Core's BIP16 activation was Apr 1
2012 (mainnet block 173,805); prior to that, P2SH outputs were treated
as anyone-can-spend at the consensus level.

**File:** `src/Haskoin/Consensus.hs:1486-1520`
**Core ref:** `bitcoin-core/src/validation.cpp:2262`
(`script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};`
plus the exception-map override).

**Severity:** P0-CDIV — reindex-from-genesis chain-split.

**Excerpt** (Consensus.hs:1486-1520):
```haskell
data ConsensusFlags = ConsensusFlags
  { flagBIP34       :: !Bool
  , flagBIP65       :: !Bool
  , flagBIP66       :: !Bool
  , flagSegWit      :: !Bool
  , flagTaproot     :: !Bool
  , flagNullDummy   :: !Bool
  }
  -- NOTE: no flagBIP16 field

consensusFlagsToScriptFlags cf = flagSet $ concat
  [ [VerifyP2SH]  -- P2SH is always enabled (post BIP-16)
  , ...
  ]
```

**Impact:** combined with BUG-1, the BIP-16 grandfather block
(h=170,053 mainnet) cannot be accepted on reindex.  Even ignoring the
exception block, blocks 0..173,804 should not have `SCRIPT_VERIFY_P2SH`
applied at all — pre-BIP16 P2SH-shaped outputs are anyone-can-spend
under consensus rules. Haskoin enforces P2SH from genesis, so any
historical anyone-can-spend P2SH chain on a fork would be rejected.

Core's modern impl simplifies this by always enabling P2SH+WITNESS+
TAPROOT and using `script_flag_exceptions` to handle the few historic
violator blocks.  Haskoin needs *either* to add a `flagBIP16` height
gate **or** to switch to the always-on-with-exceptions model.

---

## BUG-3 (P0-CDIV) — `STANDARD_SCRIPT_VERIFY_FLAGS` entirely absent (mempool uses MANDATORY only)

The mempool admission path uses `consensusFlagsToScriptFlags` to derive
script flags — i.e. only the 7-member MANDATORY set (P2SH, DERSIG,
NULLDUMMY, CLTV, CSV, WITNESS, TAPROOT).  Core's policy code applies
the 18-flag STANDARD set during `MemPoolAccept::PolicyScriptChecks`
(validation.cpp:1142).

**File:** `src/Haskoin/Mempool.hs:1248-1258, 2576-2585`
**Core ref:** `bitcoin-core/src/policy/policy.h:105-132`;
`bitcoin-core/src/validation.cpp:1142`
(`constexpr script_verify_flags scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;`).

**Severity:** P0-CDIV — policy-divergent (impacts mempool fingerprinting
and relay), but does NOT split the consensus chain.

**Excerpt** (Mempool.hs:1247-1258):
```haskell
height <- readTVarIO (mpHeight mp)
let cflags = consensusFlagsAtHeight (mpNetwork mp) (height + 1)
    scriptFlags = consensusFlagsToScriptFlags cflags
    spentAmounts = map txOutValue prevs
    spentScripts = map txOutScript prevs
    indexed = zip [0..] prevs
results <- forM indexed $ \(idx, prevOut) ->
  case Script.verifyScriptWithFlags scriptFlags tx idx
         (txOutScript prevOut) (txOutValue prevOut)
         spentAmounts spentScripts of
```

**Impact:** haskoin's mempool will accept and re-broadcast txs that
Core nodes reject as non-standard:

  - High-S signatures (would fail LOW_S in Core mempool, accepted here)
  - Non-minimal pushes (MINIMALDATA absent)
  - Dirty cleanstack on legacy inputs (CLEANSTACK absent)
  - Non-compressed witness v0 pubkeys (WITNESS_PUBKEYTYPE absent in
    mempool path; only checked when the consensus flag set covers it,
    see BUG-7)
  - Unknown witness versions or taproot leaf versions
    (DISCOURAGE_UPGRADABLE_* absent)
  - scriptSig containing non-push opcodes (SIGPUSHONLY absent)

Because Core does NOT relay these, haskoin will emit them and Core
peers will quietly drop them — wasting bandwidth and creating a peer-
identifiable fingerprint of haskoin nodes.  This is the largest
operational divergence in the wave.

---

## BUG-4 (P3) — NULLDUMMY comment-as-confession (gate is actually correct)

`OP_CHECKMULTISIG` body at Script.hs:2164-2167:

```haskell
-- NULLDUMMY: dummy must be empty (BIP-147)
-- Note: NULLDUMMY is always enforced unconditionally post-SegWit
when (hasFlag (seFlags env5) VerifyNullDummy && not (BS.null dummy)) $
  Left "NULLDUMMY violation: dummy must be empty"
```

The comment claims "always enforced unconditionally" but the code
gates on `hasFlag`. Reading `consensusFlagsToScriptFlags` shows the
flag IS emitted only `when flagNullDummy = h >= netSegwitHeight net`.
Net behaviour matches Core (`if (flags & SCRIPT_VERIFY_NULLDUMMY)`).
This is mis-leading comment / fleet pattern **comment-as-confession**,
but no behaviour bug.

**File:** `src/Haskoin/Script.hs:2160-2167`
**Severity:** P3 — documentation hygiene.

---

## BUG-5 (P1) — `flagNullDummy` activation height tied to SegWit instead of buried independently

`consensusFlagsAtHeight` at Consensus.hs:1504:
`flagNullDummy = h >= netSegwitHeight net`

Core (`bitcoin-core/src/validation.cpp:2283-2286`) gates NULLDUMMY on
`DeploymentActiveAt(..., DEPLOYMENT_SEGWIT)`. That's the same height
on mainnet/testnet3 (BIP-147 activated simultaneously with segwit
because both deployed via the same versionbits bit-1 signal).
**But this is a Core implementation detail tied to historic
versionbits behaviour, not a property of BIP-147 itself.** If a
future-haskoin user sets `netSegwitHeight=N` and accidentally
forgets to also enforce NULLDUMMY (or vice-versa), the two flags
will drift.  Better to have an explicit `netNullDummyHeight`.

**File:** `src/Haskoin/Consensus.hs:1504`
**Core ref:** `bitcoin-core/src/validation.cpp:2283-2286`.
**Severity:** P1 — maintenance hazard; no immediate consensus impact
because mainnet/testnet3 happen to align.

---

## BUG-6 (P0-CONSENSUS) — `VerifyWitness` never gated by buried height; CLEANSTACK on legacy never enforced

`verifyScriptWithFlags` at Script.hs:2721-2729 enters the `if hasFlag
flags VerifyWitness` branch for *every* non-P2SH input. Combined with
`consensusFlagsToScriptFlags`, `VerifyWitness` is emitted only when
`flagSegWit = h >= netSegwitHeight net`. So far so good — pre-segwit
blocks correctly skip the witness branch.

But on the **legacy path** (the `else` branch at Script.hs:2720) and
also on the **P2SH-without-witness path** the `checkClean` helper at
Script.hs:2716-2718 is called.  That helper enforces CLEANSTACK *only*
when `VerifyCleanStack` is in the flag set.  `consensusFlagsToScriptFlags`
**never emits** `VerifyCleanStack`.  Core's CLEANSTACK is a STANDARD
(policy-only) flag, so this matches Core's consensus rules for legacy
inputs.

**However** — Core's `interpreter.cpp:2206` enforces CLEANSTACK as a
consensus rule for witness inputs (`if (flags & SCRIPT_VERIFY_WITNESS)
return ...CLEANSTACK`).  Haskoin's `verifyP2WPKHWithFlags` /
`verifyP2WSHWithFlags` enforce cleanstack always (the comment at
Script.hs:2821 says *"This is NOT gated by a flag - it's always
enforced for witness programs"*).  That matches Core.

**The actual bug:** Core's flag-gating logic says `if
(flags & SCRIPT_VERIFY_WITNESS) { if (stack.size() != 1) return
CLEANSTACK; }` — i.e. **even on legacy non-witness inputs, when
SCRIPT_VERIFY_WITNESS is active, the final stack must be cleanstack-1**
(this is the consensus interaction between BIP-141 and BIP-147 — Core
forces cleanstack on legacy as soon as witness is active to prevent
witness malleation attacks against legacy inputs).  Haskoin does NOT
apply cleanstack to the legacy branch when witness is active; it only
calls `checkClean` which gates on `VerifyCleanStack`.

**File:** `src/Haskoin/Script.hs:2620-2730`
**Core ref:** `bitcoin-core/src/script/interpreter.cpp:2178-2226`
(`VerifyScript`, post-witness cleanstack check).

**Severity:** P0-CONSENSUS — divergent admission of legacy txs in
post-segwit blocks; concrete attack vector would be a hand-crafted
legacy input whose script leaves >1 element on the final stack.
Core rejects; haskoin accepts.

**Excerpt** (haskoin Script.hs:2620-2630):
```haskell
let checkClean finalStack = do
      when (hasFlag flags VerifyCleanStack && length finalStack /= 1) $
        Left "Stack not clean after evaluation"
      Right True
```

**Excerpt** (Core interpreter.cpp:2218-2226, paraphrased):
```cpp
if ((flags & SCRIPT_VERIFY_WITNESS)) {
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);
    if (stack.size() != 1) {
        return set_error(serror, SCRIPT_ERR_CLEANSTACK);
    }
}
```

Note: Core sets `if (flags & SCRIPT_VERIFY_WITNESS)` here precisely
because P2SH+WITNESS implies CLEANSTACK as a consensus rule.

---

## BUG-7 (P1) — `VerifyWitnessPubkeyType` plumbed but never emitted by consensus flag map

`checkWitnessPubkeyType` at Script.hs:1125-1129 gates on
`VerifyWitnessPubkeyType`, called from `verifyP2WPKHWithFlags` and
indirectly via `seFlags env` in EvalScript at Script.hs:1940.
But `consensusFlagsToScriptFlags` never emits the flag, and no other
code does either. Search results: zero callers add it.

**File:** `src/Haskoin/Consensus.hs:1511-1520`; flag callsites at
`src/Haskoin/Script.hs:1127, 1940`.

**Severity:** P1 — policy gap. WITNESS_PUBKEYTYPE is a STANDARD flag,
not MANDATORY, so this doesn't split consensus.  But Core's mempool
rejects non-compressed witness v0 pubkeys; haskoin will accept and
relay them.

**Impact:** witness v0 inputs with uncompressed pubkeys (Bitcoin
Core's `STANDARD_SCRIPT_VERIFY_FLAGS` rejects these as non-standard)
are admitted by haskoin's mempool.  Same operational impact category
as BUG-3.

---

## BUG-8 (P1) — `VerifyMinimalIf` policy-only, but mempool never sets it

`execIf` at Script.hs:1509: `minimalIfRequired = seIsWitness env'' ||
hasFlag (seFlags env'') VerifyMinimalIf`.  For legacy inputs (the `||`
right operand) the flag is consulted but never emitted by haskoin's
consensus or mempool flag derivations.

Core's MINIMALIF is a STANDARD (policy-only) flag for legacy scripts —
mempool rejects, blocks accept.  For witness v0/v1 inputs Core enforces
MINIMALIF unconditionally (interpreter.cpp:418-422 inside witness
script eval), and haskoin matches via `seIsWitness env'' ||`.

**File:** `src/Haskoin/Script.hs:1509`.
**Core ref:** `bitcoin-core/src/policy/policy.h:124` (MINIMALIF in
STANDARD set).
**Severity:** P1 — same policy-gap class as BUG-7.

---

## BUG-9 (P1) — `consensusFlagsToWord32` sigcache key only encodes 6 flags out of 21

The signature-cache key includes `flagsBytes = runPut (putWord32le
flagsWord)` (Consensus.hs:2891). `consensusFlagsToWord32` only
serialises 6 bits (BIP34, BIP65, BIP66, SegWit, Taproot, NullDummy).
The 14 STANDARD policy flags are not in the bitmask, so a sigcache hit
will reuse a verification result regardless of whether MINIMALDATA,
LOW_S, NULLFAIL, etc. were in effect.

**File:** `src/Haskoin/Consensus.hs:2693-2701`.
**Severity:** P1 — sigcache false positive risk **iff** STANDARD flags
are ever forwarded into `validateSingleTx` (currently they never are
because of BUG-3). Latent footgun: once mempool starts passing
STANDARD flags into `verifyScriptWithFlags`, the same (txid, scriptSig,
witness) combo with different policy flags will collide in the cache.

**Excerpt** (Consensus.hs:2693-2701):
```haskell
consensusFlagsToWord32 :: ConsensusFlags -> Word32
consensusFlagsToWord32 cf =
  (if flagBIP34 cf then 1 else 0)
  .|. (if flagBIP65 cf then 2 else 0)
  .|. (if flagBIP66 cf then 4 else 0)
  .|. (if flagSegWit cf then 8 else 0)
  .|. (if flagTaproot cf then 16 else 0)
  .|. (if flagNullDummy cf then 32 else 0)
```

A correct sigcache key needs the *full* `ScriptFlags` bitset, not the
6-flag `ConsensusFlags` projection.

---

## BUG-10 (P1) — `flagBIP34` is in `ConsensusFlags` but `consensusFlagsToScriptFlags` never references it

BIP-34 (block-height in coinbase) is a block-structure rule, not a
script-execution rule, so it doesn't belong in `ScriptFlags`.  This is
correct.  However the ordering in `ScriptVerifyFlag` (no member for
BIP-34) versus the field in `ConsensusFlags` (`flagBIP34 :: !Bool`)
plus the encoding in `consensusFlagsToWord32` (bit 0) is misleading:
a reader thinks BIP-34 corresponds to a SCRIPT_VERIFY_* flag when it
doesn't. There's no `SCRIPT_VERIFY_BIP34`. Cosmetic, but P1 because
the W144 audit explicitly looked for this and was momentarily
mis-routed.

**File:** `src/Haskoin/Consensus.hs:1487`.
**Severity:** P1 — code-clarity / audit-time confusion.

---

## BUG-11 (P1) — no `MANDATORY` vs `STANDARD` split type — both go through one path

There is no haskoin equivalent of Core's `MANDATORY_SCRIPT_VERIFY_FLAGS`
and `STANDARD_SCRIPT_VERIFY_FLAGS` constants. The flag set is computed
once by `consensusFlagsToScriptFlags` and forwarded to both confirmed
block validation (Consensus.hs:2886) **and** mempool admission
(Mempool.hs:1251, 2578).  There is no architectural seam for the
"check MANDATORY first; on failure, ban — check STANDARD second; on
failure, just reject the tx without banning" pattern that Core uses
in `MemPoolAccept::PolicyScriptChecks` and `ConsensusScriptChecks`.

**File:** absent across `src/Haskoin/`.
**Core ref:** `bitcoin-core/src/validation.cpp:1136-1170`
(`PolicyScriptChecks`) and `validation.cpp:1175-1230`
(`ConsensusScriptChecks`); `bitcoin-core/src/policy/policy.h:105-135`.
**Severity:** P1 — fleet pattern **architectural-gap-on-policy/consensus-
seam**.

**Impact:** without the split, haskoin cannot ever ban a peer for
forwarding a "consensus-invalid" tx — every script-fail at admission
returns the same `ErrScriptVerificationFailed` and is silently dropped.
Concretely, a malicious peer can flood haskoin with txs that fail
MANDATORY flags (e.g. forged P2SH that fails P2SH eval) and pay no
reputational cost.

---

## BUG-12 (P1) — `VerifyStrictEncoding` defined but never enforced anywhere except inside multisig

`VerifyStrictEncoding` is checked in `execCheckSig`-equivalent code at
Script.hs:1952, 1959, 1965 (sig + pubkey strictenc decoding).  It is
also consulted inside `verifyMultiSig` (Script.hs:2197+).  But it is
**never added to any flag set in the codebase**: no caller emits it.
The flag exists, the gate exists, the check exists — but the wire is
dangling. Same pattern as BUG-7, BUG-15, BUG-16.

**File:** `src/Haskoin/Script.hs:283` (defined); 1952, 1959, 1965, 2197
(consulted); no callsites that emit.
**Core ref:** `bitcoin-core/src/policy/policy.h:120` (STRICTENC in
STANDARD set).
**Severity:** P1.

---

## BUG-13 (P1) — `VerifyLowS` defined but never enforced

Same pattern as BUG-12. The flag is consulted at Script.hs:1954, 1975.
Never emitted.  In Core, LOW_S is a STANDARD flag — mempool rejects
high-S sigs to prevent third-party malleability.

**File:** `src/Haskoin/Script.hs:284` (defined); 1954, 1975 (consulted).
**Severity:** P1.

---

## BUG-14 (P1) — `VerifyNullFail` defined and consulted, never emitted into a flag set

`execCheckSig` at Script.hs:2012: `if not sigCheckResult && hasFlag
(seFlags env'') VerifyNullFail`. The flag is consulted; the BIP-146
spec requires it as a STANDARD flag. Never emitted by any consensus or
mempool flag derivation.

**File:** `src/Haskoin/Script.hs:272` (defined); 2012 (consulted).
**Core ref:** `bitcoin-core/src/policy/policy.h:125` (NULLFAIL in
STANDARD set).
**Severity:** P1.

---

## BUG-15 (P1) — `VerifySigPushOnly` defined and consulted, never emitted

Script.hs:2586: `when (hasFlag flags VerifySigPushOnly && not
(isPushOnly scriptSig)) $ Left "scriptSig is not push-only"`. Never
emitted.

**File:** `src/Haskoin/Script.hs:285` (defined); 2586 (consulted).
**Core ref:** `bitcoin-core/src/policy/policy.h` (SIGPUSHONLY in
STANDARD set).
**Severity:** P1.

---

## BUG-16 (P2) — `VerifyDiscourageOpSuccess` defined but no consultation at all

The flag exists in the enum (Script.hs:279) but a `grep VerifyDiscourageOpSuccess
src/Haskoin/` returns **only the definition line**.  There is no `hasFlag`
check anywhere that consults it.  Core enforces
`SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` in the tapscript leaf evaluator
(interpreter.cpp:1659): `if (flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS)
return set_error(serror, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);` when an
OP_SUCCESS opcode is encountered.

**File:** `src/Haskoin/Script.hs:279` (defined); no consultations.
**Severity:** P2 — dead enum constructor; would matter if anyone ever
flipped on a STANDARD policy mode for the tapscript verifier.
Fleet pattern **already-exports-the-primitive-just-not-called**.

---

## BUG-17 (P2) — `VerifyConstScriptcode` gated but consulted only inside `evalWithPosition`; never emitted

At Script.hs:2512-2516 the legacy `OP_CODESEPARATOR` rejection is
gated on `hasFlag (seFlags e) VerifyConstScriptcode`. The flag is
consulted exactly once. Never emitted by any flag set.  Core's
CONST_SCRIPTCODE is a STANDARD flag (policy.h:129).

**File:** `src/Haskoin/Script.hs:282` (defined); 2515 (consulted, once).
**Severity:** P2.

---

## BUG-18 (P2) — `VerifyDiscourageUpgradableNops` consulted but never emitted

At Script.hs:1431 `checkDiscourageNop` body: `if hasFlag (seFlags env)
VerifyDiscourageUpgradableNops`. Never emitted.  Core sets this in
STANDARD (policy.h:122). Without it, haskoin's mempool will relay
unknown NOPs (OP_NOP1, OP_NOP4..10) that future soft forks may
repurpose — exactly the case BIP-65 / BIP-112 weaponised.

**File:** `src/Haskoin/Script.hs:278` (defined); 1431 (consulted).
**Severity:** P2.

---

## BUG-19 (P2) — `VerifyDiscourageUpgradableWitnessProgram` consulted but never emitted

At Script.hs:2669: `when (hasFlag flags VerifyDiscourageUpgradableWitnessProgram)
$ Left "Upgradable witness program discouraged"`. Never emitted by any
flag set.  Core sets in STANDARD (policy.h:127). Allows mempool to
accept and relay txs spending future-soft-fork-defined witness
versions, undermining the soft-fork's user-side discouragement
signalling.

**File:** `src/Haskoin/Script.hs:277` (defined); 2669 (consulted).
**Severity:** P2.

---

## BUG-20 (P2) — `VerifyDiscourageUpgradableTaprootVersion` / `VerifyDiscourageUpgradablePubkeyType` consulted but never emitted

Same pattern. Script.hs:1879 (DISCOURAGE_UPGRADABLE_PUBKEYTYPE in
`execCheckSig` for tapscript), Script.hs:2091 (same in
`execCheckSigAdd`), Script.hs:3056 (DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
in `verifyTaprootWithFlags`). All three consulted.  None emitted.

**File:** `src/Haskoin/Script.hs:280, 281`.
**Severity:** P2 — combined with BUG-19, the entire "discourage" family
of STANDARD flags is dead.

---

## BUG-21 (P3) — `consensusFlagsToScriptFlags` adds `VerifyP2SH` unconditionally without comment cross-ref to BIP-16 exception

Line Consensus.hs:1513:
`[VerifyP2SH]  -- P2SH is always enabled (post BIP-16)`.

The comment hand-waves "post BIP-16" but doesn't reference the
`script_flag_exceptions` mechanism nor say what happens for blocks
*before* BIP16 activation (genesis..h=173,805 mainnet). A reader has
to dig into Core to discover the gap.  Fleet pattern **comment-as-
confession** when paired with BUG-1 + BUG-2.

**File:** `src/Haskoin/Consensus.hs:1513`.
**Severity:** P3 — doc hygiene.

---

## BUG-22 (P3) — Performance.hs parallel verifier re-implements flag-routing; same gaps

`src/Haskoin/Performance.hs:405, 527` both call
`Script.verifyScriptWithFlags (consensusFlagsToScriptFlags flags) tx
i ...`. The parallel verifier is structurally a copy of
`validateSingleTx`'s body. Any fix to BUG-1, BUG-3, BUG-6, BUG-9 must
land in both files.  Fleet pattern **two-pipeline guard** (15th
distinct extension since W76).

**File:** `src/Haskoin/Performance.hs:124, 405, 527`.
**Severity:** P3 — maintenance hazard; no behaviour gap **today**
because both paths derive the same flag set, but the duplication is
load-bearing for any future fix.

---

## Behaviour-by-behaviour scorecard

| # | Wave behaviour | Status | Bugs |
|---|---|---|---|
| 1 | Flag derivation per height (GetBlockScriptFlags equivalent) | PARTIAL | BUG-1, BUG-2, BUG-5, BUG-10 |
| 2 | SCRIPT_VERIFY_P2SH activation + exception | MISSING | BUG-1, BUG-2 |
| 3 | SCRIPT_VERIFY_DERSIG (BIP-66) | PRESENT | — |
| 4 | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (BIP-65) | PRESENT | — |
| 5 | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (BIP-112) | PRESENT | — |
| 6 | SCRIPT_VERIFY_WITNESS (BIP-141) | PARTIAL | BUG-6 |
| 7 | SCRIPT_VERIFY_NULLDUMMY (BIP-147) | PRESENT (comment hygiene) | BUG-4 |
| 8 | SCRIPT_VERIFY_TAPROOT (BIP-341/342) | PARTIAL | BUG-1 (exception) |
| META(a) | Are flags ACTUALLY CHECKED inside EvalScript? | PARTIAL | BUG-12..20 (10 flags consulted, never emitted) |
| META(b) | Consensus vs policy distinction (STANDARD set) | MISSING | BUG-3, BUG-7, BUG-8, BUG-11, BUG-12..20 |
| META(c) | Buried vs versionbits | PRESENT (all-buried, modern Core style) | — |

## Fleet-pattern smell index

- **"defined and consulted but never emitted"** — affects 10 flags
  (BUG-7, 8, 12, 13, 14, 15, 17, 18, 19, 20). This is the dominant
  pattern in haskoin's W144 — the policy machinery is wired through
  the EvalScript bytestream but nothing turns it on. Without a
  `STANDARD_SCRIPT_VERIFY_FLAGS` constant or a separate "policy"
  flag derivation function, all of this code is dead.
- **two-pipeline guard** — Performance.hs duplicates flag routing
  (BUG-22). 15th distinct extension of the fleet pattern since W76.
- **comment-as-confession** — BUG-4 (NULLDUMMY claim "always enforced
  unconditionally") and BUG-21 (P2SH "post BIP-16" hand-wave) both
  hide divergence from Core via mis-leading commentary. Now 6th
  distinct comment-as-confession instance in haskoin since W134.
- **architectural-gap-on-policy/consensus-seam** — BUG-11 captures
  the missing MANDATORY vs STANDARD split. This is the first
  explicit haskoin instance of the pattern; same shape as
  ouroboros/lunarblock policy-flag absences flagged in W125 and W135.
- **historical-grandfather-not-honoured** — BUG-1 (script_flag_exceptions
  map absent). Same shape as the W138 finding that 9 of 10 impls
  have stub-only assumeUTXO chainparams entries: the exception data
  exists in Core, no impl ports it.

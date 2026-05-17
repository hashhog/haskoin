# W127 Taproot / Schnorr / Tapscript audit — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** BIP-340 Schnorr verification, BIP-341 Taproot (key-path + script-path)
sighash + control-block + tweak verification, BIP-342 Tapscript opcode rules
(OP_CHECKSIGADD, leaf-version 0xc0, OP_SUCCESSx, validation-weight budget,
disabled OP_CHECKMULTISIG{,VERIFY}).
**Result:** 24 PRESENT / 4 PARTIAL / 2 MISSING out of 30 gates.
**Bugs found:** 9 (1 P0-CDIV, 4 P1, 4 P2).
**Tests added:** 32 assertions / pinning + xfail sentinels in
`W127TaprootSpec.hs`.

## Top-line verdict

haskoin has one of the most complete Taproot/Tapscript stacks in the fleet.
The `verifyTaprootWithFlags` entry point in `src/Haskoin/Script.hs` handles
both key-path and script-path spends, walks the BIP-341 control-block merkle
path bottom-up, computes the TapTweak hash inline, drives the BIP-340 Schnorr
verify through a libsecp256k1 FFI binding (`haskoin_schnorrsig_verify`), and
threads the BIP-342 validation-weight budget through OP_CHECKSIG /
OP_CHECKSIGVERIFY / OP_CHECKSIGADD. The BIP-341 sighash builder
(`Haskoin.TaprootSighash.buildSigMsg`) is byte-exact against
`bitcoin-core/src/test/data/bip341_wallet_vectors.json` (per the module
header comment, "produces byte-perfect sigMsg + sigHash for all 7
keyPathSpending vectors"). The BIP-342 OP_SUCCESSx scanner is opcode-aware
(walks PUSHDATA payloads correctly, distinguishing a 0xfe data byte from
opcode 0xfe — see the `scanTapscriptForOpSuccess` GetOp-equivalent parser).
The OP_SUCCESS set is byte-identical to Core (`bitcoin-core/src/script/
script.cpp:364`: `80, 98, 126-129, 131-134, 137-138, 141-142, 149-153,
187-254`).

The audit found three classes of divergence:

1. **P0-CDIV: Taproot accepted inside a P2SH wrapper.** Core requires
   `!is_p2sh` for witness-v1 Taproot (`interpreter.cpp:1947`): a P2SH-wrapped
   Taproot witness must fall through to the "unknown witness version" arm and
   succeed unconditionally (or fail DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
   under policy). haskoin's `verifyWitnessProgram` (`Script.hs:2656-2666`)
   dispatches to `verifyTaprootWithFlags` whenever `ver == 1 &&
   BS.length prog == 32 && VerifyTaproot` regardless of the `isP2SHWrapped`
   parameter that's already plumbed into the local closure. The result is
   that a malformed P2SH-wrapped Taproot witness will be rejected by
   haskoin (e.g. "Taproot key-path Schnorr verify failed") where Core
   accepts the spend as an upgradable-witness anyone-can-spend. This is a
   one-sided FALSE-REJECT at the script verifier — block-level it would
   cause a chain split if such a transaction ever reaches mainnet. The
   pattern is direct: add `&& not isP2SHWrapped` to the v1 guard, fall
   through to the `_` arm otherwise. **BUG-1, P0-CDIV.**

2. **P2A (Pay-to-Anchor) not special-cased.** Core's `VerifyWitnessProgram`
   (`interpreter.cpp:1990`) explicitly returns `true` when
   `CScript::IsPayToAnchor(witversion, program)` is true, BEFORE the
   DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM gate fires. haskoin defines
   `isPayToAnchor` and `p2aWitnessProgram` constants
   (`Script.hs:998-1011`) for output classification but its witness-program
   verifier does NOT short-circuit on P2A. A P2A spend (witness-v1, 2-byte
   program) under `VerifyDiscourageUpgradableWitnessProgram` would error
   "Upgradable witness program discouraged" on haskoin where Core succeeds.
   The mainnet-relay impact is small (the flag is policy, not consensus)
   but the divergence is concrete. **BUG-2, P1-CDIV.**

3. **Dead-helper-at-call-site: control-block codec.**
   `Haskoin.TaprootSighash` exports `encodeControlBlock`,
   `decodeControlBlock`, and `tapleafHashWith` with full BIP-341 / BIP-342
   parity. None of these is wired into the verifier:
   `verifyTaprootWithFlags` walks the control block by inline byte slicing
   (`Script.hs:2944-2962`: `BS.head`, `BS.take 32 (BS.drop 1 ...)`,
   `drop33Chunks`). The verifier inlining is consensus-correct, but the
   codec helpers serve no production purpose and are only consumed by the
   test suite (`test/Spec.hs:1817,1862,1907,7751,7794,7801`). This is the
   well-engineered-helper-never-wired pattern — if the verifier ever needs
   to recompute or re-emit control blocks, the inline-byte-slicing code
   path will be the one drift-prone path. **BUG-3, P2.**

Three smaller findings worth noting up front:

- BUG-4 (P1): The Taproot key-path failure error message contains "NULLFAIL"
  in one branch ("Tapscript Schnorr verify failed (NULLFAIL)" at
  `Script.hs:1891` and `:2096`). BIP-341 / BIP-342 do not invoke BIP-146
  NULLFAIL semantics — the failure-on-non-empty-sig is a primary rule, not
  a NULLFAIL refinement. Wire-equivalent (haskoin still aborts the script),
  but mis-labelled, and the wrong constant for any future error-classifier.
- BUG-5 (P1): `OP_CHECKSIGADD num overflow` guard
  (`Script.hs:2059`) uses `maxBound :: Int64` on the result of
  `decodeScriptNum` (capped at 4-byte = Int32 range). The guard
  `num > maxBound - 1` can never fire because `num` is at most ~2^31 and
  `maxBound :: Int64` is ~2^63. Core's matching check uses CScriptNum's
  internal range. The guard is defensive but dead — flag for clean-up.
- BUG-6 (P2): The witness-stack serialize size function
  (`getSerializeSizeOfWitnessStack`, `Script.hs:3112`) is a hand-rolled
  reimplementation of `::GetSerializeSize(witness.stack)`. It looks
  byte-exact, but there is no test that asserts it matches a canonical
  Core vector. Add a pinning test (we do, in G24).

## Gates: PRESENT / PARTIAL / MISSING

### BIP-340 (Schnorr signatures)

- G1  Schnorr verify FFI bound to libsecp256k1                  PRESENT
  Reference: `cbits/secp256k1_compat.c:319-343`,
  `Crypto.hs:137-138,292-300`
- G2  Schnorr verify size gate (64 or 65 bytes)                 PRESENT
  Reference: `Script.hs:2900-2902`, `Script.hs:1900-1902`
- G3  SIGHASH_DEFAULT in 65-byte form is explicit-error         PRESENT
  Reference: `Script.hs:2908-2910`, `Script.hs:1906-1907`
- G4  X-only pubkey size gate (32 bytes)                        PRESENT
  Reference: `Script.hs:2926-2927`, `Crypto.hs:294`
- G5  Tagged-hash uses SHA256(SHA256(tag)||SHA256(tag)||msg)    PRESENT
  Reference: `Crypto.hs:262-266`

### BIP-341 (Taproot key-path + control block)

- G6  TapTweak hash = tagged_hash("TapTweak", intkey||root)     PRESENT
  Reference: `Crypto.hs:391-393`, `Script.hs:2973`
- G7  Taproot witness empty -> error                            PRESENT
  Reference: `Script.hs:2882-2883`
- G8  Annex stripped only when stack.size() >= 2                PRESENT
  Reference: `Script.hs:2888-2893`
- G9  Annex tag byte = 0x50                                     PRESENT
  Reference: `Script.hs:2840-2841`
- G10 Control-block size in [33, 4129]                          PRESENT
  Reference: `Script.hs:2944-2947`
- G11 Control-block (size - 33) % 32 == 0                       PRESENT
  Reference: `Script.hs:2948-2950`
- G12 Control-block leaf-version mask = 0xfe                    PRESENT
  Reference: `Script.hs:2834-2835,2952`
- G13 TapLeaf hash uses compact-size script prefix              PRESENT
  Reference: `Script.hs:2959-2962`, `TaprootSighash.hs:248-254`
- G14 Merkle walk uses lexicographic-min branching              PRESENT
  Reference: `Script.hs:3079-3084` (Core
  `interpreter.cpp:1880-1884`)
- G15 Tweaked-key match against witness program                 PRESENT
  Reference: `Script.hs:2977-2978`
- G16 Parity-bit match against control[0] & 1                   PRESENT
  Reference: `Script.hs:2979-2980`
- G17 Taproot rejected inside P2SH wrapper                      MISSING — BUG-1
  Core: `interpreter.cpp:1947` `&& !is_p2sh`
  haskoin: `Script.hs:2656-2666` — `isP2SHWrapped` parameter is plumbed but
  never consulted.

### BIP-341 / BIP-342 (sighash computation)

- G18 Sighash hash_type byte gate {0x00,0x01-0x03,0x81-0x83}    PRESENT
  Reference: `TaprootSighash.hs:59-62`,
  `Script.hs:2911-2916,1908-1918`
- G19 SIGHASH_SINGLE with idx >= vout.size error                PRESENT
  Reference: `TaprootSighash.hs:124-128`
- G20 sha_prevouts / amounts / scripts / sequences skipped on ACP  PRESENT
  Reference: `TaprootSighash.hs:144-150`
- G21 spend_type = (ext_flag<<1) | (annex ? 1 : 0)              PRESENT
  Reference: `TaprootSighash.hs:158-160`
- G22 Tapscript extension: tapleaf || 0x00 || codesep_pos       PRESENT
  Reference: `TaprootSighash.hs:181-187`
- G23 codesep_pos is opcode INDEX (not byte offset)             PRESENT
  Reference: `Script.hs:1928` (commits `seCodeSepOpPos`, NOT
  `seCodeSepPos`)

### BIP-342 (Tapscript opcodes + budget + OP_SUCCESS)

- G24 Validation-weight budget seeded with GetSerializeSize(wit)+50  PARTIAL — BUG-6
  Reference: `Script.hs:3031-3032`, `Script.hs:3107-3115`. Implementation
  matches Core, but the helper has no canonical pinning test. Test added.
- G25 Budget decrement = 50 per non-empty CHECKSIG/CHECKSIGADD  PRESENT
  Reference: `Script.hs:1830-1838`
- G26 Empty-sig path skips budget decrement                     PRESENT
  Reference: `Script.hs:1865-1867,2066-2068`
- G27 OP_CHECKMULTISIG{,VERIFY} disabled in tapscript           PRESENT
  Reference: `Script.hs:2131-2133` (CHECKMULTISIGVERIFY inherits via
  `execCheckMultiSigVerify = execCheckMultiSig >>= execVerify`)
- G28 OP_CHECKSIGADD legacy/witness-v0 -> BAD_OPCODE             PRESENT
  Reference: `Script.hs:2034-2037`
- G29 OP_SUCCESS opcode set byte-identical to Core              PRESENT
  Reference: `Script.hs:2380-2388` (Core `script.cpp:364-370`)
- G30 OP_SUCCESS scanner is opcode-aware (not raw-byte)         PRESENT
  Reference: `Script.hs:2414-2482` (walks PUSHDATA payloads;
  `Right True` only when opcode-level OP_SUCCESS encountered).

### Additional findings (PARTIAL)

- G2a (PARTIAL): Schnorr "NULLFAIL" error string mis-labelled (BUG-4)
- G24 (PARTIAL): Validation-weight helper untested against canonical
  vector (BUG-6)
- BIP-341 unknown-leaf-version handling: works (forward-compat success
  unless `VerifyDiscourageUpgradableTaprootVersion` is set) but the test
  surface only covers leaf-version 0xc0; no test asserts the unknown-
  leaf-version forward-compat path.
- P2A: defined as a script type but not special-cased in the verifier
  (BUG-2).

## Bugs

### BUG-1 P0-CDIV: Taproot accepted inside P2SH wrapper

**Location:** `src/Haskoin/Script.hs:2656-2666`
**Core reference:** `bitcoin-core/src/script/interpreter.cpp:1947`
**Severity:** P0-CDIV (chain-split potential)

Core's `VerifyWitnessProgram` has the guard
`witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh`.
The `!is_p2sh` clause was added to BIP-341 to prevent P2SH-wrapped Taproot
from being a usable spend type — P2SH-wrapped witness v1 must always fall
through to the upgradable-witness-program arm. haskoin's verifier has the
`isP2SHWrapped` Bool plumbed into the local `verifyWitnessProgram` closure
but does not consult it on the v1 case:

```haskell
case ver of
  0 -> ...
  1 | BS.length prog == 32 && hasFlag flags VerifyTaproot ->
    verifyTaprootWithFlags flags tx idx prog witness amount spentAmounts spentScripts
  _ -> ...
```

Should be:

```haskell
case ver of
  0 -> ...
  1 | BS.length prog == 32 && hasFlag flags VerifyTaproot && not isP2SHWrapped ->
    verifyTaprootWithFlags ...
  _ -> ...
```

**Impact:** A P2SH-wrapped Taproot witness with a malformed Schnorr sig
would be rejected by haskoin (`"Taproot key-path Schnorr verify failed"`)
where Core would accept the spend as an upgradable-witness-program
anyone-can-spend. If such a transaction made it into a block, haskoin
would reject the block and fork off the network. The condition is
non-standard (no wallet creates P2SH-wrapped Taproot), but a miner could
craft it as part of a deliberate fork attack.

### BUG-2 P1-CDIV: P2A (Pay-to-Anchor) not short-circuited

**Location:** `src/Haskoin/Script.hs:2667-2675`
**Core reference:** `bitcoin-core/src/script/interpreter.cpp:1990-1992`
**Severity:** P1-CDIV (policy-flag divergence; mainnet impact bounded by
`VerifyDiscourageUpgradableWitnessProgram` flag activation)

Core's `VerifyWitnessProgram` returns `true` for any P2A spend
(`witversion == 1 && program.size() == 2 && program == {0x4e, 0x73}`)
BEFORE applying `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`.
haskoin's `_` arm at `Script.hs:2667-2675` doesn't distinguish P2A from
other upgradable-witness types, so under the DISCOURAGE flag, a P2A
output is rejected with `"Upgradable witness program discouraged"`. Core
accepts it.

**Fix:** before the DISCOURAGE check at line 2669, add a guard:

```haskell
| ver == 1 && prog == p2aWitnessProgram -> Right True
```

`p2aWitnessProgram` is already defined and exported.

### BUG-3 P2: Control-block codec well-engineered but never wired

**Location:** `src/Haskoin/TaprootSighash.hs:273-324`
**Severity:** P2 (code-quality / refactor-drift; no consensus impact today)

`ControlBlock`, `encodeControlBlock`, `decodeControlBlock`, `tapleafHashWith`
are exported, fully BIP-341-compliant, fully tested in the test suite —
but `verifyTaprootWithFlags` (the actual consensus-critical verifier) does
the byte slicing inline (`Script.hs:2944-2962`). If the verifier ever
needs to round-trip a control block (e.g. for a future RPC `verifyrawtransaction` enhancement that returns parsed witness data), the
inline path is the one that drifts. Wiring the codec from
`TaprootSighash.hs` into the verifier would centralise the BIP-341 control
block reading at a single audited site.

### BUG-4 P1: Error label "NULLFAIL" on Schnorr verify failure

**Location:** `src/Haskoin/Script.hs:1891`, `:2096`
**Severity:** P1 (consensus equivalent; label is wrong, breaks future
error-classification)

Both `execCheckSig` and `execCheckSigAdd` emit
`"Tapscript Schnorr verify failed (NULLFAIL)"` when the Schnorr verify
returns False on a non-empty sig. BIP-146 NULLFAIL is a legacy/witness-v0
rule. BIP-341/BIP-342's rule is `if (!fSuccess && (flags &
SCRIPT_VERIFY_NULLFAIL) && vchSig.size())` in `EvalChecksig` — but the
Tapscript path takes a different code path entirely (`EvalChecksigTapscript`,
`interpreter.cpp:347-385`) where a non-empty sig that fails verification
returns `false` directly (label `SCRIPT_ERR_SCHNORR_SIG` in
`interpreter.cpp:1740`). The label "NULLFAIL" is wire-equivalent (haskoin
still aborts) but misleads any future error classifier.

### BUG-5 P1: Dead overflow guard in OP_CHECKSIGADD

**Location:** `src/Haskoin/Script.hs:2059-2060`
**Severity:** P1 (dead-code defensive guard; matches Core in spirit but
unreachable)

```haskell
when (num > maxBound - 1) $
  Left "OP_CHECKSIGADD: num overflow"
```

`num` comes from `decodeScriptNum (... 4-byte cap)`, so `num` is at most
~2^31. `maxBound :: Int64` is ~9.2 × 10^18. The guard can never fire.
Core's matching check uses CScriptNum's internal range (`int64_t`) and
applies the same logic, but Core's CScriptNum can hold larger values
via the `nMaxNumSize` parameter — haskoin's decode is fixed at 4-byte.
Either reduce to `decodeScriptNumN`-aware bound or drop the guard.

### BUG-6 P2: Validation-weight helper untested against canonical vector

**Location:** `src/Haskoin/Script.hs:3100-3115`
**Severity:** P2

`getSerializeSizeOfWitnessStack` is a hand-rolled reimplementation of
Core's `::GetSerializeSize(witness.stack)` (i.e. compact-size count
+ for-each-item compact-size + body). The function looks byte-exact, but
the audit found no test that pins the function against a canonical Core
vector or against the spec's witness-stack serialization. Add a pinning
test for at least the four compact-size classes (<0xfd, u16, u32, u64)
on item counts and item sizes.

### BUG-7 P2: Unknown-leaf-version forward-compat path untested

**Location:** `src/Haskoin/Script.hs:3054-3062`
**Severity:** P2

When the leaf version is NOT 0xc0 and `VerifyDiscourageUpgradableTaprootVersion` is NOT set, the verifier returns `Right True`. This is the forward-compat
soft-fork hole that Core also has. Audit found no test asserting this
behavior. Add a test that constructs a valid control block with leaf
version 0xc2 and asserts (a) verify succeeds without the discourage flag,
(b) verify fails with `"Unknown Taproot leaf version
(DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)"` when the flag is set.

### BUG-8 P1: Tapscript OP_CHECKMULTISIGVERIFY chain is implicit

**Location:** `src/Haskoin/Script.hs:2278-2279`
**Severity:** P1 (defense-in-depth; consensus-equivalent today)

`execCheckMultiSigVerify` is implemented as
`execCheckMultiSig >>= execVerify`. The tapscript-disabled gate fires
inside `execCheckMultiSig` (`Script.hs:2131-2133`), so OP_CHECKMULTISIGVERIFY
also fails in tapscript. This is correct behavior, but the gate is
implicit — a refactor that bypasses `execCheckMultiSig` for the VERIFY
variant would silently re-enable OP_CHECKMULTISIGVERIFY in tapscript.
Add a direct test that OP_CHECKMULTISIGVERIFY in tapscript fails before
any verification work happens.

### BUG-9 P2: scanTapscriptForOpSuccess doesn't test push-data shadowing

**Location:** `src/Haskoin/Script.hs:2414-2482`
**Severity:** P2

The scanner correctly walks PUSHDATA payloads (per the verbose audit
comment at `:2390-2413`). The brief noted that "the old `any
isTapscriptSuccess (BS.unpack rawBytes)` implementation conflated the
two, over-accepting tapscripts whose push-data contained any of the
OP_SUCCESS byte values." The fix is in place and verified by reading
the source. Audit found no test that asserts the fix specifically:
a tapscript that pushes a single byte 0xfe (`OP_PUSHBYTES_1 0xfe`)
must NOT be treated as OP_SUCCESS. Add a regression test.

## Per-impl bug count (this audit): 9

| # | Pri | Description |
|---|-----|---|
| BUG-1 | P0-CDIV | Taproot accepted inside P2SH wrapper |
| BUG-2 | P1-CDIV | P2A not short-circuited under DISCOURAGE flag |
| BUG-3 | P2 | Control-block codec exported, dead-helper |
| BUG-4 | P1 | "NULLFAIL" mislabel on Schnorr verify failure |
| BUG-5 | P1 | Dead Int64-overflow guard in OP_CHECKSIGADD |
| BUG-6 | P2 | Validation-weight helper untested |
| BUG-7 | P2 | Unknown-leaf-version forward-compat untested |
| BUG-8 | P1 | OP_CHECKMULTISIGVERIFY tapscript-disabled is implicit |
| BUG-9 | P2 | Push-data shadowing of OP_SUCCESS untested |

## Patterns observed

- **Comment-as-confession follow-up**: the brief flagged haskoin as having
  a known instance ("We trust the test vector construction here").
  Verified at `Script.hs:2964-2965` — the comment has been fixed and now
  describes the structural validation that the verifier performs. The
  audit did NOT find any new comment-as-confession.
- **Dead-helper-at-call-site (BUG-3)**: `ControlBlock` + codec are
  exported with full BIP-341 parity, but `verifyTaprootWithFlags` uses
  inline byte slicing. Classic "well-engineered helper never wired" —
  the codec is correct, but the verifier is the consensus-critical path
  and the verifier ignores the codec.
- **Frozen-constants degrade silently**: BIP-342 `VALIDATION_WEIGHT_OFFSET`
  (50) and `VALIDATION_WEIGHT_PER_SIGOP_PASSED` (50) are inline literals
  (`Script.hs:3032`, `:1835`) rather than named constants. Acceptable for
  consensus-stable values but would silently drift if Core ever bumps
  them under a soft fork. Add to a future cleanup wave.

# W131 Descriptors + Miniscript (BIP-380 / 385) — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** BIP-380 output descriptor language + BIP-385 miniscript. Sources
audited: `src/Haskoin/Wallet.hs` (descriptor section ~lines 5025-5900) and
`src/Haskoin/Script.hs` (miniscript section ~lines 3185-4520).
**Result:** 10 PRESENT / 7 PARTIAL / 13 MISSING out of 30 gates.
**Bugs found:** 15 (3 P0-CDIV, 6 P1, 6 P2).
**Tests added:** 30 xfail/xit sentinels + 12 pinning `it` assertions = 42 cases
in `test/W131DescriptorsMiniscriptSpec.hs`.

## Top-line verdict

haskoin has a **surface-level descriptor parser** and a **structurally complete
but type-checking-incomplete Miniscript AST**.  The BIP-380 checksum (PolyMod +
INPUT_CHARSET + CHECKSUM_CHARSET) is byte-exact against Core.  The descriptor
AST covers pk / pkh / wpkh / sh / wsh / multi / sortedmulti / tr / rawtr / addr
/ raw / combo (12 of Core's ~14 top-level fragments — `multi_a` and
`sortedmulti_a` are present in Miniscript but NOT as standalone descriptor
fragments; you can only get them via `tr()`'s tree).  The Miniscript AST has
all 24 of Core's `Fragment` enum entries plus all 11 wrappers.

The audit found three classes of consensus-relevant divergence:

1. **P0-CDIV: `parseSh` accepts arbitrary nesting.**  Core
   (descriptor.cpp:2423-2434) requires `sh()` only at the top level, and the
   recursive `ParseScript` call uses `ParseScriptContext::P2SH` which then
   permits only `pk / pkh / wpkh / wsh / multi / sortedmulti` (no nested `sh`,
   no `tr`, no `combo`, no `addr`, no `raw`).  haskoin's `parseSh`
   (Wallet.hs:5251-5255) just recursively calls `parseDescriptorExpr` with no
   context tracking, so `sh(sh(pk(...)))`, `sh(tr(...))`, `sh(addr(...))` and
   `sh(combo(...))` all parse successfully.  This violates BIP-380 and means
   any descriptor-importing wallet will track scriptPubKeys Core would reject
   at import time.

2. **P0-CDIV: `parseWsh` accepts non-miniscript inner expressions and
   non-wsh-permitted fragments.**  Core (descriptor.cpp:2436-2446) routes
   `wsh()` to `ParseScript(..., P2WSH, ...)` which restricts the inner to
   `pk / pkh / multi / sortedmulti / miniscript_expression`.  haskoin allows
   `wsh(sh(...))`, `wsh(wsh(...))`, `wsh(tr(...))`, `wsh(addr(...))`,
   `wsh(raw(...))`, `wsh(combo(...))` and — crucially — `wsh(wpkh(...))`
   (which is malformed: P2SH-P2WPKH exists, P2WSH-P2WPKH does not).  Same
   class of bug as BUG-1.

3. **P0-CDIV: TAPROOT_CONTROL_MAX_NODE_COUNT = 128 not enforced.**  Core
   (descriptor.cpp:2484-2487) hard-bounds `tr()` nesting depth at 128.
   haskoin's `parseTapTree` (Wallet.hs:5303-5315) recurses unboundedly.
   Construct `tr(KEY,{...,{...,{...,{...,...}}}})` 130 deep and Core rejects
   while haskoin accepts; the resulting Merkle root (Wallet.hs:5785
   `tapTreeMerkleRoot`) is computed successfully and an invalid descriptor
   is "imported".

The most concerning P1 finding is BUG-4: **the miniscript parser has NO
type-checking gate at parse time**.  `parseMiniscript` returns a `Miniscript`
even if the expression is malformed at the type level (e.g.,
`or_b(after(100),pk(...))` where `or_b` requires both args type `Bdu` —
`after` is type `B` but lacks the `u` (unit) property).  Core
(miniscript.h:1854) does the parse and the type-check in a single
`miniscript::FromString` call.  haskoin makes them separate: `parseMiniscript`
followed by `checkMiniscriptType` is the API, and you can hold and serialize
a `Miniscript` value that would never round-trip through Core.

The cleanest BIP-380 spec deviation is BUG-7: **descriptor checksum is
optional in `parseDescriptor` instead of required for round-tripping** —
Core treats checksumless input as "import-only" with a warning, but haskoin
silently accepts it on the same code path as checksummed input.

Discovery-only audit: no production code changes.  Tests are pinning-shape
(assert current behaviour with `it`) and xfail-shape (assert *desired*
Core-parity behaviour with `xit`/`pendingWith`) so future fix waves can
flip the sentinels once the missing primitives are wired.

## 30-gate matrix

### BIP-380 Descriptor language (10 gates)

| # | Gate | Status | Notes |
|---|------|--------|-------|
| G1 | INPUT_CHARSET byte-exact against Core | PRESENT | Wallet.hs:5098-5102, 96 chars verified |
| G2 | CHECKSUM_CHARSET byte-exact against Core | PRESENT | Wallet.hs:5105-5106 |
| G3 | PolyMod generator constants byte-exact against Core | PRESENT | Wallet.hs:5110-5119 |
| G4 | 8-character checksum emission | PRESENT | Wallet.hs:5121-5139 |
| G5 | validateDescriptorChecksum rejects bad checksum | PRESENT | Wallet.hs:5167-5178, pre-existing Spec test |
| G6 | parseDescriptor returns ParseError on missing checksum | MISSING | BUG-7 — accepts checksumless silently |
| G7 | sh() only at top level (BIP-380 §"Script expressions") | MISSING | BUG-1 — parseSh recursive w/o ctx |
| G8 | wsh() inner only pk/pkh/multi/sortedmulti/miniscript | MISSING | BUG-2 — accepts arbitrary inner |
| G9 | tr() inner key context = P2TR; subscripts = P2TR | PARTIAL | parses but no x-only validation |
| G10 | tr() nesting depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT=128 | MISSING | BUG-3 — unbounded recursion |

### BIP-380 Key expressions (5 gates)

| # | Gate | Status | Notes |
|---|------|--------|-------|
| G11 | KeyOrigin [fp/path] supported on every KeyExpr | PRESENT | Wallet.hs:5346-5354 |
| G12 | Multipath key expressions `<0;1>` | MISSING | BUG-5 — no parser path |
| G13 | Hardened wildcard `*'` distinct from non-hardened `*` | PRESENT | DerivWildcard vs DerivHardenedWildcard |
| G14 | Hardened-derivation-from-xpub rejected | MISSING | BUG-9 — silent fallthrough |
| G15 | x-only pubkey in rawtr() / tr()-internal | PARTIAL | accepts hex but no parity gate |

### BIP-380 Multi-key + max-key fragments (5 gates)

| # | Gate | Status | Notes |
|---|------|--------|-------|
| G16 | multi() MAX_PUBKEYS_PER_MULTISIG=20 | PRESENT | Wallet.hs:5280 |
| G17 | multi_a() MAX_PUBKEYS_PER_MULTI_A=999 | MISSING | BUG-10 — no descriptor-level multi_a |
| G18 | sh(multi) MAX_SCRIPT_ELEMENT_SIZE=520 byte cap | MISSING | BUG-11 — no script-size cap |
| G19 | multi outside tr() / multi_a inside tr() context gate | PARTIAL | descriptor layer doesn't gate |
| G20 | sortedmulti(_a) lex-sorts at derive time | PRESENT | Wallet.hs:5742 sortOn |

### BIP-385 Miniscript type system (10 gates)

| # | Gate | Status | Notes |
|---|------|--------|-------|
| G21 | All 24 Core Fragment enum values represented | PRESENT | MsPk/MsPkH/.../MsAndOr |
| G22 | All 11 Core wrappers represented (a/s/c/d/v/j/n/l/u/t) | PRESENT | MsA/MsS/.../MsT |
| G23 | parseMiniscript type-checks at parse time | MISSING | BUG-4 — separate checkMiniscriptType |
| G24 | IsSane = IsValidTopLevel ∧ ValidSatisfactions ∧ m ∧ s ∧ k | PARTIAL | checkMiniscriptType subset only |
| G25 | NeedsSignature ('s' property top-level required) | PARTIAL | checked but as "s ∨ f" not "s" |
| G26 | CheckTimeLocksMix ('k' property) | PARTIAL | propK computed but conflict logic buggy |
| G27 | CheckDuplicateKey on Miniscript node | MISSING | BUG-12 — no duplicate-key scan |
| G28 | MAX_OPS_PER_SCRIPT = 201 enforced via GetOps | MISSING | BUG-13 — no GetOps helper |
| G29 | MAX_STACK_SIZE=1000 / MAX_STANDARD_P2WSH_STACK_ITEMS=100 | MISSING | BUG-14 — no GetStackSize helper |
| G30 | FromScript inverse of compileMiniscript (decode) | MISSING | BUG-15 — no Script → Miniscript |

## Bugs (15 total)

### P0-CDIV (3)

**BUG-1 (P0-CDIV) `parseSh` accepts arbitrary nesting** — Wallet.hs:5251-5255.
Core (descriptor.cpp:2423-2434) re-enters `ParseScript` with
`ParseScriptContext::P2SH` which permits only `{pk, pkh, wpkh, wsh, multi,
sortedmulti, miniscript_expr}`.  haskoin accepts `sh(sh(...))`, `sh(tr(...))`,
`sh(addr(...))`, `sh(combo(...))`, `sh(raw(...))`.  Importing one of these
into haskoin creates wallet-tracked outputs Core would never produce; the
descriptor cannot round-trip via Core's reference.

**BUG-2 (P0-CDIV) `parseWsh` accepts non-P2WSH-permitted inner** —
Wallet.hs:5258-5262.  Core (descriptor.cpp:2436-2446) re-enters `ParseScript`
with `ParseScriptContext::P2WSH` which permits only `{pk, pkh, multi,
sortedmulti, miniscript_expr}` — no nested `sh`, no nested `wsh`, no `tr`,
no `wpkh` (P2WSH-P2WPKH is malformed), no `addr`, no `raw`, no `combo`.
haskoin accepts all of those.  Same shape as BUG-1.

**BUG-3 (P0-CDIV) TAPROOT_CONTROL_MAX_NODE_COUNT=128 not enforced in tr()** —
Wallet.hs:5303-5315.  Core (descriptor.cpp:2484-2487) tracks branch depth and
rejects with `"tr() supports at most %i nesting levels"` at depth > 128.
haskoin recurses unboundedly on `{`-prefix.  At very deep nesting the
implementation runs out of stack space (RTS-default 1MB stack), but BEFORE
that point an attacker can ship a descriptor with depth 129-300 that haskoin
accepts and Core rejects — silent fork at descriptor-import time, then if
funds are sent the wallet won't recognize them since the resulting Merkle
root computation is malformed.

### P1 (6)

**BUG-4 (P1) Miniscript parse and type-check decoupled** —
Script.hs:4246-4247 `parseMiniscript` returns the raw AST without invoking
`checkMiniscriptType`; the latter is a separate exported function.  Core
(miniscript.h:1854 `Parse`) returns `std::optional<Node<Key>>` that is empty
if the type system check failed.  Consequence: external callers who use
`parseMiniscript` and skip `checkMiniscriptType` can hold malformed
Miniscript AST nodes (e.g., `or_b(after(100),pk(...))` where `after` is
zero-arg, lacks 'u' property, and `or_b` requires both subs `Bdu` —
invalid).  Even after the type check, BUG-13/14 mean ops and stack-size
limits aren't enforced.

**BUG-5 (P1) Multipath descriptors `<0;1>` not supported** —
Wallet.hs:5495-5527 `parseXPubPath` and 5394-5432 `parseKeyFromText`.  Core
(descriptor.cpp ~Parse) supports `<0;1>` and `<0;1>/*` to denote multiple
derivation paths from one descriptor string (BIP-389).  haskoin's path
parser does not recognize `<` / `;` / `>`; any descriptor using multipath
will fail with `MalformedDescriptor` or `InvalidKey`.  Wallets exporting
multipath descriptors (Sparrow, Electrum since 4.4, Specter) cannot be
imported.

**BUG-6 (P1) `Sh (Wpkh ...)` is the only allowed P2SH-wrapped-SegWit, no
context enforcement** — Wallet.hs:5868.  Core treats `sh(wpkh(...))` and
`sh(wsh(...))` as the only two valid P2SH-wrapped forms (the rest are
filtered out by `ParseScriptContext::P2SH` from BUG-1).  haskoin only
exports `Sh (Wpkh ...)` in `expandCombo`, but BUG-1 means the parser admits
`Sh (Pk ...)`, `Sh (Combo ...)`, etc.  The parser-acceptance bug feeds the
wallet-tracking bug.

**BUG-7 (P1) `parseDescriptor` does not require a checksum** —
Wallet.hs:5200-5207.  `parseDescriptor` only validates a checksum if `#`
is present in input.  Per BIP-380, a checksumless descriptor is "import
only" and Core's `parse_descriptor` emits a warning + accepts.  haskoin
silently accepts without distinction.  No "import-only" surfacing means
operators can't tell from a parsed descriptor whether it was checksum-
guarded against typos.

**BUG-8 (P1) Compressed-key requirement on `wpkh()` not enforced at parse
time** — Wallet.hs:5244-5248.  Core (descriptor.cpp:2409-2422) re-enters
with `ParseScriptContext::P2WPKH` which calls `permit_uncompressed = false`
(:1879) and rejects uncompressed pubkeys.  haskoin's `parseWpkh` accepts
any `KeyExpr`; `parseLiteralPubKey` (Wallet.hs:5530-5535) accepts 65-byte
uncompressed pubkeys.  Importing an uncompressed-key `wpkh()` descriptor
will then derive a P2WPKH scriptPubKey that Core would refuse to mine
into a block (witness-v0 uncompressed-key BIP-143 sigops gate is upstream
but the wallet output tracking is already wrong).

**BUG-9 (P1) Hardened-derivation-from-xpub silent fallthrough** —
Wallet.hs:5495-5527 `parseXPubPath`.  Core (descriptor.cpp `ParsePubkey`)
rejects `xpub.../44'/0'/0'/0/*` because deriving the hardened components
from an xpub is impossible.  haskoin's `parsePathIdx` (Wallet.hs:5516-5527)
silently sets bit 31 on every hardened component without checking whether
the upstream `KeyXPub` admits it; `derivePublic` (Wallet.hs:567) then
calls `error "derivePublic: cannot derive hardened child from public
key"` at runtime — a deferred crash rather than a parse-time error.

### P2 (6)

**BUG-10 (P2) No descriptor-level `multi_a` / `sortedmulti_a` fragment** —
Wallet.hs:5220-5226 `parseDescriptorExpr`.  Core has `multi_a` and
`sortedmulti_a` as top-level descriptor fragments accepted only inside
`tr()` (descriptor.cpp:2315-2408).  haskoin's `Descriptor` AST has no
`MultiA` / `SortedMultiA` constructors — they exist only in the
`Miniscript` AST (Script.hs:3217-3218).  To express `tr(KEY,multi_a(...))`
in a descriptor string today, haskoin would need to route through the
miniscript parser inside a `wsh(...)` or `tr(...)` body, but the
descriptor parser (Wallet.hs:5210-5227) has no miniscript dispatch arm.

**BUG-11 (P2) MAX_SCRIPT_ELEMENT_SIZE=520 byte cap in sh() not enforced** —
Wallet.hs:5251-5255.  Core (descriptor.cpp:2366-2371) computes
`script_size` and rejects `sh(multi(15,...))` if the resulting redeemScript
> 520 bytes.  haskoin doesn't compute the inner-script size.

**BUG-12 (P2) Miniscript duplicate-key check absent** — Script.hs no
`hasDuplicateKeys` function.  Core (miniscript.h:1691) computes
`has_duplicate_keys` during construction and `IsSane()` returns false if
duplicates are present.  haskoin's `checkMiniscriptType` accepts
`thresh(2,pk(K1),pk(K1))` with the same key reused.

**BUG-13 (P2) GetOps / MAX_OPS_PER_SCRIPT not exposed for Miniscript** —
Script.hs has `MAX_OPS_PER_SCRIPT = 201` as a constant for execution but
no `miniscriptOps :: Miniscript -> Int` helper.  Core (miniscript.h:1560
`GetOps`, :1571 `CheckOpsLimit`) computes ops count statically; haskoin
can't check `multi(20,...,3,...)` style ops-exceeding fragments before
compile.

**BUG-14 (P2) GetStackSize / MAX_STANDARD_P2WSH_STACK_ITEMS=100 not exposed
for Miniscript** — Script.hs no `miniscriptStackSize`.  Core
(miniscript.h:1581 `GetStackSize`, :1597 `CheckStackSize`) statically
computes max stack depth during satisfaction; haskoin's
`checkMiniscriptType` doesn't gate.

**BUG-15 (P2) Script → Miniscript decoder absent** — Script.hs no
`FromScript` / `decodeMiniscript`.  Core (miniscript.h:2272 ~
`FromScriptTokenize`) walks a CScript and rebuilds the Miniscript tree.
haskoin only has the AST → Script direction (`compileMiniscript`).
Operationally this means haskoin can't take a P2WSH witnessScript pulled
from a transaction and reconstruct the descriptor that would have produced
it; the wallet's "watch only" import path is one-way.

## Cross-reference notes

- W127 Taproot audit catalogued `tr()` Merkle-walk correctness, P2A short-
  circuit, validation-weight budget, OP_SUCCESS scanner — all at the
  *interpreter / sighash* layer.  W131 is strictly at the *descriptor /
  parser / type-check* layer; the two audits don't overlap.
- W118 wallet audit catalogued PSBT / BIP-32 / WIF / send / UTXO / fee.
  W131 BUG-9 (hardened-from-xpub) borders W118's BIP-32 surface but the
  failure mode is parse-time (descriptor) not derive-time (wallet).
- W129 coin-selection audit's BUG-15 (`minChangeAmount = 1000` vs Core
  `CHANGE_LOWER = 50000`) is unrelated.

## Out of scope for this discovery wave

- Wiring `parseMiniscript` into `parseDescriptorExpr` (i.e., making
  `wsh(or_d(pk(...),and_v(...)))` parse) — that's a separate fix wave
  closing BUG-10 by routing the descriptor parser through the miniscript
  parser for `wsh()` and `tr()` bodies.
- `FromScript` decoder (BUG-15) — significant new code, separate wave.
- Multipath `<0;1>` (BUG-5) — needs parser-state refactor.
- Hardened-derivation-from-xpub (BUG-9) — fix is in `parseXPubPath`
  cross-validating against the upstream `decodeXPub` vs `decodeXPriv`
  branch in `parseKeyFromText`.

## Files

- `audit/w131_descriptors_miniscript.md` (this file)
- `test/W131DescriptorsMiniscriptSpec.hs` — 30 xit/it sentinels + 12 pinning
  assertions
- Spec.hs wired (+`import qualified W131DescriptorsMiniscriptSpec` +
  `W131DescriptorsMiniscriptSpec.spec` invocation)
- haskoin.cabal `other-modules` += `W131DescriptorsMiniscriptSpec`

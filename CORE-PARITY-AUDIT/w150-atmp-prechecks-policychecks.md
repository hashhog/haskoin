# W150 — AcceptToMemoryPool + PreChecks + PolicyScriptChecks + ConsensusScriptChecks (haskoin)

**Wave:** W150 — `AcceptToMemoryPool`, `MemPoolAccept::AcceptSingleTransaction`,
`MemPoolAccept::PreChecks`, `MemPoolAccept::PolicyScriptChecks`,
`MemPoolAccept::ConsensusScriptChecks`, `MemPoolAccept::Finalize`,
`IsStandardTx`, `IsWitnessStandard`, `AreInputsStandard`, `GetDustThreshold`,
`SCRIPT_VERIFY_*` flag-sets at mempool, `-acceptnonstdtxn`,
`-minrelaytxfee`, `-incrementalrelayfee`, `-datacarrier`,
`-permitbaremultisig`, `-maxmempool`, `-mempoolexpiry`, `-mempoolfullrbf`,
`-bytespersigop`, `-dustrelayfee`, `prioritisetransaction`,
`mempoolminfee`, mempool reject-token wire-parity.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:780-1390` — `MemPoolAccept::AcceptSingleTransaction`,
  `PreChecks`, `PolicyScriptChecks`, `ConsensusScriptChecks`, `Finalize`,
  `RBFChecks`, `ReplacementChecks`, `PreCheckEphemeralTx`,
  `AreInputsStandard`, m_view layering, `test_accept` early-return.
- `bitcoin-core/src/policy/policy.cpp:100-263` — `IsStandardTx`,
  `IsWitnessStandard`, `AreInputsStandard`, `GetDustThreshold`,
  `IsUnspendable`, MAX_OP_RETURN_RELAY cumulative budget,
  `permit_bare_multisig`, `MAX_P2SH_SIGOPS=15`,
  `GetSigOpsAdjustedWeight`, `GetVirtualTransactionSize`.
- `bitcoin-core/src/policy/policy.h` — `DEFAULT_INCREMENTAL_RELAY_FEE=1000`,
  `DEFAULT_MIN_RELAY_TX_FEE=1000`, `MAX_STANDARD_TX_WEIGHT=400000`,
  `MAX_STANDARD_P2WSH_STACK_ITEMS=100`,
  `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE=80`,
  `MAX_STANDARD_TX_SIGOPS_COST=16000` (= MAX_BLOCK_SIGOPS_COST/5),
  `MIN_STANDARD_TX_NONWITNESS_SIZE=65`, `DEFAULT_BYTES_PER_SIGOP=20`,
  `DUST_RELAY_TX_FEE=3000`, `MAX_DUST_OUTPUTS_PER_TX=1`.
- `bitcoin-core/src/script/interpreter.h:147-220` — `MANDATORY_SCRIPT_VERIFY_FLAGS`
  (P2SH | DERSIG | NULLDUMMY | CHECKLOCKTIMEVERIFY | CHECKSEQUENCEVERIFY | WITNESS | TAPROOT),
  `STANDARD_SCRIPT_VERIFY_FLAGS` (MANDATORY +
  STRICTENC | MINIMALDATA | DISCOURAGE_UPGRADABLE_NOPS | CLEANSTACK |
  MINIMALIF | NULLFAIL | LOW_S | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
  WITNESS_PUBKEYTYPE | DISCOURAGE_UPGRADABLE_PUBKEYTYPE | CONST_SCRIPTCODE |
  DISCOURAGE_OP_SUCCESS | DISCOURAGE_UPGRADABLE_TAPROOT_VERSION |
  SIGPUSHONLY). These 14 STANDARD bits are what separates PolicyScriptChecks
  from ConsensusScriptChecks.
- `bitcoin-core/src/init.cpp` — `-acceptnonstdtxn`, `-minrelaytxfee`,
  `-incrementalrelayfee`, `-datacarrier`, `-datacarriersize`,
  `-permitbaremultisig`, `-maxmempool`, `-mempoolexpiry`,
  `-mempoolfullrbf`, `-bytespersigop`, `-dustrelayfee`.
- `bitcoin-core/src/rpc/mempool.cpp` — `sendrawtransaction`,
  `testmempoolaccept`, `submitpackage`, `getmempoolinfo`,
  `getmempoolentry`, `getrawmempool`, `prioritisetransaction`,
  `savemempool`.

**Files audited**
- `src/Haskoin/Mempool.hs` — `addTransaction` (line 655),
  `addTransactionInner` (line 677), `addTransactionNoConflicts`,
  `addTransactionWithReplacement`, `finalizeTransaction` (line 840),
  `continueAddTransaction` (line 1010), `testAcceptTransaction` (line 1141),
  `addTransactionToMempool` (line 2592), `resolveInput` (line 1198),
  `verifyAllScripts` (line 1237), `validateInputsStandardness` (line 3783),
  `generalEphemeralPreCheck` (line 3882), `checkSeqLocksAtTip`,
  `signalsOptInRBF` (line 397), `blockConnected` (line 1858),
  `newMempool` (line 626).
- `src/Haskoin/Policy/Standard.hs` — `checkStandardTx`,
  `checkStandardTxWith`, `checkWitnessStandard`, all MAX_STANDARD_*
  constants, `dustThreshold`, `isDust`.
- `src/Haskoin/Consensus.hs` — `validateTransaction` (line 1368),
  `consensusFlagsAtHeight` (line 1498) and
  `consensusFlagsToScriptFlags` (line 1511) — **MANDATORY-only**;
  `getTransactionSigOpCost`, `getLegacySigOpCount`, `getP2SHSigOpCost`,
  `getWitnessSigOpCost`, `isFinalTxCheck`, `coinbaseMaturity=100`,
  `computeWtxId` (line 3000, returns `TxId`).
- `src/Haskoin/Script.hs` — `ScriptVerifyFlag` enum (line 265-287:
  21 constructors), `verifyScriptWithFlags` (line 2575).
- `src/Haskoin/Mempool/Persist.hs` — `loadMempool` (line 326),
  `dumpMempool`, `mpFeeDeltas` persistence (line 369).
- `src/Haskoin/Crypto.hs` — `computeWtxid` (line 1064, returns `Wtxid`).
- `src/Haskoin/Rpc.hs` — `handleSendRawTransaction` (line 2219),
  `handleTestMempoolAccept` (line 5403), `handleSubmitPackage` (line 5538+),
  `handleGetRawMempool` (line 2464), `handleGetMempoolEntry` (line 5743),
  `handleGetMempoolInfo` (line 2440), `mempoolErrorToRpcResponse` (line 2296),
  `mempoolErrorToText` (line 5480).
- `app/Main.hs` — `parseNodeOptions` (line 227-332: NO mempool/policy
  knobs), mempool init (line 897: `newMempool net cache
  defaultMempoolConfig 0 0 ...`).
- `config.example.toml` — `[mempool]` section header but ZERO entries
  besides a "Uses Bitcoin Core defaults internally" comment.

---

## Gate matrix (38 sub-gates / 12 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | Operator-knob CLI surface | G1: `-acceptnonstdtxn` flag | **BUG-2 (P0-CDIV)** — flag absent; no path to disable policy in regtest |
| 1 | … | G2: `-minrelaytxfee` flag | **BUG-3 (P1)** — flag absent; hard-coded `mpcMinFeeRate = FeeRate 1` |
| 1 | … | G3: `-incrementalrelayfee` flag | **BUG-3 cross-cite** — hard-coded `incrementalRelayFeePerKvb = 100` |
| 1 | … | G4: `-datacarrier` flag | **BUG-3 cross-cite** — hard-coded |
| 1 | … | G5: `-datacarriersize` flag | **BUG-3 cross-cite** — hard-coded `maxOpReturnRelay = 100_000` |
| 1 | … | G6: `-permitbaremultisig` flag | **BUG-3 cross-cite** — hard-coded `True` |
| 1 | … | G7: `-maxmempool=N` flag | **BUG-3 cross-cite** — hard-coded `mpcMaxSize = 300*1024*1024` |
| 1 | … | G8: `-mempoolexpiry` flag | **BUG-3 cross-cite** — hard-coded `mempoolExpirySecs = 14*24*3600` |
| 1 | … | G9: `-mempoolfullrbf` flag | **BUG-3 cross-cite** — hard-coded `mpcRBFEnabled = True` |
| 1 | … | G10: `-bytespersigop` flag | **BUG-3 cross-cite** — hard-coded `defaultBytesPerSigop = 20` |
| 1 | … | G11: `-dustrelayfee` flag | **BUG-3 cross-cite** — hard-coded `dustRelayTxFee = 3000` |
| 2 | PolicyScriptChecks flag-set | G12: STANDARD_SCRIPT_VERIFY_FLAGS at mempool admit | **BUG-1 (P0-CDIV) — W144 BUG-3 echo CONFIRMED** — `consensusFlagsToScriptFlags` emits only MANDATORY set; ALL 14 STANDARD flags unenforced at mempool |
| 2 | … | G13: MINIMALIF set | **BUG-1 cross-cite** |
| 2 | … | G14: CLEANSTACK set | **BUG-1 cross-cite** |
| 2 | … | G15: LOW_S set | **BUG-1 cross-cite** |
| 2 | … | G16: NULLFAIL set | **BUG-1 cross-cite** (`VerifyNullFail` defined but never emitted) |
| 2 | … | G17: WITNESS_PUBKEYTYPE set | **BUG-1 cross-cite** (`VerifyWitnessPubkeyType` defined but never emitted) |
| 2 | … | G18: DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM set | **BUG-1 cross-cite** (defined but never emitted) |
| 3 | PreChecks consensus-side | G19: coinbase reject | PASS (`Mempool.hs:682`, `ErrCoinbaseNotAllowed`) |
| 3 | … | G20: duplicate-wtxid in mempool | PASS (`Mempool.hs:667`) |
| 3 | … | G21: bad-txns-inputs-duplicate (CVE-2018-17144) | PASS (`Consensus.hs:1413-1414`) |
| 3 | … | G22: IsFinalTx at tip+1 (BIP-113) | PASS (`Mempool.hs:710`) |
| 3 | … | G23: CheckSequenceLocksAtTip (BIP-68) | PASS (`Mempool.hs:719`) |
| 4 | Coinbase maturity at admit | G24: COINBASE_MATURITY=100 enforced relative to next block | **BUG-4 (P0-CDIV)** — `height - ueHeight < 100` ignores Core's `nSpendHeight = activeHeight+1`; rejects coinbase spends 1 block earlier than Core (consensus split if relayed and mined) |
| 4 | … | G25: Word32 wrap-safety on `height - ueHeight` underflow | **BUG-5 (P0-SEC)** — when `ueHeight > height` (cold-start, reorg-readmit), Word32 subtraction wraps to ~4 billion, < 100 is FALSE, so coinbase appears MATURE; gate inverts |
| 5 | Mempool height tracking | G26: `mpHeight` initialised to actual chain tip | **BUG-6 (P0-CDIV)** — `newMempool ... 0 0 ...` hard-codes initial height and MTP to zero regardless of loaded chain tip; never reset; only incremented +1 per `blockConnected` |
| 5 | … | G27: loadMempool runs admission against correct height | **BUG-6 cross-cite** — `loadMempool` (called at `Main.hs:904` BEFORE any block connect) admits txs against `mpHeight=0`, `mpMTP=0`; coinbase maturity, BIP-113, BIP-68, sigop-cost-flags, witness-script-flags all evaluated at genesis |
| 6 | MIN_STANDARD_TX_NONWITNESS_SIZE | G28: 65-byte minimum non-witness serialised size enforced | PASS (`Policy/Standard.hs:411-414`) |
| 7 | Witness-standardness | G29: P2WSH stack items ≤ 100 (excluding script) | PASS (`Policy/Standard.hs:625`) |
| 7 | … | G30: P2WSH stack item ≤ 80 bytes | PASS (`Policy/Standard.hs:627-629`) |
| 7 | … | G31: Tapscript annex rejected as nonstandard | PASS (`Policy/Standard.hs:641`) |
| 7 | … | G32: P2A witness-stuffing rejected | PASS (`Policy/Standard.hs:598-599`) |
| 8 | Sigop cost cap | G33: MAX_STANDARD_TX_SIGOPS_COST=16_000 (block/5) | PASS (`Policy/Standard.hs:94`); used at `Mempool.hs:939, 1114, 2517` |
| 9 | Reject-token wire parity | G34: Core's exact reject tokens (`bad-txns-vin-empty`, `bad-cb-length`, `bad-txns-vout-negative`, etc.) | **BUG-7 (P1)** — `validateTransaction` uses 6 free-form English strings instead of Core's BIP-22 tokens; `mempoolErrorToText` uses some Core-style tokens but not others |
| 9 | … | G35: `mempoolErrorToText` exhaustive over `MempoolError` constructors | **BUG-8 (P0-SEC)** — non-exhaustive case on 7 constructors; hits at runtime crash the `testmempoolaccept` handler thread with `Non-exhaustive patterns` |
| 10 | RBF / BIP-125 plumbing | G36: `meRBFOptIn` derivation single source of truth | **BUG-9 (P1)** — TWO derivations: `signalsOptInRBF` (line 398, `<= 0xfffffffd`) vs inline at line 2601 (`< 0xfffffffe`); semantically equivalent but two-pipeline guard 17th distinct extension |
| 11 | prioritisetransaction operator-knob | G37: `prioritisetransaction` RPC dispatched | **BUG-10 (P0-CDIV)** — RPC absent from dispatch table; `mpFeeDeltas` is plumbed end-to-end (read in `finalizeTransaction`, persisted in mempool.dat) but no in-band writer exists |
| 12 | getmempoolinfo / getmempoolentry RPC wire-parity | G38: `minrelaytxfee` / `incrementalrelayfee` reflect actual config | **BUG-11 (P1)** — both hard-coded to literal `1000` instead of `mpcMinFeeRate * 1000` / `incrementalRelayFeePerKvb`; `mempoolminfee` ignores rolling minimum (`getMempoolMinFeeRate` exported but never called); `fullrbf` hard-coded `True`; `modifiedfee` hard-coded to base fee; `spentby` array always empty; `descendantfees`/`ancestorfees` emit as raw integer instead of Core's BTC fractional |

---

## BUG-1 (P0-CDIV) — PolicyScriptChecks uses MANDATORY-only flags; STANDARD_SCRIPT_VERIFY_FLAGS entirely absent at mempool (W144 BUG-3 echo, CONFIRMED LIVE)

**Severity:** P0-CDIV. **W144 BUG-3 cross-fleet pattern confirmed at the
mempool side.** Bitcoin Core's `MemPoolAccept::PolicyScriptChecks`
(`validation.cpp:1234-1280`) runs script verification against
`STANDARD_SCRIPT_VERIFY_FLAGS`, which is `MANDATORY_SCRIPT_VERIFY_FLAGS`
plus 14 additional STANDARD bits. After PolicyScriptChecks succeeds,
`ConsensusScriptChecks` re-runs with `MANDATORY_SCRIPT_VERIFY_FLAGS` as
a belt-and-suspenders fallback. The split is the entire point of the
two-pass design: txs that fail STANDARD but pass MANDATORY are
non-relayable but still consensus-valid; rejecting at PolicyScriptChecks
prevents propagation of consensus-valid-but-policy-breaking txs.

haskoin's `verifyAllScripts` (`Mempool.hs:1237-1262`) calls:

```haskell
let cflags = consensusFlagsAtHeight (mpNetwork mp) (height + 1)
    scriptFlags = consensusFlagsToScriptFlags cflags
```

`consensusFlagsToScriptFlags` (`Consensus.hs:1511-1520`) emits exactly
the MANDATORY set:

```haskell
consensusFlagsToScriptFlags cf = flagSet $ concat
  [ [VerifyP2SH]
  , [VerifyDERSig | flagBIP66 cf]
  , [VerifyCheckLockTimeVerify | flagBIP65 cf]
  , [VerifyCheckSequenceVerify | flagSegWit cf]
  , [VerifyWitness | flagSegWit cf]
  , [VerifyNullDummy | flagNullDummy cf]
  , [VerifyTaproot | flagTaproot cf]
  ]
```

The comment block at `Consensus.hs:1481-1497` literally documents the
gap:

> Only MANDATORY_SCRIPT_VERIFY_FLAGS are represented here (Bitcoin Core
> policy/policy.h:105-111): P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS,
> TAPROOT. Policy-only flags (NULLFAIL, LOW_S, CLEANSTACK, etc.) must
> NOT appear in the block-connect script-verify flag computer.
>
> NULLFAIL (BIP-146) is intentionally excluded: it is a
> STANDARD_SCRIPT_VERIFY_FLAG (policy only) per Core policy/policy.h:125.

That comment is correct for `ConnectBlock` script-verification (NULLFAIL
is policy-only in CORE's CONSENSUS path). But the same helper is reused
at `Mempool.hs:1251, 1112, 2578` for mempool admission, where Core uses
STANDARD_SCRIPT_VERIFY_FLAGS. The helper has TWO callers with different
intended semantics, but emits only the union-of-MANDATORY for both.

The `ScriptVerifyFlag` enum at `Script.hs:265-287` defines all 21
constructors, including the 14 STANDARD ones:

- `VerifyNullFail` (line 272)
- `VerifyWitnessPubkeyType` (line 273)
- `VerifyMinimalData` (line 275)
- `VerifyMinimalIf` (line 276)
- `VerifyDiscourageUpgradableWitnessProgram` (line 277)
- `VerifyDiscourageUpgradableNops` (line 278)
- `VerifyDiscourageOpSuccess` (line 279)
- `VerifyDiscourageUpgradableTaprootVersion` (line 280)
- `VerifyDiscourageUpgradablePubkeyType` (line 281)
- `VerifyConstScriptcode` (line 282)
- `VerifyStrictEncoding` (line 283)
- `VerifyLowS` (line 284)
- `VerifySigPushOnly` (line 285)
- `VerifyCleanStack` (line 286)

All 14 are defined (and consulted inside `Script.hs` evaluator),
but NONE are ever emitted by any production helper — confirmed by
`grep` showing zero occurrences of `VerifyNullFail`,
`VerifyWitnessPubkeyType`, `VerifyMinimalData`, `VerifyCleanStack`,
`VerifySigPushOnly`, `VerifyLowS`, `VerifyConstScriptcode`,
`VerifyStrictEncoding`, `VerifyDiscourage*` outside the enum
declaration in `Consensus.hs` or `Mempool.hs`. This is the
"dead-data enum members" / "defined-and-consulted-but-never-emitted"
fleet pattern (W144 reported 10 of 21 such; haskoin has 14 of 21).

**File:** `src/Haskoin/Mempool.hs:1237-1262, 1108-1116, 2566-2589`;
`src/Haskoin/Consensus.hs:1511-1520`; `src/Haskoin/Script.hs:265-287`.

**Core ref:** `bitcoin-core/src/script/interpreter.h:147-220`
(STANDARD_SCRIPT_VERIFY_FLAGS definition);
`bitcoin-core/src/validation.cpp:1234-1280` (PolicyScriptChecks).

**Impact (consensus + relay):**

- haskoin accepts and relays txs that Core rejects as nonstandard
  (high-S signatures, MINIMALDATA violations, CLEANSTACK leftovers,
  bare OP_NOP4-9 / future-soft-fork usage, unknown witness versions
  beyond v0 in WITNESS mode, CHECKMULTISIG with non-empty failed-sig,
  P2WPKH with uncompressed pubkey). These txs propagate from haskoin
  into a peer mempool sliver and never reach Core nodes.
- Soft-fork preparation: when a future BIP activates one of the
  STANDARD bits as MANDATORY at a height H, haskoin nodes near H
  will be ACCEPTING txs that violate the new MANDATORY bit; when those
  txs are mined into a block, haskoin's CONSENSUS path
  (`Consensus.hs:1511` is shared) ALSO doesn't enforce the bit, and
  haskoin permanently forks off.
- Diff-test corpus: any vector that depends on a STANDARD bit being
  enforced at the mempool side will silently PASS through haskoin
  and FAIL only at the block-connect side when another impl mines
  the consensus-valid-but-nonstandard tx.

---

## BUG-2 (P0-CDIV) — `-acceptnonstdtxn` operator-knob entirely absent

**Severity:** P0-CDIV. Bitcoin Core's `-acceptnonstdtxn` (boolean,
default `false` for mainnet, default `true` for regtest) controls the
`m_require_standard` flag inside `MemPoolAccept::ATMPArgs`. When
disabled, ALL standardness gates (IsStandardTx, IsWitnessStandard,
ValidateInputsStandardness, PolicyScriptChecks's extra flags) are
skipped — the mempool admits only on consensus rules. This is the
canonical operator escape hatch for:

- Regtest test scenarios that need to mine consensus-valid-but-nonstandard
  txs to exercise edge cases (Core's regtest test suite relies on this).
- Mining pools that want to include high-fee nonstandard txs.
- Security audits that want to admit a known-bad tx to test downstream
  behaviour.

haskoin's `parseNodeOptions` (`app/Main.hs:227-332`) defines 26 CLI
flags. **None** correspond to `-acceptnonstdtxn`. The
`config.example.toml` `[mempool]` section is empty besides the
comment "Uses Bitcoin Core defaults internally". A `grep -rn
"acceptnonstdtxn\|requireStandard\|fRequireStandard"` over `src/` and
`app/` returns ONE match — a comment in `Mempool.hs:3731` saying
"@require_standard@ is set" referring to Core's variable.
`checkStandardTx` is invoked unconditionally at `Mempool.hs:699, 1162,
2458`; there is no callsite-gating boolean.

**Net effect on regtest:** every haskoin regtest mempool admits ONLY
standard txs. Tests that need to mine, e.g., a bare-OP_RETURN larger
than MAX_OP_RETURN_RELAY, a CLEANSTACK-violating but consensus-valid
witness, a CHECKMULTISIG with high-S signatures, etc., **cannot be
written**. This is a hard regtest interop break with the broader
hashhog test suite.

**File:** `app/Main.hs:227-332` (CLI definition has no policy knob);
`src/Haskoin/Mempool.hs:699, 1162, 2458` (`checkStandardTx`
unconditionally called); `src/Haskoin/Policy/Standard.hs:386-438`
(checkStandardTx implementation).

**Core ref:** `bitcoin-core/src/init.cpp` (`-acceptnonstdtxn`),
`bitcoin-core/src/validation.cpp::MemPoolAccept::ATMPArgs::m_require_standard`,
`bitcoin-core/src/validation.cpp::PreChecks` (gate at line 897-901
behind `m_require_standard`).

**Impact:**
- Regtest standardness cannot be disabled; entire classes of
  consensus-edge-case tests are inexpressible.
- Diff-test corpus entries that compare "policy-only reject" vs
  "consensus-valid accept" cannot be run through haskoin without
  patching the source.
- Operator-knob parity with Core's `-acceptnonstdtxn` is a long-standing
  hashhog cross-impl expectation; haskoin is the first audited impl
  in this quad that lacks it entirely.

---

## BUG-3 (P1, cluster of 9) — Every mempool/policy parameter is hard-coded; no CLI override path exists

**Severity:** P1 (cluster). The following 9 Bitcoin Core operator-knobs
are hard-coded constants in haskoin and have no CLI / config path:

| # | Core flag | Core default | Haskoin location | Haskoin value |
|---|-----------|-------------|-------------------|----------------|
| 1 | `-minrelaytxfee` | 1000 sat/kvB | `Mempool.hs:264` | `FeeRate 1` (sat/vB; ≈ 1000 sat/kvB) |
| 2 | `-incrementalrelayfee` | 1000 sat/kvB | `Mempool.hs:382` | `100` sat/kvB **(10× LOW vs Core)** |
| 3 | `-datacarrier` | true | `Policy/Standard.hs:484` (`permitBareMultisig` arg) | hard-coded `True` at `Mempool.hs:699` (`checkStandardTx = checkStandardTxWith True`) |
| 4 | `-datacarriersize` | 83 | `Policy/Standard.hs:112` | `100_000` **(1200× HIGH vs Core)** |
| 5 | `-permitbaremultisig` | true | `Policy/Standard.hs:387` | hard-coded `True` via default `checkStandardTx` |
| 6 | `-maxmempool` | 300 MB | `Mempool.hs:263` | `300 * 1024 * 1024` |
| 7 | `-mempoolexpiry` | 336 h | `Mempool.hs:271` and `Main.hs:902` | duplicated (`mpcExpiryHours=336`; `mempoolExpirySecs = 14 * 24 * 3600`) |
| 8 | `-mempoolfullrbf` | true (post-28.0) | `Mempool.hs:266` | hard-coded `True` |
| 9 | `-bytespersigop` | 20 | `Policy/Standard.hs:164` | `20` |
| 10 | `-dustrelayfee` | 3000 sat/kvB | `Policy/Standard.hs:117` | `3000` |

The most-egregious item is `-incrementalrelayfee = 100` vs Core's
`1000`. From `Mempool.hs:381-382`:

```haskell
-- Bitcoin Core: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48).
-- Note: CFeeRate(100) means 100 sat per 1000 bytes = 0.1 sat/vB.
incrementalRelayFeePerKvb :: Word64
incrementalRelayFeePerKvb = 100
```

The comment claims Core uses `100`. **Core actually uses `1000`** —
`policy/policy.h:48` defines `DEFAULT_INCREMENTAL_RELAY_FEE = 1000`
(`static constexpr unsigned int DEFAULT_INCREMENTAL_RELAY_FEE = 1000;`).
The `CFeeRate(1000)` constructor in Core's CFeeRate model means
1000 sat per 1000 bytes = 1 sat/vB. **haskoin is 10× below Core's
floor**, which means RBF replacements that pay an extra 0.1 sat/vB
relative to the original are accepted as bumping enough, where Core
requires 1.0 sat/vB extra. This makes haskoin a fee-bumping easy mark
in cross-mempool propagation: a pinning-attack replacement that's
free-relayable on haskoin but rejected by Core can occupy the haskoin
mempool slot and never propagate to Core.

The `-datacarriersize` discrepancy is even larger: Core ships at
`MAX_OP_RETURN_RELAY = 83` (after the 0.21+ change). haskoin uses
`MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR =
100000` (line 113), which is the BIP-141 maximum, NOT Core's policy
default. haskoin accepts OP_RETURN outputs 1200× larger than Core's
mempool will.

The `-mempoolexpiry` duplication is a separate bug: `mpcExpiryHours =
336` in `Mempool.hs:271` is the canonical source, but `Main.hs:902`
hard-codes `mempoolExpirySecs = 14 * 24 * 3600` independently. If one
is changed (e.g., to 168 h for a debug build) the other won't update.

**File:** `src/Haskoin/Mempool.hs:261-273, 381-382`;
`src/Haskoin/Policy/Standard.hs:84-165`; `app/Main.hs:227-332, 902`;
`config.example.toml`.

**Core ref:** `bitcoin-core/src/policy/policy.h` (defaults);
`bitcoin-core/src/init.cpp` (CLI registration).

**Impact:**
- `-incrementalrelayfee = 100` (10× below Core): mempool pinning
  attack vector that doesn't propagate to Core peers.
- `-datacarriersize = 100000` (1200× above Core): haskoin accepts
  massive OP_RETURN outputs that Core won't relay.
- No `-maxmempool` knob: operators cannot reduce mempool memory on
  resource-constrained nodes.
- No `-mempoolexpiry` knob: cannot shorten the 14-day window for
  faster eviction.
- Cross-impl test fragility: the hashhog cross-mempool fuzzer
  cannot vary these parameters per node.

---

## BUG-4 (P0-CDIV) — Coinbase-maturity check is off by one (uses `tip` instead of `tip+1`)

**Severity:** P0-CDIV. Bitcoin Core's `CheckTxInputs`
(`consensus/tx_verify.cpp:35-47`) checks coinbase maturity using
`nSpendHeight`, which inside MemPoolAccept is set to
`m_active_chainstate.m_chain.Height() + 1` (the next-block height,
since the mempool is what gets mined into block H+1):

```cpp
if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
    return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND,
                         "bad-txns-premature-spend-of-coinbase");
}
```

haskoin's `resolveInput` (`Mempool.hs:1198-1208`) and
`resolveInputsForReplacement` (`Mempool.hs:830-833`) and the package
path (`Mempool.hs:2398-2400`) all use:

```haskell
height <- readTVarIO (mpHeight mp)
if ueCoinbase entry && height - ueHeight entry < fromIntegral coinbaseMaturity
  then return $ Left (ErrCoinbaseNotMature (ueHeight entry) height)
  else ...
```

Where `mpHeight` is the **current tip height** (per the doc at line
565-566), not `tip+1`. So when:
- tip = 100, coinbase at height 1 → haskoin: `100 - 1 = 99 < 100` →
  **NOT MATURE (REJECT)**.
- Core (mining into block 101): `101 - 1 = 100`, NOT < 100 → **MATURE
  (ACCEPT)**.

haskoin rejects a tx that Core accepts at the same chain state. This
is a chain-split risk: if haskoin's mempool rejects a coinbase-spending
tx that Core mines into the next block, the haskoin reorg / relay
behaviour diverges. More immediately, in a regtest scenario where you
mine 100 blocks then submit a tx that spends the coinbase at block 1,
Core accepts it (next block is 101, 101-1=100), haskoin rejects it
("bad-txns-premature-spend-of-coinbase"). Cross-impl test failures.

The same off-by-one exists in the BIP-68 sequence-lock path
(`Mempool.hs:1888-1894` comment refers to "tipHeight+1" but the
implementation uses `mpHeight` directly), and in the IsFinalTx path
(`Mempool.hs:709-710`: `let nextHeight = height + 1`; this one IS
correct — but only because it explicitly +1's). The fact that one
gate +1's and the other doesn't is itself a bug.

**File:** `src/Haskoin/Mempool.hs:832, 1206, 2399`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:35-47`
(`CheckTxInputs` coinbase-maturity using `nSpendHeight`);
`bitcoin-core/src/validation.cpp::MemPoolAccept::PreChecks` (calls
`CheckTxInputs` with `nSpendHeight = active.m_chain.Height() + 1`).

**Impact:**
- Cross-impl divergence: at the boundary block, haskoin rejects what
  Core accepts.
- Regtest: any test that mines `COINBASE_MATURITY` blocks then
  immediately spends the first coinbase fails on haskoin.
- Wallet ergonomics: payments funded from a coinbase wait one extra
  block-time on haskoin.

---

## BUG-5 (P0-SEC) — Word32 underflow in coinbase-maturity check ALWAYS reports MATURE

**Severity:** P0-SEC. Building on BUG-4: the check `height - ueHeight
entry < 100` is performed on `Word32` operands (`mpHeight :: TVar
Word32`, `ueHeight :: Word32`). When `ueHeight > height` — which
happens during:

1. **Cold-start before any block connects** (mempool initialised with
   `mpHeight=0` per BUG-6; any persisted coinbase UTXO has
   `ueHeight > 0`).
2. **Reorg-readmit window** between `blockDisconnected` (which
   decrements `mpHeight`) and `blockConnected` of the new tip.
3. **Concurrent block-connect races** (atomically increments by 1 but
   not synchronised with mempool readers).

The unsigned subtraction wraps to `4_294_967_296 - (ueHeight -
height)`, which is approximately `2^32`. `2^32 < 100` is FALSE,
therefore the coinbase appears MATURE, **the gate inverts**, and a
just-mined coinbase output can be spent immediately.

Combined with BUG-6 (mpHeight=0 at startup): every coinbase UTXO from
the loaded chain has `ueHeight > 0` at mempool-load time, the
subtraction wraps, and every coinbase-spending tx from mempool.dat is
admitted regardless of maturity. This is an immediate-spend bypass at
node restart.

**File:** `src/Haskoin/Mempool.hs:832, 1206, 2399`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:35-47` (Core
uses `int` for `nSpendHeight - coin.nHeight`, so the underflow path
yields a negative number which is correctly < 100 — but that would
also REJECT correctly, just for a wrong reason; Core never has the
underflow because `nSpendHeight` and `coin.nHeight` are both `int`).

**Impact:**
- Restart-time mempool admission bypasses coinbase maturity. If
  mempool.dat contains a tx that spends a coinbase only 50 blocks
  old, that tx is admitted at restart (mpHeight=0, ueHeight=51,
  underflow → MATURE).
- Reorg-window race: a tx spending a coinbase 99 blocks deep that
  arrives between the disconnect and connect of a 1-block reorg
  is briefly admittable.
- The "tip" of the haskoin mempool is not safe to consume
  coinbase-output information without an explicit `ueHeight <=
  height` guard.

---

## BUG-6 (P0-CDIV) — `mpHeight` initialised to `0` regardless of loaded chain tip; never reset by code path

**Severity:** P0-CDIV. `newMempool` at `Mempool.hs:626-647`
unconditionally constructs `mpHeight = TVar 0`:

```haskell
newMempool :: Network -> UTXOCache -> MempoolConfig -> Word32 -> Word32
           -> (Word32 -> IO Word32) -> IO Mempool
newMempool net cache config height mtp getCoinMtp = do
  ...
    <*> newTVarIO height
    <*> newTVarIO mtp
    ...
```

The interface takes a `height` parameter, but at the single callsite
in `app/Main.hs:897`:

```haskell
mp <- newMempool net cache defaultMempoolConfig 0 0 getCoinMtpFromChain
```

The caller passes literal `0, 0`. The actual chain tip height (loaded
earlier in `Main.hs` from RocksDB best-block) is NOT plumbed through.
A grep over `src/` and `app/` for `writeTVar (mpHeight` and `writeTVar
mpHeight` returns ZERO matches — the variable is NEVER written
directly; only `modifyTVar' (mpHeight mp) (+1)` in `blockConnected`
(line 1858) and `modifyTVar' (mpHeight mp) (subtract 1)` in
`blockDisconnected` (line 1875).

**Consequences:**

1. On a node restart loading a chain at tip height H (e.g., mainnet
   870k), `mpHeight` stays at `0` until H new blocks arrive — which
   never happens, because the node syncs to the network tip via
   `connectBlock` calls that DO fire `blockConnected` and increment
   `mpHeight`. But the increments don't catch up — only NEW blocks
   incoming after restart bump `mpHeight`. So a node restarted at H=870k
   that runs for 6 blocks ends up with `mpHeight = 6`, not 870006.

2. **The `loadMempool` call at `Main.hs:904` runs BEFORE any
   `blockConnected`** (it happens at startup, with the node at tip but
   not yet receiving new blocks). Every tx in `mempool.dat` is admitted
   with `mpHeight = 0`, `mpMTP = 0`. This means:
   - Coinbase-maturity (BUG-5) Word32-underflows → all admitted.
   - IsFinalTx: `nextHeight = 1`, MTP=0 → txs with locktime in {1..H}
     are wrongly rejected as non-final (or accepted if locktime > H).
   - BIP-68 sequence-locks: `mpGetCoinMtp coinH` uses real chain
     lookup at line 890-895, but the per-input height vs `mpHeight`
     comparison breaks down.
   - `consensusFlagsAtHeight (mpNetwork mp) (mpHeight + 1)` at
     `Mempool.hs:1112, 1250, 2515, 2606` computes at height=1, which
     for mainnet means: BIP-34 inactive (227,931), BIP-66 inactive
     (363,725), BIP-65 inactive (388,381), SegWit inactive (481,824),
     Taproot inactive (709,632). **Scripts are verified WITHOUT
     SegWit, Taproot, NULLDUMMY, BIP-65, BIP-66**. This is also a
     security gap — even though mempool.dat usually doesn't contain
     pre-segwit txs, a malicious mempool.dat could.

3. The first `blockConnected` after startup bumps `mpHeight` from 0 to
   1, not from H to H+1. So even after blocks tick in, `mpHeight` is
   always wrong by `H - (blocks since restart)`. Every gate that uses
   `mpHeight` is misconfigured for the lifetime of the process.

**The inline comment at `Main.hs:889` does not flag this:**

```haskell
let getCoinMtpFromChain coinH = do
      entries  <- readTVarIO (hcEntries hc)
      ...
mp <- newMempool net cache defaultMempoolConfig 0 0 getCoinMtpFromChain
```

The author plumbed a coin-MTP lookup function (which IS chain-aware)
but forgot to plumb `tip`/`MTP` into the mempool init itself. This is
the **"plumb-the-callback-but-not-the-state"** flavour of dead-data
plumbing (W141 reported this pattern as "plumb-gate-then-flip 2× in
same wave").

**File:** `src/Haskoin/Mempool.hs:626-647` (`newMempool` accepts
height param);
`app/Main.hs:897` (caller passes literal `0 0`);
`src/Haskoin/Mempool.hs:1858, 1875` (only writers; both
incremental).

**Core ref:** `bitcoin-core/src/txmempool.cpp::CTxMemPool` initialised
from `ChainstateManager::m_active_chainstate.m_chain.Height()`;
`bitcoin-core/src/init.cpp::AppInitMain` mempool construction sequence
in the post-LoadChainstate phase.

**Impact:**
- `loadMempool` on restart admits txs against fake-zero chain state,
  bypassing coinbase maturity (Word32 underflow, BUG-5), nLockTime,
  BIP-113, BIP-68, and uses pre-segwit script flags for verification.
- `consensusFlagsToScriptFlags` at the wrong height verifies scripts
  WITHOUT WITNESS, TAPROOT, NULLDUMMY, BIP-65, BIP-66 for the
  lifetime of the process.
- Restart-time mempool replay is wholesale-wrong vs Core.
- The numeric `mpHeight` drift is permanent: increments only, never
  reset to actual tip, so `getmempoolinfo`'s implicit-height
  reporting and BIP-113 MTP-based admit are skewed.

---

## BUG-7 (P1) — `validateTransaction` reject tokens diverge from Core's BIP-22 wire-strings (6 cases)

**Severity:** P1. Bitcoin Core's
`consensus/tx_check.cpp::CheckTransaction` returns short BIP-22
"strRejectReason" tokens used in `getblocktemplate`'s reject array
and in NAK strings (where applicable). The tokens are stable across
versions and used by miners / monitoring / cross-impl tests.

haskoin's `validateTransaction` at `Consensus.hs:1368-1438` uses
free-form English strings for 6 of the 7 reject conditions, and
matches Core's token for only ONE (`bad-txns-inputs-duplicate`):

| Condition | Core token | Haskoin string |
|-----------|-----------|----------------|
| `vin.empty()` | `bad-txns-vin-empty` | `Transaction has no inputs` |
| `vout.empty()` | `bad-txns-vout-empty` | `Transaction has no outputs` |
| weight > MAX_BLOCK_WEIGHT | `bad-txns-oversize` | `bad-txns-oversize` PASS |
| `out.nValue < 0` | `bad-txns-vout-negative` | `Transaction output has negative value` |
| `out.nValue > MAX_MONEY` | `bad-txns-vout-toolarge` | `Transaction output value exceeds MAX_MONEY` |
| `nValueOut > MAX_MONEY` (acc) | `bad-txns-txouttotal-toolarge` | `bad-txns-txouttotal-toolarge` PASS |
| duplicate inputs | `bad-txns-inputs-duplicate` | `bad-txns-inputs-duplicate` PASS |
| coinbase scriptSig size | `bad-cb-length` | `Coinbase scriptSig size out of range (must be 2-100 bytes)` |
| non-coinbase null prevout | `bad-txns-prevout-null` | `Non-coinbase transaction references null prevout` |

5 mismatches out of 9 = wire-string slippage. The downstream
`mempoolErrorToText` at `Rpc.hs:5480-5508` further translates haskoin's
internal `ErrValidationFailed _` to just `"bad-txns"` for ALL such
failures — collapsing six distinct conditions into one opaque token.
Cross-impl monitoring tooling that parses reject reasons cannot
distinguish them.

This is the same shape as lunarblock W125 "reject-string wire-parity
slippage" (9-token sweep) — **first haskoin instance of this fleet
pattern** in W76+ tracking.

**File:** `src/Haskoin/Consensus.hs:1368-1438`;
`src/Haskoin/Rpc.hs:5480-5508` (collapsing helper).

**Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:CheckTransaction`.

**Impact:**
- BIP-22 `getblocktemplate.reject` array on haskoin emits non-Core
  tokens.
- `testmempoolaccept` and `sendrawtransaction` returned error strings
  break cross-impl test assertions that match on Core's wire tokens.
- Monitoring dashboards that aggregate reject-reason histograms can't
  share a column schema across haskoin + Core.

---

## BUG-8 (P0-SEC) — `mempoolErrorToText` is non-exhaustive over `MempoolError`; runtime crash on 7 constructors

**Severity:** P0-SEC. `Rpc.hs:5480-5508`:

```haskell
mempoolErrorToText :: MempoolError -> Text
mempoolErrorToText err = case err of
  ErrAlreadyInMempool -> "txn-already-in-mempool"
  ErrSameNonwitnessInMempool -> "txn-same-nonwitness-data-in-mempool"
  ErrValidationFailed _ -> "bad-txns"
  ErrMissingInput _ -> "missing-inputs"
  ErrInputSpentInMempool _ -> "txn-mempool-conflict"
  ErrInsufficientFee -> "min-fee-not-met"
  ErrFeeBelowMinimum _ _ -> "min-fee-not-met"
  ErrTooManyAncestors _ _ -> "too-long-mempool-chain"
  ErrTooManyDescendants _ _ -> "too-long-mempool-chain"
  ErrAncestorSizeTooLarge _ _ -> "too-long-mempool-chain"
  ErrDescendantSizeTooLarge _ _ -> "too-long-mempool-chain"
  ErrScriptVerificationFailed _ -> "bad-txns"
  ErrCoinbaseNotMature _ _ -> "bad-txns-premature-spend-of-coinbase"
  ErrRBFNotSignaled _ -> "txn-mempool-conflict"
  ErrRBFFeeTooLow _ _ -> "insufficient-fee"
  ErrMempoolFull -> "mempool-full"
  ErrRBFInsufficientAbsoluteFee _ _ -> "insufficient-fee"
  ErrRBFInsufficientFeeRate _ _ -> "insufficient-fee"
  ErrRBFTooManyReplacements _ _ -> "too-many-potential-replacements"
  ErrRBFInsufficientRelayFee _ _ -> "insufficient-fee"
  ErrRBFSpendingConflict _ -> "txn-mempool-conflict"
  ErrRBFNewUnconfirmedInput _ -> "replacement-adds-unconfirmed"
  ErrTrucViolation _ -> "non-standard"
  ErrEphemeralViolation _ -> "dust"
  ErrClusterLimitExceeded _ _ -> "too-long-mempool-chain"
```

The `MempoolError` ADT at `Mempool.hs:306-362` defines 32
constructors. The `mempoolErrorToText` case matches 25 of them. **7
constructors are missing**:

- `ErrCoinbaseNotAllowed` (line 314)
- `ErrMaxFeeRateExceeded` (line 318)
- `ErrSpendsConflictingTx` (line 322)
- `ErrInputsNotStandard` (line 326)
- `ErrNonStandard` (line 358)
- `ErrNonFinal` (line 360)
- `ErrSeqLockNotSatisfied` (line 361)

There is no catch-all `_ -> "unknown"` branch. In GHC, a non-exhaustive
case is a compile-time warning (`-Wincomplete-patterns`); at runtime
it raises `Control.Exception.PatternMatchFail` ("Non-exhaustive
patterns in case"). For an asynchronous IO handler like
`handleTestMempoolAccept`, the exception propagates to the warp / HTTP
handler thread, **crashes the request**, and (depending on the warp
exception handler) may produce no JSON response, only a TCP RST or a
500 with no body.

Affected RPC paths:
- `testmempoolaccept` (line 5403) calls `testAcceptTransaction`,
  which can return any of the 7 missing constructors (e.g.,
  `ErrCoinbaseNotAllowed` from line 1160; `ErrNonStandard` from
  lines 1163, 1101, 1105, 1115; `ErrNonFinal` from line 1169;
  `ErrInputsNotStandard` from line 1096).
- `sendrawtransaction` (line 2219) uses `mempoolErrorToRpcResponse`
  (line 2296) which has a SEPARATE pattern match — but let me verify
  if that one is exhaustive (it ALSO uses `case err of`, so same
  risk). Confirmed: `mempoolErrorToRpcResponse` at line 2296-2360+
  has a partial match too (separate audit).

The path is reachable via any caller submitting:
- A coinbase tx → `ErrCoinbaseNotAllowed` → **CRASH**
- A non-standard scriptSig → `ErrInputsNotStandard` → **CRASH**
- A non-standard scriptPubKey → `ErrNonStandard` → **CRASH**
- A future locktime → `ErrNonFinal` → **CRASH**
- A BIP-68 violation → `ErrSeqLockNotSatisfied` → **CRASH**

A network adversary that wants to crash haskoin's mempool RPC threads
can simply submit a stream of locktime-future txs to
`testmempoolaccept` and trigger the pattern-match crash on every
request.

**File:** `src/Haskoin/Rpc.hs:5480-5508` (non-exhaustive);
`src/Haskoin/Mempool.hs:306-362` (full 32-constructor ADT).

**Core ref:** N/A (Haskell-specific; Core has exhaustive switch).

**Impact:**
- DoS vector via RPC: submit any locktime-future, coinbase-shaped,
  non-standard-output, or non-standard-input tx to
  `testmempoolaccept` → RPC thread crashes.
- The compiled binary's behaviour depends on GHC version and
  `-Wincomplete-patterns` setting — if compile-warnings-as-errors
  is not active, this builds silently.
- Cross-cite to BUG-3 (no `-acceptnonstdtxn`): operators with regtest
  configs that submit nonstandard txs in test scenarios will hit
  these crashes consistently.

---

## BUG-9 (P1) — `meRBFOptIn` derivation has two production pipelines with semantically-equivalent-but-different comparators

**Severity:** P1. Two pipelines compute `meRBFOptIn` independently:

**Pipeline 1** — `signalsOptInRBF` at `Mempool.hs:397-398`:

```haskell
signalsOptInRBF :: Tx -> Bool
signalsOptInRBF tx = any (\inp -> txInSequence inp <= 0xfffffffd) (txInputs tx)
```

Used by `buildMempoolEntry` at line 984:
```haskell
let rbfOptIn = signalsOptInRBF tx
```

**Pipeline 2** — inline at `addTransactionToMempool` at `Mempool.hs:2601`:

```haskell
let rbfOptIn = any (\inp -> txInSequence inp < 0xfffffffe) (txInputs tx)
```

`<= 0xfffffffd` and `< 0xfffffffe` are semantically equivalent for
`Word32`. But maintaining the two helpers separately means:
- A future BIP that changes the RBF threshold needs two patches.
- One author can update one and not the other.
- Code review can't easily diff "RBF signalling" against a single
  source of truth.

This is the **two-pipeline guard** pattern — **17th distinct
extension across the fleet**. haskoin's previous instances reported
in W148 etc.; this is the first time the BIP-125 signalling primitive
itself is duplicated.

Two paths exist because `finalizeTransaction` uses `buildMempoolEntry`
(single-tx path), while `addPackageTransactions` uses
`addTransactionToMempool` (package path). The package path was added
later and inlined the check instead of calling `signalsOptInRBF`.

**File:** `src/Haskoin/Mempool.hs:397-398, 984, 2601`.

**Core ref:** `bitcoin-core/src/util/rbf.cpp::SignalsOptInRBF` is the
single source of truth in Core.

**Impact:**
- Maintenance / drift risk only — no current observable divergence.
- Lists for completeness in the two-pipeline guard tracker.

---

## BUG-10 (P0-CDIV) — `prioritisetransaction` RPC absent; `mpFeeDeltas` is plumbed but has no in-band writer

**Severity:** P0-CDIV. Bitcoin Core's `prioritisetransaction` RPC
(`rpc/mempool.cpp::prioritisetransaction`) lets the operator add a
"fee delta" to a specific txid, used by:
- `MemPoolAccept::PreChecks` (min-relay-fee gate uses modified fee).
- Mining template selection (`BlockAssembler` orders by modified fee).
- Cluster mempool ordering and eviction.
- `getmempoolentry.modifiedfee` reporting.

The delta persists in `mempool.dat` so it survives restart.

haskoin has:
- `mpFeeDeltas :: TVar (Map TxId Int64)` declared at `Mempool.hs:574-576`
  with comment "Prioritisetransaction fee deltas (in satoshis);
  persisted in mempool.dat alongside transactions."
- `finalizeTransaction` reads `mpFeeDeltas` at `Mempool.hs:859-868` and
  applies the delta to compute `modifiedFee`.
- `finalizeTransactionDry` reads at line 1078-1085 (same logic).
- `Mempool/Persist.hs:278` writes to mempool.dat.
- `Mempool/Persist.hs:369` restores on load.

**But there is NO RPC writer.** A grep over `Rpc.hs` shows zero
matches for `prioritisetransaction`, `prioritise`, or `prioritize`.
The RPC dispatch table at `Rpc.hs:1024-1100+` enumerates ~150 method
names; `prioritisetransaction` is absent (silently returns
"Method not found").

The operator therefore has no in-band way to:
- Bump a low-fee tx out of an eviction window.
- Lower the effective fee of a high-fee tx for testing.
- Synchronise priorities across cluster mempool churn.

This is the **wiring-look-but-no-wire** fleet pattern (W138-class):
the storage, the persistence, the persistence load-back, and the
consumer are all in place — the only missing link is the producer
RPC. Operator tooling that ports `bitcoin-cli prioritisetransaction
<txid> 0 100000` from a Core deployment to haskoin sees the call
silently fail.

**File:** `src/Haskoin/Mempool.hs:574-576, 859-868, 1078-1085`;
`src/Haskoin/Mempool/Persist.hs:278, 369`;
`src/Haskoin/Rpc.hs:1024-1100+` (dispatch table — `prioritisetransaction`
absent).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::prioritisetransaction`.

**Impact:**
- Operators porting Core deployments lose the prioritise primitive
  with no error indication beyond a generic "method not found".
- The delta persistence is fully wired but useless — pure dead-data
  plumbing on the producer side.
- Mining-pool / wallet-fee-bumping workflows that depend on
  prioritise are broken.

---

## BUG-11 (P1, cluster of 5) — `getmempoolinfo` / `getmempoolentry` RPC wire-parity holes

**Severity:** P1 (cluster). Five Bitcoin Core wire-format expectations
are broken in haskoin's mempool RPC output:

**B11.1: `minrelaytxfee` / `incrementalrelayfee` hard-coded to `1000`,
not derived from config**

`Rpc.hs:2449-2450`:

```haskell
pair "minrelaytxfee"       (btcAmountEnc 1000)                        <>
pair "incrementalrelayfee" (btcAmountEnc 1000)                        <>
```

These are literal `1000`s. `mpcMinFeeRate` is `FeeRate 1` (= 1 sat/vB
= 1000 sat/kvB) which BY COINCIDENCE matches the displayed `1000`.
`incrementalRelayFeePerKvb` is `100` (BUG-3 — 10× LOW), and the
emitted `1000` does not reflect that either. So both fields lie about
what the mempool actually enforces.

**B11.2: `mempoolminfee` uses static config, ignores rolling minimum**

`Rpc.hs:2448`:

```haskell
pair "mempoolminfee"       (btcAmountEnc (fromIntegral minFeeRateSatPerVb * 1000)) <>
```

Where `minFeeRateSatPerVb = getFeeRate (mpcMinFeeRate mpCfg)` (the
static config), NOT the live rolling minimum fee. Core's
`getmempoolinfo.mempoolminfee` returns
`max(rollingMinimumFeeRate, minRelayFeeRate)` — see
`CTxMemPool::GetMinFee` (`txmempool.cpp:829-851`).

`getMempoolMinFeeRate` at `Mempool.hs:1467-1472` correctly implements
the max(rolling, static), is exported from the module, but is **never
called by any RPC**. Confirmed via grep — zero callers in `Rpc.hs`.

This is **dead-function-export** (W141 pattern); the primitive is
correct and reachable, but the producer never wires it.

**B11.3: `fullrbf` hard-coded `True`**

`Rpc.hs:2452`:

```haskell
pair "fullrbf"             (AE.bool True)
```

Should reflect `mpcRBFEnabled` from config. Currently always reports
`True` regardless of how the mempool was constructed.

**B11.4: `getmempoolentry.modifiedfee` hard-coded to base fee**

`Rpc.hs:5791`:

```haskell
pair "modifiedfee"        (btcAmountEnc feeSat)                             <>
```

Where `feeSat = fromIntegral (meFee entry)`. Should be `meFee +
prioritisationDelta` per Core. Without `prioritisetransaction` (BUG-10)
there are no deltas to add today, but the field will continue to lie
even after BUG-10 is fixed.

**B11.5: `getmempoolentry.spentby` always empty**

`Rpc.hs:5803`:

```haskell
pair "spentby"            (AE.list text [])                                 <>
```

Should be the list of mempool txids that spend this tx's outputs.
`getDescendants` at `Mempool.hs:1521` is the right helper. The field
is type-correct but semantically empty.

**B11.6: `descendantfees` / `ancestorfees` emit as raw integer, not BTC fractional**

`Rpc.hs:5796, 5799`:

```haskell
pair "descendantfees"     (AE.word64 (fromIntegral descendantFees))         <>
pair "ancestorfees"       (AE.word64 (fromIntegral ancestorFees))           <>
```

These emit as JSON integers (satoshis). Core emits these via
`FormatMoney` as BTC-fractional decimals (e.g., `0.00001000`). The
sibling fields `feesEnc.base`, `feesEnc.modified`, `feesEnc.ancestor`,
`feesEnc.descendant` at line 5782-5786 DO use `btcAmountEnc`, so the
SAME data is emitted twice in two different formats. Downstream
tooling depending on the BTC format breaks on the raw-integer field.

**File:** `src/Haskoin/Rpc.hs:2440-2453` (getmempoolinfo),
`src/Haskoin/Rpc.hs:5743-5806` (getmempoolentry).

**Core ref:** `bitcoin-core/src/rpc/mempool.cpp::getmempoolinfo`,
`bitcoin-core/src/rpc/mempool.cpp::entryToJSON`.

**Impact:**
- Monitoring tooling that scrapes `mempoolminfee` to compute fee
  estimation sees the static floor, not the live decay value.
- Wallets that use `getmempoolentry.modifiedfee` for bump-fee
  calculations see the wrong number.
- `spentby` always being empty makes ancestry walks via the RPC
  impossible.
- Two-format ambiguity on `descendantfees`/`ancestorfees` is a wire
  contract bug.

---

## BUG-12 (P1) — TWO independent `wtxid` computations (`computeWtxid` returns `Wtxid`, `computeWtxId` returns `TxId`)

**Severity:** P1 (two-pipeline guard 18th distinct extension; first
"same-primitive different-type" instance). Two top-level functions
compute the same value:

`src/Haskoin/Crypto.hs:1064-1065`:
```haskell
computeWtxid :: Tx -> Wtxid
computeWtxid tx = Wtxid $ doubleSHA256 (encode tx)
```

`src/Haskoin/Consensus.hs:3000-3001`:
```haskell
computeWtxId :: Tx -> TxId
computeWtxId tx = TxId (doubleSHA256 (encode tx))
```

Same algorithm. Same encoding. Different return types (`Wtxid` vs
`TxId`). Distinct module exports. The mempool path uses `computeWtxid`
(Mempool.hs:172, 989, 2614). The block-merkle path uses `computeWtxId`
(Consensus.hs:2952). The RPC path uses BOTH — `computeWtxId` at lines
1703, 2395, 2498 alongside `computeWtxid` indirectly via mempool entries.

Additionally, the docstring at `Consensus.hs:2998` says "For coinbase,
wtxid is all zeros" but the code at line 3001 does NOT special-case
coinbase. BIP-141 §commitment specifies that the witness-commitment
merkle uses wtxid=0x0000... for the coinbase position. haskoin's
`computeMerkleRoot` callers must therefore special-case this externally
— and a grep at `Consensus.hs:2950-2953` confirms the special-case:

```haskell
let wtxids = TxId (Hash256 (BS.replicate 32 0))  -- coinbase wtxid
           : map computeWtxId (tail (blockTxns block))
```

The special case is correctly handled at the call-site, but the
docstring above `computeWtxId` is misleading.

Type-safety wise: `TxId` vs `Wtxid` are different newtypes, both
wrapping `Hash256`. The intent of distinct newtypes is to prevent
mixing — but the existence of `computeWtxId :: Tx -> TxId` defeats
the type-safety. Code that wants a `Wtxid` cannot use `computeWtxId`
without an unsafe coerce. Code that wants a `TxId` cannot use
`computeWtxid` without unwrapping.

**File:** `src/Haskoin/Crypto.hs:1064`,
`src/Haskoin/Consensus.hs:3000`.

**Core ref:** `bitcoin-core/src/primitives/transaction.cpp::CTransaction::ComputeHash`
(single function; coinbase wtxid handled in `BlockMerkleRoot` caller).

**Impact:**
- Maintenance: any future BIP that changes wtxid computation needs
  TWO patches.
- Type-safety leak: `TxId` and `Wtxid` are no longer distinguishable
  at the producer side.
- Docstring lies about coinbase handling.

---

## BUG-13 (P1) — Recently-rejected filter is keyed by `TxId`, not `Wtxid`; wtxid-malleability bypasses the filter

**Severity:** P1. `app/Main.hs:1948-1971`:

```haskell
Left err -> do
  case err of
    ErrMissingInput _ -> do
      now <- ...
      addOrphan orphanPoolRef tx now addr
    _ -> do
      -- Add to recently-rejected filter for non-orphan failures
      rejected <- readIORef recentlyRejectedRef
      when (Set.size rejected < 50000) $
        writeIORef recentlyRejectedRef (Set.insert txid rejected)
```

The filter is keyed by `txid`. Bitcoin Core uses BOTH `txid` AND
`wtxid` in its `m_recent_rejects` rolling Bloom filter (added in
0.21 / wtxid-relay BIP-339 work; see `net_processing.cpp::m_recent_rejects`
and related `m_recent_rejects_reconsiderable`). The wtxid keying
prevents the "submit-non-witness-data + change-witness" cheap-retry
bypass: with a txid-only filter, an adversary can mutate the witness
(legal under SegWit malleability) to get a fresh wtxid, but the same
txid — the filter SHOULD block it, AND it does in this implementation.

But the inverse attack works: if the adversary submits a tx with
WITNESS-A (wtxid X1, txid T), it gets rejected and `T` is filtered.
Then the adversary submits the SAME tx with WITNESS-B (wtxid X2, same
txid T). The filter says T is rejected → skip. **OK, this side works.**

Inverse: adversary submits tx with txid T1 and tx with txid T2 that
have DIFFERENT non-witness data but produce the same wtxid (impossible
in practice, but the wtxid filter exists for protocol-cleanliness).

**Real bug:** the comment at lines 1962-1965 says:

```haskell
-- skip soft / policy-only rejections (mempool full, fee too low,
-- duplicate) — those are honest peer behavior.  Reference:
-- bitcoin-core/src/net_processing.cpp:3045 — only state.IsInvalid
-- (consensus failure) increments the score, not policy rejects.
```

But the CODE at lines 1957-1960 adds **all non-orphan failures** to
the filter:

```haskell
_ -> do
  -- Add to recently-rejected filter for non-orphan failures
  rejected <- readIORef recentlyRejectedRef
  when (Set.size rejected < 50000) $
    writeIORef recentlyRejectedRef (Set.insert txid rejected)
```

The comment claims policy-only rejections (mempool-full, fee-too-low,
duplicate) are skipped — but the code does NOT skip them. Every
fee-too-low, mempool-full, RBF-rule violation gets the txid added to
recentlyRejectedRef. A legitimate sender whose fee was barely below
the rolling minimum at submission time is permanently filtered for
the lifetime of the filter (which is the whole process — there's no
rolling eviction, just a fixed `Set.size < 50000` cap).

This is a **comment-contradicts-code** instance, distinct from
"comment-as-confession" (which says "we know this is wrong"). Here the
comment claims correctness and the code is wrong.

**File:** `app/Main.hs:1948-1971`.

**Core ref:** `bitcoin-core/src/net_processing.cpp::m_recent_rejects`
(separate wtxid filter exists);
`bitcoin-core/src/net_processing.cpp:3045+` (consensus-only check).

**Impact:**
- Honest senders whose fee bid was rejected get permanently filtered.
- Once 50,000 entries accumulate (well under typical mempool churn
  for a high-traffic node), the filter STOPS accepting entries,
  silently — a sneaky-wrong: subsequent rejected txids are NOT
  tracked.
- Cross-cite to BIP-339 wtxid-relay: peer-side optimisation that
  relies on wtxid filter parity sees haskoin treating wtxid-distinct
  txs differently than Core would.

---

## BUG-14 (P1) — `getP2SHSigOpCost` has dead unreachable branch `not (True)`

**Severity:** P1. `src/Haskoin/Consensus.hs:2195-2200`:

```haskell
getP2SHSigOpCost :: Tx -> Map OutPoint TxOut -> ConsensusFlags -> SigOpCost
getP2SHSigOpCost tx utxoMap flags
  -- P2SH flag must be active (always is after BIP-16)
  | not (True) = SigOpCost 0  -- P2SH always active in our implementation
  | isCoinbase tx = SigOpCost 0
  | otherwise = ...
```

The guard `not (True)` is a constant `False` and the branch is
unreachable. This is **dead-flag-pretending-to-be-a-gate** (W144
fleet pattern, 9th distinct instance across fleet). The author
deliberately disabled the conditional but left the syntactic gate in
place, with a comment-as-confession ("P2SH always active in our
implementation") that admits the gate is fake.

If a future BIP-16-reversal (impossible but illustrative) or a
test-mode "disable P2SH sigops" is needed, the gate needs to be
rewritten from scratch — the existing condition gives no
infrastructure for it. The intent was `flagP2SH cf` (which doesn't
exist on `ConsensusFlags`).

Also note that BIP-16 (P2SH) DOES have an activation height in Core
(`BIP16Exception` mainnet block `00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22`
height 170,060), and a strict reading of Core says P2SH sigop counting
respects the BIP-16 activation. haskoin's "always active" stance
treats P2SH sigops as live from genesis, which over-counts sigops in
blocks before height 170,060 — but this is benign on mainnet (those
blocks have no real P2SH outputs to count) and consensus-correct
post-activation.

**File:** `src/Haskoin/Consensus.hs:2197-2198`.

**Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp::GetP2SHSigOpCount`
(gated on `STANDARD_NOT_MANDATORY_VERIFY_FLAGS` — P2SH always live in
modern post-activation chains, but the gate is real in the source).

**Impact:**
- Comment-as-confession admits the gate is decorative.
- Future maintenance hazard: deleting `not (True)` looks like a
  one-character no-op but actually inverts the logic to "always 0".

---

## BUG-15 (P1) — `loadMempool` exception handler is a thunk that's never forced; IO exceptions silently swallowed

**Severity:** P1. `src/Haskoin/Mempool/Persist.hs:357-364`:

```haskell
Nothing -> do
  res <- addTransaction mp (dtTx dt)
          `catch` (\(_e :: SomeException) ->
                     return $ Left
                       (error "loadMempool: caught"))
  case res of
    Right _ -> atomically (modifyTVar' loaded (+ 1))
    Left _  -> atomically (modifyTVar' failed (+ 1))
```

The `catch` returns `Left (error "loadMempool: caught")`. The
`error "..."` is a thunk that — under Haskell's lazy evaluation —
isn't forced until pattern-matched. The pattern-match at line 364 is
`Left _` (wildcard), which DOES NOT force the thunk. The exception
message is therefore NEVER printed; the `error` is never raised.

The net effect: any IO exception thrown during `addTransaction`
(RocksDB read failure, decode failure, network UTXO lookup timeout) is
counted as a `failed` increment with no diagnostic. The operator sees
"`mempool.dat: 2000 accepted, 471 failed, 0 expired`" with no clue
which txs failed or why.

Core's equivalent (`txmempool.cpp::LoadMempool`) prints a per-tx
failure line at `LogPrintLevel(BCLog::MEMPOOL, BCLog::Level::Warning,
...)` when a tx fails admission, including the reject reason. haskoin's
silent-swallow makes mempool.dat corruption invisible.

The thunk is also a **memory leak**: each failed admission allocates a
small thunk that's never forced and never garbage-collected until the
outer `IO` action completes (which is the entire load loop).

**File:** `src/Haskoin/Mempool/Persist.hs:357-364`.

**Core ref:** `bitcoin-core/src/txmempool.cpp::LoadMempool` (per-tx
failure log).

**Impact:**
- Mempool.dat corruption / version-skew failures invisible to
  operator.
- Thunk leak under long mempool.dat reload.
- No actionable failure-reason for retry diagnostics.

---

## BUG-16 (P1) — Two duplicate ATMP code paths: `finalizeTransaction` vs `addTransactionToMempool` re-implement the same gates with subtly different sigop / fee / RBF semantics

**Severity:** P1 (two-pipeline guard 19th distinct extension). The
single-tx admission path (`finalizeTransaction` →
`continueAddTransaction` → `buildMempoolEntry`) and the package admission
path (`addPackageTransactions` → `goAfterCtxFree` →
`addTransactionToMempool`) re-implement nearly identical logic, with
divergences:

- **fee delta application** — single-tx path applies prioritise delta
  (line 859-868); package path's `addTransactionToMempool` does NOT
  apply any delta (line 2592-2651), so PrioritiseTransaction has no
  effect on package-admitted txs.

- **sigop-adjusted vsize** — single-tx path uses `calculateAdjustedVSize`
  (line 980); package path also calls it (line 2611), but the order of
  operations differs: single-tx computes `adjVsize` once and uses it
  consistently for `feeRate`, `meSize`, ancestor accumulation; package
  path computes `adjVsize` per-input/per-tx-incrementally.

- **`meRBFOptIn` computation** — single-tx uses `signalsOptInRBF`
  (`<= 0xfffffffd`, BUG-9); package uses inline `< 0xfffffffe`.

- **descendant accounting on insert** — single-tx updates descendant
  counts/sizes/fees via `Map.adjust` at line 1035-1040; package path
  has the same logic at line 2644-2649 but accumulates with
  `adjVsize` whereas single-tx uses `meSize entry` directly — these
  ARE equivalent today but the lookup-then-use pattern is reproduced
  twice.

- **ancestor `meAncestorSigOps`** — single-tx pulls from
  `buildMempoolEntry` which sums `meAncestorSigOps` of ancestors plus
  `txSigOpCost` (line 988); package path inlines the same at line 2607
  but uses `selfSigOpCost` recomputed locally.

The two paths exist because the package path was added later (TRUC,
BIP-431 work) and the author copy-pasted the single-tx finalisation
shape rather than refactoring `finalizeTransaction` into a reusable
helper. This is the **code-duplication smell — byte-near-identical
helpers** pattern (W143 reported in beamchain for
merkle_pairs/merkle_pairs_check).

**File:** `src/Haskoin/Mempool.hs:840-953` (single-tx finalise) vs
`src/Haskoin/Mempool.hs:2592-2651` (package finalise).

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::Finalize`
(single function called by both single-tx and package paths).

**Impact:**
- PrioritiseTransaction has no effect on package-admitted txs
  (cross-cite BUG-10).
- Any future ATMP change must be applied twice; drift risk.
- Code review burden — two near-identical 100-line blocks.

---

## BUG-17 (P1) — `getMempoolMinFeeRate` exported but never called by any RPC; rolling minimum fee is a "ghost feature"

**Severity:** P1 (dead-function-export). `getMempoolMinFeeRate` at
`Mempool.hs:1467-1472` is correctly implemented:

```haskell
getMempoolMinFeeRate :: Mempool -> IO Word64
getMempoolMinFeeRate mp = do
  rollingKvb <- getMempoolMinFeeRateDecayed mp
  let FeeRate minRate = mpcMinFeeRate (mpConfig mp)
      staticKvb = fromIntegral minRate * 1000  -- sat/vB → sat/kvB
  return (max rollingKvb staticKvb)
```

It is in the module export list (line 48). It correctly mirrors
`CTxMemPool::GetMinFee`. The decay logic in
`getMempoolMinFeeRateDecayed` (line 1974+) correctly implements
exponential decay with `ROLLING_FEE_HALFLIFE`. The
`trackPackageRemoved` writer at line 1955 correctly bumps the rolling
minimum on size-limit eviction.

**Nothing reads it.** A `grep -n "getMempoolMinFeeRate" /home/work/hashhog/haskoin`
returns 4 results — all inside `Mempool.hs` itself (export, definition,
internal helper). Zero RPC handlers, zero P2P feefilter producers, zero
mining callers.

So the full eviction/decay pipeline runs every block and on every
size-limit eviction, but the result is never surfaced to peers
(feefilter messages should use this), never returned by
`getmempoolinfo.mempoolminfee` (BUG-11.2 — it uses the static config),
never used as the in-band rolling-fee floor.

This is the **already-exports-the-primitive-just-not-called** fleet
pattern (W141 reported in haskoin's W140 `constantTimeEq` instance).
The primitive is correct, exported, internally consistent — but no
producer wires it. The "compute path" and "consume path" are
disconnected.

**File:** `src/Haskoin/Mempool.hs:1467-1472` (definition, exported);
`src/Haskoin/Rpc.hs` (zero callers).

**Core ref:** `bitcoin-core/src/txmempool.cpp::GetMinFee` (consumed by
`rpc/mempool.cpp::getmempoolinfo` and `net_processing.cpp` feefilter
sender).

**Impact:**
- Rolling minimum fee feature is a no-op: it computes correctly,
  but nothing reads the result.
- Cross-cite BUG-11.2 — `mempoolminfee` RPC field reports static
  config, not live rolling value.
- BIP-133 feefilter (W136 separate audit) is also affected: outbound
  feefilter messages should advertise the higher of (static min,
  rolling min) — without consulting `getMempoolMinFeeRate`, the
  advertised value is wrong.

---

## BUG-18 (P0-SEC) — Mempool's `consensusFlagsAtHeight (mpHeight+1)` uses MANDATORY-only flags at PRE-segwit / pre-taproot heights when `mpHeight=0`

**Severity:** P0-SEC. Combining BUG-6 (mpHeight=0 at startup) with
BUG-1 (MANDATORY-only at mempool):

At startup, every script verification call at `Mempool.hs:1112, 1250,
2515, 2606` evaluates:

```haskell
let cflags = consensusFlagsAtHeight (mpNetwork mp) (mpHeight + 1)
```

With `mpHeight = 0` for mainnet, `mpHeight + 1 = 1`. At mainnet height
1:
- `flagBIP34 = (1 >= 227931) = False`
- `flagBIP65 = (1 >= 388381) = False`
- `flagBIP66 = (1 >= 363725) = False`
- `flagSegWit = (1 >= 481824) = False`
- `flagNullDummy = False`
- `flagTaproot = (1 >= 709632) = False`

So `consensusFlagsToScriptFlags` emits ONLY `{VerifyP2SH}` — DERSig,
CLTV, CSV, WITNESS, NULLDUMMY, TAPROOT are ALL absent.

A mempool.dat replayed on restart against this flag-set:
- Bypasses all SegWit verification (witness data ignored).
- Bypasses Taproot key-path and script-path verification.
- Bypasses BIP-65 OP_CHECKLOCKTIMEVERIFY (treats as OP_NOP2).
- Bypasses BIP-66 strict DER (admits high-S, malformed-DER signatures).
- Bypasses NULLDUMMY (admits CHECKMULTISIG with non-empty dummy).

A malicious mempool.dat (or a corrupted/replayed snapshot) could
include txs that violate any of those rules and they would be
accepted. Once `blockConnected` fires, `mpHeight` increments and the
flags update — but any tx admitted before that point is already in
the mempool.

**File:** `src/Haskoin/Mempool.hs:1112, 1250, 2515, 2606` (all call
`consensusFlagsAtHeight (mpNetwork mp) (mpHeight + 1)` without ever
asserting `mpHeight > 0` or comparing to the actual chain tip).

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::PreChecks`
(uses `m_active_chainstate.m_chain.Height() + 1` directly, never
defaults to 0).

**Impact:**
- Mempool.dat replay at startup admits txs with pre-segwit /
  pre-taproot script verification.
- A crafted mempool.dat is a one-shot UTXO bypass: get a non-witness
  tx that "spends" a SegWit output to be admitted, get propagated to
  honest peers before they reject it, sow confusion.
- Defense-in-depth gap: even if no malicious mempool.dat exists today,
  the architecture admits one whenever `mpHeight=0`.

---

## BUG-19 (P0-CDIV) — `addTransaction` does NOT re-check `bad-txns-inputs-duplicate` after RBF conflict resolution; W145 BUG-3 cache-mutation pattern echo

**Severity:** P0-CDIV (W145 BUG-3 / CVE-2018-17144 class). Bitcoin
Core's `MemPoolAccept::PreChecks` runs `CheckTransaction` (which
includes the duplicate-inputs check) at the **start** of admission.
For the standard single-tx admission path, this is sufficient.

For the RBF/replacement path, Core ALSO re-runs duplicate detection
implicitly via `Workspace::m_view` layering: after the replacement
removes conflicting txs from the view, the `CheckInputScripts` walk
through `Coin` lookups would surface any duplicate-input pathology in
the **replacement tx itself**.

haskoin's flow:
1. `addTransaction` → `addTransactionInner` (`Mempool.hs:678`).
2. `addTransactionInner` calls `validateTransaction` at line 680
   which DOES include the duplicate check (`Consensus.hs:1411-1414`).
3. **`addTransactionWithReplacement` is called** at line 734.
4. `addTransactionWithReplacementInner` at line 776+ resolves inputs
   via `resolveInputsForReplacement`, runs RBF rule-checks via
   `attemptReplacement`.
5. After conflicts are REMOVED from the mempool, the code re-resolves
   inputs and calls `finalizeTransaction`.
6. `finalizeTransaction` does NOT re-call `validateTransaction`.

So if the RBF replacement tx itself has duplicate inputs (the same
prevout listed twice), the duplicate check at step 2 catches it
(`validateTransaction` runs once per `addTransaction`). **But** the
W145 BUG-3 pattern is about cache mutation paths (`applyBlock`,
`applyBlockToCache`) bypassing duplicate detection. In the haskoin
mempool, the analogous concern is:

- `addTransaction → addTransactionInner → validateTransaction` runs duplicate check ✓
- `addTransaction → addTransactionInner → addTransactionWithReplacement → addTransactionWithReplacementInner → finalizeTransaction` runs duplicate check ✓ (via step 2 inside addTransactionInner)
- `addPackageTransactions → goAfterCtxFree → addTransactionToMempool` calls `validateTransaction` once at line 2456-2457 ✓ (in goAfterCtxFree)
- `addTransactionToMempool` is also called directly from packageDry
  paths — these MUST have had `validateTransaction` upstream.

Actually the architecture appears to call `validateTransaction` at
every entry point. The W145 BUG-3 echo at mempool would manifest at a
DIFFERENT pipeline: the `blockDisconnected → blockTxns block re-adds`
at line 1882-1883:

```haskell
-- Re-add non-coinbase transactions
-- (they may fail validation if inputs are now missing)
forM_ (tail $ blockTxns block) $ \tx ->
  void $ addTransaction mp tx
```

When a block is disconnected during a reorg, its transactions are
re-added to the mempool via `addTransaction`. `addTransaction` calls
`validateTransaction` → duplicate check fires. ✓ So this path is
covered.

However: the **package path's atomic-rollback** on failure
(`addPackageTransactions` at lines 2429-2559) does NOT call
`validateTransaction` at the OUTER level — it relies on `goAfterCtxFree`
to call it. But `goAfterCtxFree` recurses into nested validation and
only calls `validateTransaction` at line 2456 for each individual tx.
If the package contains a child tx that duplicates an OutPoint from a
parent in the same package, `validateTransaction` on each individually
won't catch it — the cross-tx duplicate check is missing.

Bitcoin Core's PackageMempoolAccept performs cross-tx duplicate
detection via the layered view. haskoin's package path detects
intra-package conflicts via `getConflicts` (line 724) which checks the
mempool's `mpByOutpoint` — but this only catches conflicts AFTER one
of the package txs has been admitted. A child + sibling that BOTH
spend the same parent outpoint, submitted as a package, would have
one accept and one reject with "txn-mempool-conflict" — instead of
the package being atomically rejected.

This is a less-severe echo than W145 BUG-3 itself, but the same
architectural class.

**File:** `src/Haskoin/Mempool.hs:2429-2559` (package admission;
intra-package duplicate-outpoint check absent).

**Core ref:** `bitcoin-core/src/validation.cpp::MemPoolAccept::AcceptMultipleTransactions`
(workspace per tx; cross-tx duplicate detection via shared view).

**Impact:**
- Package submission with intra-package duplicate spends produces
  partial admission instead of atomic rejection.
- Diff-test corpus entries that submit a "child A spending parent X
  outpoint 0" + "child B also spending parent X outpoint 0" expect
  package-level rejection per Core; haskoin admits A and rejects B
  (or vice versa) instead.

---

## BUG-20 (P1) — `blockDisconnected` re-adds via `addTransaction` runs full standardness; Core does NOT re-check standardness on re-insertion

**Severity:** P1. `Mempool.hs:1880-1883`:

```haskell
-- Re-add non-coinbase transactions
-- (they may fail validation if inputs are now missing)
forM_ (tail $ blockTxns block) $ \tx ->
  void $ addTransaction mp tx
```

This calls the FULL `addTransaction`, which runs:
- `validateTransaction` (consensus checks).
- `Std.checkStandardTx` (standardness — version 1-3, weight cap,
  scriptSig pushonly, scriptPubKey standard, OP_RETURN budget, dust).
- `isFinalTxCheck`, `checkSeqLocksAtTip`.
- `validateInputsStandardness`, `checkWitnessStandard`.
- `generalEphemeralPreCheck`.
- MAX_STANDARD_TX_SIGOPS_COST.
- Script verification with MANDATORY-only flags (BUG-1).

Bitcoin Core's `disconnectTransactions`/`MaybeUpdateMempoolForReorg`
(`validation.cpp:737-803`) re-introduces disconnected transactions
into the mempool **without re-running standardness**. The rationale:
those txs WERE in a valid block, so they're already-known to be
consensus-valid; their standardness was acceptable at the time they
were originally admitted; and applying current standardness rules
(which may be stricter due to a recent operator-knob change like
`-permitbaremultisig=0`) would cause spurious eviction.

haskoin's re-application of standardness on re-add means:
- A pre-existing bare-multisig output that was admitted under a
  permissive policy, mined, then re-disconnected during a reorg,
  would be REJECTED on re-add if the standardness policy has tightened.
- The reorg-aware mempool window narrows: txs that were live
  pre-reorg may not be re-admittable post-reorg even though the
  consensus rules say they should be.

**File:** `src/Haskoin/Mempool.hs:1880-1883`.

**Core ref:** `bitcoin-core/src/validation.cpp::MaybeUpdateMempoolForReorg`
(skips standardness; sets `bypass_limits = true`).

**Impact:**
- Reorg-disconnected txs spuriously rejected on re-add if any
  standardness gate has tightened.
- Cross-cite BUG-6: if `mpHeight` drift puts the script-verify flags
  in the wrong era during reorg-replay, even consensus-valid scripts
  may be wrongly rejected.

---

## Summary

**Bug count:** 20 (BUG-1 through BUG-20).

**Severity distribution:**
- **P0-CDIV:** 6 (BUG-1, BUG-2, BUG-4, BUG-6, BUG-10, BUG-19)
- **P0-SEC:** 3 (BUG-5, BUG-8, BUG-18)
- **P1:** 11 (BUG-3 cluster of 9, BUG-7, BUG-9, BUG-11 cluster of 5,
  BUG-12, BUG-13, BUG-14, BUG-15, BUG-16, BUG-17, BUG-20)

Total = 6 + 3 + 11 = **20** ✓

**P0-class concentration:** 9 P0 findings out of 20 (45%) — the
highest P0-density haskoin audit since W143. The mempool surface is
foundationally stacked: BUG-6 (mpHeight=0 at startup) creates BUG-5
(Word32 underflow), BUG-18 (pre-segwit script flags), partial BUG-4
(off-by-one). BUG-1 (MANDATORY-only at mempool) is the W144 BUG-3
fleet pattern's first confirmed mempool-side instance and the
single-largest consensus exposure.

**Fleet patterns confirmed:**

- **W144 BUG-3 echo CONFIRMED LIVE at mempool**: STANDARD_SCRIPT_VERIFY_FLAGS
  entirely absent (BUG-1). 14 of 21 `ScriptVerifyFlag` enum members
  are defined-and-consulted-but-never-emitted from
  `consensusFlagsToScriptFlags`. Same shape as W144 haskoin BUG-3.
- **W145 BUG-3 (CVE-2018-17144 class) echo at package path**:
  intra-package duplicate-outpoint check absent (BUG-19).
- **Two-pipeline guard 17th-19th distinct extensions**:
  BUG-9 (`signalsOptInRBF` vs inline at line 2601),
  BUG-12 (`computeWtxid` vs `computeWtxId` — first "same-primitive
  different-type" instance), BUG-16 (single-tx vs package finalisation
  pipelines).
- **Dead-data plumbing** (5th distinct haskoin instance):
  - BUG-10 (`mpFeeDeltas` stored + persisted + consumed, no writer)
  - BUG-17 (`getMempoolMinFeeRate` exported + correct, no caller)
  - BUG-11.2 (`mempoolminfee` RPC uses static config, rolling min
    ignored)
- **Dead-flag-pretending-to-be-a-gate** (W144 9th fleet instance):
  BUG-14 (`getP2SHSigOpCost` guard `not (True)` with
  comment-as-confession).
- **Wiring-look-but-no-wire** (W138 class): BUG-10 prioritisetransaction
  storage in place, persistence in place, consumer in place, ONLY the
  RPC producer is absent.
- **Already-exports-the-primitive-just-not-called** (W141 class):
  BUG-17 `getMempoolMinFeeRate` exported but no caller.
- **No operator-knob exists** (W148 / W149 / blockbrew BUG-5 echo):
  BUG-2 (no `-acceptnonstdtxn`), BUG-3 cluster of 9 (no
  `-minrelaytxfee`, `-incrementalrelayfee`, `-datacarrier`,
  `-permitbaremultisig`, `-maxmempool`, `-mempoolexpiry`,
  `-mempoolfullrbf`, `-bytespersigop`, `-dustrelayfee`).
- **Reject-string wire-parity slippage** (lunarblock W125 9-token
  sweep echo): BUG-7 (5 of 9 `validateTransaction` reject tokens
  diverge from Core's BIP-22 wire-strings).
- **Comment-as-confession** (8th haskoin instance):
  - BUG-13 (`Main.hs:1962` comment claims policy-rejects skipped,
    code adds all)
  - BUG-14 (`Consensus.hs:2198` comment "P2SH always active")
  - BUG-17 (`mempoolminfee` RPC formula uses static config, comment
    above implies live value)
- **Comment-contradicts-code** (NEW pattern, distinct from
  comment-as-confession): BUG-13 — comment promises filter-skip for
  policy rejects, code applies filter to ALL non-orphan failures.
- **Plumb-the-callback-but-not-the-state** (NEW pattern): BUG-6 —
  `getCoinMtpFromChain` callback is chain-aware, but `mpHeight`/`mpMTP`
  init values are hard-coded `0 0` ignoring the actual chain tip.
- **Code-duplication smell — byte-near-identical helpers** (W143
  beamchain pattern): BUG-16 (single-tx vs package finalisation
  pipelines 100 LOC each).
- **Non-exhaustive ADT case → runtime crash** (NEW haskoin instance):
  BUG-8 (`mempoolErrorToText` missing 7 of 32 constructors, no
  catch-all, DoS-by-RPC).
- **Stacked foundational gap** (mpHeight=0 at startup creates 4
  downstream P0s): BUG-6 → BUG-5 (Word32 underflow) → BUG-18
  (pre-segwit script flags) → partial BUG-4 (off-by-one).

**Top three findings:**

1. **BUG-1 (P0-CDIV) — STANDARD_SCRIPT_VERIFY_FLAGS entirely absent
   at mempool admit (W144 BUG-3 echo CONFIRMED LIVE)**. `verifyAllScripts`
   uses `consensusFlagsToScriptFlags` which emits only the MANDATORY
   set (P2SH | DERSIG | CLTV | CSV | WITNESS | NULLDUMMY | TAPROOT). All
   14 STANDARD bits (CLEANSTACK, MINIMALDATA, MINIMALIF, NULLFAIL,
   LOW_S, SIGPUSHONLY, DISCOURAGE_*, WITNESS_PUBKEYTYPE,
   CONST_SCRIPTCODE, STRICTENC) are defined in the
   `ScriptVerifyFlag` enum, consulted by the script evaluator, but
   never emitted by any production helper. haskoin admits and relays
   txs that Core rejects as nonstandard; soft-fork preparation
   pipeline is broken because mempool would accept future-MANDATORY
   violations.

2. **BUG-6 + BUG-5 + BUG-18 stacked foundational gap — `mpHeight=0`
   at startup creates THREE P0s**. `newMempool` is called with
   literal `0 0` for height and MTP regardless of loaded chain tip;
   `mpHeight` is never written directly, only incremented per
   `blockConnected`. So at startup (before any block arrives),
   `loadMempool` admits every tx in `mempool.dat` against fake-zero
   chain state: coinbase-maturity (`height - ueHeight < 100`)
   Word32-underflows to "MATURE" (BUG-5), script-verify flags at
   `consensusFlagsAtHeight 1` exclude SegWit/Taproot/BIP65/BIP66
   (BUG-18), `nextHeight=1`/`MTP=0` mis-evaluate IsFinalTx and BIP-68.
   A crafted `mempool.dat` can therefore inject txs that violate any
   of these rules. The fix is one line in `Main.hs:897` to plumb the
   actual chain tip, but the wrap-safety in BUG-5 also needs a guard.

3. **BUG-8 (P0-SEC) — `mempoolErrorToText` non-exhaustive ADT case
   crashes RPC thread on 7 constructors**. Missing
   `ErrCoinbaseNotAllowed`, `ErrMaxFeeRateExceeded`,
   `ErrSpendsConflictingTx`, `ErrInputsNotStandard`, `ErrNonStandard`,
   `ErrNonFinal`, `ErrSeqLockNotSatisfied`. No catch-all branch.
   Reachable via `testmempoolaccept` with any locktime-future tx,
   coinbase tx, non-standard tx, etc. A network adversary can crash
   the haskoin mempool RPC threads with a stream of cheap submissions.

**Carry-forward / cross-wave**:
- BUG-1 is the second confirmed instance of W144 BUG-3 across the
  fleet (first was W144 itself); STANDARD-flags-incomplete pattern
  now spans at least 6 of 10 impls (W144 reported 5+ impls; haskoin
  is +1).
- BUG-3 cluster of 9 confirms the **no-operator-knob-exists** pattern
  spans haskoin's entire mempool surface — comparable to W148 BUG-6
  / W149 BUG-5 for `-assumevalid` etc.
- BUG-19 partial echo of W145 BUG-3 (CVE-2018-17144 class) at package
  admission path.

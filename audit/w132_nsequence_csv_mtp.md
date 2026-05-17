# W132 BIP-68 / BIP-112 / BIP-113 — nSequence / OP_CSV / MTP audit (haskoin)

Discovery-only audit. **NO production code changes.** Tests are pinning-shape
or xit-shape so a follow-up fix wave can flip them to it after a real fix.

## Top-line verdict

Status: **MIXED — solid base, 9 BUGS (1 P0-CONSENSUS / 4 P1 / 4 P2)**.

The arithmetic of BIP-68 (`calculateSequenceLocks`, `checkSequenceLocks`),
the constants (`sequenceLockTime{DisableFlag,TypeFlag,Mask,Granularity}` =
`0x80000000` / `0x00400000` / `0x0000ffff` / `9`), BIP-113 IsFinalTx
(`isFinalTxCheck`), the OP_CSV interpreter (`execCheckSequenceVerify`),
the mempool BIP-113/BIP-68 admission gate (`checkSeqLocksAtTip` +
`mpGetCoinMtp`) and the `medianTimePast` walker are all byte-identical
to Core. **The bugs live at the wiring layer**, not the algorithms:

* The script-verify flag wiring ties `VerifyCheckSequenceVerify` to
  `flagSegWit` (= netSegwitHeight), but BIP-68/112/113 activate at
  `netCSVHeight` which is **62,496 blocks earlier on mainnet**. So for
  ~14 months of mainnet history (419,328 → 481,823) OP_CSV silently
  behaved as a NOP in this implementation. That is **P0-CONSENSUS**.
* `backgroundValidationLoop` (assume-utxo IBD path) passes
  `medianTime=0` and a constant-0 getMTP — so BIP-113 IsFinalTx and the
  BIP-68 time-based component degrade to "always pass" in IBD blocks.
* `validateFullBlock` itself **only enforces the height-based component
  of BIP-68** at block-connect, deferring the time-based component to
  OP_CSV at script-eval.  That is documented in-line as intentional
  but it is **divergent from Core**, which fully evaluates both at
  block-connect via `SequenceLocks(tx, ...)`.
* No `ConsensusFlags.flagCSV` / `flagBIP68` field exists separately —
  the activation height for BIP-68/112/113 is **threaded through one
  callsite only**, the `csvActive = height >= netCSVHeight net`
  expression in `validateFullBlock`.  Any future caller doing
  `consensusFlagsAtHeight net h` will silently miss CSV.

## Bug catalog (9)

| #  | Severity        | Subsystem        | One-line summary |
|----|-----------------|------------------|------------------|
| 1  | **P0-CONSENSUS**| Script flags     | `VerifyCheckSequenceVerify` keyed to `flagSegWit` (`netSegwitHeight`), not `netCSVHeight`. On mainnet OP_CSV is a no-op for heights 419,328 → 481,823. |
| 2  | P1              | IBD path         | `backgroundValidationLoop` calls `applyBlock cache net block height 0 (const $ return 0)` — BIP-113 cutoff = 0 and per-input MTP = 0, so non-final txs slip past assume-utxo replay. |
| 3  | P1              | Block-connect    | `validateFullBlock` skips the time-based BIP-68 component (sets `prevMTPs = [0..]` and only consumes `slMinHeight`).  Core's `SequenceLocks` uses both. |
| 4  | P1              | Consensus flags  | `ConsensusFlags` has no `flagCSV` / `flagBIP68` field; activation is threaded through one inline `csvActive` expression in `validateFullBlock` only. |
| 5  | P1              | OP_CLTV          | `execCheckLockTimeVerify` rejects with the literal string `"Sequence is final"` — should map to `SCRIPT_ERR_UNSATISFIED_LOCKTIME` (interpreter.cpp:556).  Negative-locktime path also uses non-canonical message vs `SCRIPT_ERR_NEGATIVE_LOCKTIME`. |
| 6  | P2              | OP_CSV           | `execCheckSequenceVerify` does not check disable-flag on **negative literal operand** before the `sequence' < 0` rejection — Core unconditionally fails on `nSequence < 0` (interpreter.cpp:579-580); haskoin matches but the error string is `"Negative sequence"` not `SCRIPT_ERR_NEGATIVE_LOCKTIME`. |
| 7  | P2              | OP_CSV           | `seFlags env'` referenced in `execCheckSequenceVerify` (Script.hs:1416-1419) handles `VerifyCheckSequenceVerify` flag-not-set as NOP — correct, but on tapscript path (`SigVersion::TAPSCRIPT`) Core treats CSV as a real opcode regardless of flag.  Audit: confirm tapscript wiring. |
| 8  | P2              | `bip68Active`    | `bip68Active net height` uses `height` (current block) but Core's `fEnforceBIP68` is gated by `DeploymentActiveAt(*pindex, ...)` where `pindex` is the block being connected — equivalent in steady state but **diverges at the activation boundary** (Core enables BIP-68 starting at `netCSVHeight`, haskoin enables it at `netCSVHeight - 1` if a stale caller passes `tipHeight` rather than `tipHeight+1`).  Validate every callsite. |
| 9  | P2              | Coinbase locktime| `validateTransaction` (referenced at validateFullBlock:2421) does not check that coinbase tx has nLockTime == 0 / nSequence on its single input.  Core does not check either (coinbase is BIP-34 height-prefixed, separate gate), so this is **acceptable** — pinning only for documentation. |

## 30-gate audit matrix

Gates G1–G30 listed in `test/W132NSequenceCSVMTPSpec.hs`. Cross-reference:

| Gate | Topic | Status |
|------|-------|--------|
| G1   | `sequenceLockTimeDisableFlag = 0x80000000`                                                   | PRESENT |
| G2   | `sequenceLockTimeTypeFlag    = 0x00400000`                                                   | PRESENT |
| G3   | `sequenceLockTimeMask        = 0x0000ffff`                                                   | PRESENT |
| G4   | `sequenceLockTimeGranularity = 9`                                                            | PRESENT |
| G5   | `sequenceFinalConsensus      = 0xFFFFFFFF`                                                   | PRESENT |
| G6   | `locktimeThresholdConsensus  = 500_000_000`                                                  | PRESENT |
| G7   | `calculateSequenceLocks` skips fEnforceBIP68 = false / version<2                             | PRESENT |
| G8   | `calculateSequenceLocks` skips inputs with disable-flag set                                  | PRESENT |
| G9   | `calculateSequenceLocks` time branch: `coinMTP + (lock<<9) - 1`                              | PRESENT |
| G10  | `calculateSequenceLocks` height branch: `coinHeight + lock - 1`                              | PRESENT |
| G11  | `checkSequenceLocks` height test: `height > minHeight`                                       | PRESENT |
| G12  | `checkSequenceLocks` time test: `prevBlockMTP > minTime`                                     | PRESENT |
| G13  | `isFinalTxCheck` nLockTime==0 short-circuit                                                  | PRESENT |
| G14  | `isFinalTxCheck` threshold split: `lockTime < 500M ? height : time`                          | PRESENT |
| G15  | `isFinalTxCheck` SEQUENCE_FINAL fallback                                                     | PRESENT |
| G16  | `medianTimePast` walks 11 ancestors and takes median                                         | PRESENT |
| G17  | `computeEntryMtp` adds new tip timestamp to median window                                    | PRESENT |
| G18  | `csMedianTime` consumed by `validateFullBlock` for BIP-113 cutoff                            | PRESENT |
| G19  | BIP-113: timestamp gate at validation.cpp:4092 (`bhTimestamp > csMedianTime`)                | PRESENT |
| G20  | BIP-113: `nLockTimeCutoff = csvActive ? mtp : timestamp` (validation.cpp:4140-4142)          | PRESENT |
| G21  | OP_CSV: tx version >= 2 fail                                                                 | PRESENT |
| G22  | OP_CSV: disable-flag-set short-circuit (NOP)                                                 | PRESENT |
| G23  | OP_CSV: type-flag mismatch fail                                                              | PRESENT |
| G24  | OP_CSV: masked-value comparison `nSeqMasked > txSeqMasked` fail                              | PRESENT |
| G25  | Mempool BIP-113: `isFinalTxCheck tx (tipHeight+1) mtp`                                       | PRESENT |
| G26  | Mempool BIP-68: `checkSeqLocksAtTip` walks `mpGetCoinMtp (max(coinH-1,0))`                   | PRESENT |
| G27  | **VerifyCheckSequenceVerify keyed to `netCSVHeight`** (not `flagSegWit`)                     | **BUG-1** |
| G28  | **`backgroundValidationLoop` plumbs real MTP** (not constant 0)                              | **BUG-2** |
| G29  | **`validateFullBlock` enforces BIP-68 time component** (not deferred to OP_CSV)              | **BUG-3** |
| G30  | **`ConsensusFlags.flagCSV` exists separately** (not folded into flagSegWit)                  | **BUG-4** |

## Cross-references

* Bitcoin Core `consensus/tx_verify.cpp` lines 17-110 — `IsFinalTx`,
  `CalculateSequenceLocks`, `EvaluateSequenceLocks`, `SequenceLocks`.
* Bitcoin Core `script/interpreter.cpp` lines 540-593, 1745-1826 —
  OP_CLTV / OP_CSV dispatch + `CheckLockTime` / `CheckSequence`.
* Bitcoin Core `validation.cpp` lines 147-262 (mempool `CheckFinalTxAtTip` +
  `CalculateLockPointsAtTip` + `CheckSequenceLocksAtTip`), 2478-2562
  (block-connect `nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE` +
  `SequenceLocks`), 4080-4150 (`ContextualCheckBlockHeader` MTP gate
  + `ContextualCheckBlock` BIP-113 `nLockTimeCutoff`).
* Bitcoin Core `primitives/transaction.h:74-114` — `SEQUENCE_FINAL`,
  `SEQUENCE_LOCKTIME_*` constants.
* Bitcoin Core `chain.h:231-244` — `nMedianTimeSpan = 11` +
  `GetMedianTimePast`.
* Bitcoin Core `consensus/consensus.h:28` — `LOCKTIME_VERIFY_SEQUENCE = (1 << 0)`.
* Bitcoin Core `script/script.h:47` — `LOCKTIME_THRESHOLD = 500000000`.
* Bitcoin Core `consensus/params.h:105, 142, 152` — `CSVHeight` as a
  **buried deployment** + `DeploymentHeight(DEPLOYMENT_CSV)`.
* Bitcoin Core `policy/policy.h:138` — `STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE}`.

## Activation heights (haskoin)

```
mainnet  : netCSVHeight = 419328  netSegwitHeight = 481824  delta = +62,496
testnet3 : netCSVHeight = 770112  netSegwitHeight = 834624  delta = +64,512
testnet4 : netCSVHeight = 1       netSegwitHeight = 1       delta = 0
regtest  : netCSVHeight = 1       netSegwitHeight = 0       delta = -1 (regtest BIP-9 segwit early)
```

For mainnet **the 62,496-block CSV / SegWit gap is canonical Bitcoin
history**: BIP-68/112/113 locked in (block 419,328, Jul 4 2016), SegWit
locked in (block 481,824, Aug 24 2017). Any chain replay on this binary
through that window does not enforce OP_CSV (BUG-1).

## Operational implications

This is a **discovery audit** — production code is not changed.  Live
nodes on mainnet were synced past height 481,824 long before this code
existed, so the runtime impact is bounded to:

1. Full reindex / IBD from genesis on mainnet — would silently accept
   txs whose only validity bug is non-CSV-satisfaction in the gap.
2. Regtest / testnet4 (CSV @ height 1) — unaffected (gap = 0).
3. testnet3 — same 64,512-block gap (also historical, all blocks already
   mined).

Severity: **P0-CONSENSUS** because the gap is part of canonical mainnet
chain history.  Severity is intentional even though no live drift will
happen — a future from-scratch reindex would produce a chain that
disagrees with Bitcoin Core on the validity of any tx that depended on
OP_CSV in the gap.

## Out of scope (not classified as bugs in this audit)

* BIP-68 max_tx_version cap is at MAX_STANDARD_VERSION = 3 — relay policy,
  not consensus.  Already covered by W129 / W120 standardness audits.
* OP_CSV disable-flag-with-MINIMALIF in tapscript — covered by W127 Taproot
  audit (BIP-342 OP_SUCCESS / MINIMALIF handling).
* `versionbits` activation FSM for non-buried deployments — covered by
  W104 / W109 BIP-9 audits.
* `BuriedDeployment` vs `DeploymentPos` taxonomy — covered by W109.

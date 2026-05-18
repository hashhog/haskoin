# W142 SegWit witness validation — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** BIP-141 / BIP-143 / BIP-144 (witness-data wire format, weight
accounting, witness commitment, BIP-143 sighash, witness program
parsing, witness merkle root). Audited at the consensus boundary —
script-path verifier internals are out of scope (covered by W127
Taproot for v1 and earlier waves for v0 leaf execution).

**BIPs:** BIP-141 (Consensus rules), BIP-143 (Sighash), BIP-144
(P2P serialization).

**Out of scope:** Taproot / tapscript (W127), PSBT v0/v2 (W137),
BIP-152 compact blocks (W126), policy-only WITNESS_PUBKEYTYPE wiring
(W135 standardness), addrman-side service-bit advertisement (W128).

**Sources audited:**

- `src/Haskoin/Consensus.hs:455-470` (block constants — MAX_BLOCK_WEIGHT,
  MAX_BLOCK_SIGOPS_COST, MIN_TRANSACTION_WEIGHT, WITNESS_SCALE_FACTOR).
- `src/Haskoin/Consensus.hs:914-915` (mainnet segwitHeight = 481824).
- `src/Haskoin/Consensus.hs:1067, 1157, 1212, 1302` (per-network
  netSegwitHeight wiring).
- `src/Haskoin/Consensus.hs:1378-1382` (per-tx weight cap).
- `src/Haskoin/Consensus.hs:2059-2128` (block / tx weight + dead
  `checkBlockWeight`).
- `src/Haskoin/Consensus.hs:2253-2291` (witness sigop counting).
- `src/Haskoin/Consensus.hs:2390-2590` (validateFullBlock — the
  ContextualCheckBlock equivalent: block weight gate, witness
  malleation gate).
- `src/Haskoin/Consensus.hs:2919-3001` (checkWitnessMalleation +
  txHasWitness + validateWitnessCommitment + computeWtxId).
- `src/Haskoin/Crypto.hs:1004-1037` (txSigHashSegWit — BIP-143
  sighash preimage).
- `src/Haskoin/Script.hs:744-766` (isWitnessProgram — version + program
  decoder).
- `src/Haskoin/Script.hs:1487-1495` (checkElementSize — 520-byte cap
  at PUSHDATA only, NOT at witness initial stack).
- `src/Haskoin/Script.hs:2630-2730` (verifyWitnessProgram dispatch:
  native + P2SH-wrapped, witness-version branch).
- `src/Haskoin/Script.hs:2737-2782` (verifyP2WPKHWithFlags — P2WPKH
  implicit script construction + verify).
- `src/Haskoin/Script.hs:2789-2826` (verifyP2WSHWithFlags — P2WSH
  hash check + EvalScript wrapper).
- `src/Haskoin/Types.hs:215-300` (Tx Serialize instance — segwit
  marker/flag, parseSegWitTx, parseLegacyTx).
- `src/Haskoin/BlockTemplate.hs:261-373` (mining-side coinbase
  commitment generation).

**Result:** out of 28 gates audited (across the 8 wave behaviors),
**13 PRESENT (correct)**, **9 PARTIAL (shape divergent / under-
guarded / wrong activation)**, **6 MISSING (no implementation at
all)**.

**Bugs found:** 18 (1 P0-CONSENSUS, 4 P0-CDIV, 7 P1, 4 P2, 2 P3).

## Top-line verdict

haskoin's SegWit surface is largely-correct on the happy path: the
BIP-143 sighash preimage is byte-for-byte right; the witness merkle
root computation correctly uses 0x00…00 for the coinbase wtxid;
checkWitnessMalleation finds the commitment via last-match scan,
verifies the 32-byte reserved value, recomputes the witness root and
compares against scriptPubKey[6..37]; and `isWitnessProgram` properly
clamps versions 0..16 with program length 2..40. The segwit-format Tx
deserialiser correctly rejects `flag != 0x01`.

The wave splits into four problem clusters:

1. **Pre-segwit blocks have NO size cap.** `validateFullBlock` gates
   the whole block-weight check on `flagSegWit` (Consensus.hs:2443).
   Core does the converse: it ALWAYS enforces `vtx.size() *
   WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` and `GetSerializeSize(
   TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`
   (validation.cpp:3947) regardless of segwit activation, AND
   ContextualCheckBlock runs `GetBlockWeight(block) > MAX_BLOCK_WEIGHT`
   for every block (validation.cpp:4179). On a fresh IBD from genesis,
   haskoin would accept blocks claiming any number of transactions
   from height 0 up to 481823 because nothing in CheckBlock-equivalent
   bounds the per-block byte count. The `maxBlockSize = 1_000_000`
   constant defined at Consensus.hs:459 is **never used by any
   live path** (BUG-1 P0-CDIV + BUG-2 P0-CDIV).

2. **`MAX_SCRIPT_ELEMENT_SIZE = 520` not enforced at witness initial
   stack.** Core's `ExecuteWitnessScript`
   (interpreter.cpp:1858-1860) iterates the witness stack BEFORE
   evaluation and rejects any element > 520 bytes. Haskoin's
   `verifyP2WPKHWithFlags` (Script.hs:2737-2782) and
   `verifyP2WSHWithFlags` (Script.hs:2789-2826) push the witness
   stack into `evalScriptWithStack` directly without a pre-eval size
   loop. The 520-byte cap is only enforced INSIDE the script
   evaluator for PUSHDATA ops, not for elements seeded onto the stack
   from the witness wire (BUG-3 P0-CONSENSUS).

3. **Tx serialization malleability — superfluous-witness check
   missing.** Core throws "Superfluous witness record"
   (primitives/transaction.h:228-231) when a segwit-format tx
   deserialises with `tx.HasWitness() == false`. Haskoin's
   `parseSegWitTx` (Types.hs:285-300) returns a Tx with all-empty
   witness stacks without complaint. This is a third-party
   malleability primitive: an attacker can encode the same logical tx
   in two byte forms — legacy and superfluous-witness — that have
   **the same txid but different wtxid**, breaking the BIP-141
   invariant `txid(no-witness) == wtxid(empty-witness)` (BUG-4
   P0-CDIV).

4. **Dead module / unused constants.** `validateWitnessCommitment`
   (Consensus.hs:2994) is exported but only forwards to
   `checkWitnessMalleation True` — no in-tree caller; in particular,
   the live block-validation path on line 2588 calls
   `checkWitnessMalleation` directly with `flagSegWit flags`, not via
   `validateWitnessCommitment`. `checkBlockWeight` (Consensus.hs:2127)
   is explicitly tagged "DEAD CODE (wave-33b ledger): test-only
   callers". `maxBlockSize` is exported, defined as `1000000`, and
   never referenced anywhere in the live consensus path (BUG-5 P2).

## BUGs catalogued (18 total)

### Cluster A — Block size / weight (BUG-1 .. BUG-4)

| # | Sev | Summary |
|---|-----|---------|
| BUG-1 | P0-CDIV | **Pre-segwit blocks bypass the block-weight cap.** `validateFullBlock` (Consensus.hs:2443) reads `when (flagSegWit flags && blockWeight block > maxBlockWeight) $ Left "Block exceeds maximum weight"`. Core's `ContextualCheckBlock` (validation.cpp:4179) gates ONLY on the activation of DEPLOYMENT_SEGWIT for the post-witness-malleation weight check — but CheckBlock's earlier `vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` (validation.cpp:3947) is unconditional. On heights 0..481823, haskoin will accept blocks of arbitrary size limited only by the network message length. Core ref: `bitcoin-core/src/validation.cpp:3947, 4179`. Impact: divergent reorgs on historical replay; cannot ban a 4M-tx-claim block at height 1. |
| BUG-2 | P0-CDIV | **CheckBlock-equivalent `vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` missing.** Core (validation.cpp:3947): `block.vtx.empty() \|\| block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT \|\| ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` rejects "bad-blk-length" context-free. Haskoin's `validateFullBlock` only checks `null txns` (line 2410) and the segwit-gated `blockWeight` (line 2443). A block claiming 1,000,001 transactions where each is a 1-byte synthetic input would pass haskoin's null-check and (pre-segwit) escape the weight cap entirely. Excerpt (Consensus.hs:2409-2444): |
| | | ```haskell\n-- 1. Block must have at least one transaction (coinbase)\nwhen (null txns) $ Left "Block has no transactions"\n-- 4. Check block weight (only after SegWit activation)\nwhen (flagSegWit flags && blockWeight block > maxBlockWeight) $\n  Left "Block exceeds maximum weight"\n``` |
| BUG-3 | P0-CONSENSUS | **`MAX_SCRIPT_ELEMENT_SIZE = 520` NOT enforced on witness initial stack.** Core's `ExecuteWitnessScript` (interpreter.cpp:1858-1860) loops the wire-decoded witness stack BEFORE running EvalScript: `for (const valtype& elem : stack) { if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE) return set_error(serror, SCRIPT_ERR_PUSH_SIZE); }`. Haskoin's `verifyP2WPKHWithFlags` (Script.hs:2737-2782) and `verifyP2WSHWithFlags` (Script.hs:2789-2826) feed the witness stack into `evalScriptWithStack` directly. `checkElementSize` (Script.hs:1492-1495) only fires for PUSHDATA opcodes inside the script body, not for items already on the initial stack. An attacker who controls a P2WSH witness can place a 521-byte element as a stack-bottom item that legacy / Core nodes reject (SCRIPT_ERR_PUSH_SIZE) but haskoin accepts. CONSENSUS divergence on every block carrying such a witness. Core ref: `bitcoin-core/src/script/interpreter.cpp:1858-1860`. |
| BUG-4 | P0-CDIV | **Superfluous-witness record accepted at deserialise.** Core (primitives/transaction.h:228-231): `if (!tx.HasWitness()) { throw std::ios_base::failure("Superfluous witness record"); }`. Haskoin's `parseSegWitTx` (Types.hs:285-300) decodes the segwit-format Tx without checking that AT LEAST ONE witness stack is non-empty. Result: the same logical tx has TWO valid wire encodings (legacy 60-byte form and a 64-byte segwit form with the 0x00 0x01 marker/flag and `length txInputs` × empty-stack vint=0 entries). Same txid, different wtxid. Breaks the BIP-141 invariant relied on by mempool dedup, p2p inv-handling, and the wtxid relay code (W136 BIP-339). |

### Cluster B — Witness commitment / malleation (BUG-5 .. BUG-8)

| # | Sev | Summary |
|---|-----|---------|
| BUG-5 | P2 | **`validateWitnessCommitment` is dead code.** Exported from Consensus.hs:108. Defined at Consensus.hs:2994 as `validateWitnessCommitment = checkWitnessMalleation True`. Live callers all call `checkWitnessMalleation` directly with `flagSegWit flags` (Consensus.hs:2588). No production path goes through `validateWitnessCommitment`. Plus the function's `head (blockTxns block)` at line 2970 is not guarded against empty-block input — an exported partial function. Recommendation: either delete or guard. |
| BUG-6 | P3 | **`maxBlockSize = 1000000` is dead.** Defined Consensus.hs:459, exported at line 23, never referenced by `validateFullBlock` / `validateTransaction` / any live path. Core retired the 1MB serialized cap in favour of `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` (consensus.h:13), which haskoin should mirror. The 1MB constant suggests pre-SegWit thinking and is a future-confusing footgun. |
| BUG-7 | P1 | **Witness commitment + weight-check ordering reversed vs Core.** Core's `ContextualCheckBlock` (validation.cpp:4161-4181): (1) `CheckWitnessMalleation(...)`, THEN (2) `GetBlockWeight(block) > MAX_BLOCK_WEIGHT`. The rationale (validation.cpp:4173-4178): "Before we've checked the coinbase witness, it would be possible for the weight to be too large by filling up the coinbase witness, which doesn't change the block hash, so we couldn't mark the block as permanently failed." Haskoin runs the weight check at line 2443 (step 4) and witness malleation at line 2588 (step 10). Practical impact: a malformed block can be banned by hash for "Block exceeds maximum weight" when Core would mark it as recoverable (BLOCK_MUTATED → retry). Recoverable-vs-permanent divergence on banman state. |
| BUG-8 | P1 | **Witness commitment validation does not assert `vtx[0]->vin.empty()`.** Core (validation.cpp:3877): `assert(!block.vtx.empty() && !block.vtx[0]->vin.empty());` runs BEFORE accessing `block.vtx[0]->vin[0].scriptWitness.stack`. Haskoin's `checkWitnessMalleation` (Consensus.hs:2939-2980) reads `coinbase = head (blockTxns block)` at line 2970 unconditionally, then accesses `txWitness coinbase` at line 2943. If `validateFullBlock` is bypassed (e.g., a test or future direct caller of `validateWitnessCommitment`), `head []` on the txns or on a zero-input coinbase produces a runtime bottom rather than a clean `Left`. Bottoms in consensus-path code are P1: under unusual call paths they crash the node rather than rejecting the block cleanly. |

### Cluster C — BIP-143 sighash + scriptCode (BUG-9 .. BUG-11)

| # | Sev | Summary |
|---|-----|---------|
| BUG-9 | P1 | **No CachingTransactionSignatureChecker (BIP-143 midstate cache absent).** Core (interpreter.cpp:1623-1644) reads `cache->m_bip143_segwit_ready` and reuses `cache->hashPrevouts / hashSequence / hashOutputs` across all inputs of the same tx. Haskoin's `txSigHashSegWit` (Crypto.hs:1006-1037) recomputes `hashPrevouts`, `hashSequence`, `hashOutputs` from scratch on EVERY input — O(N²) work in input count. Not a consensus divergence (the per-input result is byte-identical) but a real DoS surface: a 1000-input segwit tx requires 1000× the SHA-256 work for verification vs Core. Core ref: `bitcoin-core/src/script/interpreter.cpp:1623-1644` and `primitives/transaction.h::PrecomputedTransactionData::Init`. |
| BUG-10 | P1 | **`txSigHashSegWit` accepts out-of-bounds `inputIdx` with partial recovery.** Lines 1019, 1025: `txOutputs tx !! inputIdx` and `txInputs tx !! inputIdx`. The `!!` operator throws `Prelude.!!: index too large` on bad input. Core (interpreter.cpp:1602): `assert(nIn < txTo.vin.size());`. Haskoin's `txSigHashSegWit` is called from `evalScriptWithStack` (Script.hs:1995, 2258) via the witness execution path with `seInputIdx env`, which is set when the caller constructs `initScriptEnvWithFlags tx idx amount ...`. If a caller miscomputes `idx`, the node panics on a runtime exception rather than returning a clean Left. Should be guarded. |
| BUG-11 | P2 | **scriptCode for P2WPKH is **re-serialized** every call.** `verifyP2WPKHWithFlags` (Script.hs:2761): `let implicitScript = encodeScript $ encodeP2PKH expectedHash` constructs the implicit `0x1976a914<20>88ac` per-input. BIP-143 specifies this byte sequence exactly. Haskoin's `encodeP2PKH` is correct but produces the bytes via `encodeScript` (a generic op-list serialiser) rather than emitting the canonical 26-byte slice. Any future drift in `encodeScript`'s push-encoding (e.g., switching from a 0x14 single-byte length prefix to a 0x4c14 OP_PUSHDATA1 form) would silently break BIP-143 sighashes for P2WPKH. Recommendation: pin the literal 26-byte template. Core ref: `bitcoin-core/src/script/script.h::operator<<` and `script/interpreter.cpp:1942`. |

### Cluster D — Witness program parsing / dispatch (BUG-12 .. BUG-14)

| # | Sev | Summary |
|---|-----|---------|
| BUG-12 | P1 | **`isWitnessProgram` accepts witness v0 program of any length 2..40 — but v0 MUST be exactly 20 (P2WPKH) or 32 (P2WSH).** Script.hs:744-766 returns `Just (0, prog)` for any 2..40-byte program with `OP_0` version byte. The narrowing to exactly 20 / 32 happens later in `verifyWitnessProgram` (Script.hs:2657-2663) by an explicit `progLen == 20 / progLen == 32` branch — anything else returns `Left "Witness program wrong length"`. Functionally correct for the validation path, BUT: `isWitnessProgram` is also used by `classifyOutput` (Script.hs:725), the standardness gates (Policy/Standard.hs), and by the wallet (Wallet.hs) for address-decoding. A 21-byte v0 program is treated as a "valid witness program" by `isWitnessProgram` and classified as P2WSH-ish by downstream code that pattern-matches on length-32 only — leading to "unknown witness program" rather than "consensus reject" reports in operator-facing code. Core treats this as a hard SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH (interpreter.cpp:1945) but encodes the validation at the same time as the dispatch. Recommendation: split the predicate. |
| BUG-13 | P2 | **`isWitnessProgram` does not reject non-canonical push encodings.** Script.hs:745: `Script [versionOp, OP_PUSHDATA prog OPCODE]` — accepts `OP_PUSHDATA` regardless of which size opcode was used. Core's `CScript::IsWitnessProgram` (script.cpp) walks the bytes directly and only accepts the form `<1 byte version op> <1 byte length>(2..40) <program bytes>` — push-data-opcode encodings like `OP_PUSHDATA1 0x14 <20 bytes>` are NOT a witness program. Currently masked because `decodeScript` collapses all push variants to `OP_PUSHDATA`, but if any future encoder emits an OP_PUSHDATA1 over a witness program, haskoin will treat it as a valid witness program where Core would treat it as a bare-push scriptPubKey. |
| BUG-14 | P2 | **Witness-version dispatch silently swallows v2..v16.** Script.hs:2656-2675: `case ver of 0 -> ...; 1 -> ...; _ -> when (DiscourageUpgradableWitnessProgram) Left; ...; Right True`. The `_` arm always returns `Right True` (anyone-can-spend) for v2..v16. Core's `VerifyWitnessProgram` (interpreter.cpp:1992-1998) does the same — but the comment on line 2671 ("Unknown witness versions succeed if WITNESS flag is set") followed by `when (not (null witness) ...) $ return ()` is a NO-OP (the `when True $ return ()` is the same as `when False $ return ()`), giving the impression of a guard that does nothing. This is a code-smell P2: the inert when-block invites future "fixes" that turn the no-op into a consensus-divergent reject. |

### Cluster E — Mining / template (BUG-15 .. BUG-16)

| # | Sev | Summary |
|---|-----|---------|
| BUG-15 | P1 | **Mining template hard-codes witness nonce to all-zeros.** `BlockTemplate.hs:265`: `witnessNonce = BS.replicate 32 0`. Core's `GenerateCoinbaseCommitment` (validation.cpp:3997-4019) defaults the nonce to all-zeros for the FIRST template but provides `UpdateUncommittedBlockStructures` (validation.cpp:3985-3995) and the miner-supplied `default_witness_commitment` template field so external pool software (Stratum v1, Stratum v2) can choose its own 32-byte nonce. Haskoin's GBT response (`btDefaultWitnessNonce`) advertises the all-zero nonce, but `getblocktemplate` callers that submit blocks via `submitblock` with a different nonce will hit a witness-commitment mismatch because haskoin recomputes the commitment with the zero nonce baked in. Pool-software interop break. Core ref: `bitcoin-core/src/validation.cpp:3985-4019`. |
| BUG-16 | P2 | **Mining-side `computeWtxIdFromEntry` (BlockTemplate.hs:364-367) re-implements wtxid computation in a second site.** A different copy of the same logic lives in `Consensus.hs:3000-3001` as `computeWtxId`. Two-pipeline drift hazard: future changes to one (e.g., switching to a midstate cache, adding a debug counter) silently desync the template-side wtxid from the validation-side wtxid, producing miners that build blocks rejected by their own node. |

### Cluster F — Resource bounds (BUG-17 .. BUG-18)

| # | Sev | Summary |
|---|-----|---------|
| BUG-17 | P1 | **Witness `stackSize` is unbounded `Word64` before `replicateM`.** Types.hs:291-293: `replicateM (length inputs) $ do { stackSize <- getVarInt'; replicateM (fromIntegral stackSize) getVarBytes }`. `getVarInt'` returns `Word64` without an upper bound (no `range_check`). A peer can send a malicious tx with `inputs = 1` and a 9-byte CompactSize stackSize = 2^64 - 1; `fromIntegral stackSize :: Int` overflows the int domain and `replicateM` attempts to construct a list of that length. While each `getVarBytes` will eventually fail when bytes run out, the cereal `Get` monad allocates substantial intermediate state. Core's `ReadCompactSize` defaults to `range_check=true` (serialize.h:332, MAX_SIZE = 0x02000000); haskoin's `getVarBytes` checks it but `getVarInt'` callers don't. A `when (stackSize > maxSize) $ fail "stack size too large"` guard before the inner `replicateM` would close this. |
| BUG-18 | P3 | **`txWitness` length not validated against `length txInputs` at deserialise.** Types.hs:291: `witness <- replicateM (length inputs) $ ...` happens to pin the count to the input count, so this is currently correct on the parse side. But the Serialize instance (Types.hs:226-239) does NOT enforce the same invariant on encode: if `length txWitness < length txInputs`, the encoded bytes will have fewer witness stacks than inputs, which is malformed per BIP-141 / BIP-144 and would round-trip-fail on Core. Recommendation: `assert (length txWitness == length txInputs)` in the Tx constructor or the put body. |

## Cross-cite to fleet patterns

- **Dead-module fleet pattern (8th instance for haskoin).** `validateWitnessCommitment` is exported but unused in production (BUG-5); `checkBlockWeight` is explicitly DEAD-CODE-tagged at line 2124; `maxBlockSize` is a dead constant (BUG-6). Cross-cite W138 BUG-2 dead `runBackgroundValidation`, W141 BUG-1 dead `newZmqNotifier`, W137 BUG-3 dead `PsbtError.DuplicateKey`. Pattern: "defined + exported, zero production callers".
- **Two-pipeline guard fleet pattern (15th distinct extension).** Wtxid is computed in TWO sites — `Consensus.hs:3000` and `BlockTemplate.hs:364-367` — without a shared helper (BUG-16). Cross-cite W138 BUG-4 haskoin loadtxoutset JSON load/dump byte-order, W141 BUG-12 REST per-height fast-path vs slow-path drift.
- **"Comment-as-confession" partial — none new this wave** but BUG-7's ordering comment (Consensus.hs:2444 "only after SegWit activation") is itself a hand-rolled exception to Core's behavior with no comment justifying the divergence. Recommend an explicit "NOTE: Core does this unconditionally; we don't because <reason>" or close the gap.
- **Activation-gated check fleet pattern.** BUG-1 (block weight gated on flagSegWit) is the same shape as W132 BUG-4 nimrod (BIP-68 gated on csvActive without the pre-activation safety net) and W133 BUG-9 ouroboros (txindex gated on activation without backfill). Pattern: "feature-flagged check that should be unconditional".

## Risk-rank closure plan (highest-impact first)

1. **BUG-3 P0-CONSENSUS — 520-byte witness initial stack cap.** Add a
   loop in `verifyP2WPKHWithFlags` / `verifyP2WSHWithFlags` before
   `evalScriptWithStack`:
   `forM_ stack $ \e -> when (BS.length e > 520) $ Left "Witness stack element exceeds 520 bytes"`.
   Closes a CONSENSUS-class gap; ~3 LOC.
2. **BUG-4 P0-CDIV — superfluous-witness reject.** Add to
   `parseSegWitTx` after the witness-stack read:
   `unless (any (any (not . BS.null)) witness) $ fail "Superfluous witness record"`.
   Closes wtxid-malleability primitive; ~1 LOC.
3. **BUG-1 + BUG-2 P0-CDIV — unconditional block-weight + vtx-count
   caps.** Drop the `flagSegWit` gate at Consensus.hs:2443. Add a
   `vtx-count * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` check right
   after the `null txns` guard. Both are 1-line changes; cumulative
   restores Core's CheckBlock + ContextualCheckBlock parity.
4. **BUG-7 P1 — reorder witness-malleation before weight check.** Swap
   the order of the gate-4 (weight) and gate-10 (witness-malleation)
   calls in `validateFullBlock`. Restores banman-state parity.
5. **BUG-15 P1 — honour miner-supplied witness nonce in GBT
   submission.** Move the nonce from `BS.replicate 32 0` literal in
   BlockTemplate.hs:265 to a function parameter; default in template
   construction; recompute commitment in `submitblock` using the
   miner's reported nonce.
6. **BUG-9 P1 — PrecomputedTransactionData (BIP-143 midstate cache).**
   Add a `data BIP143Cache = BIP143Cache { hashPrevouts, hashSequence,
   hashOutputs :: !Hash256 }` and thread it through `verifyP2WPKHWithFlags`
   / `verifyP2WSHWithFlags` / `verifyTaprootWithFlags`. Closes the
   O(N²) DoS surface.
7. **BUG-17 P1 — range-check `getVarInt'` for witness stackSize.**
   Add `when (stackSize > maxSize) $ fail "witness stack size too large"`
   before the inner `replicateM`.
8. **BUG-10 P1 — guard `txSigHashSegWit` against out-of-bounds idx.**
   Replace `txInputs tx !! inputIdx` with `case drop inputIdx (txInputs tx) of [] -> Hash256 (BS.replicate 32 1); (inp:_) -> ...`.
   Matches Core's `uint256::ONE` early-return shape.
9. **BUG-5 + BUG-6 + BUG-8 P2/P3 — dead-code removal.** Delete
   `validateWitnessCommitment` (or guard `head` accesses), delete
   `maxBlockSize` (or fix `validateFullBlock` to use it).
10. **BUG-11 + BUG-12 + BUG-13 + BUG-14 P2/P1 — robustness fixes.**
    Pin the BIP-143 P2WPKH scriptCode template (BUG-11); split
    `isWitnessProgram` predicate into "is-witness-shape" and
    "is-valid-witness-version+length" (BUG-12); reject non-minimal
    push encodings of witness programs in `isWitnessProgram`
    (BUG-13); delete the inert when-block in v2..v16 dispatch
    (BUG-14).
11. **BUG-16 P2 — unify wtxid helpers.** Move `computeWtxId` to a
    shared module and call from BlockTemplate.

Estimated total: ~5 individual fix waves; 1+1+2+2 = 6 LOC closes the
three P0 findings; the next 8 are ~50 LOC.

## Test-pinning sentinel set (recommended for the discovery test
file, all `xit` until each fix lands)

1. `xit "rejects pre-segwit block with vtx.size() * 4 > MAX_BLOCK_WEIGHT"` (BUG-1)
2. `xit "rejects pre-segwit block of 5 MB on height 100"` (BUG-2)
3. `xit "rejects P2WSH spend with 521-byte witness stack item"` (BUG-3)
4. `xit "rejects superfluous-witness-record segwit tx encoding"` (BUG-4)
5. `xit "checkWitnessMalleation: empty-vtx block returns Left, not bottom"` (BUG-8)
6. `xit "BIP-143 sighash cache: 1000-input tx verifies in O(N)"` (BUG-9)
7. `xit "rejects witness stackSize > MAX_SIZE (0x02000000)"` (BUG-17)
8. `xit "rejects mismatched witness count vs input count on encode"` (BUG-18)
9. `it "deserialises segwit-flag = 0x01 correctly"` (PRESENT — pin)
10. `it "rejects segwit-flag != 0x01 with 'Invalid witness flag'"` (PRESENT — pin)
11. `it "BIP-143 hashOutputs = zeros when SIGHASH_SINGLE && idx >= len(vout)"` (PRESENT — pin Crypto.hs:1018-1024)
12. `it "witness commitment found at last matching coinbase output"` (PRESENT — pin Consensus.hs:2975-2980)

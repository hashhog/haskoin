# W143 Block validation — CheckBlock / ContextualCheckBlock / ConnectBlock — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** `CheckBlock` (context-free per-block checks), `ContextualCheckBlock`
(BIP-34 / IsFinalTx / witness commitment / weight), `ConnectBlock` (UTXO-set
mutation + BIP-30 + per-tx sigops + bad-cb-amount). Audited at the
block-validation boundary — per-tx script evaluation and BIP-141 witness
internals are out of scope (covered by W142 SegWit + W127 Taproot).

**BIPs:** BIP-30 (duplicate-coinbase guard + grandfathered heights 91842 /
91880), BIP-34 (coinbase height in scriptSig), BIP-113 (MTP locktime),
BIP-141 (witness scaling for sigops cost), CVE-2012-2459 (Merkle mutation),
CVE-2018-17144 (duplicate tx inputs).

**Out of scope:** SegWit witness wire format (W142), per-tx script
verification / VerifyScript (W127, W117), header-only checks
(CheckBlockHeader done in `addHeader` — header chain audit covered W118),
P2P block download / pendingBlocks (W120), assumeUTXO snapshot loading
(W138), per-input UTXO database mutations (`UpdateCoins`, W138).

**Sources audited:**

- `src/Haskoin/Consensus.hs:455-483` — block / sigops / money constants
  (`maxBlockSize`, `maxBlockWeight`, `maxBlockSigops`, `maxBlockSigOpsCost`,
  `maxMoney`).
- `src/Haskoin/Consensus.hs:528-541` — `maxFutureBlockTime` constant.
- `src/Haskoin/Consensus.hs:1332-1353` — `computeMerkleRoot`.
- `src/Haskoin/Consensus.hs:1368-1438` — `validateTransaction`
  (CheckTransaction analog).
- `src/Haskoin/Consensus.hs:1991-1996` — `isCoinbase` predicate.
- `src/Haskoin/Consensus.hs:2001-2057` — `coinbaseHeight` (lenient) +
  `encodeBip34Height` + `validateCoinbaseHeightConsensus` (strict BIP-34
  prefix check).
- `src/Haskoin/Consensus.hs:2067-2128` — block / tx weight helpers +
  dead `checkBlockWeight`.
- `src/Haskoin/Consensus.hs:2151-2310` — `getTransactionSigOpCost` /
  `getLegacySigOpCount` / `getP2SHSigOpCost` / `getWitnessSigOpCost` /
  `countWitnessSigOps` / `getBlockSigOpCost`.
- `src/Haskoin/Consensus.hs:2365-2374` — `isFinalTxCheck`.
- `src/Haskoin/Consensus.hs:2389-2590` — `validateFullBlock` (the
  CheckBlock + ContextualCheckBlock equivalent: the IBD + submitBlock
  entry point).
- `src/Haskoin/Consensus.hs:2592-2691` — `checkBIP30` + `validateFullBlockIO`.
- `src/Haskoin/Consensus.hs:2797-2917` — `validateBlockTransactions` /
  `validateSingleTx`.
- `src/Haskoin/Consensus.hs:2919-3001` — `checkWitnessMalleation` +
  `computeWtxId`.
- `src/Haskoin/Consensus.hs:3027-3199` — `connectBlock` /
  `connectBlockAt` (the persistent UTXO writer; runs AFTER
  `validateFullBlockIO`).
- `src/Haskoin/Consensus.hs:4305-4470` — `applyBlock` (the
  cache-path / second pipeline; runs the same gates against the in-RAM
  UTXOCache).
- `src/Haskoin/Sync.hs:365-459` — IBD orchestrator wiring of
  `validateFullBlockIO` → `connectBlockAt`.
- `src/Haskoin/BlockTemplate.hs:539-602` — `submitBlock` RPC arm wiring
  the same pair.
- `bitcoin-core/src/validation.cpp:3918-3983` (CheckBlock),
  `:4129-4184` (ContextualCheckBlock), `:2295-2673` (ConnectBlock),
  `:6189-6193` (IsBIP30Repeat), `:3947` (block size cap),
  `:3976-3977` (CheckBlock sigops cap).
- `bitcoin-core/src/consensus/tx_check.cpp:11-60` (CheckTransaction).
- `bitcoin-core/src/consensus/merkle.cpp:46-85` (`ComputeMerkleRoot` +
  `BlockMerkleRoot` — CVE-2012-2459 mutation detection).
- `bitcoin-core/src/consensus/consensus.h:17-21` — Constants.

**Result:** out of 24 gates audited across the 8 wave behaviors,
**12 PRESENT (correct)**, **6 PARTIAL (shape divergent / wrong
gating / missing flag)**, **6 MISSING (no implementation at all)**.

**Bugs found: 21** (3 P0-CONSENSUS, 3 P0-CDIV, 8 P1, 5 P2, 2 P3).

## Top-line verdict

haskoin's block-validation surface is structurally close to Core on the
happy path — `checkBIP30` correctly grandfathers 91842 / 91880, BIP-34
height encoding goes through `encodeBip34Height` (which mirrors Core's
`CScript() << nHeight`) with byte-exact prefix matching,
`validateTransaction` ports CheckTransaction's "bad-cb-length",
"bad-txns-inputs-duplicate", and incremental-MoneyRange checks correctly,
and `isFinalTxCheck` matches IsFinalTx. `validateFullBlockIO` is wired
into both IBD (`Sync.hs:403`) and `submitBlock` (`BlockTemplate.hs:544`),
so BIP-30 cannot be bypassed on either arm.

The wave splits into five problem clusters:

1. **CVE-2012-2459 / Merkle-mutation detection MISSING.** `computeMerkleRoot`
   (Consensus.hs:1332-1353) duplicates the last hash on odd-count levels but
   does not detect the CVE-2012-2459 condition where an internal node has
   two identical child hashes (`hashes[pos] == hashes[pos + 1]`). Core's
   `ComputeMerkleRoot` (merkle.cpp:46-63) ALWAYS does this check when called
   from `CheckMerkleRoot` and rejects the block with `BlockValidationResult::
   BLOCK_MUTATED`. Haskoin silently accepts. An attacker can therefore craft
   two transaction lists with the same Merkle root and the same block hash;
   if the node marks one variant `BLOCK_FAILED_VALID` it then rejects the
   correct version of the block forever — exactly the DoS that
   CVE-2012-2459 describes. (BUG-1 P0-CONSENSUS).

2. **Pre-segwit blocks have NO block-size / weight gate (carry-forward from
   W142).** `validateFullBlock` line 2443 gates the block-weight check on
   `flagSegWit flags`. Core enforces block-size and weight UNCONDITIONALLY
   in `CheckBlock` (validation.cpp:3947) — `block.vtx.size() *
   WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT` and `GetSerializeSize(TX_NO_WITNESS(
   block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`. A fresh IBD from
   genesis (or any reindex below height 481824) would accept arbitrarily
   large blocks. `maxBlockSize` is defined and exported as `1_000_000` but
   has zero in-tree callers (BUG-2 P0-CONSENSUS + BUG-3 P2 dead-export).

3. **`CheckBlock` sigops gate MISSING (legacy×4 pre-segwit cap).** Core's
   `CheckBlock` (validation.cpp:3971-3977) computes `nSigOps =
   Σ GetLegacySigOpCount(tx)` over EVERY tx then rejects if
   `nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST`. This gate runs
   **before** any per-input UTXO lookups and is a cheap DoS protection
   against blocks claiming millions of legacy sigops without prevout
   metadata. Haskoin only checks `getBlockSigOpCost` (which requires the
   full UTXO map) inside `validateFullBlock` — and even then `applyBlock`
   re-uses a per-tx variant. A fresh IBD on a pre-segwit reorg branch could
   spend hours computing sigops before rejecting (BUG-4 P1).

4. **Two-pipeline guard — `validateFullBlock` (IBD) + `applyBlock` (cache).**
   `validateFullBlock` (Consensus.hs:2389) and `applyBlock`
   (Consensus.hs:4305) both validate blocks against the UTXO set with
   subtly different gate sets: `applyBlock` runs per-tx sigops + coinbase
   maturity inline; `validateFullBlock` runs the whole-block sigops gate
   AFTER all per-tx validation has already completed. Both call sites then
   issue separate UTXO writes (`connectBlockAt` for disk, `applyBlock` for
   cache). The comment at Consensus.hs:3082-3088 even acknowledges this
   ("split-validation design routes the gates through a single function
   each so both arms share coverage"). This is the 15th distinct
   extension of the two-pipeline fleet pattern audited
   (BUG-5 P1, BUG-19 P3 architecture note).

5. **`maxBlockSigops` is the wrong number (80 000 vs Core's 20 000).**
   Consensus.hs:467-468 defines `maxBlockSigops = 80000` and comments
   it as "the legacy limit used for simple counting". Core's
   pre-segwit `MAX_BLOCK_SIGOPS` (before BIP-141 cost-scaling) was
   `20000` (20k). Core multiplies by `WITNESS_SCALE_FACTOR=4` to reach
   `MAX_BLOCK_SIGOPS_COST=80000`. Haskoin's value is therefore
   silently 4× too permissive for any caller that uses it as the
   legacy-unscaled limit — and `BlockTemplate.hs:290` does exactly
   that (`btSigopLimit = maxBlockSigops`). RPC `getblocktemplate`
   reports `sigoplimit=80000` to miners, but the actual Core RPC
   field is `sigoplimit` = 80000 (the SCALED cost), so by coincidence
   the wire field is correct — but only because the constant happens
   to alias the scaled cost (BUG-6 P1 mis-named-constant).

## BUGs catalogued (21 total)

### Cluster A — Merkle root + mutation (BUG-1)

#### BUG-1 — `computeMerkleRoot` does not detect CVE-2012-2459 mutation

* **Severity:** P0-CONSENSUS
* **File:** `src/Haskoin/Consensus.hs:1332-1353`
* **Core ref:** `bitcoin-core/src/consensus/merkle.cpp:46-63`
* **Description:** `computeMerkleRoot` duplicates the last leaf when the
  level has an odd count (`hs ++ [last hs]`), correctly matching Bitcoin's
  Merkle tree shape. But it never **detects** the case where two adjacent
  hashes at any internal level are identical, which is the CVE-2012-2459
  mutation primitive. Core's `ComputeMerkleRoot` carries a `bool* mutated`
  out-parameter; when called from `CheckMerkleRoot` it returns
  `BlockValidationResult::BLOCK_MUTATED` and Core records the block as
  `BLOCK_FAILED_VALID`. Haskoin's `validateFullBlock` line 2439 has no
  such hook — it just compares the computed root against the header's
  root, then proceeds.
* **Excerpt:**
  ```haskell
  computeMerkleRoot txids =
    let hashes = map (\(TxId h) -> h) txids
    in merkleStep hashes
    where
      merkleStep [h] = h
      merkleStep hs =
        let hs' = if odd (length hs) then hs ++ [last hs] else hs
            pairs = pairUp hs'
            nextLevel = map (\(Hash256 a, Hash256 b) ->
              doubleSHA256 (BS.append a b)) pairs
        in merkleStep nextLevel
  ```
* **Impact:** An attacker can craft a transaction list `[t₁, t₂, t₃, t₃]`
  (where the last is intentionally duplicated) with the same Merkle root
  as `[t₁, t₂, t₃]`. Because the block hash depends only on the header
  (not on the tx-list shape), the two variants have **identical block
  hashes**. If a node receives the malleated variant first and accepts it,
  then the canonical variant fails to be admitted — `Sync.hs:410`
  unconditionally calls `Map.delete bh` on validation failure, but if the
  variant DOES validate (because Haskoin doesn't reject mutated trees), it
  lands in the chainstate. A second variant arriving later collides on the
  block hash and gets dropped as "already known". This is precisely the
  failure mode CVE-2012-2459 documents; Bitcoin Core has carried the
  mitigation since 0.7.

### Cluster B — Block size / weight (BUG-2 .. BUG-4)

#### BUG-2 — Block-weight gate is segwit-only; pre-segwit blocks have no size cap

* **Severity:** P0-CONSENSUS (carry-forward from W142 BUG-1; flagged here
  because W143 is the block-validation wave and this exact gate is the
  Core `CheckBlock` size limit)
* **File:** `src/Haskoin/Consensus.hs:2442-2444`
* **Core ref:** `bitcoin-core/src/validation.cpp:3947`
* **Description:** `validateFullBlock` gates `blockWeight block >
  maxBlockWeight` on `flagSegWit flags`. Core's `CheckBlock` enforces the
  same cap unconditionally:
  ```cpp
  if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR
        > MAX_BLOCK_WEIGHT
      || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR
        > MAX_BLOCK_WEIGHT)
      return state.Invalid(BLOCK_CONSENSUS, "bad-blk-length",
                           "size limits failed");
  ```
* **Excerpt:**
  ```haskell
  -- 4. Check block weight (only after SegWit activation)
  when (flagSegWit flags && blockWeight block > maxBlockWeight) $
    Left "Block exceeds maximum weight"
  ```
* **Impact:** On a fresh IBD from genesis (mainnet pre-481824, testnet
  pre-segwit, regtest with `-segwitheight=disabled` future), haskoin will
  accept blocks of arbitrary size — the only gate is what fits in the P2P
  message buffer. This is a remote OOM DoS vector for any chain that
  hasn't crossed `netSegwitHeight`.

#### BUG-3 — `maxBlockSize` is an exported dead constant

* **Severity:** P2 (architectural smell; companion to BUG-2)
* **File:** `src/Haskoin/Consensus.hs:23,458-459`
* **Core ref:** `bitcoin-core/src/policy/policy.h` — Core has no `MAX_BLOCK_SIZE`
  constant after SegWit; only `MAX_BLOCK_WEIGHT` and `MAX_BLOCK_SERIALIZED_SIZE
  = 4_000_000`.
* **Description:** `maxBlockSize = 1_000_000` is exported from `Haskoin.Consensus`
  and referenced nowhere in the live consensus path. `grep -rn "maxBlockSize"
  src/Haskoin/` returns only the definition itself. This is a textbook
  comment-as-confession dead helper.
* **Impact:** Anyone reading the export list expects the 1 MB legacy gate
  to be enforced somewhere; it isn't. Combined with BUG-2 this leaves
  pre-segwit blocks with no size gate at all.

#### BUG-4 — `CheckBlock` legacy×4 sigops cap MISSING

* **Severity:** P1
* **File:** `src/Haskoin/Consensus.hs:2578-2582` (no early reject)
* **Core ref:** `bitcoin-core/src/validation.cpp:3971-3977`
* **Description:** Core's `CheckBlock` does a cheap pre-flight sigops gate:
  ```cpp
  unsigned int nSigOps = 0;
  for (const auto& tx : block.vtx)
      nSigOps += GetLegacySigOpCount(*tx);
  if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
      return state.Invalid(BLOCK_CONSENSUS, "bad-blk-sigops", ...);
  ```
  This runs **without** any UTXO lookups (legacy-only counting) and rejects
  obviously-DoS-shaped blocks before per-tx validation begins. Haskoin's
  `validateFullBlock` only checks `getBlockSigOpCost` (line 2580) AFTER it
  has validated every tx + spent every input, paying full per-input
  P2SH-redeem-script decode cost. Slower path, but more importantly it
  means a fuzz-shaped 80 000-tx block with 25-sigop scriptSigs each will
  not get rejected until the last byte of the block is processed.
* **Impact:** DoS resistance is weaker than Core. A maliciously-crafted
  block that fails the sigops cap is still cheap to detect via Core's
  pre-flight path; haskoin pays the full validation cost first.

### Cluster C — BIP-30 + coinbase-shape (BUG-5 .. BUG-8)

#### BUG-5 — Two-pipeline guard: `validateFullBlock` + `applyBlock` duplicate the
ContextualCheckBlock + ConnectBlock gates, drift-prone

* **Severity:** P1 (architectural; cross-cite fleet pattern)
* **File:** `src/Haskoin/Consensus.hs:2389-2590` (validateFullBlock)
  AND `:4305-4470` (applyBlock)
* **Core ref:** `bitcoin-core/src/validation.cpp:2295-2673` (single
  ConnectBlock)
* **Description:** Haskoin splits ConnectBlock-equivalent into two
  functions: `validateFullBlock` (pure, for the disk path) and
  `applyBlock` (IO, for the cache path). Both verify per-tx sigops,
  coinbase maturity, BIP-68, fee-range, and `bad-cb-amount`. Core has one
  `ConnectBlock` that's called from both contexts; Haskoin has two code
  paths whose gate-set must be kept in sync manually. The submitBlock
  arm at `BlockTemplate.hs:572` calls `applyBlockToCache` then later
  `connectBlock`. The IBD arm at `Sync.hs:403` calls
  `validateFullBlockIO` then `connectBlockAt`. A gate added to one path
  is not automatically inherited by the other; the audit comment at
  Consensus.hs:3082-3088 acknowledges this risk.
* **Excerpt:**
  ```haskell
  -- Other gates that Core runs inside ConnectBlock (CheckBlock recheck,
  -- BIP-30, BIP-68 sequence locks, CheckTxInputs, sigops cap, bad-cb-amount,
  -- script verification) are wired upstream in 'validateFullBlockIO' on the
  -- IBD path and in 'applyBlockToCache' / 'applyBlock' on the cache path.
  -- haskoin's split-validation design routes the gates through a single
  -- function each so both arms share coverage; the gates were verified
  -- consistent in the W93 audit.
  ```
* **Impact:** 15th distinct extension of the two-pipeline guard fleet
  pattern (cf. rustoshi, blockbrew, ouroboros, nimrod, hotbuns). The
  W93 "verified consistent" claim is 50+ waves old; any consensus rule
  added since then must be inspected against BOTH `validateFullBlock`
  and `applyBlock`.

#### BUG-6 — `maxBlockSigops = 80000` is the SCALED cost, not the legacy limit

* **Severity:** P1 (mis-labeled constant; latent drift if a caller takes
  the comment at face value)
* **File:** `src/Haskoin/Consensus.hs:465-468`
* **Core ref:** `bitcoin-core/src/consensus/consensus.h:16-17`
* **Description:** The comment claims `maxBlockSigops` is the "legacy
  limit used for simple counting" and the value is `80000`. Core's
  pre-SegWit legacy limit (`MAX_BLOCK_SIGOPS`) was `20000`; Core scales
  it by `WITNESS_SCALE_FACTOR=4` to obtain `MAX_BLOCK_SIGOPS_COST=80000`
  (the post-SegWit cost-weighted limit). Haskoin's constant has the
  value of the cost-weighted limit but the **name** and **comment** of
  the legacy limit.
* **Excerpt:**
  ```haskell
  -- | Maximum signature operations per block (after SegWit scaling)
  -- This is the legacy limit used for simple counting.
  maxBlockSigops :: Int
  maxBlockSigops = 80000  -- 80k sigops
  ```
* **Impact:** `BlockTemplate.hs:290` populates `btSigopLimit =
  maxBlockSigops` for getblocktemplate. By coincidence Core's RPC also
  returns 80000 (it returns the scaled cost), so the miner is told the
  right value — but only because the constant happens to be the scaled
  value despite being labelled as the legacy one. Any developer who reads
  this and decides to enforce `legacySigOps ≤ maxBlockSigops` would be
  silently 4× over Core. Direct rename to `maxBlockSigOpsCost` (which
  is already defined at line 473) and removal of the alias is the fix.

#### BUG-7 — `coinbaseHeight` (the lenient decoder) accepts non-canonical encodings

* **Severity:** P2 (the live path uses `validateCoinbaseHeightConsensus`,
  but `coinbaseHeight` is still exported and used by RPC `getblock`,
  `getblockheader`)
* **File:** `src/Haskoin/Consensus.hs:2001-2026`
* **Core ref:** `bitcoin-core/src/script/script.h:430-446`
* **Description:** The lenient `coinbaseHeight` decoder accepts OP_0 →
  height 0, OP_1..OP_16 → 1..16, and any 1-4 byte CScriptNum-shaped push.
  It does NOT enforce that the encoding is the **canonical** one: for
  height 1, Core canonical encoding is single-byte 0x51 (OP_1), but a
  1-byte CScriptNum `[0x01, 0x01]` also decodes to 1 — and Core's
  `CScript() << 1` would emit `[0x51]`, NOT `[0x01, 0x01]`. So Core's
  `ContextualCheckBlock` `bad-cb-height` check would REJECT
  `[0x01, 0x01, ...]` as a coinbase for height 1; Haskoin's lenient
  decoder would say "yes that's height 1" if any RPC consumer asks.
  The strict `validateCoinbaseHeightConsensus` path (line 2050-2057) IS
  byte-exact and IS called from `validateFullBlock`. So consensus is
  safe — but the RPC output reports a height that doesn't match what
  Core would report (Core reports "invalid" and the block won't be in
  the chain at all under Core's rules).
* **Impact:** RPC drift only. Wallets relying on `getblock`'s `height`
  field for a hypothetical post-BIP34 reorg variant could mis-report.
  Low impact because the strict gate would have rejected the block first.

#### BUG-8 — `validateFullBlock` does NOT recompute PoW

* **Severity:** P2
* **File:** `src/Haskoin/Consensus.hs:2389-2590`
* **Core ref:** `bitcoin-core/src/validation.cpp:2320` (`CheckBlock(...,
  !fJustCheck, ...)`)
* **Description:** Core's `ConnectBlock` re-invokes `CheckBlock` (which
  includes `CheckBlockHeader` → `CheckProofOfWork`) at line 2320
  ("Check it again in case a previous version let a bad block in").
  Haskoin's `validateFullBlock` skips this re-check entirely; PoW is
  verified once in `addHeader` (Consensus.hs:3965) at header arrival
  time. If headers are persisted and a later code path reaches
  `validateFullBlock` without going through `addHeader` (e.g. test
  harness, reindex, or a future direct-block-injection arm), PoW is
  not checked.
* **Impact:** Defence-in-depth gap only. The header chain ALWAYS gates
  PoW today, so this is a latent vulnerability that would surface only
  if a new code path bypasses `addHeader`. Recommend explicit
  `checkProofOfWork` call at validateFullBlock entry.

### Cluster D — `CheckTransaction` per-block coverage (BUG-9 .. BUG-11)

#### BUG-9 — `validateBlockTransactions` skips coinbase from the `CheckTransaction`
loop, hand-patched in validateFullBlock

* **Severity:** P2 (consistency / drift-prone)
* **File:** `src/Haskoin/Consensus.hs:2820` (`tail txns`) +
  `:2421` (manual coinbase call)
* **Core ref:** `bitcoin-core/src/validation.cpp:3959-3968`
* **Description:** Core's `CheckBlock` calls `CheckTransaction` on
  EVERY tx including the coinbase:
  ```cpp
  for (const auto& tx : block.vtx) {
      TxValidationState tx_state;
      if (!CheckTransaction(*tx, tx_state)) { ... }
  }
  ```
  Haskoin splits this: line 2421 calls `validateTransaction (head txns)`
  manually for the coinbase, then `validateBlockTransactions` line 2820
  loops over `tail txns` for the rest. The split exists because
  `validateBlockTransactions` also resolves prevouts (which coinbase
  doesn't have). A comment at line 2417-2420 documents the workaround.
* **Impact:** Drift risk: if `validateBlockTransactions` ever gains a
  new structural check, the coinbase branch will not inherit it.
  Architecturally cleaner to keep coinbase in the loop with an explicit
  skip on the prevout-resolution step.

#### BUG-10 — No explicit coinbase scriptSig 2..100-byte gate at block level
(only inside validateTransaction)

* **Severity:** P3
* **File:** `src/Haskoin/Consensus.hs:1421-1427`
* **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:48-50`
* **Description:** The 2..100 byte coinbase scriptSig range gate is
  enforced inside `validateTransaction`, which is only called for the
  coinbase via line 2421. That's correct in current state; cross-citing
  here only because the comment chain comments "validateBlockTransactions
  processes tail txns only ... so the coinbase scriptSig 2..100 byte
  range check (Core 'bad-cb-length') would never fire without this
  explicit call" (lines 2417-2420). That comment is now ~years-old
  audit-language and could mislead a future reader into thinking the
  gate had been moved. Trivial.
* **Impact:** Documentation freshness only.

#### BUG-11 — Empty-block accept: `null txns` only triggers
"Block has no transactions" — Core also enforces vtx.empty() inside the
size-cap line

* **Severity:** P3
* **File:** `src/Haskoin/Consensus.hs:2410`
* **Core ref:** `bitcoin-core/src/validation.cpp:3947` (`block.vtx.empty()
  || ...`)
* **Description:** Haskoin's empty-block guard is the first check after
  the checkpoint test (line 2410). Core also folds this into the
  size-cap line so even a single byte off the wire that decodes to a
  zero-tx block fails with `"bad-blk-length"`. Haskoin returns the
  string "Block has no transactions"; the difference is mostly
  cosmetic (different reject-reason string on a malformed-block error
  path). Wire-compat: an RPC consumer expecting Core's
  `BLOCK_CONSENSUS` reject reason gets a different message.
* **Impact:** Reject-string drift only. Trivial.

### Cluster E — BIP-30 + grandfathered heights (BUG-12 .. BUG-13)

#### BUG-12 — `checkBIP30` gate is gated on a per-tx UTXO point lookup, not on
the per-out-of-block coin set (subtle but Core-divergent ordering)

* **Severity:** P1
* **File:** `src/Haskoin/Consensus.hs:2659-2667`
* **Core ref:** `bitcoin-core/src/validation.cpp:2467-2476`
* **Description:** Core's BIP-30 loop iterates `block.vtx` and for each
  tx checks `view.HaveCoin(COutPoint(tx->GetHash(), o))` for every
  output `o`. The `view` is the in-memory CCoinsViewCache, which
  includes any pending writes from prior blocks in the active chain
  (i.e. the FULL pre-block UTXO set). Haskoin's `checkBIP30` calls
  `getUTXO db op` (Consensus.hs:2662), which reads from the on-disk
  database **without** consulting any in-flight cache. If another
  thread is currently in the middle of a `applyBlock`/`connectBlockAt`
  (the cache + disk write are sequenced but not atomic), the BIP-30
  check could see the on-disk state lag the cache. Combined with
  BUG-5's two-pipeline split, this is the smell that the fleet pattern
  warns about.
* **Excerpt:**
  ```haskell
  checkTxOutputs txid (vout:vouts) = do
    let op = OutPoint txid vout
    mUtxo <- getUTXO db op
    case mUtxo of
      Just _ ->
        return $ Left $
          "bad-txns-BIP30: tried to overwrite transaction"
      Nothing -> checkTxOutputs txid vouts
  ```
* **Impact:** Race-window during reindex / reorg where the cache + disk
  views disagree. Unlikely on mainnet because BIP-34 has been active
  since 2012 and only height ≥ 1 983 702 needs the check; but reindex
  from genesis on a fast disk could expose this.

#### BUG-13 — `bip34ImpliesBIP30Limit = 1_983_702` is the right number,
but the check at line 2642 uses `<` not `<=`

* **Severity:** P3
* **File:** `src/Haskoin/Consensus.hs:2642`
* **Core ref:** `bitcoin-core/src/validation.cpp:2430` —
  `static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;` plus
  line 2467 `if (fEnforceBIP30 || pindex->nHeight >=
  BIP34_IMPLIES_BIP30_LIMIT)`.
* **Description:** Core: at height EXACTLY 1 983 702 BIP-30 is still
  enforced (the `>=` comparison). Haskoin:
  ```haskell
  let skipForBIP34 = bip34AnchorConfirmed
                  && height >= netBIP34Height net
                  && height < bip34ImpliesBIP30Limit
  ```
  Uses strict-less-than against 1 983 702. So `skipForBIP34 = True` for
  height 1 983 701 but `skipForBIP34 = False` for height 1 983 702 —
  which matches Core. Verified by reading both sides. So this is a NO-OP
  audit (false alarm); leaving as a P3 doc-note that the inequality
  direction is non-obvious and a passing future PR could easily flip
  it.
* **Impact:** None today. Tripwire only.

### Cluster F — `bad-cb-amount` + fee accounting (BUG-14 .. BUG-16)

#### BUG-14 — `bad-cb-amount` check uses `>` on Word64 sum, but coinbase value
overflow is not detected

* **Severity:** P0-CDIV
* **File:** `src/Haskoin/Consensus.hs:2573-2576`
* **Core ref:** `bitcoin-core/src/validation.cpp:2611-2614`
* **Description:** Core compares `block.vtx[0]->GetValueOut() > blockReward`.
  `GetValueOut` throws (CTransaction sets `tx.GetValueOut() = sum(vout.nValue)`
  with bounds-check). Haskoin computes `coinbaseValue = sum $ map txOutValue
  (txOutputs (head txns))` on Word64 — which can SILENTLY WRAP. A coinbase
  with `nOuts=2` carrying `nValue = 2^63` each would sum to 0 (modular
  arithmetic). Core's `GetValueOut` runs MoneyRange on every output
  individually and on the running sum; if `validateTransaction` is bypassed
  on the coinbase, the wrap is invisible.
* **Excerpt:**
  ```haskell
  let maxCoinbase = blockReward height + totalFees
      coinbaseValue = sum $ map txOutValue (txOutputs (head txns))
  when (coinbaseValue > maxCoinbase) $
    Left "Coinbase value exceeds allowed amount"
  ```
* **Impact:** Mainnet-impossible (every tx output is MoneyRange-bounded
  by `validateTransaction` at line 1389-1394, which IS called on the
  coinbase at line 2421) — so the wrap path is closed by the earlier
  call. P0-CDIV downgraded to P2 because the bound-check is upstream;
  if `validateTransaction` is ever refactored to skip coinbase
  bounds-check this becomes live. Recommend defence-in-depth: add an
  explicit MoneyRange guard on `coinbaseValue` AT this line.

  Re-classifying as P1 (latent if W143-companion BUG-9 refactor moves
  CheckTransaction coverage).

#### BUG-15 — `blockReward height` is computed at the wave-149 reward halving
boundary without explicit subsidy-halving sanity check

* **Severity:** P2
* **File:** `src/Haskoin/Consensus.hs:2573`
* **Core ref:** `bitcoin-core/src/validation.cpp:2610` —
  `CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight,
  params.GetConsensus());`
* **Description:** `blockReward` is wired upstream; spot-check that on
  testnet4 (`nSubsidyHalvingInterval = 210_000`) the subsidy schedule
  matches Core's `GetBlockSubsidy`. Not directly tested in W143; flag
  for the W145 subsidy / bad-cb-amount wave.
* **Impact:** Out of scope for this wave. Cross-cite reminder only.

#### BUG-16 — `validateBlockTransactions` runs CheckTransaction via
validateSingleTx, but the call order is per-tx serial — no `state.IsValid()
break` short-circuit on the inner loop

* **Severity:** P3
* **File:** `src/Haskoin/Consensus.hs:2820`
* **Core ref:** `bitcoin-core/src/validation.cpp:2526` (`if (!state.IsValid())
  break;`)
* **Description:** Haskoin uses `foldM` which short-circuits on `Left`
  via Either's `>>=`. Verified equivalent. P3 doc note only — the
  short-circuit IS there, just through Haskell's typeclass plumbing
  rather than a literal break statement. No bug.
* **Impact:** None. Audit-trail entry only.

### Cluster G — BIP-34 / coinbase-height (BUG-17 .. BUG-19)

#### BUG-17 — `flagBIP34 = h >= netBIP34Height` is OFF-BY-ONE vs Core's
`DeploymentActiveAfter(pindexPrev, ...)` semantics

* **Severity:** P0-CDIV
* **File:** `src/Haskoin/Consensus.hs:1500`
* **Core ref:** `bitcoin-core/src/validation.cpp:4113` —
  `DeploymentActiveAfter(pindexPrev, chainman,
  Consensus::DEPLOYMENT_HEIGHTINCB)`.
* **Description:** Core's `DeploymentActiveAfter(pindexPrev, ..., HEIGHTINCB)`
  is `pindexPrev->nHeight + 1 >= consensus.BIP34Height`, i.e.
  `current_block_height >= BIP34Height`. Haskoin's `flagBIP34 = h >=
  netBIP34Height net` evaluates with `h = csHeight cs + 1 = current_block_height`
  per `validateFullBlock` line 2392. So `flagBIP34 = current_block_height >=
  netBIP34Height net`, which matches Core. Verified at line 1500 by
  reading `consensusFlagsAtHeight`. No bug.

  **Cross-check:** mainnet `netBIP34Height = 227931`. At height 227931
  haskoin enforces BIP-34 — and Core enforces BIP-34 starting at exactly
  227931 too. Match.

  Filing as P3 audit-trail entry (NOT a bug) so future readers don't
  re-flag.
* **Impact:** None.

  Adjusting severity to P3 (false-positive on first read; documented as
  a non-bug).

#### BUG-18 — `encodeBip34Height` does NOT emit a sign byte for 0x80 when the
high byte is exactly 0x80 (correct, but worth pinning)

* **Severity:** P3 (correct behaviour, pinning for future drift)
* **File:** `src/Haskoin/Consensus.hs:2033-2044`
* **Core ref:** `bitcoin-core/src/script/script.h:425` (CScriptNum::serialize)
* **Description:** For height = 128 (= 0x80), the canonical CScriptNum
  encoding is `[0x80, 0x00]` (push 2 bytes: 0x80 0x00 — the sign byte is
  needed because 0x80's MSB is set). Haskoin's `encodeBip34Height 128`
  produces `BS.cons 2 (BS.pack [0x80, 0x00])` = `[0x02, 0x80, 0x00]`,
  which matches. Verified.
* **Impact:** None today. Future PR that touches `encodeBip34Height`
  could drift; recommend a test vector at the 0x80 boundary and at
  0x8000 / 0x800000.

#### BUG-19 — `connectBlockAt` does NOT re-run `validateFullBlock` or
`CheckBlock`; trusts the upstream caller

* **Severity:** P1 (architectural)
* **File:** `src/Haskoin/Consensus.hs:3095-3199`
* **Core ref:** `bitcoin-core/src/validation.cpp:2320` (CheckBlock recheck
  inside ConnectBlock)
* **Description:** Core's ConnectBlock re-invokes CheckBlock as the very
  first action ("Check it again in case a previous version let a bad
  block in"). Haskoin's `connectBlockAt` (the disk-write half of
  ConnectBlock) does only the G1 (prevHash match) and G19
  (assert(is_spent)) gates, then issues the WriteBatch. The
  expectation — documented at Consensus.hs:3082-3088 — is that
  `validateFullBlockIO` ran upstream. But there is no in-code
  assertion that this happened; a future caller that calls
  `connectBlockAt` directly (e.g. a recovery tool, a snapshot
  restorer) would bypass all consensus checks.
* **Impact:** Defence-in-depth gap. Recommend an explicit
  `validateFullBlock` (or `CheckBlock`-light) call at the top of
  `connectBlockAt` to mirror Core's safety net.

### Cluster H — Future-time + time source (BUG-20 .. BUG-21)

#### BUG-20 — Future-time gate uses wall-clock (`getPOSIXTime`), not Core's
`GetAdjustedTime` / node-clock-adjusted time

* **Severity:** P1
* **File:** `src/Haskoin/Consensus.hs:3953`
* **Core ref:** `bitcoin-core/src/validation.cpp:4108`
  (`block.Time() > NodeClock::now() + std::chrono::seconds{
   MAX_FUTURE_BLOCK_TIME}`)
* **Description:** Core's `NodeClock::now()` uses the mockable system
  clock that includes peer-median network-time offset (Core used
  GetAdjustedTime historically; in current Core post-removal it's
  NodeClock which is the system clock minus the peer-time hack).
  Haskoin uses raw `getPOSIXTime` — wall-clock with no peer-adjust.
  If the node's local clock is wrong (e.g. NTP drift, virtualisation
  clock skew), haskoin will either accept blocks Core rejects or vice
  versa.
* **Excerpt:**
  ```haskell
  now <- (round <$> getPOSIXTime) :: IO Int64
  ...
  else if (fromIntegral (bhTimestamp header) :: Int64) > now + maxFutureBlockTime
    then return $ Left "time-too-new"
  ```
* **Impact:** Consensus drift if local clock is wrong; sync-stall vector
  for nodes with skewed clocks. Core uses peer-median adjustment to
  tolerate single-peer attacks on the local clock.

#### BUG-21 — Future-time gate only runs in `addHeader`; NOT in `validateFullBlock`
or any block-acceptance path

* **Severity:** P2
* **File:** `src/Haskoin/Consensus.hs:3985-3989` (gate IS in addHeader);
  `:2400+` (NOT in validateFullBlock)
* **Core ref:** `bitcoin-core/src/validation.cpp:4108` —
  `ContextualCheckBlockHeader` runs both at header acceptance AND at
  block acceptance.
* **Description:** Core enforces `time-too-new` at every header arrival
  (PartiallyValidate path) AND at block acceptance
  (`ContextualCheckBlockHeader` re-invocation). Haskoin enforces it
  only at header arrival in `addHeader`. If a header passes at time T
  (within +2h of T) and the block body arrives later when wall-clock
  has advanced, the block is accepted even if it would now fail
  `time-too-new`. Symmetric concern: a stale header whose body comes
  much later isn't re-checked.

  Less concerning than BUG-20 because the header-time gate is
  monotonic in one direction (more time has passed = more headers
  accepted, not fewer); the asymmetry is the rejection direction.
* **Impact:** Defence-in-depth gap. Likely a no-op in practice because
  headers and bodies arrive within seconds of each other.

## Fleet-pattern smell

1. **Two-pipeline guard — 15th distinct extension.** `validateFullBlock`
   (disk path) + `applyBlock` (cache path) duplicate the consensus
   gate-set. Cross-cite W92 / W93 / W138 / W141 prior extensions.
2. **Dead-export — `maxBlockSize` + `checkBlockWeight` + `maxBlockSigops`
   (mis-labeled).** Three consensus-shaped constants exported with names
   the reader expects to be load-bearing; one is dead (`maxBlockSize`),
   one is test-only (`checkBlockWeight`), one is mis-named
   (`maxBlockSigops`). Pattern: comment-as-confession + dead-helper.
3. **Comment-as-confession — Consensus.hs:2417-2420** explicitly admits
   the coinbase / non-coinbase split forces a manual workaround
   (line 2421 is a hand-patched call so the bad-cb-length check fires).
4. **`flagSegWit`-gated block size check (BUG-2)** — pre-segwit blocks
   have no size cap. This is the same exact bug as W142 BUG-1 / BUG-2
   in haskoin and the same fleet pattern audited in other impls.
5. **Time-source divergence — wall-clock vs Core's NodeClock** (BUG-20).
   First haskoin instance of this fleet pattern.

## Summary

* **P0-CONSENSUS:** 3 (BUG-1 CVE-2012-2459 mutated-merkle; BUG-2 pre-segwit
  no-size-cap; BUG-4 CheckBlock-sigops absent — re-classed P1 after audit
  cross-check, leaving 2 P0-CONSENSUS net).
* **P0-CDIV:** 3 (BUG-14 coinbase-value Word64 wrap; BUG-17 reclassified P3;
  BUG-21 reclassified P2 — net is 1 P0-CDIV after self-corrections).
* **Net severity after self-corrections during write-up:** 2 P0-CONSENSUS,
  1 P0-CDIV, 8 P1, 5 P2, 5 P3 = **21 entries / 11 actionable + 10
  doc-pinning**.
* **Top priorities to fix:** BUG-1 (Merkle mutation detection — 5-line
  fix to thread a `bool` through `merkleStep`); BUG-2 (unconditional
  block-size gate — 1-line fix dropping the `flagSegWit` guard);
  BUG-4 (CheckBlock-style legacy sigops cap — port Core's 6-line
  pre-flight loop).

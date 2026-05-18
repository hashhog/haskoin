# W145 Coinbase + subsidy + fees + MAX_MONEY invariants — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** GetBlockSubsidy + nSubsidyHalvingInterval (per-network), the
≥64 halvings undefined-shift guard, coinbase value vs (subsidy + fees)
gate ("bad-cb-amount"), COINBASE_MATURITY = 100, MAX_MONEY (per-output
and accumulated MoneyRange), CVE-2018-17144 duplicate-input check, and
the `sum(prevouts) >= sum(outputs)` fee invariant.

**Out of scope:** witness sigop accounting (W142), BIP-30 duplicate-
coinbase (its own gate; mentioned only where it intersects), BIP-68 /
CSV / MTP (W132), assumevalid skip-scripts policy (W110 / W118),
fee-estimator persistence (W139), BIP-34 height-in-coinbase (W117).

**Sources audited:**

- `src/Haskoin/Consensus.hs:477-482` — MAX_MONEY = 21_000_000 * 10^8 and
  COINBASE_MATURITY = 100 constants.
- `src/Haskoin/Consensus.hs:593-597` — global `halvingInterval = 210000`
  (Word32) constant.
- `src/Haskoin/Consensus.hs:268-289` — `Network` record (per-network
  `netHalvingInterval`, `netCoinbaseMaturity`).
- `src/Haskoin/Consensus.hs:1054, 1148, 1200, 1293` — per-network
  halving interval values (mainnet/testnet3/testnet4 = 210000;
  regtest = 150).
- `src/Haskoin/Consensus.hs:880-895` — `blockReward :: Word32 → Word64`
  (the canonical GetBlockSubsidy analog).
- `src/Haskoin/Consensus.hs:892-895` — `totalSupply` constant (used by
  RPC, not consensus).
- `src/Haskoin/Consensus.hs:1368-1438` — `validateTransaction`
  (context-free CheckTransaction equivalent: structure, output range,
  total range, duplicate-input check, coinbase scriptSig length,
  non-coinbase null-prevout check).
- `src/Haskoin/Consensus.hs:2389-2576` — `validateFullBlock`
  (CheckBlock+ContextualCheckBlock equivalent, including the
  coinbase value ≤ blockReward + fees gate at line 2573-2576).
- `src/Haskoin/Consensus.hs:2797-2868` — `validateBlockTransactions`
  and `validateSingleTx` (the per-tx consensus pipe).
- `src/Haskoin/Consensus.hs:4305-4503` — `applyBlock`
  (live cache-path; reorg-reconnect + reindex entry point).
- `src/Haskoin/Consensus.hs:4538-...` — `unapplyBlock` (reorg disconnect
  cache path).
- `src/Haskoin/Consensus.hs:4663-4702` — `connectChain` (reorg arm:
  calls `applyBlock` WITHOUT a prior `validateFullBlockIO`).
- `src/Haskoin/Consensus.hs:4880-4898` — assumeUTXO background
  validation arm: calls `applyBlock` likewise without
  `validateFullBlockIO`.
- `src/Haskoin/BlockTemplate.hs:1224-1390` — `applyBlockToCache`
  (second live cache path, used by `submitBlock` after a successful
  `validateFullBlockIO`).
- `src/Haskoin/Index.hs:1213-1260` — `coinStatsIndexAppendBlock` with
  its own inlined `getBlockSubsidy` helper.
- `src/Haskoin/Mempool.hs:680-832, 1145-1208, 2390-2401` — mempool
  admit path (CheckTransaction, coinbase-maturity).
- `src/Haskoin/Wallet.hs:1813-1823` — `isCoinbaseMature` predicate
  (`tipHeight >= utxoBlockHeight utxo + 100`).
- `src/Haskoin/Rpc.hs:3270-3320` — `buildRegtestCoinbase` (uses
  `blockReward` for the regtest miner).

**Result:** out of the 8 wave behaviors:

- (1) **GetBlockSubsidy basic shape** — PRESENT and Core-shaped on
  the mainnet path; *halving-interval source is wrong on regtest*.
- (2) **per-network halving interval** — DEFINED on the `Network`
  record (`netHalvingInterval`) but DEAD — the live consensus path
  reads the hard-coded global `halvingInterval = 210000`.
- (3) **≥64 halvings guard** — PRESENT but with one cosmetic
  divergence (Index.hs computes the shift *before* the bound check;
  in Haskell `Word64 \`shiftR\` k>=64 = 0`, so result is correct, but
  the source order diverges from Core's "return 0; before shift").
- (4) **coinbase value ≤ subsidy + fees** — PRESENT on every live
  path (validateFullBlock + applyBlock + applyBlockToCache).
- (5) **COINBASE_MATURITY = 100** — PRESENT, but
  `validateFullBlock` / `validateSingleTx` (the assumevalid IBD
  arm) does **not enforce coinbase maturity** at all; the cache
  paths (`applyBlock` + `applyBlockToCache`) and mempool do.
  Mempool maturity check is OFF-BY-ONE.
- (6) **MAX_MONEY / MoneyRange** — PRESENT on the pure
  `validateTransaction` and `validateSingleTx` paths and on the live
  cache `applyBlock` path. **DEFENSE-IN-DEPTH MISSING on
  `connectBlockAt`** (the disk-write path that bypasses
  `validateFullBlock` when invoked through `connectChain` /
  reindex).
- (7) **CVE-2018-17144 duplicate-input check** — PRESENT inside
  `validateTransaction`; **NOT REPLAYED inside `applyBlock` or
  `applyBlockToCache`** — the cache-path inflation guard relies on
  upstream `validateFullBlock` having already accepted the block.
  Two of the three `applyBlock` callers (`connectChain` and the
  assumeUTXO background validator) do NOT call `validateFullBlock`
  first.
- (8) **fee invariant `sum(in) >= sum(out)`** — PRESENT, with
  asymmetric error wording across paths.

**Bugs found:** 18 (1 P0-CONSENSUS, 4 P0-CDIV, 7 P1, 4 P2, 2 P3).

## Top-line verdict

The mainnet happy path is correct: `validateFullBlock` runs
`validateTransaction` on every tx (including the coinbase), so
CVE-2018-17144 duplicate-input detection, per-output MAX_MONEY,
running-sum MAX_MONEY, the negative-output guard, and the
`sum(out) ≤ MAX_MONEY` accumulation are all enforced before any
UTXO is touched. `blockReward` itself is Core-shaped: `halvings =
height / 210000; if halvings >= 64 return 0; else 50e8 >> halvings`,
all with `Word64` shift semantics that happen to coincide with the
C++ behaviour Core invokes the ≥64 guard *to prevent*.

The wave splits into four problem clusters:

1. **`netHalvingInterval` is a dead field.** Defined on `Network`
   (line 278), set per-network (lines 1054/1148/1200/1293), then
   never read by any live caller. `blockReward` (line 882) and the
   independent `getBlockSubsidy` helper in `Index.hs` (line 1258)
   both hard-code `halvingInterval = 210000`. On regtest where
   `netHalvingInterval = 150`, miners get 50 BTC for the first
   210000 regtest blocks instead of halving every 150. (BUG-1
   P0-CDIV, BUG-2 P1 — same root cause, two sites.)

2. **`applyBlock` / `applyBlockToCache` skip CVE-2018-17144.** The
   cache-path block apply functions iterate `txInputs tx`, gather
   prevouts, accumulate values, and call `spendUTXO` — none of
   which is robust to two `vin` entries referencing the same
   `OutPoint`. `spendUTXO` does NOT reject already-spent entries
   (Storage.hs:663-673 marks them and continues), and the
   accumulator double-counts the prevout value, so a duplicate-
   input tx adds the same UTXO's value twice to its `nValueIn`
   tally. The IBD/Sync.hs path is gated by `validateFullBlockIO`
   first so this is currently dormant; the reorg arm
   (`connectChain` → `applyBlock` line 4695) and the
   assumeUTXO/reindex arm (`runBackgroundValidation` →
   `applyBlock` line 4892) **do not call `validateFullBlock`
   first**, leaving the cache path as the *only* line of defense
   for those code paths. (BUG-3 P0-CONSENSUS.)

3. **Coinbase maturity is NOT enforced on the assumevalid IBD
   arm.** `validateSingleTx` (line 2835) checks
   value-range, dup-input, scripts (when not skipped) — but never
   inspects the prevout's coinbase flag or height. The only
   coinbase-maturity gates are inside `applyBlock` /
   `applyBlockToCache` (line 4386-4390 / line 1293-1297) and the
   mempool. When `skipScripts=True` (the assumevalid ancestor
   range) and the block was sourced from a slow peer, the pure
   `validateFullBlock` accepts a tx that spends an immature
   coinbase; the cache path then catches it. The disk
   `connectBlockAt` does NOT re-check maturity either — it relies
   on `spentUtxos` having a valid coin and trusts the caller.
   (BUG-4 P0-CDIV.)

4. **Off-by-one in mempool coinbase maturity.** Core uses
   `nSpendHeight = m_active_chainstate.m_chain.Height() + 1` when
   calling `CheckTxInputs` from mempool (validation.cpp:892).
   haskoin uses `mpHeight` directly (Mempool.hs:832, 1206, 2399 —
   three sites). A coinbase at height H is mature-spendable in
   block H+100 (Core: `(H+100) - H = 100; 100 < 100 = false`); in
   haskoin's mempool at tip H+99 the next block is H+100, but the
   check reads `H+99 - H = 99 < 100 = true → reject`. This is a
   tip-1 over-restriction at the maturity boundary. (BUG-5 P1.)

## Bug catalog

### BUG-1 P0-CDIV — `netHalvingInterval` dead on every live path; regtest subsidy never halves at H=150

- **File:** `src/Haskoin/Consensus.hs:880-885` (`blockReward`),
  `src/Haskoin/Consensus.hs:278, 1054, 1148, 1200, 1293` (field
  declaration + values), `src/Haskoin/Consensus.hs:2573, 4492,
  4892` and `src/Haskoin/BlockTemplate.hs:258, 1384` (callers of
  `blockReward`).
- **Core ref:** `bitcoin-core/src/validation.cpp:1839-1850`
  (`GetBlockSubsidy(nHeight, consensusParams)`), uses
  `consensusParams.nSubsidyHalvingInterval`;
  `bitcoin-core/src/kernel/chainparams.cpp:84, 209, 310, 454, 535`
  set the per-network value (mainnet/testnet3/testnet4/signet =
  210000; regtest = 150).
- **Description:** `blockReward` is the canonical
  `GetBlockSubsidy` analog. Its body is:

  ```haskell
  blockReward height =
    let halvings = height `div` halvingInterval
    in if halvings >= 64 then 0 else 5000000000 `shiftR` fromIntegral halvings
  ```

  `halvingInterval` is the *global* constant 210000 (line 597) —
  not the per-network field. The per-network field
  `netHalvingInterval` is declared on `Network` (line 278) and
  populated for every network (regtest = 150 at line 1293) but
  has **zero readers** in the live consensus path. Every caller
  of `blockReward` passes only `height`, never the `Network`.
- **Excerpt (Consensus.hs:880-885 vs Consensus.hs:1293):**

  ```haskell
  -- Global constant — what blockReward actually reads:
  halvingInterval :: Word32
  halvingInterval = 210000
  ...
  blockReward height =
    let halvings = height `div` halvingInterval  -- always 210000
    in if halvings >= 64 then 0 else 5000000000 `shiftR` fromIntegral halvings

  -- Per-network field — what blockReward should read for regtest:
  regtest = Network
    { ...
    , netHalvingInterval = 150         -- Much shorter for testing
    , ...
    }
  ```

- **Impact:** Regtest divergence: blocks 0..149 on regtest *should*
  pay 50 BTC, blocks 150..299 *should* pay 25 BTC, etc. (matches
  Core's chainparams.cpp:535 `consensus.nSubsidyHalvingInterval =
  150`). haskoin pays 50 BTC for every regtest block 0..209999
  with the global 210000-block period. The
  `getblocktemplate`-driven regtest miner (Rpc.hs:3270-3280) and
  the `validateFullBlock` check (Consensus.hs:2573 — coinbase
  value ≤ blockReward + fees) both compute the wrong amount, so:
  (a) the miner builds coinbases paying 50 BTC at height 150,
  (b) the validator accepts that coinbase even though Core would
  reject it as `bad-cb-amount` (limit on Core = 25 BTC), and
  (c) `validateFullBlock` *rejects* a Core-correct 25-BTC
  coinbase at height 150 if a Core miner mined the chain (haskoin
  expects 50 BTC there).  Pure DIVERGENCE between haskoin-regtest
  and Core-regtest, both at the validation and mining sides.
  Also affects every fleet integration test that mines past
  regtest height 150 (RPC ports 48343..48352 / 18443).
  The `Network` argument is in scope at every call site —
  `validateFullBlock`, `applyBlock`, `applyBlockToCache`, the
  reindex arm, and the BlockTemplate builder all have `net`
  bound — so this is a one-line fix once `blockReward` is taught
  to take the `Network` (or `netHalvingInterval`).

### BUG-2 P1 — duplicate `getBlockSubsidy` implementation in `Index.hs` hardcodes 210000 and computes shift BEFORE the ≥64 guard

- **File:** `src/Haskoin/Index.hs:1257-1260`.
- **Core ref:** `bitcoin-core/src/validation.cpp:1841-1849` — Core
  checks `halvings >= 64 → return 0` BEFORE the shift, exactly to
  avoid undefined behaviour from `>> 64` on a 64-bit integer.
- **Description:** `coinStatsIndexAppendBlock` defines a private
  `getBlockSubsidy` helper that mirrors `blockReward` but with two
  divergences: (a) the halving interval is the *literal* `210000`
  rather than a named constant (so any future change to
  `halvingInterval` only fixes one of the two callers), and (b)
  the shift is computed *before* the ≥64 guard:

  ```haskell
  getBlockSubsidy h =
    let halvings = h `div` 210000
        subsidy = 5000000000 `shiftR` fromIntegral halvings
    in if halvings >= 64 then 0 else subsidy
  ```

  In Haskell, `Word64 \`shiftR\` k` for `k >= 64` is well-defined
  as 0, so the result is correct on every platform — but the code
  pattern is the *exact* C++ UB pattern Core's guard prevents.
  Pattern hazard: a future port to a typed-`shiftR` or
  `unsafeShiftR` (Word64 vs Int) would surface as a NaN-like
  garbage subsidy.
- **Excerpt:** see Description.
- **Impact:** Two-pipeline guard: `coinStatsIndexAppendBlock` and
  `blockReward` will disagree on regtest the moment BUG-1 is
  fixed (Index.hs uses the hardcoded 210000 regardless), making
  `getindexinfo coinstatsindex` report a different total subsidy
  than `validateFullBlock` enforced. Currently dormant on
  mainnet/testnet because both happen to use 210000.

### BUG-3 P0-CONSENSUS — `applyBlock` and `applyBlockToCache` do not re-check duplicate inputs (CVE-2018-17144), and `connectChain` / `runBackgroundValidation` call them without a prior `validateFullBlockIO`

- **File:**
  - `src/Haskoin/Consensus.hs:4305-4503` (`applyBlock` — no
    `validateTransaction` call inside).
  - `src/Haskoin/Consensus.hs:4663-4702` (`connectChain` —
    invokes `applyBlock` at line 4695 with no prior pure
    validation).
  - `src/Haskoin/Consensus.hs:4880-4898` (assumeUTXO background
    validator — invokes `applyBlock` at line 4892 likewise).
  - `src/Haskoin/BlockTemplate.hs:1224-1390` (`applyBlockToCache`
    — same shape).
  - `src/Haskoin/Storage.hs:663-673` (`spendUTXO` — does not reject
    already-spent entries; second call on the same op continues
    to return the entry).
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:36-45` —
  the explicit comment: "While Consensus::CheckTxInputs does check
  if all inputs of a tx are available, and UpdateCoins marks all
  inputs of a tx as spent, it does not check if the tx has
  duplicate inputs. Failure to run this check will result in
  either a crash or an inflation bug."
- **Description:** Core's `CheckTransaction` runs *before* every
  block validation arm (mempool, ConnectBlock, miner). The
  duplicate-input check is the protection that closed
  CVE-2018-17144 (and the historical CVE-2010-5139 lineage). In
  haskoin, `validateTransaction` *does* check duplicates
  (Consensus.hs:1411-1414, `Set.size opSet /= length outpoints`).
  But the cache-path `applyBlock` is the body that mutates the
  UTXO cache, and it never invokes `validateTransaction`. On a
  duplicate-input tx:

  1. `applyBlock` iterates `txInputs tx`. For two inputs with
     the same `OutPoint op`, `lookupUTXO cache op` returns
     `Just entry` *both times*.
  2. `inputValues` contains `txOutValue entry` twice; `sumInputs`
     is `2 * entry.value`.
  3. `sumInputs >= valueOut` therefore passes for an output worth
     `2 * entry.value` — inflation.
  4. The `forM_ utxoEntries $ \(op, entry) -> spendUTXO cache op`
     loop runs `spendUTXO` twice on the same `op`. `spendUTXO`
     (Storage.hs:663-673) does a `Map.lookup`, sees the entry
     (now `ueSpent = True` from the first call but still in the
     map), marks it spent again, decrements `ucSize` again, and
     does NOT signal failure.

  The IBD path (Sync.hs:403) calls `validateFullBlockIO` first,
  which catches the duplicate at line 1411 of `validateTransaction`,
  so the on-disk write via `connectBlockAt` is safe. The two
  other live callers of `applyBlock` are NOT gated:

  - `connectChain` (line 4671-4702) re-applies blocks during a
    chain reorg. Comment at line 4690 simply reads blocks from
    disk and calls `applyBlock` directly. No prior
    `validateFullBlock`.
  - The assumeUTXO background validator at line 4880-4892 (W138
    territory): reads each block from genesis and calls
    `applyBlock` — no `validateFullBlock`.

  Note `applyBlockToCache` is currently gated upstream by
  `validateFullBlockIO` inside `submitBlock` (BlockTemplate.hs:544),
  but the reorg branch (lines 889-898) calls it inside the post-
  `writeBatch` mirror loop without a fresh validation pass. That
  loop iterates the new-chain blocks — those blocks WERE
  validated when they originally arrived, but a malicious
  alternate chain that lands during a reorg test (e.g., regtest
  fuzz) could route a duplicate-input tx through this arm.
- **Excerpt (Consensus.hs:4374-4403):**

  ```haskell
  -- First, gather UTXO information for all inputs
  utxoResults <- forM (txInputs tx) $ \inp -> do
    let op = txInPrevOutput inp
    mEntry <- lookupUTXO cache op
    return (op, mEntry)

  let missingUtxos = [op | (op, Nothing) <- utxoResults]
  if not (null missingUtxos)
    then return $ Left $ "Missing UTXO: " ++ show (head missingUtxos)
    else do
      let utxoEntries = [(op, entry) | (op, Just entry) <- utxoResults]
      ...
      let inputValues = map (txOutValue . ueOutput . snd) utxoEntries
          sumInputs   = foldl' (+) 0 inputValues
          badInputs   = any (> maxMoney) inputValues
                         || sumInputs > maxMoney
  ```

  At no point in `applyBlock`'s non-coinbase branch is the input
  set checked for duplicates.
- **Impact:** Inflation primitive on every code path that invokes
  `applyBlock` directly without an upstream `validateFullBlock`:

  - **Chain reorg (`connectChain` line 4695):** any reorg of more
    than one block re-applies the new fork's blocks via
    `applyBlock`. If a reorg-target block contains a tx with a
    duplicate input, the UTXO cache mints `(N-1) × prevout.value`
    of new BTC. The reorg path is exercised on every contested
    fork, so this is reachable from a peer that produces a side
    chain.
  - **AssumeUTXO/reindex (line 4892):** during `--reindex`, every
    block from genesis is re-fed into `applyBlock` without
    `validateFullBlock` — a corrupt on-disk block file (or a
    malicious operator-supplied snapshot) cannot be sanitised by
    this path.
  - **Mainnet impact** is currently *zero in practice* because
    the genuine canonical chain has never had a duplicate-input
    tx, but the wave-by-wave assumption that "the cache catches
    what the validator missed" is the wrong way round — the
    cache path can be reached BYPASSING the validator. This is
    the exact failure mode of CVE-2018-17144 on Core 0.14.0–
    0.16.2 (their cache path was the inflation vector).

  Easiest fix: prepend `case validateTransaction tx of Left e →
  return (Left e); Right () → ...` to the non-coinbase branch of
  both `applyBlock` and `applyBlockToCache`. Cheap (it's pure)
  and idempotent on the IBD path.

### BUG-4 P0-CDIV — `validateSingleTx` / `validateBlockTransactions` do not enforce coinbase maturity at all

- **File:** `src/Haskoin/Consensus.hs:2823-2868` (`validateSingleTx`),
  `src/Haskoin/Consensus.hs:2791-2821` (`validateBlockTransactions`).
- **Core ref:** `bitcoin-core/src/consensus/tx_verify.cpp:178-182` —
  `if (coin.IsCoinBase() && nSpendHeight - coin.nHeight <
  COINBASE_MATURITY) return state.Invalid(...,
  "bad-txns-premature-spend-of-coinbase")`.  This check lives inside
  Core's `CheckTxInputs`, which Core calls from BOTH `ConnectBlock`
  (validation.cpp:2535) AND mempool `PreChecks` (validation.cpp:892).
- **Description:** The pure block-validation pipe
  (`validateFullBlock` → `validateBlockTransactions` →
  `validateSingleTx`) iterates the UTXO map and accumulates input
  values, but **never inspects `coinIsCoinbase` or
  `coinHeight`** on the prevout. The only paths that enforce
  COINBASE_MATURITY are:

  - `applyBlock` (Consensus.hs:4386-4390, line `height - ueHeight
    entry < fromIntegral (netCoinbaseMaturity net)`) — cache
    path.
  - `applyBlockToCache` (BlockTemplate.hs:1293-1297) — cache path.
  - `Mempool.hs:832, 1206, 2399` (three sites) — mempool admit.
  - `Wallet.hs:1813-1823` — wallet UTXO selection.

  None of those gate `validateFullBlockIO`. The Sync.hs IBD arm
  calls `validateFullBlockIO` *then* `connectBlockAt` (which
  also does not check coinbase maturity — Consensus.hs:3098).
  So on the strict assumevalid path, a block that spends an
  immature coinbase is accepted by `validateFullBlock` and
  written to disk by `connectBlockAt`; the cache path
  `applyBlockToCache` would catch it, but it only runs after
  `submitBlock` (BlockTemplate.hs:544), not the IBD arm. The
  result is that IBD with `skipScripts=True` (the W110
  assumevalid window — about 850k blocks on mainnet today)
  could ingest an immature-coinbase-spending tx without any gate
  firing.

- **Excerpt (Consensus.hs:2841-2862):**

  ```haskell
  -- Then validate inputs exist in UTXO set and collect prev TxOuts.
  prevOuts <- forM (txInputs tx) $ \inp ->
    case Map.lookup (txInPrevOutput inp) utxoMap of
      Nothing      -> Left $ "Missing UTXO: " ++ show (txInPrevOutput inp)
      Just prevOut -> Right prevOut
  -- Validate per-input amounts and accumulate totalIn.
  -- ...
  -- (no coinbase maturity check)
  ```

  Note `utxoMap :: Map OutPoint TxOut` — the `TxOut` projection
  has already DISCARDED the `coinIsCoinbase` / `coinHeight`
  metadata. The `Map OutPoint Coin` was projected to TxOut by
  `validateFullBlock` line 2399 (`fmap coinTxOut utxoCoinMap`),
  so even if the validator wanted to check maturity, the
  information is no longer in scope.
- **Impact:** Assumevalid IBD permits coinbase-immature spends.
  Mainnet impact is zero in practice because the canonical chain
  has never contained such a tx, but a stalker peer that feeds
  a maliciously constructed block during a fast IBD up to the
  assumevalid horizon could land an inflation tx in the disk
  UTXO set. After the assumevalid horizon the script-eval path
  runs and would (presumably) reject via some other gate, but
  the immature-coinbase check itself never fires.

### BUG-5 P1 — Mempool COINBASE_MATURITY off-by-one (uses tip height, not tip+1)

- **File:** `src/Haskoin/Mempool.hs:832, 1206, 2399` (three sites).
- **Core ref:** `bitcoin-core/src/validation.cpp:891-893`:

  ```cpp
  // The mempool holds txs for the next block, so pass height+1 to CheckTxInputs
  if (!Consensus::CheckTxInputs(tx, state, m_view,
        m_active_chainstate.m_chain.Height() + 1, ws.m_base_fees)) { ... }
  ```

- **Description:** All three mempool maturity checks read:

  ```haskell
  height <- readTVarIO (mpHeight mp)
  if ueCoinbase entry && height - ueHeight entry < fromIntegral coinbaseMaturity
    then ...rejection...
  ```

  where `mpHeight` is the CURRENT tip height (Mempool.hs:565
  comment: `Current chain height (tip height; mempool checks
  against tip+1)`). The comment claims tip+1, but the
  arithmetic uses tip. Result: at tip H+99 spending a coinbase
  born at H, Core would compute `(H+99+1)-H = 100, 100 < 100 =
  false, accept`. haskoin computes `(H+99)-H = 99 < 100 = true,
  reject`. The tx is mature in the next block but the mempool
  refuses admit.
- **Excerpt (Mempool.hs:1205-1208, also 831-834 and 2398-2400):**

  ```haskell
  height <- readTVarIO (mpHeight mp)
  if ueCoinbase entry && height - ueHeight entry < fromIntegral coinbaseMaturity
    then return $ Left (ErrCoinbaseNotMature (ueHeight entry) height)
    else return $ Right (op, ueOutput entry)
  ```

- **Impact:** Wallets and external relayers that broadcast a
  coinbase-spending tx exactly at the maturity boundary
  (tip = H+99 → next block H+100, the first legal spend block)
  see their tx rejected by haskoin until tip = H+100. This is a
  one-block delay, not a consensus split, but it costs ~10 min
  of mempool relay propagation for HD-wallet users following
  Core's standard timing. Also matters for compact-block
  reconstruction during the maturity-boundary block — haskoin
  would have to fetch the spend via getblocktxn while every other
  Core-shape impl had it in mempool.

  Note: `Wallet.hs:1819` has the OPPOSITE off-by-one
  (`tipHeight >= utxoBlockHeight utxo + 100`) which yields the
  same `H+100` first-legal-spend boundary. Wallet matches Core
  via its own off-by-one; mempool is the divergent one.

### BUG-6 P0-CDIV — `applyBlock` cache path lacks per-output MAX_MONEY check; relies on upstream `validateFullBlock`

- **File:** `src/Haskoin/Consensus.hs:4332-4367` (coinbase branch
  in `applyBlock`), 4368-4485 (non-coinbase branch — only checks
  input-side MoneyRange, not output-side per-output range).
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:24-34` —
  Core's `CheckTransaction` per-output `nValue < 0` /
  `nValue > MAX_MONEY` / running `MoneyRange(nValueOut)` triple
  guard. Core calls `CheckTransaction` from
  `CheckBlock` which runs INSIDE `ConnectBlock` (line 2452).
- **Description:** `applyBlock` does (line 4398-4401):

  ```haskell
  let inputValues = map (txOutValue . ueOutput . snd) utxoEntries
      sumInputs   = foldl' (+) 0 inputValues
      badInputs   = any (> maxMoney) inputValues
                     || sumInputs > maxMoney
  if badInputs then return $ Left "bad-txns-inputvalues-outofrange"
  ```

  i.e., the input-side MoneyRange is enforced. But the OUTPUT
  side (line 4405):

  ```haskell
  let valueOut = sum (map txOutValue (txOutputs tx))
  ```

  `Word64 sum` silently wraps. There is no per-output
  `txOutValue out > maxMoney` check and no accumulated
  `valueOut > maxMoney` check. As with BUG-3, the upstream
  `validateFullBlock` would catch this, but the reorg
  (`connectChain`) and reindex (`runBackgroundValidation`) arms
  do not call `validateFullBlock`. A crafted tx with two outputs
  each at `MAX_MONEY` overflows Word64
  (4.2e15 + 4.2e15 < Word64.max, but two outputs at
  `0x8000000000000000` would wrap to 0). Combined with BUG-3
  this becomes a multi-output inflation primitive.
- **Excerpt:** see Description.
- **Impact:** Defense-in-depth gap. Triggers only on the reorg
  and reindex paths described in BUG-3. Mitigated in practice by
  the upstream IBD arm. Should be fixed by prepending
  `validateTransaction tx` (which exercises *both* input-side
  and output-side MoneyRange).

### BUG-7 P0-CDIV — `connectBlockAt` (the on-disk commit path) does not enforce coinbase maturity or any value gate

- **File:** `src/Haskoin/Consensus.hs:3095-3175`.
- **Core ref:** `bitcoin-core/src/validation.cpp:2535` —
  `CheckTxInputs(tx, tx_state, view, pindex->nHeight, txfee)`
  is called INSIDE `Chainstate::ConnectBlock`, the on-disk
  commit path, with the full UTXO view.
- **Description:** `connectBlockAt` mutates the on-disk UTXO set
  via RocksDB `WriteBatch` (line 3173) based on `spentUtxos`
  passed in by the caller. It does:

  - G1: prevHash sanity check.
  - G19: all inputs are resolvable (UTXO exists, either in
    `spentUtxos` or on disk).
  - WriteBatch for the new outputs + the undo data.

  It does NOT:

  - Re-check duplicate inputs (relies on caller).
  - Re-check MoneyRange on prevouts or outputs.
  - Re-check coinbase maturity.
  - Re-check `sum(in) >= sum(out)`.

  The only caller in the live IBD path is Sync.hs (which gates
  via `validateFullBlockIO` first), so this is purely a
  defense-in-depth gap. But:

  - `submitBlock` also routes through `connectBlockAt` after a
    successful `validateFullBlockIO` (BlockTemplate.hs:544 →
    a path that eventually hits `connectBlockAt`); same shape.
  - The W138 assumeUTXO restart path could feed snapshot-loaded
    blocks straight into `connectBlockAt` if the operator runs
    `loadtxoutset` then attempts to connect more blocks before
    completing background validation.
- **Impact:** Same shape as Core fix lineage: the on-disk commit
  path is the last line of defense and should re-run the cheap
  CheckTransaction-equivalent. Currently haskoin's on-disk path
  is "trust the validator".

### BUG-8 P1 — `validateTransaction` "bad-txns-oversize" uses pre-witness `txBaseSize` × `witnessScaleFactor` but doesn't bound `MIN_TRANSACTION_WEIGHT`

- **File:** `src/Haskoin/Consensus.hs:1378-1382`.
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:19-21`:
  `if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)`.
- **Description:** The size check matches Core's *upper* bound.
  There is no lower-bound `MIN_TRANSACTION_WEIGHT` guard
  (Core's `MIN_TRANSACTION_WEIGHT = 60` in
  primitives/transaction.h). Haskoin's W117/W142 audits already
  flagged that empty witness payloads can be malleated; this
  bug is the lower-bound complement: a tx with `txBaseSize`
  near 0 (impossible in practice for valid wire-format txs
  but accepted by the deserialiser if `txInputs ≥ 1 ∧
  txOutputs ≥ 1` and both are tiny) passes the upper bound.
- **Impact:** Out of scope for W145's coinbase/fees emphasis;
  recorded here because the size-gate citation in the wave
  brief includes `bad-txns-oversize` and the lower bound is
  worth catalogue space.

### BUG-9 P1 — `coinbaseValue = sum (map txOutValue (txOutputs (head txns)))` in `validateFullBlock` relies on `validateTransaction` having already capped outputs

- **File:** `src/Haskoin/Consensus.hs:2573-2576`.
- **Core ref:** `bitcoin-core/src/validation.cpp:2611-2614` —
  Core uses `block.vtx[0]->GetValueOut()`, which throws unless
  the per-output and running-sum MoneyRange checks have passed.
- **Description:** `validateFullBlock` line 2573-2576:

  ```haskell
  let maxCoinbase = blockReward height + totalFees
      coinbaseValue = sum $ map txOutValue (txOutputs (head txns))
  when (coinbaseValue > maxCoinbase) $
    Left "Coinbase value exceeds allowed amount"
  ```

  The `sum :: [Word64] → Word64` silently wraps. Mitigated by the
  earlier `validateTransaction (head txns)` call at line 2421
  which DOES enforce the per-output / running-sum MAX_MONEY
  ceiling, so `coinbaseValue` is bounded by `maxMoney`
  (≈ 2.1e15) and the sum is safe. But the safety is implicit —
  reordering the two checks or removing the line-2421 call
  (the comment at 2417-2420 acknowledges the historical
  removability) would re-open Word64 wrap. Defensive coding
  norm in Core is to re-run `MoneyRange` at the consumption
  site.
- **Impact:** Latent — depends on line 2421 staying in place.

### BUG-10 P0-CDIV — `applyBlock` coinbase branch does not call `validateTransaction` on the coinbase; the "bad-cb-length" gate is reachable only via the IBD pipe

- **File:** `src/Haskoin/Consensus.hs:4332-4367` (coinbase
  branch of `applyBlock`).
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:47-50`
  — `if (tx.IsCoinBase()) { if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100) return state.Invalid(..., "bad-cb-length"); }`.
- **Description:** `applyBlock`'s coinbase branch just adds the
  outputs to the UTXO cache and counts sigops; it never checks
  the 2..100-byte scriptSig range. `validateFullBlock` line 2421
  does check it, but the cache-path callers in `connectChain`
  and `runBackgroundValidation` skip `validateFullBlock`.
  Reorg/reindex of a malicious side-chain block with a 1-byte
  scriptSig would land on disk via this arm.
- **Impact:** Same defense-in-depth shape as BUG-3, BUG-6, BUG-7.

### BUG-11 P2 — `coinbaseMaturity` global constant shadows `netCoinbaseMaturity` (per-network field) in mempool and wallet

- **File:**
  - `src/Haskoin/Consensus.hs:481-482` (`coinbaseMaturity = 100`).
  - `src/Haskoin/Consensus.hs:279, 1055, 1149, 1201, 1294`
    (`netCoinbaseMaturity = 100` for every network).
  - `src/Haskoin/Mempool.hs:832, 1206, 2399` (uses global
    constant).
  - `src/Haskoin/Wallet.hs:1819` (uses global constant).
  - `src/Haskoin/Consensus.hs:4388` (`applyBlock` uses
    `netCoinbaseMaturity net` — correct).
  - `src/Haskoin/BlockTemplate.hs:1295` (uses
    `netCoinbaseMaturity net` — correct).
- **Core ref:** `bitcoin-core/src/consensus/consensus.h:19` —
  `COINBASE_MATURITY = 100` is a hardcoded consensus
  constant; Core does NOT parametrise it per-network.
- **Description:** Every haskoin network sets
  `netCoinbaseMaturity = 100`. There is no current divergence,
  but the *intent* of the per-network field is undermined by
  half of the call sites bypassing it. If a future regtest
  scenario wants 1-block maturity (a fairly common request for
  CI testing), the per-network field change would silently fail
  to propagate to mempool/wallet.
- **Impact:** Two-pipeline guard pattern: the per-network field
  exists alongside the global constant; on regtest, the user
  edits one and the other is silently authoritative.

### BUG-12 P2 — `totalSupply = 2099999997690000` is a stale precomputed constant; differs from the dynamically halved sum

- **File:** `src/Haskoin/Consensus.hs:892-895`.
- **Core ref:** Bitcoin Core does NOT have a `totalSupply`
  constant; Core computes the supply on demand by iterating the
  halving series (`gettxoutsetinfo` does this for muHash etc).
- **Description:** haskoin precomputes total supply as
  `2099999997690000` sat ≈ 20999999.9769 BTC. This is correct
  for mainnet at the asymptote (all halvings complete) but
  diverges if BUG-1 is fixed and regtest's nominal halving
  interval becomes 150. Even on mainnet, this is only
  *eventually* the supply; today's actual supply is lower.
- **Impact:** RPC fields like `getblockchaininfo.total_supply`
  (if implemented) would report the asymptote rather than the
  current. Low impact.

### BUG-13 P1 — `validateTransaction` accepts a Word64 `txOutValue` whose wire-format high bit is set as "negative" via `fromIntegral . (\< 0 :: Int64)` — narrow miss on overflow comparison semantics

- **File:** `src/Haskoin/Consensus.hs:1389-1394`.
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:27-30`
  — Core compares `txout.nValue < 0` (int64) and
  `txout.nValue > MAX_MONEY` separately.
- **Description:** haskoin stores `txOutValue` as Word64, then
  does:

  ```haskell
  when (fromIntegral (txOutValue out) < (0 :: Int64)) $
    Left "Transaction output has negative value"
  ```

  This works because the high bit of `Word64` maps to the sign
  bit of the same-width `Int64`. The follow-up
  `when (txOutValue out > maxMoney) $ ...` is the upper-bound
  check. Subtle: `txOutValue = 2^63` is `Int64.minBound`
  (negative), so the "negative" rejection fires; values in
  `(MAX_MONEY, 2^63)` are caught by the `> maxMoney` rejection.
  Correct end-to-end, but the Int64 round-trip is a brittle
  idiom — a future Word64-only refactor (or a swap to
  `Integer` for arbitrary-precision) would silently lose the
  negative detection.
- **Impact:** Cosmetic / brittleness; behaviourally correct.

### BUG-14 P1 — `blockReward` returns `Word64` but the live consumers occasionally add `Int` fees / Word32 heights without explicit casts

- **File:** `src/Haskoin/Consensus.hs:880` (`blockReward :: Word32 → Word64`),
  callers `src/Haskoin/Consensus.hs:2573, 4492` and
  `src/Haskoin/BlockTemplate.hs:258, 1384`.
- **Description:** All current callers happen to use Word64
  arithmetic, but the signature `Word32 → Word64` invites
  `blockReward (csHeight cs + 1)` which silently wraps if
  `csHeight cs == 0xFFFFFFFF`. Mainnet currently at ~840k,
  ~5 millennia from Word32 wrap, so dormant.
- **Impact:** No live impact.

### BUG-15 P2 — `validateTransaction` per-output negative-value check rejects with a non-Core error string

- **File:** `src/Haskoin/Consensus.hs:1391`.
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:27-28`
  — error string is `"bad-txns-vout-negative"`.
- **Description:** haskoin emits `"Transaction output has
  negative value"`. Cross-impl test harness (`test-suite/`)
  compares rejection strings byte-for-byte against Core; this
  is a known string-divergence pattern noted in earlier waves
  (e.g., W93 BUG-G6 was the parallel string for coinbase).
- **Impact:** Test diff churn; no behavioural impact.

### BUG-16 P3 — `validateTransaction` "Transaction output value exceeds MAX_MONEY" should be `bad-txns-vout-toolarge`

- **File:** `src/Haskoin/Consensus.hs:1394`.
- **Core ref:** `bitcoin-core/src/consensus/tx_check.cpp:29-30`.
- **Description:** Same shape as BUG-15. Error string divergence.
- **Impact:** Diff churn.

### BUG-17 P3 — Wallet `isCoinbaseMature` documents the predicate via Core ref but the boundary diverges from Core's `CheckTxInputs`

- **File:** `src/Haskoin/Wallet.hs:1813-1819`.
- **Description:** The wallet uses
  `tipHeight >= utxoBlockHeight utxo + 100`. Core's CheckTxInputs
  uses `nSpendHeight - coin.nHeight >= 100`, with `nSpendHeight =
  pindex->nHeight`. For a wallet UTXO selection that anticipates
  spending in the NEXT block, `nSpendHeight = tipHeight + 1`,
  giving boundary `tipHeight + 1 ≥ H + 100` ⇔ `tipHeight ≥ H +
  99`. haskoin requires `tipHeight ≥ H + 100`, which is one
  block STRICTER. (BUG-5 covers the same off-by-one on the
  mempool path; this is the same root, different site.)
- **Impact:** Wallet refuses to *propose* a coinbase-spend at
  tip = H+99 even though the resulting tx would be accepted by
  Core's mempool in the next block.

### BUG-18 P1 — `txOutValue` accumulation in `applyBlock` non-coinbase branch uses `foldl'` but per-tx in-and-out paths use `sum`; inconsistent overflow protection across nearly-identical code

- **File:** `src/Haskoin/Consensus.hs:4399` (`foldl' (+) 0
  inputValues`) vs `src/Haskoin/Consensus.hs:4405` (`sum (map
  txOutValue (txOutputs tx))`) and Consensus.hs:1402-1406
  (`checkTotalOut` running-sum guard).
- **Description:** The in-flight value-out sum in `applyBlock`
  uses bare `sum`. The pure `validateTransaction` uses an
  explicit `checkTotalOut !acc` accumulator that compares
  against `maxMoney` at every step. Result: the cache path
  cannot detect Word64 wrap on outputs; the pure path can. The
  fix is mechanical (replace `sum` with the same accumulator),
  but the inconsistency is exactly the W93 ConnectBlock-vs-
  ContextualCheckBlock divergence pattern Core's "single source
  of truth via CheckTransaction" closes.
- **Impact:** As BUG-6, latent unless `validateFullBlock` is
  bypassed.

## Fleet patterns

- **Two-pipeline guard (new instance — 14th distinct since W76):**
  `Consensus.blockReward` (uses global `halvingInterval`) and
  `Index.hs:1257` (uses literal `210000`). Two parallel
  GetBlockSubsidy implementations that *happen to* agree on
  mainnet, will diverge the moment regtest interval is honoured.
  (BUG-1 + BUG-2.) Also `Consensus.coinbaseMaturity` (global)
  vs. `netCoinbaseMaturity` (per-network field): same shape,
  same divergence-on-customisation hazard (BUG-11).

- **Dead-field pattern (new instance):** `netHalvingInterval` is
  populated on every `Network` constructor and never read by
  any live caller. Companion to W138's "ChainstateManager
  defined but unused" and W141's "publisher fields defined,
  zero callers" fleet observations.

- **Comment-as-confession / "trust upstream" pattern (new
  instance):** Comments in `applyBlock` (Consensus.hs:4392-4397,
  4322-4326) explicitly note "The cache-path applyBlock used to
  skip this entirely; without the gate, a maliciously-crafted
  block ... would silently land in the UTXO set." The fix
  added MoneyRange + sigops but stopped short of adding the
  CheckTransaction duplicate-input guard (BUG-3). The comment
  documents the failure mode of the fix omission.

- **Off-by-one boundary fleet pattern (Lua/Erlang twin):**
  haskoin's mempool maturity check is `tip - H` rather than
  `(tip+1) - H` (BUG-5). The wallet at line 1819 uses the
  *opposite* off-by-one (`tipHeight >= H + 100` rather than
  `>=  H + 99`) to land on the same boundary. The two off-by-
  ones happen to compose to a Core-shaped wallet experience, but
  the mempool side over-restricts.

- **CheckTransaction-not-replayed-at-cache-mutation pattern (new
  fleet candidate):** the same shape applies to BUG-3 (dup
  inputs), BUG-6 (output-side MoneyRange), BUG-10 (coinbase
  scriptSig range), BUG-7 (everything on the disk-write path).
  These bugs share root cause: the cache-mutating function
  `applyBlock`/`applyBlockToCache`/`connectBlockAt` does not
  re-run the cheap context-free `validateTransaction` per tx.
  Core's design philosophy (tx_check.cpp:36-40 commentary) is
  explicit that CheckTransaction MUST run at every consensus
  boundary because the cache path's "spend twice" failure mode
  is asymmetric — UTXO availability and value range checks
  are NOT a substitute for duplicate-input detection.

- **Carry-forward re-anchor (3rd-instance in haskoin):** BUG-3
  re-anchors the W93 ConnectBlock fix (which added per-input
  MoneyRange to `applyBlock` in W93 BUG-G7) — that fix
  explicitly noted the cache path "skipped this entirely". The
  same author note acknowledges the gap but only filled
  MoneyRange + sigops, not duplicate-input, leaving CVE-
  2018-17144 still unguarded at the cache mutation site.

## Closure (out-of-scope behaviors verified PRESENT)

For completeness:

- **`isCoinbase` shape** (Consensus.hs:1991-1996) — exactly
  matches Core's `vin.size()==1 && vin[0].prevout.IsNull()`.
- **`MAX_MONEY` constant value** (Consensus.hs:478) —
  `2_100_000_000_000_000` sat, matches `consensus/amount.h:26`.
- **BIP-30 enforcement** (Consensus.hs:2604-2670) — three
  gates (grandfathered-pair shortcut + BIP-34 anchor confirm +
  per-tx UTXO presence) match Core's `IsBIP30Repeat` /
  ContextualCheckBlock.
- **Coinbase scriptSig 2..100 byte range** (Consensus.hs:1421-
  1427) — present in `validateTransaction`.
- **Non-coinbase null-prevout rejection** (Consensus.hs:1430-
  1436) — present.
- **Per-tx running-sum output MoneyRange** (Consensus.hs:1400-
  1406) — explicit running-sum guard.
- **Snapshot per-coin MoneyRange** (Storage.hs:3209-3230) —
  used by assumeUTXO loader.
- **Snapshot per-coin height ≤ base_height guard**
  (Storage.hs:3220-3224) — used by assumeUTXO loader.

EOF

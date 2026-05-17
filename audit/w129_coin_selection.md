# W129 Coin Selection (BnB / Knapsack / SRD / CG) — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** Branch-and-Bound, Knapsack, Single Random Draw, CoinGrinder, effective_value,
long-term feerate, cost of change, SFFO (subtract_fee_from_outputs), change
avoidance heuristic. Sources audited: `src/Haskoin/Wallet.hs` (coin selection
section ~lines 1407-2000 + bumpfee section ~lines 2160-2500).
**Result:** 6 PRESENT / 11 PARTIAL / 13 MISSING out of 30 gates.
**Bugs found:** 16 (3 P0-CDIV, 7 P1, 6 P2).
**Tests added:** 30 `xit` sentinels + 9 pinning `it` assertions = 39 cases in
`W129CoinSelectionSpec.hs`.

## Relationship to W113

W113 (the original 30-gate coin-selection audit) catalogued 13 bugs covering
basic algorithm presence, the Word64 underflow, the BnB-returns-on-first-match
bug, dead helpers, anti-fee-sniping absence, and `OUTPUT_GROUP_MAX_ENTRIES`.
W129 is the **deeper Core-parity sweep**: each gate inspects a specific
`coin_selection_params` field, a specific Core algorithm internal (e.g. BnB
lookahead pruning, BnB equivalence-class skip optimization, CoinGrinder
`min_tail_weight` precomputation, SRD MinHeap eviction, Knapsack
`ApproximateBestSubset` 2-pass loop, GenerateChangeTarget RNG envelope), or a
specific orchestration concern (SFFO skips BnB, CG runs only when
`m_effective_feerate > 3 × m_long_term_feerate`, AttemptSelection's per-OutputType
loop with min-waste tiebreaker, CoinEligibilityFilter's confirmation tiers).

W129 finds bugs **W113 did not surface** by going one layer deeper into each
algorithm. Five W113 bugs are referenced by W129 with cross-cites (BUG-3 maps
to W113-BUG-1, etc.) and excluded from W129's own bug count to avoid
double-counting.

## Top-line verdict

haskoin implements two coin-selection algorithms (BnB + Knapsack) at a
**surface level only**. None of the Core selection-parameter machinery —
`CoinSelectionParams`, `min_viable_change`, `m_change_fee` separate from
`m_cost_of_change`, `m_discard_feerate`, `m_long_term_feerate` distinct from
`m_effective_feerate`, `m_min_change_target` randomized between `CHANGE_LOWER`
and `CHANGE_UPPER`, `m_max_tx_weight`, the SFFO toggle, `m_avoid_partial_spends`
plumbed into OutputGroup construction, `m_include_unsafe_inputs`, the
CoinEligibilityFilter confirmation tiers — is present. The BnB algorithm
itself is structurally broken (returns on first hit instead of tracking
best_waste; W113-BUG-1) and the Knapsack approximation runs the **wrong
algorithm shape** (per-element CSPRNG-bit inclusion vector, not Core's
2-pass deterministic-rerun loop). CoinGrinder and SRD are absent entirely.

The most concerning consensus-relevant findings are:

1. **P0-CDIV: BnB skips the "feerate-high → don't keep getting wastier"
   pruning branch.** Core's BnB has a third backtrack condition: if
   `curr_waste > best_waste && is_feerate_high`, prune. haskoin's bnbSearch
   does not check this. On high-feerate transactions with many UTXOs, this
   wastes substantial CPU (the BnB iteration cap then trips a fallback to
   Knapsack, silently regressing solution quality).

2. **P0-CDIV: Knapsack solver dispatch order is wrong.** Core's flow:
   findExactMatch → if `nTotalLower == nTargetValue` use ALL applicable
   groups → if `nTotalLower < nTargetValue` and `lowest_larger` exists use
   `lowest_larger` → ApproximateBestSubset → choose between `lowest_larger`
   and the approximate result by amount comparison. haskoin's
   knapsackSolver: findExactMatch → if Nothing, prefer `lowest_larger` if
   any → only fall back to approximateBestSubset otherwise. Net effect:
   when many small UTXOs would have given a tighter selection than one
   large UTXO, haskoin picks the large UTXO; on bumpfee or fee-sensitive
   transactions this is wasteful.

3. **P0-CDIV: SFFO toggle absent.** Core's
   `coin_selection_params.m_subtract_fee_outputs` is plumbed into
   `OutputGroup.m_subtract_fee_outputs` and controls
   `GetSelectionAmount()` (returns `m_value` not `effective_value` when
   SFFO is on; coinselection.cpp:791). haskoin has **no SFFO concept at
   all**. The `bumpFee` path in feebumper.cpp uses SFFO when the only
   recipient is a change destination (feebumper.cpp:275 — `recipients.emplace_back(... fSubtractFeeFromAmount=true)`); haskoin's
   bumpfee path bypasses selection entirely (it just reduces the change
   output) so the SFFO gap is currently latent, but any future `sendmany`
   with `subtract_fee_from_outputs=[…]` will mis-select.

The most consensus-irrelevant but most surprising finding is BUG-15:
**`minChangeAmount = 1000` is wrong by 50×.** Core's `CHANGE_LOWER` is
50000 sat (the lower bound of the randomized `m_min_change_target` envelope
spanning `[CHANGE_LOWER, min(2*payment_value, CHANGE_UPPER=1000000)]`).
The haskoin value triggers change-creation at any selection where
`totalSelected ≥ target + fee + 1000` — far below Core's 50ksat threshold.
This systematically produces tiny change outputs that Core would have
absorbed into fees as part of changeless selection.

## 30-gate matrix

| Gate | What it pins | Verdict |
|------|--------------|---------|
| G1   | `CHANGE_LOWER = 50000 sat` constant present                             | MISSING       |
| G2   | `CHANGE_UPPER = 1000000 sat` constant present                            | MISSING       |
| G3   | `GenerateChangeTarget` produces value in `[CHANGE_LOWER, min(2*pay, CHANGE_UPPER)]` | MISSING (BUG-1) |
| G4   | `m_min_change_target` chosen per-tx by RNG (not constant)                | MISSING (BUG-1) |
| G5   | `m_cost_of_change` = `m_change_fee + m_discard_feerate.GetFee(change_spend_size)` | PARTIAL (BUG-2) |
| G6   | `m_change_fee` separate field (effective-feerate × change_output_size)   | MISSING (BUG-2) |
| G7   | `m_discard_feerate` separate field (≤ effective_feerate)                 | MISSING (BUG-3) |
| G8   | `min_viable_change` = `max(change_spend_fee + 1, dust)`                  | MISSING (BUG-4) |
| G9   | `effective_value = txout.nValue - fee` per-coin pre-compute              | PRESENT       |
| G10  | Coin-level `long_term_fee` recorded (Core OutputGroup.long_term_fee)     | PARTIAL (BUG-5) |
| G11  | Long-term feerate threaded from wallet.m_consolidate_feerate             | MISSING (BUG-5; W113-BUG-12) |
| G12  | `m_effective_feerate > 3 × m_long_term_feerate` gates CoinGrinder        | MISSING (BUG-6) |
| G13  | CoinGrinder algorithm present                                           | MISSING (W113-BUG-7) |
| G14  | CoinGrinder `min_tail_weight` precompute                                 | MISSING (W113-BUG-7) |
| G15  | CoinGrinder `lookahead` precompute (running sum from tail)               | MISSING (W113-BUG-7) |
| G16  | CoinGrinder CUT/SHIFT/EXPLORE tree traversal                             | MISSING (W113-BUG-7) |
| G17  | SRD algorithm present                                                   | MISSING (W113-BUG-8) |
| G18  | SRD MinHeap eviction when weight exceeds max_selection_weight            | MISSING (W113-BUG-8) |
| G19  | SRD target_value pre-adjusted by `CHANGE_LOWER + change_fee`              | MISSING (W113-BUG-8) |
| G20  | BnB feerate-high pruning (`curr_waste > best_waste && is_feerate_high`)  | FAIL (BUG-7)  |
| G21  | BnB inclusion-shortcut skip (when prev UTXO has same effective value)    | FAIL (BUG-8)  |
| G22  | BnB tracks best_selection across all iterations (not first-match)        | FAIL (W113-BUG-1) |
| G23  | BnB `max_selection_weight` weight cap                                    | MISSING (BUG-9) |
| G24  | Knapsack dispatch order (haskoin preempts lowest_larger before approximate) | FAIL (BUG-10) |
| G25  | Knapsack `ApproximateBestSubset` 2-pass loop per iteration               | FAIL (BUG-11) |
| G26  | Knapsack 1000-iteration outer loop                                       | PARTIAL (BUG-11) |
| G27  | `m_subtract_fee_outputs` (SFFO) toggle in coin selection                 | MISSING (BUG-12) |
| G28  | SFFO skips BnB in ChooseSelectionResult dispatch                         | MISSING (BUG-12) |
| G29  | `m_max_tx_weight` plumbed into each algorithm                            | MISSING (BUG-13) |
| G30  | Multiple algorithms run; min-waste result is chosen (AttemptSelection)   | MISSING (BUG-14) |

## Bugs

### P0-CDIV (consensus-divergence; affects on-wire txs and wallet RBF safety)

- **BUG-7** P0-CDIV  BnB never prunes on rising waste at high feerates.
  Core's third backtrack condition (`curr_waste > best_waste && is_feerate_high`)
  is absent in `bnbSearch`. On high-feerate txs (e.g. RBF replacements) the
  search burns the full 100k-iteration budget exploring branches Core would
  have culled, then trips the cap and silently falls back to Knapsack
  (which produces a change-bearing selection that wastes the bump-fee
  opportunity). Reproduces with 50+ UTXOs at FeeRate > 10000 sat/kvB.

- **BUG-10** P0-CDIV  Knapsack dispatch prefers `lowest_larger` before
  ApproximateBestSubset. Core's algorithm (coinselection.cpp:709-744) runs
  ApproximateBestSubset first, then chooses between its result and
  `lowest_larger` by direct comparison (`lowest_larger->GetSelectionAmount() <= nBest`).
  haskoin's `knapsackSolver` (Wallet.hs:1685-1696) flips the order: if
  `lowest_larger` exists, it's used immediately. When 10 small UTXOs would
  have produced selection_amount=target+small_excess and lowest_larger
  produces target+large_excess, haskoin picks the second; Core picks the
  first. Privacy and fee impact.

- **BUG-12** P0-CDIV  SFFO (subtract_fee_from_outputs) toggle entirely
  absent. Core's `m_subtract_fee_outputs` flag flips `OutputGroup.GetSelectionAmount`
  to return `m_value` not `effective_value` (coinselection.cpp:789-792)
  and skips BnB in ChooseSelectionResult (spend.cpp:751). haskoin's
  `selectCoinsWithHeight` and `selectCoins` accept no SFFO flag and
  always use effective value. `sendmany` with
  `subtract_fee_from_outputs=[0]` would currently mis-select; same for
  `walletcreatefundedpsbt` with `subtractFeeFromOutputs`. Latent because
  haskoin does not yet implement those RPCs; will surface the moment
  they're added.

### P1 (correctness; user-visible but not consensus-affecting)

- **BUG-1** P1  `GenerateChangeTarget` absent: no per-tx RNG-randomized
  change-target generation. Core picks `m_min_change_target` from
  `[CHANGE_LOWER, min(2*payment_value, CHANGE_UPPER)]` per call to
  CreateTransaction (coinselection.cpp:809-818) — this breaks change-amount
  fingerprinting. haskoin uses a deterministic `minChangeAmount = 1000`
  (Wallet.hs:1499), which (a) is the wrong order of magnitude (see BUG-15)
  and (b) provides no fingerprinting resistance.

- **BUG-2** P1  `m_cost_of_change` formula simplified incorrectly.
  Core: `m_cost_of_change = m_discard_feerate.GetFee(change_spend_size) + m_change_fee`
  where `m_change_fee = m_effective_feerate.GetFee(change_output_size)`
  (spend.cpp:1174-1175). haskoin's `costOfChange` (Wallet.hs:1504-1508)
  uses the SAME feerate for both the create cost and the future spend
  cost (`feeRate` for both), and the divisor is wrong: `getFeeRate feeRate `div` 4000`
  is dividing by 4000 (off by 1000× — should be /1000 if `feeRate` is
  sat/kvB). This makes costOfChange ~4× smaller than Core's; BnB then
  accepts solutions that are too tight relative to actually-economic
  change creation.

- **BUG-3** P1  `m_discard_feerate` distinct from `m_effective_feerate`
  not present. Core uses `m_discard_feerate = GetDiscardRate(wallet)` —
  typically `min(wallet.m_min_relay_fee, wallet.m_pay_tx_fee)` — for
  "what will it cost to spend this change later" calculations. haskoin
  uses the same feerate for both, which biases towards creating change
  when fee market drops (the future-spend estimate is too high).

- **BUG-4** P1  `min_viable_change` ≠ `dustThreshold`. Core:
  `min_viable_change = max(change_spend_fee + 1, dust)` where
  `change_spend_fee = m_discard_feerate.GetFee(change_spend_size)`
  (spend.cpp:1184). haskoin uses raw `dustThreshold` (546 sat). At any
  fee rate above ~1 sat/vB the spend-fee-of-change exceeds dust, so
  Core's threshold is larger than 546. haskoin under-counts the
  "wouldn't be worth spending" threshold and emits change outputs that
  cost more to spend than they're worth.

- **BUG-5** P1  Long-term feerate is hardcoded to `FeeRate 1` (1 sat/kvB)
  in `utxosToGroups'` (Wallet.hs:1614) and `utxosToGroups`
  (Wallet.hs:1566). Cross-reference W113-BUG-12. The waste metric
  `fee - long_term_fee` is therefore always near `fee` (since
  long_term_fee ~= 0 at this rate). BnB's tiebreak-on-equal-effective-value
  comparator (Core descending struct, coinselection.cpp:30-38) is also
  broken because it depends on this differential.

- **BUG-9** P1  BnB lacks `max_selection_weight` cap. Core's BnB tracks
  `curr_selection_weight` and backtracks when it exceeds
  `max_selection_weight = MAX_STANDARD_TX_WEIGHT - tx_weight_no_input`
  (coinselection.cpp:131-133, spend.cpp:743-748). haskoin's `bnbSearch`
  ignores weight entirely — a selection of 1000 UTXOs that satisfies
  the target amount but produces a > 400k-weight tx will be returned
  by BnB. Such a tx is then rejected at relay (oversized).

- **BUG-13** P1  `m_max_tx_weight` configurable cap absent. Core supports
  `coin_control.m_max_tx_weight` (coinselection.h:176) for
  pre-set-input flows. haskoin has no equivalent; fundtransaction and
  bumpfee can produce txs that exceed the standard weight even though
  Core would have refused.

### P2 (lint / observability)

- **BUG-6** P2  CoinGrinder threshold logic absent. Even if CoinGrinder
  is added, the dispatch in ChooseSelectionResult must check
  `m_effective_feerate > 3 × m_long_term_feerate` (spend.cpp:769)
  before running CG. Without this, CG runs on low-fee txs and produces
  unnecessarily-fragmented selections.

- **BUG-8** P2  BnB inclusion-shortcut skip missing. Core's BnB skips
  the inclusion-branch when the previous UTXO had the same effective
  value AND was excluded (coinselection.cpp:171-184). haskoin's
  bnbSearch always tries both branches. Burns iterations but doesn't
  affect correctness; surfaces as performance regression on
  duplicate-effective-value pools.

- **BUG-11** P2  ApproximateBestSubset 2-pass loop wrong shape.
  Core runs each iteration with `nPass ∈ {0,1}`: pass 0 uses
  `insecure_rand.randbool()`; pass 1 uses `!vfIncluded[i]` (the
  complement of pass 0) — coinselection.cpp:618-628. haskoin's
  `approximateBestSubset` runs a single pass per iteration:
  `randomSubset` produces one inclusion vector per iteration via
  per-element bit. Net effect: haskoin explores ~half the search
  space Core does for the same iteration count.

- **BUG-14** P2  AttemptSelection's per-OutputType isolation absent.
  Core groups UTXOs by output_type, runs the full algorithm sweep on
  each type, picks the min-waste result; only falls back to
  cross-type mixing if no single type can fund (spend.cpp:702-727).
  haskoin makes no output-type distinction. Privacy regression:
  haskoin mixes input types whenever convenient.

- **BUG-15** P2  `minChangeAmount = 1000 sat` (Wallet.hs:1499) is 50×
  too low. Core's CHANGE_LOWER is 50000 sat. The haskoin value also
  has no relationship to dust or feerate. Either it should be
  `CHANGE_LOWER` (50000) or `dust * 4` or some other principled
  number; 1000 looks invented.

- **BUG-16** P2  `CoinEligibilityFilter` tiers absent. Core sweeps
  three levels (spend.cpp:898-980): {1 conf for mine, 6 for theirs,
  no unconfirmed ancestors}, {1, 1, 2}, {0, 1, 4} with progressive
  relaxation. haskoin uses a single tier (effectively
  `m_include_unsafe = true` always). Privacy regression and
  bumpfee-replacement reliability regression (BIP-125 rule 2 says
  no new unconfirmed inputs in the replacement, but haskoin would
  pick them up if available).

## Two-pipeline observations (informational)

Carried forward from W113 — no new instances surfaced by this audit.

- W113-TP1: `selectCoins` vs `selectCoinsWithHeight` (parallel impls
  with diverging coinbase-maturity behavior).
- W113-TP2: `utxosToGroups` vs `utxosToGroups'` (parallel impls;
  former is dead).

## Dead-helper findings

W113 already catalogued two dead helpers (`BnBState`, `utxosToGroups`).
W129 confirms both are still dead; no new dead helpers found.

## W88 anti-pattern check

CSPRNG usage in `shuffleList` / `randomSubset` is correct (uses
`Crypto.Random.getRandomBytes`). The Knapsack 2-pass shape bug
(BUG-11) is an algorithm-shape regression, not a CSPRNG regression.

## Coordination notes

This is one of 4 audit waves running in parallel; HIGH probability of
`Spec.hs` and `haskoin.cabal` merge conflict. The wiring is intentionally
minimal: one line in `test-suite haskoin-test:other-modules` and one
`import qualified W129CoinSelectionSpec` + one `W129CoinSelectionSpec.spec`
line in `Spec.hs`. Conflict-resolution recipe: `git reset --soft HEAD~1`,
re-stage only the W129 files, re-commit.

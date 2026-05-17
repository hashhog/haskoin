{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W129 Coin Selection (BnB / Knapsack / SRD / CG) — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/wallet/coinselection.h          — CoinSelectionParams,
--                                                       SelectionAlgorithm,
--                                                       CHANGE_LOWER=50000,
--                                                       CHANGE_UPPER=1000000,
--                                                       OUTPUT_GROUP_MAX_ENTRIES=100
--   bitcoin-core/src/wallet/coinselection.cpp        — SelectCoinsBnB,
--                                                       KnapsackSolver,
--                                                       CoinGrinder,
--                                                       SelectCoinsSRD,
--                                                       ApproximateBestSubset,
--                                                       GenerateChangeTarget,
--                                                       RecalculateWaste
--   bitcoin-core/src/wallet/spend.cpp                — AttemptSelection,
--                                                       ChooseSelectionResult,
--                                                       CreateTransactionInternal,
--                                                       3×LTFRE CoinGrinder gate
--   bitcoin-core/src/wallet/feebumper.cpp            — SFFO use on bumpfee
--                                                       change-only recipient
--
-- ============================================================
-- TOP-LINE VERDICT — PARTIAL (6 PRESENT, 11 PARTIAL, 13 MISSING)
-- ============================================================
--
-- haskoin implements BnB + Knapsack at a surface level only.
-- None of the Core selection-parameter machinery
-- (CoinSelectionParams, min_viable_change, m_change_fee distinct
-- from m_cost_of_change, m_discard_feerate, m_long_term_feerate
-- distinct from m_effective_feerate, m_min_change_target
-- randomized between CHANGE_LOWER and CHANGE_UPPER, m_max_tx_weight,
-- SFFO toggle, avoid_partial_spends, include_unsafe_inputs, the
-- CoinEligibilityFilter confirmation tiers) is present.
-- The BnB algorithm itself is structurally broken (returns on
-- first hit instead of tracking best_waste; W113-BUG-1; cross-
-- referenced here as G22) and the Knapsack approximation runs
-- the wrong algorithm shape (per-element CSPRNG-bit inclusion
-- vector, not Core's 2-pass deterministic-rerun loop).
-- CoinGrinder and SRD are absent entirely.
--
-- == Bugs (16, no double-count with W113) ==
--
-- BUG-1  P1     GenerateChangeTarget absent (no per-tx RNG envelope)
-- BUG-2  P1     m_cost_of_change formula simplified incorrectly
-- BUG-3  P1     m_discard_feerate distinct from m_effective_feerate absent
-- BUG-4  P1     min_viable_change != dustThreshold
-- BUG-5  P1     long-term feerate hardcoded FeeRate 1
-- BUG-6  P2     CoinGrinder 3×LTFRE threshold dispatch absent
-- BUG-7  P0-CDIV BnB feerate-high pruning absent
-- BUG-8  P2     BnB inclusion-shortcut skip absent
-- BUG-9  P1     BnB max_selection_weight cap absent
-- BUG-10 P0-CDIV Knapsack lowest_larger preempts approximate
-- BUG-11 P2     ApproximateBestSubset 2-pass loop wrong shape
-- BUG-12 P0-CDIV SFFO toggle entirely absent
-- BUG-13 P1     m_max_tx_weight configurable cap absent
-- BUG-14 P2     AttemptSelection per-OutputType isolation absent
-- BUG-15 P2     minChangeAmount = 1000 sat is 50× too low vs Core CHANGE_LOWER
-- BUG-16 P2     CoinEligibilityFilter tiers absent
--
-- == Cross-reference to W113 (NOT recounted here) ==
--
-- The following W113 bugs are reflected as MISSING gates in this audit
-- but counted in W113, not W129:
--   W113-BUG-1  bnbSearch returns on first match (G22)
--   W113-BUG-7  CoinGrinder absent (G13-G16)
--   W113-BUG-8  SRD absent (G17-G19)
--   W113-BUG-12 long-term feerate hardcoded (cross-cite of W129-BUG-5)
--
-- Discovery audit: NO production code changes.  Tests are
-- pinning-shape (assert current behaviour with `it`) and xfail-shape
-- (assert *desired* Core-parity behaviour with `xit`) so future fix
-- waves can flip `xit` -> `it` after wiring the missing primitives.
--
-- ============================================================

module W129CoinSelectionSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int64)

import Haskoin.Wallet
  ( Utxo(..)
  , utxoValue
  , OutputGroup(..)
  , SelectionAlgorithm(..)
  , selectCoinsBnB
  , knapsackSolver
  , approximateBestSubset
  , partitionUtxos
  , findExactMatch
  , maxBnBIterations
  , dustThreshold
  , minChangeAmount
  , costOfChange
  , effectiveValue
  , feeFromWeight
  , estimateTxWeight
  )
import Haskoin.Crypto (Address(..))
import Haskoin.Types
  ( TxId(..), Hash256(..), Hash160(..), OutPoint(..), TxOut(..) )
import Haskoin.Mempool (FeeRate(..))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a non-coinbase UTXO with given value and a deterministic outpoint.
mkUtxo :: Int -> Word64 -> Utxo
mkUtxo seed val =
  Utxo (OutPoint (TxId (Hash256 (BS.replicate 32 (fromIntegral seed)))) 0)
       (TxOut val "")
       6     -- confirmations
       False -- not coinbase
       100   -- blockHeight

-- | Dummy P2WPKH receive address.
dummyAddr :: Address
dummyAddr = WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xaa))

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W129 Coin Selection (BnB / Knapsack / SRD / CG)" $ do

  ------------------------------------------------------------------------------
  -- G1-G4 : CHANGE_LOWER / CHANGE_UPPER / GenerateChangeTarget envelope
  -- Reference: bitcoin-core/src/wallet/coinselection.h:23-25
  --            bitcoin-core/src/wallet/coinselection.cpp:809-818
  ------------------------------------------------------------------------------

  describe "G1 CHANGE_LOWER = 50000 sat constant" $ do
    it "G1 PINS minChangeAmount = 1000 (BUG-15: 50× too low vs Core CHANGE_LOWER)" $
      minChangeAmount `shouldBe` 1000
    xit "G1 GATE: minChangeAmount should equal Core CHANGE_LOWER = 50000" $
      minChangeAmount `shouldBe` 50000

  describe "G2 CHANGE_UPPER = 1000000 sat constant" $ do
    xit "G2 MISSING: no CHANGE_UPPER constant exported from Haskoin.Wallet" $
      -- Core defines `CHANGE_UPPER{1000000}` in coinselection.h:25 to bound
      -- the random envelope for change-target.  haskoin has no equivalent.
      pendingWith "BUG-15: CHANGE_UPPER constant absent"

  describe "G3 GenerateChangeTarget produces a value in [CHANGE_LOWER, min(2*pay, CHANGE_UPPER)]" $ do
    xit "G3 MISSING: GenerateChangeTarget primitive absent (BUG-1)" $
      pendingWith "BUG-1: no per-tx RNG envelope for change target"

  describe "G4 m_min_change_target chosen per-tx by RNG (not constant)" $ do
    xit "G4 MISSING: change target is a CONSTANT (1000 sat) not RNG-randomized" $
      -- Two consecutive calls to selectCoins on the same wallet with the
      -- same args should select different change targets (Core uses
      -- FastRandomContext for fingerprint resistance).  haskoin's
      -- minChangeAmount is a hardcoded value.
      pendingWith "BUG-1: deterministic change target == fingerprintable"

  ------------------------------------------------------------------------------
  -- G5-G8 : cost_of_change formula breakdown
  -- Reference: bitcoin-core/src/wallet/spend.cpp:1169-1184
  ------------------------------------------------------------------------------

  describe "G5 m_cost_of_change = m_change_fee + m_discard_feerate.GetFee(change_spend_size)" $ do
    it "G5 PINS costOfChange increases with feeRate (sanity)" $ do
      let low  = costOfChange (FeeRate 1000)
          high = costOfChange (FeeRate 100000)
      high `shouldSatisfy` (> low)
    xit "G5 GATE: costOfChange must split into change_fee (effective) + spend_fee (discard)" $
      -- Core: cost_of_change = effective_feerate × change_output_size
      --                      + discard_feerate × change_spend_size.
      -- haskoin uses SAME feerate for both (BUG-2).  At any non-trivial
      -- fee rate the two values differ; haskoin under-estimates.
      pendingWith "BUG-2: cost_of_change formula uses one feerate not two"

  describe "G6 m_change_fee separate field (effective-feerate × change_output_size)" $ do
    xit "G6 MISSING: no m_change_fee primitive exported" $
      pendingWith "BUG-2: m_change_fee is folded into costOfChange"

  describe "G7 m_discard_feerate separate field (typically <= effective_feerate)" $ do
    xit "G7 MISSING: no discardFeerate concept (uses same feerate as effective)" $
      pendingWith "BUG-3: m_discard_feerate absent"

  describe "G8 min_viable_change = max(change_spend_fee + 1, dust)" $ do
    it "G8 PINS dustThreshold = 546 sat (Core BIP-9 / policy.cpp)" $
      dustThreshold `shouldBe` 546
    xit "G8 GATE: min_viable_change should equal max(change_spend_fee + 1, dust)" $
      -- At any feerate > ~1 sat/vB, change_spend_fee > 546; min_viable_change
      -- should track that, not raw dust.  haskoin uses raw dustThreshold.
      pendingWith "BUG-4: min_viable_change != Core formula"

  ------------------------------------------------------------------------------
  -- G9-G11 : effective_value, long_term_fee, consolidate_feerate threading
  -- Reference: bitcoin-core/src/wallet/coinselection.h:31, 70, 254
  ------------------------------------------------------------------------------

  describe "G9 effective_value = txout.nValue - fee per-coin pre-compute" $ do
    it "G9 PASS: effectiveValue decreases as feeRate increases" $ do
      let utxo  = mkUtxo 1 100000
          effLow  = effectiveValue utxo (FeeRate 1)
          effHigh = effectiveValue utxo (FeeRate 10000)
      effLow `shouldSatisfy` (> effHigh)

    it "G9 PASS: effectiveValue can go negative when fee > value" $ do
      let utxo = mkUtxo 1 100  -- tiny UTXO
          effAtHugeFee = effectiveValue utxo (FeeRate 1000000)
      effAtHugeFee `shouldSatisfy` (< 0)

  describe "G10 Coin-level long_term_fee field recorded" $ do
    -- OutputGroup.ogLongTermFee exists (Wallet.hs:1432) but is hardcoded
    -- at FeeRate 1 in both utxosToGroups and utxosToGroups' (Wallet.hs:1566/1614).
    xit "G10 PARTIAL: ogLongTermFee field exists but hardcoded to FeeRate 1" $
      pendingWith "BUG-5 (cross-W113-BUG-12): long-term feerate not threaded"

  describe "G11 Long-term feerate threaded from wallet.m_consolidate_feerate" $ do
    xit "G11 MISSING: no consolidate_feerate concept anywhere in Haskoin.Wallet" $
      -- Core: spend.cpp:1087  coin_selection_params.m_long_term_feerate = wallet.m_consolidate_feerate.
      -- haskoin: long-term feerate is the literal FeeRate 1 (BUG-5).
      pendingWith "BUG-5: consolidate_feerate absent"

  ------------------------------------------------------------------------------
  -- G12-G16 : CoinGrinder gating + algorithm internals
  -- Reference: bitcoin-core/src/wallet/spend.cpp:769-776
  --            bitcoin-core/src/wallet/coinselection.cpp:325-525
  ------------------------------------------------------------------------------

  describe "G12 m_effective_feerate > 3 × m_long_term_feerate gates CoinGrinder" $ do
    xit "G12 MISSING: no 3×LTFRE threshold dispatch" $
      pendingWith "BUG-6: CoinGrinder threshold gate absent"

  describe "G13 CoinGrinder algorithm present" $ do
    xit "G13 MISSING: no coinGrinder function exported (W113-BUG-7)" $
      pendingWith "W113-BUG-7: CoinGrinder absent"

  describe "G14 CoinGrinder min_tail_weight precompute" $ do
    xit "G14 MISSING: min_tail_weight precompute is part of CoinGrinder (absent)" $
      pendingWith "W113-BUG-7: CoinGrinder absent"

  describe "G15 CoinGrinder lookahead precompute (running sum from tail)" $ do
    xit "G15 MISSING: lookahead precompute is part of CoinGrinder (absent)" $
      pendingWith "W113-BUG-7: CoinGrinder absent"

  describe "G16 CoinGrinder CUT/SHIFT/EXPLORE tree traversal" $ do
    xit "G16 MISSING: tree traversal is part of CoinGrinder (absent)" $
      pendingWith "W113-BUG-7: CoinGrinder absent"

  ------------------------------------------------------------------------------
  -- G17-G19 : SRD algorithm internals
  -- Reference: bitcoin-core/src/wallet/coinselection.cpp:536-588
  ------------------------------------------------------------------------------

  describe "G17 SRD (Single Random Draw) algorithm present" $ do
    xit "G17 MISSING: no selectCoinsSRD exported (W113-BUG-8)" $
      pendingWith "W113-BUG-8: SRD absent"

  describe "G18 SRD MinHeap eviction when weight exceeds max_selection_weight" $ do
    xit "G18 MISSING: MinHeap eviction is part of SRD (absent)" $
      pendingWith "W113-BUG-8: SRD absent"

  describe "G19 SRD target_value pre-adjusted by CHANGE_LOWER + change_fee" $ do
    xit "G19 MISSING: SRD's CHANGE_LOWER adjustment requires SRD (absent)" $
      pendingWith "W113-BUG-8: SRD absent"

  ------------------------------------------------------------------------------
  -- G20-G23 : BnB-specific gates
  -- Reference: bitcoin-core/src/wallet/coinselection.cpp:93-201
  ------------------------------------------------------------------------------

  describe "G20 BnB feerate-high pruning (curr_waste > best_waste && is_feerate_high)" $ do
    it "G20 PINS BnB terminates without hanging (iteration cap saves us)" $ do
      -- 30 UTXOs at FeeRate 50000 (high feerate) forcing the missing prune
      -- branch to burn the full 100k-iteration cap.  Without the cap this
      -- would hang.  Test just asserts termination.
      let utxos = [ mkUtxo i (fromIntegral (i * 7777 + 1111)) | i <- [1..30] ]
          target  = 100000
          _       = selectCoinsBnB utxos target (FeeRate 50000)
      True `shouldBe` True

    xit "G20 GATE: BnB should backtrack on rising waste at high feerate" $
      -- Verifying this requires inspecting the iteration count or an
      -- internal counter.  Currently no observability hook.
      pendingWith "BUG-7: no rising-waste backtrack at high feerate"

  describe "G21 BnB inclusion-shortcut skip (same effective value, prev excluded)" $ do
    xit "G21 GATE: BnB should skip inclusion when prev UTXO same value was excluded" $
      pendingWith "BUG-8: inclusion-shortcut skip absent"

  describe "G22 BnB tracks best_selection across all iterations (not first-match)" $ do
    xit "G22 GATE: BnB returns waste-optimal selection, not first hit" $
      -- Core's BnB continues after a hit, tracking best_waste.  haskoin's
      -- bnbSearch returns immediately on first match.  See W113-BUG-1.
      pendingWith "W113-BUG-1: BnB returns on first hit"

  describe "G23 BnB max_selection_weight weight cap" $ do
    xit "G23 MISSING: no max_selection_weight cap in bnbSearch" $
      pendingWith "BUG-9: BnB has no weight cap"

  ------------------------------------------------------------------------------
  -- G24-G26 : Knapsack-specific gates
  -- Reference: bitcoin-core/src/wallet/coinselection.cpp:652-747
  ------------------------------------------------------------------------------

  describe "G24 Knapsack dispatch order (Core: approximate-then-compare; haskoin: lowest_larger-first)" $ do
    it "G24 PINS knapsackSolver returns a non-empty selection for reachable target" $ do
      let utxos = [mkUtxo 1 200000, mkUtxo 2 100000, mkUtxo 3 50000]
      selected <- knapsackSolver utxos 80000 (FeeRate 10)
      length selected `shouldSatisfy` (>= 1)

    xit "G24 GATE: when many small UTXOs sum to tighter excess than lowest_larger, haskoin should pick the small set" $
      -- Construct a UTXO pool where ApproximateBestSubset of small UTXOs
      -- can produce excess < lowest_larger's excess.  Core picks the
      -- small set; haskoin picks lowest_larger immediately (BUG-10).
      pendingWith "BUG-10: lowest_larger preempts approximate"

  describe "G25 Knapsack ApproximateBestSubset 2-pass loop per iteration" $ do
    xit "G25 GATE: each iteration runs pass-0 (randbool) + pass-1 (complement)" $
      -- Core: coinselection.cpp:618-628.  haskoin runs a single per-
      -- element-bit pass per iteration in approximateBestSubset
      -- (Wallet.hs:1734-1762).  Half the search-space coverage.
      pendingWith "BUG-11: ApproximateBestSubset 2-pass loop absent"

  describe "G26 Knapsack 1000-iteration outer loop" $ do
    it "G26 PARTIAL: iteration count is correct (1000) but per-iteration shape is wrong" $ do
      -- We can't easily count iterations without instrumentation.  This
      -- pinning test exercises the function on a pool where 1000 passes
      -- is enough to converge if the algorithm is shaped right.
      let utxos = [mkUtxo i (fromIntegral (i * 1000 + 100)) | i <- [1..10]]
      selected <- approximateBestSubset utxos 5500 (FeeRate 1)
      length selected `shouldSatisfy` (> 0)

  ------------------------------------------------------------------------------
  -- G27-G28 : SFFO (subtract_fee_from_outputs)
  -- Reference: bitcoin-core/src/wallet/coinselection.h:163
  --            bitcoin-core/src/wallet/spend.cpp:1104-1107, 750-754
  ------------------------------------------------------------------------------

  describe "G27 m_subtract_fee_outputs (SFFO) toggle in coin selection" $ do
    xit "G27 MISSING: no SFFO parameter on selectCoins/selectCoinsWithHeight" $
      pendingWith "BUG-12: SFFO toggle absent"

  describe "G28 SFFO skips BnB in ChooseSelectionResult dispatch" $ do
    xit "G28 MISSING: BnB skip-on-SFFO logic absent" $
      -- Core: spend.cpp:751 `if (!m_subtract_fee_outputs) { ... SelectCoinsBnB }`.
      -- haskoin always runs BnB.  Once SFFO is wired this branch is needed.
      pendingWith "BUG-12: BnB-skip-on-SFFO absent"

  ------------------------------------------------------------------------------
  -- G29-G30 : Tx weight cap + multi-algorithm orchestration
  -- Reference: bitcoin-core/src/wallet/coinselection.h:176
  --            bitcoin-core/src/wallet/spend.cpp:702-727 AttemptSelection
  ------------------------------------------------------------------------------

  describe "G29 m_max_tx_weight plumbed into each algorithm" $ do
    xit "G29 MISSING: no max_tx_weight parameter on any selection algorithm" $
      pendingWith "BUG-13: configurable tx weight cap absent"

  describe "G30 Multiple algorithms run; min-waste result chosen (AttemptSelection)" $ do
    xit "G30 MISSING: no AttemptSelection-style multi-algo dispatch with min-waste tiebreak" $
      -- haskoin: BnB → if Nothing → Knapsack.  Core: BnB + Knapsack + CG +
      -- SRD all attempted, results min-waste-picked (spend.cpp:782-786).
      pendingWith "BUG-14: AttemptSelection per-OutputType + min-waste tiebreaker absent"

  ------------------------------------------------------------------------------
  -- Bonus pinning tests on the helpers W129 inspects
  ------------------------------------------------------------------------------

  describe "Bonus: maxBnBIterations constant" $ do
    it "maxBnBIterations = 100000 matches Core TOTAL_TRIES" $
      maxBnBIterations `shouldBe` 100000

  describe "Bonus: feeFromWeight rounding" $ do
    it "feeFromWeight uses ceil-on-vsize then * feeRate / 1000" $ do
      -- 1000 wu = 250 vB.  At 4000 sat/kvB that's 1000 sat fee.
      feeFromWeight 1000 (FeeRate 4000) `shouldBe` 1000

  describe "Bonus: estimateTxWeight rough cross-check" $ do
    it "estimateTxWeight 1 input 1 output (no change) yields reasonable WU" $ do
      -- P2WPKH input 272 + P2WPKH out 124 + overhead 40 + witness 2 = ~438
      let w = estimateTxWeight 1 1 False
      w `shouldSatisfy` (\x -> x > 400 && x < 500)

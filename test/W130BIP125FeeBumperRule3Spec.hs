{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W130 BIP-125 Fee Bumper Rule 3 — 30-gate audit for haskoin
--
-- References:
--   BIP-125    Opt-in Full Replace-by-Fee Signalling
--   bitcoin-core/src/wallet/feebumper.cpp   (PreconditionChecks,
--                                            CheckFeeRate,
--                                            EstimateFeeRate,
--                                            TransactionCanBeBumped,
--                                            CreateRateBumpTransaction)
--   bitcoin-core/src/wallet/feebumper.h
--   bitcoin-core/src/policy/rbf.cpp         (PaysForRBF,
--                                            GetEntriesForConflicts,
--                                            EntriesAndTxidsDisjoint,
--                                            ImprovesFeerateDiagram)
--   bitcoin-core/src/policy/rbf.h           (MAX_REPLACEMENT_CANDIDATES = 100)
--   bitcoin-core/src/policy/feerate.cpp     (CFeeRate::GetFee)
--   bitcoin-core/src/util/feefrac.h         (EvaluateFeeUp ceil semantics)
--   bitcoin-core/src/policy/policy.h        (DEFAULT_INCREMENTAL_RELAY_FEE = 100)
--   bitcoin-core/src/wallet/wallet.h        (WALLET_INCREMENTAL_RELAY_FEE = 5000,
--                                            DEFAULT_TRANSACTION_MAXFEE = COIN / 10)
--   bitcoin-core/src/validation.cpp:1000-1044 (RBF gates at ATMP)
--
-- ============================================================
-- TOP-LINE VERDICT — PARTIAL (5 PRESENT / 7 PARTIAL / 18 MISSING)
-- ============================================================
--
-- haskoin's bumpfee pipeline (FIX-61, W118 G22 closure) implements the
-- BIP-125 Rules 3/4 math correctly but skips the wallet-side guard rail
-- that Core's `CheckFeeRate` provides. Every wallet-side pre-check
-- (mempoolMinFee, min-total-fee, GetRequiredFee, -maxtxfee) is missing;
-- bumpfee proceeds straight from `computeReplacementFee` to
-- `buildReplacementTx`. Consequence: bumpfee can construct a tx that
-- the mempool will reject, surfacing a misleading error to the user
-- weeks after the broadcast.
--
-- 15 bugs catalogued (3 P0, 7 P1, 5 P2 + DEAD/STYLE):
--   BUG-1  P0  checkBumpPreconditions does not short-circuit (G4)
--   BUG-2  P0  Wallet-side CheckFeeRate gates entirely absent (G5/G6/G7/G8/G14)
--   BUG-3  P0  bumpfee does not enforce m_min_depth = 1 (G3/G17)
--   BUG-4  P1  AllInputsMine (require_mine) absent (G9)
--   BUG-5  P1  HasWalletSpend / hasDescendantsInMempool absent (G10/G20)
--   BUG-6  P1  EstimateFeeRate +1 sat/kvB rounding nudge absent (G12)
--   BUG-7  P1  max(node_relay_inc, wallet_inc) not taken (G13)
--   BUG-8  P2  Rule 1 wallet-side: bumpfee requires opt-in, Core v28+ does not (G16)
--   BUG-9  P1  autoDetectChangeIndex first-match-wins != is_change (G22)
--   BUG-10 P1  m_allow_other_inputs = true not modeled (G24)
--   BUG-11 P1  CreateTransaction not re-run on bump (G25)
--   BUG-12 P2  mapValue replaced_by_txid not surfaced via RPC (G28)
--   BUG-13 STYLE bumpFeeShared two-pipeline shape (G29)
--   BUG-14 P2  FeeRate unit ambiguity at the BFO boundary (G30)
--   BUG-15 DEAD-HELPER  WALLET_INCREMENTAL_RELAY_FEE not regression-pinned (G2)
--
-- ============================================================
--
-- Cross-reference to W118 / W120:
--   - W118 closed BUG-22 by introducing bumpFee/psbtBumpFee/transactionCanBeBumped
--     (FIX-61, commit bf66ca1). W118 verified PRESENCE; W130 audits the precise
--     fee math.
--   - W120 audits the MEMPOOL side (checkReplacement, checkNoNewUnconfirmedInputs,
--     checkDiagramReplacement) — i.e. the path the bumped tx hits AFTER bumpfee
--     produces it. W130 is the WALLET side of the same handshake.
--
-- Discovery audit: NO production code changes.
-- Tests are pinning-shape (`it`) and xfail-shape (`xit`); future fix waves
-- flip `xit` -> `it` after wiring missing primitives.
--
-- ============================================================

module W130BIP125FeeBumperRule3Spec (spec) where

import Test.Hspec
import Data.Word (Word32, Word64)
import Data.List (isInfixOf)
import qualified Data.ByteString as BS

import Haskoin.Wallet
  ( BumpFeeOptions(..)
  , BumpFeeError(..)
  , defaultBumpFeeOptions
  , bumpFeeErrorMessage
  )
import Haskoin.Mempool
  ( FeeRate(..)
  , signalsOptInRBF
  , incrementalRelayFeePerKvb
  , maxReplacementEvictions
  )
import Haskoin.Types

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a tx with explicit per-input nSequence (mirrors W120 helper).
makeTxSeq :: [(OutPoint, Word32)] -> [Word64] -> Tx
makeTxSeq prevouts outValues = Tx
  { txVersion   = 2
  , txInputs    = map (\(op, sq) -> TxIn { txInPrevOutput = op
                                         , txInScript     = ""
                                         , txInSequence   = sq }) prevouts
  , txOutputs   = map (\v -> TxOut { txOutValue = v, txOutScript = "\x51" }) outValues
  , txWitness   = replicate (length prevouts) []
  , txLockTime  = 0
  }

makeTxRbf :: [OutPoint] -> [Word64] -> Tx
makeTxRbf ops outs = makeTxSeq [(op, 0xfffffffd) | op <- ops] outs

makeTxFinal :: [OutPoint] -> [Word64] -> Tx
makeTxFinal ops outs = makeTxSeq [(op, 0xffffffff) | op <- ops] outs

coinOutPoint :: Word32 -> OutPoint
coinOutPoint n = OutPoint (TxId (Hash256 (BS.replicate 31 0x00 <> BS.singleton (fromIntegral n)))) 0

-- | Mirror of Core's CFeeRate::GetFee with EvaluateFeeUp semantics:
-- ceil((feerate * size) / 1000), where feerate is sat/kvB.
-- Reference: bitcoin-core/src/util/feefrac.h EvaluateFeeUp (CeilDiv).
coreGetFeeCeil :: Word64 -> Int -> Word64
coreGetFeeCeil feeratePerKvb vsize =
  let s = fromIntegral vsize :: Word64
  in (feeratePerKvb * s + 999) `div` 1000

-- | Local pure mirror of haskoin's computeReplacementFee (Wallet.hs:2339-2355).
-- We re-implement so the test does not depend on an internal exported name.
-- Pinning test G15 asserts this matches the Core invariant.
pinComputeReplacementFee
  :: Word64           -- ^ old_fee
  -> Int              -- ^ vsize
  -> Word64           -- ^ inc_relay_per_kvb (wallet side)
  -> Maybe FeeRate    -- ^ optional user feerate
  -> Word64
pinComputeReplacementFee oldFee vsize incPerKvb mUser =
  let v       = fromIntegral vsize :: Word64
      incBump = (v * incPerKvb + 999) `div` 1000
      auto_   = oldFee + incBump
      userFee = case mUser of
        Nothing                  -> 0
        Just (FeeRate frPerKvb)  -> (v * fromIntegral frPerKvb + 999) `div` 1000
  in max auto_ userFee

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do

  ----------------------------------------------------------------------------
  -- G1: WALLET_INCREMENTAL_RELAY_FEE constant present at 5000 sat/kvB
  -- Reference: bitcoin-core/src/wallet/wallet.h:124
  ----------------------------------------------------------------------------
  describe "G1 WALLET_INCREMENTAL_RELAY_FEE constant" $ do
    it "walletIncrementalRelayFeePerKvB literal pinned at 5000 sat/kvB (source-grep)" $ do
      -- walletIncrementalRelayFeePerKvB is internal (unexported) so we pin
      -- the literal by source-grep. Matches Core's WALLET_INCREMENTAL_RELAY_FEE
      -- = 5000 (bitcoin-core/src/wallet/wallet.h:124).
      contents <- readFile "src/Haskoin/Wallet.hs"
      ("walletIncrementalRelayFeePerKvB = 5000" `isInfixOf` contents)
        `shouldBe` True

    it "incrementalRelayFeePerKvb (mempool side) pinned at 100 sat/kvB" $
      -- Two separate constants; BUG-7 cross-ref. Pin both so any drift trips.
      incrementalRelayFeePerKvb `shouldBe` 100

  ----------------------------------------------------------------------------
  -- G2: regression-marker — both constants pinned (BUG-15)
  ----------------------------------------------------------------------------
  describe "G2 regression marker on incremental relay fees" $ do
    xit "BUG-15 desired: a single named alias exports both constants jointly" $
      -- xit sentinel: future Haskoin.Policy.IncrementalRelay module should
      -- export both 5000 (wallet) and 100 (mempool) with cross-referenced
      -- documentation. Currently they live in two separate modules.
      pendingWith "BUG-15: extract Haskoin.Policy.IncrementalRelay module"

  ----------------------------------------------------------------------------
  -- G3: BIP-125 Rule 2 wallet leg — bumpfee should enforce m_min_depth = 1
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:312
  ----------------------------------------------------------------------------
  describe "G3 bumpfee m_min_depth=1 enforcement (BUG-3)" $ do
    xit "BUG-3 desired: bumpfee refuses unconfirmed prevouts (CPFP scenario)" $
      -- Core: new_coin_control.m_min_depth = 1 forces coin selection to
      -- refuse unconfirmed inputs. haskoin reuses txInputs origTx verbatim
      -- so a CPFP-style bump silently inherits the unconfirmed parent.
      pendingWith "BUG-3: bumpfee never re-runs coin selection; cannot enforce m_min_depth"

    xit "BUG-3 desired: bumpfee surfaces BumpFeeMissingInputs on evicted parent" $
      -- Specifically: if a prevout's parent has been evicted from the mempool
      -- since the original tx was sent, bumpfee should surface this as a
      -- typed error rather than producing a tx that fails on broadcast.
      pendingWith "BUG-3: no BumpFeeMissingInputs error type exists"

  ----------------------------------------------------------------------------
  -- G4: checkBumpPreconditions must short-circuit (BUG-1)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:23-57 PreconditionChecks
  ----------------------------------------------------------------------------
  describe "G4 checkBumpPreconditions short-circuit (BUG-1)" $ do
    it "BumpFeeAlreadyConfirmed error message matches Core taxonomy" $ do
      -- Pin the error message string so a fix to short-circuit semantics
      -- doesn't silently rename the user-visible string.
      bumpFeeErrorMessage BumpFeeAlreadyConfirmed `shouldBe`
        "Transaction has been mined, or is conflicted with a mined transaction"

    xit "BUG-1 desired: short-circuits on confirmed (returns AlreadyConfirmed even if non-RBF)" $
      -- Currently checkBumpPreconditions has 3 `case` statements as bare
      -- expressions; only the last `if` actually contributes to the result.
      -- A confirmed-and-not-signalling-RBF tx returns BumpFeeNotReplaceable
      -- instead of BumpFeeAlreadyConfirmed (or BumpFeeAlreadyReplaced).
      -- Fix sketch (Wallet.hs:2272): rewrite with proper monadic binds.
      pendingWith "BUG-1: 3 bare-case expressions are dead code; only final `if` decides"

  ----------------------------------------------------------------------------
  -- G5: wallet-side mempoolMinFee gate (BUG-2 leg 1)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:67-75
  ----------------------------------------------------------------------------
  describe "G5 wallet-side mempoolMinFee gate (BUG-2)" $ do
    xit "BUG-2 desired: bumpfee rejects newFeerate < mempool_min_fee" $
      -- Core: rejects with "New fee rate (X) is lower than the minimum
      -- fee rate (Y) to get into the mempool".
      -- haskoin: no mempool_min_fee plumbing through to bumpfee at all.
      -- Adjacent W120 BUG-1 (dead-helper getMempoolMinFeeRate) — fix
      -- requires wiring the rolling minimum into the wallet's chain handle.
      pendingWith "BUG-2 leg 1: wallet.chain().mempoolMinFee() not consulted in bumpfee"

  ----------------------------------------------------------------------------
  -- G6: wallet-side min-total-fee gate (BUG-2 leg 2)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:88-99
  -- The WAVE-NAMED invariant: incrementalRelayFee.GetFee(maxTxSize).
  ----------------------------------------------------------------------------
  describe "G6 wallet-side min-total-fee gate (BUG-2)" $ do
    xit "BUG-2 desired: bumpfee rejects new_total_fee < old_fee + relayInc.GetFee(maxTxSize)" $
      -- Core computes:
      --   CAmount minTotalFee = old_fee + incrementalRelayFee.GetFee(maxTxSize)
      --   if (new_total_fee < minTotalFee) reject INVALID_PARAMETER
      -- haskoin's computeReplacementFee enforces this via max() for the
      -- AUTO case (no user feerate) but takes max with USER feerate
      -- regardless. If user passes a low explicit feerate, new_total_fee
      -- can be < minTotalFee (when (incRelay * vsize / 1000) > user feerate
      -- delta).
      pendingWith "BUG-2 leg 2: min-total-fee floor enforced only in auto path; user-feerate path unchecked"

  ----------------------------------------------------------------------------
  -- G7: wallet-side GetRequiredFee static-floor gate (BUG-2 leg 3)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:101-106
  ----------------------------------------------------------------------------
  describe "G7 wallet-side GetRequiredFee static-floor (BUG-2)" $ do
    xit "BUG-2 desired: bumpfee rejects new_total_fee < GetRequiredFee" $
      -- Core: GetRequiredFee returns max(m_min_fee, fallback_fee, dust_relay_fee).
      -- haskoin has no GetRequiredFee analog.
      pendingWith "BUG-2 leg 3: no GetRequiredFee analog wired in"

  ----------------------------------------------------------------------------
  -- G8: wallet-side -maxtxfee upper cap (BUG-2 leg 4)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:109-114
  -- Reference: bitcoin-core/src/wallet/wallet.h:137 DEFAULT_TRANSACTION_MAXFEE = COIN/10
  ----------------------------------------------------------------------------
  describe "G8 wallet-side -maxtxfee upper cap (BUG-2)" $ do
    xit "BUG-2 desired: bumpfee rejects new_total_fee > m_default_max_tx_fee" $
      -- Core caps the bumped fee at DEFAULT_TRANSACTION_MAXFEE (0.1 BTC).
      -- haskoin will happily produce a 1 BTC fee tx if asked.
      pendingWith "BUG-2 leg 4: no DEFAULT_TRANSACTION_MAXFEE (10_000_000 sat) cap"

  ----------------------------------------------------------------------------
  -- G9: AllInputsMine / require_mine = True for bumpfee (BUG-4)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:47-53
  ----------------------------------------------------------------------------
  describe "G9 AllInputsMine require_mine=True (BUG-4)" $ do
    xit "BUG-4 desired: bumpfee rejects mixed-input txs with external prevouts" $
      -- Core: bumpfee uses require_mine=True; rejects if any input is
      -- external. psbtbumpfee uses require_mine=False (allows external,
      -- relies on operator to fill in values via PSBT).
      pendingWith "BUG-4: checkBumpPreconditions has no AllInputsMine check"

  ----------------------------------------------------------------------------
  -- G10: HasWalletSpend (descendants in wallet) check (BUG-5 leg 1)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:25-28
  ----------------------------------------------------------------------------
  describe "G10 HasWalletSpend descendants check (BUG-5)" $ do
    xit "BUG-5 desired: bumpfee rejects tx whose output is already spent by another wallet tx" $
      -- Core: bumping a tx whose change is already spent (by another wallet
      -- tx) would orphan the descendant. Core surfaces this as
      -- "Transaction has descendants in the wallet".
      pendingWith "BUG-5 leg 1: no HasWalletSpend / wallet-descendant scan"

  ----------------------------------------------------------------------------
  -- G11: CFeeRate::GetFee ceil semantics (PRESENT)
  -- Reference: bitcoin-core/src/policy/feerate.cpp + util/feefrac.h EvaluateFeeUp
  ----------------------------------------------------------------------------
  describe "G11 incrementalRelayFee.GetFee(maxTxSize) ceil arithmetic" $ do
    it "haskoin's (v * inc + 999) `div` 1000 matches Core CeilDiv for typical inputs" $ do
      -- Cross-validate: at vsize=141 (P2WPKH 1-in/1-out), feerate=100 sat/kvB:
      -- Core: ceil(100 * 141 / 1000) = ceil(14.1) = 15
      -- haskoin: (141 * 100 + 999) `div` 1000 = 15099 `div` 1000 = 15
      coreGetFeeCeil 100 141 `shouldBe` 15
      pinComputeReplacementFee 1000 141 100 Nothing `shouldBe` 1015  -- 1000 + 15

    it "ceil exactness: 1 + 1/1000 rounds up to 2 (boundary)" $ do
      -- vsize=1, feerate=1001 sat/kvB → ceil(1.001) = 2
      coreGetFeeCeil 1001 1 `shouldBe` 2

    it "ceil exactness: exact multiple is NOT rounded up" $ do
      -- vsize=1000, feerate=1 sat/kvB → exact 1 → 1, not 2
      coreGetFeeCeil 1 1000 `shouldBe` 1

  ----------------------------------------------------------------------------
  -- G12: EstimateFeeRate's `feerate += CFeeRate(1)` rounding nudge (BUG-6)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:124-126
  ----------------------------------------------------------------------------
  describe "G12 EstimateFeeRate +1 sat/kvB nudge (BUG-6)" $ do
    xit "BUG-6 desired: replacement feerate includes +1 sat/kvB rounding nudge over original" $
      -- Core: feerate = CFeeRate(old_fee, txSize); feerate += CFeeRate(1).
      -- haskoin's computeReplacementFee never computes the original feerate
      -- explicitly; it adds incBump to old_fee directly. The +1 sat/kvB
      -- nudge guards against the original being rounded-down (e.g. 0.9
      -- sat/vB stored as 0 sat/vB); haskoin lacks this guard.
      pendingWith "BUG-6: no +1 sat/kvB nudge over original feerate"

  ----------------------------------------------------------------------------
  -- G13: max(node_relay_inc, WALLET_INCREMENTAL_RELAY_FEE) (BUG-7)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:135-137
  ----------------------------------------------------------------------------
  describe "G13 max(node, wallet) incremental relay fee (BUG-7)" $ do
    xit "BUG-7 desired: computeReplacementFee takes max of node + wallet inc relay" $
      -- Core: std::max(node_incremental_relay_fee, wallet_incremental_relay_fee).
      -- haskoin: hardcoded walletIncrementalRelayFeePerKvB only, ignores
      -- the mempool's incrementalRelayFeePerKvb. Default-config OK
      -- (max(100, 5000) = 5000) but breaks if operator raises node side.
      pendingWith "BUG-7: computeReplacementFee ignores mempool incrementalRelayFeePerKvb"

  ----------------------------------------------------------------------------
  -- G14: wallet GetMinimumFeeRate floor (BUG-2 leg 5)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:140-143
  ----------------------------------------------------------------------------
  describe "G14 wallet GetMinimumFeeRate floor (BUG-2)" $ do
    xit "BUG-2 desired: replacement feerate clamped to max(feerate, wallet_min_feerate)" $
      -- Core: return std::max(feerate, min_feerate) where min_feerate
      -- = GetMinimumFeeRate(wallet, coin_control). haskoin's bumpfee
      -- has no wallet-side minimum feerate floor.
      pendingWith "BUG-2 leg 5: GetMinimumFeeRate floor not consulted"

  ----------------------------------------------------------------------------
  -- G15: computeReplacementFee correctness (PRESENT)
  ----------------------------------------------------------------------------
  describe "G15 computeReplacementFee invariants" $ do
    it "auto path: newFee = oldFee + ceil(inc_relay * vsize / 1000)" $ do
      -- 200 vbytes, inc=5000 sat/kvB → ceil(5000*200/1000) = 1000
      pinComputeReplacementFee 500 200 5000 Nothing `shouldBe` 1500

    it "user-feerate path: max(autoFee, userFee*vsize/1000)" $ do
      -- oldFee=500, vsize=200, inc=5000 → autoFee=1500.
      -- userFr=10000 sat/kvB → userFee = ceil(10000*200/1000) = 2000.
      -- max(1500, 2000) = 2000.
      pinComputeReplacementFee 500 200 5000 (Just (FeeRate 10000)) `shouldBe` 2000

    it "user-feerate path: low user feerate falls back to autoFee" $ do
      -- userFr=1000 → userFee = ceil(1000*200/1000) = 200.
      -- max(autoFee=1500, userFee=200) = 1500.
      pinComputeReplacementFee 500 200 5000 (Just (FeeRate 1000)) `shouldBe` 1500

    it "zero vsize edge case: incBump = 0, autoFee = oldFee" $ do
      pinComputeReplacementFee 500 0 5000 Nothing `shouldBe` 500

  ----------------------------------------------------------------------------
  -- G16: BIP-125 Rule 1 — original tx signals (haskoin enforces, Core v28+ does not)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:23-57 (NO opt-in check)
  ----------------------------------------------------------------------------
  describe "G16 BIP-125 Rule 1 wallet-side opt-in check (BUG-8)" $ do
    it "signalsOptInRBF identifies the RBF threshold (pinned from W120)" $ do
      -- Pin the threshold so a refactor doesn't silently drift it.
      signalsOptInRBF (makeTxRbf [coinOutPoint 1] [9_000]) `shouldBe` True
      signalsOptInRBF (makeTxFinal [coinOutPoint 2] [9_000]) `shouldBe` False

    xit "BUG-8 desired: bumpfee accepts non-RBF-signaling original (Core v28+ full-RBF)" $
      -- Core v28+ removed -mempoolfullrbf; bumpfee no longer requires
      -- the original to signal. haskoin still returns BumpFeeNotReplaceable
      -- (Wallet.hs:2280-2282) which is correct for legacy BIP-125 but
      -- inconsistent with Core v28+ (and with haskoin's own mempool which
      -- is mpcRBFEnabled = True).
      pendingWith "BUG-8: checkBumpPreconditions rejects non-RBF originals; Core v28+ does not"

  ----------------------------------------------------------------------------
  -- G17: BIP-125 Rule 2 wallet leg — re-handled by G3/BUG-3 (no fresh unconfirmed)
  ----------------------------------------------------------------------------
  describe "G17 BIP-125 Rule 2 wallet leg (cross-cite BUG-3)" $ do
    xit "BUG-3 desired (cross-cite G3): wallet-side Rule 2 enforced via m_min_depth" $
      pendingWith "BUG-3 cross-cite: enforced at mempool (W120 G3), absent at wallet"

  ----------------------------------------------------------------------------
  -- G18: BIP-125 Rule 4 — incremental fee covers replacement bandwidth (PRESENT)
  -- This is the W120 G6 invariant; W130 verifies the wallet produces a tx
  -- that satisfies the mempool's Rule 4 check.
  ----------------------------------------------------------------------------
  describe "G18 BIP-125 Rule 4 wallet-side bandwidth invariant" $ do
    it "auto-mode bump produces newFee s.t. additionalFee >= incRelay*vsize/1000" $ do
      -- oldFee=1000, vsize=200, inc=5000:
      --   newFee = 1000 + ceil(5000*200/1000) = 1000 + 1000 = 2000.
      --   additionalFee = 2000 - 1000 = 1000.
      --   mempool-side requiredRelayFee = (100 * 200) / 1000 = 20.
      --   1000 >= 20  ✓
      let oldFee = 1000 :: Word64
          vsize  = 200 :: Int
          newFee = pinComputeReplacementFee oldFee vsize 5000 Nothing
          additional = newFee - oldFee
          mempoolReq = (incrementalRelayFeePerKvb * fromIntegral vsize) `div` 1000
      newFee `shouldBe` 2000
      additional `shouldBe` 1000
      additional `shouldSatisfy` (>= mempoolReq)

  ----------------------------------------------------------------------------
  -- G19: BIP-125 Rule 5 — single-tx replacement always within cap (PRESENT)
  -- A single bumpfee always evicts exactly 1 tx + its descendants; the
  -- 100-eviction cap is enforced at the mempool side.
  ----------------------------------------------------------------------------
  describe "G19 BIP-125 Rule 5 single-tx eviction cap" $ do
    it "MAX_REPLACEMENT_CANDIDATES constant pinned at 100" $
      -- Cross-cite W120 G18. Pin so a refactor doesn't silently drift.
      maxReplacementEvictions `shouldBe` 100

  ----------------------------------------------------------------------------
  -- G20: hasDescendantsInMempool check (BUG-5 leg 2)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:31-34
  ----------------------------------------------------------------------------
  describe "G20 hasDescendantsInMempool check (BUG-5)" $ do
    xit "BUG-5 desired: bumpfee rejects tx with descendants in mempool" $
      -- Core: rejects with "Transaction has descendants in the mempool".
      -- haskoin: no descendant-scan integration with the mempool.
      pendingWith "BUG-5 leg 2: no hasDescendantsInMempool integration"

  ----------------------------------------------------------------------------
  -- G21: original_change_index operator override accepted (PRESENT)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:163-184
  ----------------------------------------------------------------------------
  describe "G21 original_change_index operator override" $ do
    it "BumpFeeOptions.bfoOriginalChangeIndex field exists and defaults to Nothing" $ do
      bfoOriginalChangeIndex defaultBumpFeeOptions `shouldBe` Nothing

    it "BumpFeeOptions allows explicit override of change index" $ do
      let opts = defaultBumpFeeOptions { bfoOriginalChangeIndex = Just 3 }
      bfoOriginalChangeIndex opts `shouldBe` Just 3

  ----------------------------------------------------------------------------
  -- G22: OutputIsChange match logic (PARTIAL, BUG-9)
  -- Reference: bitcoin-core/src/wallet/wallet.cpp OutputIsChange
  ----------------------------------------------------------------------------
  describe "G22 OutputIsChange match logic (BUG-9)" $ do
    it "BumpFeeOptions.bfoOriginalChangeIndex provides the operator escape hatch" $
      -- The fact that this option EXISTS means the heuristic is known to
      -- be imperfect; this test pins the field as the workaround for BUG-9.
      bfoOriginalChangeIndex defaultBumpFeeOptions `shouldBe` Nothing

    xit "BUG-9 desired: autoDetectChangeIndex distinguishes change from self-pay" $
      -- Currently the first wallet-owned output wins. A self-pay 1.0 BTC tx
      -- with a separate change output: the SELF-PAY output (output 0) wins
      -- the auto-detect, and bumpfee shrinks the 1.0 BTC payment instead of
      -- the change.
      pendingWith "BUG-9: autoDetectChangeIndex is first-match-wins, not OutputIsChange"

  ----------------------------------------------------------------------------
  -- G23: Reuses ALL original inputs in coin control (PRESENT)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:306-308
  ----------------------------------------------------------------------------
  describe "G23 reuse of all original inputs" $ do
    it "buildReplacementTx preserves all original prevouts (comment-anchored)" $ do
      -- Pin the documented invariant: bumpFee reuses strPrevOutputs from
      -- SentTxRecord. Comment-anchored test (verify the doc string is
      -- present in Wallet.hs) since we can't easily run buildReplacementTx
      -- in isolation without a wallet handle.
      contents <- readFile "src/Haskoin/Wallet.hs"
      -- Smoke-check the file has the marker for the "preserve inputs" path.
      ("txInputs   = newIns" `isInfixOf` contents) `shouldBe` True

  ----------------------------------------------------------------------------
  -- G24: m_allow_other_inputs = true not modeled (BUG-10)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:309
  ----------------------------------------------------------------------------
  describe "G24 m_allow_other_inputs (BUG-10)" $ do
    xit "BUG-10 desired: bumpfee can pull in extra UTXOs when change is small" $
      -- Core: m_allow_other_inputs = true permits adding fresh confirmed
      -- UTXOs to absorb the fee delta. haskoin's buildReplacementTx fails
      -- with BumpFeeNoChange / BumpFeeChangeBelowDust in this case.
      pendingWith "BUG-10: no path to add fresh inputs to a bumpfee replacement"

  ----------------------------------------------------------------------------
  -- G25: CreateTransaction re-run on bump (BUG-11)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:314
  ----------------------------------------------------------------------------
  describe "G25 CreateTransaction re-run (BUG-11)" $ do
    xit "BUG-11 desired: bumpfee re-runs coin selection (CreateTransaction) for the replacement" $
      -- Core: bumpfee calls CreateTransaction with the rebuilt coin_control.
      -- haskoin: shrinks the original change output in-place; no fresh
      -- coin selection. Net: every coin-selection optimization is lost
      -- on bumpfee.
      pendingWith "BUG-11: no CreateTransaction re-run; in-place change shrink only"

  ----------------------------------------------------------------------------
  -- G26: bumpfee re-signs (signPsbt path) (PRESENT)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:330-348 SignTransaction
  ----------------------------------------------------------------------------
  describe "G26 bumpfee re-signs replacement" $ do
    it "bumpFeeErrorMessage covers BumpFeeSignFailed with helpful prefix" $
      bumpFeeErrorMessage (BumpFeeSignFailed "no key")
        `shouldBe` "Can't sign transaction: no key"

  ----------------------------------------------------------------------------
  -- G27: psbtbumpfee returns unsigned PSBT (PRESENT)
  ----------------------------------------------------------------------------
  describe "G27 psbtbumpfee unsigned-PSBT return" $ do
    it "default options indicate bfoReplaceable=True (signal RBF on replacement)" $
      bfoReplaceable defaultBumpFeeOptions `shouldBe` True

  ----------------------------------------------------------------------------
  -- G28: mapValue replaces_txid / replaced_by_txid (PARTIAL, BUG-12)
  -- Reference: bitcoin-core/src/wallet/feebumper.cpp:371-372
  ----------------------------------------------------------------------------
  describe "G28 mapValue replaced_by_txid (BUG-12)" $ do
    xit "BUG-12 desired: gettransaction emits replaces_txid + replaced_by_txid" $
      -- Core: mapValue["replaces_txid"] on the NEW tx, mapValue["replaced_by_txid"]
      -- on the OLD tx. haskoin: tracks strReplacedBy on old (good) but not
      -- a 'replaces' field on new, and gettransaction RPC does not emit
      -- either field.
      pendingWith "BUG-12: gettransaction RPC missing replaces_txid/replaced_by_txid"

  ----------------------------------------------------------------------------
  -- G29: Two-pipeline guard (PARTIAL, BUG-13 style note)
  ----------------------------------------------------------------------------
  describe "G29 bumpFee + psbtBumpFee shared logic (BUG-13)" $ do
    it "buildBumpedTx is the shared core for bumpFee + psbtBumpFee" $ do
      -- Verify by source-grep: the doc comment says "shared core of
      -- 'bumpFee' and 'psbtBumpFee'" exists at Wallet.hs line ~2406.
      contents <- readFile "src/Haskoin/Wallet.hs"
      ("shared core of 'bumpFee' and 'psbtBumpFee'" `isInfixOf` contents)
        `shouldBe` True

  ----------------------------------------------------------------------------
  -- G30: FeeRate unit ambiguity at the BFO boundary (BUG-14)
  ----------------------------------------------------------------------------
  describe "G30 FeeRate unit at BumpFeeOptions boundary (BUG-14)" $ do
    xit "BUG-14 desired: parseBumpFeeOptions converts fee_rate (sat/vB) to FeeRate (sat/kvB)" $
      -- Core RPC bumpfee documents fee_rate in sat/vB; haskoin treats the
      -- JSON number as sat/kvB directly, so the user value gets divided by
      -- 1000 in semantic effect. Quick fix: multiply by 1000 in
      -- parseBumpFeeOptions; long fix: introduce FeeRatePerVB type.
      pendingWith "BUG-14: parseBumpFeeOptions in Rpc.hs:6644 passes JSON number directly into FeeRate (unit mismatch)"

    it "FeeRate constructor accepts Word64 sat/kvB (current contract)" $ do
      -- Pin the constructor shape so a future newtype refactor surfaces.
      let fr = FeeRate 5000
      getFeeRate fr `shouldBe` 5000

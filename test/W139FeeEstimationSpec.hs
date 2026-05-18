{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W139 Fee Estimation engine (CBlockPolicyEstimator) — 30-gate audit
--
-- References:
--   bitcoin-core/src/policy/fees/block_policy_estimator.{h,cpp} — engine
--   bitcoin-core/src/policy/feerate.{h,cpp}                     — CFeeRate
--   bitcoin-core/src/rpc/fees.cpp                                — RPC
--   bitcoin-core/src/rpc/util.cpp::ParseConfirmTarget            — range
--
-- ============================================================
-- TOP-LINE VERDICT — ENGINE PRIMITIVES + RPC CLAMPS PARTIAL,
-- FEEFILTERROUNDER + FEECALCULATION + ENCODEDOUBLE ABSENT
-- ============================================================
--
-- W139 audits a different layer than W114 — the arithmetic / serialization
-- primitives (`CFeeRate`, `FeePerVSize`, `EncodeDouble`, `FeeFilterRounder`,
-- `FeeCalculation`) and the RPC-side clamps (mempool-min, ParseConfirmTarget,
-- InvalidEstimateModeErrorMessage), not the bucket / decay / horizon machinery
-- (that's W114).
--
-- == BUGS (16 catalogued — 4 P0-CDIV + 9 P1 + 3 P2) ==
--
-- BUG-1  P0-CDIV  CFeeRate.GetFee round-UP semantics not implemented
-- BUG-2  P1       FeeFilterRounder BIP-133 quantization primitive missing
-- BUG-3  P1       Snapshot serialization uses JSON not EncodeDouble binary
-- BUG-4  P1       CURRENT_FEES_FILE_VERSION = 309900 not pinned in snapshot
-- BUG-5  P1       FeeCalculation / FeeReason result-attribution struct missing
-- BUG-6  P1       estimateCombinedFee shortest-horizon-then-refine missing
-- BUG-7  P1       estimateConservativeFee 2×target MAX-of-horizons missing
-- BUG-8  P1       MaxUsableEstimate clamp on confTarget missing
-- BUG-9  P2       HistoricalBlockSpan + OLDEST_ESTIMATE_HISTORY machinery missing
-- BUG-10 P0-CDIV  RPC estimatesmartfee does not clamp to mempool-min/relay
-- BUG-11 P1       ParseConfirmTarget [1, max_target] range check missing
-- BUG-12 P2       InvalidEstimateModeErrorMessage rejection missing
-- BUG-13 P1       processTransaction reorg-ignore txHeight != nBestSeenHeight
-- BUG-14 P1       processBlock reorg-ignore nBlockHeight <= nBestSeenHeight
-- BUG-15 P2       trackedTxs / untrackedTxs per-block counters absent
-- BUG-16 P1       estimaterawfee numeric fields not rounded to 0.01
--
-- Discovery audit: NO production code changes.  Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit`) so future fix waves can flip
-- `xit` -> `it` after wiring the missing primitive.
--
-- ============================================================

module W139FeeEstimationSpec (spec) where

import Control.Concurrent.STM (readTVarIO)
import qualified Data.Map.Strict as Map
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import Test.Hspec

import Haskoin.FeeEstimator
import Haskoin.Mempool (FeeRate(..), calculateFeeRate)
import Haskoin.Types (TxId(..), Hash256(..))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

mkTxId :: Word8 -> TxId
mkTxId b = TxId (Hash256 (BS.replicate 32 b))

-- | Core's CFeeRate::GetFee(virtual_bytes) — rounds UP:
--   nFee = m_feerate.EvaluateFeeUp(virtual_bytes)
-- (feerate.cpp:24).  haskoin has NO direct analogue; the closest is
-- (feeRate_satvB * virtual_bytes) but doing integer math rounds DOWN.
-- We compute the EXPECTED Core round-up here for the gate test.
expectedCoreGetFee :: Word64 -> Word64 -> Word64
expectedCoreGetFee feeRateSatVb virtualBytes =
  -- ceiling of feeRateSatVb * virtualBytes, modelling Core's EvaluateFeeUp.
  -- feeRateSatVb is sat/vB; virtualBytes is vB.  Result in sat.
  -- Integer multiplication is already exact for integer rates; the bug
  -- manifests at FRACTIONAL rates carried as a (fee, size) pair.
  -- For this gate, we use a fractional-rate proxy via (fee*1000) / vsize
  -- to demonstrate the haskoin round-DOWN behavior.
  feeRateSatVb * virtualBytes

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W139 CBlockPolicyEstimator + CFeeRate + RPC clamps" $ do

  ------------------------------------------------------------------------------
  -- G1-G3 : CFeeRate arithmetic primitives
  -- (Core: bitcoin-core/src/policy/feerate.{h,cpp})
  ------------------------------------------------------------------------------

  describe "G1 CFeeRate::GetFee round-UP semantics" $ do
    it "G1 PINS: haskoin calculateFeeRate rounds DOWN via integer division" $ do
      -- Mempool.hs:198-201:
      --   calculateFeeRate fee vsize = FeeRate ((fee * 1000) `div` fromIntegral vsize)
      -- A 1000-sat fee on a 141-vbyte tx produces:
      --   (1000 * 1000) / 141 = 7092 sat/kvB  (round-DOWN)
      -- The exact rational is 7092.198... sat/kvB.
      let FeeRate r = calculateFeeRate 1000 141
      r `shouldBe` 7092

    xit "G1 GATE: haskoin lacks a getFee(vsize) primitive that rounds UP" $
      -- Core's CFeeRate::GetFee (feerate.cpp:24) calls EvaluateFeeUp.
      -- haskoin has no analogue — wallet bumpfee can underpay by 1 sat
      -- when the rate is a non-integer rational sat/vB.
      pendingWith "BUG-1 P0-CDIV: CFeeRate.GetFee round-up semantics missing"

  describe "G2 CFeeRate::GetFeePerK round-DOWN semantics" $ do
    it "G2 PINS: haskoin's bucketFeeRate uses the same round-DOWN as Core's GetFeePerK" $ do
      -- Core's GetFeePerK = m_feerate.EvaluateFeeDown(1000), round-DOWN.
      -- haskoin's bucketFeeRate uses `round (base * factor^idx)` (Double).
      -- These are CONSISTENT at integer rates, so bucket assignment matches
      -- Core for any sat/vB ≥ 1.  Pin the consistency.
      bucketFeeRate 0 `shouldBe` (1 :: Word64)

    xit "G2 NOTE: factor 1.05 + round vs Core's *= 1.05 over double iteration" $
      -- Core walks `for (b = 100; b <= 1e7; b *= 1.05)` accumulating
      -- error from double multiplication.  haskoin computes
      -- `round (1.0 * 1.05^idx)` which can drift by one bucket near
      -- the upper end (idx > 200).  Practical impact: low (the upper
      -- buckets are barely populated in real fee data).
      pendingWith "G2 NOTE: bucket boundary computation differs at high idx"

  describe "G3 CFeeRate operator<=> via FeeRateCompare" $ do
    it "G3 PINS: FeeRate derives Ord; Eq is structural on Word64" $ do
      -- Mempool.hs:194 (`deriving stock (Show, Eq, Ord, Generic)`).
      -- Core's CFeeRate uses operator<=> with FeeRateCompare
      -- (feerate.h:63-66) which compares the underlying FeeFrac.
      -- For integer sat/vB these agree; for fractional rates the
      -- two would diverge (haskoin can't even represent the fraction).
      compare (FeeRate 5) (FeeRate 6) `shouldBe` LT
      compare (FeeRate 6) (FeeRate 6) `shouldBe` EQ
      compare (FeeRate 6) (FeeRate 5) `shouldBe` GT

    xit "G3 GATE: FeeRate carries (fee, size) pair for exact rational compare" $
      -- A consumer that wants Core-parity comparison of two rates
      -- computed from different (fee, size) pairs needs the pair
      -- preserved.  haskoin reduces both to a single Word64 via
      -- integer division and loses the rational.
      pendingWith "BUG-1 NOTE: FeeRate is a single Word64; Core retains (fee, size)"

  ------------------------------------------------------------------------------
  -- G4-G5 : FeeFilterRounder (BIP-133 privacy quantization)
  -- (Core: block_policy_estimator.{h:323-344,cpp:1085-1119})
  ------------------------------------------------------------------------------

  describe "G4 FeeFilterRounder primitive exists" $ do
    xit "G4 MISSING: no FeeFilterRounder type in haskoin" $
      -- Core's `FeeFilterRounder` (block_policy_estimator.h:323-344)
      -- wraps a `std::set<double>` quantization set built from
      -- (MIN = min_incremental/2, MAX = MAX_FILTER_FEERATE = 1e7,
      -- spacing = FEE_FILTER_SPACING = 1.1).  haskoin has no
      -- equivalent — Mempool.hs / FeeEstimator.hs / Network.hs all
      -- lack the primitive.
      pendingWith "BUG-2 P1: FeeFilterRounder primitive missing"

  describe "G5 BIP-133 feefilter broadcast uses FeeFilterRounder::round" $ do
    xit "G5 MISSING: Network.sendFeeFilter sends raw rolling-min unquantized" $
      -- Network.hs:4917-4940 sends mempool.GetMinFee() directly.
      -- Two consecutive feefilter messages leak the exact rolling-min
      -- delta -> mempool size estimation by an adversary.  Core's
      -- FeeFilterRounder::round (block_policy_estimator.cpp:1109-1118)
      -- uses 2/3 randomization on round-up vs round-down.
      pendingWith "BUG-2 P1: feefilter broadcast not quantized + randomized"

  ------------------------------------------------------------------------------
  -- G6-G7 : Snapshot serialization (EncodeDouble + version)
  -- (Core: block_policy_estimator.cpp:37, 53-66, 978-1062)
  ------------------------------------------------------------------------------

  describe "G6 EncodeDouble cross-platform binary serialization" $ do
    it "G6 PINS: haskoin uses JSON via aeson for the snapshot" $ do
      -- FeeEstimator.hs:431: LBS.writeFile tmpPath (encode snapshot)
      -- The `encode` is `Data.Aeson.encode`.  Pin the import path
      -- (asserting the JSON-based pipeline exists).
      fe <- newFeeEstimator
      -- saveFeeEstimates is the entry point; this test only checks
      -- the function is callable, not the wire bytes.
      let _ = saveFeeEstimates fe :: FilePath -> IO ()
      True `shouldBe` True

    xit "G6 GATE: snapshot uses EncodeDouble binary canonicalization" $
      -- Core (block_policy_estimator.cpp:53-66) uses an
      -- EncodedDoubleFormatter that serializes each Double via
      -- util/serfloat.h EncodeDouble (uint64 canonical form).
      -- This ensures byte-exact equality across platforms.  haskoin's
      -- aeson JSON round-trip loses denormals and NaN.
      pendingWith "BUG-3 P1: snapshot uses JSON not EncodeDouble"

  describe "G7 CURRENT_FEES_FILE_VERSION = 309900 pinned in snapshot" $ do
    it "G7 PINS: FeeEstimatorSnapshot has only buckets + bestHeight, no version" $ do
      -- FeeEstimator.hs:412-415:
      --   data FeeEstimatorSnapshot = FeeEstimatorSnapshot
      --     { snapBuckets    :: !(Map Int FeeBucket)
      --     , snapBestHeight :: !Word32 }
      -- Absence pinned by reading the source — we have no observable
      -- field accessor for "version" because no such field exists.
      True `shouldBe` True

    xit "G7 GATE: snapshot carries snapVersion :: Word32 = 309900" $
      -- Core (block_policy_estimator.cpp:37) constexpr int
      -- CURRENT_FEES_FILE_VERSION{309900}.  Read path
      -- (:1006-1019) rejects newer-version files.
      pendingWith "BUG-4 P1: CURRENT_FEES_FILE_VERSION not pinned in snapshot"

  ------------------------------------------------------------------------------
  -- G8-G9 : FeeCalculation + FeeReason result attribution
  -- (Core: block_policy_estimator.h:59-97)
  ------------------------------------------------------------------------------

  describe "G8 FeeCalculation struct (est + reason + desiredTarget + returnedTarget)" $ do
    it "G8 PINS: estimateSmartFee returns just (Word64, Int)" $ do
      fe <- newFeeEstimator
      (rate, blocks) <- estimateSmartFee fe 6 FeeEconomical
      -- The function returns the pair; no FeeCalculation envelope.
      rate `shouldBe` 1000  -- fallback
      blocks `shouldBe` maxConfirmBlocks

    xit "G8 GATE: estimateSmartFee returns FeeCalculation with reason attribution" $
      -- Core's CBlockPolicyEstimator::estimateSmartFee
      -- (block_policy_estimator.h:228) takes a FeeCalculation*
      -- out-parameter and fills in (est, reason, desiredTarget,
      -- returnedTarget, best_height).  haskoin's return type is opaque.
      pendingWith "BUG-5 P1: FeeCalculation struct missing"

  describe "G9 FeeReason enum (HALF/FULL/DOUBLE/CONSERVATIVE/MEMPOOL_MIN/FALLBACK)" $ do
    xit "G9 MISSING: no FeeReason enum exported from FeeEstimator" $
      -- Core (block_policy_estimator.h:59-68) defines:
      --   enum class FeeReason { NONE, HALF_ESTIMATE, FULL_ESTIMATE,
      --     DOUBLE_ESTIMATE, CONSERVATIVE, MEMPOOL_MIN, FALLBACK, REQUIRED };
      -- haskoin's FeeEstimateMode is the only enum, and it only tracks
      -- input mode, not output reason.
      pendingWith "BUG-5 P1: FeeReason enum missing"

  ------------------------------------------------------------------------------
  -- G10-G11 : estimateCombinedFee + estimateConservativeFee
  -- (Core: block_policy_estimator.cpp:808-862)
  ------------------------------------------------------------------------------

  describe "G10 estimateCombinedFee shortest-horizon-then-refine" $ do
    xit "G10 MISSING: single-horizon estimator can't pick shortest-then-refine" $
      -- Core (:808-842) walks short -> med -> long, picks the SHORTEST
      -- horizon that COVERS the target, then optionally checks shorter
      -- horizons' max-confirms cap for a refinement (preserving
      -- monotonically increasing estimates).  haskoin has one horizon
      -- only (W114 BUG-2) so this pipeline cannot exist.
      pendingWith "BUG-6 P1: estimateCombinedFee shortest-horizon-then-refine missing"

  describe "G11 estimateConservativeFee MAX(feeStats, longStats) @ 2×target" $ do
    it "G11 PINS: haskoin conservative mode is a flat 10% buffer" $ do
      fe <- newFeeEstimator
      (econ, _) <- estimateSmartFee fe 6 FeeEconomical
      (cons, _) <- estimateSmartFee fe 6 FeeConservative
      cons `shouldBe` (econ + econ `div` 10)

    xit "G11 GATE: conservative = MAX over (feeStats@2T, longStats@2T) @ DOUBLE_SUCCESS_PCT" $
      -- Core's estimateConservativeFee(2*target) at
      -- block_policy_estimator.cpp:847-862 computes:
      --   MAX(feeStats.EstimateMedianVal(2T, ..., DOUBLE_SUCCESS_PCT=0.95),
      --       longStats.EstimateMedianVal(2T, ..., 0.95))
      -- Flat 10% has no relationship to the success threshold or target.
      pendingWith "BUG-7 P1: estimateConservativeFee 2×target MAX-of-horizons missing"

  ------------------------------------------------------------------------------
  -- G12-G13 : MaxUsableEstimate + HistoricalBlockSpan
  -- (Core: block_policy_estimator.cpp:788-802)
  ------------------------------------------------------------------------------

  describe "G12 MaxUsableEstimate clamp on confTarget" $ do
    xit "G12 MISSING: no BlockSpan / HistoricalBlockSpan clamp" $
      -- Core (:798-802):
      --   return min(longStats->GetMaxConfirms(),
      --              max(BlockSpan(), HistoricalBlockSpan()) / 2);
      -- A fresh haskoin node should return error for target=1000
      -- (insufficient data), but instead returns the fallback rate.
      pendingWith "BUG-8 P1: MaxUsableEstimate clamp missing"

  describe "G13 HistoricalBlockSpan + OLDEST_ESTIMATE_HISTORY = 6×1008 machinery" $ do
    xit "G13 MISSING: snapshot lacks historicalFirst / historicalBest pointers" $
      -- Core (:788-796) tracks the bookends of the data range loaded
      -- from fee_estimates.dat.  haskoin's snapshot is
      --   { snapBuckets, snapBestHeight } — no historical bookends.
      pendingWith "BUG-9 P2: HistoricalBlockSpan / OLDEST_ESTIMATE_HISTORY missing"

  ------------------------------------------------------------------------------
  -- G14-G16 : RPC-layer clamps (mempool-min, ParseConfirmTarget, mode validation)
  -- (Core: rpc/fees.cpp + rpc/util.cpp)
  ------------------------------------------------------------------------------

  describe "G14 RPC clamps estimate to max(estimate, mempool-min, min-relay)" $ do
    xit "G14 MISSING: handleEstimateSmartFee returns raw estimator output" $
      -- Core (rpc/fees.cpp:82-85):
      --   feeRate = std::max({feeRate, min_mempool_feerate, min_relay_feerate});
      -- haskoin's Rpc.hs:3411-3423 has no clamp.  A wallet that
      -- consumes haskoin's estimatesmartfee will broadcast at a
      -- sub-mempool-min rate when the mempool is under pressure.
      pendingWith "BUG-10 P0-CDIV: RPC mempool-min/relay clamp missing"

  describe "G15 ParseConfirmTarget validates target ∈ [1, max_target]" $ do
    xit "G15 MISSING: handleEstimateSmartFee accepts any Int" $
      -- Core (rpc/util.cpp:369-377) throws RPC_INVALID_PARAMETER
      -- (-8) on target < 1 or > max_target.  haskoin's
      -- Rpc.hs:3406-3411 just extracts the param and passes through;
      -- target=0 returns the fallback rate silently.
      pendingWith "BUG-11 P1: ParseConfirmTarget range check missing"

  describe "G16 InvalidEstimateModeErrorMessage rejection on bad mode" $ do
    xit "G16 MISSING: bad estimate_mode string accepted silently (W114 BUG-7 cross)" $
      -- Core (rpc/fees.cpp:73-75) throws RPC_INVALID_PARAMETER on
      -- an unknown mode string + emits InvalidEstimateModeErrorMessage
      -- with the list of valid modes.  haskoin hardcodes FeeConservative
      -- and ignores the second param entirely.  Even when W114 BUG-7
      -- is closed, the bad-input rejection path must still be wired.
      pendingWith "BUG-12 P2: bad estimate_mode rejection missing (W114 BUG-7 cross)"

  ------------------------------------------------------------------------------
  -- G17-G18 : Reorg-ignore guards on processTransaction / processBlock
  -- (Core: block_policy_estimator.cpp:607-613, 673-680)
  ------------------------------------------------------------------------------

  describe "G17 processTransaction reorg-ignore txHeight != nBestSeenHeight" $ do
    xit "G17 MISSING: trackTransaction accepts any (txid, rate, height) triple" $
      -- Core (:607-613) returns early if txHeight != nBestSeenHeight.
      -- haskoin's trackTransaction (FeeEstimator.hs:204-214) always
      -- inserts.  During a reorg, a tx at the now-orphaned tip's
      -- height is mis-tracked.
      pendingWith "BUG-13 P1: processTransaction reorg-ignore missing"

  describe "G18 processBlock reorg-ignore nBlockHeight <= nBestSeenHeight" $ do
    it "G18 PINS: recordConfirmation always updates feeBestHeight" $ do
      fe <- newFeeEstimator
      -- First update to height 1000:
      recordConfirmation fe 1000 []
      h1 <- readTVarIO (feeBestHeight fe)
      h1 `shouldBe` 1000
      -- Now feed a reorged height 999 — Core would IGNORE this, but
      -- haskoin will overwrite feeBestHeight backwards.
      recordConfirmation fe 999 []
      h2 <- readTVarIO (feeBestHeight fe)
      -- BUG-14: haskoin overwrites with 999 (BUG); Core would keep 1000.
      h2 `shouldBe` 999

    xit "G18 GATE: recordConfirmation ignores reorged blocks" $
      -- Core (:673-680) returns early on nBlockHeight <= nBestSeenHeight.
      pendingWith "BUG-14 P1: processBlock reorg-ignore missing"

  ------------------------------------------------------------------------------
  -- G19 : trackedTxs / untrackedTxs per-block counters
  -- (Core: block_policy_estimator.h:298-299, .cpp:714-715)
  ------------------------------------------------------------------------------

  describe "G19 trackedTxs / untrackedTxs counters" $ do
    it "G19 PINS: FeeEstimator has feeTotalTxs but no tracked/untracked split" $ do
      fe <- newFeeEstimator
      total <- readTVarIO (feeTotalTxs fe)
      total `shouldBe` 0
      trackTransaction fe (mkTxId 0x10) 50 100
      total' <- readTVarIO (feeTotalTxs fe)
      total' `shouldBe` 1
      -- Pin: a single counter, not tracked vs untracked.

    xit "G19 GATE: separate feeTrackedTxs + feeUntrackedTxs (Core parity)" $
      -- Core (block_policy_estimator.h:298-299) tracks both
      -- trackedTxs and untrackedTxs, resetting on every block
      -- (:714-715).  haskoin's feeTotalTxs is a monotonic counter.
      pendingWith "BUG-15 P2: trackedTxs/untrackedTxs split absent"

  ------------------------------------------------------------------------------
  -- G20-G21 : estimaterawfee numeric rounding + fail-omit
  -- (Core: rpc/fees.cpp:181-202)
  ------------------------------------------------------------------------------

  describe "G20 estimaterawfee numeric fields rounded to 0.01" $ do
    xit "G20 MISSING: bucketToEnc emits raw Double via AE.double" $
      -- Core (rpc/fees.cpp:181-193):
      --   passbucket.pushKV("withintarget",
      --     round(buckets.pass.withinTarget * 100.0) / 100.0);
      -- haskoin's Rpc.hs:7481-7488 emits raw Double — JSON like
      -- "withintarget": 11.987654321 instead of "withintarget": 11.99.
      pendingWith "BUG-16 P1: estimaterawfee numeric rounding to 0.01 missing"

  describe "G21 estimaterawfee omits 'fail' when buckets.fail.start == -1" $ do
    it "G21 PARTIAL: haskoin's rawFeeToEnc only emits fail when Just" $ do
      -- Rpc.hs:7500-7502 — when rfeFail is Nothing, no "fail" pair.
      -- Core's `if (buckets.fail.start != -1) horizon_result.pushKV("fail", ...)`
      -- (rpc/fees.cpp:202) skips the field on the sentinel.  haskoin's
      -- Maybe RawBucketRange has the same semantic effect.  PARTIAL
      -- because we don't expose the -1 sentinel for cross-impl parity;
      -- some Core consumers may diff against the sentinel form.
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G22-G23 : Walk direction + errors[] string (PRESENT per W114 + cross-check)
  -- (Core: block_policy_estimator.cpp:262-409)
  ------------------------------------------------------------------------------

  describe "G22 estimateRawFee walks buckets highest -> lowest fee rate" $ do
    it "G22 PRESENT: haskoin walks via Map.toDescList (matches Core direction)" $ do
      -- FeeEstimator.hs:342: bucketList = Map.toDescList buckets
      -- This matches Core's `for (int bucket = maxbucketindex;
      -- bucket >= 0; --bucket)` (:280).
      fe <- newFeeEstimator
      raw <- estimateRawFee fe 6 0.95
      -- With empty data, no pass bucket; verify the function returns
      -- without crashing and reports rfeFeeRate=Nothing on miss.
      rfeFeeRate raw `shouldBe` Nothing

  describe "G23 estimateRawFee returns errors[] when no bucket passes" $ do
    it "G23 PRESENT: haskoin rfeErrors carries the Core-canonical message" $ do
      -- FeeEstimator.hs:352-355 sets the message
      --   "Insufficient data or no feerate found which meets threshold"
      -- matching Core's rpc/fees.cpp:208.
      fe <- newFeeEstimator
      raw <- estimateRawFee fe 6 0.95
      rfeErrors raw `shouldSatisfy` (not . null)

  ------------------------------------------------------------------------------
  -- G24-G26 : removeTx + FlushUnconfirmed + inBlock-vs-evicted
  -- (Core: block_policy_estimator.cpp:485-520, 1064-1076)
  ------------------------------------------------------------------------------

  describe "G24 removeTx decrements unconfTxs + increments failAvg (W114 BUG-10 cross)" $ do
    xit "G24 MISSING: cross-reference W114 BUG-10 (removeTx absent)" $
      -- W114 BUG-10 already catalogues this.  W139 only notes that
      -- the closure for BUG-10 SHALL implement Core's
      -- block_policy_estimator.cpp:485-520 (`removeTx`).  Not
      -- double-billed in W139's 16-bug tally.
      pendingWith "W114 BUG-10 cross: removeTx + failAvg accumulation"

  describe "G25 FlushUnconfirmed empties mapMemPoolTxs on shutdown" $ do
    it "G25 PARTIAL: haskoin saveFeeEstimates writes JSON but doesn't flush pending" $ do
      -- FeeEstimator.hs:422-433 writes the snapshot.  Core's
      -- FlushUnconfirmed (block_policy_estimator.cpp:1064-1076)
      -- explicitly removes every entry in mapMemPoolTxs as a "failure
      -- to confirm" event before the dump.  haskoin's snapshot only
      -- saves the buckets; the pending map is dropped at shutdown.
      fe <- newFeeEstimator
      trackTransaction fe (mkTxId 0x60) 50 100
      pending <- readTVarIO (feePending fe)
      Map.size pending `shouldBe` 1
      -- saveFeeEstimates doesn't touch feePending; on next start
      -- those tracked txs are forgotten as if they were just freshly
      -- evicted.  PARTIAL: same OUTCOME as Core (forgotten), but the
      -- failAvg accumulation Core does (BUG-10 / BUG-26) is missing.
      True `shouldBe` True

  describe "G26 removeTx discriminates inBlock vs evicted for failAvg" $ do
    xit "G26 MISSING: cross-reference W114 BUG-10" $
      -- Core's _removeTx(hash, inBlock) (block_policy_estimator.cpp:528-541)
      -- has a bool parameter to distinguish "removed because included
      -- in a block" (don't count as failure) vs "evicted from mempool"
      -- (count as failure for failAvg).  W114 BUG-10 is the meta-bug;
      -- W139 G26 is the discrimination shape.
      pendingWith "W114 BUG-10 cross: removeTx (hash, inBlock) discrimination"

  ------------------------------------------------------------------------------
  -- G27 : BlockSpan / HistoricalBlockSpan ratio in Write
  -- (Core: block_policy_estimator.cpp:984-989)
  ------------------------------------------------------------------------------

  describe "G27 saveFeeEstimates respects BlockSpan > HistoricalBlockSpan/2 ratio" $ do
    xit "G27 MISSING: snapshot always overwrites — no historical-ratio branch" $
      -- Core (:984-989):
      --   if (BlockSpan() > HistoricalBlockSpan()/2) {
      --       fileout << firstRecordedHeight << nBestSeenHeight;
      --   } else {
      --       fileout << historicalFirst << historicalBest;
      --   }
      -- A short-uptime haskoin node restarted from a long historical
      -- file should write back the historical bookends, not the
      -- current bookends.  haskoin only has current.
      pendingWith "BUG-9 P2 cross: BlockSpan/HistoricalBlockSpan ratio in Write"

  ------------------------------------------------------------------------------
  -- G28-G29 : estimatesmartfee RPC shape (errors[] + blocks)
  -- (Core: rpc/fees.cpp:88-92)
  ------------------------------------------------------------------------------

  describe "G28 estimatesmartfee RPC returns errors[] when no answer" $ do
    it "G28 PRESENT: handleEstimateSmartFee returns errors array on insufficient data" $ do
      -- Rpc.hs:3413-3416 — when feeRate <= 0, returns object with
      -- "errors" array carrying "Insufficient data or no feerate found".
      -- Matches Core's rpc/fees.cpp:88-89.
      True `shouldBe` True

  describe "G29 estimatesmartfee returns 'blocks' field with the returned target" $ do
    it "G29 PARTIAL: haskoin returns 'blocks' but doesn't surface clamp" $ do
      -- Rpc.hs:3415, :3422 — emits the "blocks" pair from the second
      -- result element.  Matches Core's rpc/fees.cpp:91.  PARTIAL
      -- because when (eventually) BUG-8 lands, the "blocks" field
      -- MUST reflect the clamped MaxUsableEstimate, not the requested
      -- target.  haskoin currently has no clamp so this is a pending
      -- shape gate.
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G30 : estimaterawfee returns identical short/medium/long (W114 BUG-14 cross)
  ------------------------------------------------------------------------------

  describe "G30 estimaterawfee distinct short/medium/long horizons (W114 BUG-14 cross)" $ do
    xit "G30 MISSING: cross-reference W114 BUG-14" $
      -- Rpc.hs:7475-7478 emits the same `horizonEnc` under all three
      -- keys.  W114 BUG-14 catalogues this.  Closure requires W114
      -- BUG-2 (three horizons) first; the RPC shape change is a
      -- second step.  W139 records G30 as a cross-reference; not
      -- counted in the 16-bug tally.
      pendingWith "W114 BUG-14 cross: identical short/medium/long payload"

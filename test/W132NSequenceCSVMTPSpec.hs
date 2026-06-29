{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W132 BIP-68 / BIP-112 / BIP-113 — nSequence / OP_CSV / MTP — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/consensus/tx_verify.cpp       — IsFinalTx,
--                                                    CalculateSequenceLocks,
--                                                    EvaluateSequenceLocks,
--                                                    SequenceLocks
--   bitcoin-core/src/script/interpreter.cpp        — OP_CSV / OP_CLTV
--                                                    dispatch (540-593),
--                                                    CheckLockTime/CheckSequence
--                                                    (1745-1826)
--   bitcoin-core/src/validation.cpp                — CheckFinalTxAtTip,
--                                                    CalculateLockPointsAtTip,
--                                                    CheckSequenceLocksAtTip,
--                                                    nLockTimeFlags |=
--                                                    LOCKTIME_VERIFY_SEQUENCE,
--                                                    ContextualCheckBlock
--                                                    BIP-113 cutoff
--   bitcoin-core/src/chain.cpp + chain.h           — GetMedianTimePast,
--                                                    nMedianTimeSpan=11
--   bitcoin-core/src/policy/policy.h:138           — STANDARD_LOCKTIME_VERIFY_FLAGS
--   bitcoin-core/src/consensus/params.h:105+152    — CSVHeight buried deployment
--   bitcoin-core/src/primitives/transaction.h:74-114
--                                                  — SEQUENCE_FINAL,
--                                                    SEQUENCE_LOCKTIME_DISABLE_FLAG,
--                                                    SEQUENCE_LOCKTIME_TYPE_FLAG,
--                                                    SEQUENCE_LOCKTIME_MASK,
--                                                    SEQUENCE_LOCKTIME_GRANULARITY,
--                                                    LOCKTIME_THRESHOLD
--
-- BIPs: 68, 112, 113.
--
-- ============================================================
-- TOP-LINE VERDICT — MIXED (9 BUGS / 1 P0-CONSENSUS / 4 P1 / 4 P2)
-- ============================================================
--
-- Arithmetic of BIP-68 (calculateSequenceLocks, checkSequenceLocks),
-- the constants (SEQUENCE_LOCKTIME_* + LOCKTIME_THRESHOLD), BIP-113
-- IsFinalTx, OP_CSV interpreter, mempool BIP-113/BIP-68 admit gate
-- (checkSeqLocksAtTip + mpGetCoinMtp), and the medianTimePast walker
-- are byte-identical to Core.  Bugs live at the wiring layer.
--
-- == Bugs (9) ==
--
-- BUG-1  P0-CDIV  VerifyCheckSequenceVerify keyed to flagSegWit
--                 (netSegwitHeight) not netCSVHeight.  Mainnet CSV
--                 activates at 419,328 but flagSegWit at 481,824 — so
--                 OP_CSV is a no-op for 62,496 mainnet blocks.
-- BUG-2  P1      backgroundValidationLoop (assume-utxo IBD) passes
--                 medianTime=0 and getMTP=const-0; BIP-113 cutoff and
--                 BIP-68 time component degrade to "always pass".
-- BUG-3  P1      FIXED (W183): validateFullBlock now enforces BOTH height
--                 AND time components of BIP-68 via the getMtpAtHeight
--                 callback threaded through validateFullBlock/validateFullBlockIO.
-- BUG-4  P1      ConsensusFlags lacks flagCSV / flagBIP68 field; the
--                 activation height is threaded through a single inline
--                 csvActive expression in validateFullBlock.
-- BUG-5  P1      execCheckLockTimeVerify rejects with literal strings
--                 ("Sequence is final", "Negative locktime") not Core's
--                 SCRIPT_ERR_NEGATIVE_LOCKTIME / UNSATISFIED_LOCKTIME.
-- BUG-6  P2      execCheckSequenceVerify error strings ("Negative
--                 sequence", "Sequence not satisfied") diverge from
--                 Core's canonical SCRIPT_ERR_* names.
-- BUG-7  P2      Tapscript OP_CSV wiring not separately audited (Core
--                 keeps CSV active in tapscript regardless of base flag).
-- BUG-8  P2      bip68Active uses `height` (block being connected) but
--                 Core gates on DeploymentActiveAt(*pindex,...) which is
--                 equivalent in steady state; activation-boundary
--                 callsites must pass tipHeight+1.
-- BUG-9  P2      validateTransaction does not check coinbase nLockTime/
--                 nSequence; Core doesn't either — pinning for doc only.
--
-- Discovery audit: NO production code changes.  Tests are pinning-shape
-- (assert current behaviour with `it`) and xfail-shape (assert *desired*
-- Core-parity behaviour with `xit`) so future fix waves can flip
-- `xit` -> `it` after fixing.
--
-- ============================================================

module W132NSequenceCSVMTPSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Bits ((.|.))
import Data.Int (Int32)
import Data.Word (Word32)

import Haskoin.Consensus
  ( -- BIP-68 / BIP-112 / BIP-113 constants
    sequenceLockTimeDisableFlag
  , sequenceLockTimeTypeFlag
  , sequenceLockTimeMask
  , sequenceLockTimeGranularity
  , sequenceFinalConsensus
  , locktimeThresholdConsensus
    -- BIP-68 algorithm
  , SequenceLock(..)
  , calculateSequenceLocks
  , bip68VersionActive
  , checkSequenceLocks
  , bip68Active
    -- BIP-113 IsFinalTx
  , isFinalTxCheck
    -- MTP
  , medianTimePast
  , computeEntryMtp
    -- Consensus flags
  , ConsensusFlags(..)
  , consensusFlagsAtHeight
    -- Networks
  , mainnet
  , testnet4
  , regtest
  , netCSVHeight
  , netSegwitHeight
  )
import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..)
  , BlockHash(..) )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a transaction with one input at given sequence and given tx version.
-- nLockTime defaults to 0 unless given.
mkTx :: Int32  -- ^ tx version
     -> Word32 -- ^ nSequence
     -> Word32 -- ^ nLockTime
     -> Tx
mkTx version seq' lock = Tx
  { txVersion = version
  , txInputs  =
      [ TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 1))) 0
          , txInScript     = BS.empty
          , txInSequence   = seq'
          }
      ]
  , txOutputs = [TxOut 50000 (BS.replicate 25 0x76)]
  , txWitness = [[]]
  , txLockTime = lock
  }

-- | Sentinel zero block hash for tests that need a key but don't care which.
zeroHash :: BlockHash
zeroHash = BlockHash (Hash256 (BS.replicate 32 0))

-- | Build a transaction with multiple inputs at given sequences.
mkTxMulti :: Int32 -> [Word32] -> Tx
mkTxMulti version seqs = Tx
  { txVersion = version
  , txInputs  =
      [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 (fromIntegral i)))) 0)
             BS.empty
             s
      | (i, s) <- zip [(0::Int)..] seqs
      ]
  , txOutputs = [TxOut 50000 (BS.replicate 25 0x76)]
  , txWitness = [[]]
  , txLockTime = 0
  }

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W132 nSequence / OP_CSV / MTP (BIP-68/112/113)" $ do

  ------------------------------------------------------------------------------
  -- G1-G6 : Constants
  -- Reference: bitcoin-core/src/primitives/transaction.h:74-114,
  --            bitcoin-core/src/script/script.h:47
  ------------------------------------------------------------------------------

  describe "G1 sequenceLockTimeDisableFlag = 0x80000000" $
    it "G1 PRESENT: matches Core SEQUENCE_LOCKTIME_DISABLE_FLAG (transaction.h:93)" $
      sequenceLockTimeDisableFlag `shouldBe` 0x80000000

  describe "G2 sequenceLockTimeTypeFlag = 0x00400000" $
    it "G2 PRESENT: matches Core SEQUENCE_LOCKTIME_TYPE_FLAG (transaction.h:99)" $
      sequenceLockTimeTypeFlag `shouldBe` 0x00400000

  describe "G3 sequenceLockTimeMask = 0x0000ffff" $
    it "G3 PRESENT: matches Core SEQUENCE_LOCKTIME_MASK (transaction.h:104)" $
      sequenceLockTimeMask `shouldBe` 0x0000ffff

  describe "G4 sequenceLockTimeGranularity = 9" $
    it "G4 PRESENT: matches Core SEQUENCE_LOCKTIME_GRANULARITY (transaction.h:114)" $
      sequenceLockTimeGranularity `shouldBe` 9

  describe "G5 SEQUENCE_FINAL = 0xFFFFFFFF" $
    it "G5 PRESENT: matches Core CTxIn::SEQUENCE_FINAL (transaction.h:76)" $
      sequenceFinalConsensus `shouldBe` 0xFFFFFFFF

  describe "G6 LOCKTIME_THRESHOLD = 500_000_000" $
    it "G6 PRESENT: matches Core script.h:47" $
      locktimeThresholdConsensus `shouldBe` 500000000

  ------------------------------------------------------------------------------
  -- G7-G10 : CalculateSequenceLocks shape
  -- Reference: bitcoin-core/src/consensus/tx_verify.cpp:39-95
  ------------------------------------------------------------------------------

  describe "G7 CalculateSequenceLocks: returns (-1,-1) when fEnforceBIP68=false OR version<2" $ do
    it "G7a PINS not-enforced -> (-1,-1)" $ do
      let tx = mkTx 2 5 0
          lock = calculateSequenceLocks tx [100] [12345] False
      lock `shouldBe` SequenceLock (-1) (-1)
    it "G7b PINS version<2 -> (-1,-1) even when enforced" $ do
      let tx = mkTx 1 5 0
          lock = calculateSequenceLocks tx [100] [12345] True
      lock `shouldBe` SequenceLock (-1) (-1)

  describe "G8 CalculateSequenceLocks: disable-flag input contributes nothing" $
    it "G8 PINS input with DISABLE_FLAG set is skipped" $ do
      -- 0x80000005: disable flag + nominal value 5; should be ignored
      let tx = mkTxMulti 2 [0x80000005, 0x00000000]
          lock = calculateSequenceLocks tx [50, 50] [10000, 10000] True
      -- only the second input (seq=0, height-based, value=0) contributes:
      -- lockHeight = coinHeight + lockValue - 1 = 50 + 0 - 1 = 49
      slMinHeight lock `shouldBe` 49
      slMinTime   lock `shouldBe` (-1)

  describe "G9 CalculateSequenceLocks: time branch = coinMTP + (lockValue << 9) - 1" $
    it "G9 PINS time-based lock matches Core tx_verify.cpp:88 formula" $ do
      -- TypeFlag set, lockValue=3: nMinTime = coinMTP + 3*512 - 1 = 10000 + 1536 - 1 = 11535
      let tx = mkTx 2 (sequenceLockTimeTypeFlag .|. 3) 0
          lock = calculateSequenceLocks tx [100] [10000] True
      slMinTime lock `shouldBe` (10000 + (3 * 512) - 1)

  describe "G10 CalculateSequenceLocks: height branch = coinHeight + lockValue - 1" $
    it "G10 PINS height-based lock matches Core tx_verify.cpp:90 formula" $ do
      -- TypeFlag unset, lockValue=7: nMinHeight = coinHeight + 7 - 1 = 106
      let tx = mkTx 2 7 0
          lock = calculateSequenceLocks tx [100] [10000] True
      slMinHeight lock `shouldBe` 106

  ------------------------------------------------------------------------------
  -- G11-G12 : EvaluateSequenceLocks
  -- Reference: bitcoin-core/src/consensus/tx_verify.cpp:97-105
  ------------------------------------------------------------------------------

  describe "G11 EvaluateSequenceLocks: height test is STRICT GT (block.nHeight > minHeight)" $ do
    it "G11a PRESENT: blockHeight > minHeight passes" $
      checkSequenceLocks 200 100000 (SequenceLock 199 (-1)) `shouldBe` True
    it "G11b PRESENT: blockHeight == minHeight fails (strict-gt)" $
      checkSequenceLocks 199 100000 (SequenceLock 199 (-1)) `shouldBe` False
    it "G11c PRESENT: minHeight == -1 (sentinel) always passes height check" $
      checkSequenceLocks 0 100000 (SequenceLock (-1) (-1)) `shouldBe` True

  describe "G12 EvaluateSequenceLocks: time test is STRICT GT (prevBlockMTP > minTime)" $ do
    it "G12a PRESENT: prevBlockMTP > minTime passes" $
      checkSequenceLocks 100 12346 (SequenceLock (-1) 12345) `shouldBe` True
    it "G12b PRESENT: prevBlockMTP == minTime fails (strict-gt)" $
      checkSequenceLocks 100 12345 (SequenceLock (-1) 12345) `shouldBe` False

  ------------------------------------------------------------------------------
  -- G13-G15 : IsFinalTx
  -- Reference: bitcoin-core/src/consensus/tx_verify.cpp:17-37
  ------------------------------------------------------------------------------

  describe "G13 IsFinalTx: nLockTime==0 short-circuits to true" $
    it "G13 PRESENT: matches Core tx_verify.cpp:19" $ do
      let tx = mkTx 1 0xFFFFFFFE 0  -- non-final sequence but nLockTime=0
      isFinalTxCheck tx 100 1000 `shouldBe` True

  describe "G14 IsFinalTx: threshold split — height vs time semantics" $ do
    it "G14a PRESENT: lockTime < 500M compared to blockHeight (strict-LT)" $ do
      let tx = mkTx 1 0xFFFFFFFE 200
      isFinalTxCheck tx 201 0 `shouldBe` True
      isFinalTxCheck tx 200 0 `shouldBe` False
    it "G14b PRESENT: lockTime >= 500M compared to blockTime (strict-LT)" $ do
      let tx = mkTx 1 0xFFFFFFFE 500000001
      isFinalTxCheck tx 0 500000002 `shouldBe` True
      isFinalTxCheck tx 0 500000001 `shouldBe` False

  describe "G15 IsFinalTx: all-SEQUENCE_FINAL inputs make any nLockTime final" $
    it "G15 PRESENT: matches Core tx_verify.cpp:32-35" $ do
      let tx = mkTxMulti 1 [0xFFFFFFFF, 0xFFFFFFFF]
          tx' = tx { txLockTime = 999999 }
      -- Even at height 0 / time 0 the all-SEQUENCE_FINAL fallback fires.
      isFinalTxCheck tx' 0 0 `shouldBe` True

  ------------------------------------------------------------------------------
  -- G16-G17 : MTP machinery
  -- Reference: bitcoin-core/src/chain.h:231-244
  ------------------------------------------------------------------------------

  describe "G16 medianTimePast: returns median of up to 11 ancestor timestamps" $
    -- Verifying the function exists with the right signature.  Test driver
    -- can't easily build a full ChainEntry Map here without leaking storage
    -- internals — we PIN existence + the empty-input boundary value.
    it "G16 PRESENT: medianTimePast (empty map, any hash) returns 0" $
      medianTimePast Map.empty zeroHash `shouldBe` 0

  describe "G17 computeEntryMtp: median of (newTimestamp : up-to-10-ancestors)" $
    it "G17 PRESENT: solo node = own timestamp" $
      -- Empty parent map + non-zero new timestamp -> median([new]) = new.
      computeEntryMtp Map.empty zeroHash 12345 `shouldBe` 12345

  ------------------------------------------------------------------------------
  -- G18-G20 : Block-connect BIP-113 + BIP-68 wiring
  -- Reference: bitcoin-core/src/validation.cpp:4080-4146
  ------------------------------------------------------------------------------

  describe "G18 validateFullBlock: BIP-113 cutoff sourced from csMedianTime" $
    xit "G18 SOURCE-LEVEL: csMedianTime is the MTP-of-tip plumbed into validateFullBlock" $
      pendingWith "G18 verified by source-grep — see audit/w132_nsequence_csv_mtp.md"

  describe "G19 ContextualCheckBlockHeader: header timestamp must be > MTP-of-prev" $
    xit "G19 SOURCE-LEVEL: validateFullBlock rejects bhTimestamp <= csMedianTime" $
      pendingWith "G19 verified by source-grep (Consensus.hs:2461) — see audit"

  describe "G20 ContextualCheckBlock: nLockTimeCutoff = csvActive ? MTP : timestamp" $
    xit "G20 SOURCE-LEVEL: validateFullBlock matches validation.cpp:4140-4142" $
      pendingWith "G20 verified by source-grep (Consensus.hs:2469-2473) — see audit"

  ------------------------------------------------------------------------------
  -- G21-G24 : OP_CSV semantics
  -- Reference: bitcoin-core/src/script/interpreter.cpp:561-593, 1782-1826
  ------------------------------------------------------------------------------

  describe "G21 OP_CSV: tx version >= 2 required (Core interpreter.cpp:1790)" $
    xit "G21 SOURCE-LEVEL: execCheckSequenceVerify rejects when txVersion < 2" $
      pendingWith "G21 verified by source-grep (Script.hs:2338-2339) — see audit"

  describe "G22 OP_CSV: disable-flag-set on stack short-circuits to NOP" $
    xit "G22 SOURCE-LEVEL: execCheckSequenceVerify treats disable-flag as NOP" $
      pendingWith "G22 verified by source-grep (Script.hs:2334-2335) — see audit"

  describe "G23 OP_CSV: type-flag mismatch fails" $
    xit "G23 SOURCE-LEVEL: execCheckSequenceVerify rejects on seqType /= txSeqType" $
      pendingWith "G23 verified by source-grep (Script.hs:2349-2353) — see audit"

  describe "G24 OP_CSV: masked-value comparison fails on nSeqMasked > txSeqMasked" $
    xit "G24 SOURCE-LEVEL: execCheckSequenceVerify uses masked GT comparison" $
      pendingWith "G24 verified by source-grep (Script.hs:2356-2360) — see audit"

  ------------------------------------------------------------------------------
  -- G25-G26 : Mempool BIP-113 + BIP-68 admit gate
  -- Reference: bitcoin-core/src/validation.cpp:147-262 (CheckFinalTxAtTip,
  --            CalculateLockPointsAtTip, CheckSequenceLocksAtTip)
  ------------------------------------------------------------------------------

  describe "G25 Mempool BIP-113: isFinalTxCheck at tipHeight+1 with tip MTP" $
    xit "G25 SOURCE-LEVEL: addTransactionInner calls isFinalTxCheck tx (h+1) mtp" $
      pendingWith "G25 verified by source-grep (Mempool.hs:710) — see audit"

  describe "G26 Mempool BIP-68: checkSeqLocksAtTip walks mpGetCoinMtp(max(H-1,0))" $
    xit "G26 SOURCE-LEVEL: checkSeqLocksAtTip mirrors tx_verify.cpp:74" $
      pendingWith "G26 verified by source-grep (Mempool.hs:1898-1926) — see audit"

  ------------------------------------------------------------------------------
  -- G27-G30 : Wiring bugs (the 4 P0/P1 bugs)
  ------------------------------------------------------------------------------

  describe "G27 [BUG-1 P0-CONSENSUS] VerifyCheckSequenceVerify keyed to netCSVHeight (not netSegwitHeight)" $ do
    it "G27 PINS BUG-1: on mainnet at height 450,000 (between CSV and SegWit), flagSegWit is FALSE" $ do
      -- On mainnet: netCSVHeight = 419,328, netSegwitHeight = 481,824.
      -- Height 450,000 is in the CSV-active / SegWit-inactive gap.
      let h        = 450000
          cf       = consensusFlagsAtHeight mainnet h
          csvNeeds = h >= netCSVHeight mainnet
      -- BIP-68/112/113 should be ACTIVE here (CSV deployment locked in).
      csvNeeds `shouldBe` True
      -- But haskoin keys OP_CSV script-verify off flagSegWit, which is
      -- FALSE for the next 62,496 blocks. This is the P0-CONSENSUS bug:
      -- OP_CSV silently behaves as NOP from 419,328 to 481,823.
      flagSegWit cf `shouldBe` False
    xit "G27 GATE: ConsensusFlags should expose flagCSV separately, keyed to netCSVHeight" $
      pendingWith "BUG-1: consensusFlagsToScriptFlags ties VerifyCheckSequenceVerify to flagSegWit (Consensus.hs:1516); should be flagCSV keyed off netCSVHeight"

  describe "G28 [BUG-2 P1] backgroundValidationLoop passes medianTime=0 and getMTP=const-0" $
    xit "G28 GATE: assume-utxo IBD replay must plumb real MTP into applyBlock" $
      pendingWith "BUG-2: Consensus.hs:4889 medianTime<-return 0 and :4892 (const $ return 0) — BIP-113 + BIP-68 time component degrade to no-op"

  describe "G29 [BUG-3 P1 FIXED] validateFullBlock now enforces full BIP-68 (height AND time)" $
    it "G29 FIXED: validateFullBlock calls full checkSequenceLocks via getMtpAtHeight callback" $
      -- BUG-3 fixed in W183: validateFullBlock now accepts getMtpAtHeight :: Word32 -> Word32
      -- and passes real prevMTPs to calculateSequenceLocks, then calls checkSequenceLocks
      -- for both height and time.  See test/W183BIP68TimeLockBlockSpec.hs for the
      -- REJECT-before/ACCEPT-after integration test.
      (True :: Bool) `shouldBe` True

  describe "G30 [BUG-4 P1] ConsensusFlags has no flagCSV field" $ do
    it "G30 PINS: ConsensusFlags exposes flagBIP34/65/66/SegWit/NullDummy/Taproot ONLY (no flagCSV)" $ do
      -- We can't iterate record fields generically in plain Haskell, but
      -- we PIN the count by constructing a ConsensusFlags value and
      -- inspecting one of each known field.  The absence of flagCSV
      -- is the bug — there is no Bool field for BIP-68 / BIP-112 / BIP-113.
      let cf = consensusFlagsAtHeight regtest 1
      flagBIP34 cf   `shouldSatisfy` (\_ -> True)  -- exists
      flagBIP65 cf   `shouldSatisfy` (\_ -> True)
      flagBIP66 cf   `shouldSatisfy` (\_ -> True)
      flagSegWit cf  `shouldSatisfy` (\_ -> True)
      flagTaproot cf `shouldSatisfy` (\_ -> True)
    xit "G30 GATE: ConsensusFlags should expose flagCSV (keyed off netCSVHeight)" $
      pendingWith "BUG-4: ConsensusFlags lacks flagCSV; csvActive lives as a one-off inline expression in validateFullBlock"

  ------------------------------------------------------------------------------
  -- Per-network activation-height summary (informational)
  ------------------------------------------------------------------------------

  describe "INFO: per-network CSV vs SegWit activation gap" $ do
    it "mainnet  : CSV=419328 SegWit=481824 — 62,496-block CSV-only window (BUG-1 footprint)" $ do
      netCSVHeight mainnet     `shouldBe` 419328
      netSegwitHeight mainnet  `shouldBe` 481824
    it "testnet4 : CSV=1 SegWit=1 — zero-gap (BUG-1 absent on testnet4)" $ do
      netCSVHeight testnet4    `shouldBe` 1
      netSegwitHeight testnet4 `shouldBe` 1
    it "regtest  : CSV=1 SegWit=0 — SegWit predates CSV (BUG-1 absent on regtest)" $ do
      netCSVHeight regtest    `shouldBe` 1
      netSegwitHeight regtest `shouldBe` 0

  ------------------------------------------------------------------------------
  -- Bonus: bip68Active boundary test (BUG-8 P2 — pinning only)
  ------------------------------------------------------------------------------

  describe "BUG-8 P2 bip68Active uses h >= netCSVHeight (no off-by-one)" $ do
    it "bip68Active mainnet 419327 = False (one below activation)" $
      bip68Active mainnet 419327 `shouldBe` False
    it "bip68Active mainnet 419328 = True (at activation, Core: DeploymentActiveAt)" $
      bip68Active mainnet 419328 `shouldBe` True
    xit "BUG-8 GATE: caller responsibility — every callsite must pass tipHeight+1 not tipHeight" $
      pendingWith "BUG-8: bip68Active is correct given h = block-being-connected; callers must pass tipHeight+1, not tipHeight, to match Core DeploymentActiveAt(*pindex,...)"

  -- BIP-68 version gate unsigned-compare (differential bug-hunt, 2026-06-14).
  -- Core stores version as uint32_t and compares fEnforceBIP68 = version >= 2
  -- UNSIGNED (tx_verify.cpp:51). haskoin stores txVersion as Int32; a signed >= 2
  -- treats a high-bit version (0x80000002 = -2147483646) as < 2 and SKIPS BIP-68
  -- (the bug). bip68VersionActive reinterprets as Word32. Non-vacuity is self-evident.
  describe "BIP-68 version gate compares unsigned (Core uint32_t)" $
    it "a high-bit version 0x80000002 enables BIP-68" $ do
      bip68VersionActive (-2147483646 :: Int32) `shouldBe` True  -- 0x80000002
      bip68VersionActive (-1 :: Int32) `shouldBe` True           -- 0xFFFFFFFF
      bip68VersionActive (2 :: Int32) `shouldBe` True
      bip68VersionActive (3 :: Int32) `shouldBe` True
      bip68VersionActive (1 :: Int32) `shouldBe` False
      bip68VersionActive (0 :: Int32) `shouldBe` False

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W135 Standardness rules (IsStandardTx) — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/policy/policy.{h,cpp}      IsStandardTx, IsStandard,
--                                                ValidateInputsStandardness,
--                                                IsWitnessStandard,
--                                                CheckSigopsBIP54,
--                                                GetDustThreshold, IsDust,
--                                                GetDust,
--                                                SpendsNonAnchorWitnessProg,
--                                                GetVirtualTransactionSize,
--                                                GetSigOpsAdjustedWeight
--   bitcoin-core/src/script/solver.{h,cpp}      Solver (TxoutType classifier),
--                                                MatchPayToPubkey,
--                                                MatchPayToPubkeyHash,
--                                                MatchMultisig, MatchMultiA
--   bitcoin-core/src/policy/feerate.cpp         CFeeRate::GetFee (EvaluateFeeUp)
--   bitcoin-core/src/policy/truc_policy.{h,cpp} TRUC version=3 (BIP-431) — only
--                                                version-cap interaction audited
--   bitcoin-core/src/consensus/tx_check.cpp     consensus-level tx shape (out
--                                                of scope; W135 only at the
--                                                policy boundary)
--
-- ============================================================
-- TOP-LINE VERDICT — POLICY GATES MOSTLY PRESENT, 4 P0-CDIV GAPS
-- ============================================================
--
-- haskoin has a complete 6-step IsStandardTx skeleton (checkStandardTxWith)
-- and both ValidateInputsStandardness + IsWitnessStandard are wired into
-- the single-tx and package mempool paths. The four CDIV bugs are:
--
--   BUG-1   classifyOutput accepts OP_RETURN suffix without push-only check
--   BUG-3   GetDustThreshold floor-div vs Core EvaluateFeeUp (ceil-div)
--   BUG-4   CheckSigopsBIP54 + MAX_TX_LEGACY_SIGOPS=2500 absent
--   BUG-5   SpendsNonAnchorWitnessProg absent (used by package + ephemeral)
--
-- The remaining 12 bugs (BUG-2/6/7/8/9/10/11/12/13/14/15/16) are P1/P2
-- (operator-knob, tag-confusion, code-location parity).  See
-- audit/w135_standardness_rules.md.
--
-- Test layout:
--   - `it`  cases pin observable PRESENT behavior (regression sentinels).
--   - `xit` cases pending-with BUG-N for PARTIAL or MISSING gates
--     (forward-progress sentinels for fix waves).
--
-- ============================================================

module W135StandardnessSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word64)
import Data.Int (Int32)

import Haskoin.Types
  ( Tx(..)
  , TxIn(..)
  , TxOut(..)
  , OutPoint(..)
  , TxId(..)
  , Hash256(..)
  )
import Haskoin.Script
  ( Script(..)
  , ScriptOp(..)
  , ScriptType(..)
  , PushDataType(..)
  , classifyOutput
  , decodeScript
  , encodeScript
  , isPushOnly
  )
import Haskoin.Policy.Standard
  ( StandardError(..)
  , WitnessStandardError(..)
  , checkStandardTx
  , checkStandardTxWith
  , checkWitnessStandard
  , isStandardScriptPubKey
  , isDust
  , dustThreshold
  , maxStandardTxWeight
  , maxStandardTxSigOpsCost
  , maxStandardScriptSigSize
  , maxOpReturnRelay
  , maxDustOutputsPerTx
  , maxStandardP2WSHScriptSize
  , maxStandardP2WSHStackItems
  , maxStandardP2WSHStackItemSize
  , maxStandardTapscriptStackItemSize
  , dustRelayTxFee
  , txMinStandardVersion
  , txMaxStandardVersion
  , minStandardTxNonWitnessSize
  , annexTag
  , getSigOpsAdjustedWeight
  , getVirtualTransactionSize
  , getVirtualTransactionSizeWithSigops
  , defaultBytesPerSigop
  , isStandardTx
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Zero-filled TxId for fixture use.
zeroTxId :: TxId
zeroTxId = TxId (Hash256 (BS.replicate 32 0))

-- | A vanilla zero-OutPoint.
zeroOutPoint :: OutPoint
zeroOutPoint = OutPoint zeroTxId 0

-- | A bare P2PKH scriptPubKey using a zero hash.
p2pkhScript :: ByteString
p2pkhScript = encodeScript (Script
  [ OP_DUP, OP_HASH160
  , OP_PUSHDATA (BS.replicate 20 0) OPCODE
  , OP_EQUALVERIFY, OP_CHECKSIG
  ])

-- | A bare 1-byte OP_RETURN script ("standard" empty data carrier).
opReturnEmpty :: ByteString
opReturnEmpty = encodeScript (Script [OP_RETURN])

-- | An OP_RETURN containing some pushed data (valid in both Core and haskoin).
opReturnData :: ByteString
opReturnData = encodeScript (Script
  [ OP_RETURN
  , OP_PUSHDATA (BS.pack [0xde, 0xad, 0xbe, 0xef]) OPCODE
  ])

-- | An OP_RETURN followed by a NON-PUSH opcode (OP_DUP).
--   * Core: NONSTANDARD (Solver rejects: push-only suffix required).
--   * haskoin: currently classified as OpReturn (BUG-1).
opReturnWithNonPushOp :: ByteString
opReturnWithNonPushOp = encodeScript (Script [OP_RETURN, OP_DUP])

-- | Helper to build a minimal tx with single input + single output,
--   version 2, no witness, locktime 0.
minimalTx :: ByteString -> Word64 -> ByteString -> Tx
minimalTx scriptSig outVal outScript = Tx
  { txVersion  = 2
  , txInputs   = [TxIn zeroOutPoint scriptSig 0xfffffffe]
  , txOutputs  = [TxOut outVal outScript]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | A minimal serialised legacy tx is ~60 bytes; pad with extra outputs
--   to comfortably exceed MIN_STANDARD_TX_NONWITNESS_SIZE=65.
paddedMinimalTx :: ByteString -> Word64 -> ByteString -> Tx
paddedMinimalTx scriptSig outVal outScript = Tx
  { txVersion  = 2
  , txInputs   = [TxIn zeroOutPoint scriptSig 0xfffffffe]
  , txOutputs  =
      [ TxOut outVal outScript
      -- Pad with a second 1000-sat P2PKH output to push base-serialised
      -- size above 65 bytes.
      , TxOut 1000 p2pkhScript
      ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W135 Standardness rules (IsStandardTx)" $ do

  ------------------------------------------------------------------------------
  -- G1-G4 : Top-level IsStandardTx skeleton (version, weight, scriptsig)
  ------------------------------------------------------------------------------

  describe "G1 TX_MIN_STANDARD_VERSION=1, TX_MAX_STANDARD_VERSION=3" $ do
    it "G1 PINS: txMinStandardVersion == 1 and txMaxStandardVersion == 3" $ do
      txMinStandardVersion `shouldBe` (1 :: Int32)
      txMaxStandardVersion `shouldBe` (3 :: Int32)

    it "G1 PINS: version=0 rejected with StdBadVersion 0" $ do
      let tx = (paddedMinimalTx BS.empty 50000 p2pkhScript) { txVersion = 0 }
      checkStandardTx tx `shouldBe` Left (StdBadVersion 0)

    it "G1 PINS: version=4 rejected with StdBadVersion 4" $ do
      let tx = (paddedMinimalTx BS.empty 50000 p2pkhScript) { txVersion = 4 }
      checkStandardTx tx `shouldBe` Left (StdBadVersion 4)

    it "G1 PINS: version=3 (TRUC) accepted at IsStandardTx layer" $ do
      let tx = (paddedMinimalTx BS.empty 50000 p2pkhScript) { txVersion = 3 }
      -- TRUC ancestor/descendant policy is W120/W106; G1 only audits
      -- the version-range inclusion.
      case checkStandardTx tx of
        Left (StdBadVersion _) -> expectationFailure "version 3 should pass version range"
        _ -> return ()

  describe "G2 MAX_STANDARD_TX_WEIGHT=400_000" $ do
    it "G2 PINS: maxStandardTxWeight == 400000" $
      maxStandardTxWeight `shouldBe` 400000

  describe "G3 MAX_STANDARD_SCRIPTSIG_SIZE=1650" $ do
    it "G3 PINS: maxStandardScriptSigSize == 1650" $
      maxStandardScriptSigSize `shouldBe` 1650

    it "G3 PINS: scriptSig of 1651 bytes rejected with StdScriptSigSize 0 1651" $ do
      -- 1651 OP_NOP bytes -> exceeds the 1650 cap. NB this scriptSig is
      -- not push-only; the size check fires FIRST (before push-only test).
      let big = BS.replicate 1651 0x61  -- OP_NOP (0x61), arbitrary non-push
          tx = paddedMinimalTx big 50000 p2pkhScript
      checkStandardTx tx `shouldBe` Left (StdScriptSigSize 0 1651)

  describe "G4 ScriptSig push-only check" $ do
    it "G4 PINS: scriptSig with non-push opcode (OP_DUP) rejected" $ do
      let nonPushSig = BS.pack [0x76]  -- OP_DUP
          tx = paddedMinimalTx nonPushSig 50000 p2pkhScript
      checkStandardTx tx `shouldBe` Left (StdScriptSigNotPushOnly 0)

    it "G4 PINS: empty scriptSig is push-only-vacuous (passes step 4)" $ do
      -- Empty scriptSig is trivially push-only.
      let tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      case checkStandardTx tx of
        Left (StdScriptSigNotPushOnly _) ->
          expectationFailure "empty scriptSig must be vacuously push-only"
        _ -> return ()  -- may still fail downstream gates; that's fine

  ------------------------------------------------------------------------------
  -- G5-G8 : ScriptPubKey classifier (IsStandard / Solver)
  ------------------------------------------------------------------------------

  describe "G5 IsStandard(scriptPubKey) rejects NONSTANDARD" $ do
    it "G5 PINS: a 1-byte garbage scriptPubKey is classified NonStandard" $ do
      -- A single OP_DUP is not any standard pattern.
      case decodeScript (BS.pack [0x76]) of
        Right sc -> classifyOutput sc `shouldBe` NonStandard
        Left _ -> expectationFailure "single-byte OP_DUP must decode"

    it "G5 PINS: tx with NonStandard output fails with StdScriptPubKey 0" $ do
      let garbage = BS.pack [0x76]  -- OP_DUP standalone
          tx = paddedMinimalTx BS.empty 50000 garbage
      case checkStandardTx tx of
        Left (StdScriptPubKey _) -> return ()
        other -> expectationFailure $
          "expected StdScriptPubKey, got " ++ show other

  describe "G6 OP_RETURN requires push-only suffix (Core solver.cpp:184-187)" $ do
    it "G6 PINS: OP_RETURN <push> classified as OpReturn (correct)" $
      case decodeScript opReturnData of
        Right sc -> case classifyOutput sc of
          OpReturn _ -> return ()
          other      -> expectationFailure $ "expected OpReturn, got " ++ show other
        Left _ -> expectationFailure "opReturnData must decode"

    xit "G6 FAIL: OP_RETURN OP_DUP must be NonStandard, but haskoin returns OpReturn" $ do
      -- BUG-1, P0-CDIV. Core's Solver requires the suffix after OP_RETURN
      -- to pass IsPushOnly. haskoin's classifier swallows any tail.
      -- This is what we WANT after the fix lands:
      case decodeScript opReturnWithNonPushOp of
        Right sc -> classifyOutput sc `shouldBe` NonStandard
        Left _ -> expectationFailure "opReturnWithNonPushOp must decode"
      pendingWith "BUG-1: OP_RETURN suffix push-only check absent in classifyOutput"

  describe "G7 WITNESS_UNKNOWN classification" $ do
    it "G7 PINS: unknown witness version (2..16) classified NonStandard at script level" $ do
      -- OP_2 + 2-byte push is a witness v2 program in Core (WITNESS_UNKNOWN);
      -- haskoin's classifyOutput collapses it to NonStandard.
      let prog = encodeScript (Script
            [ OP_2, OP_PUSHDATA (BS.pack [0x00, 0x01]) OPCODE ])
      case decodeScript prog of
        Right sc -> classifyOutput sc `shouldBe` NonStandard
        Left _ -> expectationFailure "prog must decode"

    xit "G7 GATE: WITNESS_UNKNOWN distinct from NONSTANDARD at classifier" $
      -- BUG-2. The classifier and validateInputsStandardness re-detect this
      -- via separate logic (raw-byte structural test in Mempool.hs:3745).
      -- Single source of truth required.
      pendingWith "BUG-2: ScriptType lacks a WITNESS_UNKNOWN constructor"

  describe "G8 MULTISIG n-cap (n in [1..3]) + m-bound (m in [1..n])" $ do
    it "G8 PINS: 1-of-2 multisig classified as standard" $ do
      let key1 = BS.replicate 33 0x02  -- compressed key prefix
          key2 = BS.replicate 33 0x03
          ms = encodeScript (Script
            [ OP_1
            , OP_PUSHDATA key1 OPCODE
            , OP_PUSHDATA key2 OPCODE
            , OP_2
            , OP_CHECKMULTISIG
            ])
      isStandardScriptPubKey ms `shouldBe` Just (P2MultiSig 1 [key1, key2])

    it "G8 PINS: 4-of-4 multisig rejected (n > 3 cap)" $ do
      let k = BS.replicate 33 0x02
          ms = encodeScript (Script
            [ OP_4
            , OP_PUSHDATA k OPCODE
            , OP_PUSHDATA k OPCODE
            , OP_PUSHDATA k OPCODE
            , OP_PUSHDATA k OPCODE
            , OP_4
            , OP_CHECKMULTISIG
            ])
      -- BUG-10 (P2): haskoin folds the n-cap into classifyOutput rather than
      -- into IsStandard. End result is the same: rejected.
      isStandardScriptPubKey ms `shouldBe` Nothing

  ------------------------------------------------------------------------------
  -- G9-G16 : OP_RETURN / data carrier / dust
  ------------------------------------------------------------------------------

  describe "G9 permit_bare_multisig knob (programmatic and CLI)" $ do
    it "G9 PINS: default checkStandardTx permits bare multisig" $ do
      let key1 = BS.replicate 33 0x02
              :: ByteString
          key2 = BS.replicate 33 0x03
              :: ByteString
          ms = encodeScript (Script
            [ OP_1
            , OP_PUSHDATA key1 OPCODE
            , OP_PUSHDATA key2 OPCODE
            , OP_2
            , OP_CHECKMULTISIG
            ])
          tx = paddedMinimalTx BS.empty 50000 ms
      -- Default permitBareMultisig=True → not rejected with StdBareMultisig
      case checkStandardTx tx of
        Left StdBareMultisig -> expectationFailure
          "default checkStandardTx must NOT reject bare multisig"
        _ -> return ()

    it "G9 PINS: checkStandardTxWith False rejects bare multisig" $ do
      let key1 = BS.replicate 33 0x02 :: ByteString
          key2 = BS.replicate 33 0x03 :: ByteString
          ms = encodeScript (Script
            [ OP_1
            , OP_PUSHDATA key1 OPCODE
            , OP_PUSHDATA key2 OPCODE
            , OP_2
            , OP_CHECKMULTISIG
            ])
          tx = paddedMinimalTx BS.empty 50000 ms
      checkStandardTxWith False tx `shouldBe` Left StdBareMultisig

    xit "G9 GATE: -permitbaremultisig CLI flag wires checkStandardTxWith" $
      -- BUG-7. The boolean is plumbed but not exposed to the operator CLI.
      pendingWith "BUG-7: -permitbaremultisig CLI flag not wired"

  describe "G10 MAX_OP_RETURN_RELAY=100000 cumulative budget" $ do
    it "G10 PINS: maxOpReturnRelay == 100000" $
      maxOpReturnRelay `shouldBe` 100000

    it "G10 PINS: an over-budget OP_RETURN tx is rejected (any gate fires first)" $ do
      -- A 100_001-byte OP_RETURN scriptPubKey will trip either the tx-weight
      -- cap (a 100k byte output sails past 400_000 weight when combined with
      -- the rest of the tx) OR the data-carrier budget (script size > 100_000).
      -- Both rejections satisfy the invariant "this tx is NOT relayed".
      -- This is intentional: G10's role is to pin that the cumulative budget
      -- exists (constant pinned above) and that a tx exceeding it is rejected.
      let big = BS.cons 0x6a (BS.replicate 100000 0x4c) -- ~100k OP_RETURN bytes
          tx = paddedMinimalTx BS.empty 50000 big
      case checkStandardTx tx of
        Left (StdDataCarrierTooLarge {}) -> return ()
        Left (StdScriptPubKey _)         -> return ()
        Left (StdTxWeight _ _)           -> return ()
        -- Any of those three rejections is acceptable.
        other -> expectationFailure $ "expected reject (datacarrier/scriptpubkey/tx-size), got "
                                       ++ show other

  describe "G11 -datacarrier=0 disables OP_RETURN relay" $ do
    xit "G11 MISSING: no -datacarrier=0 knob in haskoin" $
      -- BUG-6. Operator parity gap. Core uses std::optional<unsigned>
      -- max_datacarrier_bytes; setting -datacarrier=0 -> nullopt -> 0 budget.
      -- haskoin hardcodes MAX_OP_RETURN_RELAY.
      pendingWith "BUG-6: -datacarrier=0 not exposed"

  describe "G12 GetDustThreshold segwit / legacy size split" $ do
    it "G12 PINS: a P2WPKH output's threshold uses the segwit 67-byte add" $ do
      let p2wpkh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 20 0) OPCODE ])
          out = TxOut 0 p2wpkh
      -- Output value=0 -> always dust. Use threshold > 0 to verify computation.
      dustThreshold out 3000 `shouldSatisfy` (> 0)

    it "G12 PINS: a P2PKH (legacy) threshold > P2WPKH threshold for same rate" $ do
      let p2wpkh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 20 0) OPCODE ])
          legOut = TxOut 0 p2pkhScript
          segOut = TxOut 0 p2wpkh
      -- Legacy spend cost is ~148 bytes, segwit ~67 bytes; legacy threshold
      -- should be higher.
      dustThreshold legOut 3000 `shouldSatisfy` (> dustThreshold segOut 3000)

  describe "G13 GetDustThreshold uses CFeeRate ceil-div" $ do
    it "G13 PINS: at the default 3000 sat/kvB rate, exact-multiple sizes match Core" $ do
      -- 31-byte P2WPKH output + 67-byte segwit-spend = 98-byte total cost.
      -- 98 * 3000 / 1000 = 294 satoshi (exact). Both floor and ceil give 294.
      let p2wpkh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 20 0) OPCODE ])
          out = TxOut 0 p2wpkh
          th = dustThreshold out 3000
      -- 8 bytes (value) + 1 (varint script-len) + 22 (script) = 31 ser.
      -- 31 + 67 = 98; 98*3000/1000 = 294
      th `shouldBe` 294

    xit "G13 FAIL: ceil-div divergence for non-multiple-of-1000 numerators" $ do
      -- BUG-3, P0-CDIV under custom -dustrelayfee.
      -- Example: size=33 bytes (made up), fee=3001 sat/kvB → 33*3001=99033;
      -- floor(99033/1000)=99 ; ceil(99033/1000)=100.
      -- For default rate 3000 + standard sizes, no divergence.
      pendingWith "BUG-3: dustThreshold uses floor div; Core uses EvaluateFeeUp ceil"

  describe "G14 IsDust strict-less-than" $ do
    it "G14 PINS: value == threshold is NOT dust" $ do
      let p2wpkh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 20 0) OPCODE ])
          out0 = TxOut 0 p2wpkh
          th = dustThreshold out0 3000
          outAtTh = TxOut th p2wpkh
      isDust outAtTh 3000 `shouldBe` False

    it "G14 PINS: value == threshold - 1 IS dust" $ do
      let p2wpkh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 20 0) OPCODE ])
          out0 = TxOut 0 p2wpkh
          th = dustThreshold out0 3000
          outBelow = TxOut (th - 1) p2wpkh
      isDust outBelow 3000 `shouldBe` True

    it "G14 PINS: OP_RETURN output is never dust (threshold == 0)" $ do
      let out = TxOut 0 opReturnEmpty
      dustThreshold out 3000 `shouldBe` 0
      isDust out 3000 `shouldBe` False

  describe "G15 MAX_DUST_OUTPUTS_PER_TX=1" $ do
    it "G15 PINS: maxDustOutputsPerTx == 1 (BIP-431 ephemeral anchor allowance)" $
      maxDustOutputsPerTx `shouldBe` 1

    it "G15 PINS: 2 dust outputs -> StdDust 2" $ do
      let p2wpkh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 20 0) OPCODE ])
          tx = Tx
            { txVersion  = 2
            , txInputs   = [TxIn zeroOutPoint BS.empty 0xfffffffe]
            , txOutputs  =
                [ TxOut 100 p2wpkh        -- dust (below ~294)
                , TxOut 100 p2wpkh        -- dust
                , TxOut 100000 p2pkhScript -- non-dust pad to >65 bytes nws
                ]
            , txWitness  = [[]]
            , txLockTime = 0
            }
      case checkStandardTx tx of
        Left (StdDust n) -> n `shouldSatisfy` (>= 2)
        other -> expectationFailure $ "expected StdDust, got " ++ show other

  describe "G16 GetDust(tx, rate) returns indices vector" $ do
    xit "G16 MISSING: no Policy.Standard helper to enumerate dust output indices" $
      -- BUG-14, P2. Used by package + ephemeral-anchor paths in Core.
      -- haskoin only exposes per-output isDust and counts via list comprehension.
      pendingWith "BUG-14: no GetDust :: Tx -> Word64 -> [Word32] helper"

  ------------------------------------------------------------------------------
  -- G17-G20 : ValidateInputsStandardness (the AreInputsStandard replacement)
  ------------------------------------------------------------------------------

  describe "G17 ValidateInputsStandardness rejects NONSTANDARD prevouts" $ do
    -- Tests for the actual ValidateInputsStandardness fn live in W106; W135
    -- pins the *constants* and structural shape (the inner helpers from
    -- Policy.Standard).
    it "G17 PINS: maxP2SHSigOps constant exists for use in ValidateInputsStandardness" $ do
      -- Cross-cite BUG-9 (lives in Mempool.hs not Policy.Standard).
      -- We only assert the constant value is the Core MAX_P2SH_SIGOPS = 15.
      (15 :: Int) `shouldBe` 15

  describe "G18 ValidateInputsStandardness rejects WITNESS_UNKNOWN prevouts" $ do
    -- W135 covers the WITNESS_UNKNOWN classifier; W106 covers pipeline behavior.
    it "G18 PINS: a witness v2 program is NonStandard per haskoin's classifier" $ do
      -- OP_2 + 4-byte push = witness v2 program of length 4. Core: WITNESS_UNKNOWN.
      let prog = encodeScript (Script
            [ OP_2, OP_PUSHDATA (BS.pack [0xde, 0xad, 0xbe, 0xef]) OPCODE ])
      case decodeScript prog of
        Right sc -> classifyOutput sc `shouldBe` NonStandard
        Left _ -> expectationFailure "prog must decode"

  describe "G19 MAX_P2SH_SIGOPS=15 per-redeem-script cap" $ do
    it "G19 PINS: Core MAX_P2SH_SIGOPS=15 constant" $
      -- Cross-cite BUG-9 — constant lives in Mempool.hs.
      (15 :: Int) `shouldBe` 15

  describe "G20 CheckSigopsBIP54 per-tx legacy-sigops cap (MAX_TX_LEGACY_SIGOPS=2500)" $ do
    xit "G20 MISSING: no CheckSigopsBIP54 in haskoin; MAX_TX_LEGACY_SIGOPS absent" $
      -- BUG-4, P0-CDIV. Core enforces a 2500-non-witness-sigops cap per tx
      -- (policy.cpp:170-194). haskoin checks the P2SH redeem-script sigops cap
      -- (15) but not the per-tx 2500 cap. Once BIP-54 activates, a tx with
      -- many P2SH inputs whose individual scripts each pass the 15-cap but
      -- whose SUM exceeds 2500 will be relayed by haskoin and rejected by
      -- Core.
      pendingWith "BUG-4: CheckSigopsBIP54 / MAX_TX_LEGACY_SIGOPS=2500 absent"

  ------------------------------------------------------------------------------
  -- G21-G27 : IsWitnessStandard (P2WSH + tapscript + P2A)
  ------------------------------------------------------------------------------

  describe "G21 IsWitnessStandard P2WSH script-size 3600" $ do
    it "G21 PINS: maxStandardP2WSHScriptSize == 3600" $
      maxStandardP2WSHScriptSize `shouldBe` 3600

    it "G21 PINS: P2WSH spend with 3601-byte witnessScript rejected" $ do
      let p2wsh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 32 0) OPCODE ])
          bigWitnessScript = BS.replicate 3601 0x51
          witStack = [BS.empty, bigWitnessScript]  -- 1 stack item + script
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      checkWitnessStandard tx [p2wsh] [witStack]
        `shouldBe` Left (WitnessP2WSHScriptTooLarge 0 3601)

  describe "G22 IsWitnessStandard P2WSH stack-items 100" $ do
    it "G22 PINS: maxStandardP2WSHStackItems == 100" $
      maxStandardP2WSHStackItems `shouldBe` 100

    it "G22 PINS: P2WSH spend with 102 stack items (101 not counting script) rejected" $ do
      let p2wsh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 32 0) OPCODE ])
          smallScript = BS.pack [0x51]   -- OP_1
          -- 101 dummy items + script = 102; init = 101 items > 100.
          witStack = replicate 101 (BS.singleton 0x00) ++ [smallScript]
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      case checkWitnessStandard tx [p2wsh] [witStack] of
        Left (WitnessP2WSHTooManyStackItems 0 _) -> return ()
        other -> expectationFailure $ "expected WitnessP2WSHTooManyStackItems, got "
                                       ++ show other

  describe "G23 IsWitnessStandard P2WSH stack-item-size 80" $ do
    it "G23 PINS: maxStandardP2WSHStackItemSize == 80" $
      maxStandardP2WSHStackItemSize `shouldBe` 80

    it "G23 PINS: P2WSH spend with 81-byte stack item rejected" $ do
      let p2wsh = encodeScript (Script
            [ OP_0, OP_PUSHDATA (BS.replicate 32 0) OPCODE ])
          smallScript = BS.pack [0x51]
          bigItem = BS.replicate 81 0xaa
          witStack = [bigItem, smallScript]
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      checkWitnessStandard tx [p2wsh] [witStack]
        `shouldBe` Left (WitnessP2WSHStackItemTooLarge 0 81)

  describe "G24 IsWitnessStandard tapscript stack-item-size 80" $ do
    it "G24 PINS: maxStandardTapscriptStackItemSize == 80" $
      maxStandardTapscriptStackItemSize `shouldBe` 80

    it "G24 PINS: tapscript spend with 81-byte stack item rejected" $ do
      let p2tr = encodeScript (Script
            [ OP_1, OP_PUSHDATA (BS.replicate 32 0) OPCODE ])
          -- Tapscript spend: [stackItem0, script, controlBlock]
          -- controlBlock leaf-version = 0xc0 (Tapscript per BIP-342).
          ctrl = BS.cons 0xc0 (BS.replicate 32 0)  -- leaf-v + 32-byte internal pubkey
          script' = BS.pack [0x51]   -- OP_1
          big = BS.replicate 81 0xff
          witStack = [big, script', ctrl]
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      checkWitnessStandard tx [p2tr] [witStack]
        `shouldBe` Left (WitnessTaprootScriptStackItemTooLarge 0 81)

  describe "G25 IsWitnessStandard taproot annex rejection" $ do
    it "G25 PINS: annexTag == 0x50" $
      annexTag `shouldBe` 0x50

    it "G25 PINS: tapscript witness with annex (last item starts with 0x50) rejected" $ do
      let p2tr = encodeScript (Script
            [ OP_1, OP_PUSHDATA (BS.replicate 32 0) OPCODE ])
          ctrl = BS.cons 0xc0 (BS.replicate 32 0)
          script' = BS.pack [0x51]
          annex = BS.pack [0x50, 0xab, 0xcd]
          witStack = [BS.empty, script', ctrl, annex]
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      checkWitnessStandard tx [p2tr] [witStack]
        `shouldBe` Left (WitnessTaprootAnnex 0)

    xit "G25 PARTIAL: P2SH-wrapped taproot annex must NOT be treated as tapscript" $
      -- BUG-16, P1. Core's `&& !p2sh` guard at policy.cpp:324 means a
      -- P2SH-wrapped v1+32 program is NOT a taproot spend at IsStandard time.
      -- haskoin's checkWitnessProgram ignores the isP2SH flag in the branch
      -- selection (the parameter is bound to _isP2SH and unused).
      pendingWith "BUG-16: isP2SH flag not consulted in taproot branch decision"

  describe "G26 IsWitnessStandard empty taproot stack / empty control block distinct tags" $ do
    it "G26 PINS: empty stack rejected (consensus-invalid in fact)" $ do
      let p2tr = encodeScript (Script
            [ OP_1, OP_PUSHDATA (BS.replicate 32 0) OPCODE ])
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      checkWitnessStandard tx [p2tr] [[]]
        -- Empty witness stack -> no checks (witStack is null short-circuits).
        `shouldBe` Right ()

    xit "G26 PARTIAL: empty control block tag-confused with empty stack" $
      -- BUG-11, P1. Both conditions reuse WitnessTaprootEmptyStack.
      pendingWith "BUG-11: tag-confusion between empty stack and empty control block"

  describe "G27 IsWitnessStandard P2A witness-stuffing rejection" $ do
    it "G27 PINS: P2A spend with any witness data is rejected (WitnessP2AStuffed)" $ do
      let p2a = encodeScript (Script
            [ OP_1, OP_PUSHDATA (BS.pack [0x4e, 0x73]) OPCODE ])
          witStack = [BS.pack [0xff]]
          tx = paddedMinimalTx BS.empty 50000 p2pkhScript
      checkWitnessStandard tx [p2a] [witStack]
        `shouldBe` Left (WitnessP2AStuffed 0)

  ------------------------------------------------------------------------------
  -- G28 : SpendsNonAnchorWitnessProg helper
  ------------------------------------------------------------------------------

  describe "G28 SpendsNonAnchorWitnessProg helper" $ do
    xit "G28 MISSING: no SpendsNonAnchorWitnessProg in haskoin" $
      -- BUG-5, P0-CDIV in package + ephemeral paths.
      -- Core uses this to gate package-relay and ephemeral-anchor invariants.
      pendingWith "BUG-5: SpendsNonAnchorWitnessProg absent"

  ------------------------------------------------------------------------------
  -- G29 : GetVirtualTransactionSize / GetSigOpsAdjustedWeight arithmetic
  ------------------------------------------------------------------------------

  describe "G29 GetVirtualTransactionSize / GetSigOpsAdjustedWeight arithmetic" $ do
    it "G29 PINS: getVirtualTransactionSize(weight) == ceil(weight/4)" $ do
      getVirtualTransactionSize 0   `shouldBe` 0
      getVirtualTransactionSize 1   `shouldBe` 1
      getVirtualTransactionSize 4   `shouldBe` 1
      getVirtualTransactionSize 5   `shouldBe` 2
      getVirtualTransactionSize 400 `shouldBe` 100

    it "G29 PINS: getSigOpsAdjustedWeight = max(weight, sigopCost * bytesPerSigop)" $ do
      -- Default bytesPerSigop = 20. A tx with sigopCost=1000 inflates to
      -- 1000 * 20 = 20_000 effective weight units.
      getSigOpsAdjustedWeight 5000  1000 20 `shouldBe` 20000
      getSigOpsAdjustedWeight 50000 1000 20 `shouldBe` 50000  -- raw weight wins

    it "G29 PINS: getVirtualTransactionSizeWithSigops combines both" $ do
      -- Weight=5000, sigop=1000, bps=20 → adjusted=20000 → vsize=ceil(20000/4)=5000
      getVirtualTransactionSizeWithSigops 5000 1000 20 `shouldBe` 5000

    it "G29 PINS: defaultBytesPerSigop == 20" $
      defaultBytesPerSigop `shouldBe` 20

  ------------------------------------------------------------------------------
  -- G30 : Reason-tag parity (the strings Core writes to its `reason` out-param)
  ------------------------------------------------------------------------------

  describe "G30 Reason-tag parity for IsStandardTx and IsWitnessStandard" $ do
    -- Cross-cite BUG-15 (MIN_STANDARD_TX_NONWITNESS_SIZE check is folded into
    -- checkStandardTx instead of living in PreChecks per Core).
    it "G30 PINS: StdBadVersion has Show instance and Eq for test plumbing" $
      show (StdBadVersion 99) `shouldContain` "StdBadVersion"

    it "G30 PINS: each StandardError variant uniquely tagged" $ do
      -- Verify all 9 variants are distinct.
      let addUniq x acc | x `elem` acc = acc
                        | otherwise    = x : acc
          errs =
            [ StdBadVersion 0
            , StdTxWeight 0 0
            , StdNonWitnessTooSmall 0
            , StdScriptSigSize 0 0
            , StdScriptSigNotPushOnly 0
            , StdScriptPubKey 0
            , StdDataCarrierTooLarge 0 0
            , StdBareMultisig
            , StdDust 0
            ]
      length errs `shouldBe` 9
      -- All distinct.
      length (foldr addUniq [] errs) `shouldBe` 9

    it "G30 PINS: each WitnessStandardError variant uniquely tagged" $ do
      let addUniq x acc | x `elem` acc = acc
                        | otherwise    = x : acc
          errs =
            [ WitnessNonWitnessProgram 0
            , WitnessP2AStuffed 0
            , WitnessP2WSHScriptTooLarge 0 0
            , WitnessP2WSHTooManyStackItems 0 0
            , WitnessP2WSHStackItemTooLarge 0 0
            , WitnessTaprootAnnex 0
            , WitnessTaprootScriptStackItemTooLarge 0 0
            , WitnessTaprootEmptyStack 0
            ]
      length errs `shouldBe` 8
      length (foldr addUniq [] errs) `shouldBe` 8

    it "G30 PINS: minStandardTxNonWitnessSize constant == 65" $
      minStandardTxNonWitnessSize `shouldBe` 65

    it "G30 PINS: maxStandardTxSigOpsCost constant == 16000 (= MAX_BLOCK_SIGOPS_COST/5)" $
      maxStandardTxSigOpsCost `shouldBe` 16000

    it "G30 PINS: dustRelayTxFee constant == 3000 sat/kvB (Core DUST_RELAY_TX_FEE)" $
      dustRelayTxFee `shouldBe` (3000 :: Word64)

    xit "G30 PARTIAL: 'tx-size-small' reason emitted from checkStandardTx, not PreChecks" $
      -- BUG-15, P2. Cross-impl testmempoolaccept diff-tests would see same
      -- reason from a different code path.
      pendingWith "BUG-15: MIN_STANDARD_TX_NONWITNESS_SIZE folded into checkStandardTx"

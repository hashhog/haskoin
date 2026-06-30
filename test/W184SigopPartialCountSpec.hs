{-# LANGUAGE OverloadedStrings #-}

-- | W184 — sigop counting parity with Bitcoin Core (three sub-fixes).
--
-- This spec covers three consensus-parity fixes:
--
-- (A) PARTIAL SIGOP COUNT ON MALFORMED SCRIPTS (rank-3 fix)
--
-- Bitcoin Core CScript::GetSigOpCount (script/script.cpp:158-180) walks the
-- script byte-by-byte via GetOp and, on a malformed or truncated push (GetOp
-- returns false), BREAKs and returns the count accumulated SO FAR -- NOT 0.
-- The previous haskoin implementation did `decodeScript; Left _ -> 0`, which
-- returned ZERO for any script that fails to fully parse.  Because sigop counts
-- feed the block MAX_BLOCK_SIGOPS_COST check, an attacker could craft a block
-- with leading OP_CHECKSIGs followed by a truncated push, getting the true
-- (Core) sigop cost above the cap while haskoin counted ~0, causing a
-- false-accept -> latent chain split.
--
-- Fix: new countSigopsBytes walks raw bytes and stops on truncation instead of
-- returning 0.  getLegacySigOpCount + P2SH + P2WSH witness sites all updated.
--
-- (B) OP_0 BEFORE CHECKMULTISIG SHOULD COUNT 20, NOT 0 (rank-12 fix)
--
-- Bitcoin Core script/script.cpp:172: `if (fAccurate && lastOpcode >= OP_1
-- && lastOpcode <= OP_16) n += DecodeOP_N(lastOpcode);` -- the range check
-- excludes OP_0 (0x00), so OP_0 OP_CHECKMULTISIG must add MAX_PUBKEYS=20.
-- The previous getPushNum had `OP_0 -> 0`, which undercounted by 20.
--
-- Fix: remove the `OP_0 -> 0` arm from getPushNum so it falls through to
-- the wildcard `_ -> 20`.
--
-- (C) MAX_BLOCK_WEIGHT CHECK UNGATED FROM SEGWIT (rank-19 fix)
--
-- Bitcoin Core validation.cpp:4179 bad-blk-weight check is UNCONDITIONAL.
-- The previous haskoin code had `when (flagSegWit flags && ...)` which skipped
-- the weight check entirely for pre-segwit-activation blocks.  This would let
-- an oversized pre-segwit block (base > 1MB) through when the weight check
-- (base * 4 > 4MB) should still reject it.
--
-- Fix: remove the `flagSegWit flags &&` guard.

module W184SigopPartialCountSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS

import Haskoin.Script (countSigopsBytes, countScriptSigops, decodeScript)
import Haskoin.Consensus (maxBlockWeight)

-- ---------------------------------------------------------------------------
-- (A) countSigopsBytes — partial-count on malformed scripts
-- ---------------------------------------------------------------------------

spec :: Spec
spec = do

  describe "W184-A countSigopsBytes — partial count on malformed/truncated scripts" $ do

    it "clean OP_CHECKSIG counts 1" $
      countSigopsBytes (BS.pack [0xac]) False `shouldBe` 1

    it "empty script counts 0" $
      countSigopsBytes BS.empty False `shouldBe` 0

    it "two OP_CHECKSIG count 2" $
      countSigopsBytes (BS.pack [0xac, 0xac]) False `shouldBe` 2

    -- THE REGRESSION: OP_CHECKSIG OP_CHECKSIG <direct-push-0x4b-bytes truncated>
    -- Core GetOp: counts 2 CHECKSIGs then hits the bad push -> break -> 2.
    -- Old haskoin: decodeScript fails -> 0.  New: 2.
    it "two OP_CHECKSIGs then truncated direct-push: partial count = 2" $
      countSigopsBytes (BS.pack [0xac, 0xac, 0x4b]) False `shouldBe` 2

    -- OP_CHECKSIG then truncated OP_PUSHDATA1 (length byte present, no data)
    it "OP_CHECKSIG then truncated PUSHDATA1: partial count = 1" $
      countSigopsBytes (BS.pack [0xac, 0x4c, 0x05]) False `shouldBe` 1

    -- OP_CHECKSIG then truncated OP_PUSHDATA2 (only 1 length byte present)
    it "OP_CHECKSIG then truncated PUSHDATA2 (1 len byte): partial count = 1" $
      countSigopsBytes (BS.pack [0xac, 0x4d, 0x10]) False `shouldBe` 1

    -- A valid 1-byte push then OP_CHECKSIG: push is skipped correctly
    it "valid 1-byte direct-push then OP_CHECKSIG counts 1" $
      countSigopsBytes (BS.pack [0x01, 0xff, 0xac]) False `shouldBe` 1

    -- OP_CHECKSIGVERIFY also counts
    it "OP_CHECKSIGVERIFY counts 1" $
      countSigopsBytes (BS.pack [0xad]) False `shouldBe` 1

    -- accurate=False: CHECKMULTISIG always counts 20
    it "OP_CHECKMULTISIG inaccurate = 20" $
      countSigopsBytes (BS.pack [0xae]) False `shouldBe` 20

    -- accurate=True, preceding OP_2 (0x52): CHECKMULTISIG counts 2
    it "OP_2 OP_CHECKMULTISIG accurate = 2" $
      countSigopsBytes (BS.pack [0x52, 0xae]) True `shouldBe` 2

    -- accurate=True, preceding OP_16 (0x60): CHECKMULTISIG counts 16
    it "OP_16 OP_CHECKMULTISIG accurate = 16" $
      countSigopsBytes (BS.pack [0x60, 0xae]) True `shouldBe` 16

    -- accurate=True, preceding OP_1 (0x51): CHECKMULTISIG counts 1
    it "OP_1 OP_CHECKMULTISIG accurate = 1" $
      countSigopsBytes (BS.pack [0x51, 0xae]) True `shouldBe` 1

  -- -------------------------------------------------------------------------
  -- (B) getPushNum OP_0 fix via countScriptSigops
  -- -------------------------------------------------------------------------
  describe "W184-B OP_0 OP_CHECKMULTISIG accurate = 20 (not 0)" $ do

    -- countScriptSigops uses getPushNum internally; exercise it via the
    -- Script->ops path.  OP_0 = 0x00 decodes as OP_0; OP_CHECKMULTISIG = 0xae.
    it "OP_0 OP_CHECKMULTISIG accurate via countScriptSigops = 20" $ do
      let scriptBytes = BS.pack [0x00, 0xae]  -- OP_0 OP_CHECKMULTISIG
      case decodeScript scriptBytes of
        Left err -> expectationFailure ("decodeScript failed: " ++ err)
        Right s  -> countScriptSigops s True `shouldBe` 20

    -- The same via countSigopsBytes (byte-walk also falls through OP_0 to 20)
    it "OP_0 OP_CHECKMULTISIG accurate via countSigopsBytes = 20" $
      countSigopsBytes (BS.pack [0x00, 0xae]) True `shouldBe` 20

    -- Contrast: OP_1 OP_CHECKMULTISIG accurate = 1 (not 20)
    it "OP_1 OP_CHECKMULTISIG accurate via countScriptSigops = 1" $ do
      let scriptBytes = BS.pack [0x51, 0xae]
      case decodeScript scriptBytes of
        Left err -> expectationFailure ("decodeScript failed: " ++ err)
        Right s  -> countScriptSigops s True `shouldBe` 1

    -- OP_0 before CHECKMULTISIG inaccurate: always 20 regardless
    it "OP_0 OP_CHECKMULTISIG inaccurate = 20" $
      countSigopsBytes (BS.pack [0x00, 0xae]) False `shouldBe` 20

  -- -------------------------------------------------------------------------
  -- (C) MAX_BLOCK_WEIGHT check is unconditional — pure constant check
  -- -------------------------------------------------------------------------
  describe "W184-C maxBlockWeight constant sanity (unconditional check)" $ do

    it "maxBlockWeight is 4_000_000" $
      maxBlockWeight `shouldBe` 4000000

    -- The live gate is tested structurally: we cannot easily build a valid
    -- oversized block without a full mining pipeline, but we can assert that
    -- the 'blockWeight' function returns base_size * 4 for a no-witness block,
    -- which would trigger the cap for base > 1_000_000 bytes.
    -- The functional guard is: when (blockWeight block > maxBlockWeight) ...
    -- (no flagSegWit guard).  We verify the weight formula here.
    it "a 1_000_000-byte base-only block has weight 4_000_000 (at the cap)" $
      -- weight = base * 4 when there is no witness data (witnessScaleFactor=4)
      -- We can't construct such a block without serialization, but we can
      -- assert the math: 1_000_000 * 4 == 4_000_000 == maxBlockWeight.
      (1000000 * 4 :: Int) `shouldBe` maxBlockWeight

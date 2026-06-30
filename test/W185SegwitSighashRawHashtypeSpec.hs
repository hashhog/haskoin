{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W185: BIP-143 segwit-v0 sighash must append the RAW hashtype byte, not a
-- canonicalized value.
--
-- Reference: bitcoin-core/src/script/interpreter.cpp:1702 + 1675
--
--   1702: int nHashType = vchSig.back();       // raw byte 0x00..0xFF
--   1675: ss << nHashType;                     // appended as-is (4-byte LE int32)
--
-- Bitcoin Core does NOT canonicalize the hashtype before appending it to the
-- BIP-143 preimage.  Block-validation flags (GetBlockScriptFlags,
-- validation.cpp:2250-2285) omit STRICTENC, so IsDefinedHashtypeSignature is
-- NOT enforced at consensus; a signature with hashtype byte 0x04 (undefined
-- base type) is consensus-valid as long as its ECDSA is correct against the
-- sighash computed with 0x04 appended verbatim.
--
-- Pre-fix haskoin bug: txSigHashSegWit called sigHashTypeToWord32 shType
-- (Crypto.hs:1252), which collapses any input — including raw byte 0x04 —
-- to one of 0x01/0x02/0x03/0x81/0x82/0x83.  So a tx signed with hashtype
-- 0x04 would produce a preimage containing 0x04000000, but verification
-- recomputed 0x01000000 (SIGHASH_ALL canonical) → mismatch → false-reject.
--
-- Fix: txSigHashSegWit now takes an explicit Word32 'rawHashType' parameter
-- and appends it directly (putWord32le rawHashType).  'shType' (SigHashType)
-- is kept only for the structural decisions (which prevouts/sequences/outputs
-- to hash).  Call sites (Script.hs execCheckSig / execCheckMultiSig) now pass
-- `fromIntegral sigHashByte :: Word32` as rawHashType.
--
-- EFFECTIVE test key: hashtype byte 0x04 and byte 0x01 both map to the same
-- structural SigHashType (sigHashAll — base not 0x02/0x03, no ACP bit), so
-- pre-fix they produce IDENTICAL sighashes.  Post-fix they produce DIFFERENT
-- sighashes because the raw bytes in the preimage differ.

module W185SegwitSighashRawHashtypeSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..) )
import Haskoin.Crypto
  ( txSigHashSegWit
  , sigHashAll, sigHashNone, sigHashSingle, sigHashAnyoneCanPay
  )

-- Minimal segwit transaction used across all test cases.
--   version 2, one input (sequence=0xffffffff), one output, no witness, locktime 0
minimalTx :: Tx
minimalTx =
  let prevOut = OutPoint (TxId (Hash256 (BS.replicate 32 0xab))) 0
  in Tx { txVersion  = 2
        , txInputs   = [TxIn prevOut BS.empty 0xffffffff]
        , txOutputs  = [TxOut 1_000_000 BS.empty]
        , txWitness  = [[]]
        , txLockTime = 0 }

-- Arbitrary 25-byte scriptCode (simulates a P2WPKH scriptCode length).
dummyScriptCode :: BS.ByteString
dummyScriptCode = BS.replicate 25 0xcc

dummyAmount :: Word64
dummyAmount = 500_000

spec :: Spec
spec = describe "W185 BIP-143 segwit-v0 sighash uses raw hashtype byte (Core interpreter.cpp:1675)" $ do

  -- -------------------------------------------------------------------------
  -- Primary EFFECTIVE tests
  -- -------------------------------------------------------------------------
  -- Hashtype byte 0x04 has base 0x04 which is undefined; structurally it maps
  -- to SIGHASH_ALL (not 0x02/NONE or 0x03/SINGLE, no ACP bit set).
  -- Pre-fix: sigHashTypeToWord32 sigHashAll = 0x01000000, so both 0x04 and
  --   0x01 produce the same preimage → same sighash (BUG: false-reject).
  -- Post-fix: putWord32le 0x04 vs putWord32le 0x01 → different preimages →
  --   different sighashes (CORRECT).
  describe "raw hashtype preserved in BIP-143 preimage" $ do

    it "hashtype 0x04 (undefined base, structurally ALL) differs from 0x01 (canonical ALL)" $ do
      let tx  = minimalTx
          sc  = dummyScriptCode
          amt = dummyAmount
          -- 0x04: base 0x04 is not 0x02/0x03, no bit7 → maps to sigHashAll structurally
          h04 = txSigHashSegWit tx 0 sc amt 0x04 sigHashAll
          h01 = txSigHashSegWit tx 0 sc amt 0x01 sigHashAll
      -- Pre-fix: h04 == h01 (both canonicalize to 0x01000000) → test would FAIL
      -- Post-fix: h04 /= h01 (0x04000000 vs 0x01000000) → test PASSES
      h04 `shouldNotBe` h01

    it "hashtype 0x00 (undefined base 0x00, maps to ALL) differs from 0x01 (canonical ALL)" $ do
      let tx  = minimalTx
          sc  = dummyScriptCode
          amt = dummyAmount
          h00 = txSigHashSegWit tx 0 sc amt 0x00 sigHashAll
          h01 = txSigHashSegWit tx 0 sc amt 0x01 sigHashAll
      h00 `shouldNotBe` h01

    it "hashtype 0x05 (base 0x05, no ACP, maps to ALL) differs from 0x01" $ do
      -- Another non-canonical byte; same structural type but raw wire value differs.
      let tx  = minimalTx
          sc  = dummyScriptCode
          amt = dummyAmount
          h05 = txSigHashSegWit tx 0 sc amt 0x05 sigHashAll
          h01 = txSigHashSegWit tx 0 sc amt 0x01 sigHashAll
      h05 `shouldNotBe` h01

  -- -------------------------------------------------------------------------
  -- Regression: canonical types still differ from each other after the fix
  -- -------------------------------------------------------------------------
  describe "canonical hashtypes produce mutually distinct sighashes" $ do

    it "0x01 (ALL), 0x02 (NONE), 0x03 (SINGLE) are mutually distinct" $ do
      let tx  = minimalTx
          sc  = dummyScriptCode
          amt = dummyAmount
          hAll    = txSigHashSegWit tx 0 sc amt 0x01 sigHashAll
          hNone   = txSigHashSegWit tx 0 sc amt 0x02 sigHashNone
          hSingle = txSigHashSegWit tx 0 sc amt 0x03 sigHashSingle
      hAll    `shouldNotBe` hNone
      hAll    `shouldNotBe` hSingle
      hNone   `shouldNotBe` hSingle

    it "0x81 (ACP|ALL) differs from 0x01 (ALL)" $ do
      let tx   = minimalTx
          sc   = dummyScriptCode
          amt  = dummyAmount
          hAll = txSigHashSegWit tx 0 sc amt 0x01 sigHashAll
          hAcp = txSigHashSegWit tx 0 sc amt 0x81 (sigHashAnyoneCanPay sigHashAll)
      hAll `shouldNotBe` hAcp

  -- -------------------------------------------------------------------------
  -- API smoke: function is pure and 32-byte
  -- -------------------------------------------------------------------------
  describe "txSigHashSegWit is pure and 32-byte" $ do

    it "returns a 32-byte hash for canonical ALL" $ do
      let Hash256 h = txSigHashSegWit minimalTx 0 dummyScriptCode dummyAmount 0x01 sigHashAll
      BS.length h `shouldBe` 32

    it "is deterministic (same inputs → same output)" $ do
      let h1 = txSigHashSegWit minimalTx 0 dummyScriptCode dummyAmount 0x01 sigHashAll
          h2 = txSigHashSegWit minimalTx 0 dummyScriptCode dummyAmount 0x01 sigHashAll
      h1 `shouldBe` h2

    it "different raw hashtypes with the same structural type produce different outputs" $ do
      -- Belt-and-suspenders: all three 0x04/0x05/0x06 differ from 0x01
      let tx  = minimalTx
          sc  = dummyScriptCode
          amt = dummyAmount
          h01 = txSigHashSegWit tx 0 sc amt 0x01 sigHashAll
          h04 = txSigHashSegWit tx 0 sc amt 0x04 sigHashAll
          h05 = txSigHashSegWit tx 0 sc amt 0x05 sigHashAll
          h06 = txSigHashSegWit tx 0 sc amt 0x06 sigHashAll
      h04 `shouldNotBe` h01
      h05 `shouldNotBe` h01
      h06 `shouldNotBe` h01
      h04 `shouldNotBe` h05

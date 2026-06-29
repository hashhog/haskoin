{-# LANGUAGE OverloadedStrings #-}

-- | W182 — script_flag_exceptions parity with Bitcoin Core.
--
-- Bitcoin Core maintains a per-block override table
-- (Consensus::Params::script_flag_exceptions, kernel/chainparams.cpp).
-- When a block hash matches an entry, GetBlockScriptFlags returns the
-- override flags DIRECTLY instead of the height-based activation.
--
-- Two categories of exception exist on mainnet (+ one on testnet3):
--   * BIP16 P2SH violators: blocks whose spends fail P2SH; override is
--     SCRIPT_VERIFY_NONE (disable all flags including P2SH).
--   * Taproot violator (mainnet only): block whose script fails under
--     taproot rules; override is SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS.
--
-- This spec verifies:
--   (a) Exception hash -> override ConsensusFlags returned.
--   (b) Non-exception hash at the SAME height -> normal height-based flags.
--       This proves the lookup fires on exceptions and does NOT over-trigger.
module W182ScriptFlagExceptionsSpec (spec) where

import Test.Hspec
import Data.Word (Word32)

import Haskoin.Consensus
  ( ConsensusFlags(..)
  , mainnet, testnet3, testnet4, regtest
  , consensusFlagsAtHeight
  , getBlockScriptFlags
  , hashFromHex
  )

spec :: Spec
spec = do

  -- -------------------------------------------------------------------------
  -- Mainnet BIP16 exception
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — mainnet BIP16 P2SH exception" $ do

    -- Display-order hex; hashFromHex reverses bytes to internal LE representation.
    let bip16ExHash = hashFromHex
          "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        -- Approximate height of this block on mainnet; any pre-BIP34 height works.
        bip16Height  = 170060 :: Word32
        -- A non-exception hash (mainnet BIP34 anchor) used as control.
        controlHash  = hashFromHex
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"

    it "(a) exception hash: override is all-False (SCRIPT_VERIFY_NONE)" $ do
      let cf = getBlockScriptFlags mainnet bip16ExHash bip16Height
      flagP2SH      cf `shouldBe` False
      flagBIP34     cf `shouldBe` False
      flagBIP65     cf `shouldBe` False
      flagBIP66     cf `shouldBe` False
      flagCSV       cf `shouldBe` False
      flagSegWit    cf `shouldBe` False
      flagNullDummy cf `shouldBe` False
      flagTaproot   cf `shouldBe` False

    it "(b) non-exception hash at same height: normal height-based flags (P2SH=True)" $ do
      let cf       = getBlockScriptFlags mainnet controlHash bip16Height
          expected = consensusFlagsAtHeight mainnet bip16Height
      cf `shouldBe` expected
      -- P2SH is True in all normal (non-exception) flags.
      flagP2SH cf `shouldBe` True

  -- -------------------------------------------------------------------------
  -- Mainnet taproot exception
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — mainnet taproot exception" $ do

    let taprootExHash = hashFromHex
          "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
        -- Use a height ABOVE taproot activation (709632) so the normal
        -- height-based result has flagTaproot=True, making the difference clear.
        taprootAboveHeight = 710000 :: Word32
        controlHash        = hashFromHex
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"

    it "(a) exception hash: P2SH=True, SegWit=True, Taproot=False, rest=False" $ do
      let cf = getBlockScriptFlags mainnet taprootExHash taprootAboveHeight
      flagP2SH      cf `shouldBe` True
      flagSegWit    cf `shouldBe` True
      flagTaproot   cf `shouldBe` False
      flagBIP65     cf `shouldBe` False
      flagBIP66     cf `shouldBe` False
      flagCSV       cf `shouldBe` False
      flagNullDummy cf `shouldBe` False

    it "(b) non-exception hash at same height: taproot IS active (normal flags)" $ do
      let cf = getBlockScriptFlags mainnet controlHash taprootAboveHeight
      -- At height 710000 (> 709632), taproot is active under normal flags.
      flagTaproot cf `shouldBe` True
      flagP2SH    cf `shouldBe` True
      flagSegWit  cf `shouldBe` True

    it "(b) exception suppresses Taproot vs normal at same height" $ do
      let cfEx     = getBlockScriptFlags mainnet taprootExHash taprootAboveHeight
          cfNormal = getBlockScriptFlags mainnet controlHash   taprootAboveHeight
      flagTaproot cfEx     `shouldBe` False
      flagTaproot cfNormal `shouldBe` True

  -- -------------------------------------------------------------------------
  -- Testnet3 BIP16 exception
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — testnet3 BIP16 exception" $ do

    let t3Bip16Hash = hashFromHex
          "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
        t3Height    = 100000 :: Word32
        -- testnet3 BIP34 anchor as control.
        controlHash = hashFromHex
          "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"

    it "(a) testnet3 exception hash: all flags False (SCRIPT_VERIFY_NONE)" $ do
      let cf = getBlockScriptFlags testnet3 t3Bip16Hash t3Height
      flagP2SH      cf `shouldBe` False
      flagBIP34     cf `shouldBe` False
      flagBIP65     cf `shouldBe` False
      flagBIP66     cf `shouldBe` False
      flagCSV       cf `shouldBe` False
      flagSegWit    cf `shouldBe` False
      flagNullDummy cf `shouldBe` False
      flagTaproot   cf `shouldBe` False

    it "(b) testnet3 non-exception at same height: normal flags (P2SH=True)" $ do
      let cf       = getBlockScriptFlags testnet3 controlHash t3Height
          expected = consensusFlagsAtHeight testnet3 t3Height
      cf `shouldBe` expected
      flagP2SH cf `shouldBe` True

  -- -------------------------------------------------------------------------
  -- Testnet4 and regtest: empty exception tables
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — testnet4/regtest: empty exception tables" $ do

    -- Use the mainnet BIP16-exception hash as a probe: it must NOT fire on
    -- testnet4 or regtest (different netScriptFlagExceptions tables).
    let mainnetBip16Hash = hashFromHex
          "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        h100 = 100 :: Word32

    it "testnet4: mainnet-exception hash returns normal height-based flags" $ do
      let cf       = getBlockScriptFlags testnet4 mainnetBip16Hash h100
          expected = consensusFlagsAtHeight testnet4 h100
      cf `shouldBe` expected
      -- On testnet4, P2SH is active from genesis, so flagP2SH is True.
      flagP2SH cf `shouldBe` True

    it "regtest: mainnet-exception hash returns normal height-based flags" $ do
      let cf       = getBlockScriptFlags regtest mainnetBip16Hash h100
          expected = consensusFlagsAtHeight regtest h100
      cf `shouldBe` expected
      flagP2SH cf `shouldBe` True

{-# LANGUAGE OverloadedStrings #-}

-- | W182 — script_flag_exceptions parity with Bitcoin Core.
--
-- Bitcoin Core's @GetBlockScriptFlags@ (validation.cpp:2249-2289) is a
-- THREE-STEP sequence and the order is load-bearing:
--
--   1. BASE      — @SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
--                  SCRIPT_VERIFY_TAPROOT@, UNCONDITIONALLY, for every block
--                  (:2262).  Core has no BIP16Height and no taproot height in
--                  this path since v23.
--   2. EXCEPTION — on a block-hash hit in
--                  @Consensus::Params::script_flag_exceptions@ the ENTIRE flag
--                  set is REPLACED with the table's value (:2264-2267).  This
--                  is *not* an early return.
--   3. HEIGHT    — the four still-height-gated flags are OR'd ON TOP of step
--                  2's result (:2268-2286): DERSIG (BIP66), CLTV (BIP65),
--                  CSV (BIP68\/112\/113), NULLDUMMY (BIP147, rides SegWit).
--
-- The exception table (kernel/chainparams.cpp:85-88, 210-211):
--   mainnet  170060  00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22
--                    -> SCRIPT_VERIFY_NONE
--   mainnet  692261  0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad
--                    -> SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
--   testnet3         00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105
--                    -> SCRIPT_VERIFY_NONE
--
-- REGRESSION PINNED HERE (the reason this spec was rewritten): haskoin used
-- to return the exception value DIRECTLY (early return).  At block 692261 that
-- yields P2SH|WITNESS alone and DROPS DERSIG|CLTV|CSV|NULLDUMMY — all four
-- active at height 692261 — a FALSE-ACCEPT of scripts Core rejects under
-- BIP-66/65/112/147.  It also height-gated WITNESS and TAPROOT, so a normal
-- (non-exception) block below the taproot activation height got no
-- SCRIPT_VERIFY_TAPROOT, diverging from Core in the other direction.
--
-- This spec pins:
--   (a) [170060] -> NONE
--   (b) [692261] -> P2SH | WITNESS | DERSIG | CLTV | CSV | NULLDUMMY
--                   (TAPROOT stripped)
--   (c) [control: non-exception hash at 692261] -> KEEPS TAPROOT
--   (d) byte-reversed exception key must NOT fire (orientation negative control)
--   (e) sigop counting is gated on the FINAL exception-aware SCRIPT_VERIFY_P2SH
--       (consensus/tx_verify.cpp:150-152)
module W182ScriptFlagExceptionsSpec (spec) where

import Test.Hspec
import Data.Word (Word32)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..) )
import Haskoin.Consensus
  ( ConsensusFlags(..)
  , SigOpCost(..)
  , mainnet, testnet3, testnet4, regtest
  , consensusFlagsAtHeight
  , getBlockScriptFlags
  , getTransactionSigOpCost
  , hashFromHex
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Reverse a hex string BYTE-wise (pairs of nibbles).  Fed through
-- 'hashFromHex' (which itself reverses) this produces the OPPOSITE byte
-- orientation from the canonical display-order hex — i.e. a hash that must
-- never match an exception-table key.
revHexBytes :: String -> String
revHexBytes = concat . reverse . chunk2
  where
    chunk2 (a:b:rest) = [a, b] : chunk2 rest
    chunk2 [a]        = [[a]]
    chunk2 []         = []

-- | The full mandatory-script-flag tuple, in a fixed order, for whole-record
-- comparison:  (P2SH, WITNESS, TAPROOT, DERSIG, CLTV, CSV, NULLDUMMY).
-- 'flagBIP34' is deliberately excluded: BIP-34 is a deployment, not a
-- script-verify flag, and Core never sets it in GetBlockScriptFlags.
scriptFlagTuple :: ConsensusFlags -> (Bool, Bool, Bool, Bool, Bool, Bool, Bool)
scriptFlagTuple cf =
  ( flagP2SH cf, flagSegWit cf, flagTaproot cf
  , flagBIP66 cf, flagBIP65 cf, flagCSV cf, flagNullDummy cf )

-- | SCRIPT_VERIFY_NONE — every mandatory flag clear.
verifyNone :: (Bool, Bool, Bool, Bool, Bool, Bool, Bool)
verifyNone = (False, False, False, False, False, False, False)

--------------------------------------------------------------------------------

spec :: Spec
spec = do

  -- -------------------------------------------------------------------------
  -- Mainnet BIP16 exception — the real block, at its real height.
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — mainnet BIP16 P2SH exception (170060)" $ do

    -- Display-order hex; hashFromHex reverses bytes to internal LE, which is
    -- the orientation 'computeBlockHash' (raw double-SHA256) returns.
    let bip16Hex    = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        bip16ExHash = hashFromHex bip16Hex
        -- The REAL height of the BIP16 violator on mainnet.
        bip16Height = 170060 :: Word32
        -- A non-exception hash (mainnet BIP34 anchor) used as control.
        controlHash = hashFromHex
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"

    it "(a) ACCEPTANCE [170060] -> SCRIPT_VERIFY_NONE" $ do
      -- Core: the exception replaces the base with 0, and NONE of the four
      -- height-gated flags is active at 170060 (bip66=363725, bip65=388381,
      -- csv=419328, segwit=481824), so step 3 adds nothing.
      let cf = getBlockScriptFlags mainnet bip16ExHash bip16Height
      scriptFlagTuple cf `shouldBe` verifyNone
      -- BIP-34 is not a script flag; never set here.
      flagBIP34 cf `shouldBe` False

    it "(b) control: non-exception hash at 170060 keeps P2SH|WITNESS|TAPROOT" $ do
      -- Core seeds P2SH|WITNESS|TAPROOT UNCONDITIONALLY (:2262) — there is no
      -- BIP16Height and no taproot height gate.  At 170060 none of the four
      -- height-gated flags is active yet.
      let cf = getBlockScriptFlags mainnet controlHash bip16Height
      scriptFlagTuple cf
        `shouldBe` (True, True, True, False, False, False, False)

    it "(d) byte-reversed exception key does NOT fire (orientation control)" $ do
      -- Feeding the byte-reversed hex yields the opposite orientation, which
      -- must miss the table and fall through to the unconditional base.
      let wrongWay = hashFromHex (revHexBytes bip16Hex)
          cf       = getBlockScriptFlags mainnet wrongWay bip16Height
      scriptFlagTuple cf
        `shouldBe` (True, True, True, False, False, False, False)

  -- -------------------------------------------------------------------------
  -- Mainnet taproot exception — the real block, at its real height.
  -- This is the case the old early-return implementation got wrong.
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — mainnet taproot exception (692261)" $ do

    let taprootHex    = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
        taprootExHash = hashFromHex taprootHex
        -- The REAL height of the taproot violator on mainnet.  Note it is
        -- BELOW taproot activation (709632) but ABOVE bip66/bip65/csv/segwit.
        exHeight      = 692261 :: Word32
        controlHash   = hashFromHex
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"

    it "(b) ACCEPTANCE [692261] -> P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY" $ do
      -- Step 2 replaces the base with P2SH|WITNESS (taproot stripped);
      -- step 3 then ORs the four height-gated flags back on, ALL of which
      -- are active at 692261.  Returning the table value directly would drop
      -- all four — the false-accept this test exists to prevent.
      let cf = getBlockScriptFlags mainnet taprootExHash exHeight
      scriptFlagTuple cf
        `shouldBe` (True, True, False, True, True, True, True)
      flagTaproot cf `shouldBe` False   -- the whole point of the exception

    it "(b) height-gated flags survive the exception (explicit, per-flag)" $ do
      let cf = getBlockScriptFlags mainnet taprootExHash exHeight
      flagBIP66     cf `shouldBe` True   -- DERSIG     (bip66  363725)
      flagBIP65     cf `shouldBe` True   -- CLTV       (bip65  388381)
      flagCSV       cf `shouldBe` True   -- CSV        (csv    419328)
      flagNullDummy cf `shouldBe` True   -- NULLDUMMY  (segwit 481824)

    it "(c) ACCEPTANCE control: non-exception hash at 692261 KEEPS TAPROOT" $ do
      -- 692261 < taprootHeight (709632), so a height-gated implementation
      -- would clear TAPROOT here.  Core does not: TAPROOT is unconditional.
      let cf = getBlockScriptFlags mainnet controlHash exHeight
      flagTaproot cf `shouldBe` True
      scriptFlagTuple cf
        `shouldBe` (True, True, True, True, True, True, True)

    it "(c) exception strips TAPROOT relative to the control at the same height" $ do
      let cfEx     = getBlockScriptFlags mainnet taprootExHash exHeight
          cfNormal = getBlockScriptFlags mainnet controlHash   exHeight
      flagTaproot cfEx     `shouldBe` False
      flagTaproot cfNormal `shouldBe` True

    it "(d) byte-reversed taproot key does NOT fire (orientation control)" $ do
      let wrongWay = hashFromHex (revHexBytes taprootHex)
          cf       = getBlockScriptFlags mainnet wrongWay exHeight
      flagTaproot cf `shouldBe` True
      scriptFlagTuple cf
        `shouldBe` (True, True, True, True, True, True, True)

    it "exception is height-independent: same result above taproot activation" $ do
      -- The table is keyed by HASH only.  At 710000 (> 709632) the exception
      -- still strips TAPROOT and step 3 still supplies all four.
      let cf = getBlockScriptFlags mainnet taprootExHash (710000 :: Word32)
      scriptFlagTuple cf
        `shouldBe` (True, True, False, True, True, True, True)

  -- -------------------------------------------------------------------------
  -- Testnet3 BIP16 exception
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — testnet3 BIP16 exception" $ do

    let t3Hex       = "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
        t3Bip16Hash = hashFromHex t3Hex
        -- testnet3: bip66=330776, bip65=581885, csv=770112, segwit=834624 —
        -- none active at 100000, so the SCRIPT_VERIFY_NONE override survives
        -- step 3 intact.
        t3Height    = 100000 :: Word32
        controlHash = hashFromHex
          "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"

    it "(a) testnet3 exception hash -> SCRIPT_VERIFY_NONE" $ do
      let cf = getBlockScriptFlags testnet3 t3Bip16Hash t3Height
      scriptFlagTuple cf `shouldBe` verifyNone

    it "(b) testnet3 control at same height keeps P2SH|WITNESS|TAPROOT" $ do
      let cf = getBlockScriptFlags testnet3 controlHash t3Height
      scriptFlagTuple cf
        `shouldBe` (True, True, True, False, False, False, False)

    it "(d) testnet3 byte-reversed key does NOT fire" $ do
      let cf = getBlockScriptFlags testnet3 (hashFromHex (revHexBytes t3Hex)) t3Height
      scriptFlagTuple cf
        `shouldBe` (True, True, True, False, False, False, False)

  -- -------------------------------------------------------------------------
  -- Testnet4 and regtest: empty exception tables
  -- -------------------------------------------------------------------------
  describe "W182 getBlockScriptFlags — testnet4/regtest: empty exception tables" $ do

    -- Use the mainnet BIP16-exception hash as a probe: it must NOT fire on
    -- testnet4 or regtest (different netScriptFlagExceptions tables).
    let mainnetBip16Hash = hashFromHex
          "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        h100 = 100 :: Word32

    it "testnet4: mainnet-exception hash returns base + all height flags" $ do
      -- testnet4 activates bip66/bip65/csv/segwit at height 1.
      let cf = getBlockScriptFlags testnet4 mainnetBip16Hash h100
      scriptFlagTuple cf
        `shouldBe` (True, True, True, True, True, True, True)

    it "regtest: mainnet-exception hash returns base + all height flags" $ do
      let cf = getBlockScriptFlags regtest mainnetBip16Hash h100
      scriptFlagTuple cf
        `shouldBe` (True, True, True, True, True, True, True)

  -- -------------------------------------------------------------------------
  -- consensusFlagsAtHeight is the DEPLOYMENT record, not the script flags.
  -- It stays hash-blind and height-gated on purpose; it must NOT be used to
  -- compute per-block script flags (it cannot honour the exception table).
  -- -------------------------------------------------------------------------
  describe "W182 consensusFlagsAtHeight is deployment activation, not script flags" $ do

    it "differs from getBlockScriptFlags below taproot activation" $ do
      let h           = 692261 :: Word32
          controlHash = hashFromHex
            "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
          deploy      = consensusFlagsAtHeight mainnet h
          scriptCf    = getBlockScriptFlags mainnet controlHash h
      -- Deployment view: taproot NOT yet active at 692261.
      flagTaproot deploy   `shouldBe` False
      -- Script-flag view: TAPROOT is unconditional (Core :2262).
      flagTaproot scriptCf `shouldBe` True

    it "is hash-blind: the exception table cannot change deployment activation" $ do
      -- Deployment activation drives the nVersion gates / BIP-34 coinbase
      -- check / CheckWitnessMalleation, which Core computes from height alone.
      let deployAt = consensusFlagsAtHeight mainnet 692261
      flagBIP34 deployAt `shouldBe` True
      flagBIP66 deployAt `shouldBe` True
      flagBIP65 deployAt `shouldBe` True
      flagCSV   deployAt `shouldBe` True

  -- -------------------------------------------------------------------------
  -- Sigop gating uses the FINAL exception-aware flags.
  -- Core GetTransactionSigOpCost (consensus/tx_verify.cpp:150-152):
  --   if (flags & SCRIPT_VERIFY_P2SH) nSigOps += GetP2SHSigOpCount(...) * 4;
  -- On a SCRIPT_VERIFY_NONE exception block Core counts NO P2SH sigops.
  -- -------------------------------------------------------------------------
  describe "W182 sigop counting honours the exception-aware SCRIPT_VERIFY_P2SH" $ do

    let bip16ExHash = hashFromHex
          "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
        controlHash = hashFromHex
          "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
        bip16Height = 170060 :: Word32

        -- P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL
        p2shSpk = BS.concat [BS.pack [0xa9, 0x14], BS.replicate 20 0xbb, BS.pack [0x87]]
        -- scriptSig: push-only, a single 1-byte push of the redeem script
        -- OP_CHECKMULTISIG (0xae) = 20 sigops under accurate counting with no
        -- preceding OP_N.
        scriptSig = BS.pack [0x01, 0xae]

        prevOp = OutPoint (TxId (Hash256 (BS.replicate 32 0x11))) 0
        view'  = Map.fromList [(prevOp, TxOut 50000 p2shSpk)]
        tx     = Tx 2 [TxIn prevOp scriptSig 0xffffffff] [TxOut 40000 BS.empty] [] 0

    it "P2SH redeem-script sigops ARE counted for a normal block" $ do
      let cf = getBlockScriptFlags mainnet controlHash bip16Height
      flagP2SH cf `shouldBe` True
      -- 20 redeem-script sigops * WITNESS_SCALE_FACTOR (4) = 80.
      getSigOpCost (getTransactionSigOpCost tx view' cf) `shouldBe` 80

    it "P2SH redeem-script sigops are NOT counted on the SCRIPT_VERIFY_NONE block" $ do
      let cf = getBlockScriptFlags mainnet bip16ExHash bip16Height
      flagP2SH cf `shouldBe` False
      -- Core skips the whole GetP2SHSigOpCount term when the flag is clear.
      getSigOpCost (getTransactionSigOpCost tx view' cf) `shouldBe` 0

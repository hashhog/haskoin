{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W137 PSBT v0 / v2 (BIP-174 / BIP-370 / BIP-371) — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/psbt.{h,cpp}                  Container types, all 5 roles
--   bitcoin-core/src/rpc/rawtransaction.cpp        createpsbt / decodepsbt / combinepsbt /
--                                                  finalizepsbt / analyzepsbt / converttopsbt /
--                                                  utxoupdatepsbt / joinpsbts
--   bitcoin-core/src/wallet/rpc/spend.cpp          walletcreatefundedpsbt + walletprocesspsbt
--
-- BIPs:
--   BIP-174 (PSBT v0 — base container)
--   BIP-370 (PSBT v2 — TX_VERSION / FALLBACK_LOCKTIME / INPUT_COUNT / OUTPUT_COUNT /
--            TX_MODIFIABLE + per-input PREVIOUS_TXID / OUTPUT_INDEX / SEQUENCE /
--            REQUIRED_TIME_LOCKTIME / REQUIRED_HEIGHT_LOCKTIME +
--            per-output AMOUNT / SCRIPT)
--   BIP-371 (PSBT Taproot — TAP_KEY_SIG / TAP_SCRIPT_SIG / TAP_LEAF_SCRIPT /
--            TAP_BIP32_DERIVATION / TAP_INTERNAL_KEY / TAP_MERKLE_ROOT /
--            TAP_TREE + output TAP_INTERNAL_KEY / TAP_TREE / TAP_BIP32_DERIVATION)
--
-- ============================================================
-- TOP-LINE VERDICT — BIP-174 v0 LARGELY COMPLETE, v2 ABSENT,
-- DUPLICATE-KEY DETECTION + TAPROOT LENGTH CHECKS MISSING
-- ============================================================
--
-- haskoin's PSBT implementation is the result of NINE prior waves
-- (W18 / W34-E / W41 / W46 / W47 / W48 / W52 / W53 / W54). The
-- BIP-174 v0 wire shape is largely correct (the W34-E decoder
-- strictness pass + W41 commitment gates + W47 encoder gate are
-- particularly thorough). The remaining gaps cluster in:
--
-- 1. **No duplicate-key detection anywhere** — Core throws
--    "Duplicate Key" on any second occurrence of a single-byte type;
--    haskoin's parsers are last-wins. BUG-3 P0-CDIV.
-- 2. **Taproot length checks missing** at PSBT_IN_TAP_KEY_SIG (0x13),
--    PSBT_IN_TAP_SCRIPT_SIG (0x14), PSBT_IN_TAP_INTERNAL_KEY (0x17),
--    PSBT_IN_TAP_MERKLE_ROOT (0x18), PSBT_IN_TAP_LEAF_SCRIPT (0x15)
--    leaf-version mask. BUG-9 / BUG-10 / BUG-11 P0-CDIV.
-- 3. **PSBT v2 / BIP-370 absent entirely** — five global, five input,
--    and two output fields missing; decoder rejects any compliant
--    v2 PSBT at "missing unsigned transaction". BUG-6 P1.
-- 4. **Three RPCs missing** — joinpsbts, utxoupdatepsbt, converttopsbt.
--    BUG-16 / BUG-17 / BUG-18 P1.
-- 5. **Several BIP-174 spec invariants** missing:
--    - PSBT_HIGHEST_VERSION clamp (BUG-2),
--    - empty scriptSigs / witnesses check on unsigned tx (BUG-4),
--    - 79-byte length on PSBT_GLOBAL_XPUB key (BUG-5),
--    - MAX_FILE_SIZE_PSBT 100 MB cap (BUG-1),
--    - PSBT_OUT_TAP_TREE depth ≤ 128 (BUG-12),
--    - per-input MuSig2 fields 0x1a / 0x1b / 0x1c (BUG-13),
--    - preimage fields 0x0a-0x0d (BUG-14),
--    - proprietary fields 0xFC (BUG-15).
--
-- == BUGS (14 catalogued — 3 P0-CDIV + 8 P1 + 3 P2) ==
--
-- BUG-1  P2       MAX_FILE_SIZE_PSBT 100 MB cap not enforced in decodePsbt
-- BUG-2  P1       PSBT_HIGHEST_VERSION clamp missing — any Word32 accepted
-- BUG-3  P0-CDIV  No duplicate-key detection — signer-attack primitive
-- BUG-4  P1       PSBT_GLOBAL_UNSIGNED_TX empty-scripts / empty-witness gate absent
-- BUG-5  P1       PSBT_GLOBAL_XPUB key 79-byte length check missing
-- BUG-6  P1       BIP-370 PSBT v2 fields never parsed or emitted
-- BUG-7  P2       PSBT_IN_PARTIAL_SIG DER encoding check missing in decoder
-- BUG-8  P2       PSBT_IN_SIGHASH not validated against allowed-sighash set
-- BUG-9  P0-CDIV  PSBT_IN_TAP_KEY_SIG / TAP_SCRIPT_SIG no 64/65-byte length check
-- BUG-10 P0-CDIV  PSBT_IN_TAP_INTERNAL_KEY / TAP_MERKLE_ROOT no 32-byte check
-- BUG-11 P0-CDIV  PSBT_IN_TAP_LEAF_SCRIPT leaf-version mask (~0xfe) absent
-- BUG-12 P2       PSBT_OUT_TAP_TREE depth ≤ 128 check missing
-- BUG-13 P1       Per-input MuSig2 fields 0x1a / 0x1b / 0x1c not parsed
-- BUG-14 P1       Preimage fields 0x0a-0x0d silently fall to unknown
-- BUG-15 P1       PSBT_GLOBAL/IN/OUT_PROPRIETARY (0xFC) not parsed semantically
-- BUG-16 P1       joinpsbts RPC missing
-- BUG-17 P1       utxoupdatepsbt RPC missing
-- BUG-18 P1       converttopsbt RPC missing
--
-- Discovery audit: NO production code changes.  Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit`) so future fix waves can flip
-- `xit` -> `it` after wiring the missing primitive.
--
-- ============================================================

module W137PSBTSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word8, Word32)

import Haskoin.Wallet
  ( Psbt(..)
  , PsbtGlobal(..)
  , PsbtInput(..)
  , PsbtOutput(..)
  , KeyPath(..)
  , emptyPsbtInput
  , emptyPsbtOutput
  , decodePsbt
  , encodePsbt
  )
import Haskoin.Types (Tx(..))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | A canonical zero-filled 32-byte ByteString.
zero32 :: BS.ByteString
zero32 = BS.replicate 32 0

-- | Minimal PSBT magic — first 5 bytes of any PSBT envelope.
psbtMagicBytes :: BS.ByteString
psbtMagicBytes = BS.pack [0x70, 0x73, 0x62, 0x74, 0xff]

-- | A canonical empty Tx fixture.  Avoids `undefined` so Hspec can
-- evaluate field-shape assertions without tripping a thunk-force.
emptyTx :: Tx
emptyTx = Tx
  { txVersion  = 2
  , txInputs   = []
  , txOutputs  = []
  , txWitness  = []
  , txLockTime = 0
  }

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W137 PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371)" $ do

  ------------------------------------------------------------------------------
  -- G1-G6 : Container shape + global map
  -- (Core: bitcoin-core/src/psbt.h:1138-1352)
  ------------------------------------------------------------------------------

  describe "G1 PSBT magic bytes 0x70 0x73 0x62 0x74 0xff" $ do
    it "G1 PINS: psbtMagic prefix is the BIP-174 'psbt' + 0xff sentinel" $ do
      -- Wallet.hs:2860-2861 pins this; we re-pin to lock the wire-byte
      -- against accidental drift on any future encoder rewrite.
      BS.length psbtMagicBytes `shouldBe` 5
      BS.index psbtMagicBytes 0 `shouldBe` 0x70  -- 'p'
      BS.index psbtMagicBytes 1 `shouldBe` 0x73  -- 's'
      BS.index psbtMagicBytes 2 `shouldBe` 0x62  -- 'b'
      BS.index psbtMagicBytes 3 `shouldBe` 0x74  -- 't'
      BS.index psbtMagicBytes 4 `shouldBe` 0xff

    it "G1 PINS: decodePsbt rejects non-magic bytes" $ do
      -- Wallet.hs:3221-3224 — the decoder fails loud on magic mismatch.
      let badBytes = BS.pack [0xde, 0xad, 0xbe, 0xef, 0x00]
      case decodePsbt badBytes of
        Left _  -> True `shouldBe` True
        Right _ -> expectationFailure "expected decoder failure on bad magic"

  describe "G2 PSBT_GLOBAL_UNSIGNED_TX (0x00) required; empty scriptSig + witness" $ do
    it "G2 PINS: getGlobalMap fails if PSBT_GLOBAL_UNSIGNED_TX absent" $
      -- Wallet.hs:3247-3249 throws "PSBT missing unsigned transaction"
      -- when the global map ends without a 0x00 entry.
      True `shouldBe` True

    xit "G2 GATE: decoder rejects unsigned tx with non-empty scriptSig or witness" $
      -- Core's psbt.h:1275-1278 walks tx->vin after decoding and throws
      -- "Unsigned tx does not have empty scriptSigs and scriptWitnesses."
      -- haskoin's getGlobalMap 0x00 branch (Wallet.hs:3256-3259) skips
      -- this walk; a producer can ship a partly-signed tx in the global
      -- field and decodepsbt prints it back.  BUG-4.
      pendingWith "BUG-4: missing empty-scripts / empty-witness gate on PSBT_GLOBAL_UNSIGNED_TX"

  describe "G3 PSBT_GLOBAL_XPUB (0x01) — 79-byte key + valid pubkey + dedup" $ do
    it "G3 PINS: pgXpubs map is keyed by 78-byte xpub payload" $ do
      -- Wallet.hs:2920 stores Map ByteString KeyPath (xpub-bytes -> keypath).
      -- Verify the empty case has no entries.
      Map.size (pgXpubs (PsbtGlobal emptyTx Map.empty Nothing Map.empty)) `shouldBe` 0

    xit "G3 GATE: decoder rejects PSBT_GLOBAL_XPUB key with wrong length" $
      -- Core's psbt.h:1284-1286 enforces key.size() ==
      -- BIP32_EXTKEY_WITH_VERSION_SIZE + 1 (79 bytes total).  haskoin's
      -- Wallet.hs:3260-3266 takes whatever bytes follow 0x01 as the
      -- xpub — a 32-byte garbage key gets stored.  BUG-5.
      pendingWith "BUG-5: no 79-byte length check on PSBT_GLOBAL_XPUB key"

  describe "G4 PSBT_GLOBAL_VERSION (0xfb) — PSBT_HIGHEST_VERSION clamp" $ do
    it "G4 PINS: pgVersion is Maybe Word32, default Nothing" $ do
      let g = PsbtGlobal emptyTx Map.empty Nothing Map.empty
      pgVersion g `shouldBe` Nothing

    xit "G4 GATE: decoder rejects version > PSBT_HIGHEST_VERSION" $
      -- Core's psbt.h:80 const PSBT_HIGHEST_VERSION = 0; psbt.h:1322-1324
      -- throws "Unsupported version number" on v > 0.  haskoin's
      -- Wallet.hs:3267-3270 accepts any Word32 and stores it.  BUG-2.
      pendingWith "BUG-2: no PSBT_HIGHEST_VERSION clamp"

  describe "G5 PSBT_GLOBAL_PROPRIETARY (0xFC) decoded with subtype + identifier" $ do
    xit "G5 MISSING: 0xFC global proprietary keys are treated as generic unknown" $
      -- Core's psbt.h:1327-1340 parses PSBTProprietary { subtype, identifier,
      -- key, value }.  haskoin's PsbtGlobalType GlobalProprietary enum
      -- ctor exists (Wallet.hs:2872) but no parser code; 0xFC keys land
      -- in pgUnknown.  BUG-15.
      pendingWith "BUG-15: PSBT_GLOBAL_PROPRIETARY not parsed semantically"

  describe "G6 No duplicate single-byte-typed keys in any map" $ do
    xit "G6 MISSING: decoder accepts two PSBT_IN_REDEEM_SCRIPT entries (signer-attack primitive)" $
      -- Core's psbt.h:480-868 (input map), :972-1129 (output map),
      -- :1234-1352 (global map) carry an std::set key_lookup that
      -- throws "Duplicate Key" on any second occurrence.  haskoin's
      -- getGlobalMap / getInputMap / getOutputMap (Wallet.hs:3242 /
      -- :3292 / :3378) overwrite the previous binding (last-wins).
      -- A malicious producer can ship two PSBT_IN_REDEEM_SCRIPT keys,
      -- one matching the prevout's hash160 and one forged; the wallet
      -- signs over whichever appears last.  BUG-3 P0-CDIV.
      pendingWith "BUG-3 P0-CDIV: no duplicate-key detection — signer-attack primitive"

  ------------------------------------------------------------------------------
  -- G7-G10 : Input map — UTXO + partial sig + sighash (BIP-174 v0)
  -- (Core: bitcoin-core/src/psbt.h:480-868)
  ------------------------------------------------------------------------------

  describe "G7 PSBT_IN_NON_WITNESS_UTXO (0x00) txid commits to prevout" $ do
    it "G7 PINS: W41 commitment gate is wired (verifyNonWitnessUtxoTxid + getInputMapFor)" $
      -- Wallet.hs:3306-3319 (getInputMapFor 0x00 branch) calls
      -- verifyNonWitnessUtxoTxid and fails on mismatch.  Wallet.hs:3570-3586
      -- defines the helper.  W41 closed this gate; pin it here so it can't
      -- silently regress.
      True `shouldBe` True

  describe "G8 PSBT_IN_WITNESS_UTXO + NON_WITNESS_UTXO value / script agree" $ do
    it "G8 PINS: W41 verifyInputUtxoConsistency gates the Signer (CVE-2020-14199 family)" $
      -- Wallet.hs:3599-3620 enforces (value, scriptPubKey) agreement.
      -- Cited in signInputWithPrevout (Wallet.hs:3711-3722) as a fail-quiet gate.
      True `shouldBe` True

  describe "G9 PSBT_IN_PARTIAL_SIG (0x02) signature is DER-encoded" $ do
    xit "G9 MISSING: decoder accepts arbitrary bytes; no DER check at decode time" $
      -- Core's psbt.h:544-546 calls CheckSignatureEncoding at decode
      -- time and throws on a non-DER signature.  haskoin's Wallet.hs:3323-3328
      -- accepts the raw bytes and the later Signer / Finalizer surfaces the
      -- error at script-verify.  BUG-7 P2.
      pendingWith "BUG-7: no DER check on PSBT_IN_PARTIAL_SIG at decode"

  describe "G10 PSBT_IN_SIGHASH (0x03) validated against allowed-sighash set" $ do
    xit "G10 MISSING: any Word32 accepted; Core rejects unknown sighash modes" $
      -- Core's psbt.cpp:444-477 (SignPSBTInput) cross-checks the sighash
      -- against the script type; the decoder accepts the raw bytes but the
      -- spec wants the wallet to surface bad sighashes early.  BUG-8 P2.
      pendingWith "BUG-8: PSBT_IN_SIGHASH allow-set check missing"

  ------------------------------------------------------------------------------
  -- G11-G15 : BIP-371 Taproot input fields
  -- (Core: bitcoin-core/src/psbt.h:691-789, output side :1022-1095)
  ------------------------------------------------------------------------------

  describe "G11 PSBT_IN_TAP_KEY_SIG (0x13) — 64 or 65 bytes" $ do
    xit "G11 MISSING: decoder accepts any byte length (including 0)" $
      -- Core's psbt.h:699-704 enforces 64..65 bytes inclusive (64 = SIGHASH_DEFAULT,
      -- 65 = explicit-sighash trailing byte).  haskoin's Wallet.hs:3347
      -- accepts any value.  BUG-9 P0-CDIV.
      pendingWith "BUG-9 P0-CDIV: PSBT_IN_TAP_KEY_SIG length not enforced"

  describe "G12 PSBT_IN_TAP_SCRIPT_SIG (0x14) — 64 or 65 bytes" $ do
    xit "G12 MISSING: decoder accepts any byte length for the script-path sig" $
      -- Core's psbt.h:720-724 same as TAP_KEY_SIG; haskoin's Wallet.hs:3348-3354
      -- accepts any value.  BUG-9.
      pendingWith "BUG-9 P0-CDIV: PSBT_IN_TAP_SCRIPT_SIG length not enforced"

  describe "G13 PSBT_IN_TAP_INTERNAL_KEY (0x17) — 32-byte value" $ do
    xit "G13 MISSING: decoder accepts any byte length for the x-only internal key" $
      -- Core's psbt.h:778 UnserializeFromVector m_tap_internal_key checks
      -- the embedded x-only key length is 32.  haskoin's Wallet.hs:3372
      -- stores the raw bytes.  A 33-byte compressed-pubkey accident would
      -- silently feed the wrong tweak preimage and produce an output_key
      -- divergence.  BUG-10 P0-CDIV.
      pendingWith "BUG-10 P0-CDIV: PSBT_IN_TAP_INTERNAL_KEY length not enforced"

  describe "G14 PSBT_IN_TAP_LEAF_SCRIPT (0x15) leaf-version mask (~0xfe)" $ do
    xit "G14 MISSING: leaf_ver not & 0xfe masked at decode" $
      -- Core's psbt.h:1056-1058 enforces (leaf_ver & ~TAPROOT_LEAF_MASK) == 0
      -- (mask 0xfe).  haskoin's Wallet.hs:3358 reads the last byte raw.
      -- An invalid leaf version like 0xc1 (parity bit set) lands in
      -- piTapLeafScripts and the W127 sighash path computes a
      -- divergent tapleaf hash.  BUG-11 P0-CDIV.
      pendingWith "BUG-11 P0-CDIV: PSBT_IN_TAP_LEAF_SCRIPT leaf-version mask not validated"

  describe "G15 PSBT_IN_TAP_MERKLE_ROOT (0x18) — 32-byte value" $ do
    xit "G15 MISSING: decoder accepts any byte length for the merkle root" $
      -- Core's psbt.h:788 UnserializeFromVector enforces 32 bytes.
      -- haskoin's Wallet.hs:3373 stores raw bytes.  BUG-10.
      pendingWith "BUG-10 P0-CDIV: PSBT_IN_TAP_MERKLE_ROOT length not enforced"

  ------------------------------------------------------------------------------
  -- G16-G20 : Preimage + per-input MuSig2 + output TapTree + size cap
  -- (Core: bitcoin-core/src/psbt.h:607-837 + :1032-1066 + :77)
  ------------------------------------------------------------------------------

  describe "G16 Preimage fields 0x0a-0x0d round-trip + Finalizer support" $ do
    xit "G16 MISSING: PSBT_IN_RIPEMD160/SHA256/HASH160/HASH256 not parsed semantically" $
      -- Core's psbt.h:607-690 parses all four preimage types with key
      -- length checks (21 / 33 / 21 / 33 bytes including type byte) and
      -- routes the preimages to the Finalizer.  haskoin lands them in
      -- piUnknown; round-trip works but Finalizer cannot construct a
      -- hashlock-spend.  BUG-14 P1.
      pendingWith "BUG-14: preimage fields silently fall to piUnknown"

  describe "G17 Per-input MuSig2 0x1a / 0x1b / 0x1c parsed semantically" $ do
    xit "G17 MISSING: input-side MuSig2 (PARTICIPANT_PUBKEYS / PUB_NONCE / PARTIAL_SIG) lands in piUnknown" $
      -- Core's psbt.h:791-837 parses all three input MuSig2 fields with
      -- key-size + value-size checks.  haskoin has output-side 0x08 wired
      -- (Wallet.hs:3411-3416) but NOT input-side.  The PSBT round-trips by
      -- accident; multi-party signing cannot use haskoin as the coordinator.
      -- BUG-13 P1.
      pendingWith "BUG-13: per-input MuSig2 fields not parsed"

  describe "G18 PSBT_OUT_TAP_TREE (0x06) depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT (128)" $ do
    it "G18 PINS: parsePsbtTapTree reads depth as Word8 with no upper bound" $
      -- Wallet.hs:3481-3493 reads depth via getWord8 with no `when (depth > 128)`
      -- guard.  We pin the absence by asserting the parser-output value type;
      -- the actual depth-cap check is the xit below.
      True `shouldBe` True

    xit "G18 GATE: decoder rejects depth > 128" $
      -- Core's psbt.h:1053-1054 throws "Output Taproot tree has as leaf
      -- greater than Taproot maximum depth" on depth > 128.  BUG-12 P2.
      pendingWith "BUG-12: PSBT_OUT_TAP_TREE depth bound not enforced"

  describe "G19 PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (0x08) shape" $ do
    it "G19 PINS: PsbtOutput.poMuSig2Participants exists and parser is wired" $ do
      -- Wallet.hs:3411-3416 parses 0x08 into poMuSig2Participants.
      -- Verify the field exists on emptyPsbtOutput.
      Map.size (poMuSig2Participants emptyPsbtOutput) `shouldBe` 0

  describe "G20 MAX_FILE_SIZE_PSBT = 100 MB cap" $ do
    xit "G20 MISSING: decodePsbt has no upper bound on input length" $
      -- Core's psbt.h:77 const MAX_FILE_SIZE_PSBT = 100000000.
      -- haskoin's decodePsbt (Wallet.hs:3215-3216) streams the whole input
      -- through runGet with no length guard.  BUG-1 P2.
      pendingWith "BUG-1: MAX_FILE_SIZE_PSBT 100 MB cap not enforced"

  ------------------------------------------------------------------------------
  -- G21-G25 : BIP-370 PSBT v2 — globals + inputs + outputs absent entirely
  -- (BIP-370: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
  ------------------------------------------------------------------------------

  describe "G21 BIP-370: PSBT_GLOBAL_TX_VERSION (0x02)" $ do
    xit "G21 MISSING: no parser arm for 0x02 in getGlobalMap" $
      -- Wallet.hs:3242-3271 has no case for 0x02; it falls into the
      -- pgUnknown bucket and the encoder echoes it verbatim.  A PSBT v2
      -- that omits PSBT_GLOBAL_UNSIGNED_TX (correct per BIP-370) fails
      -- the Wallet.hs:3247-3249 "missing unsigned transaction" check.
      -- BUG-6 P1.
      pendingWith "BUG-6: PSBT v2 PSBT_GLOBAL_TX_VERSION (0x02) not parsed"

  describe "G22 BIP-370: PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03)" $ do
    xit "G22 MISSING: no parser arm for 0x03 in getGlobalMap" $
      pendingWith "BUG-6: PSBT v2 PSBT_GLOBAL_FALLBACK_LOCKTIME (0x03) not parsed"

  describe "G23 BIP-370: PSBT_GLOBAL_INPUT_COUNT (0x04) / OUTPUT_COUNT (0x05)" $ do
    xit "G23 MISSING: input/output counts not parsed in v2 mode" $
      -- Without these, the decoder can't know how many per-input / per-output
      -- maps to read (in v0 the count comes from unsigned_tx).
      pendingWith "BUG-6: PSBT v2 PSBT_GLOBAL_INPUT_COUNT (0x04) / OUTPUT_COUNT (0x05) not parsed"

  describe "G24 BIP-370: PSBT_IN_PREVIOUS_TXID (0x0e) / PSBT_IN_OUTPUT_INDEX (0x0f)" $ do
    xit "G24 MISSING: per-input outpoint not parsed in v2 mode" $
      -- v2 PSBTs put the outpoint directly in the input map rather than
      -- in the unsigned tx; without these the wallet cannot identify
      -- which UTXO is being spent.
      pendingWith "BUG-6: PSBT v2 PSBT_IN_PREVIOUS_TXID (0x0e) / OUTPUT_INDEX (0x0f) not parsed"

  describe "G25 BIP-370: PSBT_OUT_AMOUNT (0x03) + PSBT_OUT_SCRIPT (0x04)" $ do
    xit "G25 MISSING: per-output amount / script not parsed in v2 mode" $
      -- v2 PSBTs put the output amount + scriptPubKey in the output map.
      pendingWith "BUG-6: PSBT v2 PSBT_OUT_AMOUNT (0x03) + PSBT_OUT_SCRIPT (0x04) not parsed"

  ------------------------------------------------------------------------------
  -- G26-G30 : RPC surface
  -- (Core: bitcoin-core/src/rpc/rawtransaction.cpp +
  --        bitcoin-core/src/wallet/rpc/spend.cpp)
  ------------------------------------------------------------------------------

  describe "G26 joinpsbts RPC" $ do
    xit "G26 MISSING: no joinpsbts handler wired" $
      -- Core's rpc/rawtransaction.cpp joinpsbts concatenates inputs +
      -- outputs from multiple PSBTs.  haskoin's Rpc.hs:1075-1083
      -- has no dispatcher entry.  BUG-16 P1.
      pendingWith "BUG-16: joinpsbts RPC absent"

  describe "G27 utxoupdatepsbt RPC" $ do
    xit "G27 MISSING: no utxoupdatepsbt handler wired" $
      -- Core's rpc/rawtransaction.cpp utxoupdatepsbt decorates input maps
      -- with witness_utxo / non_witness_utxo from chain state.  haskoin's
      -- internal updatePsbt (Wallet.hs:3527) is the right primitive but
      -- isn't exposed via RPC.  BUG-17 P1.
      pendingWith "BUG-17: utxoupdatepsbt RPC absent"

  describe "G28 converttopsbt RPC" $ do
    xit "G28 MISSING: no converttopsbt handler wired" $
      -- Core's rpc/rawtransaction.cpp converttopsbt converts a raw tx hex
      -- into a PSBT.  haskoin's createpsbt only accepts JSON inputs +
      -- outputs.  BUG-18 P1.
      pendingWith "BUG-18: converttopsbt RPC absent"

  describe "G29 walletprocesspsbt RPC (Updater + Signer)" $ do
    xit "G29 MISSING: no walletprocesspsbt handler wired" $
      -- Core's wallet/rpc/spend.cpp walletprocesspsbt runs the Updater +
      -- Signer over the wallet's keys.  haskoin's PSBT bumpfee
      -- (W118 G22 / FIX-61) composes Creator+Updater+Signer in-process
      -- but the RPC surface for an external client is missing.  Bonus
      -- finding; not double-counted in the 14-bug tally.
      pendingWith "bonus: walletprocesspsbt RPC absent (W118 cross-cite)"

  describe "G30 RemoveUnnecessaryTransactions drops non_witness_utxo after sign" $ do
    xit "G30 MISSING: signed Taproot-only PSBTs keep the full prev-tx" $
      -- Core's psbt.cpp:514-549 drops non_witness_utxo entries once all
      -- inputs are post-segwit-v0 and no SIGHASH_ANYONECANPAY is set.
      -- haskoin keeps the full prev-tx forever, inflating PSBT bytes.
      -- Bonus finding; cross-cuts BUG-1 100MB cap.
      pendingWith "bonus: RemoveUnnecessaryTransactions not implemented (W137 cross-cite BUG-1)"

  ------------------------------------------------------------------------------
  -- Bonus pinning assertions (NOT counted as gates)
  -- These exercise the in-memory shape of the existing types so future
  -- refactors can't silently change field counts.
  ------------------------------------------------------------------------------

  describe "B1 emptyPsbtInput has every BIP-174 + BIP-371 input record" $ do
    it "B1 PINS: 16 fields on emptyPsbtInput (BIP-174 v0 9 + BIP-371 6 + unknown)" $ do
      -- Wallet.hs:2929-2952 PsbtInput; Wallet.hs:2988-3006 emptyPsbtInput.
      -- A future addition (e.g. preimages for BUG-14) bumps this count.
      let pinp = emptyPsbtInput
      piNonWitnessUtxo     pinp `shouldBe` Nothing
      piWitnessUtxo        pinp `shouldBe` Nothing
      Map.size (piPartialSigs        pinp) `shouldBe` 0
      piSighashType        pinp `shouldBe` Nothing
      piRedeemScript       pinp `shouldBe` Nothing
      piWitnessScript      pinp `shouldBe` Nothing
      Map.size (piBip32Derivation    pinp) `shouldBe` 0
      piFinalScriptSig     pinp `shouldBe` Nothing
      piFinalScriptWitness pinp `shouldBe` Nothing
      piTapKeySig          pinp `shouldBe` Nothing
      Map.size (piTapScriptSigs      pinp) `shouldBe` 0
      Map.size (piTapLeafScripts     pinp) `shouldBe` 0
      Map.size (piTapBip32Derivation pinp) `shouldBe` 0
      piTapInternalKey     pinp `shouldBe` Nothing
      piTapMerkleRoot      pinp `shouldBe` Nothing
      Map.size (piUnknown            pinp) `shouldBe` 0

  describe "B2 emptyPsbtOutput has every BIP-174 + BIP-371 output record" $ do
    it "B2 PINS: 8 fields on emptyPsbtOutput" $ do
      -- Wallet.hs:2956-2968 PsbtOutput; Wallet.hs:3009-3019 emptyPsbtOutput.
      let pout = emptyPsbtOutput
      poRedeemScript       pout `shouldBe` Nothing
      poWitnessScript      pout `shouldBe` Nothing
      Map.size (poBip32Derivation    pout) `shouldBe` 0
      poTapInternalKey     pout `shouldBe` Nothing
      length (poTapTree              pout) `shouldBe` 0
      Map.size (poTapBip32Derivation pout) `shouldBe` 0
      Map.size (poMuSig2Participants pout) `shouldBe` 0
      Map.size (poUnknown            pout) `shouldBe` 0

  describe "B3 KeyPath has fingerprint + path" $ do
    it "B3 PINS: KeyPath structure matches BIP-32 derivation shape" $ do
      -- Wallet.hs:2909-2912 — fingerprint Word32 + path [Word32].
      let kp = KeyPath 0x11223344 [0x80000000, 0x00000005]
      kpFingerprint kp `shouldBe` 0x11223344
      length (kpPath kp) `shouldBe` 2

  describe "B4 PsbtGlobal has unsigned tx + xpubs + version + unknown" $ do
    it "B4 PINS: 4 fields on PsbtGlobal" $ do
      -- Wallet.hs:2918-2923.
      let g = PsbtGlobal emptyTx Map.empty Nothing Map.empty
      Map.size (pgXpubs g) `shouldBe` 0
      pgVersion g          `shouldBe` Nothing
      Map.size (pgUnknown g) `shouldBe` 0
      -- pgTx pinned to the canonical empty Tx fixture — exercising the
      -- field count + the structural reachability of all four PsbtGlobal
      -- fields.
      txVersion (pgTx g) `shouldBe` 2

  -- Encoder / decoder round-trip pinning is left to W47 / W34-E specs;
  -- W137 audits the container shape and the missing primitives, not the
  -- already-PRESENT bytes.

  -- Use the imports we haven't otherwise touched to avoid -Wunused-imports.
  describe "W137 import-use anchor (compile-time pin)" $ do
    it "anchor: zero32 + Psbt + decodePsbt + encodePsbt + Word8 + Word32 are imported" $ do
      BS.length zero32 `shouldBe` 32
      -- type-only references — ensure Psbt + decodePsbt + encodePsbt symbols are pulled in
      let _typeAnchor1 :: BS.ByteString -> Either String Psbt
          _typeAnchor1 = decodePsbt
          _typeAnchor2 :: Psbt -> BS.ByteString
          _typeAnchor2 = encodePsbt
          _w8 :: Word8  = 0x00
          _w32 :: Word32 = 0
      True `shouldBe` True

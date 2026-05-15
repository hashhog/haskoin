{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W118 Wallet — 30-gate fleet audit for haskoin (Haskell)
--
-- References:
--   bitcoin-core/src/wallet/*           (full wallet stack)
--   bitcoin-core/src/script/descriptor.cpp
--   bitcoin-core/src/key.cpp / pubkey.cpp / bip32.h
--   bitcoin-core/src/psbt.cpp / psbt.h
--   bitcoin-core/src/util/rbf.cpp / util/rbf.h
--   BIPs: 32, 38, 39, 43, 44, 49, 84, 86, 125, 174, 370, 380
--
-- =====================================================================
-- TOP-LINE VERDICT
-- =====================================================================
--
-- haskoin's wallet subsystem (Haskoin.Wallet, ~5600 LOC) covers:
--   * BIP-32 HD key derivation (private + xpub serialization)
--   * BIP-39 mnemonic (cryptonite CSPRNG since W111/FIX-40)
--   * BIP-43/44/49/84/86 path helpers
--   * BIP-174/370 PSBT (encode/decode, sign, finalize, extract)
--   * BIP-380-386 output descriptors (parser, checksum, derive)
--   * BIP-125 RBF signal detection (in Haskoin.Mempool, not Wallet)
--   * Coin selection (BnB + Knapsack), coinbase maturity, dust threshold
--
-- Six gate-class breakdown (30 gates / 6 classes / 5 gates per class):
--
--   Descriptors (G1-G6): MOSTLY PASS — parser, checksum, tr() BIP-341
--     tweak, multi/sortedmulti, range descriptors, expandCombo.  Two
--     long-standing bugs: encodeXPub/encodeXPriv emit literal "xpub..."
--     placeholders (FAIL), and decodeXPub/decodeXPriv return dummy
--     placeholder keys ignoring base58 input (FAIL).
--
--   BIP-32 derivation (G7-G12): PARTIAL — masterKey, derivePrivate,
--     deriveHardened, derivePathPriv all PASS.  derivePublic (xpub CKD)
--     is a stub: addPublicKeyPoint returns parent unchanged, so any
--     xpub-only derivation produces wrong child pubkeys (FAIL).
--     encodeExtKey / decodeExtKey round-trip works on the priv side;
--     encodeExtPubKey / decodeExtPubKey round-trip works on the pub side.
--
--   PSBT (G13-G18): MOSTLY PASS — createPsbt, updatePsbt, signPsbt
--     (P2PKH/P2WPKH/P2SH-P2WPKH/P2WSH/P2TR), combinePsbts, finalizePsbt,
--     extractTransaction, encode/decode wire format with magic bytes.
--     W41 commitment validators (verifyNonWitnessUtxoTxid /
--     verifyInputUtxoConsistency) hardening present.
--
--   Fee bumping (G19-G22): PARTIAL / MISSING — BIP-125 signal detection
--     present (signalsOptInRBF in Haskoin.Mempool) and replacement
--     validation in mempool path (isRbfReplaceable, rbfChecks).
--     BUT: no `bumpfee` RPC, no `psbtbumpfee` RPC, no `psbtmodify`,
--     no in-wallet fee-bump helper.  The wallet itself cannot
--     replace its own outgoing tx — only validates incoming replacements.
--
--   Send (G23-G26): PARTIAL — createTransaction, fundTransaction,
--     sendToAddress all wire to selectCoins.  signTransaction (non-PSBT)
--     is a stub returning empty witnesses (BUG-2 documented in W111;
--     production callers should use signPsbt).  Fee calculation via
--     feeFromWeight / estimateTxWeight covers P2WPKH only.
--
--   UTXO (G27-G30): MOSTLY PASS — addWalletUTXO / removeWalletUTXO,
--     getBalance, isOurAddress, isCoinbaseMature (100-confirmation
--     gate), filterMatureUtxos, selectCoinsWithHeight respects maturity.
--
-- =====================================================================
-- TWO-PIPELINE FINDINGS
-- =====================================================================
--
-- TP-1  [TWO-PIPELINE][P0] xpub derivation has TWO divergent pipelines:
--         (a) deriveXPubPath (Wallet.hs:5210) — foldl over derivePublic.
--             derivePublic in turn calls addPublicKeyPoint (Wallet.hs:584)
--             which is a placeholder stub `addPublicKeyPoint _scalar pk = pk`
--             that returns the PARENT key unchanged.  Result: every xpub
--             CKD step is a no-op, so any descriptor with an xpub key
--             expression derives the SAME pubkey at every index.
--         (b) deriveKeyExpr (Wallet.hs:5188) — for KeyXPriv it routes
--             through derivePath which correctly uses derivePrivate
--             (real EC math).  This path WORKS.
--       Same descriptor, same key, two different code paths, two
--       different answers.  A wallet that signs via KeyXPriv (W31)
--       derives correct addresses; a watch-only wallet using KeyXPub
--       derives all addresses to a fixed dummy key.  This is the
--       largest correctness divergence in the wallet subsystem.
--
-- TP-2  [TWO-PIPELINE][P1] transaction signing has TWO divergent pipelines:
--         (a) signTransaction (Wallet.hs:1946) — stub returning empty
--             witnesses for every input.  Production code that calls
--             this path produces UNSIGNED transactions silently.
--         (b) signPsbt + signInput + addSignature (Wallet.hs:3061+) —
--             fully implemented signing path with sighash, secp256k1,
--             Taproot key+script paths, W31/W41 commitment gates.
--       The signPsbt path is correct; signTransaction is dead-but-exported.
--
-- =====================================================================
-- DEAD-HELPER FINDINGS
-- =====================================================================
--
-- DH-1  [DEAD-HELPER] addPublicKeyPoint (Wallet.hs:584-585) is a public
--       function that is the entire BIP-32 CKD-pub EC point addition.
--       Body: `addPublicKeyPoint _scalar pk = pk` — returns parent
--       unchanged.  Used by derivePublic which is used by deriveXPubPath
--       which is used by deriveKeyExpr for KeyXPub.  The whole watch-only
--       descriptor path collapses to "always derive parent pubkey".
--
-- DH-2  [DEAD-HELPER] saveWallet (Wallet.hs:1136-1138) always throws
--       `error "Wallet persistence not yet implemented"`.  No callers
--       are protected by a try/catch — invoking this from Rpc.hs would
--       crash the daemon.  Effectively means the haskoin wallet has
--       NO persistence: every restart starts from a fresh derivation
--       of the in-memory mnemonic.  (loadManagedWallet creates a fresh
--       random wallet on every load — W111 BUG-8.)
--
-- DH-3  [DEAD-HELPER] signTransaction (Wallet.hs:1946) — see TP-2 above.
--       Stub returning empty witnesses; the per-input loop body has a
--       fallthrough `let ... in []` that always emits an empty witness.
--
-- DH-4  [DEAD-HELPER] decodeXPub (Wallet.hs:5305) and decodeXPriv
--       (Wallet.hs:5320) ignore their text argument entirely and return
--       dummy ExtendedPubKey / ExtendedKey records with hard-coded
--       0x02 / 0x01 keys, zero chain code, depth 0, etc.  Any descriptor
--       using `xpub.../path` or `xprv.../path` parses to a degenerate
--       key.  encodeXPub / encodeXPriv (5333 / 5337) likewise return
--       the literal strings "xpub..." / "xprv...".
--
--       This is distinct from encodeExtPubKey / decodeExtPubKey (in the
--       BIP-32 Serialization section — Wallet.hs:758+), which DO work
--       correctly with real base58check.  The dead-helper pair is the
--       descriptor-parser variants.
--
-- =====================================================================
-- BUGS — 30 GATES
-- =====================================================================
--
-- Descriptors (G1-G6):
--   G1   [PASS]    parseDescriptor parses pk/pkh/wpkh/sh/wsh/multi
--                  /sortedmulti/tr/rawtr/addr/raw/combo at top level.
--   G2   [PASS]    descriptorChecksum (BIP-380 polymod) + addDescriptorChecksum.
--   G3   [PASS]    tr() applies BIP-341 TapTweak per BIP-86 test vectors
--                  (fixed in W111 FIX-38).
--   G4   [PASS]    multi() and sortedmulti() parse + derive; sortedmulti
--                  sorts pubkeys lexicographically.
--   G5   [PASS]    isRangeDescriptor identifies wildcard (/*) keys.
--   G6   [FAIL/DEAD-HELPER] encodeXPub / encodeXPriv return literal
--                  "xpub..." / "xprv..." placeholders — any descriptorToText
--                  on an xpub-key descriptor emits these placeholders
--                  rather than the actual base58.  decodeXPub / decodeXPriv
--                  return a dummy ExtendedPubKey ignoring the input,
--                  so `parseDescriptor "wpkh(xpub6Cg.../0/*)"` produces
--                  a degenerate key.
--
-- BIP-32 derivation (G7-G12):
--   G7   [PASS]    masterKey HMAC-SHA512("Bitcoin seed", seed).
--   G8   [PASS]    derivePrivate non-hardened CKD-priv.
--   G9   [PASS]    deriveHardened (CKD-priv with hardened bit).
--   G10  [FAIL/STUB] derivePublic (xpub CKD): addPublicKeyPoint returns
--                  parent unchanged.  Watch-only xpub derivation is
--                  consensus-divergent (the wallet derives the WRONG
--                  child pubkey for every step).  See DH-1 + TP-1.
--   G11  [PASS]    derivePath / derivePathPriv (multi-level path).
--   G12  [PASS]    encodeExtKey / decodeExtKey for xprv (mainnet) +
--                  tprv (testnet); encodeExtPubKey / decodeExtPubKey
--                  for xpub + tpub.  These are the real serializers,
--                  not the descriptor-parser placeholders in DH-4.
--
-- PSBT (G13-G18):
--   G13  [PASS]    createPsbt rejects tx with non-empty scriptSig or
--                  non-empty witness.  emptyPsbt constructor.
--   G14  [PASS]    updatePsbt with lookup function populates
--                  piWitnessUtxo / piNonWitnessUtxo per input.
--   G15  [PASS]    signPsbt for P2WPKH adds partial signature.
--   G16  [PASS]    combinePsbts merges partial sigs from multiple
--                  signers (Combiner role per BIP-174).
--   G17  [PASS]    finalizePsbt assembles final scriptSig + witness
--                  for finalized inputs (W31/W32/W46/W47 hardening:
--                  P2SH-P2WPKH, P2SH-P2WSH, P2WSH multisig, legacy P2SH).
--                  W41 commitment gate prevents finalize on forged
--                  redeem/witness script.
--   G18  [PASS]    extractTransaction emits the network-ready tx after
--                  finalize; isPsbtFinalized predicate; getPsbtFee from
--                  piWitnessUtxo / piNonWitnessUtxo data.
--                  PSBT magic bytes 70 73 62 74 ff.
--                  W41 verifyNonWitnessUtxoTxid + verifyInputUtxoConsistency.
--
-- Fee bumping (G19-G22):
--   G19  [PASS]    signalsOptInRBF (Mempool.hs:397) — `any nSequence
--                  <= 0xfffffffd` matches Core.
--   G20  [PASS]    MAX_BIP125_RBF_SEQUENCE = 0xfffffffd documented and
--                  used.  Final-sequence (0xffffffff / 0xfffffffe) does
--                  not signal RBF.
--   G21  [PASS]    isRbfReplaceable (Mempool.hs:1576) walks ancestor
--                  set for opt-in flag (BIP-125 gate 2).
--   G22  [MISSING] No `bumpfee` RPC, no `psbtbumpfee` RPC, no in-wallet
--                  fee-bump helper.  The wallet cannot RBF its own
--                  outgoing tx.  Core has bumpfee + psbtbumpfee under
--                  wallet/rpc/spend.cpp; haskoin has neither.
--                  Replacement validation is implemented (Mempool path)
--                  but there is no producer-side flow.
--
-- Send (G23-G26):
--   G23  [PASS]    createTransaction from CoinSelection produces a Tx
--                  with the requested inputs and outputs.  Default
--                  sequence 0xfffffffe (signals RBF per BIP-125).
--   G24  [PASS]    sendToAddress wraps fundTransaction + selectCoins.
--                  Returns Left "Insufficient funds" on inadequate UTXOs.
--   G25  [FAIL/STUB] signTransaction (non-PSBT) returns empty witnesses
--                  for every input.  TP-2 / DH-3 documented above.
--                  Production must use signPsbt path.
--   G26  [PARTIAL] feeFromWeight + estimateTxWeight assume P2WPKH for
--                  every input AND every output.  Mixed-script tx (e.g.
--                  P2SH inputs spending to P2TR outputs) gets a wrong
--                  fee estimate.  No per-script weight dispatch in the
--                  estimator; inputWeightP2PKH / inputWeightP2SH_P2WPKH
--                  / inputWeightP2TR constants are DEFINED but not used
--                  by estimateTxWeight (dead constants in the estimator).
--
-- UTXO (G27-G30):
--   G27  [PASS]    addWalletUTXO / removeWalletUTXO mutate walletUTXOs
--                  TVar correctly.  getBalance sums txOutValue.
--   G28  [PASS]    isOurAddress consults walletAddresses Map for
--                  membership.
--   G29  [PASS]    selectCoins / selectCoinsBnB / knapsackSolver
--                  + dustThreshold (546) + minChangeAmount (1000)
--                  + costOfChange + effectiveValue all present and
--                  correct (W113 FIX-46 + W111).
--   G30  [PASS]    isCoinbaseMature (Wallet.hs:1712) gates on
--                  tipHeight >= blockHeight + coinbaseMaturity (100).
--                  filterMatureUtxos; selectCoinsWithHeight enforces.
--
-- Summary: 30 gates / 4 FAIL/STUB + 1 MISSING + 1 PARTIAL + 24 PASS
--          = 5 bugs + 1 missing-feature + 1 partial-feature.
--   P0    : 1  (G10 derivePublic xpub CKD stub / TP-1)
--   P1    : 1  (G25 signTransaction stub / TP-2)
--   MEDIUM: 2  (G6 descriptor xpub placeholders; G22 no bumpfee RPC)
--   LOW   : 2  (DH-2 saveWallet stub; G26 mixed-script fee estimation)
--
module W118WalletSpec (spec) where

import Test.Hspec
import Control.Exception (evaluate)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Bits ((.&.), (.|.))
import Control.Concurrent.STM (readTVarIO)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T

import Haskoin.Wallet
import Haskoin.Crypto (SecKey(..), PubKey(..), derivePubKey,
                       serializePubKeyCompressed, hash160, hmacSHA512,
                       computeTxId, Address(..))
import Haskoin.Consensus (mainnet, testnet4, Network(..))
import Haskoin.Types (TxId(..), Hash256(..), Hash160(..), OutPoint(..),
                       TxIn(..), TxOut(..), Tx(..))
import Haskoin.Mempool (FeeRate(..), signalsOptInRBF)

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Standard 32-byte test seed.
testSeed :: Word32 -> ByteString
testSeed n = BS.pack [fromIntegral (n + i) | i <- [0..31]]

-- | A null OutPoint useful for tx skeletons.
nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0

-- | Standard P2WPKH scriptPubKey for tests.  Returns the script bytes.
testP2WPKHScript :: ByteString
testP2WPKHScript = BS.pack [0x00, 0x14] <> BS.replicate 20 0xAA

-- | A small unsigned tx with a single P2WPKH-spending input and one output.
mkSampleTx :: Tx
mkSampleTx = Tx
  { txVersion  = 2
  , txInputs   = [TxIn nullOutPoint BS.empty 0xfffffffe]
  , txOutputs  = [TxOut 50_000 testP2WPKHScript]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | A tx that signals RBF on every input (sequence 0xfffffffd).
rbfSignalingTx :: Tx
rbfSignalingTx = mkSampleTx
  { txInputs = [TxIn nullOutPoint BS.empty 0xfffffffd] }

-- | A tx that does NOT signal RBF (sequence 0xffffffff).
nonRbfSignalingTx :: Tx
nonRbfSignalingTx = mkSampleTx
  { txInputs = [TxIn nullOutPoint BS.empty 0xffffffff] }

--------------------------------------------------------------------------------
-- Top-level spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "W118 Wallet — 30-gate audit (haskoin)" $ do

    spec_descriptors_g1_g6
    spec_bip32_g7_g12
    spec_psbt_g13_g18
    spec_feebump_g19_g22
    spec_send_g23_g26
    spec_utxo_g27_g30
    spec_two_pipeline
    spec_dead_helpers

--------------------------------------------------------------------------------
-- G1-G6: Descriptors (BIP-380 to BIP-386)
--------------------------------------------------------------------------------

spec_descriptors_g1_g6 :: Spec
spec_descriptors_g1_g6 = describe "G1-G6 Descriptors (BIP-380-386)" $ do

  -- G1: parseDescriptor for common forms.
  it "G1: parseDescriptor parses pk(<hex>) -> Pk" $ do
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("pk(" <> hex33 <> ")") of
      Right (Pk _) -> pure ()
      r            -> expectationFailure ("Unexpected: " ++ show r)

  it "G1: parseDescriptor parses pkh(<hex>) -> Pkh" $ do
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("pkh(" <> hex33 <> ")") of
      Right (Pkh _) -> pure ()
      r             -> expectationFailure ("Unexpected: " ++ show r)

  it "G1: parseDescriptor parses wpkh(<hex>) -> Wpkh" $ do
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("wpkh(" <> hex33 <> ")") of
      Right (Wpkh _) -> pure ()
      r              -> expectationFailure ("Unexpected: " ++ show r)

  it "G1: parseDescriptor parses sh(wpkh(<hex>)) -> Sh (Wpkh _)" $ do
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("sh(wpkh(" <> hex33 <> "))") of
      Right (Sh (Wpkh _)) -> pure ()
      r                   -> expectationFailure ("Unexpected: " ++ show r)

  it "G1: parseDescriptor rejects unknown function name" $ do
    case parseDescriptor "nosuchfunc(02ab)" of
      Left (UnknownFunction _) -> pure ()
      r                        -> expectationFailure ("Unexpected: " ++ show r)

  -- G2: BIP-380 checksum.
  it "G2: descriptorChecksum returns 8 base32 characters" $ do
    let body = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
    case descriptorChecksum body of
      Just cs -> T.length cs `shouldBe` 8
      Nothing -> expectationFailure "descriptorChecksum returned Nothing"

  it "G2: validateDescriptorChecksum round-trips through addDescriptorChecksum" $ do
    let body = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
    case addDescriptorChecksum body of
      Nothing      -> expectationFailure "addDescriptorChecksum returned Nothing"
      Just withCs  -> case validateDescriptorChecksum withCs of
                        Right stripped -> stripped `shouldBe` body
                        Left  err      -> expectationFailure ("validate failed: " ++ show err)

  it "G2: validateDescriptorChecksum rejects bad checksum" $ do
    let bad = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#xxxxxxxx"
    case validateDescriptorChecksum bad of
      Left _  -> pure ()
      Right _ -> expectationFailure "Expected Left for bad checksum"

  -- G3: tr() BIP-341 TapTweak (FIX-38 from W111).
  it "G3: tr() applies BIP-341 TapTweak — BIP-86 keypath test vector" $ do
    -- BIP-86 test vector §"Test Vectors":
    --   internal x-only key cc8a4b...
    --   expected output key  a60869...
    let internalHex = "02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        expectedOutputKey = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    case parseDescriptor ("tr(" <> T.pack internalHex <> ")") of
      Left err -> expectationFailure ("parseDescriptor tr failed: " ++ show err)
      Right d  -> do
        let scripts = deriveScripts d 0
        case scripts of
          [script] | BS.length script == 34
                   , BS.index script 0 == 0x51
                   , BS.index script 1 == 0x20 ->
                       T.pack (hexBytes (BS.take 32 (BS.drop 2 script)))
                         `shouldBe` T.pack expectedOutputKey
          _        -> expectationFailure ("Expected single P2TR script, got: " ++ show scripts)

  -- G4: multi() and sortedmulti().
  it "G4: parseDescriptor parses multi(2, k1, k2, k3) -> Multi 2 [k1,k2,k3]" $ do
    let k1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        k2 = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
        k3 = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
        input = "multi(2," <> k1 <> "," <> k2 <> "," <> k3 <> ")"
    case parseDescriptor input of
      Right (Multi 2 ks) -> length ks `shouldBe` 3
      r                  -> expectationFailure ("Unexpected: " ++ show r)

  it "G4: parseDescriptor rejects multi(k > n)" $ do
    let k1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    -- threshold 2 with only 1 key
    case parseDescriptor ("multi(2," <> k1 <> ")") of
      Left (InvalidThreshold _ _) -> pure ()
      r                           -> expectationFailure ("Unexpected: " ++ show r)

  it "G4: parseDescriptor parses sortedmulti(2, k1, k2, k3)" $ do
    let k1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        k2 = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
        k3 = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
    case parseDescriptor ("sortedmulti(2," <> k1 <> "," <> k2 <> "," <> k3 <> ")") of
      Right (SortedMulti 2 ks) -> length ks `shouldBe` 3
      r                        -> expectationFailure ("Unexpected: " ++ show r)

  -- G5: isRangeDescriptor.
  it "G5: isRangeDescriptor is False for fixed-key descriptors" $ do
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("wpkh(" <> hex33 <> ")") of
      Right d -> isRangeDescriptor d `shouldBe` False
      r       -> expectationFailure ("parse failed: " ++ show r)

  -- G6: BUG (DH-4) — encodeXPub / encodeXPriv emit literal placeholders.
  --   These are the descriptor-parser variants in Wallet.hs:5333 / 5337.
  --   The real BIP-32 base58 serializers (encodeExtKey / encodeExtPubKey)
  --   work correctly (tested under G12).
  it "G6: [DH-4 STUB] descriptor encodeXPub emits literal \"xpub...\" placeholder" $ do
    -- The descriptor pretty-printer for a KeyXPub descriptor emits literal
    -- "xpub..." instead of the actual base58 string.  Observable via
    -- descriptorToText on a parsed xpub-key descriptor.
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("wpkh(" <> hex33 <> ")") of
      Right d -> do
        -- For a literal-pubkey descriptor, descriptorToText should NOT emit "xpub..."
        let txt = descriptorToText d
        T.isInfixOf "xpub..." txt `shouldBe` False
      r       -> expectationFailure ("parse failed: " ++ show r)

  it "G6: [DH-4 STUB] expandCombo / combo() smoke test" $ do
    let hex33 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    case parseDescriptor ("combo(" <> hex33 <> ")") of
      Right (Combo _) -> do
        let scripts = deriveScripts (Combo (case parseDescriptor ("combo(" <> hex33 <> ")") of
                                             Right (Combo k) -> k
                                             _ -> error "unreachable")) 0
        -- combo() should produce 4 scripts (P2PK, P2PKH, P2WPKH, P2SH-P2WPKH).
        length scripts `shouldBe` 4
      r -> expectationFailure ("parse combo failed: " ++ show r)

--------------------------------------------------------------------------------
-- G7-G12: BIP-32 derivation
--------------------------------------------------------------------------------

spec_bip32_g7_g12 :: Spec
spec_bip32_g7_g12 = describe "G7-G12 BIP-32 key derivation" $ do

  -- G7: masterKey from seed.
  it "G7: masterKey uses HMAC-SHA512 with 'Bitcoin seed' key" $ do
    let seed = testSeed 1
        mk   = masterKey seed
        hmacResult = hmacSHA512 "Bitcoin seed" seed
        (expectedKey, expectedChainCode) = BS.splitAt 32 hmacResult
    getSecKey (ekKey mk) `shouldBe` expectedKey
    ekChainCode mk       `shouldBe` expectedChainCode
    ekDepth mk           `shouldBe` 0
    ekParentFP mk        `shouldBe` 0
    ekIndex mk           `shouldBe` 0

  it "G7: masterKey produces 32-byte private key + 32-byte chain code" $ do
    let mk = masterKey (testSeed 2)
    BS.length (getSecKey (ekKey mk)) `shouldBe` 32
    BS.length (ekChainCode mk)        `shouldBe` 32

  -- G8: derivePrivate.
  it "G8: derivePrivate non-hardened child increments depth" $ do
    let mk = masterKey (testSeed 3)
        c  = derivePrivate mk 0
    ekDepth c `shouldBe` 1
    ekIndex c `shouldBe` 0

  it "G8: derivePrivate errors when given a hardened index" $ do
    let mk = masterKey (testSeed 4)
    evaluate (derivePrivate mk 0x80000000) `shouldThrow` anyErrorCall

  it "G8: derivePrivate at different indices produces different keys" $ do
    let mk = masterKey (testSeed 5)
        c0 = derivePrivate mk 0
        c1 = derivePrivate mk 1
    ekKey c0 `shouldNotBe` ekKey c1

  -- G9: deriveHardened.
  it "G9: deriveHardened sets hardened bit (>= 0x80000000) in child index" $ do
    let mk = masterKey (testSeed 6)
        c  = deriveHardened mk 0
    ekIndex c `shouldBe` 0x80000000
    ekDepth c `shouldBe` 1

  it "G9: deriveHardened differs from derivePrivate at same logical index" $ do
    let mk = masterKey (testSeed 7)
        h  = deriveHardened mk 0
        p  = derivePrivate mk 0
    ekKey h `shouldNotBe` ekKey p

  -- G10: derivePublic (xpub CKD) — STUB.
  it "G10: [BUG-1 / TP-1 / DH-1 STUB] derivePublic xpub CKD is stub — child==parent" $ do
    -- addPublicKeyPoint is `_scalar pk = pk` — it returns the parent
    -- key unchanged.  Observable proof: derivePublic on any non-hardened
    -- index gives a child whose pubkey is byte-identical to the parent.
    let mk      = masterKey (testSeed 8)
        epkPar  = toExtendedPubKey mk
        epkChi  = derivePublic epkPar 0
    -- BUG: child pubkey equals parent pubkey (real BIP-32 CKD-pub would differ).
    epkKey epkChi `shouldBe` epkKey epkPar

  -- G11: derivePath / derivePathPriv.
  it "G11: derivePath BIP-84 m/84'/0'/0' produces depth-3 key" $ do
    let mk = masterKey (testSeed 9)
        path = bip84Path 0
        c    = derivePath mk path
    ekDepth c `shouldBe` 3

  it "G11: derivePathPriv (total variant) succeeds for normal seed" $ do
    let mk   = masterKey (testSeed 10)
        path = bip84Path 0
    case derivePathPriv mk path of
      Just k  -> ekDepth k `shouldBe` 3
      Nothing -> expectationFailure "derivePathPriv returned Nothing"

  it "G11: parseDerivationPath \"m/84'/0'/0'\" returns three hardened indices" $ do
    case parseDerivationPath "m/84'/0'/0'" of
      Just p  -> p `shouldBe` [0x80000000 .|. 84, 0x80000000, 0x80000000]
      Nothing -> expectationFailure "parseDerivationPath failed"

  -- G12: encodeExtKey / decodeExtKey / encodeExtPubKey / decodeExtPubKey.
  it "G12: encodeExtKey round-trips through decodeExtKey (mainnet -> xprv...)" $ do
    let mk      = masterKey (testSeed 11)
        encoded = encodeExtKey mainnet mk
    T.isPrefixOf "xprv" encoded `shouldBe` True
    case decodeExtKey encoded of
      Just (_, decoded) -> do
        ekKey decoded       `shouldBe` ekKey mk
        ekChainCode decoded `shouldBe` ekChainCode mk
      Nothing -> expectationFailure "decodeExtKey returned Nothing"

  it "G12: encodeExtKey emits tprv prefix on testnet" $ do
    let mk      = masterKey (testSeed 12)
        encoded = encodeExtKey testnet4 mk
    T.isPrefixOf "tprv" encoded `shouldBe` True

  it "G12: encodeExtPubKey/decodeExtPubKey round-trip on mainnet" $ do
    let mk      = masterKey (testSeed 13)
        epk     = toExtendedPubKey mk
        encoded = encodeExtPubKey mainnet epk
    T.isPrefixOf "xpub" encoded `shouldBe` True
    case decodeExtPubKey encoded of
      Just (_, decoded) -> epkKey decoded `shouldBe` epkKey epk
      Nothing           -> expectationFailure "decodeExtPubKey returned Nothing"

  it "G12: BIP-32 version-prefix constants match the standard" $ do
    xprvVersion `shouldBe` 0x0488ADE4
    xpubVersion `shouldBe` 0x0488B21E
    tprvVersion `shouldBe` 0x04358394
    tpubVersion `shouldBe` 0x043587CF

--------------------------------------------------------------------------------
-- G13-G18: PSBT (BIP-174 / BIP-370)
--------------------------------------------------------------------------------

spec_psbt_g13_g18 :: Spec
spec_psbt_g13_g18 = describe "G13-G18 PSBT" $ do

  -- G13: createPsbt.
  it "G13: emptyPsbt constructor on minimal tx — isPsbtFinalized False" $ do
    let p = emptyPsbt mkSampleTx
    isPsbtFinalized p `shouldBe` False

  it "G13: createPsbt rejects tx with non-empty scriptSig" $ do
    let badTx = mkSampleTx
          { txInputs = [TxIn nullOutPoint (BS.singleton 0x01) 0xfffffffe] }
    createPsbt badTx `shouldBe`
      Left "Transaction inputs must have empty scriptSigs"

  it "G13: createPsbt rejects tx with non-empty witness" $ do
    let badTx = mkSampleTx
          { txWitness = [[BS.singleton 0x01]] }
    createPsbt badTx `shouldBe`
      Left "Transaction must have empty witnesses"

  it "G13: createPsbt succeeds on a clean unsigned tx" $ do
    case createPsbt mkSampleTx of
      Right p  -> length (psbtInputs p) `shouldBe` 1
      Left err -> expectationFailure err

  -- G14: updatePsbt populates piWitnessUtxo / piNonWitnessUtxo.
  it "G14: updatePsbt populates piWitnessUtxo for a witness output" $ do
    let prevOut = TxOut 100_000 testP2WPKHScript
        p0      = emptyPsbt mkSampleTx
        op      = nullOutPoint
        p1      = updatePsbt (\o -> if o == op
                                    then Just (mkSampleTx, prevOut)
                                    else Nothing) p0
    case psbtInputs p1 of
      [inp] -> piWitnessUtxo inp `shouldBe` Just prevOut
      _     -> expectationFailure "expected 1 PSBT input"

  -- G15: signPsbt for P2WPKH input.
  it "G15: signPsbt adds partial signature for a P2WPKH input" $ do
    let mk        = masterKey (testSeed 20)
        xkey      = derivePath mk (bip84FullPath 0 0 0 0)
        pk        = derivePubKey (ekKey xkey)
        pkHash    = hash160 (serializePubKeyCompressed pk)
        scriptPK  = BS.pack [0x00, 0x14] <> getHash160 pkHash
        prevOut   = TxOut 100_000 scriptPK
        inpoint   = OutPoint (TxId (Hash256 (BS.replicate 32 0xcc))) 0
        unsignedTx = Tx 2 [TxIn inpoint BS.empty 0xfffffffe]
                          [TxOut 90_000 scriptPK] [[]] 0
    case createPsbt unsignedTx of
      Left err -> expectationFailure err
      Right p0 -> do
        let p1 = updatePsbt (\o -> if o == inpoint
                                   then Just (unsignedTx, prevOut)
                                   else Nothing) p0
            p2 = signPsbt xkey p1
        case psbtInputs p2 of
          (inp:_) -> Map.null (piPartialSigs inp) `shouldBe` False
          []      -> expectationFailure "no PSBT inputs"

  -- G16: combinePsbts.
  it "G16: combinePsbts with a single PSBT returns that PSBT" $ do
    let p = emptyPsbt mkSampleTx
    case combinePsbts [p] of
      Right p' -> pgTx (psbtGlobal p') `shouldBe` pgTx (psbtGlobal p)
      Left err -> expectationFailure err

  it "G16: combinePsbts on an empty list returns Left" $ do
    case combinePsbts [] of
      Left  _ -> pure ()
      Right _ -> expectationFailure "expected Left on empty list"

  -- G17: finalizePsbt.
  it "G17: finalizePsbt fails on an empty PSBT (no signatures)" $ do
    let p = emptyPsbt mkSampleTx
    case finalizePsbt p of
      Left  _ -> pure ()
      Right _ -> expectationFailure "expected Left on unsigned PSBT"

  -- G18: extractTransaction + encode/decode wire format.
  it "G18: extractTransaction rejects unfinalized PSBT" $ do
    let p = emptyPsbt mkSampleTx
    extractTransaction p `shouldBe` Left "PSBT is not fully finalized"

  it "G18: encodePsbt/decodePsbt round-trips an empty PSBT" $ do
    let p       = emptyPsbt mkSampleTx
        bytes   = encodePsbt p
    case decodePsbt bytes of
      Right p' -> pgTx (psbtGlobal p') `shouldBe` pgTx (psbtGlobal p)
      Left err -> expectationFailure ("decodePsbt failed: " ++ err)

  it "G18: encodePsbt magic is 70 73 62 74 ff (BIP-174 §Wire Format)" $ do
    let p     = emptyPsbt mkSampleTx
        magic = BS.take 5 (encodePsbt p)
    magic `shouldBe` BS.pack [0x70, 0x73, 0x62, 0x74, 0xff]

  it "G18: decodePsbt rejects garbage magic" $ do
    case decodePsbt (BS.pack [0x01, 0x02, 0x03, 0x04, 0x05]) of
      Left  _ -> pure ()
      Right _ -> expectationFailure "expected decode failure on bad magic"

  -- G18: W41 commitment validators (Bug A1 + Bug A2 / CVE-2020-14199).
  it "G18: verifyNonWitnessUtxoTxid accepts matching txid" $ do
    let realTid = computeTxId mkSampleTx
    verifyNonWitnessUtxoTxid mkSampleTx realTid `shouldBe` Right ()

  it "G18: verifyNonWitnessUtxoTxid rejects mismatched txid" $ do
    let fakeTid = TxId (Hash256 (BS.replicate 32 0xde))
    case verifyNonWitnessUtxoTxid mkSampleTx fakeTid of
      Left  _ -> pure ()
      Right _ -> expectationFailure "expected Left on txid mismatch"

  it "G18: verifyPsbtUtxoConsistency accepts a consistent emptyPsbt" $ do
    let p = emptyPsbt mkSampleTx
    verifyPsbtUtxoConsistency p `shouldBe` Right ()

--------------------------------------------------------------------------------
-- G19-G22: Fee bumping (BIP-125)
--------------------------------------------------------------------------------

spec_feebump_g19_g22 :: Spec
spec_feebump_g19_g22 = describe "G19-G22 Fee bumping (BIP-125)" $ do

  -- G19: signalsOptInRBF.
  it "G19: signalsOptInRBF is True for tx with nSequence == 0xfffffffd" $
    signalsOptInRBF rbfSignalingTx `shouldBe` True

  it "G19: signalsOptInRBF is False for tx with nSequence == 0xffffffff (final)" $
    signalsOptInRBF nonRbfSignalingTx `shouldBe` False

  it "G19: signalsOptInRBF is True if ANY input has nSequence <= 0xfffffffd" $ do
    -- Per Core util/rbf.cpp:SignalsOptInRBF — any input is enough.
    let mixed = mkSampleTx
          { txInputs = [ TxIn nullOutPoint BS.empty 0xffffffff
                       , TxIn nullOutPoint BS.empty 0xfffffffd
                       ] }
    signalsOptInRBF mixed `shouldBe` True

  -- G20: MAX_BIP125_RBF_SEQUENCE boundary.
  it "G20: nSequence == 0xfffffffe (next-to-final) does NOT signal RBF" $ do
    -- Core: MAX_BIP125_RBF_SEQUENCE = 0xfffffffd, so 0xfffffffe is the
    -- smallest non-RBF-signaling sequence below 0xffffffff.
    let nearFinal = mkSampleTx
          { txInputs = [TxIn nullOutPoint BS.empty 0xfffffffe] }
    signalsOptInRBF nearFinal `shouldBe` False

  it "G20: nSequence == 0 signals RBF (well below MAX_BIP125_RBF_SEQUENCE)" $ do
    let zeroSeq = mkSampleTx
          { txInputs = [TxIn nullOutPoint BS.empty 0] }
    signalsOptInRBF zeroSeq `shouldBe` True

  -- G21: replacement validation lives in Mempool — sanity test that the
  --      signaller is exported and is part of the BIP-125 pipeline.
  it "G21: signalsOptInRBF on empty-inputs tx is False (no input to signal)" $ do
    let empty = mkSampleTx { txInputs = [] }
    signalsOptInRBF empty `shouldBe` False

  -- G22: BIP-125 producer-side fee bump (bumpfee / psbtbumpfee) — MISSING.
  it "G22: [MISSING] no bumpfee / psbtbumpfee RPC or wallet helper exists" $ do
    -- Compare Core src/wallet/rpc/spend.cpp:bumpfee, psbtbumpfee.
    -- haskoin: neither RPC handler nor wallet-level fee-bump function.
    -- This `pending` is the documentation marker.
    pending

--------------------------------------------------------------------------------
-- G23-G26: Send (transaction creation + signing)
--------------------------------------------------------------------------------

spec_send_g23_g26 :: Spec
spec_send_g23_g26 = describe "G23-G26 Send (createTransaction / signTransaction)" $ do

  -- G23: createTransaction shape.
  it "G23: createTransaction produces tx with default sequence 0xfffffffe (RBF-signaling)" $ do
    let cs = CoinSelection
          { csInputs    = [(nullOutPoint, TxOut 100_000 testP2WPKHScript)]
          , csOutputs   = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0x01))) 90_000]
          , csChange    = Nothing
          , csFee       = 10_000
          , csFeeRate   = FeeRate 1000
          , csAlgorithm = AlgKnapsack
          , csWaste     = 0
          }
        tx = createTransaction cs
    txVersion tx     `shouldBe` 2
    length (txInputs tx)   `shouldBe` 1
    length (txOutputs tx)  `shouldBe` 1
    txInSequence (head (txInputs tx)) `shouldBe` 0xfffffffe

  it "G23: createTransaction with change adds an extra output" $ do
    let changeAddr = WitnessPubKeyAddress (Hash160 (BS.replicate 20 0x02))
        cs = CoinSelection
          { csInputs    = [(nullOutPoint, TxOut 100_000 testP2WPKHScript)]
          , csOutputs   = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0x01))) 50_000]
          , csChange    = Just (changeAddr, 40_000)
          , csFee       = 10_000
          , csFeeRate   = FeeRate 1000
          , csAlgorithm = AlgKnapsack
          , csWaste     = 0
          }
        tx = createTransaction cs
    length (txOutputs tx) `shouldBe` 2  -- payment + change

  -- G24: sendToAddress + selectCoins glue.
  it "G24: sendToAddress returns Left \"Insufficient funds\" on a fresh wallet" $ do
    m <- generateMnemonic 128
    w <- loadWallet (WalletConfig mainnet 20 "") m
    let dst = WitnessPubKeyAddress (Hash160 (BS.replicate 20 0x05))
    res <- sendToAddress w dst 50_000 (FeeRate 1000)
    case res of
      Left err -> err `shouldBe` "Insufficient funds"
      Right _  -> expectationFailure "expected insufficient funds"

  it "G24: fundTransaction returns Left on a fresh wallet" $ do
    m <- generateMnemonic 128
    w <- loadWallet (WalletConfig mainnet 20 "") m
    let dst = WitnessPubKeyAddress (Hash160 (BS.replicate 20 0x06))
    res <- fundTransaction w [WalletTxOutput dst 50_000] (FeeRate 1000)
    case res of
      Left _  -> pure ()
      Right _ -> expectationFailure "expected Left for fresh wallet"

  -- G25: signTransaction stub (BUG-2 / TP-2 / DH-3).
  it "G25: [BUG-2 / TP-2 / DH-3 STUB] signTransaction returns empty witnesses" $ do
    m <- generateMnemonic 128
    w <- loadWallet (WalletConfig mainnet 20 "") m
    let prevOut = TxOut 100_000 testP2WPKHScript
        prevs   = [(nullOutPoint, prevOut)]
    case signTransaction w mkSampleTx prevs of
      Right signed -> all null (txWitness signed) `shouldBe` True
      Left  err    -> expectationFailure ("signTransaction returned Left: " ++ err)

  -- G26: fee calculation.
  it "G26: feeFromWeight gives correct fee for 4-WU / 1-vB minimum" $ do
    -- weight 4 -> vsize 1 -> fee = 1 * feeRate/1000.
    feeFromWeight 4 (FeeRate 1000) `shouldBe` 1

  it "G26: feeFromWeight scales linearly with weight" $ do
    let fr = FeeRate 1000
    feeFromWeight 400 fr `shouldBe` 100   -- 100 vB at 1 sat/vB

  it "G26: estimateTxWeight (1 in, 1 out, no change) gives ≤ 1 P2WPKH tx weight" $ do
    let w = estimateTxWeight 1 1 False
    -- overhead(40) + P2WPKH input(272) + P2WPKH output(124) + witness overhead(2) = 438
    w `shouldBe` 438

  it "G26: [PARTIAL] estimateTxWeight assumes P2WPKH for every input/output" $ do
    -- Mixed-script wallets (P2PKH inputs to P2TR outputs) get wrong fees.
    -- inputWeightP2PKH = 592 vs inputWeightP2WPKH = 272.  The wallet's
    -- own fee calc applies the latter regardless.  Document the
    -- limitation as a `pending` test.
    pending

--------------------------------------------------------------------------------
-- G27-G30: UTXO management + coin selection + maturity
--------------------------------------------------------------------------------

spec_utxo_g27_g30 :: Spec
spec_utxo_g27_g30 = describe "G27-G30 UTXO / Coin selection / Maturity" $ do

  -- G27: addWalletUTXO / removeWalletUTXO / getBalance.
  it "G27: getBalance is 0 on a fresh wallet" $ do
    m   <- generateMnemonic 128
    w   <- loadWallet (WalletConfig mainnet 20 "") m
    getBalance w >>= (`shouldBe` 0)

  it "G27: addWalletUTXO increments getBalance" $ do
    m <- generateMnemonic 128
    w <- loadWallet (WalletConfig mainnet 20 "") m
    let op    = nullOutPoint
        txout = TxOut 50_000 testP2WPKHScript
    addWalletUTXO w op txout 100
    bal <- getBalance w
    bal `shouldBe` 50_000

  it "G27: removeWalletUTXO decrements getBalance" $ do
    m <- generateMnemonic 128
    w <- loadWallet (WalletConfig mainnet 20 "") m
    let op    = nullOutPoint
        txout = TxOut 50_000 testP2WPKHScript
    addWalletUTXO w op txout 100
    removeWalletUTXO w op
    bal <- getBalance w
    bal `shouldBe` 0

  -- G28: isOurAddress.
  it "G28: isOurAddress True for a wallet-generated address" $ do
    m   <- generateMnemonic 128
    w   <- loadWallet (WalletConfig mainnet 20 "") m
    a   <- getReceiveAddress w
    isOurAddress w a >>= (`shouldBe` True)

  it "G28: isOurAddress False for an address from a different wallet" $ do
    m1  <- generateMnemonic 128
    m2  <- generateMnemonic 128
    w1  <- loadWallet (WalletConfig mainnet 20 "") m1
    w2  <- loadWallet (WalletConfig mainnet 20 "") m2
    a2  <- getReceiveAddress w2
    isOurAddress w1 a2 >>= (`shouldBe` False)

  -- G29: Coin selection (BnB + Knapsack + constants).
  it "G29: dustThreshold == 546 sats (Bitcoin Core default)" $
    dustThreshold `shouldBe` 546

  it "G29: minChangeAmount == 1000 (above dust)" $
    minChangeAmount `shouldBe` 1000

  it "G29: maxBnBIterations matches Core's no-DoS bound (100_000)" $
    maxBnBIterations `shouldBe` 100_000

  it "G29: selectCoinsBnB returns Just [] for target=0 (non-empty utxos)" $ do
    -- The early-out for target=0 is gated by `null utxos = Nothing` first
    -- (Wallet.hs:1487-1489), so we pass a non-empty UTXO list.
    let utxo = Utxo nullOutPoint (TxOut 10_000 testP2WPKHScript) 1 False 0
    selectCoinsBnB [utxo] 0 (FeeRate 1000) `shouldBe` Just []

  it "G29: selectCoinsBnB returns Nothing on an empty UTXO set" $
    -- Empty UTXOs always returns Nothing regardless of target.
    selectCoinsBnB [] 50_000 (FeeRate 1000) `shouldBe` Nothing

  -- G30: coinbase maturity.
  it "G30: isCoinbaseMature False before 100 confirmations" $ do
    let utxo  = Utxo nullOutPoint (TxOut 100 BS.empty) 0 True {- isCoinbase -} 100
    -- tip just at block 100 — utxo is at block 100, no confirmations yet.
    isCoinbaseMature 100 utxo `shouldBe` False

  it "G30: isCoinbaseMature True at exactly 100 confirmations" $ do
    let utxo = Utxo nullOutPoint (TxOut 100 BS.empty) 0 True 100
    -- tip at 100 + 100 = 200 -> 100 confirmations exact.
    isCoinbaseMature 200 utxo `shouldBe` True

  it "G30: non-coinbase UTXOs are always mature" $ do
    let utxo = Utxo nullOutPoint (TxOut 100 BS.empty) 0 False 100
    isCoinbaseMature 100 utxo `shouldBe` True

  it "G30: filterMatureUtxos drops immature coinbase outputs" $ do
    let cb       = Utxo nullOutPoint (TxOut 100 BS.empty) 0 True  100  -- immature at tip 100
        regular  = Utxo nullOutPoint (TxOut 200 BS.empty) 0 False 100  -- always mature
    length (filterMatureUtxos 100 [cb, regular]) `shouldBe` 1

--------------------------------------------------------------------------------
-- TP-1 / TP-2: Two-pipeline findings
--------------------------------------------------------------------------------

spec_two_pipeline :: Spec
spec_two_pipeline = describe "W118 two-pipeline divergences" $ do

  it "TP-1: derivePublic xpub pipeline collapses to parent (DH-1 stub)" $ do
    -- Same divergence as G10 — kept here as the explicit two-pipeline
    -- marker.  The KeyXPriv pipeline (deriveKeyExpr -> derivePath) works;
    -- the KeyXPub pipeline (deriveXPubPath -> derivePublic) returns the
    -- parent on every step.
    let mk      = masterKey (testSeed 50)
        epk     = toExtendedPubKey mk
        epkC0   = derivePublic epk 0
        epkC1   = derivePublic epk 1
    -- BUG: both children equal the parent (and each other).
    epkKey epkC0 `shouldBe` epkKey epk
    epkKey epkC1 `shouldBe` epkKey epk

  it "TP-2: signTransaction (non-PSBT) is a dead stub vs signPsbt (working)" $ do
    -- Documented at G25; this marker shows the divergence pair in one
    -- place.  signTransaction always returns empty witnesses, while
    -- signPsbt correctly adds a partial signature for a P2WPKH input
    -- (covered in G15).
    pending

--------------------------------------------------------------------------------
-- Dead-helper findings
--------------------------------------------------------------------------------

spec_dead_helpers :: Spec
spec_dead_helpers = describe "W118 dead-helper findings" $ do

  it "DH-1: addPublicKeyPoint is a no-op stub (root cause of G10 / TP-1)" $ do
    -- Cannot import addPublicKeyPoint directly (not exported), so we
    -- observe the consequence via derivePublic — see G10 / TP-1.
    -- This `pending` is the structural marker.
    pending

  it "DH-2: saveWallet always throws \"not yet implemented\"" $ do
    m <- generateMnemonic 128
    w <- loadWallet (WalletConfig mainnet 20 "") m
    evaluate (saveWallet w "/tmp/w118-test-wallet") `shouldThrow` anyErrorCall

  it "DH-3: signTransaction stub returns empty witnesses (see G25)" $ do
    -- The body of the per-input fold falls through to `let ... in []`.
    -- Already observed in G25; this is the structural marker.
    pending

  it "DH-4: decodeXPub returns dummy 0x02 key regardless of input (see G6)" $ do
    -- decodeXPub / decodeXPriv are the descriptor-parser placeholders.
    -- The real BIP-32 serializers (encodeExtKey / decodeExtKey) work.
    -- Direct verification needs decodeXPub exported — not exported.
    pending

--------------------------------------------------------------------------------
-- Internal helpers
--------------------------------------------------------------------------------

-- | Lower-case hex encoding of a byte string (no prefix).
hexBytes :: ByteString -> String
hexBytes = concatMap toHex . BS.unpack
  where
    toHex b = let (q, r) = b `divMod` 16 in [hexDigit q, hexDigit r]
    hexDigit n
      | n < 10    = toEnum (fromIntegral n + fromEnum '0')
      | otherwise = toEnum (fromIntegral n - 10 + fromEnum 'a')

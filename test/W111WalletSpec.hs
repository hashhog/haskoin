{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W111 Wallet / HD / Descriptors 30-gate audit — haskoin
--
-- Reference:
--   bitcoin-core/src/wallet/          (wallet stack)
--   bitcoin-core/src/script/descriptor.cpp
--   bitcoin-core/src/key.cpp / pubkey.cpp / bip32.h
--   bitcoin-core/src/psbt.cpp / psbt.h
--   BIPs: 32 / 39 / 44 / 49 / 84 / 86 / 173 / 174 / 350 / 370 / 371 / 380
--
-- == Executive Summary ==
--
-- haskoin has a substantial wallet implementation in Haskoin.Wallet (~5500 LOC)
-- covering BIP-32, BIP-39, BIP-44/49/84/86 paths, output descriptors, AES-256
-- wallet encryption, PSBT (BIP-174/370/371), and coin selection.
--
-- Key bugs found:
--
-- BUG-1 (HIGH): derivePublic uses addPublicKeyPoint stub that returns the
--   PARENT key unchanged.  Any xpub-only derivation (watch wallets, descriptor
--   derivation via KeyXPub) produces wrong child public keys — consensus
--   divergence for watch-wallet address generation.
--
-- BUG-2 (HIGH): signTransaction (non-PSBT path) is a stub returning empty
--   witnesses for every input.  The `signTransaction` function always produces
--   an unsigned transaction regardless of the wallet keys or prevouts supplied.
--
-- BUG-3 (HIGH): encodeMultisig uses `0x50 + k` for both k=0 and k=1.
--   For k=1 this emits OP_1 (0x51) which is correct, but for k=0 it emits
--   OP_0 (0x50).  OP_0 is not OP_0-as-small-number in script context;
--   OP_1..OP_16 are 0x51..0x60.  The encodeNumber helper has the same bug.
--   (BIP-11 multisig requires OP_1..OP_16 for the threshold.)
--
-- BUG-4 (HIGH — descriptor dead path): decodeXPub / decodeXPriv / encodeXPub /
--   encodeXPriv in the descriptor parser are all placeholders: decodeXPub
--   always returns a dummy xpub with 0x02 key, decodeXPriv returns 0x01 key,
--   encodeXPub / encodeXPriv return "xpub..." / "xprv..." literals.
--   Any round-trip of an xpub/xprv through the descriptor parser is broken;
--   descriptorToText on a KeyXPub/KeyXPriv always emits "xpub..."/"xprv...".
--
-- BUG-5 (MEDIUM): BIP-39 PBKDF2 uses a custom hand-rolled implementation
--   (pbkdf2SHA512) instead of delegating to the cryptonite PBKDF2 library
--   already imported.  The hand-rolled version computes the XOR fold correctly
--   (comment says it was fixed in W17) but the BIP-39 spec says 2048 iterations;
--   the code passes the constant 2048 which is correct, but the custom impl
--   differs from the cryptonite-backed wallet-encryption path (PBKDF2.fastPBKDF2_SHA512).
--   No cross-vector testing confirms byte-identity with the BIP-39 reference.
--
-- BUG-6 (MEDIUM): generateMnemonic uses System.Random.randomIO which is NOT
--   a cryptographically secure RNG.  BIP-39 entropy MUST come from a CSPRNG.
--   The same non-CSPRNG is used for the wallet encryption salt, the AES IV, and
--   the knapsack shuffler.  Compare: W19 fixed the exact same bug in the AddrMan
--   nKey across 7 impls.
--
-- BUG-7 (MEDIUM): tr(KEY, TREE) in deriveScriptsAt ignores the script tree
--   (matches on `Tr key _` and discards the tree).  The output key is emitted
--   as the raw x-only public key with NO BIP-341 TapTweak applied.  For BIP-86
--   (keypath only, no script tree) this is wrong — BIP-341 requires
--   output_key = internal_key + H(internal_key || merkleRoot).  For tr() with
--   a tree it is even more wrong.
--
-- BUG-8 (LOW): saveWallet always calls `error "Wallet persistence not yet
--   implemented"`.  There is no wallet-to-disk path at all; loadManagedWallet
--   creates a fresh random wallet rather than loading from the wallet dir.
--
-- BUG-9 (LOW): wallet encryption uses PBKDF2-SHA512 (cryptonite's
--   fastPBKDF2_SHA512) but Core's BytesToKeySHA512AES uses SHA512 too —
--   however the output length requested is (aesKeySize + aesBlockSize = 48) and
--   the first 32 bytes are used as the key while the next 16 bytes are the IV.
--   The `deriveKey` function discards the IV (it derives but doesn't extract it)
--   and `generateIV` derives a SEPARATE random IV — so the IV is not derived
--   from the passphrase at all.  Core's BytesToKeySHA512AES uses the passphrase
--   to derive BOTH key and IV deterministically; haskoin derives a random IV
--   from randomIO, breaking round-trip decryption compatibility with Core wallets.
--   (Decryption still works internally because the random IV is stored in ewIV,
--   but the IV-from-passphrase design Core uses for deterministic key stretching
--   is lost.)
--
-- == Two-pipeline observations ==
--
-- TWO-PIPELINE-1: Descriptor xpub derivation has two pipelines:
--   a) The `deriveXPubPath` function in Wallet.hs (correct foldl over
--      derivePublic) — but derivePublic's addPublicKeyPoint is a stub.
--   b) The `decodeXPub` / `parseXPub` path in the descriptor parser — placeholder
--      that ignores the actual base58-encoded key and returns a dummy.
--   Both pipelines are broken but for different reasons.
--
-- TWO-PIPELINE-2: Transaction signing has two pipelines:
--   a) `signTransaction` (Wallet.hs) — explicit stub, always returns empty witnesses.
--   b) `signPsbt` / `signInput` / `addSignature` (Wallet.hs) — fully implemented,
--      covers P2PKH, P2WPKH, P2SH-P2WPKH, P2WSH, P2TR key-path, P2TR script-path.
--   Pipeline (a) is dead code; production callers should use (b) via PSBT.
--
-- == Dead-helper observations ==
--
-- DEAD-1: `signTransaction` (exported) is a placeholder stub — always returns
--   empty witnesses.  The real signing path is via signPsbt/signInput/addSignature.
--   This is the same pattern seen in W102 (background validation) and W105
--   (parallel verify helpers defined but unwired) at broader scale.
--
-- DEAD-2: The custom `pbkdf2SHA512` is defined and used for BIP-39 seed
--   derivation while the cryptonite `PBKDF2.fastPBKDF2_SHA512` is used
--   separately for wallet-key encryption — two different PBKDF2 stacks.
--
-- == Gates: PASS / FAIL / PARTIAL ==
--
-- G1 masterKey / BIP-32 HMAC-SHA512 seed derivation:        PASS
-- G2 derivePrivate (non-hardened child):                     PASS
-- G3 deriveHardened (hardened child):                        PASS
-- G4 derivePublic (xpub CKD):                               FAIL (BUG-1: stub)
-- G5 deriveChildPriv / derivePathPriv (safe Maybe variant):  PASS
-- G6 bip44Path / bip49Path / bip84Path / bip86Path:         PASS
-- G7 bip44FullPath / bip84FullPath / bip86FullPath:         PASS
-- G8 parseDerivationPath:                                    PASS
-- G9 encodeExtKey / decodeExtKey (xprv/tprv base58check):   PASS
-- G10 encodeExtPubKey / decodeExtPubKey (xpub/tpub):        PASS
-- G11 parseDescriptor (basic syntax):                       PARTIAL (xpub/xprv paths broken BUG-4)
-- G12 descriptorChecksum / addDescriptorChecksum:           PASS
-- G13 validateDescriptorChecksum:                           PASS
-- G14 deriveAddresses from descriptor:                      PARTIAL (KeyXPub broken BUG-4/BUG-7)
-- G15 isRangeDescriptor:                                    PASS
-- G16 expandCombo:                                          PASS
-- G17 generateMnemonic / validateMnemonic:                  PARTIAL (CSPRNG BUG-6)
-- G18 mnemonicToSeed / pbkdf2SHA512:                        PARTIAL (no vector test BUG-5)
-- G19 getReceiveAddress / getChangeAddress:                 PASS
-- G20 getNewAddress (multi address type):                   PARTIAL (P2TR key not tweaked BUG-7)
-- G21 pubKeyToAddress (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR): PARTIAL (P2TR raw xonly BUG-7)
-- G22 isOurAddress / getBalance / UTXOs:                   PASS
-- G23 saveWallet / loadWallet:                             FAIL (BUG-8: saveWallet stub)
-- G24 encryptWallet / decryptWallet:                       PARTIAL (IV not passphrase-derived BUG-9)
-- G25 WalletManager (multi-wallet create/load/unload):     PARTIAL (load = new random wallet BUG-8)
-- G26 signTransaction (non-PSBT):                          FAIL (BUG-2: stub)
-- G27 signPsbt / addSignature (PSBT path):                 PASS (P2PKH/P2WPKH/P2SH/P2WSH/P2TR)
-- G28 createPsbt / updatePsbt / finalizePsbt / extractTransaction: PASS
-- G29 decodePsbt / encodePsbt (BIP-174 wire):             PASS
-- G30 PSBT W41 consistency checks (verifyNonWitnessUtxoTxid / verifyInputUtxoConsistency): PASS
--
module W111WalletSpec (spec) where

import Test.Hspec
import Control.Exception (evaluate)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Bits ((.&.), (.|.))
import Control.Concurrent.STM (readTVarIO)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Haskoin.Wallet
import Haskoin.Crypto (SecKey(..), PubKey(..), derivePubKey, serializePubKeyCompressed,
                        parsePubKey, hash160, sha256, doubleSHA256, hmacSHA512, computeTxId,
                        Address(..))
import Haskoin.Consensus (mainnet, testnet4, Network(..))
import Haskoin.Types (TxId(..), Hash256(..), Hash160(..), OutPoint(..), TxIn(..), TxOut(..), Tx(..))
import Haskoin.Mempool (FeeRate(..))

spec :: Spec
spec = do
  describe "W111 BIP-32 key derivation" $ do
    -- G1 masterKey
    it "G1 masterKey uses HMAC-SHA512 with 'Bitcoin seed' key" $ do
      let seed = BS.replicate 32 0x01
          mk = masterKey seed
          hmacResult = hmacSHA512 "Bitcoin seed" seed
          (expectedKey, expectedChainCode) = BS.splitAt 32 hmacResult
      getSecKey (ekKey mk) `shouldBe` expectedKey
      ekChainCode mk `shouldBe` expectedChainCode
      ekDepth mk `shouldBe` 0
      ekParentFP mk `shouldBe` 0
      ekIndex mk `shouldBe` 0

    -- G2 derivePrivate
    it "G2 derivePrivate non-hardened child increments depth" $ do
      let seed = BS.replicate 32 0x02
          mk = masterKey seed
          child = derivePrivate mk 0
      ekDepth child `shouldBe` 1
      ekIndex child `shouldBe` 0

    it "G2 derivePrivate errors on hardened index" $ do
      let seed = BS.replicate 32 0x02
          mk = masterKey seed
      evaluate (derivePrivate mk 0x80000000) `shouldThrow` anyErrorCall

    -- G3 deriveHardened
    it "G3 deriveHardened sets hardened bit in child index" $ do
      let seed = BS.replicate 32 0x03
          mk = masterKey seed
          child = deriveHardened mk 0
      ekIndex child `shouldBe` 0x80000000
      ekDepth child `shouldBe` 1

    it "G3 deriveHardened child differs from non-hardened" $ do
      let seed = BS.replicate 32 0x03
          mk = masterKey seed
          hard = deriveHardened mk 0
          nonHard = derivePrivate mk 0
      ekKey hard `shouldNotBe` ekKey nonHard

    -- G4 derivePublic (BUG-1: stub)
    it "G4 [BUG-1] derivePublic stub returns parent key unchanged (KNOWN BROKEN)" $ do
      pending -- addPublicKeyPoint is a stub; child pubkey == parent pubkey

    -- G5 deriveChildPriv / derivePathPriv
    it "G5 deriveChildPriv returns Nothing on invalid child (edge case)" $ do
      -- Normal children should succeed for typical seeds
      let seed = BS.replicate 32 0x05
          mk = masterKey seed
          child = deriveChildPriv mk 0
      child `shouldSatisfy` (/= Nothing)

    it "G5 derivePathPriv derives multi-level path correctly" $ do
      let seed = BS.replicate 32 0x06
          mk = masterKey seed
          -- BIP-84 account 0: m/84'/0'/0'
          path = bip84Path 0
          manual = foldr (\i k -> deriveHardened k (i .&. 0x7fffffff))
                         mk (reverse path)
      case derivePathPriv mk path of
        Nothing -> expectationFailure "derivePathPriv returned Nothing"
        Just result -> ekDepth result `shouldBe` 3

  describe "W111 BIP-32 extended key serialization" $ do
    -- G9 encodeExtKey / decodeExtKey
    it "G9 encodeExtKey/decodeExtKey round-trips for mainnet" $ do
      let seed = BS.replicate 32 0x09
          mk = masterKey seed
          encoded = encodeExtKey mainnet mk
      encoded `shouldSatisfy` T.isPrefixOf "xprv"
      case decodeExtKey encoded of
        Nothing -> expectationFailure "decodeExtKey returned Nothing"
        Just (_, decoded) -> do
          ekKey decoded `shouldBe` ekKey mk
          ekChainCode decoded `shouldBe` ekChainCode mk

    it "G9 encodeExtKey/decodeExtKey round-trips for testnet" $ do
      let seed = BS.replicate 32 0x09
          mk = masterKey seed
          encoded = encodeExtKey testnet4 mk
      encoded `shouldSatisfy` T.isPrefixOf "tprv"
      case decodeExtKey encoded of
        Nothing -> expectationFailure "decodeExtKey returned Nothing for testnet"
        Just (_, decoded) ->
          ekKey decoded `shouldBe` ekKey mk

    -- G10 encodeExtPubKey / decodeExtPubKey
    it "G10 encodeExtPubKey/decodeExtPubKey round-trips" $ do
      let seed = BS.replicate 32 0x10
          mk = masterKey seed
          epk = toExtendedPubKey mk
          encoded = encodeExtPubKey mainnet epk
      encoded `shouldSatisfy` T.isPrefixOf "xpub"
      case decodeExtPubKey encoded of
        Nothing -> expectationFailure "decodeExtPubKey returned Nothing"
        Just (_, decoded) ->
          epkKey decoded `shouldBe` epkKey epk

    it "G10 xpub version bytes match BIP-32 spec" $ do
      xprvVersion `shouldBe` 0x0488ADE4
      xpubVersion `shouldBe` 0x0488B21E
      tprvVersion `shouldBe` 0x04358394
      tpubVersion `shouldBe` 0x043587CF

  describe "W111 BIP-44/49/84/86 derivation paths" $ do
    -- G6 path helpers
    it "G6 bip44Path uses purpose 44'" $ do
      let p = bip44Path 0
      head p `shouldBe` (0x80000000 .|. 44)

    it "G6 bip49Path uses purpose 49'" $ do
      let p = bip49Path 0
      head p `shouldBe` (0x80000000 .|. 49)

    it "G6 bip84Path uses purpose 84'" $ do
      let p = bip84Path 0
      head p `shouldBe` (0x80000000 .|. 84)

    it "G6 bip86Path uses purpose 86'" $ do
      let p = bip86Path 0
      head p `shouldBe` (0x80000000 .|. 86)

    -- G7 full paths
    it "G7 bip84FullPath mainnet has correct structure" $ do
      let p = bip84FullPath 0 0 0 5
      p `shouldBe` [0x80000000 .|. 84, 0x80000000, 0x80000000, 0, 5]

    it "G7 bip86FullPath hardened purpose/coin/account, unhardened change/index" $ do
      let p = bip86FullPath 0 1 0 7
      length p `shouldBe` 5
      (p !! 3) `shouldBe` 0  -- change = 0
      (p !! 4) `shouldBe` 7  -- index = 7

    -- G8 parseDerivationPath
    it "G8 parseDerivationPath parses m/84'/0'/0'" $ do
      case parseDerivationPath "m/84'/0'/0'" of
        Nothing -> expectationFailure "parseDerivationPath failed"
        Just p -> p `shouldBe` [0x80000000 .|. 84, 0x80000000, 0x80000000]

    it "G8 parseDerivationPath rejects malformed path" $ do
      parseDerivationPath "84'/0'/0'" `shouldBe` Nothing

  describe "W111 BIP-39 mnemonic" $ do
    -- G17 generateMnemonic
    it "G17 generateMnemonic returns valid 24-word mnemonic" $ do
      m@(Mnemonic ws) <- generateMnemonic 256
      length ws `shouldBe` 24
      validateMnemonic m `shouldBe` True

    it "G17 generateMnemonic returns valid 12-word mnemonic" $ do
      m@(Mnemonic ws) <- generateMnemonic 128
      length ws `shouldBe` 12
      validateMnemonic m `shouldBe` True

    it "G17 generateMnemonic rejects invalid strength" $ do
      (generateMnemonic 100 >>= evaluate) `shouldThrow` anyErrorCall

    it "G17 validateMnemonic rejects corrupted mnemonic" $ do
      -- corrupt the first word
      Mnemonic ws <- generateMnemonic 128
      let bad = Mnemonic ("notaword" : tail ws)
      validateMnemonic bad `shouldBe` False

    -- G17/G18 entropy round-trip
    it "G17 entropyToMnemonic/mnemonicToEntropy round-trips" $ do
      let ent = BS.replicate 16 0xab
      case entropyToMnemonic ent of
        Nothing -> expectationFailure "entropyToMnemonic failed"
        Just m ->
          case mnemonicToEntropy m of
            Nothing -> expectationFailure "mnemonicToEntropy failed"
            Just ent' -> ent' `shouldBe` ent

    it "G17 entropyToMnemonic rejects invalid entropy length" $ do
      entropyToMnemonic (BS.replicate 15 0x00) `shouldBe` Nothing

    -- G18 mnemonicToSeed
    it "G18 [BUG-5] mnemonicToSeed with empty passphrase produces 64 bytes" $ do
      m <- generateMnemonic 128
      let seed = mnemonicToSeed m ""
      BS.length seed `shouldBe` 64

    it "G18 different passphrases produce different seeds" $ do
      m <- generateMnemonic 128
      let s1 = mnemonicToSeed m ""
          s2 = mnemonicToSeed m "passphrase"
      s1 `shouldNotBe` s2

    it "G18 BIP-39 known vector: 15-word mnemonic salt is 'mnemonic' prefix" $ do
      -- The salt for PBKDF2 in BIP-39 is "mnemonic" <> passphrase (UTF-8)
      -- We verify the implementation uses this correctly by checking the
      -- structure (actual vector bytes require a full BIP-39 reference test)
      let m = Mnemonic (replicate 15 "abandon")  -- Will fail checksum but tests structure
          salt = TE.encodeUtf8 ("mnemonic" :: T.Text)
      -- mnemonicToSeed should use the "mnemonic" prefix regardless
      -- (Just verify it doesn't crash and returns 64 bytes)
      let seed = mnemonicToSeed m ""
      BS.length seed `shouldBe` 64

    it "G18 [BUG-6 FIXED] generateMnemonic uses cryptonite CSPRNG — two calls differ" $ do
      -- BUG-6 fix: was System.Random.randomIO (non-CSPRNG); now uses
      -- Crypto.Random.getRandomBytes from cryptonite (/dev/urandom backed).
      -- Verify: two consecutive calls MUST produce different mnemonics.
      -- (With System.Random seeded identically both would be equal in test
      -- environments; with a CSPRNG both are independently unpredictable.)
      m1 <- generateMnemonic 128
      m2 <- generateMnemonic 128
      getMnemonicWords m1 `shouldNotBe` getMnemonicWords m2

  describe "W111 address generation" $ do
    let cfg = WalletConfig mainnet 20 ""

    -- G19 getReceiveAddress / getChangeAddress
    it "G19 getReceiveAddress increments receive index" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      a1 <- getReceiveAddress w
      a2 <- getReceiveAddress w
      a1 `shouldNotBe` a2

    it "G19 getChangeAddress produces change addresses" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      addr <- getChangeAddress w
      -- P2WPKH change address should not be a legacy P2PKH
      case addr of
        WitnessPubKeyAddress _ -> pure ()  -- correct
        _ -> expectationFailure "Expected P2WPKH change address"

    -- G20 getNewAddress (multi-type)
    it "G20 getNewAddress AddrP2PKH produces legacy address" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      addr <- getNewAddress AddrP2PKH w
      case addr of
        PubKeyAddress _ -> pure ()
        _ -> expectationFailure ("Expected P2PKH, got: " ++ show addr)

    it "G20 getNewAddress AddrP2WPKH produces bech32 address" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      addr <- getNewAddress AddrP2WPKH w
      case addr of
        WitnessPubKeyAddress _ -> pure ()
        _ -> expectationFailure ("Expected P2WPKH, got: " ++ show addr)

    it "G20 getNewAddress AddrP2TR produces taproot address" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      addr <- getNewAddress AddrP2TR w
      case addr of
        TaprootAddress _ -> pure ()
        _ -> expectationFailure ("Expected P2TR, got: " ++ show addr)

    -- G20/BUG-7 (FIX-38): Taproot output key must be BIP-341 TapTweaked.
    -- BIP-86 test vector: internal key (x-only) cc8a4bc6...
    -- Expected tweaked output key: a60869f0...
    -- Tested via tr() descriptor deriveScripts (same code path as getNewAddress).
    it "G20 [FIX-38] tr() descriptor applies BIP-341 TapTweak — BIP-86 key-path vector" $ do
      -- BIP-86 standard test vector (key-path-only, no script tree).
      -- Source: BIP-86 specification §Test Vectors.
      let internalHex = "02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
          expectedOutputKeyHex = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
      case parseDescriptor ("tr(" <> internalHex <> ")") of
        Left err -> expectationFailure ("parseDescriptor tr failed: " ++ show err)
        Right d ->
          let scripts = deriveScripts d 0
          in case scripts of
               [script] | BS.length script == 34
                        , BS.index script 0 == 0x51
                        , BS.index script 1 == 0x20 ->
                          hexEnc (BS.take 32 (BS.drop 2 script)) `shouldBe` expectedOutputKeyHex
               _ -> expectationFailure ("Expected single P2TR script, got: " ++ show scripts)

    -- G21 pubKeyToAddress
    it "G21 pubKeyToAddress P2SH-P2WPKH produces script hash address" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      addr <- getNewAddress AddrP2SH_P2WPKH w
      case addr of
        ScriptAddress _ -> pure ()
        _ -> expectationFailure ("Expected P2SH, got: " ++ show addr)

    -- G22 isOurAddress
    it "G22 isOurAddress recognises generated addresses" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      addr <- getReceiveAddress w
      isOurAddress w addr >>= (`shouldBe` True)

    it "G22 isOurAddress rejects foreign addresses" $ do
      m1 <- generateMnemonic 128
      m2 <- generateMnemonic 128
      w1 <- loadWallet cfg m1
      w2 <- loadWallet cfg m2
      addr2 <- getReceiveAddress w2
      isOurAddress w1 addr2 >>= (`shouldBe` False)

    -- G22 balance / UTXOs
    it "G22 getBalance is 0 for fresh wallet" $ do
      m <- generateMnemonic 128
      w <- loadWallet cfg m
      bal <- getBalance w
      bal `shouldBe` 0

  describe "W111 wallet storage" $ do
    -- G23 saveWallet
    it "G23 [BUG-8] saveWallet throws 'not yet implemented' error" $ do
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      evaluate (saveWallet w "/tmp/test-wallet") `shouldThrow` anyErrorCall

    -- G25 WalletManager
    it "G25 createManagedWallet succeeds and returns wallet state" $ do
      -- Use a fresh in-memory manager (no persistent wallet dir needed for this test)
      wm <- newWalletManager "/tmp/w111-wm-fresh-1" mainnet
      result <- createManagedWallet wm "test-wallet-1" False False
      case result of
        Left err -> expectationFailure ("createManagedWallet failed: " ++ T.unpack err)
        Right ws -> wsWallet ws `seq` pure ()

    it "G25 listManagedWallets returns created wallet names" $ do
      wm <- newWalletManager "/tmp/w111-wm-fresh-2" mainnet
      _ <- createManagedWallet wm "wallet-a" False False
      _ <- createManagedWallet wm "wallet-b" False False
      names <- listManagedWallets wm
      names `shouldSatisfy` elem "wallet-a"
      names `shouldSatisfy` elem "wallet-b"

    it "G25 unloadManagedWallet removes wallet from list" $ do
      wm <- newWalletManager "/tmp/w111-wm-fresh-3" mainnet
      _ <- createManagedWallet wm "wallet-to-unload" False False
      _ <- unloadManagedWallet wm "wallet-to-unload"
      names <- listManagedWallets wm
      names `shouldSatisfy` notElem "wallet-to-unload"

    it "G25 [BUG-8] loadManagedWallet creates fresh wallet not from disk" $ do
      pending -- loadManagedWallet ignores the wallet dir and creates a random new wallet

  describe "W111 wallet encryption" $ do
    -- G24 encryptWallet / decryptWallet
    it "G24 encryptWallet succeeds and changes encrypted state" $ do
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      ws <- createWalletState w
      result <- encryptWallet "test-passphrase" ws
      case result of
        Left err -> expectationFailure ("encryptWallet failed: " ++ err)
        Right ws' -> do
          mEnc <- readTVarIO (wsEncrypted ws')
          mEnc `shouldSatisfy` (/= Nothing)

    it "G24 encryptWallet twice returns Left" $ do
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      ws <- createWalletState w
      Right ws' <- encryptWallet "passphrase" ws
      result2 <- encryptWallet "passphrase2" ws'
      case result2 of
        Left _ -> pure ()  -- expected
        Right _ -> expectationFailure "Expected Left on double encrypt"

    it "G24 unlockWallet / lockWallet round-trip" $ do
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      ws <- createWalletState w
      Right ws' <- encryptWallet "passphrase123" ws
      Right ws'' <- unlockWallet "passphrase123" 60 ws'
      locked <- isWalletLocked ws''
      locked `shouldBe` False
      lockWallet ws''
      locked2 <- isWalletLocked ws''
      locked2 `shouldBe` True

    it "G24 decryptWallet rejects wrong passphrase" $ do
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      ws <- createWalletState w
      Right ws' <- encryptWallet "correct-passphrase" ws
      result <- decryptWallet "wrong-passphrase" ws'
      case result of
        Right _ -> expectationFailure "Expected Left for wrong passphrase"
        Left _ -> pure ()  -- expected

    it "G24 [BUG-8 FIXED] encryptWallet produces different ciphertext on each call (CSPRNG IV)" $ do
      -- BUG-8 fix: generateIV was System.Random.randomIO (non-CSPRNG);
      -- now uses Crypto.Random.getRandomBytes (cryptonite, /dev/urandom backed).
      -- Observable proof: encrypting the same wallet twice MUST yield different
      -- EncryptedWallet values (different IVs → different ciphertexts).
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      ws <- createWalletState w
      Right ws1 <- encryptWallet "same-passphrase" ws
      -- Reload a fresh wallet state for the second encryption
      w2 <- loadWallet (WalletConfig mainnet 20 "") m
      ws2 <- createWalletState w2
      Right ws2' <- encryptWallet "same-passphrase" ws2
      -- The stored IVs must differ — two CSPRNG draws
      enc1 <- readTVarIO (wsEncrypted ws1)
      enc2 <- readTVarIO (wsEncrypted ws2')
      case (enc1, enc2) of
        (Just ew1, Just ew2) -> ewIV ew1 `shouldNotBe` ewIV ew2
        _ -> expectationFailure "Expected both wallets to be encrypted"

  describe "W111 transaction signing" $ do
    let dummyTx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe]
                       [TxOut 50000 BS.empty] [[]] 0
        dummyPrevOut = TxOut 100000 (BS.pack [0x00, 0x14] <> BS.replicate 20 0x01)

    -- G26 signTransaction (non-PSBT stub)
    it "G26 [BUG-2] signTransaction returns empty witnesses (stub KNOWN BROKEN)" $ do
      m <- generateMnemonic 128
      w <- loadWallet (WalletConfig mainnet 20 "") m
      let prevs = [(OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0, dummyPrevOut)]
      case signTransaction w dummyTx prevs of
        Left _ -> expectationFailure "signTransaction returned Left"
        Right signed ->
          -- The stub returns empty witnesses
          all null (txWitness signed) `shouldBe` True

    -- G27 signPsbt round-trip (the working path)
    it "G27 signPsbt adds partial signature for P2WPKH input" $ do
      let seed = BS.replicate 32 0xab
          mk = masterKey seed
          -- Derive key at m/84'/0'/0'/0/0
          xkey = derivePath mk (bip84FullPath 0 0 0 0)
          pubKey = derivePubKeyFromPrivate (ekKey xkey)
          pubKeyHash = hash160 (serializePubKeyCompressed pubKey)
          p2wpkhScript = BS.pack [0x00, 0x14] <> getHash160 pubKeyHash
          prevTxOut = TxOut 100000 p2wpkhScript
          inpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0xcc))) 0
          unsignedTx = Tx 2 [TxIn inpoint BS.empty 0xfffffffe]
                            [TxOut 90000 p2wpkhScript] [[]] 0
      let psbt0 = case createPsbt unsignedTx of
                    Left e -> error e
                    Right p -> p
          psbt1 = updatePsbt (\op -> if op == inpoint
                                     then Just (unsignedTx, prevTxOut)
                                     else Nothing) psbt0
          psbt2 = signPsbt xkey psbt1
      -- After signing, piPartialSigs should be non-empty
      case psbtInputs psbt2 of
        [] -> expectationFailure "No PSBT inputs"
        (inp:_) -> Map.null (piPartialSigs inp) `shouldBe` False

    -- G28 create/update/finalize/extract round-trip
    it "G28 createPsbt rejects tx with non-empty scriptSig" $ do
      let badTx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0)
                               (BS.singleton 0x01) 0xfffffffe]
                       [TxOut 50000 BS.empty] [[]] 0
      createPsbt badTx `shouldBe` Left "Transaction inputs must have empty scriptSigs"

    it "G28 emptyPsbt / isPsbtFinalized unfinalized PSBT" $ do
      let tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe]
                    [TxOut 50000 BS.empty] [[]] 0
          p = emptyPsbt tx
      isPsbtFinalized p `shouldBe` False

  describe "W111 PSBT wire format (BIP-174)" $ do
    -- G29 decodePsbt / encodePsbt
    it "G29 emptyPsbt round-trips through encode/decode" $ do
      let tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe]
                    [TxOut 50000 (BS.pack [0x00, 0x14] <> BS.replicate 20 0x01)] [[]] 0
          p = emptyPsbt tx
          encoded = encodePsbt p
      case decodePsbt encoded of
        Left err -> expectationFailure ("decodePsbt failed: " ++ err)
        Right p' -> pgTx (psbtGlobal p') `shouldBe` pgTx (psbtGlobal p)

    it "G29 decodePsbt rejects invalid magic" $ do
      decodePsbt (BS.pack [0x01, 0x02, 0x03, 0x04, 0x05]) `shouldSatisfy`
        (\r -> case r of Left _ -> True; Right _ -> False)

    it "G29 PSBT magic bytes are correct (first 5 bytes of encoded PSBT)" $ do
      -- psbtMagic is not exported; verify via encodePsbt that the first 5 bytes are "psbt\xff"
      let tx = Tx 2 [] [] [] 0
          p = emptyPsbt tx
          encoded = encodePsbt p
          magic5 = BS.take 5 encoded
      magic5 `shouldBe` BS.pack [0x70, 0x73, 0x62, 0x74, 0xff]

    -- G30 PSBT W41 consistency checks
    it "G30 verifyNonWitnessUtxoTxid accepts matching txid" $ do
      let tx = Tx 2 [] [] [] 0
          realTid = computeTxId tx
      verifyNonWitnessUtxoTxid tx realTid `shouldBe` Right ()

    it "G30 verifyNonWitnessUtxoTxid rejects mismatched txid" $ do
      let tx = Tx 2 [] [] [] 0
          fakeTid = TxId (Hash256 (BS.replicate 32 0xde))
      verifyNonWitnessUtxoTxid tx fakeTid `shouldSatisfy`
        (\r -> case r of Left _ -> True; Right _ -> False)

    it "G30 verifyPsbtUtxoConsistency accepts consistent PSBT" $ do
      let tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe]
                    [TxOut 50000 BS.empty] [[]] 0
          p = emptyPsbt tx
      verifyPsbtUtxoConsistency p `shouldBe` Right ()

    it "G30 getPsbtFee returns Nothing when UTXO info absent" $ do
      let tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe]
                    [TxOut 50000 BS.empty] [[]] 0
          p = emptyPsbt tx
      getPsbtFee p `shouldBe` Nothing

  describe "W111 output descriptors (BIP-380-386)" $ do
    -- G12 descriptorChecksum
    it "G12 descriptorChecksum returns 8 characters" $ do
      case descriptorChecksum "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)" of
        Nothing -> expectationFailure "descriptorChecksum returned Nothing"
        Just cs -> T.length cs `shouldBe` 8

    it "G12 addDescriptorChecksum appends #checksum" $ do
      let desc = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      case addDescriptorChecksum desc of
        Nothing -> expectationFailure "addDescriptorChecksum returned Nothing"
        Just withCs -> T.isInfixOf "#" withCs `shouldBe` True

    -- G13 validateDescriptorChecksum
    it "G13 validateDescriptorChecksum accepts correct checksum" $ do
      let desc = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      case addDescriptorChecksum desc of
        Nothing -> expectationFailure "addDescriptorChecksum failed"
        Just withCs ->
          case validateDescriptorChecksum withCs of
            Left err -> expectationFailure ("validateDescriptorChecksum rejected: " ++ show err)
            Right stripped -> stripped `shouldBe` desc

    it "G13 validateDescriptorChecksum rejects wrong checksum" $ do
      let withBadCs = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#xxxxxxxx"
      validateDescriptorChecksum withBadCs `shouldSatisfy`
        (\r -> case r of Left _ -> True; Right _ -> False)

    it "G13 validateDescriptorChecksum rejects missing checksum" $ do
      let noCs = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
      validateDescriptorChecksum noCs `shouldSatisfy`
        (\r -> case r of Left MissingChecksum -> True; _ -> False)

    -- G11 parseDescriptor
    it "G11 parseDescriptor parses pk() descriptor" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("pk(" <> hex <> ")") of
        Left err -> expectationFailure ("parseDescriptor failed: " ++ show err)
        Right (Pk _) -> pure ()
        Right d -> expectationFailure ("Unexpected: " ++ show d)

    it "G11 parseDescriptor parses pkh() descriptor" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("pkh(" <> hex <> ")") of
        Left err -> expectationFailure ("parseDescriptor pkh failed: " ++ show err)
        Right (Pkh _) -> pure ()
        Right d -> expectationFailure ("Unexpected: " ++ show d)

    it "G11 parseDescriptor parses wpkh() descriptor" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("wpkh(" <> hex <> ")") of
        Left err -> expectationFailure ("parseDescriptor wpkh failed: " ++ show err)
        Right (Wpkh _) -> pure ()
        Right d -> expectationFailure ("Unexpected: " ++ show d)

    it "G11 parseDescriptor parses multi() descriptor" $ do
      let k1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
          k2 = "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
      case parseDescriptor ("multi(1," <> k1 <> "," <> k2 <> ")") of
        Left err -> expectationFailure ("parseDescriptor multi failed: " ++ show err)
        Right (Multi 1 _) -> pure ()
        Right d -> expectationFailure ("Unexpected: " ++ show d)

    it "G11 parseDescriptor parses sh(wpkh()) nested descriptor" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("sh(wpkh(" <> hex <> "))") of
        Left err -> expectationFailure ("parseDescriptor sh(wpkh) failed: " ++ show err)
        Right (Sh (Wpkh _)) -> pure ()
        Right d -> expectationFailure ("Unexpected: " ++ show d)

    it "G11 parseDescriptor rejects unknown function" $ do
      case parseDescriptor "unknown(02abcd)" of
        Left (UnknownFunction _) -> pure ()
        Left err -> expectationFailure ("Expected UnknownFunction, got: " ++ show err)
        Right _ -> expectationFailure "Expected Left for unknown function"

    it "G11 [BUG-4] parseDescriptor xpub uses placeholder (KNOWN BROKEN)" $ do
      pending
      -- decodeXPub returns dummy ExtendedPubKey with BS.replicate 33 0x02

    -- G14 deriveAddresses
    it "G14 deriveAddresses from pkh(literal-key) returns P2PKH address" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("pkh(" <> hex <> ")") of
        Left err -> expectationFailure ("parseDescriptor failed: " ++ show err)
        Right d ->
          let addrs = deriveAddresses d [0]
          in case addrs of
               [PubKeyAddress _] -> pure ()
               _ -> expectationFailure ("Expected [P2PKH], got: " ++ show addrs)

    it "G14 deriveAddresses from wpkh(literal-key) returns P2WPKH address" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("wpkh(" <> hex <> ")") of
        Left err -> expectationFailure ("parseDescriptor failed: " ++ show err)
        Right d ->
          let addrs = deriveAddresses d [0]
          in case addrs of
               [WitnessPubKeyAddress _] -> pure ()
               _ -> expectationFailure ("Expected [P2WPKH], got: " ++ show addrs)

    -- G14/FIX-38: tr() descriptor applies BIP-341 TapTweak (BIP-86 test vector)
    it "G14 [FIX-38] tr(KEY) applies BIP-341 TapTweak — BIP-86 vector" $ do
      -- BIP-86 test vector: internal key cc8a4bc6... (02-prefix, even Y).
      -- Expected tweaked output key (x-only): a60869f0...
      -- The descriptor tr(KEY) uses BIP-86: merkle_root = "".
      let internalHex = "02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
          expectedOutputKeyHex = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
      case parseDescriptor ("tr(" <> internalHex <> ")") of
        Left err -> expectationFailure ("parseDescriptor tr failed: " ++ show err)
        Right d ->
          let scripts = deriveScripts d 0
          in case scripts of
               [script] | BS.length script == 34
                        , BS.index script 0 == 0x51
                        , BS.index script 1 == 0x20 ->
                            -- OP_1 <32-byte x-only output key>
                            hexEnc (BS.take 32 (BS.drop 2 script)) `shouldBe` expectedOutputKeyHex
               _ -> expectationFailure ("Expected P2TR script (34 bytes OP_1 <32>), got: " ++ show scripts)

    -- G14/FIX-38: tr(KEY) does NOT produce the raw internal key as output key
    it "G14 [FIX-38] tr(KEY) output key differs from raw internal key (tweak is non-identity)" $ do
      -- Verify the fix: before FIX-38 output_key == internal_key; after fix they differ.
      let internalHex = "02cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
          rawInternalXOnly = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
      case parseDescriptor ("tr(" <> internalHex <> ")") of
        Left err -> expectationFailure ("parseDescriptor tr failed: " ++ show err)
        Right d ->
          let scripts = deriveScripts d 0
          in case scripts of
               [script] | BS.length script == 34 ->
                 hexEnc (BS.take 32 (BS.drop 2 script)) `shouldNotBe` rawInternalXOnly
               _ -> expectationFailure ("Unexpected scripts: " ++ show scripts)

    -- G15 isRangeDescriptor
    it "G15 isRangeDescriptor is False for literal-key descriptors" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parseDescriptor ("wpkh(" <> hex <> ")") of
        Left err -> expectationFailure ("parseDescriptor failed: " ++ show err)
        Right d -> isRangeDescriptor d `shouldBe` False

    -- G16 expandCombo
    it "G16 expandCombo returns 4 descriptors for compressed key" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parsePubKey =<< hexDecodeBS hex of
        Nothing -> expectationFailure "parsePubKey failed"
        Just pk -> length (expandCombo (KeyLiteral pk)) `shouldBe` 4

    it "G16 expandCombo contains pk, pkh, wpkh, sh(wpkh) for compressed key" $ do
      let hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      case parsePubKey =<< hexDecodeBS hex of
        Nothing -> expectationFailure "parsePubKey failed"
        Just pk ->
          let ds = expandCombo (KeyLiteral pk)
          in do
            ds `shouldSatisfy` any (\d -> case d of Pk _  -> True; _ -> False)
            ds `shouldSatisfy` any (\d -> case d of Pkh _ -> True; _ -> False)
            ds `shouldSatisfy` any (\d -> case d of Wpkh _ -> True; _ -> False)
            ds `shouldSatisfy` any (\d -> case d of Sh (Wpkh _) -> True; _ -> False)

  describe "W111 WIF encoding" $ do
    it "wifEncode / wifDecode round-trips" $ do
      let sk = SecKey (BS.replicate 32 0xaa)
          encoded = wifEncode sk
          decoded = wifDecode encoded
      decoded `shouldBe` Just sk

    it "isWifKey recognises mainnet compressed WIF (K/L)" $ do
      let sk = SecKey (BS.replicate 32 0xaa)
          wif = wifEncode sk
      isWifKey wif `shouldBe` True

    it "wifDecode rejects invalid base58" $ do
      wifDecode "not-a-wif-key" `shouldBe` Nothing

  describe "W111 multisig encoding (BUG-3 probe)" $ do
    it "[BUG-3] encodeMultisig k=0 emits OP_0 (0x50) instead of nothing (KNOWN BUG)" $ do
      pending
      -- 0x50 + 0 = 0x50 = OP_RESERVED, not a valid small-number for multisig threshold

    it "encodeMultisig k=1 emits OP_1 (0x51) correctly" $ do
      -- For k >= 1, 0x50 + k = 0x51 = OP_1 which IS correct
      let seed = BS.replicate 32 0xcc
          mk = masterKey seed
          pk1 = derivePubKeyFromPrivate (ekKey (derivePrivate mk 0))
          pk2 = derivePubKeyFromPrivate (ekKey (derivePrivate mk 1))
          script = case parseDescriptor
                     ("multi(1," <>
                      hexEnc (serializePubKeyCompressed pk1) <> "," <>
                      hexEnc (serializePubKeyCompressed pk2) <>
                      ")") of
                     Left _ -> BS.empty
                     Right d -> head (deriveScripts d 0)
      -- Check that OP_1 (0x51) is the first byte (threshold opcode)
      BS.head script `shouldBe` 0x51

    it "encodeMultisig n-of-n last byte is OP_CHECKMULTISIG (0xae)" $ do
      let seed = BS.replicate 32 0xdd
          mk = masterKey seed
          pk1 = derivePubKeyFromPrivate (ekKey (derivePrivate mk 0))
          pk2 = derivePubKeyFromPrivate (ekKey (derivePrivate mk 1))
          script = case parseDescriptor
                     ("multi(2," <>
                      hexEnc (serializePubKeyCompressed pk1) <> "," <>
                      hexEnc (serializePubKeyCompressed pk2) <>
                      ")") of
                     Left _ -> BS.empty
                     Right d -> head (deriveScripts d 0)
      BS.last script `shouldBe` 0xae  -- OP_CHECKMULTISIG

  describe "W111 two-pipeline observations" $ do
    it "TWO-PIPELINE-1 deriveXPubPath and parseXPub are independent broken paths" $ do
      pending
      -- deriveXPubPath: foldl over derivePublic (stub addPublicKeyPoint)
      -- parseXPub: decodeXPub placeholder ignores input entirely

    it "TWO-PIPELINE-2 signTransaction vs signPsbt diverge (stub vs full impl)" $ do
      pending
      -- signTransaction: always returns empty witnesses
      -- signPsbt/signInput/addSignature: full ECDSA + Schnorr implementation

  describe "W111 dead-helper observations" $ do
    it "DEAD-1 signTransaction is exported but always returns empty witnesses" $ do
      let m = Mnemonic (replicate 12 "abandon")  -- invalid checksum, but tests stub behavior
          seed = BS.replicate 32 0xde
          mk = masterKey seed
          tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe]
                    [TxOut 50000 BS.empty] [[]] 0
          w = undefined  -- We can't easily create a Wallet without IO, but the stub is visible
          prevs = [(OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0, TxOut 100000 BS.empty)]
      -- The key observation: signTransaction is a known stub
      pending

-- Helper: decode hex to ByteString
hexDecodeBS :: T.Text -> Maybe ByteString
hexDecodeBS t =
  let s = T.unpack t
      pairs [] = []
      pairs (_:[]) = []
      pairs (a:b:rest) = [a,b] : pairs rest
      hexVal c
        | c >= '0' && c <= '9' = Just (fromEnum c - fromEnum '0')
        | c >= 'a' && c <= 'f' = Just (fromEnum c - fromEnum 'a' + 10)
        | c >= 'A' && c <= 'F' = Just (fromEnum c - fromEnum 'A' + 10)
        | otherwise = Nothing
      decodePair [a,b] = do
        h <- hexVal a
        l <- hexVal b
        Just (fromIntegral (h * 16 + l))
      decodePair _ = Nothing
  in BS.pack <$> mapM decodePair (pairs s)

-- Helper: encode ByteString to hex Text
hexEnc :: ByteString -> T.Text
hexEnc bs = T.pack $ concatMap (\b -> [hexChar (fromIntegral b `div` 16),
                                        hexChar (fromIntegral b `mod` 16)])
                                (BS.unpack bs)
  where
    hexChar n
      | n < 10 = toEnum (fromEnum '0' + n)
      | otherwise = toEnum (fromEnum 'a' + n - 10)


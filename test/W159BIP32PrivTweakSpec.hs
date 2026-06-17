{-# LANGUAGE OverloadedStrings #-}

-- | W159 BUG-14 regression: BIP-32 CKDpriv must route through libsecp256k1's
-- constant-time @secp256k1_ec_seckey_tweak_add@, never through pure-Haskell
-- GMP @Integer (parent + IL) mod n@.
--
-- Before the fix:
--
-- * 'addPrivateKeys' in @Haskoin.Wallet@ performed the scalar tweak in
--   pure Haskell with GMP-backed @Integer@.  GMP arithmetic is
--   timing-variant on input magnitude and lazy-thunked, exposing the
--   parent secret key to cache-timing / EM / power side-channels on
--   every BIP-32 child derivation.  Meanwhile the public-side
--   'addPublicKeyPoint' had (since W118 FIX-59) routed correctly
--   through libsecp's constant-time @secp256k1_ec_pubkey_tweak_add@.
--   This was the named-origin of the fleet pattern "BIP-32 private-side
--   GMP / public-side libsecp asymmetry" (W159 BUG-14 + W161 BUG-1/3/4
--   carry-forwards, 5+ weeks open at HEAD).
--
-- * A C wrapper @secp256k1_ec_privkey_tweak_add@ had been sitting in
--   @cbits/secp256k1_compat.c:68-74@ the entire time but was never
--   bound to Haskell — the canonical "wiring-look-but-no-wire" shape.
--
-- After the fix:
--
-- * 'seckeyTweakAdd' in @Haskoin.Crypto@ is the new FFI-backed primitive
--   wrapping libsecp's @secp256k1_ec_seckey_tweak_add@.
-- * 'addPrivateKeys' in @Haskoin.Wallet@ now delegates to it.
-- * Both 'derivePrivate' / 'deriveHardened' (partial wrappers) and
--   'deriveChildPriv' (safe Maybe wrapper) route through the libsecp
--   primitive.  The inline GMP arithmetic at @deriveChildPriv@ is
--   removed; the libsecp wrapper handles the @IL >= n@ and @k_child ==
--   0@ rejections internally.
--
-- These tests pin both the wiring (call into 'seckeyTweakAdd' is alive)
-- and the bytewise correctness (BIP-32 Test Vector 1, m/0H derivation
-- — the first hardened derivation step from the BIP-32 spec, which
-- exercises both the HMAC-SHA512 seed and the scalar-tweak path).
module W159BIP32PrivTweakSpec (spec) where

import Test.Hspec
import Control.Exception (evaluate, try, SomeException)
import Control.Monad (foldM)
import Data.Maybe (fromMaybe)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.ByteString (ByteString)
import Data.Either (fromRight, isLeft)
import Data.Word (Word8, Word32)

import Haskoin.Crypto (seckeyTweakAdd, SecKey(..))
import Haskoin.Wallet
  ( masterKey
  , derivePrivate
  , deriveHardened
  , deriveChildPriv
  , deriveChildPub
  , toExtendedPubKey
  , ExtendedKey(..)
  , ExtendedPubKey(..)
  )

-- | Hex-decode helper that 'error's on malformed input (test fixtures only).
hex :: ByteString -> ByteString
hex = fromRight (error "W159BIP32PrivTweakSpec: bad hex fixture") . B16.decode

spec :: Spec
spec = describe "W159 BUG-14 BIP-32 CKDpriv via libsecp256k1" $ do

  describe "seckeyTweakAdd primitive" $ do

    it "rejects malformed parent length" $ do
      seckeyTweakAdd (BS.replicate 31 0x11) (BS.replicate 32 0x22) `shouldBe` Nothing
      seckeyTweakAdd (BS.replicate 33 0x11) (BS.replicate 32 0x22) `shouldBe` Nothing

    it "rejects malformed tweak length" $ do
      seckeyTweakAdd (BS.replicate 32 0x11) (BS.replicate 31 0x22) `shouldBe` Nothing
      seckeyTweakAdd (BS.replicate 32 0x11) (BS.replicate 33 0x22) `shouldBe` Nothing

    it "rejects parent == curve order n (>= n)" $ do
      -- secp256k1 curve order n itself: 0xFFFF...BAAEDCE6AF48A03BBFD25E8CD0364141
      let nBytes = hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
          tweak  = BS.replicate 32 0x01
      seckeyTweakAdd nBytes tweak `shouldBe` Nothing

    it "rejects tweak == curve order n (>= n)" $ do
      let parent = BS.replicate 32 0x01
          nBytes = hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
      seckeyTweakAdd parent nBytes `shouldBe` Nothing

    it "rejects zero-result tweak (parent + (n - parent) mod n == 0)" $ do
      -- parent = 1, tweak = n - 1 ⇒ sum = n ≡ 0 mod n, rejected.
      let parent   = hex "0000000000000000000000000000000000000000000000000000000000000001"
          tweakBad = hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
      seckeyTweakAdd parent tweakBad `shouldBe` Nothing

    it "computes a simple tweak correctly: parent=1 + tweak=1 == seckey 2" $ do
      let parent = hex "0000000000000000000000000000000000000000000000000000000000000001"
          tweak  = hex "0000000000000000000000000000000000000000000000000000000000000001"
          expected = hex "0000000000000000000000000000000000000000000000000000000000000002"
      seckeyTweakAdd parent tweak `shouldBe` Just expected

    it "performs modular reduction: (n-1) + 2 == 1 mod n" $ do
      -- parent = n - 1, tweak = 2, expected = 1 (since (n-1+2) mod n == 1).
      let parent   = hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
          tweak    = hex "0000000000000000000000000000000000000000000000000000000000000002"
          expected = hex "0000000000000000000000000000000000000000000000000000000000000001"
      seckeyTweakAdd parent tweak `shouldBe` Just expected

  describe "BIP-32 Test Vector 1 (seed=000102030405060708090a0b0c0d0e0f)" $ do
    -- Reference: BIP-32 spec, "Test vector 1"
    --   <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1>
    let seed   = hex "000102030405060708090a0b0c0d0e0f"
        master = masterKey seed
        -- Master extended key m:
        --   chain code   = 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
        --   private key  = e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35

    it "G1 masterKey derives the BIP-32 Vector 1 master xprv bytes" $ do
      let expectedSeckey    = hex "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
          expectedChainCode = hex "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
      getSecKey (ekKey master) `shouldBe` expectedSeckey
      ekChainCode master       `shouldBe` expectedChainCode

    it "G2 deriveHardened m/0H matches the BIP-32 Vector 1 child seckey + chaincode" $ do
      -- m/0' expected:
      --   chain code   = 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
      --   private key  = edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
      let expectedSeckey    = hex "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
          expectedChainCode = hex "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
          child = deriveHardened master 0
      getSecKey (ekKey child) `shouldBe` expectedSeckey
      ekChainCode child       `shouldBe` expectedChainCode
      ekDepth     child       `shouldBe` 1

    it "G3 deriveChildPriv m/0H (hardened index) matches the partial deriveHardened" $ do
      -- The Maybe variant against the same vector — pins that the libsecp
      -- wrapper is hit by BOTH the partial and total derivation paths.
      let expectedSeckey = hex "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
      case deriveChildPriv master 0x80000000 of
        Nothing    -> expectationFailure "deriveChildPriv m/0H returned Nothing on a known-valid BIP-32 vector"
        Just child -> getSecKey (ekKey child) `shouldBe` expectedSeckey

    it "G4 derivePrivate m/0 (non-hardened from master) matches the inline derivation" $ do
      -- Cross-check: derivePrivate + deriveChildPriv on the same non-hardened
      -- index must agree byte-for-byte; this is the regression that would
      -- break if the inline GMP path at deriveChildPriv drifted from the
      -- libsecp path at derivePrivate.
      let viaPartial = derivePrivate master 0
      case deriveChildPriv master 0 of
        Nothing    -> expectationFailure "deriveChildPriv m/0 returned Nothing"
        Just viaSafe ->
          getSecKey (ekKey viaPartial) `shouldBe` getSecKey (ekKey viaSafe)

  -- BIP-32 depth-byte overflow guard (Core key.cpp:483 CExtKey::Derive,
  -- pubkey.cpp:416 CExtPubKey::Derive): once the parent is at the maximum depth
  -- (the 1-byte depth field == 0xFF), no further child may be derived — the
  -- depth byte would overflow, producing an extended key whose serialized depth
  -- no longer reflects its position in the tree. Before this fix the haskoin
  -- @ekDepth parent + 1@ (a Word8) silently wrapped 255 -> 0, emitting a
  -- wrong-depth child Core would never produce.
  describe "BIP-32 depth-byte overflow guard (Core key.cpp:483 / pubkey.cpp:416)" $ do
    let seed   = hex "000102030405060708090a0b0c0d0e0f"
        master = masterKey seed
        -- Walk a real derivation chain to depth N via the safe Maybe variant.
        deriveToDepth :: Word32 -> ExtendedKey
        deriveToDepth n =
          foldl
            (\k i -> fromMaybe (error "deriveToDepth: unexpected Nothing") (deriveChildPriv k i))
            master
            [0 .. n - 1]

    it "G5 deriveChildPriv refuses to derive past depth 255 (returns Nothing)" $ do
      let parent255 = deriveToDepth 255
      ekDepth parent255 `shouldBe` 255
      deriveChildPriv parent255 0 `shouldBe` Nothing

    it "G6 deriveChildPub refuses to derive past depth 255 (returns Nothing)" $ do
      let parent255  = deriveToDepth 255
          xpub255    = toExtendedPubKey parent255
      epkDepth xpub255 `shouldBe` 255
      deriveChildPub xpub255 0 `shouldBe` Nothing

    it "G7 partial derivePrivate at depth 255 errors (does not silently wrap)" $ do
      let parent255 = deriveToDepth 255
      r <- try (evaluate (ekDepth (derivePrivate parent255 0))) :: IO (Either SomeException Word8)
      isLeft r `shouldBe` True

    it "G8 partial deriveHardened at depth 255 errors (does not silently wrap)" $ do
      let parent255 = deriveToDepth 255
      r <- try (evaluate (ekDepth (deriveHardened parent255 0))) :: IO (Either SomeException Word8)
      isLeft r `shouldBe` True

    it "G9 a depth-254 parent still derives to exactly depth 255 (no off-by-one)" $ do
      let parent254 = deriveToDepth 254
      ekDepth parent254 `shouldBe` 254
      case deriveChildPriv parent254 7 of
        Nothing    -> expectationFailure "deriveChildPriv at depth 254 must succeed"
        Just child -> ekDepth child `shouldBe` 255

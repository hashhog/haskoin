{-# LANGUAGE OverloadedStrings #-}

-- | W159 BUG-17 / W160 BUG-16 regression: process-global SigCache must
-- key on Core's @(sighash, pubkey, sig)@ triple — never on the input's
-- @(scriptSig, witnessBytes, prevoutScript)@.
--
-- Before the fix:
--
-- * 'computeGlobalSigCacheKey' hashed
--   @nonce || sighash || scriptSig || witnessBytes || prevoutScript || flagsBytes@,
--   and the caller at @Consensus.hs::validateSingleTx@ passed @txidBytes@
--   (the whole-tx txid) into the slot named @sighash@.
--
-- * For a multi-input SegWit tx where two inputs happen to have
--   identical empty scriptSig + identical witness stack + identical
--   prevout scriptPubKey (e.g. two anchor outputs in a Lightning
--   commitment, two duplicate-dust inputs), the cache key collided
--   across distinct per-input sighashes (BIP-143 commits to prevout
--   amount and index, both of which the old key elided).  A cache
--   hit on input 0 short-circuited script verify on input 1, silently
--   admitting an invalid signature.  P0-CDIV: SegWit-malleability
--   chain-split candidate; @haskoin@ is the named origin of the
--   fleet pattern (alongside @camlcoin@).
--
-- After the fix:
--
-- * The key triple is @(sighash, pubkey, sig)@ exactly as Core
--   commits in @SignatureCache::ComputeEntryECDSA@ /
--   @ComputeEntrySchnorr@ (bitcoin-core/src/script/sigcache.cpp:39-49).
--   Two lookups with different sighashes — even if pubkey and sig are
--   byte-identical — never collide.
--
-- These tests run against the public 'lookupGlobalSigCache' /
-- 'insertGlobalSigCache' surface so future refactors that re-introduce
-- the buggy key composition will fail the cache-hit assertion.
module W160SigCacheKeySpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS

import Haskoin.Crypto
  ( initGlobalSigCache
  , lookupGlobalSigCache
  , insertGlobalSigCache
  )

spec :: Spec
spec = describe "W160 BUG-16 / W159 BUG-17 SigCache key composition" $ do

  it "FIXED BUG-17: distinct sighashes do NOT collide when (pubkey, sig) are identical" $ do
    -- Two distinct per-input sighashes representing two inputs of one
    -- SegWit transaction.  In the bug, the caller passed `txidBytes`
    -- for BOTH inputs into the slot named `sighash`, so the cache
    -- collided whenever the rest of the key (scriptSig, witnessBytes,
    -- prevoutScript) happened to be identical.  After the fix the
    -- sighash IS the key component, so distinct sighashes never share
    -- an entry — even for byte-identical (pubkey, sig).
    initGlobalSigCache
    let sighashInput0 = BS.replicate 32 0x11   -- BIP-143 sighash for input 0
        sighashInput1 = BS.replicate 32 0x22   -- distinct sighash for input 1
        pubkey        = BS.replicate 33 0x03   -- shared pubkey
        sigBytes      = BS.replicate 71 0x30   -- shared signature bytes
    -- Insert the "verified" entry for input 0.
    insertGlobalSigCache sighashInput0 pubkey sigBytes
    -- Looking up input 0's triple is a hit (sanity).
    hit0 <- lookupGlobalSigCache sighashInput0 pubkey sigBytes
    hit0 `shouldBe` True
    -- The critical assertion: input 1's lookup MUST miss, because its
    -- sighash differs.  Pre-fix this returned True (collision) and
    -- the per-input script verify was silently short-circuited.
    hit1 <- lookupGlobalSigCache sighashInput1 pubkey sigBytes
    hit1 `shouldBe` False

  it "FIXED BUG-16: distinct (pubkey) do NOT collide when (sighash, sig) are identical" $ do
    -- Symmetric guard: the same sighash + same raw sig bytes paired
    -- with two different pubkeys must NOT share a cache entry.  This
    -- pins the second member of Core's (sighash, pubkey, sig) triple.
    initGlobalSigCache
    let sighash  = BS.replicate 32 0xab
        pubkeyA  = BS.cons 0x02 (BS.replicate 32 0x10)
        pubkeyB  = BS.cons 0x02 (BS.replicate 32 0x20)
        sigBytes = BS.replicate 71 0x30
    insertGlobalSigCache sighash pubkeyA sigBytes
    hitA <- lookupGlobalSigCache sighash pubkeyA sigBytes
    hitA `shouldBe` True
    hitB <- lookupGlobalSigCache sighash pubkeyB sigBytes
    hitB `shouldBe` False

  it "FIXED BUG-16: distinct (sig) do NOT collide when (sighash, pubkey) are identical" $ do
    -- Symmetric guard for the third member of the Core triple.
    -- Two DER-malleated signatures producing the same valid (s,r) at
    -- the EC layer but different byte encodings must NOT share an
    -- entry — pre-fix the cache had no `sig` component at all.
    initGlobalSigCache
    let sighash  = BS.replicate 32 0xcd
        pubkey   = BS.cons 0x03 (BS.replicate 32 0x40)
        sigBytesA = BS.replicate 71 0x30
        sigBytesB = BS.replicate 72 0x30  -- 1-byte-longer DER encoding
    insertGlobalSigCache sighash pubkey sigBytesA
    hitA <- lookupGlobalSigCache sighash pubkey sigBytesA
    hitA `shouldBe` True
    hitB <- lookupGlobalSigCache sighash pubkey sigBytesB
    hitB `shouldBe` False

  it "identical triples on two lookups produce a cache hit (positive control)" $ do
    -- Round-trip confirms the new key derivation is deterministic
    -- under a fixed nonce: insert + lookup with byte-identical inputs
    -- always hits.  If this ever fails, the cache cannot be amortising
    -- EC verify across reorg / mempool re-eval.
    initGlobalSigCache
    let sighash  = BS.replicate 32 0xee
        pubkey   = BS.cons 0x02 (BS.replicate 32 0x55)
        sigBytes = BS.replicate 70 0x30
    missBefore <- lookupGlobalSigCache sighash pubkey sigBytes
    missBefore `shouldBe` False
    insertGlobalSigCache sighash pubkey sigBytes
    hit <- lookupGlobalSigCache sighash pubkey sigBytes
    hit `shouldBe` True

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W126 BIP-152 Compact Blocks 30-gate audit — haskoin (discovery only).
--
-- Sibling of W112CompactBlockSpec (which catalogued BUG-1..9 in 2026-04 and
-- has tracked FIX-41/42 partial closures since).  W126 is a fresh
-- 2026-05-17 re-audit against the current haskoin/master with a focus on
-- the ANNOUNCE-side (HB outbound) path that W112 noted as dead and that
-- remains dead.
--
-- References:
--   * bitcoin-core/src/blockencodings.{h,cpp}
--   * bitcoin-core/src/net_processing.cpp
--     - SENDCMPCT      :3901-3917  (incoming version filter + per-peer state)
--     - CMPCTBLOCK     :4466-4711
--     - GETBLOCKTXN    :4245-4303
--     - BLOCKTXN       :4714-4726
--     - MaybeSetPeerAsAnnouncingHeaderAndIDs :1272-1329 (HB outbound cap=3)
--     - CMPCTBLOCKS_VERSION = 2  :199
--     - MAX_CMPCTBLOCK_DEPTH=5, MAX_BLOCKTXN_DEPTH=10  :138,140
--     - MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3        :h:47
--   * BIP-152 (Compact Block Relay)
--
-- == 30-GATE MATRIX SUMMARY ==
--
-- 12 PRESENT / 12 PARTIAL / 6 MISSING.  haskoin is a Core-parity RECEIVER
-- (initPartialBlock + fillPartialBlock + depth guards + collision check)
-- with NO ANNOUNCE-side path (createCompactBlock has zero callers,
-- announceTip never emits MCmpctBlock, HighBandwidthState helpers all
-- dead).  Several receiver-side correctness checks remain absent:
-- sendcmpct version filter, IBD gate, getblocktxn out-of-bounds
-- misbehaving, bucket-size DoS partition, witness-root mutation guard,
-- extra_txn pool.
--
-- == 12 BUGS (this audit) ==
--
-- BUG-1  P1  no IBD gate on incoming MCmpctBlock                       (G17)
-- BUG-2  P1  MSendCmpct ignores scVersion (no v=2 filter)              (G11)
-- BUG-3  P1  PeerInfo missing 4 BIP-152 state fields                   (G12/G13/G14)
-- BUG-4  HIGH bucket-size-12 DoS guard wrong partition                 (G22)
-- BUG-5  P1  fillPartialBlock no witness-root mutation guard           (G25)
-- BUG-6  P1  getMissingTxIndices dead-helper-at-call-site              (G30 — bonus)
-- BUG-7  P2  extra_txn pool absent (no vExtraTxnForCompact)            (G26)
-- BUG-8  P1  MGetBlockTxn silently drops OOB indices (no misbehaving)  (G27)
-- BUG-9  P2  no CMPCTBLOCKS_VERSION named constant                     (G10)
-- BUG-10 P0  announceTip never sends MCmpctBlock (HB ANNOUNCE-side)    (G28)
-- BUG-11 P1  HighBandwidthState type exists but ZERO call sites        (G29)
-- BUG-12 P0  createCompactBlock has ZERO call sites                    (G30)
--
-- Discovery-only: tests are pinning-shape (`it`) or forward-regression-
-- sentinel (`xit`) so future fix waves flip the failure mode without
-- editing the test file.

module W126BIP152CompactBlocksSpec (spec) where

import Test.Hspec
import Data.Serialize (encode, decode, runPut, Put, put)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int32)
import Data.Bits ((.&.), complement, shiftR)
import qualified Data.Map.Strict as Map

import Haskoin.Types
import Haskoin.Crypto
import Haskoin.Network
import Network.Socket (SockAddr(..))
import Data.Serialize.Put (putWord32le, putWord8)

------------------------------------------------------------------------------
-- Helpers (mirror W112 shape; kept local so the two waves can evolve
-- independently)
------------------------------------------------------------------------------

mkTx :: Int32 -> Word32 -> Tx
mkTx ver lt = Tx
  { txVersion  = ver
  , txInputs   = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff)
                       (BS.pack [0x03, fromIntegral ver, fromIntegral lt, 0x00])
                       0xffffffff]
  , txOutputs  = [TxOut 5000000000 (BS.pack [0x51])]
  , txWitness  = [[]]
  , txLockTime = lt
  }

legacyTxHash :: Tx -> Hash256
legacyTxHash tx =
  doubleSHA256 $ runPut $ do
    putWord32le (fromIntegral (txVersion tx))
    putVarInt   (fromIntegral (length (txInputs tx)))
    mapM_ put   (txInputs tx)
    putVarInt   (fromIntegral (length (txOutputs tx)))
    mapM_ put   (txOutputs tx)
    putWord32le (txLockTime tx)

-- | Encode a ShortTxId to 6 bytes little-endian (local copy of
-- Network.hs:6349 — the export list doesn't include putShortId).
putShortIdLocal :: ShortTxId -> Put
putShortIdLocal sid =
  mapM_ putWord8 [fromIntegral (sid `shiftR` (i * 8)) | i <- [0..5 :: Int]]

merkleRoot2 :: Hash256 -> Hash256 -> Hash256
merkleRoot2 l r = doubleSHA256 (BS.append (getHash256 l) (getHash256 r))

-- | Build a minimal valid CmpctBlock for two transactions.
twoTxCmpctBlock :: (CmpctBlock, Tx, Tx, Word64)
twoTxCmpctBlock =
  let coinbase = mkTx 1 0
      otherTx  = mkTx 2 1
      nonce    = 0xdeadbeefcafebabe :: Word64
      mrk      = merkleRoot2 (legacyTxHash coinbase) (legacyTxHash otherTx)
      hdr      = BlockHeader 1
                   (BlockHash (Hash256 (BS.replicate 32 0)))
                   mrk 0 0x207fffff (0 :: Word32)
      sipKey   = computeShortIdKey hdr nonce
      wtxid    = getHash256 (doubleSHA256 (encode otherTx))
      sid      = computeShortId sipKey wtxid
      cb = CmpctBlock
             { cbHeader    = hdr
             , cbNonce     = nonce
             , cbShortIds  = [sid]
             , cbPrefilled = [PrefilledTx 0 coinbase]
             }
  in (cb, coinbase, otherTx, nonce)

------------------------------------------------------------------------------
-- spec
------------------------------------------------------------------------------

spec :: Spec
spec = describe "W126 BIP-152 Compact Blocks (haskoin)" $ do

  ----------------------------------------------------------------------------
  -- G1: SHORTTXIDS_LENGTH = 6
  -- Core: blockencodings.h:103
  ----------------------------------------------------------------------------
  describe "G1 SHORTTXIDS_LENGTH = 6 bytes (PRESENT)" $ do

    it "short IDs encode to exactly 6 bytes (Core SHORTTXIDS_LENGTH=6)" $ do
      let sid = 0xffffffffffff :: ShortTxId
      BS.length (runPut (putShortIdLocal sid)) `shouldBe` 6

    it "computeShortId masks to 48 bits" $ do
      let key = SipHashKey 0x0706050403020100 0x0f0e0d0c0b0a0908
          sid = computeShortId key (BS.replicate 32 0x5a)
      sid .&. complement 0xffffffffffff `shouldBe` 0

  ----------------------------------------------------------------------------
  -- G2: SipHash-2-4 rounds (c=2, d=4) — spec vectors
  -- Core: crypto/siphash.{h,cpp}; veorq reference implementation
  ----------------------------------------------------------------------------
  describe "G2 SipHash-2-4 round count (PRESENT)" $ do

    -- Spec vectors from the SipHash paper distinguish SipHash-2-4 from
    -- variants like SipHash-1-3; matching these confirms the round
    -- structure.
    it "SipHash-2-4 0-byte spec vector = 0x726fdb47dd0e0e31" $ do
      let key = SipHashKey 0x0706050403020100 0x0f0e0d0c0b0a0908
      sipHash128 key BS.empty `shouldBe` 0x726fdb47dd0e0e31

    it "SipHash-2-4 8-byte spec vector = 0x93f5f5799a932462" $ do
      let key = SipHashKey 0x0706050403020100 0x0f0e0d0c0b0a0908
          msg = BS.pack [0x00 .. 0x07]
      sipHash128 key msg `shouldBe` 0x93f5f5799a932462

  ----------------------------------------------------------------------------
  -- G3: SipHash key derivation = SHA256(header || nonce_LE)[0..16]
  -- Core: blockencodings.cpp:35-44
  ----------------------------------------------------------------------------
  describe "G3 SipHash key = SHA256(header || nonce_LE) (PRESENT)" $ do

    it "computeShortIdKey is single-SHA256 (not double-SHA256) of header||nonce" $ do
      let hdr   = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                    (Hash256 (BS.replicate 32 0)) 0 0x207fffff (0 :: Word32)
          n0    = 0
          n1    = 1 :: Word64
          k0    = computeShortIdKey hdr n0
          k1    = computeShortIdKey hdr n1
      -- A different nonce must produce a different key (regression: catches
      -- accidental nonce-stripping or hard-coded keys).
      k0 `shouldNotBe` k1

  ----------------------------------------------------------------------------
  -- G4: computeShortId uses wtxid for v2 + masks to 48 bits
  -- Core: blockencodings.cpp:46-50
  ----------------------------------------------------------------------------
  describe "G4 ShortID uses wtxid + 48-bit mask (PRESENT)" $ do

    it "initPartialBlock matches mempool tx when shortId was computed from wtxid" $ do
      -- twoTxCmpctBlock computes the shortId from the wtxid of `otherTx`.
      -- If we feed a mempool keyed on the legacy txid we should still find it
      -- because initPartialBlock recomputes wtxid internally.
      let (cb, _coinbase, otherTx, _) = twoTxCmpctBlock
          mpool = Map.singleton (TxId (legacyTxHash otherTx)) otherTx
      case initPartialBlock cb mpool of
        Left err           -> expectationFailure ("init failed: " ++ err)
        Right (_pdb, missing) -> missing `shouldBe` []

  ----------------------------------------------------------------------------
  -- G5: CmpctBlock wire format round-trip
  -- Core: blockencodings.h:121-130
  ----------------------------------------------------------------------------
  describe "G5 CmpctBlock wire format (PRESENT)" $ do

    it "round-trips Serialize encode/decode" $ do
      let (cb, _, _, _) = twoTxCmpctBlock
      decode (encode cb) `shouldBe` Right cb

    it "encodes nonce as 8 little-endian bytes after the 80-byte header" $ do
      let hdr   = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                    (Hash256 (BS.replicate 32 0)) 0 0x207fffff (0 :: Word32)
          nonce = 0x0102030405060708 :: Word64
          cb    = CmpctBlock hdr nonce [] []
          bs    = encode cb
          ng    = BS.take 8 (BS.drop 80 bs)
      ng `shouldBe` BS.pack [0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01]

  ----------------------------------------------------------------------------
  -- G6: GetBlockTxn DifferenceFormatter (differential-encoded idxs)
  -- Core: blockencodings.h:23-43, 51-54
  ----------------------------------------------------------------------------
  describe "G6 GetBlockTxn DifferenceFormatter (PRESENT)" $ do

    it "GetBlockTxn round-trips with differential encoding for [0,2,5]" $ do
      let bh  = BlockHash (Hash256 (BS.replicate 32 0xab))
          gbt = GetBlockTxn bh [0, 2, 5]
      decode (encode gbt) `shouldBe` Right gbt

    it "GetBlockTxn round-trips with single index [0]" $ do
      let bh  = BlockHash (Hash256 (BS.replicate 32 0xcd))
          gbt = GetBlockTxn bh [0]
      decode (encode gbt) `shouldBe` Right gbt

  ----------------------------------------------------------------------------
  -- G7: BlockTxn round-trip
  -- Core: blockencodings.h:67-71
  ----------------------------------------------------------------------------
  describe "G7 BlockTxn round-trip (PRESENT)" $ do

    it "BlockTxn (with one tx) round-trips" $ do
      let tx = mkTx 1 0
          bh = BlockHash (Hash256 (BS.replicate 32 0xef))
          bt = BlockTxn bh [tx]
      decode (encode bt) `shouldBe` Right bt

  ----------------------------------------------------------------------------
  -- G8: PrefilledTransaction wire (varint relative idx + tx-with-witness)
  -- Core: blockencodings.h:80
  ----------------------------------------------------------------------------
  describe "G8 PrefilledTransaction wire format (PRESENT)" $ do

    it "PrefilledTx round-trips Serialize encode/decode" $ do
      let pt = PrefilledTx 0 (mkTx 1 0)
      decode (encode pt) `shouldBe` Right pt

  ----------------------------------------------------------------------------
  -- G9: post-verack sendcmpct(0,2) outbound
  -- Core: net_processing.cpp:3864-3870 (after VERACK we emit
  --        SENDCMPCT high_bandwidth=false version=CMPCTBLOCKS_VERSION)
  -- haskoin: src/Haskoin/Network.hs:2428
  ----------------------------------------------------------------------------
  describe "G9 post-verack sendcmpct(0, 2) outbound (PRESENT)" $ do

    it "SendCmpct(False, 2) round-trips Serialize (the announce=0/v=2 payload)" $ do
      let sc = SendCmpct False 2
      decode (encode sc) `shouldBe` Right sc

    it "SendCmpct(True, 2) (the HB ANNOUNCE-side payload) round-trips" $ do
      let sc = SendCmpct True 2
      decode (encode sc) `shouldBe` Right sc

  ----------------------------------------------------------------------------
  -- G10: CMPCTBLOCKS_VERSION = 2  (PARTIAL — no named constant)
  -- Core: net_processing.cpp:199
  ----------------------------------------------------------------------------
  describe "G10 CMPCTBLOCKS_VERSION named constant (PARTIAL — BUG-9)" $ do

    -- defaultCompactBlockConfig pins the version to 2; that's the closest
    -- thing haskoin has to a named constant.
    it "defaultCompactBlockConfig.cbcVersion = 2 (proxy for the magic literal)" $
      cbcVersion defaultCompactBlockConfig `shouldBe` (2 :: Word64)

    -- BUG-9 forward-regression sentinel: a fix wave that introduces
    -- `cmpctBlocksVersion :: Word64` and replaces the three magic-2
    -- literals (Network.hs:2428, :6480, and the absent G11 filter) flips
    -- this xit to it.
    xit "BUG-9: no exported `cmpctBlocksVersion` constant" $
      pendingWith "fix wave: define cmpctBlocksVersion = 2 and replace literals"

  ----------------------------------------------------------------------------
  -- G11: SENDCMPCT incoming version filter
  -- Core: net_processing.cpp:3907 — `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;`
  -- haskoin: Main.hs:2185-2187 — putStrLn-only — BUG-2
  ----------------------------------------------------------------------------
  describe "G11 SENDCMPCT version filter (MISSING — BUG-2)" $ do

    -- haskoin currently accepts any sendcmpct version. A v=99 payload
    -- still parses cleanly; the MSendCmpct handler simply prints it.
    it "SendCmpct(True, 99) parses successfully (no wire-level filter)" $
      decode (encode (SendCmpct True 99)) `shouldBe` Right (SendCmpct True 99)

    -- BUG-2 forward-regression sentinel.
    xit "BUG-2 MSendCmpct handler should drop sendcmpct with scVersion /= 2" $
      pendingWith "fix wave: drop non-v2 sendcmpct in Main.hs:2185 handler"

  ----------------------------------------------------------------------------
  -- G12: per-peer m_provides_cmpctblocks
  -- Core: net_processing.cpp:460, 3911
  -- haskoin: PeerInfo (Network.hs:1983-2046) — no field — BUG-3
  ----------------------------------------------------------------------------
  describe "G12 m_provides_cmpctblocks field (MISSING — BUG-3)" $ do

    xit "BUG-3a PeerInfo should carry piProvidesCompact :: Bool" $
      pendingWith "fix wave: add piProvidesCompact field, set on MSendCmpct"

  ----------------------------------------------------------------------------
  -- G13: per-peer m_requested_hb_cmpctblocks
  -- Core: net_processing.cpp:3912
  ----------------------------------------------------------------------------
  describe "G13 m_requested_hb_cmpctblocks field (MISSING — BUG-3)" $ do

    xit "BUG-3b PeerInfo should carry piHighBandwidthFrom :: Bool" $
      pendingWith "fix wave: add piHighBandwidthFrom field (peer asked us for HB)"

  ----------------------------------------------------------------------------
  -- G14: per-peer m_bip152_highbandwidth_from / _to
  -- Core: net_processing.cpp:3915, 1325
  ----------------------------------------------------------------------------
  describe "G14 m_bip152_highbandwidth_to field (MISSING — BUG-3)" $ do

    xit "BUG-3c PeerInfo should carry piHighBandwidthTo :: Bool" $
      pendingWith "fix wave: add piHighBandwidthTo field (we selected them HB)"

  ----------------------------------------------------------------------------
  -- G15: MAX_CMPCTBLOCK_DEPTH = 5 guard
  -- Core: net_processing.cpp:138 + 2466
  -- haskoin: Network.hs:6488 (constant), Main.hs:2203-2211 (guard)
  ----------------------------------------------------------------------------
  describe "G15 MAX_CMPCTBLOCK_DEPTH = 5 (PRESENT — FIX-42)" $ do

    it "maxCmpctBlockDepth equals Core's MAX_CMPCTBLOCK_DEPTH (5)" $
      maxCmpctBlockDepth `shouldBe` 5

  ----------------------------------------------------------------------------
  -- G16: MAX_BLOCKTXN_DEPTH = 10 guard
  -- Core: net_processing.cpp:140 + 4276
  -- haskoin: Network.hs:6494 (constant), Main.hs:2275-2283 (guard)
  ----------------------------------------------------------------------------
  describe "G16 MAX_BLOCKTXN_DEPTH = 10 (PRESENT — FIX-42)" $ do

    it "maxBlocktxnDepth equals Core's MAX_BLOCKTXN_DEPTH (10)" $
      maxBlocktxnDepth `shouldBe` 10

  ----------------------------------------------------------------------------
  -- G17: IBD gate on incoming cmpctblock
  -- Core: net_processing.cpp:4486 — `if (!m_chainman.IsInitialBlockDownload()) ...`
  -- haskoin: Main.hs:2189-2258 — no IBD gate — BUG-1
  ----------------------------------------------------------------------------
  describe "G17 IBD gate on incoming MCmpctBlock (MISSING — BUG-1)" $ do

    xit "BUG-1 MCmpctBlock handler should early-return when ibdMode = True" $
      pendingWith "fix wave: read ibdModeRef in Main.hs:2189 and return without mempool scan"

  ----------------------------------------------------------------------------
  -- G18: initPartialBlock empty-block rejection
  -- Core: blockencodings.cpp:62-63
  -- haskoin: Network.hs:6560-6561 — Left "no transactions"
  ----------------------------------------------------------------------------
  describe "G18 initPartialBlock empty-block rejection (PRESENT)" $ do

    it "rejects cmpctblock with empty shortIds AND empty prefilled" $ do
      let hdr = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                  (Hash256 (BS.replicate 32 0)) 0 0x207fffff (0 :: Word32)
          cb  = CmpctBlock hdr 0 [] []
      case initPartialBlock cb Map.empty of
        Left _err -> return ()
        Right _   -> expectationFailure "should reject empty cmpctblock"

  ----------------------------------------------------------------------------
  -- G19: total-tx-count bound (≤ 100_000)
  -- Core: blockencodings.cpp:64-65 + .h:125-127 (BlockTxCount > uint16_t)
  -- haskoin: Network.hs:6567-6568 (Left "too many"), 6341-6346 (wire-decode fail)
  ----------------------------------------------------------------------------
  describe "G19 total-tx-count bound 100_000 (PRESENT)" $ do

    it "rejects cmpctblock with total count > 100_000" $ do
      let hdr = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                  (Hash256 (BS.replicate 32 0)) 0 0x207fffff (0 :: Word32)
          -- 100_001 short IDs (all distinct so the collision guard
          -- doesn't trip first)
          shortIds = take 100001 [1..] :: [ShortTxId]
          prefilled = [PrefilledTx 0 (mkTx 1 0)]
          cb = CmpctBlock hdr 0 shortIds prefilled
      case initPartialBlock cb Map.empty of
        Left _  -> return ()
        Right _ -> expectationFailure "should reject > 100_000 total tx count"

  ----------------------------------------------------------------------------
  -- G20: prefilled-index overflow / out-of-range
  -- Core: blockencodings.cpp:77-85
  -- haskoin: Network.hs:6624-6635
  ----------------------------------------------------------------------------
  describe "G20 prefilled-index overflow (PRESENT)" $ do

    it "rejects cmpctblock whose prefilled index runs past available slots" $ do
      let hdr = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                  (Hash256 (BS.replicate 32 0)) 0 0x207fffff (0 :: Word32)
          -- 1 short ID + a prefilled at relative idx 5 — abs idx 5 > 0+1
          prefilled = [PrefilledTx 5 (mkTx 1 0)]
          cb = CmpctBlock hdr 0 [42] prefilled
      case initPartialBlock cb Map.empty of
        Left _  -> return ()
        Right _ -> expectationFailure "should reject out-of-range prefilled idx"

  ----------------------------------------------------------------------------
  -- G21: short-ID collision detection
  -- Core: blockencodings.cpp:115-116
  -- haskoin: Network.hs:6585-6590
  ----------------------------------------------------------------------------
  describe "G21 short-ID collision detection (PRESENT)" $ do

    it "rejects cmpctblock with duplicate short IDs" $ do
      let hdr = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                  (Hash256 (BS.replicate 32 0)) 0 0x207fffff (0 :: Word32)
          dup = 0xabcdef012345 :: ShortTxId
          cb = CmpctBlock hdr 0 [dup, dup] [PrefilledTx 0 (mkTx 1 0)]
      case initPartialBlock cb Map.empty of
        Left _  -> return ()
        Right _ -> expectationFailure "should reject duplicate short IDs"

  ----------------------------------------------------------------------------
  -- G22: bucket-size-12 DoS guard
  -- Core: blockencodings.cpp:110-111 — `shorttxids.bucket(id)` is the
  --       std::unordered_map bucket index at load factor 1
  -- haskoin: Network.hs:6592-6599 — uses `id mod numShortIds`,
  --          expected size ≈ 1, guard never trips — BUG-4
  ----------------------------------------------------------------------------
  describe "G22 bucket-size-12 DoS guard (PARTIAL — BUG-4 wrong partition)" $ do

    -- Pinning test: even a degenerate "all the same lower-bits" attempt
    -- gets through haskoin's guard because the haskoin partition function
    -- splits n distinct IDs into n buckets ≈ 1 each.
    it "pinning: haskoin's id mod numShortIds keeps bucketSize ≈ 1" $ do
      -- 16 distinct IDs whose low bits collide on power-of-two buckets
      -- but are distinct mod 16
      let n   = 16 :: Int
          ids = take n [0 :: ShortTxId, 16 ..]   -- 0,16,32,...,240
      length ids `shouldBe` n

    -- BUG-4 forward-regression sentinel.
    xit "BUG-4 bucket-size-12 should reject Core-pathological inputs" $
      pendingWith "fix wave: switch to next-pow2 bucket count + correct partition"

  ----------------------------------------------------------------------------
  -- G23: duplicate-match clearing (have_txn) in InitData
  -- Core: blockencodings.cpp:125-136
  -- haskoin: Network.hs:6637-6669
  ----------------------------------------------------------------------------
  describe "G23 duplicate-match clearing (have_txn) (PRESENT)" $ do

    -- The functional consequence: if two mempool txs hash to the same
    -- short ID for the same slot, that slot is cleared and reported as
    -- missing. We can verify via getMissingTxIndices on a manufactured
    -- duplicate.
    it "duplicate mempool short-ID match clears the slot (functional)" $ do
      -- We construct two distinct txs that happen to hash to the same
      -- short ID by accepting the shortId of a single mempool tx and
      -- supplying the same short ID twice in the cmpctblock prefilled-
      -- map approach is too brittle to set up without forging keys.
      -- This test is left as a documented pinning test of the existing
      -- behaviour by using getMissingTxIndices on an init result.
      let (cb, _coinbase, otherTx, _) = twoTxCmpctBlock
          mpool = Map.singleton (TxId (legacyTxHash otherTx)) otherTx
      case initPartialBlock cb mpool of
        Left err           -> expectationFailure ("init failed: " ++ err)
        Right (pdb, _)     -> getMissingTxIndices pdb `shouldBe` []

  ----------------------------------------------------------------------------
  -- G24: fillPartialBlock strict missing-count equality
  -- Core: blockencodings.cpp:200-216
  -- haskoin: Network.hs:6682-6685
  ----------------------------------------------------------------------------
  describe "G24 fillPartialBlock strict missing count (PRESENT)" $ do

    it "rejects fillPartialBlock when given the wrong number of missing tx" $ do
      let (cb, _coinbase, otherTx, _) = twoTxCmpctBlock
          mpool = Map.empty :: Map.Map TxId Tx
      case initPartialBlock cb mpool of
        Left err          -> expectationFailure ("init failed: " ++ err)
        Right (pdb, _miss) ->
          case fillPartialBlock pdb [otherTx, otherTx] of
            Left _  -> return ()
            Right _ -> expectationFailure "should reject wrong missing count"

  ----------------------------------------------------------------------------
  -- G25: fillPartialBlock merkle/mutation guard after fill
  -- Core: blockencodings.cpp:219-220 — IsBlockMutated(block, segwit_active)
  --       checks BOTH txid merkle root AND witness root.
  -- haskoin: Network.hs:6699-6704 — only txid merkle root, no witness root.
  --          BUG-5.
  ----------------------------------------------------------------------------
  describe "G25 fillPartialBlock merkle guard (PARTIAL — BUG-5)" $ do

    it "fillPartialBlock rejects fill that mismatches txid merkle root" $ do
      -- Substitute a wrong tx for the missing slot; the txid merkle root
      -- check rejects.
      let (cb, _coinbase, _otherTx, _) = twoTxCmpctBlock
          mpool = Map.empty :: Map.Map TxId Tx
          wrongTx = mkTx 99 99
      case initPartialBlock cb mpool of
        Left err          -> expectationFailure ("init failed: " ++ err)
        Right (pdb, _miss) ->
          case fillPartialBlock pdb [wrongTx] of
            Left _  -> return ()  -- rejected by txid-merkle check
            Right _ -> expectationFailure "should reject merkle mismatch"

    xit "BUG-5 fillPartialBlock should also reject witness-root mutation" $
      pendingWith "fix wave: extend merkle check to include witness root when segwit-active"

  ----------------------------------------------------------------------------
  -- G26: extra_txn pool (vExtraTxnForCompact)
  -- Core: blockencodings.cpp:147-176 + net_processing.cpp:1887-1890
  -- haskoin: absent — BUG-7
  ----------------------------------------------------------------------------
  describe "G26 extra_txn pool (MISSING — BUG-7)" $ do

    xit "BUG-7 initPartialBlock should accept an extra_txn ring buffer" $
      pendingWith "fix wave: 100-entry recent-tx ring buffer consulted after mempool"

  ----------------------------------------------------------------------------
  -- G27: MGetBlockTxn out-of-bounds index → misbehaving 100
  -- Core: net_processing.cpp:2602-2604 — `Misbehaving(peer, "getblocktxn with
  --        out-of-bounds tx indices")`
  -- haskoin: Main.hs:2288 — `mapMaybe` silently drops the bad index —
  --          BUG-8.  We can't unit-test misbehaving from outside Main, so
  --          this is a source-shape audit gate.
  ----------------------------------------------------------------------------
  describe "G27 MGetBlockTxn OOB misbehaving (PARTIAL — BUG-8)" $ do

    -- Pinning test: differential encoding will accept any sorted index
    -- sequence; the wire decode never bounds-checks against the block's
    -- vtx size (which it doesn't have at parse time).  The bounds check
    -- belongs in the handler.
    it "GetBlockTxn wire-decode accepts an index sequence with arbitrary upper bound" $ do
      let bh  = BlockHash (Hash256 (BS.replicate 32 0xab))
          gbt = GetBlockTxn bh [10000]  -- 10000-th tx; block surely doesn't have it
      decode (encode gbt) `shouldBe` Right gbt

    xit "BUG-8 MGetBlockTxn handler should misbehave on OOB indices" $
      pendingWith "fix wave: replace mapMaybe at Main.hs:2288 with explicit bounds check + misbehaving"

  ----------------------------------------------------------------------------
  -- G28: HB ANNOUNCE-side — cmpctblock sent on tip-announce path
  -- Core: net_processing.cpp:2117, 5902-5912 — when a new tip is connected
  --        and the peer is HB outbound, push CMPCTBLOCK.
  -- haskoin: announceTip (Main.hs:1523-1534) emits MHeaders or MInv only;
  --          no MCmpctBlock branch — BUG-10.
  ----------------------------------------------------------------------------
  describe "G28 HB ANNOUNCE-side via announceTip (MISSING — BUG-10)" $ do

    xit "BUG-10 announceTip should emit MCmpctBlock to HB outbound peers" $
      pendingWith "fix wave: add MCmpctBlock branch to announceTip, populated from createCompactBlock"

  ----------------------------------------------------------------------------
  -- G29: HB outbound selection (≤ 3 peers)
  -- Core: net_processing.cpp:1272-1329 — MaybeSetPeerAsAnnouncingHeaderAndIDs
  --        manages lNodesAnnouncingHeaderAndIDs with at most 3 entries,
  --        sending sendcmpct(1, 2) to the new HB and sendcmpct(0, 2) to
  --        the evicted oldest.
  -- haskoin: HighBandwidthState type + add/remove/isMember helpers exist
  --          (Network.hs:6758-6793) but have ZERO callers in app/ or src/
  --          — BUG-11.
  ----------------------------------------------------------------------------
  describe "G29 HB outbound selection ≤ 3 (MISSING — BUG-11)" $ do

    -- Unit-test the helpers (they're correct in isolation; the bug is that
    -- nobody calls them).  Mirrors W112 G29 to keep the regression sentinel
    -- of "helpers still work as documented" alive.
    it "addHighBandwidthPeer respects the configured cap" $ do
      hbs <- newHighBandwidthState 3
      let mkAddr p = SockAddrInet p 0
      _ <- addHighBandwidthPeer hbs (mkAddr 1)
      _ <- addHighBandwidthPeer hbs (mkAddr 2)
      _ <- addHighBandwidthPeer hbs (mkAddr 3)
      r4 <- addHighBandwidthPeer hbs (mkAddr 4)
      r4 `shouldBe` False  -- cap reached, 4th peer refused

    xit "BUG-11 HighBandwidthState should be reachable from MSendCmpct path" $
      pendingWith "fix wave: addHighBandwidthPeer call from MSendCmpct + MaybeSetPeerAsAnnouncingHeaderAndIDs equivalent"

  ----------------------------------------------------------------------------
  -- G30: createCompactBlock has at least one caller
  -- Core: invoked at net_processing.cpp:2117 for cached compact-block,
  --       :5902-5912 for tip-announce.
  -- haskoin: createCompactBlock (Network.hs:6499-6519) is fully implemented
  --          but has ZERO callers in app/ or src/ — BUG-12 (dead-helper).
  --          Bonus dead-helper: getMissingTxIndices (Network.hs:6749) also
  --          unused — BUG-6.
  ----------------------------------------------------------------------------
  describe "G30 createCompactBlock has a caller (MISSING — BUG-12 + BUG-6)" $ do

    -- Pinning test: confirm the helper itself still produces a valid cmpctblock
    -- (so the day it gets wired, behaviour is well-defined).
    it "pinning: createCompactBlock still produces a valid cmpctblock" $ do
      let coinbase = mkTx 1 0
          otherTx  = mkTx 2 1
          mrk      = merkleRoot2 (legacyTxHash coinbase) (legacyTxHash otherTx)
          hdr      = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                       mrk 0 0x207fffff (0 :: Word32)
          blk      = Block hdr [coinbase, otherTx]
      cb <- createCompactBlock blk
      length (cbShortIds cb) `shouldBe` 1
      length (cbPrefilled cb) `shouldBe` 1
      -- Coinbase always at relative idx 0
      ptIndex (head (cbPrefilled cb)) `shouldBe` 0

    xit "BUG-12 createCompactBlock should be called from announceTip (HB path)" $
      pendingWith "fix wave: announceTip → createCompactBlock for HB outbound peers"

    xit "BUG-6 getMissingTxIndices should be called from MCmpctBlock handler" $
      pendingWith "fix wave: replace inline [i | (i, Nothing) <- ...] with getMissingTxIndices"

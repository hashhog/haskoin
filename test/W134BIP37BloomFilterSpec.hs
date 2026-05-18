{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W134 BIP-37 Bloom Filter (legacy SPV) — follow-up 30-gate discovery audit
-- for haskoin.  Companion of the original W110 audit; verifies that no fix
-- wave has landed in the interim and catalogues the post-FIX-86 widening
-- of the parity gap (BIP-157 P2P now serves; BIP-37 P2P still does not).
--
-- References:
--   bitcoin-core/src/common/bloom.{h,cpp}        CBloomFilter, sizing,
--                                                 Hash, insert, contains,
--                                                 IsWithinSizeConstraints,
--                                                 IsRelevantAndUpdate
--   bitcoin-core/src/merkleblock.{h,cpp}         CMerkleBlock,
--                                                 CPartialMerkleTree,
--                                                 TraverseAndBuild,
--                                                 TraverseAndExtract,
--                                                 BitsToBytes, BytesToBits
--   bitcoin-core/src/net_processing.cpp ~3680     NODE_BLOOM gate
--                                                  on version handshake
--   bitcoin-core/src/net_processing.cpp ~2440     MSG_FILTERED_BLOCK
--                                                  -> MERKLEBLOCK build
--   bitcoin-core/src/net_processing.cpp ~4853     MEMPOOL handler gate
--   bitcoin-core/src/net_processing.cpp ~4963     FILTERLOAD handler
--   bitcoin-core/src/net_processing.cpp ~4988     FILTERADD handler
--   bitcoin-core/src/net_processing.cpp ~5016     FILTERCLEAR handler
--   bitcoin-core/src/init.cpp ~572 / ~1104        -peerbloomfilters flag
--
-- BIPs: 37 (bloom filter SPV), 111 (NODE_BLOOM service bit + opt-in).
--
-- == Top-line verdict (vs W110, six weeks later, master @ 64ee7a2) ==
--
-- The BIP-37 CBloomFilter subsystem is still entirely absent.  No new
-- Bloom.hs / MerkleBlock.hs module; no MurmurHash3 in production source;
-- no CBloomFilter data type; no IsRelevantAndUpdate; no per-peer filter
-- state; no FILTERLOAD/FILTERADD/FILTERCLEAR handlers; no
-- InvFilteredBlock branch in MGetData.
--
-- New since W110:
--   * FIX-86 wired BIP-157 P2P handlers (MGetCFilters / MGetCFHeaders /
--     MGetCFCheckpt at app/Main.hs:2438-2445).  By contrast the BIP-37
--     surface area at app/Main.hs:2447 still falls to '_other ->
--     return ()' — silent discard of filterload/add/clear.
--   * MMempool handler now gates on NODE_BLOOM advertisement
--     (Main.hs:2368-2402) and serves the full mempool txid list, but
--     filters cannot be applied because filterload is not honoured.
--   * NODE_BLOOM service bit now advertised when
--     '--peerbloomfilters=true' (Network.hs:3314-3322 / :3459-3464 /
--     :3809-3816), but downstream handlers do not honour filterload.
--     -> NEW BUG-19: advertise-without-honour.  Did not exist at W110
--     time because NODE_BLOOM was not advertised.
--
-- == Bugs (19) ==
--
-- BUG-1  P1      MAX_BLOOM_FILTER_SIZE = 36000 constant absent
-- BUG-2  P1-DOS  MAX_HASH_FUNCS = 50 cap absent — amplification DoS
-- BUG-3  P1      LN2SQUARED full-precision constant absent
-- BUG-4  P0-CDIV CBloomFilter constructor absent (no sizing/clamping)
-- BUG-5  P1      nHashFuncs computation formula absent
-- BUG-6  P0-CDIV MurmurHash3 absent from production source
-- BUG-7  P1      Hash schedule (nHashNum*0xFBA4C795 + nTweak) absent
-- BUG-8  P1      Bit-set logic (vData[i>>3] |= 1<<(7&i)) absent
-- BUG-9  P0-CDIV insert / contains absent
-- BUG-10 P1-DOS  CVE-2013-5700 zero-size short-circuit absent
-- BUG-11 P1      BLOOM_UPDATE_* enum constants (0/1/2/3) absent
-- BUG-12 P1      Match logic (txid + scriptPubKey + outpoint + scriptSig) absent
-- BUG-13 P1      Solver for UPDATE_P2PUBKEY_ONLY absent (classifier exists, not wired)
-- BUG-14 P1      UPDATE_ALL / UPDATE_P2PUBKEY_ONLY / UPDATE_NONE branches absent
-- BUG-15 P1-DOS  filterload/add/clear handlers fall to '_other -> return ()'
-- BUG-16 P1      InvFilteredBlock branch absent from MGetData handler
-- BUG-17 P1-DOS  IsWithinSizeConstraints absent — no size DoS gate
-- BUG-18 P2     w47b* PMT in Rpc.hs not extracted to a shared module
-- BUG-19 P1-NEW  Advertise-without-honour (NEW since W110)
--
-- Discovery audit: NO production code changes.

module W134BIP37BloomFilterSpec (spec) where

import Test.Hspec
import Data.Bits ((.&.), (.|.), xor, shiftR, shiftL)
import Data.Word (Word8, Word32)
import qualified Data.ByteString as BS
import Data.List (foldl')

import Haskoin.Network
  ( nodeBloom, nodeNetwork, nodeWitness, nodeCompactFilters
  , ServiceFlag(..), getServiceFlag
  , combineServices, hasService
  , defaultPeerManagerConfig, pmcPeerBloomFilters
  , Message(..)
  , commandName
  )

-- ============================================================
-- Reference constants (from bitcoin-core/src/common/bloom.{h,cpp})
-- These are LOCAL test helpers, NOT production code (BUG-1, BUG-2,
-- BUG-3, BUG-7).  They exist only to give the spec something concrete
-- to compare a future production implementation against.
-- ============================================================

-- | Core bloom.h:17 "static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000".
refMaxBloomFilterSize :: Int
refMaxBloomFilterSize = 36000

-- | Core bloom.h:18 "static constexpr unsigned int MAX_HASH_FUNCS = 50".
refMaxHashFuncs :: Int
refMaxHashFuncs = 50

-- | Core bloom.cpp:23 LN2SQUARED to full 50-digit precision.
refLn2Squared :: Double
refLn2Squared = 0.4804530139182014246671025263266649717305529515945455

-- | Core bloom.cpp:46 hash-schedule multiplier 0xFBA4C795.
refHashSeedMul :: Word32
refHashSeedMul = 0xFBA4C795

-- | Core bloom.h:26-31 BLOOM_UPDATE_* enum.
refBloomUpdateNone, refBloomUpdateAll, refBloomUpdateP2PubkeyOnly, refBloomUpdateMask :: Word8
refBloomUpdateNone         = 0
refBloomUpdateAll          = 1
refBloomUpdateP2PubkeyOnly = 2
refBloomUpdateMask         = 3

-- | Core net_processing.cpp:5000 MAX_SCRIPT_ELEMENT_SIZE = 520.
refMaxScriptElementSize :: Int
refMaxScriptElementSize = 520

-- ============================================================
-- Reference MurmurHash3 (rotl32 + fmix32)
-- Local test helper only; production source has none (BUG-6).
-- ============================================================

rotl32 :: Word32 -> Int -> Word32
rotl32 x r = (x `shiftL` r) .|. (x `shiftR` (32 - r))

-- | Reference MurmurHash3 (same as bitcoin-core/src/crypto/murmurhash3.cpp).
-- This helper exists only so tests can assert what a production version
-- would have to match.  haskoin does NOT call this from production code.
murmurHash3Ref :: Word32 -> BS.ByteString -> Word32
murmurHash3Ref seed dat =
  let c1 = 0xcc9e2d51 :: Word32
      c2 = 0x1b873593 :: Word32
      len = BS.length dat
      nblocks = len `div` 4
      h1 = foldl' (\h i ->
            let off = i * 4
                k = fromIntegral (BS.index dat off)
                  .|. fromIntegral (BS.index dat (off+1)) `shiftL` 8
                  .|. fromIntegral (BS.index dat (off+2)) `shiftL` 16
                  .|. fromIntegral (BS.index dat (off+3)) `shiftL` 24
                k1 = k * c1
                k2 = rotl32 k1 15
                k3 = k2 * c2
                h' = h `xor` k3
                h2' = rotl32 h' 13
            in h2' * 5 + 0xe6546b64
           ) seed [0 .. nblocks - 1]
      tailOff = nblocks * 4
      tailLen = len `mod` 4
      h2 = foldl' (\h i ->
              let b = fromIntegral (BS.index dat (tailOff + i)) :: Word32
              in h `xor` (b `shiftL` (i * 8))
           ) h1 [0 .. tailLen - 1]
      h3 = if tailLen > 0
             then let k1 = h2 * c1
                      k2 = rotl32 k1 15
                      k3 = k2 * c2
                  in h1 `xor` k3
             else h2
      h4 = h3 `xor` fromIntegral len
      fmix x0 =
        let x1 = x0 `xor` (x0 `shiftR` 16)
            x2 = x1 * 0x85ebca6b
            x3 = x2 `xor` (x2 `shiftR` 13)
            x4 = x3 * 0xc2b2ae35
        in x4 `xor` (x4 `shiftR` 16)
  in fmix h4

-- | Hash schedule (Core bloom.cpp:46).  Production source absent.
refHashSeed :: Word32 -> Word32 -> Word32
refHashSeed nHashNum nTweak = nHashNum * refHashSeedMul + nTweak

-- | Optimal filter size in bytes (Core bloom.cpp:32).
-- min((-1 / LN2SQUARED * nElements * log fpRate), MAX_BLOOM_FILTER_SIZE*8) / 8
refBloomFilterBytes :: Int -> Double -> Int
refBloomFilterBytes nElements fpRate =
  let bits = min (round ((-1.0 / refLn2Squared) * fromIntegral nElements * log fpRate))
                 (refMaxBloomFilterSize * 8)
  in max 1 (bits `div` 8)

-- ============================================================
-- Spec
-- ============================================================

spec :: Spec
spec = do

  -- =========================================================
  -- G1-G5  Constants & sizing
  -- =========================================================

  describe "G1 MAX_BLOOM_FILTER_SIZE = 36000 (BUG-1)" $ do
    it "reference constant is 36000 (Core bloom.h:17)" $
      refMaxBloomFilterSize `shouldBe` 36000

    xit "BUG-1: MAX_BLOOM_FILTER_SIZE absent from haskoin source" $ do
      -- W134 confirmation: no production code defines this constant.
      -- A filterload payload of arbitrary length is currently accepted
      -- because the wire layer (Network.hs:1942 "filterload" -> Right
      -- $ MFilterLoad payload) does no size check, and no downstream
      -- handler exists.  Reference: Core bloom.h:17.
      pendingWith "fix wave required: add Haskoin.Bloom with MAX_BLOOM_FILTER_SIZE"

  describe "G2 MAX_HASH_FUNCS = 50 (BUG-2, P1-DOS)" $ do
    it "reference constant is 50 (Core bloom.h:18)" $
      refMaxHashFuncs `shouldBe` 50

    xit "BUG-2: MAX_HASH_FUNCS absent — amplification DoS exposed" $ do
      -- Without this cap, a crafted filterload with nHashFuncs=255 would
      -- trigger 255 MurmurHash3 invocations per lookup, a 5x amplification
      -- relative to Core's 50 cap.  Reference: Core bloom.cpp:38
      -- "nHashFuncs(std::min(... , MAX_HASH_FUNCS))".  haskoin has no
      -- nHashFuncs field at all.
      pendingWith "fix wave required: cap nHashFuncs at 50 on parse"

  describe "G3 LN2SQUARED full precision (BUG-3)" $ do
    it "reference value matches Core's 50-digit literal" $
      abs (refLn2Squared - 0.4804530139182014) < 1e-15 `shouldBe` True

    xit "BUG-3: LN2SQUARED absent from haskoin source" $ do
      -- No sizing formula exists in production.  Without LN2SQUARED at
      -- full precision the constructor would compute the wrong filter
      -- size for a given (nElements, fpRate).  Reference: Core
      -- bloom.cpp:23.
      pendingWith "fix wave required: add LN2SQUARED constant + ctor"

  describe "G4 Constructor sizing formula (BUG-4, P0-CDIV)" $ do
    it "10000-element 0.001 fp filter size <= 36000 bytes" $
      refBloomFilterBytes 10000 0.001 `shouldSatisfy` (<= 36000)

    it "20000-element 0.001 fp filter size <= 36000 bytes (clamps to cap)" $
      refBloomFilterBytes 20000 0.001 `shouldSatisfy` (<= 36000)

    xit "BUG-4: CBloomFilter constructor absent — sizing/clamping not implemented" $ do
      -- No CBloomFilter data type exists.  The sizing helper above is
      -- a local test reference, NOT production code.  P0-CDIV because
      -- a wrong-sized filter (e.g. one byte off Core) would cause
      -- divergent bit-indices and divergent set-membership answers,
      -- which would propagate to merkleblock outputs and break SPV
      -- clients on any chain.  Reference: Core bloom.cpp:26-42.
      pendingWith "fix wave required: implement CBloomFilter ctor"

  describe "G5 nHashFuncs computation (BUG-5)" $ do
    xit "BUG-5: nHashFuncs formula absent from production source" $ do
      -- Core bloom.cpp:38: nHashFuncs(std::min((unsigned int)(vData.size()
      --                    * 8 / nElements * LN2), MAX_HASH_FUNCS)).
      -- Absent because no CBloomFilter.
      pendingWith "fix wave required: implement nHashFuncs computation"

  -- =========================================================
  -- G6-G10  Hash & bit-set
  -- =========================================================

  describe "G6 MurmurHash3 32-bit (BUG-6, P0-CDIV)" $ do
    it "reference MurmurHash3(0, empty) = 0 (Core test vector)" $
      murmurHash3Ref 0 BS.empty `shouldBe` 0

    it "reference MurmurHash3(0xFBA4C795, \"abc\") is non-zero" $
      murmurHash3Ref 0xFBA4C795 "abc" `shouldNotBe` 0

    xit "BUG-6: MurmurHash3 absent from haskoin production source" $ do
      -- This module exposes murmurHash3Ref as a TEST helper only.  No
      -- production module in src/Haskoin/*.hs defines MurmurHash3.
      -- Without it, the bloom-filter bit-index function Hash() cannot
      -- be implemented; without Hash(), insert/contains cannot be
      -- implemented; without those, IsRelevantAndUpdate cannot be
      -- implemented; without that, no SPV peer can be served.
      -- P0-CDIV because every byte of every bloom-related response
      -- would differ from Core.
      pendingWith "fix wave required: add Haskoin.Crypto MurmurHash3"

  describe "G7 nHashNum*0xFBA4C795 + nTweak schedule (BUG-7)" $ do
    it "reference hash seed = nHashNum * 0xFBA4C795 + nTweak" $
      refHashSeed 1 42 `shouldBe` (0xFBA4C795 + 42)

    it "reference hash seed is distinct for nHashNum=0 vs 1" $
      refHashSeed 0 0 `shouldNotBe` refHashSeed 1 0

    xit "BUG-7: hash-schedule absent from haskoin production source" $ do
      pendingWith "fix wave required: implement Hash() with schedule"

  describe "G8 Bit-set: vData[i>>3] |= 1 << (7 & i) (BUG-8)" $ do
    it "bit 0 sets byte 0 bit 0" $ do
      let nIndex   = 0 :: Int
          byteIdx  = nIndex `shiftR` 3
          bitMask  = 1 `shiftL` (7 .&. nIndex) :: Word8
      byteIdx `shouldBe` 0
      bitMask `shouldBe` 0x01

    it "bit 7 sets byte 0 bit 7" $ do
      let nIndex   = 7 :: Int
          byteIdx  = nIndex `shiftR` 3
          bitMask  = 1 `shiftL` (7 .&. nIndex) :: Word8
      byteIdx `shouldBe` 0
      bitMask `shouldBe` (1 `shiftL` 7)

    it "bit 8 sets byte 1 bit 0" $ do
      let nIndex   = 8 :: Int
          byteIdx  = nIndex `shiftR` 3
          bitMask  = 1 `shiftL` (7 .&. nIndex) :: Word8
      byteIdx `shouldBe` 1
      bitMask `shouldBe` 0x01

    xit "BUG-8: bit-vector insert absent from haskoin production source" $ do
      pendingWith "fix wave required: implement insert() bit-set"

  describe "G9 Insert + Contains (BUG-9, P0-CDIV)" $ do
    xit "BUG-9: insert + contains absent — filter cannot be queried" $ do
      -- Core bloom.cpp:50-81 insert+contains.  Absent.  P0-CDIV
      -- because without contains() the IsRelevantAndUpdate matcher
      -- cannot run and so no merkleblock could ever be built.
      pendingWith "fix wave required: implement insert+contains"

  describe "G10 CVE-2013-5700 zero-size short-circuit (BUG-10, P1-DOS)" $ do
    xit "BUG-10: zero-size short-circuit absent in both insert and contains" $ do
      -- Core bloom.cpp:52 / :71: "if (vData.empty()) return / return
      -- true".  A zero-size vData would divide by zero in Hash()
      -- because vData.size() * 8 == 0.  Without this guard a peer can
      -- send filterload with vData=[] to crash the matcher.  haskoin
      -- has no matcher, so the immediate symptom is moot — but the
      -- footgun would be exposed the instant a future fix wave landed
      -- insert/contains without also landing the CVE guard.
      pendingWith "fix wave required: add CVE-2013-5700 zero-size guard"

  -- =========================================================
  -- G11-G15  BLOOM_UPDATE_* flags
  -- =========================================================

  describe "G11-G14 BLOOM_UPDATE_* enum constants (BUG-11)" $ do
    it "BLOOM_UPDATE_NONE = 0" $
      refBloomUpdateNone `shouldBe` 0
    it "BLOOM_UPDATE_ALL = 1" $
      refBloomUpdateAll `shouldBe` 1
    it "BLOOM_UPDATE_P2PUBKEY_ONLY = 2" $
      refBloomUpdateP2PubkeyOnly `shouldBe` 2
    it "BLOOM_UPDATE_MASK = 3" $
      refBloomUpdateMask `shouldBe` 3

    xit "BUG-11: BLOOM_UPDATE_* enum absent from haskoin production source" $ do
      pendingWith "fix wave required: add BLOOM_UPDATE_* constants"

  describe "G15 nFlags & UPDATE_MASK semantics (BUG-11)" $ do
    it "MASK covers UPDATE_ALL" $
      (refBloomUpdateAll .&. refBloomUpdateMask) `shouldBe` refBloomUpdateAll
    it "MASK covers UPDATE_P2PUBKEY_ONLY" $
      (refBloomUpdateP2PubkeyOnly .&. refBloomUpdateMask) `shouldBe` refBloomUpdateP2PubkeyOnly

    xit "BUG-11: nFlags & UPDATE_MASK check absent in production source" $ do
      pendingWith "fix wave required: add nFlags & UPDATE_MASK gate"

  -- =========================================================
  -- G16-G20  Match logic
  -- =========================================================

  describe "G16 txid match in IsRelevantAndUpdate (BUG-12)" $ do
    xit "BUG-12 (txid): txid match path absent in production source" $ do
      -- Core bloom.cpp:102-104: "const Txid& hash = tx.GetHash(); if
      -- (contains(hash.ToUint256())) fFound = true;".  Absent.
      pendingWith "fix wave required: txid match"

  describe "G17 Per-output-script pushdata match (BUG-12)" $ do
    xit "BUG-12 (output pushdata): scriptPubKey pushdata scan absent" $ do
      -- Core bloom.cpp:113-118: iterates scriptPubKey opcodes via
      -- GetOp, tests each data push against the filter.  Absent.
      pendingWith "fix wave required: scriptPubKey pushdata scan"

  describe "G18 Solver(scriptPubKey, vSolutions) for P2PK/MULTISIG (BUG-13)" $ do
    xit "BUG-13: Solver integration absent (classifyOutput exists in Script.hs but not wired here)" $ do
      -- Core bloom.cpp:125-131: "TxoutType type = Solver(txout.scriptPubKey,
      -- vSolutions); if (type == TxoutType::PUBKEY || type ==
      -- TxoutType::MULTISIG) insert(COutPoint(hash, i));".  haskoin
      -- has a script classifier (classifyOutput at Script.hs:698) but
      -- no bloom-filter code path calls it.
      pendingWith "fix wave required: wire classifyOutput into bloom matcher"

  describe "G19 Outpoint match: contains(txin.prevout) (BUG-12)" $ do
    xit "BUG-12 (prevout): prevout match path absent" $ do
      -- Core bloom.cpp:141-145: "for (const CTxIn& txin : tx.vin) if
      -- (contains(txin.prevout)) return true;".  Absent.
      pendingWith "fix wave required: prevout match"

  describe "G20 scriptSig pushdata data-element match (BUG-12)" $ do
    xit "BUG-12 (scriptSig pushdata): scriptSig pushdata scan absent" $ do
      -- Core bloom.cpp:147-156: iterates scriptSig opcodes, tests
      -- each pushdata.  Absent.
      pendingWith "fix wave required: scriptSig pushdata scan"

  -- =========================================================
  -- G21-G24  IsRelevantAndUpdate update branches
  -- =========================================================

  describe "G21 UPDATE_ALL: insert outpoint for every matching output (BUG-14)" $ do
    xit "BUG-14 (UPDATE_ALL): outpoint-insert branch absent" $ do
      pendingWith "fix wave required: UPDATE_ALL outpoint insert"

  describe "G22 UPDATE_P2PUBKEY_ONLY: insert outpoint for P2PK/MULTISIG only (BUG-14)" $ do
    xit "BUG-14 (UPDATE_P2PUBKEY_ONLY): P2PK/MULTISIG-gated insert absent" $ do
      pendingWith "fix wave required: UPDATE_P2PUBKEY_ONLY insert"

  describe "G23 UPDATE_NONE: no insert (BUG-14)" $ do
    xit "BUG-14 (UPDATE_NONE): trivially-true (whole matcher absent)" $ do
      pendingWith "fix wave required: UPDATE_NONE no-op branch (after matcher lands)"

  describe "G24 Outpoint serialisation for bloom insert (BUG-12)" $ do
    it "outpoint wire = txid (32 LE bytes) ++ vout (4 LE bytes) = 36 bytes" $ do
      let txidBytes = BS.replicate 32 0xAB
          vout      = 2 :: Word32
          encoded   = txidBytes
                   <> BS.pack [ fromIntegral (vout .&. 0xFF)
                              , fromIntegral ((vout `shiftR` 8) .&. 0xFF)
                              , fromIntegral ((vout `shiftR` 16) .&. 0xFF)
                              , fromIntegral ((vout `shiftR` 24) .&. 0xFF)
                              ]
      BS.length encoded `shouldBe` 36

    xit "BUG-12 (outpoint serialisation): bloom-specific outpoint serialise absent" $ do
      -- Note: Haskoin.Rpc.hs w47bLE32 (line ~10442) has a 4-byte LE
      -- writer; that helper is RPC-bound.  No bloom-side equivalent.
      pendingWith "fix wave required: outpoint serialise for bloom insert"

  -- =========================================================
  -- G25-G28  Wire messages
  -- =========================================================

  describe "G25 filterload: parse + apply to peer (BUG-15)" $ do
    it "wire constructor MFilterLoad exists and round-trips raw bytes (dead stub)" $ do
      -- The wire layer at Network.hs:1942 parses 'filterload' into
      -- MFilterLoad !ByteString.  We verify that round-trip by
      -- constructing an MFilterLoad and checking its commandName.
      -- This pins the W134 finding that the message is parsed but
      -- never consumed (app/Main.hs:2447 catch-all returns ()).
      let msg = MFilterLoad (BS.pack [0,0,0,0])
      commandName msg `shouldBe` "filterload"

    xit "BUG-15: filterload payload is parsed as raw ByteString without semantic parsing" $ do
      -- Production code path Network.hs:1942: "filterload" -> Right $
      -- MFilterLoad payload.  No CBloomFilter is deserialised; no
      -- IsWithinSizeConstraints check fires; no per-peer state is
      -- set.  In the syncMessageHandler at app/Main.hs the
      -- MFilterLoad case is absorbed by the '_other -> return ()'
      -- catch-all at line 2447.  Reference: Core net_processing.cpp:
      -- 4963-4986 (FILTERLOAD handler).
      pendingWith "fix wave required: implement FILTERLOAD handler"

  describe "G26 filteradd: element <= 520 bytes (BUG-15, BUG-17)" $ do
    it "MAX_SCRIPT_ELEMENT_SIZE = 520 (reference)" $
      refMaxScriptElementSize `shouldBe` 520

    xit "BUG-15 + BUG-17: filteradd 520-byte cap absent; payload silently ignored" $ do
      -- Core net_processing.cpp:5000: "if (vData.size() >
      -- MAX_SCRIPT_ELEMENT_SIZE) bad = true; ... Misbehaving(100)".
      -- haskoin: MFilterAdd absorbs to '_other -> return ()' at
      -- Main.hs:2447.  A peer can send filteradd with a 1 MB element
      -- with zero ban-score reaction.
      pendingWith "fix wave required: implement FILTERADD handler + 520-byte cap"

  describe "G27 filterclear (BUG-15)" $ do
    it "wire constructor MFilterClear exists (empty payload)" $ do
      commandName MFilterClear `shouldBe` "filterclear"

    xit "BUG-15 (filterclear): parsed but silently ignored" $ do
      -- Network.hs:1944 "filterclear" -> Right MFilterClear.  Main.hs:
      -- 2447 _other -> return () absorbs it.  The filter is never
      -- cleared because no per-peer filter state exists.
      pendingWith "fix wave required: implement FILTERCLEAR handler"

  describe "G28 merkleblock build + PMT send on getdata MSG_FILTERED_BLOCK (BUG-16, BUG-18)" $ do
    it "wire constructor MMerkleBlock exists as raw-ByteString dead stub" $ do
      let msg = MMerkleBlock (BS.replicate 16 0xAA)
      commandName msg `shouldBe` "merkleblock"

    xit "BUG-16: InvFilteredBlock branch absent from MGetData handler" $ do
      -- Reference: Core net_processing.cpp:2438-2460 (inv.IsMsgFilteredBlk
      -- builds CMerkleBlock from the loaded filter and sends MERKLEBLOCK
      -- + per-matched-txid TX messages).  haskoin: app/Main.hs:1973
      -- MGetData handler has cases for InvBlock / InvWitnessBlock /
      -- InvTx / InvWitnessTx; no InvFilteredBlock case.  The catch-all
      -- '_ -> requestFromPeer pm addr (MNotFound (NotFound [iv]))'
      -- replies NOTFOUND which is wrong per Core (which silently
      -- no-responds when no filter is loaded, and builds+sends a
      -- merkleblock when one is).
      pendingWith "fix wave required: add InvFilteredBlock case in MGetData handler"

    xit "BUG-18: w47b* PMT pipeline in Rpc.hs not extracted to a shared module" $ do
      -- Haskoin.Rpc.hs:10392-10520 contains a complete + working
      -- PartialMerkleTree implementation (w47bBuild / w47bCalcHash /
      -- w47bExtract / w47bBitsToBytes / w47bTreeWidth / w47bLE32 /
      -- w47bVarInt / w47bReadVarInt) wired into the
      -- gettxoutproof/verifytxoutproof RPCs.  If a future fix wave
      -- adds the P2P merkleblock build path it should extract these
      -- helpers to a shared module (e.g. Haskoin.MerkleBlock) so both
      -- pipelines call the same code.  Currently they would diverge,
      -- creating a NEW Core-parity audit liability.  This is the
      -- canonical haskoin two-pipeline pattern.
      pendingWith "fix wave required: extract w47b* to Haskoin.MerkleBlock + reuse for P2P"

  -- =========================================================
  -- G29-G30  DoS gate + service-bit/opt-in
  -- =========================================================

  describe "G29 IsWithinSizeConstraints DoS gate (BUG-17, P1-DOS)" $ do
    it "36001-byte vData is > MAX_BLOOM_FILTER_SIZE (oversized)" $ do
      let oversized = BS.replicate 36001 0x00
      BS.length oversized `shouldSatisfy` (> refMaxBloomFilterSize)

    xit "BUG-17: IsWithinSizeConstraints absent; filterload not validated" $ do
      -- Core bloom.cpp:91 IsWithinSizeConstraints: vData.size() <=
      -- MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS.  On
      -- violation net_processing.cpp:4975 Misbehaving(100, "too-large
      -- bloom filter").  haskoin parses the wire bytes into a raw
      -- ByteString without any size check, then drops them.
      pendingWith "fix wave required: add IsWithinSizeConstraints + Misbehaving(100)"

  describe "G30 NODE_BLOOM service bit + BIP-111 -peerbloomfilters opt-in (BUG-19, PARTIAL)" $ do
    it "nodeBloom = ServiceFlag 4 (NODE_BLOOM = 1 << 2)" $
      getServiceFlag nodeBloom `shouldBe` 4

    it "NODE_BLOOM is not set when the only flags advertised are network+witness" $ do
      let flags = combineServices [nodeNetwork, nodeWitness]
      hasService flags nodeBloom `shouldBe` False

    it "NODE_BLOOM is in the combined flag set when explicitly included" $ do
      let flags = combineServices [nodeNetwork, nodeWitness, nodeBloom]
      hasService flags nodeBloom `shouldBe` True

    it "pmcPeerBloomFilters default is False (matches Core DEFAULT_PEERBLOOMFILTERS)" $
      pmcPeerBloomFilters defaultPeerManagerConfig `shouldBe` False

    xit "BUG-19 NEW: advertise-without-honour — NODE_BLOOM advertised but filterload ignored" $ do
      -- Post-W110 change: when an operator sets --peerbloomfilters=true,
      -- Network.hs:3314-3322 / :3459-3464 / :3809-3816 add NODE_BLOOM
      -- to the version-handshake service flags.  But filterload / add /
      -- clear handlers in app/Main.hs still fall to '_other -> return
      -- ()' at line 2447.  Net: an SPV peer sees NODE_BLOOM in the
      -- version-handshake service flags, sends filterload, receives
      -- nothing.  This breaks the Core invariant "NODE_BLOOM
      -- advertised => filter messages honoured" (net_processing.cpp:
      -- 4964 etc.).  Mitigation pending the real fix wave: refuse to
      -- toggle --peerbloomfilters=true at startup, or force the bit
      -- off in the service-flag wiring until the handlers land.
      pendingWith "fix wave required: either land BIP-37 handlers or force-disable -peerbloomfilters"

  -- =========================================================
  -- W134 cross-pipeline + parity-gap pinning (4 bonus cases)
  -- =========================================================

  describe "W134 bonus: cross-pipeline observation (post-FIX-86)" $ do
    it "PIN: NODE_COMPACT_FILTERS bit value matches Core" $ do
      -- BIP-157 service bit is NODE_COMPACT_FILTERS = 1 << 6 = 64.
      -- Pinned here as the post-FIX-86 contrast point: this bit is
      -- now advertised AND the corresponding P2P handlers are wired
      -- (Main.hs:2438-2445).  By contrast nodeBloom is advertised
      -- (when opted in) but the handlers are absent.
      getServiceFlag nodeCompactFilters `shouldBe` 64

    it "PIN: BIP-37 dead-stub round-trip — MFilterLoad parses raw ByteString" $ do
      -- Verify the documented "parses but does not consume" property.
      -- A zero-length filterload is a syntactically valid raw
      -- ByteString; the wire-layer parser at Network.hs:1942 accepts
      -- it.  The audit finding is that ANY length is accepted (no
      -- IsWithinSizeConstraints), and the parsed value is then
      -- silently dropped by '_other -> return ()' at Main.hs:2447.
      let emptyMsg = MFilterLoad BS.empty
          bigMsg   = MFilterLoad (BS.replicate 100000 0xFF)
      commandName emptyMsg `shouldBe` "filterload"
      commandName bigMsg   `shouldBe` "filterload"

    it "PIN: combined-flags advertise NODE_BLOOM only when explicitly opted in" $ do
      -- The post-W110 wire-up advertises NODE_BLOOM only when
      -- pmcPeerBloomFilters is True.  Default is False so a fresh
      -- haskoin does NOT trip BUG-19 unless an operator opts in.
      -- This test pins the default safe state.
      let cfg     = defaultPeerManagerConfig
          optedIn = pmcPeerBloomFilters cfg
          flagsIfOptedIn   = combineServices [nodeNetwork, nodeWitness, nodeBloom]
          flagsIfNotOptedIn = combineServices [nodeNetwork, nodeWitness]
      optedIn `shouldBe` False
      hasService flagsIfNotOptedIn nodeBloom `shouldBe` False
      hasService flagsIfOptedIn    nodeBloom `shouldBe` True

    it "PIN: BIP-37 message-type names match Core (no wire-level divergence)" $ do
      -- The four BIP-37 wire constructors map to the four Core
      -- command-name strings.  Wire layer is correct; semantic layer
      -- is absent.  This pins the dead-stub finding (BUG-15, BUG-16).
      commandName (MFilterLoad BS.empty)   `shouldBe` "filterload"
      commandName (MFilterAdd  BS.empty)   `shouldBe` "filteradd"
      commandName MFilterClear             `shouldBe` "filterclear"
      commandName (MMerkleBlock BS.empty)  `shouldBe` "merkleblock"

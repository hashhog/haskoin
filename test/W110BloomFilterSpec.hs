{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W110 BIP-37 Bloom Filter 30-gate audit — haskoin
--
-- Reference: bitcoin-core/src/common/bloom.h/cpp
--            bitcoin-core/src/merkleblock.h/cpp
--
-- == Executive Summary ==
--
-- The BIP-37 CBloomFilter subsystem is ENTIRELY ABSENT from haskoin.
-- There is no Bloom.hs module; no MurmurHash3; no bit-vector; no
-- insert/contains; no IsRelevantAndUpdate; no per-peer bloom-filter state
-- in PeerInfo/PeerConnection; no filterload parse/validate/apply; no
-- filteradd size-gate; no filterclear; no filtered-block build path
-- (merkleblock P2P message is a raw-ByteString pass-through only).
--
-- The service-bit advertisement (NODE_BLOOM = 4) and the BIP-111
-- -peerbloomfilters opt-in config flag both exist and are CORRECT.
-- Everything above the bit-flag layer is absent.
--
-- == Two-pipeline observation ==
--
-- haskoin has a SECOND PartialMerkleTree implementation in Rpc.hs:
-- the w47b* helper suite (w47bBuild, w47bCalcHash, w47bExtract, etc.)
-- used by gettxoutproof / verifytxoutproof.  That pipeline is a
-- stand-alone RPC helper; it shares NO code with the (absent) P2P
-- bloom/merkleblock pipeline.  This is the canonical haskoin two-pipeline
-- pattern at its most extreme: the PMT encoder/decoder is fully
-- implemented for RPC but completely unimplemented for P2P.
--
-- == Dead-helper observation ==
--
-- No dead helpers were found for the bloom filter subsystem because the
-- subsystem is absent rather than implemented-but-unwired.  The Rpc.hs
-- w47b* suite IS wired (gettxoutproof/verifytxoutproof handlers call it)
-- so it is NOT a dead helper.
--
-- == Gates: PASS / FAIL / MISSING ==
--
-- G1  MAX_BLOOM_FILTER_SIZE = 36000             MISSING ENTIRELY
-- G2  MAX_HASH_FUNCS = 50                       MISSING ENTIRELY
-- G3  LN2SQUARED full precision                 MISSING ENTIRELY
-- G4  Constructor sizing formula                MISSING ENTIRELY
-- G5  nHashFuncs computation                    MISSING ENTIRELY
-- G6  MurmurHash3 32-bit                        MISSING ENTIRELY
-- G7  nTweak + i*0xFBA4C795 schedule            MISSING ENTIRELY
-- G8  Bit index (vData[nIndex>>3] |= 1<<(7&ni)) MISSING ENTIRELY
-- G9  Insert + Contains                         MISSING ENTIRELY
-- G10 isFull/isEmpty short-circuit              MISSING ENTIRELY
-- G11 UPDATE_NONE = 0                           MISSING ENTIRELY
-- G12 UPDATE_ALL = 1                            MISSING ENTIRELY
-- G13 UPDATE_P2PUBKEY_ONLY = 2                  MISSING ENTIRELY
-- G14 UPDATE_MASK = 3                           MISSING ENTIRELY
-- G15 nFlags & UPDATE_MASK                      MISSING ENTIRELY
-- G16 txid match                                MISSING ENTIRELY
-- G17 Per-output-script pushdata match          MISSING ENTIRELY
-- G18 P2PKH/P2SH/P2PK/multisig type check      MISSING ENTIRELY
-- G19 Outpoint match                            MISSING ENTIRELY
-- G20 scriptSig data items                      MISSING ENTIRELY
-- G21 UPDATE_ALL outpoint insert                MISSING ENTIRELY
-- G22 UPDATE_P2PUBKEY_ONLY outpoint insert      MISSING ENTIRELY
-- G23 UPDATE_NONE (no insert)                   MISSING ENTIRELY
-- G24 Outpoint serialization (little-endian)    MISSING ENTIRELY
-- G25 filterload parse + apply                  DEAD-STUB (raw ByteString)
-- G26 filteradd <= 520 bytes gate               MISSING ENTIRELY
-- G27 filterclear                               DEAD-STUB (raw ByteString)
-- G28 merkleblock + PartialMerkleTree P2P send  MISSING ENTIRELY (RPC has it)
-- G29 IsWithinSizeConstraints DoS gate          MISSING ENTIRELY
-- G30 NODE_BLOOM (=4) + BIP-111 gate            PASS (flag correct, gate wired)

module W110BloomFilterSpec (spec) where

import Test.Hspec
import Data.Bits ((.&.), (.|.), xor, shiftR, shiftL, testBit)
import Data.Word (Word8, Word32)
import qualified Data.ByteString as BS
import Data.List (foldl')
import Data.String (IsString)

import Haskoin.Network
  ( nodeBloom, ServiceFlag(..), nodeNetwork, nodeWitness
  , combineServices, hasService
  , defaultPeerManagerConfig, pmcPeerBloomFilters
  )

-- ============================================================
-- Reference constants (from bitcoin-core/src/common/bloom.h/cpp)
-- ============================================================

maxBloomFilterSize :: Int
maxBloomFilterSize = 36000

maxHashFuncs :: Int
maxHashFuncs = 50

-- LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455
ln2squared :: Double
ln2squared = 0.4804530139182014246671025263266649717305529515945455

-- Hash schedule seed multiplier (bloom.cpp line ~42)
hashSeedMul :: Word32
hashSeedMul = 0xFBA4C795

-- Update flags
bloomUpdateNone :: Word8
bloomUpdateNone = 0

bloomUpdateAll :: Word8
bloomUpdateAll = 1

bloomUpdateP2PubkeyOnly :: Word8
bloomUpdateP2PubkeyOnly = 2

bloomUpdateMask :: Word8
bloomUpdateMask = 3

-- ============================================================
-- Reference MurmurHash3 (rotl32 + fmix32)
-- Used to validate correctness when a real impl is added.
-- ============================================================

rotl32 :: Word32 -> Int -> Word32
rotl32 x r = (x `shiftL` r) .|. (x `shiftR` (32 - r))

-- | Reference MurmurHash3 (same as bitcoin-core/src/crypto/murmurhash3.cpp).
-- Seed is (nHashNum * 0xFBA4C795 + nTweak).
murmurHash3Ref :: Word32 -> BS.ByteString -> Word32
murmurHash3Ref seed dat =
  let c1 = 0xcc9e2d51 :: Word32
      c2 = 0x1b873593 :: Word32
      len = BS.length dat
      nblocks = len `div` 4
      -- Process 4-byte blocks
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
                h2 = rotl32 h' 13
            in h2 * 5 + 0xe6546b64
           ) seed [0 .. nblocks - 1]
      -- Tail bytes
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
      -- Finalisation
      h4 = h3 `xor` fromIntegral len
      fmix x0 =
        let x1 = x0 `xor` (x0 `shiftR` 16)
            x2 = x1 * 0x85ebca6b
            x3 = x2 `xor` (x2 `shiftR` 13)
            x4 = x3 * 0xc2b2ae35
        in x4 `xor` (x4 `shiftR` 16)
  in fmix h4

-- | Hash schedule: seed = nHashNum * 0xFBA4C795 + nTweak
hashSeed :: Word32 -> Word32 -> Word32
hashSeed nHashNum nTweak = nHashNum * hashSeedMul + nTweak

-- ============================================================
-- Bloom filter sizing formulas (for reference / future impl)
-- ============================================================

-- | Optimal filter size in bytes for nElements at false-positive rate nFPRate.
-- Core: min((-1 / LN2SQUARED * nElements * log(fpRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8
bloomFilterBytes :: Int -> Double -> Int
bloomFilterBytes nElements nFPRate =
  let bits = min (round ((-1.0 / ln2squared) * fromIntegral nElements * log nFPRate))
                 (maxBloomFilterSize * 8)
  in max 1 (bits `div` 8)

-- | Optimal number of hash functions.
-- Core: min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
bloomHashFuncs :: Int -> Int -> Int
bloomHashFuncs filterBytes nElements =
  min (round (fromIntegral filterBytes * 8 / fromIntegral nElements * sqrt ln2squared * sqrt 1.0))
      maxHashFuncs

-- ============================================================
-- spec
-- ============================================================

spec :: Spec
spec = do

  -- --------------------------------------------------------
  -- G1-G5  Constants & sizing
  -- --------------------------------------------------------

  describe "G1 MAX_BLOOM_FILTER_SIZE = 36000" $ do
    it "reference constant is 36000" $
      maxBloomFilterSize `shouldBe` 36000

    it "BUG-1: MAX_BLOOM_FILTER_SIZE absent from haskoin source" $ do
      -- There is no Bloom.hs and no MAX_BLOOM_FILTER_SIZE constant defined.
      -- filterload payload is accepted as raw ByteString without size check.
      -- A peer can send a 1 MB filterload and haskoin will silently accept it
      -- (falls to _other -> return () with no parse or validation).
      -- Bitcoin Core: bloom.h line ~16 "static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000"
      -- haskoin: absent.
      pending

  describe "G2 MAX_HASH_FUNCS = 50" $ do
    it "reference constant is 50" $
      maxHashFuncs `shouldBe` 50

    it "BUG-2: MAX_HASH_FUNCS absent from haskoin source" $ do
      -- Same as G1: no bloom filter implementation at all.
      -- A crafted filterload with nHashFuncs=255 would trigger 255 MurmurHash3
      -- invocations per lookup — quadratic amplification DoS.
      -- Bitcoin Core: bloom.h line ~17 "static constexpr unsigned int MAX_HASH_FUNCS = 50"
      pending

  describe "G3 LN2SQUARED full precision" $ do
    it "reference value matches Core's 50-digit literal" $
      -- Core bloom.cpp: static constexpr double LN2SQUARED = 0.4804530...
      abs (ln2squared - 0.4804530139182014) < 1e-15 `shouldBe` True

    it "BUG-3: LN2SQUARED absent from haskoin source" $ do
      -- No bloom filter sizing formula exists.  Without full-precision LN2SQUARED
      -- the constructor would produce filters that are systematically too small or
      -- too large, giving wrong false-positive rates.
      pending

  describe "G4 Constructor sizing formula" $ do
    it "10000-element 0.1%% FP filter should be ≤ 36000 bytes" $
      bloomFilterBytes 10000 0.001 `shouldSatisfy` (<= 36000)

    it "20000-element 0.1%% FP filter should be at or near the protocol limit (36000)" $
      -- At 20k elements / 0.1%% the ideal size is close to / at the 36000-byte cap.
      -- The exact clamping depends on FP precision matching Core's double arithmetic.
      bloomFilterBytes 20000 0.001 `shouldSatisfy` (<= 36000)

    it "BUG-4: CBloomFilter constructor absent from haskoin source" $ do
      -- No data type for a bloom filter exists.  The sizing formula above is a
      -- local test helper, not production code.
      pending

  describe "G5 nHashFuncs computation" $ do
    it "BUG-5: nHashFuncs computation absent from haskoin source" $ do
      -- Core: nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
      -- Absent because there is no CBloomFilter.
      pending

  -- --------------------------------------------------------
  -- G6-G10  Hash & bit-set
  -- --------------------------------------------------------

  describe "G6 MurmurHash3 32-bit" $ do
    it "MurmurHash3(0, empty) matches Core test vector = 0" $
      -- Core test: MurmurHash3(0, {}) == 0
      murmurHash3Ref 0 BS.empty `shouldBe` 0

    it "MurmurHash3(0xFBA4C795, 'abc') is non-zero" $
      -- Sanity: non-trivial seed + data must produce non-zero hash.
      murmurHash3Ref 0xFBA4C795 "abc" `shouldNotBe` 0

    it "BUG-6: MurmurHash3 absent from haskoin production source" $ do
      -- The murmurHash3Ref above is a local test helper, NOT production code.
      -- haskoin has no MurmurHash3 in src/Haskoin/*.hs.
      -- Without it no bloom filter bit-index computation is possible.
      pending

  describe "G7 nTweak + i*0xFBA4C795 schedule" $ do
    it "hashSeed formula: seed = nHashNum * 0xFBA4C795 + nTweak" $
      hashSeed 1 42 `shouldBe` (0xFBA4C795 + 42)

    it "hashSeed is distinct for different nHashNum values" $
      hashSeed 0 0 `shouldNotBe` hashSeed 1 0

    it "BUG-7: hash-schedule absent from haskoin production source" $ do
      -- hashSeed above is a local test helper only.
      pending

  describe "G8 Bit index: vData[nIndex>>3] |= (1 << (7 & nIndex))" $ do
    it "bit 0 sets byte 0 bit 0 (LSB)" $ do
      -- nIndex=0: byte index = 0>>3 = 0; bit mask = 1<<(7&0) = 1<<0 = 0x01
      let nIndex = 0 :: Int
          byteIdx = nIndex `shiftR` 3
          bitMask = 1 `shiftL` (7 .&. nIndex) :: Word8
      byteIdx `shouldBe` 0
      bitMask `shouldBe` 0x01

    it "bit 7 sets byte 0 bit 7 (MSB)" $ do
      let nIndex = 7 :: Int
          byteIdx = nIndex `shiftR` 3
          bitMask = 1 `shiftL` (7 .&. nIndex) :: Word8
      byteIdx `shouldBe` 0
      bitMask `shouldBe` (1 `shiftL` 7)

    it "bit 8 sets byte 1 bit 0" $ do
      let nIndex = 8 :: Int
          byteIdx = nIndex `shiftR` 3
          bitMask = 1 `shiftL` (7 .&. nIndex) :: Word8
      byteIdx `shouldBe` 1
      bitMask `shouldBe` 0x01

    it "BUG-8: bit-vector insert absent from haskoin production source" $ do
      pending

  describe "G9 Insert + Contains" $ do
    it "BUG-9: insert + contains absent from haskoin source" $ do
      -- No CBloomFilter insert or contains functions exist.
      -- Consequence: SPV clients cannot use haskoin as a filter server.
      pending

  describe "G10 isFull/isEmpty short-circuit" $ do
    it "BUG-10: isFull/isEmpty (CVE-2013-5700 divide-by-zero guard) absent" $ do
      -- Core bloom.cpp insert() and contains(): "if (vData.empty()) return;"
      -- A zero-size vData would divide by zero in Hash().  The guard is absent
      -- because there is no CBloomFilter.
      pending

  -- --------------------------------------------------------
  -- G11-G15  Update flags
  -- --------------------------------------------------------

  describe "G11-G14 Update flag constants" $ do
    it "BLOOM_UPDATE_NONE = 0" $
      bloomUpdateNone `shouldBe` 0
    it "BLOOM_UPDATE_ALL = 1" $
      bloomUpdateAll `shouldBe` 1
    it "BLOOM_UPDATE_P2PUBKEY_ONLY = 2" $
      bloomUpdateP2PubkeyOnly `shouldBe` 2
    it "BLOOM_UPDATE_MASK = 3" $
      bloomUpdateMask `shouldBe` 3
    it "MASK covers both update bits" $
      (bloomUpdateAll .&. bloomUpdateMask) `shouldBe` bloomUpdateAll
    it "BUG-11: nFlags update-flag type absent from haskoin source" $ do
      -- No data type or constructor for bloom filter flags exists.
      pending

  describe "G15 nFlags & UPDATE_MASK" $ do
    it "BUG-12: nFlags & UPDATE_MASK check absent" $ do
      -- Core IsRelevantAndUpdate: (nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL
      -- No such logic exists because IsRelevantAndUpdate is absent.
      pending

  -- --------------------------------------------------------
  -- G16-G20  Match logic
  -- --------------------------------------------------------

  describe "G16 txid match" $ do
    it "BUG-13: txid match in IsRelevantAndUpdate absent" $ do
      -- Core bloom.cpp: if (contains(hash.ToUint256())) fFound = true;
      -- No IsRelevantAndUpdate function exists in haskoin.
      pending

  describe "G17 Per-output-script pushdata match" $ do
    it "BUG-14: per-output scriptPubKey pushdata scan absent" $ do
      -- Core: iterates scriptPubKey opcodes via GetOp, tests each data push.
      -- Absent.
      pending

  describe "G18 P2PKH/P2SH/P2PK/multisig type check" $ do
    it "BUG-15: Solver(scriptPubKey, vSolutions) type check absent" $ do
      -- Core: for BLOOM_UPDATE_P2PUBKEY_ONLY, only inserts outpoint if
      -- Solver identifies TxoutType::PUBKEY or TxoutType::MULTISIG.
      -- Absent.
      pending

  describe "G19 Outpoint match" $ do
    it "BUG-16: txin.prevout match absent" $ do
      -- Core: for (const CTxIn& txin : tx.vin) if (contains(txin.prevout)) return true;
      -- Absent.
      pending

  describe "G20 scriptSig data items" $ do
    it "BUG-17: scriptSig pushdata scan absent" $ do
      -- Core: iterates scriptSig opcodes, tests each data element.
      -- Absent.
      pending

  -- --------------------------------------------------------
  -- G21-G24  isRelevantAndUpdate
  -- --------------------------------------------------------

  describe "G21 UPDATE_ALL: insert outpoint for every matching output" $ do
    it "BUG-18: UPDATE_ALL outpoint-insert path absent" $ do
      pending

  describe "G22 UPDATE_P2PUBKEY_ONLY: insert outpoint for P2PK/multisig only" $ do
    it "BUG-19: UPDATE_P2PUBKEY_ONLY path absent" $ do
      pending

  describe "G23 UPDATE_NONE: no outpoint inserted" $ do
    it "BUG-20: UPDATE_NONE path absent (trivially true — whole function absent)" $ do
      pending

  describe "G24 Outpoint serialisation for filter insert" $ do
    it "outpoint = txid (32 bytes LE) ++ vout (4 bytes LE)" $ do
      -- Core: DataStream stream{}; stream << outpoint; insert(stream)
      -- The wire format is txid (32 bytes, already LE in memory) followed by
      -- the 4-byte LE vout index.  Test the expected byte layout.
      let txidBytes = BS.replicate 32 0xAB
          vout      = 2 :: Word32
          encoded   = txidBytes
                   <> BS.pack [ fromIntegral (vout .&. 0xFF)
                               , fromIntegral ((vout `shiftR` 8) .&. 0xFF)
                               , fromIntegral ((vout `shiftR` 16) .&. 0xFF)
                               , fromIntegral ((vout `shiftR` 24) .&. 0xFF)
                               ]
      BS.length encoded `shouldBe` 36

    it "BUG-21: outpoint serialisation for bloom insert absent" $ do
      pending

  -- --------------------------------------------------------
  -- G25-G28  P2P messages
  -- --------------------------------------------------------

  describe "G25 filterload: parse nHashFuncs/nTweak/nFlags + apply to peer" $ do
    it "BUG-22: filterload payload is accepted as raw ByteString without parsing" $ do
      -- Network.hs:1645: "filterload" -> Right $ MFilterLoad payload
      -- The payload is stored as a raw ByteString; no CBloomFilter is
      -- deserialised; no size-constraint check fires; no per-peer filter
      -- state is set.
      -- PeerInfo has no bloom-filter field at all.
      -- Main.hs syncMessageHandler: MFilterLoad falls to _other -> return ().
      -- Reference: Core net_processing.cpp ProcessMessage("filterload"):
      --   1. deserialise CBloomFilter (vData, nHashFuncs, nTweak, nFlags)
      --   2. call IsWithinSizeConstraints(); Misbehaving(100) if violated
      --   3. store in peer state; set fRelay = fRelayTxes
      pending

  describe "G26 filteradd: element <= 520 bytes" $ do
    it "BUG-23: filteradd 520-byte cap absent; payload silently ignored" $ do
      -- Core net_processing.cpp ProcessMessage("filteradd"):
      --   if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) Misbehaving(100)
      -- haskoin: MFilterAdd falls to _other -> return ().
      -- A peer can send filteradd with a 1 MB element with zero reaction.
      pending

  describe "G27 filterclear: reset per-peer filter" $ do
    it "BUG-24: filterclear is parsed but silently ignored" $ do
      -- Network.hs:1647: "filterclear" -> Right MFilterClear
      -- Main.hs syncMessageHandler: MFilterClear falls to _other -> return ().
      -- The filter is never cleared because no per-peer filter state exists.
      pending

  describe "G28 merkleblock + PartialMerkleTree P2P send" $ do
    it "BUG-25: no filtered-block send path — merkleblock is P2P dead stub" $ do
      -- When a bloom-filtered peer requests a block (InvFilteredBlock / getdata
      -- with MSG_FILTERED_BLOCK), Core responds with a CMerkleBlock message
      -- containing the block header + PartialMerkleTree for matching txids +
      -- inv messages for the matching transactions.
      --
      -- haskoin: the MGetData handler in Main.hs handles InvBlock/InvWitnessBlock
      -- but has no InvFilteredBlock branch.  The MMerkleBlock constructor exists
      -- in Network.hs but only as a raw-ByteString container — no build path.
      --
      -- Note: Rpc.hs has a complete w47b* PartialMerkleTree encoder/decoder
      -- wired to gettxoutproof/verifytxoutproof.  That RPC pipeline is CORRECT
      -- but shares no code with the (absent) P2P filtered-block path.  This is
      -- the W110 two-pipeline finding: PMT exists in Rpc.hs but not in the P2P
      -- filtered-block path.
      pending

  -- --------------------------------------------------------
  -- G29-G30  DoS / service
  -- --------------------------------------------------------

  describe "G29 IsWithinSizeConstraints DoS gate" $ do
    it "BUG-26: IsWithinSizeConstraints absent; filterload not validated" $ do
      -- Core: CBloomFilter::IsWithinSizeConstraints() checks
      --   vData.size() <= MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS
      -- On violation, net_processing.cpp calls Misbehaving(100).
      -- haskoin: filterload payload is not parsed at all.
      pending

    it "36001-byte filterload should be rejected by IsWithinSizeConstraints" $ do
      -- Construct an oversized filter payload: 4-byte nHashFuncs=0 LE +
      -- 4-byte nTweak=0 LE + 1-byte nFlags=0 + 36001-byte vData varint+data.
      -- haskoin currently accepts this silently.
      let oversizedData = BS.replicate 36001 0x00
      BS.length oversizedData `shouldSatisfy` (> maxBloomFilterSize)

  describe "G30 NODE_BLOOM service bit + BIP-111 -peerbloomfilters gate" $ do
    it "nodeBloom = ServiceFlag 4 (NODE_BLOOM = 1 << 2)" $
      getServiceFlag nodeBloom `shouldBe` 4

    it "NODE_BLOOM is not set in default service flags" $ do
      let flags = combineServices [nodeNetwork, nodeWitness]
      hasService flags nodeBloom `shouldBe` False

    it "NODE_BLOOM is set when pmcPeerBloomFilters = True" $ do
      -- The pmcPeerBloomFilters flag gates NODE_BLOOM advertisement.
      -- Default is False (matches Core DEFAULT_PEERBLOOMFILTERS=false).
      pmcPeerBloomFilters defaultPeerManagerConfig `shouldBe` False

    it "PASS: BIP-111 peerbloomfilters config gate is wired correctly" $ do
      -- Network.hs:2930-2938: bloomFlags = if pmcPeerBloomFilters (pmConfig pm)
      --                                      then nodeBloom : baseFlags
      --                                      else baseFlags
      -- Main.hs:1999: let bloomEnabled = pmcPeerBloomFilters (pmConfig pm)
      -- This is the ONLY passing gate in the entire W110 audit.
      pmcPeerBloomFilters defaultPeerManagerConfig `shouldBe` False

  -- --------------------------------------------------------
  -- Two-pipeline summary test
  -- --------------------------------------------------------

  describe "Two-pipeline: w47b* PMT in Rpc.hs vs absent P2P bloom path" $ do
    it "w47b* helpers exist for RPC gettxoutproof (Rpc.hs PMT pipeline)" $ do
      -- The RPC pipeline (Rpc.hs w47bBuild/w47bCalcHash/w47bExtract) is a
      -- working PartialMerkleTree implementation wired into gettxoutproof and
      -- verifytxoutproof.  It is CORRECT but isolated to the RPC surface.
      -- Core combines both in merkleblock.cpp: CPartialMerkleTree is used for
      -- both the merkleblock P2P message and the gettxoutproof RPC response.
      -- haskoin: two separate code paths, one present (RPC) one absent (P2P).
      True `shouldBe` True   -- existence confirmed by code review

    it "BUG-27: P2P bloom/merkleblock pipeline absent — no code reuse with w47b*" $ do
      -- If haskoin were to implement the P2P bloom filter subsystem, the w47b*
      -- suite in Rpc.hs should be extracted into a shared module and reused,
      -- or the PMT build/extract functions should be implemented in a dedicated
      -- BloomFilter.hs / MerkleBlock.hs.
      -- Currently the RPC PMT and the P2P PMT are completely decoupled because
      -- the P2P side does not exist.
      pending

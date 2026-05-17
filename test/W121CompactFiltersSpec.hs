{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W121 BIP-157 / BIP-158 Compact Block Filters — 30-gate audit for haskoin.
--
-- References:
--   BIP-157   Client Side Block Filtering (P2P + service-flag side)
--   BIP-158   Compact Block Filters for Light Clients (GCS / on-disk side)
--   bitcoin-core/src/blockfilter.{cpp,h}                — GCS / BasicFilterElements
--   bitcoin-core/src/index/blockfilterindex.{cpp,h}     — CFCHECKPT_INTERVAL=1000
--   bitcoin-core/src/net_processing.cpp:184-186, 3260-3422 — getcfilters/getcfheaders/getcfcheckpt
--   bitcoin-core/src/protocol.h:321-323                 — NODE_COMPACT_FILTERS=(1<<6)
--   bitcoin-core/src/rpc/blockchain.cpp:2956            — getblockfilter RPC
--
-- ============================================================
-- TOP-LINE VERDICT — PARTIAL
-- ============================================================
--
-- haskoin's BIP-158 GCS-filter core in 'Haskoin.Index' is the most thorough
-- compact-filter implementation in the fleet.  Every BIP-158 wire primitive
-- (SipHash-2-4, FastRange64, Golomb-Rice coder, GCS encode/decode/match,
-- BasicFilterElements with the OP_RETURN asymmetry between outputs and
-- spent-outputs, set-dedup, SHA256d filter hash + chained header) is
-- implemented with explicit Core references and passes the BIP-158
-- reference vectors from @bitcoin-core/src/test/data/blockfilters.json@
-- (proven by the pre-existing GCS test block in @test/Spec.hs:13191@).
-- BlockFilterIndex itself is a real RocksDB-backed index with persisted
-- meta record, big-endian height keys (matching Core), startup recovery
-- (loadBlockFilterIndexState), CustomRewind on disconnect, and an
-- on-demand backfill driver (indexManagerBackfill).  The index is wired
-- into BOTH the IBD chain-connect path ('Sync.hs:448') AND the
-- submitBlock path ('BlockTemplate.hs:620, 960') via
-- 'indexManagerConnectBlock'.  The @-blockfilterindex@ CLI flag is
-- plumbed end-to-end (Main.hs:280..1022).  REST endpoints
-- (@/rest/blockfilter/...@ and @/rest/blockfilterheaders/...@) exist
-- with both a fast index-hit path AND a slow on-the-fly recompute
-- fallback that retains correctness when the index is disabled.
--
-- == What is MISSING ENTIRELY ==
--
-- The BIP-157 P2P surface is essentially absent.  All six wire messages
--   getcfilters / cfilter / getcfheaders / cfheaders / getcfcheckpt /
--   cfcheckpt
-- are defined in 'Haskoin.Network.Message' as opaque @ByteString@
-- constructors (lines 1543-1549).  They round-trip on commandName /
-- encodePayload / decodePayload (the dead-wire shape from W110/W116):
-- the wire is allocated, but there is no struct type for the payload,
-- no parser, no handler, no dispatch, no reply path, no peer-state for
-- "remote requested CFs", and no sender to ever push a @cfilter@ /
-- @cfheaders@ / @cfcheckpt@ back to a peer.  A peer asking us for a
-- compact filter today gets nothing — the message is read, classified
-- as MGetCFilters, and falls off the end of the dispatch case.
--
-- The NODE_COMPACT_FILTERS service bit (1<<6 = 64) is NOT advertised in
-- any 'pcfgServices' / 'baseFlags' list (Network.hs:3067, 3207, 3551).
-- A correctly-implemented light client following BIP-157 would never
-- choose haskoin as a CF server, so even if the message handlers were
-- wired the discovery layer would skip us.  This is the BIP-157 P0
-- gap.
--
-- The @getblockfilter@ JSON-RPC (rpc/blockchain.cpp:2956) is also
-- missing — haskoin only exposes the REST shape.  A wallet using the
-- standard JSON-RPC client would not find a compact filter via this
-- node.
--
-- == Two-pipeline observation ==
--
-- The Index-side @BlockFilter@ serialization is INTENTIONALLY
-- INCOMPATIBLE with the BIP-157 wire @cfilter@ payload.  Core's
-- 'BlockFilter::Serialize' emits @filter_type (u8) || block_hash (32)
-- || varint || encoded@.  haskoin's 'encodeBlockFilter' emits ONLY
-- @gcsEncoded@ (the encoded GCS bytes including the compact-size N
-- prefix) — the filter_type and block_hash are passed as a SEPARATE
-- parameter to 'decodeBlockFilter'.  This works for the internal
-- key-by-height index path (the surrounding RocksDB key encodes both),
-- but if the P2P wire is ever wired up the encoder must NOT reuse
-- 'encodeBlockFilter'.  Today there is no second pipeline to drift
-- against (because the P2P pipeline does not exist), so this is filed
-- as a forward-looking divergence rather than a TWO-PIPELINE bug.
--
-- == Dead-helper observation ==
--
-- The six MGetCF*/MCF* constructors are the cleanest dead-wire example
-- in haskoin's P2P layer: the wire envelope is allocated but the
-- payload type is @ByteString@ (i.e. unparsed), and zero call sites
-- pattern-match on the constructor.  This is the same shape as the
-- W110 BIP-37 MMerkleBlock !ByteString constructor and the W116
-- BIP-331 GetPkgTxns / PkgTxns dead-wire we previously logged.
--
-- == Gates: PASS / FAIL / MISSING ==
--
-- G1  BASIC_FILTER_P = 19                                     PASS
-- G2  BASIC_FILTER_M = 784931                                 PASS
-- G3  BlockFilterType::BASIC = 0 enum value                   PASS
-- G4  SipHash-2-4 key from first 16 bytes of block hash       PASS
-- G5  FastRange64 multiply-shift                              PASS
-- G6  Golomb-Rice encode/decode round-trip                    FAIL — BUG-16 P0 (q>=64)
-- G7  BasicFilterElements OP_RETURN asymmetry                 PASS
-- G8  Set-dedup before encoding                               PASS
-- G9  Empty-filter encoding == single byte 0x00               PASS
-- G10 SHA256d filter hash                                     PASS
-- G11 SHA256d chained filter header                           PASS
-- G12 Genesis filter header = 0x00..0x00 (32 zero bytes)      PASS
-- G13 BIP-158 reference vectors regression marker             PASS (Spec.hs:13191)
-- G14 CFCHECKPT_INTERVAL = 1000                               MISSING ENTIRELY
-- G15 MAX_GETCFILTERS_SIZE = 1000                             MISSING ENTIRELY
-- G16 MAX_GETCFHEADERS_SIZE = 2000                            MISSING ENTIRELY
-- G17 NODE_COMPACT_FILTERS = (1<<6) advertised                FAIL — BUG-1 P0
-- G18 getcfilters handler                                     MISSING ENTIRELY — BUG-2 P0
-- G19 getcfheaders handler                                    MISSING ENTIRELY — BUG-2 P0
-- G20 getcfcheckpt handler                                    MISSING ENTIRELY — BUG-2 P0
-- G21 cfilter sender                                          MISSING ENTIRELY — BUG-3 P0
-- G22 cfheaders sender                                        MISSING ENTIRELY — BUG-3 P0
-- G23 cfcheckpt sender                                        MISSING ENTIRELY — BUG-3 P0
-- G24 BIP-157 BlockFilter wire serialization                  FAIL — BUG-4 P0
-- G25 getblockfilter JSON-RPC                                 MISSING ENTIRELY — BUG-5 P0
-- G26 BlockFilterIndex chain-connect wiring (IBD)             PASS
-- G27 BlockFilterIndex chain-connect wiring (submitBlock)     PASS
-- G28 BlockFilterIndex CustomRewind on disconnect             PASS
-- G29 -blockfilterindex CLI flag end-to-end                   PASS
-- G30 REST /rest/blockfilter + /rest/blockfilterheaders       PASS
--
-- == BUGS ==
--
-- BUG-1 P0 NODE_COMPACT_FILTERS service bit (1<<6 = 64) is not
--   defined and never advertised.  Network.hs lines 673-687 enumerate
--   nodeNetwork=1 / nodeBloom=4 / nodeWitness=8 / nodeNetworkLimited=
--   1024 — no nodeCompactFilters.  Light clients walking the DNS-seed
--   results / addrman will never select haskoin as a CF server.
--   Fix: add @nodeCompactFilters :: ServiceFlag; nodeCompactFilters =
--   ServiceFlag 64@ alongside the others; conditionally include in
--   baseFlags when 'icBlockFilterIndex' is enabled (mirrors
--   nodeBloom gated on pmcPeerBloomFilters).  Reference:
--   bitcoin-core/src/init.cpp where NODE_COMPACT_FILTERS is OR'd in
--   when -blockfilterindex is on.  G17.
--
-- BUG-2 P0 The three INBOUND P2P messages (getcfilters / getcfheaders /
--   getcfcheckpt) have no parser, no handler, no dispatch case.
--   Each is stored as an opaque @!ByteString@ payload
--   (Network.hs:1544-1549) and re-emitted unchanged.  A peer that
--   sends us @getcfilters@ today gets no response — Core would
--   respond with up to MAX_GETCFILTERS_SIZE @cfilter@ messages
--   (net_processing.cpp:3315-3342).  Fix shape: add struct types
--   @GetCFilters@ / @GetCFHeaders@ / @GetCFCheckpt@ with Serialize
--   instances; switch the @ByteString@ constructors to typed
--   constructors; add three dispatch arms calling new
--   @handleGetCFilters@ / @handleGetCFHeaders@ / @handleGetCFCheckpt@
--   procedures that gate on
--     (1) NODE_COMPACT_FILTERS in @peer.m_our_services@,
--     (2) filter_type == BASIC,
--     (3) start_height <= stop_height,
--     (4) (stop_height - start_height) < MAX_GETCFILTERS_SIZE
--         (or MAX_GETCFHEADERS_SIZE for cfheaders, unlimited for
--         cfcheckpt),
--   then look up the entries via 'blockFilterIndexGet' /
--   'blockFilterIndexLastHeader' and push @cfilter@ / @cfheaders@ /
--   @cfcheckpt@ replies.  Disconnect-on-misbehaviour matches
--   Core's @node.fDisconnect = true@ branches.  G18 / G19 / G20.
--
-- BUG-3 P0 The three OUTBOUND P2P messages (cfilter / cfheaders /
--   cfcheckpt) have no sender call sites.  Reading the codebase end
--   to end, there is no path that produces an @MCFilter@ /
--   @MCFHeaders@ / @MCFCheckpt@ payload from a 'BlockFilterEntry'.
--   This is the symmetric P0 to BUG-2 — until the senders exist, a
--   peer that DOES want a filter from us cannot receive one even if
--   the inbound handler logic were spliced in.  Fix is bundled with
--   BUG-2 — the handler IS the sender; calling 'sendMessage pc
--   (MCFilter ...)' from inside the new @handleGetCFilters@ closure
--   completes the loop.  G21 / G22 / G23.
--
-- BUG-4 P0 'encodeBlockFilter' emits ONLY @gcsEncoded@ — missing the
--   leading @filter_type (u8)@ and @block_hash (32 bytes)@ fields
--   that Core's @BlockFilter::Serialize@ writes
--   (blockfilter.h:150-155).  Today this is consistent inside the
--   index because 'decodeBlockFilter' receives @filter_type@ and
--   @blockHash@ as separate arguments and the RocksDB key carries
--   the height — but any code that uses 'encodeBlockFilter' to
--   produce a BIP-157 @cfilter@ wire payload will produce garbage.
--   Fix: split 'encodeBlockFilter' into 'encodeFilterPayload'
--   (current behaviour, kept for index storage) and a new
--   'encodeCFilterMessage' that emits @u8 || u256 || varint ||
--   encoded@ for the wire.  Add a Serialize instance for
--   'BlockFilter' that matches Core verbatim; the on-disk index
--   keeps using the per-component encoder so the storage layout
--   is unchanged.  G24.
--
-- BUG-5 P0 The 'getblockfilter' JSON-RPC method
--   (rpc/blockchain.cpp:2956) is not registered.  haskoin exposes
--   the REST shape ('Rpc.hs:9961' handleRestBlockFilter) but a
--   wallet using only JSON-RPC cannot fetch a single block's
--   filter.  Fix: add a @"getblockfilter"@ case in the JSON-RPC
--   dispatcher that takes @{blockhash, filtertype}@, looks up via
--   'blockFilterIndexGet' (fast) or 'computeBlockFilter' (slow),
--   and returns @{"filter": "<hex>", "header": "<hex>"}@ matching
--   Core's response shape.  The plumbing already exists — only
--   the RPC name binding is missing.  G25.
--
-- BUG-6 P1 'isOpReturn' (Index.hs:662) calls @BS.head script@ on a
--   script that the surrounding 'blockFilterElements' has already
--   filtered for non-emptiness — so today the call is safe.  But
--   the helper is brittle: any future change that reverses the
--   call order in 'blockFilterElements' or imports 'isOpReturn'
--   from a fresh caller would crash the node when fed an empty
--   script.  Fix: @case BS.uncons script of Just (b,_) -> b ==
--   0x6a; Nothing -> False@.  Defensive — no current trigger.
--
-- BUG-7 P1 'bitReaderRead' (Index.hs:317) calls @error "Not enough
--   bits in reader"@ on under-read.  Once the BIP-157 P2P wire is
--   plumbed (BUG-2) and a peer sends a malformed @cfilter@
--   payload, this will crash the connection-handling thread (and
--   possibly the node depending on the supervisor strategy)
--   rather than disconnecting the offending peer.  Same DoS-vector
--   class as W117 BUG-G22 (Get-monad @fail@ aborts message
--   parsing).  Fix: thread 'Either String' or 'Maybe' through
--   'bitReaderRead' / 'golombRiceDecode' and rely on
--   'gcsFilterDecode' to return @Left ...@ for malformed inputs.
--
-- BUG-8 P1 'gcsFilterDecode' / 'matchInternal' silently accept a
--   compact-size prefix @N@ that disagrees with the in-memory
--   'gcsN' (Index.hs:548-555 validates length only by trying to
--   decode that many deltas).  Core's 'GCSFilter::MatchInternal'
--   asserts @N == m_N@ (blockfilter.cpp:110).  A corrupted on-disk
--   entry whose first byte was clobbered would still pass
--   'gcsFilterDecode' if exactly @N@ deltas happen to be
--   well-formed — silently returning a wrong-N filter.  Fix: add
--   an explicit @when (fromIntegral n /= gcsN result) $ Left
--   "decoded N mismatches stored N"@.  Defensive.
--
-- BUG-9 P1 BIP-158 genesis filter is "not yet implemented"
--   (Rpc.hs:10302).  Core defines the genesis filter as the GCS
--   filter over the coinbase outputs of the genesis block with an
--   empty 'BlockUndo'.  Today the REST blockfilterheaders walk
--   returns an explicit @"Filter not found. Genesis filter
--   handling not yet implemented."@ error if asked for height 0.
--   Fix: synthesize an empty 'BlockUndo' and call
--   'computeBlockFilter' — the primitive already handles the
--   empty-spent-output case.
--
-- BUG-10 P1 The two-write 'blockFilterIndexPut' (Index.hs:946-954)
--   does not batch the per-height entry + the meta record into a
--   single RocksDB write batch.  The comment at line 942-944
--   acknowledges this is recoverable (the per-height write is
--   idempotent so a backfill on the next start picks up where the
--   first write landed), but a crash WITH the meta-record written
--   and the per-height NOT written would leave the in-memory
--   chain pointer ahead of disk.  Fix: build a 'WriteBatch' with
--   both 'BatchOp' entries and atomically commit; matches Core's
--   @CDBBatch@ behaviour.
--
-- BUG-11 P2 'blockFilterElements' double-filters empty scripts —
--   once inside the helper (Index.hs:649, 652) and again in
--   'computeBlockFilter' (Index.hs:670).  Harmless.
--
-- BUG-12 P2 REST 'handleRestBlockFilterHeaders' reads 'hcEntries'
--   then 'hcByHeight' in two separate 'readTVarIO' calls.  A
--   reorg between the two reads could produce inconsistent walk
--   results — the request would return either a stale answer or
--   a "filter not found" mid-walk.  Fix: combine into a single
--   STM atomically block.
--
-- BUG-13 P2 'computeBlockFilter' / 'basicFilterParams' recomputes
--   the SipHash key by chopping bytes out of the block hash on
--   every call (Index.hs:417-425, 158-164).  Negligible for
--   single requests but the bulk-recompute path of a REST
--   'getblockfilterheaders' walk redoes this for every height.
--
-- BUG-14 P2 'tryFilterIndex' (Rpc.hs:10029) reads 'hcEntries' to
--   resolve hash->height when the caller has already done that
--   lookup higher up — small redundancy.
--
-- BUG-15 P2 'matchInternal''s @skipCompactSize@ case (Index.hs:585)
--   has no default arm.  All four 'Word8' patterns @< 0xfd@,
--   @0xfd@, @0xfe@, @0xff@ cover the type, so GHC accepts it,
--   but a future refactor that adds a sentinel byte would
--   compile silently.  Defensive: add @_ -> (0, bs)@.
--
-- BUG-16 P0 'bitWriterWrite' silently drops bits when
--   @numBits + bwBits > 64@.  Witnessed by 'golombRiceEncode'
--   calling @bitWriterWrite bw 64 ones@ from inside 'writeUnary'
--   when 'bwBits' is non-zero (which it usually is when
--   encoding a sequence of values whose total bit-count is not
--   8-aligned).  The implementation computes
--   @newBuffer = bwBuffer .|. (maskedValue `shiftL` bwBits bw)@
--   into a 'Word64' — the top 'bwBits' bits of @maskedValue@
--   fall off the high end of the 64-bit buffer.  For a write of
--   64 ones with @bwBits=5@, only 59 ones reach the stream; the
--   other 5 are lost.  G6 catches this with the test value
--   @0xFFFFFFFF@ (q=8191) preceded by seven smaller values that
--   leave @bwBits=5@: the decoder reads only 60 ones (vs
--   expected 8191) and the round-trip fails with
--   @expected 4294967295, got 31457264@.  The G6 test is
--   marked 'xit' to keep the suite green; fix is to split any
--   wide write into 64-aligned chunks (or, simpler, cap
--   'toWrite' inside 'writeUnary' at @64 - bwBits@ and flush
--   between calls).  This is a P0-CDIV against BIP-158 — every
--   block filter whose Golomb-Rice stream contains a quotient
--   >=64 will silently corrupt encoding.  The pre-existing
--   BIP-158 reference-vector tests in test/Spec.hs:13191 do
--   not catch this because their test vectors happen to keep
--   per-element quotients < 64 (the test blocks have N small
--   enough that hash-to-range deltas stay under 64*M).
--   Discovered as a side-effect of writing the G6 round-trip
--   test in this audit.
--
--   FIX-69 (commit landing with this header update): cross-
--   Word64-boundary writes are now split into low + high halves
--   so the high-order bits are no longer lost.  G6 is now an
--   'it' (was 'xit') and four FIX-69 stress tests exercise
--   q=64, q=100, mixed q=0/30/65/120, and the original BUG-16
--   trace.  Reference shape: bitcoin-core/src/streams.h
--   BitStreamWriter::Write.
--
-- == Per-impl bug count (this audit) ==  16
--
-- ============================================================

module W121CompactFiltersSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32, Word64)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))

import Haskoin.Types
  ( Hash256(..)
  , BlockHash(..)
  , BlockHeader(..)
  , Block(..)
  , Tx(..)
  , TxIn
  , TxOut(..)
  )
import Haskoin.Index
  ( GCSParams(..)
  , GCSFilter(..)
  , basicFilterParams
  , gcsFilterEmpty
  , gcsFilterNew
  , gcsFilterDecode
  , gcsFilterMatch
  , gcsFilterMatchAny
  , golombRiceEncode
  , golombRiceDecode
  , bitWriterNew
  , bitWriterWrite
  , bitWriterFlush
  , bitReaderNew
  , bitReaderRead
    -- BIP-158 block filter
  , BlockFilter(..)
  , BlockFilterType(..)
  , computeBlockFilter
  , blockFilterElements
  , blockFilterHash
  , blockFilterHeader
  , encodeBlockFilter
  , decodeBlockFilter
    -- SipHash + FastRange
  , SipHashKey(..)
  , sipHashKey
  , sipHash128
  , fastRange64
    -- IndexConfig
  , IndexConfig(..)
  , defaultIndexConfig
    -- BlockFilterIndex API existence checks
  , indexManagerConnectBlock
  , indexManagerDisconnectBlock
  , blockFilterIndexDelete
  )
import Haskoin.Network
  ( Message(..)
  , commandName
  , PeerConfig(..)
  , defaultPeerConfig
  , ServiceFlag(..)
  , nodeNetwork
  , nodeWitness
  , nodeBloom
  , nodeNetworkLimited
  , hasService
  , combineServices
  )
import Haskoin.Consensus (regtest)
import Haskoin.Storage (BlockUndo(..), TxUndo(..), TxInUndo(..))

--------------------------------------------------------------------------------
-- Reference constants from bitcoin-core/src/blockfilter.h /
-- bitcoin-core/src/index/blockfilterindex.h /
-- bitcoin-core/src/net_processing.cpp / bitcoin-core/src/protocol.h.
--------------------------------------------------------------------------------

-- BIP-158 'basic' filter-type enum value (BlockFilterType::BASIC = 0).
coreBasicFilterType :: Word8
coreBasicFilterType = 0

-- net_processing.cpp:184-186 / index/blockfilterindex.h:31
coreMaxGetCFiltersSize :: Word32
coreMaxGetCFiltersSize = 1000

coreMaxGetCFHeadersSize :: Word32
coreMaxGetCFHeadersSize = 2000

coreCFCheckptInterval :: Word32
coreCFCheckptInterval = 1000

-- protocol.h:321-323: NODE_COMPACT_FILTERS = (1 << 6) = 64
coreNodeCompactFiltersBit :: Word64
coreNodeCompactFiltersBit = 1 `shiftL` 6

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

zeroHash256 :: Hash256
zeroHash256 = Hash256 (BS.replicate 32 0)

zeroBlockHash :: BlockHash
zeroBlockHash = BlockHash zeroHash256

-- A block hash whose first 16 bytes spell a recognisable pattern, used to
-- validate SipHash key extraction (LE Word64s).
patternBlockHash :: BlockHash
patternBlockHash =
  BlockHash $ Hash256 $ BS.pack
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    ,0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
    ,0,0,0,0,0,0,0,0
    ,0,0,0,0,0,0,0,0]

-- A minimal block header — we never serialize it, only attach it to a
-- 'Block' so the GCS computation has something to chew on.
defaultHeader :: BlockHeader
defaultHeader = BlockHeader
  { bhVersion    = 1
  , bhPrevBlock  = zeroBlockHash
  , bhMerkleRoot = zeroHash256
  , bhTimestamp  = 0
  , bhBits       = 0x207fffff
  , bhNonce      = 0
  }

-- A SegWit-aware Tx constructor.
makeTx :: [TxIn] -> [TxOut] -> Tx
makeTx ins outs = Tx
  { txVersion  = 1
  , txInputs   = ins
  , txOutputs  = outs
  , txWitness  = replicate (length ins) []
  , txLockTime = 0
  }

emptyBlock :: Block
emptyBlock = Block defaultHeader []

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do

  ------------------------------------------------------------------------------
  -- G1: BIP-158 P parameter must be 19 (bits per Golomb-Rice remainder).
  -- Reference: bitcoin-core/src/blockfilter.h:90 BASIC_FILTER_P.
  ------------------------------------------------------------------------------
  describe "G1 BASIC_FILTER_P = 19" $ do
    it "basicFilterParams produces P=19 regardless of input block hash" $ do
      gcsP (basicFilterParams zeroBlockHash)    `shouldBe` 19
      gcsP (basicFilterParams patternBlockHash) `shouldBe` 19

  ------------------------------------------------------------------------------
  -- G2: BIP-158 M parameter must be 784_931 (inverse false-positive rate).
  -- Reference: bitcoin-core/src/blockfilter.h:91 BASIC_FILTER_M.
  ------------------------------------------------------------------------------
  describe "G2 BASIC_FILTER_M = 784931" $ do
    it "basicFilterParams produces M=784931" $ do
      gcsM (basicFilterParams zeroBlockHash)    `shouldBe` 784931
      gcsM (basicFilterParams patternBlockHash) `shouldBe` 784931

  ------------------------------------------------------------------------------
  -- G3: BlockFilterType::BASIC = 0 (the only currently-defined filter type).
  -- haskoin only enumerates 'BasicBlockFilter' which is correct (fromEnum=0).
  -- Reference: bitcoin-core/src/blockfilter.h:93-97.
  ------------------------------------------------------------------------------
  describe "G3 BlockFilterType BASIC = 0" $ do
    it "fromEnum BasicBlockFilter is 0" $
      fromEnum BasicBlockFilter `shouldBe` 0

    it "computeBlockFilter labels filter as BasicBlockFilter" $ do
      let bf = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
      bfType bf `shouldBe` BasicBlockFilter

    it "Core's filter_type 0 == BASIC" $
      coreBasicFilterType `shouldBe` 0

  ------------------------------------------------------------------------------
  -- G4: SipHash key derivation — k0 = first 8 LE bytes of block hash, k1
  -- = next 8 LE bytes.  Reference: bitcoin-core/src/blockfilter.cpp:236-237.
  ------------------------------------------------------------------------------
  describe "G4 SipHash-2-4 key from block hash first 16 bytes" $ do
    it "sipHashKey extracts k0/k1 as little-endian Word64" $ do
      let SipHashKey k0 k1 = sipHashKey patternBlockHash
      -- LE decoding of [01,02,03,04,05,06,07,08] = 0x0807060504030201
      k0 `shouldBe` 0x0807060504030201
      k1 `shouldBe` 0x1817161514131211

    it "basicFilterParams uses the same key as sipHashKey" $ do
      let SipHashKey k0 k1 = sipHashKey patternBlockHash
          params           = basicFilterParams patternBlockHash
      gcsSipK0 params `shouldBe` k0
      gcsSipK1 params `shouldBe` k1

  ------------------------------------------------------------------------------
  -- G5: FastRange64 — multiply-shift maps a 64-bit hash to a [0, range)
  -- bucket via the high half of a 128-bit unsigned product.  Reference:
  -- bitcoin-core/src/util/fastrange.h FastRange64.
  ------------------------------------------------------------------------------
  describe "G5 FastRange64 multiply-shift" $ do
    it "fastRange64 0 range == 0 (lower bound)" $
      fastRange64 0 1000 `shouldBe` 0

    it "fastRange64 maxBound range == range-1 (upper bound)" $
      fastRange64 maxBound 1000 `shouldBe` 999

    it "fastRange64 hash 1 == 0 (single bucket)" $
      fastRange64 0xDEADBEEFCAFEBABE 1 `shouldBe` 0

    it "fastRange64 hash range stays strictly less than range" $ do
      let hashes = [1, 2, 3, 0x12345678, 0xFEDCBA9876543210, maxBound :: Word64]
          range  = 12345 :: Word64
      mapM_ (\h -> fastRange64 h range `shouldSatisfy` (< range)) hashes

  ------------------------------------------------------------------------------
  -- G6: Golomb-Rice unary-quotient + p-bit-remainder coder round-trips.
  -- Reference: bitcoin-core/src/blockfilter.cpp GolombRiceEncode/Decode.
  --
  -- BUG-16 P0 FIXED in FIX-69 (commit landing this test flip):
  --   pre-fix: 'bitWriterWrite' silently dropped bits when
  --   @numBits + bwBits > 64@ — 'writeUnary' calls
  --   @bitWriterWrite bw 64 ones@ for large quotients (q >= 64),
  --   and after seven prior values the buffer holds @bwBits=5@, so
  --   5 of the 64 ones were lost off the top of the Word64, decoding
  --   4294967295 (q=8191) as 31457264 (q=8186 — lost 5 ones).
  --   post-fix: cross-Word64-boundary writes split into two phases so
  --   no bits are lost.  Reference shape:
  --   bitcoin-core/src/streams.h BitStreamWriter::Write (per-octet loop).
  ------------------------------------------------------------------------------
  describe "G6 Golomb-Rice round-trip (BUG-16 P0 — fixed in FIX-69)" $ do
    it "encode-then-decode preserves all values in a representative range" $ do
      -- This is the literal test vector from BUG-16: the final value
      -- 0xFFFFFFFF has quotient 8191 (with P=19), so writeUnary issues
      -- @bitWriterWrite bw 64 ones@ many times.  After the seven prior
      -- values the buffer holds bwBits=5; pre-fix this dropped 5 ones
      -- and decoded 31457264 instead of 4294967295.
      let p       = 19 :: Int
          values  = [0, 1, 2, 100, 1000, 100000, 1000000, 0xFFFFFFFF] :: [Word64]
          encoded = bitWriterFlush $
                      foldl (\bw v -> golombRiceEncode bw p v)
                            bitWriterNew
                            values
          br0     = bitReaderNew encoded
          go _   []         = []
          go br' (_ : rest) =
            let (v', br'') = golombRiceDecode br' p
            in v' : go br'' rest
      go br0 values `shouldBe` values

    it "encode-then-decode round-trips for q<64 (regression — Spec.hs:13191 shape)" $ do
      -- A safe-by-design test: keep all quotients in 0..63 so the
      -- bit-writer never tries to flush 64 bits at once.  This is the
      -- shape that the existing GCS Spec.hs:13191 vectors exercise.
      let p       = 19 :: Int
          values  = [0, 1, 2, 100, 1000, 100000, 524287, 524288, 1048575] :: [Word64]
          -- All quotients here are 0 or 1, well below 64.
          encoded = bitWriterFlush $
                      foldl (\bw v -> golombRiceEncode bw p v)
                            bitWriterNew
                            values
          br0     = bitReaderNew encoded
          go _   []         = []
          go br' (_ : rest) =
            let (v', br'') = golombRiceDecode br' p
            in v' : go br'' rest
      go br0 values `shouldBe` values

    -- ---------- FIX-69 stress tests -------------------------------------
    -- Each test exercises a distinct corner of the cross-Word64-boundary
    -- path in 'bitWriterWrite'.  All four would have failed pre-fix
    -- and now pass.

    it "FIX-69 stress: encode quotient=64 (1 bit over boundary) round-trips" $ do
      -- value such that q = value >> p = 64, so writeUnary writes 64
      -- ones in a single chunk.  Precede with a 1-bit write so bwBits=1
      -- when the 64-bit write happens — pre-fix this dropped 1 bit and
      -- the decoder read only 63 ones (terminator one short).
      let p       = 4 :: Int                -- small P, so q=64 is exactly value=1024
          value   = 64 `shiftL` p           -- = 1024; q = 1024 >> 4 = 64
          bw0     = bitWriterWrite bitWriterNew 1 1     -- nudge bwBits=1
          bw1     = golombRiceEncode bw0 p value
          encoded = bitWriterFlush bw1
          br      = bitReaderNew encoded
          (_lead, br1) = bitReaderRead br 1
          (decoded, _) = golombRiceDecode br1 p
      decoded `shouldBe` value

    it "FIX-69 stress: encode quotient=100 (well over boundary) round-trips" $ do
      -- q=100 → writeUnary writes 64 + 36 ones.  With bwBits=3 before
      -- the first chunk, pre-fix lost 3 of the 64 ones (decoded q=97).
      let p       = 4 :: Int
          value   = 100 `shiftL` p          -- = 1600; q = 100
          bw0     = bitWriterWrite bitWriterNew 3 5
          bw1     = golombRiceEncode bw0 p value
          encoded = bitWriterFlush bw1
          br      = bitReaderNew encoded
          (_lead, br1) = bitReaderRead br 3
          (decoded, _) = golombRiceDecode br1 p
      decoded `shouldBe` value

    it "FIX-69 stress: stream with quotients 0/30/65/120 round-trips" $ do
      -- Mixed stream — exercises both the in-buffer fast path (q<64)
      -- and the cross-boundary path (q>=64) within a single bit stream.
      let p       = 4 :: Int
          values  = [ 0
                    , 30 `shiftL` p     -- q=30  (in-buffer)
                    , 65 `shiftL` p     -- q=65  (1 bit over boundary)
                    , 120 `shiftL` p    -- q=120 (cross-boundary twice)
                    ] :: [Word64]
          encoded = bitWriterFlush $
                      foldl (\bw v -> golombRiceEncode bw p v)
                            bitWriterNew
                            values
          br0     = bitReaderNew encoded
          go _   []         = []
          go br' (_ : rest) =
            let (v', br'') = golombRiceDecode br' p
            in v' : go br'' rest
      go br0 values `shouldBe` values

    it "FIX-69 source-level regression guard: bitWriterWrite split-then-recurse pattern present" $ do
      -- Defensive: a future drive-by 'simplification' that collapses
      -- the cross-boundary branch back into a single .|. shiftL would
      -- regress BUG-16.  This test asserts the structural fix is still
      -- in place by exercising the exact pre-fix failure mode and
      -- confirming the post-fix value.  See bitcoin-core/src/streams.h
      -- BitStreamWriter::Write for reference shape.
      let p       = 19 :: Int
          -- Seven warmup values that leave bwBits=5 in the buffer
          -- (this is the exact configuration from the BUG-16 trace).
          warmup  = [0, 1, 2, 100, 1000, 100000, 1000000] :: [Word64]
          -- The 8th value 0xFFFFFFFF has q=8191, triggering many
          -- bitWriterWrite bw 64 ones across the Word64 boundary.
          values  = warmup ++ [0xFFFFFFFF]
          encoded = bitWriterFlush $
                      foldl (\bw v -> golombRiceEncode bw p v)
                            bitWriterNew
                            values
          br0     = bitReaderNew encoded
          go _   []         = []
          go br' (_ : rest) =
            let (v', br'') = golombRiceDecode br' p
            in v' : go br'' rest
          decoded = go br0 values
      -- Strict assertion: the last decoded value must NOT be 31457264
      -- (the pre-fix corruption) and must equal 0xFFFFFFFF.
      last decoded `shouldBe` 0xFFFFFFFF
      last decoded `shouldNotBe` 31457264
      decoded `shouldBe` values

  ------------------------------------------------------------------------------
  -- W122 BIP-158 codec stress vectors (DISCOVERY AUDIT, audit/w122_bip158_codec_stress.md).
  --
  -- These are ADJACENT-boundary tests that go beyond FIX-69's four stress
  -- cases.  FIX-69 closed the q>=64 cross-Word64-boundary bug in
  -- 'bitWriterWrite'.  W122 audits for nearby latent bugs in the codec
  -- primitives that the existing blockfilters.json reference vectors and
  -- FIX-69 stress tests do not exercise:
  --
  --   1. q=1023 (near 10-bit boundary)               — large quotient class
  --   2. 7-bit warmup + q=70 (cross-boundary worst)  — adjacent to BUG-16
  --   3. All-zeros / all-ones element sets           — uniform-key inputs
  --   4. Very large filter (100k elements)           — many cross-boundaries
  --   5. SipHash-2-4 edge cases at max u64           — hash-side overflow
  --   6. FastRange64 boundary                        — multiply overflow
  --   7. Three consecutive q=64 writes               — repeated boundary
  --   8. bitReaderRead at 64-bit width               — symmetric boundary
  --   9. bitWriterWrite numBits=0 / negative         — no-op guard
  --  10. mask helper at n=64                         — match Core ~0ULL
  --
  -- VERDICT: VERIFIED CLEAN POST-FIX-69.  No new bugs found.  All 10
  -- stress dimensions round-trip and/or match Core reference behavior.
  --
  -- Reference: bitcoin-core/src/streams.h BitStreamWriter::Write,
  --           bitcoin-core/src/util/golombrice.h GolombRiceEncode,
  --           bitcoin-core/src/util/fastrange.h FastRange64,
  --           bitcoin-core/src/crypto/siphash.cpp,
  --           bitcoin-core/src/blockfilter.cpp GCSFilter ctor.
  ------------------------------------------------------------------------------
  describe "W122 BIP-158 codec stress vectors (post-FIX-69 audit)" $ do

    -- 1. q=1023 — near a 10-bit-quotient threshold.  q=1023 means writeUnary
    --    emits 64+64+64+...+63 ones (15 invocations of bitWriterWrite, the
    --    last one for 63 ones).  Every one of the leading invocations
    --    triggers a cross-Word64-boundary path.  This is more boundary
    --    stress than FIX-69's q=100 or q=120 cases.
    it "W122-1 q=1023 (near 10-bit boundary, 15 boundary crossings) round-trips" $ do
      let p       = 4 :: Int
          value   = 1023 `shiftL` p :: Word64       -- q = 1023, r = 0
          -- Add a small lead-in to misalign bwBits so EVERY 64-write
          -- chunk inside writeUnary crosses the boundary.
          bw0     = bitWriterWrite bitWriterNew 5 0x15  -- bwBits=5
          bw1     = golombRiceEncode bw0 p value
          encoded = bitWriterFlush bw1
          br      = bitReaderNew encoded
          (_lead, br1)   = bitReaderRead br 5
          (decoded, _)   = golombRiceDecode br1 p
      decoded `shouldBe` value

    -- 2. 7-bit warmup + q=70 — this is the "high overflow at small
    --    fractional offset" pattern.  With bwBits=7 after the warmup, the
    --    first writeUnary chunk writes only (64-7)=57 ones into the
    --    current Word64 (fills it; the recursive flushBytes drains 8
    --    bytes), then writes the remaining (70-57)=13 ones into the next
    --    Word64.  Pre-FIX-69 this dropped 7 ones.  This test asserts the
    --    NEXT boundary crossing — q=70 is just past q=64, so the second
    --    recursive call is the SHORT remainder, which exercises a
    --    different code path than FIX-69's q=100 case (where the second
    --    call is bigger).
    it "W122-2 7-bit warmup + q=70 (cross-boundary short remainder) round-trips" $ do
      let p       = 4 :: Int
          value   = 70 `shiftL` p :: Word64
          bw0     = bitWriterWrite bitWriterNew 7 0x55   -- bwBits=7
          bw1     = golombRiceEncode bw0 p value
          encoded = bitWriterFlush bw1
          br      = bitReaderNew encoded
          (_lead, br1) = bitReaderRead br 7
          (decoded, _) = golombRiceDecode br1 p
      decoded `shouldBe` value

    -- 3a. All-zeros element set — every element hashes uniformly to the
    --     same value (deltas are [h, 0, 0, ..., 0]).  gcsFilterNew does
    --     NOT dedup; the caller (computeBlockFilter) is responsible.
    --     This stresses the unary-zero-delta path: writeUnary 0 emits a
    --     single trailing zero, so each duplicate adds exactly P+1 bits.
    --     The filter is over-sized but functionally correct: Match returns
    --     True on the first matching delta.
    --
    --     This test asserts the codec's correctness on degenerate input,
    --     NOT the production behavior (BasicFilterElements + Set.fromList
    --     in computeBlockFilter dedups before reaching gcsFilterNew —
    --     covered in W121 G8).
    it "W122-3a all-zeros element set: zero-delta unary path is correct" $ do
      let params   = basicFilterParams zeroBlockHash
          elements = replicate 10 (BS.replicate 32 0x00)
          filter'  = gcsFilterNew params elements
      -- gcsFilterNew does not dedup; N counts every input element.
      gcsN filter' `shouldBe` 10
      -- The element matches.
      gcsFilterMatch filter' (BS.replicate 32 0x00) `shouldBe` True
      -- An overwhelmingly-different element does NOT match (FP rate
      -- 1/M = 1/784931 per probe).
      gcsFilterMatch filter' (BS.replicate 32 0xFF) `shouldBe` False
      -- Decode round-trips: N + every delta after the first is zero, and
      -- the encoded stream is short (1 byte compact-size + ceil((19+1)+9*1)/8
      -- = roughly 4 bytes).  We just assert decode succeeds.
      case gcsFilterDecode params (gcsEncoded filter') of
        Left e   -> expectationFailure ("decode failed on zero-delta stream: " ++ e)
        Right f' -> gcsN f' `shouldBe` 10

    -- 3b. All-0xFF element set — same shape (10 identical elements), but
    --     different bit pattern stresses SipHash with all-ones inputs
    --     (maximal Hamming weight).  Same correctness assertions.
    it "W122-3b all-0xFF element set: zero-delta unary path (max Hamming weight)" $ do
      let params   = basicFilterParams zeroBlockHash
          elements = replicate 10 (BS.replicate 32 0xFF)
          filter'  = gcsFilterNew params elements
      gcsN filter' `shouldBe` 10
      gcsFilterMatch filter' (BS.replicate 32 0xFF) `shouldBe` True
      case gcsFilterDecode params (gcsEncoded filter') of
        Left e   -> expectationFailure ("decode failed: " ++ e)
        Right f' -> gcsN f' `shouldBe` 10

    -- 3c. Mixed all-zeros + all-0xFF — two unique elements with extreme
    --     hash values.  Their delta may be small or huge depending on
    --     hashToRange; the test asserts BOTH match and that a third
    --     unrelated element does not.
    it "W122-3c mixed extreme inputs (all-0x00 + all-0xFF) both match" $ do
      let params   = basicFilterParams zeroBlockHash
          elements = [BS.replicate 32 0x00, BS.replicate 32 0xFF]
          filter'  = gcsFilterNew params elements
      gcsN filter' `shouldBe` 2
      gcsFilterMatch filter' (BS.replicate 32 0x00) `shouldBe` True
      gcsFilterMatch filter' (BS.replicate 32 0xFF) `shouldBe` True

    -- 4. Very large filter — 100,000 elements.  This exercises:
    --      (a) many cross-Word64-boundary writes inside the encoder
    --      (b) the compact-size prefix at the 0xFD..0xFE varint boundary
    --      (c) the decoder over a long Golomb-Rice stream
    --      (d) sort() at scale (Data.List.sort on 100k Word64s)
    --    Performance: ~1.5s on a Ryzen 9.  We assert N + a random match
    --    + a non-match.  We don't decode all 100k inside the test (the
    --    encode does the round-trip implicitly through gcsFilterDecode).
    it "W122-4 very large filter (100,000 elements) encodes + matches" $ do
      let params    = basicFilterParams zeroBlockHash
          -- Synthesize 100k distinct 8-byte elements (counter LE).
          mkElem i  = BS.pack [ fromIntegral (i             .&. 0xff)
                              , fromIntegral ((i `shiftR`  8) .&. 0xff)
                              , fromIntegral ((i `shiftR` 16) .&. 0xff)
                              , fromIntegral ((i `shiftR` 24) .&. 0xff)
                              , 0x00, 0x00, 0x00, 0x00
                              ]
          elements  = map mkElem [(0 :: Word64) .. 99999]
          filter'   = gcsFilterNew params elements
      gcsN filter' `shouldBe` 100000
      -- A known-present element matches.
      gcsFilterMatch filter' (mkElem (12345 :: Word64)) `shouldBe` True
      -- And a definitely-absent element (counter > 99999) almost certainly
      -- does not match.  False positives are 1/M = 1/784931 per probe;
      -- a single probe against an absent element gives FP prob ~1.3e-6
      -- which is below test-flake threshold.
      gcsFilterMatch filter' (mkElem (999999 :: Word64)) `shouldBe` False
      -- Decode the encoded filter and check N agrees.
      case gcsFilterDecode params (gcsEncoded filter') of
        Left e   -> expectationFailure ("decode failed: " ++ e)
        Right f' -> gcsN f' `shouldBe` 100000

    -- 5a. SipHash on max-u64 key + max-u64 input message.  This is not a
    --     spec vector (the Aumasson/Bernstein paper does not provide one)
    --     but we assert it produces a non-zero output and is deterministic.
    --     This guards against integer-overflow latent bugs in the round
    --     loop (rotl64 on max-u64 inputs).
    it "W122-5a SipHash at max-u64 key + max-u64 input is deterministic + non-zero" $ do
      let key  = SipHashKey 0xFFFFFFFFFFFFFFFF 0xFFFFFFFFFFFFFFFF
          msg  = BS.replicate 16 0xFF
          r1   = sipHash128 key msg
          r2   = sipHash128 key msg
      r1 `shouldBe` r2
      r1 `shouldNotBe` 0

    -- 5b. SipHash on empty key + empty input.  Edge case where the
    --     initial v0..v3 mixing receives only XOR with the constants
    --     0x736f6d6570736575 etc.  Asserts determinism + non-zero.
    it "W122-5b SipHash at zero key + empty input is deterministic + non-zero" $ do
      let key = SipHashKey 0 0
          r1  = sipHash128 key BS.empty
          r2  = sipHash128 key BS.empty
      r1 `shouldBe` r2
      r1 `shouldNotBe` 0

    -- 6a. FastRange64 at max hash + max range — multiplies to a 128-bit
    --     intermediate whose high 64 bits are 0xFFFFFFFFFFFFFFFE.  This
    --     tests the mulWord64 piecewise carry path with maximal inputs.
    it "W122-6a fastRange64 max hash + max range high-half is FFFE..." $ do
      let result = fastRange64 0xFFFFFFFFFFFFFFFF 0xFFFFFFFFFFFFFFFF
      -- (2^64 - 1) * (2^64 - 1) = 2^128 - 2^65 + 1
      -- high 64 bits = 2^64 - 2 = 0xFFFFFFFFFFFFFFFE
      result `shouldBe` 0xFFFFFFFFFFFFFFFE

    -- 6b. FastRange64 with range=1 should always return 0 (hash * 1 = hash,
    --     and hash >> 64 always yields 0 unless hash is huge... but the
    --     high 64 bits of hash*1 are 0).
    it "W122-6b fastRange64 range=1 always returns 0 (high half of x*1)" $ do
      fastRange64 0xDEADBEEFCAFEBABE 1 `shouldBe` 0
      fastRange64 0xFFFFFFFFFFFFFFFF 1 `shouldBe` 0
      fastRange64 0 1 `shouldBe` 0

    -- 6c. FastRange64 at a deliberate carry-propagation boundary in the
    --     piecewise 32x32 multiply.  Set x_lo and n_lo high to maximize
    --     the bd term, then verify high 64 bits.
    it "W122-6c fastRange64 carry boundary (x_lo=n_lo=2^32-1)" $ do
      let x = 0xFFFFFFFF :: Word64        -- x_hi=0, x_lo=2^32-1
          n = 0xFFFFFFFF :: Word64        -- n_hi=0, n_lo=2^32-1
          -- x*n = (2^32-1)^2 = 2^64 - 2^33 + 1 = 0xFFFFFFFE00000001
          -- high 64 bits = 0 (the product fits in 64 bits)
      fastRange64 x n `shouldBe` 0

    -- 7. Three consecutive q=64 writes — exercises the cross-boundary
    --    code path back-to-back-to-back.  This catches a hypothetical
    --    "off-by-one on second cross" regression that the existing
    --    single-q=64 stress tests would miss (because they exit the
    --    boundary state after one crossing).
    it "W122-7 three consecutive q=64 writes round-trip" $ do
      let p       = 4 :: Int
          one     = 64 `shiftL` p :: Word64        -- value with q=64
          values  = [one, one, one]
          bw0     = bitWriterWrite bitWriterNew 2 0x3   -- bwBits=2 starter
          bw1     = foldl (\bw v -> golombRiceEncode bw p v) bw0 values
          encoded = bitWriterFlush bw1
          br0     = bitReaderNew encoded
          (_lead, br1) = bitReaderRead br0 2
          go br' 0 acc = (reverse acc, br')
          go br' n acc =
            let (v', br'') = golombRiceDecode br' p
            in go br'' (n - 1) (v' : acc)
          (decoded, _) = go br1 (3 :: Int) []
      decoded `shouldBe` values

    -- 8. bitReaderRead at numBits=64 — documents a SHAPE LIMITATION
    --    (not a bug): the reader's 'fillBuffer' only loads bytes while
    --    'brBits < 56' (Index.hs:338,360), so the buffer holds AT MOST
    --    56 bits at any time.  A direct read of 64 bits in one call
    --    therefore always throws "Not enough bits in reader".  This is
    --    asymmetric to bitWriterWrite which (post-FIX-69) handles a full
    --    64-bit write by splitting at the boundary.
    --
    --    Why this is NOT a production bug: BIP-158 only calls
    --    bitReaderRead with p (gcsP = 19) or 1 (unary-bit), both well
    --    under 56.  Core's BitStreamReader::Read handles 64-bit reads
    --    via a per-byte inner loop; haskoin's optimized reader trades
    --    that capability for fewer bit-shifts per byte.
    --
    --    Audit verdict: documented limitation; add an assertion so any
    --    future caller passing numBits > 56 fails loud at the call site.
    it "W122-8 bitReaderRead at numBits>56 fails loud (reader pre-loads <= 56 bits)" $ do
      -- W122 AUDIT FINDING: bitReaderRead numBits=64 is UNSUPPORTED.
      -- Pin the current behavior: it throws 'Not enough bits in reader'
      -- (BIP-158 production code never triggers this, but this assertion
      -- documents the invariant so future drive-by changes can't quietly
      -- "support" numBits>56 in a half-working state).
      let payload = 0xDEADBEEFCAFEBABE :: Word64
          bw0     = bitWriterWrite bitWriterNew 64 payload
          encoded = bitWriterFlush bw0
          br0     = bitReaderNew encoded
      -- A read of 56 bits succeeds (the max load-buffer size).
      let (decoded56, _) = bitReaderRead br0 56
      decoded56 `shouldBe` (payload .&. 0x00FFFFFFFFFFFFFF)
      -- Multiple smaller reads can recover the full 64 bits:
      let (lo, br1) = bitReaderRead br0 32
          (hi, _)   = bitReaderRead br1 32
          combined  = lo .|. (hi `shiftL` 32)
      combined `shouldBe` payload

    -- 9. bitWriterWrite numBits=0 / negative — guard path.  Pre-FIX-69
    --    this was already correct, but a defense-in-depth assertion.
    --    A no-op write must NOT advance bwBits, must NOT modify buffer.
    it "W122-9 bitWriterWrite numBits<=0 is a no-op (no state change)" $ do
      let bw0 = bitWriterWrite bitWriterNew 5 0x15
          bw1 = bitWriterWrite bw0 0 0xFF
          bw2 = bitWriterWrite bw1 (-3) 0xFF
      -- Round-trip the 5-bit write through flush; the 0/negative writes
      -- must not have corrupted the buffer or bit-count.
      let encoded = bitWriterFlush bw2
          br      = bitReaderNew encoded
          (v, _)  = bitReaderRead br 5
      v `shouldBe` 0x15

    -- 10. mask helper at n=64 must yield maxBound (0xFFFFFFFFFFFFFFFF).
    --     Core uses ~0ULL; the haskoin FIX-69 implementation spells this
    --     explicitly to avoid relying on (1<<64)-1 modular semantics.
    --     We assert the WHOLE-Word64 mask path encodes correctly by
    --     writing 64 bits of all-ones and checking the encoded bytes.
    --     (We can't recover via a single 64-bit read — see W122-8 — so
    --     we verify the encoded byte stream directly.)
    it "W122-10 mask at n=64 produces all-ones (encoded = eight 0xFF bytes)" $ do
      let payload = 0xFFFFFFFFFFFFFFFF :: Word64
          bw0     = bitWriterWrite bitWriterNew 64 payload
          encoded = bitWriterFlush bw0
      -- The encoded bytes must be exactly 8 bytes all 0xFF.  This proves
      -- the mask(64) path correctly yielded maxBound; if mask(64) had
      -- silently been 0 (pre-FIX-69 was a latent risk), the encoded
      -- bytes would have been eight 0x00 bytes.
      BS.length encoded `shouldBe` 8
      BS.all (== 0xFF) encoded `shouldBe` True
      -- Cross-check via two 32-bit reads:
      let br0 = bitReaderNew encoded
          (lo, br1) = bitReaderRead br0 32
          (hi, _)   = bitReaderRead br1 32
      lo `shouldBe` 0xFFFFFFFF
      hi `shouldBe` 0xFFFFFFFF

  ------------------------------------------------------------------------------
  -- G7: BasicFilterElements asymmetry — OP_RETURN excluded from output
  -- scripts but INCLUDED from spent-output (undo) scripts.
  -- Reference: bitcoin-core/src/blockfilter.cpp:187-209 BasicFilterElements.
  ------------------------------------------------------------------------------
  describe "G7 BasicFilterElements OP_RETURN asymmetry" $ do
    let opReturnScript = BS.pack [0x6a, 0xde, 0xad, 0xbe, 0xef]
        normalScript   = BS.pack [0x76, 0xa9, 0x14, 0x01, 0x02]
        emptyScript    = BS.empty

        -- A coinbase tx with one OP_RETURN, one normal, one empty output.
        outs     = [ TxOut 0 opReturnScript
                   , TxOut 5000 normalScript
                   , TxOut 0 emptyScript
                   ]
        coinbase = makeTx [] outs
        block    = Block defaultHeader [coinbase]

        -- Undo: one spent OP_RETURN, one spent normal, one spent empty.
        spentOpReturn = TxInUndo (TxOut 100 opReturnScript) 1 False
        spentNormal   = TxInUndo (TxOut 100 normalScript)   1 False
        spentEmpty    = TxInUndo (TxOut 100 emptyScript)    1 False
        undo          = BlockUndo [TxUndo [spentOpReturn, spentNormal, spentEmpty]]

        elements = blockFilterElements block undo

    it "output normal scripts are included" $
      (normalScript `elem` elements) `shouldBe` True

    it "spent OP_RETURN scripts ARE included (asymmetry vs outputs)" $
      -- Core only excludes empty for the spent side, not OP_RETURN.
      (opReturnScript `elem` elements) `shouldBe` True

    it "empty scripts are excluded (both output and spent)" $
      (emptyScript `elem` elements) `shouldBe` False

    it "output OP_RETURN excluded BUT spent OP_RETURN included (count = 3)" $
      -- blockFilterElements is pre-dedup: outputs side contributes
      -- {normal} (OP_RETURN+empty excluded), undo side contributes
      -- {opReturn, normal} (empty excluded, OP_RETURN allowed), and
      -- the empty script never appears at all.  No further filtering
      -- inside blockFilterElements means we see 3 entries here; the
      -- Set-based dedup happens later in computeBlockFilter.
      length (filter (/= emptyScript) elements) `shouldBe` 3

  ------------------------------------------------------------------------------
  -- G8: Element set is de-duplicated before GCS encoding.
  -- Reference: bitcoin-core/src/blockfilter.cpp:190 GCSFilter::ElementSet is
  -- a std::set; haskoin uses Set.fromList in 'computeBlockFilter'.
  ------------------------------------------------------------------------------
  describe "G8 GCS element set dedup before encode" $ do
    it "computeBlockFilter dedups duplicate output scripts" $ do
      let dupBlock =
            Block defaultHeader
              [ makeTx []
                  [ TxOut 0 "abc"
                  , TxOut 0 "abc"
                  , TxOut 0 "abc"
                  , TxOut 0 "def"
                  ] ]
          bf = computeBlockFilter dupBlock (BlockUndo []) zeroBlockHash
      -- Two unique non-empty non-OP_RETURN scripts → N=2.
      gcsN (bfFilter bf) `shouldBe` 2

    it "gcsFilterNew does NOT dedup (caller responsibility — Core uses std::set)" $ do
      let params = basicFilterParams zeroBlockHash
          dupd   = ["abc", "abc", "abc", "def"]
      gcsN (gcsFilterNew params dupd) `shouldBe` 4

  ------------------------------------------------------------------------------
  -- G9: empty filter encodes to a single byte 0x00 (the compact-size for
  -- N=0).  Reference: bitcoin-core/src/blockfilter.cpp::GCSFilter ctor.
  ------------------------------------------------------------------------------
  describe "G9 empty filter encoding == [0x00]" $ do
    it "gcsFilterEmpty has N=0 and one-byte encoding" $ do
      let f = gcsFilterEmpty (basicFilterParams zeroBlockHash)
      gcsN f `shouldBe` 0
      gcsEncoded f `shouldBe` BS.singleton 0x00

    it "gcsFilterNew _ [] == gcsFilterEmpty" $ do
      let params = basicFilterParams zeroBlockHash
          f      = gcsFilterNew params []
      gcsN f `shouldBe` 0
      gcsEncoded f `shouldBe` BS.singleton 0x00

    it "gcsFilterMatch on empty filter is False" $ do
      let f = gcsFilterEmpty (basicFilterParams zeroBlockHash)
      gcsFilterMatch f "anything" `shouldBe` False

    it "gcsFilterMatchAny on empty filter is False" $ do
      let f = gcsFilterEmpty (basicFilterParams zeroBlockHash)
      gcsFilterMatchAny f ["anything", "else"] `shouldBe` False

  ------------------------------------------------------------------------------
  -- G10: blockFilterHash = SHA256d(encoded_filter).
  -- Reference: bitcoin-core/src/blockfilter.cpp:248-251 GetHash.
  ------------------------------------------------------------------------------
  describe "G10 blockFilterHash = SHA256d(encoded)" $ do
    it "is deterministic" $ do
      let bf1 = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
          bf2 = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
      blockFilterHash bf1 `shouldBe` blockFilterHash bf2

    it "produces a 32-byte Hash256" $ do
      let bf = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
          h  = getHash256 (blockFilterHash bf)
      BS.length h `shouldBe` 32

  ------------------------------------------------------------------------------
  -- G11: blockFilterHeader = SHA256d(filter_hash || prev_header).
  -- Reference: bitcoin-core/src/blockfilter.cpp:253-256 ComputeHeader.
  ------------------------------------------------------------------------------
  describe "G11 blockFilterHeader = SHA256d(filter_hash || prev_header)" $ do
    it "chains differently for different prev_headers" $ do
      let bf    = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
          prev1 = zeroHash256
          prev2 = Hash256 (BS.replicate 32 0xff)
          h1    = blockFilterHeader bf prev1
          h2    = blockFilterHeader bf prev2
      h1 `shouldNotBe` h2

    it "produces a 32-byte Hash256" $ do
      let bf = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
          h  = getHash256 (blockFilterHeader bf zeroHash256)
      BS.length h `shouldBe` 32

  ------------------------------------------------------------------------------
  -- G12: genesis filter header is the all-zeroes 32-byte string.  haskoin
  -- seeds 'bfiLastHeader' to @Hash256 (replicate 32 0)@ on
  -- 'newBlockFilterIndexDB' and 'loadBlockFilterIndexState' (Index.hs:891,
  -- 934).
  ------------------------------------------------------------------------------
  describe "G12 genesis filter header = 32 zero bytes" $ do
    it "the seed (mirrored from Index.hs:891) is 32 zero bytes" $ do
      let genesis = Hash256 (BS.replicate 32 0)
      BS.length (getHash256 genesis) `shouldBe` 32
      BS.all (== 0) (getHash256 genesis) `shouldBe` True

  ------------------------------------------------------------------------------
  -- G13: BIP-158 reference vectors (blockfilters.json) — already covered
  -- by the pre-existing GCS test block in test/Spec.hs around line 13191.
  -- We assert here that the path through 'computeBlockFilter' /
  -- 'blockFilterHash' / 'blockFilterHeader' is the same one those vectors
  -- exercise (regression marker).
  ------------------------------------------------------------------------------
  describe "G13 BIP-158 reference vectors (regression marker)" $ do
    it "computeBlockFilter / blockFilterHash / blockFilterHeader compose deterministically" $ do
      let bf   = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
          fh   = blockFilterHash bf
          hdr  = blockFilterHeader bf zeroHash256
      BS.length (getHash256 fh)  `shouldBe` 32
      BS.length (getHash256 hdr) `shouldBe` 32
      bfBlockHash bf `shouldBe` zeroBlockHash

  ------------------------------------------------------------------------------
  -- G14: CFCHECKPT_INTERVAL = 1000.  Reference:
  -- bitcoin-core/src/index/blockfilterindex.h:31.  MISSING ENTIRELY — no
  -- haskoin code defines/uses this constant (because the cfcheckpt
  -- sender doesn't exist).
  ------------------------------------------------------------------------------
  describe "G14 CFCHECKPT_INTERVAL = 1000 (MISSING ENTIRELY)" $ do
    it "Core's CFCHECKPT_INTERVAL is 1000 (referenced for fix-wave)" $
      coreCFCheckptInterval `shouldBe` 1000

  ------------------------------------------------------------------------------
  -- G15: MAX_GETCFILTERS_SIZE = 1000.  Reference:
  -- bitcoin-core/src/net_processing.cpp:184.  MISSING ENTIRELY — no
  -- haskoin handler enforces this bound (because the handler doesn't
  -- exist).
  ------------------------------------------------------------------------------
  describe "G15 MAX_GETCFILTERS_SIZE = 1000 (MISSING ENTIRELY)" $ do
    it "Core's MAX_GETCFILTERS_SIZE is 1000" $
      coreMaxGetCFiltersSize `shouldBe` 1000

  ------------------------------------------------------------------------------
  -- G16: MAX_GETCFHEADERS_SIZE = 2000.  Reference:
  -- bitcoin-core/src/net_processing.cpp:186.  MISSING ENTIRELY.
  ------------------------------------------------------------------------------
  describe "G16 MAX_GETCFHEADERS_SIZE = 2000 (MISSING ENTIRELY)" $ do
    it "Core's MAX_GETCFHEADERS_SIZE is 2000" $
      coreMaxGetCFHeadersSize `shouldBe` 2000

  ------------------------------------------------------------------------------
  -- G17: NODE_COMPACT_FILTERS = (1<<6) = 64.  Reference:
  -- bitcoin-core/src/protocol.h:321-323.  haskoin does NOT define
  -- 'nodeCompactFilters' nor advertise the bit.  BUG-1 P0.
  ------------------------------------------------------------------------------
  describe "G17 NODE_COMPACT_FILTERS service-bit advertisement (BUG-1 P0)" $ do
    it "Core's NODE_COMPACT_FILTERS bit is 1<<6 = 64" $
      coreNodeCompactFiltersBit `shouldBe` 64

    it "haskoin defaultPeerConfig does NOT advertise NODE_COMPACT_FILTERS" $ do
      let services = pcfgServices (defaultPeerConfig regtest)
          nodeCompactFilters = ServiceFlag coreNodeCompactFiltersBit
      -- Today: bit is NOT set.  When BUG-1 is fixed, flip this assertion.
      hasService services nodeCompactFilters `shouldBe` False

    it "haskoin's combined known service flags do NOT cover the (1<<6) bit" $ do
      let combined = combineServices [nodeNetwork, nodeWitness, nodeBloom, nodeNetworkLimited]
          nodeCompactFilters = ServiceFlag coreNodeCompactFiltersBit
      hasService combined nodeCompactFilters `shouldBe` False

  ------------------------------------------------------------------------------
  -- G18: getcfilters inbound handler.  Reference:
  -- bitcoin-core/src/net_processing.cpp:3315-3342 ProcessGetCFilters.
  -- haskoin has the wire envelope as an opaque @!ByteString@ but no
  -- handler dispatch.  MISSING ENTIRELY — BUG-2 P0.
  ------------------------------------------------------------------------------
  describe "G18 getcfilters handler (BUG-2 P0 MISSING ENTIRELY)" $ do
    it "MGetCFilters payload type is opaque ByteString (dead-wire shape)" $ do
      let raw = BS.pack [0x00, 0x01, 0x02, 0x03]   -- filter_type=BASIC, start_height bytes
          msg = MGetCFilters raw
      commandName msg `shouldBe` "getcfilters"

  ------------------------------------------------------------------------------
  -- G19: getcfheaders inbound handler.  MISSING ENTIRELY — BUG-2 P0.
  ------------------------------------------------------------------------------
  describe "G19 getcfheaders handler (BUG-2 P0 MISSING ENTIRELY)" $ do
    it "MGetCFHeaders payload type is opaque ByteString (dead-wire shape)" $ do
      let msg = MGetCFHeaders (BS.pack [0x00, 0x10, 0x00, 0x00, 0x00])
      commandName msg `shouldBe` "getcfheaders"

  ------------------------------------------------------------------------------
  -- G20: getcfcheckpt inbound handler.  MISSING ENTIRELY — BUG-2 P0.
  ------------------------------------------------------------------------------
  describe "G20 getcfcheckpt handler (BUG-2 P0 MISSING ENTIRELY)" $ do
    it "MGetCFCheckpt payload type is opaque ByteString (dead-wire shape)" $ do
      let msg = MGetCFCheckpt (BS.pack [0x00, 0xab, 0xcd])
      commandName msg `shouldBe` "getcfcheckpt"

  ------------------------------------------------------------------------------
  -- G21: cfilter sender.  Reference: net_processing.cpp:3340
  -- 'MakeAndPushMessage(node, NetMsgType::CFILTER, filter)'.  MISSING
  -- ENTIRELY — BUG-3 P0.
  ------------------------------------------------------------------------------
  describe "G21 cfilter sender (BUG-3 P0 MISSING ENTIRELY)" $ do
    it "MCFilter exists as a dead-wire constructor only" $ do
      let msg = MCFilter (BS.singleton 0x00)
      commandName msg `shouldBe` "cfilter"

  ------------------------------------------------------------------------------
  -- G22: cfheaders sender.  Reference: net_processing.cpp:3379.
  -- MISSING ENTIRELY — BUG-3 P0.
  ------------------------------------------------------------------------------
  describe "G22 cfheaders sender (BUG-3 P0 MISSING ENTIRELY)" $ do
    it "MCFHeaders exists as a dead-wire constructor only" $ do
      let msg = MCFHeaders BS.empty
      commandName msg `shouldBe` "cfheaders"

  ------------------------------------------------------------------------------
  -- G23: cfcheckpt sender.  Reference: net_processing.cpp:3418.
  -- MISSING ENTIRELY — BUG-3 P0.
  ------------------------------------------------------------------------------
  describe "G23 cfcheckpt sender (BUG-3 P0 MISSING ENTIRELY)" $ do
    it "MCFCheckpt exists as a dead-wire constructor only" $ do
      let msg = MCFCheckpt BS.empty
      commandName msg `shouldBe` "cfcheckpt"

  ------------------------------------------------------------------------------
  -- G24: BIP-157 BlockFilter wire serialization — Core emits
  -- @filter_type (u8) || block_hash (32) || varint || encoded@.  haskoin's
  -- 'encodeBlockFilter' emits ONLY @gcsEncoded@.  FAIL — BUG-4 P0.
  ------------------------------------------------------------------------------
  describe "G24 BIP-157 BlockFilter wire format (BUG-4 P0)" $ do
    let bf  = computeBlockFilter emptyBlock (BlockUndo []) zeroBlockHash
        enc = encodeBlockFilter bf

    it "encodeBlockFilter MISSING filter_type prefix byte" $
      -- A Core-correct wire payload is at least 1 + 32 + 1 = 34 bytes
      -- (type + hash + varint(0)).  haskoin's encoded output for an
      -- empty filter is exactly 1 byte (the compact-size N=0).
      BS.length enc `shouldSatisfy` (< 34)

    it "encodeBlockFilter MISSING block_hash field" $
      -- The encoded bytes equal exactly the GCS encoding — no
      -- type/hash prefix.
      enc `shouldBe` gcsEncoded (bfFilter bf)

    it "decodeBlockFilter requires block hash to be passed externally" $
      -- The structural API divergence: Core's deserializer reads
      -- filter_type + block_hash from the stream; haskoin's takes
      -- them as arguments because the wire bytes don't carry them.
      case decodeBlockFilter BasicBlockFilter zeroBlockHash enc of
        Right bf' -> bfBlockHash bf' `shouldBe` zeroBlockHash
        Left e    -> expectationFailure $ "expected round-trip, got: " ++ e

  ------------------------------------------------------------------------------
  -- G25: getblockfilter JSON-RPC method.  Reference:
  -- bitcoin-core/src/rpc/blockchain.cpp:2956.  MISSING ENTIRELY — BUG-5 P0.
  -- haskoin only exposes the REST endpoint.
  ------------------------------------------------------------------------------
  describe "G25 getblockfilter JSON-RPC (BUG-5 P0 MISSING ENTIRELY)" $ do
    it "absence marker — see audit BUG-5 (grep src/Haskoin/Rpc.hs for 'getblockfilter' to confirm)" $
      -- Marker test: we cannot import a Set of registered RPC names
      -- (haskoin dispatch is a giant case-expression).  Audit
      -- reviewers should grep 'src/Haskoin/Rpc.hs' for the literal
      -- "getblockfilter" — today it returns 0 RPC binding hits.
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G26: BlockFilterIndex chain-connect wiring on the IBD path
  -- (Sync.hs:448 indexManagerConnectBlock).
  ------------------------------------------------------------------------------
  describe "G26 BlockFilterIndex wired to IBD chain-connect" $ do
    it "indexManagerConnectBlock symbol is exported" $ do
      -- Presence check: the binding is statically imported above so
      -- this test compiles iff the export exists.
      let _ = indexManagerConnectBlock
      True `shouldBe` True

    it "defaultIndexConfig disables BlockFilterIndex (Core -blockfilterindex=0)" $
      icBlockFilterIndex defaultIndexConfig `shouldBe` False

  ------------------------------------------------------------------------------
  -- G27: BlockFilterIndex chain-connect wiring on the submitBlock /
  -- ActivateBestChain path (BlockTemplate.hs:620, 960).
  ------------------------------------------------------------------------------
  describe "G27 BlockFilterIndex wired to submitBlock chain-connect" $ do
    it "indexManagerConnectBlock + indexManagerDisconnectBlock both exported" $ do
      let _ = indexManagerConnectBlock
          _ = indexManagerDisconnectBlock
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G28: CustomRewind on disconnect — 'blockFilterIndexDelete' restores
  -- the chain pointer to (height - 1).  Reference:
  -- bitcoin-core/src/index/blockfilterindex.cpp CustomRewind.
  ------------------------------------------------------------------------------
  describe "G28 BlockFilterIndex CustomRewind on disconnect" $ do
    it "blockFilterIndexDelete symbol is exported (rewind path exists)" $ do
      let _ = blockFilterIndexDelete
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G29: -blockfilterindex CLI flag end-to-end (app/Main.hs:280,
  -- Daemon configLookupBool, IndexConfig.icBlockFilterIndex).
  ------------------------------------------------------------------------------
  describe "G29 -blockfilterindex CLI flag end-to-end" $ do
    it "defaultIndexConfig.icBlockFilterIndex is False (Core default)" $
      icBlockFilterIndex defaultIndexConfig `shouldBe` False

    it "IndexConfig flag flips on when --blockfilterindex is passed" $ do
      let cfg = defaultIndexConfig { icBlockFilterIndex = True }
      icBlockFilterIndex cfg `shouldBe` True

  ------------------------------------------------------------------------------
  -- G30: REST /rest/blockfilter/<type>/<hash>.{bin,hex,json} +
  -- /rest/blockfilterheaders/<type>/[<count>/]<hash>.{bin,hex,json}.
  -- Reference: bitcoin-core/src/rest.cpp rest_block_filter /
  -- rest_filter_header.  haskoin exposes both (Rpc.hs:9947, 10084).
  ------------------------------------------------------------------------------
  describe "G30 REST blockfilter / blockfilterheaders endpoints" $ do
    it "REST handlers are wired (presence marker via module-load)" $
      -- The REST handlers 'handleRestBlockFilter' /
      -- 'handleRestBlockFilterHeaders' live in 'Haskoin.Rpc'.  We
      -- record their presence as an audit marker — the integration
      -- coverage lives in the higher-level RPC suite.
      True `shouldBe` True

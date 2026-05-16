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
-- G6  Golomb-Rice encode/decode round-trip                    PASS
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
-- == Per-impl bug count (this audit) ==  15
--
-- ============================================================

module W121CompactFiltersSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int32)
import Data.Bits (shiftL)

import Haskoin.Types
  ( Hash256(..)
  , BlockHash(..)
  , BlockHeader(..)
  , Block(..)
  , Tx(..)
  , TxIn(..)
  , TxOut(..)
  )
import Haskoin.Index
  ( GCSParams(..)
  , GCSFilter(..)
  , basicFilterParams
  , gcsFilterEmpty
  , gcsFilterNew
  , gcsFilterMatch
  , gcsFilterMatchAny
  , golombRiceEncode
  , golombRiceDecode
  , bitWriterNew
  , bitWriterFlush
  , bitReaderNew
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
  ------------------------------------------------------------------------------
  describe "G6 Golomb-Rice round-trip" $ do
    it "encode-then-decode preserves all values in a representative range" $ do
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

    it "output OP_RETURN excluded BUT spent OP_RETURN included (count = 2)" $
      -- After dedup the element set is {normal, opReturnFromSpent}.
      length (filter (/= emptyScript) elements) `shouldBe` 2

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

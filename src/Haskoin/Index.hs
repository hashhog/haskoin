{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Block Indexes (txindex, blockfilterindex, coinstatsindex)
--
-- This module implements optional indexes that accelerate lookups:
--   1. TxIndex: Transaction index for fast tx lookup by txid
--   2. BlockFilterIndex: BIP157/158 compact block filters
--   3. CoinStatsIndex: UTXO set statistics using MuHash3072
--
-- All indexes support background sync using async and store data in RocksDB.
--
-- Reference: bitcoin/src/index/txindex.cpp, blockfilter.cpp, coinstatsindex.cpp
--
module Haskoin.Index
  ( -- * Golomb-Coded Set (GCS) Filter
    GCSParams(..)
  , GCSFilter(..)
  , basicFilterParams
  , gcsFilterEmpty
  , gcsFilterNew
  , gcsFilterEncode
  , gcsFilterDecode
  , gcsFilterMatch
  , gcsFilterMatchAny
  , golombRiceEncode
  , golombRiceDecode
    -- * Block Filter (BIP158)
  , BlockFilter(..)
  , BlockFilterType(..)
  , computeBlockFilter
  , blockFilterElements
  , blockFilterHash
  , blockFilterHeader
  , encodeBlockFilter
  , decodeBlockFilter
    -- * MuHash3072 (Multiplicative Hash) — re-exported from "Haskoin.MuHash"
  , MuHash3072(..)
  , Num3072(..)
  , muHashEmpty
  , muHashInsert
  , muHashRemove
  , muHashCombine
  , muHashFinalize
  , num3072FromBytes
  , num3072ToBytes
  , num3072Multiply
  , num3072GetInverse
    -- * TxIndex
  , TxIndexEntry(..)
  , TxIndexDB(..)
  , newTxIndexDB
  , txIndexPut
  , txIndexGet
  , txIndexDelete
  , txIndexAppendBlock
    -- * BlockFilterIndex
  , BlockFilterIndexDB(..)
  , BlockFilterEntry(..)
  , newBlockFilterIndexDB
  , loadBlockFilterIndexState
  , blockFilterIndexPut
  , blockFilterIndexGet
  , blockFilterIndexDelete
  , blockFilterIndexAppendBlock
  , blockFilterIndexTipHeight
  , blockFilterIndexLastHeader
    -- * CoinStatsIndex
  , CoinStats(..)
  , CoinStatsEntry(..)
  , CoinStatsIndexDB(..)
  , newCoinStatsIndexDB
  , coinStatsIndexPut
  , coinStatsIndexGet
  , coinStatsIndexAppendBlock
  , coinStatsIndexRevertBlock
  , coinStatsIndexInitFromDB
  , coinStatsIndexTipHeight
  , coinStatsApplyCoin
  , coinStatsRemoveCoin
    -- * TxoSpenderIndex
  , TxoSpender(..)
  , TxoSpenderIndexDB(..)
  , newTxoSpenderIndexDB
  , txoSpenderIndexInitFromDB
  , txoSpenderIndexTipHeight
  , txoSpenderIndexAppendBlock
  , txoSpenderIndexRevertBlock
  , txoSpenderIndexFind
    -- * Index Manager
  , IndexConfig(..)
  , IndexManager(..)
  , defaultIndexConfig
  , newIndexManager
  , indexManagerInitFromDB
  , indexManagerBackfill
  , indexManagerSync
  , indexManagerConnectBlock
  , indexManagerDisconnectBlock
    -- * SipHash
  , SipHashKey(..)
  , sipHash128
  , sipHashKey
    -- * Utilities
  , fastRange64
  , bitWriterNew
  , bitWriterWrite
  , bitWriterFlush
  , bitReaderNew
  , bitReaderRead
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as BSL
import Data.Serialize (encode, decode, Serialize(..), Get, Put, runGet, runPut,
                       putWord8, getWord8, putWord32le, getWord32le,
                       putWord64le, getWord64le, putByteString, getBytes)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Int (Int64)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, complement, testBit, setBit, clearBit, xor)
import Control.Monad (when, unless, forM_, replicateM)
import Control.Exception (bracket, try, SomeException)
import Control.Concurrent.Async (async, Async, wait, cancel)
import Control.Concurrent.STM
import Data.IORef
import GHC.Generics (Generic)
import Control.DeepSeq (NFData(..))
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Set (Set)
import Data.List (sort, foldl')
import Data.Maybe (mapMaybe, isJust, fromMaybe)
import qualified Database.RocksDB as R
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as BA

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256)
import Haskoin.Storage (HaskoinDB(..), BlockUndo(..), TxUndo(..), TxInUndo(..),
                         Coin(..), BlockHeight, integerToBS, bsToInteger,
                         putTxOutSer, isUnspendable)
import Haskoin.MuHash (MuHash3072(..), Num3072(..),
                       muHashEmpty, muHashInsert, muHashRemove,
                       muHashCombine, muHashFinalize,
                       num3072ToBytes, num3072Multiply, num3072GetInverse,
                       muHashToNum3072, muHashSerialize, muHashDeserialize)
import qualified Haskoin.MuHash as MuHash

-- | Back-compat alias: the old 'Index.num3072FromBytes' was the
-- ChaCha20-based element expansion. Forward to 'muHashToNum3072' so
-- existing call sites (and re-exports via "Haskoin.Index") continue
-- to work.
num3072FromBytes :: ByteString -> Num3072
num3072FromBytes = muHashToNum3072

--------------------------------------------------------------------------------
-- SipHash Implementation
--------------------------------------------------------------------------------

-- | SipHash key (two 64-bit values)
data SipHashKey = SipHashKey !Word64 !Word64
  deriving (Show, Eq)

-- | Extract SipHash key from block hash (first 16 bytes interpreted as two LE Word64)
sipHashKey :: BlockHash -> SipHashKey
sipHashKey (BlockHash (Hash256 bs)) =
  let k0Bytes = BS.take 8 bs
      k1Bytes = BS.take 8 (BS.drop 8 bs)
      k0 = decodeLE64 k0Bytes
      k1 = decodeLE64 k1Bytes
  in SipHashKey k0 k1

-- | Decode 8 bytes as little-endian Word64
decodeLE64 :: ByteString -> Word64
decodeLE64 bs
  | BS.length bs < 8 = 0
  | otherwise =
      let bytes = BS.unpack (BS.take 8 bs)
      in foldl' (\acc (i, b) -> acc .|. (fromIntegral b `shiftL` (i * 8))) 0
                (zip [0..7] bytes)

-- | Encode Word64 as little-endian ByteString
encodeLE64 :: Word64 -> ByteString
encodeLE64 w = BS.pack [fromIntegral (w `shiftR` (i * 8)) | i <- [0..7]]

-- | SipHash-2-4 with 64-bit output
-- Reference: https://github.com/veorq/SipHash
sipHash128 :: SipHashKey -> ByteString -> Word64
sipHash128 (SipHashKey k0 k1) msg =
  let v0 = 0x736f6d6570736575 `xor` k0
      v1 = 0x646f72616e646f6d `xor` k1
      v2 = 0x6c7967656e657261 `xor` k0
      v3 = 0x7465646279746573 `xor` k1

      -- Process full 8-byte blocks
      (v0', v1', v2', v3', leftover) = processBlocks v0 v1 v2 v3 msg

      -- Process final block with length byte
      finalBlock = buildFinalBlock leftover (BS.length msg)
      (v0'', v1'', v2'', v3'') = sipRound2 v0' v1' v2' v3' finalBlock

      -- Finalization
      v2''' = v2'' `xor` 0xff
      (v0f, v1f, v2f, v3f) = sipRound4 v0'' v1'' v2''' v3''
  in v0f `xor` v1f `xor` v2f `xor` v3f
  where
    processBlocks !v0 !v1 !v2 !v3 !bs
      | BS.length bs < 8 = (v0, v1, v2, v3, bs)
      | otherwise =
          let block = decodeLE64 (BS.take 8 bs)
              rest = BS.drop 8 bs
              (v0', v1', v2', v3') = sipRound2 v0 v1 v2 v3 block
          in processBlocks v0' v1' v2' v3' rest

    buildFinalBlock leftover totalLen =
      -- Pad to exactly 8 bytes: 7 data bytes + 1 length byte
      -- The length byte goes in the high byte (bits 56-63)
      let padded = leftover `BS.append` BS.replicate (8 - BS.length leftover) 0
          lenByte = fromIntegral (totalLen .&. 0xff) `shiftL` 56
          w = decodeLE64 padded
          -- Replace the high byte with the length byte
      in (w .&. 0x00ffffffffffffff) .|. lenByte

    sipRound2 !v0 !v1 !v2 !v3 m =
      let v3' = v3 `xor` m
          (!v0a, !v1a, !v2a, !v3a) = sipRound v0 v1 v2 v3'
          (!v0b, !v1b, !v2b, !v3b) = sipRound v0a v1a v2a v3a
          v0' = v0b `xor` m
      in (v0', v1b, v2b, v3b)

    sipRound4 !v0 !v1 !v2 !v3 =
      let (!v0a, !v1a, !v2a, !v3a) = sipRound v0 v1 v2 v3
          (!v0b, !v1b, !v2b, !v3b) = sipRound v0a v1a v2a v3a
          (!v0c, !v1c, !v2c, !v3c) = sipRound v0b v1b v2b v3b
          (!v0d, !v1d, !v2d, !v3d) = sipRound v0c v1c v2c v3c
      in (v0d, v1d, v2d, v3d)

    sipRound !v0 !v1 !v2 !v3 =
      let !v0' = v0 + v1
          !v1' = rotl64 v1 13
          !v1'' = v1' `xor` v0'
          !v0'' = rotl64 v0' 32
          !v2' = v2 + v3
          !v3' = rotl64 v3 16
          !v3'' = v3' `xor` v2'
          !v0''' = v0'' + v3''
          !v3''' = rotl64 v3'' 21
          !v3'''' = v3''' `xor` v0'''
          !v2'' = v2' + v1''
          !v1''' = rotl64 v1'' 17
          !v1'''' = v1''' `xor` v2''
          !v2''' = rotl64 v2'' 32
      in (v0''', v1'''', v2''', v3'''')

    rotl64 x n = (x `shiftL` n) .|. (x `shiftR` (64 - n))

--------------------------------------------------------------------------------
-- Bit Stream Reader/Writer for Golomb-Rice coding
--------------------------------------------------------------------------------

-- | Bit writer state — BIG-ENDIAN / MSB-first bit packing, byte-for-byte
-- identical to bitcoin-core/src/streams.h @BitStreamWriter@.
--
-- BIP-158's GCS is serialized MSB-first: the first bit written goes to the
-- most-significant bit of the first output byte, and the @nbits@
-- least-significant bits of @value@ are written most-significant-first.
-- 'bwBuffer' holds the in-progress (not-yet-complete) byte with its bits
-- packed from the MSB downward; 'bwBits' is how many high bits of that byte
-- are already filled; 'bwOutput' is the completed bytes in reverse order.
--
-- WHY THIS MATTERS (the W164 fix): the previous implementation packed bits
-- LSB-first.  It round-tripped against its own (also-LSB-first) reader and so
-- passed the round-trip + header-chaining tests (which decode pre-supplied
-- Core filter bytes), but the *encoded* filter bytes produced from an element
-- set did NOT match Core — getblockfilter returned the wrong "filter"/"header"
-- hex.  SipHash, FastRange64, and the Golomb-Rice quotient/remainder split
-- were all already correct; only the bit-serialization order was wrong.
data BitWriter = BitWriter
  { bwBuffer :: !Word8       -- ^ Partial byte, bits filled from the MSB down
  , bwBits   :: !Int         -- ^ Bits already filled in 'bwBuffer' (0..7)
  , bwOutput :: ![Word8]     -- ^ Completed output bytes (in reverse order)
  } deriving (Show)

-- | Create a new bit writer
bitWriterNew :: BitWriter
bitWriterNew = BitWriter 0 0 []

-- | Write the @numBits@ least-significant bits of @value@ to the stream,
-- most-significant-first.  Direct port of Core's @BitStreamWriter::Write@
-- (bitcoin-core/src/streams.h:329-344): each iteration writes up to a byte
-- boundary, OR-ing the appropriate slice of @value@ into the partial byte.
--
--   m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset);
--
-- i.e. left-align the remaining @nbits@ of @data@ in a 64-bit word, then
-- shift down so the next chunk lands just after the already-filled high bits
-- of the current octet.
bitWriterWrite :: BitWriter -> Int -> Word64 -> BitWriter
bitWriterWrite bw0 numBits0 value
  | numBits0 < 0 || numBits0 > 64 = error "bitWriterWrite: numBits must be 0..64"
  | otherwise = go bw0 numBits0
  where
    go !bw nbits
      | nbits <= 0 = bw
      | otherwise =
          let bits = min (8 - bwBits bw) nbits
              -- (data << (64 - nbits)) >> (64 - 8 + m_offset), truncated to 8 bits.
              contrib = fromIntegral
                          ((value `shiftL` (64 - nbits)) `shiftR` (64 - 8 + bwBits bw))
                          :: Word8
              newBuf  = bwBuffer bw .|. contrib
              newBits = bwBits bw + bits
              bw'     = bw { bwBuffer = newBuf, bwBits = newBits }
              bw''    = if newBits == 8 then flushPartial bw' else bw'
          in go bw'' (nbits - bits)

    -- Emit the now-full partial byte to the output and reset it.
    flushPartial !bw =
      bw { bwBuffer = 0, bwBits = 0, bwOutput = bwBuffer bw : bwOutput bw }

-- | Flush any remaining partial byte (zero-padded to the next byte boundary,
-- exactly like Core's @BitStreamWriter::Flush@) and return the bytes.
bitWriterFlush :: BitWriter -> ByteString
bitWriterFlush bw =
  let finalOutput = if bwBits bw > 0
                    then bwBuffer bw : bwOutput bw   -- already MSB-aligned
                    else bwOutput bw
  in BS.pack (reverse finalOutput)

-- | Bit reader state — BIG-ENDIAN / MSB-first, byte-for-byte identical to
-- bitcoin-core/src/streams.h @BitStreamReader@.  'brBuffer' is the current
-- input byte; 'brOffset' is how many high bits of it have already been
-- consumed (starts at 8 = "need a fresh byte").
data BitReader = BitReader
  { brInput  :: !ByteString  -- ^ Remaining input bytes
  , brBuffer :: !Word8       -- ^ Current input byte
  , brOffset :: !Int         -- ^ High bits of 'brBuffer' already returned (0..8)
  } deriving (Show)

-- | Create a new bit reader.  Mirrors Core's initial state (m_offset = 8,
-- meaning the first 'Read' pulls a byte from the stream).
bitReaderNew :: ByteString -> BitReader
bitReaderNew bs = BitReader bs 0 8

-- | Read @numBits@ bits, most-significant-first, returned in the low bits of
-- the result.  Direct port of Core's @BitStreamReader::Read@
-- (bitcoin-core/src/streams.h:281-300):
--
--   data <<= bits;
--   data |= (uint8_t)(m_buffer << m_offset) >> (8 - bits);
--   m_offset += bits;
bitReaderRead :: BitReader -> Int -> (Word64, BitReader)
bitReaderRead br0 numBits0
  | numBits0 < 0 || numBits0 > 64 = error "bitReaderRead: numBits must be 0..64"
  | otherwise = go br0 numBits0 0
  where
    go !br nbits !acc
      | nbits <= 0 = (acc, br)
      | otherwise =
          let -- Refill the byte buffer when fully consumed.
              br1 = if brOffset br == 8
                      then case BS.uncons (brInput br) of
                             Just (b, rest) -> br { brInput = rest, brBuffer = b, brOffset = 0 }
                             Nothing        -> error "bitReaderRead: not enough bits in reader"
                      else br
              bits   = min (8 - brOffset br1) nbits
              -- (uint8_t)(m_buffer << m_offset) >> (8 - bits)
              chunk  = fromIntegral
                         (((brBuffer br1 `shiftL` brOffset br1) :: Word8)
                            `shiftR` (8 - bits))
                         :: Word64
              acc'   = (acc `shiftL` bits) .|. chunk
              br2    = br1 { brOffset = brOffset br1 + bits }
          in go br2 (nbits - bits) acc'

--------------------------------------------------------------------------------
-- Golomb-Rice Encoding/Decoding
--------------------------------------------------------------------------------

-- | Encode a value using Golomb-Rice coding
-- The quotient is encoded in unary (q ones followed by a zero)
-- The remainder is encoded in P bits
golombRiceEncode :: BitWriter -> Int -> Word64 -> BitWriter
golombRiceEncode bw p value =
  let quotient = value `shiftR` p
      remainder = value .&. ((1 `shiftL` p) - 1)
      -- Write quotient in unary (q ones followed by a zero)
      bw' = writeUnary bw quotient
      -- Write remainder in P bits
  in bitWriterWrite bw' p remainder
  where
    writeUnary !bw' 0 = bitWriterWrite bw' 1 0  -- Write trailing zero
    writeUnary !bw' q =
      let toWrite = min q 64
          ones = (1 `shiftL` fromIntegral toWrite) - 1
          bw'' = bitWriterWrite bw' (fromIntegral toWrite) ones
      in writeUnary bw'' (q - toWrite)

-- | Decode a value using Golomb-Rice coding
golombRiceDecode :: BitReader -> Int -> (Word64, BitReader)
golombRiceDecode br p =
  let (quotient, br') = readUnary br 0
      (remainder, br'') = bitReaderRead br' p
  in (quotient `shiftL` p .|. remainder, br'')
  where
    readUnary !br' !acc
      | bitReaderExhausted br' = (acc, br')
      | otherwise =
          let (bit, br'') = bitReaderRead br' 1
          in if bit == 1
             then readUnary br'' (acc + 1)
             else (acc, br'')

-- | True when the reader has no more bits to return (current byte fully
-- consumed AND no input bytes remain).  Used by 'golombRiceDecode' as a
-- defensive end-of-stream guard so a malformed/truncated filter does not loop.
bitReaderExhausted :: BitReader -> Bool
bitReaderExhausted br = brOffset br == 8 && BS.null (brInput br)

--------------------------------------------------------------------------------
-- Fast Range Mapping
--------------------------------------------------------------------------------

-- | Map a 64-bit hash to range [0, range) using multiply-shift
-- Reference: bitcoin/src/util/fastrange.h FastRange64
fastRange64 :: Word64 -> Word64 -> Word64
fastRange64 hash range =
  let (hi, _) = mulWord64 hash range
  in hi
  where
    -- Multiply two 64-bit values and return high and low parts
    mulWord64 :: Word64 -> Word64 -> (Word64, Word64)
    mulWord64 a b =
      let aLo = a .&. 0xffffffff
          aHi = a `shiftR` 32
          bLo = b .&. 0xffffffff
          bHi = b `shiftR` 32
          -- Four 32x32 multiplications
          p0 = aLo * bLo
          p1 = aLo * bHi
          p2 = aHi * bLo
          p3 = aHi * bHi
          -- Combine results
          carry0 = (p0 `shiftR` 32) + (p1 .&. 0xffffffff) + (p2 .&. 0xffffffff)
          hi = p3 + (p1 `shiftR` 32) + (p2 `shiftR` 32) + (carry0 `shiftR` 32)
          lo = (carry0 `shiftL` 32) .|. (p0 .&. 0xffffffff)
      in (hi, lo)

--------------------------------------------------------------------------------
-- Golomb-Coded Set (GCS) Filter
--------------------------------------------------------------------------------

-- | GCS filter parameters
data GCSParams = GCSParams
  { gcsP      :: !Int        -- ^ Golomb-Rice coding parameter (bits per remainder)
  , gcsM      :: !Word32     -- ^ Inverse false positive rate (M = 1/fp_rate)
  , gcsSipK0  :: !Word64     -- ^ SipHash key k0
  , gcsSipK1  :: !Word64     -- ^ SipHash key k1
  } deriving (Show, Eq, Generic)

instance NFData GCSParams

-- | BIP158 basic filter parameters: P=19, M=784931
basicFilterParams :: BlockHash -> GCSParams
basicFilterParams blockHash =
  let SipHashKey k0 k1 = sipHashKey blockHash
  in GCSParams
    { gcsP = 19
    , gcsM = 784931
    , gcsSipK0 = k0
    , gcsSipK1 = k1
    }

-- | Golomb-coded set filter
data GCSFilter = GCSFilter
  { gcsParams  :: !GCSParams       -- ^ Filter parameters
  , gcsN       :: !Word32          -- ^ Number of elements
  , gcsF       :: !Word64          -- ^ Range = N * M
  , gcsEncoded :: !ByteString      -- ^ Encoded filter data
  } deriving (Show, Eq, Generic)

instance NFData GCSFilter

-- | Create an empty GCS filter
-- Core's empty GCSFilter stores m_encoded = {0x00} (the compact-size for N=0).
-- Reference: blockfilter.cpp GCSFilter::GCSFilter(const Params& params)
gcsFilterEmpty :: GCSParams -> GCSFilter
gcsFilterEmpty params = GCSFilter
  { gcsParams = params
  , gcsN = 0
  , gcsF = 0
  , gcsEncoded = BS.singleton 0x00
  }

-- | Hash an element to range [0, F)
hashToRange :: GCSParams -> Word64 -> ByteString -> Word64
hashToRange params f element =
  let hash = sipHash128 (SipHashKey (gcsSipK0 params) (gcsSipK1 params)) element
  in fastRange64 hash f

-- | Build a GCS filter from a set of elements
gcsFilterNew :: GCSParams -> [ByteString] -> GCSFilter
gcsFilterNew params elements
  | null elements = gcsFilterEmpty params
  | otherwise =
      let n = fromIntegral (length elements) :: Word32
          f = fromIntegral n * fromIntegral (gcsM params)
          -- Hash all elements to range [0, F)
          hashed = sort $ map (hashToRange params f) elements
          -- Compute deltas between consecutive hashed values
          deltas = computeDeltas 0 hashed
          -- Encode deltas using Golomb-Rice coding
          encoded = encodeDeltas (gcsP params) deltas
          -- Prepend N as compact size
          nEncoded = encodeCompactSize (fromIntegral n)
      in GCSFilter
        { gcsParams = params
        , gcsN = n
        , gcsF = f
        , gcsEncoded = nEncoded `BS.append` encoded
        }
  where
    computeDeltas _ [] = []
    computeDeltas !prev (x:xs) = (x - prev) : computeDeltas x xs

    encodeDeltas p deltas =
      let bw = foldl' (\w d -> golombRiceEncode w p d) bitWriterNew deltas
      in bitWriterFlush bw

    encodeCompactSize :: Word64 -> ByteString
    encodeCompactSize = encode . VarInt

-- | Encode a GCS filter
gcsFilterEncode :: GCSFilter -> ByteString
gcsFilterEncode = gcsEncoded

-- | Decode a GCS filter
-- The encoded bytes must include the compact-size N prefix.  An empty
-- ByteString is rejected (Core would throw ios_base::failure); callers
-- expecting an empty filter should pass BS.singleton 0x00.
gcsFilterDecode :: GCSParams -> ByteString -> Either String GCSFilter
gcsFilterDecode params bs
  | BS.null bs = Left "Empty encoded filter (missing compact-size prefix)"
  | otherwise = do
      -- Read compact size N
      (n, rest) <- decodeCompactSize bs
      let f = fromIntegral n * fromIntegral (gcsM params)
      -- Validate by decoding all elements
      validateDecode params (fromIntegral n) rest
      Right GCSFilter
        { gcsParams = params
        , gcsN = fromIntegral n
        , gcsF = f
        , gcsEncoded = bs
        }
  where
    decodeCompactSize bs'
      | BS.null bs' = Left "Empty input"
      | otherwise =
          let first = BS.head bs'
          in case first of
               _ | first < 0xfd -> Right (fromIntegral first, BS.drop 1 bs')
               0xfd | BS.length bs' >= 3 ->
                 let val = fromIntegral (decodeLE16' (BS.drop 1 bs')) :: Word64
                 in if val < 253
                    then Left "non-canonical ReadCompactSize()"
                    else if val > maxSize
                         then Left "decodeCompactSize: value exceeds MAX_SIZE"
                         else Right (val, BS.drop 3 bs')
               0xfe | BS.length bs' >= 5 ->
                 let val = fromIntegral (decodeLE32' (BS.drop 1 bs')) :: Word64
                 in if val < 0x10000
                    then Left "non-canonical ReadCompactSize()"
                    else if val > maxSize
                         then Left "decodeCompactSize: value exceeds MAX_SIZE"
                         else Right (val, BS.drop 5 bs')
               0xff | BS.length bs' >= 9 ->
                 let val = decodeLE64 (BS.drop 1 bs')
                 in if val < 0x100000000
                    then Left "non-canonical ReadCompactSize()"
                    else if val > maxSize
                         then Left "decodeCompactSize: value exceeds MAX_SIZE"
                         else Right (val, BS.drop 9 bs')
               _ -> Left "Invalid compact size"

    decodeLE16' bs' =
      let bytes = BS.unpack (BS.take 2 bs')
      in fromIntegral (bytes !! 0) .|. (fromIntegral (bytes !! 1) `shiftL` 8) :: Word16

    decodeLE32' bs' =
      let bytes = BS.unpack (BS.take 4 bs')
      in foldl' (\acc (i, b) -> acc .|. (fromIntegral b `shiftL` (i * 8))) 0
                (zip [0..3] bytes) :: Word32

    validateDecode _ 0 _ = Right ()
    validateDecode params' n' encodedData = do
      let br = bitReaderNew encodedData
          go !br' !i
            | i >= n' = Right ()
            | otherwise =
                let (_, br'') = golombRiceDecode br' (gcsP params')
                in go br'' (i + 1)
      go br 0

-- | Check if an element might be in the filter
gcsFilterMatch :: GCSFilter -> ByteString -> Bool
gcsFilterMatch filter' element
  | gcsN filter' == 0 = False
  | otherwise =
      let query = hashToRange (gcsParams filter') (gcsF filter') element
      in matchInternal filter' [query]

-- | Check if any of the elements might be in the filter
gcsFilterMatchAny :: GCSFilter -> [ByteString] -> Bool
gcsFilterMatchAny filter' elements
  | gcsN filter' == 0 = False
  | null elements = False
  | otherwise =
      let queries = sort $ map (hashToRange (gcsParams filter') (gcsF filter')) elements
      in matchInternal filter' queries

-- | Internal matching implementation
matchInternal :: GCSFilter -> [Word64] -> Bool
matchInternal filter' sortedQueries =
  let encoded = gcsEncoded filter'
      -- Skip the compact size prefix
      (_, dataStart) = skipCompactSize encoded
      br = bitReaderNew dataStart
      p = gcsP (gcsParams filter')
  in go br 0 sortedQueries 0
  where
    skipCompactSize bs
      | BS.null bs = (0, bs)
      | otherwise =
          let first = BS.head bs
          in case first of
               _ | first < 0xfd -> (fromIntegral first, BS.drop 1 bs)
               0xfd -> (fromIntegral (decodeLE16'' (BS.drop 1 bs)), BS.drop 3 bs)
               0xfe -> (fromIntegral (decodeLE32'' (BS.drop 1 bs)), BS.drop 5 bs)
               0xff -> (decodeLE64 (BS.drop 1 bs), BS.drop 9 bs)

    decodeLE16'' bs' =
      let bytes = BS.unpack (BS.take 2 bs')
      in fromIntegral (bytes !! 0) .|. (fromIntegral (bytes !! 1) `shiftL` 8) :: Word16

    decodeLE32'' bs' =
      let bytes = BS.unpack (BS.take 4 bs')
      in foldl' (\acc (i, b) -> acc .|. (fromIntegral b `shiftL` (i * 8))) 0
                (zip [0..3] bytes) :: Word32

    go _ _ [] _ = False
    go br !filterVal queries !i
      | i >= gcsN filter' = False
      | otherwise =
          let (delta, br') = golombRiceDecode br (gcsP (gcsParams filter'))
              newVal = filterVal + delta
          in matchQueries br' newVal queries (i + 1)

    matchQueries br val [] _ = False
    matchQueries br val qs@(q:rest) i
      | q == val = True
      | q < val = matchQueries br val rest i
      | i >= gcsN filter' = False
      | otherwise = go br val qs i

--------------------------------------------------------------------------------
-- Block Filter (BIP158)
--------------------------------------------------------------------------------

-- | Block filter type
data BlockFilterType = BasicBlockFilter
  deriving (Show, Eq, Enum, Generic)

instance NFData BlockFilterType

-- | Block filter
data BlockFilter = BlockFilter
  { bfType      :: !BlockFilterType
  , bfBlockHash :: !BlockHash
  , bfFilter    :: !GCSFilter
  } deriving (Show, Eq, Generic)

instance NFData BlockFilter

-- | Get elements for a basic block filter
-- BIP-158 / bitcoin-core/src/blockfilter.cpp BasicFilterElements:
--   * Output scripts: exclude empty AND OP_RETURN (0x6a prefix)
--   * Spent output scripts (undo data): exclude only empty, NOT OP_RETURN
-- The spent-output OP_RETURN exclusion was a bug: Core only excludes
-- OP_RETURN from new outputs, not from previously-unspent outputs being
-- consumed.
blockFilterElements :: Block -> BlockUndo -> [ByteString]
blockFilterElements block undo =
  let -- Output scripts: exclude empty and OP_RETURN
      outputScripts = filter (not . isOpReturn) $
                        filter (not . BS.null) $
                          concatMap txOutputScripts (blockTxns block)
      -- Spent output scripts: exclude only empty (Core does NOT exclude OP_RETURN here)
      spentScripts  = filter (not . BS.null) $
                        concatMap txSpentScripts (buTxUndo undo)
  in outputScripts ++ spentScripts
  where
    txOutputScripts tx =
      map txOutScript (txOutputs tx)

    txSpentScripts (TxUndo prevOuts) =
      map (txOutScript . tuOutput) prevOuts

    isOpReturn script = BS.head script == 0x6a

-- | Compute a block filter
computeBlockFilter :: Block -> BlockUndo -> BlockHash -> BlockFilter
computeBlockFilter block undo blockHash =
  let params = basicFilterParams blockHash
      elements = blockFilterElements block undo
      -- Remove empty scripts and duplicates
      uniqueElements = Set.toList $ Set.fromList $ filter (not . BS.null) elements
      gcsFilter = gcsFilterNew params uniqueElements
  in BlockFilter
    { bfType = BasicBlockFilter
    , bfBlockHash = blockHash
    , bfFilter = gcsFilter
    }

-- | Compute filter hash (SHA256d — double SHA256)
-- Reference: bitcoin-core/src/blockfilter.cpp BlockFilter::GetHash()
--   return Hash(GetEncodedFilter());  where Hash() is CHash256 = SHA256d.
blockFilterHash :: BlockFilter -> Hash256
blockFilterHash bf = doubleSHA256 (gcsEncoded (bfFilter bf))

-- | Compute filter header (SHA256d of filter_hash || prev_header)
-- Reference: bitcoin-core/src/blockfilter.cpp BlockFilter::ComputeHeader()
--   return Hash(GetHash(), prev_header);  where Hash() is CHash256 = SHA256d.
blockFilterHeader :: BlockFilter -> Hash256 -> Hash256
blockFilterHeader bf prevHeader =
  let filterHash = blockFilterHash bf
      combined = getHash256 filterHash `BS.append` getHash256 prevHeader
  in doubleSHA256 combined

-- | Encode a block filter
encodeBlockFilter :: BlockFilter -> ByteString
encodeBlockFilter bf = gcsEncoded (bfFilter bf)

-- | Decode a block filter
decodeBlockFilter :: BlockFilterType -> BlockHash -> ByteString -> Either String BlockFilter
decodeBlockFilter filterType blockHash encoded = do
  let params = basicFilterParams blockHash
  gcsFilter <- gcsFilterDecode params encoded
  Right BlockFilter
    { bfType = filterType
    , bfBlockHash = blockHash
    , bfFilter = gcsFilter
    }

--------------------------------------------------------------------------------
-- MuHash3072 (Multiplicative Hash for UTXO set)
--------------------------------------------------------------------------------
--
-- The MuHash primitives live in 'Haskoin.MuHash' as a clean,
-- byte-compatible Haskell port of bitcoin-core/src/crypto/muhash.{h,cpp}.
-- We re-export the names that the rest of haskoin (CoinStatsIndex,
-- Storage.computeUtxoHash) was wired against, plus a few aliases that
-- map the old "fromBytes/toBytes/multiply/inverse" surface onto the
-- 'muHash*' / 'num3072*' API. Existing call sites do not need to change.
--
-- Earlier versions of this module hand-rolled a 48-limb Num3072 with a
-- broken modular multiply and a placeholder inverse ("return self").
-- The new implementation uses GHC's GMP-backed 'Integer' for both
-- multiply and modular inverse (extended Euclidean), which gives
-- byte-identical results to Core for the canonical test vectors in
-- 'src/test/crypto_tests.cpp' BOOST_AUTO_TEST_CASE(muhash_tests).

--------------------------------------------------------------------------------
-- TxIndex Database
--------------------------------------------------------------------------------

-- | Transaction index entry
data TxIndexEntry = TxIndexEntry
  { tieBlockHash   :: !BlockHash
  , tieBlockHeight :: !BlockHeight
  , tieTxPos       :: !Word32       -- ^ Position in block's tx list
  } deriving (Show, Eq, Generic)

instance NFData TxIndexEntry

instance Serialize TxIndexEntry where
  put TxIndexEntry{..} = do
    put tieBlockHash
    putWord32le tieBlockHeight
    putWord32le tieTxPos
  get = TxIndexEntry <$> get <*> getWord32le <*> getWord32le

-- | TxIndex database handle
data TxIndexDB = TxIndexDB
  { tidDB     :: !HaskoinDB
  , tidPrefix :: !Word8        -- ^ Key prefix: 't'
  }

-- | TxIndex key prefix
prefixTxIndex :: Word8
prefixTxIndex = 0x74  -- 't'

-- | Create a new TxIndex database
newTxIndexDB :: HaskoinDB -> TxIndexDB
newTxIndexDB db = TxIndexDB
  { tidDB = db
  , tidPrefix = prefixTxIndex
  }

-- | Put a transaction index entry
txIndexPut :: TxIndexDB -> TxId -> TxIndexEntry -> IO ()
txIndexPut TxIndexDB{..} txid entry =
  let key = BS.cons tidPrefix (encode txid)
  in R.put (dbHandle tidDB) (dbWriteOpts tidDB) key (encode entry)

-- | Get a transaction index entry
txIndexGet :: TxIndexDB -> TxId -> IO (Maybe TxIndexEntry)
txIndexGet TxIndexDB{..} txid = do
  let key = BS.cons tidPrefix (encode txid)
  mval <- R.get (dbHandle tidDB) (dbReadOpts tidDB) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Delete a transaction index entry
txIndexDelete :: TxIndexDB -> TxId -> IO ()
txIndexDelete TxIndexDB{..} txid =
  let key = BS.cons tidPrefix (encode txid)
  in R.delete (dbHandle tidDB) (dbWriteOpts tidDB) key

-- | Append a block's transactions to the index
txIndexAppendBlock :: TxIndexDB -> Block -> BlockHash -> BlockHeight -> IO ()
txIndexAppendBlock db block blockHash height = do
  -- Skip genesis block (its outputs are unspendable)
  when (height > 0) $ do
    let txns = blockTxns block
    forM_ (zip [0..] txns) $ \(pos, tx) -> do
      let txid = computeTxId tx
          entry = TxIndexEntry blockHash height (fromIntegral pos)
      txIndexPut db txid entry

-- | Compute transaction ID (double SHA256 of non-witness serialization)
-- Uses the canonical putVarInt from Haskoin.Types (inherits non-canonical + MAX_SIZE).
computeTxId :: Tx -> TxId
computeTxId tx =
  let -- Serialize without witness data
      serialized = runPut $ do
        putWord32le (fromIntegral (txVersion tx))
        putVarInt (fromIntegral (length (txInputs tx)))
        mapM_ put (txInputs tx)
        putVarInt (fromIntegral (length (txOutputs tx)))
        mapM_ put (txOutputs tx)
        putWord32le (txLockTime tx)
  in TxId $ doubleSHA256 serialized
  where
    doubleSHA256 bs =
      let first = sha256Single bs
          second = sha256Single (getHash256 first)
      in second

    sha256Single bs = Hash256 $ BS.pack $ BA.unpack (Hash.hash bs :: Hash.Digest Hash.SHA256)

--------------------------------------------------------------------------------
-- BlockFilterIndex Database
--------------------------------------------------------------------------------

-- | Block filter index entry
data BlockFilterEntry = BlockFilterEntry
  { bfeFilterHash   :: !Hash256      -- ^ SHA256(encoded_filter)
  , bfeFilterHeader :: !Hash256      -- ^ Chained filter header
  , bfeEncoded      :: !ByteString   -- ^ Encoded filter data
  } deriving (Show, Eq, Generic)

instance NFData BlockFilterEntry

-- | BlockFilterEntry Serialize uses the canonical putVarInt/getVarInt' from
-- Haskoin.Types (inherits non-canonical rejection + MAX_SIZE cap).
instance Serialize BlockFilterEntry where
  put BlockFilterEntry{..} = do
    put bfeFilterHash
    put bfeFilterHeader
    putVarInt (fromIntegral (BS.length bfeEncoded))
    putByteString bfeEncoded
  get = do
    filterHash <- get
    filterHeader <- get
    len <- getVarInt'
    encoded <- getBytes (fromIntegral len)
    return $ BlockFilterEntry filterHash filterHeader encoded

-- | BlockFilterIndex database handle
data BlockFilterIndexDB = BlockFilterIndexDB
  { bfiDB         :: !HaskoinDB
  , bfiPrefix     :: !Word8         -- ^ Key prefix for filter by height
  , bfiLastHeader :: !(IORef Hash256)  -- ^ Last filter header (for chaining)
  , bfiTipHeight  :: !(IORef (Maybe BlockHeight))
    -- ^ Highest height with a populated entry, or 'Nothing' for empty.
    -- Updated transactionally with 'bfiLastHeader' inside
    -- 'blockFilterIndexAppendBlock' / 'blockFilterIndexDelete'.  A
    -- startup call to 'loadBlockFilterIndexState' seeds this from the
    -- on-disk meta record so a restart doesn't recompute filters
    -- already present in the index.  Reference:
    -- bitcoin-core/src/index/blockfilterindex.cpp m_next_sync_block.
  }

-- | BlockFilterIndex key prefix.
--
-- @0x46@ ('F') keys per-height @BlockFilterEntry@ records;
-- @0x66@ ('f') keys a single meta record persisting the highest
-- indexed height + the chained filter header at that height. The meta
-- record is what 'loadBlockFilterIndexState' reads to resume on
-- startup; without it we'd have to scan the entire @0x46@ keyspace.
prefixBlockFilter :: Word8
prefixBlockFilter = 0x46  -- 'F'

prefixBlockFilterMeta :: Word8
prefixBlockFilterMeta = 0x66  -- 'f'

-- | Persisted meta record: (tip height, chained filter header at that
-- height). Read once at startup to seed the in-memory IORefs.
data BlockFilterIndexMeta = BlockFilterIndexMeta
  { bfimTipHeight :: !BlockHeight
  , bfimLastHeader :: !Hash256
  } deriving (Show, Eq, Generic)

instance Serialize BlockFilterIndexMeta where
  put BlockFilterIndexMeta{..} = do
    putWord32le bfimTipHeight
    put bfimLastHeader
  get = BlockFilterIndexMeta <$> getWord32le <*> get

-- | Create a new BlockFilterIndex database. Always returns the
-- @genesis filter header = 0x00..0x00@ + @tipHeight = Nothing@. Call
-- 'loadBlockFilterIndexState' immediately after to pick up state from
-- a previous run; that two-step constructor + load split keeps the
-- pure tests fast (no DB iteration when not needed) while letting the
-- live node resume cleanly.
newBlockFilterIndexDB :: HaskoinDB -> IO BlockFilterIndexDB
newBlockFilterIndexDB db = do
  lastHeaderRef <- newIORef (Hash256 (BS.replicate 32 0))  -- Genesis filter header
  tipRef <- newIORef Nothing
  return BlockFilterIndexDB
    { bfiDB = db
    , bfiPrefix = prefixBlockFilter
    , bfiLastHeader = lastHeaderRef
    , bfiTipHeight = tipRef
    }

-- | Big-endian Word32 encoder used by the index key encoding.
-- Big-endian gives RocksDB iterators ascending-by-height order, which
-- matches Core's blockfilterindex on-disk layout (DB_FILTER_HASH).
bfiToBE32 :: Word32 -> ByteString
bfiToBE32 w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xff)
  , fromIntegral ((w `shiftR` 16) .&. 0xff)
  , fromIntegral ((w `shiftR` 8) .&. 0xff)
  , fromIntegral (w .&. 0xff)
  ]

-- | Recover (tipHeight, lastHeader) from disk on startup.
--
-- Strategy: read the meta record under @0x66@. If absent (fresh
-- datadir, or an older datadir from before this commit), seed both
-- IORefs to genesis and let 'indexManagerBackfill' re-derive from
-- block 1 forward. The caller is expected to invoke
-- 'indexManagerBackfill' next; this loader only handles the
-- already-persisted side.
--
-- Reference: bitcoin-core/src/index/blockfilterindex.cpp
-- BlockFilterIndex::CustomInit reads m_db's filter header at the
-- best block + 1 to seed its in-memory state.  The meta-record
-- approach here is functionally equivalent but uses one cheap
-- point-lookup instead of a positional walk.
loadBlockFilterIndexState :: BlockFilterIndexDB -> IO ()
loadBlockFilterIndexState BlockFilterIndexDB{..} = do
  let metaKey = BS.singleton prefixBlockFilterMeta
  mval <- R.get (dbHandle bfiDB) (dbReadOpts bfiDB) metaKey
  case mval >>= either (const Nothing) Just . decode of
    Just BlockFilterIndexMeta{..} -> do
      writeIORef bfiLastHeader bfimLastHeader
      writeIORef bfiTipHeight (Just bfimTipHeight)
    Nothing -> do
      writeIORef bfiLastHeader (Hash256 (BS.replicate 32 0))
      writeIORef bfiTipHeight Nothing

-- | Put a block filter entry. Updates the in-memory chain-tip
-- (@bfiLastHeader@, @bfiTipHeight@) AND the on-disk meta record so a
-- crash doesn't lose the chain pointer. The two writes are not
-- batched today (RocksDB.put is independently durable), which means a
-- crash between them produces a duplicate filter on the next
-- 'indexManagerBackfill' — idempotent because the per-height entry
-- is keyed by height. Splitting into a single batch is a follow-up
-- micro-optimization; the correctness invariant is preserved either
-- way.
blockFilterIndexPut :: BlockFilterIndexDB -> BlockHeight -> BlockFilterEntry -> IO ()
blockFilterIndexPut BlockFilterIndexDB{..} height entry = do
  let key = BS.cons bfiPrefix (bfiToBE32 height)
      metaKey = BS.singleton prefixBlockFilterMeta
      meta = BlockFilterIndexMeta height (bfeFilterHeader entry)
  R.put (dbHandle bfiDB) (dbWriteOpts bfiDB) key (encode entry)
  R.put (dbHandle bfiDB) (dbWriteOpts bfiDB) metaKey (encode meta)
  writeIORef bfiLastHeader (bfeFilterHeader entry)
  writeIORef bfiTipHeight (Just height)

-- | Get a block filter entry
blockFilterIndexGet :: BlockFilterIndexDB -> BlockHeight -> IO (Maybe BlockFilterEntry)
blockFilterIndexGet BlockFilterIndexDB{..} height = do
  let key = BS.cons bfiPrefix (bfiToBE32 height)
  mval <- R.get (dbHandle bfiDB) (dbReadOpts bfiDB) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Delete the entry at @height@. Used by reorg to undo a connected
-- block from the filter index. After deleting, we read the entry at
-- @height-1@ (if any) and rewind the in-memory chain pointer to it;
-- if @height-1@ is absent the index becomes empty and we reset to
-- the genesis filter header, exactly mirroring
-- bitcoin-core/src/index/blockfilterindex.cpp::CustomRewind.
blockFilterIndexDelete :: BlockFilterIndexDB -> BlockHeight -> IO ()
blockFilterIndexDelete db@BlockFilterIndexDB{..} height = do
  let key = BS.cons bfiPrefix (bfiToBE32 height)
      metaKey = BS.singleton prefixBlockFilterMeta
  R.delete (dbHandle bfiDB) (dbWriteOpts bfiDB) key
  if height == 0
    then do
      R.delete (dbHandle bfiDB) (dbWriteOpts bfiDB) metaKey
      writeIORef bfiLastHeader (Hash256 (BS.replicate 32 0))
      writeIORef bfiTipHeight Nothing
    else do
      mPrev <- blockFilterIndexGet db (height - 1)
      case mPrev of
        Just prev -> do
          let meta = BlockFilterIndexMeta (height - 1) (bfeFilterHeader prev)
          R.put (dbHandle bfiDB) (dbWriteOpts bfiDB) metaKey (encode meta)
          writeIORef bfiLastHeader (bfeFilterHeader prev)
          writeIORef bfiTipHeight (Just (height - 1))
        Nothing -> do
          R.delete (dbHandle bfiDB) (dbWriteOpts bfiDB) metaKey
          writeIORef bfiLastHeader (Hash256 (BS.replicate 32 0))
          writeIORef bfiTipHeight Nothing

-- | Append a block filter to the index, chaining its header off of
-- the index's current tip header. Caller is responsible for
-- monotonic ordering — passing @height@ that is not exactly
-- @tipHeight + 1@ corrupts the chain (the entry is still written but
-- 'bfeFilterHeader' will not match what a fresh recompute would
-- produce). The IBD path in 'Sync.hs' and the submitBlock path in
-- 'BlockTemplate.hs' both call this strictly in order; the reorg
-- path in 'doSideBranchReorg' deletes from tip downward before
-- re-appending, so monotonicity is preserved across reorgs as well.
blockFilterIndexAppendBlock :: BlockFilterIndexDB -> Block -> BlockUndo -> BlockHash -> BlockHeight -> IO ()
blockFilterIndexAppendBlock db block undo blockHash height = do
  prevHeader <- readIORef (bfiLastHeader db)
  let blockFilter = computeBlockFilter block undo blockHash
      filterHash = blockFilterHash blockFilter
      filterHeader = blockFilterHeader blockFilter prevHeader
      entry = BlockFilterEntry filterHash filterHeader (encodeBlockFilter blockFilter)
  blockFilterIndexPut db height entry

-- | Read the in-memory tip height (highest indexed height, or
-- 'Nothing' for empty).
blockFilterIndexTipHeight :: BlockFilterIndexDB -> IO (Maybe BlockHeight)
blockFilterIndexTipHeight = readIORef . bfiTipHeight

-- | Read the in-memory chain pointer (@filter_header@ at the tip
-- height, or @0x00..0x00@ for empty). Used by callers that need to
-- chain a follow-on header (e.g. on-the-fly recompute when an entry
-- past the index tip is requested).
blockFilterIndexLastHeader :: BlockFilterIndexDB -> IO Hash256
blockFilterIndexLastHeader = readIORef . bfiLastHeader

--------------------------------------------------------------------------------
-- CoinStatsIndex Database
--------------------------------------------------------------------------------

-- | Coin statistics
data CoinStats = CoinStats
  { csOutputCount              :: !Word64
  , csBogoSize                 :: !Word64    -- ^ Estimate of UTXO set size
  , csTotalAmount              :: !Word64    -- ^ Total satoshis in UTXO set
  , csTotalSubsidy             :: !Word64    -- ^ Total block subsidies
  , csTotalPrevoutSpent        :: !Integer   -- ^ Total value of spent prevouts
  , csTotalNewOutputs          :: !Integer   -- ^ Total new output value (non-coinbase)
  , csTotalCoinbaseAmount      :: !Integer   -- ^ Total coinbase output value
  , csUnspendablesGenesis      :: !Word64    -- ^ Unspendable genesis outputs
  , csUnspendablesBIP30        :: !Word64    -- ^ Unspendable BIP30 duplicates
  , csUnspendablesScripts      :: !Word64    -- ^ Unspendable OP_RETURN etc.
  , csUnspendablesUnclaimed    :: !Word64    -- ^ Unclaimed block rewards
  } deriving (Show, Eq, Generic)

instance NFData CoinStats

instance Serialize CoinStats where
  put CoinStats{..} = do
    putWord64le csOutputCount
    putWord64le csBogoSize
    putWord64le csTotalAmount
    putWord64le csTotalSubsidy
    putInteger' csTotalPrevoutSpent
    putInteger' csTotalNewOutputs
    putInteger' csTotalCoinbaseAmount
    putWord64le csUnspendablesGenesis
    putWord64le csUnspendablesBIP30
    putWord64le csUnspendablesScripts
    putWord64le csUnspendablesUnclaimed
    where
      putInteger' n = do
        let bs = integerToBS n
        putWord32le (fromIntegral (BS.length bs))
        putByteString bs
  get = CoinStats
    <$> getWord64le
    <*> getWord64le
    <*> getWord64le
    <*> getWord64le
    <*> getInteger'
    <*> getInteger'
    <*> getInteger'
    <*> getWord64le
    <*> getWord64le
    <*> getWord64le
    <*> getWord64le
    where
      getInteger' = do
        len <- getWord32le
        bs <- getBytes (fromIntegral len)
        return $ bsToInteger bs

-- | CoinStats index entry (stored per block)
data CoinStatsEntry = CoinStatsEntry
  { cseBlockHash :: !BlockHash
  , cseMuHash    :: !Hash256       -- ^ MuHash finalized
  , cseStats     :: !CoinStats
  } deriving (Show, Eq, Generic)

instance NFData CoinStatsEntry

instance Serialize CoinStatsEntry where
  put CoinStatsEntry{..} = do
    put cseBlockHash
    put cseMuHash
    put cseStats
  get = CoinStatsEntry <$> get <*> get <*> get

-- | CoinStatsIndex database handle
data CoinStatsIndexDB = CoinStatsIndexDB
  { csiDB     :: !HaskoinDB
  , csiPrefix :: !Word8             -- ^ Per-height entry key prefix: 'M'
  , csiMuHash :: !(IORef MuHash3072)   -- ^ Running MuHash3072 accumulator
  , csiStats  :: !(IORef CoinStats)    -- ^ Running statistics
  , csiTipHeight :: !(IORef (Maybe BlockHeight))
    -- ^ Highest indexed height (the index "best block"), or 'Nothing'
    -- when empty.  Mirrors blockfilterindex's @bfiTipHeight@.
  }

-- | CoinStatsIndex key prefixes.
--
-- @0x4D@ ('M') keys the per-height @CoinStatsEntry@ records (block hash +
-- finalized muhash digest + counts/amounts), keyed @M || height(BE32)@.
-- @0x6D@ ('m') keys the per-height MuHash3072 accumulator SNAPSHOT (the
-- full 768-byte numerator||denominator), keyed @m || height(BE32)@.  The
-- finalized digest in the entry is one-way, so the accumulator snapshot is
-- what 'coinStatsIndexRevertBlock' resumes from on a disconnect/reorg.
-- @0x6E@ ('n') keys a single meta record: tip height + serialized running
-- accumulator + running stats, read once at startup to resume incremental
-- maintenance without replaying.
prefixCoinStats :: Word8
prefixCoinStats = 0x4D  -- 'M'

prefixCoinStatsMuHash :: Word8
prefixCoinStatsMuHash = 0x6D  -- 'm'

prefixCoinStatsMeta :: Word8
prefixCoinStatsMeta = 0x6E  -- 'n'

-- | Empty coin stats
emptyCoinStats :: CoinStats
emptyCoinStats = CoinStats 0 0 0 0 0 0 0 0 0 0 0

-- | Big-endian Word32 encoder for height-keyed coin-stats records (ascending
-- iterator order, same scheme blockfilterindex uses).
csiToBE32 :: Word32 -> ByteString
csiToBE32 w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xff)
  , fromIntegral ((w `shiftR` 16) .&. 0xff)
  , fromIntegral ((w `shiftR` 8) .&. 0xff)
  , fromIntegral (w .&. 0xff)
  ]

-- | Create a new CoinStatsIndex database
newCoinStatsIndexDB :: HaskoinDB -> IO CoinStatsIndexDB
newCoinStatsIndexDB db = do
  muHashRef <- newIORef muHashEmpty
  statsRef <- newIORef emptyCoinStats
  tipRef <- newIORef Nothing
  return CoinStatsIndexDB
    { csiDB = db
    , csiPrefix = prefixCoinStats
    , csiMuHash = muHashRef
    , csiStats = statsRef
    , csiTipHeight = tipRef
    }

-- | Put a coin stats entry
coinStatsIndexPut :: CoinStatsIndexDB -> BlockHeight -> CoinStatsEntry -> IO ()
coinStatsIndexPut CoinStatsIndexDB{..} height entry = do
  let key = BS.cons csiPrefix (csiToBE32 height)
  R.put (dbHandle csiDB) (dbWriteOpts csiDB) key (encode entry)

-- | Get a coin stats entry
coinStatsIndexGet :: CoinStatsIndexDB -> BlockHeight -> IO (Maybe CoinStatsEntry)
coinStatsIndexGet CoinStatsIndexDB{..} height = do
  let key = BS.cons csiPrefix (csiToBE32 height)
  mval <- R.get (dbHandle csiDB) (dbReadOpts csiDB) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Persist the per-height MuHash3072 accumulator snapshot (768 bytes:
-- numerator||denominator).  Restored by 'coinStatsIndexRevertBlock' to
-- resume the accumulator as of a previous height (the finalized digest in
-- the entry is one-way and cannot be resumed).
coinStatsMuHashPut :: CoinStatsIndexDB -> BlockHeight -> MuHash3072 -> IO ()
coinStatsMuHashPut CoinStatsIndexDB{..} height mh =
  let key = BS.cons prefixCoinStatsMuHash (csiToBE32 height)
  in R.put (dbHandle csiDB) (dbWriteOpts csiDB) key (muHashSerialize mh)

-- | Read back a per-height MuHash3072 accumulator snapshot.
coinStatsMuHashGet :: CoinStatsIndexDB -> BlockHeight -> IO (Maybe MuHash3072)
coinStatsMuHashGet CoinStatsIndexDB{..} height = do
  let key = BS.cons prefixCoinStatsMuHash (csiToBE32 height)
  mval <- R.get (dbHandle csiDB) (dbReadOpts csiDB) key
  return $ mval >>= either (const Nothing) Just . muHashDeserialize

-- | Delete a per-height MuHash3072 accumulator snapshot (reorg rewind).
coinStatsMuHashDelete :: CoinStatsIndexDB -> BlockHeight -> IO ()
coinStatsMuHashDelete CoinStatsIndexDB{..} height =
  R.delete (dbHandle csiDB) (dbWriteOpts csiDB)
    (BS.cons prefixCoinStatsMuHash (csiToBE32 height))

-- | Persisted CoinStatsIndex meta record: tip height + running accumulator
-- (768 bytes) + running stats.  Read once on startup.
data CoinStatsMeta = CoinStatsMeta
  { csmTipHeight :: !BlockHeight
  , csmMuHash    :: !MuHash3072
  , csmStats     :: !CoinStats
  }

instance Serialize CoinStatsMeta where
  put CoinStatsMeta{..} = do
    putWord32le csmTipHeight
    putByteString (muHashSerialize csmMuHash)
    put csmStats
  get = do
    h  <- getWord32le
    mb <- getBytes (2 * 384)
    mh <- either fail return (muHashDeserialize mb)
    st <- get
    return (CoinStatsMeta h mh st)

-- | Persist the index meta record (tip + running accumulator + stats).
coinStatsMetaPut :: CoinStatsIndexDB -> BlockHeight -> MuHash3072 -> CoinStats -> IO ()
coinStatsMetaPut CoinStatsIndexDB{..} height mh stats =
  let key = BS.singleton prefixCoinStatsMeta
  in R.put (dbHandle csiDB) (dbWriteOpts csiDB) key
       (encode (CoinStatsMeta height mh stats))

-- | Read the persisted index meta record.
coinStatsMetaGet :: CoinStatsIndexDB -> IO (Maybe CoinStatsMeta)
coinStatsMetaGet CoinStatsIndexDB{..} = do
  let key = BS.singleton prefixCoinStatsMeta
  mval <- R.get (dbHandle csiDB) (dbReadOpts csiDB) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Read the in-memory index tip height (highest indexed height).
coinStatsIndexTipHeight :: CoinStatsIndexDB -> IO (Maybe BlockHeight)
coinStatsIndexTipHeight = readIORef . csiTipHeight

-- | Restore the running accumulator + stats + tip from the persisted meta
-- record on startup.  Absent (fresh datadir) -> empty/Nothing, and a
-- subsequent 'indexManagerBackfill' rebuilds from height 1 forward.
coinStatsIndexInitFromDB :: CoinStatsIndexDB -> IO ()
coinStatsIndexInitFromDB db@CoinStatsIndexDB{..} = do
  mMeta <- coinStatsMetaGet db
  case mMeta of
    Just CoinStatsMeta{..} -> do
      writeIORef csiMuHash csmMuHash
      writeIORef csiStats csmStats
      writeIORef csiTipHeight (Just csmTipHeight)
    Nothing -> do
      writeIORef csiMuHash muHashEmpty
      writeIORef csiStats emptyCoinStats
      writeIORef csiTipHeight Nothing

-- | Serialize an outpoint + coin into Bitcoin Core's @TxOutSer@ per-coin
-- commitment record (kernel/coinstats.cpp): @outpoint || LE32(height<<1 |
-- coinbase) || LE64(value) || varint(scriptLen) || script@.  This is the
-- byte-exact element fed to the MuHash3072 accumulator, identical to the
-- record 'Haskoin.Storage.computeUtxoMuHash' (the @gettxoutsetinfo muhash@
-- tip path) streams, so the per-height running muhash equals Core's
-- @gettxoutsetinfo muhash H@ byte-for-byte.
serializeCoinForHash :: OutPoint -> Coin -> ByteString
serializeCoinForHash outpoint coin = runPut (putTxOutSer outpoint coin)

-- | Per-coin bogosize, byte-identical to Bitcoin Core
-- kernel/coinstats.cpp @GetBogoSize@:
--   32 (txid) + 4 (vout) + 4 (height|coinbase) + 8 (amount)
--   + 2 (scriptPubKey len) + scriptPubKey.size().
-- Must match the @gettxoutsetinfo@ tip path's bogosize formula
-- ('handleGetTxOutSetInfo' in "Haskoin.Rpc") so historical and tip
-- queries agree.
coinBogoSize :: Coin -> Word64
coinBogoSize coin =
  fromIntegral (32 + 4 + 4 + 8 + 2 + BS.length (txOutScript (coinTxOut coin)))

-- | Apply a coin to MuHash (when UTXO is created)
coinStatsApplyCoin :: CoinStatsIndexDB -> OutPoint -> Coin -> IO ()
coinStatsApplyCoin db outpoint coin = do
  let serialized = serializeCoinForHash outpoint coin
  modifyIORef' (csiMuHash db) (`muHashInsert` serialized)
  -- Update statistics
  modifyIORef' (csiStats db) $ \stats -> stats
    { csOutputCount = csOutputCount stats + 1
    , csTotalAmount = csTotalAmount stats + txOutValue (coinTxOut coin)
    , csBogoSize = csBogoSize stats + coinBogoSize coin
    }

-- | Remove a coin from MuHash (when UTXO is spent)
coinStatsRemoveCoin :: CoinStatsIndexDB -> OutPoint -> Coin -> IO ()
coinStatsRemoveCoin db outpoint coin = do
  let serialized = serializeCoinForHash outpoint coin
  modifyIORef' (csiMuHash db) (`muHashRemove` serialized)
  -- Update statistics
  modifyIORef' (csiStats db) $ \stats -> stats
    { csOutputCount = csOutputCount stats - 1
    , csTotalAmount = csTotalAmount stats - txOutValue (coinTxOut coin)
    , csBogoSize = csBogoSize stats - coinBogoSize coin
    }

-- | Append a block to the coin stats index, maintaining the running
-- MuHash3072 accumulator + counts INCREMENTALLY (insert created outputs,
-- remove spent coins via real undo data) and persisting:
--
--   * the per-height @CoinStatsEntry@ (block hash + finalized muhash digest
--     + counts/amounts) under @M || height@;
--   * the per-height MuHash3072 accumulator SNAPSHOT under @m || height@
--     so 'coinStatsIndexRevertBlock' can restore the exact accumulator as
--     of the previous height on a disconnect/reorg;
--   * the meta record (tip + running accumulator + running stats) so a
--     restart resumes incremental maintenance without replaying.
--
-- The coin-spendability filter is 'Haskoin.Storage.isUnspendable' — the
-- SAME predicate 'connectBlockAt' uses to decide what lands in the
-- @PrefixUTXO@ keyspace — so the index's UTXO set is byte-identical to
-- what the @gettxoutsetinfo@ tip path iterates.
--
-- Genesis (height 0) contributes NOTHING to the commitment: Bitcoin Core's
-- consensus never adds the genesis coinbase to the UTXO set, so the muhash
-- and counts at height 0 are over the empty set (matching Core's
-- coinstatsindex, which starts accumulating at height 1).
coinStatsIndexAppendBlock :: CoinStatsIndexDB -> Block -> BlockUndo -> BlockHash -> BlockHeight -> IO ()
coinStatsIndexAppendBlock db block undo blockHash height = do
  -- Track total block subsidy (informational; not gated).
  modifyIORef' (csiStats db) $ \s ->
    s { csTotalSubsidy = csTotalSubsidy s + getBlockSubsidy height }

  -- Process new outputs (skip unspendable, skip genesis entirely so the
  -- genesis coinbase is excluded from the UTXO commitment, matching Core).
  unless (height == 0) $
    forM_ (zip [0..] (blockTxns block)) $ \(txIdx, tx) -> do
      let isCoinbase = txIdx == (0 :: Int)
      forM_ (zip [0..] (txOutputs tx)) $ \(outIdx, txout) -> do
        unless (isUnspendable (txOutScript txout)) $ do
          let outpoint = OutPoint (computeTxId tx) (fromIntegral outIdx)
              coin = Coin txout height isCoinbase
          coinStatsApplyCoin db outpoint coin
          modifyIORef' (csiStats db) $ \s ->
            if isCoinbase
            then s { csTotalCoinbaseAmount = csTotalCoinbaseAmount s + fromIntegral (txOutValue txout) }
            else s { csTotalNewOutputs = csTotalNewOutputs s + fromIntegral (txOutValue txout) }

  -- Process spent outputs (from real undo data).  The undo record carries
  -- the spent coin's creating height + coinbase flag, so the removed
  -- @TxOutSer@ record is byte-identical to the one inserted when the coin
  -- was created — required for MuHash exactness.
  unless (height == 0) $
    forM_ (zip [1..] (buTxUndo undo)) $ \(txIdx, TxUndo prevOuts) -> do
      let tx = blockTxns block !! txIdx
      forM_ (zip [0..] prevOuts) $ \(inputIdx, TxInUndo spentOut spentHeight spentCoinbase) -> do
        let input = txInputs tx !! inputIdx
            outpoint = txInPrevOutput input
            coin = Coin spentOut spentHeight spentCoinbase
        coinStatsRemoveCoin db outpoint coin
        modifyIORef' (csiStats db) $ \s ->
          s { csTotalPrevoutSpent = csTotalPrevoutSpent s + fromIntegral (txOutValue spentOut) }

  -- Finalize + persist: per-height entry, per-height accumulator snapshot,
  -- and the running meta record.  Update the in-memory tip pointer.
  finalMuHash <- readIORef (csiMuHash db)
  finalStats <- readIORef (csiStats db)
  let muHashResult = muHashFinalize finalMuHash
      entry = CoinStatsEntry blockHash muHashResult finalStats
  coinStatsIndexPut db height entry
  coinStatsMuHashPut db height finalMuHash
  coinStatsMetaPut db height finalMuHash finalStats
  writeIORef (csiTipHeight db) (Just height)
  where
    getBlockSubsidy h =
      let halvings = h `div` 210000
          subsidy = 5000000000 `shiftR` fromIntegral halvings
      in if halvings >= 64 then 0 else subsidy

-- | Revert a previously-connected block from the coin stats index on a
-- disconnect/reorg.  Restores the running accumulator + stats to the state
-- AS OF @height - 1@ from the per-height snapshot + entry, deletes the
-- @height@ records, and pulls the in-memory tip back to @height - 1@.
--
-- Reference: bitcoin-core/src/index/coinstatsindex.cpp
-- CoinStatsIndex::CustomRewind (which replays per-block reverse-deltas);
-- here the per-height accumulator snapshot lets us restore in O(1) instead.
coinStatsIndexRevertBlock :: CoinStatsIndexDB -> BlockHeight -> IO ()
coinStatsIndexRevertBlock db height = do
  let prevHeight = height - 1
  -- Delete this height's per-height records.
  R.delete (dbHandle (csiDB db)) (dbWriteOpts (csiDB db))
    (BS.cons (csiPrefix db) (csiToBE32 height))
  coinStatsMuHashDelete db height
  if height == 0
    then do
      writeIORef (csiMuHash db) muHashEmpty
      writeIORef (csiStats db) emptyCoinStats
      writeIORef (csiTipHeight db) Nothing
      R.delete (dbHandle (csiDB db)) (dbWriteOpts (csiDB db))
        (BS.singleton prefixCoinStatsMeta)
    else do
      -- Restore the accumulator + stats from the previous height's snapshot
      -- + entry (the finalized digest is one-way, so we resume the full
      -- 768-byte accumulator).
      mPrevMh    <- coinStatsMuHashGet db prevHeight
      mPrevEntry <- coinStatsIndexGet db prevHeight
      let prevMh    = fromMaybe muHashEmpty mPrevMh
          prevStats = maybe emptyCoinStats cseStats mPrevEntry
      writeIORef (csiMuHash db) prevMh
      writeIORef (csiStats db) prevStats
      writeIORef (csiTipHeight db) (Just prevHeight)
      coinStatsMetaPut db prevHeight prevMh prevStats

--------------------------------------------------------------------------------
-- TxoSpenderIndex Database
--------------------------------------------------------------------------------
--
-- Maps a SPENT outpoint -> the SPENDING transaction (txid + confirming block
-- hash).  For every input of every non-coinbase transaction in a connected
-- block, write KV: @key = S || txid(32) || vout(BE32)@, @value = spendingTxid
-- (32) || blockHash(32)@.  On block disconnect, RE-DERIVE the exact same keys
-- from the disconnected block's OWN inputs and DELETE them — reorg-safe undo
-- with no separate undo data, exactly like Core's
-- @TxoSpenderIndex::CustomRemove(BuildSpenderPositions(block))@.
--
-- This is the from-scratch, outpoint -> spending-txid form the Core header
-- comment (txospenderindex.cpp) explicitly allows: Core stores the spending
-- tx's on-disk LOCATION keyed by a salted siphash(outpoint) so it can serve
-- the full spending tx and disambiguate siphash collisions; here the spending
-- txid is stored directly (no salt, no collisions) and the full spending tx —
-- needed only for @return_spending_tx@ — is read back from the confirming
-- block recorded in the value.  Default-off, gated by @-txospenderindex@,
-- mirroring Core's @DEFAULT_TXOSPENDERINDEX{false}@ and exactly how haskoin
-- gates its coinstatsindex.
--
-- Reorg-safety (the rustoshi lesson): the connect/disconnect hooks are wired
-- into 'indexManagerConnectBlock' / 'indexManagerDisconnectBlock', the SAME
-- single plumbing the coinstatsindex uses.  Both reorg entry points flow
-- through it disconnect-BEFORE-connect: the invalidateblock path
-- ('Haskoin.Consensus.reorgAtomic', conList empty -> pure disconnect) and the
-- live submitblock/P2P reorg path ('Haskoin.BlockTemplate.doSideBranchReorg').
-- Disconnecting the orphaned branch first erases its spender keys, THEN the
-- new branch's connect re-writes any shared outpoint to its own spending tx,
-- so a reorg that spends the same outpoint by a different tx on each branch
-- ends with the ACTIVE branch's spender recorded.

-- | Decoded value of a txospender-index entry: the spending transaction's
-- txid and the hash of the block that confirmed the spend.
data TxoSpender = TxoSpender
  { tsSpendingTxId :: !TxId
  , tsBlockHash    :: !BlockHash
  } deriving (Show, Eq, Generic)

instance NFData TxoSpender

-- | TxoSpenderIndex database handle.
data TxoSpenderIndexDB = TxoSpenderIndexDB
  { tsiDB        :: !HaskoinDB
  , tsiTipHeight :: !(IORef (Maybe BlockHeight))
    -- ^ Highest indexed height (the index "best block"), or 'Nothing' when
    -- empty.  Mirrors coinstatsindex's @csiTipHeight@.
  }

-- | TxoSpenderIndex key prefixes.
--
-- @0x53@ ('S') keys the per-spend records: @S || txid(32) || vout(BE32)@ ->
-- @spendingTxid(32) || blockHash(32)@.  The prefix byte 'S' echoes Core's
-- @DB_TXOSPENDERINDEX{'s'}@ (uppercase here to avoid colliding with the
-- per-height txindex/coinstats namespaces — confirmed distinct from the 't'
-- (txindex), 'F'/'f' (blockfilter), 'M'/'m'/'n' (coinstats) prefixes above).
-- @0x73@ ('s') keys a single meta record: tip height + tip block hash, read
-- once at startup to resume without replaying.
prefixTxoSpender :: Word8
prefixTxoSpender = 0x53  -- 'S'

prefixTxoSpenderMeta :: Word8
prefixTxoSpenderMeta = 0x73  -- 's'

-- | Big-endian Word32 encoder for the outpoint index component of the key.
tsiToBE32 :: Word32 -> ByteString
tsiToBE32 w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xff)
  , fromIntegral ((w `shiftR` 16) .&. 0xff)
  , fromIntegral ((w `shiftR` 8) .&. 0xff)
  , fromIntegral (w .&. 0xff)
  ]

-- | Build the per-spend KV key for a spent outpoint:
-- @S || outpoint.txid(32) || outpoint.vout(BE32)@.  The txid bytes are the
-- internal little-endian hash bytes (same as everywhere else in storage); the
-- vout is big-endian so RocksDB groups keys by spending txid prefix.
makeTxoSpenderKey :: OutPoint -> ByteString
makeTxoSpenderKey op =
  let TxId (Hash256 txidBytes) = outPointHash op
  in BS.concat [ BS.singleton prefixTxoSpender
               , txidBytes
               , tsiToBE32 (outPointIndex op) ]

-- | Serialise the (spending txid, confirming block hash) value as 64 bytes.
txoSpenderValue :: TxId -> BlockHash -> ByteString
txoSpenderValue (TxId (Hash256 txid)) (BlockHash (Hash256 bh)) =
  BS.append txid bh

-- | Decode a 64-byte txospender-index value.
decodeTxoSpenderValue :: ByteString -> Maybe TxoSpender
decodeTxoSpenderValue bs
  | BS.length bs < 64 = Nothing
  | otherwise =
      Just TxoSpender
        { tsSpendingTxId = TxId (Hash256 (BS.take 32 bs))
        , tsBlockHash    = BlockHash (Hash256 (BS.take 32 (BS.drop 32 bs)))
        }

-- | Persisted TxoSpenderIndex meta record: tip height + tip block hash.
data TxoSpenderMeta = TxoSpenderMeta
  { tsmTipHeight :: !BlockHeight
  , tsmTipHash   :: !BlockHash
  }

instance Serialize TxoSpenderMeta where
  put TxoSpenderMeta{..} = do
    putWord32le tsmTipHeight
    put tsmTipHash
  get = TxoSpenderMeta <$> getWord32le <*> get

-- | Create a new TxoSpenderIndex database handle.
newTxoSpenderIndexDB :: HaskoinDB -> IO TxoSpenderIndexDB
newTxoSpenderIndexDB db = do
  tipRef <- newIORef Nothing
  return TxoSpenderIndexDB { tsiDB = db, tsiTipHeight = tipRef }

-- | Persist the meta record (tip height + tip hash).
txoSpenderMetaPut :: TxoSpenderIndexDB -> BlockHeight -> BlockHash -> IO ()
txoSpenderMetaPut TxoSpenderIndexDB{..} height hash =
  R.put (dbHandle tsiDB) (dbWriteOpts tsiDB)
    (BS.singleton prefixTxoSpenderMeta)
    (encode (TxoSpenderMeta height hash))

-- | Read the persisted meta record.
txoSpenderMetaGet :: TxoSpenderIndexDB -> IO (Maybe TxoSpenderMeta)
txoSpenderMetaGet TxoSpenderIndexDB{..} = do
  mval <- R.get (dbHandle tsiDB) (dbReadOpts tsiDB)
            (BS.singleton prefixTxoSpenderMeta)
  return $ mval >>= either (const Nothing) Just . decode

-- | Restore the in-memory tip height from the persisted meta record on
-- startup.  Absent (fresh datadir) -> 'Nothing', and a subsequent
-- 'indexManagerBackfill' rebuilds from height 1 forward.
txoSpenderIndexInitFromDB :: TxoSpenderIndexDB -> IO ()
txoSpenderIndexInitFromDB db@TxoSpenderIndexDB{..} = do
  mMeta <- txoSpenderMetaGet db
  writeIORef tsiTipHeight (fmap tsmTipHeight mMeta)

-- | Read the in-memory index tip height (highest indexed height).
txoSpenderIndexTipHeight :: TxoSpenderIndexDB -> IO (Maybe BlockHeight)
txoSpenderIndexTipHeight = readIORef . tsiTipHeight

-- | Index every spend in a newly connected block: for each input of each
-- non-coinbase transaction, write (spent outpoint -> spending txid ||
-- confirming block hash).  The undo argument is ignored on purpose — like
-- Core's @CustomAppend(BuildSpenderPositions(block))@, every key is a pure
-- function of the block's own inputs.
--
-- Genesis (height 0) contributes nothing: its single coinbase tx has the null
-- prevout, exactly like txindex/coinstatsindex skip it.  We still advance the
-- tip pointer so a later 'indexManagerBackfill' resumes at height 1.
txoSpenderIndexAppendBlock :: TxoSpenderIndexDB -> Block -> BlockHash -> BlockHeight -> IO ()
txoSpenderIndexAppendBlock db block blockHash height = do
  unless (height == 0) $
    forM_ (zip [0..] (blockTxns block)) $ \(txIdx, tx) ->
      unless (txIdx == (0 :: Int)) $ do          -- skip coinbase: null prevout
        let spendingTxid = computeTxId tx
            val = txoSpenderValue spendingTxid blockHash
        forM_ (txInputs tx) $ \inp ->
          R.put (dbHandle (tsiDB db)) (dbWriteOpts (tsiDB db))
            (makeTxoSpenderKey (txInPrevOutput inp)) val
  txoSpenderMetaPut db height blockHash
  writeIORef (tsiTipHeight db) (Just height)

-- | Erase every spend recorded for a disconnected block.  The keys are
-- RE-DERIVED from the block's inputs (no undo data needed), mirroring Core's
-- @CustomRemove(BuildSpenderPositions(block))@.  This is the reorg-safe undo:
-- on the live-reorg path the orphaned branch is disconnected (this) BEFORE the
-- new branch is connected, so a shared outpoint ends up keyed to the active
-- branch's spending tx.  Rewinds the in-memory + persisted tip to @height-1@.
txoSpenderIndexRevertBlock :: TxoSpenderIndexDB -> Block -> BlockHash -> BlockHeight -> IO ()
txoSpenderIndexRevertBlock db block _blockHash height = do
  unless (height == 0) $
    forM_ (zip [0..] (blockTxns block)) $ \(txIdx, tx) ->
      unless (txIdx == (0 :: Int)) $
        forM_ (txInputs tx) $ \inp ->
          R.delete (dbHandle (tsiDB db)) (dbWriteOpts (tsiDB db))
            (makeTxoSpenderKey (txInPrevOutput inp))
  let prevHeight = if height > 0 then height - 1 else 0
  -- Pull the tip back to the previous height.  We do not have the parent's
  -- block hash here without a lookup; the meta hash is only used to report
  -- best_block on getindexinfo, so write the parent header hash from the
  -- disconnected block's prev pointer.
  let prevHash = bhPrevBlock (blockHeader block)
  if height == 0
    then do
      R.delete (dbHandle (tsiDB db)) (dbWriteOpts (tsiDB db))
        (BS.singleton prefixTxoSpenderMeta)
      writeIORef (tsiTipHeight db) Nothing
    else do
      txoSpenderMetaPut db prevHeight prevHash
      writeIORef (tsiTipHeight db) (Just prevHeight)

-- | Look up the on-chain transaction that spends the given outpoint.
-- Returns 'Just' the spender (spending txid + confirming block hash) if a
-- confirmed spend is recorded, or 'Nothing' if the outpoint is unspent
-- on-chain.  Mirrors Core's @TxoSpenderIndex::FindSpender@ (which returns
-- @std::nullopt@ when unspent).
txoSpenderIndexFind :: TxoSpenderIndexDB -> OutPoint -> IO (Maybe TxoSpender)
txoSpenderIndexFind TxoSpenderIndexDB{..} op = do
  mval <- R.get (dbHandle tsiDB) (dbReadOpts tsiDB) (makeTxoSpenderKey op)
  return $ mval >>= decodeTxoSpenderValue

--------------------------------------------------------------------------------
-- Index Manager
--------------------------------------------------------------------------------

-- | Index configuration
data IndexConfig = IndexConfig
  { icTxIndex          :: !Bool
  , icBlockFilterIndex :: !Bool
  , icCoinStatsIndex   :: !Bool
  , icTxoSpenderIndex  :: !Bool
  } deriving (Show, Eq)

-- | Default index configuration (all disabled)
defaultIndexConfig :: IndexConfig
defaultIndexConfig = IndexConfig False False False False

-- | Index manager
data IndexManager = IndexManager
  { imConfig          :: !IndexConfig
  , imTxIndex         :: !(Maybe TxIndexDB)
  , imBlockFilterIndex :: !(Maybe BlockFilterIndexDB)
  , imCoinStatsIndex  :: !(Maybe CoinStatsIndexDB)
  , imTxoSpenderIndex :: !(Maybe TxoSpenderIndexDB)
  , imSyncHeight      :: !(IORef BlockHeight)
  }

-- | Create a new index manager
newIndexManager :: HaskoinDB -> IndexConfig -> IO IndexManager
newIndexManager db config = do
  txIdx <- if icTxIndex config
           then Just <$> pure (newTxIndexDB db)
           else return Nothing

  bfIdx <- if icBlockFilterIndex config
           then Just <$> newBlockFilterIndexDB db
           else return Nothing

  csIdx <- if icCoinStatsIndex config
           then Just <$> newCoinStatsIndexDB db
           else return Nothing

  tsIdx <- if icTxoSpenderIndex config
           then Just <$> newTxoSpenderIndexDB db
           else return Nothing

  syncHeightRef <- newIORef 0

  return IndexManager
    { imConfig = config
    , imTxIndex = txIdx
    , imBlockFilterIndex = bfIdx
    , imCoinStatsIndex = csIdx
    , imTxoSpenderIndex = tsIdx
    , imSyncHeight = syncHeightRef
    }

-- | Sync indexes in background
indexManagerSync :: IndexManager
                 -> (BlockHeight -> IO (Maybe (Block, BlockUndo, BlockHash)))
                 -> BlockHeight
                 -> IO (Async ())
indexManagerSync im getBlock targetHeight = async $ do
  currentHeight <- readIORef (imSyncHeight im)
  forM_ [currentHeight + 1 .. targetHeight] $ \height -> do
    mData <- getBlock height
    case mData of
      Nothing -> return ()
      Just (block, undo, blockHash) -> do
        indexManagerConnectBlock im block undo blockHash height
        writeIORef (imSyncHeight im) height

-- | Connect a block to all enabled indexes
indexManagerConnectBlock :: IndexManager -> Block -> BlockUndo -> BlockHash -> BlockHeight -> IO ()
indexManagerConnectBlock im block undo blockHash height = do
  -- TxIndex
  case imTxIndex im of
    Nothing -> return ()
    Just txIdx -> txIndexAppendBlock txIdx block blockHash height

  -- BlockFilterIndex
  case imBlockFilterIndex im of
    Nothing -> return ()
    Just bfIdx -> blockFilterIndexAppendBlock bfIdx block undo blockHash height

  -- CoinStatsIndex
  case imCoinStatsIndex im of
    Nothing -> return ()
    Just csIdx -> coinStatsIndexAppendBlock csIdx block undo blockHash height

  -- TxoSpenderIndex
  case imTxoSpenderIndex im of
    Nothing -> return ()
    Just tsIdx -> txoSpenderIndexAppendBlock tsIdx block blockHash height

  -- Update the manager's tracked sync height. This makes
  -- 'imSyncHeight' the canonical "indexes are caught up to here"
  -- pointer, used by 'indexManagerBackfill' to figure out where to
  -- resume on the next startup or when a new tip arrives via the
  -- normal IBD path.
  writeIORef (imSyncHeight im) height

-- | Reverse a previously-connected block from the disconnect-aware indexes.
-- The BlockFilterIndex deletes the per-height filter entry; the CoinStatsIndex
-- restores the running accumulator from the previous-height snapshot; the
-- TxoSpenderIndex RE-DERIVES the disconnected block's own input keys and
-- deletes them (Core's CustomRemove).  TxIndex entries are intentionally
-- orphan-tolerant (Core leaves stale TxIndex entries for forked-out blocks;
-- reads are idempotent because the active-chain pointer is checked
-- separately).
--
-- The @Block@ + @BlockHash@ are the DISCONNECTED block's own data — required
-- so the TxoSpenderIndex can re-derive its spender keys without separate undo
-- data.  Both reorg paths
-- ('Haskoin.Consensus.reorgAtomic' / invalidateblock and
-- 'Haskoin.BlockTemplate.doSideBranchReorg' / live submitblock+P2P reorg) call
-- this disconnect-BEFORE-connect, so the txospender index ends a reorg keyed
-- to the ACTIVE branch's spending tx.
-- Reference: bitcoin-core/src/index/{blockfilterindex,coinstatsindex,txospenderindex}.cpp
-- CustomRewind / CustomRemove.
indexManagerDisconnectBlock :: IndexManager -> Block -> BlockHash -> BlockHeight -> IO ()
indexManagerDisconnectBlock im block blockHash height = do
  case imBlockFilterIndex im of
    Nothing -> return ()
    Just bfIdx -> blockFilterIndexDelete bfIdx height
  -- CoinStatsIndex: reverse the connected block (restore the running
  -- accumulator + counts from the previous height's snapshot and rewind the
  -- index tip). Real undo data is NOT needed on the reverse path because the
  -- per-height accumulator snapshot already captures the pre-block state.
  case imCoinStatsIndex im of
    Nothing -> return ()
    Just csIdx -> coinStatsIndexRevertBlock csIdx height
  -- TxoSpenderIndex: erase this disconnected block's spender keys, re-derived
  -- from its own inputs (Core CustomRemove). Reorg-safe: on the live path the
  -- caller runs disconnect (this) before connect, so a shared outpoint ends
  -- keyed to the new branch's spending tx.
  case imTxoSpenderIndex im of
    Nothing -> return ()
    Just tsIdx -> txoSpenderIndexRevertBlock tsIdx block blockHash height
  -- Pull imSyncHeight back to (height - 1) so a subsequent
  -- 'indexManagerBackfill' resumes from the correct point. Using
  -- saturating subtraction so disconnecting genesis (an
  -- impossible-but-defensive case) doesn't underflow.
  modifyIORef' (imSyncHeight im) $ \h ->
    if h >= height && height > 0 then height - 1 else 0

-- | Initialise per-index in-memory state from disk. This must be
-- called immediately after 'newIndexManager' on every startup so the
-- index doesn't recompute filters that are already on disk.
--
-- Today only the BlockFilterIndex carries persistable in-memory
-- state (its chained @filter_header@ pointer + tip-height). Other
-- indexes either have no in-memory state ('TxIndex') or rebuild
-- their accumulator in 'indexManagerBackfill' ('CoinStatsIndex').
indexManagerInitFromDB :: IndexManager -> IO ()
indexManagerInitFromDB im = do
  -- BlockFilterIndex: load its persisted chain pointer + tip height.
  bfTip <- case imBlockFilterIndex im of
    Nothing -> return Nothing
    Just bfIdx -> do
      loadBlockFilterIndexState bfIdx
      blockFilterIndexTipHeight bfIdx
  -- CoinStatsIndex: restore its running accumulator + counts + tip height.
  csTip <- case imCoinStatsIndex im of
    Nothing -> return Nothing
    Just csIdx -> do
      coinStatsIndexInitFromDB csIdx
      coinStatsIndexTipHeight csIdx
  -- TxoSpenderIndex: restore its tip height from the persisted meta record.
  tsTip <- case imTxoSpenderIndex im of
    Nothing -> return Nothing
    Just tsIdx -> do
      txoSpenderIndexInitFromDB tsIdx
      txoSpenderIndexTipHeight tsIdx
  -- 'imSyncHeight' is the lockstep "indexes caught up to here" pointer used
  -- by 'indexManagerBackfill'.  Seed it to the LOWEST enabled-index tip so a
  -- lagging index gets backfilled (an index ahead of another would otherwise
  -- skip the gap).  When no enabled index has any on-disk state, start at 0.
  let tips = [ t | Just t <- [bfTip, csTip, tsTip] ]
  case tips of
    [] -> writeIORef (imSyncHeight im) 0
    _  -> writeIORef (imSyncHeight im) (minimum tips)

-- | Walk the active chain forward from @imSyncHeight + 1@ to
-- @bestHeight@ and populate every enabled index. Used at startup
-- when an opt-in index flag is enabled but the on-disk index is
-- stale (or empty) — for example, a node that ran for two days with
-- the flag off and then enables it.
--
-- The @getBlockData@ callback returns the block + undo + hash for a
-- given height, exactly as 'indexManagerSync' does; passing a
-- callback (rather than calling 'getBlock' / 'getUndoData' here)
-- keeps "Haskoin.Index" decoupled from "Haskoin.Storage".
--
-- Returns the height the index is now caught up to (== bestHeight
-- on success; less if a block or undo record was missing — common
-- for block 0, where genesis has no undo data).
--
-- Reference: bitcoin-core/src/index/base.cpp BaseIndex::Sync — same
-- pattern, walk last-indexed → tip and call CustomAppend per block.
indexManagerBackfill :: IndexManager
                     -> (BlockHeight -> IO (Maybe (Block, BlockUndo, BlockHash)))
                     -> BlockHeight
                     -> IO BlockHeight
indexManagerBackfill im getBlockData bestHeight = do
  start <- readIORef (imSyncHeight im)
  let from = if start == 0 then 1 else start + 1
  let go h
        | h > bestHeight = return (max start (h - 1))
        | otherwise = do
            mData <- getBlockData h
            case mData of
              Nothing -> return (h - 1)  -- gap; stop and let live sync resume
              Just (block, undo, blockHash) -> do
                indexManagerConnectBlock im block undo blockHash h
                go (h + 1)
  go from

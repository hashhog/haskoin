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
  , coinStatsApplyCoin
  , coinStatsRemoveCoin
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
                         Coin(..), BlockHeight, integerToBS, bsToInteger)
import Haskoin.MuHash (MuHash3072(..), Num3072(..),
                       muHashEmpty, muHashInsert, muHashRemove,
                       muHashCombine, muHashFinalize,
                       num3072ToBytes, num3072Multiply, num3072GetInverse,
                       muHashToNum3072)
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

-- | Bit writer state
data BitWriter = BitWriter
  { bwBuffer :: !Word64      -- ^ Current buffer
  , bwBits   :: !Int         -- ^ Bits used in buffer
  , bwOutput :: ![Word8]     -- ^ Output bytes (in reverse order)
  } deriving (Show)

-- | Create a new bit writer
bitWriterNew :: BitWriter
bitWriterNew = BitWriter 0 0 []

-- | Write bits to the bit writer.
--
-- The @numBits@ least-significant bits of @value@ are appended to the stream.
--
-- BUG-16 P0 (W121 addendum): when @numBits + bwBits > 64@ the high-order bits
-- of the shifted value fell off the top of the 'Word64' buffer.  We now split
-- any cross-Word64-boundary write into two phases:
--
--   (1) write @(64 - bwBits)@ low-order bits with the fast path; the recursive
--       'flushBytes' drains the now-full 64-bit buffer to the byte stream;
--   (2) recursively write the remaining @numBits - (64 - bwBits)@ high-order
--       bits — these are @value `shiftR` (64 - bwBits)@.
--
-- Reference: bitcoin-core/src/streams.h BitStreamWriter::Write, which solves
-- the same boundary problem with a per-octet inner loop.  We keep the
-- existing Word64-buffer shape (cheaper than a per-byte loop in Haskell) but
-- never let an unsplit write straddle the 64-bit boundary.
bitWriterWrite :: BitWriter -> Int -> Word64 -> BitWriter
bitWriterWrite bw numBits value
  | numBits <= 0 = bw
  | numBits >  64 = error "bitWriterWrite: numBits > 64"
  | numBits + bwBits bw > 64 =
      -- Cross-Word64-boundary write: split into low + high halves.
      -- The low half exactly fills the current buffer to 64 bits, which
      -- flushBytes then drains as 8 full bytes, leaving bwBits = 0.
      let lowN  = 64 - bwBits bw                    -- bits that fit now
          highN = numBits - lowN                    -- bits left to write
          lowV  = value .&. (mask lowN)             -- low-order bits
          highV = value `shiftR` lowN               -- high-order bits
          bw'   = bitWriterWrite bw  lowN  lowV
      in     bitWriterWrite bw' highN highV
  | otherwise =
      let maskedValue = value .&. (mask numBits)
          newBuffer = bwBuffer bw .|. (maskedValue `shiftL` bwBits bw)
          newBits = bwBits bw + numBits
      in flushBytes $ bw { bwBuffer = newBuffer, bwBits = newBits }
  where
    -- | n-bit mask with n in [0,64].  At n=64 the naive @(1 << 64) - 1@
    -- collapses to 0 - 1 = 0xFFFF... by GHC's modular semantics, but spelling
    -- it explicitly avoids relying on that and matches Core's '~0ULL'.
    mask :: Int -> Word64
    mask 64 = maxBound
    mask n  = (1 `shiftL` n) - 1

    flushBytes !bw'
      | bwBits bw' >= 8 =
          let byte = fromIntegral (bwBuffer bw' .&. 0xff)
              remaining = bwBuffer bw' `shiftR` 8
              newBits = bwBits bw' - 8
          in flushBytes $ bw' { bwBuffer = remaining, bwBits = newBits,
                                bwOutput = byte : bwOutput bw' }
      | otherwise = bw'

-- | Flush remaining bits and get output
bitWriterFlush :: BitWriter -> ByteString
bitWriterFlush bw =
  let finalOutput = if bwBits bw > 0
                    then fromIntegral (bwBuffer bw .&. 0xff) : bwOutput bw
                    else bwOutput bw
  in BS.pack (reverse finalOutput)

-- | Bit reader state
data BitReader = BitReader
  { brInput  :: !ByteString  -- ^ Remaining input
  , brBuffer :: !Word64      -- ^ Current buffer
  , brBits   :: !Int         -- ^ Bits available in buffer
  } deriving (Show)

-- | Create a new bit reader
bitReaderNew :: ByteString -> BitReader
bitReaderNew bs = fillBuffer $ BitReader bs 0 0
  where
    fillBuffer !br
      | brBits br >= 56 = br
      | BS.null (brInput br) = br
      | otherwise =
          let byte = fromIntegral (BS.head (brInput br)) :: Word64
              rest = BS.tail (brInput br)
              newBuffer = brBuffer br .|. (byte `shiftL` brBits br)
              newBits = brBits br + 8
          in fillBuffer $ br { brInput = rest, brBuffer = newBuffer, brBits = newBits }

-- | Read bits from the bit reader
bitReaderRead :: BitReader -> Int -> (Word64, BitReader)
bitReaderRead br numBits
  | numBits <= 0 = (0, br)
  | brBits br < numBits = error "Not enough bits in reader"
  | otherwise =
      let mask = (1 `shiftL` numBits) - 1
          value = brBuffer br .&. mask
          newBuffer = brBuffer br `shiftR` numBits
          newBits = brBits br - numBits
      in (value, fillBuffer $ br { brBuffer = newBuffer, brBits = newBits })
  where
    fillBuffer !br'
      | brBits br' >= 56 = br'
      | BS.null (brInput br') = br'
      | otherwise =
          let byte = fromIntegral (BS.head (brInput br')) :: Word64
              rest = BS.tail (brInput br')
              newBuffer = brBuffer br' .|. (byte `shiftL` brBits br')
              newBits = brBits br' + 8
          in fillBuffer $ br' { brInput = rest, brBuffer = newBuffer, brBits = newBits }

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
      | brBits br' == 0 && BS.null (brInput br') = (acc, br')
      | otherwise =
          let (bit, br'') = bitReaderRead br' 1
          in if bit == 1
             then readUnary br'' (acc + 1)
             else (acc, br'')

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
  , csiPrefix :: !Word8             -- ^ Key prefix: 'M'
  , csiMuHash :: !(IORef MuHash3072)   -- ^ Running MuHash state
  , csiStats  :: !(IORef CoinStats)    -- ^ Running statistics
  }

-- | CoinStatsIndex key prefix
prefixCoinStats :: Word8
prefixCoinStats = 0x4D  -- 'M'

-- | Empty coin stats
emptyCoinStats :: CoinStats
emptyCoinStats = CoinStats 0 0 0 0 0 0 0 0 0 0 0

-- | Create a new CoinStatsIndex database
newCoinStatsIndexDB :: HaskoinDB -> IO CoinStatsIndexDB
newCoinStatsIndexDB db = do
  muHashRef <- newIORef muHashEmpty
  statsRef <- newIORef emptyCoinStats
  return CoinStatsIndexDB
    { csiDB = db
    , csiPrefix = prefixCoinStats
    , csiMuHash = muHashRef
    , csiStats = statsRef
    }

-- | Put a coin stats entry
coinStatsIndexPut :: CoinStatsIndexDB -> BlockHeight -> CoinStatsEntry -> IO ()
coinStatsIndexPut CoinStatsIndexDB{..} height entry = do
  let key = BS.cons csiPrefix (toBE32 height)
  R.put (dbHandle csiDB) (dbWriteOpts csiDB) key (encode entry)
  where
    toBE32 w = BS.pack
      [ fromIntegral ((w `shiftR` 24) .&. 0xff)
      , fromIntegral ((w `shiftR` 16) .&. 0xff)
      , fromIntegral ((w `shiftR` 8) .&. 0xff)
      , fromIntegral (w .&. 0xff)
      ]

-- | Get a coin stats entry
coinStatsIndexGet :: CoinStatsIndexDB -> BlockHeight -> IO (Maybe CoinStatsEntry)
coinStatsIndexGet CoinStatsIndexDB{..} height = do
  let key = BS.cons csiPrefix (toBE32 height)
  mval <- R.get (dbHandle csiDB) (dbReadOpts csiDB) key
  return $ mval >>= either (const Nothing) Just . decode
  where
    toBE32 w = BS.pack
      [ fromIntegral ((w `shiftR` 24) .&. 0xff)
      , fromIntegral ((w `shiftR` 16) .&. 0xff)
      , fromIntegral ((w `shiftR` 8) .&. 0xff)
      , fromIntegral (w .&. 0xff)
      ]

-- | Serialize an outpoint + coin for MuHash
serializeCoinForHash :: OutPoint -> Coin -> ByteString
serializeCoinForHash outpoint coin =
  encode outpoint `BS.append` encode coin

-- | Apply a coin to MuHash (when UTXO is created)
coinStatsApplyCoin :: CoinStatsIndexDB -> OutPoint -> Coin -> IO ()
coinStatsApplyCoin db outpoint coin = do
  let serialized = serializeCoinForHash outpoint coin
  modifyIORef' (csiMuHash db) (`muHashInsert` serialized)
  -- Update statistics
  modifyIORef' (csiStats db) $ \stats -> stats
    { csOutputCount = csOutputCount stats + 1
    , csTotalAmount = csTotalAmount stats + txOutValue (coinTxOut coin)
    , csBogoSize = csBogoSize stats + fromIntegral (BS.length (txOutScript (coinTxOut coin)))
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
    , csBogoSize = csBogoSize stats - fromIntegral (BS.length (txOutScript (coinTxOut coin)))
    }

-- | Append a block to the coin stats index
coinStatsIndexAppendBlock :: CoinStatsIndexDB -> Block -> BlockUndo -> BlockHash -> BlockHeight -> IO ()
coinStatsIndexAppendBlock db block undo blockHash height = do
  stats <- readIORef (csiStats db)

  -- Calculate block subsidy
  let subsidy = getBlockSubsidy height
      newStats = stats { csTotalSubsidy = csTotalSubsidy stats + subsidy }

  -- Process new outputs (skip unspendable)
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

  -- Process spent outputs (from undo data)
  forM_ (zip [1..] (buTxUndo undo)) $ \(txIdx, TxUndo prevOuts) -> do
    let tx = blockTxns block !! txIdx
    forM_ (zip [0..] prevOuts) $ \(inputIdx, TxInUndo spentOut spentHeight spentCoinbase) -> do
      let input = txInputs tx !! inputIdx
          outpoint = txInPrevOutput input
          coin = Coin spentOut spentHeight spentCoinbase
      coinStatsRemoveCoin db outpoint coin
      modifyIORef' (csiStats db) $ \s ->
        s { csTotalPrevoutSpent = csTotalPrevoutSpent s + fromIntegral (txOutValue spentOut) }

  -- Save entry
  finalMuHash <- readIORef (csiMuHash db)
  finalStats <- readIORef (csiStats db)
  let muHashResult = muHashFinalize finalMuHash
      entry = CoinStatsEntry blockHash muHashResult finalStats
  coinStatsIndexPut db height entry
  writeIORef (csiStats db) finalStats
  where
    isUnspendable script =
      not (BS.null script) && BS.head script == 0x6a  -- OP_RETURN

    getBlockSubsidy h =
      let halvings = h `div` 210000
          subsidy = 5000000000 `shiftR` fromIntegral halvings
      in if halvings >= 64 then 0 else subsidy

--------------------------------------------------------------------------------
-- Index Manager
--------------------------------------------------------------------------------

-- | Index configuration
data IndexConfig = IndexConfig
  { icTxIndex          :: !Bool
  , icBlockFilterIndex :: !Bool
  , icCoinStatsIndex   :: !Bool
  } deriving (Show, Eq)

-- | Default index configuration (all disabled)
defaultIndexConfig :: IndexConfig
defaultIndexConfig = IndexConfig False False False

-- | Index manager
data IndexManager = IndexManager
  { imConfig          :: !IndexConfig
  , imTxIndex         :: !(Maybe TxIndexDB)
  , imBlockFilterIndex :: !(Maybe BlockFilterIndexDB)
  , imCoinStatsIndex  :: !(Maybe CoinStatsIndexDB)
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

  syncHeightRef <- newIORef 0

  return IndexManager
    { imConfig = config
    , imTxIndex = txIdx
    , imBlockFilterIndex = bfIdx
    , imCoinStatsIndex = csIdx
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

  -- Update the manager's tracked sync height. This makes
  -- 'imSyncHeight' the canonical "indexes are caught up to here"
  -- pointer, used by 'indexManagerBackfill' to figure out where to
  -- resume on the next startup or when a new tip arrives via the
  -- normal IBD path.
  writeIORef (imSyncHeight im) height

-- | Reverse a previously-connected block from the BlockFilterIndex.
-- Today only the filter index needs disconnect handling — TxIndex
-- entries are intentionally orphan-tolerant (Core leaves stale
-- TxIndex entries for forked-out blocks; reads are idempotent
-- because the active-chain pointer is checked separately), and
-- CoinStatsIndex is recomputed wholesale rather than reverted.
-- Reference: bitcoin-core/src/index/blockfilterindex.cpp
-- BlockFilterIndex::CustomRewind.
indexManagerDisconnectBlock :: IndexManager -> BlockHeight -> IO ()
indexManagerDisconnectBlock im height = do
  case imBlockFilterIndex im of
    Nothing -> return ()
    Just bfIdx -> blockFilterIndexDelete bfIdx height
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
  case imBlockFilterIndex im of
    Nothing -> return ()
    Just bfIdx -> do
      loadBlockFilterIndexState bfIdx
      mTip <- blockFilterIndexTipHeight bfIdx
      case mTip of
        Just h  -> writeIORef (imSyncHeight im) h
        Nothing -> writeIORef (imSyncHeight im) 0

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

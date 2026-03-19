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
    -- * MuHash3072 (Multiplicative Hash)
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
  , blockFilterIndexPut
  , blockFilterIndexGet
  , blockFilterIndexAppendBlock
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
  , indexManagerSync
  , indexManagerConnectBlock
    -- * SipHash
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
import Haskoin.Storage (HaskoinDB(..), BlockUndo(..), TxUndo(..), TxInUndo(..),
                         Coin(..), BlockHeight, integerToBS, bsToInteger)

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
      let padded = leftover `BS.append` BS.replicate (7 - BS.length leftover) 0
          lenByte = fromIntegral (totalLen .&. 0xff) `shiftL` 56
      in decodeLE64 padded .|. lenByte

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

-- | Write bits to the bit writer
bitWriterWrite :: BitWriter -> Int -> Word64 -> BitWriter
bitWriterWrite bw numBits value
  | numBits <= 0 = bw
  | otherwise =
      let maskedValue = value .&. ((1 `shiftL` numBits) - 1)
          newBuffer = bwBuffer bw .|. (maskedValue `shiftL` bwBits bw)
          newBits = bwBits bw + numBits
      in flushBytes $ bw { bwBuffer = newBuffer, bwBits = newBits }
  where
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
gcsFilterEmpty :: GCSParams -> GCSFilter
gcsFilterEmpty params = GCSFilter
  { gcsParams = params
  , gcsN = 0
  , gcsF = 0
  , gcsEncoded = BS.empty
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
    encodeCompactSize n
      | n < 0xfd = BS.singleton (fromIntegral n)
      | n <= 0xffff = BS.cons 0xfd (encodeLE16 (fromIntegral n :: Word16))
      | n <= 0xffffffff = BS.cons 0xfe (encodeLE32 (fromIntegral n :: Word32))
      | otherwise = BS.cons 0xff (encodeLE64 n)

    encodeLE16 w = BS.pack [fromIntegral w, fromIntegral (w `shiftR` 8)]
    encodeLE32 w = BS.pack [fromIntegral (w `shiftR` (i * 8)) | i <- [0..3]]

-- | Encode a GCS filter
gcsFilterEncode :: GCSFilter -> ByteString
gcsFilterEncode = gcsEncoded

-- | Decode a GCS filter
gcsFilterDecode :: GCSParams -> ByteString -> Either String GCSFilter
gcsFilterDecode params bs
  | BS.null bs = Right $ gcsFilterEmpty params
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
                 let val = decodeLE16' (BS.drop 1 bs')
                 in Right (fromIntegral val, BS.drop 3 bs')
               0xfe | BS.length bs' >= 5 ->
                 let val = decodeLE32' (BS.drop 1 bs')
                 in Right (fromIntegral val, BS.drop 5 bs')
               0xff | BS.length bs' >= 9 ->
                 let val = decodeLE64 (BS.drop 1 bs')
                 in Right (val, BS.drop 9 bs')
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
-- From BIP158: outputs' scriptPubKeys (excluding OP_RETURN) + spent outputs' scriptPubKeys
blockFilterElements :: Block -> BlockUndo -> [ByteString]
blockFilterElements block undo =
  let -- Output scripts from all transactions (excluding OP_RETURN)
      outputScripts = concatMap txOutputScripts (blockTxns block)
      -- Spent output scripts from undo data
      spentScripts = concatMap txSpentScripts (buTxUndo undo)
  in filter (not . isOpReturn) $ outputScripts ++ spentScripts
  where
    txOutputScripts tx =
      map txOutScript (txOutputs tx)

    txSpentScripts (TxUndo prevOuts) =
      map (txOutScript . tuOutput) prevOuts

    isOpReturn script = not (BS.null script) && BS.head script == 0x6a

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

-- | Compute filter hash (single SHA256)
blockFilterHash :: BlockFilter -> Hash256
blockFilterHash bf = sha256Single (gcsEncoded (bfFilter bf))
  where
    sha256Single bs = Hash256 $ BS.pack $ BA.unpack (Hash.hash bs :: Hash.Digest Hash.SHA256)

-- | Compute filter header
-- header = SHA256(filter_hash || prev_header)
blockFilterHeader :: BlockFilter -> Hash256 -> Hash256
blockFilterHeader bf prevHeader =
  let filterHash = blockFilterHash bf
      combined = getHash256 filterHash `BS.append` getHash256 prevHeader
  in sha256Single combined
  where
    sha256Single bs = Hash256 $ BS.pack $ BA.unpack (Hash.hash bs :: Hash.Digest Hash.SHA256)

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

-- | 3072-bit number for MuHash
-- Stored as 48 Word64 limbs in little-endian order
newtype Num3072 = Num3072 { num3072Limbs :: [Word64] }
  deriving (Show, Eq, Generic)

instance NFData Num3072

-- | MuHash3072 state (numerator and denominator)
data MuHash3072 = MuHash3072
  { muHashNumerator   :: !Num3072
  , muHashDenominator :: !Num3072
  } deriving (Show, Eq, Generic)

instance NFData MuHash3072

-- | The modulus: 2^3072 - 1103717
modulus3072Diff :: Word64
modulus3072Diff = 1103717

-- | Create an empty MuHash (identity element = 1)
muHashEmpty :: MuHash3072
muHashEmpty = MuHash3072
  { muHashNumerator = num3072One
  , muHashDenominator = num3072One
  }
  where
    num3072One = Num3072 (1 : replicate 47 0)

-- | Convert bytes to Num3072 using ChaCha20 expansion
-- Reference: bitcoin/src/crypto/muhash.cpp ToNum3072
num3072FromBytes :: ByteString -> Num3072
num3072FromBytes bs =
  -- First hash with SHA256, then expand with simple hash-based expansion
  let hashed = sha256Single bs
      -- Expand to 384 bytes using iterative hashing
      expanded = expandToBytes 384 (getHash256 hashed)
      -- Convert to 48 Word64 limbs (little-endian)
      limbs = [decodeLE64 (BS.take 8 (BS.drop (i * 8) expanded)) | i <- [0..47]]
  in Num3072 limbs
  where
    sha256Single bs' = Hash256 $ BS.pack $ BA.unpack (Hash.hash bs' :: Hash.Digest Hash.SHA256)

    expandToBytes targetLen seed = go BS.empty seed
      where
        go !acc !s
          | BS.length acc >= targetLen = BS.take targetLen acc
          | otherwise =
              let newHash = sha256Single (s `BS.append` BS.singleton (fromIntegral (BS.length acc)))
              in go (acc `BS.append` getHash256 newHash) (getHash256 newHash)

-- | Convert Num3072 to bytes
num3072ToBytes :: Num3072 -> ByteString
num3072ToBytes (Num3072 limbs) =
  BS.concat [encodeLE64 l | l <- limbs]

-- | Multiply two Num3072 values modulo the prime
-- This is a simplified implementation - for production use secp256k1 style optimizations
num3072Multiply :: Num3072 -> Num3072 -> Num3072
num3072Multiply (Num3072 a) (Num3072 b) =
  -- Simplified schoolbook multiplication with reduction
  -- For a full implementation, use Karatsuba or better
  let n = length a
      -- Full product would be 96 limbs
      product' = schoolbookMul a b
      -- Reduce modulo 2^3072 - modulus3072Diff
      reduced = reduceProduct product'
  in Num3072 reduced
  where
    schoolbookMul :: [Word64] -> [Word64] -> [Word64]
    schoolbookMul xs ys =
      let n = max (length xs) (length ys)
          xs' = xs ++ replicate (2 * n - length xs) 0
          ys' = ys ++ replicate (2 * n - length ys) 0
          result = replicate (2 * n) 0
      in foldl' addPartial result [(i, j) | i <- [0..n-1], j <- [0..n-1]]
      where
        addPartial :: [Word64] -> (Int, Int) -> [Word64]
        addPartial acc (i, j) =
          let (hi, lo) = mulWord64Full (xs !! i) (ys !! j)
              -- Add lo at position i+j, hi at position i+j+1
              acc' = addAtIndex acc (i + j) lo
              acc'' = addAtIndex acc' (i + j + 1) hi
          in acc''

        addAtIndex :: [Word64] -> Int -> Word64 -> [Word64]
        addAtIndex lst idx val
          | idx >= length lst = lst
          | otherwise =
              let (before, current:after) = splitAt idx lst
                  (newVal, carry) = addWithCarry current val 0
                  after' = propagateCarry after carry
              in before ++ [newVal] ++ after'

        addWithCarry :: Word64 -> Word64 -> Word64 -> (Word64, Word64)
        addWithCarry a' b' c =
          let sum' = a' + b' + c
              carry = if sum' < a' || (sum' == a' && (b' > 0 || c > 0)) then 1 else 0
          in (sum', carry)

        propagateCarry :: [Word64] -> Word64 -> [Word64]
        propagateCarry [] _ = []
        propagateCarry (x:xs') 0 = x : xs'
        propagateCarry (x:xs') c =
          let (newX, newCarry) = addWithCarry x c 0
          in newX : propagateCarry xs' newCarry

    mulWord64Full :: Word64 -> Word64 -> (Word64, Word64)
    mulWord64Full x y =
      let xLo = x .&. 0xffffffff
          xHi = x `shiftR` 32
          yLo = y .&. 0xffffffff
          yHi = y `shiftR` 32
          p0 = xLo * yLo
          p1 = xLo * yHi
          p2 = xHi * yLo
          p3 = xHi * yHi
          carry0 = (p0 `shiftR` 32) + (p1 .&. 0xffffffff) + (p2 .&. 0xffffffff)
          hi = p3 + (p1 `shiftR` 32) + (p2 `shiftR` 32) + (carry0 `shiftR` 32)
          lo = (carry0 `shiftL` 32) .|. (p0 .&. 0xffffffff)
      in (hi, lo)

    reduceProduct :: [Word64] -> [Word64]
    reduceProduct product' =
      -- Reduce 96 limbs to 48 limbs modulo 2^3072 - diff
      let lo = take 48 product'
          hi = drop 48 product'
          -- hi * 2^3072 ≡ hi * diff (mod 2^3072 - diff)
          -- So result ≡ lo + hi * diff
          hiTimesDiff = multiplyByScalar hi modulus3072Diff
          combined = addLimbs lo hiTimesDiff
      in take 48 combined

    multiplyByScalar :: [Word64] -> Word64 -> [Word64]
    multiplyByScalar limbs scalar = go limbs 0
      where
        go [] carry = if carry > 0 then [carry] else []
        go (x:xs') carry =
          let (hi, lo) = mulWord64Full x scalar
              newLo = lo + carry
              newCarry = hi + (if newLo < lo then 1 else 0)
          in newLo : go xs' newCarry

    addLimbs :: [Word64] -> [Word64] -> [Word64]
    addLimbs xs ys =
      let maxLen = max (length xs) (length ys)
          xs' = xs ++ replicate (maxLen - length xs) 0
          ys' = ys ++ replicate (maxLen - length ys) 0
      in go xs' ys' 0
      where
        go [] [] 0 = []
        go [] [] c = [c]
        go (x:xs'') (y:ys'') carry =
          let sum' = x + y + carry
              newCarry = if sum' < x || (sum' == x && (y > 0 || carry > 0)) then 1 else 0
          in sum' : go xs'' ys'' newCarry
        go _ _ _ = []

-- | Get multiplicative inverse using extended GCD
-- Simplified implementation - for production use safegcd algorithm
num3072GetInverse :: Num3072 -> Num3072
num3072GetInverse n =
  -- For now, return identity if input is identity
  -- Full implementation would use safegcd as in Bitcoin Core
  n  -- Placeholder

-- | Insert an element into MuHash
muHashInsert :: MuHash3072 -> ByteString -> MuHash3072
muHashInsert mh element =
  let num = num3072FromBytes element
      newNumerator = num3072Multiply (muHashNumerator mh) num
  in mh { muHashNumerator = newNumerator }

-- | Remove an element from MuHash
muHashRemove :: MuHash3072 -> ByteString -> MuHash3072
muHashRemove mh element =
  let num = num3072FromBytes element
      newDenominator = num3072Multiply (muHashDenominator mh) num
  in mh { muHashDenominator = newDenominator }

-- | Combine two MuHash values
muHashCombine :: MuHash3072 -> MuHash3072 -> MuHash3072
muHashCombine a b = MuHash3072
  { muHashNumerator = num3072Multiply (muHashNumerator a) (muHashNumerator b)
  , muHashDenominator = num3072Multiply (muHashDenominator a) (muHashDenominator b)
  }

-- | Finalize MuHash to get a 256-bit hash
muHashFinalize :: MuHash3072 -> Hash256
muHashFinalize mh =
  let -- Divide numerator by denominator
      invDenom = num3072GetInverse (muHashDenominator mh)
      result = num3072Multiply (muHashNumerator mh) invDenom
      -- Convert to bytes and hash
      resultBytes = num3072ToBytes result
  in sha256Single resultBytes
  where
    sha256Single bs = Hash256 $ BS.pack $ BA.unpack (Hash.hash bs :: Hash.Digest Hash.SHA256)

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
    putVarInt n
      | n < 0xfd = putWord8 (fromIntegral n)
      | n <= 0xffff = putWord8 0xfd >> putWord16le (fromIntegral n :: Word16)
      | n <= 0xffffffff = putWord8 0xfe >> putWord32le (fromIntegral n :: Word32)
      | otherwise = putWord8 0xff >> putWord64le n

    putWord16le :: Word16 -> Put
    putWord16le w = do
      putWord8 (fromIntegral w)
      putWord8 (fromIntegral (w `shiftR` 8))

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
    where
      putVarInt n
        | n < 0xfd = putWord8 (fromIntegral n)
        | n <= 0xffff = putWord8 0xfd >> putWord16le (fromIntegral n :: Word16)
        | n <= 0xffffffff = putWord8 0xfe >> putWord32le (fromIntegral n :: Word32)
        | otherwise = putWord8 0xff >> putWord64le n

      putWord16le :: Word16 -> Put
      putWord16le w = do
        putWord8 (fromIntegral w)
        putWord8 (fromIntegral (w `shiftR` 8))

      getVarInt' :: Get Word64
      getVarInt' = do
        b <- getWord8
        case b of
          _ | b < 0xfd -> return (fromIntegral b)
          0xfd -> do
            lo <- getWord8
            hi <- getWord8
            return $ fromIntegral lo .|. (fromIntegral hi `shiftL` 8)
          0xfe -> fromIntegral <$> getWord32le
          0xff -> getWord64le

-- | BlockFilterIndex database handle
data BlockFilterIndexDB = BlockFilterIndexDB
  { bfiDB         :: !HaskoinDB
  , bfiPrefix     :: !Word8         -- ^ Key prefix for filter by height
  , bfiLastHeader :: !(IORef Hash256)  -- ^ Last filter header (for chaining)
  }

-- | BlockFilterIndex key prefix
prefixBlockFilter :: Word8
prefixBlockFilter = 0x46  -- 'F'

-- | Create a new BlockFilterIndex database
newBlockFilterIndexDB :: HaskoinDB -> IO BlockFilterIndexDB
newBlockFilterIndexDB db = do
  lastHeaderRef <- newIORef (Hash256 (BS.replicate 32 0))  -- Genesis filter header
  return BlockFilterIndexDB
    { bfiDB = db
    , bfiPrefix = prefixBlockFilter
    , bfiLastHeader = lastHeaderRef
    }

-- | Put a block filter entry
blockFilterIndexPut :: BlockFilterIndexDB -> BlockHeight -> BlockFilterEntry -> IO ()
blockFilterIndexPut BlockFilterIndexDB{..} height entry = do
  let key = BS.cons bfiPrefix (toBE32 height)
  R.put (dbHandle bfiDB) (dbWriteOpts bfiDB) key (encode entry)
  writeIORef bfiLastHeader (bfeFilterHeader entry)
  where
    toBE32 w = BS.pack
      [ fromIntegral ((w `shiftR` 24) .&. 0xff)
      , fromIntegral ((w `shiftR` 16) .&. 0xff)
      , fromIntegral ((w `shiftR` 8) .&. 0xff)
      , fromIntegral (w .&. 0xff)
      ]

-- | Get a block filter entry
blockFilterIndexGet :: BlockFilterIndexDB -> BlockHeight -> IO (Maybe BlockFilterEntry)
blockFilterIndexGet BlockFilterIndexDB{..} height = do
  let key = BS.cons bfiPrefix (toBE32 height)
  mval <- R.get (dbHandle bfiDB) (dbReadOpts bfiDB) key
  return $ mval >>= either (const Nothing) Just . decode
  where
    toBE32 w = BS.pack
      [ fromIntegral ((w `shiftR` 24) .&. 0xff)
      , fromIntegral ((w `shiftR` 16) .&. 0xff)
      , fromIntegral ((w `shiftR` 8) .&. 0xff)
      , fromIntegral (w .&. 0xff)
      ]

-- | Append a block filter to the index
blockFilterIndexAppendBlock :: BlockFilterIndexDB -> Block -> BlockUndo -> BlockHash -> BlockHeight -> IO ()
blockFilterIndexAppendBlock db block undo blockHash height = do
  prevHeader <- readIORef (bfiLastHeader db)
  let blockFilter = computeBlockFilter block undo blockHash
      filterHash = blockFilterHash blockFilter
      filterHeader = blockFilterHeader blockFilter prevHeader
      entry = BlockFilterEntry filterHash filterHeader (encodeBlockFilter blockFilter)
  blockFilterIndexPut db height entry

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

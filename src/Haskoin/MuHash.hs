{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | MuHash3072: a multiset hash for the UTXO set.
--
-- Reference: bitcoin-core/src/crypto/muhash.{h,cpp}.
--
-- This is a clean, byte-compatible Haskell port. The Core C++ implementation
-- represents Num3072 as 48 little-endian limbs and hand-rolls modular
-- multiplication, full reduction, and a safegcd-based modular inverse for
-- speed. We instead lean on GHC's GMP-backed 'Integer' (unlimited precision)
-- — modular multiply is one '*' + 'mod', and modular inverse is a one-shot
-- extended-Euclidean. The byte layouts (input/output) and the ChaCha20-based
-- 'toNum3072' element expansion exactly match Core, so finalised hashes are
-- byte-identical.
--
-- See 'bitcoin-core/src/test/crypto_tests.cpp' BOOST_AUTO_TEST_CASE(muhash_tests)
-- for the canonical test vectors used in 'test/Spec.hs'.
module Haskoin.MuHash
  ( -- * Num3072
    Num3072(..)
  , num3072One
  , num3072FromBytes
  , num3072ToBytes
  , num3072Multiply
  , num3072Divide
  , num3072GetInverse
  , num3072Modulus
  , num3072ByteSize
    -- * MuHash3072
  , MuHash3072(..)
  , muHashEmpty
  , muHashFromBytes
  , muHashInsert
  , muHashRemove
  , muHashCombine
  , muHashDivide
  , muHashFinalize
  , muHashToNum3072
    -- * Serialization (768-byte numerator || 768-byte denominator)
  , muHashSerialize
  , muHashDeserialize
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteArray as BA
import qualified Crypto.Hash as H
import qualified Crypto.Cipher.ChaCha as ChaCha
import GHC.Generics (Generic)
import Control.DeepSeq (NFData(..))
import Data.Bits (shiftR, shiftL, (.&.), (.|.))
import Data.Word (Word8)

import Haskoin.Types (Hash256(..))

--------------------------------------------------------------------------------
-- Num3072
--------------------------------------------------------------------------------

-- | A 3072-bit unsigned integer in @[0, 2^3072)@. The on-wire encoding is
-- 384 bytes, little-endian.
--
-- Internally we store the value as a Haskell 'Integer'. Operations are
-- always reduced modulo the MuHash3072 modulus, which is the largest
-- 3072-bit safe prime: @2^3072 - 1103717@.
newtype Num3072 = Num3072 { num3072Value :: Integer }
  deriving (Show, Eq, Generic)

instance NFData Num3072 where
  rnf (Num3072 !_) = ()

-- | Size of a 'Num3072' in bytes (Core: @Num3072::BYTE_SIZE@).
num3072ByteSize :: Int
num3072ByteSize = 384

-- | The MuHash3072 modulus: @2^3072 - 1103717@.
-- Reference: muhash.cpp @MAX_PRIME_DIFF = 1103717@.
num3072Modulus :: Integer
num3072Modulus = (1 `shiftL` 3072) - 1103717

-- | Multiplicative identity in Num3072.
num3072One :: Num3072
num3072One = Num3072 1

-- | Decode a 'Num3072' from 384 little-endian bytes.
-- This matches Core's @Num3072(const unsigned char (&data)[BYTE_SIZE])@,
-- which fills 48 LE64 limbs in order. We treat the whole buffer as one
-- 3072-bit little-endian number, which is the same value semantically.
-- Note: the input may exceed the modulus; we reduce.
num3072FromBytes :: ByteString -> Num3072
num3072FromBytes bs
  | BS.length bs /= num3072ByteSize =
      error $ "num3072FromBytes: expected " ++ show num3072ByteSize
              ++ " bytes, got " ++ show (BS.length bs)
  | otherwise =
      let !n = leBytesToInteger bs
      in Num3072 (n `mod` num3072Modulus)

-- | Encode a 'Num3072' as exactly 384 little-endian bytes.
num3072ToBytes :: Num3072 -> ByteString
num3072ToBytes (Num3072 v) =
  -- Reduce defensively, then pad to BYTE_SIZE.
  integerToLEBytes num3072ByteSize (v `mod` num3072Modulus)

-- | Modular multiplication in @Z / (2^3072 - 1103717) Z@.
num3072Multiply :: Num3072 -> Num3072 -> Num3072
num3072Multiply (Num3072 a) (Num3072 b) =
  Num3072 ((a * b) `mod` num3072Modulus)

-- | Modular inverse via extended Euclidean. The modulus is a safe prime,
-- so every nonzero element has an inverse. 'num3072GetInverse' on the
-- multiplicative identity returns the identity; on zero it raises.
--
-- Reference: muhash.cpp @Num3072::GetInverse@ (safegcd implementation).
-- Our extended-Euclidean runs in O(n^2) on n=3072 bits; this is fine
-- for a single call per Finalize, which is the only place inverse is
-- needed.
num3072GetInverse :: Num3072 -> Num3072
num3072GetInverse (Num3072 a) =
  let r = a `mod` num3072Modulus
  in if r == 0
        then error "num3072GetInverse: zero has no inverse"
        else Num3072 (modInverse r num3072Modulus)

-- | Modular division: @a / b = a * b^{-1}@.
num3072Divide :: Num3072 -> Num3072 -> Num3072
num3072Divide a b = num3072Multiply a (num3072GetInverse b)

--------------------------------------------------------------------------------
-- MuHash3072
--------------------------------------------------------------------------------

-- | A MuHash3072 accumulator. Set elements multiply into 'muHashNumerator';
-- removed elements multiply into 'muHashDenominator'. On 'muHashFinalize',
-- @numerator / denominator@ is computed and SHA256'd to a 32-byte digest.
--
-- Reference: bitcoin-core/src/crypto/muhash.h class @MuHash3072@.
data MuHash3072 = MuHash3072
  { muHashNumerator   :: !Num3072
  , muHashDenominator :: !Num3072
  } deriving (Show, Eq, Generic)

instance NFData MuHash3072

-- | The empty multiset. Both numerator and denominator are 1.
muHashEmpty :: MuHash3072
muHashEmpty = MuHash3072 num3072One num3072One

-- | Singleton MuHash containing one element. Equivalent to
-- @muHashInsert muHashEmpty@.
muHashFromBytes :: ByteString -> MuHash3072
muHashFromBytes bs =
  MuHash3072 (muHashToNum3072 bs) num3072One

-- | Multiply an element into the set's numerator.
muHashInsert :: MuHash3072 -> ByteString -> MuHash3072
muHashInsert mh bs =
  mh { muHashNumerator = num3072Multiply (muHashNumerator mh) (muHashToNum3072 bs) }

-- | Multiply an element into the set's denominator (i.e. remove it).
muHashRemove :: MuHash3072 -> ByteString -> MuHash3072
muHashRemove mh bs =
  mh { muHashDenominator = num3072Multiply (muHashDenominator mh) (muHashToNum3072 bs) }

-- | Multiply two MuHash accumulators (union). Pointwise multiply both
-- numerator and denominator.
muHashCombine :: MuHash3072 -> MuHash3072 -> MuHash3072
muHashCombine a b = MuHash3072
  { muHashNumerator   = num3072Multiply (muHashNumerator a)   (muHashNumerator b)
  , muHashDenominator = num3072Multiply (muHashDenominator a) (muHashDenominator b)
  }

-- | Set difference: @a / b@. Numerator gets b's denominator and vice versa.
muHashDivide :: MuHash3072 -> MuHash3072 -> MuHash3072
muHashDivide a b = MuHash3072
  { muHashNumerator   = num3072Multiply (muHashNumerator a)   (muHashDenominator b)
  , muHashDenominator = num3072Multiply (muHashDenominator a) (muHashNumerator b)
  }

-- | Finalize: divide, serialize to 384 LE bytes, SHA256 to a 32-byte hash.
-- Reference: muhash.cpp @MuHash3072::Finalize@.
muHashFinalize :: MuHash3072 -> Hash256
muHashFinalize mh =
  let !combined = num3072Divide (muHashNumerator mh) (muHashDenominator mh)
      !raw      = num3072ToBytes combined
  in Hash256 (sha256Bytes raw)

-- | Convert an arbitrary-length input into a 'Num3072' element by:
--   1. SHA256(input)  -> 32-byte key
--   2. ChaCha20 keystream of 384 bytes (key=hash, nonce=zeros, counter=0)
--   3. Interpret the keystream as a 3072-bit little-endian integer.
--
-- Matches @MuHash3072::ToNum3072@ exactly. The Bitcoin Core code uses
-- @ChaCha20Aligned{key}.Keystream(out)@, which initialises with all-zero
-- nonce and block counter — the same starting state as cryptonite's
-- @ChaCha.initialize 20 key nonce@ when @nonce = 12 bytes of zero@.
muHashToNum3072 :: ByteString -> Num3072
muHashToNum3072 input =
  let !keyBs       = sha256Bytes input
      !nonce       = BS.replicate 12 0
      !chaState    = ChaCha.initialize 20 keyBs nonce
      !(stream, _) = ChaCha.combine chaState (BS.replicate num3072ByteSize 0)
  in num3072FromBytes stream

--------------------------------------------------------------------------------
-- MuHash3072 serialization (Core wire format)
--------------------------------------------------------------------------------

-- | Encode a MuHash as @numerator || denominator@, each 384 LE bytes.
-- Matches Core's @SERIALIZE_METHODS(MuHash3072, obj)@ which streams the
-- two Num3072s back to back.
muHashSerialize :: MuHash3072 -> ByteString
muHashSerialize (MuHash3072 n d) =
  num3072ToBytes n `BS.append` num3072ToBytes d

-- | Decode a MuHash from @numerator || denominator@. Returns 'Left' on
-- length mismatch.
muHashDeserialize :: ByteString -> Either String MuHash3072
muHashDeserialize bs
  | BS.length bs /= 2 * num3072ByteSize =
      Left $ "muHashDeserialize: expected "
             ++ show (2 * num3072ByteSize) ++ " bytes, got "
             ++ show (BS.length bs)
  | otherwise =
      let (nb, db) = BS.splitAt num3072ByteSize bs
      in Right (MuHash3072 (num3072FromBytes nb) (num3072FromBytes db))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Decode a little-endian byte string as a non-negative 'Integer'.
leBytesToInteger :: ByteString -> Integer
leBytesToInteger = BS.foldr step 0
  where
    -- foldr from the right walks bytes from highest index to lowest; we
    -- accumulate by left-shifting the in-progress integer 8 bits and OR'ing
    -- in the current byte. With foldr that's "(byte) | (acc << 8)".
    step :: Word8 -> Integer -> Integer
    step b !acc = (acc `shiftL` 8) .|. fromIntegral b

-- | Encode a non-negative 'Integer' as a little-endian byte string of
-- exactly @n@ bytes. The integer must fit (i.e. @< 256^n@); we mask
-- defensively if it doesn't.
integerToLEBytes :: Int -> Integer -> ByteString
integerToLEBytes n0 v0 = BS.pack (go n0 v0)
  where
    go 0 _ = []
    go n v = fromIntegral (v .&. 0xff) : go (n - 1) (v `shiftR` 8)

-- | Standard SHA-256 (single round), returning the 32-byte digest.
sha256Bytes :: ByteString -> ByteString
sha256Bytes bs = BS.pack (BA.unpack (H.hash bs :: H.Digest H.SHA256))

-- | Compute @a^{-1} mod m@ via extended Euclidean. Assumes @gcd a m = 1@
-- (true here because @m@ is prime and @0 < a < m@).
modInverse :: Integer -> Integer -> Integer
modInverse a m =
  let (g, x, _) = extEuclid a m
  in if g /= 1
        then error "modInverse: not coprime (modulus must be prime)"
        else x `mod` m

-- | Extended Euclidean algorithm. Returns @(g, x, y)@ such that
-- @a*x + b*y = g = gcd(a, b)@.
extEuclid :: Integer -> Integer -> (Integer, Integer, Integer)
extEuclid 0 b = (b, 0, 1)
extEuclid a b =
  let (q, r)        = b `divMod` a
      (g, x1, y1)   = extEuclid r a
  in (g, y1 - q * x1, x1)

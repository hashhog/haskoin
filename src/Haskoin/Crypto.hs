{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

module Haskoin.Crypto
  ( -- * Hashing
    sha256
  , doubleSHA256
  , ripemd160
  , hash160
  , hash256
  , hmacSHA512
    -- * Keys
  , SecKey(..)
  , PubKey(..)
  , derivePubKey
  , serializePubKeyCompressed
  , serializePubKeyUncompressed
  , parsePubKey
    -- * Signatures
  , Sig(..)
  , signMsg
  , verifyMsg
  , serializeSigDER
  , parseSigDER
    -- * Sighash
  , SigHashType(..)
  , sigHashAll
  , sigHashNone
  , sigHashSingle
  , sigHashAnyoneCanPay
  , sigHashTypeToWord32
  , txSigHash
  , txSigHashSegWit
    -- * Transaction/Block hashing
  , computeTxId
  , computeBlockHash
  ) where

import qualified Crypto.Hash as H
import qualified Crypto.MAC.HMAC as HMAC
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (Serialize(..), Put, runPut, putWord32le, putWord64le,
                       putByteString, encode)
import Data.Word (Word32, Word64)
import Data.Bits ((.|.), testBit)
import GHC.Generics (Generic)

import Haskoin.Types (Hash256(..), Hash160(..), TxId(..), BlockHash(..),
                      Tx(..), TxIn(..), TxOut(..), BlockHeader(..), OutPoint(..),
                      putVarInt, putVarBytes)

--------------------------------------------------------------------------------
-- Hashing Functions
--------------------------------------------------------------------------------

-- | SHA-256 hash
sha256 :: ByteString -> ByteString
sha256 bs = convert (H.hashWith H.SHA256 bs)

-- | Double SHA-256 hash (SHA256(SHA256(data)))
doubleSHA256 :: ByteString -> Hash256
doubleSHA256 bs = Hash256 (sha256 (sha256 bs))

-- | RIPEMD-160 hash
ripemd160 :: ByteString -> ByteString
ripemd160 bs = convert (H.hashWith H.RIPEMD160 bs)

-- | HASH160: RIPEMD160(SHA256(data)), used for Bitcoin addresses
hash160 :: ByteString -> Hash160
hash160 bs = Hash160 (ripemd160 (sha256 bs))

-- | Alias for doubleSHA256
hash256 :: ByteString -> Hash256
hash256 = doubleSHA256

-- | HMAC-SHA512, used for BIP-32 key derivation
hmacSHA512 :: ByteString -> ByteString -> ByteString
hmacSHA512 key msg = convert (HMAC.hmacGetDigest hmacResult)
  where
    hmacResult :: HMAC.HMAC H.SHA512
    hmacResult = HMAC.hmac key msg

--------------------------------------------------------------------------------
-- Key Types
--------------------------------------------------------------------------------

-- | Secret (private) key: 32 bytes
newtype SecKey = SecKey { getSecKey :: ByteString }
  deriving (Show, Eq, Generic)

-- | Public key: compressed (33 bytes) or uncompressed (65 bytes)
data PubKey
  = PubKeyCompressed !ByteString     -- 33 bytes: 0x02/0x03 + x
  | PubKeyUncompressed !ByteString   -- 65 bytes: 0x04 + x + y
  deriving (Show, Eq, Generic)

-- | Derive public key from secret key
-- Uses secp256k1 curve: y^2 = x^3 + 7 (mod p)
-- p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
-- This is a placeholder - requires secp256k1 FFI for production use
derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey _sk) =
  error "derivePubKey: requires secp256k1 FFI or pure implementation"

-- | Serialize public key in compressed format (33 bytes)
serializePubKeyCompressed :: PubKey -> ByteString
serializePubKeyCompressed (PubKeyCompressed bs) = bs
serializePubKeyCompressed (PubKeyUncompressed bs) =
  -- Compress: take x-coordinate, prefix with 0x02 or 0x03 based on y parity
  let x = BS.take 32 (BS.drop 1 bs)
      y = BS.take 32 (BS.drop 33 bs)
      prefix = if BS.last y `testBit` 0 then 0x03 else 0x02
  in BS.cons prefix x

-- | Serialize public key in uncompressed format (65 bytes)
serializePubKeyUncompressed :: PubKey -> ByteString
serializePubKeyUncompressed (PubKeyUncompressed bs) = bs
serializePubKeyUncompressed (PubKeyCompressed _) =
  error "serializePubKeyUncompressed: cannot decompress without curve operations"

-- | Parse a public key from bytes
parsePubKey :: ByteString -> Maybe PubKey
parsePubKey bs
  | BS.length bs == 33 && (BS.head bs == 0x02 || BS.head bs == 0x03) =
      Just (PubKeyCompressed bs)
  | BS.length bs == 65 && BS.head bs == 0x04 =
      Just (PubKeyUncompressed bs)
  | otherwise = Nothing

--------------------------------------------------------------------------------
-- Signature Types
--------------------------------------------------------------------------------

-- | DER-encoded ECDSA signature
newtype Sig = Sig { getSigBytes :: ByteString }
  deriving (Show, Eq, Generic)

-- | Sign a message hash with a secret key
-- Placeholder - requires secp256k1 FFI for production use
signMsg :: SecKey -> Hash256 -> Sig
signMsg _sk _hash = error "signMsg: requires secp256k1 FFI"

-- | Verify a signature against a public key and message hash
-- Placeholder - requires secp256k1 FFI for production use
verifyMsg :: PubKey -> Sig -> Hash256 -> Bool
verifyMsg _pk _sig _hash = error "verifyMsg: requires secp256k1 FFI"

-- | Serialize signature in DER format
serializeSigDER :: Sig -> ByteString
serializeSigDER (Sig bs) = bs

-- | Parse a DER-encoded signature
parseSigDER :: ByteString -> Maybe Sig
parseSigDER bs
  | BS.length bs >= 8 && BS.head bs == 0x30 = Just (Sig bs)
  | otherwise = Nothing

--------------------------------------------------------------------------------
-- Sighash Types
--------------------------------------------------------------------------------

-- | Sighash type flags for transaction signing
data SigHashType = SigHashType
  { shAll          :: !Bool
  , shNone         :: !Bool
  , shSingle       :: !Bool
  , shAnyoneCanPay :: !Bool
  } deriving (Show, Eq, Generic)

-- | SIGHASH_ALL: sign all inputs and outputs
sigHashAll :: SigHashType
sigHashAll = SigHashType True False False False

-- | SIGHASH_NONE: sign all inputs, no outputs
sigHashNone :: SigHashType
sigHashNone = SigHashType False True False False

-- | SIGHASH_SINGLE: sign all inputs, only the output at same index
sigHashSingle :: SigHashType
sigHashSingle = SigHashType False False True False

-- | Add ANYONECANPAY flag: only sign the current input
sigHashAnyoneCanPay :: SigHashType -> SigHashType
sigHashAnyoneCanPay sh = sh { shAnyoneCanPay = True }

-- | Convert SigHashType to its wire format (Word32)
sigHashTypeToWord32 :: SigHashType -> Word32
sigHashTypeToWord32 sh =
  let base | shNone sh   = 0x02
           | shSingle sh = 0x03
           | otherwise   = 0x01  -- SIGHASH_ALL
      acp  = if shAnyoneCanPay sh then 0x80 else 0x00
  in base .|. acp

--------------------------------------------------------------------------------
-- Sighash Computation
--------------------------------------------------------------------------------

-- | Compute legacy sighash for transaction signing
-- Serializes the transaction with script in signing input, then double-SHA256
txSigHash :: Tx -> Int -> ByteString -> SigHashType -> Hash256
txSigHash tx inputIdx subScript shType =
  let hashTypeW32 = sigHashTypeToWord32 shType
      -- Clear all input scripts, set signing input's script to subscript
      inputs' = zipWith (\i inp ->
        if i == inputIdx
          then inp { txInScript = subScript }
          else inp { txInScript = BS.empty }
        ) [0..] (txInputs tx)
      -- Handle SIGHASH_NONE and SIGHASH_SINGLE output modifications
      outputs' = case () of
        _ | shNone shType -> []
          | shSingle shType && inputIdx < length (txOutputs tx) ->
              replicate inputIdx (TxOut 0xffffffffffffffff BS.empty)
              ++ [txOutputs tx !! inputIdx]
          | shSingle shType -> []  -- inputIdx >= length outputs, return empty
          | otherwise -> txOutputs tx
      -- Handle sequence modifications for SIGHASH_NONE and SIGHASH_SINGLE
      inputs'' = if shNone shType || shSingle shType
        then zipWith (\i inp ->
          if i == inputIdx
            then inp
            else inp { txInSequence = 0 }
          ) [0..] inputs'
        else inputs'
      -- Handle ANYONECANPAY: only include the signing input
      finalInputs = if shAnyoneCanPay shType
        then [inputs'' !! inputIdx]
        else inputs''
      modifiedTx = runPut $ do
        putWord32le (fromIntegral $ txVersion tx)
        putVarInt (fromIntegral $ length finalInputs)
        mapM_ putTxIn finalInputs
        putVarInt (fromIntegral $ length outputs')
        mapM_ putTxOut outputs'
        putWord32le (txLockTime tx)
        putWord32le hashTypeW32
  in doubleSHA256 modifiedTx

-- | BIP-143 SegWit sighash computation
-- Fixes quadratic hashing by pre-computing hash of prevouts, sequences, outputs
txSigHashSegWit :: Tx -> Int -> ByteString -> Word64 -> SigHashType -> Hash256
txSigHashSegWit tx inputIdx scriptCode amount shType =
  let hashTypeW32 = sigHashTypeToWord32 shType
      -- Hash of all prevouts (unless ANYONECANPAY)
      hashPrevouts = if shAnyoneCanPay shType
        then Hash256 (BS.replicate 32 0)
        else doubleSHA256 $ runPut $ mapM_ (putOutPoint . txInPrevOutput) (txInputs tx)
      -- Hash of all sequences (unless ANYONECANPAY, SINGLE, or NONE)
      hashSequence = if shAnyoneCanPay shType || shSingle shType || shNone shType
        then Hash256 (BS.replicate 32 0)
        else doubleSHA256 $ runPut $ mapM_ (putWord32le . txInSequence) (txInputs tx)
      -- Hash of all outputs (with modifications for SINGLE/NONE)
      hashOutputs
        | shSingle shType && inputIdx < length (txOutputs tx) =
            doubleSHA256 $ encode (txOutputs tx !! inputIdx)
        | shNone shType || shSingle shType =
            Hash256 (BS.replicate 32 0)
        | otherwise =
            doubleSHA256 $ runPut $ mapM_ putTxOut (txOutputs tx)
      inp = txInputs tx !! inputIdx
      preimage = runPut $ do
        putWord32le (fromIntegral $ txVersion tx)
        putByteString (getHash256 hashPrevouts)
        putByteString (getHash256 hashSequence)
        putOutPoint (txInPrevOutput inp)
        putVarBytes scriptCode
        putWord64le amount
        putWord32le (txInSequence inp)
        putByteString (getHash256 hashOutputs)
        putWord32le (txLockTime tx)
        putWord32le hashTypeW32
  in doubleSHA256 preimage

--------------------------------------------------------------------------------
-- Transaction/Block Hash Computation
--------------------------------------------------------------------------------

-- | Compute the transaction ID (hash of non-witness serialization)
computeTxId :: Tx -> TxId
computeTxId tx = TxId $ doubleSHA256 $ runPut $ do
  putWord32le (fromIntegral $ txVersion tx)
  putVarInt (fromIntegral $ length $ txInputs tx)
  mapM_ putTxIn (txInputs tx)
  putVarInt (fromIntegral $ length $ txOutputs tx)
  mapM_ putTxOut (txOutputs tx)
  putWord32le (txLockTime tx)

-- | Compute the block hash (hash of 80-byte header)
computeBlockHash :: BlockHeader -> BlockHash
computeBlockHash hdr = BlockHash $ doubleSHA256 (encode hdr)

--------------------------------------------------------------------------------
-- Internal Serialization Helpers
--------------------------------------------------------------------------------

-- | Serialize a TxIn (for sighash computation)
putTxIn :: TxIn -> Put
putTxIn TxIn{..} = do
  putOutPoint txInPrevOutput
  putVarBytes txInScript
  putWord32le txInSequence

-- | Serialize a TxOut
putTxOut :: TxOut -> Put
putTxOut TxOut{..} = do
  putWord64le txOutValue
  putVarBytes txOutScript

-- | Serialize an OutPoint
putOutPoint :: OutPoint -> Put
putOutPoint OutPoint{..} = do
  putByteString (getHash256 $ getTxIdHash outPointHash)
  putWord32le outPointIndex

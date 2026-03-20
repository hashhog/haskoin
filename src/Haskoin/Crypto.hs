{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Haskoin.Crypto
  ( -- * Hashing
    sha256
  , sha1
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
  , verifyMsgLax
  , serializeSigDER
  , parseSigDER
  , isValidDERSignature
  , isDefinedSigHashType
  , isLowDERSignature
    -- * Sighash
  , SigHashType(..)
  , sigHashAll
  , sigHashNone
  , sigHashSingle
  , sigHashAnyoneCanPay
  , sigHashTypeToWord32
  , txSigHash
  , txSigHashSegWit
    -- * Legacy sighash helpers
  , findAndDelete
  , removeCodeSeparators
  , scriptCodeForSighash
  , encodePushData
    -- * Transaction/Block hashing
  , computeTxId
  , computeBlockHash
    -- * Addresses
  , Address(..)
  , addressToText
  , textToAddress
  , pubKeyToP2PKH
  , pubKeyToP2WPKH
  , scriptToP2SH
  , scriptToP2WSH
    -- * Address encoding
  , base58Check
  , base58CheckDecode
  , bech32Encode
  , bech32Decode
  , bech32mEncode
  ) where

import qualified Crypto.Hash as H
import qualified Crypto.MAC.HMAC as HMAC
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (Serialize(..), Put, runPut, putWord32le, putWord64le,
                       putByteString, encode)
import Data.Word (Word8, Word32, Word64)
import Data.Bits ((.&.), (.|.), xor, shiftL, shiftR, testBit)
import Data.Char (ord, toLower)
import Data.List (elemIndex)
import Data.Maybe (fromMaybe, mapMaybe)
import qualified Data.Text as T
import Data.Text (Text)
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

import System.IO.Unsafe (unsafePerformIO)
import Foreign.C.Types (CUChar, CSize(..), CInt(..))
import Foreign.Ptr (Ptr, castPtr)

import Haskoin.Types (Hash256(..), Hash160(..), TxId(..), BlockHash(..),
                      Tx(..), TxIn(..), TxOut(..), BlockHeader(..), OutPoint(..),
                      putVarInt, putVarBytes)

-- | FFI binding to our C wrapper: lax DER parse + normalize + verify.
-- Matches Bitcoin Core's CPubKey::Verify behavior exactly.
foreign import ccall unsafe "haskoin_ecdsa_verify_lax"
  c_ecdsa_verify_lax :: Ptr CUChar -> CSize
                     -> Ptr CUChar -> CSize
                     -> Ptr CUChar
                     -> IO CInt

--------------------------------------------------------------------------------
-- Hashing Functions
--------------------------------------------------------------------------------

-- | SHA-256 hash
sha256 :: ByteString -> ByteString
sha256 bs = convert (H.hashWith H.SHA256 bs)

-- | SHA-1 hash
sha1 :: ByteString -> ByteString
sha1 bs = convert (H.hashWith H.SHA1 bs)

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
  deriving (Show, Eq, Ord, Generic)

instance NFData SecKey

-- | Public key: compressed (33 bytes) or uncompressed (65 bytes)
data PubKey
  = PubKeyCompressed !ByteString     -- 33 bytes: 0x02/0x03 + x
  | PubKeyUncompressed !ByteString   -- 65 bytes: 0x04 + x + y
  deriving (Show, Eq, Ord, Generic)

instance NFData PubKey

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

-- | Verify a signature against a public key and message hash (strict DER).
-- Uses the same lax path since strict DER is a subset.
verifyMsg :: PubKey -> Sig -> Hash256 -> Bool
verifyMsg = verifyMsgLax

-- | Verify a signature against a public key and message hash (lax DER parsing).
-- This matches Bitcoin Core's CPubKey::Verify which uses ecdsa_signature_parse_der_lax.
-- Calls directly into libsecp256k1 via our C wrapper.
verifyMsgLax :: PubKey -> Sig -> Hash256 -> Bool
verifyMsgLax pk (Sig sigDer) (Hash256 hashBytes) =
  unsafePerformIO $ do
    let pkBytes = serializePubKeyRaw pk
    BS.useAsCStringLen pkBytes $ \(pkPtr, pkLen) ->
      BS.useAsCStringLen sigDer $ \(sigPtr, sigLen) ->
        BS.useAsCStringLen hashBytes $ \(hashPtr, _) -> do
          result <- c_ecdsa_verify_lax
            (castPtr pkPtr) (fromIntegral pkLen)
            (castPtr sigPtr) (fromIntegral sigLen)
            (castPtr hashPtr)
          return (result == 1)

-- | Get raw bytes of a public key (compressed or uncompressed)
serializePubKeyRaw :: PubKey -> ByteString
serializePubKeyRaw (PubKeyCompressed bs) = bs
serializePubKeyRaw (PubKeyUncompressed bs) = bs

-- | Serialize signature in DER format
serializeSigDER :: Sig -> ByteString
serializeSigDER (Sig bs) = bs

-- | Parse a DER-encoded signature
parseSigDER :: ByteString -> Maybe Sig
parseSigDER bs
  | BS.length bs >= 8 && BS.head bs == 0x30 = Just (Sig bs)
  | otherwise = Nothing

-- | Strict DER signature validation (BIP-66).
-- The input is the full signature WITH the sighash type byte appended.
-- This implements Bitcoin Core's IsValidSignatureEncoding().
isValidDERSignature :: ByteString -> Bool
isValidDERSignature sig
  | BS.length sig < 9 = False   -- Min: 30 06 02 01 R 02 01 S hashtype
  | BS.length sig > 73 = False  -- Max: 30 46 02 21 R(33) 02 21 S(33) hashtype
  | otherwise =
    let len = BS.length sig
        -- sig without the hashtype byte
        -- The DER structure is: 0x30 <total-len> 0x02 <r-len> <r> 0x02 <s-len> <s>
        b0 = BS.index sig 0  -- Must be 0x30 (compound structure)
        b1 = BS.index sig 1  -- Length of the rest (excluding hashtype byte)
        b2 = BS.index sig 2  -- Must be 0x02 (integer marker for R)
        rLen = fromIntegral (BS.index sig 3) :: Int -- Length of R
        -- Position of S integer marker
        sMarkerPos = 4 + rLen
    in b0 == 0x30
       && fromIntegral b1 == len - 3  -- total length check (len - compound header(2) - hashtype(1))
       && b2 == 0x02                  -- R integer marker
       && rLen > 0                    -- R must be non-empty
       && sMarkerPos < len - 1        -- S marker must exist
       && BS.index sig sMarkerPos == 0x02  -- S integer marker
       && let sLen = fromIntegral (BS.index sig (sMarkerPos + 1)) :: Int
          in sLen > 0                 -- S must be non-empty
             && rLen + sLen + 7 == len  -- Total length consistency (including hashtype)
             -- R value checks
             && not (BS.index sig 4 .&. 0x80 /= 0)  -- R must not be negative
             && not (rLen > 1 && BS.index sig 4 == 0x00 && BS.index sig 5 .&. 0x80 == 0)  -- No excess padding in R
             -- S value checks
             && not (BS.index sig (sMarkerPos + 2) .&. 0x80 /= 0)  -- S must not be negative
             && not (sLen > 1 && BS.index sig (sMarkerPos + 2) == 0x00 && BS.index sig (sMarkerPos + 3) .&. 0x80 == 0)  -- No excess padding in S

-- | Check if a sighash type byte is a defined/valid hash type.
-- Valid base types: SIGHASH_ALL (1), SIGHASH_NONE (2), SIGHASH_SINGLE (3)
-- Optionally combined with SIGHASH_ANYONECANPAY (0x80)
isDefinedSigHashType :: Word8 -> Bool
isDefinedSigHashType b =
  let base = b .&. 0x7f  -- mask off ANYONECANPAY bit (0x80)
  in base >= 1 && base <= 3

-- | Check if a DER signature has low S value (BIP-62 LOW_S rule).
-- The input is the full signature WITH the sighash type byte appended.
-- S must be <= order/2 where order is the secp256k1 curve order.
-- This assumes the signature already passed isValidDERSignature.
isLowDERSignature :: ByteString -> Bool
isLowDERSignature sig
  | BS.length sig < 9 = False
  | otherwise =
    let rLen = fromIntegral (BS.index sig 3) :: Int
        sMarkerPos = 4 + rLen
        sLen = fromIntegral (BS.index sig (sMarkerPos + 1)) :: Int
        sBytes = BS.take sLen (BS.drop (sMarkerPos + 2) sig)
        -- secp256k1 half-order (order / 2):
        -- order = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        -- order/2 = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        halfOrder = BS.pack [0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                             0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
                             0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0]
    in compareBigEndian sBytes halfOrder /= GT
  where
    -- Compare two big-endian byte strings as unsigned integers
    compareBigEndian :: ByteString -> ByteString -> Ordering
    compareBigEndian a b =
      let la = BS.length a
          lb = BS.length b
          -- Pad shorter value with leading zeros
          (a', b') = if la > lb
                     then (a, BS.replicate (la - lb) 0 <> b)
                     else (BS.replicate (lb - la) 0 <> a, b)
      in compare a' b'

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
-- FindAndDelete for Legacy Sighash
--------------------------------------------------------------------------------

-- | FindAndDelete removes all occurrences of a byte pattern from a script.
-- This operates on raw bytes, matching Bitcoin Core's behavior:
-- - Only matches at opcode boundaries (doesn't match inside push data)
-- - Single-pass removal (removing one occurrence may create another, but that's not removed)
--
-- Reference: Bitcoin Core src/script/interpreter.cpp FindAndDelete()
findAndDelete :: ByteString -> ByteString -> ByteString
findAndDelete script pattern
  | BS.null pattern = script  -- Empty pattern = no-op
  | otherwise = go script BS.empty 0
  where
    patLen = BS.length pattern
    scriptLen = BS.length script

    -- Walk through script at opcode boundaries
    go :: ByteString -> ByteString -> Int -> ByteString
    go remaining result pos
      | BS.null remaining = result
      | otherwise =
          -- At each opcode boundary, check if pattern matches
          let matchesHere = BS.length remaining >= patLen &&
                           BS.take patLen remaining == pattern
          in if matchesHere
             then -- Skip the pattern, continue from after it
                  go (BS.drop patLen remaining) result (pos + patLen)
             else -- Copy this opcode to result, advance to next opcode
                  let (opBytes, nextRemaining, advance) = getNextOpcode remaining
                  in go nextRemaining (BS.append result opBytes) (pos + advance)

    -- Get the bytes for the next opcode (opcode + any push data)
    getNextOpcode :: ByteString -> (ByteString, ByteString, Int)
    getNextOpcode bs
      | BS.null bs = (BS.empty, BS.empty, 0)
      | otherwise =
          let op = BS.head bs
          in case getPushDataLength op (BS.tail bs) of
               Just (dataLen, prefixLen) ->
                 let totalLen = 1 + prefixLen + dataLen
                     opcodeBytes = BS.take totalLen bs
                     rest = BS.drop totalLen bs
                 in (opcodeBytes, rest, totalLen)
               Nothing ->
                 -- Not a push data opcode, just the single byte
                 (BS.take 1 bs, BS.tail bs, 1)

    -- Get the length of push data for a given opcode
    -- Returns (data length, prefix length after opcode)
    getPushDataLength :: Word8 -> ByteString -> Maybe (Int, Int)
    getPushDataLength op rest
      | op <= 0x4b = Just (fromIntegral op, 0)  -- OP_PUSHDATA direct: op is the length
      | op == 0x4c && not (BS.null rest) =      -- OP_PUSHDATA1: 1 byte length
          Just (fromIntegral (BS.head rest), 1)
      | op == 0x4d && BS.length rest >= 2 =     -- OP_PUSHDATA2: 2 byte length (LE)
          let len = fromIntegral (BS.index rest 0) +
                    fromIntegral (BS.index rest 1) * 256
          in Just (len, 2)
      | op == 0x4e && BS.length rest >= 4 =     -- OP_PUSHDATA4: 4 byte length (LE)
          let len = fromIntegral (BS.index rest 0) +
                    fromIntegral (BS.index rest 1) * 256 +
                    fromIntegral (BS.index rest 2) * 65536 +
                    fromIntegral (BS.index rest 3) * 16777216
          in Just (len, 4)
      | otherwise = Nothing  -- Not a push data opcode

-- | Remove all OP_CODESEPARATOR (0xab) opcodes from a script
-- This is used when preparing the scriptCode for legacy sighash computation
removeCodeSeparators :: ByteString -> ByteString
removeCodeSeparators script = findAndDelete script (BS.singleton 0xab)

-- | Prepare scriptCode for sighash computation in legacy mode.
-- Takes the original subscript, optionally the position after last OP_CODESEPARATOR,
-- and the signature being checked (to be removed via FindAndDelete).
--
-- For legacy (non-witness) scripts:
-- 1. If codeSepPos is set, take script from that position onward
-- 2. Remove all OP_CODESEPARATOR opcodes
-- 3. Remove all occurrences of the signature (with its push opcode prefix)
--
-- Note: FindAndDelete removes the push-encoded signature, not just raw bytes
scriptCodeForSighash :: ByteString        -- ^ Original subscript
                     -> Word32            -- ^ Code separator position (0xFFFFFFFF = none)
                     -> ByteString        -- ^ Signature bytes to remove (including hash type)
                     -> ByteString        -- ^ Prepared scriptCode
scriptCodeForSighash subscript codeSepPos sigBytes =
  let -- Step 1: Handle OP_CODESEPARATOR position
      -- If codeSepPos is not 0xFFFFFFFF, take from that position
      scriptAfterCodeSep = if codeSepPos /= 0xFFFFFFFF && fromIntegral codeSepPos < BS.length subscript
                           then BS.drop (fromIntegral codeSepPos) subscript
                           else subscript
      -- Step 2: Remove all OP_CODESEPARATOR opcodes from the script
      scriptNoCodeSep = removeCodeSeparators scriptAfterCodeSep
      -- Step 3: Create the push-encoded signature for FindAndDelete
      -- The signature is removed with its push opcode prefix
      sigPushEncoded = encodePushData sigBytes
      -- Step 4: Remove all occurrences of the push-encoded signature
  in if BS.null sigBytes
     then scriptNoCodeSep
     else findAndDelete scriptNoCodeSep sigPushEncoded

-- | Encode a byte string as a push data operation (for FindAndDelete)
-- This matches Bitcoin Core's CScript operator<< behavior
encodePushData :: ByteString -> ByteString
encodePushData bs
  | BS.null bs = BS.singleton 0x00  -- OP_0 for empty
  | BS.length bs <= 75 = BS.cons (fromIntegral $ BS.length bs) bs  -- Direct push
  | BS.length bs <= 255 =
      BS.cons 0x4c (BS.cons (fromIntegral $ BS.length bs) bs)  -- OP_PUSHDATA1
  | BS.length bs <= 65535 =
      let len = BS.length bs
          lenBytes = BS.pack [fromIntegral (len .&. 0xff), fromIntegral ((len `shiftR` 8) .&. 0xff)]
      in BS.cons 0x4d (BS.append lenBytes bs)  -- OP_PUSHDATA2
  | otherwise =
      let len = BS.length bs
          lenBytes = BS.pack [ fromIntegral (len .&. 0xff)
                             , fromIntegral ((len `shiftR` 8) .&. 0xff)
                             , fromIntegral ((len `shiftR` 16) .&. 0xff)
                             , fromIntegral ((len `shiftR` 24) .&. 0xff)
                             ]
      in BS.cons 0x4e (BS.append lenBytes bs)  -- OP_PUSHDATA4

--------------------------------------------------------------------------------
-- Sighash Computation
--------------------------------------------------------------------------------

-- | Compute legacy sighash for transaction signing
-- Serializes the transaction with script in signing input, then double-SHA256
--
-- The raw Word32 hash type is appended as-is to the serialized transaction
-- before hashing. This is critical: Bitcoin Core appends the original wire
-- value, not a canonicalized version. The SigHashType flags control the
-- serialization behavior (which inputs/outputs to include).
--
-- IMPORTANT: For SIGHASH_SINGLE with inputIdx >= len(outputs), Bitcoin Core
-- returns a hash of uint256(1) - this is a historical bug that became consensus.
txSigHash :: Tx -> Int -> ByteString -> Word32 -> SigHashType -> Hash256
txSigHash tx inputIdx subScript hashTypeW32 shType =
  -- SIGHASH_SINGLE with inputIdx >= length outputs: return hash of 1
  if shSingle shType && inputIdx >= length (txOutputs tx)
  then Hash256 (BS.pack $ 0x01 : replicate 31 0x00)  -- uint256(1) in little-endian
  else
    let -- Remove OP_CODESEPARATOR from subscript (FindAndDelete)
        cleanScript = removeCodeSeparators subScript
        -- Clear all input scripts, set signing input's script to cleaned subscript
        inputs' = zipWith (\i inp ->
          if i == inputIdx
            then inp { txInScript = cleanScript }
            else inp { txInScript = BS.empty }
          ) [0..] (txInputs tx)
        -- Handle SIGHASH_NONE and SIGHASH_SINGLE output modifications
        outputs' = case () of
          _ | shNone shType -> []
            | shSingle shType && inputIdx < length (txOutputs tx) ->
                replicate inputIdx (TxOut 0xffffffffffffffff BS.empty)
                ++ [txOutputs tx !! inputIdx]
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

--------------------------------------------------------------------------------
-- Address Types
--------------------------------------------------------------------------------

-- | Bitcoin address types
data Address
  = PubKeyAddress !Hash160          -- ^ P2PKH: Base58Check with version 0x00
  | ScriptAddress !Hash160          -- ^ P2SH:  Base58Check with version 0x05
  | WitnessPubKeyAddress !Hash160   -- ^ P2WPKH: Bech32 with witness version 0
  | WitnessScriptAddress !Hash256   -- ^ P2WSH:  Bech32 with witness version 0
  | TaprootAddress !Hash256         -- ^ P2TR:   Bech32m with witness version 1
  deriving (Show, Eq, Ord, Generic)

instance NFData Address

--------------------------------------------------------------------------------
-- Address Construction
--------------------------------------------------------------------------------

-- | Create a P2PKH address from a public key
pubKeyToP2PKH :: PubKey -> Address
pubKeyToP2PKH pk = PubKeyAddress (hash160 (serializePubKeyCompressed pk))

-- | Create a P2WPKH address from a public key
pubKeyToP2WPKH :: PubKey -> Address
pubKeyToP2WPKH pk = WitnessPubKeyAddress (hash160 (serializePubKeyCompressed pk))

-- | Create a P2SH address from a script
scriptToP2SH :: ByteString -> Address
scriptToP2SH script = ScriptAddress (hash160 script)

-- | Create a P2WSH address from a script
-- P2WSH uses single SHA-256 (not double)
scriptToP2WSH :: ByteString -> Address
scriptToP2WSH script = WitnessScriptAddress (Hash256 (sha256 script))

--------------------------------------------------------------------------------
-- Base58Check Encoding
--------------------------------------------------------------------------------

-- | Base58 alphabet (no 0, O, I, l to avoid ambiguity)
base58Alphabet :: String
base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

-- | Encode a ByteString to Base58
encodeBase58 :: ByteString -> Text
encodeBase58 bs
  | BS.null bs = T.empty
  | bsToInteger bs == 0 = T.empty
  | otherwise = T.pack $ reverse $ go (bsToInteger bs)
  where
    go 0 = []
    go n = let (q, r) = n `divMod` 58
           in (base58Alphabet !! fromIntegral r) : go q

-- | Decode a Base58 text to ByteString
decodeBase58 :: Text -> ByteString
decodeBase58 txt
  | T.null txt = BS.empty
  | otherwise = integerToBS $ T.foldl' step 0 txt
  where
    step acc c = acc * 58 + fromIntegral (fromMaybe 0 (elemIndex c base58Alphabet))

-- | Convert a ByteString to Integer (big-endian)
bsToInteger :: ByteString -> Integer
bsToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Convert an Integer to ByteString (big-endian)
integerToBS :: Integer -> ByteString
integerToBS 0 = BS.empty
integerToBS n = BS.pack $ reverse $ go n
  where
    go 0 = []
    go x = fromIntegral (x `mod` 256) : go (x `div` 256)

-- | Encode data with Base58Check (version byte + payload + 4-byte checksum)
base58Check :: Word8 -> ByteString -> Text
base58Check version payload =
  let versionedPayload = BS.cons version payload
      checksum = BS.take 4 $ getHash256 $ doubleSHA256 versionedPayload
      fullPayload = BS.append versionedPayload checksum
      -- Count leading zero bytes
      leadingZeros = BS.length $ BS.takeWhile (== 0) fullPayload
      -- Convert to base58 by treating fullPayload as a big-endian integer
      encoded = encodeBase58 fullPayload
      -- Prepend '1' for each leading zero byte
      prefix = T.replicate leadingZeros (T.singleton '1')
  in T.append prefix encoded

-- | Decode a Base58Check-encoded text
base58CheckDecode :: Text -> Maybe (Word8, ByteString)
base58CheckDecode txt
  | T.null txt = Nothing
  | otherwise =
      let -- Strip leading '1's, count them as zero bytes
          (ones, rest) = T.span (== '1') txt
          leadingZeros = T.length ones
          decoded = decodeBase58 rest
          withZeros = BS.append (BS.replicate leadingZeros 0) decoded
      in if BS.length withZeros < 5
         then Nothing
         else let payloadLen = BS.length withZeros - 4
                  payload = BS.take payloadLen withZeros
                  checkBytesGot = BS.drop payloadLen withZeros
                  checkBytesExpected = BS.take 4 $ getHash256 $ doubleSHA256 payload
              in if checkBytesGot == checkBytesExpected
                 then Just (BS.head payload, BS.tail payload)
                 else Nothing

--------------------------------------------------------------------------------
-- Bech32/Bech32m Encoding (BIP-173, BIP-350)
--------------------------------------------------------------------------------

-- | Bech32 character set
bech32Charset :: String
bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | Bech32 polymod for checksum calculation
bech32Polymod :: [Int] -> Int
bech32Polymod values = foldl step 1 values
  where
    generators :: [Int]
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

    step chk v =
      let b = chk `shiftR` 25
          chk' = ((chk .&. 0x1ffffff) `shiftL` 5) `xor` v
      in foldl (\c (i, g) -> if testBit b i then c `xor` g else c) chk'
           (zip [0..] generators)

-- | Expand HRP for checksum
bech32HrpExpand :: String -> [Int]
bech32HrpExpand hrp =
  map (\c -> ord c `shiftR` 5) hrp ++ [0] ++ map (\c -> ord c .&. 31) hrp

-- | Create Bech32 checksum
-- Bech32 uses constant 1, Bech32m uses constant 0x2bc830a3
bech32CreateChecksum :: String -> [Int] -> Int -> [Int]
bech32CreateChecksum hrp datapart spec =
  let values = bech32HrpExpand hrp ++ datapart ++ [0,0,0,0,0,0]
      polymod = bech32Polymod values `xor` spec
  in map (\i -> (polymod `shiftR` (5 * (5 - i))) .&. 31) [0..5]

-- | Verify Bech32 checksum
bech32VerifyChecksum :: String -> [Int] -> Int -> Bool
bech32VerifyChecksum hrp datapart spec =
  bech32Polymod (bech32HrpExpand hrp ++ datapart) == spec

-- | Convert between bit groups (e.g., 8-bit to 5-bit)
convertBits :: Int -> Int -> Bool -> [Word8] -> [Int]
convertBits fromBits toBits pad input = go 0 0 input []
  where
    maxV = (1 `shiftL` toBits) - 1

    go acc bits [] result
      | pad && bits > 0 = reverse ((acc `shiftL` (toBits - bits)) .&. maxV : result)
      | not pad && bits >= fromBits = reverse result
      | otherwise = reverse result

    go acc bits (x:xs) result =
      let acc' = (acc `shiftL` fromBits) .|. fromIntegral x
          bits' = bits + fromBits
      in extractBits acc' bits' xs result

    extractBits acc bits xs result
      | bits >= toBits =
          let bits' = bits - toBits
          in extractBits acc bits' xs ((acc `shiftR` bits') .&. maxV : result)
      | otherwise = go acc bits xs result

-- | Convert 5-bit groups back to 8-bit bytes
convertBitsBack :: Int -> Int -> Bool -> [Int] -> Maybe [Word8]
convertBitsBack fromBits toBits pad input = go 0 0 input []
  where
    maxV = (1 `shiftL` toBits) - 1

    go acc bits [] result
      | pad && bits > 0 = Just $ reverse (fromIntegral ((acc `shiftL` (toBits - bits)) .&. maxV) : result)
      | bits >= fromBits = Nothing  -- Invalid padding
      | (acc `shiftL` (toBits - bits)) .&. maxV /= 0 = Nothing  -- Non-zero padding
      | otherwise = Just $ reverse result

    go acc bits (x:xs) result
      | x < 0 || x >= (1 `shiftL` fromBits) = Nothing  -- Invalid value
      | otherwise =
          let acc' = (acc `shiftL` fromBits) .|. x
              bits' = bits + fromBits
          in extractBits acc' bits' xs result

    extractBits acc bits xs result
      | bits >= toBits =
          let bits' = bits - toBits
          in extractBits acc bits' xs (fromIntegral ((acc `shiftR` bits') .&. maxV) : result)
      | otherwise = go acc bits xs result

-- | Encode a SegWit address in Bech32 format (witness version 0)
bech32Encode :: String -> Int -> ByteString -> Text
bech32Encode hrp witVer witProg =
  let dat = witVer : convertBits 8 5 True (BS.unpack witProg)
      checksum = bech32CreateChecksum hrp dat 1  -- Bech32 constant
      encoded = map (\i -> bech32Charset !! i) (dat ++ checksum)
  in T.pack (hrp ++ "1" ++ encoded)

-- | Encode a Taproot address in Bech32m format (witness version 1+)
bech32mEncode :: String -> Int -> ByteString -> Text
bech32mEncode hrp witVer witProg =
  let dat = witVer : convertBits 8 5 True (BS.unpack witProg)
      checksum = bech32CreateChecksum hrp dat 0x2bc830a3  -- Bech32m constant
      encoded = map (\i -> bech32Charset !! i) (dat ++ checksum)
  in T.pack (hrp ++ "1" ++ encoded)

-- | Decode a Bech32/Bech32m address
-- Returns (hrp, witness version, witness program)
bech32Decode :: Text -> Maybe (String, Int, ByteString)
bech32Decode addr =
  let str = map toLower $ T.unpack addr
  in case break (== '1') (reverse str) of
       (_, []) -> Nothing  -- No separator found
       (rDataPart, '1':rHrp) ->
         let hrp = reverse rHrp
             dataPart = reverse rDataPart
         in if null hrp || length dataPart < 6
            then Nothing
            else case mapMaybe (`elemIndex` bech32Charset) dataPart of
              decoded
                | length decoded /= length dataPart -> Nothing
                | otherwise ->
                    let dataWithCheck = decoded
                        dataOnly = take (length dataWithCheck - 6) dataWithCheck
                        -- Try both Bech32 and Bech32m
                        validBech32 = bech32VerifyChecksum hrp dataWithCheck 1
                        validBech32m = bech32VerifyChecksum hrp dataWithCheck 0x2bc830a3
                    in if not (validBech32 || validBech32m) || null dataOnly
                       then Nothing
                       else let witVer = head dataOnly
                                witProgData = tail dataOnly
                            in case convertBitsBack 5 8 False witProgData of
                                 Nothing -> Nothing
                                 Just prog -> Just (hrp, witVer, BS.pack prog)
       _ -> Nothing

--------------------------------------------------------------------------------
-- Address Encoding/Decoding
--------------------------------------------------------------------------------

-- | Convert an Address to its text representation
addressToText :: Address -> Text
addressToText (PubKeyAddress h) = base58Check 0x00 (getHash160 h)
addressToText (ScriptAddress h) = base58Check 0x05 (getHash160 h)
addressToText (WitnessPubKeyAddress h) = bech32Encode "bc" 0 (getHash160 h)
addressToText (WitnessScriptAddress h) = bech32Encode "bc" 0 (getHash256 h)
addressToText (TaprootAddress h) = bech32mEncode "bc" 1 (getHash256 h)

-- | Parse an address from text
textToAddress :: Text -> Maybe Address
textToAddress txt
  | T.isPrefixOf "bc1q" txtLower || T.isPrefixOf "BC1Q" txt
    || T.isPrefixOf "bcrt1q" txtLower || T.isPrefixOf "tb1q" txtLower = -- Bech32 P2WPKH/P2WSH
      case bech32Decode txt of
        Just (_, 0, prog)
          | BS.length prog == 20 -> Just $ WitnessPubKeyAddress (Hash160 prog)
          | BS.length prog == 32 -> Just $ WitnessScriptAddress (Hash256 prog)
        _ -> Nothing
  | T.isPrefixOf "bc1p" txtLower || T.isPrefixOf "BC1P" txt
    || T.isPrefixOf "bcrt1p" txtLower || T.isPrefixOf "tb1p" txtLower = -- Bech32m P2TR
      case bech32Decode txt of
        Just (_, 1, prog)
          | BS.length prog == 32 -> Just $ TaprootAddress (Hash256 prog)
        _ -> Nothing
  | otherwise = -- Base58Check (mainnet 0x00/0x05, testnet/regtest 0x6f/0xc4)
      case base58CheckDecode txt of
        Just (0x00, h) | BS.length h == 20 -> Just $ PubKeyAddress (Hash160 h)
        Just (0x6f, h) | BS.length h == 20 -> Just $ PubKeyAddress (Hash160 h)
        Just (0x05, h) | BS.length h == 20 -> Just $ ScriptAddress (Hash160 h)
        Just (0xc4, h) | BS.length h == 20 -> Just $ ScriptAddress (Hash160 h)
        _ -> Nothing
  where
    txtLower = T.toLower txt

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
  deriving (Show, Eq, Generic)

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
  | T.isPrefixOf "bc1q" txtLower || T.isPrefixOf "BC1Q" txt = -- Bech32 P2WPKH/P2WSH
      case bech32Decode txt of
        Just (_, 0, prog)
          | BS.length prog == 20 -> Just $ WitnessPubKeyAddress (Hash160 prog)
          | BS.length prog == 32 -> Just $ WitnessScriptAddress (Hash256 prog)
        _ -> Nothing
  | T.isPrefixOf "bc1p" txtLower || T.isPrefixOf "BC1P" txt = -- Bech32m P2TR
      case bech32Decode txt of
        Just (_, 1, prog)
          | BS.length prog == 32 -> Just $ TaprootAddress (Hash256 prog)
        _ -> Nothing
  | otherwise = -- Base58Check
      case base58CheckDecode txt of
        Just (0x00, h) | BS.length h == 20 -> Just $ PubKeyAddress (Hash160 h)
        Just (0x05, h) | BS.length h == 20 -> Just $ ScriptAddress (Hash160 h)
        _ -> Nothing
  where
    txtLower = T.toLower txt

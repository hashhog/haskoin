{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
  , pubKeyTweakAdd
  , seckeyTweakAdd
    -- * Signatures
  , Sig(..)
  , signMsg
  , signMsgMaybe
  , verifyMsg
  , verifyMsgLax
  , serializeSigDER
  , parseSigDER
  , isValidDERSignature
  , isDefinedSigHashType
  , isLowDERSignature
    -- * Recoverable / message signing
  , derivePubKeyCompressed
  , derivePubKeyUncompressed
  , decompressPubKey
  , signCompact
  , recoverCompact
  , messageMagic
  , messageHash
  , signMessage
  , recoverMessagePubKey
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
  , findAndDeleteCount
  , subscriptAfterCodeSep
  , removeCodeSeparators
  , scriptCodeForSighash
  , encodePushData
    -- * Transaction/Block hashing
  , computeTxId
  , computeWtxid
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
  , encodeBase58
  , decodeBase58
  , bech32Encode
  , bech32Decode
  , bech32mEncode
    -- * Taproot Utilities
  , taggedHash
  , xonlyPubkeyTweakAdd
  , verifySchnorr
    -- * Taproot signing (BIP-340 / BIP-341)
  , signSchnorr
  , signSchnorrAux
  , taprootTweakSeckey
  , xonlyPubkeyFromSeckey
  , computeTapTweakHash
  , bip86TapTweakHash
    -- * Process-wide Signature Verification Cache
    -- (W105 BUG-2 / BUG-9 / BUG-13 + W159 BUG-17 / W160 BUG-16 fixes)
  , SigCacheEntry
  , initGlobalSigCache
  , lookupGlobalSigCache
  , insertGlobalSigCache
  , cachedVerifyMsgLax
  , cachedVerifySchnorr
  ) where

import qualified Crypto.Hash as H
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Random as CryptoRandom
import Control.Monad (when)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef, atomicModifyIORef')
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Serialize (Serialize(..), Put, runPut, putWord32le, putWord64le,
                       putByteString, encode)
import Data.Word (Word8, Word32, Word64)
import Data.Bits ((.&.), (.|.), xor, shiftL, shiftR, testBit)
import Data.Char (ord, toLower)
import Data.List (elemIndex)
import Data.Maybe (fromMaybe, mapMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Text (Text)
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

import System.IO.Unsafe (unsafePerformIO)
import Foreign.C.Types (CUChar, CSize(..), CInt(..))
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (allocaArray)
import Foreign.Storable (peek, poke)

import Haskoin.Types (Hash256(..), Hash160(..), TxId(..), Wtxid(..), BlockHash(..),
                      Tx(..), TxIn(..), TxOut(..), BlockHeader(..), OutPoint(..),
                      putVarInt, putVarBytes)

-- | FFI binding to our C wrapper: lax DER parse + normalize + verify.
-- Matches Bitcoin Core's CPubKey::Verify behavior exactly.
foreign import ccall unsafe "haskoin_ecdsa_verify_lax"
  c_ecdsa_verify_lax :: Ptr CUChar -> CSize
                     -> Ptr CUChar -> CSize
                     -> Ptr CUChar
                     -> IO CInt

-- | FFI binding for x-only pubkey tweak add (Taproot BIP-341).
foreign import ccall unsafe "haskoin_xonly_pubkey_tweak_add"
  c_xonly_pubkey_tweak_add :: Ptr CUChar   -- internal_pubkey32
                           -> Ptr CUChar   -- tweak32
                           -> Ptr CUChar   -- output_pubkey32
                           -> Ptr CInt     -- output_parity
                           -> IO CInt

-- | FFI binding for BIP-340 Schnorr signature verification.
foreign import ccall unsafe "haskoin_schnorrsig_verify"
  c_schnorrsig_verify :: Ptr CUChar   -- sig64
                      -> Ptr CUChar   -- msg32
                      -> Ptr CUChar   -- pubkey_x32
                      -> IO CInt

-- | FFI binding for ECDSA pubkey derivation from a 32-byte secret key.
foreign import ccall unsafe "haskoin_ec_pubkey_create"
  c_ec_pubkey_create :: Ptr CUChar    -- seckey32
                     -> CInt          -- compressed flag (0/1)
                     -> Ptr CUChar    -- output (33 or 65 bytes)
                     -> Ptr CSize     -- in/out length
                     -> IO CInt

-- | FFI binding for BIP-32 CKDpub: child = parent + tweak*G.
-- Wraps libsecp256k1's @secp256k1_ec_pubkey_tweak_add@.  Returns 0 on
-- failure (invalid parent, tweak >= curve order, point-at-infinity);
-- the BIP-32 spec instructs the caller to advance the child index and
-- retry on failure.  Reference: @bitcoin-core/src/pubkey.cpp@
-- `CPubKey::Derive`.
foreign import ccall unsafe "haskoin_ec_pubkey_tweak_add"
  c_ec_pubkey_tweak_add :: Ptr CUChar  -- parent_pubkey33
                        -> Ptr CUChar  -- tweak32
                        -> Ptr CUChar  -- output33
                        -> IO CInt

-- | FFI binding for BIP-32 CKDpriv: child_seckey = (parent + tweak) mod n.
-- Wraps libsecp256k1's @secp256k1_ec_seckey_tweak_add@ (constant-time).
-- Returns 0 on failure (tweak >= curve order, parent >= n, zero result);
-- the BIP-32 spec instructs the caller to advance the child index and
-- retry on failure.  Reference: @bitcoin-core/src/key.cpp:307@
-- @CKey::Derive@.  W159 BUG-14 fix: closes the private-side GMP / public-
-- side libsecp asymmetry that exposed BIP-32 CKDpriv to cache-timing
-- side-channels on every wallet derivation.
foreign import ccall unsafe "haskoin_seckey_tweak_add"
  c_ec_seckey_tweak_add :: Ptr CUChar  -- parent_seckey32
                        -> Ptr CUChar  -- tweak32
                        -> Ptr CUChar  -- output_seckey32
                        -> IO CInt

-- | FFI binding for ECDSA recoverable-compact signing
-- (signmessage / verifymessage layout: header byte + 64 byte R||S).
foreign import ccall unsafe "haskoin_ecdsa_sign_recoverable_compact"
  c_ecdsa_sign_recoverable_compact :: Ptr CUChar  -- seckey32
                                   -> Ptr CUChar  -- msghash32
                                   -> CInt        -- compressed flag (0/1)
                                   -> Ptr CUChar  -- out 65 bytes
                                   -> IO CInt

-- | FFI binding for ECDSA pubkey recovery from a 65-byte compact recoverable
-- signature.
foreign import ccall unsafe "haskoin_ecdsa_recover_compact"
  c_ecdsa_recover_compact :: Ptr CUChar  -- sig65
                          -> Ptr CUChar  -- msghash32
                          -> CInt        -- compressed flag (0/1)
                          -> Ptr CUChar  -- output (33 or 65)
                          -> Ptr CSize   -- out length
                          -> IO CInt

-- | FFI binding for compressed-to-uncompressed pubkey decompression.
-- Used by ScriptCompression decoder for tags 0x04/0x05.
foreign import ccall unsafe "haskoin_ec_pubkey_decompress"
  c_ec_pubkey_decompress :: Ptr CUChar  -- compressed33
                         -> Ptr CUChar  -- out65
                         -> IO CInt

-- | FFI binding for ECDSA DER-encoded signing (transaction-spend path).
-- Wraps libsecp256k1's @secp256k1_ecdsa_sign@ + DER serialize, with an
-- optional low-R grind that matches Core's @CKey::Sign@.
foreign import ccall unsafe "haskoin_ecdsa_sign_der"
  c_ecdsa_sign_der :: Ptr CUChar    -- seckey32
                   -> Ptr CUChar    -- msghash32
                   -> CInt          -- grind flag (0/1)
                   -> Ptr CUChar    -- output buffer (>=72 bytes)
                   -> Ptr CSize     -- in: capacity, out: written length
                   -> IO CInt

-- | FFI binding for BIP-340 Schnorr signing (Taproot key-path /
-- tapscript OP_CHECKSIG).  Wraps @secp256k1_keypair_create@ +
-- @secp256k1_schnorrsig_sign32@ from
-- @bitcoin-core/src/secp256k1/include/secp256k1_schnorrsig.h@.
--
-- The aux-rand pointer may be 'nullPtr' for the default all-zeros aux
-- that Core's @CreateSchnorrSig@ uses for byte-identity with wallet output.
foreign import ccall unsafe "haskoin_schnorrsig_sign"
  c_schnorrsig_sign :: Ptr CUChar  -- seckey32
                    -> Ptr CUChar  -- msg32
                    -> Ptr CUChar  -- aux_rand32 or NULL
                    -> Ptr CUChar  -- out_sig64
                    -> IO CInt

-- | FFI binding for the BIP-341 key-path seckey tweak.  Wraps
-- @secp256k1_keypair_create@ + @secp256k1_keypair_xonly_tweak_add@ +
-- @secp256k1_keypair_sec@.  The 32-byte tweak is computed Haskell-side
-- via 'computeTapTweakHash' (libsecp's public headers don't expose its
-- internal SHA-256, so we hash on the Haskell side and only do the curve
-- arithmetic in C).
foreign import ccall unsafe "haskoin_taproot_tweak_seckey"
  c_taproot_tweak_seckey :: Ptr CUChar  -- seckey32
                         -> Ptr CUChar  -- tweak32
                         -> Ptr CUChar  -- out_seckey32
                         -> IO CInt

-- | FFI binding for x-only pubkey extraction from a seckey, including
-- the BIP-340 even-y normalization.  Used to produce the x-only key
-- @P@ that goes into the TapTweak preimage.
foreign import ccall unsafe "haskoin_xonly_pubkey_from_seckey"
  c_xonly_pubkey_from_seckey :: Ptr CUChar  -- seckey32
                             -> Ptr CUChar  -- out_xonly32
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

-- | BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
taggedHash :: ByteString -> ByteString -> ByteString
taggedHash tag msg =
  let tagHash = sha256 tag
  in sha256 (tagHash <> tagHash <> msg)

-- | Compute tweaked x-only public key for Taproot (BIP-341).
-- Given a 32-byte x-only internal key and a 32-byte tweak,
-- returns (tweaked_x_only_key, parity) or Nothing on failure.
xonlyPubkeyTweakAdd :: ByteString -> ByteString -> Maybe (ByteString, Int)
xonlyPubkeyTweakAdd internalKey tweak
  | BS.length internalKey /= 32 || BS.length tweak /= 32 = Nothing
  | otherwise = unsafePerformIO $ do
      BS.useAsCStringLen internalKey $ \(ikPtr, _) ->
        BS.useAsCStringLen tweak $ \(twPtr, _) ->
          allocaArray (32 :: Int) $ \(outPtr :: Ptr CUChar) ->
            alloca $ \(parityPtr :: Ptr CInt) -> do
              result <- c_xonly_pubkey_tweak_add
                (castPtr ikPtr) (castPtr twPtr)
                outPtr parityPtr
              if result == 1
                then do
                  outKey <- BS.packCStringLen (castPtr outPtr, 32)
                  parity <- peek parityPtr
                  return $ Just (outKey, fromIntegral parity)
                else return Nothing

-- | Verify a BIP-340 Schnorr signature.
-- Returns True iff the 64-byte signature is valid for the 32-byte message
-- digest under the 32-byte x-only public key.
verifySchnorr :: ByteString -> ByteString -> ByteString -> Bool
verifySchnorr sig msg pubkey
  | BS.length sig /= 64 || BS.length msg /= 32 || BS.length pubkey /= 32 = False
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen sig $ \(sigPtr, _) ->
        BS.useAsCStringLen msg $ \(msgPtr, _) ->
          BS.useAsCStringLen pubkey $ \(pkPtr, _) -> do
            r <- c_schnorrsig_verify (castPtr sigPtr) (castPtr msgPtr) (castPtr pkPtr)
            return (r == 1)

-- | Produce a 64-byte BIP-340 Schnorr signature with all-zeros aux-rand.
--
-- This matches Bitcoin Core's @CreateSchnorrSig@ in
-- @bitcoin-core/src/script/sign.cpp@, which passes @uint256{}@ for the
-- aux argument so that the output is byte-identical to whatever the wallet
-- emits for the same (seckey, msg).  Production callers that prefer the
-- BIP-340 hardening recommendation should use 'signSchnorrAux' with fresh
-- 32-byte randomness instead.
--
-- For Taproot key-path spends, @seckey@ here is the *tweaked* output
-- seckey, not the internal key — see 'taprootTweakSeckey'.
--
-- Returns 'Nothing' on a malformed seckey or libsecp internal failure.
signSchnorr :: ByteString -> ByteString -> Maybe ByteString
signSchnorr seckey msg = signSchnorrAux seckey msg Nothing

-- | 'signSchnorr' with caller-supplied 32-byte aux-randomness.  Pass
-- 'Nothing' for the all-zeros (deterministic) form that matches Core's
-- wallet byte-identity, or 'Just rand' for BIP-340-hardened output.
signSchnorrAux :: ByteString -> ByteString -> Maybe ByteString -> Maybe ByteString
signSchnorrAux seckey msg mAux
  | BS.length seckey /= 32 = Nothing
  | BS.length msg    /= 32 = Nothing
  | maybe False ((/= 32) . BS.length) mAux = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen seckey $ \(skPtr, _) ->
        BS.useAsCStringLen msg $ \(msgPtr, _) ->
          allocaArray 64 $ \outPtr -> do
            ok <- case mAux of
              Nothing  ->
                c_schnorrsig_sign
                  (castPtr skPtr) (castPtr msgPtr)
                  (nullPtr) outPtr
              Just aux ->
                BS.useAsCStringLen aux $ \(auxPtr, _) ->
                  c_schnorrsig_sign
                    (castPtr skPtr) (castPtr msgPtr)
                    (castPtr auxPtr) outPtr
            if ok == 1
              then Just <$> BS.packCStringLen (castPtr outPtr, 64)
              else return Nothing

-- | Apply a 32-byte BIP-341 tweak to a 32-byte secret key.  Returns the
-- tweaked seckey ready to feed directly into 'signSchnorr' for a
-- Taproot key-path spend.
--
-- Note: the tweak itself is computed by 'computeTapTweakHash'
-- (or 'bip86TapTweakHash' for the empty-merkle-root BIP-86 case);
-- this function only does the curve arithmetic.  Internally it lifts
-- the seckey into a @secp256k1_keypair@, which performs the BIP-340
-- even-y normalization, then calls @secp256k1_keypair_xonly_tweak_add@.
--
-- Returns 'Nothing' on invalid seckey or tweak >= curve order.
taprootTweakSeckey :: ByteString -> ByteString -> Maybe ByteString
taprootTweakSeckey seckey tweak
  | BS.length seckey /= 32 = Nothing
  | BS.length tweak  /= 32 = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen seckey $ \(skPtr, _) ->
        BS.useAsCStringLen tweak $ \(twPtr, _) ->
          allocaArray 32 $ \outPtr -> do
            ok <- c_taproot_tweak_seckey
                    (castPtr skPtr) (castPtr twPtr) outPtr
            if ok == 1
              then Just <$> BS.packCStringLen (castPtr outPtr, 32)
              else return Nothing

-- | Derive the 32-byte x-only public key (BIP-340) for a 32-byte seckey.
-- Includes the implicit even-y normalization (the seckey's pubkey is
-- the keypair-x-only-pub, not the raw pubkey).  This is the @P@ that
-- goes into the BIP-341 TapTweak preimage.
xonlyPubkeyFromSeckey :: ByteString -> Maybe ByteString
xonlyPubkeyFromSeckey seckey
  | BS.length seckey /= 32 = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen seckey $ \(skPtr, _) ->
        allocaArray 32 $ \outPtr -> do
          ok <- c_xonly_pubkey_from_seckey (castPtr skPtr) outPtr
          if ok == 1
            then Just <$> BS.packCStringLen (castPtr outPtr, 32)
            else return Nothing

-- | Compute the BIP-341 TapTweak hash:
--   @t = TaggedHash("TapTweak", internal_xonly_pubkey || merkle_root)@.
--
-- For BIP-86 single-key-path spends (no script tree) the merkle_root is
-- empty — see 'bip86TapTweakHash' for the convenience wrapper.
--
-- Reference: @bitcoin-core/src/key.cpp ComputeTapTweakHash@.
computeTapTweakHash :: ByteString -> ByteString -> ByteString
computeTapTweakHash internalXOnly merkleRoot =
  taggedHash "TapTweak" (internalXOnly <> merkleRoot)

-- | BIP-86 (single-key, key-path-only) TapTweak hash.  Equivalent to
-- @computeTapTweakHash internal_xonly mempty@.
bip86TapTweakHash :: ByteString -> ByteString
bip86TapTweakHash internalXOnly = computeTapTweakHash internalXOnly BS.empty

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

-- | Derive the compressed public key for a 32-byte secret key.
--
-- Backed by libsecp256k1 via the existing @derivePubKeyCompressed@ FFI
-- wrapper (`c_ec_pubkey_create`), which itself wraps Core's
-- `secp256k1_ec_pubkey_create`.  Calls 'error' on a malformed seckey
-- (zero, out of range, etc.); callers that can recover from a bad
-- seckey should use 'derivePubKeyCompressed' directly.
--
-- Reference: @bitcoin-core/src/key.cpp@ `CKey::GetPubKey`.
derivePubKey :: SecKey -> PubKey
derivePubKey sk = case derivePubKeyCompressed sk of
  Just bs -> PubKeyCompressed bs
  Nothing -> error "derivePubKey: invalid secp256k1 secret key"

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
  | BS.length bs == 65 && (BS.head bs == 0x04 || BS.head bs == 0x06 || BS.head bs == 0x07) =
      Just (PubKeyUncompressed bs)
  | otherwise = Nothing

-- | BIP-32 CKDpub primitive: compute @parent_pubkey + tweak*G@.
--
-- The parent must be a 33-byte compressed pubkey; the tweak is a 32-byte
-- big-endian scalar (typically the IL half of HMAC-SHA512 in CKDpub).
-- Returns 'Nothing' on:
--
--   * malformed parent (wrong length or invalid X coordinate)
--   * malformed tweak (wrong length)
--   * tweak >= curve order n
--   * result is the point at infinity
--
-- BIP-32 instructs callers to advance the child index and retry on
-- 'Nothing'.  The returned bytes are 33-byte compressed.
--
-- Reference: @bitcoin-core/src/pubkey.cpp@ `CPubKey::Derive` (uses
-- @secp256k1_ec_pubkey_tweak_add@ identically to this wrapper).
pubKeyTweakAdd :: ByteString -> ByteString -> Maybe ByteString
pubKeyTweakAdd parent33 tweak32
  | BS.length parent33 /= 33 = Nothing
  | BS.length tweak32  /= 32 = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen parent33 $ \(pPtr, _) ->
        BS.useAsCStringLen tweak32 $ \(tPtr, _) ->
          allocaArray 33 $ \outPtr -> do
            ok <- c_ec_pubkey_tweak_add
                    (castPtr pPtr) (castPtr tPtr) outPtr
            if ok == 1
              then Just <$> BS.packCStringLen (castPtr outPtr, 33)
              else return Nothing

-- | BIP-32 CKDpriv primitive: compute @(parent_seckey + tweak) mod n@
-- in constant time via libsecp256k1's
-- @secp256k1_ec_seckey_tweak_add@.  Both inputs are 32-byte big-endian
-- scalars; the result is a 32-byte big-endian secret key.
--
-- Returns 'Nothing' on:
--
--   * malformed parent (wrong length)
--   * malformed tweak (wrong length)
--   * tweak >= curve order n
--   * parent >= curve order n
--   * result is zero (would map to point at infinity)
--
-- BIP-32 instructs callers to advance the child index and retry on
-- 'Nothing'.  Reference: @bitcoin-core/src/key.cpp:307@ @CKey::Derive@.
--
-- W159 BUG-14 fix: prior to this wrapper the only @addPrivateKeys@
-- implementation lived in @Haskoin.Wallet@ and used GHC's @Integer@
-- (GMP, lazy-thunked, NOT constant-time), creating the named-origin
-- "BIP-32 private-side GMP / public-side libsecp asymmetry" fleet
-- pattern.  Both sides now route through constant-time libsecp.
seckeyTweakAdd :: ByteString -> ByteString -> Maybe ByteString
seckeyTweakAdd parent32 tweak32
  | BS.length parent32 /= 32 = Nothing
  | BS.length tweak32  /= 32 = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen parent32 $ \(pPtr, _) ->
        BS.useAsCStringLen tweak32 $ \(tPtr, _) ->
          allocaArray 32 $ \outPtr -> do
            ok <- c_ec_seckey_tweak_add
                    (castPtr pPtr) (castPtr tPtr) outPtr
            if ok == 1
              then Just <$> BS.packCStringLen (castPtr outPtr, 32)
              else return Nothing

--------------------------------------------------------------------------------
-- Signature Types
--------------------------------------------------------------------------------

-- | DER-encoded ECDSA signature
newtype Sig = Sig { getSigBytes :: ByteString }
  deriving (Show, Eq, Generic)

-- | Sign a 32-byte message hash with a 32-byte secret key, returning a
-- DER-encoded ECDSA signature WITHOUT the trailing sighash byte.
--
-- Backed by libsecp256k1 via 'c_ecdsa_sign_der'.  Uses RFC-6979
-- deterministic-k and grinds for low-R, matching Core's
-- @CKey::Sign(hash, sig, /*grind=*/true)@ (`bitcoin-core/src/key.cpp:209-235`).
-- The C wrapper self-verifies the produced signature before returning,
-- so a 'Sig' coming out of this function is guaranteed to verify under
-- the corresponding pubkey.
--
-- Throws via 'error' on a malformed or out-of-range seckey, mirroring
-- the existing total signature.  Callers that can recover from a bad
-- seckey should use 'signMsgMaybe'.
signMsg :: SecKey -> Hash256 -> Sig
signMsg sk hash = case signMsgMaybe sk hash of
  Just s  -> s
  Nothing -> error "signMsg: invalid secp256k1 secret key"

-- | Total variant of 'signMsg'.  Returns 'Nothing' on any failure
-- (invalid seckey, self-verify mismatch).  This is the right primitive
-- for the wallet sign path, which should silently skip an input rather
-- than abort the whole tx.
signMsgMaybe :: SecKey -> Hash256 -> Maybe Sig
signMsgMaybe (SecKey skBytes) (Hash256 hashBytes)
  | BS.length skBytes /= 32 = Nothing
  | BS.length hashBytes /= 32 = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen skBytes $ \(skPtr, _) ->
        BS.useAsCStringLen hashBytes $ \(hashPtr, _) ->
          allocaArray 72 $ \outPtr ->
            alloca $ \lenPtr -> do
              -- Tell the C side our buffer capacity.
              poke lenPtr 72
              ok <- c_ecdsa_sign_der
                      (castPtr skPtr) (castPtr hashPtr)
                      1 {- grind for low-R, matches Core's wallet -}
                      outPtr lenPtr
              if ok == 1
                then do
                  actualLen <- peek lenPtr
                  bs <- BS.packCStringLen (castPtr outPtr, fromIntegral actualLen)
                  return (Just (Sig bs))
                else return Nothing

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

--------------------------------------------------------------------------------
-- Process-wide Signature Verification Cache
--
-- W105 BUG-2: cache absent → EC math paid on every reorg / mempool admit.
-- W105 BUG-9: keys must not be predictable across processes → 32-byte nonce.
-- W105 BUG-13: keys must distinguish DER-malleated sigs that share a txid.
--
-- W159 BUG-17 / W160 BUG-16 FIX: the cache is keyed on Core's
-- @(sighash, pubkey, sig)@ triple — exactly what
-- @SignatureCache::ComputeEntryECDSA@ / @ComputeEntrySchnorr@ commit
-- to (bitcoin-core/src/script/sigcache.cpp:39-49).  The previous key
-- used @(scriptSig, witnessBytes, prevoutScript)@ AND placed the
-- transaction txid in the slot named @sighash@; two inputs of the
-- same tx with identical empty scriptSig + identical witness +
-- identical prevout scriptPubKey collided across distinct per-input
-- sighashes (BIP-143 commits to prevout amount and index), silently
-- short-circuiting input N's script verify on a cache hit from input 0.
-- P0-CDIV: SegWit-malleability chain-split candidate.  Now the cache
-- lookup happens inside @cachedVerifyMsgLax@ / @cachedVerifySchnorr@
-- at the actual EC verify site, where the real per-input sighash,
-- the parsed pubkey, and the raw signature are all in scope.
--------------------------------------------------------------------------------

-- | Cache entry: first 8 bytes of SHA256(nonce || sighash || pubkey || sig)
-- folded into a big-endian Word64.  Matches Core's CheapHash pattern
-- (Map comparisons remain O(1)).
type SigCacheEntry = Word64

{-# NOINLINE globalSigCacheRef #-}
globalSigCacheRef :: IORef (Map SigCacheEntry ())
globalSigCacheRef = unsafePerformIO (newIORef Map.empty)

{-# NOINLINE globalSigCacheNonce #-}
globalSigCacheNonce :: IORef ByteString
globalSigCacheNonce = unsafePerformIO (newIORef (BS.replicate 32 0))

globalSigCacheMaxEntries :: Int
globalSigCacheMaxEntries = 50000

-- | Derive the cache key from the per-process nonce and Core's
-- @(sighash, pubkey, sig)@ triple.
computeGlobalSigCacheKey :: ByteString -> ByteString -> ByteString -> ByteString
                         -> SigCacheEntry
computeGlobalSigCacheKey nonce sighash pubkey sig =
  let material = nonce <> sighash <> pubkey <> sig
      digest   = convert (H.hashWith H.SHA256 material) :: ByteString
  in BS.foldl' (\acc b -> (acc `shiftL` 8) .|. fromIntegral (b :: Word8))
               (0 :: Word64) (BS.take 8 digest)
{-# INLINE computeGlobalSigCacheKey #-}

-- | Look up signature material in the process-global sig cache.
-- Arguments: (sighash, pubkey, sig).
lookupGlobalSigCache :: ByteString -> ByteString -> ByteString -> IO Bool
lookupGlobalSigCache sighash pubkey sig = do
  nonce <- readIORef globalSigCacheNonce
  m     <- readIORef globalSigCacheRef
  let key = computeGlobalSigCacheKey nonce sighash pubkey sig
  return $! Map.member key m

-- | Insert verified signature material into the process-global sig cache.
-- Arguments: (sighash, pubkey, sig).  Evicts the entry with the smallest
-- Word64 key when full.
insertGlobalSigCache :: ByteString -> ByteString -> ByteString -> IO ()
insertGlobalSigCache sighash pubkey sig = do
  nonce <- readIORef globalSigCacheNonce
  let key = computeGlobalSigCacheKey nonce sighash pubkey sig
  atomicModifyIORef' globalSigCacheRef $ \m ->
    let m' = if Map.size m >= globalSigCacheMaxEntries
                then Map.insert key () (Map.deleteMin m)
                else Map.insert key () m
    in (m', ())

-- | (Re-)initialise the process-global sig cache.  Call once during node
-- startup, before any block validation begins.  Generates a fresh
-- /dev/urandom nonce and clears all cached entries so stale results from
-- a prior run or reindex cannot be reused.
initGlobalSigCache :: IO ()
initGlobalSigCache = do
  nonce <- CryptoRandom.getRandomBytes 32 :: IO ByteString
  writeIORef globalSigCacheNonce nonce
  writeIORef globalSigCacheRef Map.empty

-- | ECDSA verify with process-global SigCache.  Caches the
-- @(sighash, pubkey, sig)@ triple on first successful verify, returning
-- True directly on subsequent calls for the same triple.  Negative
-- results are NOT cached (matches Core's @CachingTransactionSignatureChecker@).
cachedVerifyMsgLax :: PubKey -> Sig -> Hash256 -> Bool
cachedVerifyMsgLax pk s@(Sig sigBytes) h@(Hash256 hashBytes) =
  unsafePerformIO $ do
    let pkBytes = serializePubKeyRaw pk
    hit <- lookupGlobalSigCache hashBytes pkBytes sigBytes
    if hit
      then return True
      else do
        let ok = verifyMsgLax pk s h
        when ok $ insertGlobalSigCache hashBytes pkBytes sigBytes
        return ok
{-# NOINLINE cachedVerifyMsgLax #-}

-- | Schnorr verify with process-global SigCache.  Triple is
-- @(sighash, x-only pubkey, 64-byte signature)@.  Like ECDSA, only
-- positive results are cached.
cachedVerifySchnorr :: ByteString -> ByteString -> ByteString -> Bool
cachedVerifySchnorr sig msg pubkey =
  unsafePerformIO $ do
    hit <- lookupGlobalSigCache msg pubkey sig
    if hit
      then return True
      else do
        let ok = verifySchnorr sig msg pubkey
        when ok $ insertGlobalSigCache msg pubkey sig
        return ok
{-# NOINLINE cachedVerifySchnorr #-}

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
-- Recoverable / Message Signing (signmessage / verifymessage, BIP-137 era)
--------------------------------------------------------------------------------

-- | Message magic prefix used by Bitcoin Core's signmessage / verifymessage.
-- See @bitcoin-core/src/common/signmessage.cpp@.
messageMagic :: ByteString
messageMagic = TE.encodeUtf8 (T.pack "Bitcoin Signed Message:\n")

-- | Hash a message exactly the way Bitcoin Core does: double-SHA256 over
-- @CompactSize(magic) || magic || CompactSize(message) || message@.
-- This matches @MessageHash@ in @src/common/signmessage.cpp@.
messageHash :: Text -> Hash256
messageHash msg =
  let msgBytes = TE.encodeUtf8 msg
      buf = runPut $ do
              putVarBytes messageMagic
              putVarBytes msgBytes
  in doubleSHA256 buf

-- | Derive the compressed public key (33 bytes) for a secret key.
-- Returns 'Nothing' if the seckey is invalid (out of range, all zero, etc.).
derivePubKeyCompressed :: SecKey -> Maybe ByteString
derivePubKeyCompressed = derivePubKeyRaw 1 33

-- | Derive the uncompressed public key (65 bytes) for a secret key.
derivePubKeyUncompressed :: SecKey -> Maybe ByteString
derivePubKeyUncompressed = derivePubKeyRaw 0 65

derivePubKeyRaw :: CInt -> Int -> SecKey -> Maybe ByteString
derivePubKeyRaw compressedFlag bufLen (SecKey skBytes)
  | BS.length skBytes /= 32 = Nothing
  | otherwise = unsafePerformIO $ do
      BS.useAsCStringLen skBytes $ \(skPtr, _) ->
        allocaArray bufLen $ \outPtr ->
          alloca $ \lenPtr -> do
            ok <- c_ec_pubkey_create
                    (castPtr skPtr) compressedFlag
                    outPtr lenPtr
            if ok == 1
              then do
                actualLen <- peek lenPtr
                bs <- BS.packCStringLen (castPtr outPtr, fromIntegral actualLen)
                return (Just bs)
              else return Nothing

-- | Recover the full uncompressed (65-byte) form of a 33-byte compressed
-- public key.  The input must start with 0x02 or 0x03 and contain a valid
-- X coordinate on the secp256k1 curve.  Returns 'Nothing' if the X
-- coordinate is not on the curve, mirroring libsecp256k1's parse failure.
--
-- Used by 'getCompressedScript' (Storage) to inflate Core's
-- ScriptCompression tags 0x04/0x05 (uncompressed-P2PK) back into the
-- 65-byte serialized pubkey form.
--
-- Reference: bitcoin-core/src/compressor.cpp DecompressScript.
decompressPubKey :: ByteString -> Maybe ByteString
decompressPubKey compressed33
  | BS.length compressed33 /= 33 = Nothing
  | otherwise = unsafePerformIO $
      BS.useAsCStringLen compressed33 $ \(inPtr, _) ->
        allocaArray 65 $ \outPtr -> do
          ok <- c_ec_pubkey_decompress (castPtr inPtr) outPtr
          if ok == 1
            then Just <$> BS.packCStringLen (castPtr outPtr, 65)
            else return Nothing

-- | Produce a 65-byte compact recoverable ECDSA signature over @msghash@.
-- The header byte encodes the recovery id and whether the public key is
-- compressed (header = 27 + recid + (4 if compressed)).
-- Mirrors @CKey::SignCompact@ in @bitcoin-core/src/key.cpp@.
signCompact :: SecKey -> Bool -> Hash256 -> Maybe ByteString
signCompact (SecKey skBytes) compressed (Hash256 hashBytes)
  | BS.length skBytes /= 32 = Nothing
  | BS.length hashBytes /= 32 = Nothing
  | otherwise = unsafePerformIO $ do
      BS.useAsCStringLen skBytes $ \(skPtr, _) ->
        BS.useAsCStringLen hashBytes $ \(hashPtr, _) ->
          allocaArray 65 $ \outPtr -> do
            ok <- c_ecdsa_sign_recoverable_compact
                    (castPtr skPtr) (castPtr hashPtr)
                    (if compressed then 1 else 0) outPtr
            if ok == 1
              then Just <$> BS.packCStringLen (castPtr outPtr, 65)
              else return Nothing

-- | Recover the public key from a 65-byte compact recoverable signature
-- and a message hash.  Returns the bytes of the recovered key, in either
-- compressed (33 byte) or uncompressed (65 byte) form, as encoded by the
-- header byte (header & 4).
recoverCompact :: ByteString -> Hash256 -> Maybe ByteString
recoverCompact sig65 (Hash256 hashBytes)
  | BS.length sig65 /= 65 = Nothing
  | BS.length hashBytes /= 32 = Nothing
  | otherwise =
      let header = BS.head sig65
      in if header < 27 || header > 34
         then Nothing
         else
           let compressed = (header - 27) >= 4
               bufLen = if compressed then 33 else 65
           in unsafePerformIO $ do
                BS.useAsCStringLen sig65 $ \(sigPtr, _) ->
                  BS.useAsCStringLen hashBytes $ \(hashPtr, _) ->
                    allocaArray bufLen $ \outPtr ->
                      alloca $ \lenPtr -> do
                        ok <- c_ecdsa_recover_compact
                                (castPtr sigPtr) (castPtr hashPtr)
                                (if compressed then 1 else 0)
                                outPtr lenPtr
                        if ok == 1
                          then do
                            actualLen <- peek lenPtr
                            bs <- BS.packCStringLen
                                    (castPtr outPtr, fromIntegral actualLen)
                            return (Just bs)
                          else return Nothing

-- | Sign a UTF-8 message with a private key, exactly like Bitcoin Core's
-- @signmessage@ / @signmessagewithprivkey@.  Returns the 65-byte recoverable
-- compact signature on success.  The caller is responsible for base64
-- encoding for wire transport.
signMessage :: SecKey -> Bool -> Text -> Maybe ByteString
signMessage sk compressed msg = signCompact sk compressed (messageHash msg)

-- | Recover the public key bytes used to sign a UTF-8 message.  Returns
-- the same compressed/uncompressed encoding implied by the signature
-- header byte.  Used by 'verifymessage' to compare against the address.
recoverMessagePubKey :: ByteString -> Text -> Maybe ByteString
recoverMessagePubKey sig msg = recoverCompact sig (messageHash msg)

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

-- | Count how many occurrences 'findAndDelete' would remove (the @found@
-- value in Bitcoin Core's @FindAndDelete@, interpreter.cpp:229). Walks the
-- script at opcode boundaries exactly like 'findAndDelete', but returns the
-- match count instead of the rewritten script. Used to implement the
-- SCRIPT_VERIFY_CONST_SCRIPTCODE reject rule (interpreter.cpp:331,1147):
-- in legacy (BASE) scripts, if FindAndDelete removed >= 1 occurrence and the
-- CONST_SCRIPTCODE flag is set, the script fails with SIG_FINDANDDELETE.
findAndDeleteCount :: ByteString -> ByteString -> Int
findAndDeleteCount script pattern
  | BS.null pattern = 0
  | otherwise = go script 0
  where
    patLen = BS.length pattern

    go :: ByteString -> Int -> Int
    go remaining found
      | BS.null remaining = found
      | otherwise =
          let matchesHere = BS.length remaining >= patLen &&
                            BS.take patLen remaining == pattern
          in if matchesHere
             then go (BS.drop patLen remaining) (found + 1)
             else let (_, nextRemaining, _) = getNextOpcode remaining
                  in go nextRemaining found

    getNextOpcode :: ByteString -> (ByteString, ByteString, Int)
    getNextOpcode bs
      | BS.null bs = (BS.empty, BS.empty, 0)
      | otherwise =
          let op = BS.head bs
          in case getPushDataLength op (BS.tail bs) of
               Just (dataLen, prefixLen) ->
                 let totalLen = 1 + prefixLen + dataLen
                 in (BS.take totalLen bs, BS.drop totalLen bs, totalLen)
               Nothing -> (BS.take 1 bs, BS.tail bs, 1)

    getPushDataLength :: Word8 -> ByteString -> Maybe (Int, Int)
    getPushDataLength op rest
      | op <= 0x4b = Just (fromIntegral op, 0)
      | op == 0x4c && not (BS.null rest) =
          Just (fromIntegral (BS.head rest), 1)
      | op == 0x4d && BS.length rest >= 2 =
          let len = fromIntegral (BS.index rest 0) +
                    fromIntegral (BS.index rest 1) * 256
          in Just (len, 2)
      | op == 0x4e && BS.length rest >= 4 =
          let len = fromIntegral (BS.index rest 0) +
                    fromIntegral (BS.index rest 1) * 256 +
                    fromIntegral (BS.index rest 2) * 65536 +
                    fromIntegral (BS.index rest 3) * 16777216
          in Just (len, 4)
      | otherwise = Nothing

-- | The codeseparator-sliced subscript that Bitcoin Core's
-- @EvalChecksigPreTapscript@ runs FindAndDelete over:
-- @CScript scriptCode(pbegincodehash, pend)@ (interpreter.cpp:326) — i.e. the
-- subscript from the byte just after the last executed OP_CODESEPARATOR to the
-- end. Unlike 'scriptCodeForSighash' this does NOT strip OP_CODESEPARATOR
-- bytes, matching Core's @found@ count for the CONST_SCRIPTCODE reject.
subscriptAfterCodeSep :: ByteString -> Word32 -> ByteString
subscriptAfterCodeSep subscript codeSepPos
  | codeSepPos /= 0xFFFFFFFF && fromIntegral codeSepPos < BS.length subscript
      = BS.drop (fromIntegral codeSepPos) subscript
  | otherwise = subscript

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

-- | Compute the witness transaction ID (BIP-141 wtxid): SHA256d of the
-- full serialization INCLUDING witness data. For non-segwit transactions
-- (no witness items present), this equals the txid.
--
-- Reference: BIP-141 "Specification of Witness Program" and BIP-339
-- "WTXID-based transaction relay".
--
-- Note: by BIP-141 the coinbase wtxid is conventionally all-zeroes when
-- used in the witness commitment merkle, but this function returns the
-- structural hash. Callers that need the BIP-141 commitment-merkle
-- coinbase value should use a zero-hash directly.
computeWtxid :: Tx -> Wtxid
computeWtxid tx = Wtxid $ doubleSHA256 (encode tx)

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

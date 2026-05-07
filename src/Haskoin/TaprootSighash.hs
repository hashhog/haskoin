{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
-- | BIP-341 Taproot signature hash computation.
--
-- Reference: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
--
-- This module computes the message that gets fed into Schnorr signature
-- verification for Taproot key-path spends and tapscript OP_CHECKSIG.
--
-- Validated against bitcoin-core/src/test/data/bip341_wallet_vectors.json
-- via tools/bip341-vector-runner/haskoin-shim — produces byte-perfect
-- sigMsg + sigHash for all 7 keyPathSpending vectors.
module Haskoin.TaprootSighash
  ( -- * Hash type constants
    sighashDefault
  , sighashAll
  , sighashNone
  , sighashSingle
  , sighashAnyoneCanPay
  , isValidTaprootHashType
    -- * Sighash inputs
  , TaprootPrevouts(..)
  , TapscriptContext(..)
  , TaprootSighashError(..)
    -- * Sighash entry points
  , computeTaprootSighash
  , buildSigMsg
    -- * BIP-342 tapscript primitives
  , tapscriptLeafVersion
  , defaultCodesepPos
  , tapleafHashWith
    -- * BIP-341 control block (script-path)
  , ControlBlock(..)
  , encodeControlBlock
  , decodeControlBlock
  ) where

import Data.Bits ((.&.), (.|.), complement)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (runPut, putWord8, putWord32le, putInt32le,
                       putWord64le, putByteString)
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int64)

import Haskoin.Crypto (sha256, taggedHash)
import Haskoin.Types (Tx(..), TxIn(..), TxOut(..), OutPoint(..),
                      Hash256(..), TxId(..), putVarInt)

sighashDefault, sighashAll, sighashNone, sighashSingle, sighashAnyoneCanPay :: Word8
sighashDefault     = 0x00
sighashAll         = 0x01
sighashNone        = 0x02
sighashSingle      = 0x03
sighashAnyoneCanPay = 0x80

-- | Per BIP-341, the only valid hash_type bytes are these:
-- 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83.
isValidTaprootHashType :: Word8 -> Bool
isValidTaprootHashType ht =
  let upper = ht .&. complement 0x83
  in upper == 0 && (ht == 0x00 || (ht .&. 0x03) /= 0x00)

-- | Per-input prevout context required by BIP-341.
data TaprootPrevouts = TaprootPrevouts
  { taprootAmounts :: ![Word64]      -- ^ value for each input
  , taprootScripts :: ![ByteString]  -- ^ scriptPubKey for each input
  } deriving (Show)

-- | Optional script-path context (for tapscript OP_CHECKSIG, ext_flag = 1).
data TapscriptContext = TapscriptContext
  { tapleafHash  :: !ByteString  -- ^ 32-byte BIP-341 TapLeaf hash
  , codesepPos   :: !Word32      -- ^ position of last OP_CODESEPARATOR (0xFFFFFFFF if none)
  } deriving (Show)

data TaprootSighashError
  = InvalidHashType
  | InputIndexOutOfRange
  | PrevoutsLengthMismatch
  | SighashSingleNoMatchingOutput
  | InvalidTapleafHashLength
  deriving (Show, Eq)

-- | Compute the BIP-341 Taproot sighash. Returns the 32-byte tagged
-- hash that must equal the message argument of the Schnorr verify.
computeTaprootSighash
  :: Tx
  -> Int                         -- ^ input_index
  -> TaprootPrevouts
  -> Word8                       -- ^ hash_type
  -> Maybe ByteString            -- ^ optional annex (with leading 0x50)
  -> Maybe TapscriptContext      -- ^ Just _ for tapscript script-path
  -> Either TaprootSighashError ByteString
computeTaprootSighash tx idx prevouts ht annex sp = do
  msg <- buildSigMsg tx idx prevouts ht annex sp
  pure (taggedHash "TapSighash" msg)

-- | Build the BIP-341 "Common signature message" preimage.
--
-- Exposed separately so callers (e.g. the BIP-341 vector validation
-- shim) can compare against the test-vector @intermediary.sigMsg@.
buildSigMsg
  :: Tx
  -> Int
  -> TaprootPrevouts
  -> Word8
  -> Maybe ByteString
  -> Maybe TapscriptContext
  -> Either TaprootSighashError ByteString
buildSigMsg tx idx (TaprootPrevouts amounts scripts) ht annex sp
  | idx < 0 || idx >= length (txInputs tx) = Left InputIndexOutOfRange
  | length amounts /= length (txInputs tx) || length scripts /= length (txInputs tx) =
      Left PrevoutsLengthMismatch
  | not (isValidTaprootHashType ht) = Left InvalidHashType
  | maybe False (\s -> BS.length (tapleafHash s) /= 32) sp =
      Left InvalidTapleafHashLength
  | otherwise = do
      -- 0x00 (SIGHASH_DEFAULT) behaves like SIGHASH_ALL for branching, but
      -- the byte serialized into the preimage is the original hash_type.
      let outputType = if ht == sighashDefault then sighashAll else (ht .&. 0x03)
          anyoneCanPay = (ht .&. sighashAnyoneCanPay) /= 0
          extFlag = case sp of Just _ -> 1 :: Word8; Nothing -> 0

      -- SIGHASH_SINGLE-with-no-matching-output check.
      case () of
        _ | outputType == sighashSingle && idx >= length (txOutputs tx) ->
              Left SighashSingleNoMatchingOutput
          | otherwise -> Right ()

      let inputs = txInputs tx
          outputs = txOutputs tx

      let preimage = runPut $ do
            -- 1. Epoch
            putWord8 0x00
            -- 2. hash_type (original byte)
            putWord8 ht
            -- 3. nVersion
            putInt32le (txVersion tx)
            -- 4. nLockTime
            putWord32le (txLockTime tx)

            -- 5-8. sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences
            if not anyoneCanPay
              then do
                putByteString (sha256 (concatBS (map serPrevout inputs)))
                putByteString (sha256 (concatBS (map encWord64le amounts)))
                putByteString (sha256 (concatBS (map serVarBytes scripts)))
                putByteString (sha256 (concatBS (map (encWord32le . txInSequence) inputs)))
              else pure ()

            -- 9. sha_outputs (skipped for SIGHASH_NONE/SINGLE)
            if outputType /= sighashNone && outputType /= sighashSingle
              then putByteString (sha256 (concatBS (map serTxOut outputs)))
              else pure ()

            -- 10. spend_type
            let spendType =
                  (extFlag * 2) .|. (case annex of Just _ -> 1; Nothing -> 0)
            putWord8 spendType

            -- 11. Per-input data
            if anyoneCanPay
              then do
                putByteString (serPrevout (inputs !! idx))
                putWord64le (amounts !! idx)
                putByteString (serVarBytes (scripts !! idx))
                putWord32le (txInSequence (inputs !! idx))
              else putWord32le (fromIntegral idx)

            -- 12. sha_annex
            case annex of
              Just a -> putByteString (sha256 (serVarBytes a))
              Nothing -> pure ()

            -- 13. sha_single_output (SIGHASH_SINGLE only, after annex)
            if outputType == sighashSingle
              then putByteString (sha256 (serTxOut (outputs !! idx)))
              else pure ()

            -- 14. Tapscript extension (ext_flag = 1)
            case sp of
              Just (TapscriptContext tlh csp) -> do
                putByteString tlh
                putWord8 0x00  -- key_version
                putWord32le csp
              Nothing -> pure ()

      Right preimage

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

concatBS :: [ByteString] -> ByteString
concatBS = BS.concat

encWord32le :: Word32 -> ByteString
encWord32le w = runPut (putWord32le w)

encWord64le :: Word64 -> ByteString
encWord64le w = runPut (putWord64le w)

serPrevout :: TxIn -> ByteString
serPrevout TxIn{txInPrevOutput = OutPoint (TxId (Hash256 h)) i} =
  h <> encWord32le i

serTxOut :: TxOut -> ByteString
serTxOut TxOut{txOutValue = v, txOutScript = s} =
  runPut (putWord64le v >> putVarInt (fromIntegral (BS.length s)) >> putByteString s)

serVarBytes :: ByteString -> ByteString
serVarBytes bs = runPut (putVarInt (fromIntegral (BS.length bs)) >> putByteString bs)

------------------------------------------------------------------------------
-- BIP-342 tapscript primitives
------------------------------------------------------------------------------

-- | The currently-defined BIP-342 tapscript leaf version (0xc0).
--
-- Other even leaf versions are reserved by BIP-341 for future soft forks
-- (the low bit is reserved for the parity flag in the control block);
-- only 0xc0 is currently interpreted as tapscript.
tapscriptLeafVersion :: Word8
tapscriptLeafVersion = 0xc0

-- | Sentinel "no OP_CODESEPARATOR has executed" value for the BIP-341
-- script-path sighash extension @codesep_pos@ field (4-byte LE).
--
-- See @bitcoin-core/src/script/interpreter.cpp::SignatureHashSchnorr@:
--   @codeseparator_pos = 0xFFFFFFFF@ unless OP_CODESEPARATOR has executed
--   in the current tapscript leaf, in which case it is the byte offset
--   of the most recent CODESEPARATOR.  haskoin's interpreter currently
--   does not surface a non-default value via the sign path; leave at
--   sentinel for the wallet wave (W18).
defaultCodesepPos :: Word32
defaultCodesepPos = 0xFFFFFFFF

-- | BIP-341 TapLeaf hash:
--
--   @tagged_hash("TapLeaf", leaf_version || compactsize(script) || script)@
--
-- Mirrors @bitcoin-core/src/script/interpreter.cpp::ComputeTapleafHash@ +
-- haskoin's own verifier-side computation in
-- @Haskoin.Script.verifySegWitScriptWithFlags@ (script-path branch).
-- W13's CompactSize audit (haskoin commit log) verified this encoding
-- handles all four size classes (<0xfd, u16, u32, u64).
tapleafHashWith
  :: Word8         -- ^ leaf version (0xc0 for tapscript)
  -> ByteString    -- ^ leaf script bytes
  -> ByteString    -- ^ 32-byte tagged hash
tapleafHashWith leafVersion script =
  taggedHash "TapLeaf"
    (BS.singleton leafVersion <> serVarBytes script)

------------------------------------------------------------------------------
-- BIP-341 control block (witness item N for tapscript script-path spends)
------------------------------------------------------------------------------

-- | BIP-341 control block describing how the tapleaf is embedded in the
-- output Taproot tree.
--
-- Wire format (1 + 32 + 32k bytes, k = Merkle path depth):
--
--   * byte 0:           @(leafVersion .&. 0xfe) .|. parity@
--   * bytes 1..33:      32-byte x-only internal pubkey
--   * bytes 33..:       k × 32-byte sibling hashes (Merkle path)
--
-- See @bitcoin-core/src/script/interpreter.cpp ExecuteWitnessScript@ +
-- @bitcoin-core/src/script/script.h TAPROOT_CONTROL_*@.  For BIP-86 keypath
-- spends there is no control block (it's a key-path spend); this type
-- is exclusively for script-path spends.
data ControlBlock = ControlBlock
  { cbLeafVersion    :: !Word8       -- ^ leaf version, low bit MUST be 0 (it is overwritten by parity)
  , cbInternalPubkey :: !ByteString  -- ^ 32-byte x-only internal pubkey
  , cbParity         :: !Word8       -- ^ 0 or 1 — parity of internal-pubkey-tweaked output Y
  , cbMerklePath     :: ![ByteString] -- ^ list of 32-byte sibling hashes (depth k, may be empty for single-leaf)
  } deriving (Show, Eq)

-- | Serialise a 'ControlBlock' to its on-the-wire byte form.
--
-- Returns the canonical byte sequence the verifier sees as witness item
-- N.  Length is always @33 + 32 * length cbMerklePath@.
--
-- Pre-conditions (caller's responsibility; this encoder is total over its
-- inputs but garbage-in-garbage-out for invalid lengths):
--   * @cbInternalPubkey@ is exactly 32 bytes
--   * each entry of @cbMerklePath@ is exactly 32 bytes
--   * @cbParity@ is 0 or 1 (only the low bit is consulted; higher bits
--     would corrupt @leaf_version@ on round-trip)
encodeControlBlock :: ControlBlock -> ByteString
encodeControlBlock ControlBlock{..} =
  let byte0 = (cbLeafVersion .&. 0xfe) .|. (cbParity .&. 0x01)
  in BS.concat (BS.singleton byte0 : cbInternalPubkey : cbMerklePath)

-- | Decode the on-the-wire form of a 'ControlBlock'.
--
-- Returns 'Nothing' if the input is shorter than 33 bytes or its length
-- past byte 33 is not a multiple of 32.  Mirrors the structural validation
-- @bitcoin-core/src/script/interpreter.cpp@ performs before walking the
-- Merkle path.  The returned 'cbLeafVersion' has its low bit cleared and
-- the parity is stored separately in 'cbParity'; @encode . decode@ is the
-- identity over byte strings whose byte-0 low bit equals their parity.
decodeControlBlock :: ByteString -> Maybe ControlBlock
decodeControlBlock bs
  | BS.length bs < 33 = Nothing
  | (BS.length bs - 33) `mod` 32 /= 0 = Nothing
  | otherwise =
      let b0      = BS.head bs
          leafV   = b0 .&. 0xfe
          parity  = b0 .&. 0x01
          ikey    = BS.take 32 (BS.drop 1 bs)
          rest    = BS.drop 33 bs
          chunks  = chunkN 32 rest
      in Just ControlBlock
           { cbLeafVersion    = leafV
           , cbInternalPubkey = ikey
           , cbParity         = parity
           , cbMerklePath     = chunks
           }
  where
    chunkN n b
      | BS.null b = []
      | otherwise = BS.take n b : chunkN n (BS.drop n b)

{-# LANGUAGE OverloadedStrings #-}
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

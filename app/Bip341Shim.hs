{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | BIP-341 sighash shim — drives haskoin's @computeTaprootSighash@
-- against the bip341-vector-runner's stdin/stdout JSON protocol.
--
-- Input (one JSON object per line on stdin):
--   { "tx_hex": "...", "input_index": 0,
--     "spent_amounts": [12345, ...],
--     "spent_scripts": ["hex...", ...],
--     "hash_type": 0,
--     "annex_hex": null }
--
-- Output (one JSON object per line on stdout):
--   { "sig_msg": "hex...", "sig_hash": "hex..." }
module Main where

import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import qualified Data.Aeson.KeyMap as KM
import Data.Aeson ((.:), (.:?))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Serialize (decode, runGet, runPut)
import qualified Data.Serialize.Get as G
import qualified Data.Serialize.Put as P
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int32)
import System.IO (hFlush, stdout, isEOF)
import qualified Data.Scientific as Sci
import Data.Maybe (fromMaybe)
import Control.Monad (forM)

import Haskoin.TaprootSighash
  (TaprootPrevouts(..), buildSigMsg, computeTaprootSighash)
import Haskoin.Types
  (Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..),
   getVarInt')

------------------------------------------------------------------------------
-- Hex helpers
------------------------------------------------------------------------------

decodeHex :: T.Text -> Either String BS.ByteString
decodeHex t = case B16.decode (TE.encodeUtf8 t) of
  Right b -> Right b
  Left e  -> Left ("hex decode: " <> e)

encodeHex :: BS.ByteString -> T.Text
encodeHex = TE.decodeUtf8 . B16.encode

------------------------------------------------------------------------------
-- Tx parser (legacy serialization, no witness — what the BIP-341 vectors use)
------------------------------------------------------------------------------

parseTxLegacy :: BS.ByteString -> Either String Tx
parseTxLegacy bs = runGet getTxLegacy bs
  where
    getTxLegacy :: G.Get Tx
    getTxLegacy = do
      version <- G.getInt32le
      n_in <- getVarInt'
      inputs <- forM [1 .. fromIntegral n_in] $ \_ -> do
        prev_hash <- G.getByteString 32
        prev_idx <- G.getWord32le
        script_len <- getVarInt'
        _scriptsig <- G.getByteString (fromIntegral script_len)
        seq_ <- G.getWord32le
        pure TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 prev_hash)) prev_idx
          , txInScript = _scriptsig
          , txInSequence = seq_
          }
      n_out <- getVarInt'
      outputs <- forM [1 .. fromIntegral n_out] $ \_ -> do
        amount <- G.getWord64le
        spk_len <- getVarInt'
        spk <- G.getByteString (fromIntegral spk_len)
        pure TxOut { txOutValue = amount, txOutScript = spk }
      lock_time <- G.getWord32le
      pure Tx
        { txVersion = version
        , txInputs = inputs
        , txOutputs = outputs
        , txWitness = []
        , txLockTime = lock_time
        }

------------------------------------------------------------------------------
-- Request / response
------------------------------------------------------------------------------

data Request = Request
  { reqTxHex       :: T.Text
  , reqInputIndex  :: Int
  , reqAmounts     :: [Word64]
  , reqScripts     :: [T.Text]   -- hex
  , reqHashType    :: Word8
  , reqAnnexHex    :: Maybe T.Text
  }

instance A.FromJSON Request where
  parseJSON = A.withObject "Request" $ \o -> do
    Request
      <$> o .:  "tx_hex"
      <*> o .:  "input_index"
      <*> o .:  "spent_amounts"
      <*> o .:  "spent_scripts"
      <*> (fromIntegral <$> (o .: "hash_type" :: A.Parser Int))
      <*> o .:? "annex_hex"

processLine :: BL.ByteString -> IO ()
processLine line = do
  case A.eitherDecode line of
    Left e -> putStrLn $ "{\"error\":\"json parse: " <> e <> "\"}"
    Right (req :: Request) -> do
      case decodeHex (reqTxHex req) of
        Left e -> putStrLn $ "{\"error\":\"tx hex: " <> e <> "\"}"
        Right tx_bytes ->
          case parseTxLegacy tx_bytes of
            Left e -> putStrLn $ "{\"error\":\"tx parse: " <> e <> "\"}"
            Right tx -> do
              scripts_e <- pure $ traverse decodeHex (reqScripts req)
              annex_e <- pure $ traverse decodeHex (reqAnnexHex req)
              case (scripts_e, annex_e) of
                (Left e, _) -> putStrLn $ "{\"error\":\"script hex: " <> e <> "\"}"
                (_, Left e) -> putStrLn $ "{\"error\":\"annex hex: " <> e <> "\"}"
                (Right scripts, Right annex) -> do
                  let prevouts = TaprootPrevouts (reqAmounts req) scripts
                  case buildSigMsg tx (reqInputIndex req) prevouts (reqHashType req) annex Nothing of
                    Left e -> putStrLn $ "{\"error\":\"buildSigMsg: " <> show e <> "\"}"
                    Right msg -> case computeTaprootSighash tx (reqInputIndex req) prevouts (reqHashType req) annex Nothing of
                      Left e -> putStrLn $ "{\"error\":\"computeTaprootSighash: " <> show e <> "\"}"
                      Right h -> do
                        let out = "{\"sig_msg\":\"" <> encodeHex msg
                                 <> "\",\"sig_hash\":\"" <> encodeHex h <> "\"}"
                        putStrLn (T.unpack out)

main :: IO ()
main = loop
  where
    loop = do
      eof <- isEOF
      if eof
        then pure ()
        else do
          line <- BL.fromStrict . TE.encodeUtf8 . T.pack <$> getLine
          if BL.null line
            then loop
            else do
              processLine line
              hFlush stdout
              loop

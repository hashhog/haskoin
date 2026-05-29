{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Phase B @verifyscript@ shim for haskoin.
--
-- Drives haskoin's real consensus script interpreter
-- ('Haskoin.Script.verifyScriptWithFlags') against the Phase B bounded
-- reject-bar harness (tools/phaseb-vectors). Generalizes the proven
-- rustoshi-shim/src/main.rs template to Haskell, reusing haskoin's OWN
-- tx serialization + txid ('Haskoin.Crypto.computeTxId') so any
-- signature-dependent row computes a byte-identical sighash.
--
-- It reconstructs Core's crediting + spending transaction pair exactly
-- as bitcoin-core/src/test/util/transaction_utils.cpp does (and as the
-- existing test/ScriptVectors.hs harness does):
--   credit = v1, null prevout, scriptSig 0x00 0x00 (OP_0 OP_0), one
--            output {test scriptPubKey, amount}, sequence 0xffffffff.
--   spend  = v1, spends credit.txid() vout 0 with the test scriptSig +
--            witness, one empty-script output with the same amount.
--
-- Protocol (line-delimited JSON on stdin/stdout):
--   request:  {"op":"verifyscript",
--              "scriptSig_hex":"...","scriptPubKey_hex":"...",
--              "witness":["hex",...],"amount_sats":0,
--              "flags":["P2SH","WITNESS",...]}
--   response: {"result":true}                  (accept)
--             {"result":false,"reason":"..."}  (reject)
--             {"error":"..."}                  (could not evaluate)
module Main where

import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import Data.Aeson ((.:?))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word64)
import System.IO (hFlush, stdout, isEOF)
import Control.Exception (evaluate, try, SomeException)

import Haskoin.Types
  (Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..))
import Haskoin.Crypto (computeTxId)
import Haskoin.Script
  ( ScriptFlags, ScriptVerifyFlag(..), emptyFlags, flagSet
  , verifyScriptWithFlags )

------------------------------------------------------------------------------
-- Hex helpers
------------------------------------------------------------------------------

decodeHex :: T.Text -> Either String BS.ByteString
decodeHex t = case B16.decode (TE.encodeUtf8 t) of
  Right b -> Right b
  Left e  -> Left ("hex decode: " <> e)

escapeJson :: String -> String
escapeJson = concatMap esc
  where
    esc '\\' = "\\\\"
    esc '"'  = "\\\""
    esc '\n' = "\\n"
    esc '\r' = "\\r"
    esc '\t' = "\\t"
    esc c    = [c]

------------------------------------------------------------------------------
-- Flag-token mapping (port of rustoshi-shim build_flags / Core's
-- ScriptFlagNamesToEnum, interpreter.cpp:2168). All 22 tokens map to a
-- haskoin 'ScriptVerifyFlag'. Unknown tokens -> Left (shim returns
-- {"error":...} so the driver skips, never miscounts).
------------------------------------------------------------------------------

mapFlag :: T.Text -> Either String [ScriptVerifyFlag]
mapFlag name = case name of
  "P2SH"                                  -> Right [VerifyP2SH]
  "STRICTENC"                             -> Right [VerifyStrictEncoding]
  "DERSIG"                                -> Right [VerifyDERSig]
  "LOW_S"                                 -> Right [VerifyLowS]
  "SIGPUSHONLY"                           -> Right [VerifySigPushOnly]
  "MINIMALDATA"                           -> Right [VerifyMinimalData]
  "NULLDUMMY"                             -> Right [VerifyNullDummy]
  "DISCOURAGE_UPGRADABLE_NOPS"            -> Right [VerifyDiscourageUpgradableNops]
  "CLEANSTACK"                            -> Right [VerifyCleanStack]
  "MINIMALIF"                             -> Right [VerifyMinimalIf]
  "NULLFAIL"                              -> Right [VerifyNullFail]
  "CHECKLOCKTIMEVERIFY"                   -> Right [VerifyCheckLockTimeVerify]
  "CHECKSEQUENCEVERIFY"                   -> Right [VerifyCheckSequenceVerify]
  "WITNESS"                               -> Right [VerifyWitness]
  "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" -> Right [VerifyDiscourageUpgradableWitnessProgram]
  "WITNESS_PUBKEYTYPE"                    -> Right [VerifyWitnessPubkeyType]
  "CONST_SCRIPTCODE"                      -> Right [VerifyConstScriptcode]
  "TAPROOT"                               -> Right [VerifyTaproot]
  "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"      -> Right [VerifyDiscourageUpgradablePubkeyType]
  "DISCOURAGE_OP_SUCCESS"                 -> Right [VerifyDiscourageOpSuccess]
  "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" -> Right [VerifyDiscourageUpgradableTaprootVersion]
  "NONE"                                  -> Right []
  ""                                      -> Right []
  other                                   -> Left ("unknown flag token: " <> T.unpack other)

buildFlags :: [T.Text] -> Either String ScriptFlags
buildFlags toks = case traverse mapFlag toks of
  Left e   -> Left e
  Right fs -> let allFs = concat fs
              in Right (if null allFs then emptyFlags else flagSet allFs)

------------------------------------------------------------------------------
-- Tx reconstruction (mirrors test/ScriptVectors.hs buildCreditingTx /
-- buildSpendingTx, which reuse haskoin's computeTxId).
------------------------------------------------------------------------------

buildCreditingTx :: BS.ByteString -> Word64 -> Tx
buildCreditingTx scriptPubKeyBytes amount = Tx
  { txVersion  = 1
  , txInputs   = [TxIn
      { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
      , txInScript     = BS.pack [0x00, 0x00]   -- OP_0 OP_0
      , txInSequence   = 0xffffffff
      }]
  , txOutputs  = [TxOut { txOutValue = amount, txOutScript = scriptPubKeyBytes }]
  , txWitness  = [[]]
  , txLockTime = 0
  }

buildSpendingTx :: Tx -> BS.ByteString -> [BS.ByteString] -> Word64 -> Tx
buildSpendingTx creditingTx scriptSigBytes witnessStack amount = Tx
  { txVersion  = 1
  , txInputs   = [TxIn
      { txInPrevOutput = OutPoint (computeTxId creditingTx) 0
      , txInScript     = scriptSigBytes
      , txInSequence   = 0xffffffff
      }]
  , txOutputs  = [TxOut { txOutValue = amount, txOutScript = BS.empty }]
  , txWitness  = [witnessStack]
  , txLockTime = 0
  }

------------------------------------------------------------------------------
-- Request decoding via aeson
------------------------------------------------------------------------------

data Request = Request
  { reqScriptSigHex :: T.Text
  , reqScriptPubHex :: T.Text
  , reqWitness      :: [T.Text]   -- hex items, wire order
  , reqAmount       :: Word64
  , reqFlags        :: [T.Text]
  }

instance A.FromJSON Request where
  parseJSON = A.withObject "Request" $ \o -> Request
    <$> o .:? "scriptSig_hex"   A..!= ""
    <*> o .:? "scriptPubKey_hex" A..!= ""
    <*> o .:? "witness"         A..!= []
    <*> (toW64 <$> o .:? "amount_sats" A..!= (0 :: Double))
    <*> o .:? "flags"           A..!= []
    where toW64 d = round (d :: Double)

processLine :: BL.ByteString -> IO String
processLine line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case decodeReq req of
      Left e   -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right (ssig, spk, wit, amount, flags) -> do
        let credit = buildCreditingTx spk amount
            spend  = buildSpendingTx credit ssig wit amount
            -- single input: prevouts are the test scriptPubKey + amount,
            -- required for the BIP-341 Taproot sighash; ignored for
            -- legacy / SegWit-v0.
            spentAmounts = [amount]
            spentScripts = [spk]
            res = verifyScriptWithFlags flags spend 0 spk amount
                                        spentAmounts spentScripts
        r <- try (evaluate (forceEither res))
               :: IO (Either SomeException (Either String Bool))
        pure $ case r of
          Left ex             -> "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right (Left err)    -> "{\"result\":false,\"reason\":\"" <> escapeJson err <> "\"}"
          Right (Right True)  -> "{\"result\":true}"
          Right (Right False) -> "{\"result\":false,\"reason\":\"EVAL_FALSE\"}"
  where
    forceEither x = case x of
      Left s  -> Left $! (length s `seq` s)
      Right b -> Right $! b

decodeReq :: Request -> Either String (BS.ByteString, BS.ByteString, [BS.ByteString], Word64, ScriptFlags)
decodeReq req = do
  ssig  <- decodeHex (reqScriptSigHex req)
  spk   <- decodeHex (reqScriptPubHex req)
  wit   <- traverse decodeHex (reqWitness req)
  flags <- buildFlags (reqFlags req)
  Right (ssig, spk, wit, reqAmount req, flags)

main :: IO ()
main = loop
  where
    loop = do
      eof <- isEOF
      if eof
        then pure ()
        else do
          raw <- getLine
          if null (filter (/= ' ') raw)
            then loop
            else do
              let line = BL.fromStrict (TE.encodeUtf8 (T.pack raw))
              resp <- processLine line
              putStrLn resp
              hFlush stdout
              loop

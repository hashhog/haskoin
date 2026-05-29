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
--
-- Second op @verifytx@ (for tx_valid.json / tx_invalid.json): unlike
-- @verifyscript@ (which rebuilds Core's synthetic credit/spend pair),
-- these vectors give a REAL serialized multi-input tx, so the sighash
-- must be computed over THAT tx. Mirrors
-- bitcoin-core/src/test/transaction_tests.cpp::CheckTxScripts: deserialize
-- tx_hex with haskoin's OWN tx deserializer (the 'Serialize' 'Tx' instance,
-- which parses the segwit marker/flag + per-input witness), build the
-- prevout->(scriptPubKey, amount) map, and for EACH input run haskoin's
-- real 'verifyScriptWithFlags' against THE REAL TX. haskoin's interpreter
-- sources the input's scriptSig from @txInScript (txInputs tx !! idx)@ and
-- its witness from @txWitness tx !! idx@ (Script.hs:1210), so the legacy /
-- BIP-143 / BIP-341 sighash commits to the actual surrounding tx. Valid
-- iff ALL inputs pass; reject on the FIRST failing input (Core's loop is
-- @i < vin.size() && tx_valid@).
--
--   request:  {"op":"verifytx",
--              "tx_hex":"...",
--              "prevouts":[{"txid":"<display-hex>","vout":N,
--                           "scriptPubKey_hex":"...","amount_sats":0},...],
--              "flags":["P2SH","WITNESS",...]}
--   response: {"valid":true}                   (all inputs verify)
--             {"valid":false,"reason":"..."}   (>=1 input failed)
--             {"error":"..."}                  (could not evaluate)
module Main where

import qualified Data.Aeson as A
import qualified Data.Aeson.Types as A
import Data.Aeson ((.:?))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import qualified Data.Map.Strict as Map
import qualified Data.Serialize as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32, Word64)
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

-- | Dispatch on the request's @op@ field (defaulting to @verifyscript@ for
-- back-compat with the script_tests harness, which omits it for haskoin).
processLine :: BL.ByteString -> IO String
processLine line =
  case A.eitherDecode line :: Either String A.Value of
    Left e  -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right v ->
      let op = case v of
                 A.Object o -> case A.parseMaybe (.:? "op") o of
                                 Just (Just (s :: T.Text)) -> s
                                 _                          -> "verifyscript"
                 _          -> "verifyscript"
      in case op of
           "verifytx" -> processVerifyTx line
           _          -> processVerifyScript line

processVerifyScript :: BL.ByteString -> IO String
processVerifyScript line =
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

------------------------------------------------------------------------------
-- verifytx op (tx_valid.json / tx_invalid.json — REAL multi-input tx).
--
-- See transaction_tests.cpp::CheckTxScripts. The driver hands us a
-- serialized tx + the prevout set; we deserialize with haskoin's own 'Tx'
-- 'Serialize' instance (which parses segwit marker/flag + per-input
-- witness), key the prevouts by (txid-wire-order, vout), assemble per-input
-- spent_scripts/spent_amounts in the tx's INPUT order (BIP-341 commits to
-- ALL prevouts), and run verifyScriptWithFlags per input over the real tx.
------------------------------------------------------------------------------

data Prevout = Prevout
  { poTxidDisplayHex :: T.Text   -- DISPLAY-order hex (reverse for wire)
  , poVout           :: Word32
  , poSpkHex         :: T.Text
  , poAmount         :: Word64
  }

instance A.FromJSON Prevout where
  parseJSON = A.withObject "Prevout" $ \o -> Prevout
    <$> o .:? "txid"            A..!= ""
    <*> (toW32 <$> o .:? "vout" A..!= (0 :: Double))
    <*> o .:? "scriptPubKey_hex" A..!= ""
    <*> (toW64 <$> o .:? "amount_sats" A..!= (0 :: Double))
    where
      toW32 d = round (d :: Double)
      toW64 d = round (d :: Double)

data TxRequest = TxRequest
  { reqTxHex    :: T.Text
  , reqPrevouts :: [Prevout]
  , reqTxFlags  :: [T.Text]
  }

instance A.FromJSON TxRequest where
  parseJSON = A.withObject "TxRequest" $ \o -> TxRequest
    <$> o .:? "tx_hex"   A..!= ""
    <*> o .:? "prevouts" A..!= []
    <*> o .:? "flags"    A..!= []

-- | The display-order txid hex from the driver must be reversed to the
-- wire-byte order that haskoin's deserialized 'OutPoint' carries (the
-- 'Hash256' inside an 'OutPoint' is the raw little-endian-on-the-wire
-- bytes; 'putByteString' emits them verbatim — Types.hs:56,170).
displayHexToWireTxId :: T.Text -> Either String TxId
displayHexToWireTxId t = do
  raw <- decodeHex t
  if BS.length raw /= 32
    then Left ("prevout txid not 32 bytes: " <> show (BS.length raw))
    else Right (TxId (Hash256 (BS.reverse raw)))

processVerifyTx :: BL.ByteString -> IO String
processVerifyTx line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case prepareTx req of
      Left e               -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right (tx, flags, spentScripts, spentAmounts) -> do
        r <- try (evaluate (forceVerdict
                    (verifyAllInputs flags tx spentScripts spentAmounts)))
               :: IO (Either SomeException (Either (Int, String) ()))
        pure $ case r of
          Left ex            ->
            "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right (Right ())   -> "{\"valid\":true}"
          Right (Left (i,e)) ->
            "{\"valid\":false,\"reason\":\"input " <> show i <> ": "
              <> escapeJson e <> "\"}"
  where
    forceVerdict v = case v of
      Left (i, s) -> Left (i, length s `seq` s)
      Right ()    -> Right ()

-- | Decode + validate the tx request: hex-decode tx, deserialize with
-- haskoin's 'Tx' 'Serialize', build the prevout map, then materialize the
-- per-input spent_scripts/spent_amounts in input order. A prevout missing
-- from the map => {"error"} (driver skips the row; never fake-pass).
prepareTx :: TxRequest
          -> Either String (Tx, ScriptFlags, [BS.ByteString], [Word64])
prepareTx req = do
  txBytes <- decodeHex (reqTxHex req)
  tx      <- case S.decode txBytes :: Either String Tx of
               Right t -> Right t
               Left e  -> Left ("tx deserialize: " <> e)
  flags   <- buildFlags (reqTxFlags req)
  -- Build (TxId, vout) -> (scriptPubKey, amount) map from the request.
  entries <- traverse mkEntry (reqPrevouts req)
  let m = Map.fromList entries
  -- Per-input spent_scripts / spent_amounts in the tx's OWN input order.
  perInput <- traverse (lookupInput m) (txInputs tx)
  let spentScripts = map fst perInput
      spentAmounts = map snd perInput
  Right (tx, flags, spentScripts, spentAmounts)
  where
    mkEntry p = do
      txid <- displayHexToWireTxId (poTxidDisplayHex p)
      spk  <- decodeHex (poSpkHex p)
      Right ((txid, poVout p), (spk, poAmount p))
    lookupInput m inp =
      let op = txInPrevOutput inp
          key = (outPointHash op, outPointIndex op)
      in case Map.lookup key m of
           Just sa -> Right sa
           Nothing -> Left ("no prevout scriptPubKey for input "
                            <> show key)

-- | Loop EVERY input, running haskoin's real verifyScriptWithFlags over the
-- REAL tx (it sources scriptSig + witness from the tx itself). Reject on
-- the FIRST failing input, mirroring Core's short-circuit. Left carries the
-- 0-based input index + reason.
verifyAllInputs :: ScriptFlags -> Tx -> [BS.ByteString] -> [Word64]
                -> Either (Int, String) ()
verifyAllInputs flags tx spentScripts spentAmounts =
    go 0 spentScripts spentAmounts
  where
    go _ [] [] = Right ()
    go i (spk:spks) (amt:amts) =
      case verifyScriptWithFlags flags tx i spk amt spentAmounts spentScripts of
        Right True  -> go (i + 1) spks amts
        Right False -> Left (i, "EVAL_FALSE")
        Left err    -> Left (i, err)
    -- spentScripts/spentAmounts are derived 1:1 from txInputs, so the
    -- ragged case is unreachable; close it explicitly rather than crash.
    go i _ _ = Left (i, "internal: input/prevout length mismatch")

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

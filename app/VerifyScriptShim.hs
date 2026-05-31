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
import qualified Data.Aeson.Key as AK
import qualified Data.Aeson.KeyMap as AKM
import Data.Aeson ((.:?))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base16 as B16
import qualified Data.Map.Strict as Map
import qualified Data.Serialize as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Int (Int32)
import Data.List (sortBy)
import Data.Ord (comparing)
import Data.Word (Word8, Word32, Word64)
import Numeric (readHex)
import Text.Printf (printf)
import System.IO (hFlush, stdout, isEOF)
import System.Directory
  ( getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive )
import Data.IORef (IORef, newIORef, modifyIORef', readIORef, atomicModifyIORef')
import System.IO.Unsafe (unsafePerformIO)
import Control.Exception (evaluate, try, bracket, SomeException)
import Control.Monad (forM_, (>=>))
import Control.Concurrent.STM (atomically)
import qualified Control.Concurrent.STM as STM

import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..)
  , BlockHeader(..), BlockHash(..), Block(..) )
import Haskoin.Crypto (computeTxId, computeBlockHash, sha256)
import Haskoin.Consensus
  ( validateTransaction, getNextWorkRequired, BlockIndex(..)
  , Network, mainnet, testnet3, testnet4, regtest
  , computeMerkleRootMutated, blockReward
  , checkTxInputsConnect, consensusFlagsAtHeight
  , validateFullBlock, ChainState(..)
  , applyBlock, disconnectBlockAt, DisconnectResult(..)
  , maxReorgDepth )
import Haskoin.Storage
  ( HaskoinDB, DBConfig(..), defaultDBConfig, openDB, closeDB
  , UTXOEntry(..), UTXOCache(..), newUTXOCache, addUTXO
  , Coin(..), putUTXOCoin
  , KeyPrefix(..), iterateWithPrefix
  , TxInUndo(..), TxUndo(..), BlockUndo(..), mkUndoData, putUndoData )
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
           "verifytx"   -> processVerifyTx line
           "checktx"    -> processCheckTx line
           "connecttx"  -> processConnectTx line
           "checkblock" -> processCheckBlock line
           "reorg"      -> processReorg line
           "nextwork"   -> processNextWork line
           "merkleroot" -> processMerkleRoot line
           "subsidy"    -> processSubsidy line
           _            -> processVerifyScript line

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

------------------------------------------------------------------------------
-- connecttx op (REAL connect-time Consensus::CheckTxInputs — the ECONOMIC
-- verdict; tx_verify.cpp:164-214).
--
-- Drives haskoin's 'Haskoin.Consensus.checkTxInputsConnect', a thin pure
-- composite over the SAME 'validateSingleTx' the connect/mempool paths use,
-- with the coinbase-maturity loop from applyBlock (Consensus.hs:4644-4649)
-- inlined (validateSingleTx's @Map OutPoint TxOut@ view has no height/coinbase
-- metadata, so it omits maturity and would false-accept a premature coinbase
-- spend). The four economic rejects this isolates:
--   * missing/spent input  -> bad-txns-inputs-missingorspent
--   * premature coinbase    -> bad-txns-premature-spend-of-coinbase
--   * MoneyRange violation  -> bad-txns-inputvalues-outofrange
--   * value-in < value-out  -> bad-txns-in-belowout
--
-- We seed an in-memory UTXO VIEW (one 'UTXOEntry' per prevout entry carrying
-- value + height + is_coinbase). An OMITTED prevout models a missing/spent
-- input. We reuse the verifytx prevout plumbing (display->wire txid reversal).
-- checkTxInputsConnect passes skipScripts=True internally so a SCRIPT failure
-- cannot mask the economic decision (this op scores only the economic verdict).
-- The flags fed to validateSingleTx are taken at @spend_height@ via
-- 'consensusFlagsAtHeight' (mainnet) — inert here since scripts are skipped.
--
--   request:  {"op":"connecttx","tx_hex":"...",
--              "prevouts":[{"txid":"<display-hex>","vout":N,
--                           "scriptPubKey_hex":"...","value_sats":<i64>,
--                           "height":<int>,"is_coinbase":<bool>},...],
--              "spend_height":<int>}
--   response: {"valid":true,"fee_sats":<i64>}      (CheckTxInputs passes)
--             {"valid":false,"reason":"<bad-txns-*>"} (economic reject)
--             {"error":"..."}                       (could not evaluate -> SKIP)
------------------------------------------------------------------------------

data ConnPrevout = ConnPrevout
  { cpTxidDisplayHex :: T.Text   -- DISPLAY-order hex (reverse for wire)
  , cpVout           :: Word32
  , cpSpkHex         :: T.Text
  , cpValue          :: Word64
  , cpHeight         :: Word32
  , cpIsCoinbase     :: Bool
  }

instance A.FromJSON ConnPrevout where
  parseJSON = A.withObject "ConnPrevout" $ \o -> ConnPrevout
    <$> o .:? "txid"             A..!= ""
    <*> (toW32 <$> o .:? "vout"  A..!= (0 :: Double))
    <*> o .:? "scriptPubKey_hex" A..!= ""
    <*> (toW64 <$> o .:? "value_sats" A..!= (0 :: Double))
    <*> (toW32 <$> o .:? "height" A..!= (0 :: Double))
    <*> o .:? "is_coinbase"      A..!= False
    where
      toW32 d = round (d :: Double)
      toW64 d = round (d :: Double)

data ConnTxRequest = ConnTxRequest
  { creqTxHex       :: T.Text
  , creqPrevouts    :: [ConnPrevout]
  , creqSpendHeight :: Word32
  }

instance A.FromJSON ConnTxRequest where
  parseJSON = A.withObject "ConnTxRequest" $ \o -> ConnTxRequest
    <$> o .:? "tx_hex"   A..!= ""
    <*> o .:? "prevouts" A..!= []
    <*> (toW32 <$> o .:? "spend_height" A..!= (0 :: Double))
    where toW32 d = round (d :: Double)

processConnectTx :: BL.ByteString -> IO String
processConnectTx line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case prepareConnTx req of
      Left e                  -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right (tx, view, sh) -> do
        -- mainnet flags at spend_height: inert (scripts skipped) but lets the
        -- impl pick its real connect-time flag set rather than a synthetic one.
        let flags = consensusFlagsAtHeight mainnet sh
        r <- try (evaluate
                    (forceEcon (checkTxInputsConnect mainnet flags sh view tx)))
               :: IO (Either SomeException (Either String Word64))
        pure $ case r of
          Left ex            ->
            "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right (Right fee)  ->
            "{\"valid\":true,\"fee_sats\":" <> show fee <> "}"
          Right (Left reason) ->
            "{\"valid\":false,\"reason\":\"" <> escapeJson reason <> "\"}"
  where
    forceEcon x = case x of
      Left s  -> Left $! (length s `seq` s)
      Right f -> Right $! f

-- | Decode the connecttx request: hex-decode + deserialize the tx with
-- haskoin's own 'Tx' 'Serialize' (segwit-aware), then seed an in-memory UTXO
-- VIEW — one 'UTXOEntry' per prevout entry with value + height + is_coinbase.
-- A prevout that fails to decode => {"error"} (driver skips, never fake-pass);
-- an OMITTED prevout simply does not appear in the view and is surfaced by
-- checkTxInputsConnect as bad-txns-inputs-missingorspent.
prepareConnTx :: ConnTxRequest
              -> Either String (Tx, Map.Map OutPoint UTXOEntry, Word32)
prepareConnTx req = do
  txBytes <- decodeHex (creqTxHex req)
  tx      <- case S.decode txBytes :: Either String Tx of
               Right t -> Right t
               Left e  -> Left ("tx deserialize: " <> e)
  entries <- traverse mkEntry (creqPrevouts req)
  let view = Map.fromList entries
  Right (tx, view, creqSpendHeight req)
  where
    mkEntry p = do
      txid <- displayHexToWireTxId (cpTxidDisplayHex p)
      spk  <- decodeHex (cpSpkHex p)
      let txout = TxOut { txOutValue = cpValue p, txOutScript = spk }
          entry = UTXOEntry { ueOutput   = txout
                            , ueHeight   = cpHeight p
                            , ueCoinbase = cpIsCoinbase p
                            , ueSpent    = False
                            }
      Right (OutPoint txid (cpVout p), entry)

------------------------------------------------------------------------------
-- checkblock op (VALIDATE-ONLY decision-level CheckBlock / ContextualCheckBlock
-- / ConnectBlock differential — generalizes connecttx from a single tx to a
-- FULL BLOCK).
--
-- Deserialize the FINAL block_hex with haskoin's OWN segwit-aware 'Block'
-- 'Serialize' (Types.hs), seed an in-memory @Map OutPoint Coin@ from the
-- prevout set (REUSING the connecttx 'ConnPrevout' decoder + display->wire
-- txid reversal VERBATIM), synthesize the ChainState the connect path needs,
-- and drive haskoin's REAL 'validateFullBlock' — the EXACT same call
-- 'connectChain' makes on a reorg connect (Consensus.hs:5057,
-- @validateFullBlock net cs False block spentCoins@). The shim reimplements
-- NONE of the CheckBlock / ContextualCheckBlock / ConnectBlock gates — the
-- decision is entirely the impl's.
--
-- ChainState: csHeight = spend_height-1 (validateFullBlock derives the connect
-- height as csHeight+1 internally), csBestBlock = the block's prev hash,
-- csChainWork = 0 (inert here), csMedianTime = 0 (a 0x7FFFFF* sentinel-timed
-- real mainnet block always satisfies @bhTimestamp > csMedianTime@; the corpus
-- blocks are real accepted blocks whose timestamps are far above 0),
-- csFlags = consensusFlagsAtHeight mainnet spend_height (mirrors
-- connectChain's @consensusFlagsAtHeight net (ceHeight ce)@).
--
-- skip_pow: 'validateFullBlock' performs NO proof-of-work check (it is a pure
-- CheckBlock/ContextualCheckBlock/ConnectBlock composite; PoW lives in the
-- header-acceptance path, NOT here). So a FINAL/mutated block that misses the
-- mainnet PoW target is NEVER rejected on high-hash — skip_pow=true is the
-- corpus default and is satisfied structurally.
--
-- skip_scripts: forwarded as validateFullBlock's @skipScripts@ flag. The
-- contract default is False, so per-input 'verifyScriptWithFlags' actually
-- runs (no assume-valid skip in this pure path — validateFullBlock has no
-- assume-valid heuristic, so the script gate is always live when
-- skip_scripts=false).
--
--   request:  {"op":"checkblock","block_hex":"<FINAL block bytes>",
--              "prevouts":[{"txid":"<display-hex>","vout":N,
--                           "scriptPubKey_hex":"...","value_sats":<u64>,
--                           "height":N,"is_coinbase":bool}, ...],
--              "spend_height":<int>,"skip_pow":<bool>,"skip_scripts":<bool>}
--   response: {"valid":true}                    (CheckBlock chain accepts)
--             {"valid":false,"reason":"..."}    (some gate rejects)
--             {"error":"..."}                   (could not evaluate -> SKIP)
------------------------------------------------------------------------------

data CheckBlockRequest = CheckBlockRequest
  { cbBlockHex     :: T.Text
  , cbPrevouts     :: [ConnPrevout]
  , cbSpendHeight  :: Word32
  , cbSkipPow      :: Bool
  , cbSkipScripts  :: Bool
  }

instance A.FromJSON CheckBlockRequest where
  parseJSON = A.withObject "CheckBlockRequest" $ \o -> CheckBlockRequest
    <$> o .:? "block_hex" A..!= ""
    <*> o .:? "prevouts"  A..!= []
    <*> (toW32 <$> o .:? "spend_height" A..!= (0 :: Double))
    <*> o .:? "skip_pow"     A..!= True
    <*> o .:? "skip_scripts" A..!= False
    where toW32 d = round (d :: Double)

-- | Build a @Map OutPoint Coin@ from the prevout set (same view shape
-- 'validateFullBlock' consumes via 'connectChain' / 'buildReorgSpentCoinMap').
prevoutsToCoinMap :: [ConnPrevout] -> Either String (Map.Map OutPoint Coin)
prevoutsToCoinMap ps = Map.fromList <$> traverse mk ps
  where
    mk p = do
      txid <- displayHexToWireTxId (cpTxidDisplayHex p)
      spk  <- decodeHex (cpSpkHex p)
      let txout = TxOut { txOutValue = cpValue p, txOutScript = spk }
          coin  = Coin { coinTxOut      = txout
                       , coinHeight     = cpHeight p
                       , coinIsCoinbase = cpIsCoinbase p }
      Right (OutPoint txid (cpVout p), coin)

processCheckBlock :: BL.ByteString -> IO String
processCheckBlock line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case prepareCheckBlock req of
      Left e                            -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right (block, cs, skipScripts, coinMap) -> do
        r <- try (evaluate
                    (forceEither (validateFullBlock mainnet cs skipScripts block coinMap)))
               :: IO (Either SomeException (Either String ()))
        pure $ case r of
          Left ex          ->
            "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right (Right ()) -> "{\"valid\":true}"
          Right (Left err) ->
            "{\"valid\":false,\"reason\":\"" <> escapeJson err <> "\"}"
  where
    forceEither x = case x of
      Left s   -> Left $! (length s `seq` s)
      Right () -> Right ()

prepareCheckBlock :: CheckBlockRequest
                  -> Either String (Block, ChainState, Bool, Map.Map OutPoint Coin)
prepareCheckBlock req = do
  blockBytes <- decodeHex (cbBlockHex req)
  block      <- case S.decode blockBytes :: Either String Block of
                  Right b -> Right b
                  Left e  -> Left ("block deserialize: " <> e)
  coinMap    <- prevoutsToCoinMap (cbPrevouts req)
  let sh   = cbSpendHeight req
      prev = bhPrevBlock (blockHeader block)
      cs   = ChainState
               { csHeight     = sh - 1
               , csBestBlock  = prev
               , csChainWork  = 0
               , csMedianTime = 0
               , csFlags      = consensusFlagsAtHeight mainnet sh
               }
  Right (block, cs, cbSkipScripts req, coinMap)

------------------------------------------------------------------------------
-- reorg op (DETERMINISTIC side-branch re-validation — ActivateBestChain
-- differential). Drives haskoin's REAL reorg pipeline over a THROWAWAY temp
-- RocksDB + UTXOCache seeded with explicit chain-state, removing the live-tip /
-- first-seen / nSequenceId race: the most-work DECISION, the fork-point coins
-- view, and the per-block UNDO TABLE are all EXPLICIT DATA.
--
-- CORRECTED HASKOIN DRIVE (matching connectChain, Consensus.hs:5018-5069):
--   (0) DEPTH CAP: disconnect+connect > maxReorgDepth(100) -> reorg-too-deep
--       (haskoin Consensus.hs:3700 caps the SUM; Core has no fixed cap ->
--       EXPECTED-DIVERGENCE, marked in the corpus).
--   (1) WORK DECISION: strict BE-256 new > old on the EXPLICIT work hex (NOT a
--       live tip / readTVarIO hcTip / ceSequenceId). Not strictly greater ->
--       no-reorg-equal-or-less-work, view UNTOUCHED, connected_count=0, the
--       (possibly invalid) connect blocks NEVER evaluated.
--   (2) DISCONNECT: drive the REAL DB-backed 'disconnectBlockAt' tip-first over
--       the explicit undo table (BlockUndo/TxUndo tuPrevOutputs). It restores
--       inputs + deletes created outputs and returns a 'DisconnectResult'
--       (ok/unclean/failed) — the OVERWRITE-of-unspent (R5) and
--       OUTPUT-identity-mismatch (R5b) UNCLEAN checks are haskoin's own
--       (Consensus.hs:applyTxInUndo:3423 + the SpendCoin check:3625). We store
--       the explicit undo via 'putUndoData' (with the per-disconnect prev-hash
--       so the checksum verifies) so 'disconnectBlockAt' reads it back.
--   (3) CONNECT: per side-branch block in order, EXACTLY connectChain:
--       build the spent-prevout 'Coin' map from the post-disconnect cache,
--       'validateFullBlock net cs False block spentCoins' (FULL scripts +
--       economics), THEN 'applyBlock'. The coinbase-MATURITY gate (R6,
--       "Coinbase not yet mature") lives in 'applyBlock' (Consensus.hs:4715),
--       NOT in validateFullBlock — so this two-step drive is what makes R6 fire.
--       Stop at the FIRST reject (R9: MUST NOT skip ahead to a later valid
--       block). connected_count = blocks applied before the first reject.
--
-- View metadata: the cache is pre-seeded from the post-disconnect DB UTXO set
-- with FULL Core 'Coin' metadata (height + coinbase), NOT via lookupUTXO
-- fallthrough (which would zero the height/coinbase and break R6 maturity).
-- The final 'fork_utxo_digest' is computed over the cache's unspent entries
-- (canonical sort + byte layout identical to reorg_vectors.py view_digest).
--
--   request:  {"op":"reorg","network":...,"fork_utxo":[coin...],
--              "disconnect":[{block_hex,height,undo:[{tx_index,vin:[coin...]}]}],
--              "connect":[{block_hex,height,prev_mtp}],
--              "old_tip_work_hex":<32B BE hex>,"new_tip_work_hex":<32B BE hex>}
--   response: {"outcome":"reorg-applied"|"reorg-rejected"|
--                 "no-reorg-equal-or-less-work"|"reorg-too-deep",
--              "disconnect_result":"ok"|"unclean"|"failed",
--              "connected_count":N,"reject_reason":<token>?,
--              "fork_utxo_digest":<sha256 hex of canonically-sorted view>}
------------------------------------------------------------------------------

shimMaxReorgDepth :: Int
shimMaxReorgDepth = maxReorgDepth   -- 100 (Consensus.hs:3700)

processReorg :: BL.ByteString -> IO String
processReorg line =
  case A.eitherDecode line :: Either String A.Value of
    Left e  -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right v -> do
      r <- try (runReorg v) :: IO (Either SomeException String)
      pure $ case r of
        Left ex  -> "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
        Right s  -> s

-- | A single fork-point / undo coin entry (same shape as 'ConnPrevout').
parseReorgCoin :: A.Value -> Either String (OutPoint, Coin)
parseReorgCoin val = case A.parseEither A.parseJSON val of
  Left e  -> Left ("coin parse: " <> e)
  Right p -> do
    txid <- displayHexToWireTxId (cpTxidDisplayHex p)
    spk  <- decodeHex (cpSpkHex p)
    let txout = TxOut { txOutValue = cpValue p, txOutScript = spk }
        coin  = Coin { coinTxOut      = txout
                     , coinHeight     = cpHeight p
                     , coinIsCoinbase = cpIsCoinbase p }
    Right (OutPoint txid (cpVout p), coin)

-- | Parse a 32-byte BE work hex into an 'Integer'. Absent/null -> Nothing.
parseWorkHex :: Maybe A.Value -> Either String (Maybe Integer)
parseWorkHex Nothing            = Right Nothing
parseWorkHex (Just A.Null)      = Right Nothing
parseWorkHex (Just (A.String s)) = do
  raw <- decodeHex s
  if BS.length raw /= 32
    then Left ("work hex not 32 bytes: " <> show (BS.length raw))
    else Right (Just (BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 raw))
parseWorkHex (Just _)           = Left "work hex not a string"

-- | Canonical coins-view digest — byte-identical to reorg_vectors.py
-- view_digest: sort by (wire-txid, vout), then per coin:
--   txid[32] || vout u32 LE || height u32 LE || is_coinbase u8 ||
--   value u64 LE || spk_len u32 LE || spk.
reorgViewDigest :: [(OutPoint, Coin)] -> String
reorgViewDigest coins =
  let entries = sortBy (comparing keyOf) coins
      buf = BS.concat (map enc entries)
      d   = sha256 buf
  in concatMap (printf "%02x") (BS.unpack d)
  where
    keyOf (OutPoint (TxId (Hash256 bs)) vout, _) = (BS.unpack bs, vout)
    le32 w = BS.pack [ fromIntegral (w `div` (256 ^ i)) | i <- [0 .. 3 :: Int] ]
    le64 w = BS.pack [ fromIntegral (w `div` (256 ^ i)) | i <- [0 .. 7 :: Int] ]
    enc (OutPoint (TxId (Hash256 txbs)) vout, Coin txout h cb) =
      let spk = txOutScript txout
      in BS.concat
           [ txbs
           , le32 (fromIntegral vout :: Word64)
           , le32 (fromIntegral h :: Word64)
           , BS.singleton (if cb then 1 else 0 :: Word8)
           , le64 (txOutValue txout)
           , le32 (fromIntegral (BS.length spk) :: Word64)
           , spk ]

-- | Decode a disconnect entry: (block, height, flattened ordered undo coins
-- grouped per non-coinbase tx). Returns the per-tx undo prevout lists in
-- tx-ascending / input-ascending order (exactly Core's vtxundo layout).
data DiscEntry = DiscEntry
  { deBlock     :: Block
  , deHeight    :: Word32
  , deTxUndos   :: [[Coin]]   -- one inner list per non-coinbase tx, input order
  }

decodeDisc :: A.Value -> Either String DiscEntry
decodeDisc = A.parseEither pj >=> finish
  where
    pj = A.withObject "disc" $ \o -> (,,)
      <$> (o A..: "block_hex" :: A.Parser T.Text)
      <*> (round <$> (o A..: "height" :: A.Parser Double) :: A.Parser Word32)
      <*> (o .:? "undo" A..!= [] :: A.Parser [A.Value])
    finish (bhex, h, undoVals) = do
      block  <- decodeHex bhex >>= \bs -> case S.decode bs :: Either String Block of
                  Right b -> Right b
                  Left e  -> Left ("disconnect block deserialize: " <> e)
      txUndos <- traverse decodeUndoTx undoVals
      Right (DiscEntry block h txUndos)
    decodeUndoTx = A.parseEither (A.withObject "undoTx" (\o -> o .:? "vin" A..!= []))
                 >=> traverse parseReorgCoin
                 >=> \pairs -> Right (map snd pairs)

-- | Decode a connect entry: (block, height, prev_mtp).
data ConnEntry = ConnEntry
  { ceBlock   :: Block
  , ceHeight  :: Word32
  , cePrevMtp :: Word32
  }

decodeConn :: A.Value -> Either String ConnEntry
decodeConn = A.parseEither pj >=> finish
  where
    pj = A.withObject "conn" $ \o -> (,,)
      <$> (o A..: "block_hex" :: A.Parser T.Text)
      <*> (round <$> (o A..: "height" :: A.Parser Double) :: A.Parser Word32)
      <*> (round <$> (o .:? "prev_mtp" A..!= (0 :: Double)) :: A.Parser Word32)
    finish (bhex, h, mtp) = do
      block <- decodeHex bhex >>= \bs -> case S.decode bs :: Either String Block of
                 Right b -> Right b
                 Left e  -> Left ("connect block deserialize: " <> e)
      Right (ConnEntry block h mtp)

-- | Map the reorg network string -> haskoin 'Network'.
reorgNetwork :: T.Text -> Either String Network
reorgNetwork t = case t of
  "mainnet"  -> Right mainnet
  "regtest"  -> Right regtest
  "testnet"  -> Right testnet3
  "testnet3" -> Right testnet3
  "testnet4" -> Right testnet4
  other      -> Left ("unknown network: " <> T.unpack other)

-- | Look up a top-level object field by name (Nothing if absent / not object).
lookupField :: A.Value -> T.Text -> Maybe A.Value
lookupField (A.Object o) k = AKM.lookup (AK.fromText k) o
lookupField _            _ = Nothing

-- | A required-with-default string field.
textField :: A.Value -> T.Text -> T.Text -> T.Text
textField v k dflt = case lookupField v k of
  Just (A.String s) -> s
  _                 -> dflt

-- | A required array field (defaults to empty when absent / null).
arrField :: A.Value -> T.Text -> Either String [A.Value]
arrField v k = case lookupField v k of
  Nothing            -> Right []
  Just A.Null        -> Right []
  Just (A.Array a)   -> Right (foldr (:) [] a)
  Just _             -> Left (T.unpack k <> " is not an array")

runReorg :: A.Value -> IO String
runReorg v = do
  let res = do
        net      <- reorgNetwork (textField v "network" "mainnet")
        forkVals <- arrField v "fork_utxo"
        forkCoins <- traverse parseReorgCoin forkVals
        discVals <- arrField v "disconnect"
        discs    <- traverse decodeDisc discVals
        connVals <- arrField v "connect"
        conns    <- traverse decodeConn connVals
        oldW     <- parseWorkHex (lookupField v "old_tip_work_hex")
        newW     <- parseWorkHex (lookupField v "new_tip_work_hex")
        Right (net, forkCoins, discs, conns, oldW, newW)
  case res of
    Left e -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
    Right (net, forkCoins, discs, conns, oldW, newW) -> do
      let seedDigest = reorgViewDigest forkCoins
      -- (0) DEPTH CAP — haskoin caps the SUM of disconnect + connect.
      if length discs + length conns > shimMaxReorgDepth
        then pure (mk "reorg-too-deep" "ok" 0 Nothing seedDigest)
      -- (1) WORK DECISION — pure strict BE-256 new > old.
      else if maybe False not (compareStrictGreater <$> newW <*> oldW)
        then pure (mk "no-reorg-equal-or-less-work" "ok" 0 Nothing seedDigest)
        else withTempDB $ \db -> do
          -- Seed the DB UTXO set from fork_utxo (full Coin metadata).
          forM_ forkCoins $ \(op, coin) -> putUTXOCoin db op coin
          -- (2) DISCONNECT — REAL disconnectBlockAt tip-first over explicit undo.
          discResult <- runDisconnects db discs
          case discResult of
            DiscFailed reason ->
              pure (mk "reorg-rejected" "failed" 0 (Just reason) seedDigest)
            DiscDone worst   -> do
              let discStr = case worst of
                    DisconnectOk      -> "ok"
                    DisconnectUnclean -> "unclean"
                    DisconnectFailed  -> "failed"
              -- Pre-seed a cache from the post-disconnect DB UTXO set with FULL
              -- metadata, so connect-phase maturity (R6) sees real height/coinbase.
              cache <- seedCacheFromDB db
              -- (3) CONNECT — EXACTLY connectChain per side-branch block.
              (connCount, mReject) <- runConnects cache net conns 0
              finalCoins <- cacheUnspent cache
              let dig = reorgViewDigest finalCoins
              pure $ case mReject of
                Just reason -> mk "reorg-rejected" discStr connCount (Just reason) dig
                Nothing     -> mk "reorg-applied"  discStr connCount Nothing       dig
  where
    -- Build the canonical JSON response.
    mk outcome disc cc mReason dig =
      let base = "{\"outcome\":\"" <> outcome <> "\",\"disconnect_result\":\""
                 <> disc <> "\",\"connected_count\":" <> show (cc :: Int)
          reasonPart = case mReason of
            Just r  -> ",\"reject_reason\":\"" <> escapeJson r <> "\""
            Nothing -> ""
      in base <> reasonPart <> ",\"fork_utxo_digest\":\"" <> dig <> "\"}"

-- Disconnect run result.
data DiscRun = DiscDone DisconnectResult | DiscFailed String

-- | Drive the REAL DB-backed 'disconnectBlockAt' for every disconnect block
-- tip-first, storing the explicit undo via 'putUndoData' (so the checksum
-- verifies on read-back). The worst result across blocks wins
-- (failed > unclean > ok); a hard failure short-circuits.
runDisconnects :: HaskoinDB -> [DiscEntry] -> IO DiscRun
runDisconnects db = go DisconnectOk
  where
    go worst [] = pure (DiscDone worst)
    go worst (d:ds) = do
      let block   = deBlock d
          height  = deHeight d
          bh      = computeBlockHash (blockHeader block)
          prev    = bhPrevBlock (blockHeader block)
          -- Build a BlockUndo from the explicit per-tx undo coin lists.
          txUndos = map (\coins -> TxUndo
                          { tuPrevOutputs =
                              [ TxInUndo { tuOutput   = coinTxOut c
                                         , tuHeight   = coinHeight c
                                         , tuCoinbase = coinIsCoinbase c }
                              | c <- coins ] })
                        (deTxUndos d)
          blockUndo = BlockUndo { buTxUndo = txUndos }
          undoData  = mkUndoData bh height prev blockUndo
      putUndoData db bh undoData
      r <- disconnectBlockAt db height block prev
      case r of
        Left e -> pure (DiscFailed e)
        Right dr ->
          let worst' = case (worst, dr) of
                (DisconnectFailed, _) -> DisconnectFailed
                (_, DisconnectFailed) -> DisconnectFailed
                (DisconnectUnclean, _) -> DisconnectUnclean
                (_, DisconnectUnclean) -> DisconnectUnclean
                _                      -> DisconnectOk
          in go worst' ds

-- | Pre-seed a UTXOCache from the post-disconnect DB by enumerating the full
-- PrefixUTXO keyspace and inserting each coin with its FULL Core 'Coin'
-- metadata (height + coinbase). This is required because 'applyBlock' reads
-- via 'lookupUTXO', whose DB fallthrough would zero the height/coinbase
-- (Storage.hs:643) and break the connect-phase coinbase-maturity gate (R6).
-- With the cache fully pre-loaded, no fallthrough ever occurs.
seedCacheFromDB :: HaskoinDB -> IO UTXOCache
seedCacheFromDB db = do
  cache <- newUTXOCache db (maxBound :: Int)
  coins <- dumpAllCoins db
  forM_ coins $ \(op, c) ->
    atomicallyAdd cache op
      (UTXOEntry { ueOutput   = coinTxOut c
                 , ueHeight   = coinHeight c
                 , ueCoinbase = coinIsCoinbase c
                 , ueSpent    = False })
  pure cache

-- | 'addUTXO' is 'STM ()'; lift it.
atomicallyAdd :: UTXOCache -> OutPoint -> UTXOEntry -> IO ()
atomicallyAdd cache op entry = atomically (addUTXO cache op entry)

-- | Enumerate the full PrefixUTXO keyspace, decoding each (OutPoint, Coin).
-- Key layout: 0x05 ++ encode OutPoint ; value: encode Coin (Storage.hs:521).
dumpAllCoins :: HaskoinDB -> IO [(OutPoint, Coin)]
dumpAllCoins db = do
  ref <- newIORef []
  iterateWithPrefix db PrefixUTXO $ \key val -> do
    let opBytes = BS.drop 1 key   -- strip the 1-byte prefix
    case (S.decode opBytes :: Either String OutPoint,
          S.decode val     :: Either String Coin) of
      (Right op, Right c) -> modifyIORef' ref ((op, c) :)
      _                   -> pure ()
    pure True
  readIORef ref

-- | Enumerate the cache's UNSPENT entries -> (OutPoint, Coin) for the digest.
-- The cache holds the authoritative final state after connect (applyBlock
-- mutates it in place; spent entries are flagged 'ueSpent').
cacheUnspent :: UTXOCache -> IO [(OutPoint, Coin)]
cacheUnspent cache = do
  entries <- atomically (readTVarCache cache)
  pure [ (op, Coin { coinTxOut = ueOutput e
                   , coinHeight = ueHeight e
                   , coinIsCoinbase = ueCoinbase e })
       | (op, e) <- Map.toList entries, not (ueSpent e) ]
  where
    -- Read ucEntries (the in-memory map). Local helper to keep the STM read
    -- self-contained without importing readTVar at call sites.
    readTVarCache = readTVarSTM . ucEntries

-- | Drive the CONNECT phase EXACTLY as 'connectChain' (Consensus.hs:5040-5063):
-- per side-branch block, build the spent-prevout Coin map from the
-- post-disconnect / mid-connect cache, run 'validateFullBlock' (full scripts +
-- economics), THEN 'applyBlock' (carries the coinbase-maturity gate). Stop at
-- the FIRST reject (R9). Returns (count applied, Just rejectReason | Nothing).
runConnects :: UTXOCache -> Network -> [ConnEntry] -> Int
            -> IO (Int, Maybe String)
runConnects _ _ [] n = pure (n, Nothing)
runConnects cache net (c:cs) n = do
  let block    = ceBlock c
      height    = ceHeight c
      prevMtp   = cePrevMtp c
      prevHash  = bhPrevBlock (blockHeader block)
  -- (a) buildReorgSpentCoinMap: prevouts present in the cache become Coin
  -- entries; intra-block-created prevouts are absent (resolved inside
  -- validateBlockTransactions). Mirrors Consensus.hs:5096-5107.
  spentCoins <- buildSpentCoinMap cache block
  -- (b) ChainState exactly as connectChain (Consensus.hs:5054): csHeight =
  -- height-1, csBestBlock = prev, csChainWork inert, csMedianTime = prevMtp
  -- (BIP-113 / timestamp cutoff), csFlags @ this block's height.
  let cs0 = ChainState
              { csHeight     = height - 1
              , csBestBlock  = prevHash
              , csChainWork  = 0
              , csMedianTime = prevMtp
              , csFlags      = consensusFlagsAtHeight net height
              }
  case validateFullBlock net cs0 False block spentCoins of
    Left err -> pure (n, Just err)
    Right () -> do
      -- (c) applyBlock — spends inputs from the cache, checks coinbase maturity
      -- (R6), sigops, bad-cb-amount, etc. getMTP is unused on these vectors
      -- (height-based BIP-68 only); return prevMtp as a safe constant.
      applyRes <- applyBlock cache net block height prevMtp (\_ -> pure prevMtp)
      case applyRes of
        Left err -> pure (n, Just err)
        Right _  -> runConnects cache net cs (n + 1)

-- | The connectChain spent-prevout Coin map: for every non-coinbase input,
-- look the prevout up in the cache; present -> a Coin entry, absent -> dropped
-- (intra-block prevout). Mirrors 'buildReorgSpentCoinMap' (Consensus.hs:5096).
buildSpentCoinMap :: UTXOCache -> Block -> IO (Map.Map OutPoint Coin)
buildSpentCoinMap cache block = do
  entries <- atomically (readTVarSTM (ucEntries cache))
  let nonCoinbase = drop 1 (blockTxns block)
      prevouts    = [ txInPrevOutput inp | tx <- nonCoinbase, inp <- txInputs tx ]
      pairs = [ (op, Coin { coinTxOut = ueOutput e
                          , coinHeight = ueHeight e
                          , coinIsCoinbase = ueCoinbase e })
              | op <- prevouts
              , Just e <- [Map.lookup op entries]
              , not (ueSpent e) ]
  pure (Map.fromList pairs)

-- | STM read of the cache's entry map (ucEntries is a TVar).
readTVarSTM :: STM.TVar a -> STM.STM a
readTVarSTM = STM.readTVar

-- | Strict BE-256 most-work comparison: True iff @new > old@.
compareStrictGreater :: Integer -> Integer -> Bool
compareStrictGreater new old = new > old

-- | Open a throwaway RocksDB in a fresh temp dir; remove it on exit.
-- A monotone per-process counter makes the dir name unique across the many
-- requests one long-lived shim handles on its stdin loop.
withTempDB :: (HaskoinDB -> IO a) -> IO a
withTempDB act = do
  tmp <- getTemporaryDirectory
  n   <- nextTempId
  let dir = tmp <> "/haskoin-reorg-shim-" <> show n
  bracket
    (do createDirectoryIfMissing True dir
        openDB (defaultDBConfig dir) { dbBloomFilterBits = 0
                                     , dbWriteBufferSize = 4 * 1024 * 1024
                                     , dbBlockCacheSize  = 8 * 1024 * 1024 })
    (\db -> closeDB db >> removeDirectoryRecursive dir)
    act

-- | Process-global monotone counter for unique temp-dir names.
{-# NOINLINE tempIdRef #-}
tempIdRef :: IORef Int
tempIdRef = unsafePerformIO (newIORef 0)

nextTempId :: IO Int
nextTempId = atomicModifyIORef' tempIdRef (\x -> (x + 1, x))

------------------------------------------------------------------------------
-- checktx op (tx_valid.json / tx_invalid.json BADTX rows —
-- CheckTransaction-level, context-free structural validation; tx_check.cpp).
--
-- Unlike verifytx (per-input VerifyScript), the 9 BADTX rows
-- (no-inputs / no-outputs / dup-inputs / bad-amount / oversize /
-- null-prevout) are rejected by Core BEFORE script verification, inside
-- CheckTransaction. We delegate to haskoin's OWN context-free
-- 'Haskoin.Consensus.validateTransaction' (Consensus.hs:1395, which mirrors
-- bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction: empty vin/vout,
-- per-output value range + running MAX_MONEY total, duplicate inputs,
-- oversize via non-witness size * WITNESS_SCALE_FACTOR vs MAX_BLOCK_WEIGHT,
-- coinbase scriptSig length 2..100, non-coinbase null prevout). NO prevouts
-- / flags / UTXO state needed — so a divergence here is a real haskoin
-- CheckTransaction consensus bug, not a shim artifact.
--
--   request:  {"op":"checktx","tx_hex":"..."}
--   response: {"valid":true}                   (CheckTransaction passes)
--             {"valid":false,"reason":"..."}   (rejected)
--             {"error":"..."}                  (could not deserialize)
------------------------------------------------------------------------------

newtype CheckTxRequest = CheckTxRequest { ctxTxHex :: T.Text }

instance A.FromJSON CheckTxRequest where
  parseJSON = A.withObject "CheckTxRequest" $ \o -> CheckTxRequest
    <$> o .:? "tx_hex" A..!= ""

processCheckTx :: BL.ByteString -> IO String
processCheckTx line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case prepareCheckTx req of
      Left e   -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right tx -> do
        r <- try (evaluate (forceEither (validateTransaction tx)))
               :: IO (Either SomeException (Either String ()))
        pure $ case r of
          Left ex          ->
            "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right (Right ()) -> "{\"valid\":true}"
          Right (Left err) ->
            "{\"valid\":false,\"reason\":\"" <> escapeJson err <> "\"}"
  where
    forceEither x = case x of
      Left s   -> Left $! (length s `seq` s)
      Right () -> Right ()

-- | Hex-decode + deserialize the tx with haskoin's own 'Tx' 'Serialize'
-- instance (same path verifytx uses). A deserialize failure => {"error"}
-- (driver treats that as a reject decision; never a fake CheckTransaction
-- pass).
prepareCheckTx :: CheckTxRequest -> Either String Tx
prepareCheckTx req = do
  txBytes <- decodeHex (ctxTxHex req)
  case S.decode txBytes :: Either String Tx of
    Right t -> Right t
    Left e  -> Left ("tx deserialize: " <> e)

------------------------------------------------------------------------------
-- nextwork op (GetNextWorkRequired PoW differential — pow.cpp).
--
-- Drives haskoin's REAL 'Haskoin.Consensus.getNextWorkRequired' (the
-- BlockIndex/chain-generic entrypoint at Consensus.hs:744 that handles
-- retarget + the (interval-1) off-by-one + the timespan/4..*4 clamps +
-- powLimit + the BIP-94 first-vs-last selection), NOT a value-based or
-- legacy twin.
--
-- The driver hands us @last@ (= pindexLast, the tip the solver builds on,
-- height H-1) and, only on retarget-boundary rows (H % 2016 == 0),
-- @first@ (= the block at height H-2016, i.e. pindexLast.height-2015).
--
-- We reconstruct exactly the chain context Core's CalculateNextWorkRequired
-- needs: getNextWorkRequired calls calculateNextWorkRequired, which does
-- @getAncestorBI pindexLast (interval - 1)@ to find pindexFirst. With a
-- 2-node BlockIndex chain (@last@ whose biPrev is @first@, and @first@ whose
-- biPrev is Nothing), the 2015-step walk-back terminates at @first@ when it
-- runs off the chain end (getAncestorBI returns the deepest node it reaches),
-- so pindexFirst lands on @first@ exactly. For passthrough rows there is no
-- retarget: getNextWorkRequired returns @last@'s bits directly (no ancestor
-- walk), so a single-node chain (biPrev = Nothing) suffices.
--
-- The candidate BlockHeader carries bhTimestamp = block_time (only consulted
-- by the testnet min-difficulty rule; mainnet ignores it). All other header
-- fields are inert for the difficulty calc and use neutral placeholders.
--
--   request:  {"op":"nextwork","network":"mainnet","height":H,
--              "block_time":<u32>,
--              "last":{"height":<int>,"bits":"<8hex>","time":<u32>},
--              "first":{"height":<int>,"bits":"<8hex>","time":<u32>}}  (boundary only)
--   response: {"nbits":"<8hex>"}   (impl's REAL computed required nBits)
--             {"error":"..."}      (could not compute -> driver SKIPS)
------------------------------------------------------------------------------

data NwBlock = NwBlock
  { nwHeight :: Word32
  , nwBits   :: T.Text   -- 8-lowercase-hex (Core getblockheader format)
  , nwTime   :: Word32
  }

instance A.FromJSON NwBlock where
  parseJSON = A.withObject "NwBlock" $ \o -> NwBlock
    <$> (toW32 <$> o A..: "height")
    <*> o A..: "bits"
    <*> (toW32 <$> o A..: "time")
    where toW32 d = round (d :: Double)

data NextWorkRequest = NextWorkRequest
  { nwNetwork   :: T.Text
  , nwBlockTime :: Word32
  , nwLast      :: NwBlock
  , nwFirst     :: Maybe NwBlock   -- present ONLY on retarget-boundary rows
  }

instance A.FromJSON NextWorkRequest where
  parseJSON = A.withObject "NextWorkRequest" $ \o -> NextWorkRequest
    <$> o .:? "network"     A..!= "mainnet"
    <*> (toW32 <$> o .:? "block_time" A..!= (0 :: Double))
    <*> o A..: "last"
    <*> o .:? "first"
    where toW32 d = round (d :: Double)

-- | Map the network string to the haskoin 'Network'. Unknown => Left so the
-- shim emits {"error"} and the driver SKIPS (never a faked nBits).
mapNetwork :: T.Text -> Either String Network
mapNetwork t = case t of
  "mainnet"  -> Right mainnet
  "testnet"  -> Right testnet3
  "testnet3" -> Right testnet3
  "testnet4" -> Right testnet4
  "regtest"  -> Right regtest
  other      -> Left ("unknown network: " <> T.unpack other)

-- | Parse 8-lowercase-hex compact bits (getblockheader format) to Word32.
parseBits :: T.Text -> Either String Word32
parseBits t = case readHex (T.unpack t) of
  [(v, "")] | v >= 0 && v <= 0xffffffff -> Right (fromIntegral (v :: Integer))
  _                                     -> Left ("bad bits hex: " <> T.unpack t)

-- | Format a Word32 compact-bits value as 8-lowercase-hex (Core format).
formatBits :: Word32 -> String
formatBits = printf "%08x"

-- | A neutral BlockIndex node. Only height/bits/timestamp/prev are consulted
-- by the difficulty path; hash + version are inert placeholders.
mkBI :: Word32 -> Word32 -> Word32 -> Maybe BlockIndex -> BlockIndex
mkBI h bits ts prev = BlockIndex
  { biHeight    = h
  , biBits      = bits
  , biTimestamp = ts
  , biVersion   = 0
  , biHash      = BlockHash (Hash256 (BS.replicate 32 0))
  , biPrev      = prev
  }

processNextWork :: BL.ByteString -> IO String
processNextWork line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case prepareNextWork req of
      Left e   -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right (net, pindexLast, candidate) -> do
        r <- try (evaluate (getNextWorkRequired net pindexLast candidate))
               :: IO (Either SomeException Word32)
        pure $ case r of
          Left ex   ->
            "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right nb  ->
            "{\"nbits\":\"" <> formatBits nb <> "\"}"

-- | Build the (Network, pindexLast, candidate header) triple. On boundary
-- rows the @first@ block becomes pindexLast's biPrev so the impl's
-- getAncestorBI walk-back lands on it; on passthrough rows pindexLast has no
-- prev (no ancestor walk happens). A missing/garbled field => Left (skip).
prepareNextWork :: NextWorkRequest
                -> Either String (Network, BlockIndex, BlockHeader)
prepareNextWork req = do
  net      <- mapNetwork (nwNetwork req)
  let lastB = nwLast req
  lastBits <- parseBits (nwBits lastB)
  prevNode <- case nwFirst req of
    Nothing -> Right Nothing
    Just f  -> do
      fBits <- parseBits (nwBits f)
      Right (Just (mkBI (nwHeight f) fBits (nwTime f) Nothing))
  let pindexLast = mkBI (nwHeight lastB) lastBits (nwTime lastB) prevNode
      candidate  = BlockHeader
        { bhVersion    = 0 :: Int32
        , bhPrevBlock  = biHash pindexLast
        , bhMerkleRoot = Hash256 (BS.replicate 32 0)
        , bhTimestamp  = nwBlockTime req   -- testnet min-diff only; mainnet ignores
        , bhBits       = lastBits          -- placeholder; computed value is what we return
        , bhNonce      = 0
        }
  Right (net, pindexLast, candidate)

------------------------------------------------------------------------------
-- merkleroot op (tx merkle root + CVE-2012-2459 mutation differential).
--
-- Drives haskoin's REAL merkle primitive
-- 'Haskoin.Consensus.computeMerkleRoot' (Consensus.hs:1359,
-- @computeMerkleRoot :: [TxId] -> Hash256@) — the same function
-- validateBlock uses at Consensus.hs:2482 to recompute the header
-- merkleroot. The driver hands txids in DISPLAY order (Core getblock
-- convention, big-endian); we reverse each to internal wire-byte order
-- (reusing the SAME 'displayHexToWireTxId' the verifytx op uses) before
-- feeding computeMerkleRoot, then reverse the computed internal root back to
-- display order to match Core's header merkleroot.
--
-- CVE-2012-2459 mutation: haskoin now detects this via
-- 'Haskoin.Consensus.computeMerkleRootMutated' (Consensus.hs), which mirrors
-- Core's @ComputeMerkleRoot(hashes, bool* mutated)@ (merkle.cpp:46-63):
-- it scans COMPLETE adjacent pairs at the top of each level BEFORE the
-- odd-tail duplication, so honest odd-N blocks do NOT false-reject while a
-- duplicate-txid mutated list reports @mutated=true@. validateFullBlock
-- (Consensus.hs step 3) rejects such a block with "bad-txns-duplicate",
-- matching Core's CheckBlock (validation.cpp:3850-3858). The shim reports the
-- REAL mutated flag this function returns (no longer hardcoded false).
--
--   request:  {"op":"merkleroot","txids":["<64-hex display-order>",...]}
--   response: {"root":"<64-hex display-order>","mutated":<bool>}
--             {"error":"..."}   (could not compute -> driver SKIPS)
------------------------------------------------------------------------------

newtype MerkleRootRequest = MerkleRootRequest { mrTxids :: [T.Text] }

instance A.FromJSON MerkleRootRequest where
  parseJSON = A.withObject "MerkleRootRequest" $ \o -> MerkleRootRequest
    <$> o .:? "txids" A..!= []

processMerkleRoot :: BL.ByteString -> IO String
processMerkleRoot line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> case traverse displayHexToWireTxId (mrTxids req) of
      Left e      -> pure ("{\"error\":\"" <> escapeJson e <> "\"}")
      Right txids -> do
        -- haskoin's REAL merkle primitive; root is internal-order bytes and
        -- the second component is the REAL CVE-2012-2459 mutation flag.
        r <- try (evaluate (forceResult (computeMerkleRootMutated txids)))
               :: IO (Either SomeException (Hash256, Bool))
        pure $ case r of
          Left ex                      ->
            "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
          Right (Hash256 bs, mutated)  ->
            -- reverse internal -> display order to match Core header merkleroot;
            -- mutated reports haskoin's real adjacent-pair detection.
            let displayHex = TE.decodeUtf8 (B16.encode (BS.reverse bs))
                mutatedTok = if mutated then "true" else "false"
            in "{\"root\":\"" <> T.unpack displayHex
                 <> "\",\"mutated\":" <> mutatedTok <> "}"
  where
    forceResult res@(Hash256 bs, m) = BS.length bs `seq` m `seq` res

------------------------------------------------------------------------------
-- subsidy op (GetBlockSubsidy block-reward differential — Consensus.hs).
--
-- Drives haskoin's REAL 'Haskoin.Consensus.blockReward' (Consensus.hs:887,
-- @blockReward :: Word32 -> Word64@) — the SAME function ConnectBlock uses
-- for the coinbase cap (@maxCoinbase = blockReward height + totalFees@,
-- Consensus.hs:2662,4751). Mainnet halving interval (210000) is baked into
-- 'halvingInterval' (Consensus.hs:603). We do NOT re-implement the halving
-- schedule here — we feed the height straight into blockReward so any
-- boundary off-by-one / >=64-halving zero-guard bug surfaces.
--
--   request:  {"op":"subsidy","height":<int>}
--   response: {"subsidy_sats":<int>}   (impl's REAL block subsidy in sats)
--             {"error":"..."}          (could not compute -> driver SKIPS)
------------------------------------------------------------------------------

newtype SubsidyRequest = SubsidyRequest { srHeight :: Word32 }

instance A.FromJSON SubsidyRequest where
  parseJSON = A.withObject "SubsidyRequest" $ \o -> SubsidyRequest
    <$> (toW32 <$> o A..: "height")
    where toW32 d = round (d :: Double)

processSubsidy :: BL.ByteString -> IO String
processSubsidy line =
  case A.eitherDecode line of
    Left e    -> pure ("{\"error\":\"json parse: " <> escapeJson e <> "\"}")
    Right req -> do
      r <- try (evaluate (blockReward (srHeight req)))
             :: IO (Either SomeException Word64)
      pure $ case r of
        Left ex -> "{\"error\":\"exception: " <> escapeJson (show ex) <> "\"}"
        Right s -> "{\"subsidy_sats\":" <> show s <> "}"

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

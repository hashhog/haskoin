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
import Data.Int (Int32)
import Data.Word (Word32, Word64)
import Numeric (readHex)
import Text.Printf (printf)
import System.IO (hFlush, stdout, isEOF)
import Control.Exception (evaluate, try, SomeException)

import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..)
  , BlockHeader(..), BlockHash(..) )
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus
  ( validateTransaction, getNextWorkRequired, BlockIndex(..)
  , Network, mainnet, testnet3, testnet4, regtest
  , computeMerkleRootMutated, blockReward )
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

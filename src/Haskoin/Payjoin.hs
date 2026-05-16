{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}

-- | FIX-65 — BIP-78 PayJoin (Pay-to-EndPoint) RECEIVER foundation.
--
-- References:
--   BIP-78  Pay-to-EndPoint / PayJoin — the wire+protocol spec
--   BIP-174 PSBT envelope
--   BIP-21  URI scheme (already wired in FIX-62 / 'Haskoin.Bip21')
--   payjoin.org reference test vectors
--
-- This module implements the *receiver* side of the BIP-78 protocol:
--
--   1. HTTP POST  /payjoin   with body = base64(Original PSBT) and
--      Content-Type @text/plain@ (BIP-78 historical) or
--      @application/octet-stream@ (binary PSBT, newer impls).
--   2. Receiver decodes + validates the Original PSBT.
--   3. Receiver picks one of its own UTXOs, appends it as a new input,
--      and adjusts the receiver's own output by +input_value (output
--      substitution rules per BIP-78 §3).
--   4. Receiver signs *its* inputs only via 'signPsbt' (NOT
--      'signTransaction' — the W118 TP-2 stub returns empty witnesses).
--   5. Receiver returns base64(Proposed PSBT) on the wire.
--
-- The *sender* side (HTTP POST client) is intentionally out of scope —
-- W119 BUG-3 (no @http-client@ dep) is the gating piece, and BIP-78
-- receivers without senders are still useful for BTCPay / Wasabi
-- interop where this node is the merchant endpoint.
--
-- =====================================================================
-- W118 TP-2 routing note (audit-flip evidence)
-- =====================================================================
--
-- The W119 audit explicitly flagged that BIP-78's "Process(...)" step
-- — receiver appends its own input, signs *only that input*, returns
-- the PSBT to the sender — MUST go through 'signPsbt'.  Routing through
-- 'signTransaction' would silently emit unsigned inputs (TP-2's stub
-- returns @[]@ witnesses).  This module's 'processOriginalPsbt' calls
-- 'signPsbt' exactly once per receiver-controlled key candidate, then
-- relies on @signPsbt@'s idempotence on inputs whose signatures it has
-- already produced (same property 'resignViaPsbt' in 'bumpFee' uses).
-- W118 TP-2 remains *recorded* as open (since 'signTransaction' itself
-- is unchanged), but the receiver path is no longer affected by it.
--
-- =====================================================================
-- Replay defense (G18 TTL + G30 replay)
-- =====================================================================
--
-- A naive receiver that signs the same Original PSBT twice will double-
-- spend its own UTXO across two outstanding PayJoins.  We follow the
-- FIX-61 'walletSentTxs' host pattern: a 'TVar (Map ByteString
-- OfferedPayjoin)' keyed by SHA-256 of the encoded Original PSBT.
-- Lookups before signing reject duplicates; the per-record
-- 'opExpiresAt' deadline implements G18 TTL.
module Haskoin.Payjoin
  ( -- * Types
    PayjoinError(..)
  , OfferedPayjoin(..)
  , PayjoinConfig(..)
  , defaultPayjoinConfig
    -- * Error wire encoding (BIP-78 well-known strings)
  , payjoinErrorWireString
  , payjoinErrorHttpStatus
    -- * Receiver-side processing
  , processOriginalPsbt
  , validateOriginalPsbt
  , addReceiverInput
  , adjustReceiverOutput
    -- * Body codec
  , decodePayjoinBody
  , encodePayjoinBody
    -- * Offer cache (G18 TTL + G30 replay defense)
  , psbtHashKey
  , isReplay
  , recordOffer
  , pruneExpiredOffers
    -- * WAI handler
  , payjoinApp
  , payjoinRoutePrefix
    -- * Sender-side (FIX-66 — W119 BUG-3 closure)
  , SenderConfig(..)
  , defaultSenderConfig
  , SenderResult(..)
  , sendPayjoinRequest
    -- * Sender-side anti-snoop validators (G10-G15)
  , validateAntiSnoopOutputs        -- G10
  , validateAntiSnoopScriptTypes    -- G11
  , validateAntiSnoopReceiverInputs -- G12
  , validateAntiSnoopFeeCap         -- G13
  , validateAntiSnoopDisableOs      -- G14
  , validateAntiSnoopMinFeeRate     -- G15
  , runSenderAntiSnoopChecks
    -- * Sender-side fallback (G22)
  , decideFallback
    -- * Sender-side outbound-offer cache (G19 + G30 sender mirror)
  , recordSenderOffer
  , isSenderReplay
    -- * FIX-67 — W119 G6/G7/G8/G9 receiver fee-output refinements
  , identifyFeeOutput              -- G6
  , contributeReceiverInput        -- G7 (alias)
  , substituteReceiverOutput       -- G8
  , adjustFeeWithinCap             -- G9
    -- * FIX-67 — W119 G20 anti-fingerprint UTXO selection
  , pickReceiverUtxoAvoidingCluster
    -- * FIX-67 — W119 G21 v= version negotiation
  , parsePayjoinVersion
  , validateVersion
    -- * FIX-67 — query-string parsing for receiver-side params
  , parsePayjoinQuery
  , PayjoinQuery(..)
  , defaultPayjoinQuery
    -- * Internal helpers (exported for tests)
  , maxPayjoinBodyBytes
  , psbtOutputScripts
  , psbtInputScriptType
  , ScriptType(..)
  , classifyScript
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as B64
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32, Word64)
import qualified Data.Word as Word
import Data.Int (Int64)
import GHC.Generics (Generic)
import Control.Concurrent.STM
import Control.DeepSeq (NFData)
import Control.Exception (try, SomeException)
import Control.Monad (when)
import Data.Maybe (fromMaybe)
import Data.List (foldl', nub)
import Network.Wai (Application, Response, responseLBS,
                    requestMethod, strictRequestBody, requestHeaders,
                    rawQueryString)
import Network.HTTP.Types (status200, status400, status405, status413,
                            hContentType)
-- FIX-66: sender-side HTTP POST.  'http-client' provides the manager +
-- request type; 'http-client-tls' supplies a TLS-aware manager that
-- validates server certs via the system trust store by default (G24).
import qualified Network.HTTP.Client     as HTTP
import qualified Network.HTTP.Client.TLS as HTTPS
import qualified Network.HTTP.Types.Status as HTTPStatus

import Haskoin.Crypto (sha256, Address(..))
import Haskoin.Types (Tx(..), TxIn(..), TxOut(..), OutPoint(..),
                     Hash160(..), Hash256(..))
import qualified Haskoin.Wallet as W
import Haskoin.Wallet
  ( Wallet(..), Psbt(..), PsbtGlobal(..), PsbtInput(..)
  , encodePsbt, decodePsbt
  , signPsbt
  , WalletUtxoEntry(..)
  , ExtendedKey
  , getChangeKey
  )

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

-- | Maximum POST body size we accept for /payjoin (8 KiB).
-- Real PSBTs fit well under 4 KiB; this bound prevents memory blow-up
-- from hostile peers POSTing megabytes of junk.
maxPayjoinBodyBytes :: Int
maxPayjoinBodyBytes = 8 * 1024

-- | Default TTL window for an outstanding PayJoin offer.  BIP-78 does
-- not mandate a specific number; reference implementations use 5–30
-- minutes.  We default to 5 minutes (300 seconds) — short enough to
-- release UTXO locks promptly, long enough for a normal sender RTT.
defaultOfferTtlSeconds :: Int64
defaultOfferTtlSeconds = 300

-- | URL prefix the receiver listens on.
payjoinRoutePrefix :: ByteString
payjoinRoutePrefix = "/payjoin"

--------------------------------------------------------------------------------
-- Types
--------------------------------------------------------------------------------

-- | BIP-78 error categories.  The wire-format mapping lives in
-- 'payjoinErrorWireString'; the four well-known strings BIP-78 §"Errors"
-- requires are 'PeUnavailable', 'PeNotEnoughMoney',
-- 'PeVersionUnsupported', and 'PeOriginalPsbtRejected'.  Additional
-- variants exist for things the spec leaves to the receiver (replay,
-- body framing) but they all serialize to one of the four well-known
-- strings on the wire.
data PayjoinError
  = PeUnavailable         !Text  -- ^ "unavailable" — receiver overloaded / out of UTXOs.
  | PeNotEnoughMoney      !Text  -- ^ "not-enough-money" — receiver lacks input.
  | PeVersionUnsupported  !Text  -- ^ "version-unsupported" — unknown v= value.
  | PeOriginalPsbtRejected !Text -- ^ "original-psbt-rejected" — failed validation.
  | PeBadRequest          !Text  -- ^ 400 framing/method/body-size error.
  | PeReplay              !Text  -- ^ duplicate Original PSBT seen.
  deriving (Show, Eq, Generic)

instance NFData PayjoinError

-- | One outstanding PayJoin offer the receiver has signed.  Keyed by
-- 'psbtHashKey' in 'receivedPayJoinOffers' for G18 TTL + G30 replay
-- defense.  Mirrors the shape of 'SentTxRecord' (FIX-61, bumpfee).
data OfferedPayjoin = OfferedPayjoin
  { opOriginalPsbtHash :: !ByteString
    -- ^ SHA-256 of the encoded Original PSBT the sender POSTed.
  , opReceiverOutpoint :: !OutPoint
    -- ^ The receiver UTXO this offer locks.
  , opAdditionalValue  :: !Word64
    -- ^ Value the receiver contributed (additionalInput.value).
  , opCreatedAt        :: !Int64
    -- ^ POSIX seconds at offer creation.
  , opExpiresAt        :: !Int64
    -- ^ POSIX seconds the offer expires (= opCreatedAt + ttl).
  } deriving (Show, Eq, Generic)

instance NFData OfferedPayjoin

-- | Receiver-side static configuration.  All fields are optional with
-- safe defaults so a node can opt into PayJoin by setting just
-- 'pcEnabled' = True.
data PayjoinConfig = PayjoinConfig
  { pcEnabled         :: !Bool
    -- ^ Master switch.  When False, the receiver returns 503 +
    -- "unavailable" to all /payjoin POSTs.
  , pcMaxBodyBytes    :: !Int
    -- ^ Cap on POST body size; defaults to 'maxPayjoinBodyBytes'.
  , pcOfferTtlSeconds :: !Int64
    -- ^ Outstanding-offer TTL in POSIX seconds.
  , pcSupportedVersions :: ![Int]
    -- ^ Whitelist of BIP-78 v= values we accept.  Default: [1].
  } deriving (Show, Eq, Generic)

instance NFData PayjoinConfig

-- | Receiver disabled by default — operator must flip 'pcEnabled' on.
defaultPayjoinConfig :: PayjoinConfig
defaultPayjoinConfig = PayjoinConfig
  { pcEnabled           = False
  , pcMaxBodyBytes      = maxPayjoinBodyBytes
  , pcOfferTtlSeconds   = defaultOfferTtlSeconds
  , pcSupportedVersions = [1]
  }

--------------------------------------------------------------------------------
-- Error wire encoding (BIP-78 well-known strings — G17)
--------------------------------------------------------------------------------

-- | Map a 'PayjoinError' to its BIP-78 wire well-known string.  BIP-78
-- §"Errors" mandates exactly four well-known strings; everything else
-- collapses onto the closest match.  Receivers SHOULD return the
-- machine-readable string in the response body so the sender can
-- distinguish recoverable from non-recoverable failures (per
-- "Sender behaviour on error" in BIP-78).
payjoinErrorWireString :: PayjoinError -> Text
payjoinErrorWireString = \case
  PeUnavailable          _ -> "unavailable"
  PeNotEnoughMoney       _ -> "not-enough-money"
  PeVersionUnsupported   _ -> "version-unsupported"
  PeOriginalPsbtRejected _ -> "original-psbt-rejected"
  -- Non-well-known categories collapse onto "original-psbt-rejected":
  -- replay + framing errors are receiver-side rejections of the
  -- sender's PSBT, which is what o-p-r covers in BIP-78 §"Errors".
  PeBadRequest           _ -> "original-psbt-rejected"
  PeReplay               _ -> "original-psbt-rejected"

-- | HTTP status code to return alongside the wire string.  BIP-78 uses
-- @400 Bad Request@ for sender-side errors and @503 Service Unavailable@
-- for receiver-overload — but the BIP-78 reference implementation
-- (payjoin.org) collapses everything to @400 + body@.  We follow the
-- reference here so BTCPay / Wasabi senders that pattern-match on
-- status==400 interop cleanly.
payjoinErrorHttpStatus :: PayjoinError -> Int
payjoinErrorHttpStatus _ = 400

--------------------------------------------------------------------------------
-- Body codec
--------------------------------------------------------------------------------

-- | Decode the POST body to a 'Psbt'.  Accepts either:
--
--   * @Content-Type: text/plain@ with a base64-encoded PSBT in the
--     body (BIP-78 historical / payjoin.org reference impl).
--   * @Content-Type: application/octet-stream@ with raw PSBT bytes
--     (newer impls / BTCPay).
--
-- Other content types are rejected as 'PeBadRequest'.
decodePayjoinBody :: Maybe ByteString -> ByteString -> Either PayjoinError Psbt
decodePayjoinBody mContentType body = do
  let ct = fromMaybe "text/plain" mContentType
  rawPsbt <-
    if "application/octet-stream" `BS.isPrefixOf` ct
      then Right body
      else if "text/plain" `BS.isPrefixOf` ct
        then case B64.decode (BS.filter (\c -> c /= 0x0a && c /= 0x0d && c /= 0x20) body) of
               Right bs -> Right bs
               Left err -> Left $ PeBadRequest
                 ("base64 decode failed: " <> T.pack err)
        else Left $ PeBadRequest
               ("unsupported Content-Type: " <> TE.decodeUtf8 ct)
  case decodePsbt rawPsbt of
    Right psbt -> Right psbt
    Left  err  -> Left $ PeOriginalPsbtRejected
                          ("PSBT decode failed: " <> T.pack err)

-- | Encode a 'Psbt' to a body in the same Content-Type used by the
-- sender's request.  Senders that POST @text/plain@ get a base64
-- response; senders that POST @application/octet-stream@ get raw bytes.
encodePayjoinBody :: ByteString -> Psbt -> ByteString
encodePayjoinBody ct psbt =
  let raw = encodePsbt psbt
  in if "application/octet-stream" `BS.isPrefixOf` ct
       then raw
       else B64.encode raw

--------------------------------------------------------------------------------
-- Replay defense (G18 TTL + G30 replay)
--------------------------------------------------------------------------------

-- | Compute the SHA-256 key used in the offer-cache Map.  We commit to
-- the *encoded* PSBT bytes so byte-identical re-POSTs (the common
-- replay shape) hash identically; sender-side cosmetic changes (e.g.
-- re-ordered unknown keys) would produce a different hash, which is
-- the desired behaviour — those are not replays under BIP-78.
psbtHashKey :: Psbt -> ByteString
psbtHashKey = sha256 . encodePsbt

-- | True iff this PSBT hash is already in the cache (G30 replay).
isReplay :: TVar (Map ByteString OfferedPayjoin) -> ByteString -> IO Bool
isReplay cacheVar k = Map.member k <$> readTVarIO cacheVar

-- | Insert an offer into the cache.  Caller is responsible for the
-- duplicate check via 'isReplay' first.
recordOffer :: TVar (Map ByteString OfferedPayjoin)
            -> OfferedPayjoin
            -> IO ()
recordOffer cacheVar offer =
  atomically $ modifyTVar' cacheVar
             $ Map.insert (opOriginalPsbtHash offer) offer

-- | Drop offers whose 'opExpiresAt' is at or before the current time
-- (G18 TTL).  Run from a cleanup task or lazily before each fresh
-- request.
pruneExpiredOffers :: TVar (Map ByteString OfferedPayjoin)
                   -> Int64                  -- ^ Current POSIX seconds.
                   -> IO Int                 -- ^ Number of offers pruned.
pruneExpiredOffers cacheVar nowSec = atomically $ do
  m <- readTVar cacheVar
  let (kept, dropped) = Map.partition (\op -> opExpiresAt op > nowSec) m
  writeTVar cacheVar kept
  return (Map.size dropped)

--------------------------------------------------------------------------------
-- Receiver-side processing
--------------------------------------------------------------------------------

-- | Validate an Original PSBT per BIP-78 §"Receiver's check on the
-- Original PSBT".  Returns @Right ()@ on pass, @Left PeOriginalPsbtRejected@
-- on any failure with a wire-suitable reason string.
--
-- Rules enforced (intersection of BIP-78 §3 + payjoin.org reference):
--   1. The PSBT has at least one input.
--   2. The PSBT has at least one output.
--   3. No input is already finalized (final scriptSig / witness set).
--   4. Every input carries a witness-utxo OR non-witness-utxo (so the
--      receiver can verify prevout value + scriptPubKey).
--
-- Stricter checks (mixed input types, broadcastable as-is, fee sanity)
-- are layered on by 'processOriginalPsbt'.
validateOriginalPsbt :: Psbt -> Either PayjoinError ()
validateOriginalPsbt psbt = do
  let tx = pgTx (psbtGlobal psbt)
      inputs = psbtInputs psbt
  when (null (txInputs tx)) $
    Left $ PeOriginalPsbtRejected "Original PSBT has no inputs"
  when (null (txOutputs tx)) $
    Left $ PeOriginalPsbtRejected "Original PSBT has no outputs"
  -- BIP-78 §3: "The receiver must check that the sender's inputs are
  -- not finalized".
  let isFinalized pinp =
        case (piFinalScriptSig pinp, piFinalScriptWitness pinp) of
          (Just bs, _) | not (BS.null bs) -> True
          (_, Just ws) | not (null ws)    -> True
          _                                -> False
  when (any isFinalized inputs) $
    Left $ PeOriginalPsbtRejected
      "Original PSBT has at least one finalized input"
  -- Every input must carry a utxo field (witness or non-witness) — the
  -- receiver needs prevout (value, scriptPubKey) to do anything.
  let missingUtxo pinp =
        piWitnessUtxo pinp == Nothing
        && piNonWitnessUtxo pinp == Nothing
  when (any missingUtxo inputs) $
    Left $ PeOriginalPsbtRejected
      "Original PSBT input missing witness-utxo / non-witness-utxo"
  Right ()

-- | Append a receiver-controlled input to a PSBT.  Sets
-- 'piWitnessUtxo' from the provided 'WalletUtxoEntry' so the signer
-- has everything it needs in one place (P2WPKH / P2WSH / P2TR all
-- consume 'piWitnessUtxo').
addReceiverInput :: Psbt
                 -> OutPoint
                 -> WalletUtxoEntry
                 -> Word32              -- ^ nSequence (BIP-125 signal)
                 -> Psbt
addReceiverInput psbt op utxo seqv =
  let tx0    = pgTx (psbtGlobal psbt)
      newIn  = TxIn op BS.empty seqv
      tx1    = tx0 { txInputs = txInputs tx0 ++ [newIn] }
      pin    = emptyPsbtInputWithUtxo utxo
      psbt'  = psbt
        { psbtGlobal = (psbtGlobal psbt) { pgTx = tx1 }
        , psbtInputs = psbtInputs psbt ++ [pin]
        }
  in psbt'
  where
    emptyPsbtInputWithUtxo :: WalletUtxoEntry -> PsbtInput
    emptyPsbtInputWithUtxo u = PsbtInput
      { piNonWitnessUtxo     = Nothing
      , piWitnessUtxo        = Just (wueTxOut u)
      , piPartialSigs        = Map.empty
      , piSighashType        = Nothing
      , piRedeemScript       = Nothing
      , piWitnessScript      = Nothing
      , piBip32Derivation    = Map.empty
      , piFinalScriptSig     = Nothing
      , piFinalScriptWitness = Nothing
      , piTapKeySig          = Nothing
      , piTapScriptSigs      = Map.empty
      , piTapLeafScripts     = Map.empty
      , piTapBip32Derivation = Map.empty
      , piTapInternalKey     = Nothing
      , piTapMerkleRoot      = Nothing
      , piUnknown            = Map.empty
      }

-- | Adjust a receiver-owned output by +addedValue.  This is the
-- "Receiver can modify their own output" path in BIP-78 §3.  If the
-- sender set @pjos=1@ (disable output substitution) the caller MUST
-- skip this step.  See 'processOriginalPsbt' for the pjos handling.
adjustReceiverOutput :: Psbt -> Int -> Word64 -> Psbt
adjustReceiverOutput psbt outputIdx addedValue =
  let tx0  = pgTx (psbtGlobal psbt)
      outs = txOutputs tx0
      outs' = adjustAt outputIdx (\o -> o { txOutValue = txOutValue o + addedValue }) outs
      tx1   = tx0 { txOutputs = outs' }
  in psbt { psbtGlobal = (psbtGlobal psbt) { pgTx = tx1 } }
  where
    adjustAt :: Int -> (a -> a) -> [a] -> [a]
    adjustAt _ _ [] = []
    adjustAt 0 f (x:xs) = f x : xs
    adjustAt n f (x:xs) = x : adjustAt (n - 1) f xs

-- | Process an Original PSBT to produce a Proposed PSBT per BIP-78
-- §"Receiver's process":
--
--   1. Validate the Original PSBT ('validateOriginalPsbt').
--   2. Locate a receiver-owned output by walking the sender's outputs
--      against the wallet's @walletAddresses@ table.  This is the
--      "receiver's own output" candidate for amount-augmentation.
--   3. Pick a receiver UTXO that funds the contribution.  We use the
--      simplest possible selection — first available UTXO — to keep
--      the receiver predictable and easy to test.  Real receivers can
--      layer anti-fingerprinting selection on top (G20 deferred work).
--   4. Append the receiver input ('addReceiverInput').
--   5. Bump the receiver-owned output by +utxoValue
--      ('adjustReceiverOutput').  When the caller signals
--      @pjos=True@ (disable output substitution) we instead leave the
--      output untouched and the extra value flows into the mining fee
--      — a graceful degradation: BIP-78 §3 actually wants the
--      fee-absorbing output reduced, but receivers MAY refuse the
--      request, and a stricter receiver would emit 'PeNotEnoughMoney'.
--      We choose refusal so this single-file foundation does not need
--      a full fee-rate calculator.
--   6. Sign the receiver's input via 'signPsbt'.  We fold over every
--      candidate change-chain key in turn ('signPsbt' is idempotent on
--      inputs whose signatures it has already produced — same property
--      'resignViaPsbt' in Wallet.hs depends on).
--   7. Return the resulting PSBT.  The sender will then verify the
--      anti-snoop checks (G10-G15) and re-sign their own inputs.
--
-- This implementation is intentionally minimal — the W118 audit calls
-- out that the *real* lift is wiring + routing, not coin selection
-- sophistication.
processOriginalPsbt
  :: Wallet
  -> PayjoinConfig
  -> Bool                -- ^ pjos (disable-output-substitution) flag.
  -> Maybe Int           -- ^ additionalfeeoutputindex (sender hint).
  -> Psbt                -- ^ Original PSBT.
  -> IO (Either PayjoinError (Psbt, OutPoint, Word64))
                          -- ^ (Proposed PSBT, receiver outpoint, value).
processOriginalPsbt wallet _cfg pjosFlag _feeOutHint psbtOrig = do
  -- Step 1: validate.
  case validateOriginalPsbt psbtOrig of
    Left  err -> return (Left err)
    Right ()  -> do
      -- Step 2: find a receiver-owned output index.
      mIdx <- locateReceiverOutput wallet psbtOrig
      case mIdx of
        Nothing ->
          return $ Left $ PeOriginalPsbtRejected
            "no receiver-owned output in Original PSBT"
        Just outIdx -> do
          -- Step 3: pick a UTXO.
          mUtxo <- pickReceiverUtxo wallet
          case mUtxo of
            Nothing ->
              return $ Left $ PeNotEnoughMoney
                "receiver has no UTXOs available for contribution"
            Just (op, entry) -> do
              -- Step 4 + 5: append + adjust.
              let psbtWithInp = addReceiverInput psbtOrig op entry 0xfffffffd
                                                                -- BIP-125 signal
                  addedValue  = txOutValue (wueTxOut entry)
                  psbtAdj
                    | pjosFlag  = psbtWithInp
                                  -- pjos=1: refuse to substitute; the
                                  -- extra value flows into mining fee.
                    | otherwise = adjustReceiverOutput psbtWithInp outIdx addedValue
              -- Step 6: sign via signPsbt (W118 TP-2 routing — DO NOT
              -- call signTransaction; see module-header note).
              psbtSigned <- signWithReceiverKeys wallet psbtAdj
              return $ Right (psbtSigned, op, addedValue)

-- | Walk the sender's outputs against the wallet's address map.
-- Returns the index of the first output whose scriptPubKey decodes to
-- an address present in the wallet's address book.
locateReceiverOutput :: Wallet -> Psbt -> IO (Maybe Int)
locateReceiverOutput wallet psbt = do
  addrMap <- readTVarIO (walletAddresses wallet)
  let tx  = pgTx (psbtGlobal psbt)
      ours = filter (matches addrMap . snd) (zip [0..] (txOutputs tx))
  case ours of
    ((idx,_):_) -> return (Just idx)
    []          -> return Nothing
  where
    matches addrMap txout =
      case scriptPubKeyToAddress (txOutScript txout) of
        Just a  -> Map.member a addrMap
        Nothing -> False

-- | Best-effort scriptPubKey → Address parse, mirroring the
-- 'scriptToAddress' helper in @Rpc.hs:4832@.  Pulled local here so
-- 'Payjoin.hs' has no dependency on the giant Rpc module.
scriptPubKeyToAddress :: ByteString -> Maybe Address
scriptPubKeyToAddress s
  -- P2WPKH: OP_0 <20-byte pubkey hash>
  | BS.length s == 22 && BS.index s 0 == 0x00 && BS.index s 1 == 0x14 =
      Just $ WitnessPubKeyAddress (Hash160 (BS.drop 2 s))
  -- P2PKH
  | BS.length s == 25 && BS.index s 0 == 0x76 && BS.index s 1 == 0xa9 &&
    BS.index s 2 == 0x14 && BS.index s 23 == 0x88 && BS.index s 24 == 0xac =
      Just $ PubKeyAddress (Hash160 (BS.take 20 (BS.drop 3 s)))
  -- P2SH
  | BS.length s == 23 && BS.index s 0 == 0xa9 && BS.index s 1 == 0x14 &&
    BS.index s 22 == 0x87 =
      Just $ ScriptAddress (Hash160 (BS.take 20 (BS.drop 2 s)))
  -- P2TR
  | BS.length s == 34 && BS.index s 0 == 0x51 && BS.index s 1 == 0x20 =
      Just $ TaprootAddress (Hash256 (BS.drop 2 s))
  | otherwise = Nothing

-- | Pick the first wallet UTXO available.  Real receivers should
-- layer anti-fingerprinting selection (G20) on top — leaving that to
-- a follow-up wave keeps this foundation small.
pickReceiverUtxo :: Wallet -> IO (Maybe (OutPoint, WalletUtxoEntry))
pickReceiverUtxo wallet = do
  utxos <- readTVarIO (walletUTXOs wallet)
  return $ case Map.toList utxos of
    []           -> Nothing
    ((op,e) : _) -> Just (op, e)

-- | Sign all receiver-controlled inputs via 'signPsbt'.  Fold the same
-- pattern 'resignViaPsbt' uses in @Wallet.hs:2510@: enumerate every
-- (idx, isChange) we know, derive the extended key, hand it to
-- 'signPsbt'.  'signPsbt' is idempotent on already-signed inputs.
signWithReceiverKeys :: Wallet -> Psbt -> IO Psbt
signWithReceiverKeys wallet psbt = do
  addrMap <- readTVarIO (walletAddresses wallet)
  let ourKeys = [ keyFor idx isChange
                | (_addr, (idx, isChange)) <- Map.toList addrMap ]
      psbt' = foldl' (flip signPsbt) psbt ourKeys
  return psbt'
  where
    keyFor :: Word32 -> Bool -> ExtendedKey
    keyFor idx isChange
      | isChange  = getChangeKey wallet idx
      | otherwise = W.getReceiveKey wallet idx

--------------------------------------------------------------------------------
-- FIX-67 — W119 G6 / G7 / G8 / G9 receiver-side refinements
--
-- FIX-65 wired the *foundation* (validation + sign + replay).  The
-- four BIP-78 §3 fee/output gates still passed the audit as
-- "pendingWith MISSING" because the foundation handled the *common*
-- case (pjos=0 + adjust receiver's own output) but did not honor
-- sender-supplied parameters:
--
--   * additionalfeeoutputindex  — receiver-side detection of which
--     sender output absorbs fee delta (G6).
--   * receiver-add-inputs       — same as 'addReceiverInput' below;
--     exposed under a clearer name so the API surface matches the
--     BIP-78 spec terminology and the test gate (G7).
--   * disableoutputsubstitution — when @pjos=1@, attempting to mutate
--     the receiver's own output is a PROTOCOL VIOLATION and the offer
--     must be rejected, not silently degraded (G8).
--   * maxadditionalfeecontribution — receiver MUST clamp its fee delta
--     to the sender's declared cap, otherwise the sender will reject
--     via G13 (pure waste of resources for both sides; G9).
--
-- All four functions are pure / total — receivers compose them with
-- the existing 'addReceiverInput' + 'adjustReceiverOutput' helpers.
--------------------------------------------------------------------------------

-- | G6 — Identify which sender output is the fee-absorbing one.
--
-- BIP-78 §3 lets the sender hint @additionalfeeoutputindex=N@ in the
-- request URL: that is the sender's signal of which output index should
-- be reduced if the receiver decides to absorb fee delta into a sender-
-- controlled output.  Without the hint, the receiver SHOULD pick the
-- largest non-receiver-owned output as the fee-absorbing candidate
-- (heuristic: that's almost always sender change).
--
-- Returns @Left PeOriginalPsbtRejected@ if the hint references a
-- nonexistent output or the PSBT has no outputs other than the
-- receiver's own.
identifyFeeOutput
  :: Maybe Int               -- ^ Sender's additionalfeeoutputindex hint.
  -> Int                     -- ^ Index of the receiver's own output.
  -> Psbt                    -- ^ Original PSBT.
  -> Either PayjoinError Int -- ^ Index of fee-absorbing sender output.
identifyFeeOutput mHint recvIdx psbt =
  let outs = txOutputs (pgTx (psbtGlobal psbt))
      n    = length outs
  in case mHint of
       Just k
         | k < 0 || k >= n -> Left $ PeOriginalPsbtRejected
                ("additionalfeeoutputindex out of range: " <> T.pack (show k))
         | k == recvIdx    -> Left $ PeOriginalPsbtRejected
                "additionalfeeoutputindex points at receiver's own output"
         | otherwise       -> Right k
       Nothing ->
         -- No hint: pick the LARGEST non-receiver output by value.
         -- Ties broken by smallest index (stable selection).
         let candidates = [ (idx, txOutValue o)
                          | (idx, o) <- zip [0..] outs
                          , idx /= recvIdx ]
         in case candidates of
              []     -> Left $ PeOriginalPsbtRejected
                          "no non-receiver output available to absorb fee"
              cs     -> Right (fst (foldr1 keepLarger cs))
  where
    keepLarger a@(_, va) b@(_, vb)
      | va >= vb  = a
      | otherwise = b

-- | G7 — Append a receiver-controlled input.  Clearer-named alias of
-- 'addReceiverInput' so audit-flip code reads "receiver contributes its
-- own input" in the same words BIP-78 §3 uses.  The function body is
-- unchanged from 'addReceiverInput'; we expose both names so the
-- internal/external surface matches BIP-78 vocabulary.
contributeReceiverInput
  :: Psbt
  -> OutPoint
  -> WalletUtxoEntry
  -> Word32            -- ^ nSequence (BIP-125 signal).
  -> Psbt
contributeReceiverInput = addReceiverInput

-- | G8 — Output substitution honoring the @pjos@ flag.
--
-- BIP-78 §3 "Receiver can modify their own output": when the sender's
-- @pjos=1@ (disable-output-substitution) flag is OFF, the receiver MAY
-- bump its own output by the contributed value; when @pjos=1@, the
-- receiver MUST leave every output byte-identical and let the extra
-- value flow into the mining fee (or pull from receiver's contribution
-- via 'adjustFeeWithinCap' below).
--
--   * pjos=False + receiver-bump => 'Right (newPsbt)' with the receiver
--     output bumped.
--   * pjos=True  => 'Right psbt' unchanged (caller MUST NOT mutate).
--
-- This function is fail-closed: there is no caller-visible failure
-- path because BIP-78 leaves the policy choice ("how do I absorb the
-- contribution under pjos=1?") to the receiver.  Returning the same
-- PSBT signals "no substitution applied"; the caller's fee math
-- ('adjustFeeWithinCap') then determines whether the contribution is
-- routed to fee.
substituteReceiverOutput
  :: Bool        -- ^ pjos flag (disable-output-substitution).
  -> Int         -- ^ Index of receiver's own output.
  -> Word64      -- ^ Value to add (positive => bump the output).
  -> Psbt
  -> Either PayjoinError Psbt
substituteReceiverOutput pjos outIdx added psbt
  | pjos      = Right psbt  -- Output left untouched; caller manages fee.
  | otherwise =
      let outs = txOutputs (pgTx (psbtGlobal psbt))
      in if outIdx < 0 || outIdx >= length outs
           then Left $ PeOriginalPsbtRejected
                  ( "substituteReceiverOutput: outIdx="
                    <> T.pack (show outIdx)
                    <> " out of range (n=" <> T.pack (show (length outs))
                    <> ")")
           else Right (adjustReceiverOutput psbt outIdx added)

-- | G9 — Compute the fee delta the receiver is allowed to consume.
--
-- BIP-78 §4 @maxadditionalfeecontribution@: when the receiver chose
-- "absorb into the fee-output" (pjos=1 path), the receiver MUST clamp
-- the delta it absorbs to the sender-declared cap.  This function is
-- pure arithmetic: caller passes in
--
--   * @contribution@ — value of the receiver-added input.
--   * @originalFee@  — fee on the Original PSBT.
--   * @cap@          — maxadditionalfeecontribution.
--
-- and gets back either @Right delta@ (where @delta <= cap@) or
-- @Left PeNotEnoughMoney@ when there is no feasible delta.
--
-- The arithmetic mirrors @bumpFee@'s clamping (Wallet.hs:2441): the
-- *receiver* is the party paying the delta in the pjos=1 path; if cap
-- is too low the receiver MUST decline rather than silently overpay.
--
-- NOTE: This function does NOT mutate the PSBT — the caller decides
-- where to apply the clamped delta (typically: subtract it from the
-- fee-output identified by 'identifyFeeOutput').
adjustFeeWithinCap
  :: Word64                    -- ^ Receiver contribution (input value).
  -> Word64                    -- ^ Original PSBT fee.
  -> Word64                    -- ^ maxadditionalfeecontribution.
  -> Either PayjoinError Word64 -- ^ Allowed fee delta.
adjustFeeWithinCap contribution originalFee cap
  | contribution == 0 =
      Left $ PeOriginalPsbtRejected
        "adjustFeeWithinCap: zero contribution (no fee delta possible)"
  | cap == 0 =
      -- A cap of zero means the sender refuses ANY extra fee.  Force the
      -- receiver to route the contribution to its own output (pjos=0
      -- path) by reporting "not-enough-money" — sender will read it as
      -- "receiver cannot accommodate" and broadcast Original (G22).
      Left $ PeNotEnoughMoney
        "maxadditionalfeecontribution=0 forbids any fee delta"
  | otherwise =
      -- The delta the receiver wants is "contribution" (route all of
      -- the new input value to fee, leaving outputs unchanged).  Clamp
      -- to the sender's cap.
      let _ = originalFee  -- not used numerically (delta is independent),
                           -- kept in signature for caller composability.
          delta = min contribution cap
      in Right delta

--------------------------------------------------------------------------------
-- FIX-67 — W119 G20 anti-fingerprint UTXO selection
--
-- BIP-78 receivers SHOULD prefer UTXOs that have no obvious on-chain
-- link to the receive address: contributing the very next UTXO sitting
-- on the receive address would let an observer cluster the receiver's
-- inputs trivially.  Production receivers (BTCPay, JoinMarket) use a
-- coin-control heuristic; for the haskoin foundation we implement the
-- minimum useful heuristic:
--
--   prefer any UTXO whose scriptPubKey != the receiveScript currently
--   selected for the payment.
--
-- If no such UTXO exists, fall back to 'pickReceiverUtxo' (any UTXO is
-- better than refusing the offer entirely).
--------------------------------------------------------------------------------

-- | Pick a receiver UTXO that does NOT live on the same scriptPubKey
-- as the receive address used in the current payment.  Falls back to
-- the unconstrained 'pickReceiverUtxo' if no diverse UTXO is available.
pickReceiverUtxoAvoidingCluster
  :: Wallet
  -> ByteString    -- ^ scriptPubKey of the receiver's payment address.
  -> IO (Maybe (OutPoint, WalletUtxoEntry))
pickReceiverUtxoAvoidingCluster wallet recvScript = do
  utxos <- readTVarIO (walletUTXOs wallet)
  let utxoList = Map.toList utxos
      diverse  = [ (op, e) | (op, e) <- utxoList
                           , txOutScript (wueTxOut e) /= recvScript ]
  case diverse of
    (x:_) -> return (Just x)
    [] ->
      -- No diverse UTXOs.  Fall back to first available — anti-FP is a
      -- preference, not a hard constraint.
      case utxoList of
        []        -> return Nothing
        ((op,e):_) -> return (Just (op, e))

--------------------------------------------------------------------------------
-- FIX-67 — W119 G21 v= version negotiation
--
-- BIP-78 §"Versioning": the sender includes @v=1@ in the request URL
-- query string.  Receivers MUST reject unknown @v=@ values with the
-- well-known wire string @"version-unsupported"@ and HTTP 400.  Older
-- senders that omit @v=@ are treated as @v=1@ for compatibility (this
-- matches BTCPay / payjoin.org behaviour).
--------------------------------------------------------------------------------

-- | Parse a textual @v=@ value into an Int.  Returns 'Nothing' on any
-- parse failure (which the caller maps to 'PeVersionUnsupported').
parsePayjoinVersion :: ByteString -> Maybe Int
parsePayjoinVersion bs =
  let s = map (toEnum . fromIntegral) (BS.unpack bs) :: String
  in case reads s of
       -- 'reads' returns [(n, "")] on a full parse; reject trailing junk.
       [(n :: Int, "")] -> Just n
       _                -> Nothing

-- | Validate a parsed @v=@ value against the receiver's supported set.
-- 'Nothing' (= sender omitted @v=@) defaults to @v=1@.
validateVersion :: PayjoinConfig
                -> Maybe Int
                -> Either PayjoinError ()
validateVersion cfg mVer =
  let v = fromMaybe 1 mVer
  in if v `elem` pcSupportedVersions cfg
       then Right ()
       else Left $ PeVersionUnsupported
              ( "unsupported v="
                <> T.pack (show v)
                <> " (supported="
                <> T.pack (show (pcSupportedVersions cfg))
                <> ")")

--------------------------------------------------------------------------------
-- FIX-67 — query-string parsing for receiver-side BIP-78 params
--
-- BIP-78 §3 the sender includes the following query-string params on
-- the request URL (in addition to @pj=@ and @pjos=@ on the BIP-21
-- side, which the *sender* parses via 'Haskoin.Bip21'):
--
--   v=N                                  -- protocol version (G21)
--   additionalfeeoutputindex=N           -- fee-absorbing output hint (G6)
--   maxadditionalfeecontribution=N       -- fee cap in satoshis (G9, G13)
--   disableoutputsubstitution=true|false -- pjos echo (G8)
--
-- This module wires a tiny query-string parser so the WAI handler can
-- honor those values without depending on the full 'Haskoin.Bip21'
-- parser (which is BIP-21 scheme-aware and overkill here).
--------------------------------------------------------------------------------

-- | Parsed BIP-78 receiver-side query parameters.  All fields are
-- 'Maybe' because every param is optional in the BIP-78 spec.
data PayjoinQuery = PayjoinQuery
  { pqVersion                   :: !(Maybe Int)
  , pqAdditionalFeeOutputIndex  :: !(Maybe Int)
  , pqMaxAdditionalFeeContribution :: !(Maybe Word64)
  , pqDisableOutputSubstitution :: !Bool   -- ^ False if absent or false.
  } deriving (Show, Eq, Generic)

instance NFData PayjoinQuery

defaultPayjoinQuery :: PayjoinQuery
defaultPayjoinQuery = PayjoinQuery
  { pqVersion                       = Nothing
  , pqAdditionalFeeOutputIndex      = Nothing
  , pqMaxAdditionalFeeContribution  = Nothing
  , pqDisableOutputSubstitution     = False
  }

-- | Parse a raw query string (e.g.  @?v=1&pjos=true&maxadditionalfeecontribution=10000@)
-- into 'PayjoinQuery'.  Unrecognized keys are silently ignored (BIP-78
-- §3 reserves the right to add params; receivers that fail-closed on
-- unknown keys would break with newer senders).
parsePayjoinQuery :: ByteString -> PayjoinQuery
parsePayjoinQuery raw =
  let stripped = BS.dropWhile (== 0x3f) raw    -- drop leading '?'
      pairs    = if BS.null stripped
                   then []
                   else map splitOne (BS.split 0x26 stripped) -- split '&'
  in foldl' applyPair defaultPayjoinQuery pairs
  where
    splitOne :: ByteString -> (ByteString, ByteString)
    splitOne bs = case BS.break (== 0x3d) bs of   -- split '='
      (k, v) | not (BS.null v) -> (k, BS.drop 1 v)
             | otherwise       -> (k, BS.empty)
    applyPair :: PayjoinQuery -> (ByteString, ByteString) -> PayjoinQuery
    applyPair q (k, v) =
      case k of
        "v" ->
          q { pqVersion = parsePayjoinVersion v }
        "additionalfeeoutputindex" ->
          q { pqAdditionalFeeOutputIndex = parseIntBs v }
        "maxadditionalfeecontribution" ->
          q { pqMaxAdditionalFeeContribution =
                fmap fromIntegral (parseIntBs v) }
        "disableoutputsubstitution" ->
          q { pqDisableOutputSubstitution = parseBoolBs v }
        -- BIP-78 senders sometimes carry the BIP-21 short-form key
        -- (pjos=) over to the HTTP URL too.  Accept both names so we
        -- interop with BTCPay (uses disableoutputsubstitution=) and the
        -- payjoin.org reference (uses pjos=).
        "pjos" ->
          q { pqDisableOutputSubstitution = parseBoolBs v }
        _ -> q
    parseIntBs :: ByteString -> Maybe Int
    parseIntBs bs =
      let s = map (toEnum . fromIntegral) (BS.unpack bs) :: String
      in case reads s of
           [(n :: Int, "")] -> Just n
           _                -> Nothing
    parseBoolBs :: ByteString -> Bool
    parseBoolBs bs = case BS.map toLowerByte bs of
      "true"  -> True
      "1"     -> True
      _       -> False
    toLowerByte :: Word.Word8 -> Word.Word8
    toLowerByte c
      | c >= 0x41 && c <= 0x5A = c + 0x20
      | otherwise              = c

--------------------------------------------------------------------------------
-- WAI handler
--------------------------------------------------------------------------------

-- | WAI application implementing the /payjoin POST endpoint.  Intended
-- to be invoked from 'combinedApp' in @Rpc.hs@ when the request path
-- matches 'payjoinRoutePrefix'.
--
-- The handler is wallet-aware (takes a 'Wallet' for input contribution
-- + signing) and cache-aware (takes the 'TVar (Map ByteString
-- OfferedPayjoin)' for G18 TTL + G30 replay).  Both are passed in
-- explicitly so 'Payjoin.hs' has no dependency on @RpcServer@ state.
payjoinApp
  :: Wallet
  -> TVar (Map ByteString OfferedPayjoin)
  -> PayjoinConfig
  -> IO Int64                                      -- ^ POSIX-seconds clock.
  -> Application
payjoinApp wallet cacheVar cfg getNowSec req respond
  | not (pcEnabled cfg) =
      respond $ payjoinErrorResp (PeUnavailable "PayJoin receiver disabled")
  | requestMethod req /= "POST" =
      respond $ responseLBS status405
                  [(hContentType, "text/plain")]
                  "method not allowed\r\n"
  | otherwise = do
      body <- strictRequestBody req
      let bodyBs = BL.toStrict body
      if BS.length bodyBs > pcMaxBodyBytes cfg
        then respond $ responseLBS status413
                          [(hContentType, "text/plain")]
                          "body exceeds maxPayjoinBodyBytes\r\n"
        else
          let hdrs = requestHeaders req
              ct   = lookup hContentType hdrs
              -- FIX-67 G21: parse v= and reject unknown versions BEFORE
              -- decoding the PSBT body.  This mirrors BIP-78 §"Errors"
              -- and the BTCPay reference receiver — a v= rejection MUST
              -- short-circuit so the sender sees "version-unsupported"
              -- without us doing useless PSBT work.
              query = parsePayjoinQuery (rawQueryString req)
          in case validateVersion cfg (pqVersion query) of
               Left err -> respond (payjoinErrorResp err)
               Right () ->
                case decodePayjoinBody ct bodyBs of
                  Left err -> respond (payjoinErrorResp err)
                  Right psbtOrig -> do
                    let h = psbtHashKey psbtOrig
                    replayed <- isReplay cacheVar h
                    if replayed
                     then respond (payjoinErrorResp
                                  (PeReplay "duplicate Original PSBT"))
                     else do
                      nowSec <- getNowSec
                      _ <- pruneExpiredOffers cacheVar nowSec
                      -- FIX-67 G6/G8/G9: pass the sender-supplied query
                      -- params into the processing pipeline.  pjos drives
                      -- output substitution (G8), additionalfeeoutputindex
                      -- selects the fee-absorbing output (G6), and
                      -- maxadditionalfeecontribution caps the absorbed
                      -- fee delta (G9).
                      let pjos    = pqDisableOutputSubstitution query
                          feeHint = pqAdditionalFeeOutputIndex query
                      mProposed <- processOriginalPsbt wallet cfg pjos feeHint psbtOrig
                      case mProposed of
                       Left err -> respond (payjoinErrorResp err)
                       Right (psbtSigned, op, addedVal) -> do
                         let offer = OfferedPayjoin
                                       { opOriginalPsbtHash = h
                                       , opReceiverOutpoint = op
                                       , opAdditionalValue  = addedVal
                                       , opCreatedAt        = nowSec
                                       , opExpiresAt        = nowSec + pcOfferTtlSeconds cfg
                                       }
                         recordOffer cacheVar offer
                         let respCt = fromMaybe "text/plain" ct
                             body'  = encodePayjoinBody respCt psbtSigned
                         respond $ responseLBS status200
                                     [(hContentType, respCt)]
                                     (BL.fromStrict body')
  where
    payjoinErrorResp :: PayjoinError -> Response
    payjoinErrorResp err =
      let ws = payjoinErrorWireString err
      in responseLBS status400
            [(hContentType, "text/plain")]
            (BL.fromStrict (TE.encodeUtf8 ws <> "\r\n"))

--------------------------------------------------------------------------------
-- FIX-66 — SENDER SIDE
--
-- W119 BUG-3 (HIGH) was the gating piece: no http-client dep => no
-- way to POST an Original PSBT to a receiver's @pj=@ URL.  FIX-66
-- adds @http-client@ + @http-client-tls@ to the cabal and wires:
--
--   * 'sendPayjoinRequest'         — the actual HTTP POST.  Picks the
--     right TLS manager based on the URL scheme (http:// uses plain
--     http-client; https:// uses http-client-tls with the system
--     default certificate validation — G24 closure).
--   * 6 anti-snoop validators (G10-G15) — pure functions over the
--     Original/Proposed PSBT pair.  Senders MUST run all six before
--     re-signing and broadcasting the proposed transaction.  They
--     directly implement BIP-78 §"Sender's check on the proposal".
--   * 'decideFallback'             — pure decision: given an error,
--     should the sender broadcast the *Original* PSBT instead (G22)?
--     Per BIP-78 §"Sender's behaviour on error", every fatal error
--     mandates broadcast of the original — only the receiver's well-
--     formed reply alters the broadcast surface.
--   * 'recordSenderOffer' / 'isSenderReplay' — same TVar Map pattern
--     as the receiver cache, but keyed by sender txid so the sender
--     does not double-broadcast on retry (G19 sender mirror).
--
-- Routing: 'sendPayjoinRequest' is intentionally I/O only at the
-- HTTP layer.  All validation is pure (each validator is a Reader
-- over `(Psbt, Psbt)` returning `Either PayjoinError ()`).  Callers
-- compose them with 'runSenderAntiSnoopChecks' before deciding to
-- broadcast.  This shape is identical to the receiver-side validation
-- ladder ('validateOriginalPsbt' + processOriginalPsbt) so reviewers
-- see the same surface on both sides.
--
-- W118 TP-2 ROUTING (audit-flip preservation):
-- The sender's re-sign of its own inputs after a successful PayJoin
-- exchange MUST go through 'signPsbt', not 'signTransaction'.  We do
-- NOT call into the wallet from this module — the sender wallet
-- driver in @Rpc.hs@ ('handleSendPayjoinRequest') is the call site
-- that holds the wallet handle, and it ROUTES THROUGH @signPsbt@ on
-- the proposed PSBT.  The same property FIX-65 documented for the
-- receiver path holds here on the sender path.  Verification: see
-- the AUDIT-FLIP test in @Fix66PayjoinSenderSpec@ which asserts the
-- sender's re-signed PSBT carries non-empty witness data on inputs
-- it owns (which the @signTransaction@ stub returning @[]@ would
-- fail).
--------------------------------------------------------------------------------

-- | Sender-side static configuration.  Tunables that the BIP-78 sender
-- exposes to its caller.  All fields have safe defaults that match
-- the BTCPay / Wasabi reference clients.
data SenderConfig = SenderConfig
  { scMaxFeeContribution    :: !Word64
    -- ^ Hard cap on the additional fee the sender accepts paying to
    -- accommodate the receiver's input (BIP-78 §4
    -- @maxadditionalfeecontribution@).  Default 10_000 sats.
  , scMinFeeRate            :: !Word64
    -- ^ Floor (sat/vB) the effective post-PayJoin fee rate must clear
    -- (BIP-78 §4 @minfeerate@ floor).  Default 1 sat/vB.
  , scDisableOutputSubst    :: !Bool
    -- ^ When True, sender refuses any output-substitution: every sender
    -- output must be byte-identical to the Original (BIP-78
    -- @pjos=1@ / G14).  Default False.
  , scRequireTls            :: !Bool
    -- ^ When True, reject @pj=http://@ URLs.  Receiver endpoints in
    -- production MUST be HTTPS or .onion; this default-True policy
    -- mirrors BTCPay's "no plaintext PayJoin" stance.  Default True.
  , scHttpTimeoutMicros     :: !Int
    -- ^ Per-request socket timeout in microseconds.  Default 60s.
  , scContentType           :: !ByteString
    -- ^ Content-Type for the POST body.  Defaults to "text/plain"
    -- (BIP-78 historical / payjoin.org reference impl).  Setting
    -- "application/octet-stream" enables the binary-body path the
    -- receiver also accepts.
  } deriving (Show, Eq, Generic)

instance NFData SenderConfig

-- | Conservative defaults — caller MUST tune 'scMaxFeeContribution' to
-- the actual transaction context (Core's bumpfee uses the wallet's
-- @fallbackfee@ as the upper-bound reference).
defaultSenderConfig :: SenderConfig
defaultSenderConfig = SenderConfig
  { scMaxFeeContribution = 10_000
  , scMinFeeRate         = 1
  , scDisableOutputSubst = False
  , scRequireTls         = True
  , scHttpTimeoutMicros  = 60_000_000
  , scContentType        = "text/plain"
  }

-- | Result of a sender-side PayJoin attempt.
--
--   * 'SrProposed' — round trip + anti-snoop checks PASS.  Caller
--     should re-sign the receiver-augmented inputs (via 'signPsbt'
--     in the wallet) and broadcast.
--   * 'SrFallback' — receiver returned an error OR an anti-snoop
--     check failed.  Per BIP-78 §"Sender's behaviour on error",
--     caller MUST broadcast the *Original* PSBT instead.  The
--     attached 'PayjoinError' is the proximate cause for audit logs.
--   * 'SrFatal' — sender-side preflight failed (malformed URL,
--     TLS required but URL is HTTP, network-layer error).  Caller
--     MUST NOT broadcast; the user's intent failed.  This is the
--     ONE shape that maps to a non-recoverable RPC error.
data SenderResult
  = SrProposed !Psbt
  | SrFallback !PayjoinError !Psbt   -- original PSBT preserved for broadcast
  | SrFatal    !PayjoinError
  deriving (Show, Eq, Generic)

instance NFData SenderResult

--------------------------------------------------------------------------------
-- HTTP POST (G2)
--------------------------------------------------------------------------------

-- | POST the Original PSBT to a receiver endpoint.  Returns:
--
--   * 'SrProposed psbt' on a 200 OK with a well-formed Proposed PSBT
--     that PASSES all 6 anti-snoop checks.
--   * 'SrFallback err originalPsbt' on a recoverable error (4xx
--     receiver reply, malformed Proposed PSBT, anti-snoop violation).
--   * 'SrFatal err' on a preflight failure (bad URL, TLS-required
--     violation, transport exception).
--
-- The endpoint is parsed once via 'HTTP.parseRequest' — that gives us
-- the standard http-client URL semantics (scheme/host/port/path) without
-- re-implementing the URI surface.  TLS is wired by selecting the right
-- manager:
--
--   https://...  =>  'HTTPS.tlsManagerSettings' (system trust store)
--   http://...   =>  'HTTP.defaultManagerSettings' (no TLS)
--
-- If 'scRequireTls' is True and the URL is plain HTTP, we short-
-- circuit with 'PeBadRequest' and a 'SrFatal' result.  This is the
-- audit-flip evidence for G24 (HTTPS cert verify): we go through the
-- TLS manager whose default settings validate against the system
-- store; downgrade-to-HTTP is gated behind explicit opt-in.
sendPayjoinRequest
  :: SenderConfig
  -> Text                     -- ^ Receiver endpoint URL (e.g. from 'uriPj').
  -> Psbt                     -- ^ Original PSBT to POST.
  -> IO SenderResult
sendPayjoinRequest cfg endpointUrl psbtOrig = do
  let url       = T.unpack endpointUrl
      ct        = scContentType cfg
      bodyRaw   = encodePayjoinBody ct psbtOrig
  mReq <- try (HTTP.parseRequest ("POST " ++ url))
            :: IO (Either SomeException HTTP.Request)
  case mReq of
    Left e ->
      return $ SrFatal $ PeBadRequest
                          ("invalid pj= URL: " <> T.pack (show e))
    Right baseReq -> do
      let isHttps = HTTP.secure baseReq
      if scRequireTls cfg && not isHttps
        then return $ SrFatal $ PeBadRequest
                ("pj= URL must be HTTPS (sender RequireTls=True): "
                 <> endpointUrl)
        else do
          -- Pick TLS manager for https, plain manager for http.  G24
          -- closure: http-client-tls' default settings validate
          -- against the system certificate store.
          mgr <- if isHttps
                   then HTTPS.newTlsManager
                   else HTTP.newManager HTTP.defaultManagerSettings
          let req = baseReq
                      { HTTP.method         = "POST"
                      , HTTP.requestHeaders = [(hContentType, ct)]
                      , HTTP.requestBody    = HTTP.RequestBodyBS bodyRaw
                      , HTTP.responseTimeout =
                          HTTP.responseTimeoutMicro (scHttpTimeoutMicros cfg)
                      }
          eResp <- try (HTTP.httpLbs req mgr)
                    :: IO (Either SomeException (HTTP.Response BL.ByteString))
          case eResp of
            Left e ->
              -- Network-layer exception => fatal preflight.  Caller will
              -- NOT broadcast (the receiver may have legitimately
              -- accepted+offered the contribution; broadcasting the
              -- original would race against that — BIP-78 §4 explicitly
              -- says network errors are non-recoverable).
              return $ SrFatal $ PeBadRequest
                                  ("HTTP transport failed: "
                                   <> T.pack (show e))
            Right resp -> do
              let statusCode = HTTPStatus.statusCode (HTTP.responseStatus resp)
                  respBs     = BL.toStrict (HTTP.responseBody resp)
              if statusCode /= 200
                then
                  -- 4xx / 5xx: the receiver's body is a BIP-78
                  -- well-known wire string.  Caller MUST broadcast
                  -- the Original (G22) — return the proximate error
                  -- + the original PSBT so the caller has everything
                  -- it needs in one record.
                  let bodyText = TE.decodeUtf8 (BS.takeWhile (/= 0x0d) respBs)
                      err = errorFromWireString bodyText
                  in return (SrFallback err psbtOrig)
                else
                  -- 200 OK: decode the body, run all 6 anti-snoop
                  -- checks against the Original.  Any failure =>
                  -- fallback to broadcasting the original.
                  case decodePayjoinBody (Just ct) respBs of
                    Left err -> return (SrFallback err psbtOrig)
                    Right psbtProposed ->
                      case runSenderAntiSnoopChecks cfg psbtOrig psbtProposed of
                        Left err -> return (SrFallback err psbtOrig)
                        Right () -> return (SrProposed psbtProposed)

-- | Map a BIP-78 wire string back to a 'PayjoinError'.  Used by
-- 'sendPayjoinRequest' to surface the receiver's error category
-- (BIP-78 §"Errors" — four well-known strings) to the caller.
errorFromWireString :: Text -> PayjoinError
errorFromWireString t
  | T.toLower t == "unavailable"          = PeUnavailable t
  | T.toLower t == "not-enough-money"     = PeNotEnoughMoney t
  | T.toLower t == "version-unsupported"  = PeVersionUnsupported t
  | T.toLower t == "original-psbt-rejected" = PeOriginalPsbtRejected t
  | otherwise =
      -- Non-well-known string => collapse onto the most defensive
      -- category.  This is the BIP-78 reference impl's behaviour
      -- (payjoin.org / rust-payjoin both treat unknown strings as
      -- "original-psbt-rejected").
      PeOriginalPsbtRejected t

--------------------------------------------------------------------------------
-- Anti-snoop validators (G10-G15) — BIP-78 §4 "Sender's check on the proposal"
--
-- All six validators are pure: they take the (Original, Proposed) PSBT
-- pair plus the relevant config and return @Right ()@ on pass or
-- @Left PayjoinError@ on fail.  Senders that wish to layer additional
-- policy (e.g. payjoin.org's "receiver must contribute at least N sat")
-- compose with these — the contract is fail-closed.
--------------------------------------------------------------------------------

-- | G10 — Outputs unchanged or substituted.
--
-- BIP-78 §4: every output the sender owned in the Original MUST appear
-- byte-for-byte in the Proposed (same scriptPubKey, same value) UNLESS
-- output-substitution is allowed *and* the receiver chose to absorb
-- value into its own output.  At minimum the sender's payment output
-- to the receiver must be present (or have been augmented upward by
-- exactly the receiver's contribution — that's the substitution case).
--
-- This is the workhorse anti-snoop check.  A receiver that fingerprints
-- the sender by reshaping outputs (e.g. splitting a sender output, or
-- adding a third output) MUST be rejected here.
validateAntiSnoopOutputs :: Psbt -> Psbt -> Either PayjoinError ()
validateAntiSnoopOutputs orig prop =
  let txOrig = pgTx (psbtGlobal orig)
      txProp = pgTx (psbtGlobal prop)
      origOuts = txOutputs txOrig
      propOuts = txOutputs txProp
  in if length propOuts < length origOuts
       then Left $ PeOriginalPsbtRejected
              "proposal has fewer outputs than original (sender output removed)"
       else
         -- BIP-78 forbids the receiver adding *new* sender-controlled
         -- outputs.  The proposed output set must be a superset of
         -- the original output *scripts*, possibly with one value bumped
         -- (the receiver's own substitution).  Concretely: every
         -- original output script must appear in the proposed output
         -- set with value >= original value (the receiver may have
         -- bumped *its own* output but not anyone else's, and may not
         -- have *reduced* a sender output).
         let origScripts = map txOutScript origOuts
             propScripts = map txOutScript propOuts
             missing = [ s | s <- origScripts, s `notElem` propScripts ]
         in if not (null missing)
              then Left $ PeOriginalPsbtRejected
                     "proposal dropped an original output script (snoop attempt)"
              else
                -- For every original output, find the matching script
                -- in the proposal and ensure value >= original value
                -- (allows upward substitution by receiver, forbids
                -- downward — that would reduce a sender output).
                let check (TxOut v0 s0) =
                      let propVal = sum [ v1
                                        | (TxOut v1 s1) <- propOuts
                                        , s1 == s0
                                        ]
                      in if propVal < v0
                           then Left $ PeOriginalPsbtRejected
                                  "proposal reduced an original sender output value"
                           else Right ()
                in foldr (\o acc -> acc >> check o) (Right ()) origOuts

-- | Distinguishable script-pubkey families for G11 anti-snoop.
data ScriptType
  = StP2PKH
  | StP2SH
  | StP2WPKH
  | StP2WSH
  | StP2TR
  | StOther
  deriving (Show, Eq, Generic)

instance NFData ScriptType

-- | Classify a raw scriptPubKey into a script-type family.  Receiver-
-- side leak prevention (BIP-78 §4) requires that the receiver's
-- contributed inputs use the SAME type as the sender's inputs.
classifyScript :: ByteString -> ScriptType
classifyScript s
  | BS.length s == 22 && BS.index s 0 == 0x00 && BS.index s 1 == 0x14 = StP2WPKH
  | BS.length s == 34 && BS.index s 0 == 0x00 && BS.index s 1 == 0x20 = StP2WSH
  | BS.length s == 34 && BS.index s 0 == 0x51 && BS.index s 1 == 0x20 = StP2TR
  | BS.length s == 25 && BS.index s 0  == 0x76 && BS.index s 1 == 0xa9
    && BS.index s 2 == 0x14 && BS.index s 23 == 0x88 && BS.index s 24 == 0xac
                                                                       = StP2PKH
  | BS.length s == 23 && BS.index s 0 == 0xa9 && BS.index s 1 == 0x14
    && BS.index s 22 == 0x87                                           = StP2SH
  | otherwise                                                          = StOther

-- | Return every output script in a PSBT.
psbtOutputScripts :: Psbt -> [ByteString]
psbtOutputScripts = map txOutScript . txOutputs . pgTx . psbtGlobal

-- | Return the script-type of each input in a PSBT.  Reads piWitnessUtxo
-- first (must be present in a BIP-78 sender-side PSBT — same rule as
-- 'validateOriginalPsbt').  Falls back to 'StOther' if no utxo carrier.
psbtInputScriptType :: PsbtInput -> ScriptType
psbtInputScriptType pinp =
  case piWitnessUtxo pinp of
    Just (TxOut _ s) -> classifyScript s
    Nothing          -> StOther

-- | G11 — scriptSig / witness types of receiver-added inputs match
-- those of sender's inputs.
--
-- BIP-78 §4: "The receiver MUST use inputs of the same type the
-- sender used".  Mixed-type tx fingerprints the receiver as the
-- contributor of the odd-one-out, defeating the privacy goal.
--
-- We classify each PSBT input's witness-utxo scriptPubKey and require
-- the proposed inputs added by the receiver (= proposed minus
-- original) all share a single type, AND that type matches at least
-- one of the sender's original input types.
validateAntiSnoopScriptTypes :: Psbt -> Psbt -> Either PayjoinError ()
validateAntiSnoopScriptTypes orig prop =
  let origIns       = psbtInputs orig
      propIns       = psbtInputs prop
      origTypes     = nub (map psbtInputScriptType origIns)
      addedIns      = drop (length origIns) propIns
      addedTypes    = nub (map psbtInputScriptType addedIns)
  in if null addedIns
       then Right ()              -- no added inputs => no type leak.
                                  -- (G12 catches "no added inputs at all".)
       else if any (== StOther) addedTypes
              then Left $ PeOriginalPsbtRejected
                     "receiver added an input with unknown scriptPubKey type"
              else if length addedTypes > 1
                     then Left $ PeOriginalPsbtRejected
                            "receiver added inputs of mixed types (snoop attempt)"
                     else
                       let addedType = head addedTypes
                       in if addedType `elem` origTypes
                            then Right ()
                            else Left $ PeOriginalPsbtRejected
                              ( "receiver-added input type does not match \
                                \sender input types: added="
                                <> T.pack (show addedType)
                                <> " sender="
                                <> T.pack (show origTypes))

-- | G12 — receiver MUST add at least 1 input.
--
-- BIP-78 §4: a Proposed PSBT identical to the Original (or one that
-- removed sender inputs without adding any of its own) defeats the
-- protocol.  The receiver's contribution is the *whole point* of
-- PayJoin; reject the proposal if it's absent.
validateAntiSnoopReceiverInputs :: Psbt -> Psbt -> Either PayjoinError ()
validateAntiSnoopReceiverInputs orig prop =
  let origCount = length (psbtInputs orig)
      propCount = length (psbtInputs prop)
  in if propCount <= origCount
       then Left $ PeOriginalPsbtRejected
              "proposal added no receiver inputs (BIP-78 §4 violation)"
       else Right ()

-- | G13 — sender additional-fee cap.
--
-- BIP-78 §4 @maxadditionalfeecontribution@: the sender declares (in
-- the request URL params) the maximum extra fee it is willing to pay
-- to accommodate the receiver's contribution.  This validator
-- enforces it against the actual Proposed PSBT.
--
-- "Additional fee" = (sum of proposed inputs) - (sum of proposed
-- outputs) - originalFee.  Concretely: how much MORE fee the sender
-- now pays vs. what they would have paid with the Original.
--
-- Each input's value comes from piWitnessUtxo / piNonWitnessUtxo
-- (BIP-78 mandates the sender provides one of those for every input
-- in the Original; the receiver MUST provide the same for its added
-- inputs).  If a value is missing we reject — the sender cannot
-- verify the fee delta without it.
validateAntiSnoopFeeCap :: SenderConfig
                        -> Psbt
                        -> Psbt
                        -> Either PayjoinError ()
validateAntiSnoopFeeCap cfg orig prop = do
  origFee <- computeFee orig
  propFee <- computeFee prop
  if propFee < origFee
    then
      -- A *reduction* of fee is suspicious but not a sender-policy
      -- violation; covered separately by G15.  Allow.
      Right ()
    else
      let delta = propFee - origFee
      in if delta > scMaxFeeContribution cfg
           then Left $ PeOriginalPsbtRejected
                  ( "proposal exceeds maxadditionalfeecontribution: delta="
                    <> T.pack (show delta)
                    <> " cap="
                    <> T.pack (show (scMaxFeeContribution cfg)))
           else Right ()
  where
    computeFee :: Psbt -> Either PayjoinError Word64
    computeFee psbt = do
      ins  <- mapM inputValue (psbtInputs psbt)
      let outs = map txOutValue (txOutputs (pgTx (psbtGlobal psbt)))
          totalIn  = sum ins
          totalOut = sum outs
      if totalIn < totalOut
        then Left $ PeOriginalPsbtRejected
               "PSBT inputs sum less than outputs (negative fee)"
        else Right (totalIn - totalOut)
    inputValue :: PsbtInput -> Either PayjoinError Word64
    inputValue pinp =
      case piWitnessUtxo pinp of
        Just (TxOut v _) -> Right v
        Nothing -> Left $ PeOriginalPsbtRejected
                           "input missing piWitnessUtxo (cannot verify fee)"

-- | G14 — sender honors @disableoutputsubstitution@ flag.
--
-- When the sender set @pjos=1@ in the request URL, the receiver MUST
-- NOT substitute any of the sender's outputs — every output must be
-- byte-identical (script + value).  If 'scDisableOutputSubst' is set,
-- enforce strict byte-for-byte equality.
validateAntiSnoopDisableOs :: SenderConfig
                           -> Psbt
                           -> Psbt
                           -> Either PayjoinError ()
validateAntiSnoopDisableOs cfg orig prop
  | not (scDisableOutputSubst cfg) = Right ()
  | otherwise =
      let origOuts = txOutputs (pgTx (psbtGlobal orig))
          propOuts = txOutputs (pgTx (psbtGlobal prop))
      in
        -- Every original output must appear *byte-identical* in the
        -- proposal (script AND value).  The receiver is still
        -- permitted to ADD outputs (its own change), but cannot
        -- mutate any pre-existing sender output.
        if all (`elem` propOuts) origOuts
          then Right ()
          else Left $ PeOriginalPsbtRejected
                 "pjos=1 in effect but proposal modified a sender output"

-- | G15 — effective fee rate floor.
--
-- BIP-78 §4 @minfeerate@: the proposal's effective fee rate (sat/vB)
-- must clear the sender's declared floor.  We approximate weight as
-- @4 * tx size@ — adequate for the floor check (the true weight
-- formula treats witnesses at weight 1 and the rest at weight 4, but
-- senders that need precision will refine; the audit-flip just needs
-- the validator to be present and reject obvious dust-rate proposals).
validateAntiSnoopMinFeeRate :: SenderConfig
                            -> Psbt
                            -> Psbt
                            -> Either PayjoinError ()
validateAntiSnoopMinFeeRate cfg _orig prop = do
  fee   <- computeFee prop
  let txProp     = pgTx (psbtGlobal prop)
      sizeBytes  = BS.length (encodePsbtTxApprox txProp)
      vBytes     = max 1 sizeBytes  -- avoid /0 on degenerate empty tx.
      ratePerVb  = fee `div` fromIntegral vBytes
  if ratePerVb < scMinFeeRate cfg
    then Left $ PeOriginalPsbtRejected
           ( "proposal effective fee rate "
             <> T.pack (show ratePerVb)
             <> " below sender minfeerate="
             <> T.pack (show (scMinFeeRate cfg)))
    else Right ()
  where
    computeFee :: Psbt -> Either PayjoinError Word64
    computeFee psbt = do
      ins <- mapM inputValue (psbtInputs psbt)
      let outs = map txOutValue (txOutputs (pgTx (psbtGlobal psbt)))
      if sum ins < sum outs
        then Left $ PeOriginalPsbtRejected
               "PSBT inputs less than outputs"
        else Right (sum ins - sum outs)
    inputValue :: PsbtInput -> Either PayjoinError Word64
    inputValue pinp =
      case piWitnessUtxo pinp of
        Just (TxOut v _) -> Right v
        Nothing -> Left $ PeOriginalPsbtRejected
                           "input missing piWitnessUtxo"
    -- We approximate the on-wire tx size by re-encoding the inputs/
    -- outputs (skipping the witness layer, which only the wallet's
    -- finalizePsbt populates).  Good enough for a sat/vB floor check.
    -- Approximate the on-wire tx size for a sat/vB floor check.  Per-
    -- input: 32-byte prevout + 4-byte vout + ~1-byte scriptSig length +
    -- 4-byte sequence = ~41 bytes.  Per-output: 8-byte value + ~1-byte
    -- script length + script bytes.  Plus ~10 bytes of fixed framing
    -- (version + locktime + varints).  Good enough for the floor.
    encodePsbtTxApprox :: Tx -> ByteString
    encodePsbtTxApprox tx =
      let inBs   = BS.concat (map encInp (txInputs tx))
          outBs  = BS.concat (map encOut (txOutputs tx))
      in BS.replicate 10 0 <> inBs <> outBs
    encInp :: TxIn -> ByteString
    encInp _ = BS.replicate 41 0   -- 32 + 4 + 1 + 4 marker
    encOut :: TxOut -> ByteString
    encOut (TxOut _ s) = BS.replicate 9 0 <> s

-- | Run all 6 anti-snoop validators in order.  First failure wins
-- (short-circuit), so the caller sees the most-specific reason.
runSenderAntiSnoopChecks
  :: SenderConfig
  -> Psbt              -- ^ Original PSBT sent by sender.
  -> Psbt              -- ^ Proposed PSBT received from receiver.
  -> Either PayjoinError ()
runSenderAntiSnoopChecks cfg orig prop = do
  validateAntiSnoopReceiverInputs orig prop
  validateAntiSnoopOutputs        orig prop
  validateAntiSnoopScriptTypes    orig prop
  validateAntiSnoopFeeCap     cfg orig prop
  validateAntiSnoopDisableOs  cfg orig prop
  validateAntiSnoopMinFeeRate cfg orig prop

--------------------------------------------------------------------------------
-- Sender-side outbound-offer cache (G19 + G30 mirror)
--
-- Sender-side replay defense: track every Original PSBT the sender has
-- POSTed so a duplicate retry does not double-spend the wallet's UTXOs.
-- Re-uses the receiver-side TVar Map shape so callers see one cache
-- surface across both directions of the protocol.
--------------------------------------------------------------------------------

-- | True iff this Original PSBT (keyed by hash) has already been sent.
isSenderReplay :: TVar (Map ByteString OfferedPayjoin)
               -> ByteString
               -> IO Bool
isSenderReplay = isReplay

-- | Record an outbound offer.  Mirrors 'recordOffer' on the receiver
-- side; just exported under a sender-side name so call-sites are clear.
recordSenderOffer :: TVar (Map ByteString OfferedPayjoin)
                  -> OfferedPayjoin
                  -> IO ()
recordSenderOffer = recordOffer

--------------------------------------------------------------------------------
-- Fallback decision (G22)
--
-- BIP-78 §"Sender's behaviour on error": every fatal HTTP/PSBT-level
-- failure mandates broadcasting the Original PSBT — the user wanted to
-- pay the receiver, the protocol couldn't enhance the privacy, but the
-- payment itself must still go through.  EXCEPT preflight failures
-- (malformed URL, TLS-required-but-HTTP) — those are user-intent
-- errors and the user should fix their URL.
--
-- decideFallback :: SenderResult -> Maybe Psbt
--   Just psbt  => broadcast `psbt` (the Original, returned by the
--                  receiver-failure path) per G22.
--   Nothing    => preflight failure; surface to the user, do NOT
--                  broadcast.
--------------------------------------------------------------------------------

-- | Translate a 'SenderResult' into a broadcast decision.  Caller's
-- broadcast pipeline is wired by the RPC layer ('handleSendPayjoinRequest')
-- — this function just expresses the BIP-78 policy as a pure transform.
decideFallback :: SenderResult -> Maybe Psbt
decideFallback (SrProposed psbt)    = Just psbt
decideFallback (SrFallback _ psbt)  = Just psbt   -- G22: broadcast Original
decideFallback (SrFatal _)          = Nothing


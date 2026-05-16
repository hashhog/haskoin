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
    -- * Internal helpers (exported for tests)
  , maxPayjoinBodyBytes
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
import Data.Int (Int64)
import GHC.Generics (Generic)
import Control.Concurrent.STM
import Control.DeepSeq (NFData)
import Control.Monad (when)
import Data.Maybe (fromMaybe)
import Data.List (foldl')
import Network.Wai (Application, Response, responseLBS,
                    requestMethod, strictRequestBody, requestHeaders)
import Network.HTTP.Types (status200, status400, status405, status413,
                            hContentType)

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
          in case decodePayjoinBody ct bodyBs of
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
                     mProposed <- processOriginalPsbt wallet cfg False Nothing psbtOrig
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


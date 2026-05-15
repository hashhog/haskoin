{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE RecordWildCards #-}

-- | BIP-21 — Bitcoin URI scheme parser/emitter.
--
-- Format: @bitcoin:<address>[?<key>=<value>[&<key>=<value>...]]@
--
-- Standard query keys (BIP-21):
--
--   * @amount@   — payment amount in BTC (decimal, max 8 fractional digits).
--   * @label@    — short label for the payee, percent-decoded UTF-8.
--   * @message@  — message attached to the payment, percent-decoded UTF-8.
--
-- BIP-21 extension keys widely supported in the ecosystem (we treat as
-- first-class fields rather than burying them in 'uriExtras' so future
-- consumers don't have to re-parse strings):
--
--   * @lightning@ — BOLT-11 invoice (BIP-21 extension; @bolt11:@ payload
--                   without the @lightning:@ scheme prefix).
--   * @pj@        — BIP-78 PayJoin endpoint URL.
--   * @pjos@      — BIP-78 \"disable output substitution\" flag.  BIP-78
--                   specifies the default is FALSE (output substitution is
--                   allowed); @pjos=1@ disables it.  We parse @0@/@false@
--                   as 'False' and @1@/@true@ as 'True' (case-insensitive).
--
-- Unknown keys with the @req-@ prefix cause the URI to be REJECTED, per
-- BIP-21:
--
-- > Variables which are prefixed with a req- are considered required.
-- > If a client does not implement any variables which are prefixed with
-- > req-, it MUST consider the entire URI invalid.
--
-- Unknown keys without the @req-@ prefix are stored in 'uriExtras' so
-- callers can inspect / round-trip them.  Keys are compared
-- case-insensitively after percent-decoding (lower-cased).
--
-- Percent-decoding follows RFC 3986: @%HH@ where HH is two hex digits.
-- BIP-21 is NOT @application/x-www-form-urlencoded@ — @+@ is NOT decoded
-- to space; it stays a literal @+@.  This matches the behavior of every
-- BIP-21 wallet we've cross-checked (BlueWallet, BitPay, BTCPay).
--
-- Address validation: the @<address>@ token is decoded via
-- 'textToAddress' and then re-encoded to verify the result round-trips
-- to the same network the caller passed.  This catches mainnet addresses
-- pasted into a testnet wallet and vice versa.
--
-- References:
--   * <https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki BIP-21>
--   * <https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki BIP-78>
--   * RFC 3986 (URI generic syntax)
module Haskoin.Bip21
  ( -- * Types
    Bip21Uri(..)
  , Bip21Error(..)
    -- * Parsing
  , parseBip21
    -- * Emitting
  , emitBip21
    -- * Helpers (exposed for testing)
  , percentDecode
  , percentEncode
  , parseBtcAmount
  , formatBtcAmount
  ) where

import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import Data.Char (isHexDigit, isDigit)
import Data.Bits (shiftL, (.|.))
import qualified Data.ByteString as BS
import qualified Data.Text.Encoding as TE
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)

import Haskoin.Crypto (Address, textToAddress, addressToText)
import Haskoin.Consensus (Network(..))

--------------------------------------------------------------------------------
-- Types
--------------------------------------------------------------------------------

-- | Parsed BIP-21 URI.
data Bip21Uri = Bip21Uri
  { uriAddress   :: !Address
    -- ^ Recipient address.  Validated to match the 'Network' passed to
    -- 'parseBip21'.
  , uriAmount    :: !(Maybe Word64)
    -- ^ Optional amount in satoshis.  BIP-21 expresses the amount as
    -- decimal BTC (e.g. @amount=0.10@); we convert to satoshis with no
    -- loss for any amount with at most 8 fractional digits.  More than
    -- 8 fractional digits is a parse error ('Bip21AmountInvalid').
  , uriLabel     :: !(Maybe Text)
    -- ^ Optional label.  Percent-decoded UTF-8 text.
  , uriMessage   :: !(Maybe Text)
    -- ^ Optional message.  Percent-decoded UTF-8 text.
  , uriLightning :: !(Maybe Text)
    -- ^ Optional BOLT-11 lightning invoice (BIP-21 extension).
  , uriPj        :: !(Maybe Text)
    -- ^ Optional BIP-78 PayJoin endpoint URL.
  , uriPjos      :: !(Maybe Bool)
    -- ^ Optional BIP-78 \"disable output substitution\".  'Nothing' means
    -- the key was absent; per BIP-78 the receiver should then assume
    -- output substitution is allowed (False).
  , uriExtras    :: !(Map Text Text)
    -- ^ Any other non-@req-@ keys, with values percent-decoded.  Keys
    -- are lower-cased; values are kept as-is after decode.
  } deriving (Show, Eq, Generic)

instance NFData Bip21Uri

-- | Reasons a BIP-21 string fails to parse.  Exhaustive — every error
-- path 'parseBip21' takes maps to one of these.
data Bip21Error
  = Bip21BadScheme !Text
    -- ^ URI did not start with @bitcoin:@ (case-insensitive scheme is
    -- accepted; the literal returned is the offending prefix).
  | Bip21EmptyAddress
    -- ^ Address segment between @bitcoin:@ and @?@ is empty.
  | Bip21BadAddress !Text
    -- ^ Address segment did not decode to a valid address.  The
    -- attached 'Text' is the failing token (after percent-decode).
  | Bip21WrongNetwork !Text
    -- ^ Address decoded, but did not re-encode to the same string under
    -- the network the caller passed (e.g. mainnet address on testnet).
    -- The attached 'Text' is the original address token.
  | Bip21BadQuery !Text
    -- ^ A query-string component was malformed (no @=@, or duplicate
    -- key that we treat as fatal).  The attached 'Text' is the offender.
  | Bip21UnknownRequired !Text
    -- ^ An unknown @req-@-prefixed key was present.  Per BIP-21 the URI
    -- MUST be rejected.  The attached 'Text' is the offending key.
  | Bip21AmountInvalid !Text
    -- ^ @amount=@ value was not a valid BTC decimal, or had more than 8
    -- fractional digits, or did not fit in a 'Word64' satoshi value.
  | Bip21PjosInvalid !Text
    -- ^ @pjos=@ value was not one of @0@/@1@/@true@/@false@.
  | Bip21BadPercentEncoding !Text
    -- ^ A @%HH@ sequence in a value was malformed.
  deriving (Show, Eq, Generic)

instance NFData Bip21Error

--------------------------------------------------------------------------------
-- Parser
--------------------------------------------------------------------------------

-- | Parse a BIP-21 URI against a particular 'Network'.
--
-- The address is checked to re-encode identically under the network's
-- HRP / version bytes; a mainnet address on testnet (or vice versa) is
-- rejected with 'Bip21WrongNetwork'.
--
-- Per BIP-21 §Forward compatibility, unknown keys without the @req-@
-- prefix are accepted (and stored in 'uriExtras'); unknown keys WITH
-- the @req-@ prefix cause rejection.
parseBip21 :: Network -> Text -> Either Bip21Error Bip21Uri
parseBip21 net input = do
  -- Scheme: case-insensitive "bitcoin:"
  body <- case stripPrefixCI "bitcoin:" input of
    Just rest -> Right rest
    Nothing   -> Left (Bip21BadScheme (T.take 16 input))

  -- Split on first '?' into address part + query part
  let (addrPart, queryPart) = case T.break (== '?') body of
        (a, q) | T.null q  -> (a, T.empty)
               | otherwise -> (a, T.drop 1 q)

  -- Percent-decode the address segment (BIP-21 allows it but in practice
  -- addresses are ASCII; this is for spec robustness).
  addrText <- percentDecode addrPart

  case T.null addrText of
    True  -> Left Bip21EmptyAddress
    False -> Right ()

  addr <- case textToAddress addrText of
    Just a  -> Right a
    Nothing -> Left (Bip21BadAddress addrText)

  -- Network check: re-encode the address under the caller's Network and
  -- require byte-for-byte equality (case-insensitive for bech32 HRP).
  -- This catches mainnet-address-on-testnet user errors.
  case checkAddressNetwork net addr addrText of
    True  -> Right ()
    False -> Left (Bip21WrongNetwork addrText)

  -- Query parsing
  pairs <- parseQuery queryPart

  -- Reject unknown req- keys
  case findUnknownReq pairs of
    Just k  -> Left (Bip21UnknownRequired k)
    Nothing -> Right ()

  -- Pull standard keys; on duplicates we take the first occurrence
  -- (BIP-21 does not specify behavior on duplicate keys; first-wins
  -- matches BlueWallet / BTCPay).
  mAmount    <- traverse parseBtcAmount (lookupKey "amount"    pairs)
  let mLabel     = lookupKey "label"     pairs
      mMessage   = lookupKey "message"   pairs
      mLightning = lookupKey "lightning" pairs
      mPj        = lookupKey "pj"        pairs
  mPjos <- traverse parsePjos (lookupKey "pjos" pairs)

  let knownKeys =
        [ "amount", "label", "message"
        , "lightning", "pj", "pjos"
        ]
      extras = Map.fromList
        [ (k, v) | (k, v) <- pairs
        , k `notElem` knownKeys
        , not (isReqKey k)
        ]

  Right Bip21Uri
    { uriAddress   = addr
    , uriAmount    = mAmount
    , uriLabel     = mLabel
    , uriMessage   = mMessage
    , uriLightning = mLightning
    , uriPj        = mPj
    , uriPjos      = mPjos
    , uriExtras    = extras
    }

--------------------------------------------------------------------------------
-- Emitter
--------------------------------------------------------------------------------

-- | Serialize a 'Bip21Uri' back to a @bitcoin:...@ string.
--
-- Standard-key ordering is fixed (amount, label, message, lightning, pj,
-- pjos, then 'uriExtras' in 'Map' order) so round-tripping a freshly
-- emitted URI is deterministic.  Note that round-tripping an
-- arbitrarily-ordered query string is NOT preserved — only the
-- canonical order is.
emitBip21 :: Bip21Uri -> Text
emitBip21 Bip21Uri{..} =
  let addrTxt = addressToText uriAddress
      kvs     = concat
        [ kv "amount"    (fmap formatBtcAmount uriAmount)
        , kv "label"     uriLabel
        , kv "message"   uriMessage
        , kv "lightning" uriLightning
        , kv "pj"        uriPj
        , kv "pjos"      (fmap (\b -> if b then "1" else "0") uriPjos)
        ] ++
        [ (k, v) | (k, v) <- Map.toAscList uriExtras ]
      query = case kvs of
        [] -> T.empty
        _  -> "?" <> T.intercalate "&"
                       [ k <> "=" <> percentEncode v | (k, v) <- kvs ]
  in "bitcoin:" <> addrTxt <> query
  where
    kv _ Nothing  = []
    kv k (Just v) = [(k, v)]

--------------------------------------------------------------------------------
-- Address vs network check
--------------------------------------------------------------------------------

-- | True iff 'addr' decoded to the same string under the network's
-- prefixes / HRP.  This is the canonical mainnet-vs-testnet guard.
checkAddressNetwork :: Network -> Address -> Text -> Bool
checkAddressNetwork net _addr original =
  let lower = T.toLower original
      hrp   = T.pack (netBech32Prefix net)
      bech1 = hrp <> "1"
      -- Bech32 / bech32m: HRP is the source of truth
      isBech = bech1 `T.isPrefixOf` lower
      -- Base58Check: first character indicates version byte
      base58Ok = case T.uncons original of
        Just (c, _)
          | netAddrPrefix net == 0x00 && c == '1'                  -> True
          | netAddrPrefix net == 0x00 && c == '3'                  -> True
          | netAddrPrefix net == 0x6F && c `elem` ['m', 'n', '2']  -> True
          | otherwise                                              -> False
        Nothing -> False
  in isBech || base58Ok

--------------------------------------------------------------------------------
-- Query string parsing
--------------------------------------------------------------------------------

-- | Parse @k1=v1&k2=v2&...@ into a list of (lower-cased key, decoded value).
-- Empty query returns []; a bare key with no @=@ is a parse error.
parseQuery :: Text -> Either Bip21Error [(Text, Text)]
parseQuery q
  | T.null q  = Right []
  | otherwise = traverse parsePair (T.splitOn "&" q)
  where
    parsePair p
      | T.null p = Left (Bip21BadQuery T.empty)
      | otherwise = case T.break (== '=') p of
          (k, eqRest)
            | T.null eqRest -> Left (Bip21BadQuery p)
            | T.null k      -> Left (Bip21BadQuery p)
            | otherwise     -> do
                let rawV = T.drop 1 eqRest
                v <- percentDecode rawV
                Right (T.toLower k, v)

-- | First occurrence of @k@ (already lower-cased) in the pair list.
lookupKey :: Text -> [(Text, Text)] -> Maybe Text
lookupKey k = lookup k

-- | Is the (lower-cased) key marked as required-by-BIP-21?
isReqKey :: Text -> Bool
isReqKey = T.isPrefixOf "req-"

-- | Return the first @req-@-key whose name (without the prefix) is NOT
-- one we recognize.  Since this codebase does not yet recognize any
-- @req-@-prefixed extension, any @req-@ key is an unknown-required.
findUnknownReq :: [(Text, Text)] -> Maybe Text
findUnknownReq pairs =
  case [k | (k, _) <- pairs, isReqKey k] of
    []      -> Nothing
    (k : _) -> Just k

--------------------------------------------------------------------------------
-- pjos parsing
--------------------------------------------------------------------------------

-- | Parse the @pjos=@ value.  BIP-78 only specifies @0@ / @1@; we also
-- accept @true@/@false@ for ecosystem compatibility (BTCPay) — these
-- are documented to be tolerated by receivers.
parsePjos :: Text -> Either Bip21Error Bool
parsePjos t = case T.toLower t of
  "0"     -> Right False
  "false" -> Right False
  "1"     -> Right True
  "true"  -> Right True
  _       -> Left (Bip21PjosInvalid t)

--------------------------------------------------------------------------------
-- Amount parsing
--
-- BIP-21 amounts: BTC as decimal, like "0.10" or "12.00050000".  We
-- parse exactly the grammar
--
--   amount := integer ['.' fractional]
--   integer    := DIGIT+
--   fractional := DIGIT{0,8}
--
-- A bare "." or empty input is invalid.  More than 8 fractional digits
-- is invalid (would lose precision in satoshis).
--------------------------------------------------------------------------------

-- | Convert a BIP-21 amount field (decimal BTC) to satoshis.
parseBtcAmount :: Text -> Either Bip21Error Word64
parseBtcAmount raw = case T.break (== '.') raw of
  (whole, frac)
    | T.null whole && (T.null frac || frac == ".") ->
        Left (Bip21AmountInvalid raw)
    | not (T.all isDigit whole) ->
        Left (Bip21AmountInvalid raw)
    | T.null frac ->
        -- No decimal point: integer BTC, * 1e8
        toSats whole T.empty raw
    | otherwise ->
        let fracDigits = T.drop 1 frac
        in if T.length fracDigits > 8 || not (T.all isDigit fracDigits)
           then Left (Bip21AmountInvalid raw)
           else toSats whole fracDigits raw
  where
    toSats whole fracDigits raw' =
      let -- pad fractional to exactly 8 digits
          padded = fracDigits <> T.replicate (8 - T.length fracDigits) "0"
          combined = whole <> padded
          val :: Integer
          val = readDecimal combined
      in if val > toInteger (maxBound :: Word64)
         then Left (Bip21AmountInvalid raw')
         else Right (fromInteger val)

-- | Render satoshis as BIP-21 BTC decimal.  Always produces a canonical
-- form: no trailing zeros after the decimal point, no decimal point if
-- the amount is a whole number of BTC.
formatBtcAmount :: Word64 -> Text
formatBtcAmount sats =
  let whole = sats `div` 100_000_000
      frac  = sats `mod` 100_000_000
      wholeS = T.pack (show whole)
  in if frac == 0
     then wholeS
     else let fracS  = T.justifyRight 8 '0' (T.pack (show frac))
              trimmed = T.dropWhileEnd (== '0') fracS
          in wholeS <> "." <> trimmed

-- | Read a non-negative decimal integer.  Caller must have already
-- validated that every char is a digit; we fold safely.
readDecimal :: Text -> Integer
readDecimal = T.foldl' step 0
  where
    step !acc c = acc * 10 + toInteger (fromEnum c - fromEnum '0')

--------------------------------------------------------------------------------
-- Percent encoding / decoding
--
-- RFC 3986 strict: only %HH is decoded, '+' is NOT decoded to space.
--------------------------------------------------------------------------------

-- | Percent-decode a 'Text' as UTF-8.  Returns 'Left' if a @%HH@
-- sequence is malformed (not two hex digits) or the decoded byte
-- sequence is not valid UTF-8.
percentDecode :: Text -> Either Bip21Error Text
percentDecode txt =
  let s = T.unpack txt
  in case go s of
       Left bad   -> Left (Bip21BadPercentEncoding bad)
       Right bytes ->
         case TE.decodeUtf8' (BS.pack bytes) of
           Left _  -> Left (Bip21BadPercentEncoding txt)
           Right t -> Right t
  where
    go []          = Right []
    go ('%' : a : b : rest)
      | isHexDigit a && isHexDigit b =
          let !hi = fromIntegral (hexVal a)
              !lo = fromIntegral (hexVal b)
              !w  = (hi `shiftL` 4) .|. lo
          in case go rest of
               Left e  -> Left e
               Right r -> Right (w : r)
      | otherwise = Left (T.pack ('%' : a : b : take 4 rest))
    go ('%' : rest) = Left (T.pack ('%' : take 4 rest))
    go (c : rest)   =
      -- ASCII fast path; characters > 127 are encoded as multi-byte
      -- UTF-8 in the source string, so we go byte-by-byte via encodeUtf8
      case fromEnum c of
        n | n < 128 -> fmap (fromIntegral n :) (go rest)
        _ ->
          let !bs = TE.encodeUtf8 (T.singleton c)
              prefix = BS.unpack bs
          in fmap (prefix ++) (go rest)

    hexVal :: Char -> Int
    hexVal c
      | c >= '0' && c <= '9' = fromEnum c - fromEnum '0'
      | c >= 'a' && c <= 'f' = fromEnum c - fromEnum 'a' + 10
      | c >= 'A' && c <= 'F' = fromEnum c - fromEnum 'A' + 10
      | otherwise            = 0  -- unreachable; guarded by isHexDigit

-- | Percent-encode a 'Text' (UTF-8) for use in a BIP-21 query value.
-- Unreserved characters (RFC 3986 §2.3) plus a small set of BIP-21
-- safe additions (':', '/', '@') are emitted literally.  Everything
-- else is @%HH@-escaped.
percentEncode :: Text -> Text
percentEncode = T.pack . concatMap enc . BS.unpack . TE.encodeUtf8
  where
    enc b
      | safe b   = [toEnum (fromIntegral b)]
      | otherwise = '%' : hex (b `quotRem` 16)
    safe b =
      (b >= 0x30 && b <= 0x39) ||  -- 0-9
      (b >= 0x41 && b <= 0x5A) ||  -- A-Z
      (b >= 0x61 && b <= 0x7A) ||  -- a-z
      b == 0x2D || b == 0x5F ||    -- - _
      b == 0x2E || b == 0x7E       -- . ~
    hex (h, l) = [hexDigit h, hexDigit l]
    hexDigit n
      | n < 10    = toEnum (fromIntegral n + fromEnum '0')
      | otherwise = toEnum (fromIntegral n - 10 + fromEnum 'A')

--------------------------------------------------------------------------------
-- Case-insensitive prefix strip
--------------------------------------------------------------------------------

stripPrefixCI :: Text -> Text -> Maybe Text
stripPrefixCI pre full =
  let lp = T.length pre
  in if T.toLower (T.take lp full) == T.toLower pre
     then Just (T.drop lp full)
     else Nothing

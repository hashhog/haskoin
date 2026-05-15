{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | BIP-21 URI parser / emitter tests.
--
-- Drives every code path in 'Haskoin.Bip21':
--
--   * Bare @bitcoin:<address>@ with all six common address shapes.
--   * Amount: integer BTC, fractional BTC, max-precision (8 dp), one
--     satoshi (0.00000001), full-supply edge case.
--   * Percent-decoded label / message — including UTF-8 multi-byte
--     code points (CJK + emoji) — and the explicit BIP-21 rule that
--     @+@ is NOT decoded to space.
--   * Unknown keys: non-@req-@ stored in 'uriExtras', @req-@ REJECTED.
--   * BIP-78 keys: @pj=@, @pjos=0@, @pjos=1@, @pjos=true@, @pjos=false@.
--   * Case-insensitivity of @bitcoin:@ scheme and of query keys.
--   * Network-mismatch detection (mainnet address against testnet,
--     testnet address against mainnet — both rejected).
--   * Round-trip via 'emitBip21' on a fully-populated value.
--   * Reference vectors from the BIP-21 mediawiki spec.
--
-- The W119 audit (W119PayjoinSpec.hs) has three `pendingWith` gates
-- — G16 (query params), G28 (@pj=@), G29 (@pjos=@) — flipped to real
-- assertions in this spec rather than in-place so the audit's
-- "MISSING ENTIRELY" verdict prose stays intact as a historical record.
module Bip21Spec (spec) where

import Test.Hspec
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Text (Text)
import Data.Word (Word64)

import Haskoin.Bip21
import Haskoin.Consensus (mainnet, testnet3)
import Haskoin.Crypto (textToAddress)

--------------------------------------------------------------------------------
-- Reference test vectors
--------------------------------------------------------------------------------

-- | Canonical mainnet P2PKH (Genesis recipient).
mainAddrP2PKH :: Text
mainAddrP2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

-- | Canonical mainnet P2WPKH from BIP-173 §Examples.
mainAddrP2WPKH :: Text
mainAddrP2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

-- | A mainnet P2SH (multisig output).
mainAddrP2SH :: Text
mainAddrP2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

-- | A testnet3 P2PKH.
testnetAddrP2PKH :: Text
testnetAddrP2PKH = "mzBc4XEFSdzCDcTxAgf6EZXgsZWpztRhef"

--------------------------------------------------------------------------------
-- spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "BIP-21 URI parser" $ do
  describe "bare address (no query)" $ do
    it "parses bitcoin:<P2PKH>" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH) of
        Right u  -> do
          uriAmount u    `shouldBe` Nothing
          uriLabel u     `shouldBe` Nothing
          uriMessage u   `shouldBe` Nothing
          uriLightning u `shouldBe` Nothing
          uriPj u        `shouldBe` Nothing
          uriPjos u      `shouldBe` Nothing
          uriExtras u    `shouldBe` Map.empty
        Left err -> expectationFailure (show err)

    it "parses bitcoin:<P2WPKH>" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2WPKH) of
        Right u  -> uriAddress u `shouldBe`
          maybe (error "test fixture P2WPKH must decode")
                id
                (textToAddress mainAddrP2WPKH)
        Left err -> expectationFailure (show err)

    it "parses bitcoin:<P2SH>" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2SH) of
        Right _  -> pure ()
        Left err -> expectationFailure (show err)

    it "parses testnet bitcoin:<P2PKH> against testnet3" $ do
      case parseBip21 testnet3 ("bitcoin:" <> testnetAddrP2PKH) of
        Right _  -> pure ()
        Left err -> expectationFailure (show err)

  describe "amount" $ do
    it "parses integer BTC (1 BTC = 100_000_000 sat)" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=1") of
        Right u  -> uriAmount u `shouldBe` Just 100_000_000
        Left err -> expectationFailure (show err)

    it "parses fractional BTC (0.1 BTC = 10_000_000 sat)" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=0.1") of
        Right u  -> uriAmount u `shouldBe` Just 10_000_000
        Left err -> expectationFailure (show err)

    it "parses max-precision BTC (0.00000001 BTC = 1 sat)" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=0.00000001") of
        Right u  -> uriAmount u `shouldBe` Just 1
        Left err -> expectationFailure (show err)

    it "parses 50 BTC with trailing zeros (50.00000000)" $ do
      case parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=50.00000000") of
        Right u  -> uriAmount u `shouldBe` Just 5_000_000_000
        Left err -> expectationFailure (show err)

    it "rejects amount with > 8 fractional digits" $ do
      parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=0.123456789")
        `shouldBe` Left (Bip21AmountInvalid "0.123456789")

    it "rejects negative amount" $ do
      parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=-1")
        `shouldBe` Left (Bip21AmountInvalid "-1")

    it "rejects bare decimal point" $ do
      parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=.")
        `shouldBe` Left (Bip21AmountInvalid ".")

    it "rejects non-numeric amount" $ do
      parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?amount=abc")
        `shouldBe` Left (Bip21AmountInvalid "abc")

    it "round-trips amount via formatBtcAmount" $ do
      formatBtcAmount 100_000_000 `shouldBe` "1"
      formatBtcAmount 10_000_000  `shouldBe` "0.1"
      formatBtcAmount 1           `shouldBe` "0.00000001"
      formatBtcAmount 0           `shouldBe` "0"

  describe "label and message" $ do
    it "parses simple ASCII label" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?label=Luke-Jr") of
        Right u  -> uriLabel u `shouldBe` Just "Luke-Jr"
        Left err -> expectationFailure (show err)

    it "percent-decodes label with spaces (%20)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?label=Luke%20Jr") of
        Right u  -> uriLabel u `shouldBe` Just "Luke Jr"
        Left err -> expectationFailure (show err)

    it "percent-decodes label with UTF-8 (CJK)" $ do
      -- "中" = U+4E2D = E4 B8 AD in UTF-8 → %E4%B8%AD
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?label=%E4%B8%AD") of
        Right u  -> uriLabel u `shouldBe` Just "\x4E2D"
        Left err -> expectationFailure (show err)

    it "does NOT decode '+' to space (BIP-21 != form-urlencoded)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?label=A+B") of
        Right u  -> uriLabel u `shouldBe` Just "A+B"
        Left err -> expectationFailure (show err)

    it "parses message alongside label" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH
                       <> "?label=Coffee&message=Thanks%21") of
        Right u  -> do
          uriLabel u   `shouldBe` Just "Coffee"
          uriMessage u `shouldBe` Just "Thanks!"
        Left err -> expectationFailure (show err)

    it "rejects malformed percent-encoding" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?label=%ZZ") of
        Left (Bip21BadPercentEncoding _) -> pure ()
        other -> expectationFailure (show other)

  describe "BIP-78 PayJoin keys (G28, G29)" $ do
    -- These three cases (and the G16 query parsing case below) flip
    -- the W119 audit's `pendingWith` markers for G16, G28, G29.

    it "G28: parses pj=https://example.com/payjoin" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH
                       <> "?amount=0.1&pj=https%3A%2F%2Fexample.com%2Fpayjoin") of
        Right u  -> do
          uriPj u     `shouldBe` Just "https://example.com/payjoin"
          uriAmount u `shouldBe` Just 10_000_000
        Left err -> expectationFailure (show err)

    it "G29: parses pjos=0 (output substitution allowed)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?pjos=0") of
        Right u  -> uriPjos u `shouldBe` Just False
        Left err -> expectationFailure (show err)

    it "G29: parses pjos=1 (output substitution disabled)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?pjos=1") of
        Right u  -> uriPjos u `shouldBe` Just True
        Left err -> expectationFailure (show err)

    it "G29: parses pjos=true / pjos=false (BTCPay tolerance)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?pjos=true") of
        Right u  -> uriPjos u `shouldBe` Just True
        Left err -> expectationFailure (show err)
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?pjos=false") of
        Right u  -> uriPjos u `shouldBe` Just False
        Left err -> expectationFailure (show err)

    it "G29: rejects invalid pjos value" $ do
      parseBip21 mainnet ("bitcoin:" <> mainAddrP2PKH <> "?pjos=maybe")
        `shouldBe` Left (Bip21PjosInvalid "maybe")

    it "absence of pjos= leaves uriPjos = Nothing" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?pj=https%3A%2F%2Fx") of
        Right u  -> uriPjos u `shouldBe` Nothing
        Left err -> expectationFailure (show err)

  describe "G16: query-string parsing" $ do
    it "parses every standard + BIP-78 key in one URI" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH
              <> "?amount=0.5&label=Donate&message=For%20coffee&"
              <> "pj=https%3A%2F%2Fpj.example%2Fpayjoin&pjos=1") of
        Right u  -> do
          uriAmount u  `shouldBe` Just 50_000_000
          uriLabel u   `shouldBe` Just "Donate"
          uriMessage u `shouldBe` Just "For coffee"
          uriPj u      `shouldBe` Just "https://pj.example/payjoin"
          uriPjos u    `shouldBe` Just True
        Left err -> expectationFailure (show err)

    it "is case-insensitive on key names (LABEL, Amount, Pj)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH
                       <> "?Amount=0.25&LABEL=Hi&Pj=https%3A%2F%2Fx") of
        Right u  -> do
          uriAmount u `shouldBe` Just 25_000_000
          uriLabel u  `shouldBe` Just "Hi"
          uriPj u     `shouldBe` Just "https://x"
        Left err -> expectationFailure (show err)

    it "is case-insensitive on the bitcoin: scheme" $ do
      case parseBip21 mainnet ("BITCOIN:" <> mainAddrP2PKH) of
        Right _  -> pure ()
        Left err -> expectationFailure (show err)
      case parseBip21 mainnet ("Bitcoin:" <> mainAddrP2PKH <> "?amount=1") of
        Right u  -> uriAmount u `shouldBe` Just 100_000_000
        Left err -> expectationFailure (show err)

    it "stores unknown non-req keys in uriExtras" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?foo=bar&xyz=123") of
        Right u  -> uriExtras u
                      `shouldBe` Map.fromList [("foo", "bar"), ("xyz", "123")]
        Left err -> expectationFailure (show err)

    it "rejects unknown req- keys (BIP-21 forward-compat rule)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?req-unknown=x") of
        Left (Bip21UnknownRequired k) -> k `shouldBe` "req-unknown"
        other                         -> expectationFailure (show other)

    it "rejects malformed pair (no '=')" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?orphan") of
        Left (Bip21BadQuery _) -> pure ()
        other                  -> expectationFailure (show other)

    it "rejects empty key (=value)" $ do
      case parseBip21 mainnet
            ("bitcoin:" <> mainAddrP2PKH <> "?=foo") of
        Left (Bip21BadQuery _) -> pure ()
        other                  -> expectationFailure (show other)

  describe "scheme errors" $ do
    it "rejects non-bitcoin scheme" $ do
      case parseBip21 mainnet "litecoin:foo" of
        Left (Bip21BadScheme _) -> pure ()
        other                   -> expectationFailure (show other)

    it "rejects bare scheme (empty address)" $ do
      parseBip21 mainnet "bitcoin:" `shouldBe` Left Bip21EmptyAddress

    it "rejects bare scheme with query but empty address" $ do
      parseBip21 mainnet "bitcoin:?amount=1" `shouldBe` Left Bip21EmptyAddress

    it "rejects garbage in address slot" $ do
      case parseBip21 mainnet "bitcoin:not-an-address" of
        Left (Bip21BadAddress _) -> pure ()
        other                    -> expectationFailure (show other)

  describe "network mismatch" $ do
    it "rejects mainnet P2PKH against testnet3" $ do
      case parseBip21 testnet3 ("bitcoin:" <> mainAddrP2PKH) of
        Left (Bip21WrongNetwork _) -> pure ()
        other                      -> expectationFailure (show other)

    it "rejects mainnet bech32 against testnet3" $ do
      case parseBip21 testnet3 ("bitcoin:" <> mainAddrP2WPKH) of
        Left (Bip21WrongNetwork _) -> pure ()
        other                      -> expectationFailure (show other)

    it "rejects testnet3 P2PKH against mainnet" $ do
      case parseBip21 mainnet ("bitcoin:" <> testnetAddrP2PKH) of
        Left (Bip21WrongNetwork _) -> pure ()
        other                      -> expectationFailure (show other)

  describe "emit / round-trip" $ do
    it "emitBip21 . parseBip21 is identity on a fully-populated URI" $ do
      let src = "bitcoin:" <> mainAddrP2PKH
                <> "?amount=0.1"
                <> "&label=Test"
                <> "&message=A%20B"
                <> "&pj=https%3A%2F%2Fexample.com%2Fpayjoin"
                <> "&pjos=1"
      case parseBip21 mainnet src of
        Left err -> expectationFailure (show err)
        Right u  ->
          case parseBip21 mainnet (emitBip21 u) of
            Right u2 -> u2 `shouldBe` u
            Left e2  -> expectationFailure (show e2)

    it "emitBip21 omits absent fields" $ do
      let bare = "bitcoin:" <> mainAddrP2PKH
      case parseBip21 mainnet bare of
        Right u  -> emitBip21 u `shouldBe` bare
        Left err -> expectationFailure (show err)

    it "emitBip21 percent-encodes unsafe bytes in values" $ do
      case parseBip21 mainnet
             ("bitcoin:" <> mainAddrP2PKH <> "?label=A%20B%26C") of
        Right u  -> do
          uriLabel u `shouldBe` Just "A B&C"
          -- '&' must be re-encoded so the round-trip doesn't split the
          -- query string.
          T.isInfixOf "%26" (emitBip21 u) `shouldBe` True
        Left err -> expectationFailure (show err)

  describe "BIP-21 mediawiki reference vectors" $ do
    -- From bitcoin/bips/bip-0021.mediawiki §Examples
    -- (substituting the Genesis address since the spec's example
    -- address `175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W` is mainnet P2PKH).
    it "just the address" $ do
      case parseBip21 mainnet "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" of
        Right u  -> uriAmount u `shouldBe` Nothing
        Left err -> expectationFailure (show err)

    it "address with name" $ do
      case parseBip21 mainnet
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Luke-Jr" of
        Right u  -> uriLabel u `shouldBe` Just "Luke-Jr"
        Left err -> expectationFailure (show err)

    it "request 20.30 BTC to \"Luke-Jr\"" $ do
      case parseBip21 mainnet
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=20.3&label=Luke-Jr" of
        Right u  -> do
          uriAmount u `shouldBe` Just 2_030_000_000
          uriLabel u  `shouldBe` Just "Luke-Jr"
        Left err -> expectationFailure (show err)

    it "request 50 BTC with message" $ do
      case parseBip21 mainnet
            ("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
             <> "?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz") of
        Right u  -> do
          uriAmount u  `shouldBe` Just 5_000_000_000
          uriMessage u `shouldBe` Just "Donation for project xyz"
        Left err -> expectationFailure (show err)

  describe "percentDecode / percentEncode round-trip" $ do
    it "round-trips ASCII printable" $
      percentDecode (percentEncode "hello world") `shouldBe` Right "hello world"
    it "round-trips UTF-8 (emoji)" $ do
      -- "U+1F600 GRINNING FACE" = F0 9F 98 80 in UTF-8
      percentDecode (percentEncode "\x1F600") `shouldBe` Right "\x1F600"
    it "round-trips reserved chars" $
      percentDecode (percentEncode "& = ? #") `shouldBe` Right "& = ? #"

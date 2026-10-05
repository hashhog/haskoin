{-# LANGUAGE OverloadedStrings #-}
-- | Pay-to-Anchor (P2A) and WITNESS_UNKNOWN script classification.
--
-- 2026-10-02: @gettxout@ on a P2A output (scriptPubKey @51024e73@) DROPPED
-- THE RPC CONNECTION.  'scriptTypeToString' had no case for the 'P2A'
-- constructor, so the non-exhaustive case threw lazily while the response
-- 'Encoding' was being serialised -- after the handler had "succeeded".  Every
-- RPC that renders a scriptPubKey through 'psbtSpkEnc' (gettxout,
-- getrawtransaction verbose, getblock 2/3, decoderawtransaction,
-- decodepsbt) and decodescript shared the hole.  'scriptToAddress' also
-- returned no address for P2A and WITNESS_UNKNOWN, where Core returns one.
--
-- Expected values are Core's, taken from a regtest bitcoind (v31.99,
-- bitcoin-core/build) on 2026-10-02:
--
-- > decodescript 51024e73
-- >   {"asm":"1 29518","desc":"addr(bcrt1pfeesnyr2tx)#swxgse0y",
-- >    "address":"bcrt1pfeesnyr2tx","type":"anchor"}
-- > decodescript 5202abcd
-- >   {"asm":"2 -19883","desc":"addr(bcrt1z40xsz44l6p)#pj7n4prx",
-- >    "address":"bcrt1z40xsz44l6p","type":"witness_unknown"}
--
-- Every encoding is forced to bytes ('encodingToLazyByteString' + length),
-- because the original bug only fired when the lazy encoder was RUN.
module P2AScriptClassifySpec (spec) where

import Control.Exception (evaluate)
import Test.Hspec
import Data.Aeson (Value(..), decode)
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Haskoin.Consensus (mainnet, regtest)
import Haskoin.Script (ScriptType(..), p2aWitnessProgram)
import Haskoin.Types (Hash256(..))
import Haskoin.Crypto
  ( Address(..)
  , bech32Encode
  , bech32mEncode
  , textToAddress
  , addressToText
  , scriptPubKeyToAddress
  , addressToScriptPubKey
  )
import Haskoin.Rpc
  ( scriptTypeToString
  , scriptToAddress
  , psbtSpkEnc
  , witnessV1PlusAddressToScript
  , scriptToAsm
  , scriptToAsmPartial
  )

-- | secp256k1 generator (compressed). Core InferDescriptor emits pk()/multi()
-- of this key; haskoin previously emitted raw(<hex>).
pk1Hex :: T.Text
pk1Hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

pk2Hex :: T.Text
pk2Hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

hex :: T.Text -> BS.ByteString
hex t = case B16.decode (TE.encodeUtf8 t) of
  Right bs -> bs
  Left err -> error ("hex: " ++ err)

-- 33-byte push of pk1 + OP_CHECKSIG
p2pkSpk :: BS.ByteString
p2pkSpk = hex ("21" <> pk1Hex <> "ac")

-- 1-of-2 bare multisig: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
bareMultiSpk :: BS.ByteString
bareMultiSpk = hex ("5121" <> pk1Hex <> "21" <> pk2Hex <> "52ae")

p2aSpk :: BS.ByteString
p2aSpk = BS.pack [0x51, 0x02, 0x4e, 0x73]

-- | Run the encoder to completion and parse the result back.
spkObj :: BS.ByteString -> IO (KM.KeyMap Value)
spkObj spk = do
  let bytes = encodingToLazyByteString (psbtSpkEnc regtest spk)
  _ <- evaluate (BL.length bytes)
  case decode bytes of
    Just (Object o) -> return o
    _ -> expectationFailure ("not a JSON object: " ++ show bytes) >> return KM.empty

field :: KM.KeyMap Value -> T.Text -> Maybe Value
field o k = KM.lookup (K.fromText k) o

spec :: Spec
spec = describe "P2A script classification (gettxout drop, 2026-10-02)" $ do

  it "scriptTypeToString P2A is Core's \"anchor\" (and is total)" $ do
    t <- evaluate (scriptTypeToString P2A)
    t `shouldBe` "anchor"

  it "scriptToAddress P2A is bc1pfeessrawgf (mainnet) / bcrt1pfeesnyr2tx (regtest)" $ do
    scriptToAddress mainnet p2aSpk P2A `shouldBe` Just "bc1pfeessrawgf"
    scriptToAddress regtest p2aSpk P2A `shouldBe` Just "bcrt1pfeesnyr2tx"

  it "psbtSpkEnc (the gettxout/getrawtransaction/getblock encoder) matches Core for P2A" $ do
    o <- spkObj p2aSpk
    field o "type"    `shouldBe` Just (String "anchor")
    field o "address" `shouldBe` Just (String "bcrt1pfeesnyr2tx")
    field o "desc"    `shouldBe` Just (String "addr(bcrt1pfeesnyr2tx)#swxgse0y")
    field o "hex"     `shouldBe` Just (String "51024e73")
    -- Core ScriptToAsmStr: a <=4-byte push prints as its CScriptNum value.
    field o "asm"     `shouldBe` Just (String "1 29518")

  it "psbtSpkEnc matches Core for WITNESS_UNKNOWN (OP_2 <abcd>)" $ do
    o <- spkObj (BS.pack [0x52, 0x02, 0xab, 0xcd])
    field o "type"    `shouldBe` Just (String "witness_unknown")
    field o "address" `shouldBe` Just (String "bcrt1z40xsz44l6p")
    field o "desc"    `shouldBe` Just (String "addr(bcrt1z40xsz44l6p)#pj7n4prx")
    field o "asm"     `shouldBe` Just (String "2 -19883")

  it "CONTROL: P2TR and nonstandard are unchanged (no address for nonstandard)" $ do
    let h = BS.replicate 32 0x11
    scriptToAddress regtest (BS.pack [0x51, 0x20] <> h) (P2TR (Hash256 h))
      `shouldSatisfy` maybe False ("bcrt1p" `T.isPrefixOf`)
    o <- spkObj (BS.pack [0x60, 0x02, 0xab, 0xcd, 0xef])
    field o "type"    `shouldBe` Just (String "nonstandard")
    field o "address" `shouldBe` Nothing

  it "witnessV1PlusAddressToScript decodes P2A / witness_unknown addresses (scantxoutset addr())" $ do
    witnessV1PlusAddressToScript regtest "bcrt1pfeesnyr2tx" `shouldBe` Just p2aSpk
    witnessV1PlusAddressToScript mainnet "bc1pfeessrawgf"   `shouldBe` Just p2aSpk
    witnessV1PlusAddressToScript regtest "bcrt1z40xsz44l6p"
      `shouldBe` Just (BS.pack [0x52, 0x02, 0xab, 0xcd])
    BS.drop 2 <$> witnessV1PlusAddressToScript regtest "bcrt1pfeesnyr2tx"
      `shouldBe` Just p2aWitnessProgram

  it "CONTROL: witnessV1PlusAddressToScript refuses wrong network and v0" $ do
    -- mainnet address on regtest: wrong HRP
    witnessV1PlusAddressToScript regtest "bc1pfeessrawgf" `shouldBe` Nothing
    -- a v0 address is not this function's to decode
    witnessV1PlusAddressToScript regtest (bech32Encode "bcrt" 0 (BS.replicate 20 7))
      `shouldBe` Nothing
    -- BIP-350: a v1 program checksummed with BECH32 (not bech32m) is invalid
    witnessV1PlusAddressToScript regtest (bech32Encode "bcrt" 1 p2aWitnessProgram)
      `shouldBe` Nothing
    -- sanity for the line above: the bech32m form of the same data IS accepted
    witnessV1PlusAddressToScript regtest (bech32mEncode "bcrt" 1 p2aWitnessProgram)
      `shouldBe` Just p2aSpk

  it "asm renders OP_CHECKSIGADD (0xba) instead of throwing (same lazy-throw class)" $ do
    -- Core: decodescript ba -> {"asm":"OP_CHECKSIGADD", ...,"type":"nonstandard"}
    a1 <- evaluate (T.length (scriptToAsm (BS.pack [0xba])) `seq` scriptToAsm (BS.pack [0xba]))
    a1 `shouldBe` "OP_CHECKSIGADD"
    a2 <- evaluate (scriptToAsmPartial (BS.pack [0xba]))
    _ <- evaluate (T.length a2)
    a2 `shouldBe` "OP_CHECKSIGADD"
    o <- spkObj (BS.pack [0xba])
    field o "asm"  `shouldBe` Just (String "OP_CHECKSIGADD")
    field o "type" `shouldBe` Just (String "nonstandard")

  -- RPC follow-ups from the P2A fix (QUEUES.md [bot] item, 2026-10-02):
  -- descriptors show raw() where Core shows pk()/multi(); wallet Address
  -- type lacks P2A; asm prints OP_UNKNOWN[n] where Core prints OP_UNKNOWN.
  -- Control: compare decodescript / getdescriptorinfo vs a regtest Core
  -- for a P2PK, a bare multisig and a 0xba-containing script (plus 0xbb
  -- so the OP_UNKNOWN spelling is actually exercised — 0xba is named).
  describe "RPC P2A follow-up (pk/multi, Address P2A, OP_UNKNOWN)" $ do
    it "P2PK desc is Core pk(KEY)#gn28ywm7, not raw(hex)" $ do
      o <- spkObj p2pkSpk
      field o "type" `shouldBe` Just (String "pubkey")
      field o "desc" `shouldBe`
        Just (String ("pk(" <> pk1Hex <> ")#gn28ywm7"))
      field o "address" `shouldBe` Nothing

    it "bare 1-of-2 multisig desc is Core multi(1,K1,K2)#l5sy3u48, not raw(hex)" $ do
      o <- spkObj bareMultiSpk
      field o "type" `shouldBe` Just (String "multisig")
      field o "desc" `shouldBe`
        Just (String ("multi(1," <> pk1Hex <> "," <> pk2Hex <> ")#l5sy3u48"))
      field o "address" `shouldBe` Nothing

    it "asm of unnamed opcode 0xbb is OP_UNKNOWN (not OP_UNKNOWN[n])" $ do
      a1 <- evaluate (scriptToAsm (BS.pack [0xbb]))
      a1 `shouldBe` "OP_UNKNOWN"
      a2 <- evaluate (scriptToAsmPartial (BS.pack [0xbb]))
      a2 `shouldBe` "OP_UNKNOWN"
      o <- spkObj (BS.pack [0xbb])
      field o "asm"  `shouldBe` Just (String "OP_UNKNOWN")
      field o "desc" `shouldBe` Just (String "raw(bb)#79gjzk4q")
      field o "type" `shouldBe` Just (String "nonstandard")

    it "asm of 0xff is Core OP_INVALIDOPCODE" $ do
      scriptToAsm (BS.pack [0xff]) `shouldBe` "OP_INVALIDOPCODE"
      scriptToAsmPartial (BS.pack [0xff]) `shouldBe` "OP_INVALIDOPCODE"

    it "CONTROL: 0xba-containing script stays OP_CHECKSIGADD + raw(ba)#yy0eg44l" $ do
      o <- spkObj (BS.pack [0xba])
      field o "asm"  `shouldBe` Just (String "OP_CHECKSIGADD")
      field o "desc" `shouldBe` Just (String "raw(ba)#yy0eg44l")

    it "wallet Address type carries P2A (textToAddress bc1pfeessrawgf)" $ do
      -- Before: textToAddress rejected v1 programs that were not 32 bytes.
      -- Core DecodeDestination returns PayToAnchor for this string.
      textToAddress "bc1pfeessrawgf" `shouldBe` Just AnchorAddress
      textToAddress "bcrt1pfeesnyr2tx" `shouldBe` Just AnchorAddress
      addressToText AnchorAddress `shouldBe` "bc1pfeessrawgf"
      addressToScriptPubKey AnchorAddress `shouldBe` p2aSpk
      scriptPubKeyToAddress p2aSpk `shouldBe` Just AnchorAddress

    it "CONTROL: hybrid (0x06) P2PK stays raw() — InferPubkey rejects non-hybrid" $ do
      -- Core descriptor_tests.cpp CheckInferDescriptor of a 65-byte 0x06
      -- hybrid key is raw(...), not pk(...).
      let hybrid = hex "41069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4ac"
      o <- spkObj hybrid
      field o "type" `shouldBe` Just (String "pubkey")
      case field o "desc" of
        Just (String d) -> T.isPrefixOf "raw(" d `shouldBe` True
        other -> expectationFailure ("expected raw() desc, got " ++ show other)

    it "CONTROL: bech32 (not bech32m) P2A is rejected" $ do
      textToAddress (bech32Encode "bc" 1 p2aWitnessProgram) `shouldBe` Nothing

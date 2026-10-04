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
import Haskoin.Crypto (Address(..), bech32Encode, bech32mEncode, textToAddress)
import Haskoin.Wallet (addDescriptorChecksum, addressToTextW, parseDescriptor, Descriptor(..))
import Haskoin.Rpc
  ( scriptTypeToString
  , scriptToAddress
  , psbtSpkEnc
  , witnessV1PlusAddressToScript
  , scriptToAsm
  , scriptToAsmPartial
  )

-- | secp256k1 G, compressed.  Used by Core's descriptor tests.
pk1Hex :: T.Text
pk1Hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

-- | 2*G, compressed.
pk2Hex :: T.Text
pk2Hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

fromHex :: T.Text -> BS.ByteString
fromHex t = case B16.decode (TE.encodeUtf8 t) of
  Right b -> b
  Left e  -> error ("fromHex: " ++ e)

-- | <G> OP_CHECKSIG
p2pkSpk :: BS.ByteString
p2pkSpk = BS.singleton 0x21 <> fromHex pk1Hex <> BS.singleton 0xac

-- | OP_1 <G> <2G> OP_2 OP_CHECKMULTISIG
bareMultiSpk :: BS.ByteString
bareMultiSpk =
  BS.singleton 0x51
    <> BS.singleton 0x21 <> fromHex pk1Hex
    <> BS.singleton 0x21 <> fromHex pk2Hex
    <> BS.singleton 0x52
    <> BS.singleton 0xae

-- Gold from a throwaway Core v31.99.0 regtest (2026-10-04):
--   decodescript 21<G>ac
coreP2pkDesc :: T.Text
coreP2pkDesc = "pk(" <> pk1Hex <> ")#gn28ywm7"

--   decodescript 51 21<G> 21<2G> 52 ae
coreMultiDesc :: T.Text
coreMultiDesc =
  "multi(1," <> pk1Hex <> "," <> pk2Hex <> ")#l5sy3u48"

--   decodescript ba / bb / ff
coreBaDesc, coreBbDesc, coreFfDesc :: T.Text
coreBaDesc = "raw(ba)#yy0eg44l"
coreBbDesc = "raw(bb)#79gjzk4q"
coreFfDesc = "raw(ff)#wuxj4tep"

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

  -- Gold: throwaway Core v31.99.0 regtest, 2026-10-04.
  --   bitcoin-cli -regtest decodescript / getdescriptorinfo
  describe "CONTROL: P2A RPC follow-ups vs Core (decodescript/getdescriptorinfo)" $ do
    it "CONTROL: P2PK desc is pk(KEY)#csum (not raw())" $ do
      o <- spkObj p2pkSpk
      field o "type" `shouldBe` Just (String "pubkey")
      field o "desc" `shouldBe` Just (String coreP2pkDesc)
      field o "asm"  `shouldBe`
        Just (String (pk1Hex <> " OP_CHECKSIG"))
      -- getdescriptorinfo of that desc: solvable pk()
      case parseDescriptor coreP2pkDesc of
        Left err -> expectationFailure ("getdescriptorinfo parse: " ++ show err)
        Right _  -> case addDescriptorChecksum ("pk(" <> pk1Hex <> ")") of
          Just d -> d `shouldBe` coreP2pkDesc
          Nothing -> expectationFailure "checksum failed"

    it "CONTROL: bare 1-of-2 multisig desc is multi(1,k1,k2)#csum (not raw())" $ do
      o <- spkObj bareMultiSpk
      field o "type" `shouldBe` Just (String "multisig")
      field o "desc" `shouldBe` Just (String coreMultiDesc)
      field o "asm"  `shouldBe`
        Just (String ("1 " <> pk1Hex <> " " <> pk2Hex <> " 2 OP_CHECKMULTISIG"))
      case parseDescriptor coreMultiDesc of
        Left err -> expectationFailure ("getdescriptorinfo parse: " ++ show err)
        Right _  -> case addDescriptorChecksum
                       ("multi(1," <> pk1Hex <> "," <> pk2Hex <> ")") of
          Just d -> d `shouldBe` coreMultiDesc
          Nothing -> expectationFailure "checksum failed"

    it "CONTROL: 0xba-containing script asm is OP_CHECKSIGADD, desc raw(ba)#csum" $ do
      o <- spkObj (BS.pack [0xba])
      field o "asm"  `shouldBe` Just (String "OP_CHECKSIGADD")
      field o "desc" `shouldBe` Just (String coreBaDesc)
      field o "type" `shouldBe` Just (String "nonstandard")

    it "CONTROL: unknown opcode asm is OP_UNKNOWN (not OP_UNKNOWN[n])" $ do
      -- Core GetOpName for unnamed opcodes returns "OP_UNKNOWN", never the
      -- byte.  0xbb is unallocated; 0xff is the named OP_INVALIDOPCODE.
      aBb <- evaluate (scriptToAsm (BS.pack [0xbb]))
      aBb `shouldBe` "OP_UNKNOWN"
      aBbP <- evaluate (scriptToAsmPartial (BS.pack [0xbb]))
      aBbP `shouldBe` "OP_UNKNOWN"
      o <- spkObj (BS.pack [0xbb])
      field o "asm"  `shouldBe` Just (String "OP_UNKNOWN")
      field o "desc" `shouldBe` Just (String coreBbDesc)
      aFf <- evaluate (scriptToAsm (BS.pack [0xff]))
      aFf `shouldBe` "OP_INVALIDOPCODE"

    it "CONTROL: wallet Address carries P2A (textToAddress / addr() descriptor)" $ do
      -- Core DecodeDestination: bc1pfeessrawgf / bcrt1pfeesnyr2tx -> PayToAnchor.
      textToAddress "bc1pfeessrawgf" `shouldBe` Just AnchorAddress
      textToAddress "bcrt1pfeesnyr2tx" `shouldBe` Just AnchorAddress
      addressToTextW mainnet AnchorAddress `shouldBe` "bc1pfeessrawgf"
      addressToTextW regtest AnchorAddress `shouldBe` "bcrt1pfeesnyr2tx"
      case parseDescriptor "addr(bcrt1pfeesnyr2tx)#swxgse0y" of
        Right (Addr AnchorAddress) -> return ()
        other -> expectationFailure ("expected Addr AnchorAddress, got " ++ show other)

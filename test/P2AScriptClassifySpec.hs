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
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import qualified Data.ByteString.Base16 as B16

import Haskoin.Consensus (mainnet, regtest)
import Haskoin.Script (ScriptType(..), p2aWitnessProgram)
import Haskoin.Types (Hash256(..))
import Haskoin.Crypto
  ( Address(..)
  , addressToText
  , bech32Encode
  , bech32mEncode
  , textToAddress
  )
import Haskoin.Wallet
  ( Descriptor(..)
  , addressToTextW
  , parseDescriptor
  )
import Haskoin.Rpc
  ( scriptTypeToString
  , scriptToAddress
  , psbtSpkEnc
  , witnessV1PlusAddressToScript
  , scriptToAsm
  , scriptToAsmPartial
  )

-- | Control scripts, taken from a regtest bitcoind (bitcoin-core/build)
-- on 2026-10-05.  secp256k1 G and 2*G compressed.
--
-- > decodescript 210279be66…ac
-- >   {"asm":"0279be66… OP_CHECKSIG",
-- >    "desc":"pk(0279be66…)#gn28ywm7","type":"pubkey",...}
-- > decodescript 51210279be66…52ae
-- >   {"desc":"multi(1,0279be66…,02c6047f…)#l5sy3u48","type":"multisig",...}
-- > decodescript ba  -> {"asm":"OP_CHECKSIGADD","desc":"raw(ba)#yy0eg44l"}
-- > decodescript bb  -> {"asm":"OP_UNKNOWN","desc":"raw(bb)#79gjzk4q"}
fromHex :: String -> BS.ByteString
fromHex s = case B16.decode (TE.encodeUtf8 (T.pack s)) of
  Right b -> b
  Left e  -> error e

p2pkSpk, multiSpk :: BS.ByteString
p2pkSpk =
  fromHex "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
multiSpk =
  fromHex
    "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
    \2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae"

corePkDesc, coreMultiDesc :: T.Text
corePkDesc =
  "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7"
coreMultiDesc =
  "multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,\
  \02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#l5sy3u48"

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

  -- CONTROL vs a regtest Core (2026-10-05, bitcoin-core/build):
  --   cabal test haskoin-test --test-options='-m "P2A RPC follow-ups"'
  describe "P2A RPC follow-ups (pk/multi/OP_UNKNOWN/PayToAnchorAddress)" $ do

    it "decodescript/gettxout desc of a P2PK is Core's pk(KEY)#csum, not raw()" $ do
      o <- spkObj p2pkSpk
      field o "type" `shouldBe` Just (String "pubkey")
      field o "desc" `shouldBe` Just (String corePkDesc)
      field o "asm"  `shouldBe`
        Just (String "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 OP_CHECKSIG")
      case field o "desc" of
        Just (String d) -> case parseDescriptor d of
          Right (Pk _) -> return ()
          other -> expectationFailure ("expected Pk, got " ++ show other)
        other -> expectationFailure ("expected desc string, got " ++ show other)

    it "decodescript/gettxout desc of a bare 1-of-2 is Core's multi(k,...)#csum, not raw()" $ do
      o <- spkObj multiSpk
      field o "type" `shouldBe` Just (String "multisig")
      field o "desc" `shouldBe` Just (String coreMultiDesc)
      case field o "desc" of
        Just (String d) -> case parseDescriptor d of
          Right (Multi 1 _) -> return ()
          other -> expectationFailure ("expected Multi 1, got " ++ show other)
        other -> expectationFailure ("expected desc string, got " ++ show other)

    it "asm of 0xba is OP_CHECKSIGADD and desc is Core's raw(ba)#yy0eg44l" $ do
      o <- spkObj (BS.pack [0xba])
      field o "asm"  `shouldBe` Just (String "OP_CHECKSIGADD")
      field o "desc" `shouldBe` Just (String "raw(ba)#yy0eg44l")
      field o "type" `shouldBe` Just (String "nonstandard")

    it "asm of unknown opcode 0xbb is Core's OP_UNKNOWN (not OP_UNKNOWN[n])" $ do
      a1 <- evaluate (scriptToAsm (BS.pack [0xbb]))
      a1 `shouldBe` "OP_UNKNOWN"
      a2 <- evaluate (scriptToAsmPartial (BS.pack [0xbb]))
      a2 `shouldBe` "OP_UNKNOWN"
      o <- spkObj (BS.pack [0xbb])
      field o "asm"  `shouldBe` Just (String "OP_UNKNOWN")
      field o "desc" `shouldBe` Just (String "raw(bb)#79gjzk4q")

    it "asm of 0xff is Core's OP_INVALIDOPCODE" $ do
      scriptToAsm (BS.pack [0xff]) `shouldBe` "OP_INVALIDOPCODE"
      scriptToAsmPartial (BS.pack [0xff]) `shouldBe` "OP_INVALIDOPCODE"

    it "wallet Address decodes the P2A bech32m (bc1pfeessrawgf / bcrt1pfeesnyr2tx)" $ do
      -- Core DecodeDestination: PayToAnchor.
      textToAddress "bc1pfeessrawgf" `shouldBe` Just PayToAnchorAddress
      textToAddress "bcrt1pfeesnyr2tx" `shouldBe` Just PayToAnchorAddress
      addressToText PayToAnchorAddress `shouldBe` "bc1pfeessrawgf"
      addressToTextW mainnet PayToAnchorAddress `shouldBe` "bc1pfeessrawgf"
      addressToTextW regtest PayToAnchorAddress `shouldBe` "bcrt1pfeesnyr2tx"
      -- CONTROL: a 32-byte v1 program is still Taproot, not P2A
      case textToAddress "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0" of
        Just (TaprootAddress _) -> return ()
        other -> expectationFailure ("expected TaprootAddress, got " ++ show other)

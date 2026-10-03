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
  , addressToText
  , textToAddress
  , bech32Encode
  , bech32mEncode
  )
import Haskoin.Wallet (Descriptor(..), parseDescriptor, deriveScripts)
import Haskoin.Rpc
  ( scriptTypeToString
  , scriptToAddress
  , psbtSpkEnc
  , inferSpkDescriptor
  , decodeScriptEnc
  , witnessV1PlusAddressToScript
  , scriptToAsm
  , scriptToAsmPartial
  )

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

decodeObj :: BS.ByteString -> IO (KM.KeyMap Value)
decodeObj spk = do
  let bytes = encodingToLazyByteString (decodeScriptEnc regtest spk)
  _ <- evaluate (BL.length bytes)
  case decode bytes of
    Just (Object o) -> return o
    _ -> expectationFailure ("not a JSON object: " ++ show bytes) >> return KM.empty

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

  -- ------------------------------------------------------------------
  -- RPC follow-ups from the P2A fix (QUEUES.md 2026-10-03).
  -- Core values taken from a throwaway regtest bitcoind v31.99
  -- (bitcoin-core/build, 2026-10-03) via:
  --   bitcoin-cli -regtest decodescript <hex>
  --   bitcoin-cli -regtest getdescriptorinfo <desc>
  -- ------------------------------------------------------------------
  let pkHex = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd" :: T.Text
      k2Hex = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626" :: T.Text
      unhex t = case B16.decode (TE.encodeUtf8 t) of
        Right bs -> bs
        Left err -> error ("unhex: " ++ err)
      -- <pk> OP_CHECKSIG
      p2pkSpk = BS.pack [0x21] <> unhex pkHex <> BS.pack [0xac]
      -- OP_1 <pk> <k2> OP_2 OP_CHECKMULTISIG
      multiSpk =
        BS.pack [0x51, 0x21] <> unhex pkHex
        <> BS.pack [0x21] <> unhex k2Hex
        <> BS.pack [0x52, 0xae]
      corePkDesc    = "pk(" <> pkHex <> ")#vwaefwnq"
      coreMultiDescNoCsum = "multi(1," <> pkHex <> "," <> k2Hex <> ")"
      coreMultiDesc = coreMultiDescNoCsum <> "#ve902xrt"
      coreBaDesc    = "raw(ba)#yy0eg44l"
      coreBbDesc    = "raw(bb)#79gjzk4q"

  it "CONTROL: P2PK descriptor is pk() not raw() (Core InferDescriptor)" $ do
    o <- spkObj p2pkSpk
    field o "type" `shouldBe` Just (String "pubkey")
    field o "desc" `shouldBe` Just (String corePkDesc)
    field o "address" `shouldBe` Nothing

  it "CONTROL: bare multisig descriptor is multi() not raw() (Core InferDescriptor)" $ do
    o <- spkObj multiSpk
    field o "type" `shouldBe` Just (String "multisig")
    field o "desc" `shouldBe` Just (String coreMultiDesc)
    field o "address" `shouldBe` Nothing

  it "CONTROL: 0xba script descriptor stays raw(ba) (nonstandard, Core InferDescriptor)" $ do
    o <- spkObj (BS.pack [0xba])
    field o "desc" `shouldBe` Just (String coreBaDesc)
    field o "asm"  `shouldBe` Just (String "OP_CHECKSIGADD")

  it "CONTROL: unknown opcode asm is OP_UNKNOWN not OP_UNKNOWN[n] (Core GetOpName)" $ do
    -- Core: decodescript bb -> {"asm":"OP_UNKNOWN","desc":"raw(bb)#79gjzk4q","type":"nonstandard"}
    a1 <- evaluate (scriptToAsm (BS.pack [0xbb]))
    a1 `shouldBe` "OP_UNKNOWN"
    a2 <- evaluate (scriptToAsmPartial (BS.pack [0xbb]))
    a2 `shouldBe` "OP_UNKNOWN"
    o <- spkObj (BS.pack [0xbb])
    field o "asm"  `shouldBe` Just (String "OP_UNKNOWN")
    field o "desc" `shouldBe` Just (String coreBbDesc)
    field o "type" `shouldBe` Just (String "nonstandard")

  it "CONTROL: decodescript P2PK matches Core (pk desc, p2sh wrap, p2wpkh segwit)" $ do
    o <- decodeObj p2pkSpk
    field o "asm"  `shouldBe` Just (String (pkHex <> " OP_CHECKSIG"))
    field o "desc" `shouldBe` Just (String corePkDesc)
    field o "type" `shouldBe` Just (String "pubkey")
    field o "address" `shouldBe` Nothing
    field o "p2sh" `shouldBe` Just (String "2MweapFn2FbSP6tQAEv8bVMRyY4GhyCzKb8")
    case field o "segwit" of
      Just (Object s) -> do
        field s "type" `shouldBe` Just (String "witness_v0_keyhash")
        field s "address" `shouldBe` Just (String "bcrt1qgp3v3thdf7qu94ellp2299tsyyv3ug9k7j72vw")
        field s "desc" `shouldBe` Just (String "addr(bcrt1qgp3v3thdf7qu94ellp2299tsyyv3ug9k7j72vw)#k9hnkezd")
      other -> expectationFailure ("missing segwit object: " ++ show other)

  it "CONTROL: decodescript bare multisig matches Core (multi desc, wsh(multi) wrap)" $ do
    o <- decodeObj multiSpk
    field o "desc" `shouldBe` Just (String coreMultiDesc)
    field o "type" `shouldBe` Just (String "multisig")
    field o "p2sh" `shouldBe` Just (String "2NA8iB4spraDPgu6t4Uqt2bPdc16BSWUXxT")
    case field o "segwit" of
      Just (Object s) -> do
        field s "type" `shouldBe` Just (String "witness_v0_scripthash")
        field s "desc" `shouldBe` Just (String ("wsh(" <> coreMultiDescNoCsum <> ")#8yt2huam"))
        field s "address" `shouldBe` Just (String "bcrt1qt5lawy8yvnhqr8ujmst8834ztzr4rtp894k99fyah5ghch3g3g4qawxk8e")
      other -> expectationFailure ("missing segwit object: " ++ show other)

  it "CONTROL: getdescriptorinfo of inferred pk()/multi() is solvable (Core)" $ do
    inferSpkDescriptor regtest p2pkSpk `shouldBe` corePkDesc
    inferSpkDescriptor regtest multiSpk `shouldBe` coreMultiDesc
    case parseDescriptor corePkDesc of
      Right (Pk _) -> pure ()
      other -> expectationFailure ("pk() did not parse: " ++ show other)
    case parseDescriptor coreMultiDesc of
      Right (Multi 1 _) -> pure ()
      other -> expectationFailure ("multi() did not parse: " ++ show other)

  it "wallet Address type carries P2A (text/script round-trip)" $ do
    textToAddress "bc1pfeessrawgf" `shouldBe` Just AnchorAddress
    textToAddress "bcrt1pfeesnyr2tx" `shouldBe` Just AnchorAddress
    addressToText AnchorAddress `shouldBe` "bc1pfeessrawgf"
    deriveScripts (Addr AnchorAddress) 0 `shouldBe` [p2aSpk]
    -- P2TR still wins for 32-byte v1 programs
    textToAddress "bc1pfeessrawgf" `shouldNotBe` Nothing
    -- CONTROL: a v0 address is not P2A
    textToAddress (bech32Encode "bc" 0 (BS.replicate 20 7))
      `shouldSatisfy` maybe False (/= AnchorAddress)

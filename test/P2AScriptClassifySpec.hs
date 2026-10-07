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
import Haskoin.Crypto (bech32Encode, bech32mEncode)
import Haskoin.Wallet
  ( Descriptor(..)
  , parseDescriptor
  , descriptorToTextNet
  , addDescriptorChecksum
  , isRangeDescriptor
  )
import Haskoin.Rpc
  ( scriptTypeToString
  , scriptToAddress
  , psbtSpkEnc
  , witnessV1PlusAddressToScript
  , scriptToAsm
  , scriptToAsmPartial
  , inferSpkDescriptorWith
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

-- | Core getdescriptorinfo `descriptor` field on regtest: network-aware
-- canonical text plus its own checksum. A parse failure is returned as
-- text so the hspec diff shows the rejection instead of throwing.
canonical :: T.Text -> T.Text
canonical input =
  case parseDescriptor input of
    Left e  -> T.pack ("PARSE FAIL " ++ show e)
    Right d ->
      let body = descriptorToTextNet regtest d
      in case addDescriptorChecksum body of
           Just c  -> c
           Nothing -> body

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

  -- Golden strings are Bitcoin Core v31.99 (bitcoin-core/build) regtest,
  -- captured 2026-10-07 via decodescript / getdescriptorinfo:
  --   P2PK  210279be667e…1798ac
  --   multi 52210279be66…2102c6047f…52ae   (2-of-2, both compressed)
  --   babb  OP_CHECKSIGADD ++ an unnamed opcode
  --   addr(bcrt1pfeesnyr2tx)
  describe "RPC follow-ups from the P2A fix" $ do
    let pkHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        pk2   = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        p2pk  = BS.pack [0x21] <> hex pkHex <> BS.pack [0xac]
        multi = BS.pack [0x52, 0x21] <> hex pkHex
             <> BS.pack [0x21] <> hex pk2
             <> BS.pack [0x52, 0xae]
        corePk = "pk(" <> pkHex <> ")#gn28ywm7"
        coreMulti =
          "multi(2," <> pkHex <> "," <> pk2 <> ")#52kq63aa"
        hex s = case B16.decode (TE.encodeUtf8 s) of
                  Right b -> b
                  Left e  -> error e

    it "decodescript P2PK infers pk() (Core regtest), not raw()" $ do
      o <- spkObj p2pk
      field o "desc" `shouldBe` Just (String corePk)
      field o "type" `shouldBe` Just (String "pubkey")
      field o "asm"  `shouldBe` Just (String (pkHex <> " OP_CHECKSIG"))

    it "decodescript bare multisig infers multi() (Core regtest), not raw()" $ do
      o <- spkObj multi
      field o "desc" `shouldBe` Just (String coreMulti)
      field o "type" `shouldBe` Just (String "multisig")

    it "decodescript segwit wrap of a bare multisig is wsh(multi())" $ do
      -- Core decodescript of the 2-of-2 above: segwit.desc.
      -- The redeem is the bare multisig; the outer script is the P2WSH
      -- Core builds for the wrap (witness program = SHA256(redeem)).
      -- This assertion was added after the red control run: the helper
      -- did not exist yet, so the red examples could not name it.
      let prog = hex "9b984c7bae3efddc3a3f0a20ff81bfe89ed1fe07ff13e562149ee654bed845db"
          segwit = BS.pack [0x00, 0x20] <> prog
      inferSpkDescriptorWith regtest segwit (Just multi)
        `shouldBe` ("wsh(multi(2," <> pkHex <> "," <> pk2 <> "))#e7d75zev")

    it "asm of a 0xba-containing script is OP_UNKNOWN, not OP_UNKNOWN[n]" $ do
      -- Core decodescript babb -> "OP_CHECKSIGADD OP_UNKNOWN"
      -- Core decodescript bb   -> "OP_UNKNOWN"
      -- Core decodescript ff   -> "OP_INVALIDOPCODE" (the one named unknown)
      scriptToAsm (BS.pack [0xba, 0xbb]) `shouldBe` "OP_CHECKSIGADD OP_UNKNOWN"
      scriptToAsmPartial (BS.pack [0xba, 0xbb]) `shouldBe` "OP_CHECKSIGADD OP_UNKNOWN"
      scriptToAsm (BS.pack [0xbb]) `shouldBe` "OP_UNKNOWN"
      scriptToAsm (BS.pack [0xff]) `shouldBe` "OP_INVALIDOPCODE"

    it "getdescriptorinfo pk()/multi() canonical form matches regtest Core" $ do
      canonical corePk `shouldBe` corePk
      canonical coreMulti `shouldBe` coreMulti
      case parseDescriptor corePk of
        Right d -> isRangeDescriptor d `shouldBe` False
        Left e  -> expectationFailure (show e)
      case parseDescriptor coreMulti of
        Right d -> isRangeDescriptor d `shouldBe` False
        Left e  -> expectationFailure (show e)

    it "getdescriptorinfo addr(P2A) round-trips (wallet Address has PayToAnchor)" $ do
      -- Core: getdescriptorinfo "addr(bcrt1pfeesnyr2tx)"
      --   descriptor = addr(bcrt1pfeesnyr2tx)#swxgse0y
      --   checksum = swxgse0y, isrange false, issolvable false
      case parseDescriptor "addr(bcrt1pfeesnyr2tx)" of
        Left e -> expectationFailure ("addr(P2A) rejected: " ++ show e)
        Right d -> do
          canonical "addr(bcrt1pfeesnyr2tx)" `shouldBe` "addr(bcrt1pfeesnyr2tx)#swxgse0y"
          descriptorToTextNet regtest d `shouldBe` "addr(bcrt1pfeesnyr2tx)"
          isRangeDescriptor d `shouldBe` False
          case d of
            Addr _ -> pure ()
            _      -> expectationFailure ("expected Addr, got " ++ show d)

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

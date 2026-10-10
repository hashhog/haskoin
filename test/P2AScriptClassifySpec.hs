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

import Control.Exception (bracket, evaluate)
import Control.Concurrent.STM (newTVarIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import Test.Hspec
import Data.Aeson (Value(..), decode)
import qualified Data.Aeson as AE
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import Data.Either (isRight)
import Data.Maybe (isJust)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import System.Directory (getTemporaryDirectory, removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Consensus (mainnet, regtest, initHeaderChain)
import Haskoin.Script (ScriptType(..), p2aWitnessProgram)
import Haskoin.Types (Hash256(..))
import Haskoin.Crypto (bech32Encode, bech32mEncode, textToAddress)
import Haskoin.Storage
  ( defaultDBConfig, defaultPruneConfig, newUTXOCache, withDB )
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Wallet
  ( addressToTextW, addDescriptorChecksum, deriveAddresses, deriveScripts
  , parseDescriptor )
import Haskoin.Rpc
  ( scriptTypeToString
  , scriptToAddress
  , psbtSpkEnc
  , witnessV1PlusAddressToScript
  , scriptToAsm
  , scriptToAsmPartial
  , RpcServer(..), RpcConfig(..), RpcResponse(..), defaultRpcConfig
  , handleDecodeScript, handleDeriveAddresses, handleGetDescriptorInfo
  , handleValidateAddress
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

spec :: Spec
spec = do
  specP2AClassify
  specFollowUps

specP2AClassify :: Spec
specP2AClassify = describe "P2A script classification (gettxout drop, 2026-10-02)" $ do

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

-- | RPC display follow-ups from the P2A fix, pinned to Bitcoin Core v31.1
-- InferDescriptor (empty provider) and ScriptToAsmStr / GetOpName.
--
-- InferScript builds MultisigDescriptor with sorted=false even when the
-- pubkeys are lexicographically sorted (descriptor.cpp), so a
-- sortedmulti-shaped bare multisig is still multi(), and the decodescript
-- P2WSH wrap (inner script in the signing provider) is wsh(multi()).
-- Hybrid keys fail InferPubkey and stay raw(). 0xff is OP_INVALIDOPCODE;
-- every other unnamed opcode is OP_UNKNOWN with no numeric suffix.
-- Checksums are the BIP-380 values Core prints (verified against the
-- known addr/pk/multi/raw checksums from a regtest oracle).

pk1, pk2, pkRpc, pkUncomp :: T.Text
pk1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
pk2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
pkRpc = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2"
pkUncomp = "04b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb25e01fc8fde47c96c98a4f3a8123e33a38a50cf9025cc8c4494a518f991792bb7"

pkDesc, pkRpcDesc, pkUncompDesc :: T.Text
pkDesc = "pk(" <> pk1 <> ")#vwaefwnq"
pkRpcDesc = "pk(" <> pkRpc <> ")#h9zd5h4y"
pkUncompDesc = "pk(" <> pkUncomp <> ")#5u23hkue"

multiSortedDesc, multiUnsortedDesc, multiUncompDesc :: T.Text
multiSortedDesc = "multi(1," <> pk1 <> "," <> pk2 <> ")#ve902xrt"
multiUnsortedDesc = "multi(1," <> pk2 <> "," <> pk1 <> ")#krrhyz4f"
multiUncompDesc = "multi(1," <> pk1 <> "," <> pkUncomp <> ")#fuu5v7z2"

wshSortedDesc, wshUnsortedDesc :: T.Text
wshSortedDesc = "wsh(" <> T.takeWhile (/= '#') multiSortedDesc <> ")#8yt2huam"
wshUnsortedDesc = "wsh(" <> T.takeWhile (/= '#') multiUnsortedDesc <> ")#73cnnwta"

p2pkHex, p2pkRpcHex, p2pkUncompHex :: T.Text
p2pkHex = "21" <> pk1 <> "ac"
p2pkRpcHex = "21" <> pkRpc <> "ac"
p2pkUncompHex = "41" <> pkUncomp <> "ac"

multiSortedHex, multiUnsortedHex, multiUncompHex :: T.Text
multiSortedHex = "5121" <> pk1 <> "21" <> pk2 <> "52ae"
multiUnsortedHex = "5121" <> pk2 <> "21" <> pk1 <> "52ae"
multiUncompHex = "5121" <> pk1 <> "41" <> pkUncomp <> "52ae"

fromHex :: T.Text -> BS.ByteString
fromHex t = case B16.decode (TE.encodeUtf8 t) of
  Right bs -> bs
  Left err -> error ("fromHex: " ++ err)

-- | A 65-byte hybrid (0x06) key plus OP_CHECKSIG. InferPubkey rejects it.
hybridP2pk :: BS.ByteString
hybridP2pk = BS.pack (0x41 : 0x06 : replicate 64 0x00 ++ [0xac])

mustDesc :: KM.KeyMap Value -> T.Text -> IO ()
mustDesc o expected = do
  field o "desc" `shouldBe` Just (String expected)
  let csum = T.drop 1 (snd (T.breakOn "#" expected))
  T.length csum `shouldBe` 8
  addDescriptorChecksum (T.takeWhile (/= '#') expected) `shouldBe` Just expected

specFollowUps :: Spec
specFollowUps = describe "RPC follow-ups from the P2A fix" $ do

  it "InferDescriptor of compressed P2PK is pk()#vwaefwnq" $ do
    o <- spkObj (fromHex p2pkHex)
    field o "type" `shouldBe` Just (String "pubkey")
    field o "address" `shouldBe` Nothing
    field o "asm" `shouldBe` Just (String (pk1 <> " OP_CHECKSIG"))
    mustDesc o pkDesc

  it "InferDescriptor of rpc_decodescript compressed P2PK is pk()#h9zd5h4y" $ do
    o <- spkObj (fromHex p2pkRpcHex)
    field o "type" `shouldBe` Just (String "pubkey")
    mustDesc o pkRpcDesc

  it "InferDescriptor of uncompressed P2PK is pk()#5u23hkue" $ do
    o <- spkObj (fromHex p2pkUncompHex)
    field o "type" `shouldBe` Just (String "pubkey")
    field o "address" `shouldBe` Nothing
    mustDesc o pkUncompDesc

  it "InferDescriptor of a hybrid pubkey stays raw()" $ do
    o <- spkObj hybridP2pk
    field o "type" `shouldBe` Just (String "pubkey")
    let hex = TE.decodeUtf8 (B16.encode hybridP2pk)
        rawBody = "raw(" <> hex <> ")"
    case addDescriptorChecksum rawBody of
      Just expected -> mustDesc o expected
      Nothing -> expectationFailure "checksum rejected hybrid raw()"

  it "InferDescriptor of sorted-key bare multisig is multi()#ve902xrt, not sortedmulti()" $ do
    o <- spkObj (fromHex multiSortedHex)
    field o "type" `shouldBe` Just (String "multisig")
    field o "address" `shouldBe` Nothing
    field o "asm" `shouldBe` Just (String ("1 " <> pk1 <> " " <> pk2 <> " 2 OP_CHECKMULTISIG"))
    mustDesc o multiSortedDesc
    case field o "desc" of
      Just (String d) -> T.isInfixOf "sortedmulti" d `shouldBe` False
      other -> expectationFailure ("desc: " ++ show other)

  it "InferDescriptor of unsorted bare multisig keeps script order multi()#krrhyz4f" $ do
    o <- spkObj (fromHex multiUnsortedHex)
    field o "type" `shouldBe` Just (String "multisig")
    field o "asm" `shouldBe` Just (String ("1 " <> pk2 <> " " <> pk1 <> " 2 OP_CHECKMULTISIG"))
    mustDesc o multiUnsortedDesc

  it "InferDescriptor of bare multisig with an uncompressed key is multi()#fuu5v7z2" $ do
    o <- spkObj (fromHex multiUncompHex)
    field o "type" `shouldBe` Just (String "multisig")
    mustDesc o multiUncompDesc

  it "asm of unknown opcode 0xbb is OP_UNKNOWN" $ do
    a1 <- evaluate (scriptToAsm (BS.pack [0xbb]))
    a1 `shouldBe` "OP_UNKNOWN"
    a2 <- evaluate (scriptToAsmPartial (BS.pack [0xbb]))
    a2 `shouldBe` "OP_UNKNOWN"
    o <- spkObj (BS.pack [0xbb])
    field o "asm" `shouldBe` Just (String "OP_UNKNOWN")
    mustDesc o "raw(bb)#79gjzk4q"
    field o "type" `shouldBe` Just (String "nonstandard")

  it "asm of 0xbb then 0xbc is OP_UNKNOWN OP_UNKNOWN" $ do
    a <- evaluate (scriptToAsm (BS.pack [0xbb, 0xbc]))
    a `shouldBe` "OP_UNKNOWN OP_UNKNOWN"
    o <- spkObj (BS.pack [0xbb, 0xbc])
    field o "asm" `shouldBe` Just (String "OP_UNKNOWN OP_UNKNOWN")
    mustDesc o "raw(bbbc)#a0xxsjqh"

  it "asm of 0xba then 0xbb is OP_CHECKSIGADD OP_UNKNOWN" $ do
    a <- evaluate (scriptToAsm (BS.pack [0xba, 0xbb]))
    a `shouldBe` "OP_CHECKSIGADD OP_UNKNOWN"
    o <- spkObj (BS.pack [0xba, 0xbb])
    field o "asm" `shouldBe` Just (String "OP_CHECKSIGADD OP_UNKNOWN")
    mustDesc o "raw(babb)#7kj2lgwg"

  it "asm of 0xff is OP_INVALIDOPCODE" $ do
    a1 <- evaluate (scriptToAsm (BS.pack [0xff]))
    a1 `shouldBe` "OP_INVALIDOPCODE"
    a2 <- evaluate (scriptToAsmPartial (BS.pack [0xff]))
    a2 `shouldBe` "OP_INVALIDOPCODE"
    o <- spkObj (BS.pack [0xff])
    field o "asm" `shouldBe` Just (String "OP_INVALIDOPCODE")
    mustDesc o "raw(ff)#wuxj4tep"

  it "asm of disabled opcodes keeps Core names" $ do
    scriptToAsm (BS.pack [0x7e]) `shouldBe` "OP_CAT"
    scriptToAsm (BS.pack [0x95]) `shouldBe` "OP_MUL"
    scriptToAsm (BS.pack [0x8d]) `shouldBe` "OP_2MUL"
    scriptToAsm (BS.pack [0xb0]) `shouldBe` "OP_NOP1"
    scriptToAsmPartial (BS.pack [0x7e, 0x95]) `shouldBe` "OP_CAT OP_MUL"
    o <- spkObj (BS.pack [0x7e])
    field o "asm" `shouldBe` Just (String "OP_CAT")
    field o "type" `shouldBe` Just (String "nonstandard")
    mustDesc o "raw(7e)#cjmd47qx"

  it "asm of a truncated push after OP_CAT is OP_CAT [error]" $ do
    a <- evaluate (scriptToAsmPartial (BS.pack [0x7e, 0x01]))
    a `shouldBe` "OP_CAT [error]"

  it "wallet Address round-trips regtest and mainnet P2A" $ do
    textToAddress "bcrt1pfeesnyr2tx" `shouldSatisfy` isJust
    textToAddress "bc1pfeessrawgf" `shouldSatisfy` isJust
    case textToAddress "bcrt1pfeesnyr2tx" of
      Just a -> addressToTextW regtest a `shouldBe` "bcrt1pfeesnyr2tx"
      Nothing -> expectationFailure "textToAddress bcrt1pfeesnyr2tx"
    case textToAddress "bc1pfeessrawgf" of
      Just a -> addressToTextW mainnet a `shouldBe` "bc1pfeessrawgf"
      Nothing -> expectationFailure "textToAddress bc1pfeessrawgf"
    parseDescriptor "addr(bcrt1pfeesnyr2tx)#swxgse0y" `shouldSatisfy` isRight
    parseDescriptor "addr(bc1pfeessrawgf)#d6x2lh3c" `shouldSatisfy` isRight
    case parseDescriptor "addr(bcrt1pfeesnyr2tx)#swxgse0y" of
      Left err -> expectationFailure ("parseDescriptor P2A: " ++ show err)
      Right d -> do
        deriveScripts d 0 `shouldBe` [p2aSpk]
        map (addressToTextW regtest) (deriveAddresses d [])
          `shouldBe` ["bcrt1pfeesnyr2tx"]

  it "decodescript P2PK, bare multisig, P2A, and unknown opcodes" $
    withLiveServer $ \server -> do
      pkObj <- rpcObj =<< handleDecodeScript server (AE.toJSON [p2pkHex])
      field pkObj "type" `shouldBe` Just (String "pubkey")
      field pkObj "asm" `shouldBe` Just (String (pk1 <> " OP_CHECKSIG"))
      mustDesc pkObj pkDesc
      case field pkObj "segwit" of
        Just (Object so) -> do
          field so "type" `shouldBe` Just (String "witness_v0_keyhash")
          case field so "desc" of
            Just (String d) -> do
              T.isPrefixOf "addr(bcrt1q" d `shouldBe` True
              T.isInfixOf "wpkh(" d `shouldBe` False
              T.length (T.drop 1 (snd (T.breakOn "#" d))) `shouldBe` 8
            other -> expectationFailure ("P2PK segwit desc: " ++ show other)
        other -> expectationFailure ("P2PK segwit: " ++ show other)

      msObj <- rpcObj =<< handleDecodeScript server (AE.toJSON [multiSortedHex])
      field msObj "type" `shouldBe` Just (String "multisig")
      mustDesc msObj multiSortedDesc
      case field msObj "segwit" of
        Just (Object so) -> do
          field so "type" `shouldBe` Just (String "witness_v0_scripthash")
          field so "desc" `shouldBe` Just (String wshSortedDesc)
        other -> expectationFailure ("sorted multisig segwit: " ++ show other)

      usObj <- rpcObj =<< handleDecodeScript server (AE.toJSON [multiUnsortedHex])
      mustDesc usObj multiUnsortedDesc
      case field usObj "segwit" of
        Just (Object so) ->
          field so "desc" `shouldBe` Just (String wshUnsortedDesc)
        other -> expectationFailure ("unsorted multisig segwit: " ++ show other)

      ucObj <- rpcObj =<< handleDecodeScript server (AE.toJSON [multiUncompHex])
      mustDesc ucObj multiUncompDesc
      field ucObj "segwit" `shouldBe` Nothing

      p2aObj <- rpcObj =<< handleDecodeScript server (AE.toJSON ["51024e73" :: T.Text])
      field p2aObj "type" `shouldBe` Just (String "anchor")
      field p2aObj "address" `shouldBe` Just (String "bcrt1pfeesnyr2tx")
      field p2aObj "asm" `shouldBe` Just (String "1 29518")
      mustDesc p2aObj "addr(bcrt1pfeesnyr2tx)#swxgse0y"
      field p2aObj "segwit" `shouldBe` Nothing

      bbObj <- rpcObj =<< handleDecodeScript server (AE.toJSON ["bb" :: T.Text])
      field bbObj "asm" `shouldBe` Just (String "OP_UNKNOWN")
      catObj <- rpcObj =<< handleDecodeScript server (AE.toJSON ["7e01" :: T.Text])
      field catObj "asm" `shouldBe` Just (String "OP_CAT [error]")

  it "getdescriptorinfo of pk() and multi()" $
    withLiveServer $ \server -> do
      pkInfo <- rpcObj =<< handleGetDescriptorInfo server (AE.toJSON [pkDesc])
      field pkInfo "descriptor" `shouldBe` Just (String pkDesc)
      field pkInfo "checksum" `shouldBe` Just (String "vwaefwnq")
      field pkInfo "isrange" `shouldBe` Just (Bool False)
      field pkInfo "issolvable" `shouldBe` Just (Bool True)
      field pkInfo "hasprivatekeys" `shouldBe` Just (Bool False)

      msInfo <- rpcObj =<< handleGetDescriptorInfo server (AE.toJSON [multiSortedDesc])
      field msInfo "descriptor" `shouldBe` Just (String multiSortedDesc)
      field msInfo "checksum" `shouldBe` Just (String "ve902xrt")
      field msInfo "issolvable" `shouldBe` Just (Bool True)
      field msInfo "isrange" `shouldBe` Just (Bool False)

  it "getdescriptorinfo of addr(bcrt1pfeesnyr2tx)" $
    withLiveServer $ \server -> do
      info <- rpcObj =<< handleGetDescriptorInfo server
                (AE.toJSON ["addr(bcrt1pfeesnyr2tx)#swxgse0y" :: T.Text])
      field info "descriptor" `shouldBe` Just (String "addr(bcrt1pfeesnyr2tx)#swxgse0y")
      field info "checksum" `shouldBe` Just (String "swxgse0y")
      field info "issolvable" `shouldBe` Just (Bool False)
      field info "isrange" `shouldBe` Just (Bool False)
      field info "hasprivatekeys" `shouldBe` Just (Bool False)

  it "deriveaddresses of addr(bcrt1pfeesnyr2tx) is the anchor address" $
    withLiveServer $ \server -> do
      resp <- handleDeriveAddresses server
                (AE.toJSON ["addr(bcrt1pfeesnyr2tx)#swxgse0y" :: T.Text])
      v <- rpcValue resp
      v `shouldBe` AE.toJSON (["bcrt1pfeesnyr2tx"] :: [T.Text])

  it "validateaddress P2A is isscript+iswitness with no witness program" $
    withLiveServer $ \server -> do
      o <- rpcObj =<< handleValidateAddress server (AE.toJSON ["bcrt1pfeesnyr2tx" :: T.Text])
      field o "isvalid" `shouldBe` Just (Bool True)
      field o "address" `shouldBe` Just (String "bcrt1pfeesnyr2tx")
      field o "scriptPubKey" `shouldBe` Just (String "51024e73")
      field o "isscript" `shouldBe` Just (Bool True)
      field o "iswitness" `shouldBe` Just (Bool True)
      field o "witness_version" `shouldBe` Nothing
      field o "witness_program" `shouldBe` Nothing

rpcValue :: RpcResponse -> IO Value
rpcValue resp = case resError resp of
  Null -> return (unwrap (resResult resp))
  err  -> expectationFailure ("rpc error: " ++ show err) >> return Null
  where
    unwrap (String s) =
      let magic = "__RAWJSON__:"
          payload = if magic `T.isPrefixOf` s then T.drop (T.length magic) s else s
      in case decode (BL.fromStrict (TE.encodeUtf8 payload)) of
           Just v  -> v
           Nothing -> String s
    unwrap v = v

rpcObj :: RpcResponse -> IO (KM.KeyMap Value)
rpcObj resp = do
  v <- rpcValue resp
  case v of
    Object o -> return o
    other    -> expectationFailure ("expected object, got " ++ show other) >> return KM.empty

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-p2a-rpc-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg liveNoopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
            server = RpcServer
              { rsConfig = cfg, rsDB = db, rsHeaderChain = hc, rsPeerMgr = pm
              , rsMempool = mp, rsFeeEst = fe, rsUTXOCache = cache
              , rsNetwork = regtest, rsBlockStore = Nothing
              , rsThread = threadVar, rsMockTime = mockTimeVar
              , rsWalletMgr = Nothing, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
        action server

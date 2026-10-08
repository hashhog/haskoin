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
--
-- 2026-10-08 RPC follow-ups (QUEUES.md item 0): InferDescriptor of a P2PK /
-- bare multisig must emit pk()/multi() (and wsh(multi()) on the decodescript
-- P2WSH wrap), not raw(); asm of an unknown opcode is OP_UNKNOWN not
-- OP_UNKNOWN[n]; wallet Address must carry P2A so addr(bcrt1pfeesnyr2tx)
-- parses.  Oracle: throwaway Core -regtest, 2026-10-08.
module P2AScriptClassifySpec (spec) where

import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket, evaluate)
import Test.Hspec
import Data.Aeson (Value(..), decode, toJSON)
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import Data.Either (isRight)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import System.Directory (getTemporaryDirectory, removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Consensus (initHeaderChain, mainnet, regtest)
import Haskoin.Crypto (bech32Encode, bech32mEncode, textToAddress)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (defaultMempoolConfig, newMempool)
import Haskoin.Network
  ( Message
  , PeerManagerConfig(..)
  , defaultPeerManagerConfig
  , startPeerManager
  , stopPeerManager
  )
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcConfig(..)
  , RpcResponse(..)
  , RpcServer(..)
  , defaultRpcConfig
  , handleDecodeScript
  , handleGetDescriptorInfo
  , psbtSpkEnc
  , scriptToAddress
  , scriptToAsm
  , scriptToAsmPartial
  , scriptTypeToString
  , witnessV1PlusAddressToScript
  )
import Haskoin.Script (ScriptType(..), p2aWitnessProgram)
import Haskoin.Storage
  ( defaultDBConfig
  , defaultPruneConfig
  , newUTXOCache
  , withDB
  )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Types (Hash256(..))
import Haskoin.Wallet
  ( addressToTextW
  , deriveAddresses
  , deriveScripts
  , parseDescriptor
  )

p2aSpk :: BS.ByteString
p2aSpk = BS.pack [0x51, 0x02, 0x4e, 0x73]

-- Compressed pubkeys from T2R5Spec / createmultisig fixtures.  Core
-- InferDescriptor (empty provider) of the scripts below, captured from
-- bitcoin-core/build/bin/bitcoind -regtest on 2026-10-08:
--   pk(...)#vwaefwnq
--   multi(1,...)#ve902xrt
--   wsh(multi(1,...))#8yt2huam
pk1Hex, pk2Hex, p2pkHex, multiHex :: T.Text
pk1Hex = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
pk2Hex = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"
p2pkHex = "21" <> pk1Hex <> "ac"
multiHex = "51" <> "21" <> pk1Hex <> "21" <> pk2Hex <> "52ae"

fromHex :: T.Text -> BS.ByteString
fromHex t = case B16.decode (TE.encodeUtf8 t) of
  Right bs -> bs
  Left err -> error ("fromHex: " ++ err)

corePkDesc, coreMultiDesc, coreWshMultiDesc :: T.Text
corePkDesc = "pk(" <> pk1Hex <> ")#vwaefwnq"
coreMultiDesc =
  "multi(1," <> pk1Hex <> "," <> pk2Hex <> ")#ve902xrt"
coreWshMultiDesc =
  "wsh(multi(1," <> pk1Hex <> "," <> pk2Hex <> "))#8yt2huam"

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

decodeRaw :: Value -> Value
decodeRaw (String s) =
  let magic = "__RAWJSON__:"
      payload = if magic `T.isPrefixOf` s then T.drop (T.length magic) s else s
  in case decode (BL.fromStrict (TE.encodeUtf8 payload)) of
       Just v  -> v
       Nothing -> String s
decodeRaw v = v

resultObj :: RpcResponse -> IO (KM.KeyMap Value)
resultObj resp = case resError resp of
  Null -> case decodeRaw (resResult resp) of
    Object o -> return o
    other    -> expectationFailure ("expected object, got " ++ show other) >> return KM.empty
  other -> expectationFailure ("expected success, got error: " ++ show other) >> return KM.empty

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

-- | QUEUES.md item 0 control: decodescript / getdescriptorinfo vs Core for a
-- P2PK, a bare multisig, and a 0xba-containing script; plus the two display
-- follow-ups (OP_UNKNOWN, wallet Address P2A).
specFollowUps :: Spec
specFollowUps = describe "RPC follow-ups from the P2A fix" $ do

  it "psbtSpkEnc / InferDescriptor of P2PK is Core pk()#vwaefwnq, not raw()" $ do
    o <- spkObj (fromHex p2pkHex)
    field o "type" `shouldBe` Just (String "pubkey")
    field o "desc" `shouldBe` Just (String corePkDesc)
    field o "address" `shouldBe` Nothing

  it "psbtSpkEnc / InferDescriptor of bare 1-of-2 multisig is Core multi()#ve902xrt, not raw()" $ do
    o <- spkObj (fromHex multiHex)
    field o "type" `shouldBe` Just (String "multisig")
    field o "desc" `shouldBe` Just (String coreMultiDesc)
    field o "address" `shouldBe` Nothing

  it "asm of unknown opcode 0xbb is Core OP_UNKNOWN, not OP_UNKNOWN[187]" $ do
    a1 <- evaluate (scriptToAsm (BS.pack [0xbb]))
    a1 `shouldBe` "OP_UNKNOWN"
    a2 <- evaluate (scriptToAsmPartial (BS.pack [0xbb]))
    a2 `shouldBe` "OP_UNKNOWN"
    o <- spkObj (BS.pack [0xbb])
    field o "asm"  `shouldBe` Just (String "OP_UNKNOWN")
    field o "desc" `shouldBe` Just (String "raw(bb)#79gjzk4q")
    field o "type" `shouldBe` Just (String "nonstandard")

  it "asm of 0xba then 0xbb is Core 'OP_CHECKSIGADD OP_UNKNOWN'" $ do
    a <- evaluate (scriptToAsm (BS.pack [0xba, 0xbb]))
    a `shouldBe` "OP_CHECKSIGADD OP_UNKNOWN"
    o <- spkObj (BS.pack [0xba, 0xbb])
    field o "asm"  `shouldBe` Just (String "OP_CHECKSIGADD OP_UNKNOWN")
    field o "desc" `shouldBe` Just (String "raw(babb)#7kj2lgwg")

  it "asm of 0xff is Core OP_INVALIDOPCODE" $ do
    a <- evaluate (scriptToAsm (BS.pack [0xff]))
    a `shouldBe` "OP_INVALIDOPCODE"

  it "wallet Address parses P2A so addr(bcrt1pfeesnyr2tx) is a descriptor" $ do
    textToAddress "bcrt1pfeesnyr2tx" `shouldSatisfy` isJust
    textToAddress "bc1pfeessrawgf" `shouldSatisfy` isJust
    parseDescriptor "addr(bcrt1pfeesnyr2tx)#swxgse0y" `shouldSatisfy` isRight
    case parseDescriptor "addr(bcrt1pfeesnyr2tx)#swxgse0y" of
      Left err -> expectationFailure ("parseDescriptor P2A: " ++ show err)
      Right d  -> do
        map (addressToTextW regtest) (deriveAddresses d [0])
          `shouldBe` ["bcrt1pfeesnyr2tx"]
        deriveScripts d 0 `shouldBe` [p2aSpk]

  it "CONTROL: decodescript P2PK / bare multisig / 0xba vs Core (regtest RpcServer)" $
    withLiveServer $ \server -> do
      pkResp <- handleDecodeScript server (toJSON [p2pkHex])
      pkObj  <- resultObj pkResp
      field pkObj "desc" `shouldBe` Just (String corePkDesc)
      field pkObj "type" `shouldBe` Just (String "pubkey")
      field pkObj "asm"  `shouldBe` Just (String (pk1Hex <> " OP_CHECKSIG"))

      msResp <- handleDecodeScript server (toJSON [multiHex])
      msObj  <- resultObj msResp
      field msObj "desc" `shouldBe` Just (String coreMultiDesc)
      field msObj "type" `shouldBe` Just (String "multisig")
      case field msObj "segwit" of
        Just (Object so) ->
          field so "desc" `shouldBe` Just (String coreWshMultiDesc)
        other -> expectationFailure ("expected segwit object, got " ++ show other)

      baResp <- handleDecodeScript server (toJSON ["ba" :: T.Text])
      baObj  <- resultObj baResp
      field baObj "asm"  `shouldBe` Just (String "OP_CHECKSIGADD")
      field baObj "desc" `shouldBe` Just (String "raw(ba)#yy0eg44l")
      field baObj "type" `shouldBe` Just (String "nonstandard")

      bbResp <- handleDecodeScript server (toJSON ["bb" :: T.Text])
      bbObj  <- resultObj bbResp
      field bbObj "asm" `shouldBe` Just (String "OP_UNKNOWN")

  it "CONTROL: getdescriptorinfo of inferred pk()/multi() and addr(P2A) vs Core" $
    withLiveServer $ \server -> do
      pkInfo <- handleGetDescriptorInfo server (toJSON [corePkDesc])
      pkObj  <- resultObj pkInfo
      field pkObj "descriptor"     `shouldBe` Just (String corePkDesc)
      field pkObj "checksum"       `shouldBe` Just (String "vwaefwnq")
      field pkObj "issolvable"     `shouldBe` Just (Bool True)
      field pkObj "isrange"        `shouldBe` Just (Bool False)
      field pkObj "hasprivatekeys" `shouldBe` Just (Bool False)

      msInfo <- handleGetDescriptorInfo server (toJSON [coreMultiDesc])
      msObj  <- resultObj msInfo
      field msObj "descriptor" `shouldBe` Just (String coreMultiDesc)
      field msObj "checksum"   `shouldBe` Just (String "ve902xrt")
      field msObj "issolvable" `shouldBe` Just (Bool True)

      p2aInfo <- handleGetDescriptorInfo server
                   (toJSON ["addr(bcrt1pfeesnyr2tx)#swxgse0y" :: T.Text])
      p2aObj  <- resultObj p2aInfo
      field p2aObj "descriptor" `shouldBe` Just (String "addr(bcrt1pfeesnyr2tx)#swxgse0y")
      field p2aObj "checksum"   `shouldBe` Just (String "swxgse0y")
      field p2aObj "issolvable" `shouldBe` Just (Bool False)

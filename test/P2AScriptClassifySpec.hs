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

import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket, evaluate)
import Control.Monad (forM)
import Data.Maybe (catMaybes, fromMaybe)
import Test.Hspec
import Data.Aeson (Value(..), decode, toJSON)
import qualified Data.Aeson as AE
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import System.Directory (getTemporaryDirectory, removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Consensus (mainnet, regtest, initHeaderChain, Network(..))
import Haskoin.Crypto (bech32Encode, bech32mEncode, computeBlockHash)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (defaultMempoolConfig, newMempool)
import Haskoin.Network
  ( Message, PeerManagerConfig(..), defaultPeerManagerConfig
  , startPeerManager, stopPeerManager
  )
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Script (ScriptType(..), p2aWitnessProgram)
import Haskoin.Storage
  ( defaultDBConfig, defaultPruneConfig, newUTXOCache, putBlock, withDB )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Types (Block(..), Hash256(..))
import Haskoin.Rpc
  ( RpcConfig(..), RpcResponse(..), RpcServer(..), defaultRpcConfig
  , handleDecodeScript
  , handleGetDescriptorInfo
  , handleValidateAddress
  , psbtSpkEnc
  , scriptToAddress
  , scriptToAsm
  , scriptToAsmPartial
  , scriptTypeToString
  , witnessV1PlusAddressToScript
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
  p2aClassify
  rpcDescAsm

p2aClassify :: Spec
p2aClassify = describe "P2A script classification (gettxout drop, 2026-10-02)" $ do

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

-- | decodescript / getdescriptorinfo / validateaddress vs a regtest Core
-- (bitcoin-core/build bitcoind, 2026-10-04, cookie RPC on 127.0.0.1:18443).
-- Pubkey G is BIP-340's generator point; pk2 is a second compressed key.
-- These are display-only: descriptor inference (pk/multi/wsh), P2A as an
-- address inside addr(), and GetOpName (bare OP_UNKNOWN, OP_INVALIDOPCODE).
gPk :: T.Text
gPk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

pk2 :: T.Text
pk2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

rpcDescAsm :: Spec
rpcDescAsm = describe "rpc-desc-asm" $
  it "decodescript / getdescriptorinfo match regtest Core (P2PK, bare multisig, 0xba)" $
    withLiveServer $ \srv -> do
      let dec hex = handleDecodeScript srv (toJSON [hex :: T.Text])
          gdi d   = handleGetDescriptorInfo srv (toJSON [d :: T.Text])
          vad a   = handleValidateAddress srv (toJSON [a :: T.Text])
          cases =
            [ ("decodescript P2PK", dec ("21" <> gPk <> "ac"), p2pkJson)
            , ("decodescript bare multisig", dec ("5121" <> gPk <> "21" <> pk2 <> "52ae"), multiJson)
            , ("decodescript babb", dec "babb", babbJson)
            , ("decodescript ba4c", dec "ba4c", ba4cJson)
            , ("decodescript ff", dec "ff", ffJson)
            , ("decodescript hybrid P2PK (stays raw)", dec hybridHex, hybridJson)
            , ("decodescript P2PKH (stays addr)", dec p2pkhHex, p2pkhJson)
            , ("decodescript OP_RETURN", dec "6a", opReturnJson)
            , ("getdescriptorinfo pk", gdi ("pk(" <> gPk <> ")#gn28ywm7"), gdiPkJson)
            , ("getdescriptorinfo multi", gdi ("multi(1," <> gPk <> "," <> pk2 <> ")#l5sy3u48"), gdiMultiJson)
            , ("getdescriptorinfo wsh(multi)", gdi ("wsh(multi(1," <> gPk <> "," <> pk2 <> "))#25mv9evd"), gdiWshJson)
            , ("getdescriptorinfo raw(babb)", gdi "raw(babb)#7kj2lgwg", gdiRawJson)
            , ("getdescriptorinfo addr(P2A)", gdi "addr(bcrt1pfeesnyr2tx)", gdiP2AJson)
            , ("validateaddress P2A", vad "bcrt1pfeesnyr2tx", validateP2AJson)
            ]
      misses <- fmap catMaybes $ forM cases $ \(name, action, expected) -> do
        resp <- action
        gotE <- resultValue resp
        let wantE = decode (BL.fromStrict (TE.encodeUtf8 expected)) :: Maybe Value
        return $ case (wantE, gotE) of
          (Just w, Right g) | w == g -> Nothing
          (Just w, Right g) ->
            Just (name ++ "\n  want " ++ json w ++ "\n  got  " ++ json g)
          (_, Left err) -> Just (name ++ "\n  " ++ err)
          (Nothing, _) -> Just (name ++ "\n  test bug: expected JSON did not parse")
      misses `shouldBe` ([] :: [String])
  where
    json v = T.unpack (TE.decodeUtf8 (BL.toStrict (AE.encode v)))

-- 65-byte hybrid key (header 0x06): Core keeps type=pubkey but desc=raw().
hybridHex :: T.Text
hybridHex =
  "41" <> "06" <> T.replicate 32 "11" <> T.replicate 32 "22" <> "ac"

p2pkhHex :: T.Text
p2pkhHex = "76a914" <> T.replicate 20 "00" <> "88ac"

p2pkJson :: T.Text
p2pkJson = "{\"asm\":\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 OP_CHECKSIG\",\"desc\":\"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7\",\"type\":\"pubkey\",\"p2sh\":\"2MvVwHhgE2JyjkjQk72CghrhrJsanKfHfqe\",\"segwit\":{\"asm\":\"0 751e76e8199196d454941c45d1b3a323f1433bd6\",\"desc\":\"addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)#8pk5s7ya\",\"hex\":\"0014751e76e8199196d454941c45d1b3a323f1433bd6\",\"address\":\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\",\"type\":\"witness_v0_keyhash\",\"p2sh-segwit\":\"2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN\"}}"

multiJson :: T.Text
multiJson = "{\"asm\":\"1 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 2 OP_CHECKMULTISIG\",\"desc\":\"multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#l5sy3u48\",\"type\":\"multisig\",\"p2sh\":\"2MzDSaqMcnds82ggLGjXLxhtHBL52nhBmWC\",\"segwit\":{\"asm\":\"0 6eb3ac1f460d34871c2b21e1ce02f0c056bcf558a6d4942052b1856a4fe54f6d\",\"desc\":\"wsh(multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))#25mv9evd\",\"hex\":\"00206eb3ac1f460d34871c2b21e1ce02f0c056bcf558a6d4942052b1856a4fe54f6d\",\"address\":\"bcrt1qd6e6c86xp56gw8pty8suuqhscpttea2c5m2fggzjkxzk5nl9faksws97ff\",\"type\":\"witness_v0_scripthash\",\"p2sh-segwit\":\"2NA17ckxnzsXvQsECnEwjtf2MhRo1s8tPB5\"}}"

babbJson :: T.Text
babbJson = "{\"asm\":\"OP_CHECKSIGADD OP_UNKNOWN\",\"desc\":\"raw(babb)#7kj2lgwg\",\"type\":\"nonstandard\"}"

ba4cJson :: T.Text
ba4cJson = "{\"asm\":\"OP_CHECKSIGADD [error]\",\"desc\":\"raw(ba4c)#xvatkhsu\",\"type\":\"nonstandard\"}"

ffJson :: T.Text
ffJson = "{\"asm\":\"OP_INVALIDOPCODE\",\"desc\":\"raw(ff)#wuxj4tep\",\"type\":\"nonstandard\"}"

hybridJson :: T.Text
hybridJson = "{\"asm\":\"0611111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222 OP_CHECKSIG\",\"desc\":\"raw(410611111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222ac)#xs54l0wv\",\"type\":\"pubkey\",\"p2sh\":\"2Mwes5aV8LWLrstpSaUxJsoAa8dFC3xfPXA\"}"

p2pkhJson :: T.Text
p2pkhJson = "{\"asm\":\"OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG\",\"desc\":\"addr(mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8)#ydtjlapp\",\"address\":\"mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8\",\"type\":\"pubkeyhash\",\"p2sh\":\"2NGFrZmcc9pRLpL1veuDercvpTQHhicwg5r\",\"segwit\":{\"asm\":\"0 0000000000000000000000000000000000000000\",\"desc\":\"addr(bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202)#v0fp9yyh\",\"hex\":\"00140000000000000000000000000000000000000000\",\"address\":\"bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202\",\"type\":\"witness_v0_keyhash\",\"p2sh-segwit\":\"2N2hprXZBLaHMseLgR7zdBWg14FNCxM6UzZ\"}}"

opReturnJson :: T.Text
opReturnJson = "{\"asm\":\"OP_RETURN\",\"desc\":\"raw(6a)#4mhr9ur5\",\"type\":\"nulldata\"}"

gdiPkJson :: T.Text
gdiPkJson = "{\"descriptor\":\"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#gn28ywm7\",\"checksum\":\"gn28ywm7\",\"isrange\":false,\"issolvable\":true,\"hasprivatekeys\":false}"

gdiMultiJson :: T.Text
gdiMultiJson = "{\"descriptor\":\"multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#l5sy3u48\",\"checksum\":\"l5sy3u48\",\"isrange\":false,\"issolvable\":true,\"hasprivatekeys\":false}"

gdiWshJson :: T.Text
gdiWshJson = "{\"descriptor\":\"wsh(multi(1,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))#25mv9evd\",\"checksum\":\"25mv9evd\",\"isrange\":false,\"issolvable\":true,\"hasprivatekeys\":false}"

gdiRawJson :: T.Text
gdiRawJson = "{\"descriptor\":\"raw(babb)#7kj2lgwg\",\"checksum\":\"7kj2lgwg\",\"isrange\":false,\"issolvable\":false,\"hasprivatekeys\":false}"

gdiP2AJson :: T.Text
gdiP2AJson = "{\"descriptor\":\"addr(bcrt1pfeesnyr2tx)#swxgse0y\",\"checksum\":\"swxgse0y\",\"isrange\":false,\"issolvable\":false,\"hasprivatekeys\":false}"

validateP2AJson :: T.Text
validateP2AJson = "{\"isvalid\":true,\"address\":\"bcrt1pfeesnyr2tx\",\"scriptPubKey\":\"51024e73\",\"isscript\":true,\"iswitness\":true}"

resultValue :: RpcResponse -> IO (Either String Value)
resultValue resp = case (resError resp, resResult resp) of
  (Null, String s) ->
    let t = fromMaybe s (T.stripPrefix "__RAWJSON__:" s)
    in case decode (BL.fromStrict (TE.encodeUtf8 t)) of
         Just v  -> return (Right v)
         Nothing -> return (Left ("undecodable result: " ++ T.unpack t))
  (Null, v) -> return (Right v)
  (e, _)    -> return (Left ("RPC error: " ++ show e))

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

-- | regtest RpcServer. decodescript / getdescriptorinfo only read rsNetwork,
-- but every RpcServer field is strict, so the unused pieces are real (and
-- inert: listen port 0, DNS seed off).
withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-rpc-desc-asm-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let gen = netGenesisBlock regtest
      putBlock db (computeBlockHash (blockHeader gen)) gen
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

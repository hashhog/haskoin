{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | T2 R5 probe parity vs live Bitcoin Core (tools/r5-probes.d).
--
-- CONTROL: @cabal run haskoin-test -- -m t2_r5@
--
-- Encodes the T2 FAILs from the 2026-09-01 r5_probe sweep
-- (tools/diff-test-artifacts/r5-probe/20260901T182642Z.json haskoin T2 18/41).
module T2R5Spec (spec) where

import Test.Hspec
import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket)
import Data.Aeson (Value(..), toJSON, decode, object)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import Data.Scientific (toBoundedInteger)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import System.Directory (removeDirectoryRecursive, getTemporaryDirectory)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Consensus
  ( regtest, initHeaderChain )
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..)
  )
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Rpc
  ( RpcResponse(..), RpcServer(..), RpcConfig(..), defaultRpcConfig
  , rpcInvalidParameter, rpcTypeError, rpcInvalidAddressOrKey
  , rpcDeserializationError, rpcMiscError, rpcVerifyError
  , handleDecodeRawTransaction
  , handleValidateAddress
  , handleGetDeploymentInfo
  , handleVerifyTxOutProof
  , handleGetTxSpendingPrevout
  , handleImportMempool
  , handleScanTxOutSet
  , handleDecodeScript
  , handleCombinePsbt
  , handleSubmitPackage
  , handleCreateMultisig
  , handleDeriveAddresses
  , handleGetDescriptorInfo
  , handleGetIndexInfo
  , handleSignMessage
  , handleCombineRawTransaction
  , handleGetChainTxStats
  , handleCreatePsbt
  , handleJoinPsbts
  , handlePruneBlockchain
  , handleUtxoUpdatePsbt
  , handleDescriptorProcessPsbt
  )

noServer :: a
noServer = error "RpcServer must not be touched by this probe"

errorOf :: RpcResponse -> IO (Int, T.Text)
errorOf resp = case resError resp of
  Object o ->
    let code = case KM.lookup "code" o of
          Just (Number n) -> maybe minBound id (toBoundedInteger n :: Maybe Int)
          _               -> minBound
        msg = case KM.lookup "message" o of
          Just (String t) -> t
          _               -> "<absent>"
    in return (code, msg)
  Null -> expectationFailure
            ("expected an error, got result: " ++ show (resResult resp))
            >> return (0, "")
  other -> expectationFailure ("unexpected error shape: " ++ show other)
            >> return (0, "")

resultOf :: RpcResponse -> IO Value
resultOf resp = case resError resp of
  Null -> return (resResult resp)
  other -> expectationFailure ("expected success, got error: " ++ show other)
            >> return Null

decodeRaw :: Value -> Value
decodeRaw (String s) =
  let magic = "__RAWJSON__:"
      payload = if magic `T.isPrefixOf` s then T.drop (T.length magic) s else s
  in case decode (BL.fromStrict (TE.encodeUtf8 payload)) of
       Just v  -> v
       Nothing -> String s
decodeRaw v = v

-- Canonical R5 fixtures (tools/r5-probes.d).
psbtA :: T.Text
psbtA = "cHNidP8BAFICAAAAAaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAD9////AaCGAQAAAAAAFgAUdR526BmRltRUlBxF0bOjI/FDO9YAAAAAAAAA"

psbtB :: T.Text
psbtB = "cHNidP8BACkCAAAAAAGghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAAAA"

rawHex :: T.Text
rawHex = "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000fdffffff01a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000"

coreSig :: T.Text
coreSig = "HANWTfmfhMdsuje52nPqOD/Q4QXfl6q188p2LpAG4ICJONIllahpDidMpe8n2TWE+VV2kR2cHd3gAv6n+jtRWV0="

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-t2r5-")
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

spec :: Spec
spec = describe "t2_r5" $ do

  describe "decoderawtransaction" $ do
    it "nonhex is -22 TX decode failed" $ do
      resp <- handleDecodeRawTransaction noServer (toJSON ["zz" :: T.Text])
      errorOf resp >>= (`shouldBe` (rpcDeserializationError, "TX decode failed"))

  describe "validateaddress" $ do
    it "exact-invalid matches Core DecodeDestination checksum/length" $ do
      resp <- handleValidateAddress noServer (toJSON ["notanaddress" :: T.Text])
      v <- decodeRaw <$> resultOf resp
      case v of
        Object o -> do
          KM.lookup "isvalid" o `shouldBe` Just (Bool False)
          KM.lookup "error" o `shouldBe`
            Just (String "Invalid checksum or length of Base58 address (P2PKH or P2SH)")
        _ -> expectationFailure ("expected object, got " ++ show v)

  describe "decodescript" $ do
    it "nonhex is -8 ParseHexV" $ do
      resp <- handleDecodeScript noServer (toJSON ["zz" :: T.Text])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcInvalidParameter
      msg `shouldBe` "argument must be hexadecimal string (not 'zz')"

  describe "verifytxoutproof" $ do
    it "nonhex is -8 ParseHexV" $ do
      resp <- handleVerifyTxOutProof noServer (toJSON ["zz" :: T.Text])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcInvalidParameter
      msg `shouldBe` "proof must be hexadecimal string (not 'zz')"

  describe "gettxspendingprevout" $ do
    it "missing vout is -3 type error" $ do
      resp <- handleGetTxSpendingPrevout noServer
                (toJSON [[object [("txid", String (T.replicate 64 "0"))]]])
      (code, _) <- errorOf resp
      code `shouldBe` rpcTypeError

  describe "pruneblockchain" $ do
    it "string height is -3 before the prune-mode gate" $ do
      resp <- handlePruneBlockchain noServer (toJSON ["zz" :: T.Text])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcTypeError
      msg `shouldBe` "JSON value of type string is not of expected type number"

  describe "getindexinfo" $ do
    it "numeric arg is -3" $ do
      resp <- handleGetIndexInfo noServer (toJSON [123 :: Int])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcTypeError
      msg `shouldBe` "JSON value of type number is not of expected type string"

  describe "scantxoutset" $ do
    it "bogus action is -8" $ do
      resp <- handleScanTxOutSet noServer (toJSON ["bogus" :: T.Text])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcInvalidParameter
      msg `shouldBe` "Invalid action 'bogus'"

  describe "submitpackage" $ do
    it "empty array is -8" $ do
      resp <- handleSubmitPackage noServer (toJSON [[] :: [T.Text]])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcInvalidParameter
      T.isPrefixOf "Array must contain between 1 and" msg `shouldBe` True

  describe "combinepsbt" $ do
    it "empty array is -8" $ do
      resp <- handleCombinePsbt noServer (toJSON [[] :: [T.Text]])
      errorOf resp >>= (`shouldBe`
        (rpcInvalidParameter, "Parameter 'txs' cannot be empty"))

  describe "createmultisig" $ do
    it "invalid pubkey is -5 HexToPubKey" $ do
      resp <- handleCreateMultisig
                (toJSON [Number 1, toJSON ["deadbeef" :: T.Text]])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcInvalidAddressOrKey
      T.isInfixOf "33 or 65 bytes" msg `shouldBe` True
    it "not-enough-keys is -8" $ do
      let k1 = "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd" :: T.Text
          k2 = "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626" :: T.Text
      resp <- handleCreateMultisig (toJSON [Number 3, toJSON [k1, k2]])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcInvalidParameter
      T.isInfixOf "not enough keys supplied" msg `shouldBe` True

  describe "deriveaddresses" $ do
    it "missing checksum is -5" $ do
      resp <- handleDeriveAddresses noServer
                (toJSON ["wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)" :: T.Text])
      errorOf resp >>= (`shouldBe` (rpcInvalidAddressOrKey, "Missing checksum"))
    it "range on unranged is -8" $ do
      resp <- handleDeriveAddresses noServer
                (toJSON [ String "wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#e72f49hy"
                        , toJSON [0 :: Int, 2 :: Int]
                        ])
      errorOf resp >>= (`shouldBe`
        (rpcInvalidParameter, "Range should not be specified for an un-ranged descriptor"))

  describe "getdescriptorinfo" $ do
    it "invalid descriptor is -5" $ do
      resp <- handleGetDescriptorInfo noServer (toJSON ["notadescriptor" :: T.Text])
      (code, _) <- errorOf resp
      code `shouldBe` rpcInvalidAddressOrKey
    it "bad checksum is -5" $ do
      resp <- handleGetDescriptorInfo noServer
                (toJSON ["wpkh(03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd)#00000000" :: T.Text])
      (code, _) <- errorOf resp
      code `shouldBe` rpcInvalidAddressOrKey

  describe "createpsbt" $ do
    it "canonical-exact matches Core ConstructTransaction PSBT" $ do
      let inputs  = [object [("txid", String (T.replicate 64 "a")), ("vout", Number 0)]]
          outputs = object [("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Number 0.001)]
      resp <- handleCreatePsbt noServer (toJSON [toJSON inputs, outputs])
      r <- resultOf resp
      r `shouldBe` String psbtA
    it "bad-txid is -8" $ do
      let inputs  = [object [("txid", String "zz"), ("vout", Number 0)]]
          outputs = object [("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Number 0.001)]
      resp <- handleCreatePsbt noServer (toJSON [toJSON inputs, outputs])
      (code, _) <- errorOf resp
      code `shouldBe` rpcInvalidParameter

  describe "joinpsbts" $ do
    it "join-exact of 1-in + 0-in (identical output) succeeds" $ do
      resp <- handleJoinPsbts noServer (toJSON [[psbtA, psbtB]])
      r <- resultOf resp
      case r of
        String s -> T.isPrefixOf "cHNidP8" s `shouldBe` True
        _ -> expectationFailure ("expected base64 string, got " ++ show r)

  describe "signmessagewithprivkey" $ do
    it "success-exact-sig matches Core RFC6979 compact header" $ do
      resp <- handleSignMessage noServer
                (toJSON [ "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ" :: T.Text
                        , "hashhog r5 probe" :: T.Text
                        ])
      resultOf resp >>= (`shouldBe` String coreSig)

  describe "importmempool" $ do
    it "missing file is -1" $ do
      resp <- handleImportMempool noServer
                (toJSON ["/nonexistent/r5-probe-no-such-file.dat" :: T.Text])
      (code, msg) <- errorOf resp
      code `shouldBe` rpcMiscError
      msg `shouldBe` "Unable to import mempool file, see debug log for details."

  describe "utxoupdatepsbt" $ do
    it "bad-base64 is -22" $ do
      resp <- handleUtxoUpdatePsbt noServer (toJSON ["notbase64!!" :: T.Text])
      (code, _) <- errorOf resp
      code `shouldBe` rpcDeserializationError
    it "unknown-inputs passthrough is a PSBT string" $
      withLiveServer $ \server -> do
        resp <- handleUtxoUpdatePsbt server (toJSON [psbtA])
        r <- resultOf resp
        case r of
          String s -> T.isPrefixOf "cHNidP8" s `shouldBe` True
          _ -> expectationFailure ("expected PSBT string, got " ++ show r)

  describe "descriptorprocesspsbt" $ do
    it "bad-descriptor is -5" $ do
      resp <- handleDescriptorProcessPsbt noServer
                (toJSON [toJSON psbtA, toJSON ["nonsense(desc)" :: T.Text]])
      (code, _) <- errorOf resp
      code `shouldBe` rpcInvalidAddressOrKey
    it "update of unknown-input PSBT returns complete=false" $
      withLiveServer $ \server -> do
        let desc = "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)" :: T.Text
        resp <- handleDescriptorProcessPsbt server (toJSON [toJSON psbtA, toJSON [desc]])
        v <- decodeRaw <$> resultOf resp
        case v of
          Object o -> KM.lookup "complete" o `shouldBe` Just (Bool False)
          _ -> expectationFailure ("expected object, got " ++ show v)

  describe "combinerawtransaction" $ do
    it "unknown-input is -25" $
      withLiveServer $ \server -> do
        resp <- handleCombineRawTransaction server
                  (toJSON [[rawHex, rawHex]])
        errorOf resp >>= (`shouldBe`
          (rpcVerifyError, "Input not found or already spent"))

  describe "getdeploymentinfo" $ do
    it "notfound is -5" $
      withLiveServer $ \server -> do
        resp <- handleGetDeploymentInfo server
                  (toJSON [T.replicate 63 "0" <> "1"])
        errorOf resp >>= (`shouldBe` (rpcInvalidAddressOrKey, "Block not found"))

  describe "getchaintxstats" $ do
    it "bad-blockcount is -8" $
      withLiveServer $ \server -> do
        resp <- handleGetChainTxStats server (toJSON [-1 :: Int])
        (code, _) <- errorOf resp
        code `shouldBe` rpcInvalidParameter
    it "no-arg on a genesis chain returns without walking the body store" $
      withLiveServer $ \server -> do
        resp <- handleGetChainTxStats server (toJSON ([] :: [Value]))
        v <- decodeRaw <$> resultOf resp
        case v of
          Object o -> do
            KM.lookup "window_block_count" o `shouldNotBe` Nothing
            KM.lookup "window_final_block_hash" o `shouldNotBe` Nothing
          _ -> expectationFailure ("expected object, got " ++ show v)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | R5 error-code parity pins for the T1/T2 methods the 2026-09-28 live
-- R5 probe failed (tools/diff-test-artifacts/r5-probe/*noproxy-0928*.json,
-- impls.haskoin.rows).  Every expected (code, message) below was captured
-- from a regtest bitcoind built from bitcoin-core/ (v31.99), not inferred.
--
--   getmempoolentry  <absent txid>          -5  "Transaction not in mempool"   (was -1)
--   getblockstats    <blk> ["bogusstat"]    -8  "Invalid selected statistic 'bogusstat'"
--   addnode          <node> "notacommand"   -1  <addnode help text>            (was -32602)
--   getnettotals     .uploadtarget          {timeframe 86400, target 0, ...}   (was absent)
--   getnetworkhashps "foo"                  -3  "Wrong type passed: ..."       (was success)
--
-- plus the siblings that made the same mistakes (mempool ancestors /
-- descendants malformed txid -32602 -> -8; wrong-typed args answered or
-- mis-coded instead of Core's RPCHelpMan -3).
--
-- 'noServer' is bottom: a case that passes it proves the rejection happens
-- in argument validation, before any node state is consulted (Core's
-- RPCHelpMan type check runs before the method body).
module R5ErrCodeParitySpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket)
import Data.Aeson (Value(..), toJSON, decode)
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

import Haskoin.Consensus (regtest, initHeaderChain, Network(..))
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Types (Block(..))
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..)
  )
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, putBlock )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Rpc
  ( RpcResponse(..), RpcServer(..), RpcConfig(..), defaultRpcConfig
  , handleGetMempoolEntry, handleGetMempoolAncestors, handleGetMempoolDescendants
  , handleGetBlockStats, handleAddNode, addnodeHelpText
  , handleGetNetTotals, handleGetNetworkHashPS
  )

noServer :: a
noServer = error "RpcServer must not be touched by argument validation"

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

-- | The raw-JSON result text (handlers that stream an ordered Encoding wrap
-- it in the __RAWJSON__ magic), so key ORDER can be asserted.
rawResultText :: RpcResponse -> IO T.Text
rawResultText resp = case (resError resp, resResult resp) of
  (Null, String s) -> return (maybe s id (T.stripPrefix "__RAWJSON__:" s))
  (Null, v)        -> return (TE.decodeUtf8 (BL.toStrict (encodeV v)))
  (e, _)           -> expectationFailure ("expected success, got " ++ show e)
                        >> return ""
  where encodeV = BL.fromStrict . TE.encodeUtf8 . T.pack . show

resultValue :: RpcResponse -> IO Value
resultValue resp = do
  t <- rawResultText resp
  case decode (BL.fromStrict (TE.encodeUtf8 t)) of
    Just v  -> return v
    Nothing -> expectationFailure ("undecodable result: " ++ T.unpack t) >> return Null

absentTxid :: T.Text
absentTxid = T.replicate 63 "0" <> "1"

-- | Core's RPCHelpMan type-error text for one mismatching position.
wrongType :: Int -> T.Text -> T.Text -> T.Text -> T.Text
wrongType pos name got want =
  "Wrong type passed:\n{\n    \"Position " <> T.pack (show pos) <> " (" <> name
  <> ")\": \"JSON value of type " <> got <> " is not of expected type " <> want
  <> "\"\n}"

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-r5errcode-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      -- The regtest genesis block body, so getblockstats can reach its stats.
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

spec :: Spec
spec = describe "r5_errcode" $ do

  describe "r5_errcode getmempoolentry" $ do
    it "a well-formed txid not in the pool is -5, not -1" $ withLiveServer $ \srv -> do
      resp <- handleGetMempoolEntry srv (toJSON [absentTxid])
      errorOf resp >>= (`shouldBe` (-5, "Transaction not in mempool"))
    it "CONTROL: a malformed txid is still -8 ParseHashV" $ withLiveServer $ \srv -> do
      resp <- handleGetMempoolEntry srv (toJSON ["zz" :: T.Text])
      errorOf resp >>= (`shouldBe` (-8, "txid must be of length 64 (not 2, for 'zz')"))
    it "a numeric txid is Core's RPCHelpMan -3" $ do
      resp <- handleGetMempoolEntry noServer (toJSON [1 :: Int])
      errorOf resp >>= (`shouldBe` (-3, wrongType 1 "txid" "number" "string"))

  describe "r5_errcode getmempoolancestors/descendants" $ do
    let both = [ ("ancestors",   handleGetMempoolAncestors)
               , ("descendants", handleGetMempoolDescendants) ]
    mapM_ (\(nm, h) -> do
      it (nm ++ ": a malformed txid is -8 ParseHashV, not -32602") $
        withLiveServer $ \srv -> do
          resp <- h srv (toJSON ["zz" :: T.Text])
          errorOf resp >>= (`shouldBe` (-8, "txid must be of length 64 (not 2, for 'zz')"))
      it (nm ++ ": CONTROL: an absent txid stays -5") $ withLiveServer $ \srv -> do
        resp <- h srv (toJSON [absentTxid])
        errorOf resp >>= (`shouldBe` (-5, "Transaction not in mempool"))
      it (nm ++ ": a non-bool verbose is -3") $ do
        resp <- h noServer (toJSON [String absentTxid, String "x"])
        errorOf resp >>= (`shouldBe` (-3, wrongType 2 "verbose" "string" "bool"))
      ) both

  describe "r5_errcode getblockstats" $ do
    it "an unknown stat name is -8 Invalid selected statistic" $ withLiveServer $ \srv -> do
      resp <- handleGetBlockStats srv (toJSON [toJSON (0 :: Int), toJSON ["bogusstat" :: T.Text]])
      errorOf resp >>= (`shouldBe` (-8, "Invalid selected statistic 'bogusstat'"))
    it "CONTROL: a known stat name answers (the -8 is not a blanket reject)" $
      withLiveServer $ \srv -> do
        resp <- handleGetBlockStats srv (toJSON [toJSON (0 :: Int), toJSON ["height" :: T.Text]])
        v <- resultValue resp
        v `shouldBe` Object (KM.fromList [("height", Number 0)])
    it "a non-array stats is -3 before anything else" $ do
      resp <- handleGetBlockStats noServer (toJSON [toJSON (0 :: Int), String "x"])
      errorOf resp >>= (`shouldBe` (-3, wrongType 2 "stats" "string" "array"))
    it "a non-string stat element is -3 get_str" $ withLiveServer $ \srv -> do
      resp <- handleGetBlockStats srv (toJSON [toJSON (0 :: Int), toJSON [1 :: Int]])
      errorOf resp >>= (`shouldBe`
        (-3, "JSON value of type number is not of expected type string"))

  describe "r5_errcode addnode" $ do
    it "an unknown command is -1 with Core's help text, not -32602" $ do
      resp <- handleAddNode noServer (toJSON ["192.0.2.1:8333", "notacommand" :: T.Text])
      (code, msg) <- errorOf resp
      code `shouldBe` (-1)
      msg `shouldBe` addnodeHelpText
      -- Pin the constant itself against Core's text (captured from bitcoind).
      T.take 110 msg `shouldBe`
        "addnode \"node\" \"command\" ( v2transport )\n\nAttempts to add or remove a node from the addnode list.\nOr try a con"
      T.length msg `shouldBe` 1180
    it "a numeric node is Core's RPCHelpMan -3" $ do
      resp <- handleAddNode noServer (toJSON [toJSON (1 :: Int), String "add"])
      errorOf resp >>= (`shouldBe` (-3, wrongType 1 "node" "number" "string"))
    it "a non-bool v2transport is -3" $ do
      resp <- handleAddNode noServer (toJSON [String "192.0.2.1", String "add", toJSON (1 :: Int)])
      errorOf resp >>= (`shouldBe` (-3, wrongType 3 "v2transport" "number" "bool"))

  describe "r5_errcode getnettotals" $ do
    it "carries Core's uploadtarget object, in Core's key order" $ do
      resp <- handleGetNetTotals noServer
      t <- rawResultText resp
      let keyPos k = T.length (fst (T.breakOn ("\"" <> k <> "\"") t))
          order = [ "totalbytesrecv", "totalbytessent", "timemillis", "uploadtarget"
                  , "timeframe", "target", "target_reached", "serve_historical_blocks"
                  , "bytes_left_in_cycle", "time_left_in_cycle" ]
          ps = map keyPos order
      all (< T.length t) ps `shouldBe` True
      and (zipWith (<) ps (drop 1 ps)) `shouldBe` True
      v <- resultValue resp
      case v of
        Object o -> KM.lookup "uploadtarget" o `shouldBe` Just (Object (KM.fromList
          [ ("timeframe", Number 86400), ("target", Number 0)
          , ("target_reached", Bool False), ("serve_historical_blocks", Bool True)
          , ("bytes_left_in_cycle", Number 0), ("time_left_in_cycle", Number 0) ]))
        _ -> expectationFailure ("expected object, got " ++ show v)

  describe "r5_errcode getnetworkhashps" $ do
    it "a string nblocks is -3, not a silent default" $ do
      resp <- handleGetNetworkHashPS noServer (toJSON ["foo" :: T.Text])
      errorOf resp >>= (`shouldBe` (-3, wrongType 1 "nblocks" "string" "number"))
    it "two wrong-typed args are reported together, as Core does" $ do
      resp <- handleGetNetworkHashPS noServer (toJSON ["a", "b" :: T.Text])
      errorOf resp >>= (`shouldBe` (-3,
        "Wrong type passed:\n{\n    \"Position 1 (nblocks)\": \"JSON value of type string is not of expected type number\",\n    \"Position 2 (height)\": \"JSON value of type string is not of expected type number\"\n}"))
    it "nblocks 0 and < -1 are -8" $
      mapM_ (\n -> do
        resp <- handleGetNetworkHashPS noServer (toJSON [n :: Int])
        errorOf resp >>= (`shouldBe` (-8, "Invalid nblocks. Must be a positive number or -1.")))
        [0, -2]
    it "an out-of-int32 or fractional nblocks is -1 from the conversion" $
      mapM_ (\v -> do
        resp <- handleGetNetworkHashPS noServer (toJSON [v])
        errorOf resp >>= (`shouldBe` (-1, "JSON integer out of range")))
        [Number 4294967296, Number 1.5]
    it "a height beyond the tip or < -1 is -8" $ withLiveServer $ \srv ->
      mapM_ (\h -> do
        resp <- handleGetNetworkHashPS srv (toJSON [120, h :: Int])
        errorOf resp >>= (`shouldBe` (-8, "Block does not exist at specified height")))
        [5, -2]
    it "CONTROL: valid args (incl. nblocks -1) still answer 0 at genesis" $
      withLiveServer $ \srv ->
        mapM_ (\ps -> do
          resp <- handleGetNetworkHashPS srv (toJSON ps)
          resError resp `shouldBe` Null
          resResult resp `shouldBe` Number 0)
          [[], [120 :: Int], [-1], [120, 0], [120, -1]]

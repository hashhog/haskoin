{-# LANGUAGE OverloadedStrings #-}

-- | Transaction hex decoding is strict, as Core's DecodeHexTx.
--
-- Core accepts a decode only when it consumes the whole byte stream, and
-- decoderawtransaction's @iswitness@ argument restricts which encoding is
-- tried.  haskoin used 'S.decode', which ignores trailing bytes, so
--
--   * decoderawtransaction <tx>00         decoded instead of -22
--   * decoderawtransaction <segwit> false decoded instead of -22
--   * testmempoolaccept [<tx>00]          was judged instead of -22
--   * sendrawtransaction <tx>00           BROADCAST the truncated tx
--   * sendrawtransaction zz               worded the error differently
--
-- (core-regtest rows operator/decoderawtransaction/{trailing,
-- segwit-iswitness-false}, operator/testmempoolaccept/trailing,
-- operator/sendrawtransaction/{trailing,not-hex}).
--
-- TEETH: on the unfixed tree the "-22" expectations below fail.
module DecodeStrictSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Serialize as S
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage
  (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-rawmempool-")
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
        action RpcServer
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




rpc :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
rpc server method ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method)
        , ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

errCode :: A.Value -> Maybe A.Value
errCode (A.Object o) = KM.lookup "code" o
errCode _ = Nothing

errMsg :: A.Value -> Maybe A.Value
errMsg (A.Object o) = KM.lookup "message" o
errMsg _ = Nothing

mkTx :: [BS.ByteString] -> Tx
mkTx wit = Tx
  { txVersion = 2
  , txInputs = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0x11))) 0) BS.empty 0xfffffffd]
  , txOutputs = [TxOut 1000 (BS.pack [0x00, 0x14] <> BS.replicate 20 0x22)]
  , txWitness = [wit]
  , txLockTime = 0 }

hexOf :: Tx -> T.Text
hexOf = TE.decodeUtf8 . B16.encode . S.encode

spec :: Spec
spec = describe "tx hex decoding is strict (Core DecodeHexTx)" $ do
  let legacy = hexOf (mkTx [])
      segwit = hexOf (mkTx [BS.replicate 4 0x33])
      decodeFailed = Just (A.Number (-22))
      sendMsg = Just (A.String "TX decode failed. Make sure the tx has at least one input.")
  describe "decoderawtransaction" $ do
    it "decodes a legacy and a segwit tx" $ withServer $ \server -> do
      (_, e1) <- rpc server "decoderawtransaction" [A.String legacy]
      e1 `shouldBe` A.Null
      (_, e2) <- rpc server "decoderawtransaction" [A.String segwit]
      e2 `shouldBe` A.Null
    it "rejects trailing bytes with -22" $ withServer $ \server -> do
      (_, e) <- rpc server "decoderawtransaction" [A.String (segwit <> "00")]
      errCode e `shouldBe` decodeFailed
      errMsg e `shouldBe` Just (A.String "TX decode failed")
    it "iswitness=false refuses a segwit encoding with -22" $ withServer $ \server -> do
      (_, e) <- rpc server "decoderawtransaction" [A.String segwit, A.Bool False]
      errCode e `shouldBe` decodeFailed
    it "iswitness=true decodes segwit; iswitness=false decodes legacy" $ withServer $ \server -> do
      (_, e) <- rpc server "decoderawtransaction" [A.String segwit, A.Bool True]
      e `shouldBe` A.Null
      (_, e') <- rpc server "decoderawtransaction" [A.String legacy, A.Bool False]
      e' `shouldBe` A.Null
  describe "testmempoolaccept" $
    it "rejects trailing bytes with -22 instead of judging the tx" $ withServer $ \server -> do
      (r, e) <- rpc server "testmempoolaccept" [A.Array (V.fromList [A.String (legacy <> "00")])]
      errCode e `shouldBe` decodeFailed
      r `shouldBe` A.Null
  describe "sendrawtransaction" $ do
    it "rejects trailing bytes with -22 and Core's wording" $ withServer $ \server -> do
      (_, e) <- rpc server "sendrawtransaction" [A.String (legacy <> "00")]
      errCode e `shouldBe` decodeFailed
      errMsg e `shouldBe` sendMsg
    it "words non-hex input like any other decode failure" $ withServer $ \server -> do
      (_, e) <- rpc server "sendrawtransaction" [A.String "zz"]
      errCode e `shouldBe` decodeFailed
      errMsg e `shouldBe` sendMsg

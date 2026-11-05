{-# LANGUAGE OverloadedStrings #-}

-- | getblock accepts a JSON bool verbosity (true = 1, false = 0).
--
-- Core (rpc/blockchain.cpp getblock) reads the argument with
-- ParseVerbosity(request.params[1], /*default_verbosity=*/1, /*allow_bool=*/true)
-- (rpc/util.cpp), so @getblock <hash> false@ returns raw hex and
-- @getblock <hash> true@ the verbose object.  haskoin answered -3 "JSON value
-- of type bool is not of expected type number" (core-regtest rows
-- operator/getblock/true and operator/getblock/false).
--
-- TEETH: on the unfixed tree both bool calls return the -3 error.
module GetBlockBoolSpec (spec) where

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
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus (regtest, initHeaderChain, netGenesisBlock)
import Haskoin.Storage
  (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, putBlock)
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


hashHex :: BlockHash -> T.Text
hashHex (BlockHash (Hash256 bs)) = TE.decodeUtf8 (B16.encode (BS.reverse bs))

-- | whole response object (result + error) for getblock <hash> <verbosity>
callGetBlock :: RpcServer -> T.Text -> A.Value -> IO (A.Value, A.Value)
callGetBlock server h v = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getblock")
        , ("params", A.Array (V.fromList [A.String h, v])) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

spec :: Spec
spec = describe "getblock bool verbosity (Core ParseVerbosity allow_bool)" $ do
  let genesis = netGenesisBlock regtest
      gh      = computeBlockHash (blockHeader genesis)
      rawHex  = TE.decodeUtf8 (B16.encode (S.encode genesis))
  it "false returns raw hex, as verbosity 0" $ withServer $ \server -> do
    putBlock (rsDB server) gh genesis
    (r0, e0) <- callGetBlock server (hashHex gh) (A.Number 0)
    r0 `shouldBe` A.String rawHex
    e0 `shouldBe` A.Null
    (rb, eb) <- callGetBlock server (hashHex gh) (A.Bool False)
    eb `shouldBe` A.Null
    rb `shouldBe` r0
  it "true returns the verbose object, as verbosity 1" $ withServer $ \server -> do
    putBlock (rsDB server) gh genesis
    (r1, e1) <- callGetBlock server (hashHex gh) (A.Number 1)
    e1 `shouldBe` A.Null
    (rb, eb) <- callGetBlock server (hashHex gh) (A.Bool True)
    eb `shouldBe` A.Null
    rb `shouldBe` r1
    case rb of
      A.Object o -> KM.lookup "hash" o `shouldBe` Just (A.String (hashHex gh))
      other -> expectationFailure ("not an object: " ++ show other)
  it "a string verbosity is still a -3 type error" $ withServer $ \server -> do
    putBlock (rsDB server) gh genesis
    (_, e) <- callGetBlock server (hashHex gh) (A.String "x")
    case e of
      A.Object o -> KM.lookup "code" o `shouldBe` Just (A.Number (-3))
      other -> expectationFailure ("no error: " ++ show other)

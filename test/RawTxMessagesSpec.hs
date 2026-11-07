{-# LANGUAGE OverloadedStrings #-}

-- | getblockheader type-checks its verbose argument; getrawtransaction's
-- "not in this block" error carries Core's full text.
--
-- Core's RPC framework checks declared argument types before the handler
-- runs, so @getblockheader <hash> "x"@ is -3 "Wrong type passed" (haskoin
-- silently read it as the default).  rpc/rawtransaction.cpp ends every
-- not-found error with ". Use gettransaction for wallet transactions."
-- (core-regtest rows operator/getblockheader/bad-verbose,
-- operator/getrawtransaction/{wrong-block,unknown-in-block}).
--
-- TEETH: on the unfixed tree both tests fail.
module RawTxMessagesSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
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
  (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, putBlock, putBlockHeader)
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

call :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
call server method ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method), ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

field :: T.Text -> A.Value -> Maybe A.Value
field k (A.Object o) = KM.lookup (Key.fromText k) o
field _ _ = Nothing

spec :: Spec
spec = describe "rawtx / header RPC messages (Core)" $ do
  let genesis = netGenesisBlock regtest
      gh      = computeBlockHash (blockHeader genesis)
      missing = T.replicate 32 "ab"
  it "getblockheader <hash> \"x\" is -3 Wrong type passed, naming verbose" $
    withServer $ \server -> do
      putBlock (rsDB server) gh genesis
      putBlockHeader (rsDB server) gh (blockHeader genesis)
      (r, e) <- call server "getblockheader" [A.String (hashHex gh), A.String "x"]
      r `shouldBe` A.Null
      field "code" e `shouldBe` Just (A.Number (-3))
      field "message" e `shouldBe` Just (A.String
        "Wrong type passed:\n{\n    \"Position 2 (verbose)\": \"JSON value of type string is not of expected type bool\"\n}")
  it "getblockheader still accepts a bool verbose" $
    withServer $ \server -> do
      putBlock (rsDB server) gh genesis
      putBlockHeader (rsDB server) gh (blockHeader genesis)
      (_, e) <- call server "getblockheader" [A.String (hashHex gh), A.Bool False]
      e `shouldBe` A.Null
  it "getrawtransaction: a txid absent from the named block ends with the gettransaction hint" $
    withServer $ \server -> do
      putBlock (rsDB server) gh genesis
      putBlockHeader (rsDB server) gh (blockHeader genesis)
      (r, e) <- call server "getrawtransaction"
                  [A.String missing, A.Bool True, A.String (hashHex gh)]
      r `shouldBe` A.Null
      field "code" e `shouldBe` Just (A.Number (-5))
      field "message" e `shouldBe` Just (A.String
        "No such transaction found in the provided block. Use gettransaction for wallet transactions.")

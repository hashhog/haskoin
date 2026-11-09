{-# LANGUAGE OverloadedStrings #-}
-- | secfix-haskoin-default-rpc-login (C1): the RPC listener must not accept a
-- built-in login, and must not answer a request whose Host header names a
-- foreign site while it is bound to loopback (DNS rebinding).
--
-- Core reference: bitcoin-core/src/httprpc.cpp InitRPCAuthentication. With
-- no -rpcpassword, Core generates a random cookie and has no built-in
-- password; a user:password pair is only accepted when the operator set one.
-- HTTPRPCRequestProc checks the Authorization header before dispatch.
--
-- Every request here goes through 'combinedApp', the same WAI application
-- Warp serves, so the test covers the full routing/auth path.
module RpcAuthSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BC
import Data.IORef (newIORef, readIORef, writeIORef, atomicModifyIORef')
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Network.HTTP.Types (Header, statusCode)
import Network.Socket (SockAddr(..), tupleToHostAddress)
import Network.Wai
  ( Request(..), defaultRequest, responseStatus, setRequestBodyChunks )
import System.Directory (createDirectoryIfMissing, getTemporaryDirectory,
                         removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.Network
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
import Haskoin.Storage
import Haskoin.TxOrphanage (emptyOrphanPool)


cookiePass :: T.Text
cookiePass = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

noopHandler :: a -> Message -> IO ()
noopHandler _ _ = return ()

withServer :: (RpcConfig -> RpcConfig) -> (RpcServer -> IO ()) -> IO ()
withServer tweak action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-rpcauth-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg noopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = tweak defaultRpcConfig { rpcDataDir = dir }
        action RpcServer
              { rsConfig = cfg, rsDB = db, rsHeaderChain = hc, rsPeerMgr = pm
              , rsMempool = mp, rsFeeEst = fe, rsUTXOCache = cache
              , rsNetwork = regtest, rsBlockStore = Nothing
              , rsThread = threadVar, rsMockTime = mockTimeVar
              , rsWalletMgr = Nothing, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = cookiePass
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }

basic :: BS.ByteString -> Header
basic userPass = ("Authorization", "Basic " <> B64.encode userPass)

cookieAuth :: Header
cookieAuth = basic ("__cookie__:" <> BC.pack (T.unpack cookiePass))

loopback :: SockAddr
loopback = SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1))

-- | Send one request through 'combinedApp' from a loopback client and return
-- the HTTP status code.
send :: RpcServer -> BS.ByteString -> BS.ByteString -> [Header] -> IO Int
send server method path hdrs = do
  bodyRef <- newIORef [ "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"getblockcount\",\"params\":[]}"
                      | method == "POST" ]
  let nextChunk = atomicModifyIORef' bodyRef $ \cs -> case cs of
        []       -> ([], BS.empty)
        (c:rest) -> (rest, c)
      req = setRequestBodyChunks nextChunk defaultRequest
              { requestMethod  = method
              , rawPathInfo    = path
              , requestHeaders = hdrs
              , remoteHost     = loopback
              }
  out <- newIORef 0
  _ <- combinedApp server req $ \resp -> do
    writeIORef out (statusCode (responseStatus resp))
    return undefined
  readIORef out

rpc :: RpcServer -> [Header] -> IO Int
rpc server = send server "POST" "/"

spec :: Spec
spec = describe "default_credentials_rejected" $ do

  it "ships no built-in rpcuser/rpcpassword (Core: both default to empty)" $ do
    rpcUser defaultRpcConfig     `shouldBe` ""
    rpcPassword defaultRpcConfig `shouldBe` ""

  it "rejects Basic haskoin:haskoin when no rpcuser/rpcpassword is set (401)" $
    withServer id $ \s ->
      rpc s [basic "haskoin:haskoin", ("Host", "127.0.0.1:8332")] `shouldReturn` 401

  it "rejects an empty user:password pair when none is configured (401)" $
    withServer id $ \s ->
      rpc s [basic ":", ("Host", "127.0.0.1:8332")] `shouldReturn` 401

  it "accepts the cookie when no rpcuser/rpcpassword is set (200)" $
    withServer id $ \s ->
      rpc s [cookieAuth, ("Host", "127.0.0.1:8332")] `shouldReturn` 200

  it "accepts an operator-set rpcuser/rpcpassword (200), and nothing else (401)" $
    withServer (\c -> c { rpcUser = "test", rpcPassword = "test" }) $ \s -> do
      rpc s [basic "test:test", ("Host", "127.0.0.1:8332")] `shouldReturn` 200
      rpc s [basic "haskoin:haskoin", ("Host", "127.0.0.1:8332")] `shouldReturn` 401

  it "does not accept user: alone when only rpcuser is set (401)" $
    withServer (\c -> c { rpcUser = "test", rpcPassword = "" }) $ \s ->
      rpc s [basic "test:", ("Host", "127.0.0.1:8332")] `shouldReturn` 401

  it "rejects a non-loopback Host on a loopback-bound listener, even with the cookie (403)" $
    withServer id $ \s -> do
      rpc s [cookieAuth, ("Host", "attacker.example:8332")] `shouldReturn` 403
      rpc s [cookieAuth, ("Host", "192.168.1.5:8332")] `shouldReturn` 403
      rpc s [cookieAuth, ("Host", "127.0.0.1.attacker.example")] `shouldReturn` 403

  it "rejects a non-loopback Host on the REST route too (403)" $
    withServer (\c -> c { rpcRestEnabled = True }) $ \s ->
      send s "GET" "/rest/chaininfo.json" [("Host", "attacker.example:8332")]
        `shouldReturn` 403

  it "accepts loopback Host spellings and a missing Host (200)" $
    withServer id $ \s -> do
      rpc s [cookieAuth, ("Host", "127.0.0.1:8332")] `shouldReturn` 200
      rpc s [cookieAuth, ("Host", "127.0.0.1")] `shouldReturn` 200
      rpc s [cookieAuth, ("Host", "localhost:18443")] `shouldReturn` 200
      rpc s [cookieAuth, ("Host", "LOCALHOST")] `shouldReturn` 200
      rpc s [cookieAuth, ("Host", "[::1]:8332")] `shouldReturn` 200
      rpc s [cookieAuth] `shouldReturn` 200

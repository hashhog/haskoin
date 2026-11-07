{-# LANGUAGE OverloadedStrings #-}

-- | Operator-visible shape rows that differed from Core v31.1:
--
--   * getpeerinfo carries @addrlocal@ (the address the peer reported for us in
--     its version message, Core CNode::SetAddrLocal) and @addrbind@ (the
--     socket's local address), both directly after @addr@ (rpc/net.cpp).
--   * stop answers "Bitcoin Core stopping" (rpc/server.cpp, CLIENT_NAME).
--
-- core-regtest rows operator/peer/shape:[0].{addrbind,addrlocal} and
-- operator/stop/result.
--
-- TEETH: on the unfixed tree the addrlocal, addrbind and stop tests fail.  The
-- addrbind test goes through the live getpeerinfo handler with a real loopback
-- socket registered in the peer manager, so it builds on the unfixed tree too.
module OperatorShapeSpec (spec) where

import Test.Hspec
import Control.Concurrent.MVar (newEmptyMVar, newMVar, tryPutMVar, takeMVar)
import Control.Concurrent.STM (newTVarIO, newTBQueueIO, atomically, modifyTVar')
import Control.Exception (bracket)
import Control.Monad (void)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.Encoding as AE
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import Network.Socket
  ( SockAddr(..), tupleToHostAddress, Socket, socket, Family(AF_INET)
  , SocketType(Stream), defaultProtocol, bind, listen, connect, getSocketName
  , close )
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)
import System.Posix.Signals (installHandler, Handler(..), sigTERM)

import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Network
  ( PeerInfo(..), PeerState(..), Version(..), PeerConnection(..), PeerManager(..), startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.Types
import Haskoin.Storage
  (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc

testAddr :: SockAddr
testAddr = SockAddrInet 8333 (tupleToHostAddress (203, 0, 113, 7))

testInfo :: PeerInfo
testInfo = PeerInfo
  { piAddress             = testAddr
  , piVersion             = Nothing
  , piState               = PeerConnected
  , piServices            = 9            -- NETWORK | WITNESS
  , piStartHeight         = 123456       -- MUST NOT surface as "startingheight"
  , piRelay               = True
  , piLastSeen            = 1700000000
  , piLastPing            = Nothing
  , piPingLatency         = Just 0.05
  , piBanScore            = 0
  , piBytesSent           = 4242
  , piBytesRecv           = 8484
  , piMsgsSent            = 10
  , piMsgsRecv            = 20
  , piConnectedAt         = 1699999000
  , piTimeOffset          = 0
  , piInbound             = False
  , piWantsAddrV2         = False
  , piWantsHeaders        = False
  , piFeeFilterReceived   = 0
  , piFeeFilterSent       = 0
  , piNextFeeFilterSend   = 0
  , piBlockOnly           = False
  , piUnconnectingHeaders = 0
  , piNoBan               = False
  , piIsManual            = False
  , piIsLocal             = False
  , piWtxidRelay          = False
  , piProvidesCmpct       = False
  , piCmpctHBFrom         = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }


-- | A version message whose addr_recv (our address, as the peer sees it) is
-- 127.0.0.1:18444, as the core-regtest peer sends.
versionWith :: [Word8] -> Version
versionWith ip = Version
  { vVersion = 70016, vServices = 9, vTimestamp = 0
  , vAddrRecv = NetworkAddress 9
      (BS.pack ([0,0,0,0,0,0,0,0,0,0,0xff,0xff] ++ ip)) 18444
  , vAddrSend = NetworkAddress 9 (BS.replicate 16 0) 0
  , vNonce = 1, vUserAgent = VarString "/t/", vStartHeight = 0, vRelay = True }

encodeObj :: AE.Encoding -> KM.KeyMap A.Value
encodeObj e = case A.decode (AE.encodingToLazyByteString e) of
  Just (A.Object o) -> o
  _ -> error "not an object"

-- | A connected loopback TCP pair; returns the client end and its local address.
withLoopbackSocket :: (Socket -> SockAddr -> IO a) -> IO a
withLoopbackSocket act =
  bracket (socket AF_INET Stream defaultProtocol) close $ \lst ->
  bracket (socket AF_INET Stream defaultProtocol) close $ \cli -> do
    bind lst (SockAddrInet 0 (tupleToHostAddress (127,0,0,1)))
    listen lst 1
    lsn <- getSocketName lst
    connect cli lsn
    me <- getSocketName cli
    act cli me

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-opshape-")
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

spec :: Spec
spec = describe "operator RPC shapes (Core)" $ do
  it "getpeerinfo: addrlocal is the address the peer reported for us" $ do
    let info = testInfo { piVersion = Just (versionWith [127,0,0,1]) }
        o = encodeObj (peerInfoToEncoding BS.empty 0 (testAddr, info))
    KM.lookup (Key.fromText "addrlocal") o `shouldBe` Just (A.String "127.0.0.1:18444")
  it "getpeerinfo: no addrlocal when the reported address is invalid (0.0.0.0)" $ do
    let info = testInfo { piVersion = Just (versionWith [0,0,0,0]) }
        o = encodeObj (peerInfoToEncoding BS.empty 0 (testAddr, info))
    KM.member (Key.fromText "addrlocal") o `shouldBe` False
  it "getpeerinfo: addrbind carries the socket's local address" $
    withServer $ \server -> withLoopbackSocket $ \sock me -> do
      infoVar <- newTVarIO testInfo
      sendLock <- newMVar ()
      recvQ <- newTBQueueIO 10
      buf <- newIORef BS.empty
      v2 <- newIORef Nothing
      fb <- newIORef Nothing
      let pc = PeerConnection
            { pcSocket = sock, pcInfo = infoVar, pcSendLock = sendLock
            , pcRecvQueue = recvQ, pcSendThread = Nothing, pcRecvThread = Nothing
            , pcNetwork = regtest, pcReadBuffer = buf, pcV2Transport = v2
            , pcBlockFirstByteAt = fb }
      atomically $ modifyTVar' (pmPeers (rsPeerMgr server)) (Map.insert testAddr pc)
      (r, e) <- call server "getpeerinfo" []
      e `shouldBe` A.Null
      let SockAddrInet port host = me
          [a, b, c, d] = map show (let h = fromIntegral host :: Word32
                                   in [h `mod` 256, (h `div` 256) `mod` 256, (h `div` 65536) `mod` 256, h `div` 16777216])
          expected = T.pack (a ++ "." ++ b ++ "." ++ c ++ "." ++ d ++ ":" ++ show port)
      case r of
        A.Array xs | [A.Object o] <- V.toList xs ->
          KM.lookup (Key.fromText "addrbind") o `shouldBe` Just (A.String expected)
        other -> expectationFailure ("unexpected getpeerinfo: " ++ show other)
  it "stop answers Bitcoin Core stopping" $
    withServer $ \server -> do
      -- stop raises SIGTERM in this process; catch it so the test survives.
      got <- newEmptyMVar
      old <- installHandler sigTERM (Catch (void (tryPutMVar got ()))) Nothing
      (r, e) <- call server "stop" []
      takeMVar got
      void (installHandler sigTERM old Nothing)
      e `shouldBe` A.Null
      r `shouldBe` A.String "Bitcoin Core stopping"

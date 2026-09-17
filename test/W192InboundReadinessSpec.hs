{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Inbound P2P readiness — CHARTER "full P2P, outbound AND inbound".
--
-- Control for QUEUES.md haskoin item 0. Each requirement has a
-- regtest assertion that does not need mainnet:
--
--   (1) configurable bind, default 0.0.0.0 + [::], restrict via --bind
--   (2) inbound version/verack appears in getpeerinfo with inbound: true
--   (3) inbound slots are separate from outbound (flood cannot starve sync)
--   (4) half-open handshake is reaped and frees the slot
--   (5) inbound peer is served getheaders + getdata (a block) like outbound
--
-- Negative control: a TCP connect that never sends version is disconnected
-- on the handshake timeout and does not keep occupying an inbound slot.
--
-- Default bind address (report in the commit body): 0.0.0.0 and ::
module W192InboundReadinessSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.STM (readTVarIO)
import Control.Exception (IOException, bracket, catch)
import Control.Monad (forM_, unless, when)
import Data.Aeson (Value (..), decode)
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Aeson.Key as AK
import qualified Data.Aeson.KeyMap as KM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Int (Int64)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, isJust)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word64)
import Network.Socket
  ( AddrInfo (..),
    SockAddr (..),
    Socket,
    SocketType (..),
    close,
    connect,
    defaultHints,
    getAddrInfo,
    socket,
    tupleToHostAddress,
    tupleToHostAddress6,
  )
import Network.Socket.ByteString (recv, sendAll)
import System.IO.Temp (withSystemTempDirectory)
import System.Timeout (timeout)
import Test.Hspec

import Haskoin.Consensus (netGenesisBlock, netMagic, regtest)
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Network
  ( BindSpec (..),
    GetData (..),
    GetHeaders (..),
    Headers (..),
    InboundAdmission (..),
    InvType (..),
    InvVector (..),
    Message (..),
    PeerConnection (..),
    PeerInfo (..),
    PeerManager (..),
    PeerManagerConfig (..),
    PeerState (..),
    Version (..),
    countInboundPeers,
    countOutboundPeers,
    decodeMessage,
    decodeMessageHeader,
    defaultBindHosts,
    defaultPeerManagerConfig,
    encodeMessage,
    inboundAdmissionDecision,
    inboundSlotsFromMaxConnections,
    insertTestPeer,
    parseBindSpec,
    protocolVersion,
    requestFromPeer,
    resolveListenBinds,
    startInboundListenerOn,
    startPeerManager,
    stopPeerManager,
  )
import Haskoin.Rpc (peerInfoToEncoding)
import Haskoin.Types
  ( Block (..),
    BlockHash (..),
    BlockHeader (..),
    Hash256 (..),
    NetworkAddress (..),
    VarString (..),
    getBlockHashHash,
  )

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

handshakeTimeoutSecs :: Int
handshakeTimeoutSecs = 1

genesis :: Block
genesis = netGenesisBlock regtest

genesisHeader :: BlockHeader
genesisHeader = blockHeader genesis

genesisHash :: BlockHash
genesisHash = computeBlockHash genesisHeader

zeroHash :: BlockHash
zeroHash = BlockHash (Hash256 (BS.replicate 32 0))

--------------------------------------------------------------------------------
-- Peer manager fixture
--------------------------------------------------------------------------------

serveInbound :: PeerManager -> SockAddr -> Message -> IO ()
serveInbound pm addr msg = case msg of
  MGetHeaders _ ->
    requestFromPeer pm addr (MHeaders (Headers [genesisHeader]))
  MGetData (GetData ivs) ->
    forM_ ivs $ \iv ->
      when (ivType iv == InvBlock || ivType iv == InvWitnessBlock) $
        requestFromPeer pm addr (MBlock genesis)
  _ -> return ()

baseCfg :: PeerManagerConfig
baseCfg =
  defaultPeerManagerConfig
    { pmcDnsSeed = False,
      pmcBindHosts = ["127.0.0.1"],
      pmcHandshakeTimeout = handshakeTimeoutSecs,
      pmcMaxInbound = 8,
      pmcMaxOutbound = 8,
      pmcMaxTotal = 16
    }

withPM :: PeerManagerConfig -> (PeerManager -> IO a) -> IO a
withPM cfg inner =
  withSystemTempDirectory "haskoin-inbound" $ \dir -> do
    pmRef <- newIORef (error "PeerManager not started")
    let handler addr msg = do
          pm <- readIORef pmRef
          serveInbound pm addr msg
        cfg' = cfg {pmcDataDir = dir, pmcDnsSeed = False}
    bracket
      (startPeerManager regtest cfg' handler)
      stopPeerManager
      $ \pm -> do
        writeIORef pmRef pm
        inner pm

listenPortOf :: SockAddr -> Int
listenPortOf (SockAddrInet p _) = fromIntegral p
listenPortOf (SockAddrInet6 p _ _ _) = fromIntegral p
listenPortOf _ = 0

listenLoopback :: PeerManager -> IO Int
listenLoopback pm = do
  addrs <- startInboundListenerOn pm [BindSpec "127.0.0.1" 0]
  case addrs of
    [] -> do
      expectationFailure "P2P listener did not bind 127.0.0.1"
      return 0
    (a : _) -> return (listenPortOf a)

waitUntil :: Int -> IO Bool -> IO Bool
waitUntil timeoutMs action = go timeoutMs
  where
    go remaining
      | remaining <= 0 = return False
      | otherwise = do
          ok <- action
          if ok
            then return True
            else do
              threadDelay 20_000
              go (remaining - 20)

--------------------------------------------------------------------------------
-- Raw Bitcoin P2P client (dials an already-listening node = inbound)
--------------------------------------------------------------------------------

-- Blocking read.  Do NOT wrap each recv in a short System.Timeout.timeout:
-- a timeout that fires after recv has copied bytes from the kernel drops
-- those bytes, which is how the first version/verack pass lost the node's
-- version frame.
recvAll :: Socket -> Int -> IO (Maybe ByteString)
recvAll _ n | n <= 0 = return (Just BS.empty)
recvAll sock n = recvExact BS.empty n
  where
    recvExact acc need
      | BS.length acc >= need = return (Just (BS.take need acc))
      | otherwise = do
          -- Recv exactly what we still need.  Reading ahead and dropping
          -- the tail loses the rest of a coalesced TCP burst (version
          -- payload + verack + sendheaders) and the next decode fails.
          chunk <-
            recv sock need
              `catch` (\(_ :: IOException) -> return BS.empty)
          if BS.null chunk
            then return Nothing
            else recvExact (acc `BS.append` chunk) need

-- Header layout: magic(4) || command(12) || length(4 LE) || checksum(4)
mhCommandOf :: ByteString -> ByteString
mhCommandOf bs = BS.takeWhile (/= 0) (BS.take 12 (BS.drop 4 bs))

mhLengthOf :: ByteString -> Int
mhLengthOf bs =
  let b = BS.unpack (BS.take 4 (BS.drop 16 bs))
   in case b of
        [b0, b1, b2, b3] ->
          fromIntegral b0
            + fromIntegral b1 * 256
            + fromIntegral b2 * 65536
            + fromIntegral b3 * 16777216
        _ -> 0

recvMsg :: Socket -> IO (Maybe Message)
recvMsg sock = do
  mHdr <- recvAll sock 24
  case mHdr of
    Nothing -> return Nothing
    Just hdrBs -> case decodeMessageHeader hdrBs of
      Left _ -> return Nothing
      Right _hdr -> do
        let cmd = mhCommandOf hdrBs
            plen = mhLengthOf hdrBs
        mPay <- if plen == 0 then return (Just BS.empty) else recvAll sock plen
        case mPay of
          Nothing -> return Nothing
          Just p -> case decodeMessage cmd p of
            Left _ -> return Nothing
            Right m -> return (Just m)

sendMsg :: Socket -> Message -> IO ()
sendMsg sock msg = sendAll sock (encodeMessage (netMagic regtest) msg)

mkVersion :: Word64 -> Int64 -> Version
mkVersion nonce now =
  Version
    { vVersion = protocolVersion,
      vServices = 9,
      vTimestamp = now,
      vAddrRecv = NetworkAddress 0 (BS.replicate 16 0) 0,
      vAddrSend = NetworkAddress 9 (BS.replicate 16 0) 0,
      vNonce = nonce,
      vUserAgent = VarString "/inbound-readiness:0.0.1/",
      vStartHeight = 0,
      vRelay = True
    }

connectTcp :: String -> Int -> IO Socket
connectTcp host port = do
  let hints = defaultHints {addrSocketType = Stream}
  ais <- getAddrInfo (Just hints) (Just host) (Just (show port))
  case ais of
    [] -> error $ "connectTcp: cannot resolve " ++ host
    (ai : _) -> do
      sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
      connect sock (addrAddress ai)
      return sock

drainUntil :: Socket -> (Message -> Bool) -> Int -> IO (Maybe Message)
drainUntil sock predFn timeoutMs = do
  m <- timeout (timeoutMs * 1000) loop
  return (fromMaybe Nothing m)
  where
    loop = do
      mMsg <- recvMsg sock
      case mMsg of
        Nothing -> return Nothing
        Just msg
          | predFn msg -> return (Just msg)
          | otherwise -> loop

inboundHandshake :: Int -> IO Socket
inboundHandshake port = do
  sock <- connectTcp "127.0.0.1" port
  now <- round <$> getPOSIXTime
  -- Send version AND verack up front (the Bitcoin handshake is not
  -- strictly lock-step).  Waiting to read the node's version before
  -- sending verack races the inbound handshake watchdog.
  sendMsg sock (MVersion (mkVersion 0x1122334455667788 now))
  sendMsg sock MVerAck
  mVer <- drainUntil sock isVersion 5000
  unless (isJust mVer) $ expectationFailure "did not receive version from node"
  return sock
  where
    isVersion (MVersion _) = True
    isVersion _ = False

peerJsonObject :: SockAddr -> PeerInfo -> KM.KeyMap Value
peerJsonObject addr info =
  case decode (encodingToLazyByteString (peerInfoToEncoding BS.empty 0 (addr, info))) of
    Just (Object o) -> o
    _ -> KM.empty

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "inbound P2P readiness" $ do
  --------------------------------------------------------------------------
  -- (1) bind configuration
  --------------------------------------------------------------------------
  describe "(1) bind configuration" $ do
    it "default bind hosts are all-interfaces IPv4 and IPv6, not loopback" $ do
      defaultBindHosts `shouldBe` ["0.0.0.0", "::"]
      defaultBindHosts `shouldNotContain` ["127.0.0.1"]
      defaultBindHosts `shouldNotContain` ["::1"]

    it "parses IPv4, IPv4:port, bracketed IPv6, and bare IPv6" $ do
      parseBindSpec "0.0.0.0" 8333
        `shouldBe` Right (BindSpec "0.0.0.0" 8333)
      parseBindSpec "127.0.0.1:8334" 8333
        `shouldBe` Right (BindSpec "127.0.0.1" 8334)
      parseBindSpec "[::]" 8333
        `shouldBe` Right (BindSpec "::" 8333)
      parseBindSpec "[::1]:18444" 8333
        `shouldBe` Right (BindSpec "::1" 18444)
      parseBindSpec "::" 8333
        `shouldBe` Right (BindSpec "::" 8333)

    it "resolveListenBinds [] is 0.0.0.0 and :: on the listen port" $ do
      resolveListenBinds [] 18444
        `shouldBe` Right
          [ BindSpec "0.0.0.0" 18444,
            BindSpec "::" 18444
          ]

    it "resolveListenBinds with --bind restricts to the given address" $ do
      resolveListenBinds ["127.0.0.1"] 8333
        `shouldBe` Right [BindSpec "127.0.0.1" 8333]

    it "--bind=127.0.0.1 restricts the live listener to loopback" $
      withPM baseCfg $ \pm -> do
        addrs <- startInboundListenerOn pm [BindSpec "127.0.0.1" 0]
        length addrs `shouldSatisfy` (>= 1)
        forM_ addrs $ \a ->
          case a of
            SockAddrInet _ ha ->
              ha `shouldBe` tupleToHostAddress (127, 0, 0, 1)
            other ->
              expectationFailure $ "expected IPv4 loopback, got " ++ show other

    it "default listen binds all interfaces, not loopback" $
      withPM (baseCfg {pmcBindHosts = []}) $ \pm -> do
        case resolveListenBinds [] 0 of
          Left err -> expectationFailure err
          Right specs -> do
            addrs <- startInboundListenerOn pm specs
            length addrs `shouldSatisfy` (>= 1)
            any isAnyAddr addrs `shouldBe` True
            any isLoopbackAddr addrs `shouldBe` False
            -- Dual-stack [::] or IPv4 0.0.0.0 must still accept IPv4 clients.
            let port = listenPortOf (head addrs)
            sock <- connectTcp "127.0.0.1" port
            close sock

  --------------------------------------------------------------------------
  -- (2)(5) inbound handshake, getpeerinfo inbound:true, served block
  --------------------------------------------------------------------------
  describe "(2)(5) inbound handshake + getpeerinfo + serve" $ do
    it "inbound version/verack appears in getpeerinfo with inbound:true and is served a block" $
      withPM baseCfg $ \pm -> do
        port <- listenLoopback pm
        sock <- inboundHandshake port
        ok <-
          waitUntil 3000 $ do
            peers <- readTVarIO (pmPeers pm)
            infos <- mapM (readTVarIO . pcInfo) (Map.elems peers)
            return (any (\i -> piInbound i && piState i == PeerConnected) infos)
        ok `shouldBe` True
        peers <- readTVarIO (pmPeers pm)
        infos <-
          mapM
            ( \(addr, pc) -> do
                info <- readTVarIO (pcInfo pc)
                return (addr, info)
            )
            (Map.toList peers)
        let inboundInfos = filter (piInbound . snd) infos
        length inboundInfos `shouldSatisfy` (>= 1)
        let (addr, info) = head inboundInfos
        piInbound info `shouldBe` True
        piState info `shouldBe` PeerConnected
        let obj = peerJsonObject addr info
        KM.lookup (AK.fromText "inbound") obj `shouldBe` Just (Bool True)
        KM.lookup (AK.fromText "connection_type") obj
          `shouldBe` Just (String "inbound")

        sendMsg
          sock
          ( MGetHeaders
              ( GetHeaders
                  (fromIntegral protocolVersion)
                  [genesisHash]
                  zeroHash
              )
          )
        mHdrs <- drainUntil sock isHeadersMsg 3000
        isJust mHdrs `shouldBe` True

        sendMsg
          sock
          ( MGetData
              (GetData [InvVector InvBlock (getBlockHashHash genesisHash)])
          )
        mBlock <- drainUntil sock isBlockMsg 3000
        isJust mBlock `shouldBe` True
        close sock

  --------------------------------------------------------------------------
  -- (4) half-open handshake reap
  --------------------------------------------------------------------------
  describe "(4) half-open handshake reap" $ do
    it "half-open inbound is reaped on handshake timeout and frees the slot" $
      withPM
        ( baseCfg
            { pmcMaxInbound = 2,
              pmcMaxOutbound = 0,
              pmcHandshakeTimeout = handshakeTimeoutSecs
            }
        )
        $ \pm -> do
          port <- listenLoopback pm
          sock <- connectTcp "127.0.0.1" port
          held <-
            waitUntil 2000 $ do
              n <- countInboundPeers pm
              return (n == 1)
          held `shouldBe` True
          freed <-
            waitUntil ((handshakeTimeoutSecs + 2) * 1000) $ do
              n <- countInboundPeers pm
              return (n == 0)
          freed `shouldBe` True
          nIn <- countInboundPeers pm
          nOut <- countOutboundPeers pm
          nIn `shouldBe` 0
          nOut `shouldBe` 0
          mClosed <- timeout 500_000 (recv sock 1)
          case mClosed of
            Just chunk -> chunk `shouldBe` BS.empty
            Nothing -> return ()
          close sock

  --------------------------------------------------------------------------
  -- (3) inbound slots separate from outbound
  --------------------------------------------------------------------------
  describe "(3) inbound slots separate from outbound" $ do
    it "inboundSlotsFromMaxConnections reserves outbound from maxconnections" $ do
      -- Core: nMaxInbound = nMaxConnections - nMaxOutbound
      -- haskoin outbound budget = full-relay (8) + block-relay-only (2)
      inboundSlotsFromMaxConnections 125 `shouldBe` 115
      inboundSlotsFromMaxConnections 20 `shouldBe` 10
      inboundSlotsFromMaxConnections 3 `shouldBe` 0

    it "inbound flood cannot starve an outbound slot" $
      withPM
        ( baseCfg
            { pmcMaxInbound = 2,
              pmcMaxOutbound = 1,
              pmcMaxBlockRelayOnly = 0,
              pmcMaxTotal = 3
            }
        )
        $ \pm -> do
          port <- listenLoopback pm
          s1 <- inboundHandshake port
          s2 <- inboundHandshake port
          ok <-
            waitUntil 3000 $ do
              n <- countInboundPeers pm
              return (n == 2)
          ok `shouldBe` True

          -- A third inbound must not steal the reserved outbound slot.
          s3 <- connectTcp "127.0.0.1" port
          threadDelay 300_000
          nIn <- countInboundPeers pm
          nIn `shouldSatisfy` (<= 2)
          decision <-
            inboundAdmissionDecision
              pm
              (SockAddrInet 18444 (tupleToHostAddress (203, 0, 113, 9)))
          case decision of
            AdmitInbound ->
              expectationFailure "expected inbound reject at cap, got AdmitInbound"
            AdmitInboundAfterEvicting _ ->
              return () -- eviction is allowed; inbound still cannot grow past cap
            RejectInbound _ -> return ()

          -- An outbound peer can still occupy its reserved slot.
          now <- round <$> getPOSIXTime
          let outAddr = SockAddrInet 18445 (tupleToHostAddress (198, 51, 100, 7))
              outInfo =
                (dummyInfo outAddr now)
                  { piInbound = False,
                    piState = PeerConnected,
                    piLastSeen = 9_999_999_999
                  }
          insertTestPeer pm outAddr outInfo
          nOut <- countOutboundPeers pm
          nIn' <- countInboundPeers pm
          nOut `shouldBe` 1
          nIn' `shouldSatisfy` (<= 2)
          close s1
          close s2
          close s3

--------------------------------------------------------------------------------
-- Helpers used by (3)
--------------------------------------------------------------------------------

dummyInfo :: SockAddr -> Int64 -> PeerInfo
dummyInfo a connectedAt =
  PeerInfo
    { piAddress = a,
      piVersion = Nothing,
      piState = PeerConnected,
      piServices = 0,
      piStartHeight = 0,
      piRelay = True,
      piLastSeen = 9_999_999_999,
      piLastPing = Nothing,
      piPingLatency = Nothing,
      piBanScore = 0,
      piBytesSent = 0,
      piBytesRecv = 0,
      piMsgsSent = 0,
      piMsgsRecv = 0,
      piConnectedAt = connectedAt,
      piTimeOffset = 0,
      piInbound = True,
      piWantsAddrV2 = False,
      piWantsHeaders = False,
      piFeeFilterReceived = 0,
      piFeeFilterSent = 0,
      piNextFeeFilterSend = 0,
      piBlockOnly = False,
      piUnconnectingHeaders = 0,
      piNoBan = False,
      piIsManual = False,
      piIsLocal = True,
      piWtxidRelay = False,
      piGetaddrRecvd = False,
      piAddrTokenBucket = 1.0,
      piAddrTokenTimestamp = 0
    }

isAnyAddr :: SockAddr -> Bool
isAnyAddr (SockAddrInet _ ha) = ha == tupleToHostAddress (0, 0, 0, 0)
isAnyAddr (SockAddrInet6 _ _ ha _) = ha == tupleToHostAddress6 (0, 0, 0, 0, 0, 0, 0, 0)
isAnyAddr _ = False

isHeadersMsg :: Message -> Bool
isHeadersMsg (MHeaders _) = True
isHeadersMsg _ = False

isBlockMsg :: Message -> Bool
isBlockMsg (MBlock _) = True
isBlockMsg _ = False

isLoopbackAddr :: SockAddr -> Bool
isLoopbackAddr (SockAddrInet _ ha) = ha == tupleToHostAddress (127, 0, 0, 1)
isLoopbackAddr (SockAddrInet6 _ _ ha _) = ha == tupleToHostAddress6 (0, 0, 0, 0, 0, 0, 0, 1)
isLoopbackAddr _ = False

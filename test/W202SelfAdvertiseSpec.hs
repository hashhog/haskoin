{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | Self-address advertisement (Bitcoin Core MaybeSendAddr / -externalip /
-- -discover).
--
-- haskoin never told the network where it can be reached: getnetworkinfo
-- localaddresses was a hardcoded [] and no addr carrying our own address
-- was ever sent, so a port-forwarded node got no inbound peers.
--
-- Control: cabal run haskoin-test --enable-tests -- -m 'self-advertise'
--
-- Reference: bitcoin-core/src/net_processing.cpp MaybeSendAddr (5445-5479),
-- net.cpp GetLocalAddrForPeer (240-268), AddLocal / SeenLocal, init.cpp
-- (-externalip soft-sets -discover=0).
module W202SelfAdvertiseSpec (spec) where

import Control.Concurrent.STM
import Control.Exception (bracket)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Int (Int64)
import Data.Word (Word16)
import System.IO.Temp (withSystemTempDirectory)
import System.Timeout (timeout)
import Test.Hspec

import Control.Concurrent.MVar (newMVar)
import Network.Socket
  ( Family (..), SockAddr (..), Socket, SocketType (..), close
  , defaultProtocol, socketPair, tupleToHostAddress )
import Network.Socket.ByteString (recv)

import Haskoin.Consensus (regtest, Network (..))
import Haskoin.Types (NetworkAddress (..), VarString (..))
import Haskoin.Network

ip4 :: (Int, Int, Int, Int) -> BS.ByteString
ip4 (a, b, c, d) =
  BS.pack ([0,0,0,0,0,0,0,0,0,0,0xff,0xff] ++ map fromIntegral [a, b, c, d])

ip6 :: [Int] -> BS.ByteString
ip6 = BS.pack . map fromIntegral

grp :: Int -> NetworkGroup
grp n = NetworkGroup (BS.pack [0x04, fromIntegral n, 0])

spec :: Spec
spec = describe "self-advertise" $ do
  describe "routable filter" $ do
    it "accepts public IPv4 and IPv6" $ do
      isRoutableIP16 (ip4 (1, 2, 3, 4)) `shouldBe` True
      isRoutableIP16 (ip4 (76, 38, 7, 169)) `shouldBe` True
      isRoutableIP16 (ip6 (0x2a : 0x01 : replicate 13 0 ++ [1])) `shouldBe` True
    it "rejects private, loopback, CGNAT, doc, link-local and unspecified" $ do
      mapM_ (\a -> isRoutableIP16 (ip4 a) `shouldBe` False)
        [ (127, 0, 0, 1), (10, 0, 0, 1), (192, 168, 1, 128), (172, 16, 0, 1)
        , (100, 64, 0, 1), (169, 254, 1, 1), (192, 0, 2, 1), (0, 0, 0, 0) ]
      isRoutableIP16 (ip6 (replicate 15 0 ++ [1])) `shouldBe` False       -- ::1
      isRoutableIP16 (ip6 (replicate 16 0)) `shouldBe` False              -- ::
      isRoutableIP16 (ip6 (0xfe : 0x80 : replicate 13 0 ++ [1])) `shouldBe` False
      isRoutableIP16 (ip6 (0xfd : replicate 14 0 ++ [1])) `shouldBe` False
      isRoutableIP16 (ip6 ([0x20, 0x01, 0x0d, 0xb8] ++ replicate 11 0 ++ [1]))
        `shouldBe` False
      isRoutableIP16 (BS.replicate 4 1) `shouldBe` False

  describe "address rendering and parsing" $ do
    it "renders like Core" $ do
      showIP16 (ip4 (1, 2, 3, 4)) `shouldBe` "1.2.3.4"
      showIP16 (ip6 ([0x20, 0x01, 0x0d, 0xb8] ++ replicate 11 0 ++ [1]))
        `shouldBe` "2001:db8::1"
      showIP16 (ip6 (replicate 15 0 ++ [1])) `shouldBe` "::1"
    it "parses --externalip forms" $ do
      parseExternalIP "1.2.3.4" >>= (`shouldBe` Right (ip4 (1, 2, 3, 4), 0))
      parseExternalIP "1.2.3.4:18444" >>= (`shouldBe` Right (ip4 (1, 2, 3, 4), 18444))
      parseExternalIP "[2001:db8::1]:8333"
        >>= (`shouldBe` Right (ip6 ([0x20, 0x01, 0x0d, 0xb8] ++ replicate 11 0 ++ [1]), 8333))
      parseExternalIP "2001:db8::1"
        >>= (`shouldBe` Right (ip6 ([0x20, 0x01, 0x0d, 0xb8] ++ replicate 11 0 ++ [1]), 0))
      r1 <- parseExternalIP "not-an-ip"
      either (const True) (const False) r1 `shouldBe` True
      r2 <- parseExternalIP "1.2.3.4:0"
      either (const True) (const False) r2 `shouldBe` True

  describe "discovery table" $ do
    let me = ip4 (76, 38, 7, 169)
    it "one netgroup is not enough; two distinct netgroups are" $ do
      let t1 = localAddrConfirm 1000 me 8338 (grp 1) True Map.empty
          t1' = localAddrConfirm 1001 me 8338 (grp 1) True t1
          t2 = localAddrConfirm 1002 me 8338 (grp 2) True t1'
      localAddrBest 1002 Nothing t1' `shouldBe` Nothing
      localAddrBest 1002 Nothing t2 `shouldBe` Just (LocalAddress me 8338 2)
    it "stores the listen port given, not the peer's view" $ do
      let t = localAddrConfirm 5 me 8338 (grp 1) True Map.empty
      fmap laePort (Map.lookup me t) `shouldBe` Just 8338
    it "inbound peers only bump an existing entry" $ do
      localAddrConfirm 5 me 8338 (grp 1) False Map.empty `shouldBe` Map.empty
      let t = localAddrConfirm 5 me 8338 (grp 1) True Map.empty
          t' = localAddrConfirm 6 me 8338 (grp 2) False t
      fmap (Set.size . laeConfirmers) (Map.lookup me t') `shouldBe` Just 2
    it "ignores non-routable addresses" $
      localAddrConfirm 5 (ip4 (10, 0, 0, 1)) 8338 (grp 1) True Map.empty
        `shouldBe` Map.empty
    it "expires discovered entries after 3h, keeps manual ones" $ do
      let t = localAddrConfirm 0 me 8338 (grp 1) True Map.empty
          Just tm = localAddrAddManual (ip4 (1, 2, 3, 4)) 8338 t
          later = discoveredLocalAddrTTL + 1
      Map.keys (localAddrExpire (discoveredLocalAddrTTL) tm)
        `shouldMatchList` [me, ip4 (1, 2, 3, 4)]
      Map.keys (localAddrExpire later tm) `shouldBe` [ip4 (1, 2, 3, 4)]
    it "caps discovered entries at 8" $ do
      let t = foldl (\acc i -> localAddrConfirm (fromIntegral i) (ip4 (50, i, 1, 1)) 8338 (grp i) True acc)
                    Map.empty [1 .. 20]
      Map.size t `shouldBe` maxDiscoveredLocalAddrs
    it "manual entries score LOCAL_MANUAL and win" $ do
      let Just t = localAddrAddManual (ip4 (1, 2, 3, 4)) 18444 Map.empty
      localAddrList 0 t `shouldBe` [LocalAddress (ip4 (1, 2, 3, 4)) 18444 4]
      localAddrAddManual (ip4 (192, 168, 1, 1)) 18444 Map.empty `shouldBe` Nothing

  describe "GetLocalAddrForPeer" $ do
    let seen = NetworkAddress 0 (ip4 (5, 6, 7, 8)) 51234
        peer = Just (ip4 (9, 9, 9, 9))
        best = Just (LocalAddress (ip4 (1, 2, 3, 4)) 8338 4)
    it "no table entry: uses the peer's view, with OUR listen port for outbound" $
      chooseLocalAddrForPeer True 8338 Nothing False peer (Just seen) 1
        `shouldBe` Just (ip4 (5, 6, 7, 8), 8338)
    it "inbound peer's view carries its port" $
      chooseLocalAddrForPeer True 8338 Nothing True peer (Just seen) 1
        `shouldBe` Just (ip4 (5, 6, 7, 8), 51234)
    it "table entry wins unless the 1/2 roll hits" $ do
      chooseLocalAddrForPeer True 8338 best False peer (Just seen) 1
        `shouldBe` Just (ip4 (1, 2, 3, 4), 8338)
      chooseLocalAddrForPeer True 8338 best False peer (Just seen) 2
        `shouldBe` Just (ip4 (5, 6, 7, 8), 8338)
    it "a loopback peer's view is never used" $
      chooseLocalAddrForPeer True 8338 Nothing False (Just (ip4 (127, 0, 0, 1)))
        (Just seen) 0 `shouldBe` Nothing
    it "discover off: peer view ignored" $
      chooseLocalAddrForPeer False 8338 Nothing False peer (Just seen) 0
        `shouldBe` Nothing

  describe "addr / addrv2 message" $ do
    it "addr carries one entry: our address, services, time, listen port" $
      selfAdvertMessage False 0x409 1_700_000_000 (ip4 (1, 2, 3, 4)) 18444
        `shouldBe` MAddr (Addr [AddrEntry 1_700_000_000
                                  (NetworkAddress 0x409 (ip4 (1, 2, 3, 4)) 18444)])
    it "addrv2 when the peer sent sendaddrv2" $
      selfAdvertMessage True 0x409 7 (ip4 (1, 2, 3, 4)) 18444
        `shouldBe` MAddrV2 (AddrV2Msg [AddrV2 7 0x409 NetIPv4 (BS.pack [1, 2, 3, 4]) 18444])
    it "round-trips through the wire codec" $ do
      let m = selfAdvertMessage False 0x409 7 (ip4 (1, 2, 3, 4)) 18444
          wire = encodeMessage (netMagic regtest) m
      Right hdr <- pure (decodeMessageHeader (BS.take 24 wire))
      decodeMessage (C8.takeWhile (/= '\0') (mhCommand hdr)) (BS.drop 24 wire)
        `shouldBe` Right m

  describe "manager wiring" $ do
    it "outbound addr_recv discovery stores the listen port; loopback peer ignored" $
      withPM 18444 True $ \pm -> do
        now <- pure (1000 :: Int64)
        let recvMe = NetworkAddress 0 (ip4 (76, 38, 7, 169)) 40000
        noteVersionAddrRecv pm (v4 (8, 8, 8, 8) 8333) False (mkVersion recvMe) now
        noteVersionAddrRecv pm (v4 (9, 9, 9, 9) 8333) False (mkVersion recvMe) now
        noteVersionAddrRecv pm (v4 (127, 0, 0, 1) 8333) False
          (mkVersion (NetworkAddress 0 (ip4 (3, 3, 3, 3)) 1)) now
        tbl <- readTVarIO (pmLocalAddrs pm)
        Map.keys tbl `shouldBe` [ip4 (76, 38, 7, 169)]
        fmap laePort (Map.lookup (ip4 (76, 38, 7, 169)) tbl) `shouldBe` Just 18444
        fmap (Set.size . laeConfirmers) (Map.lookup (ip4 (76, 38, 7, 169)) tbl)
          `shouldBe` Just 2
    it "discover off: addr_recv is not learned" $
      withPM 18444 False $ \pm -> do
        noteVersionAddrRecv pm (v4 (8, 8, 8, 8) 8333) False
          (mkVersion (NetworkAddress 0 (ip4 (76, 38, 7, 169)) 1)) 0
        readTVarIO (pmLocalAddrs pm) >>= (`shouldBe` Map.empty)
    it "--externalip with port 0 takes the listen port" $
      withPM 18444 False $ \pm -> do
        addExternalIP pm (ip4 (1, 2, 3, 4)) 0 >>= (`shouldBe` True)
        addExternalIP pm (ip4 (10, 0, 0, 1)) 0 >>= (`shouldBe` False)
        getLocalAddresses pm >>= (`shouldBe` [LocalAddress (ip4 (1, 2, 3, 4)) 18444 4])
    it "not listening: --externalip is refused" $
      withPM 0 False $ \pm ->
        addExternalIP pm (ip4 (1, 2, 3, 4)) 0 >>= (`shouldBe` False)

  describe "IBD gate and send" $ do
    it "held during IBD, sent (addr, listen port) once IBD ends" $
      withPM 18444 False $ \pm -> do
        _ <- addExternalIP pm (ip4 (1, 2, 3, 4)) 0
        ibd <- newIORef True
        setSelfAdvIBDCheck pm (readIORef ibd)
        withPeer pm (v4 (8, 8, 8, 8) 8333) False False $ \pc other -> do
          selfAdvOnHandshake pm (v4 (8, 8, 8, 8) 8333) pc 0x409
            (mkVersion (NetworkAddress 0 BS.empty 0)) True
          readAddrMsg other 300_000 >>= (`shouldBe` Nothing)
          st <- Map.lookup (v4 (8, 8, 8, 8) 8333) <$> readTVarIO (pmSelfAdvPeers pm)
          fmap sapNextSend st `shouldBe` Just Nothing   -- timer untouched
          writeIORef ibd False
          selfAdvTick pm
          m <- readAddrMsg other 2_000_000
          case m of
            Just (MAddr (Addr [AddrEntry _ na])) -> do
              naAddress na `shouldBe` ip4 (1, 2, 3, 4)
              naPort na `shouldBe` 18444
              naServices na `shouldBe` 0x409
            other' -> expectationFailure ("expected one-entry addr, got " ++ show other')
          -- Poisson timer armed: a second tick sends nothing.
          selfAdvTick pm
          readAddrMsg other 300_000 >>= (`shouldBe` Nothing)
    it "addrv2 to a sendaddrv2 peer" $
      withPM 18444 False $ \pm -> do
        _ <- addExternalIP pm (ip4 (1, 2, 3, 4)) 0
        setSelfAdvIBDCheck pm (pure False)
        withPeer pm (v4 (8, 8, 8, 8) 8333) True False $ \pc other -> do
          selfAdvOnHandshake pm (v4 (8, 8, 8, 8) 8333) pc 0x409
            (mkVersion (NetworkAddress 0 BS.empty 0)) True
          m <- readAddrMsg other 2_000_000
          m `shouldBe` Just (MAddrV2 (AddrV2Msg [AddrV2 (avTime m) 0x409 NetIPv4
                                                  (BS.pack [1, 2, 3, 4]) 18444]))
    it "never to block-relay-only peers" $
      withPM 18444 False $ \pm -> do
        _ <- addExternalIP pm (ip4 (1, 2, 3, 4)) 0
        setSelfAdvIBDCheck pm (pure False)
        withPeer pm (v4 (8, 8, 8, 8) 8333) False True $ \pc other -> do
          selfAdvOnHandshake pm (v4 (8, 8, 8, 8) 8333) pc 0x409
            (mkVersion (NetworkAddress 0 BS.empty 0)) True
          readAddrMsg other 300_000 >>= (`shouldBe` Nothing)
    it "no local address known: nothing sent" $
      withPM 18444 False $ \pm -> do
        setSelfAdvIBDCheck pm (pure False)
        withPeer pm (v4 (8, 8, 8, 8) 8333) False False $ \pc other -> do
          selfAdvOnHandshake pm (v4 (8, 8, 8, 8) 8333) pc 0x409
            (mkVersion (NetworkAddress 0 BS.empty 0)) True
          readAddrMsg other 300_000 >>= (`shouldBe` Nothing)
    it "the manager defaults to IBD until a check is installed" $
      withPM 18444 False $ \pm -> do
        _ <- addExternalIP pm (ip4 (1, 2, 3, 4)) 0
        withPeer pm (v4 (8, 8, 8, 8) 8333) False False $ \pc other -> do
          selfAdvOnHandshake pm (v4 (8, 8, 8, 8) 8333) pc 0x409
            (mkVersion (NetworkAddress 0 BS.empty 0)) True
          readAddrMsg other 300_000 >>= (`shouldBe` Nothing)
  where
    avTime (Just (MAddrV2 (AddrV2Msg [a]))) = av2Time a
    avTime _ = 0

v4 :: (Int, Int, Int, Int) -> Word16 -> SockAddr
v4 (a, b, c, d) p =
  SockAddrInet (fromIntegral p)
    (tupleToHostAddress (fromIntegral a, fromIntegral b, fromIntegral c, fromIntegral d))

mkVersion :: NetworkAddress -> Version
mkVersion recvAddr = Version
  { vVersion = 70016
  , vServices = 0x409
  , vTimestamp = 0
  , vAddrRecv = recvAddr
  , vAddrSend = NetworkAddress 0 (BS.replicate 16 0) 0
  , vNonce = 1
  , vUserAgent = VarString "/test/"
  , vStartHeight = 0
  , vRelay = True
  }

withPM :: Int -> Bool -> (PeerManager -> IO a) -> IO a
withPM listenPort discover act =
  withSystemTempDirectory "haskoin-selfadv" $ \dir -> do
    let cfg = defaultPeerManagerConfig
          { pmcDataDir = dir
          , pmcDnsSeed = False
          , pmcMaxOutbound = 0
          , pmcMaxBlockRelayOnly = 0
          , pmcListenPort = listenPort
          , pmcDiscover = discover
          }
    bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager act

-- | Register a connected peer backed by a socket pair; the other end is
-- handed to the test to read what we sent.
withPeer :: PeerManager -> SockAddr -> Bool -> Bool
         -> (PeerConnection -> Socket -> IO a) -> IO a
withPeer pm addr wantsV2 blockOnly act =
  bracket (socketPair AF_UNIX Stream defaultProtocol)
          (\(a, b) -> close a >> close b) $ \(sock, other) -> do
    infoVar <- newTVarIO (mkInfo addr wantsV2 blockOnly)
    sendLock <- newMVar ()
    recvQ <- newTBQueueIO 16
    bufRef <- newIORef BS.empty
    v2Ref <- newIORef Nothing
    fbRef <- newIORef Nothing
    let pc = PeerConnection
          { pcSocket = sock, pcInfo = infoVar, pcSendLock = sendLock
          , pcRecvQueue = recvQ, pcSendThread = Nothing, pcRecvThread = Nothing
          , pcNetwork = pmNetwork pm, pcReadBuffer = bufRef
          , pcV2Transport = v2Ref, pcBlockFirstByteAt = fbRef }
    atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc)
    act pc other

-- | Read framed messages until an addr/addrv2 arrives or the budget runs out.
-- Other traffic (e.g. a manager-loop ping) is skipped.
readAddrMsg :: Socket -> Int -> IO (Maybe Message)
readAddrMsg sock micros = fmap (either (const Nothing) id) . fmap maybeToEither $
  timeout micros (loop BS.empty)
  where
    maybeToEither = maybe (Left ()) Right
    loop buf
      | BS.length buf >= 24
      , Right hdr <- decodeMessageHeader (BS.take 24 buf)
      , BS.length buf >= 24 + fromIntegral (mhLength hdr) = do
          let cmd = C8.takeWhile (/= '\0') (mhCommand hdr)
              payload = BS.take (fromIntegral (mhLength hdr)) (BS.drop 24 buf)
              rest = BS.drop (24 + fromIntegral (mhLength hdr)) buf
          case decodeMessage cmd payload of
            Right m@(MAddr _)   -> pure (Just m)
            Right m@(MAddrV2 _) -> pure (Just m)
            _                   -> loop rest
      | otherwise = do
          chunk <- recv sock 65536
          if BS.null chunk then pure Nothing else loop (buf <> chunk)

mkInfo :: SockAddr -> Bool -> Bool -> PeerInfo
mkInfo a wantsV2 blockOnly =
  PeerInfo
    { piAddress = a
    , piVersion = Nothing
    , piState = PeerConnected
    , piServices = 0
    , piStartHeight = 0
    , piRelay = True
    , piLastSeen = 9_999_999_999
    , piLastPing = Nothing
    , piPingLatency = Nothing
    , piBanScore = 0
    , piBytesSent = 0
    , piBytesRecv = 0
    , piMsgsSent = 0
    , piMsgsRecv = 0
    , piConnectedAt = 0
    , piTimeOffset = 0
    , piInbound = False
    , piWantsAddrV2 = wantsV2
    , piWantsHeaders = False
    , piFeeFilterReceived = 0
    , piFeeFilterSent = 0
    , piNextFeeFilterSend = 0
    , piBlockOnly = blockOnly
    , piUnconnectingHeaders = 0
    , piNoBan = False
    , piIsManual = False
    , piIsLocal = False
    , piWtxidRelay = False
    , piProvidesCmpct = False
    , piCmpctHBFrom = False
    , piGetaddrRecvd = False
    , piAddrTokenBucket = 1.0
    , piAddrTokenTimestamp = 0
    }

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W203 VERSION/VERACK handshake — Bitcoin Core parity.
--
-- Reference: bitcoin-core/src/net_processing.cpp
--   * :3619  @if (nVersion < MIN_PEER_PROTO_VERSION)@ — the ONLY version
--     floor (31800, node/protocol_version.h:18), inbound and outbound.
--   * :3700-3738 WTXIDRELAY / SENDADDRV2 only when common version >= 70016.
--   * :3864 SENDCMPCT >= 70014, :5525 SENDHEADERS >= 70012,
--     :5543 FEEFILTER >= 70013.
--   * :3894-3960 SENDHEADERS / SENDCMPCT / WTXIDRELAY / SENDADDRV2 are
--     PROCESSED before verack; :4009-4012 every other message before
--     verack is logged and ignored (no disconnect, no misbehaviour).
--
-- Pre-fix haskoin refused every peer below 70015 ("Protocol version too
-- low"), sent sendaddrv2/sendheaders/sendcmpct/feefilter to peers that
-- cannot parse them, and dropped pre-verack wtxidrelay/sendheaders/
-- sendcmpct on the floor (so piWtxidRelay was never set for a Core peer,
-- which sends wtxidrelay before verack).
--
-- Part A drives the real 'performHandshake' over a socketpair; the far
-- end is a hand-rolled peer. Part B pins the pure helpers.
module W203HandshakeCoreParitySpec (spec) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (newEmptyMVar, newMVar, putMVar, takeMVar)
import Control.Concurrent.STM (newTVarIO, newTBQueueIO, readTVarIO)
import Control.Exception (SomeException, try)
import Data.IORef (newIORef)
import qualified Data.ByteString as BS
import Data.Int (Int32)
import Data.Serialize (runGet, getWord32le)
import System.Timeout (timeout)
import Test.Hspec

import Network.Socket
  ( Socket, SockAddr(..), socketPair, Family(AF_UNIX), SocketType(Stream)
  , tupleToHostAddress, close )
import Network.Socket.ByteString (recv, sendAll)

import Haskoin.Consensus (regtest, netMagic)
import Haskoin.Types (NetworkAddress(..), VarString(..), Hash256(..), BlockHash(..))
import Haskoin.Network

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

peerAddr :: SockAddr
peerAddr = SockAddrInet 18444 (tupleToHostAddress (127, 0, 0, 1))

freshInfo :: PeerInfo
freshInfo = PeerInfo
  { piAddress             = peerAddr
  , piVersion             = Nothing
  , piState               = PeerConnecting
  , piServices            = 0
  , piStartHeight         = 0
  , piRelay               = True
  , piLastSeen            = 0
  , piLastPing            = Nothing
  , piPingLatency         = Nothing
  , piBanScore            = 0
  , piBytesSent           = 0
  , piBytesRecv           = 0
  , piMsgsSent            = 0
  , piMsgsRecv            = 0
  , piConnectedAt         = 0
  , piTimeOffset          = 0
  , piInbound             = True
  , piWantsAddrV2         = False
  , piWantsHeaders        = False
  , piFeeFilterReceived   = 0
  , piFeeFilterSent       = 0
  , piNextFeeFilterSend   = 0
  , piBlockOnly           = False
  , piUnconnectingHeaders = 0
  , piNoBan               = False
  , piIsManual            = False
  , piIsLocal             = True
  , piWtxidRelay          = False
  , piProvidesCmpct       = False
  , piCmpctHBFrom         = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | Our end as a PeerConnection, plus the far (hand-rolled peer) socket.
mkConn :: IO (PeerConnection, Socket)
mkConn = do
  (ours, far) <- socketPair AF_UNIX Stream 0
  infoVar  <- newTVarIO freshInfo
  sendLock <- newMVar ()
  recvQ    <- newTBQueueIO 100
  bufRef   <- newIORef BS.empty
  v2Ref    <- newIORef Nothing
  fbRef    <- newIORef Nothing
  return ( PeerConnection
             { pcSocket      = ours
             , pcInfo        = infoVar
             , pcSendLock    = sendLock
             , pcRecvQueue   = recvQ
             , pcSendThread  = Nothing
             , pcRecvThread  = Nothing
             , pcNetwork     = regtest
             , pcReadBuffer  = bufRef
             , pcV2Transport = v2Ref
             , pcBlockFirstByteAt = fbRef
             }
         , far )

-- | The far peer's VERSION at protocol @v@ (services 1 = NODE_NETWORK
-- only below 70015, as a real old node would advertise).
farVersion :: Int32 -> Version
farVersion v = Version
  { vVersion     = v
  , vServices    = if v < 70015 then 1 else 9
  , vTimestamp   = 1_700_000_000
  , vAddrRecv    = NetworkAddress 0 (BS.replicate 16 0) 0
  , vAddrSend    = NetworkAddress 0 (BS.replicate 16 0) 0
  , vNonce       = 12345
  , vUserAgent   = VarString "/BTC-Nodes:test/Sonar/"
  , vStartHeight = 0
  , vRelay       = False
  }

send' :: Socket -> Message -> IO ()
send' s m = sendAll s (encodeMessage (netMagic regtest) m)

recvN :: Socket -> Int -> IO (Maybe BS.ByteString)
recvN s n = go BS.empty
  where
    go acc
      | BS.length acc >= n = return (Just acc)
      | otherwise = do
          c <- recv s (n - BS.length acc)
          if BS.null c then return Nothing else go (acc <> c)

-- | Read one framed message from the far socket; its command name.
recvCmd :: Socket -> IO (Maybe BS.ByteString)
recvCmd s = do
  mh <- recvN s 24
  case mh of
    Nothing -> return Nothing
    Just h -> do
      let cmd = BS.takeWhile (/= 0) (BS.take 12 (BS.drop 4 h))
          len = either (const 0) fromIntegral
                  (runGet getWord32le (BS.take 4 (BS.drop 16 h)))
      _ <- if len > 0 then recvN s len else return (Just BS.empty)
      return (Just cmd)

-- | Collect command names until @stop@ is seen (inclusive), 3 s budget.
recvUntil :: Socket -> BS.ByteString -> IO [BS.ByteString]
recvUntil s stop = maybe [] id <$> timeout 3_000_000 (go [])
  where
    go acc = do
      m <- recvCmd s
      case m of
        Nothing -> return (reverse acc)
        Just c | c == stop -> return (reverse (c : acc))
               | otherwise -> go (c : acc)

-- | Everything that arrives within @us@ microseconds.
recvFor :: Int -> Socket -> IO [BS.ByteString]
recvFor us s = go []
  where
    go acc = do
      m <- timeout us (recvCmd s)
      case m of
        Just (Just c) -> go (c : acc)
        _             -> return (reverse acc)

-- | Run 'performHandshake' on our end; the far peer sends VERSION(v),
-- reads up to our VERACK, sends @pre@ (between VERSION and VERACK),
-- then VERACK. Returns (handshake result, cmds before our verack
-- inclusive, cmds after, final PeerInfo).
driveHandshake
  :: Int32 -> [Message]
  -> IO (Either String Version, [BS.ByteString], [BS.ByteString], PeerInfo)
driveHandshake v pre = do
  (pc, far) <- mkConn
  done <- newEmptyMVar
  _ <- forkIO $ do
    r <- try (performHandshake (defaultPeerConfig regtest) pc)
    putMVar done (either (\(e :: SomeException) -> Left (show e)) id r)
  send' far (MVersion (farVersion v))
  before <- recvUntil far "verack"
  mapM_ (send' far) pre
  send' far MVerAck
  mres <- timeout 5_000_000 (takeMVar done)
  after <- recvFor 300_000 far
  info <- readTVarIO (pcInfo pc)
  close far
  close (pcSocket pc)
  return (maybe (Left "handshake did not finish") id mres, before, after, info)

isRight' :: Either a b -> Bool
isRight' = either (const False) (const True)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W203 handshake Core parity (MIN_PEER_PROTO_VERSION, pre-verack)" $ do

  describe "Part A — live performHandshake over a socketpair" $ do

    it "an inbound VERSION(70002) completes the handshake (Core floor is 31800)" $ do
      (r, _, _, info) <- driveHandshake 70002 []
      isRight' r `shouldBe` True
      piState info `shouldBe` PeerConnected
      fmap vVersion (piVersion info) `shouldBe` Just 70002

    it "a 70002 peer is sent only version+verack — nothing it cannot parse" $ do
      (_, before, after, _) <- driveHandshake 70002 []
      before `shouldBe` ["version", "verack"]
      after `shouldBe` []

    it "a 70016 peer gets wtxidrelay+sendaddrv2 before verack, then sendheaders+sendcmpct" $ do
      (_, before, after, _) <- driveHandshake 70016 []
      before `shouldBe` ["version", "wtxidrelay", "sendaddrv2", "verack"]
      -- farVersion sets relay=False, so no feefilter (Core: no tx relay).
      after `shouldBe` ["sendheaders", "sendcmpct"]

    it "a 70013 peer gets sendheaders only (no sendcmpct/wtxidrelay/sendaddrv2)" $ do
      (_, before, after, _) <- driveHandshake 70013 []
      before `shouldBe` ["version", "verack"]
      after `shouldBe` ["sendheaders"]

    it "a peer below MIN_PEER_PROTO_VERSION (31799) is still refused" $ do
      (r, _, _, _) <- driveHandshake 31799 []
      r `shouldBe` Left "Protocol version too low"

    it "pre-verack sendheaders is RECORDED and does not disconnect" $ do
      (r, _, _, info) <- driveHandshake 70016 [MSendHeaders]
      isRight' r `shouldBe` True
      piWantsHeaders info `shouldBe` True

    it "pre-verack wtxidrelay (common >= 70016) is recorded" $ do
      (r, _, _, info) <- driveHandshake 70016 [MWtxidRelay]
      isRight' r `shouldBe` True
      piWtxidRelay info `shouldBe` True

    it "pre-verack sendcmpct(1, 2) is recorded as provides + high-bandwidth" $ do
      (r, _, _, info) <- driveHandshake 70016 [MSendCmpct (SendCmpct True 2)]
      isRight' r `shouldBe` True
      piProvidesCmpct info `shouldBe` True
      piCmpctHBFrom info `shouldBe` True

    it "pre-verack ping / inv / feefilter / getheaders are ignored, no disconnect" $ do
      let junk = [ MPing (Ping 7)
                 , MInv (Inv [])
                 , MFeeFilter (FeeFilter 1000)
                 , MPing (Ping 8)
                 ]
      (r, _, after, info) <- driveHandshake 70016 (junk ++ [MSendHeaders] ++ junk)
      isRight' r `shouldBe` True
      piState info `shouldBe` PeerConnected
      piWantsHeaders info `shouldBe` True
      -- ignored, not answered: no pong went out
      ("pong" `elem` after) `shouldBe` False

  describe "Part B — pure helpers" $ do
    it "minProtocolVersion is Core MIN_PEER_PROTO_VERSION (31800)" $
      minProtocolVersion `shouldBe` 31800

    it "preVerackReplies gates wtxidrelay/sendaddrv2 at 70016" $ do
      map commandName (preVerackReplies 70002) `shouldBe` ["verack"]
      map commandName (preVerackReplies 70015) `shouldBe` ["verack"]
      map commandName (preVerackReplies 70016)
        `shouldBe` ["wtxidrelay", "sendaddrv2", "verack"]

    it "postVerackFeatureMessages gates at 70012 / 70014 / 70013(+relay)" $ do
      map commandName (postVerackFeatureMessages 70011 True) `shouldBe` []
      map commandName (postVerackFeatureMessages 70012 True) `shouldBe` ["sendheaders"]
      map commandName (postVerackFeatureMessages 70013 True)
        `shouldBe` ["sendheaders", "feefilter"]
      map commandName (postVerackFeatureMessages 70016 True)
        `shouldBe` ["sendheaders", "sendcmpct", "feefilter"]
      map commandName (postVerackFeatureMessages 70016 False)
        `shouldBe` ["sendheaders", "sendcmpct"]

    it "recordPreVerackMessage ignores wtxidrelay below 70016 (Core :3928)" $
      piWtxidRelay (recordPreVerackMessage 70015 MWtxidRelay freshInfo) `shouldBe` False

    it "recordSendCmpct ignores sendcmpct version 1 (Core :3907)" $
      piProvidesCmpct (recordSendCmpct (SendCmpct True 1) freshInfo) `shouldBe` False

    it "recordPreVerackMessage leaves unsupported messages untouched" $ do
      let i' = recordPreVerackMessage 70016 (MPing (Ping 1)) freshInfo
      (piWantsHeaders i', piWtxidRelay i', piWantsAddrV2 i', piProvidesCmpct i')
        `shouldBe` (False, False, False, False)

    it "blocks are only requested from NODE_WITNESS peers (Core CanServeWitnesses)" $ do
      let h   = Hash256 (BS.replicate 32 1)
          blk = MGetData (GetData [InvVector InvWitnessBlock h])
          tx  = MGetData (GetData [InvVector InvWitnessTx h])
      blockRequestAllowed 1 blk `shouldBe` False   -- NODE_NETWORK only
      blockRequestAllowed 9 blk `shouldBe` True    -- NETWORK|WITNESS
      blockRequestAllowed 1 tx  `shouldBe` True    -- tx getdata is not gated
      blockRequestAllowed 1 (MGetBlockTxn (GetBlockTxn (BlockHash h) [])) `shouldBe` False

    it "outbound peers still need NODE_NETWORK|NODE_WITNESS" $ do
      outboundHasDesirableServices 1 `shouldBe` False
      outboundHasDesirableServices 8 `shouldBe` False
      outboundHasDesirableServices 9 `shouldBe` True

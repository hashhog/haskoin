{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W188 inbound-ping -> pong (BIP-0031 keep-alive).
--
-- Reference:
--   * bitcoin-core/src/net_processing.cpp — ProcessMessage, PING branch:
--       @vRecv >> nonce; MakeAndPushMessage(pfrom, NetMsgType::PONG, nonce);@
--     and the TIMEOUT_INTERVAL (20 min) that disconnects a peer which never
--     receives a pong for its outstanding ping.
--
-- Gap this pins: haskoin's 'syncMessageHandler' MPing arm used to be
-- @return ()@ (a comment claimed "Pong handled at peer level", but there was
-- no peer-level responder), so inbound pings were never answered and peers
-- would drop us on their ping timeout.  The fix answers each ping with
-- @requestFromPeer pm addr (pongForPing ping)@.
--
-- Tests:
--   * Part A (pure 'pongForPing'): the reply is a pong whose nonce is the
--     ping's nonce, byte-for-byte — including the boundary nonces 0 and
--     maxBound — and distinct nonces map to distinct pongs (guards against a
--     constant/zero echo, the classic "no pong" liveness bug).
--   * Part B (live wire): a real 'PeerConnection' over a socketpair injected
--     into a real 'PeerManager'; the exact bytes 'syncMessageHandler' puts on
--     the wire for an inbound ping (@requestFromPeer pm addr (pongForPing p)@)
--     are observed to be a framed pong carrying the matching nonce, and a
--     different nonce yields different bytes.
module W188InboundPongSpec (spec) where

import Control.Concurrent.MVar (newMVar)
import Test.Hspec

import Control.Concurrent.STM (atomically, newTVarIO, modifyTVar', newTBQueueIO)
import Data.IORef (newIORef)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word64)

import Network.Socket
  ( Socket, SockAddr(..), socketPair, Family(AF_UNIX), SocketType(Stream)
  , tupleToHostAddress, close )
import Network.Socket.ByteString (recv)

import Haskoin.Consensus (regtest, netMagic)
import Haskoin.Network
  ( PeerManager(..), PeerConnection(..), PeerInfo(..), PeerState(..)
  , Message(..), Ping(..), Pong(..), pongForPing
  , startPeerManager, stopPeerManager, requestFromPeer
  , defaultPeerManagerConfig, encodeMessage )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

addr0, addr1 :: SockAddr
addr0 = SockAddrInet 18444 (tupleToHostAddress (127, 0, 0, 1))
addr1 = SockAddrInet 18445 (tupleToHostAddress (127, 0, 0, 2))

-- | A minimal PeerInfo (only the address matters for these tests).
mkInfo :: SockAddr -> PeerInfo
mkInfo a = PeerInfo
  { piAddress             = a
  , piVersion             = Nothing
  , piState               = PeerConnected
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
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | Build a live PeerConnection over one end of a socketpair.  Returns the
--   connection (whose pcSocket is the writer end) and the reader socket (the
--   far end), so a caller can observe exactly what 'sendMessage' writes.
mkLiveConn :: SockAddr -> IO (PeerConnection, Socket)
mkLiveConn a = do
  (writerEnd, readerEnd) <- socketPair AF_UNIX Stream 0
  infoVar <- newTVarIO (mkInfo a)
  sendLock <- newMVar ()
  recvQ   <- newTBQueueIO 100
  bufRef  <- newIORef BS.empty
  v2Ref   <- newIORef Nothing
  let pc = PeerConnection
             { pcSocket      = writerEnd
             , pcInfo        = infoVar
             , pcSendLock    = sendLock
             , pcRecvQueue   = recvQ
             , pcSendThread  = Nothing
             , pcRecvThread  = Nothing
             , pcNetwork     = regtest
             , pcReadBuffer  = bufRef
             , pcV2Transport = v2Ref
             }
  return (pc, readerEnd)

-- | The expected framed pong the handler sends for an inbound ping nonce.
expectedPongBytes :: Word64 -> BS.ByteString
expectedPongBytes n = encodeMessage (netMagic regtest) (MPong (Pong n))

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W188 inbound ping -> pong (BIP-0031 keep-alive)" $ do

  ------------------------------------------------------------------------------
  -- Part A — pure reply construction (pongForPing echoes the nonce)
  ------------------------------------------------------------------------------
  describe "pongForPing (Core PING -> PONG(nonce))" $ do
    it "answers a ping with a pong carrying the SAME nonce" $
      pongForPing (Ping 0x0123456789ABCDEF)
        `shouldBe` MPong (Pong 0x0123456789ABCDEF)

    it "echoes the zero nonce unchanged (not treated as \"absent\")" $
      pongForPing (Ping 0) `shouldBe` MPong (Pong 0)

    it "echoes the maxBound nonce unchanged" $
      pongForPing (Ping maxBound) `shouldBe` MPong (Pong maxBound)

    it "distinct ping nonces produce distinct pongs (never a constant echo)" $ do
      let a = pongForPing (Ping 1)
          b = pongForPing (Ping 2)
      a `shouldNotBe` b

    it "always yields a pong, never a ping (no message-type confusion)" $
      case pongForPing (Ping 42) of
        MPong _ -> True `shouldBe` True
        other   -> expectationFailure ("expected MPong, got " ++ show other)

  ------------------------------------------------------------------------------
  -- Part B — live wire: the handler's ping-reply send lands a framed pong,
  -- with the matching nonce, on the pinging peer's socket (socketpair seam).
  ------------------------------------------------------------------------------
  describe "inbound ping -> framed pong on the pinging peer's wire" $ do

    it "writes a byte-exact pong echoing the nonce to the pinging peer" $ do
      let nonce = 0xDEADBEEFCAFEF00D :: Word64
      pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
      (conn, reader) <- mkLiveConn addr0
      atomically $ modifyTVar' (pmPeers pm) (Map.insert addr0 conn)

      -- Exactly what syncMessageHandler's MPing arm now runs.
      requestFromPeer pm addr0 (pongForPing (Ping nonce))

      let expected = expectedPongBytes nonce
      got <- recv reader (BS.length expected)
      got `shouldBe` expected

      close reader
      stopPeerManager pm

    it "a different ping nonce puts different bytes on the wire" $ do
      pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
      (conn, reader) <- mkLiveConn addr0
      atomically $ modifyTVar' (pmPeers pm) (Map.insert addr0 conn)

      requestFromPeer pm addr0 (pongForPing (Ping 7))
      let expected = expectedPongBytes 7
      got <- recv reader (BS.length expected)
      got `shouldBe` expected
      got `shouldNotBe` expectedPongBytes 8   -- would be a wrong-nonce pong

      close reader
      stopPeerManager pm

    it "is a no-op when the pinging addr is not in pmPeers (peer already gone)" $ do
      pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
      (_conn, reader) <- mkLiveConn addr1
      -- addr1 is never inserted, so the reply must be dropped silently.
      requestFromPeer pm addr1 (pongForPing (Ping 99))
      close reader
      stopPeerManager pm

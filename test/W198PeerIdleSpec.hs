{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | Peers that complete a v2 handshake must not be banned for going quiet.
--
-- Live 2026-09-24 (pid on deploy/haskoin 2ab99af, up 5.0 d): getconnectioncount
-- 0, ~1.03e6 connect attempts, and the post-handshake line
--
--   Peer <ip>:8333 misbehavior: MalformedMessage
--     (v2: v2: connection closed reading length)
--
-- 4,479 v2 handshakes paired with that misbehavior. A second dial of the
-- same address landed ~23 h later — pmcBanDuration. The recv loop only
-- exempted the capitalised v1 spelling "Connection closed", so every v2
-- hangup (including a 60 s recvExact idle, shorter than the 120 s ping
-- interval) was MalformedMessage and banPeer'd for 24 h. peerManagerLoop
-- also dropped a peer after 300 s of silence, which is shorter than one
-- block connect at height ~910 k, so the handler died with
-- "thread killed" mid-block.
--
-- Control: cabal run haskoin-test --enable-tests -- -m 'peer-idle'
--
-- Reference: bitcoin-core/src/net.h TIMEOUT_INTERVAL (20 min) and
-- net.cpp InactivityCheck — a quiet peer is disconnected, never banned.
module W198PeerIdleSpec (spec) where

import Control.Exception (bracket)
import Data.List (isInfixOf)
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Network.Socket (SockAddr (..), tupleToHostAddress)

import Haskoin.Consensus (regtest)
import Haskoin.Network
  ( PeerInfo (..)
  , PeerManagerConfig (..)
  , PeerState (..)
  , defaultPeerManagerConfig
  , insertTestPeer
  , isBanned
  , peerSilentTooLong
  , pingTimeout
  , recvErrorIsMisbehavior
  , recvIdleTimeoutMicros
  , scoreRecvError
  , startPeerManager
  , stopPeerManager
  )

spec :: Spec
spec = describe "peer-idle" $ do
  it "a v2 hangup is not misbehavior" $ do
    recvErrorIsMisbehavior "v2: v2: connection closed reading length"
      `shouldBe` False
    recvErrorIsMisbehavior "v2: connection closed reading payload"
      `shouldBe` False
    recvErrorIsMisbehavior "Connection closed" `shouldBe` False
    recvErrorIsMisbehavior "Connection closed during payload" `shouldBe` False
    recvErrorIsMisbehavior "closed before sending data" `shouldBe` False

  it "checksum and oversize frames are still misbehavior" $ do
    recvErrorIsMisbehavior "Checksum mismatch" `shouldBe` True
    recvErrorIsMisbehavior "v2: payload too large" `shouldBe` True
    recvErrorIsMisbehavior "Header parse error: short" `shouldBe` True
    recvErrorIsMisbehavior "Wrong network magic" `shouldBe` True

  it "idle budget is Core's 20 min, not 60 s and not 300 s" $ do
    -- Longer than the 120 s ping interval, so a peer that only pings
    -- is still connected when the ping arrives. Longer than the old
    -- 300 s stale cutoff, so a block connect at height ~910 k is not
    -- killThread'd mid-handler.
    pingTimeout `shouldBe` 1200
    recvIdleTimeoutMicros `shouldBe` fromIntegral pingTimeout * 1_000_000
    recvIdleTimeoutMicros `shouldSatisfy` (> 60 * 1_000_000)
    peerSilentTooLong 0 301 `shouldBe` False
    peerSilentTooLong 0 1200 `shouldBe` False
    peerSilentTooLong 0 1201 `shouldBe` True

  it "the recv loop and the stale check are wired to that budget" $ do
    src <- readFile "src/Haskoin/Network.hs"
    src `shouldSatisfy` ("timeout recvIdleTimeoutMicros" `isInfixOf`)
    src `shouldSatisfy` ("peerSilentTooLong (piLastSeen info) now" `isInfixOf`)
    -- The old cutoff. A comment may still mention 300; the comparison
    -- itself must be gone.
    not ("now - piLastSeen info > 300" `isInfixOf` src) `shouldBe` True
    mainSrc <- readFile "app/Main.hs"
    mainSrc `shouldSatisfy` ("catchSync" `isInfixOf`)

  it "a v2 close does not ban; a checksum mismatch does" $
    withSystemTempDirectory "haskoin-peer-idle" $ \dir -> do
      let cfg =
            defaultPeerManagerConfig
              { pmcDataDir = dir
              , pmcDnsSeed = False
              , pmcMaxOutbound = 0
              , pmcMaxBlockRelayOnly = 0
              }
          addr = SockAddrInet 8333 (tupleToHostAddress (50, 5, 167, 204))
      bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager $
        \pm -> do
          insertTestPeer pm addr (mkInfo addr)
          scoreRecvError pm addr "v2: v2: connection closed reading length"
          bannedClose <- isBanned pm addr
          bannedClose `shouldBe` False
          scoreRecvError pm addr "Checksum mismatch"
          bannedSum <- isBanned pm addr
          bannedSum `shouldBe` True

-- | Non-local, recently-seen peer. piIsLocal False is required: misbehaving
-- does not ban local addresses. piLastSeen far in the future keeps the
-- manager loop from stale-dropping the fixture before the assertion.
mkInfo :: SockAddr -> PeerInfo
mkInfo a =
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
    , piWantsAddrV2 = False
    , piWantsHeaders = False
    , piFeeFilterReceived = 0
    , piFeeFilterSent = 0
    , piNextFeeFilterSend = 0
    , piBlockOnly = False
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

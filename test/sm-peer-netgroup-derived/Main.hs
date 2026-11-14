{-# LANGUAGE NumericUnderscores #-}

-- | sm-peer-netgroup-derived: an outbound peer's netgroup stops counting
-- towards outbound diversity the moment the peer is gone, whichever path
-- removed it.
--
-- Core: CConnman::ThreadOpenConnections rebuilds outbound_ipv46_peer_netgroups
-- from the live m_nodes on every pass (bitcoin-core/src/net.cpp ~2656-2690),
-- counting only MANUAL / OUTBOUND_FULL_RELAY / BLOCK_RELAY connections.
--
-- On haskoin master only peerManagerLoop released a netgroup, and only for a
-- peer still in pmPeers as PeerDisconnected.  misbehaving, the ping/silence
-- timeouts, the eviction loop and the stall disconnects in app/Main.hs all
-- delete the peer from pmPeers themselves, so its /16 stayed taken for the
-- life of the process.
--
-- The four release tests fail on master; the controls pass on both sides and
-- pin that the fix does not release more than it should.
module Main (main) where

import Test.Hspec
import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO)
import Control.Exception (bracket)
import qualified Data.Map.Strict as Map
import System.IO.Temp (withSystemTempDirectory)
import Network.Socket (SockAddr (..), tupleToHostAddress)

import Haskoin.Consensus (regtest)
import Haskoin.Network
  ( startPeerManager, stopPeerManager
  , defaultPeerManagerConfig, PeerManagerConfig(..), PeerManager(..)
  , PeerConnection(..), PeerInfo(..), PeerState(..), MisbehaviorReason(..)
  , insertTestPeer, misbehaving, addOutboundConnection, checkOutboundDiversity )

-- | Non-local, recently-seen outbound peer (SmSweepSpec / W198PeerIdleSpec fixture).
mkInfo :: SockAddr -> PeerInfo
mkInfo a = PeerInfo
  { piAddress = a, piVersion = Nothing, piState = PeerConnected
  , piServices = 0, piStartHeight = 0, piRelay = True
  , piLastSeen = 9_999_999_999, piLastPing = Nothing, piPingLatency = Nothing
  , piBanScore = 0, piBytesSent = 0, piBytesRecv = 0, piMsgsSent = 0
  , piMsgsRecv = 0, piConnectedAt = 0, piTimeOffset = 0, piInbound = False
  , piWantsAddrV2 = False, piWantsHeaders = False, piFeeFilterReceived = 0
  , piFeeFilterSent = 0, piNextFeeFilterSend = 0, piBlockOnly = False
  , piUnconnectingHeaders = 0, piNoBan = False, piIsManual = False
  , piIsLocal = False, piWtxidRelay = False, piProvidesCmpct = False
  , piCmpctHBFrom = False, piGetaddrRecvd = False
  , piAddrTokenBucket = 1.0, piAddrTokenTimestamp = 0
  }

ip :: (Integer, Integer, Integer, Integer) -> SockAddr
ip (a, b, c, d) =
  SockAddrInet 8333 (tupleToHostAddress (fromIntegral a, fromIntegral b, fromIntegral c, fromIntegral d))

-- Two addresses in 50.5.0.0/16, one in another /16.
peerA, peerB, candidate, elsewhere :: SockAddr
peerA     = ip (50, 5, 167, 204)
peerB     = ip (50, 5, 9, 9)
candidate = ip (50, 5, 1, 1)
elsewhere = ip (60, 6, 1, 1)

-- | A peer manager whose loop never dials out.
withPM :: (PeerManager -> IO a) -> IO a
withPM act = withSystemTempDirectory "haskoin-sm-peer-netgroup" $ \dir -> do
  let cfg = defaultPeerManagerConfig
        { pmcDataDir = dir, pmcDnsSeed = False
        , pmcMaxOutbound = 0, pmcMaxBlockRelayOnly = 0 }
  bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager act

-- | Insert a peer and register it the way tryConnect does.
connectOutbound :: PeerManager -> SockAddr -> PeerInfo -> IO ()
connectOutbound pm a info = do
  insertTestPeer pm a info
  addOutboundConnection (pmOutboundDiversity pm) (pmAsmapData pm) a

diverse :: PeerManager -> SockAddr -> IO Bool
diverse pm = checkOutboundDiversity (pmOutboundDiversity pm) (pmAsmapData pm)

setState :: PeerManager -> SockAddr -> PeerState -> IO ()
setState pm a st = do
  peers <- readTVarIO (pmPeers pm)
  case Map.lookup a peers of
    Nothing -> expectationFailure ("peer not in pmPeers: " ++ show a)
    Just pc -> atomically $ modifyTVar' (pcInfo pc) (\i -> i { piState = st })

main :: IO ()
main = hspec $ describe "sm-peer-netgroup-derived" $ do

  -- Release paths: each fails on master (the counter is never decremented).

  it "sm-peer-netgroup-misbehave-releases-at-once: misbehaving releases the netgroup without waiting for the loop" $
    withPM $ \pm -> do
      connectOutbound pm peerA (mkInfo peerA)
      diverse pm candidate `shouldReturn` False
      (_, disconnected) <- misbehaving pm peerA InvalidBlock
      disconnected `shouldBe` True
      -- no wait: Core rebuilds the set from m_nodes on the next pass
      diverse pm candidate `shouldReturn` True

  it "sm-peer-netgroup-local-misbehave-releases: the local-address misbehave path releases the netgroup" $
    withPM $ \pm -> do
      connectOutbound pm peerA ((mkInfo peerA) { piIsLocal = True })
      diverse pm candidate `shouldReturn` False
      (_, disconnected) <- misbehaving pm peerA InvalidBlock
      disconnected `shouldBe` True
      diverse pm candidate `shouldReturn` True

  -- Stands in for the ping/silence timeouts, the eviction loop and the
  -- app/Main.hs stall disconnects: each does disconnectPeer and then
  -- Map.delete on pmPeers.
  it "sm-peer-netgroup-map-delete-releases: a peer deleted from pmPeers by any path releases the netgroup" $
    withPM $ \pm -> do
      connectOutbound pm peerA (mkInfo peerA)
      diverse pm candidate `shouldReturn` False
      atomically $ modifyTVar' (pmPeers pm) (Map.delete peerA)
      diverse pm candidate `shouldReturn` True

  -- Core skips INBOUND connections when it builds the set (an attacker could
  -- make them to keep us out of a netgroup).  The address is registered here
  -- so the test sees the inbound filter itself, not only the registry.
  it "sm-peer-netgroup-inbound-does-not-hold: an inbound peer does not hold the /16, even under a registered address" $
    withPM $ \pm -> do
      connectOutbound pm peerA ((mkInfo peerA) { piInbound = True })
      diverse pm candidate `shouldReturn` True

  -- Controls: pass on master and on the fix.

  it "sm-peer-netgroup-control-other-peer-holds: a second live peer in the same /16 still holds it after the first misbehaves" $
    withPM $ \pm -> do
      connectOutbound pm peerA (mkInfo peerA)
      connectOutbound pm peerB (mkInfo peerB)
      _ <- misbehaving pm peerA InvalidBlock
      diverse pm candidate `shouldReturn` False
      diverse pm elsewhere `shouldReturn` True

  -- Core counts every node in m_nodes, an fDisconnect node included until
  -- DisconnectNodes removes it; haskoin's equivalent is presence in pmPeers.
  it "sm-peer-netgroup-control-in-map-holds: an outbound peer holds the netgroup in every state while it is in pmPeers" $
    withPM $ \pm -> do
      connectOutbound pm peerA (mkInfo peerA)
      mapM_ (\st -> do setState pm peerA st
                       diverse pm candidate `shouldReturn` False)
            [PeerConnecting, PeerHandshaking, PeerConnected, PeerDisconnecting, PeerDisconnected]

  it "sm-peer-netgroup-control-unregistered-does-not-hold: an outbound peer never registered (Tor/I2P host path) does not block the /16" $
    withPM $ \pm -> do
      insertTestPeer pm peerA (mkInfo peerA)
      diverse pm candidate `shouldReturn` True

  it "sm-peer-netgroup-control-reconnect-holds-again: after a release, a new peer in the /16 takes it again" $
    withPM $ \pm -> do
      connectOutbound pm peerA (mkInfo peerA)
      atomically $ modifyTVar' (pmPeers pm) (Map.delete peerA)
      connectOutbound pm peerB (mkInfo peerB)
      diverse pm candidate `shouldReturn` False

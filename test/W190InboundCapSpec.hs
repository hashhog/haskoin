{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W190 inbound-connection admission control (max-inbound cap + eviction +
-- ban on the accept path).
--
-- Reference:
--   * bitcoin-core/src/net.cpp — CConnman::AcceptConnection: refuse banned
--     addresses, refuse discouraged when slots are full, enforce the total and
--     inbound connection limits, and AttemptToEvictConnection when the inbound
--     slots are full but an eviction candidate exists.
--
-- Gap this pins: haskoin HAD the whole ladder written — 'checkPreHandshake'
-- (ban / discouraged / max-total / max-inbound-with-eviction),
-- 'selectEvictionCandidate', 'evictConnection', and the per-netgroup
-- 'maxInboundPerGroup' limiter — but @handleInbound@ called NONE of it: every
-- inbound socket was handshaked and Map.insert'd unconditionally.  Inbound was
-- therefore UNBOUNDED (resource-exhaustion / eclipse DoS surface) and a banned
-- peer could reconnect freely.  The fix wires 'inboundAdmissionDecision' into
-- @handleInbound@ before any handshake or registration.
--
-- These tests drive the socket-free 'inboundAdmissionDecision' (the exact
-- decision @handleInbound@ now consults) plus 'evictConnection', asserting:
--   * the inbound peer count CAPS at pmcMaxInbound as new inbound arrive, and
--     eviction actually fires (pre-fix: unbounded growth);
--   * a banned address is rejected before handshake;
--   * when every inbound peer is protected (NoBan) and slots are full, a new
--     inbound is rejected (no eviction candidate);
--   * the per-netgroup inbound cap ('maxInboundPerGroup') rejects an over-
--     represented /16 while admitting a fresh group.
module W190InboundCapSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM
  (atomically, newTVarIO, modifyTVar', readTVarIO, newTBQueueIO)
import Control.Monad (forM_)
import Data.IORef (newIORef, readIORef, modifyIORef')
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Int (Int64)
import Data.Word (Word8)

import Network.Socket
  ( SockAddr(..), socketPair, Family(AF_UNIX), SocketType(Stream)
  , tupleToHostAddress )

import Haskoin.Consensus (regtest)
import Haskoin.Network
  ( PeerManager(..), PeerConnection(..), PeerInfo(..), PeerState(..)
  , PeerManagerConfig(..)
  , InboundAdmission(..), inboundAdmissionDecision, checkInboundGroupLimit
  , evictConnection, countInboundPeers
  , startPeerManager, stopPeerManager, defaultPeerManagerConfig
  , maxInboundPerGroup )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

-- | An IPv4 SockAddr 10.a.b.1 — @a@ picks the /16 network group.
mkAddr :: Word8 -> Word8 -> SockAddr
mkAddr a b = SockAddrInet 18444 (tupleToHostAddress (10, a, b, 1))

-- | A minimal inbound PeerInfo with a configurable connect-time / NoBan flag.
mkInfo :: SockAddr -> Int64 -> Bool -> PeerInfo
mkInfo a connectedAt noban = PeerInfo
  { piAddress             = a
  , piVersion             = Nothing
  , piState               = PeerConnected
  , piServices            = 0
  , piStartHeight         = 0
  , piRelay               = True
  -- Far-future "last seen" so peerManagerLoop's background staleness reaper
  -- (Network.hs: "Disconnect if no response for 5 minutes",
  --  @now - piLastSeen > 300@) does not race in on its immediate first tick and
  -- drop these fixtures mid-test.  A real connected peer has a recent
  -- piLastSeen; epoch-0 made every fixture look 56 years stale, which reaped the
  -- filled inbound set and dropped the count below the cap (flaky AdmitInbound).
  -- piLastSeen is not used by the eviction scoring, so this only quiets the
  -- background reaper/pinger; it does not affect the admission decision itself.
  , piLastSeen            = 9_999_999_999
  , piLastPing            = Nothing
  , piPingLatency         = Nothing
  , piBanScore            = 0
  , piBytesSent           = 0
  , piBytesRecv           = 0
  , piMsgsSent            = 0
  , piMsgsRecv            = 0
  , piConnectedAt         = connectedAt
  , piTimeOffset          = 0
  , piInbound             = True
  , piWantsAddrV2         = False
  , piWantsHeaders        = False
  , piFeeFilterReceived   = 0
  , piFeeFilterSent       = 0
  , piNextFeeFilterSend   = 0
  , piBlockOnly           = False
  , piUnconnectingHeaders = 0
  , piNoBan               = noban
  , piIsManual            = False
  , piIsLocal             = False
  , piWtxidRelay          = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | Build an inbound PeerConnection over one end of a socketpair (so
-- 'evictConnection' can safely close 'pcSocket') and register it in pmPeers.
addInbound :: PeerManager -> SockAddr -> Int64 -> Bool -> IO ()
addInbound pm a connectedAt noban = do
  (writerEnd, _readerEnd) <- socketPair AF_UNIX Stream 0
  infoVar <- newTVarIO (mkInfo a connectedAt noban)
  sendQ   <- newTBQueueIO 100
  recvQ   <- newTBQueueIO 100
  bufRef  <- newIORef BS.empty
  v2Ref   <- newIORef Nothing
  let pc = PeerConnection
             { pcSocket      = writerEnd
             , pcInfo        = infoVar
             , pcSendQueue   = sendQ
             , pcRecvQueue   = recvQ
             , pcSendThread  = Nothing
             , pcRecvThread  = Nothing
             , pcNetwork     = regtest
             , pcReadBuffer  = bufRef
             , pcV2Transport = v2Ref
             }
  atomically $ modifyTVar' (pmPeers pm) (Map.insert a pc)

-- | A tight config for the "full + all-protected -> hard-refuse" test: exactly
-- 8 inbound slots so filling 8 NoBan peers saturates the cap and the eviction
-- ladder has no removable candidate (every peer is NoBan-protected).
smallConfig :: PeerManagerConfig
smallConfig = defaultPeerManagerConfig
  { pmcMaxInbound = 8
  , pmcMaxTotal   = 12
  }

-- | A realistic-scale config for the cap+eviction test.  The Core-faithful
-- 'applyProtections' ladder protects up to ~4 (netgroup) + 8 (ping) + 4 (tx) +
-- 4 (block) + 50% (longevity) peers, so eviction can only be *demonstrated*
-- when the total inbound set is larger than the sum of those protections.  At 8
-- peers the ladder protects the whole set and the fix correctly hard-refuses
-- (no candidate) — which is real behaviour but not the eviction path we want to
-- exercise here.  40 inbound leaves ~10 unprotected candidates, so eviction
-- fires.  pmcMaxTotal is raised in proportion so the total-connections gate
-- does not trip first.
capConfig :: PeerManagerConfig
capConfig = defaultPeerManagerConfig
  { pmcMaxInbound = 40
  , pmcMaxTotal   = 50
  }

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W190 inbound admission control (cap + eviction + ban)" $ do

  ------------------------------------------------------------------------------
  -- Cap + eviction: inbound count never exceeds pmcMaxInbound, eviction fires.
  ------------------------------------------------------------------------------
  it "caps inbound at pmcMaxInbound and evicts to make room (was UNBOUNDED)" $ do
    pm <- startPeerManager regtest capConfig (\_ _ -> return ())
    -- Fill all 40 inbound slots, spread across 10 /16 groups (4 each) with
    -- distinct (increasing) connect-times.  Scale is the real lever: the
    -- Core-faithful protection ladder shields up to ~4+8+4+4+50% peers, so a
    -- 40-strong set leaves ~10 unprotected eviction candidates.  Spreading
    -- across several groups (rather than one giant group) keeps the set
    -- realistic while still leaving candidates after netgroup protection.
    let cap = pmcMaxInbound capConfig            -- 40
    forM_ [0 .. cap - 1] $ \i ->
      addInbound pm (mkAddr (fromIntegral (i `div` 4)) (fromIntegral (i `mod` 4)))
                    (fromIntegral i) False

    startInbound <- countInboundPeers pm
    startInbound `shouldBe` cap

    -- Now push several MORE inbound arrivals (distinct fresh /16 groups, so the
    -- per-netgroup cap never trips).  Simulate exactly what handleInbound does
    -- with the decision: reject -> drop, admit-after-evicting -> evict then
    -- register, admit -> register.  Because inbound is saturated at the cap and
    -- ~10 candidates survive the protection ladder, every arrival should take
    -- the evict-then-admit path.
    evictionsRef <- newIORef (0 :: Int)
    forM_ [100 .. 107] $ \i -> do
      let a = mkAddr i 0
      decision <- inboundAdmissionDecision pm a
      case decision of
        RejectInbound _ -> return ()
        AdmitInbound    -> addInbound pm a (fromIntegral i) False
        AdmitInboundAfterEvicting _ -> do
          evicted <- evictConnection pm
          case evicted of
            Nothing -> return ()   -- eviction raced away: refuse (no overflow)
            Just _  -> do
              modifyIORef' evictionsRef (+ 1)
              addInbound pm a (fromIntegral i) False
      -- Bounded/DoS invariant after every arrival: inbound never exceeds the cap.
      n <- countInboundPeers pm
      n `shouldSatisfy` (<= cap)

    -- Eviction must actually have fired (otherwise "cap" would just be a
    -- hard-refuse, which is the weaker lunarblock behaviour, not Core's).
    evictions <- readIORef evictionsRef
    evictions `shouldSatisfy` (> 0)

    finalInbound <- countInboundPeers pm
    finalInbound `shouldBe` cap
    stopPeerManager pm

  ------------------------------------------------------------------------------
  -- Banned address is rejected before any handshake.
  ------------------------------------------------------------------------------
  it "rejects a banned address on the accept path" $ do
    pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
    let bad = mkAddr 42 0
    -- Ban with a far-future expiry.
    atomically $ modifyTVar' (pmBannedAddrs pm) (Map.insert bad 99_999_999_999)
    decision <- inboundAdmissionDecision pm bad
    case decision of
      RejectInbound _ -> return ()
      other -> expectationFailure ("expected RejectInbound for banned addr, got " ++ show other)
    stopPeerManager pm

  ------------------------------------------------------------------------------
  -- All inbound protected (NoBan) + slots full -> reject (no eviction victim).
  ------------------------------------------------------------------------------
  it "rejects a new inbound when slots are full and every peer is protected" $ do
    pm <- startPeerManager regtest smallConfig (\_ _ -> return ())
    forM_ [0 .. 7] $ \i ->
      addInbound pm (mkAddr i 0) (fromIntegral i) True   -- NoBan => never evictable
    decision <- inboundAdmissionDecision pm (mkAddr 200 0)
    case decision of
      RejectInbound _ -> return ()
      other -> expectationFailure ("expected RejectInbound (no eviction candidate), got " ++ show other)
    stopPeerManager pm

  ------------------------------------------------------------------------------
  -- Per-netgroup cap: an over-represented /16 is rejected; a fresh group ok.
  ------------------------------------------------------------------------------
  it "enforces the per-netgroup inbound cap (maxInboundPerGroup)" $ do
    pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
    -- Fill one /16 (10.5.0.0/16) right up to the per-group cap.
    forM_ [1 .. fromIntegral maxInboundPerGroup] $ \b ->
      addInbound pm (mkAddr 5 b) 0 False

    -- A further inbound from the SAME /16 must be refused (eclipse guard) ...
    groupOk <- checkInboundGroupLimit pm (mkAddr 5 200)
    groupOk `shouldBe` False
    sameGroup <- inboundAdmissionDecision pm (mkAddr 5 200)
    case sameGroup of
      RejectInbound _ -> return ()
      other -> expectationFailure ("expected RejectInbound for full netgroup, got " ++ show other)

    -- ... while a peer from a DIFFERENT /16 is still admitted (plenty of room).
    otherOk <- checkInboundGroupLimit pm (mkAddr 6 1)
    otherOk `shouldBe` True
    diffGroup <- inboundAdmissionDecision pm (mkAddr 6 1)
    diffGroup `shouldBe` AdmitInbound
    stopPeerManager pm

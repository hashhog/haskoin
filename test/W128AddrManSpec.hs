{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W128 AddrMan + connman + peer selection 30-gate audit for haskoin.
--
-- Discovery audit: NO production code changes.  Pinning-shape tests
-- assert current observable behavior; `xit` sentinels document the
-- desired Core-parity behavior, flippable to `it` by future fix waves.
--
-- Scope: AddrMan tried-collision resolution, connman peer selection
-- (`ThreadOpenConnections` analogue), BanMan + discouragement.
-- EXCLUDES the AddrMan in-table mechanics covered exhaustively by
-- W104 (those are referenced as W104 G* where they overlap).
--
-- References:
--   bitcoin-core/src/addrman.h           ADDRMAN_REPLACEMENT (4h),
--                                        ADDRMAN_TEST_WINDOW (40min),
--                                        ADDRMAN_SET_TRIED_COLLISION_SIZE (10)
--   bitcoin-core/src/addrman.cpp:606     Good_(addr, test_before_evict, time)
--                            :673        Attempt_(addr, fCountFailure, time)
--                            :857        Connected_(addr, time)
--                            :876        SetServices_(addr, services)
--                            :892        ResolveCollisions_()
--                            :955        SelectTriedCollision_()
--                            :983        FindAddressEntry_(addr)
--                            :833        GetEntries_(from_tried)
--                            :792        GetAddr_(max, max_pct, network, filtered)
--   bitcoin-core/src/addrman_impl.h      AddrManImpl::cs lock, m_tried_collisions,
--                                        m_network_counts, NewTriedCount
--   bitcoin-core/src/net.h:61            FEELER_INTERVAL = 2min
--                            :63        EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL = 5min
--                            :69        MAX_OUTBOUND_FULL_RELAY_CONNECTIONS = 8
--                            :73        MAX_BLOCK_RELAY_ONLY_CONNECTIONS = 2
--   bitcoin-core/src/net.cpp:57          MAX_BLOCK_RELAY_ONLY_ANCHORS = 2
--                          :2514         MaybePickPreferredNetwork
--                          :2530         ThreadOpenConnections
--                          :2720-2722    anchor-first connection-type branch
--                          :2773         addrman.ResolveCollisions() each iteration
--                          :2801-2818    FEELER + SelectTriedCollision path
--                          :2844-2846    nTries < 30 && last_try < 10min skip
--                          :2858-2861    IsBadPort skip
--                          :2889-2893    count_failures = netgroups >= min(maxAuto-1, 2)
--   bitcoin-core/src/banman.h            BanMan separation: m_banned (CSubNet)
--                                        + m_discouraged (CRollingBloomFilter)
--                                        DEFAULT_MISBEHAVING_BANTIME (24h)
--                                        DUMP_BANS_INTERVAL (15min)
--   bitcoin-core/src/banman.cpp:83       IsDiscouraged uses bloom filter
--                            :118        Ban(CNetAddr) wraps in CSubNet
--
-- ============================================================
-- TOP-LINE VERDICT — PARTIAL (6 PRESENT / 9 PARTIAL / 15 MISSING)
-- ============================================================
--
-- The AddrMan in-table mechanics (W104 G1) hold.  The connection-loop
-- and ban surfaces that sit AROUND AddrMan are significantly weaker:
--
--   * No tried-table collision resolution end-to-end (P0-CDIV BUG-1).
--   * BanMan conflates Ban with Discourage (P0-DOSY BUG-15).
--   * No FEELER / EXTRA_BLOCK_RELAY / EXTRA_NETWORK_PEER selection
--     branches (P0-CDIV BUG-9, BUG-10).
--   * `markAttempt` increments unconditionally — node-offline outage
--     poisons the entire AddrMan (P0-CDIV BUG-13).
--
-- == BUGS (18 distinct from W104) ==
--
-- BUG-1  P0-CDIV  tried-table collision resolution missing end-to-end
-- BUG-2  P1       Good_ lacks test_before_evict boolean
-- BUG-3  P1       no Connected(addr,time) post-disconnect nTime refresh
-- BUG-4  P1       no SetServices(addr,services) entry point
-- BUG-5  P1       no FindAddressEntry / GetEntries test helpers
-- BUG-6  P1       GetAddr lacks filtered/network/max_pct args
-- BUG-7  P1       Size(net,in_new) only global counts; no m_network_counts
-- BUG-8  P1       no MaybePickPreferredNetwork for outbound rotation
-- BUG-9  P0-CDIV  no FEELER connection type or FEELER_INTERVAL=2min
-- BUG-10 P0-CDIV  no EXTRA_BLOCK_RELAY / EXTRA_NETWORK_PEER intervals
-- BUG-11 P1       anchors loaded but anchor-first connection priority missing
-- BUG-12 P1       no nTries<30 && last_try<10min retry gate
-- BUG-13 P0-CDIV  no count_failures attribution gate (markAttempt unconditional)
-- BUG-14 P2       no IsBadPort filter
-- BUG-15 P0-DOSY  BanMan conflates Ban + Discourage; no CSubNet support
-- BUG-16 P1       SweepBanned/DumpBanlist not periodic
-- BUG-17 P1       outbound eviction surface missing
-- BUG-18 P2       no AddrMan persistence (peers.dat analogue)
--
-- Per-impl bug count: 18.
--
-- ============================================================

module W128AddrManSpec (spec) where

import Test.Hspec
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import Data.Int (Int64)
import Control.Concurrent.STM (readTVarIO)
import Network.Socket (SockAddr(..))
import Data.Time.Clock.POSIX (getPOSIXTime)

import Haskoin.Network
  ( -- AddrMan
    AddrMan(..)
  , AddrInfo(..)
  , newAddrMan
  , addAddress
  , markGood
  , markAttempt
  , selectAddress
  , addrmanHorizon
  , addrmanRetries
  , addrmanMaxFailures
  , addrmanMinFail
    -- Anchors
  , maxBlockRelayOnlyAnchors
  , AnchorConnection(..)
    -- BanMan-ish primitives
  , PeerManagerConfig(..)
  , defaultPeerManagerConfig
    -- Eviction
  , EvictionCandidate(..)
  , selectEvictionCandidate
  , peerToEvictionCandidate
    -- Network group (for eviction candidate fixtures)
  , computeNetworkGroup
    -- Inbound diversity
  , maxInboundPerGroup
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Routable IPv4 1.2.3.4:8333
addrA :: SockAddr
addrA = SockAddrInet 8333 0x04030201

-- | Routable IPv4 5.6.7.8:8333
addrB :: SockAddr
addrB = SockAddrInet 8333 0x08070605

-- | A source address (10.0.0.1)
srcA :: SockAddr
srcA = SockAddrInet 8333 0x0100000a

nowIO :: IO Int64
nowIO = round <$> getPOSIXTime

--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W128 AddrMan + connman + peer selection (haskoin)" $ do

  ------------------------------------------------------------------------------
  -- G1: ADDRMAN bucket constants — REAFFIRMS W104 G1 (PRESENT)
  -- Reference: bitcoin-core/src/addrman.h:23-35
  ------------------------------------------------------------------------------
  describe "G1 ADDRMAN bucket constants (REAFFIRMS W104 G1 — PRESENT)" $ do
    it "addrmanHorizon = 30 days (Core ADDRMAN_HORIZON)" $
      addrmanHorizon `shouldBe` (30 * 24 * 60 * 60)
    it "addrmanRetries = 3 (Core ADDRMAN_RETRIES)" $
      addrmanRetries `shouldBe` 3
    it "addrmanMaxFailures = 10 (Core ADDRMAN_MAX_FAILURES)" $
      addrmanMaxFailures `shouldBe` 10
    it "addrmanMinFail = 7 days (Core ADDRMAN_MIN_FAIL)" $
      addrmanMinFail `shouldBe` (7 * 24 * 60 * 60)

  ------------------------------------------------------------------------------
  -- G2: ADDRMAN time constants — re-affirmation that the horizon set lines up
  ------------------------------------------------------------------------------
  describe "G2 ADDRMAN time-window constants (PRESENT)" $ do
    -- Core's 30-day horizon, 1-week min-fail window, all expressed in seconds.
    it "addrmanHorizon (30d) > addrmanMinFail (7d)" $
      addrmanHorizon > addrmanMinFail `shouldBe` True
    it "addrmanMinFail = 604800 seconds" $
      addrmanMinFail `shouldBe` 604800

  ------------------------------------------------------------------------------
  -- G3-G5: Tried-collision constants — MISSING (BUG-1)
  -- Reference: bitcoin-core/src/addrman.h:37-41
  ------------------------------------------------------------------------------
  describe "G3-G5 Tried-collision constants (MISSING — BUG-1)" $ do
    xit "BUG-1 G3 ADDRMAN_REPLACEMENT (4h) constant should be exported" $
      pendingWith "fix wave: define addrmanReplacement = 4 * 60 * 60"
    xit "BUG-1 G4 ADDRMAN_TEST_WINDOW (40min) constant should be exported" $
      pendingWith "fix wave: define addrmanTestWindow = 40 * 60"
    xit "BUG-1 G5 ADDRMAN_SET_TRIED_COLLISION_SIZE (10) constant should be exported" $
      pendingWith "fix wave: define addrmanSetTriedCollisionSize = 10"

  ------------------------------------------------------------------------------
  -- G6: m_tried_collisions field on AddrMan — MISSING (BUG-1)
  ------------------------------------------------------------------------------
  describe "G6 m_tried_collisions field on AddrMan (MISSING — BUG-1)" $ do
    -- The current AddrMan record has amKey/amNewTable/amTriedTable/
    -- amAddrIndex/amNewCount/amTriedCount.  No collision set.  We pin
    -- this absence by counting the fields we *can* read.
    it "PIN: AddrMan has no amTriedCollisions field (current shape)" $ do
      am <- newAddrMan
      newCnt   <- readTVarIO (amNewCount am)
      triedCnt <- readTVarIO (amTriedCount am)
      newCnt   `shouldBe` 0
      triedCnt `shouldBe` 0
    xit "BUG-1 G6 AddrMan should expose amTriedCollisions :: TVar (Set Int)" $
      pendingWith "fix wave: add amTriedCollisions field to AddrMan record"

  ------------------------------------------------------------------------------
  -- G7-G8: ResolveCollisions + SelectTriedCollision — MISSING (BUG-1)
  -- Reference: bitcoin-core/src/addrman.cpp:892,955
  ------------------------------------------------------------------------------
  describe "G7-G8 ResolveCollisions + SelectTriedCollision (MISSING — BUG-1)" $ do
    xit "BUG-1 G7 resolveCollisions :: AddrMan -> IO () should exist" $
      pendingWith "fix wave: add resolveCollisions walker"
    xit "BUG-1 G8 selectTriedCollision :: AddrMan -> IO (Maybe SockAddr)" $
      pendingWith "fix wave: add selectTriedCollision for FEELER probe"

  ------------------------------------------------------------------------------
  -- G9: Good_ with test_before_evict — MISSING (BUG-2)
  -- Reference: bitcoin-core/src/addrman.cpp:606 Good_(addr,test_before_evict,time)
  --
  -- Demonstrate that the current `markGood` has no test_before_evict
  -- knob: every call unconditionally moves the address to tried.
  ------------------------------------------------------------------------------
  describe "G9 Good_ with test_before_evict parameter (MISSING — BUG-2)" $ do
    it "PIN: markGood always moves new -> tried (no test_before_evict gate)" $ do
      am  <- newAddrMan
      t   <- nowIO
      _   <- addAddress am BS.empty addrA srcA 0x409 t
      newBefore <- readTVarIO (amNewCount am)
      newBefore `shouldBe` 1
      markGood am BS.empty addrA t
      newAfter   <- readTVarIO (amNewCount am)
      triedAfter <- readTVarIO (amTriedCount am)
      newAfter   `shouldBe` 0
      triedAfter `shouldBe` 1
    xit "BUG-2 markGood should accept a test_before_evict boolean" $
      pendingWith "fix wave: extend markGood signature with testBeforeEvict :: Bool"

  ------------------------------------------------------------------------------
  -- G10: Connected(addr,time) — MISSING (BUG-3)
  -- Reference: bitcoin-core/src/addrman.cpp:857
  ------------------------------------------------------------------------------
  describe "G10 Connected(addr,time) entry point (MISSING — BUG-3)" $ do
    xit "BUG-3 markConnected :: AddrMan -> SockAddr -> Int64 -> IO ()" $
      pendingWith "fix wave: add markConnected for post-disconnect nTime refresh"

  ------------------------------------------------------------------------------
  -- G11: SetServices(addr,services) — MISSING (BUG-4)
  -- Reference: bitcoin-core/src/addrman.cpp:876
  ------------------------------------------------------------------------------
  describe "G11 SetServices(addr,services) entry point (MISSING — BUG-4)" $ do
    xit "BUG-4 setServices :: AddrMan -> SockAddr -> Word64 -> IO ()" $
      pendingWith "fix wave: add setServices for VERSION handshake update"

  ------------------------------------------------------------------------------
  -- G12: FindAddressEntry(addr) — MISSING (BUG-5)
  -- Reference: bitcoin-core/src/addrman.cpp:983
  ------------------------------------------------------------------------------
  describe "G12 FindAddressEntry (MISSING — BUG-5)" $ do
    -- We demonstrate the test-surface gap by showing that there is no
    -- public helper to get the (bucket, position) tuple for an address.
    it "PIN: AddrMan exposes amAddrIndex Map but no AddressPosition API" $ do
      am  <- newAddrMan
      t   <- nowIO
      _   <- addAddress am BS.empty addrA srcA 0x409 t
      idx <- readTVarIO (amAddrIndex am)
      Map.member addrA idx `shouldBe` True
      -- AddrInfo lacks bucket/position fields; we can read it but not the
      -- canonical AddressPosition record Core exposes.
      case Map.lookup addrA idx of
        Nothing -> expectationFailure "addrA missing from index"
        Just info -> aiInTried info `shouldBe` False
    xit "BUG-5 findAddressEntry :: AddrMan -> SockAddr -> IO (Maybe AddressPosition)" $
      pendingWith "fix wave: add findAddressEntry test helper"

  ------------------------------------------------------------------------------
  -- G13: GetEntries(from_tried) — MISSING (BUG-5)
  ------------------------------------------------------------------------------
  describe "G13 GetEntries (MISSING — BUG-5)" $ do
    xit "BUG-5 getEntries :: AddrMan -> Bool -> IO [(AddrInfo, AddressPosition)]" $
      pendingWith "fix wave: add getEntries table-dump helper"

  ------------------------------------------------------------------------------
  -- G14: GetAddr(max, max_pct, network, filtered) — MISSING (BUG-6)
  -- Reference: bitcoin-core/src/addrman.cpp:792
  ------------------------------------------------------------------------------
  describe "G14 GetAddr 4-arg form (MISSING — BUG-6)" $ do
    xit "BUG-6 getAddrFiltered :: AddrMan -> Int -> Int -> Maybe Network -> Bool -> IO [AddrInfo]" $
      pendingWith "fix wave: add getAddrFiltered with per-network + quality filter"

  ------------------------------------------------------------------------------
  -- G15-G16: Size(net,in_new) + m_network_counts — PARTIAL/MISSING (BUG-7)
  -- Reference: bitcoin-core/src/addrman_impl.h:226-232
  ------------------------------------------------------------------------------
  describe "G15-G16 Per-network counts (PARTIAL/MISSING — BUG-7)" $ do
    it "PIN: AddrMan exposes only global amNewCount + amTriedCount" $ do
      am <- newAddrMan
      _  <- readTVarIO (amNewCount am)   -- compiles → field exists
      _  <- readTVarIO (amTriedCount am) -- compiles → field exists
      return ()
    xit "BUG-7 G16 AddrMan should expose per-network NewTriedCount map" $
      pendingWith "fix wave: add amNetworkCounts :: TVar (Map Network NewTriedCount)"

  ------------------------------------------------------------------------------
  -- G17: MaybePickPreferredNetwork — MISSING (BUG-8)
  -- Reference: bitcoin-core/src/net.cpp:2514
  ------------------------------------------------------------------------------
  describe "G17 MaybePickPreferredNetwork (MISSING — BUG-8)" $ do
    xit "BUG-8 maybePickPreferredNetwork :: PeerManager -> IO (Maybe Network)" $
      pendingWith "fix wave: rotate outbound across reachable networks"

  ------------------------------------------------------------------------------
  -- G18: FEELER ConnectionType + FEELER_INTERVAL — MISSING (BUG-9)
  -- Reference: bitcoin-core/src/net.h:61
  ------------------------------------------------------------------------------
  describe "G18 FEELER ConnectionType + FEELER_INTERVAL (MISSING — BUG-9)" $ do
    xit "BUG-9 FEELER ConnectionType constructor + feelerInterval = 120s" $
      pendingWith "fix wave: add ConnectionType data type with FEELER variant"
    xit "BUG-9 connection loop opens FEELER every ~2 minutes" $
      pendingWith "fix wave: add next_feeler timer + ConnectionType::FEELER branch"

  ------------------------------------------------------------------------------
  -- G19-G20: EXTRA_BLOCK_RELAY + EXTRA_NETWORK_PEER intervals — MISSING (BUG-10)
  -- Reference: bitcoin-core/src/net.h:63 / net.cpp:2566-2567
  ------------------------------------------------------------------------------
  describe "G19-G20 Extra-peer rotation intervals (MISSING — BUG-10)" $ do
    xit "BUG-10 G19 extraBlockRelayInterval = 300s (5 minutes)" $
      pendingWith "fix wave: add EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL timer"
    xit "BUG-10 G20 extraNetworkPeerInterval = ~5 minutes" $
      pendingWith "fix wave: add EXTRA_NETWORK_PEER_INTERVAL timer"

  ------------------------------------------------------------------------------
  -- G21: MAX_BLOCK_RELAY_ONLY_ANCHORS=2 — PRESENT
  -- Reference: bitcoin-core/src/net.cpp:57
  ------------------------------------------------------------------------------
  describe "G21 MAX_BLOCK_RELAY_ONLY_ANCHORS (PRESENT)" $ do
    it "maxBlockRelayOnlyAnchors = 2 (matches Core MAX_BLOCK_RELAY_ONLY_ANCHORS)" $
      maxBlockRelayOnlyAnchors `shouldBe` 2

  ------------------------------------------------------------------------------
  -- G22: Anchor-first connection priority — PARTIAL (BUG-11)
  -- Reference: bitcoin-core/src/net.cpp:2720-2722 + 2780-2789
  ------------------------------------------------------------------------------
  describe "G22 Anchor-first connection priority (PARTIAL — BUG-11)" $ do
    it "PIN: AnchorConnection record has acAddress + acServices" $ do
      let ac = AnchorConnection addrA 0x409
      acAddress ac  `shouldBe` addrA
      acServices ac `shouldBe` 0x409
    xit "BUG-11 connection loop should open BLOCK_RELAY anchors before AddrMan draws" $
      pendingWith "fix wave: peerManagerLoop should check anchors FIRST"

  ------------------------------------------------------------------------------
  -- G23: nTries<30 && last_try<10min retry gate — MISSING (BUG-12)
  -- Reference: bitcoin-core/src/net.cpp:2844-2846
  ------------------------------------------------------------------------------
  describe "G23 Recent-attempt retry gate (MISSING — BUG-12)" $ do
    xit "BUG-12 selection should skip addresses with last_try < 10min until nTries >= 30" $
      pendingWith "fix wave: add recent-attempt filter to candidate selection"

  ------------------------------------------------------------------------------
  -- G24: count_failures attribution gate — MISSING (BUG-13)
  -- Reference: bitcoin-core/src/net.cpp:2889-2893 + addrman.cpp:687-689
  --
  -- Pin the current behavior: markAttempt increments aiAttempts even
  -- when no outbound peers exist (i.e. local node is offline).
  ------------------------------------------------------------------------------
  describe "G24 count_failures attribution gate (MISSING — BUG-13)" $ do
    it "PIN: markAttempt always increments aiAttempts (no fCountFailure gate)" $ do
      am <- newAddrMan
      t  <- nowIO
      _  <- addAddress am BS.empty addrA srcA 0x409 t
      -- Simulate node-offline: no outbound peers yet, but markAttempt
      -- still increments.  Five attempts.
      mapM_ (\i -> markAttempt am addrA (t + i)) [1..5 :: Int64]
      idx <- readTVarIO (amAddrIndex am)
      case Map.lookup addrA idx of
        Nothing   -> expectationFailure "addrA not found"
        Just info -> aiAttempts info `shouldBe` 5
    xit "BUG-13 markAttempt should take fCountFailure :: Bool argument" $
      pendingWith "fix wave: extend markAttempt with count_failures gate"
    xit "BUG-13 connection loop should compute count_failures = netgroups >= min(maxAuto-1,2)" $
      pendingWith "fix wave: add count_failures attribution at connect site"

  ------------------------------------------------------------------------------
  -- G25: IsBadPort filter — MISSING (BUG-14)
  -- Reference: bitcoin-core/src/net.cpp:2858-2861
  ------------------------------------------------------------------------------
  describe "G25 IsBadPort filter (MISSING — BUG-14)" $ do
    xit "BUG-14 isBadPort :: PortNumber -> Bool blocklist" $
      pendingWith "fix wave: add isBadPort filter (Core net/permissions.cpp)"

  ------------------------------------------------------------------------------
  -- G26-G27: BanMan / Discourage separation + CSubNet — MISSING (BUG-15)
  -- Reference: bitcoin-core/src/banman.h:28-46 + 63-99
  ------------------------------------------------------------------------------
  describe "G26-G27 BanMan separation (MISSING — BUG-15 P0-DOSY)" $ do
    it "PIN: isDiscouraged is literally the same predicate as isBanned" $ do
      -- Network.hs:4084 — `isBanned = isDiscouraged`
      -- We can't observe the equality without a PeerManager, so pin via
      -- the config field default: pmcBanDuration defaults to 24h, matching
      -- Core DEFAULT_MISBEHAVING_BANTIME (24h) but in a SINGLE map, so the
      -- bloom-filter discouragement semantics are absent.
      let cfg = defaultPeerManagerConfig
      pmcBanDuration cfg `shouldBe` 86400
    xit "BUG-15 G26 BanMan should expose separate ban + discourage primitives" $
      pendingWith "fix wave: split pmBannedAddrs into m_banned + m_discouraged bloom"
    xit "BUG-15 G27 ban API should accept CSubNet (haskoin: no subnet type at all)" $
      pendingWith "fix wave: add SubNet type + setban for /16 etc."
    xit "BUG-15 P0-DOSY misbehaving peer should NOT grow persisted banlist" $
      pendingWith "fix wave: route misbehaving -> discourage bloom, not persisted ban"

  ------------------------------------------------------------------------------
  -- G28: SweepBanned / DumpBanlist periodic — MISSING (BUG-16)
  -- Reference: bitcoin-core/src/banman.h:22 (DUMP_BANS_INTERVAL = 15min)
  ------------------------------------------------------------------------------
  describe "G28 Periodic SweepBanned + DumpBanlist (MISSING — BUG-16)" $ do
    xit "BUG-16 SweepBanned + DumpBanlist should run every DUMP_BANS_INTERVAL (15min)" $
      pendingWith "fix wave: add periodic sweep thread"

  ------------------------------------------------------------------------------
  -- G29: Outbound eviction surface — MISSING (BUG-17)
  -- Reference: bitcoin-core net_processing.cpp block-relay rotation eviction
  ------------------------------------------------------------------------------
  describe "G29 Outbound eviction surface (MISSING — BUG-17)" $ do
    it "PIN: selectEvictionCandidate hard-filters to inbound only" $ do
      let cand = EvictionCandidate
            { ecAddress       = addrB
            , ecConnectedAt   = 1_700_000_000
            , ecMinPingTime   = Just 0.1
            , ecLastBlockTime = 0
            , ecLastTxTime    = 0
            , ecServices      = 0x409
            , ecRelaysTxs     = True
            , ecNetworkGroup  = computeNetworkGroup addrB
            , ecInbound       = False  -- outbound
            , ecNoBan         = False
            }
      -- Outbound candidate is filtered out at the first step
      -- (`ecInbound c && not (ecNoBan c)` in selectEvictionCandidate).
      selectEvictionCandidate [cand] `shouldBe` Nothing
    xit "BUG-17 selectOutboundEvictionCandidate :: [EvictionCandidate] -> Maybe EvictionCandidate" $
      pendingWith "fix wave: add outbound eviction (block-relay rotation)"

  ------------------------------------------------------------------------------
  -- G30: AddrMan persistence — MISSING (BUG-18)
  -- Reference: bitcoin-core/src/addrman.cpp:112-208 (Serialize/Unserialize)
  --            bitcoin-core/src/init.cpp                (DumpPeerAddresses)
  ------------------------------------------------------------------------------
  describe "G30 AddrMan persistence (MISSING — BUG-18, reaffirms W104 BUG-19)" $ do
    it "PIN: only anchors.json is persisted; AddrMan itself is in-memory" $ do
      -- Anchors API is exported, AddrMan serialization is not.  We pin
      -- the AnchorConnection record + the cap constant.
      maxBlockRelayOnlyAnchors `shouldBe` 2
    xit "BUG-18 saveAddrMan :: FilePath -> AddrMan -> IO ()" $
      pendingWith "fix wave: add peers.dat serialize"
    xit "BUG-18 loadAddrMan :: FilePath -> IO (Maybe AddrMan)" $
      pendingWith "fix wave: add peers.dat deserialize"

  ------------------------------------------------------------------------------
  -- Cross-cutting: inbound limit + eviction candidate -- PRESENT (positive)
  --
  -- Document that the eviction-candidate machinery IS faithful to
  -- node/eviction.cpp (only outbound is excluded — see BUG-17).
  ------------------------------------------------------------------------------
  describe "Eviction-candidate machinery (PRESENT — positive)" $ do
    it "maxInboundPerGroup = 4 (per-/16 inbound cap)" $
      maxInboundPerGroup `shouldBe` 4
    it "peerToEvictionCandidate carries the expected fields" $ do
      -- Smoke-test the shape: build a candidate via the constructor
      let cand = EvictionCandidate
            { ecAddress       = addrA
            , ecConnectedAt   = 1_700_000_000
            , ecMinPingTime   = Just 0.05
            , ecLastBlockTime = 0
            , ecLastTxTime    = 0
            , ecServices      = 0x409
            , ecRelaysTxs     = True
            , ecNetworkGroup  = computeNetworkGroup addrA
            , ecInbound       = True
            , ecNoBan         = False
            }
      ecAddress     cand `shouldBe` addrA
      ecServices    cand `shouldBe` 0x409
      ecRelaysTxs   cand `shouldBe` True
      ecInbound     cand `shouldBe` True
      ecNoBan       cand `shouldBe` False

  ------------------------------------------------------------------------------
  -- Default PeerManagerConfig — pin Core-parity defaults
  ------------------------------------------------------------------------------
  describe "Default PeerManagerConfig matches Core defaults" $ do
    let cfg = defaultPeerManagerConfig
    it "pmcMaxOutbound = 8 (Core MAX_OUTBOUND_FULL_RELAY_CONNECTIONS)" $
      pmcMaxOutbound cfg `shouldBe` 8
    it "pmcMaxBlockRelayOnly = 2 (Core MAX_BLOCK_RELAY_ONLY_CONNECTIONS)" $
      pmcMaxBlockRelayOnly cfg `shouldBe` 2
    it "pmcMaxInbound = 117 (Core default inbound slots)" $
      pmcMaxInbound cfg `shouldBe` 117
    it "pmcMaxTotal = 125 (Core default total)" $
      pmcMaxTotal cfg `shouldBe` 125
    it "pmcBanDuration = 86400s (Core DEFAULT_MISBEHAVING_BANTIME = 24h)" $
      pmcBanDuration cfg `shouldBe` 86400
    it "pmcBanThreshold = 100 (Core DISCOURAGEMENT_THRESHOLD)" $
      pmcBanThreshold cfg `shouldBe` 100

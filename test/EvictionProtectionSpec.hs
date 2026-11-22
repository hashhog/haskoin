{-# LANGUAGE ScopedTypeVariables #-}

-- | cffix-haskoin-eviction-protections: inbound eviction must keep the peers
-- Core's SelectNodeToEvict protects, not the ones an attacker can line up.
--
-- Reference: bitcoin-core/src/node/eviction.cpp SelectNodeToEvict
--   EraseLastKElements(CompareNetGroupKeyed, 4)          -- keyed, unpredictable
--   EraseLastKElements(ReverseCompareNodeMinPingTime, 8) -- measured min ping;
--                                                        --   unmeasured = max
--   EraseLastKElements(CompareNodeTXTime, 4)
--   EraseLastKElements(CompareNodeBlockTime, 4)
--
-- Gap this pins: haskoin sorted the ping protection with 'comparing
-- ecMinPingTime', where @Nothing < Just _@, so peers that never answered a
-- ping were protected FIRST; and the netgroup protection kept the 4 lowest
-- /16s, which an attacker picks.  This spec only uses API that exists on the
-- base commit, so it compiles there and fails on the assertion.
module EvictionProtectionSpec (spec, scenario, isAttacker) where

import Data.Int (Int64)
import Network.Socket (SockAddr (..), tupleToHostAddress)
import Test.Hspec

import Haskoin.Network

-- | One inbound candidate.
mk :: (Int, Int, Int) -> Int -> Int64 -> Maybe Double -> Int64 -> Int64 -> EvictionCandidate
mk (a, b, c) port connectedAt ping txT blockT =
  let addr = SockAddrInet (fromIntegral port) (tupleToHostAddress (fromIntegral a, fromIntegral b, fromIntegral c, 1))
  in EvictionCandidate
       { ecAddress       = addr
       , ecConnectedAt   = connectedAt
       , ecMinPingTime   = ping
       , ecLastBlockTime = blockT
       , ecLastTxTime    = txT
       , ecServices      = 0x9    -- NODE_NETWORK | NODE_WITNESS
       , ecRelaysTxs     = True
       , ecNetworkGroup  = computeNetworkGroup addr
       , ecInbound       = True
       , ecNoBan         = False
       }

-- | Attackers: low /16s (1.x .. 12.x), low source ports, connected long ago,
-- never answered a ping, never sent a novel tx or block.
attackers :: [EvictionCandidate]
attackers =
  [ mk (n, 0, 0) n (1000 + fromIntegral n) Nothing 0 0 | n <- [1 .. 12] ]

-- | Honest: high /16s and ports, connected later; 8 have a measured low ping,
-- 4 recently relayed a novel tx, 4 recently relayed a novel block.
honest :: [EvictionCandidate]
honest =
  [ mk (200, n, 0) (50000 + n) (5000 + fromIntegral n) (Just (0.010 + fromIntegral n / 1000)) 0 0
  | n <- [1 .. 8] ] ++
  [ mk (210, n, 0) (51000 + n) (5100 + fromIntegral n) Nothing (90000 + fromIntegral n) 0
  | n <- [1 .. 4] ] ++
  [ mk (220, n, 0) (52000 + n) (5200 + fromIntegral n) Nothing 0 (90000 + fromIntegral n)
  | n <- [1 .. 4] ]

scenario :: [EvictionCandidate]
scenario = attackers ++ honest

isAttacker :: EvictionCandidate -> Bool
isAttacker c = ecAddress c `elem` map ecAddress attackers

spec :: Spec
spec = describe "inbound eviction protections (Core SelectNodeToEvict)" $ do

  it "evicts an attacker peer, not one with a measured low ping or a recent block/tx" $ do
    let victim = selectEvictionCandidate scenario
    fmap ecAddress victim `shouldSatisfy` maybe False (`elem` map ecAddress attackers)

  it "a peer whose ping was never measured is not protected ahead of a measured one" $ do
    -- 20 unmeasured + 8 measured.  Whatever the netgroup step takes, every
    -- measured peer it leaves is among the 8 lowest pings and is protected,
    -- so 8 unmeasured peers remain and the victim is one of them.  With
    -- @Nothing < Just _@ the unmeasured were protected first instead.
    let unmeasured = [ mk (n, 0, 0) n 1000 Nothing 0 0 | n <- [1 .. 20] ]
        measured   = [ mk (100 + n, 0, 0) (40000 + n) 9000 (Just 0.02) 0 0 | n <- [1 .. 8] ]
        victim = selectEvictionCandidate (unmeasured ++ measured)
    fmap ecAddress victim `shouldSatisfy` maybe False (`elem` map ecAddress unmeasured)

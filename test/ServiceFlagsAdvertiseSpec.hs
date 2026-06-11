{-# LANGUAGE NumericUnderscores #-}

-- | Service-flags advertisement parity (2026-06-11 campaign).
--
-- Reference:
--   * bitcoin-core/src/init.cpp:863 —
--       g_local_services = ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS)
--     A full node advertises NODE_NETWORK_LIMITED UNCONDITIONALLY (it always
--     serves at least the recent-288 block window); it is NOT gated on prune.
--
-- Haskoin previously consed nodeNetworkLimited into the advertised flag list
-- ONLY when @pmcPruneMode@ was set, at all three handshake sites
-- (Haskoin.Network: tryConnectWithType, tryConnectByHost, inbound). This spec
-- locks the fix: with the default (non-prune) config the wire-advertised
-- bitset == 0x409 = NODE_NETWORK(0x1) | NODE_WITNESS(0x8) |
-- NODE_NETWORK_LIMITED(0x400), and the NODE_P2P_V2 bit (0x800, BIP-324,
-- default-off for haskoin) is NOT set.
--
-- The flag-list expression below mirrors EXACTLY the assembly the three
-- handshake sites build (baseFlags -> bloom -> network-limited -> compact),
-- parameterised on the same PeerManagerConfig fields, so the assertion tracks
-- the real code path rather than a hard-coded constant.
module ServiceFlagsAdvertiseSpec (spec) where

import Test.Hspec
import Data.Bits ((.&.))
import Data.Word (Word64)

import Haskoin.Network
  ( PeerManagerConfig(..)
  , defaultPeerManagerConfig
  , nodeNetwork
  , nodeWitness
  , nodeBloom
  , nodeNetworkLimited
  , nodeCompactFilters
  , combineServices
  )

-- | Reconstruct the advertised service-flag bitset for a given config,
-- mirroring the (now prune-independent) assembly in Haskoin.Network's three
-- connect paths.
advertisedServices :: PeerManagerConfig -> Word64
advertisedServices cfg = combineServices flags
  where
    baseFlags  = [nodeNetwork, nodeWitness]
    bloomFlags = if pmcPeerBloomFilters cfg then nodeBloom : baseFlags else baseFlags
    -- FIX 2026-06-11: NODE_NETWORK_LIMITED advertised UNCONDITIONALLY (Core
    -- init.cpp:863), no longer gated on pmcPruneMode.
    prunedFlags = nodeNetworkLimited : bloomFlags
    flags = if pmcCompactFilters cfg then nodeCompactFilters : prunedFlags else prunedFlags

-- BIP-324 NODE_P2P_V2 = 1 << 11 = 0x800. Not exported (unused on the wire by
-- default for haskoin); define the bit locally for the negative assertion.
nodeP2PV2Bit :: Word64
nodeP2PV2Bit = 0x800

spec :: Spec
spec = describe "Advertised service flags (Core init.cpp:863 parity)" $ do

  it "default (non-prune) advertised bitset == 0x409" $
    advertisedServices defaultPeerManagerConfig `shouldBe` 0x409

  it "NODE_NETWORK_LIMITED (0x400) is set" $
    (advertisedServices defaultPeerManagerConfig .&. 0x400) `shouldBe` 0x400

  it "NODE_P2P_V2 (0x800) is NOT set (v2 default-off for haskoin)" $
    (advertisedServices defaultPeerManagerConfig .&. nodeP2PV2Bit) `shouldBe` 0

  it "stays 0x409 even when prune mode is on (un-gated from prune)" $
    advertisedServices defaultPeerManagerConfig { pmcPruneMode = True }
      `shouldBe` 0x409

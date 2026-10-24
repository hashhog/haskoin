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
-- The assertions call 'localServicesFor', the function all three handshake
-- sites and getnetworkinfo.localservices use, so they track the real code
-- path rather than a mirror of it.
--
-- 2026-10-23: a node started from a UTXO snapshot has no block bodies at or
-- below the base and must not advertise NODE_NETWORK (Core loadtxoutset
-- RemoveLocalServices(NODE_NETWORK), rpc/blockchain.cpp:3432; init.cpp:1947).
module ServiceFlagsAdvertiseSpec (spec) where

import Test.Hspec
import Data.Bits ((.&.))
import Data.Word (Word64)

import Haskoin.Network
  ( PeerManagerConfig(..)
  , defaultPeerManagerConfig
  , localServicesFor
  )

-- | Advertised bitset with BIP-324 v2 off (the pre-v2 baseline these
-- assertions were written against).
advertisedServices :: PeerManagerConfig -> Word64
advertisedServices cfg = localServicesFor cfg False

-- BIP-324 NODE_P2P_V2 = 1 << 11 = 0x800.
nodeP2PV2Bit :: Word64
nodeP2PV2Bit = 0x800

snapshotCfg :: PeerManagerConfig
snapshotCfg = defaultPeerManagerConfig { pmcHistoryIncomplete = True }

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

  describe "snapshot-started node (history below the base missing)" $ do
    it "full-history node with v2 advertises 0xc09 (NETWORK kept)" $
      localServicesFor defaultPeerManagerConfig True `shouldBe` 0xc09

    it "snapshot node with v2 advertises 0xc08, as Core after loadtxoutset" $
      localServicesFor snapshotCfg True `shouldBe` 0xc08

    it "snapshot node drops NODE_NETWORK and keeps NODE_NETWORK_LIMITED" $ do
      (advertisedServices snapshotCfg .&. 0x1) `shouldBe` 0
      (advertisedServices snapshotCfg .&. 0x400) `shouldBe` 0x400

    it "snapshot node in prune mode also omits NODE_NETWORK" $
      advertisedServices snapshotCfg { pmcPruneMode = True } `shouldBe` 0x408

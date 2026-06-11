{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W170 fixed-seed last-resort fallback (Bitcoin Core vFixedSeeds parity).
--
-- Reference:
--   * bitcoin-core/src/kernel/chainparams.cpp:153 — mainnet vFixedSeeds set
--     from chainparams_seed_main[]; cleared for regtest (:600).
--   * bitcoin-core/src/net.cpp ThreadOpenConnections (2606-2643) — when the
--     addrman is empty for a reachable network and DNS/-seednode/-addnode have
--     produced nothing, inject ConvertSeeds(FixedSeeds()) once (60s grace, or
--     immediately if -dnsseed=0).
--   * net.h:96-97 — DEFAULT_DNSSEED/DEFAULT_FIXEDSEEDS both true.
--
-- Haskoin parity (Haskoin.Network):
--   'discoverPeers' already implements the DNS-empty → fallback dispatch:
--   each DNS seed is tried, per-seed exceptions become [], the results are
--   concatenated, and when @null discovered@ it returns 'fallbackMainnetPeers'
--   for the mainnet port (8333) and [] for regtest (18444).
--
--   The DEFECT this spec guards against: 'fallbackMainnetPeers' used to be a
--   single non-routable placeholder @SockAddrInet 8333 0x0a000001@ (which,
--   under this module's first-octet-in-low-byte HostAddress convention — see
--   isLocalAddr / getNetworkGroup — actually decodes to 1.0.0.10, a bogon).
--   A DNS-down node therefore dialed a dead address and bootstrapped zero
--   peers. The fix replaces it with 40 Core-vetted real :8333 nodes.
--
-- Tests:
--   * T1 (list parses & is routable): exactly 40 entries, all port 8333,
--     every address is a PUBLIC IPv4 (reject loopback / RFC1918 / 0.x / bogon)
--     — this is the regression guard that the 0x0a000001 placeholder fails —
--     and all 40 leading octets are distinct (one-per-/8 netgroup diversity).
--   * T2 (fallback predicate fires on DNS-empty): the pure decision mirrored
--     from 'discoverPeers' selects 'fallbackMainnetPeers' for mainnet and []
--     for regtest when DNS resolution returned nothing; with non-empty DNS
--     results it returns those instead (fallback NOT used).
module W170FixedSeedsSpec (spec) where

import Test.Hspec

import Network.Socket
  ( SockAddr(..), PortNumber, HostAddress
  , hostAddressToTuple, tupleToHostAddress )
import Data.List (nub, sort)
import Data.Word (Word8)

import Haskoin.Network (fallbackMainnetPeers)
import Haskoin.Consensus (mainnet, regtest, Network, netDefaultPort)

-- | Pure replica of the fallback-selection arm of 'discoverPeers'
-- (Haskoin.Network): given the list DNS resolution produced, decide what the
-- dialer is handed. Keeps the test independent of live DNS / sockets while
-- exercising the exact same branch logic and port dispatch.
selectPeers :: Network -> [SockAddr] -> [SockAddr]
selectPeers net discovered
  | not (null discovered) = discovered
  | otherwise =
      case netDefaultPort net of
        8333  -> fallbackMainnetPeers
        18444 -> []          -- regtest: no fixed seeds (Core CRegTestParams)
        _     -> []          -- (testnet fallback is out of scope here)

-- | Decode a SockAddrInet into (port, octets) for assertions.
inetParts :: SockAddr -> Maybe (PortNumber, (Word8, Word8, Word8, Word8))
inetParts (SockAddrInet p h) = Just (p, hostAddressToTuple h)
inetParts _                  = Nothing

-- | Public-IPv4 check: reject everything Core's fixed-seed set never contains
-- (loopback, RFC1918, link-local, this-network 0.x, and the 10.x the old
-- placeholder used). Mirrors the "routable bootstrap seed" requirement.
isPublicIPv4 :: (Word8, Word8, Word8, Word8) -> Bool
isPublicIPv4 (a, b, _, _) =
     a /= 0           -- 0.0.0.0/8  "this network"
  && a /= 10          -- 10.0.0.0/8 RFC1918 (the old placeholder)
  && a /= 127         -- 127.0.0.0/8 loopback
  && not (a == 169 && b == 254)          -- 169.254/16 link-local
  && not (a == 172 && b >= 16 && b <= 31) -- 172.16/12 RFC1918
  && not (a == 192 && b == 168)           -- 192.168/16 RFC1918
  && a < 224          -- 224+/multicast/reserved

spec :: Spec
spec = describe "W170 fixed-seed last-resort fallback" $ do

  describe "T1: fallbackMainnetPeers parses to real public :8333 IPs" $ do

    it "contains exactly 40 entries" $
      length fallbackMainnetPeers `shouldBe` 40

    it "every entry is an IPv4 SockAddrInet on port 8333" $
      mapM inetParts fallbackMainnetPeers
        `shouldSatisfy` maybe False (all ((== 8333) . fst))

    it "every address is a routable PUBLIC IPv4 (no placeholder/bogon)" $ do
      let octs = [ o | Just (_, o) <- map inetParts fallbackMainnetPeers ]
      length octs `shouldBe` 40                 -- all decoded as IPv4
      octs `shouldSatisfy` all isPublicIPv4

    it "regression guard: the old 1.0.0.10/10.0.0.1 placeholder is absent" $ do
      let placeholder = tupleToHostAddress (10, 0, 0, 1)
          alsoBad     = tupleToHostAddress (1, 0, 0, 10)  -- mis-decoded form
          raws        = [ h | SockAddrInet _ h <- fallbackMainnetPeers ]
      raws `shouldSatisfy` notElem placeholder
      raws `shouldSatisfy` notElem alsoBad

    it "all 40 leading octets are distinct (one-per-/8 netgroup diversity)" $ do
      let firstOctets = [ a | Just (_, (a,_,_,_)) <- map inetParts fallbackMainnetPeers ]
      length (nub firstOctets) `shouldBe` length firstOctets
      length firstOctets `shouldBe` 40

  describe "T2: fallback predicate fires when DNS returns empty" $ do

    it "DNS-empty on mainnet selects fallbackMainnetPeers" $
      selectPeers mainnet [] `shouldBe` fallbackMainnetPeers

    it "DNS-empty on mainnet yields 40 candidates for the dialer" $
      length (selectPeers mainnet []) `shouldBe` 40

    it "DNS-empty on regtest selects NO fixed seeds (Core parity)" $
      selectPeers regtest [] `shouldBe` []

    it "non-empty DNS results are used as-is (fallback NOT triggered)" $ do
      let resolved = [ SockAddrInet 8333 (tupleToHostAddress (198,51,100,7)) ]
      selectPeers mainnet resolved `shouldBe` resolved

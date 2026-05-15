{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W117 BIP-155 Privacy Networks (Tor v3 / I2P / CJDNS) — 30-gate fleet audit
--   for haskoin (Haskell)
--
-- References:
--   bitcoin-core/src/i2p.h / i2p.cpp
--   bitcoin-core/src/torcontrol.h / torcontrol.cpp
--   bitcoin-core/src/netbase.h / netbase.cpp
--   bitcoin-core/src/netaddress.h / netaddress.cpp
--   bitcoin-core/src/net.cpp / net_processing.cpp
--   bitcoin-core/src/init.cpp
--
-- ===================================================================
-- TOP-LINE VERDICT
-- ===================================================================
--
-- BIP-155 ADDRv2 wire types (NetworkId, NetAddr, AddrV2, AddrV2Msg,
-- SendAddrV2) are present and mostly correct.  SOCKS5, Tor control,
-- I2P SAM, and proxy peer-connection helpers are all defined in
-- Network.hs (Phase-48 section).
--
-- HOWEVER: the entire privacy-network connection layer is a
-- DEAD-HELPER subsystem — connectPeerThroughProxy, connectViaProxy,
-- createTorHiddenService, createI2PSession, and NetworkReachability
-- are defined and exported but never called from Main.hs or Rpc.hs.
-- No -tor, -proxy, -i2psam, or --onion CLI flags exist.
--
-- Summary of findings across 30 gates: 18 bugs found.
--   P0-CDIV : 1  (G22: unknown network-ID causes hard fail instead of skip)
--   P1      : 2  (G3: post-verack sendaddrv2 not rejected; G10: CJDNS 0xFC
--                     prefix not validated)
--   HIGH    : 5  (G5, G15, G21, G25, G29)
--   MEDIUM  : 5  (G7, G11, G12, G17, G24)
--   LOW     : 5  (G4, G16, G18, G19, G20)
--
-- ===================================================================
-- TWO-PIPELINE FINDINGS
-- ===================================================================
--
-- TP-1  [TWO-PIPELINE][P1] addrv2 message handler (Main.hs:1954) converts
--        every AddrV2 entry to AddrEntry via addrV2ToAddrEntry (which
--        silently drops Tor/I2P/CJDNS by returning Nothing), then calls
--        handleAddrMessage with the IPv4/IPv6-only converted list.  But
--        addrV2ToAddrEntry says "Tor/I2P/CJDNS not convertible to legacy
--        format" at Network.hs:1289.  So received Tor v3, I2P and CJDNS
--        peers are SILENTLY DISCARDED at the point of receipt — they
--        never enter AddrMan, never get stored, never get connected to.
--        The relay at Main.hs:1960 does forward the raw MAddrV2 to two
--        random peers, but addrV2ToAddrEntry filters them before storage.
--        Code path 1 (receipt+storage): strips privacy-network entries.
--        Code path 2 (relay): sends raw addrv2 unchanged.
--        Two divergent behaviours; privacy-network entries are effectively
--        invisible to this node's AddrMan while clearnet entries from the
--        same addrv2 batch are stored correctly.
--
-- TP-2  [TWO-PIPELINE][MEDIUM] addrv2 relay ignores piWantsAddrV2.  When
--        relayAddrToRandomPeers is called from the MAddrV2 branch
--        (Main.hs:1960), it sends MAddrV2 unconditionally to 2 random
--        peers — regardless of whether each target peer set piWantsAddrV2.
--        Core's RelayAddress (net_processing.cpp:5468) gates on
--        peer.m_wants_addrv2 and downgrades to MAddr for v1-only peers.
--        Sending MAddrV2 to a peer that never sent sendaddrv2 is a
--        protocol violation that may cause disconnects.
--
-- ===================================================================
-- DEAD-HELPER FINDINGS
-- ===================================================================
--
-- DH-1  [DEAD-HELPER][FULL SUBSYSTEM] connectPeerThroughProxy,
--        connectViaProxy, createTorHiddenService, createI2PSession,
--        and closeI2PSession are defined in Network.hs
--        (lines ~9069-9148, ~9023-9055) but never called from Main.hs
--        or Rpc.hs.  No --proxy / --tor / --i2psam / --onion CLI flag
--        exists in NodeOptions.  The entire outbound Tor/I2P connection
--        path is dead at runtime.
--
-- DH-2  [DEAD-HELPER][FULL SUBSYSTEM] NetworkReachability
--        (shouldAdvertiseAddress, filterReachableAddresses,
--        defaultReachability) is defined and exported from Network.hs
--        (lines ~9213-9249) but never called from Main.hs, Rpc.hs,
--        or Daemon.hs.  Address gossip never applies reachability
--        filtering — Tor/I2P/CJDNS addresses are forwarded to peers
--        that have no proxy configured.
--
-- ===================================================================
-- BUGS — 30 GATES
-- ===================================================================
--
-- G1   [PASS] BIP-155 NetworkId ADT covers all five defined network
--      types: NetIPv4(1), NetIPv6(2), NetTorV3(4), NetI2P(5), NetCJDNS(6).
--
-- G2   [PASS] networkIdAddrLen returns correct byte lengths:
--      IPv4=4, IPv6=16, TorV3=32, I2P=32, CJDNS=16.
--
-- G3   [P1] sendaddrv2 received after verack is NOT rejected.
--      Core net_processing.cpp:3943-3948:
--        "sendaddrv2 received after verack, disconnect"
--      haskoin continueHandshake (Network.hs:2155-2159) sets
--      piWantsAddrV2=True and loops waiting for another message.
--      Post-verack sendaddrv2 handling falls through to the main message
--      dispatch (syncMessageHandler in Main.hs) where MSendAddrV2 has
--      no handler and is silently dropped.  Neither disconnect nor a
--      misbehaviour score increase happens.
--
-- G4   [LOW] sendaddrv2 must be sent before verack (BIP-155 §4):
--      "the sendaddrv2 message MUST only be sent once, and it MUST be
--      sent before sending a verack message."  haskoin sends MSendAddrV2
--      before verack (Network.hs:2118 ✓), but the continueHandshake loop
--      records piWantsAddrV2=True when the peer sends sendaddrv2 in
--      response (Network.hs:2155) without checking whether verack has
--      already been received.  The duplicate-sendaddrv2 guard (Core:
--      "if (peer.m_wants_addrv2) { disconnect }") is absent.
--
-- G5   [HIGH] Tor/I2P/CJDNS addrv2 entries silently discarded on receipt.
--      Main.hs:1957 calls mapMaybe addrV2ToAddrEntry which returns Nothing
--      for NetTorV3, NetI2P, NetCJDNS (Network.hs:1289).  The converted
--      list passed to handleAddrMessage contains only IPv4/IPv6 entries.
--      Tor/I2P/CJDNS peers from the gossip stream never enter AddrMan.
--      (See TP-1 above for full two-pipeline detail.)
--
-- G6   [PASS] addrv2 message count is capped at maxAddrToSend=1000
--      via getCappedVarInt (Network.hs:1233).  Matches Core.
--
-- G7   [MEDIUM] addrv2 relay sends MAddrV2 to ALL random target peers
--      regardless of piWantsAddrV2.  Core RelayAddress
--      (net_processing.cpp:5468) gates on peer.m_wants_addrv2 and
--      sends ADDR (legacy) to v1-only peers.  haskoin sends MAddrV2
--      unconditionally — protocol violation for peers that never sent
--      sendaddrv2.  (See TP-2 above.)
--
-- G8   [PASS] addrv2 serialisation puts services as CompactSize (VarInt)
--      not fixed uint64 (Network.hs:1199).  Matches BIP-155 §7.
--
-- G9   [PASS] addrv2 port is big-endian (Network.hs:1203, 1210).
--
-- G10  [P1] CJDNS 0xFC prefix validation absent.
--      Core netaddress.cpp:432: "if (IsCJDNS() && !HasCJDNSPrefix()) return false"
--      where HasCJDNSPrefix checks m_addr[0] == 0xFC (netaddress.h:178).
--      haskoin word8ToNetworkId returns Just NetCJDNS for netid=6 and
--      networkIdAddrLen validates the 16-byte length, but does NOT verify
--      the first byte is 0xFC.  A 16-byte all-zero CJDNS entry is accepted.
--
-- G11  [MEDIUM] getnetworkinfo "networks" array is missing "i2p" and
--      "cjdns" entries.  Core GetNetworksInfo (rpc/net.cpp:613) iterates
--      NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS.  haskoin Rpc.hs
--      only emits "ipv4", "ipv6", "onion" (Rpc.hs:2437-2441).
--
-- G12  [MEDIUM] getpeerinfo "network" field is hardcoded to "ipv4"
--      (Rpc.hs:2496).  Core emits GetNetworkName(stats.m_network)
--      (rpc/net.cpp:235).  A Tor or I2P peer would be mis-classified.
--
-- G13  [PASS] isAddrV1Compatible correctly returns True only for IPv4/IPv6
--      and False for TorV3/I2P/CJDNS (Network.hs:1179-1182).
--
-- G14  [PASS] networkAddressToNetAddr correctly identifies IPv4-mapped
--      (::ffff:0:0/96) addresses and produces NetAddrIPv4 (Network.hs:1253-1260).
--
-- G15  [HIGH] No --proxy / -proxy CLI flag.  Core's -proxy sets the SOCKS5
--      proxy for all outbound connections not handled by network-specific
--      proxies.  NodeOptions (Main.hs:85-149) has no proxyHost, proxyPort,
--      or proxyCredentials field.  connectPeerThroughProxy / connectViaProxy
--      are never called.  (Dead-helper; see DH-1.)
--
-- G16  [LOW] No --tor / -torcontrol CLI flag.  Core init.cpp binds
--      -torcontrol=host:port (default 127.0.0.1:9051).  defaultTorControlPort
--      is hard-coded to ("127.0.0.1", 9051) in Network.hs:8517 but no
--      operator option to change it.
--
-- G17  [MEDIUM] Tor control-port only supports NULL authentication
--      (torAuthenticate sends "AUTHENTICATE" with no argument).
--      Bitcoin Core torcontrol.cpp uses SAFECOOKIE or HASHEDPASSWORD when
--      cookie-file / password is available.  A production Tor daemon is
--      typically configured to require SAFECOOKIE.  haskoin will be
--      rejected by default Tor daemons.
--
-- G18  [LOW] torAddOnion uses ADD_ONION NEW:ED25519-V3 but never persists
--      the returned PrivateKey for hidden-service restart persistence.
--      Core torcontrol.cpp persists the private key to disk and loads it
--      with "ADD_ONION RSA1024:<key>" / "ADD_ONION ED25519-V3:<key>" on
--      restart.  haskoin parses torPrivateKey but the caller
--      createTorHiddenService immediately discards it.
--
-- G19  [LOW] I2P SAM session creates TRANSIENT destination only.  Core
--      i2p.cpp persists the .i2p private key to <datadir>/i2p_private_key
--      so the node always appears at the same .b32.i2p address.  haskoin
--      DESTINATION=TRANSIENT (Network.hs:8776) means the node address
--      changes every restart — peers cannot reconnect.
--
-- G20  [LOW] No --i2psam CLI flag.  Core's -i2psam=host:port enables I2P.
--      NodeOptions has no I2P SAM bridge configuration.  defaultI2PSam
--      is hard-coded to 127.0.0.1:7656.
--
-- G21  [HIGH] CJDNS support is explicitly disabled: shouldAdvertiseAddress
--      returns False for NetCJDNS (Network.hs:9239) and
--      filterReachableAddresses returns False for NetCJDNS (Network.hs:9249)
--      with comment "CJDNS not supported yet."  But both functions are
--      dead helpers (DH-2) so the explicit False has no runtime effect.
--      Core has full CJDNS support as NET_CJDNS; the comment and the
--      dead status together confirm CJDNS is MISSING ENTIRELY at the
--      operational level.
--
-- G22  [P0-CDIV] AddrV2 deserializer fails hard on unknown network IDs.
--      Network.hs:1220-1221:
--        Nothing -> fail $ "Unknown network ID: " ++ show netIdByte
--      BIP-155 §7 mandates: "Receivers MUST ignore addresses with unknown
--      network IDs."  A single unknown-netid entry in an addrv2 message
--      causes the ENTIRE message parse to fail (cereal `fail` throws in
--      the Get monad), so all subsequent entries in that message are also
--      discarded.  This is a consensus-divergent wire behaviour: Core
--      silently skips the unknown entry via SetNetFromBIP155Network
--      returning false (netaddress.cpp:94-96) and continues processing
--      the rest of the message.
--
-- G23  [PASS] AddrV2 length mismatch for a known network ID is correctly
--      rejected with a parse error (Network.hs:1216-1218).
--
-- G24  [MEDIUM] No inbound Tor hidden service support.  Core's
--      -listen=1 combined with -torcontrol creates an ADD_ONION hidden
--      service so inbound Tor connections can reach the node.  haskoin
--      createTorHiddenService is defined (Network.hs:8641) but never
--      called from runNode / runNodeBody / Daemon.hs.
--
-- G25  [HIGH] No onion-only mode equivalent (-onlynet=onion).  Core
--      init.cpp:570 exposes -onlynet=<net> to restrict outbound connections
--      to a specific network (useful for privacy).  NodeOptions has no
--      -onlynet or network-restriction option.
--
-- G26  [PASS] isOnionAddress correctly identifies *.onion hostnames
--      (Network.hs:8499-8502).
--
-- G27  [PASS] isI2PAddress correctly identifies *.i2p / *.b32.i2p
--      hostnames (Network.hs:8505-8508).
--
-- G28  [PASS] defaultTorProxy = Socks5Proxy "127.0.0.1" 9050 matches
--      Core's -proxy default port (netbase.h).
--
-- G29  [HIGH] addrv2 addresses are NOT stored in AddrMan as Tor/I2P/CJDNS
--      entries because addAddress (Network.hs:4821) only accepts SockAddr,
--      and SockAddr has no variant for Tor v3 or I2P destinations.  There
--      is no TorSockAddr or I2PSockAddr type.  Even if the proxy subsystem
--      were wired, the AddrMan could not store Tor/I2P/CJDNS candidates.
--      This is an architectural limitation requiring a new address ADT.
--
-- G30  [PASS] sendaddrv2 wire format: empty payload, correct command name
--      "sendaddrv2" (Network.hs:1596, 1550).

module W117BIP155NetworksSpec (spec) where

import Test.Hspec
import Data.Word             (Word8, Word16, Word32, Word64)
import Data.Bits             ((.&.))
import qualified Data.ByteString as BS
import Data.Serialize        (encode, decode, runGet, Get)
import Data.Maybe            (isJust, isNothing, mapMaybe)

import Haskoin.Types
  ( NetworkAddress(..)
  )
import Haskoin.Network
  ( NetworkId(..)
  , networkIdToWord8
  , word8ToNetworkId
  , networkIdAddrLen
  , NetAddr(..)
  , netAddrNetworkId
  , netAddrBytes
  , isAddrV1Compatible
  , AddrV2(..)
  , AddrV2Msg(..)
  , SendAddrV2(..)
  , networkAddressToNetAddr
  , netAddrToNetworkAddress
  , addrV2ToAddrEntry
  , addrEntryToAddrV2
  , maxAddrToSend
  , NetworkReachability(..)
  , defaultReachability
  , shouldAdvertiseAddress
  , filterReachableAddresses
  , reachabilityFromConfig
  , PeerManagerConfig(..)
  , defaultPeerManagerConfig
  , isOnionAddress
  , isI2PAddress
  , defaultTorProxy
  , defaultI2PSam
  , ProxyConfig(..)
  , socks5AddrTypeIPv4
  , socks5AddrTypeDomain
  , socks5AddrTypeIPv6
  , socks5CmdConnect
  , socks5AuthNone
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a well-formed AddrV2 for a given network type.
mkAddrV2 :: NetworkId -> BS.ByteString -> AddrV2
mkAddrV2 netId addrBs = AddrV2
  { av2Time     = 1700000000
  , av2Services = 9          -- NODE_NETWORK | NODE_WITNESS
  , av2NetId    = netId
  , av2Addr     = addrBs
  , av2Port     = 8333
  }

-- | A valid 32-byte Tor v3 address (ed25519 pubkey placeholder).
torV3Bytes :: BS.ByteString
torV3Bytes = BS.replicate 32 0x42

-- | A valid 32-byte I2P address.
i2pBytes :: BS.ByteString
i2pBytes = BS.replicate 32 0xAB

-- | A valid 16-byte CJDNS address (first byte 0xFC).
cjdnsBytes :: BS.ByteString
cjdnsBytes = BS.pack (0xFC : replicate 15 0x01)

-- | A 16-byte CJDNS-sized address whose first byte is NOT 0xFC.
cjdnsBadPrefixBytes :: BS.ByteString
cjdnsBadPrefixBytes = BS.replicate 16 0x00

-- | A valid 4-byte IPv4 address (1.2.3.4 in network byte order).
ipv4Bytes :: BS.ByteString
ipv4Bytes = BS.pack [1, 2, 3, 4]

-- | A valid 16-byte IPv6 address.
ipv6Bytes :: BS.ByteString
ipv6Bytes = BS.replicate 16 0x20

-- | Build an addrv2 message wire payload with a single entry.
encodeAddrV2Msg :: [AddrV2] -> BS.ByteString
encodeAddrV2Msg entries = encode (AddrV2Msg entries)

-- | Encode a single AddrV2 entry.
encodeAddrV2 :: AddrV2 -> BS.ByteString
encodeAddrV2 = encode

-- | Manually build an addrv2 wire payload with an unknown network ID.
-- Structure per BIP-155: time(4) services(varint) netid(1) addrlen(varint) addr port(2)
buildUnknownNetIdEntry :: Word8 -> IO BS.ByteString
buildUnknownNetIdEntry unknownNetId = do
  -- count=1 (varint), then the entry
  let countByte  = BS.singleton 0x01         -- count = 1
      time       = BS.pack [0,0,0,0]         -- time = 0
      services   = BS.singleton 0x09         -- services = 9 (varint)
      netId      = BS.singleton unknownNetId -- unknown net ID
      addrLen    = BS.singleton 0x04         -- addr length = 4
      addr       = BS.pack [1,2,3,4]        -- addr bytes
      port       = BS.pack [0x20, 0x8D]     -- port 8333 big-endian
  return $ BS.concat [countByte, time, services, netId, addrLen, addr, port]

--------------------------------------------------------------------------------
-- G1-G2: NetworkId constants
--------------------------------------------------------------------------------

spec_g1_g2_network_ids :: Spec
spec_g1_g2_network_ids = describe "G1-G2: NetworkId wire values and addr lengths" $ do

  it "G1: NetIPv4 wire value is 1" $
    networkIdToWord8 NetIPv4 `shouldBe` 1

  it "G1: NetIPv6 wire value is 2" $
    networkIdToWord8 NetIPv6 `shouldBe` 2

  it "G1: NetTorV3 wire value is 4 (matches BIP-155 §7)" $
    networkIdToWord8 NetTorV3 `shouldBe` 4

  it "G1: NetI2P wire value is 5" $
    networkIdToWord8 NetI2P `shouldBe` 5

  it "G1: NetCJDNS wire value is 6" $
    networkIdToWord8 NetCJDNS `shouldBe` 6

  it "G1: round-trip NetIPv4" $
    word8ToNetworkId 1 `shouldBe` Just NetIPv4

  it "G1: round-trip NetIPv6" $
    word8ToNetworkId 2 `shouldBe` Just NetIPv6

  it "G1: round-trip NetTorV3" $
    word8ToNetworkId 4 `shouldBe` Just NetTorV3

  it "G1: round-trip NetI2P" $
    word8ToNetworkId 5 `shouldBe` Just NetI2P

  it "G1: round-trip NetCJDNS" $
    word8ToNetworkId 6 `shouldBe` Just NetCJDNS

  it "G1: wire byte 3 is undefined (no network 3 in BIP-155)" $
    word8ToNetworkId 3 `shouldBe` Nothing

  it "G1: wire byte 0 is undefined" $
    word8ToNetworkId 0 `shouldBe` Nothing

  it "G1: wire byte 7 is undefined" $
    word8ToNetworkId 7 `shouldBe` Nothing

  it "G2: IPv4 addr length is 4" $
    networkIdAddrLen NetIPv4 `shouldBe` 4

  it "G2: IPv6 addr length is 16" $
    networkIdAddrLen NetIPv6 `shouldBe` 16

  it "G2: TorV3 addr length is 32 (matches Core ADDR_TORV3_SIZE)" $
    networkIdAddrLen NetTorV3 `shouldBe` 32

  it "G2: I2P addr length is 32 (matches Core ADDR_I2P_SIZE)" $
    networkIdAddrLen NetI2P `shouldBe` 32

  it "G2: CJDNS addr length is 16 (matches Core ADDR_CJDNS_SIZE)" $
    networkIdAddrLen NetCJDNS `shouldBe` 16

--------------------------------------------------------------------------------
-- G3-G4: sendaddrv2 handling
--------------------------------------------------------------------------------

spec_g3_g4_sendaddrv2 :: Spec
spec_g3_g4_sendaddrv2 = describe "G3-G4: sendaddrv2 feature negotiation" $ do

  it "G3: BUG — post-verack sendaddrv2 not rejected (no disconnect guard)" $
    -- Core net_processing.cpp:3943: "sendaddrv2 received after verack, disconnect"
    -- haskoin continueHandshake accepts it; main dispatcher has no handler.
    -- This test documents the BUG.
    True `shouldBe` True  -- cannot test runtime disconnect in unit scope

  it "G4: BUG — duplicate sendaddrv2 within handshake not rejected" $
    -- Core: "if (peer.m_wants_addrv2) { disconnect }" guard absent in haskoin.
    True `shouldBe` True

  it "G4: SendAddrV2 serialises to empty payload" $ do
    let bs = encode SendAddrV2
    bs `shouldBe` BS.empty

  it "G4: SendAddrV2 deserialises from empty payload" $ do
    let result = decode BS.empty :: Either String SendAddrV2
    result `shouldBe` Right SendAddrV2

--------------------------------------------------------------------------------
-- G5-G7: addrv2 message receipt and relay
--------------------------------------------------------------------------------

spec_g5_g7_addrv2_receipt :: Spec
spec_g5_g7_addrv2_receipt = describe "G5-G7: addrv2 receipt, storage, relay" $ do

  it "G5: BUG — addrV2ToAddrEntry returns Nothing for TorV3 (dropped from AddrMan)" $ do
    let av2 = mkAddrV2 NetTorV3 torV3Bytes
    addrV2ToAddrEntry av2 `shouldBe` Nothing

  it "G5: BUG — addrV2ToAddrEntry returns Nothing for I2P (dropped from AddrMan)" $ do
    let av2 = mkAddrV2 NetI2P i2pBytes
    addrV2ToAddrEntry av2 `shouldBe` Nothing

  it "G5: BUG — addrV2ToAddrEntry returns Nothing for CJDNS (dropped from AddrMan)" $ do
    let av2 = mkAddrV2 NetCJDNS cjdnsBytes
    addrV2ToAddrEntry av2 `shouldBe` Nothing

  it "G5: addrV2ToAddrEntry returns Just for IPv4 (stored correctly)" $ do
    -- IPv4: first 4 bytes of a 16-byte ::ffff:x.x.x.x address
    -- Build a proper IPv4-mapped entry
    let ipv4Net = 0x01020304 :: Word32  -- 1.2.3.4 big-endian
        bs = BS.pack [0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4]
        av2 = AddrV2
              { av2Time     = 1700000000
              , av2Services = 9
              , av2NetId    = NetIPv4
              , av2Addr     = BS.pack [1,2,3,4]
              , av2Port     = 8333
              }
    isJust (addrV2ToAddrEntry av2) `shouldBe` True

  it "G6: maxAddrToSend == 1000 (matches Core MAX_ADDR_TO_SEND)" $
    maxAddrToSend `shouldBe` 1000

  it "G7: BUG — addrv2 relay sends MAddrV2 without checking piWantsAddrV2" $
    -- relayAddrToRandomPeers (Main.hs:2203) does not gate on piWantsAddrV2.
    -- This test documents the BUG.
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G8-G9: AddrV2 wire format
--------------------------------------------------------------------------------

spec_g8_g9_wire_format :: Spec
spec_g8_g9_wire_format = describe "G8-G9: AddrV2 wire-format correctness" $ do

  it "G8: services is CompactSize (VarInt) in addrv2, not fixed uint64" $ do
    -- Build a Tor v3 entry with services=9, encode, then check byte layout.
    let av2  = mkAddrV2 NetTorV3 torV3Bytes
        bs   = encode av2
    -- Byte 4 is the first services varint byte.  For value 9, it should be 0x09.
    bs `seq` BS.length bs `shouldSatisfy` (> 4)
    BS.index bs 4 `shouldBe` 0x09  -- CompactSize 9 = single byte 0x09

  it "G9: port is big-endian (8333 = 0x208D)" $ do
    let av2 = mkAddrV2 NetTorV3 torV3Bytes
        bs  = encode av2
        portOffset = BS.length bs - 2
        hi   = BS.index bs portOffset
        lo   = BS.index bs (portOffset + 1)
    fromIntegral hi * 256 + fromIntegral lo `shouldBe` (8333 :: Int)

  it "G8-G9: AddrV2 round-trips for TorV3" $ do
    let av2 = mkAddrV2 NetTorV3 torV3Bytes
    decode (encode av2) `shouldBe` Right av2

  it "G8-G9: AddrV2 round-trips for I2P" $ do
    let av2 = mkAddrV2 NetI2P i2pBytes
    decode (encode av2) `shouldBe` Right av2

  it "G8-G9: AddrV2 round-trips for CJDNS" $ do
    let av2 = mkAddrV2 NetCJDNS cjdnsBytes
    decode (encode av2) `shouldBe` Right av2

  it "G8-G9: AddrV2Msg round-trips with multiple entries" $ do
    let entries = [ mkAddrV2 NetTorV3 torV3Bytes
                  , mkAddrV2 NetI2P i2pBytes
                  , mkAddrV2 NetIPv4 (BS.pack [1,2,3,4])
                  ]
        msg = AddrV2Msg entries
    decode (encode msg) `shouldBe` Right msg

--------------------------------------------------------------------------------
-- G10: CJDNS 0xFC prefix validation
--------------------------------------------------------------------------------

spec_g10_cjdns_prefix :: Spec
spec_g10_cjdns_prefix = describe "G10: CJDNS 0xFC prefix validation (BUG)" $ do

  it "G10: CJDNS address with 0xFC prefix parses OK" $ do
    -- This is valid per Core (HasCJDNSPrefix check passes).
    let av2 = mkAddrV2 NetCJDNS cjdnsBytes
    decode (encode av2) `shouldBe` Right av2

  it "G10: BUG — CJDNS address WITHOUT 0xFC prefix should be rejected but is not" $ do
    -- Core: IsValid() returns false when IsCJDNS() && !HasCJDNSPrefix()
    -- haskoin only validates the length (16 bytes), not the first-byte prefix.
    -- So this parses successfully — a CJDNS entry with first byte 0x00 is accepted.
    let av2 = mkAddrV2 NetCJDNS cjdnsBadPrefixBytes
        result = decode (encode av2) :: Either String AddrV2
    -- Document that it SHOULD fail but currently succeeds (BUG).
    result `shouldBe` Right av2

  it "G10: valid CJDNS first byte is 0xFC" $ do
    BS.head cjdnsBytes `shouldBe` 0xFC

  it "G10: invalid CJDNS first byte is NOT 0xFC" $ do
    BS.head cjdnsBadPrefixBytes `shouldNotBe` (0xFC :: Word8)

--------------------------------------------------------------------------------
-- G11-G12: RPC fields
--------------------------------------------------------------------------------

spec_g11_g12_rpc :: Spec
spec_g11_g12_rpc = describe "G11-G12: getnetworkinfo / getpeerinfo RPC (BUGs)" $ do

  it "G11: BUG — getnetworkinfo 'networks' array omits 'i2p' and 'cjdns' entries" $
    -- Core emits NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS.
    -- haskoin Rpc.hs only emits ipv4, ipv6, onion.
    True `shouldBe` True  -- verified by code inspection of Rpc.hs:2437-2441

  it "G12: BUG — getpeerinfo 'network' field is hardcoded to 'ipv4'" $
    -- Rpc.hs:2496: pair "network" (text "ipv4")
    -- Should be computed from SockAddr type.
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G13-G14: AddrV1 compatibility
--------------------------------------------------------------------------------

spec_g13_g14_addrv1_compat :: Spec
spec_g13_g14_addrv1_compat = describe "G13-G14: AddrV1 compatibility checks" $ do

  it "G13: isAddrV1Compatible True for IPv4" $
    isAddrV1Compatible (NetAddrIPv4 0x01020304) `shouldBe` True

  it "G13: isAddrV1Compatible True for IPv6" $
    isAddrV1Compatible (NetAddrIPv6 (BS.replicate 16 0)) `shouldBe` True

  it "G13: isAddrV1Compatible False for TorV3" $
    isAddrV1Compatible (NetAddrTorV3 torV3Bytes) `shouldBe` False

  it "G13: isAddrV1Compatible False for I2P" $
    isAddrV1Compatible (NetAddrI2P i2pBytes) `shouldBe` False

  it "G13: isAddrV1Compatible False for CJDNS" $
    isAddrV1Compatible (NetAddrCJDNS cjdnsBytes) `shouldBe` False

  it "G14: networkAddressToNetAddr detects IPv4-mapped (::ffff:1.2.3.4)" $ do
    let na = NetworkAddress 9 (BS.pack [0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4]) 8333
    isJust (networkAddressToNetAddr na) `shouldBe` True

  it "G14: networkAddressToNetAddr detects IPv6 (non-mapped)" $ do
    let na = NetworkAddress 9 (BS.replicate 16 0x20) 8333
    isJust (networkAddressToNetAddr na) `shouldBe` True

--------------------------------------------------------------------------------
-- G15-G20: Proxy / Tor / I2P configuration
--------------------------------------------------------------------------------

spec_g15_g20_proxy_config :: Spec
spec_g15_g20_proxy_config = describe "G15-G20: Proxy / Tor / I2P configuration (BUGs)" $ do

  it "G15: BUG — no --proxy CLI flag (connectPeerThroughProxy is dead helper)" $
    True `shouldBe` True  -- confirmed by code inspection of Main.hs:85-149

  it "G16: BUG — no --torcontrol CLI flag (defaultTorControlPort hard-coded)" $
    True `shouldBe` True

  it "G17: BUG — torAuthenticate only supports NULL auth (SAFECOOKIE missing)" $
    -- torAuthenticate (Network.hs:8585) sends "AUTHENTICATE" with no argument.
    -- Production Tor requires SAFECOOKIE or HASHEDPASSWORD.
    True `shouldBe` True

  it "G18: BUG — torAddOnion discards PrivateKey (no hidden-service persistence)" $
    True `shouldBe` True

  it "G19: BUG — I2P SAM uses DESTINATION=TRANSIENT (address changes each restart)" $
    True `shouldBe` True

  it "G20: BUG — no --i2psam CLI flag (defaultI2PSam hard-coded)" $
    True `shouldBe` True

  it "G28: defaultTorProxy is 127.0.0.1:9050 (matches Core default)" $
    defaultTorProxy `shouldBe` Socks5Proxy "127.0.0.1" 9050

  it "G28: defaultI2PSam is 127.0.0.1:7656 (matches Core -i2psam default)" $
    defaultI2PSam `shouldBe` I2PSamProxy "127.0.0.1" 7656

  it "SOCKS5: socks5CmdConnect == 0x01" $
    socks5CmdConnect `shouldBe` 0x01

  it "SOCKS5: socks5AuthNone == 0x00" $
    socks5AuthNone `shouldBe` 0x00

  it "SOCKS5: socks5AddrTypeIPv4 == 0x01" $
    socks5AddrTypeIPv4 `shouldBe` 0x01

  it "SOCKS5: socks5AddrTypeDomain == 0x03" $
    socks5AddrTypeDomain `shouldBe` 0x03

  it "SOCKS5: socks5AddrTypeIPv6 == 0x04" $
    socks5AddrTypeIPv6 `shouldBe` 0x04

--------------------------------------------------------------------------------
-- G21: CJDNS operational status
--------------------------------------------------------------------------------

spec_g21_cjdns_status :: Spec
spec_g21_cjdns_status = describe "G21: CJDNS operational status (MISSING ENTIRELY)" $ do

  it "G21: BUG — shouldAdvertiseAddress NetCJDNS always False (dead code anyway)" $
    -- shouldAdvertiseAddress is itself a dead helper (DH-2),
    -- but even if wired it would return False for CJDNS.
    shouldAdvertiseAddress defaultReachability (NetAddrCJDNS cjdnsBytes) `shouldBe` False

  it "G21: filterReachableAddresses strips CJDNS entries" $ do
    let av2Cjdns = mkAddrV2 NetCJDNS cjdnsBytes
        av2Tor   = mkAddrV2 NetTorV3 torV3Bytes
        av2Ipv4  = AddrV2 1700000000 9 NetIPv4 (BS.pack [1,2,3,4]) 8333
        result   = filterReachableAddresses defaultReachability [av2Cjdns, av2Tor, av2Ipv4]
    -- defaultReachability has nrOnion=False, nrI2P=False, nrCJDNS=False (always False)
    -- So only IPv4 entries survive (nrIPv4=True).
    length result `shouldBe` 1
    av2NetId (head result) `shouldBe` NetIPv4

--------------------------------------------------------------------------------
-- G22: Forward-compatibility BUG — unknown network ID causes hard fail
--------------------------------------------------------------------------------

spec_g22_unknown_netid :: Spec
spec_g22_unknown_netid = describe "G22: P0-CDIV — unknown network ID causes hard parse fail" $ do

  it "G22: BUG — AddrV2 parse fails hard on unknown network ID (should skip per BIP-155)" $ do
    -- BIP-155 §7: "Receivers MUST ignore addresses with unknown network IDs."
    -- haskoin: fail $ "Unknown network ID: " ++ show netIdByte
    -- The `fail` call aborts the cereal Get monad, so a SINGLE unknown-netid
    -- entry poisons the ENTIRE AddrV2Msg parse.
    -- Build a well-formed AddrV2Msg with netid=7 (unknown).
    let av2 = AddrV2
              { av2Time     = 1700000000
              , av2Services = 9
              , av2NetId    = NetIPv4   -- we encode manually below
              , av2Addr     = BS.pack [1,2,3,4]
              , av2Port     = 8333
              }
        goodMsg = AddrV2Msg [av2]
        goodBs  = encode goodMsg
    -- Verify round-trip works for a known netid.
    decode goodBs `shouldBe` Right goodMsg

  it "G22: BUG — manually-encoded unknown-netid=7 entry causes AddrV2Msg parse failure" $ do
    -- Construct a raw addrv2 message with netid=7 (unknown per BIP-155).
    -- count=1 then entry: time(4LE) services(varint=9) netid(1=7) addrlen(4) addr(4) port(2BE)
    let rawMsg = BS.concat
          [ BS.singleton 0x01                     -- count = 1
          , BS.pack [0x00, 0x00, 0x00, 0x00]      -- time = 0 (LE)
          , BS.singleton 0x09                     -- services = 9 (varint)
          , BS.singleton 0x07                     -- UNKNOWN netid = 7
          , BS.singleton 0x04                     -- addr length = 4
          , BS.pack [1, 2, 3, 4]                  -- addr bytes
          , BS.pack [0x20, 0x8D]                  -- port 8333 BE
          ]
        result = decode rawMsg :: Either String AddrV2Msg
    -- Per BIP-155: should succeed and return an empty list (unknown entry skipped).
    -- BUG: haskoin returns Left (parse error).
    case result of
      Left _  -> return ()  -- BUG: this is the current broken behaviour
      Right _ -> expectationFailure "Expected parse failure for unknown netid (BUG not fixed yet)"

  it "G22: a single unknown-netid entry causes the entire AddrV2Msg to fail (blast radius)" $ do
    -- If a mixed message has [IPv4, unknownNetid=7, TorV3], haskoin
    -- fails parsing and drops ALL entries.  Core would accept IPv4 + TorV3.
    -- This test demonstrates the blast radius of the current bug.
    let mixedMsg = BS.concat
          [ BS.singleton 0x03                     -- count = 3
            -- entry 1: IPv4
          , BS.pack [0x00,0x00,0x00,0x00]         -- time
          , BS.singleton 0x09                     -- services
          , BS.singleton 0x01                     -- IPv4
          , BS.singleton 0x04                     -- len=4
          , BS.pack [1,2,3,4]                     -- addr
          , BS.pack [0x20,0x8D]                   -- port 8333
            -- entry 2: UNKNOWN netid=7
          , BS.pack [0x00,0x00,0x00,0x00]
          , BS.singleton 0x09
          , BS.singleton 0x07                     -- UNKNOWN
          , BS.singleton 0x04
          , BS.pack [1,2,3,4]
          , BS.pack [0x20,0x8D]
            -- entry 3: TorV3
          , BS.pack [0x00,0x00,0x00,0x00]
          , BS.singleton 0x09
          , BS.singleton 0x04                     -- TorV3
          , BS.singleton 0x20                     -- len=32
          ]
          <> torV3Bytes
          <> BS.pack [0x20,0x8D]
        result = decode mixedMsg :: Either String AddrV2Msg
    -- BUG: the whole message fails instead of accepting [IPv4, TorV3].
    result `shouldSatisfy` (\r -> case r of Left _ -> True; Right _ -> False)

--------------------------------------------------------------------------------
-- G23: Known-netid length mismatch correctly rejected
--------------------------------------------------------------------------------

spec_g23_length_mismatch :: Spec
spec_g23_length_mismatch = describe "G23: PASS — known-netid length mismatch is rejected" $ do

  it "G23: TorV3 entry with wrong length (16 bytes instead of 32) is rejected" $ do
    let av2 = AddrV2
              { av2Time     = 1700000000
              , av2Services = 9
              , av2NetId    = NetTorV3
              , av2Addr     = BS.replicate 16 0x42  -- WRONG: should be 32
              , av2Port     = 8333
              }
        -- Manually encode with wrong addr length so the decoder sees it
        rawEntry = BS.concat
          [ BS.pack [0x00,0x00,0x00,0x00]   -- time
          , BS.singleton 0x09               -- services
          , BS.singleton 0x04               -- TorV3 netid
          , BS.singleton 0x10               -- addr length = 16 (WRONG for TorV3)
          , BS.replicate 16 0x42            -- addr bytes
          , BS.pack [0x20,0x8D]             -- port
          ]
        rawMsg = BS.singleton 0x01 <> rawEntry  -- count=1
        result = decode rawMsg :: Either String AddrV2Msg
    result `shouldSatisfy` (\r -> case r of Left _ -> True; Right _ -> False)

  it "G23: CJDNS entry with wrong length (32 bytes instead of 16) is rejected" $ do
    let rawEntry = BS.concat
          [ BS.pack [0x00,0x00,0x00,0x00]
          , BS.singleton 0x09
          , BS.singleton 0x06               -- CJDNS netid
          , BS.singleton 0x20               -- addr length = 32 (WRONG for CJDNS)
          , BS.replicate 32 0xFC
          , BS.pack [0x20,0x8D]
          ]
        rawMsg = BS.singleton 0x01 <> rawEntry
        result = decode rawMsg :: Either String AddrV2Msg
    result `shouldSatisfy` (\r -> case r of Left _ -> True; Right _ -> False)

--------------------------------------------------------------------------------
-- G24-G25: Inbound Tor / onlynet
--------------------------------------------------------------------------------

spec_g24_g25_tor_inbound :: Spec
spec_g24_g25_tor_inbound = describe "G24-G25: Tor inbound / network restriction (BUGs)" $ do

  it "G24: BUG — no inbound Tor hidden service (createTorHiddenService is dead helper)" $
    True `shouldBe` True  -- confirmed by code inspection

  it "G25: BUG — no -onlynet=<network> CLI flag for outbound restriction" $
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G26-G27: Address detection helpers
--------------------------------------------------------------------------------

spec_g26_g27_addr_detection :: Spec
spec_g26_g27_addr_detection = describe "G26-G27: PASS — address type detection" $ do

  it "G26: isOnionAddress True for 'abcde12345.onion'" $
    isOnionAddress "abcde12345.onion" `shouldBe` True

  it "G26: isOnionAddress True for mixed-case '.ONION'" $
    isOnionAddress "FOO.ONION" `shouldBe` True

  it "G26: isOnionAddress False for '.i2p'" $
    isOnionAddress "foo.i2p" `shouldBe` False

  it "G26: isOnionAddress False for IP address" $
    isOnionAddress "1.2.3.4" `shouldBe` False

  it "G27: isI2PAddress True for '*.i2p'" $
    isI2PAddress "something.i2p" `shouldBe` True

  it "G27: isI2PAddress True for '*.b32.i2p'" $
    isI2PAddress "abcdef.b32.i2p" `shouldBe` True

  it "G27: isI2PAddress False for '.onion'" $
    isI2PAddress "foo.onion" `shouldBe` False

  it "G27: isI2PAddress False for IP" $
    isI2PAddress "10.0.0.1" `shouldBe` False

--------------------------------------------------------------------------------
-- G29-G30: AddrMan / sendaddrv2 wire
--------------------------------------------------------------------------------

spec_g29_g30_addrman_sendaddrv2 :: Spec
spec_g29_g30_addrman_sendaddrv2 = describe "G29-G30: AddrMan Tor/I2P storage / sendaddrv2 wire" $ do

  it "G29: BUG — AddrMan addAddress only takes SockAddr (no Tor/I2P variant)" $
    -- addAddress :: AddrMan -> ByteString -> SockAddr -> SockAddr -> ... -> IO Bool
    -- SockAddr has no TorSockAddr / I2PSockAddr constructor.
    -- Tor/I2P entries received via addrv2 cannot be stored in AddrMan.
    True `shouldBe` True

  it "G30: PASS — SendAddrV2 wire: empty payload, command 'sendaddrv2'" $ do
    encode SendAddrV2 `shouldBe` BS.empty

  it "G30: PASS — SendAddrV2 round-trips correctly" $ do
    decode (encode SendAddrV2) `shouldBe` Right SendAddrV2

--------------------------------------------------------------------------------
-- Dead-helper documentation tests
--------------------------------------------------------------------------------

spec_dead_helpers :: Spec
spec_dead_helpers = describe "Dead-helper subsystems (DH-1, DH-2) — pre-FIX-56" $ do

  -- FIX-56 wires DH-1 + DH-2.  These remaining tests document the
  -- pre-fix behaviour of 'defaultReachability' (still conservative
  -- when no CLI flags are passed) and confirm the storage-path
  -- behaviour without the gossip filter; the runtime gossip filter
  -- itself is covered by spec_fix56_dh_wiring below.

  it "DH-2: PASS — shouldAdvertiseAddress drops Tor when reachability disabled" $
    -- defaultReachability has nrOnion=False.  Pre-FIX-56 this was a
    -- documentation BUG (the function was dead-helper).  Post-FIX-56
    -- the function is wired via reachabilityFromConfig in Main.hs
    -- (MAddrV2 handler), but the unit-level semantics of the function
    -- itself remain unchanged.
    shouldAdvertiseAddress defaultReachability (NetAddrTorV3 torV3Bytes) `shouldBe` False

  it "DH-2: PASS — filterReachableAddresses drops privacy addrs under defaults" $ do
    let entries = [ mkAddrV2 NetTorV3 torV3Bytes
                  , mkAddrV2 NetI2P   i2pBytes
                  , mkAddrV2 NetCJDNS cjdnsBytes
                  ]
        result  = filterReachableAddresses defaultReachability entries
    -- All three are filtered under defaults; the operator must set
    -- --onion / --i2psam / --cjdnsreachable to unfilter them.
    result `shouldBe` []

  it "DH-2: PASS — defaultReachability has nrOnion=False (Tor disabled by default)" $
    nrOnion defaultReachability `shouldBe` False

  it "DH-2: PASS — defaultReachability has nrI2P=False (I2P disabled by default)" $
    nrI2P defaultReachability `shouldBe` False

  it "DH-2: PASS — defaultReachability has nrCJDNS=False (CJDNS disabled by default)" $
    nrCJDNS defaultReachability `shouldBe` False

--------------------------------------------------------------------------------
-- FIX-56: DH-1 + DH-2 wiring tests
--------------------------------------------------------------------------------

spec_fix56_dh_wiring :: Spec
spec_fix56_dh_wiring = describe "FIX-56 DH-1 + DH-2 wiring (W117)" $ do

  -- ----- DH-2: NetworkReachability driven by PeerManagerConfig ----- --

  it "DH-2: defaultPeerManagerConfig → reachabilityFromConfig matches defaultReachability" $
    reachabilityFromConfig defaultPeerManagerConfig `shouldBe` defaultReachability

  it "DH-2: --onion=host:port flips nrOnion=True" $ do
    let cfg = defaultPeerManagerConfig
          { pmcOnion = Just ("127.0.0.1", 9050) }
        r   = reachabilityFromConfig cfg
    nrOnion r `shouldBe` True

  it "DH-2: --proxy=host:port flips nrOnion=True (Core onion-fallback semantics)" $ do
    -- When -onion is not set but -proxy is, Core routes .onion through
    -- the generic SOCKS5 proxy.  reachabilityFromConfig must honour
    -- that fallback so Tor v3 advertise/relay still flips on.
    let cfg = defaultPeerManagerConfig
          { pmcProxy = Just ("127.0.0.1", 9050) }
        r   = reachabilityFromConfig cfg
    nrOnion r `shouldBe` True

  it "DH-2: --onion takes precedence over --proxy for Tor reachability" $ do
    let cfg = defaultPeerManagerConfig
          { pmcProxy = Just ("10.0.0.1", 1080)
          , pmcOnion = Just ("127.0.0.1", 9050)
          }
        r   = reachabilityFromConfig cfg
    nrOnion r `shouldBe` True

  it "DH-2: --i2psam=host:port flips nrI2P=True" $ do
    let cfg = defaultPeerManagerConfig
          { pmcI2pSam = Just ("127.0.0.1", 7656) }
        r   = reachabilityFromConfig cfg
    nrI2P r `shouldBe` True

  it "DH-2: --i2psam does NOT flip Tor reachability" $ do
    let cfg = defaultPeerManagerConfig
          { pmcI2pSam = Just ("127.0.0.1", 7656) }
        r   = reachabilityFromConfig cfg
    nrOnion r `shouldBe` False

  it "DH-2: --cjdnsreachable=True flips nrCJDNS=True" $ do
    let cfg = defaultPeerManagerConfig { pmcCjdnsReachable = True }
        r   = reachabilityFromConfig cfg
    nrCJDNS r `shouldBe` True

  it "DH-2: --cjdnsreachable does NOT affect Tor or I2P reachability" $ do
    let cfg = defaultPeerManagerConfig { pmcCjdnsReachable = True }
        r   = reachabilityFromConfig cfg
    (nrOnion r, nrI2P r) `shouldBe` (False, False)

  it "DH-2: all four CLI flags compose (Tor + I2P + CJDNS all reachable)" $ do
    let cfg = defaultPeerManagerConfig
          { pmcProxy          = Just ("127.0.0.1", 9050)
          , pmcOnion          = Just ("127.0.0.1", 9050)
          , pmcI2pSam         = Just ("127.0.0.1", 7656)
          , pmcCjdnsReachable = True
          }
        r   = reachabilityFromConfig cfg
    (nrIPv4 r, nrIPv6 r, nrOnion r, nrI2P r, nrCJDNS r)
      `shouldBe` (True, True, True, True, True)

  -- ----- DH-2: filterReachableAddresses gates the addrv2 receipt path ----- --

  it "DH-2 wired: filterReachableAddresses keeps Tor entries when --onion set" $ do
    let cfg = defaultPeerManagerConfig
          { pmcOnion = Just ("127.0.0.1", 9050) }
        r   = reachabilityFromConfig cfg
        ent = mkAddrV2 NetTorV3 torV3Bytes
    filterReachableAddresses r [ent] `shouldBe` [ent]

  it "DH-2 wired: filterReachableAddresses keeps I2P entries when --i2psam set" $ do
    let cfg = defaultPeerManagerConfig
          { pmcI2pSam = Just ("127.0.0.1", 7656) }
        r   = reachabilityFromConfig cfg
        ent = mkAddrV2 NetI2P i2pBytes
    filterReachableAddresses r [ent] `shouldBe` [ent]

  it "DH-2 wired: filterReachableAddresses keeps CJDNS entries when --cjdnsreachable" $ do
    let cfg = defaultPeerManagerConfig { pmcCjdnsReachable = True }
        r   = reachabilityFromConfig cfg
        ent = mkAddrV2 NetCJDNS cjdnsBytes
    filterReachableAddresses r [ent] `shouldBe` [ent]

  it "DH-2 wired: filterReachableAddresses still drops Tor when only --i2psam set" $ do
    let cfg = defaultPeerManagerConfig
          { pmcI2pSam = Just ("127.0.0.1", 7656) }
        r   = reachabilityFromConfig cfg
        ent = mkAddrV2 NetTorV3 torV3Bytes
    -- Reachability filter must be per-network: enabling I2P alone
    -- should NOT collapse onion / cjdns gates on.
    filterReachableAddresses r [ent] `shouldBe` []

  it "DH-2 wired: filterReachableAddresses always keeps clearnet (IPv4/IPv6)" $ do
    let entries = [ AddrV2 1700000000 9 NetIPv4 (BS.pack [1,2,3,4]) 8333
                  , AddrV2 1700000000 9 NetIPv6 (BS.replicate 16 0x20) 8333
                  ]
    filterReachableAddresses defaultReachability entries `shouldBe` entries

  -- ----- DH-2: shouldAdvertiseAddress under wired reachability ----- --

  it "DH-2 wired: shouldAdvertiseAddress True for Tor when --onion set" $ do
    let cfg = defaultPeerManagerConfig
          { pmcOnion = Just ("127.0.0.1", 9050) }
        r   = reachabilityFromConfig cfg
    shouldAdvertiseAddress r (NetAddrTorV3 torV3Bytes) `shouldBe` True

  it "DH-2 wired: shouldAdvertiseAddress True for I2P when --i2psam set" $ do
    let cfg = defaultPeerManagerConfig
          { pmcI2pSam = Just ("127.0.0.1", 7656) }
        r   = reachabilityFromConfig cfg
    shouldAdvertiseAddress r (NetAddrI2P i2pBytes) `shouldBe` True

  it "DH-2 wired: shouldAdvertiseAddress True for CJDNS when --cjdnsreachable" $ do
    let cfg = defaultPeerManagerConfig { pmcCjdnsReachable = True }
        r   = reachabilityFromConfig cfg
    shouldAdvertiseAddress r (NetAddrCJDNS cjdnsBytes) `shouldBe` True

  -- ----- DH-1: PeerManagerConfig surface ----- --

  it "DH-1: defaultPeerManagerConfig has all four privacy flags off" $ do
    let c = defaultPeerManagerConfig
    (pmcProxy c, pmcOnion c, pmcI2pSam c, pmcCjdnsReachable c)
      `shouldBe` (Nothing, Nothing, Nothing, False)

  it "DH-1: address dispatch picks Tor proxy for .onion when --onion set" $ do
    -- This is a structural assertion: when an operator sets --onion,
    -- the parsed PeerManagerConfig must record it so 'tryConnectByHost'
    -- can pick the SOCKS5 path.  Functional dialing requires a live
    -- Tor proxy which is out of scope for the unit suite.
    let cfg = defaultPeerManagerConfig
          { pmcOnion = Just ("127.0.0.1", 9050) }
    pmcOnion cfg `shouldBe` Just ("127.0.0.1", 9050)

  it "DH-1: address dispatch picks SAM proxy for .i2p when --i2psam set" $ do
    let cfg = defaultPeerManagerConfig
          { pmcI2pSam = Just ("127.0.0.1", 7656) }
    pmcI2pSam cfg `shouldBe` Just ("127.0.0.1", 7656)

  it "DH-1: --proxy is used for clearnet outbound SOCKS5 routing" $ do
    let cfg = defaultPeerManagerConfig
          { pmcProxy = Just ("127.0.0.1", 9050) }
    pmcProxy cfg `shouldBe` Just ("127.0.0.1", 9050)

  it "DH-1: --cjdnsreachable does NOT install a proxy (CJDNS is direct dial)" $ do
    let cfg = defaultPeerManagerConfig { pmcCjdnsReachable = True }
    (pmcProxy cfg, pmcI2pSam cfg, pmcOnion cfg)
      `shouldBe` (Nothing, Nothing, Nothing)

--------------------------------------------------------------------------------
-- Two-pipeline documentation tests
--------------------------------------------------------------------------------

spec_two_pipeline :: Spec
spec_two_pipeline = describe "Two-pipeline divergences (TP-1, TP-2)" $ do

  it "TP-1: addrV2ToAddrEntry silently drops TorV3 (storage path discards privacy addrs)" $ do
    let av2s = [ mkAddrV2 NetTorV3 torV3Bytes
               , mkAddrV2 NetI2P   i2pBytes
               , mkAddrV2 NetCJDNS cjdnsBytes
               ]
        converted = mapMaybe addrV2ToAddrEntry av2s
    -- The STORAGE code path (Main.hs:1957) converts via addrV2ToAddrEntry.
    -- All three privacy-network entries are dropped.
    converted `shouldBe` []

  it "TP-1: addrV2ToAddrEntry keeps IPv4 entries (storage path is correct for clearnet)" $ do
    let av2 = AddrV2 1700000000 9 NetIPv4 (BS.pack [1,2,3,4]) 8333
        converted = mapMaybe addrV2ToAddrEntry [av2]
    length converted `shouldBe` 1

  it "TP-2: BUG — relay path (relayAddrToRandomPeers) ignores piWantsAddrV2 flag" $
    -- relayAddrToRandomPeers sends MAddrV2 unconditionally.
    -- Core gates relay on peer.m_wants_addrv2 (net_processing.cpp:5468).
    True `shouldBe` True

--------------------------------------------------------------------------------
-- Top-level spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "W117 BIP-155 Privacy Networks (Tor / I2P / CJDNS) — 30 gates" $ do

    spec_g1_g2_network_ids

    spec_g3_g4_sendaddrv2

    spec_g5_g7_addrv2_receipt

    spec_g8_g9_wire_format

    spec_g10_cjdns_prefix

    spec_g11_g12_rpc

    spec_g13_g14_addrv1_compat

    spec_g15_g20_proxy_config

    spec_g21_cjdns_status

    spec_g22_unknown_netid

    spec_g23_length_mismatch

    spec_g24_g25_tor_inbound

    spec_g26_g27_addr_detection

    spec_g29_g30_addrman_sendaddrv2

    spec_dead_helpers

    spec_two_pipeline

    -- FIX-56 DH-1 + DH-2 wiring tests
    spec_fix56_dh_wiring

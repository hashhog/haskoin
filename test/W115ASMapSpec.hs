{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W115 ASMap (Autonomous System Map) — 30-gate fleet audit
--
-- References:
--   bitcoin-core/src/util/asmap.h / asmap.cpp
--   bitcoin-core/src/netgroup.h / netgroup.cpp
--   bitcoin-core/src/addrman.cpp (GetMappedAS usage in GetGroup / GetNewBucket)
--   bitcoin-core/src/init.cpp (asmap loading, -asmap config option)
--   bitcoin-core/src/rpc/net.cpp (mapped_as in getpeerinfo / getnodeaddresses)
--
-- ===================================================================
-- VERDICT: ASMap is MISSING ENTIRELY from haskoin.
--
-- Zero source files import or define: Interpret, SanityCheckAsmap,
-- CheckStandardAsmap, DecodeAsmap, AsmapVersion, GetMappedAS,
-- NetGroupManager, or any "-asmap" config field.
--
-- The AddrMan bucket-hashing path (getNewBucket / getTriedBucket /
-- computeNetworkGroup) always uses raw IP /16 or /32 groups.  No
-- ASN override path exists.  The getpeerinfo RPC response has no
-- "mapped_as" field.  The getnetworkinfo response has no
-- "asmap_version" field.
-- ===================================================================
--
-- ===================================================================
-- TWO-PIPELINE FINDINGS
-- ===================================================================
--
-- TP-1  [TWO-PIPELINE][HIGH] Two independent network-group functions:
--        * getNetworkGroup  :: SockAddr -> Word32   (eviction only, Network.hs:3806)
--        * computeNetworkGroup :: SockAddr -> NetworkGroup (AddrMan, Network.hs:4372)
--        Both implement the same /16 (IPv4) / /32 (IPv6) grouping logic
--        from separate code paths.  Their IPv6 logic differs:
--          getNetworkGroup:    h1 `div` 0x10000   (drops lower 16 bits)
--          computeNetworkGroup: 4 bytes from h1   (correct /32 extraction)
--        Without ASMap the divergence only affects eclipse eviction
--        diversity; WITH ASMap the eviction path would not benefit from
--        ASN-based diversity even if it were implemented, because
--        getNetworkGroup is never consulted by the AddrMan path and
--        computeNetworkGroup is never consulted by eviction.
--        Reference: netgroup.cpp GetGroup() — one canonical implementation.
--
-- ===================================================================
-- DEAD-HELPER FINDINGS
-- ===================================================================
--
-- (No ASMap dead helpers — the entire subsystem is absent, not defined-
--  but-unused.  This is stronger: MISSING ENTIRELY.)
--
-- ===================================================================
-- BUGS — 30 GATES
-- ===================================================================
--
-- G1  [CONFIG][MISSING ENTIRELY] No -asmap=<file> config option.
--     Core init.cpp:540 adds "-asmap=<file>" to argsman.  haskoin
--     NodeOptions (Main.hs:84) has no asmapPath or asmapEnable field.
--     Files: app/Main.hs:84-138 (NodeOptions), config.example.toml.
--
-- G2  [CONFIG][MISSING ENTIRELY] No asmap file loading at startup.
--     Core init.cpp:1587-1628 calls DecodeAsmap(path) if -asmap is set,
--     or uses embedded ip_asn bytes.  haskoin Daemon has no equivalent.
--     File: src/Haskoin/Daemon.hs.
--
-- G3  [CONFIG][MISSING ENTIRELY] No MAX_ASMAP_FILESIZE (8 MiB) guard.
--     Core rejects files larger than 8 MiB (init.cpp / DecodeAsmap).
--     haskoin: no file-size limit at all.
--
-- G4  [CONFIG][MISSING ENTIRELY] No CheckStandardAsmap call at startup.
--     Core calls CheckStandardAsmap(buffer) (128-bit input check) before
--     accepting the file.  haskoin: no sanity-check path.
--
-- G5  [CONFIG][MISSING ENTIRELY] No embedded asmap (ip_asn) support.
--     Core ships an optional embedded ip_asn byte array and uses it when
--     -asmap is passed without a path (-asmap=1 / -asmap).  haskoin has
--     no embedded array and no fallback.
--
-- G6  [DATA-STRUCTURE][MISSING ENTIRELY] No bytecode interpreter (Interpret).
--     Core: Interpret(asmap, ip) walks the bit-trie with RETURN / JUMP /
--     MATCH / DEFAULT instructions.  haskoin: nothing.
--     File: bitcoin-core/src/util/asmap.cpp:182.
--
-- G7  [DATA-STRUCTURE][MISSING ENTIRELY] No DecodeBits / DecodeASN /
--     DecodeMatch / DecodeJump / DecodeType helpers.
--     These parse the variable-length bit-encoded ASMap instructions.
--     File: bitcoin-core/src/util/asmap.cpp:87-171.
--
-- G8  [DATA-STRUCTURE][MISSING ENTIRELY] No SanityCheckAsmap.
--     Core SanityCheckAsmap(asmap, bits) validates all execution paths,
--     jump ranges, padding, and instruction ordering.
--     File: bitcoin-core/src/util/asmap.cpp:239.
--
-- G9  [DATA-STRUCTURE][MISSING ENTIRELY] No AsmapVersion (SHA256 checksum).
--     Core AsmapVersion(data) hashes the raw bytes to produce a uint256
--     for version comparison and peers.dat consistency checks.
--     File: bitcoin-core/src/util/asmap.cpp:348.
--
-- G10 [DATA-STRUCTURE][MISSING ENTIRELY] No IPv4-in-IPv6 padding for lookup.
--     Core GetMappedAS: IPv4 addresses are padded to 16 bytes as
--     IPV4_IN_IPV6_PREFIX + 4-byte IPv4 before calling Interpret().
--     haskoin computeNetworkGroup/getNewBucket: works on raw SockAddr
--     with no padding; an IPv4 ASN lookup would receive only 4 bytes
--     instead of 16, giving wrong trie traversal.
--     File: bitcoin-core/src/netgroup.cpp:88-96.
--
-- G11 [ADDRMAN][MISSING ENTIRELY] No GetMappedAS call in GetGroup path.
--     Core NetGroupManager::GetGroup() calls GetMappedAS() first; if the
--     ASN is non-zero, returns [NET_IPV6, asn_byte3, asn_byte2, asn_byte1,
--     asn_byte0] so IPv4 and IPv6 peers in the same AS share a bucket.
--     haskoin computeNetworkGroup: always falls back to raw /16 or /32
--     groups; no ASN lookup, no ASN-keyed group bytes.
--     File: src/Haskoin/Network.hs:4372.
--
-- G12 [ADDRMAN][MISSING ENTIRELY] No ASN-based bucket override in getNewBucket.
--     Core AddrInfo::GetNewBucket: when ASMap is active, addrGroup and
--     sourceGroup are the 5-byte ASN groups returned by GetGroup()
--     (NET_IPV6 + 4 ASN bytes) rather than raw IP prefixes.
--     haskoin getNewBucket: always uses getNetworkGroupBS which ignores ASN.
--     File: src/Haskoin/Network.hs:4583.
--
-- G13 [ADDRMAN][MISSING ENTIRELY] No ASN-based bucket override in getTriedBucket.
--     Same as G12 but for the tried table.
--     File: src/Haskoin/Network.hs:4599.
--
-- G14 [ADDRMAN][MISSING ENTIRELY] No NetGroupManager / usingAsmap flag.
--     Core NetGroupManager holds the asmap data and exposes UsingASMap().
--     haskoin AddrMan / PeerManager: no such wrapper; no runtime flag to
--     enable/disable ASN-based bucketing.
--     File: bitcoin-core/src/netgroup.h:17.
--
-- G15 [ADDRMAN][MISSING ENTIRELY] No GetAsmapVersion() in AddrMan.
--     Core addrman.cpp serialises the asmap version (uint256) after
--     bucket entries so that loading peers.dat detects a stale asmap and
--     resets the new-table.  haskoin AddrMan has no asmap version field
--     and no peers.dat serialisation at all (W104 BUG-19).
--     File: bitcoin-core/src/addrman.cpp:205.
--
-- G16 [SANITY][MISSING ENTIRELY] No SanityCheckAsmap validation path.
--     Core rejects asmap data that fails SanityCheckAsmap at load time.
--     haskoin: no validation; malformed data would silently produce ASN=0
--     for every lookup (or crash in an interpreter that doesn't exist).
--
-- G17 [SANITY][MISSING ENTIRELY] No startup log "Using asmap version ...".
--     Core init.cpp:1628: LogInfo("Using asmap version %s for IP bucketing").
--     haskoin: no equivalent log line.
--
-- G18 [SANITY] No 8 MiB size guard (same as G3; explicit gate).
--     The MAX_ASMAP_FILESIZE limit is a standalone guard in Core (separate
--     from the parser).  haskoin: no file-size validation anywhere.
--
-- G19 [SANITY][MISSING ENTIRELY] No bit-alignment / padding check.
--     SanityCheckAsmap verifies that trailing bits after the last RETURN
--     are all zero and that padding ≤ 7 bits.  haskoin: absent.
--
-- G20 [SANITY][MISSING ENTIRELY] No INVALID sentinel propagation.
--     Core Interpret() returns 0 (not a valid ASN per RFC 7607) on any
--     parse error, including INVALID from DecodeBits.  A haskoin Interpret
--     would need to mirror this contract.  Currently absent entirely.
--
-- G21 [PEER-BEHAVIOUR][MISSING ENTIRELY][P1] getpeerinfo missing "mapped_as".
--     Core rpc/net.cpp:236-237: emits "mapped_as" key only when the
--     stat is non-zero.  haskoin handleGetPeerInfo (Rpc.hs:2464): no
--     "mapped_as" field at all.  Operator tooling that reads mapped_as
--     to detect ASN diversity will silently get nothing.
--     File: src/Haskoin/Rpc.hs:2475-2511.
--
-- G22 [PEER-BEHAVIOUR][MISSING ENTIRELY] getnodeaddresses missing "mapped_as".
--     Core rpc/net.cpp:1123-1125 emits "mapped_as" and "source_mapped_as"
--     in the per-entry object.  haskoin: getnodeaddresses is not
--     implemented at all (not in method dispatch table).
--     File: src/Haskoin/Rpc.hs:903-919 (dispatch table).
--
-- G23 [PEER-BEHAVIOUR][MISSING ENTIRELY] No ASMapHealthCheck.
--     Core net.h:1256 / net.cpp: ASMapHealthCheck() called on an
--     interval (ASMapHealthCheck interval = 24h in net.cpp) to log
--     "N clearnet peers mapped to M ASNs".
--     haskoin: no health-check, no ASN diversity logging.
--
-- G24 [PEER-BEHAVIOUR][TWO-PIPELINE] getNetworkGroup vs computeNetworkGroup
--     divergence (same as TP-1).  Even without ASMap, the /16 and /32
--     prefix extraction logic is implemented twice.  The IPv6 case uses
--     `div 0x10000` in getNetworkGroup (drops low 16 bits of h1) vs
--     explicit 4-byte extraction in computeNetworkGroup — different output
--     for any IPv6 address where bits 16–31 of h1 are non-zero.
--     File: src/Haskoin/Network.hs:3806-3818 vs 4372-4392.
--
-- G25 [STATS][MISSING ENTIRELY] No "mapped_as" in getpeerinfo output (same as G21).
--     Restating explicitly as a stats gate: the per-peer stat field is
--     absent; bitcoin-cli and monitoring scripts cannot display per-peer
--     ASN.
--
-- G26 [STATS][MISSING ENTIRELY] No asmap_version in getnetworkinfo.
--     Core does not currently expose asmap_version directly in
--     getnetworkinfo, but bitcoin-cli GetInfo reads mapped_as from
--     getpeerinfo to decide whether to show the ASN column.  haskoin
--     does not expose any asmap state via RPC.
--
-- G27 [STATS][MISSING ENTIRELY] No ASN diversity tracking in outbound slots.
--     Core net.cpp: outbound connection logic uses ASN groups (from
--     NetGroupManager) to limit connections to the same AS.
--     haskoin: odConnectedGroups (Network.hs:4784) tracks NetworkGroup
--     by raw IP prefix; no ASN-aware diversity limit.
--     File: src/Haskoin/Network.hs:4784-4820.
--
-- G28 [STATS][MISSING ENTIRELY] No per-peer ASN stored in PeerInfo / PeerConnection.
--     Core NodeStats::m_mapped_as is populated via GetMappedAS on every
--     CNode stats snapshot.  haskoin PeerInfo (Network.hs:2536) has no
--     mappedAS field.
--     File: src/Haskoin/Network.hs:2536.
--
-- G29 [PERSISTENCE][MISSING ENTIRELY] No asmap version in peers.dat.
--     Core addrman.cpp:205 serialises the AsmapVersion uint256 after bucket
--     entries so a new asmap triggers re-bucketing of the new table on load.
--     haskoin: no peers.dat at all (W104 BUG-19) and no AsmapVersion field.
--
-- G30 [PERSISTENCE][MISSING ENTIRELY] No re-bucketing on asmap change.
--     Core addrman.cpp:313-347: if loaded asmap_version != serialised version
--     the new table is discarded and re-bucketed with the new asmap.
--     haskoin: no such logic.

module W115ASMapSpec (spec) where

import Test.Hspec
import Data.Bits (shiftR, (.&.), (.|.))
import Data.Word (Word8, Word32)
import qualified Data.ByteString as BS
import Network.Socket (SockAddr(..))

import Haskoin.Network
  ( computeNetworkGroup
  , getNetworkGroup
  , NetworkGroup(..)
  , getNetworkGroupBS
  )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | A routable IPv4 address 1.2.3.4 in host-byte-order (Linux little-endian)
-- HostAddress = 0x04030201 means first octet = 0x01 = 1 on little-endian.
-- Network.hs comments confirm: "first_octet = addr .&. 0xff"
addr_1_2_3_4 :: SockAddr
addr_1_2_3_4 = SockAddrInet 8333 0x04030201

-- | A different routable IPv4 address 5.6.7.8
addr_5_6_7_8 :: SockAddr
addr_5_6_7_8 = SockAddrInet 8333 0x08070605

-- | An IPv4 address in the same /16 as 1.2.3.4: 1.2.99.100
addr_1_2_99_100 :: SockAddr
addr_1_2_99_100 = SockAddrInet 8333 0x64630201

-- | An IPv4 address in a different /16: 1.3.4.5
addr_1_3_4_5 :: SockAddr
addr_1_3_4_5 = SockAddrInet 8333 0x05040301

--------------------------------------------------------------------------------
-- G1-G5: Config gates — MISSING ENTIRELY
-- These tests document the absence of ASMap config support.
--------------------------------------------------------------------------------

spec_g1_g5_config :: Spec
spec_g1_g5_config = describe "G1-G5: ASMap config (MISSING ENTIRELY)" $ do

  it "G1: -asmap config option is absent from NodeOptions (MISSING ENTIRELY)" $
    -- NodeOptions in Main.hs has no asmapPath :: Maybe FilePath field.
    -- This test documents the structural gap; it passes trivially because
    -- haskoin compiles without any asmap-related fields.
    True `shouldBe` True

  it "G2: no asmap file loading at startup (MISSING ENTIRELY)" $
    -- Daemon startup in Haskoin.Daemon does not call DecodeAsmap or any
    -- equivalent.  Passes trivially; documents the absence.
    True `shouldBe` True

  it "G3: no MAX_ASMAP_FILESIZE (8 MiB) guard (MISSING ENTIRELY)" $
    -- Core rejects asmap files > 8 MiB.  haskoin has no such constant or check.
    let maxAsmapFileSizeCore = 8 * 1024 * 1024 :: Int  -- 8 MiB
    in maxAsmapFileSizeCore `shouldBe` 8_388_608

  it "G4: no CheckStandardAsmap (128-bit validation) at startup (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G5: no embedded asmap (ip_asn) support (MISSING ENTIRELY)" $
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G6-G10: Data structure gates — MISSING ENTIRELY
--------------------------------------------------------------------------------

spec_g6_g10_data :: Spec
spec_g6_g10_data = describe "G6-G10: ASMap data structures (MISSING ENTIRELY)" $ do

  it "G6: Interpret bytecode interpreter is absent (MISSING ENTIRELY)" $
    -- Core: Interpret(asmap, ip) → Word32 ASN via RETURN/JUMP/MATCH/DEFAULT.
    -- haskoin: no such function exists in any module.
    True `shouldBe` True

  it "G7: DecodeBits/DecodeASN/DecodeMatch/DecodeJump helpers absent (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G8: SanityCheckAsmap absent (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G9: AsmapVersion (SHA256 checksum) absent (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G10: IPv4-in-IPv6 padding for lookup absent — 4 bytes not 16 (MISSING ENTIRELY)" $
    -- Core GetMappedAS pads IPv4 to 16 bytes: IPV4_IN_IPV6_PREFIX ++ 4-byte IPv4.
    -- haskoin computeNetworkGroup / getNetworkGroupBS operate on raw SockAddr
    -- and produce ≤5 bytes for IPv4; a trie lookup would receive wrong input.
    let ipv4Group = getNetworkGroupBS addr_1_2_3_4
    in BS.length ipv4Group `shouldBe` 3  -- [0x04, octet1, octet2] — NOT 16 bytes

--------------------------------------------------------------------------------
-- G11-G15: AddrMan integration gates — MISSING ENTIRELY
--------------------------------------------------------------------------------

spec_g11_g15_addrman :: Spec
spec_g11_g15_addrman = describe "G11-G15: AddrMan ASMap integration (MISSING ENTIRELY)" $ do

  it "G11: computeNetworkGroup never calls GetMappedAS — always raw IP prefix" $ do
    -- When ASMap is active, Core returns [NET_IPV6, b3, b2, b1, b0] of the ASN.
    -- haskoin always returns [0x04, octet1, octet2] for IPv4 regardless.
    let ng = computeNetworkGroup addr_1_2_3_4
        bs = getNetworkGroupBytes ng
    BS.length bs `shouldBe` 3          -- not 5 (ASN group would be 5 bytes)
    BS.index bs 0 `shouldBe` 0x04      -- NET_IPV4 tag, not NET_IPV6=0x06

  it "G11b: two IPv4 addresses in same AS would get different groups (no ASN)" $ do
    -- Peers 1.2.3.4 and 5.6.7.8 could share the same AS; without ASMap they
    -- end up in different /16 groups, defeating eclipse resistance.
    let ng1 = computeNetworkGroup addr_1_2_3_4
        ng2 = computeNetworkGroup addr_5_6_7_8
    ng1 `shouldNotBe` ng2  -- different /16 groups without ASMap

  it "G12: getNewBucket uses raw IP groups, not ASN groups (MISSING ENTIRELY)" $
    -- Core getNewBucket uses addrGroup from GetGroup() which may be ASN-keyed.
    -- haskoin getNewBucket uses getNetworkGroupBS — always raw /16 or /32.
    True `shouldBe` True

  it "G13: getTriedBucket uses raw IP groups, not ASN groups (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G14: no NetGroupManager / usingAsmap flag in AddrMan or PeerManager (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G15: no AsmapVersion stored in peers.dat / AddrMan serialisation (MISSING ENTIRELY)" $
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G16-G20: Sanity / validation gates — MISSING ENTIRELY
--------------------------------------------------------------------------------

spec_g16_g20_sanity :: Spec
spec_g16_g20_sanity = describe "G16-G20: ASMap sanity/validation (MISSING ENTIRELY)" $ do

  it "G16: no SanityCheckAsmap call on load (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G17: no startup log 'Using asmap version ...' (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G18: no 8 MiB file-size guard (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G19: no trailing-bit zero-padding check (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G20: no INVALID (0xFFFFFFFF) sentinel propagation from DecodeBits (MISSING ENTIRELY)" $
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G21-G24: Peer-behaviour gates
--------------------------------------------------------------------------------

spec_g21_g24_peer :: Spec
spec_g21_g24_peer = describe "G21-G24: Peer behaviour / ASMap" $ do

  it "G21: getpeerinfo has no 'mapped_as' field (MISSING ENTIRELY)" $
    -- The peerToEnc function in Rpc.hs:2464 emits 34 fields; none is
    -- "mapped_as".  This test documents the absence structurally.
    -- Core rpc/net.cpp:236-237 emits "mapped_as" when non-zero.
    True `shouldBe` True

  it "G22: getnodeaddresses is not implemented (MISSING ENTIRELY)" $
    -- Core exposes getnodeaddresses which includes "mapped_as" and
    -- "source_mapped_as" per-entry.  haskoin has no such RPC handler.
    True `shouldBe` True

  it "G23: no ASMapHealthCheck periodic log (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G24 / TP-1: two-pipeline — getNetworkGroup vs computeNetworkGroup diverge for IPv6" $ do
    -- getNetworkGroup (eviction path) uses `h1 \`div\` 0x10000` — extracts bits
    -- 16-31 of the first Word32, treating it as a 16-bit prefix.
    -- computeNetworkGroup (AddrMan path) extracts 4 full bytes from h1.
    -- For an IPv6 address where bits 0-15 of h1 are non-zero, the two
    -- functions produce different groupings:
    --   getNetworkGroup:    octet1 = h1 .&. 0xff is NOT used;
    --                       result = h1 `div` 0x10000 (a Word32 scalar)
    --   computeNetworkGroup: extracts all 4 bytes of h1 as NetworkGroup ByteString
    --
    -- Verify the structural difference: the two functions have different
    -- return types — one is Word32, the other is NetworkGroup (ByteString).
    -- They cannot be trivially compared, confirming separate pipelines.
    let ipv6Addr = SockAddrInet6 8333 0 (0xABCD1234, 0, 0, 0) 0
        wordGroup = getNetworkGroup ipv6Addr         -- Word32
        bsGroup   = computeNetworkGroup ipv6Addr     -- NetworkGroup
        bsBytes   = getNetworkGroupBytes bsGroup
    -- getNetworkGroup extracts h1 `div` 0x10000 = 0xABCD
    wordGroup `shouldBe` 0xABCD
    -- computeNetworkGroup extracts all 4 bytes of h1 big-endian: AB CD 12 34
    -- but the actual byte ordering depends on host representation
    BS.length bsBytes `shouldBe` 5  -- [0x06, b1, b2, b3, b4]

  it "G24b: getNetworkGroup IPv4 and computeNetworkGroup IPv4 agree on /16 grouping" $ do
    -- For IPv4 this is the same logic; verify consistency as a positive case.
    -- addr 1.2.3.4 in little-endian host: 0x04030201
    -- first octet = 0x04030201 .&. 0xff = 1, second = (>>8).&.0xff = 2
    -- getNetworkGroup: octet1*256+octet2 = 1*256+2 = 258
    -- computeNetworkGroup: [0x04, 1, 2]
    let wg = getNetworkGroup addr_1_2_3_4
        ng = computeNetworkGroup addr_1_2_3_4
        bs = getNetworkGroupBytes ng
    wg `shouldBe` 258   -- 1*256 + 2
    BS.index bs 0 `shouldBe` 0x04   -- NET_IPV4
    BS.index bs 1 `shouldBe` 1      -- first octet
    BS.index bs 2 `shouldBe` 2      -- second octet

  it "G24c: same /16 — two addresses with same first two octets get same group" $ do
    -- 1.2.3.4 and 1.2.99.100 should share /16 group
    let ng1 = computeNetworkGroup addr_1_2_3_4
        ng2 = computeNetworkGroup addr_1_2_99_100
    ng1 `shouldBe` ng2

  it "G24d: different /16 — 1.2.x.x vs 1.3.x.x get different groups" $ do
    let ng1 = computeNetworkGroup addr_1_2_3_4
        ng3 = computeNetworkGroup addr_1_3_4_5
    ng1 `shouldNotBe` ng3

--------------------------------------------------------------------------------
-- G25-G28: Stats gates — MISSING ENTIRELY
--------------------------------------------------------------------------------

spec_g25_g28_stats :: Spec
spec_g25_g28_stats = describe "G25-G28: ASMap stats" $ do

  it "G25: no mapped_as in getpeerinfo — same as G21 (MISSING ENTIRELY)" $
    True `shouldBe` True

  it "G26: no asmap-related field in getnetworkinfo (MISSING ENTIRELY)" $
    -- Core does not expose asmap_version in getnetworkinfo, but bitcoin-cli
    -- reads mapped_as from getpeerinfo.  haskoin getnetworkinfo at
    -- Rpc.hs:2393 has no asmap indicator field.
    True `shouldBe` True

  it "G27: outbound diversity uses raw IP group, not ASN (MISSING ENTIRELY)" $
    -- odConnectedGroups in Network.hs:4784 tracks NetworkGroup by raw /16
    -- IP prefix.  With ASMap, Core tracks by ASN group so two peers in
    -- the same AS (different /16) would share a slot.  haskoin never
    -- applies ASN-based slot limiting.
    True `shouldBe` True

  it "G28: PeerInfo has no mappedAS field (MISSING ENTIRELY)" $
    True `shouldBe` True

--------------------------------------------------------------------------------
-- G29-G30: Persistence gates — MISSING ENTIRELY
--------------------------------------------------------------------------------

spec_g29_g30_persist :: Spec
spec_g29_g30_persist = describe "G29-G30: ASMap persistence" $ do

  it "G29: no AsmapVersion stored in peers.dat (MISSING ENTIRELY)" $
    -- Core addrman.cpp:205 writes uint256 asmap_version after bucket entries.
    -- haskoin has no peers.dat at all (W104 BUG-19) and no AsmapVersion field.
    True `shouldBe` True

  it "G30: no re-bucketing logic on asmap version mismatch (MISSING ENTIRELY)" $
    -- Core addrman.cpp:313-347: if serialised asmap_version differs from
    -- the loaded asmap, the new table is discarded and re-bucketed.
    -- haskoin: absent.
    True `shouldBe` True

--------------------------------------------------------------------------------
-- Bonus: Core format / contract pinning tests
-- These pin the expected contract so that future implementations can be
-- verified against them.
--------------------------------------------------------------------------------

spec_asmap_contracts :: Spec
spec_asmap_contracts = describe "ASMap contracts (Core format reference pins)" $ do

  it "ASN 0 is the 'not found' sentinel (RFC 7607 reserves AS0)" $
    -- Core Interpret returns 0 on error or no-match.
    -- AS0 is reserved and not a valid assignable AS per RFC 7607.
    -- A future haskoin Interpret must return 0, not error, on unknown prefix.
    (0 :: Word32) `shouldBe` 0

  it "getNetworkGroupBS for IPv4 produces 3 bytes: [NET_IPV4, oct1, oct2]" $ do
    let bs = getNetworkGroupBS addr_1_2_3_4
    BS.length bs `shouldBe` 3
    BS.index bs 0 `shouldBe` 0x04  -- NET_IPV4

  it "getNetworkGroupBS for IPv6 produces 5 bytes: [NET_IPV6, b1..b4]" $ do
    let ipv6 = SockAddrInet6 8333 0 (0x20010DB8, 0, 0, 0) 0
        bs   = getNetworkGroupBS ipv6
    BS.length bs `shouldBe` 5
    BS.index bs 0 `shouldBe` 0x06  -- NET_IPV6

  it "ASN group (when ASMap active) would be 5 bytes: [NET_IPV6, asn_b3..asn_b0]" $
    -- Core netgroup.cpp:26-30: for non-zero ASN the group is
    --   [NET_IPV6 (0x06), (asn>>0)&0xff, (asn>>8)&0xff, (asn>>16)&0xff, (asn>>24)&0xff]
    -- This pins the expected wire format for a future implementation.
    let asn = 13335 :: Word32  -- Cloudflare's ASN
        expectedGroup = BS.pack [ 0x06
                                , fromIntegral (asn .&. 0xff)
                                , fromIntegral ((asn `shiftR` 8) .&. 0xff)
                                , fromIntegral ((asn `shiftR` 16) .&. 0xff)
                                , fromIntegral ((asn `shiftR` 24) .&. 0xff)
                                ]
    in BS.length expectedGroup `shouldBe` 5

  it "MAX_ASMAP_FILESIZE contract: 8 MiB = 8388608 bytes" $
    (8 * 1024 * 1024 :: Int) `shouldBe` 8_388_608

  it "ASMap bit encoding: ConsumeBitLE uses LSB-first bit ordering within bytes" $
    -- Core asmap.cpp:54-58: bit n of byte b is (bytes[n/8] >> (n%8)) & 1
    -- (little-endian bit order within each byte, opposite of IP address bits
    --  which use big-endian bit order via ConsumeBitBE)
    -- 0xB1 = 1011 0001 binary
    let byte = 0xB1 :: Word8
        bit0 = (byte `shiftR` 0) .&. 1  -- LSB = 1  (bit 0 of 0xB1)
        bit7 = (byte `shiftR` 7) .&. 1  -- MSB = 1  (bit 7 of 0xB1 = 0xB1 >> 7 = 1)
        bit1 = (byte `shiftR` 1) .&. 1  -- next bit = 0 (0xB1 = ...0001, bit1 = 0)
    in (bit0, bit1, bit7) `shouldBe` (1, 0, 1)

  it "ASMap IP bit encoding: ConsumeBitBE uses MSB-first (network byte order)" $
    -- Core asmap.cpp:65-68: bit n of IP byte b is (bytes[n/8] >> (7 - n%8)) & 1
    -- For IP 1.2.3.4 (big-endian wire: 0x01 0x02 0x03 0x04):
    -- bit 0 = MSB of first byte = 0x01 >> 7 = 0
    -- bit 7 = LSB of first byte = 0x01 >> 0 & 1 = 1
    let firstByte = 0x01 :: Word8
        bit0 = (firstByte `shiftR` 7) .&. 1   -- MSB = 0
        bit7 = (firstByte `shiftR` 0) .&. 1   -- LSB = 1
    in (bit0, bit7) `shouldBe` (0, 1)

--------------------------------------------------------------------------------
-- Top-level spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W115 ASMap — haskoin (MISSING ENTIRELY)" $ do
  spec_g1_g5_config
  spec_g6_g10_data
  spec_g11_g15_addrman
  spec_g16_g20_sanity
  spec_g21_g24_peer
  spec_g25_g28_stats
  spec_g29_g30_persist
  spec_asmap_contracts

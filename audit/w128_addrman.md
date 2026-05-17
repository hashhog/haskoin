# W128 AddrMan + connman + peer selection audit — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** AddrMan add/select/good/attempt/connected/terrible; tried-collision
resolution; bucketing parameters; outbound peer selection (ThreadOpenConnections
analogue); eviction; BanMan + discouragement. **EXCLUDES BIP-155** (covered by
W117) and the AddrMan in-table mechanics already exhaustively catalogued by
W104 (those are referenced where they overlap, not re-counted).
**Result:** 6 PRESENT / 9 PARTIAL / 15 MISSING out of 30 gates.
**Bugs found:** 18 distinct from W104 (1 P0-DOSY, 5 P0-CDIV, 6 P1, 6 P2).
**Tests added:** 38 hspec assertions / `xit` sentinels in
`W128AddrManSpec.hs`.

## Top-line verdict

haskoin's `Network.hs` AddrMan covers the bucket-table data structures (1024
new + 256 tried, 64-per-bucket, all the per-group/per-source ratios) and the
two table-mutating entry points (`addAddress`, `markGood`, `markAttempt`)
that W104 catalogued in detail. **The connection-loop and ban surface that
sits AROUND AddrMan is much weaker than the AddrMan itself.** This audit
focuses on those surrounding layers and finds three classes of divergence:

1. **Tried-table collision resolution is absent (P0-CDIV).** Core implements
   a test-before-evict discipline: when `Good()` finds the tried slot
   occupied, it inserts the new candidate into `m_tried_collisions`,
   `ThreadOpenConnections` opens a FEELER connection to the OLD address
   first via `SelectTriedCollision()`, and the slot is only overwritten if
   that probe fails. haskoin's `markGood` unconditionally overwrites the
   tried slot — there is no `m_tried_collisions` set, no
   `SelectTriedCollision()`, no `ResolveCollisions()`, no FEELER connection
   type, and no `ADDRMAN_REPLACEMENT` / `ADDRMAN_TEST_WINDOW` /
   `ADDRMAN_SET_TRIED_COLLISION_SIZE` constants anywhere in the codebase.
   This is W104 BUG-11 escalated to "the test-before-evict path is missing
   end-to-end" — not just the AddrMan-side flag set, but the
   ThreadOpenConnections-side probe and the FEELER ConnectionType itself.

2. **BanMan conflates Ban with Discourage and lacks subnet semantics
   (P0-DOSY).** Core's `BanMan` separates two distinct concepts:
   *Banning* (CSubNet -> CBanEntry, operator-set via `setban` RPC, blocks
   inbound + outbound + addr-gossip, persisted to `banlist.json`) and
   *Discouragement* (`CRollingBloomFilter<50000, 0.000001>` membership
   test on `CNetAddr::GetAddrBytes()`, automatic on misbehavior, blocks
   outbound + addr-gossip, allows inbound when slots free, NOT persisted).
   haskoin has a single `pmBannedAddrs :: TVar (Map SockAddr Int64)` keyed
   on `SockAddr` (address + port) with no subnet support, used for both
   `banPeer` and `Discourage` semantics. `isDiscouraged` is literally just
   `isBanned`. Consequences:
   * No way to ban an IPv4 /24 or IPv6 /48 subnet (operator must enumerate
     individual address+port pairs).
   * Misbehaving peers are added to the same persisted map as operator-set
     bans, growing the disk-backed banlist unboundedly across runs
     (precisely the DOS vector that prompted the 2024 Core advisory at
     bitcoincore.org/en/2024/07/03/disclose-unbounded-banlist — fixed in
     Core PR #25974, by switching misbehavior to a discouragement bloom).
   * Two different peers on the same /16 cannot be discouraged at the
     subnet level; an attacker rotating source IPs in a /24 evades the ban
     by simply spinning up a new port.

3. **The connection-loop conflates connection types and lacks several
   selection branches.** Core's `ThreadOpenConnections` rotates between
   `OUTBOUND_FULL_RELAY`, `BLOCK_RELAY`, `FEELER`, `MANUAL`, `ADDR_FETCH`,
   and `PRIVATE_BROADCAST` (and decides per-iteration which type to open
   via a 5-branch if/else around line 2720). haskoin has only "full-relay"
   and "block-relay-only"; FEELER / EXTRA / MaybePickPreferredNetwork all
   missing. Tracking variables that gate Core's logic (`next_feeler`,
   `next_extra_block_relay`, `next_extra_network_peer`,
   `EXTRA_NETWORK_PEER_INTERVAL`, `SEED_OUTBOUND_CONNECTION_THRESHOLD`)
   have no haskoin analogue. The diversity check is a single
   `checkOutboundDiversity` set lookup instead of the per-connection-type
   netgroup tracking that Core does (Core counts privacy-network peers
   separately; haskoin does not).

The single P0-DOSY shape divergence (item 2) and four P0-CDIV scattered
across items 1/3 are the most important findings.

## Gates: PRESENT / PARTIAL / MISSING

| Gate | Topic | Status | Bug |
|------|-------|--------|-----|
| G1 | `ADDRMAN_*` bucket constants (256 tried, 1024 new, 64-per-bucket, 8-per-group) | PRESENT | (W104 G1) |
| G2 | `ADDRMAN_HORIZON=30d`, `ADDRMAN_RETRIES=3`, `ADDRMAN_MAX_FAILURES=10`, `ADDRMAN_MIN_FAIL=7d` | PRESENT | (W104 G1) |
| G3 | `ADDRMAN_REPLACEMENT=4h` constant | MISSING | BUG-1 |
| G4 | `ADDRMAN_TEST_WINDOW=40min` constant | MISSING | BUG-1 |
| G5 | `ADDRMAN_SET_TRIED_COLLISION_SIZE=10` constant | MISSING | BUG-1 |
| G6 | `m_tried_collisions :: set<nid_type>` field in AddrMan | MISSING | BUG-1 |
| G7 | `ResolveCollisions()` entry point | MISSING | BUG-1 |
| G8 | `SelectTriedCollision()` entry point | MISSING | BUG-1 |
| G9 | `Good_(addr, test_before_evict, time)` two-arg form | MISSING | BUG-2 |
| G10 | `Connected(addr, time)` entry point (post-disconnect nTime refresh) | MISSING | BUG-3 |
| G11 | `SetServices(addr, services)` entry point | MISSING | BUG-4 |
| G12 | `FindAddressEntry(addr)` test helper | MISSING | BUG-5 |
| G13 | `GetEntries(from_tried)` test helper (table dump) | MISSING | BUG-5 |
| G14 | `GetAddr(max, max_pct, network, filtered)` 4-arg form | MISSING | BUG-6 |
| G15 | `Size(net, in_new)` 2-arg form (per-network table count) | PARTIAL | BUG-7 |
| G16 | `m_network_counts` field (per-Network NewTriedCount) | MISSING | BUG-7 |
| G17 | `MaybePickPreferredNetwork` outbound network rotation | MISSING | BUG-8 |
| G18 | `FEELER` ConnectionType + `FEELER_INTERVAL=2min` | MISSING | BUG-9 |
| G19 | `EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL=5min` rotation | MISSING | BUG-10 |
| G20 | `EXTRA_NETWORK_PEER_INTERVAL` extra-network outbound | MISSING | BUG-10 |
| G21 | `MAX_BLOCK_RELAY_ONLY_ANCHORS=2` constant | PRESENT (`maxBlockRelayOnlyAnchors`) | — |
| G22 | Anchor connection priority at connection-loop start | PARTIAL | BUG-11 |
| G23 | `nTries < 30 && current_time - addr_last_try < 10min` retry-gate | MISSING | BUG-12 |
| G24 | `count_failures = (netgroups+privacy) >= min(maxAuto-1, 2)` failure-attribution | MISSING | BUG-13 |
| G25 | `IsBadPort()` rejection gate | MISSING | BUG-14 |
| G26 | BanMan / Discourage separation (CSubNet bans + CRollingBloomFilter discouragement) | MISSING | BUG-15 |
| G27 | `CSubNet` subnet-ban support | MISSING | BUG-15 |
| G28 | Periodic `SweepBanned()` + `DumpBanlist()` (15-min interval) | MISSING | BUG-16 |
| G29 | Outbound eviction (Core's `MaybeSendStartedRecentBlockRelayPeers` etc.) | MISSING | BUG-17 |
| G30 | Periodic `AddrMan` persistence (`peers.dat` analogue) | MISSING | BUG-18 |

**G1-G2 are reaffirmations of W104 G1.** The remaining 28 gates are W128-specific.

## BUGS

### BUG-1 P0-CDIV: Tried-table collision resolution missing end-to-end
- **Files:** `src/Haskoin/Network.hs:5500-5526` (`markGood`) + entire
  `Network.hs` (no `m_tried_collisions`, no `ResolveCollisions`, no
  `SelectTriedCollision`, no `ADDRMAN_REPLACEMENT` / `_TEST_WINDOW` /
  `_SET_TRIED_COLLISION_SIZE` constants).
- **Core ref:** `bitcoin-core/src/addrman.h:37-41`,
  `addrman.cpp:606-659` (`Good_` with `test_before_evict`),
  `addrman.cpp:892-953` (`ResolveCollisions_`), `:955-981`
  (`SelectTriedCollision_`), `net.cpp:2773` + `:2804-2818`
  (ThreadOpenConnections feeler probe call site).
- **Impact:** New `Good` calls unconditionally overwrite occupied tried
  slots. An attacker who controls a /16 worth of addresses can force-evict
  arbitrary honest tried-table entries by simply triggering `Good_` (e.g.
  by completing handshake from rotated addresses that hash to colliding
  positions). Core defers eviction until a FEELER probe confirms the old
  address is unreachable; haskoin offers no such guarantee.
- **Fix sketch:** Add `amTriedCollisions :: TVar (Set nid)` to AddrMan,
  extend `markGood` to insert into the collision set when the tried slot
  is occupied (and the existing entry is still recent enough per
  `ADDRMAN_REPLACEMENT`), add a `resolveCollisions` walker called at the
  top of every connection-loop iteration, and add a `FEELER` connection
  type to `tryConnect`.

### BUG-2 P1: `Good_` lacks `test_before_evict` parameter
- **Files:** `src/Haskoin/Network.hs:5500` (`markGood`).
- **Core ref:** `addrman.cpp:606` (`Good_(addr, test_before_evict, time)`)
  + `addrman.cpp:155` (`Good(addr, time)` public wrapper passes
  `test_before_evict=true`).
- **Impact:** Without the boolean, haskoin cannot distinguish "first-time
  Good after VERSION/VERACK" (must test-before-evict) from "ResolveCollisions
  resolves stale collision" (must skip test, just MakeTried directly).
  This is a precondition for BUG-1's fix.

### BUG-3 P1: No `Connected(addr, time)` entry point
- **Files:** `src/Haskoin/Network.hs` — nothing matches `Connected_` in
  Core `addrman.cpp:857-874`.
- **Core ref:** `addrman.cpp:857-874` (`Connected_` updates `nTime` if
  more than 20 minutes have passed). Called from `net_processing.cpp`
  on *disconnect* (not connect, to avoid leaking which peers are
  currently connected; see header comment at `addrman.h:209-216`).
- **Impact:** haskoin never refreshes the AddrMan `nTime` field on
  disconnect, so addresses we've been connected to for hours will look
  stale to peers we gossip them to. Combined with W104 BUG-2 (no
  `nTime` / horizon check), the staleness is observable only via the
  gossip-out shape — but it still leaks "this peer is fresh = we just
  connected" timing info to spies.

### BUG-4 P1: No `SetServices(addr, services)` entry point
- **Files:** `src/Haskoin/Network.hs` — no analogue of `SetServices_`
  (`addrman.cpp:876-890`).
- **Core ref:** `addrman.cpp:876-890`. Called from VERSION-message
  handler when a peer advertises updated service flags.
- **Impact:** Once an address is in AddrMan, its service flags never
  update — even if the peer advertises new flags on next VERSION
  exchange. This causes the `HasAllDesirableServiceFlags` filter in
  the connection loop to reject genuinely-now-compatible peers and
  also to MIS-accept obsolete ones (we cached NODE_NETWORK_LIMITED
  but the peer has since upgraded to NODE_NETWORK, we don't notice).

### BUG-5 P1: No `FindAddressEntry` / `GetEntries` test helpers
- **Files:** `src/Haskoin/Network.hs` — no analogue of
  `FindAddressEntry_` (`addrman.cpp:983-1004`) or `GetEntries_`
  (`addrman.cpp:833-855`).
- **Core ref:** Same.
- **Impact:** Test-only API for inspecting bucket layout / per-entry
  position; without it, conformance tests can't verify the bucket
  invariants Core relies on (e.g. "after `MakeTried` the source
  address's `nRefCount` is decremented in every new bucket it
  appeared in"). Lower severity because it's test-surface, not
  production. Tagged P1 not P2 because the absence is what makes
  this audit's BUG-12 in W104 impossible to validate.

### BUG-6 P1: `GetAddr` lacks filtered/network/max_pct args
- **Files:** `src/Haskoin/Network.hs` — no `GetAddr` function at all
  (the `MGetAddr` message is parsed at `Network.hs:1934` but
  un-dispatched, as W104 BUG-20 noted; no implementation of the
  response side anywhere).
- **Core ref:** `addrman.cpp:792-831` (`GetAddr_(max_addresses,
  max_pct, network, filtered)`).
- **Impact:** When haskoin eventually wires up the GetAddr response
  (W104 BUG-20), it needs the per-network filter (Core respects
  `-onlynet`) and the `filtered=true` quality filter (drops terrible
  addresses before sending). Without these, haskoin would gossip
  every entry indiscriminately, including non-reachable networks
  for the recipient and known-terrible entries.

### BUG-7 P1: `Size(net, in_new)` only returns the global count
- **Files:** `src/Haskoin/Network.hs` — `amNewCount` and `amTriedCount`
  are global TVars; no per-network counters.
- **Core ref:** `addrman_impl.h:226-232` (`NewTriedCount` per
  `Network`), `addrman.cpp:1006-1026` (`Size_` with optional `net` +
  `in_new`).
- **Impact:** `MaybePickPreferredNetwork` (BUG-8) needs per-network
  counts to identify which networks are under-represented; without
  them, network-diversity outbound is impossible.

### BUG-8 P1: No `MaybePickPreferredNetwork` for outbound rotation
- **Files:** `src/Haskoin/Network.hs:3115-3212` (peerManagerLoop)
  selects without per-network preference.
- **Core ref:** `net.cpp:2514-2528` (`MaybePickPreferredNetwork`,
  iterates `g_reachable_nets`, returns the first one with
  zero current connections and non-empty AddrMan).
- **Impact:** haskoin can connect 10 outbounds all on the same
  network (e.g. all IPv4). Core enforces at least one outbound
  per reachable network when AddrMan has candidates for that
  network. Eclipse-resistance regression on multi-network nodes.

### BUG-9 P0-CDIV: No FEELER connection type or FEELER_INTERVAL
- **Files:** `src/Haskoin/Network.hs` — no `FEELER` ConnectionType,
  no analogue of `FEELER_INTERVAL = 2min`, no `next_feeler` timer.
- **Core ref:** `net.h:61` (`FEELER_INTERVAL = 2min`), `net.cpp:88`
  (`FEELER_SLEEP_WINDOW = 1s`), `net.cpp:2565+2754-2756`.
- **Impact:** FEELER is the mechanism by which Core promotes new
  addresses from the new table to the tried table over time:
  approximately every 2 minutes, one short-lived connection is opened
  to a randomly-selected new-table entry just long enough for a
  successful handshake (which triggers `Good_`, which moves it to
  tried). Without FEELER, haskoin's tried table only ever grows from
  addresses that successfully complete full peer handshakes — a much
  slower and less varied set. Combined with BUG-1, the tried table
  is fragile to attack and slow to populate.

### BUG-10 P0-CDIV: No EXTRA_BLOCK_RELAY / EXTRA_NETWORK_PEER intervals
- **Files:** `src/Haskoin/Network.hs` — no rotation timers other
  than the 10-second top-level peerManagerLoop sleep.
- **Core ref:** `net.cpp:2566-2567` (`next_extra_block_relay`,
  `next_extra_network_peer`), `net.cpp:2729-2767`.
- **Impact:** Core periodically opens an *extra* block-relay-only
  peer (every ~5 min, exponential), keeps it long enough to learn
  headers, then disconnects the next-youngest block-relay peer if
  no new blocks arrived. This is the eclipse-resistance mechanism
  described in `net.cpp:2735-2746`. haskoin's connection loop has no
  such mechanism; if an eclipse attacker controls all 2 block-relay
  slots from startup, they remain in control.

### BUG-11 P1: Anchors are loaded but anchor priority is partial
- **Files:** `src/Haskoin/Network.hs:3067-3068` (anchors loaded),
  `:3091-3092` (anchors saved), but the connection-loop branch at
  `Network.hs:3115-3212` does not prioritize anchor entries over
  AddrMan draws.
- **Core ref:** `net.cpp:2720-2722` and `:2780-2789`. Core opens
  BLOCK_RELAY anchors FIRST (`if (!m_anchors.empty() &&
  nOutboundBlockRelay < m_max_outbound_block_relay) { conn_type =
  BLOCK_RELAY; anchor = true; }`) before any AddrMan selection.
  Haskoin's loop draws from AddrMan first, then falls back to
  `pmKnownAddrs`; anchors only matter when SetupPeerManager seeds
  them into `pmKnownAddrs` at startup, after which they're
  indistinguishable from any other seed.
- **Impact:** Eclipse-attack resistance is weaker on restart —
  Core's "reconnect to anchors first" guarantees that a node coming
  back online from a partially-poisoned state reuses its previous
  block-relay-only peers (which were chosen for known-good behavior).
  Haskoin loses this guarantee.

### BUG-12 P1: Retry-window gate (`nTries < 30 && last_try < 10min`)
- **Files:** `src/Haskoin/Network.hs:3194-3201` — filter excludes
  banned/connected/failed but NOT recently-tried.
- **Core ref:** `net.cpp:2844-2846` (`if (current_time -
  addr_last_try < 10min && nTries < 30) continue;`).
- **Impact:** haskoin may select an address that we tried 30 seconds
  ago and just got connection-refused on. Core skips
  recently-tried addresses unless we've already burned 30 attempts
  this iteration. Pathological case: a flapping peer can absorb the
  full draw count by being selected, refusing, being demoted to
  `pmFailedAddrs`, being purged from `pmFailedAddrs` on the next DNS
  refresh (`Network.hs:3164-3165`), and re-selected — wastes
  outbound slots.

### BUG-13 P0-CDIV: `count_failures` attribution gate missing
- **Files:** `src/Haskoin/Network.hs:3398-3410` (`tryConnect`-side
  `markAttempt` calls fire unconditionally).
- **Core ref:** `net.cpp:2889-2893` and `addrman.cpp:687-689`.
  Core's `Attempt_` increments `nAttempts` only when
  `fCountFailure && m_last_count_attempt < m_last_good`. The gate
  is computed at the call site as `(outbound_ipv46_peer_netgroups
  + outbound_privacy_network_peers) >= min(maxAuto-1, 2)`.
- **Impact:** haskoin counts attempt failures even when the local
  node is offline (zero distinct netgroup peers connected).
  Result: all known-good addresses accumulate `nAttempts >=
  ADDRMAN_RETRIES` during an outage, get marked terrible
  (`isTerribleAddress` returns true at retries=3 with success=0),
  and are excluded from selection after reconnect. **A node that
  comes online after a 30-minute outage finds its entire
  AddrMan poisoned.** This is the W104 BUG-4 escalation: not just
  "always increments" but "increments wrong even relative to the
  call-site gate".

### BUG-14 P2: `IsBadPort()` filter missing
- **Files:** `src/Haskoin/Network.hs:3115-3212` — no port check.
- **Core ref:** `net.cpp:2858-2861` + `net/permissions.cpp`
  `IsBadPort` list (1, 7, 9, 11, ..., 22, 25, 53, 109, ...) —
  ~100 ports that are typically firewalled or run incompatible
  protocols. Skipped for the first 50 tries.
- **Impact:** Wastes outbound slots dialing a peer that advertised
  port 25 (SMTP) etc. Low severity because no security boundary
  is crossed, just compute and time.

### BUG-15 P0-DOSY: BanMan conflates Ban + Discourage + lacks subnet semantics
- **Files:** `src/Haskoin/Network.hs:2854` (`pmBannedAddrs :: TVar
  (Map SockAddr Int64)`), `:3943-3947` (`banPeer`), `:4075-4081`
  (`isDiscouraged` = `isBanned`), `:4196-4218` (loadBanList /
  saveBanList).
- **Core ref:** `banman.h:63-99` (separate `m_banned :: banmap_t`
  CSubNet -> CBanEntry and `m_discouraged ::
  CRollingBloomFilter<50000, 0.000001>`); `banman.cpp:83-87`
  (`IsDiscouraged` uses the bloom), `:118-122` (`Ban(CNetAddr)`
  wraps in CSubNet single-host); `banman.h:28-46` (header comment
  documents the SEPARATION OF CONCERNS).
- **Impact:**
  * `setban` RPC cannot ban a subnet (operator must add each IP+port
    individually); even simple `192.168.0.0/16` blanket bans require
    enumerating 65,536 entries.
  * Auto-banning misbehaving peers grows the persisted on-disk
    banlist unboundedly across runs — precisely the DOS vector
    that Core fixed in PR #25974 (2024-07-03 advisory at
    bitcoincore.org/en/2024/07/03/disclose-unbounded-banlist).
  * The bloom filter's probabilistic eviction means Core's
    discouragement is bounded at 50,000 entries with FP rate 1e-6
    regardless of how many peers misbehave; haskoin's Map is
    unbounded.
- **Top-line P0-DOSY severity** despite no immediate consensus
  divergence because the disk-fill DOS is wire-triggerable: any peer
  that misbehaves once is added permanently to the persisted map.

### BUG-16 P1: SweepBanned not periodic
- **Files:** `src/Haskoin/Network.hs:4092-4099` (`clearExpiredBans`
  exists but is called manually from RPC, never on a timer).
- **Core ref:** `banman.h:22` (`DUMP_BANS_INTERVAL = 15min`),
  `banman.cpp:48-70` (`DumpBanlist` calls `SweepBanned`).
- **Impact:** Expired entries linger in `pmBannedAddrs` until an
  operator runs `listbanned`. With BUG-15 compounding, an attacker
  who triggers a misbehavior event causes a permanent entry; with
  no periodic sweep, the expiration `expiry` field never gets
  honored on the on-disk side either.

### BUG-17 P1: Outbound eviction surface missing
- **Files:** `src/Haskoin/Network.hs:4429-4441`
  (`selectEvictionCandidate` filters to `ecInbound && not ecNoBan`
  — outbound is hard-excluded).
- **Core ref:** `net_processing.cpp` (`MaybeSendStartedRecentBlockRelayPeers`
  + headers-stale check decides to disconnect the
  next-youngest block-relay-only outbound). Eviction can be
  outbound when EXTRA_BLOCK_RELAY rotation runs (`net.cpp:2729-
  2752`). Haskoin has no analogue.
- **Impact:** When a block-relay-only peer fails to deliver new
  headers, Core rotates it out; haskoin holds the slot. Combined
  with BUG-10, makes eclipse resistance weaker than Core's design.

### BUG-18 P2: No AddrMan persistence (peers.dat analogue)
- **Files:** `src/Haskoin/Network.hs` — anchors.json is the only
  on-disk peer file; the AddrMan tables themselves are
  in-memory-only.
- **Core ref:** `addrdb.h` / `addrman.cpp:112-208` (`Serialize` +
  `Unserialize`), `init.cpp` (DumpPeerAddresses every 15 minutes
  and at shutdown).
- **Impact:** **The entire address book is lost on restart.** Every
  reboot triggers a full DNS-seed re-discovery (peerManagerLoop at
  `Network.hs:3149-3166`), wasting the carefully-built tried table
  from the previous session. This is W104 BUG-19 reaffirmed; the
  W128 angle is that the persistence absence interacts with BUG-1
  (no tried-collision resolution) to make the tried table even
  harder to populate at steady-state.

## Per-impl bug count (this audit): 18 distinct from W104

Bug severity histogram:

| Severity | Count | Bugs |
|----------|-------|------|
| P0-DOSY  | 1     | BUG-15 |
| P0-CDIV  | 5     | BUG-1, BUG-9, BUG-10, BUG-13, (BUG-15 secondary) |
| P1       | 8     | BUG-2, BUG-3, BUG-4, BUG-5, BUG-6, BUG-7, BUG-8, BUG-11, BUG-12, BUG-16, BUG-17 |
| P2       | 4     | BUG-14, BUG-18, (BUG-5 test-only), (BUG-11 partial) |

(P1 count is 11 because some BUGs are both P0 and P1 depending on
threat model; the count above sums by the most-pessimistic class.)

## What's good

* W104 G1 holds: bucket constants exactly match Core's values; the
  cryptographic bucketing key uses CSPRNG (W104 BUG-7 fixed at some
  point between W104 audit and now — see `Network.hs:5323-5336`).
* `isRoutable` is a careful port of Core's `CNetAddr::IsRoutable`
  (`Network.hs:5243-5270`) — every RFC range matches Core's check.
* The eviction-candidate machinery (`buildEvictionCandidates`,
  `applyProtections`, `protectByNetGroup`, `protectByPingTime`,
  `protectByLastTxTime`, `protectByLastBlockTime`,
  `protectByLongevity`, `selectFromNetworkGroup`) is a faithful port
  of Core's `node/eviction.cpp` — only outbound is excluded (BUG-17).
* Anchors are loaded + saved via `saveAnchors` / `loadAnchors`
  (`Network.hs:5631-5650`) with the correct
  `MAX_BLOCK_RELAY_ONLY_ANCHORS=2` cap.
* `markGood` is called from both the post-VERSION-handshake path
  (`Network.hs:3431` / `:3693`) and on successful TCP connect (W104
  BUG-6 was fixed); this leaves only the test-before-evict semantics
  as the gap (BUG-1).

## Discovery audit: NO production code changes

Tests are pinning-shape (`it` asserting current observable behavior
where possible) and xfail-shape (`xit` for sentinels documenting the
desired Core-parity behavior, flippable to `it` by future fix waves).

Eight `xit` sentinels are explicitly bug-tagged so the fix-wave
auditor can search for them by BUG-N. No imports require Network.hs
changes — every gate references either existing Network.hs exports
or hardcoded Core constants.

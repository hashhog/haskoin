# W126 — BIP-152 Compact Blocks (haskoin)

Discovery-only audit. NO production code changes.

## References

- Bitcoin Core `src/blockencodings.h` (CBlockHeaderAndShortTxIDs,
  PartiallyDownloadedBlock, BlockTransactionsRequest, BlockTransactions,
  PrefilledTransaction, ReadStatus, DifferenceFormatter,
  CMPCTBLOCKS_VERSION=2).
- Bitcoin Core `src/blockencodings.cpp` (InitData, FillBlock,
  FillShortTxIDSelector, GetShortID, bucket-size-12 DoS check, duplicate-
  short-id behaviour, merkle/witness-mutation guard).
- Bitcoin Core `src/net_processing.cpp` (SENDCMPCT, CMPCTBLOCK, GETBLOCKTXN,
  BLOCKTXN handlers; `MAX_CMPCTBLOCK_DEPTH=5`, `MAX_BLOCKTXN_DEPTH=10`,
  `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3`; `m_provides_cmpctblocks`,
  `m_requested_hb_cmpctblocks`, `m_bip152_highbandwidth_from`,
  `m_bip152_highbandwidth_to`; `MaybeSetPeerAsAnnouncingHeaderAndIDs`;
  `lNodesAnnouncingHeaderAndIDs` (HB outbound cap=3); `SendBlockTransactions`
  out-of-bounds misbehaving; `ProcessCompactBlockTxns`).
- BIP-152 (Compact Block Relay).

## Where things live in haskoin

| Concern                          | Where (file:line)                                  |
|----------------------------------|----------------------------------------------------|
| Wire types CmpctBlock/SendCmpct/GetBlockTxn/BlockTxn | `src/Haskoin/Network.hs:1116-1131, 6310-6422` |
| ShortTxId / PrefilledTx wire    | `Network.hs:6280-6308, 6349-6361`                 |
| Differential-encoding helpers    | `Network.hs:6386-6403`                             |
| SipHash-2-4 implementation       | `Network.hs:6804-6878`                             |
| computeShortIdKey / computeShortId | `Network.hs:6430-6454`                            |
| createCompactBlock               | `Network.hs:6499-6519`                             |
| initPartialBlock (InitData)      | `Network.hs:6552-6669`                             |
| fillPartialBlock (FillBlock)     | `Network.hs:6676-6736`                             |
| reconstructBlock                 | `Network.hs:6740-6746`                             |
| HighBandwidthState type & ops    | `Network.hs:6758-6793`                             |
| CompactBlockState                | `Network.hs:6536-6540`                             |
| MAX_CMPCTBLOCK_DEPTH / MAX_BLOCKTXN_DEPTH | `Network.hs:6488, 6494`                    |
| post-verack sendcmpct(0,2)       | `Network.hs:2428`                                  |
| Compact block state ref in Main  | `app/Main.hs:948-959` (instantiated)               |
| MSendCmpct handler (incoming)    | `app/Main.hs:2185-2187`                            |
| MCmpctBlock handler              | `app/Main.hs:2189-2258`                            |
| MGetBlockTxn handler             | `app/Main.hs:2260-2292`                            |
| MBlockTxn handler                | `app/Main.hs:2294-2337`                            |
| announceTip (HB ANNOUNCE-side)   | `app/Main.hs:1523-1534`                            |

## Top-line verdict — PARTIAL (12 PRESENT / 12 PARTIAL / 6 MISSING)

haskoin's BIP-152 implementation has solid wire-codec + SipHash + receiver-side
guards (initPartialBlock / fillPartialBlock, merkle-root mutation check,
MAX_CMPCTBLOCK_DEPTH=5 + MAX_BLOCKTXN_DEPTH=10 guards from W112 FIX-41/42).
But the ANNOUNCE-side path — what Core calls `MaybeSetPeerAsAnnouncingHeaderAndIDs`
plus `lNodesAnnouncingHeaderAndIDs` — is entirely absent.  haskoin will never
announce a new block as a compact block to any peer: `announceTip` only emits
`MInv` or `MHeaders` and never `MCmpctBlock`.  `createCompactBlock` is a
fully-implemented helper with zero call sites in `app/` or `src/`.  In Core
parity terms haskoin is an LB-receiver-only node.

Concurrent with that, several Core-mandated correctness checks remain absent
on the receiver side as well:

- `SENDCMPCT` version filter (Core rejects `sendcmpct` with version != 2;
  haskoin accepts any version, logs and discards).
- `getblocktxn` out-of-bounds index misbehaving (Core misbehaves 100;
  haskoin silently drops via `mapMaybe`).
- IBD gate on incoming `cmpctblock` (Core `IsInitialBlockDownload()` check
  at net_processing.cpp:4486).
- Per-peer state (`piProvidesCompact`, `piHighBandwidthFrom`,
  `piHighBandwidthTo`, `piCmpctVersion`).  Without these the HB selection
  logic that limits to 3 HB outbound peers (Core
  `MaybeSetPeerAsAnnouncingHeaderAndIDs`) cannot run.
- Bucket-size-12 DoS guard uses the wrong partition function (BUG-6 from W112
  remains unfixed — Core hashes into `unordered_map` buckets at load-factor 1
  with bucket count = next power of two; haskoin uses `id mod numShortIds`,
  which yields expected-1 per "bucket" and so never triggers).

## 30-gate matrix

| Gate | Topic | Status | Core ref | haskoin ref |
|------|-------|--------|----------|-------------|
| G1   | SHORTTXIDS_LENGTH = 6                                        | PRESENT  | blockencodings.h:103                      | Network.hs:6280-6281, 6349-6361 |
| G2   | SipHash-2-4 round count (c=2, d=4) — spec vectors            | PRESENT  | crypto/siphash.{h,cpp}                    | Network.hs:6849-6878            |
| G3   | SipHash key = SHA256(header‖nonce_LE), k0/k1 LE              | PRESENT  | blockencodings.cpp:35-44                  | Network.hs:6430-6439            |
| G4   | computeShortId masks to 48 bits + uses wtxid (v2)            | PRESENT  | blockencodings.cpp:46-50                  | Network.hs:6450-6462            |
| G5   | CmpctBlock wire (header‖nonceLE‖shortids[]‖prefilled[])      | PRESENT  | blockencodings.h:121-130                  | Network.hs:6321-6347            |
| G6   | GetBlockTxn DifferenceFormatter (differential-encoded idxs)  | PRESENT  | blockencodings.h:23-43, 51-54             | Network.hs:6371-6403            |
| G7   | BlockTxn round-trip                                          | PRESENT  | blockencodings.h:67-71                    | Network.hs:6413-6422            |
| G8   | PrefilledTransaction wire (varint relative idx + tx)         | PRESENT  | blockencodings.h:80                       | Network.hs:6300-6308            |
| G9   | post-verack sendcmpct(low_bandwidth=0, v=2) outbound         | PRESENT  | net_processing.cpp:3870 + 3864            | Network.hs:2428                 |
| G10  | CMPCTBLOCKS_VERSION = 2 constant                             | PARTIAL  | net_processing.cpp:199                    | Network.hs:6480 (cbcVersion=2) + 2428 hard-coded; no named constant — BUG-9 |
| G11  | SENDCMPCT incoming-version filter (drop iff != 2)            | MISSING  | net_processing.cpp:3907                   | Main.hs:2185-2187 — logs only — BUG-2 |
| G12  | Per-peer m_provides_cmpctblocks state                        | MISSING  | net_processing.cpp:460, 3911              | PeerInfo (Network.hs:1983-2046) — no field — BUG-3 |
| G13  | Per-peer m_requested_hb_cmpctblocks (peer's HB ask of us)    | MISSING  | net_processing.cpp:3912                   | PeerInfo — no field — BUG-3 |
| G14  | Per-peer m_bip152_highbandwidth_from / _to                   | MISSING  | net_processing.cpp:3915, 1325             | PeerInfo — no field — BUG-3 |
| G15  | MAX_CMPCTBLOCK_DEPTH=5 guard on incoming cmpctblock          | PRESENT  | net_processing.cpp:2466                   | Main.hs:2203-2211 (FIX-42)      |
| G16  | MAX_BLOCKTXN_DEPTH=10 guard on incoming getblocktxn          | PRESENT  | net_processing.cpp:4276                   | Main.hs:2275-2283 (FIX-42)      |
| G17  | IBD gate on incoming cmpctblock                              | MISSING  | net_processing.cpp:4486                   | Main.hs:2189-2258 — no IBD check — BUG-1 |
| G18  | initPartialBlock empty-block rejection                       | PRESENT  | blockencodings.cpp:62-63                  | Network.hs:6560-6561            |
| G19  | initPartialBlock total-tx-count bound (≤100k)                | PRESENT  | blockencodings.cpp:64-65                  | Network.hs:6567-6568 + 6345-6346 |
| G20  | initPartialBlock prefilled-index overflow & bounds           | PRESENT  | blockencodings.cpp:77-85                  | Network.hs:6624-6635            |
| G21  | initPartialBlock short-ID collision detection                | PRESENT  | blockencodings.cpp:115-116                | Network.hs:6585-6590            |
| G22  | Bucket-size-12 DoS guard (uses correct partition)            | PARTIAL  | blockencodings.cpp:110-111                | Network.hs:6592-6599 — wrong partition — BUG-4 |
| G23  | Duplicate-match clearing (have_txn behaviour)                | PRESENT  | blockencodings.cpp:125-136                | Network.hs:6637-6669            |
| G24  | fillPartialBlock missing-count strict equality               | PRESENT  | blockencodings.cpp:200-216                | Network.hs:6682-6685            |
| G25  | fillPartialBlock merkle/mutation guard after fill            | PARTIAL  | blockencodings.cpp:219-221                | Network.hs:6699-6704 — txid merkle only, no witness-root mutation guard — BUG-5 |
| G26  | extra_txn pool fallback (vExtraTxnForCompact)                | MISSING  | blockencodings.cpp:147-176                | absent — BUG-7 |
| G27  | MGetBlockTxn out-of-bounds index → misbehaving 100           | PARTIAL  | net_processing.cpp:2602-2604              | Main.hs:2288 — `mapMaybe` silently drops — BUG-8 |
| G28  | ANNOUNCE-side: cmpctblock to HB peers in tip-announce path   | MISSING  | net_processing.cpp:2117, 5902-5912        | announceTip (Main.hs:1523-1534) — never sends MCmpctBlock — BUG-10 |
| G29  | HB outbound selection (lNodesAnnouncingHeaderAndIDs ≤ 3)     | MISSING  | net_processing.cpp:1272-1329              | HighBandwidthState type exists (Network.hs:6758-6793) but never wired — BUG-11 |
| G30  | createCompactBlock has at least one caller                   | MISSING  | (used at net_processing.cpp:2117)         | `createCompactBlock` defined in Network.hs:6499 but ZERO callers in app/ or src/ — BUG-12 (dead-helper) |

## Bugs

### BUG-1 (P1) — no IBD gate on incoming cmpctblock
- Core (`net_processing.cpp:4486`) early-returns on `MaybeSendGetHeaders`
  during IBD when the prev-block isn't found, and the ANNOUNCE path
  short-circuits during IBD because no peer has been promoted to HB.
- haskoin processes `MCmpctBlock` regardless of IBD: it walks the mempool
  (which is empty during IBD), almost always misses, sends `getblocktxn`,
  and then ends up doing the same disk read it would have done for a full
  block — wasting one round-trip.
- Cost: per-cmpctblock round-trip during IBD, plus per-cmpctblock mempool
  scan.  Not consensus.

### BUG-2 (P1) — MSendCmpct ignores scVersion
- Core (`net_processing.cpp:3907`) `if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;`
- haskoin (`Main.hs:2185-2187`) just `putStrLn`s and returns; any peer can
  send `sendcmpct(announce=*, version=999)` and we silently accept it.
- Cost: protocol-version-drift exposure; downstream code that reads
  `scVersion` would honour a bogus value.

### BUG-3 (P1) — PeerInfo missing 4 BIP-152 negotiation fields
- Core peer state: `m_provides_cmpctblocks`, `m_requested_hb_cmpctblocks`,
  `m_bip152_highbandwidth_from`, `m_bip152_highbandwidth_to`.
- haskoin PeerInfo (`Network.hs:1983-2046`) has none of these. Without them
  the SENDCMPCT handler cannot record per-peer state, and the HB selection
  logic cannot decide which peers to announce-via-cmpctblock to.
- Cost: receiver-only operation. Cannot mirror Core's HB topology.

### BUG-4 (HIGH) — bucket-size-12 DoS guard uses wrong partition
- Core (`blockencodings.cpp:110-111`) computes `shorttxids.bucket(id)` —
  the std::unordered_map bucket index, which is the hash modulo
  `next_pow2(shortIds.size())` at load-factor 1.
- haskoin (`Network.hs:6592-6599`) uses `id mod numShortIds`, treating each
  short ID as its own bucket modulo. For n unique IDs mod n the expected
  bucket size is ~1, so > 12 is essentially unreachable. The check is
  effectively a no-op.
- Cost: an attacker who can place 13+ short IDs into one bucket of Core's
  unordered_map bypasses haskoin's guard but is rejected by Core. Receiver-
  side; not consensus.

### BUG-5 (P1) — fillPartialBlock merkle guard misses witness-root mutation
- Core (`blockencodings.cpp:219-220`) calls `IsBlockMutated(block, segwit_active)`
  which checks both the txid merkle root AND the witness root (when
  `segwit_active`) via `CheckWitnessMalleation`.
- haskoin (`Network.hs:6699-6704`) recomputes `computeMerkleRoot` from
  `computeTxid` (non-witness) and compares against the header merkle root.
  No witness-root check is performed, so a peer that swaps a witness
  in/out without changing txid would slip through and be caught later by
  CheckBlock — but only after the cmpctblock is "reconstructed", costing
  the per-tx mempool-scan + getblocktxn round-trip first.
- Cost: not consensus (downstream CheckBlock still catches it) but a
  missed early-rejection opportunity.

### BUG-6 (P1-DEAD-HELPER) — getMissingTxIndices is dead-helper-at-call-site
- `getMissingTxIndices :: PartiallyDownloadedBlock -> [Int]` is exported
  (`Network.hs:6749-6750`) but **zero callers** in `app/` or `src/`. The
  `MCmpctBlock` handler inlines its own `[i | (i, Nothing) <- ...]` filter
  (`Main.hs` indirectly via `initPartialBlock` returning `missing`), so
  the helper is dead code.  Pattern continues 34-wave streak of "well-engineered
  helper never wired".

### BUG-7 (P2) — extra_txn pool absent
- Core (`blockencodings.cpp:147-176`) consults `vExtraTxnForCompact` (a
  ring buffer of 100 recently-seen tx) **after** the mempool scan, so a tx
  that already left the mempool (replaced/expired) can still complete a
  compact-block reconstruction without a round-trip.
- haskoin only consults `mempoolTxs`. Cost: extra `getblocktxn` round-trip
  for any tx that has aged out of the mempool, which is the most common
  failure mode for compact-block reconstruction on a busy network.

### BUG-8 (P1) — MGetBlockTxn silently drops out-of-bounds indices
- Core (`net_processing.cpp:2602-2604`) `Misbehaving(peer, "getblocktxn with
  out-of-bounds tx indices")`.
- haskoin (`Main.hs:2288`) uses `mapMaybe (\i -> if idx < length blockTxns
  then Just (blockTxns !! idx) else Nothing)` — silently drops the bad
  index and sends a `blocktxn` shorter than requested, which the requester
  will then fail to reconstruct against.  Result: the peer can probe our
  block contents via index probes without penalty, and a requester sees
  silent garbage-out.
- Cost: missing peer-misbehaving signal. Not consensus.

### BUG-9 (P2) — CMPCTBLOCKS_VERSION constant absent
- Core has `static constexpr uint64_t CMPCTBLOCKS_VERSION{2};` at
  `net_processing.cpp:199`.
- haskoin hard-codes `2` at three sites: `Network.hs:2428` (post-verack
  outbound), `Network.hs:6480` (`cbcVersion = 2`), and the absent BUG-2
  filter would compare against `2` as a magic literal.
- "frozen constants degrade silently" pattern: future BIP-152 v3 work
  has three sites to grep for instead of one constant.

### BUG-10 (P0-DEAD-PATH) — announceTip never sends MCmpctBlock
- Core (`net_processing.cpp:2117, 5902-5912`) for HB outbound peers
  caches `m_most_recent_compact_block` and pushes `CMPCTBLOCK` to those
  peers when a new tip is connected.  The whole HB topology (≤ 3 outbound,
  topology managed by `MaybeSetPeerAsAnnouncingHeaderAndIDs`) exists so
  that block propagation latency is one round-trip instead of two.
- haskoin (`Main.hs:1523-1534`):
  ```haskell
  let msg = if piWantsHeaders info then headersMsg else invMsg
  sendMessage pc msg
  ```
  Only emits `MHeaders` or `MInv`.  We never tell any peer "here's the
  new block as a cmpctblock"; even if a peer sent us `sendcmpct(1,2)`
  we silently downgrade to headers/inv on our tip-announce.
- Consequence: haskoin nodes contribute zero compact-block ANNOUNCE
  traffic.  Receivers don't notice (cmpctblock is optional and they
  fall back to getdata) but our bandwidth-saving share of the network
  is zero.
- Receiver-side compact-block reconstruction continues to work because
  remote miners/relays *do* announce compact blocks to us, and we run
  the InitData/FillBlock path correctly. The bug is purely on our
  outbound path.

### BUG-11 (P1-DEAD-HELPER) — HighBandwidthState dead at call site
- `HighBandwidthState`, `newHighBandwidthState`, `addHighBandwidthPeer`,
  `removeHighBandwidthPeer`, `isHighBandwidthPeer`, `getHighBandwidthPeers`
  are all exported (`Network.hs:89-94`) but have ZERO callers in `app/`
  or `src/`.  The W112 audit catalogued this in 2026-04 as BUG-3 and it
  has remained dead through every wave since.
- Pattern continues: well-engineered helper module, fully tested at the
  unit level (W112 G29 tests pass), never wired into the message
  handlers because `MSendCmpct` is a stub.

### BUG-12 (P0-DEAD-HELPER) — createCompactBlock has no callers
- `createCompactBlock :: Block -> IO CmpctBlock` (`Network.hs:6499-6519`)
  builds a fresh cmpctblock from a full block: random nonce, SipHash key,
  prefilled coinbase, short IDs for the tail.
- Zero callers in `app/`, `src/`, or `bench/`.  Without a caller the
  ANNOUNCE path (BUG-10) has nowhere to source its outbound payload from
  even if it wanted to send one.  This is the upstream half of the same
  dead path; both must be wired for ANNOUNCE-side compact blocks to
  function.

## Cross-wave patterns observed

1. **dead-helper-at-call-site (34-wave streak preserved)** — BUG-6, BUG-11,
   BUG-12 are all "implementation present, never wired". The streak now
   stands at *at least* 34 waves with this pattern.  Worth noting that
   haskoin's BIP-152 has 3 dead-helper bugs in a single audit — the most
   in any haskoin audit so far.
2. **comment-as-confession (12-wave streak preserved)** — none in W126.
   `Main.hs:949-951` comment about persisting state was honoured (the
   compact-block state is genuinely instantiated). Good discipline.
3. **frozen-constant-degrade** — BUG-9 (no `CMPCTBLOCKS_VERSION` named
   constant) means future v3 work will need to grep + replace three
   magic literals.
4. **MISSING ANNOUNCE-side, PRESENT RECEIVER-side asymmetry** — haskoin
   is functionally a "receive-only" BIP-152 node. This is the same shape
   we caught in nimrod W117 (BIP-155 inbound but no proxy outbound) and
   in several BIP-157 audits across other impls — implementations tend
   to build the parsing/decoding path first because the wire fixture is
   small, and leave the produce/announce side as a TODO.

## Recommended fix-wave decomposition (out of scope for W126)

- **FIX-A (HB ANNOUNCE-side wire-up)**: piProvidesCompact, piHighBandwidthFrom,
  piHighBandwidthTo fields on PeerInfo + MSendCmpct populates them +
  announceTip dispatches MCmpctBlock to HB peers + createCompactBlock callsite
  + MaybeSetPeerAsAnnouncingHeaderAndIDs-equivalent. Closes BUG-3, BUG-10,
  BUG-11, BUG-12 (P0/P1).
- **FIX-B (SENDCMPCT version filter + named constant)**: rejects non-v2
  + defines `cmpctBlocksVersion = 2`. Closes BUG-2, BUG-9.
- **FIX-C (Bucket-size partition fix)**: switch to next-power-of-2
  bucket count + correct hash partition. Closes BUG-4.
- **FIX-D (Out-of-bounds misbehaving on getblocktxn)**: replace `mapMaybe`
  with explicit bounds check + `misbehaving pm addr InvalidCompactBlock`.
  Closes BUG-8.
- **FIX-E (IBD gate)**: early-return on MCmpctBlock when `ibdMode = True`.
  Closes BUG-1.
- **FIX-F (witness-root mutation guard in fillPartialBlock)**: extend
  merkle check to include witness root when segwit-active. Closes BUG-5.
- **FIX-G (extra_txn pool)**: 100-entry ring buffer of recently-seen tx
  consulted after mempool scan in initPartialBlock. Closes BUG-7.

## Bug count summary

| Priority   | Count | Bugs                                     |
|------------|-------|------------------------------------------|
| P0-CDIV    | 0     | —                                        |
| P0         | 2     | BUG-10, BUG-12                           |
| P1         | 7     | BUG-1, BUG-2, BUG-3, BUG-5, BUG-8, BUG-11 (and BUG-4 HIGH) |
| P2         | 2     | BUG-7, BUG-9                             |
| P3         | 0     | —                                        |
| HIGH       | 1     | BUG-4                                    |
| **Total**  | **12**| —                                        |

(BUG-4 priority-classed HIGH because P1 already crowded; "HIGH" indicates
"DoS guard is silently no-op" — worse than P2, lighter than P0-CDIV
because it's receiver-side and not consensus.)

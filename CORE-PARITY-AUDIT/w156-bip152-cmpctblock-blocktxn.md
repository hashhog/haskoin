# W156 — BIP-152 sendcmpct + cmpctblock + blocktxn + getblocktxn (haskoin)

**Wave:** W156 — `sendcmpct` (BIP-152 v1/v2 negotiation, scAnnounce / HB),
`cmpctblock` (CBlockHeaderAndShortTxIDs: header‖nonce‖shortids[]‖prefilled[]),
`blocktxn` (BlockTransactions: hash‖missing[] full Txs),
`getblocktxn` (BlockTransactionsRequest: hash‖differential-encoded indexes[]),
`PartiallyDownloadedBlock` (`InitData` / `FillBlock`),
`SHORTTXIDS_LENGTH=6` (low 48 bits of SipHash-2-4 of wtxid),
`MAX_CMPCTBLOCK_DEPTH=5`, `MAX_BLOCKTXN_DEPTH=10`,
`MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3`,
`MaybeSetPeerAsAnnouncingHeaderAndIDs`, HB outbound cap `nNodesAnnouncingHeaderAndIDs ≤ 3`,
`m_provides_cmpctblocks` / `m_requested_hb_cmpctblocks` /
`m_bip152_highbandwidth_from` / `m_bip152_highbandwidth_to`,
`FillShortTxIDSelector` = SHA256(header‖nonce_LE), k0/k1 = LE 8-byte slices.

**Scope:** discovery only — no production code changes. W126 covered the
**fundamentals** (12 bugs catalogued, see `audit/w126_bip152_compact_blocks.md`).
W156 is the **deep-dive**: wire-level corner cases, ban-vs-discourage
divergences, two-pipeline drifts (computeWtxid duplicated), and the
cmpctblock-specific echo of W148 BUG-13's MBlock-bans-peers-for-reorgs
pattern.

**Bitcoin Core references**
- `bitcoin-core/src/blockencodings.h` — `CBlockHeaderAndShortTxIDs`,
  `PartiallyDownloadedBlock`, `BlockTransactions`, `BlockTransactionsRequest`,
  `PrefilledTransaction` (relative compactsize index + CTransaction),
  `SHORTTXIDS_LENGTH=6`, `MAX_NUM_TRANSACTIONS_PER_BLOCK = 100000`.
- `bitcoin-core/src/blockencodings.cpp` — `FillShortTxIDSelector` (SHA256
  of header‖nonce, k0=hash[0..8] k1=hash[8..16] little-endian),
  `GetShortID(Wtxid)` (SipHash-2-4 of wtxid uint256, mask to 48 bits),
  `InitData` (gates: empty / total-tx-count / prefilled-idx-overflow /
  short-id-collision / bucket-size-12 DoS / duplicate-match-clearing),
  `FillBlock` (missing-count strict equality + post-fill mutation guard
  via `IsBlockMutated(block, segwit_active)`).
- `bitcoin-core/src/net_processing.cpp`:
  - `SENDCMPCT` handler at ~3870-3915: drops if `version != CMPCTBLOCKS_VERSION=2`,
    refuses second sendcmpct after segwit-activation if pre-segwit version,
    sets `m_provides_cmpctblocks` and `m_bip152_highbandwidth_from`.
  - `MaybeSetPeerAsAnnouncingHeaderAndIDs` at ~1272-1329: HB outbound cap
    (`lNodesAnnouncingHeaderAndIDs.size() < 3`), evicts oldest HB on overflow,
    sends `sendcmpct(announce=true, version=2)` to promote the new peer.
  - `CMPCTBLOCK` handler at ~4486-4612: `MaybeSendGetHeaders` first, IBD
    early-return, MAX_CMPCTBLOCK_DEPTH=5 gate, `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3`
    gate, `InitData` → `RequestMissingTxsAfter`.
  - `GETBLOCKTXN` handler at ~2598-2616: out-of-bounds index `Misbehaving(peer,
    "getblocktxn with out-of-bounds tx indices")` then return; out-of-depth
    falls back to full-block reply (~4276).
  - `BLOCKTXN` handler at ~3473-3490: `Misbehaving(peer, "previous compact block
    reconstruction attempt failed")` on stale-pdb-missing,
    `Misbehaving(peer, "invalid compact block/non-matching block transactions")`
    on `READ_STATUS_INVALID`.
  - `MaybePunishNodeForBlock` at ~1906-1948: **`BLOCK_CONSENSUS` and
    `BLOCK_MUTATED` are EXEMPT from punishment when `via_compact_block=true`**
    (the cmpct-derived block must NOT punish the announcer for honest
    reconstruction failures).
  - `Misbehaving` itself at ~1893-1904: sets `m_should_discourage=true` ONLY —
    no immediate ban; `MaybeDiscourageAndDisconnect` later evaluates the
    discourage list and disconnects with `BanMan::Discourage` (NOT `BanMan::Ban`).
- BIP-152 spec (Compact Block Relay).

**Files audited**
- `src/Haskoin/Network.hs:1116-1131` — `SendCmpct` wire record.
- `src/Haskoin/Network.hs:6275-6422` — `CmpctBlock`, `PrefilledTx`,
  `GetBlockTxn`, `BlockTxn` wire records + `differentialEncode`/`Decode`.
- `src/Haskoin/Network.hs:6424-6462` — `computeShortIdKey`, `computeShortId`,
  in-Network duplicate of `computeWtxid`.
- `src/Haskoin/Network.hs:6464-6519` — `CompactBlockConfig`,
  `defaultCompactBlockConfig`, `maxCmpctBlockDepth=5`, `maxBlocktxnDepth=10`,
  `createCompactBlock` (ANNOUNCE-side encoder).
- `src/Haskoin/Network.hs:6521-6750` — `PartiallyDownloadedBlock`,
  `CompactBlockState`, `initPartialBlock` (InitData equivalent),
  `fillPartialBlock` (FillBlock equivalent), `reconstructBlock`,
  `getMissingTxIndices`.
- `src/Haskoin/Network.hs:6752-6793` — `HighBandwidthState` type + ops
  (add/remove/is/get HB peer).
- `src/Haskoin/Network.hs:6800-6880` — duplicated `SipHashKey`,
  `sipHash128`-named-but-64-bit-output.
- `src/Haskoin/Network.hs:2410-2433` — `continueHandshake` post-verack
  `sendMessage pc (MSendCmpct (SendCmpct False 2))`.
- `src/Haskoin/Network.hs:640-685` — `MisbehaviorReason` enum,
  `misbehaviorScore`, `defaultBanThreshold=100`.
- `src/Haskoin/Network.hs:4031-4071` — `misbehaving` implementation
  (single-event ban path).
- `src/Haskoin/Network.hs:5837-5865` — `blockStallTimeout`,
  `blockStallTimeoutCompact=2`, `blockStallTimeoutMax=64`.
- `src/Haskoin/Network.hs:6028-6053` — `isBlockStalled` (dead helper).
- `src/Haskoin/Crypto.hs:1064-1065` — second `computeWtxid` definition.
- `src/Haskoin/Types.hs:226-249` — `instance Serialize Tx` (witness-flag
  emission on encode; marker/flag decode).
- `app/Main.hs:944-959` — `compactBlockStateRef` instantiation.
- `app/Main.hs:1523-1534` — `announceTip` (only emits MHeaders / MInv).
- `app/Main.hs:1640-2340` — `syncMessageHandler` case dispatch.
- `app/Main.hs:1973-2004` — `MGetData` handler (no `InvCompactBlock` case).
- `app/Main.hs:2185-2187` — `MSendCmpct sc` handler (first arm — alive).
- `app/Main.hs:2189-2258` — `MCmpctBlock cb` handler.
- `app/Main.hs:2260-2292` — `MGetBlockTxn gbt` handler.
- `app/Main.hs:2294-2337` — `MBlockTxn bt` handler.
- `app/Main.hs:2353` — `MSendCmpct _ -> return ()` (second arm — dead).
- `src/Haskoin/Sync.hs:255-285` — `bdPendingBlocks` / `bdBaseTimeout`
  (parallel stall accounting, ignores compact-block path).

---

## Top-line verdict — RECEIVER-ONLY with multiple ban/wire/DoS divergences

W126 already established that haskoin is functionally a "BIP-152 receiver
only" node (ANNOUNCE-side helpers — `createCompactBlock`,
`HighBandwidthState` — exist but have zero production callers since
2026-04). W156 confirms that gap is unchanged AND finds new bugs in the
receiver-side path:

- The post-verack `sendcmpct(False, 2)` is sent unconditionally, with no
  per-peer `piProvidesCompact`, `piHbFrom`, `piHbTo`, `piCmpctVersion`
  tracking (W126 BUG-3 carry-forward), no NODE_WITNESS gate on v=2, and
  no IBD gate.
- Every reconstruction failure (whether the peer was malicious or simply
  unlucky-on-mempool-hit-rate) escalates to `misbehaving InvalidCompactBlock`
  which haskoin maps to **score=100, immediate ban + add-to-discourage-list +
  disconnect** — but Core's `Misbehaving` sets `m_should_discourage=true`
  only (no ban), AND Core's `MaybePunishNodeForBlock` with
  `via_compact_block=true` is EXEMPT from any punishment for
  `BLOCK_CONSENSUS` / `BLOCK_MUTATED`. This is the cmpctblock-specific
  echo of W148 BUG-13 (MBlock bans peers for reorgs).
- `MSendCmpct` has TWO case arms in the same `case msg of` block —
  Haskell first-match means line 2353 (`MSendCmpct _ -> return ()`) is
  **redundant and unreachable**. The arm at line 2185 is the only one
  that fires. A GHC `-Woverlapping-patterns` warning is being emitted at
  every compile.
- `computeWtxid` is duplicated across `Haskoin.Network` (line 6461-6462)
  and `Haskoin.Crypto` (line 1064-1065) — two-pipeline-guard:
  any fix in one path (e.g., a coinbase-wtxid=00..00 special case for
  BIP-141) silently diverges from the other.
- `cbsPending` Map has no size cap, no expiration, no per-peer keying.
  A peer can flood `MCmpctBlock` to bloat memory; a competing announcement
  for the same hash silently overwrites the original sender's PDB.
- Wire decode paths for `BlockTxn`, `GetBlockTxn`, `PrefilledTx` lack
  varint bounds checks (the per-`CmpctBlock` 100k bound at line 6345 is
  the only guard).
- `tryFill`'s 3+-duplicate-match accounting decrements `hits` once per
  dupe, so `pdbMempoolCount` can go **negative** if three or more
  mempool txs collide on the same shortId. Core stops decrementing after
  the first dupe.

The fundamentals from W126 (12 bugs) are all unchanged. W156 adds 19
bugs on top, of which 2 are P0 (ban-vs-discourage + dead arm), 6 P1,
9 P2, 2 P3.

---

## Gate matrix (24 W156-specific deep-dive gates)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | post-verack sendcmpct outbound | G1: gated on peer NODE_WITNESS for v=2 | **BUG-1 (P1)** — `Network.hs:2428` always sends `(False, 2)` regardless of `vServices theirVersion`; non-witness peers receive a v2 negotiation they cannot satisfy |
| 1 | … | G2: gated on `vRelay theirVersion` and post-IBD | **BUG-2 (P1)** — no relay gate, no IBD gate; we negotiate cmpctblocks during IBD where they're useless |
| 1 | … | G3: gated on outbound (Core only sends from us iff peer is willing to honour HB FROM us) | **BUG-3 (P2)** — sent to inbound and outbound alike with no asymmetry |
| 2 | MSendCmpct inbound dispatch | G4: single case arm in syncMessageHandler | **BUG-4 (P0)** — TWO arms in same `case msg of`: line 2185 (active log-only handler) AND line 2353 (`MSendCmpct _ -> return ()` — dead unreachable code). GHC `-Woverlapping-patterns` warning at every compile |
| 2 | … | G5: per-peer state recorded (m_provides_cmpctblocks etc.) | MISSING (W126 BUG-3 carry-forward) |
| 2 | … | G6: drops sendcmpct with version != CMPCTBLOCKS_VERSION=2 | MISSING (W126 BUG-2 carry-forward) |
| 2 | … | G7: refuses second sendcmpct after segwit-activation if version=1 (Core: signals legacy peer) | MISSING (no version-tracking state to enforce) |
| 3 | createCompactBlock encoder | G8: at least one production caller | **MISSING (W126 BUG-12 carry-forward)** — still zero callers in `app/`, `src/`, `bench/` |
| 3 | … | G9: prefilled txns are SORTED ascending by absolute index before differential encoding | PASS-by-accident — only 1 prefilled element (coinbase@0), trivially sorted. **BUG-5 (P2)** — a future multi-prefilled call would emit unsorted-and-thus-undecodable wire |
| 3 | … | G10: nonce is cryptographic-random (not `randomIO` PRNG) | **BUG-6 (P2)** — `Network.hs:6502` uses `randomIO` from `System.Random` (Mersenne Twister, not cryptographic). Core uses `GetRand64()` from libsecp256k1's RNG. Predictable nonce → predictable short-IDs → tx-deanonymization vector |
| 4 | computeWtxid in BIP-152 path | G11: single canonical implementation | **BUG-7 (P1)** — duplicated in `Network.hs:6461-6462` AND `Crypto.hs:1064-1065`; doc-comment at `Network.hs:6459` admits "New code should prefer the typed Haskoin.Crypto.computeWtxid" but the BIP-152 path uses the local copy |
| 4 | … | G12: coinbase wtxid emitted as 0x00...00 (BIP-141) | **BUG-8 (P2)** — both `computeWtxid` definitions do `doubleSHA256 (encode tx)` with no coinbase special-case. In the BIP-152 receiver `tryFill` path this is moot (coinbase is always prefilled, never in shortIds), but if a future caller hashes coinbase wtxid for any other purpose it diverges from BIP-141 |
| 5 | initPartialBlock duplicate-mempool-match accounting | G13: 1st dupe nulls slot + decrements hits; 2nd+ dupes leave hits unchanged | **BUG-9 (P1)** — `Network.hs:6660-6664` decrements `hits` on EVERY dupe occurrence. Three or more mempool txs collide on the same shortId → `pdbMempoolCount` goes **negative**. Core (`blockencodings.cpp:129-136`) gates the decrement on `if (txn_available[idit->second])` which is null after the first clear, so subsequent dupes don't double-decrement |
| 5 | … | G14: bucket-size-12 partition matches unordered_map | **PARTIAL (W126 BUG-4 carry-forward HIGH)** — still `id mod numShortIds`, guard effectively unreachable |
| 5 | … | G15: prefilled-index decoder bounds on Word16 | **BUG-10 (P2)** — `PrefilledTx.get` (Network.hs:6308) does `fromIntegral idx` on a varint with no bound; a varint = 0x10000 truncates silently to 0 |
| 6 | fillPartialBlock mutation guard | G16: checks witness-root in addition to txid-merkle root when segwit-active | MISSING (W126 BUG-5 carry-forward) |
| 6 | … | G17: extra_txn pool (vExtraTxnForCompact ring buffer) consulted | MISSING (W126 BUG-7 carry-forward) |
| 7 | MCmpctBlock receive-side | G18: IBD gate (Core net_processing.cpp:4486) | MISSING (W126 BUG-1 carry-forward) |
| 7 | … | G19: MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3 per-peer cap | **BUG-11 (P1)** — no per-peer in-flight cap on cmpctblocks for the same hash; competing announcements silently overwrite cbsPending entries |
| 7 | … | G20: tip-underflow safety on unsigned `currentTipHeight - blockH` | **BUG-12 (P3)** — `Main.hs:2201` subtracts two `Word32` values; cmpctblock for a future-height block (legitimate during normal operation when peer is ahead of us) underflows to a huge positive depth → falls into `> maxCmpctBlockDepth=5` branch → full-block-getdata fallback. Side-effect masks the underflow but the type contract is wrong |
| 8 | MCmpctBlock failure punishment | G21: `initPartialBlock` returning `Left _` does NOT ban the peer | **BUG-13 (P0)** — `Main.hs:2222` calls `void $ misbehaving pm addr InvalidCompactBlock` which maps to `score=100`, **immediate ban + add-to-discourage-list + disconnect** (`misbehaving` at Network.hs:4047-4071). Core's `Misbehaving` only sets `m_should_discourage=true`. Cmpctblock-specific echo of W148 BUG-13 |
| 8 | … | G22: `fillPartialBlock` returning `Left _` does NOT ban the peer | **BUG-13 same shape** — `Main.hs:2327` re-bans the peer that delivered the missing txns even though reconstruction failure on `BLOCK_MUTATED` is explicitly EXEMPT from punishment in Core when `via_compact_block=true` (net_processing.cpp:1918-1923) |
| 8 | … | G23: post-reconstruction `MBlock` validation failure does NOT ban the announcer for honest mempool-collision | **BUG-14 (P0-CDIV)** — the reconstructed block is fed back into `syncMessageHandler ... (MBlock block)` at Main.hs:2231 + 2337; if `connectBlock` fails, `MBlock` handler at line 1809 fires `void $ misbehaving pm addr InvalidBlock` (score=100, ban). Core's `MaybePunishNodeForBlock` is EXEMPT from BLOCK_CONSENSUS/BLOCK_MUTATED punishment when `via_compact_block=true`. Result: an honest peer who happened to relay a cmpctblock whose reconstruction yielded a block we mark BAD gets banned |
| 9 | MGetBlockTxn serve-side | G24: out-of-bounds index → misbehaving (Core: discourage) | **PARTIAL (W126 BUG-8 carry-forward + new)** — `Main.hs:2288` silently drops via `mapMaybe`; but a future patch to add bounds-misbehaving would (per BUG-13) instantly BAN the requester instead of discourage |
| 9 | … | G25: list-index access avoids O(n²) (`!!` on `blockTxns block`) | **BUG-15 (P1)** — `Main.hs:2288` uses `blockTxns block !! idx` (O(n)) inside `mapMaybe`, and `length (blockTxns block)` (O(n)) per iteration. Total O(n²) on a block of n txs. With n=4000 that's 16M list traversals per getblocktxn; a peer that asks for all txs of a 10k-tx block costs ~100M traversals. Trivial wire-DoS amplification |
| 9 | … | G26: response when block is pruned/unknown (Core: send NOTFOUND or omit) | **BUG-16 (P2)** — `Main.hs:2292` returns `()` silently on `Nothing` from `getBlock db blockHash`. Core does not send NOTFOUND here either, but Core never reaches this branch because `MAX_BLOCKTXN_DEPTH ≤ MIN_BLOCKS_TO_KEEP` static_assert means MAX_BLOCKTXN_DEPTH-deep blocks are always retained. haskoin's prune path (W149-class) doesn't satisfy this invariant: a prune sweep could leave a 10-deep block unreachable, and the getblocktxn requester times out instead of receiving a deterministic NOTFOUND |
| 10 | MGetBlockTxn HB-promotion signal | G27: receipt of getblocktxn sets `piRequestedHbCmpct=True` | MISSING — no field exists (W126 BUG-3 carry-forward) |
| 11 | BlockTxn wire decode | G28: bounds on `count <- getVarInt'` before `replicateM count get` | **BUG-17 (P1)** — `Network.hs:6418-6422` has no upper bound on `count`. A peer sending `count = 2^64-1` triggers `replicateM (fromIntegral count) get` which is unbounded `IO` allocation in the `Get` monad. Memory bomb DoS |
| 11 | … | G29: bounds on `getVarInt'` for `GetBlockTxn.count` | **BUG-18 (P1)** — `Network.hs:6379-6384` identical issue: `count <- getVarInt'`, no bound. A peer sending getblocktxn with 10^9 indices forces an unbounded `replicateM (fromIntegral count) (fromIntegral <$> getVarInt')`. Differential decoder also iterates unboundedly |
| 11 | … | G30: differential-decoder Word16 wrap detection | **BUG-19 (P2)** — `Network.hs:6396-6403` does `cur = prev + d + 1` on `Word16`; bogus diffs silently wrap modulo 2^16. A peer sending the diff sequence `(65000, 600)` produces `(65000, 65 (wrapped))` instead of the intended `(65000, 65601)` — but 65601 itself is invalid (block can't have that many txs). Core's `DifferenceFormatter::Unser` checks `nextIndex > std::numeric_limits<uint16_t>::max()` and rejects |
| 12 | block-in-flight tracking | G31: receipt of MCmpctBlock resets Sync.hs's `bdPendingBlocks` for that hash | **BUG-20 (P2)** — no integration between `MCmpctBlock` / `MBlockTxn` handlers and `Sync.hs::bdPendingBlocks`. A cmpctblock that successfully reconstructs is fed back as `MBlock` (Main.hs:2231 + 2337), but the sync layer's pending Map sees `brReceived=False`. After `bdBaseTimeout` (2..64s) Sync re-requests the same block from a different peer as a FULL block — double-fetch |
| 12 | … | G32: receipt of cmpctblock-driven MBlock calls `recordBlockReceived` | **BUG-21 (P2)** — `Network.hs:6019-6026` defines `recordBlockReceived` (decays stall timeout) but **zero callers in Main.hs**. Sync.hs uses its own pending Map; both `recordBlockRequested` and `recordBlockReceived` are dead helpers (carry-forward W126 dead-helper streak) |
| 13 | InvCompactBlock serve via getdata | G33: `MGetData` dispatch handles `InvCompactBlock` (inv-type 4) | **BUG-22 (P2)** — `Main.hs:1975-2004` enumerates `InvBlock`, `InvWitnessBlock`, `InvTx`, `InvWitnessTx`, default `_ -> NOTFOUND`. There is NO `InvCompactBlock` branch. Core (~5910) responds to MSG_CMPCT_BLOCK getdata with the cached `m_most_recent_compact_block` when within MAX_CMPCTBLOCK_DEPTH=5; haskoin always replies NOTFOUND |

---

## BUG-1 (P1) — post-verack `sendcmpct(False, 2)` sent unconditionally, regardless of peer NODE_WITNESS

**Severity:** P1. Bitcoin Core gates the v=2 sendcmpct on whether the peer
advertises NODE_WITNESS — sending v=2 to a non-witness peer is meaningless
because the peer's GetShortID uses txid, not wtxid, and the short-ID
table will not match. Core sends v=1 (txid-based) to legacy peers and v=2
to NODE_WITNESS peers.

haskoin's `continueHandshake` (`src/Haskoin/Network.hs:2428`):

```haskell
sendMessage pc MSendHeaders
sendMessage pc (MSendCmpct (SendCmpct False 2))
when (vRelay theirVersion) $
  sendMessage pc (MFeeFilter (FeeFilter 100000))
```

The `(SendCmpct False 2)` is fired unconditionally — no
`when (vServices theirVersion .&. nodeWitness /= 0)` gate. A pre-segwit
peer (e.g., a deliberately stripped-down test peer or a legacy node)
receives our v=2 negotiation, may respond with its own v=2, and then
both sides compute mismatched short-IDs.

**File:** `src/Haskoin/Network.hs:2428`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` ~5901-5912 (sends
v=2 only when `pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION`
**and** `State(peer.id)->fHaveWitness`).

**Impact:** silent short-ID divergence with non-witness peers; reduces
the receiver-side reconstruction success rate against the (rare but
present) legacy-only segment of the network. No consensus risk.

---

## BUG-2 (P1) — post-verack sendcmpct lacks IBD and relay-mode gates

**Severity:** P1. Core's BIP-152 negotiation is contingent on:
1. Past IBD (no point negotiating cmpctblocks if we're seconds-of-blocks
   behind; the receiver-side path's mempool-hit rate is ~0% during IBD),
2. Relay enabled (block-relay-only peers still get sendcmpct, but
   `m_blocks_only_relay` peers should be evaluated separately).

haskoin's `continueHandshake` ignores both. The mempool is empty for
the first 6+ hours of mainnet IBD, every received cmpctblock falls
through to `getblocktxn` round-trip, and we end up paying the cmpct
overhead with zero benefit (the W126 BUG-1 carry-forward observation).

**File:** `src/Haskoin/Network.hs:2426-2431`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` ~5905-5912.

**Impact:** wasted bandwidth/CPU during IBD; per-cmpctblock round-trip
cost without any of the latency savings cmpctblocks are designed to
provide.

---

## BUG-3 (P2) — sendcmpct sent to inbound and outbound peers symmetrically

**Severity:** P2. Core's BIP-152 outbound asymmetry (inbound vs outbound)
matters for HB topology: the announcer-side promotion path
`MaybeSetPeerAsAnnouncingHeaderAndIDs` caps OUTBOUND HB peers at 3
(`lNodesAnnouncingHeaderAndIDs.size() < 3`), and inbound peers are
gated separately by `m_requested_hb_cmpctblocks`.

haskoin's `continueHandshake` runs identically for inbound and outbound
connections, sending `MSendCmpct (SendCmpct False 2)` to both. Without
the per-peer fields from W126 BUG-3 (`piProvidesCompact`, `piHbFrom`,
`piHbTo`), the asymmetry cannot be reconstructed downstream even if we
later wanted to enforce a 3-peer cap.

**File:** `src/Haskoin/Network.hs:2410-2433` (`continueHandshake` runs
the same code path regardless of `pcInbound` / `pcOutbound`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1272-1329`
(`MaybeSetPeerAsAnnouncingHeaderAndIDs` HB-outbound-cap).

**Impact:** cosmetic for now (W126 BUG-10/-11 dead-helper status means
no HB topology exists either way); blocks any future HB rollout from
mirroring Core's selection logic.

---

## BUG-4 (P0) — Two `MSendCmpct` arms in the same `case msg of`; second is dead unreachable code

**Severity:** P0 ("non-exhaustive ADT" 1st haskoin instance / dead-arm
1st instance — first time the SAME constructor appears TWICE in one
case-of). `syncMessageHandler` at `app/Main.hs:1639` is a single big
`case msg of` over the `Message` ADT. Within that case:

- Line 2185: `MSendCmpct sc -> do putStrLn $ "Peer supports compact
  blocks: version=" ++ show (scVersion sc) ++ ", announce=" ++ show
  (scAnnounce sc)`
- Line 2353: `MSendCmpct _ -> return ()`

Haskell pattern-matching is **first-match wins** — the line 2185 arm
ALWAYS fires, the line 2353 arm is **completely dead code**. GHC's
`-Woverlapping-patterns` warning is emitted at every compile. The
behaviour is functionally OK (the active arm is a log-only stub anyway,
per W126 BUG-2) but the dead arm is a smoking-gun marker that a previous
refactor moved the handler without removing the placeholder.

The pattern matters for two reasons:
1. **Fix-blast radius**: a developer adding state-tracking to the
   handler may edit one arm and not the other. If they edit ONLY the
   dead arm, their fix never runs.
2. **Compile-warning noise**: GHC emits the overlap warning on every
   build, training developers to ignore the warning class. A future
   genuine overlap (e.g., `MTx _ -> ...` after a more-specific catch)
   blends into the noise.

**File:** `app/Main.hs:2185` (active arm) + `app/Main.hs:2353` (dead arm).

**Core ref:** N/A (Haskell-specific bug — Core's switch-by-message-type
doesn't allow this).

**Impact:** trivial perf (compile warning); high latent risk that a
fix lands in the dead arm and never executes.

---

## BUG-5 (P2) — `createCompactBlock` does not sort prefilled txns before encoding

**Severity:** P2. BIP-152 spec requires prefilled txns to be in
ascending order of absolute index (so the DifferenceFormatter's
differential encoding yields non-negative differences). Core ensures
this by construction in `CBlockHeaderAndShortTxIDs` constructor:
prefilled is built in vtx order, which is naturally sorted.

haskoin's `createCompactBlock` (`Network.hs:6499-6519`) takes an arbitrary
`[Tx]` and builds:
```haskell
let coinbase = head txns
    prefilled = [PrefilledTx 0 coinbase]
```
Only one prefilled element (the coinbase at absolute index 0). Trivially
sorted, so the encoded wire is correct for the current single-caller
contract.

But: if a future patch adds a "prefill any tx not in mempool" heuristic
(Core does this for transactions that the announcer expects the receiver
to be missing), passing an unsorted list to `createCompactBlock` would
emit relative indices with one or more negative values, which the
receiver's `insertPrefilledTxns` interprets as either zero-offsets or
huge-skips, breaking reconstruction.

**File:** `src/Haskoin/Network.hs:6499-6519` (no sort step).

**Core ref:** `bitcoin-core/src/blockencodings.h:88-103`
(CBlockHeaderAndShortTxIDs constructor walks vtx in order).

**Impact:** dormant; activated by a future caller that passes
multi-prefilled. Worth adding a `sortOn ptIndex` defensive guard.

---

## BUG-6 (P2) — cmpctblock nonce uses `System.Random.randomIO` (non-cryptographic)

**Severity:** P2. Bitcoin Core derives the cmpctblock nonce from
`GetRand64()` which routes through libsecp256k1's RNG (cryptographically
secure). The nonce is the **only** unpredictable input to the SipHash
short-ID key — if an attacker can predict the nonce, they can construct
two distinct wtxids that collide under the SipHash, attacking
reconstruction.

haskoin's `createCompactBlock` (`Network.hs:6502`):
```haskell
nonce <- randomIO
```

`System.Random.randomIO :: Random a => IO a` for `Word64` uses the
default StdGen, which is Mersenne-Twister-based (or splitmix in
newer base versions) — neither is cryptographically secure. An
adversary who observes ~624 consecutive nonces can predict subsequent
ones.

For receiver-side parity, this is moot because `createCompactBlock` has
zero callers today (W126 BUG-12). But if the ANNOUNCE-side path is ever
wired up and we start announcing cmpctblocks to HB peers, the
predictable-nonce vulnerability becomes real.

**File:** `src/Haskoin/Network.hs:6502`.

**Core ref:** `bitcoin-core/src/blockencodings.h:114` (constructor
takes nonce from `GetRand64()`); `bitcoin-core/src/random.cpp::GetRand`.

**Impact:** dormant; activates with ANNOUNCE-side wiring. Use
`Crypto.Random.getRandomBytes` or libsecp256k1's RNG.

---

## BUG-7 (P1) — `computeWtxid` duplicated across `Haskoin.Network` and `Haskoin.Crypto`

**Severity:** P1 (two-pipeline guard — 16th distinct extension this
quad-month; first haskoin BIP-152 instance). `computeWtxid` is defined
in two modules:

1. `src/Haskoin/Network.hs:6461-6462`:
   ```haskell
   computeWtxid :: Tx -> Hash256
   computeWtxid tx = doubleSHA256 (encode tx)
   ```
2. `src/Haskoin/Crypto.hs:1064-1065`:
   ```haskell
   computeWtxid :: Tx -> Wtxid
   computeWtxid tx = Wtxid $ doubleSHA256 (encode tx)
   ```

Both implementations are byte-identical at runtime, differing only in
the result type (`Hash256` vs `Wtxid` newtype). The doc-comment at
`Network.hs:6459-6460` admits:

> "New code should prefer the typed 'Haskoin.Crypto.computeWtxid' which
> returns a typed 'Wtxid' newtype."

But the BIP-152 path at `Network.hs:6512` and `Network.hs:6653` uses
the local `computeWtxid` (the untyped one). The two definitions are
parallel pipelines for the same primitive.

Failure mode: a future fix (e.g., adding a coinbase wtxid=0x00...00
special case per BIP-141, or fixing a hypothetical witness-serialization
bug) applied to ONE of the two will leave the BIP-152 path with the old
behaviour. The compile-time type system does not enforce the
"prefer the typed one" comment.

**File:** `src/Haskoin/Network.hs:6461-6462`,
`src/Haskoin/Crypto.hs:1064-1065`.

**Core ref:** `bitcoin-core/src/primitives/transaction.cpp` —
`CTransaction::ComputeWitnessHash` is the SINGLE source of truth.

**Impact:** consensus-divergence-on-future-fix; classical two-pipeline
guard.

---

## BUG-8 (P2) — `computeWtxid` of coinbase tx does NOT return 0x00...00

**Severity:** P2. BIP-141 mandates that the coinbase transaction's
wtxid is hardcoded to `0x00000000...00` (32 zero bytes). This is what
allows the witness commitment in the coinbase's last output to be
computed without circular dependency.

haskoin's `computeWtxid` (both copies, per BUG-7) does
`doubleSHA256 (encode tx)` unconditionally. For the coinbase, this
returns a non-zero hash. In the BIP-152 receiver path this is moot
because the coinbase is always prefilled (never in shortIds), but:

- Any caller that hashes coinbase-tx wtxid for a *different* purpose
  diverges from BIP-141.
- Cross-cite: the `tryFill` path at `Network.hs:6652-6654` walks the
  mempool, computes wtxid for each, and looks up the shortId. If the
  mempool ever held a coinbase tx (it shouldn't, since coinbase txs
  cannot enter the mempool — but a corrupt mempool state from a
  separate bug class would), the wtxid would be the wrong one
  silently.

**File:** `src/Haskoin/Network.hs:6461-6462`,
`src/Haskoin/Crypto.hs:1064-1065`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h` —
`CMutableTransaction::GetWitnessHash` returns `Txid::FromUint256(uint256::ZERO)`
for coinbase.

**Impact:** dormant; activates on any future caller that hashes coinbase
wtxid for non-cmpctblock purposes.

---

## BUG-9 (P1) — `tryFill` decrements `hits` on EVERY duplicate match; can go negative

**Severity:** P1. Bitcoin Core's `blockencodings.cpp:125-136`:

```cpp
if (!have_txn[idit->second]) {
    txn_available[idit->second] = txit->GetSharedTx();
    have_txn[idit->second]  = true;
    mempool_count++;
} else {
    // If we find two mempool txn that match the short id, just request it.
    if (txn_available[idit->second]) {
        txn_available[idit->second].reset();
        mempool_count--;
    }
}
```

After the FIRST duplicate match, `txn_available[idx]` is reset to
nullptr; subsequent matches enter the `else` branch but `if
(txn_available[idit->second])` is now FALSE, so neither the reset
nor the `mempool_count--` fire. Net effect on count after k≥2 dupes:
+1 (first) then -1 (second) then nothing → final 0 (slot cleared).

haskoin's `tryFill` (`Network.hs:6652-6669`):

```haskell
tryFill skey shortIdMap (avail, hits, haveTxn) _txid tx =
  let wtxid   = computeWtxid tx
      shortId = computeShortId skey (getHash256 wtxid)
  in case Map.lookup shortId shortIdMap of
       Nothing  -> (avail, hits, haveTxn)
       Just idx ->
         if Map.member idx haveTxn
           then
             ( Map.insert idx Nothing avail
             , hits - 1                  -- ALWAYS decrements on dupe
             , haveTxn                   -- haveTxn keeps idx
             )
           else
             ( Map.insert idx (Just tx) avail
             , hits + 1
             , Map.insert idx () haveTxn
             )
```

The `if Map.member idx haveTxn then ... hits - 1` fires for EVERY dupe
match, not just the first. Trace with 3 mempool txs A/B/C all having
the same shortId mapped to slot Y:

- iter A: haveTxn doesn't contain Y → insert (Y, Just A), hits=+1, haveTxn={Y}
- iter B: haveTxn contains Y → insert (Y, Nothing), hits=0, haveTxn={Y}
- iter C: haveTxn STILL contains Y → insert (Y, Nothing), hits=**-1**, haveTxn={Y}

After fold completes, `pdbMempoolCount = -1`. This is consumed at
`Network.hs:6230` for log output ("mempool_hits=-1") — cosmetic — but
it's also pulled into `pdb` and stored. Any downstream metric that uses
`pdbMempoolCount` (none today, but the field is exported via the
`PartiallyDownloadedBlock` ADT) sees a negative count.

Severity is P1 not P0 because (a) the failure mode is benign-by-luck
(the slot is correctly nulled, the missing-index list at line 6608
includes it, getblocktxn is sent), and (b) Core's behaviour is also
"null the slot" — only the COUNT diverges.

**File:** `src/Haskoin/Network.hs:6660-6664`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:125-136`.

**Excerpt (haskoin, dupe accounting)**
```haskell
if Map.member idx haveTxn
  then
    ( Map.insert idx Nothing avail
    , hits - 1     -- ← BUG: should be `hits` (no decrement after first dupe)
    , haveTxn
    )
```

**Impact:** misleading mempool-hit metric in logs; latent risk if any
downstream consumer treats `pdbMempoolCount` as Int (it is) and triggers
on `< 0`.

---

## BUG-10 (P2) — `PrefilledTx.get` silently truncates varint relative-index > 65535 to Word16

**Severity:** P2. Bitcoin Core's `PrefilledTransaction::Unser` validates
that the relative index does not overflow the absolute uint16 bound:
"Prefilled transaction index overflows uint16_t" at
`blockencodings.cpp:77-79`.

haskoin's `PrefilledTx.get` (`Network.hs:6305-6308`):

```haskell
get = do
  idx <- getVarInt'
  tx <- get
  return $ PrefilledTx (fromIntegral idx) tx
```

`getVarInt'` returns `Word64`. `fromIntegral idx :: Word16` silently
truncates the high 48 bits. A peer sends `idx = 0x10000` (= 65536) →
`fromIntegral 65536 :: Word16 = 0`. The downstream `insertPrefilledTxns`
absolute-index check at `Network.hs:6630-6634` ("Prefilled transaction
index out of range") then fires on the *truncated* value, not the
original, so the rejection reason is misleading. Worse: a malicious
peer with knowledge of our prefilled-list state can craft varint
values that truncate to specific positions and bypass intended bound
checks.

**File:** `src/Haskoin/Network.hs:6305-6308`.

**Core ref:** `bitcoin-core/src/blockencodings.cpp:77-79`.

**Impact:** wire-decode bound bypass; rejection reasons in logs are
misleading.

---

## BUG-11 (P1) — No `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK=3` cap; competing announcements overwrite cbsPending

**Severity:** P1. Core's `MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3` limits
how many concurrent cmpctblock reconstructions can be in flight for the
same block hash. When a 4th peer announces the same block, Core ignores
the announcement (still relays full block via getdata fallback). This
prevents memory amplification when N peers all simultaneously announce
the same new block.

haskoin's `cbsPending :: TVar (Map BlockHash PartiallyDownloadedBlock)`
is keyed by hash, NOT by `(hash, peer)`. When peer A announces
cmpctblock for hash H and we start initPartialBlock → getblocktxn round-trip,
the PDB is stored at `cbsPending[H]`. If peer B then announces the
same cmpctblock for H (different nonce, different shortId table), the
new PDB OVERWRITES peer A's at `cbsPending[H]`:

```haskell
-- Main.hs:2253-2254
cbs <- readIORef compactBlockStateRef
atomically $ modifyTVar' (cbsPending cbs) (Map.insert bh pdb)
```

`Map.insert` silently replaces existing entries. When peer A's
`MBlockTxn` arrives, the lookup at Main.hs:2306 returns peer B's PDB
(which has a different shortId map), and fillPartialBlock fails because
the index slot mapping is wrong → peer A gets banned (per BUG-13)
for what was actually peer B's overwrite race.

**File:** `app/Main.hs:2253-2254` (Map.insert, no per-peer keying).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4593-4604`
(MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK gate).

**Impact:** ban-on-honest-race when two peers race-announce the same
block; memory bloat when 100s of peers announce simultaneously
(though offset by the overwrite — total memory is bounded by # of
distinct hashes, not # of announcements).

---

## BUG-12 (P3) — `currentTipHeight - blockH` underflows Word32 for future-height blocks

**Severity:** P3. `Main.hs:2200-2202`:

```haskell
let mBlockHeight = fmap ceHeight (Map.lookup bh chainEntries)
    depth = case mBlockHeight of
      Just blockH -> fromIntegral currentTipHeight - fromIntegral blockH :: Int
      Nothing     -> 0
```

Both `currentTipHeight` and `blockH` are `Word32`. The `fromIntegral`
casts to `Int` (signed) before subtraction, so on 64-bit Linux the
subtraction is signed-64-bit-safe and a negative `depth` is allowed.
The subsequent `depth > maxCmpctBlockDepth` check is signed, so a
negative depth is correctly handled as "not too deep, proceed".

So the bug is actually NOT a wrap — it's "future-height block treated as
depth=negative, no fallback to full-block-getdata triggered, proceeds
to `initPartialBlock` for a block whose header we may not even have".
That branch eventually calls `syncMessageHandler ... (MBlock block)`,
which calls `addHeader` first (line 1761), which tries to find the
parent header (which we don't have for a future block), and fails. The
failure path at line 1772 BANS the peer (`misbehaving pm addr
InvalidBlock`) for sending us a valid-but-future cmpctblock.

**File:** `app/Main.hs:2200-2202` (depth derivation),
`app/Main.hs:1772` (ban path).

**Core ref:** `bitcoin-core/src/net_processing.cpp:4486-4515`
(MaybeSendGetHeaders + IBD short-circuit handles the "we don't have
the parent" case without punishment).

**Impact:** ban-on-honest-cmpctblock-for-future-block (peer is on a
tip we haven't received headers for yet). Combined with BUG-13/-14, the
same peer can also be banned for the subsequent reconstruction-fallback
MBlock failure.

---

## BUG-13 (P0) — `initPartialBlock` and `fillPartialBlock` failures BAN peer; Core only discourages

**Severity:** P0 ("ban-vs-discourage 2nd haskoin instance" — first was
W148 BUG-13 MBlock-on-reorg-bans-peer; this is the cmpctblock echo of
the same pattern). Bitcoin Core's `Misbehaving(peer, message)` at
`net_processing.cpp:1893-1904`:

```cpp
void PeerManagerImpl::Misbehaving(Peer& peer, const std::string& message)
{
    LOCK(peer.m_misbehavior_mutex);
    const std::string message_prefixed = message.empty() ? "" : (": " + message);
    peer.m_should_discourage = true;
    LogDebug(BCLog::NET, "Misbehaving: peer=%d%s\n", peer.m_id, message_prefixed);
    ...
}
```

Sets `m_should_discourage = true` only. The peer is not banned, not
disconnected in this function. Disconnection happens later via
`MaybeDiscourageAndDisconnect` at `~5070` which uses `BanMan::Discourage`
(NOT `BanMan::Ban`). Discouragement is a softer signal: address goes
into a bloom-filter for short-term avoidance, NOT into the explicit ban
list with a 24-hour expiry.

For the BIP-152 path specifically, Core's `BLOCKTXN` handler at
~3473-3490 fires `Misbehaving(peer, "previous compact block
reconstruction attempt failed")` and `Misbehaving(peer, "invalid
compact block/non-matching block transactions")` — both discouragement-only.

haskoin's `misbehaving` (`Network.hs:4031-4071`):

```haskell
-- Single-event discourage: set PeerBanned state immediately.
-- piBanScore is updated for diagnostic logging only.
newScore <- atomically $ do
  ...
  modifyTVar' (pcInfo pc) $ \j ->
    j { piBanScore = newScore'
      , piState = PeerBanned        -- ← bans
      }
  return newScore'

-- Regular peer: add to discourage list and disconnect
banPeer pm addr                     -- ← adds to ban list
disconnectPeer pc                    -- ← disconnects immediately
atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)
```

The function name is `misbehaving` but the behaviour is full **ban +
add-to-discourage-list + disconnect** on a SINGLE event. `InvalidCompactBlock`
has score=100 (`Network.hs:673`) which triggers this entire chain on
the FIRST occurrence.

Cmpctblock-specific failure modes that BAN in haskoin:
1. `Main.hs:2222` — `initPartialBlock` returns `Left _` (empty block,
   prefilled-overflow, short-id collision, bucket-size DoS).
2. `Main.hs:2327` — `fillPartialBlock` returns `Left _` (wrong missing
   count or merkle-root mismatch).

Core's behaviour: each of these is `Misbehaving(peer, ...)` —
discourage-only.

**Pattern shape**: same as W148 BUG-13 (MBlock-on-reorg-bans-peer);
haskoin's `misbehaving` primitive is too aggressive across the entire
P2P surface, and BIP-152 is one more place where Core's discourage
becomes haskoin's ban.

**File:** `app/Main.hs:2222`, `app/Main.hs:2327`,
`src/Haskoin/Network.hs:4031-4071` (misbehaving impl),
`src/Haskoin/Network.hs:673` (InvalidCompactBlock=100).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1893-1904`
(`Misbehaving` discourage-only),
`bitcoin-core/src/net_processing.cpp:3473-3490` (cmpctblock-specific
misbehavior).

**Impact:**
- Honest peer who happens to send us a cmpctblock that collides on
  shortIds (e.g., mempool race where a tx we don't have is in their
  mempool but not ours) → BANNED for 24h.
- A peer that sends a cmpctblock for a block whose parent header we
  haven't received yet (race during normal IBD wrap-up) → BANNED.
- A peer that announces a cmpctblock concurrently with another peer's
  announcement of the same block (per BUG-11 race) → one of the two
  is banned for the other's overwrite.
- Cumulative effect: haskoin's mainnet peer-set is more turnover-prone
  than Core's, the addrman degrades faster, peer-quality drops.

---

## BUG-14 (P0-CDIV) — Post-reconstruction `MBlock` validation failure bans the cmpctblock announcer

**Severity:** P0-CDIV (cmpctblock-specific echo of W148 BUG-13).
Bitcoin Core's `MaybePunishNodeForBlock` at `net_processing.cpp:1906-1948`
takes a `bool via_compact_block` parameter and **EXEMPTS** the cmpct
case from punishment for `BLOCK_CONSENSUS` / `BLOCK_MUTATED`:

```cpp
case BlockValidationResult::BLOCK_CONSENSUS:
case BlockValidationResult::BLOCK_MUTATED:
    if (!via_compact_block) {
        if (peer) Misbehaving(*peer, message);
        return;
    }
    break;
```

The rationale: a cmpctblock-reconstructed block can be invalid for
reasons that are NOT the announcer's fault — e.g., a tx the announcer
mempool-resolved happens to have a stale witness, or short-ID collisions
swap two different txns. Core's design choice is to NOT punish the
announcer for these honest failures.

haskoin's MCmpctBlock handler at `Main.hs:2231` and MBlockTxn handler
at `Main.hs:2337` both end with:

```haskell
syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef
  requestedUpToRef ibdModeRef recentlyRejectedRef blocksSinceFlushRef
  lastFlushEpochRef pruneCfg mBlockStore mIdxMgr orphanPoolRef
  compactBlockStateRef addr (MBlock block)
```

— a recursive call into the SAME message handler with `MBlock block`
constructed from the reconstructed block. The MBlock handler at
`Main.hs:1801-1809` does:

```haskell
Left cbErr -> do
  putStrLn $ "Block rejected at height " ++ show height
          ++ " (peer " ++ show addr ++ "): " ++ cbErr
  pm <- readIORef pmRef
  void $ misbehaving pm addr InvalidBlock
```

`InvalidBlock` is also score=100 → BAN. There is NO `via_compact_block`
flag plumbed through the recursive call, so the MBlock handler cannot
distinguish "peer sent us a bad full block" from "peer sent us a
cmpctblock whose reconstruction yielded a block we marked BAD".

The recursive submission also doesn't carry the originator address
through to any logic that would suppress punishment. The same `addr` is
passed verbatim, so the cmpctblock-derived MBlock call bans the
cmpctblock announcer.

**File:** `app/Main.hs:2231` (cmpct reconstruction submitted as MBlock),
`app/Main.hs:2337` (BlockTxn reconstruction submitted as MBlock),
`app/Main.hs:1809` (MBlock handler bans on validation failure).

**Core ref:** `bitcoin-core/src/net_processing.cpp:1906-1948`
(`MaybePunishNodeForBlock` with `via_compact_block=true` exemption).

**Impact:** honest peer who relays a cmpctblock that reconstructs into
a (perhaps just-mutated-by-collision) block we mark BAD → banned for
24h. This is the cmpct-specific repeat of W148 BUG-13: same
ban-on-honest-data pattern, different message path.

---

## BUG-15 (P1) — `MGetBlockTxn` handler is O(n²) on block transactions; trivial wire-DoS amplification

**Severity:** P1. `app/Main.hs:2288`:

```haskell
let txns = mapMaybe (\i -> let idx = fromIntegral i
                           in if idx < length (blockTxns block)
                              then Just (blockTxns block !! idx)
                              else Nothing) indices
```

`blockTxns block` is a Haskell list (`[Tx]`). Both `length` and `!!`
are O(n). With `n = |blockTxns|` (up to ~4000 for a full mainnet block)
and `k = |indices|` (the peer's request), the total work is `O(n*k)`.
For `k = n` (peer requests all transactions), that's `O(n²)` ≈ 16M
operations for n=4000. For n=10000 (Taproot block with many small
txns), ≈ 100M operations.

A peer can craft a getblocktxn with `k` carefully-chosen large indices
in a single message (limited only by the absent G29 wire-count bound,
BUG-18) and force us to scan the list `k` times. With `k = 65535`
(max uint16) and `n = 4000`, each getblocktxn message triggers ~262M
list traversals.

Core uses a `vector<CTransactionRef>` indexed in O(1) via
`block.vtx[req.indexes[i]]`, so it's O(k) for k requests on any block.

**File:** `app/Main.hs:2288`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2598-2607`
(`SendBlockTransactions` uses vector indexing).

**Impact:** trivial wire-DoS amplification: peer sends a 2-byte
getblocktxn-with-huge-indices, we burn seconds of CPU per message.
Combined with the BUG-18 absent decode bound, an adversary can
construct a single 70-KB getblocktxn message that triggers hours of
CPU on a busy receiver.

---

## BUG-16 (P2) — `MGetBlockTxn` for unknown/pruned block returns silently; no NOTFOUND

**Severity:** P2. Bitcoin Core's invariant
`static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP)` ensures that
the `MAX_BLOCKTXN_DEPTH=10` gate at net_processing.cpp:4276 always
fires before reaching the "block not in storage" branch. Pruning never
removes blocks within the cmpct-block window.

haskoin's prune subsystem (W149-class, partially shared with blockbrew)
does not enforce this invariant strictly — a prune sweep can in
principle leave a 10-deep block unreachable if the chainstate-MIN_BLOCKS_TO_KEEP
gap is exact.

`MGetBlockTxn` handler at `Main.hs:2285-2292`:

```haskell
mBlock <- getBlock db blockHash
case mBlock of
  Just block -> ... requestFromPeer pm addr (MBlockTxn ...) ...
  Nothing -> return ()
```

If `getBlock db blockHash` returns `Nothing` (pruned or storage error),
the handler silently returns `()`. The requester then times out waiting
for our blocktxn response and re-requests the full block via
getdata-fallback (per the absent `isBlockStalled` integration, BUG-20).

Core also has no NOTFOUND in this path (Core relies on the
MAX_BLOCKTXN_DEPTH ≤ MIN_BLOCKS_TO_KEEP invariant to make it
unreachable), so haskoin's behaviour is technically not a divergence
from Core's. But the invariant violation in haskoin's prune is the
underlying gap.

**File:** `app/Main.hs:2292` (silent no-op on missing block).

**Core ref:** `bitcoin-core/src/net_processing.cpp:140-141`
(`static_assert(MAX_BLOCKTXN_DEPTH <= MIN_BLOCKS_TO_KEEP)`).

**Impact:** rare; pruned-storage edge case. Combined with W149-class
prune+reorg bugs (cross-cite blockbrew W149 BUG-1).

---

## BUG-17 (P1) — `BlockTxn` decoder has no upper bound on `count`; memory-bomb DoS

**Severity:** P1. `src/Haskoin/Network.hs:6418-6422`:

```haskell
get = do
  blockHash <- get
  count <- getVarInt'
  txns <- replicateM (fromIntegral count) get
  return $ BlockTxn blockHash txns
```

`getVarInt'` returns `Word64` (up to 2^64-1). `replicateM (fromIntegral
count) get` is unbounded — `replicateM` lazily allocates the result
list as `get` is repeated, but `Get` is strict on the parser, so it
attempts to read `count * sizeof(Tx)` bytes from the wire. A peer
sending `count = 2^32` triggers an allocation of `4 billion *
sizeof(Tx)` bytes.

Practically the wire-buffer-size cap (4 MiB per Bitcoin message) limits
the actual bytes read, but the `replicateM` and `count` arithmetic are
unbounded — `fromIntegral 2^32 :: Int` on 64-bit is 4 billion, which
fits in `Int` but cannot be allocated as a list.

Core's `BlockTransactions` deserialization (CTransactionRef vector,
controlled by stream-size bounds in `streams.h` — `VARINT_DEFAULT` etc.)
caps the count via the stream's `MAX_SIZE` parameter.

**File:** `src/Haskoin/Network.hs:6418-6422`.

**Core ref:** `bitcoin-core/src/blockencodings.h:67-78`
(BlockTransactions Unser bounded by stream MAX_SIZE).

**Impact:** wire-decode memory-bomb DoS; combined with the absent
network-level message-size cap, a single peer can exhaust haskoin's
heap with one `blocktxn` message.

---

## BUG-18 (P1) — `GetBlockTxn` decoder has no upper bound on `count`

**Severity:** P1. Identical shape to BUG-17 for `GetBlockTxn`:

```haskell
-- Network.hs:6379-6384
get = do
  blockHash <- get
  count <- getVarInt'
  diffs <- replicateM (fromIntegral count) (fromIntegral <$> getVarInt')
  let indexes = differentialDecode diffs
  return $ GetBlockTxn blockHash indexes
```

Each iteration parses a varint (1 to 9 bytes). A peer sending `count =
2^32` with each diff being a 1-byte varint = 4 billion bytes of input
(impossible per the network message-size cap) but `count` is unbounded
at the type level.

A peer sending `count = 0x10000` (= 65536) with each diff = 1 byte =
65 KB input → buildable into a single 8-KB compressed Bitcoin message
(varints with overlap). The `differentialDecode` then runs in O(count),
and the resulting list is fed into BUG-15's O(n²) handler at
`Main.hs:2288`, multiplying the amplification.

**File:** `src/Haskoin/Network.hs:6379-6384`.

**Core ref:** `bitcoin-core/src/blockencodings.h:23-43`
(BlockTransactionsRequest with DifferenceFormatter bounded by stream
MAX_SIZE).

**Impact:** wire-decode DoS amplification combined with BUG-15.

---

## BUG-19 (P2) — `differentialDecode` Word16 wrap on adversarial diffs goes undetected

**Severity:** P2. `Network.hs:6396-6403`:

```haskell
differentialDecode :: [Word16] -> [Word16]
differentialDecode [] = []
differentialDecode (x:xs) = go x xs [x]
  where
    go _ [] acc = reverse acc
    go prev (d:rest) acc =
      let cur = prev + d + 1
      in go cur rest (cur:acc)
```

`prev + d + 1` is `Word16` arithmetic — silent wraparound on overflow.
A peer sending the diff sequence `(65000, 600)` produces `cur = 65000
+ 600 + 1 = 65601` which on `Word16` is **65601 mod 65536 = 65**. The
resulting indexes list `[65000, 65]` is non-ascending and would never
have been a legal request, but haskoin's downstream handler at
`Main.hs:2288` would happily try to serve `blockTxns block !! 65000`
(out-of-bounds for any real block, silently dropped per W126 BUG-8)
and `blockTxns block !! 65` (a valid in-block index).

Core's `DifferenceFormatter::Unser` at `blockencodings.h:28-43`:

```cpp
uint64_t lastVal = -1;
for (size_t i = 0; i < v.size(); i++) {
    uint64_t diff = 0;
    READWRITE(VARINT(diff));
    if (lastVal + 1 + diff > std::numeric_limits<uint16_t>::max())
        throw std::ios_base::failure("differential value overflow");
    v[i] = lastVal + 1 + diff;
    lastVal = v[i];
}
```

Explicitly checks `lastVal + 1 + diff > uint16_t::max()` and throws.
haskoin silently wraps.

**File:** `src/Haskoin/Network.hs:6396-6403`.

**Core ref:** `bitcoin-core/src/blockencodings.h:28-43`.

**Impact:** wrap-bug allows out-of-order index injection without
detection; combined with BUG-15's O(n²) handler, an adversary can
craft an index list that triggers worst-case list-walk patterns.

---

## BUG-20 (P2) — MCmpctBlock/MBlockTxn handlers do NOT reset `Sync.hs::bdPendingBlocks`; double-fetch on reconstruction

**Severity:** P2. `Sync.hs:255-285` runs a per-second loop that checks
`bdPendingBlocks` for `brReceived=False && now - brRequested >
baseTimeout`. On stall, it re-queues the block hash via
`bdDownloadQueue` and the next download worker re-requests the block
as a full block.

The BIP-152 path:
1. We request block H via getdata-cmpctblock (or accept an unsolicited
   cmpctblock announcement).
2. Sync.hs's `bdPendingBlocks[H]` is set with `brReceived=False`.
3. `MCmpctBlock` arrives, `initPartialBlock` succeeds with missing txns
   → we send `getblocktxn`.
4. `MBlockTxn` arrives, `fillPartialBlock` succeeds → we recursively
   submit `MBlock block` to syncMessageHandler.
5. `connectBlock` succeeds → block is connected.
6. But `bdPendingBlocks[H].brReceived` is still `False`. Sync.hs's
   timeout loop sees the entry, re-queues H for download.
7. A different peer is selected (round-robin), we fire another
   `getdata MSG_WITNESS_BLOCK` for H → receive the full block we
   already have.

Net effect: every cmpctblock-reconstructed block is fetched TWICE.

**File:** `app/Main.hs:2231, 2337` (no `Sync.markBlockReceived` call),
`src/Haskoin/Sync.hs:255-285` (stall loop unaware of cmpct path).

**Core ref:** `bitcoin-core/src/net_processing.cpp` — Core uses a
single `mapBlocksInFlight` keyed by `(hash, peer)` that is updated
from the cmpctblock receive path.

**Impact:** ~2x bandwidth waste on every cmpct-reconstructed block.
On a busy network where ~30% of blocks come via cmpct, this is a
15% net bandwidth tax.

---

## BUG-21 (P2) — `recordBlockReceived` / `recordBlockRequested` / `isBlockStalled` are dead helpers

**Severity:** P2 ("dead-helper-at-call-site" 35th-or-later distinct
fleet instance; haskoin's BIP-152 module now has 4 dead helpers per
BUG-7 (computeWtxid dupe), W126 BUG-11/-12, and this one). The
`StalePeerTracker` API at `Network.hs:6019-6053`:

- `recordBlockRequested :: StalePeerTracker -> SockAddr -> BlockHash -> IO ()`
  (decays stall timeout on success)
- `recordBlockReceived :: StalePeerTracker -> SockAddr -> BlockHash -> IO ()`
- `isBlockStalled :: StalePeerTracker -> SockAddr -> Bool -> IO (Bool, Maybe BlockHash)`

All three are exported (Network.hs:294-296) but have **ZERO callers** in
`app/Main.hs`. Sync.hs uses its own `bdPendingBlocks`/`bdBaseTimeout`
mechanism. The `blockStallTimeoutCompact = 2` constant referenced at
`Network.hs:6026, 6036` is consumed only by these dead helpers.

**File:** `src/Haskoin/Network.hs:6019-6053, 274-296`.

**Impact:** "blockStallTimeoutCompact = 2" is misleading documentation:
operators reading the constant assume the 2-second compact-block stall
timeout is enforced. It isn't. The actual sync stall is governed by
Sync.hs's `bdBaseTimeout` starting at 30 seconds (cross-cite the
separate 30 vs 2 second divergence vs Core).

---

## BUG-22 (P2) — `MGetData` dispatch has NO `InvCompactBlock` case; getdata(MSG_CMPCT_BLOCK) silently returns NOTFOUND

**Severity:** P2. Bitcoin Core's `MGetData` handler at
`net_processing.cpp:~5900-5920` checks if the requested block is
within `MAX_CMPCTBLOCK_DEPTH=5` of the tip and, if so, responds with
a cached `m_most_recent_compact_block` (a pre-built CmpctBlock) directly.
This is what lets a peer that already has the parent header request a
cmpctblock without our re-announcing.

haskoin's `MGetData` handler at `Main.hs:1973-2004`:

```haskell
MGetData (GetData ivs) -> do
  pm <- readIORef pmRef
  forM_ ivs $ \iv -> case ivType iv of
    InvBlock -> do
      let bh = BlockHash (ivHash iv)
      ...
    InvWitnessBlock -> ...
    InvTx -> ...
    InvWitnessTx -> ...
    _ -> requestFromPeer pm addr (MNotFound (NotFound [iv]))
```

`InvCompactBlock` (defined at `Network.hs:847` as inv-type 4) falls
into the `_ ->` branch and gets NOTFOUND. Peers that explicitly
request cmpctblocks via getdata are told we don't have the block, even
when we do.

**File:** `app/Main.hs:1973-2004` (no InvCompactBlock case).

**Core ref:** `bitcoin-core/src/net_processing.cpp` MSG_CMPCT_BLOCK
handling in ProcessGetBlockData / SendMessages.

**Impact:** receiver-side capability gap; no consensus risk. Compounds
with W126 BUG-10 (no ANNOUNCE-side path): haskoin neither announces
nor serves-on-request compact blocks, fully receive-only with no
in-band way for peers to ask for cmpctblock from us.

---

## Cross-wave patterns confirmed

| Pattern | Instance(s) this wave |
|---------|----------------------|
| **two-pipeline guard 16th distinct extension** | BUG-7 `computeWtxid` duplicated across Network.hs and Crypto.hs; first haskoin BIP-152 instance of the pattern |
| **dead-helper-at-call-site 35th+ distinct instance** | BUG-21 `recordBlockReceived/Requested/isBlockStalled` (Sync.hs has its own pipeline); 4 dead helpers across haskoin's BIP-152 surface (this + W126 BUG-11/-12 + BUG-7) |
| **non-exhaustive ADT → runtime crash variant** | BUG-4 — first haskoin instance of "SAME constructor appears TWICE in one case-of" (dead-arm-of-same-constructor); related to (but inverse of) the standard non-exhaustive pattern |
| **comment-as-confession 13th-14th** | BUG-7 doc-comment "New code should prefer the typed Haskoin.Crypto.computeWtxid" admits the duplicate-pipeline is the local one being used; BUG-21 commented constant `blockStallTimeoutCompact = 2` misleads operators about an unenforced value |
| **ban-vs-discourage carry-forward from W148 BUG-13** | BUG-13 / BUG-14 — cmpctblock-specific echo: `misbehaving` primitive bans where Core only discourages, and cmpctblock failures are EXEMPT from punishment in Core when `via_compact_block=true`. This is the SAME `misbehaving` primitive that W148 BUG-13 flagged for MBlock-on-reorg; W156 confirms the divergence spans BIP-152 too |
| **wiring-look-but-no-wire (W138 archetype)** | BUG-21 `recordBlockReceived` is defined + exported + has tests, but never called — same shape as W138 ChainstateManager dead-method pattern |
| **frozen-constant-degrade (W126 BUG-9 carry-forward)** | `CMPCTBLOCKS_VERSION=2` still hardcoded at 3 sites (Network.hs:2428, 6480, BUG-1 / future version filter) |
| **MISSING ANNOUNCE-side, PRESENT RECEIVER-side asymmetry (W126 carry-forward)** | Unchanged — haskoin remains receive-only on BIP-152 |
| **decoder accepts superset-of-encoder (W142 BUG-8 archetype)** | BUG-10/-17/-18 — wire decoders for PrefilledTx/BlockTxn/GetBlockTxn accept varints with no bound, allowing peer inputs that the encoder would never produce |
| **comparator-mismatch / sign-mismatch on adjacent gates** | BUG-12 — `currentTipHeight - blockH` underflow handling vs `depth > maxCmpctBlockDepth` comparison; the future-height case silently falls through |

---

## Summary

**Bug count:** 22 (BUG-1 through BUG-22) + 12 W126 carry-forwards
(all unchanged) = 34 catalogued findings on the BIP-152 surface.

**W156-only severity distribution (22 new bugs):**
- **P0-CDIV:** 1 (BUG-14)
- **P0:** 2 (BUG-4 dead-arm, BUG-13 ban-vs-discourage cmpct echo)
- **P1:** 8 (BUG-1, BUG-2, BUG-7, BUG-9, BUG-11, BUG-15, BUG-17, BUG-18)
- **P2:** 10 (BUG-3, BUG-5, BUG-6, BUG-8, BUG-10, BUG-16, BUG-19, BUG-20, BUG-21, BUG-22)
- **P3:** 1 (BUG-12)

**Top three findings:**

1. **BUG-13 + BUG-14 (P0 / P0-CDIV) — cmpctblock-specific echo of W148
   BUG-13 ban-vs-discourage divergence**. haskoin's `misbehaving`
   primitive bans peers where Core's `Misbehaving` only sets the
   `m_should_discourage` flag. `InvalidCompactBlock` (score=100)
   triggers a full ban on every reconstruction failure (BUG-13), AND
   the recursive submission of a reconstructed block as `MBlock` then
   bans the cmpctblock announcer for any post-reconstruction validation
   failure (BUG-14) — but Core's `MaybePunishNodeForBlock` with
   `via_compact_block=true` is EXEMPT from punishment for both
   `BLOCK_CONSENSUS` and `BLOCK_MUTATED`. Honest peer who races on
   mempool state or relays a cmpctblock for a block we haven't validated
   yet → banned for 24h.

2. **BUG-4 (P0 dead-arm) — two `MSendCmpct` arms in same `case msg of`**.
   `app/Main.hs:2185` is the active arm (log-only stub), `app/Main.hs:2353`
   is `MSendCmpct _ -> return ()` — Haskell first-match-wins means the
   second arm is **completely unreachable**. GHC `-Woverlapping-patterns`
   emits the warning at every compile. The arm-itself is functionally
   inert (returns `()`) but the structural bug is a smoking gun: a
   future developer adding state-tracking to the SENDCMPCT handler may
   edit the dead arm and ship a no-op fix. First haskoin instance of
   "SAME constructor TWICE in one case-of".

3. **BUG-15 + BUG-17 + BUG-18 (P1 wire-DoS amplification cluster)**.
   The `MGetBlockTxn` handler at `Main.hs:2288` is `O(n²)` due to
   list-indexed `!!` and per-iteration `length`; the `BlockTxn` and
   `GetBlockTxn` decoders accept unbounded varint counts (BUG-17/-18)
   — together a single 70-KB getblocktxn message can drive haskoin
   into hours of CPU. Core's vector-indexed `SendBlockTransactions`
   is `O(k)` and the wire bounds are enforced by stream `MAX_SIZE`.

**Fleet pattern crystallizations:**

- **"misbehaving primitive too aggressive"** — the haskoin
  `misbehaving` function bans-not-discourages, AND the BIP-152 path
  is the 2nd P2P surface (after W148 BUG-13's MBlock reorgs) where
  this single primitive causes Core-divergent behaviour. A single fix
  to `misbehaving` (split ban vs discourage; treat
  `InvalidCompactBlock` as discourage-only) closes BUG-13/-14 in
  W156 AND W148 BUG-13.

- **"4 dead helpers in one subsystem"** — haskoin's BIP-152 module
  now has the densest dead-helper concentration in haskoin: W126
  BUG-11 (HighBandwidthState ops) + W126 BUG-12 (createCompactBlock)
  + W156 BUG-7 (duplicate computeWtxid) + W156 BUG-21
  (recordBlockReceived/Requested/isBlockStalled). 9-10 distinct
  exported functions, ZERO production callers. Cleanup-or-wire-or-delete
  decision overdue.

- **"recursive MBlock submission carries no `via_compact_block`
  context"** — the recursive `syncMessageHandler ... (MBlock block)`
  call in the BIP-152 reconstruction path strips ALL provenance
  information. The receiving MBlock handler cannot distinguish a
  peer-sent full block from a cmpctblock-reconstructed block, so any
  validation failure is attributed equally. Architectural fix
  candidate: add a `viaCompactBlock :: Bool` parameter to
  `syncMessageHandler` (or thread a `BlockSource` ADT through).

- **"wire decoders accept superset of encoder"** — BUG-10/-17/-18 add
  three more instances of the W142 BUG-8 archetype to the haskoin
  ledger.

**Recommended fix-wave decomposition (out of scope for W156):**

- **FIX-A (P0 ban-vs-discourage)**: split `misbehaving` into
  `discourage` (Core's `Misbehaving`) and `ban` (rare, score≥100
  AND consensus-invalid). Reclassify `InvalidCompactBlock` and
  `InvalidBlock` to score `discouragement-only`. Closes BUG-13/-14
  AND W148 BUG-13.
- **FIX-B (P0 dead arm)**: delete `app/Main.hs:2353`
  `MSendCmpct _ -> return ()`. One-line fix. Closes BUG-4.
- **FIX-C (P1 wire-DoS bounds)**: add `MAX_BLOCKTXN_COUNT ≤
  MAX_BLOCK_WEIGHT/MIN_SERIALIZABLE_TX_WEIGHT = 100000` bound to
  `BlockTxn.get` and `GetBlockTxn.get`. Closes BUG-17/-18.
- **FIX-D (P1 O(n²))**: convert `blockTxns block` from `[Tx]` to
  `Vector Tx` (or at least precompute `length` once and use an
  IntMap for index lookup). Closes BUG-15. Cross-fleet relevance:
  any other haskoin handler doing `!!` on `[Tx]`.
- **FIX-E (P1 dupe-accounting)**: gate the `hits - 1` decrement on
  `Map.lookup idx avail == Just (Just _)` (slot was non-null before
  this dupe). Closes BUG-9.
- **FIX-F (P1 wtxid dedup)**: import `Haskoin.Crypto.computeWtxid`
  in `Haskoin.Network`, delete the local copy, change callers
  (Network.hs:6512, 6653) to use the typed version. Closes BUG-7.
- **FIX-G (P2 cmpct ANNOUNCE-side)**: wire `createCompactBlock` +
  `HighBandwidthState` into `announceTip` + the post-verack handshake.
  Closes W126 BUG-10/-11/-12 (fleet announce-side gap).
- **FIX-H (P2 in-flight reset)**: add a `Sync.markBlockReceived`
  call after MCmpctBlock-reconstruction → MBlock submission. Closes
  BUG-20.

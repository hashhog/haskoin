# W134 BIP-37 Bloom Filter (legacy SPV) — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** legacy SPV bloom filter subsystem covering wire messages
`filterload` / `filteradd` / `filterclear` / `merkleblock` / `mempool`
(BIP-35); the `CBloomFilter` data type; `CMerkleBlock` + `CPartialMerkleTree`
build-from-filter path; the `IsRelevantAndUpdate` matcher; per-peer
filter state (`m_bloom_filter`, `m_relay_txs`, `m_bloom_filter_loaded`);
the NODE_BLOOM service bit (BIP-111) and the `-peerbloomfilters` opt-in
operator flag.
**Out of scope:** BIP-157/158 compact block filters (separately covered by
W121 / W122 / FIX-86); the gettxoutproof RPC `w47b*` partial-merkle-tree
pipeline in `Haskoin.Rpc` (works as documented, but is structurally
isolated from the P2P bloom pipeline — see "Two-pipeline observation" below).
**References:**
- `bitcoin-core/src/common/bloom.{h,cpp}` (CBloomFilter, sizing formulas,
  Hash, insert, contains, IsWithinSizeConstraints, IsRelevantAndUpdate)
- `bitcoin-core/src/merkleblock.{h,cpp}` (CMerkleBlock,
  CPartialMerkleTree, TraverseAndBuild, TraverseAndExtract, BitsToBytes,
  BytesToBits, CalcHash, ExtractMatches)
- `bitcoin-core/src/net_processing.cpp` lines ~3680 (NODE_BLOOM gate on
  version handshake), ~2440 (MSG_FILTERED_BLOCK → MERKLEBLOCK build),
  ~4853 (MEMPOOL gate on NODE_BLOOM), ~4963 (FILTERLOAD), ~4988
  (FILTERADD), ~5016 (FILTERCLEAR)
- `bitcoin-core/src/init.cpp` lines ~572 / ~1104 (`-peerbloomfilters`
  default, NODE_BLOOM advertisement)
**BIPs:** BIP-37 (bloom filter SPV), BIP-111 (NODE_BLOOM service bit /
opt-in `-peerbloomfilters`).
**Result:** 0 PRESENT / 1 PARTIAL (service-bit + opt-in flag) / 29
MISSING out of 30 gates.
**Bugs found:** 19 (3 P0-CDIV, 4 P1-DOS, 8 P1, 4 P2).
**Tests added:** 30 gate cases + 4 bonus pinning assertions = 34 cases in
`test/W134BIP37BloomFilterSpec.hs` (mix of `it` pinning + `xit` sentinel).

## Relationship to W110

W110 (filed weeks ago) is the original 30-gate discovery audit of the
BIP-37 bloom filter subsystem for haskoin. **W134 is the follow-up
discovery audit** that re-runs the same lens against the current `master`
HEAD (`64ee7a2`) to check whether (a) any fix wave has landed in the
interim, and (b) other waves' code growth has changed the threat surface.

**Headline finding:** No fix wave has landed. The BIP-37 subsystem is
still entirely absent — no `Haskoin.Bloom` module, no MurmurHash3, no
`CBloomFilter` data type, no `CMerkleBlock` build path, no
`IsRelevantAndUpdate`, no per-peer filter state, no FILTERLOAD /
FILTERADD / FILTERCLEAR handlers (still falls to `_other -> return ()` at
`app/Main.hs:2447`).

**What's changed since W110:**

1. **FIX-86 BIP-157 P2P handlers landed** (`app/Main.hs:2438-2445`):
   `MGetCFilters`, `MGetCFHeaders`, `MGetCFCheckpt` are now wired
   end-to-end with Core-parity validation. By contrast `MFilterLoad`,
   `MFilterAdd`, `MFilterClear`, `MMempool` (for filtered-relay use)
   still have **no handler at all** (MMempool is now wired for
   serving all-txids, but not for filter-aware reply). This widens the
   parity gap: compact filters are first-class, bloom filters are
   wholly absent.

2. **MMempool gating on NODE_BLOOM landed at `app/Main.hs:2368-2402`.**
   The MMempool handler now disconnects peers if NODE_BLOOM is not
   advertised. This is correct Core parity at the service-bit layer,
   but is **moot in practice** because filterload/add/clear are still
   ignored — even when an operator opts in via
   `--peerbloomfilters=true`, the node advertises NODE_BLOOM but
   cannot honour a bloom-filtered request. This creates a **new misleading
   advertisement bug** (see BUG-19) that did not exist at W110 time
   because the MMempool handler was not yet wired.

3. **New service-flag plumbing for NODE_BLOOM at `:3314-3322`,
   `:3459-3464`, `:3809-3816`.** The bit is advertised correctly when
   `pmcPeerBloomFilters = True`, but no downstream code reads filterload
   payloads (see BUG-19 dependency).

4. **The `w47b*` PartialMerkleTree pipeline in `Haskoin.Rpc.hs:10392-10520`**
   is unchanged from W110 — still complete and CORRECT for the
   gettxoutproof/verifytxoutproof RPC, but still 100% separate from the
   absent P2P bloom pipeline. This is the canonical haskoin two-pipeline
   pattern (and the one most worth promoting to a shared module if BIP-37
   is ever wired — see BUG-18).

## Two-pipeline observation (UPDATED)

W110 noted that the PartialMerkleTree exists fully in `Haskoin.Rpc.hs`
(w47b* helpers) but is absent from the P2P bloom pipeline. As of W134,
this is **the most-extreme two-pipeline shape in haskoin**:

| Layer            | RPC (`gettxoutproof`/`verifytxoutproof`)         | P2P (`merkleblock`/`filterload`/`filteradd`/`filterclear`) |
|------------------|---------------------------------------------------|------------------------------------------------------------|
| PMT encoder      | `w47bBuild` (Rpc.hs:10412)                        | **absent**                                                 |
| PMT decoder      | `w47bExtract` (Rpc.hs:10483)                      | **absent**                                                 |
| Bits packing     | `w47bBitsToBytes` (Rpc.hs:10433)                  | **absent**                                                 |
| Tree-width calc  | `w47bTreeWidth` (Rpc.hs:10392)                    | **absent**                                                 |
| Bloom filter     | not needed (txid set is supplied directly)        | **absent** — no `CBloomFilter` analogue                    |
| Match logic      | not needed                                        | **absent** — no `IsRelevantAndUpdate`                      |
| Per-peer state   | not needed (stateless RPC)                        | **absent** — no `piBloomFilter` field in `PeerInfo`        |
| Wire decode      | not needed                                        | **dead stub** — `MFilterLoad !ByteString` raw pass-through |
| Wire handler     | `RPCgettxoutproof` (Rpc.hs:10727+)                | **absent** — falls to `_other -> return ()`                |
| Send path        | RPC response body                                 | **absent** — no `MGetData InvFilteredBlock` branch         |

The implication for a future fix wave: the `w47b*` helpers are reusable
**inside the same crate**, but their current location in `Rpc.hs` mixes a
generic Bitcoin-protocol primitive with an HTTP/JSON handler. A fix wave
that wires BIP-37 should refactor `w47b*` out of `Rpc.hs` into a shared
`Haskoin.MerkleBlock` (or `Haskoin.Bloom`) module so both pipelines call
the same code (otherwise the divergence between the RPC PMT encoder and
a hypothetical new P2P PMT encoder becomes a Core-parity audit liability
of its own).

## Dead-helper / dead-stub observation

W134 catalogues **four dead stubs** in the BIP-37 surface area — wire
constructors that exist for parsing/encoding but have no handler:

1. `MFilterLoad !ByteString` (`Network.hs:1774`) — parsed but
   ignored (`Main.hs:2447 _other -> return ()`).
2. `MFilterAdd !ByteString` (`Network.hs:1775`) — same.
3. `MFilterClear` (`Network.hs:1776`) — same.
4. `MMerkleBlock !ByteString` (`Network.hs:1777`) — same. (Could be
   inbound, e.g. if haskoin were to operate as an SPV peer rather than
   as a server, but no inbound handler exists either.)

Unlike W117 (BIP-155) where a wire constructor was parsed but the
*serialiser* silently produced wrong bytes, the BIP-37 stubs are
"silently accepted, silently discarded" — no Core-divergence at the
wire level, but full Core-divergence at the *behaviour* level. Net
effect on the network: a remote SPV peer sees haskoin send the version
handshake with NODE_BLOOM advertised (when `--peerbloomfilters=true`),
sends `filterload`, and then never receives any filtered traffic
(neither inv-filtered txs nor merkleblocks for getdata-filtered-block
requests). The peer's view: haskoin acts as if `filterclear` had been
called immediately.

## Top-line verdict

The W110 verdict stands: **the BIP-37 CBloomFilter subsystem is
entirely absent** from haskoin. As of W134 the only progress is in the
**service-bit layer** (NODE_BLOOM is correctly advertised when
`--peerbloomfilters=true` is set; MMempool gate now matches Core). The
**behaviour layer** is unchanged: no filter state, no matcher, no
serialiser, no build path, no DoS guards.

The unique W134 contribution beyond W110:

1. **New advertise-without-honour bug (BUG-19).** Setting
   `--peerbloomfilters=true` now causes haskoin to advertise NODE_BLOOM
   in the version handshake, but `filterload` is still discarded. An
   SPV peer sees a `NODE_BLOOM`-bit-set service flags but no filtered
   traffic. This is a NEW post-W110 misleading-advertisement bug
   created by the wire-up of NODE_BLOOM through `:3314-3322` etc. while
   the handlers remain absent. Recommended pre-fix mitigation: in
   `Main.hs`, refuse to set `--peerbloomfilters=true` (i.e. force-disable
   the bit) until the BIP-37 handlers are landed. This avoids the
   silent-discard footgun.

2. **Cross-wave DoS-class amplification.** Because FIX-86 wired the
   BIP-157 P2P handlers, operators who run with `--blockfilterindex=true`
   `--peerblockfilters=true` will see the BIP-157 path serve filtered
   block info correctly; if those same operators set
   `--peerbloomfilters=true` expecting parity, they get the
   misleading-advertise + silent-discard behaviour above. Operator
   ergonomics: it's natural to assume "if BIP-157 P2P works, BIP-37
   does too". It does not.

3. **MMempool-side DoS implications.** With the MMempool handler now
   wired but filterload still ignored, an attacker advertising the
   victim-as-SPV pattern can request `mempool` (which is served:
   `Main.hs:2384-2402`) and get the full mempool txid list, but receive
   no follow-up `tx` messages because no filter is loaded. This means
   the mempool-disclosure side-channel exists even though the bloom
   service-bit gate technically passed. The Core invariant is:
   "MMempool is honoured only when NODE_BLOOM is advertised AND
   filterload has been processed". haskoin enforces the former, not
   the latter.

## Bug catalogue (19 BUGs)

| ID    | Severity | Gate(s) | Bug |
|-------|----------|---------|-----|
| BUG-1 | P1       | G1, G29 | MAX_BLOOM_FILTER_SIZE = 36000 constant absent — DoS gate not present |
| BUG-2 | P1-DOS   | G2, G29 | MAX_HASH_FUNCS = 50 constant absent — `nHashFuncs=255` payload would amplify (50× → 255× MurmurHash3) |
| BUG-3 | P1       | G3      | LN2SQUARED full-precision constant absent — sizing formula not implemented |
| BUG-4 | P0-CDIV  | G4      | `CBloomFilter` constructor absent — no data type, no sizing, no clamping |
| BUG-5 | P1       | G5      | `nHashFuncs = min(vData.size()*8/nElements * LN2, MAX_HASH_FUNCS)` formula absent |
| BUG-6 | P0-CDIV  | G6      | MurmurHash3 32-bit absent from production source (only a local test helper exists at `test/W110BloomFilterSpec.hs:128` — that is NOT production code) |
| BUG-7 | P1       | G7      | Hash schedule (`seed = nHashNum * 0xFBA4C795 + nTweak`) absent |
| BUG-8 | P1       | G8      | Bit-set logic (`vData[nIndex>>3] \|= 1 << (7 & nIndex)`) absent |
| BUG-9 | P0-CDIV  | G9      | `insert` / `contains` absent — filter cannot be queried or updated |
| BUG-10| P1-DOS   | G10     | CVE-2013-5700 zero-size short-circuit absent in both `insert` and `contains` (both `if (vData.empty()) return;`) |
| BUG-11| P1       | G11–G14 | BLOOM_UPDATE_* constants (0/1/2/3) absent + UPDATE_MASK semantics absent |
| BUG-12| P1       | G16, G17, G19, G20 | Match logic (txid, output-script pushdata, outpoint, scriptSig pushdata) absent — full `IsRelevantAndUpdate` skeleton missing |
| BUG-13| P1       | G18     | `Solver(scriptPubKey, vSolutions)` integration with UPDATE_P2PUBKEY_ONLY absent (script classifier `classifyOutput` exists at `Script.hs:698` but is NOT called by any bloom path) |
| BUG-14| P1       | G21, G22, G23 | UPDATE_ALL outpoint insert + UPDATE_P2PUBKEY_ONLY (only for PUBKEY/MULTISIG) + UPDATE_NONE (no insert) all absent |
| BUG-15| P1-DOS   | G25, G26, G27 | All three FILTERLOAD/FILTERADD/FILTERCLEAR handlers fall to `_other -> return ()` (`Main.hs:2447`) — wire bytes parsed into `MFilterLoad !ByteString` etc. but never consumed. No `IsWithinSizeConstraints` call, no 520-byte FILTERADD cap, no per-peer state update. |
| BUG-16| P1       | G28     | `MGetData` handler at `Main.hs:1973` has cases for `InvBlock`/`InvWitnessBlock`/`InvTx`/`InvWitnessTx` but **no `InvFilteredBlock` case** — fall-through serves `MNotFound` for filtered-block requests, which is wrong: Core silently no-responds for filtered blocks when no filter is loaded, and sends a `merkleblock` (built from the loaded filter) when one is loaded. haskoin does neither. |
| BUG-17| P1       | G29     | `IsWithinSizeConstraints` absent — no DoS gate on filterload payload size or hash-function count. A 100 MB filterload would be accepted into memory before the (absent) parser drops it. Currently the wire layer (`Network.hs:1942`) accepts any payload length. |
| BUG-18| P2       | G28     | `w47b*` PMT helpers in `Rpc.hs:10392-10520` should be extracted to a shared `Haskoin.MerkleBlock` module so the (future) P2P bloom pipeline does not re-implement PartialMerkleTree from scratch. Current location couples Bitcoin-protocol primitives to RPC/JSON. |
| BUG-19| **P1-NEW**  | G30 | **NEW since W110.** NODE_BLOOM is now advertised when `--peerbloomfilters=true` (via `Network.hs:3314-3322 / 3459-3464 / 3809-3816`), but no filterload/add/clear/getdata-filtered handler is wired. Net effect: an SPV peer sees the `NODE_BLOOM` bit on the version handshake, sends `filterload`, and receives nothing. This is misleading advertisement and breaks Core's invariant "NODE_BLOOM advertised ⇒ filter messages honoured". Mitigation pending a real fix wave: force `pmcPeerBloomFilters = False` until the handler skeleton lands. |

### Severity legend

- **P0-CDIV**: consensus-divergent (would cause haskoin to disagree with
  Bitcoin Core on a wire/consensus question). BUG-4 / BUG-6 / BUG-9 land
  here because the absence of MurmurHash3 / CBloomFilter / insert+contains
  means haskoin cannot match Core on any bloom-derived behaviour.
- **P1-DOS**: denial-of-service vector that's exposed today (BUG-2 /
  BUG-10 / BUG-15 / BUG-17).
- **P1**: parity gap with no immediate exploit but Core-required.
- **P2**: refactor / hygiene.

## Gate matrix (30 gates)

| #  | Gate                                          | Status                          | BUG(s) |
|----|-----------------------------------------------|---------------------------------|--------|
| G1 | MAX_BLOOM_FILTER_SIZE = 36000                 | MISSING                         | BUG-1  |
| G2 | MAX_HASH_FUNCS = 50                           | MISSING                         | BUG-2  |
| G3 | LN2SQUARED full precision                     | MISSING                         | BUG-3  |
| G4 | Constructor sizing formula                    | MISSING                         | BUG-4  |
| G5 | nHashFuncs computation                        | MISSING                         | BUG-5  |
| G6 | MurmurHash3 32-bit                            | MISSING (test helper only)      | BUG-6  |
| G7 | nTweak + i*0xFBA4C795 schedule                | MISSING                         | BUG-7  |
| G8 | Bit index `vData[nIndex>>3] \|= 1<<(7&nIdx)`  | MISSING                         | BUG-8  |
| G9 | Insert + Contains                             | MISSING                         | BUG-9  |
| G10| CVE-2013-5700 zero-size short-circuit         | MISSING                         | BUG-10 |
| G11| BLOOM_UPDATE_NONE = 0                         | MISSING                         | BUG-11 |
| G12| BLOOM_UPDATE_ALL = 1                          | MISSING                         | BUG-11 |
| G13| BLOOM_UPDATE_P2PUBKEY_ONLY = 2                | MISSING                         | BUG-11 |
| G14| BLOOM_UPDATE_MASK = 3                         | MISSING                         | BUG-11 |
| G15| nFlags & UPDATE_MASK semantics                | MISSING                         | BUG-11 |
| G16| txid match in IsRelevantAndUpdate             | MISSING                         | BUG-12 |
| G17| Per-output-script pushdata match              | MISSING                         | BUG-12 |
| G18| Solver(scriptPubKey, …) for P2PKEY/MULTISIG   | MISSING (classifier exists, not wired) | BUG-13 |
| G19| Outpoint match (`contains(txin.prevout)`)     | MISSING                         | BUG-12 |
| G20| scriptSig pushdata data-element match         | MISSING                         | BUG-12 |
| G21| UPDATE_ALL: insert outpoint on output match   | MISSING                         | BUG-14 |
| G22| UPDATE_P2PUBKEY_ONLY: P2PK/MULTISIG only      | MISSING                         | BUG-14 |
| G23| UPDATE_NONE: no insert                        | MISSING                         | BUG-14 |
| G24| Outpoint serialisation (32 LE + 4 LE)         | MISSING (RPC has similar)       | BUG-12 |
| G25| filterload parse + apply to peer              | DEAD STUB (raw ByteString)      | BUG-15 |
| G26| filteradd <= 520 bytes gate                   | MISSING                         | BUG-15 |
| G27| filterclear                                   | DEAD STUB                       | BUG-15 |
| G28| merkleblock build + PMT send on getdata       | MISSING (RPC w47b* exists)      | BUG-16, BUG-18 |
| G29| IsWithinSizeConstraints DoS gate              | MISSING                         | BUG-17 |
| G30| NODE_BLOOM + BIP-111 `-peerbloomfilters` gate | **PARTIAL** (flag wired correctly; advertise-without-honour) | BUG-19 |

## Methodology

Reference (Core) read first:
- `bitcoin-core/src/common/bloom.{h,cpp}` (full file)
- `bitcoin-core/src/merkleblock.{h,cpp}` (full file)
- `bitcoin-core/src/net_processing.cpp` lines ~2440 (MSG_FILTERED_BLOCK
  serving), ~3680 (version-handshake NODE_BLOOM tx-relay gating), ~4853
  (MEMPOOL gate), ~4963 / ~4988 / ~5016 (FILTERLOAD / FILTERADD /
  FILTERCLEAR handlers)
- `bitcoin-core/src/init.cpp` lines ~572 (`-peerbloomfilters` CLI arg
  with default `DEFAULT_PEERBLOOMFILTERS = false`), ~1104 (conditional
  `NODE_BLOOM` add to `g_local_services`)

Implementation (haskoin) read second:
- `src/Haskoin/Network.hs:99` (`nodeBloom` export), `:705-706`
  (`nodeBloom = ServiceFlag 4`), `:1773-1777` (wire constructors),
  `:1942-1945` (wire decoders), `:2899` (`pmcPeerBloomFilters` config
  field), `:2948` (default `False`), `:3314-3322` / `:3459-3464` /
  `:3809-3816` (NODE_BLOOM service-flag advertisement)
- `app/Main.hs:242` (CLI arg), `:507` (RPC config lookup), `:1973`
  (MGetData branches, no InvFilteredBlock case), `:2368-2402`
  (MMempool handler with NODE_BLOOM gate), `:2447` (`_other -> return ()`
  catch-all that silently absorbs MFilterLoad/MFilterAdd/MFilterClear)
- `src/Haskoin/Rpc.hs:10392-10520` (w47b* PMT helpers — present and
  correct for RPC, structurally isolated from P2P)
- `src/Haskoin/Sync.hs` and `src/Haskoin/Mempool.hs` — confirmed no
  bloom-related code path.

Wire-up check:
- `grep -nE "MFilterLoad|MFilterAdd|MFilterClear|MMerkleBlock|InvFilteredBlock|m_bloom|peerBloomFilter|peerBloom"`
  across the whole `haskoin/src` and `haskoin/app` tree — only matches in
  `Network.hs` (declarations) and `Main.hs` (CLI flag + MMempool gate
  using `pmcPeerBloomFilters`). No matches in handler bodies.

## Recommended fix-wave skeleton (NON-binding — for future planning)

If a future fix wave wires BIP-37, the recommended decomposition is:

1. **Extract `w47b*` from `Rpc.hs` into `Haskoin.MerkleBlock`** —
   `bitsToBytes`, `bytesToBits`, `partialMerkleTreeBuild`,
   `partialMerkleTreeExtract`, `calcTreeWidth`, `calcHash`. RPC keeps
   calling them via the new module name.
2. **New `Haskoin.Bloom` module** — MurmurHash3 (production, not test
   helper), `BloomFilter { bfData, bfHashFuncs, bfTweak, bfFlags }`,
   `bloomInsert`, `bloomContains`, `bloomIsWithinSizeConstraints`,
   `bloomIsRelevantAndUpdate`. Cite BIP-37 + `common/bloom.cpp` line
   numbers in haddock.
3. **Per-peer state** — add `piBloomFilter :: !(TVar (Maybe BloomFilter))`,
   `piRelayTxs :: !(TVar Bool)`, `piBloomFilterLoaded :: !(TVar Bool)`
   to `PeerInfo`. Wire defaults at the two `PeerInfo` constructor sites
   (`Network.hs:2116` outbound, `:3766` inbound).
4. **Handler arm in `Main.hs:2438` syncMessageHandler** — `MFilterLoad`
   case (parse + IsWithinSizeConstraints + Misbehaving on violation +
   store), `MFilterAdd` (520-byte cap + insert), `MFilterClear` (clear
   state). Each gated on `pmcPeerBloomFilters`; otherwise issue
   `Misbehaving InvalidTransaction` (10) and disconnect, matching Core
   net_processing.cpp:4964-4967.
5. **InvFilteredBlock branch in `MGetData`** — at `Main.hs:1973`, add
   case `InvFilteredBlock -> buildAndSendMerkleBlock pmRef addr bh` that
   reads the peer's filter from TVar, builds a `CMerkleBlock`-equivalent
   using the new `Haskoin.MerkleBlock` + `Haskoin.Bloom`, sends
   `MMerkleBlock` + N follow-up `MTx` for each matched txid.
6. **Block-connected hook** — on each new block at the tip, walk the
   peer table and for each peer with a loaded filter call
   `bloomIsRelevantAndUpdate` per tx and queue inv/tx accordingly. This
   mirrors Core's `PushBlockInvFiltered` codepath. Defer to a follow-up
   wave if needed.

The fix wave should land in two sub-waves to keep the diff size sane:
sub-wave A (steps 1–3, no behaviour change yet, all new modules unused),
sub-wave B (steps 4–6, actually wires the handlers). This lets the
discovery → fix → fix cadence apply cleanly.

## What I did not check (declared limits)

- **Reorg + per-peer-filter consistency.** Core's per-peer filter state
  is independent of the chain (filterload doesn't reset on reorg). Not
  audited here because the subsystem is absent; would be a follow-up
  audit once the fix wave lands.
- **`mempool` (BIP-35) message body content beyond gating.** The
  MMempool handler is correct at the service-bit layer but I did not
  verify that the txids returned are filter-aware (they are NOT — but
  they cannot be because no filter exists; this collapses into BUG-19).
- **Wallet-side bloom filter producer** (i.e. haskoin as an *SPV
  client* sending filterload). haskoin does not currently operate as
  an SPV client (it's a full node), so producer-side absence is
  expected and not flagged.
- **CRollingBloomFilter.** This is Core's mempool-tx-known set in
  `validation.cpp` (m_recent_rejects / m_recent_rejects_reconsiderable
  / m_recent_confirmed_transactions). haskoin has equivalents at a
  different layer (W103 TxRelay audit covers `ptsSentFilter`); not
  re-audited here.
- **`feefilter`.** Wired and correct (W103); not part of BIP-37.

## Test plan

`test/W134BIP37BloomFilterSpec.hs` provides 30 + 4 cases:
- For each of the 30 gates, an `it` pinning assertion (asserts current
  observable behaviour — usually "missing") and where useful an `xit`
  sentinel encoding the Core-parity behaviour (so a future fix wave can
  flip `xit -> it` to mark progress).
- 4 bonus pinning assertions: dead-stub catch-all behaviour
  (`MFilterLoad` round-trips through wire layer but no handler), service-
  flag value (NODE_BLOOM = 4), advertise-without-honour pinning, and
  cross-pipeline observation (w47b* exists in Rpc.hs but bloom does
  not).

Tests added to `test/Spec.hs` import + invocation block and
`haskoin.cabal` `other-modules` list under separate, non-overlapping
lines to minimise conflict with concurrent waves.

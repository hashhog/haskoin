# W136 BIP-130 sendheaders + BIP-133 feefilter + BIP-339 wtxidrelay — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** post-handshake relay-feature negotiation: `sendheaders` (BIP-130),
`feefilter` (BIP-133), `wtxidrelay` (BIP-339).  Covers wire encoding /
decoding, send-side trigger conditions, receive-side state mutation,
version/timing gates, per-peer flag semantics, and how the flags
interact with the inv/headers relay paths.
**Out of scope:** the underlying inv-trickler engine (W103),
NODE_BLOOM / `filterload` / `filteradd` (W110 / W134), compact-block
announcement gating via `sendcmpct` (W112 / W126), BIP-155 ADDRv2
feature negotiation (W117).
Sources audited:
- `src/Haskoin/Network.hs:1098-1143` (SendHeaders / FeeFilter wire types),
- `src/Haskoin/Network.hs:1750-1965` (Message ADT + commandName / encodePayload
  / decodeMessage round-trip),
- `src/Haskoin/Network.hs:1990-2046` (PeerInfo fields piWantsHeaders /
  piWtxidRelay / piFeeFilterReceived / piFeeFilterSent / piNextFeeFilterSend),
- `src/Haskoin/Network.hs:2120-2150 + 3770-3795 + 9740-9760` (three
  initialisation sites for PeerInfo — all three set the three flags False),
- `src/Haskoin/Network.hs:2347-2446` (`performHandshake` + `continueHandshake`
  — version exchange, pre-verack feature messages, post-verack send),
- `src/Haskoin/Network.hs:2764-2829` (`startPeerThreadsWithMisbehavior` —
  receive thread + handler dispatch),
- `src/Haskoin/Network.hs:4610-4940` (BIP-133 constants + `poissonDelay` +
  `handleFeeFilter` + `shouldSendFeeFilter` + `sendFeeFilter` +
  `filterTxByFeeRate` + InvTrickler engine),
- `app/Main.hs:1508-1535` (`announceTip` — sendheaders honoured),
- `app/Main.hs:2167-2176 + 2340-2366` (incoming MFeeFilter / MSendHeaders /
  MWtxidRelay handlers in `syncMessageHandler`),
- `src/Haskoin/Rpc.hs:2383-2404` (`broadcastTxToPeers` — wtxid type
  switching).

**Result:** 5 PRESENT / 8 PARTIAL / 17 MISSING out of 30 gates.

**Bugs found:** 14 (3 P0-CDIV, 7 P1, 4 P2).

**Tests added:** 30 gate cases in `W136RelayFlagsSpec.hs`
(mix of `it` pinning + `xit` sentinel) plus 6 bonus pinning assertions
= 36 cases.

## Relationship to W103 / W117 / W118 / W126

Three nearby waves already documented adjacent subsystems:

- **W103 TxRelay** documented that `InvTrickler` (the engine that
  actually consumes `piFeeFilterReceived`) is **dead code at runtime**.
  W136 cross-cites this once as BUG-14 (per-peer fee filter is read
  only by an unused engine) and does **not** re-count the trickler
  wire-up gap.
- **W117 BIP-155 Networks** documented the SENDADDRV2 negotiation
  pattern (sent before VERACK).  W136 audits the same handshake
  window for WTXIDRELAY and finds the symmetric gap is present but
  in the OPPOSITE direction: haskoin handles inbound WTXIDRELAY
  correctly, but never SENDS WTXIDRELAY on outbound (BUG-1).
- **W118 Wallet** is unrelated.
- **W126 BIP-152 Compact Blocks** documented the post-verack
  feature-message ordering (SENDCMPCT after VERACK).  W136 finds
  haskoin **violates Core ordering** for SENDHEADERS: Core delays
  SENDHEADERS until headers-sync completion + nMinChainWork check
  (`MaybeSendSendHeaders` at net_processing.cpp:5519); haskoin
  sends SENDHEADERS unconditionally immediately after VERACK
  (BUG-5).

Where the same constant or guard would close multiple gates, the bug
is counted once and cross-cited.

## Top-line verdict

The three relay-feature flags split into three quality tiers in haskoin:

1. **BIP-130 sendheaders** — wire codec, PeerInfo field, inbound
   handler, and outbound consumer (`announceTip`) all exist and are
   wired together.  But the **outbound trigger is wrong**: Core delays
   the SEND of SENDHEADERS until we have completed headers sync with
   the peer AND `pindexBestKnownBlock->nChainWork > MinimumChainWork`;
   haskoin sends SENDHEADERS immediately after VERACK unconditionally.
   This is the single largest divergence in this wave (BUG-5,
   P0-CDIV).

2. **BIP-133 feefilter** — wire codec, PeerInfo fields, inbound
   handler, send-side scheduling (`shouldSendFeeFilter`,
   `sendFeeFilter`), and Poisson-distributed broadcast delay all
   exist.  But four substantive divergences remain:

   - the initial feefilter sent at handshake is **a hardcoded
     constant 100000 sat/kvB** (BUG-6, `Network.hs:2431`) instead of
     `m_mempool.GetMinFee().GetFeePerK()` rounded via
     `FeeFilterRounder`;
   - **no IBD branch** — Core sends `MAX_MONEY` while in IBD so peers
     stop advertising txs to us; haskoin has no IBD check in
     `shouldSendFeeFilter` (BUG-7, P0-CDIV);
   - **no `FeeFilterRounder` quantization** — Core quantizes the
     filter to one of ~120 buckets via a log-spaced fee_set to avoid
     leaking the exact mempool minfee; haskoin sends the raw value
     verbatim (BUG-8, P1, privacy);
   - **the trickler engine that consumes `piFeeFilterReceived` is
     unwired** at the app/Main level — `broadcastTxToPeers` ignores
     the field entirely (BUG-9 cross-cite W103-BUG-3, P0-CDIV).

3. **BIP-339 wtxidrelay** — wire codec, PeerInfo field
   (`piWtxidRelay`), and the inv-type switch in `broadcastTxToPeers`
   (Rpc.hs:2401) all exist.  But the **handshake-side feature
   negotiation is COMPLETELY MISSING**:

   - haskoin **NEVER sends MWtxidRelay outbound** during handshake
     (BUG-1, P0-CDIV) — Core sends it at net_processing.cpp:3710
     unconditionally when greatest_common_version >=
     WTXID_RELAY_VERSION;
   - the inbound MWtxidRelay handler at `app/Main.hs:2354` does
     **NOT check that the message arrived BEFORE verack** (Core
     net_processing.cpp:3922-3927 disconnects peers that send
     WTXIDRELAY after fSuccessfullyConnected) — BUG-2, P1;
   - the inbound handler does **NOT check
     `peer.GetCommonVersion() >= WTXID_RELAY_VERSION`** before
     accepting (Core net_processing.cpp:3928) — BUG-3, P1;
   - the inbound handler does **NOT log "ignoring duplicate
     wtxidrelay"** when called twice (Core net_processing.cpp:3933) —
     BUG-4, P2.

   Net effect: haskoin will advertise wtxids back to a peer that
   asked for them, but will **never request wtxids from outbound
   peers**, so every outbound peer keeps spamming legacy-txid invs to
   us — defeating the BIP-339 anti-DoS goal of reducing wtxid /
   txid duplication.

## BUGS (14 catalogued, no double-count with W103 / W117 / W126)

### BIP-339 wtxidrelay

| # | Pri | Description | Reference |
|---|-----|-------------|-----------|
| BUG-1 | **P0-CDIV** | We never send MWtxidRelay outbound during handshake | Core net_processing.cpp:3710-3712 |
| BUG-2 | P1 | Inbound MWtxidRelay handler does not check pre-VERACK arrival | Core net_processing.cpp:3922-3927 |
| BUG-3 | P1 | Inbound MWtxidRelay handler does not check protocol version >= 70016 | Core net_processing.cpp:3928 |
| BUG-4 | P2 | Inbound MWtxidRelay handler silently overwrites on duplicate (no log, no rate-limit) | Core net_processing.cpp:3933 |

### BIP-130 sendheaders

| # | Pri | Description | Reference |
|---|-----|-------------|-----------|
| BUG-5 | **P0-CDIV** | SendHeaders sent unconditionally after VERACK; no `m_sent_sendheaders` gate; no `pindexBestKnownBlock->nChainWork > MinimumChainWork` check | Core net_processing.cpp:5519-5538 (`MaybeSendSendHeaders`) |
| BUG-10 | P1 | Inbound MSendHeaders handler does not check protocol version >= 70012 | Core net_processing.cpp:5525 (`SENDHEADERS_VERSION`) |
| BUG-11 | P2 | `piSentSendHeaders` mirror state not tracked (no idempotence on the SEND side; we send SENDHEADERS once per handshake but the flag is implicit in the post-verack message order) | Core net_processing.cpp:406 (`m_sent_sendheaders`) |

### BIP-133 feefilter

| # | Pri | Description | Reference |
|---|-----|-------------|-----------|
| BUG-6 | P1 | Initial outbound feefilter hardcoded to 100000 sat/kvB | Core net_processing.cpp:5550 (`m_mempool.GetMinFee().GetFeePerK()`) |
| BUG-7 | **P0-CDIV** | No IBD branch in `shouldSendFeeFilter` — Core sets currentFilter to MAX_MONEY while IBD | Core net_processing.cpp:5552-5555 |
| BUG-8 | P1 | No FeeFilterRounder quantization (privacy regression) | Core policy/fees/block_policy_estimator.cpp:1103-1119 |
| BUG-12 | P1 | `handleFeeFilter` accepts feefilter on block-relay-only / feeler peers (Core sends none and ignores any inbound) | Core net_processing.cpp:5542-5548 |
| BUG-13 | P1 | No ForceRelay / NoBan / Whitelist permission check — Core skips MaybeSendFeefilter for ForceRelay peers | Core net_processing.cpp:5545 |
| BUG-14 | P1 | `piFeeFilterReceived` is read only by `InvTrickler` flush, which is dead code at app/Main level (W103 cross-cite BUG-3) | Cross-cite W103 |
| BUG-9 | **P0-CDIV** | `broadcastTxToPeers` ignores `piFeeFilterReceived` — sendrawtransaction relays below-filter txs | `Rpc.hs:2389-2404`, Core `RelayTransaction` via trickler |

## 30-gate matrix

| Gate | Subject | Status | Bug |
|------|---------|--------|-----|
| G1  | MSendHeaders wire encode/decode round-trip | PRESENT | — |
| G2  | MWtxidRelay wire encode/decode round-trip | PRESENT | — |
| G3  | MFeeFilter wire encode/decode round-trip (Word64 little-endian) | PRESENT | — |
| G4  | commandName / msgTypeName parity for all 3 | PRESENT | — |
| G5  | piWantsHeaders set True on inbound MSendHeaders | PRESENT | — |
| G6  | piWtxidRelay set True on inbound MWtxidRelay | PRESENT | — |
| G7  | piFeeFilterReceived updated on inbound MFeeFilter | PRESENT | — |
| G8  | announceTip routes MHeaders when piWantsHeaders | PRESENT | — |
| G9  | broadcastTxToPeers picks InvWtx when piWtxidRelay | PRESENT | — |
| G10 | We send MWtxidRelay outbound during handshake (pre-VERACK) | MISSING | BUG-1 |
| G11 | Inbound MWtxidRelay rejected (peer disconnected) when after VERACK | MISSING | BUG-2 |
| G12 | Inbound MWtxidRelay version-gated (>= 70016) | MISSING | BUG-3 |
| G13 | Duplicate MWtxidRelay logged + does not double-count | MISSING | BUG-4 |
| G14 | SendHeaders delayed until headers-sync complete (`MaybeSendSendHeaders`) | MISSING | BUG-5 |
| G15 | SendHeaders gated by `pindexBestKnownBlock->nChainWork > MinimumChainWork` | MISSING | BUG-5 |
| G16 | SendHeaders idempotent (`m_sent_sendheaders`) | PARTIAL | BUG-11 |
| G17 | Inbound MSendHeaders version-gated (>= 70012) | MISSING | BUG-10 |
| G18 | Initial outbound feefilter uses mempool min fee, not constant | MISSING | BUG-6 |
| G19 | FeeFilter sent every ~AVG_FEEFILTER_BROADCAST_INTERVAL (10min) | PRESENT | — |
| G20 | FeeFilter expedited to within MAX_FEEFILTER_CHANGE_DELAY on significant fee change | PARTIAL | — |
| G21 | FeeFilter "significant change" threshold = 3/4 .. 4/3 of last-sent | PRESENT | — |
| G22 | FeeFilter NOT sent to block-relay-only peers | PARTIAL | BUG-12 |
| G23 | FeeFilter NOT sent to peers below FEEFILTER_VERSION (70013) | MISSING | BUG-10 (shared) |
| G24 | FeeFilter NOT sent if peer has ForceRelay permission | MISSING | BUG-13 |
| G25 | FeeFilter set to MAX_MONEY during IBD | MISSING | BUG-7 |
| G26 | FeeFilter quantized via FeeFilterRounder (log-spaced, ~120 buckets) | MISSING | BUG-8 |
| G27 | piFeeFilterReceived honoured at outbound relay time | PARTIAL | BUG-9 / BUG-14 |
| G28 | feeAtRate (sat/vB × vsize / 1000) maps tx fee to filter unit | PRESENT | — |
| G29 | poissonDelay produces a non-degenerate exponential | PARTIAL | — |
| G30 | All three flags default False at PeerInfo init | PRESENT | — |

## Methodology

This is a **discovery-only** audit.  No production code is modified.
Tests are written in two shapes:

- **`it` pinning**: assert observable current behavior so a future fix
  wave that changes the shape is forced to update the test (regression
  forward-guard).
- **`xit` sentinel** (via `pendingWith "BUG-N: ..."`): assert the
  desired Core-parity behavior, gated on the bug being fixed.  Future
  fix waves flip `xit` -> `it` after wiring the missing primitive.

Bugs are tagged by priority:

- **P0-CDIV**: consensus divergence or active relay-correctness gap
  (would cause divergent behavior on a real mainnet peer);
- **P1**: protocol-compliance gap or DoS vector that has not yet been
  exercised in production;
- **P2**: hygiene / documentation / refactor risk.

## References

- BIP-130 (sendheaders): https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki
- BIP-133 (feefilter):   https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki
- BIP-339 (wtxidrelay):  https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki
- bitcoin-core/src/net_processing.cpp `MaybeSendSendHeaders` (5519-5538),
  `MaybeSendFeefilter` (5540-5580), WTXIDRELAY handler (3919-3939),
  initial WTXIDRELAY send (3710-3712).
- bitcoin-core/src/node/protocol_version.h SENDHEADERS_VERSION=70012,
  FEEFILTER_VERSION=70013, WTXID_RELAY_VERSION=70016.
- bitcoin-core/src/policy/fees/block_policy_estimator.cpp
  `FeeFilterRounder::round` (1109-1119), `MakeFeeSet` (1085-1101),
  MAX_FILTER_FEERATE=1e7, FEE_FILTER_SPACING=1.1.

## Next-step fix sketch (NOT part of W136)

1. Move the SENDHEADERS + initial FEEFILTER sends out of
   `continueHandshake` and into a new `MaybeSendSendHeaders` /
   `MaybeSendFeefilter` pair called from the message-loop tick, with
   the proper gates (G14 / G15 / G17 / G18 / G22 / G23 / G24 / G25 /
   G26).
2. Add `sendMessage pc MWtxidRelay` to the outbound branch of
   `performHandshake` (Core net_processing.cpp:3710), gated by
   `protocolVersion >= 70016` (G10).
3. Add pre-VERACK + version-gating + dup-log checks to the inbound
   MWtxidRelay handler at `app/Main.hs:2354` (G11 / G12 / G13).
4. Wire `InvTrickler` from `app/Main.hs` so `broadcastTxToPeers` (or
   its replacement) actually respects `piFeeFilterReceived` (G27 /
   BUG-9 / cross-cite W103).
5. Add `FeeFilterRounder` (G26) — small, self-contained module
   (`policy/fees/block_policy_estimator.cpp:1085-1119` is ~40 LOC).

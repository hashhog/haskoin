# W152 — Tx relay + inv batching + orphan handling (haskoin)

**Wave:** W152 — `RelayTransaction`, `InitiateTxBroadcastToAll`,
`AddTxAnnouncement` (txdownloadman), `m_tx_inventory_to_send`,
`m_tx_inventory_known_filter`, `m_recently_announced_invs` (transitive
through `m_tx_inventory_known_filter`), `m_next_inv_send_time` /
`NextInvToInbounds` (Poisson trickle), `m_recently_rejected`
(CRollingBloomFilter), BIP-339 `MSG_WTX` vs `MSG_TX` vs `MSG_WITNESS_TX`
dispatch, `wtxidrelay` post-VERACK gate, `TxOrphanage::AddTx` /
`EraseForPeer` / `EraseForBlock` / `LimitOrphans` /
`AddChildrenToWorkSet` / `m_outpoint_to_orphan_wtxids`,
`INVENTORY_BROADCAST_PER_SECOND=14`, `INVENTORY_BROADCAST_TARGET=70`,
`INVENTORY_BROADCAST_MAX=1000`, `INBOUND_INVENTORY_BROADCAST_INTERVAL=5s`,
`OUTBOUND_INVENTORY_BROADCAST_INTERVAL=2s`, `TXID_RELAY_DELAY=2s`,
`NONPREF_PEER_TX_DELAY=2s`, `OVERLOADED_PEER_TX_DELAY=2s`,
`GETDATA_TX_INTERVAL=60s`, `MAX_PEER_TX_REQUEST_IN_FLIGHT=100`,
`MAX_PEER_TX_ANNOUNCEMENTS=5000`, `MAX_INV_SZ=50000`,
`MAX_GETDATA_SZ=1000`, BIP-37 `mempool` handler + bloom-filter
application, BIP-152 cmpctblock high-bandwidth announce path,
`fSuccessfullyConnected` gate (per-peer relay start).

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/net_processing.cpp:165` —
  `INBOUND_INVENTORY_BROADCAST_INTERVAL = 5s`,
  `OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2s` (line 167),
  `INVENTORY_BROADCAST_PER_SECOND = 14` (line 172),
  `INVENTORY_BROADCAST_TARGET = INVENTORY_BROADCAST_PER_SECOND * 5 = 70`
  (line 174), `INVENTORY_BROADCAST_MAX = 1000` (line 176).
- `bitcoin-core/src/node/txdownloadman.h:25` —
  `MAX_PEER_TX_REQUEST_IN_FLIGHT = 100`, `MAX_PEER_TX_ANNOUNCEMENTS = 5000`
  (line 30), `TXID_RELAY_DELAY = 2s` (line 32),
  `NONPREF_PEER_TX_DELAY = 2s` (line 34),
  `OVERLOADED_PEER_TX_DELAY = 2s` (line 36),
  `GETDATA_TX_INTERVAL = 60s` (line 38).
- `bitcoin-core/src/node/txorphanage.h:23` —
  `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000` (post-2024 — replaced the
  old `DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100` constant).
- `bitcoin-core/src/protocol.h:481-486` — `MSG_TX = 1`, `MSG_BLOCK = 2`,
  `MSG_FILTERED_BLOCK = 3` (getdata-only), `MSG_CMPCT_BLOCK = 4`
  (getdata-only), **`MSG_WTX = 5` (BIP-339)**,
  `MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG = 0x40000002`
  (getdata-only — per spec comment line 482 "Invs always use TX/WTX or
  BLOCK"), `MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG = 0x40000001`
  (getdata-only).
- `bitcoin-core/src/net_processing.cpp:303` —
  `CRollingBloomFilter m_tx_inventory_known_filter{50000, 0.000001}`
  per-peer; `m_lazy_recent_rejects` is also CRollingBloomFilter.
- `bitcoin-core/src/net_processing.cpp:308` —
  `std::set<Wtxid> m_tx_inventory_to_send` (wtxid-keyed pending
  announcement queue, per-peer).
- `bitcoin-core/src/net_processing.cpp:2243-2264` —
  `InitiateTxBroadcastToAll`: skip peers whose
  `m_next_inv_send_time == 0s` (handshake not done), dedupe against
  `m_tx_inventory_known_filter`, insert into
  `m_tx_inventory_to_send`.
- `bitcoin-core/src/net_processing.cpp:5984-6090` — SendMessages tx
  relay loop: fSendTrickle gate, Poisson timer
  (`NextInvToInbounds(current_time, INBOUND_INVENTORY_BROADCAST_INTERVAL, m_network_key)`),
  `m_send_mempool` one-shot flag, bloom-filter
  `IsRelevantAndUpdate`, fee-filter `txinfo.fee < filterrate.GetFee(...)`,
  topological + fee-rate sort via `CompareInvMempoolOrder` + heap,
  per-cycle cap `INVENTORY_BROADCAST_TARGET + (q/1000)*5` clamped to
  `INVENTORY_BROADCAST_MAX`, per-peer wtxid-relay dispatch
  (`MSG_WTX` vs `MSG_TX`), `MAX_INV_SZ=50000` per inv message.
- `bitcoin-core/src/net_processing.cpp:4055-4063` — wtxidrelay-side
  inv filter (silent drop, no misbehavior).
- `bitcoin-core/src/net_processing.cpp:3919-3938` — `WTXIDRELAY` post-VERACK
  gate (`fSuccessfullyConnected` → disconnect).
- `bitcoin-core/src/net_processing.cpp:4088` — IBD-side tx-inv gate
  (`if (!m_chainman.IsInitialBlockDownload())` wraps
  `m_txdownloadman.AddTxAnnouncement`).
- `bitcoin-core/src/net_processing.cpp:6200-6217` — outbound getdata
  loop: `MSG_WTX` for wtxid-relay peers, `MSG_TX | GetFetchFlags(peer)`
  for legacy; chunks at `MAX_GETDATA_SZ = 1000`.
- `bitcoin-core/src/node/txdownloadman_impl.cpp:200-280` —
  `AddTxAnnouncement` per-peer scheduling: stop at
  `MAX_PEER_TX_ANNOUNCEMENTS`; per-announcement `delay = 0` then
  `+ NONPREF_PEER_TX_DELAY` if not preferred,
  `+ TXID_RELAY_DELAY` if `!gtxid.IsWtxid() && m_num_wtxid_peers > 0`,
  `+ OVERLOADED_PEER_TX_DELAY` if `CountInFlight(peer) >= MAX_PEER_TX_REQUEST_IN_FLIGHT`;
  `RequestedTx(nodeid, hash, current_time + GETDATA_TX_INTERVAL)` on
  emit.
- `bitcoin-core/src/node/txorphanage.cpp:442-525` — `LimitOrphans`:
  per-peer DoS score (max-heap), evicts oldest announcement from
  highest-DoS peer until under global limit.
- `bitcoin-core/src/node/txorphanage.cpp:527-565` —
  `AddChildrenToWorkSet`: walks the new tx's `vout`,
  `m_outpoint_to_orphan_wtxids.find(COutPoint(tx.GetHash(), i))`
  for each output index, picks RANDOM announcer from
  `m_orphans.get<ByWtxid>()` range, marks
  `m_reconsiderable_wtxids.insert(wtxid)`.
- `bitcoin-core/src/node/txorphanage.cpp:610-643` — `EraseForBlock`:
  walks each block tx's `vin[i].prevout`, looks up
  `m_outpoint_to_orphan_wtxids`, erases EVERY orphan whose input
  matches (conflict eviction), not just orphans whose own txid was
  confirmed. Calls `LimitOrphans` at the end.

**Files audited**
- `src/Haskoin/TxOrphanage.hs` — `OrphanPool`, `emptyOrphanPool`,
  `maxOrphanTxs = 100`, `orphanExpireSecs = 300`, `addOrphan`,
  `expireOrphans`, `eraseOrphansForPeer`, `eraseOrphansForBlock`.
  Secondary index keyed by parent **TxId** (not outpoint).
- `src/Haskoin/Network.hs` — `Inv`, `GetData`, `NotFound` wire types
  (line 956-994); `MAX_INV_SZ = 50000` (`maxInvSz` line 904);
  `MAX_GETDATA_SZ = 1000` (`maxGetDataSz` line 914); `InvType` ADT and
  `invTypeToWord32` / `word32ToInvType` (line 842-876); InvTrickler
  subsystem (line 4556-4864): `inboundInventoryBroadcastInterval = 5s`,
  `outboundInventoryBroadcastInterval = 2s`,
  `inventoryBroadcastPerSecond = 14`,
  `inventoryBroadcastTarget = 70`, `inventoryBroadcastMax = 1000`,
  `defaultTrickleConfig`, `TrickleConfig`, `InvTrickler`,
  `PeerTrickleState` (ptsNextSendTime / ptsPendingInvs / ptsSentFilter),
  `poissonDelay`, `newInvTrickler`, `queueTxForTrickling`,
  `flushPeerInventoryWithFilter`, `scheduleNextSend`,
  `startTrickleThread`, `trickleLoop`,
  `removePeerTrickleState`, `clearPeerSentFilter`. All of these are
  **exported but never called**.
- `app/Main.hs` — `syncMessageHandler` (line 1639-2403):
  `MTx` handler (line 1910-1971), `MGetData` (line 1973-2004),
  `MInv` (line 2006-2080), `MWtxidRelay` (line 2354-2366),
  `MMemPool` (line 2368-2402), `announceTip` helper (line 1523-1534),
  `processOrphan` (line 1579-1603), `recentlyRejectedRef`
  (line 931 + line 1876 + line 1958-1960), `ibdModeRef`
  (line 929 + line 1741). Imports `TxOrphanage` (line 64-67) but
  never imports `newInvTrickler`/`queueTxForTrickling`.
- `src/Haskoin/Rpc.hs` — `broadcastTxToPeers` (line 2389-2404,
  fast-path bypass to `MInv` per peer, NOT routed through trickler);
  `handleSubmitPackage` / `submitPackageTxns` (line 5537-5731);
  per-RPC call sites for `broadcastTxToPeers` (sendrawtransaction line
  2283, bumpfee/createrawtransaction etc 6445/6714/7050).
- `src/Haskoin/Mempool.hs` — `blockConnected` (line 1831-1866;
  removes confirmed + conflict txs, but does NOT invoke any tx-relay
  hook); `removeConflicts` (line 1739-1822); no orphan-cleanup hook
  on RBF/conflict path.
- `test/W103TxRelaySpec.hs` — self-documenting test asserts at
  line 883 "BUG-3 EXTENSION: MTx handler calls broadcastMessage
  (no trickle) not queueTxForTrickling" (the failure is encoded as
  passing test).

---

## Gate matrix (44 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | InvTrickler subsystem wired into production tx relay | G1: MTx handler routes accepted tx through trickler with Poisson timer | **BUG-1 (P0)** — InvTrickler is dead code (zero call sites in app/Main.hs for `newInvTrickler`/`queueTxForTrickling`/`startTrickleThread`); MTx fast-path at Main.hs:1922-1928 calls `sendMessage pc (MInv ...)` per peer immediately |
| 1 | … | G2: RPC sendrawtransaction routes through trickler | **BUG-1 cross-cite** — Rpc.hs:2389-2404 `broadcastTxToPeers` also bypasses trickler |
| 1 | … | G3: trickleLoop is running on a background thread | **BUG-1 cross-cite** — `startTrickleThread` never invoked anywhere |
| 2 | BIP-339 MSG_WTX dispatch (inv announcement) | G4: MTx broadcast picks `InvWtx` (type=5) for wtxid-relay peers | PASS (Main.hs:1926) |
| 2 | … | G5: MTx broadcast picks `InvTx` (type=1) for legacy peers | PASS (Main.hs:1927) |
| 2 | … | G6: MMemPool response picks `InvWtx` (type=5) for wtxid-relay peers | **BUG-2 (P1)** — Main.hs:2393 picks between `InvWitnessTx` (=0x40000001, BIP-144 getdata-only) and `InvTx` (=1) — never `InvWtx` (=5). Violates Core's wire invariant (protocol.h:482 "Invs always use TX/WTX or BLOCK") and breaks BIP-339 wtxid-relay peer state machine |
| 2 | … | G7: Comment on MMemPool dispatch correctly cites `MSG_WTX = 5` | **BUG-3 (P2)** — Main.hs:2385 comment says "MSG_WTX (0x40000002)"; 0x40000002 is `MSG_WITNESS_BLOCK`, not `MSG_WTX`. Documentation is wrong |
| 3 | BIP-339 wtxidrelay-before-VERACK negotiation gate | G8: `wtxidrelay` AFTER verack disconnects peer | **BUG-4 (P0-SEC)** — Main.hs:2354-2366 handler unconditionally sets `piWtxidRelay = True`, no `piState`/handshake-done check. Core net_processing.cpp:3919-3938 explicitly disconnects (`fDisconnect=true`) on post-VERACK wtxidrelay |
| 4 | TxRequest scheduler (txdownloadman) | G9: per-peer in-flight cap `MAX_PEER_TX_REQUEST_IN_FLIGHT=100` | **BUG-5 (P0)** — entirely absent. No `MAX_PEER_TX_REQUEST_IN_FLIGHT`, no `txdownloadman` analog. Main.hs:2078-2080 emits GETDATA immediately on every inv |
| 4 | … | G10: `NONPREF_PEER_TX_DELAY=2s` (privacy delay for inbound) | **BUG-5 cross-cite** — no NONPREF_PEER_TX_DELAY in the repo |
| 4 | … | G11: `TXID_RELAY_DELAY=2s` (wtxid-peer privacy: prefer wtxid invs over txid invs from old peers) | **BUG-5 cross-cite** — no TXID_RELAY_DELAY |
| 4 | … | G12: `OVERLOADED_PEER_TX_DELAY=2s` | **BUG-5 cross-cite** — no OVERLOADED_PEER_TX_DELAY |
| 4 | … | G13: `GETDATA_TX_INTERVAL=60s` reschedule on no-response | **BUG-6 (P1)** — there is no GETDATA re-request timer; once we emit GETDATA the request is abandoned silently on timeout, no rescheduling to a different peer |
| 4 | … | G14: `MAX_PEER_TX_ANNOUNCEMENTS=5000` cap | **BUG-7 (P1)** — no per-peer announcement cap; a single peer can flood our `recentlyRejectedRef` (capped at 50000, fleet-wide rather than per-peer) but no per-peer guard exists |
| 5 | m_tx_inventory_known_filter (per-peer dedup) | G15: per-peer CRollingBloomFilter (50000 elements, FPP 1e-6) tracking already-announced wtxids | **BUG-8 (P0)** — `ptsSentFilter` (Network.hs:4664) is a flat `Set.Set TxId` inside the dead InvTrickler. The live MTx fast-path has NO known-filter at all; we re-announce the same tx to a peer that already saw it |
| 5 | … | G16: Source-peer skip (don't echo tx back to the peer that sent it) | **BUG-9 (P1)** — Main.hs:1921-1928 iterates `Map.elems peers` with no `addr /= peerSockAddr` filter; we echo the inv back to the sender peer |
| 6 | m_tx_inventory_to_send (per-peer batched queue) | G17: per-peer wtxid-keyed std::set accumulator | **BUG-8 cross-cite** — not implemented in fast-path; even the dead InvTrickler uses txid not wtxid (`ptsPendingInvs :: TVar (Set PendingInv)`, PendingInv keyed by `piTxId :: TxId`, Network.hs:4651) |
| 7 | recently-rejected filter | G18: CRollingBloomFilter (rolling, persists across blocks) | **BUG-10 (P0)** — `recentlyRejectedRef` (Main.hs:931) is `IORef (Set TxId)`; cleared to `Set.empty` on EVERY connected block (Main.hs:1876). Core's `m_lazy_recent_rejects` retains across many blocks |
| 7 | … | G19: filter keyed by wtxid for BIP-339 peers, txid for legacy | **BUG-11 (P0-CDIV)** — Main.hs:2056-2067 unconditionally constructs `TxId (ivHash iv)` from `ivHash`; for an `InvWtx`, `ivHash` is a wtxid but is treated as txid for lookup in mempool and reject-filter. Both lookups always miss for wtxid invs → every wtxid inv is re-requested even when the tx is already known |
| 8 | Orphan pool size limit | G20: `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000` (post-2024 Core) | **BUG-12 (P2)** — `maxOrphanTxs = 100` (TxOrphanage.hs:64) tracks pre-2024 Core constant. Comment line 62 still cites "DEFAULT_MAX_ORPHAN_TRANSACTIONS=100"; that constant no longer exists in Core. Pool is much smaller than current Core's effective capacity |
| 8 | … | G21: per-peer DoS scoring on eviction | **BUG-13 (P0)** — `addOrphan` eviction (TxOrphanage.hs:112-121) calls `Map.minViewWithKey`, i.e. evict the orphan with smallest Wtxid (a hash). This is adversary-attackable: a peer crafting txs with low wtxid hashes always evicts other peers' orphans first. Core's `LimitOrphans` (txorphanage.cpp:442-525) uses a max-heap on per-peer DoS score and evicts oldest announcements from worst peer |
| 9 | EraseForBlock (orphan conflict eviction) | G22: erase orphans whose own txid appears in the block | PASS (TxOrphanage.hs:184-194) |
| 9 | … | G23: erase orphans whose inputs CONFLICT with confirmed block txs (different txid, same prevout) | **BUG-14 (P1)** — `eraseOrphansForBlock` only removes orphans whose txid is in the confirmedTxIds set. Core's `EraseForBlock` (txorphanage.cpp:610-643) walks each block tx's `vin[i].prevout`, looks up `m_outpoint_to_orphan_wtxids`, and erases all orphans spending those prevouts. The TxOrphanage.hs:175-183 comment is comment-as-confession: "Core also removes orphans that conflict with the block ... This implementation removes orphans whose own txid appears in the block, covering the primary case" |
| 9 | … | G24: erase orphans whose parents are RBF'd in mempool (separate from block path) | **BUG-15 (P1)** — `Mempool.blockConnected` removes conflict txs from mempool but does NOT invoke `eraseOrphansForBlock`-equivalent for those conflicts; `removeConflicts` (Mempool.hs:1739) does not call into orphan pool. Orphans pointing at RBF'd parents linger |
| 10 | Periodic orphan expiry | G25: `expireOrphans` runs on a wall-clock timer (not just on parent-accept) | **BUG-16 (P1)** — single call site Main.hs:1581 inside `processOrphan`. If no parent tx is ever accepted, expired orphans (older than `orphanExpireSecs = 300`) linger forever. Core's `LimitOrphans` is called on multiple paths (txorphanage.cpp:350, 381, 410, 433, 642) including in every block-erase path and AddTx |
| 11 | OrphanByParent secondary index | G26: keyed by `COutPoint (txid, vout)` for output-level resolution | **BUG-17 (P2)** — `orphanWtxid :: Map.Map TxId (Set.Set Wtxid)` (TxOrphanage.hs:52) keyed by parent **TxId** only — loses vout. `processOrphan` retry walks all child orphans of the new parent regardless of which output they spend; correctness-neutral for retry but the data shape cannot support Core's input-level conflict detection (BUG-14 cross-cite) and uses more memory than needed |
| 11 | … | G27: random-announcer selection (anti-DoS for multi-peer orphan announcements) | **BUG-18 (P1)** — `addOrphan` (TxOrphanage.hs:108-109) dedupes by wtxid: "no-op if the wtxid is already present". Stores only the FIRST announcer's `SockAddr`. Core (txorphanage.cpp:542-548) tracks ALL announcers and picks a random one with `rng.randrange(num_announcers)` for retry, so a single malicious first-announcer cannot withhold orphan progress by disconnecting |
| 12 | IBD-side gates on tx relay | G28: tx-inv requests suppressed during IBD | **BUG-19 (P0)** — Main.hs:2010-2023 `unless isIBD` guards ONLY the block-inv branch; tx-inv handling at line 2042+ runs unconditionally during IBD. Core net_processing.cpp:4088 wraps `AddTxAnnouncement` in `if (!IsInitialBlockDownload())` |
| 12 | … | G29: IBD-exit gated on tip-recency AND minimum-chainwork | **BUG-20 (P0)** — `ibdModeRef` flips to False as soon as a single getheaders batch returns <2000 headers (Main.hs:1737-1741). No tip-age check, no MinimumChainWork check, no requirement that blocks are also caught up. Header sync completion ≠ block sync completion |
| 13 | BIP-37 bloom-filter handlers (filtered relay) | G30: MFilterLoad handler installs per-peer bloom filter | **BUG-21 (P1)** — no `MFilterLoad`/`MFilterAdd`/`MFilterClear` case in `syncMessageHandler` (Main.hs:1639-2403). Wire decoder accepts the messages but the body is never stored. SPV peers loading filters get the unfiltered mempool dump |
| 13 | … | G31: MMemPool applies the peer's stored bloom filter before responding | **BUG-21 cross-cite** + **BUG-22 (P1)** — Main.hs:2384-2402 dumps the entire mempool by txid; Core (net_processing.cpp:6004-6021) applies `tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)` per entry |
| 13 | … | G32: MMemPool applies the peer's feefilter before responding | **BUG-23 (P1)** — same MMemPool block has no feefilter application. Core line 6013: `if (txinfo.fee < filterrate.GetFee(txinfo.vsize)) continue;` |
| 14 | piRelay (BIP-37 fRelay) gate on outbound tx relay | G33: MTx broadcast skips peers whose version had `fRelay=false` | **BUG-24 (P0-SEC)** — Main.hs:1924 checks `not (piBlockOnly info)` but NOT `piRelay info`. `piRelay` is set from `vRelay theirVersion` (Network.hs:2422) but only the trickler at Network.hs:4848 actually honours it. Peers with `fRelay=false` still get tx invs from the fast-path. Note `piBlockOnly` is set only when WE initiated a block-relay-only outbound (Network.hs:3426/3552/3620/3680), independent of peer's fRelay claim |
| 14 | … | G34: BIP-37 disabled → never set piRelay=true (interop with non-bloom peers) | (advisory — covered by G33) |
| 15 | MSG_WTX vs MSG_WITNESS_TX in outbound GETDATA | G35: GETDATA for wtxid-relay peers uses MSG_WTX (=5) | **BUG-25 (P1)** — Main.hs:2076 unconditionally rewrites every tx-inv to `InvWitnessTx` (=0x40000001) for the outbound GETDATA, even when the inbound inv was `InvWtx` (=5). Core net_processing.cpp:6206 emits `MSG_WTX` for `gtxid.IsWtxid()` peers. Wtxid-relay peers may not resolve their `m_tx_inventory_to_send` against MSG_WITNESS_TX getdata |
| 16 | m_send_mempool (one-shot mempool dump) | G36: peer cannot replay `mempool` to force repeated full dump | **BUG-26 (P1)** — Main.hs:2368-2402 has no `m_send_mempool` analog; a peer can spam `mempool` to repeatedly drain a 50000-inv response per dump. Core sets `tx_relay->m_send_mempool = false` after a single response per inv-trickle cycle |
| 17 | BIP-152 cmpctblock high-bandwidth tip announce | G37: `announceTip` sends `MCmpctBlock` directly to high-bandwidth peers (no inv intermediate) | **BUG-27 (P1)** — `announceTip` (Main.hs:1523-1534) only picks between `MHeaders` (sendheaders peers) and `MInv` (legacy). Never sends `MCmpctBlock` directly. Core's `SendMessages` BIP-152 high-bandwidth path skips the inv stage entirely |
| 17 | … | G38: source-peer skip on block announce | **BUG-28 (P1)** — `announceTip` iterates `Map.elems peers` with no source-peer filter (same shape as BUG-9). Cross-cite W148 BUG-13 (MBlock handler bans peers announcing reorgs) |
| 18 | computeWtxid two-pipeline guard | G39: ONE canonical wtxid implementation | **BUG-29 (P1)** — `Haskoin.Crypto.computeWtxid` (Crypto.hs:1064) returns `Wtxid`; `Haskoin.Consensus.computeWtxId` (Consensus.hs:3000) returns `TxId`. Both compute `doubleSHA256 (encode tx)` — same bytes, different types. Main.hs:1920 uses the Crypto variant; Rpc.hs:5582 uses the Consensus variant. Two-pipeline guard, 17th distinct extension across the W76+ tracking |
| 19 | Two-pipeline guard on relay paths | G40: ONE canonical RelayTransaction equivalent | **BUG-30 (P0)** — three distinct relay implementations coexist: (a) Main.hs:1922-1929 MTx fast-path (immediate, no trickle, no source-skip, no piRelay check); (b) Rpc.hs:2389-2404 `broadcastTxToPeers` (immediate, no trickle, source not applicable, no piRelay check); (c) Network.hs:4691-4825 InvTrickler subsystem (full Poisson + Filter + fee-filter, never called). Three pipelines — same shape as W143 rustoshi 3-merkle and ouroboros 3-consensus-pipeline ("three-pipeline drift", 4th fleet instance) |

---

## BUG-1 (P0) — InvTrickler subsystem entirely dead code; production tx relay is unbatched

**Severity:** P0. Bitcoin Core's tx relay batches outbound inv
announcements per peer behind a **Poisson timer**
(`INBOUND_INVENTORY_BROADCAST_INTERVAL = 5s`,
`OUTBOUND_INVENTORY_BROADCAST_INTERVAL = 2s`,
`INVENTORY_BROADCAST_PER_SECOND = 14`,
`INVENTORY_BROADCAST_TARGET = 70`,
`INVENTORY_BROADCAST_MAX = 1000`). This provides four critical
properties simultaneously:
1. **Privacy** — fingerprinting via inv-emit timing is degraded by the
   exponential jitter; inbound peers share a single jitter clock to
   prevent correlation attacks.
2. **Fee-filter application** — only txs above the peer's BIP-133
   `feefilter` are sent.
3. **De-duplication** — `m_tx_inventory_known_filter`
   (CRollingBloomFilter, 50000 elements) suppresses re-announcement of
   txs the peer already saw.
4. **Backpressure** — `INVENTORY_BROADCAST_MAX = 1000` caps the per-flush
   burst; the (q/1000)*5 bonus drains slowly without spiking.

haskoin's `Haskoin.Network.InvTrickler` (Network.hs:4681-4864)
implements ALL of this correctly — Poisson delay (line 4634-4643),
per-peer `PeerTrickleState` (line 4661-4674), fee-filter application
(line 4770-4772), backpressure with bonus (line 4775-4779),
inbound-shared-timer (line 4807-4821), trickle thread (line 4829-4851).

But the entire subsystem is **dead code**. A repo-wide grep over
`src/` and `app/` shows ZERO call sites for `newInvTrickler`,
`queueTxForTrickling`, or `startTrickleThread`:

```bash
$ grep -rn "queueTxForTrickling\|newInvTrickler\|startTrickleThread" \
    /home/work/hashhog/haskoin/src /home/work/hashhog/haskoin/app
src/Haskoin/Network.hs:195: , newInvTrickler        # export
src/Haskoin/Network.hs:196: , queueTxForTrickling   # export
src/Haskoin/Network.hs:199: , startTrickleThread    # export
src/Haskoin/Network.hs:4691: newInvTrickler :: ...  # definition
src/Haskoin/Network.hs:4706: queueTxForTrickling :: ... # definition
src/Haskoin/Network.hs:4829: startTrickleThread :: ... # definition
```

No `import` from Main.hs, no use site in Rpc.hs, no startup thread.
The test suite confirms this is intentional / unfixed:
`test/W103TxRelaySpec.hs:883` —
`"BUG-3 EXTENSION: MTx handler calls broadcastMessage (no trickle) not queueTxForTrickling"`
— the failure is encoded as a passing test asserting `True`.

The live production path is `Main.hs:1922-1929`:

```haskell
forM_ (Map.elems peers) $ \pc -> do
  info <- readTVarIO (pcInfo pc)
  when (piState info == PeerConnected && not (piBlockOnly info)) $ do
    let (itype, ihash)
          | piWtxidRelay info = (InvWtx, getWtxidHash wtxid)
          | otherwise         = (InvTx,  getTxIdHash txid)
    sendMessage pc (MInv (Inv [InvVector itype ihash]))
```

For every accepted tx: iterate ALL peers, immediately send an MInv
containing JUST THIS ONE tx. No batching, no Poisson timer, no
fee-filter (BIP-133), no known-filter, no source-peer skip, no
per-peer rate limit. The Rpc.hs `broadcastTxToPeers` (line 2389-2404)
has the exact same structure.

**File:** `src/Haskoin/Network.hs:4556-4864` (dead InvTrickler);
`app/Main.hs:1922-1929` (live unbatched path);
`src/Haskoin/Rpc.hs:2389-2404` (RPC live unbatched path).

**Core ref:** `bitcoin-core/src/net_processing.cpp:5984-6090`
(SendMessages tx-relay loop with Poisson + filter + fee-filter +
heap-sort + per-cycle cap); `net_processing.cpp:2243-2264`
(`InitiateTxBroadcastToAll`).

**Impact:**
- Privacy: every accepted tx hits all peers immediately. A spy
  observing inv-emit time can correlate to the originating broadcast.
- BIP-133 violation: fee-filter is NEVER applied to MTx-relayed
  outbound invs (only the dead trickler honours it). A peer with
  `feefilter=10000` sat/kvB receives invs for 1 sat/vB junk.
- No known-filter: we re-announce the same tx to a peer that
  already saw it (within the same MTx burst this is dedup'd by the
  loop, but across two accepts of related txs, no).
- Source-peer echo: BUG-9 below.
- Operational: ~280 lines of well-written Poisson/heap/filter code
  sits unreferenced. A future refactor could remove the export and
  the loss would be invisible until a CI test for trickle behaviour
  ran (and the existing test asserts the bypass, so even that catches
  nothing).

---

## BUG-2 (P1) — MMemPool serves `InvWitnessTx` to wtxid-relay peers (BIP-339 wire-invariant violation)

**Severity:** P1. Per Bitcoin Core `protocol.h:482`, the
`MSG_WITNESS_TX` / `MSG_WITNESS_BLOCK` constants
(= `MSG_TX | MSG_WITNESS_FLAG` = `0x40000001`,
= `MSG_BLOCK | MSG_WITNESS_FLAG` = `0x40000002`) are explicitly
documented as **getdata-only**: *"Invs always use TX/WTX or BLOCK"*.
The valid inv types are exactly `MSG_TX = 1`, `MSG_BLOCK = 2`, and
`MSG_WTX = 5` (BIP-339).

haskoin's `MMemPool` handler (`app/Main.hs:2384-2402`) violates this
invariant when responding to a `mempool` request:

```haskell
let invKind = if peerWantsWitness then InvWitnessTx else InvTx
txids <- getMempoolTxIds mp
let invs   = [ InvVector invKind (getTxIdHash t) | t <- txids ]
```

`InvWitnessTx` is the legacy BIP-144 getdata flag (0x40000001), never
a legal inv type. For wtxid-relay peers (BIP-339), the response
should use `InvWtx` (= 5) with `wtxid` hash, not `InvWitnessTx` with
txid hash. The MTx broadcast path at line 1924-1928 picks the
**correct** types (`InvWtx` for wtxid-relay, `InvTx` for legacy), but
MMemPool diverges.

Compare Core (`net_processing.cpp:6004-6020`):
```cpp
for (const auto& txinfo : vtxinfo) {
    const Txid& txid{txinfo.tx->GetHash()};
    const Wtxid& wtxid{txinfo.tx->GetWitnessHash()};
    const auto inv = peer.m_wtxid_relay ?
                         CInv{MSG_WTX, wtxid.ToUint256()} :
                         CInv{MSG_TX, txid.ToUint256()};
    ...
}
```

**File:** `app/Main.hs:2384-2402`.

**Core ref:** `bitcoin-core/src/protocol.h:481-486`,
`bitcoin-core/src/net_processing.cpp:6004-6020`.

**Impact:**
- Wtxid-relay peers will NOT resolve the announcement against their
  `m_tx_inventory_known_filter` (which contains wtxids); they request
  again via getdata on a wtxid they never advertised, churn ensues.
- Some BIP-339-strict implementations (rustoshi, hotbuns) may
  classify a `0x40000001` inv as protocol-malformed and disconnect.
- Modern bitcoind tolerates this as legacy fallback, so this is
  graceful degradation in the Core direction — still a wire-spec
  violation.

---

## BUG-3 (P2) — `MMemPool` comment misnumbers MSG_WTX as 0x40000002

**Severity:** P2 (documentation). `app/Main.hs:2385-2386`:

```haskell
-- Determine inv type per peer: MSG_WTX (0x40000002) for nodeWitness
-- peers, otherwise MSG_TX (1). Bitcoin Core picks per peer state.
```

`0x40000002` is the wire value for `MSG_WITNESS_BLOCK`
(`MSG_BLOCK | MSG_WITNESS_FLAG`). `MSG_WTX = 5` (BIP-339,
`protocol.h:481`). The comment cites the wrong constant; combined with
BUG-2's wrong actual dispatch, this is "comment-as-confession" 9th
distinct haskoin instance.

**File:** `app/Main.hs:2385-2386`.

**Impact:** code-reading divergence; an engineer trusting the comment
would expect MSG_WITNESS_BLOCK to be a tx inv type.

---

## BUG-4 (P0-SEC) — `wtxidrelay` after VERACK is accepted without misbehavior

**Severity:** P0-SEC. BIP-339 explicitly requires
`wtxidrelay` between VERSION and VERACK to avoid relay-state ambiguity
mid-stream. Core net_processing.cpp:3919-3938:

```cpp
if (msg_type == NetMsgType::WTXIDRELAY) {
    if (pfrom.fSuccessfullyConnected) {
        // Disconnect peers that send a wtxidrelay message after VERACK.
        pfrom.fDisconnect = true;
        return;
    }
    if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) {
        if (!peer.m_wtxid_relay) {
            peer.m_wtxid_relay = true;
            m_wtxid_relay_peers++;
        }
        ...
```

haskoin's `MWtxidRelay` handler (`app/Main.hs:2354-2366`):

```haskell
MWtxidRelay -> do
  pm <- readIORef pmRef
  peerMap <- readTVarIO (pmPeers pm)
  case Map.lookup addr peerMap of
    Just pc -> atomically $ modifyTVar' (pcInfo pc) $ \i ->
      i { piWtxidRelay = True }
    Nothing -> return ()
```

No `fSuccessfullyConnected` / `piState == PeerConnected` precondition;
no protocol-version gate (`vVersion >= 70016`); no idempotency log; no
disconnect on post-VERACK frame. A malicious peer can:
1. Complete handshake (verack sent + received).
2. Wait until the node has sent some tx invs via the legacy `MSG_TX`
   wire.
3. Send `wtxidrelay`. From the next inv the node emits `MSG_WTX` —
   the peer can demonstrate it caught a relay-state flip mid-stream
   and use the inv-type change as a side-channel for fingerprinting
   the node's own wtxid-relay peer count.

**File:** `app/Main.hs:2354-2366`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:3919-3938`.

**Impact:**
- BIP-339 protocol-state violation; allows mid-stream relay-state
  flip not anticipated by the spec.
- Cross-fleet: a peer that opportunistically sends post-VERACK
  `wtxidrelay` to fingerprint impls; haskoin silently accepts where
  Core disconnects.
- Defense-in-depth gap: the handshake state machine is meant to be
  monotonic post-VERACK.

---

## BUG-5 (P0) — TxRequest scheduler entirely absent (no NONPREF/TXID/OVERLOADED delays, no in-flight cap)

**Severity:** P0. Bitcoin Core's
`bitcoin-core/src/node/txdownloadman_impl.cpp:200-280`
implements the canonical tx-request scheduler with four distinct
delays:

| Constant | Value | Purpose |
|---|---|---|
| `NONPREF_PEER_TX_DELAY` | 2s | privacy delay for non-preferred (inbound) peers |
| `TXID_RELAY_DELAY` | 2s | bias toward wtxid-relay peers when both kinds announce |
| `OVERLOADED_PEER_TX_DELAY` | 2s | back off if peer has ≥ MAX_PEER_TX_REQUEST_IN_FLIGHT |
| `GETDATA_TX_INTERVAL` | 60s | re-request from another peer on timeout |
| `MAX_PEER_TX_REQUEST_IN_FLIGHT` | 100 | per-peer outstanding cap |
| `MAX_PEER_TX_ANNOUNCEMENTS` | 5000 | per-peer announcement cap |

Without these, the standard anti-DoS posture is broken:
- Privacy: NONPREF_PEER_TX_DELAY gives outbound peers a 2-second head
  start over inbound, hiding our own broadcasts.
- TXID_RELAY_DELAY: when both wtxid-relay peer A and legacy peer B
  announce the same tx, prefer A — closes a wtxid-malleation
  fingerprint vector.
- OVERLOADED: a slow peer can't be turned into a slow-loris
  bottleneck — we route GETDATA to a faster peer instead.
- GETDATA_TX_INTERVAL: if A doesn't respond to our GETDATA within
  60s, ask B. Otherwise the inv is held against A indefinitely.

A repo-wide grep finds ZERO instances of any of these constants:

```bash
$ grep -rn "TXID_RELAY_DELAY\|NONPREF_PEER_TX_DELAY\|OVERLOADED_PEER_TX_DELAY\|GETDATA_TX_INTERVAL\|MAX_PEER_TX_REQUEST\|MAX_PEER_TX_ANNOUNCEMENTS\|TxRequest\|txrequest" /home/work/hashhog/haskoin/src /home/work/hashhog/haskoin/app
(no output)
```

The live behaviour at `Main.hs:2078-2080`:

```haskell
mapM_ (\batch ->
  requestFromPeer pm addr (MGetData (GetData batch))
    `catch` (\(_ :: SomeException) -> return ())) batches
```

Immediate GETDATA on first inv, to the announcing peer only, no
retry on timeout, no per-peer in-flight cap.

**File:** `app/Main.hs:2078-2080` (immediate GETDATA);
absence everywhere else.

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:25-38`;
`bitcoin-core/src/node/txdownloadman_impl.cpp:200-280`.

**Impact:**
- A malicious announcing peer can hold our GETDATA against them
  forever (no timeout-reroute → tx never appears even though other
  peers have it).
- A peer can announce 100k inv vectors and we issue 100 GETDATA
  batches of 1000 immediately (no per-peer cap).
- Privacy fingerprinting: no NONPREF delay → our broadcast origin
  is easier to identify.

---

## BUG-6 (P1) — No GETDATA re-request timer; abandoned requests linger forever

**Severity:** P1. Companion to BUG-5. Once `requestFromPeer pm addr
(MGetData ...)` fires (Main.hs:2078-2080), there is no tracker for
"we asked peer X for tx T at time S"; no `GETDATA_TX_INTERVAL = 60s`
expiry; no re-routing of the request to a different peer on timeout.

If the peer disconnects or simply ignores the request, the tx is
abandoned. The next time some OTHER peer's inv references the same
txid, the `recentlyRejectedRef` does not contain it (we did not
reject; we just timed out), and the `mempool` does not contain it,
so it will be re-requested — but only on a fresh inv from any peer.
If no peer ever re-announces, the tx is lost to us. Core re-requests
from the next-in-queue peer after `GETDATA_TX_INTERVAL`.

**File:** `app/Main.hs:2078-2080`.

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:38`
(`GETDATA_TX_INTERVAL{60s}`);
`bitcoin-core/src/node/txdownloadman_impl.cpp:278`
(`m_txrequest.RequestedTx(nodeid, hash, current_time + GETDATA_TX_INTERVAL)`).

**Impact:** drop in tx-propagation quality; orphans-of-orphans can
form because a parent tx that we requested-but-timed-out never
arrives, and the children never resolve.

---

## BUG-7 (P1) — No per-peer announcement cap

**Severity:** P1. Core's `MAX_PEER_TX_ANNOUNCEMENTS = 5000`
(txdownloadman.h:30) limits how many tx invs a single peer can have
queued at once; over the limit, additional inv vectors are silently
dropped (txdownloadman_impl.cpp:204). haskoin has no such per-peer
limit. The only cap is the global `recentlyRejectedRef < 50000`
check (Main.hs:1959), which is fleet-wide and only applies to
rejection-tracking, not to inv-acceptance.

A single malicious peer can flood our processing pipeline with 1M
distinct inv vectors in a single `MInv` (the wire decoder caps at
`maxInvSz = 50000` per message, but a peer can send 20 successive
`MInv` messages, each with 50k inv vectors); each one triggers a
mempool lookup, a `recentlyRejected` lookup, and (if unknown) a
GETDATA emit.

**File:** `app/Main.hs:2055-2080`.

**Core ref:** `bitcoin-core/src/node/txdownloadman.h:30`;
`bitcoin-core/src/node/txdownloadman_impl.cpp:204` (`Count(peer) >= MAX_PEER_TX_ANNOUNCEMENTS`).

**Impact:** per-peer DoS amplification; one peer dominating our
inv-processing throughput, starving honest peers' announcements.

---

## BUG-8 (P0) — No `m_tx_inventory_known_filter` on fast-path; we re-announce already-known invs

**Severity:** P0. Core maintains, per peer, a
`CRollingBloomFilter m_tx_inventory_known_filter{50000, 0.000001}`
(`net_processing.cpp:303`) that tracks BOTH directions of inv flow:
- On receipt of an inv from peer X, `AddKnownTx(peer X, inv.hash)`
  inserts into X's filter (line 1148).
- Before re-announcing to peer X, `m_tx_inventory_known_filter.contains(hash)`
  short-circuits (line 6067).

haskoin's MTx broadcast (Main.hs:1922-1929) has NO known-filter. We
re-send the inv to every peer including the one that just sent it to
us (BUG-9), and including peers that previously announced it to us.

The dead InvTrickler's `ptsSentFilter` (Network.hs:4664) is a
`TVar (Set TxId)` — a flat unbounded set, not a rolling bloom. Even
if it were wired up: (a) it's keyed by txid only (not wtxid) so
wtxid-relay peers' filter is wrong; (b) it never tracks what peers
ANNOUNCED to us (only what we sent); (c) it is only updated, never
rotated, so it grows unbounded.

**File:** `app/Main.hs:1921-1929` (no filter at all);
`src/Haskoin/Network.hs:4664, 4794` (`ptsSentFilter` unbounded `Set TxId`).

**Core ref:** `bitcoin-core/src/net_processing.cpp:303, 1148, 6067`.

**Impact:**
- Bandwidth waste: same tx inv'd repeatedly to peers that already
  saw it.
- Privacy: forwarding back to the source peer (BUG-9) is a
  side-channel for the source peer to confirm we accepted the tx.

---

## BUG-9 (P1) — MTx broadcast does not skip the source peer

**Severity:** P1. Bitcoin Core's `RelayTransaction` deliberately
skips the originating peer (`pnode != pfrom`) when broadcasting the
new tx inv. This serves two purposes:
1. **Bandwidth:** the peer obviously already has the tx.
2. **Privacy:** echoing back is a confirmation signal — a spy peer
   that ships us a unique transaction can detect "did this node
   accept my tx" by watching for the echo.

haskoin's MTx handler (`app/Main.hs:1921-1929`):

```haskell
peers <- readTVarIO (pmPeers pm)
forM_ (Map.elems peers) $ \pc -> do
  info <- readTVarIO (pcInfo pc)
  when (piState info == PeerConnected && not (piBlockOnly info)) $ do
    let (itype, ihash) = ...
    sendMessage pc (MInv (Inv [InvVector itype ihash]))
```

No `addr /= pcAddr` filter (the source peer's SockAddr is `addr`,
the handler arg). Every peer including the source gets the inv back.

Same shape applies to `announceTip` (BUG-28).

**File:** `app/Main.hs:1921-1929`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` (RelayTransaction
caller skips `pnode == pfrom`).

**Impact:**
- Confirms-tx-receipt side channel for spy peers (privacy leak).
- Bandwidth waste: 32-byte payload per accepted tx per peer
  including source; for 1000 txs/s and 8 peers that's ~256 KB/s of
  redundant inv traffic upper bound.

---

## BUG-10 (P0) — `recentlyRejectedRef` cleared on every block; not a rolling filter

**Severity:** P0. Core's `m_lazy_recent_rejects` is a
`CRollingBloomFilter(120000, 0.000001)` initialised on first use; it
rotates ~every 24 blocks but does NOT clear on each block. This
matters because a spammer's batch of junk txs persists in the filter
long enough that the spammer cannot just re-spray the same hashes on
every block.

haskoin's filter is a flat `IORef (Set TxId)`, initialised
`Set.empty` (`app/Main.hs:931`) and:

```haskell
-- Main.hs:1876, inside MBlock connect handler:
writeIORef recentlyRejectedRef Set.empty
```

Wiped to empty on EVERY block connect. The same junk can be replayed
on the very next block, triggering full re-validation, fee-estimation
work, and re-rejection — a perpetual amplification vector against
attackers willing to wait one block between identical re-spray
cycles.

Additionally, capacity is gated:

```haskell
-- Main.hs:1958-1960:
rejected <- readIORef recentlyRejectedRef
when (Set.size rejected < 50000) $
  writeIORef recentlyRejectedRef (Set.insert txid rejected)
```

Once at 50000 in a single block window, no more entries are added —
silent admission of further-rejected txs as "unknown" on the next
inv loop (which re-requests them via GETDATA).

**File:** `app/Main.hs:931, 1876, 1958-1960`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` (CRollingBloomFilter
size 120000 for `m_lazy_recent_rejects`, rotated not wiped).

**Impact:**
- Cross-block re-spray amplification (1 sat tx → block boundary
  → 1 sat tx → block boundary, repeat indefinitely with same
  validation cost per cycle).
- Capacity DoS: a peer that ships 50k unique junk txs in one block
  cycle elevates the filter to capacity; subsequent rejects are
  silently un-tracked.

---

## BUG-11 (P0-CDIV) — Reject-filter / mempool lookups use `TxId (ivHash iv)` for ALL inv types, breaking wtxid-keyed BIP-339 invs

**Severity:** P0-CDIV. `app/Main.hs:2058-2067`:

```haskell
unknown <- filterM (\iv -> do
      let txid = TxId (ivHash iv)
      if Set.member txid rejected
        then return False
        else do
          mEntry <- getTransaction mp txid
          case mEntry of
            Just _  -> return False
            Nothing -> return True
      ) txIvs
```

`txIvs` may contain `InvWtx` vectors (BIP-339), whose `ivHash` is the
**wtxid**, not the txid. But the lookup constructs
`TxId (ivHash iv)` and queries the mempool (keyed by txid) and the
reject set (keyed by txid). Both lookups will always miss for
wtxid-tagged invs — even when the tx IS in our mempool.

Consequence:
- Every wtxid-tagged inv (the BIP-339 path) is classified as
  "unknown" and triggers a fresh GETDATA — even for txs already in
  mempool.
- The "recently rejected" filter never applies to wtxid invs because
  we store rejections by txid, but look up by wtxid.

**File:** `app/Main.hs:2056-2067`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:303` —
`m_tx_inventory_known_filter` stores either txid or wtxid per peer's
`m_wtxid_relay` flag. The lookup respects the per-peer keying.

**Impact:**
- BIP-339 path is functionally degraded: every wtxid inv is a
  guaranteed GETDATA emit, defeating the BIP-339 efficiency benefit.
- Cross-impl divergence: a peer sending us a wtxid inv for a tx in
  our mempool gets a redundant GETDATA, which then resolves with us
  serving the tx back. Wasted RTT.

---

## BUG-12 (P2) — `maxOrphanTxs = 100` is the pre-2024 Core constant; current Core uses DoS-scored latency limit (DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000)

**Severity:** P2. `src/Haskoin/TxOrphanage.hs:62-64`:

```haskell
-- | Maximum orphan pool size (Bitcoin Core DEFAULT_MAX_ORPHAN_TRANSACTIONS=100).
maxOrphanTxs :: Int
maxOrphanTxs = 100
```

The cited constant `DEFAULT_MAX_ORPHAN_TRANSACTIONS` no longer exists
in current Bitcoin Core (grep confirms zero hits in `bitcoin-core/src/`).
Core replaced it with
`DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE = 3000`
(`bitcoin-core/src/node/txorphanage.h:23`) — a per-peer-weighted
latency-cost limit, where each orphan's contribution depends on its
input count and announcement count (txorphanage.cpp:61). The effective
orphan pool with N peers connected is much larger than 100 entries
(a typical 8-peer node holds ~24k orphan announcements).

haskoin's fixed 100-entry limit:
- Is far below what Core would tolerate, so honest orphans get
  evicted faster.
- Combined with BUG-13 (eviction by min-wtxid) and BUG-18
  (first-announcer locks in), the orphan pool is much more
  fragile against eviction abuse than current Core.

**File:** `src/Haskoin/TxOrphanage.hs:62-64`.

**Core ref:** `bitcoin-core/src/node/txorphanage.h:23` (current
constant `DEFAULT_MAX_ORPHANAGE_LATENCY_SCORE`).

**Impact:** smaller effective orphan pool than Core; doc-comment
references a constant that no longer exists.

---

## BUG-13 (P0) — `addOrphan` evicts by minimum wtxid (adversary-selectable)

**Severity:** P0. `src/Haskoin/TxOrphanage.hs:112-121`:

```haskell
let op' = if Map.size (orphanPool op) >= maxOrphanTxs
            then case Map.minViewWithKey (orphanPool op) of
                   Nothing -> op
                   Just ((_evictW, (evictTx, _, _)), m') ->
                     ...
```

`Map.minViewWithKey` on a `Map Wtxid v` returns the entry with the
**smallest Wtxid key**. A Wtxid is a hash; "smallest" is deterministic
and adversary-selectable.

A malicious peer can:
1. Grind a transaction with a low wtxid hash (cheap — a few thousand
   tries gets a wtxid starting `0x00`).
2. Announce that low-wtxid orphan.
3. Every subsequent OrphanPool eviction targets the lowest-wtxid
   entry — i.e., always evicts honest orphans, never the attacker's
   own low-wtxid grind-target.

This is the same shape as the Core CVE pattern Core eventually fixed
via the DoS-scored heap in `LimitOrphans` (txorphanage.cpp:442-525) —
evict the WORST PEER's OLDEST orphans, not whoever has the smallest
hash.

**File:** `src/Haskoin/TxOrphanage.hs:108-121`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp:442-525`
(`LimitOrphans` builds a max-heap of `(NodeId, DoS_score)` and evicts
oldest announcements from the worst peer).

**Impact:**
- Trivial DoS on the orphan pool: a single peer with a small grind
  budget can pin its own orphan(s) in the pool and force honest
  orphans to be evicted on every contention. With `maxOrphanTxs = 100`
  the attacker only needs ~100 grind-target invs to evict every
  honest orphan.
- Combined with BUG-16 (no periodic expiry), the attacker's pinned
  orphan stays in the pool until its 300-second expiry — but it's
  re-announced before then, restoring it indefinitely.

---

## BUG-14 (P1) — `eraseOrphansForBlock` skips conflict eviction; only removes orphans whose own txid was confirmed

**Severity:** P1. `src/Haskoin/TxOrphanage.hs:184-194`:

```haskell
eraseOrphansForBlock :: [TxId] -> IORef OrphanPool -> IO ()
eraseOrphansForBlock confirmedTxIds ref = modifyIORef' ref $ \op ->
  let confirmedSet = Set.fromList confirmedTxIds
      (keep, discard) = Map.partition
        (\(tx, _, _) -> not (Set.member (computeTxId tx) confirmedSet))
        (orphanPool op)
      ...
```

Only removes orphans whose own txid appears in the block. Core's
`EraseForBlock` (txorphanage.cpp:610-643) ALSO removes orphans whose
inputs **conflict** with the block — i.e., orphan O spending outpoint
`(parent.txid, k)` is evicted when ANY block tx spends the same
outpoint, even though O's own txid is not in the block. This handles
the "the orphan's parent was double-spent by a confirmed tx" case.

The comment at TxOrphanage.hs:175-183 is comment-as-confession (9th
distinct fleet pattern instance for haskoin):

> Core also removes orphans that /conflict/ with the block (spend the
> same inputs as confirmed txs). This implementation removes orphans
> whose own txid appears in the block, covering the primary case.

The "covering the primary case" understates the gap: in practice
conflict eviction is the more common path (most orphans are children
spending parents that get confirmed via a different chain of inputs).

This is architecturally locked-in: the secondary index
`orphanWtxid :: Map.Map TxId (Set.Set Wtxid)` is keyed by parent
**TxId only** (not COutPoint), so even if `eraseOrphansForBlock`
wanted to do conflict eviction, it cannot look up "which orphans spend
outpoint (X, k)" — it can only ask "which orphans claim parent X".

**File:** `src/Haskoin/TxOrphanage.hs:184-194` (eviction);
`src/Haskoin/TxOrphanage.hs:52` (index keyed by TxId not OutPoint).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp:610-643`
(EraseForBlock walks `block_tx.vin[i].prevout`).

**Impact:** orphans whose parents were double-spent by confirmed txs
linger in the pool until expiry; they will be re-validated on every
parent-accept retry (via `processOrphan`), always failing.

---

## BUG-15 (P1) — No orphan-pool cleanup on mempool RBF/conflict eviction

**Severity:** P1. `Mempool.blockConnected` (Mempool.hs:1831-1866)
removes conflicting transactions from the mempool. `Mempool.removeConflicts`
(line 1739-1822) removes RBF-conflict txs. Neither path calls into
the orphan pool. So when an in-mempool parent is RBF'd out, any
orphans waiting on that parent's outpoints (a) no longer have a
valid parent path AND (b) are not evicted from the orphan pool. They
sit until expiry (~5 minutes) or until the next block clears them
via BUG-14's narrow eviction.

Core handles this via the same `m_outpoint_to_orphan_wtxids` lookup
across both block and mempool removal paths (transitively through
`EraseForBlock` and reorg events).

**File:** `src/Haskoin/Mempool.hs:1739-1866`; absent in
`app/Main.hs` MBlock handler.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp` (EraseTx hooks
into mempool-removal paths via the m_outpoint_to_orphan_wtxids index).

**Impact:** orphan pool accumulates stale entries pointing at RBF'd
parents; combined with BUG-13 (min-wtxid eviction), this further
fragments honest-orphan capacity.

---

## BUG-16 (P1) — `expireOrphans` only runs on parent-accept; no periodic timer

**Severity:** P1. Single call site for `expireOrphans` in the entire
repo:

```bash
$ grep -rn "expireOrphans" /home/work/hashhog/haskoin/src /home/work/hashhog/haskoin/app
src/Haskoin/TxOrphanage.hs:136: expireOrphans :: IORef OrphanPool -> Int64 -> IO ()
app/Main.hs:65:   , addOrphan, expireOrphans
app/Main.hs:1581:    expireOrphans ref now
```

Line 1581 is inside `processOrphan` (Main.hs:1579-1603), which runs
only after a parent tx is successfully accepted into mempool. If no
parent is ever accepted (e.g., during a quiet period or an attack
where the attacker's orphans deliberately don't have available
parents), expired orphans linger past `orphanExpireSecs = 300` forever.

Core's expiry triggers on every `AddTx` path AND on every
`LimitOrphans` call (multiple call sites in
`txorphanage.cpp:350, 381, 410, 433, 642`).

**File:** `app/Main.hs:1581` (only call site).

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp:350, 381, 410, 433, 642`.

**Impact:** stale orphans persist past expiry during quiet periods.

---

## BUG-17 (P2) — Orphan secondary index keyed by parent TxId, not COutPoint (loses vout discrimination)

**Severity:** P2. `src/Haskoin/TxOrphanage.hs:52`:

```haskell
, orphanWtxid :: !(Map.Map TxId (Set.Set Wtxid))
  -- ^ Secondary index: parent TxId → Set of child Wtxids.
```

Core's equivalent `m_outpoint_to_orphan_wtxids` (txorphanage.h)
is keyed by `COutPoint(txid, vout)`. The difference:
- haskoin: "which orphans claim parent X" (any output of X)
- Core: "which orphans claim outpoint (X, k)" (specifically output k)

Correctness-neutral for the retry path (when X is accepted, retry
ALL children of X — Core walks each output `i ∈ [0, vout.size())`
which collectively covers all children). But the haskoin shape
prevents Core-style conflict eviction (BUG-14) and uses
worst-case-quadratic memory for parents with many outputs:
- Core: O(child_count) total entries across the index
- haskoin: O(child_count × parent_count_per_child) if a child spends
  multiple outputs of the same parent

**File:** `src/Haskoin/TxOrphanage.hs:52, 80-91, 100-131`.

**Core ref:** `bitcoin-core/src/node/txorphanage.h`
(`std::map<COutPoint, std::set<Wtxid>> m_outpoint_to_orphan_wtxids`).

**Impact:** architectural lock-in for BUG-14; minor memory
overhead.

---

## BUG-18 (P1) — `addOrphan` dedupes by wtxid; loses multi-announcer info; no random-announcer selection

**Severity:** P1. `src/Haskoin/TxOrphanage.hs:108-109`:

```haskell
in if Map.member wtxid (orphanPool op)
     then op  -- already present — deduplicate by wtxid
```

Once a wtxid is in the pool, subsequent announcements from OTHER
peers are silently dropped — including the announcer's `SockAddr`.
Only the FIRST announcer's address is stored (as the third tuple
element).

Core (`txorphanage.cpp:527-565`'s `AddChildrenToWorkSet`) tracks
ALL announcers (a `multi_index` keyed by `(Wtxid, NodeId)`) and:

```cpp
// Select a random peer to assign orphan processing, reducing wasted work if the orphan is still missing
// inputs. However, we don't want to create an issue in which the assigned peer can purposefully stop us
// from processing the orphan by disconnecting.
auto it_end = index_by_wtxid.upper_bound(ByWtxidView{wtxid, MAX_PEER});
const auto num_announcers{std::distance(it, it_end)};
if (!Assume(num_announcers > 0)) continue;
std::advance(it, rng.randrange(num_announcers));
```

The random-announcer selection is anti-DoS: a single first-announcer
peer cannot stop orphan processing by disconnecting; we round-robin
across all known announcers. Haskoin's first-announcer-wins means a
malicious peer can:
1. Be the first to announce an orphan.
2. Disconnect.
3. `eraseOrphansForPeer` (BUG: only called on graceful disconnect;
   not all disconnect paths reach it) evicts the orphan.
4. Honest re-announcers' subsequent `addOrphan` is a no-op because
   the wtxid was just re-inserted by step 3's race, OR fails to
   re-add because of capacity (BUG-13).

**File:** `src/Haskoin/TxOrphanage.hs:108-131, 47-56`.

**Core ref:** `bitcoin-core/src/node/txorphanage.cpp:542-557`
(random announcer selection).

**Impact:** orphan-processing DoS via deliberate first-announce +
disconnect.

---

## BUG-19 (P0) — Tx-inv processing runs unconditionally during IBD

**Severity:** P0. `app/Main.hs:2006-2080`:

```haskell
MInv (Inv ivs) -> do
  isIBD <- readIORef ibdModeRef
  unless isIBD $ do
    -- block-inv branch (IBD-gated)
    ...
  -- BUG-14 FIX: reject tx invs from block-relay-only peers.
  ...
  -- Tx-inv branch (NOT IBD-gated!) — runs even during IBD
  ...
  unless (null txIvs) $ do
    ...
    requestFromPeer pm addr (MGetData (GetData batch))
```

The `unless isIBD` guard wraps ONLY the block-inv branch (line 2011).
The tx-inv branch at line 2042+ runs unconditionally. During IBD:
- We issue GETDATA for every announced tx.
- The remote sends `MTx`.
- `MTx` runs `addTransaction mp tx` (Main.hs:1912), which depends on
  a synced chain to validate against. During IBD, mempool admission
  fails (missing parents, wrong feerate, etc.) and the tx lands in
  `recentlyRejectedRef` or the orphan pool.
- Net effect: hundreds of MB of bandwidth wasted on tx invs we
  cannot validate.

Core net_processing.cpp:4088 wraps `AddTxAnnouncement` in
`if (!m_chainman.IsInitialBlockDownload())`. Tx invs are noted via
`AddKnownTx` (so we know not to re-announce to that peer later) but
**no GETDATA is emitted** during IBD.

**File:** `app/Main.hs:2010, 2042-2080`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:4088`.

**Impact:**
- Bandwidth waste during IBD (significant on slow links).
- Orphan-pool fill: many txs received during IBD are inevitably
  orphans because we haven't validated their parents; they sit in
  the orphan pool consuming capacity (BUG-13 amplifies this).
- IBD slowdown: CPU spent on doomed `addTransaction` attempts.

---

## BUG-20 (P0) — `ibdModeRef` flips on header sync completion, not block sync; no tip-recency / MinimumChainWork check

**Severity:** P0. `app/Main.hs:1737-1741`:

```haskell
when (added > 0 && added < 2000) $ do
  wasIBD <- readIORef ibdModeRef
  when wasIBD $ do
    putStrLn "Header sync complete — leaving IBD mode"
    writeIORef ibdModeRef False
```

`ibdModeRef` flips to False when a single `getheaders` reply contains
< 2000 headers — i.e., HEADER sync is complete. But haskoin uses
headers-first sync (Main.hs:1714-1741), so when headers complete the
node has validated ZERO BLOCKS beyond the header chain. Block IBD
continues for hours afterwards. During that window:
- `ibdModeRef = False` says we're caught up.
- The actual block tip is potentially weeks behind.
- `getblockchaininfo.initial_block_download` (assuming a similar
  flag is plumbed) reports `false`.
- All IBD-gated behaviour above (BUG-19 block-inv branch in MInv)
  enables, even though no blocks have been validated.

Compare Core's `IsInitialBlockDownload` joint gate:
1. `chainstate.m_chain.Tip()->nChainWork >= MinimumChainWork()`
2. `chainstate.m_chain.Tip()->GetBlockTime() >= GetTime() - max_tip_age`
3. Latched one-way (never flips back).

haskoin checks NONE of (1), (2), (3) — purely "headers got short
batch".

**File:** `app/Main.hs:1737-1741, 929`.

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`
(`UpdateIBDStatus` joint MinimumChainWork + IsTipRecent gate).

**Impact:**
- IBD-gated optimisations (relay paused, peer scoring suppressed,
  banning relaxed) are dropped prematurely.
- A peer that fed us short header batches can trigger us to think
  IBD is over while we're still downloading every block.
- Wallets / monitoring tools that decide eligibility off
  `initial_block_download` would see incorrect "in sync" status
  potentially hours before block IBD finishes.

---

## BUG-21 (P1) — MFilterLoad / MFilterAdd / MFilterClear have no handlers

**Severity:** P1. `syncMessageHandler` in `app/Main.hs:1639-2403`
has cases for the Bitcoin messages it actually processes. Grep
finds NO case for `MFilterLoad`, `MFilterAdd`, or `MFilterClear`:

```bash
$ grep -n "MFilterLoad\|MFilterAdd\|MFilterClear\|bloom_filter\|m_bloom_filter" /home/work/hashhog/haskoin/app/Main.hs
(no output)
```

The wire types are decoded (Network.hs:1774-1776) but the message
falls through to whatever the default case is. SPV peers can `filterload`
us but the filter is never stored. The MMemPool handler does not
apply any per-peer bloom filter (BUG-22), confirming the absence
end-to-end.

**File:** `app/Main.hs:1639-2403` (no handler cases for
MFilterLoad/Add/Clear); `src/Haskoin/Network.hs:1774-1776` (wire
types defined but unused).

**Core ref:** `bitcoin-core/src/net_processing.cpp` (NetMsgType::FILTERLOAD,
FILTERADD, FILTERCLEAR handlers; per-peer
`tx_relay->m_bloom_filter`).

**Impact:**
- BIP-37 SPV clients cannot use this node for filtered relay.
- The `MMemPool` handler dumps the full mempool to an SPV peer that
  expected a filtered dump (privacy and bandwidth gap for the SPV).

---

## BUG-22 (P1) — MMemPool dumps full mempool without applying peer's bloom filter or feefilter

**Severity:** P1. `app/Main.hs:2384-2402` (MMemPool handler):

```haskell
txids <- getMempoolTxIds mp
let invs   = [ InvVector invKind (getTxIdHash t) | t <- txids ]
    chunks = chunksOf 50000 invs
forM_ chunks $ \chunk -> unless (null chunk) $
  requestFromPeer pm addr (MInv (Inv chunk))
```

No filter, no feefilter, no `m_send_mempool` one-shot gate (BUG-26).
A peer that asks for `mempool` gets EVERY txid in the mempool
returned, regardless of:
- The peer's BIP-37 bloom filter (BUG-21 — even if stored, would
  not be applied here).
- The peer's BIP-133 feefilter
  (`piFeeFilterReceived` field exists at Network.hs:4848 — used by
  the dead trickler, not here).

Compare Core (net_processing.cpp:5995-6024) which applies BOTH
filters per-tx before adding to vInv.

**File:** `app/Main.hs:2384-2402`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5995-6024`.

**Impact:**
- BIP-37 / BIP-133 violation: a peer that asked for filtered relay
  gets unfiltered.
- Bandwidth waste: with 100k-tx mempool, full dump is 3.2 MB of inv
  (32 bytes × 100k) per `mempool` request; multiply by every spy
  peer that opportunistically sends `mempool` for fingerprinting.

---

## BUG-23 (P1) — MMemPool ignores BIP-133 feefilter

**Severity:** P1. Subset of BUG-22; called out separately because
BIP-133 fee filter application is independent of BIP-37 bloom
filtering — it's "don't send txs the peer said they don't want via
feerate" (vs. "don't send txs that don't match the peer's bloom").
Both are missing from MMemPool.

**File:** `app/Main.hs:2384-2402`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:6013`
(`if (txinfo.fee < filterrate.GetFee(txinfo.vsize)) continue;`).

**Impact:** see BUG-22.

---

## BUG-24 (P0-SEC) — MTx broadcast ignores peer's `piRelay` (BIP-37 fRelay) flag

**Severity:** P0-SEC. `app/Main.hs:1924`:

```haskell
when (piState info == PeerConnected && not (piBlockOnly info)) $ do
```

Checks `not (piBlockOnly info)` but NOT `piRelay info`. `piRelay`
is set from the peer's `vRelay` in version message
(`src/Haskoin/Network.hs:2422`). Per BIP-37, when a peer sends
`fRelay=false` in version, the node MUST NOT send unsolicited tx
invs to that peer.

`piBlockOnly` is set only when WE initiated a block-relay-only
OUTBOUND connection (Network.hs:3426/3552/3620/3680). It is NOT
derived from the peer's `fRelay` claim. So an inbound peer with
`fRelay=false` (legitimately a wallet that doesn't want spam invs)
gets unsolicited tx invs anyway.

The dead trickler at Network.hs:4848 DOES honour `piRelay`:

```haskell
when (piState info == PeerConnected && piRelay info && not (piBlockOnly info)) $ do
```

— but the trickler is dead (BUG-1).

**File:** `app/Main.hs:1924`.

**Core ref:** `bitcoin-core/src/net_processing.cpp`
(`peer.GetTxRelay()` returns null when `fRelay=false`, suppressing
all tx-relay paths).

**Impact:**
- BIP-37 protocol violation.
- A wallet client that explicitly disabled tx relay still gets
  spammed.

---

## BUG-25 (P1) — Outbound GETDATA for wtxid-relay peers uses `InvWitnessTx` (=0x40000001), not `InvWtx` (=5)

**Severity:** P1. `app/Main.hs:2076`:

```haskell
let witnessTxIvs = map (\iv -> iv { ivType = InvWitnessTx }) unknown
```

This rewrites EVERY unknown tx-inv to `InvWitnessTx` (=0x40000001,
BIP-144 MSG_WITNESS_TX) before emitting GETDATA — even when the
inbound inv was `InvWtx` (=5, BIP-339 MSG_WTX). Core net_processing.cpp:6206
preserves the wtxid-vs-txid choice per peer:

```cpp
vGetData.emplace_back(gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | GetFetchFlags(peer)), gtxid.ToUint256());
```

For a wtxid-relay peer:
- Our inv processing accepts their `InvWtx` (=5) input.
- We emit GETDATA with `InvWitnessTx` (=0x40000001) instead of `InvWtx`.
- The peer's `m_tx_inventory_to_send` is keyed by wtxid; receiving
  a getdata for `MSG_WITNESS_TX` (a txid-based identifier) doesn't
  resolve against the wtxid set.

In practice Core's peer fall-through accepts MSG_WITNESS_TX getdata
as a legacy-compatible txid query and responds, so this is graceful
degradation. But:
- Round-trip is wasted (Core may answer with a tx the peer's
  filter then rejects).
- Strict BIP-339 implementations (rustoshi, hotbuns) may not
  respond to MSG_WITNESS_TX from a peer they thought was wtxid-relay.

**File:** `app/Main.hs:2076`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:6206`.

**Impact:** suboptimal BIP-339 round-tripping; potential interop
breakage with strict BIP-339 impls.

---

## BUG-26 (P1) — No `m_send_mempool` flag; peer can spam `mempool` for repeated full dumps

**Severity:** P1. Core's `m_send_mempool` is a one-shot flag set
when a peer's `mempool` message arrives; it is consulted in the
next SendMessages tick and cleared after the response. A peer
that sends two `mempool` messages back-to-back gets one response
(the second is collapsed into the first).

haskoin's MMemPool handler (Main.hs:2368-2402) runs immediately on
receipt with no de-duplication / rate limit / one-shot flag. A peer
can:
1. Send `mempool` → receive 100k inv vectors.
2. Send `mempool` again immediately → receive ANOTHER 100k inv vectors.
3. Loop indefinitely.

Each iteration triggers `getMempoolTxIds mp` (full mempool scan) and
emits 50000-inv chunks to the peer.

**File:** `app/Main.hs:2368-2402`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:5996, 6001`
(`m_send_mempool = false` after response).

**Impact:** trivial DoS vector — one peer can saturate our outbound
bandwidth by spamming `mempool`. The pmcPeerBloomFilters guard at
2374-2383 (disconnect-on-mempool-without-bloom-advertised) helps
when bloom is disabled, but with `peerbloomfilters=true` the DoS is
open.

---

## BUG-27 (P1) — `announceTip` never uses BIP-152 cmpctblock high-bandwidth path

**Severity:** P1. `app/Main.hs:1523-1534`:

```haskell
announceTip :: PeerManager -> BlockHeader -> BlockHash -> IO ()
announceTip pm header bh = do
  peers <- readTVarIO (pmPeers pm)
  let invVec = InvVector InvBlock (getBlockHashHash bh)
      invMsg = MInv (Inv [invVec])
      headersMsg = MHeaders (Headers [header])
  forM_ (Map.elems peers) $ \pc -> do
    info <- readTVarIO (pcInfo pc)
    when (piState info == PeerConnected) $ do
      let msg = if piWantsHeaders info then headersMsg else invMsg
      sendMessage pc msg
        ...
```

Picks between `MHeaders` (BIP-130 sendheaders) and `MInv`. Never
sends `MCmpctBlock` directly. Per BIP-152 / Core net_processing.cpp,
peers that registered as high-bandwidth cmpctblock recipients (via
`sendcmpct, 1, version=2`) receive the compact block directly as the
tip announcement — skipping the headers/inv stage entirely. haskoin
tracks `piWantsHeaders` (sendheaders state) but the BIP-152 high-bw
state is not consulted in announceTip.

The `MSendCmpct` handler (Main.hs:2353) is a no-op:

```haskell
MSendCmpct _ -> return ()
```

So even if a peer DID register as HB, we wouldn't know.

**File:** `app/Main.hs:1523-1534, 2353`.

**Core ref:** `bitcoin-core/src/net_processing.cpp` SendMessages
tip-announce branch (BIP-152 HB-peer fast path).

**Impact:** BIP-152 high-bandwidth optimisation absent; cmpctblock
propagation degrades to inv-getdata-block-or-cmpctblock round-trip
even with HB-capable peers.

---

## BUG-28 (P1) — `announceTip` does not skip source peer

**Severity:** P1. Same shape as BUG-9 but for block announcements.
`app/Main.hs:1523-1534` iterates `Map.elems peers` with no
source-peer filter. The peer that just sent us the block gets the
announcement back. Cross-cite W148 BUG-13 (the MBlock handler bans
peers for reorg announcements) — a peer with a recent reorg sends
us the new tip, we send it back as `MInv`, the peer sees an unsolicited
inv for a block they just sent us → could trigger their own bug, or
just waste bandwidth.

**File:** `app/Main.hs:1523-1534, 1893-1896`.

**Core ref:** Core's SendMessages tip-announce path skips
`pnode == pfrom` when announcing the new tip.

**Impact:** echo-back, cross-cite BUG-9 (privacy + bandwidth).

---

## BUG-29 (P1) — Two-pipeline guard: `computeWtxid` and `computeWtxId` coexist

**Severity:** P1 ("two-pipeline guard 17th distinct fleet
extension"). Two functions compute the wtxid:

```haskell
-- src/Haskoin/Crypto.hs:1064:
computeWtxid :: Tx -> Wtxid
computeWtxid tx = Wtxid $ doubleSHA256 (encode tx)

-- src/Haskoin/Consensus.hs:3000:
computeWtxId :: Tx -> TxId
computeWtxId tx = TxId (doubleSHA256 (encode tx))
```

Same bytes, different newtypes. Different consumers:
- `app/Main.hs:1920` uses `Haskoin.Crypto.computeWtxid`
  (qualified import as `Crypto.computeWtxid`).
- `src/Haskoin/Rpc.hs:5582` uses `Haskoin.Consensus.computeWtxId`.
- `src/Haskoin/TxOrphanage.hs:32` imports
  `Haskoin.Crypto.computeWtxid`.

Both happen to be byte-identical today. But the type difference
(`Wtxid` vs `TxId`) means a refactor that swaps the formula in one
place (e.g. to use a different encoder for SegWit wtxid) won't
propagate, and downstream consumers using `getTxIdHash` vs
`getWtxidHash` are coupling against the type rather than the
semantics.

In Rpc.hs line 2401:

```haskell
| piWtxidRelay info = (InvWtx, getTxIdHash wtxid)
```

— `wtxid` here is `computeWtxId tx :: TxId` (from Consensus.hs),
then `getTxIdHash :: TxId -> Hash256` extracts. The fact that the
type system silently allows this means a future swap of TxId →
Wtxid in just one of the two functions would silently mis-relay.

**File:** `src/Haskoin/Crypto.hs:1064`,
`src/Haskoin/Consensus.hs:3000`; consumers: `app/Main.hs:1920`,
`src/Haskoin/Rpc.hs:5582`, `src/Haskoin/TxOrphanage.hs:32`.

**Core ref:** Core has ONE function (`CTransaction::GetWitnessHash()`)
returning `Wtxid`.

**Impact:**
- API contract leak; future refactor risk.
- Cross-fleet two-pipeline-guard accounting — 17th distinct
  extension across the W76+ tracking (extends the W138-W141 ZMQ
  socket-per-topic, W142-W145 three-pipeline drift patterns).

---

## BUG-30 (P0) — Three-pipeline drift: MTx fast-path / RPC broadcastTxToPeers / dead InvTrickler all coexist with different semantics

**Severity:** P0 ("three-pipeline drift" — 4th distinct fleet
instance after W142 rustoshi 3-merkle, W143 ouroboros 3-consensus,
W145 clearbit 3-CheckTxInputs). Three distinct tx-relay implementations
coexist:

| Implementation | Location | Trickle | Source-skip | piRelay | piBlockOnly | known-filter | fee-filter |
|---|---|---|---|---|---|---|---|
| (a) MTx fast-path | Main.hs:1922-1928 | NO | NO | NO | yes | NO | NO |
| (b) RPC broadcastTxToPeers | Rpc.hs:2389-2404 | NO | n/a | NO | yes | NO | NO |
| (c) InvTrickler | Network.hs:4691-4825 (dead) | YES | n/a | yes | yes | partial (txid-keyed, unbounded) | YES |

All three are "RelayTransaction" analogs. Only (c) implements Core's
relay properly; only (a) and (b) actually run in production. The
divergence allows a class of bugs unique to having multiple paths:
- A fix to (a) (e.g. add source-skip) does not propagate to (b).
- (c) is the canonical "good" implementation but is never
  exercised, so it bit-rots — no CI test guards against it
  diverging from (a)/(b) over time.

This is the same shape as the W143 ouroboros finding (3 distinct
consensus pipelines including 2 dead) but specific to net code.
The W145 clearbit and W143 ouroboros precedents mean the operational
expectation should be: a single canonical helper consumed by all
relay paths, not three coexisting branches.

**File:** `app/Main.hs:1922-1928`, `src/Haskoin/Rpc.hs:2389-2404`,
`src/Haskoin/Network.hs:4691-4825`.

**Core ref:** `bitcoin-core/src/net_processing.cpp:2243-2264`
(`InitiateTxBroadcastToAll` — ONE canonical broadcaster).

**Impact:**
- Inconsistent relay semantics across entry points.
- Operational dead-code rot risk on (c).
- Bug-class amplifier: every BUG-1 through BUG-9 above multiplies
  by 2 (the two live paths), and BUG-1 alone disables BUG-21/22/23
  feefilter+bloom on the live paths.

---

## Carry-forwards (from prior waves)

- **W144 BUG-3 STANDARD_SCRIPT_VERIFY_FLAGS entirely absent** —
  CONFIRMED LIVE. Grep for `STANDARD_SCRIPT_VERIFY_FLAGS` /
  `standardFlags` / `StandardScriptVerify` in
  `src/Haskoin/Policy/Standard.hs` and `src/Haskoin/Script.hs`
  returns nothing meaningful. Mempool admission still routes through
  the MANDATORY-only 7-member set. The W150/W151 confirmations carry
  forward to W152.
- **W148 BUG-13 MBlock handler bans peers announcing reorgs** —
  out of scope for this audit; cross-cite BUG-28 (`announceTip` echoes
  block back to source peer; if the peer responds with `MBlock` or
  re-announces, the ban path triggers).
- **W148 BUG-3 + BUG-11 performReorg writes only undo** — out of scope.
- **W150 BUG-1 mpHeight=0 startup gap** — out of scope for tx-relay
  surface but cross-cite BUG-19/BUG-20: if mpHeight=0 at startup AND
  `ibdModeRef` flips early (BUG-20), the tx-relay path admits txs
  against an empty mempool/chainstate. Tx-relay BUG class compounds.
- **W151 BUG-2 submitpackage does not broadcast** — CONFIRMED LIVE.
  `Rpc.hs:5537-5731` `handleSubmitPackage` / `submitPackageTxns`
  has zero `broadcastTxToPeers` calls; compare `sendrawtransaction`
  at Rpc.hs:2283 which does broadcast. Verified by reading the
  submitPackageTxns function end-to-end (lines 5616-5706 — every
  return path is `buildSuccessResponse` or `buildAbortResponse` with
  no relay). 

---

## Summary

**Bug count:** 30 (BUG-1 through BUG-30).

**Severity distribution:**
- **P0 / P0-SEC / P0-CDIV:** 12 (BUG-1, BUG-4, BUG-5, BUG-8, BUG-10,
  BUG-11, BUG-13, BUG-19, BUG-20, BUG-24, BUG-30; plus implicit
  P0-CDIV in BUG-11 wtxid/txid lookup mismatch)
- **P1:** 16 (BUG-2, BUG-6, BUG-7, BUG-9, BUG-14, BUG-15, BUG-16,
  BUG-18, BUG-21, BUG-22, BUG-23, BUG-25, BUG-26, BUG-27, BUG-28,
  BUG-29)
- **P2:** 2 (BUG-3, BUG-12, BUG-17 — recount: BUG-3, BUG-12, BUG-17 = 3)

Recount: P0/P0-SEC/P0-CDIV = BUG-1, BUG-4, BUG-5, BUG-8, BUG-10,
BUG-11, BUG-13, BUG-19, BUG-20, BUG-24, BUG-30 = **11**.
P1 = BUG-2, BUG-6, BUG-7, BUG-9, BUG-14, BUG-15, BUG-16, BUG-18,
BUG-21, BUG-22, BUG-23, BUG-25, BUG-26, BUG-27, BUG-28, BUG-29 = **16**.
P2 = BUG-3, BUG-12, BUG-17 = **3**. Total **30**. ✓

**Fleet patterns confirmed:**
- **dead-module / dead-subsystem fleet pattern** (BUG-1, BUG-21) —
  haskoin carrier: InvTrickler ~280 LOC unreferenced;
  MFilterLoad/Add/Clear handlers entirely absent. Self-documented
  by test/W103TxRelaySpec.hs:883 asserting the bypass.
- **three-pipeline drift** (BUG-30) — 4th distinct fleet instance
  (after W142 rustoshi 3-merkle, W143 ouroboros 3-consensus, W145
  clearbit 3-CheckTxInputs). MTx fast-path + RPC broadcastTxToPeers
  + dead InvTrickler all implement RelayTransaction with different
  semantics.
- **two-pipeline guard 17th distinct extension** (BUG-29) — two
  computeWtxid functions returning different newtypes.
- **comment-as-confession 9th distinct haskoin instance** (BUG-3
  comment cites wrong constant; BUG-14 comment admits gap).
- **already-exports-the-primitive-just-not-called** (BUG-1) —
  newInvTrickler / queueTxForTrickling / startTrickleThread all
  exported, none called. Cross-cite W140 haskoin
  `constantTimeEq exported-but-not-called`.
- **non-exhaustive ADT → silent fallthrough** (BUG-21) — MFilterLoad
  / MFilterAdd / MFilterClear constructors defined in `Message` ADT
  but no case in syncMessageHandler. Symptom is silent ignore, not
  runtime crash (case is total because handler is `case msg of` with
  exhaustive coverage via a catch-all `_ -> return ()` implicit
  fallthrough — would need to verify, but the practical effect is
  the same).
- **STANDARD-flags-incomplete (haskoin carrier)** — W144 BUG-3
  carry-forward CONFIRMED LIVE for the third wave running.
- **secret deployment-topology dependency** (BUG-20) — IBD-exit
  semantics depend on whether the **peer's** header stream ended
  early; not on our own validation state.
- **carry-forward re-anchor** — W151 BUG-2 submitpackage-doesn't-broadcast
  CONFIRMED LIVE; that's a relay-surface bug that should have been
  caught in W151 fix wave; restating here for tracking.

**Top three findings:**
1. **BUG-1 (P0 InvTrickler dead) + BUG-30 (P0 three-pipeline drift)**
   — the entire BIP-133 / privacy / known-filter / batching machinery
   is implemented (correctly) and exported, but never called. Live
   tx relay runs immediate per-peer per-tx with no batching, no
   feefilter, no source-skip, no known-filter. Test suite documents
   the bypass as a passing assertion. This single architectural gap
   amplifies BUG-8, BUG-9, BUG-22, BUG-23, BUG-24 — five other P0/P1
   findings would resolve if MTx routed through the trickler.
2. **BUG-11 (P0-CDIV wtxid/txid lookup mismatch)** — tx-inv resolution
   constructs `TxId (ivHash iv)` for ALL inv types, treating BIP-339
   wtxids as if they were txids. Mempool and reject-filter lookups
   always miss for wtxid invs → every wtxid inv from a wtxid-relay
   peer triggers a redundant GETDATA, defeating BIP-339's deduplication
   benefit. Cross-impl divergence with anyone running BIP-339-strict
   relay.
3. **BUG-19 (P0 tx-inv during IBD) + BUG-20 (P0 IBD-exit on header
   sync not block sync)** — `ibdModeRef` flips early (when headers
   complete, not when blocks do), and tx-inv processing has no
   IBD gate even before that flip. During IBD we issue GETDATA for
   tx invs we cannot validate; the txs land in `recentlyRejectedRef`
   or orphan pool. Plus the IBD-exit gate ignores tip-recency and
   minimum-chainwork — purely "headers got short batch". Compounds
   with BUG-13 orphan eviction by min-wtxid to fill the orphan pool
   with attacker-pinned junk during IBD.

**Carry-forwards confirmed LIVE this wave:**
- W144 BUG-3 STANDARD_SCRIPT_VERIFY_FLAGS absent (3rd wave running).
- W151 BUG-2 submitpackage does not broadcast (2nd wave running).

# W148 — Headers-first sync + chain selection + reorg (haskoin)

**Wave:** W148 — `ProcessNewBlockHeaders`, `AcceptBlockHeader`,
`ActivateBestChain`, `ActivateBestChainStep`, `ConnectTip`, `DisconnectTip`,
`FindMostWorkChain`, `MAX_REORG_DEPTH`/`MIN_BLOCKS_TO_KEEP`, `CBlockIndex`
validity bitfield (`BLOCK_VALID_TREE`/`TRANSACTIONS`/`CHAIN`/`SCRIPTS`),
`m_chain_tx_count`, `m_best_header`, `InvalidChainFound`,
`ResetBlockFailureFlags`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/validation.cpp:4183-4239` — `AcceptBlockHeader`
  (PoW + context check + bad-prevblk + min_pow_checked gate +
  AddToBlockIndex + `m_best_header` update).
- `bitcoin-core/src/validation.cpp:4242-4270` — `ProcessNewBlockHeaders`
  (batch acceptance under cs_main; `CheckBlockIndex` after each;
  `NotifyHeaderTip`).
- `bitcoin-core/src/validation.cpp:3114-3171` — `FindMostWorkChain`
  (reverse iter over `setBlockIndexCandidates`; ancestor `BLOCK_FAILED_VALID`
  + `BLOCK_HAVE_DATA` filter; candidate erase on failure).
- `bitcoin-core/src/validation.cpp:3191-3280` — `ActivateBestChainStep`
  (DisconnectTip loop to fork; vpindexToConnect descending walk in chunks
  of 32; ConnectTip loop; `MaybeUpdateMempoolForReorg`).
- `bitcoin-core/src/validation.cpp:3323-3450` — `ActivateBestChain`
  (do-while loop; releases `cs_main` between iterations; breaks on
  `pindexMostWork == m_chain.Tip()`).
- `bitcoin-core/src/validation.cpp:2900-3000` — `ConnectTip`
  (block read; ConnectBlock + chainstate write + UpdateTip).
- `bitcoin-core/src/validation.cpp:3055-3107` — `DisconnectTip`
  (read CBlockUndo; DisconnectBlock; mempool refill).
- `bitcoin-core/src/validation.cpp:3711-3730` — `ResetBlockFailureFlags`
  (filters by ancestor/descendant relation AND `BLOCK_FAILED_VALID`; does
  NOT touch non-failed ancestors).
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` (`m_cached_is_ibd` latched
  to false when `IsTipRecent(MinimumChainWork(), max_tip_age)`).
- `bitcoin-core/src/validation.cpp:1964-1984` — `InvalidChainFound`
  (sets `m_best_invalid`; recomputes `m_best_header` if current best_header
  descends from invalid pindex).
- `bitcoin-core/src/validation.cpp:3765-3815` — `ReceivedBlockTransactions`
  (sets `nTx` and `m_chain_tx_count`; walks descendants to propagate).
- `bitcoin-core/src/chain.h:42-86` — `BlockStatus` enum (5-level ordered
  validity ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS plus
  HAVE_DATA/HAVE_UNDO/FAILED_VALID/FAILED_CHILD/OPT_WITNESS bits and
  `BLOCK_VALID_MASK = 7`).
- `bitcoin-core/src/chain.h:120-129` — `CBlockIndex::nTx`,
  `m_chain_tx_count` fields.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.

**Files audited**
- `src/Haskoin/Consensus.hs` — `addHeader` (3944-4081),
  `addSideBranchHeader` (4106-4133), `HeaderChain` / `ChainEntry`
  (3699-3717), `initHeaderChain` (3888-3913), `findForkPoint`
  (4145-4165), `getAncestor` (4170-4181), `ancestorAtHeight`
  (444-451), `performReorg` (4621-4646), `disconnectChain`
  (4651-4667), `connectChain` (4671-4712), `invalidateBlock`
  (5002-5074), `activateBestChain` (5098-5134), `reconsiderBlock`
  (5146-5175), `maxReorgDepth=100` (3566-3567), `BlockStatus`
  (Storage.hs:1506-1518), `isFailedStatus` (5089-5093),
  `connectBlockAt` (3095-3199), `handleHeaders` (4243-4264).
- `src/Haskoin/Sync.hs` — `BlockDownloader` / `bdIBDActive`
  (91-116), `blockProcessor` (349-477), `PRESYNC`/`REDOWNLOAD` state
  machine (530-879), `startIBD` / `stopIBD` (146-203).
- `src/Haskoin/BlockTemplate.hs` — `submitBlockSideBranch`
  (666-726), `findSideBranchForkPoint` (739-802),
  `doSideBranchReorg` (837-940), `maxReorgDepth` usage (853-859).
- `app/Main.hs` — `initHeaderChainFromDB` (1385-1450),
  `syncMessageHandler` `MHeaders` (1643-1751), `MBlock` (1753-1908),
  `ibdModeRef` toggles (929, 1738-1741), `requestedUpToRef` /
  `fTooFarAhead` gate (1775-1784).
- `src/Haskoin/Storage.hs` — `BlockStatus` (1506-1518),
  `putBlockStatus`/`getBlockStatus` (1521-1531), `minBlocksToKeep`
  (2149-2150).
- `src/Haskoin/Rpc.hs` — `estimateIsInitialBlockDownload`
  (9142-9153).

---

## Gate matrix (30 sub-gates / 8 behaviours)

| #  | Behaviour | Sub-gate | Verdict |
|----|-----------|----------|---------|
| 1  | AcceptBlockHeader contract | G1: PoW + MTP + difficulty + +2h future + BIP-94 validated | PASS (`Consensus.hs:3965-4000`) |
| 1  | … | G2: `m_best_header` advanced independently of full validation | PARTIAL — `hcTip` doubles as both "best header" AND "active connected tip" (BUG-3) |
| 1  | … | G3: header rejected if `pprev->nStatus & BLOCK_FAILED_VALID` ("bad-prevblk") | **BUG-1 (P0-CDIV)** `addHeader` never checks `parent.Status.isFailedStatus`; descendants of an invalidated parent enter `hcEntries` unmarked |
| 1  | … | G4: `min_pow_checked` boolean threaded to header acceptance | PASS (`Consensus.hs:4037`, peer paths pass False) |
| 1  | … | G5: empty headers message is no-op (no Misbehaving) | PASS (`Main.hs:1656` fold over empty list returns (0,0,0)) |
| 2  | CChain m_chain tip pointer | G6: random-access `m_chain[height]` semantics | PARTIAL — `hcByHeight :: Map Word32 BlockHash` is O(log N) and only writes a SINGLE entry on tip-flip (BUG-4) |
| 2  | … | G7: `m_chain.Genesis()` / `Tip()` accessors | PASS (`getChainTip` 4136-4137) |
| 2  | … | G8: `m_chain.FindFork(other_chain)` | **BUG-5 (P1)** `findForkPoint` walks `Parent` pointers O(h); no skip-list. `ancestorAtHeight` same shape |
| 3  | ActivateBestChain loop | G9: do-while loop iterates until `pindexMostWork == Tip()` | **BUG-6 (P0)** `activateBestChain` is a single-pass best-tip pick + single `performReorg`; no outer loop. Only fires from `invalidateBlock`/`reconsiderBlock` RPCs — NOT from `addHeader` or P2P `MBlock` paths |
| 3  | … | G10: releases lock between iterations for responsiveness | N/A — no outer loop exists |
| 3  | … | G11: `MaybeUpdateMempoolForReorg` after each ConnectTip | **BUG-7 (P1)** `performReorg` never re-validates mempool against new tip; `connectChain` and `submitBlockSideBranch` both bypass mempool re-validation post-connect |
| 3  | … | G12: vpindexToConnect chunked by 32 to bound stack frame | **BUG-8 (P2)** `doSideBranchReorg` builds full disconnect+connect list in one shot (BlockTemplate.hs:851-877); no chunking |
| 4  | MAX_REORG_DEPTH guard | G13: refuse `disconnect+connect > 100` | PRESENT but constant DIVERGES from Core; Core has **NO** MAX_REORG_DEPTH — see **BUG-9 (P0-CDIV)** |
| 4  | … | G14: error message identifies the limit | PASS (`BlockTemplate.hs:855-858`) |
| 4  | … | G15: operator override to bypass cap | **BUG-10 (P1)** `maxReorgDepth=100` is a compile-time constant (`Consensus.hs:3567`); no `-maxreorgdepth` knob |
| 5  | ConnectTip semantics | G16: ConnectBlock + chainstate write + UpdateTip atomic | PARTIAL — `connectBlockAt` writes BestBlock+BlockHeader+BlockHeight+UTXOs+undo atomically (PASS); but `performReorg`→`connectChain` writes ONLY undo data, never updates BestBlock/UTXOs (BUG-11) |
| 5  | … | G17: on failure, block marked `BLOCK_FAILED_VALID` and chain disconnected | **BUG-12 (P0-CDIV)** failed `validateFullBlockIO` / `connectBlockAt` returns error but never calls `putBlockStatus`. `ceStatus` stays `StatusHeaderValid`/`StatusValid`. Next `activateBestChain` re-selects the same failing block. |
| 5  | … | G18: IBD-side accepts non-extending block as side-branch via `AcceptBlock` storage | PARTIAL — `submitBlock` has the side-branch path (`addSideBranchHeader` + `doSideBranchReorg`), but the **P2P-driven `MBlock` handler never invokes it** (BUG-13) |
| 6  | DisconnectTip semantics | G19: rev*.dat undo applied in reverse | PASS via `disconnectChain` → `unapplyBlock` (4651-4667) |
| 6  | … | G20: DISCONNECT_UNCLEAN logged but not fatal | PASS (`DisconnectResult` triple at 3219-3223; `applyTxInUndo` records UNCLEAN) |
| 6  | … | G21: failure halts (Core `FatalError`), not silent | PARTIAL — `disconnectChain` returns `Left err`; `performReorg`/`invalidateBlock` propagate as `InvalidateDisconnectFailed`; no `FatalError` halt |
| 7  | CBlockIndex validity bitfield | G22: 5-level ordered ladder UNKNOWN/RESERVED/TREE/TRANSACTIONS/CHAIN/SCRIPTS | **BUG-14 (P1)** `BlockStatus` (Storage.hs:1506-1514) is a 7-tag sum with `Enum` 0..6: `StatusUnknown/HeaderValid/DataReceived/Valid/Invalid/FailedValid/FailedChild`. Collapses Core's 5-level ladder into one, conflates failure with level, loses HAVE_DATA / HAVE_UNDO / OPT_WITNESS bits. Cannot express `BLOCK_VALID_TRANSACTIONS` (have body, no chain-validity yet) which Core's assume-valid IBD needs |
| 7  | … | G23: `BLOCK_HAVE_DATA` set after block body lands on disk | **BUG-15 (P1)** no `StatusDataReceived` is ever set by `connectBlockAt` / `Main.hs:MBlock` / `blockProcessor` — `putBlockStatus` is called only from `invalidateBlock` (5034) and `reconsiderBlock` (5168). The DataReceived constructor exists but no production path writes it |
| 7  | … | G24: `BLOCK_HAVE_UNDO` set after rev*.dat write | MISSING — no `StatusHaveUndo` constructor at all in `BlockStatus`; subset of BUG-14 |
| 7  | … | G25: `BLOCK_FAILED_CHILD` propagated to descendants on InvalidateBlock | PASS (`invalidateBlock` 5022-5024 maps direct → `FailedValid`, descendants → `FailedChild`) |
| 7  | … | G26: persisted to disk so flags survive restart | **BUG-16 (P0-CDIV)** `initHeaderChainFromDB` (`Main.hs:1429`) hardcodes `ceStatus = StatusValid` for every loaded entry, ignoring the persisted `PrefixBlockStatus` entries. A `StatusFailedValid` written before shutdown is resurrected as `StatusValid` on restart |
| 8  | m_chain_tx_count + m_chain_work | G27: per-block cumulative tx counter set at header acceptance | **BUG-17 (P1)** `ChainEntry` (3699-3707) has NO `ceTx` or `ceChainTxCount` field. `getblockchaininfo`/`verificationprogress` cannot consult cumulative tx density; falls back to height-only interpolation |
| 8  | … | G28: m_chain_work cumulative chainwork maintained | PASS (`ceChainWork`; `cumulativeWork` 3733-3734) |
| 8  | … | G29: ResetBlockFailureFlags clears only FAILED bits (not arbitrary ancestor flags) | **BUG-18 (P1)** `reconsiderBlock` (5163-5168) walks descendants and unconditionally OVERWRITES `ceStatus` to `StatusHeaderValid` — losing existing `StatusValid` / `StatusDataReceived` levels and forcing full re-validation of every descendant from scratch (Core's `ResetBlockFailureFlags` only clears the FAILED bit, leaves underlying validity level intact) |
| 8  | … | G30: `IsInitialBlockDownload` exit gated on tip-recent + MinimumChainWork | **BUG-19 (P0-CDIV)** TWO competing IBD predicates: (a) `ibdModeRef` (Main.hs:929) flipped to False the first time `MHeaders` returns < 2000 headers AND never flipped back; (b) `estimateIsInitialBlockDownload` (Rpc.hs:9142) hardcodes `estimatedCurrentTime = 1231006505 + 850000*600` (a fixed point in late 2024) so the predicate goes permanently false ~2 years from now. Neither uses Core's tip-age + MinimumChainWork model. RPC and consensus disagree on IBD state |

---

## BUG-1 (P0-CDIV) — `addHeader` never checks `parent.Status` for invalid

**Severity:** P0-CDIV. Bitcoin Core's `AcceptBlockHeader`
(validation.cpp:4220-4223) rejects with `"bad-prevblk"` /
`BLOCK_INVALID_PREV` when `pindexPrev->nStatus & BLOCK_FAILED_VALID`.
haskoin's `addHeader` (Consensus.hs:3944-4081) validates PoW, MTP, BIP-94,
+2h future-time, difficulty bits, checkpoint, and too-little-chainwork —
but never inspects `isFailedStatus (ceStatus parent)`.

A peer can extend a chain rooted at an explicitly-invalidated block (via
`invalidateblock` RPC) and every successor header is silently grafted
into `hcEntries`. The descendants get `StatusFailedChild` ONLY when
`invalidateBlock` walks them via `findDescendants` — but `findDescendants`
runs ONCE, at the moment of invalidation; any header arriving AFTER the
invalidation that builds on the bad subtree enters the index unmarked.

**File:** `src/Haskoin/Consensus.hs:3944-3989` (`addHeader`)

**Core ref:** `bitcoin-core/src/validation.cpp:4220-4223`

**Excerpt (haskoin, missing check)**
```haskell
addHeader net hc header minPowChecked = do
  ...
  Nothing -> case Map.lookup prevHash entries of
    Nothing -> return $ Left ("Unknown previous block: " ++ ...)
    Just parent -> do            -- ← NO parent.Status check
      let height = ceHeight parent + 1
      if not (checkProofOfWork header (netPowLimit net))
        then return $ Left "Proof of work check failed"
        ...
```

**Excerpt (Core, the gate haskoin lacks)**
```cpp
if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
    return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV,
                         "bad-prevblk");
}
```

**Impact:** post-invalidation, an attacker (or honest peer with a stale
header) can re-populate `hcEntries` with the entire bad subtree. The
peer is not misbehaving-scored. On the next `activateBestChain` call,
the candidate filter (5114-5117) checks `StatusValid` and the
`hcInvalidated` set, but only the explicitly-marked target block is in
the set — the freshly-arrived descendants slip through with their
default `StatusHeaderValid` and stay in the index until the next
invalidate-cycle traverses them.

---

## BUG-2 (P0-CDIV) — `connectChain` hardcodes `mainnet` regardless of actual network

**Severity:** P0-CDIV (consensus divergence on regtest/testnet reorgs).
`connectChain` (Consensus.hs:4671-4702) takes a `HeaderChain` as
parameter (which knows its network indirectly through chain entries),
but when invoking `applyBlock` for each block to re-connect during a
reorg, it passes the literal `mainnet` value:

```haskell
result <- applyBlock cache mainnet block (ceHeight ce) prevBlockMTP getMTP
```

`applyBlock` consults `net` for:
- `bip68Active net height` (BIP-68 sequence-lock activation height)
- `consensusFlagsAtHeight net height` (SegWit, Taproot, CLEANSTACK,
  CHECKLOCKTIMEVERIFY, etc.)
- network-specific subsidy / halving interval (via downstream calls)

On testnet4 / signet / regtest a reorg via `invalidateBlock` →
`activateBestChain` → `performReorg` → `connectChain` will re-validate
the connect-chain using **mainnet** consensus rules. Regtest typically
has different BIP-9 / segwit activation heights; the wrong activation
height changes script flags; a Taproot-signed regtest input fails
under mainnet's activation height calculation and the block is
rejected — or worse, an invalid block passes.

**File:** `src/Haskoin/Consensus.hs:4695`

**Core ref:** `bitcoin-core/src/validation.cpp:3115` (`ConnectBlock`
takes the active chainparams from the chainstate manager).

**Impact:** Any reorg path that flows through `performReorg` on
non-mainnet networks runs validation against the wrong consensus
rules. Note `doSideBranchReorg` (the `submitblock` RPC path) does NOT
have this bug — it threads `net` correctly. So `submitblock` reorgs
follow the right rules; `invalidateblock`-triggered reorgs do not.
**Two-pipeline guard** — the two reorg pipelines diverge on which
network parameters they obey.

---

## BUG-3 (P0-CDIV) — `performReorg` mutates only the UTXOCache and undo data; never updates on-disk BestBlock / UTXOs / hcTip

**Severity:** P0-CDIV (catastrophic). `performReorg` (Consensus.hs:4621-4646)
calls `disconnectChain` → `unapplyBlock` (cache only, no disk) and
`connectChain` → `applyBlock` (cache only) + `putUndoData`. It NEVER:
- writes the new `PrefixBestBlock` pointer
- deletes spent UTXOs from disk
- writes new UTXOs to disk
- updates `PrefixBlockHeight` for blocks now on the new chain
- updates `hcTip` / `hcHeight` / `hcByHeight`

After `performReorg` returns Right (), the on-disk chainstate is in the
PRE-REORG configuration but the in-memory `UTXOCache` reflects the
POST-REORG state. On next `flushCache` the cache wins — the on-disk
UTXO set ends up in a HYBRID state with some spends removed, others not.
A process restart re-derives `hcTip` from disk (`initHeaderChainFromDB`
walks `PrefixBlockHeight`) — and recovers the OLD tip, not the new one.

The author of `doSideBranchReorg` was aware of this and inlined an entire
parallel reorg implementation that DOES write to disk, explicitly noting
(BlockTemplate.hs:696-707):

> "We bypass the `performReorg` top-level helper because it does not
> maintain the on-disk `PrefixUTXO` / `PrefixBestBlock` /
> `PrefixBlockHeight` entries that `gettxoutsetinfo` / restart recovery
> rely on."

This is a **comment-as-confession**: the comment names the bug and the
codebase has TWO reorg pipelines — one fully correct
(`doSideBranchReorg`, submitblock RPC), one broken (`performReorg`,
invalidateblock/reconsiderblock RPC). The broken one is the one wired
into `activateBestChain` (5129) for general best-chain selection.

**File:** `src/Haskoin/Consensus.hs:4621-4646`, `4671-4702`

**Core ref:** `bitcoin-core/src/validation.cpp:2900-3000` (`ConnectTip`
writes chainstate THEN updates UpdateTip atomically per-block).

**Impact:** every `invalidateblock` followed by a higher-work
alternative chain emerging produces a hybrid disk state. On restart
the node returns to the invalidated chain. Cross-cite: explicit
two-pipeline-guard finding; **15th distinct fleet two-pipeline
instance** (per memory index W142-W145 quad-audit count).

---

## BUG-4 (P0-CDIV) — `addHeader` writes only ONE `hcByHeight` entry on tip-flip; lower heights still point at the old branch

**Severity:** P0-CDIV. `addHeader` (Consensus.hs:4073-4079) inserts
the new header into `hcEntries`, then if its work exceeds the current
tip's work it writes:

```haskell
modifyTVar' (hcByHeight hc) (Map.insert height hash)   -- only THIS height
writeTVar (hcTip hc) entry
writeTVar (hcHeight hc) height
```

If the new tip is on a different branch than the prior tip, EVERY
height between the fork point and the new tip needs `hcByHeight`
rewritten — but only the new-tip height gets touched. Heights below
the new tip still point at the OLD chain's block hashes.

Downstream consequences:
- `buildBlockLocatorFromChain` (4274-4279) walks `hcByHeight` to build
  the getheaders locator. Post-tip-flip, the locator contains a
  mixture of new-tip and old-chain hashes — peers see a nonsensical
  fork claim.
- `connectChain` (4682) looks up MTPs via `hcByHeight` for the
  `getMTP` helper. Returns OLD chain's MTPs, breaking BIP-113 locktime
  evaluation on the reconnect.
- `bdCurrentHeight` (Sync.hs:99, "Highest connected block") is read in
  IBD's `blockProcessor` (Sync.hs:356-360); the next-to-download hash
  is read from `hcByHeight`. After a side-branch tip-flip without
  full reorg, IBD will request the OLD chain's block at the new
  height, fail to validate (wrong parent), and stall.

**File:** `src/Haskoin/Consensus.hs:4073-4079`

**Core ref:** `bitcoin-core/src/chain.cpp` `CChain::SetTip` walks
from new tip back to fork, rewriting `vChain[i]` for every height.

**Impact:** after a tip-flip the in-memory chain index is internally
inconsistent. The header layer "knows" the new tip but the height-index
map disagrees. Cross-cite to BUG-3: same family of "in-memory state
mutated but persistent / supporting state not synchronized".

---

## BUG-5 (P1) — `findForkPoint` walks `Parent` pointers; no skip-list

**Severity:** P1 (performance). Core's `CBlockIndex::GetAncestor`
uses `pskip` to make ancestor walks O(log h). haskoin's
`ancestorAtHeight` (444-451) and `findForkPoint` (4145-4165) both
recurse on `cePrev` one block at a time. `findForkPoint` walks BOTH
chains down to common ancestor.

**File:** `src/Haskoin/Consensus.hs:444-451`, `4145-4165`

**Core ref:** `bitcoin-core/src/chain.h:189-201` (`pskip` field
construction in `CBlockIndex::BuildSkip`).

**Impact:** on a deep reorg request (`reconsiderblock` reaching far
back), `findForkPoint` walks ~100k parents per side under
implicit-STM read of `hcEntries`. Combined with BUG-6 (no chunking +
no lock release) this serializes the whole node behind the operation.

---

## BUG-6 (P0) — No `ActivateBestChain` outer loop; chain selection only fires from RPC paths

**Severity:** P0 (semantic gap). Bitcoin Core's `ActivateBestChain`
(validation.cpp:3323-3450) is the central chain-selection driver:
called from `ProcessNewBlock`, `ProcessNewBlockHeaders` (indirectly
via `NotifyHeaderTip`), `submitblock`, `invalidateblock`,
`reconsiderblock`, `preciousblock`. It re-runs `FindMostWorkChain`
in a do-while loop until the most-work candidate equals the active
tip, releasing `cs_main` between iterations.

haskoin's `activateBestChain` (Consensus.hs:5098-5134):
- runs ONCE per call (no outer loop)
- only invoked from `invalidateBlock` (5062) and `reconsiderBlock` (5174)
- NEVER called from `addHeader`, `connectBlockAt`, `Main.hs:MBlock`
  handler, `blockProcessor`, or `submitBlockSideBranch`

So in the IBD / P2P live-flow case, the chain selector simply does not
exist. If two chains race and one becomes heavier, the active tip
follows whichever block arrived through the `MBlock` extend-the-tip
path. There is no driver that says "the heavier chain is over there,
flip to it".

**File:** `src/Haskoin/Consensus.hs:5098-5134`

**Core ref:** `bitcoin-core/src/validation.cpp:3323-3450`

**Impact:** Multi-tip ambiguity. A peer that announces a side-branch
heavier than the active tip is silently dropped (BUG-13). Even after
the heavier chain accumulates more headers, `addHeader`'s
write-on-strictly-greater-work check (4076) bumps `hcTip` to point
at the side-branch header tip — but no reorg fires to move the
on-disk active chain across. The node is now in a state where:
- `hcTip` claims chain B (header tip)
- on-disk BestBlock claims chain A (last connected tip)
- `bdCurrentHeight` claims chain A's height
- the next block on chain A that arrives fails `addHeader` (parent
  already in index but A is no longer the heaviest chain — actually
  this part passes), but the next chain-B block that arrives via
  `MBlock` calls `connectBlock` which calls `connectBlockAt` which
  fails G1 (prevHash != BestBlock) because BestBlock is still chain A.

---

## BUG-7 (P1) — `MaybeUpdateMempoolForReorg` analog never fires post-connect

**Severity:** P1. Bitcoin Core's `ActivateBestChainStep` calls
`MaybeUpdateMempoolForReorg` (validation.cpp:3206) BOTH after each
DisconnectTip (to refill mempool with disconnected txs) AND after the
final ConnectTip (to evict newly-mined txs and re-validate against
the new tip's UTXO view).

haskoin has the disconnect-side closure (`doSideBranchReorg` line 926-927
calls `blockDisconnected mp blk`), but NEVER calls a post-connect
mempool refill / re-validate. `performReorg` doesn't touch mempool at
all. `Sync.hs:blockProcessor` calls `blockConnected mp block` (via
Main.hs:1875) but that's per-block extend, not a reorg.

**File:** `src/Haskoin/Consensus.hs:4621-4646` (`performReorg`,
no mempool callback); `src/Haskoin/BlockTemplate.hs:887-927`
(disconnect-side only).

**Core ref:** `bitcoin-core/src/validation.cpp:3206-3220`.

**Impact:** after a reorg, mempool may contain txs that now reference
non-existent UTXOs on the new chain, or that violate new-chain BIP-68
sequence locks. Next ConnectBlock that includes one fails sanity.

---

## BUG-8 (P2) — `doSideBranchReorg` builds full disconnect+connect list in one shot; no 32-block chunking

**Severity:** P2 (responsiveness). Core's `ActivateBestChainStep`
processes `vpindexToConnect` in chunks bounded by `nTargetHeight =
min(nHeight + 32, pindexMostWork->nHeight)` (validation.cpp:3224) and
releases `cs_main` between chunks. haskoin's `doSideBranchReorg`
(BlockTemplate.hs:851-877) builds the full disconnect and connect
lists, then commits all batch ops in one final `writeBatch`.

**File:** `src/Haskoin/BlockTemplate.hs:851-877`

**Impact:** a full-depth reorg (up to `maxReorgDepth=100` blocks)
holds the RPC thread's resources continuously; concurrent P2P inv /
getheaders work behind it. Low on its own; combines with BUG-9
(arbitrary cap) and BUG-3 (`performReorg` broken anyway) to be
operationally fragile.

---

## BUG-9 (P0-CDIV) — `maxReorgDepth=100` constant DIVERGES from Core's policy

**Severity:** P0-CDIV. Core has **no MAX_REORG_DEPTH constant**.
A node will reorg arbitrarily deep if the alternative chain has more
chainwork (subject only to `MIN_BLOCKS_TO_KEEP=288` for prune
protection). haskoin's `maxReorgDepth=100` (Consensus.hs:3567)
refuses a reorg whose `disconnect + connect > 100` with `Reorg too
deep: ...` (BlockTemplate.hs:853-858).

This is strictly more restrictive than Core. On a genuinely heavy
side-branch (e.g. a 150-block deep reorg during a contentious fork),
haskoin goes off-consensus by *staying* on the losing chain. The
inline justification comment at Consensus.hs:3556-3565 claims this
mirrors "Core's @MAX_REORG_DEPTH@-equivalent guard in
@ActivateBestChain@" — but Core has no such constant or guard. The
100 figure is a fabrication.

**File:** `src/Haskoin/Consensus.hs:3566-3567`, usage at
`src/Haskoin/BlockTemplate.hs:853-858`.

**Core ref:** `bitcoin-core/src/validation.h:75-76`
(`MIN_BLOCKS_TO_KEEP = 288`); Core has no MAX_REORG_DEPTH.

**Excerpt (haskoin's comment that's factually wrong)**
```haskell
-- Mirrors Core's @MAX_REORG_DEPTH@-equivalent
-- guard in @ActivateBestChain@ + the cross-impl cap landed in
-- nimrod / camlcoin / rustoshi during the 2026-05 Pattern D wave.
```

**Impact:** cross-impl divergence — fleet-wide pattern, mirrors
blockbrew's BUG-5 in the same wave. Same fabricated constant in
nimrod/camlcoin/rustoshi per the comment. Pattern: **comment-as-
confession 5th instance** (per W142-W145 quad-audit memory index).

---

## BUG-10 (P1) — No operator-knob to override `maxReorgDepth`

**Severity:** P1. `maxReorgDepth` is a top-level Haskell binding
(Consensus.hs:3567), not configurable. On a > 100-block reorg
operator has no in-band recovery — recompile or sync-from-genesis.

**File:** `src/Haskoin/Consensus.hs:3567`

**Impact:** see BUG-9.

---

## BUG-11 (P0-CDIV) — `connectChain` writes ONLY undo data; never updates BestBlock / UTXOs

**Severity:** P0-CDIV. Already cross-referenced in BUG-3. Worth
calling out separately: even setting aside the cache-vs-disk drift
in `performReorg`, the connect side of the reorg writes only:

```haskell
Right undoData -> do
  putUndoData db (ceHash ce) undoData    -- ← ONLY this!
  return (Right ())
```

It does NOT:
- write `PrefixBestBlock` to advance the tip pointer
- write `PrefixBlockHeader` for the new tip
- write `PrefixBlockHeight (height) (hash)` for the new active height
- delete spent UTXOs (`BatchDelete PrefixUTXO`)
- write new UTXOs from the connected block

So the on-disk DB has an undo record for a block that was never
connected (the BestBlock pointer still points to the old tip).
`getblock` for the new tip's hash returns Nothing for `bestblock`
queries; `gettxoutsetinfo` walks the OLD UTXO set; the reorg has no
durable effect.

**File:** `src/Haskoin/Consensus.hs:4686-4701`

**Core ref:** `bitcoin-core/src/validation.cpp:2920-2960`
(`ConnectTip` updates UTXO set + writes coins + advances tip
pointer in the chainstate atomically per block).

**Impact:** same as BUG-3.

---

## BUG-12 (P0-CDIV) — Failed validation never marks node `StatusFailedValid` or persists it

**Severity:** P0-CDIV. Bitcoin Core's `ConnectTip` failure path
(validation.cpp:1988-1994) sets `pindex->nStatus |= BLOCK_FAILED_VALID`
and calls `InvalidChainFound(pindex)`. The node is then ineligible
for re-selection by `FindMostWorkChain`.

haskoin's `connectBlockAt` (Consensus.hs:3095-3199), `validateFullBlockIO`,
and `blockProcessor` (Sync.hs:349-477) all return Left on failure
WITHOUT calling `putBlockStatus` or mutating `ceStatus`. The
`blockProcessor` arm (line 406-411) reads:

```haskell
Left err -> do
  putStrLn $ "Block validation failed at height " ++ ...
  -- Mark block as invalid, remove from pending
  atomically $ modifyTVar' (bdPendingBlocks bd) (Map.delete bh)
  -- TODO: Could try to find alternative chain
```

The comment says "Mark block as invalid" — but the only action is
removing from the in-flight pending map. The `ChainEntry.ceStatus`
remains `StatusValid` (it was set by `initHeaderChainFromDB` or
`addHeader`); the `PrefixBlockStatus` DB key is never written. On
the next call to `activateBestChain` the same failing block is
re-selected. The TODO admits the gap.

**File:** `src/Haskoin/Sync.hs:405-411`, `src/Haskoin/Consensus.hs:3130-3157`
(connectBlockAt error returns), `src/Haskoin/App/Main.hs:1801-1813`
(MBlock handler error path).

**Core ref:** `bitcoin-core/src/validation.cpp:1988-1994`
(`InvalidBlockFound`).

**Impact:** infinite re-validation loop on a malformed block whose
header passes `addHeader`. No `m_best_invalid` analog — operator
gets no `LARGE_WORK_INVALID_CHAIN` warning. Cross-cite: BUG-1
(parent invalid not propagated); BUG-12 (block-level invalid not
propagated) — header layer and block layer BOTH leak invalid state.

---

## BUG-13 (P0) — P2P-driven `MBlock` handler never invokes side-branch acceptance

**Severity:** P0 (Pattern Y closure GAP). The `submitblock` RPC has
side-branch acceptance (`submitBlockSideBranch` calls
`addSideBranchHeader` + `doSideBranchReorg`). The P2P-driven
`MBlock` handler (Main.hs:1753-1908) does NOT. It calls `addHeader`
to add the header to the index, then `connectBlock` (which is
`connectBlockAt`). `connectBlockAt`'s G1 check (Consensus.hs:3120-3134)
rejects with:

> "block's prevHash X does not equal current BestBlock Y (Core G1 —
>  validation.cpp:2333)"

So any P2P-arrived block whose parent is not the active tip — i.e.
every side-branch block, every reorg-candidate block — gets dropped
at the G1 gate AND the peer is misbehaving-scored as `InvalidBlock`
(Main.hs:1808-1809). An honest peer announcing a parallel chain
that's about to overtake ours gets banned for telling us about it.

**File:** `app/Main.hs:1796-1813`

**Core ref:** `bitcoin-core/src/validation.cpp:4296-4456`
(`AcceptBlock`: stores body to disk independently of which chain it's
on; tip selection is a separate concern in `ActivateBestChain`).

**Excerpt (haskoin MBlock handler)**
```haskell
connectResult <-
  (connectBlock db net block height spent) `catch` ...
case connectResult of
  Left cbErr -> do
    putStrLn $ "Block rejected at height " ++ show height
            ++ " (peer " ++ show addr ++ "): " ++ cbErr
    pm <- readIORef pmRef
    void $ misbehaving pm addr InvalidBlock   -- ← bans honest peer!
```

**Impact:** haskoin cannot follow any reorg announced via the P2P
inv/getdata pathway. It only follows the chain that extends its
current tip block-by-block. The Pattern Y closure landed for
`submitblock` but never extended to the P2P path.

---

## BUG-14 (P1) — `BlockStatus` is a 7-tag sum, not Core's ordered ladder with flag bits

**Severity:** P1 (semantic mismatch). Core's `BlockStatus` enum
(chain.h:42-86) encodes a 5-level ORDERED validity ladder in the low
3 bits (UNKNOWN=0, RESERVED=1, TREE=2, TRANSACTIONS=3, CHAIN=4,
SCRIPTS=5, mask=7), with independent high-bit flags HAVE_DATA=8,
HAVE_UNDO=16, FAILED_VALID=32, FAILED_CHILD=64, OPT_WITNESS=128.
Checks like `pindex->IsValid(BLOCK_VALID_TRANSACTIONS)` mean "level >= 3".

haskoin's `BlockStatus` (Storage.hs:1506-1518):
```haskell
data BlockStatus
  = StatusUnknown        -- 0x00
  | StatusHeaderValid    -- 0x01
  | StatusDataReceived   -- 0x02
  | StatusValid          -- 0x03
  | StatusInvalid        -- 0x04
  | StatusFailedValid    -- 0x05
  | StatusFailedChild    -- 0x06
```

A pure 7-tag sum. Issues:
- `BLOCK_VALID_TRANSACTIONS` (have body, no chain-validity yet) and
  `BLOCK_VALID_CHAIN` (chain-valid, scripts not yet checked) cannot
  be expressed — assume-valid IBD wants to mark blocks as
  "chain-valid, skip script verify" but the type collapses both into
  `StatusValid`.
- `BLOCK_HAVE_DATA` / `BLOCK_HAVE_UNDO` are stored as DISTINCT tags
  rather than independent flags, so a block CANNOT be both
  `StatusFailedValid` AND `StatusDataReceived` — they're mutually
  exclusive (one constructor at a time).
- `BLOCK_OPT_WITNESS` (for the BIP-141 SegWit witness commitment
  presence-check) absent entirely.

**File:** `src/Haskoin/Storage.hs:1506-1518`

**Core ref:** `bitcoin-core/src/chain.h:42-86`

**Impact:** `FindMostWorkChain` can't filter on `BLOCK_VALID_CHAIN`
(Core uses this to pick tips that have transactions + chain-valid
but may still need script verification — used by assume-valid IBD).
`assumeUTXO` snapshot machinery can't represent
`BLOCK_VALID_TREE | BLOCK_HAVE_DATA | nTx=0`.

---

## BUG-15 (P1) — `StatusDataReceived` constructor exists but no production path writes it

**Severity:** P1 (dead constructor + missing HAVE_DATA signal).
`putBlockStatus` is called from exactly two places in production:
- `invalidateBlock` (Consensus.hs:5034) — writes Failed/FailedChild
- `reconsiderBlock` (Consensus.hs:5168) — writes HeaderValid

Neither `connectBlockAt`, `applyBlock`, `blockProcessor`,
`Main.hs:MBlock` handler, nor `addHeader` ever call
`putBlockStatus`. So no block ever transitions through
`StatusHeaderValid → StatusDataReceived → StatusValid`. The whole
"data received" state is unreachable in normal operation.

**File:** all `putBlockStatus` call sites (4 total: 2 in Consensus.hs,
0 in Sync.hs, 0 in Main.hs, 0 elsewhere).

**Core ref:** `bitcoin-core/src/validation.cpp:3765-3787`
(`ReceivedBlockTransactions` sets `BLOCK_VALID_TRANSACTIONS |
BLOCK_HAVE_DATA`).

**Impact:** `Storage.hs:getBlockStatus` returns `Nothing` for every
block except those touched by invalidate/reconsider. Operators who
inspect block-status state get nulls everywhere. Block-pruning
heuristics that consult `BLOCK_HAVE_DATA` can't function (FIX-33 era
storage relied on this signal). Pattern: **dead-data plumbing** —
the type constructor and DB prefix exist but the production write
path is wired to nothing.

---

## BUG-16 (P0-CDIV) — `initHeaderChainFromDB` hardcodes `ceStatus = StatusValid`, ignoring persisted `PrefixBlockStatus`

**Severity:** P0-CDIV. `initHeaderChainFromDB` (Main.hs:1385-1450)
walks `PrefixBlockHeight` to rebuild `hcEntries` on startup. For
every loaded entry it hardcodes:

```haskell
let entry = ChainEntry
      { ceHeader = header
      , ceHash = bh
      , ceHeight = height
      , ceChainWork = work
      , cePrev = Just (ceHash prevEntry)
      , ceStatus = StatusValid              -- ← ALWAYS StatusValid
      , ceMedianTime = bhTimestamp header
      }
```

No call to `getBlockStatus db bh` to recover the persisted state.
A `StatusFailedValid` written by `invalidateBlock` before shutdown
is RESURRECTED as `StatusValid` on the next startup. The
`hcInvalidated` set is also reconstructed from scratch (line 1403
`invalidatedVar <- newTVarIO Set.empty`) — never re-loaded from disk.

So:
- operator runs `invalidateblock B`
- haskoin marks B as `StatusFailedValid` and stops considering it
- haskoin restarts
- on restart, B's status is reset to `StatusValid` and B is no
  longer in `hcInvalidated`
- next `activateBestChain` re-selects B as a candidate

**File:** `app/Main.hs:1429`, `app/Main.hs:1403`.

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp`
(`LoadBlockIndexDB` reads `nStatus` from `CDiskBlockIndex` on each
restart).

**Impact:** `invalidateblock` RPC effects are LOST on every restart.
Pattern: **carry-forward re-anchor** — same shape as blockbrew W148
BUG-10 (block index not persisted at all). Here the persistence
machinery EXISTS (`putBlockStatus`/`getBlockStatus`/PrefixBlockStatus)
but the load path doesn't call it.

---

## BUG-17 (P1) — `ChainEntry` has no `ceTx` / `ceChainTxCount` field

**Severity:** P1 (cross-cite blockbrew W148 BUG-11). Core's
`CBlockIndex` carries `nTx` (per-block tx count, set by
`ReceivedBlockTransactions`) and `m_chain_tx_count` (cumulative tx
count from genesis or assumeutxo base). Used by
`getblockchaininfo` (`nchaintx`), `EstimateBlockTime`,
sync-progress reporting, `verificationprogress`.

haskoin's `ChainEntry` (Consensus.hs:3699-3707):
```haskell
data ChainEntry = ChainEntry
  { ceHeader     :: !BlockHeader
  , ceHash       :: !BlockHash
  , ceHeight     :: !Word32
  , ceChainWork  :: !Integer
  , cePrev       :: !(Maybe BlockHash)
  , ceStatus     :: !BlockStatus
  , ceMedianTime :: !Word32
  }
```

No `nTx` / `chainTxCount` / equivalent. AssumeUtxoParams (line 312)
has `aupChainTxCount` for the snapshot base, but it's never
propagated into the live chain index after the snapshot loads.

**File:** `src/Haskoin/Consensus.hs:3699-3707`

**Core ref:** `bitcoin-core/src/chain.h:120-129`

**Impact:** `verificationprogress` and `nchaintx` RPC fields cannot
return Core-equivalent values. `EstimateBlockTime` falls back to
height-only linear interpolation.

---

## BUG-18 (P1) — `reconsiderBlock` overwrites descendant status to `StatusHeaderValid`, losing prior validity levels

**Severity:** P1. Core's `ResetBlockFailureFlags` (validation.cpp:3711-3730)
only CLEARS the `BLOCK_FAILED_VALID` / `BLOCK_FAILED_CHILD` flag bits;
the underlying validity level (`BLOCK_VALID_TRANSACTIONS`, etc.) is
preserved so re-validation can resume from where it left off.

haskoin's `reconsiderBlock` (Consensus.hs:5163-5168):
```haskell
forM_ descendants $ \ce -> do
  -- Restore status to StatusHeaderValid (will need re-validation)
  atomically $ modifyTVar' (hcEntries hc) $
    Map.adjust (\e -> e { ceStatus = StatusHeaderValid }) (ceHash ce)
  putBlockStatus db (ceHash ce) StatusHeaderValid
```

UNCONDITIONALLY overwrites to `StatusHeaderValid`. This is doubly
wrong:
1. A descendant that was previously `StatusValid` (fully validated,
   scripts+UTXOs verified) loses its validity level and must be
   re-validated from scratch on the next `activateBestChain`.
2. A descendant that was NEVER failed (e.g. somehow had
   `StatusDataReceived` from BUG-15 if that path were active)
   gets downgraded.

The function also doesn't filter — it walks `findDescendants`
which includes ONLY descendants of the reconsidered block (correct
shape), but applies the overwrite to ALL of them unconditionally.

**File:** `src/Haskoin/Consensus.hs:5163-5168`

**Core ref:** `bitcoin-core/src/validation.cpp:3711-3730`
(`ResetBlockFailureFlags` does `block_index.nStatus &=
~BLOCK_FAILED_MASK`).

**Impact:** every `reconsiderblock` triggers a full re-validation of
the reconsidered subtree. On a 1000-block subtree this is hours of
script verification work that didn't need to happen.

---

## BUG-19 (P0-CDIV) — Two competing IBD predicates; neither uses Core's tip-age + MinimumChainWork model

**Severity:** P0-CDIV.

**Predicate (a):** `Main.hs:929` initializes `ibdModeRef <- newIORef True`.
Flipped to False ONLY at `Main.hs:1737-1741`:
```haskell
when (added > 0 && added < 2000) $ do
  wasIBD <- readIORef ibdModeRef
  when wasIBD $ do
    putStrLn "Header sync complete — leaving IBD mode"
    writeIORef ibdModeRef False
```

i.e. IBD exits when a single `MHeaders` batch returns fewer than 2000
headers. Never flipped back to True. So a transient peer that sends
< 2000 headers because its tip is BEHIND ours flips us out of IBD
permanently.

**Predicate (b):** `Rpc.hs:9142-9153`
`estimateIsInitialBlockDownload`:
```haskell
estimateIsInitialBlockDownload _height blockTime =
  let dayInSeconds = 24 * 60 * 60 :: Word32
      -- Use a rough estimate: mainnet is around block 850000 as of late 2024
      estimatedCurrentTime = 1231006505 + (850000 * 600) :: Word32
  in blockTime + dayInSeconds < estimatedCurrentTime
```

Hardcodes `estimatedCurrentTime` to genesis + 850000\*600 = late 2024
(approximately 1741006505 = 2025-03-03). This is the ENTIRE "now"
clock for the RPC IBD predicate — it never reads the actual system
time. So `getblockchaininfo.initialblockdownload` returns True
forever once the chain advances past late-2024 tip timestamps; or
returns False forever once a sufficiently-current block is in the
chain, regardless of how stale our local tip is.

Bitcoin Core's model (validation.cpp:3283-3291): IBD exits when
`IsTipRecent(MinimumChainWork(), max_tip_age)` — tip is recent AND
chainwork crosses `nMinimumChainWork`. Latched once-and-done. Two
properties haskoin lacks.

**File:** `app/Main.hs:929, 1737-1741`;
`src/Haskoin/Rpc.hs:9142-9153`.

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`.

**Impact:** RPC and the P2P stack disagree on IBD state. The RPC
predicate is hardcoded to a fixed point in time and will silently
flip on its own. The internal predicate (`ibdModeRef`) is fragile.
Mempool / fee-estimator behavior gated on IBD becomes nondeterministic.
Pattern: **two-pipeline guard 16th distinct instance** — two
competing predicates, both broken in different ways.

---

## BUG-20 (P1) — `MBlock` `fTooFarAhead` uses HEADER tip height, not connected tip height

**Severity:** P1. The P2P `MBlock` handler computes:
```haskell
activeTipHeight <- readTVarIO (hcHeight hc)
let fTooFarAhead = height > activeTipHeight + minBlocksToKeep   -- 288
```
(`Main.hs:1781-1783`)

But `hcHeight` is the HEADER chain tip (the highest-work header
known), not the active CONNECTED tip. Core's `fTooFarAhead` check
(validation.cpp:4325) uses `ActiveHeight()` which is the connected
chain tip. If headers are 1000 blocks ahead of connected tip during
IBD, every legitimately-requested-then-arriving block at height
`hcHeight - 999` is FALSELY accepted as "within 288" of the active
tip when actually it's 712 blocks too far ahead of the connected
tip.

Symmetric: a block at height `bdCurrentHeight + 500` could be
accepted because `hcHeight = bdCurrentHeight + 1000` and 500 <
1000 + 288, but it's actually 500 blocks ahead of `bdCurrentHeight`
— Core would correctly classify "within 288" using the connected
tip, but the wider gap here means we admit more unsolicited blocks
than Core would.

**File:** `app/Main.hs:1781-1783`

**Core ref:** `bitcoin-core/src/validation.cpp:4322-4327`
(`fTooFarAhead = (pindex->nHeight > m_chainman.ActiveHeight() +
MIN_BLOCKS_TO_KEEP)`).

**Impact:** during IBD with a long headers-lead, the unsolicited-
block flood DoS gate is effectively disabled.

---

## BUG-21 (P2) — `addHeader` lacks `m_best_header` / `m_best_invalid` separation

**Severity:** P2 (operator-warning gap). Bitcoin Core tracks
`m_best_header` (the most-work HEADER-VALID tip, regardless of
data presence or chain validity) AND `m_best_invalid` (the most-
work known-invalid tip, used to detect chain-splits). The
difference triggers `LARGE_WORK_INVALID_CHAIN` warning when
`m_best_invalid > m_chain.Tip() + 6` blocks of work.

haskoin has neither. `hcTip` is overloaded: when `addHeader` accepts
a header heavier than the current tip it writes:
```haskell
when (work > ceChainWork currentTip) $ do
  modifyTVar' (hcByHeight hc) (Map.insert height hash)
  writeTVar (hcTip hc) entry
  writeTVar (hcHeight hc) height
```

So `hcTip` becomes the "best header" but ALSO the "active tip the
RPC reports". Mempool, miner template, broadcast logic all consult
`hcTip` — but the actual connected chain (`PrefixBestBlock`) may
lag behind by hundreds of blocks during IBD or after a reorg
involving BUG-3.

**File:** `src/Haskoin/Consensus.hs:4073-4079`

**Core ref:** `bitcoin-core/src/validation.h` (ChainstateManager
fields `m_best_header`, `m_best_invalid`).

**Impact:** no `LARGE_WORK_INVALID_CHAIN` alert; operator cannot
tell when a heavier chain than the active tip exists but has been
invalidated.

---

## BUG-22 (P2) — `addHeader` `byHeightVar` update racing with `hcEntries` write under STM but with non-atomic `readTVarIO` outside

**Severity:** P2. `addHeader` reads `entries <- readTVarIO (hcEntries hc)`
at line 3948 OUTSIDE of any STM transaction — uses the snapshot for
all PoW/MTP/difficulty/checkpoint checks. Then a SEPARATE STM
transaction at line 4073-4079 inserts the new header and possibly
flips the tip.

Between the readTVarIO and the atomically block, a concurrent
`addHeader` call (e.g. another peer's `MHeaders` batch) can mutate
`hcEntries` — possibly inserting a header that this call's PoW/MTP
checks didn't consider. Specifically, the MTP check at line 3970
`medianTimePast entries prevHash` uses the stale `entries`
snapshot; concurrent insertions of NEW ancestors of `prevHash`
won't be seen, so the MTP value is computed over a potentially-
incomplete set.

**File:** `src/Haskoin/Consensus.hs:3948, 4073-4079`

**Impact:** under concurrent peer streams, MTP / difficulty checks
race the index updates. Difficulty calc at 3996 uses the same stale
`entries`. Low practical risk because adjacent headers see nearly
the same MTP, but a transient inconsistency window is exposed.

---

## BUG-23 (P2) — `disconnectChain` walks `Parent` pointers in IO with no overall transaction; partial rewinds visible to readers

**Severity:** P2. `disconnectChain` (Consensus.hs:4651-4667)
recurses one block at a time, calling `unapplyBlock cache block undo`
which mutates the UTXOCache TVar inside its own atomically block per
input. So a concurrent reader (e.g. `getrawtransaction`, mempool
admission, RPC `gettxout`) sees an intermediate state in which
SOME peels are applied and others are not. Core takes `cs_main`
for the whole disconnect span.

**File:** `src/Haskoin/Consensus.hs:4651-4667`

**Impact:** RPC and mempool can briefly observe a UTXOCache state
that corresponds to no real chain configuration.

---

## BUG-24 (P3) — `addHeader` future-time gate uses `getPOSIXTime` instead of `GetAdjustedTime`

**Severity:** P3. Core's +2h future-time gate uses
`GetAdjustedTime()` (adjusted-network time), which factors in peer
time offsets. haskoin uses `getPOSIXTime` directly
(Consensus.hs:3953):
```haskell
now <- (round <$> getPOSIXTime) :: IO Int64
```

If the local system clock is skewed but most peers agree on a
different time, Core would adjust; haskoin won't. Headers that are
"too new" against local clock but legitimate against network-
median time are rejected.

**File:** `src/Haskoin/Consensus.hs:3953`

**Core ref:** `bitcoin-core/src/timedata.cpp` `GetAdjustedTime`.

**Impact:** under skewed local clock, valid headers are rejected
as `time-too-new`. Operator-fixable via system clock sync.

---

## Fleet-pattern smells

- **Comment-as-confession (1×):** `Consensus.hs:3556-3565` —
  `maxReorgDepth=100` justified as "mirroring Core's
  @MAX_REORG_DEPTH@-equivalent guard in @ActivateBestChain@". Core
  has no such constant. Cross-cite BUG-9. Pattern's **5th explicit
  instance** (memory index W144 BUG-12).
- **Comment-as-confession (2×):** `BlockTemplate.hs:696-707` —
  "We bypass the `performReorg` top-level helper because it does
  not maintain the on-disk `PrefixUTXO` / `PrefixBestBlock` /
  `PrefixBlockHeight` entries". The fix is to FIX `performReorg`,
  not to inline a parallel implementation. The comment LITERALLY
  documents the bug. Pattern's 6th instance this cycle.
- **Two-pipeline guard (1×):** TWO completely separate reorg
  implementations exist: `performReorg`/`connectChain`
  (Consensus.hs:4621-4702) and `doSideBranchReorg`/`buildReorgBatch`
  (BlockTemplate.hs:837+). They diverge on:
  - whether disk state is updated (BUG-3, BUG-11)
  - whether the network parameter is honored (BUG-2)
  - whether mempool refresh fires post-connect (BUG-7)
  Same shape as rustoshi W142's three-merkle pipelines, but here
  it's **two-pipeline at the reorg layer**. 17th distinct extension
  in the fleet log.
- **Two-pipeline guard (2×):** TWO competing IBD predicates
  (BUG-19), one in Main.hs and one in Rpc.hs, with disjoint
  triggers and neither matching Core's `IsTipRecent +
  MinimumChainWork` semantics. **18th distinct extension**.
- **Dead-data plumbing:** `StatusDataReceived` (BUG-15) — type
  constructor + DB prefix + serialize/deserialize all wired, but
  the production write path is wired to nothing. Pattern same
  shape as W138 fleet-wide ChainstateManager dead-class.
- **Carry-forward re-anchor:** `invalidateblock` effects lost on
  restart (BUG-16) — `putBlockStatus` exists, `getBlockStatus`
  exists, but `initHeaderChainFromDB` hardcodes `StatusValid` and
  the load path never calls `getBlockStatus`. Same family of
  "persistence half-wired" as BUG-15.
- **CheckTransaction-not-replayed-at-cache-mutation** sibling:
  `performReorg`/`connectChain` (BUG-11) writes undo data but not
  the UTXO mutations themselves — same shape class as haskoin W145
  BUG-3 (CVE-2018-17144) where the cache path skips the consensus
  gate that the on-disk path runs.
- **Dead-helper-at-call-site:** `activateBestChain` (Consensus.hs:5098)
  is wired to TWO call sites (`invalidateBlock` 5062,
  `reconsiderBlock` 5174) — but the more interesting call sites
  (post-`MBlock`, post-`addHeader`, post-`blockProcessor`) are
  missing entirely (BUG-6).
- **Asymmetric defensive depth:** `submitBlock` path runs the
  full `validateFullBlockIO` + `doSideBranchReorg` + persists
  PrefixBestBlock etc.; `MBlock` peer path runs `connectBlock`
  alone and fails on the G1 gate without ever invoking the
  side-branch arm (BUG-13). Same shape as ouroboros W143's
  five-pipeline drift.

---

## Summary

24 bugs catalogued — 19 P0/P1, 5 P2/P3. Severity totals:

- **P0-CDIV** (consensus divergent): 7 — BUG-1, BUG-2, BUG-3, BUG-4,
  BUG-9, BUG-11, BUG-12, BUG-16, BUG-19
- **P0** (semantic gap): 2 — BUG-6, BUG-13
- **P1** (correctness / performance): 8 — BUG-5, BUG-7, BUG-10,
  BUG-14, BUG-15, BUG-17, BUG-18, BUG-20
- **P2**: 4 — BUG-8, BUG-21, BUG-22, BUG-23
- **P3**: 1 — BUG-24

**Most-interesting findings:**

1. **`performReorg` writes ONLY undo data — never updates the on-
   disk BestBlock pointer, UTXO set, or `hcTip`** (BUG-3, BUG-11).
   The author of the SECOND reorg implementation
   (`doSideBranchReorg`) inlined a fully-correct disk-writing
   parallel implementation and added a comment explicitly naming
   the bug in the first one. Pattern: textbook two-pipeline guard
   with a comment-as-confession in the source itself. The wired-in
   `invalidateblock`/`reconsiderblock` RPCs flow through the
   broken pipeline.

2. **P2P-driven `MBlock` handler never invokes side-branch
   acceptance** (BUG-13). The `submitblock` RPC path correctly
   handles a side-branch via `submitBlockSideBranch` + `addSideBranchHeader`
   + `doSideBranchReorg`. The P2P `MBlock` path calls `connectBlock`
   directly, which fails the G1 (prevHash != BestBlock) gate, and
   **bans the peer** as `InvalidBlock`. Haskoin cannot follow any
   reorg that arrives via the P2P inv/getdata flow — only chains
   that extend block-by-block.

3. **`initHeaderChainFromDB` resurrects `StatusValid` for every
   loaded entry, ignoring persisted `PrefixBlockStatus` entries**
   (BUG-16). The persistence infrastructure exists end-to-end
   (`putBlockStatus`/`getBlockStatus`/Storage.hs:1506-1531) but
   the restart loader hardcodes `ceStatus = StatusValid`. Every
   `invalidateblock` effect is silently undone by the next
   restart. Pattern: persistence-half-wired, same family as the
   `StatusDataReceived` constructor that no production path ever
   writes (BUG-15).

**Cross-impl context:** Six P0-CDIV findings cluster around the
SAME architectural pattern: in-memory state is mutated but a
parallel persistence layer or supporting index isn't synchronized
(BUG-3 cache-vs-disk, BUG-4 hcByHeight tip-flip partial, BUG-11
undo-only writes, BUG-12 invalid not persisted, BUG-16 status not
loaded, BUG-19 dual IBD predicates). This is the haskoin-specific
shape of "two-pipeline drift" — the same class as the fleet-wide
W148 blockbrew BUG-9/10/11/12 cluster.

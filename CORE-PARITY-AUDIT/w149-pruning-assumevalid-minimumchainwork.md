# W149 — Pruning + assumevalid + minimumchainwork (haskoin)

**Wave:** W149 — `FindFilesToPrune`, `FindFilesToPruneManual`,
`PruneOneBlockFile`, `UnlinkPrunedFiles`, `MIN_BLOCKS_TO_KEEP`,
`nPruneAfterHeight`, `MIN_DISK_SPACE_FOR_BLOCK_FILES`,
`PRUNE_TARGET_MANUAL`, `pruneblockchain` RPC, `BlockStatus::BLOCK_HAVE_DATA`
/ `HAVE_UNDO`, `m_have_pruned`, `m_prune_locks`, `WriteReindexing`,
`-prune=N` parse semantics, `BLOCK_ASSUMED_VALID`, `fScriptChecks`
gate in `ConnectBlock`, `defaultAssumeValid`, `-assumevalid` arg parse,
`nMinimumChainWork`, `IsInitialBlockDownload`, `MinimumChainWork()`,
`MinimumConnectedChainWork` (P2P peer-drop), `min_pow_checked` flag in
`AcceptBlockHeader`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**

### Pruning
- `bitcoin-core/src/node/blockstorage.cpp:321-400` — `FindFilesToPrune`
  (target buffer + `nPruneAfterHeight` gate + IBD-extra buffer +
  `num_chainstates` divisor + `m_prune_locks` consultation via
  `GetPruneRange`).
- `bitcoin-core/src/node/blockstorage.cpp:73-84` — `WriteReindexing` /
  `ReadReindexing` (persisted `DB_REINDEX_FLAG` so a crashed reindex
  resumes on restart).
- `bitcoin-core/src/node/blockstorage.h:147` — `PruneLockInfo`; line
  297 — `m_prune_locks` map; line 450 — `m_have_pruned`.
- `bitcoin-core/src/validation.h:75-76` — `MIN_BLOCKS_TO_KEEP = 288`.
- `bitcoin-core/src/kernel/chainparams.cpp:122,240,340,482,565` —
  `nPruneAfterHeight` (mainnet 100000, testnet/testnet4/signet 1000,
  regtest 1000 or 100 with `-fastprune`).
- `bitcoin-core/src/init.cpp:1408` — `m_have_pruned` consulted by
  `-checkblocks` cap (`MIN_BLOCKS_TO_KEEP`).
- `bitcoin-core/src/init.cpp:2371,2379` — refuse-to-start when an
  index references a height below the first stored block.
- `bitcoin-core/src/rpc/blockchain.cpp` — `pruneblockchain` RPC:
  refuses with `RPC_MISC_ERROR` + `"Cannot prune blocks because node
  is not in prune mode."` when `!fPruneMode`; height in `[0..tip-288]`
  range check; also accepts a Unix-timestamp argument when the value
  fits a Unix timestamp (dual-mode: height OR time).
- `bitcoin-core/src/node/blockmanager_args.cpp` — `-prune=N` parse:
  N==0 disabled, N==1 manual (PRUNE_TARGET_MANUAL = uint64::max),
  N<0 rejected, 2..549 rejected ("below 550 MiB minimum"), N>=550
  auto-prune at N MiB.

### AssumeValid
- `bitcoin-core/src/validation.cpp:2345-2383` — `fScriptChecks` skip
  gate in `ConnectBlock`: all 6 conditions (assume-valid configured;
  block in index; ancestor of assume-valid; ancestor of best header;
  best-header chainwork ≥ MinimumChainWork; best-header 2 weeks past
  block via `GetBlockProofEquivalentTime`).
- `bitcoin-core/src/kernel/chainparams.h` / `chainparams.cpp:110, 233,
  333, 424, 436, 558` — `defaultAssumeValid` per network (mainnet
  block 938343; testnet3 block 4842348; testnet4 block 123613).
- `bitcoin-core/src/node/chainstate.cpp` — `LoadChainstate`
  consults `MinimumChainWork()`.
- `bitcoin-core/src/init.cpp` — `-assumevalid=<hex>` parses operator
  override; `-assumevalid=0` disables (every script runs).

### MinimumChainWork
- `bitcoin-core/src/kernel/chainparams.cpp:109,232,332,423,435,557` —
  `nMinimumChainWork` per network.
- `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291` —
  `IsInitialBlockDownload` / `UpdateIBDStatus` — IBD latch when
  `IsTipRecent(MinimumChainWork(), max_tip_age)` is satisfied (one-way
  latch).
- `bitcoin-core/src/net_processing.cpp` — `MinimumConnectedChainWork`
  (peer drop when peer's claimed work is below the threshold).
- `bitcoin-core/src/validation.cpp:4229-4232` — `min_pow_checked`
  gate in `AcceptBlockHeader` — Core only sets this True once the
  WHOLE downloaded chain crosses `nMinimumChainWork`, gated by the
  PRESYNC / REDOWNLOAD state machine in `headerssync.cpp`.

**Files audited**
- `src/Haskoin/Storage.hs:2128-2387` — `PruneConfig`, `parsePruneArg`,
  `pruneConfigEnabled` / `pruneConfigManual` / `pruneConfigAutoTarget`,
  `autoPruneIfNeeded`, `findFilesToPrune`, `findFilesToPruneManual`,
  `pruneOneBlockFile`, `isBlockPruned`, `pruneBlockchain`,
  `minPruneTarget`, `minBlocksToKeep`, `pruneTargetManual`.
- `src/Haskoin/Storage.hs:1660-1709` — `wipeChainstate` (the
  `-reindex-chainstate` wipe surface).
- `src/Haskoin/Consensus.hs:356-451` — `shouldSkipScripts`,
  `ancestorAtHeight`, `BestHeaderInfo`.
- `src/Haskoin/Consensus.hs:1098,1170,1131,1183,1223,1236,1310,1323`
  — per-network `netMinimumChainWork` / `netAssumedValid` records.
- `src/Haskoin/Consensus.hs:2380-2920` — `validateFullBlock`,
  `validateBlockTransactions`, `validateSingleTx` (the
  `skipScripts` plumbing).
- `src/Haskoin/Consensus.hs:3027-3199` — `connectBlock` /
  `connectBlockAt` (the reindex-replay consumer).
- `src/Haskoin/Consensus.hs:3944-4082` — `addHeader` (the
  `minPowChecked` gate / `too-little-chainwork`).
- `src/Haskoin/Consensus.hs:4305-4500` — `applyBlock` (the cache-path
  block applier; W145 BUG-3 site).
- `src/Haskoin/BlockTemplate.hs:472-720, 1224-1450` — `submitBlock`
  active-tip and side-branch arms; `applyBlockToCache`.
- `src/Haskoin/Sync.hs:370-460` — IBD block-processor calling
  `shouldSkipScripts` + `validateFullBlockIO` + `connectBlockAt`.
- `src/Haskoin/Sync.hs:615-663` — `initHeaderSyncPeer`,
  `shouldStartPresync` (PRESYNC threshold uses `netMinimumChainWork`).
- `src/Haskoin/Rpc.hs:1170-1233` — `handleGetBlockchainInfo` prune /
  IBD fields.
- `src/Haskoin/Rpc.hs:1436-1620` — `handleGetBlock` +
  `fetchGetBlockFromCore` proxy fallback.
- `src/Haskoin/Rpc.hs:1935-1980` — `handlePruneBlockchain` (the
  `pruneblockchain` RPC).
- `src/Haskoin/Rpc.hs:7984-8005` — `dumptxoutset` prune precheck.
- `src/Haskoin/Rpc.hs:9140-9153` — `estimateIsInitialBlockDownload`.
- `app/Main.hs:90-187, 234-237, 487-493, 651-670, 690-797, 1620-1880`
  — CLI parsing, config-file merge, prune-CLI plumbing,
  reindex-chainstate driver, syncMessageHandler.

---

## Gate matrix (30 sub-gates / 9 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | `-prune=N` parse | G1: N==0 → disabled; N==1 → manual; N<0 + 2..549 → reject | PASS (`Storage.hs:2190-2211` `parsePruneArg`) |
| 1 | … | G2: PRUNE_TARGET_MANUAL = uint64::max sentinel matches Core | PARTIAL — `pruneTargetManual = maxBound` of `Int64`, not `uint64::max` (sign-extends to `0x7fffffffffffffff` not `0xffffffffffffffff`); `pcPruneTarget` typed `Int64`, not `Word64` |
| 1 | … | G3: CLI `--prune` flag matches Core `-prune` short-form | DIVERGENT — `app/Main.hs:234` uses GNU `--prune`; Core uses single-dash `-prune`. Operator copy-pasting `bitcoin.conf` muscle memory is silently ignored. |
| 1 | … | G4: explicit `--prune=0` CLI overrides `prune=N` from config | **BUG-1 (P1)** `app/Main.hs:491-493` — `if noPrune n == 0 then config else CLI` — operator cannot disable pruning explicitly when the bundled `haskoin.conf` enables it |
| 2 | `FindFilesToPrune` semantics | G5: `MIN_BLOCKS_TO_KEEP=288` consulted | PASS (`Storage.hs:2287, 2292`); but constant is module-level not per-config (see G6) |
| 2 | … | G6: per-config `pcMinBlocksToKeep` honoured | **BUG-2 (P1) DEAD-FIELD** `pcMinBlocksToKeep` defined + default-populated but `findFilesToPrune` / `pruneBlockchain` ignore it and reach for the module-level `minBlocksToKeep` constant (`Storage.hs:2287, 2292, 2366, 2369`) — fleet pattern W138 "field defined, exported, never read" |
| 2 | … | G7: `nPruneAfterHeight` per-network gate | **BUG-3 (P0-CDIV)** entirely absent (`grep -ni 'pruneAfterHeight' src/ app/` returns nothing). On mainnet haskoin starts pruning at h=288 whereas Core blocks pruning until h=100000; on testnet/regtest haskoin starts at 288 vs Core's 1000 |
| 2 | … | G8: pre-prune buffer (BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE) above target | **BUG-4 (P1)** absent (`Storage.hs:2285-2302`); haskoin triggers pruning at exactly `usage > target`, Core leaves 32 MiB headroom so a single new block-file allocation does not immediately re-trigger pruning |
| 2 | … | G9: IBD-aware extra buffer (`average_block_size * remaining_blocks`) | **BUG-5 (P2)** absent — Core inflates the headroom during IBD because it knows blocks are still arriving; haskoin's flat-target check thrashes during catch-up |
| 2 | … | G10: `num_chainstates` divisor for assumeUTXO dual-chainstate | **BUG-6 (P1)** absent — when an assumeUTXO snapshot chainstate is active Core halves the per-chain target so each chain gets a fair share; haskoin's prune target stays whole and the historical chainstate can starve out the snapshot one |
| 3 | `PruneOneBlockFile` | G11: delete blk*.dat + matching rev*.dat atomically | PASS (`Storage.hs:2308-2332`); but neither delete is checked for failure (catch-all `\_ :: IOException -> return ()`) — half-deleted pairs silently survive |
| 3 | … | G12: update on-disk file-info to mark file empty | PASS — `putFileInfo db fileNum emptyBlockFileInfo` |
| 3 | … | G13: clear `BLOCK_HAVE_DATA` bit on every block in the pruned file | **BUG-7 (P1)** absent — block-index entries are NOT updated to remove the haskoin equivalent of `BLOCK_HAVE_DATA` (haskoin has no such bit at all — see W148 BUG-9). `isBlockPruned` re-derives "is it pruned" from on-disk file existence + size, which is fragile (race between `removeFile` and the next `isBlockPruned` query) and bypasses the candidate-eligibility model entirely |
| 4 | `pruneblockchain` RPC | G14: `RPC_MISC_ERROR` + Core wording when `!fPruneMode` | PASS (`Rpc.hs:1946-1948, 1958-1961`) |
| 4 | … | G15: refuses heights below tip-288 with explicit error | PASS (`Storage.hs:2365-2371`) |
| 4 | … | G16: dual-mode — accepts a Unix-timestamp instead of a height when value > 1e9 | **BUG-8 (P1)** absent — `Rpc.hs:1967` extracts the param as `Word32` height only. Core's `pruneblockchain` walks back from the tip to find the block AT a given block-time when the input looks like a Unix timestamp (`rpc/blockchain.cpp` `EnsureAnyChainman ... if (heightParam > Params().GenesisBlock().GetBlockTime())`) |
| 4 | … | G17: returns the height that was actually pruned to (after MIN_BLOCKS_TO_KEEP clamp) | PARTIAL — `Rpc.hs:1977-1980` returns the request height verbatim even if 0 files were pruned, instead of the highest pruned height per Core |
| 5 | Reindex + prune interaction | G18: persistent `DB_REINDEX_FLAG` so a crashed `-reindex-chainstate` resumes on restart | **BUG-9 (P0)** absent — no flag persisted. A crashed reindex leaves `BestBlock=genesis` + partially-rebuilt UTXO + heights 1..N in the height index; restart without `--reindex-chainstate` does not detect this and the live-sync block handler will immediately fail G1 (`prevHash != BestBlock`) at the next inbound block. Cross-cite W148 BUG-7. |
| 5 | … | G19: refuse `-reindex` on a pruned datadir unless `-prune=N` also set | **BUG-10 (P1)** absent — `app/Main.hs:704-720` runs `wipeChainstate` then schedules replay regardless of whether the datadir was previously pruned. `wipeChainstate` (`Storage.hs:1667-1709`) wipes the chainstate prefixes but not the file-info table; the replay will run `connectBlock` on heights it has data for, then "honestly stop" at the first missing height — operator is left with a partial chainstate at e.g. h=100k while the header chain claims tip=900k. No InitError. |
| 5 | … | G20: persisted `m_have_pruned` flag survives restart and disables `-reindex` | **BUG-11 (P1)** absent — haskoin has no `m_have_pruned` analog. Even if BUG-10 were fixed, the on-disk record of "this node has ever pruned" is missing, so the gate has no signal to consult |
| 5 | … | G21: `-reindex-chainstate` replay routes through `validateFullBlockIO` so consensus rules re-run | **BUG-12 (P0-CONS)** `app/Main.hs:777` calls `connectBlock db net blk h spent` which is a thin alias for `connectBlockAt` (`Consensus.hs:3034-3058`) — only enforces G1 (best-block pointer match) and G19 (spent-input lookup). NO CheckBlock, NO CheckTransaction (duplicate inputs / CVE-2018-17144), NO BIP-30, NO sigops cap, NO MoneyRange, NO bad-cb-amount, NO BIP-68 sequence-locks, NO script verification, NO BIP-34 coinbase-height. The IBD-side `validateFullBlockIO` gate set is **entirely skipped**. Same shape as nimrod W143 BUG-3 reindex-bypass, and a sibling to haskoin's own W145 BUG-3 cache-mutation gap. |
| 6 | `assumevalid` semantics | G22: 6-condition gate matches Core's ConnectBlock | PARTIAL — 6 conditions enumerated correctly in `Consensus.hs:357-440`, but condition 6 (G24 below) and condition 4 (G23) have correctness issues |
| 6 | … | G23: condition 4 — best-header ancestor check | PASS (`Consensus.hs:422-428`) but uses linear `ancestorAtHeight` (parent-walk) — no skip-list, O(height) per call |
| 6 | … | G24: condition 6 — `GetBlockProofEquivalentTime` (chainwork-based) | **BUG-13 (P0-CDIV)** `Consensus.hs:438-440` uses `Word32` subtraction `bhTimestamp bestHeader - pTimestamp` and compares `>= twoWeeks`. (a) Unsigned underflow when `bestHeader.bhTimestamp < pTimestamp` (a side-branch reorg sees this regularly because block timestamps are only MTP-monotonic, not strict-monotonic) wraps to a huge `Word32` → check passes when it should fail closed → scripts get skipped on a block where the 2-week guard was designed to PREVENT skip. (b) "Proxy" comment-as-confession: Core uses `GetBlockProofEquivalentTime` which is work-based not timestamp-based, immune to timestamp manipulation. |
| 6 | … | G25: `-assumevalid=<hash>` operator override | **BUG-14 (P1)** entirely absent — `grep -ni 'assumevalid' app/Main.hs` returns no matches. The hash is hardcoded per-network in `Consensus.hs:1131,1183,1236,1323`. Operator cannot override on the CLI. |
| 6 | … | G26: `-assumevalid=0` to disable (every script runs) | **BUG-15 (P1)** absent — sibling to BUG-14. The only way to disable assumevalid is to recompile with `netAssumedValid = Nothing` |
| 7 | `defaultAssumeValid` per network | G27: hash matches Core for mainnet | PASS (`Consensus.hs:1131` = `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`, height 938343 = Core line 110) |
| 7 | … | G28: hash matches Core for testnet3 and testnet4 | **BUG-16 (P0-CDIV)** **HASHES SWAPPED** — haskoin `Consensus.hs:1183` (testnet3 record) carries `0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a` which is Core's TESTNET4 hash (height 123613, Core line 333). Haskoin `Consensus.hs:1236` (testnet4 record) carries `000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` which is Core's TESTNET3 hash (height 4842348, Core line 233). Comment on line 1183 says "testnet3 block 123613" — but testnet3 has ~4.8M blocks so 123613 is decades stale on testnet3. Comment on line 1236 says "testnet4 block 4842348" — testnet4 has ~123k blocks so 4842348 is unreachable. The defensive 2-week timestamp guard (BUG-13) cannot rescue this: on testnet4 the assume-valid hash refers to a block that will never exist, so condition 2 (`Map.lookup avHash blockIndex`) ALWAYS returns Nothing and `skipScripts` is silently always False on testnet4 (operationally safe but semantically broken — performance regression: full script verification on every testnet4 block). On testnet3 the hash refers to height 123613 — which means script-skip stops at h=123613 instead of h=4842348 (Core skips ~38× more script work during testnet3 IBD). |
| 8 | `nMinimumChainWork` per network | G29: values match Core | PASS (`Consensus.hs:1098, 1170, 1223, 1310` mirror Core lines 109, 232, 332, 557) |
| 8 | … | G30: `MinimumChainWork()` consulted by `IsInitialBlockDownload` exit | **BUG-17 (P0-CDIV)** `Rpc.hs:9140-9153` `estimateIsInitialBlockDownload` ignores chainwork entirely and uses a heuristic (`tipTime + 24h < estimatedCurrentTime` where `estimatedCurrentTime = 1231006505 + 850000 * 600`). The "current time" constant is **frozen at the time of mainnet block 850000 (~Sep 2024)**. Today's tip will report `isIBD=false` for the wrong reason (the frozen estimate is in the past, so `tipTime + 24h < estimatedCurrentTime` is always false even for a 5-year-old tip). Core's gate is `IsTipRecent(MinimumChainWork(), max_tip_age)` — work AND wall-clock; haskoin uses neither correctly. |
| 9 | `min_pow_checked` / `too-little-chainwork` peer-driven header sync | G31: per-batch chainwork accumulator gates header acceptance | **BUG-18 (P0-CDIV)** `Consensus.hs:4037-4038` checks `if not minPowChecked && work < netMinimumChainWork net` PER HEADER. `work = cumulativeWork (parent.ceChainWork) header` — for a header at height 1 on mainnet, `work ≈ 2 * 2^32 = 2^33` which is ≪ mainnet `nMinimumChainWork = 0x01128750f82f4c366153a3a030 ≈ 2^76`. **Every header below ~h=840000 is rejected** with `"too-little-chainwork"` on mainnet, and the rejection is silently dropped (not counted as badPow or badConn in `app/Main.hs:1667-1675` — the `otherwise` arm). A fresh haskoin install with no preloaded headers (`anchors.json` is empty per `wc -c anchors.json`) **cannot bootstrap from genesis on mainnet** via peer-driven `MHeaders` because every header is rejected. The comment on `Main.hs:1647-1651` confesses this ("the chainwork gate provides equivalent protection") — false: Core's PRESYNC machine accumulates work ACROSS many batches before deciding, haskoin's per-header gate cannot accumulate by construction. |

---

## BUG-1 (P1) — `--prune=0` CLI is silently overridden by `bitcoin.conf`

**Severity:** P1. Core's gArgs.ForceSetArg makes CLI arguments
override config-file values unconditionally. Haskoin's config merge
inverts the precedence for any option whose CLI default is "zero or
empty" — including `--prune=0`.

**File:** `app/Main.hs:491-493`

**Excerpt**
```haskell
, noPrune      = if noPrune n == 0
                   then Daemon.configLookupInt "prune" 0 cm
                   else noPrune n
```

**Impact:** Operator runs `haskoin --prune=0 --conf=existing.conf`
intending to force-disable pruning for one session. If `existing.conf`
has `prune=1000`, pruning silently stays on; the operator's `--prune=0`
is treated as "unset, fall back to config". No warning logged. Same
inversion applies to `noRpcPort==0`, `noDbCache==450`, `noMaxPeers==125`
— a 6-line pattern that misframes "CLI explicit zero" as
"CLI unset". Core distinguishes "missing" from "passed-as-0".

---

## BUG-2 (P1) — `pcMinBlocksToKeep` is a dead field

**Severity:** P1 (W138 dead-field family). `PruneConfig` carries a
per-instance `pcMinBlocksToKeep :: Word32` (`Storage.hs:2155`) with a
default of `minBlocksToKeep` (288). The field is in the public export
list (`Storage.hs:159`) so callers can theoretically reconfigure it.
But neither prune consumer consults it:

- `findFilesToPrune` (`Storage.hs:2287, 2292`) uses module-level
  `minBlocksToKeep`.
- `pruneBlockchain` (`Storage.hs:2366, 2369`) uses module-level
  `minBlocksToKeep`.

`autoPruneIfNeeded` (`Storage.hs:2249-2257`) is the call-site that
threads the `PruneConfig` in, but it dispatches `findFilesToPrune
tipHeight target fileInfos` — `cfg` is not forwarded.

**File:** `src/Haskoin/Storage.hs:2155, 2249-2257, 2281-2302, 2361-2387`

**Impact:** A test harness or operator-tuned `PruneConfig` with a
custom `pcMinBlocksToKeep` (e.g. 144 for short-window regtest CI)
is silently discarded. This is the same shape as W144's 10-of-21
flag enum members defined-and-consulted-but-never-emitted, and the
W141 hashtx fan-out gap. Fleet "wiring-look-but-no-wire" archetype.

---

## BUG-3 (P0-CDIV) — `nPruneAfterHeight` per-network gate is entirely absent

**Severity:** P0-CDIV. Bitcoin Core's `FindFilesToPrune`
(`bitcoin-core/src/node/blockstorage.cpp:343-345`) refuses to prune
until the active chain has reached `Params().PruneAfterHeight()`.
This protects newly-installed nodes from pruning their just-validated
genesis-anchored data before they have any reorg cushion. Per-network:

| Network | Core `nPruneAfterHeight` | haskoin |
|---------|--------------------------|---------|
| mainnet | 100000 | absent |
| testnet3 | 1000 | absent |
| testnet4 | 1000 | absent |
| signet | 1000 | absent |
| regtest | 1000 (or 100 with `-fastprune`) | absent |

`grep -ni 'pruneAfterHeight\|prune_after\|nPruneAfter' src/ app/`
returns no matches. Haskoin's only height-related guard is the
single `tipHeight < minBlocksToKeep = 288` check
(`Storage.hs:2287, 2366`).

**File:** `src/Haskoin/Storage.hs:2281-2302, 2361-2387`;
`src/Haskoin/Consensus.hs:1080-1325` (Network record has no
`netPruneAfterHeight` field).

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:122, 240, 340,
482, 565`; `bitcoin-core/src/node/blockstorage.cpp:343-345`.

**Impact:**
- Operator runs `haskoin --prune=550` against a fresh mainnet
  datadir. After the chain reaches h=288, every flush starts
  pruning. Core would not prune until h=100000 (about 12 days of
  blocks). Haskoin's prune kicks in 99712 blocks earlier — and the
  most-recent 288 of those pruned blocks would be needed for a
  routine reorg-protection window.
- Reorg recovery is gated by the operator's prune target, not by
  Core's intentional 100000-block deferral. On a contentious-fork
  scenario (the deepest mainnet reorg was 53 blocks at h=128890
  Aug 2010), the cushion is unaffected; but the WAVE shape of
  prune-flush ↔ block-arrive cycles is operationally different.

---

## BUG-4 (P1) — No pre-prune buffer above target

**Severity:** P1. Core leaves a `BLOCKFILE_CHUNK_SIZE +
UNDOFILE_CHUNK_SIZE` headroom (16 MiB + 1 MiB = 17 MiB) above the
prune target so a fresh block-file allocation does not immediately
re-trigger pruning. Haskoin checks `currentUsage <= target` exactly
(`Storage.hs:2286, 2296`). Once usage crosses target, every flush
triggers a prune cycle, and the next block file allocation pushes
back over target → re-prune. Saw-tooth pattern under steady-state
mining.

**File:** `src/Haskoin/Storage.hs:2285-2302`

**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:353`
(`nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE`).

**Impact:** Constant prune thrash on a target-sized node; each
`pruneOneBlockFile` does a synchronous unlink which serialises
against the next `writeBlockToDisk`. Mitigation is operator-only
(set target higher than needed).

---

## BUG-5 (P2) — No IBD-aware extra prune buffer

**Severity:** P2. Core (`blockstorage.cpp:362-368`) inflates the
prune buffer during IBD by `average_block_size * remaining_blocks`
(1 MB × distance to `target_sync_height`). The intent is: during
IBD blocks are landing fast, so prune-then-immediately-re-prune is
counterproductive; let the buffer grow to absorb the catch-up
window. Haskoin has no IBD distinction in the prune path
(`Storage.hs:2249-2257`).

**File:** `src/Haskoin/Storage.hs:2249-2257`

**Impact:** Catch-up pruning during IBD thrashes more than steady-
state. Cross-cite BUG-4.

---

## BUG-6 (P1) — `num_chainstates` divisor absent for assumeUTXO dual-chain

**Severity:** P1. When a `loadtxoutset` snapshot has been imported,
Core runs TWO chainstates in parallel: the snapshot chainstate (at
the assume-utxo height) and the historical chainstate (validating
from genesis in the background). To avoid one starving the other,
`FindFilesToPrune` divides `target` by `num_chainstates`
(`blockstorage.cpp:335-337`). Haskoin runs `applyBlock` /
`connectBlock` on a single chainstate and has no notion of a
historical+snapshot dual; if `--load-snapshot` is wired (Main.hs:120)
the prune-target divisor cannot apply.

**File:** `src/Haskoin/Storage.hs:2249-2257, 2281-2302`

**Impact:** With assumeUTXO snapshot active, prune target is the
full operator-configured value rather than half — historical
chainstate eviction may purge the data the snapshot needs for cross-
validation.

---

## BUG-7 (P1) — Block index is not updated when a file is pruned

**Severity:** P1. Core stamps `BLOCK_HAVE_DATA` / `HAVE_UNDO` bits
on `CBlockIndex` per block. `PruneOneBlockFile` then clears those
bits on every block in the pruned file. Haskoin's `pruneOneBlockFile`
(`Storage.hs:2308-2332`) does the deletes and `putFileInfo
emptyBlockFileInfo`, but the block-index records still claim the
data is present (haskoin has no `BLOCK_HAVE_DATA` analog at all —
see W148 BUG-9 for the bitfield-vs-ladder mismatch). `isBlockPruned`
re-derives "is it pruned" from on-disk file existence + size lookup
each time it is called, which is fragile under race (concurrent
prune + RPC `getblock`) and bypasses the candidate-eligibility
model that `FindMostWorkChain` uses for chain selection.

**File:** `src/Haskoin/Storage.hs:2308-2354`

**Impact:**
- Race: `isBlockPruned` may be called by REST `/rest/block/<hash>`
  (`Rpc.hs:9296-9302`) between the `removeFile blkFile` line and
  the `removeFile undoFile` line of `pruneOneBlockFile`. Returns
  `True` for a half-pruned file. Caller then bails out, but the
  rev file (with undo data) lingers on disk and never gets cleaned
  up because `Storage.hs:2327` only flips the in-memory file-info
  to empty if the deletes succeed.
- W148 cross-cite: BlockNode has no `Status` persistence, so
  `BLOCK_HAVE_DATA` could not be cleared on disk even if haskoin
  added the bitfield. The bug is structural to the block-index
  format.

---

## BUG-8 (P1) — `pruneblockchain` RPC missing Unix-timestamp dual-mode

**Severity:** P1. Core's `pruneblockchain` accepts either a block
height OR a Unix timestamp — when the argument exceeds the genesis
block's `nTime`, it is interpreted as a timestamp and Core walks
back to find the block whose `nTime` is closest to that value.
Haskoin treats the parameter as `Word32` height only (`Rpc.hs:1967`).

**File:** `src/Haskoin/Rpc.hs:1958-1980`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp` `pruneblockchain`.

**Impact:** Operator script `pruneblockchain 1609459200` (Jan 1 2021)
silently truncates to `Word32` and prunes up to height ~1.6e9 (which
hits the `tipHeight - minBlocksToKeep` clamp at `Storage.hs:2369`
and returns the "Cannot prune blocks within 288" error). Misuse is
caught, but the dual-mode operator UX is lost.

---

## BUG-9 (P0) — No persisted `DB_REINDEX_FLAG`; crashed reindex is invisible on restart

**Severity:** P0. Core writes a `DB_REINDEX_FLAG` to the block-tree
DB (`blockstorage.cpp:73-84`) when `-reindex` starts and removes it
when the reindex completes. On restart Core reads the flag — if set,
it knows the reindex was interrupted and resumes. Haskoin has no
analog (`grep -ni 'REINDEX_FLAG\|reindex.*flag\|writeReindexing' src/
app/` returns nothing).

**File:** `app/Main.hs:704-797` (the entire `-reindex-chainstate`
driver); no persistent-flag write.

**Impact:**
- `wipeChainstate` runs (`Storage.hs:1667-1709`), wiping
  PrefixUTXO + PrefixBestBlock + PrefixTxIndex + PrefixChainWork +
  PrefixBlockStatus + PrefixAddrHistory + PrefixAddrBalance +
  PrefixAddrUTXO. `BestBlock` is then re-pinned to genesis
  (`Main.hs:719`). Replay starts.
- If the process crashes mid-replay (OOM, power loss, SIGKILL) at,
  say, h=400000, the on-disk state is: BestBlock=h=400000 (set by
  the last successful `connectBlockAt`), UTXO partially rebuilt,
  height index intact at h=900000 (the height index was NOT wiped
  because `wipeChainstate` only wipes 8 prefixes — height/header
  prefixes survive).
- Restart WITHOUT `--reindex-chainstate`: live-sync starts at the
  reported BestBlock=h=400000 → the next inbound block from a peer
  at h=900000+ fails G1 (`prevHash != BestBlock`) → no progress.
- Operator must either manually re-run `--reindex-chainstate` (and
  hope it idempotently completes) or wipe the entire datadir.
- Cross-cite W148 BUG-7 (failed ConnectBlock doesn't mark
  StatusInvalid — same family of "transient errors not persisted").

---

## BUG-10 (P1) — No refuse-to-start when `-reindex` runs on a pruned datadir

**Severity:** P1. Core (`init.cpp` `LoadBlocksDisk` ↔
`m_have_pruned`) refuses to start `-reindex` on a datadir that has
already been pruned, unless `-prune=N` is also passed. The
rationale: reindex needs to re-read every blk*.dat to rebuild the
chainstate; if some have been deleted, the rebuild will be partial
and silently incorrect. Haskoin runs `wipeChainstate` then
`-reindex-chainstate` replay regardless (`Main.hs:704-797`), and the
replay loop "honestly stops" at the first missing block
(`Main.hs:741-746`).

**File:** `app/Main.hs:704-797`

**Core ref:** init.cpp around `m_have_pruned` consultation.

**Impact:** Operator runs `haskoin --reindex` on a previously-pruned
datadir. Wipe succeeds. Replay starts at h=1. If the prune watermark
was at h=500000, the replay stops at h=499999 with an "honest" log
line, leaving the chainstate at h=499999 while the header chain
still claims tip=900000+. No InitError, no exit code, no operator
prompt — the node just sits there with a stale chainstate that
cannot be re-extended (BUG-9 path).

---

## BUG-11 (P1) — No persisted `m_have_pruned` flag

**Severity:** P1. Core stamps `m_have_pruned` once any block file is
pruned and persists it via `WriteFlag`. It survives restarts and
disables `-reindex` (per BUG-10). Haskoin has no analog
(`Storage.hs` has no such constant; `BlockFileInfo` has no "has been
pruned at some point" bit). Even if BUG-10 were fixed, the gate has
no on-disk signal to consult.

**File:** `src/Haskoin/Storage.hs:1800-1900` (BlockStore record);
`Consensus.hs:281-330` (Network record).

**Impact:** Structural — closes the gap that BUG-10 documents.

---

## BUG-12 (P0-CONS) — `-reindex-chainstate` replay bypasses the entire validation pipeline

**Severity:** P0-CONS (consensus-divergent on a from-genesis reindex
replay). The `-reindex-chainstate` driver in `Main.hs:777` calls:

```haskell
cr <- connectBlock db net blk h spent
```

`connectBlock` (`Consensus.hs:3027-3058`) is documented as a "thin
alias for `connectBlockAt`" — a structural-only writer that enforces
exactly two gates:

- G1 — `hashPrevBlock == GetBestBlock()` (best-block pointer match).
- G19 — `assert(is_spent)` analog (every non-coinbase input must be
  resolvable in `spentUtxos` map or on disk).

Everything else from `validateFullBlockIO` is **skipped**:
CheckBlock (merkle root, weight, sigops, coinbase shape),
CheckTransaction (duplicate inputs / CVE-2018-17144, MoneyRange,
coinbase length, null-input restriction), BIP-30 duplicate-txid
guard, BIP-34 coinbase-height enforcement, BIP-65/66 nVersion gate,
BIP-68 sequence locks, BIP-113 MTP locktime, bad-cb-amount
(subsidy + fees ≥ coinbase), script verification, sigops cap. None
of these run on the reindex path. The comment in `Consensus.hs:3082-3088`
acknowledges the split: "Other gates that Core runs inside
ConnectBlock (CheckBlock recheck, BIP-30, BIP-68 sequence locks,
CheckTxInputs, sigops cap, bad-cb-amount, script verification) are
wired upstream in 'validateFullBlockIO' on the IBD path and in
'applyBlockToCache' / 'applyBlock' on the cache path." — but the
reindex driver is **neither** of those: it goes straight to
`connectBlock`.

**File:** `app/Main.hs:773-786`; `src/Haskoin/Consensus.hs:3027-3199`.

**Core ref:** Core's `-reindex` re-runs `ConnectBlock` per block with
the full validation set; the chainstate is regenerated from scratch
from on-disk blk*.dat with consensus gates intact.

**Impact:**
- A locally-stored blk*.dat that was previously accepted under
  earlier (less strict) rules — or that was tampered with on disk
  (filesystem corruption, malicious operator with disk access) — is
  silently re-installed into the UTXO set with no consensus check.
- CVE-2018-17144 class re-exposure on the reindex path: a block in
  blk*.dat with duplicate inputs is replayed without
  `validateTransaction`'s duplicate-input check.
- Cross-cite: haskoin W145 BUG-3 (`applyBlock` / `applyBlockToCache`
  cache paths don't re-check duplicate inputs) and W147 BUG re:
  `connectBlockAt` rejects intra-block spends. **Three** paths into
  the chainstate (IBD via validateFullBlockIO, cache via
  applyBlock(ToCache), reindex via connectBlock) carry different
  validation surfaces — the W143 / W145 "three-pipeline drift"
  shape, repeated here at the chainstate-write layer.
- Same shape as nimrod W143 BUG-3 (`--reindex` skips
  acceptBlock-validateBlock-checkBip30) and lunarblock W143 BUG-3
  (reorg connect loop bypasses check_block).

---

## BUG-13 (P0-CDIV) — Assumevalid condition 6 has Word32 underflow + uses timestamps not proof-equivalent-time

**Severity:** P0-CDIV. `shouldSkipScripts` condition 6
(`Consensus.hs:434-440`):

```haskell
let twoWeeks = 60 * 60 * 24 * 7 * 2 :: Word32  -- 1209600 s
    timeDiff = bhTimestamp (ceHeader bestHeader) - pTimestamp
in timeDiff >= twoWeeks
```

Two correctness problems:

1. **Unsigned underflow.** `Word32` subtraction wraps. When
   `bhTimestamp bestHeader < pTimestamp` (which IS legal — block
   timestamps are gated by MTP, not strict monotonic; during a
   side-branch reorg the best-header on a side branch is often
   older than the block being validated, plus consensus permits up
   to 2-hour future timestamps relative to MTP), `timeDiff`
   underflows to a near-`maxBound :: Word32` value (~4.29B) which is
   trivially `>= 1209600` → condition 6 **passes** when it should
   **fail closed**. The defensive 2-week guard, designed to prevent
   a manufactured shallow header chain from unlocking the
   script-skip path, fails OPEN under the very condition it was
   meant to detect.

2. **Wrong primitive.** Core uses `GetBlockProofEquivalentTime`
   (`pow.cpp`) — a chain-work-based calculation, immune to peer
   timestamp manipulation. Comment on `Consensus.hs:436-437`
   confesses: "We use timestamp difference as a proxy for
   GetBlockProofEquivalentTime." Comment-as-confession 6th instance
   (W141 NewlibLinker, W143 hex_to_bin, W144 lunarblock
   verify_const_scriptcode, W145 lunarblock validation.lua:220
   assert leak, W141 rustoshi).

**File:** `src/Haskoin/Consensus.hs:434-440`

**Core ref:** `bitcoin-core/src/validation.cpp:2380-2383`;
`bitcoin-core/src/pow.cpp GetBlockProofEquivalentTime`.

**Impact:**
- A peer that builds a side-branch header chain rooted in a recent
  block, with timestamps SLIGHTLY backwards from the active tip,
  causes haskoin to flip into "skip scripts" on the side-branch
  blocks during reorg evaluation. Combined with the active tip being
  the assumevalid ancestor, every condition can be coerced to pass.
- Core's chainwork-based version is unforgeable: forging a
  GetBlockProofEquivalentTime requires actually mining the work.

---

## BUG-14 (P1) — No `-assumevalid=<hash>` CLI override

**Severity:** P1. Core lets operators override the assume-valid hash
on the CLI: `-assumevalid=<hexhash>` re-anchors the script-skip
window to a different (typically more recent) block. Haskoin has no
analog (`grep -ni 'assumevalid' app/Main.hs` empty). The hash is
hardcoded per-network in `Consensus.hs:1131, 1183, 1236, 1323`.

**File:** `app/Main.hs:90-187` (NodeOptions); no `noAssumeValid`
field.

**Impact:**
- Operators tracking a contested fork cannot point haskoin at a
  newer assume-valid hash than the shipped one.
- W145 cross-cite: assume-valid is the only operator-facing knob
  Core ships for "I trust scripts up to here, please run fast"; with
  no CLI surface, operators have no recourse short of a recompile.

---

## BUG-15 (P1) — No `-assumevalid=0` to disable script-skip entirely

**Severity:** P1. Sibling to BUG-14. Core's `-assumevalid=0`
disables the script-skip entirely (every script runs). Haskoin can
only disable it by recompiling `Consensus.hs:1323` style — `,
netAssumedValid = Nothing` — per network.

**File:** `app/Main.hs:90-187`; `src/Haskoin/Consensus.hs:1131,
1183, 1236, 1323`.

**Impact:** Operator wanting full script verification on mainnet
(for forensic re-validation, e.g. confirming a hard-fork outcome)
has no in-band option. Has to recompile.

---

## BUG-16 (P0-CDIV) — Testnet3 / testnet4 `defaultAssumeValid` hashes are SWAPPED

**Severity:** P0-CDIV (consensus-divergent on testnet3/testnet4
IBD). Comparing haskoin's `netAssumedValid` against Core's
`defaultAssumeValid`:

| Network | Core (chainparams.cpp) | haskoin (Consensus.hs) |
|---------|------------------------|------------------------|
| mainnet | `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac` (h=938343, line 110) | `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac` (line 1131) — match |
| testnet3 | `000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` (h=4842348, Core line 233 — inside `CTestNetParams`) | `0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a` (haskoin line 1183) — **WRONG** — this is Core's testnet4 hash |
| testnet4 | `0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a` (h=123613, Core line 333 — inside `CTestNet4Params`) | `000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4` (haskoin line 1236) — **WRONG** — this is Core's testnet3 hash |

Worse: haskoin's docstrings encode the wrong heights:

- `Consensus.hs:1182` — "Assume-valid (Bitcoin Core v28.0): testnet3
  block 123613." — but the hash on line 1183 corresponds to
  testnet4 block 123613, and testnet3 has ~4.8M blocks so 123613 is
  decades stale on testnet3.
- `Consensus.hs:1235` — "Assume-valid (Bitcoin Core v28.0): testnet4
  block 4842348." — but testnet4 has ~123k blocks so 4842348 will
  not exist for ~9 years (10-min target × 4.7M blocks).

**File:** `src/Haskoin/Consensus.hs:1182-1183, 1235-1236`

**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:232-233`
(CTestNetParams), `:332-333` (CTestNet4Params).

**Impact:**
- **Testnet4 from-genesis IBD:** `netAssumedValid` on testnet4
  points to a block that will never exist (4842348 is ~9y future).
  Condition 2 of `shouldSkipScripts` (`Consensus.hs:407-408`)
  always returns `Nothing` from the `Map.lookup avHash blockIndex`.
  `skipScripts` is always `False` on testnet4 → every script runs.
  Operationally safe (over-validation) but performance regression
  — testnet4 IBD takes the full unaccelerated script-verification
  time instead of the intended assume-valid skip past h=123613.
- **Testnet3 from-genesis IBD:** `netAssumedValid` on testnet3
  points to h=123613 (testnet4's actual assume-valid block) which
  DOES exist on testnet3 because testnet3 is at h=4.8M+. Haskoin's
  condition 2 SUCCEEDS — but the assume-valid window is anchored
  at h=123613 instead of Core's intended h=4842348. So script
  verification is **skipped for blocks ≤ 123613** and **enforced
  for blocks > 123613**. Core skips up to h=4842348 (~38× more
  blocks). Haskoin re-validates ~4.7M blocks that Core skips —
  multi-day IBD-time regression on testnet3 vs Core parity.
- The chainwork (`netMinimumChainWork`) values on those lines
  appear correct (per-network from Core), so the swap is hash-only,
  not record-block.

---

## BUG-17 (P0-CDIV) — `estimateIsInitialBlockDownload` ignores `MinimumChainWork` AND wall-clock

**Severity:** P0-CDIV. Core's `IsInitialBlockDownload`
(`validation.cpp:3283-3291`) latches `m_cached_is_ibd` to false ONLY
when `IsTipRecent(MinimumChainWork(), max_tip_age)` is satisfied —
both chainwork AND wall-clock-age gates. Haskoin's
`estimateIsInitialBlockDownload` (`Rpc.hs:9140-9153`):

```haskell
estimateIsInitialBlockDownload _height blockTime =
  let dayInSeconds = 24 * 60 * 60 :: Word32
      estimatedCurrentTime = 1231006505 + (850000 * 600) :: Word32
  in blockTime + dayInSeconds < estimatedCurrentTime
```

The `_height` argument is **ignored** (leading underscore — no
chainwork consultation possible because the signature doesn't take
chainwork). `estimatedCurrentTime` is frozen at Sep 2024 (genesis
1231006505 + 850000 × 600). Today is May 2026 (~h=938k). A real
tip with a current timestamp (e.g. May 2026) has
`blockTime + 86400 ≈ 1747e6` which is FAR greater than the frozen
`estimatedCurrentTime ≈ 1741e6`. So the check returns False
("not in IBD") — accidentally correct for a fresh tip, but for the
WRONG REASON (the frozen estimate is older than the real current
time). For a stale tip at e.g. Aug 2024, `blockTime + 86400 ≈
1725e6 < 1741e6` → "in IBD" → arguably correct. But:

- A node at h=900000 with tip Sep 2024 is NOT in IBD (chain is
  current at the time of the estimate constant) but haskoin says
  IBD=true.
- A node at h=1 with tip Sep 2024 timestamp (a malicious peer
  feeds a single header with current time) is NOT in IBD by
  haskoin, despite having one block of work.

`MinimumChainWork` is **not consulted at all** here. The function
that gates IBD exit ignores the very constant the wave is auditing.

**File:** `src/Haskoin/Rpc.hs:9140-9153`

**Core ref:** `bitcoin-core/src/validation.cpp:1940-1942, 3283-3291`
(`IsInitialBlockDownload` / `UpdateIBDStatus`).

**Impact:**
- `getblockchaininfo`'s `initialblockdownload` field reports
  incorrect values on any tip older than Sep 2024 OR any node
  whose recent peer-fed time differs from the hardcoded estimate.
- Mempool acceptance, fee estimation, and feefilter behaviour all
  consult `isIBD` — wrong IBD state means policies that should
  apply post-IBD are off.
- Cross-cite W148 BUG-13: blockbrew's IBD exit uses
  `tipHeight == assumeValidHeight` (equality). Haskoin's is even
  more divergent: frozen wall-clock + ignores work + ignores
  height.

---

## BUG-18 (P0-CDIV) — `too-little-chainwork` gate breaks mainnet bootstrap from genesis

**Severity:** P0-CDIV (operationally catastrophic on a fresh
mainnet install). `addHeader` `Consensus.hs:4037-4038`:

```haskell
if not minPowChecked && work < netMinimumChainWork net
  then return $ Left "too-little-chainwork"
```

`work = cumulativeWork (parent.ceChainWork) header` — for a header
at height 1 on mainnet, `parent.ceChainWork = 2^32` (the per-genesis
seed), `work ≈ 2 * 2^32 = 2^33`. Mainnet `nMinimumChainWork =
0x01128750f82f4c366153a3a030 ≈ 2^76`. Every peer-fed header below
height ~840,000 is rejected with `"too-little-chainwork"`.

The rejection wording does not contain `"proof of work"`, `"PoW"`,
`"parent"`, `"previous"`, or `"not connected"` — so the
`MHeaders` peer handler (`app/Main.hs:1656-1675`) drops the header
silently in the `otherwise` arm without incrementing either
`badPow` or `badConn`. No misbehaving score, no log line above the
debug threshold, no DoS attribution.

A fresh haskoin install with `anchors.json` empty (`wc -c
anchors.json` = 0) **cannot bootstrap from genesis on mainnet** via
the peer-driven path. The IBD path requires headers in `hcEntries`
to know what to download, and `addHeader` is the only way headers
land there (`addSideBranchHeader` is only for post-validation
side-branch insertion). The `MHeaders` handler is the only path
from a peer to `addHeader`.

The comment at `app/Main.hs:1647-1651` confesses the divergence:
"We do not stand up the full PRESYNC/REDOWNLOAD state machine ...
the chainwork gate provides equivalent protection against
low-work header floods without requiring the extra round-trips."
This claim is **false**. Core's PRESYNC machine accumulates work
ACROSS many batches by buffering all received headers in memory
and committing to the in-memory index only once the cumulative
batch crosses `nMinimumChainWork`. Haskoin's per-header gate
cannot accumulate by construction — every header is judged in
isolation against the network minimum.

Comment-as-confession 7th instance.

**File:** `src/Haskoin/Consensus.hs:4027-4038`; `app/Main.hs:1645-1676`

**Core ref:** `bitcoin-core/src/validation.cpp:4229-4232`
(`min_pow_checked` gate); `bitcoin-core/src/headerssync.cpp`
(PRESYNC / REDOWNLOAD state machine that drives the boolean).

**Impact:**
- Fresh mainnet install: cannot bootstrap from genesis. (The
  bootstrap path that DOES work today is presumably the
  `initHeaderChainFromDB` path that reads pre-existing headers
  from RocksDB — but those headers had to get there somehow.
  Suggests haskoin's bootstrap requires an out-of-band header
  preload that the codebase does not document.)
- The `presyncData` + `processPresyncHeaders` machinery exists in
  `Sync.hs:615-682` but appears to be a separate code path that is
  not wired into the `MHeaders` peer handler (`app/Main.hs:1657`
  calls `addHeader` directly, not `processPresyncHeaders`). Dead
  bypass: a full PRESYNC state machine is implemented but
  unreachable from production peer flow.
- Cross-cite W148 BUG-3 / BUG-13 (haskoin's "we have the parts but
  they aren't wired" pattern at the ABC loop).

---

## BUG-19 (P0) — `handleGetBlock` proxies to external Bitcoin Core when local block is missing

**Severity:** P0 (operational + security). When `getBlock` returns
`Nothing` (block-body missing — could be pruned, could be a side-
branch never downloaded, could be a corrupted blk*.dat),
`handleGetBlock` falls through to `fetchGetBlockFromCore` (`Rpc.hs:
1449-1455`) which opens an HTTP/1.0 socket to `127.0.0.1:8332`,
reads cookie auth from a HARDCODED maxbox path, sends the request
to an external Bitcoin Core, and returns Core's response as if it
came from haskoin's own store.

```haskell
mBlock <- getBlock (rsDB server) bh
case mBlock of
  Nothing -> do
    mRaw <- fetchGetBlockFromCore hexHash verbosity
    case mRaw of
      Nothing  -> return $ RpcResponse Null
        (toJSON $ RpcError rpcMiscError "Block not found") Null
      Just raw -> return $ RpcResponse (rawJsonResult ...) Null Null
```

Cookie paths (`Rpc.hs:1526-1527`):
```
/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie
/home/work/hashhog/testnet4-data/bitcoin-core/.cookie
```

**File:** `src/Haskoin/Rpc.hs:1436-1620`

**Impact:**
- **No pruned-data error wording.** Core's `getblock` on a pruned
  block returns the exact wording `"Block not available (pruned
  data)"` (`bitcoin-core/src/rpc/blockchain.cpp`). REST has this
  pre-check in haskoin (`Rpc.hs:9296-9302`), but the JSON-RPC path
  does NOT.
- **Silent dependency on a co-located Core node.** A pruned
  haskoin instance with Core running on the same host
  (mainnet/testnet4) silently returns answers from Core, masking
  its own data-loss state. The operator sees `getblock` work and
  has no idea their pruned store is being shimmed.
- **Hardcoded paths.** A haskoin instance on any other host
  silently fails the fallback (`tryReadCookies` returns Nothing)
  and reports `"Block not found"` — a generic error that conflates
  "this block does not exist" with "this block was pruned" with
  "the operator misconfigured Core's cookie path".
- **Bypass of consensus authority.** If Core's data diverges from
  haskoin's view (because of a long-running consensus split,
  invalidateblock divergence, etc.), `getblock` returns Core's
  answer — a downstream tool relying on `getblock` for haskoin's
  view of the chain gets Core's view.
- Fleet pattern: "secret dependency" — code path that only works
  on one specific deployment topology. Same shape as a network-
  hardcoded constant; cross-cite to W141 default-creds findings.

---

## BUG-20 (P1) — `getblockchaininfo` reports `pruneheight=0` hardcoded

**Severity:** P1 (dead-data). Core's `getblockchaininfo` reports
`pruneheight` as "lowest-height complete block stored (only when
pruned)" — typically the first block in the oldest non-pruned
blk*.dat. Haskoin (`Rpc.hs:1210`):

```haskell
pair "pruneheight" (AE.word32 (0 :: Word32))
```

Hardcoded to zero. A node that has pruned heights 0..400000 still
reports `pruneheight=0`.

**File:** `src/Haskoin/Rpc.hs:1206-1213`

**Core ref:** `bitcoin-core/src/rpc/blockchain.cpp
getblockchaininfo`.

**Impact:** Wallet software and indexers (electrs, fulcrum,
mempool.space) consult `pruneheight` to decide what range to
backfill from peers. A wrong `pruneheight=0` tells the downstream
"all blocks from genesis are available locally" → it asks haskoin
for h=100 → haskoin's `getblock` proxies to Core (BUG-19) OR
returns "Block not found" (no Core fallback available). Either
way, downstream gets stale or misattributed data without warning.

---

## BUG-21 (P2) — `pruneTargetManual` uses `Int64 maxBound` instead of `Word64 max`

**Severity:** P2. Core's `PRUNE_TARGET_MANUAL` =
`std::numeric_limits<uint64_t>::max()` = `0xffffffffffffffff`
(`bitcoin-core/src/node/blockstorage.h:408`). Haskoin's analog
(`Storage.hs:2170-2171`):

```haskell
pruneTargetManual :: Int64
pruneTargetManual = maxBound
```

`maxBound :: Int64` = `0x7fffffffffffffff` — half of Core's
sentinel. The two will never round-trip if any external tool
serialises the sentinel as a Core-compatible JSON number. Also
`pcPruneTarget :: Maybe Int64` (`Storage.hs:2154`) is signed,
which limits the addressable disk-target range to ~9.2 EiB vs
Core's 18.4 EiB (academic but architectural mismatch).

**File:** `src/Haskoin/Storage.hs:2153-2171`

**Impact:** Cosmetic until a serialiser or RPC field expects the
exact `uint64::max` sentinel. The `prune_target_size` field in
`getblockchaininfo` (`Rpc.hs:1212`) emits `AE.int64 t` which would
encode haskoin's sentinel as `9.2e18`, not Core's `1.8e19`. A
sufficiently paranoid client comparing equality against Core's
known sentinel sees a mismatch.

---

## BUG-22 (P2) — `pruneOneBlockFile` swallows IO exceptions

**Severity:** P2 (durability / forensics). `pruneOneBlockFile`
(`Storage.hs:2316-2324`):

```haskell
blkExists <- doesFileExist blkFile
when blkExists $ do
  removeFile blkFile `catch` (\(_ :: IOException) -> return ())

undoExists <- doesFileExist undoFile
when undoExists $ do
  removeFile undoFile `catch` (\(_ :: IOException) -> return ())
```

Any IOException (EBUSY, EACCES, ENOSPC during a rename, EROFS,
etc.) is silently swallowed. Then `bsFileInfos` is unconditionally
flipped to empty (`Storage.hs:2327`) and the on-disk file-info is
cleared. Now haskoin's in-memory state says "file pruned" while
the file is actually still on disk; subsequent `calculateCurrentUsage`
calls under-report disk usage; next `findFilesToPrune` doesn't
re-attempt the un-deleted file because it's no longer in
`bsFileInfos`.

**File:** `src/Haskoin/Storage.hs:2308-2332`

**Impact:** Disk leaks. Over many failed-prune cycles, blk*.dat
files orphaned on disk that haskoin will never re-attempt to
delete. Operator only notices via disk-usage monitoring.

---

## Fleet-pattern smells

- **Comment-as-confession (7th instance this audit, contributing
  to the W142–W149 streak).** `app/Main.hs:1647-1651` literally
  documents the bug it perpetuates: "We do not stand up the full
  PRESYNC/REDOWNLOAD state machine ... the chainwork gate provides
  equivalent protection." False — Core's PRESYNC accumulates
  cross-batch, haskoin's per-header gate cannot. (BUG-18)
- **Comment-as-confession (8th instance).** `Consensus.hs:436-437`
  — "We use timestamp difference as a proxy for
  GetBlockProofEquivalentTime." Proxy is wrong primitive AND has
  Word32 underflow. (BUG-13)
- **Dead-data / dead-field plumbing (W138 family + W144 family,
  10-of-21 archetype).** `pcMinBlocksToKeep` (BUG-2) is the W138
  shape; `presyncData`/`processPresyncHeaders` exists but is not
  wired into the peer flow (BUG-18) — a full subsystem
  implemented and unreachable from production. `pruneheight`
  hardcoded to 0 (BUG-20) — RPC field defined-and-emitted but
  source-of-truth is a literal `0`.
- **Three-pipeline drift (W143 family).** Chainstate mutation
  reaches RocksDB through three paths with three different
  validation surfaces:
  1. IBD: `Sync.hs` → `validateFullBlockIO` → `connectBlockAt`
     (full validation + structural write)
  2. Cache: `submitBlock` → `applyBlockToCache` → `connectBlock`
     (block-mining validation + structural write)
  3. Reindex: `Main.hs` → `connectBlock` direct
     (NO validation, structural write only — BUG-12)
  Each path's gate set diverges from the others; reindex carries
  the W145 BUG-3 inflation-primitive shape AT THE REINDEX LEVEL,
  separate from haskoin's existing cache-mutation gap.
- **Carry-forward not anchored.** `pcMinBlocksToKeep` (BUG-2)
  shows up in `defaultPruneConfig` and is passed through
  `autoPruneIfNeeded`'s signature — looks wired, isn't read. Same
  "wiring-look-but-no-wire" pattern as the W138 ChainstateManager
  family.
- **Hardcoded constants where parameters should be params-aware
  (W145 family).** `pcMinBlocksToKeep` defaults to module constant
  not per-network. No `nPruneAfterHeight` per-network constant at
  all (BUG-3). `estimatedCurrentTime` hardcoded inside
  `estimateIsInitialBlockDownload` (BUG-17) — a literal block
  timestamp baked into an IBD-exit gate.
- **Wire-format / data-correctness via swap (W125 family).**
  Testnet3/testnet4 `defaultAssumeValid` hashes swapped between
  records (BUG-16) — same shape as the W125 "labels look right but
  the data inside is the OTHER network's value".
- **Secret deployment-topology dependency (NEW pattern).** BUG-19
  — `getblock` proxies to a co-located Bitcoin Core via a
  hardcoded cookie path. Tool only works on the specific maxbox
  layout. Add to fleet-pattern catalog.
- **30-of-30-gates-buggy not fired** — this audit has 22 BUGs
  across 9 behaviours; concentration is high (3 P0-CDIV + 3 P0
  + 12 P1 + 4 P2) but not the universal-failure shape.

---

## Summary

22 BUGs. Severity-totals:

- **P0-CONS** (consensus-class on a primary code path): **1** —
  BUG-12 (`-reindex-chainstate` bypasses entire validation
  pipeline)
- **P0-CDIV** (consensus-divergent / wire-divergent / bootstrap-
  breaking): **6** — BUG-3 (no nPruneAfterHeight), BUG-13
  (assumevalid cond-6 underflow + wrong primitive), BUG-16
  (testnet3/4 assumevalid hashes swapped), BUG-17
  (estimateIsInitialBlockDownload ignores work + uses frozen
  wall-clock), BUG-18 (`too-little-chainwork` breaks mainnet
  bootstrap from genesis), BUG-19 (`getblock` proxies to external
  Core)
- **P0** (semantic gap / operational catastrophe): **2** — BUG-9
  (no persisted DB_REINDEX_FLAG), BUG-19 (see above; P0 spanning
  both consensus-divergence and operational)
- **P1**: **12** — BUG-1, BUG-2, BUG-4, BUG-6, BUG-7, BUG-8,
  BUG-10, BUG-11, BUG-14, BUG-15, BUG-20
- **P2**: **4** — BUG-5, BUG-21, BUG-22, BUG-19 (REST verbose
  wording)
- **P3**: 0

Highest-leverage fixes (in order of consensus-correctness payoff):

1. **BUG-18** — fix the `too-little-chainwork` gate to either (a)
   not fire on `minPowChecked=False` headers until cumulative
   work across the connected chain has been verified, OR (b)
   actually wire the existing `processPresyncHeaders` /
   `runPresync` state machine into the `MHeaders` handler in
   `app/Main.hs:1657`. Today's behaviour breaks mainnet
   bootstrap-from-genesis on any fresh install.
2. **BUG-16** — swap the `netAssumedValid` hashes between
   testnet3 (Consensus.hs:1183) and testnet4 (Consensus.hs:1236)
   and correct the docstrings. One-character change per line.
3. **BUG-12** — route `-reindex-chainstate` replay through
   `validateFullBlockIO` instead of bare `connectBlock`. Closes a
   CVE-2018-17144-class re-validation gap on every reindex, and
   restores parity with the IBD validation pipeline.
4. **BUG-13** — change condition 6 of `shouldSkipScripts` to
   either (a) widen to `Int64` subtraction with explicit
   negative-clamp-to-zero, OR (b) replace the timestamp proxy
   with a work-based `GetBlockProofEquivalentTime` analog.
5. **BUG-17** — rewrite `estimateIsInitialBlockDownload` to take
   tip chainwork + current wall-clock and consult
   `netMinimumChainWork`. Drop the frozen-2024 constant.
6. **BUG-3** — add `netPruneAfterHeight` to the Network record
   and gate `findFilesToPrune` on it. One field + one early
   return.
7. **BUG-19** — delete `fetchGetBlockFromCore` entirely. Return
   the Core-parity error `"Block not available (pruned data)"`
   when `isBlockPruned` is True; return `"Block not found"`
   otherwise. Closes the secret-Core-dependency.
8. **BUG-9** — persist a `DB_REINDEX_FLAG` analog key in
   chainstate so a crashed reindex resumes on restart instead of
   silently leaving a half-rebuilt chainstate.
9. **BUG-14 + BUG-15** — add `--assumevalid=<hash>` and
   `--assumevalid=0` CLI knobs; thread into a runtime override
   of `netAssumedValid net` consulted by `shouldSkipScripts`.
10. **BUG-2** — wire `pcMinBlocksToKeep` through
    `autoPruneIfNeeded` → `findFilesToPrune` so the field is
    actually read.

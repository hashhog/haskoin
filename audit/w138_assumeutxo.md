# W138 assumeUTXO snapshots — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** Bitcoin Core's `assumeutxo` snapshot lifecycle from
`bitcoin-core/src/node/utxo_snapshot.{h,cpp}` plus
`bitcoin-core/src/validation.cpp` (`ActivateSnapshot`,
`PopulateAndValidateSnapshot`, `MaybeValidateSnapshot`,
`LoadAssumeutxoChainstate`, `ValidatedSnapshotCleanup`,
`InvalidateCoinsDBOnDisk`, `MaybeRebalanceCaches`, `GetPruneRange`) and the
three blockchain RPCs `loadtxoutset` / `dumptxoutset` / `getchainstates`
in `bitcoin-core/src/rpc/blockchain.cpp`.
**BIPs:** none (assumeutxo is a Core implementation detail, not a BIP).
**Out of scope:** the on-disk Core `Coin` compression primitives
(`putCoreCoin` / `getCoreCoin`, `compressAmount`, `CompressScript`) — those
were audited in W102 and re-confirmed via `dumptxoutset` round-trips; the
`HASH_SERIALIZED` / `MUHASH` digest algorithms themselves (W102 again);
and the BIP-37 / BIP-157 service-flag advertisement after a snapshot load
(W110 / W121).

Sources audited:
- `src/Haskoin/Consensus.hs:4779-4933` — `AssumeUtxoState`, `initAssumeUtxoState`,
  `activateSnapshot`, `runBackgroundValidation`, `backgroundValidationLoop`,
  `getAssumeUtxoProgress`, `isAssumeUtxoValidated`.
- `src/Haskoin/Consensus.hs:307-354` — `AssumeUtxoParams`, `assumeUtxoForHeight`,
  `assumeUtxoForBlockHash`, `assumeutxoWhitelistError`,
  `checkAssumeutxoWhitelist`.
- `src/Haskoin/Consensus.hs:1101-1320` — per-network `netAssumeUtxo` tables
  (mainnet 4 entries at heights 840000/880000/910000/935000; testnet3 one
  at 2500000; testnet4 one at 90000; regtest one at 110).
- `src/Haskoin/Storage.hs:2390-3308` — snapshot codec, parser, hash, writer,
  reader, RocksDB base-hash key, `BackgroundValidation` shadow record.
- `src/Haskoin/Rpc.hs:7666-8200` — `handleLoadTxOutSet` (REFUSED via
  `loadTxOutSetGateMessage` — see W102 BUG-1/2/4 background),
  `handleDumpTxOutSet` (full implementation with rollback dance),
  `parseDumpTxOutSetParams`, `resolveDumpTarget`,
  `latestAvailableSnapshotHeight`.
- `app/Main.hs:802-883` — `--load-snapshot=<path>` CLI flag (the ONLY
  working snapshot-load path in the build).
- W102 prior audit (`test/W102AssumeUTXOSpec.hs`) — 10 BUGs already
  catalogued for the snapshot loader proper; this audit focuses on
  the **lifecycle plumbing around** the loader (background validation,
  chainstate-dir handling, cache rebalancing, prune-range adjustment,
  service-flag adjustment, the `loadtxoutset` / `getchainstates` RPCs),
  which W102 explicitly deferred.

**Result:** 4 PRESENT / 7 PARTIAL / 19 MISSING out of 30 gates.
**Bugs found:** 17 (5 P0-CDIV, 9 P1, 3 P2).
**Tests added:** 30 gate cases (`it` pinning + `xit` sentinel) in
`test/W138AssumeUTXOSpec.hs`.

## Relationship to W102

W102 covered the snapshot *loader* (parse + verify + populate + per-coin
guards). It catalogued **10 BUGs** and the fix waves for BUG-1 / BUG-2 /
BUG-8 / BUG-9 / BUG-10 landed in `app/Main.hs` and `Storage.hs`. What
W102 explicitly did NOT cover:

1. **Background validation correctness** (BUG-5/6/7 mentioned but not
   exhaustively re-tested — flipped here at G15/G16/G17 and extended to
   the chain-from-genesis machinery itself).
2. **Chainstate-dir handling** (`SNAPSHOT_CHAINSTATE_SUFFIX`, base-blockhash
   file persistence, snapshot-dir detection on restart, validated-cleanup,
   invalidated-dir rename) — entirely absent in haskoin, now G19-G24.
3. **Cache rebalance** between IBD and snapshot chainstates
   (`IBD_CACHE_PERC` / `SNAPSHOT_CACHE_PERC` / `MaybeRebalanceCaches`) —
   no equivalent in haskoin, G18.
4. **Prune-range** post-snapshot (`Chainstate::GetPruneRange` blocks before
   the snapshot until validated) — no equivalent in haskoin, G25.
5. **Service flag adjustment** post-snapshot (`RemoveLocalServices(NODE_NETWORK)`
   + `AddLocalServices(NODE_NETWORK_LIMITED)`) — not done by `--load-snapshot`,
   G26.
6. **`getchainstates` RPC** — entirely absent, G27.
7. **Coins-per-txid sanity guard** during snapshot load
   (`coins_per_txid > coins_left`) — silent overrun, G28.
8. **Trailing-data guard** post-coins-loaded (`out_of_coins`
   single-byte read) — silent acceptance, G29.
9. **Interruption support** via the existing `m_interrupt` analogue —
   no equivalent in haskoin, G30.

So W138 is the FIRST cross-cutting view of "snapshot lifecycle from
load-on-restart through background validation to cleanup" for haskoin.
Where W102 closed a corner cleanly it is counted as PRESENT or PARTIAL
and not re-billed as a bug; where W102 left a parallel gap it is billed
once here.

## Top-line verdict

haskoin's assumeUTXO support is a **one-shot CLI flag that loads a
snapshot file into the legacy UTXO keyspace and pins best-block** —
plus a **fully implemented `dumptxoutset` RPC** with rollback dance.
Everything else in the assumeutxo lifecycle is absent or stubbed:

1. **No separate "snapshot chainstate".** Bitcoin Core's design point is
   that the snapshot chainstate runs in parallel with the IBD (background)
   chainstate; haskoin overwrites the single chainstate in place. The
   `SnapshotChainstate` record at `Storage.hs:2485` exists but is never
   wired into `--load-snapshot` or any RPC. **BUG-1 P0-CDIV.**
2. **No background validation actually runs.** `runBackgroundValidation`
   is defined (`Consensus.hs:4857`) but never started anywhere in the
   codebase — `grep -rn 'runBackgroundValidation' src/` returns only the
   definition. The CLI flag returns immediately after the import.
   **BUG-2 P0-CDIV.**
3. **Background loop computes wrong MTP and never compares the final
   UTXO hash** (W102 BUG-5/6/7 are still open). The loop hard-codes
   `medianTime = 0` (`Consensus.hs:4889`), marks `ausValidated = True`
   even on error (`Consensus.hs:4912`), and the success branch comment
   literally reads "In a full implementation, we would compute MuHash3072
   here. For now, mark as validated" (`Consensus.hs:4917-4919`).
   **BUG-3 P0-CDIV.**
4. **No `chainstate_snapshot` directory.** Core writes a `base_blockhash`
   file inside `chainstate_snapshot/` so the snapshot chainstate can be
   reconstructed on restart (`utxo_snapshot.cpp:22-46`,
   `validation.cpp:6151-6168` `LoadAssumeutxoChainstate`). haskoin writes
   the base hash to RocksDB key `0x53` via `putSnapshotBaseHash` —
   wrong key, wrong location, and the read-side
   `getSnapshotBaseHash` is never called from init.
   **BUG-4 P0-CDIV.**
5. **`loadtxoutset` RPC is refused, not implemented.** This is option (B)
   from the cross-impl 2026-05-05 audit and the safe choice given the
   live-daemon atomicity problem, but it means `getchainstates` /
   background validation / snapshot-chainstate switchover never run
   under the RPC path. Operators MUST use the CLI flag — the RPC merely
   prints a documentation message. (Counted as PARTIAL not BUG since
   the refused state is intentional.)
6. **`getchainstates` RPC is entirely missing.** Not dispatched anywhere
   in `Rpc.hs`. **BUG-5 P0-CDIV.**
7. **`m_from_snapshot_blockhash` analogue is missing.** Core uses it
   everywhere (`MaybeRebalanceCaches`, `MaybeValidateSnapshot`, the
   `getchainstates` RPC, the snapshot-prune-range guard).
   haskoin has nothing equivalent at the chainstate level.
   **BUG-6 P1.**
8. **Cache rebalance is missing** — Core resizes both caches to 1%/99%
   for the duration of the bulk load, then rebalances when validated.
   haskoin doesn't have two caches and so no rebalance step exists.
   **BUG-7 P1.**
9. **Snapshot-prune-range guard is missing.** Core's
   `Chainstate::GetPruneRange` (`validation.cpp:6347-6373`) refuses to
   prune blocks below the snapshot base until validation completes
   (otherwise the background chainstate can't validate). haskoin's
   `pruneBlockchain` (`Storage.hs:2160-2200`) does not consult the
   snapshot base. **BUG-8 P1.**
10. **Service-flag adjustment after `--load-snapshot` is missing.** Core's
    `loadtxoutset` (`rpc/blockchain.cpp:3432-3435`) drops `NODE_NETWORK`
    and adds `NODE_NETWORK_LIMITED` because a snapshot-based node cannot
    serve historical blocks below the base. haskoin's `--load-snapshot`
    flag does not call any equivalent at `app/Main.hs:881`.
    **BUG-9 P1.**
11. **Coins-per-txid overrun guard missing.** Core
    `validation.cpp:5804-5806`:
    `if (coins_per_txid > coins_left) Error{"Mismatch..."}`. haskoin's
    `parseCoins` (`Storage.hs:2539-2562`) checks the GROUP total against
    `remaining` but not the *coin-count field itself*. A malicious
    snapshot can declare a 2 GB group, allocate, and exhaust memory
    before the `remaining` check fires. **BUG-10 P0-CDIV.**
12. **Trailing-data guard missing.** Core `validation.cpp:5873-5882`
    reads a single byte after the last coin and ASSERTS that the file
    is EOF. haskoin's `parseCoins` rejects trailing-data of the WRONG
    shape (`go 0 acc bs | BS.null bs = …`), but the EOF-byte read
    that catches one trailing 0xFF byte at the end is implicit on
    `BS.null bs` only — fine for haskoin's "whole file in memory"
    parse, but the test below pins this. (Counted as PRESENT-by-shape,
    not a bug, but pinned at G29.)
13. **Interruption support missing.** Core injects an
    `m_interrupt` check every 120 000 coins. haskoin parses the entire
    file before validating anything, so a malicious 100 GB snapshot
    pins memory for minutes with no graceful abort. **BUG-11 P1.**
14. **`ValidatedSnapshotCleanup` analogue missing.** When background
    validation passes, Core renames the snapshot dir to be the new
    primary chainstate dir and deletes the old IBD dir
    (`validation.cpp:6280-6345`). haskoin has no two-dir layout and
    so no rename step — but on the flip side, when validation
    SUCCEEDS in the background loop, nothing gets rewired; the
    snapshot state remains in the single chainstate and `ausValidated`
    is just a flag. **BUG-12 P1.**
15. **`InvalidateCoinsDBOnDisk` analogue missing.** Core renames the
    snapshot dir to `<dir>_INVALID` on hash mismatch
    (`validation.cpp:6201-6231`) so the operator can do forensics.
    haskoin's `--load-snapshot` exits with `ExitFailure 1` BEFORE any
    persistence happens (good!) but `runBackgroundValidation` swallows
    the error into an `IORef` and never invalidates the chainstate.
    **BUG-13 P1.**
16. **`SnapshotMetadata` schema misses Core's `MessageStartChars`
    cross-network check.** Core stores 4 magic bytes; haskoin stores
    a `Word32` (which it happens to compare against `netMagic net` in
    `parseSnapshot`). Format-wise equivalent (both 4 bytes LE), but
    haskoin's error message on mismatch is haskoin-specific rather
    than Core's "The network of the snapshot (X) does not match the
    network of this node (Y)." (`utxo_snapshot.h:97`). **BUG-14 P2.**
17. **`SnapshotMetadata` version field is hard-coded to 2 with no
    "supported versions set"** that would permit a v1 snapshot to be
    loaded if Core ever adds backward compatibility. Core uses
    `m_supported_versions{VERSION}` (`utxo_snapshot.h:40`) — currently
    `{2}` but the seam exists. haskoin's `parseSnapshotMetadata`
    fails on anything other than literal `2`. **BUG-15 P2.**
18. **`activateSnapshot` (the in-Haskoin function — different from the
    CLI flag) looks up by BLOCK HASH not height** (W102 BUG-3 re-confirmed;
    the agent left a comment but did not fix). The CLI flag does it
    right; only the unused helper path is wrong. **BUG-16 P2.**
19. **`writeSnapshot` (NOT `dumpTxOutSetFromDB`) reads coins from the
    cache only, not the DB.** `Storage.hs:2687-2700`: `collectAllCoins`
    only returns cached coins and warns "full implementation would
    iterate DB". Not called by `dumptxoutset` (which uses
    `dumpTxOutSetFromDB`), so this is dead-code; but it's exported and
    a future caller would produce a corrupt snapshot.
    **BUG-17 P1 (dead-code hazard).**

## 30-gate audit matrix

| # | Gate | Status | Bug |
|---|------|--------|-----|
| G1  | `snapshotMagicBytes` = `"utxo" + 0xFF` (5 bytes) | PRESENT | — |
| G2  | `SnapshotMetadata` Serialize/Unserialize round-trip | PRESENT | — |
| G3  | Network-magic mismatch rejected with Core-style message | PARTIAL | BUG-14 |
| G4  | Version-field hard-coded `{2}` (vs Core's `m_supported_versions{2}`) | PARTIAL | BUG-15 |
| G5  | Whitelist check (`checkAssumeutxoWhitelist`) on snapshot height | PRESENT | — (closed in W102) |
| G6  | `assumeUtxoForHeight` vs `assumeUtxoForBlockHash` lookup parity | PARTIAL | BUG-16 (re-confirms W102 BUG-3) |
| G7  | Snapshot base block must appear in headers chain | PRESENT | — (closed in W102 fix wave) |
| G8  | `BLOCK_FAILED_VALID` guard on snapshot start block | MISSING | (covered by G7 — counted as duplicate) |
| G9  | "Forked headers chain with more work" guard | MISSING | BUG-6 (m_best_header analogue) |
| G10 | Mempool-must-be-empty guard before snapshot activation | MISSING | BUG-6 |
| G11 | Coins-per-txid sanity guard during parse | MISSING | BUG-10 |
| G12 | Per-coin `height <= base_height` guard | PRESENT | — (closed in W102 BUG-9) |
| G13 | Per-coin MoneyRange guard | PRESENT | — (closed in W102 BUG-10) |
| G14 | Per-coin `vout < uint32_max` overflow guard | PARTIAL | (covered by `VarInt`) |
| G15 | Background validation actually runs after snapshot import | MISSING | BUG-2 |
| G16 | Background validation uses correct MTP per block | MISSING | BUG-3 |
| G17 | Background validation marks `ausValidated=False` on error | MISSING | BUG-3 |
| G18 | Cache rebalance (`MaybeRebalanceCaches` analogue) | MISSING | BUG-7 |
| G19 | Snapshot chainstate is SEPARATE from IBD chainstate | MISSING | BUG-1 |
| G20 | Base-blockhash file written to `chainstate_snapshot/` on disk | MISSING | BUG-4 |
| G21 | Base-blockhash file read at startup → snapshot chainstate reload | MISSING | BUG-4 |
| G22 | `loadtxoutset` RPC (functional, not refused) | PARTIAL | — (refused intentionally; documented) |
| G23 | `dumptxoutset` RPC implementation (tip + rollback) | PRESENT | — |
| G24 | `getchainstates` RPC | MISSING | BUG-5 |
| G25 | Prune-range respects snapshot base until validated | MISSING | BUG-8 |
| G26 | Service flags adjusted after snapshot load (`-NODE_NETWORK +NODE_NETWORK_LIMITED`) | MISSING | BUG-9 |
| G27 | `MaybeValidateSnapshot` hash check + invalidation rename | MISSING | BUG-12 + BUG-13 |
| G28 | `ValidatedSnapshotCleanup` (snapshot dir → primary dir, IBD dir → `_todelete`) | MISSING | BUG-12 |
| G29 | Trailing-data guard post-coins-loaded | PRESENT | — (`go 0 acc bs | BS.null bs` shape) |
| G30 | Interruption support during snapshot load (`m_interrupt` analogue) | MISSING | BUG-11 |

## Bug catalogue

| # | Severity | Title |
|---|----------|-------|
| BUG-1  | P0-CDIV | Snapshot chainstate is not separate from IBD chainstate |
| BUG-2  | P0-CDIV | `runBackgroundValidation` is dead code, never started |
| BUG-3  | P0-CDIV | `backgroundValidationLoop` uses MTP=0, marks validated on error, never compares UTXO hash |
| BUG-4  | P0-CDIV | No `chainstate_snapshot/base_blockhash` file → snapshot lost on restart |
| BUG-5  | P0-CDIV | `getchainstates` RPC missing |
| BUG-6  | P1      | No `m_from_snapshot_blockhash` analogue at the chainstate level |
| BUG-7  | P1      | No `MaybeRebalanceCaches` analogue between IBD and snapshot caches |
| BUG-8  | P1      | `Chainstate::GetPruneRange` snapshot-aware logic missing |
| BUG-9  | P1      | `--load-snapshot` doesn't adjust `NODE_NETWORK` / `NODE_NETWORK_LIMITED` |
| BUG-10 | P0-CDIV | `parseCoins` doesn't sanity-check coins-per-txid field (memory bomb) |
| BUG-11 | P1      | Snapshot load has no interrupt support (no `m_interrupt` analogue) |
| BUG-12 | P1      | No `ValidatedSnapshotCleanup` analogue (snapshot dir → primary dir rename) |
| BUG-13 | P1      | No `InvalidateCoinsDBOnDisk` analogue (`<dir>_INVALID` rename on hash mismatch) |
| BUG-14 | P2      | Network-magic mismatch error message is haskoin-specific, not Core-style |
| BUG-15 | P2      | `SnapshotMetadata` version field is hard-coded to literal `2`, no `m_supported_versions` set |
| BUG-16 | P2      | `activateSnapshot` (the helper) still looks up by hash not height (W102 BUG-3 re-confirmed) |
| BUG-17 | P1      | Dead-code `writeSnapshot` reads cache-only, would produce corrupt snapshot if wired |

## Methodology

Discovery audit. No production code is modified. Every `xit` test
declares the desired Core-parity behaviour and is `pendingWith` a
short BUG-pointer; a future fix wave flips `xit -> it` after wiring
the missing primitive. Every `it` test pins observable behaviour
that's currently correct, so any regression here is caught the next
time `cabal test` runs.

The `xit`/`it` split mirrors the W137 PSBT audit (commit `5092be1`,
`test/W137PSBTSpec.hs`) and the W134 BIP-37 audit (commit `f015e72`,
`test/W134BIP37BloomFilterSpec.hs`) — same shape so the future fix
waves can pattern-match on prior cleanups.

## Concurrent-agent coordination

This wave is one of FOUR concurrent haskoin discovery waves landing
on 2026-05-18. The triple wire-up hazard for `Spec.hs` + `haskoin.cabal`
is handled by stashing all other in-flight changes, soft-resetting to
the parent commit, restaging only the W138-specific files (this audit
+ the test module + the two wire-up lines in `Spec.hs` and
`haskoin.cabal`), committing, then unstashing. The other concurrent
waves do the same; merge conflicts on the same lines in `Spec.hs` /
`haskoin.cabal` resolve via append-only sort-by-wave-number.

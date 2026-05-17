# W123 Mining / GBT parity audit — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — 17 bugs across 30 gates
**Scope:** `src/Haskoin/BlockTemplate.hs` + mining RPC handlers in
`src/Haskoin/Rpc.hs` (getblocktemplate / submitblock / getmininginfo
/ generate*)
**Result:** 45 Hspec examples; 19 pending (= bug observations) + 26
PRESENT/PASS assertions

## Context

W108 already covered the BIP-22 result-string passthrough table, the
regtest-coinbase two-pipeline gaps (`buildRegtestCoinbase` nSequence /
nLockTime / witness output), the isFinalTx constants, and the basic
GBT IBD / connection / segwit-rules guards.  W123 takes DIFFERENT
angles — it is a fresh discovery pass focused on:

  1. RPCs entirely absent from the dispatch table.
  2. BIP-22 `include_dummy_extranonce` consensus floor (bad-cb-length
     at heights 1..16 when extranonce is empty).
  3. `getmininginfo` response shape parity (`networkhashps`,
     `currentblockweight`, `currentblocktx`, `signet_challenge`,
     warnings-array).
  4. `estimateIsInitialBlockDownload` uses a **HARDCODED** 2025
     baseline that will eventually trip every node into IBD.
  5. Anti-fee-sniping randomisation gap (Core's 10 % probabilistic
     locktime offset + lagging-chain → 0 fallback).
  6. Regtest two-pipeline divergences W108 did not enumerate
     (block-version, reservedWeight, fee handling).

## References

- `bitcoin-core/src/node/miner.cpp` — `BlockAssembler::CreateNewBlock`,
  `GetMinimumTime`, `UpdateTime`, `RegenerateCommitments`.
- `bitcoin-core/src/rpc/mining.cpp` — `getblocktemplate`,
  `submitblock`, `submitheader`, `prioritisetransaction`,
  `getmininginfo`, `getnetworkhashps`, `generatetoaddress`,
  `generatetodescriptor`, `generateblock`, `generate`.
- `bitcoin-core/src/policy/policy.h` —
  `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`.
- BIP-22 (getblocktemplate), BIP-23 (proposal mode), BIP-141
  (segwit / commitment), BIP-9 (versionbits), BIP-152 (compact
  blocks → `submitheader` is part of the upgrade path).

## Gates summary

| #   | Title                                                      | Status   | Pri  |
| --- | ---------------------------------------------------------- | -------- | ---- |
| G1  | `submitheader` RPC                                         | MISSING  | P1   |
| G2  | `prioritisetransaction` RPC + mempool fee deltas           | MISSING  | P1   |
| G3  | `getprioritisedtransactions` RPC                           | MISSING  | P2   |
| G4  | `include_dummy_extranonce` (bad-cb-length at h=1..16)      | BUG      | **P0-CONSENSUS** |
| G5  | `networkhashps` in `getmininginfo` (hardcoded 0)           | BUG      | P1   |
| G6  | `currentblockweight` + `currentblocktx`                    | MISSING  | P2   |
| G7  | `signet_challenge` in getmininginfo / GBT                  | MISSING  | P2   |
| G8  | `warnings` shape (string vs array)                         | BUG      | P2   |
| G9  | `estimateIsInitialBlockDownload` hardcoded 2025 constant   | BUG      | **P0-LATENT** |
| G10 | `setAntiFeeSniping` 10 % randomisation + lagging-chain     | BUG      | P2   |
| G11 | `generateSingleBlock` drops mempool fees                   | BUG      | P1   |
| G12 | `generateSingleBlock` hardcodes `bhVersion=0x20000000`     | BUG      | P2   |
| G13 | `generateSingleBlock` `reservedWeight=4000` (vs 8000)      | divergence | P2 |
| G14 | `generatetoaddress` maxtries parameter ignored             | BUG      | P2   |
| G15 | `findRegtestNonce` loops to Word32 maxBound                | BUG      | P2   |
| G16 | `encodeRegtestHeight` diverges from `encodeBip34Height`    | BUG      | P1   |
| G17 | `submitBlock` duplicate-vs-inconclusive split              | MISSING  | P1   |
| G18 | `encodeHeight` delegation (regression guard)               | PRESENT  | —    |
| G19 | `buildCoinbase` scriptSig length (h>=17)                   | PRESENT  | —    |
| G20 | `buildCoinbase` witness commitment OP_RETURN output        | PRESENT  | —    |
| G21 | `buildCoinbase` nSequence = `MAX_SEQUENCE_NONFINAL`        | PRESENT  | —    |
| G22 | `buildCoinbase` nLockTime = nHeight - 1                    | PRESENT  | —    |
| G23 | `blockReward` halvings ladder                              | PRESENT  | —    |
| G24 | GBT `longpollid` no transactions-updated counter           | BUG      | P2   |
| G25 | GBT `vbrequired` hardcoded 0 + no mask machinery           | BUG      | P2   |
| G26 | GBT `sizelimit = 4_000_000`                                | PRESENT  | —    |
| G27 | `buildCoinbase` 100-byte upper-bound clamp absent          | BUG-LATENT | P2 |
| G28 | BIP-22 `coinbasetxn` / `workid` capabilities               | MISSING  | P2   |
| G29 | GBT template cooldown / cache absent                       | BUG      | P2   |
| G30 | RPC error codes `-9` / `-10` not defined                   | MISSING  | P2   |

**Tally:** 17 bug findings (1 P0-CONSENSUS, 1 P0-LATENT, 4 P1, 11
P2), 8 PRESENT/PASS gates, 5 MISSING-RPC items.  Total Hspec: 45
examples / 0 failures / 19 pending.

## Top findings

### BUG-4 [P0-CONSENSUS]: `bad-cb-length` at heights 1..16 with empty extraNonce

`buildCoinbase` builds the scriptSig as `heightBytes <> extraNonce`.
`encodeBip34Height` correctly emits OP_0 / OP_1..OP_16 (a single byte)
for h=0..16.  Consensus check `validateTransaction`
(`Consensus.hs:1426`) requires coinbase scriptSig length `2..100`.  If
the GBT handler (or any external caller) passes `extraNonce = BS.empty`
at h=0..16, the resulting scriptSig is exactly 1 byte — fails
`bad-cb-length` immediately on submit.

`handleTemplateRequest` (`Rpc.hs:2773`) does exactly this:

```haskell
bt <- createBlockTemplate (rsNetwork server) (rsHeaderChain server)
        (rsMempool server) (rsUTXOCache server)
        BS.empty BS.empty  -- placeholder coinbase script
```

i.e. the GBT response coinbase is unbuildable on the first 17 blocks
of any new regtest chain.  Core's fix is `include_dummy_extranonce`
in `BlockAssembler::Options` — append OP_0 (0x00) so the scriptSig
clears the 2-byte floor.

### BUG-9 [P0-LATENT]: `estimateIsInitialBlockDownload` baseline is a frozen 2025 constant

```haskell
let estimatedCurrentTime = 1231006505 + (850000 * 600) :: Word32
```

= `1_740_006_505` ≈ **2025-02-19 UTC**.

Today (2026-05-17) the baseline is ~15 months stale.  The function
classifies the chain as "in IBD" iff `blockTime + 24h <
estimatedCurrentTime`, i.e. iff the tip is more than 24 h behind the
**frozen** 2025-02 reference.  Every haskoin mainnet node has been
silently reporting `inIBD = false` for tips beyond the constant since
2025-02-20 — fine in 2026 because real tips have moved forward, but
the threshold inverts as soon as `blockTime > 1_740_092_905`.  At
that point we get `inIBD = false` for ALL recent blocks even when
fresh-syncing.  Either direction is a hazard.

Used in three call sites (`Rpc.hs:1179`, `:1381`, `:9633`), all of
which gate other RPC behaviour on the result.  Fix is a 5-line
`getCurrentTime` plumb-through.

### BUG-11 [P1]: `generateSingleBlock` drops mempool fees from coinbase (source-confessed)

`Rpc.hs:3277-3280`:

```haskell
let reward = blockReward height
-- Note: For regtest with specific transactions, we would add their fees too
-- For simplicity, we use just the block reward here
let coinbase = buildRegtestCoinbase height reward scriptPubKey blockTime
```

Result: every regtest block mined via `generatetoaddress` /
`generateblock` / `generate` burns mempool fees.  Inconsistent with
the GBT path (`createBlockTemplate` correctly does
`reward + totalFees`).  Pattern matches W120 / W122 "comment-as-
confession" universal finding.

### BUG-16 [P1]: `encodeRegtestHeight` two-pipeline divergence

`encodeRegtestHeight` (`Rpc.hs:3347-3359`) always emits a
length-prefixed push, even for h=0..16:

  - `h=5` → `[0x01, 0x05]` (push 1 byte, value 5).
  - `encodeBip34Height 5` → `[0x55]` (OP_5).

`validateCoinbaseHeightConsensus` (`Consensus.hs:2050`) does a
byte-exact PREFIX match against `encodeBip34Height`.  So a regtest
block mined via this path at h=5 will fail the consensus check ONCE
BIP-34 is active on regtest (which it is at h=1 on regtest).

Symmetric to W108 BUG-11 / BUG-12 / BUG-13 (regtest-coinbase
two-pipeline) but on a different field (height encoding rather than
sequence/locktime/witness-output).

### BUG-17 [P1]: no duplicate-vs-inconclusive split in submitblock result

Core (`mining.cpp:1097-1102`) distinguishes `"duplicate"` (block
accepted but already known) from `"inconclusive"` (state catcher
saw no callback).  haskoin's `submitBlock` returns a single `Left`
which `bip22ResultString` maps to `"rejected"` for both cases.
Mining pools' BIP-22 result handlers misclassify both.  Companion
to W108 BUG-16.

## Two-pipeline patterns (recap of W123 finds)

| Site                                           | Divergent field                       |
| ---------------------------------------------- | ------------------------------------- |
| `buildCoinbase` vs `buildRegtestCoinbase`      | (W108) nSequence / nLockTime / witout |
| `createBlockTemplate` vs `generateSingleBlock` | **fees, version, reservedWeight**     |
| `encodeBip34Height` vs `encodeRegtestHeight`   | **h=0..16 encoding**                  |

## Universal patterns this audit confirms

- **"Comment-as-confession"** — `generateSingleBlock` (G11) and the
  `findRegtestNonce` upper bound (G14/G15) both ship with apologetic
  comments explaining the gap.  This is the 12th wave to find at
  least one such instance.
- **"Function exists but never wired"** — `handleGetNetworkHashPS`
  (a full computation, `Rpc.hs:10602`) exists and is registered,
  yet `handleGetMiningInfo` hardcodes the same field to `0`.
  Dead-helper-at-call-site, 34th wave streak.
- **"RPC dispatch table gap, foundational"** — `submitheader`,
  `prioritisetransaction`, `getprioritisedtransactions` not in the
  dispatch (lines 1038-1145).  3 missing RPCs from a single Core
  category.
- **"Test-fixture-masks-production-invariant-incompleteness"** —
  G18 / G19 / G20 / G21 / G22 PASS because the constants and the
  GBT path are correct; the GBT path FEEDS those constants into a
  caller (`handleTemplateRequest`) that pre-zeros the coinbase
  script before any consensus check sees the result.  Anti-fee-
  sniping (G10) and the IBD constant (G9) follow the same shape.
- **"Frozen constants degrade silently"** — G9 baseline (W123) is
  the 3rd wave to find a hardcoded "current time" / "now" constant
  in production code (after W108 BUG-14 regtest bits and W121
  `BlockFilterIndex::index_block` dead-code).

## Out of scope

- BIP-22 long-polling (BUG-4a / BUG-4b on W108 already cover the
  surface).
- `bip22ResultString` table (W108 G28 / G29 / G30 covered).
- Consensus / submitBlock side-branch routing (W97 / W99 / Pattern
  X).
- Fix work.  W123 is DISCOVERY-only; the 17 bug observations land
  as `pending` in `test/W123MiningGBTSpec.hs` and as PASS-witness
  assertions where the bug demonstrates by emitting the wrong
  value (G4, G9, G16, G27).

## Files touched

- `test/W123MiningGBTSpec.hs` — 30 gates / 45 Hspec examples.
- `haskoin.cabal` — registered new `other-module`.
- `test/Spec.hs` — wired into the runner.
- `audit/w123_mining_gbt.md` — this file.

No production code changes.

# Changelog

All notable changes to haskoin are documented in this file.

## [1.0.0.0] - 2026-07-31

First stable release: a Bitcoin full node written from scratch in Haskell,
validated for consensus parity against Bitcoin Core.

### Highlights

- Full block and transaction validation with all consensus BIP rules
  (BIP-34/65/66/68/112/113, SegWit BIP-141/143/147, Taproot BIP-340/341/342),
  including BIP-113 median-time-past header gating and BIP-68 ancestry-aware
  MTP resolution on reorg connect.
- Script interpreter covering P2PKH, P2SH, P2WPKH, P2WSH, and P2TR, with
  Core-parity sigop accounting and script-verify flag wiring on every
  validation path (block connect, parallel verify, mempool admission).
- Headers-first IBD with a parallel block-download pipeline, RocksDB-backed
  storage with UTXO cache, and Core-parity BLOCK_DOWNLOAD_WINDOW depth.
- Mempool with full RBF (BIP-125), cluster limits, TRUC (BIP-431) policy,
  package acceptance (BIP-331 submitpackage), and reorg refill of
  disconnected non-coinbase transactions.
- AssumeUTXO snapshot load (`--load-snapshot`, `loadtxoutset`,
  `dumptxoutset`) with two-stage independent re-derivation, plus
  assumevalid script skipping (`--noassumevalid` to disable).
- HD wallet (BIP-32/39/44/84/86) with durable, AES-sealed-at-rest
  persistence, PSBT (BIP-174/370/371), output descriptors (BIP-380-386),
  and Miniscript (BIP-379).
- BIP-324 v2 encrypted transport (on by default, Core v26+ parity) with
  CSPRNG-generated session keys and full 16-byte v1-prefix detection.
- Block indexes: txindex, BIP-157/158 compact block filters
  (bit-stream codec byte-compatible with Core), coinstatsindex.
- Peer manager with addrman (routability-gated, Core `AddSingle` parity),
  misbehavior scoring, inbound caps with eviction, Tor/I2P connectivity,
  and BIP-155 addrv2.
- RPC server with Core-compatible `getblock` verbosity 0-3, mempool RPCs
  with Core bare reject tokens, and regtest mining RPCs.

### Release-blocker fixes since 0.1.0.0

- consensus: `validateFullBlock` evaluated `tail txns` (coinbase maturity
  check) before the empty-block guard, so a block with zero transactions
  crashed with `Prelude.tail: empty list` instead of a clean rejection.
  The "Block has no transactions" guard now runs first, matching Core's
  CheckBlock (`bad-cb-missing`) ordering.
- p2p: BIP-324 handshake session keys, auxiliary randomness, and garbage
  are now drawn from a CSPRNG (cryptonite `/dev/urandom`) instead of
  `System.Random` — Core parity (`GetStrongRandBytes`) for the ephemeral
  key material BIP-324 forward secrecy depends on.
- tests: refreshed stale expectations for intentional Core-parity behavior
  changes (BIP-113 MTP gating, accurate sigop counting, MSB-first BIP-158
  bit stream, BE keypath fingerprints, v2-by-default transport, addrman
  routability gate, RocksDB `maxOpenFiles` 16384, expanded assumeutxo
  table, real wallet persistence, live two-stage `loadtxoutset`), and
  converted closed gap sentinels into assertions of the fixed behavior
  (W98 G1/G26, W98 G13/G14, W111 G23, W118 DH-2).
- ci: re-enabled the CI and release workflows.

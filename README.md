# haskoin

A Bitcoin full node implementation in Haskell.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from
scratch. haskoin is a from-scratch Bitcoin full node written in Haskell that
does exactly that, using pure functions for consensus logic and the type
system to make invalid states unrepresentable.

## Current status

- [x] Core data types (Hash256, TxId, BlockHash, etc.)
- [x] Binary serialization via cereal
- [x] VarInt encoding and SegWit transaction support
- [x] Cryptographic hashing (SHA256, doubleSHA256, RIPEMD160, HASH160)
- [x] Address encoding (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Script parsing, classification, and interpreter
- [x] Full consensus validation with all BIP rules
- [x] RocksDB storage layer with UTXO cache
- [x] P2P networking with peer manager, misbehavior scoring, and connection eviction
- [x] Stale peer eviction (ping timeout, block stall, chain sync timeout)
- [x] Headers-first sync and IBD pipeline
- [x] Transaction mempool with RBF support
- [x] Fee estimation with confirmation tracking
- [x] Block template construction for mining
- [x] Bitcoin Core compatible JSON-RPC server
- [x] HD wallet (BIP-32/39/44/84)
- [x] CLI with node, wallet, and utility commands
- [x] Performance optimizations (parallel validation, LRU cache, metrics)
- [x] Block indexes (txindex, blockfilterindex, coinstatsindex)
- [x] PSBT (BIP-174/BIP-370) - create, update, sign, combine, finalize
- [x] Output descriptors (BIP-380-386) - parse, checksum, derive addresses
- [x] Miniscript (BIP-379) - type system, compilation, satisfaction
- [ ] ECDSA signing/verification (requires secp256k1)

## Quick start

```bash
cabal build
cabal run haskoin -- --help
cabal run haskoin -- node --network Regtest --rpcport 18443
cabal test
```

For optimized builds with RTS tuning:

```bash
cabal build -O2
cabal run haskoin -- +RTS -N -A64m -H2G -I0 -RTS node --network mainnet
```

## Project structure

```
haskoin/
  src/Haskoin/
    Types.hs         -- core data types and serialization
    Crypto.hs        -- hashing, keys, signatures, addresses
    Script.hs        -- script parsing and interpreter
    Consensus.hs     -- validation, header sync, reorgs
    Storage.hs       -- rocksdb persistence, UTXO cache
    Network.hs       -- p2p messages, peer connection, ban scoring, eviction
    Sync.hs          -- block download, IBD pipeline
    Mempool.hs       -- transaction pool, RBF
    FeeEstimator.hs  -- fee rate estimation
    BlockTemplate.hs -- block template for mining
    Rpc.hs           -- json-rpc server, importdescriptors
    Wallet.hs        -- hd wallet, psbt, output descriptors
    Performance.hs   -- parallel validation, LRU cache, metrics
    Index.hs         -- txindex, blockfilterindex, coinstatsindex
  bench/
    Bench.hs         -- criterion benchmarks
  app/
    Main.hs          -- CLI entry point
  test/
    Spec.hs          -- test suite
```

## Running tests

```bash
cabal test --test-show-details=direct
```

## Running benchmarks

```bash
cabal bench --benchmark-options='-o report.html'
```

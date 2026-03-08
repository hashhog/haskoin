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
- [x] VarInt encoding
- [x] Transaction types with SegWit support
- [x] Block and BlockHeader types
- [x] Network address type
- [ ] Cryptographic hashing (SHA256d, RIPEMD160)
- [ ] Script parsing and execution
- [ ] Transaction validation
- [ ] Block validation
- [ ] P2P networking
- [ ] Chain state management

## Quick start

```bash
cabal build
cabal test
cabal run haskoin
```

## Project structure

```
haskoin/
  src/
    Haskoin/
      Types.hs      -- core data types and serialization
  app/
    Main.hs         -- executable entry point
  test/
    Spec.hs         -- serialization tests
```

## Running tests

```bash
cabal test
```

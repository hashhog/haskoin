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
- [x] Cryptographic hashing (SHA256, doubleSHA256, RIPEMD160, HASH160)
- [x] HMAC-SHA512 for key derivation
- [x] Public key parsing and serialization
- [x] DER signature parsing
- [x] Sighash computation (legacy and BIP-143 SegWit)
- [x] Address encoding (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] Base58Check encoding/decoding
- [x] Bech32/Bech32m encoding/decoding (BIP-173, BIP-350)
- [ ] ECDSA signing/verification (requires secp256k1)
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
      Crypto.hs     -- hashing, keys, signatures, sighash, addresses
  app/
    Main.hs         -- executable entry point
  test/
    Spec.hs         -- serialization, crypto, and address tests
```

## Running tests

```bash
cabal test
```

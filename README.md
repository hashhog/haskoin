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
- [x] Script parsing and encoding
- [x] Script classification (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, multisig)
- [x] Script interpreter with all standard opcodes
- [x] P2SH script verification (BIP-16)
- [x] SegWit script verification (P2WPKH, P2WSH)
- [x] Flow control (IF/ELSE/ENDIF), arithmetic, stack ops
- [x] CHECKLOCKTIMEVERIFY (BIP-65), CHECKSEQUENCEVERIFY (BIP-112)
- [x] Consensus parameters (block limits, script limits, weight)
- [x] Difficulty target conversion (compact bits format)
- [x] Block reward schedule with halving
- [x] Merkle root computation
- [x] Network configs (mainnet, testnet3, regtest)
- [x] Genesis blocks for all networks
- [x] Basic block header validation
- [x] Basic transaction validation
- [x] RocksDB storage layer (block headers, UTXOs, tx index)
- [x] Prefix-based key schema with batch writes
- [x] Full block validation with consensus rules
- [x] Transaction validation against UTXO set
- [x] Coinbase detection and BIP-34 height extraction
- [x] Block weight calculation (BIP-141)
- [x] Sigop counting with witness discount
- [x] Witness commitment validation
- [x] Block connection/disconnection for chain state
- [x] Intra-block UTXO spending support
- [x] P2P message serialization (version, inv, getdata, headers, etc.)
- [x] Service flags (NODE_NETWORK, NODE_WITNESS, etc.)
- [x] Protocol version negotiation support
- [x] TCP peer connection with buffered reads
- [x] Version handshake protocol (BIP handshake sequence)
- [x] Feature negotiation (sendheaders BIP-130, sendcmpct BIP-152)
- [x] Async send/receive threads with STM queues
- [x] Peer manager with multi-peer connection handling
- [x] DNS seed discovery with fallback addresses
- [x] Peer scoring and banning (misbehavior threshold, 24h ban)
- [x] Ping/pong monitoring with stale peer disconnection
- [x] Block locator building for getheaders/getblocks
- [x] Addr message handling for peer discovery
- [x] Header chain with cumulative proof-of-work tracking
- [x] Median time past calculation (BIP-113)
- [x] Difficulty adjustment (retarget every 2016 blocks)
- [x] Header validation (PoW, timestamp, difficulty)
- [x] Headers-first sync controller
- [x] Fork point detection and ancestor lookup
- [x] Block download pipeline (IBD)
- [x] Pipelined block downloads (up to 128 in-flight)
- [x] Per-peer download throttling (~16 blocks/peer)
- [x] Adaptive stall detection and re-request
- [x] Batch GetData messages for efficiency
- [x] Block validation and chain connection during IBD
- [ ] ECDSA signing/verification (requires secp256k1)
- [ ] Mempool management

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
      Script.hs     -- script parsing, classification, interpreter
      Consensus.hs  -- network config, validation, header sync
      Storage.hs    -- rocksdb persistence layer
      Network.hs    -- p2p messages, peer connection, peer manager
      Sync.hs       -- block download, IBD pipeline
  app/
    Main.hs         -- executable entry point
  test/
    Spec.hs         -- comprehensive test suite
```

## Running tests

```bash
cabal test
```

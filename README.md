# haskoin

A Bitcoin full node written from scratch in Haskell. Part of the [Hashhog](https://github.com/hashhog/hashhog) project.

## Quick Start

### Docker

```bash
docker-compose up -d
```

This starts haskoin on mainnet with data persisted to a Docker volume. Ports 8333 (P2P) and 8332 (RPC) are exposed.

### Build from Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y librocksdb-dev pkg-config libsecp256k1-dev zlib1g-dev

# Build
cabal update
cabal build all

# Run on testnet4
cabal run haskoin -- -n Testnet4 node

# Run on mainnet with RTS tuning for IBD
cabal run haskoin -- +RTS -N -A64m -H2G -I0 -RTS -n Mainnet node
```

## Features

- Full block and transaction validation with all consensus BIP rules
- Script interpreter supporting P2PKH, P2SH, P2WPKH, P2WSH, and P2TR
- SegWit transaction serialization via cereal
- Headers-first sync with parallel IBD pipeline
- RocksDB storage layer with UTXO cache and LRU eviction
- Memory-mapped I/O for block files
- Transaction mempool with RBF and cluster mempool
- Fee estimation with confirmation tracking
- Block template construction for mining
- HD wallet (BIP-32/39/44/84) with mnemonic generation and restore
- PSBT support (BIP-174/BIP-370: create, decode, combine, finalize, sign)
- Output descriptors (BIP-380-386: parse, checksum, derive addresses, import)
- Miniscript (BIP-379: type system, compilation, satisfaction)
- Block indexes (txindex, BIP-157/158 blockfilterindex, coinstatsindex)
- Hardware-accelerated crypto (SHA-NI/AVX2 auto-detect, batch Schnorr, parallel ECDSA)
- Peer manager with misbehavior scoring, connection eviction, and ban lists
- Stale peer eviction (ping timeout, block stall, chain sync timeout)
- Tor/I2P connectivity (SOCKS5 proxy, Tor hidden services, I2P SAM)
- Regtest mode with generatetoaddress, generateblock, and generate RPCs
- CLI with node, wallet, and utility subcommands

## Configuration

### CLI Flags (Global)

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --datadir DIR` | Data directory | `~/.haskoin` |
| `-n, --network NETWORK` | Network: Mainnet, Testnet, Testnet4, Regtest | `Mainnet` |

### Node Subcommand Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--rpcport ARG` | RPC port | network default |
| `--rpcuser ARG` | RPC username | |
| `--rpcpassword ARG` | RPC password | |
| `--maxpeers ARG` | Maximum peer connections | |
| `--connect ARG` | Peer to connect to | |
| `--prune` | Enable pruning | disabled |
| `--dbcache ARG` | DB cache size in MB | |
| `--listen ARG` | Accept incoming connections | `True` |
| `--port ARG` | P2P listen port | network default |

### Wallet Subcommands

| Command | Description |
|---------|-------------|
| `wallet create` | Create a new wallet |
| `wallet restore` | Restore wallet from mnemonic |
| `wallet balance` | Show wallet balance |
| `wallet address` | Generate a new receive address |
| `wallet send` | Send bitcoin |
| `wallet history` | Show transaction history |
| `wallet dump` | Dump wallet info |

### Utility Subcommands

| Command | Description |
|---------|-------------|
| `util decodetx` | Decode a raw transaction |
| `util decodescript` | Decode a script |
| `util validateaddress` | Validate a Bitcoin address |
| `util hashblock` | Hash a block header |

## RPC API

### Blockchain

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Returns blockchain processing state info |
| `getblockcount` | Returns height of the most-work fully-validated chain |
| `getbestblockhash` | Returns hash of the best (tip) block |
| `getblockhash` | Returns hash of block at given height |
| `getblock` | Returns block data for a given hash |
| `getblockheader` | Returns block header data |
| `getdifficulty` | Returns proof-of-work difficulty |
| `getchaintips` | Returns information about all known tips in the block tree |
| `gettxout` | Returns details about an unspent transaction output |

### Transactions

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Returns raw transaction data |
| `sendrawtransaction` | Submits a raw transaction to the network |
| `decoderawtransaction` | Decodes a hex-encoded raw transaction |
| `createrawtransaction` | Creates an unsigned raw transaction |
| `signrawtransactionwithwallet` | Signs a raw transaction with wallet keys |
| `decodescript` | Decodes a hex-encoded script |
| `testmempoolaccept` | Tests whether a raw transaction would be accepted by the mempool |

### Mempool

| Method | Description |
|--------|-------------|
| `getmempoolinfo` | Returns mempool state details |
| `getrawmempool` | Returns all transaction IDs in the mempool |
| `getmempoolentry` | Returns mempool data for a given transaction |
| `getmempoolancestors` | Returns all in-mempool ancestors for a transaction |

### Network

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Returns P2P networking state info |
| `getpeerinfo` | Returns data about each connected peer |
| `getconnectioncount` | Returns the number of connections |
| `getnettotals` | Returns network traffic statistics |
| `addnode` | Adds or removes a peer |
| `disconnectnode` | Disconnects a peer |

### Mining

| Method | Description |
|--------|-------------|
| `getblocktemplate` | Returns a block template for mining |
| `submitblock` | Submits a new block to the network |
| `getmininginfo` | Returns mining-related information |
| `estimatesmartfee` | Estimates fee rate for confirmation within N blocks |
| `generatetoaddress` | Mines blocks to an address (regtest only) |
| `generateblock` | Mines a block with specific transactions (regtest only) |
| `generate` | Mines blocks (regtest only) |
| `setmocktime` | Sets mock time for testing (regtest only) |

### Wallet

| Method | Description |
|--------|-------------|
| `createwallet` | Creates a new wallet |
| `listwallets` | Lists loaded wallets |
| `getwalletinfo` | Returns wallet state info |
| `getnewaddress` | Generates a new receiving address |
| `getbalance` | Returns wallet balance |
| `listunspent` | Lists unspent outputs |
| `sendtoaddress` | Sends bitcoin to an address |
| `listtransactions` | Lists wallet transactions |
| `walletpassphrase` | Unlocks an encrypted wallet |
| `walletlock` | Locks the wallet |
| `setlabel` | Sets an address label |
| `importdescriptors` | Imports output descriptors into the wallet |
| `listdescriptors` | Lists imported descriptors |

### Descriptors and PSBT

| Method | Description |
|--------|-------------|
| `createpsbt` | Creates a PSBT |
| `decodepsbt` | Decodes a base64 PSBT |
| `combinepsbt` | Combines multiple PSBTs |
| `finalizepsbt` | Finalizes a PSBT |

### Utility

| Method | Description |
|--------|-------------|
| `validateaddress` | Validates a Bitcoin address |
| `verifymessage` | Verifies a signed message |
| `getinfo` | Returns general node info |
| `stop` | Stops the node |
| `help` | Lists available RPC commands |

## Architecture

haskoin uses Haskell's type system to make invalid blockchain states unrepresentable. Core data types (Hash256, TxId, BlockHash, Transaction, Block) are defined with strict binary serialization via the cereal library. Cryptographic operations -- SHA256d, RIPEMD160, HASH160, and secp256k1 ECDSA/Schnorr -- use hardware-accelerated implementations that auto-detect SHA-NI and AVX2 CPU features at startup. Batch Schnorr verification and parallel ECDSA validation are used during IBD for throughput.

The consensus module implements the script interpreter as a pure function, covering all standard script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) with full BIP rule enforcement. Block and transaction validation, header sync, and reorg handling are cleanly separated. The storage layer uses RocksDB for persistent state with a UTXO cache backed by an LRU eviction policy. Block files are memory-mapped for efficient random access during validation and reindexing.

P2P networking is managed through an async peer manager that handles DNS seed discovery, version/verack handshakes, misbehavior scoring, and connection eviction. Stale peer eviction covers ping timeouts, block download stalls, and chain sync timeouts. The sync pipeline implements headers-first IBD with parallel block downloads. Tor and I2P connectivity is supported via SOCKS5 proxies with optional hidden service and SAM session management.

The mempool supports Replace-By-Fee (RBF) and a cluster mempool design for more accurate mining score computation. Fee estimation tracks confirmation times across fee-rate buckets. Block template construction selects transactions by ancestor feerate for optimal miner revenue. The wallet module provides BIP-32/39/44/84 HD key derivation with mnemonic generation, PSBT workflows (BIP-174/370), and output descriptor support (BIP-380-386).

The RPC server exposes a Bitcoin Core-compatible JSON-RPC interface with HTTP Basic Auth. It supports blockchain queries, raw transaction operations, mempool inspection, mining (block templates and regtest generation), wallet operations, and PSBT handling. The CLI provides three subcommands: `node` for running the full node, `wallet` for offline wallet operations, and `util` for transaction/script/address utilities.

## Project Structure

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
    Mempool.hs       -- transaction pool, RBF, cluster mempool
    FeeEstimator.hs  -- fee rate estimation
    BlockTemplate.hs -- block template for mining
    Rpc.hs           -- json-rpc server
    Wallet.hs        -- hd wallet, psbt, output descriptors
    Performance.hs   -- hardware crypto, parallel validation, mmap
    Index.hs         -- txindex, blockfilterindex, coinstatsindex
  bench/
    Bench.hs         -- criterion benchmarks
  app/
    Main.hs          -- CLI entry point
  test/
    Spec.hs          -- test suite
```

## Running Tests

```bash
cabal test --test-show-details=direct
```

## Running Benchmarks

```bash
cabal bench --benchmark-options='-o report.html'
```

## License

MIT

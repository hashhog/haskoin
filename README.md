# haskoin

A Bitcoin full node written from scratch in Haskell. Part of the [Hashhog](https://github.com/hashhog/hashhog) project.

## Status — v1.0.0

**Label: "Pending — genesis rig running; label not assignable from a committed
artifact"** (`receipts/RELEASE-v1.0-SCORECARD.md`). haskoin is the one node the
release scorecard declines to grade: a from-genesis rig is running, but its height
is not recorded in any committed artifact — the only source is an uncommitted live
log. The git tag `v0.1.0-beta1` (`receipts/RELEASE-v1.0-FREEZE.md`) says the same
from the other side: `rc` is reserved for an independent from-genesis
`--assumevalid=0` reproduction of Core's UTXO-set commitment, and `beta` means that
receipt does not exist (`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither
label certifies wallet or fund-custody readiness — see `SECURITY.md`.

**haskoin has not been shown to validate the chain from genesis.** There is no
haskoin row in the reproduction ledger (`receipts/TRUST-ANCHOR.md:140-145`) and
no haskoin replay ledger in `CORE-PARITY-AUDIT/replay-ledgers/`.
`receipts/SYNCS.md:30` records the live mainnet chainstate as having been created
by `--load-snapshot` (base height 956407, 166,119,542 coins, 2026-07-02
recovery), with "from-genesis full script validation **UNKNOWN** — no banked
AV=0/genesis replay found". The node honours assumevalid (`skipScripts`), so
being at Core's tip with a matching best-block hash is not by itself evidence
that it verified the scripts below the assumevalid height. A from-genesis rig is
in flight, but the release scorecard records its height as NOT PROVEN — the only
source is an uncommitted live log, and a download pointer is not a validated
height. A reader of this repository alone should assume haskoin's from-genesis
validation is untested.

**Operator RPC parity: 57 of Bitcoin Core's 85.** From the 103-method R5
operator probe run 2026-09-01
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): haskoin 57 PASS /
28 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core. Failures are largely error-code
mismatches (`decoderawtransaction` on non-hex returns `-1` where Core returns
`-22`; `getmempoolentry` on an absent transaction returns `-1` where Core returns
`-5`). Until `ccfa0f2`, 31 methods were dispatched but absent from
`allRpcCommands`, so `help` never listed them — the RPC surface under-reported
itself.

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
suite (5052 examples, 466 pending) went 34 failing → 0 with no skips and no gaps
carried; one of those was a real bug, mutation-verified — `26f71d7`, so that
`loadtxoutset` answers `-8 "Couldn't open file … for reading."` before any
snapshot parsing, matching Core's `rpc/blockchain.cpp:3411-3416`. The assumeUTXO
snapshot-boot gate was red for haskoin from 2026-08-11; the genesis-body defect
behind it was fixed in `b1d1d43`
(`receipts/boot-smoke-4-red-triaged-2026-08-16.md:76-90`).

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the
[hashhog meta-repo](https://github.com/hashhog/hashhog).

> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, not to this repository.

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
# Also required (not packaged on Debian): libminisketch, built from
# https://github.com/sipa/minisketch, and the rocksdb_compat shim for RocksDB 9.x:
#   bash scripts/build-rocksdb-compat.sh     (see haskoin.cabal extra-libraries)
# Toolchain: haskoin.cabal pins no GHC (base >= 4.14 && < 5); the Dockerfile
# builds with GHC 9.8 (haskell:9.8-slim) and the fleet builds with GHC 9.6.7 /
# cabal-install 3.14.2.0 (cabal-version 3.0).

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

The RPC server exposes a JSON-RPC interface with HTTP Basic Auth, modelled on Bitcoin Core's. It is not yet behaviourally compatible: on the 2026-09-01 operator probe haskoin answers 57 of the 103 probed methods correctly against Core's 85, with 28 failures, largely error-code mismatches. Until `ccfa0f2`, 31 methods were dispatched but missing from `allRpcCommands`, so `help` did not list them. It supports blockchain queries, raw transaction operations, mempool inspection, mining (block templates and regtest generation), wallet operations, and PSBT handling. The CLI provides three subcommands: `node` for running the full node, `wallet` for offline wallet operations, and `util` for transaction/script/address utilities.

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

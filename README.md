# haskoin

A Bitcoin full node written from scratch in Haskell. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Mainnet validation | Validated mainnet from genesis to height 958,794 with assumevalid off and matched Core's `gettxoutsetinfo` `hash_serialized_3` there (`29692050…6e7af0`, 166,180,925 coins). How to reproduce: [docs/status.md](docs/status.md). |
| Consensus | Block, transaction and script validation through Taproot. Runs all of Core's `script_tests.json` and `sighash.json` vectors as test suites. |
| RPC | 135 JSON-RPC methods modelled on Core's, plus optional REST. Known differences in [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, inbound and outbound peers, BIP-324 v2 transport, addrv2, compact blocks, SOCKS5/Tor/I2P outbound. |
| Wallet | Descriptor wallets, multi-wallet, PSBT, BIP-32/39 keys. No custody audit. |
| Known limitations | `getblocktemplate` can order a child before its parent (do not mine with it). No signet. RPC responses carry `"id": null`. See [docs/status.md](docs/status.md#known-limitations). |

Last updated: 2026-10-17.

## Quick start

Needs GHC 9.6 and cabal-install 3.14 ([GHCup](https://www.haskell.org/ghcup/) installs both),
RocksDB 9, libsecp256k1, libzmq 4, and two libraries Debian does not package:
[minisketch](https://github.com/sipa/minisketch) and a small RocksDB shim built by
`scripts/build-rocksdb-compat.sh`. On Debian 13:

```bash
sudo apt-get install -y build-essential autoconf automake libtool pkg-config git curl \
  librocksdb-dev libsecp256k1-dev libzmq5 zlib1g-dev libgmp-dev
git clone --depth 1 https://github.com/sipa/minisketch.git && (cd minisketch && ./autogen.sh && ./configure && make -j"$(nproc)" && sudo make install && sudo ldconfig)
git clone https://github.com/hashhog/haskoin.git && cd haskoin
sudo bash scripts/build-rocksdb-compat.sh
cabal update
cabal build exe:haskoin
cp "$(cabal list-bin haskoin)" ./haskoin && ./haskoin --help | head -3
```

More detail is in [docs/building.md](docs/building.md). Start a regtest node in a throwaway
data directory and make an RPC call:

```bash
export DATADIR=$(mktemp -d)
./haskoin -d "$DATADIR" -n Regtest node --rpcport 18443 --metricsport 0 > "$DATADIR/node.log" 2>&1 &
sleep 10
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

## Running

Global options (`-d`, `-n`) go before the `node` subcommand, node options after it:

```bash
./haskoin -n Mainnet  node
./haskoin -n Testnet4 node --rpcport 48332
./haskoin -n Regtest  node --rpcport 18443
```

`-n Testnet` selects testnet3. The data directory defaults to `~/.haskoin`, and each network
uses a subdirectory of it: `main`, `testnet3`, `testnet4` or `regtest`.

| Network | P2P port | RPC port |
|---|---|---|
| Mainnet | 8333 | 8332 |
| Testnet4 | 48333 | 8332 unless `--rpcport` |
| Testnet (testnet3) | 18333 | 8332 unless `--rpcport` |
| Regtest | 18444 | 8332 unless `--rpcport` |

The RPC port does not follow the network: it is 8332 unless you pass `--rpcport`. RPC listens
on `127.0.0.1` only. A Prometheus metrics endpoint listens on port 9332 unless you pass
`--metricsport 0`. If something else already holds that port (another node, or a Bitcoin Core
exporting metrics there), haskoin keeps running without metrics and logs
`Network.Socket.bind: resource busy (Address already in use)`, so give each node its own
`--metricsport`.

A full mainnet node keeps every block unless you pass `--prune N` (N ≥ 550 MiB): plan for at
least 1 TB of fast disk. The UTXO cache is set by `--dbcache` (default 450 MiB). With
default settings a node following the mainnet tip uses about 8 GB of resident memory and
initial sync can use more; give the machine at least 16 GB. `--noassumevalid` checks every
script from genesis.

Every flag, the config file, the data directory layout and logging are in
[docs/running.md](docs/running.md).

## RPC

haskoin aims to match Bitcoin Core's JSON-RPC interface: same method names, parameters and
result shapes. It accepts HTTP Basic auth with the `.cookie` file written to the network
data directory at startup, or with `--rpcuser`/`--rpcpassword` (default `haskoin`/`haskoin`;
change it if anything else can reach the port):

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
cabal test --test-show-details=direct
```

builds and runs the eight test suites (see [docs/status.md](docs/status.md) for what they cover).

```
app/Main.hs              CLI, startup, sync driver
src/Haskoin/Consensus.hs validation, chain parameters, reorgs, snapshots
src/Haskoin/Script.hs    script interpreter
src/Haskoin/Storage.hs   RocksDB, UTXO cache, block files
src/Haskoin/Network.hs   peers, addrman, P2P messages, BIP-324
src/Haskoin/Mempool.hs   mempool policy, RBF, packages
src/Haskoin/Rpc.hs       JSON-RPC and REST server
src/Haskoin/Wallet.hs    wallet, PSBT, descriptors
test/                    hspec suites and Core's vector runners
```

The full map is in [docs/architecture.md](docs/architecture.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).

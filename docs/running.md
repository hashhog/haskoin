# Running haskoin

## Command shape

```
haskoin [-d DIR] [-n NETWORK] COMMAND [OPTIONS]
```

`-d`/`--datadir` and `-n`/`--network` are global and go before the command. The commands are:

| Command | What it does |
|---|---|
| `node` | Runs the full node. Its options are below. |
| `wallet create\|restore\|balance\|address\|send ADDRESS AMOUNT\|history\|dump` | Placeholders. `wallet create` prints a new BIP-39 mnemonic and saves nothing; the others print a fixed message. Use the RPC wallet (`createwallet`, `getnewaddress`, ...) instead. |
| `util decodetx HEX\|decodescript HEX\|validateaddress ADDR\|hashblock HEX` | Offline decoders, for example `./haskoin -n Regtest util validateaddress bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89`. |

`haskoin --help`, `haskoin node --help` and so on print the same lists.

## Networks and data directory

| `-n` | Subdirectory | P2P port | RPC port |
|---|---|---|---|
| `Mainnet` (default) | `main` | 8333 | 8332 |
| `Testnet4` | `testnet4` | 48333 | 8332 |
| `Testnet` (testnet3) | `testnet3` | 18333 | 8332 |
| `Regtest` | `regtest` | 18444 | 8332 |

Signet is not supported. The data directory (`-d`, default `~/.haskoin`) holds one
subdirectory per network; everything below lives in that subdirectory. The RPC port is 8332
on every network unless you pass `--rpcport`, so give each node its own port if you run
more than one.

What a network directory contains after a start:

| Path | Contents |
|---|---|
| `chainstate/` | RocksDB: block index, block data, undo data, UTXO set, best-block pointer, indexes |
| `blocks/` | Only with `--prune`: block files in Core's `blk*.dat` / `rev*.dat` layout |
| `wallets/` | One directory per wallet created over RPC |
| `.cookie` | RPC cookie (`__cookie__:<hex>`), mode 0600, removed on clean shutdown |
| `haskoin.pid` | PID file (override with `--pid`), removed on clean shutdown |
| `haskoin.conf` | Optional config file, read if present (override with `--conf`) |
| `peers.json`, `anchors.json` | Address manager and block-relay anchors, written on shutdown |
| `mempool.dat`, `fee_estimates.json` | Mempool and fee estimator state, written on shutdown |

## Node options

Every option of `haskoin node`, from `parseNodeOptions` in `app/Main.hs`:

| Option | Default | Meaning |
|---|---|---|
| `--rpcport N` | 8332 | JSON-RPC port. RPC binds to `127.0.0.1` only. |
| `--rpcuser U`, `--rpcpassword P` | `haskoin` / `haskoin` | Basic-auth credentials, accepted in addition to the cookie. |
| `--rpc-tls-cert PATH`, `--rpc-tls-key PATH` | off | Serve RPC over HTTPS. Both or neither. |
| `--rest` | off | Serve Core's read-only REST endpoints (`/rest/...`) on the RPC port. |
| `--port N` | network default | P2P listen port. |
| `--listen BOOL` | `True` | Accept inbound connections. Takes `True` or `False`. |
| `--bind ADDR[:PORT]` | `0.0.0.0` and `[::]` | P2P listen address. Repeatable. |
| `--maxpeers N` | 125 | Maximum peer connections. |
| `--connect HOST:PORT` | none | Connect only to this peer. Repeatable. Turns off DNS seeds and automatic outbound connections. |
| `--nodnsseed` | off | Do not query DNS seeds. |
| `--externalip IP[:PORT]` | none | Public address to advertise. Repeatable or comma-separated. |
| `--discover BOOL` | `True` unless `--externalip` or `--proxy` | Learn the public address from outbound peers. |
| `--proxy HOST:PORT` | off | SOCKS5 proxy for all outbound connections. |
| `--onion HOST:PORT` | off | SOCKS5 proxy for `.onion` peers; makes Tor reachable. |
| `--i2psam HOST:PORT` | off | I2P SAM bridge; makes I2P reachable. |
| `--cjdnsreachable` | off | Treat CJDNS (`fc00::/8`) as reachable. |
| `--asmap FILE` | off | ASMap file for address bucketing (max 8 MiB). |
| `--peerbloomfilters BOOL` | `False` | Advertise `NODE_BLOOM` and serve BIP-37 filters. |
| `--dbcache MiB` | 450 | UTXO cache and RocksDB block cache size. |
| `--par N` | 0 | Script-check threads: 0 = all cores, 1 = serial, N = N threads, negative = leave that many cores free. |
| `--prune N` | 0 | 0 = keep all blocks, 1 = prune only via `pruneblockchain`, ≥ 550 = keep about N MiB of blocks. |
| `--noassumevalid` | off | Verify every script, including those below the built-in assumevalid block (mainnet 938,343). |
| `--txospenderindex` | off | Index spent outpoints to spending transactions (used by `gettxspendingprevout`). |
| `--blockfilterindex` | off | Build the BIP-158 basic filter index. |
| `--coinstatsindex` | off | Keep per-height UTXO statistics so `gettxoutsetinfo` can answer for past blocks. |
| `--reindex-chainstate` | off | Drop the UTXO set and reconnect every stored block from height 1. |
| `--reindex` | off | Currently the same as `--reindex-chainstate`. |
| `--load-snapshot PATH` | none | Load a Core-format UTXO snapshot (`dumptxoutset` output) before networking starts. The base block must be one of the built-in assumeutxo heights. |
| `--metricsport N` | 9332 | Prometheus metrics on `/metrics`. 0 disables it. |
| `--healthport N` | 0 | A `/health` endpoint that answers `ok`. 0 disables it. |
| `--daemon` | off | Detach into the background. |
| `--pid PATH` | `<netdir>/haskoin.pid` | PID file. |
| `--conf PATH` | `<netdir>/haskoin.conf` | Config file. |
| `--logfile PATH` | `<netdir>/debug.log` with `--daemon` | Where the log goes under `--daemon`. Without `--daemon` the file is created but stays empty; redirect stdout instead. |
| `--printtoconsole` | off | Keep logging to stdout under `--daemon`. |
| `--debug CAT` | none | Extra logging for `net`, `mempool`, `validation`, `rpc`, `rocksdb` (or `db`), `zmq`, `prune`, `ibd`, `peers`, `utxo`, `wallet`, or `all` (or `1`). Repeatable. |

Boolean options that take a value (`--listen`, `--peerbloomfilters`, `--discover`) need
`True` or `False` with a capital letter.

## Config file

`haskoin.conf` uses Core's `bitcoin.conf` syntax: `key=value` lines, `#` comments, and
optional `[main]`, `[test]`, `[testnet4]` and `[regtest]` sections whose keys apply only to
that network. Command-line options win over the file.

Keys read from the file: `rpcport`, `rpcuser`, `rpcpassword`, `rpc-tls-cert`, `rpc-tls-key`,
`rest`, `port`, `listen`, `bind`, `maxpeers`, `connect`, `dnsseed`, `externalip`, `discover`,
`asmap`, `peerbloomfilters`, `dbcache`, `par`, `prune`, `assumevalid` (only `0` has an
effect), `txospenderindex`, `blockfilterindex`, `coinstatsindex`, `reindex`,
`reindex-chainstate`, `load-snapshot`, `metricsport`, `healthport`, `daemon`, `pid`,
`logfile`, `printtoconsole`, `debug`. Booleans accept `1`/`0`, `true`/`false`, `yes`/`no`
and `on`/`off`. `connect`, `bind`, `externalip` and `debug` take comma-separated lists.

```ini
# ~/.haskoin/regtest/haskoin.conf
rpcport=18443
metricsport=0
[regtest]
dbcache=100
```

`config.example.toml` in the repository root is not in this format and is not read by the
node.

## Environment variables

| Variable | Effect |
|---|---|
| `HASKOIN_BIP324_V2=0` or `HASKOIN_BIP324_V2_OUTBOUND=0` | Turn off BIP-324 v2 outbound connections and the `NODE_P2P_V2` service bit (on by default). |
| `HASKOIN_GC_TICK_SECS=N` | Interval of the forced major GC (default 60 s, 0 disables). |
| `HASHHOG_BLOCKS_IN_FLIGHT_PER_PEER=N` | Per-peer block download window. Defaults to 128 with a single `--connect` peer. |
| `HASHHOG_UNSAFE_SNAPSHOT_HEIGHT=H` | Testing only: accept a `--load-snapshot`/`loadtxoutset` file whose base is not a built-in assumeutxo block, treating it as height H. The node then trusts that UTXO set without checking it. |

## Resources

A mainnet node that keeps every block needs about 1 TB of disk and growing; with
`--prune 550` the block files stay small but the UTXO set (`chainstate/`) still takes tens of
GB. With default settings a node following the mainnet tip uses about 8 GB of resident
memory, and initial sync can use more. Give it at least 16 GB of RAM.

## Logging and monitoring

The node logs to stdout; redirect it to keep a log. With `--daemon` it detaches, writes its
output to `<netdir>/debug.log` (or `--logfile`), and prints where the log and PID file are.
SIGINT and SIGTERM shut the node down cleanly, as does the `stop` RPC.

With `--metricsport` (on by default at 9332) Prometheus metrics are served at
`http://<host>:<port>/metrics`. When the node is started by systemd with `Type=notify` it
reports readiness through `NOTIFY_SOCKET`.

## Stopping

```bash
curl -s --user "$(cat ~/.haskoin/regtest/.cookie)" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

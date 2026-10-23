# Status: how to check it yourself

Each row of the README status table, and how to reproduce it from this repository. The
regtest examples below were run with Bitcoin Core v31.1; put its `bitcoind` and
`bitcoin-cli` on your `PATH`.

## Test suites

```bash
cabal test --test-show-details=direct
```

builds and runs the eight test suites in `haskoin.cabal`:

| Suite | What it covers |
|---|---|
| `haskoin-test` | The main hspec suite: serialization, crypto, script, consensus, storage, P2P, mempool, RPC, wallet |
| `script-vectors` | Every entry of Core's `script_tests.json` (`resources/`) |
| `sighash-vectors` | Every entry of Core's `sighash.json` (`resources/`) |
| `service-flags` | The service bits the node advertises |
| `parallel-script` | Parallel script checking agrees with serial checking |
| `gate6` | Disk and database errors are not recorded as invalid blocks |
| `reload-rewind-test`, `reconcile-forward-test` | Restart paths: the stored tip and the applied UTXO set stay consistent |

On 2026-10-17 seven suites passed. `script-vectors` ran 1,109 legacy and 65 witness
vectors with no failures, and `sighash-vectors` 500 of 500. `haskoin-test` ran 5,507
examples with 462 pending and 2 failures, both checks that read the source text rather than
run code:

- `W99 ProcessMessage dispatch gates ... G27 BUG: getdata pruning (HAVE_DATA check) absent`
- `W124 — Operator experience ... G22 (PARTIAL): acceptLoop in Network.hs:3749 has NO catch around forever`

Most pending examples name a known gap against Core (for example `CoinGrinder absent`); a
few skip an integration leg whose tool is missing. One, `PUB->SUB round-trip via libzmq
inproc handshake`, marks itself pending when it loses a timing race, so the pending count
can be 462 or 463 (both seen on 2026-10-18). Run one part of the suite with `--match`, as
in [CONTRIBUTING.md](../CONTRIBUTING.md).

Keep `TMPDIR` short when running the suite. The two `sd_notify` examples create a Unix
socket under it, and they fail with `pokeSockAddr: path is too long` if the socket path is
longer than 108 bytes.

## UTXO set against Core, on regtest

Build a chain on Core, let haskoin sync it over P2P, and compare the UTXO-set hashes.
`hash_serialized_3` covers every coin, so one wrong coin, amount or script changes it.

```bash
CORE=$(mktemp -d); NODE=$(mktemp -d)
bitcoind -regtest -datadir="$CORE" -port=18544 -rpcport=18543 -listen=1 -daemon
sleep 3
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 generatetoaddress 200 bcrt1qlfglp2xalgefyyy8hdh3h6wg8ceqn006jdyp89
./haskoin -d "$NODE" -n Regtest node --rpcport 18443 --metricsport 0 --connect 127.0.0.1:18544 > "$NODE/node.log" 2>&1 &
sleep 20
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 gettxoutsetinfo
bitcoin-cli -regtest -rpcport=18443 -rpccookiefile="$NODE/regtest/.cookie" gettxoutsetinfo
bitcoin-cli -regtest -rpcport=18443 -rpccookiefile="$NODE/regtest/.cookie" stop
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 stop
```

Both report `"height": 200`, the same `bestblock`, and `"hash_serialized_3":
"55a904f0ebf65d38b61e674ea2c411e0241cd7d311ad8c5f35c24c9eafbfe44f"`. Block hashes change
from run to run, but this hash does not: the chain holds only coinbase outputs to a fixed
address, and their txids do not depend on the block time.

## UTXO set at a past height

`gettxoutsetinfo` reports the current tip only, as in Core. To read the hash at an earlier
height H, roll the tip back with `invalidateblock` on the block at H+1, read the hash, and
undo it. Core gives the reference value for the same height with `dumptxoutset ...
rollback=H` (its `txoutset_hash`). On regtest, with both nodes from the previous section
still running:

```bash
bitcoin-cli -regtest -datadir="$CORE" -rpcport=18543 -named dumptxoutset path="$CORE/utxo-100.dat" rollback=100
RPC() { curl -s --user "$(cat "$COOKIE")" -d "{\"method\":\"$1\",\"params\":$2}" "$URL"; }
COOKIE=$NODE/regtest/.cookie URL=http://127.0.0.1:18443/
NEXT=$(RPC getblockhash '[101]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
RPC invalidateblock "[\"$NEXT\"]"
RPC gettxoutsetinfo '["hash_serialized_3"]'
RPC reconsiderblock "[\"$NEXT\"]"
```

Core's `txoutset_hash` and haskoin's `hash_serialized_3` are both
`b3f628fb807af7b98dc7f3ba0ec5d54005bd20cdd846236629f952d0905507e1` over 100 coins.

## Mainnet validation to height 958,794

At mainnet height 958,794 (block
`000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`) the UTXO set has
`hash_serialized_3` `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over
166,180,925 coins; Core reports both with `gettxoutsetinfo` at that height, or with
`dumptxoutset` and `rollback=958794`.

### What has been recorded, and what has not

On 2026-09-09 a rig run with `--noassumevalid`, fed by a block server capped at 958,794
so it stopped on the anchor, held a UTXO set at height 958,794 whose `hash_serialized_3`
was `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over 166,180,925
coins, equal to Core's value above. The match was recorded; it is not ratified (no signed
tag rests on it).

What the rig log supports:

- the UTXO set at 958,794 matched Core's;
- the log has five start banners, each with `--noassumevalid`, and shows the node
  validating from height 200,089 onward.

What it does not support, and the README therefore does not claim:

- Heights 0 to 200,089. The log begins with a resume at 200,089 (`Chainstate reconciliation:
  connected-block tip is height 200089`), so that stretch is not in it.
- One binary throughout. The log prints no binary identity. Per the capture record, binary
  `57026489ec71` (sha256
  `57026489ec71d7d5456c9393bc5a2ef07f337d7e7425707985d39cf6cff3a38b`) built the
  chainstate; the hash was taken by `965764b10786` after the rig was killed by the
  out-of-memory killer during the first attempt. Its full sha256 was not recorded and
  the binary was not kept. The last two starts resumed at the anchor itself, so nothing
  below 958,794 was re-validated by the second binary.
- An explanation for the 994 log lines containing `thread killed`. They split into 674
  `P2P reorg (MBlock) error`, 90 `putBlock (side-branch) error`, 221 `Handler error`,
  1 `ERROR validating block 481828`, 4 `ERROR connecting block` (heights 621,958,
  621,960, 712,924 and 924,478), and 4 diagnostic lines `rejected by connectBlock:
  exception: thread killed` at those same four heights.

To check haskoin against it, sync a mainnet node from genesis with every script verified:

```bash
./haskoin -n Mainnet node --noassumevalid
```

Then, once it is past 958,794, use the rollback recipe above with height 958,794 and
`URL=http://127.0.0.1:8332/`, `COOKIE=~/.haskoin/main/.cookie`. `invalidateblock`
disconnects every block above that height and `reconsiderblock` reconnects them, so run it
soon after the node passes the height. A from-genesis sync with `--noassumevalid` takes
days.

## RPC behaviour against Core

Two scripts in `test/` start Core and haskoin side by side on regtest (both on
`127.0.0.1`, no outside peers) and compare RPC results field by field:

```bash
BITCOIND=$(command -v bitcoind) BITCOIN_CLI=$(command -v bitcoin-cli) HASKOIN=./haskoin \
  PARITY_DIR=$(mktemp -d) python3 test/regtest/core_parity.py
python3 test/p2a_followups_core_parity.py --bitcoind "$(command -v bitcoind)" --haskoin ./haskoin
```

The first covers `invalidateblock`/`reconsiderblock`, `submitblock` result strings, and
mempool and `getblocktemplate` ordering for a parent and child. It matches on every chain
check. It reports 6 mismatches, all in `getblocktemplate` (see below), and in some runs a
seventh, `getrawmempool order`: haskoin does not list the parent and child in a fixed
order. On 2026-10-18 that seventh mismatch appeared in 2 of 4 runs. The second covers `decodescript`, descriptors, `decoderawtransaction` and
pay-to-anchor outputs: 133 matched, 11 mismatched, 1 justified (the two chains differ). The
mismatches are listed in [rpc.md](rpc.md).

## Known limitations

- `getblocktemplate` can list a child transaction before its in-mempool parent, and reports
  `sigops` as 0. Do not mine with it.
- `getrawmempool` lists transactions in an order that can change from run to run, so a
  parent can come after its child.
- JSON-RPC responses always have `"id": null`.
- On 2026-10-18 a testnet4 node that had been syncing from public peers for 10 seconds
  printed `Shutdown complete.` after `stop` and then aborted with a RocksDB assertion
  (``Assertion `get_impl_options.column_family' failed``). This was seen once. The
  regtest, testnet3 and mainnet runs in the same session exited cleanly.
- No signet.
- `--reindex` is the same as `--reindex-chainstate`; there is no rebuild of the block index.
- The RPC port defaults to 8332 on every network.
- The wallet has not been audited. Do not use it with real funds.

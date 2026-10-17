# RPC reference

haskoin serves JSON-RPC over HTTP POST on `127.0.0.1:<rpcport>` (default 8332 on every
network). It aims to match Bitcoin Core: same method names, positional and named parameters,
result fields and error codes. Authenticate with HTTP Basic auth, either with the `.cookie`
file in the network data directory or with `--rpcuser`/`--rpcpassword`:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockhash","params":[0]}' http://127.0.0.1:18443/
```

Batches (a JSON array of requests) are accepted. Wallet methods take the wallet from the URL
path (`/wallet/<name>`) when more than one wallet is loaded, as in Core.

With `--rest`, Core's read-only REST endpoints are served on the same port: `/rest/block/`,
`/rest/block/notxdetails/`, `/rest/tx/`, `/rest/headers/`, `/rest/blockhashbyheight/`,
`/rest/chaininfo.json`, `/rest/mempool/info.json`, `/rest/mempool/contents.json`,
`/rest/getutxos/`, `/rest/blockfilter/` and `/rest/blockfilterheaders/`, each with `.json`,
`.hex` or `.bin` as in Core. Without `--rest` they return 404.

## Methods

The 135 methods below are the node's dispatch table in `src/Haskoin/Rpc.hs`
(`handleRpcRequest`); `help` with no argument prints the same list with signatures. The
grouping follows `help`. The second column lists differences from Core that are known from
the code; an empty cell means none are known, not that the method has been checked
field-by-field against Core.

### Blockchain

| Method | Difference from Core |
|---|---|
| `getbestblockhash` |  |
| `getblock` |  |
| `getblockchaininfo` |  |
| `getblockcount` |  |
| `getblockfrompeer` |  |
| `getsyncstate` | haskoin only: header/block download state. |
| `getdeploymentinfo` |  |
| `getblockhash` |  |
| `getblockheader` |  |
| `getchaintips` |  |
| `getchainstates` | Each chainstate also reports `script_checks`, the number of input scripts actually verified. |
| `getchaintxstats` |  |
| `getdifficulty` |  |
| `gettxout` |  |
| `invalidateblock` |  |
| `preciousblock` |  |
| `pruneblockchain` |  |
| `reconsiderblock` |  |
| `gettxoutsetinfo` |  |
| `gettxoutproof` |  |
| `getblockstats` |  |
| `scanblocks` |  |
| `verifychain` |  |
| `waitforblock` |  |
| `waitforblockheight` |  |
| `waitfornewblock` |  |

### Index

| Method | Difference from Core |
|---|---|
| `getblockfilter` |  |
| `getindexinfo` |  |

### Mempool

| Method | Difference from Core |
|---|---|
| `getmempoolancestors` |  |
| `getmempooldescendants` |  |
| `getmempoolentry` |  |
| `getmempoolinfo` |  |
| `getorphantxs` |  |
| `getrawmempool` |  |
| `testmempoolaccept` |  |
| `submitpackage` |  |

### Mining

| Method | Difference from Core |
|---|---|
| `getblocktemplate` | Can order a child before its in-mempool parent, and reports `sigops` 0. See [status.md](status.md#known-limitations). |
| `getmininginfo` |  |
| `getprioritisedtransactions` |  |
| `prioritisetransaction` |  |
| `submitblock` |  |
| `submitheader` |  |

### Network

| Method | Difference from Core |
|---|---|
| `addnode` |  |
| `addpeeraddress` |  |
| `disconnectnode` |  |
| `getaddednodeinfo` |  |
| `getaddrmaninfo` |  |
| `getconnectioncount` |  |
| `getnetworkinfo` |  |
| `getnodeaddresses` |  |
| `getpeerinfo` |  |
| `listbanned` |  |
| `ping` |  |
| `setban` |  |
| `setnetworkactive` |  |

### Rawtransactions

| Method | Difference from Core |
|---|---|
| `createrawtransaction` |  |
| `decoderawtransaction` |  |
| `decodescript` | Returns a `segwit` object for scripts containing invalid or disabled opcodes, where Core returns none. |
| `getrawtransaction` |  |
| `sendrawtransaction` |  |
| `signrawtransactionwithkey` |  |
| `signrawtransactionwithwallet` |  |

### Wallet

| Method | Difference from Core |
|---|---|
| `backupwallet` |  |
| `createwallet` |  |
| `encryptwallet` |  |
| `getaddressinfo` |  |
| `getbalance` |  |
| `getbalances` |  |
| `getnewaddress` |  |
| `getwalletinfo` |  |
| `importdescriptors` |  |
| `listdescriptors` |  |
| `listtransactions` |  |
| `listunspent` |  |
| `listwallets` |  |
| `loadwallet` |  |
| `send` |  |
| `sendtoaddress` |  |
| `unloadwallet` |  |

### PSBT

| Method | Difference from Core |
|---|---|
| `analyzepsbt` |  |
| `combinepsbt` |  |
| `converttopsbt` |  |
| `createpsbt` |  |
| `decodepsbt` |  |
| `descriptorprocesspsbt` |  |
| `finalizepsbt` |  |
| `utxoupdatepsbt` |  |

### Control

| Method | Difference from Core |
|---|---|
| `getmemoryinfo` |  |
| `getrpcinfo` |  |
| `help` | `help <method>` has text for only some methods; for the others it answers `Unknown command`. |
| `logging` |  |
| `stop` |  |

### Utility

| Method | Difference from Core |
|---|---|
| `estimaterawfee` |  |
| `estimatesmartfee` |  |
| `getnettotals` |  |
| `setlabel` |  |
| `signmessage` | Also accepts a WIF private key in place of an address. |
| `signmessagewithprivkey` |  |
| `uptime` |  |
| `validateaddress` |  |
| `verifymessage` |  |
| `walletlock` |  |
| `walletpassphrase` |  |

### Other

| Method | Difference from Core |
|---|---|
| `bumpfee` |  |
| `clearbanned` |  |
| `combinerawtransaction` |  |
| `createmultisig` |  |
| `deriveaddresses` | Answers for `pk()` and `multi()` descriptors, where Core fails with -5 (no address). |
| `dumpprivkey` | Not in Core v30+ (legacy wallets were removed). |
| `dumptxoutset` |  |
| `fundrawtransaction` |  |
| `generate` | Mines blocks to a random address (regtest). Core only returns an error for this name. |
| `generateblock` |  |
| `generatetoaddress` |  |
| `getdescriptorinfo` | Rewrites an uncompressed key in `pk()` to its compressed form; Core keeps it. |
| `getinfo` | Not in Core (removed in v0.16). Returns a summary object. |
| `getnetworkhashps` |  |
| `getpayjoinrequest` | haskoin only: BIP-78 payjoin receiver. |
| `gettransaction` |  |
| `gettxspendingprevout` |  |
| `importmempool` |  |
| `importprivkey` | Not in Core v30+ (legacy wallets were removed). |
| `joinpsbts` |  |
| `loadmempool` | haskoin only: an alias of `importmempool`. |
| `loadtxoutset` |  |
| `psbtbumpfee` |  |
| `rescanblockchain` |  |
| `restorewallet` | Loads a `backupwallet` file, as Core does. |
| `savemempool` |  |
| `scantxoutset` |  |
| `sendpayjoinrequest` | haskoin only: BIP-78 payjoin sender. |
| `setmocktime` |  |
| `verifytxoutproof` |  |
| `walletcreatefundedpsbt` |  |
| `walletprocesspsbt` |  |


## Core methods haskoin does not implement

Compared with the RPC tables in Bitcoin Core's source, these are missing and answer
`-32601 Method not found`: `abandontransaction`, `abortrescan`, `createwalletdescriptor`,
`enumeratesigners`, `getaddressesbylabel`, `getdescriptoractivity`, `gethdkeys`,
`getmempoolcluster`, `getrawchangeaddress`, `getreceivedbyaddress`, `getreceivedbylabel`,
`getzmqnotifications`, `importprunedfunds`, `keypoolrefill`, `listaddressgroupings`,
`listlabels`, `listlockunspent`, `listreceivedbyaddress`, `listreceivedbylabel`,
`listsinceblock`, `listwalletdir`, `lockunspent`, `migratewallet`, `removeprunedfunds`,
`sendall`, `sendmany`, `setwalletflag`, `simulaterawtransaction`, `walletdisplayaddress`,
`walletpassphrasechange`.

## Other differences

- Responses always carry `"id": null`, whatever `id` the request sent. Core's `bitcoin-cli`
  does not check it and works:
  `bitcoin-cli -regtest -rpcport=18443 -rpccookiefile="$DATADIR/regtest/.cookie" getblockcount`.
- The default RPC port is 8332 on every network, not Core's per-network port.
- Signet is not supported, so no RPC reports `"chain": "signet"`.

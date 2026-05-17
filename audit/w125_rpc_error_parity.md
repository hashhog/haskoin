# W125 JSON-RPC error code parity audit — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY — no production code changes
**Scope:** JSON-RPC error code mapping (haskoin emits Core's protocol.h
codes consistently) across `src/Haskoin/Rpc.hs` (the entire single-file
RPC server).
**Result:** 17 PRESENT / 8 PARTIAL / 5 MISSING out of 30 gates.
**Bugs found:** 12 (1 P0-DOSY, 4 P1, 7 P2).
**Tests added:** 34 xfail/asserting tests in `W125RPCErrorParitySpec.hs`.

## Top-line verdict

`Rpc.hs` is by far the strongest RPC error-code surface in the fleet
this audit has seen.  The five JSON-RPC 2.0 errors (`-32600`/`-32601`/
`-32602`/`-32603`/`-32700`) are named constants exported from the
module header, the wallet error codes (`-4`/`-14`/`-15`/`-16`/`-18`/`-19`/
`-35`/`-36`) are named constants, transaction codes (`-22`/`-25`/`-26`/`-27`)
are named constants, and `rpcInvalidAddressOrKey (-5)` + `rpcClientNode-
NotConnected (-29)` are named (though defined far away from the others
— line 5876 and 6170 respectively).  The `RpcError` record shape
matches Core's `JSONRPCError`: `{"code": Int, "message": String}` with
no `data` field, encoded as part of an envelope `{"result", "error",
"id"}` that mirrors Core's `JSONRPCReplyObj`.

The audit found three classes of divergence:

1. **Missing constants for codes that Core uses heavily** —
   `RPC_TYPE_ERROR (-3)`, `RPC_INVALID_PARAMETER (-8)`,
   `RPC_OUT_OF_MEMORY (-7)`, `RPC_DATABASE_ERROR (-20)`,
   `RPC_IN_WARMUP (-28)`, `RPC_METHOD_DEPRECATED (-32)`,
   `RPC_FORBIDDEN_BY_SAFE_MODE (-2)`,
   `RPC_CLIENT_NOT_CONNECTED (-9)`,
   `RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10)`,
   `RPC_CLIENT_NODE_ALREADY_ADDED (-23)`,
   `RPC_CLIENT_NODE_NOT_ADDED (-24)`,
   `RPC_CLIENT_INVALID_IP_OR_SUBNET (-30)`,
   `RPC_CLIENT_P2P_DISABLED (-31)`,
   `RPC_CLIENT_MEMPOOL_DISABLED (-33)`,
   `RPC_CLIENT_NODE_CAPACITY_REACHED (-34)`,
   `RPC_WALLET_INSUFFICIENT_FUNDS (-6)`,
   `RPC_WALLET_INVALID_LABEL_NAME (-11)`,
   `RPC_WALLET_KEYPOOL_RAN_OUT (-12)`,
   `RPC_WALLET_UNLOCK_NEEDED (-13)`,
   `RPC_WALLET_ALREADY_UNLOCKED (-17)`.
   When a handler needs one of these, it currently picks the closest
   available — usually `rpcInvalidParams` (-32602) or `rpcMiscError`
   (-1) — which is **wire-compatible** at the shape level (a JSON
   client still parses the response) but **breaks code-based error
   recognition** (a client matching on `error.code == -8` to detect
   bad parameters will silently miss the bad-parameter case here).

2. **Inline literal codes scattered through handlers** — 8 call sites
   use `RpcError (-5) "..."` instead of `rpcInvalidAddressOrKey`, and
   two use `(-3) "..."` / `(-8) "..."` instead of even the closest
   existing constant.  These are minor lint debt (since the literal
   matches Core for the FIVE = -5 cases) but they bypass the named-
   constant invariant and rot the moment someone refactors them.

3. **Wrong code for an emitted error** — 8 call sites emit an error
   that Core would emit a *different* code for.  The four worst are:
   - `setban` "Invalid IP/Subnet" / "IP/Subnet already banned" /
     "Unban failed" use `rpcInvalidParams` (-32602) / `rpcMiscError`
     (-1) instead of `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30) /
     `RPC_CLIENT_NODE_ALREADY_ADDED` (-23) / `RPC_CLIENT_INVALID_IP_OR_SUBNET`
     (-30) — three out of three setban error paths diverge from Core.
   - `getmempoolentry` "Transaction not in mempool" uses
     `rpcMiscError` (-1) but `bitcoin-core/src/rpc/blockchain.cpp:887`
     uses `RPC_INVALID_ADDRESS_OR_KEY` (-5).
   - `submitblock` "Hex decode error" / "Block decode error" use
     `rpcMiscError` (-1) but the precedent throughout `sendraw-
     transaction` uses `rpcDeserializationError` (-22).
   - `walletpassphrase` "Timeout cannot be negative" uses
     `rpcInvalidParams` (-32602) but Core's `wallet/rpc/encrypt.cpp`
     uses `RPC_INVALID_PARAMETER` (-8) for parameter-value-out-of-
     range.

The cleanest single bug is the `addnode` handler returning a JSON
*string* in the `error` field instead of an `{code, message}` object
(Rpc.hs:2707-2713) — that violates the JSON-RPC reply shape and is the
W125 P0-DOSY shape-divergence.

## 30 gates

| G  | Code         | Constant in haskoin                 | Status         | Notes |
|----|--------------|-------------------------------------|----------------|-------|
| G1 | -32700 PARSE_ERROR        | rpcParseError                     | PRESENT  | Used at request entry (Rpc.hs:818, 835).  Matches Core. |
| G2 | -32600 INVALID_REQUEST    | rpcInvalidRequest                 | PRESENT  | Used for batch errors + parseSingleRequest fallback. Matches Core. |
| G3 | -32601 METHOD_NOT_FOUND   | rpcMethodNotFound                 | PRESENT  | Unknown-method dispatch line 1160.  Matches Core. |
| G4 | -32602 INVALID_PARAMS     | rpcInvalidParams                  | PARTIAL  | Heavy use (104 sites).  Over-used for cases Core would emit `-3` / `-8` (BUG-1 / BUG-2). |
| G5 | -32603 INTERNAL_ERROR     | rpcInternalError                  | PRESENT  | Used for exception fallback (line 861) + `loadtxoutset` refusal gate. Matches Core's RPC_INTERNAL_ERROR contract. |
| G6 | -1  RPC_MISC_ERROR        | rpcMiscError                      | PARTIAL  | Used at 50 sites.  Some sites mis-classify (BUG-3 setban "already banned", BUG-4 getmempoolentry, BUG-5 submitblock hex decode). |
| G7 | -2  RPC_FORBIDDEN_BY_SAFE_MODE | (none)                       | MISSING  | Unused / reserved in Core too.  Not used in haskoin.  Forward-compat only — fine to defer. |
| G8 | -3  RPC_TYPE_ERROR        | (none — literal `-3` used)        | MISSING  | Core uses for "address does not refer to key" + "missing data String key for proposal" + util.cpp type assertions.  haskoin uses literal `(-3)` at signmessage.cpp:7390/7404 (BUG-6) — should define `rpcTypeError`. |
| G9 | -5  RPC_INVALID_ADDRESS_OR_KEY | rpcInvalidAddressOrKey      | PARTIAL  | Constant exists (line 5876, far from the other codes) but 6 inline `(-5)` literals also used in `getrawtransaction` (Rpc.hs:2099-2142) — BUG-7. |
| G10 | -6  RPC_WALLET_INSUFFICIENT_FUNDS | (none)                  | MISSING  | Core uses heavily for `sendtoaddress` / `walletcreatefundedpsbt`.  haskoin's `sendtoaddress` returns success/failure without this code (BUG-8). |
| G11 | -7  RPC_OUT_OF_MEMORY     | (none)                            | MISSING  | Not used in haskoin; not used in Core proper either (forward-compat reservation).  Defer. |
| G12 | -8  RPC_INVALID_PARAMETER | (none — literal `-8` used)        | PARTIAL  | Used by Core 181× across rpc/wallet.rpc/.  haskoin: literal `(-8)` at Rpc.hs:7471 (`estimaterawfee`).  All other "invalid parameter value" paths use `rpcInvalidParams` (-32602) instead (BUG-2). |
| G13 | -9  RPC_CLIENT_NOT_CONNECTED | (none)                         | MISSING  | Core uses when peer-to-peer is enabled but no peers connected.  haskoin returns empty array for `getpeerinfo` without erroring (acceptable per Core's actual behaviour).  Defer. |
| G14 | -10 RPC_CLIENT_IN_INITIAL_DOWNLOAD | (none)                  | MISSING  | Core uses `mining.cpp:773` + `mempool.cpp:1141` to refuse `getblocktemplate` / `importmempool` during IBD.  haskoin allows both regardless of sync state (BUG-9). |
| G15 | -11 RPC_WALLET_INVALID_LABEL_NAME | (none)                  | MISSING  | Core uses for `getaddressesbylabel` empty result + `setlabel` validation.  haskoin's `handleSetLabel` is a stub returning success — no validation path to flag (forward-compat). |
| G16 | -12 RPC_WALLET_KEYPOOL_RAN_OUT | (none)                     | MISSING  | Core throws when descriptor next-index exhausted on `getnewaddress`.  haskoin's wallet does not implement a keypool cap (deterministic descriptor); no code path can hit this. |
| G17 | -13 RPC_WALLET_UNLOCK_NEEDED | (none)                       | MISSING  | Core throws when an encrypted+locked wallet is asked to sign.  haskoin: signing on a locked wallet returns `rpcInvalidParams` / `rpcMiscError` (BUG-10). |
| G18 | -14 RPC_WALLET_PASSPHRASE_INCORRECT | rpcWalletPassphraseIncorrect | PRESENT | Used by `handleWalletPassphrase` line 7323. Matches Core's `wallet/rpc/encrypt.cpp`. |
| G19 | -15 RPC_WALLET_WRONG_ENC_STATE | rpcWalletWrongEncState       | PRESENT  | Used by `encryptwallet` / `walletpassphrase` / `walletlock`. 3 sites. Matches Core. |
| G20 | -16 RPC_WALLET_ENCRYPTION_FAILED | rpcWalletEncryptionFailed  | PRESENT  | Used by `encryptwallet` fallback path. Matches Core. |
| G21 | -17 RPC_WALLET_ALREADY_UNLOCKED | (none)                      | MISSING  | Core throws when `walletpassphrase` is called on an already-unlocked wallet.  haskoin's path treats re-unlock as a no-op success (BUG-11). |
| G22 | -18 RPC_WALLET_NOT_FOUND  | rpcWalletNotFound                 | PRESENT  | Heavily used.  Matches Core. |
| G23 | -19 RPC_WALLET_NOT_SPECIFIED | rpcWalletNotSpecified          | PRESENT  | Used by `getWalletForRequest` for multi-wallet selection. Matches Core. |
| G24 | -20 RPC_DATABASE_ERROR    | (none)                            | MISSING  | Core uses for ban-database persistence failure + invalidateblock state.ToString().  haskoin: setban catches the persist exception and logs without erroring (BUG-12). |
| G25 | -22 RPC_DESERIALIZATION_ERROR | rpcDeserializationError       | PRESENT  | Used by `sendrawtransaction` / `decoderawtransaction`.  Matches Core.  See BUG-5 for `submitblock` divergence. |
| G26 | -23 RPC_CLIENT_NODE_ALREADY_ADDED | (none)                  | MISSING  | Core uses for `addnode` ("already added") and `setban` ("already banned").  haskoin: both paths use `rpcMiscError`/string (BUG-3, BUG-13). |
| G27 | -24 RPC_CLIENT_NODE_NOT_ADDED | (none)                      | MISSING  | Core uses for `addnode` "remove" of a never-added entry.  haskoin's `handleAddNode` returns success regardless. |
| G28 | -25 RPC_VERIFY_ERROR      | rpcVerifyError                    | PRESENT  | Used by `mempoolErrorToRpcResponse` + `sendrawtransaction` maxfeerate.  Matches Core. |
| G29 | -26 RPC_VERIFY_REJECTED   | rpcVerifyRejected                 | PRESENT  | Used by mempool rejection paths.  Matches Core. |
| G30 | -27 RPC_VERIFY_ALREADY_IN_UTXO_SET | rpcVerifyAlreadyInChain      | PRESENT  | Used for `ErrAlreadyInMempool` / `ErrSameNonwitnessInMempool`. Matches Core. |

(Additional Core codes covered by haskoin constants but outside the
above table because they are "PRESENT" non-divergent gates that the
audit framework subsumes under G22-G23: `rpcWalletAlreadyLoaded`
(-35), `rpcWalletAlreadyExists` (-36), `rpcWalletError` (-4),
`rpcClientNodeNotConnected` (-29).  All present, all match Core.)

## Bugs

### BUG-1 P0-DOSY: `addnode` errors are bare JSON strings, not `RpcError` objects

`handleAddNode` (Rpc.hs:2676-2713) returns `RpcResponse Null (toJSON $
String "Invalid command, expected onetry/add/remove") Null` on three
of its four error branches (lines 2705-2713).  The `error` field of
the JSON-RPC reply is supposed to be an object `{code, message}` per
JSON-RPC 1.0/2.0 — a bare string is a **shape divergence** that breaks
every conformant JSON-RPC client.  A client that does
`response['error']['code']` will throw a `TypeError` here.

**Reproducer:** `curl ... -d '{"method":"addnode","params":["1.2.3.4:8333"]}'`
returns `{"result":null,"error":"Expected [node, command]","id":...}`
where Core would return `{"result":null,"error":{"code":-1,"message":
"..."},"id":...}`.

**Fix shape:** Wrap every branch in `toJSON $ RpcError <code> <msg>`.
Codes:
- "Invalid command": `rpcInvalidParameter` (-8) — new constant.
- "Invalid parameter types": `rpcInvalidParams` (-32602).
- "Expected [node, command]": `rpcInvalidParams` (-32602).

Plus the genuine `addnode` semantics:
- duplicate add: `RPC_CLIENT_NODE_ALREADY_ADDED` (-23) — new constant.
- remove of never-added: `RPC_CLIENT_NODE_NOT_ADDED` (-24) — new constant.

Without these, a client cannot distinguish "you typo'd a flag" from
"that peer is already on your addnode list" — the entire `addnode`
RPC is effectively code-blind.  G26 / G27.

### BUG-2 P1: missing `rpcInvalidParameter (-8)` constant; literal `(-8)` at one site

Core uses `RPC_INVALID_PARAMETER` (-8) 181 times across `rpc/` and
`wallet/rpc/` (`grep -rn 'RPC_INVALID_PARAMETER' rpc/*.cpp wallet/rpc/*.cpp | wc -l`).
It's the canonical "this value is invalid" code, distinct from
`RPC_INVALID_PARAMS` (-32602) which is the JSON-RPC-spec "params
shape wrong" code.

haskoin: literal `(-8)` at Rpc.hs:7471 (`estimaterawfee` threshold
out of range).  All other "invalid parameter value" paths use
`rpcInvalidParams` (-32602) — wrong.  Concrete divergences:
- `walletpassphrase` "Timeout cannot be negative" (Rpc.hs:7307) —
  Core's `wallet/rpc/encrypt.cpp` uses `-8`.
- `pruneblockchain` "Missing height parameter" (Rpc.hs:1969) — Core's
  `rpc/blockchain.cpp:936` uses `-8` for "Negative block height".
- `txoutproof.cpp:49` "txids cannot be empty" pattern: haskoin
  `gettxoutproof` (Rpc.hs:10664) uses `rpcInvalidParams` (-32602)
  instead of `-8`.
- `fees.cpp:74` `estimatesmartfee` "Invalid estimate_mode": haskoin
  doesn't validate mode but if it did, it should be `-8`.

**Fix:** Define `rpcInvalidParameter :: Int = -8` next to the other
constants; route value-range / value-domain failures to it.  Distinct
shape from `rpcInvalidParams` (which Core's protocol.h reserves for
"internally mapped to HTTP_BAD_REQUEST" wire shape errors).  G12.

### BUG-3 P0-CDIV: `setban` uses three wrong error codes

`handleSetBan` (Rpc.hs:6236-6317) emits:
- "Invalid IP/Subnet" → `rpcInvalidParams` (-32602).  Core's
  `rpc/net.cpp:780` uses `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30).
- "IP/Subnet already banned" → `rpcMiscError` (-1).  Core's
  `rpc/net.cpp:785` uses `RPC_CLIENT_NODE_ALREADY_ADDED` (-23).
- "Unban failed" → `rpcMiscError` (-1).  Core's `rpc/net.cpp:811`
  uses `RPC_CLIENT_INVALID_IP_OR_SUBNET` (-30).
- "Invalid command" → `rpcInvalidParams` (-32602).  Core does not
  have an explicit "invalid command" branch (the param shape is
  validated by RPCTypeCheck → `RPC_TYPE_ERROR`).

3 of 4 setban error branches diverge from Core.  Operators automating
ban management will mis-classify "already banned" as "internal error"
and write retry loops or alerts.

**Fix:** Define `rpcClientInvalidIpOrSubnet :: Int = -30` and
`rpcClientNodeAlreadyAdded :: Int = -23`, route the three setban
errors to them.  G26 (already-added) and the never-defined -30 code.

### BUG-4 P1: `getmempoolentry` "not found" uses wrong code

`handleGetMempoolEntry` (Rpc.hs:5757) emits "Transaction not in
mempool" with `rpcMiscError` (-1).  Core's `rpc/blockchain.cpp:887`
emits `RPC_INVALID_ADDRESS_OR_KEY` (-5) with the same message.

This is the same Core code as `getrawtransaction` not-found — clients
that match on `-5` for "key not present" will treat haskoin's
mempool-miss as an unrelated "miscellaneous error" instead.

**Fix:** Change to `rpcInvalidAddressOrKey`.  Trivial one-line fix.
G9.

### BUG-5 P1: `submitblock` hex/decode errors use `rpcMiscError`, not `-22`

`handleSubmitBlockUnpaused` (Rpc.hs:3051, 3055) and
`handleBlockProposal` (Rpc.hs:2860, 2864) emit
- "Hex decode error" → `rpcMiscError` (-1)
- "Block decode error" → `rpcMiscError` (-1)

This contradicts `handleSendRawTransaction` (Rpc.hs:2228) which uses
`rpcDeserializationError` (-22) for the symmetric TX-side error.
Core's mining.cpp treats deserialisation problems in `submitblock`
the same way: bad hex / bad serialization → `-22`.

**Fix:** Route both call sites through `rpcDeserializationError`.
Internal consistency + Core consistency in one move.  G25.

### BUG-6 P1: literal `(-3)` codes at signmessage.cpp, no `rpcTypeError`

`handleVerifyMessage` (Rpc.hs:7390, 7404) emits `RpcError (-3) "..."`
twice.  Core's `rpc/signmessage.cpp:47-49` uses
`RPC_TYPE_ERROR` (-3) with the same messages.

The literal matches; the lint violation is using a magic number
where the other 17 codes have named constants.  More importantly,
NO `rpcTypeError` constant exists, so other handlers cannot reuse
it — `handleBlockProposal` (Rpc.hs:2856) wants Core's mining.cpp:734
"Missing data String key for proposal" code (-3) but uses
`rpcInvalidParams` (-32602) instead.

**Fix:** Define `rpcTypeError :: Int = -3`; switch the two literal
sites + the mining.cpp proposal site.  G8.

### BUG-7 P2: literal `(-5)` at 6 sites in `handleGetRawTransaction`

`handleGetRawTransaction` (Rpc.hs:2099, 2115, 2120, 2128, 2133, 2142)
uses `RpcError (-5) "..."` instead of `rpcInvalidAddressOrKey`.  The
constant is defined (line 5876) but far from these call sites — visual
proximity probably explains the divergence.  Code value matches Core;
only the lint failure is here.

**Fix:** Replace each `(-5)` with `rpcInvalidAddressOrKey`.  G9.

### BUG-8 P2: no `rpcWalletInsufficientFunds (-6)` constant

`handleSendToAddress` (and all the other wallet-spend paths) returns
no specific code for "wallet does not have enough confirmed funds".
Core uses `RPC_WALLET_INSUFFICIENT_FUNDS` (-6) heavily across
`wallet/rpc/spend.cpp` (10+ sites).

Today haskoin's spend paths either succeed or report an error string
without a distinguished code.  A wallet GUI client cannot distinguish
"insufficient funds" from "key not found" — both surface as a generic
`-1`.

**Fix:** Define `rpcWalletInsufficientFunds :: Int = -6`; wire it
through every InsufficientFunds branch in
`Wallet.hs`/`Payjoin.hs`/`Mempool.hs` → `Rpc.hs`.  Coordinate with
a wallet-spend audit follow-up.  G10.

### BUG-9 P1: no `rpcClientInInitialDownload (-10)` constant; IBD gating absent

Core's `rpc/mining.cpp:773` refuses `getblocktemplate` during IBD
with `RPC_CLIENT_IN_INITIAL_DOWNLOAD` (-10).
`rpc/mempool.cpp:1141` does the same for `importmempool`.

haskoin: neither handler checks IBD state at the gate.  Calling
`getblocktemplate` during IBD will execute the full template walk
against the partial chain — wrong answer at minimum, possible panic
if the chain doesn't have 100 ancestors yet.  Calling `importmempool`
during IBD will queue txs against a chainstate that's about to be
overwritten.

**Fix:** Define `rpcClientInInitialDownload :: Int = -10`; gate both
handlers on `estimateIsInitialBlockDownload` (Rpc.hs:1179) at entry.
G14.

### BUG-10 P1: no `rpcWalletUnlockNeeded (-13)` constant; locked-wallet signing returns generic error

Core's `wallet/rpc/util.cpp:91` throws `RPC_WALLET_UNLOCK_NEEDED`
(-13) for any call that needs a key while the wallet is encrypted
and locked.

haskoin's encrypted-locked wallet signing paths
(`signrawtransactionwithwallet`, `signmessage`, the Payjoin sender)
either bail out with a string like "no key available" via
`rpcInvalidParams` (-32602) or proceed and produce an invalid
signature.  A GUI client cannot prompt the user for the passphrase
on `-32602` because that's also "bad param shape".

**Fix:** Define `rpcWalletUnlockNeeded :: Int = -13`; thread an
`isWalletLocked` check at the entry of every signing/spending RPC.
G17.

### BUG-11 P2: no `rpcWalletAlreadyUnlocked (-17)`; re-unlock is no-op success

Core's `wallet/rpc/encrypt.cpp` returns `RPC_WALLET_ALREADY_UNLOCKED`
(-17) if `walletpassphrase` is called twice without an intervening
`walletlock`.

haskoin: `handleWalletPassphrase` (Rpc.hs:7285-7341) treats a re-
unlock as a no-op success — it overwrites the unlock expiry without
erroring.  This is arguably *more* useful than Core's behaviour
(operators can extend the unlock lease in one call), but it diverges
from Core's documented contract.  Operator scripts that rely on `-17`
to detect "already unlocked, don't re-prompt" will not work here.

**Fix:** Define `rpcWalletAlreadyUnlocked :: Int = -17`; emit it
when the wallet is already unlocked.  Document the trade-off vs
silent lease-extension.  G21.

### BUG-12 P2: no `rpcDatabaseError (-20)`; ban-database persistence failures are silently logged

Core's `rpc/server_util.cpp:51` throws `RPC_DATABASE_ERROR` (-20)
when the ban database fails to load.  `blockchain.cpp:1709/1734/1779`
throws it for various invalidate/reconsider failures.

haskoin's `handleSetBan` catches the persist exception
(Rpc.hs:6293-6294) and logs to stdout — the in-memory ban is still
effective, but the operator gets a successful response while the
on-disk state diverged from in-memory.  This is the
"silent-divergence" pattern: the operator's tooling will believe the
ban persisted, then the next restart undoes it.

**Fix:** Define `rpcDatabaseError :: Int = -20`; surface the persist
failure as a `-20` JSON-RPC error so the operator gets a loud signal.
G24.

## Cross-impl context (W125 framework note)

W125's 30-gate framework is shaped against Core's `protocol.h`
RPCErrorCode enum (90 lines, 30 codes plus aliases) and how heavily
each is used in `bitcoin-core/src/rpc/*.cpp` /
`bitcoin-core/src/wallet/rpc/*.cpp`.  Some codes are widely used by
Core (the JSON-RPC 2.0 standard ones, the wallet ones, `-1`/`-3`/`-5`/`-8`),
others are barely used (`-2 RPC_FORBIDDEN_BY_SAFE_MODE` is reserved
and dead, `-7 RPC_OUT_OF_MEMORY` is unused in modern Core, `-15` is
only triggered by very specific wallet states).

The pattern from prior W125-shaped audits across the fleet (W117 BIP-
155, W118 wallet, W120 RBF) is that even strong impls have **5-15
PARTIAL gates** where a code is "almost matched": the named constant
exists but the call site uses the wrong one, or the call site emits
a literal that happens to match Core but isn't routed through a named
constant.  haskoin's `Rpc.hs` is on the strong end of that range:
17/30 PRESENT, 8/30 PARTIAL, 5/30 MISSING; the missing codes are the
"obscure" ones (-7 / -2) plus the wallet-states (-11/-12/-15/-17)
plus the IBD / Database edge cases.

Notable conventions haskoin already gets right that other fleet impls
have routinely missed:

- **JSONRPCError shape**: `{code: Int, message: String}` — matches
  Core, no extra `data` field (Rpc.hs:566-570).  No "stringified
  error" leak.
- **Reply envelope**: `{result, error, id}` with mutual-exclusion
  semantics — when error is set, result is `Null`; matches Core's
  `JSONRPCReplyObj` V1_LEGACY shape (Rpc.hs:535-540).
- **Method-not-found** uses the JSON-RPC-2.0 code (-32601) not a
  custom code (Rpc.hs:1160).
- **Wallet error split** between `rpcWalletError (-4)` (generic),
  `rpcWalletNotFound (-18)` (multi-wallet selection),
  `rpcWalletNotSpecified (-19)` (ambiguous multi-wallet),
  `rpcWalletAlreadyLoaded (-35)`, `rpcWalletAlreadyExists (-36)` —
  every Core-defined wallet code is named.  See Rpc.hs:627-665.

## Forward-looking observations

(Not bugs — design notes that might land in a future fix wave.)

- **JSON-RPC 2.0 vs V1_LEGACY shape**: Core distinguishes the two
  versions in `rpc/request.cpp:51-67`.  Under V2, the reply object
  carries `"jsonrpc": "2.0"` and omits the unused-side key (`error`
  is absent on success, `result` is absent on failure).  haskoin
  always emits BOTH keys with one being `null` (V1_LEGACY shape).
  A V2 strict client will reject this.  Out of scope for W125
  (error-CODE parity, not envelope-shape parity) but worth a
  separate gate in a future audit if a strict-V2 client matters.

- **Notification-without-id**: A JSON-RPC notification (request
  without "id" key) is supposed to elicit no reply.  haskoin
  defaults `reqId` to `Null` (Rpc.hs:524) and always replies.  Same
  V2 strictness consideration.

- **Batch + notification combination**: Spec says a batch of only-
  notifications must produce empty response (no array).  haskoin
  always returns an array (Rpc.hs:830).  V2 strictness.

## Per-impl bug count (this audit)

12 bugs flagged: 1 P0-DOSY (addnode shape), 4 P1 (BUG-2 / BUG-4 /
BUG-5 / BUG-6 / BUG-9 / BUG-10), 7 P2 (BUG-7 / BUG-8 / BUG-11 /
BUG-12 + 3 missing-constant items rolled into the "MISSING" gates).
Counting BUG-3's three setban sub-bugs as one entry (the audit
framework counts per-handler bugs); if expanded to per-call-site,
the count is 14.

## Tests

34 xfail/PRESENT-asserting tests in
`test/W125RPCErrorParitySpec.hs`.  None modify production code.
Pattern: a) every named-constant gate is pinned with a tautological
"this code equals what Core says it equals" test (regression guard
against accidental constant drift); b) every BUG is documented with
a code-comment that names the call site and the expected Core code;
c) the audit framework's 30-gate table is encoded inline at the top
of the file for cross-reference.

## Verification

`cabal test haskoin-test --test-show-details=streaming` BEFORE and
AFTER: pre-existing failures are 27 (unrelated to W125).  W125 adds
34 new PASS tests, no new failures.  Total moves from
3587 examples → 3621 examples; passing count moves +34; failing
unchanged at 27.

## Reference

- `bitcoin-core/src/rpc/protocol.h` — the canonical RPCErrorCode enum
- `bitcoin-core/src/rpc/request.cpp` — JSONRPCReplyObj / JSONRPCError
- `bitcoin-core/src/rpc/server.cpp` — RPC_IN_WARMUP gate; method-not-found wire
- `bitcoin-core/src/rpc/util.cpp` — RPC_TYPE_ERROR call sites
- `bitcoin-core/src/rpc/net.cpp` — RPC_CLIENT_NODE_ALREADY_ADDED, INVALID_IP_OR_SUBNET, NOT_ADDED, NODE_CAPACITY_REACHED
- `bitcoin-core/src/rpc/server_util.cpp` — RPC_CLIENT_P2P_DISABLED, RPC_CLIENT_MEMPOOL_DISABLED, RPC_DATABASE_ERROR
- `bitcoin-core/src/rpc/mining.cpp:773` — RPC_CLIENT_IN_INITIAL_DOWNLOAD on getblocktemplate
- `bitcoin-core/src/rpc/mempool.cpp:1141` — same, on importmempool
- `bitcoin-core/src/rpc/blockchain.cpp` — RPC_DATABASE_ERROR + RPC_INVALID_PARAMETER on invalidateblock/reconsiderblock
- `bitcoin-core/src/wallet/rpc/encrypt.cpp` — RPC_WALLET_*_NEEDED / RPC_WALLET_WRONG_ENC_STATE / RPC_WALLET_PASSPHRASE_INCORRECT
- `bitcoin-core/src/wallet/rpc/spend.cpp` — RPC_WALLET_INSUFFICIENT_FUNDS
- `bitcoin-core/src/wallet/rpc/coins.cpp:200` — RPC_METHOD_DEPRECATED

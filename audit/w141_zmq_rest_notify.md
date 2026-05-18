# W141 ZMQ + REST + Notification scripts — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** Three Bitcoin Core operator-surface subsystems bundled into one
audit wave (each is small in isolation):

1. **ZMQ pub/sub notifications**
   (`bitcoin-core/src/zmq/zmqnotificationinterface.cpp` +
    `zmq/zmqpublishnotifier.cpp` + `zmq/zmqabstractnotifier.{h,cpp}`)
   — five publish topics (`pubhashblock`, `pubhashtx`, `pubrawblock`,
   `pubrawtx`, `pubsequence`), each with a 3-frame wire shape
   `[topic | body | LE u32 sequence]`, IPv6 / IPC transport handling,
   per-topic SNDHWM, multi-notifier socket sharing.
2. **REST HTTP API** (`bitcoin-core/src/rest.cpp` + `rest.h`)
   — 14 endpoints across `/rest/{tx,block,block/notxdetails,blockpart,
   blockfilter,blockfilterheaders,chaininfo,mempool,headers,getutxos,
   deploymentinfo,blockhashbyheight,spenttxouts}/...`, three response
   formats (`bin` / `hex` / `json`), warmup gate, `-rest` enablement.
3. **External notification scripts** (`bitcoin-core/src/init.cpp:2009-2018` +
   `node/kernel_notifications.cpp` `AlertNotify` + `wallet/wallet.cpp:1141-1164`
   `m_notify_tx_changed_script`) — `-blocknotify`, `-walletnotify`,
   `-alertnotify`, all of which call `runCommand` via a detached
   `std::thread` after `%s`/`%b`/`%h`/`%w` substitution.

**BIPs:** none (ZMQ + REST + the three notify-scripts are Core
implementation details — not BIPs).

**Out of scope:** the JSON-RPC dispatch surface itself
(audited in W124 / W125), `getblockfilter` / `getindexinfo` /
`scanblocks` RPC paths (W121 / W133), the BIP-78 `/payjoin` HTTP route
(W119 / FIX-65 / FIX-66), and the SOCKS / TLS / Tor / I2P proxy fabric
under the REST listener (W117 / FIX-64).

**Sources audited:**

- ZMQ:
  - `src/Haskoin/Rpc.hs:10807-11121` (entire ZMQ section: topics,
    events, config, notifier lifecycle, worker, encoders, public
    notify functions)
  - `src/System/ZMQ4.hs:1-459` (libzmq.so.5 FFI binding — context,
    socket, bind, send, sendMulti, setSendHighWM, setLinger,
    setTcpKeepAlive)
  - `cbits/zmq_stubs.c` (C shim for the FFI)
  - `app/Main.hs:1-end` (no call sites for `newZmqNotifier` /
    `notifyBlockConnect` / `notifyHashTx` / `notifyTxAcceptance` /
    `notifyTxRemoval` / `notifyBlockDisconnect` — confirmed by
    repo-wide grep)
- REST:
  - `src/Haskoin/Rpc.hs:9156-10318` (REST format parser + 13 handlers
    + dispatcher `routeRest`)
  - `src/Haskoin/Rpc.hs:10336-10355` (`combinedApp` — the gate that
    routes `/rest/*` to `restApp` only when `rpcRestEnabled` is `True`)
- Notification scripts:
  - `app/Main.hs`, `src/Haskoin/Rpc.hs`, `src/Haskoin/Sync.hs`,
    `src/Haskoin/Mempool.hs`, `src/Haskoin/Wallet.hs`,
    `src/Haskoin/Daemon.hs` — repo-wide grep returns **zero** hits for
    `blocknotify` / `walletnotify` / `alertnotify` / `runCommand` /
    `safeChars` / `sanitize`.

**Result:** out of 30 gates, **2 PRESENT (correct)** /
**12 PARTIAL (built but unwired or shape-divergent)** /
**16 MISSING (no implementation at all)**.

**Bugs found:** 17 (3 P0-CDIV, 8 P1, 6 P2).

**Tests added:** 30 gate cases in
`test/W141ZmqRestNotifySpec.hs` (mix of `it` pinning + `xit`
sentinels) plus 5 bonus pinning assertions = 35 cases.

## Relationship to W117 / W119 / W121 / W124

Four adjacent waves touched parts of this surface; W141 does not
re-count their findings:

- **W117 BIP-155** documented the inbound P2P protocol surface;
  W141 documents the outbound operator surface (ZMQ + REST) that
  consumes the same chain/mempool state. No overlap.
- **W119 PayJoin / FIX-65 / FIX-66** added the `/payjoin` HTTP route
  to `combinedApp`. That route is gated separately (`pcEnabled`) from
  `/rest/*` and is audited under its own wave; W141 only audits the
  REST route prefix.
- **W121 Compact filters** documented the BIP-157/158 `getblockfilter`
  RPC path. W141 audits the parallel `/rest/blockfilter/...` REST
  endpoint and **finds the same byte shape as W121** (BUG-12 cross-
  cite if W141's per-height fast-path drifts from the W121 slow-path).
- **W124 Operator-experience** documented `-blocknotify` etc. as a
  meta-gap. W141 measures the gap concretely (zero call sites, no
  argument parsing, no `runCommand` primitive) and lifts it to three
  distinct numbered BUGs (BUG-14 / BUG-15 / BUG-16).

## Top-line verdict

haskoin's three operator surfaces fall into three clearly separated
quality tiers:

1. **REST API — mostly wired, three endpoints missing, several
   shape gaps.** 11 of Core's 14 endpoints are wired and behave
   correctly for the happy path. The three missing endpoints are
   `/rest/blockpart/`, `/rest/deploymentinfo/`, and `/rest/spenttxouts/`
   (BUG-9 / BUG-10 / BUG-11). The shape gaps are: no warmup gate
   (BUG-7 P1), no `MAX_GETUTXOS_OUTPOINTS` enforcement on the
   wire-binary input branch (BUG-8 P1), and the per-height
   `/rest/blockfilter/` fast-path can return bytes that disagree with
   the on-demand slow-path if `udBlockUndo` differs from the index's
   stored compute (BUG-12 P2 cross-cite W121).

2. **ZMQ — built but completely unwired in the production path.**
   The full publisher implementation exists in `Rpc.hs:10807-11121`,
   the libzmq.so.5 FFI binding works (a `newZmqNotifier` integration
   test passes today), but `Main.hs` never instantiates the notifier
   and the `notifyBlockConnect` / `notifyHashTx` / `notifyTxAcceptance`
   / `notifyTxRemoval` / `notifyBlockDisconnect` helpers have zero
   call sites outside the module that defines them. The dead-code-
   helper pattern is by now a familiar haskoin shape (BUG-1 P0-CDIV).
   In addition: the per-topic SNDHWM is collapsed into a single
   `zmqHighWaterMark` field (BUG-2), the `unix://` -> `ipc://`
   transport rewrite is absent (BUG-3), and there is no IPv6
   conditional on the bind address (BUG-4).

3. **Notification scripts — completely absent.** No CLI argument
   parsing for `-blocknotify` / `-walletnotify` / `-alertnotify`,
   no per-event hook in the validation / mempool / wallet event
   stream, no `runCommand` primitive, no `safeChars` sanitisation.
   This is the largest of the three gaps in lines-of-missing-code
   terms (BUG-14 / BUG-15 / BUG-16; BUG-17 covers the missing
   `%s` / `%b` / `%h` / `%w` substitution primitive).

## BUGs catalogued (17 total)

### ZMQ pub/sub (BUG-1 .. BUG-6)

| # | Sev | Summary |
|---|-----|---------|
| BUG-1  | P0-CDIV | `ZmqNotifier` built but **never instantiated** from `Main.hs`; the five `notify*` helpers (`notifyBlockConnect` / `notifyHashTx` / `notifyTxAcceptance` / `notifyTxRemoval` / `notifyBlockDisconnect`) are dead code. Any subscriber that connects to `tcp://127.0.0.1:28332` sees an empty stream forever. |
| BUG-2  | P1      | `ZmqConfig.zmqHighWaterMark` is a single Int for the whole notifier; Core's `CZMQNotificationInterface::Create` reads `-zmqpubhashblockhwm`, `-zmqpubhashtxhwm`, `-zmqpubrawblockhwm`, etc. as **per-topic** values with default `CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM = 1000`. |
| BUG-3  | P1      | `unix://` prefix is not rewritten to `ipc://` before `zmq_bind`. Core's `zmqnotificationinterface.cpp:62-64` does `address.replace(0, ADDR_PREFIX_UNIX.length(), ADDR_PREFIX_IPC)`; haskoin's `newZmqNotifier` calls `ZMQ.bind sock (zmqEndpoint config)` verbatim and a `unix://...` endpoint would `EINVAL` at runtime. |
| BUG-4  | P2      | No `IsZMQAddressIPV6` conditional on the bind address; Core sets `ZMQ_IPV6=1` only for IPv6 addresses (zmqpublishnotifier.cpp:129-136) because some BSDs reject `ZMQ_IPV6=1` for IPv4 sockets. haskoin always inherits the libzmq default (0). |
| BUG-5  | P2      | Multi-notifier socket sharing absent: Core's `CZMQAbstractPublishNotifier::Initialize` reuses an existing socket if `mapPublishNotifiers.find(address) != end()` (zmqpublishnotifier.cpp:99-159); haskoin opens a fresh socket per `newZmqNotifier` call, so two topics on the same endpoint would collide. (Currently moot because BUG-1 prevents any topic from being instantiated.) |
| BUG-6  | P2      | `ZMQ_TCP_KEEPALIVE` is set unconditionally (good), but `ZMQ_LINGER=0` is set BEFORE bind (haskoin), whereas Core sets it during shutdown only (zmqpublishnotifier.cpp:185-188). With LINGER=0 from open, a fast-restart loses in-flight messages even if no shutdown race exists. |

### REST API (BUG-7 .. BUG-13)

| # | Sev | Summary |
|---|-----|---------|
| BUG-7  | P1      | No warmup gate. Core's every `rest_*` handler starts with `if (!CheckWarmup(req)) return false;` which returns `503 Service Temporarily Unavailable` while `RPCIsInWarmup`. haskoin's `routeRest` jumps straight to each handler regardless of IBD / index sync state. |
| BUG-8  | P1      | `MAX_GETUTXOS_OUTPOINTS = 15` is enforced on the URI-parsed input path (`Rpc.hs:9795-9798`) but **not** on the binary / hex body branch — Core's `rest_getutxos` enforces it after `oss >> vOutPoints;` (rest.cpp:990) so a malicious client could ship 1M outpoints in the binary body. |
| BUG-9  | P1      | `/rest/blockpart/<hash>.<ext>?offset=N&size=M` endpoint absent. Core's `rest_block_part` (rest.cpp:481-498) supports range queries; haskoin has no dispatcher entry. |
| BUG-10 | P1      | `/rest/deploymentinfo/[<hash>].json` endpoint absent. Core's `rest_deploymentinfo` (rest.cpp:743-780) reuses the `getdeploymentinfo` RPC handler under HTTP; haskoin has the RPC but no REST front-end. |
| BUG-11 | P1      | `/rest/spenttxouts/<hash>.<ext>` endpoint absent. Core's `rest_spent_txouts` (rest.cpp:313-381) serialises `CBlockUndo`; haskoin has the undo data but exposes it only via the block-extended JSON, not as a dedicated endpoint. |
| BUG-12 | P2      | `/rest/blockfilter/` fast-path vs slow-path drift: the per-height index lookup returns `bfeEncoded` bytes verbatim, but the on-demand slow-path recomputes via `computeBlockFilter block (udBlockUndo undoData) bh`. If the persisted-index code path and the recompute code path ever drift in their handling of empty-output scripts or non-coinbase OP_RETURNs, the same query returns different bytes for the same block hash (cross-cite W121 BUG-16 P0-CDIV). |
| BUG-13 | P2      | `/rest/headers/` `?count=` query parameter is not bounded against negative integers; haskoin's `readMaybe` -> `Maybe Int` accepts a leading `-`. Core uses `ToIntegral<size_t>` which rejects negatives at parse time (rest.cpp:207). The downstream `count < 1` guard catches this in practice, but the error message says "out of acceptable range" instead of "invalid". |

### Notification scripts (BUG-14 .. BUG-17)

| # | Sev | Summary |
|---|-----|---------|
| BUG-14 | P0-CDIV | `-blocknotify=<cmd>` argument **absent**. Core's `init.cpp:498` registers it and `init.cpp:2009-2018` hooks `NotifyBlockTip_connect` to run the command in a detached thread on every new tip. haskoin has no CLI flag, no event hook, no thread. Operators who depend on `-blocknotify` for monitoring (alerting, mempool snapshots, mining-pool round-end signalling) cannot use haskoin. |
| BUG-15 | P0-CDIV | `-walletnotify=<cmd>` argument **absent**. Core's `wallet/wallet.cpp:1141-1164` runs the command on `NotifyTransactionChanged` with `%s`/`%b`/`%h`/`%w` substitution and `ShellEscape` on the wallet name. haskoin has no CLI flag, no hook in the wallet event path. |
| BUG-16 | P1      | `-alertnotify=<cmd>` argument absent. Core's `node/kernel_notifications.cpp:30-47` runs the command after `SanitizeString(strMessage)` and `'<safe>'` single-quoting on every `warningSet` (KernelNotifications). haskoin has no hook on its own warning system. |
| BUG-17 | P1      | `runCommand` + `safeChars` / `SanitizeString` + `ShellEscape` primitives absent. Closing BUG-14 / BUG-15 / BUG-16 requires a shared command-runner that sanitizes shell metacharacters and substitutes `%s`/`%b`/`%h`/`%w` — equivalent to Core's `common/run_command.cpp::RunCommand` + `util/string.cpp::SanitizeString` + `util/strencodings.cpp::ShellEscape`. No file in `src/` mentions any of these names. |

## Risk-rank closure plan (highest-impact first)

1. Implement `runCommand` + `safeChars` + `ShellEscape` primitive
   (closes the prerequisite for BUG-14 / BUG-15 / BUG-16 / BUG-17).
2. Wire `-blocknotify` argument + tip-event hook (closes BUG-14, P0-CDIV).
3. Wire `ZmqNotifier` from `Main.hs` (closes BUG-1, P0-CDIV) — the
   notifier already works; this is one new constructor call plus
   plumbing five `notify*` calls onto the existing block-connect /
   block-disconnect / mempool-add / mempool-remove hooks.
4. Wire `-walletnotify` argument + per-tx wallet hook (closes BUG-15).
5. Add `/rest/blockpart/` + `/rest/deploymentinfo/` + `/rest/spenttxouts/`
   endpoints (closes BUG-9 / BUG-10 / BUG-11).
6. Per-topic SNDHWM parsing in `ZmqConfig` (closes BUG-2).
7. `unix://` -> `ipc://` rewrite (closes BUG-3).
8. Warmup gate in every REST handler (closes BUG-7).
9. `MAX_GETUTXOS_OUTPOINTS` enforcement on the binary-body branch
   (closes BUG-8).
10. `-alertnotify` argument + warning-system hook (closes BUG-16).
11. Cosmetic / robustness fixes (BUG-4 / BUG-5 / BUG-6 / BUG-12 /
    BUG-13).

Estimated total: ~8 individual fix waves. The discovery audit pre-
positions all 30 gates as `xit` (where MISSING / dead-code) so each
closure step flips a clear sentinel.

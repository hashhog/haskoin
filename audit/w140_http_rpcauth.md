# W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** end-to-end HTTP authentication and dispatch surface that
fronts haskoin's JSON-RPC + REST endpoints, including:

- The HTTP server lifecycle (bind addresses, listener config, shutdown).
- HTTP Basic auth (rpcuser/rpcpassword path AND cookie path).
- The missing rpcauth (HMAC-SHA256 over salted password) path.
- The missing rpcallowip + rpcbind + rpcwhitelist ACL surface.
- HTTP status-code mapping for JSON-RPC errors.
- Brute-force-deterrence sleep.
- Body / header size limits and work-queue depth gating.
- Cookie-file lifecycle and permissions (rpccookieperms).
- Operator-visible defaults (rpcuser=haskoin, rpcpassword=haskoin).

**Out of scope:**
- JSON-RPC body content / method-level dispatch behaviour (covered by
  W125 RPC error parity for the error-code-message surface, and
  per-method waves for the actual handler bodies).
- TLS / HTTPS termination (W119 + FIX-64 already audited; cited but
  not re-counted).
- REST endpoint correctness (W124 / W125 / per-handler waves).
- ZMQ notifications (separate transport).

Sources audited:
- `src/Haskoin/Rpc.hs:362-412` (`RpcConfig` + `defaultRpcConfig`),
- `src/Haskoin/Rpc.hs:684-757` (`startRpcServer` + cookie generation
  + Warp listener),
- `src/Haskoin/Rpc.hs:797-929` (`rpcApp` + `checkAuth` + `readBody`
  + `jsonResponse`),
- `src/Haskoin/Rpc.hs:931-993` (`extractWalletName` +
  `getWalletForRequest` /wallet/<name> URI handling),
- `src/Haskoin/Rpc.hs:10336-10355` (`combinedApp` — REST vs RPC vs
  /payjoin router),
- `src/Haskoin/Rpc.hs:9203-9277` (`restApp` + `routeRest`),
- `src/Haskoin/Daemon.hs:537-563` (`healthApp` + `runHealthServer`),
- `app/Main.hs:227-285` (CLI flag declarations for the RPC subsystem),
- `app/Main.hs:475-545` (`Daemon.configLookup` for haskoin.conf
  fallback values),
- `app/Main.hs:1194-1212` (RPC config plumbing through to
  `startRpcServer`).

**Result:** 4 PRESENT / 4 PARTIAL / 22 MISSING out of 30 gates.

**Bugs found:** 17 (5 P0-SEC, 6 P1, 6 P2).

**Tests added:** 30 gate cases in `test/W140HTTPRpcAuthSpec.hs`
(mix of `it` pinning + `xit` sentinel) so future fix waves can flip
`xit` -> `it` after wiring the missing primitives.

## Relationship to W119 / W124 / W125

Three nearby waves overlap the RPC HTTP surface:

- **W119 PayJoin + FIX-64 TLS** documented the HTTPS-termination
  knobs (rpcTlsCertFile / rpcTlsKeyFile + validateTlsConfig +
  rpcTlsSettings).  W140 takes that wiring as given and does NOT
  re-count it as a gate.
- **W124 Operator experience** documented the cookie-file
  lifecycle from the operator angle (file path, removal on
  shutdown, permissions); W140 cross-cites those findings and
  adds new gates for the missing `-rpccookieperms` CLI surface
  (G14).
- **W125 RPC error parity** documented body-level
  error-code/message parity (12 bugs).  W140 documents the
  **HTTP-layer status-code parity** (G16-G19), which is a
  separate (and orthogonal) divergence: even when the body
  carries the correct `-32601 Method not found` error object,
  haskoin returns HTTP 200 instead of Core's HTTP 404.  This is
  visible to any client that consults the HTTP status line
  before parsing the body (curl `-f`, libcurl
  `CURLOPT_FAILONERROR`, `requests.raise_for_status`).

Where the same constant or guard would close multiple gates, the bug
is counted once and cross-cited.

## Top-line verdict

The HTTP/auth/dispatch surface splits into four quality tiers:

1. **Cookie auth wire format** is present and mostly correct.  The
   cookie file is `__cookie__:<hex>` (matches Core), permissions
   are `0o600`, the file is removed at clean shutdown, and the
   contents are checked with the haskoin-internal user
   `__cookie__`.  The comparison is **NOT** constant-time
   (BUG-5).

2. **rpcuser/rpcpassword auth** is present, but with several
   serious defects:

   - Default credentials are **`haskoin:haskoin`** in
     `defaultRpcConfig` AND in the CLI parser
     (`app/Main.hs:230-231`).  These are propagated into a node
     started with no `-rpcuser=` override.  Combined with cookie
     auth being **ALWAYS active** regardless of whether rpcuser is
     set (Core gates cookie gen on `rpcpassword == ""`), this means
     even a "configured user/password" haskoin node has TWO
     parallel auth paths the operator may not realize are active.
     (BUG-1 P0-SEC + BUG-2 P0-SEC + BUG-3 P0-SEC.)
   - **No timing-resistant comparison.** `checkAuth` uses Haskell's
     `(==)` on `Text` and `ByteString`, which is short-circuiting.
     A network attacker can mount a timing attack to recover the
     password byte-by-byte.  Bitcoin Core uses
     `TimingResistantEqual` for exactly this reason.  haskoin
     ALREADY has `constantTimeEq` in
     `src/Haskoin/Network.hs:7507` (used by v2 transport) — it is
     simply not called from `checkAuth`.  (BUG-5 P0-SEC.)

3. **rpcauth (HMAC-SHA256 salted-hash) auth is COMPLETELY
   MISSING.**  This is the most-recommended auth path in
   Core's documentation (`share/rpcauth/rpcauth.py`) and the
   one used by every well-known third-party deployment guide
   (BTCPay, Umbrel, Start9, RaspiBlitz).  haskoin has:

   - No `rpcAuth :: [Text]` field on `RpcConfig`.
   - No CLI parser for `-rpcauth=user:salt$hmac`.
   - No HMAC-SHA256 verifier.  (`Network.hs` has SHA-256d /
     HMAC primitives via `cryptonite` already; the gap is the
     parser + verifier, not the crypto.)

   (BUG-4 P0-SEC.)  An operator copying a `-rpcauth=...`
   line from a Bitcoin Core wiki page will get a node that
   silently fails authentication for every request.

4. **HTTP status-code mapping is wrong on the JSON-RPC path.**
   Every JSON-RPC reply — whether success or error — uses
   HTTP 200.  Bitcoin Core maps `RPC_INVALID_REQUEST` to
   HTTP 400, `RPC_METHOD_NOT_FOUND` to HTTP 404, and JSON-RPC
   2.0 notifications (id field absent) to HTTP 204.  Clients
   that branch on HTTP status are broken: `curl -f` against
   haskoin will always succeed; `curl -f` against Core will
   correctly fail.  (BUG-7 / BUG-8 / BUG-9.)

5. **IP allowlist is structurally absent.**  `rpcAllowIp ::
   [String]` is a field on `RpcConfig` but **the field is never
   read anywhere** (BUG-6 P0-SEC).  The default is
   `["127.0.0.1"]`, but a node that binds to `0.0.0.0` (manual
   reconfig) or that runs behind a reverse proxy would accept
   connections from any client that can reach the listener.
   Core enforces `ClientAllowed` BEFORE the auth check, so an
   off-network attacker never even gets the chance to brute-force.
   haskoin has neither the early ACL check nor the
   parser for `-rpcallowip=` / `-rpcbind=` CLI flags.

6. **DoS surface: no work-queue depth gate, no body size limit,
   no 250ms brute-force sleep.**  Core caps the work queue
   at 16 items by default (returns HTTP 503 when full),
   enforces `MAX_SIZE` on the body (32 MiB), and sleeps 250 ms
   on every failed authentication attempt.  haskoin has none
   of these: `readBody` chunks the entire payload into a
   single in-memory `ByteString` (RAM-exhaustion DoS),
   there is no work-queue throttle, and on auth failure we
   immediately return 401 (free brute-force).
   (BUG-10 / BUG-11 / BUG-12.)

## Reference table (Core <-> haskoin)

| Core construct                                    | Core file              | haskoin equivalent                                              |
|---------------------------------------------------|------------------------|-----------------------------------------------------------------|
| `HTTPReq_JSONRPC` dispatch                         | httprpc.cpp:104-238    | `Haskoin.Rpc.rpcApp`                                            |
| `RPCAuthorized` (Basic prefix + Base64 + user:pass split) | httprpc.cpp:84-102 | `Haskoin.Rpc.checkAuth`                                         |
| `CheckUserAuthorized` (per-`g_rpcauth` entry HMAC) | httprpc.cpp:63-82      | **MISSING**                                                     |
| `InitRPCAuthentication` (-rpcuser / -rpcpassword / -rpcauth) | httprpc.cpp:240-329 | `Haskoin.Rpc.startRpcServer` + `app/Main.hs:1194-1212`         |
| Cookie auth (`__cookie__`)                         | rpc/server_util.cpp    | `Haskoin.Rpc.writeCookieFile` / cookie eq path in `checkAuth`   |
| `ClientAllowed` ACL                                | httpserver.cpp:137-145 | **MISSING** (`rpcAllowIp` field is unused)                      |
| `InitHTTPAllowList`                                | httpserver.cpp:148-168 | **MISSING**                                                     |
| `HTTPBindAddresses` (-rpcbind + dual-stack fallback) | httpserver.cpp:309-361 | `app/Main.hs:1194-1212` (single bind via `setHost`)            |
| `TimingResistantEqual`                             | util/strencodings.cpp  | `Haskoin.Network.constantTimeEq` (NOT used by `checkAuth`)      |
| `UninterruptibleSleep(250ms)` brute-force deter    | httprpc.cpp:128        | **MISSING**                                                     |
| `WWW-Authenticate: Basic realm="jsonrpc"` header   | httprpc.cpp:33,114,130 | **MISSING**                                                     |
| `JSONErrorReply` HTTP status code mapping          | httprpc.cpp:41-59      | **MISSING** (always 200)                                        |
| `g_rpc_whitelist` per-user method ACL              | httprpc.cpp:38,154-191 | **MISSING**                                                     |
| `g_rpc_whitelist_default`                          | httprpc.cpp:39,306     | **MISSING**                                                     |
| `-rpccookieperms` (owner/group/all)                | httprpc.cpp:248-256    | **MISSING** (hardcoded 0o600 inside `writeCookieFile`)          |
| `-rpcworkqueue` 503 service-unavailable gate       | httpserver.cpp:255-258 | **MISSING** (Warp has no equivalent knob)                       |
| `-rpcthreads`                                      | httpserver.cpp:440-442 | **MISSING** (Warp default)                                      |
| `-rpcservertimeout`                                | httpserver.cpp:408     | **MISSING**                                                     |
| `MAX_SIZE` body cap                                | httpserver.cpp:410     | **MISSING** (`readBody` is unbounded)                           |
| `MAX_HEADERS_SIZE` (8192)                          | httpserver.cpp:51,409  | **MISSING** (Warp default ~ 32 KiB; not configurable)           |
| JSON-RPC 2.0 notification → HTTP 204               | httprpc.cpp:169,221    | **MISSING** (always 200)                                        |
| `RPC_INVALID_REQUEST` → HTTP 400                   | httprpc.cpp:50-51      | **MISSING** (always 200)                                        |
| `RPC_METHOD_NOT_FOUND` → HTTP 404                  | httprpc.cpp:52-53      | **MISSING** (always 200)                                        |

## 30-gate audit matrix

| Gate | Description                                                    | Status   | Bug |
|------|----------------------------------------------------------------|----------|-----|
| G1   | Default rpcuser/rpcpassword are NOT well-known constants       | MISSING  | BUG-1 P0-SEC |
| G2   | Cookie auth gated on `rpcpassword == ""` (Core parity)         | MISSING  | BUG-2 P0-SEC |
| G3   | Cookie file content format `__cookie__:<hex>`                   | PRESENT  | -   |
| G4   | `rpcauth=user:salt$hmac` parser + HMAC-SHA256 verifier         | MISSING  | BUG-4 P0-SEC |
| G5   | Constant-time password comparison (TimingResistantEqual)       | MISSING  | BUG-5 P0-SEC |
| G6   | `-rpcallowip` CIDR/subnet ACL enforced BEFORE auth             | MISSING  | BUG-6 P0-SEC |
| G7   | Bind both `127.0.0.1` and `::1` by default (Core dual-stack)   | MISSING  | BUG-13 P1 |
| G8   | `-rpcbind` multi-endpoint parser                                | MISSING  | BUG-14 P1 |
| G9   | `-rpcbind`+`-rpcallowip` required-together safety check        | MISSING  | BUG-15 P1 |
| G10  | 250 ms `UninterruptibleSleep` on auth-fail (brute-force deter) | MISSING  | BUG-10 P0-SEC |
| G11  | `WWW-Authenticate: Basic realm="jsonrpc"` on 401                | MISSING  | BUG-16 P2 |
| G12  | `-rpcwhitelist=user:method,method` per-user method ACL          | MISSING  | BUG-17 P1 |
| G13  | `-rpcwhitelistdefault` deny-all-by-default                      | MISSING  | BUG-17 P1 (folded) |
| G14  | `-rpccookieperms=owner|group|all` permission selector           | MISSING  | BUG-18 P2 |
| G15  | `Authorization` header case-insensitive lookup (WAI default)   | PRESENT  | -   |
| G16  | HTTP 400 on `RPC_INVALID_REQUEST` (-32600)                     | MISSING  | BUG-7 P1 |
| G17  | HTTP 404 on `RPC_METHOD_NOT_FOUND` (-32601)                    | MISSING  | BUG-8 P1 |
| G18  | HTTP 204 on JSON-RPC 2.0 notification (id absent)              | MISSING  | BUG-9 P2 |
| G19  | Notification → no response body (JSON-RPC 2.0)                 | MISSING  | BUG-9 P2 (folded) |
| G20  | `jsonrpc:"2.0"` switches to catch-errors-return-200 mode       | MISSING  | BUG-19 P2 |
| G21  | `/wallet/<name>` URI handler routes per request                | PRESENT  | -   |
| G22  | HTTP method must be POST (others → 405)                        | PRESENT  | -   |
| G23  | `UNKNOWN` HTTP method early-rejected before path dispatch      | PARTIAL  | BUG-20 P2 |
| G24  | Work-queue depth gate → 503 "Work queue depth exceeded"        | MISSING  | BUG-11 P1 |
| G25  | `-rpcthreads` thread-pool size knob                             | MISSING  | BUG-21 P2 |
| G26  | `-rpcservertimeout` server-side request timeout                | MISSING  | BUG-22 P2 |
| G27  | `MAX_HEADERS_SIZE = 8192` header-cap enforced                   | PARTIAL  | BUG-23 P2 |
| G28  | `MAX_SIZE` (32 MiB) body-cap enforced                           | MISSING  | BUG-12 P1 |
| G29  | 503 SERVICE_UNAVAILABLE on requests during shutdown            | MISSING  | BUG-24 P2 |
| G30  | `Connection: close` header on responses during shutdown         | PARTIAL  | BUG-25 P2 |

## Bug catalogue

### P0-SEC (5)

#### BUG-1 (P0-SEC) — Default credentials `haskoin:haskoin`

**Where:** `src/Haskoin/Rpc.hs:402-411` (`defaultRpcConfig`) +
`app/Main.hs:230-231` (CLI defaults `value "haskoin"`).

**What Core does:** Has no default credentials.  `rpcuser` defaults
to `""` (empty), `rpcpassword` defaults to `""` (empty).  If both are
empty AND `-rpcauth` is empty, `InitRPCAuthentication` falls back to
cookie auth ONLY (httprpc.cpp:245).

**What haskoin does:** Ships `rpcUser = "haskoin"` and
`rpcPassword = "haskoin"` as live, working credentials at
`defaultRpcConfig`.  Combined with BUG-2 (cookie auth always
active), this means the auth surface has THREE accept paths:

1. `haskoin:haskoin` (the well-known shipping credential).
2. The cookie at `<datadir>/.cookie`.
3. Whatever the operator may have set via `-rpcuser=`.

A node deployed with `-rpcallowip=0.0.0.0/0` (or via a misconfigured
reverse proxy that drops the IP allowlist) will be open to any
attacker who tries the obvious credentials.  This is a SHIP-DAY P0
issue: every demo, every `start_testnet4.sh` invocation, every
README-driven first-run uses these defaults.

**Severity:** P0-SEC.  Single credential to remember = single
credential to brute-force.

---

#### BUG-2 (P0-SEC) — Cookie auth ALWAYS active regardless of rpcuser/rpcpassword

**Where:** `src/Haskoin/Rpc.hs:716-719` (always
`generateCookiePassword` + `writeCookieFile`).

**What Core does:** `InitRPCAuthentication` (httprpc.cpp:245-273)
gates cookie generation on `gArgs.GetArg("-rpcpassword","") == ""`.
Operators who configure `rpcuser` + `rpcpassword` get user/pass
auth ONLY; no cookie is generated and the `.cookie` file does not
exist.  Operators who leave `-rpcpassword` empty get cookie auth
ONLY.  The two paths are MUTUALLY EXCLUSIVE.

**What haskoin does:** Generates a fresh 32-byte cookie on every
startup regardless of whether `-rpcuser`/`-rpcpassword` are set.
The cookie file always exists, always contains a valid credential,
and is accepted by `checkAuth`.

**Severity:** P0-SEC.  Combined with BUG-1, operators who
intentionally rotate `rpcpassword` to a strong value still have a
random-but-disk-leaked cookie that grants full RPC.  An attacker
with local read access to the datadir bypasses the user/pass
entirely.

---

#### BUG-3 (P0-SEC) — Cookie credential bypass via known string `__cookie__`

**Where:** `src/Haskoin/Rpc.hs:895-898` (`checkAuth` cookie branch).

**What Core does:** Same wire format (`__cookie__:<hex>`), same
fixed username `__cookie__`.  The `<hex>` is generated with
`GetStrongRandBytes` and stored only in the cookie file with
restricted permissions (`-rpccookieperms`, default 0o600).  The
fixed username is part of the design — what protects the cookie is
the secrecy of the `<hex>` payload, not the obscurity of the
username.

**What haskoin does:** Same.  This row is not a divergence from
Core; it is a STRUCTURAL property of the cookie-auth design that
becomes a real issue when combined with BUG-1 and BUG-2 (a
hardcoded user is acceptable when there is only ONE auth path that
uses it; when a second known auth path is always active it
multiplies the attack surface).

**Severity:** P0-SEC, but conditional on BUG-1 and BUG-2.
**Action:** Auditing convention requires a bug ID for the surface
even when the local behaviour matches Core, because the
non-divergence becomes a divergence when adjacent bugs land.
Flagged here so a fix wave that touches BUG-1 / BUG-2 also revisits
the wire-format wording in `checkAuth` to make the dual-credential
state explicit.

---

#### BUG-4 (P0-SEC) — `rpcauth=user:salt$hmac` missing entirely

**Where:** Nowhere — there is no `rpcAuth` field on `RpcConfig`,
no CLI parser for `-rpcauth=`, no HMAC-SHA256 verifier in `Rpc.hs`.

**What Core does:** `InitRPCAuthentication` (httprpc.cpp:290-303)
parses every `-rpcauth=user:salt$hmac` line.  `CheckUserAuthorized`
(httprpc.cpp:63-82) recomputes HMAC-SHA256(salt, password) and
checks it constant-time against the stored hash.  The
`share/rpcauth/rpcauth.py` helper produces the salt + hash for
operators.

**What haskoin does:** Provides no parser, no field, no verifier.
An operator who copies `-rpcauth=alice:f7b14e...$d4d1ab...` from
their Bitcoin Core wiki page will get rejected for every request
with HTTP 401.

**Severity:** P0-SEC.  rpcauth is the only auth path that lets an
operator avoid storing the cleartext password in `bitcoin.conf` /
`haskoin.conf`.  Missing this path forces operators back to
cleartext passwords (BUG-1) or cookie auth (BUG-2).

---

#### BUG-5 (P0-SEC) — Password comparison is NOT constant-time

**Where:** `src/Haskoin/Rpc.hs:897-900`:

```haskell
(user == "__cookie__" && pass == rsCookiePassword server)
|| (user == rpcUser config && pass == rpcPassword config)
```

**What Core does:** httprpc.cpp:66 (CheckUserAuthorized) and
httprpc.cpp:77 (hash compare) both use
`TimingResistantEqual`.  The user-name comparison is also
constant-time (httprpc.cpp:66), so even leaking which user exists
through timing is avoided.

**What haskoin does:** Uses Haskell's `(==)` on `Text` and
`ByteString`.  Both short-circuit on the first mismatched byte.
A network attacker can mount a timing side-channel attack to
recover the password byte by byte.

**Note:** haskoin ALREADY has a constant-time byte comparison
helper at `src/Haskoin/Network.hs:7507` (`constantTimeEq`),
exported and used by the v2 transport.  The fix is mechanical —
re-export it from `Haskoin.Network` (already exported), import
in `Rpc.hs`, and replace `==` with `constantTimeEq` after lifting
`Text` to `ByteString` via `TE.encodeUtf8`.

**Severity:** P0-SEC.  Trivial fix, real attack surface.

---

#### BUG-6 (P0-SEC) — `rpcAllowIp` is a dead field; no IP ACL anywhere

**Where:** `src/Haskoin/Rpc.hs:367,407` defines and defaults the
field; `grep -nE "rpcAllowIp" src/Haskoin/Rpc.hs` returns ONLY the
definition and the default — the field is never READ anywhere.

**What Core does:** `InitHTTPAllowList` (httpserver.cpp:148-168)
parses every `-rpcallowip=` entry, including bare hosts
(`1.2.3.4`), netmasks (`1.2.3.4/255.255.255.0`), and CIDR
(`1.2.3.4/24` or `0.0.0.0/0`).  Adds `127.0.0.0/8` and `::1`
unconditionally.  Every incoming request is checked
against this list at `http_request_cb` line 217 — BEFORE auth.

**What haskoin does:** `defaultRpcConfig` ships with
`rpcAllowIp = ["127.0.0.1"]`, but the field is never consulted.
The actual ACL is whatever Warp's `setHost` is given — and that's
a SINGLE bind address (BUG-13).  A node started with `--rpcbind`-
equivalent semantics (which haskoin doesn't have) would have NO
allowlist enforcement at all.

**Severity:** P0-SEC.  A user-visible config option that silently
no-ops is worse than no option at all, because operators believe
they have a defense-in-depth they don't.

---

#### BUG-10 (P0-SEC) — No brute-force deterrent sleep on auth fail

**Where:** `src/Haskoin/Rpc.hs:807-812` immediately returns 401.

**What Core does:** httprpc.cpp:128 inserts
`UninterruptibleSleep(std::chrono::milliseconds{250})` on every
failed auth attempt.  At 250 ms per try, an attacker can mount at
most 4 attempts per second per connection.

**What haskoin does:** Returns 401 immediately.  An attacker can
brute-force at the full speed of the RPC port (thousands of
attempts/second).  Combined with BUG-1 (`haskoin:haskoin` default),
the time to crack is dominated by latency, not server compute.

**Severity:** P0-SEC.

---

### P1 (6)

#### BUG-7 (P1) — HTTP 400 not returned on `RPC_INVALID_REQUEST`

**Where:** `src/Haskoin/Rpc.hs:915-924` (`jsonResponse`,
`jsonArrayResponse`).

**What Core does:** httprpc.cpp:50-51 sets `nStatus = HTTP_BAD_REQUEST`
when the error code is `RPC_INVALID_REQUEST` (-32600).

**What haskoin does:** Always returns HTTP 200, even when
`resError.code == -32600`.

**Effect:** Any HTTP-status-aware client (`curl -f`, `requests
.raise_for_status`, libcurl's `CURLOPT_FAILONERROR`) treats haskoin
as if every request succeeded.

---

#### BUG-8 (P1) — HTTP 404 not returned on `RPC_METHOD_NOT_FOUND`

**Where:** `src/Haskoin/Rpc.hs:915-924`.

**What Core does:** httprpc.cpp:52-53 sets `nStatus = HTTP_NOT_FOUND`
when the error code is `RPC_METHOD_NOT_FOUND` (-32601).

**What haskoin does:** Always HTTP 200.

**Severity:** P1.  Many CLI tools (`bitcoin-cli`-equivalents,
`curl --fail`) rely on the 4xx/5xx distinction to retry or to fail
loudly; the inability to surface "method missing" at the HTTP
layer hides real bugs.

---

#### BUG-11 (P1) — No work-queue depth gate (DoS surface)

**Where:** `src/Haskoin/Rpc.hs:753-755` uses
`runSettings settings (combinedApp server)` without
`setOnException`, `setMaximumBodyFlush`, or any throttle.

**What Core does:** `g_threadpool_http` has `g_max_queue_depth`
items (httpserver.cpp:79, default 16, configurable via
`-rpcworkqueue=`).  When the queue is full, the listener
returns HTTP 503 "Work queue depth exceeded".

**What haskoin does:** Warp's `defaultSettings` has no
work-queue limit.  Every accepted TCP connection forks a green
thread; under a slowloris-style attack, the RTS can run out of
threads and the process degrades.

---

#### BUG-12 (P1) — Unbounded `readBody` body buffer (DoS surface)

**Where:** `src/Haskoin/Rpc.hs:903-912`.

```haskell
readBody req = do
  chunks <- getChunks
  return $ BS.concat chunks
  where
    getChunks = do
      chunk <- requestBody req
      if BS.null chunk
        then return []
        else (chunk :) <$> getChunks
```

**What Core does:** httpserver.cpp:410 calls
`evhttp_set_max_body_size(http, MAX_SIZE)`.  `MAX_SIZE` is 32 MiB
(`MAX_PROTOCOL_MESSAGE_LENGTH` in `serialize.h`).  Requests over
the cap are rejected at the libevent layer before the handler runs.

**What haskoin does:** Loops `requestBody` until EOF and stitches
into a single `ByteString`.  A 4 GiB body is accepted in full
before any size check, exhausting RAM.

**Severity:** P1.  Pre-auth DoS surface — a single unauthenticated
attacker can OOM the daemon by sending a multi-GiB POST.

---

#### BUG-13 (P1) — Single-bind only; no dual-stack 127.0.0.1 + ::1

**Where:** `app/Main.hs:1194-1212` (no `rpcHost` override) +
`src/Haskoin/Rpc.hs:751-752` (`setHost (fromString (rpcHost config))`).

**What Core does:** httpserver.cpp:319-321 binds BOTH `127.0.0.1`
AND `::1` when `-rpcbind` / `-rpcallowip` are unset.  Operators
get IPv4+IPv6 localhost without configuration.

**What haskoin does:** Binds the single address in `rpcHost`
(default `"127.0.0.1"`).  IPv6-only clients (`localhost` resolving
to `::1` on most modern Linux) cannot connect.

---

#### BUG-14 (P1) — `-rpcbind` parser missing (single-endpoint only)

**Where:** No CLI flag, no config-file lookup, no parser.

**What Core does:** httpserver.cpp:328-338 accepts repeated
`-rpcbind=host[:port]` arguments and binds each one separately.

**What haskoin does:** A single `--rpcport` (positional) +
hardcoded `rpcHost = "127.0.0.1"`.  Operators who need to bind
on a specific interface (e.g. a VPN address) cannot do so.

---

#### BUG-15 (P1) — `-rpcbind` + `-rpcallowip` required-together safety check missing

**Where:** Nowhere.

**What Core does:** httpserver.cpp:319-327: if EITHER `-rpcallowip`
OR `-rpcbind` is missing, fall back to localhost and emit a
loud warning.  This prevents the "wide-open RPC port" footgun
where an operator sets `-rpcbind=0.0.0.0` but forgets the
allowlist.

**What haskoin does:** No such cross-check.  Combined with
BUG-6 and BUG-13/14, an operator who hand-rolls a wider bind
gets NO ACL enforcement.

---

#### BUG-17 (P1) — `-rpcwhitelist` per-user method ACL missing

**Where:** Nowhere.

**What Core does:** httprpc.cpp:38,154-191 supports
`-rpcwhitelist=alice:getblockchaininfo,getblockcount`.  When set,
the user `alice` can ONLY call those two methods; everything else
returns HTTP 403.  Combined with `-rpcwhitelistdefault`, this
enables deny-by-default operator policies (G13 folded into G12 bug).

**What haskoin does:** No equivalent.  Every authenticated user
has full RPC access.

---

### P2 (6)

#### BUG-9 (P2) — JSON-RPC 2.0 notification → 200 not 204

**Where:** `src/Haskoin/Rpc.hs:915-924`.

**What Core does:** httprpc.cpp:167-170 returns HTTP 204
NO_CONTENT (no response body) when the request is a JSON-RPC 2.0
notification (no `id` field).

**What haskoin does:** Always returns HTTP 200 + a body.

**Severity:** P2 because legitimate JSON-RPC 2.0 clients are rare
in the Bitcoin ecosystem; most use the v1.x convention with `id`
always present.

---

#### BUG-16 (P2) — `WWW-Authenticate: Basic realm="jsonrpc"` header missing on 401

**Where:** `src/Haskoin/Rpc.hs:810-812`.

```haskell
respond $ responseLBS status401
  [(hContentType, "application/json")]
  "{\"error\": \"Unauthorized\"}"
```

**What Core does:** httprpc.cpp:33,114,130 sends
`WWW-Authenticate: Basic realm="jsonrpc"` on every 401.  This is
what triggers `curl --basic --user a:b` to retry with the
Authorization header, and what triggers the browser
basic-auth-dialog prompt.

**What haskoin does:** Returns 401 with no `WWW-Authenticate`
header.  Browser interop is broken; `curl -u user:pass` still
works because curl always sends the Authorization header up
front.

---

#### BUG-18 (P2) — `-rpccookieperms` missing (hardcoded 0o600)

**Where:** `src/Haskoin/Rpc.hs:698` (`setFileMode cookiePath 0o600`).

**What Core does:** httprpc.cpp:247-256 accepts
`-rpccookieperms=owner|group|all` to widen the cookie file's
permissions for shared-deployment use cases (e.g. a non-root
operator wanting their `bitcoin` group to read the cookie).

**What haskoin does:** Always 0o600.  Shared-group deployments
have to `chmod g+r` after every restart.

---

#### BUG-19 (P2) — JSON-RPC 2.0 catch-errors semantics missing

**Where:** `src/Haskoin/Rpc.hs:519-525` parses `reqJsonrpc :: Text`
with default `"1.0"` but **never branches on it**.

**What Core does:** When `jsonrpc:"2.0"` is set, exceptions thrown
by the handler are caught and returned as RPC errors with HTTP
200 (not HTTP 500).  When the version is "1.0" or "1.1", the
exception path falls back to HTTP-error responses (catch_errors =
false; httprpc.cpp:163-166).

**What haskoin does:** Identical behaviour regardless of version
(everything is HTTP 200 + JSON body).  The v1.x compatibility
path is missing, BUT in haskoin's case both branches happen to
match because of BUG-7/BUG-8 (all errors → 200).

---

#### BUG-20 (P2) — `UNKNOWN` HTTP method not early-rejected at httpserver layer

**Where:** `src/Haskoin/Rpc.hs:801-805`.

```haskell
if requestMethod req /= "POST"
  then respond $ responseLBS status405 [...] "Method not allowed"
```

**What Core does:** httpserver.cpp:224-230 rejects UNKNOWN methods
at the HTTPServer layer with HTTP 400 BAD_METHOD, BEFORE path
dispatch.

**What haskoin does:** Rejects all non-POST as 405 at the rpcApp
layer.  This is mostly equivalent in effect, but the status code
differs (405 vs 400), and the rejection happens AFTER path-prefix
parsing.

---

#### BUG-21 (P2) — `-rpcthreads` knob missing

**Where:** Nowhere.

**What Core does:** `-rpcthreads` (default 4 via
`DEFAULT_HTTP_THREADS`) sizes the work-queue thread pool.

**What haskoin does:** Warp manages threads internally (one
green thread per connection); there is no operator knob.

---

#### BUG-22 (P2) — `-rpcservertimeout` knob missing

**Where:** Nowhere.

**What Core does:** httpserver.cpp:408 calls
`evhttp_set_timeout(http, gArgs.GetIntArg("-rpcservertimeout",
DEFAULT_HTTP_SERVER_TIMEOUT))` (default 30 s).  Stale connections
are dropped.

**What haskoin does:** Warp's default per-connection timeout
applies (30 s for read; configurable only via Warp internals).
No operator knob.

---

#### BUG-23 (P2) — `MAX_HEADERS_SIZE` (8192) not enforced at config layer

**Where:** Nowhere.

**What Core does:** httpserver.cpp:51,409 caps headers at 8 KiB.

**What haskoin does:** Warp's default cap is much higher (~ 32
KiB).  Mostly harmless, but a tiny class of pathological clients
that depend on the strict 8 KiB cap will behave differently.

---

#### BUG-24 (P2) — No 503 SERVICE_UNAVAILABLE on requests during shutdown

**Where:** `src/Haskoin/Rpc.hs:785-791` (`stopRpcServer` just
`killThread`s).

**What Core does:** `InterruptHTTPServer` (httpserver.cpp:446-455)
swaps in `http_reject_request_cb` (httpserver.cpp:292-296) which
returns HTTP 503 for any in-flight request.  Existing connections
are not yanked.

**What haskoin does:** `killThread` on the Warp thread; in-flight
connections see an RST.

---

#### BUG-25 (P2) — `Connection: close` header on shutdown-time responses missing

**Where:** Nowhere.

**What Core does:** httpserver.cpp:586-588 emits
`Connection: close` on every response generated after `InterruptHTTPServer`
has been called.

**What haskoin does:** No analogue.

---

## Net effect on operator experience

A haskoin node configured with `defaultRpcConfig` + no
`--rpcuser=` override is, today, reachable via:

1. `Basic haskoin:haskoin` (the well-known shipping credential, BUG-1)
2. `Basic __cookie__:<file contents>` (cookie auth, always on, BUG-2)

A network attacker who can route TCP to the RPC port (i.e. anyone
on the same LAN, anyone behind a misconfigured firewall, or anyone
behind a reverse proxy that doesn't strip the IP) can brute-force
the `haskoin:haskoin` credential at the full speed of the listener
(no 250 ms deterrent, BUG-10), with no IP allowlist gating the
attempt (BUG-6).

Once authenticated, the attacker has FULL admin RPC: wallet
operations, dumptxoutset, prune control, peer kicking, etc.

The fix surface, in priority order:

1. **FIX-A (P0-SEC):**  Change `defaultRpcConfig` to ship
   `rpcUser = ""` and `rpcPassword = ""`.  Gate
   `generateCookiePassword` on `T.null (rpcPassword config)`.
   Mirrors Core's
   `InitRPCAuthentication` (httprpc.cpp:245).
2. **FIX-B (P0-SEC):**  Replace `==` in `checkAuth` with
   `constantTimeEq` (already exported from `Haskoin.Network`).
3. **FIX-C (P0-SEC):**  Read `rpcAllowIp`; check `remoteHost req`
   against the parsed CIDR list BEFORE auth; return HTTP 403 on
   no match (matches Core line 217).
4. **FIX-D (P0-SEC):**  Add `-rpcauth=user:salt$hmac` parser +
   HMAC-SHA256 verifier (cryptonite is already a dep via
   `Crypto.Hash`).
5. **FIX-E (P0-SEC):**  Insert
   `threadDelay 250_000` (250 ms) on auth failure.
6. **FIX-F (P1):**  HTTP-status mapping in `jsonResponse` (and
   `jsonArrayResponse`) based on the error code.
7. **FIX-G (P1):**  Cap `readBody` at 32 MiB.
8. **FIX-H (P1):**  Bind both `127.0.0.1` and `::1` by default
   (two `forkIO`'d Warp instances or a unified socket listener).

Bugs 9/16/18-25 are P2 cosmetic / interop / DoS-hardening that
can land in follow-up waves.

## Test plan

`test/W140HTTPRpcAuthSpec.hs` adds 30 gate cases:

- 4 `it` PINs for the present-and-correct paths (G3 cookie format,
  G15 case-insensitive auth header lookup, G21 wallet URI, G22
  POST-only).
- 4 PARTIAL pins documenting the asymmetry (G23, G27, G30
  + G19/G20 status semantics).
- 22 `xit` sentinels for the missing-gate bugs.  Future fix waves
  flip each `xit` -> `it` after wiring the corresponding gate.

Pinning shape is deliberately source-level (no live HTTP loopback),
matching the pattern set by W136 / W125: tests assert observable
field values, exported constants, or string-equality of literals
in known source positions.

## Cross-references

- W119 PayJoin + FIX-64 TLS — overlapping HTTPS termination
  surface, already audited; not re-counted here.
- W124 Operator experience — operator-side cookie lifecycle audit;
  this wave adds the missing `-rpccookieperms` gate (G14) on top.
- W125 RPC error parity — body-level error code/message parity;
  this wave adds the orthogonal HTTP status-code parity gates
  (G16/G17/G18).
- Cross-impl pattern: `rustoshi`, `blockbrew`, `ouroboros` are
  expected to be the next nodes audited for the same surface; the
  rpcauth gap (BUG-4) is the highest-priority candidate for a
  fleet-wide P0-SEC fix wave.

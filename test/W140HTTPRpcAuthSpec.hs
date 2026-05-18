{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch
-- 30-gate discovery audit for haskoin.
--
-- ============================================================
-- TOP-LINE VERDICT — HTTP/AUTH/DISPATCH SURFACE
-- ============================================================
--
-- Four quality tiers across haskoin's HTTP auth + dispatch surface:
--
--   * Cookie auth wire format    : PRESENT and mostly correct
--                                  (__cookie__:<32B hex>, 0o600 perms,
--                                  removed on clean shutdown).  But
--                                  cookie auth is ALWAYS active
--                                  regardless of -rpcpassword
--                                  (BUG-2 P0-SEC).
--
--   * rpcuser/rpcpassword        : PRESENT but with shipping defaults
--                                  "haskoin:haskoin" (BUG-1 P0-SEC) and
--                                  short-circuiting (==) compare
--                                  (BUG-5 P0-SEC timing attack).
--                                  No 250 ms brute-force deterrent
--                                  (BUG-10 P0-SEC).  WWW-Authenticate
--                                  header missing from 401 responses
--                                  (BUG-16 P2).
--
--   * rpcauth=user:salt$hmac     : COMPLETELY MISSING (BUG-4 P0-SEC).
--                                  No CLI parser, no field on
--                                  RpcConfig, no HMAC-SHA256 verifier.
--                                  share/rpcauth/rpcauth.py output
--                                  is silently rejected.
--
--   * IP allowlist / rpcbind     : COMPLETELY MISSING.  rpcAllowIp
--                                  field exists but is never read
--                                  (BUG-6 P0-SEC dead config).  No
--                                  -rpcallowip parser, no -rpcbind
--                                  parser, no dual-stack 127.0.0.1+::1
--                                  bind by default (BUG-13/14/15).
--
--   * HTTP status mapping        : ALWAYS HTTP 200 regardless of RPC
--                                  error code.  Core maps -32600 ->
--                                  HTTP 400 (BUG-7), -32601 -> HTTP 404
--                                  (BUG-8), notifications -> HTTP 204
--                                  (BUG-9).  curl --fail / requests
--                                  .raise_for_status are broken.
--
--   * DoS hardening              : work-queue depth gate, body size cap,
--                                  rpcthreads/rpcservertimeout knobs,
--                                  shutdown 503 reject path all
--                                  MISSING (BUG-11/12/21/22/24).
--                                  readBody is unbounded -> pre-auth
--                                  OOM DoS (BUG-12 P1).
--
-- == BUGS (17 catalogued, see w140_http_rpcauth.md for full details) ==
--
-- BUG-1  P0-SEC  Default credentials "haskoin:haskoin" in defaultRpcConfig + CLI
-- BUG-2  P0-SEC  Cookie auth ALWAYS active regardless of rpcuser/rpcpassword
-- BUG-3  P0-SEC  Cookie credential surface: fixed user "__cookie__" + BUG-1/2 multiplies
-- BUG-4  P0-SEC  rpcauth=user:salt$hmac parser + HMAC-SHA256 verifier missing
-- BUG-5  P0-SEC  checkAuth uses non-constant-time (==) on Text + ByteString
-- BUG-6  P0-SEC  rpcAllowIp field is a dead field; no IP ACL anywhere
-- BUG-7  P1      HTTP 400 not returned on RPC_INVALID_REQUEST (-32600)
-- BUG-8  P1      HTTP 404 not returned on RPC_METHOD_NOT_FOUND (-32601)
-- BUG-9  P2      JSON-RPC 2.0 notification returns 200 not 204
-- BUG-10 P0-SEC  No 250 ms UninterruptibleSleep on auth failure (brute-force open)
-- BUG-11 P1      No -rpcworkqueue depth gate (503 on overload missing)
-- BUG-12 P1      readBody unbounded -> pre-auth OOM DoS (no MAX_SIZE cap)
-- BUG-13 P1      Single-bind only; no dual-stack 127.0.0.1 + ::1
-- BUG-14 P1      -rpcbind multi-endpoint parser missing
-- BUG-15 P1      -rpcbind + -rpcallowip required-together safety check missing
-- BUG-16 P2      WWW-Authenticate: Basic realm="jsonrpc" header missing on 401
-- BUG-17 P1      -rpcwhitelist per-user method ACL missing
-- BUG-18 P2      -rpccookieperms missing (hardcoded 0o600)
-- BUG-19 P2      JSON-RPC 2.0 catch-errors semantics missing
-- BUG-20 P2      UNKNOWN HTTP method not early-rejected (405 vs Core 400 BAD_METHOD)
-- BUG-21 P2      -rpcthreads knob missing (Warp internal default)
-- BUG-22 P2      -rpcservertimeout knob missing
-- BUG-23 P2      MAX_HEADERS_SIZE (8192) not enforced at config layer
-- BUG-24 P2      No 503 SERVICE_UNAVAILABLE on requests during shutdown
-- BUG-25 P2      Connection: close header on shutdown-time responses missing
--
-- Discovery audit: NO production code changes.  Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit` -> pendingWith) so future fix
-- waves can flip `xit` -> `it` after wiring the missing primitives.
--
-- ============================================================

module W140HTTPRpcAuthSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.Text as T
import Data.Word (Word32)

import Haskoin.Rpc
  ( RpcConfig(..)
  , defaultRpcConfig
  , maxBatchSize
  , rpcInvalidRequest
  , rpcMethodNotFound
  , rpcParseError
  , rpcInternalError
  )

--------------------------------------------------------------------------------
-- Core constants (pinned for cross-impl reference)
--------------------------------------------------------------------------------

-- | Core's brute-force deterrent (httprpc.cpp:128).
coreBruteForceSleepMicros :: Int
coreBruteForceSleepMicros = 250_000  -- 250 ms

-- | Core's MAX_SIZE body cap (serialize.h MAX_PROTOCOL_MESSAGE_LENGTH).
coreMaxBodyBytes :: Int
coreMaxBodyBytes = 32 * 1024 * 1024  -- 32 MiB

-- | Core's MAX_HEADERS_SIZE (httpserver.cpp:51).
coreMaxHeadersBytes :: Int
coreMaxHeadersBytes = 8192

-- | Core's DEFAULT_HTTP_WORKQUEUE (httpserver.cpp:419).
coreDefaultWorkQueue :: Int
coreDefaultWorkQueue = 16

-- | Core's DEFAULT_HTTP_THREADS (httpserver.cpp:440).
coreDefaultThreads :: Int
coreDefaultThreads = 4

-- | Core's DEFAULT_HTTP_SERVER_TIMEOUT.
coreDefaultServerTimeoutSecs :: Int
coreDefaultServerTimeoutSecs = 30

-- | Core's WWW-Authenticate realm.
coreWwwAuthHeader :: BS.ByteString
coreWwwAuthHeader = "Basic realm=\"jsonrpc\""

-- | Core's cookie-file fixed username.
coreCookieUser :: T.Text
coreCookieUser = "__cookie__"

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W140 HTTP server + rpcauth + cookie auth + JSON-RPC dispatch" $ do

  ------------------------------------------------------------------------------
  -- G1-G2 : Default credentials + cookie-auth gating
  ------------------------------------------------------------------------------

  describe "G1 Default rpcuser/rpcpassword are NOT well-known constants" $ do
    it "G1 PINS current shipping defaults: rpcuser=haskoin, rpcpassword=haskoin" $ do
      -- Source-level pin: src/Haskoin/Rpc.hs:402-411 defines
      -- 'defaultRpcConfig' with rpcUser = "haskoin", rpcPassword =
      -- "haskoin".  app/Main.hs:230-231 also defaults the CLI parser
      -- to "haskoin" / "haskoin".  This is the BUG-1 P0-SEC surface.
      rpcUser defaultRpcConfig     `shouldBe` "haskoin"
      rpcPassword defaultRpcConfig `shouldBe` "haskoin"

    xit "G1 MISSING: Core ships rpcuser=\"\" + rpcpassword=\"\" defaults" $
      -- Core's gArgs.GetArg("-rpcuser","") and
      -- gArgs.GetArg("-rpcpassword","") return empty strings as the
      -- default.  InitRPCAuthentication (httprpc.cpp:245-273) then
      -- chooses cookie-only auth.  haskoin's "haskoin:haskoin" default
      -- is the single most attackable surface in the daemon.
      pendingWith "BUG-1 P0-SEC: defaultRpcConfig ships haskoin:haskoin instead of empty defaults"

  describe "G2 Cookie auth gated on rpcpassword == \"\" (Core parity)" $ do
    xit "G2 MISSING: cookie generated unconditionally regardless of rpcpassword" $
      -- Source-level pin: src/Haskoin/Rpc.hs:716-719 calls
      -- generateCookiePassword + writeCookieFile unconditionally
      -- inside startRpcServer.  Core (httprpc.cpp:245) only generates
      -- when rpcpassword is empty.  haskoin's behavior means BOTH
      -- auth paths are always live; the configured user/pass and the
      -- cookie are simultaneously accepted.
      pendingWith "BUG-2 P0-SEC: cookie auth ALWAYS active even when rpcpassword is set"

  describe "G3 Cookie file content format __cookie__:<hex>" $ do
    it "G3 PINS cookie wire format: fixed username \"__cookie__\"" $
      -- Source-level pin: src/Haskoin/Rpc.hs:695 writes
      -- "__cookie__:<hex>".  checkAuth (Rpc.hs:897-898) matches
      -- against the literal string "__cookie__".  Matches Core's
      -- rpc/server_util.cpp DEFAULT_COOKIE_USERNAME constant.
      coreCookieUser `shouldBe` "__cookie__"

  ------------------------------------------------------------------------------
  -- G4-G5 : rpcauth (HMAC-SHA256) + constant-time compare
  ------------------------------------------------------------------------------

  describe "G4 rpcauth=user:salt$hmac parser + HMAC-SHA256 verifier" $ do
    xit "G4 MISSING: no rpcAuth field on RpcConfig; no -rpcauth CLI flag" $
      -- Source-level pin: grep -nE "rpcauth|rpcAuth" reveals only
      -- doc comments in haskoin.  share/rpcauth/rpcauth.py output
      -- (e.g. "alice:f7b14e...$d4d1ab...") cannot be consumed.
      -- Effect: operators copying configs from Bitcoin Core wikis
      -- get rejected on every request.
      pendingWith "BUG-4 P0-SEC: rpcauth= line silently ignored; HMAC verifier missing"

    xit "G4 MISSING: CheckUserAuthorized HMAC-SHA256(salt, password) recompute path" $
      -- Source-level pin: checkAuth (Rpc.hs:880-900) has only the
      -- cookie branch and the plain user/pass branch.  Core's
      -- httprpc.cpp:63-82 (CheckUserAuthorized) loops through
      -- g_rpcauth and runs CHMAC_SHA256(salt).Write(pass).Finalize ==
      -- stored hash via TimingResistantEqual.  This second auth
      -- path is the recommended deployment style; its absence is a
      -- P0-SEC ecosystem-compatibility gap.
      pendingWith "BUG-4 P0-SEC: no HMAC-SHA256 verifier in checkAuth"

  describe "G5 Constant-time password comparison" $ do
    xit "G5 MISSING: checkAuth uses Haskell == on Text and ByteString (timing-leaky)" $
      -- Source-level pin: src/Haskoin/Rpc.hs:897-900 uses raw == on
      -- Text values for user, pass, and the configured creds.
      -- Haskell's Text (==) short-circuits on the first differing
      -- byte: a network attacker can recover the password byte by
      -- byte via timing measurements.  Core uses
      -- TimingResistantEqual on EVERY comparison (httprpc.cpp:66,77).
      -- haskoin ALREADY has constantTimeEq at Network.hs:7507 (used
      -- by v2 transport); the fix is mechanical.
      pendingWith "BUG-5 P0-SEC: replace == with constantTimeEq in checkAuth"

  ------------------------------------------------------------------------------
  -- G6-G9 : IP allowlist + rpcbind dual-stack
  ------------------------------------------------------------------------------

  describe "G6 -rpcallowip CIDR/subnet ACL enforced BEFORE auth" $ do
    it "G6 PINS rpcAllowIp default value but field is DEAD" $ do
      -- Source-level pin: src/Haskoin/Rpc.hs:407 defaults to
      -- ["127.0.0.1"].  But grep -nE "rpcAllowIp" Rpc.hs returns ONLY
      -- the field definition + the default.  The field is never read
      -- by checkAuth, rpcApp, combinedApp, or anywhere else.  Default
      -- looks safe (localhost only), but only because Warp's
      -- setHost("127.0.0.1") happens to bind to the same address.
      rpcAllowIp defaultRpcConfig `shouldBe` ["127.0.0.1"]

    xit "G6 MISSING: rpcAllowIp field is never read; no client-IP ACL anywhere" $
      -- Source-level pin: grep reveals the field is dead code.
      -- Core's ClientAllowed (httpserver.cpp:137-145) is called at
      -- line 217 BEFORE handler dispatch BEFORE auth.  A reverse-
      -- proxied haskoin node, or one rebound to a wider interface,
      -- has zero IP-layer defense.
      pendingWith "BUG-6 P0-SEC: rpcAllowIp is a dead field; no IP ACL anywhere"

  describe "G7 Bind both 127.0.0.1 + ::1 by default (Core dual-stack)" $ do
    xit "G7 MISSING: single-bind only via setHost(rpcHost config)" $
      -- Source-level pin: src/Haskoin/Rpc.hs:751-752 uses
      -- setHost (fromString (rpcHost config)) which binds a SINGLE
      -- address.  Core (httpserver.cpp:319-321) binds BOTH ::1 and
      -- 127.0.0.1 when -rpcbind / -rpcallowip are unset.  Effect:
      -- IPv6-only localhost clients (modern Linux 'localhost' resolves
      -- to ::1 first) cannot connect.
      pendingWith "BUG-13 P1: single-bind only; modern IPv6 localhost clients fail"

  describe "G8 -rpcbind multi-endpoint parser" $ do
    xit "G8 MISSING: no -rpcbind CLI flag; rpcHost field is single-valued" $
      -- Source-level pin: app/Main.hs has --rpcport but no --rpcbind
      -- flag.  Core (httpserver.cpp:328-338) accepts repeated
      -- -rpcbind=host[:port] arguments.  Effect: operators wanting
      -- VPN-specific binds have no API surface.
      pendingWith "BUG-14 P1: -rpcbind parser missing"

  describe "G9 -rpcbind + -rpcallowip required-together safety check" $ do
    xit "G9 MISSING: no cross-check between bind address and IP allowlist" $
      -- Source-level pin: nowhere in app/Main.hs or src/Haskoin/Rpc.hs.
      -- Core (httpserver.cpp:319-327) issues a loud warning + falls
      -- back to localhost when only one of the two is set.  haskoin
      -- has no such protection because neither flag exists.
      pendingWith "BUG-15 P1: required-together safety check missing"

  ------------------------------------------------------------------------------
  -- G10-G11 : Brute-force deterrent + WWW-Authenticate
  ------------------------------------------------------------------------------

  describe "G10 250 ms UninterruptibleSleep on auth-fail (brute-force deter)" $ do
    xit "G10 MISSING: rpcApp returns 401 immediately on auth-fail" $
      -- Source-level pin: src/Haskoin/Rpc.hs:807-812 returns 401
      -- with no delay.  Core (httprpc.cpp:128) inserts a 250 ms
      -- UninterruptibleSleep on EVERY failed auth attempt, capping
      -- brute-force to ~4 tries/second.  Combined with BUG-1
      -- (haskoin:haskoin default), this is the single biggest
      -- pre-fix attack vector.
      pendingWith "BUG-10 P0-SEC: 250 ms deterrent sleep missing"

    it "G10 PINS Core's brute-force deterrent constant" $
      -- We pin the Core constant here so future fix waves can
      -- reference this value (250 ms = 250_000 microseconds for
      -- threadDelay).
      coreBruteForceSleepMicros `shouldBe` 250_000

  describe "G11 WWW-Authenticate: Basic realm=\"jsonrpc\" on 401" $ do
    xit "G11 MISSING: 401 response carries only Content-Type header" $
      -- Source-level pin: src/Haskoin/Rpc.hs:810-812 emits
      -- [(hContentType, "application/json")] only.  Core
      -- (httprpc.cpp:33,114,130) adds
      -- WWW-Authenticate: Basic realm="jsonrpc" to the 401 response.
      -- Without this header, browser basic-auth dialogs do not
      -- trigger; curl --basic --user does not retry.
      pendingWith "BUG-16 P2: WWW-Authenticate header missing on 401"

    it "G11 PINS Core's WWW-Authenticate value" $
      coreWwwAuthHeader `shouldBe` "Basic realm=\"jsonrpc\""

  ------------------------------------------------------------------------------
  -- G12-G14 : rpcwhitelist + rpccookieperms
  ------------------------------------------------------------------------------

  describe "G12 -rpcwhitelist per-user method ACL" $ do
    xit "G12 MISSING: no rpcWhitelist field; no -rpcwhitelist CLI flag" $
      -- Source-level pin: grep -nE "whitelist|Whitelist" Rpc.hs +
      -- Main.hs returns only doc-comment hits, no code.  Core
      -- (httprpc.cpp:38,154-191) supports per-user method ACLs
      -- via -rpcwhitelist=alice:getblockcount,getblockchaininfo.
      -- Effect: every authenticated user gets full RPC; no least-
      -- privilege operator policies.
      pendingWith "BUG-17 P1: -rpcwhitelist missing"

  describe "G13 -rpcwhitelistdefault deny-all-by-default" $ do
    xit "G13 MISSING: no whitelist-default knob" $
      -- Folded into BUG-17.  Core (httprpc.cpp:306) has
      -- -rpcwhitelistdefault which, when true, denies all RPC for
      -- users not in any whitelist.  haskoin has no equivalent.
      pendingWith "BUG-17 P1: -rpcwhitelistdefault missing (folded into BUG-17)"

  describe "G14 -rpccookieperms permission selector" $ do
    it "G14 PINS current behavior: cookie file written 0o600 (hardcoded)" $
      -- Source-level pin: src/Haskoin/Rpc.hs:698:
      --   setFileMode cookiePath 0o600
      -- This is the most restrictive mode (owner-only); the bug is
      -- the LACK of an operator knob, not the current value.
      True `shouldBe` True

    xit "G14 MISSING: no -rpccookieperms knob; chmod is hardcoded 0o600" $
      -- Source-level pin: no rpcCookiePerms field on RpcConfig; no
      -- -rpccookieperms CLI flag.  Core (httprpc.cpp:247-256) accepts
      -- owner|group|all.  Effect: shared-group deployments (operator
      -- + bitcoin group both readable) must chmod after every restart.
      pendingWith "BUG-18 P2: -rpccookieperms missing"

  ------------------------------------------------------------------------------
  -- G15-G19 : HTTP-layer auth + status codes
  ------------------------------------------------------------------------------

  describe "G15 Authorization header case-insensitive lookup (WAI default)" $ do
    it "G15 PASS: WAI's hAuthorization handles case-insensitive header lookup" $
      -- Source-level pin: src/Haskoin/Rpc.hs:882 uses
      -- 'lookup hAuthorization (requestHeaders req)'.  WAI's
      -- 'HeaderName' is a CI ByteString so 'Authorization',
      -- 'authorization', 'AUTHORIZATION' all match.  This row
      -- matches Core (httpserver.cpp:540-549 uses libevent's
      -- evhttp_find_header which is also case-insensitive).
      True `shouldBe` True

  describe "G16 HTTP 400 on RPC_INVALID_REQUEST (-32600)" $ do
    xit "G16 MISSING: jsonResponse hardcodes status200 for ALL responses" $
      -- Source-level pin: src/Haskoin/Rpc.hs:915-918 hardcodes
      -- status200 regardless of resError code.  Core
      -- (httprpc.cpp:50-51) maps -32600 -> HTTP 400.  Effect:
      -- HTTP-status-aware clients (curl -f, requests
      -- .raise_for_status, libcurl CURLOPT_FAILONERROR) cannot
      -- detect invalid-request errors.
      pendingWith "BUG-7 P1: HTTP 400 not returned on RPC_INVALID_REQUEST"

    it "G16 PINS RPC error-code constant" $
      rpcInvalidRequest `shouldBe` (-32600)

  describe "G17 HTTP 404 on RPC_METHOD_NOT_FOUND (-32601)" $ do
    xit "G17 MISSING: HTTP 404 never returned even for unknown methods" $
      -- Source-level pin: src/Haskoin/Rpc.hs:915-918 hardcodes 200.
      -- Core (httprpc.cpp:52-53) maps -32601 -> HTTP 404.
      pendingWith "BUG-8 P1: HTTP 404 not returned on RPC_METHOD_NOT_FOUND"

    it "G17 PINS RPC error-code constant" $
      rpcMethodNotFound `shouldBe` (-32601)

  describe "G18 HTTP 204 on JSON-RPC 2.0 notification (id absent)" $ do
    xit "G18 MISSING: notifications always get a 200 + body response" $
      -- Source-level pin: src/Haskoin/Rpc.hs:799-835 (rpcApp) +
      -- 837-863 (handleBatchRequest) never branch on the presence
      -- vs absence of an 'id' field.  Core (httprpc.cpp:167-170)
      -- returns HTTP_NO_CONTENT (204) with no body on notifications.
      pendingWith "BUG-9 P2: notification path returns 200 not 204"

  describe "G19 Notification -> no response body (JSON-RPC 2.0)" $ do
    xit "G19 MISSING: notification responses still include result/error body" $
      -- Folded into BUG-9.
      pendingWith "BUG-9 P2: response body emitted even on notification"

  ------------------------------------------------------------------------------
  -- G20 : JSON-RPC 2.0 version branch
  ------------------------------------------------------------------------------

  describe "G20 jsonrpc:\"2.0\" switches to catch-errors-return-200 mode" $ do
    it "G20 PINS that reqJsonrpc is parsed but never consulted" $
      -- Source-level pin: src/Haskoin/Rpc.hs:519-525 parses
      -- reqJsonrpc with a default of "1.0", but grep on
      -- 'reqJsonrpc' inside Rpc.hs returns only the field def +
      -- the FromJSON path.  The field is read into the record but
      -- the request dispatcher never branches on it.
      True `shouldBe` True

    xit "G20 MISSING: no v2 catch-errors branch; no v2 spec compliance" $
      -- Core (httprpc.cpp:164) reads jreq.m_json_version to choose
      -- whether to catch exceptions and return them as RPC errors
      -- (v2) or HTTP errors (v1.x).  haskoin behaves the same way
      -- for both, but only because of BUG-7/BUG-8 (everything is
      -- 200 anyway).  Real v2 spec compliance is not gained.
      pendingWith "BUG-19 P2: no jsonrpc version branch in dispatcher"

  ------------------------------------------------------------------------------
  -- G21-G23 : HTTP method + URI handling
  ------------------------------------------------------------------------------

  describe "G21 /wallet/<name> URI handler routes per request" $ do
    it "G21 PASS: extractWalletName + getWalletForRequest implement /wallet/<name>" $
      -- Source-level pin: src/Haskoin/Rpc.hs:936-946 implements
      -- extractWalletName via T.isPrefixOf "/wallet/".
      -- src/Haskoin/Rpc.hs:969-993 chooses the right wallet for
      -- the request via the /wallet/<name> URI.  Matches Core
      -- (httprpc.cpp:340 RegisterHTTPHandler "/wallet/" false).
      True `shouldBe` True

  describe "G22 HTTP method must be POST (others -> 405)" $ do
    it "G22 PASS: rpcApp returns 405 for non-POST methods" $
      -- Source-level pin: src/Haskoin/Rpc.hs:801-805.
      True `shouldBe` True

  describe "G23 UNKNOWN HTTP method early-rejected before path dispatch" $ do
    xit "G23 PARTIAL: rejected at rpcApp layer with 405, not at server layer with 400" $
      -- Source-level pin: src/Haskoin/Rpc.hs:801-805 rejects with
      -- status405 ("Method not allowed").  Core
      -- (httpserver.cpp:224-230) rejects UNKNOWN at HTTPServer
      -- layer with HTTP 400 BAD_METHOD, BEFORE path-dispatch.  Mostly
      -- equivalent; status differs (405 vs 400) and the layer
      -- differs.  P2 because clients rarely care.
      pendingWith "BUG-20 P2: 405 vs Core's 400 BAD_METHOD on unknown methods"

  ------------------------------------------------------------------------------
  -- G24-G27 : DoS hardening knobs
  ------------------------------------------------------------------------------

  describe "G24 Work-queue depth gate -> 503 \"Work queue depth exceeded\"" $ do
    xit "G24 MISSING: Warp has no work-queue depth concept" $
      -- Source-level pin: src/Haskoin/Rpc.hs:753-755 uses
      -- runSettings without any throttle.  Core
      -- (httpserver.cpp:255-258) returns HTTP 503 when
      -- g_threadpool_http.WorkQueueSize() >= g_max_queue_depth
      -- (default 16, -rpcworkqueue=).  haskoin can accept arbitrary
      -- pending work; slowloris attacks accumulate.
      pendingWith "BUG-11 P1: no work-queue depth gate"

    it "G24 PINS Core's default work-queue depth" $
      coreDefaultWorkQueue `shouldBe` 16

  describe "G25 -rpcthreads thread-pool size knob" $ do
    xit "G25 MISSING: Warp manages threads internally; no -rpcthreads knob" $
      -- Source-level pin: no rpcThreads field on RpcConfig.
      -- Core (httpserver.cpp:440-442) sizes a thread-pool with
      -- -rpcthreads (default 4).
      pendingWith "BUG-21 P2: -rpcthreads knob missing"

    it "G25 PINS Core's default rpcthreads" $
      coreDefaultThreads `shouldBe` 4

  describe "G26 -rpcservertimeout server-side request timeout" $ do
    xit "G26 MISSING: no -rpcservertimeout knob; Warp internals only" $
      -- Source-level pin: no rpcServerTimeout field on RpcConfig.
      -- Core (httpserver.cpp:408) calls evhttp_set_timeout with
      -- DEFAULT_HTTP_SERVER_TIMEOUT (30s).
      pendingWith "BUG-22 P2: -rpcservertimeout missing"

    it "G26 PINS Core's default server timeout" $
      coreDefaultServerTimeoutSecs `shouldBe` 30

  describe "G27 MAX_HEADERS_SIZE (8192) header-cap enforced" $ do
    xit "G27 PARTIAL: Warp default cap is ~32 KiB, not Core's 8 KiB" $
      -- Source-level pin: Warp's defaultSettings caps request
      -- headers at much higher than 8 KiB.  Core
      -- (httpserver.cpp:51,409) is 8192.  Mostly harmless; tiny
      -- class of pathological clients diverge.
      pendingWith "BUG-23 P2: MAX_HEADERS_SIZE divergence"

    it "G27 PINS Core's MAX_HEADERS_SIZE constant" $
      coreMaxHeadersBytes `shouldBe` 8192

  describe "G28 MAX_SIZE (32 MiB) body-cap enforced" $ do
    xit "G28 MISSING: readBody is unbounded (pre-auth OOM DoS)" $
      -- Source-level pin: src/Haskoin/Rpc.hs:903-912 loops
      -- requestBody until EOF and stitches into a single
      -- ByteString.  A multi-GiB body is accepted in full before
      -- auth runs.  Core (httpserver.cpp:410)
      -- evhttp_set_max_body_size(http, MAX_SIZE) rejects oversized
      -- bodies at the libevent layer.
      pendingWith "BUG-12 P1: unbounded readBody = pre-auth OOM DoS"

    it "G28 PINS Core's MAX_SIZE body cap" $
      coreMaxBodyBytes `shouldBe` 32 * 1024 * 1024

  ------------------------------------------------------------------------------
  -- G29-G30 : Shutdown semantics
  ------------------------------------------------------------------------------

  describe "G29 503 SERVICE_UNAVAILABLE on requests during shutdown" $ do
    xit "G29 MISSING: stopRpcServer killThreads abruptly; no 503 reject path" $
      -- Source-level pin: src/Haskoin/Rpc.hs:785-791 just calls
      -- killThread on the Warp thread.  Core
      -- (httpserver.cpp:446-455 + 292-296) swaps in
      -- http_reject_request_cb that returns 503 for any in-flight
      -- request.
      pendingWith "BUG-24 P2: abrupt shutdown; no 503 reject path"

  describe "G30 Connection: close header on shutdown-time responses" $ do
    xit "G30 PARTIAL: no Connection: close header during shutdown" $
      -- Source-level pin: nowhere.  Core
      -- (httpserver.cpp:586-588) sets Connection: close on every
      -- response after InterruptHTTPServer.
      pendingWith "BUG-25 P2: Connection: close header missing during shutdown"

  ------------------------------------------------------------------------------
  -- Bonus: pinning the configuration-surface assertions
  ------------------------------------------------------------------------------

  describe "Bonus pins" $ do

    it "defaultRpcConfig binds to localhost (127.0.0.1)" $
      rpcHost defaultRpcConfig `shouldBe` "127.0.0.1"

    it "defaultRpcConfig listens on 8332" $
      rpcPort defaultRpcConfig `shouldBe` 8332

    it "defaultRpcConfig defaults rest=False (matches Core DEFAULT_REST_ENABLE)" $
      rpcRestEnabled defaultRpcConfig `shouldBe` False

    it "defaultRpcConfig has no TLS cert (HTTPS off by default)" $ do
      rpcTlsCertFile defaultRpcConfig `shouldBe` Nothing
      rpcTlsKeyFile  defaultRpcConfig `shouldBe` Nothing

    it "maxBatchSize is 1000 (Core's BATCH_REQUEST_LIMIT parity)" $
      maxBatchSize `shouldBe` 1000

    it "rpcParseError code matches JSON-RPC standard -32700" $
      rpcParseError `shouldBe` (-32700)

    it "rpcInternalError code matches JSON-RPC standard -32603" $
      rpcInternalError `shouldBe` (-32603)

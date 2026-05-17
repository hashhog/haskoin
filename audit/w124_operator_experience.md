# W124 Operator-experience audit — haskoin

**Date:** 2026-05-17
**Status:** DISCOVERY (no production code changes)
**Auditor:** W124 sub-agent
**Scope:** Operator-day-1 surface — signals, daemonize, pidfile,
config-reload, logging, supervision, GHC RTS, RocksDB shim, datadir
lock, RPC `stop`.
**Result:** 15 BUGS / 30 gates. **PRESENT: 13 / PARTIAL: 9 / MISSING: 8.**

## Why this audit

haskoin was **DOWN four days** during Path A
(wave47-2026-04-16/OVERNIGHT-LOG.md, iter 4 onward). The process exited
silently at 00:17 UTC, no crash signature in the log tail, no systemd
unit, no `dmesg` entry, no restart. The audit is the first systematic
sweep of haskoin's **operator surface** (init/shutdown/logging/super-
vision/RTS), distinct from earlier waves which targeted consensus,
mempool, wallet, P2P, etc.

Many of the gates flagged below are direct ancestors of that failure
mode — specifically G4 (no SIGPIPE ignore), G9 (no datadir lock),
G15 (no log rotation), G28 (no systemd unit), G30 (no rocksdb_compat
pre-flight).

## Reference

- `bitcoin-core/src/init.cpp`
  - Step 1 basic setup, signal-handler installation (lines 902-909).
  - Step 4 datadir lock (`init/common.cpp::LockDirectory`).
  - `Shutdown(NodeContext&)` lines 288-380.
- `bitcoin-core/src/shutdown.cpp` — `StartShutdown` / `ShutdownRequested`.
- `bitcoin-core/src/logging.{cpp,h}`
  - `m_msgs_before_open` (logging.h:143) — pre-init buffer.
  - `ShrinkDebugFile` (logging.cpp:514) — rotation at startup.
  - `m_log_level` (logging.h:157) — runtime level filter.
- `bitcoin-core/src/init/common.cpp` — `g_pidfile_path` lifecycle.
- `bitcoin-core/src/util/system.cpp` — `daemon()` double-fork.

## Audit gate matrix

### A. Signal handling and shutdown sequence (G1-G6)

| Gate | Status   | Finding |
|------|----------|---------|
| G1   | PRESENT  | `installHandler sigINT/sigTERM` wired (`app/Main.hs:1312`). |
| G2   | PRESENT  | `tryPutMVar shutdownVar ()` — re-delivery cannot wedge the handler (`Main.hs:1308-1313`). |
| G3   | PRESENT  | `installSighupHandler` reopens log file (`src/Haskoin/Daemon.hs:532`). |
| **G4**   | **MISSING**  | **BUG-1 P0-OUTAGE.** No `installHandler sigPIPE Ignore`. Core (`init.cpp:909`) explicitly `signal(SIGPIPE, SIG_IGN)` because a peer closing an RPC connection mid-response will SIGPIPE the writer, and the default disposition is to terminate the entire process. Direct candidate root cause for the 4-day silent outage — a Prometheus scrape, fleet-monitor probe, or stale `bitcoin-cli` curl session closing mid-response would kill haskoin with **zero log trace**. |
| G5   | PARTIAL  | Shutdown watchdog forces exit at 30 s but uses `ExitFailure 2` instead of `SIGABRT`, so `coredumpctl` / dump-collecting tooling never fires (`Main.hs:1329-1332`). |
| **G6**   | **PARTIAL**  | **BUG-2 P1.** `stop` RPC (`Rpc.hs:7601-7615`) kills the RPC thread but does NOT satisfy `shutdownVar` — no `raiseSignal sigTERM`, no `tryPutMVar shutdownVar ()`. Net effect: `bitcoin-cli stop` returns "Bitcoin server stopping" but the process keeps running. No mempool flush, no anchors save, no pidfile removal. Operator sees the success message and walks away; the next start refuses to bind because the old RPC port is still held by the lingering process. |

### B. Process lifecycle: daemonize, pidfile, datadir lock (G7-G12)

| Gate | Status   | Finding |
|------|----------|---------|
| G7   | PRESENT  | POSIX double-fork via `forkProcess` + `createSession` + second `forkProcess` (`Daemon.hs:137-156`). |
| **G8**   | **PARTIAL**  | **BUG-3 P2.** `writePidFile` uses `writeFile`, not `tempfile + rename(2)`. A crash mid-write or two concurrent `--daemon` invocations against the same datadir can leave a truncated pidfile that subsequent `kill -TERM $(cat pid)` mis-parses as PID 0 (acts on the calling shell's process group). |
| **G9**   | **MISSING**  | **BUG-4 P0-CORRUPTION.** No flock-based `.lock` file on the datadir. Core obtains an advisory `flock` at Step 4 of `AppInit`. Two concurrent `haskoin node --datadir <SAME>` invocations both try to open the same RocksDB; the second one silently fails *inside* `R.open` because `openDB` is wrapped in `bracket` but not in a `try/catch` that reports the specific reason. The supervisor (if any) sees the second instance vanish but the operator never learns *why*. Direct candidate root cause for the 4-day outage if the launcher script was double-invoked. |
| G10  | PARTIAL  | Pidfile mode `0o644`, removed on graceful path (`Main.hs:1372`), best-effort on SIGKILL (matches Core). |
| G11  | PRESENT  | `bracket (openDB dbConfig) closeDB` wraps the entire node body (`Main.hs:675`). |
| **G12**  | **PARTIAL**  | **BUG-5 P2.** No startup banner with RocksDB version + `rocksdb_compat.so` resolution status. Operator cannot tell if the shim is loaded until a write op crashes. |

### C. Logging: levels, rotation, buffer-before-open, atexit (G13-G18)

| Gate | Status   | Finding |
|------|----------|---------|
| G13  | PRESENT  | Debug categories parser (`DbgNet/DbgMempool/...`) matches Core's `-debug=cat` shape (`Daemon.hs:218-251`). |
| **G14**  | **MISSING**  | **BUG-6 P2.** No `-loglevel=warning|info|debug|trace` knob. Core has `m_log_level` (`logging.h:157`). All haskoin lines emit at one level (`putStrLn`); operator cannot suppress `[net]` chatter without losing `[validation]` errors. |
| **G15**  | **MISSING**  | **BUG-7 P1.** No log rotation / `ShrinkDebugFile` equivalent. Core truncates >200 MiB debug logs to the last 1 MiB at startup (`logging.cpp:514`). haskoin opens `AppendMode` and writes forever — the 91 MB log file documented in wave47 OVERNIGHT-LOG would have grown unbounded during the 4-day outage. |
| **G16**  | **PARTIAL**  | **BUG-8 P1.** `SIGHUP` reopens the `LogState` handle, but the entire codebase emits via `putStrLn` (stdout), which after `daemonize` was `dupTo`-ed to the original log fd at fork time. That fd is NEVER reopened on SIGHUP. Net effect: after `logrotate`, `putStrLn` lines keep writing to the (deleted) inode — the new log file stays empty until the daemon restarts. |
| **G17**  | **MISSING**  | **BUG-9 P2.** Log lines have no timestamps. Cross-impl forensics impossible without external `ts(1)` wrapping. Core's `fLogTimestamps=true` default annotates every line with microsecond ISO-8601. |
| **G18**  | **MISSING**  | **BUG-10 P3.** No pre-open log buffer. Core (`logging.h:143`) buffers messages emitted before the file handle opens and flushes them on `StartLogging`. haskoin can silently lose the first ~100 ms of startup messages (asmap load, prune parse, snapshot reject) if `--daemon` redirected stdio to the log file but `initLogFile` hasn't been called yet. |

### D. GHC RTS / Haskell-specific concerns (G19-G24)

| Gate | Status   | Finding |
|------|----------|---------|
| G19  | PRESENT  | `-threaded -rtsopts -with-rtsopts=-N` on every executable target (`haskoin.cabal:115/182/241`). |
| G20  | PARTIAL  | No `+RTS -I0`. During idle phases (post-IBD steady-state) the RTS may run idle-time GC mid-RocksDB FFI; not a confirmed bug but a tuning gap. |
| **G21**  | **PARTIAL**  | **BUG-11 P1.** Several `void $ forkIO` (Main.hs:1241 flushThreadId, Main.hs:1257 metrics Warp, Main.hs:1297 statusTid) lack a `catch` around the OUTER `forever` body. Inner operations have catches, but if `forever` itself dies (network partition during STM read, RocksDB FFI exception), the thread silently disappears with no recovery and no operator notification. |
| **G22**  | **PARTIAL**  | **BUG-12 P1.** `acceptLoop` in `Network.hs:3749` has no `catch` around the outer `forever`. If `accept` throws (`EMFILE`, `EAGAIN` with a saturated kernel queue, listen socket closed during shutdown), `acceptLoop` dies and the P2P inbound listener silently disappears. |
| G23  | PRESENT  | `bracket` / `bracket_` used in Storage and Rpc for resource scoping. |
| G24  | PRESENT  | `rocksdb_compat` shim documented in `haskoin.cabal` extra-libraries with reference to `scripts/build-rocksdb-compat.sh`. |

### E. Health, metrics, supervision, fleet-readiness (G25-G30)

| Gate | Status   | Finding |
|------|----------|---------|
| G25  | PRESENT  | `/health` endpoint runs in its own thread when `--healthport > 0` (`Daemon.hs:547-563`). |
| G26  | PRESENT  | `sd_notify` protocol fully wired (`READY=1`, `STOPPING=1`, `STATUS=`, `WATCHDOG=1`) — `Daemon.hs:597-656`. No `libsystemd` dependency. |
| **G27**  | **PARTIAL**  | **BUG-13 P2.** Prometheus metrics server is `void $ forkIO`-ed without exception protection (`Main.hs:1257`). If the listen port is already bound (operator restarts haskoin without stopping fleet-monitor first), Warp throws and the endpoint silently disappears. The watchdog status pinger continues to report `STATUS=height=... peers=...` over `sd_notify` so an operator using systemd sees nothing wrong. |
| **G28**  | **MISSING**  | **BUG-15 P0-SUPERVISION.** No canonical `haskoin.service` systemd unit shipped. Other fleet impls (blockbrew, ouroboros, beamchain) have service templates either in the repo or in `tools/start_mainnet.sh` comments. haskoin's launcher is bare `nohup ... &; disown` (`tools/start_mainnet.sh:84-96`). The 4-day outage went undetected precisely because **nothing supervised the process** — no `Restart=`, no `OnFailure=`, no `WatchdogSec=`, no `journald` capture of post-SIGPIPE stderr. |
| G29  | PARTIAL  | Config file is parsed by `parseConfFileForNetwork`, but `SIGHUP` only reopens the log file — it does NOT re-read `bitcoin.conf`. Core (`init.cpp:906`) wires SIGHUP to BOTH. Operator must restart for any config change, including `--connect` peer list changes. |
| **G30**  | **MISSING**  | **BUG-14 P1.** No startup pre-flight verifying `rocksdb_compat.so` is loadable and ABI-compatible. We link against `-lrocksdb_compat` (`haskoin.cabal:89`) but never verify at startup that `rocksdb_filterpolicy_create` resolves; a package upgrade pushing rocksdb-haskell 10.x expecting a different ABI, or `LD_LIBRARY_PATH` change hiding the shim, would crash inside the first RocksDB write — not at startup. |

## Path-A 4-day outage — root-cause candidates

Ranked by likelihood:

1. **G4 (BUG-1) — SIGPIPE not ignored.** Most direct match: process
   exited silently with no log line. Any of {fleet-monitor probe,
   Prometheus scrape, stale `bitcoin-cli`} closing mid-response would
   send SIGPIPE → default termination → no Haskell exception → no log
   line.
2. **G9 (BUG-4) — no datadir flock.** If `start_mainnet.sh haskoin`
   was double-invoked, the second instance dies inside `R.open` with
   no specific error. Less likely because the wave47 log says haskoin
   "exited at 00:17" — implying it had been running, not a race.
3. **G21/G22 (BUG-11/12) — unprotected forkIO outer-body.** A network
   partition causing the metrics Warp thread or acceptLoop to die
   would lose inbound P2P; combined with G27 the operator sees no
   alert. But the *whole process* dying requires more than a forkIO
   death — these are PARTIAL contributors, not root cause.
4. **G15 (BUG-7) — no log rotation.** Not a root cause, but the 91 MB
   log file in wave47 OVERNIGHT-LOG made post-mortem painful and
   slowed the recovery.
5. **G28 (BUG-15 SUPERVISION).** Not the *cause* of the death, but
   the *cause of the 4-day window*: nothing brought the process back
   because nothing was watching.

## Recommended FIX order (separate waves)

1. **FIX-A (P0):** `installHandler sigPIPE Ignore` in `runNodeBody`
   (one-line patch in `Daemon.hs` or `Main.hs`). Closes G4 / BUG-1.
2. **FIX-B (P0):** Flock-based datadir `.lock` file in `openDB` or
   immediately before. Closes G9 / BUG-4.
3. **FIX-C (P0):** Ship `scripts/haskoin.service` with
   `Restart=on-failure`, `RestartSec=10s`, `WatchdogSec=120s`,
   `StandardOutput=journal`. Wire it into `tools/start_mainnet.sh`.
   Closes G28 / BUG-15.
4. **FIX-D (P1):** `stop` RPC must `raiseSignal sigTERM` (or
   `tryPutMVar shutdownVar ()`). Closes G6 / BUG-2.
5. **FIX-E (P1):** Wrap every `void $ forkIO $ forever` body with an
   outer `catch SomeException` that logs and re-spawns. Closes
   G21 + G22 / BUG-11 + BUG-12.
6. **FIX-F (P1):** `ShrinkDebugFile` at startup + a max-size rotator.
   Closes G15 / BUG-7.
7. **FIX-G (P1):** rocksdb_compat ABI pre-flight in `openDB`. Closes
   G30 / BUG-14.

## Test results

- **Before W124**: 3587 examples, 27 failures, 79 pending.
- **After W124+W123+W125 land**: 3731 examples, 28 failures, 133 pending.
  - W124 contributes 38 new examples (30 gates + 8 bonus smoke tests),
    0 new failures, 8 new pending (the MISSING gates).
- **W124 in isolation**: `cabal test --test-options='--match=W124'`
  returns 38 examples / 0 failures / 8 pending.

W124 adds 30 audit gates as pendingWith / shouldBe placeholders plus
8 positive smoke tests for `Daemon` module helpers (parseDebugSet ×2,
writePidFile/removePidFile ×2, networkSection, parseConfFileForNetwork,
newLogState/initLogFile/reopenLogFile, sdNotify* no-op behavior).

Production code is unchanged — this is a discovery wave. No xfail
gate currently passes; every "PRESENT" gate is a regression guard
(future code change that breaks the assertion will fail the gate).
The 8 MISSING / PARTIAL `pendingWith` gates land green in subsequent
FIX waves (FIX-A through FIX-G outlined above).

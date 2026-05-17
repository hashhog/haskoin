{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W124 Operator Experience — 30-gate audit for haskoin.
--
-- DISCOVERY-ONLY audit.  Each gate calls 'pendingWith' with a
-- one-line rationale tying it back to a citation in
-- @audit/w124_operator_experience.md@.  No production code is
-- modified in this wave; subsequent FIX waves flip the gates one by
-- one against the same Hspec call sites.
--
-- Context: haskoin was DOWN 4 days during Path A (wave47 overnight
-- iter 5 onward).  The process exited silently at 00:17 UTC, no
-- crash signature in log tail, no systemd unit, no dmesg entry, no
-- restart.  Many of these gates are direct ancestors of that
-- failure mode.
--
-- References:
--   bitcoin-core/src/init.cpp          Step 1 (basic setup, signal
--                                      handlers, datadir lock)
--   bitcoin-core/src/shutdown.cpp      Interrupt + Shutdown
--   bitcoin-core/src/logging.{cpp,h}   ShrinkDebugFile, log levels,
--                                      buffered-pre-init logs
--   bitcoin-core/src/init/common.cpp   PIDFile lifecycle
--   bitcoin-core/src/util/system.cpp   daemon() double-fork
module W124OperatorSpec (spec) where

import Test.Hspec
import Control.Monad (when)
import Data.List (isInfixOf)
import System.Directory (doesFileExist, removeFile, getTemporaryDirectory)
import System.FilePath ((</>))
import Control.Exception (try, SomeException)

import qualified Haskoin.Daemon as Daemon


-- | Read the haskoin source files (Main.hs / Daemon.hs / Rpc.hs /
-- Storage.hs / Network.hs / haskoin.cabal) once per gate so each
-- check sees the live tree.  Cheap because Hspec runs sequentially.
mainHs :: IO String
mainHs = readFile "app/Main.hs"

daemonHs :: IO String
daemonHs = readFile "src/Haskoin/Daemon.hs"

cabalFile :: IO String
cabalFile = readFile "haskoin.cabal"

rpcHs :: IO String
rpcHs = readFile "src/Haskoin/Rpc.hs"

networkHs :: IO String
networkHs = readFile "src/Haskoin/Network.hs"


spec :: Spec
spec = describe "W124 — Operator experience (haskoin)" $ do

  ------------------------------------------------------------------
  -- Group A — Signal / shutdown (gates 1-6)
  ------------------------------------------------------------------

  describe "A. Signal handling and shutdown sequence" $ do

    it "G1 (PRESENT): SIGINT/SIGTERM installed via installHandler" $ do
      src <- mainHs
      ("installHandler sigINT"  `isInfixOf` src) `shouldBe` True
      ("installHandler sigTERM" `isInfixOf` src) `shouldBe` True

    it "G2 (PRESENT): tryPutMVar (not putMVar) inside handler" $ do
      -- Re-delivery of SIGINT/SIGTERM must not wedge the handler.
      -- Main.hs:1308-1313 already uses tryPutMVar — guard against
      -- regression.
      src <- mainHs
      ("tryPutMVar shutdownVar" `isInfixOf` src) `shouldBe` True

    it "G3 (PRESENT): SIGHUP reopens the log file" $ do
      src <- daemonHs
      ("installSighupHandler" `isInfixOf` src) `shouldBe` True
      ("reopenLogFile"        `isInfixOf` src) `shouldBe` True

    it "G4 (MISSING): SIGPIPE is not ignored — peer-close on RPC stream can kill the daemon" $
      -- Core (init.cpp:909): signal(SIGPIPE, SIG_IGN).  haskoin
      -- installs NO handler for SIGPIPE.  A Warp / WAI worker that
      -- writes to a peer socket which has been closed will raise
      -- SIGPIPE; the default disposition on Linux is to terminate
      -- the entire process.  Direct candidate root cause for the
      -- 4-day silent outage: a single stale RPC client (curl-loop,
      -- Prometheus scrape, fleet-monitor) closing mid-response
      -- could SIGPIPE the daemon with no log trail.
      pendingWith "AUDIT(W124)/G4: no installHandler sigPIPE Ignore — \
                  \BUG-1 P0-OUTAGE.  Core init.cpp:909 explicitly \
                  \signal(SIGPIPE, SIG_IGN).  4-day Path-A outage \
                  \candidate."

    it "G5 (PARTIAL): shutdown watchdog forces exit at 30 s" $ do
      src <- mainHs
      -- This IS present (Main.hs:1329-1332) — but the watchdog
      -- exits with ExitFailure 2 instead of SIGABRT, so post-mortem
      -- tooling that scrapes "Aborted" / coredumpctl never fires.
      ("Shutdown watchdog: forcing exit after 30s" `isInfixOf` src) `shouldBe` True

    it "G6 (PARTIAL): `stop` RPC kills the RPC thread but does not satisfy main shutdownVar" $ do
      src <- rpcHs
      -- Rpc.hs:7601-7615.  handleStop only killThread's the
      -- internal RPC thread; it never raiseSignal sigTERM /
      -- tryPutMVar shutdownVar.  Net effect: the JSON-RPC client
      -- gets "Bitcoin server stopping" but the process keeps
      -- running (no mempool/UTXO flush, no anchors.json save, no
      -- pidfile removal).  Operator runs `bitcoin-cli stop`,
      -- believes the node is down, then notices --rpcport is still
      -- bound on the next restart.  BUG-2 P1.
      ("killThread tid" `isInfixOf` src) `shouldBe` True
      ("raiseSignal"    `isInfixOf` src) `shouldBe` False


  ------------------------------------------------------------------
  -- Group B — Process lifecycle (gates 7-12)
  ------------------------------------------------------------------

  describe "B. Process lifecycle: daemonize, pidfile, datadir lock" $ do

    it "G7 (PRESENT): double-fork daemonize implemented" $ do
      src <- daemonHs
      ("daemonize"      `isInfixOf` src) `shouldBe` True
      ("createSession"  `isInfixOf` src) `shouldBe` True
      ("forkProcess"    `isInfixOf` src) `shouldBe` True

    it "G8 (PARTIAL): PID file is written but not atomically (no temp + rename)" $ do
      src <- daemonHs
      -- Daemon.hs:191-196.  writeFile is direct, not atomic
      -- (temp-file + rename(2)).  A crash mid-write or two
      -- concurrent --daemon invocations against the same datadir
      -- can leave a truncated pidfile that subsequent reads
      -- mis-parse as PID 0 → kill(0, SIGTERM) acts on the calling
      -- process group, not on haskoin.
      ("writeFile path (show (fromEnum pid)"        `isInfixOf` src) `shouldBe` True
      ("renameFile" `isInfixOf` src)                              `shouldBe` False

    it "G9 (MISSING): no datadir lock file (.lock) at startup" $ do
      mn <- mainHs
      dm <- daemonHs
      let src = mn ++ dm
      -- Core obtains an advisory flock on
      -- <datadir>/.lock at startup (init.cpp Step 4).  haskoin
      -- has NO such lock.  Two concurrent
      --   haskoin node --datadir /data/nvme1/hashhog-mainnet/haskoin
      -- invocations (operator typo, runaway systemd Restart=,
      -- second `start_mainnet.sh haskoin` while the first is
      -- still alive) will both open the same RocksDB.
      -- rocksdb-haskell propagates the LOCK file inside RocksDB
      -- as an exception, but the second instance will then
      -- silently exit with no log line because openDB is wrapped
      -- in bracket but not in a try/catch that reports the
      -- specific reason.  BUG-3 P0-CORRUPTION.
      ("flock"        `isInfixOf` src) `shouldBe` False
      (".lock"        `isInfixOf` src) `shouldBe` False
      ("dirLock"      `isInfixOf` src) `shouldBe` False
      pendingWith "AUDIT(W124)/G9: no flock(.lock) on datadir — \
                  \BUG-3 P0-CORRUPTION. Path-A 4-day outage \
                  \candidate (silent second-instance race)."

    it "G10 (PARTIAL): PID file written with mode 0644 but not removed on SIGKILL" $ do
      src <- daemonHs
      ("setFileMode path 0o644" `isInfixOf` src) `shouldBe` True
      -- removePidFile is called on the graceful path (Main.hs:1372),
      -- but a SIGKILL / OOM kill / panic leaves a stale pidfile.
      -- Documented in Main.hs:611-614 ("matching Bitcoin Core") so
      -- this is best-effort, not a bug.

    it "G11 (PRESENT): bracket (openDB closeDB) around the whole node body" $ do
      src <- mainHs
      ("bracket (openDB dbConfig) closeDB" `isInfixOf` src) `shouldBe` True

    it "G12 (PARTIAL): openDB has no startup banner with the exact RocksDB version + rocksdb_compat shim status" $ do
      -- Recall the rocksdb_compat shim provides
      -- rocksdb_filterpolicy_create() so haskoin links against
      -- rocksdb-haskell 9.x. If the shim is missing or stale,
      -- the link succeeds but RocksDB I/O later segfaults.  haskoin
      -- prints nothing at startup that an operator could grep for
      -- ("rocksdb_compat OK" / version banner).  BUG-4 P2 silent
      -- ABI risk.
      src <- mainHs
      ("rocksdb_compat" `isInfixOf` src) `shouldBe` False


  ------------------------------------------------------------------
  -- Group C — Logging (gates 13-18)
  ------------------------------------------------------------------

  describe "C. Logging: levels, rotation, buffer-before-open, atexit" $ do

    it "G13 (PRESENT): debug categories parser matches Core (DbgNet/Mempool/...)" $ do
      src <- daemonHs
      ("DbgNet"        `isInfixOf` src) `shouldBe` True
      ("DbgMempool"    `isInfixOf` src) `shouldBe` True
      ("DbgValidation" `isInfixOf` src) `shouldBe` True
      ("DbgRpc"        `isInfixOf` src) `shouldBe` True

    it "G14 (MISSING): no -loglevel=<warning|info|debug|trace> knob (Core has m_log_level)" $ do
      src <- daemonHs
      ("LogLevel" `isInfixOf` src) `shouldBe` False
      ("loglevel" `isInfixOf` src) `shouldBe` False
      pendingWith "AUDIT(W124)/G14: no log-level knob.  All log \
                  \lines emit at one level (putStrLn) — operator \
                  \cannot suppress noisy DbgNet without losing \
                  \DbgValidation errors. BUG-5 P2."

    it "G15 (MISSING): no log file rotation / ShrinkDebugFile equivalent" $ do
      src <- daemonHs
      -- Core: BCLog::Logger::ShrinkDebugFile (logging.cpp:514) is
      -- invoked at startup to truncate >200 MiB log files to the
      -- last 1 MiB.  haskoin opens AppendMode and writes forever;
      -- the 91 MB log file recorded in wave47-2026-04-16 OVERNIGHT-LOG
      -- would have grown unbounded across a 4-day outage.
      -- (Note: ShrinkDebugFile *appears* as a literal in Daemon.hs's
      -- documentation block — daemon.hs:489 — but only as a
      -- comparison comment.  We check that the function itself is
      -- not exported by the module nor wired into 'initLogFile'.)
      let isFnDef s = ("shrinkLog "    `isInfixOf` s)
                   || ("shrinkDebug "  `isInfixOf` s)
                   || ("rotateLog "    `isInfixOf` s)
      isFnDef src `shouldBe` False
      pendingWith "AUDIT(W124)/G15: no log rotation — BUG-7 P1. \
                  \Operator must rely on external logrotate + \
                  \SIGHUP. With the silent-outage failure mode this \
                  \means crash forensics require fishing 91 MB+ of \
                  \unrotated text."

    it "G16 (PARTIAL): SIGHUP reopens log but ALL other writes go through putStrLn" $ do
      mn <- mainHs
      dm <- daemonHs
      -- LogState handle is mutated by reopenLogFile but the rest
      -- of the codebase calls putStrLn directly (stdout), which
      -- after daemonize was dupTo'd to the log fd at fork time.
      -- That fd is NOT reopened on SIGHUP.  Net effect: after
      -- logrotate, putStrLn lines keep writing to the (deleted)
      -- inode.  BUG-8 P1.
      ("hPutStrLn (lsHandle" `isInfixOf` dm) `shouldBe` False
      -- putStrLn count is large — sanity check it's the dominant logger.
      -- Strip the line then check via 'isInfixOf' so leading indent
      -- doesn't matter.
      let putStrLnCount = length (filter ("putStrLn" `isInfixOf`) (lines mn))
      putStrLnCount `shouldSatisfy` (> 50)

    it "G17 (MISSING): no log-line timestamping" $ do
      src <- mainHs
      -- Core: fLogTimestamps=true is default; every log line gets
      -- a microsecond ISO-8601 prefix.  haskoin's putStrLn writes
      -- raw lines — operator forensics on the silent-outage path
      -- have no way to align across nodes without external
      -- ts(1) / journalctl annotation.
      ("hPutStrLnTimestamped" `isInfixOf` src) `shouldBe` False
      ("ISO8601"              `isInfixOf` src) `shouldBe` False
      pendingWith "AUDIT(W124)/G17: log lines have no timestamps. \
                  \Cross-impl forensics impossible without external \
                  \ts(1) wrapping. BUG-8 P2."

    it "G18 (MISSING): no buffered-before-open log queue (Core m_msgs_before_open)" $
      -- Core logging.h:143: messages emitted before the log file
      -- handle is open are buffered into m_msgs_before_open and
      -- flushed once the file opens.  haskoin can silently lose
      -- the first ~100 ms of startup messages (asmap load, prune
      -- parse) if --daemon redirected stdio to the log file but
      -- newLogState hasn't initialised yet.
      pendingWith "AUDIT(W124)/G18: no pre-open log buffer. Startup \
                  \errors before initLogFile may be lost. BUG-9 P3."


  ------------------------------------------------------------------
  -- Group D — Runtime / GHC-specific (gates 19-24)
  ------------------------------------------------------------------

  describe "D. GHC RTS / Haskell-specific concerns" $ do

    it "G19 (PRESENT): -threaded -rtsopts -with-rtsopts=-N on every executable" $ do
      cab <- cabalFile
      let occ = length (filter (\ln -> "-threaded -rtsopts" `isInfixOf` ln) (lines cab))
      -- One for the executable, one for haskoin-test, one for
      -- sighash-vectors, one for script-vectors.  At least 3.
      occ `shouldSatisfy` (>= 3)

    it "G20 (PARTIAL): NO +RTS -I0 to disable idle-time GC during long IBD pauses" $ do
      cab <- cabalFile
      -- During the wave47 outage window, haskoin was idle (no
      -- block-connect work) and could have triggered an idle GC
      -- mid-RocksDB FFI.  -I0 disables idle GC; Core doesn't have
      -- this knob (no Haskell RTS) so the cross-impl reference
      -- doesn't help.  Soft-flag as PARTIAL — recommend
      -- "-with-rtsopts=-N -I0" for the production executable.
      ("-I0"       `isInfixOf` cab) `shouldBe` False
      ("-with-rtsopts=-N -I0" `isInfixOf` cab) `shouldBe` False

    it "G21 (MISSING): bracketed forkIO for background threads — many `void $ forkIO` lack catch on the OUTER body" $ do
      src <- mainHs
      -- Main.hs:1241 flushThreadId, Main.hs:1257 Warp.run (metrics),
      -- Main.hs:1297 statusTid all bare-forkIO.  Inner ops do have
      -- catch wrappers, but if `forever` itself throws (network
      -- partition during STM read, RocksDB FFI), the thread dies
      -- silently with no recovery and no operator notification.
      -- BUG-10 P1.
      let mainLines = lines src
          forkIOLines = filter ("forkIO" `isInfixOf`) mainLines
      -- Count is large enough that at least some are unprotected.
      length forkIOLines `shouldSatisfy` (>= 6)
      -- The acceptLoop in Network.hs has the same issue.

    it "G22 (PARTIAL): acceptLoop in Network.hs:3749 has NO catch around forever" $ do
      src <- networkHs
      -- The inner handleInbound has a catch, but if accept itself
      -- throws (EMFILE, EAGAIN with a saturated kernel queue,
      -- listen socket closed during shutdown), acceptLoop dies
      -- and the inbound listener silently disappears.
      ("acceptLoop listenSock = forever" `isInfixOf` src) `shouldBe` True

    it "G23 (PRESENT): bracket/bracket_ used in Storage and Rpc for resource scoping" $ do
      st <- readFile "src/Haskoin/Storage.hs"
      ("bracket" `isInfixOf` st) `shouldBe` True

    it "G24 (PRESENT): rocksdb_compat shim documented in haskoin.cabal extra-libraries" $ do
      cab <- cabalFile
      ("rocksdb_compat" `isInfixOf` cab) `shouldBe` True
      ("rocksdb_filterpolicy_create" `isInfixOf` cab) `shouldBe` True
      ("scripts/build-rocksdb-compat.sh" `isInfixOf` cab) `shouldBe` True


  ------------------------------------------------------------------
  -- Group E — Observability & supervision (gates 25-30)
  ------------------------------------------------------------------

  describe "E. Health, metrics, supervision, fleet-readiness" $ do

    it "G25 (PRESENT): /health endpoint runs in its own thread when --healthport > 0" $ do
      src <- daemonHs
      ("runHealthServer" `isInfixOf` src) `shouldBe` True
      ("healthApp"       `isInfixOf` src) `shouldBe` True

    it "G26 (PRESENT): sd_notify protocol (READY/STOPPING/STATUS/WATCHDOG)" $ do
      src <- daemonHs
      ("sdNotifyReady"   `isInfixOf` src) `shouldBe` True
      ("sdNotifyStopping" `isInfixOf` src) `shouldBe` True
      ("sdNotifyStatus"  `isInfixOf` src) `shouldBe` True
      ("sdNotifyWatchdog" `isInfixOf` src) `shouldBe` True

    it "G27 (PARTIAL): Prometheus metrics server is forked without exception protection" $ do
      src <- mainHs
      -- Main.hs:1257.  Warp.run swallows synchronous WAI errors,
      -- but if the listen port is already bound (operator restarts
      -- haskoin without stopping fleet-monitor first) Warp throws
      -- and the metrics endpoint silently disappears with no log
      -- line.  BUG-11 P2.
      ("void $ forkIO $ Warp.run noMetricsPort" `isInfixOf` src) `shouldBe` True

    it "G28 (MISSING): no canonical haskoin.service systemd unit file shipped" $ do
      -- The other fleet impls (blockbrew, ouroboros, beamchain) have
      -- ${name}.service templates either in the repo or in
      -- start_mainnet.sh comments.  haskoin's start_mainnet.sh path
      -- is bare `nohup ... &; disown` (tools/start_mainnet.sh:84-96).
      -- The 4-day outage went undetected precisely because nothing
      -- supervised the process.  Recommend shipping
      -- scripts/haskoin.service.in. BUG-12 P0-SUPERVISION.
      ex1 <- doesFileExist "scripts/haskoin.service"
      ex2 <- doesFileExist "scripts/haskoin.service.in"
      ex3 <- doesFileExist "scripts/haskoin@.service"
      (ex1 || ex2 || ex3) `shouldBe` False
      pendingWith "AUDIT(W124)/G28: no systemd unit shipped — \
                  \BUG-12 P0-SUPERVISION.  Direct cause of the \
                  \4-day silent outage: bare nohup launch + disown \
                  \in start_mainnet.sh:84-96, no Restart=, no \
                  \OnFailure=, no watchdog."

    it "G29 (PARTIAL): config file is parsed but config-reload on SIGHUP is NOT wired" $ do
      src <- daemonHs
      -- SIGHUP only reopens the log file.  Core also re-reads
      -- bitcoin.conf on SIGHUP (init.cpp:906 wires it through).
      -- haskoin operator must restart the daemon for any config
      -- change, including --connect peer list changes.
      ("installSighupHandler" `isInfixOf` src) `shouldBe` True
      ("readConfFileForNetwork" `isInfixOf` src) `shouldBe` True

    it "G30 (MISSING): no startup pre-flight check that rocksdb_compat.so is loadable / version-pinned" $ do
      mn <- mainHs
      dm <- daemonHs
      let src = mn ++ dm
      -- We link against -lrocksdb_compat but never verify at
      -- startup that the symbol rocksdb_filterpolicy_create
      -- resolves correctly.  A package upgrade that pushes a
      -- newer rocksdb-haskell expecting a different ABI (or
      -- LD_LIBRARY_PATH change that hides the shim) would crash
      -- inside the first RocksDB write, not at startup.  BUG-13
      -- P1.
      ("checkRocksdbCompat" `isInfixOf` src) `shouldBe` False
      ("rocksdb_version"    `isInfixOf` src) `shouldBe` False
      pendingWith "AUDIT(W124)/G30: no startup pre-flight \
                  \verifying rocksdb_compat.so is loadable + \
                  \ABI-compatible.  BUG-13 P1 startup-silent-fail."


  ------------------------------------------------------------------
  -- Bonus / integrity guards (do not change gate count)
  ------------------------------------------------------------------

  describe "Bonus: positive smoke tests for Daemon module" $ do

    it "parseDebugSet handles comma-separated categories" $ do
      let ds = Daemon.parseDebugSet "net,mempool,rpc"
      Daemon.debugEnabled Daemon.DbgNet     ds `shouldBe` True
      Daemon.debugEnabled Daemon.DbgMempool ds `shouldBe` True
      Daemon.debugEnabled Daemon.DbgRpc     ds `shouldBe` True
      Daemon.debugEnabled Daemon.DbgWallet  ds `shouldBe` False

    it "parseDebugSet handles 'all' / '1' as Core does" $ do
      let dsAll = Daemon.parseDebugSet "all"
          ds1   = Daemon.parseDebugSet "1"
      -- Any category is enabled when DbgAll is set.
      Daemon.debugEnabled Daemon.DbgValidation dsAll `shouldBe` True
      Daemon.debugEnabled Daemon.DbgValidation ds1   `shouldBe` True

    it "writePidFile + removePidFile round-trip" $ do
      tmp <- getTemporaryDirectory
      let p = tmp </> "haskoin-w124-pid.test"
      Daemon.writePidFile p
      ex1 <- doesFileExist p
      ex1 `shouldBe` True
      Daemon.removePidFile p
      ex2 <- doesFileExist p
      ex2 `shouldBe` False

    it "removePidFile is idempotent (no error when file absent)" $ do
      tmp <- getTemporaryDirectory
      let p = tmp </> "haskoin-w124-pid-missing.test"
      r <- try (Daemon.removePidFile p) :: IO (Either SomeException ())
      case r of
        Right () -> return ()
        Left e   -> expectationFailure $
          "removePidFile must not throw on absent file: " ++ show e

    it "networkSection maps haskoin netName strings to Core section headers" $ do
      Daemon.networkSection "main"     `shouldBe` "main"
      Daemon.networkSection "mainnet"  `shouldBe` "main"
      Daemon.networkSection "testnet"  `shouldBe` "test"
      Daemon.networkSection "testnet3" `shouldBe` "test"
      Daemon.networkSection "testnet4" `shouldBe` "testnet4"
      Daemon.networkSection "regtest"  `shouldBe` "regtest"

    it "parseConfFileForNetwork applies section filtering" $ do
      let conf = unlines
            [ "rpcuser = global-user"
            , ""
            , "[main]"
            , "rpcport = 8332"
            , ""
            , "[test]"
            , "rpcport = 18332"
            ]
          mainMap  = Daemon.parseConfFileForNetwork "main"  conf
          testMap  = Daemon.parseConfFileForNetwork "testnet3" conf
      Daemon.configLookup     "rpcuser" mainMap `shouldBe` Just "global-user"
      Daemon.configLookupInt  "rpcport" 0 mainMap `shouldBe` 8332
      Daemon.configLookupInt  "rpcport" 0 testMap `shouldBe` 18332

    it "newLogState + initLogFile + reopenLogFile in a temp file" $ do
      tmp <- getTemporaryDirectory
      let p = tmp </> "haskoin-w124-log.test"
      -- Cleanup if leftover from previous run.
      ex0 <- doesFileExist p
      when ex0 (removeFile p)
      ls <- Daemon.newLogState p
      Daemon.initLogFile ls
      ex1 <- doesFileExist p
      ex1 `shouldBe` True
      Daemon.reopenLogFile ls
      ex2 <- doesFileExist p
      ex2 `shouldBe` True
      -- Cleanup.
      removeFile p

    it "sdNotify* are no-ops when NOTIFY_SOCKET is unset" $ do
      -- These must NEVER throw, even when systemd is not present.
      -- Core's HandleSIGTERM / Interrupt path calls sd_notify
      -- unconditionally and similarly tolerates a non-systemd
      -- environment.
      Daemon.sdNotifyReady
      Daemon.sdNotifyStopping
      Daemon.sdNotifyStatus "test status"
      Daemon.sdNotifyWatchdog
      -- If we reach here, no exception was raised.
      True `shouldBe` True

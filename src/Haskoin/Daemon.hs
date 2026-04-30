{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}

-- | Operational helpers for running haskoin as a long-lived daemon:
--
-- * @-daemon@ background fork (POSIX double-fork + setsid)
-- * @-pid=<file>@ PID file write/cleanup
-- * @-debug=<cat>@ category-filtered logging
-- * @-conf=<file>@ minimalist Bitcoin-Core-style @key=value@ parser
-- * @-printtoconsole@ explicit console-logging flag
-- * SIGHUP log-file reopen handler
-- * @\/health@ HTTP endpoint for process supervisors / load balancers
--
-- References (Bitcoin Core):
--
-- * @src\/init.cpp@ — daemonize/PID/conf/debug wiring
-- * @src\/util\/system.cpp@ daemon() — POSIX double-fork
-- * @src\/init\/common.cpp@ g_pidfile_path — pidfile lifecycle
-- * @src\/util\/fs.cpp@ — config file path resolution
--
-- This module is deliberately self-contained: no @rocksdb@,
-- @secp256k1@, or other heavyweight deps, so it links cleanly
-- into pure-Haskell test suites.
module Haskoin.Daemon
  ( -- * Daemonize
    daemonize
    -- * PID file
  , writePidFile
  , removePidFile
  , withPidFile
    -- * Debug categories
  , DebugCategory(..)
  , parseDebugCategory
  , DebugSet
  , emptyDebugSet
  , parseDebugSet
  , debugEnabled
  , logDebug
  , globalDebugSet
  , setGlobalDebugSet
    -- * Config file
  , ConfigMap
  , parseConfFile
  , parseConfFileForNetwork
  , readConfFile
  , readConfFileForNetwork
  , configLookup
  , configLookupBool
  , configLookupInt
  , networkSection
    -- * Log file rotation
  , LogState
  , newLogState
  , initLogFile
  , reopenLogFile
  , installSighupHandler
    -- * Health endpoint
  , healthApp
  , runHealthServer
    -- * systemd sd_notify
  , sdNotify
  , sdNotifyReady
  , sdNotifyStopping
  , sdNotifyStatus
  , sdNotifyWatchdog
  ) where

import Control.Concurrent (ThreadId, forkIO)
import Control.Exception (SomeException, bracket, catch, try)
import Control.Monad (forM_, void, when)
import Data.Char (isSpace, toLower)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.List (dropWhileEnd)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy.Char8 as BL8
import qualified Network.HTTP.Types as HTTP
import qualified Network.Socket as Sock
import qualified Network.Socket.ByteString as SockBS
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import System.Directory (doesFileExist, removeFile)
import System.Environment (lookupEnv)
import System.IO
  ( BufferMode(..)
  , Handle
  , IOMode(..)
  , hClose
  , hFlush
  , hPutStrLn
  , hSetBuffering
  , openFile
  , stderr
  , stdout
  )
import System.IO.Unsafe (unsafePerformIO)
import qualified System.Posix.Files as PosixFiles
import System.Posix.IO (OpenMode(..), closeFd, defaultFileFlags, dupTo, openFd)
import qualified System.Posix.IO as PosixIO
import System.Posix.Process
  ( createSession
  , exitImmediately
  , forkProcess
  , getProcessID
  )
import System.Posix.Signals
  ( Handler(..)
  , installHandler
  , sigHUP
  )
import System.Posix.Types (Fd(..))
import System.Exit (ExitCode(..))


--------------------------------------------------------------------------------
-- Daemonize
--------------------------------------------------------------------------------

-- | POSIX-style daemonize: detach the current process from the
-- controlling terminal and run @action@ in the background.
--
-- 1. @fork()@ — parent exits, intermediate child continues.
-- 2. @setsid()@ in the intermediate child to detach from the TTY.
-- 3. Second @fork()@ — intermediate exits, grandchild is the daemon
--    and is NOT a session leader (so it can never re-acquire a TTY).
-- 4. Redirect stdin\/stdout\/stderr in the grandchild to @mLogPath@
--    (or @\/dev\/null@).
-- 5. Run @action@ in the grandchild.
--
-- This function only returns in the grandchild (via @action@). The
-- original foreground process and the intermediate exit before
-- @daemonize@ would conceptually return. Mirrors Bitcoin Core's
-- @util\/system.cpp@ @daemon()@ behaviour.
daemonize :: Maybe FilePath -> IO () -> IO ()
daemonize mLogPath action = do
  -- Flush before fork so parent/child don't double-emit pending stdio.
  hFlush stdout
  hFlush stderr

  -- First fork: parent exits, intermediate child continues.
  _pid1 <- forkProcess $ do
    -- Become session leader, detaching from the controlling TTY.
    void createSession

    -- Second fork so the daemon is NOT a session leader.
    _pid2 <- forkProcess $ do
      redirectStdio mLogPath
      action

    -- Intermediate exits immediately so the daemon is reparented to
    -- init / systemd. exitImmediately bypasses normal Haskell
    -- shutdown so the grandchild's RTS state is unaffected.
    exitImmediately ExitSuccess

  -- Original parent exits immediately so the launching shell returns.
  exitImmediately ExitSuccess

-- | Replace stdin\/stdout\/stderr with the given log file (or
-- @\/dev\/null@). Used immediately after the second fork so the
-- daemon has well-defined file descriptors.
redirectStdio :: Maybe FilePath -> IO ()
redirectStdio mLogPath = do
  let target = case mLogPath of
        Just p  -> p
        Nothing -> "/dev/null"
      -- unix-2.8 openFd: openFd path mode flags
      logFlags  = defaultFileFlags { PosixIO.append = True
                                   , PosixIO.creat  = Just 0o644 }
      nullFlags = defaultFileFlags
  -- Open the log target read-write; fall back to /dev/null on failure.
  fd <- openFd target ReadWrite logFlags
          `catch` (\(_ :: SomeException) ->
                     openFd "/dev/null" ReadWrite nullFlags)
  -- Standard fds 0,1,2.
  mapM_ (\(Fd target') -> dupTo fd (Fd target') `catch`
                            (\(_ :: SomeException) -> return (Fd target')))
        [Fd 0, Fd 1, Fd 2]
  closeFd fd `catch` (\(_ :: SomeException) -> return ())


--------------------------------------------------------------------------------
-- PID file
--------------------------------------------------------------------------------

-- | Write the current process's PID to the given file.
-- Path is created with mode 0644. Failure is propagated as an
-- @IOError@; callers typically want to abort startup.
writePidFile :: FilePath -> IO ()
writePidFile path = do
  pid <- getProcessID
  writeFile path (show (fromEnum pid) ++ "\n")
  PosixFiles.setFileMode path 0o644
    `catch` (\(_ :: SomeException) -> return ())

-- | Remove a PID file if present. Idempotent.
removePidFile :: FilePath -> IO ()
removePidFile path = do
  exists <- doesFileExist path
  when exists $
    removeFile path `catch` (\(_ :: SomeException) -> return ())

-- | Bracket the PID file across an IO action: write on entry, remove
-- on exit (success or exception).
withPidFile :: FilePath -> IO a -> IO a
withPidFile path = bracket (writePidFile path) (\_ -> removePidFile path) . const


--------------------------------------------------------------------------------
-- Debug categories
--------------------------------------------------------------------------------

-- | Subset of Bitcoin Core's @-debug=<cat>@ categories that map to
-- subsystems present in haskoin. @DbgAll@ is the explicit "everything"
-- bucket and matches Core's @-debug=1@ / @-debug=all@.
data DebugCategory
  = DbgAll
  | DbgNet
  | DbgMempool
  | DbgValidation
  | DbgRpc
  | DbgRocksdb
  | DbgZmq
  | DbgPrune
  | DbgIbd
  | DbgPeers
  | DbgUtxo
  | DbgWallet
  | DbgUnknown !String
  deriving (Eq, Ord, Show)

-- | Parse a single category token.
parseDebugCategory :: String -> DebugCategory
parseDebugCategory s = case map toLower s of
  "all"        -> DbgAll
  "1"          -> DbgAll
  "net"        -> DbgNet
  "mempool"    -> DbgMempool
  "validation" -> DbgValidation
  "rpc"        -> DbgRpc
  "rocksdb"    -> DbgRocksdb
  "db"         -> DbgRocksdb
  "zmq"        -> DbgZmq
  "prune"      -> DbgPrune
  "ibd"        -> DbgIbd
  "peers"      -> DbgPeers
  "utxo"       -> DbgUtxo
  "wallet"     -> DbgWallet
  other        -> DbgUnknown other

-- | A set of enabled categories. 'DbgAll' subsumes everything and
-- is checked specially in 'debugEnabled'.
type DebugSet = Set.Set DebugCategory

-- | Empty (no categories enabled) — quietest configuration.
emptyDebugSet :: DebugSet
emptyDebugSet = Set.empty

-- | Build a 'DebugSet' from a comma-separated category list, e.g.
-- @"net,mempool"@. Whitespace tolerated.
parseDebugSet :: String -> DebugSet
parseDebugSet = Set.fromList . map (parseDebugCategory . trim) . splitOn ','
  where
    trim = dropWhile isSpace . dropWhileEnd isSpace
    splitOn c xs = case break (== c) xs of
      (h, [])      -> [h]
      (h, _ : rest) -> h : splitOn c rest

-- | True if the supplied category should produce output given the
-- current 'DebugSet'. 'DbgAll' wins over every specific category.
debugEnabled :: DebugCategory -> DebugSet -> Bool
debugEnabled cat ds
  | Set.member DbgAll ds = True
  | otherwise            = Set.member cat ds

-- | Process-global debug set. Mutated once at startup from
-- 'setGlobalDebugSet' and then read by 'logDebug'. Race-free because
-- writes happen before any logging thread is spawned.
{-# NOINLINE globalDebugSet #-}
globalDebugSet :: IORef DebugSet
globalDebugSet = unsafePerformIO (newIORef emptyDebugSet)

-- | Replace the process-global debug set. Safe to call repeatedly
-- (e.g. on @SIGHUP@ if we add a config-reload path).
setGlobalDebugSet :: DebugSet -> IO ()
setGlobalDebugSet = writeIORef globalDebugSet

-- | Print a category-prefixed log line if and only if the category
-- is enabled. The prefix mirrors Bitcoin Core's bracketed
-- @[net]@\/@[mempool]@\/etc. style for visual parity.
logDebug :: DebugCategory -> String -> IO ()
logDebug cat msg = do
  ds <- readIORef globalDebugSet
  when (debugEnabled cat ds) $
    putStrLn $ "[" ++ catLabel cat ++ "] " ++ msg
  where
    catLabel DbgAll          = "all"
    catLabel DbgNet          = "net"
    catLabel DbgMempool      = "mempool"
    catLabel DbgValidation   = "validation"
    catLabel DbgRpc          = "rpc"
    catLabel DbgRocksdb      = "rocksdb"
    catLabel DbgZmq          = "zmq"
    catLabel DbgPrune        = "prune"
    catLabel DbgIbd          = "ibd"
    catLabel DbgPeers        = "peers"
    catLabel DbgUtxo         = "utxo"
    catLabel DbgWallet       = "wallet"
    catLabel (DbgUnknown s)  = s


--------------------------------------------------------------------------------
-- Config file
--------------------------------------------------------------------------------

-- | Parsed config values, keyed by lowercase option name (mirrors
-- Bitcoin Core's case-insensitive option handling).
type ConfigMap = Map.Map String String

-- | Map a haskoin 'netName' string to the Bitcoin Core conf-file
-- section header. Core uses @[main]@, @[test]@ (for testnet3),
-- @[testnet4]@, @[signet]@, and @[regtest]@. We match those names
-- exactly so a @bitcoin.conf@ written for Core works unchanged.
networkSection :: String -> String
networkSection n = case map toLower n of
  "main"     -> "main"
  "mainnet"  -> "main"
  "testnet"  -> "test"
  "testnet3" -> "test"
  "test"     -> "test"
  "testnet4" -> "testnet4"
  "signet"   -> "signet"
  "regtest"  -> "regtest"
  other      -> other

-- | Parse a Bitcoin-Core-style config file and return the entries
-- visible to a node running on the given network.
--
-- Section semantics (matches @bitcoin.conf(5)@):
--
-- * Keys above the first @[section]@ header apply to ALL networks.
-- * Keys under @[main]@ apply only when the active network is
--   mainnet; ditto @[test]@ (testnet3), @[testnet4]@, @[signet]@,
--   @[regtest]@.
-- * A section-specific key OVERRIDES a global key of the same name.
--   This mirrors Core's left-to-right merge order in @ArgsManager@.
-- * Sections that don't match the active network are dropped silently
--   (they're valid for OTHER networks).
--
-- The @network@ argument is the haskoin 'netName' (\"main\",
-- \"testnet3\", \"testnet4\", \"regtest\"). 'networkSection' maps it
-- to the corresponding Core section header before filtering.
parseConfFileForNetwork :: String -> String -> ConfigMap
parseConfFileForNetwork network = mergeSections . sectionedLines
  where
    target = networkSection network

    -- Walk lines, threading the current section state. Emit
    -- (section, key, value) triples; the merge step downstream
    -- filters by section and overlays section-specific entries on
    -- top of the global ones.
    sectionedLines :: String -> [(Maybe String, String, String)]
    sectionedLines = go Nothing . lines
      where
        go _   []         = []
        go cur (raw:rest) =
          let stripped = dropWhile isSpace raw
          in case stripped of
               ""        -> go cur rest
               ('#':_)   -> go cur rest
               (';':_)   -> go cur rest
               ('[':xs)  ->
                 let nameAndRest = takeWhile (/= ']') xs
                     newSection  = map toLower (trim nameAndRest)
                 in go (Just newSection) rest
               _ -> case break (== '=') stripped of
                      (k, '=':v) ->
                        let key   = map toLower (trim k)
                            value = trimVal v
                        in (cur, key, value) : go cur rest
                      _ -> go cur rest

    trim     = dropWhile isSpace . dropWhileEnd isSpace
    trimVal  = dropWhile isSpace . dropWhileEnd isSpace . takeWhile (/= '#')

    -- Two-pass merge: globals first, then section-specific entries
    -- override. Within each pass, last-wins (matches Core).
    mergeSections :: [(Maybe String, String, String)] -> ConfigMap
    mergeSections triples =
      let globals = Map.fromList [(k, v) | (Nothing, k, v) <- triples]
          scoped  = Map.fromList [(k, v) | (Just s, k, v) <- triples
                                         , s == target]
      in Map.union scoped globals

-- | Backwards-compatible parser: ignores section headers entirely,
-- merging every @key=value@ in the file into a single 'ConfigMap'.
-- Use 'parseConfFileForNetwork' for proper @[main]@\/@[test]@\/
-- @[testnet4]@\/@[regtest]@ scoping. This is kept so existing
-- callers (and tests) that don't know the active network still work,
-- but they will silently absorb cross-network keys — prefer the
-- network-aware variant in production code.
parseConfFile :: String -> ConfigMap
parseConfFile = Map.fromList . concatMap parseLine . zip [1 :: Int ..] . lines
  where
    parseLine (_, raw) =
      let stripped = dropWhile isSpace raw
      in case stripped of
           ""             -> []
           ('#':_)        -> []
           (';':_)        -> []
           ('[':_)        -> []  -- section header: ignored
           _ -> case break (== '=') stripped of
                  (k, '=':v) ->
                    let key   = map toLower (dropWhileEnd isSpace k)
                        value = trimVal v
                    in [(key, value)]
                  _ -> []
    trimVal = dropWhile isSpace . dropWhileEnd isSpace . takeWhile (/= '#')

-- | Read and parse a config file. Returns an empty 'ConfigMap'
-- (not an error) if the file is absent — this matches Bitcoin Core,
-- which silently tolerates a missing default @bitcoin.conf@.
-- Permission errors / decode errors propagate as @Left msg@.
--
-- This is the section-blind variant; for @[main]@\/@[test]@\/
-- @[testnet4]@\/@[regtest]@ scoping use 'readConfFileForNetwork'.
readConfFile :: FilePath -> IO (Either String ConfigMap)
readConfFile path = do
  exists <- doesFileExist path
  if not exists
    then return (Right Map.empty)
    else do
      r <- try (readFile path) :: IO (Either SomeException String)
      case r of
        Left e  -> return (Left ("readConfFile " ++ path ++ ": " ++ show e))
        Right s -> return (Right (parseConfFile s))

-- | Read and parse a config file, filtering entries by the active
-- network's @[section]@. See 'parseConfFileForNetwork' for the
-- section semantics. Missing file = empty map (matches Core).
readConfFileForNetwork :: String -> FilePath -> IO (Either String ConfigMap)
readConfFileForNetwork network path = do
  exists <- doesFileExist path
  if not exists
    then return (Right Map.empty)
    else do
      r <- try (readFile path) :: IO (Either SomeException String)
      case r of
        Left e  -> return (Left ("readConfFile " ++ path ++ ": " ++ show e))
        Right s -> return (Right (parseConfFileForNetwork network s))

-- | Look up a config key, returning the raw string value if present.
configLookup :: String -> ConfigMap -> Maybe String
configLookup k = Map.lookup (map toLower k)

-- | Look up a boolean. Bitcoin-Core-compatible: @1@\/@true@\/@yes@
-- = True; @0@\/@false@\/@no@ = False; missing = default.
configLookupBool :: String -> Bool -> ConfigMap -> Bool
configLookupBool k def cm = case configLookup k cm of
  Nothing -> def
  Just v  -> case map toLower v of
    "1"     -> True
    "true"  -> True
    "yes"   -> True
    "on"    -> True
    "0"     -> False
    "false" -> False
    "no"    -> False
    "off"   -> False
    _       -> def

-- | Look up an integer. Returns the default if missing or unparseable.
configLookupInt :: String -> Int -> ConfigMap -> Int
configLookupInt k def cm = case configLookup k cm of
  Nothing -> def
  Just v  -> case reads v of
    [(n, "")] -> n
    _         -> def


--------------------------------------------------------------------------------
-- Log file rotation (SIGHUP)
--------------------------------------------------------------------------------

-- | Mutable handle to the current log file. Captured by the SIGHUP
-- handler, which closes the old handle and reopens the same path.
-- Bitcoin Core's @ShrinkDebugFile@\/SIGHUP behaviour.
data LogState = LogState
  { lsPath   :: !FilePath
  , lsHandle :: !(IORef (Maybe Handle))
  }

-- | Build a 'LogState' for the given path. Does NOT open the file
-- yet; call 'initLogFile' after constructing.
newLogState :: FilePath -> IO LogState
newLogState p = do
  ref <- newIORef Nothing
  return LogState { lsPath = p, lsHandle = ref }

-- | Open the log file in append mode and store the handle in 'LogState'.
-- Subsequent calls leak the previous handle; prefer 'reopenLogFile'.
initLogFile :: LogState -> IO ()
initLogFile ls = do
  h <- openFile (lsPath ls) AppendMode
  hSetBuffering h LineBuffering
  writeIORef (lsHandle ls) (Just h)

-- | Close the current handle (if any) and reopen the same path in
-- append mode. Triggered by SIGHUP so an external @logrotate@ can
-- @mv@ the log out of the way and signal the daemon to start writing
-- to a fresh inode.
reopenLogFile :: LogState -> IO ()
reopenLogFile ls = do
  mOld <- atomicModifyIORef' (lsHandle ls) (\h -> (Nothing, h))
  forM_ mOld $ \h ->
    hClose h `catch` (\(_ :: SomeException) -> return ())
  r <- try (openFile (lsPath ls) AppendMode)
         :: IO (Either SomeException Handle)
  case r of
    Left e -> do
      hPutStrLn stderr $ "reopenLogFile: failed to open "
                       ++ lsPath ls ++ ": " ++ show e
      writeIORef (lsHandle ls) Nothing
    Right h -> do
      hSetBuffering h LineBuffering
      writeIORef (lsHandle ls) (Just h)

-- | Install the SIGHUP handler to call 'reopenLogFile'.
-- Idempotent — replaces any previously installed SIGHUP handler.
installSighupHandler :: LogState -> IO ()
installSighupHandler ls =
  void $ installHandler sigHUP (Catch (reopenLogFile ls)) Nothing


--------------------------------------------------------------------------------
-- Health endpoint
--------------------------------------------------------------------------------

-- | A minimal WAI 'Application' for a process supervisor's health check.
--
-- Returns @200 OK@ + @\"ok\\n\"@ for any path. We deliberately don't
-- gate on RPC liveness or chain progress: the goal is "is the haskoin
-- process accepting connections?" — a richer @\/status@ should live in
-- the RPC server, which already exposes chain/peer counts.
healthApp :: Wai.Application
healthApp _req respond =
  respond $ Wai.responseLBS HTTP.status200
    [(HTTP.hContentType, "text/plain; charset=utf-8")]
    (BL8.pack "ok\n")

-- | Run the health endpoint on the given port in a background
-- thread. Returns the spawned 'ThreadId' so the caller can kill it
-- on shutdown. Port @0@ disables the server (returns 'Nothing').
runHealthServer :: Int -> IO (Maybe ThreadId)
runHealthServer 0 = return Nothing
runHealthServer port = do
  tid <- forkIO $ Warp.run port healthApp
                    `catch` (\(e :: SomeException) ->
                               hPutStrLn stderr $
                                 "runHealthServer error: " ++ show e)
  return (Just tid)


--------------------------------------------------------------------------------
-- systemd sd_notify
--------------------------------------------------------------------------------
--
-- The sd_notify protocol is a one-way write to a Unix-domain DGRAM
-- socket whose path is published in the @NOTIFY_SOCKET@ environment
-- variable. We deliberately do NOT depend on any libsystemd / libsd
-- binding: every message is a plain ASCII line, and the OS socket
-- API in @network@ is enough to deliver it.
--
-- Reference: @man 3 sd_notify@ and Bitcoin Core's
-- @src\/util\/syscall_sandbox.cpp@ (which calls @sd_notify@ via the
-- libsystemd-shim include path). We mirror the four messages haskoin
-- actually needs:
--
-- * @READY=1@        — sent once the node finishes initial setup.
-- * @STOPPING=1@     — sent at the top of graceful shutdown.
-- * @STATUS=<text>@  — short human-readable status (height etc.).
-- * @WATCHDOG=1@     — keep-alive ping for @WatchdogSec=@ units.
--
-- All functions are no-ops when @NOTIFY_SOCKET@ is unset (the common
-- case for non-systemd launches), and silently swallow socket errors
-- so a misconfigured supervisor never crashes the node.

-- | Address-family decoder for @NOTIFY_SOCKET@. systemd accepts:
--
-- * Absolute paths beginning with @\/@ (Unix path namespace).
-- * Strings beginning with @\@@ (Linux abstract namespace; the
--   leading @\@@ is replaced by NUL on the wire).
--
-- See @sd_notify(3)@. Other formats are unsupported.
notifySocketAddr :: String -> Maybe Sock.SockAddr
notifySocketAddr s = case s of
  ('/':_)  -> Just (Sock.SockAddrUnix s)
  ('@':rs) -> Just (Sock.SockAddrUnix ('\0' : rs))
  _        -> Nothing

-- | Send a raw notification payload (e.g. @\"READY=1\\n\"@,
-- @\"STATUS=Synced to 947000\\nWATCHDOG=1\\n\"@) to systemd via the
-- @NOTIFY_SOCKET@ datagram socket. No-op if the env var is unset
-- or the socket is unreachable; never raises.
--
-- Multiple variables can be packed into one call by separating them
-- with @\\n@ in the payload (matches @sd_notify@ semantics).
sdNotify :: String -> IO ()
sdNotify msg = do
  mEnv <- lookupEnv "NOTIFY_SOCKET"
  case mEnv >>= notifySocketAddr of
    Nothing   -> return ()
    Just addr -> sendOne addr `catch` swallow
  where
    swallow :: SomeException -> IO ()
    swallow _ = return ()

    sendOne addr = bracket
      (Sock.socket Sock.AF_UNIX Sock.Datagram 0)
      (\s -> Sock.close s `catch` swallow)
      (\s -> do
        Sock.connect s addr
        -- Use sendAll: sd_notify lets the kernel atomically deliver
        -- the whole datagram or fail. EAGAIN/EWOULDBLOCK on a full
        -- queue is rare for sub-128B notifications.
        SockBS.sendAll s (BS8.pack msg))

-- | Notify systemd that startup has completed. Equivalent to
-- @sd_notify(0, "READY=1")@. Call this once, after the node is
-- accepting RPC and P2P traffic.
sdNotifyReady :: IO ()
sdNotifyReady = sdNotify "READY=1\n"

-- | Notify systemd that graceful shutdown has begun. Equivalent to
-- @sd_notify(0, "STOPPING=1")@. Call this from the SIGINT/SIGTERM
-- shutdown path BEFORE long flushes — systemd uses it to extend
-- @TimeoutStopSec=@.
sdNotifyStopping :: IO ()
sdNotifyStopping = sdNotify "STOPPING=1\n"

-- | Send a free-form status string to systemd. Shows up in
-- @systemctl status haskoin@ output. Newlines in @s@ are stripped
-- so the wire format stays single-line.
sdNotifyStatus :: String -> IO ()
sdNotifyStatus s =
  let cleaned = filter (\c -> c /= '\n' && c /= '\r') s
  in sdNotify ("STATUS=" ++ cleaned ++ "\n")

-- | Send a watchdog keep-alive. Required when the unit file sets
-- @WatchdogSec=@; if the daemon goes silent for longer than that
-- interval, systemd will SIGABRT it. Call from a background thread
-- at half the watchdog interval.
sdNotifyWatchdog :: IO ()
sdNotifyWatchdog = sdNotify "WATCHDOG=1\n"

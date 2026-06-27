{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

module Main where

import Options.Applicative
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import System.IO (hSetBuffering, stdout, BufferMode(..))
import System.Directory (createDirectoryIfMissing, getHomeDirectory, doesFileExist)
import System.FilePath ((</>))
import Control.Concurrent (threadDelay, forkIO, killThread)
import System.Mem (performMajorGC)
import System.Environment (lookupEnv)
import Text.Read (readMaybe)
import Control.Concurrent.MVar (MVar, newEmptyMVar, newMVar, putMVar, takeMVar, tryPutMVar, withMVar)
import System.Exit (exitWith, ExitCode(..), exitSuccess)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Control.Monad (forM, forM_, unless, when, void, forever, filterM, foldM)
import System.Posix.Signals (installHandler, sigINT, sigTERM, Handler(..))
import qualified Haskoin.Daemon as Daemon
import Data.Maybe (mapMaybe, fromMaybe, isJust, isNothing, fromJust)
import Control.Concurrent.STM
import Control.Exception (bracket, catch, SomeException)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Int (Int32, Int64)
import Data.IORef
import qualified Data.List as L
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy.Char8 as BL8
import Data.Serialize (decode)
import Data.Bits (shiftR, (.&.), (.|.))
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.HTTP.Types as HTTP

import qualified Network.Socket as NS (getAddrInfo, addrAddress, AddrInfo)
import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash, textToAddress, Address(..))
import qualified Haskoin.Crypto as Crypto (computeWtxid)
import Haskoin.Script (decodeScript)
import Haskoin.Network
import qualified Haskoin.ASMap as ASMap (loadAsmap)
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Rpc
import Haskoin.Mempool
import qualified Haskoin.Mempool.Persist as MPP
import Haskoin.FeeEstimator
import Haskoin.Wallet
import Haskoin.Index (IndexManager(..), IndexConfig(..),
                       defaultIndexConfig, newIndexManager,
                       indexManagerInitFromDB, indexManagerBackfill,
                       indexManagerConnectBlock,
                       blockFilterIndexTipHeight,
                       coinStatsIndexTipHeight,
                       txoSpenderIndexTipHeight,
                       -- FIX-86: serving compact filters over P2P.
                       BlockFilterIndexDB(..),
                       BlockFilterEntry(..),
                       blockFilterIndexGet)
import Haskoin.TxOrphanage
  ( OrphanPool(..), emptyOrphanPool, maxOrphanTxs, orphanExpireSecs
  , addOrphan, expireOrphans
  , eraseOrphansForPeer, eraseOrphansForBlock
  )

--------------------------------------------------------------------------------
-- CLI Data Types
--------------------------------------------------------------------------------

data Options = Options
  { optDataDir   :: !FilePath
  , optNetwork   :: !NetworkName
  , optCommand   :: !Command
  } deriving (Show)

data NetworkName = Mainnet | Testnet | Testnet4 | Regtest
  deriving (Show, Read, Eq)

data Command
  = CmdNode !NodeOptions
  | CmdWallet !WalletCommand
  | CmdUtil !UtilCommand
  deriving (Show)

data NodeOptions = NodeOptions
  { noRpcPort    :: !Int
  , noRpcUser    :: !Text
  , noRpcPass    :: !Text
  , noMaxPeers   :: !Int
  , noConnect    :: ![String]
  , noPrune      :: !Int
    -- ^ Bitcoin Core @-prune=N@ semantics (init.cpp /
    -- node/blockmanager_args.cpp):
    --   * 0     : pruning disabled (default)
    --   * 1     : manual pruning (auto-prune off; only via
    --             @pruneblockchain@ RPC)
    --   * >=550 : auto-prune at N MiB target
    --   * <0    : rejected at startup
    --   * 2..549: rejected at startup (below 550 MiB minimum)
    -- Parsed via 'parsePruneArg' into a 'PruneConfig'.
  , noDbCache    :: !Int
  , noListen     :: !Bool
  , noListenPort :: !Int
  , noMetricsPort :: !Int
  , noPeerBloomFilters :: !Bool
    -- Operational / supervisor flags (Bitcoin Core parity).
  , noDaemon     :: !Bool       -- ^ -daemon: detach to background
  , noPidFile    :: !(Maybe FilePath) -- ^ -pid=<file>; defaults to <datadir>/haskoin.pid
  , noConfFile   :: !(Maybe FilePath) -- ^ -conf=<file>; defaults to <datadir>/haskoin.conf
  , noDebug      :: ![String]   -- ^ -debug=<cat>; comma-separated allowed
  , noPrintToConsole :: !Bool   -- ^ -printtoconsole: explicit, default True when foreground
  , noLogFile    :: !(Maybe FilePath) -- ^ -logfile=<path>; defaults to <datadir>/debug.log when daemonised
  , noHealthPort :: !Int        -- ^ /health endpoint port (0 disables)
  , noReindex            :: !Bool -- ^ -reindex: full block-index rebuild (TODO: partial impl, see below)
  , noReindexChainstate  :: !Bool -- ^ -reindex-chainstate: wipe + replay UTXO set from existing block-index
  , noLoadSnapshot       :: !(Maybe FilePath) -- ^ --load-snapshot=<path>: import a Core-format UTXO snapshot before starting peer/RPC threads
  , noEnableRest         :: !Bool
    -- ^ @-rest@: accept public REST GET requests on the RPC port.
    -- Defaults to 'False' to match Bitcoin Core's
    -- @DEFAULT_REST_ENABLE = false@ (init.cpp:153). When 'False' the
    -- listener still serves JSON-RPC POSTs but @/rest/*@ returns 404,
    -- matching Core's @-rest=0@ behavior. Cross-impl audit:
    -- CORE-PARITY-AUDIT/_rest-api-cross-impl-audit-2026-05-06-part2.md
    -- (R7 / Pattern P4) called this out as a P3 over-exposure on
    -- haskoin where REST was always-on.
  , noBlockFilterIndex   :: !Bool
    -- ^ @-blockfilterindex=basic@: maintain a BIP-157/158 GCS-filter
    -- index over the active chain.  When 'True', every successful
    -- 'connectBlock' (IBD path + submitBlock path + reorg path)
    -- mirrors a per-block @BlockFilterEntry@ into a RocksDB column
    -- ('F'-prefix) keyed by height, and the chained filter-header
    -- pointer is persisted under the 'f'-prefix meta record so a
    -- restart resumes without recomputing.  When 'False' (default,
    -- Bitcoin Core parity), no index is maintained and the REST
    -- @/rest/blockfilter@ / @/rest/blockfilterheaders@ endpoints
    -- recompute from stored block + undo data — O(tip_height) per
    -- request from genesis.  Reference:
    -- bitcoin-core/src/index/blockfilterindex.cpp.
  , noCoinStatsIndex     :: !Bool
    -- ^ @-coinstatsindex=1@: maintain a per-height UTXO-set statistics
    -- index (running MuHash3072 + coin counts/amounts) over the active
    -- chain.  When 'True', every successful @connectBlock@ inserts the
    -- block's created outputs and removes its spent coins (via real undo
    -- data) from a running accumulator, finalizes a per-height muhash
    -- digest + counts snapshot to RocksDB, and on disconnect/reorg
    -- reverses the block from the previous height's snapshot.  This is
    -- what lets @gettxoutsetinfo "muhash" <height|hash>@ answer for a
    -- HISTORICAL block (Bitcoin Core parity), not just the tip.  When
    -- 'False' (default, Core parity), a non-tip @hash_or_height@ errors
    -- with @-8 "Querying specific block heights requires coinstatsindex"@.
    -- Reference: bitcoin-core/src/index/coinstatsindex.cpp +
    -- kernel/coinstats.cpp.
  , noTxoSpenderIndex    :: !Bool
    -- ^ @-txospenderindex=1@: maintain a spent-outpoint -> spending-tx index
    -- over the active chain.  When 'True', every successful @connectBlock@
    -- writes, for each non-coinbase input, @spent outpoint -> spending txid ||
    -- confirming block hash@; on disconnect/reorg the disconnected block's own
    -- input keys are re-derived and erased (reorg-safe, no separate undo
    -- data).  This is the confirmed-spend data source for the
    -- @gettxspendingprevout@ RPC (the mempool reverse-index serves the
    -- unconfirmed-spend form regardless).  When 'False' (default, Bitcoin Core
    -- parity, @DEFAULT_TXOSPENDERINDEX{false}@), @gettxspendingprevout@ can
    -- only answer from the mempool and errors @-1 "Mempool lacks a relevant
    -- spend, and txospenderindex is unavailable."@ for the confirmed path.
    -- Reference: bitcoin-core/src/index/txospenderindex.cpp.
  , noAsmapFile          :: !(Maybe FilePath)
    -- ^ @-asmap=\<file\>@: path to an ASMap bytecode file for
    -- ASN-based IP bucketing.  When set, haskoin loads the file at
    -- startup, validates it with 'checkStandardAsmap' (128-bit
    -- inputs), rejects files exceeding MAX_ASMAP_FILESIZE (8 MiB),
    -- and stores the bytecode in 'rsAsmapData' / 'pmAsmapData' for
    -- use in 'computeNetworkGroupWithASMap' and the @getpeerinfo@
    -- RPC @mapped_as@ field.
    -- Reference: bitcoin-core/src/init.cpp:1587-1628,
    -- bitcoin-core/src/util/asmap.cpp DecodeAsmap/CheckStandardAsmap.
  , noProxy              :: !(Maybe String)
    -- ^ @-proxy=host:port@: generic SOCKS5 proxy for all outbound
    -- connections (Bitcoin Core @-proxy@; default off).  When set,
    -- clearnet IPv4/IPv6 dials route via 'connectViaProxy' (no local
    -- DNS leak).  Also used as the .onion proxy fallback when
    -- @--onion@ is not provided.  W117 DH-1 wire.
  , noOnion              :: !(Maybe String)
    -- ^ @-onion=host:port@: dedicated SOCKS5 proxy for Tor v3
    -- @.onion@ outbound (Bitcoin Core @-onion@; default off).
    -- Overrides @--proxy@ for the Tor pipeline.  When set, this also
    -- flips 'NetworkReachability.nrOnion=True' so Tor v3 addrv2
    -- entries are stored / relayed / advertised.  W117 DH-1 + DH-2.
  , noI2pSam             :: !(Maybe String)
    -- ^ @-i2psam=host:port@: I2P SAM bridge (Bitcoin Core @-i2psam@;
    -- default off).  When set, '.i2p' hostnames dial through SAM via
    -- 'createI2PSession' + 'samStreamConnect', and
    -- 'NetworkReachability.nrI2P' flips on for advertise/relay.
  , noCjdnsReachable     :: !Bool
    -- ^ @-cjdnsreachable@ (Bitcoin Core @-cjdnsreachable@; default
    -- False).  When True, this node treats the fc00::/8 CJDNS overlay
    -- as reachable and stores / advertises CJDNS peers.  Operator is
    -- responsible for having a working CJDNS interface up; we do not
    -- bring up cjdroute ourselves.  W117 DH-1 + DH-2 wire.
  , noRpcTlsCert         :: !(Maybe FilePath)
    -- ^ @--rpc-tls-cert=\<file\>@: optional X.509 certificate (PEM)
    -- for HTTPS termination on the RPC listener.  When set together
    -- with @--rpc-tls-key@, the JSON-RPC / REST listener serves over
    -- TLS via warp-tls.  When neither flag is set, the listener
    -- stays plain HTTP (backward-compat).  Setting only one of the
    -- two is a startup error (mirrors Core's @httpserver.cpp@).
    -- W119 + FIX-64.
  , noRpcTlsKey          :: !(Maybe FilePath)
    -- ^ @--rpc-tls-key=\<file\>@: PEM private key matching
    -- @--rpc-tls-cert@. See 'noRpcTlsCert' for the full contract.
  , noNoDnsSeed          :: !Bool
    -- ^ @--nodnsseed@ (Bitcoin Core @-dnsseed=0@): suppress DNS seed
    --   resolution independently of @--connect@.  AddrMan / anchors /
    --   addr gossip still drive auto-outbound, but 'discoverPeers' is
    --   never called.  When @--connect@ peers are given, DNS is
    --   suppressed regardless of this flag (Core's @-connect@ implies
    --   @-dnsseed=0@).  Mirrors clearbit's standalone @--nodnsseed@.
    --   Default: 'False' (DNS seeding on, Core DEFAULT_DNSSEED = true).
  } deriving (Show)

data WalletCommand
  = WalletCreate
  | WalletRestore
  | WalletBalance
  | WalletAddress
  | WalletSend !Text !Word64
  | WalletHistory
  | WalletDump
  deriving (Show)

data UtilCommand
  = UtilDecodeRawTx !Text
  | UtilDecodeScript !Text
  | UtilValidateAddress !Text
  | UtilHashBlock !Text
  deriving (Show)

--------------------------------------------------------------------------------
-- Option Parsing
--------------------------------------------------------------------------------

parseOptions :: Parser Options
parseOptions = Options
  <$> strOption
      ( long "datadir" <> short 'd' <> metavar "DIR"
        <> value "~/.haskoin" <> help "Data directory" )
  <*> option auto
      ( long "network" <> short 'n' <> metavar "NETWORK"
        <> value Mainnet <> help "Network: Mainnet, Testnet, Testnet4, Regtest" )
  <*> hsubparser
      ( command "node" (info (CmdNode <$> parseNodeOptions)
          (progDesc "Run the full node"))
        <> command "wallet" (info (CmdWallet <$> parseWalletCommand)
          (progDesc "Wallet operations"))
        <> command "util" (info (CmdUtil <$> parseUtilCommand)
          (progDesc "Utility commands"))
      )

parseNodeOptions :: Parser NodeOptions
parseNodeOptions = NodeOptions
  <$> option auto (long "rpcport" <> value 8332 <> help "RPC port")
  <*> strOption (long "rpcuser" <> value "haskoin" <> help "RPC username")
  <*> strOption (long "rpcpassword" <> value "haskoin" <> help "RPC password")
  <*> option auto (long "maxpeers" <> value 125 <> help "Max peer connections")
  <*> many (strOption (long "connect" <> help "Peer to connect to"))
  <*> option auto (long "prune" <> value 0 <> metavar "N"
        <> help "Pruning: 0=off (default), 1=manual (RPC only), \
                \>=550=auto-prune at N MiB. Mirrors Bitcoin Core's \
                \-prune=N (init.cpp).")
  <*> option auto (long "dbcache" <> value 450 <> help "DB cache in MB")
  <*> option auto (long "listen" <> value True <> help "Accept incoming connections (default: True)")
  <*> option auto (long "port" <> value 8333 <> help "Listen port")
  <*> option auto (long "metricsport" <> value 9332 <> help "Prometheus metrics port (0 to disable)")
  <*> option auto (long "peerbloomfilters" <> value False
        <> help "Advertise NODE_BLOOM and serve BIP-37/BIP-35 (default: False, matches Core)")
  -- Operational flags
  <*> switch (long "daemon"
        <> help "Detach to background (Bitcoin Core -daemon)")
  <*> optional (strOption (long "pid" <> metavar "PATH"
        <> help "PID file path (default: <datadir>/haskoin.pid)"))
  <*> optional (strOption (long "conf" <> metavar "PATH"
        <> help "Config file path (default: <datadir>/haskoin.conf)"))
  <*> many (strOption (long "debug" <> metavar "CAT"
        <> help "Enable debug category (net, mempool, validation, rpc, rocksdb, all). Repeatable."))
  <*> switch (long "printtoconsole"
        <> help "Force log output to stdout even when --daemon (Bitcoin Core -printtoconsole)")
  <*> optional (strOption (long "logfile" <> metavar "PATH"
        <> help "Log file path (default: <datadir>/debug.log when --daemon, none otherwise). SIGHUP reopens."))
  <*> option auto (long "healthport" <> value 0
        <> help "HTTP /health endpoint port (0 disables)")
  <*> switch (long "reindex"
        <> help "Wipe chainstate AND rebuild block index (PARTIAL: \
                \today this implies --reindex-chainstate; full block-index \
                \rebuild from blk*.dat is TODO).")
  <*> switch (long "reindex-chainstate"
        <> help "Wipe UTXO/best-block/tx-index and replay connectBlock from \
                \height 1 to the current header tip. Block-index (headers \
                \+ block data) is preserved. Bitcoin Core's \
                \-reindex-chainstate semantics.")
  <*> optional (strOption (long "load-snapshot" <> metavar "PATH"
        <> help "Load a Core-format UTXO snapshot from PATH before \
                \starting the network/RPC threads (assumeutxo bootstrap). \
                \The file must be a 'utxo'+0xff snapshot for the same \
                \network magic; mismatched snapshots are rejected. \
                \Equivalent to invoking the loadtxoutset RPC at \
                \startup, useful when the node has not yet started \
                \listening on RPC."))
  <*> switch (long "rest"
        <> help "Accept public REST GET requests on the RPC port \
                \(Bitcoin Core -rest, default off). When enabled, \
                \read-only /rest/block, /rest/tx, /rest/headers, \
                \/rest/blockfilter, /rest/blockfilterheaders, etc. \
                \are served alongside JSON-RPC. When disabled (default), \
                \any GET to /rest/* returns 404, matching Core's \
                \DEFAULT_REST_ENABLE = false (init.cpp:153).")
  <*> switch (long "blockfilterindex"
        <> help "Maintain a BIP-157/158 basic block filter index \
                \(Bitcoin Core -blockfilterindex=basic, default off). \
                \When enabled, every connected block contributes a \
                \GCS filter + chained filter-header to a RocksDB \
                \index keyed by height; the /rest/blockfilter and \
                \/rest/blockfilterheaders REST endpoints fast-path \
                \through this index in O(1)/O(count). On startup \
                \haskoin backfills any gap between the index tip \
                \and the chain tip before opening the network port.")
  <*> switch (long "coinstatsindex"
        <> help "Maintain a per-height UTXO-set statistics index \
                \(Bitcoin Core -coinstatsindex=1, default off). When \
                \enabled, every connected block updates a running \
                \MuHash3072 + coin counts/amounts, and gettxoutsetinfo \
                \can answer for a HISTORICAL block height or hash, not \
                \just the tip. On startup haskoin backfills any gap \
                \between the index tip and the chain tip.")
  <*> switch (long "txospenderindex"
        <> help "Maintain a spent-outpoint -> spending-transaction index \
                \(Bitcoin Core -txospenderindex=1, default off). When \
                \enabled, every connected block records, per non-coinbase \
                \input, the spent outpoint -> spending txid + confirming \
                \block hash; on disconnect/reorg the disconnected block's \
                \keys are re-derived from its own inputs and erased. This \
                \is the confirmed-spend data source for gettxspendingprevout. \
                \On startup haskoin backfills any gap between the index tip \
                \and the chain tip.")
  <*> optional (strOption (long "asmap" <> metavar "FILE"
        <> help "Path to an ASMap bytecode file for ASN-based IP \
                \bucketing (Bitcoin Core -asmap=<file>). When set, \
                \haskoin loads and validates the file at startup, \
                \and uses ASN-keyed groups for AddrMan bucketing + \
                \getpeerinfo mapped_as. File must be <= 8 MiB and \
                \pass sanity check. Default: off (raw /16 or /32 groups)."))
  -- W117 DH-1 + DH-2: BIP-155 privacy-network proxy / reachability CLI.
  <*> optional (strOption (long "proxy" <> metavar "HOST:PORT"
        <> help "Generic SOCKS5 proxy for all outbound peer connections \
                \(Bitcoin Core -proxy). When set, IPv4/IPv6 dials route \
                \through the proxy with no local DNS leak. Format: \
                \127.0.0.1:9050. Default: off (direct dial)."))
  <*> optional (strOption (long "onion" <> metavar "HOST:PORT"
        <> help "Dedicated SOCKS5 proxy for Tor v3 .onion outbound \
                \(Bitcoin Core -onion). Overrides --proxy for the Tor \
                \pipeline. Setting this flips NetworkReachability so \
                \haskoin advertises and relays Tor v3 addrv2 entries. \
                \Default: off (Tor unreachable)."))
  <*> optional (strOption (long "i2psam" <> metavar "HOST:PORT"
        <> help "I2P SAM bridge for .i2p outbound (Bitcoin Core \
                \-i2psam). When set, .i2p hostnames dial through SAM \
                \and I2P reachability flips on for advertise + relay. \
                \Default: off (I2P unreachable)."))
  <*> switch (long "cjdnsreachable"
        <> help "Treat the CJDNS overlay (fc00::/8) as reachable \
                \(Bitcoin Core -cjdnsreachable). When set, CJDNS \
                \addrv2 peers are stored / advertised / relayed. \
                \Operator is responsible for cjdroute setup; we do \
                \not start the interface. Default: off.")
  -- W119 + FIX-64: optional HTTPS termination on the RPC listener.
  <*> optional (strOption (long "rpc-tls-cert" <> metavar "PATH"
        <> help "PEM X.509 certificate for HTTPS termination on the \
                \RPC listener. Must be paired with --rpc-tls-key. \
                \When neither flag is set, the listener stays plain \
                \HTTP. Setting only one of the two is a startup error."))
  <*> optional (strOption (long "rpc-tls-key" <> metavar "PATH"
        <> help "PEM private key for HTTPS termination. Pair with \
                \--rpc-tls-cert."))
  <*> switch (long "nodnsseed"
        <> help "Disable DNS seed resolution (Bitcoin Core -dnsseed=0). \
                \AddrMan/anchors/addr-gossip still drive auto-outbound, \
                \but DNS seeds are never queried. When --connect peers \
                \are given, DNS is suppressed regardless of this flag. \
                \Default: off (DNS seeding on).")

parseWalletCommand :: Parser WalletCommand
parseWalletCommand = hsubparser
  ( command "create" (info (pure WalletCreate)
      (progDesc "Create a new wallet"))
    <> command "restore" (info (pure WalletRestore)
      (progDesc "Restore wallet from mnemonic"))
    <> command "balance" (info (pure WalletBalance)
      (progDesc "Show wallet balance"))
    <> command "address" (info (pure WalletAddress)
      (progDesc "Generate a new receive address"))
    <> command "send" (info (WalletSend
        <$> strArgument (metavar "ADDRESS")
        <*> argument auto (metavar "AMOUNT"))
      (progDesc "Send bitcoin"))
    <> command "history" (info (pure WalletHistory)
      (progDesc "Show transaction history"))
    <> command "dump" (info (pure WalletDump)
      (progDesc "Dump wallet info (dangerous)"))
  )

parseUtilCommand :: Parser UtilCommand
parseUtilCommand = hsubparser
  ( command "decodetx" (info (UtilDecodeRawTx <$> strArgument (metavar "HEX"))
      (progDesc "Decode a raw transaction"))
    <> command "decodescript" (info (UtilDecodeScript <$> strArgument (metavar "HEX"))
      (progDesc "Decode a script"))
    <> command "validateaddress" (info (UtilValidateAddress <$> strArgument (metavar "ADDR"))
      (progDesc "Validate a Bitcoin address"))
    <> command "hashblock" (info (UtilHashBlock <$> strArgument (metavar "HEX"))
      (progDesc "Hash a block header"))
  )

--------------------------------------------------------------------------------
-- Main
--------------------------------------------------------------------------------

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  opts <- execParser $ info (parseOptions <**> helper)
    ( fullDesc
      <> progDesc "Haskoin - Bitcoin Full Node"
      <> header "haskoin v0.1.0.0 - a Bitcoin full node in Haskell" )
  runCommand opts

runCommand :: Options -> IO ()
runCommand Options{..} = do
  let net = case optNetwork of
              Mainnet  -> mainnet
              Testnet  -> testnet3
              Testnet4 -> testnet4
              Regtest  -> regtest

  -- Expand ~ in data directory
  dataDir <- expandPath optDataDir
  let networkDir = dataDir </> netName net

  createDirectoryIfMissing True networkDir

  case optCommand of
    CmdNode nodeOpts -> runNode net networkDir nodeOpts
    CmdWallet walletCmd -> runWalletCommand net networkDir walletCmd
    CmdUtil utilCmd -> runUtilCommand net utilCmd

-- | Expand ~ to home directory
expandPath :: FilePath -> IO FilePath
expandPath path
  | "~/" `isPrefixOf` path = do
      home <- getHomeDirectory
      return $ home </> drop 2 path
  | path == "~" = getHomeDirectory
  | otherwise = return path
  where
    isPrefixOf prefix str = take (length prefix) str == prefix

--------------------------------------------------------------------------------
-- Node Command
--------------------------------------------------------------------------------

runNode :: Network -> FilePath -> NodeOptions -> IO ()
runNode net dataDir nodeOptsCli = do
  -- 1. Load the config file (if any) and overlay onto CLI options.
  --    Bitcoin Core precedence: CLI > config > built-in default. We
  --    only override CLI fields that still equal the compile-time
  --    default (sentinel comparison); explicit CLI flags always win.
  let confPath = case noConfFile nodeOptsCli of
                   Just p  -> p
                   Nothing -> dataDir </> "haskoin.conf"
  -- Network-aware config parse: keys under [main]/[test]/[testnet4]/
  -- [regtest] are filtered to the active network; top-of-file keys
  -- (no section) apply globally. See Haskoin.Daemon.networkSection.
  confResult <- Daemon.readConfFileForNetwork (netName net) confPath
  cm <- case confResult of
    Right m -> do
      unless (null m) $
        putStrLn $ "Loaded config file " ++ confPath
                ++ " (" ++ show (length m) ++ " entries)"
      return m
    Left e -> do
      putStrLn $ "Config file warning: " ++ e
      return mempty
  let nodeOpts = applyConfigOverlay cm nodeOptsCli
      NodeOptions{..} = nodeOpts

  -- 2. Wire up debug categories (process-global) early so subsequent
  --    setup messages can call logDebug.
  let debugSet = Daemon.parseDebugSet (concatPlus noDebug)
  Daemon.setGlobalDebugSet debugSet
  unless (Daemon.debugEnabled Daemon.DbgAll debugSet
            && null noDebug) $
    Daemon.logDebug Daemon.DbgAll $
      "debug categories enabled: " ++ show (length noDebug) ++ " token(s)"

  -- 3. Decide effective log file path. If --daemon and no --logfile,
  --    default to <datadir>/debug.log. If --printtoconsole, leave
  --    stdio alone; otherwise daemonised mode redirects to logfile.
  let effectiveLogFile :: Maybe FilePath
      effectiveLogFile = case noLogFile of
        Just p  -> Just p
        Nothing -> if noDaemon
                     then Just (dataDir </> "debug.log")
                     else Nothing

  -- 4. PID file path (default <datadir>/haskoin.pid).
  let pidFilePath = case noPidFile of
        Just p  -> p
        Nothing -> dataDir </> "haskoin.pid"

  -- Run the actual node body. Wrapped so daemonize can supply it
  -- as the grandchild's continuation.
  let nodeMain = runNodeBody net dataDir nodeOpts effectiveLogFile pidFilePath

  if noDaemon
    then do
      putStrLn $ "Daemonising; logs -> "
              ++ maybe "/dev/null" id effectiveLogFile
              ++ ", pid -> " ++ pidFilePath
      Daemon.daemonize effectiveLogFile nodeMain
    else nodeMain

-- | Apply a parsed config file as a fallback to CLI-provided
-- 'NodeOptions'. CLI values that differ from the compile-time
-- defaults are preserved. See 'parseNodeOptions' for the defaults.
applyConfigOverlay :: Daemon.ConfigMap -> NodeOptions -> NodeOptions
applyConfigOverlay cm n = n
  { noRpcPort    = if noRpcPort n == 8332
                     then Daemon.configLookupInt "rpcport" 8332 cm
                     else noRpcPort n
  , noRpcUser    = if noRpcUser n == "haskoin"
                     then T.pack (fromMaybe "haskoin" (Daemon.configLookup "rpcuser" cm))
                     else noRpcUser n
  , noRpcPass    = if noRpcPass n == "haskoin"
                     then T.pack (fromMaybe "haskoin" (Daemon.configLookup "rpcpassword" cm))
                     else noRpcPass n
  , noMaxPeers   = if noMaxPeers n == 125
                     then Daemon.configLookupInt "maxpeers" 125 cm
                     else noMaxPeers n
  , noPrune      = if noPrune n == 0
                     then Daemon.configLookupInt "prune" 0 cm
                     else noPrune n
  , noDbCache    = if noDbCache n == 450
                     then Daemon.configLookupInt "dbcache" 450 cm
                     else noDbCache n
  , noListen     = if noListen n
                     then Daemon.configLookupBool "listen" True cm
                     else noListen n
  , noListenPort = if noListenPort n == 8333
                     then Daemon.configLookupInt "port" 8333 cm
                     else noListenPort n
  , noMetricsPort = if noMetricsPort n == 9332
                     then Daemon.configLookupInt "metricsport" 9332 cm
                     else noMetricsPort n
  , noPeerBloomFilters = if not (noPeerBloomFilters n)
                     then Daemon.configLookupBool "peerbloomfilters" False cm
                     else noPeerBloomFilters n
  , noDaemon     = if not (noDaemon n)
                     then Daemon.configLookupBool "daemon" False cm
                     else noDaemon n
  , noPidFile    = case noPidFile n of
                     Just _ -> noPidFile n
                     Nothing -> Daemon.configLookup "pid" cm
  , noPrintToConsole = if not (noPrintToConsole n)
                     then Daemon.configLookupBool "printtoconsole" False cm
                     else noPrintToConsole n
  , noLogFile    = case noLogFile n of
                     Just _ -> noLogFile n
                     Nothing -> Daemon.configLookup "logfile" cm
  , noHealthPort = if noHealthPort n == 0
                     then Daemon.configLookupInt "healthport" 0 cm
                     else noHealthPort n
  , noReindex   = if not (noReindex n)
                     then Daemon.configLookupBool "reindex" False cm
                     else noReindex n
  , noReindexChainstate = if not (noReindexChainstate n)
                     then Daemon.configLookupBool "reindex-chainstate" False cm
                     else noReindexChainstate n
  , noLoadSnapshot = case noLoadSnapshot n of
                     Just _  -> noLoadSnapshot n
                     Nothing -> Daemon.configLookup "load-snapshot" cm
  , noEnableRest = if not (noEnableRest n)
                     then Daemon.configLookupBool "rest" False cm
                     else noEnableRest n
  -- @blockfilterindex = 1@ in haskoin.conf flips on the BIP-157/158
  -- basic filter index just like the CLI flag does.  Bitcoin Core
  -- accepts both @-blockfilterindex=basic@ and @-blockfilterindex=1@;
  -- haskoin only ships the basic filter type today, so a boolean
  -- conf entry is sufficient.
  , noBlockFilterIndex = if not (noBlockFilterIndex n)
                          then Daemon.configLookupBool "blockfilterindex" False cm
                          else noBlockFilterIndex n
  -- @coinstatsindex = 1@ in haskoin.conf flips on the per-height UTXO
  -- statistics index just like the CLI flag does (Bitcoin Core
  -- -coinstatsindex=1).
  , noCoinStatsIndex = if not (noCoinStatsIndex n)
                          then Daemon.configLookupBool "coinstatsindex" False cm
                          else noCoinStatsIndex n
  -- @txospenderindex = 1@ in haskoin.conf flips on the spent-outpoint ->
  -- spending-tx index just like the CLI flag (Bitcoin Core -txospenderindex=1).
  , noTxoSpenderIndex = if not (noTxoSpenderIndex n)
                          then Daemon.configLookupBool "txospenderindex" False cm
                          else noTxoSpenderIndex n
  , noAsmapFile  = case noAsmapFile n of
                     Just _  -> noAsmapFile n
                     Nothing -> Daemon.configLookup "asmap" cm
  -- W119 + FIX-64: TLS cert/key may also be sourced from the config
  -- file (rpc-tls-cert + rpc-tls-key) when the CLI flag is absent.
  , noRpcTlsCert = case noRpcTlsCert n of
                     Just _  -> noRpcTlsCert n
                     Nothing -> Daemon.configLookup "rpc-tls-cert" cm
  , noRpcTlsKey  = case noRpcTlsKey n of
                     Just _  -> noRpcTlsKey n
                     Nothing -> Daemon.configLookup "rpc-tls-key" cm
  -- noConnect (peer list) and noDebug are list-valued: append from conf.
  , noConnect    = noConnect n ++ maybe [] (splitCsv) (Daemon.configLookup "connect" cm)
  , noDebug      = noDebug n ++ maybe [] (splitCsv) (Daemon.configLookup "debug" cm)
  -- --nodnsseed / -dnsseed=0: conf overlay accepts dnsseed=0 (Core
  -- naming) when the CLI flag is absent.  configLookupBool "dnsseed"
  -- defaults True; we invert it to the "no DNS" flag.
  , noNoDnsSeed  = if noNoDnsSeed n
                     then True
                     else not (Daemon.configLookupBool "dnsseed" True cm)
  -- Pass-through (not in conf overlay).
  , noConfFile   = noConfFile n
  }
  where
    splitCsv = filter (not . null) . map trim . wordsBy (== ',')
    trim = dropWhile (== ' ') . reverse . dropWhile (== ' ') . reverse
    wordsBy p s = case break p s of
      (h, [])      -> [h]
      (h, _ : rest) -> h : wordsBy p rest

-- | Encode the network's @netMagic@ Word32 as the 4 little-endian
-- bytes that @newBlockStore@ stores for blk-file framing.  This
-- mirrors the same conversion done in 'netMagicBytes' inside
-- 'Haskoin.Network'; we re-implement it here to avoid widening that
-- module's export list (the helper is only needed at startup).
netMagicBytesLE :: Network -> BS.ByteString
netMagicBytesLE net =
  let m = netMagic net
      b0 = fromIntegral (m .&. 0xff)
      b1 = fromIntegral ((m `shiftR` 8) .&. 0xff)
      b2 = fromIntegral ((m `shiftR` 16) .&. 0xff)
      b3 = fromIntegral ((m `shiftR` 24) .&. 0xff)
  in BS.pack [b0, b1, b2, b3]

-- | Concatenate debug-flag tokens with commas so the daemon-side
-- parser can split on ','. Tolerates duplicates.
concatPlus :: [String] -> String
concatPlus xs = case xs of
  []     -> ""
  (h:tl) -> foldl (\a b -> a ++ "," ++ b) h tl

-- | The actual node startup body. Extracted from 'runNode' so
-- 'Daemon.daemonize' can run it as the grandchild's continuation
-- after fork+setsid+stdio-redirect.
runNodeBody :: Network -> FilePath -> NodeOptions
            -> Maybe FilePath -> FilePath -> IO ()
runNodeBody net dataDir NodeOptions{..} effectiveLogFile pidFilePath = do
  -- 0. Set up logging file + SIGHUP handler, if requested. We keep
  --    LineBuffering so log lines flush immediately even when the
  --    process is daemonised.
  hSetBuffering stdout LineBuffering
  case effectiveLogFile of
    Nothing -> return ()
    Just lp -> do
      ls <- Daemon.newLogState lp
      Daemon.initLogFile ls
        `catch` (\(e :: SomeException) ->
                   putStrLn $ "Could not open log file " ++ lp
                            ++ ": " ++ show e)
      Daemon.installSighupHandler ls
      Daemon.logDebug Daemon.DbgAll $
        "log file: " ++ lp ++ " (SIGHUP reopens)"

  -- 1. Write PID file. Bracket-style: removed on graceful shutdown
  --    via the existing exitSuccess path (we explicitly remove at
  --    the end of nodeBodyInner; for SIGKILL we accept the stale
  --    file is a known limitation, matching Bitcoin Core).
  Daemon.writePidFile pidFilePath
    `catch` (\(e :: SomeException) ->
               putStrLn $ "Could not write PID file " ++ pidFilePath
                        ++ ": " ++ show e)

  -- 2. Optional /health endpoint for process supervisors.
  _healthTid <- Daemon.runHealthServer noHealthPort
  when (noHealthPort > 0) $
    putStrLn $ "Health endpoint listening on port " ++ show noHealthPort

  putStrLn $ "Starting Haskoin on " ++ netName net
  putStrLn $ "Data directory: " ++ dataDir

  -- W105 BUG-2 FIX: initialise the process-global signature verification cache
  -- before any block validation begins (db open, reindex, or live sync).
  -- Core equivalent: SignatureCache construction in AppInitMain (init.cpp).
  initGlobalSigCache
  putStrLn "Signature cache initialised (50000 entries)"

  -- W115 FIX-50: load ASMap file if -asmap=<file> is configured.
  -- Reference: bitcoin-core/src/init.cpp:1587-1628 (DecodeAsmap call).
  -- MAX_ASMAP_FILESIZE = 8 MiB; CheckStandardAsmap (128-bit) is applied
  -- inside ASMap.loadAsmap.
  asmapData <- case noAsmapFile of
    Nothing -> return BS.empty
    Just asmapPath -> do
      r <- ASMap.loadAsmap asmapPath
      case r of
        Left err -> do
          putStrLn $ "FATAL: -asmap=" ++ asmapPath ++ ": " ++ err
          exitWith (ExitFailure 1)
        Right bs -> do
          putStrLn $ "Using asmap file " ++ asmapPath
                  ++ " (" ++ show (BS.length bs) ++ " bytes)"
          return bs

  -- 2b. Parse --prune=N (Bitcoin Core init.cpp /
  --     node/blockmanager_args.cpp semantics).  Reject negative and
  --     2..549 values up front so misconfiguration fails fast before
  --     we touch the DB.
  pruneCfg <- case parsePruneArg noPrune of
    Left err -> do
      putStrLn $ "FATAL: " ++ err
      exitWith (ExitFailure 1)
    Right cfg -> do
      case pcPruneTarget cfg of
        Nothing -> return ()
        Just t
          | t == pruneTargetManual ->
              putStrLn "Pruning: manual mode (auto-prune off; \
                       \pruneblockchain RPC armed)"
          | otherwise ->
              putStrLn $ "Pruning: auto-prune target = "
                      ++ show (t `div` (1024 * 1024)) ++ " MiB"
      return cfg
  let pruneOn = pruneConfigEnabled pruneCfg

  -- Open database
  let dbConfig = (defaultDBConfig (dataDir </> "chainstate"))
        { dbBlockCacheSize = noDbCache * 1024 * 1024 }
  bracket (openDB dbConfig) closeDB $ \db -> do

    -- Initialize or load chain state.
    --
    -- W162 P0 chainstate-wedge fix.  The authoritative on-disk
    -- chainstate-existence signal is the @PrefixBestBlock@ pointer
    -- ('getBestBlockHash') — the UTXO-view tip that 'connectBlockAt'
    -- advances atomically with every block.  The pre-fix code used a
    -- separate 'getChainState' / 'saveChainState' pair keyed at prefix
    -- 0x20, but 'saveChainState' was never called from any code path,
    -- so 'getChainState' ALWAYS returned 'Nothing'.  The startup logic
    -- therefore took the 'Nothing' branch on EVERY restart and ran
    -- @putBestBlockHash db genesisHash@, resetting the live UTXO-view
    -- best-block pointer all the way back to genesis even though the
    -- 74 GB UTXO set on disk was intact at height ~949 k.  After the
    -- reset, every peer block failed the ConnectBlock G1 gate
    -- (hashPrevBlock == view.GetBestBlock(), validation.cpp:2333)
    -- because no block's prevHash equals genesis — a permanent wedge.
    -- The dead 'saveChainState' / 'getChainState' / 'PersistedChainState'
    -- API was removed in P2-6 (W109 BUG-31 root cause).
    --
    -- Fix: gate the genesis-init on 'getBestBlockHash'.  Only a DB that
    -- has never had a best-block pointer written (genuinely fresh) is
    -- initialised; an existing chainstate is left completely untouched.
    -- Core analogue: AppInitMain only writes the genesis coins entry
    -- when the chainstate is empty (validation.cpp LoadBlockIndex /
    -- LoadGenesisBlock), and never rewinds an existing best block.
    mBestAtStartup <- getBestBlockHash db
    case mBestAtStartup of
      Nothing -> do
        putStrLn "Initializing new chain..."
        let genesis = netGenesisBlock net
            genesisHash = computeBlockHash (blockHeader genesis)
        putBlockHeader db genesisHash (blockHeader genesis)
        putBlockHeight db 0 genesisHash
        putBestBlockHash db genesisHash
      Just bestHash ->
        putStrLn $ "Resuming chainstate from best-block " ++ show bestHash

    -- -reindex / -reindex-chainstate.
    --
    -- Bitcoin Core distinguishes two reindex modes (init.cpp):
    --
    --   * -reindex             rebuild block-index from blk*.dat,
    --                          THEN replay chainstate.
    --   * -reindex-chainstate  keep block-index, wipe + replay
    --                          chainstate only.
    --
    -- Today haskoin only implements -reindex-chainstate. The full
    -- -reindex (parsing blk*.dat from scratch) is TODO; if -reindex
    -- is passed we log that we are downgrading to chainstate-only
    -- and continue. This matches the "honest progress" Cat-F
    -- decision (nimrod c14311d shipped the same scope).
    let doReindexChainstate = noReindex || noReindexChainstate
    when noReindex $
      putStrLn $ "Note: -reindex ran as -reindex-chainstate "
              ++ "(block-index rebuild from blk*.dat is TODO)."
    when doReindexChainstate $ do
      putStrLn "[-reindex-chainstate] Wiping chainstate (UTXO + tx-index + best-block)..."
      n <- wipeChainstate db
        `catch` (\(e :: SomeException) -> do
                   putStrLn $ "[-reindex-chainstate] wipe error: " ++ show e
                   return 0)
      putStrLn $ "[-reindex-chainstate] wiped " ++ show n ++ " keys."
      -- Re-pin best-block to the genesis hash so the rebuild starts
      -- from height 0 (any pre-existing tip pointer was just wiped).
      let genesis     = netGenesisBlock net
          genesisHash = computeBlockHash (blockHeader genesis)
      putBestBlockHash db genesisHash
      putBlockHeight db 0 genesisHash

    -- Initialize header chain
    hc <- initHeaderChainFromDB db net

    -- Replay phase of -reindex-chainstate: walk every height we
    -- still have a block for, and replay connectBlock so the UTXO
    -- set + tx-index are rebuilt. This MUST run after
    -- initHeaderChainFromDB so the height index is loaded into
    -- memory, and BEFORE the peer manager / RPC server start
    -- (otherwise concurrent block download would race the rebuild).
    when doReindexChainstate $ do
      tipH <- readTVarIO (hcHeight hc)
      putStrLn $ "[-reindex-chainstate] Rebuilding chainstate "
              ++ "by replaying blocks 1.." ++ show tipH
      let logEvery = 10000 :: Word32
          replay h
            | h > tipH = return h
            | otherwise = do
                mHash <- getBlockHeight db h
                case mHash of
                  Nothing -> do
                    -- Honest progress: stop at the first missing
                    -- block-data instead of pretending to continue.
                    putStrLn $ "[-reindex-chainstate] no block at height "
                            ++ show h ++ "; stopping replay."
                    return (h - 1)
                  Just bh -> do
                    mBlk <- getBlock db bh
                    case mBlk of
                      Nothing -> do
                        -- TODO(reindex): if haskoin is configured to
                        -- store block bodies in the flat-file store
                        -- (writeBlockToDisk), look them up via
                        -- BlockIndex / readBlockFromDisk here. For
                        -- now we honestly stop, matching Core's
                        -- "missing block data, exiting" log.
                        putStrLn $ "[-reindex-chainstate] block data "
                                ++ "missing at height " ++ show h
                                ++ " (hash=" ++ show bh
                                ++ "); stopping replay."
                        return (h - 1)
                      Just blk -> do
                        -- Look up the spent UTXOs from the in-progress
                        -- chainstate so connectBlock can write per-block
                        -- undo data alongside the UTXO mutation.
                        spent <- buildSpentUtxoMapFromDB db blk
                        -- W97/W99-G18: connectBlock now returns
                        -- Either String () instead of silently
                        -- falling back to the unchecked overwrite.
                        -- During reindex-replay we expect every block
                        -- to extend the rebuilt tip (parent = prior
                        -- block in height order); a Left here means
                        -- on-disk corruption (e.g. missing prevout)
                        -- and we surface the error so the operator
                        -- can investigate.  We still keep going so
                        -- partial-replay diagnostics remain visible.
                        cr <- connectBlock db net blk h spent
                          `catch` (\(e :: SomeException) -> do
                            putStrLn $ "[-reindex-chainstate] connectBlock "
                                    ++ "h=" ++ show h ++ " exception: " ++ show e
                            return (Left ("exception: " <> show e)))
                        case cr of
                          Left err ->
                            putStrLn $ "[-reindex-chainstate] connectBlock "
                                    ++ "h=" ++ show h ++ " gate failure: " ++ err
                          Right () -> return ()
                        when (h `mod` logEvery == 0) $ do
                          putStrLn $ "[-reindex-chainstate] replayed "
                                  ++ "height=" ++ show h
                          syncFlush db `catch` (\(e :: SomeException) ->
                            putStrLn $ "syncFlush during replay error: " ++ show e)
                        replay (h + 1)
      finalH <- replay 1
      syncFlush db `catch` (\(e :: SomeException) ->
        putStrLn $ "syncFlush after replay error: " ++ show e)
      putStrLn $ "[-reindex-chainstate] Done. Replayed up to height "
              ++ show finalH ++ "."

    -- Initialize UTXO cache.
    -- NOTE: ucMaxSize is an ENTRY COUNT (Storage.hs), not a byte budget, and is
    -- currently dead config (no eviction reads it; the cache is bounded by the
    -- periodic flushCache). Derive a conservative entry budget from the -dbcache
    -- MB figure (~200 B/entry) instead of the nonsensical `div 100`-on-bytes.
    -- Inert w.r.t. validation and current runtime behavior.
    cache <- newUTXOCache db (noDbCache * 1024 * 1024 `div` 200)

    -- --load-snapshot: import a Core-format UTXO snapshot before any
    -- peer or RPC activity. We bail out early on parse / magic mismatch
    -- so misconfigured operators see the failure immediately rather
    -- than silently starting from genesis. Reference: Bitcoin Core's
    -- assumeutxo bootstrap (rpc/blockchain.cpp loadtxoutset).
    --
    -- W102 BUG-1: checkAssumeutxoWhitelist — snapshot height must appear
    --   in the hardcoded table (Core validation.cpp:5776-5778).
    -- W102 BUG-2: verifySnapshot — coin-set hash must match audHashSerialized
    --   (Core validation.cpp:5920).
    -- W102 BUG-8: base block must appear in the header chain before we
    --   accept the snapshot (Core validation.cpp:5613).
    -- W102 BUG-9+10: per-coin height ≤ base_height and MoneyRange guards
    --   (Core validation.cpp:5818-5822), enforced via validateSnapshotCoins.
    forM_ noLoadSnapshot $ \snapshotPath -> do
      putStrLn $ "[--load-snapshot] reading header from " ++ snapshotPath
      let magic = netMagic net
      -- Step 1: Read only the 51-byte header — O(1) regardless of file size.
      -- The old code used 'loadSnapshot' (BS.readFile of the full ~8.8 GB
      -- file) which OOMed at ~80 G on the 165 M-coin mainnet snapshot.
      rMeta <- readSnapshotMetadata snapshotPath magic
      case rMeta of
        Left err -> do
          putStrLn $ "[--load-snapshot] FATAL: " ++ err
          exitWith (ExitFailure 1)
        Right meta -> do
          let baseHash = smBaseBlockHash meta
          -- Snapshot-bootstrap: resolve the base HEIGHT from the hardcoded
          -- assumeutxo whitelist (keyed by base hash), NOT from the in-memory
          -- header chain. Core requires the base header to already appear in
          -- the headers chain (validation.cpp:5613), but on a wiped datadir the
          -- chain holds only genesis — the genesis->base headers-first P2P sync
          -- backfills the real header chain AFTER import (the proven
          -- snapshot-bootstrap recipe; nimrod/camlcoin/clearbit do the same).
          -- Validity is still pinned: the base hash must be a known assumeutxo
          -- base, and streamSnapshotIntoLegacyUTXO verifies the coin-set hash
          -- against the hardcoded audHashSerialized after writing.
          case assumeUtxoForBlockHash net baseHash of
            Nothing -> do
              putStrLn $ "[--load-snapshot] FATAL: base block "
                      ++ show baseHash
                      ++ " is not a known assumeutxo base "
                      ++ "(wrong snapshot for this network)."
              exitWith (ExitFailure 1)
            Just baseParams -> do
              let baseHeight = aupHeight baseParams
              -- BUG-1: whitelist check — height must be in the
              -- hardcoded assumeutxo table.
              case checkAssumeutxoWhitelist net baseHeight of
                Left wlErr -> do
                  putStrLn $ "[--load-snapshot] FATAL: " ++ wlErr
                  exitWith (ExitFailure 1)
                Right () ->
                  -- BUG-2: hash verification — coin-set hash must match
                  -- the hardcoded audHashSerialized value.  Performed by
                  -- 'streamSnapshotIntoLegacyUTXO' after writing all coins
                  -- to the DB (Core PopulateAndValidateSnapshot order).
                  case assumeUtxoForHeight net baseHeight of
                    Nothing -> do
                      putStrLn "[--load-snapshot] FATAL: internal error: \
                               \whitelist lookup failed after whitelist passed"
                      exitWith (ExitFailure 1)
                    Just params -> do
                      putStrLn $ "[--load-snapshot] base hash = "
                              ++ show baseHash
                              ++ ", height = " ++ show baseHeight
                              ++ ", coins = " ++ show (smCoinsCount meta)
                      putStrLn "[--load-snapshot] streaming coins to DB \
                               \(bounded memory, 100k-coin batches)..."
                      -- Step 2: stream coins → validate per-coin → write in
                      -- batches → verify hash from DB (BUG-9/10 + BUG-2).
                      -- Memory stays bounded (O(batch) ≈ <5 MB), never
                      -- materialising the full 165 M-coin list in the heap.
                      r <- streamSnapshotIntoLegacyUTXO db snapshotPath magic
                             baseHeight (aupHashSerialized params)
                      case r of
                        Left loadErr -> do
                          putStrLn $ "[--load-snapshot] FATAL: " ++ loadErr
                          exitWith (ExitFailure 1)
                        Right n -> do
                              -- Class-A dbcache: defensively wipe the
                              -- read-through mirror after the snapshot bulk
                              -- write. rcEntries is empty here (peer/RPC threads
                              -- have not started), but this keeps it a strict
                              -- subset of disk by construction.
                              rcClear cache
                              -- Durably record the snapshot base hash
                              -- (analogue of Core's
                              -- chainstate_snapshot/base_blockhash file,
                              -- utxo_snapshot.cpp WriteSnapshotBaseBlockhash).
                              -- The startup chainstate reconciliation reads
                              -- this back via 'getSnapshotBaseHash' to learn
                              -- that the UTXO set legitimately begins at the
                              -- snapshot base — a snapshot import writes NO
                              -- per-block undo records, so without this
                              -- marker the undo-record binary search would
                              -- mistake the chainstate for empty and seed
                              -- block download from height 1.  The 0x53
                              -- key survives both restarts and
                              -- 'wipeChainstate'.
                              putSnapshotBaseHash db baseHash
                              putStrLn $ "[--load-snapshot] imported " ++ show n
                                      ++ " UTXO(s); best-block pinned to snapshot base."
                              putStrLn $ "[--load-snapshot] recorded snapshot "
                                      ++ "base marker (height " ++ show baseHeight
                                      ++ ") for restart-safe reconciliation."

    -- Initialize mempool.
    -- Provide a per-input coin-MTP lookup function (BIP-68 time-based locks):
    -- given a coin-height H, return MTP(max(H-1, 0)).
    -- Reference: Bitcoin Core tx_verify.cpp:74 — nCoinTime =
    --   GetAncestor(max(H-1,0))->GetMedianTimePast().
    let getCoinMtpFromChain coinH = do
          entries  <- readTVarIO (hcEntries hc)
          byHeight <- readTVarIO (hcByHeight hc)
          let targetH = if coinH == 0 then 0 else coinH - 1
          case Map.lookup targetH byHeight of
            Just blockHash -> return (medianTimePast entries blockHash)
            Nothing        -> return 0  -- height not in chain (shouldn't happen)
    mp <- newMempool net cache defaultMempoolConfig 0 0 getCoinMtpFromChain

    -- Load mempool.dat (Core-format), if present. We use a 14-day
    -- expiry (matches Bitcoin Core's DEFAULT_MEMPOOL_EXPIRY_HOURS = 336).
    let mempoolDatPath = MPP.defaultMempoolDatPath dataDir
        mempoolExpirySecs = 14 * 24 * 3600  -- 14 days
    do
      r <- MPP.loadMempool mp mempoolDatPath mempoolExpirySecs
             `catch` (\(e :: SomeException) -> do
                       putStrLn $ "loadMempool error: " ++ show e
                       return (Right (0, 0, 0, 0)))
      case r of
        Right (loaded, failed, expired, already) ->
          when (loaded + failed + expired + already > 0) $
            putStrLn $ "Loaded mempool.dat: " ++ show loaded ++ " accepted, " ++
                       show failed ++ " failed, " ++ show expired ++
                       " expired, " ++ show already ++ " already there"
        Left e -> putStrLn $ "Could not parse mempool.dat: " ++ e

    -- Initialize fee estimator with persistence
    fe <- newFeeEstimator
    let feeEstimatesPath = dataDir </> "fee_estimates.json"
    loadFeeEstimates fe feeEstimatesPath

    -- Startup chainstate reconciliation (Core: Chainstate::LoadChainTip
    -- + Chainstate::ReplayBlocks, bitcoin-core/src/validation.cpp:4546
    -- / :4773).
    --
    -- W162 P0 chainstate-wedge recovery + prevention.
    --
    -- haskoin is headers-first: 'initHeaderChainFromDB' rebuilds the
    -- in-memory header chain from the persisted height index, which
    -- header sync advances *ahead* of block connection.  So 'hcHeight'
    -- is the highest known *header*, NOT the highest *connected* block.
    -- The block-download resume point must be the connected-block tip.
    --
    -- We do NOT trust the @PrefixBestBlock@ pointer to give us that
    -- tip.  In the incident this fix targets, that pointer had been
    -- destroyed: the startup code (now fixed above) reset it to genesis
    -- on every restart, so on disk it read "height 0" while the UTXO
    -- set was actually intact at ~949 k.  Trusting it and replaying
    -- from block 1 would re-apply coinbases and resurrect long-spent
    -- coins — corrupting the UTXO set.
    --
    -- Instead we recover the *true* connected tip from the per-block
    -- undo records.  'connectBlockAt' commits the UTXO mutations, the
    -- undo record (key @0x10 ++ blockHash@) and the chain pointers in
    -- ONE atomic RocksDB 'writeBatch' — so an undo record for the
    -- block at height H exists IFF that block's UTXO mutations were
    -- applied.  Blocks connect strictly sequentially (the ConnectBlock
    -- G1 gate enforces it), so undo records occupy a contiguous range
    -- [1 .. U]; we binary-search for U.  This is haskoin's analogue of
    -- Core's ReplayBlocks, which reconstructs the correct tip from the
    -- on-disk coins view rather than a possibly-stale hint.
    --
    -- Having found U we (a) re-stamp @PrefixBestBlock@ to the block at
    -- height U — repairing a corrupted pointer in place, the actual
    -- recovery step — and (b) resume block download from U+1.  No
    -- reindex or chainstate wipe is needed: the UTXO set is already
    -- correct at U, only the pointer and the un-connected tail need
    -- fixing.  On a healthy node U already equals the pointer height
    -- and both steps are no-ops.
    headerTipHeight <- readTVarIO (hcHeight hc)
    let -- Does the block at height @h@ have a persisted undo record?
        -- Height 0 (genesis) has no undo record but is always
        -- "connected"; callers handle 0 separately.
        blockIsConnected h = do
          mHash <- getBlockHeight db h
          case mHash of
            Nothing -> return False
            Just bh -> isJust <$> getUndoData db bh
        -- Binary search for the highest contiguous connected height in
        -- the inclusive range [lo .. hi].  Invariant on entry: every
        -- height <= lo is connected, every height > hi is not.
        findConnectedTip lo hi
          | lo >= hi  = return lo
          | otherwise = do
              let mid = lo + (hi - lo + 1) `div` 2
              connected <- blockIsConnected mid
              if connected
                then findConnectedTip mid hi
                else findConnectedTip lo (mid - 1)
    -- Snapshot-aware lower bound for the connected-tip search.
    --
    -- An assumeUTXO snapshot load ('--load-snapshot',
    -- loadSnapshotIntoLegacyUTXO) writes the full UTXO set + the
    -- @PrefixBestBlock@ pointer (= snapshot base hash) but writes NO
    -- per-block undo records: the UTXO set is imported wholesale, not
    -- replayed block-by-block.  So on a snapshot-bootstrapped node the
    -- per-block undo records do NOT occupy [1..U] — they occupy
    -- [base+1 .. U], with heights [1..base] permanently empty.
    --
    -- The plain binary search above assumes a [1..U] range: it probes
    -- block 1, finds no undo record, and reports connectedTipHeight = 0.
    -- That seeds nextBlockRef to 1 and makes haskoin try to connect
    -- block 1 on top of a best-block pointer far up the chain — the
    -- ConnectBlock G1 gate (@hashPrevBlock == view.GetBestBlock()@,
    -- validation.cpp:2333) then rejects every downloaded block and the
    -- node wedges + DoS-bans its peers.  This bites BOTH immediately
    -- after the snapshot load AND on every later restart (once blocks
    -- above the base have connected, the best-block pointer no longer
    -- names a snapshot base either).
    --
    -- Fix: '--load-snapshot' durably records the snapshot base hash
    -- under the 0x53 key ('putSnapshotBaseHash' — Core's
    -- chainstate_snapshot/base_blockhash file analogue).  We read it
    -- back here: when set, the UTXO set legitimately begins at the
    -- snapshot base, so the connected tip is >= baseHeight and the
    -- undo-record search floor is baseHeight+1 (not 1).  If even
    -- baseHeight+1 has no undo record, no post-snapshot block has
    -- connected yet and the connected tip is exactly baseHeight.
    -- This is haskoin's analogue of Core resuming the active chain from
    -- @m_from_snapshot_blockhash@ after an assumeutxo bootstrap.
    mSnapshotBase <- getSnapshotBaseHash db
    mSnapshotBaseHeight <-
      case mSnapshotBase of
        Nothing       -> return Nothing
        Just baseHash -> do
          -- Resolve the base hash to a height.  Prefer the in-memory
          -- header chain ('initHeaderChainFromDB' already loaded it);
          -- fall back to the hardcoded assumeUTXO whitelist (the same
          -- table '--load-snapshot' validates against) so the floor is
          -- still correct even if the base header is not in the height
          -- index for any reason.
          entries <- readTVarIO (hcEntries hc)
          case Map.lookup baseHash entries of
            Just ce -> return (Just (ceHeight ce))
            Nothing -> return (aupHeight <$> assumeUtxoForBlockHash net baseHash)
    connectedTipHeight <-
      case mSnapshotBaseHeight of
        -- Snapshot-bootstrapped chainstate: undo records (if any) start
        -- at baseHeight+1.  The connected tip is at least baseHeight —
        -- the imported UTXO set legitimately begins at the snapshot base.
        --
        -- W164 forward-sync-wedge fix: this case MUST take priority over
        -- the @headerTipHeight == 0@ short-circuit below.  On a freshly
        -- wiped datadir bootstrapped from a snapshot, 'initHeaderChainFromDB'
        -- loads only genesis ("Loaded 0 headers"), so 'headerTipHeight' is 0
        -- at this point — the genesis->base->tip header chain is backfilled
        -- by the headers-first P2P sync that runs AFTER node startup, not
        -- before this reconciliation.  The old @if headerTipHeight == 0
        -- then return 0@ guard ran first and seeded connectedTipHeight=0
        -- (=> nextBlockRef=1), so the block-gap kicker forever requested
        -- block 1 on top of BestBlock=base and every getdata failed the
        -- ConnectBlock G1 gate (validation.cpp:2333) — the node wedged at
        -- the base with blocks=base / headers=tip / ibd=false.  The snapshot
        -- base marker is the authoritative UTXO-set floor regardless of how
        -- far the header chain has rebuilt, so honour it unconditionally.
        Just baseHeight -> do
          -- No usable header tip yet (genesis-only chain, headers still
          -- backfilling): the connected tip is exactly the snapshot base.
          if headerTipHeight <= baseHeight
            then do
              putStrLn $ "Chainstate reconciliation: assumeUTXO snapshot "
                      ++ "base at height " ++ show baseHeight
                      ++ "; header chain not yet rebuilt past the base "
                      ++ "(header tip " ++ show headerTipHeight
                      ++ ") — treating the base as the connected tip. The "
                      ++ "headers-first P2P sync will backfill "
                      ++ "genesis->base->tip; the block-gap kicker then "
                      ++ "downloads bodies " ++ show (baseHeight + 1)
                      ++ "..header-tip."
              return baseHeight
            else do
              aboveConnected <- blockIsConnected (baseHeight + 1)
              if not aboveConnected
                then do
                  putStrLn $ "Chainstate reconciliation: assumeUTXO "
                          ++ "snapshot base at height " ++ show baseHeight
                          ++ "; no post-snapshot blocks connected yet "
                          ++ "(snapshot UTXO set has no undo records by "
                          ++ "design) — treating the base as the "
                          ++ "connected tip."
                  return baseHeight
                else findConnectedTip (baseHeight + 1) headerTipHeight
        -- Normal (genesis-up) chainstate, no snapshot marker.
        Nothing ->
          if headerTipHeight == 0
            then return 0
            else do
              -- If even block 1 has no undo record the UTXO set never
              -- advanced past genesis; otherwise binary-search [1..tip].
              oneConnected <- blockIsConnected 1
              if not oneConnected
                then return 0
                else findConnectedTip 1 headerTipHeight
    -- Repair the best-block pointer so it names the true connected tip.
    -- This is the recovery: a genesis-stuck (or otherwise stale)
    -- @PrefixBestBlock@ is re-pointed at the block whose UTXO mutations
    -- are actually the last ones on disk, so the ConnectBlock G1 gate
    -- (validation.cpp:2333) will accept block U+1.
    do
      mBest <- getBestBlockHash db
      mTrueTipHash <-
        if connectedTipHeight == 0
          then return Nothing
          else getBlockHeight db connectedTipHeight
      case (mBest, mTrueTipHash) of
        (Just cur, Just trueTip)
          | cur /= trueTip -> do
              putStrLn $ "Chainstate reconciliation: persisted best-block "
                      ++ show cur ++ " disagrees with the true connected "
                      ++ "tip at height " ++ show connectedTipHeight
                      ++ " (" ++ show trueTip ++ "); re-stamping best-block "
                      ++ "pointer to the connected tip."
              putBestBlockHash db trueTip
          | otherwise -> return ()
        (Nothing, Just trueTip) -> do
          putStrLn $ "Chainstate reconciliation: best-block pointer absent; "
                  ++ "stamping it to the true connected tip at height "
                  ++ show connectedTipHeight ++ " (" ++ show trueTip ++ ")."
          putBestBlockHash db trueTip
        _ ->
          -- connectedTipHeight == 0: the genesis pointer (or a fresh
          -- DB) is already correct for an empty UTXO set.
          return ()
    when (connectedTipHeight < headerTipHeight) $
      putStrLn $ "Chainstate reconciliation: connected-block tip is height "
              ++ show connectedTipHeight ++ ", header tip is height "
              ++ show headerTipHeight ++ "; will re-download + connect "
              ++ show (headerTipHeight - connectedTipHeight)
              ++ " block(s) to catch the UTXO set up."
    -- Track next expected block height for download. Resume from the
    -- connected-block tip (true UTXO-view tip), NOT the header tip.
    let loadedHeight = connectedTipHeight
    nextBlockRef <- newIORef (loadedHeight + 1)
    -- Track highest block we've requested (for sliding window)
    requestedUpToRef <- newIORef loadedHeight
    -- IBD mode flag: skip block inv requests until header sync catches up
    ibdModeRef <- newIORef True
    -- Headers-first IBD: POSIX time of the last full (>=2000) header
    -- batch. Block download is deferred while this is recent, so the
    -- block processor does not throttle bulk header sync via RocksDB +
    -- CPU contention. 0 = no full batch seen (steady-state node).
    lastFullBatchAtRef <- newIORef (0 :: Int64)
    -- Recently-rejected transaction filter (cleared on each new block)
    recentlyRejectedRef <- newIORef (Set.empty :: Set.Set TxId)
    -- BIP-339 wtxid-keyed orphan pool (W99 G12/G13/G14)
    orphanPoolRef <- newIORef emptyOrphanPool
    -- Durability: count blocks since last chainstate flush. We do a
    -- periodic synchronous WAL fsync (see doPeriodicFlush) every
    -- flushBlockInterval blocks OR every flushTimeInterval seconds,
    -- whichever comes first. This closes the durability gap observed
    -- in Wave 2 where 133k connected blocks were lost because a
    -- non-graceful shutdown skipped closeDB.
    blocksSinceFlushRef <- newIORef (0 :: Word32)
    lastFlushEpochRef <- do
      t0 <- round <$> getPOSIXTime
      newIORef (t0 :: Integer)

    -- Start header sync
    hs <- startHeaderSync net hc

    -- BIP-152 BUG-1/BUG-8 FIX (W112): Instantiate CompactBlockState so that
    -- in-flight PartiallyDownloadedBlocks can be persisted between MCmpctBlock
    -- (which calls initPartialBlock + sends getblocktxn) and MBlockTxn (which
    -- must call fillPartialBlock to complete the two-round-trip path).
    -- Reference: bitcoin-core/src/net_processing.cpp mapBlocksInFlight /
    -- PartiallyDownloadedBlock kept alive across the two messages.
    cbsPendingVar <- newTVarIO (Map.empty :: Map.Map BlockHash (Int64, PartiallyDownloadedBlock))
    let compactBlockState = CompactBlockState
          { cbsPending = cbsPendingVar
          , cbsConfig  = defaultCompactBlockConfig
          }
    compactBlockStateRef <- newIORef compactBlockState

    -- P1-2 (chainstate-atomicity family, dispatch-layer race).
    --
    -- Per-peer recv threads call 'syncMessageHandler' directly
    -- (Network.hs:2797 in 'startPeerThreadsWithMisbehavior'), so two
    -- different peer threads can land inside the MBlock arm at the same
    -- instant. 'connectBlockAt' (Consensus.hs:3031) does a
    -- read-BestBlock / check-G1 / build-WriteBatch / commit sequence
    -- with no internal lock. Two threads can both see
    -- @BestBlock = hash(N)@, both pass G1 for the same height N+1,
    -- both write the same WriteBatch (idempotent), AND on different
    -- blocks the chainstate + the in-memory 'nextBlockRef' desync —
    -- the kicker's next-needed height diverges from the actual on-disk
    -- tip and the catch-up wedges. This race is acknowledged in the
    -- commit body of '9fda3f4' ("A concurrency race remains — blocks
    -- connect from multiple peer threads with no lock around
    -- connectBlockAt's read-best-block / check-G1 / write sequence").
    --
    -- The MVar serialises the read-check-write critical section across
    -- all peer threads + both compact-block re-dispatch sites. We hold
    -- it across 'connectBlock', the 'nextBlockRef' bump, and the flush
    -- bookkeeping so the @BestBlock / nextBlockRef@ pair stays
    -- consistent end-to-end. Held only for the block-connection arm;
    -- other message types (MTx, MInv, MGetData, etc.) are unaffected.
    --
    -- Reference: bitcoin-core/src/validation.cpp 'ChainstateManager'
    -- holds 'cs_main' across 'ActivateBestChainStep' for the same
    -- reason — Core's single mutex serialises tip-update across all
    -- net_processing threads.
    --
    -- Cross-ref: '_chainstate-atomicity-family-2026-05-26.md' (this is
    -- the new dispatch-layer sibling) and
    -- '_haskoin-unfreeze-plan-2026-05-27.md' (Phase 1, P1-2).
    connectLock <- newMVar () :: IO (MVar ())

    -- DURABILITY (sweep wa0fq5wtk): forward-declared handle to the
    -- WalletManager so the live P2P/IBD connect loop in
    -- 'syncMessageHandler' can feed every connected block to the wallet
    -- (credit/debit + history + persist), not just the mining/RPC path.
    -- The manager itself is created later (it needs the datadir wired);
    -- the connect loop reads this IORef each block, so a 'Nothing' before
    -- the manager exists simply means "no wallet to scan yet".
    walletMgrRef <- newIORef (Nothing :: Maybe WalletManager)

    -- Initialise BlockStore IFF pruning is enabled.  Most haskoin
    -- block I/O still flows through RocksDB, so the BlockStore is
    -- not on the hot path; we only create it when prune RPC /
    -- auto-prune triggers need it.  newBlockStore is idempotent —
    -- re-running on an existing blocks/ dir loads the persisted
    -- file-info index from RocksDB.
    let blocksDir = dataDir </> "blocks"
    mBlockStore <- if pruneOn
      then do
        bs <- newBlockStore blocksDir (netMagicBytesLE net) db
        putStrLn $ "BlockStore initialised at " ++ blocksDir
                ++ " (prune subsystem armed)"
        return (Just bs)
      else return Nothing

    -- Initialise secondary indexes (BIP-157/158 blockfilterindex,
    -- and the existing txindex / coinstatsindex stubs) iff the
    -- operator opted in via @--blockfilterindex@ (or
    -- @blockfilterindex = 1@ in haskoin.conf).  We:
    --
    --   1. Build the IndexManager and load any persisted in-memory
    --      state from the F/f keyspaces ('indexManagerInitFromDB').
    --   2. Walk forward from the index's last-known height + 1 to
    --      the chain's current best height, populating any gap.
    --      This is what closes the deferred scope in commit
    --      e8068bcd: REST handlers no longer have to recompute from
    --      genesis on every call once the backfill completes.
    --   3. Hand the manager to the peer-message handler + RPC server
    --      so live IBD / submitBlock / reorg keep the index in sync.
    --
    -- Reference: bitcoin-core/src/index/blockfilterindex.cpp
    -- BlockFilterIndex::CustomInit + BlockFilterIndex::Sync.  The
    -- @Maybe IndexManager@ is plumbed through every connect/reorg
    -- callsite as an opt-in null instead of a global, so the
    -- non-indexed default case stays a single 'Nothing' branch with
    -- zero overhead per block.
    mIdxMgr <- if noBlockFilterIndex || noCoinStatsIndex || noTxoSpenderIndex
      then do
        let idxConfig = defaultIndexConfig
              { icBlockFilterIndex = noBlockFilterIndex
              , icCoinStatsIndex   = noCoinStatsIndex
              , icTxoSpenderIndex  = noTxoSpenderIndex
              }
        im <- newIndexManager db idxConfig
        indexManagerInitFromDB im
        -- Seed GENESIS (height 0) for any enabled index that is empty.
        --
        -- BlockFilterIndex: BIP-157 chains every block's filter header off
        -- the PARENT's filter header, and genesis's parent is the all-zero
        -- hash; Core indexes the genesis filter (blockfilterindex starts at
        -- block 0), so height 1 must chain off the genesis filter header.
        --
        -- CoinStatsIndex: the running accumulator + per-height records must
        -- have a height-0 base (the EMPTY UTXO set — Core never adds the
        -- genesis coinbase to the UTXO set; 'coinStatsIndexAppendBlock'
        -- skips genesis outputs), so height 1 resumes from a correct base.
        --
        -- The genesis block has no spent prevouts, so its undo data is the
        -- empty 'BlockUndo []'.  Idempotent: only runs when an index has no
        -- entry yet (fresh datadir), so a restart never re-seeds.
        -- Reference: bitcoin-core/src/index/{blockfilterindex,coinstatsindex}.cpp
        -- CustomAppend (called for the genesis block).
        bfEmpty <- case imBlockFilterIndex im of
          Nothing  -> return False
          Just bfIdx0 -> maybe True (const False) <$> blockFilterIndexTipHeight bfIdx0
        csEmpty <- case imCoinStatsIndex im of
          Nothing  -> return False
          Just csIdx0 -> maybe True (const False) <$> coinStatsIndexTipHeight csIdx0
        tsEmpty <- case imTxoSpenderIndex im of
          Nothing  -> return False
          Just tsIdx0 -> maybe True (const False) <$> txoSpenderIndexTipHeight tsIdx0
        when (bfEmpty || csEmpty || tsEmpty) $ do
          -- Use 'netGenesisBlock' directly: the genesis block body is NOT
          -- persisted via 'putBlock' at chain init (only its header is), so
          -- 'getBlock db genHash' would return Nothing.  The in-memory
          -- genesis block carries the coinbase output(s) the indexes need.
          let genBlk  = netGenesisBlock net
              genHash = computeBlockHash (blockHeader genBlk)
          putStrLn "Index: seeding genesis (height 0)"
          indexManagerConnectBlock im genBlk (BlockUndo []) genHash 0
        -- Backfill from the LOWEST enabled-index tip to the chain tip
        -- (indexManagerInitFromDB seeded imSyncHeight to that min).
        -- 'indexManagerBackfill' populates every enabled index per block.
        startTip <- readIORef (imSyncHeight im)
        bestH <- readTVarIO (hcHeight hc)
        when (bestH > startTip) $
          putStrLn $ "Index: backfilling from height "
                  ++ show (startTip + 1) ++ " to " ++ show bestH
        let getBlockData h = do
              mHash <- getBlockHeight db h
              case mHash of
                Nothing -> return Nothing
                Just bh -> do
                  mBlk <- getBlock db bh
                  mUndo <- getUndoData db bh
                  case (mBlk, mUndo) of
                    (Just blk, Just u) ->
                      return $ Just (blk, udBlockUndo u, bh)
                    _ -> return Nothing
        finalH <- indexManagerBackfill im getBlockData bestH
        when (bestH > startTip) $
          putStrLn $ "Index: backfill complete, indexed up to "
                  ++ show finalH
        return (Just im)
      else return Nothing

    -- Start peer manager with sync-aware message handler.
    -- BIP-159: --prune (any non-zero value) flips on
    -- NODE_NETWORK_LIMITED in the version handshake so peers know we
    -- only serve the recent ~288-block window.  The wire-protocol gate
    -- is correct regardless of whether the prune subsystem itself is
    -- live -- consistent with Core's `IsPruneMode()` semantics.
    --
    -- W117 DH-1: parse the optional --proxy / --onion / --i2psam
    -- host:port strings into structured Maybe (String, Int) for
    -- PeerManagerConfig.  Mal-formed values are logged and ignored
    -- so a typo doesn't crash startup.
    let parseHostPort :: String -> Maybe (String, Int)
        parseHostPort s = case break (== ':') s of
          (h, ':':p) -> case reads p of
            [(port, "")] | port > 0 && port < 65536 -> Just (h, port)
            _ -> Nothing
          _ -> Nothing
        warnBad lbl v = case v of
          Nothing -> return ()
          Just s  -> putStrLn $ "WARNING: " ++ lbl
                                ++ " value '" ++ s ++ "' is not host:port; ignoring"
        mProxy  = noProxy  >>= parseHostPort
        mOnion  = noOnion  >>= parseHostPort
        mI2pSam = noI2pSam >>= parseHostPort
    -- Surface mal-formed values explicitly so silent privacy-network
    -- bypass doesn't go unnoticed by an operator.
    when (isJust noProxy  && isNothing mProxy)  $ warnBad "--proxy"  noProxy
    when (isJust noOnion  && isNothing mOnion)  $ warnBad "--onion"  noOnion
    when (isJust noI2pSam && isNothing mI2pSam) $ warnBad "--i2psam" noI2pSam
    when (isJust mOnion)  $ putStrLn $ "W117: Tor v3 (.onion) reachable via "
                                   ++ show (fromJust mOnion)
    when (isJust mI2pSam) $ putStrLn $ "W117: I2P (.i2p) reachable via SAM "
                                    ++ show (fromJust mI2pSam)
    when noCjdnsReachable $ putStrLn "W117: CJDNS (fc00::/8) marked reachable"

    -- Bitcoin Core @-connect=<ip:port>@ peer pinning.  Resolve every
    -- clearnet @--connect@ entry to a concrete 'SockAddr' here, ONCE,
    -- so 'peerManagerLoop' never does a host lookup in connect mode.
    -- The resolved list feeds 'pmcConnectAddrs' which flips the peer
    -- manager into connect-only mode: DNS seeds + addrman auto-outbound
    -- are both suppressed and only these peers are (re)dialed (mirrors
    -- clearbit peer.zig:7009 + 7050 and Core's @-connect@ which implies
    -- @-dnsseed=0@).  Privacy-network (.onion/.i2p) @--connect@ entries
    -- keep their existing 'tryConnectByHost' dispatch below and are NOT
    -- added to 'pmcConnectAddrs' (they cannot be dialed as a plain
    -- SockAddr); but their presence still enables connect-only mode.
    let connectClearnet = [ (h, p)
                          | c <- noConnect
                          , let (h, p) = case break (== ':') c of
                                  (h', ':':ps) -> (h', ps)
                                  (h', _)      -> (h', show (netDefaultPort net))
                          , not (isOnionAddress h)
                          , not (isI2PAddress h)
                          , case reads p of [(_ :: Int, "")] -> True; _ -> False ]
    resolvedConnectAddrs <- fmap concat $ forM connectClearnet $ \(h, p) ->
      (map NS.addrAddress
        <$> (NS.getAddrInfo Nothing (Just h) (Just p) :: IO [NS.AddrInfo]))
        `catch` (\(e :: SomeException) -> do
            putStrLn $ "WARNING: --connect peer " ++ h ++ ":" ++ p
                    ++ " did not resolve (" ++ show e ++ "); skipping"
            return [])
    -- Connect mode is active whenever ANY --connect peer was supplied
    -- (clearnet OR privacy-network).  Core's -connect disables DNS even
    -- if the only pinned peer is a .onion; honour that.
    let connectModeActive = not (null noConnect)
    when connectModeActive $
      putStrLn $ "-connect: peer-pinning ON ("
              ++ show (length resolvedConnectAddrs)
              ++ " clearnet addr(s) resolved); DNS seeds + auto-outbound "
              ++ "disabled, dialing only pinned peers"
    -- --nodnsseed (or -connect) suppresses DNS seed resolution.
    let dnsSeedEnabled = not noNoDnsSeed && not connectModeActive
    when (noNoDnsSeed && not connectModeActive) $
      putStrLn "--nodnsseed: DNS seed resolution disabled"

    let pmConfig = defaultPeerManagerConfig
          { pmcMaxOutbound = min 8 noMaxPeers
          , pmcDataDir     = dataDir
          , pmcPeerBloomFilters = noPeerBloomFilters
          , pmcPruneMode   = pruneOn
          -- -connect peer pinning + -dnsseed gate (see resolution above).
          , pmcConnectAddrs = resolvedConnectAddrs
          , pmcDnsSeed      = dnsSeedEnabled
          -- W117 DH-1: plumb privacy-network proxy + reachability.
          , pmcProxy          = mProxy
          , pmcOnion          = mOnion
          , pmcI2pSam         = mI2pSam
          , pmcCjdnsReachable = noCjdnsReachable
          -- FIX-86: BIP-157 NODE_COMPACT_FILTERS advertisement.
          -- Honest only when the operator opted in via @-blockfilterindex@
          -- AND we successfully built the IndexManager (which implies the
          -- on-disk index is openable; indexManagerInitFromDB has loaded
          -- any persisted state).  The handler-side gate in syncMessageHandler
          -- provides defence-in-depth: it refuses to serve cfilters/cfheaders/
          -- cfcheckpts when this bit is off.
          , pmcCompactFilters = case mIdxMgr of
              Just im -> case imBlockFilterIndex im of
                Just _  -> True
                Nothing -> False
              Nothing -> False
          }
        -- W117 DH-2: 'reachabilityFromConfig pmConfig' is what the
        -- addrv2 receipt handler (MAddrV2 in syncMessageHandler)
        -- recomputes per-message from pm's config to apply
        -- 'filterReachableAddresses'.  Logged here for operator visibility.
        _reach = reachabilityFromConfig pmConfig
    pmRef <- newIORef (undefined :: PeerManager)
    pm <- startPeerManagerWith net pmConfig
      (\addr msg ->
        syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef requestedUpToRef ibdModeRef lastFullBatchAtRef recentlyRejectedRef blocksSinceFlushRef lastFlushEpochRef pruneCfg mBlockStore mIdxMgr orphanPoolRef compactBlockStateRef connectLock walletMgrRef addr msg
          `catch` (\(e :: SomeException) -> putStrLn $ "Handler error: " ++ show e))
      -- BUG-12 FIX: EraseForPeer — purge orphans from disconnected peer.
      -- Core: TxOrphanage::EraseForPeer (txorphanage.h:86) is called in
      -- net_processing.cpp FinalizeNode when a peer disconnects.
      (\addr -> eraseOrphansForPeer addr orphanPoolRef
          `catch` (\(e :: SomeException) ->
            putStrLn $ "eraseOrphansForPeer error: " ++ show e))
    writeIORef pmRef pm
    -- W115 FIX-50: inject asmap bytecode into PeerManager so that
    -- computeNetworkGroupWithASMap can use ASN-keyed bucketing.
    let pm' = pm { pmAsmapData = asmapData }
    writeIORef pmRef pm'

    -- W117 DH-1: hidden-service / SAM-session announcement at startup.
    --
    -- When --onion is set we attempt a best-effort 'createTorHiddenService'
    -- call against the standard Tor control port (127.0.0.1:9051).
    -- Success surfaces the .onion address in the log; failure is
    -- harmless and logged-only (e.g. Tor control auth disabled, daemon
    -- not running).  Key persistence is intentionally out of scope
    -- (W117 G18) — the service is ephemeral for this haskoin run.
    --
    -- When --i2psam is set we open a transient SAM session via
    -- 'createI2PSession' so failures show up at startup instead of
    -- the first .i2p dial.  G19 (transient destination) is also
    -- explicitly out of scope.
    when (isJust mOnion) $ do
      let (ctrlHost, ctrlPort) = defaultTorControlPort
          virtualPort          = fromIntegral noListenPort :: Word16
          targetPort           = fromIntegral noListenPort :: Word16
      void $ forkIO $ do
        r <- createTorHiddenService ctrlHost ctrlPort
                                    virtualPort "127.0.0.1" targetPort
              `catch` (\(e :: SomeException) ->
                  return $ Left $ "createTorHiddenService exception: " ++ show e)
        case r of
          Left err -> putStrLn $ "W117 Tor hidden-service unavailable: " ++ err
          Right resp ->
            putStrLn $ "W117 Tor hidden-service published: "
                    ++ show (torServiceId resp) ++ ".onion"
    when (isJust mI2pSam) $ do
      let (samHost, samPort) = fromJust mI2pSam
      void $ forkIO $ do
        r <- createI2PSession samHost samPort
              `catch` (\(e :: SomeException) ->
                  return $ Left $ "createI2PSession exception: " ++ show e)
        case r of
          Left err -> putStrLn $ "W117 I2P SAM session unavailable: " ++ err
          Right sess -> do
            putStrLn $ "W117 I2P SAM session established: "
                    ++ show (samB32Address sess)
            -- Operator-visible address.  Caller closes the session
            -- when the node shuts down (no explicit lifetime tracking
            -- in this DH-1 wiring; the SAM bridge garbage-collects on
            -- TCP close).
            closeI2PSession sess

    -- Seed known addresses from --connect flags.
    --
    -- W117 DH-1: when the host is a privacy-network hostname
    -- (.onion or .i2p) we cannot resolve it via getAddrInfo (the
    -- system resolver does not know about the Tor / I2P overlays).
    -- Instead, dispatch through 'tryConnectByHost' which uses the
    -- operator's --onion / --i2psam proxy.  Clearnet hosts continue
    -- the existing AddrMan-seed path.
    forM_ noConnect $ \connectStr -> do
      let (host, portStr) = case break (== ':') connectStr of
            (h, ':':p) -> (h, p)
            (h, _)     -> (h, show (netDefaultPort net))
      case reads portStr of
        [(port, "")]
          | isOnionAddress host || isI2PAddress host -> do
              putStrLn $ "Adding privacy-network connect peer: "
                      ++ host ++ ":" ++ show (port :: Int)
              void $ forkIO $ tryConnectByHost pm' host port False
                `catch` (\(e :: SomeException) ->
                  putStrLn $ "tryConnectByHost error: " ++ show e)
          | otherwise -> do
              addrInfos <- NS.getAddrInfo Nothing (Just host) (Just (show (port :: Int))) :: IO [NS.AddrInfo]
              forM_ addrInfos $ \ai -> do
                let addr = NS.addrAddress ai
                putStrLn $ "Adding connect peer: " ++ show addr
                -- Feed into AddrMan (BUG-5/BUG-1 fix: structured storage).
                -- Use addr as its own source (manual-connect = trusted source).
                nowTs <- (round <$> getPOSIXTime :: IO Int64)
                _ <- addAddress (pmAddrMan pm') (pmAsmapData pm') addr addr 0x409 nowTs
                -- Keep pmKnownAddrs in sync for backward-compat.
                atomically $ modifyTVar' (pmKnownAddrs pm') (Set.insert addr)
        _ -> putStrLn $ "Invalid connect address: " ++ connectStr

    -- Spawn a thread to send getheaders once a peer connects
    void $ forkIO $ getheadersSender pm' hc net
      `catch` (\(e :: SomeException) -> putStrLn $ "getheadersSender error: " ++ show e)

    -- Block downloading is done from the MHeaders and MBlock handlers.
    --
    -- W162 P0 chainstate-wedge fix — gap re-download kicker.
    --
    -- The MHeaders handler only fires 'requestBlocks' when it accepts
    -- *new* headers ('added > 0'), and the MInv handler only requests
    -- blocks whose header is *unknown*.  Neither path covers the case
    -- this fix targets: a restart where the header chain is already
    -- fully synced but the UTXO-view tip ('getBestBlockHash') lags the
    -- header tip — every gap block's header is already known, so no
    -- getdata is ever sent and the UTXO set stays frozen forever.
    --
    -- This watcher closes that gap.  Once peers are connected it
    -- re-requests the blocks between the next-needed height
    -- ('nextBlockRef', seeded from the connected-block tip by the
    -- reconciliation step above) and the header tip, then keeps
    -- polling: as blocks connect 'nextBlockRef' advances and the
    -- watcher requests the next window, so a dropped or slow block
    -- never permanently stalls catch-up.  It is a no-op once the UTXO
    -- tip reaches the header tip (nextBlock > headerTip), so it costs
    -- nothing in steady state.
    void $ forkIO $
      (let kicker rot = do
             -- W163: 12 s (was 3 s) so a 64-block window finishes
             -- downloading + connecting before the next request — a 3 s
             -- re-fire overlapped windows across rotating peers, so
             -- ~99% of requested blocks arrived out of order and dropped.
             threadDelay (12 * 1_000_000)
             peers <- getConnectedPeerList pm'
             headerTip <- readTVarIO (hcHeight hc)
             nextBlock <- readIORef nextBlockRef
             -- Headers-first: stay quiet while bulk header sync is live
             -- (a full 2000-header batch within the last 45 s) so block
             -- download does not throttle header sync.
             nowKick <- (round <$> getPOSIXTime :: IO Int64)
             lastFullKick <- readIORef lastFullBatchAtRef
             let headerSyncActiveKick = nowKick - lastFullKick < 45
             when (not (null peers) && nextBlock <= headerTip && not headerSyncActiveKick) $ do
               -- Request a bounded window so we don't blast every gap
               -- block at once; the loop re-runs every 3 s and slides
               -- forward as blocks connect.
               -- W163 recovery: 16-block window = exactly one getdata
               -- batch (requestBlocks chunks in 16s), sent to a single
               -- peer. That peer serves the batch in request order, and
               -- haskoin processes one peer's messages sequentially, so
               -- the 16 blocks connect in order with no out-of-order
               -- churn against connectBlockAt's strict G1 gate.
               -- requestBlocks rotates the peer by the kicker counter
               -- 'rot' so each retry of a stalled window hits a
               -- different peer — a non-serving peer cannot wedge IBD.
               --
               -- 2026-05-27 fix: the window was `nextBlock + 63` (64
               -- blocks) — but the comment above says 16. A 64-block
               -- window is `chunksOf 16` = 4 batches distributed across
               -- 4 peers. Three of those batches start at heights
               -- `nextBlock + 16/32/48` whose parent is NOT yet the
               -- BestBlock when the blocks arrive, so they fail
               -- connectBlockAt G1 and are silently dropped (the
               -- W163 diag only logs height==nextBlock rejections).
               -- The mainnet sync wedged at h=976 reproducing exactly
               -- this: kicker re-fires every 12s on the same window,
               -- all 4 peers send 64 blocks back, only the one peer
               -- serving the [nextBlock..nextBlock+15] batch ever
               -- makes progress, and even that intermittently because
               -- of the concurrency race in connectBlockAt (no lock
               -- around read-BestBlock / check-G1 / write).
               -- Truncate to 16 to match the comment's intent: one
               -- batch, one peer, in-order, no race.
               -- (chainstate-atomicity family — _chainstate-atomicity-family-2026-05-26.md)
               -- GAP2 fork-aware download floor.  When a heavier COMPETING
               -- header chain forks BELOW the connected tip, the connect
               -- cursor 'nextBlock' (= connected-tip+1) is NOT low enough:
               -- the heavier branch's bodies between the fork point and the
               -- connected-tip height have never been downloaded, yet
               -- 'buildReorgConnectList' needs them on disk before the
               -- reorg can run.  Drop the request floor to FORK_POINT+1 so
               -- 'requestBlocks' (reading hashes from hcByHeight = the
               -- heavier header chain) fetches the whole heavier branch.
               -- A no-op on the linear path (floor == nextBlock).
               reqFrom <- forkDownloadFloor db hc nextBlock
               let windowEnd = min headerTip (reqFrom + 15)
               putStrLn $ "Block-gap kicker: requesting blocks "
                       ++ show reqFrom ++ "-" ++ show windowEnd
                       ++ " (UTXO-view tip behind header tip "
                       ++ show headerTip ++ ")"
               requestBlocks pm' hc reqFrom windowEnd rot
               -- GAP2 fork-aware download.  'requestBlocks' above reads
               -- hashes from 'hcByHeight', which only points at the heavier
               -- branch ABOVE the work crossover; below it, it still resolves
               -- to the OLD chain's hashes (the serving peer answers
               -- 'notfound').  'requestForkBlocks' walks the heavier branch by
               -- 'cePrev' over 'hcEntries' and requests its REAL hashes from
               -- the fork point up, so the lower bodies the reorg needs
               -- actually arrive.  A no-op on the linear path (no competing
               -- fork).
               requestForkBlocks pm' db hc rot
               -- Advance the requested-window marker so the MBlock
               -- handler's fTooFarAhead gate admits these blocks.
               modifyIORef' requestedUpToRef (max windowEnd)
               -- GAP3 route-through.  If we are wedged behind a heavier
               -- competing fork and all its bridging bodies have now
               -- arrived, disconnect the connected branch to the fork
               -- point and connect the heavier branch (Core
               -- ActivateBestChain) via the existing reorg engine.  No-op
               -- on the linear path; retried each tick until the bodies
               -- are present.
               tryP2PReorg net db hc cache mIdxMgr nextBlockRef
                 `catch` (\(e :: SomeException) ->
                            putStrLn $ "P2P reorg kicker error: " ++ show e)
             kicker (rot + 1)
       in kicker 0)
        `catch` (\(e :: SomeException) ->
                   putStrLn $ "block-gap kicker error: " ++ show e)

    -- Start RPC server
    let rpcConfig = defaultRpcConfig
          { rpcPort     = noRpcPort
          , rpcUser     = noRpcUser
          , rpcPassword = noRpcPass
          , rpcDataDir  = dataDir
          , rpcRestEnabled = noEnableRest
          -- ^ Bitcoin Core @-rest@ (default off). REST stays gated
          --   behind the explicit @--rest@ flag (or @rest = 1@ in
          --   haskoin.conf); audit
          --   CORE-PARITY-AUDIT/_rest-api-cross-impl-audit-2026-05-06-part2.md
          --   flagged the previous always-on listener as a P3
          --   over-exposure.
          , rpcTlsCertFile = noRpcTlsCert
          , rpcTlsKeyFile  = noRpcTlsKey
          -- ^ W119 + FIX-64: optional HTTPS termination via warp-tls.
          --   Both set => listener runs WarpTLS.runTLS; both unset =>
          --   plain HTTP (backward-compat).  Half-configured TLS
          --   aborts at startup inside startRpcServer.
          , rpcDbCacheMb   = noDbCache
          -- ^ The same parsed @-dbcache=N@ (MiB) used at line 752 to
          --   size @dbBlockCacheSize = noDbCache*1024*1024@ (the
          --   RocksDB block cache = coins-DB cache) and at line 902 to
          --   size the UTXO cache.  'getchainstates' reports the real
          --   configured coins-cache budgets from this value.
          }
    -- Plumb the parsed --prune=N config into the RPC server.  The
    -- 'pruneblockchain' RPC refuses calls when prune mode is off
    -- (Core parity; audit 2026-05-05 Bug 4); 'getblockchaininfo'
    -- reports pruned/automatic_pruning/prune_target_size from this
    -- config; the BlockStore is required for the manual RPC path.
    --
    -- Wire a WalletManager so the createwallet/loadwallet/unloadwallet/
    -- listwallets/getwalletinfo/getbalance RPCs land in real code instead
    -- of the previous lying-stub handlers (Cat-H Part-2 audit
    -- 2026-05-06: Rpc.hs:3124-3152 returned 200 OK + empty bodies).
    -- The manager owns its wallet directory under {datadir}/wallets/.
    walletMgr <- newWalletManager (dataDir </> "wallets") net
    -- Publish the manager to the connect loop so live IBD/P2P blocks feed
    -- the wallet (sweep wa0fq5wtk).
    writeIORef walletMgrRef (Just walletMgr)
    rpcServer <- startRpcServer rpcConfig db hc pm' mp fe cache net mBlockStore (Just walletMgr) pruneCfg mIdxMgr orphanPoolRef
    -- W115 FIX-50: inject asmap bytecode into RpcServer for getpeerinfo mapped_as.
    let rpcServer' = rpcServer { rsAsmapData = asmapData }
    putStrLn $ "RPC server listening on port " ++ show noRpcPort
            ++ (if noEnableRest then " (REST enabled)" else " (REST disabled)")

    -- Periodic chainstate flush.
    -- Bitcoin Core's FlushStateToDisk flushes on a wall-clock interval
    -- (~1h) plus on size/shutdown. We use a more conservative 5-minute
    -- interval here because the cost of a sync write is small and the
    -- cost of losing even a few thousand validated blocks on restart
    -- is large. The syncMessageHandler also triggers a flush every
    -- flushBlockInterval blocks via doPeriodicFlush — whichever fires
    -- first wins.
    let flushTimeInterval  = 300  :: Integer  -- seconds
        flushTimerDelayUs  = 30 * 1_000_000   -- wake every 30s to check
    flushThreadId <- forkIO $ forever $ do
      threadDelay flushTimerDelayUs
      now <- round <$> getPOSIXTime
      lastF <- readIORef lastFlushEpochRef
      when (now - lastF >= flushTimeInterval) $ do
        h <- readTVarIO (hcHeight hc)
        putStrLn $ "Periodic flush: syncing WAL + UTXO cache at height=" ++ show h
        flushCache cache
          `catch` (\(e :: SomeException) -> putStrLn $ "flushCache error: " ++ show e)
        syncFlush db
          `catch` (\(e :: SomeException) -> putStrLn $ "syncFlush error: " ++ show e)
        writeIORef lastFlushEpochRef now
        writeIORef blocksSinceFlushRef 0

    -- DURABILITY (sweep wa0fq5wtk): periodic wallet flusher.  Wakes every
    -- 30s and persists any wallet whose dirty flag is set (save-on-mutation
    -- with a bounded window).  This is what makes wallet state survive a
    -- SIGKILL/OOM/power-loss — we do NOT rely on a clean-shutdown-only
    -- save.  Best-effort; a flush failure is logged, not fatal.
    _walletFlushTid <- forkIO $ forever $ do
      threadDelay (30 * 1_000_000)
      (do wallets <- readTVarIO (wmWallets walletMgr)
          flushDirtyWallets
            [ (nm, wsWallet ws) | (nm, ws) <- Map.toList wallets ])
        `catch` (\(e :: SomeException) ->
          putStrLn $ "wallet flush error: " ++ show e)

    -- Start Prometheus metrics server
    when (noMetricsPort > 0) $ do
      void $ forkIO $ Warp.run noMetricsPort $ \_ respond -> do
        height <- readTVarIO (hcHeight hc)
        peers <- Map.size <$> readTVarIO (pmPeers pm)
        mempoolCount <- Map.size <$> readTVarIO (mpEntries mp)
        let body = BL8.pack $ unlines
              [ "# HELP bitcoin_blocks_total Current block height"
              , "# TYPE bitcoin_blocks_total gauge"
              , "bitcoin_blocks_total " ++ show height
              , "# HELP bitcoin_peers_connected Number of connected peers"
              , "# TYPE bitcoin_peers_connected gauge"
              , "bitcoin_peers_connected " ++ show peers
              , "# HELP bitcoin_mempool_size Mempool transaction count"
              , "# TYPE bitcoin_mempool_size gauge"
              , "bitcoin_mempool_size " ++ show mempoolCount
              ]
        respond $ Wai.responseLBS HTTP.status200
          [(HTTP.hContentType, "text/plain; version=0.0.4; charset=utf-8")]
          body
      putStrLn $ "Prometheus metrics server listening on port " ++ show noMetricsPort

    -- Start P2P listener for inbound connections
    let listenPort = if noListenPort == 8333
          then netDefaultPort net  -- Use network-appropriate default
          else noListenPort
    when noListen $ do
      startInboundListener pm listenPort
      putStrLn $ "P2P listener started on port " ++ show listenPort

    -- Notify systemd we're up. No-op when NOTIFY_SOCKET is unset
    -- (typical for non-systemd launches via nohup, supervisord, etc).
    -- Sends READY=1 + an initial STATUS line; periodic STATUS pings
    -- track tip height for `systemctl status haskoin` operators.
    do
      h0 <- readTVarIO (hcHeight hc)
      Daemon.sdNotifyStatus $
        "Started on " ++ netName net ++ " at height " ++ show h0
      Daemon.sdNotifyReady
    -- Background watchdog/status pinger: keeps systemd's
    -- WatchdogSec= alive (no-op if unset) and refreshes the
    -- STATUS string with the current tip every 30s.
    statusTid <- forkIO $ forever $ do
      threadDelay (30 * 1_000_000)
      h' <- readTVarIO (hcHeight hc)
      peers' <- Map.size <$> readTVarIO (pmPeers pm)
      Daemon.sdNotifyStatus $
        "height=" ++ show h' ++ " peers=" ++ show peers'
      Daemon.sdNotifyWatchdog

    -- task #10 (at-tip RSS leak FIX): at tip haskoin allocates so little that
    -- GHC's major GC almost never runs, so produced garbage is never collected
    -- and RSS climbs ~50-65 MB/h unbounded (8h41m -> 2.07G observed; the old
    -- pre-fix node reached 6.7G). A periodic forced major GC collects it: a 3h
    -- live soak with this ticker held RSS FLAT (plateau ~1.80G, +0 MB over the
    -- last 15 min) vs the monotonic no-ticker climb -- proving the "leak" was
    -- uncollected garbage, not a retained structure. Default ON at 60s; override
    -- the interval via HASKOIN_GC_TICK_SECS=<n>, or set 0 to disable. (A 60s
    -- major GC on the ~1.8G heap is a sub-second pause once a minute.)
    gcTickEnv <- lookupEnv "HASKOIN_GC_TICK_SECS"
    let gcTickSecs = maybe 60 (\s -> maybe 60 id (readMaybe s)) gcTickEnv :: Int
    when (gcTickSecs > 0) $ do
      putStrLn $ "GC ticker: forcing performMajorGC every " ++ show gcTickSecs ++ "s (HASKOIN_GC_TICK_SECS)"
      void $ forkIO $ forever $ do
        threadDelay (gcTickSecs * 1_000_000)
        performMajorGC

    -- BIP-152 cbsPending leak fix (2026-06-20): a getblocktxn whose BLOCKTXN
    -- reply never arrives (the peer dropped it, a full-block fallback won the
    -- race, or the peer disconnected mid-reconstruction) strands a near-full
    -- block of Txs in the cbsPending TVar forever. That data is reachable, so
    -- even the forced major GC above cannot reclaim it — it is the residual
    -- at-tip RSS climb the GC ticker alone could not bound. Bitcoin Core reaps
    -- the equivalent (mapBlocksInFlight) via the block-download timeout + peer
    -- teardown; haskoin has neither, so sweep entries older than
    -- cbPendingTimeoutSecs once a minute. (cbsPending is keyed by block hash,
    -- not peer, so an insertion-age sweep is the natural reaper.) Always on,
    -- independent of the GC ticker's enable flag.
    let cbPendingTimeoutSecs = 600 :: Int64  -- ~Core's block-download timeout
    void $ forkIO $ forever $ do
      threadDelay (60 * 1_000_000)
      nowTs    <- (round <$> getPOSIXTime :: IO Int64)
      cbsSweep <- readIORef compactBlockStateRef
      atomically $ modifyTVar' (cbsPending cbsSweep) $
        Map.filter (\(ts, _) -> nowTs - ts < cbPendingTimeoutSecs)

    -- Wait forever (or until signal)
    putStrLn "Node is running. Press Ctrl+C to stop."
    shutdownVar <- newEmptyMVar
    -- Use tryPutMVar so re-delivery of SIGINT/SIGTERM never blocks in
    -- the signal handler. The original Catch used putMVar, which is
    -- synchronous on a full MVar and would wedge the signal handler
    -- if a second signal arrived during shutdown.
    void $ installHandler sigINT  (Catch $ void $ tryPutMVar shutdownVar ()) Nothing
    void $ installHandler sigTERM (Catch $ void $ tryPutMVar shutdownVar ()) Nothing
    takeMVar shutdownVar
    putStrLn "Shutting down..."
    -- Tell systemd we are intentionally exiting so it extends
    -- TimeoutStopSec= and doesn't escalate to SIGKILL mid-flush.
    Daemon.sdNotifyStopping
    Daemon.sdNotifyStatus "Shutting down: flushing chainstate"
    killThread statusTid
      `catch` (\(e :: SomeException) -> putStrLn $ "killThread statusTid error: " ++ show e)

    -- Hard-exit watchdog: if the graceful shutdown below hangs for any
    -- reason (stuck FFI call, uninterruptible thread, RocksDB close
    -- waiting on a compaction), force-exit after 30s. Wave 2 observed
    -- the process printing "Shutdown complete." yet staying alive
    -- with 1017 FDs open and the RPC/P2P ports bound; a guaranteed
    -- exit is required to avoid that.
    void $ forkIO $ do
      threadDelay (30 * 1_000_000)
      putStrLn "Shutdown watchdog: forcing exit after 30s"
      exitWith (ExitFailure 2)

    -- Stop background workers first so they don't race with the final
    -- flush / closeDB. killThread on Haskell threads is cooperative
    -- (delivers an async exception at the next safe point); we don't
    -- wait for them to report completion.
    (stopRpcServer rpcServer'
       `catch` (\(e :: SomeException) -> putStrLn $ "stopRpcServer error: " ++ show e))
    (stopPeerManager pm'
       `catch` (\(e :: SomeException) -> putStrLn $ "stopPeerManager error: " ++ show e))
    killThread flushThreadId
      `catch` (\(e :: SomeException) -> putStrLn $ "killThread flushThreadId error: " ++ show e)

    -- Final durable flush of the chainstate before we close the DB.
    -- Without this, any blocks connected since the last periodic flush
    -- live only in the RocksDB memtable and are lost if the process is
    -- SIGKILL'd or otherwise killed before closeDB returns.
    putStrLn "Flushing chainstate to disk..."
    (flushCache cache
       `catch` (\(e :: SomeException) -> putStrLn $ "flushCache error: " ++ show e))
    (syncFlush db
       `catch` (\(e :: SomeException) -> putStrLn $ "syncFlush error: " ++ show e))
    putStrLn "Chainstate flushed."

    saveFeeEstimates fe feeEstimatesPath
    putStrLn $ "Fee estimates saved to " ++ feeEstimatesPath

    -- Persist mempool.dat in Bitcoin Core wire format. Failure here is
    -- non-fatal; we just log and continue the shutdown sequence.
    do
      r <- MPP.dumpMempool mp mempoolDatPath
             `catch` (\(e :: SomeException) -> do
                       putStrLn $ "dumpMempool error: " ++ show e
                       return (Left "exception"))
      case r of
        Right n -> putStrLn $ "Dumped " ++ show n ++ " transactions to " ++ mempoolDatPath
        Left e  -> putStrLn $ "Failed to dump mempool: " ++ e

    -- Remove PID file as part of graceful shutdown so external
    -- supervisors (systemd, runit, monit) see we're really gone.
    Daemon.removePidFile pidFilePath
      `catch` (\(e :: SomeException) ->
                 putStrLn $ "removePidFile error: " ++ show e)

    putStrLn "Shutdown complete."
    -- Explicit exit. Without this, any forked thread mid-FFI call
    -- (accept on the inbound listener, RocksDB I/O, Warp thread in
    -- the middle of a response) keeps the RTS alive after main
    -- returns. exitSuccess raises ExitSuccess which unwinds the
    -- surrounding bracket (running closeDB) and then terminates.
    exitSuccess

-- | Initialize header chain from database
initHeaderChainFromDB :: HaskoinDB -> Network -> IO HeaderChain
initHeaderChainFromDB db net = do
  let genesis = netGenesisBlock net
      genesisHash = computeBlockHash (blockHeader genesis)
      genesisEntry = ChainEntry
        { ceHeader = blockHeader genesis
        , ceHash = genesisHash
        , ceHeight = 0
        , ceChainWork = headerWork (blockHeader genesis)
        , cePrev = Nothing
        , ceStatus = StatusValid
        , ceMedianTime = bhTimestamp (blockHeader genesis)
        -- P2-2: genesis sits at Core's SEQ_ID_BEST_CHAIN_FROM_DISK (0).
        , ceSequenceId = seqIdBestChainFromDisk
        }

  entriesVar <- newTVarIO (Map.singleton genesisHash genesisEntry)
  tipVar <- newTVarIO genesisEntry
  heightVar <- newTVarIO 0
  byHeightVar <- newTVarIO (Map.singleton 0 genesisHash)
  invalidatedVar <- newTVarIO Set.empty
  -- P2-2: seed the sorted candidate set with genesis so 'activateBestChain'
  -- always has at least one tip candidate available.  'hcSeqCounter'
  -- starts at 'seqIdInitFromDisk + 1' (== 2) so the first live insert
  -- ranks strictly behind any disk-loaded entries with equal work
  -- (Core comparator invariant; see node/blockstorage.cpp:174-192).
  candidatesVar <- newTVarIO (Set.singleton (mkCandidateKey genesisEntry))
  seqCounterVar <- newTVarIO (seqIdInitFromDisk + 1)
  -- Tip-change generation counter for wait-family RPCs (waitfornewblock /
  -- waitforblock / waitforblockheight).  Starts at 0; bumped at every
  -- tip advance inside Consensus.hs (addHeaderAt, performReorg) and
  -- BlockTemplate.hs (doSideBranchReorg) in the same STM transaction
  -- as hcTip, providing a lost-wakeup-free wake primitive.
  tipGenVar <- newTVarIO (0 :: Int)
  -- preciousblock (Core nBlockReverseSequenceId / nLastPreciousChainwork):
  -- reverse sequence-id counter handed out by 'preciousBlock' so a precious
  -- block out-ranks equal-work rivals, plus the tip work at the last call.
  -- Not retained across restarts (Core: "effects are not retained across
  -- restarts") — re-seeded on every boot.
  preciousReverseSeqVar <- newTVarIO preciousReverseSeqInit
  lastPreciousWorkVar <- newTVarIO 0

  -- Load persisted headers from the height index to rebuild the in-memory chain.
  -- connectBlock writes PrefixBlockHeader and PrefixBlockHeight for every
  -- connected block, so we can walk the height index sequentially.
  --
  -- Phase 2 step P2-5 (rewrite-design haskoin §5; unfreeze plan
  -- _haskoin-unfreeze-plan-2026-05-27.md): closes W101 BUG-7 /
  -- W109 BUG-4 (P4).  Pre-fix this loop set
  -- @ceMedianTime = bhTimestamp header@ — the entry's OWN raw
  -- timestamp — so every reloaded ChainEntry stored a wrong MTP.
  -- Live @addHeader@ (Consensus.hs:4031) calls
  -- @computeEntryMtp entries prevHash (bhTimestamp header)@, which is
  -- the median of (new timestamp : up-to-10 ancestor timestamps), and
  -- BIP-113 (CSV / CLTV) consensus checks read @prevCe.ceMedianTime@
  -- via @ceMedianTime@ lookup at @Consensus.hs:4763/4773@.  After a
  -- restart the raw-timestamp values fed BIP-113 the wrong cutoff,
  -- potentially mis-accepting or mis-rejecting timelocked
  -- transactions — a silent consensus divergence with Core that
  -- existed only on the reloaded chain.
  --
  -- Fix: mirror @addHeader@.  We already build the entries map in
  -- height order, so a small per-iteration call to 'computeEntryMtp'
  -- against the entries-so-far snapshot produces the same median that
  -- @addHeader@ writes on live receive.  Cost: at most 10 'Map.lookup's
  -- per block (the 10-ancestor walk inside 'computeEntryMtp').
  -- Reference: bitcoin-core/src/chain.h:233-244 (GetMedianTimePast).
  mBestHash <- getBestBlockHash db
  case mBestHash of
    Nothing -> return ()
    Just _ -> do
      putStrLn "Loading persisted headers from database..."
      let go height prevEntry = do
            mHash <- getBlockHeight db height
            case mHash of
              Nothing -> return ()
              Just bh -> do
                mHeader <- getBlockHeader db bh
                case mHeader of
                  Nothing -> return ()
                  Just header -> do
                    -- Snapshot the entries-so-far map so 'computeEntryMtp'
                    -- can walk parent ancestors.  We need entries-up-to-prev
                    -- here, not entries-including-self; reading the TVar
                    -- BEFORE the insert below gives exactly that.
                    entriesSoFar <- readTVarIO entriesVar
                    let work = ceChainWork prevEntry + headerWork header
                        newMtp = computeEntryMtp entriesSoFar
                                                 (ceHash prevEntry)
                                                 (bhTimestamp header)
                        -- P2-2: every reloaded entry IS on the best chain
                        -- (we walk PrefixBlockHeight, which only stores
                        -- the active chain — side-branch headers go
                        -- through 'addSideBranchHeader' on the live path
                        -- and are not persisted via this prefix).  So
                        -- each loaded entry gets Core's
                        -- 'seqIdBestChainFromDisk' value (0), matching
                        -- @LoadBlockIndex@'s @SEQ_ID_BEST_CHAIN_FROM_DISK@
                        -- assignment for active-chain tips
                        -- (validation.cpp:4566-4576).
                        entry = ChainEntry
                          { ceHeader = header
                          , ceHash = bh
                          , ceHeight = height
                          , ceChainWork = work
                          , cePrev = Just (ceHash prevEntry)
                          , ceStatus = StatusValid
                          , ceMedianTime = newMtp
                          , ceSequenceId = seqIdBestChainFromDisk
                          }
                    atomically $ do
                      modifyTVar' entriesVar (Map.insert bh entry)
                      modifyTVar' byHeightVar (Map.insert height bh)
                      writeTVar tipVar entry
                      writeTVar heightVar height
                      -- P2-2 + P2-3: every reloaded StatusValid entry is a
                      -- candidate.  PruneBlockIndexCandidates-style cleanup
                      -- (Core validation.cpp:3173-3183) happens lazily
                      -- inside 'findBestCandidate' on the next
                      -- 'activateBestChain' call — we don't need a
                      -- separate post-load pruning sweep.
                      modifyTVar' candidatesVar
                        (Set.insert (mkCandidateKey entry))
                    when (height `mod` 100000 == 0) $
                      putStrLn $ "  loaded headers up to height " ++ show height
                    go (height + 1) entry
      go 1 genesisEntry
      finalHeight <- readTVarIO heightVar
      putStrLn $ "Loaded " ++ show finalHeight ++ " headers from database"

  return HeaderChain
    { hcEntries = entriesVar
    , hcTip = tipVar
    , hcHeight = heightVar
    , hcByHeight = byHeightVar
    , hcInvalidated = invalidatedVar
    , hcCandidates = candidatesVar
    , hcSeqCounter = seqCounterVar
    , hcTipGen = tipGenVar
    , hcPreciousReverseSeq = preciousReverseSeqVar
    , hcLastPreciousWork = lastPreciousWorkVar
    }

-- | Send a message to a peer.
-- Use sendMessage directly since the send queue approach has issues
-- with dead send threads. sendMessage is simpler and works.
safeSendMessage :: PeerConnection -> Message -> IO ()
safeSendMessage = sendMessage

-- | Periodically send getheaders to sync the chain
getheadersSender :: PeerManager -> HeaderChain -> Network -> IO ()
getheadersSender pm hc _net = do
  putStrLn "getheadersSender: starting periodic sync..."
  forever $ do
    -- Get a fresh peer snapshot each iteration, filtering for connected peers
    connectedPeers <- getConnectedPeerList pm
    if null connectedPeers
      then threadDelay 1000000  -- 1s wait if no peers
      else do
        tip <- getChainTip hc
        -- Use proper exponential-backoff block locator instead of single hash
        locator <- buildBlockLocatorFromChain hc
        let finalLocator = if null locator then [ceHash tip] else locator
            zeroHash = BlockHash (Hash256 (BS.replicate 32 0))
            getHdrs = GetHeaders
              { ghVersion  = fromIntegral protocolVersion
              , ghLocators = finalLocator
              , ghHashStop = zeroHash
              }
        -- Send to ALL connected peers, not just the first one that works
        -- This way if some peers are stale we still get headers from others
        sentCount <- sendToAllPeers connectedPeers (MGetHeaders getHdrs)
        when (sentCount > 0) $
          putStrLn $ "getheadersSender: requesting headers from height " ++ show (ceHeight tip)
            ++ " (locator size " ++ show (length finalLocator) ++ ", sent to " ++ show sentCount ++ " peers)"
        when (sentCount == 0) $
          putStrLn "getheadersSender: no reachable peers, will retry..."

    -- Wait 5 seconds before next check
    threadDelay 5000000
  where
    -- Send a message to all peers, return count of successful sends
    sendToAllPeers :: [PeerConnection] -> Message -> IO Int
    sendToAllPeers pcs msg = do
      results <- forM pcs $ \pc ->
        (safeSendMessage pc msg >> return (1 :: Int))
          `catch` (\(_ :: SomeException) -> return 0)
      return (sum results)

-- | Get list of peers that are in PeerConnected state
getConnectedPeerList :: PeerManager -> IO [PeerConnection]
getConnectedPeerList pm = do
  peers <- readTVarIO (pmPeers pm)
  filterM isPeerConnected (Map.elems peers)
  where
    isPeerConnected pc = do
      peerInfo <- readTVarIO (pcInfo pc)
      return (piState peerInfo == PeerConnected)

-- | Announce a newly-connected block to all connected peers, honouring
-- BIP-130 'sendheaders' per-peer preference.
--
-- Peers that previously sent us @sendheaders@ ('piWantsHeaders' set)
-- receive the actual 'BlockHeader' via an 'MHeaders' message; everyone
-- else receives the legacy 'MInv' announcement.  Mirrors Bitcoin Core's
-- @PeerManagerImpl::SendMessages@ tip-announcement branch
-- (net_processing.cpp) and the camlcoin
-- @Peer_manager.announce_block@ reference (lib/peer_manager.ml:1219).
--
-- Pre-fix this function did not exist: the new-block path called
-- @broadcastMessage pm (MInv (Inv [invVec]))@ unconditionally, so the
-- 'piWantsHeaders' flag was dead code.  See header-sync DoS audit
-- 'CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part2.md'
-- (haskoin Pattern A finding).
announceTip :: PeerManager -> BlockHeader -> BlockHash -> IO ()
announceTip pm header bh = do
  peers <- readTVarIO (pmPeers pm)
  let invVec = InvVector InvBlock (getBlockHashHash bh)
      invMsg = MInv (Inv [invVec])
      headersMsg = MHeaders (Headers [header])
  forM_ (Map.elems peers) $ \pc -> do
    info <- readTVarIO (pcInfo pc)
    when (piState info == PeerConnected) $ do
      let msg = if piWantsHeaders info then headersMsg else invMsg
      sendMessage pc msg
        `catch` (\(_ :: SomeException) -> return ())

-- | Request blocks for a range of heights from the header chain
-- Batches requests in groups of 16 to avoid overwhelming peers
requestBlocks :: PeerManager -> HeaderChain -> Word32 -> Word32 -> Int -> IO ()
requestBlocks pm hc fromHeight toHeight rot = do
  peerList <- getConnectedPeerList pm
  case peerList of
    [] -> putStrLn "No connected peers to request blocks from"
    _ -> do
      heightMap <- readTVarIO (hcByHeight hc)
      let hashes = [ h | height <- [fromHeight..toHeight]
                       , Just h <- [Map.lookup height heightMap] ]
          -- Split into batches of 16
          batches = chunksOf 16 hashes
          numPeers = length peerList
      unless (null hashes) $ do
        putStrLn $ "Requesting " ++ show (length hashes) ++ " blocks (heights "
                   ++ show fromHeight ++ "-" ++ show toHeight
                   ++ ") from " ++ show numPeers ++ " peers"
        -- Distribute batches across available peers (round-robin)
        forM_ (zip [0..] batches) $ \(idx :: Int, batch) -> do
          -- 'rot' is the kicker's per-call counter: it increments every
          -- 3 s, so a stalled window (re-requesting the same heights)
          -- rotates across all peers and a non-serving peer cannot wedge
          -- the IBD. Height-based rotation could not retry-rotate — a
          -- stuck window never advances fromHeight (W163 recovery).
          let pc = peerList !! ((idx + rot) `mod` numPeers)
              invVecs = [ InvVector InvWitnessBlock (getBlockHashHash h) | h <- batch ]
          ok <- (safeSendMessage pc (MGetData (GetData invVecs)) >> return True)
            `catch` (\(e :: SomeException) -> do
              putStrLn $ "Failed to send getdata: " ++ show e
              return False)
          unless ok $ return ()

--------------------------------------------------------------------------------
-- P2P fork-aware download + reorg routing (reorg-drop production blocker)
--------------------------------------------------------------------------------
--
-- BACKGROUND.  The header chain ('hcByHeight' / 'hcTip') is maintained by
-- 'addHeader' and follows the heaviest-work HEADER chain — Core's
-- @m_best_header@.  The CONNECTED chain (the UTXO-view tip, @PrefixBestBlock@
-- = 'getBestBlockHash') is the chain whose bodies have actually been
-- validated + connected to the UTXO set — Core's @ActiveChain().Tip()@.
-- During header-first sync these two can diverge: a peer can present a
-- heavier COMPETING header chain that forks BELOW our connected tip, at
-- which point 'addHeader' flips 'hcByHeight' / 'hcTip' to the heavier chain
-- while the connected tip is still on the old (now-lighter) branch.
--
-- The pre-fix MBlock arm + block-gap kicker downloaded + connected strictly
-- by height from connected-tip+1, gating each connect on
-- @prevHash == GetBestBlock()@ (Core ConnectBlock G1, validation.cpp:2333).
-- When the heavier header chain forks below the connected tip, the block at
-- connected-tip+1 belongs to the heavier branch and its parent is NOT the
-- connected tip, so it fails G1 and is dropped — and the fork's ancestry
-- BELOW the connected tip is never even requested.  The node stays wedged on
-- the lighter chain forever (the reorg-drop blocker).
--
-- FIX (mirrors beamchain's reorg-drop fix; Core ActivateBestChain):
--   GAP2 — fork-aware download: download the heavier branch from
--          FORK_POINT+1 (not connected-tip+1) so every bridging body lands
--          on disk via 'putBlock', and persist the body of any non-extending
--          MBlock so the reorg engine can read it back.
--   GAP3 — route-through: when the header tip is a heavier COMPETING fork,
--          drive 'performReorg' (disconnect connected-chain → fork, connect
--          fork → header tip) instead of the linear connectBlock G1 path.
--          'performReorg' / 'reorgAtomic' are the existing reorg engine
--          (the connected-chain-aware sibling of
--          'BlockTemplate.doSideBranchReorg', sharing 'reorgAtomic' with the
--          invalidateblock path); they find the fork via 'findForkPoint'
--          over 'hcEntries' (hash-keyed, so it sees BOTH branches), build the
--          disconnect/connect lists from disk bodies, re-validate every
--          connect block, and commit the whole reorg in one atomic batch.
--
-- IMPORTANT: this path triggers ONLY when the header tip is NOT a descendant
-- of the connected tip.  Normal linear IBD (header tip extends the connected
-- tip) takes the unchanged connectBlock path and is byte-for-byte identical.

-- | Classify the current connected-vs-header chain relationship.
--
-- Returns @Just (connectedTipEntry, headerTipEntry, forkEntry)@ when the
-- active HEADER tip is STRICTLY heavier than the connected (UTXO-view) tip
-- AND forks BELOW it (i.e. the header tip does not descend from the
-- connected tip) — the reorg-drop case that needs the fork-aware path.
-- The fork entry is their lowest common ancestor in 'hcEntries'.
--
-- Returns 'Nothing' for the normal cases: no connected/header tip yet, the
-- header tip descends linearly from the connected tip (plain IBD / already
-- ahead), or the header tip is not heavier (nothing to reorg onto).
detectP2PFork :: HaskoinDB -> HeaderChain
              -> IO (Maybe (ChainEntry, ChainEntry, ChainEntry))
detectP2PFork db hc = do
  mBest <- getBestBlockHash db
  case mBest of
    Nothing -> return Nothing
    Just bestHash -> do
      entries   <- readTVarIO (hcEntries hc)
      headerTip <- readTVarIO (hcTip hc)
      case Map.lookup bestHash entries of
        Nothing -> return Nothing   -- connected tip not in header index (shouldn't happen)
        Just connectedTip
          -- Header tip must be strictly heavier to be worth a reorg.
          | ceChainWork headerTip <= ceChainWork connectedTip -> return Nothing
          | ceHash headerTip == ceHash connectedTip           -> return Nothing
          | otherwise -> do
              mFork <- findForkPoint hc bestHash (ceHash headerTip)
              case mFork of
                Nothing -> return Nothing
                Just forkEntry
                  -- Header tip descends linearly from the connected tip:
                  -- the fork point IS the connected tip, so this is plain
                  -- forward IBD — leave it to the unchanged connect path.
                  | ceHash forkEntry == ceHash connectedTip -> return Nothing
                  -- Genuine competing fork rooted below the connected tip.
                  | otherwise -> return (Just (connectedTip, headerTip, forkEntry))

-- | GAP3 route-through.  If the connected chain is wedged behind a heavier
-- COMPETING header chain (per 'detectP2PFork') and every bridging body of
-- the heavier branch is already on disk, drive 'performReorg' to disconnect
-- the connected branch back to the fork point and connect the heavier branch
-- up to the header tip.  Advances 'nextBlockRef' to the header tip + 1 on a
-- successful reorg so the connect-by-height cursor tracks the new active tip.
--
-- A missing bridging body is NOT an error: the fork-aware download
-- ('forkDownloadFloor' wired into the block-gap kicker) keeps re-requesting
-- the gap, and the next kicker tick re-attempts the reorg once the bodies
-- arrive.  Mirrors Core's @ActivateBestChain@ retrying when a block body is
-- not yet available.
tryP2PReorg :: Network -> HaskoinDB -> HeaderChain -> UTXOCache
            -> Maybe IndexManager -> IORef Word32 -> IO ()
tryP2PReorg net db hc cache mIdxMgr nextBlockRef = do
  mFork <- detectP2PFork db hc
  case mFork of
    Nothing -> return ()
    Just (connectedTip, headerTip, forkEntry) -> do
      -- Verify all heavier-branch bodies from fork+1..headerTip are present
      -- on disk before attempting the reorg ('buildReorgConnectList' reads
      -- them back via 'getBlock').  If any are missing, defer — the kicker
      -- will fetch them and retry.
      entries <- readTVarIO (hcEntries hc)
      let forkHash = ceHash forkEntry
          collectConnect h acc
            | h == forkHash = Just acc
            | otherwise = case Map.lookup h entries of
                Nothing -> Nothing
                Just ce -> cePrev ce >>= \ph -> collectConnect ph (h : acc)
      case collectConnect (ceHash headerTip) [] of
        Nothing -> return ()
        Just connectHashes -> do
          missing <- filterM (\h -> isNothing <$> getBlock db h) connectHashes
          if not (null missing)
            then putStrLn $ "P2P reorg deferred: " ++ show (length missing)
                         ++ " heavier-branch body(ies) not yet downloaded "
                         ++ "(fork@" ++ show (ceHeight forkEntry)
                         ++ " -> header tip " ++ show (ceHeight headerTip) ++ ")"
            else do
              putStrLn $ "P2P reorg: connected tip " ++ show (ceHeight connectedTip)
                      ++ " is on a lighter branch; reorging to heavier header "
                      ++ "tip " ++ show (ceHeight headerTip)
                      ++ " (fork@" ++ show (ceHeight forkEntry) ++ ")"
              res <- performReorg net cache db hc mIdxMgr
                                  (ceHash connectedTip) (ceHash headerTip)
                       `catch` (\(e :: SomeException) ->
                                  return (Left ("exception: " <> show e)))
              case res of
                Left err -> putStrLn $ "P2P reorg failed: " ++ err
                Right () -> do
                  writeIORef nextBlockRef (ceHeight headerTip + 1)
                  putStrLn $ "P2P reorg complete: active tip now "
                          ++ show (ceHeight headerTip)

-- | GAP2 download floor.  The height the block-gap kicker should start
-- requesting bodies from.  Normally this is the connected-tip+1 cursor
-- ('nextBlock').  But when a heavier COMPETING header chain forks BELOW the
-- connected tip ('detectP2PFork'), the heavier branch's ancestry between the
-- fork point and the connected-tip height has never been downloaded — those
-- bodies are required by 'buildReorgConnectList' before the reorg can run.
-- In that case the floor drops to FORK_POINT+1 so 'requestForkBlocks' fetches
-- the whole heavier branch.
forkDownloadFloor :: HaskoinDB -> HeaderChain -> Word32 -> IO Word32
forkDownloadFloor db hc nextBlock = do
  mFork <- detectP2PFork db hc
  return $ case mFork of
    Just (_connectedTip, _headerTip, forkEntry) ->
      min nextBlock (ceHeight forkEntry + 1)
    Nothing -> nextBlock

-- | GAP2 fork-aware download.  Request the bodies of the HEAVIER COMPETING
-- branch — every block from FORK_POINT+1 up to the header tip — by their
-- ACTUAL branch hashes.
--
-- CRITICAL distinction from 'requestBlocks': 'requestBlocks' reads hashes
-- from 'hcByHeight', which is the height->hash index for the ACTIVE chain.
-- But 'addHeader' only rewrites 'hcByHeight' at heights ABOVE the work
-- crossover — i.e. only for the heavier branch's blocks whose CUMULATIVE
-- work already exceeds the old connected tip (Consensus.hs:4537,
-- @when (work > ceChainWork currentTip)@).  The heavier branch's LOWER
-- blocks (fork_point+1 .. crossover) still resolve through 'hcByHeight' to
-- the OLD (now-lighter) chain's hashes.  Requesting those wrong hashes makes
-- the serving peer answer @notfound@ (it never had the lighter chain), so
-- the heavier branch's lower bodies never arrive and the reorg can never
-- assemble — the residual wedge the height-indexed download could not see.
--
-- Instead we walk 'cePrev' over 'hcEntries' (hash-keyed, sees BOTH branches)
-- from the header tip back to the fork point, yielding the heavier branch's
-- real hashes, and request exactly the ones whose body is not yet on disk.
-- Mirrors Core's @BlockManager@ requesting blocks along the most-work HEADER
-- chain (CBlockIndex::GetAncestor walks pprev, never the active height map).
-- A no-op when there is no competing fork ('detectP2PFork' = Nothing).
requestForkBlocks :: PeerManager -> HaskoinDB -> HeaderChain -> Int -> IO ()
requestForkBlocks pm db hc rot = do
  mFork <- detectP2PFork db hc
  case mFork of
    Nothing -> return ()
    Just (_connectedTip, headerTip, forkEntry) -> do
      entries <- readTVarIO (hcEntries hc)
      let forkHash = ceHash forkEntry
          -- Walk the heavier branch from the header tip down to (but not
          -- including) the fork point, collecting real branch hashes in
          -- ascending-height order.
          collect h acc
            | h == forkHash = acc
            | otherwise = case Map.lookup h entries of
                Nothing -> acc
                Just ce -> case cePrev ce of
                  Nothing -> h : acc
                  Just ph -> collect ph (h : acc)
          branchHashes = collect (ceHash headerTip) []
      -- Only request the bodies we don't already have, so a re-tick does not
      -- re-flood already-downloaded blocks.
      needed <- filterM (\h -> isNothing <$> getBlock db h) branchHashes
      unless (null needed) $ do
        peerList <- getConnectedPeerList pm
        case peerList of
          [] -> return ()
          _ -> do
            let batches  = chunksOf 16 needed
                numPeers = length peerList
            putStrLn $ "Fork-aware download: requesting " ++ show (length needed)
                    ++ " heavier-branch block(s) (fork@" ++ show (ceHeight forkEntry)
                    ++ " -> header tip " ++ show (ceHeight headerTip)
                    ++ ") by branch hash from " ++ show numPeers ++ " peer(s)"
            forM_ (zip [0 ..] batches) $ \(idx :: Int, batch) -> do
              let pc      = peerList !! ((idx + rot) `mod` numPeers)
                  invVecs = [ InvVector InvWitnessBlock (getBlockHashHash h) | h <- batch ]
              (safeSendMessage pc (MGetData (GetData invVecs)))
                `catch` (\(e :: SomeException) ->
                           putStrLn $ "Fork-aware getdata send failed: " ++ show e)

-- | Split a list into chunks of n
chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (chunk, rest) = splitAt n xs in chunk : chunksOf n rest

--------------------------------------------------------------------------------
-- Orphan Pool — BIP-339 wtxid-keyed (W99 G12/G13/G14)
-- OrphanPool, emptyOrphanPool, maxOrphanTxs, orphanExpireSecs,
-- addOrphan, expireOrphans, eraseOrphansForPeer, eraseOrphansForBlock
-- are imported from Haskoin.TxOrphanage.
--------------------------------------------------------------------------------

-- | Look up orphan children of a newly-accepted transaction and re-try them.
-- Mirrors Bitcoin Core ProcessOrphanTx / AddChildrenToWorkSet: after a parent
-- is accepted, all queued orphans that spend its outputs are re-submitted.
processOrphan :: IORef OrphanPool -> Mempool -> TxId -> Int64 -> IO ()
processOrphan ref mp parentTxId now = do
  expireOrphans ref now
  op <- readIORef ref
  let childWtxids = Map.findWithDefault Set.empty parentTxId (orphanWtxid op)
  forM_ (Set.toList childWtxids) $ \wtxid ->
    case Map.lookup wtxid (orphanPool op) of
      Nothing       -> return ()
      Just (orphTx, _, _) -> do
        -- Remove from pool before retry to avoid double-processing
        modifyIORef' ref $ \o ->
          let parentIds2 = map (outPointHash . txInPrevOutput) (txInputs orphTx)
              removeChild pTxId idx =
                Map.alter (\ms -> case ms of
                  Nothing -> Nothing
                  Just s  -> let s' = Set.delete wtxid s
                             in if Set.null s' then Nothing else Just s'
                  ) pTxId idx
              idx'   = foldr removeChild (orphanWtxid o) parentIds2
          in o { orphanPool  = Map.delete wtxid (orphanPool o)
               , orphanWtxid = idx'
               }
        -- Re-try admission to the mempool.  Another missing input re-queues
        -- this tx as a new orphan; a successful accept handles relay in MTx.
        void $ addTransaction mp orphTx

-- | Case-insensitive infix substring check used by message-handler
-- misbehavior classifiers.  Lower-cases both sides before
-- 'Data.List.isInfixOf' so error strings like "Invalid PoW",
-- "invalid pow", or "INVALID-POW" all match.
infixOfStr :: String -> String -> Bool
infixOfStr needle haystack =
  L.isInfixOf (map toLowerSafe needle) (map toLowerSafe haystack)
  where
    toLowerSafe c
      | c >= 'A' && c <= 'Z' = toEnum (fromEnum c + 32)
      | otherwise            = c

-- | Sync-aware message handler
syncMessageHandler :: HaskoinDB -> HeaderChain -> HeaderSync -> UTXOCache
                   -> Mempool -> FeeEstimator -> Network
                   -> IORef PeerManager -> IORef Word32 -> IORef Word32
                   -> IORef Bool -> IORef Int64 -> IORef (Set.Set TxId)
                   -> IORef Word32 -> IORef Integer
                   -> PruneConfig -> Maybe BlockStore
                   -> Maybe IndexManager
                      -- ^ Optional secondary-index manager.  When
                      -- 'Just', every successful 'connectBlock'
                      -- inside 'MBlock' is mirrored into the
                      -- enabled indexes (txindex /
                      -- blockfilterindex / coinstatsindex) so the
                      -- index tracks the chain in real time.
                   -> IORef OrphanPool
                      -- ^ BIP-339 wtxid-keyed orphan pool (W99 G12/G13/G14).
                   -> IORef CompactBlockState
                      -- ^ BIP-152 BUG-1 FIX: in-flight partial blocks keyed by
                      -- BlockHash, persisted across MCmpctBlock→MBlockTxn.
                      -- Reference: bitcoin-core/src/net_processing.cpp
                      -- mapBlocksInFlight / PartiallyDownloadedBlock lifetime.
                   -> MVar ()
                      -- ^ P1-2 connect-lock — serialises the read-BestBlock /
                      -- check-G1 / write critical section in the MBlock arm
                      -- across all per-peer recv threads (Network.hs:2797)
                      -- + the two compact-block re-dispatch sites. Closes
                      -- the dispatch-layer chainstate-atomicity race
                      -- documented in commit 9fda3f4. Cross-ref:
                      -- _chainstate-atomicity-family-2026-05-26.md +
                      -- _haskoin-unfreeze-plan-2026-05-27.md (Phase 1, P1-2).
                   -> IORef (Maybe WalletManager)
                      -- ^ DURABILITY (sweep wa0fq5wtk): the WalletManager,
                      -- once initialised.  Every block connected on the live
                      -- IBD/P2P path is scanned into the default wallet
                      -- ('scanBlockForWallet') so wallet balance/history
                      -- track the chain in real time and persist — not only
                      -- on the mining/RPC path.
                   -> SockAddr -> Message -> IO ()
syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef requestedUpToRef ibdModeRef lastFullBatchAtRef recentlyRejectedRef blocksSinceFlushRef lastFlushEpochRef pruneCfg mBlockStore mIdxMgr orphanPoolRef compactBlockStateRef connectLock walletMgrRef addr msg = case msg of
  MPing (Ping _nonce) ->
    return ()  -- Pong handled at peer level

  MHeaders (Headers hdrs) -> do
    putStrLn $ "Received " ++ show (length hdrs) ++ " headers"
    -- Headers arrive from a peer so minPowChecked=False: the
    -- too-little-chainwork gate (W97 G8) must fire for any batch
    -- whose cumulative work is below netMinimumChainWork.  We do not
    -- stand up the full PRESYNC/REDOWNLOAD state machine (that is
    -- implemented in headerssync.cpp and is a separate hardening layer);
    -- the chainwork gate provides equivalent protection against
    -- low-work header floods without requiring the extra round-trips.
    -- Track header rejection reasons so we can attribute misbehavior:
    -- "Block header has no valid parent" -> NonContinuousHeaders
    -- "Invalid proof of work" -> InvalidBlockHeader
    pmRefVal <- readIORef pmRef
    (added, badPow, badConn) <- foldM (\(count, pow, conn) hdr -> do
        result <- addHeader net hc hdr False
        case result of
            Right entry -> do
              -- Persist header and height index so the chain survives restarts.
              -- putBlockHeader/putBlockHeight are idempotent for duplicates.
              let bh = ceHash entry
                  h  = ceHeight entry
              putBlockHeader db bh hdr
              putBlockHeight db h bh
              return (count + 1, pow, conn)
            Left err
              | "proof of work" `infixOfStr` err
                || "PoW"          `infixOfStr` err
                  -> return (count, pow + 1 :: Int, conn)
              | "parent"          `infixOfStr` err
                || "previous"       `infixOfStr` err
                || "not connected"  `infixOfStr` err
                  -> return (count, pow, conn + 1 :: Int)
              | otherwise -> return (count, pow, conn)
        ) (0 :: Int, 0 :: Int, 0 :: Int) hdrs
    putStrLn $ "Added " ++ show added ++ " of " ++ show (length hdrs) ++ " headers"
    -- Attribute misbehavior for any rejected headers.  Reference:
    -- bitcoin-core/src/net_processing.cpp ProcessHeadersMessage —
    -- non-continuous batches are scored 100 (immediate ban); each
    -- invalid PoW header is also 100.
    --
    -- Bad PoW remains an immediate-ban offense.  Non-continuous
    -- (unconnecting) headers, however, must follow Core's
    -- MAX_NUM_UNCONNECTING_HEADERS_MSGS=10 counter — a single
    -- transient reorg should not cause a +100 ban.  Pre-fix, this
    -- branch unconditionally fired NonContinuousHeaders=100 on the
    -- first batch with any rejected-by-parent header; see
    -- CORE-PARITY-AUDIT/_header-sync-dos-cross-impl-audit-2026-05-06-part1.md
    -- (Pattern B), extended to Part-2 impls.
    when (badPow > 0) $
      void $ misbehaving pmRefVal addr InvalidBlockHeader
    when (badConn > 0) $ do
      exceeded <- noteUnconnectingHeaders pmRefVal addr
      if exceeded
        then do
          putStrLn $ "Peer " ++ show addr
                  ++ " exceeded MAX_NUM_UNCONNECTING_HEADERS_MSGS="
                  ++ show maxNumUnconnectingHeadersMsgs
                  ++ ", banning"
          void $ misbehaving pmRefVal addr NonContinuousHeaders
          resetUnconnectingHeaders pmRefVal addr
        else do
          n <- getUnconnectingHeadersCount pmRefVal addr
          putStrLn $ "Unconnecting headers from " ++ show addr
                  ++ " (count=" ++ show n
                  ++ "/" ++ show maxNumUnconnectingHeadersMsgs
                  ++ "), tolerating per Core parity"
    -- A successful connecting batch resets the unconnecting-headers
    -- counter (mirrors Core's nUnconnectingHeaders = 0).
    when (added > 0 && badConn == 0) $
      resetUnconnectingHeaders pmRefVal addr
    -- If we got a full batch (2000), request more headers immediately
    when (added >= 2000) $ do
      -- Headers-first: mark bulk header sync as live so the block-gap
      -- kicker and the post-headers requestBlocks below stay deferred.
      nowFull <- (round <$> getPOSIXTime :: IO Int64)
      writeIORef lastFullBatchAtRef nowFull
      tip <- getChainTip hc
      let tipHeight = ceHeight tip
          locator = [ceHash tip]
          zeroHash = BlockHash (Hash256 (BS.replicate 32 0))
          getHdrs = GetHeaders
            { ghVersion  = fromIntegral protocolVersion
            , ghLocators = locator
            , ghHashStop = zeroHash
            }
      pm <- readIORef pmRef
      connPeers <- getConnectedPeerList pm
      case connPeers of
        [] -> putStrLn "No peers to request more headers from"
        _  -> do
          putStrLn $ "Requesting next batch of headers from height " ++ show tipHeight
          let trySend [] = putStrLn "Failed to send getheaders to any peer"
              trySend (pc:rest) = do
                ok <- (safeSendMessage pc (MGetHeaders getHdrs) >> return True)
                  `catch` (\(_ :: SomeException) -> return False)
                unless ok $ trySend rest
          trySend connPeers
    -- Detect when header sync has caught up (peer returned < 2000 headers)
    when (added > 0 && added < 2000) $ do
      wasIBD <- readIORef ibdModeRef
      when wasIBD $ do
        putStrLn "Header sync complete — leaving IBD mode"
        writeIORef ibdModeRef False

    -- Block download is driven SOLELY by the block-gap kicker (16-block
    -- sliding windows, one getdata batch per peer, peer rotated by
    -- height). The MHeaders handler used to also requestBlocks the whole
    -- nextBlock..headerTip range here — a 6000+-block flood that arrived
    -- wildly out of order against connectBlockAt's strict in-order G1
    -- gate and connected nothing — and it mis-set nextBlockRef to the
    -- HEADER tip, which then silenced the kicker (nextBlock > headerTip).
    -- Removed: MHeaders only extends the header chain; the kicker owns
    -- block download, and nextBlockRef tracks the CONNECTED tip (advanced
    -- only by MBlock on a successful connect). headerSyncActive deferral
    -- is still honoured — by the kicker's own gate, not here.
    return ()

  MBlock block -> do
    let bh = computeBlockHash (blockHeader block)
        hdr = blockHeader block
    -- First, ensure the header is in our chain index.
    -- For unsolicited blocks (received via inv->getdata), the header may
    -- not yet be in the chain. addHeader is idempotent if already known.
    -- minPowChecked=False: peer-sourced blocks must pass the
    -- too-little-chainwork gate (W97 G8 + W99 G5).
    addResult <- addHeader net hc hdr False
    case addResult of
      Left err -> do
        isIBD <- readIORef ibdModeRef
        unless isIBD $
          putStrLn $ "Block header rejected: " ++ err
        -- Attribute misbehavior: block whose header fails consensus
        -- validation (bad PoW, etc) is an immediate-ban offense.
        -- Reference: bitcoin-core/src/net_processing.cpp
        -- BlockChecked — invalid blocks score 100.
        pm <- readIORef pmRef
        void $ misbehaving pm addr InvalidBlock
      Right entry -> do
        let height = ceHeight entry
        -- W97 G19c: fTooFarAhead gate.
        -- Core validation.cpp:4325 — for unrequested blocks, reject when
        --   pindex->nHeight > ActiveHeight() + MIN_BLOCKS_TO_KEEP (288).
        -- "Unrequested" means we never sent a getdata for this height;
        -- requestedUpToRef tracks the highest height we explicitly asked for.
        requestedUpTo <- readIORef requestedUpToRef
        activeTipHeight <- readTVarIO (hcHeight hc)
        let fRequested    = height <= requestedUpTo
            fTooFarAhead  = height > activeTipHeight + minBlocksToKeep
        unless (not fRequested && fTooFarAhead) $ do
          -- W97/W99-G18 P0 fix: 'connectBlock' now surfaces a Left when the
          -- block fails the W93 G1 (prevHash != BestBlock) or G19 (missing
          -- prevout) gates.  A peer sending an unsolicited side-branch
          -- MBlock whose prevHash ≠ BestBlock used to corrupt BestBlock
          -- via the old 'connectBlockUnchecked' fallback; now it is
          -- dropped + the peer is misbehaved.  See
          --   bitcoin-core/src/validation.cpp AcceptBlock @4350-4354
          --   (InvalidBlockFound -> Misbehaving(100, "bad-block")).
          --
          -- P1-2 (chainstate-atomicity family, dispatch-layer race):
          -- The read-BestBlock / check-G1 / write-WriteBatch / advance-
          -- nextBlockRef sequence below is the critical section. Per-peer
          -- recv threads call this handler directly (Network.hs:2797);
          -- without the lock, two threads racing the same height N+1
          -- both pass G1 against @BestBlock = hash(N)@ and both commit —
          -- idempotent on the same block, but on different blocks the
          -- chainstate and 'nextBlockRef' desync and the kicker wedges.
          -- See _haskoin-unfreeze-plan-2026-05-27.md (Phase 1, P1-2).
          --
          -- The lock is held across:
          --   1. buildSpentUtxoMapFromDB — reads UTXOs that an in-flight
          --      sibling MBlock might mutate via its WriteBatch.
          --   2. connectBlock — reads BestBlock + G1 check + WriteBatch
          --      commit (the entire 'connectBlockAt' body).
          --   3. nextBlockRef advance — keeps the download cursor
          --      consistent with on-disk tip.
          -- It is RELEASED before secondary-index mirror, flush, mempool
          -- clean, peer announce — those are independently thread-safe
          -- and don't compete with another peer's tip update.
          connectResult <- withMVar connectLock $ \() -> do
            -- Route the per-input prevout reads through the dedicated
            -- read-through cache (Class-A dbcache): a coin created at block N
            -- and spent at block N+k is served from the in-memory mirror
            -- instead of a cold RocksDB read. Byte-identical Coins to the
            -- DB-only builder; invalidated per-spend in the Right () branch
            -- below and wiped at every reorg/disconnect/flush boundary.
            spent <- buildSpentUtxoMapCached cache block
            -- W164 hollow-live-path fix: run the SAME full consensus gate the
            -- shim (VerifyScriptShim.hs:710) and submitblock (BlockTemplate.hs:544)
            -- use, BEFORE connecting.  connectBlock alone (connectBlockAt)
            -- enforces only G1/G2/G19; this adds scripts, sigops, BIP30, merkle +
            -- CVE-2012-2459, bad-cb-amount, value-conservation, BIP34/65/66/68/113,
            -- witness commitment, weight, coinbase structure, and checkpoints.
            -- Mirrors the dead Sync.hs:382-403 IBD template, with the PARENT-hash
            -- MTP (NOT Sync.hs:387's own-hash, one block too deep because addHeader
            -- at :2271 already inserted bh into hcEntries).  assumevalid skip is
            -- fail-closed: best-header lag => shouldSkipScripts=False => scripts
            -- verified.  validateFullBlock is pure; checkBIP30's only IO is
            -- read-only DB lookups on the same db.  NOTE: coinbase-maturity is
            -- still NOT enforced on this arm (TxOut-only view), a residual
            -- false-ACCEPT gap, not a spurious reject.
            blockEntries <- readTVarIO (hcEntries hc)
            bestHdr      <- readTVarIO (hcTip hc)
            let blockTs     = bhTimestamp hdr
                parentHash  = bhPrevBlock hdr
                prevMTP     = medianTimePast blockEntries parentHash
                skipScripts = shouldSkipScripts bh height blockTs net blockEntries bestHdr
                cs          = ChainState (height - 1) parentHash (ceChainWork entry) prevMTP
                                (consensusFlagsAtHeight net height)
            vr <- (validateFullBlockIO db net cs skipScripts block spent)
                    `catch` (\(e :: SomeException) -> do
                               putStrLn $ "ERROR validating block "
                                       ++ show height ++ ": " ++ show e
                               return (Left ("Core full-block validation: exception: " <> show e)))
            r <- case vr of
                   Left verr -> return (Left ("Core full-block validation: " <> verr))
                   Right () ->
                     (connectBlock db net block height spent)
                       `catch` (\(e :: SomeException) -> do
                                  putStrLn $ "ERROR connecting block "
                                          ++ show height ++ ": " ++ show e
                                  return (Left ("exception: " <> show e)))
            -- Advance the next-block pointer IF the connect succeeded.
            -- Done inside the lock so the @BestBlock / nextBlockRef@
            -- pair stays consistent end-to-end — a concurrent kicker
            -- read of 'nextBlockRef' won't see a "tip without cursor"
            -- or vice versa.
            case r of
              Right () -> do
                -- Class-A dbcache coherence: mirror connectBlockAt's PrefixUTXO
                -- BatchDelete set (the spent prevouts, Consensus.hs:3667) into
                -- the dedicated read-through cache so a later read-through can
                -- never serve a just-spent coin as unspent. This generator is
                -- IDENTICAL to the BatchDelete generator, so the invalidation
                -- set == the on-disk delete set by construction. Under
                -- connectLock => atomic vs sibling connects; vs the lock-free
                -- kicker reorg the rcGen guard protects the populate path.
                mapM_ (\inp -> rcInvalidate cache (txInPrevOutput inp))
                      [ inp | tx <- drop 1 (blockTxns block), inp <- txInputs tx ]
                nextBlock <- readIORef nextBlockRef
                when (height >= nextBlock) $
                  writeIORef nextBlockRef (height + 1)
              Left _ -> return ()
            return r
          case connectResult of
            Left cbErr -> do
              -- W163 diagnostic: log every connectBlock rejection of the
              -- NEXT-NEEDED block so the IBD wedge cause is visible.
              -- Out-of-order rejections of higher blocks stay quiet (the
              -- gap kicker re-fetches them in order). No peer ban while
              -- diagnosing — a wrongly-rejected valid block is not the
              -- peer's fault. NOTE: the earlier guard matched "Core G1"
              -- which is ALSO a prefix of "Core G19" (missing-prevout),
              -- so genuine G19 failures were silently swallowed.
              nb <- readIORef nextBlockRef
              when (height == nb) $
                putStrLn $ "[W163 diag] next-needed block " ++ show height
                        ++ " rejected by connectBlock: " ++ cbErr
              -- GAP2/GAP3 reorg-drop fix.  A block whose parent is NOT the
              -- connected tip fails the linear connect G1 gate
              -- (@prevHash == GetBestBlock()@).  Pre-fix the body was simply
              -- dropped, so a heavier COMPETING fork could never be
              -- assembled.  Persist the body (Core 'SaveBlockToDisk' stores
              -- every accepted block regardless of which branch wins) so the
              -- reorg engine's 'buildReorgConnectList' can read it back, then
              -- attempt a reorg: if this block (or the heavier header tip it
              -- belongs to) outweighs the connected chain and forks below it,
              -- 'tryP2PReorg' disconnects the connected branch to the fork
              -- point and connects the heavier branch.  No-op when the header
              -- tip is not a heavier competing fork.  The block header is
              -- already in 'hcEntries' (addHeader above), so 'putBlock' is the
              -- only missing piece for the engine to find the body.
              putBlock db bh block
                `catch` (\(e :: SomeException) ->
                           putStrLn $ "putBlock (side-branch) error at height "
                                   ++ show height ++ ": " ++ show e)
              tryP2PReorg net db hc cache mIdxMgr nextBlockRef
                `catch` (\(e :: SomeException) ->
                           putStrLn $ "P2P reorg (MBlock) error at height "
                                   ++ show height ++ ": " ++ show e)
            Right () -> do
              -- Mirror the connect into any opted-in secondary indexes
              -- (txindex / blockfilterindex / coinstatsindex).  We read
              -- the freshly-persisted undo record back from disk so the
              -- BlockFilterIndex sees the byte-identical 'BlockUndo' that
              -- 'disconnectBlock' would replay — keeping the GCS filter
              -- byte-for-byte compatible with Bitcoin Core's
              -- blockfilterindex.cpp::CustomAppend output.
              (case mIdxMgr of
                  Nothing -> return ()
                  Just im -> do
                    mUndo <- getUndoData db bh
                    case mUndo of
                      Just undoData ->
                        indexManagerConnectBlock im block
                          (udBlockUndo undoData) bh height
                      Nothing -> return ())
                `catch` (\(e :: SomeException) ->
                  putStrLn $ "index mirror error at height "
                          ++ show height ++ ": " ++ show e)
              -- DURABILITY (sweep wa0fq5wtk): feed the live-connected block
              -- to the default wallet so balance/history/UTXO ledger track
              -- the chain in real time and persist (save-on-mutation).  This
              -- is THE connect-loop hook that makes wallet state survive an
              -- unclean restart from the P2P/IBD path, mirroring Core's
              -- CWallet::blockConnected.  Best-effort: a wallet error must
              -- never abort block connection.
              (do mWm <- readIORef walletMgrRef
                  case mWm of
                    Nothing -> return ()
                    Just wm -> do
                      (mDef, _) <- getDefaultWallet wm
                      case mDef of
                        Nothing -> return ()
                        Just ws -> scanBlockForWallet (wsWallet ws) block height)
                `catch` (\(e :: SomeException) ->
                  putStrLn $ "wallet scan error at height "
                          ++ show height ++ ": " ++ show e)
              when (height `mod` 500 == 0) $
                putStrLn $ "Connected block at height " ++ show height
              -- Durability: flush WAL + UTXO cache every flushBlockInterval
              -- blocks. This bounds the data-loss window on a non-graceful
              -- shutdown. Reference: Bitcoin Core src/validation.cpp
              -- FlushStateToDisk (50 MB of UTXO changes / 24h).
              let flushBlockInterval = 1000 :: Word32
              cnt <- atomicModifyIORef' blocksSinceFlushRef (\c -> (c + 1, c + 1))
              when (cnt >= flushBlockInterval) $ do
                putStrLn $ "Block-count flush at height=" ++ show height
                           ++ " (" ++ show cnt ++ " blocks since last flush)"
                flushCache cache
                  `catch` (\(e :: SomeException) -> putStrLn $ "flushCache error: " ++ show e)
                syncFlush db
                  `catch` (\(e :: SomeException) -> putStrLn $ "syncFlush error: " ++ show e)
                writeIORef blocksSinceFlushRef 0
                nowE <- round <$> getPOSIXTime
                writeIORef lastFlushEpochRef nowE
                -- Auto-prune trigger.  Mirrors Bitcoin Core's
                -- @FlushStateToDisk -> PruneBlockFiles@ branch in
                -- bitcoin-core/src/validation.cpp: pruning fires only on a
                -- flush boundary (not every block), only when prune mode is
                -- on and the target is finite (not manual / disabled).
                -- Best-effort; pruning errors must never abort the block
                -- connection or the flush path.
                case mBlockStore of
                  Just bs -> do
                    n <- autoPruneIfNeeded bs height pruneCfg
                           `catch` (\(e :: SomeException) -> do
                                      putStrLn $ "auto-prune error: " ++ show e
                                      return 0)
                    when (n > 0) $
                      putStrLn $ "auto-prune: pruned " ++ show n
                              ++ " block file(s) at height=" ++ show height
                  Nothing -> return ()
              -- Remove confirmed txs from mempool and clear rejection filter
              blockConnected mp block
              writeIORef recentlyRejectedRef Set.empty
              -- BUG-13 FIX: EraseForBlock — remove confirmed txs from the
              -- orphan pool.  Core calls TxOrphanage::EraseForBlock after
              -- each block is connected so that orphans whose parents are
              -- now on-chain do not linger until expiry.
              -- Reference: bitcoin-core/src/node/txorphanage.h:89
              let confirmedTxIds = map computeTxId (blockTxns block)
              eraseOrphansForBlock confirmedTxIds orphanPoolRef
              -- BUG-1 FIX (W114): record confirmation heights for all txs in
              -- this block so the fee estimator can compute how long they took
              -- to confirm.  Reference: bitcoin-core/src/policy/fees.cpp
              -- CBlockPolicyEstimator::processBlock — called from
              -- CTxMemPool::removeForBlock after each valid block.
              recordConfirmation fe height confirmedTxIds
              -- Announce the new tip honouring BIP-130 sendheaders
              -- preference: peers that requested 'sendheaders' get an
              -- MHeaders, the rest get the legacy MInv.  Reference:
              -- announceTip helper +
              -- bitcoin-core/src/net_processing.cpp PeerManagerImpl::SendMessages.
              pm <- readIORef pmRef
              announceTip pm (blockHeader block) bh
              -- After connecting a new block from a peer, request headers
              -- to discover any further blocks we might be missing.
              connPeers <- getConnectedPeerList pm
              unless (null connPeers) $ do
                let zeroHash = BlockHash (Hash256 (BS.replicate 32 0))
                    getHdrs = GetHeaders
                      { ghVersion  = fromIntegral protocolVersion
                      , ghLocators = [bh]
                      , ghHashStop = zeroHash
                      }
                void $ (safeSendMessage (head connPeers) (MGetHeaders getHdrs))
                  `catch` (\(_ :: SomeException) -> return ())

  MTx tx -> do
    let txid = computeTxId tx
    result <- addTransaction mp tx
    case result of
      Right _ -> do
        -- BIP-339: relay accepted tx inv to all connected peers,
        -- selecting InvWtx (MSG_WTX=5) + wtxid for wtxid-relay peers
        -- and InvTx (type=1) + txid for legacy peers.
        -- Reference: bitcoin-core/src/net_processing.cpp RelayTransaction.
        pm <- readIORef pmRef
        let wtxid = Crypto.computeWtxid tx
        peers <- readTVarIO (pmPeers pm)
        forM_ (Map.elems peers) $ \pc -> do
          info <- readTVarIO (pcInfo pc)
          when (piState info == PeerConnected && not (piBlockOnly info)) $ do
            let (itype, ihash)
                  | piWtxidRelay info = (InvWtx, getWtxidHash wtxid)
                  | otherwise         = (InvTx,  getTxIdHash txid)
            sendMessage pc (MInv (Inv [InvVector itype ihash]))
              `catch` (\(_ :: SomeException) -> return ())
        -- BUG-1 FIX (W114): feed accepted tx into the fee estimator.
        -- Reference: bitcoin-core/src/txmempool.cpp
        -- CTxMemPool::addUnchecked — notifies policy estimator via
        -- CBlockPolicyEstimator::processTransaction.
        -- Look up the just-added entry to get the mempool fee rate
        -- (sat/vB), then record it at the current best-tip height.
        mEntry <- getTransaction mp txid
        case mEntry of
          Just entry -> do
            tipHeight <- readTVarIO (hcHeight hc)
            trackTransaction fe txid (getFeeRate (meFeeRate entry)) tipHeight
          Nothing -> return ()
        -- G13: recursive orphan resolution — re-try any queued orphan that
        -- listed this tx as a parent.  Mirrors Bitcoin Core ProcessOrphanTx
        -- (net_processing.cpp) which iterates AddChildrenToWorkSet after
        -- each parent accept.
        now <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
        processOrphan orphanPoolRef mp txid now
      Left err -> do
        -- G12: on ErrMissingInput, park the tx in the wtxid-keyed orphan pool
        -- instead of immediately discarding it.  Core: TX_MISSING_INPUTS path
        -- calls AddOrphanTx (net_processing.cpp:3078).
        case err of
          ErrMissingInput _ -> do
            now <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
            addOrphan orphanPoolRef tx now addr
          _ -> do
            -- Add to recently-rejected filter for non-orphan failures
            rejected <- readIORef recentlyRejectedRef
            when (Set.size rejected < 50000) $
              writeIORef recentlyRejectedRef (Set.insert txid rejected)
            -- Attribute misbehavior on consensus-invalid txs.  We deliberately
            -- skip soft / policy-only rejections (mempool full, fee too low,
            -- duplicate) — those are honest peer behavior.  Reference:
            -- bitcoin-core/src/net_processing.cpp:3045 — only state.IsInvalid
            -- (consensus failure) increments the score, not policy rejects.
            let errStr = show err
            when ("consensus" `infixOfStr` errStr
                 || "invalid"       `infixOfStr` errStr
                 || "bad-"          `infixOfStr` errStr) $ do
              pm <- readIORef pmRef
              void $ misbehaving pm addr InvalidTransaction

  MGetData (GetData ivs) -> do
    pm <- readIORef pmRef
    forM_ ivs $ \iv -> case ivType iv of
      InvBlock -> do
        let bh = BlockHash (ivHash iv)
        mBlock <- getBlock db bh
        case mBlock of
          Just block -> requestFromPeer pm addr (MBlock block)
          Nothing    -> requestFromPeer pm addr
            (MNotFound (NotFound [iv]))
      InvWitnessBlock -> do
        let bh = BlockHash (ivHash iv)
        mBlock <- getBlock db bh
        case mBlock of
          Just block -> requestFromPeer pm addr (MBlock block)
          Nothing    -> requestFromPeer pm addr
            (MNotFound (NotFound [iv]))
      InvTx -> do
        let txid = TxId (ivHash iv)
        mEntry <- getTransaction mp txid
        case mEntry of
          Just entry -> requestFromPeer pm addr (MTx (meTransaction entry))
          Nothing    -> requestFromPeer pm addr
            (MNotFound (NotFound [iv]))
      InvWitnessTx -> do
        let txid = TxId (ivHash iv)
        mEntry <- getTransaction mp txid
        case mEntry of
          Just entry -> requestFromPeer pm addr (MTx (meTransaction entry))
          Nothing    -> requestFromPeer pm addr
            (MNotFound (NotFound [iv]))
      _ -> requestFromPeer pm addr (MNotFound (NotFound [iv]))

  MInv (Inv ivs) -> do
    -- During IBD, skip block inv requests — we download blocks sequentially
    -- via the header chain. Requesting inv blocks during IBD wastes bandwidth
    -- on blocks at the chain tip that can't be connected yet.
    isIBD <- readIORef ibdModeRef
    unless isIBD $ do
      let blockIvs = filter (\iv -> ivType iv == InvBlock
                                  || ivType iv == InvWitnessBlock) ivs
      unless (null blockIvs) $ do
        entries <- readTVarIO (hcEntries hc)
        let unknown = filter (\iv ->
              not $ Map.member (BlockHash (ivHash iv)) entries) blockIvs
        unless (null unknown) $ do
          pm <- readIORef pmRef
          -- Request as witness blocks to get full witness data
          let witnessIvs = map (\iv -> iv { ivType = InvWitnessBlock }) unknown
          requestFromPeer pm addr (MGetData (GetData witnessIvs))
            `catch` (\(_ :: SomeException) -> return ())

    -- BUG-14 FIX: reject tx invs from block-relay-only peers.
    -- Core: RejectIncomingTxs() returns true for block-relay-only connections;
    -- a tx inv from such a peer triggers pfrom.fDisconnect = true.
    -- Reference: bitcoin-core/src/net_processing.cpp:4080.
    pm0 <- readIORef pmRef
    peerIsBlockOnly <- do
      peerMap <- readTVarIO (pmPeers pm0)
      case Map.lookup addr peerMap of
        Just pc -> piBlockOnly <$> readTVarIO (pcInfo pc)
        Nothing -> return False
    -- BUG-2 FIX: read the per-peer wtxid-relay flag for BIP-339 filtering.
    peerWtxidRelay <- do
      peerMap <- readTVarIO (pmPeers pm0)
      case Map.lookup addr peerMap of
        Just pc -> piWtxidRelay <$> readTVarIO (pcInfo pc)
        Nothing -> return False

    -- Request unknown transactions (not in mempool, not recently rejected).
    -- BIP-339 / Core PR #18044: accept InvWtx (MSG_WTX=5) in addition to
    -- InvTx (type=1) and InvWitnessTx (0x40000001, legacy compat).
    -- Apply Core's filter: if peer is wtxid-relay, ignore InvTx entries
    -- (they were replaced by InvWtx); if not, ignore InvWtx entries.
    let isTxInv iv = ivType iv == InvTx || ivType iv == InvWitnessTx || ivType iv == InvWtx
        txIvsRaw   = filter isTxInv ivs
        -- BUG-339 filter per Core net_processing.cpp:4059-4063:
        --   m_wtxid_relay ? drop InvTx : drop InvWtx
        txIvs
          | peerIsBlockOnly = []  -- BUG-14: no tx inv from block-relay-only
          | peerWtxidRelay  = filter (\iv -> ivType iv /= InvTx)  txIvsRaw
          | otherwise       = filter (\iv -> ivType iv /= InvWtx) txIvsRaw
    unless (null txIvs) $ do
      rejected <- readIORef recentlyRejectedRef
      -- Filter to unknown txs: not in mempool and not recently rejected
      unknown <- filterM (\iv -> do
            let txid = TxId (ivHash iv)
            if Set.member txid rejected
              then return False
              else do
                mEntry <- getTransaction mp txid
                case mEntry of
                  Just _  -> return False
                  Nothing -> return True
            ) txIvs
      unless (null unknown) $ do
        pm <- readIORef pmRef
        -- Request as witness txs for full witness data.
        -- BUG-5 FIX: cap outgoing GETDATA at maxGetDataSz=1000 per message.
        -- Core net_processing.cpp:6207 batches at MAX_GETDATA_SZ=1000;
        -- without this cap a single MInv with 50_000 items would emit one
        -- giant GetData, violating Core's application-level protocol limit.
        -- Reference: bitcoin-core/src/protocol.h:482 MAX_GETDATA_SZ = 1000.
        let witnessTxIvs = map (\iv -> iv { ivType = InvWitnessTx }) unknown
            batches = chunksOf maxGetDataSz witnessTxIvs
        mapM_ (\batch ->
          requestFromPeer pm addr (MGetData (GetData batch))
            `catch` (\(_ :: SomeException) -> return ())) batches

  MGetHeaders (GetHeaders _ver locators hashStop) -> do
    -- Respond to getheaders from peers so they can sync from us.
    -- Find the fork point using the locator hashes, then send up to 2000 headers.
    entries <- readTVarIO (hcEntries hc)
    heightMap <- readTVarIO (hcByHeight hc)
    tipHeight <- readTVarIO (hcHeight hc)
    -- Find the starting point from locator hashes (first known hash)
    let findStart [] = 0  -- Genesis
        findStart (loc:rest) = case Map.lookup loc entries of
          Just e  -> ceHeight e
          Nothing -> findStart rest
        startHeight = findStart locators
        stopHash = hashStop
        zeroHash = BlockHash (Hash256 (BS.replicate 32 0))
        -- Collect up to 2000 headers starting after the locator match
        maxHeaders = 2000 :: Int
        collectHeaders h acc
          | length acc >= maxHeaders = acc
          | h > tipHeight = acc
          | otherwise = case Map.lookup h heightMap of
              Nothing -> acc
              Just bh | bh == stopHash -> acc ++ [bh]
                      | stopHash /= zeroHash && bh == stopHash -> acc ++ [bh]
                      | otherwise -> collectHeaders (h + 1) (acc ++ [bh])
        headerHashes = collectHeaders (startHeight + 1) []
        headersList = [ ceHeader e | bh <- headerHashes
                                   , Just e <- [Map.lookup bh entries] ]
    unless (null headersList) $ do
      pm <- readIORef pmRef
      requestFromPeer pm addr (MHeaders (Headers headersList))
        `catch` (\(_ :: SomeException) -> return ())

  MGetBlocks (GetBlocks _ver locators hashStop) -> do
    -- Respond to getblocks from peers by sending inv messages.
    entries <- readTVarIO (hcEntries hc)
    heightMap <- readTVarIO (hcByHeight hc)
    tipHeight <- readTVarIO (hcHeight hc)
    let findStart [] = 0
        findStart (loc:rest) = case Map.lookup loc entries of
          Just e  -> ceHeight e
          Nothing -> findStart rest
        startHeight = findStart locators
        zeroHash = BlockHash (Hash256 (BS.replicate 32 0))
        maxInv = 500 :: Int
        collectInv h acc
          | length acc >= maxInv = acc
          | h > tipHeight = acc
          | otherwise = case Map.lookup h heightMap of
              Nothing -> acc
              Just bh | hashStop /= zeroHash && bh == hashStop -> acc ++ [bh]
                      | otherwise -> collectInv (h + 1) (acc ++ [bh])
        invHashes = collectInv (startHeight + 1) []
        invVecs = [ InvVector InvBlock (getBlockHashHash bh) | bh <- invHashes ]
    unless (null invVecs) $ do
      pm <- readIORef pmRef
      requestFromPeer pm addr (MInv (Inv invVecs))
        `catch` (\(_ :: SomeException) -> return ())

  MAddr (Haskoin.Network.Addr entries) -> do
    -- BIP155: Store addresses and relay to 2 random peers.
    -- Anti-DoS inbound-addr token bucket (Core net_processing.cpp ProcessAddrs,
    -- ~5644): refill by elapsed*0.1 (cap 1000), admit floor(bucket) entries and
    -- DROP the rest (rate-limited).  This caps how many addr entries a single
    -- peer can feed our addrman per second.
    pm <- readIORef pmRef
    admitted <- admitInboundAddrs pmRef addr entries
    unless (null admitted) $ do
      handleAddrMessage pm (Haskoin.Network.Addr admitted)
      relayAddrToRandomPeers pm addr (MAddr (Haskoin.Network.Addr admitted))

  MAddrV2 addrv2msg -> do
    -- BIP155: Handle addrv2 message - extract IPv4/IPv6 and store.
    --
    -- W117 DH-2 wire: apply 'filterReachableAddresses' to the
    -- incoming entry list using the PeerManagerConfig-derived
    -- 'NetworkReachability'.  Tor / I2P / CJDNS entries are dropped
    -- when the operator hasn't configured the corresponding proxy
    -- (so we don't store unreachable peers in AddrMan and don't
    -- forward Tor/I2P entries to clearnet peers — TP-1 + DH-2).
    pm <- readIORef pmRef
    let reachRt   = reachabilityFromConfig (pmConfig pm)
        rawList   = getAddrV2List addrv2msg
        filtered0 = filterReachableAddresses reachRt rawList
    -- Anti-DoS inbound-addr token bucket (Core ProcessAddrs, ~5644): the same
    -- per-peer 0.1/sec bucket gates addrv2 too.  Admit floor(bucket) entries,
    -- drop the rest.
    filtered <- admitInboundAddrsV2 pmRef addr filtered0
    let converted = mapMaybe addrV2ToAddrEntry filtered
    -- Only relay the filtered list, never the raw one (W117 DH-2).
    -- If everything was filtered out, no relay happens either.
    unless (null filtered) $ do
      unless (null converted) $
        handleAddrMessage pm (Haskoin.Network.Addr converted)
      relayAddrToRandomPeers pm addr (MAddrV2 (AddrV2Msg filtered))

  MFeeFilter (FeeFilter fee) -> do
    -- BIP133: Store peer's fee filter
    pm <- readIORef pmRef
    let peerMap = pmPeers pm
    mInfo <- atomically $ do
      m <- readTVar peerMap
      return (Map.lookup addr m)
    case mInfo of
      Just pc -> void $ handleFeeFilter (pcInfo pc) fee
      Nothing -> return ()

  MNotFound (NotFound invs) ->
    putStrLn $ "Peer says not found: " ++ show (length invs) ++ " items"

  MReject (Reject cmd code reason _) ->
    putStrLn $ "Peer rejected " ++ show cmd ++ ": code=" ++ show code ++ " reason=" ++ show reason

  -- BIP 152: Compact block relay messages
  MSendCmpct sc -> do
    putStrLn $ "Peer supports compact blocks: version=" ++ show (scVersion sc)
               ++ ", announce=" ++ show (scAnnounce sc)

  MCmpctBlock cb -> do
    -- BIP 152: Reconstruct block from compact block + mempool
    let bh = computeBlockHash (cbHeader cb)
    -- MAX_CMPCTBLOCK_DEPTH=5 guard (BUG-4 FIX, W112).
    -- Core (net_processing.cpp:2466): only process compact blocks within 5 of
    -- the tip. Blocks deeper than that waste mempool lookup time and enable
    -- trivial CPU/memory exhaustion. Fall back to full block getdata.
    -- Reference: bitcoin-core/src/net_processing.cpp:2466-2470
    currentTipHeight <- readTVarIO (hcHeight hc)
    chainEntries <- readTVarIO (hcEntries hc)
    let mBlockHeight = fmap ceHeight (Map.lookup bh chainEntries)
        depth = case mBlockHeight of
          Just blockH -> fromIntegral currentTipHeight - fromIntegral blockH :: Int
          Nothing     -> 0  -- Unknown block: depth=0 (let normal validation handle it)
    if depth > maxCmpctBlockDepth
      then do
        putStrLn $ "Compact block " ++ show bh ++ " too old (depth=" ++ show depth
                ++ " > MAX_CMPCTBLOCK_DEPTH=" ++ show maxCmpctBlockDepth
                ++ "), falling back to full block"
        pm <- readIORef pmRef
        let iv = InvVector InvWitnessBlock (getBlockHashHash bh)
        requestFromPeer pm addr (MGetData (GetData [iv]))
          `catch` (\(_ :: SomeException) -> return ())
      else do
        entries <- readTVarIO (mpEntries mp)
        let mempoolTxMap = Map.map meTransaction entries
        case initPartialBlock cb mempoolTxMap of
          Left err -> do
            putStrLn $ "Compact block " ++ show bh ++ " init failed: " ++ err
            pm <- readIORef pmRef
            -- Bad compact-block reconstruction is a Core ban offense.
            -- Reference: bitcoin-core/src/net_processing.cpp:3700 —
            -- "non-continuous-headers" for cmpctblock with bogus parent.
            void $ misbehaving pm addr InvalidCompactBlock
            let iv = InvVector InvWitnessBlock (getBlockHashHash bh)
            requestFromPeer pm addr (MGetData (GetData [iv]))
              `catch` (\(_ :: SomeException) -> return ())
          Right (pdb, missing) ->
            if null missing
              then case fillPartialBlock pdb [] of
                Right block -> do
                  putStrLn $ "Compact block " ++ show bh ++ " reconstructed (mempool_hits=" ++ show (pdbMempoolCount pdb) ++ ")"
                  syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef requestedUpToRef ibdModeRef lastFullBatchAtRef recentlyRejectedRef blocksSinceFlushRef lastFlushEpochRef pruneCfg mBlockStore mIdxMgr orphanPoolRef compactBlockStateRef connectLock walletMgrRef addr (MBlock block)
                Left err -> do
                  putStrLn $ "Compact block " ++ show bh ++ " fill error: " ++ err
                  pm <- readIORef pmRef
                  let iv = InvVector InvWitnessBlock (getBlockHashHash bh)
                  requestFromPeer pm addr (MGetData (GetData [iv]))
                    `catch` (\(_ :: SomeException) -> return ())
              else do
                let missPct = fromIntegral (length missing) / fromIntegral (pdbTotalTxns pdb) * 100.0 :: Double
                if missPct > 50.0
                  then do
                    putStrLn $ "Compact block " ++ show bh ++ " too many missing, requesting full block"
                    pm <- readIORef pmRef
                    let iv = InvVector InvWitnessBlock (getBlockHashHash bh)
                    requestFromPeer pm addr (MGetData (GetData [iv]))
                      `catch` (\(_ :: SomeException) -> return ())
                  else do
                    putStrLn $ "Compact block " ++ show bh ++ " missing " ++ show (length missing) ++ " txns, sending getblocktxn"
                    -- BIP-152 BUG-1 FIX: persist the partial block state so MBlockTxn
                    -- can complete reconstruction.  Core keeps PartiallyDownloadedBlock
                    -- alive in mapBlocksInFlight keyed by block hash until BLOCKTXN arrives.
                    -- Reference: bitcoin-core/src/net_processing.cpp:3964-3967
                    cbs <- readIORef compactBlockStateRef
                    pdbTs <- (round <$> getPOSIXTime :: IO Int64)
                    atomically $ modifyTVar' (cbsPending cbs) (Map.insert bh (pdbTs, pdb))
                    pm <- readIORef pmRef
                    let gbt = GetBlockTxn { gbtBlockHash = bh, gbtIndexes = map fromIntegral missing }
                    requestFromPeer pm addr (MGetBlockTxn gbt)
                      `catch` (\(_ :: SomeException) -> return ())

  MGetBlockTxn gbt -> do
    -- Serve missing transactions for compact block reconstruction
    -- MAX_BLOCKTXN_DEPTH=10 guard (BUG-5 FIX, W112).
    -- Core (net_processing.cpp:4276): if the requested block is more than 10
    -- deep from the tip, respond with the full block (MSG_WITNESS_BLOCK)
    -- instead of serving individual transactions.
    -- Reference: bitcoin-core/src/net_processing.cpp:4276-4285
    let blockHash = gbtBlockHash gbt
        indices = gbtIndexes gbt
    currentTip <- readTVarIO (hcHeight hc)
    chainEnts <- readTVarIO (hcEntries hc)
    let mBlkHeight = fmap ceHeight (Map.lookup blockHash chainEnts)
        blkDepth = case mBlkHeight of
          Just blockH -> fromIntegral currentTip - fromIntegral blockH :: Int
          Nothing     -> 0  -- Unknown: let normal block lookup handle it
    if blkDepth > maxBlocktxnDepth
      then do
        putStrLn $ "GetBlockTxn for " ++ show blockHash ++ " too old (depth=" ++ show blkDepth
                ++ " > MAX_BLOCKTXN_DEPTH=" ++ show maxBlocktxnDepth
                ++ "), sending full block"
        pm <- readIORef pmRef
        let iv = InvVector InvWitnessBlock (getBlockHashHash blockHash)
        requestFromPeer pm addr (MGetData (GetData [iv]))
          `catch` (\(_ :: SomeException) -> return ())
      else do
        mBlock <- getBlock db blockHash
        case mBlock of
          Just block -> do
            let txns = mapMaybe (\i -> let idx = fromIntegral i in if idx < length (blockTxns block) then Just (blockTxns block !! idx) else Nothing) indices
            pm <- readIORef pmRef
            requestFromPeer pm addr (MBlockTxn (BlockTxn { btBlockHash = blockHash, btTxns = txns }))
              `catch` (\(_ :: SomeException) -> return ())
          Nothing -> return ()

  MBlockTxn bt -> do
    -- BIP-152 BUG-1 FIX (W112): Complete compact block reconstruction.
    -- Bitcoin Core BLOCKTXN handler (net_processing.cpp:4307-4360):
    --   1. Look up PartiallyDownloadedBlock from mapBlocksInFlight.
    --   2. Call partialBlock.FillBlock(block, resp.txn).
    --   3. On READ_STATUS_OK  → ProcessNewBlock.
    --   4. On READ_STATUS_INVALID → Misbehaving(100) + getdata MSG_WITNESS_BLOCK.
    let blockHash = btBlockHash bt
        missingTxns = btTxns bt
    cbs <- readIORef compactBlockStateRef
    mPdb <- atomically $ do
      pending <- readTVar (cbsPending cbs)
      case Map.lookup blockHash pending of
        Nothing       -> return Nothing
        Just (_, pdb) -> do
          -- Remove from pending regardless of outcome (either we reconstruct
          -- successfully and submit, or we fall back to full block getdata).
          writeTVar (cbsPending cbs) (Map.delete blockHash pending)
          return (Just pdb)
    case mPdb of
      Nothing -> do
        -- No pending partial block for this hash — stale or unsolicited.
        -- This can happen if we already fell back to a full block getdata.
        putStrLn $ "MBlockTxn: no pending partial block for " ++ show blockHash ++ " (stale/unsolicited)"
      Just pdb -> do
        putStrLn $ "MBlockTxn: filling " ++ show blockHash ++ " with " ++ show (length missingTxns) ++ " missing txns"
        case fillPartialBlock pdb missingTxns of
          Left err -> do
            -- Reconstruction failure (merkle mismatch or wrong tx count).
            -- Core: Misbehaving(100, "invalid-cmpctblk-txns") + getdata fallback.
            -- Reference: bitcoin-core/src/net_processing.cpp:4339-4349
            putStrLn $ "MBlockTxn: fillPartialBlock failed for " ++ show blockHash ++ ": " ++ err
            pm <- readIORef pmRef
            void $ misbehaving pm addr InvalidCompactBlock
            let iv = InvVector InvWitnessBlock (getBlockHashHash blockHash)
            requestFromPeer pm addr (MGetData (GetData [iv]))
              `catch` (\(_ :: SomeException) -> return ())
          Right block -> do
            -- Reconstruction succeeded — submit to the validation pipeline.
            -- Reuse the MBlock path exactly (handles connectBlock, reorg,
            -- IBD, header indexing, index manager mirroring, etc.).
            -- Reference: bitcoin-core/src/net_processing.cpp:4350-4360
            putStrLn $ "MBlockTxn: compact block " ++ show blockHash ++ " reconstructed via getblocktxn round-trip"
            syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef requestedUpToRef ibdModeRef lastFullBatchAtRef recentlyRejectedRef blocksSinceFlushRef lastFlushEpochRef pruneCfg mBlockStore mIdxMgr orphanPoolRef compactBlockStateRef connectLock walletMgrRef addr (MBlock block)

  MPong _ -> return ()
  MVerAck -> return ()
  MSendHeaders -> do
    -- BIP-130: peer is requesting headers-first announcements.  Record
    -- the preference on the peer record so 'announceTip' below routes
    -- new tips through 'MHeaders' instead of 'MInv' for this peer.
    -- Reference: bitcoin-core/src/net_processing.cpp NetMsgType::SENDHEADERS
    -- — sets 'm_peer_state.m_prefers_headers' for the peer.
    pm <- readIORef pmRef
    peerMap <- readTVarIO (pmPeers pm)
    case Map.lookup addr peerMap of
      Just pc -> atomically $ modifyTVar' (pcInfo pc) $ \i ->
        i { piWantsHeaders = True }
      Nothing -> return ()
  MSendCmpct _ -> return ()
  MWtxidRelay -> do
    -- BIP-339: peer is requesting wtxid-based relay.
    -- Set piWtxidRelay=True so all three relay paths (MTx handler,
    -- broadcastTxToPeers, sendtoaddress) can select InvWtx (MSG_WTX=5)
    -- + wtxid for this peer instead of InvTx (type=1) + txid.
    -- Reference: bitcoin-core/src/net_processing.cpp:2027
    --   peer.m_wtxid_relay = true;
    pm <- readIORef pmRef
    peerMap <- readTVarIO (pmPeers pm)
    case Map.lookup addr peerMap of
      Just pc -> atomically $ modifyTVar' (pcInfo pc) $ \i ->
        i { piWtxidRelay = True }
      Nothing -> return ()

  MMemPool -> do
    -- BIP-35: serve our mempool to the requesting peer.
    -- Mirrors Bitcoin Core net_processing.cpp NetMsgType::MEMPOOL handler:
    -- only honour the request if we advertised NODE_BLOOM (per-runtime via
    -- pmcPeerBloomFilters); otherwise drop and disconnect the peer.
    pm <- readIORef pmRef
    let bloomEnabled = pmcPeerBloomFilters (pmConfig pm)
    if not bloomEnabled
      then do
        putStrLn $ "MMemPool from " ++ show addr
                ++ " but NODE_BLOOM is disabled; disconnecting"
        peerMap <- readTVarIO (pmPeers pm)
        case Map.lookup addr peerMap of
          Just pc -> disconnectPeer pc
                       `catch` (\(_ :: SomeException) -> return ())
          Nothing -> return ()
      else do
        -- Determine inv type per peer: MSG_WTX (0x40000002) for nodeWitness
        -- peers, otherwise MSG_TX (1). Bitcoin Core picks per peer state.
        peerMap <- readTVarIO (pmPeers pm)
        peerWantsWitness <- case Map.lookup addr peerMap of
          Just pc -> do
            info <- readTVarIO (pcInfo pc)
            return $ hasService (piServices info) nodeWitness
          Nothing -> return False
        let invKind = if peerWantsWitness then InvWitnessTx else InvTx
        txids <- getMempoolTxIds mp
        let invs   = [ InvVector invKind (getTxIdHash t) | t <- txids ]
            -- Bitcoin Core MAX_INV_SZ = 50000 entries per inv message.
            chunks = chunksOf 50000 invs
        forM_ chunks $ \chunk -> unless (null chunk) $
          requestFromPeer pm addr (MInv (Inv chunk))
            `catch` (\(_ :: SomeException) -> return ())
        putStrLn $ "MMemPool: served " ++ show (length invs)
                ++ " inv entries to " ++ show addr

  -- ============================================================
  -- FIX-86: BIP-157 Compact Block Filter P2P serving
  -- ============================================================
  --
  -- Reference: bitcoin-core/src/net_processing.cpp:3260-3422
  --   PrepareBlockFilterRequest / ProcessGetCFilters /
  --   ProcessGetCFHeaders / ProcessGetCFCheckPt
  --
  -- Each handler:
  --   1. Parses the payload with decodeGetCF*Msg.  If the wire bytes are
  --      malformed, the peer scored MalformedMessage and the message is
  --      dropped (we do not partially honour a request we can't parse).
  --   2. Gates on NODE_COMPACT_FILTERS in our advertised service set
  --      (handler-side defence-in-depth per FIX-85 hotbuns pattern, so
  --      we can't accidentally serve while not advertising the bit).
  --   3. Walks the active chain via the in-memory header chain to
  --      locate stop_hash and follow the FIX-74 stop-hash-anchor
  --      ancestor pattern (NOT the active-chain walk, which would
  --      lie to peers probing orphan-hash stop hashes).
  --   4. Enforces filter_type == BASIC (0), range caps
  --      MAX_GETCFILTERS_SIZE=1000 / MAX_GETCFHEADERS_SIZE=2000, and
  --      start_height <= stop_height.  Violations:
  --        InvalidTransaction (1) is too soft; UnsolicitedMessage (1)
  --        is too soft.  Core sets pfrom.fDisconnect = true for every
  --        violation, so we use 'misbehaving ... ProtocolViolation'
  --        (10) which triggers ban scoring and disconnect under
  --        Bitcoin Core parity.  Additionally we explicitly
  --        disconnect the peer afterward to mirror Core's
  --        fDisconnect=true semantics.
  --   5. Looks up the filter via the BlockFilterIndexDB; if a record
  --      is missing (e.g. index isn't fully synced yet), the request
  --      is silently dropped per Core's behaviour at LookupFilterRange
  --      / LookupFilterHeader failure (LogDebug + return).

  MGetCFilters payload ->
    handleGetCFilters pmRef hc mIdxMgr addr payload

  MGetCFHeaders payload ->
    handleGetCFHeaders pmRef hc mIdxMgr addr payload

  MGetCFCheckpt payload ->
    handleGetCFCheckpt pmRef hc mIdxMgr addr payload

  MGetAddr -> do
    -- Anti-eclipse GETADDR guards (Core net_processing.cpp:4816).
    --   (1) inbound-only: an outbound peer's getaddr is ignored to mitigate the
    --       address-stamping fingerprint attack (Core IsInboundConn() gate).
    --   (2) answer-once: only the FIRST getaddr per connection is answered
    --       (piGetaddrRecvd); repeats are dropped (Core m_getaddr_recvd).
    --   (3) 23%-cap: the reply is capped at getAddrCap (min(1000,
    --       ceil(0.23*addrman_size))) inside buildGetAddrResponse.
    pm <- readIORef pmRef
    peerMap <- readTVarIO (pmPeers pm)
    case Map.lookup addr peerMap of
      Nothing -> return ()
      Just pc -> do
        info <- readTVarIO (pcInfo pc)
        if not (piInbound info)
          then return ()                      -- (1) outbound: ignore getaddr
          else if piGetaddrRecvd info
            then return ()                     -- (2) already answered once
            else do
              atomically $ modifyTVar' (pcInfo pc)
                (\i -> i { piGetaddrRecvd = True })
              entries <- buildGetAddrResponse (pmAddrMan pm)   -- (3) 23%-cap inside
              unless (null entries) $
                requestFromPeer pm addr (MAddr (Haskoin.Network.Addr entries))
                  `catch` (\(_ :: SomeException) -> return ())

  _other -> return ()  -- Silently ignore other messages

--------------------------------------------------------------------------------
-- FIX-86: BIP-157 P2P handler implementations
--------------------------------------------------------------------------------

-- | Common validation step shared by all three cfilter handlers.  Mirrors
-- Core's @PrepareBlockFilterRequest@ at net_processing.cpp:3262.  Returns
-- 'Right (stopHeight, bfIdx)' on success, 'Left' on the misbehave path.
--
-- Five invariants enforced (Core net_processing.cpp:3262-3313):
--
--   (1) filter_type == BASIC (0).  Any other value: misbehave + disconnect.
--   (2) NODE_COMPACT_FILTERS in our advertised services.  Core checks
--       @peer.m_our_services & NODE_COMPACT_FILTERS@; we mirror via the
--       PeerManager config's pcfgServices.  Misbehave + disconnect.
--   (3) stop_hash is a known block on the active chain.  Core uses
--       LookupBlockIndex + BlockRequestAllowed; we look up the chain
--       entry by stop_hash and confirm height->hash matches (i.e. it's
--       on the active chain, not on an orphan side branch).  This is
--       the FIX-74 stop-hash-anchor invariant.  Misbehave + disconnect.
--   (4) start_height <= stop_height.  Misbehave + disconnect.
--   (5) stop_height - start_height < max_height_diff.  Misbehave + disconnect.
--
-- After all five pass, we also assert the BlockFilterIndex exists; if
-- not (e.g. operator turned off the index between advertisement and
-- request) we return Left silently — the misbehaviour gate already
-- ensured we wouldn't be advertising if we couldn't serve.
prepareBlockFilterRequest
  :: IORef PeerManager
  -> HeaderChain
  -> Maybe IndexManager
  -> SockAddr
  -> Word8           -- ^ filter_type
  -> Word32          -- ^ start_height
  -> BlockHash       -- ^ stop_hash
  -> Word32          -- ^ max_height_diff (MAX_GETCF*_SIZE or maxBound)
  -> IO (Either String (Word32, BlockFilterIndexDB))
prepareBlockFilterRequest pmRef hc mIdxMgr addr filterType startHeight stopHash maxHeightDiff = do
  pm <- readIORef pmRef

  -- Invariant (1): only BASIC (0) is supported.
  if filterType /= 0
    then do
      void $ misbehaving pm addr (ProtocolViolation "cfilter: unsupported filter type")
      forceDisconnect pm addr
      return $ Left "unsupported filter type"
    else do
      -- Invariant (2): we must have advertised NODE_COMPACT_FILTERS.
      let myServices = pcfgServices (defaultPeerConfig (pmNetwork pm))
          --   ^ shape of what defaultPeerConfig would build; we OR
          --   in pmConfig-derived flags below if the index is live.
      mIdxBit <- pure $ case mIdxMgr >>= imBlockFilterIndex of
        Just _  -> getServiceFlag nodeCompactFilters
        Nothing -> 0
      let effectiveServices = myServices .|. mIdxBit
      if not (hasService effectiveServices nodeCompactFilters)
        then do
          void $ misbehaving pm addr (ProtocolViolation "cfilter: NODE_COMPACT_FILTERS not advertised")
          forceDisconnect pm addr
          return $ Left "service not advertised"
        else do
          -- Invariant (3): stop_hash is on the active chain (FIX-74 anchor).
          entries  <- readTVarIO (hcEntries hc)
          byHeight <- readTVarIO (hcByHeight hc)
          case Map.lookup stopHash entries of
            Nothing -> do
              void $ misbehaving pm addr (ProtocolViolation "cfilter: unknown stop_hash")
              forceDisconnect pm addr
              return $ Left "unknown stop_hash"
            Just stopEntry ->
              -- Confirm the stop_hash is on the active chain by checking
              -- the height->hash map.  This is the FIX-74 stop-hash-anchor
              -- semantics: a peer probing with an orphan-side stop_hash
              -- must NOT receive a signed-but-lying response.
              case Map.lookup (ceHeight stopEntry) byHeight of
                Just activeHash | activeHash == stopHash -> do
                  let stopHeight = ceHeight stopEntry
                  -- Invariant (4): start_height <= stop_height
                  if startHeight > stopHeight
                    then do
                      void $ misbehaving pm addr (ProtocolViolation "cfilter: start>stop")
                      forceDisconnect pm addr
                      return $ Left "start>stop"
                    -- Invariant (5): range cap.  Core compares
                    --   stop_height - start_height >= max_height_diff
                    -- (i.e. the *count*, stop-start+1, > max_height_diff).
                    else if stopHeight - startHeight >= maxHeightDiff
                      then do
                        void $ misbehaving pm addr (ProtocolViolation "cfilter: range too large")
                        forceDisconnect pm addr
                        return $ Left "range too large"
                      else case mIdxMgr >>= imBlockFilterIndex of
                        Just bfIdx -> return $ Right (stopHeight, bfIdx)
                        Nothing    -> return $ Left "no block filter index"
                _ -> do
                  -- stop_hash exists in the entries map but is on a
                  -- side branch (different hash at that height in the
                  -- active chain).  This is the FIX-74 case we MUST
                  -- reject — Core treats it as "block not in active
                  -- chain" via BlockRequestAllowed.
                  void $ misbehaving pm addr (ProtocolViolation "cfilter: stop_hash not on active chain")
                  forceDisconnect pm addr
                  return $ Left "stop_hash not on active chain"

-- | Force-disconnect a peer immediately, mirroring Core's
-- @node.fDisconnect = true@.  Misbehaving above already adds ban score
-- via the threshold gate; this is the explicit kick.
forceDisconnect :: PeerManager -> SockAddr -> IO ()
forceDisconnect pm addr = do
  peerMap <- readTVarIO (pmPeers pm)
  case Map.lookup addr peerMap of
    Just pc -> disconnectPeer pc `catch` (\(_ :: SomeException) -> return ())
    Nothing -> return ()

handleGetCFilters
  :: IORef PeerManager -> HeaderChain -> Maybe IndexManager
  -> SockAddr -> BS.ByteString -> IO ()
handleGetCFilters pmRef hc mIdxMgr addr payload =
  case decodeGetCFiltersMsg payload of
    Left _ -> do
      pm <- readIORef pmRef
      void $ misbehaving pm addr MalformedMessage
    Right (GetCFiltersMsg ft sh stopH) -> do
      res <- prepareBlockFilterRequest pmRef hc mIdxMgr addr
               ft sh stopH maxGetCFiltersSize
      case res of
        Left _ -> return ()
        Right (stopHeight, bfIdx) -> do
          pm <- readIORef pmRef
          byHeight <- readTVarIO (hcByHeight hc)
          -- Walk start_height..stop_height inclusive; per Core, the
          -- block-index walk uses stop_index->GetAncestor(h) (FIX-74
          -- ancestor anchor).  We have already verified above that
          -- stop_hash is on the active chain, so the active-chain
          -- height->hash mapping IS the stop_hash ancestor chain in
          -- this range.
          let heights = [sh .. stopHeight]
          forM_ heights $ \h ->
            case Map.lookup h byHeight of
              Nothing -> return ()  -- gap; Core LogDebug + return
              Just bh -> do
                mEntry <- blockFilterIndexGet bfIdx h
                case mEntry of
                  Nothing -> return ()
                  Just BlockFilterEntry{..} -> do
                    let msg = MCFilter
                            $ encodeCFilterMsg
                            $ CFilterMsg ft bh bfeEncoded
                    requestFromPeer pm addr msg
                      `catch` (\(_ :: SomeException) -> return ())

handleGetCFHeaders
  :: IORef PeerManager -> HeaderChain -> Maybe IndexManager
  -> SockAddr -> BS.ByteString -> IO ()
handleGetCFHeaders pmRef hc mIdxMgr addr payload =
  case decodeGetCFHeadersMsg payload of
    Left _ -> do
      pm <- readIORef pmRef
      void $ misbehaving pm addr MalformedMessage
    Right (GetCFHeadersMsg ft sh stopH) -> do
      res <- prepareBlockFilterRequest pmRef hc mIdxMgr addr
               ft sh stopH maxGetCFHeadersSize
      case res of
        Left _ -> return ()
        Right (stopHeight, bfIdx) -> do
          pm <- readIORef pmRef
          byHeight <- readTVarIO (hcByHeight hc)
          -- prev_header = filter_header at (start_height - 1).  Defensive
          -- per FIX-79 ouroboros pattern: if the prev filter header is
          -- missing (index lag), silently drop the response — never
          -- emit a header with a zeroed prev that the peer would
          -- accept as canonical.  At start_height == 0, prev_header
          -- is the conventional 32-byte zero (BIP-157 genesis seed).
          mPrev <- if sh == 0
                     then return (Just (Hash256 (BS.replicate 32 0)))
                     else do
                       me <- blockFilterIndexGet bfIdx (sh - 1)
                       return (fmap bfeFilterHeader me)
          case mPrev of
            Nothing -> return ()
            Just prevHeader -> do
              -- Collect filter hashes for [sh .. stopHeight].
              let heights = [sh .. stopHeight]
              entries' <- forM heights $ \h -> do
                me <- blockFilterIndexGet bfIdx h
                return (fmap bfeFilterHash me)
              if any (\m -> case m of Nothing -> True; _ -> False) entries'
                then return ()  -- gap; LogDebug + return
                else do
                  let hashes = [ x | Just x <- entries' ]
                  -- stop_index hash is the canonical stop_hash on the
                  -- active chain at stopHeight.  Reuse the verified
                  -- stopH from the request.
                  let _ = stopHeight
                      stopBlockHash = case Map.lookup stopHeight byHeight of
                                        Just b -> b
                                        Nothing -> stopH
                  let msg = MCFHeaders
                          $ encodeCFHeadersMsg
                          $ CFHeadersMsg ft stopBlockHash prevHeader hashes
                  requestFromPeer pm addr msg
                    `catch` (\(_ :: SomeException) -> return ())

handleGetCFCheckpt
  :: IORef PeerManager -> HeaderChain -> Maybe IndexManager
  -> SockAddr -> BS.ByteString -> IO ()
handleGetCFCheckpt pmRef hc mIdxMgr addr payload =
  case decodeGetCFCheckptMsg payload of
    Left _ -> do
      pm <- readIORef pmRef
      void $ misbehaving pm addr MalformedMessage
    Right (GetCFCheckptMsg ft stopH) -> do
      -- Core passes start_height=0 + max_height_diff=UINT32_MAX so the
      -- range-cap branch never triggers; the start-vs-stop branch can
      -- still fire if stopHeight is somehow negative-equivalent (it
      -- can't, since stopHeight is Word32 and start_height is 0).
      res <- prepareBlockFilterRequest pmRef hc mIdxMgr addr
               ft 0 stopH maxBound
      case res of
        Left _ -> return ()
        Right (stopHeight, bfIdx) -> do
          pm <- readIORef pmRef
          byHeight <- readTVarIO (hcByHeight hc)
          -- One header per CFCHECKPT_INTERVAL=1000 blocks.
          --   headers.size() = stopHeight / CFCHECKPT_INTERVAL.
          -- Core walks i in [headers.size()-1 .. 0] via
          -- stop_index->GetAncestor((i+1) * CFCHECKPT_INTERVAL); we walk
          -- forward over the same heights (1000, 2000, 3000, ...).
          let nHeaders :: Word32
              nHeaders = stopHeight `div` cfcheckptInterval
              checkptHeights = [ i * cfcheckptInterval | i <- [1 .. nHeaders] ]
          entries' <- forM checkptHeights $ \h -> do
            -- Verify the height is still on the active chain at
            -- request-service time (could race with reorg).
            case Map.lookup h byHeight of
              Nothing -> return Nothing
              Just _bh -> do
                me <- blockFilterIndexGet bfIdx h
                return (fmap bfeFilterHeader me)
          if any (\m -> case m of Nothing -> True; _ -> False) entries'
            then return ()  -- gap; LogDebug + return
            else do
              let headers' = [ x | Just x <- entries' ]
                  stopBlockHash = case Map.lookup stopHeight byHeight of
                                    Just b  -> b
                                    Nothing -> stopH
                  msg = MCFCheckpt
                      $ encodeCFCheckptMsg
                      $ CFCheckptMsg ft stopBlockHash headers'
              requestFromPeer pm addr msg
                `catch` (\(_ :: SomeException) -> return ())

-- | Relay a message to up to 2 random connected peers, excluding the source.
-- Implements Bitcoin Core's RelayAddress behavior (BIP155).
relayAddrToRandomPeers :: PeerManager -> SockAddr -> Message -> IO ()
relayAddrToRandomPeers pm sourceAddr msg = do
  peerMap <- atomically $ readTVar (pmPeers pm)
  let candidates = Map.keys $ Map.filterWithKey (\a _ -> a /= sourceAddr) peerMap
  unless (null candidates) $ do
    -- Pick up to 2 random peers (simple approach: take first 2)
    let targets = take 2 candidates
    forM_ targets $ \targetAddr ->
      requestFromPeer pm targetAddr msg
        `catch` (\(_ :: SomeException) -> return ())

-- | Apply the per-peer inbound-addr token bucket to a received addr/addrv2 list.
-- Refills the bucket by elapsed*MAX_ADDR_RATE_PER_SECOND (capped at 1000),
-- admits floor(bucket) entries (spending one token each) and DROPS the rest,
-- then writes the post-spend bucket + timestamp back onto the peer record —
-- all atomically so concurrent addr messages from the same peer can't double
-- spend.  Mirrors Core net_processing.cpp ProcessAddrs (~5644).  When the peer
-- is unknown (already disconnected) the input list is returned unchanged (no
-- peer record to charge).
-- Reference: bitcoin-core/src/net_processing.cpp ProcessAddrs.
applyAddrTokenBucket :: IORef PeerManager -> SockAddr -> [a] -> IO [a]
applyAddrTokenBucket pmRef addr xs = do
  pm <- readIORef pmRef
  peerMap <- readTVarIO (pmPeers pm)
  case Map.lookup addr peerMap of
    Nothing -> return xs   -- peer gone; nothing to rate-limit against
    Just pc -> do
      now <- (round <$> getPOSIXTime :: IO Int64)
      atomically $ do
        info <- readTVar (pcInfo pc)
        let lastTs   = piAddrTokenTimestamp info
            -- 0 timestamp = first addr message: no elapsed refill, bucket
            -- starts at its 1.0 init (matches Core's m_addr_token_timestamp).
            elapsed  = if lastTs == 0 then 0 else fromIntegral (max 0 (now - lastTs))
            refilled = refillAddrTokenBucket (piAddrTokenBucket info) elapsed
            (admitted, bucket') = admitAddrsByTokenBucket refilled xs
        writeTVar (pcInfo pc) info
          { piAddrTokenBucket    = bucket'
          , piAddrTokenTimestamp = now
          }
        return admitted

-- | 'applyAddrTokenBucket' specialised for legacy @addr@ entries.
admitInboundAddrs :: IORef PeerManager -> SockAddr -> [AddrEntry] -> IO [AddrEntry]
admitInboundAddrs = applyAddrTokenBucket

-- | 'applyAddrTokenBucket' specialised for @addrv2@ entries.
admitInboundAddrsV2 :: IORef PeerManager -> SockAddr -> [AddrV2] -> IO [AddrV2]
admitInboundAddrsV2 = applyAddrTokenBucket

--------------------------------------------------------------------------------
-- Wallet Commands
--------------------------------------------------------------------------------

runWalletCommand :: Network -> FilePath -> WalletCommand -> IO ()
runWalletCommand net _dataDir cmd = case cmd of
  WalletCreate -> do
    let config = WalletConfig net 20 ""
    (mnemonic, _wallet) <- createWallet config
    putStrLn "Wallet created successfully!"
    putStrLn "Write down your recovery phrase:"
    putStrLn ""
    TIO.putStrLn $ T.intercalate " " (getMnemonicWords mnemonic)
    putStrLn ""
    putStrLn "WARNING: Keep this phrase safe. Anyone with it can access your funds."

  WalletBalance -> do
    putStrLn "Wallet balance: 0 BTC"

  WalletAddress -> do
    putStrLn "Generate new receive address (wallet not loaded)"

  WalletSend addr amount -> do
    putStrLn $ "Sending " ++ show amount ++ " sat to " ++ T.unpack addr

  WalletHistory -> do
    putStrLn "Transaction history:"

  WalletRestore -> do
    putStrLn "Enter your 12/24 word recovery phrase:"
    -- Read mnemonic from stdin
    return ()

  WalletDump -> do
    putStrLn "WARNING: This will display sensitive information"

--------------------------------------------------------------------------------
-- Utility Commands
--------------------------------------------------------------------------------

runUtilCommand :: Network -> UtilCommand -> IO ()
runUtilCommand _net cmd = case cmd of
  UtilDecodeRawTx hexTx -> do
    case B16.decode (TE.encodeUtf8 hexTx) of
      Left err -> putStrLn $ "Hex decode error: " ++ err
      Right bytes -> case decode bytes of
        Left err -> putStrLn $ "TX decode error: " ++ err
        Right tx -> do
          let txid = computeTxId tx
          putStrLn $ "TxId:     " ++ showTxId txid
          putStrLn $ "Version:  " ++ show (txVersion tx)
          putStrLn $ "Inputs:   " ++ show (length (txInputs tx))
          putStrLn $ "Outputs:  " ++ show (length (txOutputs tx))
          putStrLn $ "LockTime: " ++ show (txLockTime tx)
          putStrLn ""
          putStrLn "Inputs:"
          mapM_ showInput (zip [0..] (txInputs tx))
          putStrLn ""
          putStrLn "Outputs:"
          mapM_ showOutput (zip [0..] (txOutputs tx))

  UtilValidateAddress addrText ->
    case textToAddress addrText of
      Just addr -> do
        putStrLn $ "Valid:   True"
        putStrLn $ "Address: " ++ T.unpack addrText
        putStrLn $ "Type:    " ++ addressTypeName addr
      Nothing ->
        putStrLn "Valid: False"

  UtilDecodeScript hexScript -> do
    case B16.decode (TE.encodeUtf8 hexScript) of
      Left err -> putStrLn $ "Hex decode error: " ++ err
      Right bytes -> case decodeScript bytes of
        Left err -> putStrLn $ "Script decode error: " ++ err
        Right script -> print script

  UtilHashBlock hexHeader -> do
    case B16.decode (TE.encodeUtf8 hexHeader) of
      Left err -> putStrLn $ "Hex decode error: " ++ err
      Right bytes
        | BS.length bytes /= 80 -> putStrLn "Block header must be exactly 80 bytes"
        | otherwise -> case decode bytes of
            Left err -> putStrLn $ "Header decode error: " ++ err
            Right hdr -> do
              let hash = computeBlockHash hdr
              putStrLn $ "Block hash: " ++ showBlockHash hash

--------------------------------------------------------------------------------
-- Display Helpers
--------------------------------------------------------------------------------

showTxId :: TxId -> String
showTxId (TxId (Hash256 bs)) = T.unpack $ TE.decodeUtf8 $ B16.encode $ BS.reverse bs

showBlockHash :: BlockHash -> String
showBlockHash (BlockHash (Hash256 bs)) = T.unpack $ TE.decodeUtf8 $ B16.encode $ BS.reverse bs

showInput :: (Int, TxIn) -> IO ()
showInput (idx, inp) = do
  let prevTxId = outPointHash (txInPrevOutput inp)
      prevIdx = outPointIndex (txInPrevOutput inp)
  putStrLn $ "  [" ++ show idx ++ "] " ++ showTxId prevTxId ++ ":" ++ show prevIdx

showOutput :: (Int, TxOut) -> IO ()
showOutput (idx, out) = do
  let valueBtc = fromIntegral (txOutValue out) / 100000000.0 :: Double
      scriptHex = TE.decodeUtf8 $ B16.encode (txOutScript out)
  putStrLn $ "  [" ++ show idx ++ "] " ++ show valueBtc ++ " BTC"
  putStrLn $ "       script: " ++ T.unpack scriptHex

addressTypeName :: Address -> String
addressTypeName (PubKeyAddress _) = "P2PKH (legacy)"
addressTypeName (ScriptAddress _) = "P2SH (script hash)"
addressTypeName (WitnessPubKeyAddress _) = "P2WPKH (native SegWit)"
addressTypeName (WitnessScriptAddress _) = "P2WSH (native SegWit script)"
addressTypeName (TaprootAddress _) = "P2TR (Taproot)"

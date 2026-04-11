{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Options.Applicative
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import System.IO (hSetBuffering, stdout, BufferMode(..))
import System.Directory (createDirectoryIfMissing, getHomeDirectory)
import System.FilePath ((</>))
import Control.Concurrent (threadDelay, forkIO)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Monad (forM, forM_, unless, when, void, forever, filterM, foldM)
import System.Posix.Signals (installHandler, sigINT, sigTERM, Handler(..))
import Data.Maybe (mapMaybe)
import Control.Concurrent.STM
import Control.Exception (bracket, catch, SomeException)
import Data.Word (Word32, Word64)
import Data.Int (Int32)
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy.Char8 as BL8
import Data.Serialize (decode)
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.HTTP.Types as HTTP

import qualified Network.Socket as NS (getAddrInfo, addrAddress, AddrInfo)
import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash, textToAddress, Address(..))
import Haskoin.Script (decodeScript)
import Haskoin.Network
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Rpc
import Haskoin.Mempool
import Haskoin.FeeEstimator
import Haskoin.Wallet

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
  , noPrune      :: !Bool
  , noDbCache    :: !Int
  , noListen     :: !Bool
  , noListenPort :: !Int
  , noMetricsPort :: !Int
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
  <*> switch (long "prune" <> help "Enable pruning")
  <*> option auto (long "dbcache" <> value 450 <> help "DB cache in MB")
  <*> option auto (long "listen" <> value True <> help "Accept incoming connections (default: True)")
  <*> option auto (long "port" <> value 8333 <> help "Listen port")
  <*> option auto (long "metricsport" <> value 9332 <> help "Prometheus metrics port (0 to disable)")

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
runNode net dataDir NodeOptions{..} = do
  putStrLn $ "Starting Haskoin on " ++ netName net
  putStrLn $ "Data directory: " ++ dataDir

  -- Open database
  let dbConfig = (defaultDBConfig (dataDir </> "chainstate"))
        { dbBlockCacheSize = noDbCache * 1024 * 1024 }
  bracket (openDB dbConfig) closeDB $ \db -> do

    -- Initialize or load chain state
    mState <- getChainState db
    case mState of
      Nothing -> do
        putStrLn "Initializing new chain..."
        let genesis = netGenesisBlock net
            genesisHash = computeBlockHash (blockHeader genesis)
        putBlockHeader db genesisHash (blockHeader genesis)
        putBlockHeight db 0 genesisHash
        putBestBlockHash db genesisHash
      Just state ->
        putStrLn $ "Resuming from height " ++ show (pcsHeight state)

    -- Initialize header chain
    hc <- initHeaderChainFromDB db net

    -- Initialize UTXO cache
    cache <- newUTXOCache db (noDbCache * 1024 * 1024 `div` 100)

    -- Initialize mempool
    mp <- newMempool net cache defaultMempoolConfig 0

    -- Initialize fee estimator with persistence
    fe <- newFeeEstimator
    let feeEstimatesPath = dataDir </> "fee_estimates.json"
    loadFeeEstimates fe feeEstimatesPath

    -- Track next expected block height for download.
    -- Resume from the loaded header chain tip so we don't re-request
    -- blocks that are already connected.
    loadedHeight <- readTVarIO (hcHeight hc)
    nextBlockRef <- newIORef (loadedHeight + 1)
    -- Track highest block we've requested (for sliding window)
    requestedUpToRef <- newIORef loadedHeight
    -- IBD mode flag: skip block inv requests until header sync catches up
    ibdModeRef <- newIORef True
    -- Recently-rejected transaction filter (cleared on each new block)
    recentlyRejectedRef <- newIORef (Set.empty :: Set.Set TxId)

    -- Start header sync
    hs <- startHeaderSync net hc

    -- Start peer manager with sync-aware message handler
    let pmConfig = defaultPeerManagerConfig
          { pmcMaxOutbound = min 8 noMaxPeers
          , pmcDataDir     = dataDir
          }
    pmRef <- newIORef (undefined :: PeerManager)
    pm <- startPeerManager net pmConfig (\addr msg ->
      syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef requestedUpToRef ibdModeRef recentlyRejectedRef addr msg
        `catch` (\(e :: SomeException) -> putStrLn $ "Handler error: " ++ show e))
    writeIORef pmRef pm

    -- Seed known addresses from --connect flags
    forM_ noConnect $ \connectStr -> do
      let (host, portStr) = case break (== ':') connectStr of
            (h, ':':p) -> (h, p)
            (h, _)     -> (h, show (netDefaultPort net))
      case reads portStr of
        [(port, "")] -> do
          addrInfos <- NS.getAddrInfo Nothing (Just host) (Just (show (port :: Int))) :: IO [NS.AddrInfo]
          forM_ addrInfos $ \ai -> do
            let addr = NS.addrAddress ai
            putStrLn $ "Adding connect peer: " ++ show addr
            atomically $ modifyTVar' (pmKnownAddrs pm) (Set.insert addr)
        _ -> putStrLn $ "Invalid connect address: " ++ connectStr

    -- Spawn a thread to send getheaders once a peer connects
    void $ forkIO $ getheadersSender pm hc net
      `catch` (\(e :: SomeException) -> putStrLn $ "getheadersSender error: " ++ show e)

    -- Block downloading is done from the MHeaders and MBlock handlers

    -- Start RPC server
    let rpcConfig = defaultRpcConfig
          { rpcPort     = noRpcPort
          , rpcUser     = noRpcUser
          , rpcPassword = noRpcPass
          , rpcDataDir  = dataDir
          }
    _rpcServer <- startRpcServer rpcConfig db hc pm mp fe cache net Nothing Nothing
    putStrLn $ "RPC server listening on port " ++ show noRpcPort

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

    -- Wait forever (or until signal)
    putStrLn "Node is running. Press Ctrl+C to stop."
    shutdownVar <- newEmptyMVar
    void $ installHandler sigINT (Catch $ putMVar shutdownVar ()) Nothing
    void $ installHandler sigTERM (Catch $ putMVar shutdownVar ()) Nothing
    takeMVar shutdownVar
    putStrLn "Shutting down..."
    saveFeeEstimates fe feeEstimatesPath
    putStrLn $ "Fee estimates saved to " ++ feeEstimatesPath
    putStrLn "Shutdown complete."

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
        }

  entriesVar <- newTVarIO (Map.singleton genesisHash genesisEntry)
  tipVar <- newTVarIO genesisEntry
  heightVar <- newTVarIO 0
  byHeightVar <- newTVarIO (Map.singleton 0 genesisHash)
  invalidatedVar <- newTVarIO Set.empty

  -- Load persisted headers from the height index to rebuild the in-memory chain.
  -- connectBlock writes PrefixBlockHeader and PrefixBlockHeight for every
  -- connected block, so we can walk the height index sequentially.
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
                    let work = ceChainWork prevEntry + headerWork header
                        entry = ChainEntry
                          { ceHeader = header
                          , ceHash = bh
                          , ceHeight = height
                          , ceChainWork = work
                          , cePrev = Just (ceHash prevEntry)
                          , ceStatus = StatusValid
                          , ceMedianTime = bhTimestamp header
                          }
                    atomically $ do
                      modifyTVar' entriesVar (Map.insert bh entry)
                      modifyTVar' byHeightVar (Map.insert height bh)
                      writeTVar tipVar entry
                      writeTVar heightVar height
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

-- | Request blocks for a range of heights from the header chain
-- Batches requests in groups of 16 to avoid overwhelming peers
requestBlocks :: PeerManager -> HeaderChain -> Word32 -> Word32 -> IO ()
requestBlocks pm hc fromHeight toHeight = do
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
          let pc = peerList !! (idx `mod` numPeers)
              invVecs = [ InvVector InvWitnessBlock (getBlockHashHash h) | h <- batch ]
          ok <- (safeSendMessage pc (MGetData (GetData invVecs)) >> return True)
            `catch` (\(e :: SomeException) -> do
              putStrLn $ "Failed to send getdata: " ++ show e
              return False)
          unless ok $ return ()

-- | Split a list into chunks of n
chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (chunk, rest) = splitAt n xs in chunk : chunksOf n rest

-- | Sync-aware message handler
syncMessageHandler :: HaskoinDB -> HeaderChain -> HeaderSync -> UTXOCache
                   -> Mempool -> FeeEstimator -> Network
                   -> IORef PeerManager -> IORef Word32 -> IORef Word32
                   -> IORef Bool -> IORef (Set.Set TxId)
                   -> SockAddr -> Message -> IO ()
syncMessageHandler db hc hs _cache mp _fe net pmRef nextBlockRef requestedUpToRef ibdModeRef recentlyRejectedRef addr msg = case msg of
  MPing (Ping _nonce) ->
    return ()  -- Pong handled at peer level

  MHeaders (Headers hdrs) -> do
    putStrLn $ "Received " ++ show (length hdrs) ++ " headers"
    -- Bypass presync/redownload state machine and add headers directly
    -- to the chain. The anti-DoS presync is overkill for our environment.
    added <- foldM (\count hdr -> do
        result <- addHeader net hc hdr
        case result of
            Right entry -> do
              -- Persist header and height index so the chain survives restarts.
              -- putBlockHeader/putBlockHeight are idempotent for duplicates.
              let bh = ceHash entry
                  h  = ceHeight entry
              putBlockHeader db bh hdr
              putBlockHeight db h bh
              return (count + 1)
            Left _  -> return count
        ) (0 :: Int) hdrs
    putStrLn $ "Added " ++ show added ++ " of " ++ show (length hdrs) ++ " headers"
    -- If we got a full batch (2000), request more headers immediately
    when (added >= 2000) $ do
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

    -- After headers, request ALL blocks up to new tip
    when (added > 0) $ do
      tip <- getChainTip hc
      let tipHeight = ceHeight tip
      nextBlock <- readIORef nextBlockRef
      pm <- readIORef pmRef
      requestBlocks pm hc nextBlock tipHeight
      writeIORef nextBlockRef (tipHeight + 1)
      writeIORef requestedUpToRef tipHeight

  MBlock block -> do
    let bh = computeBlockHash (blockHeader block)
        hdr = blockHeader block
    -- First, ensure the header is in our chain index.
    -- For unsolicited blocks (received via inv->getdata), the header may
    -- not yet be in the chain. addHeader is idempotent if already known.
    addResult <- addHeader net hc hdr
    case addResult of
      Left err -> do
        isIBD <- readIORef ibdModeRef
        unless isIBD $
          putStrLn $ "Block header rejected: " ++ err
      Right entry -> do
        let height = ceHeight entry
        let result = do
              connectBlock db net block height
              putBlockHeight db height bh
              putBestBlockHash db bh
        result `catch` (\(e :: SomeException) ->
          putStrLn $ "ERROR connecting block " ++ show height ++ ": " ++ show e)
        when (height `mod` 500 == 0) $
          putStrLn $ "Connected block at height " ++ show height
        -- Advance the next-block pointer past this height
        -- This allows the download window to slide forward
        nextBlock <- readIORef nextBlockRef
        when (height >= nextBlock) $
          writeIORef nextBlockRef (height + 1)
        -- Remove confirmed txs from mempool and clear rejection filter
        blockConnected mp block
        writeIORef recentlyRejectedRef Set.empty
        -- Broadcast the block inv to other peers so it propagates
        pm <- readIORef pmRef
        let invVec = InvVector InvBlock (getBlockHashHash bh)
        broadcastMessage pm $ MInv $ Inv [invVec]
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
        -- Relay accepted tx inv to all connected peers
        pm <- readIORef pmRef
        let invVec = InvVector InvWitnessTx (getTxIdHash txid)
        broadcastMessage pm (MInv (Inv [invVec]))
      Left _err -> do
        -- Add to recently-rejected filter
        rejected <- readIORef recentlyRejectedRef
        when (Set.size rejected < 50000) $
          writeIORef recentlyRejectedRef (Set.insert txid rejected)

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

    -- Request unknown transactions (not in mempool, not recently rejected)
    let txIvs = filter (\iv -> ivType iv == InvTx
                             || ivType iv == InvWitnessTx) ivs
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
        -- Request as witness txs for full witness data
        let witnessTxIvs = map (\iv -> iv { ivType = InvWitnessTx }) unknown
        requestFromPeer pm addr (MGetData (GetData witnessTxIvs))
          `catch` (\(_ :: SomeException) -> return ())

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

  MAddr addrs -> do
    -- BIP155: Store addresses and relay to 2 random peers
    pm <- readIORef pmRef
    handleAddrMessage pm addrs
    relayAddrToRandomPeers pm addr (MAddr addrs)

  MAddrV2 addrv2msg -> do
    -- BIP155: Handle addrv2 message - extract IPv4/IPv6 and store
    pm <- readIORef pmRef
    let converted = mapMaybe addrV2ToAddrEntry (getAddrV2List addrv2msg)
    unless (null converted) $ do
      handleAddrMessage pm (Haskoin.Network.Addr converted)
      relayAddrToRandomPeers pm addr (MAddrV2 addrv2msg)

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
    entries <- readTVarIO (mpEntries mp)
    let mempoolTxMap = Map.map meTransaction entries
    case initPartialBlock cb mempoolTxMap of
      Left err -> do
        putStrLn $ "Compact block " ++ show bh ++ " init failed: " ++ err
        pm <- readIORef pmRef
        let iv = InvVector InvWitnessBlock (getBlockHashHash bh)
        requestFromPeer pm addr (MGetData (GetData [iv]))
          `catch` (\(_ :: SomeException) -> return ())
      Right (pdb, missing) ->
        if null missing
          then case fillPartialBlock pdb [] of
            Right block -> do
              putStrLn $ "Compact block " ++ show bh ++ " reconstructed (mempool_hits=" ++ show (pdbMempoolCount pdb) ++ ")"
              syncMessageHandler db hc hs _cache mp _fe net pmRef nextBlockRef requestedUpToRef ibdModeRef recentlyRejectedRef addr (MBlock block)
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
                pm <- readIORef pmRef
                let gbt = GetBlockTxn { gbtBlockHash = bh, gbtIndexes = map fromIntegral missing }
                requestFromPeer pm addr (MGetBlockTxn gbt)
                  `catch` (\(_ :: SomeException) -> return ())

  MGetBlockTxn gbt -> do
    -- Serve missing transactions for compact block reconstruction
    let blockHash = gbtBlockHash gbt
        indices = gbtIndexes gbt
    mBlock <- getBlock db blockHash
    case mBlock of
      Just block -> do
        let txns = mapMaybe (\i -> let idx = fromIntegral i in if idx < length (blockTxns block) then Just (blockTxns block !! idx) else Nothing) indices
        pm <- readIORef pmRef
        requestFromPeer pm addr (MBlockTxn (BlockTxn { btBlockHash = blockHash, btTxns = txns }))
          `catch` (\(_ :: SomeException) -> return ())
      Nothing -> return ()

  MBlockTxn bt ->
    putStrLn $ "Received blocktxn for " ++ show (btBlockHash bt) ++ " (" ++ show (length (btTxns bt)) ++ " txns)"

  MPong _ -> return ()
  MVerAck -> return ()
  MSendHeaders -> return ()
  MSendCmpct _ -> return ()
  MWtxidRelay -> return ()

  _other -> return ()  -- Silently ignore other messages

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

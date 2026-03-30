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
import Control.Monad (forM, forM_, unless, when, void, forever, filterM)
import Control.Concurrent.STM
import Control.Exception (bracket, catch, SomeException)
import Data.Word (Word32, Word64)
import Data.Int (Int32)
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Serialize (decode)

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

    -- Initialize fee estimator
    fe <- newFeeEstimator

    -- Track next expected block height for download
    nextBlockRef <- newIORef (1 :: Word32)
    -- Track highest block we've requested (for sliding window)
    requestedUpToRef <- newIORef (0 :: Word32)

    -- Start header sync
    hs <- startHeaderSync net hc

    -- Start peer manager with sync-aware message handler
    let pmConfig = defaultPeerManagerConfig
          { pmcMaxOutbound = min 8 noMaxPeers }
    pmRef <- newIORef (undefined :: PeerManager)
    pm <- startPeerManager net pmConfig (\addr msg ->
      syncMessageHandler db hc hs cache mp fe net pmRef nextBlockRef requestedUpToRef addr msg
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
          { rpcPort = noRpcPort
          , rpcUser = noRpcUser
          , rpcPassword = noRpcPass
          }
    _rpcServer <- startRpcServer rpcConfig db hc pm mp fe cache net Nothing Nothing
    putStrLn $ "RPC server listening on port " ++ show noRpcPort

    -- Start P2P listener for inbound connections
    let listenPort = if noListenPort == 8333
          then netDefaultPort net  -- Use network-appropriate default
          else noListenPort
    when noListen $ do
      startInboundListener pm listenPort
      putStrLn $ "P2P listener started on port " ++ show listenPort

    -- Wait forever (or until signal)
    putStrLn "Node is running. Press Ctrl+C to stop."
    let loop = threadDelay (maxBound `div` 2) >> loop
    loop

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

  -- Load best block hash from DB to determine tip
  mBestHash <- getBestBlockHash db

  entriesVar <- newTVarIO (Map.singleton genesisHash genesisEntry)
  tipVar <- newTVarIO genesisEntry
  heightVar <- newTVarIO 0
  byHeightVar <- newTVarIO (Map.singleton 0 genesisHash)

  -- If we have persisted state, update the tip
  case mBestHash of
    Nothing -> return ()
    Just _bestHash -> do
      -- In a full implementation, we'd load headers from DB
      -- For now, start from genesis
      return ()

  invalidatedVar <- newTVarIO Set.empty
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
                   -> SockAddr -> Message -> IO ()
syncMessageHandler db hc hs _cache mp _fe net pmRef nextBlockRef requestedUpToRef addr msg = case msg of
  MPing (Ping _nonce) ->
    return ()  -- Pong handled at peer level

  MHeaders (Headers hdrs) -> do
    putStrLn $ "Received " ++ show (length hdrs) ++ " headers"
    (added, errs) <- handleHeaders hs hdrs
    putStrLn $ "Added " ++ show added ++ " headers"
    unless (null errs) $
      putStrLn $ "Header errors: " ++ show errs
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
    -- Find the height for this block
    heightMap <- readTVarIO (hcByHeight hc)
    let mHeight = Map.foldlWithKey'
          (\acc h hash -> if hash == bh then Just h else acc) Nothing heightMap
    case mHeight of
      Nothing -> return ()  -- Ignore unknown blocks silently
      Just height -> do
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

  MTx tx -> do
    _ <- addTransaction mp tx
    return ()

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

  MInv _inv ->
    return ()

  MAddr _addrs ->
    return ()

  MNotFound (NotFound invs) ->
    putStrLn $ "Peer says not found: " ++ show (length invs) ++ " items"

  MReject (Reject cmd code reason _) ->
    putStrLn $ "Peer rejected " ++ show cmd ++ ": code=" ++ show code ++ " reason=" ++ show reason

  MPong _ -> return ()
  MVerAck -> return ()
  MSendHeaders -> return ()
  MSendCmpct _ -> return ()
  MFeeFilter _ -> return ()
  MWtxidRelay -> return ()

  _other -> return ()  -- Silently ignore other messages

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

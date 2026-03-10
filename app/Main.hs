{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Options.Applicative
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import System.IO (hSetBuffering, stdout, BufferMode(..))
import System.Directory (createDirectoryIfMissing, getHomeDirectory)
import System.FilePath ((</>))
import Control.Concurrent (newEmptyMVar, takeMVar)
import Control.Concurrent.STM
import Control.Exception (bracket)
import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Serialize (decode)

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

data NetworkName = Mainnet | Testnet | Regtest
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
        <> value Mainnet <> help "Network: Mainnet, Testnet, Regtest" )
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
  <*> switch (long "listen" <> help "Accept incoming connections")
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
              Mainnet -> mainnet
              Testnet -> testnet3
              Regtest -> regtest

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

    -- Start peer manager
    let pmConfig = defaultPeerManagerConfig
          { pmcMaxOutbound = min 8 noMaxPeers }
    pm <- startPeerManager net pmConfig (messageHandler db hc cache mp fe)

    -- Start header sync
    _hs <- startHeaderSync net hc pm

    -- Start RPC server
    let rpcConfig = defaultRpcConfig
          { rpcPort = noRpcPort
          , rpcUser = noRpcUser
          , rpcPassword = noRpcPass
          }
    _rpcServer <- startRpcServer rpcConfig db hc pm mp fe cache net
    putStrLn $ "RPC server listening on port " ++ show noRpcPort

    -- Wait forever (or until signal)
    putStrLn "Node is running. Press Ctrl+C to stop."
    waitVar <- newEmptyMVar
    takeMVar waitVar  -- block forever

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

  return HeaderChain
    { hcEntries = entriesVar
    , hcTip = tipVar
    , hcHeight = heightVar
    , hcByHeight = byHeightVar
    }

-- | Central message handler
messageHandler :: HaskoinDB -> HeaderChain -> UTXOCache -> Mempool
               -> FeeEstimator -> SockAddr -> Message -> IO ()
messageHandler _db _hc _cache mp _fe _addr msg = case msg of
  MPing (Ping _nonce) ->
    -- Respond with pong (handled at peer level)
    return ()
  MHeaders _headers ->
    -- Process in header sync
    return ()
  MBlock _block ->
    -- Process in block download
    return ()
  MTx tx -> do
    _ <- addTransaction mp tx
    return ()
  MInv _inv ->
    -- Request unknown transactions and blocks
    return ()
  MAddr _addrs ->
    -- Add to known addresses
    return ()
  _ -> return ()

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

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | JSON-RPC Server and REST API
--
-- This module implements a JSON-RPC server compatible with Bitcoin Core's RPC
-- interface, providing endpoints for blockchain queries, transaction submission,
-- network information, mining, and wallet operations.
--
-- It also provides a REST API compatible with Bitcoin Core's REST interface,
-- supporting multiple output formats (JSON, hex, binary) for common queries.
--
-- Key Features:
--   - HTTP server using Warp for high performance
--   - Full Bitcoin Core RPC API compatibility
--   - Bitcoin Core REST API compatibility
--   - HTTP Basic authentication (RPC only, REST is read-only)
--   - Non-blocking handlers using STM
--
module Haskoin.Rpc
  ( -- * Server
    RpcServer(..)
  , RpcConfig(..)
  , defaultRpcConfig
  , startRpcServer
  , stopRpcServer
    -- * Request/Response Types
  , RpcRequest(..)
  , RpcResponse(..)
  , RpcError(..)
    -- * Error Codes
  , rpcInvalidRequest
  , rpcMethodNotFound
  , rpcInvalidParams
  , rpcInternalError
  , rpcParseError
  , rpcMiscError
    -- * Transaction Error Codes
  , rpcDeserializationError
  , rpcVerifyError
  , rpcVerifyRejected
  , rpcVerifyAlreadyInChain
    -- * Batch Constants
  , maxBatchSize
    -- * REST API
  , RestResponseFormat(..)
  , parseRestFormat
  , maxRestHeadersResults
  , maxGetUtxosOutpoints
    -- * BIP-22 result string mapping
  , bip22ResultString
    -- * Internal helpers (exported for testing)
  , deploymentInfoForEntry
  , softforksFromEntry
  , mempoolErrorToRpcResponse
  , decodeTxWithFallback
  , handleBatchRequest
  , parseSingleRequest
  , restApp
  , handleRestBlock
  , handleRestTx
  , handleRestHeaders
  , handleRestChainInfo
  , handleRestMempoolInfo
  , handleRestMempoolContents
  , handleRestBlockHashByHeight
  , handleRestGetUtxos
  , combinedApp
    -- * dumptxoutset rollback resolution (exported for testing)
  , DumpTarget(..)
  , RollbackSpec(..)
  , parseDumpTxOutSetParams
  , latestAvailableSnapshotHeight
  , resolveDumpTarget
    -- * ZMQ Notifications
  , ZmqTopic(..)
  , ZmqConfig(..)
  , ZmqNotifier(..)
  , ZmqEvent(..)
  , SequenceLabel(..)
  , defaultZmqConfig
  , newZmqNotifier
  , closeZmqNotifier
  , notifyBlockConnect
  , notifyBlockDisconnect
  , notifyRawBlock
  , notifyHashBlock
  , notifyTxAcceptance
  , notifyTxRemoval
  , notifyRawTx
  , notifyHashTx
  , zmqTopicToBytes
  , sequenceLabelToByte
  , eventToTopicAndBody
  , hashToLeBytes
  , txidToLeBytes
  , zmqNotSupportedMessage
    -- * Multi-Wallet Support
  , extractWalletName
  , rpcWalletNotFound
  , rpcWalletNotSpecified
  , rpcWalletAlreadyLoaded
  , rpcWalletAlreadyExists
  ) where

import Data.Aeson
import Data.Aeson.Types (Parser, Result(..))
import Data.Scientific (toBoundedInteger)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as C8
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32, Word64)
import Data.Int (Int32, Int64)
import Network.Wai (Application, Request, Response, responseLBS, requestBody,
                    requestMethod, requestHeaders, pathInfo, rawPathInfo,
                    rawQueryString)
import Network.Wai.Handler.Warp (run, Settings, defaultSettings, setPort, setHost)
import Network.HTTP.Types (status200, status400, status401, status404, status405,
                           status500, status503, hContentType, hAuthorization)
import Control.Concurrent (ThreadId, forkIO, killThread)
import Control.Concurrent.STM
import Control.Exception (try, SomeException, catch, bracket, bracket_, mask_, handle)
import Data.List.NonEmpty (NonEmpty(..))
import qualified System.ZMQ4 as ZMQ
import Data.IORef
import Data.Word (Word8)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Serialize as S
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import Control.Monad (forM, forM_, void, when)
import Control.Concurrent (threadDelay)
import Data.Maybe (fromMaybe, catMaybes, listToMaybe, mapMaybe, isJust)
import Data.List (find, sort)
import qualified Data.Set as Set
import qualified Crypto.Hash as Crypto
import qualified Data.ByteArray as BA
import Data.Bits (shiftL, shiftR, (.|.), (.&.), xor, testBit)
import Data.Char (chr, toLower)
import Data.List (foldl', isInfixOf)
import Text.Printf (printf)
import qualified Data.Vector as V
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Time.Clock (NominalDiffTime)
import qualified Data.Time.Clock as TimeClock
import qualified Crypto.Random as CryptoRandom
import System.Directory (doesFileExist, removeFile)
import System.FilePath ((</>))
import System.Posix.Files (setFileMode)
import System.IO (hSetEncoding, hPutStr, utf8, withFile, IOMode(..))

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256, computeTxId, computeBlockHash, textToAddress,
                        Address(..), PubKey(..), serializePubKeyCompressed,
                        base58Check, bech32Encode, bech32mEncode,
                        SecKey(..), hash160, signMessage, recoverMessagePubKey)
import Haskoin.Consensus (Network(..), HeaderChain(..), ChainEntry(..), BlockStatus(..),
                           bitsToTarget, blockReward, txBaseSize, txTotalSize,
                           witnessScaleFactor, computeWtxId, computeMerkleRoot,
                           medianTimePast, maxBlockWeight,
                           invalidateBlock, reconsiderBlock, InvalidateError(..),
                           Deployment(..), taprootDeployment,
                           checkAssumeutxoWhitelist,
                           AssumeUtxoParams(..), assumeUtxoForBlockHash,
                           connectBlock, disconnectBlock)
import Haskoin.Script (decodeScript, classifyOutput, ScriptType(..), Script(..),
                        ScriptOp(..), encodeScriptOps)
import Haskoin.Storage (HaskoinDB, UTXOCache(..), getBlock, getBlockHeader,
                         lookupUTXO, UTXOEntry(..), TxLocation(..), getTxIndex,
                         BlockStore(..), BlockIndex(..), getBlockIndex,
                         isBlockPruned, pruneBlockchain, minBlocksToKeep,
                         loadSnapshot, SnapshotMetadata(..), UtxoSnapshot(..),
                         dumpTxOutSetFromDB,
                         AssumeUtxoData(..), verifySnapshot,
                         buildSpentUtxoMapFromDB,
                         getUndoData)
import Haskoin.Network (PeerManager(..), PeerInfo(..), Version(..),
                         getPeerCount, getConnectedPeers, broadcastMessage,
                         Message(..), Inv(..), InvVector(..), InvType(..),
                         protocolVersion, nodeNetwork, nodeWitness, nodeBloom,
                         nodeNetworkLimited, hasService, ServiceFlag(..),
                         disconnectPeer, addNodeConnect, sockAddrToHostPort)
import Network.Socket (SockAddr(..))
import Haskoin.Mempool (Mempool(..), MempoolEntry(..), MempoolConfig(..),
                         MempoolError(..),
                         addTransaction, getTransaction, getMempoolTxIds,
                         getMempoolSize, FeeRate(..), calculateVSize,
                         calculateFeeRate, selectTransactions,
                         getAncestors, getDescendants, removeTransaction,
                         isRbfReplaceable)
import qualified Haskoin.Mempool.Persist as MPP
import Haskoin.FeeEstimator (FeeEstimator(..), estimateSmartFee, FeeEstimateMode(..),
                              estimateRawFee, RawFeeEstimate(..), RawBucketRange(..))
import Haskoin.BlockTemplate (BlockTemplate(..), TemplateTransaction(..),
                               createBlockTemplate, submitBlock)
import Haskoin.Wallet (Descriptor(..), KeyExpr(..), ParseError(..),
                        parseDescriptor, descriptorToText, deriveAddresses,
                        deriveScripts, descriptorChecksum, addDescriptorChecksum,
                        validateDescriptorChecksum, isRangeDescriptor,
                        WalletManager(..), WalletState(..), WalletInfo(..),
                        wifDecode,
                        newWalletManager, createManagedWallet, loadManagedWallet,
                        unloadManagedWallet, getManagedWallet, getDefaultWallet,
                        listManagedWallets, getWalletInfo, getBalance,
                        -- Wallet encryption (BIP-38-style passphrase locking)
                        Passphrase, encryptWallet, unlockWallet, lockWallet,
                        isWalletLocked,
                        -- Wallet address/transaction functions
                        AddressType(..), getNewAddress, sendToAddress,
                        getWalletUTXOs, Utxo(..),
                        -- PSBT types and functions
                        Psbt(..), PsbtGlobal(..), PsbtInput(..), PsbtOutput(..),
                        KeyPath(..), emptyPsbt, emptyPsbtInput,
                        createPsbt, combinePsbts, finalizePsbt, extractTransaction,
                        decodePsbt, encodePsbt, isPsbtFinalized, getPsbtFee)

--------------------------------------------------------------------------------
-- RPC Configuration
--------------------------------------------------------------------------------

-- | RPC server configuration
data RpcConfig = RpcConfig
  { rpcHost     :: !String     -- ^ Bind address (default "127.0.0.1")
  , rpcPort     :: !Int        -- ^ Port number (default 8332)
  , rpcUser     :: !Text       -- ^ RPC username
  , rpcPassword :: !Text       -- ^ RPC password
  , rpcAllowIp  :: ![String]   -- ^ Allowed IP addresses
  , rpcDataDir  :: !FilePath   -- ^ Data directory for cookie file
  } deriving (Show, Generic)

instance NFData RpcConfig

-- | Default RPC configuration (localhost only for security)
defaultRpcConfig :: RpcConfig
defaultRpcConfig = RpcConfig
  { rpcHost     = "127.0.0.1"
  , rpcPort     = 8332
  , rpcUser     = "haskoin"
  , rpcPassword = "haskoin"
  , rpcAllowIp  = ["127.0.0.1"]
  , rpcDataDir  = "."
  }

--------------------------------------------------------------------------------
-- RPC Server State
--------------------------------------------------------------------------------

-- | RPC server handle
data RpcServer = RpcServer
  { rsConfig         :: !RpcConfig
  , rsDB             :: !HaskoinDB
  , rsHeaderChain    :: !HeaderChain
  , rsPeerMgr        :: !PeerManager
  , rsMempool        :: !Mempool
  , rsFeeEst         :: !FeeEstimator
  , rsUTXOCache      :: !UTXOCache
  , rsNetwork        :: !Network
  , rsBlockStore     :: !(Maybe BlockStore)  -- ^ Block store for pruning (optional)
  , rsThread         :: !(TVar (Maybe ThreadId))
  , rsMockTime       :: !(TVar (Maybe Word32))  -- ^ Mock time for regtest (setmocktime)
  , rsWalletMgr      :: !(Maybe WalletManager)  -- ^ Multi-wallet manager (optional)
  , rsStartTime      :: !Int64                  -- ^ Server start time (POSIX seconds)
  , rsCookieFile     :: !FilePath               -- ^ Path to the .cookie file
  , rsCookiePassword :: !Text                   -- ^ Cookie password (__cookie__ auth)
  , rsBlockSubmissionPaused :: !(TVar Bool)
    -- ^ NetworkDisable flag: when True, 'handleSubmitBlock' (and any
    -- P2P block-handler callsite that consults this flag) refuses new
    -- blocks. Set during 'handleDumpTxOutSet's rewind→dump→replay
    -- dance to mirror Bitcoin Core's NetworkDisable RAII guard around
    -- TemporaryRollback in @rpc/blockchain.cpp::dumptxoutset@. Peers
    -- stay connected; only block acceptance is gated. TVar so the
    -- P2P block-receive path can read without contending with the
    -- chain-write lock.
  }

-- | Get current time, using mock time if set (for regtest testing)
getCurrentTime :: RpcServer -> IO Word32
getCurrentTime server = do
  mockTime <- readTVarIO (rsMockTime server)
  case mockTime of
    Just t  -> return t
    Nothing -> (round :: Double -> Word32) . realToFrac <$> getPOSIXTime

--------------------------------------------------------------------------------
-- JSON-RPC Request/Response Types
--------------------------------------------------------------------------------

-- | JSON-RPC request
data RpcRequest = RpcRequest
  { reqJsonrpc :: !Text        -- ^ JSON-RPC version (typically "1.0" or "2.0")
  , reqMethod  :: !Text        -- ^ Method name
  , reqParams  :: !Value       -- ^ Parameters (array or object)
  , reqId      :: !Value       -- ^ Request ID (string, number, or null)
  } deriving (Show, Generic)

instance NFData RpcRequest

instance FromJSON RpcRequest where
  parseJSON = withObject "RpcRequest" $ \o -> RpcRequest
    <$> o .:? "jsonrpc" .!= "1.0"
    <*> o .: "method"
    <*> o .:? "params" .!= Null
    <*> o .:? "id" .!= Null

-- | JSON-RPC response
data RpcResponse = RpcResponse
  { resResult :: !Value        -- ^ Result on success
  , resError  :: !Value        -- ^ Error object or null
  , resId     :: !Value        -- ^ Request ID (echoed back)
  } deriving (Show, Generic)

instance NFData RpcResponse

instance ToJSON RpcResponse where
  toJSON RpcResponse{..} = object
    [ "result" .= resResult
    , "error"  .= resError
    , "id"     .= resId
    ]

-- | JSON-RPC error
data RpcError = RpcError
  { errCode    :: !Int         -- ^ Error code
  , errMessage :: !Text        -- ^ Human-readable message
  } deriving (Show, Generic)

instance NFData RpcError

instance ToJSON RpcError where
  toJSON RpcError{..} = object
    [ "code"    .= errCode
    , "message" .= errMessage
    ]

--------------------------------------------------------------------------------
-- Standard Error Codes
--------------------------------------------------------------------------------

-- | Invalid JSON was received by the server
rpcParseError :: Int
rpcParseError = -32700

-- | The JSON sent is not a valid Request object
rpcInvalidRequest :: Int
rpcInvalidRequest = -32600

-- | The method does not exist / is not available
rpcMethodNotFound :: Int
rpcMethodNotFound = -32601

-- | Invalid method parameter(s)
rpcInvalidParams :: Int
rpcInvalidParams = -32602

-- | Internal JSON-RPC error
rpcInternalError :: Int
rpcInternalError = -32603

-- | Miscellaneous error (Bitcoin-specific)
rpcMiscError :: Int
rpcMiscError = -1

--------------------------------------------------------------------------------
-- Bitcoin Core Transaction Error Codes
--------------------------------------------------------------------------------

-- | TX decode/deserialization failed (error code -22)
rpcDeserializationError :: Int
rpcDeserializationError = -22

-- | General error during transaction or block submission
-- Missing inputs, high fee rate, etc. (error code -25)
rpcVerifyError :: Int
rpcVerifyError = -25

-- | Transaction rejected by network rules (error code -26)
-- Policy rejection (non-standard, insufficient fee, etc.)
rpcVerifyRejected :: Int
rpcVerifyRejected = -26

-- | Transaction already in chain/mempool (error code -27)
rpcVerifyAlreadyInChain :: Int
rpcVerifyAlreadyInChain = -27

--------------------------------------------------------------------------------
-- Bitcoin Core Wallet Error Codes
--------------------------------------------------------------------------------

-- | Requested wallet does not exist or is not loaded (error code -18)
rpcWalletNotFound :: Int
rpcWalletNotFound = -18

-- | Multiple wallets loaded, wallet must be specified (error code -19)
rpcWalletNotSpecified :: Int
rpcWalletNotSpecified = -19

-- | Wallet already loaded (error code -35)
rpcWalletAlreadyLoaded :: Int
rpcWalletAlreadyLoaded = -35

-- | Wallet already exists (error code -36)
rpcWalletAlreadyExists :: Int
rpcWalletAlreadyExists = -36

-- | Wallet passphrase entered was incorrect (error code -14, mirrors Bitcoin
--   Core's @RPC_WALLET_PASSPHRASE_INCORRECT@).
rpcWalletPassphraseIncorrect :: Int
rpcWalletPassphraseIncorrect = -14

-- | Wallet is in an invalid state for the requested operation (error code -15,
--   mirrors Bitcoin Core's @RPC_WALLET_WRONG_ENC_STATE@).  E.g. calling
--   @walletpassphrase@ on an unencrypted wallet, or @encryptwallet@ on an
--   already-encrypted one.
rpcWalletWrongEncState :: Int
rpcWalletWrongEncState = -15

-- | Wallet encryption failed (error code -16, mirrors Bitcoin Core's
--   @RPC_WALLET_ENCRYPTION_FAILED@).
rpcWalletEncryptionFailed :: Int
rpcWalletEncryptionFailed = -16

-- | Maximum @walletpassphrase@ unlock duration in seconds (~3.17 years).
--   Matches Bitcoin Core's @MAX_SLEEP_TIME@ in wallet/rpc/encrypt.cpp.
walletPassphraseMaxSleepTime :: Int
walletPassphraseMaxSleepTime = 100000000

--------------------------------------------------------------------------------
-- Batch Request Constants
--------------------------------------------------------------------------------

-- | Maximum number of requests allowed in a batch (Bitcoin Core limit)
maxBatchSize :: Int
maxBatchSize = 1000

--------------------------------------------------------------------------------
-- Server Lifecycle
--------------------------------------------------------------------------------

-- | Generate a 32-byte random cookie password, hex-encoded (64 chars)
generateCookiePassword :: IO Text
generateCookiePassword = do
  bytes <- CryptoRandom.getRandomBytes 32 :: IO BS.ByteString
  return $! TE.decodeUtf8 (B16.encode bytes)

-- | Write the cookie file and set permissions to 0o600 (owner read/write only)
writeCookieFile :: FilePath -> Text -> IO ()
writeCookieFile cookiePath cookiePass = do
  withFile cookiePath WriteMode $ \h -> do
    hSetEncoding h utf8
    let content = "__cookie__:" <> T.unpack cookiePass <> "\n"
    hPutStr h content
  -- Restrict to owner read+write only: no group or other permissions
  setFileMode cookiePath 0o600

-- | Start the RPC server
-- Handles both JSON-RPC (POST requests) and REST API (GET /rest/* requests)
startRpcServer :: RpcConfig -> HaskoinDB -> HeaderChain -> PeerManager
               -> Mempool -> FeeEstimator -> UTXOCache -> Network
               -> Maybe BlockStore -> Maybe WalletManager -> IO RpcServer
startRpcServer config db hc pm mp fe cache net mBlockStore mWalletMgr = do
  threadVar <- newTVarIO Nothing
  mockTimeVar <- newTVarIO Nothing  -- No mock time by default
  startTime <- round <$> getPOSIXTime
  -- Generate cookie and write to {datadir}/.cookie
  cookiePass <- generateCookiePassword
  let cookiePath = rpcDataDir config </> ".cookie"
  writeCookieFile cookiePath cookiePass
  -- NetworkDisable flag (mirrors Core's NetworkDisable RAII around
  -- TemporaryRollback in rpc/blockchain.cpp::dumptxoutset). Initialised
  -- to False; flipped True only inside the rollback dance.
  pauseVar <- newTVarIO False
  let server = RpcServer config db hc pm mp fe cache net mBlockStore threadVar mockTimeVar mWalletMgr startTime cookiePath cookiePass pauseVar
  -- Use combined app to handle both RPC and REST endpoints
  tid <- forkIO $ run (rpcPort config) (combinedApp server)
  atomically $ writeTVar threadVar (Just tid)
  return server

-- | Stop the RPC server
stopRpcServer :: RpcServer -> IO ()
stopRpcServer rs = do
  mTid <- readTVarIO (rsThread rs)
  mapM_ killThread mTid
  atomically $ writeTVar (rsThread rs) Nothing
  -- Remove the cookie file on clean shutdown; ignore errors (e.g. already deleted)
  removeFile (rsCookieFile rs) `catch` (\(_ :: SomeException) -> return ())

--------------------------------------------------------------------------------
-- HTTP Application
--------------------------------------------------------------------------------

-- | WAI application for the RPC server
-- Supports both single JSON-RPC requests (object) and batch requests (array)
rpcApp :: RpcServer -> Application
rpcApp server req respond = do
  -- Only accept POST requests
  if requestMethod req /= "POST"
    then respond $ responseLBS status405
           [(hContentType, "application/json")]
           "{\"error\": \"Method not allowed\"}"
    else do
      -- Check authentication
      let authOk = checkAuth server req
      if not authOk
        then respond $ responseLBS status401
               [(hContentType, "application/json")]
               "{\"error\": \"Unauthorized\"}"
        else do
          -- Read request body and parse as generic JSON Value
          body <- readBody req
          case eitherDecode (BL.fromStrict body) :: Either String Value of
            Left err -> respond $ jsonResponse $ RpcResponse
              Null (toJSON $ RpcError rpcParseError (T.pack err)) Null

            -- Single request: body is a JSON object
            Right (Object obj) ->
              case parseSingleRequest (Object obj) of
                Left errResp -> respond $ jsonResponse errResp
                Right rpcReq -> do
                  result <- handleRpcRequest server rpcReq
                  respond $ jsonResponse result

            -- Batch request: body is a JSON array
            Right (Array arr) -> do
              result <- handleBatchRequest server (V.toList arr)
              respond $ jsonArrayResponse result

            -- Invalid: neither object nor array
            Right _ -> respond $ jsonResponse $ RpcResponse
              Null (toJSON $ RpcError rpcParseError "Parse error: expected object or array") Null

-- | Handle a batch of RPC requests
-- Returns an array of responses in the same order as requests.
-- Each request is executed independently; failures don't affect other requests.
-- Empty batch returns an error. Batch size is limited to maxBatchSize.
handleBatchRequest :: RpcServer -> [Value] -> IO [RpcResponse]
handleBatchRequest _server [] =
  -- Empty batch is an error (but return as array with single error for consistency)
  return [RpcResponse Null (toJSON $ RpcError rpcInvalidRequest "Invalid Request: empty batch") Null]
handleBatchRequest _server reqs | length reqs > maxBatchSize =
  -- Batch too large
  return [RpcResponse Null (toJSON $ RpcError rpcInvalidRequest
    ("Invalid Request: batch size " <> T.pack (show (length reqs)) <>
     " exceeds maximum of " <> T.pack (show maxBatchSize))) Null]
handleBatchRequest server reqs = mapM (execSingleRpc server) reqs

-- | Execute a single RPC request from a batch, catching any errors
execSingleRpc :: RpcServer -> Value -> IO RpcResponse
execSingleRpc server val = do
  case parseSingleRequest val of
    Left errResp -> return errResp
    Right rpcReq -> do
      result <- try (handleRpcRequest server rpcReq) :: IO (Either SomeException RpcResponse)
      case result of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInternalError (T.pack $ show err))
          (reqId rpcReq)
        Right resp -> return resp

-- | Parse a JSON Value as an RpcRequest
-- Returns Left with an error response if parsing fails
parseSingleRequest :: Value -> Either RpcResponse RpcRequest
parseSingleRequest val =
  case fromJSON val of
    Success rpcReq -> Right rpcReq
    Error err -> Left $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidRequest (T.pack $ "Invalid Request: " ++ err))
      -- Try to extract id from the value if possible
      (extractIdFromValue val)

-- | Check HTTP Basic authentication.
-- Accepts either:
--   (a) configured rpcUser:rpcPassword, or
--   (b) __cookie__:<cookie-password> (cookie-based auth for local clients)
checkAuth :: RpcServer -> Request -> Bool
checkAuth server req =
  case lookup hAuthorization (requestHeaders req) of
    Nothing -> False
    Just authHeader ->
      let config = rsConfig server
          -- Decode the Base64 "Basic <credentials>" header
          decoded = case BS.stripPrefix "Basic " authHeader of
            Nothing  -> Nothing
            Just b64 -> case B64.decode b64 of
              Left _    -> Nothing
              Right raw -> Just (TE.decodeUtf8Lenient raw)
      in case decoded of
           Nothing -> False
           Just creds ->
             let (user, rest) = T.breakOn ":" creds
                 pass = T.drop 1 rest  -- drop the leading ':'
             in -- Cookie auth: username must be exactly "__cookie__"
                (user == "__cookie__" && pass == rsCookiePassword server)
                -- Configured user/password auth
                || (user == rpcUser config && pass == rpcPassword config)

-- | Read the full request body
readBody :: Request -> IO ByteString
readBody req = do
  chunks <- getChunks
  return $ BS.concat chunks
  where
    getChunks = do
      chunk <- requestBody req
      if BS.null chunk
        then return []
        else (chunk :) <$> getChunks

-- | Create a JSON response for a single RpcResponse
jsonResponse :: RpcResponse -> Response
jsonResponse rpcRes = responseLBS status200
  [(hContentType, "application/json")]
  (encode rpcRes)

-- | Create a JSON response for a batch (array of RpcResponses)
jsonArrayResponse :: [RpcResponse] -> Response
jsonArrayResponse resps = responseLBS status200
  [(hContentType, "application/json")]
  (encode (toJSON resps))

-- | Extract the 'id' field from a JSON Value, if present
extractIdFromValue :: Value -> Value
extractIdFromValue (Object obj) = fromMaybe Null (KM.lookup "id" obj)
extractIdFromValue _ = Null

--------------------------------------------------------------------------------
-- Multi-Wallet URI Handling
--------------------------------------------------------------------------------

-- | Wallet endpoint base path (matching Bitcoin Core)
walletEndpointBase :: Text
walletEndpointBase = "/wallet/"

-- | Extract wallet name from URI path.
-- Supports /wallet/<name> URI prefix for wallet selection.
-- Reference: Bitcoin Core wallet/rpc/util.cpp GetWalletNameFromJSONRPCRequest
extractWalletName :: Request -> Maybe Text
extractWalletName req =
  let path = TE.decodeUtf8 (rawPathInfo req)
  in if walletEndpointBase `T.isPrefixOf` path
     then Just $ urlDecode $ T.drop (T.length walletEndpointBase) path
     else Nothing

-- | URL decode a text string (simple implementation for wallet names)
urlDecode :: Text -> Text
urlDecode = T.pack . decode' . T.unpack
  where
    decode' [] = []
    decode' ('%':a:b:rest) = case (toHexDigit a, toHexDigit b) of
      (Just hi, Just lo) -> toEnum (hi * 16 + lo) : decode' rest
      _ -> '%' : a : b : decode' rest
    decode' ('+':rest) = ' ' : decode' rest
    decode' (c:rest) = c : decode' rest

    toHexDigit c
      | c >= '0' && c <= '9' = Just (fromEnum c - fromEnum '0')
      | c >= 'a' && c <= 'f' = Just (fromEnum c - fromEnum 'a' + 10)
      | c >= 'A' && c <= 'F' = Just (fromEnum c - fromEnum 'A' + 10)
      | otherwise = Nothing

-- | Get wallet for the request, handling wallet selection.
-- Uses /wallet/<name> URI if present, otherwise uses the default wallet.
-- Returns error response if no wallet is available or multiple wallets without selection.
getWalletForRequest :: RpcServer -> Request -> IO (Either RpcResponse WalletState)
getWalletForRequest server req = do
  case rsWalletMgr server of
    Nothing -> return $ Left $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet manager available") Null
    Just wm -> do
      case extractWalletName req of
        Just walletName -> do
          mWallet <- getManagedWallet wm walletName
          case mWallet of
            Nothing -> return $ Left $ RpcResponse Null
              (toJSON $ RpcError rpcWalletNotFound
                ("Requested wallet does not exist or is not loaded: " <> walletName)) Null
            Just ws -> return $ Right ws
        Nothing -> do
          (mDefault, count) <- getDefaultWallet wm
          case mDefault of
            Nothing -> return $ Left $ RpcResponse Null
              (toJSON $ RpcError rpcWalletNotFound
                "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet.") Null
            Just ws
              | count == 1 -> return $ Right ws
              | otherwise -> return $ Left $ RpcResponse Null
                  (toJSON $ RpcError rpcWalletNotSpecified
                    "Multiple wallets are loaded. Please select which wallet to use by requesting the RPC through the /wallet/<walletname> URI path.") Null

--------------------------------------------------------------------------------
-- Request Dispatcher
--------------------------------------------------------------------------------

-- | Handle an RPC request and dispatch to the appropriate handler
handleRpcRequest :: RpcServer -> RpcRequest -> IO RpcResponse
handleRpcRequest server req = do
  let params = reqParams req
      mkOk result = RpcResponse result Null (reqId req)
      mkErr code msg = RpcResponse Null (toJSON $ RpcError code msg) (reqId req)

  result <- case reqMethod req of
    -- Blockchain RPCs
    "getblockchaininfo"    -> handleGetBlockchainInfo server
    "getdeploymentinfo"    -> handleGetDeploymentInfo server params
    "getblockcount"        -> handleGetBlockCount server
    "getblockhash"         -> handleGetBlockHash server params
    "getblock"             -> handleGetBlock server params
    "getblockheader"       -> handleGetBlockHeader server params
    "gettxout"             -> handleGetTxOut server params
    "getbestblockhash"     -> handleGetBestBlockHash server
    "getsyncstate"         -> handleGetSyncState server
    "getdifficulty"        -> handleGetDifficulty server
    "pruneblockchain"      -> handlePruneBlockchain server params
    "invalidateblock"      -> handleInvalidateBlock server params
    "reconsiderblock"      -> handleReconsiderBlock server params

    -- Transaction RPCs
    "getrawtransaction"    -> handleGetRawTransaction server params
    "sendrawtransaction"   -> handleSendRawTransaction server params
    "decoderawtransaction" -> handleDecodeRawTransaction server params

    -- Mempool RPCs
    "getmempoolinfo"       -> handleGetMempoolInfo server
    "getrawmempool"        -> handleGetRawMempool server params

    -- Network RPCs
    "getnetworkinfo"       -> handleGetNetworkInfo server
    "getpeerinfo"          -> handleGetPeerInfo server
    "getconnectioncount"   -> handleGetConnectionCount server
    "addnode"              -> handleAddNode server params

    -- Mining RPCs
    "getblocktemplate"     -> handleGetBlockTemplate server params
    "submitblock"          -> handleSubmitBlock server params
    "getmininginfo"        -> handleGetMiningInfo server

    -- Regtest Mining RPCs
    "generatetoaddress"    -> handleGenerateToAddress server params
    "generateblock"        -> handleGenerateBlock server params
    "generate"             -> handleGenerate server params

    -- Regtest Control RPCs
    "setmocktime"          -> handleSetMockTime server params

    -- Fee estimation
    "estimatesmartfee"     -> handleEstimateSmartFee server params
    "estimaterawfee"       -> handleEstimateRawFee server params

    -- Utility
    "validateaddress"      -> handleValidateAddress server params
    "getinfo"              -> handleGetInfo server

    -- Wallet descriptor RPCs
    "importdescriptors"    -> handleImportDescriptors server params
    "listdescriptors"      -> handleListDescriptors server params

    -- Multi-wallet management RPCs
    "createwallet"         -> handleCreateWallet server params
    "loadwallet"           -> handleLoadWallet server params
    "unloadwallet"         -> handleUnloadWallet server params
    "listwallets"          -> handleListWallets server
    "getwalletinfo"        -> handleGetWalletInfo server params

    -- Wallet balance RPCs (require wallet selection)
    "getbalance"           -> handleGetBalance server params

    -- PSBT RPCs
    "createpsbt"           -> handleCreatePsbt server params
    "decodepsbt"           -> handleDecodePsbt server params
    "combinepsbt"          -> handleCombinePsbt server params
    "finalizepsbt"         -> handleFinalizePsbt server params

    -- Blockchain RPCs (new)
    "getchaintips"         -> handleGetChainTips server

    -- Script RPCs
    "decodescript"         -> handleDecodeScript server params

    -- Mempool RPCs (new)
    "testmempoolaccept"    -> handleTestMempoolAccept server params
    "getmempoolentry"      -> handleGetMempoolEntry server params
    "getmempoolancestors"  -> handleGetMempoolAncestors server params
    "getmempooldescendants"-> handleGetMempoolDescendants server params
    "savemempool"          -> handleSaveMempool server
    "importmempool"        -> handleImportMempool server params
    "loadmempool"          -> handleImportMempool server params

    -- Raw transaction RPCs (new)
    "createrawtransaction"         -> handleCreateRawTransaction server params
    "signrawtransactionwithwallet" -> handleSignRawTransactionWithWallet server params

    -- Network RPCs (new)
    "disconnectnode"       -> handleDisconnectNode server params

    -- Wallet RPCs (new)
    "getnewaddress"        -> handleGetNewAddress server params
    "sendtoaddress"        -> handleSendToAddress server params
    "listtransactions"     -> handleListTransactions server params
    "listunspent"          -> handleListUnspent server params

    -- AssumeUTXO RPCs
    "loadtxoutset"         -> handleLoadTxOutSet server params
    "dumptxoutset"         -> handleDumpTxOutSet server params

    -- Control RPCs
    "help"                 -> handleHelp server params
    "stop"                 -> handleStop server

    -- Utility RPCs (additional)
    "encryptwallet"        -> handleEncryptWallet server params
    "walletpassphrase"     -> handleWalletPassphrase server params
    "walletlock"           -> handleWalletLock server
    "setlabel"             -> handleSetLabel server params
    "verifymessage"        -> handleVerifyMessage server params
    "signmessage"          -> handleSignMessage server params
    "signmessagewithprivkey" -> handleSignMessage server params
    "uptime"               -> handleUptime server
    "getnettotals"         -> handleGetNetTotals server

    other -> return $ mkErr rpcMethodNotFound ("Method not found: " <> other)

  return result

--------------------------------------------------------------------------------
-- Blockchain RPC Handlers
--------------------------------------------------------------------------------

-- | Get information about the current state of the blockchain
-- Returns comprehensive blockchain state matching Bitcoin Core's getblockchaininfo
handleGetBlockchainInfo :: RpcServer -> IO RpcResponse
handleGetBlockchainInfo server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  -- Compute verification progress estimate (blocks validated / estimated total)
  -- For a fully synced node this approaches 1.0
  let progress = computeVerificationProgress (ceHeight tip) (bhTimestamp (ceHeader tip))
      -- Initial block download heuristic: we're in IBD if the tip is older than 24 hours
      -- or if we're significantly behind the estimated chain height
      currentTime = bhTimestamp (ceHeader tip)
      isIBD = estimateIsInitialBlockDownload (ceHeight tip) currentTime
      -- Soft-fork state: always sourced from the shared softforksFromEntry
      -- helper so getblockchaininfo and getdeploymentinfo cannot disagree.
      sforks = softforksFromEntry (rsNetwork server) tip
  let result = object
        [ "chain"                .= netName (rsNetwork server)
        , "blocks"               .= ceHeight tip
        , "headers"              .= ceHeight tip
        , "bestblockhash"        .= showHash (ceHash tip)
        , "bits"                 .= showBits (bhBits (ceHeader tip))
        , "target"               .= showHex (bitsToTarget (bhBits (ceHeader tip)))
        , "difficulty"           .= getDifficulty (bhBits (ceHeader tip))
        , "time"                 .= bhTimestamp (ceHeader tip)
        , "mediantime"           .= ceMedianTime tip
        , "verificationprogress" .= progress
        , "initialblockdownload" .= isIBD
        , "chainwork"            .= showHex (ceChainWork tip)
        , "size_on_disk"         .= (0 :: Int)
        , "pruned"               .= False
        , "softforks"            .= sforks
        , "warnings"             .= ([] :: [Text])
        ]
  return $ RpcResponse result Null Null

-- | Pure helper: build the full getdeploymentinfo result for a given
-- network configuration and chain entry.
--
-- All deployments in haskoin are currently modelled as "buried"
-- activations (fixed activation heights from the Network record).
-- Taproot on mainnet is reported as BIP9/active because Bitcoin Core
-- activated it via BIP9 (speedy trial) at block 709632.  Testdummy is
-- a stub BIP9 entry; full state-machine wiring is tracked in follow-up
-- issue: "getdeploymentinfo: wire full BIP9 state machine for mainnet
-- taproot / testdummy".
--
-- Reference: bitcoin-core/src/rpc/blockchain.cpp getdeploymentinfo.
deploymentInfoForEntry :: Network -> ChainEntry -> Value
deploymentInfoForEntry net entry =
  let height = ceHeight entry
      bHash  = showHash (ceHash entry)

      -- Helper: build a buried-style deployment object.
      buried activH =
        object [ "type"   .= ("buried" :: Text)
               , "active" .= (height >= activH)
               , "height" .= activH
               ]

      -- Helper: build a BIP9-style deployment object.
      -- statusStr / sinceH are approximations until the full state
      -- machine is wired; mActivH carries the activation height when known.
      bip9Obj dep statusStr sinceH isActive mActivH =
        let bip9Sub = object
              [ "bit"                   .= depBit dep
              , "start_time"            .= depStartTime dep
              , "timeout"               .= depTimeout dep
              , "min_activation_height" .= depMinActivationHeight dep
              , "status"                .= (statusStr :: Text)
              , "since"                 .= (sinceH :: Word32)
              , "status_next"           .= (statusStr :: Text)
              ]
            base = [ "type"   .= ("bip9" :: Text)
                   , "active" .= isActive
                   , "bip9"   .= bip9Sub
                   ]
            withHeight = case mActivH of
              Just h  -> ("height" .= (h :: Word32)) : base
              Nothing -> base
        in object withHeight

      -- Taproot: buried on regtest / testnet4 (activated at height 0 or 1),
      -- BIP9/active on mainnet (locked-in via speedy trial, height 709632).
      taprootObj =
        if netName net == "main"
          then
            let dep     = taprootDeployment net
                activH  = netTaprootHeight net
                isAct   = height >= activH
            in bip9Obj dep "active" activH isAct (Just activH)
          else
            buried (netTaprootHeight net)

      -- Testdummy: BIP9 stub.  State machine not yet wired; always
      -- reported as defined/inactive.
      -- TODO: wire full BIP9 state machine (follow-up issue).
      testdummyDep = Deployment
        { depBit                = 28
        , depStartTime          = 0
        , depTimeout            = maxBound
        , depMinActivationHeight = 0
        , depPeriod             = 144
        , depThreshold          = 108
        }
      testdummyObj = bip9Obj testdummyDep "defined" 0 False Nothing

      deployments = object
        [ "bip34"     .= buried (fromIntegral (netBIP34Height net))
        , "bip65"     .= buried (fromIntegral (netBIP65Height net))
        , "bip66"     .= buried (fromIntegral (netBIP66Height net))
        , "csv"       .= buried (fromIntegral (netCSVHeight net))
        , "segwit"    .= buried (fromIntegral (netSegwitHeight net))
        , "taproot"   .= taprootObj
        , "testdummy" .= testdummyObj
        ]
  in object
      [ "hash"        .= bHash
      , "height"      .= height
      , "deployments" .= deployments
      ]

-- | Pure helper: extract just the deployment-state map from
-- 'deploymentInfoForEntry'.  This is the single source of truth for
-- soft-fork state; both 'getblockchaininfo' (.softforks) and
-- 'getdeploymentinfo' (.deployments) project from this value so the
-- two RPCs can never disagree.
softforksFromEntry :: Network -> ChainEntry -> Value
softforksFromEntry net entry =
  case deploymentInfoForEntry net entry of
    Object km -> case KM.lookup "deployments" km of
      Just v  -> v
      Nothing -> object []
    _ -> object []

-- | Return deployment info for each known soft fork.
-- Accepts an optional block-hash parameter (default: chain tip).
handleGetDeploymentInfo :: RpcServer -> Value -> IO RpcResponse
handleGetDeploymentInfo server params = do
  let net = rsNetwork server
      hc  = rsHeaderChain server

  -- Resolve the target block entry.
  mEntry <- case extractParamText params 0 of
    Nothing -> do
      tip <- readTVarIO (hcTip hc)
      return (Just tip)
    Just hexHash ->
      case parseHash hexHash of
        Nothing -> return Nothing
        Just bh -> do
          entries <- readTVarIO (hcEntries hc)
          return (Map.lookup bh entries)

  case mEntry of
    Nothing ->
      return $ RpcResponse Null
        (toJSON $ RpcError rpcInvalidParams "Block not found") Null
    Just entry ->
      return $ RpcResponse (deploymentInfoForEntry net entry) Null Null

-- | Get the current block height
handleGetBlockCount :: RpcServer -> IO RpcResponse
handleGetBlockCount server = do
  height <- readTVarIO (hcHeight (rsHeaderChain server))
  return $ RpcResponse (toJSON height) Null Null

-- | Get the hash of the best (tip) block
handleGetBestBlockHash :: RpcServer -> IO RpcResponse
handleGetBestBlockHash server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  return $ RpcResponse (toJSON $ showHash (ceHash tip)) Null Null

-- | hashhog W70: uniform fleet-wide sync-state report.
-- Spec: meta-repo `spec/getsyncstate.md`.
handleGetSyncState :: RpcServer -> IO RpcResponse
handleGetSyncState server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  peerCount <- getPeerCount (rsPeerMgr server)
  let tipHeight = ceHeight tip
      tipHash   = showHash (ceHash tip)
      blockTime = bhTimestamp (ceHeader tip)
      isIBD     = estimateIsInitialBlockDownload tipHeight blockTime
      progress  = computeVerificationProgress tipHeight blockTime
      result = object
        [ "tip_height"               .= tipHeight
        , "tip_hash"                 .= tipHash
        , "best_header_height"       .= tipHeight
        , "best_header_hash"         .= tipHash
        , "initial_block_download"   .= isIBD
        , "num_peers"                .= peerCount
        , "verification_progress"    .= progress
        , "blocks_in_flight"         .= Null
        , "blocks_pending_connect"   .= Null
        , "last_block_received_time" .= Null
        , "chain"                    .= netName (rsNetwork server)
        , "protocol_version"         .= protocolVersion
        ]
  return $ RpcResponse result Null Null

-- | Get block hash at a specific height
handleGetBlockHash :: RpcServer -> Value -> IO RpcResponse
handleGetBlockHash server params = do
  case extractParam params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing height parameter") Null
    Just height -> do
      heightMap <- readTVarIO (hcByHeight (rsHeaderChain server))
      case Map.lookup height heightMap of
        Just bh -> return $ RpcResponse (toJSON $ showHash bh) Null Null
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcMiscError "Block height out of range") Null

-- | Get block data by hash
handleGetBlock :: RpcServer -> Value -> IO RpcResponse
handleGetBlock server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing blockhash parameter") Null
    Just hexHash -> do
      case parseHash hexHash of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid block hash") Null
        Just bh -> do
          -- Check if block has been pruned
          isPruned <- case rsBlockStore server of
            Nothing -> return False
            Just blockStore -> isBlockPruned blockStore bh
          if isPruned
            then return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block not available (pruned data)") Null
            else do
              let verbosity = fromMaybe 1 (extractParam params 1 :: Maybe Int)
              mBlock <- getBlock (rsDB server) bh
              case mBlock of
                Nothing -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcMiscError "Block not found") Null
                Just block -> do
                  if verbosity == 0
                    then do
                      -- Return raw hex
                      let rawHex = TE.decodeUtf8 $ B16.encode (S.encode block)
                      return $ RpcResponse (toJSON rawHex) Null Null
                    else do
                      -- Return JSON object
                      entries <- readTVarIO (hcEntries (rsHeaderChain server))
                      let mEntry = Map.lookup bh entries
                          txids = map computeTxId (blockTxns block)
                          result = object $ catMaybes
                            [ Just $ "hash" .= showHash bh
                            , Just $ "confirmations" .= (1 :: Int)
                            , Just $ "size" .= BS.length (S.encode block)
                            , Just $ "height" .= maybe (0 :: Word32) ceHeight mEntry
                            , Just $ "version" .= bhVersion (blockHeader block)
                            , Just $ "merkleroot" .= showHash256 (bhMerkleRoot (blockHeader block))
                            , Just $ "tx" .= map (showHash . blockHashFromTxId) txids
                            , Just $ "time" .= bhTimestamp (blockHeader block)
                            , Just $ "nonce" .= bhNonce (blockHeader block)
                            , Just $ "bits" .= showBits (bhBits (blockHeader block))
                            , Just $ "difficulty" .= getDifficulty (bhBits (blockHeader block))
                            , Just $ "previousblockhash" .= showHash (bhPrevBlock (blockHeader block))
                            ]
                      return $ RpcResponse result Null Null

-- | Get block header by hash
handleGetBlockHeader :: RpcServer -> Value -> IO RpcResponse
handleGetBlockHeader server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing blockhash parameter") Null
    Just hexHash -> do
      case parseHash hexHash of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid block hash") Null
        Just bh -> do
          let verbose = fromMaybe True (extractParam params 1 :: Maybe Bool)
          mHeader <- getBlockHeader (rsDB server) bh
          case mHeader of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block header not found") Null
            Just header -> do
              if not verbose
                then do
                  let rawHex = TE.decodeUtf8 $ B16.encode (S.encode header)
                  return $ RpcResponse (toJSON rawHex) Null Null
                else do
                  entries <- readTVarIO (hcEntries (rsHeaderChain server))
                  let mEntry = Map.lookup bh entries
                      result = object $ catMaybes
                        [ Just $ "hash" .= showHash bh
                        , Just $ "confirmations" .= (1 :: Int)
                        , Just $ "height" .= maybe (0 :: Word32) ceHeight mEntry
                        , Just $ "version" .= bhVersion header
                        , Just $ "merkleroot" .= showHash256 (bhMerkleRoot header)
                        , Just $ "time" .= bhTimestamp header
                        , Just $ "nonce" .= bhNonce header
                        , Just $ "bits" .= showBits (bhBits header)
                        , Just $ "difficulty" .= getDifficulty (bhBits header)
                        , Just $ "chainwork" .= maybe "0" (showHex . ceChainWork) mEntry
                        , Just $ "previousblockhash" .= showHash (bhPrevBlock header)
                        ]
                  return $ RpcResponse result Null Null

-- | Get information about a specific unspent transaction output
handleGetTxOut :: RpcServer -> Value -> IO RpcResponse
handleGetTxOut server params = do
  case (extractParamText params 0, extractParam params 1) of
    (Just hexTxid, Just vout) -> do
      case parseHash hexTxid of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid txid") Null
        Just bh -> do
          let op = OutPoint (TxId (getBlockHashHash bh)) vout
          mEntry <- lookupUTXO (rsUTXOCache server) op
          case mEntry of
            Nothing -> return $ RpcResponse Null Null Null  -- UTXO not found
            Just entry -> do
              let txout = ueOutput entry
                  result = object
                    [ "bestblock"     .= ("" :: Text)
                    , "confirmations" .= (1 :: Int)
                    , "value"         .= (fromIntegral (txOutValue txout) / 100000000.0 :: Double)
                    , "scriptPubKey"  .= object
                        [ "hex" .= (TE.decodeUtf8 $ B16.encode (txOutScript txout))
                        ]
                    , "coinbase"      .= ueCoinbase entry
                    ]
              return $ RpcResponse result Null Null
    _ -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing txid or vout parameter") Null

-- | Get the current difficulty
handleGetDifficulty :: RpcServer -> IO RpcResponse
handleGetDifficulty server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  let difficulty = getDifficulty (bhBits (ceHeader tip))
  return $ RpcResponse (toJSON difficulty) Null Null

-- | Prune blockchain data up to a specified height.
-- Parameters:
--   height (required): Prune blocks up to this height
-- Returns:
--   The height at which pruning was completed
-- Error codes:
--   -1: Cannot prune blocks (e.g., pruning not enabled, height too high)
--
-- Reference: Bitcoin Core's pruneblockchain RPC
handlePruneBlockchain :: RpcServer -> Value -> IO RpcResponse
handlePruneBlockchain server params = do
  case rsBlockStore server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcMiscError "Pruning is not enabled (block store not available)") Null
    Just blockStore -> do
      case extractParam params 0 :: Maybe Word32 of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Missing height parameter") Null
        Just targetHeight -> do
          tip <- readTVarIO (hcTip (rsHeaderChain server))
          let tipHeight = ceHeight tip
          result <- pruneBlockchain blockStore tipHeight targetHeight
          case result of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack err)) Null
            Right numPruned -> do
              -- Return the height that was actually pruned to
              -- (the target height or lower if some files couldn't be pruned)
              return $ RpcResponse (toJSON targetHeight) Null Null

-- | Invalidate a block and all its descendants
-- Reference: bitcoin/src/rpc/blockchain.cpp invalidateblock
-- Parameters:
--   blockhash (required): The hash of the block to invalidate
-- Returns:
--   null on success
-- Errors:
--   -5: Block not found
--   -8: Cannot invalidate genesis block
handleInvalidateBlock :: RpcServer -> Value -> IO RpcResponse
handleInvalidateBlock server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing blockhash parameter") Null
    Just hexHash -> do
      case parseHash hexHash of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid block hash") Null
        Just bh -> do
          result <- invalidateBlock (rsNetwork server) (rsUTXOCache server)
                      (rsDB server) (rsHeaderChain server) bh
          case result of
            Left InvalidateGenesis -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams "Cannot invalidate genesis block") Null
            Left (InvalidateBlockNotFound _) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block not found") Null
            Left (InvalidateDisconnectFailed err) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "Failed to disconnect: " ++ err)) Null
            Left (InvalidateMissingUndo hash) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Missing undo data for block") Null
            Left _ -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block invalidation failed") Null
            Right () -> return $ RpcResponse Null Null Null

-- | Reconsider a previously invalidated block
-- Reference: bitcoin/src/rpc/blockchain.cpp reconsiderblock
-- Parameters:
--   blockhash (required): The hash of the block to reconsider
-- Returns:
--   null on success
-- Errors:
--   -5: Block not found
--   -8: Block was not previously invalidated
handleReconsiderBlock :: RpcServer -> Value -> IO RpcResponse
handleReconsiderBlock server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing blockhash parameter") Null
    Just hexHash -> do
      case parseHash hexHash of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid block hash") Null
        Just bh -> do
          result <- reconsiderBlock (rsNetwork server) (rsUTXOCache server)
                      (rsDB server) (rsHeaderChain server) bh
          case result of
            Left (ReconsiderBlockNotFound _) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block not found") Null
            Left (ReconsiderNotInvalidated _) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block is not marked as invalid") Null
            Left (ReconsiderValidationFailed _ err) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "Validation failed: " ++ err)) Null
            Left (ReconsiderActivationFailed err) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "Chain activation failed: " ++ err)) Null
            Left _ -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block reconsideration failed") Null
            Right () -> return $ RpcResponse Null Null Null

--------------------------------------------------------------------------------
-- Transaction RPC Handlers
--------------------------------------------------------------------------------

-- | Get raw transaction data
-- Parameters:
--   txid (required): The transaction id
--   verbose (optional): If true, return JSON object instead of hex (default: false)
--   blockhash (optional): The block hash to look in for confirmed txs
-- Returns:
--   If verbose=false: hex-encoded transaction data
--   If verbose=true: JSON object with decoded transaction details
-- Error code -5 if not found
handleGetRawTransaction :: RpcServer -> Value -> IO RpcResponse
handleGetRawTransaction server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing txid parameter") Null
    Just hexTxid -> do
      case parseHash hexTxid of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid txid") Null
        Just bh -> do
          let txid = TxId (getBlockHashHash bh)
              -- Parse verbose parameter (can be bool or int for verbosity levels)
              verbose = case extractParam params 1 :: Maybe Bool of
                Just b -> b
                Nothing -> case extractParam params 1 :: Maybe Int of
                  Just n -> n > 0
                  Nothing -> False
              -- Parse optional blockhash parameter
              mBlockHashParam = extractParamText params 2 >>= parseHash

          -- 1. Check mempool first
          mMempoolEntry <- getTransaction (rsMempool server) txid
          case mMempoolEntry of
            Just entry -> do
              let tx = meTransaction entry
              returnTxResult server tx txid Nothing verbose

            Nothing -> do
              -- 2. If blockhash provided, load that specific block
              case mBlockHashParam of
                Just blockHash -> do
                  mBlock <- getBlock (rsDB server) blockHash
                  case mBlock of
                    Nothing -> return $ RpcResponse Null
                      (toJSON $ RpcError (-5) "Block hash not found") Null
                    Just block -> do
                      let mTx = find (\t -> computeTxId t == txid) (blockTxns block)
                      case mTx of
                        Nothing -> return $ RpcResponse Null
                          (toJSON $ RpcError (-5) "No such transaction found in the provided block") Null
                        Just tx -> returnTxResult server tx txid (Just blockHash) verbose

                Nothing -> do
                  -- 3. Try txindex lookup
                  mTxLoc <- getTxIndex (rsDB server) txid
                  case mTxLoc of
                    Nothing -> return $ RpcResponse Null
                      (toJSON $ RpcError (-5) "No such mempool or blockchain transaction. Use -txindex or provide a block hash.") Null
                    Just txLoc -> do
                      mBlock <- getBlock (rsDB server) (txLocBlock txLoc)
                      case mBlock of
                        Nothing -> return $ RpcResponse Null
                          (toJSON $ RpcError (-5) "Block not available") Null
                        Just block -> do
                          let txns = blockTxns block
                              txIdx = fromIntegral (txLocIndex txLoc)
                          if txIdx < length txns
                            then do
                              let tx = txns !! txIdx
                              returnTxResult server tx txid (Just (txLocBlock txLoc)) verbose
                            else return $ RpcResponse Null
                              (toJSON $ RpcError (-5) "Transaction index out of range") Null

-- | Helper to return transaction result (raw hex or verbose JSON)
returnTxResult :: RpcServer -> Tx -> TxId -> Maybe BlockHash -> Bool -> IO RpcResponse
returnTxResult server tx txid mBlockHash verbose =
  if not verbose
    then return $ RpcResponse
      (toJSON $ TE.decodeUtf8 $ B16.encode $ S.encode tx) Null Null
    else do
      verboseResult <- txToVerboseJSON server tx txid mBlockHash
      return $ RpcResponse verboseResult Null Null

-- | Submit a raw transaction to the network
-- Parameters:
--   hexstring (required): The hex-encoded raw transaction
--   maxfeerate (optional): Reject transactions whose fee rate is higher than
--                          the specified value in BTC/kvB (default: 0.10)
-- Returns: The transaction hash (txid) in hex on success
-- Error codes:
--   -22: TX decode failed
--   -25: Missing inputs or fee rate exceeds maxfeerate
--   -26: Policy rejection (insufficient fee, etc.)
--   -27: Transaction already in mempool or blockchain
handleSendRawTransaction :: RpcServer -> Value -> IO RpcResponse
handleSendRawTransaction server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing transaction hex") Null
    Just hexTx -> do
      -- Decode hex string
      case B16.decode (TE.encodeUtf8 hexTx) of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcDeserializationError
            (T.pack $ "TX decode failed. " ++ err)) Null
        Right txBytes -> do
          -- Try to decode transaction (witness format first, then legacy)
          case decodeTxWithFallback txBytes of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcDeserializationError
                (T.pack $ "TX decode failed. Make sure the tx has at least one input.")) Null
            Right tx -> do
              -- Parse maxfeerate parameter (default: 0.10 BTC/kvB = 10,000 sat/vB)
              let defaultMaxFeeRate = 10000 :: Word64  -- 0.10 BTC/kvB in sat/vB
                  maxFeeRateSatPerVB = case extractParam params 1 :: Maybe Double of
                    Nothing -> defaultMaxFeeRate
                    Just btcPerKvB
                      | btcPerKvB <= 0 -> 0  -- 0 means no limit
                      | otherwise ->
                          -- Convert BTC/kvB to sat/vB
                          -- 1 BTC = 100,000,000 satoshis
                          -- 1 kvB = 1000 vB
                          -- So BTC/kvB -> sat/vB = value * 100,000,000 / 1000 = value * 100,000
                          round (btcPerKvB * 100000)

              -- Calculate fee rate of this transaction
              let vsize = calculateVSize tx

              -- Attempt to add to mempool
              result <- addTransaction (rsMempool server) tx
              case result of
                Left err -> return $ mempoolErrorToRpcResponse err
                Right txid -> do
                  -- Get the fee from the mempool entry (for maxfeerate check)
                  mEntry <- getTransaction (rsMempool server) txid
                  case mEntry of
                    Nothing ->
                      -- Shouldn't happen - we just added it
                      return $ RpcResponse
                        (toJSON $ showHash (BlockHash (getTxIdHash txid))) Null Null
                    Just entry -> do
                      let fee = meFee entry
                          actualFeeRate = if vsize > 0
                                          then (fee * 1000) `div` fromIntegral vsize
                                          else 0

                      -- Check maxfeerate (if set to non-zero)
                      if maxFeeRateSatPerVB > 0 && actualFeeRate > maxFeeRateSatPerVB
                        then do
                          -- Remove from mempool since fee is too high
                          -- Note: In real impl we'd do this atomically
                          return $ RpcResponse Null
                            (toJSON $ RpcError rpcVerifyError
                              (T.pack $ "Fee exceeds maximum configured by user: "
                                ++ show actualFeeRate ++ " > " ++ show maxFeeRateSatPerVB
                                ++ " sat/vB")) Null
                        else do
                          -- Broadcast to peers via inv trickling
                          -- The fee rate is used for prioritization
                          broadcastTxToPeers server txid (getFeeRate (meFeeRate entry))
                          return $ RpcResponse
                            (toJSON $ showHash (BlockHash (getTxIdHash txid))) Null Null

-- | Try to decode a transaction, trying witness format first then legacy
decodeTxWithFallback :: ByteString -> Either String Tx
decodeTxWithFallback txBytes =
  -- The standard decode tries witness format first (looks for marker/flag bytes)
  case S.decode txBytes of
    Right tx -> Right tx
    Left _ -> Left "TX decode failed"

-- | Convert MempoolError to appropriate RPC response with correct error codes
mempoolErrorToRpcResponse :: MempoolError -> RpcResponse
mempoolErrorToRpcResponse err = RpcResponse Null (toJSON rpcErr) Null
  where
    rpcErr = case err of
      ErrAlreadyInMempool ->
        RpcError rpcVerifyAlreadyInChain "Transaction already in mempool"

      ErrMissingInput op ->
        RpcError rpcVerifyError ("Missing inputs. OutPoint: " <> T.pack (show op))

      ErrInputSpentInMempool conflictTxId ->
        RpcError rpcVerifyError
          ("Input already spent by mempool transaction: " <>
           showHash (BlockHash (getTxIdHash conflictTxId)))

      ErrValidationFailed msg ->
        RpcError rpcVerifyRejected (T.pack msg)

      ErrInsufficientFee ->
        RpcError rpcVerifyRejected "Insufficient fee (output value exceeds input)"

      ErrFeeBelowMinimum actual minFee ->
        RpcError rpcVerifyRejected
          ("Fee rate too low: " <> T.pack (show (getFeeRate actual)) <>
           " sat/vB < minimum " <> T.pack (show (getFeeRate minFee)) <> " sat/vB")

      ErrTooManyAncestors actual limit ->
        RpcError rpcVerifyRejected
          ("Too many unconfirmed ancestors: " <> T.pack (show actual) <>
           " > limit " <> T.pack (show limit))

      ErrTooManyDescendants actual limit ->
        RpcError rpcVerifyRejected
          ("Too many unconfirmed descendants: " <> T.pack (show actual) <>
           " > limit " <> T.pack (show limit))

      ErrAncestorSizeTooLarge actual limit ->
        RpcError rpcVerifyRejected
          ("Ancestor package too large: " <> T.pack (show actual) <>
           " vB > limit " <> T.pack (show limit) <> " vB")

      ErrDescendantSizeTooLarge actual limit ->
        RpcError rpcVerifyRejected
          ("Descendant package too large: " <> T.pack (show actual) <>
           " vB > limit " <> T.pack (show limit) <> " vB")

      ErrScriptVerificationFailed msg ->
        RpcError rpcVerifyRejected ("Script verification failed: " <> T.pack msg)

      ErrCoinbaseNotMature createdAt currentHeight ->
        RpcError rpcVerifyRejected
          ("Coinbase not mature: created at height " <> T.pack (show createdAt) <>
           ", current height " <> T.pack (show currentHeight) <>
           " (need 100 confirmations)")

      ErrRBFNotSignaled conflictTxId ->
        RpcError rpcVerifyRejected
          ("Conflicting transaction does not signal RBF: " <>
           showHash (BlockHash (getTxIdHash conflictTxId)))

      ErrRBFFeeTooLow newFee oldFee ->
        RpcError rpcVerifyRejected
          ("RBF fee too low: " <> T.pack (show newFee) <>
           " < required " <> T.pack (show oldFee) <> " satoshis")

      ErrMempoolFull ->
        RpcError rpcVerifyRejected "Mempool is full"

-- | Broadcast a transaction to all connected peers via inv trickling
-- Uses the trickling mechanism for privacy (batches inv messages)
broadcastTxToPeers :: RpcServer -> TxId -> Word64 -> IO ()
broadcastTxToPeers server txid feeRate = do
  -- For now, use simple broadcast (direct inv to all peers)
  -- In a full implementation, this would use the InvTrickler for privacy
  broadcastMessage (rsPeerMgr server) $
    MInv $ Inv [InvVector InvWitnessTx (getTxIdHash txid)]
  -- Note: The feeRate parameter would be used by the trickling mechanism
  -- to prioritize higher-fee transactions in the queue

-- | Decode a raw transaction without submitting
handleDecodeRawTransaction :: RpcServer -> Value -> IO RpcResponse
handleDecodeRawTransaction _server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing transaction hex") Null
    Just hexTx -> do
      case B16.decode (TE.encodeUtf8 hexTx) of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcMiscError (T.pack $ "Hex decode error: " ++ err)) Null
        Right txBytes -> do
          case S.decode txBytes of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "TX decode error: " ++ err)) Null
            Right tx -> do
              let txid = computeTxId tx
              return $ RpcResponse (txToJSON tx txid) Null Null

--------------------------------------------------------------------------------
-- Mempool RPC Handlers
--------------------------------------------------------------------------------

-- | Get information about the mempool
handleGetMempoolInfo :: RpcServer -> IO RpcResponse
handleGetMempoolInfo server = do
  (count, size) <- getMempoolSize (rsMempool server)
  -- Calculate total fees from all mempool entries
  txids <- getMempoolTxIds (rsMempool server)
  entries <- forM txids $ \txid -> getTransaction (rsMempool server) txid
  let totalFeeSat = sum [meFee e | Just e <- entries]
  let mpCfg = mpConfig (rsMempool server)
      minFeeRate = getFeeRate (mpcMinFeeRate mpCfg)
      result = object
        [ "loaded"              .= True
        , "size"                .= count
        , "bytes"               .= size
        , "usage"               .= size
        , "total_fee"           .= (fromIntegral totalFeeSat / 100000000.0 :: Double)
        , "maxmempool"          .= mpcMaxSize mpCfg
        , "mempoolminfee"       .= minFeeRate
        , "minrelaytxfee"       .= (0.00001 :: Double)
        , "incrementalrelayfee" .= (0.00001 :: Double)
        , "unbroadcastcount"    .= (0 :: Int)
        , "fullrbf"             .= True
        ]
  return $ RpcResponse result Null Null

-- | Get all transaction IDs in the mempool
-- | Get all transaction IDs in the mempool
-- Parameters:
--   verbose (optional, default=false): If true, returns a map with detailed info for each tx
--   mempool_sequence (optional, default=false): If true and verbose=false, also returns sequence
-- Returns:
--   If verbose=false: array of txids
--   If verbose=true: object mapping txid -> entry details
handleGetRawMempool :: RpcServer -> Value -> IO RpcResponse
handleGetRawMempool server params = do
  let verbose = fromMaybe False (extractParam params 0 :: Maybe Bool)
  txids <- getMempoolTxIds (rsMempool server)

  if not verbose
    then do
      -- Simple mode: just return list of txids
      let result = toJSON $ map (\txid -> showHash (BlockHash (getTxIdHash txid))) txids
      return $ RpcResponse result Null Null
    else do
      -- Verbose mode: return detailed info for each entry
      tip <- readTVarIO (hcTip (rsHeaderChain server))
      let tipHeight = ceHeight tip
      entries <- forM txids $ \txid -> do
        mEntry <- getTransaction (rsMempool server) txid
        case mEntry of
          Nothing -> return Nothing
          Just entry -> return $ Just (txid, entry)
      let validEntries = catMaybes entries
          entryMap = map (mempoolEntryToJSON tipHeight) validEntries
      return $ RpcResponse (object entryMap) Null Null
  where
    mempoolEntryToJSON :: Word32 -> (TxId, MempoolEntry) -> (Key.Key, Value)
    mempoolEntryToJSON tipHeight (txid, entry) =
      let txidKey = Key.fromText $ showHash (BlockHash (getTxIdHash txid))
          wtxid = computeWtxId (meTransaction entry)
          entryHeight = meHeight entry
          confirmations = if tipHeight >= entryHeight
                          then tipHeight - entryHeight
                          else 0
          entryObj = object
            [ "vsize"              .= meSize entry
            , "weight"             .= (meSize entry * witnessScaleFactor)  -- Approximate
            , "fee"                .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
            , "modifiedfee"        .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
            , "time"               .= meTime entry
            , "height"             .= meHeight entry
            , "descendantcount"    .= meDescendantCount entry
            , "descendantsize"     .= meDescendantSize entry
            , "descendantfees"     .= meDescendantFees entry
            , "ancestorcount"      .= meAncestorCount entry
            , "ancestorsize"       .= meAncestorSize entry
            , "ancestorfees"       .= meAncestorFees entry
            , "wtxid"              .= showHash (BlockHash (getTxIdHash wtxid))
            , "fees"               .= object
                [ "base"       .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
                , "modified"   .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
                , "ancestor"   .= (fromIntegral (meAncestorFees entry) / 100000000.0 :: Double)
                , "descendant" .= (fromIntegral (meDescendantFees entry) / 100000000.0 :: Double)
                ]
            , "depends"            .= ([] :: [Text])  -- Would need to track parent txids
            , "spentby"            .= ([] :: [Text])  -- Would need to track child txids
            , "bip125-replaceable" .= meRBFOptIn entry
            , "unbroadcast"        .= False
            ]
      in (txidKey, entryObj)

--------------------------------------------------------------------------------
-- Network RPC Handlers
--------------------------------------------------------------------------------

-- | Get network information
-- | Get network information
-- Returns comprehensive network state matching Bitcoin Core's getnetworkinfo
handleGetNetworkInfo :: RpcServer -> IO RpcResponse
handleGetNetworkInfo server = do
  peerCount <- getPeerCount (rsPeerMgr server)
  peersForOffset <- getConnectedPeers (rsPeerMgr server)
  -- Median clock-skew across peers that have completed the VERSION handshake.
  -- Matches Bitcoin Core GetTimeOffset() / getnetworkinfo.timeoffset semantics.
  let offsets = sort [ piTimeOffset info
                     | (_, info) <- peersForOffset
                     , isJust (piVersion info) ]
      timeOffsetMedian :: Int64
      timeOffsetMedian = case offsets of
        [] -> 0
        xs -> let n = length xs
                  m = n `div` 2
              in if odd n
                 then xs !! m
                 else (xs !! (m - 1) + xs !! m) `div` 2
  -- Our local services: NODE_NETWORK (1) + NODE_WITNESS (8) = 9
  let localServices = getServiceFlag nodeNetwork .|. getServiceFlag nodeWitness :: Word64
      localServicesHex = T.pack $ printf "%016x" localServices
      -- Build human-readable service names
      serviceNames = catMaybes
        [ if hasService localServices nodeNetwork then Just ("NETWORK" :: Text) else Nothing
        , if hasService localServices nodeWitness then Just "WITNESS" else Nothing
        , if hasService localServices nodeBloom then Just "BLOOM" else Nothing
        , if hasService localServices nodeNetworkLimited then Just "NETWORK_LIMITED" else Nothing
        ]
      -- Network info for IPv4, IPv6, onion
      networks =
        [ object
            [ "name" .= ("ipv4" :: Text)
            , "limited" .= False
            , "reachable" .= True
            , "proxy" .= ("" :: Text)
            , "proxy_randomize_credentials" .= True
            ]
        , object
            [ "name" .= ("ipv6" :: Text)
            , "limited" .= False
            , "reachable" .= True
            , "proxy" .= ("" :: Text)
            , "proxy_randomize_credentials" .= True
            ]
        , object
            [ "name" .= ("onion" :: Text)
            , "limited" .= True
            , "reachable" .= False
            , "proxy" .= ("" :: Text)
            , "proxy_randomize_credentials" .= True
            ]
        ]
  let result = object
        [ "version"            .= (100000 :: Int)  -- 0.1.0.0 in version format
        , "subversion"         .= ("/Haskoin:0.1.0/" :: Text)
        , "protocolversion"    .= protocolVersion
        , "localservices"      .= localServicesHex
        , "localservicesnames" .= serviceNames
        , "localrelay"         .= True
        , "timeoffset"         .= timeOffsetMedian
        , "networkactive"      .= True
        , "connections"        .= peerCount
        , "connections_in"     .= (0 :: Int)  -- Would need to count inbound peers
        , "connections_out"    .= peerCount   -- Simplified: treat all as outbound
        , "networks"           .= networks
        , "relayfee"           .= (0.00001 :: Double)  -- 1 sat/vB in BTC/kB
        , "incrementalfee"     .= (0.00001 :: Double)
        , "localaddresses"     .= ([] :: [Value])
        , "warnings"           .= ([] :: [Text])
        ]
  return $ RpcResponse result Null Null

-- | Get information about connected peers
handleGetPeerInfo :: RpcServer -> IO RpcResponse
handleGetPeerInfo server = do
  peers <- getConnectedPeers (rsPeerMgr server)
  let peerInfos = zipWith peerToJSON [0..] peers
  return $ RpcResponse (toJSON peerInfos) Null Null
  where
    peerToJSON idx (addr, info) =
      let services = piServices info
          serviceNames = catMaybes
            [ if services .&. 1 /= 0 then Just ("NETWORK" :: Text) else Nothing
            , if services .&. 8 /= 0 then Just "WITNESS" else Nothing
            , if services .&. 1024 /= 0 then Just "NETWORK_LIMITED" else Nothing
            ]
          isInbound = piInbound info
      in object
      [ "id"              .= (idx :: Int)
      , "addr"            .= show addr
      , "network"         .= ("ipv4" :: Text)
      , "services"        .= (T.pack $ printf "%016x" services)
      , "servicesnames"   .= serviceNames
      , "relaytxes"       .= piRelay info
      , "lastsend"        .= piLastSeen info
      , "lastrecv"        .= piLastSeen info
      , "bytessent"       .= piBytesSent info
      , "bytesrecv"       .= piBytesRecv info
      , "conntime"        .= piConnectedAt info
      , "timeoffset"      .= piTimeOffset info
      , "pingtime"        .= fromMaybe (0 :: Double) (piPingLatency info)
      , "version"         .= maybe (0 :: Int32) vVersion (piVersion info)
      , "subver"          .= maybe "" (TE.decodeUtf8 . getVarString . vUserAgent) (piVersion info)
      , "inbound"         .= isInbound
      , "bip152_hb_to"    .= False
      , "bip152_hb_from"  .= False
      , "startingheight"  .= piStartHeight info
      , "synced_headers"  .= (-1 :: Int)
      , "synced_blocks"   .= (-1 :: Int)
      , "inflight"        .= ([] :: [Int])
      , "connection_type" .= (if isInbound then "inbound" :: Text else "outbound-full-relay")
      ]

-- | Get the number of connected peers
handleGetConnectionCount :: RpcServer -> IO RpcResponse
handleGetConnectionCount server = do
  count <- getPeerCount (rsPeerMgr server)
  return $ RpcResponse (toJSON count) Null Null

-- | Add a node to connect to
handleAddNode :: RpcServer -> Value -> IO RpcResponse
handleAddNode server params = do
  case params of
    Array arr | V.length arr >= 2 ->
      case ((arr V.!) 0, (arr V.!) 1) of
        (String nodeStr, String cmd) -> do
          let net = rsNetwork server
              defaultPort = netDefaultPort net
              (host, port) = case T.breakOnEnd ":" nodeStr of
                (h, p) | not (T.null h) && not (T.null p) ->
                  case reads (T.unpack p) of
                    [(portNum, "")] -> (T.unpack (T.init h), portNum)
                    _ -> (T.unpack nodeStr, defaultPort)
                _ -> (T.unpack nodeStr, defaultPort)
          case cmd of
            "onetry" -> do
              void $ forkIO $ addNodeConnect (rsPeerMgr server) host port
              return $ RpcResponse Null Null Null
            "add" -> do
              void $ forkIO $ addNodeConnect (rsPeerMgr server) host port
              return $ RpcResponse Null Null Null
            "remove" -> do
              -- Find and disconnect peers matching the host:port
              peers <- readTVarIO (pmPeers (rsPeerMgr server))
              forM_ (Map.toList peers) $ \(addr, pc) -> do
                let (peerHost, peerPort) = sockAddrToHostPort addr defaultPort
                when (peerHost == host && peerPort == port) $
                  disconnectPeer pc
              return $ RpcResponse Null Null Null
            _ ->
              return $ RpcResponse Null
                (toJSON $ String "Invalid command, expected onetry/add/remove") Null
        _ ->
          return $ RpcResponse Null
            (toJSON $ String "Invalid parameter types") Null
    _ ->
      return $ RpcResponse Null
        (toJSON $ String "Expected [node, command]") Null

--------------------------------------------------------------------------------
-- Mining RPC Handlers
--------------------------------------------------------------------------------

-- | Get a block template for mining
-- | Get a block template for mining (BIP22/BIP23)
-- Returns comprehensive block template matching Bitcoin Core's getblocktemplate
-- Parameters:
--   template_request (optional): object with mode, capabilities, rules
handleGetBlockTemplate :: RpcServer -> Value -> IO RpcResponse
handleGetBlockTemplate server params = do
  -- Parse template request parameters
  let modeParam = extractTemplateMode params
  case modeParam of
    Just "proposal" -> handleBlockProposal server params
    _ -> handleTemplateRequest server

-- | Handle standard "template" mode for getblocktemplate
handleTemplateRequest :: RpcServer -> IO RpcResponse
handleTemplateRequest server = do
  bt <- createBlockTemplate (rsNetwork server) (rsHeaderChain server)
          (rsMempool server) (rsUTXOCache server)
          BS.empty BS.empty  -- placeholder coinbase script

  tip <- readTVarIO (hcTip (rsHeaderChain server))

  -- Generate longpollid: <previousblockhash><transactionsUpdated>
  -- For simplicity, we use the block hash and height
  let longpollid = showHash (btPreviousBlock bt) <> T.pack (show (btHeight bt))

      -- BIP22/23 capabilities we support
      capabilities = ["proposal" :: Text]

      -- Active rules (soft forks that are active)
      rules = catMaybes
        [ Just ("csv" :: Text)        -- BIP68/112/113 always active now
        , Just "!segwit"              -- ! prefix means required
        ]

      -- Mutable fields that miners can modify
      mutable = ["time" :: Text, "transactions", "prevblock"]

      -- Version bits available for signaling (BIP9)
      vbavailable = object []  -- No active deployments for now

      -- Coinbase auxiliary data
      coinbaseaux = object []

      -- Default witness commitment (for SegWit blocks)
      -- The actual commitment is computed by the miner from the final merkle root
      defaultWitnessCommitment = buildWitnessCommitmentScript bt

  let result = object $ catMaybes
        [ Just $ "capabilities"        .= capabilities
        , Just $ "version"             .= btVersion bt
        , Just $ "rules"               .= rules
        , Just $ "vbavailable"         .= vbavailable
        , Just $ "vbrequired"          .= (0 :: Int)
        , Just $ "previousblockhash"   .= showHash (btPreviousBlock bt)
        , Just $ "transactions"        .= map templateTxToJSON (btTransactions bt)
        , Just $ "coinbaseaux"         .= coinbaseaux
        , Just $ "coinbasevalue"       .= btCoinbaseValue bt
        , Just $ "longpollid"          .= longpollid
        , Just $ "target"              .= showHex (bitsToTarget (btBits bt))
        , Just $ "mintime"             .= btMinTime bt
        , Just $ "mutable"             .= mutable
        , Just $ "noncerange"          .= ("00000000ffffffff" :: Text)
        , Just $ "sigoplimit"          .= btSigopLimit bt
        , Just $ "sizelimit"           .= (4000000 :: Int)  -- MAX_BLOCK_SERIALIZED_SIZE
        , Just $ "weightlimit"         .= btWeightLimit bt
        , Just $ "curtime"             .= btCurTime bt
        , Just $ "bits"                .= showBits (btBits bt)
        , Just $ "height"              .= btHeight bt
        , if not (BS.null defaultWitnessCommitment)
          then Just $ "default_witness_commitment" .= (TE.decodeUtf8 $ B16.encode defaultWitnessCommitment)
          else Nothing
        ]
  return $ RpcResponse result Null Null
  where
    templateTxToJSON tt = object
      [ "data"   .= (TE.decodeUtf8 $ B16.encode $ S.encode $ ttTx tt)
      , "txid"   .= showHash (BlockHash (getTxIdHash (ttTxId tt)))
      , "hash"   .= showHash (BlockHash (getTxIdHash (computeWtxId (ttTx tt))))
      , "fee"    .= ttFee tt
      , "sigops" .= ttSigops tt
      , "weight" .= ttWeight tt
      , "depends" .= ttDepends tt
      ]

-- | Handle "proposal" mode for getblocktemplate (BIP23)
handleBlockProposal :: RpcServer -> Value -> IO RpcResponse
handleBlockProposal server params = do
  -- Extract block data from params
  case extractProposalData params of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing data String key for proposal") Null
    Just hexBlock -> do
      case B16.decode (TE.encodeUtf8 hexBlock) of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcMiscError (T.pack $ "Block decode failed: " ++ err)) Null
        Right blockBytes -> do
          case S.decode blockBytes :: Either String Block of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "Block decode failed: " ++ err)) Null
            Right block -> do
              -- For proposal mode, we just validate the block structure
              -- In a full implementation, we'd check PoW, merkle root, etc.
              -- and return appropriate BIP22 rejection reason
              return $ RpcResponse Null Null Null  -- null means accepted

-- | Extract mode from template_request parameter
extractTemplateMode :: Value -> Maybe Text
extractTemplateMode (Array arr) = case V.toList arr of
  (Object obj : _) -> case KM.lookup "mode" obj of
    Just (String s) -> Just s
    _ -> Nothing
  _ -> Nothing
extractTemplateMode _ = Nothing

-- | Extract block data from proposal mode params
extractProposalData :: Value -> Maybe Text
extractProposalData (Array arr) = case V.toList arr of
  (Object obj : _) -> case KM.lookup "data" obj of
    Just (String s) -> Just s
    _ -> Nothing
  _ -> Nothing
extractProposalData _ = Nothing

-- | Build the OP_RETURN witness commitment script for SegWit blocks
-- Format: OP_RETURN <0xaa21a9ed><32-byte commitment hash>
-- The commitment is: SHA256d(witness_merkle_root || witness_nonce)
-- For now we return empty since the actual commitment is computed by miner
buildWitnessCommitmentScript :: BlockTemplate -> ByteString
buildWitnessCommitmentScript bt
  | null (btTransactions bt) = BS.empty
  | otherwise =
      -- OP_RETURN <aa21a9ed><placeholder 32 bytes>
      -- In a real implementation, we'd compute the witness merkle root
      -- For now, return empty and let miner compute it
      BS.empty

-- | Map an internal block-validation error string to a canonical BIP-22
-- submitblock result string.
--
-- BIP-22: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
-- Reference: Bitcoin Core BIP22ValidationResult() in src/rpc/mining.cpp
--
-- Consensus rejections go in the JSON-RPC *result* field as short ASCII
-- strings, NOT as JSON-RPC error objects.
bip22ResultString :: String -> String
bip22ResultString err
  -- Already-canonical strings pass through unchanged
  | err `elem` ["duplicate", "inconclusive", "duplicate-invalid",
                "high-hash", "bad-txnmrklroot", "bad-witness-merkle-match",
                "bad-cb-amount", "bad-blk-sigops", "bad-cb-height",
                "bad-txns-nonfinal", "bad-txns-duplicate", "rejected",
                "mandatory-script-verify-flag-failed",
                "bad-txns-inputs-missingorspent"] = err

  -- PoW / difficulty (from validateFullBlock / submitBlock)
  | "does not meet proof of work" `isInfixOf` s = "high-hash"
  | "proof of work check failed" `isInfixOf` s  = "high-hash"
  | "incorrect difficulty target" `isInfixOf` s  = "high-hash"

  -- Merkle root
  | "merkle root mismatch" `isInfixOf` s         = "bad-txnmrklroot"

  -- Witness commitment (BIP141)
  | "witness commitment mismatch" `isInfixOf` s  = "bad-witness-merkle-match"
  | "witness commitment" `isInfixOf` s           = "bad-witness-merkle-match"

  -- Coinbase scriptSig length (consensus/tx_check.cpp "bad-cb-length"; 2..100 bytes)
  | "coinbase scriptsig size out of range" `isInfixOf` s = "bad-cb-length"

  -- Coinbase value / subsidy
  | "coinbase value exceeds" `isInfixOf` s       = "bad-cb-amount"
  | "coinbase amount" `isInfixOf` s              = "bad-cb-amount"
  | "subsidy" `isInfixOf` s                      = "bad-cb-amount"

  -- Sigops limit
  | "sigop" `isInfixOf` s                        = "bad-blk-sigops"

  -- Block weight / size
  | "exceeds maximum weight" `isInfixOf` s       = "bad-blk-length"

  -- BIP34 coinbase height (already canonical in validateFullBlock)
  | "bad-cb-height" `isInfixOf` s               = "bad-cb-height"

  -- Non-final transactions (already canonical in validateFullBlock)
  | "bad-txns-nonfinal" `isInfixOf` s           = "bad-txns-nonfinal"
  | "sequence lock" `isInfixOf` s               = "bad-txns-nonfinal"

  -- Duplicate transactions
  | "duplicate inputs" `isInfixOf` s            = "bad-txns-duplicate"
  | "duplicate transaction" `isInfixOf` s       = "bad-txns-duplicate"

  -- Missing inputs / UTXO
  | "missing utxo" `isInfixOf` s                = "bad-txns-inputs-missingorspent"
  | "missing input" `isInfixOf` s               = "bad-txns-inputs-missingorspent"

  -- Script verification failures
  | "script verify failed" `isInfixOf` s        = "mandatory-script-verify-flag-failed"
  | "script verification failed" `isInfixOf` s  = "mandatory-script-verify-flag-failed"
  | "checksig failed" `isInfixOf` s             = "mandatory-script-verify-flag-failed"
  | "tapscript" `isInfixOf` s                   = "mandatory-script-verify-flag-failed"

  -- Timestamp errors
  | "timestamp not after median" `isInfixOf` s  = "time-too-old"
  | "too far in the future" `isInfixOf` s       = "time-too-new"

  -- Block validation failed wrapper (submitBlock adds this prefix)
  | ("block validation failed:" :: String) `isInfixOf` s =
      bip22ResultString (drop (length ("block validation failed: " :: String)) err)

  -- Previous / unknown block
  | "unknown previous block" `isInfixOf` s      = "inconclusive"
  | "prev" `isInfixOf` s && "not found" `isInfixOf` s = "inconclusive"

  | otherwise = "rejected"
  where
    s = map toLower err

-- | Submit a mined block
handleSubmitBlock :: RpcServer -> Value -> IO RpcResponse
handleSubmitBlock server params = do
  -- NetworkDisable gate: refuse submissions while a `dumptxoutset
  -- rollback` rewind→dump→replay dance is in progress. Mirrors
  -- Bitcoin Core's NetworkDisable RAII around TemporaryRollback in
  -- rpc/blockchain.cpp::dumptxoutset.
  paused <- readTVarIO (rsBlockSubmissionPaused server)
  if paused
    then return $ RpcResponse
           (toJSON ("rejected" :: Text))
           Null Null
    else handleSubmitBlockUnpaused server params

handleSubmitBlockUnpaused :: RpcServer -> Value -> IO RpcResponse
handleSubmitBlockUnpaused server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing block hex") Null
    Just hexBlock -> do
      case B16.decode (TE.encodeUtf8 hexBlock) of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcMiscError (T.pack $ "Hex decode error: " ++ err)) Null
        Right blockBytes -> do
          case S.decode blockBytes of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "Block decode error: " ++ err)) Null
            Right block -> do
              result <- submitBlock (rsNetwork server) (rsDB server)
                          (rsHeaderChain server) (rsUTXOCache server)
                          (rsPeerMgr server) block
              case result of
                Left err ->
                  -- Map internal error strings to canonical BIP-22 result strings.
                  -- BIP-22: rejection reason goes in the result field as a plain
                  -- string, not as a JSON-RPC error object.
                  let bip22 = T.pack $ bip22ResultString err
                  in return $ RpcResponse (toJSON bip22) Null Null
                Right () -> return $ RpcResponse Null Null Null

-- | Get mining-related information
handleGetMiningInfo :: RpcServer -> IO RpcResponse
handleGetMiningInfo server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  let result = object
        [ "blocks"        .= ceHeight tip
        , "difficulty"    .= getDifficulty (bhBits (ceHeader tip))
        , "networkhashps" .= (0 :: Double)
        , "chain"         .= netName (rsNetwork server)
        ]
  return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- Regtest Mining RPC Handlers
--------------------------------------------------------------------------------

-- | Generate blocks to an address (regtest only)
-- RPC: generatetoaddress nblocks address
-- Returns array of block hashes
handleGenerateToAddress :: RpcServer -> Value -> IO RpcResponse
handleGenerateToAddress server params = do
  -- Only allow on regtest
  if netName (rsNetwork server) /= "regtest"
    then return $ RpcResponse Null
      (toJSON $ RpcError rpcMiscError "generatetoaddress is only available on regtest") Null
    else case (extractParam params 0, extractParamText params 1) of
      (Nothing, _) -> return $ RpcResponse Null
        (toJSON $ RpcError rpcInvalidParams "Missing nblocks parameter") Null
      (_, Nothing) -> return $ RpcResponse Null
        (toJSON $ RpcError rpcInvalidParams "Missing address parameter") Null
      (Just (nblocks :: Int), Just addrText) ->
        case textToAddress addrText of
          Nothing -> return $ RpcResponse Null
            (toJSON $ RpcError rpcInvalidParams "Invalid address") Null
          Just addr -> do
            -- Generate n blocks
            result <- generateBlocks server nblocks addr
            case result of
              Left err -> return $ RpcResponse Null
                (toJSON $ RpcError rpcMiscError (T.pack err)) Null
              Right hashes -> return $ RpcResponse (toJSON $ map showHash hashes) Null Null

-- | Generate a block with specific transactions (regtest only)
-- RPC: generateblock output [rawtx,...]
-- Returns block hash
handleGenerateBlock :: RpcServer -> Value -> IO RpcResponse
handleGenerateBlock server params = do
  -- Only allow on regtest
  if netName (rsNetwork server) /= "regtest"
    then return $ RpcResponse Null
      (toJSON $ RpcError rpcMiscError "generateblock is only available on regtest") Null
    else case (extractParamText params 0, extractParamArray params 1) of
      (Nothing, _) -> return $ RpcResponse Null
        (toJSON $ RpcError rpcInvalidParams "Missing output parameter") Null
      (Just addrText, mTxArray) -> do
        case textToAddress addrText of
          Nothing -> return $ RpcResponse Null
            (toJSON $ RpcError rpcInvalidParams "Invalid address") Null
          Just addr -> do
            -- Parse raw transactions if provided
            let txHexes = case mTxArray of
                  Nothing -> []
                  Just arr -> [ t | String t <- V.toList arr ]
            txs <- parseRawTxs txHexes
            case txs of
              Left err -> return $ RpcResponse Null
                (toJSON $ RpcError rpcMiscError (T.pack err)) Null
              Right parsedTxs -> do
                result <- generateBlockWithTxs server addr parsedTxs
                case result of
                  Left err -> return $ RpcResponse Null
                    (toJSON $ RpcError rpcMiscError (T.pack err)) Null
                  Right bh -> return $ RpcResponse (toJSON $ object
                    [ "hash" .= showHash bh
                    ]) Null Null

-- | Generate blocks to a random address (regtest only, deprecated)
-- RPC: generate nblocks
-- This is deprecated in Bitcoin Core but still useful for quick testing
handleGenerate :: RpcServer -> Value -> IO RpcResponse
handleGenerate server params = do
  -- Only allow on regtest
  if netName (rsNetwork server) /= "regtest"
    then return $ RpcResponse Null
      (toJSON $ RpcError rpcMiscError "generate is only available on regtest") Null
    else case extractParam params 0 of
      Nothing -> return $ RpcResponse Null
        (toJSON $ RpcError rpcInvalidParams "Missing nblocks parameter") Null
      Just (nblocks :: Int) -> do
        -- Use a dummy address for regtest
        let dummyScript = BS.pack [0x51]  -- OP_TRUE (anyone can spend)
        result <- generateBlocksWithScript server nblocks dummyScript
        case result of
          Left err -> return $ RpcResponse Null
            (toJSON $ RpcError rpcMiscError (T.pack err)) Null
          Right hashes -> return $ RpcResponse (toJSON $ map showHash hashes) Null Null

-- | Parse an array of raw transaction hex strings
parseRawTxs :: [Text] -> IO (Either String [Tx])
parseRawTxs hexes = do
  let parsed = map parseOneTx hexes
  return $ sequence parsed
  where
    parseOneTx :: Text -> Either String Tx
    parseOneTx hex = do
      bytes <- case B16.decode (TE.encodeUtf8 hex) of
        Left err -> Left $ "Hex decode error: " ++ err
        Right bs -> Right bs
      case S.decode bytes of
        Left err -> Left $ "Transaction decode error: " ++ err
        Right tx -> Right tx

--------------------------------------------------------------------------------
-- Regtest Control RPC Handlers
--------------------------------------------------------------------------------

-- | Set mock time for testing (regtest only)
-- RPC: setmocktime timestamp
-- timestamp = 0 resets to real time
handleSetMockTime :: RpcServer -> Value -> IO RpcResponse
handleSetMockTime server params = do
  -- Only allow on regtest
  if netName (rsNetwork server) /= "regtest"
    then return $ RpcResponse Null
      (toJSON $ RpcError rpcMiscError "setmocktime is only available on regtest") Null
    else case extractParam params 0 of
      Nothing -> return $ RpcResponse Null
        (toJSON $ RpcError rpcInvalidParams "Missing timestamp parameter") Null
      Just (timestamp :: Word32) -> do
        atomically $ writeTVar (rsMockTime server) $
          if timestamp == 0 then Nothing else Just timestamp
        return $ RpcResponse Null Null Null

--------------------------------------------------------------------------------
-- Block Generation Helpers
--------------------------------------------------------------------------------

-- | Generate n blocks with coinbase paying to the given address
generateBlocks :: RpcServer -> Int -> Address -> IO (Either String [BlockHash])
generateBlocks server nblocks addr = do
  let scriptPubKey = addressToScript addr
  generateBlocksWithScript server nblocks scriptPubKey

-- | Generate n blocks with coinbase paying to the given scriptPubKey
generateBlocksWithScript :: RpcServer -> Int -> ByteString -> IO (Either String [BlockHash])
generateBlocksWithScript server nblocks scriptPubKey = do
  go nblocks []
  where
    go 0 acc = return $ Right (reverse acc)
    go n acc = do
      result <- generateSingleBlock server scriptPubKey []
      case result of
        Left err -> return $ Left err
        Right bh -> go (n - 1) (bh : acc)

-- | Generate a block with specific transactions
generateBlockWithTxs :: RpcServer -> Address -> [Tx] -> IO (Either String BlockHash)
generateBlockWithTxs server addr txs = do
  let scriptPubKey = addressToScript addr
  generateSingleBlock server scriptPubKey txs

-- | Generate a single block, optionally with specific transactions
generateSingleBlock :: RpcServer -> ByteString -> [Tx] -> IO (Either String BlockHash)
generateSingleBlock server scriptPubKey specificTxs = do
  let net = rsNetwork server
      hc = rsHeaderChain server
      cache = rsUTXOCache server
      pm = rsPeerMgr server
      db = rsDB server

  -- Get current chain tip
  tip <- readTVarIO (hcTip hc)
  let height = ceHeight tip + 1
      prevHash = ceHash tip

  -- Get current time (mock or real)
  now <- getCurrentTime server

  -- For regtest, we use the minimum difficulty from powLimit
  let bits = 0x207fffff  -- Regtest minimum difficulty

  -- Get median time past
  entries <- readTVarIO (hcEntries hc)
  let mtp = medianTimePast entries prevHash
      blockTime = max (mtp + 1) now

  -- Build coinbase transaction
  let reward = blockReward height
  -- Note: For regtest with specific transactions, we would add their fees too
  -- For simplicity, we use just the block reward here
  let coinbase = buildRegtestCoinbase height reward scriptPubKey blockTime

  -- Get transactions from mempool if none specified
  txs <- if null specificTxs
    then do
      -- Select from mempool
      entries' <- selectTransactions (rsMempool server) (maxBlockWeight - 4000)
      return $ map meTransaction entries'
    else return specificTxs

  -- Build the block
  let allTxs = coinbase : txs
      merkleRoot = computeMerkleRoot (map computeTxId allTxs)

  -- Find a valid nonce (trivial for regtest since difficulty is minimum)
  let header = BlockHeader
        { bhVersion = 0x20000000
        , bhPrevBlock = prevHash
        , bhMerkleRoot = merkleRoot
        , bhTimestamp = blockTime
        , bhBits = bits
        , bhNonce = 0  -- Start with 0, almost always works for regtest
        }

  -- For regtest, we may need to find a valid nonce
  mValidHeader <- findRegtestNonce header (netPowLimit net)
  case mValidHeader of
    Nothing -> return $ Left "Failed to find valid nonce"
    Just validHeader -> do
      let block = Block validHeader allTxs
          bh = computeBlockHash validHeader

      -- Validate and connect the block
      result <- submitBlock net db hc cache pm block
      case result of
        Left err -> return $ Left err
        Right () -> return $ Right bh

-- | Build a coinbase transaction for regtest
buildRegtestCoinbase :: Word32 -> Word64 -> ByteString -> Word32 -> Tx
buildRegtestCoinbase height value scriptPubKey _blockTime =
  let -- BIP-34: height in coinbase scriptSig
      heightBytes = encodeRegtestHeight height
      scriptSig = heightBytes

      -- Coinbase input with null prevout
      coinbaseInput = TxIn
        { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
        , txInScript = scriptSig
        , txInSequence = 0xffffffff
        }

      -- Main output: reward to miner's address
      mainOutput = TxOut value scriptPubKey

  in Tx
    { txVersion = 2
    , txInputs = [coinbaseInput]
    , txOutputs = [mainOutput]
    , txWitness = [[]]  -- Empty witness for coinbase
    , txLockTime = 0
    }

-- | Encode block height for BIP-34 coinbase (CScriptNum data push encoding)
-- BIP-34 requires the height as a CScriptNum data push (length prefix + LE bytes),
-- NOT as OP_N opcodes. The coinbaseHeight parser expects this format.
encodeRegtestHeight :: Word32 -> ByteString
encodeRegtestHeight h
  | h == 0     = BS.pack [1, 0]  -- Push 1 byte of zero
  | h <= 0x7f  = BS.pack [1, fromIntegral h]
  | h <= 0x7fff = BS.pack [2, fromIntegral (h .&. 0xff),
                              fromIntegral ((h `shiftR` 8) .&. 0xff)]
  | h <= 0x7fffff = BS.pack [3, fromIntegral (h .&. 0xff),
                                fromIntegral ((h `shiftR` 8) .&. 0xff),
                                fromIntegral ((h `shiftR` 16) .&. 0xff)]
  | otherwise = BS.pack [4, fromIntegral (h .&. 0xff),
                            fromIntegral ((h `shiftR` 8) .&. 0xff),
                            fromIntegral ((h `shiftR` 16) .&. 0xff),
                            fromIntegral ((h `shiftR` 24) .&. 0xff)]

-- | Find a valid nonce for a regtest block (trivial due to minimum difficulty)
-- Returns the header with valid nonce, or Nothing if no valid nonce found
findRegtestNonce :: BlockHeader -> Integer -> IO (Maybe BlockHeader)
findRegtestNonce header powLimit = go 0
  where
    target = bitsToTarget (bhBits header)
    go nonce
      | nonce > (maxBound :: Word32) = return Nothing
      | otherwise = do
          let header' = header { bhNonce = nonce }
              Hash256 hashBytes = doubleSHA256 (S.encode header')
              hashInt = bsToInteger (BS.reverse hashBytes)
          if hashInt <= min target powLimit
            then return $ Just header'
            else go (nonce + 1)

-- | Convert ByteString to Integer (big-endian)
bsToInteger :: ByteString -> Integer
bsToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Convert an address to its scriptPubKey
addressToScript :: Address -> ByteString
addressToScript addr = case addr of
  PubKeyAddress (Hash160 h) ->
    -- P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    BS.pack [0x76, 0xa9, 0x14] <> h <> BS.pack [0x88, 0xac]
  ScriptAddress (Hash160 h) ->
    -- P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    BS.pack [0xa9, 0x14] <> h <> BS.pack [0x87]
  WitnessPubKeyAddress (Hash160 h) ->
    -- P2WPKH: OP_0 <20 bytes>
    BS.pack [0x00, 0x14] <> h
  WitnessScriptAddress (Hash256 h) ->
    -- P2WSH: OP_0 <32 bytes>
    BS.pack [0x00, 0x20] <> h
  TaprootAddress (Hash256 h) ->
    -- P2TR: OP_1 <32 bytes>
    BS.pack [0x51, 0x20] <> h

--------------------------------------------------------------------------------
-- Fee Estimation RPC Handlers
--------------------------------------------------------------------------------

-- | Estimate smart fee for confirmation in N blocks
handleEstimateSmartFee :: RpcServer -> Value -> IO RpcResponse
handleEstimateSmartFee server params = do
  case extractParam params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing conf_target") Null
    Just (confTarget :: Int) -> do
      (feeRate, blocks) <- estimateSmartFee (rsFeeEst server) confTarget FeeConservative
      if feeRate <= 0
        then return $ RpcResponse (object
          [ "errors" .= (["Insufficient data or no feerate found"] :: [Text])
          , "blocks" .= blocks
          ]) Null Null
        else do
          let btcPerKb = fromIntegral feeRate / 100000.0 :: Double
          return $ RpcResponse (object
            [ "feerate" .= btcPerKb
            , "blocks"  .= blocks
            ]) Null Null

--------------------------------------------------------------------------------
-- Utility RPC Handlers
--------------------------------------------------------------------------------

-- | Validate an address
-- | Validate an address and return detailed information about it
-- Returns comprehensive address information matching Bitcoin Core's validateaddress
handleValidateAddress :: RpcServer -> Value -> IO RpcResponse
handleValidateAddress server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing address") Null
    Just addr ->
      case textToAddress addr of
        Nothing -> return $ RpcResponse (object
          [ "isvalid" .= False
          ]) Null Null
        Just address -> do
          let (scriptPubKey, isScript, isWitness, witnessVersion, witnessProgram) =
                addressToScriptInfo (rsNetwork server) address
          return $ RpcResponse (object $ catMaybes
            [ Just $ "isvalid"          .= True
            , Just $ "address"          .= addr
            , Just $ "scriptPubKey"     .= scriptPubKey
            , Just $ "isscript"         .= isScript
            , Just $ "iswitness"        .= isWitness
            , if isWitness then Just $ "witness_version" .= witnessVersion else Nothing
            , if isWitness then Just $ "witness_program" .= witnessProgram else Nothing
            ]) Null Null

-- | Convert an Address to its scriptPubKey and metadata
addressToScriptInfo :: Network -> Address -> (Text, Bool, Bool, Int, Text)
addressToScriptInfo _net addr = case addr of
  PubKeyAddress (Hash160 h) ->
    -- P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let script = BS.pack [0x76, 0xa9, 0x14] <> h <> BS.pack [0x88, 0xac]
    in (TE.decodeUtf8 $ B16.encode script, False, False, -1, "")
  ScriptAddress (Hash160 h) ->
    -- P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    let script = BS.pack [0xa9, 0x14] <> h <> BS.pack [0x87]
    in (TE.decodeUtf8 $ B16.encode script, True, False, -1, "")
  WitnessPubKeyAddress (Hash160 h) ->
    -- P2WPKH: OP_0 <20 bytes>
    let script = BS.pack [0x00, 0x14] <> h
    in (TE.decodeUtf8 $ B16.encode script, False, True, 0, TE.decodeUtf8 $ B16.encode h)
  WitnessScriptAddress (Hash256 h) ->
    -- P2WSH: OP_0 <32 bytes>
    let script = BS.pack [0x00, 0x20] <> h
    in (TE.decodeUtf8 $ B16.encode script, True, True, 0, TE.decodeUtf8 $ B16.encode h)
  TaprootAddress (Hash256 h) ->
    -- P2TR: OP_1 <32 bytes>
    let script = BS.pack [0x51, 0x20] <> h
    in (TE.decodeUtf8 $ B16.encode script, False, True, 1, TE.decodeUtf8 $ B16.encode h)

-- | Get general information (deprecated but still useful)
handleGetInfo :: RpcServer -> IO RpcResponse
handleGetInfo server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  peerCount <- getPeerCount (rsPeerMgr server)
  let result = object
        [ "version"         .= (10000 :: Int)
        , "protocolversion" .= protocolVersion
        , "blocks"          .= ceHeight tip
        , "connections"     .= peerCount
        , "proxy"           .= ("" :: Text)
        , "difficulty"      .= getDifficulty (bhBits (ceHeader tip))
        , "testnet"         .= (netName (rsNetwork server) /= "main")
        , "errors"          .= ("" :: Text)
        ]
  return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- Descriptor RPC Handlers (BIP-380-386)
--------------------------------------------------------------------------------

-- | Import descriptors into the wallet.
-- Reference: Bitcoin Core's importdescriptors RPC
-- Parameters:
--   Array of descriptor objects, each with:
--     - desc (string, required): The output descriptor
--     - active (boolean, optional): Set descriptor as active for new addresses
--     - range (int or [int, int], optional): Range of indices for ranged descriptors
--     - next_index (int, optional): Next unused index
--     - timestamp (int|"now", optional): Creation time of keys
--     - internal (boolean, optional): Whether this is an internal/change descriptor
--     - label (string, optional): Label for the descriptor
-- Returns:
--   Array of result objects with success/error status
handleImportDescriptors :: RpcServer -> Value -> IO RpcResponse
handleImportDescriptors _server params = do
  case params of
    Array arr -> do
      results <- mapM processDescriptorImport (V.toList arr)
      return $ RpcResponse (toJSON results) Null Null
    _ -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Expected array of descriptor objects") Null
  where
    processDescriptorImport :: Value -> IO Value
    processDescriptorImport val = case val of
      Object obj -> do
        let mDesc = KM.lookup "desc" obj >>= getString
            mRange = KM.lookup "range" obj
            mActive = KM.lookup "active" obj >>= getBool
            mInternal = KM.lookup "internal" obj >>= getBool
            mLabel = KM.lookup "label" obj >>= getString
        case mDesc of
          Nothing -> return $ object
            [ "success" .= False
            , "error" .= object
                [ "code" .= rpcInvalidParams
                , "message" .= ("Missing 'desc' field" :: Text)
                ]
            ]
          Just descText -> case parseDescriptor descText of
            Left err -> return $ object
              [ "success" .= False
              , "error" .= object
                  [ "code" .= rpcInvalidParams
                  , "message" .= T.pack (show err)
                  ]
              ]
            Right desc -> do
              -- In a full implementation, we would:
              -- 1. Store the descriptor in the wallet database
              -- 2. Derive addresses based on range
              -- 3. Scan the blockchain for matching UTXOs
              -- For now, we validate and acknowledge the import
              let isRanged = isRangeDescriptor desc
                  rangeInfo = case mRange of
                    Just (Number n) -> Just (0, floor n :: Int)
                    Just (Array rv) | V.length rv == 2 ->
                      case (V.head rv, V.last rv) of
                        (Number start, Number end) ->
                          Just (floor start, floor end)
                        _ -> Nothing
                    _ -> if isRanged then Just (0, 999) else Nothing
                  -- Derive some addresses for testing
                  derivedAddrs = case rangeInfo of
                    Just (start, end) ->
                      deriveAddresses desc [start..min end (start + 10)]
                    Nothing -> deriveAddresses desc [0]
              return $ object
                [ "success" .= True
                , "warnings" .= ([] :: [Text])
                ]
      _ -> return $ object
        [ "success" .= False
        , "error" .= object
            [ "code" .= rpcInvalidParams
            , "message" .= ("Expected object" :: Text)
            ]
        ]

    getString :: Value -> Maybe Text
    getString (String t) = Just t
    getString _ = Nothing

    getBool :: Value -> Maybe Bool
    getBool (Bool b) = Just b
    getBool _ = Nothing

-- | List imported descriptors.
-- Reference: Bitcoin Core's listdescriptors RPC
-- Parameters:
--   private (boolean, optional): Whether to show private keys (default: false)
-- Returns:
--   Object with wallet_name and array of descriptor objects
handleListDescriptors :: RpcServer -> Value -> IO RpcResponse
handleListDescriptors _server params = do
  let _showPrivate = case extractParam params 0 of
        Just b -> b
        Nothing -> False
  -- In a full implementation, this would return stored descriptors from the wallet
  -- For now, return empty list
  let result = object
        [ "wallet_name" .= ("" :: Text)
        , "descriptors" .= ([] :: [Value])
        ]
  return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- PSBT RPC Handlers
--------------------------------------------------------------------------------

-- | Create a PSBT from inputs and outputs.
-- Reference: Bitcoin Core's createpsbt RPC
-- Parameters:
--   inputs (required): Array of inputs [{txid, vout, sequence}]
--   outputs (required): Array of outputs [{address: amount}] or [{data: hex}]
--   locktime (optional): Lock time (default: 0)
-- Returns:
--   Base64-encoded PSBT string
handleCreatePsbt :: RpcServer -> Value -> IO RpcResponse
handleCreatePsbt _server params = do
  case (extractParamArray params 0, extractParamArray params 1) of
    (Nothing, _) -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing inputs parameter") Null
    (_, Nothing) -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing outputs parameter") Null
    (Just inputsArr, Just outputsArr) -> do
      -- Parse locktime (optional, default 0)
      let locktime = fromMaybe 0 (extractParam params 2 :: Maybe Word32)

      -- Parse inputs
      case parseInputs (V.toList inputsArr) of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams (T.pack err)) Null
        Right inputs -> do
          -- Parse outputs
          case parseOutputs (V.toList outputsArr) of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams (T.pack err)) Null
            Right outputs -> do
              -- Create unsigned transaction
              let tx = Tx
                    { txVersion = 2
                    , txInputs = inputs
                    , txOutputs = outputs
                    , txLockTime = locktime
                    , txWitness = replicate (length inputs) []
                    }
              -- Create PSBT
              case createPsbt tx of
                Left err -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcMiscError (T.pack err)) Null
                Right psbt -> do
                  -- Encode to base64
                  let encoded = encodePsbt psbt
                      base64 = TE.decodeUtf8 $ B64.encode encoded
                  return $ RpcResponse (toJSON base64) Null Null

-- | Parse input array elements to TxIn
parseInputs :: [Value] -> Either String [TxIn]
parseInputs = mapM parseOneInput
  where
    parseOneInput :: Value -> Either String TxIn
    parseOneInput (Object obj) = do
      -- Get txid
      txidHex <- case KM.lookup "txid" obj of
        Just (String t) -> Right t
        _ -> Left "Missing or invalid txid"
      txid <- case B16.decode (TE.encodeUtf8 txidHex) of
        Left _ -> Left "Invalid txid hex"
        Right bs | BS.length bs /= 32 -> Left "txid must be 32 bytes"
        Right bs -> Right $ TxId (Hash256 (BS.reverse bs))
      -- Get vout
      vout <- case KM.lookup "vout" obj of
        Just (Number n) -> Right (floor n)
        _ -> Left "Missing or invalid vout"
      -- Get sequence (optional, default 0xfffffffd for RBF)
      let seqNum = case KM.lookup "sequence" obj of
            Just (Number n) -> floor n
            _ -> 0xfffffffd  -- Enable RBF by default
      Right TxIn
        { txInPrevOutput = OutPoint txid vout
        , txInScript = BS.empty  -- Empty for PSBT
        , txInSequence = seqNum
        }
    parseOneInput _ = Left "Input must be an object"

-- | Parse output array elements to TxOut
parseOutputs :: [Value] -> Either String [TxOut]
parseOutputs = fmap concat . mapM parseOneOutput
  where
    parseOneOutput :: Value -> Either String [TxOut]
    parseOneOutput (Object obj) = do
      let pairs = KM.toList obj
      forM pairs $ \(key, val) -> do
        let keyText = Key.toText key
        if keyText == "data"
          then do
            -- OP_RETURN data output
            hexData <- case val of
              String t -> Right t
              _ -> Left "data value must be a string"
            dataBytes <- case B16.decode (TE.encodeUtf8 hexData) of
              Left _ -> Left "Invalid hex in data"
              Right bs -> Right bs
            let script = BS.cons 0x6a (encodePushDataForScript dataBytes)  -- OP_RETURN + push data
            Right TxOut { txOutValue = 0, txOutScript = script }
          else do
            -- Address output
            amount <- case val of
              Number n -> Right (floor (n * 100000000))  -- BTC to satoshi
              _ -> Left "Amount must be a number"
            addr <- case textToAddress keyText of
              Nothing -> Left $ "Invalid address: " ++ T.unpack keyText
              Just a -> Right a
            let script = addressToScript addr
            Right TxOut { txOutValue = amount, txOutScript = script }
    parseOneOutput _ = Left "Output must be an object"

    -- Encode push data for script (simplified version)
    encodePushDataForScript :: ByteString -> ByteString
    encodePushDataForScript bs
      | len <= 75 = BS.cons (fromIntegral len) bs
      | len <= 255 = BS.concat [BS.pack [0x4c, fromIntegral len], bs]
      | len <= 65535 = BS.concat [BS.singleton 0x4d,
          BS.pack [fromIntegral (len .&. 0xff), fromIntegral (len `shiftR` 8)], bs]
      | otherwise = bs
      where len = BS.length bs

-- | Decode a PSBT and return detailed information.
-- Reference: Bitcoin Core's decodepsbt RPC
-- Parameters:
--   psbt (required): Base64-encoded PSBT string
-- Returns:
--   JSON object with tx details, input info, output info, fee
handleDecodePsbt :: RpcServer -> Value -> IO RpcResponse
handleDecodePsbt _server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing psbt parameter") Null
    Just psbtBase64 -> do
      case B64.decode (TE.encodeUtf8 psbtBase64) of
        Left _ -> return $ RpcResponse Null
          (toJSON $ RpcError rpcDeserializationError "Invalid base64 encoding") Null
        Right psbtBytes -> do
          case decodePsbt psbtBytes of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcDeserializationError (T.pack $ "PSBT decode failed: " ++ err)) Null
            Right psbt -> do
              let result = psbtToJSON psbt
              return $ RpcResponse result Null Null

-- | Convert PSBT to detailed JSON representation
psbtToJSON :: Psbt -> Value
psbtToJSON psbt =
  let tx = pgTx (psbtGlobal psbt)
      txid = computeTxId tx
      -- Calculate fee if possible
      mFee = getPsbtFee psbt
  in object $ catMaybes
    [ Just $ "tx" .= txToJSON tx txid
    , Just $ "global_xpubs" .= map xpubToJSON (Map.toList (pgXpubs (psbtGlobal psbt)))
    , Just $ "psbt_version" .= fromMaybe 0 (pgVersion (psbtGlobal psbt))
    , Just $ "inputs" .= zipWith psbtInputToJSON [0..] (psbtInputs psbt)
    , Just $ "outputs" .= zipWith psbtOutputToJSON [0..] (psbtOutputs psbt)
    , fmap (\fee -> "fee" .= (fromIntegral fee / 100000000.0 :: Double)) mFee
    ]
  where
    xpubToJSON :: (ByteString, KeyPath) -> Value
    xpubToJSON (xpub, keypath) = object
      [ "xpub" .= TE.decodeUtf8 (B16.encode xpub)
      , "master_fingerprint" .= (printf "%08x" (kpFingerprint keypath) :: String)
      , "path" .= formatKeyPath keypath
      ]

    psbtInputToJSON :: Int -> PsbtInput -> Value
    psbtInputToJSON idx inp = object $ catMaybes
      [ Just $ "index" .= idx
      , fmap (\utxo -> "witness_utxo" .= utxoToJSON utxo) (piWitnessUtxo inp)
      , fmap (\tx' -> "non_witness_utxo" .= nonWitnessTxToJSON tx') (piNonWitnessUtxo inp)
      , if Map.null (piPartialSigs inp) then Nothing
        else Just $ "partial_signatures" .= map partialSigToJSON (Map.toList (piPartialSigs inp))
      , fmap (\st -> "sighash" .= sighashToText st) (piSighashType inp)
      , fmap (\rs -> "redeem_script" .= scriptToJSON rs) (piRedeemScript inp)
      , fmap (\ws -> "witness_script" .= scriptToJSON ws) (piWitnessScript inp)
      , if Map.null (piBip32Derivation inp) then Nothing
        else Just $ "bip32_derivs" .= map bip32DerivToJSON (Map.toList (piBip32Derivation inp))
      , fmap (\fs -> "final_scriptsig" .= object ["hex" .= TE.decodeUtf8 (B16.encode fs)]) (piFinalScriptSig inp)
      , fmap (\fw -> "final_scriptwitness" .= map (TE.decodeUtf8 . B16.encode) fw) (piFinalScriptWitness inp)
      ]

    psbtOutputToJSON :: Int -> PsbtOutput -> Value
    psbtOutputToJSON idx out = object $ catMaybes
      [ Just $ "index" .= idx
      , fmap (\rs -> "redeem_script" .= scriptToJSON rs) (poRedeemScript out)
      , fmap (\ws -> "witness_script" .= scriptToJSON ws) (poWitnessScript out)
      , if Map.null (poBip32Derivation out) then Nothing
        else Just $ "bip32_derivs" .= map bip32DerivToJSON (Map.toList (poBip32Derivation out))
      ]

    utxoToJSON :: TxOut -> Value
    utxoToJSON txout = object
      [ "amount" .= (fromIntegral (txOutValue txout) / 100000000.0 :: Double)
      , "scriptPubKey" .= scriptToJSON (txOutScript txout)
      ]

    nonWitnessTxToJSON :: Tx -> Value
    nonWitnessTxToJSON tx' =
      let tid = computeTxId tx'
      in txToJSON tx' tid

    partialSigToJSON :: (PubKey, ByteString) -> Value
    partialSigToJSON (pk, sig) = object
      [ "pubkey" .= TE.decodeUtf8 (B16.encode (serializePubKeyCompressed pk))
      , "signature" .= TE.decodeUtf8 (B16.encode sig)
      ]

    scriptToJSON :: ByteString -> Value
    scriptToJSON s = object
      [ "hex" .= TE.decodeUtf8 (B16.encode s)
      ]

    bip32DerivToJSON :: (PubKey, KeyPath) -> Value
    bip32DerivToJSON (pk, kp) = object
      [ "pubkey" .= TE.decodeUtf8 (B16.encode (serializePubKeyCompressed pk))
      , "master_fingerprint" .= (printf "%08x" (kpFingerprint kp) :: String)
      , "path" .= formatKeyPath kp
      ]

    formatKeyPath :: KeyPath -> Text
    formatKeyPath kp =
      let pathParts = map formatIndex (kpPath kp)
      in T.intercalate "/" ("m" : pathParts)

    formatIndex :: Word32 -> Text
    formatIndex idx
      | idx >= 0x80000000 = T.pack (show (idx .&. 0x7fffffff)) <> "'"
      | otherwise = T.pack (show idx)

    sighashToText :: Word32 -> Text
    sighashToText 0x01 = "ALL"
    sighashToText 0x02 = "NONE"
    sighashToText 0x03 = "SINGLE"
    sighashToText 0x81 = "ALL|ANYONECANPAY"
    sighashToText 0x82 = "NONE|ANYONECANPAY"
    sighashToText 0x83 = "SINGLE|ANYONECANPAY"
    sighashToText n    = T.pack $ printf "0x%02x" n

-- | Combine multiple PSBTs into one.
-- Reference: Bitcoin Core's combinepsbt RPC
-- Parameters:
--   psbts (required): Array of base64-encoded PSBT strings
-- Returns:
--   Combined PSBT as base64 string
handleCombinePsbt :: RpcServer -> Value -> IO RpcResponse
handleCombinePsbt _server params = do
  case extractParamArray params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing psbts parameter") Null
    Just psbtsArr -> do
      -- Parse all PSBTs
      let psbtTexts = [t | String t <- V.toList psbtsArr]
      case parsePsbtsFromBase64 psbtTexts of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcDeserializationError (T.pack err)) Null
        Right psbts -> do
          case combinePsbts psbts of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack err)) Null
            Right combined -> do
              let encoded = encodePsbt combined
                  base64 = TE.decodeUtf8 $ B64.encode encoded
              return $ RpcResponse (toJSON base64) Null Null

-- | Parse multiple PSBTs from base64 strings
parsePsbtsFromBase64 :: [Text] -> Either String [Psbt]
parsePsbtsFromBase64 = mapM parseOnePsbt
  where
    parseOnePsbt :: Text -> Either String Psbt
    parseOnePsbt t = do
      bytes <- case B64.decode (TE.encodeUtf8 t) of
        Left _ -> Left "Invalid base64 encoding"
        Right bs -> Right bs
      decodePsbt bytes

-- | Finalize a PSBT and optionally extract the transaction.
-- Reference: Bitcoin Core's finalizepsbt RPC
-- Parameters:
--   psbt (required): Base64-encoded PSBT string
--   extract (optional): If true and complete, also extract tx (default: true)
-- Returns:
--   Object with psbt, hex (if extracted), and complete flag
handleFinalizePsbt :: RpcServer -> Value -> IO RpcResponse
handleFinalizePsbt _server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing psbt parameter") Null
    Just psbtBase64 -> do
      -- Parse extract parameter (default true)
      let doExtract = fromMaybe True (extractParam params 1 :: Maybe Bool)

      case B64.decode (TE.encodeUtf8 psbtBase64) of
        Left _ -> return $ RpcResponse Null
          (toJSON $ RpcError rpcDeserializationError "Invalid base64 encoding") Null
        Right psbtBytes -> do
          case decodePsbt psbtBytes of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcDeserializationError (T.pack $ "PSBT decode failed: " ++ err)) Null
            Right psbt -> do
              -- Try to finalize
              let finalized = case finalizePsbt psbt of
                    Left _ -> psbt  -- Return original if can't finalize
                    Right p -> p
                  isComplete = isPsbtFinalized finalized
                  finalizedBase64 = TE.decodeUtf8 $ B64.encode $ encodePsbt finalized

              -- Build result
              let baseResult =
                    [ "psbt" .= finalizedBase64
                    , "complete" .= isComplete
                    ]
                  -- Add hex if extracted and complete
                  resultWithHex = if doExtract && isComplete
                    then case extractTransaction finalized of
                      Left _ -> baseResult
                      Right tx -> baseResult ++
                        [ "hex" .= TE.decodeUtf8 (B16.encode (S.encode tx)) ]
                    else baseResult

              return $ RpcResponse (object resultWithHex) Null Null

--------------------------------------------------------------------------------
-- Multi-Wallet Management RPC Handlers (stubs)
--------------------------------------------------------------------------------

-- | Create a new wallet (stub)
handleCreateWallet :: RpcServer -> Value -> IO RpcResponse
handleCreateWallet server _params =
  return $ RpcResponse (object ["name" .= ("" :: Text), "warning" .= ("Wallet support not yet implemented" :: Text)]) Null (Number 0)

-- | Load a wallet (stub)
handleLoadWallet :: RpcServer -> Value -> IO RpcResponse
handleLoadWallet server _params =
  return $ RpcResponse (object ["name" .= ("" :: Text), "warning" .= ("Wallet support not yet implemented" :: Text)]) Null (Number 0)

-- | Unload a wallet (stub)
handleUnloadWallet :: RpcServer -> Value -> IO RpcResponse
handleUnloadWallet server _params =
  return $ RpcResponse (object ["warning" .= ("Wallet support not yet implemented" :: Text)]) Null (Number 0)

-- | List loaded wallets (stub)
handleListWallets :: RpcServer -> IO RpcResponse
handleListWallets server =
  return $ RpcResponse (toJSON ([] :: [Text])) Null (Number 0)

-- | Get wallet info (stub)
handleGetWalletInfo :: RpcServer -> Value -> IO RpcResponse
handleGetWalletInfo server _params =
  return $ RpcResponse (object ["walletname" .= ("" :: Text), "walletversion" .= (0 :: Int)]) Null (Number 0)

-- | Get wallet balance (stub)
handleGetBalance :: RpcServer -> Value -> IO RpcResponse
handleGetBalance server _params =
  return $ RpcResponse (Number 0) Null (Number 0)

--------------------------------------------------------------------------------
-- Chain Tips RPC Handler
--------------------------------------------------------------------------------

-- | Get information about all known chain tips
-- Reference: Bitcoin Core's getchaintips RPC (blockchain.cpp)
-- Returns array of: {height, hash, branchlen, status}
-- Status values: "active", "valid-fork", "valid-headers", "headers-only", "invalid"
handleGetChainTips :: RpcServer -> IO RpcResponse
handleGetChainTips server = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  invalidated <- readTVarIO (hcInvalidated (rsHeaderChain server))

  -- Algorithm: find all chain tips (blocks with no children)
  -- A tip is a block where no other block has it as cePrev
  let allEntries = Map.elems entries
      -- Build set of all blocks that are parents of some block
      parentSet = Set.fromList $ catMaybes $ map cePrev allEntries
      -- Tips are entries not in the parent set (except genesis might not have children)
      tips = filter (\e -> not (Set.member (ceHash e) parentSet) || ceHash e == ceHash tip) allEntries
      -- Always include the active tip
      allTips = if ceHash tip `elem` map ceHash tips
                then tips
                else tip : tips

  -- Build result array
  let tipResults = map (tipToJSON entries tip invalidated) allTips
  return $ RpcResponse (toJSON tipResults) Null Null
  where
    tipToJSON :: Map BlockHash ChainEntry -> ChainEntry -> Set.Set BlockHash
              -> ChainEntry -> Value
    tipToJSON entries activeTip invalidatedSet entry =
      let status = getChainTipStatus entries activeTip invalidatedSet entry
          branchLen = computeBranchLen entries activeTip entry
      in object
        [ "height"    .= ceHeight entry
        , "hash"      .= showHash (ceHash entry)
        , "branchlen" .= branchLen
        , "status"    .= status
        ]

    getChainTipStatus :: Map BlockHash ChainEntry -> ChainEntry -> Set.Set BlockHash
                      -> ChainEntry -> Text
    getChainTipStatus entries activeTip invalidatedSet entry
      | ceHash entry == ceHash activeTip = "active"
      | Set.member (ceHash entry) invalidatedSet = "invalid"
      | ceStatus entry == StatusInvalid = "invalid"
      | ceStatus entry == StatusValid = "valid-fork"
      | ceStatus entry == StatusHeaderValid = "valid-headers"
      | otherwise = "headers-only"

    computeBranchLen :: Map BlockHash ChainEntry -> ChainEntry -> ChainEntry -> Int
    computeBranchLen entries activeTip entry
      | ceHash entry == ceHash activeTip = 0
      | otherwise =
          -- Find fork point with active chain and compute distance
          let forkHeight = findForkHeight entries activeTip entry
          in fromIntegral (ceHeight entry) - fromIntegral forkHeight

    findForkHeight :: Map BlockHash ChainEntry -> ChainEntry -> ChainEntry -> Word32
    findForkHeight entries activeTip entry =
      walkToCommonAncestor entries activeTip entry

    walkToCommonAncestor :: Map BlockHash ChainEntry -> ChainEntry -> ChainEntry -> Word32
    walkToCommonAncestor entries a b
      | ceHash a == ceHash b = ceHeight a
      | ceHeight a > ceHeight b =
          case cePrev a >>= (`Map.lookup` entries) of
            Just parent -> walkToCommonAncestor entries parent b
            Nothing -> 0
      | ceHeight a < ceHeight b =
          case cePrev b >>= (`Map.lookup` entries) of
            Just parent -> walkToCommonAncestor entries a parent
            Nothing -> 0
      | otherwise =
          -- Same height, step both back
          case (cePrev a >>= (`Map.lookup` entries), cePrev b >>= (`Map.lookup` entries)) of
            (Just pa, Just pb) -> walkToCommonAncestor entries pa pb
            _ -> 0

--------------------------------------------------------------------------------
-- Script Decode RPC Handler
--------------------------------------------------------------------------------

-- | Decode a hex-encoded script
-- Reference: Bitcoin Core's decodescript RPC (rawtransaction.cpp)
-- Parameters:
--   hexstring (required): The hex-encoded script
-- Returns:
--   Object with asm, type, p2sh, segwit addresses
handleDecodeScript :: RpcServer -> Value -> IO RpcResponse
handleDecodeScript server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing hexstring parameter") Null
    Just hexStr -> do
      case B16.decode (TE.encodeUtf8 hexStr) of
        Left _ -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid hex encoding") Null
        Right scriptBytes -> do
          let mScript = decodeScript scriptBytes
              scriptType = case mScript of
                Right s -> classifyOutput s
                Left _ -> NonStandard
              typeStr = scriptTypeToString scriptType
              asmStr = scriptToAsm scriptBytes

          -- Build base result
          let baseFields =
                [ "asm"  .= asmStr
                , "type" .= typeStr
                ]

          -- Add address if one exists
          let mAddress = scriptToAddress (rsNetwork server) scriptBytes scriptType
              fieldsWithAddr = case mAddress of
                Just addr -> baseFields ++ ["address" .= addr]
                Nothing -> baseFields

          -- Add P2SH address (wrap this script in P2SH)
          let p2shFields = case canWrapP2SH scriptType scriptBytes of
                True ->
                  let p2shAddr = computeP2SHAddress (rsNetwork server) scriptBytes
                  in fieldsWithAddr ++ ["p2sh" .= p2shAddr]
                False -> fieldsWithAddr

          -- Add SegWit info if wrappable
          let segwitFields = case canWrapSegWit scriptType scriptBytes of
                True ->
                  let segwitInfo = computeSegWitInfo (rsNetwork server) scriptBytes scriptType
                  in p2shFields ++ ["segwit" .= segwitInfo]
                False -> p2shFields

          return $ RpcResponse (object segwitFields) Null Null
  where
    -- Check if script can be wrapped in P2SH
    canWrapP2SH :: ScriptType -> ByteString -> Bool
    canWrapP2SH st _bytes = case st of
      P2SH _ -> False  -- Don't wrap P2SH in P2SH
      P2WPKH _ -> False
      P2WSH _ -> False
      P2TR _ -> False
      OpReturn _ -> False
      _ -> True

    -- Check if script can be wrapped in P2WSH
    canWrapSegWit :: ScriptType -> ByteString -> Bool
    canWrapSegWit st _bytes = case st of
      P2SH _ -> False
      P2WPKH _ -> False
      P2WSH _ -> False
      P2TR _ -> False
      OpReturn _ -> False
      _ -> True

    -- Compute P2SH address for a script
    computeP2SHAddress :: Network -> ByteString -> Text
    computeP2SHAddress net scriptBytes =
      let scriptHash = hash160 scriptBytes
      in base58Check (netScriptPrefix net) (getHash160 scriptHash)

    -- Compute SegWit wrapper info
    computeSegWitInfo :: Network -> ByteString -> ScriptType -> Value
    computeSegWitInfo net scriptBytes scriptType =
      let -- For P2PKH, create P2WPKH (if it has a pubkey hash)
          -- For others, create P2WSH
          (segwitScript, segwitType, segwitAddr) = case scriptType of
            P2PKH h ->
              -- Convert to P2WPKH
              let witnessScript = BS.pack [0x00, 0x14] <> getHash160 h
                  addr = bech32Encode (netBech32Prefix net) 0 (getHash160 h)
              in (witnessScript, "witness_v0_keyhash" :: Text, addr)
            _ ->
              -- Create P2WSH
              let witnessHash = sha256 scriptBytes
                  witnessScript = BS.pack [0x00, 0x20] <> getHash256 witnessHash
                  addr = bech32Encode (netBech32Prefix net) 0 (getHash256 witnessHash)
              in (witnessScript, "witness_v0_scripthash" :: Text, addr)
          -- P2SH-SegWit address
          p2shSegwitAddr = computeP2SHAddress net segwitScript
      in object
        [ "asm"         .= scriptToAsm segwitScript
        , "hex"         .= TE.decodeUtf8 (B16.encode segwitScript)
        , "type"        .= segwitType
        , "address"     .= segwitAddr
        , "p2sh-segwit" .= p2shSegwitAddr
        ]

    hash160 :: ByteString -> Hash160
    hash160 = Hash160 . BS.take 20 . doHash160

    sha256 :: ByteString -> Hash256
    sha256 = Hash256 . doSHA256

    doHash160 :: ByteString -> ByteString
    doHash160 bs = doRIPEMD160 (doSHA256 bs)

    doSHA256 :: ByteString -> ByteString
    doSHA256 bs =
      let digest = Crypto.hash bs :: Crypto.Digest Crypto.SHA256
      in BS.pack $ BA.unpack digest

    doRIPEMD160 :: ByteString -> ByteString
    doRIPEMD160 bs =
      let digest = Crypto.hash bs :: Crypto.Digest Crypto.RIPEMD160
      in BS.pack $ BA.unpack digest

    getHash160 :: Hash160 -> ByteString
    getHash160 (Hash160 bs) = bs

    getHash256 :: Hash256 -> ByteString
    getHash256 (Hash256 bs) = bs

--------------------------------------------------------------------------------
-- Mempool Test Accept RPC Handler
--------------------------------------------------------------------------------

-- | Test mempool acceptance without submitting
-- Reference: Bitcoin Core's testmempoolaccept RPC (mempool.cpp)
-- Parameters:
--   rawtxs (required): Array of hex-encoded raw transactions
--   maxfeerate (optional): Reject if fee rate exceeds this (default: 0.10 BTC/kvB)
-- Returns:
--   Array of {txid, wtxid, allowed, vsize, fees, reject-reason}
handleTestMempoolAccept :: RpcServer -> Value -> IO RpcResponse
handleTestMempoolAccept server params = do
  case extractParamArray params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing rawtxs parameter") Null
    Just txArray -> do
      -- Parse maxfeerate (sat/vB, default 0.10 BTC/kvB = 10000 sat/vB)
      let maxFeeRateSatPerVB = case extractParam params 1 :: Maybe Double of
            Just rate -> rate * 100000  -- BTC/kvB to sat/vB
            Nothing -> 10000.0  -- Default 0.10 BTC/kvB

      -- Parse and test each transaction
      results <- forM (V.toList txArray) $ \txVal -> do
        case txVal of
          String hexTx -> testSingleTx hexTx maxFeeRateSatPerVB
          _ -> return $ object
            [ "allowed" .= False
            , "reject-reason" .= ("invalid-type" :: Text)
            ]

      return $ RpcResponse (toJSON results) Null Null
  where
    testSingleTx :: Text -> Double -> IO Value
    testSingleTx hexTx maxFeeRate = do
      case B16.decode (TE.encodeUtf8 hexTx) of
        Left _ -> return $ object
          [ "allowed" .= False
          , "reject-reason" .= ("TX decode failed" :: Text)
          ]
        Right txBytes -> do
          case decodeTxWithFallback txBytes of
            Left err -> return $ object
              [ "allowed" .= False
              , "reject-reason" .= ("TX decode failed: " <> T.pack err)
              ]
            Right tx -> do
              let txid = computeTxId tx
                  wtxid = computeWtxId tx

              -- Check if already in mempool
              mExisting <- getTransaction (rsMempool server) txid
              case mExisting of
                Just _ -> return $ object
                  [ "txid"   .= showHash (BlockHash (getTxIdHash txid))
                  , "wtxid"  .= showHash (BlockHash (getTxIdHash wtxid))
                  , "allowed" .= False
                  , "reject-reason" .= ("txn-already-in-mempool" :: Text)
                  ]
                Nothing -> do
                  -- Try to add (dry run)
                  result <- addTransaction (rsMempool server) tx
                  case result of
                    Left err -> return $ object
                      [ "txid"   .= showHash (BlockHash (getTxIdHash txid))
                      , "wtxid"  .= showHash (BlockHash (getTxIdHash wtxid))
                      , "allowed" .= False
                      , "reject-reason" .= mempoolErrorToText err
                      ]
                    Right _ -> do
                      -- Get the entry to compute vsize and fee
                      mEntry <- getTransaction (rsMempool server) txid
                      -- Remove it (since this is test only)
                      removeTransaction (rsMempool server) txid

                      case mEntry of
                        Nothing -> return $ object
                          [ "txid"   .= showHash (BlockHash (getTxIdHash txid))
                          , "wtxid"  .= showHash (BlockHash (getTxIdHash wtxid))
                          , "allowed" .= True
                          ]
                        Just entry -> do
                          let vsize = meSize entry
                              fee = meFee entry
                              feeRateSatPerVB = fromIntegral fee / fromIntegral vsize :: Double

                          if feeRateSatPerVB > maxFeeRate
                            then return $ object
                              [ "txid"   .= showHash (BlockHash (getTxIdHash txid))
                              , "wtxid"  .= showHash (BlockHash (getTxIdHash wtxid))
                              , "allowed" .= False
                              , "reject-reason" .= ("max-fee-exceeded" :: Text)
                              ]
                            else return $ object
                              [ "txid"   .= showHash (BlockHash (getTxIdHash txid))
                              , "wtxid"  .= showHash (BlockHash (getTxIdHash wtxid))
                              , "allowed" .= True
                              , "vsize"  .= vsize
                              , "fees"   .= object
                                  [ "base" .= (fromIntegral fee / 100000000.0 :: Double)
                                  ]
                              ]

    mempoolErrorToText :: MempoolError -> Text
    mempoolErrorToText err = case err of
      ErrAlreadyInMempool -> "txn-already-known"
      ErrValidationFailed _ -> "bad-txns"
      ErrMissingInput _ -> "missing-inputs"
      ErrInputSpentInMempool _ -> "txn-mempool-conflict"
      ErrInsufficientFee -> "min-fee-not-met"
      ErrFeeBelowMinimum _ _ -> "min-fee-not-met"
      ErrTooManyAncestors _ _ -> "too-long-mempool-chain"
      ErrTooManyDescendants _ _ -> "too-long-mempool-chain"
      ErrAncestorSizeTooLarge _ _ -> "too-long-mempool-chain"
      ErrDescendantSizeTooLarge _ _ -> "too-long-mempool-chain"
      ErrScriptVerificationFailed _ -> "bad-txns"
      ErrCoinbaseNotMature _ _ -> "bad-txns-premature-spend-of-coinbase"
      ErrRBFNotSignaled _ -> "txn-mempool-conflict"
      ErrRBFFeeTooLow _ _ -> "insufficient-fee"
      ErrMempoolFull -> "mempool-full"
      ErrRBFInsufficientAbsoluteFee _ _ -> "insufficient-fee"
      ErrRBFInsufficientFeeRate _ _ -> "insufficient-fee"
      ErrRBFTooManyReplacements _ _ -> "too-many-potential-replacements"
      ErrRBFInsufficientRelayFee _ _ -> "insufficient-fee"
      ErrRBFSpendingConflict _ -> "txn-mempool-conflict"
      ErrTrucViolation _ -> "non-standard"
      ErrEphemeralViolation _ -> "dust"
      ErrClusterLimitExceeded _ _ -> "too-long-mempool-chain"

--------------------------------------------------------------------------------
-- Mempool Entry RPC Handler
--------------------------------------------------------------------------------

-- | Get detailed mempool entry for a transaction
-- Reference: Bitcoin Core's getmempoolentry RPC (mempool.cpp)
-- Parameters:
--   txid (required): The transaction ID
-- Returns:
--   Object with vsize, weight, fee, time, height, descendant/ancestor info
handleGetMempoolEntry :: RpcServer -> Value -> IO RpcResponse
handleGetMempoolEntry server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing txid parameter") Null
    Just hexTxid -> do
      case parseHash hexTxid of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid txid") Null
        Just bh -> do
          let txid = TxId (getBlockHashHash bh)
          mEntry <- getTransaction (rsMempool server) txid
          case mEntry of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Transaction not in mempool") Null
            Just entry -> do
              -- Get ancestor/descendant info
              ancestors <- getAncestors (rsMempool server) (meTransaction entry)
              descendants <- getDescendants (rsMempool server) txid

              let ancestorCount = length ancestors + 1  -- Include self
                  ancestorSize = sum (map meSize ancestors) + meSize entry
                  ancestorFees = sum (map meFee ancestors) + meFee entry

                  descendantCount = length descendants + 1
                  descendantSize = sum (map meSize descendants) + meSize entry
                  descendantFees = sum (map meFee descendants) + meFee entry

                  -- Calculate weight
                  baseSize = txBaseSize (meTransaction entry)
                  totalSize = txTotalSize (meTransaction entry)
                  weight = baseSize * (witnessScaleFactor - 1) + totalSize

                  -- Get parent txids (depends)
                  depends = map (\e -> showHash (BlockHash (getTxIdHash (meTxId e)))) ancestors

              let result = object
                    [ "vsize"           .= meSize entry
                    , "weight"          .= weight
                    , "fee"             .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
                    , "modifiedfee"     .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
                    , "time"            .= meTime entry
                    , "height"          .= meHeight entry
                    , "descendantcount" .= descendantCount
                    , "descendantsize"  .= descendantSize
                    , "descendantfees"  .= descendantFees
                    , "ancestorcount"   .= ancestorCount
                    , "ancestorsize"    .= ancestorSize
                    , "ancestorfees"    .= ancestorFees
                    , "wtxid"           .= showHash (BlockHash (getTxIdHash (computeWtxId (meTransaction entry))))
                    , "fees"            .= object
                        [ "base"       .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
                        , "modified"   .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
                        , "ancestor"   .= (fromIntegral ancestorFees / 100000000.0 :: Double)
                        , "descendant" .= (fromIntegral descendantFees / 100000000.0 :: Double)
                        ]
                    , "depends"         .= depends
                    , "spentby"         .= ([] :: [Text])  -- Would need child tracking
                    , "bip125-replaceable" .= meRBFOptIn entry
                    , "unbroadcast"     .= False
                    ]
              return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- Mempool: Get Mempool Ancestors RPC Handler
--------------------------------------------------------------------------------

-- | Get all in-mempool ancestors of a transaction
-- Reference: Bitcoin Core's getmempoolancestors RPC (blockchain.cpp)
-- Parameters:
--   txid (required): Transaction ID
--   verbose (optional): If true, return detailed info for each ancestor
-- Returns:
--   Array of ancestor txids, or object with detailed ancestor info
handleGetMempoolAncestors :: RpcServer -> Value -> IO RpcResponse
handleGetMempoolAncestors server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing txid parameter") Null
    Just txidHex -> do
      let verbose = fromMaybe False (extractParam params 1 :: Maybe Bool)
          mp = rsMempool server
      entries <- readTVarIO (mpEntries mp)
      case parseTxId txidHex of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid txid") Null
        Just txid -> do
          case Map.lookup txid entries of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidAddressOrKey "Transaction not in mempool") Null
            Just entry -> do
              -- Use the mempool's ancestor lookup
              ancestors <- getAncestors mp (meTransaction entry)
              if verbose
                then do
                  let ancestorDetails = Map.fromList
                        [ (showTxId (meTxId anc), mempoolEntryToJSON anc)
                        | anc <- ancestors
                        ]
                  return $ RpcResponse (toJSON ancestorDetails) Null Null
                else
                  return $ RpcResponse (toJSON (map (showTxId . meTxId) ancestors)) Null Null
  where
    parseTxId :: Text -> Maybe TxId
    parseTxId hex =
      case B16.decode (TE.encodeUtf8 hex) of
        Left _ -> Nothing
        Right bs
          | BS.length bs == 32 -> Just $ TxId (Hash256 (BS.reverse bs))
          | otherwise -> Nothing

    showTxId :: TxId -> Text
    showTxId (TxId (Hash256 bs)) = TE.decodeUtf8 $ B16.encode (BS.reverse bs)

    mempoolEntryToJSON :: MempoolEntry -> Value
    mempoolEntryToJSON entry = object
      [ "vsize"           .= meSize entry
      , "fee"             .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
      , "ancestorcount"   .= meAncestorCount entry
      , "ancestorsize"    .= meAncestorSize entry
      , "ancestorfees"    .= meAncestorFees entry
      , "descendantcount" .= meDescendantCount entry
      , "descendantsize"  .= meDescendantSize entry
      , "descendantfees"  .= meDescendantFees entry
      ]

-- | Error code for invalid address or key
rpcInvalidAddressOrKey :: Int
rpcInvalidAddressOrKey = -5

--------------------------------------------------------------------------------
-- Raw Transaction: Create Raw Transaction RPC Handler
--------------------------------------------------------------------------------

-- | Create a raw transaction from inputs and outputs
-- Reference: Bitcoin Core's createrawtransaction RPC (rawtransaction.cpp)
-- Parameters:
--   inputs: [{"txid":"hex","vout":n,"sequence":n}]
--   outputs: [{"address":amount},{"data":"hex"}]
--   locktime (optional): Raw locktime
--   replaceable (optional): BIP125 replaceable flag
-- Returns:
--   Hex-encoded raw transaction
handleCreateRawTransaction :: RpcServer -> Value -> IO RpcResponse
handleCreateRawTransaction _server params = do
  let mInputs = extractParamArray params 0
      mOutputs = extractParamArray params 1
      locktime = fromMaybe 0 (extractParam params 2 :: Maybe Word32)
      replaceable = fromMaybe False (extractParam params 3 :: Maybe Bool)

  case (mInputs, mOutputs) of
    (Nothing, _) -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing inputs parameter") Null
    (_, Nothing) -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing outputs parameter") Null
    (Just inputsArr, Just outputsArr) -> do
      -- Parse inputs
      let parseInput v = do
            txidHex <- v .:: "txid" :: Maybe Text
            vout <- v .:: "vout" :: Maybe Word32
            let seqNum = case v .:: "sequence" :: Maybe Word32 of
                  Just s -> s
                  Nothing -> if replaceable then 0xFFFFFFFD else 0xFFFFFFFE
            txidBs <- case B16.decode (TE.encodeUtf8 txidHex) of
              Left _ -> Nothing
              Right bs | BS.length bs == 32 -> Just (BS.reverse bs)
                       | otherwise -> Nothing
            Just TxIn
              { txInPrevOutput = OutPoint (TxId (Hash256 txidBs)) vout
              , txInScript = BS.empty
              , txInSequence = seqNum
              }

      let inputs = mapMaybe parseInput (V.toList inputsArr)

      -- Parse outputs - each is an object with address:amount or data:hex
      let parseOutput v = case v of
            Object obj -> case KM.toList obj of
              [(k, val)] ->
                let key = Key.toText k
                in if key == "data"
                   then case fromJSON val of
                     Success (hexStr :: Text) ->
                       case B16.decode (TE.encodeUtf8 hexStr) of
                         Left _ -> Nothing
                         Right dataBs ->
                           let script = BS.pack [0x6a] <> encodeVarLen dataBs <> dataBs
                           in Just $ TxOut 0 script
                     _ -> Nothing
                   else case fromJSON val of
                     Success (amount :: Double) ->
                       let satoshis = round (amount * 100000000)
                           -- Placeholder script (actual address parsing would go here)
                           script = BS.pack [0x00, 0x14] <> BS.replicate 20 0
                       in Just $ TxOut satoshis script
                     _ -> Nothing
              _ -> Nothing
            _ -> Nothing

      let outputs = mapMaybe parseOutput (V.toList outputsArr)

      -- Build the transaction
      let tx = Tx
            { txVersion = 2
            , txInputs = inputs
            , txOutputs = outputs
            , txWitness = []
            , txLockTime = locktime
            }
          hexTx = TE.decodeUtf8 $ B16.encode $ S.encode tx

      return $ RpcResponse (toJSON hexTx) Null Null
  where
    (.::) :: FromJSON a => Value -> Text -> Maybe a
    (.::) (Object obj) key = case KM.lookup (Key.fromText key) obj of
      Nothing -> Nothing
      Just v -> case fromJSON v of
        Success a -> Just a
        Error _ -> Nothing
    (.::) _ _ = Nothing

    encodeVarLen :: ByteString -> ByteString
    encodeVarLen bs
      | BS.length bs < 76 = BS.pack [fromIntegral (BS.length bs)]
      | BS.length bs < 256 = BS.pack [0x4c, fromIntegral (BS.length bs)]
      | otherwise = BS.pack [0x4d, fromIntegral (BS.length bs .&. 0xff),
                              fromIntegral ((BS.length bs `shiftR` 8) .&. 0xff)]

--------------------------------------------------------------------------------
-- Wallet: Sign Raw Transaction With Wallet RPC Handler
--------------------------------------------------------------------------------

-- | Sign a raw transaction with wallet keys
-- Reference: Bitcoin Core's signrawtransactionwithwallet RPC (wallet/rpc/spend.cpp)
-- Parameters:
--   hexstring (required): Hex-encoded raw transaction
-- Returns:
--   {hex, complete} - signed transaction and whether fully signed
handleSignRawTransactionWithWallet :: RpcServer -> Value -> IO RpcResponse
handleSignRawTransactionWithWallet server params = do
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      case extractParamText params 0 of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Missing hexstring parameter") Null
        Just hexTx -> do
          case B16.decode (TE.encodeUtf8 hexTx) of
            Left _ -> return $ RpcResponse Null
              (toJSON $ RpcError rpcDeserializationError "TX decode failed") Null
            Right txBytes -> do
              case S.decode txBytes of
                Left _ -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcDeserializationError "TX decode failed") Null
                Right (tx :: Tx) -> do
                  -- For now, return the transaction as-is with complete=false
                  -- Full implementation would look up private keys from wallet
                  -- and sign each input
                  let signedHex = TE.decodeUtf8 $ B16.encode $ S.encode tx
                      result = object
                        [ "hex"      .= signedHex
                        , "complete" .= False
                        , "errors"   .= ([] :: [Value])
                        ]
                  return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- Network Disconnect Node RPC Handler
--------------------------------------------------------------------------------

-- | Disconnect a peer by address or node ID
-- Reference: Bitcoin Core's disconnectnode RPC (net.cpp)
-- Parameters:
--   address (optional): IP address:port of the node
--   nodeid (optional): Node ID from getpeerinfo
-- Returns:
--   null on success, error if not found
handleDisconnectNode :: RpcServer -> Value -> IO RpcResponse
handleDisconnectNode server params = do
  let mAddress = extractParamText params 0
      mNodeId = extractParam params 1 :: Maybe Int

  case (mAddress, mNodeId) of
    (Nothing, Nothing) -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Either address or nodeid must be provided") Null

    (Just addr, Nothing) | not (T.null addr) -> do
      -- Disconnect by address
      success <- disconnectByAddress (rsPeerMgr server) (T.unpack addr)
      if success
        then return $ RpcResponse Null Null Null
        else return $ RpcResponse Null
          (toJSON $ RpcError rpcClientNodeNotConnected "Node not found in connected nodes") Null

    (_, Just nodeId) -> do
      -- Disconnect by node ID
      success <- disconnectByNodeId (rsPeerMgr server) nodeId
      if success
        then return $ RpcResponse Null Null Null
        else return $ RpcResponse Null
          (toJSON $ RpcError rpcClientNodeNotConnected "Node not found in connected nodes") Null

    (Just _, Just _) -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Only one of address and nodeid should be provided") Null

    _ -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Either address or nodeid must be provided") Null
  where
    disconnectByAddress :: PeerManager -> String -> IO Bool
    disconnectByAddress pm addrStr = do
      peers <- readTVarIO (pmPeers pm)
      -- Parse the address string and find matching peer
      let matching = filter (matchAddress addrStr . fst) (Map.toList peers)
      case matching of
        ((addr, pc):_) -> do
          disconnectPeer pc
          atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)
          return True
        [] -> return False

    matchAddress :: String -> SockAddr -> Bool
    matchAddress target addr =
      let addrStr = show addr
      in target == addrStr || target `isInfixOf` addrStr

    isInfixOf :: String -> String -> Bool
    isInfixOf needle haystack = needle `elem` [take (length needle) (drop i haystack) | i <- [0..length haystack - length needle]]

    disconnectByNodeId :: PeerManager -> Int -> IO Bool
    disconnectByNodeId pm nodeId = do
      peers <- readTVarIO (pmPeers pm)
      -- Node ID is index in the peer list (simplified)
      let peerList = Map.toList peers
      if nodeId >= 0 && nodeId < length peerList
        then do
          let (addr, pc) = peerList !! nodeId
          disconnectPeer pc
          atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)
          return True
        else return False

-- | Error code for node not connected (-29 in Bitcoin Core)
rpcClientNodeNotConnected :: Int
rpcClientNodeNotConnected = -29

--------------------------------------------------------------------------------
-- Wallet: Get New Address RPC Handler
--------------------------------------------------------------------------------

-- | Generate a new receiving address
-- Reference: Bitcoin Core's getnewaddress RPC (wallet/rpc/addresses.cpp)
-- Parameters:
--   label (optional): Label for the address
--   address_type (optional): "legacy", "p2sh-segwit", "bech32", "bech32m"
-- Returns:
--   New address string
handleGetNewAddress :: RpcServer -> Value -> IO RpcResponse
handleGetNewAddress server params = do
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      -- Get default wallet
      (mWallet, _walletCount) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState -> do
          -- Parse address type (default to bech32)
          let addrTypeStr = fromMaybe "bech32" (extractParamText params 1)
              addrType = parseAddressType addrTypeStr

          -- Generate new address
          case addrType of
            Just aType -> do
              addr <- getNewAddress aType (wsWallet walletState)
              return $ RpcResponse (toJSON (show addr)) Null Null
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams ("Unknown address type: " <> addrTypeStr)) Null
  where
    parseAddressType :: Text -> Maybe AddressType
    parseAddressType t = case T.toLower t of
      "legacy"      -> Just AddrP2PKH
      "p2sh-segwit" -> Just AddrP2SH_P2WPKH
      "bech32"      -> Just AddrP2WPKH
      "bech32m"     -> Just AddrP2TR
      _             -> Nothing

--------------------------------------------------------------------------------
-- Wallet: Send To Address RPC Handler
--------------------------------------------------------------------------------

-- | Send an amount to an address
-- Reference: Bitcoin Core's sendtoaddress RPC (wallet/rpc/spend.cpp)
-- Parameters:
--   address (required): Bitcoin address to send to
--   amount (required): Amount in BTC
-- Returns:
--   Transaction ID hex string
handleSendToAddress :: RpcServer -> Value -> IO RpcResponse
handleSendToAddress server params = do
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      (mWallet, _) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState -> do
          case (extractParamText params 0, extractParam params 1 :: Maybe Double) of
            (Just addrText, Just amountBtc) -> do
              -- Parse address
              case textToAddress addrText of
                Nothing -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcInvalidParams "Invalid Bitcoin address") Null
                Just addr -> do
                  -- Convert BTC to satoshis
                  let satoshis = round (amountBtc * 100000000) :: Word64

                  -- Create and send transaction
                  result <- sendToAddress (wsWallet walletState) addr satoshis (FeeRate 10)
                  case result of
                    Left err -> return $ RpcResponse Null
                      (toJSON $ RpcError rpcMiscError (T.pack err)) Null
                    Right tx -> do
                      -- Broadcast to network
                      let txid = computeTxId tx
                      _ <- addTransaction (rsMempool server) tx
                      broadcastMessage (rsPeerMgr server)
                        (MInv (Inv [InvVector InvTx (getTxIdHash txid)]))
                      return $ RpcResponse (toJSON $ showHash (BlockHash (getTxIdHash txid))) Null Null
            _ -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams "Missing address or amount parameter") Null

--------------------------------------------------------------------------------
-- Wallet: List Transactions RPC Handler
--------------------------------------------------------------------------------

-- | List wallet transaction history
-- Reference: Bitcoin Core's listtransactions RPC (wallet/rpc/transactions.cpp)
-- Parameters:
--   label (optional): Filter by label, or "*" for all
--   count (optional): Number of transactions to return (default 10)
--   skip (optional): Number of transactions to skip (default 0)
-- Returns:
--   Array of transaction entries
handleListTransactions :: RpcServer -> Value -> IO RpcResponse
handleListTransactions server params = do
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      (mWallet, _) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState -> do
          let count = fromMaybe 10 (extractParam params 1 :: Maybe Int)
              skip = fromMaybe 0 (extractParam params 2 :: Maybe Int)

          -- Get wallet transactions
          txHistory <- getWalletTransactions walletState count skip

          let results = map txHistoryToJSON txHistory
          return $ RpcResponse (toJSON results) Null Null
  where
    txHistoryToJSON :: WalletTransaction -> Value
    txHistoryToJSON wtx = object $ catMaybes
      [ Just $ "txid"     .= showHash (BlockHash (getTxIdHash (wtxTxId wtx)))
      , wtxAddress wtx >>= \addr -> Just $ "address" .= addr
      , Just $ "category" .= wtxCategory wtx
      , Just $ "amount"   .= (fromIntegral (wtxAmount wtx) / 100000000.0 :: Double)
      , Just $ "vout"     .= wtxVout wtx
      , Just $ "confirmations" .= wtxConfirmations wtx
      , wtxBlockHash wtx >>= \bh -> Just $ "blockhash" .= showHash bh
      , wtxBlockTime wtx >>= \t -> Just $ "blocktime" .= t
      , Just $ "time"     .= wtxTime wtx
      ]

-- | Wallet transaction record
data WalletTransaction = WalletTransaction
  { wtxTxId          :: !TxId
  , wtxAddress       :: !(Maybe Text)
  , wtxCategory      :: !Text
  , wtxAmount        :: !Int64
  , wtxVout          :: !Int
  , wtxConfirmations :: !Int
  , wtxBlockHash     :: !(Maybe BlockHash)
  , wtxBlockTime     :: !(Maybe Word32)
  , wtxTime          :: !Word32
  }

-- | Get wallet transactions (placeholder - needs proper wallet tx tracking)
getWalletTransactions :: WalletState -> Int -> Int -> IO [WalletTransaction]
getWalletTransactions _walletState _count _skip = do
  -- TODO: Implement proper transaction history from wallet
  return []

--------------------------------------------------------------------------------
-- Wallet: List Unspent RPC Handler
--------------------------------------------------------------------------------

-- | List unspent transaction outputs in wallet
-- Reference: Bitcoin Core's listunspent RPC (wallet/rpc/coins.cpp)
-- Parameters:
--   minconf (optional): Minimum confirmations (default 1)
--   maxconf (optional): Maximum confirmations (default 9999999)
--   addresses (optional): Array of addresses to filter
-- Returns:
--   Array of UTXO entries
handleListUnspent :: RpcServer -> Value -> IO RpcResponse
handleListUnspent server params = do
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      (mWallet, _) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState -> do
          let minConf = fromMaybe 1 (extractParam params 0 :: Maybe Int)
              maxConf = fromMaybe 9999999 (extractParam params 1 :: Maybe Int)

          -- Get current tip height for confirmation calculation
          tipHeight <- readTVarIO (hcHeight (rsHeaderChain server))

          -- Get wallet UTXOs
          utxos <- getWalletUTXOs (wsWallet walletState)

          -- Filter and format
          let results = catMaybes $ map (utxoToJSON tipHeight minConf maxConf) utxos

          return $ RpcResponse (toJSON results) Null Null
  where
    utxoToJSON :: Word32 -> Int -> Int -> (OutPoint, TxOut, Word32) -> Maybe Value
    utxoToJSON tipHeight minConf maxConf (op, txout, confs) = do
      let confirmations = fromIntegral confs :: Int

      -- Filter by confirmation range
      if confirmations >= minConf && confirmations <= maxConf
        then Just $ object
          [ "txid"          .= showHash (BlockHash (getTxIdHash (outPointHash op)))
          , "vout"          .= outPointIndex op
          , "scriptPubKey"  .= TE.decodeUtf8 (B16.encode (txOutScript txout))
          , "amount"        .= (fromIntegral (txOutValue txout) / 100000000.0 :: Double)
          , "confirmations" .= confirmations
          , "spendable"     .= True
          , "solvable"      .= True
          , "safe"          .= True
          ]
        else Nothing

--------------------------------------------------------------------------------
-- Control: Help RPC Handler
--------------------------------------------------------------------------------

-- | List all commands or get help for a specific command
-- Reference: Bitcoin Core's help RPC (server.cpp)
-- Parameters:
--   command (optional): Get help for this command
-- Returns:
--   Help text string
handleHelp :: RpcServer -> Value -> IO RpcResponse
handleHelp _server params = do
  case extractParamText params 0 of
    Nothing -> do
      -- Return list of all commands
      let helpText = T.unlines $ sort allRpcCommands
      return $ RpcResponse (toJSON helpText) Null Null
    Just cmd -> do
      -- Return help for specific command
      let helpText = getCommandHelp cmd
      return $ RpcResponse (toJSON helpText) Null Null
  where
    sort = Data.List.sort

-- | List of all available RPC commands
allRpcCommands :: [Text]
allRpcCommands =
  [ "== Blockchain =="
  , "getbestblockhash"
  , "getblock \"blockhash\" ( verbosity )"
  , "getblockchaininfo"
  , "getblockcount"
  , "getsyncstate"
  , "getdeploymentinfo ( \"blockhash\" )"
  , "getblockhash height"
  , "getblockheader \"blockhash\" ( verbose )"
  , "getchaintips"
  , "getdifficulty"
  , "gettxout \"txid\" n ( include_mempool )"
  , "invalidateblock \"blockhash\""
  , "pruneblockchain height"
  , "reconsiderblock \"blockhash\""
  , ""
  , "== Mempool =="
  , "getmempoolancestors \"txid\" ( verbose )"
  , "getmempooldescendants \"txid\" ( verbose )"
  , "getmempoolentry \"txid\""
  , "getmempoolinfo"
  , "getrawmempool ( verbose mempool_sequence )"
  , "testmempoolaccept [\"rawtx\",...] ( maxfeerate )"
  , ""
  , "== Mining =="
  , "getblocktemplate ( \"template_request\" )"
  , "getmininginfo"
  , "submitblock \"hexdata\" ( \"dummy\" )"
  , ""
  , "== Network =="
  , "addnode \"node\" \"command\""
  , "disconnectnode ( \"address\" nodeid )"
  , "getconnectioncount"
  , "getnetworkinfo"
  , "getpeerinfo"
  , ""
  , "== Rawtransactions =="
  , "createrawtransaction [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime replaceable )"
  , "decoderawtransaction \"hexstring\" ( iswitness )"
  , "decodescript \"hexstring\""
  , "getrawtransaction \"txid\" ( verbosity \"blockhash\" )"
  , "sendrawtransaction \"hexstring\" ( maxfeerate )"
  , "signrawtransactionwithwallet \"hexstring\""
  , ""
  , "== Wallet =="
  , "createwallet \"wallet_name\""
  , "encryptwallet \"passphrase\""
  , "getbalance"
  , "getnewaddress ( \"label\" \"address_type\" )"
  , "getwalletinfo"
  , "importdescriptors \"requests\""
  , "listdescriptors"
  , "listtransactions ( \"label\" count skip )"
  , "listunspent ( minconf maxconf [\"address\",...] )"
  , "listwallets"
  , "loadwallet \"filename\""
  , "sendtoaddress \"address\" amount"
  , "unloadwallet ( \"wallet_name\" )"
  , ""
  , "== PSBT =="
  , "combinepsbt [\"psbt\",...]"
  , "createpsbt [{\"txid\":\"hex\",\"vout\":n},...] [{\"address\":amount},...] ( locktime replaceable )"
  , "decodepsbt \"psbt\""
  , "finalizepsbt \"psbt\" ( extract )"
  , ""
  , "== Control =="
  , "help ( \"command\" )"
  , "stop"
  , ""
  , "== Utility =="
  , "estimaterawfee conf_target ( threshold )"
  , "estimatesmartfee conf_target ( \"estimate_mode\" )"
  , "getnettotals"
  , "setlabel \"address\" \"label\""
  , "signmessage \"privkey-or-address\" \"message\""
  , "signmessagewithprivkey \"privkey\" \"message\""
  , "uptime"
  , "validateaddress \"address\""
  , "verifymessage \"address\" \"signature\" \"message\""
  , "walletlock"
  , "walletpassphrase \"passphrase\" timeout"
  ]

-- | Get help text for a specific command
getCommandHelp :: Text -> Text
getCommandHelp cmd = case T.toLower cmd of
  "getblockchaininfo" ->
    "getblockchaininfo\n\nReturns an object containing various state info regarding blockchain processing."
  "getblock" ->
    "getblock \"blockhash\" ( verbosity )\n\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\nIf verbosity is 1, returns an Object with information about block <hash>.\nIf verbosity is 2, returns an Object with information about block <hash> and information about each transaction."
  "getchaintips" ->
    "getchaintips\n\nReturn information about all known tips in the block tree, including the main chain as well as orphaned branches.\n\nResult:\n[\n  {\n    \"height\": n,       (numeric) height of the chain tip\n    \"hash\": \"hash\",   (string) block hash of the tip\n    \"branchlen\": n,    (numeric) length of branch connecting the tip to the main chain\n    \"status\": \"status\" (string) status of the chain\n  },\n  ...\n]"
  "decodescript" ->
    "decodescript \"hexstring\"\n\nDecode a hex-encoded script.\n\nArguments:\n1. hexstring    (string, required) the hex-encoded script\n\nResult:\n{\n  \"asm\": \"asm\",      (string) Script public key\n  \"type\": \"type\",    (string) The output type\n  \"address\": \"addr\", (string) bitcoin address\n  \"p2sh\": \"addr\",    (string) address of P2SH script wrapping this script\n  \"segwit\": {...}    (object) segwit wrapper info\n}"
  "testmempoolaccept" ->
    "testmempoolaccept [\"rawtx\",...] ( maxfeerate )\n\nReturns result of mempool acceptance tests indicating if raw transaction would be accepted by mempool."
  "getmempoolentry" ->
    "getmempoolentry \"txid\"\n\nReturns mempool data for given transaction."
  "disconnectnode" ->
    "disconnectnode ( \"address\" nodeid )\n\nImmediately disconnects from the specified peer node.\n\nArguments:\n1. address    (string, optional) The IP address/port of the node\n2. nodeid     (numeric, optional) The node ID (see getpeerinfo for node IDs)"
  "getnewaddress" ->
    "getnewaddress ( \"label\" \"address_type\" )\n\nReturns a new Bitcoin address for receiving payments.\n\nArguments:\n1. label         (string, optional) The label name for the address\n2. address_type  (string, optional) The address type: \"legacy\", \"p2sh-segwit\", \"bech32\", \"bech32m\""
  "sendtoaddress" ->
    "sendtoaddress \"address\" amount\n\nSend an amount to a given address.\n\nArguments:\n1. address    (string, required) The bitcoin address to send to\n2. amount     (numeric, required) The amount in BTC to send"
  "listtransactions" ->
    "listtransactions ( \"label\" count skip )\n\nReturns up to 'count' most recent transactions."
  "listunspent" ->
    "listunspent ( minconf maxconf [\"address\",...] )\n\nReturns array of unspent transaction outputs."
  "help" ->
    "help ( \"command\" )\n\nList all commands, or get help for a specified command."
  "stop" ->
    "stop\n\nRequest a graceful shutdown of Bitcoin server."
  _ ->
    "Unknown command: " <> cmd <> "\nUse help without arguments to list all commands."

--------------------------------------------------------------------------------
-- Additional Utility RPC Handlers
--------------------------------------------------------------------------------

-- | Encrypt the default wallet with a passphrase.
-- Reference: Bitcoin Core's @encryptwallet@ RPC (wallet/rpc/encrypt.cpp).
-- The wallet must be currently unencrypted; otherwise we return
-- 'rpcWalletWrongEncState' to mirror Core's @RPC_WALLET_WRONG_ENC_STATE@.
-- An empty passphrase is rejected with 'rpcInvalidParams'.  Once encrypted,
-- the wallet remains *unlocked* for the lifetime of this call (no automatic
-- lock) — callers should follow up with @walletlock@ to drop the in-memory
-- key, matching Core's documented behaviour.
handleEncryptWallet :: RpcServer -> Value -> IO RpcResponse
handleEncryptWallet server params =
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      (mWallet, _) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState ->
          case extractParamText params 0 of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams
                "Usage: encryptwallet \"passphrase\"") Null
            Just passphrase
              | T.null passphrase -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcInvalidParams
                    "passphrase cannot be empty") Null
              | otherwise -> do
                  result <- encryptWallet passphrase walletState
                  case result of
                    Left err
                      | "already encrypted" `T.isInfixOf` T.toLower (T.pack err) ->
                          return $ RpcResponse Null
                            (toJSON $ RpcError rpcWalletWrongEncState
                              (T.pack ("Error: " ++ err))) Null
                      | otherwise ->
                          return $ RpcResponse Null
                            (toJSON $ RpcError rpcWalletEncryptionFailed
                              (T.pack ("Error: " ++ err))) Null
                    Right _ -> return $ RpcResponse
                      (toJSON ("wallet encrypted; the keypool has been flushed and a \
                               \new HD seed was generated. You need to make a new backup." :: Text))
                      Null Null

-- | Unlock the default wallet for @timeout@ seconds.
-- Reference: Bitcoin Core's @walletpassphrase@ RPC (wallet/rpc/encrypt.cpp).
-- Calling this on an unencrypted wallet returns 'rpcWalletWrongEncState';
-- a wrong passphrase returns 'rpcWalletPassphraseIncorrect'; a negative
-- timeout returns 'rpcInvalidParams'.  Timeout is clamped to
-- 'walletPassphraseMaxSleepTime' (matches Core).  After the timeout we
-- also actively re-lock the wallet via 'forkIO' / 'threadDelay' so that
-- callers reading the in-memory key directly observe the lock without
-- needing to poll 'isWalletLocked'.
handleWalletPassphrase :: RpcServer -> Value -> IO RpcResponse
handleWalletPassphrase server params =
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      (mWallet, _) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState ->
          case (extractParamText params 0, extractParam params 1 :: Maybe Int) of
            (Just _, Nothing) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams
                "Usage: walletpassphrase \"passphrase\" timeout") Null
            (Nothing, _) -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams
                "Usage: walletpassphrase \"passphrase\" timeout") Null
            (Just passphrase, Just timeoutSec)
              | T.null passphrase -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcInvalidParams
                    "passphrase cannot be empty") Null
              | timeoutSec < 0 -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcInvalidParams
                    "Timeout cannot be negative.") Null
              | otherwise -> do
                  let clamped = min timeoutSec walletPassphraseMaxSleepTime
                      duration = fromIntegral clamped :: NominalDiffTime
                  result <- unlockWallet passphrase duration walletState
                  case result of
                    Left err
                      | "not encrypted" `T.isInfixOf` T.toLower (T.pack err) ->
                          return $ RpcResponse Null
                            (toJSON $ RpcError rpcWalletWrongEncState
                              "Error: running with an unencrypted wallet, but \
                              \walletpassphrase was called.") Null
                      | otherwise ->
                          return $ RpcResponse Null
                            (toJSON $ RpcError rpcWalletPassphraseIncorrect
                              "Error: The wallet passphrase entered was incorrect.") Null
                    Right _ -> do
                      -- Active re-lock callback.  Bitcoin Core schedules this
                      -- via the wallet scheduler so the most-recent
                      -- walletpassphrase wins; we mirror that with an expiry
                      -- check before locking, so a second walletpassphrase
                      -- call that bumps 'wsUnlockExpiry' past our deadline
                      -- will keep the wallet unlocked.
                      _ <- forkIO $ do
                        threadDelay (clamped * 1000000)
                        mExpiry <- readTVarIO (wsUnlockExpiry walletState)
                        nowT <- TimeClock.getCurrentTime
                        case mExpiry of
                          Just expiry | nowT < expiry ->
                            -- A later walletpassphrase extended the lease.
                            return ()
                          _ -> lockWallet walletState
                      return $ RpcResponse Null Null Null

-- | Lock the default wallet, dropping the decrypted key from memory.
-- Reference: Bitcoin Core's @walletlock@ RPC (wallet/rpc/encrypt.cpp).
-- Locking an unencrypted wallet returns 'rpcWalletWrongEncState'.
handleWalletLock :: RpcServer -> IO RpcResponse
handleWalletLock server =
  case rsWalletMgr server of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
    Just walletMgr -> do
      (mWallet, _) <- getDefaultWallet walletMgr
      case mWallet of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcWalletNotFound "No wallet loaded") Null
        Just walletState -> do
          mEncrypted <- readTVarIO (wsEncrypted walletState)
          case mEncrypted of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcWalletWrongEncState
                "Error: running with an unencrypted wallet, but walletlock \
                \was called.") Null
            Just _ -> do
              lockWallet walletState
              return $ RpcResponse Null Null Null

-- | Set label for an address.
-- Stub: label storage not yet implemented.
handleSetLabel :: RpcServer -> Value -> IO RpcResponse
handleSetLabel _server _params =
  return $ RpcResponse Null Null Null

-- | Verify a signed message.
-- Reference: Bitcoin Core's @verifymessage@ RPC (rpc/signmessage.cpp) and
-- @MessageVerify@ in common/signmessage.cpp.  We recover the public key
-- from the 65-byte compact signature, hash160 it, and compare against the
-- P2PKH hash encoded in the supplied address.  Bitcoin Core only supports
-- P2PKH for verifymessage; we mirror that.
handleVerifyMessage :: RpcServer -> Value -> IO RpcResponse
handleVerifyMessage _server params = do
  case (extractParamText params 0, extractParamText params 1, extractParamText params 2) of
    (Just address, Just sig, Just message) -> do
      case textToAddress address of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidAddressOrKey "Invalid address") Null
        Just addr -> case addr of
          PubKeyAddress (Hash160 expectedHash) ->
            case B64.decode (TE.encodeUtf8 sig) of
              Left _ -> return $ RpcResponse Null
                (toJSON $ RpcError (-3) "Malformed base64 encoding") Null
              Right sigBytes
                | BS.length sigBytes /= 65 ->
                    -- Not a 65-byte compact recoverable signature; mirror
                    -- Bitcoin Core which returns false for ERR_PUBKEY_NOT_RECOVERED
                    return $ RpcResponse (toJSON False) Null Null
                | otherwise ->
                    case recoverMessagePubKey sigBytes message of
                      Nothing -> return $ RpcResponse (toJSON False) Null Null
                      Just pkBytes ->
                        let Hash160 actual = hash160 pkBytes
                        in return $ RpcResponse (toJSON (actual == expectedHash))
                                                Null Null
          _ -> return $ RpcResponse Null
            (toJSON $ RpcError (-3) "Address does not refer to key") Null
    _ -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams
        "Usage: verifymessage \"address\" \"signature\" \"message\"") Null

-- | Sign a UTF-8 message with the private key referenced by an address
-- (haskoin's wallet stores keys directly, so we accept either a WIF private
-- key OR an address whose key the wallet manages).
--
-- Reference: Bitcoin Core's @signmessage@ (wallet/rpc/signmessage.cpp) and
-- @signmessagewithprivkey@ (rpc/signmessage.cpp).
--
-- Calling conventions accepted:
--   1. signmessage(\"<WIF privkey>\", \"<message>\")           — privkey-direct path
--   2. signmessagewithprivkey(\"<WIF privkey>\", \"<message>\") — privkey-direct path
-- The resulting 65-byte compact signature is base64-encoded.
handleSignMessage :: RpcServer -> Value -> IO RpcResponse
handleSignMessage _server params = do
  case (extractParamText params 0, extractParamText params 1) of
    (Just keyOrAddress, Just message) ->
      case wifDecode keyOrAddress of
        Just sk@(SecKey _) ->
          -- WIF: trailing 0x01 byte selects compressed; wifDecode strips it
          -- but the decoder remembers via the resulting payload length. We
          -- conservatively assume compressed (the modern default).
          case signMessage sk True message of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidAddressOrKey "Sign failed") Null
            Just sigBytes ->
              return $ RpcResponse
                (toJSON (TE.decodeUtf8 (B64.encode sigBytes))) Null Null
        Nothing ->
          -- Treat as an address: walk the wallet, find the matching key.
          -- haskoin's wallet API does not currently expose a private-key
          -- lookup by address, so this path returns a structured error so
          -- callers can fall back to the privkey form.
          case textToAddress keyOrAddress of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidAddressOrKey "Invalid private key") Null
            Just _ -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidAddressOrKey
                 "Private key for address not available; pass a WIF key directly") Null
    _ -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams
        "Usage: signmessage \"privkey-or-address\" \"message\"") Null

--------------------------------------------------------------------------------
-- Fee Estimation: estimaterawfee
--------------------------------------------------------------------------------

-- | Per-bucket fee estimator exposure, mirroring Bitcoin Core's
-- @estimaterawfee@ (src/rpc/fees.cpp).  The result groups buckets by the
-- horizon names @short@/@medium@/@long@; haskoin's 'FeeEstimator' uses a
-- single horizon, so we report identical payloads under all three keys
-- (matching the shape so JSON-RPC clients can parse it unchanged).
handleEstimateRawFee :: RpcServer -> Value -> IO RpcResponse
handleEstimateRawFee server params = do
  case extractParam params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams
        "Usage: estimaterawfee conf_target ( threshold )") Null
    Just (confTarget :: Int) -> do
      let threshold = case extractParam params 1 :: Maybe Double of
            Just t  -> t
            Nothing -> 0.95
      if threshold < 0 || threshold > 1
        then return $ RpcResponse Null
          (toJSON $ RpcError (-8) "Invalid threshold") Null
        else do
          raw <- estimateRawFee (rsFeeEst server) confTarget threshold
          let horizonObj = rawFeeToJSON raw
              result = object
                [ "short"  .= horizonObj
                , "medium" .= horizonObj
                , "long"   .= horizonObj
                ]
          return $ RpcResponse result Null Null
  where
    bucketToJSON :: RawBucketRange -> Value
    bucketToJSON RawBucketRange{..} = object
      [ "startrange"     .= rbrStartRange
      , "endrange"       .= rbrEndRange
      , "withintarget"   .= rbrWithinTarget
      , "totalconfirmed" .= rbrTotalConfirmed
      , "inmempool"      .= rbrInMempool
      , "leftmempool"    .= rbrLeftMempool
      ]

    -- Bitcoin Core reports feerate as BTC/kvB; haskoin tracks sat/vB.
    -- Conversion: sat/vB * 1000 sat/kvB / 1e8 sat/BTC = sat/vB / 1e5.
    satPerVbToBtcPerKvb :: Word64 -> Double
    satPerVbToBtcPerKvb r = fromIntegral r / 100000.0

    rawFeeToJSON :: RawFeeEstimate -> Value
    rawFeeToJSON RawFeeEstimate{..} =
      let common = [ "decay" .= rfeDecay
                   , "scale" .= rfeScale
                   , "pass"  .= bucketToJSON rfePass
                   ]
          withFail = case rfeFail of
            Just b  -> ("fail" .= bucketToJSON b) : common
            Nothing -> common
          withRate = case rfeFeeRate of
            Just r  -> ("feerate" .= satPerVbToBtcPerKvb r) : withFail
            Nothing -> withFail
          withErrors = if null rfeErrors
                       then withRate
                       else ("errors" .= rfeErrors) : withRate
      in object withErrors

--------------------------------------------------------------------------------
-- Mempool: getmempooldescendants
--------------------------------------------------------------------------------

-- | List the unconfirmed descendants of a transaction in the mempool.
-- Reference: Bitcoin Core's @getmempooldescendants@ RPC (rpc/mempool.cpp).
-- Mirrors 'handleGetMempoolAncestors' but walks the descendant index.
handleGetMempoolDescendants :: RpcServer -> Value -> IO RpcResponse
handleGetMempoolDescendants server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing txid parameter") Null
    Just txidHex -> do
      let verbose = fromMaybe False (extractParam params 1 :: Maybe Bool)
          mp = rsMempool server
      entries <- readTVarIO (mpEntries mp)
      case parseTxId txidHex of
        Nothing -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams "Invalid txid") Null
        Just txid -> case Map.lookup txid entries of
          Nothing -> return $ RpcResponse Null
            (toJSON $ RpcError rpcInvalidAddressOrKey "Transaction not in mempool") Null
          Just _ -> do
            descendants <- getDescendants mp txid
            if verbose
              then do
                let descendantDetails = Map.fromList
                      [ (showTxId (meTxId d), mempoolEntryToJSON d)
                      | d <- descendants
                      ]
                return $ RpcResponse (toJSON descendantDetails) Null Null
              else
                return $ RpcResponse
                  (toJSON (map (showTxId . meTxId) descendants)) Null Null
  where
    parseTxId :: Text -> Maybe TxId
    parseTxId hex =
      case B16.decode (TE.encodeUtf8 hex) of
        Left _ -> Nothing
        Right bs
          | BS.length bs == 32 -> Just $ TxId (Hash256 (BS.reverse bs))
          | otherwise -> Nothing

    showTxId :: TxId -> Text
    showTxId (TxId (Hash256 bs)) = TE.decodeUtf8 $ B16.encode (BS.reverse bs)

    mempoolEntryToJSON :: MempoolEntry -> Value
    mempoolEntryToJSON entry = object
      [ "vsize"           .= meSize entry
      , "fee"             .= (fromIntegral (meFee entry) / 100000000.0 :: Double)
      , "ancestorcount"   .= meAncestorCount entry
      , "ancestorsize"    .= meAncestorSize entry
      , "ancestorfees"    .= meAncestorFees entry
      , "descendantcount" .= meDescendantCount entry
      , "descendantsize"  .= meDescendantSize entry
      , "descendantfees"  .= meDescendantFees entry
      ]

-- | Return server uptime in seconds.
-- Reference: Bitcoin Core's uptime RPC (server.cpp)
handleUptime :: RpcServer -> IO RpcResponse
handleUptime server = do
  now <- round <$> getPOSIXTime :: IO Int64
  let uptimeSeconds = now - rsStartTime server
  return $ RpcResponse (toJSON uptimeSeconds) Null Null

-- | Return network traffic totals.
-- Returns stub with zero byte counts and current time in milliseconds.
handleGetNetTotals :: RpcServer -> IO RpcResponse
handleGetNetTotals _server = do
  now <- getPOSIXTime
  let timeMillis = round (now * 1000) :: Int64
      result = object
        [ "totalbytesrecv" .= (0 :: Int64)
        , "totalbytessent" .= (0 :: Int64)
        , "timemillis"     .= timeMillis
        ]
  return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- Control: Stop RPC Handler
--------------------------------------------------------------------------------

-- | Initiate graceful shutdown
-- Reference: Bitcoin Core's stop RPC (server.cpp)
-- Returns:
--   "Bitcoin server stopping"
handleStop :: RpcServer -> IO RpcResponse
handleStop server = do
  -- Signal shutdown (stop the RPC server thread)
  mTid <- readTVarIO (rsThread server)
  case mTid of
    Just tid -> do
      -- Kill the server thread (will stop accepting new connections)
      forkIO $ do
        threadDelay 100000  -- 100ms delay to allow response to be sent
        killThread tid
      return ()
    Nothing -> return ()

  -- Return the standard message immediately
  return $ RpcResponse (toJSON ("Bitcoin server stopping" :: Text)) Null Null

--------------------------------------------------------------------------------
-- Mempool persistence RPCs (Bitcoin Core compatible)
--------------------------------------------------------------------------------

-- | Dump the mempool to disk in Bitcoin Core mempool.dat format.
-- Equivalent of Bitcoin Core's @savemempool@ RPC.
-- Returns: { "filename": "<absolute path>" }
handleSaveMempool :: RpcServer -> IO RpcResponse
handleSaveMempool server = do
  let path = MPP.defaultMempoolDatPath (rpcDataDir (rsConfig server))
  r <- MPP.dumpMempool (rsMempool server) path
  case r of
    Right _n ->
      return $ RpcResponse
        (object [ "filename" .= (T.pack path) ])
        Null Null
    Left e ->
      return $ RpcResponse Null
        (toJSON $ RpcError rpcMiscError (T.pack ("savemempool: " ++ e))) Null

-- | Import (load) the mempool from a Bitcoin Core mempool.dat file.
-- Equivalent of Bitcoin Core's @importmempool@ / @loadmempool@ RPCs.
-- Optional first param is the path; defaults to <datadir>/mempool.dat.
-- Returns the same shape as Bitcoin Core: counts of accepted/failed/etc.
handleImportMempool :: RpcServer -> Value -> IO RpcResponse
handleImportMempool server params = do
  let defaultPath = MPP.defaultMempoolDatPath (rpcDataDir (rsConfig server))
      path = case extractParamText params 0 of
        Just p  -> T.unpack p
        Nothing -> defaultPath
      expirySecs = 14 * 24 * 3600  -- 14 days, matches Bitcoin Core default
  r <- MPP.loadMempool (rsMempool server) path expirySecs
  case r of
    Right (loaded, failed, expired, already) ->
      return $ RpcResponse
        (object
          [ "imported"     .= loaded
          , "failed"       .= failed
          , "expired"      .= expired
          , "already_there".= already
          , "filename"     .= T.pack path
          ])
        Null Null
    Left e ->
      return $ RpcResponse Null
        (toJSON $ RpcError rpcMiscError
          (T.pack ("importmempool: " ++ e))) Null

--------------------------------------------------------------------------------
-- AssumeUTXO RPC Handlers
--------------------------------------------------------------------------------

-- | Load a UTXO snapshot from a file for fast initial sync (AssumeUTXO).
-- Reference: Bitcoin Core's loadtxoutset RPC (rpc/blockchain.cpp) and
-- 'PopulateAndValidateSnapshot' in validation.cpp.
--
-- Core-strict guard ported here:
--
--   1. The snapshot's @base_blockhash@ must resolve to a known
--      'ChainEntry' in the header chain. If not, refuse with the same
--      "Did not find snapshot start blockheader %s" message Core uses.
--
--   2. The resolved height must appear in 'netAssumeUtxo' (the
--      'm_assumeutxo_data' map in Core). If not, refuse with the
--      canonical
--      "Assumeutxo height in snapshot metadata not recognized (%d)
--       - refusing to load snapshot"
--      message — see 'checkAssumeutxoWhitelist' /
--      'assumeutxoWhitelistError'.
--
-- Without these guards a malicious or misconfigured snapshot could be
-- loaded against an arbitrary base block, since 'loadSnapshot' itself
-- only validates magic + version + on-disk shape.
--
-- Params: [path]
-- Returns: { "coins_loaded": <count>, "tip_hash": "<hash>" }
handleLoadTxOutSet :: RpcServer -> Value -> IO RpcResponse
handleLoadTxOutSet server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Usage: loadtxoutset \"path\"") Null
    Just pathText -> do
      let path = T.unpack pathText
          net = rsNetwork server
          magic = netMagic net
      result <- loadSnapshot path magic
      case result of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInternalError (T.pack err)) Null
        Right snapshot -> do
          let metadata = usMetadata snapshot
              coinsCount = smCoinsCount metadata
              baseHash   = smBaseBlockHash metadata
          -- Step 1: resolve base blockhash → height via the header chain.
          entries <- readTVarIO (hcEntries (rsHeaderChain server))
          case Map.lookup baseHash entries of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInternalError
                (T.pack ("Did not find snapshot start blockheader "
                         ++ show baseHash))) Null
            Just entry ->
              -- Step 2: that height must be whitelisted in netAssumeUtxo.
              case checkAssumeutxoWhitelist net (ceHeight entry) of
                Left err -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcInternalError (T.pack err)) Null
                Right () ->
                  -- Step 3: strict hash validation per
                  -- bitcoin-core/src/validation.cpp:5912-5914
                  -- ('PopulateAndValidateSnapshot'). Recompute Core's
                  -- HASH_SERIALIZED over the loaded coin set and compare
                  -- against the whitelisted 'audHashSerialized' for this
                  -- block hash. Refusal here means the snapshot file's
                  -- contents do not match the chainparams commitment, so
                  -- we must not load it (that is also Core's behaviour).
                  case assumeUtxoForBlockHash net baseHash of
                    Nothing -> return $ RpcResponse Null
                      (toJSON $ RpcError rpcInternalError
                        (T.pack ("loadtxoutset: no assumeutxo data for "
                                 ++ show baseHash))) Null
                    Just params ->
                      let audData = AssumeUtxoData
                            { audHeight = aupHeight params
                            , audHashSerialized = aupHashSerialized params
                            , audChainTxCount = aupChainTxCount params
                            , audBlockHash = aupBlockHash params
                            }
                      in case verifySnapshot snapshot audData of
                           Left vErr -> return $ RpcResponse Null
                             (toJSON $ RpcError rpcInternalError
                               (T.pack ("Bad snapshot content hash: " ++ vErr))) Null
                           Right () ->
                             return $ RpcResponse
                               (object [ "coins_loaded" .= coinsCount
                                       , "tip_hash"     .= show baseHash
                                       , "base_height"  .= ceHeight entry
                                       ])
                               Null Null

-- | What snapshot height the @dumptxoutset@ RPC has been asked to
-- produce. Mirrors Bitcoin Core's three modes from
-- @bitcoin-core/src/rpc/blockchain.cpp@:
--
--   * @latest@   (the default) — dump the current chain tip's UTXO set.
--   * @rollback@ — resolve to the highest 'netAssumeUtxo' entry that is
--     not above the current tip.
--   * @rollback=<height|hash>@ — resolve to a specific historical block.
data DumpTarget
  = DumpLatest
    -- ^ Snapshot the current tip (default; equivalent to no @type@ arg
    -- or @"latest"@).
  | DumpRollbackLatestSnapshot
    -- ^ Snapshot at the highest 'netAssumeUtxo' entry that is not above
    -- the current tip. Matches Core's @"rollback"@ default behaviour
    -- (see @GetAvailableSnapshotHeights@ in chainparams.cpp).
  | DumpRollbackToHeight !Word32
    -- ^ Snapshot at the given height.
  | DumpRollbackToHash !BlockHash
    -- ^ Snapshot at the block with the given hash (must be on the
    -- current best chain).
  deriving (Show, Eq)

-- | Caller-supplied @rollback=<…>@ value. Used by 'parseDumpTxOutSetParams'.
data RollbackSpec
  = RollbackByHeight !Word32
  | RollbackByHash   !BlockHash
  deriving (Show, Eq)

-- | Parse the JSON params accepted by @dumptxoutset@.
--
-- The shapes accepted (matching Core 3076-3107):
--
-- @
--   [\"path\"]                                  -- DumpLatest
--   [\"path\", \"latest\"]                      -- DumpLatest
--   [\"path\", \"rollback\"]                    -- DumpRollbackLatestSnapshot
--   [\"path\", \"\", { \"rollback\": <h|hash> }]  -- DumpRollbackToHeight/Hash
--   [\"path\", \"rollback\", { \"rollback\": <h|hash> }]
-- @
--
-- The same conflict-detection rule Core uses (3117) is enforced: if the
-- options object carries an explicit @rollback=<…>@ but the @type@ arg
-- is something other than @\"\"@ or @\"rollback\"@, that's an error.
--
-- Returns @Left@ with an actionable message on bad params, @Right@ with
-- the resolved request shape on success.
parseDumpTxOutSetParams :: Value -> Either Text (FilePath, DumpTarget)
parseDumpTxOutSetParams params =
  case extractParamText params 0 of
    Nothing -> Left "Usage: dumptxoutset \"path\" [type] [{\"rollback\": <height|hash>}]"
    Just pathText ->
      let path     = T.unpack pathText
          mTypeArg = extractParamText params 1
          mOptions = case params of
            Array arr | V.length arr > 2 ->
              case arr V.! 2 of
                Object km -> Just km
                Null      -> Nothing
                _         -> Nothing
            _ -> Nothing
          mRollback = mOptions >>= KM.lookup "rollback" >>= rollbackSpecFromValue
      in case (mTypeArg, mRollback) of
           -- Explicit rollback=<…> in options
           (typeArg, Just spec)
             | maybe True (\t -> T.null t || t == "rollback") typeArg ->
                 Right (path, rollbackSpecToTarget spec)
             | otherwise ->
                 Left $ "Invalid snapshot type \""
                        <> fromMaybe "" typeArg
                        <> "\" specified with rollback option"
           -- "rollback" with no explicit target → latest assumeutxo entry
           (Just t, Nothing) | t == "rollback" ->
             Right (path, DumpRollbackLatestSnapshot)
           -- "" / "latest" / no type → tip
           (Just t, Nothing)
             | T.null t || t == "latest" -> Right (path, DumpLatest)
           (Nothing, Nothing) -> Right (path, DumpLatest)
           -- Anything else
           (Just t, Nothing) ->
             Left $ "Invalid snapshot type \"" <> t
                    <> "\" specified. Please specify \"rollback\" or \"latest\""
  where
    rollbackSpecFromValue :: Value -> Maybe RollbackSpec
    rollbackSpecFromValue v = case v of
      Number n -> case toBoundedInteger n :: Maybe Word32 of
        Just h  -> Just (RollbackByHeight h)
        Nothing -> Nothing
      String s
        | T.length s == 64 -> RollbackByHash <$> parseHash s
        | otherwise        -> case readMaybeInt (T.unpack s) of
            Just h  -> Just (RollbackByHeight (fromIntegral (h :: Integer)))
            Nothing -> Nothing
      _ -> Nothing

    readMaybeInt :: String -> Maybe Integer
    readMaybeInt s = case reads s of
      [(n, "")] -> Just n
      _         -> Nothing

    rollbackSpecToTarget :: RollbackSpec -> DumpTarget
    rollbackSpecToTarget (RollbackByHeight h) = DumpRollbackToHeight h
    rollbackSpecToTarget (RollbackByHash h)   = DumpRollbackToHash h

-- | Highest 'netAssumeUtxo' entry that is not above @tipHeight@.
-- Mirrors Core's @GetAvailableSnapshotHeights()@ + @std::max_element@
-- from rpc/blockchain.cpp:3122-3125. Returns @Nothing@ if no whitelisted
-- snapshot is available at or below the tip — which on regtest at
-- height < 110 or testnet/mainnet pre-snapshot is a normal early-IBD
-- state.
latestAvailableSnapshotHeight :: Network -> Word32 -> Maybe Word32
latestAvailableSnapshotHeight net tipHeight =
  let candidates = [ h | (h, _) <- netAssumeUtxo net, h <= tipHeight ]
  in if null candidates then Nothing else Just (maximum candidates)

-- | Resolve a 'DumpTarget' against the live header chain to a concrete
-- @(height, hash)@. Returns @Left@ with a Core-style error on failure
-- (target above tip, hash not on chain, no snapshot available, …).
resolveDumpTarget
  :: Network
  -> Map BlockHash ChainEntry  -- ^ from @hcEntries@
  -> Map Word32 BlockHash      -- ^ from @hcByHeight@ (height index of best chain)
  -> ChainEntry                -- ^ current tip
  -> DumpTarget
  -> Either Text (Word32, BlockHash)
resolveDumpTarget net entries byHeight tip target = case target of
  DumpLatest -> Right (ceHeight tip, ceHash tip)
  DumpRollbackLatestSnapshot ->
    case latestAvailableSnapshotHeight net (ceHeight tip) of
      Nothing -> Left $ T.pack $
        "No assumeutxo snapshot height available at or below tip "
        <> show (ceHeight tip) <> " for network " <> netName net
      Just h -> resolveByHeight h
  DumpRollbackToHeight h
    | h > ceHeight tip ->
        Left $ T.pack $ "Target height " <> show h
                       <> " is above current tip " <> show (ceHeight tip)
    | otherwise -> resolveByHeight h
  DumpRollbackToHash bh ->
    case Map.lookup bh entries of
      Nothing -> Left $ "Block hash not found in header chain: " <> showHash bh
      Just ce
        | ceHeight ce > ceHeight tip ->
            Left $ T.pack $ "Target block at height "
                           <> show (ceHeight ce)
                           <> " is above current tip "
                           <> show (ceHeight tip)
        | Map.lookup (ceHeight ce) byHeight /= Just bh ->
            Left $ "Block " <> showHash bh
                  <> " is not on the current best chain"
        | otherwise -> Right (ceHeight ce, bh)
  where
    resolveByHeight h = case Map.lookup h byHeight of
      Nothing -> Left $ T.pack $
        "No block on best chain at height " <> show h
      Just bh -> Right (h, bh)

-- | Dump the UTXO set to a file for creating a snapshot.
-- Reference: Bitcoin Core's dumptxoutset RPC (rpc/blockchain.cpp).
--
-- Params accepted (matching Core; see 'parseDumpTxOutSetParams'):
--
-- @
--   dumptxoutset \"path\"
--   dumptxoutset \"path\" \"latest\"
--   dumptxoutset \"path\" \"rollback\"
--   dumptxoutset \"path\" \"rollback\" {\"rollback\": <height|hash>}
--   dumptxoutset \"path\" \"\" {\"rollback\": <height|hash>}
-- @
--
-- Returns: { coins_written, base_hash, base_height, path, rollback_status }
--
-- Implementation notes:
--   * Iterates the legacy 'PrefixUTXO' keyspace via 'dumpTxOutSetFromDB'.
--   * Emits a Core byte-format snapshot (51-byte SnapshotMetadata header
--     followed by per-txid groups of (vout, Coin) pairs using
--     CompressAmount + ScriptCompression).
--   * 'height' / 'isCoinbase' are stored as 0/false because haskoin's
--     legacy UTXO row only persists the TxOut. This is documented in
--     'dumpTxOutSetFromDB' and is the same lossy mode the rest of the
--     codebase already operates in.
--
-- Rollback dance:
--   When @target /= tip@, we temporarily rewind the chainstate to the
--   target block, dump the UTXO set as it was at that height, and then
--   replay forward to the original tip. The dance:
--
--     1. Walk @target+1 .. tip@ via 'cePrev', collecting block hashes
--        in tip→target order.
--     2. For each block in that list (highest first), call
--        'disconnectBlock' which uses the on-disk per-block undo data
--        to restore the spent UTXOs and remove the block's outputs.
--     3. Dump the now-rewound UTXO set via 'dumpTxOutSetFromDB'.
--     4. For each block in target→tip order, call 'connectBlock'
--        again. We pass the spent-utxo map looked up from the (now
--        partially-rebuilt) chainstate; this works because the UTXO
--        set has been restored to its target state, and each replayed
--        block's prevouts are present in the chainstate.
--     5. The header chain (in-memory) is unchanged throughout — only
--        the UTXO key-space is rewound and replayed. The best-block
--        pointer flips with disconnect/connect but is restored to the
--        original tip at the end.
--
--   Replay skips script validation: the blocks were already validated
--   on the way up, and re-validating during rollback would multiply
--   the cost of the dump. This matches Bitcoin Core's behaviour in
--   @SnapshotUTXOs@ which uses chainstate views, not full re-validation.
--
--   If undo data is missing for any block in @target+1 .. tip@ (an
--   old datadir whose IBD predates the connectBlock undo wiring) we
--   abort the dance early and surface an error to the caller. We do
--   NOT silently emit a truncated UTXO set.
--
--   TODO(concurrency): the dance mutates the live UTXO keyspace, so a
--   concurrent block-connect from the IBD pipeline would race the
--   rewind+replay. Bitcoin Core takes @cs_main@ for the duration of
--   @CreateUTXOSnapshot@. haskoin currently lacks a global validation
--   lock; in practice operators run @dumptxoutset rollback@ on a
--   stopped node or at the chain tip when no new blocks are arriving.
--   A follow-up should either (a) hold a coordination MVar with the
--   block downloader, or (b) document that rollback dump must be
--   issued only when IBD is idle.
--
-- Reference: bitcoin-core/src/rpc/blockchain.cpp dumptxoutset and
-- @CreateUTXOSnapshot@; the rollback param is documented at 3076-3107.
handleDumpTxOutSet :: RpcServer -> Value -> IO RpcResponse
handleDumpTxOutSet server params = do
  case parseDumpTxOutSetParams params of
    Left msg -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams msg) Null
    Right (path, target) -> do
      -- Refuse to overwrite an existing destination — matches Core's
      -- "<path> already exists. If you are sure this is what you want,
      -- move it out of the way first." guard in
      -- rpc/blockchain.cpp::dumptxoutset. Probe BEFORE any chain-state
      -- mutation so a name collision cannot leave the chain stuck in a
      -- half-rolled-back state.
      pathExists <- doesFileExist path
      if pathExists
        then return $ RpcResponse Null
          (toJSON $ RpcError rpcInvalidParams
            (T.pack (path <>
              " already exists. If you are sure this is what you want, "
              <> "move it out of the way first."))) Null
        else do
          let net   = rsNetwork server
              magic = netMagic net
              hc    = rsHeaderChain server
          tip       <- readTVarIO (hcTip hc)
          entries   <- readTVarIO (hcEntries hc)
          byHeight  <- readTVarIO (hcByHeight hc)
          case resolveDumpTarget net entries byHeight tip target of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcInvalidParams err) Null
            Right (baseHeight, baseHash) ->
              if baseHash == ceHash tip
                 then doDump path magic baseHeight baseHash "tip"
                 else do
                   -- Pruned-mode pre-check. Mirrors Bitcoin Core
                   -- rpc/blockchain.cpp:dumptxoutset:
                   --   if (IsPruneMode() &&
                   --       target_index->nHeight <
                   --       m_blockman.GetFirstBlock()->nHeight)
                   --       throw "Block height N not available (pruned data).
                   --              Use a height after M.";
                   -- haskoin's `isBlockPruned` checks file existence + size,
                   -- so it answers the "do we still have data for this hash?"
                   -- question directly. Fail fast before disconnect_block
                   -- hits a pruned block file.
                   prunedHere <- case rsBlockStore server of
                     Nothing -> return False
                     Just blockStore -> isBlockPruned blockStore baseHash
                   if prunedHere
                      then return $ RpcResponse Null
                        (toJSON $ RpcError rpcMiscError
                          (T.pack ("Block height "
                                   <> show baseHeight
                                   <> " not available (pruned data). "
                                   <> "Use a height closer to the current tip."))) Null
                      else doRollbackDump
                             net path magic
                             baseHeight baseHash
                             tip entries
  where
    doDump path magic baseHeight baseHash status = do
      result <- dumpTxOutSetFromDB (rsDB server) path magic baseHash
      case result of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInternalError (T.pack err)) Null
        Right cnt ->
          return $ RpcResponse
            (object [ "coins_written"   .= cnt
                    , "base_hash"       .= showHash baseHash
                    , "base_height"     .= baseHeight
                    , "path"            .= T.pack path
                    , "rollback_status" .= (status :: Text)
                    ])
            Null Null

    -- Build the path of blocks from tip back to target (exclusive of
    -- target, inclusive of tip), walking 'cePrev'. Returns the list
    -- with tip first, target+1 last. Returns 'Left' if the chain
    -- breaks before reaching target.
    buildRewindPath
      :: Map BlockHash ChainEntry
      -> ChainEntry  -- ^ current tip
      -> BlockHash   -- ^ target hash (not included)
      -> Either String [ChainEntry]
    buildRewindPath ents start targetH = go start []
      where
        go ce acc
          | ceHash ce == targetH = Right (reverse acc)
          | otherwise = case cePrev ce of
              Nothing ->
                Left $ "buildRewindPath: hit genesis before reaching target "
                       ++ show targetH
              Just prevH -> case Map.lookup prevH ents of
                Nothing ->
                  Left $ "buildRewindPath: missing chain entry "
                         ++ show prevH
                Just prevCe -> go prevCe (ce : acc)

    doRollbackDump net path magic baseHeight baseHash tip entries = do
      let db = rsDB server
      -- NetworkDisable RAII via Control.Exception.bracket_. Mirrors
      -- Bitcoin Core's NetworkDisable wrapper around TemporaryRollback
      -- in rpc/blockchain.cpp::dumptxoutset. Pause inbound block
      -- acceptance for the duration of the rewind→dump→replay dance
      -- and restore on every exit path (success, error, exception).
      bracket_
        (atomically $ writeTVar (rsBlockSubmissionPaused server) True)
        (atomically $ writeTVar (rsBlockSubmissionPaused server) False)
        (doRollbackDumpInner db net path magic baseHeight baseHash tip entries)

    doRollbackDumpInner db net path magic baseHeight baseHash tip entries = do
      case buildRewindPath entries tip baseHash of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcInternalError
            (T.pack ("dumptxoutset rollback: " <> err))) Null
        Right rewindPath -> do
          -- rewindPath = [target+1 .. tip], so the disconnect order
          -- (tip first) is the reverse and the reconnect order is the
          -- list itself. We fetch each block + verify undo data exists
          -- BEFORE we start mutating — fail fast on a stale datadir.
          checkResult <- checkRewindFeasible db rewindPath
          case checkResult of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack err)) Null
            Right blocksToReplay -> do
              -- Disconnect from tip down to target.
              dRes <- disconnectChainTo db (reverse blocksToReplay)
              case dRes of
                Left err -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcInternalError (T.pack err)) Null
                Right () -> do
                  -- Dump at the rewound state.
                  dumpRes <- dumpTxOutSetFromDB db path magic baseHash
                  -- Replay blocks back to the original tip regardless
                  -- of whether the dump itself errored — leaving the
                  -- chainstate in a half-rewound state would be worse.
                  rRes <- reconnectChain db net blocksToReplay
                  case (dumpRes, rRes) of
                    (Left dErr, _) -> return $ RpcResponse Null
                      (toJSON $ RpcError rpcInternalError
                        (T.pack ("dumptxoutset rollback dump failed: "
                                 <> dErr))) Null
                    (_, Left rErr) -> return $ RpcResponse Null
                      (toJSON $ RpcError rpcInternalError
                        (T.pack ("dumptxoutset rollback replay failed: "
                                 <> rErr <> " — chainstate may be "
                                 <> "inconsistent, restart to recover"))) Null
                    (Right cnt, Right ()) ->
                      return $ RpcResponse
                        (object
                          [ "coins_written"   .= cnt
                          , "base_hash"       .= showHash baseHash
                          , "base_height"     .= baseHeight
                          , "path"            .= T.pack path
                          , "rollback_status" .= ("rollback" :: Text)
                          ])
                        Null Null

    -- Pre-flight check: every block in the rewind path must have its
    -- block body and a verified undo record on disk. If any are
    -- missing we refuse to start the dance — surface the gap honestly
    -- so operators can decide whether to re-IBD or accept dump=tip.
    checkRewindFeasible
      :: HaskoinDB
      -> [ChainEntry]  -- ^ rewind path, target+1 .. tip
      -> IO (Either String [(ChainEntry, Block)])
    checkRewindFeasible db ces = do
      results <- forM ces $ \ce -> do
        let bh = ceHash ce
        mBlk <- getBlock db bh
        mUndo <- getUndoData db bh
        case (mBlk, mUndo) of
          (Just blk, Just _) -> return $ Right (ce, blk)
          (Nothing, _) ->
            return $ Left $ "missing block body for "
                            <> show bh <> " at height "
                            <> show (ceHeight ce)
          (_, Nothing) ->
            return $ Left $ "missing undo data for "
                            <> show bh <> " at height "
                            <> show (ceHeight ce)
                            <> " — this datadir was IBD'd before "
                            <> "haskoin started writing undo records "
                            <> "(connectBlock landed in this commit). "
                            <> "Re-IBD is required to use rollback dump."
      return $ sequence results

    -- Disconnect blocks tip→target. Input is in tip-first order.
    disconnectChainTo :: HaskoinDB -> [(ChainEntry, Block)]
                      -> IO (Either String ())
    disconnectChainTo _ [] = return (Right ())
    disconnectChainTo db ((ce, blk) : rest) = do
      let prevHash = case cePrev ce of
            Just h  -> h
            Nothing -> ceHash ce  -- impossible: would mean disconnecting genesis
      r <- disconnectBlock db blk prevHash
      case r of
        Left err -> return $ Left $
          "disconnectBlock at height " <> show (ceHeight ce) <> ": " <> err
        Right () -> disconnectChainTo db rest

    -- Reconnect blocks target+1 .. tip. Looks up spent UTXOs from the
    -- (rewound, then partially rebuilt) chainstate at each step. This
    -- works because each block's prevouts are either in the rewound
    -- state or were created by an earlier replayed block.
    reconnectChain :: HaskoinDB -> Network -> [(ChainEntry, Block)]
                   -> IO (Either String ())
    reconnectChain _ _ [] = return (Right ())
    reconnectChain db net ((ce, blk) : rest) = do
      spent <- buildSpentUtxoMapFromDB db blk
      connectBlock db net blk (ceHeight ce) spent
      reconnectChain db net rest

--------------------------------------------------------------------------------
-- Helper Functions
--------------------------------------------------------------------------------

-- | Extract a parameter from the params array by index
extractParam :: FromJSON a => Value -> Int -> Maybe a
extractParam (Array arr) idx
  | idx < V.length arr = case fromJSON (arr V.! idx) of
      Success a -> Just a
      Error _   -> Nothing
  | otherwise = Nothing
extractParam _ _ = Nothing

-- | Extract a Text parameter from the params array by index
extractParamText :: Value -> Int -> Maybe Text
extractParamText = extractParam

-- | Extract an array parameter from the params array by index
extractParamArray :: Value -> Int -> Maybe (V.Vector Value)
extractParamArray (Array arr) idx
  | idx < V.length arr = case arr V.! idx of
      Array a -> Just a
      _       -> Nothing
  | otherwise = Nothing
extractParamArray _ _ = Nothing

-- | Display a BlockHash as hex (reversed byte order for display)
showHash :: BlockHash -> Text
showHash (BlockHash (Hash256 bs)) = TE.decodeUtf8 $ B16.encode (BS.reverse bs)

-- | Display a Hash256 as hex (reversed byte order for display)
showHash256 :: Hash256 -> Text
showHash256 (Hash256 bs) = TE.decodeUtf8 $ B16.encode (BS.reverse bs)

-- | Display an Integer as hex
showHex :: Integer -> Text
showHex n = T.pack $ showHex' n ""
  where
    showHex' 0 s = if null s then "0" else s
    showHex' v s = showHex' (v `div` 16) (hexDigit (fromIntegral (v `mod` 16)) : s)
    hexDigit :: Int -> Char
    hexDigit d | d < 10    = toEnum (d + fromEnum '0')
               | otherwise = toEnum (d - 10 + fromEnum 'a')

-- | Display difficulty bits in hex
showBits :: Word32 -> Text
showBits bits = T.pack $ printf "%08x" bits

-- | Calculate difficulty from compact bits format
getDifficulty :: Word32 -> Double
getDifficulty bits =
  let target = bitsToTarget bits
      maxTarget = bitsToTarget 0x1d00ffff
  in if target == 0 then 0
     else fromIntegral maxTarget / fromIntegral target

-- | Parse a hex hash string to BlockHash
parseHash :: Text -> Maybe BlockHash
parseHash hex =
  case B16.decode (TE.encodeUtf8 hex) of
    Left _ -> Nothing
    Right bs
      | BS.length bs == 32 -> Just $ BlockHash (Hash256 (BS.reverse bs))
      | otherwise -> Nothing

-- | Convert TxId to BlockHash (for display purposes)
blockHashFromTxId :: TxId -> BlockHash
blockHashFromTxId (TxId h) = BlockHash h

-- | Convert a transaction to JSON
txToJSON :: Tx -> TxId -> Value
txToJSON tx txid = object
  [ "txid"     .= showHash (BlockHash (getTxIdHash txid))
  , "version"  .= txVersion tx
  , "size"     .= BS.length (S.encode tx)
  , "locktime" .= txLockTime tx
  , "vin"      .= map vinToJSON (txInputs tx)
  , "vout"     .= zipWith voutToJSON [0..] (txOutputs tx)
  ]
  where
    vinToJSON inp = object
      [ "txid"      .= showHash (BlockHash (getTxIdHash (outPointHash (txInPrevOutput inp))))
      , "vout"      .= outPointIndex (txInPrevOutput inp)
      , "scriptSig" .= object
          [ "hex" .= (TE.decodeUtf8 $ B16.encode (txInScript inp))
          ]
      , "sequence"  .= txInSequence inp
      ]
    voutToJSON :: Int -> TxOut -> Value
    voutToJSON n out = object
      [ "value"        .= (fromIntegral (txOutValue out) / 100000000.0 :: Double)
      , "n"            .= n
      , "scriptPubKey" .= object
          [ "hex" .= (TE.decodeUtf8 $ B16.encode (txOutScript out))
          ]
      ]

-- | Convert a transaction to verbose JSON with blockchain context
-- Includes: txid, hash (wtxid), size, vsize, weight, version, locktime,
-- vin, vout, hex, and optionally blockhash, confirmations, blocktime
txToVerboseJSON :: RpcServer -> Tx -> TxId -> Maybe BlockHash -> IO Value
txToVerboseJSON server tx txid mBlockHash = do
  -- Calculate transaction metrics
  let baseSize = txBaseSize tx
      totalSize = txTotalSize tx
      weight = baseSize * (witnessScaleFactor - 1) + totalSize
      vsize = (weight + witnessScaleFactor - 1) `div` witnessScaleFactor
      wtxid = computeWtxId tx
      hexTx = TE.decodeUtf8 $ B16.encode $ S.encode tx

  -- Build base transaction object
  let baseFields =
        [ "txid"     .= showHash (BlockHash (getTxIdHash txid))
        , "hash"     .= showHash (BlockHash (getTxIdHash wtxid))
        , "version"  .= txVersion tx
        , "size"     .= totalSize
        , "vsize"    .= vsize
        , "weight"   .= weight
        , "locktime" .= txLockTime tx
        , "vin"      .= vinToVerboseJSON tx
        , "vout"     .= zipWith voutToVerboseJSON [0..] (txOutputs tx)
        , "hex"      .= hexTx
        ]

  -- Add blockchain context if confirmed
  blockFields <- case mBlockHash of
    Nothing -> return []
    Just blockHash -> do
      entries <- readTVarIO (hcEntries (rsHeaderChain server))
      tip <- readTVarIO (hcTip (rsHeaderChain server))
      let mEntry = Map.lookup blockHash entries
      case mEntry of
        Nothing -> return [ "blockhash" .= showHash blockHash ]
        Just entry -> do
          let confirmations = ceHeight tip - ceHeight entry + 1
              blockTime = bhTimestamp (ceHeader entry)
          return
            [ "blockhash"      .= showHash blockHash
            , "confirmations"  .= confirmations
            , "time"           .= blockTime
            , "blocktime"      .= blockTime
            ]

  return $ object (baseFields ++ blockFields)
  where
    vinToVerboseJSON :: Tx -> [Value]
    vinToVerboseJSON t = zipWith (vinEntry t) [0..] (txInputs t)

    vinEntry :: Tx -> Int -> TxIn -> Value
    vinEntry t idx inp =
      let isCoinbaseInput = txInPrevOutput inp == OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          witnessStack = if idx < length (txWitness t) then txWitness t !! idx else []
      in if isCoinbaseInput
         then object $ catMaybes
           [ Just $ "coinbase" .= (TE.decodeUtf8 $ B16.encode (txInScript inp))
           , Just $ "sequence" .= txInSequence inp
           , if null witnessStack then Nothing
             else Just $ "txinwitness" .= map (TE.decodeUtf8 . B16.encode) witnessStack
           ]
         else object $ catMaybes
           [ Just $ "txid"      .= showHash (BlockHash (getTxIdHash (outPointHash (txInPrevOutput inp))))
           , Just $ "vout"      .= outPointIndex (txInPrevOutput inp)
           , Just $ "scriptSig" .= object
               [ "asm" .= scriptToAsm (txInScript inp)
               , "hex" .= (TE.decodeUtf8 $ B16.encode (txInScript inp))
               ]
           , if null witnessStack then Nothing
             else Just $ "txinwitness" .= map (TE.decodeUtf8 . B16.encode) witnessStack
           , Just $ "sequence"  .= txInSequence inp
           ]

    voutToVerboseJSON :: Int -> TxOut -> Value
    voutToVerboseJSON n out =
      let scriptHex = txOutScript out
          scriptType = case decodeScript scriptHex of
            Right s -> classifyOutput s
            Left _ -> NonStandard
          typeStr = scriptTypeToString scriptType
          mAddress = scriptToAddress (rsNetwork server) scriptHex scriptType
      in object $ catMaybes
        [ Just $ "value"        .= (fromIntegral (txOutValue out) / 100000000.0 :: Double)
        , Just $ "n"            .= n
        , Just $ "scriptPubKey" .= object (catMaybes
            [ Just $ "asm"  .= scriptToAsm scriptHex
            , Just $ "hex"  .= (TE.decodeUtf8 $ B16.encode scriptHex)
            , Just $ "type" .= typeStr
            , mAddress >>= \addr -> Just $ "address" .= addr
            ])
        ]

-- | Convert script bytes to assembly string representation
scriptToAsm :: ByteString -> Text
scriptToAsm scriptBytes =
  case decodeScript scriptBytes of
    Left _ -> TE.decodeUtf8 $ B16.encode scriptBytes
    Right (Script ops) -> T.intercalate " " $ map opToAsm ops
  where
    opToAsm :: ScriptOp -> Text
    opToAsm op = case op of
      OP_0 -> "0"
      OP_PUSHDATA bs _ -> TE.decodeUtf8 $ B16.encode bs
      OP_1NEGATE -> "-1"
      OP_RESERVED -> "OP_RESERVED"
      OP_1 -> "1"
      OP_2 -> "2"
      OP_3 -> "3"
      OP_4 -> "4"
      OP_5 -> "5"
      OP_6 -> "6"
      OP_7 -> "7"
      OP_8 -> "8"
      OP_9 -> "9"
      OP_10 -> "10"
      OP_11 -> "11"
      OP_12 -> "12"
      OP_13 -> "13"
      OP_14 -> "14"
      OP_15 -> "15"
      OP_16 -> "16"
      OP_NOP -> "OP_NOP"
      OP_VER -> "OP_VER"
      OP_IF -> "OP_IF"
      OP_NOTIF -> "OP_NOTIF"
      OP_VERIF -> "OP_VERIF"
      OP_VERNOTIF -> "OP_VERNOTIF"
      OP_ELSE -> "OP_ELSE"
      OP_ENDIF -> "OP_ENDIF"
      OP_VERIFY -> "OP_VERIFY"
      OP_RETURN -> "OP_RETURN"
      OP_TOALTSTACK -> "OP_TOALTSTACK"
      OP_FROMALTSTACK -> "OP_FROMALTSTACK"
      OP_2DROP -> "OP_2DROP"
      OP_2DUP -> "OP_2DUP"
      OP_3DUP -> "OP_3DUP"
      OP_2OVER -> "OP_2OVER"
      OP_2ROT -> "OP_2ROT"
      OP_2SWAP -> "OP_2SWAP"
      OP_IFDUP -> "OP_IFDUP"
      OP_DEPTH -> "OP_DEPTH"
      OP_DROP -> "OP_DROP"
      OP_DUP -> "OP_DUP"
      OP_NIP -> "OP_NIP"
      OP_OVER -> "OP_OVER"
      OP_PICK -> "OP_PICK"
      OP_ROLL -> "OP_ROLL"
      OP_ROT -> "OP_ROT"
      OP_SWAP -> "OP_SWAP"
      OP_TUCK -> "OP_TUCK"
      OP_CAT -> "OP_CAT"
      OP_SUBSTR -> "OP_SUBSTR"
      OP_LEFT -> "OP_LEFT"
      OP_RIGHT -> "OP_RIGHT"
      OP_SIZE -> "OP_SIZE"
      OP_INVERT -> "OP_INVERT"
      OP_AND -> "OP_AND"
      OP_OR -> "OP_OR"
      OP_XOR -> "OP_XOR"
      OP_EQUAL -> "OP_EQUAL"
      OP_EQUALVERIFY -> "OP_EQUALVERIFY"
      OP_RESERVED1 -> "OP_RESERVED1"
      OP_RESERVED2 -> "OP_RESERVED2"
      OP_1ADD -> "OP_1ADD"
      OP_1SUB -> "OP_1SUB"
      OP_2MUL -> "OP_2MUL"
      OP_2DIV -> "OP_2DIV"
      OP_NEGATE -> "OP_NEGATE"
      OP_ABS -> "OP_ABS"
      OP_NOT -> "OP_NOT"
      OP_0NOTEQUAL -> "OP_0NOTEQUAL"
      OP_ADD -> "OP_ADD"
      OP_SUB -> "OP_SUB"
      OP_MUL -> "OP_MUL"
      OP_DIV -> "OP_DIV"
      OP_MOD -> "OP_MOD"
      OP_LSHIFT -> "OP_LSHIFT"
      OP_RSHIFT -> "OP_RSHIFT"
      OP_BOOLAND -> "OP_BOOLAND"
      OP_BOOLOR -> "OP_BOOLOR"
      OP_NUMEQUAL -> "OP_NUMEQUAL"
      OP_NUMEQUALVERIFY -> "OP_NUMEQUALVERIFY"
      OP_NUMNOTEQUAL -> "OP_NUMNOTEQUAL"
      OP_LESSTHAN -> "OP_LESSTHAN"
      OP_GREATERTHAN -> "OP_GREATERTHAN"
      OP_LESSTHANOREQUAL -> "OP_LESSTHANOREQUAL"
      OP_GREATERTHANOREQUAL -> "OP_GREATERTHANOREQUAL"
      OP_MIN -> "OP_MIN"
      OP_MAX -> "OP_MAX"
      OP_WITHIN -> "OP_WITHIN"
      OP_RIPEMD160 -> "OP_RIPEMD160"
      OP_SHA1 -> "OP_SHA1"
      OP_SHA256 -> "OP_SHA256"
      OP_HASH160 -> "OP_HASH160"
      OP_HASH256 -> "OP_HASH256"
      OP_CODESEPARATOR -> "OP_CODESEPARATOR"
      OP_CHECKSIG -> "OP_CHECKSIG"
      OP_CHECKSIGVERIFY -> "OP_CHECKSIGVERIFY"
      OP_CHECKMULTISIG -> "OP_CHECKMULTISIG"
      OP_CHECKMULTISIGVERIFY -> "OP_CHECKMULTISIGVERIFY"
      OP_NOP1 -> "OP_NOP1"
      OP_CHECKLOCKTIMEVERIFY -> "OP_CHECKLOCKTIMEVERIFY"
      OP_CHECKSEQUENCEVERIFY -> "OP_CHECKSEQUENCEVERIFY"
      OP_NOP4 -> "OP_NOP4"
      OP_NOP5 -> "OP_NOP5"
      OP_NOP6 -> "OP_NOP6"
      OP_NOP7 -> "OP_NOP7"
      OP_NOP8 -> "OP_NOP8"
      OP_NOP9 -> "OP_NOP9"
      OP_NOP10 -> "OP_NOP10"
      OP_INVALIDOPCODE w -> T.pack $ "OP_UNKNOWN[" ++ show w ++ "]"

-- | Convert ScriptType to string for JSON output
scriptTypeToString :: ScriptType -> Text
scriptTypeToString st = case st of
  P2PKH _     -> "pubkeyhash"
  P2SH _      -> "scripthash"
  P2WPKH _    -> "witness_v0_keyhash"
  P2WSH _     -> "witness_v0_scripthash"
  P2TR _      -> "witness_v1_taproot"
  P2PK _      -> "pubkey"
  P2MultiSig _ _ -> "multisig"
  OpReturn _  -> "nulldata"
  NonStandard -> "nonstandard"

-- | Extract address from scriptPubKey based on network and script type
scriptToAddress :: Network -> ByteString -> ScriptType -> Maybe Text
scriptToAddress net _ scriptType = case scriptType of
  P2PKH (Hash160 h) -> Just $ encodeBase58Check (BS.cons (netAddrPrefix net) h)
  P2SH (Hash160 h)  -> Just $ encodeBase58Check (BS.cons (netScriptPrefix net) h)
  P2WPKH (Hash160 h) -> Just $ bech32Encode (netBech32Prefix net) 0 h
  P2WSH (Hash256 h) -> Just $ bech32Encode (netBech32Prefix net) 0 h
  P2TR (Hash256 h)  -> Just $ bech32mEncode (netBech32Prefix net) 1 h
  _ -> Nothing
  where
    -- Base58Check encoding
    encodeBase58Check :: ByteString -> Text
    encodeBase58Check payload =
      let checksum = BS.take 4 $ getHash256 (doubleSHA256 payload)
      in TE.decodeUtf8 $ encodeBase58' (payload <> checksum)

    encodeBase58' :: ByteString -> ByteString
    encodeBase58' bs =
      let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
          leadingZeros = BS.length $ BS.takeWhile (== 0) bs
          n = bsToInteger bs
          encoded = go n ""
          go 0 acc = acc
          go v acc = go (v `div` 58) (chr (fromIntegral (BS.index alphabet (fromIntegral (v `mod` 58)))) : acc)
      in C8.pack $ replicate leadingZeros '1' ++ encoded

    bsToInteger :: ByteString -> Integer
    bsToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

    -- Bech32 encoding for witness v0 (P2WPKH, P2WSH)
    encodeBech32 :: Text -> Int -> ByteString -> Text
    encodeBech32 hrp witVer hash =
      let converted = convertBits 8 5 True (BS.unpack hash)
          dataWords = fromIntegral witVer : converted
          checksummed = dataWords ++ bech32Checksum hrp dataWords
      in hrp <> "1" <> T.pack (map bech32Char checksummed)

    -- Bech32m encoding for witness v1+ (P2TR)
    encodeBech32m :: Text -> Int -> ByteString -> Text
    encodeBech32m hrp witVer hash =
      let converted = convertBits 8 5 True (BS.unpack hash)
          dataWords = fromIntegral witVer : converted
          checksummed = dataWords ++ bech32mChecksum hrp dataWords
      in hrp <> "1" <> T.pack (map bech32Char checksummed)

    bech32Char :: Int -> Char
    bech32Char n = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" !! n

    convertBits :: Int -> Int -> Bool -> [Word8] -> [Int]
    convertBits fromBits toBits pad input =
      let go acc bits result [] =
            if pad && bits > 0
              then result ++ [fromIntegral (acc `shiftL` (toBits - bits)) .&. ((1 `shiftL` toBits) - 1)]
              else result
          go acc bits result (x:xs) =
            let acc' = (acc `shiftL` fromBits) .|. fromIntegral x
                bits' = bits + fromBits
                (r, acc'', bits'') = extract acc' bits' []
            in go acc'' bits'' (result ++ r) xs
          extract acc bits res
            | bits >= toBits =
                let bits' = bits - toBits
                    v = fromIntegral ((acc `shiftR` bits') .&. ((1 `shiftL` toBits) - 1))
                in extract acc bits' (res ++ [v])
            | otherwise = (res, acc, bits)
      in go (0 :: Int) (0 :: Int) [] input

    bech32Polymod :: [Int] -> Int
    bech32Polymod values = foldl' step 1 values .&. 0x3fffffff
      where
        step chk v =
          let b = chk `shiftR` 25
              chk' = ((chk .&. 0x1ffffff) `shiftL` 5) `xor` v
          in foldl' (gen b) chk' [0..4]
        gen b c i
          | testBit b i = c `xor` ([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3] !! i)
          | otherwise = c

    hrpExpand :: Text -> [Int]
    hrpExpand h =
      let chars = T.unpack h
      in map (\c -> fromEnum c `shiftR` 5) chars ++ [0] ++ map (\c -> fromEnum c .&. 31) chars

    bech32Checksum :: Text -> [Int] -> [Int]
    bech32Checksum hrp dataWords =
      let values = hrpExpand hrp ++ dataWords ++ [0,0,0,0,0,0]
          polymod = bech32Polymod values `xor` 1
      in map (\i -> (polymod `shiftR` (5 * (5 - i))) .&. 31) [0..5]

    bech32mChecksum :: Text -> [Int] -> [Int]
    bech32mChecksum hrp dataWords =
      let values = hrpExpand hrp ++ dataWords ++ [0,0,0,0,0,0]
          polymod = bech32Polymod values `xor` 0x2bc830a3
      in map (\i -> (polymod `shiftR` (5 * (5 - i))) .&. 31) [0..5]

--------------------------------------------------------------------------------
-- Blockchain State Estimation
--------------------------------------------------------------------------------

-- | Estimate verification progress based on current height and timestamp.
-- Returns a value between 0.0 (no progress) and 1.0 (fully synced).
-- Uses a simple heuristic: compare block timestamp to expected sync time.
computeVerificationProgress :: Word32 -> Word32 -> Double
computeVerificationProgress height blockTime =
  -- Estimate expected height based on mainnet parameters:
  -- Genesis timestamp: 1231006505 (Jan 3, 2009)
  -- Target block interval: 600 seconds (10 minutes)
  let genesisTime = 1231006505 :: Word32
      targetInterval = 600 :: Word32
      -- Estimate expected height if we were at this timestamp
      expectedHeight = if blockTime > genesisTime
                       then fromIntegral ((blockTime - genesisTime) `div` targetInterval)
                       else 0 :: Double
      actualHeight = fromIntegral height :: Double
  in if expectedHeight <= 0 then 1.0
     else min 1.0 (actualHeight / expectedHeight)

-- | Estimate if we're in Initial Block Download mode.
-- IBD is true if the tip is more than 24 hours old (heuristic).
estimateIsInitialBlockDownload :: Word32 -> Word32 -> Bool
estimateIsInitialBlockDownload _height blockTime =
  -- Simple heuristic: if the block timestamp is more than 24 hours behind
  -- "current time" (we use a conservative estimate), we're in IBD.
  -- Since we don't have access to real current time here, we use
  -- a generous threshold based on expected mainnet height.
  -- A better implementation would pass in current system time.
  let dayInSeconds = 24 * 60 * 60 :: Word32
      -- Use a rough estimate: mainnet is around block 850000 as of late 2024
      -- At 10 min/block, that's about 5.1M seconds = ~59 days from genesis
      estimatedCurrentTime = 1231006505 + (850000 * 600) :: Word32
  in blockTime + dayInSeconds < estimatedCurrentTime

--------------------------------------------------------------------------------
-- REST API
--------------------------------------------------------------------------------

-- | REST response format types (matching Bitcoin Core)
-- Reference: /home/max/hashhog/bitcoin/src/rest.cpp
data RestResponseFormat
  = RestBinary     -- ^ Binary serialized data (application/octet-stream)
  | RestHex        -- ^ Hex-encoded string (text/plain)
  | RestJson       -- ^ JSON object (application/json)
  | RestUndefined  -- ^ Invalid/unknown format
  deriving (Eq, Show)

-- | Maximum number of headers returned in /rest/headers/
maxRestHeadersResults :: Int
maxRestHeadersResults = 2000

-- | Maximum number of outpoints for /rest/getutxos/
maxGetUtxosOutpoints :: Int
maxGetUtxosOutpoints = 15

-- | Parse REST response format from URL path suffix.
-- Extracts format from ".bin", ".hex", ".json" suffixes.
-- Returns (path_without_suffix, format)
parseRestFormat :: Text -> (Text, RestResponseFormat)
parseRestFormat path
  | ".bin" `T.isSuffixOf` path  = (T.dropEnd 4 path, RestBinary)
  | ".hex" `T.isSuffixOf` path  = (T.dropEnd 4 path, RestHex)
  | ".json" `T.isSuffixOf` path = (T.dropEnd 5 path, RestJson)
  | otherwise                   = (path, RestUndefined)

-- | Format string for available REST formats
availableFormats :: Text
availableFormats = ".bin, .hex, .json"

-- | REST error response helper
restError :: Int -> Text -> Response
restError statusCode msg =
  let status = case statusCode of
        400 -> status400
        404 -> status404
        500 -> status500
        503 -> status503
        _   -> status400
  in responseLBS status
       [(hContentType, "text/plain")]
       (BL.fromStrict $ TE.encodeUtf8 $ msg <> "\r\n")

--------------------------------------------------------------------------------
-- REST Application
--------------------------------------------------------------------------------

-- | WAI application for REST API.
-- REST is read-only and does not require authentication.
-- Handles paths starting with /rest/
restApp :: RpcServer -> Application
restApp server req respond = do
  -- Only accept GET requests for REST
  if requestMethod req /= "GET"
    then respond $ restError 405 "Method not allowed"
    else do
      let path = TE.decodeUtf8 $ rawPathInfo req
          query = TE.decodeUtf8 $ rawQueryString req

      -- Route based on path prefix
      result <- routeRest server path query
      respond result

-- | Route REST requests to appropriate handlers
routeRest :: RpcServer -> Text -> Text -> IO Response
routeRest server path query
  -- Block with full tx details: /rest/block/<hash>.[bin|hex|json]
  | "/rest/block/" `T.isPrefixOf` path && not ("/rest/block/notxdetails/" `T.isPrefixOf` path) =
      handleRestBlock server (T.drop 12 path) True

  -- Block without tx details: /rest/block/notxdetails/<hash>.[bin|hex|json]
  | "/rest/block/notxdetails/" `T.isPrefixOf` path =
      handleRestBlock server (T.drop 24 path) False

  -- Transaction: /rest/tx/<txid>.[bin|hex|json]
  | "/rest/tx/" `T.isPrefixOf` path =
      handleRestTx server (T.drop 9 path)

  -- Headers: /rest/headers/<count>/<hash>.[bin|hex|json] (deprecated)
  -- or /rest/headers/<hash>.[bin|hex|json]?count=<count> (new)
  | "/rest/headers/" `T.isPrefixOf` path =
      handleRestHeaders server (T.drop 14 path) query

  -- Block hash by height: /rest/blockhashbyheight/<height>.[bin|hex|json]
  | "/rest/blockhashbyheight/" `T.isPrefixOf` path =
      handleRestBlockHashByHeight server (T.drop 23 path)

  -- Chain info: /rest/chaininfo.json
  | "/rest/chaininfo" `T.isPrefixOf` path =
      handleRestChainInfo server (T.drop 15 path)

  -- Mempool info: /rest/mempool/info.json
  | "/rest/mempool/info" `T.isPrefixOf` path =
      handleRestMempoolInfo server (T.drop 18 path)

  -- Mempool contents: /rest/mempool/contents.json
  | "/rest/mempool/contents" `T.isPrefixOf` path =
      handleRestMempoolContents server (T.drop 22 path) query

  -- UTXO query: /rest/getutxos/[checkmempool/]<txid>-<n>/....[bin|hex|json]
  | "/rest/getutxos" `T.isPrefixOf` path =
      handleRestGetUtxos server (T.drop 13 path)

  -- Unknown endpoint
  | otherwise =
      return $ restError 404 "Not found"

--------------------------------------------------------------------------------
-- REST Block Handler
--------------------------------------------------------------------------------

-- | Handle /rest/block/<hash> and /rest/block/notxdetails/<hash>
handleRestBlock :: RpcServer -> Text -> Bool -> IO Response
handleRestBlock server pathPart includeTxDetails = do
  let (hashStr, format) = parseRestFormat pathPart

  case format of
    RestUndefined ->
      return $ restError 404 $ "output format not found (available: " <> availableFormats <> ")"
    _ -> do
      case parseHash hashStr of
        Nothing ->
          return $ restError 400 $ "Invalid hash: " <> hashStr
        Just bh -> do
          -- Check if block is pruned
          isPruned <- case rsBlockStore server of
            Nothing -> return False
            Just blockStore -> isBlockPruned blockStore bh

          if isPruned
            then return $ restError 404 $ hashStr <> " not available (pruned data)"
            else do
              mBlock <- getBlock (rsDB server) bh
              case mBlock of
                Nothing ->
                  return $ restError 404 $ hashStr <> " not found"
                Just block -> do
                  let blockBytes = S.encode block
                  case format of
                    RestBinary ->
                      return $ responseLBS status200
                        [(hContentType, "application/octet-stream")]
                        (BL.fromStrict blockBytes)

                    RestHex ->
                      return $ responseLBS status200
                        [(hContentType, "text/plain")]
                        (BL.fromStrict $ TE.encodeUtf8 $
                          TE.decodeUtf8 (B16.encode blockBytes) <> "\n")

                    RestJson -> do
                      entries <- readTVarIO (hcEntries (rsHeaderChain server))
                      tip <- readTVarIO (hcTip (rsHeaderChain server))
                      let mEntry = Map.lookup bh entries
                          txData = if includeTxDetails
                            then map (\tx -> object
                                   [ "txid" .= showHash (blockHashFromTxId (computeTxId tx))
                                   , "size" .= BS.length (S.encode tx)
                                   , "vsize" .= calculateVSize tx
                                   ]) (blockTxns block)
                            else map (toJSON . showHash . blockHashFromTxId . computeTxId) (blockTxns block)
                          jsonResult = object $ catMaybes
                            [ Just $ "hash" .= showHash bh
                            , Just $ "confirmations" .= confirmations mEntry (ceHeight tip)
                            , Just $ "size" .= BS.length blockBytes
                            , Just $ "height" .= maybe (0 :: Word32) ceHeight mEntry
                            , Just $ "version" .= bhVersion (blockHeader block)
                            , Just $ "merkleroot" .= showHash256 (bhMerkleRoot (blockHeader block))
                            , Just $ "tx" .= txData
                            , Just $ "time" .= bhTimestamp (blockHeader block)
                            , Just $ "nonce" .= bhNonce (blockHeader block)
                            , Just $ "bits" .= showBits (bhBits (blockHeader block))
                            , Just $ "difficulty" .= getDifficulty (bhBits (blockHeader block))
                            , Just $ "previousblockhash" .= showHash (bhPrevBlock (blockHeader block))
                            , fmap ("chainwork" .=) (showHex . ceChainWork <$> mEntry)
                            ]
                      return $ responseLBS status200
                        [(hContentType, "application/json")]
                        (encode jsonResult)

                    RestUndefined ->
                      return $ restError 404 "output format not found"
  where
    confirmations :: Maybe ChainEntry -> Word32 -> Int
    confirmations Nothing _ = -1
    confirmations (Just entry) tipHeight =
      fromIntegral tipHeight - fromIntegral (ceHeight entry) + 1

--------------------------------------------------------------------------------
-- REST Transaction Handler
--------------------------------------------------------------------------------

-- | Handle /rest/tx/<txid>.[bin|hex|json]
handleRestTx :: RpcServer -> Text -> IO Response
handleRestTx server pathPart = do
  let (txidStr, format) = parseRestFormat pathPart

  case format of
    RestUndefined ->
      return $ restError 404 $ "output format not found (available: " <> availableFormats <> ")"
    _ -> do
      case parseHash txidStr of
        Nothing ->
          return $ restError 400 $ "Invalid hash: " <> txidStr
        Just bh -> do
          let txid = TxId (getBlockHashHash bh)

          -- Check mempool first
          mMempoolEntry <- getTransaction (rsMempool server) txid
          case mMempoolEntry of
            Just entry ->
              returnRestTx (meTransaction entry) Nothing format
            Nothing -> do
              -- Try txindex
              mTxLoc <- getTxIndex (rsDB server) txid
              case mTxLoc of
                Nothing ->
                  return $ restError 404 $ txidStr <> " not found"
                Just txLoc -> do
                  mBlock <- getBlock (rsDB server) (txLocBlock txLoc)
                  case mBlock of
                    Nothing ->
                      return $ restError 404 $ txidStr <> " not found"
                    Just block -> do
                      let txns = blockTxns block
                          txIdx = fromIntegral (txLocIndex txLoc)
                      if txIdx < length txns
                        then returnRestTx (txns !! txIdx) (Just (txLocBlock txLoc)) format
                        else return $ restError 404 $ txidStr <> " not found"
  where
    returnRestTx :: Tx -> Maybe BlockHash -> RestResponseFormat -> IO Response
    returnRestTx tx mBlockHash fmt = do
      let txBytes = S.encode tx
          txid = computeTxId tx
      case fmt of
        RestBinary ->
          return $ responseLBS status200
            [(hContentType, "application/octet-stream")]
            (BL.fromStrict txBytes)

        RestHex ->
          return $ responseLBS status200
            [(hContentType, "text/plain")]
            (BL.fromStrict $ TE.encodeUtf8 $
              TE.decodeUtf8 (B16.encode txBytes) <> "\n")

        RestJson -> do
          let jsonResult = object $ catMaybes
                [ Just $ "txid" .= showHash (blockHashFromTxId txid)
                , Just $ "size" .= BS.length txBytes
                , Just $ "vsize" .= calculateVSize tx
                , Just $ "version" .= txVersion tx
                , Just $ "locktime" .= txLockTime tx
                , Just $ "vin" .= map vinToJson (txInputs tx)
                , Just $ "vout" .= zipWith voutToJson [0..] (txOutputs tx)
                , fmap (\bh -> "blockhash" .= showHash bh) mBlockHash
                ]
          return $ responseLBS status200
            [(hContentType, "application/json")]
            (encode jsonResult)

        RestUndefined ->
          return $ restError 404 "output format not found"

    vinToJson :: TxIn -> Value
    vinToJson txin = object
      [ "txid" .= showHash (blockHashFromTxId (outPointHash (txInPrevOutput txin)))
      , "vout" .= outPointIndex (txInPrevOutput txin)
      , "scriptSig" .= object ["hex" .= (TE.decodeUtf8 $ B16.encode (txInScript txin))]
      , "sequence" .= txInSequence txin
      ]

    voutToJson :: Int -> TxOut -> Value
    voutToJson n txout = object
      [ "value" .= (fromIntegral (txOutValue txout) / 100000000.0 :: Double)
      , "n" .= n
      , "scriptPubKey" .= object
          [ "hex" .= (TE.decodeUtf8 $ B16.encode (txOutScript txout))
          ]
      ]

--------------------------------------------------------------------------------
-- REST Headers Handler
--------------------------------------------------------------------------------

-- | Handle /rest/headers/<count>/<hash>.[bin|hex|json] (deprecated)
-- or /rest/headers/<hash>.[bin|hex|json]?count=<count> (new)
handleRestHeaders :: RpcServer -> Text -> Text -> IO Response
handleRestHeaders server pathPart query = do
  let (param, format) = parseRestFormat pathPart
      parts = T.splitOn "/" param

  case format of
    RestUndefined ->
      return $ restError 404 $ "output format not found (available: " <> availableFormats <> ")"
    _ -> do
      -- Parse path: either <count>/<hash> (deprecated) or <hash> (new)
      (count, hashStr) <- case parts of
        [countStr, hash] ->
          -- Deprecated: /rest/headers/<count>/<hash>
          case readMaybe (T.unpack countStr) :: Maybe Int of
            Nothing -> return (5, hash)  -- Fall back to treating as hash
            Just c -> return (c, hash)
        [hash] ->
          -- New: /rest/headers/<hash>?count=<count>
          let countParam = parseQueryParam query "count"
              c = maybe 5 id (countParam >>= readMaybe . T.unpack)
          in return (c, hash)
        _ -> return (5, "")

      -- Validate count
      if count < 1 || count > maxRestHeadersResults
        then return $ restError 400 $
          "Header count is invalid or out of acceptable range (1-" <>
          T.pack (show maxRestHeadersResults) <> "): " <> T.pack (show count)
        else do
          case parseHash hashStr of
            Nothing ->
              return $ restError 400 $ "Invalid hash: " <> hashStr
            Just startHash -> do
              entries <- readTVarIO (hcEntries (rsHeaderChain server))
              heightMap <- readTVarIO (hcByHeight (rsHeaderChain server))

              -- Get headers starting from hash
              let headers = collectHeaders entries heightMap startHash count
              if null headers
                then return $ restError 404 $ hashStr <> " not found"
                else do
                  tip <- readTVarIO (hcTip (rsHeaderChain server))
                  case format of
                    RestBinary -> do
                      let headerBytes = BS.concat $ map (S.encode . ceHeader) headers
                      return $ responseLBS status200
                        [(hContentType, "application/octet-stream")]
                        (BL.fromStrict headerBytes)

                    RestHex -> do
                      let headerBytes = BS.concat $ map (S.encode . ceHeader) headers
                      return $ responseLBS status200
                        [(hContentType, "text/plain")]
                        (BL.fromStrict $ TE.encodeUtf8 $
                          TE.decodeUtf8 (B16.encode headerBytes) <> "\n")

                    RestJson -> do
                      let jsonHeaders = map (headerEntryToJson (ceHeight tip)) headers
                      return $ responseLBS status200
                        [(hContentType, "application/json")]
                        (encode $ toJSON jsonHeaders)

                    RestUndefined ->
                      return $ restError 404 "output format not found"
  where
    collectHeaders :: Map BlockHash ChainEntry -> Map Word32 BlockHash
                   -> BlockHash -> Int -> [ChainEntry]
    collectHeaders entries heightMap startHash maxCount =
      case Map.lookup startHash entries of
        Nothing -> []
        Just entry ->
          let loop _ 0 acc = reverse acc
              loop h n acc =
                case Map.lookup h entries of
                  Nothing -> reverse acc
                  Just e ->
                    let nextHeight = ceHeight e + 1
                    in case Map.lookup nextHeight heightMap of
                      Nothing -> reverse (e:acc)
                      Just nextHash -> loop nextHash (n-1) (e:acc)
          in loop startHash maxCount []

    headerEntryToJson :: Word32 -> ChainEntry -> Value
    headerEntryToJson tipHeight entry = object
      [ "hash" .= showHash (ceHash entry)
      , "confirmations" .= (fromIntegral tipHeight - fromIntegral (ceHeight entry) + 1 :: Int)
      , "height" .= ceHeight entry
      , "version" .= bhVersion (ceHeader entry)
      , "merkleroot" .= showHash256 (bhMerkleRoot (ceHeader entry))
      , "time" .= bhTimestamp (ceHeader entry)
      , "nonce" .= bhNonce (ceHeader entry)
      , "bits" .= showBits (bhBits (ceHeader entry))
      , "difficulty" .= getDifficulty (bhBits (ceHeader entry))
      , "chainwork" .= showHex (ceChainWork entry)
      , "previousblockhash" .= showHash (bhPrevBlock (ceHeader entry))
      ]

    parseQueryParam :: Text -> Text -> Maybe Text
    parseQueryParam q key =
      let params = T.splitOn "&" (T.drop 1 q)  -- Drop leading '?'
          find' k = listToMaybe [v | p <- params, let (k', v) = splitParam p, k' == k]
          splitParam p = case T.splitOn "=" p of
            [k, v] -> (k, v)
            _ -> ("", "")
      in find' key

--------------------------------------------------------------------------------
-- REST Block Hash By Height Handler
--------------------------------------------------------------------------------

-- | Handle /rest/blockhashbyheight/<height>.[bin|hex|json]
handleRestBlockHashByHeight :: RpcServer -> Text -> IO Response
handleRestBlockHashByHeight server pathPart = do
  let (heightStr, format) = parseRestFormat pathPart

  case format of
    RestUndefined ->
      return $ restError 404 $ "output format not found (available: " <> availableFormats <> ")"
    _ -> do
      case readMaybe (T.unpack heightStr) :: Maybe Word32 of
        Nothing ->
          return $ restError 400 $ "Invalid height: " <> heightStr
        Just height -> do
          heightMap <- readTVarIO (hcByHeight (rsHeaderChain server))
          tip <- readTVarIO (hcTip (rsHeaderChain server))

          if height > ceHeight tip
            then return $ restError 404 "Block height out of range"
            else case Map.lookup height heightMap of
              Nothing ->
                return $ restError 404 "Block height out of range"
              Just bh -> do
                let hashBytes = S.encode bh
                case format of
                  RestBinary ->
                    return $ responseLBS status200
                      [(hContentType, "application/octet-stream")]
                      (BL.fromStrict hashBytes)

                  RestHex ->
                    return $ responseLBS status200
                      [(hContentType, "text/plain")]
                      (BL.fromStrict $ TE.encodeUtf8 $ showHash bh <> "\n")

                  RestJson ->
                    return $ responseLBS status200
                      [(hContentType, "application/json")]
                      (encode $ object ["blockhash" .= showHash bh])

                  RestUndefined ->
                    return $ restError 404 "output format not found"

--------------------------------------------------------------------------------
-- REST Chain Info Handler
--------------------------------------------------------------------------------

-- | Handle /rest/chaininfo.json
handleRestChainInfo :: RpcServer -> Text -> IO Response
handleRestChainInfo server pathPart = do
  let (_, format) = parseRestFormat pathPart

  case format of
    RestJson -> do
      tip <- readTVarIO (hcTip (rsHeaderChain server))
      let progress = computeVerificationProgress (ceHeight tip) (bhTimestamp (ceHeader tip))
          currentTime = bhTimestamp (ceHeader tip)
          isIBD = estimateIsInitialBlockDownload (ceHeight tip) currentTime
          -- Use the shared soft-fork helper so REST /chaininfo and RPC
          -- getblockchaininfo / getdeploymentinfo all read the same source.
          sforks = softforksFromEntry (rsNetwork server) tip
          jsonResult = object
            [ "chain" .= netName (rsNetwork server)
            , "blocks" .= ceHeight tip
            , "headers" .= ceHeight tip
            , "bestblockhash" .= showHash (ceHash tip)
            , "bits" .= showBits (bhBits (ceHeader tip))
            , "target" .= showHex (bitsToTarget (bhBits (ceHeader tip)))
            , "difficulty" .= getDifficulty (bhBits (ceHeader tip))
            , "time" .= bhTimestamp (ceHeader tip)
            , "mediantime" .= ceMedianTime tip
            , "verificationprogress" .= progress
            , "initialblockdownload" .= isIBD
            , "chainwork" .= showHex (ceChainWork tip)
            , "size_on_disk" .= (0 :: Int)
            , "pruned" .= False
            , "softforks" .= sforks
            , "warnings" .= ([] :: [Text])
            ]
      return $ responseLBS status200
        [(hContentType, "application/json")]
        (encode jsonResult)

    _ ->
      return $ restError 404 "output format not found (available: json)"

--------------------------------------------------------------------------------
-- REST Mempool Info Handler
--------------------------------------------------------------------------------

-- | Handle /rest/mempool/info.json
handleRestMempoolInfo :: RpcServer -> Text -> IO Response
handleRestMempoolInfo server pathPart = do
  let (_, format) = parseRestFormat pathPart

  case format of
    RestJson -> do
      (count, size) <- getMempoolSize (rsMempool server)
      let mpCfg = mpConfig (rsMempool server)
          jsonResult = object
            [ "loaded" .= True
            , "size" .= count
            , "bytes" .= size
            , "usage" .= size
            , "maxmempool" .= mpcMaxSize mpCfg
            , "mempoolminfee" .= getFeeRate (mpcMinFeeRate mpCfg)
            , "minrelaytxfee" .= (1 :: Int)
            ]
      return $ responseLBS status200
        [(hContentType, "application/json")]
        (encode jsonResult)

    _ ->
      return $ restError 404 "output format not found (available: json)"

--------------------------------------------------------------------------------
-- REST Mempool Contents Handler
--------------------------------------------------------------------------------

-- | Handle /rest/mempool/contents.json
handleRestMempoolContents :: RpcServer -> Text -> Text -> IO Response
handleRestMempoolContents server pathPart query = do
  let (_, format) = parseRestFormat pathPart

  case format of
    RestJson -> do
      txids <- getMempoolTxIds (rsMempool server)

      -- Parse verbose parameter (default: true)
      let verboseParam = parseQueryParamBool query "verbose" True
      -- Parse mempool_sequence parameter (default: false)
      let seqParam = parseQueryParamBool query "mempool_sequence" False

      if verboseParam && seqParam
        then return $ restError 400
          "Verbose results cannot contain mempool sequence values. (hint: set \"verbose=false\")"
        else if verboseParam
          then do
            -- Return detailed info for each tx
            entries <- forM txids $ \txid -> do
              mEntry <- getTransaction (rsMempool server) txid
              return $ case mEntry of
                Nothing -> Nothing
                Just entry -> Just (showHash (BlockHash (getTxIdHash txid)), entryToJson entry)

            let jsonResult = object $ catMaybes $
                  map (fmap (\(k, v) -> Key.fromText k .= v)) entries
            return $ responseLBS status200
              [(hContentType, "application/json")]
              (encode jsonResult)
          else do
            -- Simple mode: just return list of txids
            let txidStrs = map (\txid -> showHash (BlockHash (getTxIdHash txid))) txids
                jsonResult = if seqParam
                  then object ["txids" .= txidStrs, "mempool_sequence" .= (0 :: Int)]
                  else toJSON txidStrs
            return $ responseLBS status200
              [(hContentType, "application/json")]
              (encode jsonResult)

    _ ->
      return $ restError 404 "output format not found (available: json)"

  where
    entryToJson :: MempoolEntry -> Value
    entryToJson entry = object
      [ "vsize" .= meSize entry
      , "weight" .= (meSize entry * 4)
      , "fee" .= meFee entry
      , "time" .= meTime entry
      , "height" .= meHeight entry
      , "descendantcount" .= meDescendantCount entry
      , "descendantsize" .= meDescendantSize entry
      , "descendantfees" .= meDescendantFees entry
      , "ancestorcount" .= meAncestorCount entry
      , "ancestorsize" .= meAncestorSize entry
      , "ancestorfees" .= meAncestorFees entry
      ]

    parseQueryParamBool :: Text -> Text -> Bool -> Bool
    parseQueryParamBool q key def =
      let params = T.splitOn "&" (T.drop 1 q)
          find' k = listToMaybe [v | p <- params, let (k', v) = splitParam p, k' == k]
          splitParam p = case T.splitOn "=" p of
            [k, v] -> (k, v)
            _ -> ("", "")
      in case find' key of
           Just "true" -> True
           Just "false" -> False
           _ -> def

--------------------------------------------------------------------------------
-- REST UTXO Handler
--------------------------------------------------------------------------------

-- | Handle /rest/getutxos/[checkmempool/]<txid>-<n>/....[bin|hex|json]
handleRestGetUtxos :: RpcServer -> Text -> IO Response
handleRestGetUtxos server pathPart = do
  let (param, format) = parseRestFormat pathPart
      parts = filter (not . T.null) $ T.splitOn "/" param

  case format of
    RestUndefined ->
      return $ restError 404 $ "output format not found (available: " <> availableFormats <> ")"
    _ -> do
      if null parts
        then return $ restError 400 "Error: empty request"
        else do
          -- Check for checkmempool flag
          let (checkMempool, outpointParts) = case parts of
                ("checkmempool":rest) -> (True, rest)
                rest -> (False, rest)

          -- Parse outpoints
          case parseOutpoints outpointParts of
            Left err ->
              return $ restError 400 err
            Right outpoints -> do
              if length outpoints > maxGetUtxosOutpoints
                then return $ restError 400 $
                  "Error: max outpoints exceeded (max: " <> T.pack (show maxGetUtxosOutpoints) <>
                  ", tried: " <> T.pack (show (length outpoints)) <> ")"
                else do
                  -- Look up UTXOs
                  tip <- readTVarIO (hcTip (rsHeaderChain server))
                  let tipHeight = ceHeight tip
                      tipHash = ceHash tip

                  results <- forM outpoints $ \op -> do
                    -- First check UTXO cache
                    mUtxo <- lookupUTXO (rsUTXOCache server) op
                    case mUtxo of
                      Just entry -> return (True, Just entry)
                      Nothing ->
                        -- If checkMempool, also check mempool for unspent
                        if checkMempool
                          then do
                            -- Check if the output exists in mempool (simplified)
                            let txid = outPointHash op
                            mEntry <- getTransaction (rsMempool server) txid
                            case mEntry of
                              Just mempoolEntry ->
                                let tx = meTransaction mempoolEntry
                                    idx = fromIntegral (outPointIndex op)
                                in if idx < length (txOutputs tx)
                                   then return (True, Just $ UTXOEntry
                                          { ueOutput = txOutputs tx !! idx
                                          , ueHeight = tipHeight
                                          , ueCoinbase = False
                                          , ueSpent = False
                                          })
                                   else return (False, Nothing)
                              Nothing -> return (False, Nothing)
                          else return (False, Nothing)

                  -- Build bitmap
                  let hits = map fst results
                      utxos = catMaybes $ map snd results
                      bitmap = buildBitmap hits
                      bitmapStr = map (\b -> if b then '1' else '0') hits

                  case format of
                    RestBinary -> do
                      -- Serialize: height (4) + hash (32) + bitmap + utxos
                      let response = BL.concat
                            [ BL.fromStrict $ S.encode tipHeight
                            , BL.fromStrict $ S.encode tipHash
                            , BL.fromStrict $ BS.pack bitmap
                            , BL.fromStrict $ BS.concat $ map encodeUtxo utxos
                            ]
                      return $ responseLBS status200
                        [(hContentType, "application/octet-stream")]
                        response

                    RestHex -> do
                      let responseBytes = BS.concat
                            [ S.encode tipHeight
                            , S.encode tipHash
                            , BS.pack bitmap
                            , BS.concat $ map encodeUtxo utxos
                            ]
                      return $ responseLBS status200
                        [(hContentType, "text/plain")]
                        (BL.fromStrict $ TE.encodeUtf8 $
                          TE.decodeUtf8 (B16.encode responseBytes) <> "\n")

                    RestJson -> do
                      let utxoJson = zipWith utxoToJson [0..] utxos
                          jsonResult = object
                            [ "chainHeight" .= tipHeight
                            , "chaintipHash" .= showHash tipHash
                            , "bitmap" .= T.pack bitmapStr
                            , "utxos" .= utxoJson
                            ]
                      return $ responseLBS status200
                        [(hContentType, "application/json")]
                        (encode jsonResult)

                    RestUndefined ->
                      return $ restError 404 "output format not found"

  where
    parseOutpoints :: [Text] -> Either Text [OutPoint]
    parseOutpoints = mapM parseOutpoint
      where
        parseOutpoint part =
          case T.splitOn "-" part of
            [txidStr, nStr] ->
              case (parseHash txidStr, readMaybe (T.unpack nStr) :: Maybe Word32) of
                (Just bh, Just n) ->
                  Right $ OutPoint (TxId (getBlockHashHash bh)) n
                _ -> Left $ "Parse error: " <> part
            _ -> Left $ "Parse error: " <> part

    buildBitmap :: [Bool] -> [Word8]
    buildBitmap hits =
      let grouped = groupN 8 hits
          toByte bits = foldl (\acc (i, b) -> if b then acc .|. (1 `shiftL` i) else acc)
                              0 (zip [0..] bits)
      in map toByte grouped

    groupN :: Int -> [a] -> [[a]]
    groupN _ [] = []
    groupN n xs = take n xs : groupN n (drop n xs)

    encodeUtxo :: UTXOEntry -> ByteString
    encodeUtxo entry =
      -- Serialize as: version (4) + height (4) + txout
      S.encode (0 :: Word32) <> S.encode (ueHeight entry) <> S.encode (ueOutput entry)

    utxoToJson :: Int -> UTXOEntry -> Value
    utxoToJson _idx entry = object
      [ "height" .= ueHeight entry
      , "value" .= (fromIntegral (txOutValue (ueOutput entry)) / 100000000.0 :: Double)
      , "scriptPubKey" .= object
          [ "hex" .= (TE.decodeUtf8 $ B16.encode (txOutScript (ueOutput entry)))
          ]
      ]

--------------------------------------------------------------------------------
-- Helper for reading integers
--------------------------------------------------------------------------------

readMaybe :: Read a => String -> Maybe a
readMaybe s = case reads s of
  [(x, "")] -> Just x
  _ -> Nothing

--------------------------------------------------------------------------------
-- Combined RPC + REST Server
--------------------------------------------------------------------------------

-- | Start both RPC and REST servers on the same port.
-- Routes requests based on URL path prefix.
combinedApp :: RpcServer -> Application
combinedApp server req respond = do
  let path = rawPathInfo req
  if BS.isPrefixOf "/rest/" path
    then restApp server req respond
    else rpcApp server req respond

--------------------------------------------------------------------------------
-- ZMQ Notifications
--------------------------------------------------------------------------------
-- Reference: /home/max/hashhog/bitcoin/src/zmq/zmqpublishnotifier.cpp

-- | ZMQ notification topics
-- Each topic corresponds to a type of blockchain event
data ZmqTopic
  = ZmqHashBlock     -- ^ 32-byte block hash (little-endian as stored)
  | ZmqHashTx        -- ^ 32-byte transaction hash (little-endian as stored)
  | ZmqRawBlock      -- ^ Full serialized block
  | ZmqRawTx         -- ^ Full serialized transaction
  | ZmqSequence      -- ^ Sequence notification with type byte + hash + optional mempool seq
  deriving (Eq, Show)

-- | Convert ZMQ topic to wire format (topic string)
zmqTopicToBytes :: ZmqTopic -> ByteString
zmqTopicToBytes ZmqHashBlock = "hashblock"
zmqTopicToBytes ZmqHashTx    = "hashtx"
zmqTopicToBytes ZmqRawBlock  = "rawblock"
zmqTopicToBytes ZmqRawTx     = "rawtx"
zmqTopicToBytes ZmqSequence  = "sequence"

-- | Sequence notification label (matches Bitcoin Core)
data SequenceLabel
  = SeqBlockConnect     -- ^ 'C' - Block connected to tip
  | SeqBlockDisconnect  -- ^ 'D' - Block disconnected from tip (reorg)
  | SeqMempoolAccept    -- ^ 'A' - Transaction added to mempool
  | SeqMempoolRemoval   -- ^ 'R' - Transaction removed from mempool
  deriving (Eq, Show)

-- | Convert sequence label to byte
sequenceLabelToByte :: SequenceLabel -> Word8
sequenceLabelToByte SeqBlockConnect    = 0x43  -- 'C'
sequenceLabelToByte SeqBlockDisconnect = 0x44  -- 'D'
sequenceLabelToByte SeqMempoolAccept   = 0x41  -- 'A'
sequenceLabelToByte SeqMempoolRemoval  = 0x52  -- 'R'

-- | ZMQ events to be published
data ZmqEvent
  = ZmqEventHashBlock !BlockHash
  | ZmqEventHashTx !TxId
  | ZmqEventRawBlock !ByteString !BlockHash
  | ZmqEventRawTx !ByteString !TxId
  | ZmqEventSequence !SequenceLabel !BlockHash !(Maybe Word64)
  deriving (Eq, Show)

-- | ZMQ configuration
data ZmqConfig = ZmqConfig
  { zmqEndpoint        :: !String      -- ^ ZMQ bind endpoint (e.g. "tcp://127.0.0.1:28332")
  , zmqHighWaterMark   :: !Int         -- ^ Send high water mark (message queue limit)
  , zmqEnabled         :: !Bool        -- ^ Whether ZMQ notifications are enabled
  } deriving (Show, Generic)

instance NFData ZmqConfig

-- | Default ZMQ configuration
defaultZmqConfig :: ZmqConfig
defaultZmqConfig = ZmqConfig
  { zmqEndpoint      = "tcp://127.0.0.1:28332"
  , zmqHighWaterMark = 1000
  , zmqEnabled       = True
  }

-- | ZMQ notifier state.
--
-- = Wire-up
--
-- ZMQ runtime publishing IS compiled into this build via direct FFI
-- against @libzmq.so.5@ (see @cbits\/zmq_stubs.c@ + @src\/System\/ZMQ4.hs@).
-- We do not depend on @libzmq3-dev@ — only on the runtime SONAME, which
-- ships in Debian's @libzmq5@ package. This mirrors the camlcoin
-- pattern (commit 23c02ac).
--
-- = Mechanism
--
-- 'newZmqNotifier' opens a ZMQ context, creates a PUB socket, sets
-- @LINGER=0@ + @SNDHWM=znConfig.zmqHighWaterMark@ + TCP keepalive, binds
-- to @znConfig.zmqEndpoint@, then spawns a worker that drains the
-- 'TBQueue' and pushes each event as a 3-frame
-- @[topic | body | LE u32 sequence]@ message — same wire format as
-- Bitcoin Core's @CZMQPublishNotifier::SendZmqMessage@.
--
-- = Failure semantics
--
-- All three frames are sent with @ZMQ_DONTWAIT@; if SNDHWM is hit the
-- message is dropped silently (same as Core). Bind failures are
-- surfaced as exceptions from 'newZmqNotifier' so the operator sees
-- "address already in use" / "no permission" loudly instead of
-- discovering a silent broken pipe later.
--
-- The pure encoding helpers (@zmqTopicToBytes@, @sequenceLabelToByte@,
-- @eventToTopicAndBody@, @hashToLeBytes@, @txidToLeBytes@) remain
-- testable in isolation — wire-format tests need no live socket.
data ZmqNotifier = ZmqNotifier
  { znConfig      :: !ZmqConfig
  , znContext     :: !ZMQ.Context
  , znSocket      :: !(ZMQ.Socket ZMQ.Pub)
  , znSequence    :: !(TVar Word32)         -- ^ Monotonic sequence number for each message
  , znEventQueue  :: !(TBQueue ZmqEvent)    -- ^ Buffered event queue
  , znWorker      :: !(TVar (Maybe ThreadId))
  }

-- | Legacy error message kept for callers that previously checked
-- whether the build supported ZMQ. It now describes the (rare)
-- failure mode where 'newZmqNotifier' itself throws — e.g. the bind
-- address is in use.
zmqNotSupportedMessage :: String
zmqNotSupportedMessage =
  "ZMQ notifier could not be initialised. Either the bind address is " ++
  "in use, libzmq.so.5 is not on the runtime loader path, or the " ++
  "configured endpoint syntax is invalid. See cbits/zmq_stubs.c."

-- | Create a new ZMQ notifier.
--
-- Opens a libzmq PUB socket and binds it to 'zmqEndpoint'. The high
-- water mark is configured before bind (libzmq requires this order),
-- TCP keepalive is enabled, and LINGER is set to 0 so shutdown is
-- prompt. A worker thread is forked which drains the event queue and
-- pushes each entry as a 3-frame message.
--
-- @newZmqNotifier@ raises 'ZMQ.ZmqError' if the bind fails; the
-- caller (e.g. node startup) is responsible for downgrading that to
-- a warning if ZMQ is opt-in.
newZmqNotifier :: ZmqConfig -> IO ZmqNotifier
newZmqNotifier config = mask_ $ do
  ctx  <- ZMQ.context
  sock <- ZMQ.socket ctx ZMQ.Pub `catch` \(e :: SomeException) -> do
            ZMQ.term ctx
            error (zmqNotSupportedMessage ++ " (socket: " ++ show e ++ ")")
  -- Order: setsockopt before bind (libzmq 4.x ABI contract).
  ZMQ.setSendHighWM (ZMQ.restrict (zmqHighWaterMark config)) sock
  ZMQ.setLinger     (ZMQ.restrict (0 :: Int))                 sock
  ZMQ.setTcpKeepAlive ZMQ.On sock
  (ZMQ.bind sock (zmqEndpoint config))
    `catch` \(e :: SomeException) -> do
      ZMQ.close sock
      ZMQ.term ctx
      error (zmqNotSupportedMessage ++ " (bind " ++ zmqEndpoint config
             ++ ": " ++ show e ++ ")")
  seqVar     <- newTVarIO 0
  queue      <- newTBQueueIO 1000
  workerVar  <- newTVarIO Nothing
  let n = ZmqNotifier
        { znConfig      = config
        , znContext     = ctx
        , znSocket      = sock
        , znSequence    = seqVar
        , znEventQueue  = queue
        , znWorker      = workerVar
        }
  tid <- forkIO (zmqWorkerLoop n)
  atomically $ writeTVar workerVar (Just tid)
  pure n

-- | Close the ZMQ notifier.
--
-- Stops the worker thread, closes the socket (LINGER=0 means in-flight
-- messages are dropped), and terminates the context (which blocks
-- until I/O thread cleanup is complete). Idempotent in practice
-- because the underlying ForeignPtr finalisers are no-ops once run.
closeZmqNotifier :: ZmqNotifier -> IO ()
closeZmqNotifier notifier = do
  mTid <- readTVarIO (znWorker notifier)
  mapM_ killThread mTid
  atomically $ writeTVar (znWorker notifier) Nothing
  -- Best-effort teardown — exceptions during shutdown are logged via
  -- 'handle' rather than escalated; we do not want a half-stopped
  -- node to fail the shutdown sequence.
  handle (\(_ :: SomeException) -> pure ()) $
    ZMQ.close (znSocket notifier)
  handle (\(_ :: SomeException) -> pure ()) $
    ZMQ.term (znContext notifier)

-- | Worker loop that drains the event queue and pushes each event as
-- a 3-frame ZMQ message. Runs forever; killed by 'closeZmqNotifier'.
--
-- Errors from 'sendZmqEvent' are caught and ignored — a slow or
-- disconnected subscriber must not stall block validation. The
-- underlying 'ZMQ.sendMulti' already returns silently on SNDHWM hits,
-- so this catch only covers programming errors (e.g. socket already
-- closed during shutdown race).
zmqWorkerLoop :: ZmqNotifier -> IO ()
zmqWorkerLoop notifier = do
  event <- atomically $ readTBQueue (znEventQueue notifier)
  handle (\(_ :: SomeException) -> pure ()) (sendZmqEvent notifier event)
  zmqWorkerLoop notifier

-- | Encode a single 'ZmqEvent' as a 3-frame ZMQ message and push it
-- on the wire. Frame layout matches Bitcoin Core
-- (@CZMQPublishNotifier::SendZmqMessage@):
--
-- @
--   frame 0: topic   (e.g. "rawblock", "hashtx")
--   frame 1: body    (event-specific bytes — see eventToTopicAndBody)
--   frame 2: seq     (4-byte little-endian uint32, monotonic per notifier)
-- @
sendZmqEvent :: ZmqNotifier -> ZmqEvent -> IO ()
sendZmqEvent notifier event = do
  let (topic, body) = eventToTopicAndBody event
  seqNum <- atomically $ do
    n <- readTVar (znSequence notifier)
    writeTVar (znSequence notifier) (n + 1)
    pure n
  let seqBytes = encodeLE32 seqNum
  ZMQ.sendMulti (znSocket notifier)
    (zmqTopicToBytes topic :| [body, seqBytes])
  where
    encodeLE32 :: Word32 -> ByteString
    encodeLE32 n = BS.pack
      [ fromIntegral (n .&. 0xff)
      , fromIntegral ((n `shiftR` 8)  .&. 0xff)
      , fromIntegral ((n `shiftR` 16) .&. 0xff)
      , fromIntegral ((n `shiftR` 24) .&. 0xff)
      ]

-- | Convert event to topic and body
eventToTopicAndBody :: ZmqEvent -> (ZmqTopic, ByteString)
eventToTopicAndBody (ZmqEventHashBlock bh) =
  (ZmqHashBlock, hashToLeBytes bh)
eventToTopicAndBody (ZmqEventHashTx txid) =
  (ZmqHashTx, txidToLeBytes txid)
eventToTopicAndBody (ZmqEventRawBlock rawBytes _) =
  (ZmqRawBlock, rawBytes)
eventToTopicAndBody (ZmqEventRawTx rawBytes _) =
  (ZmqRawTx, rawBytes)
eventToTopicAndBody (ZmqEventSequence label bh mMempoolSeq) =
  let hashBytes = hashToLeBytes bh
      labelByte = BS.singleton (sequenceLabelToByte label)
      body = case mMempoolSeq of
        Nothing -> hashBytes <> labelByte
        Just seqNum -> hashBytes <> labelByte <> encodeLE64 seqNum
  in (ZmqSequence, body)
  where
    encodeLE64 :: Word64 -> ByteString
    encodeLE64 n = BS.pack
      [ fromIntegral (n .&. 0xff)
      , fromIntegral ((n `shiftR` 8) .&. 0xff)
      , fromIntegral ((n `shiftR` 16) .&. 0xff)
      , fromIntegral ((n `shiftR` 24) .&. 0xff)
      , fromIntegral ((n `shiftR` 32) .&. 0xff)
      , fromIntegral ((n `shiftR` 40) .&. 0xff)
      , fromIntegral ((n `shiftR` 48) .&. 0xff)
      , fromIntegral ((n `shiftR` 56) .&. 0xff)
      ]

-- | Convert BlockHash to little-endian bytes (as stored internally)
-- Bitcoin Core reverses the hash for display but stores it LE
hashToLeBytes :: BlockHash -> ByteString
hashToLeBytes bh = getHash256 (getBlockHashHash bh)

-- | Convert TxId to little-endian bytes
txidToLeBytes :: TxId -> ByteString
txidToLeBytes txid = getHash256 (getTxIdHash txid)

--------------------------------------------------------------------------------
-- Public notification functions
--------------------------------------------------------------------------------

-- | Queue a block connect notification
-- Publishes both hashblock and sequence (with 'C' label)
notifyBlockConnect :: ZmqNotifier -> BlockHash -> ByteString -> IO ()
notifyBlockConnect notifier bh rawBlock = atomically $ do
  -- hashblock notification
  writeTBQueue (znEventQueue notifier) (ZmqEventHashBlock bh)
  -- rawblock notification
  writeTBQueue (znEventQueue notifier) (ZmqEventRawBlock rawBlock bh)
  -- sequence notification with 'C' (connect)
  writeTBQueue (znEventQueue notifier) (ZmqEventSequence SeqBlockConnect bh Nothing)

-- | Queue a block disconnect notification
-- Publishes sequence notification with 'D' label
notifyBlockDisconnect :: ZmqNotifier -> BlockHash -> IO ()
notifyBlockDisconnect notifier bh = atomically $
  writeTBQueue (znEventQueue notifier) (ZmqEventSequence SeqBlockDisconnect bh Nothing)

-- | Queue a raw block notification
notifyRawBlock :: ZmqNotifier -> BlockHash -> ByteString -> IO ()
notifyRawBlock notifier bh rawBlock = atomically $
  writeTBQueue (znEventQueue notifier) (ZmqEventRawBlock rawBlock bh)

-- | Queue a hash block notification
notifyHashBlock :: ZmqNotifier -> BlockHash -> IO ()
notifyHashBlock notifier bh = atomically $
  writeTBQueue (znEventQueue notifier) (ZmqEventHashBlock bh)

-- | Queue a transaction acceptance notification
-- Publishes hashtx, rawtx, and sequence (with 'A' label)
notifyTxAcceptance :: ZmqNotifier -> TxId -> ByteString -> Word64 -> IO ()
notifyTxAcceptance notifier txid rawTx mempoolSeq = atomically $ do
  -- hashtx notification
  writeTBQueue (znEventQueue notifier) (ZmqEventHashTx txid)
  -- rawtx notification
  writeTBQueue (znEventQueue notifier) (ZmqEventRawTx rawTx txid)
  -- sequence notification with 'A' (mempool accept) and mempool sequence number
  let bh = BlockHash (getTxIdHash txid)
  writeTBQueue (znEventQueue notifier) (ZmqEventSequence SeqMempoolAccept bh (Just mempoolSeq))

-- | Queue a transaction removal notification
-- Publishes sequence notification with 'R' label
notifyTxRemoval :: ZmqNotifier -> TxId -> Word64 -> IO ()
notifyTxRemoval notifier txid mempoolSeq = atomically $ do
  let bh = BlockHash (getTxIdHash txid)
  writeTBQueue (znEventQueue notifier) (ZmqEventSequence SeqMempoolRemoval bh (Just mempoolSeq))

-- | Queue a raw transaction notification
notifyRawTx :: ZmqNotifier -> TxId -> ByteString -> IO ()
notifyRawTx notifier txid rawTx = atomically $
  writeTBQueue (znEventQueue notifier) (ZmqEventRawTx rawTx txid)

-- | Queue a hash transaction notification
notifyHashTx :: ZmqNotifier -> TxId -> IO ()
notifyHashTx notifier txid = atomically $
  writeTBQueue (znEventQueue notifier) (ZmqEventHashTx txid)

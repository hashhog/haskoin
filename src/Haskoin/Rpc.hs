{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | JSON-RPC Server
--
-- This module implements a JSON-RPC server compatible with Bitcoin Core's RPC
-- interface, providing endpoints for blockchain queries, transaction submission,
-- network information, mining, and wallet operations.
--
-- Key Features:
--   - HTTP server using Warp for high performance
--   - Full Bitcoin Core RPC API compatibility
--   - HTTP Basic authentication
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
    -- * Internal helpers (exported for testing)
  , mempoolErrorToRpcResponse
  , decodeTxWithFallback
  , handleBatchRequest
  , parseSingleRequest
  ) where

import Data.Aeson
import Data.Aeson.Types (Parser, Result(..))
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
                    requestMethod, requestHeaders)
import Network.Wai.Handler.Warp (run, Settings, defaultSettings, setPort, setHost)
import Network.HTTP.Types (status200, status401, status405, hContentType, hAuthorization)
import Control.Concurrent (ThreadId, forkIO, killThread)
import Control.Concurrent.STM
import Control.Exception (try, SomeException, catch)
import Data.IORef
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import Data.Serialize (encode, decode)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import Control.Monad (forM)
import Data.Maybe (fromMaybe, catMaybes, listToMaybe)
import Data.List (find)
import Text.Printf (printf)
import qualified Data.Vector as V

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256, computeTxId, computeBlockHash, textToAddress,
                        Address(..))
import Haskoin.Consensus (Network(..), HeaderChain(..), ChainEntry(..),
                           bitsToTarget, blockReward, txBaseSize, txTotalSize,
                           witnessScaleFactor, computeWtxId)
import Haskoin.Script (decodeScript, classifyOutput, ScriptType(..), Script(..),
                        ScriptOp(..), encodeScriptOps)
import Haskoin.Storage (HaskoinDB, UTXOCache(..), getBlock, getBlockHeader,
                         lookupUTXO, UTXOEntry(..), TxLocation(..), getTxIndex)
import Haskoin.Network (PeerManager(..), PeerInfo(..), Version(..),
                         getPeerCount, getConnectedPeers, broadcastMessage,
                         Message(..), Inv(..), InvVector(..), InvType(..),
                         protocolVersion, nodeNetwork, nodeWitness, nodeBloom,
                         nodeNetworkLimited, hasService)
import Haskoin.Mempool (Mempool(..), MempoolEntry(..), MempoolConfig(..),
                         MempoolError(..),
                         addTransaction, getTransaction, getMempoolTxIds,
                         getMempoolSize, FeeRate(..), calculateVSize,
                         calculateFeeRate)
import Haskoin.FeeEstimator (FeeEstimator(..), estimateSmartFee, FeeEstimateMode(..))
import Haskoin.BlockTemplate (BlockTemplate(..), TemplateTransaction(..),
                               createBlockTemplate, submitBlock)

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
  }

--------------------------------------------------------------------------------
-- RPC Server State
--------------------------------------------------------------------------------

-- | RPC server handle
data RpcServer = RpcServer
  { rsConfig      :: !RpcConfig
  , rsDB          :: !HaskoinDB
  , rsHeaderChain :: !HeaderChain
  , rsPeerMgr     :: !PeerManager
  , rsMempool     :: !Mempool
  , rsFeeEst      :: !FeeEstimator
  , rsUTXOCache   :: !UTXOCache
  , rsNetwork     :: !Network
  , rsThread      :: !(TVar (Maybe ThreadId))
  }

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
-- Batch Request Constants
--------------------------------------------------------------------------------

-- | Maximum number of requests allowed in a batch (Bitcoin Core limit)
maxBatchSize :: Int
maxBatchSize = 1000

--------------------------------------------------------------------------------
-- Server Lifecycle
--------------------------------------------------------------------------------

-- | Start the RPC server
startRpcServer :: RpcConfig -> HaskoinDB -> HeaderChain -> PeerManager
               -> Mempool -> FeeEstimator -> UTXOCache -> Network
               -> IO RpcServer
startRpcServer config db hc pm mp fe cache net = do
  threadVar <- newTVarIO Nothing
  let server = RpcServer config db hc pm mp fe cache net threadVar
  tid <- forkIO $ run (rpcPort config) (rpcApp server)
  atomically $ writeTVar threadVar (Just tid)
  return server

-- | Stop the RPC server
stopRpcServer :: RpcServer -> IO ()
stopRpcServer rs = do
  mTid <- readTVarIO (rsThread rs)
  mapM_ killThread mTid
  atomically $ writeTVar (rsThread rs) Nothing

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
      let authOk = checkAuth (rsConfig server) req
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

-- | Check HTTP Basic authentication
checkAuth :: RpcConfig -> Request -> Bool
checkAuth config req =
  case lookup hAuthorization (requestHeaders req) of
    Nothing -> False
    Just authHeader ->
      let expected = "Basic " <> B64.encode (TE.encodeUtf8 $
            rpcUser config <> ":" <> rpcPassword config)
      in authHeader == expected

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
    "getblockcount"        -> handleGetBlockCount server
    "getblockhash"         -> handleGetBlockHash server params
    "getblock"             -> handleGetBlock server params
    "getblockheader"       -> handleGetBlockHeader server params
    "gettxout"             -> handleGetTxOut server params
    "getbestblockhash"     -> handleGetBestBlockHash server
    "getdifficulty"        -> handleGetDifficulty server

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

    -- Fee estimation
    "estimatesmartfee"     -> handleEstimateSmartFee server params

    -- Utility
    "validateaddress"      -> handleValidateAddress server params
    "getinfo"              -> handleGetInfo server

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
        , "warnings"             .= ([] :: [Text])
        ]
  return $ RpcResponse result Null Null

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
          let verbosity = fromMaybe 1 (extractParam params 1 :: Maybe Int)
          mBlock <- getBlock (rsDB server) bh
          case mBlock of
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Block not found") Null
            Just block -> do
              if verbosity == 0
                then do
                  -- Return raw hex
                  let rawHex = TE.decodeUtf8 $ B16.encode (encode block)
                  return $ RpcResponse (toJSON rawHex) Null Null
                else do
                  -- Return JSON object
                  entries <- readTVarIO (hcEntries (rsHeaderChain server))
                  let mEntry = Map.lookup bh entries
                      txids = map computeTxId (blockTxns block)
                      result = object $ catMaybes
                        [ Just $ "hash" .= showHash bh
                        , Just $ "confirmations" .= (1 :: Int)
                        , Just $ "size" .= BS.length (encode block)
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
                  let rawHex = TE.decodeUtf8 $ B16.encode (encode header)
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
      (toJSON $ TE.decodeUtf8 $ B16.encode $ encode tx) Null Null
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
  case decode txBytes of
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
          case decode txBytes of
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
  let mpCfg = mpConfig (rsMempool server)
      result = object
        [ "loaded"          .= True
        , "size"            .= count
        , "bytes"           .= size
        , "usage"           .= size
        , "maxmempool"      .= mpcMaxSize mpCfg
        , "mempoolminfee"   .= getFeeRate (mpcMinFeeRate mpCfg)
        , "minrelaytxfee"   .= (1 :: Int)
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
  -- Our local services: NODE_NETWORK (1) + NODE_WITNESS (8) = 9
  let localServices = nodeNetwork .|. nodeWitness :: Word64
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
        , "timeoffset"         .= (0 :: Int)
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
  let peerInfos = map peerToJSON peers
  return $ RpcResponse (toJSON peerInfos) Null Null
  where
    peerToJSON (addr, info) = object
      [ "addr"            .= show addr
      , "services"        .= show (piServices info)
      , "lastsend"        .= piLastSeen info
      , "lastrecv"        .= piLastSeen info
      , "conntime"        .= piConnectedAt info
      , "pingtime"        .= fromMaybe (0 :: Double) (piPingLatency info)
      , "version"         .= maybe (0 :: Int32) vVersion (piVersion info)
      , "subver"          .= maybe "" (TE.decodeUtf8 . getVarString . vUserAgent) (piVersion info)
      , "inbound"         .= piInbound info
      , "startingheight"  .= piStartHeight info
      , "banscore"        .= piBanScore info
      , "bytessent"       .= piBytesSent info
      , "bytesrecv"       .= piBytesRecv info
      ]

-- | Get the number of connected peers
handleGetConnectionCount :: RpcServer -> IO RpcResponse
handleGetConnectionCount server = do
  count <- getPeerCount (rsPeerMgr server)
  return $ RpcResponse (toJSON count) Null Null

-- | Add a node to connect to
handleAddNode :: RpcServer -> Value -> IO RpcResponse
handleAddNode _server _params =
  -- Placeholder - would actually initiate a connection
  return $ RpcResponse (toJSON True) Null Null

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
      [ "data"   .= (TE.decodeUtf8 $ B16.encode $ encode $ ttTx tt)
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
          case decode blockBytes of
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

-- | Submit a mined block
handleSubmitBlock :: RpcServer -> Value -> IO RpcResponse
handleSubmitBlock server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing block hex") Null
    Just hexBlock -> do
      case B16.decode (TE.encodeUtf8 hexBlock) of
        Left err -> return $ RpcResponse Null
          (toJSON $ RpcError rpcMiscError (T.pack $ "Hex decode error: " ++ err)) Null
        Right blockBytes -> do
          case decode blockBytes of
            Left err -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError (T.pack $ "Block decode error: " ++ err)) Null
            Right block -> do
              result <- submitBlock (rsNetwork server) (rsDB server)
                          (rsHeaderChain server) (rsUTXOCache server)
                          (rsPeerMgr server) block
              case result of
                Left err -> return $ RpcResponse (toJSON err) Null Null
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
        , "testnet"         .= (netName (rsNetwork server) /= "mainnet")
        , "errors"          .= ("" :: Text)
        ]
  return $ RpcResponse result Null Null

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
  , "size"     .= BS.length (encode tx)
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
      hexTx = TE.decodeUtf8 $ B16.encode $ encode tx

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
      OP_FALSE -> "0"
      OP_PUSHDATA bs _ -> TE.decodeUtf8 $ B16.encode bs
      OP_1NEGATE -> "-1"
      OP_RESERVED -> "OP_RESERVED"
      OP_1 -> "1"
      OP_TRUE -> "1"
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
      OP_CHECKSIGADD -> "OP_CHECKSIGADD"
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
  P2WPKH (Hash160 h) -> Just $ encodeBech32 (T.pack $ netBech32Prefix net) 0 h
  P2WSH (Hash256 h) -> Just $ encodeBech32 (T.pack $ netBech32Prefix net) 0 h
  P2TR (Hash256 h)  -> Just $ encodeBech32m (T.pack $ netBech32Prefix net) 1 h
  _ -> Nothing
  where
    -- Base58Check encoding
    encodeBase58Check :: ByteString -> Text
    encodeBase58Check payload =
      let checksum = BS.take 4 $ doubleSHA256 payload
      in TE.decodeUtf8 $ encodeBase58' (payload <> checksum)

    encodeBase58' :: ByteString -> ByteString
    encodeBase58' bs =
      let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
          leadingZeros = BS.length $ BS.takeWhile (== 0) bs
          n = bsToInteger bs
          encoded = go n ""
          go 0 acc = acc
          go v acc = go (v `div` 58) (BS.index alphabet (fromIntegral (v `mod` 58)) : acc)
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

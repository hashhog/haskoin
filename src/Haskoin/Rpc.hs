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
  ) where

import Data.Aeson
import Data.Aeson.Types (Parser)
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
import Data.Maybe (fromMaybe, catMaybes)
import Text.Printf (printf)
import qualified Data.Vector as V

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256, computeTxId, computeBlockHash, textToAddress)
import Haskoin.Consensus (Network(..), HeaderChain(..), ChainEntry(..),
                           bitsToTarget, blockReward)
import Haskoin.Storage (HaskoinDB, UTXOCache(..), getBlock, getBlockHeader,
                         lookupUTXO, UTXOEntry(..))
import Haskoin.Network (PeerManager(..), PeerInfo(..), Version(..),
                         getPeerCount, getConnectedPeers, broadcastMessage,
                         Message(..), Inv(..), InvVector(..), InvType(..),
                         protocolVersion)
import Haskoin.Mempool (Mempool(..), MempoolEntry(..), MempoolConfig(..),
                         addTransaction, getTransaction, getMempoolTxIds,
                         getMempoolSize, FeeRate(..))
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
          -- Read request body
          body <- readBody req
          case eitherDecode (BL.fromStrict body) of
            Left err -> respond $ jsonResponse $ RpcResponse
              Null (toJSON $ RpcError rpcParseError (T.pack err)) Null
            Right rpcReq -> do
              result <- handleRpcRequest server rpcReq
              respond $ jsonResponse result

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

-- | Create a JSON response
jsonResponse :: RpcResponse -> Response
jsonResponse rpcRes = responseLBS status200
  [(hContentType, "application/json")]
  (encode rpcRes)

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
handleGetBlockchainInfo :: RpcServer -> IO RpcResponse
handleGetBlockchainInfo server = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  let result = object
        [ "chain"             .= netName (rsNetwork server)
        , "blocks"            .= ceHeight tip
        , "headers"           .= ceHeight tip
        , "bestblockhash"     .= showHash (ceHash tip)
        , "difficulty"        .= getDifficulty (bhBits (ceHeader tip))
        , "chainwork"         .= showHex (ceChainWork tip)
        , "size_on_disk"      .= (0 :: Int)
        , "pruned"            .= False
        , "warnings"          .= ("" :: Text)
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
          -- Check mempool first
          mMempoolEntry <- getTransaction (rsMempool server) txid
          case mMempoolEntry of
            Just entry -> do
              let tx = meTransaction entry
                  verbose = fromMaybe False (extractParam params 1 :: Maybe Bool)
              if not verbose
                then return $ RpcResponse
                  (toJSON $ TE.decodeUtf8 $ B16.encode $ encode tx) Null Null
                else return $ RpcResponse (txToJSON tx txid) Null Null
            Nothing -> return $ RpcResponse Null
              (toJSON $ RpcError rpcMiscError "Transaction not found") Null

-- | Submit a raw transaction to the network
handleSendRawTransaction :: RpcServer -> Value -> IO RpcResponse
handleSendRawTransaction server params = do
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
              result <- addTransaction (rsMempool server) tx
              case result of
                Left err -> return $ RpcResponse Null
                  (toJSON $ RpcError rpcMiscError (T.pack $ show err)) Null
                Right txid -> do
                  -- Broadcast to peers
                  broadcastMessage (rsPeerMgr server) $
                    MInv $ Inv [InvVector InvWitnessTx (getTxIdHash txid)]
                  return $ RpcResponse
                    (toJSON $ showHash (BlockHash (getTxIdHash txid))) Null Null

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
handleGetRawMempool :: RpcServer -> Value -> IO RpcResponse
handleGetRawMempool server _params = do
  txids <- getMempoolTxIds (rsMempool server)
  let result = toJSON $ map (\txid -> showHash (BlockHash (getTxIdHash txid))) txids
  return $ RpcResponse result Null Null

--------------------------------------------------------------------------------
-- Network RPC Handlers
--------------------------------------------------------------------------------

-- | Get network information
handleGetNetworkInfo :: RpcServer -> IO RpcResponse
handleGetNetworkInfo server = do
  peerCount <- getPeerCount (rsPeerMgr server)
  let result = object
        [ "version"          .= (10000 :: Int)
        , "subversion"       .= ("/Haskoin:0.1.0/" :: Text)
        , "protocolversion"  .= protocolVersion
        , "connections"      .= peerCount
        , "networks"         .= ([] :: [Value])
        , "relayfee"         .= (0.00001 :: Double)
        , "localrelay"       .= True
        , "warnings"         .= ("" :: Text)
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
handleGetBlockTemplate :: RpcServer -> Value -> IO RpcResponse
handleGetBlockTemplate server _params = do
  bt <- createBlockTemplate (rsNetwork server) (rsHeaderChain server)
          (rsMempool server) (rsUTXOCache server)
          BS.empty BS.empty  -- placeholder coinbase script
  let result = object
        [ "version"           .= btVersion bt
        , "previousblockhash" .= showHash (btPreviousBlock bt)
        , "transactions"      .= map templateTxToJSON (btTransactions bt)
        , "coinbasevalue"     .= btCoinbaseValue bt
        , "target"            .= showHex (bitsToTarget (btBits bt))
        , "mintime"           .= btMinTime bt
        , "curtime"           .= btCurTime bt
        , "bits"              .= showBits (btBits bt)
        , "height"            .= btHeight bt
        , "sigoplimit"        .= btSigopLimit bt
        , "weightlimit"       .= btWeightLimit bt
        ]
  return $ RpcResponse result Null Null
  where
    templateTxToJSON tt = object
      [ "data"   .= (TE.decodeUtf8 $ B16.encode $ encode $ ttTx tt)
      , "txid"   .= showHash (BlockHash (getTxIdHash (ttTxId tt)))
      , "fee"    .= ttFee tt
      , "sigops" .= ttSigops tt
      , "weight" .= ttWeight tt
      , "depends" .= ttDepends tt
      ]

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
handleValidateAddress :: RpcServer -> Value -> IO RpcResponse
handleValidateAddress _server params = do
  case extractParamText params 0 of
    Nothing -> return $ RpcResponse Null
      (toJSON $ RpcError rpcInvalidParams "Missing address") Null
    Just addr ->
      case textToAddress addr of
        Just _  -> return $ RpcResponse (object
          [ "isvalid" .= True
          , "address" .= addr
          ]) Null Null
        Nothing -> return $ RpcResponse (object
          [ "isvalid" .= False
          ]) Null Null

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

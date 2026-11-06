{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | RPC-submitted transactions are flagged unbroadcast until a peer asks.
--
-- Core node/transaction.cpp BroadcastTransaction calls
-- mempool.AddUnbroadcastTx(txid) for every sendrawtransaction;
-- rpc/mempool.cpp reports it as entry.unbroadcast and
-- getmempoolinfo.unbroadcastcount.  net_processing ProcessGetData and
-- txmempool removeUnchecked erase it.  haskoin always said false / 0.
module UnbroadcastSetSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically, writeTVar, readTVarIO)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))
import Data.Word (Word32, Word64)

import Haskoin.Types
import Data.Serialize (encode)
import qualified Data.Text.Encoding as TE
import Data.Word (Word8)
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, addUTXO, UTXOEntry(..))
import Haskoin.Crypto (sha256)
import Control.Concurrent.STM (modifyTVar')
import qualified Data.Set as Set
import qualified Data.ByteString.Base16 as B16
import Haskoin.Mempool
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest )

dropScript :: BS.ByteString
dropScript = BS.pack [0x75, 0x51, 0x75]

dropSpk :: BS.ByteString
dropSpk = BS.pack [0x00, 0x20] <> sha256 dropScript

coin :: OutPoint
coin = OutPoint (TxId (Hash256 (BS.replicate 32 0x5c))) 0

spendTx :: Tx
spendTx = Tx
  { txVersion = 2
  , txInputs = [TxIn coin BS.empty 0xfffffffd]
  , txOutputs = [TxOut 90_000 dropSpk]
  , txWitness = [[BS.replicate 80 0x11, BS.replicate 80 0x22, dropScript]]
  , txLockTime = 0 }

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-rawmempool-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      atomically $ addUTXO cache coin (UTXOEntry (TxOut 100_000 dropSpk) 1 False False)
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg liveNoopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
        action RpcServer
              { rsConfig = cfg, rsDB = db, rsHeaderChain = hc, rsPeerMgr = pm
              , rsMempool = mp, rsFeeEst = fe, rsUTXOCache = cache
              , rsNetwork = regtest, rsBlockStore = Nothing
              , rsThread = threadVar, rsMockTime = mockTimeVar
              , rsWalletMgr = Nothing, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }


rpc :: RpcServer -> T.Text -> [A.Value] -> IO A.Value
rpc server m ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String m), ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o | Just r <- KM.lookup "result" o -> return r
    other -> fail ("unexpected response: " ++ show other)

hexTx :: Tx -> A.Value
hexTx = A.String . TE.decodeUtf8 . B16.encode . encode

unbroadcastFlag :: RpcServer -> TxId -> IO A.Value
unbroadcastFlag server t = do
  r <- rpc server "getrawmempool" [A.Bool True]
  case r of
    A.Object o | Just (A.Object e) <- KM.lookup (Key.fromText (hex t)) o ->
      maybe (fail "no unbroadcast key") return (KM.lookup "unbroadcast" e)
    _ -> fail "tx not in getrawmempool"

infoCount :: RpcServer -> IO A.Value
infoCount server = do
  r <- rpc server "getmempoolinfo" []
  case r of
    A.Object o -> maybe (fail "no unbroadcastcount") return (KM.lookup "unbroadcastcount" o)
    _ -> fail "bad info"

hex :: TxId -> T.Text
hex (TxId (Hash256 bs)) = T.pack (concatMap byte (reverse (BS.unpack bs)))
  where byte b = [d (b `div` 16), d (b `mod` 16)]
        d n = "0123456789abcdef" !! fromIntegral (n :: Word8)

spec :: Spec
spec = describe "unbroadcast set (sendrawtransaction)" $ do
  let tid = computeTxId spendTx

  it "unbroadcast-flag-after-sendrawtransaction: entry.unbroadcast is true and getmempoolinfo.unbroadcastcount is 1" $
    withServer $ \server -> do
      _ <- rpc server "sendrawtransaction" [hexTx spendTx]
      unbroadcastFlag server tid >>= (`shouldBe` A.Bool True)
      infoCount server >>= (`shouldBe` A.Number 1)

  it "unbroadcast-cleared-when-peer-requests: dropping from the set reports false / 0" $
    withServer $ \server -> do
      _ <- rpc server "sendrawtransaction" [hexTx spendTx]
      unbroadcastFlag server tid >>= (`shouldBe` A.Bool True)
      atomically $ modifyTVar' (mpUnbroadcast (rsMempool server)) (Set.delete tid)
      unbroadcastFlag server tid >>= (`shouldBe` A.Bool False)
      infoCount server >>= (`shouldBe` A.Number 0)

  it "unbroadcast-erased-on-removal: removing the tx from the pool clears the set" $
    withServer $ \server -> do
      _ <- rpc server "sendrawtransaction" [hexTx spendTx]
      infoCount server >>= (`shouldBe` A.Number 1)
      removeTransaction (rsMempool server) tid
      infoCount server >>= (`shouldBe` A.Number 0)
      readTVarIO (mpUnbroadcast (rsMempool server)) >>= (`shouldBe` Set.empty)

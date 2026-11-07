{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | sendrawtransaction error paths follow Core's BroadcastTransaction.
--
-- node/transaction.cpp, in order: an output of the tx already unspent in the
-- chain -> -27 "Transaction outputs already in utxo set"; a txid already in
-- the mempool -> re-announce and return the txid (no error); otherwise
-- ATMP, whose TX_MISSING_INPUTS text is the state string
-- "bad-txns-inputs-missingorspent" (testmempoolaccept alone remaps it to
-- "missing-inputs").  haskoin answered -25 "missing-inputs" for a confirmed
-- tx, -27 "txn-already-in-mempool" for a known one, and "missing-inputs" for
-- a missing parent (core-regtest rows operator/sendrawtransaction/
-- {in-mempool,confirmed,missing-inputs}).
--
-- TEETH: on the unfixed tree all three sendrawtransaction cases fail.
module SendRawErrorsSpec (spec) where

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


rpcFull :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
rpcFull server m ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String m), ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

hexTx :: Tx -> A.Value
hexTx = A.String . TE.decodeUtf8 . B16.encode . encode

hex :: TxId -> T.Text
hex (TxId (Hash256 bs)) = T.pack (concatMap byte (reverse (BS.unpack bs)))
  where byte b = [d (b `div` 16), d (b `mod` 16)]
        d n = "0123456789abcdef" !! fromIntegral (n :: Word8)

errField :: T.Text -> A.Value -> Maybe A.Value
errField k (A.Object o) = KM.lookup (fromText' k) o
  where fromText' = Key.fromText
errField _ _ = Nothing

spec :: Spec
spec = describe "sendrawtransaction errors (Core BroadcastTransaction)" $ do
  let txid = computeTxId spendTx
  it "a tx already in the mempool returns its txid, not an error" $
    withServer $ \server -> do
      (r1, e1) <- rpcFull server "sendrawtransaction" [hexTx spendTx]
      e1 `shouldBe` A.Null
      r1 `shouldBe` A.String (hex txid)
      (r2, e2) <- rpcFull server "sendrawtransaction" [hexTx spendTx]
      e2 `shouldBe` A.Null
      r2 `shouldBe` A.String (hex txid)
  it "a tx whose outputs are already in the UTXO set is -27" $
    withServer $ \server -> do
      atomically $ addUTXO (rsUTXOCache server) (OutPoint txid 0)
        (UTXOEntry (TxOut 90_000 dropSpk) 2 False False)
      (r, e) <- rpcFull server "sendrawtransaction" [hexTx spendTx]
      r `shouldBe` A.Null
      errField "code" e `shouldBe` Just (A.Number (-27))
      errField "message" e `shouldBe` Just (A.String "Transaction outputs already in utxo set")
  it "a missing parent says bad-txns-inputs-missingorspent (-25); testmempoolaccept keeps missing-inputs" $
    withServer $ \server -> do
      let orphan = spendTx { txInputs = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0x22))) 1) BS.empty 0xfffffffd] }
      (r, e) <- rpcFull server "sendrawtransaction" [hexTx orphan]
      r `shouldBe` A.Null
      errField "code" e `shouldBe` Just (A.Number (-25))
      errField "message" e `shouldBe` Just (A.String "bad-txns-inputs-missingorspent")
      (t, te) <- rpcFull server "testmempoolaccept" [A.Array (V.fromList [hexTx orphan])]
      te `shouldBe` A.Null
      case t of
        A.Array xs | [A.Object o] <- V.toList xs ->
          KM.lookup "reject-reason" o `shouldBe` Just (A.String "missing-inputs")
        other -> expectationFailure ("unexpected testmempoolaccept result: " ++ show other)

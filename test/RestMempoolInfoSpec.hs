{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | REST @/rest/mempool/info.json@ is Core's getmempoolinfo object.
--
-- Core builds the REST body from the same function as the RPC:
-- rest.cpp:825 @MempoolInfoToJSON(*mempool).write() + "\n"@
-- (MempoolInfoToJSON is rpc/mempool.cpp:1043).  haskoin's REST handler built
-- its own 7-field subset: no total_fee, incrementalrelayfee, unbroadcastcount,
-- fullrbf or the five v31 policy fields, and mempoolminfee / minrelaytxfee as
-- raw sat/kvB (100) instead of BTC/kvB (0.000001).  The Core regtest rows
-- @warden_invalidated_submit/rest/pressure-info:*@ (10 rows) are this.
--
-- TEETH: on the unfixed tree every case below fails (missing keys, 100 /= 1.0e-6,
-- REST object /= RPC object).
module RestMempoolInfoSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically, writeTVar)
import Data.IORef (newIORef)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as Key
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as BL
import qualified Data.Vector as V
import Data.Word (Word32, Word64)
import Network.Wai.Internal (Response(..))
import System.Directory
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest, handleRestMempoolInfo )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-restmempoolinfo-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
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

mkTx :: Word32 -> Tx
mkTx salt = Tx
  { txVersion = 2
  , txInputs  = [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0xee))) salt) BS.empty 0xfffffffd ]
  , txOutputs = [ TxOut 1_000 BS.empty ]
  , txWitness = []
  , txLockTime = salt
  }

mkEntry :: Tx -> Word64 -> MempoolEntry
mkEntry tx fee = MempoolEntry
  { meTransaction = tx, meTxId = computeTxId tx
  , meWtxid = Wtxid (getTxIdHash (computeTxId tx))
  , meFee = fee, meFeeRate = FeeRate 0, meSize = 100, meAdjWeight = 400
  , meTime = 0, meHeight = 0
  , meAncestorCount = 1, meAncestorSize = 0, meAncestorFees = 0, meAncestorSigOps = 0
  , meDescendantCount = 1, meDescendantSize = 0, meDescendantFees = 0
  , meRBFOptIn = True }

load :: RpcServer -> [MempoolEntry] -> IO ()
load server es = atomically $
  writeTVar (mpEntries (rsMempool server)) (Map.fromList [ (meTxId e, e) | e <- es ])

-- | The JSON object REST /rest/mempool/info.json returns.
restInfo :: RpcServer -> IO (KM.KeyMap A.Value)
restInfo server = do
  resp <- handleRestMempoolInfo server ".json"
  body <- case resp of
    ResponseBuilder _ _ b -> return (BB.toLazyByteString b)
    _ -> fail "unexpected REST response kind"
  case A.decode body of
    Just (A.Object o) -> return o
    _ -> fail ("REST body is not a JSON object: " ++ show (BL.take 200 body))

-- | The getmempoolinfo RPC result object.
rpcInfo :: RpcServer -> IO (KM.KeyMap A.Value)
rpcInfo server = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getmempoolinfo")
        , ("params", A.Array V.empty) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o | Just (A.Object r) <- KM.lookup "result" o -> return r
    other -> fail ("unexpected getmempoolinfo response: " ++ show other)

field :: KM.KeyMap A.Value -> T.Text -> Maybe A.Value
field o k = KM.lookup (Key.fromText k) o

spec :: Spec
spec = describe "REST /rest/mempool/info.json (Core rest.cpp:825 MempoolInfoToJSON)" $ do
  it "rest-mempool-info carries every getmempoolinfo field (fullrbf, total_fee, v31 policy fields)" $
    withServer $ \server -> do
      r <- restInfo server
      let want = [ "loaded", "size", "bytes", "usage", "total_fee", "maxmempool"
                 , "mempoolminfee", "minrelaytxfee", "incrementalrelayfee"
                 , "unbroadcastcount", "fullrbf", "permitbaremultisig"
                 , "maxdatacarriersize", "limitclustercount", "limitclustersize"
                 , "optimal" ]
      filter (\k -> field r k == Nothing) want `shouldBe` []

  it "rest-mempool-info reports mempoolminfee and minrelaytxfee in BTC/kvB, not sat/kvB" $
    withServer $ \server -> do
      r <- restInfo server
      field r "minrelaytxfee" `shouldBe` Just (A.Number 0.000001)
      field r "mempoolminfee" `shouldBe` Just (A.Number 0.000001)
      field r "incrementalrelayfee" `shouldBe` Just (A.Number 0.000001)

  it "rest-mempool-info equals the getmempoolinfo RPC object with a non-empty mempool" $
    withServer $ \server -> do
      load server [mkEntry (mkTx 1) 990_000, mkEntry (mkTx 2) 10_000]
      r <- restInfo server
      field r "total_fee" `shouldBe` Just (A.Number 0.01)
      field r "size" `shouldBe` Just (A.Number 2)
      rpc <- rpcInfo server
      r `shouldBe` rpc

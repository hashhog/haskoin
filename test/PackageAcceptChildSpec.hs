{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | testmempoolaccept with several txs is a package evaluation.
--
-- Core rpc/mempool.cpp testmempoolaccept: more than one raw tx goes to
-- ProcessNewPackage(test_accept=true) (validation.cpp AcceptPackage), so a child
-- is judged WITH its in-package parent.  Results carry
-- fees.effective-feerate / effective-includes.  haskoin judged each tx alone,
-- so the child said allowed=false, reject-reason=missing-inputs.
module PackageAcceptChildSpec (spec) where

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
import Haskoin.Crypto (computeTxId, computeWtxid)
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

hex :: TxId -> T.Text
hex (TxId (Hash256 bs)) = T.pack (concatMap byte (reverse (BS.unpack bs)))
  where byte b = [d (b `div` 16), d (b `mod` 16)]
        d n = "0123456789abcdef" !! fromIntegral (n :: Word8)

wtx :: Tx -> T.Text
wtx t = hex (TxId (getWtxidHash (computeWtxid t)))

mkTx :: OutPoint -> Word64 -> Tx
mkTx op out = Tx
  { txVersion = 2
  , txInputs = [TxIn op BS.empty 0xfffffffd]
  , txOutputs = [TxOut out dropSpk]
  , txWitness = [[BS.replicate 80 0x11, BS.replicate 80 0x22, dropScript]]
  , txLockTime = 0 }

-- parent: 100_000 -> 90_000 (fee 10_000); child spends it: 90_000 -> 80_000
parentTx, childTx :: Tx
parentTx = mkTx coin 90_000
childTx  = mkTx (OutPoint (computeTxId parentTx) 0) 80_000

results :: A.Value -> [A.Object]
results (A.Array v) = [o | A.Object o <- V.toList v]
results _ = []

field :: A.Key -> A.Object -> Maybe A.Value
field = KM.lookup

spec :: Spec
spec = describe "testmempoolaccept package evaluation" $ do
  it "package-child-sees-in-package-parent: child is allowed with its parent, not missing-inputs" $
    withServer $ \server -> do
      r <- rpc server "testmempoolaccept" [A.toJSON [hexTx parentTx, hexTx childTx]]
      let [p, c] = results r
      field "allowed" p `shouldBe` Just (A.Bool True)
      field "allowed" c `shouldBe` Just (A.Bool True)
      field "reject-reason" c `shouldBe` Nothing

  it "package-effective-includes: each result reports effective-feerate and its own wtxid in effective-includes" $
    withServer $ \server -> do
      r <- rpc server "testmempoolaccept" [A.toJSON [hexTx parentTx, hexTx childTx]]
      let [p, c] = results r
          inc o = field "fees" o >>= \f -> case f of
                    A.Object fo -> KM.lookup "effective-includes" fo
                    _ -> Nothing
          rate o = field "fees" o >>= \f -> case f of
                    A.Object fo -> KM.lookup "effective-feerate" fo
                    _ -> Nothing
      inc p `shouldBe` Just (A.toJSON [wtx parentTx])
      inc c `shouldBe` Just (A.toJSON [wtx childTx])
      rate p `shouldSatisfy` (/= Nothing)

  it "package-single-effective-feerate: a lone tx reports effective-feerate and itself in effective-includes" $
    withServer $ \server -> do
      r <- rpc server "testmempoolaccept" [A.toJSON [hexTx parentTx]]
      let [p] = results r
          inc = field "fees" p >>= \f -> case f of
                    A.Object fo -> KM.lookup "effective-includes" fo
                    _ -> Nothing
      field "allowed" p `shouldBe` Just (A.Bool True)
      inc `shouldBe` Just (A.toJSON [wtx parentTx])

  it "package-first-failure-stops: a below-floor parent is rejected on its own and the child gets no verdict (no CPFP rescue in test_accept)" $
    withServer $ \server -> do
      let lowParent = mkTx coin 99_999            -- fee 1 sat
          highChild = mkTx (OutPoint (computeTxId lowParent) 0) 50_000
      r <- rpc server "testmempoolaccept" [A.toJSON [hexTx lowParent, hexTx highChild]]
      let [p, c] = results r
      field "allowed" p `shouldBe` Just (A.Bool False)
      field "reject-reason" p `shouldBe` Just (A.String "min relay fee not met")
      field "allowed" c `shouldBe` Nothing
      field "txid" c `shouldBe` Just (A.String (hex (computeTxId highChild)))

  it "package-child-alone-still-missing-inputs: the same child without its parent is rejected" $
    withServer $ \server -> do
      r <- rpc server "testmempoolaccept" [A.toJSON [hexTx childTx]]
      let [c] = results r
      field "allowed" c `shouldBe` Just (A.Bool False)
      field "reject-reason" c `shouldBe` Just (A.String "missing-inputs")

  it "package-dry-run-leaves-pool-empty: testing a package admits nothing" $
    withServer $ \server -> do
      _ <- rpc server "testmempoolaccept" [A.toJSON [hexTx parentTx, hexTx childTx]]
      r <- rpc server "getrawmempool" []
      r `shouldBe` A.toJSON ([] :: [T.Text])

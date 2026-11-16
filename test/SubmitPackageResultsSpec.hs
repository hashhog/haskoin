{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | submitpackage per-tx results follow Core's AcceptPackage.
--
-- Core validation.cpp MemPoolAccept::AcceptPackage tries each tx alone first:
-- a tx that passes alone is admitted and stays admitted; a tx that fails alone
-- for a reason other than feerate / missing inputs ends package evaluation
-- with package_msg "transaction failed"; the remaining txs are still tried
-- alone.  rpc/mempool.cpp submitpackage gives every tx its own result: vsize +
-- fees for an admitted tx, "error" = TxValidationState::ToString() for a
-- rejected one.  haskoin evaluated the package atomically, rolled back every
-- tx, answered "package validation failed", and put the Haskell @show@ of one
-- package error into every tx's "error".
--
-- Core regtest rows: package/submit/missing-input,
-- seed_submitpackage/invalid-sig-{child,parent}/submit and /txids.
module SubmitPackageResultsSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, atomically)
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
import Data.Word (Word8, Word64)
import Data.List (sort)

import Haskoin.Types
import Data.Serialize (encode)
import qualified Data.Text.Encoding as TE
import Haskoin.Crypto (computeTxId, computeWtxid, sha256)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, addUTXO, UTXOEntry(..))
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

-- P2WSH of OP_DROP OP_1 OP_DROP: the witness [a, b, script] leaves [a] on the
-- stack, so the input is valid iff a is true.
dropScript :: BS.ByteString
dropScript = BS.pack [0x75, 0x51, 0x75]

dropSpk :: BS.ByteString
dropSpk = BS.pack [0x00, 0x20] <> sha256 dropScript

goodWit, badWit :: [BS.ByteString]
goodWit = [BS.replicate 80 0x11, BS.replicate 80 0x22, dropScript]
badWit  = [BS.empty,             BS.replicate 80 0x22, dropScript]   -- evaluates to false

coin :: OutPoint
coin = OutPoint (TxId (Hash256 (BS.replicate 32 0x5c))) 0

-- An outpoint that exists nowhere.
nowhere :: OutPoint
nowhere = OutPoint (TxId (Hash256 (BS.replicate 32 0x22))) 0

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-submitpackage-")
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

mkTx :: [(OutPoint, [BS.ByteString])] -> Word64 -> Tx
mkTx ins out = Tx
  { txVersion = 2
  , txInputs = [TxIn op BS.empty 0xfffffffd | (op, _) <- ins]
  , txOutputs = [TxOut out dropSpk]
  , txWitness = map snd ins
  , txLockTime = 0 }

spendOf :: Tx -> OutPoint
spendOf p = OutPoint (computeTxId p) 0

-- parent: 100_000 -> 90_000 (fee 10_000), valid on its own.
parentOk :: Tx
parentOk = mkTx [(coin, goodWit)] 90_000

submit :: RpcServer -> [Tx] -> IO (A.Object, A.Value)
submit server txs = do
  r <- rpc server "submitpackage" [A.toJSON (map hexTx txs)]
  case r of
    A.Object o -> return (o, r)
    other -> fail ("unexpected submitpackage result: " ++ show other)

-- tx-results[wtxid of tx]
txResult :: A.Object -> Tx -> A.Object
txResult o t = case KM.lookup "tx-results" o of
  Just (A.Object m) | Just (A.Object r) <- KM.lookup (Key.fromText (wtx t)) m -> r
  _ -> KM.empty

pool :: RpcServer -> IO [T.Text]
pool server = do
  r <- rpc server "getrawmempool" []
  case A.fromJSON r of
    A.Success xs -> return (sort xs)
    A.Error e    -> fail e

-- No Haskell constructor / record text may leak into an RPC error.
noHaskellShow :: Maybe A.Value -> Expectation
noHaskellShow (Just (A.String s)) =
  s `shouldSatisfy` (\t -> not (any (`T.isInfixOf` t) ["PkgTxError", "TxId {", "getTxIdHash", "Err"]))
noHaskellShow other = expectationFailure ("expected a string error, got " ++ show other)

spec :: Spec
spec = describe "submitpackage per-tx results (Core AcceptPackage)" $ do
  it "submitpackage-missing-input: the parent that passes alone stays admitted, the child reports bad-txns-inputs-missingorspent" $
    withServer $ \server -> do
      let child = mkTx [(spendOf parentOk, goodWit), (nowhere, goodWit)] 80_000
      (o, _) <- submit server [parentOk, child]
      KM.lookup "package_msg" o `shouldBe` Just (A.String "transaction failed")
      let p = txResult o parentOk
          c = txResult o child
      KM.lookup "error" p `shouldBe` Nothing
      KM.lookup "vsize" p `shouldSatisfy` (/= Nothing)
      KM.lookup "error" c `shouldBe` Just (A.String "bad-txns-inputs-missingorspent")
      noHaskellShow (KM.lookup "error" c)
      pool server `shouldReturn` [hex (computeTxId parentOk)]

  it "submitpackage-invalid-child: a child failing its script does not roll back the parent admitted alone" $
    withServer $ \server -> do
      let child = mkTx [(spendOf parentOk, badWit)] 80_000
      (o, _) <- submit server [parentOk, child]
      KM.lookup "package_msg" o `shouldBe` Just (A.String "transaction failed")
      KM.lookup "error" (txResult o parentOk) `shouldBe` Nothing
      let ce = KM.lookup "error" (txResult o child)
      ce `shouldSatisfy` (/= Nothing)
      ce `shouldSatisfy` (/= Just (A.String "bad-txns-inputs-missingorspent"))
      noHaskellShow ce
      pool server `shouldReturn` [hex (computeTxId parentOk)]

  it "submitpackage-invalid-parent: the parent gets its own reason, the child bad-txns-inputs-missingorspent, nothing admitted" $
    withServer $ \server -> do
      let badParent = mkTx [(coin, badWit)] 90_000
          child     = mkTx [(spendOf badParent, goodWit)] 80_000
      (o, _) <- submit server [badParent, child]
      KM.lookup "package_msg" o `shouldBe` Just (A.String "transaction failed")
      let pe = KM.lookup "error" (txResult o badParent)
      pe `shouldSatisfy` (/= Nothing)
      noHaskellShow pe
      KM.lookup "error" (txResult o child) `shouldBe` Just (A.String "bad-txns-inputs-missingorspent")
      pool server `shouldReturn` []

  it "submitpackage-single-failure: a lone failing tx reports Core's reason, not Haskell show output" $
    withServer $ \server -> do
      let orphan = mkTx [(nowhere, goodWit)] 80_000
      (o, _) <- submit server [orphan]
      KM.lookup "package_msg" o `shouldBe` Just (A.String "transaction failed")
      KM.lookup "error" (txResult o orphan) `shouldBe` Just (A.String "bad-txns-inputs-missingorspent")

  it "submitpackage-admitted-alone-effective-includes: a tx admitted alone reports itself in effective-includes" $
    withServer $ \server -> do
      let child = mkTx [(spendOf parentOk, goodWit)] 80_000
      (o, _) <- submit server [parentOk, child]
      KM.lookup "package_msg" o `shouldBe` Just (A.String "success")
      let incl t = case KM.lookup "fees" (txResult o t) of
                     Just (A.Object f) -> KM.lookup "effective-includes" f
                     _ -> Nothing
      incl parentOk `shouldBe` Just (A.toJSON [wtx parentOk])
      incl child    `shouldBe` Just (A.toJSON [wtx child])

  -- Control: the fee-dependent path still goes through package evaluation.
  it "submitpackage-cpfp-control: a below-floor parent with a paying child is admitted as a package" $
    withServer $ \server -> do
      let lowParent = mkTx [(coin, goodWit)] 99_999            -- fee 1 sat
          child     = mkTx [(spendOf lowParent, goodWit)] 50_000
      (o, _) <- submit server [lowParent, child]
      KM.lookup "package_msg" o `shouldBe` Just (A.String "success")
      pool server `shouldReturn` sort [hex (computeTxId lowParent), hex (computeTxId child)]

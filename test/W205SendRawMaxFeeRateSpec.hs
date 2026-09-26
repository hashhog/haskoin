{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W205 sendrawtransaction maxfeerate Core parity.
--
-- Reference: bitcoin-core/src/rpc/mempool.cpp sendrawtransaction,
-- src/rpc/util.cpp ParseFeeRate, src/node/transaction.cpp
-- BroadcastTransaction:
--
--   max_raw_tx_fee_rate = ParseFeeRate(maxfeerate)        -- BTC/kvB, default 0.10
--   max_raw_tx_fee      = max_raw_tx_fee_rate.GetFee(vsize) -- rounded up
--   ATMP(test_accept=true); base_fee > max_raw_tx_fee -> MAX_FEE_EXCEEDED
--     (-25 "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)")
--   and only then ATMP(test_accept=false) + relay.
--
-- Pre-fix haskoin computed the tx feerate in sat/kvB but compared it to the
-- cap in sat/vB (so any tx above ~10 sat/vB was rejected with -25 under the
-- DEFAULT cap), and ran the check AFTER addTransaction without removing the
-- tx: every "rejected" tx stayed in the mempool, unannounced.
module W205SendRawMaxFeeRateSpec (spec, liveSpec) where

import Control.Concurrent.STM (atomically, newTVarIO)
import Control.Exception (bracket)
import Data.Aeson (Value(..))
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import qualified Data.Scientific as Sci
import Data.Serialize (encode)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import Data.Word (Word64)
import System.Directory (createDirectoryIfMissing, getTemporaryDirectory,
                         removeDirectoryRecursive)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)
import Test.Hspec

import Haskoin.Consensus (initHeaderChain, regtest)
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (calculateVSize, defaultMempoolConfig, getTransaction,
                        newMempool)
import Haskoin.Network (Message, PeerManagerConfig(..),
                        defaultPeerManagerConfig, startPeerManager,
                        stopPeerManager)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc (RpcConfig(..), RpcResponse(..), RpcServer(..),
                    defaultRpcConfig, handleBatchRequest)
import Haskoin.Storage (UTXOEntry(..), addUTXO, defaultDBConfig,
                        defaultPruneConfig, newUTXOCache, withDB)
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Types

spec :: Spec
spec = describe "W205 sendrawtransaction maxfeerate (Core parity)" liveSpec

-- | Behavioural tests through the real dispatcher.  Exported separately so
-- the same assertions can be compiled against the pre-fix tree (which lacks
-- the pure helpers) to demonstrate the failure.
liveSpec :: Spec
liveSpec = do
  -- The fixture spends a P2WSH(OP_TRUE) coin to one P2WPKH output; its
  -- vsize is 84, so the default cap (0.10 BTC/kvB) is ceil(10e6*84/1000)
  -- = 840,000 sat.
  it "fixture vsize is 84 (so the default cap is 840,000 sat)" $
    calculateVSize (spendTx 1_680) `shouldBe` 84

  it "accepts a normal 20 sat/vB tx under the DEFAULT maxfeerate, and it is in the mempool" $
    withFundedServer $ \server -> do
      let tx = spendTx 1_680           -- 20 sat/vB
      r <- sendRaw server tx []
      r `shouldBe` Right (txidHex tx)
      inPool server tx >>= (`shouldBe` True)

  it "accepts a tx whose fee equals the default cap exactly (base fee > cap is the test)" $
    withFundedServer $ \server -> do
      let tx = spendTx 840_000
      r <- sendRaw server tx []
      r `shouldBe` Right (txidHex tx)

  it "rejects a tx one sat over the default cap with -25 and does NOT add it to the mempool" $
    withFundedServer $ \server -> do
      let tx = spendTx 840_001
      r <- sendRaw server tx []
      -- membership first: pre-fix the tx was left in the pool after -25
      inPool server tx >>= (`shouldBe` False)
      r `shouldBe` Left (-25, maxFeeMsg)

  it "rejects a genuinely excessive tx (~6 BTC/kvB) with -25 and does NOT add it to the mempool" $
    withFundedServer $ \server -> do
      let tx = spendTx 50_000_000
      r <- sendRaw server tx []
      -- membership first: pre-fix the tx was left in the pool after -25
      inPool server tx >>= (`shouldBe` False)
      r `shouldBe` Left (-25, maxFeeMsg)

  it "maxfeerate is BTC/kvB: 0.0002 (=20 sat/vB) admits 20 sat/vB, 0.00019 rejects it" $ do
    withFundedServer $ \server -> do
      let tx = spendTx 1_680
      sendRaw server tx [Number 0.00019] >>= (`shouldBe` Left (-25, maxFeeMsg))
      inPool server tx >>= (`shouldBe` False)
      sendRaw server tx [Number 0.0002] >>= (`shouldBe` Right (txidHex tx))
      inPool server tx >>= (`shouldBe` True)

  it "maxfeerate 0 disables the check (excessive tx accepted)" $
    withFundedServer $ \server -> do
      let tx = spendTx 50_000_000
      sendRaw server tx [Number 0] >>= (`shouldBe` Right (txidHex tx))
      inPool server tx >>= (`shouldBe` True)

  it "maxfeerate null means the default" $
    withFundedServer $ \server -> do
      let tx = spendTx 50_000_000
      sendRaw server tx [Null] >>= (`shouldBe` Left (-25, maxFeeMsg))

  it "maxfeerate accepts an amount string like Core AmountFromValue" $
    withFundedServer $ \server -> do
      let tx = spendTx 1_680
      sendRaw server tx [String "0.1"] >>= (`shouldBe` Right (txidHex tx))

  it "maxfeerate >= 1 BTC/kvB is -8 (Core ParseFeeRate), tx not added" $
    withFundedServer $ \server -> do
      let tx = spendTx 1_680
      sendRaw server tx [Number 1] >>= (`shouldBe`
        Left (-8, "Fee rates larger than or equal to 1BTC/kvB are not accepted"))
      inPool server tx >>= (`shouldBe` False)

  it "negative maxfeerate is -3 Amount out of range" $
    withFundedServer $ \server -> do
      let tx = spendTx 1_680
      sendRaw server tx [Number (-0.1)] >>= (`shouldBe` Left (-3, "Amount out of range"))

  it "maxfeerate with more than 8 decimals is -3 Invalid amount" $
    withFundedServer $ \server -> do
      let tx = spendTx 1_680
      sendRaw server tx [Number 0.000000001] >>= (`shouldBe` Left (-3, "Invalid amount"))

  it "non-numeric maxfeerate is -3 Amount is not a number or string" $
    withFundedServer $ \server -> do
      let tx = spendTx 1_680
      sendRaw server tx [Bool True] >>= (`shouldBe`
        Left (-3, "Amount is not a number or string"))

maxFeeMsg :: T.Text
maxFeeMsg = "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)"

--------------------------------------------------------------------------------
-- Fixture: a confirmed, non-coinbase P2WSH(OP_TRUE) coin worth 1 BTC.
--------------------------------------------------------------------------------

opTrueScript :: BS.ByteString
opTrueScript = BS.pack [0x51]

p2wshOpTrue :: BS.ByteString
p2wshOpTrue = BS.pack [0x00, 0x20] <> sha256 opTrueScript

fundingOutPoint :: OutPoint
fundingOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0xab))) 0

coinValue :: Word64
coinValue = 100_000_000

spendTx :: Word64 -> Tx
spendTx fee = Tx
  { txVersion  = 2
  , txInputs   = [TxIn fundingOutPoint BS.empty 0xfffffffd]
  , txOutputs  = [TxOut (coinValue - fee) (BS.pack [0x00, 0x14] <> BS.replicate 20 0x42)]
  , txWitness  = [[opTrueScript]]
  , txLockTime = 0
  }

txidHex :: Tx -> T.Text
txidHex tx = let TxId (Hash256 h) = computeTxId tx
             in TE.decodeUtf8 (B16.encode (BS.reverse h))

inPool :: RpcServer -> Tx -> IO Bool
inPool server tx = isJust <$> getTransaction (rsMempool server) (computeTxId tx)

-- | sendrawtransaction through the real dispatcher: Right txid | Left (code,msg).
sendRaw :: RpcServer -> Tx -> [Value] -> IO (Either (Int, T.Text) T.Text)
sendRaw server tx extra = do
  let hex = TE.decodeUtf8 (B16.encode (encode tx))
      req = Object $ KM.fromList
        [ (K.fromText "jsonrpc", String "2.0")
        , (K.fromText "id",      Number 1)
        , (K.fromText "method",  String "sendrawtransaction")
        , (K.fromText "params",  Array (V.fromList (String hex : extra)))
        ]
  resps <- handleBatchRequest server [req]
  case resps of
    (r:_) -> case (resError r, resResult r) of
      (Object o, _) -> do
        let code = case KM.lookup "code" o of
              Just (Number c) -> maybe 0 id (Sci.toBoundedInteger c)
              _               -> 0
            msg = case KM.lookup "message" o of
              Just (String s) -> s
              _               -> T.empty
        return (Left (code, msg))
      (Null, String t) -> return (Right t)
      other -> fail ("unexpected response " ++ show other)
    [] -> fail "no response"

withFundedServer :: (RpcServer -> IO ()) -> IO ()
withFundedServer action =
  withTmpDir $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      atomically $ addUTXO cache fundingOutPoint UTXOEntry
        { ueOutput = TxOut coinValue p2wshOpTrue, ueHeight = 1
        , ueCoinbase = False, ueSpent = False }
      mp    <- newMempool regtest cache defaultMempoolConfig 200 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg noopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
            server = RpcServer
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
        action server
  where
    noopHandler :: a -> Message -> IO ()
    noopHandler _ _ = return ()

withTmpDir :: (FilePath -> IO ()) -> IO ()
withTmpDir act = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-w205-") removeDirectoryRecursive act

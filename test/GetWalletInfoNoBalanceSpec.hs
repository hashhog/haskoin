{-# LANGUAGE OverloadedStrings #-}

-- | getwalletinfo must not emit the legacy balance fields (wallet-cause-B).
--
-- Core v31.1 wallet/rpc/wallet.cpp getwalletinfo has no balance,
-- unconfirmed_balance or immature_balance; they live in getbalances.
--
-- TEETH: on the unfixed tree the first case fails (all three keys present).
module GetWalletInfoNoBalanceSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.Aeson (toJSON, Value(Object, String), decodeStrict)
import qualified Data.ByteString.Lazy as BL
import Data.Aeson.Key (fromText)
import qualified Data.Aeson.KeyMap as KM
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Serialize as S
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Data.List (sort)
import Haskoin.Crypto (computeTxId, computeBlockHash, Address(..))
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..) )
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Wallet
  ( WalletManager, WalletState(..), newWalletManager, createManagedWallet
  , getNewAddress, AddressType(..), getWalletTxHistory, getChangeAddress
  , scanBlockForWallet, WalletTxHistoryEntry(..), WalletTxDetail(..)
  , removeWalletUTXO, recordSentTx )
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleGetWalletInfo )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withWalletServer :: (RpcServer -> WalletManager -> IO ()) -> IO ()
withWalletServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-sbwallet-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      wm    <- newWalletManager (dir </> "wallets") regtest
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg liveNoopHandler) stopPeerManager $ \pm -> do
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
              , rsWalletMgr = Just wm, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
        action server wm

-- | getwalletinfo returns the sentinel-wrapped streaming encoding
-- (@__RAWJSON__:@ prefix); strip it and decode.
unwrapRaw :: Value -> Maybe Value
unwrapRaw (String t) = T.stripPrefix "__RAWJSON__:" t >>= decodeStrict . TE.encodeUtf8
unwrapRaw v = Just v

spec :: Spec
spec = describe "getwalletinfo has no balance fields (Core v31.1)" $ do
  it "omits balance, unconfirmed_balance and immature_balance" $
    withWalletServer $ \server wm -> do
      Right _ <- createManagedWallet wm "w" False False
      r <- handleGetWalletInfo server (toJSON ([] :: [Int]))
      case unwrapRaw (resResult r) of
        Just (Object o) -> mapM_ (\k -> KM.member (fromText k) o `shouldBe` False)
                      ["balance", "unconfirmed_balance", "immature_balance"]
        other -> expectationFailure ("not an object: " ++ show other)
  it "control: keeps the Core fields" $
    withWalletServer $ \server wm -> do
      Right _ <- createManagedWallet wm "w" False False
      r <- handleGetWalletInfo server (toJSON ([] :: [Int]))
      case unwrapRaw (resResult r) of
        Just (Object o) -> mapM_ (\k -> KM.member (fromText k) o `shouldBe` True)
                      ["walletname", "walletversion", "format", "txcount", "keypoolsize"
                      , "private_keys_enabled", "avoid_reuse", "scanning", "descriptors"
                      , "external_signer", "blank", "flags", "lastprocessedblock"]
        other -> expectationFailure ("not an object: " ++ show other)

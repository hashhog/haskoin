{-# LANGUAGE OverloadedStrings #-}

-- | secfix-haskoin-encryptwallet-persist (audit finding H10).
--
-- encryptwallet only wrote the encrypted master key to a TVar
-- ('wsEncrypted'); the wallet snapshot had no field for it.  So after a
-- restart (or unloadwallet + loadwallet) an encrypted wallet came back
-- UNENCRYPTED: no passphrase was asked for, dumpprivkey answered, and a
-- second encryptwallet with any passphrase was accepted.  The RPC also
-- answered "a new HD seed was generated", which haskoin never did.
--
-- Core: wallet/wallet.cpp CWallet::EncryptWallet writes the master key
-- record (crypted key + salt + derivation method + iterations) and the
-- encrypted keys in one WalletBatch transaction, so the encryption is on
-- disk before the RPC returns; wallet/rpc/encrypt.cpp answers -15
-- (RPC_WALLET_WRONG_ENC_STATE) to encryptwallet on an encrypted wallet.
--
-- Every test drives the wallet through the real WalletManager load path
-- (newWalletManager + loadManagedWallet on the same wallet directory),
-- which is what a node restart does.  The RPC tests go through the real
-- dispatcher (handleBatchRequest) by method name.
module WalletPersistSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import Data.IORef (newIORef)
import qualified Data.ByteString as BS
import Data.Either (isLeft, isRight)
import Data.Maybe (isJust)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Crypto (Address)
import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Wallet
  ( WalletManager(..), WalletState(..), newWalletManager
  , createManagedWallet, loadManagedWallet
  , encryptWallet, unlockWallet, isWalletLocked, persistWallet
  , getNewAddress, AddressType(..), addressToTextW )
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..), handleBatchRequest )

--------------------------------------------------------------------------------
-- Wallet-level harness
--------------------------------------------------------------------------------

withWalletDir :: (FilePath -> IO a) -> IO a
withWalletDir k = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-encpersist-")
          removeDirectoryRecursive
          (\dir -> k (dir </> "wallets"))

-- | What a node restart does: a fresh manager on the same wallet
-- directory, loading the wallet back from its wallet.dat.
reload :: FilePath -> IO WalletState
reload wdir = do
  wm <- newWalletManager wdir regtest
  r <- loadManagedWallet wm "w"
  either (\e -> fail ("loadManagedWallet: " ++ T.unpack e)) return r

passphrase :: T.Text
passphrase = "correct horse"

--------------------------------------------------------------------------------
-- RPC harness (same wiring as RpcWalletSpec)
--------------------------------------------------------------------------------

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withWalletServer :: (RpcServer -> WalletManager -> IO ()) -> IO ()
withWalletServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-encpersist-rpc-")
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
              , rsPayjoinOffers = payjoinOffers
              , rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
        action server wm

-- | The same server after a restart: a fresh WalletManager on the same
-- wallet directory with the wallet loaded back from disk.
restartWallets :: RpcServer -> WalletManager -> IO RpcServer
restartWallets server wm = do
  wm2 <- newWalletManager (wmWalletDir wm) regtest
  r <- loadManagedWallet wm2 "w"
  either (\e -> fail ("loadManagedWallet: " ++ T.unpack e)) (const (return ())) r
  return server { rsWalletMgr = Just wm2 }

call :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
call server method ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method), ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

errCode :: A.Value -> Maybe Int
errCode (A.Object o) = case KM.lookup "code" o of
  Just (A.Number n) -> Just (round n)
  _ -> Nothing
errCode _ = Nothing

str :: T.Text -> A.Value
str = A.String

addrText :: Address -> T.Text
addrText = addressToTextW regtest

-- | A wallet "w" with one P2WPKH address and its WIF, read while the
-- wallet is still unencrypted.
freshWallet :: RpcServer -> WalletManager -> IO (Address, T.Text)
freshWallet server wm = do
  Right ws <- createManagedWallet wm "w" False False
  addr <- getNewAddress AddrP2WPKH (wsWallet ws)
  (wif, e) <- call server "dumpprivkey" [str (addrText addr)]
  e `shouldBe` A.Null
  case wif of
    A.String t -> return (addr, t)
    other -> fail ("dumpprivkey returned " ++ show other)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "encryptwallet persists across a wallet reload (Core EncryptWallet writes the master key record)" $ do

  it "encryption_survives_reload" $ withWalletDir $ \wdir -> do
    wm <- newWalletManager wdir regtest
    Right ws <- createManagedWallet wm "w" False False
    r <- encryptWallet passphrase ws
    isRight r `shouldBe` True
    _ <- persistWallet (wsWallet ws)          -- save
    ws2 <- reload wdir                         -- restart
    enc <- readTVarIO (wsEncrypted ws2)
    isJust enc `shouldBe` True
    isWalletLocked ws2 `shouldReturn` True
    -- The key is not readable without the passphrase ...
    bad <- unlockWallet "wrong passphrase" 60 ws2
    isLeft bad `shouldBe` True
    isWalletLocked ws2 `shouldReturn` True
    -- ... and is with it.
    good <- unlockWallet passphrase 60 ws2
    isRight good `shouldBe` True
    isWalletLocked ws2 `shouldReturn` False

  it "encryptwallet_is_on_disk_before_it_returns (no flush needed)" $
    withWalletDir $ \wdir -> do
      wm <- newWalletManager wdir regtest
      Right ws <- createManagedWallet wm "w" False False
      r <- encryptWallet passphrase ws
      isRight r `shouldBe` True
      ws2 <- reload wdir
      enc <- readTVarIO (wsEncrypted ws2)
      isJust enc `shouldBe` True
      isWalletLocked ws2 `shouldReturn` True

  it "CONTROL: an unencrypted wallet reloads unencrypted, file layout still version 1" $
    withWalletDir $ \wdir -> do
      wm <- newWalletManager wdir regtest
      Right _ <- createManagedWallet wm "w" False False
      blob <- BS.readFile (wdir </> "w" </> "wallet.dat")
      -- "HSKWLT01" magic then the little-endian format version.
      BS.take 12 blob `shouldBe` ("HSKWLT01" <> BS.pack [1, 0, 0, 0])
      ws2 <- reload wdir
      enc <- readTVarIO (wsEncrypted ws2)
      isJust enc `shouldBe` False
      bad <- unlockWallet passphrase 60 ws2
      isLeft bad `shouldBe` True                  -- "Wallet is not encrypted"

  it "dumpprivkey_refused_after_restart until walletpassphrase" $
    withWalletServer $ \server wm -> do
      (addr, wif) <- freshWallet server wm
      let a = str (addrText addr)
      (_, e1) <- call server "encryptwallet" [str passphrase]
      e1 `shouldBe` A.Null
      server2 <- restartWallets server wm
      (r2, e2) <- call server2 "dumpprivkey" [a]
      (errCode e2, r2) `shouldBe` (Just (-13), A.Null)
      (_, e3) <- call server2 "walletpassphrase" [str "wrong passphrase", A.Number 600]
      errCode e3 `shouldBe` Just (-14)
      (_, e4) <- call server2 "walletpassphrase" [str passphrase, A.Number 600]
      e4 `shouldBe` A.Null
      (r5, e5) <- call server2 "dumpprivkey" [a]
      (r5, e5) `shouldBe` (str wif, A.Null)

  it "encryptwallet_after_restart_is_refused (-15, already encrypted)" $
    withWalletServer $ \server wm -> do
      _ <- freshWallet server wm
      (_, e1) <- call server "encryptwallet" [str passphrase]
      e1 `shouldBe` A.Null
      server2 <- restartWallets server wm
      (r2, e2) <- call server2 "encryptwallet" [str "attacker passphrase"]
      (errCode e2, r2) `shouldBe` (Just (-15), A.Null)

  it "encryptwallet_message_does_not_claim_a_new_hd_seed" $
    withWalletServer $ \server wm -> do
      _ <- freshWallet server wm
      (r, e) <- call server "encryptwallet" [str passphrase]
      e `shouldBe` A.Null
      r `shouldBe` str "wallet encrypted; You need to make a new backup with the backupwallet RPC."

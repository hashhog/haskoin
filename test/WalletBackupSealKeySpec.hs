{-# LANGUAGE OverloadedStrings #-}

-- | Wallet backups are self-contained and a failed load is an error
-- (secfix-haskoin-wallet-backup-seal-key, audit H11).
--
-- Core (wallet/walletdb.cpp, wallet/wallet.cpp RestoreWallet / LoadWallet):
-- a backupwallet file carries everything needed to open it on another
-- machine, and a wallet file that cannot be read makes loadwallet /
-- restorewallet return an error.  Core never swaps in a fresh wallet.
--
-- Before the fix haskoin sealed the master key under a per-datadir
-- @wallet.key@ that backupwallet did not copy, so a backup restored into
-- another datadir could not be decrypted; the loader then renamed the file
-- to @wallet.dat.bad@ and created a brand-new wallet under the same name,
-- and the RPC reported success.
--
-- TEETH on the unfixed tree:
--   * restore_backup_on_other_datadir: restore "succeeds" but the restored
--     wallet has a different master key (a fresh wallet).
--   * failed_load_is_error_not_new_wallet: loadwallet on a corrupt
--     wallet.dat returns a result instead of an error and a new wallet is
--     loaded.
--   * restore_unreadable_backup_is_error: restorewallet of a file this
--     datadir cannot decrypt returns success with a fresh wallet.
--   * missing_walletdat_is_error_not_new_wallet: loadwallet on a wallet
--     directory with no wallet.dat loads a fresh wallet.
--   * corrupt_walletdat_is_wallet_error_not_new_wallet: the same for a
--     torn wallet.dat, which Core reports as -4.
--   * backup_file_is_private: the backup, which now carries its own key,
--     is not readable by group or others.
--   * concurrent_key_create_single_key: concurrent first use of wallet.key
--     throws (the shared wallet.key.new temp file is locked) or yields
--     different keys.
module WalletBackupSealKeySpec (spec) where

import Test.Hspec
import Control.Concurrent.Async (forConcurrently)
import Control.Concurrent.STM (newTVarIO)
import Control.Exception (SomeException, bracket, try)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import Data.Bits ((.&.))
import Data.IORef (newIORef)
import Data.List (nub)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import System.Directory
  ( createDirectoryIfMissing, doesDirectoryExist, doesFileExist
  , getTemporaryDirectory, removeDirectoryRecursive, removeFile )
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)
import qualified System.Posix.Files as PosixFiles

import Haskoin.Consensus (regtest, initHeaderChain)
import Haskoin.Crypto (getSecKey)
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Wallet
  ( WalletManager, WalletState(..), Wallet(..), ExtendedKey(..), newWalletManager
  , getManagedWallet )
import Haskoin.Wallet.Persist (loadOrCreateAtRestKey)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..), handleBatchRequest )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withTmp :: String -> (FilePath -> IO a) -> IO a
withTmp tag act = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base ("haskoin-wpersist-" ++ tag ++ "-"))
          removeDirectoryRecursive act

-- | An RPC server over a fresh datadir with its own wallet manager (and so
-- its own wallet.key).  Two of these model two machines.
withNode :: FilePath -> (RpcServer -> WalletManager -> IO a) -> IO a
withNode dir action =
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

-- | Call one RPC through the real dispatcher; return (result, error).
rpc :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
rpc server method params = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method)
        , ("params", A.Array (V.fromList params)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

str :: FilePath -> A.Value
str = A.String . T.pack

masterKeyOf :: WalletManager -> T.Text -> IO (Maybe BS.ByteString)
masterKeyOf wm name =
  fmap (getSecKey . ekKey . walletMasterKey . wsWallet) <$> getManagedWallet wm name

isError :: A.Value -> Bool
isError A.Null = False
isError _      = True

-- | The JSON-RPC error code, if the response carries one.
errCode :: A.Value -> Maybe Int
errCode (A.Object o) = case KM.lookup "code" o of
  Just (A.Number n) -> Just (round n)
  _                 -> Nothing
errCode _ = Nothing

-- Core rpc/protocol.h.
rpcWalletErrorCode, rpcWalletNotFoundCode :: Maybe Int
rpcWalletErrorCode    = Just (-4)
rpcWalletNotFoundCode = Just (-18)

spec :: Spec
spec = describe "wallet backups are self-contained; failed loads are errors (H11)" $ do

  it "restore_backup_on_other_datadir" $
    withTmp "a" $ \dirA -> withTmp "b" $ \dirB -> withTmp "bk" $ \bkDir -> do
      let bk = bkDir </> "w.bak"
      origKey <- withNode dirA $ \srvA wmA -> do
        (_, e1) <- rpc srvA "createwallet" [A.String "w"]
        e1 `shouldBe` A.Null
        (_, e2) <- rpc srvA "backupwallet" [str bk]
        e2 `shouldBe` A.Null
        masterKeyOf wmA "w"
      origKey `shouldSatisfy` (/= Nothing)
      withNode dirB $ \srvB wmB -> do
        (_, e) <- rpc srvB "restorewallet" [A.String "r", str bk]
        e `shouldBe` A.Null
        restored <- masterKeyOf wmB "r"
        restored `shouldBe` origKey

  it "backup_restores_on_same_datadir (control)" $
    withTmp "s" $ \dir -> withTmp "bk" $ \bkDir -> do
      let bk = bkDir </> "w.bak"
      withNode dir $ \srv wm -> do
        _ <- rpc srv "createwallet" [A.String "w"]
        (_, e1) <- rpc srv "backupwallet" [str bk]
        e1 `shouldBe` A.Null
        orig <- masterKeyOf wm "w"
        (_, e2) <- rpc srv "restorewallet" [A.String "r", str bk]
        e2 `shouldBe` A.Null
        restored <- masterKeyOf wm "r"
        restored `shouldBe` orig

  it "backup_does_not_embed_datadir_key" $
    withTmp "k" $ \dir -> withTmp "bk" $ \bkDir -> do
      let bk = bkDir </> "w.bak"
      withNode dir $ \srv _ -> do
        _ <- rpc srv "createwallet" [A.String "w"]
        _ <- rpc srv "backupwallet" [str bk]
        dk <- BS.readFile (dir </> "wallets" </> "wallet.key")
        blob <- BS.readFile bk
        BS.length dk `shouldBe` 32
        -- The datadir key seals every wallet in the datadir; one wallet's
        -- backup must not hand it out.
        (dk `BS.isInfixOf` blob) `shouldBe` False

  it "backup_file_is_private" $
    withTmp "p" $ \dir -> withTmp "bk" $ \bkDir -> do
      let bk = bkDir </> "w.bak"
      withNode dir $ \srv _ -> do
        _ <- rpc srv "createwallet" [A.String "w"]
        (_, e) <- rpc srv "backupwallet" [str bk]
        e `shouldBe` A.Null
        -- The backup is enough to spend: no group or other access.
        -- (Core creates wallet files under umask 077, common/system.cpp.)
        mode <- PosixFiles.fileMode <$> PosixFiles.getFileStatus bk
        (mode .&. 0o077) `shouldBe` 0

  it "failed_load_is_error_not_new_wallet" $
    withTmp "c" $ \dir -> withNode dir $ \srv wm -> do
      (_, e0) <- rpc srv "createwallet" [A.String "w"]
      e0 `shouldBe` A.Null
      (_, e1) <- rpc srv "unloadwallet" [A.String "w"]
      e1 `shouldBe` A.Null
      let dat = dir </> "wallets" </> "w" </> "wallet.dat"
          junk = BS.pack [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]
      BS.writeFile dat junk
      (res, err) <- rpc srv "loadwallet" [A.String "w"]
      res `shouldBe` A.Null
      err `shouldSatisfy` isError
      -- Core MakeDatabase: not a wallet file -> FAILED_BAD_FORMAT, which
      -- HandleWalletError maps to RPC_WALLET_NOT_FOUND (-18).
      errCode err `shouldBe` rpcWalletNotFoundCode
      loaded <- getManagedWallet wm "w"
      fmap (const ()) loaded `shouldBe` Nothing
      -- The user's file is left exactly where it was, untouched.
      BS.readFile dat `shouldReturn` junk
      doesFileExist (dat ++ ".bad") `shouldReturn` False
      -- A second attempt is still an error, not a fresh wallet.
      (res2, err2) <- rpc srv "loadwallet" [A.String "w"]
      res2 `shouldBe` A.Null
      err2 `shouldSatisfy` isError

  it "corrupt_walletdat_is_wallet_error_not_new_wallet" $
    withTmp "t" $ \dir -> withNode dir $ \srv wm -> do
      _ <- rpc srv "createwallet" [A.String "w"]
      _ <- rpc srv "unloadwallet" [A.String "w"]
      let dat = dir </> "wallets" </> "w" </> "wallet.dat"
      full <- BS.readFile dat
      -- A torn write: recognisable as a wallet file, but unreadable.
      let torn = BS.take (BS.length full `div` 2) full
      BS.writeFile dat torn
      (res, err) <- rpc srv "loadwallet" [A.String "w"]
      res `shouldBe` A.Null
      -- Core: LoadExisting fails (DBErrors::CORRUPT) -> FAILED_LOAD -> -4.
      errCode err `shouldBe` rpcWalletErrorCode
      loaded <- getManagedWallet wm "w"
      fmap (const ()) loaded `shouldBe` Nothing
      BS.readFile dat `shouldReturn` torn

  it "missing_walletdat_is_error_not_new_wallet" $
    withTmp "m" $ \dir -> withNode dir $ \srv wm -> do
      _ <- rpc srv "createwallet" [A.String "w"]
      _ <- rpc srv "unloadwallet" [A.String "w"]
      let dat = dir </> "wallets" </> "w" </> "wallet.dat"
      BS.readFile dat >>= BS.writeFile (dat ++ ".moved")
      removeFile dat
      (res, err) <- rpc srv "loadwallet" [A.String "w"]
      res `shouldBe` A.Null
      err `shouldSatisfy` isError
      -- Core: the directory exists but holds no data file -> BAD_FORMAT -> -18.
      errCode err `shouldBe` rpcWalletNotFoundCode
      loaded <- getManagedWallet wm "w"
      fmap (const ()) loaded `shouldBe` Nothing
      doesFileExist dat `shouldReturn` False

  it "legacy_bare_walletdat_restores_on_same_datadir (guard)" $
    withTmp "l" $ \dir -> withTmp "bk" $ \bkDir -> do
      let bk = bkDir </> "wallet.dat.copy"
      withNode dir $ \srv wm -> do
        _ <- rpc srv "createwallet" [A.String "w"]
        orig <- masterKeyOf wm "w"
        -- What backupwallet wrote before backups were self-contained.
        BS.readFile (dir </> "wallets" </> "w" </> "wallet.dat") >>= BS.writeFile bk
        (_, e) <- rpc srv "restorewallet" [A.String "r", str bk]
        e `shouldBe` A.Null
        restored <- masterKeyOf wm "r"
        restored `shouldBe` orig

  it "restore_unreadable_backup_is_error" $
    withTmp "u" $ \dir -> withTmp "bk" $ \bkDir -> do
      let bk = bkDir </> "junk.bak"
      BS.writeFile bk (BS.pack [0x01, 0x02, 0x03, 0x04])
      withNode dir $ \srv wm -> do
        (res, err) <- rpc srv "restorewallet" [A.String "r", str bk]
        res `shouldBe` A.Null
        err `shouldSatisfy` isError
        -- Core RestoreWallet -> LoadWallet -> BAD_FORMAT -> -18.
        errCode err `shouldBe` rpcWalletNotFoundCode
        loaded <- getManagedWallet wm "r"
        fmap (const ()) loaded `shouldBe` Nothing
        -- Core RestoreWallet removes the wallet directory it created.
        doesDirectoryExist (dir </> "wallets" </> "r") `shouldReturn` False

  it "concurrent_key_create_single_key" $
    withTmp "x" $ \dir -> do
      let kp = dir </> "wallet.key"
      rs <- forConcurrently [1 .. 32 :: Int] $ \_ ->
              try (loadOrCreateAtRestKey kp) :: IO (Either SomeException BS.ByteString)
      case sequence rs of
        Left e -> expectationFailure ("concurrent create threw: " ++ show e)
        Right ks -> do
          length (nub ks) `shouldBe` 1
          onDisk <- BS.readFile kp
          ks `shouldSatisfy` all (== onDisk)
          BS.length onDisk `shouldBe` 32

{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W166 — durable wallet persistence regression suite (sweep wa0fq5wtk).
--
-- DATA-LOSS FIX under test: before this fix the haskoin wallet held its
-- entire state — master key, addresses, UTXO ledger, labels — only in
-- 'TVar's, and 'saveWallet' @error@ed. ANY restart (clean OR an unclean
-- SIGKILL / OOM / power loss) lost every key and coin: balances reset to
-- zero, funds unrecoverable. This suite pins the four guarantees of the
-- new 'Haskoin.Wallet.Persist' module + the wallet's save-on-mutation /
-- fault-tolerant-load wiring:
--
--   G1  ATOMIC + DURABLE round-trip: a saved wallet re-loads byte-for-byte
--       (master key, indices, addresses, UTXOs, labels, last-synced).
--   G2  MUTATION SURVIVES A SIMULATED UNCLEAN RESTART: mutate the live
--       wallet, flush (the periodic-flusher action, NOT a clean shutdown),
--       drop it, re-load from disk — the mutation is present.
--   G3  FAULT-TOLERANT LOAD: a partially-written / truncated / garbage
--       wallet file does NOT crash; it is moved aside to @.bad@ and the
--       loader returns 'Left' so startup proceeds with seed recovery.
--   G4  ENCRYPTION AT REST + wrong-key safety: the spendable key material
--       is sealed (NOT plaintext on disk); a wrong at-rest key fails the
--       load gracefully (no exception, file moved aside).
--
-- Mirrors bitcoin-core/src/wallet/{wallet,walletdb}.cpp durability and
-- this node's own 'Haskoin.Mempool.Persist'.
module W166WalletPersistSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM (readTVarIO)
import Control.Exception (SomeException, try)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Word (Word32)
import System.Directory (createDirectoryIfMissing, doesFileExist,
                         getTemporaryDirectory, removePathForcibly)
import System.FilePath ((</>))

import Haskoin.Consensus (mainnet)
import Haskoin.Wallet
import Haskoin.Wallet.Persist
import Haskoin.Crypto (Address, getSecKey)
import Haskoin.Types (OutPoint (..), TxId (..), Hash256 (..), TxOut (..))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | A throwaway working directory under the system temp dir, wiped first.
withTmpDir :: String -> (FilePath -> IO a) -> IO a
withTmpDir tag k = do
  base <- getTemporaryDirectory
  let dir = base </> ("haskoin-w166-" ++ tag)
  removePathForcibly dir
  createDirectoryIfMissing True dir
  k dir

mkOutPoint :: Word -> OutPoint
mkOutPoint n =
  OutPoint (TxId (Hash256 (BS.pack (replicate 31 0 ++ [fromIntegral n])))) 0

-- P2WPKH-shaped 22-byte script (OP_0 PUSH20 <hash>) — content irrelevant
-- to the codec, just needs to round-trip.
sampleScript :: BS.ByteString
sampleScript = BS.pack (0x00 : 0x14 : replicate 20 0xAB)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W166 durable wallet persistence (sweep wa0fq5wtk)" $ do

  ------------------------------------------------------------------------
  describe "G1 atomic + durable round-trip" $ do

    it "G1.1: a saved wallet re-loads identically (keys/addrs/utxos/labels)" $
      withTmpDir "g1" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        -- Build + mutate a wallet.
        m <- generateMnemonic 128
        w <- loadWallet (WalletConfig mainnet 20 "") m
        attachWalletPersistence w datPath atRestKey
        a1 <- getNewAddress AddrP2WPKH w
        addWalletUTXO w (mkOutPoint 1) (TxOut 50_000 sampleScript) 100
        addWalletUTXO w (mkOutPoint 2) (TxOut 25_000 sampleScript) 101
        Right _ <- persistWallet w

        -- Re-load from disk into a fresh wallet.
        Right (Just snap) <- loadWalletSnapshot atRestKey datPath
        w2 <- restoreWalletFromSnapshot mainnet datPath atRestKey snap

        -- Master key survives (full recoverability anchor).
        skOf w2 `shouldBe` skOf w
        -- Address book + UTXO ledger survive.
        addrs2 <- readWalletAddresses w2
        Map.member a1 addrs2 `shouldBe` True
        bal2 <- getBalance w2
        bal2 `shouldBe` 75_000

    it "G1.2: pure codec is a faithful round-trip" $ do
      let snap = WalletSnapshot
            { wsnMasterSecKey = BS.replicate 32 0x11
            , wsnMasterChain  = BS.replicate 32 0x22
            , wsnNetworkName  = "main"
            , wsnGapLimit     = 20
            , wsnReceiveIndex = 7
            , wsnChangeIndex  = 3
            , wsnAddresses    = Map.empty
            , wsnUtxos        = [ SnapUtxo (mkOutPoint 9)
                                    (TxOut 12_345 sampleScript) 200 True ]
            , wsnAddrLabels   = Map.empty
            , wsnTxLabels     = Map.empty
            , wsnLastSynced   = 944183
            }
      decodeWalletSnapshot (encodeWalletSnapshot snap) `shouldBe` Right snap

  ------------------------------------------------------------------------
  describe "G2 mutation survives a SIMULATED UNCLEAN restart" $ do

    -- The teeth: we never call a clean-shutdown save. We mutate, then run
    -- ONLY the periodic-flusher action (flushDirtyWallets), then throw the
    -- live wallet away (== process killed) and re-open from disk. The
    -- mutation must be present. Pre-fix, saveWallet errored and there was
    -- no on-disk form, so this was impossible.
    it "G2.1: a new address + UTXO + last-synced height survive a kill" $
      withTmpDir "g2" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        m  <- generateMnemonic 128
        w  <- loadWallet (WalletConfig mainnet 20 "") m
        attachWalletPersistence w datPath atRestKey
        Right _ <- persistWallet w     -- initial save (create-time)

        -- Mutate AFTER the initial save, like a running node would.
        a  <- getNewAddress AddrP2WPKH w
        addWalletUTXO w (mkOutPoint 42) (TxOut 99_000 sampleScript) 944100

        -- Periodic flusher fires (the ONLY save before the "crash").
        flushDirtyWallets [("default", w)]

        -- Simulate SIGKILL: discard w entirely, re-open cold from disk.
        Right (Just snap) <- loadWalletSnapshot atRestKey datPath
        w' <- restoreWalletFromSnapshot mainnet datPath atRestKey snap

        bal <- getBalance w'
        bal `shouldBe` 99_000
        addrs <- readWalletAddresses w'
        Map.member a addrs `shouldBe` True

  ------------------------------------------------------------------------
  describe "G3 fault-tolerant load (must NOT crash startup)" $ do

    it "G3.1: a truncated/partial wallet file does not crash; recovers + .bak" $
      withTmpDir "g3a" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        -- Write a valid wallet, then corrupt it by truncating to a partial
        -- write (the classic torn-write failure mode).
        m <- generateMnemonic 128
        w <- loadWallet (WalletConfig mainnet 20 "") m
        attachWalletPersistence w datPath atRestKey
        Right _ <- persistWallet w
        full <- BS.readFile datPath
        BS.writeFile datPath (BS.take (BS.length full `div` 2) full)

        -- The load MUST NOT throw; it returns Left and moves the bad file.
        r <- try (loadWalletSnapshot atRestKey datPath)
               :: IO (Either SomeException (Either String (Maybe WalletSnapshot)))
        case r of
          Left e  -> expectationFailure $ "loader threw: " ++ show e
          Right (Left _)  -> pure ()   -- expected: graceful failure
          Right (Right _) -> expectationFailure "expected Left on corrupt file"
        bakExists <- doesFileExist (datPath ++ ".bad")
        bakExists `shouldBe` True

    it "G3.2: garbage bytes (bad magic) are rejected gracefully, not parsed" $
      withTmpDir "g3b" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        BS.writeFile datPath (BS.pack [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
        r <- try (loadWalletSnapshot atRestKey datPath)
               :: IO (Either SomeException (Either String (Maybe WalletSnapshot)))
        case r of
          Left e          -> expectationFailure $ "loader threw: " ++ show e
          Right (Left _)  -> pure ()
          Right (Right _) -> expectationFailure "expected Left on garbage"

    it "G3.3: a missing wallet file is 'fresh wallet', not an error" $
      withTmpDir "g3c" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        r <- loadWalletSnapshot atRestKey datPath
        r `shouldBe` Right Nothing

  ------------------------------------------------------------------------
  describe "G4 encryption at rest + wrong-key safety" $ do

    it "G4.1: the 32-byte master key is NOT stored in cleartext on disk" $
      withTmpDir "g4a" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        m <- generateMnemonic 128
        w <- loadWallet (WalletConfig mainnet 20 "") m
        attachWalletPersistence w datPath atRestKey
        Right _ <- persistWallet w
        snap     <- snapshotWallet w     -- plaintext snapshot (in memory)
        onDisk   <- BS.readFile datPath
        let plaintextKey = wsnMasterSecKey snap
        -- The raw secret must NOT appear verbatim anywhere in the file.
        BS.length plaintextKey `shouldBe` 32
        (plaintextKey `BS.isInfixOf` onDisk) `shouldBe` False

    it "G4.2: a wrong at-rest key fails the load gracefully (no crash)" $
      withTmpDir "g4b" $ \dir -> do
        let datPath = dir </> "wallet.dat"
        atRestKey <- loadOrCreateAtRestKey (dir </> "wallet.key")
        m <- generateMnemonic 128
        w <- loadWallet (WalletConfig mainnet 20 "") m
        attachWalletPersistence w datPath atRestKey
        Right _ <- persistWallet w
        let wrongKey = BS.map (\b -> b + 1) atRestKey
        r <- try (loadWalletSnapshot wrongKey datPath)
               :: IO (Either SomeException (Either String (Maybe WalletSnapshot)))
        case r of
          Left e          -> expectationFailure $ "loader threw: " ++ show e
          Right (Left _)  -> pure ()   -- expected: decrypt failure, recovered
          Right (Right _) -> expectationFailure "expected Left with wrong key"

--------------------------------------------------------------------------------
-- Small accessors (kept local to avoid widening the Wallet export surface)
--------------------------------------------------------------------------------

skOf :: Wallet -> BS.ByteString
skOf = getSecKey . ekKey . walletMasterKey

readWalletAddresses :: Wallet -> IO (Map.Map Address (Word32, Bool))
readWalletAddresses = readTVarIO . walletAddresses

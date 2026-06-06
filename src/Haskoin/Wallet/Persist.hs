{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Durable, crash-safe wallet persistence for haskoin.
--
-- DATA-LOSS FIX (sweep wa0fq5wtk): prior to this module the wallet held
-- its entire state — master key, address book, UTXO ledger, labels,
-- tx history — only in 'TVar's. A restart (clean OR a SIGKILL / OOM /
-- power loss) lost every key and coin: balances reset to zero and funds
-- became unrecoverable. 'saveWallet' was a stub that @error@ed.
--
-- This module gives the wallet a real on-disk representation that
-- survives an unclean restart, mirroring the durability guarantees of
-- @bitcoin-core/src/wallet/walletdb.cpp@ (BerkeleyRO/SQLite atomic
-- commits) and this node's own @Haskoin.Mempool.Persist@ /
-- @Haskoin.Storage.dumpTxOutSetFromDB@ (temp + fsync + atomic rename).
--
-- == Design ==
--
-- 1. ATOMIC + DURABLE WRITES ('atomicWriteFileSync'): every save writes
--    to @wallet.dat.new@, @hFlush@es, @fileSynchronise@s the fd, then
--    @renameFile@s onto @wallet.dat@ and finally fsyncs the containing
--    directory so the rename itself is durable. A crash mid-write can
--    only ever leave the stale-but-valid @wallet.dat@ or an orphan
--    @.new@, never a torn primary file.
--
-- 2. SAVE-ON-MUTATION: the wallet carries a dirty flag + persist path
--    ('Haskoin.Wallet.markWalletDirty'); mutating ops set it and a short
--    periodic flusher ('flushDirtyWallets') writes every dirty wallet.
--    State is therefore NOT lost on SIGKILL the way a flush-only-on-clean-
--    shutdown scheme would.
--
-- 3. FAULT-TOLERANT LOAD ('loadWalletFile'): a missing file is "fresh
--    wallet, no error"; a corrupt / truncated / partially-written file is
--    moved aside to @wallet.dat.bad@, logged, and reported as @Left@ so
--    the caller can fall back to seed re-derivation instead of crashing
--    node startup.
--
-- 4. ENCRYPTION AT REST: the secret-bearing region (master private key +
--    chain code) is sealed with AES-256-CBC under a key derived from a
--    per-datadir random key file (@wallet.key@, 0600). The clear-text
--    address/UTXO/history metadata needed for fast balance display is
--    stored in the clear; only key material that could spend funds is
--    encrypted, matching Core's "encrypt the keys, index the rest" split.
module Haskoin.Wallet.Persist
  ( -- * Snapshot type
    WalletSnapshot(..)
  , SnapUtxo(..)
    -- * Codec (pure, exported for tests)
  , encodeWalletSnapshot
  , decodeWalletSnapshot
  , walletSnapshotVersion
    -- * IO: atomic durable save / fault-tolerant load
  , saveWalletSnapshot
  , loadWalletSnapshot
  , atomicWriteFileSync
    -- * Encryption-at-rest key file
  , loadOrCreateAtRestKey
  ) where

import Control.Exception (IOException, SomeException, bracketOnError, catch, try)
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Serialize (Get, Put, Serialize (..), getBytes,
                       getWord32le, getWord8, putByteString,
                       putWord32le, putWord8, runGet, runPut)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word32)
import System.Directory (doesFileExist, renameFile)
import System.FilePath (takeDirectory)
import System.IO (IOMode (WriteMode), hClose, hFlush, hPutStrLn,
                  openBinaryFile, stderr)
import qualified System.Posix.Files as PosixFiles
import qualified System.Posix.IO as PosixIO
import qualified System.Posix.Unistd as PosixUnistd

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher (..), Cipher (..), IV, cbcDecrypt,
                            cbcEncrypt, makeIV)
import Crypto.Error (CryptoFailable (..))
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.Hash (SHA512 (..))
import qualified Crypto.Random as CryptoRandom

import Haskoin.Crypto (Address (..))
import Haskoin.Types (Hash160 (..), Hash256 (..), OutPoint (..), TxId (..),
                      TxOut (..), getHash160, getHash256)

--------------------------------------------------------------------------------
-- Format constants
--------------------------------------------------------------------------------

-- | Magic prefix so a stray non-wallet file is rejected early rather
-- than mis-parsed into garbage state.
walletSnapshotMagic :: ByteString
walletSnapshotMagic = "HSKWLT01"

-- | On-disk format version. Bump on any layout change; 'decodeWalletSnapshot'
-- refuses unknown versions (fault-tolerant load treats that as corrupt).
walletSnapshotVersion :: Word32
walletSnapshotVersion = 1

--------------------------------------------------------------------------------
-- Snapshot data
--------------------------------------------------------------------------------

-- | One persisted UTXO with the maturity metadata the live wallet keeps
-- (mirrors @Haskoin.Wallet.WalletUtxoEntry@ without importing it, to keep
-- this module dependency-light and avoid an import cycle).
data SnapUtxo = SnapUtxo
  { suOutPoint    :: !OutPoint
  , suTxOut       :: !TxOut
  , suBlockHeight :: !Word32
  , suIsCoinbase  :: !Bool
  } deriving (Show, Eq)

-- | A complete, restartable wallet snapshot. Everything needed to bring
-- a wallet back byte-for-byte after an unclean shutdown.
data WalletSnapshot = WalletSnapshot
  { wsnMasterSecKey   :: !ByteString          -- ^ 32-byte master private key (encrypted at rest on disk)
  , wsnMasterChain    :: !ByteString          -- ^ 32-byte master chain code (encrypted at rest on disk)
  , wsnNetworkName    :: !Text                 -- ^ "main" / "test" / "regtest" — guards a cross-net reload
  , wsnGapLimit       :: !Word32
  , wsnReceiveIndex   :: !Word32
  , wsnChangeIndex    :: !Word32
  , wsnAddresses      :: !(Map Address (Word32, Bool))  -- ^ address -> (index, isChange)
  , wsnUtxos          :: ![SnapUtxo]
  , wsnAddrLabels     :: !(Map Address Text)
  , wsnTxLabels       :: !(Map TxId Text)
  , wsnLastSynced     :: !Word32               -- ^ chain height the UTXO ledger is reconciled to (rescan anchor)
  } deriving (Show, Eq)

--------------------------------------------------------------------------------
-- Pure codec
--------------------------------------------------------------------------------

-- | Serialise a snapshot. The secret region (master key + chain code) is
-- supplied already-sealed by the caller via 'wsnMasterSecKey' /
-- 'wsnMasterChain' so this stays a pure function; 'saveWalletSnapshot'
-- does the AES sealing.
encodeWalletSnapshot :: WalletSnapshot -> ByteString
encodeWalletSnapshot WalletSnapshot{..} = runPut $ do
  putByteString walletSnapshotMagic
  putWord32le walletSnapshotVersion
  putVarBytes' wsnMasterSecKey
  putVarBytes' wsnMasterChain
  putText wsnNetworkName
  putWord32le wsnGapLimit
  putWord32le wsnReceiveIndex
  putWord32le wsnChangeIndex
  putAddrMap wsnAddresses
  putList putSnapUtxo wsnUtxos
  putAddrTextMap wsnAddrLabels
  putTxIdTextMap wsnTxLabels
  putWord32le wsnLastSynced

-- | Parse a snapshot blob. 'Left' on magic / version / structural
-- mismatch; the IO loader turns that into the move-aside recovery path.
decodeWalletSnapshot :: ByteString -> Either String WalletSnapshot
decodeWalletSnapshot = runGet $ do
  magic <- getBytes (BS.length walletSnapshotMagic)
  when (magic /= walletSnapshotMagic) $
    fail "wallet snapshot: bad magic"
  ver <- getWord32le
  when (ver /= walletSnapshotVersion) $
    fail ("wallet snapshot: unsupported version " ++ show ver)
  sk      <- getVarBytes'
  cc      <- getVarBytes'
  net     <- getText
  gap     <- getWord32le
  recvIx  <- getWord32le
  chgIx   <- getWord32le
  addrs   <- getAddrMap
  utxos   <- getList getSnapUtxo
  aLabels <- getAddrTextMap
  tLabels <- getTxIdTextMap
  synced  <- getWord32le
  pure WalletSnapshot
    { wsnMasterSecKey = sk
    , wsnMasterChain  = cc
    , wsnNetworkName  = net
    , wsnGapLimit     = gap
    , wsnReceiveIndex = recvIx
    , wsnChangeIndex  = chgIx
    , wsnAddresses    = addrs
    , wsnUtxos        = utxos
    , wsnAddrLabels   = aLabels
    , wsnTxLabels     = tLabels
    , wsnLastSynced   = synced
    }

--------------------------------------------------------------------------------
-- Codec helpers
--------------------------------------------------------------------------------

putVarBytes' :: ByteString -> Put
putVarBytes' bs = putWord32le (fromIntegral (BS.length bs)) >> putByteString bs

getVarBytes' :: Get ByteString
getVarBytes' = do
  n <- getWord32le
  when (n > 100_000_000) $ fail "wallet snapshot: implausible byte length"
  getBytes (fromIntegral n)

putText :: Text -> Put
putText = putVarBytes' . TE.encodeUtf8

getText :: Get Text
getText = TE.decodeUtf8 <$> getVarBytes'

putList :: (a -> Put) -> [a] -> Put
putList p xs = putWord32le (fromIntegral (length xs)) >> mapM_ p xs

getList :: Get a -> Get [a]
getList g = do
  n <- getWord32le
  when (n > 50_000_000) $ fail "wallet snapshot: implausible list length"
  go (fromIntegral n) []
  where
    go 0 acc = pure (reverse acc)
    go k acc = do x <- g; go (k - 1 :: Int) (x : acc)

-- Address: 1-byte tag + raw hash bytes (network-independent; the bech32
-- HRP is reapplied from the stored network on display).
putAddress :: Address -> Put
putAddress = \case
  PubKeyAddress h        -> putWord8 0 >> putVarBytes' (getHash160 h)
  ScriptAddress h        -> putWord8 1 >> putVarBytes' (getHash160 h)
  WitnessPubKeyAddress h -> putWord8 2 >> putVarBytes' (getHash160 h)
  WitnessScriptAddress h -> putWord8 3 >> putVarBytes' (getHash256 h)
  TaprootAddress h       -> putWord8 4 >> putVarBytes' (getHash256 h)

getAddress :: Get Address
getAddress = getWord8 >>= \case
  0 -> PubKeyAddress . Hash160 <$> getVarBytes'
  1 -> ScriptAddress . Hash160 <$> getVarBytes'
  2 -> WitnessPubKeyAddress . Hash160 <$> getVarBytes'
  3 -> WitnessScriptAddress . Hash256 <$> getVarBytes'
  4 -> TaprootAddress . Hash256 <$> getVarBytes'
  t -> fail ("wallet snapshot: bad address tag " ++ show t)

putAddrMap :: Map Address (Word32, Bool) -> Put
putAddrMap m = putList putEntry (Map.toList m)
  where putEntry (a, (i, ch)) =
          putAddress a >> putWord32le i >> putWord8 (if ch then 1 else 0)

getAddrMap :: Get (Map Address (Word32, Bool))
getAddrMap = Map.fromList <$> getList getEntry
  where getEntry = do
          a <- getAddress
          i <- getWord32le
          c <- getWord8
          pure (a, (i, c /= 0))

putAddrTextMap :: Map Address Text -> Put
putAddrTextMap m = putList (\(a, t) -> putAddress a >> putText t) (Map.toList m)

getAddrTextMap :: Get (Map Address Text)
getAddrTextMap = Map.fromList <$> getList ((,) <$> getAddress <*> getText)

putTxIdTextMap :: Map TxId Text -> Put
putTxIdTextMap m = putList (\(k, t) -> put k >> putText t) (Map.toList m)

getTxIdTextMap :: Get (Map TxId Text)
getTxIdTextMap = Map.fromList <$> getList ((,) <$> get <*> getText)

putSnapUtxo :: SnapUtxo -> Put
putSnapUtxo SnapUtxo{..} = do
  put suOutPoint
  put suTxOut
  putWord32le suBlockHeight
  putWord8 (if suIsCoinbase then 1 else 0)

getSnapUtxo :: Get SnapUtxo
getSnapUtxo = do
  op  <- get
  txo <- get
  h   <- getWord32le
  cb  <- getWord8
  pure (SnapUtxo op txo h (cb /= 0))

--------------------------------------------------------------------------------
-- Encryption at rest
--------------------------------------------------------------------------------

aesKeyBytes :: Int
aesKeyBytes = 32

aesBlockBytes :: Int
aesBlockBytes = 16

-- | PBKDF2-SHA512(passphrase, salt) -> 32-byte AES key.
deriveAtRestKey :: ByteString -> ByteString -> ByteString
deriveAtRestKey passphrase salt =
  PBKDF2.generate (PBKDF2.prfHMAC SHA512)
    (PBKDF2.Parameters { PBKDF2.iterCounts = 20000
                       , PBKDF2.outputLength = aesKeyBytes })
    passphrase salt

pkcs7Pad :: ByteString -> ByteString
pkcs7Pad bs =
  let n = aesBlockBytes - (BS.length bs `mod` aesBlockBytes)
  in bs <> BS.replicate n (fromIntegral n)

pkcs7Unpad :: ByteString -> Maybe ByteString
pkcs7Unpad bs
  | BS.null bs = Nothing
  | otherwise =
      let n = fromIntegral (BS.last bs)
      in if n >= 1 && n <= aesBlockBytes && n <= BS.length bs
           && BS.all (== fromIntegral n) (BS.drop (BS.length bs - n) bs)
           then Just (BS.take (BS.length bs - n) bs)
           else Nothing

-- | Seal plaintext with AES-256-CBC. Output: salt(16) ++ iv(16) ++ ct.
sealAtRest :: ByteString -> ByteString -> IO (Either String ByteString)
sealAtRest atRestPass plaintext = do
  salt <- CryptoRandom.getRandomBytes 16 :: IO ByteString
  ivbs <- CryptoRandom.getRandomBytes aesBlockBytes :: IO ByteString
  let key = deriveAtRestKey atRestPass salt
  pure $ case cipherInit key :: CryptoFailable AES256 of
    CryptoFailed e -> Left ("seal: cipherInit: " ++ show e)
    CryptoPassed cipher -> case makeIV ivbs :: Maybe (IV AES256) of
      Nothing -> Left "seal: bad IV"
      Just iv -> Right (salt <> ivbs <> cbcEncrypt cipher iv (pkcs7Pad plaintext))

-- | Reverse 'sealAtRest'.
unsealAtRest :: ByteString -> ByteString -> Either String ByteString
unsealAtRest atRestPass blob
  | BS.length blob < 32 = Left "unseal: blob too short"
  | otherwise =
      let (salt, rest) = BS.splitAt 16 blob
          (ivbs, ct)   = BS.splitAt aesBlockBytes rest
          key          = deriveAtRestKey atRestPass salt
      in case cipherInit key :: CryptoFailable AES256 of
           CryptoFailed e -> Left ("unseal: cipherInit: " ++ show e)
           CryptoPassed cipher -> case makeIV ivbs :: Maybe (IV AES256) of
             Nothing -> Left "unseal: bad IV"
             Just iv -> case pkcs7Unpad (cbcDecrypt cipher iv ct) of
               Nothing -> Left "unseal: bad padding (wrong key or corrupt)"
               Just pt -> Right pt

-- | Load (or create on first use) the per-datadir 32-byte at-rest key
-- file used to seal wallet secrets. Stored mode 0600. This lets the
-- wallet re-open after an UNCLEAN restart with no interactive passphrase,
-- while still keeping the spendable key material off disk in the clear.
loadOrCreateAtRestKey :: FilePath -> IO ByteString
loadOrCreateAtRestKey keyPath = do
  exists <- doesFileExist keyPath
  if exists
    then BS.readFile keyPath
    else do
      k <- CryptoRandom.getRandomBytes 32 :: IO ByteString
      -- Atomic + restrictive perms; created once, never overwritten.
      atomicWriteFileSync keyPath k
      (PosixFiles.setFileMode keyPath 0o600)
        `catch` (\(_ :: IOException) -> pure ())
      pure k

--------------------------------------------------------------------------------
-- IO: atomic durable write
--------------------------------------------------------------------------------

-- | Write @bytes@ to @path@ crash-safely: bytes go to @path.new@, the fd
-- is fsynced, then renamed onto @path@, then the containing directory is
-- fsynced so the rename itself is durable. A crash can only leave the
-- previous valid @path@ or an orphan @path.new@ — never a torn @path@.
--
-- Mirrors 'Haskoin.Storage.dumpTxOutSetFromDB' and Core's
-- @AtomicWrite@ / @fsync@ flow in wallet/db.
atomicWriteFileSync :: FilePath -> ByteString -> IO ()
atomicWriteFileSync path bytes = do
  let tmp = path <> ".new"
  bracketOnError
    (openBinaryFile tmp WriteMode)
    (\h -> hClose h `catch` (\(_ :: IOException) -> pure ()))
    (\h -> do
       BS.hPut h bytes
       hFlush h
       fd <- PosixIO.handleToFd h        -- consumes the handle's fd ownership
       PosixUnistd.fileSynchronise fd
       PosixIO.closeFd fd)
  renameFile tmp path
  -- Durability barrier for the rename: fsync the directory entry.
  fsyncDir (takeDirectory path)

-- | Best-effort directory fsync (so the rename survives power loss).
-- Errors are swallowed — not all filesystems permit opening a dir for
-- fsync, and the data fsync above is the load-bearing barrier.
fsyncDir :: FilePath -> IO ()
fsyncDir dir =
  (do fd <- PosixIO.openFd dir PosixIO.ReadOnly PosixIO.defaultFileFlags
      PosixUnistd.fileSynchronise fd `catch` (\(_ :: IOException) -> pure ())
      PosixIO.closeFd fd)
    `catch` (\(_ :: IOException) -> pure ())

--------------------------------------------------------------------------------
-- IO: save / load
--------------------------------------------------------------------------------

-- | Save a snapshot durably. The secret region (master key + chain code)
-- is AES-sealed under @atRestKey@ before it touches disk; the rest is
-- stored in the clear so balance display is fast on reload.
saveWalletSnapshot :: ByteString      -- ^ at-rest key (see 'loadOrCreateAtRestKey')
                   -> FilePath        -- ^ wallet.dat path
                   -> WalletSnapshot  -- ^ snapshot with PLAINTEXT key fields
                   -> IO (Either String ())
saveWalletSnapshot atRestKey path snap0 = do
  sealedSk <- sealAtRest atRestKey (wsnMasterSecKey snap0)
  sealedCc <- sealAtRest atRestKey (wsnMasterChain snap0)
  case (,) <$> sealedSk <*> sealedCc of
    Left e -> pure (Left e)
    Right (sk', cc') -> do
      let snap = snap0 { wsnMasterSecKey = sk', wsnMasterChain = cc' }
      r <- try (atomicWriteFileSync path (encodeWalletSnapshot snap))
      pure $ case r of
        Left (e :: SomeException) -> Left ("saveWalletSnapshot: " ++ show e)
        Right ()                  -> Right ()

-- | Fault-tolerant load. Returns:
--
--   * @Right Nothing@  — no file yet (a brand-new wallet, NOT an error).
--   * @Right (Just s)@ — a valid snapshot with the master key/chain code
--                        UNSEALED back to plaintext.
--   * @Left err@       — file present but corrupt / undecodable / wrong
--                        key. The bad file is moved aside to @path.bad@
--                        (best-effort) and the error logged; the caller
--                        falls back to seed re-derivation and node
--                        startup proceeds. NEVER throws.
loadWalletSnapshot :: ByteString -> FilePath -> IO (Either String (Maybe WalletSnapshot))
loadWalletSnapshot atRestKey path = do
  exists <- doesFileExist path
  if not exists
    then pure (Right Nothing)
    else do
      eBlob <- try (BS.readFile path) :: IO (Either SomeException ByteString)
      case eBlob of
        Left e  -> recover ("read error: " ++ show e)
        Right blob -> case decodeWalletSnapshot blob of
          Left e     -> recover ("decode error: " ++ e)
          Right snap ->
            case (,) <$> unsealAtRest atRestKey (wsnMasterSecKey snap)
                     <*> unsealAtRest atRestKey (wsnMasterChain snap) of
              Left e -> recover ("decrypt error: " ++ e)
              Right (sk, cc) ->
                pure (Right (Just snap { wsnMasterSecKey = sk
                                       , wsnMasterChain  = cc }))
  where
    recover reason = do
      let bad = path <> ".bad"
      hPutStrLn stderr $
        "[wallet] corrupt wallet file " ++ path ++ " (" ++ reason
        ++ "); moving to " ++ bad ++ " and continuing with seed recovery"
      (renameFile path bad) `catch` (\(_ :: IOException) -> pure ())
      pure (Left reason)

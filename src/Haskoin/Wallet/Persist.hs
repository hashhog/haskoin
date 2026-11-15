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
-- 3. FAULT-TOLERANT LOAD ('loadWalletSnapshot'): a missing file is
--    @Right Nothing@; a corrupt / truncated / undecryptable file is logged
--    and reported as @Left@ and LEFT IN PLACE.  The caller must fail the
--    load (Core wallet.cpp LoadWallet: a database that cannot be read is
--    an error); it must never replace the wallet with a fresh one.
--
-- 4. ENCRYPTION AT REST: the secret-bearing region (master private key +
--    chain code) is sealed with AES-256-CBC under a key derived from a
--    per-datadir random key file (@wallet.key@, 0600). The clear-text
--    address/UTXO/history metadata needed for fast balance display is
--    stored in the clear; only key material that could spend funds is
--    encrypted, matching Core's "encrypt the keys, index the rest" split.
--
-- 5. SELF-CONTAINED BACKUPS ('encodeWalletBackup'): the at-rest key lives
--    beside the wallets, not inside wallet.dat, so a copy of wallet.dat
--    cannot be opened on another datadir.  A backup therefore re-seals the
--    secrets under a fresh random key and carries that key in the file
--    (@HSKWBK01@ magic).  It does NOT carry the datadir's @wallet.key@,
--    which seals every other wallet in the datadir.  Like an unencrypted
--    Core wallet backup, the file alone is enough to spend: keep it safe.
module Haskoin.Wallet.Persist
  ( -- * Snapshot type
    WalletSnapshot(..)
  , SnapUtxo(..)
  , SnapEncryption(..)
    -- * Codec (pure, exported for tests)
  , encodeWalletSnapshot
  , decodeWalletSnapshot
  , walletSnapshotVersion   -- newest layout; unencrypted wallets are still written as version 1
    -- * IO: atomic durable save / fault-tolerant load
  , saveWalletSnapshot
  , loadWalletSnapshot
  , atomicWriteFileSync
  , atomicWritePrivateFileSync
  , isRecognizedWalletFile
    -- * Self-contained backups
  , encodeWalletBackup
  , decodeWalletBackup
  , readWalletBackupFile
    -- * Encryption-at-rest key file
  , loadOrCreateAtRestKey
  ) where

import Control.Exception (IOException, SomeException, bracketOnError, catch,
                          finally, onException, throwIO, try)
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Serialize
import Data.Serialize (Get, Put, Serialize (..), getBytes,
                       getWord32le, getWord8, putByteString,
                       putWord32le, putWord8, runGet, runPut)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Word (Word32)
import System.Directory (doesFileExist, renameFile)
import System.FilePath (takeDirectory)
import System.IO (IOMode (ReadMode, WriteMode), hClose, hFlush, hPutStrLn,
                  openBinaryFile, stderr, withBinaryFile)
import System.IO.Error (isAlreadyExistsError)
import Numeric (showHex)
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
--
-- Version 2 = version 1 + a trailing passphrase-encryption record
-- ('SnapEncryption'). Only an ENCRYPTED wallet is written as version 2;
-- an unencrypted wallet is still written byte-for-byte as version 1, so a
-- binary that predates version 2 still reads it.
walletSnapshotVersion :: Word32
walletSnapshotVersion = 2

-- | Layout without the encryption record (every unencrypted wallet).
walletSnapshotVersionPlain :: Word32
walletSnapshotVersionPlain = 1

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

-- | The passphrase-encryption record of an encrypted wallet: the master
-- private key AES-256-CBC-encrypted under a key derived from the user's
-- passphrase, plus the KDF parameters needed to derive it again.  Core's
-- @CMasterKey@ record (wallet/crypter.h: vchCryptedKey, vchSalt,
-- nDerivationMethod, nDeriveIterations), written by
-- @CWallet::EncryptWallet@ (wallet/wallet.cpp).  It is NOT sealed again
-- under the at-rest key: without the passphrase it is unreadable anyway.
data SnapEncryption = SnapEncryption
  { seSalt       :: !ByteString   -- ^ PBKDF2 salt
  , seIterations :: !Word32       -- ^ PBKDF2-HMAC-SHA512 iteration count
  , seIV         :: !ByteString   -- ^ AES-CBC IV (16 bytes)
  , seCiphertext :: !ByteString   -- ^ encrypted master private key (PKCS#7 padded)
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
  , wsnEncryption     :: !(Maybe SnapEncryption)
      -- ^ 'Just' once the wallet is passphrase-encrypted (encryptwallet);
      --   a reload restores it LOCKED.  Format version 2 only.
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
  putWord32le (maybe walletSnapshotVersionPlain (const walletSnapshotVersion)
                     wsnEncryption)
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
  mapM_ putSnapEncryption wsnEncryption

-- | Parse a snapshot blob. 'Left' on magic / version / structural
-- mismatch; the IO loader turns that into the move-aside recovery path.
decodeWalletSnapshot :: ByteString -> Either String WalletSnapshot
decodeWalletSnapshot = runGet $ do
  magic <- getBytes (BS.length walletSnapshotMagic)
  when (magic /= walletSnapshotMagic) $
    fail "wallet snapshot: bad magic"
  ver <- getWord32le
  when (ver /= walletSnapshotVersionPlain && ver /= walletSnapshotVersion) $
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
  enc     <- if ver == walletSnapshotVersion
               then Just <$> getSnapEncryption
               else pure Nothing
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
    , wsnEncryption   = enc
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
  PayToAnchorAddress     -> putWord8 5

getAddress :: Get Address
getAddress = getWord8 >>= \case
  0 -> PubKeyAddress . Hash160 <$> getVarBytes'
  1 -> ScriptAddress . Hash160 <$> getVarBytes'
  2 -> WitnessPubKeyAddress . Hash160 <$> getVarBytes'
  3 -> WitnessScriptAddress . Hash256 <$> getVarBytes'
  4 -> TaprootAddress . Hash256 <$> getVarBytes'
  5 -> pure PayToAnchorAddress
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

putSnapEncryption :: SnapEncryption -> Put
putSnapEncryption SnapEncryption{..} = do
  putVarBytes' seSalt
  putWord32le seIterations
  putVarBytes' seIV
  putVarBytes' seCiphertext

-- | A malformed record fails the decode (and so the load) rather than
-- loading the wallet unencrypted: dropping the record would silently
-- remove the passphrase.
getSnapEncryption :: Get SnapEncryption
getSnapEncryption = do
  salt <- getVarBytes'
  iter <- getWord32le
  iv   <- getVarBytes'
  ct   <- getVarBytes'
  when (BS.null salt) $ fail "wallet snapshot: empty encryption salt"
  when (iter == 0) $ fail "wallet snapshot: zero KDF iterations"
  when (BS.length iv /= aesBlockBytes) $ fail "wallet snapshot: bad encryption IV length"
  when (BS.null ct || BS.length ct `mod` aesBlockBytes /= 0) $
    fail "wallet snapshot: bad encrypted key length"
  pure (SnapEncryption salt iter iv ct)

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
--
-- Creation is exclusive: the key is written and fsynced to a temp file
-- opened @O_CREAT|O_EXCL@ with mode 0600 (so it is never readable by
-- others, not even briefly), then published with @link(2)@, which fails
-- with EEXIST instead of replacing a key another caller published first.
-- The loser reads the winner's key.  Before this, two first-use callers
-- could each write a key and the second rename overwrote the first,
-- leaving any wallet sealed under the first key unreadable.
loadOrCreateAtRestKey :: FilePath -> IO ByteString
loadOrCreateAtRestKey keyPath = do
  exists <- doesFileExist keyPath
  if exists
    then BS.readFile keyPath
    else do
      k   <- CryptoRandom.getRandomBytes 32 :: IO ByteString
      tmp <- writePrivateTemp keyPath k
      linked <- try (PosixFiles.createLink tmp keyPath)
      removeQuietly tmp
      case linked of
        Right () -> fsyncDir (takeDirectory keyPath) >> pure k
        Left e
          | isAlreadyExistsError e -> BS.readFile keyPath
          | otherwise              -> throwIO e

-- | Write @bytes@ to a new, uniquely named @path.new.<random>@ created
-- @O_CREAT|O_EXCL@ with mode 0600, fsync it, and return its name.  The
-- file is never readable by group or others, not even briefly.  On any
-- failure the temp file is removed and the exception rethrown.
writePrivateTemp :: FilePath -> ByteString -> IO FilePath
writePrivateTemp path bytes = do
  tag <- CryptoRandom.getRandomBytes 8 :: IO ByteString
  let tmp    = path <> ".new." <> concatMap hex2 (BS.unpack tag)
      hex2 b = let h = showHex b "" in if length h < 2 then '0' : h else h
      flags  = PosixIO.defaultFileFlags { PosixIO.creat     = Just 0o600
                                        , PosixIO.exclusive = True }
  (do h <- PosixIO.openFd tmp PosixIO.WriteOnly flags >>= PosixIO.fdToHandle
      (do BS.hPut h bytes
          hFlush h
          fd <- PosixIO.handleToFd h      -- consumes the handle
          PosixUnistd.fileSynchronise fd `finally` PosixIO.closeFd fd)
        `onException` (hClose h `catch` (\(_ :: IOException) -> pure ())))
    `onException` removeQuietly tmp
  pure tmp

removeQuietly :: FilePath -> IO ()
removeQuietly p = PosixFiles.removeLink p `catch` (\(_ :: IOException) -> pure ())

-- | 'atomicWriteFileSync' for secrets: the file is created mode 0600
-- under a unique temp name ('writePrivateTemp'), then renamed onto
-- @path@.  Used for backups, which carry their own seal key and so are
-- enough to spend (Core creates wallet files under umask 077).
atomicWritePrivateFileSync :: FilePath -> ByteString -> IO ()
atomicWritePrivateFileSync path bytes = do
  tmp <- writePrivateTemp path bytes
  renameFile tmp path `onException` removeQuietly tmp
  fsyncDir (takeDirectory path)

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
--                        key. The error is logged and the file is LEFT
--                        WHERE IT IS: the caller fails the load (Core
--                        LoadWallet), so the user's file is never moved
--                        aside and replaced by a fresh wallet. NEVER throws.
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
      hPutStrLn stderr $
        "[wallet] cannot read wallet file " ++ path ++ " (" ++ reason
        ++ "); leaving it in place, load fails"
      pure (Left reason)

--------------------------------------------------------------------------------
-- Self-contained backups
--------------------------------------------------------------------------------

-- | Magic prefix of a 'encodeWalletBackup' file.
walletBackupMagic :: ByteString
walletBackupMagic = "HSKWBK01"

-- | Serialise a PLAINTEXT snapshot as a self-contained backup:
-- @HSKWBK01 ++ varbytes(backupKey) ++ encodeWalletSnapshot(sealed)@, with
-- the secrets sealed under a fresh random @backupKey@.  Opening it needs
-- nothing from the source datadir, and it does not reveal the datadir's
-- @wallet.key@.
encodeWalletBackup :: WalletSnapshot -> IO (Either String ByteString)
encodeWalletBackup snap0 = do
  bk <- CryptoRandom.getRandomBytes 32 :: IO ByteString
  sealedSk <- sealAtRest bk (wsnMasterSecKey snap0)
  sealedCc <- sealAtRest bk (wsnMasterChain snap0)
  pure $ do
    sk' <- sealedSk
    cc' <- sealedCc
    let snap = snap0 { wsnMasterSecKey = sk', wsnMasterChain = cc' }
    pure (walletBackupMagic <> runPut (putVarBytes' bk)
                            <> encodeWalletSnapshot snap)

-- | Reverse 'encodeWalletBackup'; the result holds PLAINTEXT secrets.
decodeWalletBackup :: ByteString -> Either String WalletSnapshot
decodeWalletBackup blob
  | not (walletBackupMagic `BS.isPrefixOf` blob) = Left "wallet backup: bad magic"
  | otherwise = do
      (bk, rest) <- runGet ((,) <$> getVarBytes' <*> (getBytes =<< remainingLen))
                           (BS.drop (BS.length walletBackupMagic) blob)
      snap <- decodeWalletSnapshot rest
      sk <- unsealAtRest bk (wsnMasterSecKey snap)
      cc <- unsealAtRest bk (wsnMasterChain snap)
      pure snap { wsnMasterSecKey = sk, wsnMasterChain = cc }
  where
    remainingLen = Data.Serialize.remaining

-- | Does the file start with a haskoin wallet or backup magic?  Tells a
-- file that is not a wallet at all (Core's FAILED_BAD_FORMAT) from a
-- wallet file that is damaged (Core's FAILED_LOAD, "Wallet corrupted").
isRecognizedWalletFile :: FilePath -> IO Bool
isRecognizedWalletFile path = do
  r <- try (withBinaryFile path ReadMode (\h -> BS.hGet h 8))
         :: IO (Either SomeException ByteString)
  pure $ case r of
    Right pfx -> pfx == walletSnapshotMagic || pfx == walletBackupMagic
    Left _    -> False

-- | Read a file given to restorewallet.  A self-contained backup opens on
-- its own; a bare wallet.dat (what backupwallet wrote before backups were
-- self-contained) opens only under this datadir's at-rest key.  'Left' on
-- anything that does not open; the file is never moved or modified.
readWalletBackupFile :: ByteString      -- ^ this datadir's at-rest key
                     -> FilePath
                     -> IO (Either String WalletSnapshot)
readWalletBackupFile atRestKey path = do
  eBlob <- try (BS.readFile path) :: IO (Either SomeException ByteString)
  pure $ case eBlob of
    Left e -> Left ("read error: " ++ show e)
    Right blob
      | walletBackupMagic `BS.isPrefixOf` blob -> decodeWalletBackup blob
      | otherwise -> do
          snap <- decodeWalletSnapshot blob
          sk <- unsealAtRest atRestKey (wsnMasterSecKey snap)
          cc <- unsealAtRest atRestKey (wsnMasterChain snap)
          pure snap { wsnMasterSecKey = sk, wsnMasterChain = cc }

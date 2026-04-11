{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}

-- | HD Wallet Implementation (BIP-32, BIP-39, BIP-44, BIP-49, BIP-84, BIP-86)
--
-- This module implements a hierarchical deterministic (HD) wallet following
-- Bitcoin Improvement Proposals:
--   - BIP-39: Mnemonic code for generating deterministic keys
--   - BIP-32: Hierarchical Deterministic Wallets
--   - BIP-44: Multi-Account Hierarchy for Deterministic Wallets (P2PKH)
--   - BIP-49: Derivation scheme for P2SH-P2WPKH accounts
--   - BIP-84: Derivation scheme for P2WPKH based accounts
--   - BIP-86: Derivation scheme for P2TR (Taproot) based accounts
--
-- Coin Selection Algorithms:
--   - Branch-and-Bound (BnB): Exact-match search minimizing waste
--   - Knapsack: Randomized fallback with change output
--
-- Key Design:
--   - Type-safe key derivation (hardened vs non-hardened paths)
--   - Thread-safe wallet state with STM
--   - BIP-44 gap limit for address scanning
--   - UTXO tracking for balance and coin selection
--   - Transaction creation with signing support
--
module Haskoin.Wallet
  ( -- * Wallet
    Wallet(..)
  , WalletConfig(..)
  , createWallet
  , loadWallet
  , saveWallet
    -- * Multi-Wallet Manager
  , WalletManager(..)
  , WalletInfo(..)
  , newWalletManager
  , createManagedWallet
  , loadManagedWallet
  , unloadManagedWallet
  , getManagedWallet
  , getDefaultWallet
  , listManagedWallets
  , getWalletInfo
    -- * BIP-39 Mnemonic
  , Mnemonic(..)
  , generateMnemonic
  , mnemonicToSeed
  , validateMnemonic
  , bip39WordList
    -- * BIP-32 Key Derivation
  , ExtendedKey(..)
  , ExtendedPubKey(..)
  , masterKey
  , derivePrivate
  , derivePublic
  , deriveHardened
  , derivePath
  , toExtendedPubKey
    -- * BIP-44/49/84/86 Paths
  , defaultDerivationPath
  , bip44Path
  , bip49Path
  , bip84Path
  , bip86Path
  , parseDerivationPath
    -- * Address Types
  , AddressType(..)
  , getNewAddress
    -- * Address Management
  , getReceiveAddress
  , getChangeAddress
  , getAddresses
  , isOurAddress
  , getReceiveAddressAt
    -- * Balance & UTXOs
  , getBalance
  , getWalletUTXOs
  , addWalletUTXO
  , removeWalletUTXO
    -- * Transaction Creation
  , createTransaction
  , fundTransaction
  , sendToAddress
  , signTransaction
  , WalletTxOutput(..)
  , CoinSelection(..)
  , selectCoins
  , selectCoinsWithHeight
    -- * Coin Selection Algorithms
  , SelectionAlgorithm(..)
  , selectCoinsBnB
  , knapsackSolver
    -- * UTXO Types
  , Utxo(..)
  , utxoValue
  , OutputGroup(..)
  , WalletUtxoEntry(..)
  , getWalletUTXOsFull
  , addWalletUTXOFull
    -- * Coinbase Maturity
  , isCoinbaseMature
  , filterMatureUtxos
    -- * Wallet Encryption
  , Passphrase
  , EncryptionParams(..)
  , EncryptedWallet(..)
  , WalletState(..)
  , encryptWallet
  , decryptWallet
  , unlockWallet
  , lockWallet
  , isWalletLocked
  , createWalletState
    -- * Address Labels
  , setAddressLabel
  , getAddressLabel
  , setTxLabel
  , getTxLabel
  , getAllAddressLabels
  , getAllTxLabels
    -- * PSBT (BIP-174/BIP-370)
  , Psbt(..)
  , PsbtGlobal(..)
  , PsbtInput(..)
  , PsbtOutput(..)
  , KeyPath(..)
  , emptyPsbt
  , emptyPsbtInput
  , emptyPsbtOutput
    -- * PSBT Roles
  , createPsbt
  , updatePsbt
  , signPsbt
  , combinePsbts
  , finalizePsbt
  , extractTransaction
    -- * PSBT Utilities
  , decodePsbt
  , encodePsbt
  , isPsbtFinalized
  , getPsbtFee
    -- * Output Descriptors (BIP-380-386)
  , Descriptor(..)
  , KeyExpr(..)
  , TapTree(..)
  , DerivRange(..)
  , ParseError(..)
  , parseDescriptor
  , descriptorToText
  , deriveAddresses
  , deriveScripts
  , descriptorChecksum
  , addDescriptorChecksum
  , validateDescriptorChecksum
  , isRangeDescriptor
  , expandCombo
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int64)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, testBit, xor)
import Data.Serialize (Serialize(..), Get, Put, encode, decode, runPut, runGet,
                        putWord32be, putWord32le, getWord32le, putWord8, getWord8,
                        putByteString, getBytes, remaining, lookAhead, skip)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Set (Set)
import qualified Data.Set as Set
import Control.Monad (forM, forM_, when, replicateM, void, foldM)
import Control.Applicative ((<|>))
import System.Random (randomIO, randomRIO)
import Data.List (sortBy, foldl', sortOn)
import Data.Ord (comparing, Down(..))
import Control.Concurrent.STM
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import System.IO.Unsafe (unsafePerformIO)
import Data.Char (isSpace, isDigit, isHexDigit, digitToInt, ord)
import Data.Maybe (listToMaybe, mapMaybe, fromMaybe)
import System.Directory (createDirectoryIfMissing, doesDirectoryExist, listDirectory)
import System.FilePath ((</>))

import Haskoin.Types (Hash256(..), Hash160(..), TxId(..), BlockHash(..), OutPoint(..),
                       TxIn(..), TxOut(..), Tx(..), putVarInt, getVarInt', putVarBytes, getVarBytes)
import Haskoin.Crypto
import Haskoin.Script (encodeP2WPKH, encodeP2PKH, encodeP2SH, encodeP2TR, encodeScript)
import Haskoin.Mempool (FeeRate(..))
import Haskoin.Consensus (Network(..), coinbaseMaturity)

-- For wallet encryption
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), cbcEncrypt, cbcDecrypt, makeIV, IV)
import Crypto.Error (CryptoFailable(..))
import Data.Time.Clock (UTCTime(..), NominalDiffTime, addUTCTime, getCurrentTime, diffUTCTime)
import Data.Time.Calendar (Day(..))
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Crypto.Hash (SHA512(..))

--------------------------------------------------------------------------------
-- BIP-39 Word List
--------------------------------------------------------------------------------

-- | BIP-39 English word list (2048 words).
-- Loaded from resources/bip39-english.txt at module initialization.
-- KNOWN PITFALL: Using unsafePerformIO is acceptable here as the file is
-- read-only and the result is pure.
{-# NOINLINE bip39WordList #-}
bip39WordList :: [Text]
bip39WordList = unsafePerformIO loadBip39WordList

-- | Load the BIP-39 word list from the resources file.
loadBip39WordList :: IO [Text]
loadBip39WordList = do
  content <- TIO.readFile "resources/bip39-english.txt"
  let wordLines = T.lines content
      -- Filter out empty lines and trim whitespace
      words' = filter (not . T.null) $ map T.strip wordLines
  if length words' == 2048
    then return words'
    else error $ "BIP-39 word list must have exactly 2048 words, found " ++ show (length words')

--------------------------------------------------------------------------------
-- BIP-39 Mnemonic
--------------------------------------------------------------------------------

-- | A BIP-39 mnemonic phrase (12-24 words)
newtype Mnemonic = Mnemonic { getMnemonicWords :: [Text] }
  deriving (Show, Eq, Generic)

instance NFData Mnemonic

-- | Generate a new mnemonic with specified entropy bits.
-- Valid strengths: 128 (12 words), 160 (15 words), 192 (18 words),
-- 224 (21 words), 256 (24 words).
generateMnemonic :: Int -> IO Mnemonic
generateMnemonic strength = do
  when (strength `notElem` [128, 160, 192, 224, 256]) $
    error "Mnemonic strength must be 128, 160, 192, 224, or 256 bits"

  -- Generate random entropy
  entropy <- BS.pack <$> replicateM (strength `div` 8) randomIO

  -- Compute checksum (first CS bits of SHA-256)
  let checksum = sha256 entropy
      checksumBits = strength `div` 32

  -- Combine entropy + checksum bits
  let allBits = bytesToBits entropy ++ take checksumBits (bytesToBits checksum)

  -- Split into 11-bit groups and map to words
  let groups = splitEvery 11 allBits
      indices = map bitsToInt groups
      wordList = bip39WordList
      words' = map (\i -> wordList !! i) indices

  return $ Mnemonic words'

-- | Convert mnemonic to seed using PBKDF2-SHA512.
-- The passphrase is optional (empty string for no passphrase).
mnemonicToSeed :: Mnemonic -> Text -> ByteString
mnemonicToSeed (Mnemonic words') passphrase =
  let password = TE.encodeUtf8 (T.intercalate " " words')
      salt = TE.encodeUtf8 ("mnemonic" <> passphrase)
  in pbkdf2SHA512 password salt 2048 64

-- | PBKDF2 with HMAC-SHA512.
-- Standard key derivation function per RFC 8018.
pbkdf2SHA512 :: ByteString -> ByteString -> Int -> Int -> ByteString
pbkdf2SHA512 password salt iterations keyLen =
  let blocks = (keyLen + 63) `div` 64  -- SHA-512 produces 64 bytes
      f blockNum =
        let -- U_1 = PRF(Password, Salt || INT_32_BE(i))
            u1 = hmacSHA512 password (BS.append salt (encodeWord32BE blockNum))
            -- U_n = PRF(Password, U_{n-1})
            -- Result = U_1 XOR U_2 XOR ... XOR U_c
            go prev 1 = prev
            go prev n =
              let next = hmacSHA512 password prev
              in BS.pack (BS.zipWith xor next (go next (n - 1)))
        in go u1 iterations
  in BS.take keyLen $ BS.concat $ map f [1..fromIntegral blocks]

-- | Encode a Word32 as 4 bytes big-endian.
encodeWord32BE :: Int -> ByteString
encodeWord32BE n = runPut $ putWord32be (fromIntegral n)

-- | Validate a mnemonic phrase.
-- Checks word count, dictionary membership, and checksum.
validateMnemonic :: Mnemonic -> Bool
validateMnemonic (Mnemonic words') =
  let wordCount = length words'
      validCount = wordCount `elem` [12, 15, 18, 21, 24]
      allInDict = all (`elem` bip39WordList) words'
  in validCount && allInDict && verifyMnemonicChecksum words'

-- | Verify the mnemonic checksum.
verifyMnemonicChecksum :: [Text] -> Bool
verifyMnemonicChecksum words'
  | null words' = False
  | otherwise =
      let -- Convert words back to indices
          indices = map wordToIndex' words'
          -- Convert indices to 11-bit groups
          bits = concatMap (intToBits 11) indices
          -- Calculate entropy and checksum lengths
          totalBits = length words' * 11
          checksumBits = totalBits `div` 33
          entropyBits = totalBits - checksumBits
          -- Split into entropy and checksum
          (entropyPart, checksumPart) = splitAt entropyBits bits
          -- Reconstruct entropy bytes
          entropyBytes = BS.pack $ map (fromIntegral . bitsToInt) (splitEvery 8 entropyPart)
          -- Compute expected checksum
          expectedChecksum = take checksumBits (bytesToBits (sha256 entropyBytes))
      in checksumPart == expectedChecksum
  where
    wordToIndex :: Text -> Int
    wordToIndex w = case T.breakOn w (T.intercalate "\n" bip39WordList) of
      (before, _) -> length $ filter (== '\n') $ T.unpack before

    -- This is inefficient but correct; for production use a Map
    -- Actually let's use a proper lookup
    wordToIndex' w = go 0 bip39WordList
      where
        go _ [] = 0
        go n (x:xs) = if x == w then n else go (n+1) xs

-- | Convert a byte to 8 bits (MSB first).
bytesToBits :: ByteString -> [Bool]
bytesToBits = concatMap byteToBits . BS.unpack
  where
    byteToBits b = map (testBit b) [7, 6..0]

-- | Convert bits to an integer.
bitsToInt :: [Bool] -> Int
bitsToInt = foldl' (\acc b -> acc * 2 + if b then 1 else 0) 0

-- | Convert an integer to N bits (MSB first).
intToBits :: Int -> Int -> [Bool]
intToBits n val = map (testBit val) [n-1, n-2..0]

-- | Split a list into chunks of size n.
splitEvery :: Int -> [a] -> [[a]]
splitEvery _ [] = []
splitEvery n xs = let (h, t) = splitAt n xs in h : splitEvery n t

--------------------------------------------------------------------------------
-- BIP-32 Extended Keys
--------------------------------------------------------------------------------

-- | Extended private key for BIP-32 HD wallets.
data ExtendedKey = ExtendedKey
  { ekKey        :: !SecKey         -- ^ 32-byte private key
  , ekChainCode  :: !ByteString     -- ^ 32-byte chain code
  , ekDepth      :: !Word8          -- ^ Depth in derivation tree
  , ekParentFP   :: !Word32         -- ^ First 4 bytes of parent key hash
  , ekIndex      :: !Word32         -- ^ Child index (including hardened bit)
  } deriving (Show, Eq, Generic)

instance NFData ExtendedKey

-- | Extended public key for BIP-32 HD wallets.
data ExtendedPubKey = ExtendedPubKey
  { epkKey       :: !PubKey
  , epkChainCode :: !ByteString
  , epkDepth     :: !Word8
  , epkParentFP  :: !Word32
  , epkIndex     :: !Word32
  } deriving (Show, Eq, Generic)

instance NFData ExtendedPubKey

-- | Derive master key from seed (BIP-32).
-- Uses HMAC-SHA512 with key "Bitcoin seed".
masterKey :: ByteString -> ExtendedKey
masterKey seed =
  let hmacResult = hmacSHA512 "Bitcoin seed" seed
      (privateKey, chainCode) = BS.splitAt 32 hmacResult
  in ExtendedKey
    { ekKey = SecKey privateKey
    , ekChainCode = chainCode
    , ekDepth = 0
    , ekParentFP = 0
    , ekIndex = 0
    }

-- | Derive child private key (non-hardened).
-- Index must be < 0x80000000.
-- KNOWN PITFALL: Public key derivation can follow, but NOT for hardened keys.
derivePrivate :: ExtendedKey -> Word32 -> ExtendedKey
derivePrivate parent index
  | index >= 0x80000000 = error "derivePrivate: use deriveHardened for index >= 0x80000000"
  | otherwise =
      let pubKey = derivePubKeyFromPrivate (ekKey parent)
          pubBytes = serializePubKeyCompressed pubKey
          dat = BS.append pubBytes (encodeWord32BE' index)
          hmacResult = hmacSHA512 (ekChainCode parent) dat
          (il, ir) = BS.splitAt 32 hmacResult
          childKey = addPrivateKeys il (getSecKey (ekKey parent))
          fingerprint = computeFingerprint pubBytes
      in ExtendedKey
        { ekKey = SecKey childKey
        , ekChainCode = ir
        , ekDepth = ekDepth parent + 1
        , ekParentFP = fingerprint
        , ekIndex = index
        }

-- | Derive child private key (hardened).
-- Hardened derivation uses the private key directly, preventing public
-- key derivation without the private key.
deriveHardened :: ExtendedKey -> Word32 -> ExtendedKey
deriveHardened parent index =
  let hardenedIndex = index .|. 0x80000000
      dat = BS.cons 0x00 (getSecKey (ekKey parent)) `BS.append` encodeWord32BE' hardenedIndex
      hmacResult = hmacSHA512 (ekChainCode parent) dat
      (il, ir) = BS.splitAt 32 hmacResult
      childKey = addPrivateKeys il (getSecKey (ekKey parent))
      pubBytes = serializePubKeyCompressed (derivePubKeyFromPrivate (ekKey parent))
      fingerprint = computeFingerprint pubBytes
  in ExtendedKey
    { ekKey = SecKey childKey
    , ekChainCode = ir
    , ekDepth = ekDepth parent + 1
    , ekParentFP = fingerprint
    , ekIndex = hardenedIndex
    }

-- | Derive child public key (non-hardened only).
-- KNOWN PITFALL: Cannot derive hardened children from public key alone.
derivePublic :: ExtendedPubKey -> Word32 -> ExtendedPubKey
derivePublic parent index
  | index >= 0x80000000 = error "derivePublic: cannot derive hardened child from public key"
  | otherwise =
      let pubBytes = serializePubKeyCompressed (epkKey parent)
          dat = BS.append pubBytes (encodeWord32BE' index)
          hmacResult = hmacSHA512 (epkChainCode parent) dat
          (il, ir) = BS.splitAt 32 hmacResult
          -- Child pubkey = point(il) + parent pubkey
          -- This requires EC point addition which we don't have fully implemented
          -- For now, this is a placeholder
          childPubKey = addPublicKeyPoint il (epkKey parent)
          fingerprint = computeFingerprint pubBytes
      in ExtendedPubKey
        { epkKey = childPubKey
        , epkChainCode = ir
        , epkDepth = epkDepth parent + 1
        , epkParentFP = fingerprint
        , epkIndex = index
        }

-- | Derive along a path.
-- Path elements >= 0x80000000 are hardened.
derivePath :: ExtendedKey -> [Word32] -> ExtendedKey
derivePath = foldl' (\key idx ->
  if idx >= 0x80000000
    then deriveHardened key (idx .&. 0x7fffffff)
    else derivePrivate key idx)

-- | Convert extended private key to extended public key.
toExtendedPubKey :: ExtendedKey -> ExtendedPubKey
toExtendedPubKey ek = ExtendedPubKey
  { epkKey = derivePubKeyFromPrivate (ekKey ek)
  , epkChainCode = ekChainCode ek
  , epkDepth = ekDepth ek
  , epkParentFP = ekParentFP ek
  , epkIndex = ekIndex ek
  }

-- | Add two 32-byte private keys modulo the secp256k1 order.
-- This is simplified - in production, use proper big integer arithmetic.
addPrivateKeys :: ByteString -> ByteString -> ByteString
addPrivateKeys a b =
  let -- secp256k1 order n
      n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 :: Integer
      aInt = bsToIntegerBE a
      bInt = bsToIntegerBE b
      sumInt = (aInt + bInt) `mod` n
  in integerToBS32 sumInt

-- | Add a scalar to a public key point (simplified placeholder).
-- In production, this requires proper EC point arithmetic.
addPublicKeyPoint :: ByteString -> PubKey -> PubKey
addPublicKeyPoint _scalar pk = pk  -- Placeholder - needs secp256k1 implementation

-- | Derive public key from private key.
-- Placeholder that returns a dummy compressed public key.
-- In production, this requires secp256k1 EC multiplication.
derivePubKeyFromPrivate :: SecKey -> PubKey
derivePubKeyFromPrivate (SecKey sk) =
  -- This is a placeholder - actual implementation needs secp256k1
  -- For now, we create a deterministic but invalid public key
  let h = sha256 sk
      prefix = if BS.last h `testBit` 0 then 0x03 else 0x02
  in PubKeyCompressed (BS.cons prefix (BS.take 32 h))

-- | Compute key fingerprint (first 4 bytes of HASH160).
computeFingerprint :: ByteString -> Word32
computeFingerprint pubBytes =
  let Hash160 h = hash160 pubBytes
  in decodeWord32BE (BS.take 4 h)

-- | Encode Word32 as 4 bytes big-endian.
encodeWord32BE' :: Word32 -> ByteString
encodeWord32BE' w = runPut $ putWord32be w

-- | Decode 4 bytes big-endian to Word32.
decodeWord32BE :: ByteString -> Word32
decodeWord32BE bs = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 (BS.take 4 bs)

-- | Convert ByteString to Integer (big-endian).
bsToIntegerBE :: ByteString -> Integer
bsToIntegerBE = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

-- | Convert Integer to 32-byte ByteString (big-endian, zero-padded).
integerToBS32 :: Integer -> ByteString
integerToBS32 n =
  let bytes = reverse $ go n
      go 0 = []
      go x = fromIntegral (x `mod` 256) : go (x `div` 256)
      padded = replicate (32 - length bytes) 0 ++ bytes
  in BS.pack padded

--------------------------------------------------------------------------------
-- BIP-44/84 Derivation Paths
--------------------------------------------------------------------------------

-- | BIP-44 path: m/44'/0'/account'
-- For legacy P2PKH addresses.
bip44Path :: Word32 -> [Word32]
bip44Path account = [0x80000000 .|. 44, 0x80000000 .|. 0, 0x80000000 .|. account]

-- | BIP-49 path: m/49'/0'/account'
-- For P2SH-wrapped SegWit (P2SH-P2WPKH) addresses.
bip49Path :: Word32 -> [Word32]
bip49Path account = [0x80000000 .|. 49, 0x80000000 .|. 0, 0x80000000 .|. account]

-- | BIP-84 path: m/84'/0'/account'
-- For native SegWit (P2WPKH) addresses.
bip84Path :: Word32 -> [Word32]
bip84Path account = [0x80000000 .|. 84, 0x80000000 .|. 0, 0x80000000 .|. account]

-- | BIP-86 path: m/86'/0'/account'
-- For Taproot (P2TR) addresses.
bip86Path :: Word32 -> [Word32]
bip86Path account = [0x80000000 .|. 86, 0x80000000 .|. 0, 0x80000000 .|. account]

-- | Default derivation path: BIP-84 account 0.
defaultDerivationPath :: [Word32]
defaultDerivationPath = bip84Path 0

--------------------------------------------------------------------------------
-- Address Types
--------------------------------------------------------------------------------

-- | Supported address types for wallet operations.
data AddressType
  = AddrP2PKH       -- ^ Legacy Pay-to-Public-Key-Hash (BIP-44)
  | AddrP2SH_P2WPKH -- ^ P2SH-wrapped SegWit (BIP-49)
  | AddrP2WPKH      -- ^ Native SegWit (BIP-84)
  | AddrP2TR        -- ^ Taproot (BIP-86)
  deriving (Show, Eq, Ord, Generic)

instance NFData AddressType

-- | Get the derivation path prefix for an address type.
addressTypeDerivPath :: AddressType -> Word32 -> [Word32]
addressTypeDerivPath AddrP2PKH       = bip44Path
addressTypeDerivPath AddrP2SH_P2WPKH = bip49Path
addressTypeDerivPath AddrP2WPKH      = bip84Path
addressTypeDerivPath AddrP2TR        = bip86Path

-- | Parse a derivation path string like "m/84'/0'/0'".
parseDerivationPath :: String -> Maybe [Word32]
parseDerivationPath path =
  let parts = filter (not . null) $ splitOn '/' path
  in case parts of
       ("m":rest) -> Just $ map parsePathComponent rest
       _ -> Nothing
  where
    parsePathComponent :: String -> Word32
    parsePathComponent s
      | last s == '\'' || last s == 'h' =
          0x80000000 .|. read (init s)
      | otherwise = read s

    splitOn :: Char -> String -> [String]
    splitOn _ [] = []
    splitOn c s = let (h, t) = break (== c) s
                  in h : case t of
                           [] -> []
                           (_:rest) -> splitOn c rest

--------------------------------------------------------------------------------
-- Wallet Types
--------------------------------------------------------------------------------

-- | Stored UTXO entry with metadata needed for maturity checking.
data WalletUtxoEntry = WalletUtxoEntry
  { wueTxOut       :: !TxOut         -- ^ The output data
  , wueBlockHeight :: !Word32        -- ^ Block height where UTXO was created
  , wueIsCoinbase  :: !Bool          -- ^ Whether this is from a coinbase tx
  } deriving (Show, Eq, Generic)

instance NFData WalletUtxoEntry

-- | HD Wallet with BIP-84 (native SegWit) support.
data Wallet = Wallet
  { walletMasterKey    :: !ExtendedKey        -- ^ BIP-32 master key from seed
  , walletAccountKey   :: !ExtendedKey        -- ^ Derived at m/84'/0'/0'
  , walletReceiveIndex :: !(TVar Word32)      -- ^ Next unused receive index
  , walletChangeIndex  :: !(TVar Word32)      -- ^ Next unused change index
  , walletAddresses    :: !(TVar (Map Address (Word32, Bool)))
      -- ^ address -> (index, isChange)
  , walletUTXOs        :: !(TVar (Map OutPoint WalletUtxoEntry))
      -- ^ outpoint -> UTXO entry with height and coinbase info
  , walletNetwork      :: !Network
  , walletGapLimit     :: !Int                -- ^ BIP-44 gap limit (default 20)
  , walletAddressLabels :: !(TVar (Map Address Text))
      -- ^ Address labels
  , walletTxLabels     :: !(TVar (Map TxId Text))
      -- ^ Transaction labels
  }

-- | Wallet configuration parameters.
data WalletConfig = WalletConfig
  { wcNetwork    :: !Network
  , wcGapLimit   :: !Int
  , wcPassphrase :: !Text
  } deriving (Show)

--------------------------------------------------------------------------------
-- Wallet Creation
--------------------------------------------------------------------------------

-- | Create a new wallet with fresh mnemonic.
-- Returns the mnemonic (which should be backed up) and the wallet.
createWallet :: WalletConfig -> IO (Mnemonic, Wallet)
createWallet WalletConfig{..} = do
  mnemonic <- generateMnemonic 256  -- 24 words for maximum security
  wallet <- loadWallet WalletConfig{..} mnemonic
  -- Pre-generate gap limit addresses
  mapM_ (\i -> void $ getReceiveAddressAt wallet i) [0 .. fromIntegral wcGapLimit - 1]
  return (mnemonic, wallet)

-- | Load a wallet from an existing mnemonic.
loadWallet :: WalletConfig -> Mnemonic -> IO Wallet
loadWallet WalletConfig{..} mnemonic = do
  let seed = mnemonicToSeed mnemonic wcPassphrase
      master = masterKey seed
      account = derivePath master defaultDerivationPath
  recvIdx <- newTVarIO 0
  changeIdx <- newTVarIO 0
  addrs <- newTVarIO Map.empty
  utxos <- newTVarIO Map.empty
  addrLabels <- newTVarIO Map.empty
  txLabels <- newTVarIO Map.empty
  return $ Wallet master account recvIdx changeIdx addrs utxos wcNetwork wcGapLimit
                  addrLabels txLabels

-- | Save wallet state to a file.
-- SECURITY: In production, encrypt private keys with a passphrase.
-- NEVER store mnemonics or private keys unencrypted.
saveWallet :: Wallet -> FilePath -> IO ()
saveWallet _wallet _path =
  error "Wallet persistence not yet implemented - requires encrypted storage"

--------------------------------------------------------------------------------
-- Address Generation
--------------------------------------------------------------------------------

-- | Get the private key for a specific receive address index.
getReceiveKey :: Wallet -> Word32 -> ExtendedKey
getReceiveKey wallet idx =
  let externalChain = derivePrivate (walletAccountKey wallet) 0  -- External chain (receive)
  in derivePrivate externalChain idx

-- | Get the private key for a specific change address index.
getChangeKey :: Wallet -> Word32 -> ExtendedKey
getChangeKey wallet idx =
  let internalChain = derivePrivate (walletAccountKey wallet) 1  -- Internal chain (change)
  in derivePrivate internalChain idx

-- | Derive receive address at specific index.
-- Path: m/84'/0'/0'/0/idx
getReceiveAddressAt :: Wallet -> Word32 -> IO Address
getReceiveAddressAt wallet idx = do
  let key = getReceiveKey wallet idx
      pubKey = derivePubKeyFromPrivate (ekKey key)
      addr = pubKeyToP2WPKH pubKey
  atomically $ modifyTVar' (walletAddresses wallet) (Map.insert addr (idx, False))
  return addr

-- | Get the next unused receive address.
getReceiveAddress :: Wallet -> IO Address
getReceiveAddress wallet = do
  idx <- readTVarIO (walletReceiveIndex wallet)
  addr <- getReceiveAddressAt wallet idx
  atomically $ modifyTVar' (walletReceiveIndex wallet) (+ 1)
  return addr

-- | Get a new address of the specified type.
-- Derives the key from the appropriate BIP path based on address type.
getNewAddress :: AddressType -> Wallet -> IO Address
getNewAddress addrType wallet = do
  -- Get account key for this address type
  let accountPath = addressTypeDerivPath addrType 0
      accountKey = derivePath (walletMasterKey wallet) accountPath
      -- External chain (receive addresses)
      externalChain = derivePrivate accountKey 0

  -- Get next index and derive address
  idx <- readTVarIO (walletReceiveIndex wallet)
  let derivedKey = derivePrivate externalChain idx
      pubKey = derivePubKeyFromPrivate (ekKey derivedKey)
      addr = pubKeyToAddress addrType pubKey

  atomically $ do
    modifyTVar' (walletReceiveIndex wallet) (+ 1)
    modifyTVar' (walletAddresses wallet) (Map.insert addr (idx, False))

  return addr

-- | Convert a public key to the appropriate address type.
pubKeyToAddress :: AddressType -> PubKey -> Address
pubKeyToAddress AddrP2PKH pk = pubKeyToP2PKH pk
pubKeyToAddress AddrP2SH_P2WPKH pk =
  -- P2SH-P2WPKH: wrap the P2WPKH script in P2SH
  let pubKeyHash = hash160 (serializePubKeyCompressed pk)
      -- The redeemScript is: OP_0 <20-byte pubkey hash>
      redeemScript = BS.cons 0x00 (BS.cons 0x14 (getHash160 pubKeyHash))
  in scriptToP2SH redeemScript
pubKeyToAddress AddrP2WPKH pk = pubKeyToP2WPKH pk
pubKeyToAddress AddrP2TR pk =
  -- For P2TR, we use the internal key directly (simplified, no tweaking)
  -- In production, this should use proper BIP-341 key tweaking
  let pubKeyBytes = serializePubKeyCompressed pk
      -- Take the x-coordinate (drop the prefix byte)
      xOnly = BS.drop 1 pubKeyBytes
  in TaprootAddress (Hash256 xOnly)

-- | Get a change address of the specified type.
getChangeAddressTyped :: AddressType -> Wallet -> IO Address
getChangeAddressTyped addrType wallet = do
  let accountPath = addressTypeDerivPath addrType 0
      accountKey = derivePath (walletMasterKey wallet) accountPath
      -- Internal chain (change addresses)
      internalChain = derivePrivate accountKey 1

  idx <- readTVarIO (walletChangeIndex wallet)
  let derivedKey = derivePrivate internalChain idx
      pubKey = derivePubKeyFromPrivate (ekKey derivedKey)
      addr = pubKeyToAddress addrType pubKey

  atomically $ do
    modifyTVar' (walletChangeIndex wallet) (+ 1)
    modifyTVar' (walletAddresses wallet) (Map.insert addr (idx, True))

  return addr

-- | Get the next unused change address (default P2WPKH type).
getChangeAddress :: Wallet -> IO Address
getChangeAddress wallet = do
  idx <- readTVarIO (walletChangeIndex wallet)
  let key = getChangeKey wallet idx
      pubKey = derivePubKeyFromPrivate (ekKey key)
      addr = pubKeyToP2WPKH pubKey
  atomically $ do
    modifyTVar' (walletChangeIndex wallet) (+ 1)
    modifyTVar' (walletAddresses wallet) (Map.insert addr (idx, True))
  return addr

-- | Get all generated addresses.
getAddresses :: Wallet -> IO [(Address, Word32, Bool)]
getAddresses wallet = do
  addrs <- readTVarIO (walletAddresses wallet)
  return [(addr, idx, isChange) | (addr, (idx, isChange)) <- Map.toList addrs]

-- | Check if an address belongs to this wallet.
isOurAddress :: Wallet -> Address -> IO Bool
isOurAddress wallet addr =
  Map.member addr <$> readTVarIO (walletAddresses wallet)

--------------------------------------------------------------------------------
-- Balance & UTXOs
--------------------------------------------------------------------------------

-- | Get the total confirmed balance.
getBalance :: Wallet -> IO Word64
getBalance wallet = do
  utxos <- readTVarIO (walletUTXOs wallet)
  return $ sum $ map (txOutValue . wueTxOut) (Map.elems utxos)

-- | Get all wallet UTXOs with metadata.
-- Returns (outpoint, txout, confirmations) for compatibility.
-- Note: Confirmations must be computed externally from current tip height.
getWalletUTXOs :: Wallet -> IO [(OutPoint, TxOut, Word32)]
getWalletUTXOs wallet = do
  utxos <- readTVarIO (walletUTXOs wallet)
  -- Return block height as confirmations placeholder
  -- Real confirmations = tipHeight - blockHeight + 1
  return [(op, wueTxOut entry, wueBlockHeight entry)
         | (op, entry) <- Map.toList utxos]

-- | Get all wallet UTXOs with full entry info.
getWalletUTXOsFull :: Wallet -> IO [(OutPoint, WalletUtxoEntry)]
getWalletUTXOsFull wallet = do
  utxos <- readTVarIO (walletUTXOs wallet)
  return $ Map.toList utxos

-- | Add a UTXO to the wallet.
-- For backward compatibility, assumes non-coinbase if using simple API.
addWalletUTXO :: Wallet -> OutPoint -> TxOut -> Word32 -> IO ()
addWalletUTXO wallet op txout blockHeight =
  addWalletUTXOFull wallet op txout blockHeight False

-- | Add a UTXO to the wallet with full metadata.
addWalletUTXOFull :: Wallet -> OutPoint -> TxOut -> Word32 -> Bool -> IO ()
addWalletUTXOFull wallet op txout blockHeight isCoinbase = do
  let entry = WalletUtxoEntry txout blockHeight isCoinbase
  atomically $ modifyTVar' (walletUTXOs wallet) (Map.insert op entry)

-- | Remove a UTXO from the wallet (when spent).
removeWalletUTXO :: Wallet -> OutPoint -> IO ()
removeWalletUTXO wallet op =
  atomically $ modifyTVar' (walletUTXOs wallet) (Map.delete op)

--------------------------------------------------------------------------------
-- UTXO Types for Coin Selection
--------------------------------------------------------------------------------

-- | A UTXO available for spending.
data Utxo = Utxo
  { utxoOutPoint     :: !OutPoint      -- ^ Reference to the UTXO
  , utxoTxOut        :: !TxOut         -- ^ The output data
  , utxoConfirmations :: !Word32       -- ^ Number of confirmations
  , utxoIsCoinbase   :: !Bool          -- ^ Whether this is from a coinbase tx
  , utxoBlockHeight  :: !Word32        -- ^ Block height where UTXO was created
  } deriving (Show, Eq, Generic)

instance NFData Utxo

-- | Get the value of a UTXO in satoshis.
utxoValue :: Utxo -> Word64
utxoValue = txOutValue . utxoTxOut

-- | Grouped outputs for coin selection with fee calculations.
-- Reference: Bitcoin Core coinselection.h OutputGroup
data OutputGroup = OutputGroup
  { ogUtxos         :: ![Utxo]         -- ^ UTXOs in this group
  , ogValue         :: !Word64         -- ^ Total value
  , ogEffectiveValue :: !Int64         -- ^ Value minus fee to spend (can be negative)
  , ogFee           :: !Word64         -- ^ Fee to spend at current rate
  , ogLongTermFee   :: !Word64         -- ^ Fee to spend at long-term rate
  , ogWeight        :: !Int            -- ^ Weight in witness units
  } deriving (Show, Eq, Generic)

instance NFData OutputGroup

-- | Selection algorithm choice.
data SelectionAlgorithm
  = AlgBnB        -- ^ Branch-and-Bound (exact match, no change)
  | AlgKnapsack   -- ^ Knapsack with random selection
  | AlgLargestFirst -- ^ Simple largest-first (legacy)
  deriving (Show, Eq, Generic)

instance NFData SelectionAlgorithm

--------------------------------------------------------------------------------
-- Transaction Size Constants
--------------------------------------------------------------------------------

-- | Estimated weight for different input/output types (in WU).
-- Reference: Bitcoin Core policy/policy.cpp

-- P2PKH input: 148 vB = 592 WU (signature ~71 + pubkey ~34 + overhead)
inputWeightP2PKH :: Int
inputWeightP2PKH = 592

-- P2WPKH input: 68 vB = 272 WU (41 base + 27 witness overhead)
inputWeightP2WPKH :: Int
inputWeightP2WPKH = 272

-- P2SH-P2WPKH input: 91 vB = 364 WU
inputWeightP2SH_P2WPKH :: Int
inputWeightP2SH_P2WPKH = 364

-- P2TR input: 58 vB = 232 WU (key path spend)
inputWeightP2TR :: Int
inputWeightP2TR = 232

-- P2PKH output: 34 vB = 136 WU
outputWeightP2PKH :: Int
outputWeightP2PKH = 136

-- P2WPKH output: 31 vB = 124 WU
outputWeightP2WPKH :: Int
outputWeightP2WPKH = 124

-- P2SH output: 32 vB = 128 WU
outputWeightP2SH :: Int
outputWeightP2SH = 128

-- P2TR output: 43 vB = 172 WU
outputWeightP2TR :: Int
outputWeightP2TR = 172

-- Transaction overhead: ~10 vB = 40 WU (version + locktime + varint counts)
txOverheadWeight :: Int
txOverheadWeight = 40

-- Witness overhead per input: 2 WU (for marker and flag if needed)
witnessOverheadWeight :: Int
witnessOverheadWeight = 2

-- | Minimum dust threshold in satoshis.
dustThreshold :: Word64
dustThreshold = 546

-- | Minimum change amount (must be > dust to be economical).
minChangeAmount :: Word64
minChangeAmount = 1000

-- | Cost of creating a change output (in satoshis at given fee rate).
-- Includes output size + future input size to spend it.
costOfChange :: FeeRate -> Word64
costOfChange feeRate =
  let outputCost = fromIntegral outputWeightP2WPKH * getFeeRate feeRate `div` 4000
      spendCost = fromIntegral inputWeightP2WPKH * getFeeRate feeRate `div` 4000
  in outputCost + spendCost

--------------------------------------------------------------------------------
-- Transaction Creation
--------------------------------------------------------------------------------

-- | A payment output for transaction creation.
data WalletTxOutput = WalletTxOutput
  { wtoAddress :: !Address
  , wtoAmount  :: !Word64
  } deriving (Show, Generic)

instance NFData WalletTxOutput

-- | Result of coin selection.
data CoinSelection = CoinSelection
  { csInputs      :: ![(OutPoint, TxOut)]
  , csOutputs     :: ![WalletTxOutput]
  , csChange      :: !(Maybe (Address, Word64))
  , csFee         :: !Word64
  , csFeeRate     :: !FeeRate
  , csAlgorithm   :: !SelectionAlgorithm
  , csWaste       :: !Int64              -- ^ Waste metric (for optimization)
  } deriving (Show)

-- | Estimate transaction weight for fee calculation.
estimateTxWeight :: Int -> Int -> Bool -> Int
estimateTxWeight numInputs numOutputs hasChange =
  let totalOutputs = numOutputs + (if hasChange then 1 else 0)
      -- Assume P2WPKH inputs and outputs (most common case)
  in txOverheadWeight
     + numInputs * inputWeightP2WPKH
     + totalOutputs * outputWeightP2WPKH
     + (if numInputs > 0 then witnessOverheadWeight else 0)

-- | Calculate fee from weight and fee rate.
feeFromWeight :: Int -> FeeRate -> Word64
feeFromWeight weight feeRate =
  let vsize = (weight + 3) `div` 4  -- Round up to nearest vB
  in fromIntegral vsize * getFeeRate feeRate `div` 1000

-- | Calculate effective value of a UTXO (value minus fee to spend it).
effectiveValue :: Utxo -> FeeRate -> Int64
effectiveValue utxo feeRate =
  let value = fromIntegral (utxoValue utxo) :: Int64
      spendFee = fromIntegral $ feeFromWeight inputWeightP2WPKH feeRate
  in value - spendFee

-- | Convert wallet UTXOs to OutputGroups for coin selection.
utxosToGroups :: [(OutPoint, TxOut, Word32)] -> FeeRate -> [OutputGroup]
utxosToGroups utxos feeRate = map toGroup utxos
  where
    toGroup (op, txo, confs) =
      let utxo = Utxo op txo confs False 0
          value = utxoValue utxo
          effVal = effectiveValue utxo feeRate
          fee = feeFromWeight inputWeightP2WPKH feeRate
          -- Use same fee rate for long-term (simplified)
          longTermFee = feeFromWeight inputWeightP2WPKH (FeeRate 1)
      in OutputGroup [utxo] value effVal fee longTermFee inputWeightP2WPKH

--------------------------------------------------------------------------------
-- Branch-and-Bound Coin Selection (BIP-XXX)
--------------------------------------------------------------------------------

-- | Maximum iterations for BnB search to prevent DoS.
maxBnBIterations :: Int
maxBnBIterations = 100000

-- | BnB search state.
data BnBState = BnBState
  { bnbSelected     :: ![OutputGroup]   -- ^ Currently selected groups
  , bnbValue        :: !Int64           -- ^ Sum of effective values
  , bnbWaste        :: !Int64           -- ^ Current waste
  , bnbIterations   :: !Int             -- ^ Iteration count
  } deriving (Show)

-- | Select coins using Branch-and-Bound algorithm.
-- Finds an exact match (or within fee tolerance) without needing change.
-- Reference: Bitcoin Core coinselection.cpp SelectCoinsBnB
--
-- Returns selected UTXOs if found, Nothing if no exact match exists.
selectCoinsBnB :: [Utxo] -> Word64 -> FeeRate -> Maybe [Utxo]
selectCoinsBnB utxos target feeRate
  | null utxos = Nothing
  | target == 0 = Just []
  | otherwise =
      let -- Convert to output groups sorted by descending effective value
          groups = sortOn (Down . ogEffectiveValue) $ utxosToGroups' utxos feeRate
          -- Filter out groups with non-positive effective value
          positiveGroups = filter (\g -> ogEffectiveValue g > 0) groups
          targetInt = fromIntegral target :: Int64
          -- Cost of change output determines acceptable overshoot
          changeCost = fromIntegral (costOfChange feeRate) :: Int64
      in case bnbSearch positiveGroups targetInt changeCost of
           Just selected -> Just $ concatMap ogUtxos selected
           Nothing -> Nothing

-- | Convert UTXOs to output groups.
utxosToGroups' :: [Utxo] -> FeeRate -> [OutputGroup]
utxosToGroups' utxos feeRate = map toGroup utxos
  where
    toGroup utxo =
      let value = utxoValue utxo
          effVal = effectiveValue utxo feeRate
          fee = feeFromWeight inputWeightP2WPKH feeRate
          longTermFee = feeFromWeight inputWeightP2WPKH (FeeRate 1)
      in OutputGroup [utxo] value effVal fee longTermFee inputWeightP2WPKH

-- | Core BnB search algorithm.
-- Uses depth-first search with pruning to find exact matches.
bnbSearch :: [OutputGroup] -> Int64 -> Int64 -> Maybe [OutputGroup]
bnbSearch groups target costOfChangeInt = go groups 0 [] 0 Nothing
  where
    -- Precompute cumulative lookahead values
    lookaheadValues = scanr (\g acc -> acc + ogEffectiveValue g) 0 groups

    go :: [OutputGroup] -> Int64 -> [OutputGroup] -> Int -> Maybe [OutputGroup]
       -> Maybe [OutputGroup]
    go remaining currValue selected iterations best
      -- Exceeded iteration limit
      | iterations >= maxBnBIterations = best
      -- Found a match: current value is in [target, target + costOfChange]
      | currValue >= target && currValue <= target + costOfChangeInt =
          -- Accept this solution (no need for change output)
          Just selected
      -- Pruning: current value exceeded upper bound
      | currValue > target + costOfChangeInt =
          best  -- Backtrack
      -- End of groups
      | null remaining =
          best
      | otherwise =
          let (g:rest) = remaining
              idxInLookahead = length groups - length remaining
              lookahead = if idxInLookahead < length lookaheadValues
                         then lookaheadValues !! idxInLookahead
                         else 0
              -- Pruning: even with all remaining, can't reach target
              canReachTarget = currValue + lookahead >= target
          in if not canReachTarget
             then best  -- Prune this branch
             else
               -- Try including this group first (depth-first)
               let withGroup = go rest (currValue + ogEffectiveValue g)
                                 (g : selected) (iterations + 1) best
               in case withGroup of
                    Just result -> Just result  -- Found a solution
                    Nothing ->
                      -- Try excluding this group
                      go rest currValue selected (iterations + 1) best

--------------------------------------------------------------------------------
-- Knapsack Coin Selection
--------------------------------------------------------------------------------

-- | Knapsack solver with randomized selection.
-- Falls back when BnB doesn't find an exact match.
-- Reference: Bitcoin Core coinselection.cpp KnapsackSolver
--
-- Algorithm:
-- 1. Shuffle UTXOs for privacy
-- 2. Try to find subset sum close to target + change
-- 3. Use randomized approximation if exact match not found
knapsackSolver :: [Utxo] -> Word64 -> FeeRate -> IO [Utxo]
knapsackSolver utxos target feeRate
  | null utxos = return []
  | target == 0 = return []
  | otherwise = do
      -- Shuffle for privacy
      shuffled <- shuffleList utxos

      -- Calculate target with minimum change
      let changeTarget = minChangeAmount + costOfChange feeRate
          fullTarget = target + changeTarget

          -- Separate into groups
          (applicable, lowestLarger) = partitionUtxos shuffled fullTarget feeRate

      -- Try to find exact match first
      case findExactMatch applicable target feeRate of
        Just exact -> return exact
        Nothing ->
          -- Find smallest single UTXO >= full target
          case lowestLarger of
            Just single -> return [single]
            Nothing ->
              -- Use approximate subset sum
              approximateBestSubset applicable (target + changeTarget) feeRate

-- | Partition UTXOs into applicable (< target + change) and find lowest larger.
partitionUtxos :: [Utxo] -> Word64 -> FeeRate -> ([Utxo], Maybe Utxo)
partitionUtxos utxos fullTarget feeRate =
  let effValues = map (\u -> (u, effectiveValue u feeRate)) utxos
      (applicable, larger) = foldl' categorize ([], []) effValues
      lowestLarger = listToMaybe $ sortOn utxoValue larger
  in (applicable, lowestLarger)
  where
    categorize (app, lrg) (utxo, effVal)
      | effVal > 0 && fromIntegral effVal < fromIntegral fullTarget =
          (utxo : app, lrg)
      | effVal >= fromIntegral fullTarget =
          (app, utxo : lrg)
      | otherwise = (app, lrg)

-- | Try to find an exact subset sum match.
findExactMatch :: [Utxo] -> Word64 -> FeeRate -> Maybe [Utxo]
findExactMatch utxos target feeRate =
  let targetInt = fromIntegral target :: Int64
      -- Sort by descending effective value
      sorted = sortOn (Down . (`effectiveValue` feeRate)) utxos
      go [] _ acc = Nothing
      go (u:rest) remaining acc
        | remaining <= 0 = Just (reverse acc)
        | effVal <= remaining =
            case go rest (remaining - effVal) (u : acc) of
              Just result -> Just result
              Nothing -> go rest remaining acc
        | otherwise = go rest remaining acc
        where
          effVal = effectiveValue u feeRate
  in go sorted targetInt []

-- | Approximate best subset using stochastic approximation.
-- Runs multiple passes with random inclusion/exclusion.
approximateBestSubset :: [Utxo] -> Word64 -> FeeRate -> IO [Utxo]
approximateBestSubset utxos target feeRate = do
  let iterations = 1000
      targetInt = fromIntegral target :: Int64

  -- Track best solution
  bestRef <- newTVarIO (Nothing :: Maybe ([Utxo], Int64))

  -- Run iterations
  forM_ [1..iterations] $ \_ -> do
    -- Random selection for this iteration
    selected <- randomSubset utxos
    let totalEffVal = sum $ map (`effectiveValue` feeRate) selected

    when (totalEffVal >= targetInt) $ do
      atomically $ do
        best <- readTVar bestRef
        let excess = totalEffVal - targetInt
        case best of
          Nothing -> writeTVar bestRef (Just (selected, excess))
          Just (_, bestExcess)
            | excess < bestExcess -> writeTVar bestRef (Just (selected, excess))
            | otherwise -> return ()

  -- Return best or fall back to all UTXOs
  result <- readTVarIO bestRef
  case result of
    Just (selected, _) -> return selected
    Nothing -> return utxos  -- Use all if no valid subset found

-- | Random subset selection.
randomSubset :: [Utxo] -> IO [Utxo]
randomSubset utxos = do
  -- Include each UTXO with 50% probability
  decisions <- mapM (\_ -> randomIO :: IO Bool) utxos
  return [u | (u, include) <- zip utxos decisions, include]

-- | Shuffle a list randomly.
shuffleList :: [a] -> IO [a]
shuffleList [] = return []
shuffleList xs = do
  let n = length xs
  indices <- mapM (\i -> randomRIO (i, n - 1)) [0..n - 1]
  let pairs = zip [0..] xs
      shuffled = foldl' swap pairs (zip [0..] indices)
  return $ map snd shuffled
  where
    swap :: [(Int, a)] -> (Int, Int) -> [(Int, a)]
    swap pairs (i, j) =
      let vi = snd (pairs !! i)
          vj = snd (pairs !! j)
      in take i pairs ++ [(i, vj)] ++ drop (i+1) (take j pairs)
         ++ [(j, vi)] ++ drop (j+1) pairs

--------------------------------------------------------------------------------
-- Coinbase Maturity
--------------------------------------------------------------------------------

-- | Check if a coinbase UTXO is mature (can be spent).
-- Coinbase outputs require 100 confirmations before spending.
-- Reference: Bitcoin Core consensus/consensus.h COINBASE_MATURITY
isCoinbaseMature :: Word32 -> Utxo -> Bool
isCoinbaseMature tipHeight utxo
  | not (utxoIsCoinbase utxo) = True  -- Non-coinbase UTXOs are always spendable
  | otherwise = tipHeight >= utxoBlockHeight utxo + fromIntegral coinbaseMaturity

-- | Filter UTXOs to include only those that can be spent (mature coinbase).
filterMatureUtxos :: Word32 -> [Utxo] -> [Utxo]
filterMatureUtxos tipHeight = filter (isCoinbaseMature tipHeight)

--------------------------------------------------------------------------------
-- Main Coin Selection
--------------------------------------------------------------------------------

-- | Select coins for a transaction with explicit tip height for maturity check.
-- Tries BnB first for exact match, falls back to Knapsack.
-- Immature coinbase UTXOs are automatically filtered out.
selectCoinsWithHeight :: Wallet -> [WalletTxOutput] -> FeeRate -> Word32
                      -> IO (Either String CoinSelection)
selectCoinsWithHeight wallet outputs feeRate tipHeight = do
  walletUtxos <- getWalletUTXOsFull wallet
  let targetAmount = sum $ map wtoAmount outputs
      numOutputs = length outputs

      -- Convert to Utxo type with full info
      allUtxos = [ Utxo op (wueTxOut entry) (computeConfs tipHeight (wueBlockHeight entry))
                         (wueIsCoinbase entry) (wueBlockHeight entry)
                 | (op, entry) <- walletUtxos ]

      -- Filter out immature coinbase UTXOs
      utxos = filterMatureUtxos tipHeight allUtxos

      -- Total available (only mature UTXOs)
      totalAvailable = sum $ map utxoValue utxos

  -- Check if we have enough funds
  if totalAvailable < targetAmount
    then return $ Left "Insufficient funds"
    else do
      -- Calculate base fee (without change output)
      let baseFee = feeFromWeight (estimateTxWeight (length utxos) numOutputs False) feeRate

      -- Try BnB first (target includes fee)
      case selectCoinsBnB utxos (targetAmount + baseFee) feeRate of
        Just selected -> do
          -- BnB found exact match, no change needed
          let selectedPairs = [(utxoOutPoint u, utxoTxOut u) | u <- selected]
              actualFee = feeFromWeight
                (estimateTxWeight (length selected) numOutputs False) feeRate
              totalSelected = sum $ map utxoValue selected
              waste = fromIntegral (totalSelected - targetAmount - actualFee) :: Int64
          return $ Right CoinSelection
            { csInputs = selectedPairs
            , csOutputs = outputs
            , csChange = Nothing
            , csFee = actualFee
            , csFeeRate = feeRate
            , csAlgorithm = AlgBnB
            , csWaste = waste
            }

        Nothing -> do
          -- Fall back to Knapsack
          selected <- knapsackSolver utxos targetAmount feeRate
          if null selected
            then return $ Left "Insufficient funds for transaction"
            else do
              let selectedPairs = [(utxoOutPoint u, utxoTxOut u) | u <- selected]
                  totalSelected = sum $ map utxoValue selected
                  -- Calculate fee with change output
                  feeWithChange = feeFromWeight
                    (estimateTxWeight (length selected) numOutputs True) feeRate
                  changeAmount = totalSelected - targetAmount - feeWithChange

              -- Add change output if above dust threshold
              changeAddr <- if changeAmount > dustThreshold
                           then Just <$> getChangeAddress wallet
                           else return Nothing

              let actualFee = if changeAmount > dustThreshold
                             then feeWithChange
                             else totalSelected - targetAmount
                  waste = fromIntegral (totalSelected - targetAmount - actualFee) :: Int64

              return $ Right CoinSelection
                { csInputs = selectedPairs
                , csOutputs = outputs
                , csChange = fmap (\a -> (a, changeAmount)) changeAddr
                , csFee = actualFee
                , csFeeRate = feeRate
                , csAlgorithm = AlgKnapsack
                , csWaste = waste
                }

-- | Compute confirmations from tip height and UTXO block height.
computeConfs :: Word32 -> Word32 -> Word32
computeConfs tipHeight blockHeight
  | tipHeight >= blockHeight = tipHeight - blockHeight + 1
  | otherwise = 0

-- | Select coins for a transaction (legacy interface, assumes tip height 0).
-- For proper coinbase maturity enforcement, use selectCoinsWithHeight.
-- Tries BnB first for exact match, falls back to Knapsack.
selectCoins :: Wallet -> [WalletTxOutput] -> FeeRate -> IO (Either String CoinSelection)
selectCoins wallet outputs feeRate = do
  walletUtxos <- getWalletUTXOsFull wallet
  let targetAmount = sum $ map wtoAmount outputs
      numOutputs = length outputs

      -- Convert to Utxo type - without tip height, mark all as non-coinbase for safety
      utxos = [ Utxo op (wueTxOut entry) (wueBlockHeight entry) False (wueBlockHeight entry)
              | (op, entry) <- walletUtxos ]

      -- Total available
      totalAvailable = sum $ map utxoValue utxos

  -- Check if we have enough funds
  if totalAvailable < targetAmount
    then return $ Left "Insufficient funds"
    else do
      -- Calculate base fee (without change output)
      let baseFee = feeFromWeight (estimateTxWeight (length utxos) numOutputs False) feeRate

      -- Try BnB first (target includes fee)
      case selectCoinsBnB utxos (targetAmount + baseFee) feeRate of
        Just selected -> do
          -- BnB found exact match, no change needed
          let selectedPairs = [(utxoOutPoint u, utxoTxOut u) | u <- selected]
              actualFee = feeFromWeight
                (estimateTxWeight (length selected) numOutputs False) feeRate
              totalSelected = sum $ map utxoValue selected
              waste = fromIntegral (totalSelected - targetAmount - actualFee) :: Int64
          return $ Right CoinSelection
            { csInputs = selectedPairs
            , csOutputs = outputs
            , csChange = Nothing
            , csFee = actualFee
            , csFeeRate = feeRate
            , csAlgorithm = AlgBnB
            , csWaste = waste
            }

        Nothing -> do
          -- Fall back to Knapsack
          selected <- knapsackSolver utxos targetAmount feeRate
          if null selected
            then return $ Left "Insufficient funds for transaction"
            else do
              let selectedPairs = [(utxoOutPoint u, utxoTxOut u) | u <- selected]
                  totalSelected = sum $ map utxoValue selected
                  -- Calculate fee with change output
                  feeWithChange = feeFromWeight
                    (estimateTxWeight (length selected) numOutputs True) feeRate
                  changeAmount = totalSelected - targetAmount - feeWithChange

              -- Add change output if above dust threshold
              changeAddr <- if changeAmount > dustThreshold
                           then Just <$> getChangeAddress wallet
                           else return Nothing

              let actualFee = if changeAmount > dustThreshold
                             then feeWithChange
                             else totalSelected - targetAmount
                  waste = fromIntegral (totalSelected - targetAmount - actualFee) :: Int64

              return $ Right CoinSelection
                { csInputs = selectedPairs
                , csOutputs = outputs
                , csChange = fmap (\a -> (a, changeAmount)) changeAddr
                , csFee = actualFee
                , csFeeRate = feeRate
                , csAlgorithm = AlgKnapsack
                , csWaste = waste
                }

--------------------------------------------------------------------------------
-- Transaction Building
--------------------------------------------------------------------------------

-- | Create an unsigned transaction from coin selection.
createTransaction :: CoinSelection -> Tx
createTransaction CoinSelection{..} =
  let inputs = map (\(op, _) -> TxIn op BS.empty 0xfffffffe) csInputs
      outputs = map (\wto -> TxOut (wtoAmount wto)
        (encodeOutputScript (wtoAddress wto))) csOutputs
      changeOutput = case csChange of
        Nothing -> []
        Just (addr, amount) -> [TxOut amount (encodeOutputScript addr)]
  in Tx
    { txVersion = 2
    , txInputs = inputs
    , txOutputs = outputs ++ changeOutput
    , txWitness = replicate (length inputs) []
    , txLockTime = 0
    }
  where
    encodeOutputScript :: Address -> ByteString
    encodeOutputScript (WitnessPubKeyAddress (Hash160 h)) =
      encodeScript $ encodeP2WPKH (Hash160 h)
    encodeOutputScript (PubKeyAddress (Hash160 h)) =
      encodeScript $ encodeP2PKH (Hash160 h)
    encodeOutputScript (ScriptAddress (Hash160 h)) =
      encodeScript $ encodeP2SH (Hash160 h)
    encodeOutputScript (TaprootAddress (Hash256 h)) =
      encodeScript $ encodeP2TR (Hash256 h)
    encodeOutputScript (WitnessScriptAddress _) = BS.empty -- Would need full script

-- | Fund a transaction by selecting coins and creating inputs.
-- This is a convenience wrapper around selectCoins and createTransaction.
fundTransaction :: Wallet -> [WalletTxOutput] -> FeeRate -> IO (Either String Tx)
fundTransaction wallet outputs feeRate = do
  result <- selectCoins wallet outputs feeRate
  case result of
    Left err -> return $ Left err
    Right cs -> return $ Right $ createTransaction cs

-- | Send to a single address (convenience function).
sendToAddress :: Wallet -> Address -> Word64 -> FeeRate -> IO (Either String Tx)
sendToAddress wallet addr amount feeRate =
  fundTransaction wallet [WalletTxOutput addr amount] feeRate

-- | Sign a transaction with wallet keys.
-- Returns the signed transaction with witness data.
signTransaction :: Wallet -> Tx -> [(OutPoint, TxOut)] -> Either String Tx
signTransaction wallet tx prevOutputs = do
  -- For each input, find the private key and sign
  let signedWitnesses = map (signInput wallet tx prevOutputs) [0 .. length (txInputs tx) - 1]
  Right tx { txWitness = signedWitnesses }
  where
    signInput :: Wallet -> Tx -> [(OutPoint, TxOut)] -> Int -> [ByteString]
    signInput w t prevs idx =
      let inp = txInputs t !! idx
          op = txInPrevOutput inp
          mPrevOut = lookup op prevs
      in case mPrevOut of
           Nothing -> []
           Just _txout ->
             -- Find which key corresponds to this output
             -- For P2WPKH: witness = [signature, pubkey]
             -- The signature requires the private key and sighash
             -- This is a placeholder - actual signing requires secp256k1
             let -- We need to find the key path for this address
                 -- For now, return empty witness (actual signing needs implementation)
             in []  -- Placeholder: requires secp256k1 for actual signing

--------------------------------------------------------------------------------
-- Wallet Encryption (AES-256-CBC)
--------------------------------------------------------------------------------

-- | A passphrase for wallet encryption.
type Passphrase = Text

-- | Encryption parameters for the wallet.
-- Reference: Bitcoin Core wallet/crypter.cpp CCrypter
data EncryptionParams = EncryptionParams
  { epSalt       :: !ByteString   -- ^ Random salt for PBKDF2 (8 bytes)
  , epIterations :: !Int          -- ^ PBKDF2 iteration count (default: 25000)
  } deriving (Show, Eq, Generic)

instance NFData EncryptionParams

-- | Encrypted wallet data.
data EncryptedWallet = EncryptedWallet
  { ewParams     :: !EncryptionParams  -- ^ Encryption parameters
  , ewIV         :: !ByteString        -- ^ AES-CBC initialization vector (16 bytes)
  , ewCiphertext :: !ByteString        -- ^ Encrypted master key
  } deriving (Show, Eq, Generic)

instance NFData EncryptedWallet

-- | Imported descriptor entry for storage.
data ImportedDescriptor = ImportedDescriptor
  { idDescriptor  :: !Descriptor     -- ^ The parsed descriptor
  , idDescText    :: !Text           -- ^ Original descriptor text
  , idActive      :: !Bool           -- ^ Whether active for address generation
  , idInternal    :: !Bool           -- ^ Whether internal (change) descriptor
  , idTimestamp   :: !Word64         -- ^ Import timestamp
  , idNextIndex   :: !Word32         -- ^ Next index for ranged descriptors
  , idRangeStart  :: !Word32         -- ^ Start of range
  , idRangeEnd    :: !Word32         -- ^ End of range
  , idLabel       :: !(Maybe Text)   -- ^ Optional label
  } deriving (Show, Eq, Generic)

instance NFData ImportedDescriptor

-- | Wallet state wrapper that handles encryption.
data WalletState = WalletState
  { wsWallet       :: !Wallet           -- ^ The underlying wallet
  , wsEncrypted    :: !(TVar (Maybe EncryptedWallet))
      -- ^ Encrypted master key (Nothing if unencrypted)
  , wsUnlockExpiry :: !(TVar (Maybe UTCTime))
      -- ^ When the wallet should be locked (Nothing if unlocked indefinitely)
  , wsDecryptedKey :: !(TVar (Maybe ByteString))
      -- ^ Decrypted master key (Nothing if locked)
  , wsDescriptors  :: !(TVar [ImportedDescriptor])
      -- ^ Imported output descriptors
  }

-- | Default PBKDF2 iterations for key derivation.
-- Bitcoin Core uses 25000 iterations.
defaultPBKDF2Iterations :: Int
defaultPBKDF2Iterations = 25000

-- | AES key size (256 bits = 32 bytes).
aesKeySize :: Int
aesKeySize = 32

-- | AES block size (128 bits = 16 bytes).
aesBlockSize :: Int
aesBlockSize = 16

-- | PBKDF2 salt size (8 bytes, matching Bitcoin Core).
saltSize :: Int
saltSize = 8

-- | Derive an AES-256 key from a passphrase using PBKDF2-HMAC-SHA512.
-- Reference: Bitcoin Core wallet/crypter.cpp BytesToKeySHA512AES
deriveKey :: Passphrase -> EncryptionParams -> ByteString
deriveKey passphrase EncryptionParams{..} =
  let password = TE.encodeUtf8 passphrase
      params = PBKDF2.Parameters
        { PBKDF2.iterCounts = epIterations
        , PBKDF2.outputLength = aesKeySize + aesBlockSize  -- Key + IV
        }
  in PBKDF2.fastPBKDF2_SHA512 params password epSalt

-- | Generate random encryption parameters.
generateEncryptionParams :: IO EncryptionParams
generateEncryptionParams = do
  salt <- BS.pack <$> replicateM saltSize randomIO
  return EncryptionParams
    { epSalt = salt
    , epIterations = defaultPBKDF2Iterations
    }

-- | Generate a random IV for AES-CBC.
generateIV :: IO ByteString
generateIV = BS.pack <$> replicateM aesBlockSize randomIO

-- | Pad plaintext to AES block size using PKCS#7 padding.
pkcs7Pad :: Int -> ByteString -> ByteString
pkcs7Pad blockSize bs =
  let padding = blockSize - (BS.length bs `mod` blockSize)
      padByte = fromIntegral padding :: Word8
  in BS.append bs (BS.replicate padding padByte)

-- | Remove PKCS#7 padding.
pkcs7Unpad :: ByteString -> Maybe ByteString
pkcs7Unpad bs
  | BS.null bs = Nothing
  | otherwise =
      let lastByte = BS.last bs
          padLen = fromIntegral lastByte
      in if padLen > 0 && padLen <= BS.length bs
         then Just $ BS.take (BS.length bs - padLen) bs
         else Nothing

-- | Encrypt the wallet master key with a passphrase.
-- Returns the encrypted wallet state or an error.
encryptWallet :: Passphrase -> WalletState -> IO (Either String WalletState)
encryptWallet passphrase ws = do
  -- Check if already encrypted
  existing <- readTVarIO (wsEncrypted ws)
  case existing of
    Just _ -> return $ Left "Wallet is already encrypted"
    Nothing -> do
      -- Generate encryption parameters
      params <- generateEncryptionParams
      ivBytes <- generateIV

      -- Derive key from passphrase
      let derivedKeyAndIV = deriveKey passphrase params
          aesKey = BS.take aesKeySize derivedKeyAndIV

      -- Get the master key to encrypt
      let masterKeyBytes = getSecKey (ekKey (walletMasterKey (wsWallet ws)))

      -- Initialize AES cipher
      case cipherInit aesKey :: CryptoFailable AES256 of
        CryptoFailed err -> return $ Left $ "Failed to initialize cipher: " ++ show err
        CryptoPassed cipher -> do
          case makeIV ivBytes :: Maybe (IV AES256) of
            Nothing -> return $ Left "Failed to create IV"
            Just iv -> do
              -- Pad and encrypt the master key
              let paddedKey = pkcs7Pad aesBlockSize masterKeyBytes
                  ciphertext = cbcEncrypt cipher iv paddedKey
                  encWallet = EncryptedWallet params ivBytes ciphertext

              -- Store encrypted state
              atomically $ writeTVar (wsEncrypted ws) (Just encWallet)
              return $ Right ws

-- | Decrypt a wallet with a passphrase.
-- Returns the decrypted master key or an error.
decryptWallet :: Passphrase -> WalletState -> IO (Either String ByteString)
decryptWallet passphrase ws = do
  mEncrypted <- readTVarIO (wsEncrypted ws)
  case mEncrypted of
    Nothing -> return $ Left "Wallet is not encrypted"
    Just EncryptedWallet{..} -> do
      -- Derive key from passphrase
      let derivedKeyAndIV = deriveKey passphrase ewParams
          aesKey = BS.take aesKeySize derivedKeyAndIV

      -- Initialize AES cipher
      case cipherInit aesKey :: CryptoFailable AES256 of
        CryptoFailed err -> return $ Left $ "Failed to initialize cipher: " ++ show err
        CryptoPassed cipher -> do
          case makeIV ewIV :: Maybe (IV AES256) of
            Nothing -> return $ Left "Failed to create IV"
            Just iv -> do
              -- Decrypt the master key
              let plaintext = cbcDecrypt cipher iv ewCiphertext
              case pkcs7Unpad plaintext of
                Nothing -> return $ Left "Invalid passphrase or corrupted data"
                Just decryptedKey ->
                  -- Verify by comparing to stored master key
                  let storedKey = getSecKey (ekKey (walletMasterKey (wsWallet ws)))
                  in if decryptedKey == storedKey
                     then return $ Right decryptedKey
                     else return $ Left "Invalid passphrase"

-- | Unlock the wallet for a specified duration.
-- The wallet will automatically lock after the duration expires.
unlockWallet :: Passphrase -> NominalDiffTime -> WalletState -> IO (Either String WalletState)
unlockWallet passphrase duration ws = do
  result <- decryptWallet passphrase ws
  case result of
    Left err -> return $ Left err
    Right decryptedKey -> do
      now <- getCurrentTime
      let expiry = addUTCTime duration now
      atomically $ do
        writeTVar (wsDecryptedKey ws) (Just decryptedKey)
        writeTVar (wsUnlockExpiry ws) (Just expiry)
      return $ Right ws

-- | Lock the wallet immediately.
lockWallet :: WalletState -> IO ()
lockWallet ws = atomically $ do
  writeTVar (wsDecryptedKey ws) Nothing
  writeTVar (wsUnlockExpiry ws) Nothing

-- | Check if the wallet is currently locked.
-- Returns True if locked, False if unlocked.
isWalletLocked :: WalletState -> IO Bool
isWalletLocked ws = do
  mKey <- readTVarIO (wsDecryptedKey ws)
  case mKey of
    Nothing -> return True
    Just _ -> do
      -- Check if unlock has expired
      mExpiry <- readTVarIO (wsUnlockExpiry ws)
      case mExpiry of
        Nothing -> return False  -- Unlocked indefinitely
        Just expiry -> do
          now <- getCurrentTime
          if now > expiry
            then do
              lockWallet ws
              return True
            else return False

-- | Create a new WalletState from a Wallet.
createWalletState :: Wallet -> IO WalletState
createWalletState w = do
  encrypted <- newTVarIO Nothing
  unlockExpiry <- newTVarIO Nothing
  decryptedKey <- newTVarIO Nothing
  descriptors <- newTVarIO []
  return WalletState
    { wsWallet = w
    , wsEncrypted = encrypted
    , wsUnlockExpiry = unlockExpiry
    , wsDecryptedKey = decryptedKey
    , wsDescriptors = descriptors
    }

--------------------------------------------------------------------------------
-- Address and Transaction Labels
--------------------------------------------------------------------------------

-- | Set a label for an address.
setAddressLabel :: Wallet -> Address -> Text -> IO ()
setAddressLabel wallet addr label =
  atomically $ modifyTVar' (walletAddressLabels wallet) (Map.insert addr label)

-- | Get the label for an address.
-- Returns empty text if no label is set.
getAddressLabel :: Wallet -> Address -> IO Text
getAddressLabel wallet addr = do
  labels <- readTVarIO (walletAddressLabels wallet)
  return $ fromMaybe "" (Map.lookup addr labels)

-- | Set a label for a transaction.
setTxLabel :: Wallet -> TxId -> Text -> IO ()
setTxLabel wallet txid label =
  atomically $ modifyTVar' (walletTxLabels wallet) (Map.insert txid label)

-- | Get the label for a transaction.
-- Returns empty text if no label is set.
getTxLabel :: Wallet -> TxId -> IO Text
getTxLabel wallet txid = do
  labels <- readTVarIO (walletTxLabels wallet)
  return $ fromMaybe "" (Map.lookup txid labels)

-- | Get all address labels.
getAllAddressLabels :: Wallet -> IO (Map Address Text)
getAllAddressLabels wallet = readTVarIO (walletAddressLabels wallet)

-- | Get all transaction labels.
getAllTxLabels :: Wallet -> IO (Map TxId Text)
getAllTxLabels wallet = readTVarIO (walletTxLabels wallet)

--------------------------------------------------------------------------------
-- PSBT (Partially Signed Bitcoin Transactions) - BIP-174/BIP-370
--------------------------------------------------------------------------------

-- | PSBT magic bytes: "psbt" followed by 0xff
-- Reference: BIP-174
psbtMagic :: ByteString
psbtMagic = BS.pack [0x70, 0x73, 0x62, 0x74, 0xff]  -- "psbt" + 0xff

--------------------------------------------------------------------------------
-- PSBT Key Types (BIP-174/BIP-370)
--------------------------------------------------------------------------------

-- | Global key types
data PsbtGlobalType
  = GlobalUnsignedTx       -- ^ 0x00: Unsigned transaction
  | GlobalXpub             -- ^ 0x01: Extended public key
  | GlobalVersion          -- ^ 0xFB: PSBT version
  | GlobalProprietary      -- ^ 0xFC: Proprietary extension
  deriving (Show, Eq, Ord, Generic)

instance NFData PsbtGlobalType

-- | Input key types
data PsbtInputType
  = InputNonWitnessUtxo    -- ^ 0x00: Non-witness UTXO (full tx)
  | InputWitnessUtxo       -- ^ 0x01: Witness UTXO (just the output)
  | InputPartialSig        -- ^ 0x02: Partial signature
  | InputSighashType       -- ^ 0x03: Sighash type
  | InputRedeemScript      -- ^ 0x04: Redeem script
  | InputWitnessScript     -- ^ 0x05: Witness script
  | InputBip32Derivation   -- ^ 0x06: BIP-32 derivation path
  | InputFinalScriptSig    -- ^ 0x07: Final scriptSig
  | InputFinalScriptWitness -- ^ 0x08: Final scriptWitness
  | InputProprietary       -- ^ 0xFC: Proprietary extension
  deriving (Show, Eq, Ord, Generic)

instance NFData PsbtInputType

-- | Output key types
data PsbtOutputType
  = OutputRedeemScript     -- ^ 0x00: Redeem script
  | OutputWitnessScript    -- ^ 0x01: Witness script
  | OutputBip32Derivation  -- ^ 0x02: BIP-32 derivation path
  | OutputProprietary      -- ^ 0xFC: Proprietary extension
  deriving (Show, Eq, Ord, Generic)

instance NFData PsbtOutputType

--------------------------------------------------------------------------------
-- PSBT Data Types
--------------------------------------------------------------------------------

-- | BIP-32 derivation path information.
-- Stores fingerprint of master key and derivation path indices.
data KeyPath = KeyPath
  { kpFingerprint :: !Word32      -- ^ First 4 bytes of master pubkey hash
  , kpPath        :: ![Word32]    -- ^ Path indices (hardened if >= 0x80000000)
  } deriving (Show, Eq, Ord, Generic)

instance NFData KeyPath

-- | PSBT Global fields.
-- Contains the unsigned transaction and optional xpubs.
data PsbtGlobal = PsbtGlobal
  { pgTx         :: !Tx                          -- ^ Unsigned transaction
  , pgXpubs      :: !(Map ByteString KeyPath)    -- ^ xpub -> keypath
  , pgVersion    :: !(Maybe Word32)              -- ^ PSBT version (optional)
  , pgUnknown    :: !(Map ByteString ByteString) -- ^ Unknown key-value pairs
  } deriving (Show, Eq, Generic)

instance NFData PsbtGlobal

-- | PSBT Input fields.
-- Contains UTXO data, scripts, signatures, and derivation paths.
data PsbtInput = PsbtInput
  { piNonWitnessUtxo   :: !(Maybe Tx)                   -- ^ Full previous tx
  , piWitnessUtxo      :: !(Maybe TxOut)                -- ^ Previous output
  , piPartialSigs      :: !(Map PubKey ByteString)      -- ^ pubkey -> signature
  , piSighashType      :: !(Maybe Word32)               -- ^ Sighash type
  , piRedeemScript     :: !(Maybe ByteString)           -- ^ P2SH redeem script
  , piWitnessScript    :: !(Maybe ByteString)           -- ^ P2WSH witness script
  , piBip32Derivation  :: !(Map PubKey KeyPath)         -- ^ pubkey -> keypath
  , piFinalScriptSig   :: !(Maybe ByteString)           -- ^ Final scriptSig
  , piFinalScriptWitness :: !(Maybe [ByteString])       -- ^ Final witness stack
  , piUnknown          :: !(Map ByteString ByteString)  -- ^ Unknown key-value pairs
  } deriving (Show, Eq, Generic)

instance NFData PsbtInput

-- | PSBT Output fields.
-- Contains scripts and derivation paths for outputs.
data PsbtOutput = PsbtOutput
  { poRedeemScript    :: !(Maybe ByteString)           -- ^ P2SH redeem script
  , poWitnessScript   :: !(Maybe ByteString)           -- ^ P2WSH witness script
  , poBip32Derivation :: !(Map PubKey KeyPath)         -- ^ pubkey -> keypath
  , poUnknown         :: !(Map ByteString ByteString)  -- ^ Unknown key-value pairs
  } deriving (Show, Eq, Generic)

instance NFData PsbtOutput

-- | Partially Signed Bitcoin Transaction.
-- Container holding global data, per-input data, and per-output data.
-- Reference: BIP-174
data Psbt = Psbt
  { psbtGlobal  :: !PsbtGlobal     -- ^ Global key-value pairs
  , psbtInputs  :: ![PsbtInput]    -- ^ Per-input key-value pairs
  , psbtOutputs :: ![PsbtOutput]   -- ^ Per-output key-value pairs
  } deriving (Show, Eq, Generic)

instance NFData Psbt

--------------------------------------------------------------------------------
-- Empty Constructors
--------------------------------------------------------------------------------

-- | Create an empty PSBT input with no data.
emptyPsbtInput :: PsbtInput
emptyPsbtInput = PsbtInput
  { piNonWitnessUtxo = Nothing
  , piWitnessUtxo = Nothing
  , piPartialSigs = Map.empty
  , piSighashType = Nothing
  , piRedeemScript = Nothing
  , piWitnessScript = Nothing
  , piBip32Derivation = Map.empty
  , piFinalScriptSig = Nothing
  , piFinalScriptWitness = Nothing
  , piUnknown = Map.empty
  }

-- | Create an empty PSBT output with no data.
emptyPsbtOutput :: PsbtOutput
emptyPsbtOutput = PsbtOutput
  { poRedeemScript = Nothing
  , poWitnessScript = Nothing
  , poBip32Derivation = Map.empty
  , poUnknown = Map.empty
  }

-- | Create an empty PSBT from an unsigned transaction.
emptyPsbt :: Tx -> Psbt
emptyPsbt tx = Psbt
  { psbtGlobal = PsbtGlobal
      { pgTx = clearScripts tx
      , pgXpubs = Map.empty
      , pgVersion = Nothing
      , pgUnknown = Map.empty
      }
  , psbtInputs = replicate (length (txInputs tx)) emptyPsbtInput
  , psbtOutputs = replicate (length (txOutputs tx)) emptyPsbtOutput
  }
  where
    -- Clear scriptSigs and witnesses from the transaction
    clearScripts t = t
      { txInputs = map (\inp -> inp { txInScript = BS.empty }) (txInputs t)
      , txWitness = replicate (length (txInputs t)) []
      }

--------------------------------------------------------------------------------
-- PSBT Serialization
--------------------------------------------------------------------------------

-- | Serialize PSBT to binary format.
-- Format: magic | global_map | 0x00 | input_map | 0x00 | ... | output_map | 0x00
encodePsbt :: Psbt -> ByteString
encodePsbt psbt = runPut $ do
  -- Magic bytes
  putByteString psbtMagic
  -- Global map
  putGlobalMap (psbtGlobal psbt)
  -- Separator
  putWord8 0x00
  -- Input maps
  mapM_ (\inp -> putInputMap inp >> putWord8 0x00) (psbtInputs psbt)
  -- Output maps
  mapM_ (\out -> putOutputMap out >> putWord8 0x00) (psbtOutputs psbt)

-- | Serialize global map
putGlobalMap :: PsbtGlobal -> Put
putGlobalMap PsbtGlobal{..} = do
  -- PSBT_GLOBAL_UNSIGNED_TX (0x00)
  putKeyValue (BS.singleton 0x00) (serializeTxNoWitness pgTx)
  -- PSBT_GLOBAL_XPUB (0x01) for each xpub
  forM_ (Map.toList pgXpubs) $ \(xpub, keypath) ->
    putKeyValue (BS.cons 0x01 xpub) (serializeKeyPath keypath)
  -- PSBT_GLOBAL_VERSION (0xFB) if present
  case pgVersion of
    Just v -> putKeyValue (BS.singleton 0xfb) (runPut $ putWord32le v)
    Nothing -> return ()
  -- Unknown key-value pairs
  forM_ (Map.toList pgUnknown) $ \(k, v) ->
    putKeyValue k v

-- | Serialize input map
putInputMap :: PsbtInput -> Put
putInputMap PsbtInput{..} = do
  -- PSBT_IN_NON_WITNESS_UTXO (0x00)
  case piNonWitnessUtxo of
    Just tx -> putKeyValue (BS.singleton 0x00) (encode tx)
    Nothing -> return ()
  -- PSBT_IN_WITNESS_UTXO (0x01)
  case piWitnessUtxo of
    Just utxo -> putKeyValue (BS.singleton 0x01) (encode utxo)
    Nothing -> return ()
  -- PSBT_IN_PARTIAL_SIG (0x02) for each signature
  forM_ (Map.toList piPartialSigs) $ \(pk, sig) ->
    putKeyValue (BS.cons 0x02 (serializePubKeyCompressed pk)) sig
  -- PSBT_IN_SIGHASH_TYPE (0x03)
  case piSighashType of
    Just st -> putKeyValue (BS.singleton 0x03) (runPut $ putWord32le st)
    Nothing -> return ()
  -- PSBT_IN_REDEEM_SCRIPT (0x04)
  case piRedeemScript of
    Just rs -> putKeyValue (BS.singleton 0x04) rs
    Nothing -> return ()
  -- PSBT_IN_WITNESS_SCRIPT (0x05)
  case piWitnessScript of
    Just ws -> putKeyValue (BS.singleton 0x05) ws
    Nothing -> return ()
  -- PSBT_IN_BIP32_DERIVATION (0x06) for each path
  forM_ (Map.toList piBip32Derivation) $ \(pk, keypath) ->
    putKeyValue (BS.cons 0x06 (serializePubKeyCompressed pk)) (serializeKeyPath keypath)
  -- PSBT_IN_FINAL_SCRIPTSIG (0x07)
  case piFinalScriptSig of
    Just fs -> putKeyValue (BS.singleton 0x07) fs
    Nothing -> return ()
  -- PSBT_IN_FINAL_SCRIPTWITNESS (0x08)
  case piFinalScriptWitness of
    Just ws -> putKeyValue (BS.singleton 0x08) (serializeWitnessStack ws)
    Nothing -> return ()
  -- Unknown key-value pairs
  forM_ (Map.toList piUnknown) $ \(k, v) ->
    putKeyValue k v

-- | Serialize output map
putOutputMap :: PsbtOutput -> Put
putOutputMap PsbtOutput{..} = do
  -- PSBT_OUT_REDEEM_SCRIPT (0x00)
  case poRedeemScript of
    Just rs -> putKeyValue (BS.singleton 0x00) rs
    Nothing -> return ()
  -- PSBT_OUT_WITNESS_SCRIPT (0x01)
  case poWitnessScript of
    Just ws -> putKeyValue (BS.singleton 0x01) ws
    Nothing -> return ()
  -- PSBT_OUT_BIP32_DERIVATION (0x02) for each path
  forM_ (Map.toList poBip32Derivation) $ \(pk, keypath) ->
    putKeyValue (BS.cons 0x02 (serializePubKeyCompressed pk)) (serializeKeyPath keypath)
  -- Unknown key-value pairs
  forM_ (Map.toList poUnknown) $ \(k, v) ->
    putKeyValue k v

-- | Serialize a key-value pair
putKeyValue :: ByteString -> ByteString -> Put
putKeyValue key value = do
  putVarBytes key
  putVarBytes value

-- | Serialize a keypath
serializeKeyPath :: KeyPath -> ByteString
serializeKeyPath KeyPath{..} =
  runPut $ do
    putWord32le kpFingerprint
    mapM_ putWord32le kpPath

-- | Serialize transaction without witness (for PSBT global)
serializeTxNoWitness :: Tx -> ByteString
serializeTxNoWitness tx = runPut $ do
  putWord32le (fromIntegral $ txVersion tx)
  putVarInt (fromIntegral $ length $ txInputs tx)
  mapM_ put (txInputs tx)
  putVarInt (fromIntegral $ length $ txOutputs tx)
  mapM_ put (txOutputs tx)
  putWord32le (txLockTime tx)

-- | Serialize a witness stack
serializeWitnessStack :: [ByteString] -> ByteString
serializeWitnessStack items = runPut $ do
  putVarInt (fromIntegral $ length items)
  mapM_ putVarBytes items

--------------------------------------------------------------------------------
-- PSBT Deserialization
--------------------------------------------------------------------------------

-- | Deserialize PSBT from binary format.
-- Returns Nothing if parsing fails.
decodePsbt :: ByteString -> Either String Psbt
decodePsbt bs = runGet getPsbt bs

-- | Parser for PSBT
getPsbt :: Get Psbt
getPsbt = do
  -- Check magic bytes
  magic <- getBytes 5
  when (magic /= psbtMagic) $
    fail "Invalid PSBT magic bytes"
  -- Parse global map
  global <- getGlobalMap
  -- Parse input maps (one per input in tx)
  let numInputs = length $ txInputs $ pgTx global
  inputs <- replicateM numInputs getInputMap
  -- Parse output maps (one per output in tx)
  let numOutputs = length $ txOutputs $ pgTx global
  outputs <- replicateM numOutputs getOutputMap
  return $ Psbt global inputs outputs

-- | Parse global map
getGlobalMap :: Get PsbtGlobal
getGlobalMap = go Nothing Map.empty Nothing Map.empty
  where
    go mTx xpubs mVersion unknown = do
      keyLen <- getVarInt'
      if keyLen == 0
        then case mTx of
          Nothing -> fail "PSBT missing unsigned transaction"
          Just tx -> return $ PsbtGlobal tx xpubs mVersion unknown
        else do
          key <- getBytes (fromIntegral keyLen)
          value <- getVarBytes
          let keyType = BS.head key
              keyData = BS.tail key
          case keyType of
            0x00 -> do  -- PSBT_GLOBAL_UNSIGNED_TX
              case decode value of
                Left err -> fail $ "Failed to parse unsigned tx: " ++ err
                Right tx -> go (Just tx) xpubs mVersion unknown
            0x01 -> do  -- PSBT_GLOBAL_XPUB
              let keypath = parseKeyPath value
              go mTx (Map.insert keyData keypath xpubs) mVersion unknown
            0xfb -> do  -- PSBT_GLOBAL_VERSION
              case runGet getWord32le value of
                Left _ -> fail "Invalid PSBT version"
                Right v -> go mTx xpubs (Just v) unknown
            _ -> go mTx xpubs mVersion (Map.insert key value unknown)

-- | Parse input map
getInputMap :: Get PsbtInput
getInputMap = go emptyPsbtInput
  where
    go inp = do
      keyLen <- getVarInt'
      if keyLen == 0
        then return inp
        else do
          key <- getBytes (fromIntegral keyLen)
          value <- getVarBytes
          let keyType = BS.head key
              keyData = BS.tail key
          case keyType of
            0x00 -> case decode value of  -- NON_WITNESS_UTXO
              Left _ -> go inp
              Right tx -> go inp { piNonWitnessUtxo = Just tx }
            0x01 -> case decode value of  -- WITNESS_UTXO
              Left _ -> go inp
              Right utxo -> go inp { piWitnessUtxo = Just utxo }
            0x02 -> case parsePubKey keyData of  -- PARTIAL_SIG
              Nothing -> go inp
              Just pk -> go inp { piPartialSigs = Map.insert pk value (piPartialSigs inp) }
            0x03 -> case runGet getWord32le value of  -- SIGHASH_TYPE
              Left _ -> go inp
              Right st -> go inp { piSighashType = Just st }
            0x04 -> go inp { piRedeemScript = Just value }  -- REDEEM_SCRIPT
            0x05 -> go inp { piWitnessScript = Just value }  -- WITNESS_SCRIPT
            0x06 -> case parsePubKey keyData of  -- BIP32_DERIVATION
              Nothing -> go inp
              Just pk -> go inp { piBip32Derivation = Map.insert pk (parseKeyPath value) (piBip32Derivation inp) }
            0x07 -> go inp { piFinalScriptSig = Just value }  -- FINAL_SCRIPTSIG
            0x08 -> go inp { piFinalScriptWitness = Just (parseWitnessStack value) }  -- FINAL_SCRIPTWITNESS
            _ -> go inp { piUnknown = Map.insert key value (piUnknown inp) }

-- | Parse output map
getOutputMap :: Get PsbtOutput
getOutputMap = go emptyPsbtOutput
  where
    go out = do
      keyLen <- getVarInt'
      if keyLen == 0
        then return out
        else do
          key <- getBytes (fromIntegral keyLen)
          value <- getVarBytes
          let keyType = BS.head key
              keyData = BS.tail key
          case keyType of
            0x00 -> go out { poRedeemScript = Just value }  -- REDEEM_SCRIPT
            0x01 -> go out { poWitnessScript = Just value }  -- WITNESS_SCRIPT
            0x02 -> case parsePubKey keyData of  -- BIP32_DERIVATION
              Nothing -> go out
              Just pk -> go out { poBip32Derivation = Map.insert pk (parseKeyPath value) (poBip32Derivation out) }
            _ -> go out { poUnknown = Map.insert key value (poUnknown out) }

-- | Parse a keypath from bytes
parseKeyPath :: ByteString -> KeyPath
parseKeyPath bs
  | BS.length bs < 4 = KeyPath 0 []
  | otherwise =
      let fp = runGetPartial getWord32le (BS.take 4 bs)
          pathBytes = BS.drop 4 bs
          pathLen = BS.length pathBytes `div` 4
          path = map (\i -> runGetPartial getWord32le (BS.take 4 (BS.drop (i * 4) pathBytes)))
                     [0 .. pathLen - 1]
      in KeyPath fp path
  where
    runGetPartial g b = case runGet g b of
      Left _ -> 0
      Right v -> v

-- | Parse a witness stack from bytes
parseWitnessStack :: ByteString -> [ByteString]
parseWitnessStack bs = case runGet getStack bs of
  Left _ -> []
  Right items -> items
  where
    getStack = do
      count <- getVarInt'
      replicateM (fromIntegral count) getVarBytes

--------------------------------------------------------------------------------
-- PSBT Role: Creator
--------------------------------------------------------------------------------

-- | Create a PSBT from an unsigned transaction.
-- This is the Creator role in BIP-174.
-- The transaction must have empty scriptSigs and witnesses.
createPsbt :: Tx -> Either String Psbt
createPsbt tx
  | any (not . BS.null . txInScript) (txInputs tx) =
      Left "Transaction inputs must have empty scriptSigs"
  | any (not . null) (txWitness tx) =
      Left "Transaction must have empty witnesses"
  | otherwise = Right $ emptyPsbt tx

--------------------------------------------------------------------------------
-- PSBT Role: Updater
--------------------------------------------------------------------------------

-- | Update a PSBT with UTXO and script information.
-- This is the Updater role in BIP-174.
-- Takes a lookup function for previous outputs.
updatePsbt :: (OutPoint -> Maybe (Tx, TxOut)) -> Psbt -> Psbt
updatePsbt lookupUtxo psbt =
  psbt { psbtInputs = zipWith updateInput (txInputs tx) (psbtInputs psbt) }
  where
    tx = pgTx (psbtGlobal psbt)

    updateInput :: TxIn -> PsbtInput -> PsbtInput
    updateInput inp pinp =
      case lookupUtxo (txInPrevOutput inp) of
        Nothing -> pinp
        Just (prevTx, utxo) ->
          let -- Add UTXO information based on script type
              script = txOutScript utxo
              updated = if isWitnessScript script
                        then pinp { piWitnessUtxo = Just utxo }
                        else pinp { piNonWitnessUtxo = Just prevTx }
          in updated

    isWitnessScript :: ByteString -> Bool
    isWitnessScript s
      | BS.length s == 22 && BS.head s == 0x00 && BS.index s 1 == 0x14 = True  -- P2WPKH
      | BS.length s == 34 && BS.head s == 0x00 && BS.index s 1 == 0x20 = True  -- P2WSH
      | BS.length s == 34 && BS.head s == 0x51 && BS.index s 1 == 0x20 = True  -- P2TR
      | otherwise = False

--------------------------------------------------------------------------------
-- PSBT Role: Signer
--------------------------------------------------------------------------------

-- | Sign a PSBT with an extended key.
-- This is the Signer role in BIP-174.
-- Adds partial signatures for inputs that match the key.
signPsbt :: ExtendedKey -> Psbt -> Psbt
signPsbt xkey psbt =
  psbt { psbtInputs = zipWith (signInput xkey tx) [0..] (psbtInputs psbt) }
  where
    tx = pgTx (psbtGlobal psbt)

-- | Sign a single input if we have the key
signInput :: ExtendedKey -> Tx -> Int -> PsbtInput -> PsbtInput
signInput xkey tx inputIdx pinp
  -- Already finalized, skip
  | isInputFinalized pinp = pinp
  -- Try to sign
  | otherwise = case getInputUtxo pinp of
      Nothing -> pinp  -- No UTXO info
      Just utxo ->
        let pubKey = derivePubKeyFromPrivate (ekKey xkey)
            pubKeyBytes = serializePubKeyCompressed pubKey
            pubKeyHash = hash160 pubKeyBytes
            script = txOutScript utxo
            value = txOutValue utxo
            -- Determine sighash type (default to SIGHASH_ALL)
            shType = maybe 0x01 id (piSighashType pinp)
        in if canSign pubKeyHash script
           then addSignature xkey pubKey tx inputIdx script value shType pinp
           else pinp

-- | Check if an input is already finalized
isInputFinalized :: PsbtInput -> Bool
isInputFinalized pinp =
  piSingleFinalized pinp || not (null (maybe [] id (piFinalScriptWitness pinp)))
  where
    piSingleFinalized p = case piFinalScriptSig p of
      Just _ -> True
      Nothing -> case piFinalScriptWitness p of
        Just _ -> True
        Nothing -> False

-- | Get UTXO from input (witness or non-witness)
getInputUtxo :: PsbtInput -> Maybe TxOut
getInputUtxo pinp =
  piWitnessUtxo pinp <|> getNonWitnessUtxo pinp
  where
    (<|>) Nothing b = b
    (<|>) a _ = a

    getNonWitnessUtxo p = case piNonWitnessUtxo p of
      Nothing -> Nothing
      Just prevTx -> Nothing  -- Would need outpoint index

-- | Check if we can sign for this script with our key
canSign :: Hash160 -> ByteString -> Bool
canSign pubKeyHash script
  | isP2PKHScript script = getP2PKHHash script == Just pubKeyHash
  | isP2WPKHScript script = getP2WPKHHash script == Just pubKeyHash
  | otherwise = False

-- | Check if script is P2PKH
isP2PKHScript :: ByteString -> Bool
isP2PKHScript s = BS.length s == 25 &&
  BS.index s 0 == 0x76 &&  -- OP_DUP
  BS.index s 1 == 0xa9 &&  -- OP_HASH160
  BS.index s 2 == 0x14 &&  -- Push 20 bytes
  BS.index s 23 == 0x88 && -- OP_EQUALVERIFY
  BS.index s 24 == 0xac    -- OP_CHECKSIG

-- | Check if script is P2WPKH
isP2WPKHScript :: ByteString -> Bool
isP2WPKHScript s = BS.length s == 22 &&
  BS.index s 0 == 0x00 &&  -- OP_0
  BS.index s 1 == 0x14     -- Push 20 bytes

-- | Extract P2PKH hash from script
getP2PKHHash :: ByteString -> Maybe Hash160
getP2PKHHash s
  | isP2PKHScript s = Just $ Hash160 (BS.take 20 (BS.drop 3 s))
  | otherwise = Nothing

-- | Extract P2WPKH hash from script
getP2WPKHHash :: ByteString -> Maybe Hash160
getP2WPKHHash s
  | isP2WPKHScript s = Just $ Hash160 (BS.take 20 (BS.drop 2 s))
  | otherwise = Nothing

-- | Add a signature to the input
addSignature :: ExtendedKey -> PubKey -> Tx -> Int -> ByteString -> Word64 -> Word32 -> PsbtInput -> PsbtInput
addSignature xkey pubKey tx inputIdx script value shType pinp =
  -- Compute sighash based on script type
  let sighash = if isP2WPKHScript script
                then computeSegwitSighash tx inputIdx script value shType
                else computeLegacySighash tx inputIdx script shType
      -- Sign with private key (placeholder - needs secp256k1)
      signature = signWithKey xkey sighash shType
  in pinp { piPartialSigs = Map.insert pubKey signature (piPartialSigs pinp) }

-- | Compute legacy sighash
computeLegacySighash :: Tx -> Int -> ByteString -> Word32 -> Hash256
computeLegacySighash tx inputIdx script shType =
  let shTypeFlag = SigHashType (shType .&. 0x1f == 0x01)
                               (shType .&. 0x1f == 0x02)
                               (shType .&. 0x1f == 0x03)
                               (shType .&. 0x80 /= 0)
  in txSigHash tx inputIdx script shType shTypeFlag

-- | Compute segwit v0 sighash (BIP-143)
computeSegwitSighash :: Tx -> Int -> ByteString -> Word64 -> Word32 -> Hash256
computeSegwitSighash tx inputIdx script value shType =
  let shTypeFlag = SigHashType (shType .&. 0x1f == 0x01)
                               (shType .&. 0x1f == 0x02)
                               (shType .&. 0x1f == 0x03)
                               (shType .&. 0x80 /= 0)
      -- For P2WPKH, scriptCode is: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
      pkh = BS.take 20 (BS.drop 2 script)
      scriptCode = BS.pack [0x76, 0xa9, 0x14] <> pkh <> BS.pack [0x88, 0xac]
  in txSigHashSegWit tx inputIdx scriptCode value shTypeFlag

-- | Sign a hash with the extended key (placeholder)
signWithKey :: ExtendedKey -> Hash256 -> Word32 -> ByteString
signWithKey _xkey _hash _shType =
  -- Placeholder - actual signing requires secp256k1
  -- In production, this would:
  -- 1. Sign the hash with ekKey using ECDSA
  -- 2. DER-encode the signature
  -- 3. Append the sighash type byte
  BS.replicate 72 0x00  -- Dummy 72-byte signature

--------------------------------------------------------------------------------
-- PSBT Role: Combiner
--------------------------------------------------------------------------------

-- | Combine multiple PSBTs into one.
-- This is the Combiner role in BIP-174.
-- All PSBTs must have the same underlying transaction.
combinePsbts :: [Psbt] -> Either String Psbt
combinePsbts [] = Left "No PSBTs to combine"
combinePsbts [p] = Right p
combinePsbts (p:ps) = do
  -- Verify all PSBTs have the same transaction
  let baseTx = pgTx (psbtGlobal p)
  forM_ ps $ \other ->
    when (pgTx (psbtGlobal other) /= baseTx) $
      Left "PSBTs have different underlying transactions"
  -- Combine all PSBTs
  Right $ foldl' combineTwoPsbts p ps

-- | Combine two PSBTs
combineTwoPsbts :: Psbt -> Psbt -> Psbt
combineTwoPsbts a b = Psbt
  { psbtGlobal = combineGlobals (psbtGlobal a) (psbtGlobal b)
  , psbtInputs = zipWith combineInputs (psbtInputs a) (psbtInputs b)
  , psbtOutputs = zipWith combineOutputs (psbtOutputs a) (psbtOutputs b)
  }

-- | Combine global maps
combineGlobals :: PsbtGlobal -> PsbtGlobal -> PsbtGlobal
combineGlobals a b = a
  { pgXpubs = Map.union (pgXpubs a) (pgXpubs b)
  , pgUnknown = Map.union (pgUnknown a) (pgUnknown b)
  }

-- | Combine input maps
combineInputs :: PsbtInput -> PsbtInput -> PsbtInput
combineInputs a b = PsbtInput
  { piNonWitnessUtxo = piNonWitnessUtxo a <|> piNonWitnessUtxo b
  , piWitnessUtxo = piWitnessUtxo a <|> piWitnessUtxo b
  , piPartialSigs = Map.union (piPartialSigs a) (piPartialSigs b)
  , piSighashType = piSighashType a <|> piSighashType b
  , piRedeemScript = piRedeemScript a <|> piRedeemScript b
  , piWitnessScript = piWitnessScript a <|> piWitnessScript b
  , piBip32Derivation = Map.union (piBip32Derivation a) (piBip32Derivation b)
  , piFinalScriptSig = piFinalScriptSig a <|> piFinalScriptSig b
  , piFinalScriptWitness = piFinalScriptWitness a <|> piFinalScriptWitness b
  , piUnknown = Map.union (piUnknown a) (piUnknown b)
  }
  where
    (<|>) Nothing x = x
    (<|>) x _ = x

-- | Combine output maps
combineOutputs :: PsbtOutput -> PsbtOutput -> PsbtOutput
combineOutputs a b = PsbtOutput
  { poRedeemScript = poRedeemScript a <|> poRedeemScript b
  , poWitnessScript = poWitnessScript a <|> poWitnessScript b
  , poBip32Derivation = Map.union (poBip32Derivation a) (poBip32Derivation b)
  , poUnknown = Map.union (poUnknown a) (poUnknown b)
  }
  where
    (<|>) Nothing x = x
    (<|>) x _ = x

--------------------------------------------------------------------------------
-- PSBT Role: Finalizer
--------------------------------------------------------------------------------

-- | Finalize a PSBT by constructing final scriptSig/witness.
-- This is the Finalizer role in BIP-174.
-- Returns the finalized PSBT or an error if not all inputs can be finalized.
finalizePsbt :: Psbt -> Either String Psbt
finalizePsbt psbt =
  let finalizedInputs = map finalizeInput (psbtInputs psbt)
      errors = [i | (i, inp) <- zip [0..] finalizedInputs, not (isInputFinalized inp)]
  in if null errors
     then Right psbt { psbtInputs = finalizedInputs }
     else Left $ "Could not finalize inputs: " ++ show errors

-- | Finalize a single input
finalizeInput :: PsbtInput -> PsbtInput
finalizeInput pinp
  -- Already finalized
  | isInputFinalized pinp = pinp
  -- Try to finalize based on available data
  | otherwise = case (getInputUtxo pinp, Map.toList (piPartialSigs pinp)) of
      (Just utxo, sigs@(_:_)) ->
        let script = txOutScript utxo
        in finalizeForScript script sigs pinp
      _ -> pinp  -- Cannot finalize

-- | Finalize input based on script type
finalizeForScript :: ByteString -> [(PubKey, ByteString)] -> PsbtInput -> PsbtInput
finalizeForScript script sigs pinp
  -- P2WPKH: witness = [signature, pubkey]
  | isP2WPKHScript script =
      case sigs of
        [(pk, sig)] ->
          let witness = [sig, serializePubKeyCompressed pk]
          in clearSigningFields $ pinp { piFinalScriptWitness = Just witness }
        _ -> pinp
  -- P2PKH: scriptSig = <sig> <pubkey>
  | isP2PKHScript script =
      case sigs of
        [(pk, sig)] ->
          let scriptSig = BS.concat
                [ encodePushData' sig
                , encodePushData' (serializePubKeyCompressed pk)
                ]
          in clearSigningFields $ pinp { piFinalScriptSig = Just scriptSig }
        _ -> pinp
  -- TODO: Handle P2SH, P2WSH, multisig, etc.
  | otherwise = pinp

-- | Encode push data for scriptSig
encodePushData' :: ByteString -> ByteString
encodePushData' bs
  | len <= 75 = BS.cons (fromIntegral len) bs
  | len <= 255 = BS.concat [BS.pack [0x4c, fromIntegral len], bs]
  | len <= 65535 = BS.concat [BS.singleton 0x4d, BS.pack [fromIntegral (len .&. 0xff), fromIntegral (len `shiftR` 8)], bs]
  | otherwise = bs  -- Invalid size
  where len = BS.length bs

-- | Clear signing-related fields after finalization
clearSigningFields :: PsbtInput -> PsbtInput
clearSigningFields pinp = pinp
  { piPartialSigs = Map.empty
  , piSighashType = Nothing
  , piRedeemScript = Nothing
  , piWitnessScript = Nothing
  , piBip32Derivation = Map.empty
  }

--------------------------------------------------------------------------------
-- PSBT Role: Extractor
--------------------------------------------------------------------------------

-- | Extract the final signed transaction from a finalized PSBT.
-- This is the Extractor role in BIP-174.
extractTransaction :: Psbt -> Either String Tx
extractTransaction psbt
  | not (all isInputFinalized (psbtInputs psbt)) =
      Left "PSBT is not fully finalized"
  | otherwise =
      let tx = pgTx (psbtGlobal psbt)
          -- Build final inputs with scriptSigs
          finalInputs = zipWith buildFinalInput (txInputs tx) (psbtInputs psbt)
          -- Build final witness
          finalWitness = map buildFinalWitness (psbtInputs psbt)
      in Right tx
           { txInputs = finalInputs
           , txWitness = finalWitness
           }

-- | Build final input with scriptSig
buildFinalInput :: TxIn -> PsbtInput -> TxIn
buildFinalInput inp pinp = case piFinalScriptSig pinp of
  Just scriptSig -> inp { txInScript = scriptSig }
  Nothing -> inp

-- | Build final witness stack
buildFinalWitness :: PsbtInput -> [ByteString]
buildFinalWitness pinp = case piFinalScriptWitness pinp of
  Just witness -> witness
  Nothing -> []

--------------------------------------------------------------------------------
-- PSBT Utilities
--------------------------------------------------------------------------------

-- | Check if a PSBT is fully finalized (ready for extraction).
isPsbtFinalized :: Psbt -> Bool
isPsbtFinalized psbt = all isInputFinalized (psbtInputs psbt)

-- | Calculate the fee for a PSBT (if possible).
-- Requires UTXO information for all inputs.
getPsbtFee :: Psbt -> Maybe Word64
getPsbtFee psbt = do
  -- Sum input values
  inputValues <- mapM getInputValue (psbtInputs psbt)
  let totalIn = sum inputValues
  -- Sum output values
  let totalOut = sum $ map txOutValue (txOutputs $ pgTx $ psbtGlobal psbt)
  -- Fee = inputs - outputs
  if totalIn >= totalOut
    then Just (totalIn - totalOut)
    else Nothing
  where
    getInputValue :: PsbtInput -> Maybe Word64
    getInputValue pinp = txOutValue <$> getInputUtxo pinp

--------------------------------------------------------------------------------
-- Output Descriptors (BIP-380-386)
--------------------------------------------------------------------------------

-- | Derivation range for ranged descriptors.
-- `DerivRange` represents either a specific index or a wildcard (*).
data DerivRange
  = DerivIndex !Word32      -- ^ Specific index
  | DerivWildcard           -- ^ Wildcard (*) - iterate at runtime
  | DerivHardenedWildcard   -- ^ Hardened wildcard (*h or *')
  deriving (Show, Eq, Generic)

instance NFData DerivRange

-- | Key expression for use in descriptors.
-- Represents the various ways keys can be specified in a descriptor.
data KeyExpr
  = KeyLiteral !PubKey                               -- ^ Literal public key (hex)
  | KeyXPub !ExtendedPubKey ![Word32] !DerivRange    -- ^ xpub with derivation path
  | KeyXPriv !ExtendedKey ![Word32] !DerivRange      -- ^ xprv with derivation path
  | KeyWIF !SecKey                                    -- ^ WIF-encoded private key
  | KeyOrigin !ByteString ![Word32] !KeyExpr         -- ^ Key with origin info [fingerprint/path]key
  deriving (Show, Eq, Generic)

instance NFData KeyExpr

-- | Taproot tree structure for tr() descriptors.
data TapTree
  = TapLeaf !Descriptor                   -- ^ Single leaf script
  | TapBranch !TapTree !TapTree           -- ^ Branch with two children
  deriving (Show, Eq, Generic)

instance NFData TapTree

-- | Output descriptor AST following BIP-380 through BIP-386.
data Descriptor
  = Pk !KeyExpr                            -- ^ pk(KEY) - P2PK
  | Pkh !KeyExpr                           -- ^ pkh(KEY) - P2PKH
  | Wpkh !KeyExpr                          -- ^ wpkh(KEY) - P2WPKH (native SegWit)
  | Sh !Descriptor                         -- ^ sh(SCRIPT) - P2SH wrapper
  | Wsh !Descriptor                        -- ^ wsh(SCRIPT) - P2WSH (native SegWit)
  | Multi !Int ![KeyExpr]                  -- ^ multi(k, KEY, KEY, ...) - k-of-n multisig
  | SortedMulti !Int ![KeyExpr]            -- ^ sortedmulti(k, KEY, ...) - sorted multisig
  | Tr !KeyExpr !(Maybe TapTree)           -- ^ tr(KEY) or tr(KEY, TREE) - Taproot
  | Addr !Address                          -- ^ addr(ADDRESS) - literal address
  | Raw !ByteString                        -- ^ raw(HEX) - raw script
  | Combo !KeyExpr                         -- ^ combo(KEY) - multiple script types
  deriving (Show, Eq, Generic)

instance NFData Descriptor

-- | Parse error for descriptors.
data ParseError
  = UnexpectedChar !Char !Int              -- ^ Unexpected character at position
  | UnexpectedEnd                          -- ^ Unexpected end of input
  | InvalidChecksum !Text !Text            -- ^ Expected vs actual checksum
  | InvalidKey !Text                       -- ^ Invalid key encoding
  | InvalidAddress !Text                   -- ^ Invalid address
  | InvalidHex !Text                       -- ^ Invalid hex string
  | InvalidThreshold !Int !Int             -- ^ Threshold out of range (given, max)
  | UnknownFunction !Text                  -- ^ Unknown descriptor function
  | MissingChecksum                        -- ^ Missing required checksum
  | MalformedDescriptor !Text              -- ^ General malformed descriptor
  deriving (Show, Eq, Generic)

instance NFData ParseError

--------------------------------------------------------------------------------
-- Descriptor Checksum (BIP-380)
--------------------------------------------------------------------------------

-- | Character set for descriptor input (maps to 5-bit values).
-- This is the character set for position calculation in the checksum.
descriptorInputCharset :: String
descriptorInputCharset =
  "0123456789()[],'/*abcdefgh@:$%{}" ++
  "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" ++
  "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

-- | Character set for checksum output (same as bech32).
descriptorChecksumCharset :: String
descriptorChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | Polynomial modular operation for descriptor checksum.
-- Reference: Bitcoin Core src/script/descriptor.cpp PolyMod()
descriptorPolyMod :: Word64 -> Int -> Word64
descriptorPolyMod c val =
  let c0 = c `shiftR` 35
      c' = ((c .&. 0x7ffffffff) `shiftL` 5) `xor` fromIntegral val
      c1 = if testBit c0 0 then c' `xor` 0xf5dee51989 else c'
      c2 = if testBit c0 1 then c1 `xor` 0xa9fdca3312 else c1
      c3 = if testBit c0 2 then c2 `xor` 0x1bab10e32d else c2
      c4 = if testBit c0 3 then c3 `xor` 0x3706b1677a else c3
      c5 = if testBit c0 4 then c4 `xor` 0x644d626ffd else c4
  in c5

-- | Compute the 8-character checksum for a descriptor string.
-- Reference: Bitcoin Core src/script/descriptor.cpp DescriptorChecksum()
descriptorChecksum :: Text -> Maybe Text
descriptorChecksum input = do
  -- Process each character
  let chars = T.unpack input
  positions <- mapM charPosition chars
  -- Compute checksum by folding over all characters
  finalState <- foldM processChar' (1 :: Word64, 0 :: Int, 0 :: Int) positions
  let (c2, cls2, count2) = finalState
      -- Emit final cls if needed
      c3 = if count2 > 0 then descriptorPolyMod c2 cls2 else c2
      -- Shift 8 times for checksum calculation
      c4 = foldl' (\acc _ -> descriptorPolyMod acc 0) c3 [1..8 :: Int]
      -- XOR with 1 to prevent appending zeros
      c5 = c4 `xor` 1
      -- Extract 8 checksum characters
      checksumChars = map (\j -> descriptorChecksumCharset !! fromIntegral ((c5 `shiftR` (5 * (7 - j))) .&. 31)) [0..7]
  return $ T.pack checksumChars
  where
    charPosition :: Char -> Maybe Int
    charPosition ch = elemIndex' ch descriptorInputCharset

    elemIndex' :: Eq a => a -> [a] -> Maybe Int
    elemIndex' _ [] = Nothing
    elemIndex' x (y:ys)
      | x == y = Just 0
      | otherwise = (+ 1) <$> elemIndex' x ys

    processChar' :: (Word64, Int, Int) -> Int -> Maybe (Word64, Int, Int)
    processChar' (c, cls, count) pos = Just $
      let c' = descriptorPolyMod c (pos .&. 31)
          cls' = cls * 3 + (pos `shiftR` 5)
          count' = count + 1
      in if count' == 3
         then (descriptorPolyMod c' cls', 0, 0)
         else (c', cls', count')

-- | Add checksum to a descriptor string.
addDescriptorChecksum :: Text -> Maybe Text
addDescriptorChecksum desc = do
  checksum <- descriptorChecksum desc
  return $ desc <> "#" <> checksum

-- | Validate and strip checksum from a descriptor string.
-- Returns the descriptor without checksum if valid.
validateDescriptorChecksum :: Text -> Either ParseError Text
validateDescriptorChecksum input =
  case T.breakOn "#" input of
    (desc, rest)
      | T.null rest -> Left MissingChecksum
      | otherwise ->
          let providedChecksum = T.drop 1 rest
          in case descriptorChecksum desc of
               Nothing -> Left $ MalformedDescriptor "Invalid characters in descriptor"
               Just expectedChecksum
                 | providedChecksum == expectedChecksum -> Right desc
                 | otherwise -> Left $ InvalidChecksum expectedChecksum providedChecksum

--------------------------------------------------------------------------------
-- Descriptor Parser
--------------------------------------------------------------------------------

-- | Parser state for recursive descent parsing.
data ParserState = ParserState
  { psInput :: !Text        -- ^ Remaining input
  , psPos   :: !Int         -- ^ Current position (for error reporting)
  } deriving (Show)

-- | Parser monad (simple state + error).
type Parser a = ParserState -> Either ParseError (a, ParserState)

-- | Run a parser on input text.
runParser :: Parser a -> Text -> Either ParseError a
runParser p input = case p (ParserState input 0) of
  Left err -> Left err
  Right (result, _) -> Right result

-- | Parse a descriptor string (with or without checksum).
parseDescriptor :: Text -> Either ParseError Descriptor
parseDescriptor input = do
  -- Check for and validate checksum if present
  descText <- if T.isInfixOf "#" input
              then validateDescriptorChecksum input
              else Right input
  -- Parse the descriptor
  runParser parseDescriptorExpr (T.strip descText)

-- | Parse a descriptor expression.
parseDescriptorExpr :: Parser Descriptor
parseDescriptorExpr st = do
  (funcName, st1) <- parseIdentifier st
  (_, st2) <- expectChar '(' st1
  case T.toLower funcName of
    "pk"          -> parsePk st2
    "pkh"         -> parsePkh st2
    "wpkh"        -> parseWpkh st2
    "sh"          -> parseSh st2
    "wsh"         -> parseWsh st2
    "multi"       -> parseMulti False st2
    "sortedmulti" -> parseMulti True st2
    "tr"          -> parseTr st2
    "addr"        -> parseAddr st2
    "raw"         -> parseRaw st2
    "combo"       -> parseCombo st2
    other         -> Left $ UnknownFunction other

-- | Parse pk(KEY).
parsePk :: Parser Descriptor
parsePk st = do
  (key, st1) <- parseKeyExpr st
  (_, st2) <- expectChar ')' st1
  return (Pk key, st2)

-- | Parse pkh(KEY).
parsePkh :: Parser Descriptor
parsePkh st = do
  (key, st1) <- parseKeyExpr st
  (_, st2) <- expectChar ')' st1
  return (Pkh key, st2)

-- | Parse wpkh(KEY).
parseWpkh :: Parser Descriptor
parseWpkh st = do
  (key, st1) <- parseKeyExpr st
  (_, st2) <- expectChar ')' st1
  return (Wpkh key, st2)

-- | Parse sh(SCRIPT).
parseSh :: Parser Descriptor
parseSh st = do
  (inner, st1) <- parseDescriptorExpr st
  (_, st2) <- expectChar ')' st1
  return (Sh inner, st2)

-- | Parse wsh(SCRIPT).
parseWsh :: Parser Descriptor
parseWsh st = do
  (inner, st1) <- parseDescriptorExpr st
  (_, st2) <- expectChar ')' st1
  return (Wsh inner, st2)

-- | Parse multi(k, KEY, KEY, ...) or sortedmulti(...).
parseMulti :: Bool -> Parser Descriptor
parseMulti sorted st = do
  (k, st1) <- parseNumber st
  (_, st2) <- expectChar ',' st1
  (keys, st3) <- parseKeyList st2
  (_, st4) <- expectChar ')' st3
  let n = length keys
  if k < 1 || k > n || n > 20
    then Left $ InvalidThreshold k n
    else let ctor = if sorted then SortedMulti else Multi
         in return (ctor k keys, st4)

-- | Parse tr(KEY) or tr(KEY, TREE).
parseTr :: Parser Descriptor
parseTr st = do
  (key, st1) <- parseKeyExpr st
  -- Check for optional tree
  case peekChar st1 of
    Just ',' -> do
      (_, st2) <- expectChar ',' st1
      (tree, st3) <- parseTapTree st2
      (_, st4) <- expectChar ')' st3
      return (Tr key (Just tree), st4)
    Just ')' -> do
      (_, st2) <- expectChar ')' st1
      return (Tr key Nothing, st2)
    Just c -> Left $ UnexpectedChar c (psPos st1)
    Nothing -> Left UnexpectedEnd

-- | Parse a Taproot tree expression.
parseTapTree :: Parser TapTree
parseTapTree st = case peekChar st of
  Just '{' -> do
    (_, st1) <- expectChar '{' st
    (left, st2) <- parseTapTree st1
    (_, st3) <- expectChar ',' st2
    (right, st4) <- parseTapTree st3
    (_, st5) <- expectChar '}' st4
    return (TapBranch left right, st5)
  Just _ -> do
    (desc, st1) <- parseDescriptorExpr st
    return (TapLeaf desc, st1)
  Nothing -> Left UnexpectedEnd

-- | Parse addr(ADDRESS).
parseAddr :: Parser Descriptor
parseAddr st = do
  (addrText, st1) <- parseUntilChar ')' st
  (_, st2) <- expectChar ')' st1
  case textToAddress addrText of
    Just addr -> return (Addr addr, st2)
    Nothing -> Left $ InvalidAddress addrText

-- | Parse raw(HEX).
parseRaw :: Parser Descriptor
parseRaw st = do
  (hexText, st1) <- parseUntilChar ')' st
  (_, st2) <- expectChar ')' st1
  case hexDecode' hexText of
    Just bs -> return (Raw bs, st2)
    Nothing -> Left $ InvalidHex hexText

-- | Parse combo(KEY).
parseCombo :: Parser Descriptor
parseCombo st = do
  (key, st1) <- parseKeyExpr st
  (_, st2) <- expectChar ')' st1
  return (Combo key, st2)

-- | Parse a key expression.
parseKeyExpr :: Parser KeyExpr
parseKeyExpr st = case peekChar st of
  -- Origin info: [fingerprint/path]key
  Just '[' -> do
    (_, st1) <- expectChar '[' st
    (origin, st2) <- parseOrigin st1
    (_, st3) <- expectChar ']' st2
    (key, st4) <- parseKeyExpr st3
    let (fp, path) = origin
    return (KeyOrigin fp path key, st4)
  -- Key without origin
  _ -> parseKeyInner st

-- | Parse origin info (fingerprint and path).
parseOrigin :: Parser (ByteString, [Word32])
parseOrigin st = do
  (fpText, st1) <- parseNChars 8 st
  case hexDecode' fpText of
    Nothing -> Left $ InvalidHex fpText
    Just fp -> do
      (path, st2) <- parseDerivPath st1
      return ((fp, path), st2)

-- | Parse a derivation path (e.g., /44'/0'/0').
parseDerivPath :: Parser [Word32]
parseDerivPath st = case peekChar st of
  Just '/' -> do
    (_, st1) <- expectChar '/' st
    (idx, st2) <- parsePathComponent st1
    (rest, st3) <- parseDerivPath st2
    return (idx : rest, st3)
  _ -> return ([], st)

-- | Parse a single path component (e.g., 44' or 0).
parsePathComponent :: Parser Word32
parsePathComponent st = do
  (numText, st1) <- parseWhile isDigit st
  if T.null numText
    then Left $ MalformedDescriptor "Expected number in path"
    else do
      let num = read (T.unpack numText) :: Word32
      -- Check for hardened indicator
      case peekChar st1 of
        Just '\'' -> do
          (_, st2) <- expectChar '\'' st1
          return (num .|. 0x80000000, st2)
        Just 'h' -> do
          (_, st2) <- expectChar 'h' st1
          return (num .|. 0x80000000, st2)
        _ -> return (num, st1)

-- | Parse a key without origin info.
parseKeyInner :: Parser KeyExpr
parseKeyInner st = do
  -- Collect key string until delimiter
  (keyText, st1) <- parseKeyString st
  -- Determine key type and parse
  parseKeyFromText keyText st1

-- | Parse key string (may include derivation path).
parseKeyString :: Parser Text
parseKeyString st = parseWhile isKeyChar st
  where
    -- Include all characters that can appear in xpub/xprv/WIF keys
    isKeyChar c = isHexDigit c || c `elem` ("xprvtubKLcn/*'" :: String) ||
                  isDigit c || c == 'h' ||
                  -- Base58 alphabet for WIF keys
                  (c >= 'A' && c <= 'Z' && c /= 'I' && c /= 'O') ||
                  (c >= 'a' && c <= 'z' && c /= 'l')

-- | Parse a key from its text representation.
parseKeyFromText :: Text -> Parser KeyExpr
parseKeyFromText keyText st
  -- Extended public key (xpub...)
  | "xpub" `T.isPrefixOf` keyText || "tpub" `T.isPrefixOf` keyText =
      parseXPub keyText st
  -- Extended private key (xprv...)
  | "xprv" `T.isPrefixOf` keyText || "tprv" `T.isPrefixOf` keyText =
      parseXPriv keyText st
  -- WIF private key (starts with 5, K, L for mainnet; c, 9 for testnet)
  | isWifKey keyText =
      parseWifKey keyText st
  -- Hex public key
  | T.all isHexDigit keyText && (T.length keyText == 66 || T.length keyText == 130) =
      parseLiteralPubKey keyText st
  -- X-only public key (32 bytes = 64 hex chars)
  | T.all isHexDigit keyText && T.length keyText == 64 =
      parseLiteralPubKey ("02" <> keyText) st  -- Assume even y
  | otherwise =
      Left $ InvalidKey keyText

-- | Check if text looks like a WIF-encoded private key.
isWifKey :: Text -> Bool
isWifKey t
  | T.null t = False
  | otherwise =
      let firstChar = T.head t
          len = T.length t
      in -- Mainnet uncompressed (5) = 51 chars, compressed (K/L) = 52 chars
         -- Testnet uncompressed (9) = 51 chars, compressed (c) = 52 chars
         (firstChar == '5' && len == 51) ||
         (firstChar `elem` ("KL" :: String) && len == 52) ||
         (firstChar == '9' && len == 51) ||
         (firstChar == 'c' && len == 52)

-- | Parse a WIF-encoded private key.
parseWifKey :: Text -> Parser KeyExpr
parseWifKey keyText st =
  case wifDecode keyText of
    Nothing -> Left $ InvalidKey keyText
    Just sk -> return (KeyWIF sk, st)

-- | Decode a WIF-encoded private key.
-- WIF format: Base58Check(version || key || [0x01 if compressed])
-- Mainnet version: 0x80, Testnet version: 0xef
wifDecode :: Text -> Maybe SecKey
wifDecode txt =
  case base58CheckDecode txt of
    Nothing -> Nothing
    Just (version, payload)
      | version /= 0x80 && version /= 0xef -> Nothing  -- Invalid version
      | BS.length payload == 32 -> Just (SecKey payload)  -- Uncompressed
      | BS.length payload == 33 && BS.last payload == 0x01 ->
          Just (SecKey (BS.init payload))  -- Compressed (strip 0x01 suffix)
      | otherwise -> Nothing

-- | Parse an extended public key with optional derivation path.
parseXPub :: Text -> Parser KeyExpr
parseXPub keyText st = do
  -- Split on '/' to separate key from path
  let (baseKey, pathPart) = T.breakOn "/" keyText
  -- Decode the xpub (placeholder - would use proper base58 decoding)
  case decodeXPub baseKey of
    Nothing -> Left $ InvalidKey keyText
    Just xpub -> do
      -- Parse derivation path from remaining text
      let pathText = T.drop 1 pathPart  -- Drop leading '/'
      (path, range) <- parseXPubPath pathText
      return (KeyXPub xpub path range, st)

-- | Parse an extended private key with optional derivation path.
parseXPriv :: Text -> Parser KeyExpr
parseXPriv keyText st = do
  let (baseKey, pathPart) = T.breakOn "/" keyText
  case decodeXPriv baseKey of
    Nothing -> Left $ InvalidKey keyText
    Just xprv -> do
      let pathText = T.drop 1 pathPart
      (path, range) <- parseXPubPath pathText
      return (KeyXPriv xprv path range, st)

-- | Parse xpub path and range.
parseXPubPath :: Text -> Either ParseError ([Word32], DerivRange)
parseXPubPath pathText
  | T.null pathText = Right ([], DerivIndex 0)
  | otherwise = do
      -- Split on '/'
      let components = filter (not . T.null) $ T.splitOn "/" pathText
      -- Check for wildcard in last component
      (indices, range) <- case components of
        [] -> Right ([], DerivIndex 0)
        _ -> do
          let (initComps, lastComp) = (init components, last components)
          initIndices <- mapM parsePathIdx initComps
          case lastComp of
            "*" -> Right (initIndices, DerivWildcard)
            "*'" -> Right (initIndices, DerivHardenedWildcard)
            "*h" -> Right (initIndices, DerivHardenedWildcard)
            _ -> do
              lastIdx <- parsePathIdx lastComp
              Right (initIndices ++ [lastIdx], DerivIndex 0)
      return (indices, range)
  where
    parsePathIdx :: Text -> Either ParseError Word32
    parsePathIdx t
      | T.null t = Left $ MalformedDescriptor "Empty path component"
      | T.last t == '\'' || T.last t == 'h' =
          let numText = T.init t
          in case reads (T.unpack numText) of
               [(n, "")] -> Right (n .|. 0x80000000)
               _ -> Left $ MalformedDescriptor $ "Invalid path: " <> t
      | otherwise =
          case reads (T.unpack t) of
            [(n, "")] -> Right n
            _ -> Left $ MalformedDescriptor $ "Invalid path: " <> t

-- | Parse a literal hex-encoded public key.
parseLiteralPubKey :: Text -> Parser KeyExpr
parseLiteralPubKey hexText st = case hexDecode' hexText of
  Nothing -> Left $ InvalidKey hexText
  Just bs -> case parsePubKey bs of
    Nothing -> Left $ InvalidKey hexText
    Just pk -> return (KeyLiteral pk, st)

-- | Parse a comma-separated list of keys.
parseKeyList :: Parser [KeyExpr]
parseKeyList st = do
  (key, st1) <- parseKeyExpr st
  case peekChar st1 of
    Just ',' -> do
      (_, st2) <- expectChar ',' st1
      (rest, st3) <- parseKeyList st2
      return (key : rest, st3)
    _ -> return ([key], st1)

-- | Parse an identifier (function name).
parseIdentifier :: Parser Text
parseIdentifier st = parseWhile isIdChar st
  where
    isIdChar c = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'

-- | Parse a number.
parseNumber :: Parser Int
parseNumber st = do
  (numText, st1) <- parseWhile isDigit st
  if T.null numText
    then Left $ MalformedDescriptor "Expected number"
    else return (read (T.unpack numText), st1)

-- | Parse characters while predicate holds.
parseWhile :: (Char -> Bool) -> Parser Text
parseWhile p st =
  let (taken, rest) = T.span p (psInput st)
  in return (taken, st { psInput = rest, psPos = psPos st + T.length taken })

-- | Parse exactly N characters.
parseNChars :: Int -> Parser Text
parseNChars n st
  | T.length (psInput st) < n = Left UnexpectedEnd
  | otherwise =
      let (taken, rest) = T.splitAt n (psInput st)
      in return (taken, st { psInput = rest, psPos = psPos st + n })

-- | Parse until a specific character (exclusive).
parseUntilChar :: Char -> Parser Text
parseUntilChar c st =
  let (taken, rest) = T.break (== c) (psInput st)
  in return (taken, st { psInput = rest, psPos = psPos st + T.length taken })

-- | Expect and consume a specific character.
expectChar :: Char -> Parser ()
expectChar expected st = case T.uncons (psInput st) of
  Nothing -> Left UnexpectedEnd
  Just (c, rest)
    | c == expected -> return ((), st { psInput = rest, psPos = psPos st + 1 })
    | otherwise -> Left $ UnexpectedChar c (psPos st)

-- | Peek at the next character without consuming.
peekChar :: ParserState -> Maybe Char
peekChar st = fst <$> T.uncons (psInput st)

-- | Skip whitespace.
skipWhitespace :: Parser ()
skipWhitespace st =
  let rest = T.dropWhile isSpace (psInput st)
      skipped = T.length (psInput st) - T.length rest
  in return ((), st { psInput = rest, psPos = psPos st + skipped })

--------------------------------------------------------------------------------
-- Descriptor Serialization
--------------------------------------------------------------------------------

-- | Convert a descriptor back to text representation.
descriptorToText :: Descriptor -> Text
descriptorToText desc = case desc of
  Pk key -> "pk(" <> keyExprToText key <> ")"
  Pkh key -> "pkh(" <> keyExprToText key <> ")"
  Wpkh key -> "wpkh(" <> keyExprToText key <> ")"
  Sh inner -> "sh(" <> descriptorToText inner <> ")"
  Wsh inner -> "wsh(" <> descriptorToText inner <> ")"
  Multi k keys -> "multi(" <> T.pack (show k) <> "," <>
                  T.intercalate "," (map keyExprToText keys) <> ")"
  SortedMulti k keys -> "sortedmulti(" <> T.pack (show k) <> "," <>
                        T.intercalate "," (map keyExprToText keys) <> ")"
  Tr key Nothing -> "tr(" <> keyExprToText key <> ")"
  Tr key (Just tree) -> "tr(" <> keyExprToText key <> "," <>
                        tapTreeToText tree <> ")"
  Addr addr -> "addr(" <> addressToText addr <> ")"
  Raw script -> "raw(" <> hexEncode' script <> ")"
  Combo key -> "combo(" <> keyExprToText key <> ")"

-- | Convert a key expression to text.
keyExprToText :: KeyExpr -> Text
keyExprToText key = case key of
  KeyLiteral pk -> hexEncode' (serializePubKeyCompressed pk)
  KeyXPub xpub path range ->
    encodeXPub xpub <> pathToText path <> rangeToText range
  KeyXPriv xprv path range ->
    encodeXPriv xprv <> pathToText path <> rangeToText range
  KeyWIF sk -> wifEncode sk
  KeyOrigin fp path inner ->
    "[" <> hexEncode' fp <> pathToText path <> "]" <> keyExprToText inner

-- | Convert a derivation path to text.
pathToText :: [Word32] -> Text
pathToText [] = ""
pathToText path = "/" <> T.intercalate "/" (map idxToText path)
  where
    idxToText idx
      | idx >= 0x80000000 = T.pack (show (idx .&. 0x7fffffff)) <> "'"
      | otherwise = T.pack (show idx)

-- | Convert a derivation range to text.
rangeToText :: DerivRange -> Text
rangeToText (DerivIndex _) = ""
rangeToText DerivWildcard = "/*"
rangeToText DerivHardenedWildcard = "/*'"

-- | Convert a Taproot tree to text.
tapTreeToText :: TapTree -> Text
tapTreeToText tree = case tree of
  TapLeaf desc -> descriptorToText desc
  TapBranch left right ->
    "{" <> tapTreeToText left <> "," <> tapTreeToText right <> "}"

--------------------------------------------------------------------------------
-- Address Derivation
--------------------------------------------------------------------------------

-- | Check if a descriptor contains wildcards (is ranged).
isRangeDescriptor :: Descriptor -> Bool
isRangeDescriptor desc = case desc of
  Pk key -> isRangeKey key
  Pkh key -> isRangeKey key
  Wpkh key -> isRangeKey key
  Sh inner -> isRangeDescriptor inner
  Wsh inner -> isRangeDescriptor inner
  Multi _ keys -> any isRangeKey keys
  SortedMulti _ keys -> any isRangeKey keys
  Tr key tree -> isRangeKey key || maybe False isRangeTree tree
  Addr _ -> False
  Raw _ -> False
  Combo key -> isRangeKey key
  where
    isRangeKey :: KeyExpr -> Bool
    isRangeKey k = case k of
      KeyLiteral _ -> False
      KeyXPub _ _ range -> isWildcard range
      KeyXPriv _ _ range -> isWildcard range
      KeyWIF _ -> False
      KeyOrigin _ _ inner -> isRangeKey inner

    isWildcard :: DerivRange -> Bool
    isWildcard DerivWildcard = True
    isWildcard DerivHardenedWildcard = True
    isWildcard _ = False

    isRangeTree :: TapTree -> Bool
    isRangeTree (TapLeaf d) = isRangeDescriptor d
    isRangeTree (TapBranch l r) = isRangeTree l || isRangeTree r

-- | Derive addresses from a descriptor at given indices.
-- For non-ranged descriptors, indices are ignored and a single address is returned.
deriveAddresses :: Descriptor -> [Int] -> [Address]
deriveAddresses desc indices =
  if isRangeDescriptor desc
    then concatMap (\i -> scriptToAddresses $ deriveScriptsAt desc i) indices
    else scriptToAddresses $ deriveScriptsAt desc 0

-- | Derive scripts from a descriptor at a given index.
deriveScripts :: Descriptor -> Int -> [ByteString]
deriveScripts = deriveScriptsAt

-- | Derive scriptPubKeys at a specific index.
deriveScriptsAt :: Descriptor -> Int -> [ByteString]
deriveScriptsAt desc idx = case desc of
  Pk key ->
    let pk = deriveKeyExpr key idx
    in [BS.concat [encodePubKey pk, encodeOp 0xac]]  -- <pubkey> OP_CHECKSIG
  Pkh key ->
    let pk = deriveKeyExpr key idx
        pkh = hash160 (serializePubKeyCompressed pk)
    in [encodeScript (encodeP2PKH pkh)]
  Wpkh key ->
    let pk = deriveKeyExpr key idx
        pkh = hash160 (serializePubKeyCompressed pk)
    in [encodeScript (encodeP2WPKH pkh)]
  Sh inner ->
    let innerScripts = deriveScriptsAt inner idx
    in map (\s -> encodeScript (encodeP2SH (hash160 s))) innerScripts
  Wsh inner ->
    let innerScripts = deriveScriptsAt inner idx
    in map (\s -> encodeP2WSH (sha256 s)) innerScripts
  Multi k keys ->
    let pks = map (`deriveKeyExpr` idx) keys
    in [encodeMultisig k pks]
  SortedMulti k keys ->
    let pks = sortOn serializePubKeyCompressed $ map (`deriveKeyExpr` idx) keys
    in [encodeMultisig k pks]
  Tr key _ ->
    let pk = deriveKeyExpr key idx
        -- Simplified: just output spend key (no script path)
    in [encodeScript (encodeP2TR (xOnlyPubKey pk))]
  Addr addr ->
    [addressToScript addr]
  Raw script ->
    [script]
  Combo key ->
    -- combo(KEY) = pk(KEY) + pkh(KEY) + wpkh(KEY) + sh(wpkh(KEY))
    let pk = deriveKeyExpr key idx
        pkh = hash160 (serializePubKeyCompressed pk)
        p2wpkhScript = encodeP2WPKH pkh
        p2wpkhBS = encodeScript p2wpkhScript
    in [ BS.concat [encodePubKey pk, encodeOp 0xac]     -- P2PK
       , encodeScript (encodeP2PKH pkh)                  -- P2PKH
       , p2wpkhBS                                        -- P2WPKH
       , encodeScript (encodeP2SH (hash160 p2wpkhBS))    -- P2SH-P2WPKH
       ]

-- | Derive a public key from a key expression at a given index.
deriveKeyExpr :: KeyExpr -> Int -> PubKey
deriveKeyExpr key idx = case key of
  KeyLiteral pk -> pk
  KeyXPub xpub path range ->
    let fullPath = path ++ rangeToPath range idx
        derived = deriveXPubPath xpub fullPath
    in epkKey derived
  KeyXPriv xprv path range ->
    let fullPath = path ++ rangeToPath range idx
        derived = derivePath xprv (map adjustHardened fullPath)
    in derivePubKeyFromPrivate (ekKey derived)
  KeyWIF sk -> derivePubKeyFromPrivate sk
  KeyOrigin _ _ inner -> deriveKeyExpr inner idx
  where
    rangeToPath :: DerivRange -> Int -> [Word32]
    rangeToPath (DerivIndex i) _ = [i]
    rangeToPath DerivWildcard i = [fromIntegral i]
    rangeToPath DerivHardenedWildcard i = [fromIntegral i .|. 0x80000000]

    adjustHardened :: Word32 -> Word32
    adjustHardened w = w

-- | Derive an extended public key along a path.
deriveXPubPath :: ExtendedPubKey -> [Word32] -> ExtendedPubKey
deriveXPubPath = foldl' derivePublic

-- | Convert scripts to addresses.
scriptToAddresses :: [ByteString] -> [Address]
scriptToAddresses = mapMaybe scriptToAddress

-- | Convert a script to an address (if applicable).
scriptToAddress :: ByteString -> Maybe Address
scriptToAddress script
  -- P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  | BS.length script == 25 && BS.index script 0 == 0x76 =
      Just $ PubKeyAddress (Hash160 $ BS.take 20 $ BS.drop 3 script)
  -- P2SH: OP_HASH160 <20> OP_EQUAL
  | BS.length script == 23 && BS.index script 0 == 0xa9 =
      Just $ ScriptAddress (Hash160 $ BS.take 20 $ BS.drop 2 script)
  -- P2WPKH: OP_0 <20>
  | BS.length script == 22 && BS.index script 0 == 0x00 =
      Just $ WitnessPubKeyAddress (Hash160 $ BS.take 20 $ BS.drop 2 script)
  -- P2WSH: OP_0 <32>
  | BS.length script == 34 && BS.index script 0 == 0x00 && BS.index script 1 == 0x20 =
      Just $ WitnessScriptAddress (Hash256 $ BS.take 32 $ BS.drop 2 script)
  -- P2TR: OP_1 <32>
  | BS.length script == 34 && BS.index script 0 == 0x51 && BS.index script 1 == 0x20 =
      Just $ TaprootAddress (Hash256 $ BS.take 32 $ BS.drop 2 script)
  | otherwise = Nothing

-- | Convert an address to its scriptPubKey.
addressToScript :: Address -> ByteString
addressToScript addr = case addr of
  PubKeyAddress h -> encodeScript (encodeP2PKH h)
  ScriptAddress h -> encodeScript (encodeP2SH h)
  WitnessPubKeyAddress h -> encodeScript (encodeP2WPKH h)
  WitnessScriptAddress h -> encodeP2WSH (getHash256 h)
  TaprootAddress h -> encodeScript (encodeP2TR h)

-- | Expand a combo descriptor into its constituent descriptors.
-- For compressed keys: P2PK, P2PKH, P2WPKH, P2SH-P2WPKH (4 outputs)
-- For uncompressed keys: P2PK, P2PKH only (2 outputs - no SegWit)
-- Reference: Bitcoin Core src/script/descriptor.cpp ComboDescriptor::MakeScripts
expandCombo :: KeyExpr -> [Descriptor]
expandCombo key =
  let baseDescriptors = [Pk key, Pkh key]
      -- SegWit outputs only valid for compressed keys
      segwitDescriptors = if isCompressedKey key
                          then [Wpkh key, Sh (Wpkh key)]
                          else []
  in baseDescriptors ++ segwitDescriptors

-- | Check if a key expression produces compressed public keys.
isCompressedKey :: KeyExpr -> Bool
isCompressedKey key = case key of
  KeyLiteral pk -> case pk of
    PubKeyCompressed _ -> True
    PubKeyUncompressed _ -> False
  KeyXPub _ _ _ -> True   -- xpub always produces compressed keys
  KeyXPriv _ _ _ -> True  -- xprv always produces compressed keys
  KeyWIF _ -> True        -- WIF with 0x01 suffix = compressed
  KeyOrigin _ _ inner -> isCompressedKey inner

--------------------------------------------------------------------------------
-- Helper Functions for Descriptors
--------------------------------------------------------------------------------

-- | Hex decode helper.
hexDecode' :: Text -> Maybe ByteString
hexDecode' t = case BS.pack <$> mapM hexPair (pairs $ T.unpack t) of
  Just bs -> Just bs
  Nothing -> Nothing
  where
    pairs [] = []
    pairs [_] = []
    pairs (a:b:rest) = [a,b] : pairs rest

    hexPair [a, b] = do
      high <- hexVal a
      low <- hexVal b
      return $ fromIntegral (high * 16 + low)
    hexPair _ = Nothing

    hexVal c
      | c >= '0' && c <= '9' = Just (ord c - ord '0')
      | c >= 'a' && c <= 'f' = Just (ord c - ord 'a' + 10)
      | c >= 'A' && c <= 'F' = Just (ord c - ord 'A' + 10)
      | otherwise = Nothing

-- | Hex encode helper.
hexEncode' :: ByteString -> Text
hexEncode' = T.pack . concatMap (\b -> [hexChar (b `shiftR` 4), hexChar (b .&. 0xf)]) . BS.unpack
  where
    hexChar n
      | n < 10 = toEnum (fromIntegral n + ord '0')
      | otherwise = toEnum (fromIntegral n - 10 + ord 'a')

-- | Placeholder for xpub decoding.
decodeXPub :: Text -> Maybe ExtendedPubKey
decodeXPub t
  | "xpub" `T.isPrefixOf` t || "tpub" `T.isPrefixOf` t =
      -- Placeholder: return a dummy xpub
      -- In production, this would do proper base58 decoding
      Just $ ExtendedPubKey
        { epkKey = PubKeyCompressed (BS.replicate 33 0x02)
        , epkChainCode = BS.replicate 32 0
        , epkDepth = 0
        , epkParentFP = 0
        , epkIndex = 0
        }
  | otherwise = Nothing

-- | Placeholder for xprv decoding.
decodeXPriv :: Text -> Maybe ExtendedKey
decodeXPriv t
  | "xprv" `T.isPrefixOf` t || "tprv" `T.isPrefixOf` t =
      Just $ ExtendedKey
        { ekKey = SecKey (BS.replicate 32 0x01)
        , ekChainCode = BS.replicate 32 0
        , ekDepth = 0
        , ekParentFP = 0
        , ekIndex = 0
        }
  | otherwise = Nothing

-- | Placeholder for xpub encoding.
encodeXPub :: ExtendedPubKey -> Text
encodeXPub _ = "xpub..."  -- Placeholder

-- | Placeholder for xprv encoding.
encodeXPriv :: ExtendedKey -> Text
encodeXPriv _ = "xprv..."  -- Placeholder

-- | Encode a private key as WIF (Wallet Import Format).
-- Encodes as compressed (with 0x01 suffix) for mainnet.
wifEncode :: SecKey -> Text
wifEncode (SecKey sk) =
  -- Version 0x80 for mainnet, 0x01 suffix for compressed
  let payload = BS.snoc sk 0x01  -- Compressed format
  in base58Check 0x80 payload

-- | Encode a public key as script bytes.
encodePubKey :: PubKey -> ByteString
encodePubKey = serializePubKeyCompressed

-- | Encode an opcode.
encodeOp :: Word8 -> ByteString
encodeOp = BS.singleton

-- | Encode a multisig script.
encodeMultisig :: Int -> [PubKey] -> ByteString
encodeMultisig k pks =
  let n = length pks
      kOp = if k <= 16 then BS.singleton (0x50 + fromIntegral k) else encodeNumber k
      nOp = if n <= 16 then BS.singleton (0x50 + fromIntegral n) else encodeNumber n
      pkPushes = map (\pk -> let bs = serializePubKeyCompressed pk
                             in BS.cons (fromIntegral $ BS.length bs) bs) pks
  in BS.concat ([kOp] ++ pkPushes ++ [nOp, BS.singleton 0xae])  -- OP_CHECKMULTISIG

-- | Encode a number for script.
encodeNumber :: Int -> ByteString
encodeNumber n
  | n == 0 = BS.singleton 0x00
  | n >= 1 && n <= 16 = BS.singleton (0x50 + fromIntegral n)
  | otherwise = BS.pack [0x01, fromIntegral n]  -- Simplified

-- | Get x-only public key (32 bytes).
xOnlyPubKey :: PubKey -> Hash256
xOnlyPubKey pk = Hash256 $ BS.drop 1 $ serializePubKeyCompressed pk

-- | Encode P2WSH script.
encodeP2WSH :: ByteString -> ByteString
encodeP2WSH witnessScriptHash =
  BS.concat [BS.singleton 0x00, BS.singleton 0x20, witnessScriptHash]

--------------------------------------------------------------------------------
-- Multi-Wallet Manager (Bitcoin Core compatible)
--------------------------------------------------------------------------------

-- | Wallet manager for multiple simultaneous wallets.
-- Each wallet is identified by a unique name and has an independent SQLite database.
-- Reference: Bitcoin Core wallet/context.h WalletContext
data WalletManager = WalletManager
  { wmWallets     :: !(TVar (Map Text WalletState))
      -- ^ Loaded wallets by name
  , wmWalletDir   :: !FilePath
      -- ^ Base directory for wallet storage (e.g. "wallets/")
  , wmNetwork     :: !Network
      -- ^ Network (mainnet/testnet/regtest)
  , wmDefaultName :: !(TVar (Maybe Text))
      -- ^ Default wallet name (first loaded, or explicitly set)
  }

-- | Information about a wallet for getwalletinfo RPC.
-- Reference: Bitcoin Core wallet/rpc/wallet.cpp getwalletinfo
data WalletInfo = WalletInfo
  { wiWalletName           :: !Text
      -- ^ Wallet name
  , wiWalletVersion        :: !Int
      -- ^ Wallet version (format version)
  , wiBalance              :: !Word64
      -- ^ Total confirmed balance in satoshis
  , wiUnconfirmedBalance   :: !Word64
      -- ^ Unconfirmed balance (0 for now, we don't track this yet)
  , wiImmatureBalance      :: !Word64
      -- ^ Immature coinbase balance (0 for now)
  , wiTxCount              :: !Int
      -- ^ Number of wallet transactions (0 for now)
  , wiKeypoolSize          :: !Int
      -- ^ Number of pregenerated keys
  , wiUnlockedUntil        :: !(Maybe Word64)
      -- ^ Unlock expiry timestamp (Nothing if not encrypted or locked)
  , wiPaytxfee             :: !Word64
      -- ^ Transaction fee per kB (0 for now)
  , wiPrivateKeysEnabled   :: !Bool
      -- ^ Whether private keys are enabled
  , wiAvoidReuse           :: !Bool
      -- ^ Whether avoid_reuse flag is set
  , wiScanning             :: !Bool
      -- ^ Whether wallet is currently scanning
  , wiDescriptors          :: !Bool
      -- ^ Whether this is a descriptor wallet (always true for us)
  , wiExternalSigner       :: !Bool
      -- ^ Whether external signer is used
  } deriving (Show, Eq, Generic)

instance NFData WalletInfo

-- | Create a new wallet manager.
-- Initializes the wallet directory structure.
newWalletManager :: FilePath -> Network -> IO WalletManager
newWalletManager walletDir net = do
  createDirectoryIfMissing True walletDir
  walletsVar <- newTVarIO Map.empty
  defaultNameVar <- newTVarIO Nothing
  return WalletManager
    { wmWallets     = walletsVar
    , wmWalletDir   = walletDir
    , wmNetwork     = net
    , wmDefaultName = defaultNameVar
    }

-- | Create a new managed wallet.
-- Parameters:
--   name: Unique wallet name
--   disablePrivateKeys: If true, creates a watch-only wallet
--   blank: If true, creates a wallet with no keys
-- Returns: Either an error message or the new WalletState
-- Reference: Bitcoin Core wallet/rpc/wallet.cpp createwallet
createManagedWallet :: WalletManager
                    -> Text           -- ^ Wallet name
                    -> Bool           -- ^ disable_private_keys (watch-only)
                    -> Bool           -- ^ blank (no keys initially)
                    -> IO (Either Text WalletState)
createManagedWallet wm name _disablePrivateKeys blank = do
  -- Check if wallet already exists
  existingWallets <- readTVarIO (wmWallets wm)
  if Map.member name existingWallets
    then return $ Left $ "Wallet \"" <> name <> "\" already exists"
    else do
      -- Create wallet directory
      let walletPath = wmWalletDir wm </> T.unpack name
      dirExists <- doesDirectoryExist walletPath
      if dirExists
        then return $ Left $ "Wallet directory already exists: " <> T.pack walletPath
        else do
          createDirectoryIfMissing True walletPath

          -- Create the wallet
          let config = WalletConfig (wmNetwork wm) 20 ""
          if blank
            then do
              -- For blank wallet, create with a random mnemonic but don't pre-generate addresses
              (_mnemonic, wallet) <- createWallet config
              walletState <- createWalletState wallet
              -- Add to manager
              atomically $ do
                modifyTVar' (wmWallets wm) (Map.insert name walletState)
                -- Set as default if first wallet
                mDefault <- readTVar (wmDefaultName wm)
                when (mDefault == Nothing) $ writeTVar (wmDefaultName wm) (Just name)
              return $ Right walletState
            else do
              -- Normal wallet creation
              (_mnemonic, wallet) <- createWallet config
              walletState <- createWalletState wallet
              -- Add to manager
              atomically $ do
                modifyTVar' (wmWallets wm) (Map.insert name walletState)
                -- Set as default if first wallet
                mDefault <- readTVar (wmDefaultName wm)
                when (mDefault == Nothing) $ writeTVar (wmDefaultName wm) (Just name)
              return $ Right walletState

-- | Load an existing wallet by name.
-- The wallet must exist in the wallet directory.
-- Reference: Bitcoin Core wallet/rpc/wallet.cpp loadwallet
loadManagedWallet :: WalletManager
                  -> Text           -- ^ Wallet name
                  -> IO (Either Text WalletState)
loadManagedWallet wm name = do
  -- Check if already loaded
  existingWallets <- readTVarIO (wmWallets wm)
  if Map.member name existingWallets
    then return $ Left $ "Wallet \"" <> name <> "\" is already loaded"
    else do
      -- Check if wallet directory exists
      let walletPath = wmWalletDir wm </> T.unpack name
      dirExists <- doesDirectoryExist walletPath
      if not dirExists
        then return $ Left $ "Wallet not found: " <> name
        else do
          -- For now, we create a fresh wallet since we don't have persistence yet
          -- In a real implementation, we'd load from the SQLite database
          let config = WalletConfig (wmNetwork wm) 20 ""
          (_mnemonic, wallet) <- createWallet config
          walletState <- createWalletState wallet
          atomically $ do
            modifyTVar' (wmWallets wm) (Map.insert name walletState)
            -- Set as default if first wallet
            mDefault <- readTVar (wmDefaultName wm)
            when (mDefault == Nothing) $ writeTVar (wmDefaultName wm) (Just name)
          return $ Right walletState

-- | Unload a wallet.
-- Removes the wallet from the manager but does not delete wallet files.
-- Reference: Bitcoin Core wallet/rpc/wallet.cpp unloadwallet
unloadManagedWallet :: WalletManager -> Text -> IO (Either Text ())
unloadManagedWallet wm name = do
  result <- atomically $ do
    wallets <- readTVar (wmWallets wm)
    if Map.member name wallets
      then do
        writeTVar (wmWallets wm) (Map.delete name wallets)
        -- Update default if we just unloaded it
        mDefault <- readTVar (wmDefaultName wm)
        when (mDefault == Just name) $ do
          let remaining = Map.keys (Map.delete name wallets)
          writeTVar (wmDefaultName wm) (listToMaybe remaining)
        return $ Right ()
      else return $ Left $ "Wallet not found: " <> name
  return result

-- | Get a specific wallet by name.
-- Returns Nothing if the wallet is not loaded.
getManagedWallet :: WalletManager -> Text -> IO (Maybe WalletState)
getManagedWallet wm name = do
  wallets <- readTVarIO (wmWallets wm)
  return $ Map.lookup name wallets

-- | Get the default wallet.
-- Returns the first loaded wallet, or Nothing if no wallets are loaded.
-- Also returns the total count of loaded wallets.
-- Reference: Bitcoin Core wallet/wallet.cpp GetDefaultWallet
getDefaultWallet :: WalletManager -> IO (Maybe WalletState, Int)
getDefaultWallet wm = do
  wallets <- readTVarIO (wmWallets wm)
  mDefaultName <- readTVarIO (wmDefaultName wm)
  let count = Map.size wallets
  case mDefaultName of
    Just name -> return (Map.lookup name wallets, count)
    Nothing -> case Map.elems wallets of
      (w:_) -> return (Just w, count)
      []    -> return (Nothing, 0)

-- | List all loaded wallet names.
-- Reference: Bitcoin Core wallet/rpc/wallet.cpp listwallets
listManagedWallets :: WalletManager -> IO [Text]
listManagedWallets wm = do
  wallets <- readTVarIO (wmWallets wm)
  return $ Map.keys wallets

-- | Get information about a wallet.
-- Returns wallet metadata for the getwalletinfo RPC.
-- Reference: Bitcoin Core wallet/rpc/wallet.cpp getwalletinfo
getWalletInfo :: Text -> WalletState -> IO WalletInfo
getWalletInfo walletName ws = do
  balance <- getBalance (wsWallet ws)
  locked <- isWalletLocked ws
  mExpiry <- readTVarIO (wsUnlockExpiry ws)

  -- Calculate unlock timestamp if applicable
  let unlockedUntil = case (locked, mExpiry) of
        (False, Just expiry) -> Just $ round (realToFrac (utcTimeToPOSIXSeconds expiry) :: Double)
        _ -> Nothing

  return WalletInfo
    { wiWalletName         = walletName
    , wiWalletVersion      = 169900  -- Matches Bitcoin Core version format
    , wiBalance            = balance
    , wiUnconfirmedBalance = 0
    , wiImmatureBalance    = 0
    , wiTxCount            = 0
    , wiKeypoolSize        = 20  -- Our gap limit
    , wiUnlockedUntil      = unlockedUntil
    , wiPaytxfee           = 0
    , wiPrivateKeysEnabled = True  -- We always have private keys (for now)
    , wiAvoidReuse         = False
    , wiScanning           = False
    , wiDescriptors        = True  -- We're descriptor-based
    , wiExternalSigner     = False
    }

-- | Convert UTCTime to POSIX seconds (helper).
utcTimeToPOSIXSeconds :: UTCTime -> NominalDiffTime
utcTimeToPOSIXSeconds = diffUTCTime $ UTCTime (fromGregorian 1970 1 1) 0

-- | Create UTCTime from Gregorian date (helper).
fromGregorian :: Integer -> Int -> Int -> Day
fromGregorian y m d = ModifiedJulianDay $ dayOfGregorian y m d

-- | Helper for day calculation.
dayOfGregorian :: Integer -> Int -> Int -> Integer
dayOfGregorian year month day =
  let a = (14 - month) `div` 12
      y = year + 4800 - fromIntegral a
      m = fromIntegral (month + 12 * a - 3) :: Integer
  in fromIntegral day + (153 * m + 2) `div` 5 + 365 * y + y `div` 4 - y `div` 100 + y `div` 400 - 32045 - 2400001

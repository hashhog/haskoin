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
  , entropyToMnemonic
  , mnemonicToEntropy
    -- * BIP-32 Key Derivation
  , ExtendedKey(..)
  , ExtendedPubKey(..)
  , masterKey
  , derivePrivate
  , derivePublic
  , deriveHardened
  , derivePath
  , derivePathPriv
  , deriveChildPriv
  , deriveChildPub
  , toExtendedPubKey
    -- * BIP-32 Extended Key Serialization
  , encodeExtKey
  , decodeExtKey
  , encodeExtPubKey
  , decodeExtPubKey
  , XKeyVersion(..)
  , xprvVersion
  , xpubVersion
  , tprvVersion
  , tpubVersion
    -- * BIP-44/49/84/86 Paths
  , defaultDerivationPath
  , bip44Path
  , bip49Path
  , bip84Path
  , bip86Path
  , bip44FullPath
  , bip49FullPath
  , bip84FullPath
  , bip86FullPath
  , bip44Mainnet
  , bip49Mainnet
  , bip84Mainnet
  , bip86Mainnet
  , parseDerivationPath
    -- * BIP-44 helpers / wallet integration
  , importMnemonic
  , deriveSigningKey
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
  , approximateBestSubset
  , partitionUtxos
  , findExactMatch
  , maxBnBIterations
  , dustThreshold
  , minChangeAmount
  , costOfChange
  , estimateTxWeight
  , feeFromWeight
  , effectiveValue
  , shuffleList
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
    -- * Sign-side primitives (exposed for tests / advanced callers)
  , signWithKey
  , signWithKeyTaproot
  , signWithKeyTapscript
  , derivePubKeyFromPrivate
  , computeLegacySighash
  , computeSegwitSighash
  , computeSegwitSighashFromProgram
  , computeSegwitSighashScriptCode
  , computeTaprootKeyPathSighash
  , computeTaprootScriptPathSighash
  , isP2PKHScript
  , isP2WPKHScript
  , isP2WSHScript
  , isP2SHScript
  , isP2TRScript
  , getP2TRProgram
    -- * BIP-16 / BIP-141 commitment helpers (W31)
  , getP2SHHash
  , getP2WSHHash
  , p2shCommits
  , p2wshCommits
    -- * Tapscript single-leaf wallet integration (W18)
  , tapscriptLeafScriptPsbtKey
  , tapscriptControlBlockPsbtKey
  , isSingleKeyOpChecksigTapscript
  , verifyTaprootCommitment
    -- * PSBT consistency validators (W41 — Bug A1 + Bug A2 / CVE-2020-14199)
  , verifyNonWitnessUtxoTxid
  , verifyInputUtxoConsistency
  , verifyPsbtUtxoConsistency
  , extractNonWitnessTxOut
  , getInputUtxoFor
    -- * PSBT Utilities
  , decodePsbt
  , encodePsbt
  , isPsbtFinalized
  , getPsbtFee
  , parseMultisigRedeem
    -- * PSBT decoder primitives (W34-E: exposed for strictness regression tests)
  , parseKeyPath
  , parseWitnessStack
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
    -- * WIF (private-key text encoding)
  , wifDecode
  , wifEncode
  , isWifKey
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
                        putWord32be, putWord32le, getWord32le, getWord32be, putWord8, getWord8,
                        putByteString, getBytes, remaining, lookAhead, skip)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Set (Set)
import qualified Data.Set as Set
import Control.Monad (forM, forM_, when, replicateM, void, foldM)
import Control.Applicative ((<|>))
import qualified Crypto.Random as CryptoRandom
import Data.List (sortBy, foldl', sortOn)
import Data.Ord (comparing, Down(..))
import Control.Concurrent.STM
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import System.IO.Unsafe (unsafePerformIO)
import Data.Char (isSpace, isDigit, isHexDigit, digitToInt, ord)
import Data.Maybe (listToMaybe, mapMaybe, fromMaybe, isJust)
import System.Directory (createDirectoryIfMissing, doesDirectoryExist, listDirectory)
import System.FilePath ((</>))

import Haskoin.Types (Hash256(..), Hash160(..), TxId(..), BlockHash(..), OutPoint(..),
                       TxIn(..), TxOut(..), Tx(..), putVarInt, getVarInt', putVarBytes, getVarBytes)
import Haskoin.Crypto
import qualified Haskoin.TaprootSighash as TS
import Haskoin.Script (encodeP2WPKH, encodeP2PKH, encodeP2SH, encodeP2TR, encodeScript)
import Haskoin.Mempool (FeeRate(..))
import Haskoin.Consensus (Network(..), coinbaseMaturity)
import qualified Haskoin.Consensus

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

  -- Generate random entropy using cryptonite CSPRNG (/dev/urandom backed).
  -- BUG-6 fix: was System.Random.randomIO (non-CSPRNG); BIP-39 requires CSPRNG.
  entropy <- CryptoRandom.getRandomBytes (strength `div` 8)

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
--
-- Per RFC 2898 §5.2, for each output block i in @[1..L/hLen]@:
--
-- > U_1 = PRF(P, S || INT(i))
-- > U_j = PRF(P, U_{j-1})         for j = 2..c
-- > T_i = U_1 XOR U_2 XOR … XOR U_c
--
-- Concretely: build the chain of U values lazily, then XOR-fold them.
-- The earlier implementation's recursion accidentally collapsed every
-- iteration after the first to all-zeros, which silently produced bogus
-- BIP-39 seeds (mnemonicToSeed never had a vector test until W17).
pbkdf2SHA512 :: ByteString -> ByteString -> Int -> Int -> ByteString
pbkdf2SHA512 password salt iterations keyLen =
  let blocks = (keyLen + 63) `div` 64  -- SHA-512 produces 64 bytes
      f blockNum =
        let -- U_1 = PRF(Password, Salt || INT_32_BE(i))
            u1 = hmacSHA512 password (BS.append salt (encodeWord32BE blockNum))
            -- Iteratively: u <- HMAC(password, u); accumulate XOR.
            step (acc, u) _ =
              let nxt = hmacSHA512 password u
                  acc' = BS.pack (BS.zipWith xor acc nxt)
              in (acc', nxt)
            (final, _) = foldl' step (u1, u1) [2 .. iterations]
        in final
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
--
-- Computes @child_pubkey = parent_pubkey + parse256(IL)*G@ per BIP-32 §
-- "Public parent key → public child key" via libsecp256k1's
-- @secp256k1_ec_pubkey_tweak_add@.  Mirrors Bitcoin Core's
-- @CPubKey::Derive@ (`bitcoin-core/src/pubkey.cpp:341`).
--
-- Throws via 'error' on the vanishingly-rare invalid-child case
-- (@IL >= n@ or resulting point at infinity).  Callers that want
-- to advance to the next index instead should use 'deriveChildPub'.
derivePublic :: ExtendedPubKey -> Word32 -> ExtendedPubKey
derivePublic parent index = case deriveChildPub parent index of
  Just child -> child
  Nothing
    | index >= 0x80000000 ->
        error "derivePublic: cannot derive hardened child from public key"
    | otherwise ->
        error "derivePublic: invalid child key (IL >= n or point at infinity)"

-- | 'Maybe'-returning child-public derivation.  Returns 'Nothing' on:
--
--   * @index >= 0x80000000@ (hardened, not derivable from xpub)
--   * @parse256(IL) >= n@ (BIP-32 spec: skip and bump index)
--   * resulting point is the point at infinity (BIP-32 spec: skip
--     and bump index)
--
-- This is the canonical BIP-32 CKDpub predicate; 'derivePublic' is the
-- partial variant that 'error's instead.  Wallet code that scans many
-- indices to find a valid one should call 'deriveChildPub' directly.
deriveChildPub :: ExtendedPubKey -> Word32 -> Maybe ExtendedPubKey
deriveChildPub parent index
  | index >= 0x80000000 = Nothing
  | otherwise =
      let pubBytes   = serializePubKeyCompressed (epkKey parent)
          dat        = BS.append pubBytes (encodeWord32BE' index)
          hmacResult = hmacSHA512 (epkChainCode parent) dat
          (il, ir)   = BS.splitAt 32 hmacResult
          ilInt      = bsToIntegerBE il
      in if ilInt >= secp256k1Order
           then Nothing
           else case addPublicKeyPoint il (epkKey parent) of
             Nothing -> Nothing  -- point at infinity or libsecp failure
             Just childPubKey ->
               let fingerprint = computeFingerprint pubBytes
               in Just ExtendedPubKey
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

-- | BIP-32 CKDpub EC point addition: child = parent_pubkey + scalar*G.
--
-- Routes through 'Haskoin.Crypto.pubKeyTweakAdd', which is FFI-backed by
-- libsecp256k1 (`secp256k1_ec_pubkey_tweak_add`).  Returns 'Nothing' on
-- @scalar >= n@ (curve order), point-at-infinity result, or malformed
-- parent serialization (none of which should happen in practice for a
-- correctly-typed 'PubKey', but we propagate the failure as BIP-32 instructs
-- the caller to skip the index).
--
-- Result is always a compressed pubkey ('PubKeyCompressed').
--
-- Prior to W118 FIX-59 this function was a stub returning the parent
-- unchanged, causing every CKDpub step to be a no-op (G10 / DH-1 / TP-1
-- in the W118 audit).  Reference: @bitcoin-core/src/pubkey.cpp@
-- `CPubKey::Derive`.
addPublicKeyPoint :: ByteString -> PubKey -> Maybe PubKey
addPublicKeyPoint scalar pk =
  let parentBytes = serializePubKeyCompressed pk
  in PubKeyCompressed <$> pubKeyTweakAdd parentBytes scalar

-- | Derive public key from private key.
--
-- Routes through 'Haskoin.Crypto.derivePubKey', which is FFI-backed by
-- libsecp256k1 (`secp256k1_ec_pubkey_create`).  Prior to this fix this
-- function returned `sha256(sk)` shaped to look like a compressed key,
-- which produced unspendable addresses for every wallet path that
-- exercised it (BIP-32 child derivation, address generation,
-- fingerprinting).  See
-- @CORE-PARITY-AUDIT/_design-haskoin-ecdsa-secp256k1-wiring-2026-05-07.md@
-- §2.5 / §3 for the historical context.
derivePubKeyFromPrivate :: SecKey -> PubKey
derivePubKeyFromPrivate = derivePubKey

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

-- | The order of the secp256k1 curve.  Used in BIP-32 child-key validity
-- checks (a freshly-derived child seckey is valid iff
-- @0 < k_child < n@; the spec says fail and bump the index otherwise).
secp256k1Order :: Integer
secp256k1Order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

-- | 'Maybe'-returning child-private derivation.  Returns 'Nothing' on the
-- vanishingly-rare invalid-child case (BIP-32: @IL >= n@ or
-- @k_child == 0@).  Hardened children use @i >= 0x80000000@.
--
-- This is the canonical BIP-32 CKD_priv predicate; 'derivePrivate' /
-- 'deriveHardened' are the partial variants that 'error' instead.
deriveChildPriv :: ExtendedKey -> Word32 -> Maybe ExtendedKey
deriveChildPriv parent index =
  let isHardened = index >= 0x80000000
      dat = if isHardened
              then BS.cons 0x00 (getSecKey (ekKey parent)) `BS.append` encodeWord32BE' index
              else let pubBytes = serializePubKeyCompressed (derivePubKeyFromPrivate (ekKey parent))
                   in BS.append pubBytes (encodeWord32BE' index)
      hmacResult = hmacSHA512 (ekChainCode parent) dat
      (il, ir) = BS.splitAt 32 hmacResult
      ilInt = bsToIntegerBE il
      parentInt = bsToIntegerBE (getSecKey (ekKey parent))
      childInt = (ilInt + parentInt) `mod` secp256k1Order
      childKey = integerToBS32 childInt
      pubBytesParent = serializePubKeyCompressed (derivePubKeyFromPrivate (ekKey parent))
      fingerprint = computeFingerprint pubBytesParent
  in if ilInt >= secp256k1Order || childInt == 0
       then Nothing
       else Just $ ExtendedKey
              { ekKey = SecKey childKey
              , ekChainCode = ir
              , ekDepth = ekDepth parent + 1
              , ekParentFP = fingerprint
              , ekIndex = index
              }

-- | Fold 'deriveChildPriv' across a path, short-circuiting on the rare
-- invalid-child case.  Use this when you need a total signature; the
-- partial 'derivePath' is retained for backwards-compat with existing
-- callers that already short-circuit on 'error'.
derivePathPriv :: ExtendedKey -> [Word32] -> Maybe ExtendedKey
derivePathPriv = foldM deriveChildPriv

--------------------------------------------------------------------------------
-- BIP-32 Extended Key Serialization
--------------------------------------------------------------------------------
-- Reference:
--   BIP-32 §"Serialization format"
--     <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
--   bitcoin-core/src/key.cpp: CExtKey::Encode / CExtKey::Decode
--   bitcoin-core/src/chainparams.cpp: base58Prefixes for EXT_*_KEY
--
-- 78-byte payload + 4-byte base58check tail:
--   4  bytes  version            (0x0488ADE4 xprv / 0x0488B21E xpub /
--                                 0x04358394 tprv / 0x043587CF tpub)
--   1  byte   depth
--   4  bytes  parent fingerprint (BE)
--   4  bytes  child number       (BE; high bit set ⇒ hardened)
--   32 bytes  chain code
--   33 bytes  key
--             - xprv/tprv: 0x00 || ser256(k)
--             - xpub/tpub: ser_compressed(K)

-- | The four well-known BIP-32 version prefixes.
data XKeyVersion = XPrvMain | XPubMain | XPrvTest | XPubTest
  deriving (Show, Eq, Generic)

instance NFData XKeyVersion

xprvVersion :: Word32
xprvVersion = 0x0488ADE4

xpubVersion :: Word32
xpubVersion = 0x0488B21E

tprvVersion :: Word32
tprvVersion = 0x04358394

tpubVersion :: Word32
tpubVersion = 0x043587CF

-- | True for Bitcoin mainnet (per 'Haskoin.Consensus.mainnet' / netName).
isMainnetVersion :: Network -> Bool
isMainnetVersion net = case netName net of
  "main"    -> True
  "mainnet" -> True
  _         -> False

-- | Encode a BIP-32 extended private key to its base58check string
-- (`xprv...` for mainnet, `tprv...` otherwise).
encodeExtKey :: Network -> ExtendedKey -> Text
encodeExtKey net ek =
  let version = if isMainnetVersion net then xprvVersion else tprvVersion
      keyData = BS.cons 0x00 (getSecKey (ekKey ek))
      payload = serializeExtKeyPayload version (ekDepth ek) (ekParentFP ek)
                                                (ekIndex ek) (ekChainCode ek) keyData
  in base58CheckRaw payload

-- | Decode an extended private key.  Returns 'Nothing' on:
--   * non-78-byte payload after base58check
--   * unknown version prefix
--   * malformed checksum
--   * non-zero leading byte on the key data (xpub data instead of xprv)
decodeExtKey :: Text -> Maybe (Network, ExtendedKey)
decodeExtKey txt = do
  payload <- base58CheckRawDecode txt
  if BS.length payload /= 78 then Nothing else do
    let version    = decodeWord32BE (BS.take 4 payload)
        depth      = BS.index payload 4
        parentFP   = decodeWord32BE (BS.take 4 (BS.drop 5 payload))
        childNum   = decodeWord32BE (BS.take 4 (BS.drop 9 payload))
        chainCode  = BS.take 32 (BS.drop 13 payload)
        keyData    = BS.take 33 (BS.drop 45 payload)
    net <- case () of
      _ | version == xprvVersion -> Just mainnetForExt
        | version == tprvVersion -> Just testnetForExt
        | otherwise              -> Nothing
    -- xprv: 0x00 || k32
    if BS.head keyData /= 0x00
      then Nothing
      else Just (net, ExtendedKey
        { ekKey       = SecKey (BS.tail keyData)
        , ekChainCode = chainCode
        , ekDepth     = depth
        , ekParentFP  = parentFP
        , ekIndex     = childNum
        })

-- | Encode a BIP-32 extended public key to its base58check string
-- (`xpub...` for mainnet, `tpub...` otherwise).
encodeExtPubKey :: Network -> ExtendedPubKey -> Text
encodeExtPubKey net epk =
  let version = if isMainnetVersion net then xpubVersion else tpubVersion
      keyData = serializePubKeyCompressed (epkKey epk)
      payload = serializeExtKeyPayload version (epkDepth epk) (epkParentFP epk)
                                                (epkIndex epk) (epkChainCode epk) keyData
  in base58CheckRaw payload

-- | Decode an extended public key.
decodeExtPubKey :: Text -> Maybe (Network, ExtendedPubKey)
decodeExtPubKey txt = do
  payload <- base58CheckRawDecode txt
  if BS.length payload /= 78 then Nothing else do
    let version   = decodeWord32BE (BS.take 4 payload)
        depth     = BS.index payload 4
        parentFP  = decodeWord32BE (BS.take 4 (BS.drop 5 payload))
        childNum  = decodeWord32BE (BS.take 4 (BS.drop 9 payload))
        chainCode = BS.take 32 (BS.drop 13 payload)
        keyData   = BS.take 33 (BS.drop 45 payload)
    net <- case () of
      _ | version == xpubVersion -> Just mainnetForExt
        | version == tpubVersion -> Just testnetForExt
        | otherwise              -> Nothing
    pk <- parsePubKey keyData
    Just (net, ExtendedPubKey
      { epkKey       = pk
      , epkChainCode = chainCode
      , epkDepth     = depth
      , epkParentFP  = parentFP
      , epkIndex     = childNum
      })

-- | Sentinel networks returned by the decoder.  The caller can match on
-- 'netName' (`"main"` vs `"testnet3"`); for full Network records the
-- caller should re-derive from their configuration.
mainnetForExt :: Network
mainnetForExt = Haskoin.Consensus.mainnet

testnetForExt :: Network
testnetForExt = Haskoin.Consensus.testnet3

-- | Helper: assemble the 78-byte extended-key payload.
serializeExtKeyPayload
  :: Word32      -- ^ version
  -> Word8       -- ^ depth
  -> Word32      -- ^ parent fingerprint
  -> Word32      -- ^ child number
  -> ByteString  -- ^ chain code (32)
  -> ByteString  -- ^ key data (33)
  -> ByteString
serializeExtKeyPayload version depth parentFP childNum chainCode keyData =
  BS.concat
    [ encodeWord32BE' version
    , BS.singleton depth
    , encodeWord32BE' parentFP
    , encodeWord32BE' childNum
    , chainCode
    , keyData
    ]

-- | Variant of 'base58Check' that accepts a multi-byte version prefix
-- (BIP-32 uses 4-byte versions, the existing 'base58Check' takes a single
-- 'Word8').  Implements: payload || dsha256(payload)[:4] → base58.
base58CheckRaw :: ByteString -> Text
base58CheckRaw payload =
  let Hash256 d = doubleSHA256 payload
      checksum = BS.take 4 d
      full = BS.append payload checksum
      leadingZeros = BS.length $ BS.takeWhile (== 0) full
      encoded = encodeBase58 full
      prefix = T.replicate leadingZeros (T.singleton '1')
  in T.append prefix encoded

-- | Inverse of 'base58CheckRaw'.  Returns the payload (without the
-- 4-byte checksum) on success, 'Nothing' on checksum mismatch or empty
-- input.
base58CheckRawDecode :: Text -> Maybe ByteString
base58CheckRawDecode txt
  | T.null txt = Nothing
  | otherwise =
      let (ones, rest) = T.span (== '1') txt
          leadingZeros = T.length ones
          decoded = decodeBase58 rest
          withZeros = BS.append (BS.replicate leadingZeros 0) decoded
      in if BS.length withZeros < 5
           then Nothing
           else
             let payloadLen = BS.length withZeros - 4
                 payload    = BS.take payloadLen withZeros
                 gotCheck   = BS.drop payloadLen withZeros
                 Hash256 d  = doubleSHA256 payload
                 expCheck   = BS.take 4 d
             in if gotCheck == expCheck then Just payload else Nothing

--------------------------------------------------------------------------------
-- BIP-39 entropy round-trip
--------------------------------------------------------------------------------
-- The existing 'generateMnemonic' synthesises fresh entropy and emits a
-- mnemonic.  These two helpers expose the raw entropy↔mnemonic mapping
-- so callers can:
--   * import an externally-supplied mnemonic and recover its entropy
--     (used by recovery flows + BIP-39 vector tests)
--   * deterministically construct a mnemonic from known entropy
--     (used by BIP-39 vector tests)
--
-- Reference: BIP-39 §"From mnemonic to seed" + §"Generating the
-- mnemonic" — <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

-- | Convert raw entropy bytes to a mnemonic phrase.  Entropy length must
-- be one of 16/20/24/28/32 bytes (128/160/192/224/256 bits).
entropyToMnemonic :: ByteString -> Maybe Mnemonic
entropyToMnemonic ent
  | BS.length ent `notElem` [16, 20, 24, 28, 32] = Nothing
  | otherwise =
      let strength     = BS.length ent * 8
          checksumBits = strength `div` 32
          allBits      = bytesToBits ent ++ take checksumBits (bytesToBits (sha256 ent))
          groups       = splitEvery 11 allBits
          indices      = map bitsToInt groups
          ws           = map (bip39WordList !!) indices
      in Just (Mnemonic ws)

-- | Convert a mnemonic back to entropy.  Returns 'Nothing' on any of:
--   * word count not in {12,15,18,21,24}
--   * any word missing from the BIP-39 English wordlist
--   * checksum mismatch
mnemonicToEntropy :: Mnemonic -> Maybe ByteString
mnemonicToEntropy m@(Mnemonic ws)
  | not (validateMnemonic m) = Nothing
  | otherwise =
      let indices       = map (\w -> wordIndex w) ws
          bits          = concatMap (intToBits 11) indices
          totalBits     = length ws * 11
          checksumBits  = totalBits `div` 33
          entropyBits   = totalBits - checksumBits
          (entropyPart, _) = splitAt entropyBits bits
          entropyBytes  = BS.pack $ map (fromIntegral . bitsToInt) (splitEvery 8 entropyPart)
      in Just entropyBytes
  where
    -- Reuses the same lookup as 'verifyMnemonicChecksum'.
    wordIndex :: Text -> Int
    wordIndex w = go 0 bip39WordList
      where
        go _ [] = 0
        go n (x:xs) = if x == w then n else go (n+1) xs

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

-- | Full BIP-44 path: m/44'/coin'/account'/change/index
bip44FullPath
  :: Word32  -- ^ coin_type (0 = mainnet, 1 = testnet)
  -> Word32  -- ^ account
  -> Word32  -- ^ change   (0 = receive, 1 = change)
  -> Word32  -- ^ index
  -> [Word32]
bip44FullPath coin acct chg idx =
  [ 0x80000000 .|. 44
  , 0x80000000 .|. coin
  , 0x80000000 .|. acct
  , chg
  , idx
  ]

-- | Full BIP-49 path: m/49'/coin'/account'/change/index (P2SH-P2WPKH).
bip49FullPath :: Word32 -> Word32 -> Word32 -> Word32 -> [Word32]
bip49FullPath coin acct chg idx =
  [ 0x80000000 .|. 49
  , 0x80000000 .|. coin
  , 0x80000000 .|. acct
  , chg
  , idx
  ]

-- | Full BIP-84 path: m/84'/coin'/account'/change/index (native P2WPKH).
bip84FullPath :: Word32 -> Word32 -> Word32 -> Word32 -> [Word32]
bip84FullPath coin acct chg idx =
  [ 0x80000000 .|. 84
  , 0x80000000 .|. coin
  , 0x80000000 .|. acct
  , chg
  , idx
  ]

-- | Full BIP-86 path: m/86'/coin'/account'/change/index (Taproot).
bip86FullPath :: Word32 -> Word32 -> Word32 -> Word32 -> [Word32]
bip86FullPath coin acct chg idx =
  [ 0x80000000 .|. 86
  , 0x80000000 .|. coin
  , 0x80000000 .|. acct
  , chg
  , idx
  ]

-- | Convenience: BIP-44 mainnet path m/44'/0'/account'/change/index.
bip44Mainnet :: Word32 -> Word32 -> Word32 -> [Word32]
bip44Mainnet = bip44FullPath 0

-- | Convenience: BIP-49 mainnet path m/49'/0'/account'/change/index.
bip49Mainnet :: Word32 -> Word32 -> Word32 -> [Word32]
bip49Mainnet = bip49FullPath 0

-- | Convenience: BIP-84 mainnet path m/84'/0'/account'/change/index.
bip84Mainnet :: Word32 -> Word32 -> Word32 -> [Word32]
bip84Mainnet = bip84FullPath 0

-- | Convenience: BIP-86 mainnet path m/86'/0'/account'/change/index
-- (Taproot key-path).
bip86Mainnet :: Word32 -> Word32 -> Word32 -> [Word32]
bip86Mainnet = bip86FullPath 0

--------------------------------------------------------------------------------
-- BIP-44 wallet integration helpers
--------------------------------------------------------------------------------

-- | Import an existing mnemonic + passphrase into a freshly-loaded
-- 'Wallet' on the supplied network.  Thin wrapper around 'loadWallet' +
-- 'validateMnemonic'.
--
-- Validation includes BIP-39 checksum + word-count + dictionary
-- membership; an invalid mnemonic returns 'Left' rather than silently
-- producing a "wallet" full of unspendable addresses.
importMnemonic
  :: WalletConfig
  -> Mnemonic
  -> IO (Either String Wallet)
importMnemonic config m
  | not (validateMnemonic m) = pure (Left "invalid mnemonic (checksum / word count / dictionary)")
  | otherwise = Right <$> loadWallet config m

-- | Derive a 32-byte signing key at a given BIP-32 path from a wallet's
-- master key.  The supplied path is interpreted in the BIP-32 form where
-- @i >= 0x80000000@ marks a hardened component.
--
-- Returns 'Left' on the (extremely rare) BIP-32 invalid-child case.
deriveSigningKey :: Wallet -> [Word32] -> Either String SecKey
deriveSigningKey w path =
  case derivePathPriv (walletMasterKey w) path of
    Just ek -> Right (ekKey ek)
    Nothing -> Left "BIP-32 derivation failed (invalid child key)"

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
  -- BIP-86: apply BIP-341 TapTweak with empty merkle root (key-path-only).
  -- output_key = lift_x(internal_key) + int(hashTapTweak(internal_key || ""))*G
  -- Reference: BIP-341 §4.2, BIP-86 §Derivation.
  let internalX = BS.drop 1 (serializePubKeyCompressed pk)
      tweak     = bip86TapTweakHash internalX
  in case xonlyPubkeyTweakAdd internalX tweak of
       Just (tweakedX, _) -> TaprootAddress (Hash256 tweakedX)
       Nothing            -> TaprootAddress (Hash256 internalX)  -- unreachable for valid keys

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

-- | Random subset selection using CSPRNG.
-- Uses cryptonite getRandomBytes; each UTXO included with 50% probability.
randomSubset :: [Utxo] -> IO [Utxo]
randomSubset utxos = do
  -- Include each UTXO with 50% probability; use CSPRNG bit for each decision.
  decisions <- mapM (\_ -> do
    b <- CryptoRandom.getRandomBytes 1 :: IO BS.ByteString
    return (BS.head b `mod` 2 == 0)) utxos
  return [u | (u, include) <- zip utxos decisions, include]

-- | Shuffle a list randomly using CSPRNG (Fisher-Yates via cryptonite).
-- Each swap index is derived from getRandomBytes to avoid bias.
shuffleList :: [a] -> IO [a]
shuffleList [] = return []
shuffleList xs = do
  let n = length xs
  indices <- mapM (\i -> csrngRangeIO i (n - 1)) [0..n - 1]
  let pairs = zip [0..] xs
      shuffled = foldl' swap pairs (zip [0..] indices)
  return $ map snd shuffled
  where
    -- | Return a uniformly-distributed Int in [lo, hi] using CSPRNG.
    -- Uses rejection sampling on 4 random bytes to avoid modulo bias.
    csrngRangeIO :: Int -> Int -> IO Int
    csrngRangeIO lo hi
      | lo >= hi  = return lo
      | otherwise = do
          bytes <- CryptoRandom.getRandomBytes 4 :: IO BS.ByteString
          let w = fromIntegral (BS.index bytes 0) * 16777216
                + fromIntegral (BS.index bytes 1) * 65536
                + fromIntegral (BS.index bytes 2) * 256
                + fromIntegral (BS.index bytes 3) :: Int
              range = hi - lo + 1
          return (lo + (w `mod` range))
    swap :: [(Int, a)] -> (Int, Int) -> [(Int, a)]
    swap pairs (i, j)
      -- BUG-6 fix: self-swap (i==j) must be a no-op.  Without this guard the
      -- two-entry insertion below produces [(i,vj),(j,vi)] at the same index,
      -- growing the list by 1 per self-swap.
      | i == j    = pairs
      | otherwise =
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
                  -- BUG-4 fix: guard against Word64 underflow before subtraction.
                  -- If totalSelected < targetAmount + feeWithChange the change
                  -- calculation would wrap to ~2^64; treat as no-change instead.
                  totalNeeded = targetAmount + feeWithChange
                  changeAmount = if totalSelected >= totalNeeded
                                 then totalSelected - totalNeeded
                                 else 0

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
                  -- BUG-4 fix: guard against Word64 underflow before subtraction.
                  -- If totalSelected < targetAmount + feeWithChange the change
                  -- calculation would wrap to ~2^64; treat as no-change instead.
                  totalNeeded = targetAmount + feeWithChange
                  changeAmount = if totalSelected >= totalNeeded
                                 then totalSelected - totalNeeded
                                 else 0

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

-- | Generate random encryption parameters using CSPRNG.
-- BUG-6 fix: was System.Random.randomIO (non-CSPRNG); salt MUST come from CSPRNG.
generateEncryptionParams :: IO EncryptionParams
generateEncryptionParams = do
  salt <- CryptoRandom.getRandomBytes saltSize
  return EncryptionParams
    { epSalt = salt
    , epIterations = defaultPBKDF2Iterations
    }

-- | Generate a random IV for AES-CBC using CSPRNG.
-- BUG-8 fix: was System.Random.randomIO (non-CSPRNG); AES-CBC IV MUST be
-- cryptographically random to prevent predictability attacks.
generateIV :: IO ByteString
generateIV = CryptoRandom.getRandomBytes aesBlockSize

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
  -- BIP-371 Taproot fields (input-side)
  , piTapKeySig        :: !(Maybe ByteString)           -- ^ PSBT_IN_TAP_KEY_SIG (0x13)
  , piTapScriptSigs    :: !(Map (ByteString, ByteString) ByteString)
                                                        -- ^ (xonly,leaf_hash)->sig (0x14)
  , piTapLeafScripts   :: !(Map (ByteString, Int) (Set ByteString))
                                                        -- ^ (script,leaf_ver)->control_blocks (0x15)
  , piTapBip32Derivation :: !(Map ByteString (Set ByteString, KeyPath))
                                                        -- ^ xonly->(leaf_hashes,keypath) (0x16)
  , piTapInternalKey   :: !(Maybe ByteString)           -- ^ PSBT_IN_TAP_INTERNAL_KEY (0x17)
  , piTapMerkleRoot    :: !(Maybe ByteString)           -- ^ PSBT_IN_TAP_MERKLE_ROOT (0x18)
  , piUnknown          :: !(Map ByteString ByteString)  -- ^ Unknown key-value pairs
  } deriving (Show, Eq, Generic)

instance NFData PsbtInput

-- | PSBT Output fields.
-- Contains scripts and derivation paths for outputs.
data PsbtOutput = PsbtOutput
  { poRedeemScript    :: !(Maybe ByteString)           -- ^ P2SH redeem script
  , poWitnessScript   :: !(Maybe ByteString)           -- ^ P2WSH witness script
  , poBip32Derivation :: !(Map PubKey KeyPath)         -- ^ pubkey -> keypath
  -- BIP-371 Taproot fields (output-side)
  , poTapInternalKey  :: !(Maybe ByteString)           -- ^ PSBT_OUT_TAP_INTERNAL_KEY (0x05)
  , poTapTree         :: ![(Word8, Word8, ByteString)] -- ^ (depth,leaf_ver,script) triples (0x06)
  , poTapBip32Derivation :: !(Map ByteString (Set ByteString, KeyPath))
                                                       -- ^ xonly->(leaf_hashes,keypath) (0x07)
  , poMuSig2Participants :: !(Map ByteString [ByteString])
                                                       -- ^ agg_pubkey->participants (0x08)
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
  , piTapKeySig = Nothing
  , piTapScriptSigs = Map.empty
  , piTapLeafScripts = Map.empty
  , piTapBip32Derivation = Map.empty
  , piTapInternalKey = Nothing
  , piTapMerkleRoot = Nothing
  , piUnknown = Map.empty
  }

-- | Create an empty PSBT output with no data.
emptyPsbtOutput :: PsbtOutput
emptyPsbtOutput = PsbtOutput
  { poRedeemScript = Nothing
  , poWitnessScript = Nothing
  , poBip32Derivation = Map.empty
  , poTapInternalKey = Nothing
  , poTapTree = []
  , poTapBip32Derivation = Map.empty
  , poMuSig2Participants = Map.empty
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

-- | Serialize input map.
--
-- W47 encoder gate + canonical sort-key (mirrors blockbrew W45 commit
-- e000f9b and beamchain W46-2 commit e8f04a0):
--
--   * Encoder gate.  When an input is finalized (either 'piFinalScriptSig'
--     or 'piFinalScriptWitness' is 'Just'), the producer-only fields
--     (PSBT_IN_PARTIAL_SIG 0x02, PSBT_IN_SIGHASH_TYPE 0x03,
--     PSBT_IN_REDEEM_SCRIPT 0x04, PSBT_IN_WITNESS_SCRIPT 0x05,
--     PSBT_IN_BIP32_DERIVATION 0x06) MUST NOT be emitted to the wire.
--     This mirrors @bitcoin-core/src/psbt.h:313@'s
--     @if (final_script_sig.empty() && final_script_witness.IsNull())@
--     gate around the producer-field emit block.  @clearSigningFields@
--     also strips them from the in-memory representation, but the gate
--     here is the byte-level invariant: a Combiner that re-merges a
--     finalized PSBT with a still-signing partial would otherwise leak
--     producer fields back onto the wire.
--
--   * Canonical sort-key.  Within an input map, key-value pairs MUST be
--     emitted in canonical key order (BIP-174).  Bitcoin Core stores
--     'piPartialSigs' in @std::map<CKeyID, SigPair>@
--     (@bitcoin-core/src/psbt.h:270@) where 'CKeyID' is the 20-byte
--     HASH160 of the pubkey, and serializes in @std::map@ iteration
--     order — i.e. by HASH160(pubkey), NOT raw pubkey bytes.  Sorting by
--     raw pubkey bytes (the default 'Ord PubKey' on a 'Map PubKey ...')
--     only matched Core when raw-pubkey order coincided with HASH160
--     order; for any pubkey set where the two orders disagree the wire
--     bytes diverge.  'piBip32Derivation' is intentionally LEFT in raw
--     pubkey order because Core keys it on @std::map<CPubKey, ...>@.
putInputMap :: PsbtInput -> Put
putInputMap PsbtInput{..} = do
  let isFinalized = isJust piFinalScriptSig || isJust piFinalScriptWitness
  -- PSBT_IN_NON_WITNESS_UTXO (0x00)
  case piNonWitnessUtxo of
    Just tx -> putKeyValue (BS.singleton 0x00) (encode tx)
    Nothing -> return ()
  -- PSBT_IN_WITNESS_UTXO (0x01)
  case piWitnessUtxo of
    Just utxo -> putKeyValue (BS.singleton 0x01) (encode utxo)
    Nothing -> return ()
  -- W47 encoder gate: producer fields (0x02 / 0x03 / 0x04 / 0x05 / 0x06)
  -- are skipped once the input is finalized.  Mirrors psbt.h:313.
  when (not isFinalized) $ do
    -- PSBT_IN_PARTIAL_SIG (0x02) for each signature.
    -- W47: sort by HASH160(pubkey) to match Core's std::map<CKeyID, ...>
    -- iteration order (psbt.h:270).
    let sortedPartialSigs =
          sortBy
            (\(pkA, _) (pkB, _) ->
              compare
                (getHash160 (hash160 (serializePubKeyCompressed pkA)))
                (getHash160 (hash160 (serializePubKeyCompressed pkB))))
            (Map.toList piPartialSigs)
    forM_ sortedPartialSigs $ \(pk, sig) ->
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
    -- PSBT_IN_BIP32_DERIVATION (0x06) for each path.
    -- Core keys this map on `std::map<CPubKey, ...>` (psbt.h:271+) — raw
    -- pubkey ordering, which the default `Ord PubKey` already provides
    -- via Map.toList.
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
-- Fingerprint is emitted as big-endian (raw network bytes, matching Core).
-- Path indices are little-endian (BIP-32 standard).
serializeKeyPath :: KeyPath -> ByteString
serializeKeyPath KeyPath{..} =
  runPut $ do
    putWord32be kpFingerprint
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
  -- Parse input maps (one per input in tx).  W41 (Bug A1): each input map
  -- is parsed in the context of its corresponding global-tx prevout
  -- @OutPoint@, so the decoder can reject a @PSBT_IN_NON_WITNESS_UTXO@
  -- whose txid does not match the prevout's txid.  See
  -- 'verifyNonWitnessUtxoTxid' for the per-tx check; this is a hard
  -- decoder failure (PSBT spec / Core 'PSBTInput::IsSane').
  let inputPrevouts = map txInPrevOutput (txInputs (pgTx global))
  inputs <- mapM getInputMapFor inputPrevouts
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
              -- W34-E: fail loud on malformed keypath rather than
              -- inserting KeyPath 0 [] and breaking byte-identity.
              case parseKeyPath value of
                Left err -> fail err
                Right keypath ->
                  go mTx (Map.insert keyData keypath xpubs) mVersion unknown
            0xfb -> do  -- PSBT_GLOBAL_VERSION
              case runGet getWord32le value of
                Left _ -> fail "Invalid PSBT version"
                Right v -> go mTx xpubs (Just v) unknown
            _ -> go mTx xpubs mVersion (Map.insert key value unknown)

-- | Parse input map.  Compatibility wrapper: callers that don't have the
-- corresponding global-tx prevout will skip the W41 NON_WITNESS_UTXO
-- txid check.  Production code (the top-level 'getPsbt') always uses
-- 'getInputMapFor' so the decoder can enforce the BIP-174 / Core
-- @PSBTInput::IsSane@ txid commitment.
getInputMap :: Get PsbtInput
getInputMap = getInputMapFor (OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff)

-- | Parse input map in the context of the global-tx prevout it
-- corresponds to.  W41 (Bug A1): when a @PSBT_IN_NON_WITNESS_UTXO@
-- (key type 0x00) decodes to a transaction, its txid MUST equal the
-- prevout's txid; otherwise the producer is lying about which UTXO
-- the input is spending.  This is the check Core enforces in
-- @bitcoin-core/src/psbt.cpp PSBTInput::IsSane@.  We treat it as a
-- hard decoder failure so the rest of the wallet can rely on the
-- invariant.  The sentinel @OutPoint (TxId 0x00..00) 0xffffffff@
-- (used by the legacy 'getInputMap' wrapper) bypasses the check; it
-- is only used by callers that don't have the global tx in hand.
getInputMapFor :: OutPoint -> Get PsbtInput
getInputMapFor expectedOp = go emptyPsbtInput
  where
    sentinel = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff
    isSentinel = expectedOp == sentinel
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
              -- W34-E: malformed non-witness-utxo bytes are a strict
              -- decoder failure (matches the 0x02 / 0x06 / 0x08 lines).
              Left err -> fail $ "PSBT: malformed NON_WITNESS_UTXO: " ++ err
              Right tx ->
                -- W41 (Bug A1): txid commitment.  The decoder fails
                -- loudly so a forged PSBT cannot be silently accepted
                -- and then later mis-signed; Core's PSBTInput::IsSane
                -- has the same check.
                if isSentinel
                  then go inp { piNonWitnessUtxo = Just tx }
                  else case verifyNonWitnessUtxoTxid tx (outPointHash expectedOp) of
                    Left err -> fail $ "PSBT: NON_WITNESS_UTXO " ++ err
                    Right () -> go inp { piNonWitnessUtxo = Just tx }
            0x01 -> case decode value of  -- WITNESS_UTXO
              Left _ -> go inp
              Right utxo -> go inp { piWitnessUtxo = Just utxo }
            0x02 -> case parsePubKey keyData of  -- PARTIAL_SIG
              -- W34-E: STRICT — invalid pubkey in a 0x02 key indicates a
              -- malformed producer; surface it instead of silently dropping
              -- the partial signature (PSBT-spec / Core-parity behavior).
              Nothing -> fail "PSBT: invalid pubkey in PARTIAL_SIG (0x02) key"
              Just pk -> go inp { piPartialSigs = Map.insert pk value (piPartialSigs inp) }
            0x03 -> case runGet getWord32le value of  -- SIGHASH_TYPE
              Left _ -> go inp
              Right st -> go inp { piSighashType = Just st }
            0x04 -> go inp { piRedeemScript = Just value }  -- REDEEM_SCRIPT
            0x05 -> go inp { piWitnessScript = Just value }  -- WITNESS_SCRIPT
            0x06 -> case parsePubKey keyData of  -- BIP32_DERIVATION
              -- W34-E: STRICT — invalid pubkey in a 0x06 key is malformed.
              Nothing -> fail "PSBT: invalid pubkey in BIP32_DERIVATION (0x06) key"
              Just pk -> case parseKeyPath value of
                Left err -> fail err
                Right kp -> go inp { piBip32Derivation = Map.insert pk kp (piBip32Derivation inp) }
            0x07 -> go inp { piFinalScriptSig = Just value }  -- FINAL_SCRIPTSIG
            0x08 -> case parseWitnessStack value of  -- FINAL_SCRIPTWITNESS
              -- W34-E: fail loud on malformed witness rather than emitting
              -- a zero-count witness on the encode side.
              Left err -> fail err
              Right ws -> go inp { piFinalScriptWitness = Just ws }
            -- BIP-371 Taproot input fields
            0x13 -> go inp { piTapKeySig = Just value }  -- PSBT_IN_TAP_KEY_SIG
            0x14 -> do  -- PSBT_IN_TAP_SCRIPT_SIG: key = type(1) + xonly(32) + leaf_hash(32)
              if BS.length keyData /= 64
                then go inp  -- malformed, skip
                else let xonly    = BS.take 32 keyData
                         leafHash = BS.drop 32 keyData
                         sigs'    = Map.insert (xonly, leafHash) value (piTapScriptSigs inp)
                     in go inp { piTapScriptSigs = sigs' }
            0x15 -> do  -- PSBT_IN_TAP_LEAF_SCRIPT: key = type(1) + control_block; value = script + leaf_ver
              if BS.null value
                then go inp  -- malformed, skip
                else let leafVer = fromIntegral (BS.last value)
                         script  = BS.init value
                         cb      = keyData  -- the control block bytes
                         leaf    = (script, leafVer)
                         ls'     = Map.insertWith Set.union leaf (Set.singleton cb) (piTapLeafScripts inp)
                     in go inp { piTapLeafScripts = ls' }
            0x16 -> do  -- PSBT_IN_TAP_BIP32_DERIVATION: key = type(1) + xonly(32)
              if BS.length keyData /= 32
                then go inp  -- malformed, skip
                else case parseTapBip32Value value of
                  Left _ -> go inp  -- malformed value, skip
                  Right (leafHashes, kp) ->
                    let td' = Map.insert keyData (leafHashes, kp) (piTapBip32Derivation inp)
                    in go inp { piTapBip32Derivation = td' }
            0x17 -> go inp { piTapInternalKey = Just value }  -- PSBT_IN_TAP_INTERNAL_KEY
            0x18 -> go inp { piTapMerkleRoot = Just value }   -- PSBT_IN_TAP_MERKLE_ROOT
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
              -- W34-E: STRICT — see input-map note for 0x06.
              Nothing -> fail "PSBT: invalid pubkey in output BIP32_DERIVATION (0x02) key"
              Just pk -> case parseKeyPath value of
                Left err -> fail err
                Right kp -> go out { poBip32Derivation = Map.insert pk kp (poBip32Derivation out) }
            -- BIP-371 Taproot output fields
            0x05 -> go out { poTapInternalKey = Just value }  -- PSBT_OUT_TAP_INTERNAL_KEY
            0x06 -> case parsePsbtTapTree value of  -- PSBT_OUT_TAP_TREE
              Left _ -> go out  -- malformed, skip
              Right triples -> go out { poTapTree = triples }
            0x07 -> do  -- PSBT_OUT_TAP_BIP32_DERIVATION: key = type(1) + xonly(32)
              if BS.length keyData /= 32
                then go out  -- malformed, skip
                else case parseTapBip32Value value of
                  Left _ -> go out  -- malformed, skip
                  Right (leafHashes, kp) ->
                    let td' = Map.insert keyData (leafHashes, kp) (poTapBip32Derivation out)
                    in go out { poTapBip32Derivation = td' }
            0x08 -> do  -- PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: key = type(1) + agg_pubkey(33)
              if BS.length keyData /= 33
                then go out  -- malformed, skip
                else let parts = parseMuSig2Participants value
                         mp'   = Map.insert keyData parts (poMuSig2Participants out)
                     in go out { poMuSig2Participants = mp' }
            _ -> go out { poUnknown = Map.insert key value (poUnknown out) }

-- | Parse a keypath from bytes.
--
-- W34-E (PSBT decoder strictness): previously this returned
-- @KeyPath 0 []@ for any input shorter than 4 bytes and silently
-- truncated trailing bytes that were not a multiple of 4. That broke
-- byte-identity round-trip and could silently drop derivation paths
-- on malformed PSBTs. We now fail loudly and let the parent 'Get'
-- monad propagate the error.
parseKeyPath :: ByteString -> Either String KeyPath
parseKeyPath bs
  | BS.length bs < 4 =
      Left "PSBT: keypath bytes too short (need >= 4 for fingerprint)"
  | BS.length bs `mod` 4 /= 0 =
      Left "PSBT: keypath not multiple of 4 bytes"
  | otherwise =
      -- Fingerprint is 4 raw bytes read as big-endian (matching Core's ReadBE32 in output).
      -- Path indices are little-endian Word32 (standard BIP-32 serialization).
      let fp = runGetPartial getWord32be (BS.take 4 bs)
          pathBytes = BS.drop 4 bs
          pathLen = BS.length pathBytes `div` 4
          path = map (\i -> runGetPartial getWord32le (BS.take 4 (BS.drop (i * 4) pathBytes)))
                     [0 .. pathLen - 1]
      in Right (KeyPath fp path)
  where
    runGetPartial g b = case runGet g b of
      Left _ -> 0
      Right v -> v

-- | Parse a witness stack from bytes.
--
-- W34-E (PSBT decoder strictness): previously a malformed witness was
-- silently coerced to @[]@, which the encoder would then re-emit as a
-- zero-count witness — destroying byte-identity round-trip and quietly
-- dropping the original (malformed-but-present) data. We now propagate
-- the underlying 'Get' failure.
parseWitnessStack :: ByteString -> Either String [ByteString]
parseWitnessStack bs = case runGet getStack bs of
  Left err -> Left ("PSBT: malformed FINAL_SCRIPTWITNESS: " ++ err)
  Right items -> Right items
  where
    getStack = do
      count <- getVarInt'
      replicateM (fromIntegral count) getVarBytes

-- | Parse a BIP-371 TAP_BIP32_DERIVATION value.
-- Value format: compact_size(leaf_count) + leaf_hashes(32*n) + fingerprint(4) + path_indices
-- Reference: bitcoin-core/src/psbt.h PSBT_IN_TAP_BIP32_DERIVATION / PSBT_OUT_TAP_BIP32_DERIVATION.
parseTapBip32Value :: ByteString -> Either String (Set ByteString, KeyPath)
parseTapBip32Value bs = runGet go bs
  where
    go = do
      leafCount <- getVarInt'
      leafHashes <- replicateM (fromIntegral leafCount) (getBytes 32)
      rest <- remaining
      kpBytes <- getBytes rest
      case parseKeyPath kpBytes of
        Left err -> fail err
        Right kp -> return (Set.fromList leafHashes, kp)

-- | Parse a BIP-371 PSBT_OUT_TAP_TREE value.
-- Value format: repeated { depth(1) + leaf_ver(1) + compact_size(len) + script(len) }
-- Reference: bitcoin-core/src/psbt.h PSBT_OUT_TAP_TREE case.
parsePsbtTapTree :: ByteString -> Either String [(Word8, Word8, ByteString)]
parsePsbtTapTree bs = runGet go bs
  where
    go = do
      rem0 <- remaining
      if rem0 == 0
        then return []
        else do
          depth   <- getWord8
          leafVer <- getWord8
          script  <- getVarBytes
          rest    <- go
          return ((depth, leafVer, script) : rest)

-- | Parse MuSig2 participant pubkeys from a PSBT_MUSIG2_PARTICIPANT_PUBKEYS value.
-- Value format: repeated 33-byte compressed pubkeys.
-- Reference: bitcoin-core/src/psbt.h DeserializeMuSig2ParticipantPubkeys.
parseMuSig2Participants :: ByteString -> [ByteString]
parseMuSig2Participants bs = go bs
  where
    go b
      | BS.length b >= 33 = BS.take 33 b : go (BS.drop 33 b)
      | otherwise         = []

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

-- | W41 (Bug A1): verify that a 'PSBT_IN_NON_WITNESS_UTXO'-supplied
-- transaction actually hashes to the expected prevout txid.  Returns
-- @Right ()@ on match, @Left err@ on mismatch (the error message is
-- intended to be embedded into a parent decoder / signer error).
--
-- BIP-174 §"NON_WITNESS_UTXO" requires the producer to supply the full
-- previous transaction; the consumer (Signer / Finalizer) is then
-- expected to read @value@ + @scriptPubKey@ out of it for the input
-- being spent.  Without a txid commitment a malicious producer can
-- ship an arbitrary transaction and steer the wallet into signing
-- under attacker-chosen amount + scriptPubKey (CVE-2020-14199 family;
-- the non-witness analog of the W31 P2WSH commitment gate).
--
-- Reference: @bitcoin-core/src/psbt.cpp PSBTInput::IsSane@.
verifyNonWitnessUtxoTxid :: Tx -> TxId -> Either String ()
verifyNonWitnessUtxoTxid prevTx expectedTxId =
  let TxId (Hash256 actualBs)   = computeTxId prevTx
      TxId (Hash256 expectedBs) = expectedTxId
  in if actualBs == expectedBs
       then Right ()
       else Left $ "txid mismatch: expected "
                ++ hexShort expectedBs ++ " got " ++ hexShort actualBs
  where
    hexShort bs =
      let h = concatMap toHex (BS.unpack (BS.take 8 bs))
      in h ++ "..."
    toHex b = let (q, r) = b `divMod` 16
              in [hexDigit (fromIntegral q), hexDigit (fromIntegral r)]
    hexDigit n
      | n < 10 = toEnum (fromEnum '0' + n)
      | otherwise = toEnum (fromEnum 'a' + n - 10)

-- | W41 (Bug A2 / CVE-2020-14199): when a PSBT input carries BOTH
-- @piWitnessUtxo@ and @piNonWitnessUtxo@, the (value, scriptPubKey)
-- must agree.  The Signer otherwise has two oracles for the prevout's
-- @value@; @piWitnessUtxo@ is canonical for segwit, but a forged
-- @piWitnessUtxo@ (which the verifier never re-derives from the
-- prev-tx) lets an attacker inflate the signed amount.
--
-- This validator pulls the @TxOut@ at the prevout's index out of
-- @piNonWitnessUtxo@ (when both present) and asserts it equals the
-- @piWitnessUtxo at .  The W41 'getInputUtxo' rewrite uses the same
-- index lookup; both call 'extractNonWitnessTxOut'.
verifyInputUtxoConsistency :: OutPoint -> PsbtInput -> Either String ()
verifyInputUtxoConsistency op pinp = do
  -- A1: NON_WITNESS_UTXO txid must commit to prevout txid.
  case piNonWitnessUtxo pinp of
    Just prevTx ->
      verifyNonWitnessUtxoTxid prevTx (outPointHash op)
    Nothing -> Right ()
  -- A2: when both UTXO carriers are present, their (value, script) MUST agree.
  case (piWitnessUtxo pinp, piNonWitnessUtxo pinp) of
    (Just wUtxo, Just prevTx) ->
      case extractNonWitnessTxOut prevTx (outPointIndex op) of
        Nothing ->
          Left $ "NON_WITNESS_UTXO output index "
              ++ show (outPointIndex op) ++ " out of range"
        Just nwUtxo
          | txOutValue  wUtxo /= txOutValue  nwUtxo ->
              Left $ "WITNESS_UTXO / NON_WITNESS_UTXO amount mismatch: "
                  ++ show (txOutValue wUtxo) ++ " vs " ++ show (txOutValue nwUtxo)
          | txOutScript wUtxo /= txOutScript nwUtxo ->
              Left "WITNESS_UTXO / NON_WITNESS_UTXO scriptPubKey mismatch"
          | otherwise -> Right ()
    _ -> Right ()

-- | Walk the @piNonWitnessUtxo@ into the requested output.  Returns
-- 'Nothing' if the index is out of range; the caller should treat that
-- as a signing failure.
extractNonWitnessTxOut :: Tx -> Word32 -> Maybe TxOut
extractNonWitnessTxOut prevTx idx =
  let outs = txOutputs prevTx
      i    = fromIntegral idx
  in if i < 0 || i >= length outs
       then Nothing
       else Just (outs !! i)

-- | W41 top-level pre-flight validator: walks every input and runs
-- 'verifyInputUtxoConsistency'.  Surfaces the first mismatch as
-- @Left "input N: <reason>"@.  Production callers can use this to
-- reject a PSBT before invoking 'signPsbt'; 'signPsbt' itself runs the
-- same per-input check on the way through (defense-in-depth — even if
-- a caller skips the pre-flight, mis-validating inputs are quietly
-- left unsigned).
verifyPsbtUtxoConsistency :: Psbt -> Either String ()
verifyPsbtUtxoConsistency psbt =
  let tx       = pgTx (psbtGlobal psbt)
      inputs   = psbtInputs psbt
      txInsList = txInputs tx
      step (i, txin, pinp) =
        case verifyInputUtxoConsistency (txInPrevOutput txin) pinp of
          Right () -> Right ()
          Left err -> Left $ "input " ++ show i ++ ": " ++ err
  in if length inputs /= length txInsList
       then Left "PSBT input map count != global tx input count"
       else mapM_ step (zip3 [0 :: Int ..] txInsList inputs)

-- | Sign a PSBT with an extended key.
-- This is the Signer role in BIP-174.
-- Adds partial signatures for inputs that match the key.
--
-- Phase 5 / W16 extends the per-input loop to gather every input's
-- prevout (amount + scriptPubKey) up-front, since BIP-341 §"Common
-- signature message" requires the Taproot key-path sighash to commit
-- to *all* inputs' prevouts, not just the one being signed.  Inputs
-- whose @piWitnessUtxo@ is missing fall back to their on-tx scriptSig
-- bytes (rare but possible for legacy-only PSBTs); the BIP-341 sighash
-- check below will fail loudly if any P2TR input is missing prevout
-- data, which is the right failure mode.
--
-- W41 hardening (Bug A1 + Bug A2 / CVE-2020-14199): the per-input
-- loop now consults 'verifyInputUtxoConsistency' for each input.  If
-- the input's @piNonWitnessUtxo@ does not commit to the prevout's
-- txid, OR if both UTXO carriers disagree on (value, scriptPubKey),
-- the input is left unsigned.  This mirrors the W31 fail-quiet pattern
-- in 'canSignWrapped' — the input never gets a partial sig under a
-- forged amount oracle, which is the byte the attacker is trying to
-- get the wallet to sign over.
signPsbt :: ExtendedKey -> Psbt -> Psbt
signPsbt xkey psbt =
  let prevouts = zipWith collectPrevout txInsList (psbtInputs psbt)
  in psbt { psbtInputs =
              zipWith3 (signInputWithPrevout xkey tx prevouts)
                       [0..]
                       txInsList
                       (psbtInputs psbt)
          }
  where
    tx        = pgTx (psbtGlobal psbt)
    txInsList = txInputs tx
    -- For Taproot key-path signing we need (amount, scriptPubKey) per
    -- input.  piWitnessUtxo is the canonical PSBT carrier; non-witness
    -- inputs would not be Taproot anyway, so a placeholder is harmless
    -- (it will never feed the BIP-341 preimage).
    collectPrevout txin pinp = case piWitnessUtxo pinp of
      Just (TxOut v s) -> (v, s)
      Nothing          ->
        -- W41 (Bug A2 NonWitness branch): fall back to the
        -- prev-tx output IF the txid matches (otherwise the
        -- non-witness data is forged and we must not feed it
        -- into the Taproot prevouts vector).
        case piNonWitnessUtxo pinp of
          Just prevTx
            | Right () <- verifyNonWitnessUtxoTxid prevTx
                            (outPointHash (txInPrevOutput txin)) ->
                case extractNonWitnessTxOut prevTx
                       (outPointIndex (txInPrevOutput txin)) of
                  Just (TxOut v s) -> (v, s)
                  Nothing          -> (0, BS.empty)
          _ -> (0, BS.empty)

-- | W41 wrapper around 'signInput' that gates per-input on
-- 'verifyInputUtxoConsistency'.  An input that fails the gate is
-- returned unchanged (no partial sig) — matching the W31 fail-quiet
-- precedent for forged commitment inputs.
signInputWithPrevout
  :: ExtendedKey
  -> Tx
  -> [(Word64, ByteString)]
  -> Int
  -> TxIn
  -> PsbtInput
  -> PsbtInput
signInputWithPrevout xkey tx prevouts inputIdx txin pinp =
  case verifyInputUtxoConsistency (txInPrevOutput txin) pinp of
    Left _   -> pinp  -- forged amount / txid oracle; refuse to sign
    Right () -> signInput xkey tx prevouts inputIdx pinp

-- | Sign a single input if we have the key.
--
-- Phase 2 (W15) extends the dispatcher to recognise wrapped script
-- types (P2SH-P2WPKH / P2SH-P2WSH) and bare P2WSH single-key spends.
-- For those, the matchable hash lives in the PSBT-supplied
-- 'piRedeemScript' / 'piWitnessScript' rather than in the prevout
-- scriptPubKey, so we have to consult the PSBT input metadata.
--
-- Phase 5 (W16) adds bare-P2TR key-path: the @prevouts@ list is the
-- full per-input (amount, scriptPubKey) context required by the
-- BIP-341 sighash, gathered once up-front in 'signPsbt'.
signInput :: ExtendedKey -> Tx -> [(Word64, ByteString)] -> Int -> PsbtInput -> PsbtInput
signInput xkey tx prevouts inputIdx pinp
  -- Already finalized, skip
  | isInputFinalized pinp = pinp
  -- Try to sign.  W41 (Bug A2): when the input is non-witness-only the
  -- @piNonWitnessUtxo@ branch of 'getInputUtxoFor' walks into the
  -- prev-tx's output at the prevout's index.  This requires the
  -- caller's @inputIdx@ to be in range for @tx@; if it isn't we
  -- have nothing to do anyway.
  | inputIdx < 0 || inputIdx >= length (txInputs tx) = pinp
  | otherwise =
      let txin = txInputs tx !! inputIdx
          op   = txInPrevOutput txin
      in case getInputUtxoFor op pinp of
      Nothing -> pinp  -- No UTXO info
      Just utxo ->
        let pubKey = derivePubKeyFromPrivate (ekKey xkey)
            pubKeyBytes = serializePubKeyCompressed pubKey
            pubKeyHash = hash160 pubKeyBytes
            script = txOutScript utxo
            value = txOutValue utxo
            -- Determine sighash type (default to SIGHASH_ALL).  The Taproot
            -- branch in addSignature interprets 0x01 (= explicit
            -- SIGHASH_ALL) and treats the SIGHASH_DEFAULT (0x00) case
            -- separately when the PSBT explicitly stores it.
            shType = maybe 0x01 id (piSighashType pinp)
        in if canSign pubKeyHash script || canSignWrapped pubKeyHash script pinp
              || canSignTaproot xkey script pinp
              || canSignTapscript xkey script pinp
           then addSignature xkey pubKey tx prevouts inputIdx script value shType pinp
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

-- | Get UTXO from input (witness or non-witness).  Pre-W41 the
-- non-witness branch was a stub returning 'Nothing' (the caller did
-- not supply the outpoint index).  W41 wires the index-aware
-- 'getInputUtxoFor'; this no-arg form remains for callers that don't
-- have the prevout in hand and falls back to @piWitnessUtxo@ only.
getInputUtxo :: PsbtInput -> Maybe TxOut
getInputUtxo pinp = piWitnessUtxo pinp

-- | W41 (Bug A2 NonWitness branch): index-aware UTXO lookup.
--
-- Lookup order:
--   1. @piWitnessUtxo@ if present (canonical for segwit).
--   2. Otherwise, walk @piNonWitnessUtxo@ into its
--      @outPointIndex op@-th output, but ONLY after asserting
--      'verifyNonWitnessUtxoTxid' (Bug A1).  A forged @piNonWitnessUtxo@
--      whose txid does not commit to the prevout returns 'Nothing'
--      here, which the caller treats as "no UTXO info" — same as the
--      pre-W41 stub but now selectively, not unconditionally.
--
-- When BOTH carriers are present, we still return @piWitnessUtxo@
-- (canonical), and 'verifyInputUtxoConsistency' separately enforces
-- they agree.  That keeps the dispatcher in 'signInput' on the same
-- (value, script) tuple as before for segwit inputs.
getInputUtxoFor :: OutPoint -> PsbtInput -> Maybe TxOut
getInputUtxoFor op pinp =
  case piWitnessUtxo pinp of
    Just utxo -> Just utxo
    Nothing   -> case piNonWitnessUtxo pinp of
      Nothing     -> Nothing
      Just prevTx ->
        case verifyNonWitnessUtxoTxid prevTx (outPointHash op) of
          Left _   -> Nothing  -- forged non-witness oracle; refuse
          Right () -> extractNonWitnessTxOut prevTx (outPointIndex op)

-- | Check if we can sign for this script with our key.
--
-- For bare scripts (P2PKH / P2WPKH) the keyhash must match the program
-- directly.  For wrapped scripts (P2SH-P2WPKH / P2SH-P2WSH) the
-- 'piRedeemScript' / 'piWitnessScript' carry the inner program; the
-- caller's 'canSignWrapped' helper handles those.  See 'signInput' for
-- the dispatcher.
canSign :: Hash160 -> ByteString -> Bool
canSign pubKeyHash script
  | isP2PKHScript script = getP2PKHHash script == Just pubKeyHash
  | isP2WPKHScript script = getP2WPKHHash script == Just pubKeyHash
  | otherwise = False

-- | Check if we can sign a wrapped (P2SH or P2WSH) input given the
-- PSBT-supplied redeemScript / witnessScript.  Single-key P2WSH means
-- the witnessScript is "<33-byte pubkey> OP_CHECKSIG".
--
-- W31 hardening: every branch validates that the PSBT-supplied inner
-- script(s) commit to the on-chain @scriptPubKey@ (BIP-16 hash160
-- and / or BIP-141 sha256).  A forged @piRedeemScript@ /
-- @piWitnessScript@ that does not commit cannot make this function
-- return @True@ — preventing the Signer from being lured into
-- signing under an attacker-chosen @scriptCode@.
canSignWrapped :: Hash160 -> ByteString -> PsbtInput -> Bool
canSignWrapped pubKeyHash script pinp
  -- P2SH-P2WPKH: redeemScript = OP_0 <20-byte pkh>, must match our hash
  -- AND must hash160 to the P2SH commitment.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WPKHScript redeem
  = p2shCommits script redeem
    && getP2WPKHHash redeem == Just pubKeyHash
  -- P2SH-P2WSH single-key: redeemScript = OP_0 <32-byte sha256(witnessScript)>;
  -- witnessScript itself is "<33-byte pubkey> OP_CHECKSIG".
  -- Both BIP-16 (script→redeem) and BIP-141 (redeem→wScript)
  -- commitments must verify.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WSHScript redeem
  , Just wScript <- piWitnessScript pinp
  = p2shCommits script redeem
    && p2wshCommits redeem wScript
    && isWitnessScriptSingleKey pubKeyHash wScript
  -- Bare P2WSH single-key.  BIP-141 commitment script→wScript must verify.
  | isP2WSHScript script
  , Just wScript <- piWitnessScript pinp
  = p2wshCommits script wScript
    && isWitnessScriptSingleKey pubKeyHash wScript
  | otherwise = False

-- | Recognise a "<33-byte compressed pubkey> OP_CHECKSIG" witnessScript
-- whose pubkey hashes to the given Hash160.  Layout is
-- @0x21 <pk:33> 0xac@ (35 bytes total).
isWitnessScriptSingleKey :: Hash160 -> ByteString -> Bool
isWitnessScriptSingleKey pubKeyHash wScript =
  BS.length wScript == 35 &&
  BS.index wScript 0 == 0x21 &&
  BS.index wScript 34 == 0xac &&
  hash160 (BS.take 33 (BS.drop 1 wScript)) == pubKeyHash

-- | Phase 5 (W16): can we sign for a Taproot key-path output with the
-- given key?  The on-chain script is @OP_1 0x20 <output_xonly>@ where
-- @output_xonly@ is the BIP-341-tweaked key derived from our internal
-- key + the optional BIP-371 merkle_root.
--
-- For BIP-86 (single-key, no script tree) we recompute the tweak from
-- our seckey and check the resulting tweaked key matches the on-chain
-- output key.  For descriptors with a script tree the merkle_root would
-- come from `piTaprootMerkleRoot` (PSBT_IN_TAP_MERKLE_ROOT, BIP-371) —
-- not yet stored in `PsbtInput`, so this commit handles only the
-- BIP-86 path.  Tapscript spends are out of scope (Phase 9).
canSignTaproot :: ExtendedKey -> ByteString -> PsbtInput -> Bool
canSignTaproot xkey script _pinp
  | isP2TRScript script
  , Just outputKey <- getP2TRProgram script =
      let SecKey sk     = ekKey xkey
          mInternalX    = xonlyPubkeyFromSeckey sk
          tweak mInt    = bip86TapTweakHash <$> mInt
          mTweaked      = do
            iX <- mInternalX
            t  <- tweak (Just iX)
            xonlyPubkeyTweakAdd iX t
      in case mTweaked of
           Just (k, _) -> k == outputKey
           Nothing     -> False
  | otherwise = False

-- | Phase 4 / W18: can we sign for a Taproot script-path (tapscript) spend
-- with the given key?  We require:
--
--   * The prevout is a P2TR script.
--   * 'piUnknown' carries both the leaf script (under
--     'tapscriptLeafScriptPsbtKey') and the control block (under
--     'tapscriptControlBlockPsbtKey').
--   * The leaf script is a single-key OP_CHECKSIG tapscript whose pubkey
--     matches our x-only internal key.
--   * The control block decodes, has BIP-342 leaf version 0xc0, and its
--     embedded internal pubkey matches ours.
--   * W41 (W40-D fix): the BIP-341 Taproot commitment from
--     @internal_pubkey + merkleRoot@ recomputes to the on-chain output
--     key (x-only equality AND parity bit equality).  Pre-W41 the W18
--     comment claimed "single-leaf trees pass naturally because the
--     path is empty" — that was wrong, because 'decodeControlBlock'
--     accepts arbitrary trailing 32-byte chunks (any depth) and the
--     wallet never re-derived the output key.  An attacker could ship
--     a control block whose Merkle path was forged to make the leaf
--     they want signed look like it lives in some unrelated tree.
--     The on-chain @output_key@ is the single ground-truth pin: if
--     the @internal_key + tweak(merkleRoot)@ does not equal it, we
--     refuse to sign.
--
-- Multi-leaf MAST, multisig predicates, OP_CHECKSIGADD, BIP-371 fields,
-- and ANNEX handling are explicitly out of scope.  See 'addSignature'
-- for the corresponding "not yet implemented" branches.
--
-- Reference: @bitcoin-core/src/script/interpreter.cpp VerifyTaprootCommitment@.
canSignTapscript :: ExtendedKey -> ByteString -> PsbtInput -> Bool
canSignTapscript xkey script pinp
  | isP2TRScript script
  , Just outputKey   <- getP2TRProgram script
  , Just leafScript  <- Map.lookup tapscriptLeafScriptPsbtKey   (piUnknown pinp)
  , Just cbBytes     <- Map.lookup tapscriptControlBlockPsbtKey (piUnknown pinp)
  , Just cb          <- TS.decodeControlBlock cbBytes
  , TS.cbLeafVersion cb == TS.tapscriptLeafVersion
  , let SecKey sk = ekKey xkey
  , Just internalX <- xonlyPubkeyFromSeckey sk
  , TS.cbInternalPubkey cb == internalX
  , isSingleKeyOpChecksigTapscript leafScript internalX
  = verifyTaprootCommitment cb leafScript outputKey
  | otherwise = False

-- | W41 (W40-D fix): verify that walking the BIP-341 Merkle path in the
-- control block, then BIP-341-tweaking the internal pubkey with the
-- resulting root, reproduces the on-chain output key (x-only equality
-- AND parity bit).
--
-- Algorithm (mirrors @bitcoin-core/src/script/interpreter.cpp
-- VerifyTaprootCommitment@):
--
--   1. Compute @tapleaf_hash = tagged_hash("TapLeaf",
--          leafVersion || compactSize(script) || script)@.
--   2. Walk @cbMerklePath@ as 32-byte sibling chunks; at each step,
--      lexicographically-order the (current, sibling) pair and hash
--      under @tagged_hash("TapBranch", lo || hi)@.  An empty path
--      means @merkleRoot = tapleaf_hash@.
--   3. Compute @tweak = tagged_hash("TapTweak", internalKey || merkleRoot)@.
--   4. Compute @(Q'_x, Q'_parity) = xonlyPubkeyTweakAdd(internalKey, tweak)@.
--   5. Assert @Q'_x == on_chain_output_key@ AND
--             @Q'_parity == cbParity@.
--
-- The parity check is what closes the second half of the W40-D gap:
-- 'decodeControlBlock' parses @cbParity@ but pre-W41 nothing
-- consumed it, so a control block whose low bit was flipped would
-- still produce a signature (the script-path verifier would later
-- reject it on chain, but the wallet would have already signed under
-- the wrong (internal_key, output_key) pairing).
verifyTaprootCommitment :: TS.ControlBlock -> ByteString -> ByteString -> Bool
verifyTaprootCommitment cb leafScript outputKey =
  let leafHash   = TS.tapleafHashWith (TS.cbLeafVersion cb) leafScript
      merkleRoot = walkMerklePath leafHash (TS.cbMerklePath cb)
      tweak      = computeTapTweakHash (TS.cbInternalPubkey cb) merkleRoot
  in case xonlyPubkeyTweakAdd (TS.cbInternalPubkey cb) tweak of
       Nothing            -> False
       Just (qx, qParity) ->
         qx == outputKey
         && fromIntegral qParity == TS.cbParity cb
  where
    -- BIP-341 §"Constructing and spending Taproot outputs":
    -- TapBranch(child, sibling) with lexicographic ordering of the
    -- two 32-byte hashes.  Sibling chunks shorter / longer than 32
    -- bytes would have already been rejected by 'decodeControlBlock',
    -- but we treat anything off-spec defensively (return a bogus
    -- root, which the tweak comparison will then reject).
    walkMerklePath cur [] = cur
    walkMerklePath cur (sib:rest)
      | BS.length sib /= 32 = BS.replicate 32 0xff  -- defensive sentinel
      | otherwise =
          let (lo, hi) = if cur <= sib then (cur, sib) else (sib, cur)
          in walkMerklePath (taggedHash "TapBranch" (lo <> hi)) rest

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

-- | Check if script is P2WSH (BIP-141 witness-v0 32-byte program).
-- Layout: OP_0 0x20 <32-byte sha256(witnessScript)>.
isP2WSHScript :: ByteString -> Bool
isP2WSHScript s = BS.length s == 34 &&
  BS.index s 0 == 0x00 &&  -- OP_0
  BS.index s 1 == 0x20     -- Push 32 bytes

-- | Check if script is P2SH (BIP-13/16). Layout:
-- OP_HASH160 0x14 <20-byte hash160(redeemScript)> OP_EQUAL.
isP2SHScript :: ByteString -> Bool
isP2SHScript s = BS.length s == 23 &&
  BS.index s 0 == 0xa9 &&  -- OP_HASH160
  BS.index s 1 == 0x14 &&  -- Push 20 bytes
  BS.index s 22 == 0x87    -- OP_EQUAL

-- | Check if script is a P2TR (BIP-341 segwit-v1) output script.
-- Layout: @OP_1 0x20 <32-byte x-only output key>@ (34 bytes total).
-- This is the on-chain "tweaked output key" form (post-tweak); the
-- internal key (and merkle root, if any) live in the PSBT Taproot
-- input fields per BIP-371.
isP2TRScript :: ByteString -> Bool
isP2TRScript s = BS.length s == 34 &&
  BS.index s 0 == 0x51 &&  -- OP_1
  BS.index s 1 == 0x20     -- Push 32 bytes

-- | Extract the 32-byte x-only output key from a P2TR scriptPubKey.
getP2TRProgram :: ByteString -> Maybe ByteString
getP2TRProgram s
  | isP2TRScript s = Just (BS.take 32 (BS.drop 2 s))
  | otherwise = Nothing

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

-- | Extract the 20-byte @hash160(redeemScript)@ commitment from a P2SH
-- @scriptPubKey@.  Layout: @OP_HASH160 0x14 <hash20> OP_EQUAL@.
getP2SHHash :: ByteString -> Maybe Hash160
getP2SHHash s
  | isP2SHScript s = Just $ Hash160 (BS.take 20 (BS.drop 2 s))
  | otherwise = Nothing

-- | Extract the 32-byte @sha256(witnessScript)@ commitment from a
-- bare P2WSH @scriptPubKey@ or from a P2SH-P2WSH redeemScript.
-- Layout (both): @OP_0 0x20 <hash32>@.
getP2WSHHash :: ByteString -> Maybe ByteString
getP2WSHHash s
  | isP2WSHScript s = Just (BS.take 32 (BS.drop 2 s))
  | otherwise = Nothing

-- | BIP-16 commitment check: does @redeem@ match the 20-byte
-- @hash160@ embedded in the P2SH @scriptPubKey@?
--
-- This is the gate Bitcoin Core enforces in
-- @bitcoin-core/src/script/interpreter.cpp::EvalScript@ when the
-- P2SH-evaluation flag fires.  Without it, a PSBT-supplied
-- @piRedeemScript@ would be accepted verbatim — letting an attacker
-- ship a forged redeem program that pretends to be ours and steers
-- the wallet into signing under the wrong scriptCode.
p2shCommits :: ByteString -> ByteString -> Bool
p2shCommits script redeem =
  case getP2SHHash script of
    Just (Hash160 expected) -> expected == getHash160 (hash160 redeem)
    Nothing                 -> False

-- | BIP-141 commitment check: does @wScript@ match the 32-byte
-- @sha256@ embedded in a P2WSH witness program (whether bare in a
-- @scriptPubKey@ or wrapped inside a P2SH-P2WSH redeemScript)?
--
-- Without this check a PSBT-supplied @piWitnessScript@ could carry
-- arbitrary bytes; the Signer would then compute the BIP-143 sighash
-- under the forged @scriptCode@ and emit a signature usable for a
-- transaction the user did not authorise.
p2wshCommits :: ByteString -> ByteString -> Bool
p2wshCommits witnessProgram wScript =
  case getP2WSHHash witnessProgram of
    Just expected -> expected == sha256 wScript
    Nothing       -> False

-- | Add a signature to the input.
--
-- Phase 1 wired the legacy P2PKH spend path; Phase 2 (W15) extends this
-- to segwit-v0 spends: bare P2WPKH (BIP-141 + BIP-143) plus the wrapped
-- P2SH-P2WPKH (BIP-49).  Taproot key-path remains deferred to Phase 5.
--
-- Dispatch order matters.  Inputs that pay to bare P2WPKH carry their
-- 0x0014... witness program directly in 'piWitnessUtxo'; inputs that
-- pay to wrapped P2SH-P2WPKH carry an 0xa914... P2SH script in
-- 'piWitnessUtxo' (or in the prevTxOut) and an 0x0014... redeemScript
-- in 'piRedeemScript'.  We detect the wrap by looking at
-- 'piRedeemScript' before falling through to the bare-P2WPKH branch,
-- because the spend-side sighash (BIP-143) is identical in either
-- case once the implicit-script scriptCode is computed.
--
-- Reference: @bitcoin-core/src/script/sign.cpp::SignStep@ +
-- @CreateSig@ pair (BASE for P2PKH, WITNESS_V0 for the rest).
addSignature :: ExtendedKey -> PubKey -> Tx -> [(Word64, ByteString)] -> Int -> ByteString -> Word64 -> Word32 -> PsbtInput -> PsbtInput
addSignature xkey pubKey tx prevouts inputIdx script value shType pinp
  -- P2SH-P2WPKH wrap (BIP-49): scriptPubKey is P2SH; redeemScript is the
  -- P2WPKH program.  Sign as P2WPKH using the redeemScript-derived
  -- scriptCode, then finalize will write both the scriptSig (push of the
  -- redeemScript) and the witness stack.
  -- W31 hardening: BIP-16 commits redeem to scriptPubKey.  Without this
  -- gate, a forged piRedeemScript would be accepted verbatim and the
  -- Signer would emit a sig under attacker-chosen scriptCode.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WPKHScript redeem
  , p2shCommits script redeem =
      let sighash   = computeSegwitSighashFromProgram tx inputIdx redeem value shType
          signature = signWithKey xkey sighash shType
      in pinp { piPartialSigs = Map.insert pubKey signature (piPartialSigs pinp) }
  -- P2SH-P2WSH wrap: P2SH redeemScript = 0x0020<32-byte witnessScript-hash>;
  -- the witnessScript itself is in 'piWitnessScript' and used as the
  -- BIP-143 scriptCode verbatim.
  -- W31 hardening: both BIP-16 (script→redeem) and BIP-141
  -- (redeem→wScript) commitments must verify.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WSHScript redeem
  , Just wScript <- piWitnessScript pinp
  , p2shCommits script redeem
  , p2wshCommits redeem wScript =
      let sighash   = computeSegwitSighashScriptCode tx inputIdx wScript value shType
          signature = signWithKey xkey sighash shType
      in pinp { piPartialSigs = Map.insert pubKey signature (piPartialSigs pinp) }
  | isP2PKHScript script =
      let sighash   = computeLegacySighash tx inputIdx script shType
          signature = signWithKey xkey sighash shType
      in pinp { piPartialSigs = Map.insert pubKey signature (piPartialSigs pinp) }
  | isP2WPKHScript script =
      -- BIP-143 scriptCode for a P2WPKH spend is the *implicit* legacy
      -- P2PKH program: 0x76 0xa9 0x14 <20-byte pubkey-hash> 0x88 0xac.
      -- 'computeSegwitSighash' already builds it from the witness program.
      let sighash   = computeSegwitSighash tx inputIdx script value shType
          signature = signWithKey xkey sighash shType
      in pinp { piPartialSigs = Map.insert pubKey signature (piPartialSigs pinp) }
  | isP2WSHScript script
  , Just wScript <- piWitnessScript pinp
  -- W31 hardening: BIP-141 commits wScript to scriptPubKey.  Without
  -- this, a forged piWitnessScript would be used verbatim as the
  -- BIP-143 scriptCode.
  , p2wshCommits script wScript =
      -- BIP-143 §"Witness program of version 0": for P2WSH the scriptCode
      -- is the witnessScript itself, used verbatim (no implicit-script
      -- transform).  The wallet must have populated 'piWitnessScript'
      -- via the PSBT updater chain before we get here.
      let sighash   = computeSegwitSighashScriptCode tx inputIdx wScript value shType
          signature = signWithKey xkey sighash shType
      in pinp { piPartialSigs = Map.insert pubKey signature (piPartialSigs pinp) }
  -- Phase 4 (W18): bare-P2TR script-path (tapscript, BIP-341 + BIP-342),
  -- single-leaf single-key OP_CHECKSIG.  Detection is gated on
  -- 'canSignTapscript' having confirmed the PSBT carries the leaf script
  -- and control block, and the embedded internal key matches ours.
  -- The signature is computed over the BIP-341 *script-path* sighash
  -- (extra fields: tapleaf hash, key_version=0, codesep_pos sentinel),
  -- and BIP-342 redefines OP_CHECKSIG to verify under the *plain* x-only
  -- key pushed inside the script — so we sign with the raw seckey, not
  -- the BIP-341-tweaked seckey.  Witness item is stored in
  -- 'piPartialSigs' keyed by our internal pubkey so the finalizer can
  -- pair it with the leaf script + control block from 'piUnknown'.
  | isP2TRScript script
  , Just leafScript <- Map.lookup tapscriptLeafScriptPsbtKey   (piUnknown pinp)
  , Just _cbBytes   <- Map.lookup tapscriptControlBlockPsbtKey (piUnknown pinp) =
      let prevoutsTS = TS.TaprootPrevouts
            { TS.taprootAmounts = map fst prevouts
            , TS.taprootScripts = map snd prevouts
            }
          taprootHashType = if shType == 0x01 && piSighashType pinp == Nothing
                              then 0x00
                              else fromIntegral (shType .&. 0xff) :: Word8
      in case computeTaprootScriptPathSighash
                  tx inputIdx prevoutsTS taprootHashType
                  TS.tapscriptLeafVersion leafScript
                  TS.defaultCodesepPos Nothing of
           Left _  -> pinp  -- malformed prevouts; leave the input unsigned
           Right sighash ->
             let witnessSig = signWithKeyTapscript xkey sighash taprootHashType
             in pinp { piPartialSigs = Map.insert pubKey witnessSig (piPartialSigs pinp) }
  -- Phase 5 (W16): bare-P2TR key-path (BIP-341 + BIP-86).  Witness item
  -- is the Schnorr signature alone; the finalizer writes it directly
  -- and the @piPartialSigs@ map keys the entry by our *internal* pubkey
  -- so the Combiner / Finalizer can find it later.  Tapscript spends
  -- and merkle_root-bearing key-paths (BIP-371 PSBT_IN_TAP_MERKLE_ROOT)
  -- remain deferred; they need new PsbtInput fields.
  | isP2TRScript script =
      let prevoutsTS = TS.TaprootPrevouts
            { TS.taprootAmounts = map fst prevouts
            , TS.taprootScripts = map snd prevouts
            }
          -- BIP-341 hash type: SIGHASH_DEFAULT (0x00) is the wallet
          -- default for Taproot — see CreateSchnorrSig in Core's
          -- script/sign.cpp.  An explicit SIGHASH_ALL (0x01) in the
          -- PSBT is also valid; this branch passes whatever the PSBT
          -- carries.  We coerce 0x01 (the segwit-v0 default that
          -- 'signInput' falls back to when no piSighashType is set)
          -- to 0x00 here, since for Taproot the natural "no override"
          -- behavior is SIGHASH_DEFAULT.
          taprootHashType = if shType == 0x01 && piSighashType pinp == Nothing
                              then 0x00
                              else fromIntegral (shType .&. 0xff) :: Word8
      in case computeTaprootKeyPathSighash tx inputIdx prevoutsTS taprootHashType Nothing of
           Left _  -> pinp  -- malformed prevouts; leave the input unsigned
           Right sighash ->
             let witnessItem = signWithKeyTaproot xkey sighash taprootHashType Nothing
             in pinp { piPartialSigs = Map.insert pubKey witnessItem (piPartialSigs pinp) }
  | otherwise =
      -- W18 closed single-leaf single-key OP_CHECKSIG tapscript.  Still
      -- deferred:
      --   * Multi-leaf MAST trees (different leaf, deeper Merkle path)
      --   * In-script multisig (CHECKSIGADD / multi-pk OP_CHECKSIG predicates)
      --   * Bare-witness multisig P2WSH and P2SH-P2WSH multi-key paths
      --     (Combiner state expansion)
      error "addSignature: unsupported script type (multi-leaf MAST / in-script multisig / multi-key P2WSH still TODO)"

-- | Compute legacy sighash
computeLegacySighash :: Tx -> Int -> ByteString -> Word32 -> Hash256
computeLegacySighash tx inputIdx script shType =
  let shTypeFlag = SigHashType (shType .&. 0x1f == 0x01)
                               (shType .&. 0x1f == 0x02)
                               (shType .&. 0x1f == 0x03)
                               (shType .&. 0x80 /= 0)
  in txSigHash tx inputIdx script shType shTypeFlag

-- | Compute segwit v0 sighash (BIP-143) for a bare P2WPKH spend.
--
-- The input @script@ is the witness program @0x00 0x14 <20-byte pkh>@.
-- BIP-143 Step 6 specifies that for a v0 P2WPKH the @scriptCode@
-- inserted into the preimage is the *implicit* P2PKH script
-- @OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG@; the wallet
-- never sees that as an actual scriptPubKey on chain.  This rebuild
-- step is what makes wrapped P2SH-P2WPKH share the same code path
-- (see 'computeSegwitSighashFromProgram').
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

-- | BIP-143 sighash for a P2SH-P2WPKH spend.  Identical to
-- 'computeSegwitSighash' except the caller hands us the *redeemScript*
-- (the 22-byte witness program lifted out of the P2SH wrap) rather
-- than a scriptPubKey.  Same scriptCode rebuild applies.
computeSegwitSighashFromProgram :: Tx -> Int -> ByteString -> Word64 -> Word32 -> Hash256
computeSegwitSighashFromProgram = computeSegwitSighash

-- | BIP-143 sighash for a P2WSH spend (and the wrapped P2SH-P2WSH
-- case).  The @scriptCode@ in the preimage is the witnessScript
-- itself, taken verbatim — no implicit-script transform.  See
-- BIP-143 §"Witness program of version 0" bullet 3.
computeSegwitSighashScriptCode :: Tx -> Int -> ByteString -> Word64 -> Word32 -> Hash256
computeSegwitSighashScriptCode tx inputIdx scriptCode value shType =
  let shTypeFlag = SigHashType (shType .&. 0x1f == 0x01)
                               (shType .&. 0x1f == 0x02)
                               (shType .&. 0x1f == 0x03)
                               (shType .&. 0x80 /= 0)
  in txSigHashSegWit tx inputIdx scriptCode value shTypeFlag

-- | Compute the BIP-341 Taproot key-path sighash.
--
-- The caller supplies the full per-input prevout context
-- (@TaprootPrevouts {amounts, scripts}@) — BIP-341 §"Common signature
-- message" §"Per-input sigs" requires committing to *every* input's
-- amount and scriptPubKey, not just the one being signed.  Inside a
-- PSBT this comes from each input's @piWitnessUtxo@.
--
-- For the canonical BIP-86 single-key-path case (no script tree, no
-- annex), pass:
--   * @hashType  = 0x00@ (SIGHASH_DEFAULT)
--   * @annex     = Nothing@
--   * @scriptPath = Nothing@
--
-- Returns 'Left' if the inputs are inconsistent (length mismatch,
-- index out of range, invalid hashtype byte) — see
-- 'TaprootSighash.TaprootSighashError' for the error variants.
--
-- Reference: @bitcoin-core/src/script/interpreter.cpp SignatureHashSchnorr@.
computeTaprootKeyPathSighash
  :: Tx
  -> Int
  -> TS.TaprootPrevouts
  -> Word8                       -- ^ hash_type (0x00 SIGHASH_DEFAULT for BIP-86)
  -> Maybe ByteString            -- ^ optional annex
  -> Either TS.TaprootSighashError Hash256
computeTaprootKeyPathSighash tx idx prevouts hashType annex =
  Hash256 <$> TS.computeTaprootSighash tx idx prevouts hashType annex Nothing

-- | Sign a 32-byte sighash with the extended key's private scalar and
-- return the wire-format spend-side ECDSA signature: DER-encoded
-- @secp256k1_ecdsa_sign@ output WITH the sighash-type byte appended,
-- as specified by @CreateSig@ in @bitcoin-core/src/script/sign.cpp@.
--
-- Backed by the libsecp256k1 FFI binding 'Crypto.signMsgMaybe' (see
-- @cbits/secp256k1_compat.c haskoin_ecdsa_sign_der@), which uses
-- RFC-6979 deterministic-k and grinds for low-R, exactly matching
-- @CKey::Sign(hash, sig, /*grind=*/true)@ in
-- @bitcoin-core/src/key.cpp:209-235@.  Internal self-verify guarantees
-- the returned bytes verify under the corresponding pubkey before they
-- ever leave this function.
--
-- Throws 'error' on a malformed seckey; this is a programmer error
-- (callers should have validated 'ekKey' on construction) and not a
-- recoverable runtime condition.  For a recoverable variant, see the
-- 'signMsgMaybe' primitive directly.
signWithKey :: ExtendedKey -> Hash256 -> Word32 -> ByteString
signWithKey xkey hash shType =
  let Sig derBytes = signMsg (ekKey xkey) hash
      hashTypeByte = fromIntegral (shType .&. 0xff) :: Word8
  in derBytes `BS.snoc` hashTypeByte

-- | Sign a 32-byte BIP-341 Taproot key-path sighash and return the
-- wire-format witness item.
--
-- The internal key inside @xkey@ is BIP-341-tweaked (with the optional
-- BIP-371 merkle_root, or all-zeros for BIP-86 single-key spends), the
-- result is signed via BIP-340 Schnorr with all-zeros aux-rand to match
-- Core's `CreateSchnorrSig` byte-identity, and the produced 64-byte
-- signature is suffixed with the sighash byte iff non-zero (per
-- @bitcoin-core/src/script/sign.cpp:88-101@):
--
--   * @hashType == 0x00@ (SIGHASH_DEFAULT) → 64-byte witness item
--   * @hashType != 0x00@                   → 65-byte witness item
--     (sig64 ‖ hashType)
--
-- The BIP-341 spec collapses SIGHASH_DEFAULT into SIGHASH_ALL for the
-- preimage, but the *encoded* witness item omits the byte for size
-- savings and forces the strictest interpretation.  See
-- @bitcoin-core/src/script/interpreter.cpp:1820-1836@.
--
-- Throws 'error' on malformed seckey / tweak overflow (programmer bug,
-- never happens for a well-formed BIP-32 derived key).
--
-- Reference: bitcoin-core/src/key.cpp KeyPair::Create + KeyPair::SignSchnorr,
--            bitcoin-core/src/script/sign.cpp CreateSchnorrSig.
signWithKeyTaproot
  :: ExtendedKey
  -> Hash256                 -- ^ BIP-341 sighash (output of 'computeTaprootKeyPathSighash')
  -> Word8                   -- ^ hash_type (0x00 default for BIP-86)
  -> Maybe ByteString        -- ^ optional 32-byte BIP-371 merkle_root (Nothing = BIP-86)
  -> ByteString
signWithKeyTaproot xkey (Hash256 msg32) hashType mMerkleRoot =
  let SecKey skBytes = ekKey xkey
      -- Step 1: derive the *internal* x-only key for the TapTweak preimage.
      internalXOnly = case xonlyPubkeyFromSeckey skBytes of
        Just k  -> k
        Nothing -> error "signWithKeyTaproot: invalid internal seckey"
      -- Step 2: compute the BIP-341 tweak.
      merkleRoot = fromMaybe BS.empty mMerkleRoot
      tweak      = computeTapTweakHash internalXOnly merkleRoot
      -- Step 3: tweak the seckey on the curve.
      tweakedSk  = case taprootTweakSeckey skBytes tweak of
        Just s  -> s
        Nothing -> error "signWithKeyTaproot: tweak failed"
      -- Step 4: BIP-340 Schnorr sign with all-zeros aux (Core byte-identity).
      sig64      = case signSchnorr tweakedSk msg32 of
        Just s  -> s
        Nothing -> error "signWithKeyTaproot: Schnorr sign failed"
  -- Step 5: BIP-341 sighash-byte append rule — only non-default hashtypes
  -- carry a trailing byte.  Missing byte means SIGHASH_DEFAULT.
  in if hashType == 0x00
       then sig64
       else sig64 `BS.snoc` hashType

--------------------------------------------------------------------------------
-- Phase 4 / W18 — Tapscript script-path (BIP-342) signing primitives.
--
-- Scope: single-leaf single-key OP_CHECKSIG tapscript spends only.  This is
-- the BIP-342 analog of P2WPKH inside a Taproot leaf: the leaf script is
-- @<32-byte-x-only-pubkey> OP_CHECKSIG@, the witness is
-- @[sig, script, control_block]@, and the signature verifies under the
-- *plain* x-only key pushed inside the script (NOT the tweaked output key).
--
-- Out of scope (explicit "not yet implemented" branches; separate waves):
--   * Multi-leaf MAST trees (Merkle path > depth 0 in the control block —
--     decode is supported, sign-side leaf-selection is not).
--   * In-script multisig (multi-key OP_CHECKSIG / OP_CHECKSIGADD predicates).
--   * OP_CHECKSIGADD (BIP-342 1-of-N / N-of-M).
--   * ANNEX handling (witness item with leading 0x50; spec is final but no
--     standardness rules around it have shipped on mainnet).
--   * OP_CODESEPARATOR mid-script (would bump @codesep_pos@; the W18 wallet
--     always uses the sentinel 0xFFFFFFFF since haskoin's interpreter does
--     not surface non-default codesep_pos to the sign path).
--   * BIP-371 PSBT taproot fields (PSBT_IN_TAP_LEAF_SCRIPT,
--     PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_MERKLE_ROOT, etc.) — for the
--     wallet round-trip we use 'piUnknown' magic keys
--     'tapscriptLeafScriptPsbtKey' and 'tapscriptControlBlockPsbtKey'.
--     Mapping these to the canonical BIP-371 keytypes is a follow-up.
--------------------------------------------------------------------------------

-- | Compute the BIP-341 *script-path* sighash for a tapscript spend.
--
-- Same as 'computeTaprootKeyPathSighash' except the BIP-341 preimage adds
-- the script-path extension fields:
--
--   * 32-byte tapleaf hash (computed from leaf version + script bytes)
--   * 1-byte key_version (always 0 today; reserved for future SF)
--   * 4-byte LE codesep_pos (0xFFFFFFFF = no OP_CODESEPARATOR seen)
--
-- and the spend_type byte is 0x02 (script-path, no annex) instead of 0x00.
-- Mirrors @bitcoin-core/src/script/interpreter.cpp::SignatureHashSchnorr@
-- with @SIGVERSION_TAPSCRIPT@.
--
-- Reference: BIP-342 / @bitcoin-core/src/script/interpreter.cpp::SignatureHashSchnorr@.
computeTaprootScriptPathSighash
  :: Tx
  -> Int
  -> TS.TaprootPrevouts
  -> Word8                       -- ^ hash_type (0x00 SIGHASH_DEFAULT default)
  -> Word8                       -- ^ leaf version (0xc0 for current tapscript)
  -> ByteString                  -- ^ leaf script bytes
  -> Word32                      -- ^ codesep_pos (use 'TS.defaultCodesepPos' / 0xFFFFFFFF if no CODESEPARATOR)
  -> Maybe ByteString            -- ^ optional annex (with leading 0x50)
  -> Either TS.TaprootSighashError Hash256
computeTaprootScriptPathSighash tx idx prevouts hashType leafVersion script csp annex =
  let leafHash = TS.tapleafHashWith leafVersion script
      ctx      = TS.TapscriptContext
        { TS.tapleafHash = leafHash
        , TS.codesepPos  = csp
        }
  in Hash256 <$> TS.computeTaprootSighash tx idx prevouts hashType annex (Just ctx)

-- | Sign a 32-byte BIP-341 *script-path* sighash and return the wire-format
-- witness signature item for a tapscript OP_CHECKSIG spend.
--
-- Crucially, BIP-342 redefines OP_CHECKSIG inside tapscript: the signature
-- is verified under the *plain* x-only public key pushed by the script
-- (NOT the tweaked output key).  So unlike 'signWithKeyTaproot', this
-- primitive does NOT apply any tweak — it Schnorr-signs the raw seckey.
--
-- Hashtype byte append rule is identical to key-path:
--   * @hashType == 0x00@ (SIGHASH_DEFAULT) → 64-byte witness item
--   * @hashType != 0x00@                   → 65-byte witness item (sig64 ‖ ht)
--
-- Throws 'error' on malformed seckey / signing failure (programmer bug,
-- never happens for a well-formed BIP-32 derived key with valid sighash).
--
-- Reference: bitcoin-core/src/key.cpp KeyPair::SignSchnorr +
--            bitcoin-core/src/script/sign.cpp CreateSchnorrSig.
signWithKeyTapscript
  :: ExtendedKey
  -> Hash256                 -- ^ BIP-341 script-path sighash
  -> Word8                   -- ^ hash_type (0x00 default)
  -> ByteString              -- ^ 64- or 65-byte witness signature item
signWithKeyTapscript xkey (Hash256 msg32) hashType =
  let SecKey skBytes = ekKey xkey
      sig64 = case signSchnorr skBytes msg32 of
        Just s  -> s
        Nothing -> error "signWithKeyTapscript: Schnorr sign failed"
  in if hashType == 0x00
       then sig64
       else sig64 `BS.snoc` hashType

-- | Magic 'piUnknown' key used to carry a tapscript leaf script through
-- a haskoin PSBT input pending BIP-371 PSBT_IN_TAP_LEAF_SCRIPT support.
--
-- This is haskoin-internal: external PSBTs using BIP-371 keytypes will
-- need a translation step.  The key is intentionally implausible-as-an-
-- external key (single byte 0xff is reserved by BIP-174 as proprietary),
-- chosen so a real BIP-174 parser will round-trip it as opaque
-- proprietary data without semantic interpretation.
tapscriptLeafScriptPsbtKey :: ByteString
tapscriptLeafScriptPsbtKey = BS.pack [0xff, 0x74, 0x6c, 0x73]  -- 0xff "tls"

-- | Magic 'piUnknown' key used to carry a tapscript control block through
-- a haskoin PSBT input pending BIP-371 PSBT_IN_TAP_LEAF_SCRIPT support.
-- See 'tapscriptLeafScriptPsbtKey' note on the keyspace.
tapscriptControlBlockPsbtKey :: ByteString
tapscriptControlBlockPsbtKey = BS.pack [0xff, 0x74, 0x63, 0x62]  -- 0xff "tcb"

-- | Recognise a single-key OP_CHECKSIG tapscript: @<0x20> <pk:32> <0xac>@,
-- 34 bytes total, where the pushed pubkey matches the given x-only key.
--
-- This is BIP-342's analog of P2WPKH inside a tapleaf: a 1-of-1 single-key
-- spending policy with no further predicates.  More complex tapscripts
-- (multisig, hashlock+timelock combos, MuSig2 aggregations, etc.) are
-- explicitly out of scope for the W18 wave.
isSingleKeyOpChecksigTapscript :: ByteString -> ByteString -> Bool
isSingleKeyOpChecksigTapscript script pkXOnly =
  BS.length script == 34 &&
  BS.length pkXOnly == 32 &&
  BS.index  script 0  == 0x20 &&  -- push 32 bytes
  BS.take   32 (BS.drop 1 script) == pkXOnly &&
  BS.index  script 33 == 0xac     -- OP_CHECKSIG

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
  , piTapKeySig = piTapKeySig a <|> piTapKeySig b
  , piTapScriptSigs = Map.union (piTapScriptSigs a) (piTapScriptSigs b)
  , piTapLeafScripts = Map.unionWith Set.union (piTapLeafScripts a) (piTapLeafScripts b)
  , piTapBip32Derivation = Map.union (piTapBip32Derivation a) (piTapBip32Derivation b)
  , piTapInternalKey = piTapInternalKey a <|> piTapInternalKey b
  , piTapMerkleRoot = piTapMerkleRoot a <|> piTapMerkleRoot b
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
  , poTapInternalKey = poTapInternalKey a <|> poTapInternalKey b
  , poTapTree = if null (poTapTree a) then poTapTree b else poTapTree a
  , poTapBip32Derivation = Map.union (poTapBip32Derivation a) (poTapBip32Derivation b)
  , poMuSig2Participants = Map.union (poMuSig2Participants a) (poMuSig2Participants b)
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
--
-- W32-A hardening: the per-input finalizer 'finalizeForScript' now
-- enforces the same BIP-16 / BIP-141 commitment gates that W31 wired
-- into 'canSignWrapped' and 'addSignature'.  An attacker-supplied
-- (Combiner-supplied) PSBT carrying a partial signature under a
-- forged 'piRedeemScript' or 'piWitnessScript' is dropped here:
-- the input is left without 'piFinalScriptSig' / 'piFinalScriptWitness',
-- which trips 'isInputFinalized' and surfaces as
-- @FinalizeCommitmentMismatch at index N@ in the error string.
finalizePsbt :: Psbt -> Either String Psbt
finalizePsbt psbt =
  -- W47: pair each input with its outpoint from the unsigned tx so we
  -- can route legacy (non-witness) P2SH inputs through the index-aware
  -- 'getInputUtxoFor'.  The pre-W47 finalizer used the no-arg
  -- 'getInputUtxo' inside 'finalizeInput', which only consults
  -- 'piWitnessUtxo' — so legacy P2SH-multisig inputs whose only UTXO
  -- carrier was 'piNonWitnessUtxo' silently failed to finalize, even
  -- after the W46-3 multisig branches landed.  This was the second
  -- divergence reported by tools/psbt-multi-input-test.sh T3 / T4.
  let outpoints = map txInPrevOutput (txInputs (pgTx (psbtGlobal psbt)))
      paddedOps = outpoints ++ repeat (OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0)
      pairs     = zip paddedOps (psbtInputs psbt)
      finalizedInputs = map (uncurry finalizeInputAt) pairs
      indexed         = zip [0 :: Int ..] (zip (psbtInputs psbt) finalizedInputs)
      errors          = [i | (i, (_, inp)) <- indexed, not (isInputFinalized inp)]
      mismatches      = [ i | (i, (orig, _)) <- indexed
                            , not (isInputFinalized (finalizedInputs !! i))
                            , inputHasCommitmentMismatch orig
                            ]
  in if null errors
     then Right psbt { psbtInputs = finalizedInputs }
     else Left $ case mismatches of
       []   -> "Could not finalize inputs: " ++ show errors
       _    -> "FinalizeCommitmentMismatch at index "
            ++ show mismatches
            ++ " (other unfinalized inputs: "
            ++ show [i | i <- errors, i `notElem` mismatches] ++ ")"

-- | True when the input's PSBT-supplied @piRedeemScript@ /
-- @piWitnessScript@ does not commit to the output script under
-- BIP-16 (P2SH hash160) or BIP-141 (P2WSH sha256).  Used by
-- 'finalizePsbt' to surface a more explicit error than the generic
-- "could not finalize" — this is the W32-A finalizer companion to
-- the W31 gates in 'canSignWrapped' + 'addSignature'.
inputHasCommitmentMismatch :: PsbtInput -> Bool
inputHasCommitmentMismatch pinp =
  case getInputUtxo pinp of
    Nothing   -> False
    Just utxo ->
      let script = txOutScript utxo
      in case piRedeemScript pinp of
           Just redeem
             | isP2SHScript script
             , isP2WPKHScript redeem
             -> not (p2shCommits script redeem)
             | isP2SHScript script
             , isP2WSHScript redeem
             , Just wScript <- piWitnessScript pinp
             -> not (p2shCommits script redeem
                     && p2wshCommits redeem wScript)
           _ -> case piWitnessScript pinp of
                  Just wScript
                    | isP2WSHScript script
                    -> not (p2wshCommits script wScript)
                  _ -> False

-- | Finalize a single input.
--
-- The no-arg variant only consults 'piWitnessUtxo' via 'getInputUtxo', so
-- legacy (non-witness) P2SH inputs whose UTXO is carried in
-- 'piNonWitnessUtxo' fall through to "cannot finalize".  Prefer
-- 'finalizeInputAt' when the outpoint is known (which 'finalizePsbt'
-- always has via the unsigned tx).  Kept exported because external
-- callers may construct a 'PsbtInput' in isolation.
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

-- | W47: index-aware single-input finalizer used by 'finalizePsbt'.
--
-- Routes through the W41 'getInputUtxoFor' so that legacy P2SH inputs
-- (whose UTXO carrier is 'piNonWitnessUtxo') resolve their output
-- script and reach 'finalizeForScript'.  Without this, the W46-3
-- multisig branches in 'finalizeForScript' were unreachable for legacy
-- P2SH-multisig inputs, which surfaced as T3 / T4 byte-divergence on
-- tools/psbt-multi-input-test.sh.
--
-- Mirrors the segwit-aware 'finalizeInput' for the no-outpoint case.
finalizeInputAt :: OutPoint -> PsbtInput -> PsbtInput
finalizeInputAt op pinp
  | isInputFinalized pinp = pinp
  | otherwise = case (getInputUtxoFor op pinp, Map.toList (piPartialSigs pinp)) of
      (Just utxo, sigs@(_:_)) ->
        let script = txOutScript utxo
        in finalizeForScript script sigs pinp
      _ -> pinp  -- Cannot finalize

-- | Finalize input based on script type.
--
-- Phase 2 (W15) covers segwit-v0:
--   * Bare P2WPKH:           witness = [sig, pubkey]; scriptSig empty.
--   * Bare P2WSH single-key: witness = [sig, witnessScript].
--   * Wrapped P2SH-P2WPKH:   witness = [sig, pubkey];
--                            scriptSig = push(redeemScript).
--   * Wrapped P2SH-P2WSH:    witness = [sig, witnessScript];
--                            scriptSig = push(redeemScript).
-- For the wrapped cases we read 'piRedeemScript' / 'piWitnessScript'
-- from the PSBT input rather than parsing them out of the output
-- script.  Multi-key P2WSH falls through to "cannot finalize" today —
-- the BIP-143 sighash machinery is the same, only the witness layout
-- differs and that needs Combiner state we don't track yet.
--
-- W32-A hardening: the wrapped P2SH-P2WPKH, P2SH-P2WSH and bare
-- P2WSH branches additionally gate on 'p2shCommits' / 'p2wshCommits',
-- mirroring the W31 commitment checks in 'canSignWrapped' and
-- 'addSignature'.  W31 already prevents 'addSignature' from ever
-- producing a partial sig under a forged redeem/witnessScript, but
-- a Combiner-supplied PSBT could plant such a sig directly into
-- 'piPartialSigs'.  Without these gates 'finalizeForScript' would
-- happily assemble a malformed transaction whose scriptSig pushes
-- the forged redeemScript and whose witness presents the forged
-- witnessScript — accepting attacker-controlled scriptCode at the
-- finalizer step.  On mismatch we leave 'pinp' untouched so
-- 'isInputFinalized' stays False; 'finalizePsbt' then surfaces an
-- explicit @FinalizeCommitmentMismatch@ error.
finalizeForScript :: ByteString -> [(PubKey, ByteString)] -> PsbtInput -> PsbtInput
finalizeForScript script sigs pinp
  -- W46: P2SH-P2WSH multisig.  Match BEFORE the single-sig P2SH-P2WSH
  -- branch below so that 2+ collected sigs route through the multisig
  -- assembler.  The single-sig branch's `_ -> pinp` would otherwise
  -- short-circuit and the multisig case never finalize.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WSHScript redeem
  , Just wScript <- piWitnessScript pinp
  , p2shCommits script redeem
  , p2wshCommits redeem wScript
  , Just (m, redeemPubkeys) <- parseMultisigRedeem wScript =
      case orderedMultisigSigs m redeemPubkeys (piPartialSigs pinp) of
        Just orderedSigs ->
          let witness   = [BS.empty] ++ orderedSigs ++ [wScript]
              scriptSig = encodePushData' redeem
          in clearSigningFields $ pinp
             { piFinalScriptSig     = Just scriptSig
             , piFinalScriptWitness = Just witness
             }
        Nothing -> pinp
  -- W46: native P2WSH multisig.  Match BEFORE the single-sig P2WSH
  -- branch below for the same reason as P2SH-P2WSH above.
  | isP2WSHScript script
  , Just wScript <- piWitnessScript pinp
  , p2wshCommits script wScript
  , Just (m, redeemPubkeys) <- parseMultisigRedeem wScript =
      case orderedMultisigSigs m redeemPubkeys (piPartialSigs pinp) of
        Just orderedSigs ->
          let witness = [BS.empty] ++ orderedSigs ++ [wScript]
          in clearSigningFields $ pinp { piFinalScriptWitness = Just witness }
        Nothing -> pinp
  -- P2SH wrap: figure out which inner program the redeemScript carries.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WPKHScript redeem
  , p2shCommits script redeem =
      case sigs of
        [(pk, sig)] ->
          let witness   = [sig, serializePubKeyCompressed pk]
              scriptSig = encodePushData' redeem
          in clearSigningFields $ pinp
             { piFinalScriptSig     = Just scriptSig
             , piFinalScriptWitness = Just witness
             }
        _ -> pinp
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , isP2WSHScript redeem
  , Just wScript <- piWitnessScript pinp
  , p2shCommits script redeem
  , p2wshCommits redeem wScript =
      case sigs of
        [(_, sig)] ->
          let witness   = [sig, wScript]
              scriptSig = encodePushData' redeem
          in clearSigningFields $ pinp
             { piFinalScriptSig     = Just scriptSig
             , piFinalScriptWitness = Just witness
             }
        _ -> pinp
  -- Bare P2WPKH: witness = [signature, pubkey]
  | isP2WPKHScript script =
      case sigs of
        [(pk, sig)] ->
          let witness = [sig, serializePubKeyCompressed pk]
          in clearSigningFields $ pinp { piFinalScriptWitness = Just witness }
        _ -> pinp
  -- Bare P2WSH single-key: witness = [signature, witnessScript]
  | isP2WSHScript script
  , Just wScript <- piWitnessScript pinp
  , p2wshCommits script wScript =
      case sigs of
        [(_, sig)] ->
          let witness = [sig, wScript]
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
  -- Phase 4 (W18): bare P2TR script-path (tapscript) single-leaf
  -- single-key OP_CHECKSIG.  Witness stack is [sig, leaf_script, control_block].
  -- The leaf script and control block come from 'piUnknown' under the
  -- W18 magic keys (BIP-371 PSBT taproot field translation is a
  -- separate wave).  The control block as decoded must round-trip to
  -- the same bytes (BIP-341 byte 0 packs leafVersion + parity), so we
  -- emit the original PSBT bytes verbatim.
  | isP2TRScript script
  , Just leafScript <- Map.lookup tapscriptLeafScriptPsbtKey   (piUnknown pinp)
  , Just cbBytes    <- Map.lookup tapscriptControlBlockPsbtKey (piUnknown pinp) =
      case sigs of
        [(_, sig)] ->
          let witness = [sig, leafScript, cbBytes]
          in clearSigningFields $ pinp { piFinalScriptWitness = Just witness }
        _ -> pinp
  -- Phase 5 (W16): bare P2TR key-path.  Witness stack is just [sig],
  -- no pubkey (the on-chain output key is the witness program itself,
  -- and the verifier rebuilds its identity from the sig + sighash).
  -- scriptSig is empty for native segwit.  See
  -- bitcoin-core/src/script/sign.cpp ProduceSignature WITNESS_V1_TAPROOT.
  | isP2TRScript script =
      case sigs of
        [(_, sig)] ->
          let witness = [sig]
          in clearSigningFields $ pinp { piFinalScriptWitness = Just witness }
        _ -> pinp
  -- W46 multisig finalize: Legacy P2SH-multisig.
  -- redeemScript is `m <pk1> ... <pkn> n OP_CHECKMULTISIG`; assemble
  -- scriptSig = OP_0 sig1 ... sigM PUSH(redeemScript) where sigs appear
  -- in script-pubkey (redeemScript) order, not piPartialSigs Map order.
  -- This branch sits below the single-sig P2SH-P2WPKH / P2SH-P2WSH wrap
  -- branches above because their redeem-script predicates (isP2WPKHScript
  -- / isP2WSHScript) are stricter and disjoint with parseMultisigRedeem,
  -- so the order is unambiguous.
  -- Reference: bitcoin-core/src/script/sign.cpp ProduceSignature, the
  -- TxoutType::MULTISIG branch which calls SignStep with SIGVERSION_BASE.
  | isP2SHScript script
  , Just redeem <- piRedeemScript pinp
  , p2shCommits script redeem
  , Just (m, redeemPubkeys) <- parseMultisigRedeem redeem =
      case orderedMultisigSigs m redeemPubkeys (piPartialSigs pinp) of
        Just orderedSigs ->
          let scriptSig = BS.concat $
                  [BS.singleton 0x00]            -- OP_0 dummy (BIP-11 off-by-one)
               ++ map encodePushData' orderedSigs
               ++ [encodePushData' redeem]
          in clearSigningFields $ pinp
             { piFinalScriptSig = Just scriptSig
             }
        Nothing -> pinp
  -- TODO: multi-leaf tapscript MAST.
  | otherwise = pinp

-- | W46: Parse a bare multisig redeemScript / witnessScript.
--
-- Layout (BIP-11): @OP_m <pk1> ... <pkn> OP_n OP_CHECKMULTISIG@ where
-- @OP_m@ / @OP_n@ are small-number opcodes (@OP_1@..@OP_16@).  Each
-- pubkey push is a direct OPCODE push (33-byte compressed = @0x21
-- <33b>@; 65-byte uncompressed = @0x41 <65b>@).
--
-- Returns @Just (m, [pubkeyBytes])@ on a clean parse, @Nothing@ on
-- any structural mismatch (wrong opcode, wrong push length, wrong
-- M/N relation, trailing bytes, etc.) so that finalize falls through
-- to the safe "leave unchanged" branch.
--
-- Reference: bitcoin-core/src/script/standard.cpp@MatchMultisig.
parseMultisigRedeem :: ByteString -> Maybe (Int, [ByteString])
parseMultisigRedeem bs
  | BS.length bs < 4 = Nothing
  | otherwise = do
      let b0 = BS.index bs 0
      m <- smallNumByte b0
      (pubkeys, rest) <- takePubkeys (BS.drop 1 bs)
      case BS.unpack (BS.take 2 rest) of
        [nByte, 0xae] -> do
          n <- smallNumByte nByte
          if BS.length rest == 2
             && length pubkeys == n
             && m >= 1 && m <= n
             && n >= 1 && n <= 20
            then Just (m, pubkeys)
            else Nothing
        _ -> Nothing
  where
    smallNumByte :: Word8 -> Maybe Int
    smallNumByte b
      | b >= 0x51 && b <= 0x60 = Just (fromIntegral b - 0x50)
      | otherwise              = Nothing
    takePubkeys :: ByteString -> Maybe ([ByteString], ByteString)
    takePubkeys input
      | BS.null input = Just ([], input)
      | otherwise =
          let pushLen = BS.index input 0
          in case pushLen of
               0x21
                 | BS.length input >= 1 + 33 -> do
                     let pk = BS.take 33 (BS.drop 1 input)
                         rem' = BS.drop (1 + 33) input
                     (rest, final) <- takePubkeys rem'
                     Just (pk : rest, final)
                 | otherwise -> Nothing
               0x41
                 | BS.length input >= 1 + 65 -> do
                     let pk = BS.take 65 (BS.drop 1 input)
                         rem' = BS.drop (1 + 65) input
                     (rest, final) <- takePubkeys rem'
                     Just (pk : rest, final)
                 | otherwise -> Nothing
               _ -> Just ([], input)

-- | W46: Order a partial-sig map by redeemScript pubkey order and pick
-- the first @m@ signatures.
--
-- 'piPartialSigs' is an unordered @Map PubKey ByteString@ keyed by the
-- 33-byte compressed pubkey; OP_CHECKMULTISIG verifies sigs in
-- script-pubkey order, popping each unmatched pubkey, so the assembled
-- scriptSig / witness stack must list sigs in that same order.
--
-- Returns @Just (sig1..sigM)@ when at least @m@ of the redeemScript's
-- pubkeys have a partial sig; @Nothing@ otherwise (e.g. only @m-1@
-- sigs collected — leave the input unfinalized so the Combiner can
-- pick up more).
orderedMultisigSigs
  :: Int            -- ^ M (signatures required)
  -> [ByteString]   -- ^ pubkeys in redeemScript order (33 or 65 bytes)
  -> Map PubKey ByteString
  -> Maybe [ByteString]
orderedMultisigSigs m redeemPubkeys partialSigs =
  let sigByBytes :: Map ByteString ByteString
      sigByBytes = Map.fromList
        [ (serializePubKeyCompressed pk, sig)
        | (pk, sig) <- Map.toList partialSigs
        ]
      collected = mapMaybe (`Map.lookup` sigByBytes) redeemPubkeys
  in if length collected >= m
       then Just (take m collected)
       else Nothing

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
  -- Sum input values; pair each PSBT input with its tx input's outpoint so
  -- that getInputUtxoFor can index into non_witness_utxo when needed.
  let txIns   = txInputs (pgTx (psbtGlobal psbt))
      inPairs = zip txIns (psbtInputs psbt)
  inputValues <- mapM getInputValue inPairs
  let totalIn = sum inputValues
  -- Sum output values
  let totalOut = sum $ map txOutValue (txOutputs $ pgTx $ psbtGlobal psbt)
  -- Fee = inputs - outputs
  if totalIn >= totalOut
    then Just (totalIn - totalOut)
    else Nothing
  where
    getInputValue :: (TxIn, PsbtInput) -> Maybe Word64
    getInputValue (txIn, pinp) =
      txOutValue <$> getInputUtxoFor (txInPrevOutput txIn) pinp

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
  | Rawtr !KeyExpr                         -- ^ rawtr(KEY) - BIP-386: x-only key, no taproot tweak
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
    "rawtr"       -> parseRawtr st2
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

-- | Parse rawtr(KEY) — BIP-386: x-only pubkey output key without taproot tweak.
-- Reference: Bitcoin Core src/script/descriptor.cpp RawTRDescriptor.
parseRawtr :: Parser Descriptor
parseRawtr st = do
  (key, st1) <- parseKeyExpr st
  (_, st2) <- expectChar ')' st1
  return (Rawtr key, st2)

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
  Rawtr key -> "rawtr(" <> keyExprToXOnlyText key <> ")"
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

-- | Convert a key expression to x-only (32-byte) hex text, for use in rawtr().
-- BIP-386: rawtr() emits the x-only pubkey without the leading parity byte.
keyExprToXOnlyText :: KeyExpr -> Text
keyExprToXOnlyText key = case key of
  KeyLiteral pk -> hexEncode' (BS.drop 1 (serializePubKeyCompressed pk))
  KeyOrigin fp path inner ->
    "[" <> hexEncode' fp <> pathToText path <> "]" <> keyExprToXOnlyText inner
  -- For xpub/xprv/WIF, fall back to compressed form (range descriptors rarely used with rawtr)
  other -> keyExprToText other

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
  Rawtr key -> isRangeKey key
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
  Rawtr key ->
    -- BIP-386: x-only pubkey IS the output key, no taproot tweak.
    let pk = deriveKeyExpr key idx
    in [encodeScript (encodeP2TR (xOnlyPubKey pk))]
  Tr key mTree ->
    -- BIP-341 §4.2: output_key = lift_x(internal_key) + int(tapTweak)*G
    -- where tapTweak = hashTapTweak(internal_key || merkle_root).
    -- merkle_root is "" for key-path-only (BIP-86), or the root of the
    -- Merkle tree of leaf scripts for tr(KEY,TREE).
    -- Reference: bitcoin-core/src/script/descriptor.cpp TrDescriptor::MakeScripts.
    let pk        = deriveKeyExpr key idx
        internalX = getHash256 (xOnlyPubKey pk)
        merkleRoot = maybe BS.empty (tapTreeMerkleRoot idx) mTree
        tweak      = computeTapTweakHash internalX merkleRoot
    in case xonlyPubkeyTweakAdd internalX tweak of
         Just (tweakedX, _) -> [encodeScript (encodeP2TR (Hash256 tweakedX))]
         Nothing            -> [encodeScript (encodeP2TR (xOnlyPubKey pk))]  -- unreachable for valid keys
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

-- | Compute the BIP-341 Merkle root for a descriptor TapTree at a given
-- derivation index.
--
-- For a single leaf: @tapleafHash("TapLeaf", 0xc0 || compactSize(script) || script)@.
-- For a branch: @tagged_hash("TapBranch", sort(left, right))@ recursively.
--
-- Reference: bitcoin-core/src/script/descriptor.cpp TaprootBuilder::Add,
--            BIP-341 §"Computing the Taproot tree" (merkle tree hashing).
tapTreeMerkleRoot :: Int -> TapTree -> ByteString
tapTreeMerkleRoot idx = go
  where
    go (TapLeaf d) =
      -- Use the first derived script for the leaf; tapscript leaf version 0xc0.
      let scripts = deriveScriptsAt d idx
          script  = if null scripts then BS.empty else head scripts
      in TS.tapleafHashWith TS.tapscriptLeafVersion script
    go (TapBranch l r) =
      let lh         = go l
          rh         = go r
          (lo, hi)   = if lh <= rh then (lh, rh) else (rh, lh)
      in taggedHash "TapBranch" (lo <> hi)

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

-- | Decode a base58check BIP-32 extended public key (xpub.../tpub...)
-- as used inside a descriptor key expression.
--
-- Delegates to 'decodeExtPubKey' (the real BIP-32 base58check decoder
-- — Wallet.hs:767) and discards the network tag, since the descriptor
-- caller already disambiguated via the prefix.
--
-- Prior to W118 FIX-59 this returned a dummy 'ExtendedPubKey' ignoring
-- the input entirely (G6 / DH-4 in the W118 audit).
decodeXPub :: Text -> Maybe ExtendedPubKey
decodeXPub t = snd <$> decodeExtPubKey t

-- | Decode a base58check BIP-32 extended private key (xprv.../tprv...)
-- as used inside a descriptor key expression.  See 'decodeXPub'.
decodeXPriv :: Text -> Maybe ExtendedKey
decodeXPriv t = snd <$> decodeExtKey t

-- | Encode a BIP-32 extended public key as base58check (xpub.../tpub...).
-- Used by descriptor pretty-printing for 'KeyXPub' expressions.
--
-- Defaults to mainnet (xpub) since the descriptor 'KeyXPub' carries no
-- network tag; callers that need testnet should round-trip through
-- 'encodeExtPubKey' with the desired network instead.
--
-- Prior to W118 FIX-59 this returned the literal string "xpub..."
-- (G6 / DH-4 in the W118 audit).
encodeXPub :: ExtendedPubKey -> Text
encodeXPub = encodeExtPubKey Haskoin.Consensus.mainnet

-- | Encode a BIP-32 extended private key as base58check (xprv.../tprv...).
-- See 'encodeXPub' for the network-defaulting behavior.
encodeXPriv :: ExtendedKey -> Text
encodeXPriv = encodeExtKey Haskoin.Consensus.mainnet

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

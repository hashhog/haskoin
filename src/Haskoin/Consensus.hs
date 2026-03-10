{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Consensus
  ( -- * Network
    Network(..)
  , mainnet
  , testnet3
  , regtest
    -- * Consensus Constants
  , maxBlockSize
  , maxBlockWeight
  , maxBlockSigops
  , maxMoney
  , coinbaseMaturity
  , maxScriptSize
  , maxScriptElementSize
  , maxStackSize
  , maxOpsPerScript
  , maxPubkeysPerMultisig
  , maxBlockHeaderSize
  , witnessScaleFactor
    -- * Difficulty
  , difficultyAdjustmentInterval
  , targetSpacing
  , targetTimespan
  , powLimit
  , bitsToTarget
  , targetToBits
  , checkProofOfWork
    -- * Block Reward
  , halvingInterval
  , blockReward
  , totalSupply
    -- * BIP Activation Heights
  , bip34Height
  , bip65Height
  , bip66Height
  , segwitHeight
  , taprootHeight
    -- * Genesis Block
  , genesisBlock
  , genesisBlockHeader
    -- * Validation
  , validateBlockHeader
  , validateTransaction
  , computeMerkleRoot
    -- * Utilities
  , hexToBS
  , hashFromHex
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32, Word64)
-- import Data.Int (Int32)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.List (nub)
import Control.Monad (when, unless)

import Haskoin.Types
import Haskoin.Crypto

--------------------------------------------------------------------------------
-- Network Configuration
--------------------------------------------------------------------------------

-- | Network configuration for mainnet, testnet, or regtest
data Network = Network
  { netName              :: !String
  , netMagic             :: !Word32         -- ^ Protocol magic bytes
  , netDefaultPort       :: !Int
  , netAddrPrefix        :: !Word8          -- ^ Base58 P2PKH version
  , netScriptPrefix      :: !Word8          -- ^ Base58 P2SH version
  , netSecretPrefix      :: !Word8          -- ^ WIF secret key version
  , netBech32Prefix      :: !String         -- ^ Bech32 HRP
  , netPowLimit          :: !Integer        -- ^ Max target (easiest difficulty)
  , netPowTargetSpacing  :: !Word32         -- ^ 600 seconds (10 minutes)
  , netPowTargetTimespan :: !Word32         -- ^ 1209600 seconds (2 weeks)
  , netRetargetInterval  :: !Word32         -- ^ 2016 blocks
  , netHalvingInterval   :: !Word32         -- ^ 210000 blocks
  , netCoinbaseMaturity  :: !Int            -- ^ 100 blocks
  , netGenesisBlock      :: !Block
  , netBIP34Height       :: !Word32
  , netBIP65Height       :: !Word32
  , netBIP66Height       :: !Word32
  , netSegwitHeight      :: !Word32
  , netTaprootHeight     :: !Word32
  , netDNSSeeds          :: ![String]
  , netCheckpoints       :: ![(Word32, BlockHash)]
  , netAllowMinDiffBlocks :: !Bool
  } deriving (Show)

--------------------------------------------------------------------------------
-- Consensus Constants
--------------------------------------------------------------------------------

-- | Maximum block size in bytes (legacy limit)
maxBlockSize :: Int
maxBlockSize = 1000000  -- 1 MB

-- | Maximum block weight in weight units (SegWit)
maxBlockWeight :: Int
maxBlockWeight = 4000000  -- 4M weight units

-- | Maximum signature operations per block (after SegWit scaling)
maxBlockSigops :: Int
maxBlockSigops = 80000  -- 80k sigops

-- | Maximum total money supply in satoshis (21 million BTC)
maxMoney :: Word64
maxMoney = 2100000000000000  -- 21M * 100M satoshis

-- | Coinbase maturity (blocks before coinbase can be spent)
coinbaseMaturity :: Int
coinbaseMaturity = 100

-- | Maximum script size in bytes
maxScriptSize :: Int
maxScriptSize = 10000  -- 10k bytes

-- | Maximum size of an element pushed to the stack
maxScriptElementSize :: Int
maxScriptElementSize = 520  -- 520 bytes

-- | Maximum stack size (combined main + alt stack)
maxStackSize :: Int
maxStackSize = 1000

-- | Maximum opcodes per script (excluding push ops)
maxOpsPerScript :: Int
maxOpsPerScript = 201

-- | Maximum public keys in a multisig script
maxPubkeysPerMultisig :: Int
maxPubkeysPerMultisig = 20

-- | Block header size (always exactly 80 bytes)
maxBlockHeaderSize :: Int
maxBlockHeaderSize = 80

-- | Witness scale factor (non-witness data counts 4x)
witnessScaleFactor :: Int
witnessScaleFactor = 4

--------------------------------------------------------------------------------
-- Difficulty Constants
--------------------------------------------------------------------------------

-- | Difficulty adjustment interval (blocks between retargets)
difficultyAdjustmentInterval :: Word32
difficultyAdjustmentInterval = 2016

-- | Target time between blocks (10 minutes in seconds)
targetSpacing :: Word32
targetSpacing = 600

-- | Target timespan for difficulty adjustment (2 weeks in seconds)
targetTimespan :: Word32
targetTimespan = 1209600  -- 2016 * 600

-- | Halving interval (blocks between reward halvings)
halvingInterval :: Word32
halvingInterval = 210000

-- | Maximum target for mainnet (minimum difficulty)
-- This represents difficulty 1
powLimit :: Integer
powLimit = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

--------------------------------------------------------------------------------
-- Difficulty Target Conversion
--------------------------------------------------------------------------------

-- | Convert compact "bits" format to full target
-- Format: first byte = exponent (number of bytes), next 3 bytes = significand
-- target = significand * 2^(8*(exponent-3))
bitsToTarget :: Word32 -> Integer
bitsToTarget bits =
  let exponent' = fromIntegral (bits `shiftR` 24) :: Int
      mantissa = fromIntegral (bits .&. 0x007fffff) :: Integer
      negative = bits .&. 0x00800000 /= 0
      target = if exponent' <= 3
               then mantissa `shiftR` (8 * (3 - exponent'))
               else mantissa `shiftL` (8 * (exponent' - 3))
  in if negative then negate target else target

-- | Convert full target to compact "bits" format
targetToBits :: Integer -> Word32
targetToBits target
  | target <= 0 = 0
  | otherwise =
      let bytes = integerToBytes target
          len = length bytes
          -- Get the most significant 3 bytes
          (sig, expo)
            | len <= 3 =
                let padded = replicate (3 - len) 0 ++ bytes
                in (bytesToWord24 padded, len)
            | otherwise =
                (bytesToWord24 (take 3 bytes), len)
          -- Ensure positive encoding (MSB of significand can't be set)
          (sig', expo')
            | sig .&. 0x00800000 /= 0 =
                (sig `shiftR` 8, expo + 1)
            | otherwise = (sig, expo)
      in (fromIntegral expo' `shiftL` 24) .|. fromIntegral sig'

-- | Convert Integer to list of bytes (big-endian, no leading zeros)
integerToBytes :: Integer -> [Word8]
integerToBytes 0 = [0]
integerToBytes n = reverse $ go n
  where
    go 0 = []
    go x = fromIntegral (x .&. 0xff) : go (x `shiftR` 8)

-- | Convert 3 bytes to Word32 (24-bit value)
bytesToWord24 :: [Word8] -> Word32
bytesToWord24 [a, b, c] =
  (fromIntegral a `shiftL` 16) .|.
  (fromIntegral b `shiftL` 8) .|.
  fromIntegral c
bytesToWord24 _ = 0

-- | Verify proof of work for a block header
-- Hash must be <= target and target must be <= powLimit
checkProofOfWork :: BlockHeader -> Integer -> Bool
checkProofOfWork header powLimitTarget =
  let target = bitsToTarget (bhBits header)
      -- Compute block hash and convert to integer
      headerHash = getHash256 $ getBlockHashHash $ computeBlockHash header
      -- Bitcoin uses little-endian hash comparison, so reverse to big-endian
      hashAsInteger = bsToInteger (BS.reverse headerHash)
  in target > 0 && target <= powLimitTarget && hashAsInteger <= target

-- | Convert ByteString to Integer (big-endian)
bsToInteger :: ByteString -> Integer
bsToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

--------------------------------------------------------------------------------
-- Block Reward
--------------------------------------------------------------------------------

-- | Calculate block reward for a given height
-- Initial reward: 50 BTC (5,000,000,000 satoshis)
-- Halves every 210,000 blocks
blockReward :: Word32 -> Word64
blockReward height =
  let halvings = height `div` halvingInterval
  in if halvings >= 64
     then 0  -- After 64 halvings, reward is 0
     else 5000000000 `shiftR` fromIntegral halvings
  -- Block 0-209999:      50 BTC
  -- Block 210000-419999: 25 BTC
  -- Block 420000-629999: 12.5 BTC
  -- Block 630000-839999: 6.25 BTC
  -- Block 840000-1049999: 3.125 BTC (April 2024)

-- | Total supply of Bitcoin in satoshis
-- Slightly less than 21 million BTC due to rounding
totalSupply :: Word64
totalSupply = 2099999997690000

--------------------------------------------------------------------------------
-- BIP Activation Heights (mainnet)
--------------------------------------------------------------------------------

-- | BIP-34: Block height in coinbase (mainnet)
bip34Height :: Word32
bip34Height = 227931

-- | BIP-65: OP_CHECKLOCKTIMEVERIFY (mainnet)
bip65Height :: Word32
bip65Height = 388381

-- | BIP-66: Strict DER signatures (mainnet)
bip66Height :: Word32
bip66Height = 363725

-- | SegWit activation height (mainnet)
segwitHeight :: Word32
segwitHeight = 481824

-- | Taproot activation height (mainnet)
taprootHeight :: Word32
taprootHeight = 709632

--------------------------------------------------------------------------------
-- Genesis Block
--------------------------------------------------------------------------------

-- | Mainnet genesis block header
genesisBlockHeader :: BlockHeader
genesisBlockHeader = BlockHeader
  { bhVersion    = 1
  , bhPrevBlock  = BlockHash (Hash256 (BS.replicate 32 0))
  , bhMerkleRoot = hexToHash256 "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  , bhTimestamp  = 1231006505   -- 2009-01-03 18:15:05 UTC
  , bhBits       = 0x1d00ffff   -- Difficulty 1
  , bhNonce      = 2083236893
  }
  -- Genesis block hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  -- Coinbase message: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

-- | Mainnet genesis block
genesisBlock :: Block
genesisBlock = Block
  { blockHeader = genesisBlockHeader
  , blockTxns   = [genesisCoinbase]
  }
  where
    genesisCoinbase = Tx
      { txVersion  = 1
      , txInputs   = [TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          , txInScript = hexToBS "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
            -- Contains: \x04\xff\xff\x00\x1d\x01\x04EThe Times 03/Jan/2009 Chancellor on brink of second bailout for banks
          , txInSequence = 0xffffffff
          }]
      , txOutputs  = [TxOut
          { txOutValue  = 5000000000  -- 50 BTC
          , txOutScript = hexToBS "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
            -- Satoshi's P2PK pubkey
          }]
      , txWitness  = [[]]
      , txLockTime = 0
      }

--------------------------------------------------------------------------------
-- Testnet3 Genesis Block
--------------------------------------------------------------------------------

-- | Testnet3 genesis block header
testnet3GenesisHeader :: BlockHeader
testnet3GenesisHeader = BlockHeader
  { bhVersion    = 1
  , bhPrevBlock  = BlockHash (Hash256 (BS.replicate 32 0))
  , bhMerkleRoot = hexToHash256 "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  , bhTimestamp  = 1296688602   -- 2011-02-02
  , bhBits       = 0x1d00ffff
  , bhNonce      = 414098458
  }

-- | Testnet3 genesis block
testnet3GenesisBlock :: Block
testnet3GenesisBlock = Block
  { blockHeader = testnet3GenesisHeader
  , blockTxns   = [genesisCoinbaseTx]
  }
  where
    genesisCoinbaseTx = Tx
      { txVersion  = 1
      , txInputs   = [TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          , txInScript = hexToBS "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
          , txInSequence = 0xffffffff
          }]
      , txOutputs  = [TxOut
          { txOutValue  = 5000000000
          , txOutScript = hexToBS "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
          }]
      , txWitness  = [[]]
      , txLockTime = 0
      }

--------------------------------------------------------------------------------
-- Regtest Genesis Block
--------------------------------------------------------------------------------

-- | Regtest genesis block header
regtestGenesisHeader :: BlockHeader
regtestGenesisHeader = BlockHeader
  { bhVersion    = 1
  , bhPrevBlock  = BlockHash (Hash256 (BS.replicate 32 0))
  , bhMerkleRoot = hexToHash256 "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
  , bhTimestamp  = 1296688602
  , bhBits       = 0x207fffff  -- Very easy difficulty
  , bhNonce      = 2
  }

-- | Regtest genesis block
regtestGenesisBlock :: Block
regtestGenesisBlock = Block
  { blockHeader = regtestGenesisHeader
  , blockTxns   = [genesisCoinbaseTx]
  }
  where
    genesisCoinbaseTx = Tx
      { txVersion  = 1
      , txInputs   = [TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          , txInScript = hexToBS "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"
          , txInSequence = 0xffffffff
          }]
      , txOutputs  = [TxOut
          { txOutValue  = 5000000000
          , txOutScript = hexToBS "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
          }]
      , txWitness  = [[]]
      , txLockTime = 0
      }

--------------------------------------------------------------------------------
-- Network Configurations
--------------------------------------------------------------------------------

-- | Bitcoin mainnet configuration
mainnet :: Network
mainnet = Network
  { netName              = "mainnet"
  , netMagic             = 0xD9B4BEF9  -- Wire bytes: F9 BE B4 D9 (little-endian)
  , netDefaultPort       = 8333
  , netAddrPrefix        = 0x00        -- P2PKH addresses start with '1'
  , netScriptPrefix      = 0x05        -- P2SH addresses start with '3'
  , netSecretPrefix      = 0x80        -- WIF keys start with '5' or 'K'/'L'
  , netBech32Prefix      = "bc"        -- SegWit addresses
  , netPowLimit          = powLimit
  , netPowTargetSpacing  = 600         -- 10 minutes
  , netPowTargetTimespan = 1209600     -- 2 weeks
  , netRetargetInterval  = 2016        -- Every 2016 blocks
  , netHalvingInterval   = 210000      -- Reward halving
  , netCoinbaseMaturity  = 100         -- 100 confirmations
  , netGenesisBlock      = genesisBlock
  , netBIP34Height       = 227931
  , netBIP65Height       = 388381
  , netBIP66Height       = 363725
  , netSegwitHeight      = 481824
  , netTaprootHeight     = 709632
  , netDNSSeeds          =
      [ "seed.bitcoin.sipa.be"
      , "dnsseed.bluematt.me"
      , "dnsseed.bitcoin.dashjr-list-of-hierarchical-nodes.us"
      , "seed.bitcoinstats.com"
      , "seed.bitcoin.jonasschnelli.ch"
      , "seed.btc.petertodd.net"
      , "seed.bitcoin.sprovoost.nl"
      , "dnsseed.emzy.de"
      ]
  , netCheckpoints       =
      [ (11111,  hashFromHex "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")
      , (33333,  hashFromHex "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")
      , (74000,  hashFromHex "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")
      , (105000, hashFromHex "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")
      , (134444, hashFromHex "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")
      , (168000, hashFromHex "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")
      , (193000, hashFromHex "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")
      , (210000, hashFromHex "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")
      , (216116, hashFromHex "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")
      , (225430, hashFromHex "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")
      ]
  , netAllowMinDiffBlocks = False
  }

-- | Bitcoin testnet3 configuration
testnet3 :: Network
testnet3 = Network
  { netName              = "testnet3"
  , netMagic             = 0x0709110B
  , netDefaultPort       = 18333
  , netAddrPrefix        = 0x6F        -- P2PKH addresses start with 'm' or 'n'
  , netScriptPrefix      = 0xC4        -- P2SH addresses start with '2'
  , netSecretPrefix      = 0xEF        -- WIF keys start with '9' or 'c'
  , netBech32Prefix      = "tb"        -- SegWit addresses
  , netPowLimit          = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  , netPowTargetSpacing  = 600
  , netPowTargetTimespan = 1209600
  , netRetargetInterval  = 2016
  , netHalvingInterval   = 210000
  , netCoinbaseMaturity  = 100
  , netGenesisBlock      = testnet3GenesisBlock
  , netBIP34Height       = 21111
  , netBIP65Height       = 581885
  , netBIP66Height       = 330776
  , netSegwitHeight      = 834624
  , netTaprootHeight     = 0           -- Active from genesis on signet-like
  , netDNSSeeds          =
      [ "testnet-seed.bitcoin.jonasschnelli.ch"
      , "seed.tbtc.petertodd.net"
      , "seed.testnet.bitcoin.sprovoost.nl"
      , "testnet-seed.bluematt.me"
      ]
  , netCheckpoints       = []
  , netAllowMinDiffBlocks = True       -- Allow min difficulty blocks on testnet
  }

-- | Bitcoin regtest configuration (local testing)
regtest :: Network
regtest = Network
  { netName              = "regtest"
  , netMagic             = 0xDAB5BFFA
  , netDefaultPort       = 18444
  , netAddrPrefix        = 0x6F        -- Same as testnet
  , netScriptPrefix      = 0xC4
  , netSecretPrefix      = 0xEF
  , netBech32Prefix      = "bcrt"      -- Regtest bech32 prefix
  , netPowLimit          = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  , netPowTargetSpacing  = 600
  , netPowTargetTimespan = 1209600
  , netRetargetInterval  = 150         -- Much shorter for testing
  , netHalvingInterval   = 150         -- Much shorter for testing
  , netCoinbaseMaturity  = 100
  , netGenesisBlock      = regtestGenesisBlock
  , netBIP34Height       = 500
  , netBIP65Height       = 1351
  , netBIP66Height       = 1251
  , netSegwitHeight      = 0           -- Active from genesis
  , netTaprootHeight     = 0           -- Active from genesis
  , netDNSSeeds          = []          -- No DNS seeds for regtest
  , netCheckpoints       = []
  , netAllowMinDiffBlocks = True
  }

--------------------------------------------------------------------------------
-- Merkle Root Computation
--------------------------------------------------------------------------------

-- | Compute Merkle root from list of transaction IDs
-- Returns zero hash for empty list
computeMerkleRoot :: [TxId] -> Hash256
computeMerkleRoot [] = Hash256 (BS.replicate 32 0)
computeMerkleRoot [TxId h] = h
computeMerkleRoot txids =
  let hashes = map (\(TxId h) -> h) txids
  in merkleStep hashes
  where
    merkleStep :: [Hash256] -> Hash256
    merkleStep [h] = h
    merkleStep hs =
      let -- If odd number of hashes, duplicate the last one
          hs' = if odd (length hs) then hs ++ [last hs] else hs
          -- Pair up and hash
          pairs = pairUp hs'
          nextLevel = map (\(Hash256 a, Hash256 b) ->
            doubleSHA256 (BS.append a b)) pairs
      in merkleStep nextLevel

    pairUp :: [a] -> [(a, a)]
    pairUp [] = []
    pairUp (a:b:rest) = (a, b) : pairUp rest
    pairUp [a] = [(a, a)]  -- Should not happen due to odd handling above

--------------------------------------------------------------------------------
-- Block Header Validation
--------------------------------------------------------------------------------

-- | Validate a block header (context-free checks)
-- Does NOT validate:
--   - Timestamp against network time (requires current time)
--   - Previous block hash (requires chain state)
--   - Merkle root (requires full block)
validateBlockHeader :: Network -> BlockHeader -> Word32 -> Either String ()
validateBlockHeader net header height = do
  -- Check proof of work
  unless (checkProofOfWork header (netPowLimit net)) $
    Left "Block does not meet proof of work target"

  -- Check version (BIP-34: version >= 2 after certain height)
  when (height >= netBIP34Height net && bhVersion header < 2) $
    Left "Block version too low (BIP-34 requires version >= 2)"

  -- Check version (BIP-66: version >= 3 after certain height)
  when (height >= netBIP66Height net && bhVersion header < 3) $
    Left "Block version too low (BIP-66 requires version >= 3)"

  -- Check version (BIP-65: version >= 4 after certain height)
  when (height >= netBIP65Height net && bhVersion header < 4) $
    Left "Block version too low (BIP-65 requires version >= 4)"

  Right ()

--------------------------------------------------------------------------------
-- Transaction Validation
--------------------------------------------------------------------------------

-- | Validate a transaction (context-free checks)
-- Does NOT validate:
--   - Input scripts (requires UTXOs)
--   - Signature verification (requires secp256k1)
--   - Amounts (requires UTXOs)
validateTransaction :: Tx -> Either String ()
validateTransaction tx = do
  -- At least one input
  when (null $ txInputs tx) $
    Left "Transaction has no inputs"

  -- At least one output
  when (null $ txOutputs tx) $
    Left "Transaction has no outputs"

  -- Check total output value doesn't overflow or exceed max money
  let totalOut = sum $ map txOutValue (txOutputs tx)
  when (totalOut > maxMoney) $
    Left "Total output value exceeds max money"

  -- Check for duplicate inputs
  let outpoints = map txInPrevOutput (txInputs tx)
  when (length outpoints /= length (nub outpoints)) $
    Left "Duplicate inputs"

  -- Coinbase checks
  let nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
      isCoinbase = length (txInputs tx) == 1
                && txInPrevOutput (head $ txInputs tx) == nullOutpoint

  when isCoinbase $ do
    let scriptLen = BS.length $ txInScript $ head $ txInputs tx
    -- Coinbase scriptSig must be 2-100 bytes (BIP-34 encodes height)
    -- KNOWN PITFALL: CScriptNum sign-magnitude means thresholds are 0x7f/0x7fff
    -- because MSB is sign bit, but for coinbase height this just affects encoding
    when (scriptLen < 2 || scriptLen > 100) $
      Left "Coinbase scriptSig size out of range (must be 2-100 bytes)"

  -- Non-coinbase checks
  unless isCoinbase $ do
    -- No null prevouts in non-coinbase
    let hasNullPrevout = any (\inp ->
          txInPrevOutput inp == OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          ) (txInputs tx)
    when hasNullPrevout $
      Left "Non-coinbase transaction references null prevout"

  Right ()

--------------------------------------------------------------------------------
-- Utility Functions
--------------------------------------------------------------------------------

-- | Convert hex string to ByteString
hexToBS :: String -> ByteString
hexToBS [] = BS.empty
hexToBS (a:b:rest) =
  let byte = fromIntegral (hexDigit a * 16 + hexDigit b) :: Word8
  in BS.cons byte (hexToBS rest)
hexToBS [_] = error "hexToBS: odd length hex string"

-- | Convert single hex digit to Int
hexDigit :: Char -> Int
hexDigit c
  | c >= '0' && c <= '9' = fromEnum c - fromEnum '0'
  | c >= 'a' && c <= 'f' = fromEnum c - fromEnum 'a' + 10
  | c >= 'A' && c <= 'F' = fromEnum c - fromEnum 'A' + 10
  | otherwise = error "hexDigit: invalid hex character"

-- | Convert hex string to Hash256
hexToHash256 :: String -> Hash256
hexToHash256 hex = Hash256 (hexToBS hex)

-- | Create BlockHash from hex string (reverses bytes for display format)
hashFromHex :: String -> BlockHash
hashFromHex hex = BlockHash (Hash256 (BS.reverse $ hexToBS hex))

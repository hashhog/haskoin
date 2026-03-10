{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

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
    -- * Full Block Validation
  , validateFullBlock
  , validateBlockTransactions
  , ChainState(..)
  , ConsensusFlags(..)
  , consensusFlagsAtHeight
    -- * Coinbase
  , isCoinbase
  , coinbaseHeight
    -- * Block Metrics
  , blockWeight
  , blockBaseSize
  , blockTotalSize
  , txBaseSize
  , txTotalSize
  , varIntSize
  , checkBlockWeight
    -- * Sigop Counting
  , countBlockSigops
  , countTxSigops
  , countScriptSigops
    -- * Witness Commitment
  , validateWitnessCommitment
  , computeWtxId
    -- * Block Connection
  , connectBlock
  , disconnectBlock
    -- * Block Status (re-exported from Storage)
  , BlockStatus(..)
    -- * Header Synchronization
  , ChainEntry(..)
  , HeaderChain(..)
  , HeaderSync(..)
  , initHeaderChain
  , headerWork
  , cumulativeWork
  , medianTimePast
  , difficultyAdjustment
  , addHeader
  , getChainTip
  , findForkPoint
  , getAncestor
  , buildLocatorHeights
  , startHeaderSync
  , handleHeaders
    -- * Utilities
  , hexToBS
  , hashFromHex
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32, Word64)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.List (nub, sort)
import Control.Monad (when, unless, forM, foldM, forever, void)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Serialize (encode, runPut, putWord32le, putWord64le, putByteString)
import GHC.Generics (Generic)
import Control.Concurrent.STM
import Control.Concurrent (forkIO, threadDelay)

import Haskoin.Types (Hash256(..), TxId(..), BlockHash(..),
                      OutPoint(..), TxIn(..), TxOut(..), Tx(..), BlockHeader(..),
                      Block(..), putVarInt, putVarBytes)
import Haskoin.Crypto (doubleSHA256, computeTxId, computeBlockHash)
import Haskoin.Script (decodeScript, countScriptSigops)
import Haskoin.Storage (HaskoinDB, WriteBatch(..), BatchOp(..), writeBatch,
                        makeKey, KeyPrefix(..), toBE32, TxLocation(..),
                        BlockStatus(..))

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
      txIsCoinbase = length (txInputs tx) == 1
                  && txInPrevOutput (head $ txInputs tx) == nullOutpoint

  when txIsCoinbase $ do
    let scriptLen = BS.length $ txInScript $ head $ txInputs tx
    -- Coinbase scriptSig must be 2-100 bytes (BIP-34 encodes height)
    -- KNOWN PITFALL: CScriptNum sign-magnitude means thresholds are 0x7f/0x7fff
    -- because MSB is sign bit, but for coinbase height this just affects encoding
    when (scriptLen < 2 || scriptLen > 100) $
      Left "Coinbase scriptSig size out of range (must be 2-100 bytes)"

  -- Non-coinbase checks
  unless txIsCoinbase $ do
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

--------------------------------------------------------------------------------
-- Chain State and Consensus Flags
--------------------------------------------------------------------------------

-- | Current chain state for block validation
data ChainState = ChainState
  { csHeight        :: !Word32
  , csBestBlock     :: !BlockHash
  , csChainWork     :: !Integer
  , csMedianTime    :: !Word32
  , csFlags         :: !ConsensusFlags
  } deriving (Show, Generic)

-- | Consensus flags indicating which BIPs are active
data ConsensusFlags = ConsensusFlags
  { flagBIP34       :: !Bool    -- ^ Block height in coinbase
  , flagBIP65       :: !Bool    -- ^ OP_CHECKLOCKTIMEVERIFY
  , flagBIP66       :: !Bool    -- ^ Strict DER signatures
  , flagSegWit      :: !Bool    -- ^ Segregated Witness
  , flagTaproot     :: !Bool    -- ^ Taproot
  , flagNullDummy   :: !Bool    -- ^ NULLDUMMY (BIP-147)
  } deriving (Show, Generic)

-- | Compute consensus flags for a given height based on network rules
consensusFlagsAtHeight :: Network -> Word32 -> ConsensusFlags
consensusFlagsAtHeight net h = ConsensusFlags
  { flagBIP34   = h >= netBIP34Height net
  , flagBIP65   = h >= netBIP65Height net
  , flagBIP66   = h >= netBIP66Height net
  , flagSegWit  = h >= netSegwitHeight net
  , flagNullDummy = h >= netSegwitHeight net
  , flagTaproot = h >= netTaprootHeight net
  }

--------------------------------------------------------------------------------
-- Coinbase Detection and BIP-34
--------------------------------------------------------------------------------

-- | Check if a transaction is a coinbase transaction.
-- A coinbase tx has exactly one input with null prevout hash and index 0xffffffff.
isCoinbase :: Tx -> Bool
isCoinbase tx =
  length (txInputs tx) == 1
  && outPointHash (txInPrevOutput (head (txInputs tx)))
     == TxId (Hash256 (BS.replicate 32 0))
  && outPointIndex (txInPrevOutput (head (txInputs tx))) == 0xffffffff

-- | Extract the block height from a coinbase transaction (BIP-34).
-- Returns Nothing if not a coinbase or if height encoding is invalid.
-- The height is encoded as a CScriptNum at the start of the scriptSig.
coinbaseHeight :: Tx -> Maybe Word32
coinbaseHeight tx
  | not (isCoinbase tx) = Nothing
  | BS.null script = Nothing
  | otherwise =
      let len = fromIntegral (BS.head script)
      in if len > 0 && len <= 4 && BS.length script > len
         then Just $ decodeLittleEndian (BS.take len (BS.drop 1 script))
         else Nothing
  where
    script = txInScript (head (txInputs tx))
    -- Decode little-endian bytes to Word32
    decodeLittleEndian :: ByteString -> Word32
    decodeLittleEndian bs =
      let bytes = BS.unpack bs
          withIndex = zip [0..] bytes
      in foldr (\(i, b) acc -> acc .|. (fromIntegral b `shiftL` (8 * i))) 0 withIndex

--------------------------------------------------------------------------------
-- Block Weight Calculation (BIP-141)
--------------------------------------------------------------------------------

-- | Calculate block weight.
-- KNOWN PITFALL: weight = (non_witness_bytes * 3) + total_bytes
-- This is equivalent to: base_size * 3 + total_size
-- Or: base_size * (witnessScaleFactor - 1) + total_size
blockWeight :: Block -> Int
blockWeight block =
  let baseSize = blockBaseSize block
      totalSize = blockTotalSize block
  -- weight = base_size * 3 + total_size
  -- Which equals base_size * 4 when there's no witness data
  in baseSize * (witnessScaleFactor - 1) + totalSize

-- | Calculate the base size of a block (without witness data).
-- This is the size as if the block had no witness data at all.
blockBaseSize :: Block -> Int
blockBaseSize block =
  80  -- header size
  + varIntSize (length $ blockTxns block)
  + sum (map txBaseSize (blockTxns block))

-- | Calculate the total size of a block (with witness data).
blockTotalSize :: Block -> Int
blockTotalSize block =
  80  -- header size
  + varIntSize (length $ blockTxns block)
  + sum (map txTotalSize (blockTxns block))

-- | Calculate the base size of a transaction (without witness data).
txBaseSize :: Tx -> Int
txBaseSize tx = BS.length $ runPut $ do
  putWord32le (fromIntegral $ txVersion tx)
  putVarInt (fromIntegral $ length $ txInputs tx)
  mapM_ putTxInNoWitness (txInputs tx)
  putVarInt (fromIntegral $ length $ txOutputs tx)
  mapM_ putTxOutBinary (txOutputs tx)
  putWord32le (txLockTime tx)
  where
    putTxInNoWitness inp = do
      putByteString (encode $ txInPrevOutput inp)
      putVarBytes (txInScript inp)
      putWord32le (txInSequence inp)
    putTxOutBinary out = do
      putWord64le (txOutValue out)
      putVarBytes (txOutScript out)

-- | Calculate the total size of a transaction (with witness data).
txTotalSize :: Tx -> Int
txTotalSize tx = BS.length (encode tx)

-- | Calculate the size needed to encode an integer as a VarInt.
varIntSize :: Int -> Int
varIntSize n
  | n < 0xfd      = 1
  | n <= 0xffff   = 3
  | n <= 0xffffffff = 5
  | otherwise      = 9

-- | Check if a block's weight is within the consensus limit.
-- Returns True if the block weight is valid, False otherwise.
-- BIP-141 defines maxBlockWeight = 4,000,000 weight units.
checkBlockWeight :: Block -> Bool
checkBlockWeight block = blockWeight block <= maxBlockWeight

--------------------------------------------------------------------------------
-- Sigop Counting
--------------------------------------------------------------------------------

-- | Count signature operations in a block.
-- For accurate counting, we need the UTXO map to look up previous outputs.
countBlockSigops :: Block -> Map OutPoint TxOut -> Int
countBlockSigops block utxoMap =
  sum $ map (countTxSigops utxoMap) (blockTxns block)

-- | Count signature operations in a transaction.
-- Includes sigops from outputs (scriptPubKey) and inputs (scriptSig + redeemed script).
countTxSigops :: Map OutPoint TxOut -> Tx -> Int
countTxSigops utxoMap tx =
  let outputSigops = sum $ map (scriptSigopsFromBytes . txOutScript) (txOutputs tx)
      inputSigops = if isCoinbase tx then 0
                    else sum $ map (inputSigopCount utxoMap) (txInputs tx)
  in outputSigops + inputSigops
  where
    scriptSigopsFromBytes script =
      case decodeScript script of
        Right s -> countScriptSigops s False
        Left _  -> 0
    inputSigopCount utxos inp =
      case Map.lookup (txInPrevOutput inp) utxos of
        Nothing -> 0
        Just prevOut ->
          case decodeScript (txOutScript prevOut) of
            Right s -> countScriptSigops s True
            Left _  -> 0

--------------------------------------------------------------------------------
-- Full Block Validation
--------------------------------------------------------------------------------

-- | Validate a full block against consensus rules.
-- Requires the UTXO map for input validation and sigop counting.
validateFullBlock :: Network -> ChainState -> Block -> Map OutPoint TxOut
                 -> Either String ()
validateFullBlock net cs block utxoMap = do
  let height = csHeight cs + 1
      flags = consensusFlagsAtHeight net height
      header = blockHeader block
      txns = blockTxns block

  -- 1. Block must have at least one transaction (coinbase)
  when (null txns) $ Left "Block has no transactions"

  -- 2. First transaction must be coinbase, no others
  unless (isCoinbase (head txns)) $ Left "First transaction is not coinbase"
  when (any isCoinbase (tail txns)) $ Left "Multiple coinbase transactions"

  -- 3. Verify merkle root
  let computedRoot = computeMerkleRoot (map computeTxId txns)
  unless (computedRoot == bhMerkleRoot header) $ Left "Merkle root mismatch"

  -- 4. Check block weight (only after SegWit activation)
  when (flagSegWit flags && blockWeight block > maxBlockWeight) $
    Left "Block exceeds maximum weight"

  -- 5. BIP-34: coinbase must contain height
  when (flagBIP34 flags) $
    case coinbaseHeight (head txns) of
      Nothing -> Left "Coinbase missing height (BIP-34)"
      Just h  -> unless (h == height) $ Left "Coinbase height mismatch"

  -- 6. Validate all transactions and compute total fees
  -- KNOWN PITFALL: Intra-block spending - txs can spend outputs from earlier txs
  -- We update UTXO set during validation, not after
  totalFees <- validateBlockTransactions flags txns utxoMap

  -- 7. Coinbase value must not exceed reward + fees
  let maxCoinbase = blockReward height + totalFees
      coinbaseValue = sum $ map txOutValue (txOutputs (head txns))
  when (coinbaseValue > maxCoinbase) $
    Left "Coinbase value exceeds allowed amount"

  -- 8. Check sigops limit
  when (countBlockSigops block utxoMap > maxBlockSigops) $
    Left "Block exceeds sigop limit"

  -- 9. SegWit witness commitment validation
  when (flagSegWit flags) $ validateWitnessCommitment block

  Right ()

-- | Validate all non-coinbase transactions in a block.
-- Returns the total fees collected.
-- KNOWN PITFALL: Handles intra-block spending by updating UTXO map as we go.
validateBlockTransactions :: ConsensusFlags -> [Tx] -> Map OutPoint TxOut
                         -> Either String Word64
validateBlockTransactions flags txns initialUtxoMap = do
  -- Process transactions sequentially, updating UTXO map for intra-block spending
  let go :: (Word64, Map OutPoint TxOut) -> Tx -> Either String (Word64, Map OutPoint TxOut)
      go (accFees, utxoMap) tx = do
        fee <- validateSingleTx flags utxoMap tx
        -- Add outputs from this tx to UTXO map for subsequent txs in block
        let txid = computeTxId tx
            newUtxos = Map.fromList
              [ (OutPoint txid (fromIntegral i), txout)
              | (i, txout) <- zip [0..] (txOutputs tx)
              ]
            -- Remove spent outputs
            spentOutpoints = map txInPrevOutput (txInputs tx)
            utxoMap' = foldr Map.delete (Map.union newUtxos utxoMap) spentOutpoints
        return (accFees + fee, utxoMap')

  (totalFees, _) <- foldM go (0, initialUtxoMap) (tail txns)  -- Skip coinbase
  return totalFees

-- | Validate a single non-coinbase transaction.
-- Returns the fee (inputs - outputs) on success.
validateSingleTx :: ConsensusFlags -> Map OutPoint TxOut -> Tx
                 -> Either String Word64
validateSingleTx _flags utxoMap tx = do
  -- First, run context-free validation
  validateTransaction tx

  -- Then validate inputs exist in UTXO set and compute values
  inputValues <- forM (txInputs tx) $ \inp ->
    case Map.lookup (txInPrevOutput inp) utxoMap of
      Nothing -> Left $ "Missing UTXO: " ++ show (txInPrevOutput inp)
      Just prevOut -> Right (txOutValue prevOut)

  let totalIn  = sum inputValues
      totalOut = sum $ map txOutValue (txOutputs tx)

  -- Inputs must cover outputs
  when (totalIn < totalOut) $ Left "Outputs exceed inputs"

  -- Script verification would go here
  -- For now, we skip actual signature verification as it requires secp256k1

  return (totalIn - totalOut)

--------------------------------------------------------------------------------
-- Witness Commitment Validation
--------------------------------------------------------------------------------

-- | Validate the witness commitment in a SegWit block.
-- The commitment is in a coinbase output with prefix 0x6a24aa21a9ed.
validateWitnessCommitment :: Block -> Either String ()
validateWitnessCommitment block = do
  let coinbase = head (blockTxns block)
      commitPrefix = BS.pack [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
      -- Find outputs with witness commitment pattern
      commitOutputs = filter (\txo ->
        BS.length (txOutScript txo) >= 38
        && BS.isPrefixOf commitPrefix (txOutScript txo)
        ) (txOutputs coinbase)

  -- If no commitment outputs, that's valid (pre-SegWit style or no witness txs)
  case commitOutputs of
    [] -> Right ()
    _ -> do
      -- Use the last commitment output (as per BIP-141)
      let commitOut = last commitOutputs
          commitment = BS.take 32 (BS.drop 6 (txOutScript commitOut))
          -- Witness nonce is in the coinbase witness
          witnessNonce = case txWitness coinbase of
            (stack:_) | not (null stack) && BS.length (head stack) == 32 -> head stack
            _ -> BS.replicate 32 0
          -- Compute witness root from wtxids
          wtxids = TxId (Hash256 (BS.replicate 32 0))  -- coinbase wtxid is all zeros
                   : map computeWtxId (tail (blockTxns block))
          witnessRoot = computeMerkleRoot wtxids
          -- Expected commitment = SHA256d(witness_root || witness_nonce)
          expected = doubleSHA256 (BS.append (getHash256 witnessRoot) witnessNonce)

      unless (Hash256 commitment == expected) $
        Left "Witness commitment mismatch"

-- | Compute the witness transaction ID (wtxid).
-- For coinbase, wtxid is all zeros.
-- For other transactions, it's the hash of the full serialization including witness.
computeWtxId :: Tx -> TxId
computeWtxId tx = TxId (doubleSHA256 (encode tx))

--------------------------------------------------------------------------------
-- Block Connection and Disconnection
--------------------------------------------------------------------------------

-- | Connect a block to the chain state, updating UTXO set and indexes.
-- Must be called atomically via batch writes.
connectBlock :: HaskoinDB -> Network -> Block -> Word32 -> IO ()
connectBlock db _net block height = do
  let bh = computeBlockHash (blockHeader block)
      txns = blockTxns block
      txids = map computeTxId txns
      ops = concat
        [ -- Add new UTXOs from all transactions
          [ BatchPut (makeKey PrefixUTXO (encode (OutPoint txid (fromIntegral i))))
                     (encode txout)
          | (txid, tx) <- zip txids txns
          , (i, txout) <- zip [0..] (txOutputs tx)
          ]
        , -- Remove spent UTXOs (skip coinbase as it has no real inputs)
          [ BatchDelete (makeKey PrefixUTXO (encode (txInPrevOutput inp)))
          | tx <- tail txns
          , inp <- txInputs tx
          ]
        , -- Transaction index entries
          [ BatchPut (makeKey PrefixTxIndex (encode txid))
                     (encode (TxLocation bh (fromIntegral i)))
          | (i, txid) <- zip [0..] txids
          ]
        , -- Update chain state
          [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode bh)
          , BatchPut (makeKey PrefixBlockHeader (encode bh))
                     (encode (blockHeader block))
          , BatchPut (makeKey PrefixBlockHeight (encode (toBE32 height)))
                     (encode bh)
          ]
        ]
  writeBatch db (WriteBatch ops)

-- | Disconnect a block from the chain state (for reorgs).
-- Note: Full undo requires storing spent UTXO values when connecting.
disconnectBlock :: HaskoinDB -> Block -> BlockHash -> IO ()
disconnectBlock db block prevHash = do
  let txns = blockTxns block
      txids = map computeTxId txns
      ops = concat
        [ -- Remove outputs created by this block
          [ BatchDelete (makeKey PrefixUTXO (encode (OutPoint txid (fromIntegral i))))
          | (txid, tx) <- zip txids txns
          , (i, _) <- zip [0..] (txOutputs tx)
          ]
        -- Note: Restoring spent UTXOs would require undo data
        -- In production, store undo data when connecting blocks
        , -- Update best block to previous
          [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode prevHash) ]
        ]
  writeBatch db (WriteBatch ops)

--------------------------------------------------------------------------------
-- Header Chain Types
--------------------------------------------------------------------------------

-- | An entry in the header chain with computed metadata.
-- KNOWN PITFALL: header_tip vs chain_tip - track separately in DB.
-- Headers can be far ahead of validated blocks. Same DB key = data corruption.
data ChainEntry = ChainEntry
  { ceHeader     :: !BlockHeader     -- ^ The raw 80-byte header
  , ceHash       :: !BlockHash       -- ^ Block hash (computed from header)
  , ceHeight     :: !Word32          -- ^ Height in the chain
  , ceChainWork  :: !Integer         -- ^ Cumulative proof-of-work
  , cePrev       :: !(Maybe BlockHash) -- ^ Previous block hash (for genesis: Nothing)
  , ceStatus     :: !BlockStatus     -- ^ Validation status
  , ceMedianTime :: !Word32          -- ^ Median time past for this block
  } deriving (Show, Generic)

-- | In-memory header chain with concurrent access support.
-- Uses TVars for thread-safe access from multiple threads.
data HeaderChain = HeaderChain
  { hcEntries  :: !(TVar (Map BlockHash ChainEntry)) -- ^ All known entries by hash
  , hcTip      :: !(TVar ChainEntry)                 -- ^ Current best tip
  , hcHeight   :: !(TVar Word32)                     -- ^ Height of current tip
  , hcByHeight :: !(TVar (Map Word32 BlockHash))     -- ^ Height -> hash index
  }

--------------------------------------------------------------------------------
-- Chain Work Calculation
--------------------------------------------------------------------------------

-- | Calculate the work for a single header.
-- Work = 2^256 / (target + 1), representing the expected number of hashes
-- needed to find a block at this difficulty.
headerWork :: BlockHeader -> Integer
headerWork header =
  let target = bitsToTarget (bhBits header)
  in if target <= 0 then 0
     else (2 ^ (256 :: Integer)) `div` (target + 1)

-- | Calculate cumulative chain work by adding header work to previous work.
cumulativeWork :: Integer -> BlockHeader -> Integer
cumulativeWork prevWork header = prevWork + headerWork header

--------------------------------------------------------------------------------
-- Median Time Past (BIP-113)
--------------------------------------------------------------------------------

-- | Calculate the median time past for a block.
-- MTP is the median of the previous 11 block timestamps.
-- Used for locktime validation (BIP-113).
medianTimePast :: Map BlockHash ChainEntry -> BlockHash -> Word32
medianTimePast entries blockHash =
  let timestamps = collectTimestamps entries blockHash 11
      sorted = sort timestamps
  in if null sorted then 0 else sorted !! (length sorted `div` 2)
  where
    collectTimestamps :: Map BlockHash ChainEntry -> BlockHash -> Int -> [Word32]
    collectTimestamps _ _ 0 = []
    collectTimestamps ents hash n =
      case Map.lookup hash ents of
        Nothing -> []
        Just ce -> bhTimestamp (ceHeader ce)
          : maybe [] (\p -> collectTimestamps ents p (n-1)) (cePrev ce)

--------------------------------------------------------------------------------
-- Difficulty Adjustment
--------------------------------------------------------------------------------

-- | Calculate the expected difficulty bits for the next block.
-- Difficulty adjusts every 2016 blocks on mainnet.
-- The adjustment clamps the timespan to [1/4, 4x] of the target (2 weeks).
difficultyAdjustment :: Network -> Map BlockHash ChainEntry -> ChainEntry -> Word32
difficultyAdjustment net entries entry =
  let height = ceHeight entry + 1
  in if height `mod` netRetargetInterval net /= 0
     then bhBits (ceHeader entry)  -- No adjustment
     else
       -- Find the first block in this 2016-block period
       let firstHash = walkBack entries (ceHash entry) (netRetargetInterval net - 1)
       in case firstHash >>= (`Map.lookup` entries) of
            Nothing -> bhBits (ceHeader entry)  -- Fallback if not found
            Just firstEntry ->
              let actualTime = bhTimestamp (ceHeader entry)
                             - bhTimestamp (ceHeader firstEntry)
                  -- Clamp to [targetTimespan/4, targetTimespan*4]
                  minTime = netPowTargetTimespan net `div` 4
                  maxTime = netPowTargetTimespan net * 4
                  clampedTime = max minTime (min maxTime actualTime)
                  oldTarget = bitsToTarget (bhBits (ceHeader entry))
                  -- New target = old_target * actual_time / target_time
                  newTarget = min (netPowLimit net) $
                    (oldTarget * fromIntegral clampedTime)
                    `div` fromIntegral (netPowTargetTimespan net)
              in targetToBits newTarget
  where
    walkBack :: Map BlockHash ChainEntry -> BlockHash -> Word32 -> Maybe BlockHash
    walkBack _ hash 0 = Just hash
    walkBack ents hash n = case Map.lookup hash ents of
      Nothing -> Nothing
      Just ce -> cePrev ce >>= \p -> walkBack ents p (n-1)

--------------------------------------------------------------------------------
-- Header Chain Initialization
--------------------------------------------------------------------------------

-- | Initialize a header chain with the genesis block.
initHeaderChain :: Network -> IO HeaderChain
initHeaderChain net = do
  let genesis = blockHeader (netGenesisBlock net)
      genesisHash = computeBlockHash genesis
      work = headerWork genesis
      genesisEntry = ChainEntry
        { ceHeader = genesis
        , ceHash = genesisHash
        , ceHeight = 0
        , ceChainWork = work
        , cePrev = Nothing
        , ceStatus = StatusValid
        , ceMedianTime = bhTimestamp genesis
        }
  entriesVar <- newTVarIO (Map.singleton genesisHash genesisEntry)
  tipVar <- newTVarIO genesisEntry
  heightVar <- newTVarIO 0
  byHeightVar <- newTVarIO (Map.singleton 0 genesisHash)
  return HeaderChain
    { hcEntries = entriesVar
    , hcTip = tipVar
    , hcHeight = heightVar
    , hcByHeight = byHeightVar
    }

--------------------------------------------------------------------------------
-- Header Validation and Insertion
--------------------------------------------------------------------------------

-- | Add a header to the chain after validation.
-- Returns Left with error message on failure, Right with entry on success.
addHeader :: Network -> HeaderChain -> BlockHeader -> IO (Either String ChainEntry)
addHeader net hc header = do
  let hash = computeBlockHash header
      prevHash = bhPrevBlock header
  entries <- readTVarIO (hcEntries hc)

  -- Check if already known
  case Map.lookup hash entries of
    Just existing -> return $ Right existing
    Nothing -> case Map.lookup prevHash entries of
      Nothing -> return $ Left "Unknown previous block"
      Just parent -> do
        let height = ceHeight parent + 1

        -- Validate proof of work
        if not (checkProofOfWork header (netPowLimit net))
          then return $ Left "Proof of work check failed"
          else do
            -- Validate timestamp > MTP
            let mtp = medianTimePast entries prevHash
            if bhTimestamp header <= mtp
              then return $ Left "Timestamp not after median time past"
              else do
                -- Validate difficulty (skip on testnet if min-diff blocks allowed)
                let expectedBits = difficultyAdjustment net entries parent
                    difficultyOk = bhBits header == expectedBits
                                || netAllowMinDiffBlocks net

                if not difficultyOk
                  then return $ Left "Incorrect difficulty target"
                  else do
                    -- Compute metadata
                    let work = cumulativeWork (ceChainWork parent) header
                        entry = ChainEntry
                          { ceHeader = header
                          , ceHash = hash
                          , ceHeight = height
                          , ceChainWork = work
                          , cePrev = Just prevHash
                          , ceStatus = StatusHeaderValid
                          , ceMedianTime = mtp
                          }

                    -- Insert and potentially update tip atomically
                    atomically $ do
                      modifyTVar' (hcEntries hc) (Map.insert hash entry)
                      modifyTVar' (hcByHeight hc) (Map.insert height hash)
                      currentTip <- readTVar (hcTip hc)
                      when (work > ceChainWork currentTip) $ do
                        writeTVar (hcTip hc) entry
                        writeTVar (hcHeight hc) height

                    return $ Right entry

-- | Get the current chain tip.
getChainTip :: HeaderChain -> IO ChainEntry
getChainTip hc = readTVarIO (hcTip hc)

--------------------------------------------------------------------------------
-- Chain Navigation
--------------------------------------------------------------------------------

-- | Find the common ancestor (fork point) of two blocks.
-- Works by walking both chains back until they meet.
findForkPoint :: HeaderChain -> BlockHash -> BlockHash -> IO (Maybe ChainEntry)
findForkPoint hc h1 h2 = do
  entries <- readTVarIO (hcEntries hc)
  let e1 = Map.lookup h1 entries
      e2 = Map.lookup h2 entries
  case (e1, e2) of
    (Just a, Just b) -> return $ go entries a b
    _ -> return Nothing
  where
    go :: Map BlockHash ChainEntry -> ChainEntry -> ChainEntry -> Maybe ChainEntry
    go ents a b
      | ceHash a == ceHash b = Just a
      | ceHeight a > ceHeight b =
          cePrev a >>= (`Map.lookup` ents) >>= \p -> go ents p b
      | ceHeight a < ceHeight b =
          cePrev b >>= (`Map.lookup` ents) >>= \p -> go ents a p
      | otherwise = do
          -- Same height, both need to step back
          p1 <- cePrev a >>= (`Map.lookup` ents)
          p2 <- cePrev b >>= (`Map.lookup` ents)
          go ents p1 p2

-- | Get the ancestor at a specific height.
-- Returns Nothing if the target height is higher than the block's height
-- or if the chain is incomplete.
getAncestor :: HeaderChain -> BlockHash -> Word32 -> IO (Maybe ChainEntry)
getAncestor hc hash target = do
  entries <- readTVarIO (hcEntries hc)
  return $ walk entries hash
  where
    walk :: Map BlockHash ChainEntry -> BlockHash -> Maybe ChainEntry
    walk ents h = case Map.lookup h ents of
      Nothing -> Nothing
      Just ce
        | ceHeight ce == target -> Just ce
        | ceHeight ce < target  -> Nothing  -- Target is higher
        | otherwise -> cePrev ce >>= walk ents

--------------------------------------------------------------------------------
-- Block Locator
--------------------------------------------------------------------------------

-- | Build block locator heights using exponential backoff.
-- Returns heights: tip, tip-1, tip-2, ..., tip-9, tip-11, tip-15, tip-23, ...
-- This allows efficiently finding the fork point with minimal data.
buildLocatorHeights :: Word32 -> [Word32]
buildLocatorHeights tip = go tip 1 (0 :: Int)
  where
    go :: Word32 -> Word32 -> Int -> [Word32]
    go h step count
      | h == 0    = [0]
      | count < 10 = h : go (h - 1) 1 (count + 1)
      | h <= step = h : [0]  -- Avoid underflow, end at genesis
      | otherwise = h : go (h - step) (step * 2) (count + 1)

--------------------------------------------------------------------------------
-- Header Sync Controller
--------------------------------------------------------------------------------

-- | Header sync controller state.
-- Manages the headers-first synchronization process.
data HeaderSync = HeaderSync
  { hsChain    :: !HeaderChain        -- ^ The header chain being built
  , hsNetwork  :: !Network            -- ^ Network configuration
  , hsSyncing  :: !(TVar Bool)        -- ^ Whether sync is in progress
  , hsSyncPeer :: !(TVar (Maybe Int)) -- ^ Peer ID we're syncing from (placeholder)
  }

-- | Start the header sync controller.
-- Returns a HeaderSync that can be used to control synchronization.
startHeaderSync :: Network -> HeaderChain -> IO HeaderSync
startHeaderSync net hc = do
  syncingVar <- newTVarIO False
  peerVar <- newTVarIO Nothing
  let hs = HeaderSync
        { hsChain = hc
        , hsNetwork = net
        , hsSyncing = syncingVar
        , hsSyncPeer = peerVar
        }
  -- Start the sync loop in a background thread
  void $ forkIO $ headerSyncLoop hs
  return hs

-- | Main header sync loop.
-- Periodically checks if we need to sync and initiates sync if needed.
headerSyncLoop :: HeaderSync -> IO ()
headerSyncLoop hs = forever $ do
  syncing <- readTVarIO (hsSyncing hs)
  unless syncing $ do
    -- Check if we need to sync (placeholder - in real implementation
    -- this would check peer heights and initiate getheaders)
    return ()
  threadDelay 1000000  -- 1 second

-- | Handle incoming headers message.
-- Validates and adds each header, potentially triggering more requests.
-- Returns the number of successfully added headers.
handleHeaders :: HeaderSync -> [BlockHeader] -> IO (Int, [String])
handleHeaders hs hdrs = do
  results <- mapM (addHeader (hsNetwork hs) (hsChain hs)) hdrs
  let successes = length [() | Right _ <- results]
      failures = [e | Left e <- results]

  -- If we got 2000 headers, there may be more
  when (length hdrs == 2000 && null failures) $ do
    -- In a real implementation, we'd request more headers
    -- starting from the last received header
    return ()

  -- If we got fewer than 2000 or had failures, sync is complete
  when (length hdrs < 2000 || not (null failures)) $ do
    atomically $ writeTVar (hsSyncing hs) False
    _ <- getChainTip (hsChain hs)  -- Could be used for logging
    -- Log completion (placeholder)
    return ()

  return (successes, failures)

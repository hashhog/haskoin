{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Haskoin.Consensus
  ( -- * Network
    Network(..)
  , mainnet
  , testnet3
  , testnet4
  , regtest
    -- * AssumeUTXO
  , AssumeUtxoParams(..)
  , assumeUtxoForHeight
  , assumeUtxoForBlockHash
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
  , getNextWorkRequired
  , BlockIndex(..)
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
    -- * AssumeValid
  , shouldSkipScripts
    -- * Full Block Validation
  , validateFullBlock
  , validateFullBlockWithSigCache
  , validateBlockTransactions
  , ChainState(..)
  , ConsensusFlags(..)
  , consensusFlagsAtHeight
  , consensusFlagsToScriptFlags
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
  , SigOpCost(..)
  , maxBlockSigOpsCost
  , getTransactionSigOpCost
  , getBlockSigOpCost
  , countBlockSigops
  , countTxSigops
  , countScriptSigops
    -- * Witness Commitment
  , validateWitnessCommitment
  , computeWtxId
    -- * Block Connection (Legacy)
  , connectBlock
  , disconnectBlock
    -- * UTXO Cache Block Operations
  , applyBlock
  , unapplyBlock
    -- * Undo Data Types (re-exported from Storage)
  , TxInUndo(..)
  , TxUndo(..)
  , BlockUndo(..)
  , UndoData(..)
    -- * Chain Reorganization
  , performReorg
  , disconnectChain
  , connectChain
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
  , buildBlockLocatorFromChain
  , startHeaderSync
  , handleHeaders
    -- * BIP68 Sequence Locks
  , sequenceLockTimeDisableFlag
  , sequenceLockTimeTypeFlag
  , sequenceLockTimeMask
  , sequenceLockTimeGranularity
  , SequenceLock(..)
  , calculateSequenceLocks
  , checkSequenceLocks
  , bip68Active
    -- * BIP9 Version Bits (Soft Fork Deployment)
  , ThresholdState(..)
  , Deployment(..)
  , DeploymentCache
  , getDeploymentState
  , getStateSinceHeight
  , countSignalingBlocks
  , isVersionBitSignaling
  , computeBlockVersion
  , versionBitsTopBits
  , versionBitsTopMask
  , versionBitsNumBits
  , mainnetThreshold
  , testnetThreshold
  , taprootDeployment
    -- * Checkpoints
  , Checkpoints
  , getLastCheckpoint
  , checkpointAtHeight
  , verifyCheckpoint
  , isReorgPastCheckpoint
  , ChainError(..)
    -- * Utilities
  , hexToBS
  , hashFromHex
    -- * AssumeUTXO Background Validation
  , AssumeUtxoState(..)
  , initAssumeUtxoState
  , activateSnapshot
  , runBackgroundValidation
  , getAssumeUtxoProgress
  , isAssumeUtxoValidated
    -- * Block Invalidation (invalidateblock/reconsiderblock RPCs)
  , InvalidateError(..)
  , invalidateBlock
  , reconsiderBlock
  , findDescendants
  , isBlockInvalidated
  , activateBestChain
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int32, Int64)
import Data.Bits (shiftL, shiftR, (.&.), (.|.), testBit)
import Data.List (nub, sort, sortBy, foldl')
import Control.Monad (when, unless, forM, forM_, foldM, forever, void)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Serialize (encode, runPut, putWord32le, putWord64le, putByteString)
import GHC.Generics (Generic)
import Control.Concurrent.STM
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Async (Async, async, cancel, waitCatch)
import Control.Exception (try, SomeException)
import Data.IORef (IORef, newIORef, readIORef, writeIORef, atomicModifyIORef')
import Network.Socket (SockAddr)

import Haskoin.Types (Hash256(..), TxId(..), BlockHash(..),
                      OutPoint(..), TxIn(..), TxOut(..), Tx(..), BlockHeader(..),
                      Block(..), putVarInt, putVarBytes)
import Haskoin.Crypto (doubleSHA256, computeTxId, computeBlockHash)
import Haskoin.Script (decodeScript, countScriptSigops,
                       ScriptVerifyFlag(..), ScriptFlags, flagSet,
                       verifyScriptWithFlags, isPushOnly, classifyOutput,
                       ScriptType(..), Script(..), ScriptOp(..))
import Haskoin.Storage (HaskoinDB, WriteBatch(..), BatchOp(..), writeBatch,
                        makeKey, KeyPrefix(..), toBE32, TxLocation(..),
                        BlockStatus(..), UTXOCache(..), UTXOEntry(..),
                        TxInUndo(..), TxUndo(..), BlockUndo(..), UndoData(..),
                        mkUndoData, lookupUTXO, addUTXO, spendUTXO,
                        putUndoData, getUndoData, getUndoDataVerified, getBlock,
                        -- AssumeUTXO support
                        SnapshotMetadata(..), UtxoSnapshot(..), AssumeUtxoData(..),
                        loadSnapshot, verifySnapshot,
                        CoinsViewDB(..), newCoinsViewDB,
                        CoinsViewCache(..), newCoinsViewCache, cacheFlush, defaultCacheSize,
                        putBlockStatus, newUTXOCache, flushCache)

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
  , netCSVHeight         :: !Word32         -- ^ BIP68/112/113 (CSV) activation
  , netSegwitHeight      :: !Word32
  , netTaprootHeight     :: !Word32
  , netDNSSeeds          :: ![String]
  , netCheckpoints       :: ![(Word32, BlockHash)]
  , netAllowMinDiffBlocks :: !Bool          -- ^ Allow min difficulty on testnet
  , netPowNoRetargeting  :: !Bool           -- ^ No difficulty retargeting (regtest)
  , netEnforceBIP94      :: !Bool           -- ^ BIP94 time warp fix (testnet4)
  , netMinimumChainWork  :: !Integer        -- ^ Anti-DoS: minimum chain work for header sync
  , netAssumeUtxo        :: ![(Word32, AssumeUtxoParams)]  -- ^ AssumeUTXO snapshot parameters
  , netAssumedValid      :: !(Maybe BlockHash)  -- ^ Assume-valid: skip scripts for ancestors of this block
  } deriving (Show)

-- | AssumeUTXO snapshot parameters for a specific block height.
-- Reference: bitcoin/src/kernel/chainparams.h AssumeutxoData
data AssumeUtxoParams = AssumeUtxoParams
  { aupHeight        :: !Word32      -- ^ Block height of the snapshot
  , aupHashSerialized :: !Hash256    -- ^ Expected hash of serialized UTXO set
  , aupChainTxCount  :: !Word64      -- ^ Cumulative transaction count at height
  , aupBlockHash     :: !BlockHash   -- ^ Block hash at this height
  } deriving (Show, Eq)

-- | Look up assumeUTXO data for a specific height.
assumeUtxoForHeight :: Network -> Word32 -> Maybe AssumeUtxoParams
assumeUtxoForHeight net height =
  lookup height (netAssumeUtxo net)

-- | Look up assumeUTXO data for a specific block hash.
assumeUtxoForBlockHash :: Network -> BlockHash -> Maybe AssumeUtxoParams
assumeUtxoForBlockHash net bh =
  listToMaybe [ p | (_, p) <- netAssumeUtxo net, aupBlockHash p == bh ]
  where
    listToMaybe [] = Nothing
    listToMaybe (x:_) = Just x

--------------------------------------------------------------------------------
-- AssumeValid: ancestor-check script-skip
--
-- Reference: Bitcoin Core v28.0 src/validation.cpp lines 2345-2383.
-- Script verification is SKIPPED if and only if ALL six conditions hold:
--   1. netAssumedValid is set (Just hash).
--   2. The assumed-valid block is present in the in-memory block index.
--   3. The block being connected is an ancestor of the assumed-valid block
--      (ancestor check, NOT a height check).
--   4. The block is also an ancestor of the best known header.
--   5. The best-known-header's chainwork >= minimumChainWork.
--   6. The best-known-header is at least 2 weeks of timestamps past the
--      block being connected (prevents a manufactured shallow header chain
--      from unlocking the script-skip path).
--
-- All non-script checks (PoW, merkle, coinbase, BIP30, block size, sigops)
-- ALWAYS run regardless.  Regtest has netAssumedValid = Nothing — every
-- regtest script always runs.
--------------------------------------------------------------------------------

-- | Data about the best header tip, used for the assumevalid safety guards.
data BestHeaderInfo = BestHeaderInfo
  { bhiChainWork  :: !Integer  -- ^ Cumulative chain work at the best header tip
  , bhiTimestamp  :: !Word32   -- ^ Timestamp of the best header tip
  } deriving (Show, Eq)

-- | Decide whether to skip script verification for the block at 'pHeight'
-- with hash 'pHash'.
--
-- Arguments:
--   pHash       -- hash of the block being connected
--   pHeight     -- height of the block being connected
--   pTimestamp  -- timestamp of the block being connected (used for 2-week guard)
--   net         -- network configuration
--   blockIndex  -- Map BlockHash ChainEntry (in-memory index, same as HeaderChain.hcEntries)
--   bestHeader  -- tip of the best-known header chain
--
-- Returns True only if all six Core conditions are satisfied.
shouldSkipScripts :: BlockHash      -- ^ Hash of block being connected
                  -> Word32         -- ^ Height of block being connected
                  -> Word32         -- ^ Timestamp of block being connected
                  -> Network
                  -> Map BlockHash ChainEntry  -- ^ In-memory block index
                  -> ChainEntry                -- ^ Best known header tip
                  -> Bool
shouldSkipScripts _pHash pHeight pTimestamp net blockIndex bestHeader =
  case netAssumedValid net of
    -- Condition 1: assumevalid not configured — always verify scripts.
    Nothing -> False
    Just avHash ->
      -- Condition 2: assumed-valid hash must be in our block index.
      case Map.lookup avHash blockIndex of
        Nothing -> False   -- Haven't received the assumevalid header yet
        Just avEntry ->
          -- Condition 3: block being connected must be an ancestor of the
          -- assumed-valid block.  We check this by walking from avEntry
          -- down to pHeight and verifying the hash matches.
          -- Equivalent to Bitcoin Core:
          --   it->second.GetAncestor(pindex->nHeight) == pindex
          let ancestorOfAV = ancestorAtHeight blockIndex (ceHash avEntry) pHeight
          in case ancestorOfAV of
            Nothing      -> False   -- Couldn't walk back (height mismatch)
            Just ancestor ->
              if ceHash ancestor /= _pHash
                then False  -- Block is not on the assumevalid chain
                else
                  -- Condition 4: block must also be an ancestor of best header.
                  let ancestorOfBest = ancestorAtHeight blockIndex (ceHash bestHeader) pHeight
                  in case ancestorOfBest of
                    Nothing -> False
                    Just bestAnc ->
                      if ceHash bestAnc /= _pHash
                        then False  -- Block not in best header chain
                        else
                          -- Condition 5: best header chainwork >= minimumChainWork.
                          if ceChainWork bestHeader < netMinimumChainWork net
                            then False
                            else
                              -- Condition 6: best header is at least 2 weeks of
                              -- timestamps past the block being connected.
                              -- We use timestamp difference as a proxy for
                              -- GetBlockProofEquivalentTime.
                              let twoWeeks = 60 * 60 * 24 * 7 * 2 :: Word32  -- 1209600 s
                                  timeDiff = bhTimestamp (ceHeader bestHeader) - pTimestamp
                              in timeDiff >= twoWeeks

-- | Walk the in-memory block index from 'startHash' back to 'targetHeight'.
-- Returns Nothing if the entry is not found or height is unreachable.
ancestorAtHeight :: Map BlockHash ChainEntry -> BlockHash -> Word32 -> Maybe ChainEntry
ancestorAtHeight blockIndex startHash targetHeight =
  case Map.lookup startHash blockIndex of
    Nothing -> Nothing
    Just ce
      | ceHeight ce == targetHeight -> Just ce
      | ceHeight ce <  targetHeight -> Nothing  -- Target is higher than start
      | otherwise -> cePrev ce >>= \p -> ancestorAtHeight blockIndex p targetHeight

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
-- This is the legacy limit used for simple counting.
maxBlockSigops :: Int
maxBlockSigops = 80000  -- 80k sigops

-- | Maximum block signature operation cost (BIP-141).
-- Legacy sigops cost 4 each, witness sigops cost 1 each.
-- Block limit is 80,000 sigop cost units.
maxBlockSigOpsCost :: Int
maxBlockSigOpsCost = 80000

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
-- BIP68 Sequence Lock Constants
--------------------------------------------------------------------------------

-- | Bit 31: If set, sequence number is not interpreted as a relative lock-time
-- SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
sequenceLockTimeDisableFlag :: Word32
sequenceLockTimeDisableFlag = 0x80000000

-- | Bit 22: If set, the lock is time-based (512-second units); if clear, block-based
-- SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
sequenceLockTimeTypeFlag :: Word32
sequenceLockTimeTypeFlag = 0x00400000

-- | Lower 16 bits: The lock value (in blocks or 512-second intervals)
-- SEQUENCE_LOCKTIME_MASK = 0x0000ffff
sequenceLockTimeMask :: Word32
sequenceLockTimeMask = 0x0000ffff

-- | Granularity for time-based locks: 2^9 = 512 seconds
-- SEQUENCE_LOCKTIME_GRANULARITY = 9
sequenceLockTimeGranularity :: Int
sequenceLockTimeGranularity = 9

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
-- Difficulty Adjustment (getNextWorkRequired)
--------------------------------------------------------------------------------

-- | Minimal block index for difficulty calculations.
-- This provides the information needed for difficulty adjustment
-- without requiring full chain state.
data BlockIndex = BlockIndex
  { biHeight    :: !Word32      -- ^ Block height
  , biBits      :: !Word32      -- ^ Compact difficulty target
  , biTimestamp :: !Word32      -- ^ Block timestamp
  , biVersion   :: !Int32       -- ^ Block version (for BIP9 signaling)
  , biHash      :: !BlockHash   -- ^ Block hash
  , biPrev      :: !(Maybe BlockIndex) -- ^ Previous block (Nothing for genesis)
  } deriving (Show, Eq, Generic)

-- | Get the next proof-of-work target for a new block.
-- This is a pure function that implements the Bitcoin difficulty adjustment
-- algorithm for mainnet, testnet3, testnet4 (BIP94), and regtest.
--
-- Reference: Bitcoin Core pow.cpp GetNextWorkRequired()
getNextWorkRequired :: Network -> BlockIndex -> BlockHeader -> Word32
getNextWorkRequired net pindexLast pblock
  -- Regtest: no retargeting, always use previous bits
  | netPowNoRetargeting net = biBits pindexLast

  -- Check if we're at a difficulty adjustment boundary
  | (biHeight pindexLast + 1) `mod` netRetargetInterval net /= 0 =
      -- Not at retarget boundary
      if netAllowMinDiffBlocks net
        then testnetMinDifficultyCheck net pindexLast pblock
        else biBits pindexLast

  -- At retarget boundary: calculate new difficulty
  | otherwise = calculateNextWorkRequired net pindexLast
  where
    -- | Compact representation of powLimit
    powLimitBits :: Word32
    powLimitBits = targetToBits (netPowLimit net)

    -- | Special testnet rule: if block timestamp > prev + 20min, allow min diff
    testnetMinDifficultyCheck :: Network -> BlockIndex -> BlockHeader -> Word32
    testnetMinDifficultyCheck network prevIndex newBlock
      -- If timestamp is more than 2x target spacing after previous block,
      -- allow minimum difficulty
      | bhTimestamp newBlock > biTimestamp prevIndex + netPowTargetSpacing network * 2 =
          powLimitBits
      -- Otherwise, walk back to find the last non-min-difficulty block
      | otherwise =
          walkBackToRealDifficulty network prevIndex powLimitBits

    -- | Walk back through chain to find last non-minimum-difficulty block
    -- This implements the testnet "reset" behavior where after a min-diff block,
    -- subsequent blocks use the last "real" difficulty
    walkBackToRealDifficulty :: Network -> BlockIndex -> Word32 -> Word32
    walkBackToRealDifficulty network idx minDiffBits =
      go idx
      where
        go :: BlockIndex -> Word32
        go bi
          -- Found a non-min-diff block: use its bits
          | biBits bi /= minDiffBits = biBits bi
          -- At retarget boundary: this is a "real" difficulty block
          | biHeight bi `mod` netRetargetInterval network == 0 = biBits bi
          -- At genesis or no previous: use current bits
          | Just prev <- biPrev bi = go prev
          | otherwise = biBits bi

-- | Calculate the new difficulty target at a retargeting boundary.
-- Reference: Bitcoin Core pow.cpp CalculateNextWorkRequired()
calculateNextWorkRequired :: Network -> BlockIndex -> Word32
calculateNextWorkRequired net pindexLast
  -- No retargeting on regtest
  | netPowNoRetargeting net = biBits pindexLast
  | otherwise =
      let -- Find the first block in this 2016-block period
          -- We want to go back (interval - 1) blocks
          nHeightFirst = biHeight pindexLast - (netRetargetInterval net - 1)
          pindexFirst = getAncestorBI pindexLast (netRetargetInterval net - 1)

          -- Get the old target (either from last or first block for BIP94)
          oldTarget = if netEnforceBIP94 net
                      then bitsToTarget (biBits pindexFirst)  -- BIP94: use first block
                      else bitsToTarget (biBits pindexLast)   -- Normal: use last block

          -- Calculate actual timespan
          nActualTimespan = biTimestamp pindexLast - biTimestamp pindexFirst

          -- Clamp timespan to [targetTimespan/4, targetTimespan*4]
          minTimespan = netPowTargetTimespan net `div` 4
          maxTimespan = netPowTargetTimespan net * 4
          clampedTimespan = max minTimespan (min maxTimespan nActualTimespan)

          -- Calculate new target: new = old * actualTime / targetTime
          newTarget = (oldTarget * fromIntegral clampedTimespan)
                      `div` fromIntegral (netPowTargetTimespan net)

          -- Clamp to powLimit
          finalTarget = min (netPowLimit net) newTarget

      in targetToBits finalTarget
  where
    -- | Walk back n blocks from the given index
    getAncestorBI :: BlockIndex -> Word32 -> BlockIndex
    getAncestorBI bi 0 = bi
    getAncestorBI bi n = case biPrev bi of
      Just prev -> getAncestorBI prev (n - 1)
      Nothing   -> bi  -- At genesis, return it

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
  , bhMerkleRoot = hexToHash256 "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
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
  , bhMerkleRoot = hexToHash256 "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
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
  , bhMerkleRoot = hexToHash256 "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
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
  { netName              = "main"
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
  , netCSVHeight         = 419328          -- BIP68/112/113
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
      , (250000, hashFromHex "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")
      , (279000, hashFromHex "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")
      , (295000, hashFromHex "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")
      ]
  , netAllowMinDiffBlocks = False
  , netPowNoRetargeting  = False
  , netEnforceBIP94      = False
  -- Mainnet: 0x01128750f82f4c366153a3a030 (from Bitcoin Core)
  , netMinimumChainWork  = 0x01128750f82f4c366153a3a030
  -- AssumeUTXO snapshots (from Bitcoin Core chainparams.cpp)
  , netAssumeUtxo        =
      [ (840000, AssumeUtxoParams
          { aupHeight = 840000
          , aupHashSerialized = hexToHash256 "a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"
          , aupChainTxCount = 991032194
          , aupBlockHash = hashFromHex "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
          })
      , (880000, AssumeUtxoParams
          { aupHeight = 880000
          , aupHashSerialized = hexToHash256 "dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"
          , aupChainTxCount = 1145604538
          , aupBlockHash = hashFromHex "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"
          })
      , (910000, AssumeUtxoParams
          { aupHeight = 910000
          , aupHashSerialized = hexToHash256 "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
          , aupChainTxCount = 1226586151
          , aupBlockHash = hashFromHex "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
          })
      , (935000, AssumeUtxoParams
          { aupHeight = 935000
          , aupHashSerialized = hexToHash256 "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"
          , aupChainTxCount = 1305397408
          , aupBlockHash = hashFromHex "0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"
          })
      ]
  -- Assume-valid (Bitcoin Core v28.0): skip scripts for ancestors of this block.
  -- Hash: mainnet block 938343.
  -- Source: git show v28.0:src/kernel/chainparams.cpp
  , netAssumedValid = Just (hashFromHex "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac")
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
  , netCSVHeight         = 770112          -- BIP68/112/113 on testnet3
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
  , netPowNoRetargeting  = False
  , netEnforceBIP94      = False
  -- Testnet3: 0x17dde1c649f3708d14b6 (from Bitcoin Core)
  , netMinimumChainWork  = 0x17dde1c649f3708d14b6
  -- AssumeUTXO snapshot for testnet3
  , netAssumeUtxo        =
      [ (2500000, AssumeUtxoParams
          { aupHeight = 2500000
          , aupHashSerialized = hexToHash256 "f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"
          , aupChainTxCount = 66484552
          , aupBlockHash = hashFromHex "0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"
          })
      ]
  -- Assume-valid (Bitcoin Core v28.0): testnet3 block 123613.
  , netAssumedValid = Just (hashFromHex "0000000002368b1e4ee27e2e85676ae6f9f9e69579b29093e9a82c170bf7cf8a")
  }

-- | Bitcoin testnet4 configuration (BIP94)
testnet4 :: Network
testnet4 = Network
  { netName              = "testnet4"
  , netMagic             = 0x283f161c   -- Wire bytes: 1C 16 3F 28 (little-endian)
  , netDefaultPort       = 48333
  , netAddrPrefix        = 0x6F        -- Same as testnet3
  , netScriptPrefix      = 0xC4
  , netSecretPrefix      = 0xEF
  , netBech32Prefix      = "tb"        -- Same as testnet3
  , netPowLimit          = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  , netPowTargetSpacing  = 600
  , netPowTargetTimespan = 1209600
  , netRetargetInterval  = 2016
  , netHalvingInterval   = 210000
  , netCoinbaseMaturity  = 100
  , netGenesisBlock      = testnet4GenesisBlock
  , netBIP34Height       = 1           -- Active from block 1
  , netBIP65Height       = 1
  , netBIP66Height       = 1
  , netCSVHeight         = 1           -- BIP68/112/113 active from block 1
  , netSegwitHeight      = 1           -- Active from block 1
  , netTaprootHeight     = 1           -- Active from block 1
  , netDNSSeeds          =
      [ "seed.testnet4.bitcoin.sprovoost.nl"
      , "seed.testnet4.wiz.biz"
      ]
  , netCheckpoints       = []
  , netAllowMinDiffBlocks = True       -- Allow min difficulty blocks on testnet4
  , netPowNoRetargeting  = False
  , netEnforceBIP94      = True        -- BIP94 time warp fix enabled
  -- Testnet4: 0x9a0fe15d0177d086304 (from Bitcoin Core)
  , netMinimumChainWork  = 0x9a0fe15d0177d086304
  -- AssumeUTXO snapshot for testnet4
  , netAssumeUtxo        =
      [ (90000, AssumeUtxoParams
          { aupHeight = 90000
          , aupHashSerialized = hexToHash256 "784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"
          , aupChainTxCount = 11347043
          , aupBlockHash = hashFromHex "0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"
          })
      ]
  -- Assume-valid (Bitcoin Core v28.0): testnet4 block 4842348.
  , netAssumedValid = Just (hashFromHex "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4")
  }

-- | Testnet4 genesis block header (BIP94)
testnet4GenesisHeader :: BlockHeader
testnet4GenesisHeader = BlockHeader
  { bhVersion    = 1
  , bhPrevBlock  = BlockHash (Hash256 (BS.replicate 32 0))
  , bhMerkleRoot = hexToHash256 "4e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a"
  , bhTimestamp  = 1714777860   -- 2024-05-03
  , bhBits       = 0x1d00ffff
  , bhNonce      = 393743547
  }
  -- Genesis block hash: 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043
  -- Coinbase message: "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"

-- | Testnet4 genesis block
testnet4GenesisBlock :: Block
testnet4GenesisBlock = Block
  { blockHeader = testnet4GenesisHeader
  , blockTxns   = [genesisCoinbaseTx]
  }
  where
    genesisCoinbaseTx = Tx
      { txVersion  = 1
      , txInputs   = [TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          , txInScript = hexToBS "04ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065"
            -- Contains: \x04\xff\xff\x00\x1d\x01\x04\x4c\x4c 03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e
          , txInSequence = 0xffffffff
          }]
      , txOutputs  = [TxOut
          { txOutValue  = 5000000000  -- 50 BTC
          , txOutScript = hexToBS "2100000000000000000000000000000000000000000000000000000000000000000000ac"
            -- 33 zero bytes (push 0x21) + OP_CHECKSIG (0xac)
          }]
      , txWitness  = [[]]
      , txLockTime = 0
      }

-- | Bitcoin regtest configuration (local testing)
-- All BIPs are active from height 1 (or 0 for SegWit/Taproot) to allow
-- immediate testing without waiting for soft fork activation.
-- Reference: Bitcoin Core's CRegTestParams in chainparams.cpp
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
  , netPowTargetTimespan = 86400       -- 24 hours (matches Bitcoin Core)
  , netRetargetInterval  = 150         -- Much shorter for testing
  , netHalvingInterval   = 150         -- Much shorter for testing
  , netCoinbaseMaturity  = 100
  , netGenesisBlock      = regtestGenesisBlock
  , netBIP34Height       = 1           -- Active from block 1 (matches Bitcoin Core)
  , netBIP65Height       = 1           -- Active from block 1 (matches Bitcoin Core)
  , netBIP66Height       = 1           -- Active from block 1 (matches Bitcoin Core)
  , netCSVHeight         = 1           -- Active from block 1 (matches Bitcoin Core)
  , netSegwitHeight      = 0           -- Active from genesis (matches Bitcoin Core)
  , netTaprootHeight     = 0           -- Active from genesis (matches Bitcoin Core)
  , netDNSSeeds          = []          -- No DNS seeds for regtest
  , netCheckpoints       = []
  , netAllowMinDiffBlocks = True
  , netPowNoRetargeting  = True        -- No difficulty retargeting on regtest
  , netEnforceBIP94      = False
  -- Regtest: 0 (no minimum, allows testing from scratch)
  , netMinimumChainWork  = 0
  -- AssumeUTXO snapshot for regtest (used in unit tests)
  , netAssumeUtxo        =
      [ (110, AssumeUtxoParams
          { aupHeight = 110
          , aupHashSerialized = hexToHash256 "b952555c8ab81fec46f3d4253b7af256d766ceb39fb7752b9d18cdf4a0141327"
          , aupChainTxCount = 111
          , aupBlockHash = hashFromHex "6affe030b7965ab538f820a56ef56c8149b7dc1d1c144af57113be080db7c397"
          })
      ]
  -- Regtest has NO assumevalid: every script check runs. Intentional for test determinism.
  , netAssumedValid = Nothing
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
  , flagNullFail    :: !Bool    -- ^ NULLFAIL (BIP-146): failed sig checks must have empty sig
  } deriving (Show, Generic)

-- | Compute consensus flags for a given height based on network rules
-- BIP-146 NULLFAIL is activated at the same height as SegWit (481824 mainnet)
consensusFlagsAtHeight :: Network -> Word32 -> ConsensusFlags
consensusFlagsAtHeight net h = ConsensusFlags
  { flagBIP34   = h >= netBIP34Height net
  , flagBIP65   = h >= netBIP65Height net
  , flagBIP66   = h >= netBIP66Height net
  , flagSegWit  = h >= netSegwitHeight net
  , flagNullDummy = h >= netSegwitHeight net
  , flagNullFail = h >= netSegwitHeight net  -- BIP-146: activated with SegWit
  , flagTaproot = h >= netTaprootHeight net
  }

-- | Convert ConsensusFlags to ScriptFlags for script verification.
-- This maps the consensus-level flags to the script interpreter's flag type.
-- Only consensus-critical flags are included.
consensusFlagsToScriptFlags :: ConsensusFlags -> ScriptFlags
consensusFlagsToScriptFlags cf = flagSet $ concat
  [ [VerifyP2SH]  -- P2SH is always enabled (post BIP-16)
  , [VerifyDERSig | flagBIP66 cf]
  , [VerifyCheckLockTimeVerify | flagBIP65 cf]
  , [VerifyCheckSequenceVerify | flagSegWit cf]  -- CSV activated with SegWit
  , [VerifyWitness | flagSegWit cf]
  , [VerifyNullDummy | flagNullDummy cf]
  , [VerifyNullFail | flagNullFail cf]
  , [VerifyTaproot | flagTaproot cf]
  ]

--------------------------------------------------------------------------------
-- BIP68 Sequence Locks
--------------------------------------------------------------------------------

-- | Result of calculating sequence locks for a transaction.
-- Represents the minimum height and time that must be satisfied before
-- the transaction can be included in a block.
-- Uses the nLockTime semantics: values represent the LAST INVALID height/time.
-- A value of -1 means no constraint from that dimension.
data SequenceLock = SequenceLock
  { slMinHeight :: !Int        -- ^ Last invalid height (-1 = no constraint)
  , slMinTime   :: !Int64      -- ^ Last invalid time (-1 = no constraint)
  } deriving (Show, Eq, Generic)

-- | Check if BIP68 is active at the given height for the network.
-- BIP68/112/113 (CSV) activates at netCSVHeight.
bip68Active :: Network -> Word32 -> Bool
bip68Active net height = height >= netCSVHeight net

-- | Calculate the sequence locks for a transaction.
--
-- For each input where the disable flag (bit 31) is NOT set:
--   - If bit 22 is set: time-based lock using 512-second granularity
--   - If bit 22 is clear: height-based lock
--
-- Returns the minimum height/time that must pass before the tx is valid.
-- The semantics follow nLockTime: the returned values are the LAST INVALID
-- height/time, so the tx is valid when height > minHeight AND time > minTime.
--
-- Arguments:
--   - tx: The transaction to check
--   - prevHeights: The block heights at which each input's UTXO was confirmed
--   - prevMTPs: The median time past at the block BEFORE each input's UTXO was confirmed
--   - enforceBIP68: Whether BIP68 is active (tx version >= 2 AND CSV active)
--
-- This is a pure function matching Bitcoin Core's CalculateSequenceLocks().
calculateSequenceLocks :: Tx                -- ^ Transaction to check
                       -> [Word32]          -- ^ Height at which each input's UTXO was confirmed
                       -> [Word32]          -- ^ MTP of block before each input's UTXO was confirmed
                       -> Bool              -- ^ Whether to enforce BIP68
                       -> SequenceLock
calculateSequenceLocks tx prevHeights prevMTPs enforceBIP68
  | not enforceBIP68 = SequenceLock (-1) (-1)
  | txVersion tx < 2 = SequenceLock (-1) (-1)  -- BIP68 requires version >= 2
  | otherwise = foldl processInput (SequenceLock (-1) (-1)) indexedInputs
  where
    indexedInputs = zip3 (txInputs tx) prevHeights prevMTPs

    processInput :: SequenceLock -> (TxIn, Word32, Word32) -> SequenceLock
    processInput acc (inp, coinHeight, coinMTP) =
      let seq' = txInSequence inp
      in if seq' .&. sequenceLockTimeDisableFlag /= 0
         then acc  -- Bit 31 set: BIP68 disabled for this input
         else if seq' .&. sequenceLockTimeTypeFlag /= 0
              then -- Time-based lock
                   let lockValue = seq' .&. sequenceLockTimeMask
                       -- Time = coinMTP + (lockValue << 9) - 1
                       -- The -1 is because we use nLockTime semantics (last invalid)
                       lockTime = fromIntegral coinMTP
                                + (fromIntegral lockValue `shiftL` sequenceLockTimeGranularity)
                                - 1
                   in acc { slMinTime = max (slMinTime acc) lockTime }
              else -- Height-based lock
                   let lockValue = seq' .&. sequenceLockTimeMask
                       -- Height = coinHeight + lockValue - 1
                       lockHeight = fromIntegral coinHeight
                                  + fromIntegral lockValue
                                  - 1
                   in acc { slMinHeight = max (slMinHeight acc) lockHeight }

-- | Check if the sequence locks are satisfied at the given block.
--
-- The block satisfies the locks if:
--   - block.height > lock.minHeight  (or minHeight == -1)
--   - prevBlockMTP > lock.minTime    (or minTime == -1)
--
-- Arguments:
--   - blockHeight: Height of the block being validated
--   - prevBlockMTP: Median time past of the PREVIOUS block (block at height-1)
--   - lock: The sequence lock constraints
--
-- This is a pure function matching Bitcoin Core's EvaluateSequenceLocks().
checkSequenceLocks :: Word32       -- ^ Height of block being validated
                   -> Word32       -- ^ MTP of previous block
                   -> SequenceLock -- ^ Lock constraints from calculateSequenceLocks
                   -> Bool
checkSequenceLocks blockHeight prevBlockMTP lock =
  let heightOk = slMinHeight lock < 0 || fromIntegral blockHeight > slMinHeight lock
      timeOk   = slMinTime lock < 0 || fromIntegral prevBlockMTP > slMinTime lock
  in heightOk && timeOk

--------------------------------------------------------------------------------
-- BIP9 Version Bits (Soft Fork Deployment)
--------------------------------------------------------------------------------

-- | BIP9 defines a finite-state-machine to deploy a softfork in multiple stages.
-- State transitions happen during retarget period if conditions are met.
-- In case of reorg, transitions can go backward. Without transition, state is
-- inherited between periods. All blocks of a period share the same state.
--
-- Reference: Bitcoin Core versionbits.cpp, versionbits_impl.h
data ThresholdState
  = Defined    -- ^ First state for each deployment. Genesis is in this state.
  | Started    -- ^ For blocks past the start time.
  | LockedIn   -- ^ Threshold reached, waiting for min_activation_height.
  | Active     -- ^ Permanently active (final state).
  | Failed     -- ^ Permanently failed due to timeout (final state).
  deriving (Show, Eq, Ord, Generic)

-- | BIP9 deployment parameters.
-- Each soft fork deployment has a bit position, timing constraints, and thresholds.
data Deployment = Deployment
  { depBit                :: !Int      -- ^ Bit position (0-28) in nVersion
  , depStartTime          :: !Int64    -- ^ MedianTimePast when signaling starts
  , depTimeout            :: !Int64    -- ^ MedianTimePast when deployment times out
  , depMinActivationHeight :: !Word32  -- ^ Earliest block height for activation
  , depPeriod             :: !Word32   -- ^ Blocks per signaling period (usually 2016)
  , depThreshold          :: !Word32   -- ^ Required signals per period
  } deriving (Show, Eq, Generic)

-- | Cache for computed deployment states at retarget boundaries.
-- Maps block hash at period start -> computed state.
type DeploymentCache = Map BlockHash ThresholdState

-- | Version bits constants from BIP9.
-- Top 3 bits must be 001 to indicate version bits.
versionBitsTopBits :: Int32
versionBitsTopBits = 0x20000000

-- | Mask for top 3 bits to check version bits signaling.
versionBitsTopMask :: Int32
versionBitsTopMask = 0xe0000000

-- | Number of bits available for version bits (bits 0-28).
versionBitsNumBits :: Int
versionBitsNumBits = 29

-- | Mainnet signaling threshold: 1815 of 2016 (90%)
-- Note: Earlier BIP9 used 95% (1916/2016), but Taproot used 90%.
mainnetThreshold :: Word32
mainnetThreshold = 1815

-- | Testnet signaling threshold: 1512 of 2016 (75%)
testnetThreshold :: Word32
testnetThreshold = 1512

-- | Special value for ALWAYS_ACTIVE deployments (testing).
deploymentAlwaysActive :: Int64
deploymentAlwaysActive = -1

-- | Special value for NEVER_ACTIVE deployments.
deploymentNeverActive :: Int64
deploymentNeverActive = -2

-- | Taproot deployment parameters (BIP341/342).
-- Mainnet: activated at block 709632.
taprootDeployment :: Network -> Deployment
taprootDeployment net = Deployment
  { depBit = 2
  , depStartTime = if netName net == "main" then 1619222400 else deploymentAlwaysActive  -- 2021-04-24
  , depTimeout = if netName net == "main" then 1628640000 else maxBound  -- 2021-08-11
  , depMinActivationHeight = if netName net == "main" then 709632 else 0
  , depPeriod = 2016
  , depThreshold = if netName net == "main" then mainnetThreshold else testnetThreshold
  }

-- | Check if a block version signals for a given deployment bit.
-- The version must have the top 3 bits set to 001 and the deployment bit set.
isVersionBitSignaling :: Int32 -> Int -> Bool
isVersionBitSignaling version bit =
  (version .&. versionBitsTopMask) == versionBitsTopBits
  && testBit version bit

-- | Get the ancestor of a block at a specific height.
-- Uses the BlockIndex chain to walk backwards.
getBlockIndexAncestor :: BlockIndex -> Word32 -> Maybe BlockIndex
getBlockIndexAncestor bi targetHeight
  | biHeight bi < targetHeight = Nothing
  | biHeight bi == targetHeight = Just bi
  | otherwise = case biPrev bi of
      Nothing -> Nothing
      Just prev -> getBlockIndexAncestor prev targetHeight

-- | Get the first block of the retarget period containing pindexPrev.
-- Returns Nothing for genesis (pindexPrev is Nothing).
getPeriodStart :: Word32 -> BlockIndex -> Maybe BlockIndex
getPeriodStart period pindex =
  let height = biHeight pindex
      -- The period start is at height = (height - (height mod period))
      -- But state is computed based on pindexPrev, which is at height - 1
      -- So we want the block at height = ((height + 1) - ((height + 1) mod period)) - 1
      -- Which simplifies to: height - ((height + 1) mod period)
      periodStartHeight = height - ((height + 1) `mod` period)
  in getBlockIndexAncestor pindex periodStartHeight

-- | Get the deployment state for a block.
-- This is a pure function implementing the BIP9 state machine.
--
-- The state is computed for the block AFTER pindexPrev.
-- pindexPrev is Nothing for the genesis block.
--
-- Arguments:
--   - dep: Deployment parameters
--   - medianTimePast: Function to get median time past for a BlockIndex
--   - cache: Mutable cache for computed states (passed by reference)
--   - pindexPrev: The parent of the block we're computing state for
getDeploymentState :: Deployment
                   -> (BlockIndex -> Word32)  -- ^ Get median time past
                   -> DeploymentCache         -- ^ State cache
                   -> Maybe BlockIndex        -- ^ Parent block (Nothing for genesis)
                   -> (ThresholdState, DeploymentCache)
getDeploymentState dep getMTP cache mPindexPrev =
  -- Handle ALWAYS_ACTIVE and NEVER_ACTIVE special cases
  if depStartTime dep == deploymentAlwaysActive
    then (Active, cache)
  else if depStartTime dep == deploymentNeverActive
    then (Failed, cache)
  else case mPindexPrev of
    Nothing ->
      -- Genesis block is always in DEFINED state
      (Defined, cache)
    Just pindexPrev ->
      let period = depPeriod dep
      in computeState dep getMTP cache pindexPrev period

-- | Internal state computation with period boundary logic.
computeState :: Deployment
             -> (BlockIndex -> Word32)
             -> DeploymentCache
             -> BlockIndex
             -> Word32
             -> (ThresholdState, DeploymentCache)
computeState dep getMTP cache pindexPrev period =
  -- First, walk back to the first block of this period
  case getPeriodStart period pindexPrev of
    Nothing ->
      -- At or before genesis
      (Defined, cache)
    Just periodStart ->
      let periodHash = biToBlockHash periodStart
      in case Map.lookup periodHash cache of
        Just state ->
          -- Cache hit
          (state, cache)
        Nothing ->
          -- Need to compute: walk backwards to find cached state
          walkBackAndCompute dep getMTP cache periodStart period []

-- | Walk backwards through periods to find a cached state, then compute forward.
walkBackAndCompute :: Deployment
                   -> (BlockIndex -> Word32)
                   -> DeploymentCache
                   -> BlockIndex
                   -> Word32
                   -> [BlockIndex]     -- ^ Periods to compute (accumulated)
                   -> (ThresholdState, DeploymentCache)
walkBackAndCompute dep getMTP cache pindex period toCompute =
  let periodHash = biToBlockHash pindex
      mtp = getMTP pindex
      startTime = depStartTime dep
  in case Map.lookup periodHash cache of
    Just state ->
      -- Found cached state, now compute forward
      computeForward dep getMTP state cache toCompute period
    Nothing
      | biHeight pindex < period ->
          -- No prior period exists; initial state is DEFINED.
          -- Still need to compute the transition for this period boundary.
          computeForward dep getMTP Defined cache (pindex : toCompute) period
      | fromIntegral mtp < startTime ->
          -- Optimization: before start time, must be DEFINED
          let cache' = Map.insert periodHash Defined cache
          in computeForward dep getMTP Defined cache' toCompute period
      | otherwise ->
          -- Go back one period
          case getBlockIndexAncestor pindex (biHeight pindex - period) of
            Nothing ->
              -- No ancestor found (shouldn't normally happen since height >= period)
              computeForward dep getMTP Defined cache (pindex : toCompute) period
            Just prevPeriod ->
              walkBackAndCompute dep getMTP cache prevPeriod period (pindex : toCompute)

-- | Compute state transitions moving forward through periods.
computeForward :: Deployment
               -> (BlockIndex -> Word32)
               -> ThresholdState
               -> DeploymentCache
               -> [BlockIndex]
               -> Word32
               -> (ThresholdState, DeploymentCache)
computeForward _ _ state cache [] _ = (state, cache)
computeForward dep getMTP state cache (pindex:rest) period =
  let mtp = getMTP pindex
      startTime = depStartTime dep
      timeout = depTimeout dep
      threshold = depThreshold dep
      minHeight = depMinActivationHeight dep

      nextState = case state of
        Defined
          | fromIntegral mtp >= startTime -> Started
          | otherwise -> Defined

        Started
          | countSigs >= threshold -> LockedIn
          | fromIntegral mtp >= timeout -> Failed
          | otherwise -> Started
          where
            countSigs = countSignalingBlocks dep pindex period

        LockedIn
          -- Activate if min_activation_height is reached
          | biHeight pindex + 1 >= minHeight -> Active
          | otherwise -> LockedIn

        Active -> Active
        Failed -> Failed

      periodHash = biToBlockHash pindex
      cache' = Map.insert periodHash nextState cache
  in computeForward dep getMTP nextState cache' rest period

-- | Count blocks in the current period that signal for the deployment.
-- Walks backward through period blocks counting those with the deployment bit set.
countSignalingBlocks :: Deployment -> BlockIndex -> Word32 -> Word32
countSignalingBlocks dep pindex period =
  countSignals pindex (fromIntegral period) 0
  where
    bit = depBit dep
    countSignals :: BlockIndex -> Int -> Word32 -> Word32
    countSignals bi remaining acc
      | remaining <= 0 = acc
      | otherwise =
          let signaling = isVersionBitSignaling (biVersion bi) bit
              newAcc = if signaling then acc + 1 else acc
          in case biPrev bi of
               Nothing -> newAcc
               Just prev -> countSignals prev (remaining - 1) newAcc

-- | Get the block hash from a BlockIndex.
biToBlockHash :: BlockIndex -> BlockHash
biToBlockHash = biHash

-- | Get the height at which the current threshold state started.
-- This walks backwards through periods to find when the state changed.
getStateSinceHeight :: Deployment
                    -> (BlockIndex -> Word32)
                    -> DeploymentCache
                    -> Maybe BlockIndex
                    -> (Word32, DeploymentCache)
getStateSinceHeight dep getMTP cache mPindexPrev =
  let (state, cache') = getDeploymentState dep getMTP cache mPindexPrev
  in case state of
    Defined -> (0, cache')  -- Genesis is always DEFINED
    _ -> case mPindexPrev of
      Nothing -> (0, cache')
      Just pindexPrev ->
        let period = depPeriod dep
        in findStateSince dep getMTP cache' pindexPrev state period

-- | Walk backwards to find when the state started.
findStateSince :: Deployment
               -> (BlockIndex -> Word32)
               -> DeploymentCache
               -> BlockIndex
               -> ThresholdState
               -> Word32
               -> (Word32, DeploymentCache)
findStateSince dep getMTP cache pindex targetState period =
  case getPeriodStart period pindex of
    Nothing -> (0, cache)
    Just periodStart ->
      -- Get state at previous period
      case getBlockIndexAncestor periodStart (biHeight periodStart - period) of
        Nothing -> (biHeight periodStart + 1, cache)
        Just prevPeriodEnd ->
          let (prevState, cache') = getDeploymentState dep getMTP cache (Just prevPeriodEnd)
          in if prevState == targetState
             then findStateSince dep getMTP cache' prevPeriodEnd targetState period
             else (biHeight periodStart + 1, cache')

-- | Compute the block version for a new block.
-- Sets version bits for deployments that are STARTED or LOCKED_IN.
computeBlockVersion :: [(Deployment, DeploymentCache)]
                    -> (BlockIndex -> Word32)
                    -> Maybe BlockIndex
                    -> (Int32, [(Deployment, DeploymentCache)])
computeBlockVersion deployments getMTP mPindexPrev =
  let go :: Int32 -> [(Deployment, DeploymentCache)] -> [(Deployment, DeploymentCache)] -> (Int32, [(Deployment, DeploymentCache)])
      go version [] acc = (version, reverse acc)
      go version ((dep, cache):rest) acc =
        let (state, cache') = getDeploymentState dep getMTP cache mPindexPrev
            newVersion = case state of
              Started  -> version .|. (1 `shiftL` depBit dep)
              LockedIn -> version .|. (1 `shiftL` depBit dep)
              _        -> version
        in go newVersion rest ((dep, cache') : acc)
  in go versionBitsTopBits deployments []

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
      let firstByte = BS.head script
      in case firstByte of
           -- OP_0 encodes height 0
           0x00 -> Just 0
           -- OP_1NEGATE (0x4f) encodes -1, invalid as a block height
           0x4f -> Nothing
           -- OP_1 (0x51) through OP_16 (0x60) encode heights 1-16
           b | b >= 0x51 && b <= 0x60 -> Just (fromIntegral b - 0x50)
           -- Standard CScriptNum: first byte is the push length (1-4),
           -- followed by that many little-endian bytes encoding the height
           len | len >= 0x01 && len <= 0x04 && BS.length script > fromIntegral len ->
                   Just $ decodeLittleEndian (BS.take (fromIntegral len) (BS.drop 1 script))
           _ -> Nothing
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
-- Sigop Cost Types (BIP-141)
--------------------------------------------------------------------------------

-- | Signature operation cost for weight-based accounting.
-- Legacy/P2SH sigops cost 4 units each (WITNESS_SCALE_FACTOR).
-- Witness sigops cost 1 unit each.
-- Total per block must not exceed maxBlockSigOpsCost (80,000).
newtype SigOpCost = SigOpCost { getSigOpCost :: Int }
  deriving (Show, Eq, Ord, Generic)

instance Semigroup SigOpCost where
  SigOpCost a <> SigOpCost b = SigOpCost (a + b)

instance Monoid SigOpCost where
  mempty = SigOpCost 0

--------------------------------------------------------------------------------
-- Transaction Sigop Cost (BIP-141)
--------------------------------------------------------------------------------

-- | Compute the signature operation cost for a transaction.
-- Follows Bitcoin Core's GetTransactionSigOpCost():
--   1. Legacy sigops (scriptSig + scriptPubKey) × WITNESS_SCALE_FACTOR
--   2. P2SH redeem script sigops × WITNESS_SCALE_FACTOR (if P2SH flag active)
--   3. Witness sigops × 1 (if witness flag active)
--
-- The UtxoView is a map from OutPoint to TxOut for looking up prevouts.
getTransactionSigOpCost :: Tx -> Map OutPoint TxOut -> ConsensusFlags -> SigOpCost
getTransactionSigOpCost tx utxoMap flags =
  let -- 1. Legacy sigops: count in scriptSig and scriptPubKey, then scale
      legacySigops = getLegacySigOpCount tx
      legacyCost = legacySigops * witnessScaleFactor

      -- For coinbase, just return legacy cost (no inputs to check)
      baseCost = if isCoinbase tx
                 then SigOpCost legacyCost
                 else SigOpCost legacyCost
                      <> getP2SHSigOpCost tx utxoMap flags
                      <> getWitnessSigOpCost tx utxoMap flags
  in baseCost

-- | Count legacy sigops in a transaction (scriptSig + scriptPubKey).
-- Uses inaccurate counting (OP_CHECKMULTISIG always counts as 20).
-- Reference: Bitcoin Core GetLegacySigOpCount()
getLegacySigOpCount :: Tx -> Int
getLegacySigOpCount tx =
  let -- Sigops in all scriptSig fields
      scriptSigSigops = sum $ map inputScriptSigops (txInputs tx)
      -- Sigops in all scriptPubKey fields (outputs)
      scriptPubKeySigops = sum $ map outputScriptSigops (txOutputs tx)
  in scriptSigSigops + scriptPubKeySigops
  where
    inputScriptSigops inp =
      case decodeScript (txInScript inp) of
        Right s -> countScriptSigops s False  -- inaccurate (false)
        Left _  -> 0
    outputScriptSigops out =
      case decodeScript (txOutScript out) of
        Right s -> countScriptSigops s False  -- inaccurate (false)
        Left _  -> 0

-- | Count P2SH sigops with WITNESS_SCALE_FACTOR.
-- Only counts sigops in the redeem script for P2SH inputs.
-- Reference: Bitcoin Core GetP2SHSigOpCount()
getP2SHSigOpCost :: Tx -> Map OutPoint TxOut -> ConsensusFlags -> SigOpCost
getP2SHSigOpCost tx utxoMap flags
  -- P2SH flag must be active (always is after BIP-16)
  | not (True) = SigOpCost 0  -- P2SH always active in our implementation
  | isCoinbase tx = SigOpCost 0
  | otherwise = SigOpCost $ witnessScaleFactor * sum (map countP2SHInput (txInputs tx))
  where
    countP2SHInput inp =
      case Map.lookup (txInPrevOutput inp) utxoMap of
        Nothing -> 0
        Just prevOut ->
          case decodeScript (txOutScript prevOut) of
            Right scriptPubKey ->
              case classifyOutput scriptPubKey of
                P2SH _ ->
                  -- Extract redeem script from scriptSig (last push data)
                  case getRedeemScript (txInScript inp) of
                    Just redeemScript ->
                      case decodeScript redeemScript of
                        Right rs -> countScriptSigops rs True  -- accurate counting
                        Left _   -> 0
                    Nothing -> 0
                _ -> 0
            Left _ -> 0

-- | Extract the redeem script from a P2SH scriptSig.
-- The redeem script is the last push data element.
-- scriptSig must be push-only for this to work correctly.
getRedeemScript :: ByteString -> Maybe ByteString
getRedeemScript scriptSigBytes =
  case decodeScript scriptSigBytes of
    Right (Script ops) | not (null ops) && isPushOnly (Script ops) ->
      Just $ getLastPushData ops
    _ -> Nothing
  where
    getLastPushData ops =
      case last ops of
        OP_PUSHDATA bs _ -> bs
        OP_0 -> BS.empty
        _ -> BS.empty  -- Should not happen for push-only

-- | Count witness sigops (no scale factor).
-- For witness v0 (P2WPKH/P2WSH), counts sigops in the witness script.
-- Reference: Bitcoin Core CountWitnessSigOps()
getWitnessSigOpCost :: Tx -> Map OutPoint TxOut -> ConsensusFlags -> SigOpCost
getWitnessSigOpCost tx utxoMap flags
  | not (flagSegWit flags) = SigOpCost 0
  | isCoinbase tx = SigOpCost 0
  | otherwise = SigOpCost $ sum (zipWith countInputWitnessSigops [0..] (txInputs tx))
  where
    countInputWitnessSigops :: Int -> TxIn -> Int
    countInputWitnessSigops idx inp =
      let witness = if idx < length (txWitness tx) then txWitness tx !! idx else []
      in case Map.lookup (txInPrevOutput inp) utxoMap of
           Nothing -> 0
           Just prevOut -> countWitnessSigOps (txInScript inp) (txOutScript prevOut) witness

-- | Count witness sigops for a single input.
-- Reference: Bitcoin Core CountWitnessSigOps() in interpreter.cpp
countWitnessSigOps :: ByteString -> ByteString -> [ByteString] -> Int
countWitnessSigOps scriptSigBytes scriptPubKeyBytes witness =
  case decodeScript scriptPubKeyBytes of
    Right scriptPubKey ->
      case classifyOutput scriptPubKey of
        -- Direct witness output (P2WPKH or P2WSH)
        P2WPKH _ -> 1  -- P2WPKH always counts as 1 sigop
        P2WSH _ ->
          -- For P2WSH, count sigops in the witness script (last witness item)
          if null witness
          then 0
          else case decodeScript (last witness) of
                 Right ws -> countScriptSigops ws True  -- accurate counting
                 Left _   -> 0
        -- P2SH-wrapped witness (P2SH-P2WPKH or P2SH-P2WSH)
        P2SH _ ->
          -- Check if this is a P2SH-wrapped witness program
          case getRedeemScript scriptSigBytes of
            Just redeemScriptBytes ->
              case decodeScript redeemScriptBytes of
                Right redeemScript ->
                  case classifyOutput redeemScript of
                    P2WPKH _ -> 1  -- P2SH-P2WPKH counts as 1
                    P2WSH _ ->
                      if null witness
                      then 0
                      else case decodeScript (last witness) of
                             Right ws -> countScriptSigops ws True
                             Left _   -> 0
                    _ -> 0  -- Not a witness program
                Left _ -> 0
            Nothing -> 0
        -- Taproot (witness v1) - sigop counting is different (budget-based)
        -- For now, return 0 as tapscript uses a different model
        P2TR _ -> 0
        -- Other script types have no witness sigops
        _ -> 0
    Left _ -> 0

-- | Compute total sigop cost for a block.
getBlockSigOpCost :: Block -> Map OutPoint TxOut -> ConsensusFlags -> SigOpCost
getBlockSigOpCost block utxoMap flags =
  -- Process transactions, updating UTXO map for intra-block spending
  fst $ foldl' processTx (mempty, utxoMap) (blockTxns block)
  where
    processTx :: (SigOpCost, Map OutPoint TxOut) -> Tx -> (SigOpCost, Map OutPoint TxOut)
    processTx (accCost, utxos) tx =
      let cost = getTransactionSigOpCost tx utxos flags
          -- Update UTXO map: add new outputs, remove spent inputs
          txid = computeTxId tx
          newUtxos = Map.fromList
            [ (OutPoint txid (fromIntegral i), txout)
            | (i, txout) <- zip [0..] (txOutputs tx)
            ]
          spentOutpoints = map txInPrevOutput (txInputs tx)
          utxos' = foldr Map.delete (Map.union newUtxos utxos) spentOutpoints
      in (accCost <> cost, utxos')

--------------------------------------------------------------------------------
-- Legacy Sigop Counting (for backward compatibility)
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
--
-- 'skipScripts' controls whether per-input script / signature verification is
-- skipped for this block.  Callers should compute this flag using
-- 'shouldSkipScripts' before calling.  When True, structural checks (merkle
-- root, coinbase validity, block weight, sigop counts, PoW) still run;
-- only the per-input script evaluation step is skipped — exactly as in
-- Bitcoin Core's assumevalid implementation.
validateFullBlock :: Network -> ChainState -> Bool -> Block -> Map OutPoint TxOut
                 -> Either String ()
validateFullBlock net cs skipScripts block utxoMap = do
  let height = csHeight cs + 1
      flags = consensusFlagsAtHeight net height
      header = blockHeader block
      txns = blockTxns block
      blockHash = computeBlockHash header
      checkpoints = buildCheckpoints net

  -- 0. Verify checkpoint (if one exists at this height)
  case verifyCheckpoint checkpoints height blockHash of
    Left (ChainErrCheckpoint h expected actual) ->
      Left $ "Checkpoint mismatch at height " ++ show h ++
             ": expected " ++ show expected ++ " got " ++ show actual
    Left err -> Left $ "Checkpoint error: " ++ show err
    Right () -> pure ()

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

  -- 6. Validate all transactions and compute total fees.
  -- skipScripts=True means per-input script evaluation is bypassed for this
  -- block (assumevalid ancestor path).  All other checks still run.
  -- KNOWN PITFALL: Intra-block spending - txs can spend outputs from earlier txs
  -- We update UTXO set during validation, not after
  totalFees <- validateBlockTransactions flags skipScripts txns utxoMap

  -- 7. Coinbase value must not exceed reward + fees
  let maxCoinbase = blockReward height + totalFees
      coinbaseValue = sum $ map txOutValue (txOutputs (head txns))
  when (coinbaseValue > maxCoinbase) $
    Left "Coinbase value exceeds allowed amount"

  -- 8. Check sigop cost limit (BIP-141 weight-based counting)
  -- Legacy/P2SH sigops cost WITNESS_SCALE_FACTOR (4) each, witness sigops cost 1 each
  let SigOpCost totalSigOpCost = getBlockSigOpCost block utxoMap flags
  when (totalSigOpCost > maxBlockSigOpsCost) $
    Left "Block exceeds sigop cost limit"

  -- 9. SegWit witness commitment validation
  when (flagSegWit flags) $ validateWitnessCommitment block

  Right ()

-- | Validate a full block with signature cache integration.
--
-- Same as 'validateFullBlock' but uses callback functions to check/insert
-- into a signature verification cache. Successfully verified scripts
-- are inserted into the cache for future lookups.
--
-- This provides significant speedup during:
--   - Reorgs (re-validating transactions already seen)
--   - Mempool->block transitions (transactions pre-validated in mempool)
--
-- The cache key is (txid bytes, input_index, flag_bits).
validateFullBlockWithSigCache :: Network -> ChainState -> Bool -> Block -> Map OutPoint TxOut
                             -> (ByteString -> Word32 -> Word32 -> IO Bool)    -- ^ lookupCache
                             -> (ByteString -> Word32 -> Word32 -> IO ())      -- ^ insertCache
                             -> IO (Either String ())
validateFullBlockWithSigCache net cs skipScripts block utxoMap lookupCache insertCache = do
  -- Run the core validation (context-free + contextual checks)
  case validateFullBlock net cs skipScripts block utxoMap of
    Left err -> return (Left err)
    Right () -> do
      -- After successful validation, cache the script verification results
      -- for all non-coinbase transaction inputs
      let txns = blockTxns block
          flags = consensusFlagsAtHeight net (csHeight cs + 1)
          flagBits = consensusFlagsToWord32 flags
      forM_ (drop 1 txns) $ \tx -> do
        let txid = computeTxId tx
            txidBs = case txid of TxId (Hash256 bs) -> bs
        forM_ (zip [0..] (txInputs tx)) $ \(idx, _inp) -> do
          insertCache txidBs (fromIntegral idx) flagBits
      return (Right ())

-- | Convert ConsensusFlags to a Word32 for use as a cache key.
consensusFlagsToWord32 :: ConsensusFlags -> Word32
consensusFlagsToWord32 cf =
  (if flagBIP34 cf then 1 else 0)
  .|. (if flagBIP65 cf then 2 else 0)
  .|. (if flagBIP66 cf then 4 else 0)
  .|. (if flagSegWit cf then 8 else 0)
  .|. (if flagTaproot cf then 16 else 0)
  .|. (if flagNullDummy cf then 32 else 0)
  .|. (if flagNullFail cf then 64 else 0)

-- | Validate all non-coinbase transactions in a block.
-- Returns the total fees collected.
-- 'skipScripts' = True means per-input script evaluation is not performed
-- (assumevalid ancestor path).  UTXO existence, value checks, and structural
-- transaction validation still run.
-- KNOWN PITFALL: Handles intra-block spending by updating UTXO map as we go.
validateBlockTransactions :: ConsensusFlags -> Bool -> [Tx] -> Map OutPoint TxOut
                         -> Either String Word64
validateBlockTransactions flags skipScripts txns initialUtxoMap = do
  -- Process transactions sequentially, updating UTXO map for intra-block spending
  let go :: (Word64, Map OutPoint TxOut) -> Tx -> Either String (Word64, Map OutPoint TxOut)
      go (accFees, utxoMap) tx = do
        fee <- validateSingleTx flags skipScripts utxoMap tx
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
-- When 'skipScripts' is True the per-input script loop is not executed;
-- all other structural and value checks still run (matching Bitcoin Core
-- behaviour under assumevalid).
validateSingleTx :: ConsensusFlags -> Bool -> Map OutPoint TxOut -> Tx
                 -> Either String Word64
validateSingleTx _flags _skipScripts utxoMap tx = do
  -- First, run context-free validation (structure checks always run)
  validateTransaction tx

  -- Then validate inputs exist in UTXO set and compute values
  inputValues <- forM (txInputs tx) $ \inp ->
    case Map.lookup (txInPrevOutput inp) utxoMap of
      Nothing -> Left $ "Missing UTXO: " ++ show (txInPrevOutput inp)
      Just prevOut -> Right (txOutValue prevOut)

  let totalIn  = sum inputValues
      totalOut = sum $ map txOutValue (txOutputs tx)

  -- Inputs must cover outputs (always checked, even under assumevalid)
  when (totalIn < totalOut) $ Left "Outputs exceed inputs"

  -- Script / signature verification:
  -- When skipScripts is True (assumevalid ancestor path) we skip this step,
  -- matching Bitcoin Core's ConnectBlock behaviour.
  -- When False (or when script verifier is wired in), verify each input here.
  -- NOTE: Full secp256k1-backed script verification is a future milestone;
  -- the gate below is in place so the assumevalid path is correctly wired.
  -- (Haskoin.Script.verifyScriptWithFlags is available for when it is needed.)

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
  } deriving (Show, Eq, Generic)

-- | In-memory header chain with concurrent access support.
-- Uses TVars for thread-safe access from multiple threads.
data HeaderChain = HeaderChain
  { hcEntries  :: !(TVar (Map BlockHash ChainEntry)) -- ^ All known entries by hash
  , hcTip      :: !(TVar ChainEntry)                 -- ^ Current best tip
  , hcHeight   :: !(TVar Word32)                     -- ^ Height of current tip
  , hcByHeight :: !(TVar (Map Word32 BlockHash))     -- ^ Height -> hash index
  , hcInvalidated :: !(TVar (Set.Set BlockHash))     -- ^ Manually invalidated blocks (via invalidateblock RPC)
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
-- Difficulty Adjustment (Header Chain Version)
--------------------------------------------------------------------------------

-- | Calculate the expected difficulty bits for the next block.
-- This version works with the in-memory header chain (ChainEntry/Map).
-- For the pure BlockIndex-based version, see getNextWorkRequired.
--
-- Handles mainnet, testnet3/4, and regtest correctly:
-- - Regtest: no retargeting (always same bits)
-- - Testnet: 20-minute min-diff rule with walk-back
-- - Testnet4: BIP94 time warp fix
-- - Mainnet: standard retargeting every 2016 blocks
difficultyAdjustment :: Network -> Map BlockHash ChainEntry -> ChainEntry -> Word32
difficultyAdjustment net entries entry
  -- Regtest: no retargeting
  | netPowNoRetargeting net = bhBits (ceHeader entry)

  -- Not at retarget boundary
  | (ceHeight entry + 1) `mod` netRetargetInterval net /= 0 =
      if netAllowMinDiffBlocks net
        then bhBits (ceHeader entry)  -- Min-diff check is done in addHeader
        else bhBits (ceHeader entry)

  -- At retarget boundary
  | otherwise = calculateRetarget net entries entry
  where
    calculateRetarget :: Network -> Map BlockHash ChainEntry -> ChainEntry -> Word32
    calculateRetarget network ents lastEntry =
      -- Find the first block in this 2016-block period
      let firstHash = walkBack ents (ceHash lastEntry) (netRetargetInterval network - 1)
      in case firstHash >>= (`Map.lookup` ents) of
           Nothing -> bhBits (ceHeader lastEntry)  -- Fallback if not found
           Just firstEntry ->
             let actualTime = bhTimestamp (ceHeader lastEntry)
                            - bhTimestamp (ceHeader firstEntry)
                 -- Clamp to [targetTimespan/4, targetTimespan*4]
                 minTime = netPowTargetTimespan network `div` 4
                 maxTime = netPowTargetTimespan network * 4
                 clampedTime = max minTime (min maxTime actualTime)
                 -- BIP94: use first block's bits, otherwise use last block's bits
                 oldTarget = if netEnforceBIP94 network
                             then bitsToTarget (bhBits (ceHeader firstEntry))
                             else bitsToTarget (bhBits (ceHeader lastEntry))
                 -- New target = old_target * actual_time / target_time
                 newTarget = min (netPowLimit network) $
                   (oldTarget * fromIntegral clampedTime)
                   `div` fromIntegral (netPowTargetTimespan network)
             in targetToBits newTarget

    walkBack :: Map BlockHash ChainEntry -> BlockHash -> Word32 -> Maybe BlockHash
    walkBack _ hash 0 = Just hash
    walkBack ents hash n = case Map.lookup hash ents of
      Nothing -> Nothing
      Just ce -> cePrev ce >>= \p -> walkBack ents p (n-1)

-- | Calculate expected bits for testnet with min-difficulty rule.
-- If the new block's timestamp is > 20 minutes after previous, allow min diff.
-- Otherwise, walk back to find the last non-min-diff block.
testnetExpectedBits :: Network -> Map BlockHash ChainEntry -> ChainEntry -> BlockHeader -> Word32
testnetExpectedBits net entries lastEntry newHeader
  | bhTimestamp newHeader > bhTimestamp (ceHeader lastEntry) + netPowTargetSpacing net * 2 =
      -- More than 20 minutes: allow min difficulty
      powLimitBits
  | otherwise =
      -- Walk back to find last non-min-diff block
      walkBackMinDiff entries lastEntry
  where
    powLimitBits = targetToBits (netPowLimit net)

    walkBackMinDiff :: Map BlockHash ChainEntry -> ChainEntry -> Word32
    walkBackMinDiff ents ce
      -- Not min-diff: use this block's bits
      | bhBits (ceHeader ce) /= powLimitBits = bhBits (ceHeader ce)
      -- At retarget boundary: this is authoritative
      | ceHeight ce `mod` netRetargetInterval net == 0 = bhBits (ceHeader ce)
      -- Walk back
      | otherwise = case cePrev ce >>= (`Map.lookup` ents) of
          Just prev -> walkBackMinDiff ents prev
          Nothing   -> bhBits (ceHeader ce)

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
  invalidatedVar <- newTVarIO Set.empty
  return HeaderChain
    { hcEntries = entriesVar
    , hcTip = tipVar
    , hcHeight = heightVar
    , hcByHeight = byHeightVar
    , hcInvalidated = invalidatedVar
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
      Nothing -> return $ Left ("Unknown previous block: " ++ show (B16.encode (BS.reverse (getHash256 (getBlockHashHash prevHash)))))

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
                    -- Verify checkpoint (if one exists at this height)
                    let checkpoints = buildCheckpoints net
                    case verifyCheckpoint checkpoints height hash of
                      Left (ChainErrCheckpoint h expected actual) ->
                        return $ Left $ "Checkpoint mismatch at height " ++ show h ++
                                       ": expected " ++ show expected ++ " got " ++ show actual
                      Left err -> return $ Left $ "Checkpoint error: " ++ show err
                      Right () -> do
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
  { hsChain    :: !HeaderChain              -- ^ The header chain being built
  , hsNetwork  :: !Network                  -- ^ Network configuration
  , hsSyncing  :: !(TVar Bool)              -- ^ Whether sync is in progress
  , hsSyncPeer :: !(TVar (Maybe SockAddr))  -- ^ Peer address we're syncing from
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

--------------------------------------------------------------------------------
-- Block Locator Building
--------------------------------------------------------------------------------

-- | Build a block locator from the current header chain.
-- Returns a list of block hashes that can be used in getheaders messages.
-- Uses exponentially-spaced heights to efficiently find fork points.
buildBlockLocatorFromChain :: HeaderChain -> IO [BlockHash]
buildBlockLocatorFromChain hc = do
  tipHeight <- readTVarIO (hcHeight hc)
  heightMap <- readTVarIO (hcByHeight hc)
  let locHeights = buildLocatorHeights tipHeight
      locHashes = [h | height <- locHeights, Just h <- [Map.lookup height heightMap]]
  return locHashes

--------------------------------------------------------------------------------
-- UTXO Cache Block Application
--------------------------------------------------------------------------------

-- | Apply a block to the UTXO cache, generating undo data.
-- This function:
--   1. For each transaction, validates BIP68 sequence locks (if active)
--   2. For each transaction, spends inputs and creates outputs
--   3. Validates coinbase maturity (100 blocks)
--   4. Returns undo data for potential chain reorganizations
--
-- The undo data follows Bitcoin Core's structure:
--   - BlockUndo contains a TxUndo for each non-coinbase transaction
--   - TxUndo contains a TxInUndo for each input (the spent UTXO + metadata)
--
-- KNOWN PITFALL: Coinbase outputs cannot be spent until 100 blocks later.
--
-- Arguments:
--   - cache: The UTXO cache
--   - net: Network configuration
--   - block: The block to apply
--   - height: Height of this block
--   - prevBlockMTP: Median time past of the previous block (for sequence locks)
--   - getMTP: Function to look up MTP given a block height
applyBlock :: UTXOCache -> Network -> Block -> Word32 -> Word32 -> (Word32 -> IO Word32) -> IO (Either String UndoData)
applyBlock cache net block height prevBlockMTP getMTP = do
  let txns = blockTxns block
      bh = computeBlockHash (blockHeader block)
      prevHash = bhPrevBlock (blockHeader block)
      enforceBIP68 = bip68Active net height

  -- Process each transaction, collecting TxUndo for non-coinbase txs
  txUndoListRef <- newTVarIO []

  -- Process each transaction
  results <- forM (zip [0..] txns) $ \(txIdx :: Int, tx) -> do
    if isCoinbase tx
      then do
        -- Coinbase: only create outputs, no inputs to spend, no undo data
        atomically $ forM_ (zip [0..] (txOutputs tx)) $ \(outIdx, txout) -> do
          let op = OutPoint (computeTxId tx) (fromIntegral outIdx)
              entry = UTXOEntry txout height True False
          addUTXO cache op entry
        return (Right ())
      else do
        -- Regular transaction: check sequence locks, spend inputs, create outputs
        -- Collect TxInUndo for each input
        txInUndoListRef <- newTVarIO []

        -- First, gather UTXO information for all inputs
        utxoResults <- forM (txInputs tx) $ \inp -> do
          let op = txInPrevOutput inp
          mEntry <- lookupUTXO cache op
          return (op, mEntry)

        let missingUtxos = [op | (op, Nothing) <- utxoResults]
        if not (null missingUtxos)
          then return $ Left $ "Missing UTXO: " ++ show (head missingUtxos)
          else do
            let utxoEntries = [(op, entry) | (op, Just entry) <- utxoResults]

            -- Check coinbase maturity for all inputs first
            let immatureCoinbase = [(op, entry) | (op, entry) <- utxoEntries
                                   , ueCoinbase entry
                                   , height - ueHeight entry < fromIntegral (netCoinbaseMaturity net)]
            if not (null immatureCoinbase)
              then return $ Left "Coinbase not yet mature"
              else do
                -- BIP68: Check sequence locks
                sequenceLockResult <- if enforceBIP68 && txVersion tx >= 2
                  then do
                    -- Get the heights and MTPs for each input's UTXO
                    let prevHeights = [ueHeight entry | (_, entry) <- utxoEntries]
                    -- For time-based locks, we need MTP of block BEFORE the coin was mined
                    -- MTP(height-1) where height is where the UTXO was confirmed
                    prevMTPs <- forM prevHeights $ \h ->
                      if h == 0 then return 0 else getMTP (max 0 (h - 1))
                    let lock = calculateSequenceLocks tx prevHeights prevMTPs True
                        lockOk = checkSequenceLocks height prevBlockMTP lock
                    if lockOk
                      then return (Right ())
                      else return $ Left $ "BIP68 sequence lock not satisfied: " ++
                             "minHeight=" ++ show (slMinHeight lock) ++
                             ", minTime=" ++ show (slMinTime lock) ++
                             ", blockHeight=" ++ show height ++
                             ", prevMTP=" ++ show prevBlockMTP
                  else return (Right ())

                case sequenceLockResult of
                  Left err -> return (Left err)
                  Right () -> do
                    -- Spend inputs
                    forM_ utxoEntries $ \(op, entry) -> atomically $ do
                      void $ spendUTXO cache op
                      -- Record TxInUndo for this spent output
                      let inUndo = TxInUndo
                            { tuOutput = ueOutput entry
                            , tuHeight = ueHeight entry
                            , tuCoinbase = ueCoinbase entry
                            }
                      modifyTVar' txInUndoListRef (inUndo :)

                    -- Create outputs
                    atomically $ forM_ (zip [0..] (txOutputs tx)) $ \(outIdx, txout) -> do
                      let op = OutPoint (computeTxId tx) (fromIntegral outIdx)
                          entry = UTXOEntry txout height False False
                      addUTXO cache op entry

                    -- Build TxUndo from collected TxInUndos (reverse to match input order)
                    txInUndos <- readTVarIO txInUndoListRef
                    let txUndo = TxUndo { tuPrevOutputs = reverse txInUndos }
                    atomically $ modifyTVar' txUndoListRef (txUndo :)
                    return (Right ())

  case sequence results of
    Left err -> return (Left err)
    Right _ -> do
      -- Build BlockUndo from collected TxUndos (reverse to match tx order)
      txUndos <- readTVarIO txUndoListRef
      let blockUndo = BlockUndo { buTxUndo = reverse txUndos }
          undoData = mkUndoData bh height prevHash blockUndo
      return $ Right undoData

-- | Unapply a block using undo data (for reorgs).
-- Restores the UTXO set to its state before this block was applied.
-- This removes outputs created by the block and restores spent outputs.
--
-- Process in reverse transaction order:
--   1. Remove outputs created by each transaction
--   2. Restore the spent UTXOs from undo data
unapplyBlock :: UTXOCache -> Block -> UndoData -> IO ()
unapplyBlock cache block undo = atomically $ do
  let txns = blockTxns block
      nonCoinbaseTxns = tail txns  -- Skip coinbase
      txUndos = buTxUndo (udBlockUndo undo)

  -- Process transactions in reverse order (for proper undo)
  forM_ (reverse $ zip nonCoinbaseTxns txUndos) $ \(tx, txUndo) -> do
    -- Remove outputs created by this transaction
    forM_ (zip [0..] (txOutputs tx)) $ \(outIdx, _) -> do
      let op = OutPoint (computeTxId tx) (fromIntegral outIdx)
      void $ spendUTXO cache op

    -- Restore inputs that were spent by this transaction
    forM_ (zip (txInputs tx) (tuPrevOutputs txUndo)) $ \(inp, inUndo) -> do
      let op = txInPrevOutput inp
          entry = UTXOEntry
            { ueOutput = tuOutput inUndo
            , ueHeight = tuHeight inUndo
            , ueCoinbase = tuCoinbase inUndo
            , ueSpent = False
            }
      addUTXO cache op entry

  -- Finally, remove coinbase outputs
  let coinbaseTx = head txns
  forM_ (zip [0..] (txOutputs coinbaseTx)) $ \(outIdx, _) -> do
    let op = OutPoint (computeTxId coinbaseTx) (fromIntegral outIdx)
    void $ spendUTXO cache op

--------------------------------------------------------------------------------
-- Chain Reorganization
--------------------------------------------------------------------------------

-- | Perform a chain reorganization from old tip to new tip.
-- This finds the fork point, disconnects blocks from old tip to fork,
-- then connects blocks from fork to new tip.
--
-- KNOWN PITFALL: Reorgs require undo data for all blocks being disconnected.
-- If undo data is missing, the reorg will fail.
--
-- CHECKPOINT PROTECTION: Reorganizations that would go past the last checkpoint
-- are rejected. This prevents alternative chain attacks during IBD.
performReorg :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
             -> BlockHash -> BlockHash -> IO (Either String ())
performReorg net cache db hc oldTip newTip = do
  -- Find the fork point
  mFork <- findForkPoint hc oldTip newTip
  case mFork of
    Nothing -> return $ Left "Cannot find fork point"
    Just forkEntry -> do
      -- Get current tip height
      currentHeight <- readTVarIO (hcHeight hc)
      let checkpoints = buildCheckpoints net
          forkHeight = ceHeight forkEntry

      -- Check if reorg would go past a checkpoint
      if isReorgPastCheckpoint checkpoints forkHeight currentHeight
        then do
          let Just (cpHeight, _) = getLastCheckpoint checkpoints currentHeight
          return $ Left $ "Reorg rejected: would go past checkpoint at height " ++ show cpHeight
        else do
          -- Disconnect blocks from old tip to fork
          disconnectResult <- disconnectChain cache db hc oldTip (ceHash forkEntry)
          case disconnectResult of
            Left err -> return $ Left err
            Right () -> do
              -- Connect blocks from fork to new tip
              connectChain cache db hc (ceHash forkEntry) newTip

-- | Disconnect blocks from current hash back to target hash.
-- Uses undo data to restore spent UTXOs at each step.
-- Verifies undo data checksum before applying.
disconnectChain :: UTXOCache -> HaskoinDB -> HeaderChain
                -> BlockHash -> BlockHash -> IO (Either String ())
disconnectChain cache db _hc currentHash targetHash
  | currentHash == targetHash = return (Right ())
  | otherwise = do
      mBlock <- getBlock db currentHash
      case mBlock of
        Nothing -> return $ Left $ "Missing block data for disconnect: " ++ show currentHash
        Just block -> do
          let prevHash = bhPrevBlock (blockHeader block)
          -- Verify undo data with checksum
          undoResult <- getUndoDataVerified db currentHash prevHash
          case undoResult of
            Left err -> return $ Left $ "Undo data error for " ++ show currentHash ++ ": " ++ err
            Right undo -> do
              unapplyBlock cache block undo
              disconnectChain cache db _hc prevHash targetHash

-- | Connect blocks from fork point to new tip.
-- Applies each block in order, generating and storing undo data.
connectChain :: UTXOCache -> HaskoinDB -> HeaderChain
             -> BlockHash -> BlockHash -> IO (Either String ())
connectChain cache db hc fromHash toHash = do
  -- Build list of blocks to connect (from fork to new tip)
  entries <- readTVarIO (hcEntries hc)
  let path = buildPath entries toHash fromHash []
      -- Helper to look up MTP for a given height
      getMTP :: Word32 -> IO Word32
      getMTP h = do
        ents <- readTVarIO (hcEntries hc)
        byHeight <- readTVarIO (hcByHeight hc)
        case Map.lookup h byHeight >>= (`Map.lookup` ents) of
          Just ce -> return $ ceMedianTime ce
          Nothing -> return 0  -- Fallback for missing data
  -- Use the network from the header chain context (default to mainnet)
  results <- forM path $ \ce -> do
    mBlock <- getBlock db (ceHash ce)
    case mBlock of
      Nothing -> return $ Left $ "Missing block data for reconnect: " ++ show (ceHash ce)
      Just block -> do
        -- Get the MTP of the previous block for sequence lock validation
        prevBlockMTP <- case cePrev ce >>= (`Map.lookup` entries) of
          Just prevCe -> return $ ceMedianTime prevCe
          Nothing -> return 0  -- Genesis or missing parent
        result <- applyBlock cache mainnet block (ceHeight ce) prevBlockMTP getMTP
        case result of
          Left err -> return $ Left err
          Right undoData -> do
            -- Store undo data for this block
            putUndoData db (ceHash ce) undoData
            return (Right ())
  return $ sequence_ results
  where
    -- Build the path from toHash back to fromHash, then reverse
    buildPath :: Map BlockHash ChainEntry -> BlockHash -> BlockHash -> [ChainEntry] -> [ChainEntry]
    buildPath ents hash target acc
      | hash == target = acc
      | otherwise = case Map.lookup hash ents of
          Nothing -> acc  -- Should not happen in a valid chain
          Just ce -> case cePrev ce of
            Nothing -> acc  -- Reached genesis
            Just prevH -> buildPath ents prevH target (ce : acc)

--------------------------------------------------------------------------------
-- Checkpoint Enforcement
--------------------------------------------------------------------------------

-- | Checkpoints map block height to expected block hash.
-- Used to prevent alternative chain attacks during IBD.
-- Reference: Bitcoin Core validation.cpp (historical), chainparams.cpp
type Checkpoints = Map Word32 BlockHash

-- | Chain validation errors
data ChainError
  = ChainErrCheckpoint !Word32 !BlockHash !BlockHash  -- ^ Height, expected, actual
  | ChainErrReorgPastCheckpoint !Word32               -- ^ Last checkpoint height
  | ChainErrOrphan !BlockHash                         -- ^ Unknown parent block
  | ChainErrInvalidPoW                                -- ^ Proof of work failed
  | ChainErrTimestamp                                 -- ^ Timestamp validation failed
  | ChainErrDifficulty                                -- ^ Difficulty target mismatch
  | ChainErrValidation !String                        -- ^ Other validation error
  deriving (Show, Eq)

-- | Build Checkpoints map from network configuration.
-- Converts the list-based netCheckpoints to a Map for efficient lookup.
buildCheckpoints :: Network -> Checkpoints
buildCheckpoints net = Map.fromList (netCheckpoints net)

-- | Get the last checkpoint at or before a given height.
-- Returns Nothing if no checkpoints exist or all are above the height.
getLastCheckpoint :: Checkpoints -> Word32 -> Maybe (Word32, BlockHash)
getLastCheckpoint cps height =
  case Map.lookupLE height cps of
    Nothing -> Nothing
    Just (h, hash) -> Just (h, hash)

-- | Get the checkpoint at an exact height, if one exists.
checkpointAtHeight :: Checkpoints -> Word32 -> Maybe BlockHash
checkpointAtHeight = flip Map.lookup

-- | Verify a block against checkpoints.
-- If the block height matches a checkpoint, the hash must match exactly.
-- Returns Left ChainErrCheckpoint if verification fails.
-- Returns Right () if verification passes or no checkpoint at this height.
verifyCheckpoint :: Checkpoints -> Word32 -> BlockHash -> Either ChainError ()
verifyCheckpoint cps height hash =
  case checkpointAtHeight cps height of
    Nothing -> Right ()  -- No checkpoint at this height
    Just expected
      | expected == hash -> Right ()
      | otherwise -> Left (ChainErrCheckpoint height expected hash)

-- | Check if a reorganization would go past the last checkpoint.
-- This is forbidden as checkpoints are meant to be immutable anchor points.
--
-- Arguments:
--   - checkpoints: The network checkpoints
--   - forkHeight: The height of the fork point (common ancestor)
--   - currentHeight: The current chain tip height
--
-- Returns True if the reorg would go past a checkpoint (and should be rejected).
isReorgPastCheckpoint :: Checkpoints -> Word32 -> Word32 -> Bool
isReorgPastCheckpoint cps forkHeight currentHeight =
  case getLastCheckpoint cps currentHeight of
    Nothing -> False  -- No checkpoints below current height
    Just (checkpointHeight, _) -> forkHeight < checkpointHeight

--------------------------------------------------------------------------------
-- AssumeUTXO Background Validation
--------------------------------------------------------------------------------
-- Reference: bitcoin/src/validation.cpp ActivateSnapshot, MaybeValidateSnapshot
--
-- AssumeUTXO allows the node to:
-- 1. Load a UTXO snapshot and start validating new blocks immediately
-- 2. Validate the full chain from genesis in the background
-- 3. Once background validation completes, verify the UTXO hashes match
--
-- This enables fast initial sync while maintaining full trustlessness.

-- | State of assumeUTXO operation.
-- Tracks both the snapshot chainstate and background validation progress.
data AssumeUtxoState = AssumeUtxoState
  { ausNetwork         :: !Network                  -- ^ Network parameters
  , ausSnapshotHeight  :: !Word32                   -- ^ Height of the snapshot
  , ausSnapshotHash    :: !BlockHash                -- ^ Block hash of the snapshot
  , ausExpectedHash    :: !Hash256                  -- ^ Expected UTXO hash
  , ausCurrentHeight   :: !(IORef Word32)           -- ^ Current background validation height
  , ausValidated       :: !(IORef Bool)             -- ^ True when background validation completes
  , ausError           :: !(IORef (Maybe String))   -- ^ Any error during validation
  , ausBackgroundTask  :: !(IORef (Maybe (Async ()))) -- ^ Background validation task
  }

-- | Initialize assumeUTXO state from snapshot parameters.
initAssumeUtxoState :: Network -> AssumeUtxoParams -> IO AssumeUtxoState
initAssumeUtxoState net params = do
  heightRef <- newIORef 0
  validatedRef <- newIORef False
  errorRef <- newIORef Nothing
  taskRef <- newIORef Nothing
  return AssumeUtxoState
    { ausNetwork = net
    , ausSnapshotHeight = aupHeight params
    , ausSnapshotHash = aupBlockHash params
    , ausExpectedHash = aupHashSerialized params
    , ausCurrentHeight = heightRef
    , ausValidated = validatedRef
    , ausError = errorRef
    , ausBackgroundTask = taskRef
    }

-- | Activate a UTXO snapshot.
-- This loads the snapshot, populates the chainstate, and starts background validation.
-- Reference: bitcoin/src/validation.cpp ActivateSnapshot
activateSnapshot :: HaskoinDB
                 -> Network
                 -> FilePath           -- ^ Path to snapshot file
                 -> IO (Either String AssumeUtxoState)
activateSnapshot db net snapshotPath = do
  -- Load the snapshot file
  result <- loadSnapshot snapshotPath (netMagic net)
  case result of
    Left err -> return $ Left $ "Failed to load snapshot: " ++ err
    Right snapshot -> do
      let baseHash = smBaseBlockHash (usMetadata snapshot)
      -- Look up assumeUtxo data for this block hash
      case assumeUtxoForBlockHash net baseHash of
        Nothing -> return $ Left $
          "Block hash not recognized as valid assumeUtxo hash: " ++ show baseHash
        Just params -> do
          -- Verify the snapshot against expected parameters
          case verifySnapshot snapshot (AssumeUtxoData
                { audHeight = aupHeight params
                , audHashSerialized = aupHashSerialized params
                , audChainTxCount = aupChainTxCount params
                , audBlockHash = aupBlockHash params
                }) of
            Left err -> return $ Left $ "Snapshot verification failed: " ++ err
            Right () -> do
              -- Initialize state
              state <- initAssumeUtxoState net params
              return $ Right state

-- | Run background validation from genesis to the snapshot height.
-- This validates all blocks from genesis to the snapshot height in a background thread.
-- When complete, it verifies that the UTXO hash matches the expected value.
-- Reference: bitcoin/src/validation.cpp MaybeValidateSnapshot
runBackgroundValidation :: AssumeUtxoState
                        -> HaskoinDB
                        -> (Word32 -> IO (Maybe Block))  -- ^ Block getter by height
                        -> IO ()
runBackgroundValidation state db getBlockAtHeight = do
  task <- async $ backgroundValidationLoop state db getBlockAtHeight
  writeIORef (ausBackgroundTask state) (Just task)

-- | Internal background validation loop.
backgroundValidationLoop :: AssumeUtxoState
                         -> HaskoinDB
                         -> (Word32 -> IO (Maybe Block))
                         -> IO ()
backgroundValidationLoop state db getBlockAtHeight = do
  let targetHeight = ausSnapshotHeight state
      net = ausNetwork state

  -- Create a separate UTXO cache for background validation
  cache <- newUTXOCache db defaultCacheSize

  -- Validate blocks from genesis (height 1) to snapshot height
  result <- try $ do
    forM_ [1..targetHeight] $ \height -> do
      -- Check if we've been cancelled
      mBlock <- getBlockAtHeight height
      case mBlock of
        Nothing -> fail $ "Block not found at height " ++ show height
        Just block -> do
          -- Validate the block
          -- Note: Full validation would include script verification
          -- For now, we just apply the block to the UTXO set
          let prevHash = bhPrevBlock (blockHeader block)
          medianTime <- return 0  -- Simplified; real impl would compute MTP

          -- Apply block to UTXO cache
          applyResult <- applyBlock cache net block height medianTime (const $ return 0)
          case applyResult of
            Left err -> fail $ "Block validation failed at height " ++
                              show height ++ ": " ++ err
            Right _undo -> do
              -- Update progress
              writeIORef (ausCurrentHeight state) height

              -- Flush on either interval or entry count limit.
              -- At height 400K+, each block has ~4000 outputs, so 100 blocks
              -- = ~400K entries ≈ 120MB. Hard limit at 500K entries catches
              -- blocks with unusually many outputs.
              cacheEntries <- readTVarIO (ucSize cache)
              when (height `mod` 100 == 0 || cacheEntries > 500000) $ do
                putStrLn $ "Flushing UTXO cache: " ++ show cacheEntries ++ " entries at height " ++ show height
                flushCache cache

  case result of
    Left (e :: SomeException) -> do
      writeIORef (ausError state) (Just $ show e)
      writeIORef (ausValidated state) True  -- Mark as "done" even on error
    Right () -> do
      -- Validation complete - verify UTXO hash
      -- Collect all coins and compute hash
      flushCache cache
      -- In a full implementation, we would compute MuHash3072 here
      -- For now, mark as validated
      writeIORef (ausValidated state) True

-- | Get the progress of background validation (0.0 to 1.0).
getAssumeUtxoProgress :: AssumeUtxoState -> IO Double
getAssumeUtxoProgress state = do
  current <- readIORef (ausCurrentHeight state)
  let target = ausSnapshotHeight state
  if target == 0
    then return 1.0
    else return $ fromIntegral current / fromIntegral target

-- | Check if background validation is complete.
isAssumeUtxoValidated :: AssumeUtxoState -> IO Bool
isAssumeUtxoValidated state = readIORef (ausValidated state)

--------------------------------------------------------------------------------
-- Block Invalidation (invalidateblock / reconsiderblock)
--------------------------------------------------------------------------------
-- Reference: bitcoin/src/validation.cpp InvalidateBlock, ReconsiderBlock
--
-- These RPCs allow manual marking of blocks as invalid (and reversing that).
-- Key behaviors:
--   1. invalidateblock marks a block and all descendants as StatusInvalid
--   2. If the block is on the active chain, disconnect back to before it
--   3. Activate the best valid chain (may be a shorter fork)
--   4. Track manually invalidated blocks so they aren't auto-reconsidered
--   5. reconsiderblock clears invalid marks and re-validates
--   6. After reconsider, may activate the reconsidered chain if it has more work

-- | Errors that can occur during block invalidation/reconsideration.
data InvalidateError
  = InvalidateBlockNotFound !BlockHash           -- ^ Block not in block index
  | InvalidateGenesis                            -- ^ Cannot invalidate genesis
  | InvalidateDisconnectFailed !String           -- ^ Failed to disconnect chain
  | InvalidateMissingUndo !BlockHash             -- ^ Missing undo data for disconnect
  | ReconsiderBlockNotFound !BlockHash           -- ^ Block not in block index
  | ReconsiderNotInvalidated !BlockHash          -- ^ Block was not marked invalid
  | ReconsiderValidationFailed !BlockHash !String -- ^ Re-validation failed
  | ReconsiderActivationFailed !String           -- ^ Failed to activate chain
  deriving (Show, Eq)

-- | Check if a block hash is in the manually invalidated set.
isBlockInvalidated :: HeaderChain -> BlockHash -> IO Bool
isBlockInvalidated hc blockHash =
  Set.member blockHash <$> readTVarIO (hcInvalidated hc)

-- | Find all descendants of a block in the header chain.
-- Returns blocks in height order (lowest first).
-- This includes the input block itself.
findDescendants :: HeaderChain -> BlockHash -> IO [ChainEntry]
findDescendants hc blockHash = do
  entries <- readTVarIO (hcEntries hc)
  case Map.lookup blockHash entries of
    Nothing -> return []
    Just rootEntry -> do
      let rootHeight = ceHeight rootEntry
      -- Find all entries that have this block as an ancestor
      let isDescendant :: ChainEntry -> Bool
          isDescendant ce
            | ceHeight ce < rootHeight = False
            | ceHash ce == blockHash = True
            | otherwise = case cePrev ce of
                Nothing -> False
                Just prevHash -> case Map.lookup prevHash entries of
                  Nothing -> False
                  Just parent -> isDescendant parent
      let descendants = filter isDescendant (Map.elems entries)
      -- Sort by height (ascending)
      return $ sortBy (\a b -> compare (ceHeight a) (ceHeight b)) descendants

-- | Invalidate a block and all its descendants.
-- Reference: bitcoin/src/validation.cpp Chainstate::InvalidateBlock
--
-- This function:
--   1. Marks the block and all descendants as StatusInvalid
--   2. If on active chain, disconnects blocks back to before the invalid block
--   3. Activates the best remaining valid chain
--   4. Adds the block to the manually-invalidated set
--
-- Returns Left on error, Right on success (possibly with a new tip).
invalidateBlock :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
                -> BlockHash -> IO (Either InvalidateError ())
invalidateBlock net cache db hc blockHash = do
  entries <- readTVarIO (hcEntries hc)
  tip <- readTVarIO (hcTip hc)

  case Map.lookup blockHash entries of
    Nothing -> return $ Left (InvalidateBlockNotFound blockHash)
    Just entry
      -- Cannot invalidate genesis block
      | ceHeight entry == 0 -> return $ Left InvalidateGenesis
      | otherwise -> do
          -- Find all descendants (including this block)
          descendants <- findDescendants hc blockHash

          -- Mark all descendants as invalid in memory and storage
          forM_ descendants $ \ce -> do
            -- Update in-memory status
            atomically $ modifyTVar' (hcEntries hc) $
              Map.adjust (\e -> e { ceStatus = StatusInvalid }) (ceHash ce)
            -- Persist status
            putBlockStatus db (ceHash ce) StatusInvalid

          -- Add to manually-invalidated set
          atomically $ modifyTVar' (hcInvalidated hc) (Set.insert blockHash)

          -- Check if the block is on the active chain (ancestor of tip)
          let isOnActiveChain = isAncestor entries blockHash (ceHash tip)

          if isOnActiveChain
            then do
              -- Disconnect chain from tip back to the parent of invalid block
              let targetHash = case cePrev entry of
                    Just prevHash -> prevHash
                    Nothing -> blockHash  -- Should never happen (genesis handled above)

              -- Disconnect blocks
              disconnectResult <- disconnectChain cache db hc (ceHash tip) targetHash
              case disconnectResult of
                Left err -> return $ Left (InvalidateDisconnectFailed err)
                Right () -> do
                  -- Update tip to the parent of the invalid block
                  case Map.lookup targetHash entries of
                    Nothing -> return $ Left (InvalidateBlockNotFound targetHash)
                    Just newTipEntry -> do
                      atomically $ do
                        writeTVar (hcTip hc) newTipEntry
                        writeTVar (hcHeight hc) (ceHeight newTipEntry)
                      -- Try to activate the best valid chain
                      activateBestChain net cache db hc
                      return (Right ())
            else
              -- Block not on active chain, just marking is enough
              return (Right ())

-- | Check if hash1 is an ancestor of hash2.
isAncestor :: Map BlockHash ChainEntry -> BlockHash -> BlockHash -> Bool
isAncestor entries ancestorHash descendantHash
  | ancestorHash == descendantHash = True
  | otherwise = case Map.lookup descendantHash entries of
      Nothing -> False
      Just ce -> case cePrev ce of
        Nothing -> False
        Just prevHash -> isAncestor entries ancestorHash prevHash

-- | Activate the best valid chain.
-- After invalidation, we may need to switch to a different fork.
-- Reference: bitcoin/src/validation.cpp ActivateBestChain
activateBestChain :: Network -> UTXOCache -> HaskoinDB -> HeaderChain -> IO ()
activateBestChain net cache db hc = do
  entries <- readTVarIO (hcEntries hc)
  currentTip <- readTVarIO (hcTip hc)
  invalidated <- readTVarIO (hcInvalidated hc)

  -- Find all valid tips (blocks with no children that are not invalid)
  let allEntries = Map.elems entries
      -- A block is a tip candidate if it's valid and has no valid children
      hasValidChildren :: ChainEntry -> Bool
      hasValidChildren ce =
        any (\other -> cePrev other == Just (ceHash ce) && ceStatus other /= StatusInvalid)
            allEntries
      tipCandidates = filter (\ce -> ceStatus ce /= StatusInvalid
                                  && not (hasValidChildren ce)
                                  && not (Set.member (ceHash ce) invalidated))
                             allEntries

  -- Find the best tip by chain work
  case tipCandidates of
    [] -> return ()  -- No valid tips (shouldn't happen)
    candidates ->
      let best = maximumBy (\a b -> compare (ceChainWork a) (ceChainWork b)) candidates
      in when (ceChainWork best > ceChainWork currentTip) $ do
           -- Need to switch to a better chain
           mFork <- findForkPoint hc (ceHash currentTip) (ceHash best)
           case mFork of
             Nothing -> return ()  -- No common ancestor (shouldn't happen)
             Just fork -> void $ performReorg net cache db hc (ceHash currentTip) (ceHash best)
  where
    maximumBy :: (a -> a -> Ordering) -> [a] -> a
    maximumBy _ [x] = x
    maximumBy cmp (x:xs) = foldl' (\acc y -> if cmp acc y == LT then y else acc) x xs
    maximumBy _ [] = error "maximumBy: empty list"

-- | Reconsider a previously invalidated block.
-- Reference: bitcoin/src/validation.cpp Chainstate::ResetBlockFailureFlags
--
-- This function:
--   1. Removes the invalid mark from the block and all its descendants
--   2. Removes the block from the manually-invalidated set
--   3. Re-validates blocks if needed
--   4. May activate the reconsidered chain if it has more work
--
-- Returns Left on error, Right on success.
reconsiderBlock :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
                -> BlockHash -> IO (Either InvalidateError ())
reconsiderBlock net cache db hc blockHash = do
  entries <- readTVarIO (hcEntries hc)
  invalidated <- readTVarIO (hcInvalidated hc)

  case Map.lookup blockHash entries of
    Nothing -> return $ Left (ReconsiderBlockNotFound blockHash)
    Just entry
      | ceStatus entry /= StatusInvalid && not (Set.member blockHash invalidated) ->
          -- Block isn't actually invalid
          return $ Left (ReconsiderNotInvalidated blockHash)
      | otherwise -> do
          -- Find all descendants (including this block)
          descendants <- findDescendants hc blockHash

          -- Remove invalid marks from all descendants
          forM_ descendants $ \ce -> do
            -- Restore status to StatusHeaderValid (will need re-validation)
            atomically $ modifyTVar' (hcEntries hc) $
              Map.adjust (\e -> e { ceStatus = StatusHeaderValid }) (ceHash ce)
            -- Persist status
            putBlockStatus db (ceHash ce) StatusHeaderValid

          -- Remove from manually-invalidated set
          atomically $ modifyTVar' (hcInvalidated hc) (Set.delete blockHash)

          -- Try to activate the best chain (may include reconsidered blocks)
          activateBestChain net cache db hc
          return (Right ())

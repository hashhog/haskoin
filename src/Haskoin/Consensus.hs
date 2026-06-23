{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE BangPatterns #-}

module Haskoin.Consensus
  ( -- * Network
    Network(..)
  , mainnet
  , testnet3
  , testnet4
  , regtest
  , HeaderSyncParams(..)
  , permittedDifficultyTransition
    -- * AssumeUTXO
  , AssumeUtxoParams(..)
  , assumeUtxoForHeight
  , assumeUtxoForBlockHash
  , assumeutxoWhitelistError
  , checkAssumeutxoWhitelist
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
  , maxFutureBlockTime
  , maxTimewarp
    -- * Difficulty
  , difficultyAdjustmentInterval
  , targetSpacing
  , targetTimespan
  , powLimit
  , bitsToTarget
  , bitsToTargetFull
  , targetToBits
  , checkProofOfWork
  , getNextWorkRequired
  , BlockIndex(..)
    -- * Block Reward
  , halvingInterval
  , blockReward
  , blockRewardForNet
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
  , validateTransaction
  , computeMerkleRoot
  , computeMerkleRootMutated
    -- * AssumeValid
  , shouldSkipScripts
    -- * Transaction Finality
  , isFinalTxCheck
  , locktimeThresholdConsensus
  , sequenceFinalConsensus
    -- * Full Block Validation
  , validateFullBlock
  , validateFullBlockIO
  , validateBlockTransactions
  , validateSingleTx
  , checkTxInputsConnect
  , checkBIP30
  , ChainState(..)
  , ConsensusFlags(..)
  , consensusFlagsAtHeight
  , consensusFlagsToScriptFlags
    -- * Coinbase
  , isCoinbase
  , coinbaseHeight
  , encodeBip34Height
  , validateCoinbaseHeightConsensus
    -- * Block Metrics
  , blockWeight
  , blockBaseSize
  , blockTotalSize
  , txBaseSize
  , txTotalSize
  , varIntSize
  , checkBlockWeight
  , minTransactionWeight
  , minSerializableTransactionWeight
    -- NOTE(wave-33b dead-symbol audit): checkBlockWeight is test-only; the live
    -- weight check is inline in connectBlock. Fixes for BIP-141 weight rules
    -- belong in connectBlock / validateFullBlockIO, NOT here.
    -- * Sigop Counting
  , SigOpCost(..)
  , maxBlockSigOpsCost
  , getTransactionSigOpCost
  , getBlockSigOpCost
  , countBlockSigops
  , countTxSigops
  , countScriptSigops
  , getLegacySigOpCount
    -- * Witness Commitment
  , checkWitnessMalleation
  , validateWitnessCommitment
  , txHasWitness
  , computeWtxId
    -- * Block Connection (Legacy)
  , connectBlock
  , connectBlockAt
  , disconnectBlock
  , disconnectBlockAt
  , DisconnectResult(..)
  , bip30ExceptionHeight
  , applyTxInUndo
    -- * Pure Batch Builders (Pattern D — multi-block atomicity)
  , buildConnectBlockOps
  , buildDisconnectBlockOps
  , maxReorgDepth
    -- * UTXO Cache Block Operations
  , applyBlock
  , unapplyBlock
    -- * Undo Data Types (re-exported from Storage)
  , UTXOEntry(..)
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
  , CandidateKey(..)
  , mkCandidateKey
  , seqIdBestChainFromDisk
  , seqIdInitFromDisk
  , initHeaderChain
  , headerWork
  , cumulativeWork
  , medianTimePast
  , computeEntryMtp
  , difficultyAdjustment
  , addHeader
  , addHeaderAt
  , addSideBranchHeader
  , getChainTip
  , getValidatedChainTip
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
  , bip68VersionActive
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
  , computeBlockVersionFromChain
  , chainEntriesToBlockIndex
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
    -- ** Real second-chainstate (genesis->base) re-derivation
  , BackgroundChainstate(..)
  , SnapshotVerdict(..)
  , BackgroundValidationError(..)
  , newBackgroundChainstate
  , bgStoreId
  , setBgActiveStoreId
  , bgCoinCount
  , bgGetCoin
  , bgTipHeight
  , connectGenesisToBase
  , finalizeBackgroundValidation
  , bgSnapshotCoins
  , activateSnapshotWithRederivation
  , activateSnapshotSync
    -- ** Runtime-registerable regtest AssumeUTXO whitelist
  , registerRegtestAssumeUtxo
  , clearRegtestAssumeUtxo
  , assumeUtxoForHeightIO
  , assumeUtxoForBlockHashIO
  , checkAssumeutxoWhitelistIO
    -- * Block Invalidation (invalidateblock/reconsiderblock RPCs)
  , InvalidateError(..)
  , invalidateBlock
  , reconsiderBlock
  , findDescendants
  , isBlockInvalidated
  , isFailedStatus
  , activateBestChain
  , findBestCandidate
    -- * Global Signature Cache
  , initGlobalSigCache
  , lookupGlobalSigCache
  , insertGlobalSigCache
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int32, Int64)
import Data.Bits (shiftL, shiftR, (.&.), (.|.), testBit)
import Data.List (sort, sortBy, foldl')
import Numeric (showHex)
import Control.Monad (when, unless, forM, forM_, foldM, forever, void)
import Control.Parallel.Strategies (withStrategy, parListChunk, rdeepseq)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Serialize (encode, runPut, putWord32le, putWord64le, putByteString)
import GHC.Generics (Generic)
import Control.Concurrent.STM
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Async (Async, async, cancel, waitCatch)
import Control.Exception (try, SomeException)
import Data.IORef (IORef, newIORef, readIORef, writeIORef, modifyIORef', atomicModifyIORef')
import System.Mem.StableName (makeStableName, hashStableName)
import System.IO.Unsafe (unsafePerformIO)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket (SockAddr)
import Data.Maybe (mapMaybe)

import Haskoin.Types (Hash256(..), TxId(..), BlockHash(..),
                      OutPoint(..), TxIn(..), TxOut(..), Tx(..), BlockHeader(..),
                      Block(..), putVarInt, putVarBytes)
import Haskoin.Crypto (doubleSHA256, sha256, computeTxId, computeBlockHash,
                       initGlobalSigCache, lookupGlobalSigCache, insertGlobalSigCache)
import Haskoin.Script (decodeScript, countScriptSigops,
                       ScriptVerifyFlag(..), ScriptFlags, flagSet,
                       verifyScriptWithFlags, isPushOnly, classifyOutput,
                       ScriptType(..), Script(..), ScriptOp(..))
import Haskoin.Storage (HaskoinDB, WriteBatch(..), BatchOp(..), writeBatch,
                        makeKey, KeyPrefix(..), toBE32, TxLocation(..),
                        BlockStatus(..), UTXOCache(..), UTXOEntry(..),
                        TxInUndo(..), TxUndo(..), BlockUndo(..), UndoData(..),
                        mkUndoData, lookupUTXO, addUTXO, spendUTXO, rcClear,
                        putUndoData, getUndoData, getUndoDataVerified, getBlock, getUTXO, getUTXOCoin, getBlockHeight,
                        getBestBlockHash,
                        isUnspendable, Coin(..),
                        -- AssumeUTXO support
                        SnapshotMetadata(..), UtxoSnapshot(..), AssumeUtxoData(..),
                        SnapshotCoin(..), computeUtxoHash,
                        loadSnapshot, verifySnapshot,
                        CoinsViewDB(..), newCoinsViewDB,
                        CoinsViewCache(..), newCoinsViewCache, cacheFlush, defaultCacheSize,
                        putBlockStatus, newUTXOCache, flushCache)
-- Secondary-index fan-out on the disconnect/reorg path (txindex /
-- blockfilterindex / coinstatsindex).  Index.hs depends only on
-- Types/Crypto/Storage/MuHash (never on Consensus), so importing it here
-- introduces no module cycle.  This is what lets 'reorgAtomic' revert the
-- coinstatsindex on every disconnected block (CustomRemove) and re-append
-- it on every reconnected block (CustomAppend) during an invalidateblock-
-- triggered reorg, exactly like the submitBlock side-branch reorg path
-- (BlockTemplate.doSideBranchReorg).
import Haskoin.Index (IndexManager,
                      indexManagerConnectBlock, indexManagerDisconnectBlock)

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
  , netBIP34Hash         :: !BlockHash   -- ^ Hash of block at BIP34Height (anchor for BIP30 skip)
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
  , netHeaderSyncParams  :: !HeaderSyncParams -- ^ Parameters for PRESYNC/REDOWNLOAD anti-DoS pipeline
  , netAssumeUtxo        :: ![(Word32, AssumeUtxoParams)]  -- ^ AssumeUTXO snapshot parameters
  , netAssumedValid      :: !(Maybe BlockHash)  -- ^ Assume-valid: skip scripts for ancestors of this block
  } deriving (Show)

-- | Parameters for the headers-sync anti-DoS pipeline.
-- Each network has distinct values tuned to its observed block rate.
-- Reference: bitcoin-core/src/kernel/chainparams.cpp (HeadersSyncParams field).
data HeaderSyncParams = HeaderSyncParams
  { hspCommitmentPeriod    :: !Int   -- ^ Blocks between 1-bit commitments (Core: commitment_period)
  , hspRedownloadBufferSize :: !Int  -- ^ Min headers buffered before acceptance (Core: redownload_buffer_size)
  } deriving (Show, Eq)

-- | AssumeUTXO snapshot parameters for a specific block height.
-- Reference: bitcoin/src/kernel/chainparams.h AssumeutxoData
data AssumeUtxoParams = AssumeUtxoParams
  { aupHeight        :: !Word32      -- ^ Block height of the snapshot
  , aupHashSerialized :: !Hash256    -- ^ Expected hash of serialized UTXO set
  , aupChainTxCount  :: !Word64      -- ^ Cumulative transaction count at height
  , aupBlockHash     :: !BlockHash   -- ^ Block hash at this height
  } deriving (Show, Eq)

-- | Runtime-registerable AssumeUTXO whitelist, REGTEST ONLY.
--
-- Bitcoin Core hard-codes its @m_assumeutxo_data@ table per network; for the
-- mainnet / testnet4 tables we keep that exact behaviour (the entries live in
-- 'netAssumeUtxo' and are never mutated at runtime).  Regtest, however, has no
-- canonical snapshot commitment — a functional test mines its OWN short chain,
-- dumps the UTXO set, and must then load it back.  Core supports this via the
-- regtest @-assumeutxo@ kernel hooks; haskoin models it with this in-memory
-- registry so a regtest test (and ONLY a regtest test) can register a
-- @(base_height, AssumeUtxoParams)@ pair at runtime.
--
-- The registry is consulted by 'assumeUtxoForHeight' /
-- 'assumeUtxoForBlockHash' EXCLUSIVELY when the network is regtest.  Mainnet
-- and testnet4 lookups never touch it, so their assumeutxo data is untouched.
{-# NOINLINE regtestAssumeUtxoRegistry #-}
regtestAssumeUtxoRegistry :: IORef [(Word32, AssumeUtxoParams)]
regtestAssumeUtxoRegistry = unsafePerformIO (newIORef [])

-- | Register a regtest AssumeUTXO whitelist entry at runtime (idempotent on
-- height — re-registering a height replaces its params).  No-op semantics for
-- mainnet/testnet4: there is no API to mutate those tables, by design.
registerRegtestAssumeUtxo :: Word32 -> AssumeUtxoParams -> IO ()
registerRegtestAssumeUtxo height params =
  modifyIORef' regtestAssumeUtxoRegistry $ \tbl ->
    (height, params) : filter ((/= height) . fst) tbl

-- | Clear the runtime regtest AssumeUTXO whitelist (test teardown).
clearRegtestAssumeUtxo :: IO ()
clearRegtestAssumeUtxo = writeIORef regtestAssumeUtxoRegistry []

-- | The runtime regtest whitelist entries (empty unless 'registerRegtestAssumeUtxo'
-- was called).  Only ever non-empty under regtest.
regtestRuntimeEntries :: Network -> IO [(Word32, AssumeUtxoParams)]
regtestRuntimeEntries net
  | netName net == "regtest" = readIORef regtestAssumeUtxoRegistry
  | otherwise                = return []

-- | Look up assumeUTXO data for a specific height (STATIC tables only).
--
-- This is the pure lookup over the hard-coded 'netAssumeUtxo' table.  The
-- runtime-registerable regtest whitelist is consulted only by the IO variants
-- ('assumeUtxoForHeightIO' / 'checkAssumeutxoWhitelistIO'); a pure function
-- cannot observe a later 'registerRegtestAssumeUtxo' without an
-- 'unsafePerformIO' CAF-sharing hazard, so the runtime path is kept explicitly
-- in IO.  Mainnet/testnet4 only ever have static entries, so for them the pure
-- and IO answers always agree.
assumeUtxoForHeight :: Network -> Word32 -> Maybe AssumeUtxoParams
assumeUtxoForHeight net height =
  lookup height (netAssumeUtxo net)

-- | Look up assumeUTXO data for a specific block hash (STATIC tables only).
assumeUtxoForBlockHash :: Network -> BlockHash -> Maybe AssumeUtxoParams
assumeUtxoForBlockHash net bh =
  listToMaybe [ p | (_, p) <- netAssumeUtxo net, aupBlockHash p == bh ]
  where
    listToMaybe [] = Nothing
    listToMaybe (x:_) = Just x

-- | IO height lookup that ALSO consults the runtime-registerable regtest
-- whitelist (regtest only).  Runtime entries shadow static ones at the same
-- height.  Mainnet/testnet4 behave exactly like 'assumeUtxoForHeight'.
assumeUtxoForHeightIO :: Network -> Word32 -> IO (Maybe AssumeUtxoParams)
assumeUtxoForHeightIO net height = do
  runtime <- regtestRuntimeEntries net
  return $ case lookup height runtime of
    Just p  -> Just p
    Nothing -> assumeUtxoForHeight net height

-- | IO block-hash lookup that ALSO consults the runtime-registerable regtest
-- whitelist (regtest only).
assumeUtxoForBlockHashIO :: Network -> BlockHash -> IO (Maybe AssumeUtxoParams)
assumeUtxoForBlockHashIO net bh = do
  runtime <- regtestRuntimeEntries net
  return $ case [ p | (_, p) <- runtime, aupBlockHash p == bh ] of
    (p:_) -> Just p
    []    -> assumeUtxoForBlockHash net bh

-- | Canonical Bitcoin Core error message for an unrecognized assumeutxo
-- height in snapshot metadata.
--
-- Reference: bitcoin/src/validation.cpp ~L5778:
--
-- > "Assumeutxo height in snapshot metadata not recognized
-- >  (%d) - refusing to load snapshot"
--
-- Kept as a single function so the wording stays in lock-step with Core
-- and so the loadtxoutset RPC and its tests share the exact string.
assumeutxoWhitelistError :: Word32 -> String
assumeutxoWhitelistError h =
  "Assumeutxo height in snapshot metadata not recognized ("
  ++ show h
  ++ ") - refusing to load snapshot"

-- | Core-strict whitelist check: a snapshot's base block height must
-- appear in 'netAssumeUtxo' or it is refused outright.
--
-- Reference: bitcoin/src/validation.cpp PopulateAndValidateSnapshot
-- (the 'GetParams().AssumeutxoForHeight(base_height)' guard).
checkAssumeutxoWhitelist :: Network -> Word32 -> Either String ()
checkAssumeutxoWhitelist net height =
  case assumeUtxoForHeight net height of
    Just _  -> Right ()
    Nothing -> Left (assumeutxoWhitelistError height)

-- | IO whitelist check that ALSO honours the runtime-registerable regtest
-- whitelist (regtest only).  The two-stage activation and regtest tests use
-- this so a freshly registered regtest base height is accepted; mainnet /
-- testnet4 behave exactly like 'checkAssumeutxoWhitelist'.
checkAssumeutxoWhitelistIO :: Network -> Word32 -> IO (Either String ())
checkAssumeutxoWhitelistIO net height = do
  m <- assumeUtxoForHeightIO net height
  return $ case m of
    Just _  -> Right ()
    Nothing -> Left (assumeutxoWhitelistError height)

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

-- | Minimum transaction weight for a valid serialised CTransaction.
-- @MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60 = 240@.
-- Reference: bitcoin-core/src/consensus/consensus.h:23.
-- Used as a denominator bound when decoding compact blocks
-- (blockencodings.cpp, merkleblock.cpp) to bound the maximum
-- number of transactions a block header can claim.
minTransactionWeight :: Int
minTransactionWeight = witnessScaleFactor * 60

-- | Minimum weight of a serializable CTransaction (may be incomplete).
-- @MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10 = 40@.
-- Reference: bitcoin-core/src/consensus/consensus.h:24.
-- Used in compact block pre-fill sanity check (blockencodings.cpp:64).
minSerializableTransactionWeight :: Int
minSerializableTransactionWeight = witnessScaleFactor * 10

-- | +2 hours future-time gate for header acceptance.
--
-- Reference: bitcoin-core/src/chain.h:29
-- @MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60 = 7200@.  A header whose
-- timestamp exceeds @now + MAX_FUTURE_BLOCK_TIME@ is rejected by
-- 'addHeader' as @time-too-new@ and the peer is misbehaving.
-- Anti-DoS: without this gate a peer can announce a header chain whose
-- timestamps are far in the future (the timestamps are internally
-- consistent so MTP + difficulty checks all pass), which inflates
-- 'hcEntries' until manually pruned.
-- Type is Int64 to match Core's int64_t and avoid Word32 wraparound
-- when computing @now + maxFutureBlockTime@ near 2106.
maxFutureBlockTime :: Int64
maxFutureBlockTime = 7200

-- | Maximum allowed timewarp for difficulty-adjustment boundary blocks (BIP94).
--
-- Reference: bitcoin-core/src/consensus/consensus.h:35
-- @MAX_TIMEWARP = 600@.  On testnet4 (and regtest when enforce_BIP94 is on),
-- the first block of each 2016-block difficulty-adjustment interval must not
-- have a timestamp more than 600 seconds (one block target) earlier than
-- the previous block.  This prevents the time-warp attack described in
-- https://github.com/bitcoin/bitcoin/pull/15482.
-- Reference: bitcoin-core/src/validation.cpp:4097-4104
maxTimewarp :: Int64
maxTimewarp = 600

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

-- | Convert compact "bits" format to full target.
-- Mirrors arith_uint256::SetCompact from Bitcoin Core (arith_uint256.cpp).
-- Returns (value, isNegative, isOverflow).
-- Reference: bitcoin-core/src/arith_uint256.cpp SetCompact
bitsToTargetFull :: Word32 -> (Integer, Bool, Bool)
bitsToTargetFull bits =
  let nSize   = fromIntegral (bits `shiftR` 24) :: Int
      nWord   = fromIntegral (bits .&. 0x007fffff) :: Integer
      -- Reconstruct the magnitude
      value   = if nSize <= 3
                then nWord `shiftR` (8 * (3 - nSize))
                else nWord `shiftL` (8 * (nSize - 3))
      -- Negative flag: sign bit set AND mantissa is non-zero
      isNeg   = nWord /= 0 && (bits .&. 0x00800000) /= 0
      -- Overflow: nWord != 0 AND (nSize > 34, or nWord > 0xff and nSize > 33,
      --           or nWord > 0xffff and nSize > 32)
      -- Reference: bitcoin-core/src/arith_uint256.cpp SetCompact lines 190-192
      isOvfl  = nWord /= 0 &&
                  (nSize > 34
                   || (nWord > 0xff   && nSize > 33)
                   || (nWord > 0xffff && nSize > 32))
  in (value, isNeg, isOvfl)

-- | Convert compact "bits" format to full target (unsigned magnitude).
-- Returns 0 for negative or overflow compact values; callers that need
-- to distinguish those cases should use 'bitsToTargetFull'.
-- Format: first byte = exponent (number of bytes), next 3 bytes = significand
-- target = significand * 2^(8*(exponent-3))
bitsToTarget :: Word32 -> Integer
bitsToTarget bits =
  let (value, isNeg, isOvfl) = bitsToTargetFull bits
  in if isNeg || isOvfl then 0 else value

-- | Convert full target to compact "bits" format.
-- Mirrors arith_uint256::GetCompact from Bitcoin Core (arith_uint256.cpp).
-- Reference: bitcoin-core/src/arith_uint256.cpp GetCompact
targetToBits :: Integer -> Word32
targetToBits target
  | target <= 0 = 0
  | otherwise =
      -- Count the number of bytes needed (= ceil(bits/8))
      let nSize0 = byteLength target
          -- Extract 3-byte mantissa: if value fits in 3 bytes, left-shift
          -- it into the top of the 3-byte field; otherwise take the top 3 bytes.
          -- This mirrors Core's GetCompact which left-shifts small values:
          --   nCompact = GetLow64() << (8 * (3 - nSize))
          nCompact0 :: Word32
          nCompact0
            | nSize0 <= 3 =
                -- Left-align the value within 3 bytes, matching Core:
                --   nCompact = low64 << (8*(3 - nSize))
                fromIntegral (target `shiftL` (8 * (3 - nSize0)))
            | otherwise =
                -- Right-shift to keep only top 3 bytes
                fromIntegral (target `shiftR` (8 * (nSize0 - 3)))
          -- If the sign bit (0x00800000) is set in the 3-byte mantissa,
          -- we must shift right by one byte and bump the exponent.
          (nCompact1, nSize1)
            | nCompact0 .&. 0x00800000 /= 0 = (nCompact0 `shiftR` 8, nSize0 + 1)
            | otherwise                      = (nCompact0, nSize0)
      in (fromIntegral nSize1 `shiftL` 24) .|. (nCompact1 .&. 0x007fffff)

-- | Number of bytes required to represent a positive Integer.
-- Used by targetToBits to compute the compact exponent.
byteLength :: Integer -> Int
byteLength 0 = 0
byteLength n = go n 0
  where
    go 0 acc = acc
    go x acc = go (x `shiftR` 8) (acc + 1)

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

-- | Verify proof of work for a block header.
-- Mirrors Bitcoin Core's DeriveTarget + CheckProofOfWorkImpl (pow.cpp).
-- Rejects nBits that are negative, overflow, zero, or exceed powLimit.
-- Reference: bitcoin-core/src/pow.cpp DeriveTarget / CheckProofOfWorkImpl
checkProofOfWork :: BlockHeader -> Integer -> Bool
checkProofOfWork header powLimitTarget =
  let nBits = bhBits header
      (target, isNeg, isOvfl) = bitsToTargetFull nBits
      -- Compute block hash and convert to integer
      headerHash = getHash256 $ getBlockHashHash $ computeBlockHash header
      -- Bitcoin uses little-endian hash comparison, so reverse to big-endian
      hashAsInteger = bsToInteger (BS.reverse headerHash)
  -- Gate order matches Core's DeriveTarget:
  --   fNegative || bnTarget == 0 || fOverflow || bnTarget > pow_limit
  -- Reference: bitcoin-core/src/pow.cpp lines 155-158
  in not isNeg && not isOvfl && target /= 0 && target <= powLimitTarget
     && hashAsInteger <= target

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
          pindexFirst = getAncestorBI pindexLast (netRetargetInterval net - 1)

          -- Get the old target (either from last or first block for BIP94)
          -- Reference: bitcoin-core/src/pow.cpp lines 67-76
          oldTarget = if netEnforceBIP94 net
                      then bitsToTarget (biBits pindexFirst)  -- BIP94: use first block
                      else bitsToTarget (biBits pindexLast)   -- Normal: use last block

          -- Calculate actual timespan using Int64 arithmetic to match Core.
          -- Core uses int64_t: nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime
          -- This preserves sign for out-of-order / time-warped timestamps.
          -- Using Word32 subtraction would wrap to a large positive value instead.
          -- Reference: bitcoin-core/src/pow.cpp line 56
          nActualTimespan :: Int64
          nActualTimespan = fromIntegral (biTimestamp pindexLast)
                          - fromIntegral (biTimestamp pindexFirst)

          -- Clamp timespan to [targetTimespan/4, targetTimespan*4]
          -- Reference: bitcoin-core/src/pow.cpp lines 57-60
          minTimespan :: Int64
          minTimespan = fromIntegral (netPowTargetTimespan net) `div` 4
          maxTimespan :: Int64
          maxTimespan = fromIntegral (netPowTargetTimespan net) * 4
          clampedTimespan :: Int64
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

-- | Check whether a difficulty transition from @oldNBits@ to @newNBits@ at
-- @height@ is permitted under consensus rules.
--
-- Reference: bitcoin-core/src/pow.cpp PermittedDifficultyTransition (lines 89-136).
--
-- At a retarget boundary: new target must lie within [oldTarget/4, oldTarget*4]
-- (clamped to powLimit).
-- Between retarget boundaries: bits must be identical (except on networks where
-- min-diff blocks are allowed, in which case any transition is permitted).
--
-- Used by the PRESYNC and REDOWNLOAD phases to bound the difficulty change rate,
-- capping the maximum per-block work an attacker can claim.
permittedDifficultyTransition :: Network -> Int64 -> Word32 -> Word32 -> Bool
permittedDifficultyTransition net height oldNBits newNBits
  -- fPowAllowMinDifficultyBlocks: any transition is ok (testnet)
  | netAllowMinDiffBlocks net = True
  -- At a retarget boundary: check 4× bound
  | height `mod` fromIntegral (netRetargetInterval net) == 0 =
      let tspan  = fromIntegral (netPowTargetTimespan net) :: Integer
          minTs  = tspan `div` 4
          maxTs  = tspan * 4
          pLim   = netPowLimit net
          -- Observed new target (from compact)
          obsNew = bitsToTarget newNBits
          -- Largest permitted target = oldTarget * 4, clamped to powLimit
          largestT0 = (bitsToTarget oldNBits * maxTs) `div` tspan
          largestT  = min pLim largestT0
          -- Re-compact+expand to match Core's rounding
          largestR  = bitsToTarget (targetToBits largestT)
          -- Smallest permitted target = oldTarget / 4, clamped to powLimit
          smallestT0 = (bitsToTarget oldNBits * minTs) `div` tspan
          smallestT  = min pLim smallestT0
          smallestR  = bitsToTarget (targetToBits smallestT)
      in obsNew <= largestR && obsNew >= smallestR
  -- Not at boundary: bits must be unchanged
  | otherwise = oldNBits == newNBits

--------------------------------------------------------------------------------
-- Block Reward
--------------------------------------------------------------------------------

-- | Calculate block reward for a given height
-- Initial reward: 50 BTC (5,000,000,000 satoshis)
-- Halves every 210,000 blocks
blockReward :: Word32 -> Word64
blockReward = blockRewardWithInterval halvingInterval
  -- Block 0-209999:      50 BTC
  -- Block 210000-419999: 25 BTC
  -- Block 420000-629999: 12.5 BTC
  -- Block 630000-839999: 6.25 BTC
  -- Block 840000-1049999: 3.125 BTC (April 2024)

-- | Network-aware block subsidy.  Bitcoin Core's GetBlockSubsidy halves on
-- @consensus.nSubsidyHalvingInterval@, which is 210000 on mainnet/testnet3/
-- testnet4/signet but 150 on REGTEST (kernel/chainparams.cpp:535).  The
-- value-blind 'blockReward' baked in the mainnet 210000 constant, so the
-- coinbase-cap gate ('validateFullBlock' / 'applyBlock' — @blockReward height
-- + fees@) computed the WRONG ceiling on regtest: at regtest height >= 150 the
-- true subsidy has already halved to 25 BTC, but the 210000-constant gate still
-- permitted a 50-BTC coinbase (a regtest-only "bad-cb-amount" false-accept).
-- This delegates to the per-network 'netHalvingInterval', which already carries
-- 150 for regtest and 210000 for mainnet/testnet — so mainnet/testnet output is
-- byte-identical (default-preserving) and only regtest is corrected.
-- Reference: bitcoin-core/src/validation.cpp GetBlockSubsidy +
-- kernel/chainparams.cpp nSubsidyHalvingInterval.
blockRewardForNet :: Network -> Word32 -> Word64
blockRewardForNet net = blockRewardWithInterval (netHalvingInterval net)

-- | Shared subsidy schedule parameterised on the halving interval.
blockRewardWithInterval :: Word32 -> Word32 -> Word64
blockRewardWithInterval interval height =
  let halvings = height `div` interval
  in if halvings >= 64
     then 0  -- After 64 halvings, reward is 0
     else 5000000000 `shiftR` fromIntegral halvings

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
  -- Hash of the block at height 227931.  Core uses this as an anchor:
  -- BIP30 is skipped in the range [BIP34Height, 1983702) only when this
  -- hash is confirmed in the local chainstate, ensuring BIP30 stays
  -- enforced on any fork that lacks the canonical BIP34 activation block.
  -- Source: bitcoin-core/src/kernel/chainparams.cpp line 90.
  , netBIP34Hash         = hashFromHex "000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"
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
  -- Mainnet headerssync params: bitcoin-core/src/kernel/chainparams.cpp line 193-195
  , netHeaderSyncParams  = HeaderSyncParams { hspCommitmentPeriod = 641, hspRedownloadBufferSize = 15218 }
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
      -- hashhog-local snapshot at h=944183, used to recover haskoin's
      -- mainnet chainstate after the W162 corruption (UTXO-view best-block
      -- stuck at genesis).  NOT a Bitcoin Core chainparams entry — the four
      -- 840k/880k/910k/935k entries above ARE.  The serialized-UTXO hash
      -- below is computed locally over the on-disk snapshot file
      -- (165,095,935 coins, /data/nvme1/rustoshi-recovery-snapshot-944183.dat)
      -- and is cross-impl consistent with rustoshi's
      -- crates/consensus/src/params.rs and blockbrew's
      -- internal/consensus/assumeutxo.go (both store ChainTxCount =
      -- 1334000000 and the same display-order hash 2eaf7172…).
      --
      -- 'aupHashSerialized' is in DISPLAY (uint256) order to match the four
      -- Core entries above: 'hexToHash256' does NOT reverse, and
      -- 'verifySnapshot' compares this value byte-for-byte against
      -- 'computeUtxoHash' which yields display order.
      , (944183, AssumeUtxoParams
          { aupHeight = 944183
          , aupHashSerialized = hexToHash256 "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"
          , aupChainTxCount = 1334000000
          , aupBlockHash = hashFromHex "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"
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
  -- Source: bitcoin-core/src/kernel/chainparams.cpp line 213.
  , netBIP34Hash         = hashFromHex "0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"
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
  -- Testnet3 headerssync params: bitcoin-core/src/kernel/chainparams.cpp line ~294-296
  , netHeaderSyncParams  = HeaderSyncParams { hspCommitmentPeriod = 673, hspRedownloadBufferSize = 14460 }
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
  -- Testnet4: BIP34Hash = {} (zero hash) per Core chainparams.cpp line 312.
  -- With BIP34Height=1 and BIP34Hash=zero, the anchor check always passes
  -- (no block in the chain has the zero hash), so BIP30 stays enforced
  -- below height 1983702 as Core intends.
  , netBIP34Hash         = BlockHash (Hash256 (BS.replicate 32 0))
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
  -- Testnet4 headerssync params: bitcoin-core/src/kernel/chainparams.cpp line ~399-401
  , netHeaderSyncParams  = HeaderSyncParams { hspCommitmentPeriod = 606, hspRedownloadBufferSize = 16092 }
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
  -- Regtest: BIP34Hash = {} (zero hash) per Core chainparams.cpp line 537.
  , netBIP34Hash         = BlockHash (Hash256 (BS.replicate 32 0))
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
  -- Regtest headerssync params: bitcoin-core/src/kernel/chainparams.cpp line ~516-518
  , netHeaderSyncParams  = HeaderSyncParams { hspCommitmentPeriod = 620, hspRedownloadBufferSize = 15724 }
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

-- | Compute Merkle root from list of transaction IDs.
-- Returns zero hash for empty list. This is the root-only projection of
-- 'computeMerkleRootMutated' (which additionally reports the CVE-2012-2459
-- mutation flag); the root bytes are byte-identical to the previous
-- implementation.
computeMerkleRoot :: [TxId] -> Hash256
computeMerkleRoot = fst . computeMerkleRootMutated

-- | Compute the Merkle root AND the CVE-2012-2459 mutation flag, mirroring
-- Bitcoin Core's @ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated)@
-- (bitcoin-core/src/consensus/merkle.cpp:46-63).
--
-- Core's mutation rule, per-level:
--   1. At the TOP of each level-collapse iteration (BEFORE the odd-tail
--      duplication and BEFORE any pairwise hashing), scan COMPLETE adjacent
--      pairs only: @for (pos = 0; pos + 1 < size; pos += 2) if h[pos]==h[pos+1]@.
--      The lone trailing element on an odd level (pos+1 == size) is NOT
--      compared at this level.
--   2. THEN, if the level size is odd, duplicate the last element
--      (merkle.cpp:54-56) — that duplicate becomes an identical adjacent pair
--      caught on the NEXT level's top-of-loop scan.
--   3. Hash the pairs to form the next level; repeat while size > 1.
--
-- Scanning BEFORE the odd-dup and over complete pairs only is essential:
-- doing it after duplication (or including the lone tail) would false-reject
-- honest odd-N blocks. CheckBlock treats @mutated=True@ identically to a bad
-- merkle root ("bad-txns-duplicate"); see 'validateFullBlock' step 3.
computeMerkleRootMutated :: [TxId] -> (Hash256, Bool)
computeMerkleRootMutated []        = (Hash256 (BS.replicate 32 0), False)
computeMerkleRootMutated [TxId h]  = (h, False)
computeMerkleRootMutated txids =
  let hashes = map (\(TxId h) -> h) txids
  in merkleStep False hashes
  where
    -- mutation: sticky accumulator carried across levels, exactly like Core's
    -- @bool mutation@ local that persists through the while loop.
    merkleStep :: Bool -> [Hash256] -> (Hash256, Bool)
    merkleStep mutation [h] = (h, mutation)
    merkleStep mutation hs =
      let -- (1) Top-of-iteration scan over COMPLETE adjacent pairs, BEFORE the
          --     odd-tail duplication. Lone trailing element is excluded.
          mutation' = mutation || scanAdjacentPairs hs
          -- (2) If odd number of hashes, duplicate the last one.
          hs' = if odd (length hs) then hs ++ [last hs] else hs
          -- (3) Pair up and hash to form the next level.
          pairs = pairUp hs'
          nextLevel = map (\(Hash256 a, Hash256 b) ->
            doubleSHA256 (BS.append a b)) pairs
      in merkleStep mutation' nextLevel

    -- Core merkle.cpp:50-52 — only complete pairs (pos, pos+1) are compared;
    -- a final odd element is skipped at THIS level.
    scanAdjacentPairs :: [Hash256] -> Bool
    scanAdjacentPairs (a:b:rest) = a == b || scanAdjacentPairs rest
    scanAdjacentPairs _          = False   -- 0 or 1 element left: no complete pair

    pairUp :: [a] -> [(a, a)]
    pairUp [] = []
    pairUp (a:b:rest) = (a, b) : pairUp rest
    pairUp [a] = [(a, a)]  -- Should not happen due to odd handling above

--------------------------------------------------------------------------------
-- Block Header Validation
--------------------------------------------------------------------------------

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

  -- Size check: non-witness serialized size * WITNESS_SCALE_FACTOR must not
  -- exceed MAX_BLOCK_WEIGHT. Mirrors Bitcoin Core consensus/tx_check.cpp:19-21.
  -- Reference: "bad-txns-oversize" (TX_CONSENSUS)
  when (txBaseSize tx * witnessScaleFactor > maxBlockWeight) $
    Left "bad-txns-oversize"

  -- Check each output value is non-negative and within range.
  -- txOutValue is Word64 (unsigned), but Bitcoin's wire format is int64 (signed).
  -- A negative wire value has its high bit set; we must check this before the
  -- upper-bound test to produce the correct BIP-22 rejection string.
  -- Mirrors Bitcoin Core consensus/tx_check.cpp::CheckTransaction order.
  forM_ (txOutputs tx) $ \out -> do
    when (fromIntegral (txOutValue out) < (0 :: Int64)) $
      Left "Transaction output has negative value"
    -- Per-output upper-bound check (consensus/tx_check.cpp::CheckTransaction — Core parity)
    when (txOutValue out > maxMoney) $
      Left "Transaction output value exceeds MAX_MONEY"

  -- Check total output value incrementally to catch Word64 wrap-around.
  -- Core accumulates nValueOut with a per-step MoneyRange guard:
  --   consensus/tx_check.cpp::CheckTransaction → "bad-txns-txouttotal-toolarge".
  -- A plain `sum` on Word64 silently wraps; we must replicate Core's running check.
  let checkTotalOut !acc [] = Right acc
      checkTotalOut !acc (out:outs) =
        let acc' = acc + txOutValue out
        in if acc' > maxMoney
             then Left "bad-txns-txouttotal-toolarge"
             else checkTotalOut acc' outs
  _ <- checkTotalOut 0 (txOutputs tx)

  -- Check for duplicate inputs (CVE-2018-17144).
  -- Use Data.Set for O(n log n) rather than nub's O(n²).
  -- Core: consensus/tx_check.cpp::CheckTransaction → "bad-txns-inputs-duplicate".
  let outpoints = map txInPrevOutput (txInputs tx)
      opSet     = Set.fromList outpoints
  when (Set.size opSet /= length outpoints) $
    Left "bad-txns-inputs-duplicate"

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

-- | Consensus flags indicating which BIPs are active.
-- Only MANDATORY_SCRIPT_VERIFY_FLAGS are represented here (Bitcoin Core
-- policy/policy.h:105-111): P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS,
-- TAPROOT.  Policy-only flags (NULLFAIL, LOW_S, CLEANSTACK, etc.) must NOT
-- appear in the block-connect script-verify flag computer.
data ConsensusFlags = ConsensusFlags
  { flagBIP34       :: !Bool    -- ^ Block height in coinbase
  , flagBIP65       :: !Bool    -- ^ OP_CHECKLOCKTIMEVERIFY
  , flagBIP66       :: !Bool    -- ^ Strict DER signatures
  , flagSegWit      :: !Bool    -- ^ Segregated Witness
  , flagTaproot     :: !Bool    -- ^ Taproot
  , flagNullDummy   :: !Bool    -- ^ NULLDUMMY (BIP-147) — consensus (Core MANDATORY set)
  , flagCSV         :: !Bool    -- ^ OP_CHECKSEQUENCEVERIFY (BIP-68/112/113) —
                                --   keyed off 'netCSVHeight', which on mainnet
                                --   (419328) is EARLIER than 'netSegwitHeight'
                                --   (481824).  Core's GetBlockScriptFlags
                                --   (validation.cpp:2278-2281) gates
                                --   SCRIPT_VERIFY_CHECKSEQUENCEVERIFY on
                                --   DEPLOYMENT_CSV, NOT on segwit.  Was
                                --   previously aliased to 'flagSegWit', which
                                --   under-flagged OP_CSV as a NOP for the
                                --   62,496-block CSV-only window
                                --   (W132 BUG-1 P0-CONSENSUS).
  } deriving (Show, Generic)

-- | Compute consensus flags for a given height based on network rules.
-- NULLFAIL (BIP-146) is intentionally excluded: it is a
-- STANDARD_SCRIPT_VERIFY_FLAG (policy only) per Core policy/policy.h:125.
consensusFlagsAtHeight :: Network -> Word32 -> ConsensusFlags
consensusFlagsAtHeight net h = ConsensusFlags
  { flagBIP34     = h >= netBIP34Height net
  , flagBIP65     = h >= netBIP65Height net
  , flagBIP66     = h >= netBIP66Height net
  , flagSegWit    = h >= netSegwitHeight net
  , flagNullDummy = h >= netSegwitHeight net
  , flagTaproot   = h >= netTaprootHeight net
  , flagCSV       = h >= netCSVHeight net
  }

-- | Convert ConsensusFlags to ScriptFlags for script verification.
-- This maps the consensus-level flags to the script interpreter's flag type.
-- Only consensus-critical flags are included.
consensusFlagsToScriptFlags :: ConsensusFlags -> ScriptFlags
consensusFlagsToScriptFlags cf = flagSet $ concat
  [ [VerifyP2SH]  -- P2SH is always enabled (post BIP-16)
  , [VerifyDERSig | flagBIP66 cf]
  , [VerifyCheckLockTimeVerify | flagBIP65 cf]
  , [VerifyCheckSequenceVerify | flagCSV cf]     -- CSV (BIP-112) gated by
                                                 -- netCSVHeight, EARLIER than
                                                 -- segwit on mainnet — matches
                                                 -- Core GetBlockScriptFlags
                                                 -- DEPLOYMENT_CSV gate.
  , [VerifyWitness | flagSegWit cf]
  , [VerifyNullDummy | flagNullDummy cf]
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

-- | BIP-68 applies only when version >= 2. Core stores version as uint32_t and
-- compares it UNSIGNED (fEnforceBIP68 = tx.version >= 2, tx_verify.cpp:51), so a
-- high-bit version (e.g. 0x80000002) STILL enforces BIP-68. haskoin stores the
-- version as Int32 (signed); a signed comparison treats 0x80000002 as negative and
-- SKIPS enforcement, false-accepting a tx with an unmet relative timelock (a chain
-- split). Reinterpret the bits as Word32 -- same as the OP_CSV path (Script.hs:2408).
bip68VersionActive :: Int32 -> Bool
bip68VersionActive v = (fromIntegral v :: Word32) >= 2

calculateSequenceLocks :: Tx                -- ^ Transaction to check
                       -> [Word32]          -- ^ Height at which each input's UTXO was confirmed
                       -> [Word32]          -- ^ MTP of block before each input's UTXO was confirmed
                       -> Bool              -- ^ Whether to enforce BIP68
                       -> SequenceLock
calculateSequenceLocks tx prevHeights prevMTPs enforceBIP68
  | not enforceBIP68 = SequenceLock (-1) (-1)
  | not (bip68VersionActive (txVersion tx)) = SequenceLock (-1) (-1)  -- BIP68 requires version >= 2 (unsigned)
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
--
-- Reference: Bitcoin Core versionbits.cpp GetStateSinceHeightFor (lines 157-190).
-- For ALWAYS_ACTIVE and NEVER_ACTIVE deployments Core returns 0 immediately.
getStateSinceHeight :: Deployment
                    -> (BlockIndex -> Word32)
                    -> DeploymentCache
                    -> Maybe BlockIndex
                    -> (Word32, DeploymentCache)
getStateSinceHeight dep getMTP cache mPindexPrev
  -- Gate 1: ALWAYS_ACTIVE / NEVER_ACTIVE → return 0 immediately.
  -- Core versionbits.cpp:158-162:
  --   if (start_time == ALWAYS_ACTIVE || start_time == NEVER_ACTIVE) return 0;
  | depStartTime dep == deploymentAlwaysActive = (0, cache)
  | depStartTime dep == deploymentNeverActive  = (0, cache)
  | otherwise =
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

-- | Build a 'BlockIndex' linked list from a 'Map BlockHash ChainEntry' tip.
-- Walks back at most @depth@ entries. Used by 'computeBlockVersionFromChain'.
-- The chain needs to extend at least one BIP9 period (2016 blocks) for accurate
-- signalling counts.
--
-- We limit the walk to @maxBI@ steps so this is O(maxBI) not O(chain length).
chainEntriesToBlockIndex :: Map BlockHash ChainEntry  -- ^ All known headers
                         -> ChainEntry                -- ^ Tip to start from
                         -> Int                       -- ^ Maximum depth to walk back
                         -> Maybe BlockIndex
chainEntriesToBlockIndex entries tip maxDepth = go tip maxDepth
  where
    go :: ChainEntry -> Int -> Maybe BlockIndex
    go ce depth =
      let prevBI = if depth <= 0
                   then Nothing
                   else cePrev ce >>= \ph ->
                          Map.lookup ph entries >>= \prevCe ->
                            go prevCe (depth - 1)
          bi = BlockIndex
                 { biHeight    = ceHeight ce
                 , biBits      = bhBits (ceHeader ce)
                 , biTimestamp = bhTimestamp (ceHeader ce)
                 , biVersion   = bhVersion (ceHeader ce)
                 , biHash      = ceHash ce
                 , biPrev      = prevBI
                 }
      in Just bi

-- | Compute the block version for a new block using the chain entry map.
-- This is the correct entry point for mining code (block template construction).
-- Sets VERSIONBITS_TOP_BITS (0x20000000) and OR-in bits for every deployment
-- that is in STARTED or LOCKED_IN state for the block after @tip@.
--
-- Reference: Bitcoin Core versionbits.cpp ComputeBlockVersion (lines 265-279).
computeBlockVersionFromChain :: [(Deployment, DeploymentCache)]  -- ^ Active deployments + caches
                             -> Map BlockHash ChainEntry          -- ^ Header chain entries
                             -> ChainEntry                        -- ^ Parent block (tip)
                             -> (Int32, [(Deployment, DeploymentCache)])
computeBlockVersionFromChain deployments entries tip =
  let -- Build a BlockIndex chain deep enough for one BIP9 period.
      -- BIP9 signals are counted over one retarget period (2016 blocks) so we
      -- only need to walk back 2016 entries.
      maxLookback = 2016
      mBI = chainEntriesToBlockIndex entries tip maxLookback
      -- MTP function: each BlockIndex node carries ceMedianTime from ChainEntry.
      -- We use the pre-computed ceMedianTime stored in the chain entries map
      -- via the biHash → ceMedianTime lookup. For blocks not in the map we
      -- fall back to biTimestamp (safe: timestamp ≥ MTP by construction).
      getMTP :: BlockIndex -> Word32
      getMTP bi = case Map.lookup (biHash bi) entries of
                    Just ce -> ceMedianTime ce
                    Nothing -> biTimestamp bi
  in computeBlockVersion deployments getMTP mBI

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

-- | Build the canonical BIP-34 byte encoding for a block height.
-- Mirrors Bitcoin Core's CScript() << nHeight (script.h:433-448):
--   height == 0  → OP_0 (0x00), single byte
--   1..16        → OP_1..OP_16 (0x51..0x60), single byte
--   otherwise    → length-prefixed sign-magnitude CScriptNum
encodeBip34Height :: Word32 -> ByteString
encodeBip34Height 0 = BS.singleton 0x00
encodeBip34Height h | h >= 1 && h <= 16 = BS.singleton (0x50 + fromIntegral h)
encodeBip34Height h =
  let le = encodeLeBytes h
      -- If high bit of last byte is set, append zero sign byte
      le' = if BS.last le .&. 0x80 /= 0 then BS.snoc le 0x00 else le
  in BS.cons (fromIntegral (BS.length le')) le'
  where
    encodeLeBytes :: Word32 -> ByteString
    encodeLeBytes 0 = BS.empty
    encodeLeBytes n = BS.cons (fromIntegral (n .&. 0xff)) (encodeLeBytes (n `shiftR` 8))

-- | Consensus gate for BIP-34 coinbase height.
-- Performs byte-exact PREFIX match against the canonical encoding of height,
-- matching Bitcoin Core's ContextualCheckBlock (validation.cpp:4151-4159).
-- The lenient 'coinbaseHeight' decoder is intentionally NOT used here.
validateCoinbaseHeightConsensus :: Word32 -> Tx -> Bool
validateCoinbaseHeightConsensus height tx
  | not (isCoinbase tx) = False
  | otherwise =
      let expect = encodeBip34Height height
          sig    = txInScript (head (txInputs tx))
          n      = BS.length expect
      in BS.length sig >= n && BS.take n sig == expect

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
--
-- DEAD CODE (wave-33b ledger): test-only callers (Spec.hs:2251).
-- The live weight check is inline in 'connectBlock'.
-- BIP-141 weight rule fixes belong in 'connectBlock', NOT here.
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
-- Transaction Finality (IsFinalTx)
--------------------------------------------------------------------------------

-- | LOCKTIME_THRESHOLD: locktimes >= this value are UNIX timestamps;
-- values below are interpreted as block heights.
-- Reference: Bitcoin Core consensus/tx_check.cpp
locktimeThresholdConsensus :: Word32
locktimeThresholdConsensus = 500000000

-- | SEQUENCE_FINAL: when all inputs carry this sequence, nLockTime is ignored.
sequenceFinalConsensus :: Word32
sequenceFinalConsensus = 0xFFFFFFFF

-- | Check if a transaction is final at the given block height and time.
-- A transaction is final if:
--   1. nLockTime == 0, OR
--   2. nLockTime < threshold (satisfied by height or time), OR
--   3. All inputs have nSequence == 0xFFFFFFFF (SEQUENCE_FINAL)
--
-- This matches Bitcoin Core's IsFinalTx() in src/consensus/tx_check.cpp.
-- Called from validateFullBlock to implement ContextualCheckBlock parity.
isFinalTxCheck :: Tx -> Word32 -> Word32 -> Bool
isFinalTxCheck tx blockHeight blockTime
  | txLockTime tx == 0 = True
  | isLockTimeSatisfied = True
  | otherwise = all (\inp -> txInSequence inp == sequenceFinalConsensus) (txInputs tx)
  where
    lockTime = txLockTime tx
    isLockTimeSatisfied
      | lockTime < locktimeThresholdConsensus = lockTime < blockHeight
      | otherwise                             = lockTime < blockTime

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
-- | @skipConnectChecks@: when @True@, skip all UTXO-dependent checks
-- (coinbase maturity, BIP-68 sequence locks, input existence \/ fee
-- computation, sigop cost, coinbase value cap).  Pass @True@ ONLY from
-- the side-branch acceptance arm of @submitBlock@, mirroring Bitcoin
-- Core's @AcceptBlock@ (validation.cpp:4298-4357): only @CheckBlock@ +
-- @ContextualCheckBlock@ run for every block at accept time; full UTXO
-- validation (@ConnectBlock@) runs only during @ActivateBestChainStep@
-- against the fork-point UTXO view rebuilt by @DisconnectBlock@.
-- All callers that validate against a real UTXO view pass @False@.
validateFullBlock :: Network -> ChainState -> Bool -> Bool -> Block -> Map OutPoint Coin
                 -> Either String ()
validateFullBlock net cs skipScripts skipConnectChecks block utxoCoinMap = do
  let height = csHeight cs + 1
      flags = consensusFlagsAtHeight net height
      header = blockHeader block
      txns = blockTxns block
      blockHash = computeBlockHash header
      checkpoints = buildCheckpoints net
      -- TxOut-only view for validateBlockTransactions (script checking).
      utxoMap = fmap coinTxOut utxoCoinMap

  -- 0a. COINBASE_MATURITY (W164 follow-up). A tx may not spend a coinbase
  -- output until it is netCoinbaseMaturity (100) blocks deep. validateFullBlock
  -- receives the full Map OutPoint Coin (coinHeight + coinIsCoinbase), but the
  -- TxOut-only utxoMap above DISCARDS that metadata (fmap coinTxOut) -- so the
  -- live MBlock arm (Main.hs) and the dead Sync.hs IBD path both skipped
  -- maturity (only the submitblock arm enforced it, via applyBlockToCache).
  -- Check it HERE, the single chokepoint both leaky arms flow through,
  -- mirroring checkTxInputsConnect (:2996) and applyBlock (:4644). Spend height
  -- is the connecting block's own `height` (= csHeight cs + 1), matching Core
  -- consensus/tx_verify.cpp:177-180 + validation.cpp:2535 (NO +1: the +1 is
  -- mempool-only). Coinbase tx is naturally exempt (its null prevout is absent
  -- from utxoCoinMap); an intra-block coinbase spend is absent too (added to
  -- the UTXO set only after the block connects).
  -- Gated on skipConnectChecks: coinbase maturity requires the correct UTXO
  -- view (fork-point), which is not available at side-branch accept time.
  -- Core enforces this in ConnectBlock (validation.cpp:2535), not AcceptBlock.
  unless skipConnectChecks $ do
    let cbMaturity  = fromIntegral (netCoinbaseMaturity net)
        immatureCb  = [ () | tx   <- tail txns
                           , txin <- txInputs tx
                           , Just c <- [Map.lookup (txInPrevOutput txin) utxoCoinMap]
                           , coinIsCoinbase c
                           , height - coinHeight c < cbMaturity ]
    unless (null immatureCb) $
      Left "bad-txns-premature-spend-of-coinbase"

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

  -- 2a. Run context-free validation on the coinbase (CheckTransaction analog).
  -- validateBlockTransactions processes tail txns only (skipping coinbase), so
  -- the coinbase scriptSig 2..100 byte range check (Core "bad-cb-length") would
  -- never fire without this explicit call.
  -- Bitcoin Core: consensus/tx_check.cpp CheckTransaction "bad-cb-length"
  validateTransaction (head txns)

  -- 2b. BIP-34/66/65: reject blocks with outdated nVersion.
  -- Bitcoin Core validation.cpp:4112-4118 (ContextualCheckBlockHeader):
  --   nVersion < 2 rejected after BIP34 (DEPLOYMENT_HEIGHTINCB) activation.
  --   nVersion < 3 rejected after BIP66 (DEPLOYMENT_DERSIG) activation.
  --   nVersion < 4 rejected after BIP65 (DEPLOYMENT_CLTV) activation.
  -- DeploymentActiveAfter(pindexPrev, ...) = (pindexPrev.height+1) >= activation,
  -- which maps to `height >= netBIPNNHeight net` in our scheme.
  let blockVer = bhVersion header
  when (flagBIP34 flags && blockVer < 2) $
    Left $ "bad-version(0x" ++ showHex (fromIntegral blockVer :: Word32) ")"
  when (flagBIP66 flags && blockVer < 3) $
    Left $ "bad-version(0x" ++ showHex (fromIntegral blockVer :: Word32) ")"
  when (flagBIP65 flags && blockVer < 4) $
    Left $ "bad-version(0x" ++ showHex (fromIntegral blockVer :: Word32) ")"

  -- 3. Verify merkle root + CVE-2012-2459 mutation detection.
  -- Bitcoin Core CheckBlock (validation.cpp:3850-3858) calls
  -- BlockMerkleRoot(block, &mutated) and rejects with "bad-txns-duplicate"
  -- when mutated is set — treating a duplicate-txid mutation identically to a
  -- bad merkle root. Detection (consensus/merkle.cpp:46-63) scans complete
  -- adjacent pairs at the top of each level BEFORE the odd-tail duplication;
  -- see 'computeMerkleRootMutated'. We MUST reject on mutation even when the
  -- recomputed root matches the header root, because a CVE-2012-2459 mutated
  -- tx list produces the SAME root as the honest list.
  let (computedRoot, merkleMutated) = computeMerkleRootMutated (map computeTxId txns)
  unless (computedRoot == bhMerkleRoot header) $ Left "Merkle root mismatch"
  when merkleMutated $ Left "bad-txns-duplicate"

  -- 4. Check block weight (only after SegWit activation)
  when (flagSegWit flags && blockWeight block > maxBlockWeight) $
    Left "Block exceeds maximum weight"

  -- 5. BIP-34: coinbase scriptSig must start with byte-exact canonical encoding
  -- of the block height. Bitcoin Core validation.cpp:4151-4159:
  --   CScript expect = CScript() << nHeight;
  --   sig.size() >= expect.size() && equal(expect, sig[:expect.size()])
  -- Using validateCoinbaseHeightConsensus (strict byte-prefix) rather than
  -- coinbaseHeight (lenient value-decoder) to match Core parity exactly.
  when (flagBIP34 flags) $
    unless (validateCoinbaseHeightConsensus height (head txns)) $
      Left "bad-cb-height"

  -- 6. BIP-113 / Core ContextualCheckBlockHeader (validation.cpp:4092):
  -- block timestamp must be strictly greater than the median-time-past
  -- of the previous 11 blocks. csMedianTime is the MTP of the current tip
  -- (set from ceMedianTime in submitBlock / connectBlock callers).
  -- Reference: bitcoin-core/src/validation.cpp:4092
  when (height > 0 && bhTimestamp header <= csMedianTime cs) $
    Left "timestamp not after median time past"

  -- 7. IsFinalTx: every transaction must be final at this block height/time.
  -- Reference: Bitcoin Core ContextualCheckBlock (validation.cpp:4146).
  -- nLockTimeCutoff = MTP of prev block when CSV is active (BIP-113), else
  -- block timestamp. Note: this check applies even when skipScripts=True
  -- (assumevalid only bypasses script evaluation, not structural consensus rules).
  let csvActive = height >= netCSVHeight net
      lockTimeCutoff = if csvActive then csMedianTime cs else bhTimestamp header
  mapM_ (\tx ->
    unless (isFinalTxCheck tx height lockTimeCutoff) $
      Left "bad-txns-nonfinal"
    ) txns

  -- Steps 7b, 8, 9 are UTXO-dependent (ConnectBlock-level) checks.  When
  -- skipConnectChecks=True (side-branch acceptance via submitBlock), they are
  -- deferred to the reorg-connect path, which reconstructs the fork-point UTXO
  -- view via DisconnectBlock before calling validateFullBlock again.
  -- Bitcoin Core AcceptBlock (validation.cpp:4350) runs only CheckBlock +
  -- ContextualCheckBlock; ConnectBlock (validation.cpp:2295) is called only
  -- during ActivateBestChainStep against the correct UTXO view.
  unless skipConnectChecks $ do
    -- 7b. BIP-68 SequenceLocks: check relative lock-times for every non-coinbase
    --     transaction BEFORE script verification.
    --     Reference: Bitcoin Core validation.cpp ConnectBlock() ~line 2549:
    --       prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
    --       if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex))
    --         state.Invalid(..., "bad-txns-nonfinal", ...)
    --     Core fires this BEFORE CheckInputScripts (script-eval) so that the
    --     rejection is bad-txns-nonfinal, not block-script-verify-flag-failed.
    --     Ordering fix: clearbit/camlcoin/haskoin all had this after script-eval.
    when csvActive $ do
      -- Process transactions in order, accumulating intra-block output heights
      -- so that same-block spends (height = current block height = 0 confirmations)
      -- are handled correctly.  Same-block prevouts are NOT in utxoCoinMap (which
      -- only covers the pre-block chainstate), so we fall back to height for them.
      --
      -- BIP-68 IBD-context wiring: we evaluate ONLY the height-based component
      -- of BIP-68 here and defer the time-based component to the BIP-112
      -- OP_CSV opcode at script-eval time.  Reason: the IBD-side caller does
      -- not have a real `getMtpAtHeight` callback wired through
      -- `validateFullBlock`, so the previous code passed `prevBlockMTP`
      -- (tip's parent MTP) for every input.  But `calculateSequenceLocks`
      -- expects the MTP at `coin_height - 1` per input (a different,
      -- typically much older, value).  With the wrong wiring, any v2 tx
      -- with a non-zero time-based BIP-68 lock_value is unconditionally
      -- rejected (`min_time = prev_block_mtp + lock - 1` always exceeds the
      -- tip's `prev_block_mtp`).  That's a deferred self-wedge: the live
      -- haskoin chainstate (April 12) was synced before this code path
      -- existed, but a fresh IBD on this binary will wedge at the first
      -- post-CSV block carrying a time-based BIP-68 input.
      --
      -- Until per-input MTP-at-height is plumbed through, the safe
      -- parity-with-Core behaviour is to skip the time-based branch here
      -- and rely on BIP-112 (OP_CSV) inside the script interpreter — which
      -- has full per-tx context and already runs for every input.
      -- Height-based locks remain enforced: `coinHeight` from the UTXO row
      -- is correct for both external and intra-block prevouts, so the
      -- height comparison is byte-for-byte the same as Core.
      --
      -- Reference: clearbit's matching resolution (clearbit 44454c1,
      -- src/validation.zig) and rustoshi's matching resolution (this wave).
      -- Cross-impl audit:
      -- CORE-PARITY-AUDIT/_ibd-context-wiring-cross-impl-2026-05-05.md.
      -- Bitcoin Core split: validation.cpp::CheckSequenceLocks (full
      -- chain-access path) + script/interpreter.cpp OP_CSV (script-eval
      -- with full per-tx sighash context).
      let prevBlockMTP = csMedianTime cs
          go :: Map OutPoint Word32 -> [Tx] -> Either String ()
          go _ [] = Right ()
          go intrablockHeights (tx:rest)
            | isCoinbase tx = do
                -- Add coinbase outputs to intra-block map (height = current block)
                let txid = computeTxId tx
                    newOuts = Map.fromList
                      [ (OutPoint txid (fromIntegral i), height)
                      | i <- [0 .. length (txOutputs tx) - 1]
                      ]
                go (Map.union newOuts intrablockHeights) rest
            | otherwise = do
                -- Build prevHeights for the BIP-68 height-based check.  We
                -- pass MTP=0 for every input because we ONLY consume
                -- `slMinHeight` from the resulting `SequenceLock`; the
                -- time-based component is deferred to OP_CSV (see comment
                -- above).
                let prevHeights = map (\inp ->
                      let op = txInPrevOutput inp
                      in case Map.lookup op utxoCoinMap of
                           Just coin -> coinHeight coin
                           Nothing   -> case Map.lookup op intrablockHeights of
                             Just ih  -> ih
                             Nothing  -> height -- missing UTXO: fail elsewhere
                      ) (txInputs tx)
                    prevMTPs    = map (const 0) prevHeights -- unused (height-only gate)
                    enforceBIP68 = bip68Active net height
                    lock = calculateSequenceLocks tx prevHeights prevMTPs enforceBIP68
                    -- Height-only check: ignore `slMinTime` (see comment
                    -- above).  Mirrors `checkSequenceLocks` heightOk branch.
                    heightOk = slMinHeight lock < 0
                            || fromIntegral height > slMinHeight lock
                unless heightOk $
                  Left "bad-txns-nonfinal"
                -- Add this tx's outputs to intra-block height map.
                let txid = computeTxId tx
                    newOuts = Map.fromList
                      [ (OutPoint txid (fromIntegral i), height)
                      | i <- [0 .. length (txOutputs tx) - 1]
                      ]
                go (Map.union newOuts intrablockHeights) rest
      go Map.empty txns

    -- 8. Validate all transactions and compute total fees.
    -- skipScripts=True means per-input script evaluation is bypassed for this
    -- block (assumevalid ancestor path).  All other checks still run.
    -- KNOWN PITFALL: Intra-block spending - txs can spend outputs from earlier txs
    -- We update UTXO set during validation, not after
    totalFees <- validateBlockTransactions flags skipScripts txns utxoMap

    -- 8. Coinbase value must not exceed reward + fees
    -- Network-aware subsidy: regtest halves at 150 (Core
    -- kernel/chainparams.cpp:535), mainnet/testnet at 210000 — see
    -- 'blockRewardForNet'.  Using the value-blind 'blockReward' here computed the
    -- wrong cap on regtest (a regtest-only bad-cb-amount false-accept).
    let maxCoinbase = blockRewardForNet net height + totalFees
        coinbaseValue = sum $ map txOutValue (txOutputs (head txns))
    when (coinbaseValue > maxCoinbase) $
      Left "Coinbase value exceeds allowed amount"

    -- 9. Check sigop cost limit (BIP-141 weight-based counting)
    -- Legacy/P2SH sigops cost WITNESS_SCALE_FACTOR (4) each, witness sigops cost 1 each
    let SigOpCost totalSigOpCost = getBlockSigOpCost block utxoMap flags
    when (totalSigOpCost > maxBlockSigOpsCost) $
      Left "Block exceeds sigop cost limit"

  -- 10. Witness commitment / unexpected-witness validation.
  -- Core: ContextualCheckBlock calls CheckWitnessMalleation unconditionally
  -- (validation.cpp:4169) with expect_witness_commitment = segwit_active.
  -- This means the unexpected-witness check also runs for pre-segwit blocks.
  checkWitnessMalleation (flagSegWit flags) block

  Right ()

-- | BIP-30: Reject a block if any of its transactions would overwrite an existing
-- unspent transaction output in the UTXO set.
--
-- This check must run BEFORE the block's outputs are added to the UTXO set
-- (i.e., before 'connectBlock'/'applyBlock').
--
-- Reference: Bitcoin Core ConnectBlock() / IsBIP30Repeat(), validation.cpp.
-- Mainnet exemptions: blocks 91842 and 91880 are grandfathered.
-- BIP-34 implication: once BIP-34 is active, coinbase txids are guaranteed
-- unique (height is encoded in the scriptSig), so BIP-30 violations are
-- impossible up to height 1,983,702 where the BIP-34 implication is no longer
-- guaranteed (a future miner could re-grind an old coinbase hash).
checkBIP30 :: HaskoinDB -> Network -> Word32 -> Block -> IO (Either String ())
checkBIP30 db net height block = do
  -- Gate 1: IsBIP30Repeat — grandfathered duplicate-coinbase blocks.
  -- Bitcoin Core validation.cpp:6189-6193 (IsBIP30Repeat) checks BOTH height
  -- AND block hash.  Checking height alone would incorrectly exempt a block at
  -- the same height on an alternative fork.
  let bh = computeBlockHash (blockHeader block)
      bip30Repeat91842 = height == 91842
                      && bh == hashFromHex "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
      bip30Repeat91880 = height == 91880
                      && bh == hashFromHex "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
  if bip30Repeat91842 || bip30Repeat91880
    then return (Right ())
    else do
      -- Gate 2: BIP34 hash-anchor skip.
      -- Once BIP-34 is active AND the block at netBIP34Height has the canonical
      -- hash (netBIP34Hash), coinbase txids are unique by construction, so BIP30
      -- cannot be violated in the range [BIP34Height, 1983702).
      -- Bitcoin Core validation.cpp:2460-2462:
      --   pindexBIP34height = pindex->pprev->GetAncestor(params.BIP34Height);
      --   fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height ||
      --     !(pindexBIP34height->GetBlockHash() == params.BIP34Hash));
      -- We query the stored hash at netBIP34Height from the DB.  If it matches
      -- netBIP34Hash the anchor is confirmed and BIP30 can be skipped.
      -- Note: when netBIP34Hash is the zero hash (testnet4/regtest), no stored
      -- block ever has that hash, so the anchor check always fails and BIP30
      -- remains enforced — matching Core's behaviour for those networks.
      bip34AnchorConfirmed <- do
        let bip34H = netBIP34Height net
        if height <= bip34H
          then return False
          else do
            mStoredHash <- getBlockHeight db bip34H
            return $ case mStoredHash of
              Just storedHash -> storedHash == netBIP34Hash net
              Nothing         -> False
      let skipForBIP34 = bip34AnchorConfirmed
                      && height >= netBIP34Height net
                      && height < bip34ImpliesBIP30Limit
      if skipForBIP34
        then return (Right ())
        else go (blockTxns block)
  where
    bip34ImpliesBIP30Limit :: Word32
    bip34ImpliesBIP30Limit = 1983702

    go [] = return (Right ())
    go (tx:txs) = do
      let txid = computeTxId tx
          vouts = [0 .. fromIntegral (length (txOutputs tx) - 1)]
      result <- checkTxOutputs txid vouts
      case result of
        Left err -> return (Left err)
        Right () -> go txs

    checkTxOutputs _ [] = return (Right ())
    checkTxOutputs txid (vout:vouts) = do
      let op = OutPoint txid vout
      mUtxo <- getUTXO db op
      case mUtxo of
        Just _ ->
          return $ Left $
            "bad-txns-BIP30: tried to overwrite transaction"
        Nothing -> checkTxOutputs txid vouts

-- | Validate a full block with BIP-30 enforcement.
--
-- This is the canonical block-validation entry point for both the IBD path
-- (Sync.hs) and the RPC submitblock path (BlockTemplate.hs).  It sequences:
--
--   1. 'checkBIP30'       — UTXO-set duplicate-txid guard (requires DB, IO)
--   2. 'validateFullBlock' — all context-free + contextual checks (pure)
--
-- By routing both paths through this single function, BIP-30 cannot be missed
-- on either arm.  The structural alternative (passing HaskoinDB into the pure
-- 'validateFullBlock') would require making that function monadic, bloating its
-- signature and every caller.  This IO wrapper achieves the same invariant with
-- minimal churn.
--
-- Reference: Bitcoin Core ConnectBlock() order — IsBIP30Repeat() fires before
-- any UTXO mutation at validation.cpp.
validateFullBlockIO :: HaskoinDB -> Network -> ChainState -> Bool -> Block
                   -> Map OutPoint Coin -> IO (Either String ())
validateFullBlockIO db net cs skipScripts block utxoCoinMap = do
  bip30Result <- checkBIP30 db net (csHeight cs + 1) block
  case bip30Result of
    Left err -> return (Left err)
    Right () -> return $ validateFullBlock net cs skipScripts False block utxoCoinMap

-- | Convert ConsensusFlags to a Word32 for use as a cache key.
consensusFlagsToWord32 :: ConsensusFlags -> Word32
consensusFlagsToWord32 cf =
  (if flagBIP34 cf then 1 else 0)
  .|. (if flagBIP65 cf then 2 else 0)
  .|. (if flagBIP66 cf then 4 else 0)
  .|. (if flagSegWit cf then 8 else 0)
  .|. (if flagTaproot cf then 16 else 0)
  .|. (if flagNullDummy cf then 32 else 0)
  .|. (if flagCSV cf then 64 else 0)

--------------------------------------------------------------------------------
-- Process-wide Signature Verification Cache
--
-- The primitives (initGlobalSigCache, lookupGlobalSigCache,
-- insertGlobalSigCache) now live in 'Haskoin.Crypto' so that 'Haskoin.Script'
-- can call them at the actual EC verify site without creating a Script ↔
-- Consensus import cycle.  We re-export them from here so that existing
-- consumers (app/Main.hs runNodeBody, test/W105CheckQueueSpec.hs) keep
-- compiling.
--
-- W159 BUG-17 / W160 BUG-16 FIX: cache key is now Core's
-- @(sighash, pubkey, sig)@ triple — matching
-- @SignatureCache::ComputeEntryECDSA@ / @ComputeEntrySchnorr@
-- (bitcoin-core/src/script/sigcache.cpp:39-49).  See Haskoin.Crypto for
-- the long-form rationale.
--------------------------------------------------------------------------------

-- | A single resolved per-input script-verification work item — the unit of
-- parallel work dispatched after the serial economic pass.  Core's
-- @CScriptCheck@ analog (one entry per non-coinbase input).
--
-- Every field is already resolved against the correct UTXO view (including
-- intra-block prevouts) by 'validateSingleTxCollect', so the worker is a pure
-- 'verifyScriptWithFlags' call with no further map lookups.  @sciInputIdx@ is
-- the input index WITHIN ITS TRANSACTION (the @idx@ argument to the verifier
-- and the number in the rejection message), matching the old serial loop's
-- @forM_ (zip3 [0..] ...)@ numbering exactly.
--
-- NOTE: this is the same shape as 'Haskoin.Performance.ScriptCheck'; it is
-- duplicated here only because 'Haskoin.Performance' imports
-- 'Haskoin.Consensus' (for 'ConsensusFlags') — importing it back would form a
-- module cycle.  The parallel dispatch logic is likewise kept local to this
-- module ('runScriptChecksParallel') to avoid that cycle.
data ScriptCheckItem = ScriptCheckItem
  { sciTx           :: !Tx           -- ^ Spending transaction
  , sciInputIdx     :: !Int          -- ^ Input index within sciTx
  , sciPrevScript   :: !ByteString   -- ^ prevout scriptPubKey
  , sciPrevValue    :: !Word64       -- ^ prevout amount
  , sciSpentAmounts :: ![Word64]     -- ^ BIP-341 sha_amounts (this tx, in order)
  , sciSpentScripts :: ![ByteString] -- ^ BIP-341 sha_scriptpubkeys (this tx, in order)
  }

-- | Verify a single 'ScriptCheckItem', returning @Nothing@ on success or
-- @Just errmsg@ on failure.  Error strings are byte-identical to the old
-- serial loop in 'validateSingleTx'.
verifyScriptCheckItem :: ScriptFlags -> ScriptCheckItem -> Maybe String
verifyScriptCheckItem scriptFlags ScriptCheckItem{..} =
  case verifyScriptWithFlags scriptFlags sciTx sciInputIdx
         sciPrevScript sciPrevValue sciSpentAmounts sciSpentScripts of
    Left err    -> Just $ "script verify failed (input " ++ show sciInputIdx
                        ++ "): " ++ err
    Right False -> Just $ "script verify failed (input " ++ show sciInputIdx
                        ++ "): script returned false"
    Right True  -> Nothing

-- | Run a batch of pre-resolved script checks IN PARALLEL, returning the FIRST
-- failure (if any) — exactly as the equivalent serial loop would have rejected.
--
-- This mirrors Bitcoin Core's @CheckInputScripts@ collecting a
-- @std::vector<CScriptCheck>@ that @ConnectBlock@ dispatches across the
-- @CCheckQueue@ worker pool (validation.cpp:2581-2584): the non-script
-- consensus gates and the UTXO mutation sequence already ran serially and in
-- order; only the embarrassingly-parallel, CPU-bound script verification is
-- fanned out here.
--
-- Semantics are IDENTICAL to the serial loop:
--   * same 'verifyScriptWithFlags' arguments + 'ScriptFlags';
--   * the SigCache (read inside @cachedVerify*@ via thread-safe
--     'atomicModifyIORef'') makes concurrent evaluation safe — a concurrent
--     miss simply re-runs the deterministic verify, never changing the verdict;
--     only positive results are cached, so the accept/reject decision is the
--     same whether checks run serially or in parallel;
--   * ANY single input check failing rejects the whole block, with the same
--     per-input error string;
--   * only non-coinbase inputs are ever in the batch (the caller skips the
--     coinbase and skips this batch entirely under assumevalid).
--
-- Parallelism is bounded by the RTS @-N@ capability count (haskoin runs
-- @-threaded -N4@).
--
-- SPARK-FIZZLE FIX (2026-06-22): the previous body
--   @let results = parMap rseq (verifyScriptCheckItem f) checks
--    in case [err | Just err <- results] of ...@
-- created one spark per check but then scanned @results@ with a lazy list
-- comprehension.  The main thread's left-to-right scan forced each
-- @Maybe String@ to WHNF *as it walked the list*, racing ahead of the
-- worker HECs and evaluating most elements itself before the corresponding
-- spark could be converted — classic spark fizzle (@+RTS -s@ showed
-- @converted@ ≈ 0, @fizzled@ ≈ N), so the verifies ran serially on one HEC.
--
-- The fix forces the ENTIRE parallel pass to complete BEFORE the sequential
-- scan, and chunks the checks to amortize spark overhead:
--
--   1. @withStrategy (parListChunk chunkSize rdeepseq) results@ sparks one
--      task per chunk; @rdeepseq@ fully evaluates each chunk's @Maybe String@
--      list to NF (which runs every @verifyScriptCheckItem@ in it).
--   2. @withStrategy@ returns the value only after the strategy's own
--      traversal has driven the spark conversions, so the parallel work is
--      genuinely handed to the worker HECs (they convert the sparks) rather
--      than being stolen back by a racing consumer.  Binding the forced
--      list to @results'@ and scanning THAT means the scan reads
--      already-evaluated thunks.
--
-- Semantics are unchanged: @rdeepseq@ on @Maybe String@ forces the same
-- @verifyScriptCheckItem@ result it always did (its WHNF — @Just@/@Nothing@ —
-- already required running the full verify; deep-forcing the wrapped @String@
-- is harmless and total).  ANY single input failing still rejects the whole
-- block, and the first-failure scan below preserves the lowest-index error
-- string byte-for-byte.  The only behavioural difference is that ALL checks
-- are now evaluated (the old lazy scan could short-circuit after the first
-- failure) — this is a non-observable change to the verdict (the same
-- @Left err@ for the same first failure) and matches Core's @CCheckQueue@,
-- which likewise dispatches the whole batch.
runScriptChecksParallel :: ScriptFlags -> [ScriptCheckItem] -> Either String ()
runScriptChecksParallel _scriptFlags [] = Right ()
runScriptChecksParallel scriptFlags checks =
  let -- Chunk size amortizes per-spark overhead while keeping enough chunks to
      -- fill the (N4) HECs on script-heavy blocks.  Powers of ~16-64 are the
      -- usual sweet spot; 32 keeps thousands-of-input blocks well-distributed.
      chunkSize = 32
      results :: [Maybe String]
      results = map (verifyScriptCheckItem scriptFlags) checks
      -- Force the whole parallel pass to COMPLETE before scanning.  The
      -- strategy traversal converts the per-chunk sparks across the HECs and
      -- only returns once every element is in NF, so the scan below never
      -- races ahead of (and thus fizzles) a spark.
      results' = withStrategy (parListChunk chunkSize rdeepseq) results
  in case [err | Just err <- results'] of
       []      -> Right ()
       (err:_) -> Left err

-- | Run a batch of pre-resolved script checks SERIALLY, first failure wins.
-- Used by 'validateSingleTx' so its standalone contract (and every existing
-- caller/test) is byte-for-byte unchanged.
runScriptChecksSerial :: ScriptFlags -> [ScriptCheckItem] -> Either String ()
runScriptChecksSerial scriptFlags = go
  where
    go []     = Right ()
    go (c:cs) = case verifyScriptCheckItem scriptFlags c of
                  Just err -> Left err
                  Nothing  -> go cs

-- | Validate all non-coinbase transactions in a block.
-- Returns the total fees collected.
-- 'skipScripts' = True means per-input script evaluation is not performed
-- (assumevalid ancestor path).  UTXO existence, value checks, and structural
-- transaction validation still run.
-- KNOWN PITFALL: Handles intra-block spending by updating UTXO map as we go.
--
-- PARALLEL SCRIPT VERIFICATION (W105 G16 / CCheckQueue parity): the serial fold
-- below runs every NON-SCRIPT consensus gate (structural CheckTransaction,
-- per-input + running-sum MoneyRange, value-in >= value-out, accumulated-fee
-- range) AND the intra-block UTXO map maintenance IN ORDER, exactly as before —
-- but it no longer runs the per-input script interpreter inline.  Instead each
-- tx's resolved per-input script checks are collected
-- ('validateSingleTxCollect'), and after the fold the whole block's checks are
-- dispatched ONCE across the RTS capabilities ('runScriptChecksParallel').
-- Under assumevalid ('skipScripts' = True) no checks are collected or run,
-- identical to before.  This is Core's @ConnectBlock@ collecting @vChecks@ and
-- handing them to the @CCheckQueue@ (validation.cpp:2581-2584).
validateBlockTransactions :: ConsensusFlags -> Bool -> [Tx] -> Map OutPoint TxOut
                         -> Either String Word64
validateBlockTransactions flags skipScripts txns initialUtxoMap = do
  -- Process transactions sequentially, updating UTXO map for intra-block
  -- spending, accumulating the per-input script checks (in block order) for a
  -- single parallel dispatch after the fold.
  let go :: (Word64, Map OutPoint TxOut, [[ScriptCheckItem]]) -> Tx
         -> Either String (Word64, Map OutPoint TxOut, [[ScriptCheckItem]])
      go (accFees, utxoMap, accChecks) tx = do
        -- Economic + structural validation runs in order against the current
        -- (intra-block-aware) UTXO view; script checks are NOT run here — they
        -- are returned resolved for the deferred parallel pass.
        (fee, txChecks) <- validateSingleTxCollect flags utxoMap tx
        -- Accumulated fee range check mirrors Bitcoin Core validation.cpp::ConnectBlock:
        --   nFees += txfee; if (!MoneyRange(nFees)) → "bad-txns-accumulated-fee-outofrange"
        let accFees' = accFees + fee
        when (accFees' > maxMoney) $
          Left "bad-txns-accumulated-fee-outofrange"
        -- Add outputs from this tx to UTXO map for subsequent txs in block
        let txid = computeTxId tx
            newUtxos = Map.fromList
              [ (OutPoint txid (fromIntegral i), txout)
              | (i, txout) <- zip [0..] (txOutputs tx)
              ]
            -- Remove spent outputs
            spentOutpoints = map txInPrevOutput (txInputs tx)
            utxoMap' = foldr Map.delete (Map.union newUtxos utxoMap) spentOutpoints
        return (accFees', utxoMap', txChecks : accChecks)

  (totalFees, _, revChecks) <- foldM go (0, initialUtxoMap, []) (tail txns)  -- Skip coinbase

  -- Deferred parallel script verification.  All non-script gates and UTXO
  -- mutations above ran serially and in order; the block's script checks are
  -- now dispatched once across the RTS capabilities.  Under assumevalid we
  -- skip this entirely (the old `unless skipScripts` behaviour).  `revChecks`
  -- is in reverse block order; `concat . reverse` restores block order so the
  -- first-failure error string matches the lowest-indexed failing input/tx —
  -- byte-identical to the old serial loop's rejection.
  unless skipScripts $
    runScriptChecksParallel (consensusFlagsToScriptFlags flags)
                            (concat (reverse revChecks))

  return totalFees

-- | Validate a single non-coinbase transaction.
-- Returns the fee (inputs - outputs) on success.
-- When 'skipScripts' is True the per-input script loop is not executed;
-- all other structural and value checks still run (matching Bitcoin Core
-- behaviour under assumevalid).
--
-- Bitcoin Core reference: @validation.cpp ConnectBlock → CheckInputScripts
-- → VerifyScript@. The 'flags' argument is mapped to 'ScriptFlags' via
-- 'consensusFlagsToScriptFlags' (MANDATORY set: P2SH, DERSIG, NULLDUMMY,
-- CLTV, CSV, WITNESS, TAPROOT). 'spentAmounts' / 'spentScripts' are the
-- prevout amount/scriptPubKey lists required by BIP-341 sighash for
-- Taproot inputs.
validateSingleTx :: ConsensusFlags -> Bool -> Map OutPoint TxOut -> Tx
                 -> Either String Word64
validateSingleTx flags skipScripts utxoMap tx = do
  -- Economic + structural validation (always runs), plus the resolved per-input
  -- script-check work items for this tx.  This is the SAME path the block
  -- connect fold uses; here we run the collected checks SERIALLY so this
  -- function's standalone behaviour and error strings are byte-for-byte
  -- unchanged for its existing callers (checkTxInputsConnect, tests).
  (fee, txChecks) <- validateSingleTxCollect flags utxoMap tx
  -- Script / signature verification:
  -- When skipScripts is True (assumevalid ancestor path) we skip this step,
  -- matching Bitcoin Core's ConnectBlock behaviour. Otherwise, every input's
  -- scriptSig + witness must satisfy its scriptPubKey under the consensus
  -- ScriptFlags for this height.
  unless skipScripts $
    runScriptChecksSerial (consensusFlagsToScriptFlags flags) txChecks
  return fee

-- | Economic + structural validation of a single non-coinbase transaction,
-- returning the fee (inputs - outputs) AND the resolved per-input script-check
-- work items (NOT yet executed).  Splitting the resolution/economic checks
-- from the script execution lets 'validateBlockTransactions' run the per-tx
-- economic gates + UTXO maintenance serially and in order while deferring the
-- (independent, CPU-bound) script verification to a single parallel pass.
--
-- The economic checks and their error strings are byte-for-byte the same as
-- the prior inline implementation in 'validateSingleTx':
--   * 'validateTransaction' (structural CheckTransaction);
--   * missing prevout -> "Missing UTXO: ..." (HARD failure, never skipped);
--   * per-input + running-sum MoneyRange -> "bad-txns-inputvalues-outofrange";
--   * value-in >= value-out -> "Outputs exceed inputs".
--
-- W159 BUG-17 / W160 BUG-16: the SigCache lives one level deeper, inside
-- @cachedVerifyMsgLax@ / @cachedVerifySchnorr@ in Haskoin.Script, keyed on the
-- actual per-input @(sighash, pubkey, sig)@ triple — matching Core's
-- @SignatureCache::ComputeEntryECDSA@ (src/script/sigcache.cpp:39-49).
validateSingleTxCollect :: ConsensusFlags -> Map OutPoint TxOut -> Tx
                        -> Either String (Word64, [ScriptCheckItem])
validateSingleTxCollect flags utxoMap tx = do
  -- First, run context-free validation (structure checks always run)
  validateTransaction tx

  -- Then validate inputs exist in UTXO set and collect prev TxOuts.
  -- Resolve all prevouts up-front so we can build the per-tx
  -- spentAmounts / spentScripts lists required for BIP-341 sighash.
  prevOuts <- forM (txInputs tx) $ \inp ->
    case Map.lookup (txInPrevOutput inp) utxoMap of
      Nothing      -> Left $ "Missing UTXO: " ++ show (txInPrevOutput inp)
      Just prevOut -> Right prevOut

  -- Validate per-input amounts and accumulate totalIn.
  -- Bitcoin Core consensus/tx_verify.cpp::CheckTxInputs:
  --   MoneyRange(coin.out.nValue) + MoneyRange(nValueIn) each iteration
  --   → "bad-txns-inputvalues-outofrange".
  -- Word64 wraps silently on overflow; the running-sum check catches it.
  let checkInputs !acc [] = Right acc
      checkInputs !acc (out:outs) =
        let v    = txOutValue out
            acc' = acc + v
        in if v > maxMoney || acc' > maxMoney
             then Left "bad-txns-inputvalues-outofrange"
             else checkInputs acc' outs
  totalIn <- checkInputs 0 prevOuts

  let inputValues = map txOutValue prevOuts
      totalOut    = sum $ map txOutValue (txOutputs tx)

  -- Inputs must cover outputs (always checked, even under assumevalid)
  when (totalIn < totalOut) $ Left "Outputs exceed inputs"

  -- Build the resolved per-input script-check work items (in input order).
  -- These are NOT run here; the caller runs them (serially in
  -- 'validateSingleTx', or in parallel across the whole block in
  -- 'validateBlockTransactions').  The arguments captured per input are exactly
  -- those the prior inline serial loop passed to 'verifyScriptWithFlags':
  -- (tx, idx, prevout script, prevout value, this-tx spentAmounts,
  -- this-tx spentScripts).  The witness is read inside 'verifyScriptWithFlags'
  -- from @txWitness tx !! idx@, so no witness field is needed here (the old
  -- loop's @_witStack@ was already unused).
  let spentAmounts = inputValues
      spentScripts = map txOutScript prevOuts
      txChecks =
        [ ScriptCheckItem
            { sciTx           = tx
            , sciInputIdx     = idx
            , sciPrevScript   = txOutScript prevOut
            , sciPrevValue    = txOutValue prevOut
            , sciSpentAmounts = spentAmounts
            , sciSpentScripts = spentScripts
            }
        | (idx, prevOut) <- zip [0..] prevOuts
        ]

  return (totalIn - totalOut, txChecks)

-- | Connect-time @Consensus::CheckTxInputs@ composite — the economic verdict
-- a non-coinbase tx must pass when it is connected into a block at
-- @nSpendHeight@ (bitcoin-core/src/consensus/tx_verify.cpp:164-214).
--
-- This is a THIN PURE wrapper over the existing 'validateSingleTx' that
-- restores the ONE check 'validateSingleTx' structurally cannot make: the
-- coinbase-maturity rule.  'validateSingleTx' takes a @Map OutPoint TxOut@
-- view which carries no per-coin height / is-coinbase metadata, so it omits
-- maturity and would FALSE-ACCEPT a premature coinbase spend.  The live
-- connect path ('applyBlock', Consensus.hs:4644-4649) reads that metadata
-- from the 'UTXOEntry' view; we take the SAME @Map OutPoint UTXOEntry@ view
-- and inline that exact maturity loop, then delegate the rest
-- (missing/spent inputs, per-input + running-sum MoneyRange, nValueIn >=
-- valueOut, structural CheckTransaction) to 'validateSingleTx'.
--
-- We do NOT re-implement value-in>=value-out, MoneyRange, or the missing-input
-- check here — those run inside 'validateSingleTx' exactly as the connect path
-- and mempool path use them.  We pass @skipScripts = True@ so a script failure
-- cannot mask the ECONOMIC verdict this function isolates (Core's CheckTxInputs
-- runs before CheckInputScripts).
--
-- Reject reasons follow Core's @bad-txns-*@ tokens:
--   * missing/spent input               -> @bad-txns-inputs-missingorspent@
--   * premature coinbase spend           -> @bad-txns-premature-spend-of-coinbase@
--     (re-mapped from 'validateSingleTx'\''s twin "Coinbase not yet mature")
--   * per-input / running-sum MoneyRange -> @bad-txns-inputvalues-outofrange@
--   * nValueIn < valueOut                -> @bad-txns-in-belowout@
--     ('validateSingleTx' returns "Outputs exceed inputs"; re-mapped here)
-- On success returns the fee (nValueIn - valueOut).
checkTxInputsConnect :: Network -> ConsensusFlags -> Word32
                     -> Map OutPoint UTXOEntry -> Tx
                     -> Either String Word64
checkTxInputsConnect net flags spendHeight utxoView tx = do
  -- (1) HaveInputs: resolve EVERY prevout from the UTXOEntry view; an
  --     omitted prevout models a missing/spent input. Core: tx_verify.cpp:166.
  entries <- forM (txInputs tx) $ \inp ->
    case Map.lookup (txInPrevOutput inp) utxoView of
      Nothing -> Left "bad-txns-inputs-missingorspent"
      Just e  -> Right e

  -- (2) Coinbase maturity — the SAME loop the live connect path runs at
  --     applyBlock Consensus.hs:4644-4649 (Core tx_verify.cpp:177-180:
  --     coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY).
  --     validateSingleTx cannot see ueCoinbase/ueHeight, so it is inlined here.
  let maturity = fromIntegral (netCoinbaseMaturity net) :: Word32
      immature = [ () | e <- entries
                      , ueCoinbase e
                      , spendHeight - ueHeight e < maturity ]
  unless (null immature) $
    Left "bad-txns-premature-spend-of-coinbase"

  -- (3) Delegate the remaining economic checks (missing-again no-op,
  --     per-input + running-sum MoneyRange, nValueIn >= valueOut) AND the
  --     structural CheckTransaction to the SAME validateSingleTx the connect
  --     and mempool paths use. skipScripts=True isolates the economic verdict.
  let txOutView = Map.map ueOutput utxoView
  fee <- case validateSingleTx flags True txOutView tx of
           Right f  -> Right f
           -- Normalize validateSingleTx's twin to the Core bad-txns-* token.
           Left "Outputs exceed inputs" -> Left "bad-txns-in-belowout"
           Left err -> Left err
  return fee

--------------------------------------------------------------------------------
-- Witness Commitment Validation
--------------------------------------------------------------------------------

-- | Full witness-malleation check — mirrors Core's CheckWitnessMalleation
-- (validation.cpp:3870-3916).
--
-- When @expectCommitment@ is True (segwit active):
--   * If a witness-commitment output exists in the coinbase (last match wins):
--       1. Coinbase vin[0] witness stack must be exactly [32-byte nonce].
--          Reject: \"bad-witness-nonce-size\" (Core: BLOCK_MUTATED).
--       2. Compute BlockWitnessMerkleRoot (coinbase wtxid = 0x00..00).
--       3. Verify SHA256d(witness_root || nonce) == commitment[6..37].
--          Reject: \"bad-witness-merkle-match\".
--   * If NO commitment output: fall through to unexpected-witness check.
-- When @expectCommitment@ is False (pre-segwit) OR no commitment found:
--   * Any transaction with witness data → reject \"unexpected-witness\".
--
-- Reference: Bitcoin Core validation.cpp:3870-3916, consensus/validation.h:147-165.
checkWitnessMalleation :: Bool -> Block -> Either String ()
checkWitnessMalleation expectCommitment block
  | expectCommitment, Just commitOut <- mCommitOut = do
      -- Gate G3: coinbase vin[0] witness stack must be exactly 1 item of 32 bytes.
      -- Reference: Core validation.cpp:3880-3885.
      let coinbaseStack = case txWitness coinbase of
            (s:_) -> s
            []    -> []
      unless (length coinbaseStack == 1 && BS.length (head coinbaseStack) == 32) $
        Left "bad-witness-nonce-size"
      let witnessNonce = head coinbaseStack
          -- Gate G4: BlockWitnessMerkleRoot — coinbase wtxid is all zeros.
          -- Reference: Core consensus/merkle.cpp:76-85.
          wtxids = TxId (Hash256 (BS.replicate 32 0))
                   : map computeWtxId (tail (blockTxns block))
          witnessRoot = computeMerkleRoot wtxids
          -- Gate G5: SHA256d(witness_root || witness_nonce).
          -- Reference: Core validation.cpp:3892.
          expected = doubleSHA256 (BS.append (getHash256 witnessRoot) witnessNonce)
          -- commitment is bytes [6..37] of the output script.
          commitment = BS.take 32 (BS.drop 6 (txOutScript commitOut))
      -- Gate G6: compare.
      -- Reference: Core validation.cpp:3893.
      unless (Hash256 commitment == expected) $
        Left "bad-witness-merkle-match"
  | otherwise = do
      -- Gate G7: no commitment (pre-segwit, or segwit-active but no commitment
      -- output) — no transaction may carry witness data.
      -- Reference: Core validation.cpp:3905-3913.
      when (any txHasWitness (blockTxns block)) $
        Left "unexpected-witness"
  where
    coinbase = head (blockTxns block)
    commitPrefix = BS.pack [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
    -- Gate G1/G2: find the LAST coinbase output matching the commitment prefix.
    -- Minimum size 38 bytes (MINIMUM_WITNESS_COMMITMENT).
    -- Reference: Core consensus/validation.h:147-165.
    mCommitOut =
      let matches = filter (\txo ->
            BS.length (txOutScript txo) >= 38
            && BS.isPrefixOf commitPrefix (txOutScript txo)
            ) (txOutputs coinbase)
      in if null matches then Nothing else Just (last matches)

-- | True if a transaction has any non-empty witness stack item.
-- Mirrors Core CTransaction::HasWitness() — any input with a non-empty
-- scriptWitness.stack counts as having witness data.
-- Reference: Bitcoin Core primitives/transaction.h HasWitness().
txHasWitness :: Tx -> Bool
txHasWitness tx = any (not . null) (txWitness tx)

-- | Validate the witness commitment in a SegWit block.
-- Kept for backward-compatibility of the exported API; delegates to
-- 'checkWitnessMalleation' with expectCommitment=True.
-- NOTE: callers that need the full Core gate set (including unexpected-witness
-- for the no-commitment case) should call 'checkWitnessMalleation' directly.
validateWitnessCommitment :: Block -> Either String ()
validateWitnessCommitment = checkWitnessMalleation True

-- | Compute the witness transaction ID (wtxid).
-- For coinbase, wtxid is all zeros.
-- For other transactions, it's the hash of the full serialization including witness.
computeWtxId :: Tx -> TxId
computeWtxId tx = TxId (doubleSHA256 (encode tx))

--------------------------------------------------------------------------------
-- Block Connection and Disconnection
--------------------------------------------------------------------------------

-- | Connect a block to the chain state, updating UTXO set and indexes,
-- and writing per-block undo data for future rewinds.
--
-- The @spentUtxos@ argument carries the full Core-format @Coin@
-- (TxOut + height + coinbase flag) for every non-coinbase input the
-- block consumes; it is the same map @Sync.buildUTXOMap@ produces
-- just before validation, sourced from 'getUTXOCoin' against the
-- 'PrefixUTXO' keyspace. We persist those Coins as a 'BlockUndo'
-- record so 'disconnectBlock' (and the @dumptxoutset@ rollback dance)
-- can restore the spent UTXO entries with their original height and
-- coinbase flag intact — a byte-identical round-trip.
--
-- Reference: bitcoin-core/src/validation.cpp @ConnectBlock@ — Core
-- populates @CTxUndo::vprevout@ with full @Coin@ data including
-- height + fCoinBase, then writes a parallel @rev*.dat@ undo entry
-- via @WriteBlockUndo@. @DisconnectBlock@ reads it and restores
-- Coins via @view.AddCoin(..)@. We piggy-back the equivalent record
-- on the same RocksDB write batch so the UTXO mutation and the undo
-- record commit atomically; partial commits on shutdown can never
-- desync them.
connectBlock :: HaskoinDB -> Network -> Block -> Word32
             -> Map OutPoint Coin  -- ^ Spent UTXOs (prevouts being consumed
                                   --   by non-coinbase inputs in this block);
                                   --   carries Core-format height + coinbase
                                   --   metadata for byte-identical round-trip
                                   --   through 'disconnectBlock'.
             -> IO (Either String ())
connectBlock db net block height spentUtxos = do
  -- W97/W99-G18 P0 fix: this is now a thin alias for 'connectBlockAt'.
  -- The pre-fix version silently fell back to an unchecked variant when
  -- 'connectBlockAt' rejected the G1 (prevHash mismatch) or G19
  -- (missing prevout) gates — that unchecked variant overwrote the
  -- PrefixBestBlock pointer unconditionally, so a peer that sent a
  -- side-branch MBlock whose prevHash ≠ BestBlock could corrupt the
  -- chain-tip pointer.  Reference (Core: bitcoin-core/src/validation.cpp
  -- AcceptBlock @4298+): the tip pointer is only advanced through
  -- 'ActivateBestChain' after a clean 'ConnectTip' on a block that
  -- extends the active chain.  Side-branch blocks must go through a
  -- reorg or be persisted as inactive — they NEVER unilaterally
  -- overwrite BestBlock.
  --
  -- All callers MUST pattern-match the Either:
  --   * MBlock peer handler — Left → log + misbehaving(InvalidBlock)
  --   * submitBlock active-tip arm — Left is structurally impossible
  --     (the if-guard above ensures parent==tip) and should surface
  --     as an error if it ever fires
  --   * reindex-chainstate replay — Left → log + stop (the on-disk
  --     replay is sequential by height; a gate failure means data
  --     corruption)
  --   * dumptxoutset rollback replay — Left → bail and surface as
  --     "chainstate may be inconsistent"
  connectBlockAt db net block height spentUtxos

-- | Connect a block to the chain state with the full Bitcoin Core
-- ConnectBlock gate set (validation.cpp:2295-2673):
--
--   * G1  hashPrevBlock == view.GetBestBlock()  (line 2333).  We compare
--         the block's prev-hash against the on-disk BestBlock pointer.
--         When BestBlock is unset (fresh DB) we treat it as the implicit
--         pre-genesis hash uint256() — matching Core's @view.GetBestBlock()@
--         which returns null on an empty view.
--   * G2  Genesis-block special case (line 2339-2343): when the block hash
--         equals the network's genesis hash, skip the per-tx connect loop
--         and only stamp the new BestBlock pointer.  Genesis coinbases are
--         unspendable in Core, but more importantly genesis carries no
--         prevouts so the buildUTXOMap caller would feed in an empty map.
--   * G19 SpendCoin existence — for every non-coinbase input we look up
--         the prevout in @spentUtxos@ first, then on disk, and fail fast
--         if neither has it.  Core's @UpdateCoins@ does @assert(is_spent)@
--         (validation.cpp:2007); without this gate connectBlock would
--         silently issue a BatchDelete on a key that does not exist,
--         producing an undo record with @TxUndo { tuPrevOutputs = [] }@
--         which subsequently breaks @disconnectBlock@'s size-equality
--         gate (W92 Gate 7).
--
-- Other gates that Core runs inside ConnectBlock (CheckBlock recheck,
-- BIP-30, BIP-68 sequence locks, CheckTxInputs, sigops cap, bad-cb-amount,
-- script verification) are wired upstream in 'validateFullBlockIO' on the
-- IBD path and in 'applyBlockToCache' / 'applyBlock' on the cache path.
-- haskoin's split-validation design routes the gates through a single
-- function each so both arms share coverage; the gates were verified
-- consistent in the W93 audit.
--
-- Returns 'Right ()' on success or 'Left err' on a structural mismatch
-- (G1, G19).  G2 is silent — the genesis fast-path returns 'Right ()'.
--
-- Reference: bitcoin-core/src/validation.cpp:2295-2673 (ConnectBlock)
-- + :1999-2012 (UpdateCoins).
connectBlockAt :: HaskoinDB -> Network -> Block -> Word32
               -> Map OutPoint Coin
               -> IO (Either String ())
connectBlockAt db net block height spentUtxos = do
  let bh = computeBlockHash (blockHeader block)
      prevHash = bhPrevBlock (blockHeader block)
      txns = blockTxns block

  -- W93 Gate G2: genesis-block fast-path.
  -- We compare on the canonical genesis hash for this network (rather
  -- than a height==0 heuristic) so a regtest block at height 0 that is
  -- NOT the genesis hash still goes through the full per-tx pipeline.
  let genesisHash = computeBlockHash (blockHeader (netGenesisBlock net))
  if bh == genesisHash
    then do
      -- Genesis: just stamp BestBlock + header index entries.
      --
      -- W162: the height-index key payload is the bare 4-byte
      -- big-endian height ('toBE32 height'), NOT 'encode (toBE32 …)'.
      -- 'Data.Serialize.encode' on a 'ByteString' prepends an 8-byte
      -- Word64 length tag, so 'encode (toBE32 h)' produced a 12-byte
      -- payload — a key that 'Storage.getBlockHeight' / 'putBlockHeight'
      -- (which use the bare 'toBE32 height') can never read back.  The
      -- old form silently wrote phantom keys; this matches the
      -- canonical 'batchPutBlockHeight' encoding in Storage.hs.
      --
      -- 2026-05-24 fix: also persist the full block body (PrefixBlockData)
      -- in the same atomic batch.  The pre-fix code only wrote the
      -- header / height / best-block pointer; the body was the
      -- responsibility of a separate 'putBlock' callsite — but the only
      -- such caller in the live tree was 'Sync.handleBlockMessage' in
      -- the (dead) BlockDownloader pipeline.  Every block reaching the
      -- running daemon through the MBlock arm therefore left
      -- 'PrefixBlockData' empty, so 'getblock' could never serve a
      -- locally-stored block.  Folding 'putBlock' into the connect
      -- batch fixes the universal "Block not found" symptom and keeps
      -- body + chainstate atomic across crashes — a crash between two
      -- separate writes could otherwise diverge them.  See
      -- _bug-reports/haskoin-chain-state-inconsistency-2026-05-24.md.
      writeBatch db (WriteBatch
        [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode bh)
        , BatchPut (makeKey PrefixBlockHeader (encode bh))
                   (encode (blockHeader block))
        , BatchPut (makeKey PrefixBlockHeight (toBE32 height))
                   (encode bh)
        , BatchPut (makeKey PrefixBlockData (encode bh))
                   (encode block)
        ])
      return (Right ())
    else do
      -- W93 Gate G1: hashPrevBlock == GetBestBlock().
      -- Skipped on a fresh DB (BestBlock = Nothing) so the test harness
      -- and IBD genesis-bootstrap path keep working — same semantics as
      -- Core's @view.GetBestBlock() == uint256()@ when the chainstate
      -- has never been written.
      mBest <- getBestBlockHash db
      let prevMismatch = case mBest of
            Just b  -> b /= prevHash
            Nothing -> False  -- fresh DB; let caller bootstrap.
      if prevMismatch
        then return $ Left $
          "connectBlockAt " <> show bh
          <> ": block's prevHash " <> show prevHash
          <> " does not equal current BestBlock " <> show mBest
          <> " (Core G1 — validation.cpp:2333)"
        else do
          -- W93 Gate G19: every non-coinbase input must have a resolvable
          -- prevout — in the passed-in spentUtxos map, on disk, or
          -- created by an earlier transaction in THIS block.
          -- This mirrors Core's @assert(is_spent)@ in UpdateCoins.
          let inputs = [ inp | tx <- drop 1 txns, inp <- txInputs tx ]
              -- W163: outpoints created by this block's own transactions.
              -- A later tx may spend an output of an earlier tx in the
              -- SAME block (chained / intra-block spend); that prevout is
              -- in neither the pre-block UTXO set nor 'spentUtxos' (which
              -- is built from the DB), so G19 must accept it here too —
              -- otherwise every block containing a chained transaction is
              -- falsely rejected "missing prevout". This wedged the W163
              -- assumeUTXO recovery: block 944184 (the first block to
              -- connect) has an intra-block spend at tx index 1. The
              -- WriteBatch below already resolves such an outpoint
              -- correctly (BatchPut then BatchDelete on the same key).
              blockCreated = Map.fromList
                [ (OutPoint txid (fromIntegral i), ())
                | (txid, tx) <- zip (map computeTxId txns) txns
                , (i, _) <- zip [(0 :: Int) ..] (txOutputs tx)
                ]
          missingInputs <- foldM (\acc inp ->
              case acc of
                Just _  -> return acc  -- short-circuit
                Nothing
                  | Map.member (txInPrevOutput inp) blockCreated ->
                      return Nothing
                  | otherwise ->
                  case Map.lookup (txInPrevOutput inp) spentUtxos of
                    Just _  -> return Nothing
                    Nothing -> do
                      mc <- getUTXOCoin db (txInPrevOutput inp)
                      case mc of
                        Just _  -> return Nothing
                        Nothing -> return (Just (txInPrevOutput inp))
            ) (Nothing :: Maybe OutPoint) inputs
          case missingInputs of
            Just op -> return $ Left $
              "connectBlockAt " <> show bh
              <> ": missing prevout " <> show op
              <> " (Core G19 — validation.cpp:2007 assert(is_spent))"
            Nothing -> do
              -- All gates passed; build and commit the WriteBatch.
              let txids = map computeTxId txns
                  mkTxInUndo inp = case Map.lookup (txInPrevOutput inp) spentUtxos of
                    Just c  -> Just (TxInUndo (coinTxOut c)
                                              (coinHeight c)
                                              (coinIsCoinbase c))
                    Nothing -> Nothing  -- caller's responsibility; logged below
                  mkTxUndo tx = TxUndo
                    { tuPrevOutputs = mapMaybe mkTxInUndo (txInputs tx) }
                  blockUndo = BlockUndo
                    { buTxUndo = map mkTxUndo (drop 1 txns)  -- skip coinbase
                    }
                  undoData = mkUndoData bh height prevHash blockUndo
                  undoKey  = BS.cons 0x10 (encode bh)
                  coinbaseFlag txIdx = txIdx == (0 :: Int)
                  ops = concat
                    [ [ BatchPut (makeKey PrefixUTXO (encode (OutPoint txid (fromIntegral i))))
                                 (encode (Coin { coinTxOut = txout
                                               , coinHeight = height
                                               , coinIsCoinbase = coinbaseFlag txIdx }))
                      | (txIdx, txid, tx) <- zip3 [0..] txids txns
                      , (i, txout) <- zip [0..] (txOutputs tx)
                      , not (isUnspendable (txOutScript txout))
                      ]
                    , [ BatchDelete (makeKey PrefixUTXO (encode (txInPrevOutput inp)))
                      | tx <- drop 1 txns
                      , inp <- txInputs tx
                      ]
                    , [ BatchPut undoKey (encode undoData) ]
                    , [ BatchPut (makeKey PrefixTxIndex (encode txid))
                                 (encode (TxLocation bh (fromIntegral i)))
                      | (i, txid) <- zip [0..] txids
                      ]
                    , [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode bh)
                      , BatchPut (makeKey PrefixBlockHeader (encode bh))
                                 (encode (blockHeader block))
                      -- W162: bare 'toBE32 height' (4-byte BE) so this
                      -- key matches 'Storage.getBlockHeight'.  See the
                      -- genesis fast-path note above — 'encode' on a
                      -- ByteString prepends an 8-byte length tag.
                      , BatchPut (makeKey PrefixBlockHeight (toBE32 height))
                                 (encode bh)
                      -- 2026-05-24 fix: persist the full block body in
                      -- the same atomic batch.  Pre-fix, only the
                      -- 'Sync.handleBlockMessage' downloader wrote
                      -- PrefixBlockData — but that pipeline is dead
                      -- code; every block reaching the live MBlock arm
                      -- (Main.hs:2041) went through 'connectBlock' and
                      -- the body was never persisted.  As a result
                      -- 'getblock' always missed on local storage and
                      -- fell back to the Bitcoin Core proxy.  Folding
                      -- 'putBlock' into the connect batch closes the
                      -- "Block not found" hole AND keeps body +
                      -- chainstate atomic across crashes.  See
                      -- _bug-reports/haskoin-chain-state-inconsistency-2026-05-24.md.
                      , BatchPut (makeKey PrefixBlockData (encode bh))
                                 (encode block)
                      ]
                    ]
              writeBatch db (WriteBatch ops)
              return (Right ())

-- | Result of a 'disconnectBlock' / 'disconnectBlockAt' call, mirroring
-- Bitcoin Core's 'DisconnectResult' enum
-- (bitcoin-core/src/validation.h:451-455).
--
--  * 'DisconnectOk'      — clean rewind; UTXO set is bit-for-bit equal to
--                         the pre-connect state.
--  * 'DisconnectUnclean' — rewind completed, but the UTXO set was
--                         inconsistent with the block being disconnected
--                         (e.g. a created output was already gone from
--                         the cache, or an unspent output was
--                         overwritten).  Core treats this as recoverable
--                         (no abort) but logs it; flush is still safe.
--  * 'DisconnectFailed'  — the rewind itself could not be performed
--                         (missing undo data, malformed undo shape,
--                         AccessByTxid sibling-lookup failure on an
--                         old-format undo record).  The caller MUST
--                         leave the on-disk view in an indeterminate
--                         state and refuse to advance.
data DisconnectResult
  = DisconnectOk
  | DisconnectUnclean
  | DisconnectFailed
  deriving (Show, Eq)

-- | BIP-30 exception heights — the two mainnet blocks at heights 91722
-- and 91812 contain transactions that overwrite earlier outputs that
-- are NOT fully spent at the moment they are overwritten.  Core
-- skips the "transaction output mismatch" UNCLEAN flag for the
-- coinbase of these blocks during disconnect to avoid spurious
-- UNCLEAN noise (validation.cpp:2201-2202).
--
-- Returns @Just expectedBlockHash@ when @height@ is one of the two
-- known exception heights; the caller checks against the actual block
-- hash to harden against false positives (the height alone is
-- insufficient since regtest/testnet/sidechains can reuse those
-- heights with completely different content).
bip30ExceptionHeight :: Word32 -> Maybe BlockHash
bip30ExceptionHeight 91722 = Just $
  hashFromHex "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
bip30ExceptionHeight 91812 = Just $
  hashFromHex "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
bip30ExceptionHeight _     = Nothing

-- | Restore the UTXO of a single TxIn from an undo record.
--
-- Mirrors @ApplyTxInUndo@ (validation.cpp:2149-2175):
--
--   * If the coin is already present in the view, the disconnect is
--     marked UNCLEAN (overwrite of an unspent output, but the AddCoin
--     call below proceeds with @possible_overwrite = true@).
--   * If the undo record has @tuHeight == 0@ — the "missing-metadata"
--     marker for legacy undo records that only stored height/coinbase
--     on the FINAL spend of a tx's outputs — we fall back to
--     @AccessByTxid@: look up a sibling output (same txid, any index)
--     that is currently unspent in the view, and copy its height +
--     coinbase flag onto the restored coin.  If no sibling exists,
--     the rewind fails (we genuinely lost the metadata).
--   * Otherwise the coin is added directly.
--
-- Pure: this function emits the 'BatchOp' it would have written so
-- the caller can accumulate all ops into a single 'WriteBatch' (the
-- Pattern D multi-block atomicity invariant — partial reorgs cannot
-- exist on disk).
--
-- Reference: bitcoin-core/src/validation.cpp:2149-2175.
applyTxInUndo
  :: HaskoinDB
  -> Map OutPoint Coin   -- ^ Pending coins from THIS disconnect (block-internal
                         --   restores that sibling lookups need to see before
                         --   they hit disk).  Keyed by full OutPoint.
  -> OutPoint
  -> TxInUndo
  -> IO (Either String (BatchOp, DisconnectResult, Maybe Coin))
                         -- ^ The Right tuple carries the batch op to write,
                         --   the per-input disconnect result, and the
                         --   resolved Coin (used to seed the sibling map for
                         --   later inputs that may share the same txid).
applyTxInUndo db pending out undo = do
  -- Gate 1: HaveCoin → overwrite-of-unspent detection.  Match Core's
  -- semantics: only set UNCLEAN; AddCoin still proceeds with
  -- @possible_overwrite = !fClean@.
  -- Reference: validation.cpp:2153.
  existing <- case Map.lookup out pending of
    Just c  -> return (Just c)
    Nothing -> getUTXOCoin db out
  let overwrite = case existing of
        Just _  -> True
        Nothing -> False
      preStatus = if overwrite then DisconnectUnclean else DisconnectOk

  -- Gate 2: tuHeight == 0 → missing-metadata legacy fallback.
  -- AccessByTxid scans the view for any unspent sibling output of the
  -- same txid and copies its height + coinbase flag.
  -- Reference: validation.cpp:2155-2166.
  resolved <- if tuHeight undo == 0
    then do
      sib <- findSibling db pending (opTxid out)
      case sib of
        Nothing -> return Nothing
        Just (sibH, sibCb) -> return $ Just undo
          { tuHeight   = sibH
          , tuCoinbase = sibCb
          }
    else return (Just undo)

  case resolved of
    Nothing -> return $ Left $
      "ApplyTxInUndo: missing undo metadata for " <> show out
      <> " and no unspent sibling output (AccessByTxid) — undo record "
      <> "predates connectBlock and cannot be rewound."
    Just u  ->
      let coin = Coin { coinTxOut      = tuOutput u
                      , coinHeight     = tuHeight u
                      , coinIsCoinbase = tuCoinbase u
                      }
          -- Gate 5: AddCoin with possible_overwrite = !fClean.  We are
          -- batch-oriented, so the BatchPut implicitly is an
          -- "overwrite-allowed" upsert (RocksDB Put semantics).
          -- The UNCLEAN flag is what the upstream caller propagates.
          op = BatchPut (makeKey PrefixUTXO (encode out)) (encode coin)
      in return $ Right (op, preStatus, Just coin)
  where
    opTxid (OutPoint t _) = t

-- | Find an unspent sibling output of @txid@ (any index) in either the
-- pending-restore map or the on-disk UTXO set.  Mirrors @AccessByTxid@
-- (bitcoin-core/src/coins.cpp:106-117) which scans the view for any
-- coin keyed by @txid@ regardless of @vout@ index.
--
-- We cap the on-disk scan at index 0..15 to keep the worst-case cost
-- bounded; Core does the same in spirit by exploiting the
-- @Coin@ height + coinbase flag living on every output of the same
-- tx (an output of any index will do).  The vast majority of legacy
-- undo records that need this fallback have vout 0 or 1 unspent.
findSibling :: HaskoinDB -> Map OutPoint Coin -> TxId
            -> IO (Maybe (Word32, Bool))
findSibling db pending txid = do
  -- 1) Check the pending-restore map first (block-internal restorations
  --    landed earlier in the same disconnect).
  let pendingHit =
        [ (coinHeight c, coinIsCoinbase c)
        | (OutPoint t _, c) <- Map.toList pending
        , t == txid
        ]
  case pendingHit of
    (h, cb) : _ -> return $ Just (h, cb)
    [] -> scan (0 :: Word32)
  where
    scan idx
      | idx > 15 = return Nothing
      | otherwise = do
          mc <- getUTXOCoin db (OutPoint txid idx)
          case mc of
            Just c  -> return $ Just (coinHeight c, coinIsCoinbase c)
            Nothing -> scan (idx + 1)

-- | Disconnect a block from the chain state — legacy single-arg
-- signature.  Internally delegates to 'disconnectBlockAt' with the
-- height resolved from the on-disk block-height index.  Existing
-- callers (Rpc.hs disconnectChainTo, test harness) keep working
-- unchanged; new callers that already have a height should prefer
-- 'disconnectBlockAt' to avoid the extra lookup and to feed in the
-- BIP-30 exception check.
--
-- Returns @Right ()@ for both 'DisconnectOk' and 'DisconnectUnclean'
-- (Core treats UNCLEAN as recoverable — it logs but does not abort
-- the rewind).  Returns @Left err@ only on 'DisconnectFailed'
-- (missing undo, malformed undo shape, sibling-recovery failure).
--
-- Reference: bitcoin-core/src/validation.cpp @DisconnectBlock@.
disconnectBlock :: HaskoinDB -> Block -> BlockHash -> IO (Either String ())
disconnectBlock db block prevHash = do
  let bh = computeBlockHash (blockHeader block)
  -- The persisted undo record carries the block height (udHeight); we
  -- peek it here so 'disconnectBlockAt' can drive the BIP-30
  -- exception check.  If undo is missing/checksum-bad,
  -- 'disconnectBlockAt' will surface the same Left this peek would.
  mUndo <- getUndoData db bh
  let height = maybe 0 udHeight mUndo
  r <- disconnectBlockAt db height block prevHash
  case r of
    Left err                -> return $ Left err
    Right DisconnectOk      -> return $ Right ()
    Right DisconnectUnclean -> return $ Right ()  -- Core: log but proceed.
    Right DisconnectFailed  -> return $ Left $
      "disconnectBlock " <> show bh <> ": rewind failed"

-- | Full-fidelity disconnect-block.  Carries the block height so the
-- BIP-30 exception heights (91722, 91812) can be honored, and returns
-- the discriminated 'DisconnectResult' so callers can distinguish
-- "rewound but UTXO set was inconsistent" from "clean rewind".
--
-- All gates from Bitcoin Core's @DisconnectBlock@ are enforced
-- (validation.cpp:2179-2247):
--
--   1.  ReadBlockUndo failure                → DisconnectFailed.
--   2.  vtxundo.size() + 1 != vtx.size()     → DisconnectFailed.
--   3.  BIP-30 exception heights 91722 / 91812 (with hash match) →
--       suppress coinbase UNCLEAN flag.
--   4.  Reverse-iterate transactions (i = nTx-1 down to 0).
--   5.  For each vout[o]: skip @IsUnspendable@ outputs (they were
--       never inserted by @connectBlock@; deleting them is a no-op
--       but Core's order matters for the UNCLEAN flag).
--   6.  Verify SpendCoin succeeds AND TxOut + height + coinbase
--       match — mismatch → UNCLEAN (suppressed for BIP-30 coinbase).
--   7.  For i > 0: vprevout.size() != vin.size() → DisconnectFailed.
--   8.  Reverse-iterate inputs (j = nIn down to 1, decrement first).
--   9.  ApplyTxInUndo per input (overwrite-detect + sibling-recovery).
--  10.  SetBestBlock(pprev) AFTER all undos applied.
--  11.  Return DisconnectOk if fClean else DisconnectUnclean.
--
-- The implementation accumulates all batch ops into a single
-- 'WriteBatch' so a crash mid-rewind cannot leave a partial UTXO
-- state on disk — same Pattern D invariant 'buildDisconnectBlockOps'
-- enforces for the multi-block reorg dispatcher.
--
-- Reference: bitcoin-core/src/validation.cpp:2179-2247.
disconnectBlockAt :: HaskoinDB -> Word32 -> Block -> BlockHash
                  -> IO (Either String DisconnectResult)
disconnectBlockAt db height block prevHash = do
  let bh   = computeBlockHash (blockHeader block)
      txns = blockTxns block
  -- Gate 1: ReadBlockUndo (with checksum) failure → FAILED.
  undoResult <- getUndoDataVerified db bh prevHash
  case undoResult of
    Left err -> return $ Left $
      "disconnectBlockAt " <> show bh <> ": " <> err
    Right undoData -> do
      let txUndos     = buTxUndo (udBlockUndo undoData)
          nonCoinbase = drop 1 txns
      -- Gate 2: undo-shape mismatch → FAILED.
      if length txUndos /= length nonCoinbase
        then return $ Left $
          "disconnectBlockAt " <> show bh
          <> ": undo data has " <> show (length txUndos)
          <> " TxUndo entries, but block has "
          <> show (length nonCoinbase)
          <> " non-coinbase txs"
        else do
          -- Gate 3: BIP-30 exception detection.  Suppress UNCLEAN for
          -- the coinbase of 91722 + 91812 — those blocks legally
          -- overwrite an earlier unspent coinbase.
          let enforceBIP30 = case bip30ExceptionHeight height of
                Just expected -> expected /= bh
                Nothing       -> True

              -- Build a per-tx pairing list so we can iterate in
              -- REVERSE tx order (Gate 4) AND keep undo indexing
              -- stable.  Index 0 == coinbase (no input undo); indexes
              -- 1..n correspond to txUndos[0..n-1].
              pairs :: [(Int, Tx, Maybe TxUndo)]
              pairs =
                (0, head txns, Nothing)
                : [ (i, t, Just u)
                  | (i, t, u) <- zip3 [1..] (tail txns) txUndos
                  ]

          cleanRef <- newIORef True
          opsRef   <- newIORef ([] :: [BatchOp])
          pendRef  <- newIORef (Map.empty :: Map OutPoint Coin)
          let bumpUnclean = writeIORef cleanRef False
              appendOps xs = modifyIORef' opsRef (++ xs)
              addPending p c = modifyIORef' pendRef (Map.insert p c)
          -- Gates 4-9: walk tx list in REVERSE.
          let walk :: [(Int, Tx, Maybe TxUndo)]
                   -> IO (Either String ())
              walk [] = return (Right ())
              walk ((i, tx, mUndo) : rest) = do
                let txHash      = computeTxId tx
                    isCoinbase  = i == 0
                    -- BIP-30 exception: suppress the per-output UNCLEAN
                    -- flag for the coinbase of grandfathered blocks.
                    -- Core sets is_bip30_exception only when is_coinbase
                    -- AND !fEnforceBIP30 (validation.cpp:2209).
                    bip30Exempt = isCoinbase && not enforceBIP30

                -- Gate 5+6: delete created outputs, with mismatch check.
                -- Iterate outputs in INDEX order to keep delete ops in
                -- the order they were created (Core uses forward index
                -- iteration inside each tx).
                forM_ (zip [0 :: Int ..] (txOutputs tx)) $ \(o, vout) ->
                  unless (isUnspendable (txOutScript vout)) $ do
                    let outp = OutPoint txHash (fromIntegral o)
                    -- SpendCoin equivalent: look up the on-disk coin
                    -- and verify it matches the block's stated output.
                    -- Reference: validation.cpp:2217-2222.
                    pending <- readIORef pendRef
                    existing <- case Map.lookup outp pending of
                      Just c  -> return (Just c)
                      Nothing -> getUTXOCoin db outp
                    let ok = case existing of
                          Nothing -> False  -- already gone (UNCLEAN)
                          Just c  ->
                               coinTxOut c == vout
                            && coinHeight c == height
                            && coinIsCoinbase c == isCoinbase
                    unless (ok || bip30Exempt) bumpUnclean
                    appendOps [ BatchDelete
                                  (makeKey PrefixUTXO (encode outp)) ]

                -- Gates 7-9: restore inputs (skipped for coinbase).
                case mUndo of
                  Nothing -> walk rest  -- coinbase has no input undo
                  Just txundo -> do
                    let inputs   = txInputs tx
                        prevouts = tuPrevOutputs txundo
                    -- Gate 7: vprevout.size() != vin.size() → FAILED.
                    if length prevouts /= length inputs
                      then return $ Left $
                        "disconnectBlockAt " <> show bh
                        <> ": tx " <> show i
                        <> " has " <> show (length inputs)
                        <> " inputs but undo has " <> show (length prevouts)
                        <> " prevouts"
                      else do
                        -- Gate 8: reverse-iterate inputs.
                        let pairsIn = reverse (zip inputs prevouts)
                        rIn <- applyInputs pairsIn
                        case rIn of
                          Left e  -> return (Left e)
                          Right _ -> walk rest

              applyInputs [] = return (Right ())
              applyInputs ((inp, tin) : rest) = do
                pending <- readIORef pendRef
                r <- applyTxInUndo db pending (txInPrevOutput inp) tin
                case r of
                  Left e -> return (Left e)
                  Right (op, status, mResolved) -> do
                    appendOps [op]
                    case mResolved of
                      Just c  -> addPending (txInPrevOutput inp) c
                      Nothing -> return ()
                    when (status == DisconnectUnclean) bumpUnclean
                    applyInputs rest

          walkResult <- walk (reverse pairs)
          case walkResult of
            Left e  -> return (Left e)
            Right () -> do
              ops   <- readIORef opsRef
              clean <- readIORef cleanRef
              -- Gate 10: SetBestBlock(pprev) after all undos applied.
              let bestOp = BatchPut
                             (makeKey PrefixBestBlock BS.empty)
                             (encode prevHash)
              writeBatch db (WriteBatch (ops ++ [bestOp]))
              -- Gate 11.
              return $ Right $ if clean then DisconnectOk else DisconnectUnclean

--------------------------------------------------------------------------------
-- Pure Batch Builders — Pattern D Multi-Block Atomicity
--------------------------------------------------------------------------------

-- | Maximum number of blocks that can be reorganised in a single
-- side-branch reorg.  Mirrors Core's @MAX_REORG_DEPTH@-equivalent
-- guard in @ActivateBestChain@ + the cross-impl cap landed in
-- nimrod / camlcoin / rustoshi during the 2026-05 Pattern D wave.
--
-- The cap is enforced on the SUM of the disconnect + connect lists:
-- a 50-block disconnect followed by a 60-block connect would be
-- rejected at 110 > 100.  Reorgs deeper than this surface as
-- "inconclusive" and require operator intervention
-- (@reconsiderblock@) — same shape Core uses when @ActivateBestChain@
-- bails on an oversized reorg.
maxReorgDepth :: Int
maxReorgDepth = 100

-- | Pure batch-op builder for a connect-block step.  Computes the
-- exact same RocksDB ops 'connectBlock' would write, but returns
-- them instead of invoking 'writeBatch'.  The companion 'BlockUndo'
-- record is included in the ops (PrefixUndo entry).
--
-- Caller responsibilities:
--   * @spentUtxos@ MUST contain a 'Coin' entry for every non-coinbase
--     prevout this block consumes (Core-format height + coinbase
--     metadata, sourced post-disconnect from a virtual overlay so
--     mid-reorg consistency holds).
--   * The block must already have passed full validation
--     ('validateFullBlockIO').
--
-- This is the building block for multi-block atomicity in
-- 'doSideBranchReorg': accumulate ops across the entire reorg
-- sequence and commit ONCE at the end.  Crash before the final
-- commit → on-disk state is unchanged → restart sees pre-reorg
-- chainstate, no partial reorg.
--
-- Reference: bitcoin-core/src/validation.cpp ConnectBlock +
-- Pattern D atomicity audit
-- (CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md).
buildConnectBlockOps :: Network -> Block -> Word32
                     -> Map OutPoint Coin
                     -> [BatchOp]
buildConnectBlockOps _net block height spentUtxos =
  let bh = computeBlockHash (blockHeader block)
      prevHash = bhPrevBlock (blockHeader block)
      txns = blockTxns block
      txids = map computeTxId txns
      mkTxInUndo inp = case Map.lookup (txInPrevOutput inp) spentUtxos of
        Just c  -> Just (TxInUndo (coinTxOut c)
                                  (coinHeight c)
                                  (coinIsCoinbase c))
        Nothing -> Nothing
      mkTxUndo tx = TxUndo
        { tuPrevOutputs = mapMaybe mkTxInUndo (txInputs tx) }
      blockUndo = BlockUndo
        { buTxUndo = map mkTxUndo (drop 1 txns)
        }
      undoData = mkUndoData bh height prevHash blockUndo
      undoKey  = BS.cons 0x10 (encode bh)
      coinbaseFlag txIdx = txIdx == (0 :: Int)
  in concat
       [ -- New UTXOs (skip provably-unspendable; same filter as
         -- 'connectBlock').
         [ BatchPut (makeKey PrefixUTXO (encode (OutPoint txid (fromIntegral i))))
                    (encode (Coin { coinTxOut = txout
                                  , coinHeight = height
                                  , coinIsCoinbase = coinbaseFlag txIdx }))
         | (txIdx, txid, tx) <- zip3 [0..] txids txns
         , (i, txout) <- zip [0..] (txOutputs tx)
         , not (isUnspendable (txOutScript txout))
         ]
       , -- Spent UTXOs (skip coinbase).
         [ BatchDelete (makeKey PrefixUTXO (encode (txInPrevOutput inp)))
         | tx <- drop 1 txns
         , inp <- txInputs tx
         ]
       , -- Per-block undo data (same key format as 'connectBlock').
         [ BatchPut undoKey (encode undoData) ]
       , -- Transaction index entries.
         [ BatchPut (makeKey PrefixTxIndex (encode txid))
                    (encode (TxLocation bh (fromIntegral i)))
         | (i, txid) <- zip [0..] txids
         ]
       , -- Chain state pointers (PrefixBestBlock + headers + height).
         -- W162: bare 'toBE32 height' key payload (4-byte BE), matching
         -- 'Storage.getBlockHeight' / 'batchPutBlockHeight'.  'encode'
         -- on a ByteString prepends an 8-byte length tag and would make
         -- the key unreadable — see the connectBlockAt notes above.
         --
         -- 2026-05-24 fix: include PrefixBlockData so the multi-block
         -- reorg batch ('doSideBranchReorg' → 'buildConnectChain')
         -- persists block bodies alongside the chainstate, matching the
         -- single-block 'connectBlockAt' path.  Without this, the body
         -- of a side-branch block that becomes the new active tip is
         -- lost.  See _bug-reports/haskoin-chain-state-inconsistency-2026-05-24.md.
         [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode bh)
         , BatchPut (makeKey PrefixBlockHeader (encode bh))
                    (encode (blockHeader block))
         , BatchPut (makeKey PrefixBlockHeight (toBE32 height))
                    (encode bh)
         , BatchPut (makeKey PrefixBlockData (encode bh))
                    (encode block)
         ]
       ]

-- | Pure batch-op builder for a disconnect-block step.  Computes the
-- exact same RocksDB ops 'disconnectBlock' would write, but returns
-- them instead of invoking 'writeBatch'.
--
-- Caller responsibilities:
--   * @undoData@ must already be loaded + checksum-verified
--     ('getUndoDataVerified').
--   * The /sanity/ check (TxUndo count == non-coinbase tx count)
--     is performed here and surfaces as 'Left' on mismatch.
--
-- Returns 'Right [BatchOp]' on success or 'Left err' on undo-shape
-- mismatch.  The caller accumulates the ops into a single
-- 'WriteBatch' for the multi-block reorg.
--
-- Reference: bitcoin-core/src/validation.cpp DisconnectBlock + the
-- Pattern D atomicity audit (single-batch reorg).
buildDisconnectBlockOps :: Block -> BlockHash -> UndoData
                        -> Either String [BatchOp]
buildDisconnectBlockOps block prevHash undoData =
  let txns = blockTxns block
      txUndos = buTxUndo (udBlockUndo undoData)
      nonCoinbase = drop 1 txns
  in if length txUndos /= length nonCoinbase
     then Left $
       "buildDisconnectBlockOps: undo data has "
       <> show (length txUndos)
       <> " TxUndo entries, but block has "
       <> show (length nonCoinbase)
       <> " non-coinbase txs"
     else
       let txids = map computeTxId txns
           restoreOps =
             [ BatchPut (makeKey PrefixUTXO (encode (txInPrevOutput inp)))
                        (encode (Coin { coinTxOut = tuOutput tin
                                      , coinHeight = tuHeight tin
                                      , coinIsCoinbase = tuCoinbase tin }))
             | (tx, txUndo) <- zip nonCoinbase txUndos
             , (inp, tin)   <- zip (txInputs tx) (tuPrevOutputs txUndo)
             ]
           removeOps =
             [ BatchDelete (makeKey PrefixUTXO (encode (OutPoint txid (fromIntegral i))))
             | (txid, tx) <- zip txids txns
             , (i, _) <- zip [0..] (txOutputs tx)
             ]
           bestBlockOp =
             [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode prevHash) ]
       in Right (restoreOps ++ removeOps ++ bestBlockOp)

--------------------------------------------------------------------------------
-- Header Chain Types
--------------------------------------------------------------------------------

-- | An entry in the header chain with computed metadata.
-- KNOWN PITFALL: header_tip vs chain_tip - track separately in DB.
-- Headers can be far ahead of validated blocks. Same DB key = data corruption.
--
-- 'ceSequenceId' mirrors Core's @CBlockIndex::nSequenceId@
-- (bitcoin-core/src/chain.h:149) and is the tiebreaker after
-- @nChainWork@ in 'CBlockIndexWorkComparator' — "earliest activatable
-- time wins" at equal chainwork.  Genesis uses 'seqIdBestChainFromDisk'
-- (== 0), entries reloaded from disk get 'seqIdBestChainFromDisk' as
-- well (they sit on the active chain), and live entries (added via
-- 'addHeader' / 'addSideBranchHeader') pull a fresh value from
-- 'hcSeqCounter' on insert.  Closes W101 BUG-8 by giving the sorted
-- candidate set a stable second-key so 'activateBestChain' can do an
-- O(log n) best-pick instead of an O(n²) full-map scan.
data ChainEntry = ChainEntry
  { ceHeader     :: !BlockHeader     -- ^ The raw 80-byte header
  , ceHash       :: !BlockHash       -- ^ Block hash (computed from header)
  , ceHeight     :: !Word32          -- ^ Height in the chain
  , ceChainWork  :: !Integer         -- ^ Cumulative proof-of-work
  , cePrev       :: !(Maybe BlockHash) -- ^ Previous block hash (for genesis: Nothing)
  , ceStatus     :: !BlockStatus     -- ^ Validation status
  , ceMedianTime :: !Word32          -- ^ Median time past for this block
  , ceSequenceId :: !Word64          -- ^ Activation-order tiebreaker (Core nSequenceId)
  } deriving (Show, Eq, Generic)

-- | Core's @SEQ_ID_BEST_CHAIN_FROM_DISK@ (bitcoin-core/src/chain.h:39).
-- Assigned to entries on the best chain when they are loaded from disk
-- (and to genesis at 'initHeaderChain' time).  Wins ties against
-- 'seqIdInitFromDisk' under 'CBlockIndexWorkComparator'.
seqIdBestChainFromDisk :: Word64
seqIdBestChainFromDisk = 0

-- | Core's @SEQ_ID_INIT_FROM_DISK@ (bitcoin-core/src/chain.h:40).
-- Assigned to non-best-chain entries when they are loaded from disk;
-- new live entries from 'addHeader' / 'addSideBranchHeader' get a
-- monotonically incremented value strictly greater than this one.
seqIdInitFromDisk :: Word64
seqIdInitFromDisk = 1

-- | Sorted-set key for the candidate-tip set.  Mirrors Core's
-- @CBlockIndexWorkComparator@ (node/blockstorage.cpp:174-192):
--   * Primary: highest 'ceChainWork' wins.
--   * Secondary: at equal work, lowest 'ceSequenceId' wins
--     (\"earliest activatable\").
--   * Final tiebreaker: 'BlockHash' identity.
--
-- The 'Set' is ordered by Haskell's derived 'Ord' (ascending on
-- 'Integer' then 'Word64' then 'BlockHash').  We store
-- @sequenceId@ as @maxBound - seq@ so that \"max\" in the Set
-- corresponds to \"lowest actual seq\" — letting @Set.lookupMax@
-- return the same element Core's @std::set::rbegin()@ would.
data CandidateKey = CandidateKey
  { ckWork   :: !Integer   -- ^ Cumulative chain work (higher = better)
  , ckSeqInv :: !Word64    -- ^ maxBound - ceSequenceId (higher = older = better)
  , ckHash   :: !BlockHash -- ^ Identity tiebreaker
  } deriving (Show, Eq, Ord)

-- | Build a 'CandidateKey' for an entry.
mkCandidateKey :: ChainEntry -> CandidateKey
mkCandidateKey ce = CandidateKey
  { ckWork   = ceChainWork ce
  , ckSeqInv = maxBound - ceSequenceId ce
  , ckHash   = ceHash ce
  }

-- | In-memory header chain with concurrent access support.
-- Uses TVars for thread-safe access from multiple threads.
data HeaderChain = HeaderChain
  { hcEntries     :: !(TVar (Map BlockHash ChainEntry)) -- ^ All known entries by hash
  , hcTip         :: !(TVar ChainEntry)                 -- ^ Current best tip
  , hcHeight      :: !(TVar Word32)                     -- ^ Height of current tip
  , hcByHeight    :: !(TVar (Map Word32 BlockHash))     -- ^ Height -> hash index
  , hcInvalidated :: !(TVar (Set.Set BlockHash))        -- ^ Manually invalidated blocks (via invalidateblock RPC)
  , hcCandidates  :: !(TVar (Set.Set CandidateKey))     -- ^ Sorted candidate tips (Core's setBlockIndexCandidates)
  , hcSeqCounter  :: !(TVar Word64)                     -- ^ Monotonic counter for ceSequenceId on live inserts
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
-- Collects timestamps starting from @blockHash@ itself (inclusive).
-- Used for locktime validation (BIP-113) and block-header time-too-old gate.
--
-- Reference: bitcoin-core/src/chain.h:233-244 (GetMedianTimePast)
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

-- | Compute the MTP of a *new* entry that has not yet been inserted into the
-- entries map.  Takes the parent hash (to walk ancestors) and the new entry's
-- own timestamp.  The result is the median of (newTimestamp : up-to-10-ancestors).
--
-- This is used by 'addHeader' and 'addSideBranchHeader' to store the correct
-- 'ceMedianTime' on the new entry so that child blocks can read it directly
-- without recomputing from the map.
-- Reference: bitcoin-core/src/chain.h:233-244
computeEntryMtp :: Map BlockHash ChainEntry -> BlockHash -> Word32 -> Word32
computeEntryMtp entries parentHash newTimestamp =
  let ancestors = collectTimestamps entries parentHash 10
      timestamps = newTimestamp : ancestors
      sorted = sort timestamps
  in sorted !! (length sorted `div` 2)
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
-- | Calculate the expected difficulty bits for a new block header.
-- Takes the parent 'ChainEntry' and the *candidate* header so that the
-- testnet min-difficulty rule (timestamp > prev + 20 min) can be
-- evaluated correctly.
--
-- Reference: bitcoin-core/src/pow.cpp GetNextWorkRequired()
difficultyAdjustment :: Network -> Map BlockHash ChainEntry -> ChainEntry -> BlockHeader -> Word32
difficultyAdjustment net entries entry newHeader
  -- Regtest: no retargeting
  | netPowNoRetargeting net = bhBits (ceHeader entry)

  -- Not at retarget boundary
  | (ceHeight entry + 1) `mod` netRetargetInterval net /= 0 =
      if netAllowMinDiffBlocks net
        -- Testnet: apply the 20-minute min-difficulty rule by consulting
        -- the new header's timestamp.  This is 'testnetExpectedBits',
        -- NOT a blanket pass — a header inside the 20-minute window still
        -- must match the last non-min-diff block's target.
        -- Reference: bitcoin-core/src/pow.cpp:95-115
        then testnetExpectedBits net entries entry newHeader
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
             -- Use Int64 arithmetic to match Core's int64_t subtraction.
             -- Word32 subtraction wraps on time-warped timestamps; Int64 does not.
             -- Reference: bitcoin-core/src/pow.cpp line 56
             let actualTime :: Int64
                 actualTime = fromIntegral (bhTimestamp (ceHeader lastEntry))
                            - fromIntegral (bhTimestamp (ceHeader firstEntry))
                 -- Clamp to [targetTimespan/4, targetTimespan*4]
                 -- Reference: bitcoin-core/src/pow.cpp lines 57-60
                 minTime :: Int64
                 minTime = fromIntegral (netPowTargetTimespan network) `div` 4
                 maxTime :: Int64
                 maxTime = fromIntegral (netPowTargetTimespan network) * 4
                 clampedTime :: Int64
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
--
-- P2-2: 'hcCandidates' is seeded with the genesis entry: it is the
-- only validated chain tip at startup, so 'activateBestChain' has a
-- non-empty candidate pool from the first instant (mirrors Core,
-- which inserts the genesis 'CBlockIndex' into
-- 'setBlockIndexCandidates' inside @LoadChainTip@).  'hcSeqCounter'
-- starts at 'seqIdInitFromDisk + 1' so the next live insert gets
-- @2@ (strictly greater than the disk-init values @0@ and @1@) —
-- preserving the comparator invariant that disk-loaded entries
-- always rank ahead of live entries at equal work.
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
        , ceSequenceId = seqIdBestChainFromDisk
        }
  entriesVar <- newTVarIO (Map.singleton genesisHash genesisEntry)
  tipVar <- newTVarIO genesisEntry
  heightVar <- newTVarIO 0
  byHeightVar <- newTVarIO (Map.singleton 0 genesisHash)
  invalidatedVar <- newTVarIO Set.empty
  candidatesVar <- newTVarIO (Set.singleton (mkCandidateKey genesisEntry))
  seqCounterVar <- newTVarIO (seqIdInitFromDisk + 1)
  return HeaderChain
    { hcEntries = entriesVar
    , hcTip = tipVar
    , hcHeight = heightVar
    , hcByHeight = byHeightVar
    , hcInvalidated = invalidatedVar
    , hcCandidates = candidatesVar
    , hcSeqCounter = seqCounterVar
    }

--------------------------------------------------------------------------------
-- Header Validation and Insertion
--------------------------------------------------------------------------------

-- | Add a header to the chain after validation.
-- Returns Left with error message on failure, Right with entry on success.
--
-- 'minPowChecked' mirrors Bitcoin Core's @min_pow_checked@ flag in
-- @AcceptBlockHeader@ (validation.cpp:4229-4232).  Pass 'False' for
-- headers received from peers (MHeaders / MBlock handlers) so that the
-- too-little-chainwork gate fires; pass 'True' only when the caller has
-- already verified sufficient chainwork externally (e.g. IBD after the
-- chain has crossed the threshold).
--
-- Validation order mirrors Bitcoin Core's
-- 'ContextualCheckBlockHeader' (validation.cpp:4080-4121):
--  1. PoW check (context-free)
--  2. Timestamp > MTP of previous 11 blocks (time-too-old)
--  3. BIP94 timewarp check at difficulty-adjustment boundaries (time-timewarp-attack)
--  4. Timestamp <= now + 2h (time-too-new, anti-DoS)
--  5. Difficulty bits match expected target (bad-diffbits)
--  6. Checkpoint verification
--  7. min_pow_checked / too-little-chainwork (W97 G8, Core 4229-4232)
--
-- The future-time gate is anti-DoS: without it a peer can announce a
-- header chain whose timestamps are far in the future, which passes
-- PoW + MTP + difficulty (the timestamps are internally consistent so
-- all checks pass), and pollutes 'hcEntries' until manually pruned.
-- Reference: bitcoin-core/src/validation.cpp:4108-4110.
addHeader :: Network -> HeaderChain -> BlockHeader -> Bool -> IO (Either String ChainEntry)
addHeader net hc header minPowChecked =
  -- Default (production) path: read the wall clock for the +2h future-time
  -- gate.  Byte-for-byte identical to the original behaviour.
  addHeaderAt net hc header minPowChecked Nothing

-- | 'addHeader' with an INJECTABLE current time for the +2h future-time gate
-- (Gate 3 / @time-too-new@).  @mNow@ of 'Nothing' reads the wall clock via
-- 'getPOSIXTime' (the production path 'addHeader' uses); @Just t@ overrides it
-- with @t@ (POSIX seconds, Int64) so a differential harness can drive the
-- @time-too-new@ boundary deterministically WITHOUT touching the wall clock.
-- The override changes NOTHING about the gate logic — it only fixes the value
-- of @now@ that Core's @ContextualCheckBlockHeader@ reads from
-- @GetAdjustedTime()@ (validation.cpp:4108).  All other gates are unaffected.
-- Default-preserving: every production caller goes through 'addHeader' (mNow =
-- Nothing) and observes the wall-clock behaviour exactly as before.
addHeaderAt :: Network -> HeaderChain -> BlockHeader -> Bool -> Maybe Int64
            -> IO (Either String ChainEntry)
addHeaderAt net hc header minPowChecked mNow = do
  let hash = computeBlockHash header
      prevHash = bhPrevBlock header
  entries <- readTVarIO (hcEntries hc)
  -- Wall-clock for the +2h future-time gate.  Read once per header so
  -- batch-acceptance does not see a sliding cutoff inside one call.
  -- Use Int64 to match Core's int64_t and avoid Word32 overflow near 2106.
  -- Reference: bitcoin-core/src/chain.h:29 (MAX_FUTURE_BLOCK_TIME is int64_t)
  now <- case mNow of
           Just t  -> pure t
           Nothing -> (round <$> getPOSIXTime) :: IO Int64

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
            -- Gate 1: Timestamp > MTP of previous 11 blocks (time-too-old).
            -- Reference: bitcoin-core/src/validation.cpp:4092-4093
            let mtp = medianTimePast entries prevHash
            if bhTimestamp header <= mtp
              then return $ Left "time-too-old"
            -- Gate 2: BIP94 timewarp check at difficulty-adjustment boundaries.
            -- Only applies when enforce_BIP94 is set (testnet4, regtest w/ BIP94).
            -- The first block of each 2016-block interval must not have a timestamp
            -- more than MAX_TIMEWARP (600s) earlier than the previous block.
            -- Reference: bitcoin-core/src/validation.cpp:4097-4104
            else if netEnforceBIP94 net
                    && height `mod` netRetargetInterval net == 0
                    && (fromIntegral (bhTimestamp header) :: Int64)
                         < (fromIntegral (bhTimestamp (ceHeader parent)) :: Int64) - maxTimewarp
              then return $ Left "time-timewarp-attack"
            -- Gate 3: Timestamp <= now + MAX_FUTURE_BLOCK_TIME (time-too-new).
            -- Reference: bitcoin-core/src/validation.cpp:4108-4110
            else if (fromIntegral (bhTimestamp header) :: Int64) > now + maxFutureBlockTime
              -- +2h future-time gate.  Header timestamp must not exceed our
              -- adjusted-network time + 2 hours.  A peer who keeps sending such
              -- headers is misbehaving and the caller should ban / disconnect them.
              then return $ Left "time-too-new"
              else do
                -- Gate 4: Difficulty bits match expected target (bad-diffbits).
                -- For testnet the expected bits from difficultyAdjustment already
                -- incorporates the 20-minute min-difficulty rule — no additional
                -- override is needed here.
                -- Reference: bitcoin-core/src/validation.cpp:4088-4089
                let expectedBits = difficultyAdjustment net entries parent header
                    difficultyOk  = bhBits header == expectedBits

                if not difficultyOk
                  then return $ Left "bad-diffbits"
                  else do
                    -- Gate 5: Checkpoint verification
                    let checkpoints = buildCheckpoints net
                    case verifyCheckpoint checkpoints height hash of
                      Left (ChainErrCheckpoint h expected actual) ->
                        return $ Left $ "Checkpoint mismatch at height " ++ show h ++
                                       ": expected " ++ show expected ++ " got " ++ show actual
                      Left err -> return $ Left $ "Checkpoint error: " ++ show err
                      Right () -> do
                        -- Compute MTP of the new entry itself (inclusive of its own
                        -- timestamp).  This is the value a child block will use when
                        -- looking up prevCe.ceMedianTime in connectChain.
                        -- Pre-fix ceMedianTime stored the *parent's* MTP here, which
                        -- was one block behind — connectChain saw MTP(grandparent)
                        -- instead of MTP(parent) and the BIP-113 locktime cutoff was
                        -- one block stale.
                        -- Reference: bitcoin-core/src/chain.h:233-244 GetMedianTimePast()
                        let newEntryMtp = computeEntryMtp entries prevHash (bhTimestamp header)
                        -- Compute metadata
                        let work = cumulativeWork (ceChainWork parent) header

                        -- Gate 7: too-little-chainwork (W97 G8 + W99 G5).
                        -- Core enforces nMinimumChainWork through the
                        -- headerssync.cpp PRESYNC machine: a peer's whole header
                        -- chain is tallied in a temporary structure and committed
                        -- only once its TOTAL work clears the threshold; Core also
                        -- passes min_pow_checked=true outright when the headers
                        -- extend a chain already past nMinimumChainWork.
                        --
                        -- haskoin has no PRESYNC machine.  The pre-fix code gated
                        -- every header on its OWN cumulative work, which is
                        -- unsatisfiable during a from-genesis sync: header 1's
                        -- cumulative work is far below the mainnet threshold, so it
                        -- was rejected "too-little-chainwork", every later header in
                        -- the batch then failed the parent lookup, and the sync
                        -- wedged ("Unconnecting headers" forever).  The bug stayed
                        -- latent because a populated chainstate never re-runs the
                        -- height-1 path — only a genuinely empty DB exposes it.
                        --
                        -- Fix: enforce the gate only once our own best chain has
                        -- itself reached nMinimumChainWork (Core's "extending an
                        -- already-high-work chain" case).  During from-genesis
                        -- bootstrap the gate is skipped; a low-work header flood is
                        -- still bounded by the checkpoint set (Gate 5), PoW (Gate 3)
                        -- and diffbits (Gate 4).  A real PRESYNC machine is the
                        -- principled follow-up.
                        tipWork <- ceChainWork <$> readTVarIO (hcTip hc)
                        if not minPowChecked
                             && tipWork >= netMinimumChainWork net
                             && work < netMinimumChainWork net
                          then return $ Left "too-little-chainwork"
                          else do
                            -- P2-2: allocate a fresh sequence ID under the same
                            -- STM transaction that inserts the entry.  Doing
                            -- the increment outside the atomic block would
                            -- race against a sibling 'addHeader' on a
                            -- different thread (Main.hs hands each peer its
                            -- own recv thread); two concurrent inserts could
                            -- otherwise hand out duplicate sequence IDs and
                            -- break the candidate-set ordering invariant.
                            -- Note that 'StatusHeaderValid' entries do NOT
                            -- enter 'hcCandidates' — Core's FindMostWorkChain
                            -- requires BLOCK_HAVE_DATA (validation.cpp:3140)
                            -- and a header-only entry has no body to connect.
                            -- The candidate insert happens once the body is
                            -- received and the entry transitions to
                            -- StatusValid (via 'addSideBranchHeader' on the
                            -- submitblock path; the live MBlock arm does not
                            -- currently transition in-memory status, so
                            -- 'activateBestChain' for IBD-style live receive
                            -- is a no-op — the tip advances via direct
                            -- 'connectBlockAt' writes instead).
                            seqId <- atomically $ do
                              n <- readTVar (hcSeqCounter hc)
                              writeTVar (hcSeqCounter hc) (n + 1)
                              return n
                            let entry = ChainEntry
                                  { ceHeader = header
                                  , ceHash = hash
                                  , ceHeight = height
                                  , ceChainWork = work
                                  , cePrev = Just prevHash
                                  , ceStatus = StatusHeaderValid
                                  , ceMedianTime = newEntryMtp
                                  , ceSequenceId = seqId
                                  }

                            -- Insert and potentially update tip atomically.
                            --
                            -- Pattern Y companion (CORE-PARITY-AUDIT
                            -- _reorg-via-submitblock-fleet-result-2026-05-05.md):
                            -- the @hcByHeight@ map is the height -> hash index for
                            -- the ACTIVE chain only.  Pre-fix this branch wrote it
                            -- unconditionally, so a side-branch header at the same
                            -- height as an active-chain block CLOBBERED the active
                            -- entry — the same shape camlcoin's pre-fix
                            -- @Sync.accept_header@ exhibited (camlcoin 22667c2) and
                            -- the cause nimrod's @putBlockIndexHashOnly@ split off
                            -- (nimrod 7196d41).  Bitcoin Core decouples these two
                            -- concerns: @BlockManager::AcceptBlock@ stores the
                            -- index entry regardless of which chain the block
                            -- lives on (validation.cpp), while @ActivateBestChain@
                            -- separately maintains the active-chain pointers.
                            --
                            -- Mirror Core: only update @hcByHeight@ when this
                            -- header becomes the new tip (strictly heavier work).
                            -- Side-branch headers go into @hcEntries@ (hash-keyed)
                            -- but leave the height index pointing at the active
                            -- chain.  Reorg-driven tip switches handle the
                            -- height-index rewrite.
                            atomically $ do
                              modifyTVar' (hcEntries hc) (Map.insert hash entry)
                              currentTip <- readTVar (hcTip hc)
                              when (work > ceChainWork currentTip) $ do
                                modifyTVar' (hcByHeight hc) (Map.insert height hash)
                                writeTVar (hcTip hc) entry
                                writeTVar (hcHeight hc) height

                            return $ Right entry

-- | Persist a side-branch header that has already been validated by the
-- caller (typically 'submitBlock' which runs the full
-- 'validateFullBlockIO' pipeline before deciding whether the block extends
-- the active tip or roots a side-branch).  This is the haskoin counterpart
-- of nimrod's 'putBlockIndexHashOnly' (nimrod 7196d41) and camlcoin's
-- 'register_side_branch_header' (camlcoin 22667c2).
--
-- Core reference: 'BlockManager::AcceptBlock' in @validation.cpp@ stores a
-- 'CBlockIndex' entry with cumulative chain work for every accepted block
-- regardless of which chain the block lives on; the active-chain pointers
-- are maintained separately by 'ActivateBestChain'.  Without this split,
-- a follow-up block whose parent lives on the side-branch cannot find its
-- parent in the in-memory index and is rejected as orphan even though the
-- parent is on disk.
--
-- This entry-point intentionally does NOT re-run difficulty / MTP / PoW /
-- checkpoint validation: the caller has already done that.  Re-running
-- 'addHeader' here would risk double-validation against an active-chain
-- MTP that doesn't apply to the side-branch path.  We do still run the
-- "already known" short-circuit so a duplicate submitblock is idempotent.
--
-- Returns 'Right entry' on insertion (or already-known), 'Left' on a
-- parent-lookup miss (caller must surface as orphan).
addSideBranchHeader :: HeaderChain -> BlockHeader -> IO (Either String ChainEntry)
addSideBranchHeader hc header = do
  let hash = computeBlockHash header
      prevHash = bhPrevBlock header
  entries <- readTVarIO (hcEntries hc)
  case Map.lookup hash entries of
    Just existing -> return $ Right existing
    Nothing -> case Map.lookup prevHash entries of
      Nothing -> return $ Left ("Unknown previous block: " ++ show prevHash)
      Just parent -> do
        let height = ceHeight parent + 1
            work   = cumulativeWork (ceChainWork parent) header
            -- MTP of the new entry itself (inclusive of its own timestamp).
            -- Uses computeEntryMtp so that child blocks reading ceMedianTime
            -- get the correct value rather than the off-by-one parent's MTP.
            -- Reference: bitcoin-core/src/chain.h:233-244
            newMtp = computeEntryMtp entries prevHash (bhTimestamp header)
        -- P2-2 + P2-3: allocate sequenceId AND insert into the candidate
        -- set in the same STM transaction.  Side-branch headers are
        -- validated by the caller before reaching this function
        -- ('submitBlock' runs the full pipeline first), so the entry
        -- already satisfies Core's BLOCK_HAVE_DATA + BLOCK_VALID_SCRIPTS
        -- precondition for being a candidate (validation.cpp:3140).
        -- Combining the sequence-ID handout, entries insert, and
        -- candidate insert under one 'atomically' keeps the three TVars
        -- mutually consistent against a concurrent 'invalidateBlock'
        -- or sibling 'addSideBranchHeader' on another thread.
        seqId <- atomically $ do
          n <- readTVar (hcSeqCounter hc)
          writeTVar (hcSeqCounter hc) (n + 1)
          return n
        let entry = ChainEntry
              { ceHeader     = header
              , ceHash       = hash
              , ceHeight     = height
              , ceChainWork  = work
              , cePrev       = Just prevHash
              , ceStatus     = StatusValid -- caller has run validateFullBlockIO
              , ceMedianTime = newMtp
              , ceSequenceId = seqId
              }
        atomically $ do
          modifyTVar' (hcEntries hc) (Map.insert hash entry)
          modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey entry))
        return $ Right entry

-- | Get the current chain tip.
getChainTip :: HeaderChain -> IO ChainEntry
getChainTip hc = readTVarIO (hcTip hc)

-- | Get the /validated/ chain tip — the highest block that has actually
-- been connected to the on-disk chainstate, not merely the highest header
-- whose PoW + chain-context checks passed.
--
-- These two can differ during header-first sync (Core's
-- @m_chainman->m_best_header@ vs @ActiveChain().Tip()@): a header may be
-- added to the in-memory 'HeaderChain' (mutating 'hcTip', 'hcHeight',
-- and 'hcByHeight' via 'addHeader') long before — or independently of —
-- its block body being validated and committed to the UTXO set via
-- 'connectBlock'.  Side-branch headers that win the chainwork race also
-- overwrite 'hcByHeight[h]' regardless of whether their bodies ever
-- connected, so reading the header chain to answer "what hash sits at
-- height h on the active validated chain?" is unsafe.
--
-- The validated tip is anchored to the on-disk 'PrefixBestBlock' pointer
-- that 'connectBlockAt' commits as part of its atomic write batch.
-- This helper resolves that pointer back to its 'ChainEntry' so chain-
-- state-reading RPCs ('getblockcount', 'getbestblockhash', the
-- chainstate-derived fields of 'getblockchaininfo') can serve a tip
-- that is internally consistent with 'getblockhash' / 'getblock'.
--
-- Fallback semantics:
--
--   * 'PrefixBestBlock' unset (fresh DB / pre-genesis bootstrap) —
--     return the in-memory 'hcTip'.  At this point the header chain
--     contains exactly the genesis 'ChainEntry' inserted by
--     'initHeaderChain', so 'hcTip' IS the (degenerate) validated tip.
--
--   * 'PrefixBestBlock' set but its hash is not in 'hcEntries' —
--     return 'hcTip' as a defensive fallback.  In a well-formed DB this
--     should never trigger; if it does the operator should run
--     @-reindex-chainstate@ to rebuild the header chain from disk.
--
-- Reference: bitcoin-core/src/rpc/blockchain.cpp keys every
-- chainstate-derived RPC field off @m_chainman->ActiveChain().Tip()@,
-- with @m_chainman->m_best_header@ reserved for the @"headers"@ field
-- of @getblockchaininfo@.
--
-- Companion fix: camlcoin commit 2a915b6 ("fix(rpc): getbestblockhash
-- returns validated tip not header tip").  See haskoin
-- _bug-reports/haskoin-chain-state-inconsistency-2026-05-24.md for the
-- full root-cause analysis (fuzzamoto IR-corpus replay surfaced the
-- divergence as @getblockhash(getblockcount) != getbestblockhash@).
getValidatedChainTip :: HaskoinDB -> HeaderChain -> IO ChainEntry
getValidatedChainTip db hc = do
  mBest <- getBestBlockHash db
  case mBest of
    Nothing -> readTVarIO (hcTip hc)
    Just bh -> do
      entries <- readTVarIO (hcEntries hc)
      case Map.lookup bh entries of
        Just ce -> return ce
        Nothing -> readTVarIO (hcTip hc)

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
  -- Pass minPowChecked=False: headers arrive from peers so we must enforce
  -- the too-little-chainwork gate (W97 G8).
  results <- mapM (\h -> addHeader (hsNetwork hs) (hsChain hs) h False) hdrs
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
      flags = consensusFlagsAtHeight net height

  -- Process each transaction, collecting TxUndo for non-coinbase txs
  txUndoListRef <- newTVarIO []

  -- W93 Gate (G9 / G16): accumulate fees across non-coinbase txs to catch
  -- `bad-txns-accumulated-fee-outofrange` (Core validation.cpp:2543-2547).
  -- We also need the total to enforce `bad-cb-amount` after the loop
  -- (Core validation.cpp:2611-2614, blockReward + fees >= coinbase value).
  feesRef <- newIORef (0 :: Word64)

  -- W93 Gate (G5 / G13): accumulate sigop cost across the block and reject
  -- if it exceeds MAX_BLOCK_SIGOPS_COST.  The cache-path applyBlock used
  -- to skip this entirely; without the gate, a maliciously-crafted block
  -- with > 80,000 weighted sigops would silently land in the UTXO set.
  -- Reference: bitcoin-core/src/validation.cpp:2568-2572.
  sigOpsRef <- newIORef (0 :: Int)
  utxoViewRef <- newIORef (Map.empty :: Map OutPoint TxOut)

  -- Process each transaction
  results <- forM (zip [0..] txns) $ \(txIdx :: Int, tx) -> do
    if isCoinbase tx
      then do
        -- Coinbase: only create outputs, no inputs to spend, no undo data.
        -- W93 Gate (G3): filter out provably-unspendable outputs (OP_RETURN
        -- and oversized scripts) just like Core's AddCoins (coins.cpp:91).
        -- The witness-commitment output is the most common case; without
        -- this filter the cache disagrees with the on-disk path
        -- (connectBlock already filters via 'isUnspendable').
        atomically $ forM_ (zip [0..] (txOutputs tx)) $ \(outIdx, txout) ->
          unless (isUnspendable (txOutScript txout)) $ do
            let op = OutPoint (computeTxId tx) (fromIntegral outIdx)
                entry = UTXOEntry txout height True False
            addUTXO cache op entry
        -- Track all coinbase outputs (including unspendable ones) in the
        -- in-flight view so subsequent intra-block spends and sigop
        -- counts see them.  Unspendable outputs are excluded from the
        -- UTXO set but still count for sigop computation if referenced.
        let cbId = computeTxId tx
        modifyIORef' utxoViewRef $ \m ->
          Map.union m $ Map.fromList
            [ (OutPoint cbId (fromIntegral i), txout)
            | (i, txout) <- zip [0 :: Int ..] (txOutputs tx)
            ]
        -- W93 Gate (G5 / G13): count coinbase sigops (legacy only;
        -- P2SH/witness require prevouts which coinbase has none of).
        -- Check against MAX_BLOCK_SIGOPS_COST immediately because the
        -- non-coinbase branch may never execute (coinbase-only block).
        view <- readIORef utxoViewRef
        let SigOpCost c = getTransactionSigOpCost tx view flags
        acc0 <- readIORef sigOpsRef
        let acc1 = acc0 + c
        if acc1 > maxBlockSigOpsCost
          then return $ Left "bad-blk-sigops"
          else do
            writeIORef sigOpsRef acc1
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
                -- W93 Gate (G7): per-input MoneyRange — Core CheckTxInputs
                -- (consensus/tx_verify.cpp:186-188) rejects coins whose
                -- value or accumulated input value would exceed MAX_MONEY.
                -- The original applyBlock skipped this entirely; a
                -- coin with value > MAX_MONEY (impossible on mainnet
                -- but possible on regtest / fuzz) would silently pass.
                let inputValues = map (txOutValue . ueOutput . snd) utxoEntries
                    sumInputs   = foldl' (+) 0 inputValues
                    badInputs   = any (> maxMoney) inputValues
                                   || sumInputs > maxMoney
                if badInputs
                  then return $ Left "bad-txns-inputvalues-outofrange"
                  else do
                    let valueOut = sum (map txOutValue (txOutputs tx))
                    -- W93 Gate (G8): nValueIn >= valueOut (Core
                    -- CheckTxInputs 196-199, "bad-txns-in-belowout").
                    if sumInputs < valueOut
                      then return $ Left "bad-txns-in-belowout"
                      else do
                        let txfee = sumInputs - valueOut
                        -- W93 Gate (G9): accumulated-fee-outofrange.
                        accFees0 <- readIORef feesRef
                        let accFees1 = accFees0 + txfee
                        if accFees1 > maxMoney
                          then return $ Left "bad-txns-accumulated-fee-outofrange"
                          else do
                            writeIORef feesRef accFees1
                            -- BIP68 sequence locks (Core 2549-2561).
                            sequenceLockResult <-
                              if enforceBIP68 && bip68VersionActive (txVersion tx)
                              then do
                                let prevHeights = [ueHeight entry | (_, entry) <- utxoEntries]
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
                                -- W93 Gate (G5 / G13): per-tx sigop cost.
                                view <- readIORef utxoViewRef
                                let SigOpCost c = getTransactionSigOpCost tx view flags
                                acc <- readIORef sigOpsRef
                                let acc' = acc + c
                                if acc' > maxBlockSigOpsCost
                                  then return $ Left "bad-blk-sigops"
                                  else do
                                    writeIORef sigOpsRef acc'
                                    -- Spend inputs
                                    forM_ utxoEntries $ \(op, entry) -> atomically $ do
                                      void $ spendUTXO cache op
                                      let inUndo = TxInUndo
                                            { tuOutput = ueOutput entry
                                            , tuHeight = ueHeight entry
                                            , tuCoinbase = ueCoinbase entry
                                            }
                                      modifyTVar' txInUndoListRef (inUndo :)

                                    -- W93 Gate (G4): filter unspendable
                                    -- outputs from the cache insertion
                                    -- (Core: AddCoins → skip IsUnspendable).
                                    atomically $ forM_ (zip [0..] (txOutputs tx)) $ \(outIdx, txout) ->
                                      unless (isUnspendable (txOutScript txout)) $ do
                                        let op = OutPoint (computeTxId tx) (fromIntegral outIdx)
                                            entry = UTXOEntry txout height False False
                                        addUTXO cache op entry

                                    -- Update the in-flight view (all outputs
                                    -- regardless of spendability — sigop
                                    -- counting for downstream txs needs them).
                                    let txid = computeTxId tx
                                        newView = Map.fromList
                                          [ (OutPoint txid (fromIntegral i), txout)
                                          | (i, txout) <- zip [0 :: Int ..] (txOutputs tx)
                                          ]
                                        spent = map (txInPrevOutput . fst) (zip (txInputs tx) utxoEntries)
                                    modifyIORef' utxoViewRef $ \m ->
                                      foldr Map.delete (Map.union newView m) spent

                                    -- Build TxUndo from collected TxInUndos
                                    txInUndos <- readTVarIO txInUndoListRef
                                    let txUndo = TxUndo { tuPrevOutputs = reverse txInUndos }
                                    atomically $ modifyTVar' txUndoListRef (txUndo :)
                                    return (Right ())

  case sequence results of
    Left err -> return (Left err)
    Right _ -> do
      -- W93 Gate (G6): bad-cb-amount — coinbase value out must not
      -- exceed blockReward + accumulated fees (Core 2611-2614).
      totalFees <- readIORef feesRef
      -- Network-aware subsidy (regtest halves at 150; mainnet/testnet 210000).
      -- See 'blockRewardForNet' — value-blind 'blockReward' mis-capped regtest.
      let maxCoinbase  = blockRewardForNet net height + totalFees
          cbValueOut   = sum (map txOutValue (txOutputs (head txns)))
      if cbValueOut > maxCoinbase
        then return $ Left $
          "bad-cb-amount: coinbase pays too much (actual=" ++ show cbValueOut
          ++ " vs limit=" ++ show maxCoinbase ++ ")"
        else do
          -- Build BlockUndo from collected TxUndos (reverse to match tx order)
          txUndos <- readTVarIO txUndoListRef
          let blockUndo = BlockUndo { buTxUndo = reverse txUndos }
              undoData = mkUndoData bh height prevHash blockUndo
          return $ Right undoData

-- | Unapply a block from the in-memory 'UTXOCache' using its undo
-- data (the cache analogue of 'disconnectBlockAt' on the on-disk DB).
--
-- Restores the UTXO set to its state before this block was applied:
--
--   * Iterate transactions in REVERSE order (matches Core's
--     @DisconnectBlock@ outer loop, validation.cpp:2205).
--   * For each tx, first remove every output created by the block
--     (skipping provably-unspendable scripts — they were never
--     inserted by @applyBlock@ / 'connectBlock'), then restore the
--     spent inputs via the undo record.  Within a single tx, the
--     remove-then-restore order lets a later block-internal spend
--     (a tx that consumes an output created earlier in the same
--     block) round-trip cleanly.
--   * Input restoration also walks INPUTS IN REVERSE
--     (Core: validation.cpp:2233 — @j = vin.size(); j > 0; --j@) so
--     that block-internal spend-of-same-block-prevout cases land in
--     bytewise-identical order.
--   * Undo records with @tuHeight == 0@ trigger an @AccessByTxid@
--     fallback (Core: validation.cpp:2155-2166): look up an unspent
--     sibling output (same txid, any vout) and copy its height +
--     coinbase flag.  This is what makes old-format undo records
--     (pre-mature-spend) replayable.
--
-- This function continues to return 'IO ()' rather than 'IO
-- DisconnectResult' to preserve every existing caller (Sync.hs, the
-- reorg pipeline, the dumptxoutset rollback dance).  UNCLEAN
-- mismatches are logged via 'cacheTouch' to the cache's STM state
-- but do not abort — same as Core's 'DISCONNECT_UNCLEAN' semantics.
--
-- Reference: bitcoin-core/src/validation.cpp:2179-2247
-- (@DisconnectBlock@), with the cache-only @ApplyTxInUndo@ adapted
-- to STM.
unapplyBlock :: UTXOCache -> Block -> UndoData -> IO ()
unapplyBlock cache block undo = do
  let txns = blockTxns block
      nonCoinbaseTxns = tail txns
      txUndos = buTxUndo (udBlockUndo undo)

  -- Walk transactions in REVERSE order.  Coinbase (i=0) is processed
  -- last — it has no input undo, only the output-remove step.
  let pairs :: [(Tx, Maybe TxUndo)]
      pairs = (head txns, Nothing)
            : [ (t, Just u) | (t, u) <- zip nonCoinbaseTxns txUndos ]

  forM_ (reverse pairs) $ \(tx, mUndo) -> do
    -- Remove outputs created by this tx.  Skip provably-unspendable
    -- outputs (same filter @applyBlock@ uses when creating them).
    -- Reference: validation.cpp:2213-2223 — Core skips
    -- @IsUnspendable@ outputs before the SpendCoin check.
    atomically $ forM_ (zip [0 :: Int ..] (txOutputs tx)) $ \(outIdx, vout) ->
      unless (isUnspendable (txOutScript vout)) $ do
        let op = OutPoint (computeTxId tx) (fromIntegral outIdx)
        void $ spendUTXO cache op

    -- Restore inputs (only for non-coinbase txs).  Walk inputs in
    -- REVERSE so block-internal restorations land bytewise-identical
    -- to Core (validation.cpp:2233).
    case mUndo of
      Nothing -> return ()
      Just txUndo ->
        let restorePairs = reverse $
              zip (txInputs tx) (tuPrevOutputs txUndo)
        in forM_ restorePairs $ \(inp, inUndo) -> do
          let op = txInPrevOutput inp
          -- AccessByTxid sibling-recovery for legacy undo records.
          inUndo' <- if tuHeight inUndo == 0
            then do
              let (OutPoint txid _) = op
              sib <- cacheFindSibling cache txid
              case sib of
                Just (h, cb) -> return inUndo { tuHeight = h, tuCoinbase = cb }
                Nothing      -> return inUndo  -- best-effort: keep height=0
            else return inUndo
          atomically $ do
            let entry = UTXOEntry
                  { ueOutput   = tuOutput inUndo'
                  , ueHeight   = tuHeight inUndo'
                  , ueCoinbase = tuCoinbase inUndo'
                  , ueSpent    = False
                  }
            addUTXO cache op entry

-- | Cache analogue of 'findSibling' — scans the cache's in-memory
-- entry map for an unspent output of @txid@ (any vout) and returns
-- its height + coinbase flag.  Used by 'unapplyBlock' to recover the
-- height/coinbase metadata of legacy undo records whose @tuHeight@
-- is the sentinel 0.
--
-- Reference: bitcoin-core/src/coins.cpp:106-117 @AccessByTxid@.
cacheFindSibling :: UTXOCache -> TxId -> IO (Maybe (Word32, Bool))
cacheFindSibling cache txid = atomically $ do
  entries <- readTVar (ucEntries cache)
  let candidates =
        [ (ueHeight e, ueCoinbase e)
        | (OutPoint t _, e) <- Map.toList entries
        , t == txid
        , not (ueSpent e)
        ]
  return $ case candidates of
    (h, cb) : _ -> Just (h, cb)
    []          -> Nothing

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
--
-- ATOMICITY (consensus, 2026-06-06):
--   The whole reorg — every disconnect UTXO restore, every connect UTXO
--   mutation, every per-block undo record, the height index AND the
--   @PrefixBestBlock@ tip pointer — commits in ONE RocksDB 'writeBatch'.
--   This mirrors Bitcoin Core's @CCoinsViewDB::BatchWrite@
--   (txdb.cpp:100-159), which writes the entire coin batch and
--   @DB_BEST_BLOCK@ together so the on-disk coins view and the best-block
--   pointer can never disagree across a crash/flush boundary.  It is the
--   exact Phase A/B/C/D shape the live MBlock-arm reorg dispatcher
--   ('BlockTemplate.doSideBranchReorg') uses, replicated here because
--   Consensus.hs cannot import BlockTemplate.hs (module cycle).
--
--   PRE-FIX BUG: the old 'performReorg' drove the disconnect via
--   'disconnectChain' (cache-only 'unapplyBlock') and the connect via
--   'connectChain' (cache-only 'applyBlock' + a bare 'putUndoData').
--   Neither path updated the on-disk @PrefixBestBlock@ pointer OR the
--   @PrefixBlockHeight@ active-chain index.  After a 'flushCache' +
--   restart the persisted UTXO set reflected the NEW chain while the
--   best-block pointer + height index still named the OLD chain.  The
--   startup reconciliation (Main.hs:1009-1180) reloads the active chain
--   from @PrefixBlockHeight@ and re-stamps @PrefixBestBlock@ from undo
--   records — but undo records existed for BOTH branches (the old ones
--   were never deleted), so it re-anchored to the stale old tip.  The
--   next connect then failed the ConnectBlock G1 gate
--   (@hashPrevBlock == GetBestBlock()@, validation.cpp:2333) — a
--   post-restart false-reject.  Routing through 'buildDisconnectBlockOps'
--   + 'buildConnectBlockOps' (which write the chain pointers + height
--   index inside the same batch) closes the hole.
performReorg :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
             -> Maybe IndexManager
             -> BlockHash -> BlockHash -> IO (Either String ())
performReorg net cache db hc mIdxMgr oldTip newTip = do
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
          -- Build the disconnect list (old tip → fork, oldTip first) and
          -- the connect list (fork → new tip, fork-child first), pulling
          -- each block body from disk.
          entries <- readTVarIO (hcEntries hc)
          let forkHash = ceHash forkEntry
          disListRes <- buildReorgDisconnectList db entries oldTip forkHash
          case disListRes of
            Left err -> return (Left err)
            Right disList -> do
              conListRes <- buildReorgConnectList db entries newTip forkHash
              case conListRes of
                Left err -> return (Left err)
                Right conList ->
                  reorgAtomic net cache db hc mIdxMgr disList conList

-- | The atomic core shared by 'performReorg' and 'invalidateBlock'.
--
-- Accumulates the disconnect ops + connect ops into a single
-- 'WriteBatch' (Phase B), commits once (Phase C), then mirrors the
-- result into the in-memory cache + header-chain pointers (Phase D).
-- A 'connList' with the SAME hash as the fork (empty connect side) is
-- a pure disconnect (the invalidateblock case).
--
-- The connect side runs full, script-verifying 'validateFullBlock' on
-- each side-branch block BEFORE building its ops, exactly as the
-- straight-line connect path and 'BlockTemplate.buildReorgBatch' do —
-- a heavier fork whose scripts Core would reject is refused and the
-- reorg aborts with the batch never committed (disk stays at the
-- pre-reorg state).
reorgAtomic :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
            -> Maybe IndexManager
               -- ^ Secondary indexes (txindex / blockfilterindex /
               --   coinstatsindex).  When present, each disconnected block
               --   is reverted from every enabled index
               --   ('indexManagerDisconnectBlock' ->
               --   'coinStatsIndexRevertBlock') and each reconnected block
               --   re-appended ('indexManagerConnectBlock' ->
               --   'coinStatsIndexAppendBlock'), so the per-height
               --   coinstatsindex MuHash tracks the ACTIVE chain across an
               --   invalidateblock-triggered reorg, exactly like the
               --   submitBlock side-branch path
               --   ('BlockTemplate.doSideBranchReorg').
            -> [(ChainEntry, Block)]   -- ^ disconnect list (oldTip first)
            -> [(ChainEntry, Block)]   -- ^ connect list (fork-child first)
            -> IO (Either String ())
reorgAtomic net cache db hc mIdxMgr disList conList = do
  let totalDepth = length disList + length conList
  if totalDepth > maxReorgDepth
    then return $ Left $
      "Reorg too deep: " ++ show totalDepth
      ++ " blocks (disconnect=" ++ show (length disList)
      ++ "+connect=" ++ show (length conList)
      ++ ") exceeds maxReorgDepth=" ++ show maxReorgDepth
    else do
      -- Phase A — pre-load + checksum-verify undo for every disconnect
      -- block.  Fail fast before mutating anything.
      undoRes <- loadReorgDisconnectUndo db disList
      case undoRes of
        Left err -> return (Left err)
        Right disUndos -> do
          -- Phase B — pure batch build with a virtual UTXO overlay.
          let disBuild = reorgDisBuildPure (zip disList disUndos)
                                           ([], reorgEmptyOverlay)
          case disBuild of
            Left err -> return (Left err)
            Right (disOps, ov1) -> do
              conBuild <- reorgConBuild net cache db hc ov1 conList []
              case conBuild of
                Left err -> return (Left err)
                Right conOps -> do
                  -- Phase C — single atomic disk commit.  A crash before
                  -- this point leaves disk fully at the pre-reorg state;
                  -- once it returns the reorg is durable, tip + UTXO +
                  -- undo + height index committed together.
                  writeBatch db (WriteBatch (disOps ++ conOps))

                  -- Class-A dbcache reorg-entry clear: a reorg mutates the
                  -- on-disk UTXO set non-monotonically (disOps restore/remove +
                  -- conOps create/spend), so the dedicated read-through mirror
                  -- must be wiped wholesale. Placed AFTER the disk commit (disk
                  -- durable first) and BEFORE Phase D so the rcGen bump discards
                  -- any concurrent read-through populate that read pre-reorg
                  -- disk. Covers ALL reorg callers (kicker, MBlock side-branch,
                  -- invalidateblock) by living inside reorgAtomic.
                  rcClear cache

                  -- Phase D — mirror disk into the in-memory cache +
                  -- header-chain pointers.  These are process-local: if
                  -- the process dies between Phase C and here, the next
                  -- incarnation re-derives the cache from disk and the
                  -- header chain from PrefixBlockHeight — no split-brain.
                  forM_ (zip disList disUndos) $ \((_, blk), undo) ->
                    unapplyBlock cache blk undo
                  forM_ conList $ \(ce, blk) -> do
                    prevMTP <- reorgPrevMtp hc ce
                    void $ applyBlock cache net blk (ceHeight ce) prevMTP
                                      (reorgGetMtp hc)

                  -- Header-chain pointer flip: rewind disconnected
                  -- heights out of the active-height index, fold in the
                  -- connected heights, and set the new tip.  The new tip
                  -- is the last connect entry, or — for a pure disconnect
                  -- (empty connect list) — the parent of the deepest
                  -- disconnected block (the fork).
                  newTipEntry <- reorgNewTip hc disList conList
                  atomically $ do
                    forM_ disList $ \(ce, _) ->
                      modifyTVar' (hcByHeight hc) (Map.delete (ceHeight ce))
                    forM_ conList $ \(ce, _) ->
                      modifyTVar' (hcByHeight hc)
                        (Map.insert (ceHeight ce) (ceHash ce))
                    case newTipEntry of
                      Just nt -> do
                        writeTVar (hcTip hc) nt
                        writeTVar (hcHeight hc) (ceHeight nt)
                      Nothing -> return ()

                  -- Phase E — mirror the reorg into any opted-in secondary
                  -- indexes (txindex / blockfilterindex / coinstatsindex),
                  -- block-by-block, so they track the ACTIVE chain.  Done
                  -- AFTER the atomic disk commit (so each reconnected block's
                  -- undo record is already on disk for the connect-side
                  -- append) and AFTER the header-chain pointer flip (so the
                  -- per-height index records line up with the new chain).
                  --
                  -- For the invalidateblock case 'conList' is empty, so this
                  -- is a pure disconnect: every disconnected block calls
                  -- 'indexManagerDisconnectBlock' -> 'coinStatsIndexRevertBlock',
                  -- which restores the running MuHash3072 accumulator + counts
                  -- to the pre-block state.  Without this the index would
                  -- retain the now-disconnected chain's coins and serve a
                  -- corrupted 'gettxoutsetinfo muhash H' after the reorg.
                  --
                  -- Order matters and mirrors 'doSideBranchReorg':
                  --   * disconnect oldTip-first -> fork-child last
                  --     ('disList' order), so each delete pulls the index tip
                  --     back one height at a time;
                  --   * connect fork-child first -> newTip last ('conList'
                  --     order), so each append chains off the previous height.
                  -- Reference: bitcoin-core/src/index/coinstatsindex.cpp
                  -- (CustomRemove on disconnect, CustomAppend on reconnect)
                  -- and blockfilterindex.cpp (chained filter headers).
                  case mIdxMgr of
                    Nothing -> return ()
                    Just im -> do
                      forM_ disList $ \(ce, blk) ->
                        indexManagerDisconnectBlock im blk (ceHash ce) (ceHeight ce)
                      forM_ conList $ \(ce, blk) -> do
                        let bh = ceHash ce
                        mUndo <- getUndoData db bh
                        case mUndo of
                          Just u ->
                            indexManagerConnectBlock im blk
                              (udBlockUndo u) bh (ceHeight ce)
                          Nothing -> return ()

                  return (Right ())

-- | Resolve the new in-memory tip after a reorg.  For a non-empty
-- connect list it's the last (highest) connected entry.  For a pure
-- disconnect (invalidateblock) it's the parent of the deepest
-- disconnected block, i.e. the fork point.
reorgNewTip :: HeaderChain -> [(ChainEntry, Block)] -> [(ChainEntry, Block)]
            -> IO (Maybe ChainEntry)
reorgNewTip hc disList conList =
  case reverse conList of
    ((ce, _) : _) -> return (Just ce)
    [] -> case disList of
      [] -> return Nothing   -- nothing to do
      _  ->
        -- disList is oldTip-first; the LAST entry is the deepest
        -- (fork-child) block.  Its parent is the fork point / new tip.
        let (deepestCe, _) = last disList
        in case cePrev deepestCe of
             Nothing -> return Nothing
             Just ph -> do
               entries <- readTVarIO (hcEntries hc)
               return (Map.lookup ph entries)

-- | MTP of @ce@'s parent (BIP-113 cutoff for 'applyBlock' on the
-- cache-mirror step).  0 for genesis / a missing parent.
reorgPrevMtp :: HeaderChain -> ChainEntry -> IO Word32
reorgPrevMtp hc ce = do
  entries <- readTVarIO (hcEntries hc)
  return $ case cePrev ce >>= (`Map.lookup` entries) of
    Just prevCe -> ceMedianTime prevCe
    Nothing     -> 0

-- | MTP-by-height lookup used by 'applyBlock' on the cache-mirror step.
reorgGetMtp :: HeaderChain -> Word32 -> IO Word32
reorgGetMtp hc h = do
  ents     <- readTVarIO (hcEntries hc)
  byHeight <- readTVarIO (hcByHeight hc)
  return $ case Map.lookup h byHeight >>= (`Map.lookup` ents) of
    Just ce -> ceMedianTime ce
    Nothing -> 0

-- | Build the disconnect list (oldTip first, fork-child last) by
-- walking parent pointers from @fromHash@ back to @toHash@, loading
-- each block body from disk.  'Left' if a body or header entry is
-- missing.
buildReorgDisconnectList :: HaskoinDB -> Map BlockHash ChainEntry
                         -> BlockHash -> BlockHash
                         -> IO (Either String [(ChainEntry, Block)])
buildReorgDisconnectList db entries fromHash toHash = go fromHash []
  where
    go h acc
      | h == toHash = return (Right (reverse acc))
      | otherwise = case Map.lookup h entries of
          Nothing -> return $ Left $
            "Reorg disconnect: header entry missing for " ++ show h
          Just ce -> do
            mBlk <- getBlock db h
            case mBlk of
              Nothing -> return $ Left $
                "Missing block data for disconnect: " ++ show h
              Just blk -> case cePrev ce of
                Nothing -> return $ Left $
                  "Reorg disconnect: reached genesis before fork " ++ show toHash
                Just ph -> go ph ((ce, blk) : acc)

-- | Build the connect list (fork-child first, newTip last) by walking
-- parent pointers from @toHash@ back to @fromHash@, loading each block
-- body from disk.  'Left' if a body or header entry is missing.
buildReorgConnectList :: HaskoinDB -> Map BlockHash ChainEntry
                      -> BlockHash -> BlockHash
                      -> IO (Either String [(ChainEntry, Block)])
buildReorgConnectList db entries toHash fromHash = go toHash []
  where
    go h acc
      | h == fromHash = return (Right acc)
      | otherwise = case Map.lookup h entries of
          Nothing -> return $ Left $
            "Reorg connect: header entry missing for " ++ show h
          Just ce -> do
            mBlk <- getBlock db h
            case mBlk of
              Nothing -> return $ Left $
                "Missing block data for reconnect: " ++ show h
              Just blk -> case cePrev ce of
                Nothing -> return $ Left $
                  "Reorg connect: reached genesis before fork " ++ show fromHash
                Just ph -> go ph ((ce, blk) : acc)

-- | Pre-load + checksum-verify undo for every disconnect block (Phase
-- A), failing fast on the first missing/corrupt record.  Returns the
-- undo list parallel to the input.
loadReorgDisconnectUndo :: HaskoinDB -> [(ChainEntry, Block)]
                        -> IO (Either String [UndoData])
loadReorgDisconnectUndo _  []                 = return (Right [])
loadReorgDisconnectUndo db ((_, blk) : rest) = do
  let bh  = computeBlockHash (blockHeader blk)
      prv = bhPrevBlock (blockHeader blk)
  undoR <- getUndoDataVerified db bh prv
  case undoR of
    Left err -> return $ Left $
      "Undo data error for " ++ show bh ++ ": " ++ err
    Right u  -> do
      restR <- loadReorgDisconnectUndo db rest
      return $ case restR of
        Left e   -> Left e
        Right us -> Right (u : us)

-- | Virtual UTXO overlay threaded through the pure batch build so a
-- connect-side spend of a disconnect-side restoration (or of an
-- earlier connect block's output) resolves without touching the
-- not-yet-committed cache/disk.  Same shape as
-- 'BlockTemplate.ReorgOverlay' (replicated here to avoid a module
-- cycle).
data ReorgOverlay = ReorgOverlay
  { roAdded :: !(Map OutPoint Coin)
  , roSpent :: !(Set.Set OutPoint)
  }

reorgEmptyOverlay :: ReorgOverlay
reorgEmptyOverlay = ReorgOverlay Map.empty Set.empty

-- | Look up an outpoint via overlay → cache → disk for the reorg batch
-- build.  An overlay-spent outpoint shadows cache + disk.
reorgLookup :: ReorgOverlay -> UTXOCache -> OutPoint -> IO (Maybe Coin)
reorgLookup ov cache op
  | Set.member op (roSpent ov) = return Nothing
  | otherwise = case Map.lookup op (roAdded ov) of
      Just c  -> return (Just c)
      Nothing -> do
        mEntry <- lookupUTXO cache op
        return $ fmap (\e -> Coin (ueOutput e) (ueHeight e) (ueCoinbase e)) mEntry

-- | Pure folder for the disconnect side (Phase B/disconnect).  Mirrors
-- 'BlockTemplate.buildReorgBatch's @disBuildPure@: each step builds
-- 'buildDisconnectBlockOps', restores spent prevouts into the overlay
-- and marks the block's own created outputs as spent.
reorgDisBuildPure :: [((ChainEntry, Block), UndoData)]
                  -> ([BatchOp], ReorgOverlay)
                  -> Either String ([BatchOp], ReorgOverlay)
reorgDisBuildPure []                       acc = Right acc
reorgDisBuildPure (((_, blk), u) : rest) (opsAcc, ov) =
  let prevHash = bhPrevBlock (blockHeader blk)
  in case buildDisconnectBlockOps blk prevHash u of
    Left e   -> Left e
    Right bo ->
      let txns        = blockTxns blk
          nonCoinbase = drop 1 txns
          txUndos     = buTxUndo (udBlockUndo u)
          restored =
            [ (txInPrevOutput inp,
               Coin (tuOutput tin) (tuHeight tin) (tuCoinbase tin))
            | (tx, txUndo) <- zip nonCoinbase txUndos
            , (inp, tin)   <- zip (txInputs tx) (tuPrevOutputs txUndo)
            ]
          created =
            [ OutPoint (computeTxId tx) (fromIntegral i)
            | tx     <- txns
            , (i, _) <- zip [0 :: Int ..] (txOutputs tx)
            ]
          ov' = ov
            { roAdded = foldr (\(op, c) m -> Map.insert op c m)
                              (roAdded ov) restored
            , roSpent = foldr Set.insert (roSpent ov) created
            }
          -- A restored prevout shadows any prior overlay-spent mark.
          ov'' = ov' { roSpent = foldr (\(op, _) -> Set.delete op)
                                       (roSpent ov') restored }
      in reorgDisBuildPure rest (opsAcc ++ bo, ov'')

-- | IO folder for the connect side (Phase B/connect).  Mirrors
-- 'BlockTemplate.buildReorgBatch's @buildConnectChain@: resolve every
-- prevout via overlay → cache → disk, run full script-verifying
-- 'validateFullBlock', then build 'buildConnectBlockOps' and thread the
-- created outputs into the overlay.
reorgConBuild :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
              -> ReorgOverlay -> [(ChainEntry, Block)] -> [BatchOp]
              -> IO (Either String [BatchOp])
reorgConBuild _   _     _  _  _  []                ops = return (Right ops)
reorgConBuild net cache db hc ov ((ce, blk) : rest) ops = do
  let bh          = computeBlockHash (blockHeader blk)
      txns        = blockTxns blk
      nonCoinbase = drop 1 txns
      prevouts    = [ txInPrevOutput inp | tx <- nonCoinbase, inp <- txInputs tx ]
  spentRes <- foldM
    (\acc op -> case acc of
        Left e  -> return (Left e)
        Right m -> do
          mc <- reorgLookup ov cache op
          case mc of
            Just c' -> return $ Right (Map.insert op c' m)
            Nothing -> return $ Left $
              "Reorg connect: missing prevout " ++ show op
              ++ " for block " ++ show bh)
    (Right Map.empty)
    prevouts
  case spentRes of
    Left e           -> return (Left e)
    Right spentUtxos -> do
      -- BIP-113 cutoff = the median time of the PREVIOUS block, exactly
      -- as the pre-fix 'connectChain' fed 'prevBlockMTP'.  Read it from
      -- the header chain (medianTime is stamped at header insert).
      parentMTP <- reorgPrevMtp hc ce
      -- REORG SCRIPT VERIFICATION (Core parity): full validation incl.
      -- per-input verifyScriptWithFlags under consensusFlagsAtHeight,
      -- BEFORE building the connect ops — a heavier fork whose scripts
      -- Core rejects must abort the reorg, not be silently adopted.
      let cs = ChainState (ceHeight ce - 1) (bhPrevBlock (blockHeader blk))
                          0 parentMTP
                          (consensusFlagsAtHeight net (ceHeight ce))
      case validateFullBlock net cs False False blk spentUtxos of
        Left err -> return $ Left $
          "reorg connect: block " ++ show bh
          ++ " (height " ++ show (ceHeight ce)
          ++ ") failed full validation: " ++ err
        Right () -> do
          let blockOps = buildConnectBlockOps net blk (ceHeight ce) spentUtxos
              txids = map computeTxId txns
              coinbaseFlag txIdx = txIdx == (0 :: Int)
              created =
                [ (OutPoint txid (fromIntegral i),
                   Coin txout (ceHeight ce) (coinbaseFlag txIdx))
                | (txIdx, txid, tx) <- zip3 [0..] txids txns
                , (i, txout) <- zip [0..] (txOutputs tx)
                , not (isUnspendable (txOutScript txout))
                ]
              ov' = ov
                { roAdded = foldr (\(op, c') m -> Map.insert op c' m)
                                  (roAdded ov) created
                , roSpent = foldr Set.insert (roSpent ov) prevouts
                }
              ov'' = ov' { roAdded = foldr Map.delete (roAdded ov') prevouts }
          reorgConBuild net cache db hc ov'' rest (ops ++ blockOps)

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
--
-- REORG SCRIPT VERIFICATION (Core parity):
--   Core connects a side-branch block during a reorg through exactly the
--   same path the main chain uses: @ActivateBestChainStep@ → @ConnectTip@
--   → @ConnectBlock@, which calls @CheckInputScripts@ under the
--   per-height @GetBlockScriptFlags@ (validation.cpp:2250-2289).  A
--   side-branch block with MORE work but an INVALID input script must be
--   rejected and the reorg aborted, NOT silently accepted.
--
--   Pre-fix, this path applied blocks with 'applyBlock' (the cache-only
--   UTXO/value/sigop analog of 'connectBlock') which performs NO script
--   verification — a chain-split-class false-accept: a heavier fork whose
--   scripts Core rejects would be adopted as the active tip.  We now run
--   'validateFullBlock' (with @skipScripts = False@) against each
--   side-branch block BEFORE 'applyBlock' mutates the cache, mirroring
--   rustoshi (chain_state.rs reorganize → connect_block_with_sequence_locks)
--   and blockbrew (ReorgTo → ConnectBlock).  Script verification runs via
--   'validateBlockTransactions' → 'validateSingleTx' → 'verifyScriptWithFlags'
--   under 'consensusFlagsAtHeight' for the block's height — the SAME flag
--   computer + verifier the straight-line connect path uses.
connectChain :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
             -> BlockHash -> BlockHash -> IO (Either String ())
connectChain net cache db hc fromHash toHash = do
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
  results <- forM path $ \ce -> do
    mBlock <- getBlock db (ceHash ce)
    case mBlock of
      Nothing -> return $ Left $ "Missing block data for reconnect: " ++ show (ceHash ce)
      Just block -> do
        -- Get the MTP of the previous block for sequence lock validation
        prevBlockMTP <- case cePrev ce >>= (`Map.lookup` entries) of
          Just prevCe -> return $ ceMedianTime prevCe
          Nothing -> return 0  -- Genesis or missing parent

        -- FULL SCRIPT-VERIFYING VALIDATION of the side-branch block, BEFORE
        -- 'applyBlock' spends its inputs from the cache.  This is the reorg
        -- analog of the main path's 'validateFullBlockIO' gate (Sync.hs:403,
        -- BlockTemplate.hs:544).  Build the spent-prevout 'Coin' map from the
        -- post-disconnect / mid-connect cache (the same view 'applyBlock'
        -- reads), then run the height-correct consensus checks INCLUDING
        -- per-input 'verifyScriptWithFlags'.
        spentRes <- buildReorgSpentCoinMap cache block (ceHeight ce)
        case spentRes of
          Left e -> return (Left e)
          Right spentCoins -> do
            -- csHeight + 1 == this block's height (validateFullBlock derives
            -- the connect height internally), csMedianTime == prev block MTP
            -- (BIP-113 / timestamp cutoff).  Flags computed for ceHeight ce.
            let cs = ChainState (ceHeight ce - 1) (bhPrevBlock (blockHeader block))
                                0 prevBlockMTP
                                (consensusFlagsAtHeight net (ceHeight ce))
            case validateFullBlock net cs False False block spentCoins of
              Left err -> return $ Left $
                "reorg connect: block " ++ show (ceHash ce)
                ++ " (height " ++ show (ceHeight ce)
                ++ ") failed full validation: " ++ err
              Right () -> do
                result <- applyBlock cache net block (ceHeight ce) prevBlockMTP getMTP
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

-- | Build the spent-prevout 'Coin' map for a side-branch block from the
-- in-memory 'UTXOCache' as it stands BEFORE the block is applied (i.e. the
-- post-disconnect / mid-connect chainstate during a reorg).  This is the
-- input 'validateFullBlock' needs to run per-input script verification on a
-- reorg connect — the same 'Map OutPoint Coin' shape the IBD / submitBlock
-- paths build via 'buildUTXOMap' / 'buildBlockUTXOMap'.
--
-- Only prevouts already present in the cache are included.  Prevouts created
-- earlier WITHIN the same block (intra-block spends) are intentionally
-- absent: 'validateBlockTransactions' threads each tx's outputs into its
-- working UTXO map as it processes the block, so those resolve there.  A
-- prevout that is in neither the cache nor the block surfaces as a
-- "Missing UTXO" rejection inside 'validateSingleTx', which is the correct
-- consensus outcome.
buildReorgSpentCoinMap :: UTXOCache -> Block -> Word32 -> IO (Either String (Map OutPoint Coin))
buildReorgSpentCoinMap cache block _height = do
  let nonCoinbase = drop 1 (blockTxns block)
      prevouts    = [ txInPrevOutput inp | tx <- nonCoinbase, inp <- txInputs tx ]
  pairs <- forM prevouts $ \op -> do
    mEntry <- lookupUTXO cache op
    case mEntry of
      Just ue -> return [ (op, Coin { coinTxOut      = ueOutput ue
                                    , coinHeight     = ueHeight ue
                                    , coinIsCoinbase = ueCoinbase ue }) ]
      Nothing -> return []  -- intra-block prevout (resolved by validateBlockTransactions)
  return $ Right (Map.fromList (concat pairs))

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
  , ausValidated       :: !(IORef Bool)             -- ^ True ONLY when the genesis->base re-derivation MATCHED
  , ausError           :: !(IORef (Maybe String))   -- ^ Any error during validation
  , ausVerdict         :: !(IORef (Maybe SnapshotVerdict)) -- ^ Terminal verdict (Valid / Invalid), Nothing while running
  , ausBackgroundTask  :: !(IORef (Maybe (Async ()))) -- ^ Background validation task
  }

-- | Initialize assumeUTXO state from snapshot parameters.
initAssumeUtxoState :: Network -> AssumeUtxoParams -> IO AssumeUtxoState
initAssumeUtxoState net params = do
  heightRef <- newIORef 0
  validatedRef <- newIORef False
  errorRef <- newIORef Nothing
  verdictRef <- newIORef Nothing
  taskRef <- newIORef Nothing
  return AssumeUtxoState
    { ausNetwork = net
    , ausSnapshotHeight = aupHeight params
    , ausSnapshotHash = aupBlockHash params
    , ausExpectedHash = aupHashSerialized params
    , ausCurrentHeight = heightRef
    , ausValidated = validatedRef
    , ausError = errorRef
    , ausVerdict = verdictRef
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
      -- Look up assumeUtxo data for this block hash.  The IO variant also
      -- consults the runtime-registerable regtest whitelist (regtest only), so
      -- a regtest test can activate a snapshot whose base hash it registered;
      -- mainnet/testnet4 still resolve against their static tables only.
      mParams <- assumeUtxoForBlockHashIO net baseHash
      case mParams of
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
-- This re-derives the UTXO set from genesis to the snapshot height in a
-- background thread, in a SEPARATE store, then verifies that the recomputed
-- HASH_SERIALIZED matches the snapshot commitment.
-- Reference: bitcoin/src/validation.cpp MaybeCompleteSnapshotValidation
runBackgroundValidation :: AssumeUtxoState
                        -> HaskoinDB
                        -> (Word32 -> IO (Maybe Block))  -- ^ Block getter by height
                        -> IO ()
runBackgroundValidation state db getBlockAtHeight = do
  -- Identity of the ACTIVE coins store (its RocksDB handle, as a stable
  -- pointer-ish key) for the aliasing guard.  We model it with the database's
  -- 'StableName'; the background store is a freshly-allocated 'Map' so it can
  -- never share identity with the active coins DB.
  activeId <- activeStoreIdentity db
  task <- async $ backgroundValidationLoop state activeId getBlockAtHeight
  writeIORef (ausBackgroundTask state) (Just task)

-- | A stable identity for the ACTIVE coins store, used purely by the aliasing
-- guard.  Two distinct stores must produce distinct identities; the same store
-- must produce the same identity.  Backed by 'System.Mem.StableName' over the
-- live RocksDB handle.
activeStoreIdentity :: HaskoinDB -> IO Int
activeStoreIdentity db = hashStableName <$> makeStableName db

-- | Internal background validation loop — the REAL genesis->base re-derivation.
--
-- Walks every block from genesis (height 0) to the snapshot base height,
-- applying its coin updates (spend inputs / add outputs) into a SEPARATE
-- in-memory store ('BackgroundChainstate'), then recomputes the
-- @HASH_SERIALIZED@ over THAT store and compares it to the snapshot commitment
-- ('ausExpectedHash').  MATCH -> 'SnapshotValid' (validated, retire bg
-- chainstate); MISMATCH -> 'SnapshotInvalid' (flagged, NEVER silently
-- accepted), Core @MaybeCompleteSnapshotValidation@.
backgroundValidationLoop :: AssumeUtxoState
                         -> Int                         -- ^ active coins-store identity (aliasing guard)
                         -> (Word32 -> IO (Maybe Block))
                         -> IO ()
backgroundValidationLoop state activeId getBlockAtHeight = do
  let targetHeight = ausSnapshotHeight state
  -- A fresh, EMPTY background chainstate (its own Map store), pre-genesis.
  bg <- newBackgroundChainstate targetHeight activeId
  -- 'ausExpectedHash' is the snapshot's HASH_SERIALIZED in DISPLAY order
  -- (Bitcoin's reversed uint256 hex, as 'verifySnapshot' compares).
  result <- connectGenesisToBaseProgress bg (ausExpectedHash state)
              (\h -> writeIORef (ausCurrentHeight state) h)
              getBlockAtHeight
  case result of
    Left err -> do
      -- Hard failure (aliasing, missing block, inconsistent input): NOT
      -- validated.  The snapshot is never silently accepted.
      writeIORef (ausError state) (Just (show err))
      writeIORef (ausVerdict state) (Just SnapshotInvalid)
      writeIORef (ausValidated state) False
    Right SnapshotValid -> do
      writeIORef (ausVerdict state) (Just SnapshotValid)
      writeIORef (ausValidated state) True
    Right SnapshotInvalid -> do
      -- The independent re-derivation computed a DIFFERENT hash than the
      -- snapshot committed to: REJECT.  Never sets ausValidated.
      writeIORef (ausError state)
        (Just "AssumeUTXO background re-derivation hash mismatch: snapshot REJECTED")
      writeIORef (ausVerdict state) (Just SnapshotInvalid)
      writeIORef (ausValidated state) False

--------------------------------------------------------------------------------
-- Real second chainstate (genesis->base re-derivation)
--
-- This is the genuine background chainstate Bitcoin Core builds in
-- validation.cpp AddChainstate: a SEPARATE coins store, seeded EMPTY at
-- genesis, that independently re-derives the UTXO set the loaded snapshot
-- claims.  When it reaches the base height it recomputes HASH_SERIALIZED and
-- compares it to au_data.hash_serialized (MaybeCompleteSnapshotValidation).
--
-- The store is a plain in-memory @Map OutPoint Coin@ — NOT the active coins
-- DB.  An aliasing guard refuses to run if the recorded active-store identity
-- equals THIS store's identity, so it can never become a hash-of-self.
--------------------------------------------------------------------------------

-- | Terminal verdict of a genesis->base re-derivation.
data SnapshotVerdict
  = SnapshotValid    -- ^ The re-derived HASH_SERIALIZED MATCHED the commitment.
  | SnapshotInvalid  -- ^ It MISMATCHED — the snapshot is rejected.
  deriving (Show, Eq, Generic)

-- | Hard errors from the background re-derivation.  Every one of these means
-- "NOT validated" (the snapshot is never silently accepted).
data BackgroundValidationError
  = BgAliasesActiveStore
    -- ^ The background store shares identity with the ACTIVE coins store; a
    -- hash-of-self is not an independent re-derivation, so refuse to run.
  | BgMissingBlock !Word32
    -- ^ A block required by the genesis->base walk was unavailable.
  | BgMissingInput !TxId !Word32 !Word32
    -- ^ A tx input's coin was not in the background store (txid, vout,
    -- block-height) — the replayed chain is internally inconsistent.
  deriving (Show, Eq, Generic)

-- | The SECOND chainstate used to independently re-derive the snapshot UTXO
-- set from genesis.  Holds its OWN coins map, seeded EMPTY at genesis,
-- completely separate from the active chainstate's coins DB.
data BackgroundChainstate = BackgroundChainstate
  { bgCoins        :: !(IORef (Map OutPoint Coin))
    -- ^ The background store's OWN UTXO set.  A freshly-allocated mutable cell,
    -- distinct from the active coins DB.
  , bgTipHeightRef :: !(IORef Int)
    -- ^ Height of the last block connected (-1 == pre-genesis).
  , bgBaseHeight   :: !Word32
    -- ^ The snapshot base height this chainstate re-derives to.
  , bgActiveStoreId :: !(IORef Int)
    -- ^ Identity of the ACTIVE coins store (for the aliasing guard); 0 == "no
    -- active store registered" (unit-test construction with no distinct
    -- active store to alias-check against).
  , bgStoreIdRef   :: !(IORef Int)
    -- ^ This background store's OWN identity (a 'StableName' over 'bgCoins').
  }

-- | Create a fresh background chainstate seeded EMPTY at pre-genesis.
--
-- @activeId@ is the identity of the live/active coins store (e.g. from
-- 'activeStoreIdentity'); pass @0@ only in tests that have no distinct active
-- store to alias-check against.
newBackgroundChainstate :: Word32 -> Int -> IO BackgroundChainstate
newBackgroundChainstate baseHeight activeId = do
  coinsRef  <- newIORef Map.empty
  tipRef    <- newIORef (-1)
  activeRef <- newIORef activeId
  -- THIS store's identity is a StableName over its own coins cell.
  ownId     <- hashStableName <$> makeStableName coinsRef
  ownRef    <- newIORef ownId
  return BackgroundChainstate
    { bgCoins         = coinsRef
    , bgTipHeightRef  = tipRef
    , bgBaseHeight    = baseHeight
    , bgActiveStoreId = activeRef
    , bgStoreIdRef    = ownRef
    }

-- | This background store's OWN identity (for the aliasing guard / proving the
-- two stores are distinct).
bgStoreId :: BackgroundChainstate -> IO Int
bgStoreId = readIORef . bgStoreIdRef

-- | Record the active coins-store identity for the aliasing guard.  Lets a
-- test pin the active id AFTER construction — used to deterministically
-- exercise the guard by setting the active id to THIS store's own id (which
-- then refuses a tautological hash-of-self).
setBgActiveStoreId :: BackgroundChainstate -> Int -> IO ()
setBgActiveStoreId bg = writeIORef (bgActiveStoreId bg)

-- | Number of unspent coins currently in the background store.
bgCoinCount :: BackgroundChainstate -> IO Int
bgCoinCount bg = Map.size <$> readIORef (bgCoins bg)

-- | Read-only access to a coin in the background store (for tests proving the
-- phantom coin is ABSENT from a real re-derivation).
bgGetCoin :: BackgroundChainstate -> OutPoint -> IO (Maybe Coin)
bgGetCoin bg op = Map.lookup op <$> readIORef (bgCoins bg)

-- | Height of the last connected block (-1 == pre-genesis).
bgTipHeight :: BackgroundChainstate -> IO Int
bgTipHeight = readIORef . bgTipHeightRef

-- | The background store's coins as a list of 'SnapshotCoin', ready to feed
-- 'computeUtxoHash' (it sorts on (txid,vout) internally, matching Core's
-- cursor order).
bgSnapshotCoins :: BackgroundChainstate -> IO [SnapshotCoin]
bgSnapshotCoins bg = do
  m <- readIORef (bgCoins bg)
  return [ SnapshotCoin op c | (op, c) <- Map.toList m ]

-- | Apply ONE block's coin updates to the background store, Core
-- @ConnectBlock@-style (validation.cpp ConnectBlock mirror):
--
--   * genesis (height 0): mutates NOTHING — Core never adds the genesis
--     coinbase to any chainstate's coins DB (it is unspendable).
--   * coinbase tx (h>0): no inputs to spend; add its spendable outputs flagged
--     @coinIsCoinbase=True@.
--   * every other tx: SPEND each input's coin (must exist), then add its
--     spendable outputs flagged @coinIsCoinbase=False@.
--   * provably-unspendable outputs (OP_RETURN / oversize) are SKIPPED — never
--     inserted, exactly like @CCoinsViewCache::AddCoin@ (isUnspendable).
--
-- This is the real state transition (spend/add), NOT a counter.
bgConnectOneBlock :: BackgroundChainstate
                  -> Block
                  -> Word32       -- ^ this block's height in the active chain
                  -> IO (Either BackgroundValidationError ())
bgConnectOneBlock _bg _block 0 = return (Right ())   -- genesis: no UTXO mutation
bgConnectOneBlock bg block height = go (blockTxns block)
  where
    go [] = return (Right ())
    go (tx : rest) = do
      let txid = computeTxId tx
          isCb = isCoinbaseTx tx
      -- Spend inputs (non-coinbase only).
      spendRes <-
        if isCb
          then return (Right ())
          else spendInputs (txInputs tx) height
      case spendRes of
        Left e  -> return (Left e)
        Right () -> do
          -- Add this tx's spendable outputs.
          addOutputs txid isCb height (zip [0 ..] (txOutputs tx))
          go rest

    spendInputs [] _ = return (Right ())
    spendInputs (i : is) h = do
      let op = txInPrevOutput i
      present <- Map.member op <$> readIORef (bgCoins bg)
      if not present
        then return (Left (BgMissingInput (outPointHash op) (outPointIndex op) h))
        else do
          modifyIORef' (bgCoins bg) (Map.delete op)
          spendInputs is h

    addOutputs _ _ _ [] = return ()
    addOutputs txid isCb h ((vout, o) : os) = do
      unless (isUnspendable (txOutScript o)) $ do
        let op   = OutPoint txid vout
            coin = Coin { coinTxOut = o, coinHeight = h, coinIsCoinbase = isCb }
        modifyIORef' (bgCoins bg) (Map.insert op coin)
      addOutputs txid isCb h os

-- | Whether a tx is a coinbase: exactly one input whose prevout is the
-- all-zero txid with vout 0xffffffff (Core @CTransaction::IsCoinBase@).
isCoinbaseTx :: Tx -> Bool
isCoinbaseTx tx =
  case txInputs tx of
    [i] -> let op = txInPrevOutput i
           in outPointHash op == TxId (Hash256 (BS.replicate 32 0))
              && outPointIndex op == 0xffffffff
    _   -> False

-- | Run the REAL genesis->base re-derivation into the SEPARATE background
-- store, then recompute @HASH_SERIALIZED@ over THAT store's coins and compare
-- to the snapshot commitment.
--
-- @assumedHash@ is the snapshot's @HASH_SERIALIZED@ in the same DISPLAY order
-- that 'verifySnapshot' compares (Bitcoin's reversed uint256 hex).
--
-- Returns @Right SnapshotValid@ when the independently re-derived hash MATCHED;
-- @Right SnapshotInvalid@ when it MISMATCHED (the non-circular reject path: the
-- snapshot passed the load-time gate because it committed to its own hash, but
-- the genesis->base replay computes a DIFFERENT hash); @Left@ on a hard failure
-- (aliasing, missing block, inconsistent input) which also means NOT validated.
connectGenesisToBase :: BackgroundChainstate
                     -> Hash256                       -- ^ assumed (display-order) HASH_SERIALIZED
                     -> (Word32 -> IO (Maybe Block))  -- ^ block getter by height
                     -> IO (Either BackgroundValidationError SnapshotVerdict)
connectGenesisToBase bg assumedHash getBlock =
  connectGenesisToBaseProgress bg assumedHash (const (return ())) getBlock

-- | As 'connectGenesisToBase', but reports per-height progress via a callback.
connectGenesisToBaseProgress
  :: BackgroundChainstate
  -> Hash256
  -> (Word32 -> IO ())              -- ^ progress callback (height connected)
  -> (Word32 -> IO (Maybe Block))
  -> IO (Either BackgroundValidationError SnapshotVerdict)
connectGenesisToBaseProgress bg assumedHash onProgress getBlock = do
  -- ALIASING GUARD: refuse to run if the background store IS the active store.
  -- A hash-of-self is not an independent re-derivation.
  ownId    <- readIORef (bgStoreIdRef bg)
  activeId <- readIORef (bgActiveStoreId bg)
  if activeId /= 0 && ownId == activeId
    then return (Left BgAliasesActiveStore)
    else do
      tip0 <- readIORef (bgTipHeightRef bg)
      let start = fromIntegral (tip0 + 1) :: Word32
      walk start
  where
    walk height
      | height > bgBaseHeight bg =
          -- Reached the base: recompute HASH_SERIALIZED and compare.
          Right <$> finalizeBackgroundValidation bg assumedHash
      | otherwise = do
          mBlock <- getBlock height
          case mBlock of
            Nothing -> return (Left (BgMissingBlock height))
            Just block -> do
              r <- bgConnectOneBlock bg block height
              case r of
                Left e   -> return (Left e)
                Right () -> do
                  writeIORef (bgTipHeightRef bg) (fromIntegral height)
                  onProgress height
                  walk (height + 1)

-- | Recompute @HASH_SERIALIZED@ over the background store's OWN coins and
-- compare to the commitment.  MATCH -> 'SnapshotValid', MISMATCH ->
-- 'SnapshotInvalid'.
--
-- REUSES 'computeUtxoHash' / 'putTxOutSer' (the existing Core HASH_SERIALIZED
-- routine) — it does NOT define a second hasher.  'computeUtxoHash' returns the
-- raw double-SHA256 digest (internal uint256 byte order); we reverse it into
-- the DISPLAY order that 'ausExpectedHash' / 'audHashSerialized' hold (exactly
-- as 'verifySnapshot' does), then compare.
finalizeBackgroundValidation :: BackgroundChainstate
                             -> Hash256       -- ^ assumed (display-order) HASH_SERIALIZED
                             -> IO SnapshotVerdict
finalizeBackgroundValidation bg assumedHash = do
  coins <- bgSnapshotCoins bg
  let Hash256 rawDigest = computeUtxoHash coins
      recomputed        = Hash256 (BS.reverse rawDigest)
  return $ if recomputed == assumedHash then SnapshotValid else SnapshotInvalid

-- | Core two-stage AssumeUTXO activation (validation.cpp ActivateSnapshot ->
-- AddChainstate -> background re-derivation).
--
-- Stage 1 (load-time gate, 'activateSnapshot'): authenticate the snapshot FILE
-- against the whitelist + its committed HASH_SERIALIZED.
--
-- Stage 2 (THIS function): kick the REAL genesis->base re-derivation in a
-- SEPARATE background store, which independently re-derives the UTXO set and
-- compares its hash to the commitment.  A snapshot that passes the load-time
-- gate by committing to its OWN tampered hash is STILL rejected here, because
-- the background store never reads the file — it replays the blocks.
--
-- Returns the activated 'AssumeUtxoState' (whose 'ausValidated' / 'ausVerdict'
-- the spawned background task updates) on a successful load-time gate, or the
-- load-time error otherwise.
activateSnapshotWithRederivation
  :: HaskoinDB
  -> Network
  -> FilePath                       -- ^ path to snapshot file
  -> (Word32 -> IO (Maybe Block))   -- ^ block getter by height (genesis..base)
  -> IO (Either String AssumeUtxoState)
activateSnapshotWithRederivation db net snapshotPath getBlock = do
  -- Stage 1: load-time hash gate.
  gate <- activateSnapshot db net snapshotPath
  case gate of
    Left err    -> return (Left err)
    Right state -> do
      -- Stage 2: kick the REAL background genesis->base re-derivation.
      runBackgroundValidation state db getBlock
      return (Right state)

-- | Core two-stage AssumeUTXO activation, run SYNCHRONOUSLY to a terminal
-- verdict.
--
-- Identical to 'activateSnapshotWithRederivation' except Stage 2 runs
-- INLINE (via the very same 'backgroundValidationLoop' the async path uses)
-- instead of being spawned, so the caller observes the terminal
-- 'SnapshotValid' / 'SnapshotInvalid' verdict on return.  This is what the
-- live @loadtxoutset@ RPC needs: the handler must answer the operator with
-- ACCEPT or REJECT, and must NOT promote a snapshot whose independent
-- re-derivation disagrees with the committed hash.
--
-- The re-derivation walks a SEPARATE in-memory store (never the active
-- coins DB — the aliasing guard in 'connectGenesisToBaseProgress' enforces
-- this), so a synchronous run touches NOTHING in the active chainstate.
-- That is precisely why it is safe to run from the live RPC: the active
-- store, header chain, PeerManager and BlockStore are all left untouched
-- regardless of verdict (Core ActivateSnapshot builds the snapshot
-- chainstate alongside the active one; here we validate-without-promote).
--
-- Returns the activated 'AssumeUtxoState' (its 'ausValidated' / 'ausVerdict'
-- already set to the terminal result) on a successful load-time gate, or the
-- load-time error otherwise.
activateSnapshotSync
  :: HaskoinDB
  -> Network
  -> FilePath                       -- ^ path to snapshot file
  -> (Word32 -> IO (Maybe Block))   -- ^ block getter by height (genesis..base)
  -> IO (Either String AssumeUtxoState)
activateSnapshotSync db net snapshotPath getBlock = do
  -- Stage 1: load-time hash gate (whitelist + committed HASH_SERIALIZED).
  gate <- activateSnapshot db net snapshotPath
  case gate of
    Left err    -> return (Left err)
    Right state -> do
      -- Stage 2: run the REAL genesis->base re-derivation INLINE (the same
      -- loop the async path forks) so the verdict is known on return.
      activeId <- activeStoreIdentity db
      backgroundValidationLoop state activeId getBlock
      return (Right state)

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
--   1. invalidateblock marks the target StatusFailedValid, descendants StatusFailedChild
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
--   1. If on active chain, disconnects blocks back to before the invalid block
--      THEN marks each disconnected entry (BUG-4 fix: mark-after-disconnect).
--   2. For off-chain descendants, marks all at once (no UTXO state at risk).
--   3. Uses StatusFailedValid for the directly-invalidated block and
--      StatusFailedChild for its descendants (BUG-5 fix: distinct failure flags).
--   4. Activates the best remaining valid chain.
--   5. Adds the block to the manually-invalidated set.
--
-- Returns Left on error, Right on success (possibly with a new tip).
invalidateBlock :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
                -> Maybe IndexManager
                -> BlockHash -> IO (Either InvalidateError ())
invalidateBlock net cache db hc mIdxMgr blockHash = do
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

          -- Helper: compute the appropriate failure status for one entry.
          -- BUG-5 fix: directly-invalidated block → StatusFailedValid;
          --            its descendants        → StatusFailedChild.
          -- Mirrors Core validation.cpp:3618-3619 (FAILED_VALID) and
          -- 3704-3705 (FAILED_CHILD).
          let entryStatus ce = if ceHash ce == blockHash
                                 then StatusFailedValid
                                 else StatusFailedChild

          -- Mark all in-memory states first (single atomic STM update),
          -- then persist to DB.  Separating the phases means the in-memory
          -- index is consistent before the first DB write touches the disk.
          --
          -- P2-2 + P2-3: drop every affected entry from 'hcCandidates'
          -- in the SAME STM transaction that flips its status.  Without
          -- this an invalidated entry would still satisfy the
          -- 'Set.lookupMax' in 'activateBestChain' until the next
          -- BLOCK_HAVE_DATA-gate failure rejects it on the ancestry
          -- walk — wasted work proportional to the bad subtree's depth.
          -- Mirrors Core's @setBlockIndexCandidates.erase(pindexFailed)@
          -- in validation.cpp:3159.
          let markDescendants ces = do
                atomically $ do
                  modifyTVar' (hcEntries hc) $ \m ->
                    foldl' (\acc ce ->
                      Map.adjust (\e -> e { ceStatus = entryStatus ce }) (ceHash ce) acc)
                      m ces
                  modifyTVar' (hcCandidates hc) $ \s ->
                    foldl' (\acc ce -> Set.delete (mkCandidateKey ce) acc) s ces
                forM_ ces $ \ce -> putBlockStatus db (ceHash ce) (entryStatus ce)

          -- Check if the block is on the active chain (ancestor of tip)
          let isOnActiveChain = isAncestor entries blockHash (ceHash tip)

          result <- if isOnActiveChain
            then do
              -- BUG-4 fix: disconnect FIRST, then mark each entry after its
              -- successful disconnect (mirrors Core's per-block marking order).
              let targetHash = case cePrev entry of
                    Just prevHash -> prevHash
                    Nothing -> blockHash  -- Should never happen (genesis handled above)

              -- Disconnect blocks back to the parent of the invalid block.
              -- ATOMIC (consensus, 2026-06-06): route through 'reorgAtomic'
              -- with an EMPTY connect list so the disk commit (UTXO restore +
              -- @PrefixBestBlock@ rewind to the new tip + height-index
              -- rewind) is one 'writeBatch' AND the in-memory tip flip is
              -- driven by the same helper.  The pre-fix path called the
              -- cache-only 'disconnectChain' and then re-stamped the tip
              -- only in memory — the on-disk best-block pointer + height
              -- index were left naming the now-invalidated chain, so a
              -- flush+restart resurrected it (same false-reject the reorg
              -- path had).  See 'performReorg'.
              disListRes <- buildReorgDisconnectList db entries (ceHash tip) targetHash
              case disListRes of
                Left err -> return $ Left (InvalidateDisconnectFailed err)
                Right disList -> do
                  -- Thread the IndexManager into the atomic disconnect so the
                  -- coinstatsindex (and blockfilterindex/txindex) is reverted
                  -- for every disconnected block — the bug this fix closes:
                  -- the invalidateblock reorg path previously did NOT fan out
                  -- to the IndexManager, so 'coinStatsIndexRevertBlock' was
                  -- never called and the running MuHash retained the
                  -- disconnected chain-A blocks (corrupted muhash@H after a
                  -- reorg).
                  disconnectResult <- reorgAtomic net cache db hc mIdxMgr disList []
                  case disconnectResult of
                    Left err -> return $ Left (InvalidateDisconnectFailed err)
                    Right () -> do
                      -- Mark all descendants now that the UTXO rewind is done
                      markDescendants descendants
                      -- 'reorgAtomic' already flipped hcTip/hcHeight to the
                      -- parent of the invalid block; just confirm it resolved.
                      case Map.lookup targetHash entries of
                        Nothing -> return $ Left (InvalidateBlockNotFound targetHash)
                        Just _newTipEntry -> do
                          -- Try to activate the best valid chain (a heavier
                          -- side branch, if any) — also index-aware.
                          activateBestChain net cache db hc mIdxMgr
                          return (Right ())
            else do
              -- Block not on active chain: no UTXO state to rewind, mark all.
              markDescendants descendants
              return (Right ())

          -- Add to manually-invalidated set only on success
          case result of
            Right () -> atomically $ modifyTVar' (hcInvalidated hc) (Set.insert blockHash)
            Left _   -> return ()

          return result

-- | Check if hash1 is an ancestor of hash2.
isAncestor :: Map BlockHash ChainEntry -> BlockHash -> BlockHash -> Bool
isAncestor entries ancestorHash descendantHash
  | ancestorHash == descendantHash = True
  | otherwise = case Map.lookup descendantHash entries of
      Nothing -> False
      Just ce -> case cePrev ce of
        Nothing -> False
        Just prevHash -> isAncestor entries ancestorHash prevHash

-- | True for any status that represents a failed/invalidated block.
-- Covers the legacy StatusInvalid as well as the new StatusFailedValid and
-- StatusFailedChild introduced by the BUG-5 fix.
isFailedStatus :: BlockStatus -> Bool
isFailedStatus StatusInvalid     = True
isFailedStatus StatusFailedValid = True
isFailedStatus StatusFailedChild = True
isFailedStatus _                 = False

-- | Activate the best valid chain.
-- After invalidation, we may need to switch to a different fork.
-- Reference: bitcoin/src/validation.cpp ActivateBestChain +
-- FindMostWorkChain (validation.cpp:3114-3170).
--
-- P2-2 (W101 BUG-8): the pre-fix implementation built a 'tipCandidates'
-- list by filtering 'Map.elems entries' (O(n)) and, for each entry,
-- calling 'any (… == cePrev …) allEntries' (O(n) per entry) — O(n²)
-- total on every invalidate/reconsider RPC.  At mainnet IBD scale
-- (>850k entries) that scan stalls the main thread.  Fix: read the
-- sorted 'hcCandidates' set and pull the best candidate via
-- 'Set.lookupMax' (O(log n)).
--
-- P2-3 (W101 BUG-3): Core also walks the candidate's ancestry back to
-- the active chain checking @BLOCK_HAVE_DATA@ on every step
-- (validation.cpp:3132-3167); a chain whose ancestor's body is missing
-- (or whose ancestor is invalidated) is dropped from
-- @setBlockIndexCandidates@ and the loop tries the next-best
-- candidate.  We replicate that here: 'haveBlockData' equates to
-- @StatusValid@ in haskoin's status model
-- ('addSideBranchHeader' is the only path that sets 'StatusValid';
-- 'addHeader' parks a new header at 'StatusHeaderValid').
activateBestChain :: Network -> UTXOCache -> HaskoinDB -> HeaderChain
                  -> Maybe IndexManager -> IO ()
activateBestChain net cache db hc mIdxMgr = do
  currentTip <- readTVarIO (hcTip hc)
  best       <- findBestCandidate hc
  case best of
    Nothing     -> return ()
    Just bestCe ->
      when (ceChainWork bestCe > ceChainWork currentTip) $ do
        -- BUG-1: propagate findForkPoint failure (don't silently swallow it).
        mFork <- findForkPoint hc (ceHash currentTip) (ceHash bestCe)
        case mFork of
          Nothing -> do
            -- No common ancestor: prune this disconnected candidate
            -- from 'hcCandidates' so future calls don't re-pick it.
            atomically $
              modifyTVar' (hcCandidates hc)
                (Set.delete (mkCandidateKey bestCe))
          Just _fork ->
            void $ performReorg net cache db hc mIdxMgr (ceHash currentTip) (ceHash bestCe)

-- | Pull the best valid tip candidate from the sorted set, applying
-- Core's ancestor-walk @BLOCK_HAVE_DATA@ + invalidation gate
-- (validation.cpp:3128-3167).
--
-- If the best candidate's ancestor chain has any entry missing block
-- data (haskoin: not 'StatusValid') or any invalidated entry, the
-- candidate and its disconnected ancestor subtree are removed from
-- 'hcCandidates' and the loop retries with the next-best candidate.
-- Returns 'Nothing' when the set is exhausted.
findBestCandidate :: HeaderChain -> IO (Maybe ChainEntry)
findBestCandidate hc = do
  entries     <- readTVarIO (hcEntries hc)
  invalidated <- readTVarIO (hcInvalidated hc)
  byHeight    <- readTVarIO (hcByHeight hc)
  let onActiveChain h = case Map.lookup h entries of
        Nothing -> False
        Just ce -> Map.lookup (ceHeight ce) byHeight == Just (ceHash ce)
  let loop = do
        cs <- readTVarIO (hcCandidates hc)
        case Set.lookupMax cs of
          Nothing -> return Nothing
          Just bestKey -> case Map.lookup (ckHash bestKey) entries of
            Nothing -> do
              -- Stale key (entry was removed); drop and retry.
              atomically $ modifyTVar' (hcCandidates hc) (Set.delete bestKey)
              loop
            Just bestCe ->
              case walkAncestry entries invalidated onActiveChain bestCe of
                Right ()   -> return (Just bestCe)
                Left badCe -> do
                  -- Drop this candidate AND any descendant of the bad
                  -- ancestor that's still in the set.  Mirrors Core's
                  -- inner @while (pindexTest != pindexFailed)@ loop
                  -- (validation.cpp:3148-3162).
                  atomically $ modifyTVar' (hcCandidates hc) $ \s ->
                    Set.filter (\k ->
                      case Map.lookup (ckHash k) entries of
                        Nothing -> False
                        Just ce -> not (descendsFrom entries ce (ceHash badCe)))
                      s
                  loop
  loop
  where
    -- | Walk from 'start' back toward genesis, stopping at the active
    -- chain.  Returns 'Left badCe' on the first ancestor that fails the
    -- gate, 'Right ()' if every ancestor up to the active chain has
    -- BLOCK_HAVE_DATA + is not invalidated.
    walkAncestry :: Map BlockHash ChainEntry
                 -> Set.Set BlockHash
                 -> (BlockHash -> Bool)
                 -> ChainEntry
                 -> Either ChainEntry ()
    walkAncestry ents inv onActive ce
      | onActive (ceHash ce)               = Right ()
      | Set.member (ceHash ce) inv         = Left ce
      | ceStatus ce /= StatusValid         = Left ce
      | otherwise = case cePrev ce of
          Nothing      -> Right ()  -- reached genesis
          Just prevHash -> case Map.lookup prevHash ents of
            Nothing  -> Left ce  -- missing parent in index; treat as bad
            Just par -> walkAncestry ents inv onActive par

    -- | True iff 'ce' is 'target' or a descendant of 'target'.  Used to
    -- evict an entire side-branch when one ancestor fails the gate.
    descendsFrom :: Map BlockHash ChainEntry
                 -> ChainEntry
                 -> BlockHash
                 -> Bool
    descendsFrom ents ce target
      | ceHash ce == target = True
      | otherwise = case cePrev ce of
          Nothing       -> False
          Just prevHash -> case Map.lookup prevHash ents of
            Nothing  -> False
            Just par -> descendsFrom ents par target

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
                -> Maybe IndexManager
                -> BlockHash -> IO (Either InvalidateError ())
reconsiderBlock net cache db hc mIdxMgr blockHash = do
  entries <- readTVarIO (hcEntries hc)
  invalidated <- readTVarIO (hcInvalidated hc)

  case Map.lookup blockHash entries of
    Nothing -> return $ Left (ReconsiderBlockNotFound blockHash)
    Just entry
      | not (isFailedStatus (ceStatus entry)) && not (Set.member blockHash invalidated) ->
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

          -- Try to activate the best chain (may include reconsidered blocks);
          -- index-aware so any reorg keeps the secondary indexes in sync.
          activateBestChain net cache db hc mIdxMgr
          return (Right ())

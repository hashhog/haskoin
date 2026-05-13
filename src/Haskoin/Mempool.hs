{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DerivingStrategies #-}

-- | Transaction Memory Pool
--
-- This module implements a transaction memory pool that stores unconfirmed
-- transactions, validates them against the current UTXO set, enforces policy
-- rules (fee rates, standard scripts), handles transaction replacement
-- (BIP-125 RBF), and provides transaction relay to peers.
--
-- Key Design:
--   - Multiple indexes for efficient lookups (by TxId, OutPoint, fee rate)
--   - Ancestor/descendant tracking to limit chain depth
--   - BIP-125 Replace-By-Fee support
--   - Automatic eviction of low-fee transactions when full
--   - Thread-safe with STM
--
module Haskoin.Mempool
  ( -- * Mempool Types
    Mempool(..)
  , MempoolConfig(..)
  , MempoolEntry(..)
  , FeeRate(..)
  , MempoolError(..)
  , RbfError(..)
  , defaultMempoolConfig
    -- * Fee Calculations
  , calculateFeeRate
  , calculateVSize
  , calculateAdjustedVSize
    -- * Mempool Creation
  , newMempool
  , noopCoinMtp
    -- * Transaction Operations
  , addTransaction
  , removeTransaction
  , getTransaction
  , getTransactionByWtxid
  , txIdForWtxid
  , getMempoolTxIds
  , getMempoolWtxids
  , getMempoolSize
  , getMempoolInfo
  , getMempoolMinFeeRate
    -- * Block Handlers
  , blockConnected
  , blockDisconnected
    -- * Ancestry
  , getAncestors
  , getDescendants
    -- * Mining
  , selectTransactions
    -- * Conflict Detection
  , getConflicts
    -- * BIP-68 sequence lock checks
  , checkSeqLocksAtTip
    -- * Eviction / Expiry
  , expireOldTransactions
  , trackPackageRemoved
  , trimToSize
  , rollingFeeHalflife
    -- * RBF (Replace-by-Fee)
  , checkReplacement
  , removeConflicts
  , isRbfReplaceable
  , checkAllConflictsRbfReplaceable
  , signalsOptInRBF
  , maxReplacementEvictions
  , incrementalRelayFeePerKvb
  , checkNoConflictSpending
  , checkNoNewUnconfirmedInputs
    -- * Package Relay (BIP-331)
  , TxPackage(..)
  , PackageError(..)
  , maxPackageCount
  , maxPackageWeight
  , acceptPackage
  , isTopoSortedPackage
  , isConsistentPackage
  , isWellFormedPackage
  , isChildWithParents
  , calculatePackageFeeRate
    -- * v3/TRUC Transactions (BIP 431)
  , TrucError(..)
  , trucVersion
  , trucAncestorLimit
  , trucDescendantLimit
  , trucMaxVsize
  , trucChildMaxVsize
  , isV3
  , checkTrucPolicy
  , checkVersionInheritance
  , getMempoolParent
  , getMempoolChildren
  , attemptSiblingEviction
    -- * Ephemeral Anchors
  , EphemeralError(..)
  , hasEphemeralAnchor
  , getEphemeralOutputs
  , checkEphemeralAnchors
  , checkEphemeralPreCheck
  , evictEphemeralParent
    -- * Cluster Mempool
  , Cluster(..)
  , Chunk(..)
  , ClusterState(..)
  , maxClusterSize
  , maxClusterSizeVbytes
  , findCluster
  , findAllClusters
  , linearize
  , linearizeCluster
  , chunkLinearization
  , computeChunks
  , selectTransactionsFromClusters
  , evictLowestFeeRateCluster
  , buildClusterState
  , getClusterForTx
  , getClusterFeeRate
    -- * Union-Find
  , UnionFind(..)
  , emptyUnionFind
  , ufMakeSet
  , ufFind
  , ufUnion
  , ufConnected
  , ufGetSize
  , buildUnionFind
  , wouldExceedClusterLimit
  , getDistinctClusterSizes
    -- * Feerate Diagrams (RBF)
  , FeerateDiagram
  , buildFeerateDiagram
  , compareDiagrams
  , interpolate
  , buildReplacementDiagrams
  , checkDiagramReplacement
    -- * Cluster Limits
  , ClusterLimitError(..)
  , checkClusterLimit
    -- * W96: AcceptToMemoryPool helpers
  , validateInputsStandardness
  , generalEphemeralPreCheck
  , isUnknownWitnessProgram
  , ancestorTxIdsForUnconfirmedTx
  , maxP2SHSigOps
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int32, Int64)
import Data.List (sortBy, foldl', sort)
import Data.Ord (comparing, Down(..))
import Data.Maybe (mapMaybe, catMaybes)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Set (Set)
import Control.Monad (forM, forM_, when, unless, foldM)
import Control.Concurrent.STM
import Data.Time.Clock.POSIX (getPOSIXTime)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import Data.Serialize (encode)

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Consensus (Network(..), validateTransaction, witnessScaleFactor,
                           txBaseSize, txTotalSize, coinbaseMaturity,
                           isFinalTxCheck, calculateSequenceLocks,
                           checkSequenceLocks, bip68Active,
                           getTransactionSigOpCost, consensusFlagsAtHeight,
                           consensusFlagsToScriptFlags,
                           SigOpCost(..), isCoinbase)
import Haskoin.Storage (UTXOCache(..), UTXOEntry(..), lookupUTXO)
import Haskoin.Script (verifyScript, isPayToAnchor, decodeScript)
import qualified Haskoin.Script as Script
import qualified Haskoin.Policy.Standard as Std
import Haskoin.Policy.Standard (maxStandardTxSigOpsCost, defaultBytesPerSigop,
                                getSigOpsAdjustedWeight, dustRelayTxFee, isDust)

--------------------------------------------------------------------------------
-- Fee Rate
--------------------------------------------------------------------------------

-- | Fee rate in satoshis per virtual byte (sat/vB)
-- Virtual size accounts for SegWit discount: vsize = (weight + 3) / 4
newtype FeeRate = FeeRate { getFeeRate :: Word64 }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)

-- | Calculate fee rate from fee and virtual size
calculateFeeRate :: Word64 -> Int -> FeeRate
calculateFeeRate fee vsize
  | vsize <= 0 = FeeRate 0
  | otherwise  = FeeRate ((fee * 1000) `div` fromIntegral vsize)

-- | Calculate virtual size from transaction weight (no sigop adjustment).
-- @vsize = ceil(weight / 4) = (weight + 3) \`div\` 4@.
-- Use 'calculateAdjustedVSize' when the sigop cost is known (fee-rate storage).
calculateVSize :: Tx -> Int
calculateVSize tx =
  let base = txBaseSize tx
      total = txTotalSize tx
      weight = base * (witnessScaleFactor - 1) + total
  in (weight + witnessScaleFactor - 1) `div` witnessScaleFactor

-- | Sigop-adjusted virtual size.
-- Mirrors @GetVirtualTransactionSize(weight, sigopCost, bytesPerSigop)@ in Core.
-- If the sigop cost inflates the effective weight beyond the raw BIP-141 weight,
-- the higher value is used for the vsize stored in 'meSize' and used for
-- fee-rate comparison.
--
-- Reference: bitcoin-core/src/policy/policy.cpp:395-402.
calculateAdjustedVSize :: Tx -> Int -> Int
calculateAdjustedVSize tx sigopCost =
  let base   = txBaseSize tx
      total  = txTotalSize tx
      weight = base * (witnessScaleFactor - 1) + total
      adj    = getSigOpsAdjustedWeight weight sigopCost defaultBytesPerSigop
  in (adj + witnessScaleFactor - 1) `div` witnessScaleFactor

--------------------------------------------------------------------------------
-- Mempool Configuration
--------------------------------------------------------------------------------

-- | Mempool configuration parameters
data MempoolConfig = MempoolConfig
  { mpcMaxSize           :: !Int      -- ^ Max pool size in bytes (default 300MB)
  , mpcMinFeeRate        :: !FeeRate  -- ^ Min fee rate to accept (sat/vB)
  , mpcMaxOrphans        :: !Int      -- ^ Max orphan transactions
  , mpcRBFEnabled        :: !Bool     -- ^ Allow BIP-125 RBF
  , mpcMaxAncestors      :: !Int      -- ^ Max ancestor count (default 25)
  , mpcMaxDescendants    :: !Int      -- ^ Max descendant count (default 25)
  , mpcMaxAncestorSize   :: !Int64    -- ^ Max ancestor size in vB (default 101k)
  , mpcMaxDescendantSize :: !Int64    -- ^ Max descendant size in vB (default 101k)
  , mpcExpiryHours       :: !Int      -- ^ Hours after which unconfirmed txs expire
                                      --   (default 336 = 14 days).
                                      --   Bitcoin Core: DEFAULT_MEMPOOL_EXPIRY_HOURS=336
                                      --   (kernel/mempool_options.h:23).
  , mpcMaxFeeRate        :: !(Maybe FeeRate)
                                      -- ^ Optional caller-defined maximum effective
                                      --   fee-rate (sat/vB). When set, a transaction
                                      --   whose modified-fee/vsize exceeds this is
                                      --   rejected before mempool admission.
                                      --   Mirrors Bitcoin Core's
                                      --   ATMPArgs::m_client_maxfeerate
                                      --   (validation.cpp:1368, set via
                                      --   sendrawtransaction's maxfeerate arg or
                                      --   -maxtxfee). Default Nothing = no cap.
  } deriving (Show, Generic)

instance NFData MempoolConfig

-- | Default mempool configuration matching Bitcoin Core defaults
defaultMempoolConfig :: MempoolConfig
defaultMempoolConfig = MempoolConfig
  { mpcMaxSize           = 300 * 1024 * 1024  -- 300 MB
  , mpcMinFeeRate        = FeeRate 1          -- 1 sat/vB
  , mpcMaxOrphans        = 100
  , mpcRBFEnabled        = True
  , mpcMaxAncestors      = 25
  , mpcMaxDescendants    = 25
  , mpcMaxAncestorSize   = 101000             -- ~101 KB
  , mpcMaxDescendantSize = 101000             -- ~101 KB
  , mpcExpiryHours       = 336               -- 14 days
  , mpcMaxFeeRate        = Nothing            -- no cap by default
  }

--------------------------------------------------------------------------------
-- Mempool Entry
--------------------------------------------------------------------------------

-- | A transaction entry in the mempool with computed metadata
data MempoolEntry = MempoolEntry
  { meTransaction      :: !Tx         -- ^ The transaction
  , meTxId             :: !TxId       -- ^ Transaction ID (cached, no witness)
  , meWtxid            :: !Wtxid      -- ^ Witness Transaction ID (BIP-141/339)
  , meFee              :: !Word64     -- ^ Fee in satoshis
  , meFeeRate          :: !FeeRate    -- ^ Fee rate in sat/vB
  , meSize             :: !Int        -- ^ Virtual size (vB)
  , meTime             :: !Int64      -- ^ Unix timestamp when added
  , meHeight           :: !Word32     -- ^ Chain height when added
  , meAncestorCount    :: !Int        -- ^ Number of unconfirmed ancestors (including self)
  , meAncestorSize     :: !Int        -- ^ Total ancestor vsize (including self)
  , meAncestorFees     :: !Word64     -- ^ Total ancestor fees (including self)
  , meAncestorSigOps   :: !Int        -- ^ Total ancestor sigops
  , meDescendantCount  :: !Int        -- ^ Number of unconfirmed descendants (including self)
  , meDescendantSize   :: !Int        -- ^ Total descendant vsize (including self)
  , meDescendantFees   :: !Word64     -- ^ Total descendant fees (including self)
  , meRBFOptIn         :: !Bool       -- ^ Signals RBF (nSequence < 0xfffffffe)
  } deriving (Show, Generic)

instance NFData MempoolEntry

--------------------------------------------------------------------------------
-- Mempool Errors
--------------------------------------------------------------------------------

-- | Errors that can occur when adding a transaction to the mempool
data MempoolError
  = ErrAlreadyInMempool
    -- ^ Exact duplicate (same wtxid) already in mempool.
    --   Bitcoin Core: TX_CONFLICT, "txn-already-in-mempool".
  | ErrSameNonwitnessInMempool
    -- ^ Same non-witness data (same txid) but different witness already
    -- in mempool. Bitcoin Core: TX_CONFLICT,
    -- "txn-same-nonwitness-data-in-mempool" (validation.cpp:829).
  | ErrCoinbaseNotAllowed
    -- ^ Coinbase transactions are only valid in a block, not as loose
    -- mempool transactions. Bitcoin Core: TX_CONSENSUS, "coinbase"
    -- (validation.cpp:804).
  | ErrMaxFeeRateExceeded !FeeRate !FeeRate
    -- ^ (effective_feerate, client_max_feerate). Caller-defined max
    -- fee-rate exceeded. Bitcoin Core: TX_MEMPOOL_POLICY,
    -- "max feerate exceeded" (validation.cpp:1369).
  | ErrSpendsConflictingTx !TxId
    -- ^ Transaction depends on an ancestor that is also in the conflict
    -- set being replaced. Bitcoin Core: TX_CONSENSUS,
    -- "bad-txns-spends-conflicting-tx" (validation.cpp:1359).
  | ErrInputsNotStandard !Int !String
    -- ^ (input_index, reason). ValidateInputsStandardness failure.
    -- Bitcoin Core: TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs"
    -- (policy.cpp:214 → validation.cpp:897).
  | ErrValidationFailed !String
  | ErrMissingInput !OutPoint
  | ErrInputSpentInMempool !TxId
  | ErrInsufficientFee
  | ErrFeeBelowMinimum !FeeRate !FeeRate
  | ErrTooManyAncestors !Int !Int        -- ^ (actual, limit)
  | ErrTooManyDescendants !Int !Int      -- ^ (actual, limit)
  | ErrAncestorSizeTooLarge !Int64 !Int64  -- ^ (actual, limit)
  | ErrDescendantSizeTooLarge !Int64 !Int64  -- ^ (actual, limit)
  | ErrScriptVerificationFailed !String
  | ErrCoinbaseNotMature !Word32 !Word32
  | ErrRBFNotSignaled !TxId
  | ErrRBFFeeTooLow !Word64 !Word64
  | ErrMempoolFull
  -- Full RBF errors (BIP-125)
  | ErrRBFInsufficientAbsoluteFee !Word64 !Word64  -- ^ (new_fee, required_fee) - Rule 3
  | ErrRBFInsufficientFeeRate !FeeRate !FeeRate    -- ^ (new_feerate, min_required) - Rule 3a
  | ErrRBFTooManyReplacements !Int !Int            -- ^ (eviction_count, max_allowed) - Rule 5
  | ErrRBFInsufficientRelayFee !Word64 !Word64     -- ^ (additional_fee, required) - Rule 4
  | ErrRBFSpendingConflict !TxId                   -- ^ Replacement tx spends conflicting tx
  | ErrRBFNewUnconfirmedInput !TxId                -- ^ (parent_txid) - Rule 2: replacement adds new unconfirmed input
  -- v3/TRUC policy errors (BIP 431)
  | ErrTrucViolation !TrucError                    -- ^ TRUC policy violation
  -- Ephemeral anchor errors
  | ErrEphemeralViolation !EphemeralError          -- ^ Ephemeral anchor policy violation
  -- Cluster size limit errors
  | ErrClusterLimitExceeded !Int !Int              -- ^ (actual_size, max_size)
  -- Relay-policy / standardness (Bitcoin Core IsStandardTx)
  | ErrNonStandard !String                         -- ^ short reason tag (e.g. "tx-size", "scriptpubkey")
  -- Locktime / sequence-lock policy (Bitcoin Core MemPoolAccept::PreChecks)
  | ErrNonFinal !String           -- ^ nLockTime not satisfied at tip+1 (BIP-113 IsFinalTx)
  | ErrSeqLockNotSatisfied        -- ^ BIP-68 relative locktime not satisfied at tip+1
  deriving (Show, Eq, Generic)

instance NFData MempoolError

--------------------------------------------------------------------------------
-- Full RBF Constants and Types
--------------------------------------------------------------------------------

-- | Maximum number of transactions that can be evicted by a single replacement
-- This includes direct conflicts and all their descendants
-- Bitcoin Core: MAX_REPLACEMENT_CANDIDATES = 100
maxReplacementEvictions :: Int
maxReplacementEvictions = 100

-- | Incremental relay fee in sat/kvB.
-- This is the minimum fee increase required to pay for replacement bandwidth
-- and also the floor added to evicted fee rates when bumping the rolling minimum.
-- Bitcoin Core: DEFAULT_INCREMENTAL_RELAY_FEE = 100 sat/kvB (policy/policy.h:48).
-- Note: CFeeRate(100) means 100 sat per 1000 bytes = 0.1 sat/vB.
incrementalRelayFeePerKvb :: Word64
incrementalRelayFeePerKvb = 100

-- | Rolling fee halflife in seconds (12 hours).
-- Controls how quickly the rolling minimum fee decays toward zero after the
-- mempool stops being full.  Halved (to 3h or 6h) when pool is less than
-- half- or quarter-full to speed up decay in light-traffic conditions.
-- Bitcoin Core: CTxMemPool::ROLLING_FEE_HALFLIFE = 60*60*12 (txmempool.h:212).
rollingFeeHalflife :: Double
rollingFeeHalflife = fromIntegral (60 * 60 * 12 :: Int)

-- | BIP-125 Gate 1: does this transaction directly signal opt-in RBF?
-- A transaction signals opt-in RBF if ANY input has nSequence <= 0xfffffffd
-- (i.e. nSequence <= MAX_BIP125_RBF_SEQUENCE).
-- bitcoin-core/src/util/rbf.cpp:SignalsOptInRBF
-- bitcoin-core/src/util/rbf.h:MAX_BIP125_RBF_SEQUENCE = 0xfffffffd
signalsOptInRBF :: Tx -> Bool
signalsOptInRBF tx = any (\inp -> txInSequence inp <= 0xfffffffd) (txInputs tx)

-- | RBF-specific error type for replacement validation
data RbfError
  = RbfInsufficientAbsoluteFee
      { rbfNewFee :: !Word64
      , rbfRequiredFee :: !Word64
      }
  | RbfInsufficientFeeRate
      { rbfNewFeeRate :: !FeeRate
      , rbfMinFeeRate :: !FeeRate
      }
  | RbfTooManyEvictions
      { rbfEvictionCount :: !Int
      , rbfMaxEvictions :: !Int
      }
  | RbfInsufficientRelayFee
      { rbfAdditionalFee :: !Word64
      , rbfRequiredRelayFee :: !Word64
      }
  | RbfSpendingConflict
      { rbfConflictTxId :: !TxId
      }
  -- BIP-125 Rule 2: replacement may not introduce new unconfirmed inputs
  -- (i.e. inputs that were not present in the conflicting txs being replaced
  -- and are themselves not yet confirmed).
  | RbfNewUnconfirmedInput
      { rbfNewParentTxId :: !TxId
      }
  deriving (Show, Eq, Generic)

instance NFData RbfError

--------------------------------------------------------------------------------
-- v3/TRUC Policy Constants (BIP 431)
--------------------------------------------------------------------------------

-- | Transaction version that indicates TRUC (Topologically Restricted Until
-- Confirmation) policy. v3 transactions have restricted topology to make
-- RBF more reliable.
trucVersion :: Int32
trucVersion = 3

-- | Maximum number of ancestors (including self) for a TRUC transaction.
-- This means a v3 transaction can have at most 1 unconfirmed parent.
-- Bitcoin Core: TRUC_ANCESTOR_LIMIT = 2
trucAncestorLimit :: Int
trucAncestorLimit = 2

-- | Maximum number of descendants (including self) for a TRUC transaction.
-- This means a v3 transaction can have at most 1 unconfirmed child.
-- Bitcoin Core: TRUC_DESCENDANT_LIMIT = 2
trucDescendantLimit :: Int
trucDescendantLimit = 2

-- | Maximum virtual size of a TRUC transaction in vbytes.
-- Bitcoin Core: TRUC_MAX_VSIZE = 10,000
trucMaxVsize :: Int64
trucMaxVsize = 10000

-- | Maximum virtual size of a TRUC child transaction (one that spends from
-- an unconfirmed v3 parent) in vbytes.
-- Bitcoin Core: TRUC_CHILD_MAX_VSIZE = 1,000
trucChildMaxVsize :: Int64
trucChildMaxVsize = 1000

--------------------------------------------------------------------------------
-- v3/TRUC Error Types
--------------------------------------------------------------------------------

-- | Errors specific to TRUC (v3 transaction) policy violations
data TrucError
  = TrucTooLarge
      { trucActualVsize :: !Int64
      , trucMaxAllowed :: !Int64
      }
    -- ^ v3 transaction exceeds TRUC_MAX_VSIZE
  | TrucChildTooLarge
      { trucChildActualVsize :: !Int64
      , trucChildMaxAllowed :: !Int64
      }
    -- ^ v3 child (has unconfirmed parent) exceeds TRUC_CHILD_MAX_VSIZE
  | TrucTooManyAncestors
      { trucAncestorCount :: !Int
      , trucAncestorMax :: !Int
      }
    -- ^ v3 transaction would have too many unconfirmed ancestors
  | TrucTooManyDescendants
      { trucDescendantCount :: !Int
      , trucDescendantMax :: !Int
      }
    -- ^ v3 transaction would exceed descendant limit
  | TrucV3SpendingNonV3
      { trucChildTxId :: !TxId
      , trucParentTxId :: !TxId
      }
    -- ^ v3 transaction cannot spend from non-v3 unconfirmed transaction
  | TrucNonV3SpendingV3
      { trucNonV3TxId :: !TxId
      , trucV3ParentTxId :: !TxId
      }
    -- ^ non-v3 transaction cannot spend from v3 unconfirmed transaction
  | TrucSiblingExists
      { trucParentTxId' :: !TxId
      , trucExistingSiblingTxId :: !TxId
      }
    -- ^ v3 parent already has a child in mempool (may allow sibling eviction)
  deriving (Show, Eq, Generic)

instance NFData TrucError

--------------------------------------------------------------------------------
-- Ephemeral Anchor Errors
--------------------------------------------------------------------------------

-- | Errors related to ephemeral anchor policy.
-- Ephemeral anchors are zero-value P2A outputs that must be spent in the same
-- package to prevent dust from persisting in the UTXO set.
data EphemeralError
  = EphemeralDustWithFee
      { ephemeralTxId :: !TxId
      , ephemeralFee :: !Word64
      }
    -- ^ Transaction with ephemeral anchor output has non-zero fee.
    -- Ephemeral (dust) outputs must have 0 fee to prevent mining alone.
  | EphemeralMultipleAnchors
      { ephemeralTxId' :: !TxId
      , ephemeralCount :: !Int
      }
    -- ^ Transaction has multiple ephemeral anchor outputs (only one allowed).
  | EphemeralNotSpent
      { ephemeralParentTxId :: !TxId
      , ephemeralUnspent :: ![OutPoint]
      }
    -- ^ Ephemeral anchor outputs were not spent by any child transaction.
    -- All ephemeral anchors must be spent within the same package.
  deriving (Show, Eq, Generic)

instance NFData EphemeralError

--------------------------------------------------------------------------------
-- Mempool
--------------------------------------------------------------------------------

-- | The transaction memory pool
--
-- Per Bitcoin Core (txmempool.h: boost::multi_index over CTxMemPoolEntry),
-- mempool entries are addressable by both txid AND wtxid. We mirror that
-- with two parallel maps. The wtxid index is required for BIP-339 wtxid
-- relay (deduplication by wtxid in inv messages and getdata pruning).
data Mempool = Mempool
  { mpEntries    :: !(TVar (Map TxId MempoolEntry))
    -- ^ All mempool entries indexed by TxId
  , mpByWtxid    :: !(TVar (Map Wtxid TxId))
    -- ^ BIP-339 dual index: Wtxid -> TxId. Always synced with mpEntries.
  , mpByOutpoint :: !(TVar (Map OutPoint TxId))
    -- ^ Index: spent outpoint -> spending transaction
  , mpByFeeRate  :: !(TVar (Map (FeeRate, TxId) ()))
    -- ^ Index: sorted by (fee rate, txid) for eviction
  , mpConfig     :: !MempoolConfig
    -- ^ Configuration parameters
  , mpUTXOCache  :: !UTXOCache
    -- ^ UTXO cache for input validation
  , mpSize       :: !(TVar Int)
    -- ^ Total serialized size in bytes
  , mpNetwork    :: !Network
    -- ^ Network configuration
  , mpHeight     :: !(TVar Word32)
    -- ^ Current chain height (tip height; mempool checks against tip+1)
  , mpMTP        :: !(TVar Word32)
    -- ^ Median Time Past of the current tip (BIP-113).
    -- Derived from mpRecentTimestamps; updated in blockConnected/blockDisconnected.
    -- Used by IsFinalTx at mempool admit.
  , mpRecentTimestamps :: !(TVar [Word32])
    -- ^ Ring of the last ≤11 block timestamps (newest first).
    -- Maintained by blockConnected/blockDisconnected for MTP computation.
  , mpFeeDeltas  :: !(TVar (Map TxId Int64))
    -- ^ Prioritisetransaction fee deltas (in satoshis); persisted in
    -- mempool.dat alongside transactions.
  , mpUnbroadcast :: !(TVar (Set TxId))
    -- ^ Transactions originated locally that have not yet been confirmed
    -- relayed to a peer. Persisted in mempool.dat.
  , mpGetCoinMtp :: !(Word32 -> IO Word32)
    -- ^ BIP-68: Given a coin's confirmation height H, returns the Median Time
    -- Past of block max(H-1, 0).  This is the per-input nCoinTime used by
    -- Bitcoin Core's CalculateSequenceLocks (tx_verify.cpp:74).
    -- Callers with a live header chain should supply a function that looks up
    -- the height->hash index and calls medianTimePast.  In tests or when chain
    -- history is unavailable, pass 'noopCoinMtp' (returns 0), which makes all
    -- time-based BIP-68 locks appear trivially satisfied (over-permissive but
    -- correct: the real enforcement is done by OP_CSV at script-eval time).
    -- Rolling minimum fee state (Bitcoin Core txmempool.h:195-197, 212).
    -- Together these implement CTxMemPool::GetMinFee / trackPackageRemoved.
  , mpRollingMinFeeRate :: !(TVar Double)
    -- ^ Rolling minimum fee rate in sat/kvB (as Double for exponential decay).
    -- Starts at 0.  Bumped by trackPackageRemoved when we evict due to sizelimit;
    -- decays exponentially in GetMinFee with halflife ROLLING_FEE_HALFLIFE.
    -- Bitcoin Core: rollingMinimumFeeRate (txmempool.h:197).
  , mpBlockSinceLastFeeBump :: !(TVar Bool)
    -- ^ True after a block is connected; cleared when rollingMinimumFeeRate is
    -- bumped by an eviction.  Controls decay: if a block has been mined since
    -- the last eviction-bump the fee has already decayed naturally, so we skip
    -- the update-time check and decay unconditionally.
    -- Bitcoin Core: blockSinceLastRollingFeeBump (txmempool.h:196).
  , mpLastRollingFeeUpdate :: !(TVar Int64)
    -- ^ Unix timestamp of the last decay calculation.  Initialised to now.
    -- Updated every time GetMinFee applies a decay step (only if >10s elapsed).
    -- Bitcoin Core: lastRollingFeeUpdate (txmempool.h:195).
  }

-- | A no-op coin-MTP lookup that returns 0 for every height.
-- With coinMTP=0 the computed nMinTime = (lockValue<<9) - 1, which is always
-- less than any real block timestamp, so all time-based BIP-68 constraints
-- are treated as satisfied.  This is over-permissive but safe: the canonical
-- enforcement happens via OP_CSV at script-evaluation time (which has full
-- per-tx sequence context).  Use in tests and in nodes that have not wired a
-- live header-chain lookup.
noopCoinMtp :: Word32 -> IO Word32
noopCoinMtp _ = return 0

-- | Create a new empty mempool.
-- 'height' is the current chain tip height; 'mtp' is the Median Time Past
-- of the current tip (used for BIP-113 IsFinalTx at mempool admit).
-- Pass 0 for both on a fresh node; they are updated via blockConnected.
-- 'getCoinMtp' is a function that, given a confirmed UTXO's block height H,
-- returns the Median Time Past of block max(H-1, 0).  This is used by the
-- BIP-68 time-based relative-locktime check in checkSeqLocksAtTip.  Pass
-- 'noopCoinMtp' when historical chain MTP data is unavailable.
newMempool :: Network -> UTXOCache -> MempoolConfig -> Word32 -> Word32
           -> (Word32 -> IO Word32) -> IO Mempool
newMempool net cache config height mtp getCoinMtp = do
  now <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
  Mempool
    <$> newTVarIO Map.empty
    <*> newTVarIO Map.empty
    <*> newTVarIO Map.empty
    <*> newTVarIO Map.empty
    <*> pure config
    <*> pure cache
    <*> newTVarIO 0
    <*> pure net
    <*> newTVarIO height
    <*> newTVarIO mtp
    <*> newTVarIO []         -- mpRecentTimestamps: empty until blocks connect
    <*> newTVarIO Map.empty
    <*> newTVarIO Set.empty
    <*> pure getCoinMtp
    <*> newTVarIO 0.0        -- mpRollingMinFeeRate: starts at 0
    <*> newTVarIO False      -- mpBlockSinceLastFeeBump: no block yet
    <*> newTVarIO now        -- mpLastRollingFeeUpdate: now

--------------------------------------------------------------------------------
-- Transaction Addition
--------------------------------------------------------------------------------

-- | Add a transaction to the mempool after validation
-- Returns the TxId on success, or an error on failure
addTransaction :: Mempool -> Tx -> IO (Either MempoolError TxId)
addTransaction mp tx = do
  let txid = computeTxId tx
      wtxid = computeWtxid tx

  -- 1. Existence checks — mirrors Bitcoin Core MemPoolAccept::PreChecks
  --    (validation.cpp:823-830). Core distinguishes:
  --      a) wtxid hit → "txn-already-in-mempool" (exact duplicate)
  --      b) txid  hit → "txn-same-nonwitness-data-in-mempool"
  --                     (witness mutated, same non-witness data)
  --    We use ErrAlreadyInMempool for (a) and ErrSameNonwitnessInMempool
  --    for (b) to distinguish on the wire / in RPC errors.
  byWtxid <- atomically $ Map.lookup wtxid <$> readTVar (mpByWtxid mp)
  case byWtxid of
    Just _ -> return $ Left ErrAlreadyInMempool
    Nothing -> do
      byTxid <- atomically $ Map.lookup txid <$> readTVar (mpEntries mp)
      case byTxid of
        Just _ -> return $ Left ErrSameNonwitnessInMempool
        Nothing -> addTransactionInner mp tx txid

-- | Inner implementation of addTransaction after duplicate check
addTransactionInner :: Mempool -> Tx -> TxId -> IO (Either MempoolError TxId)
addTransactionInner mp tx txid = do
  -- 2a. Context-free CheckTransaction (consensus/tx_check.cpp).
  case validateTransaction tx of
    Left err -> return $ Left (ErrValidationFailed err)
    Right () | isCoinbase tx ->
      -- Coinbase is only valid in a block, not as a loose mempool tx.
      -- Mirrors Bitcoin Core PreChecks (validation.cpp:803-804):
      --   if (tx.IsCoinBase()) return state.Invalid(TX_CONSENSUS, "coinbase").
      -- Without this gate `validateTransaction` only checks coinbase
      -- scriptSig size (2-100 bytes via BIP-34); a well-formed coinbase
      -- otherwise reaches resolveInput and fails generically there. We
      -- reject up-front with the canonical reason so the rejection is
      -- byte-identical to Core's and doesn't depend on UTXO presence.
      return $ Left ErrCoinbaseNotAllowed
    Right () ->
      -- 2b. Relay-policy standardness gate (Bitcoin Core IsStandardTx).
      -- Mirrors policy/policy.cpp:IsStandardTx — version bounds, weight
      -- cap (MAX_STANDARD_TX_WEIGHT=400_000), pushOnly scriptSigs,
      -- standard scriptPubKeys, OP_RETURN budget, dust limit.
      -- Failures are policy, not consensus, so we tag them with
      -- 'ErrNonStandard <reason>' for parity with Core's RPC errors.
      case Std.checkStandardTx tx of
        Left stdErr -> return $ Left (ErrNonStandard (renderStdReason stdErr))
        Right () -> do
          -- 2c. IsFinalTx (BIP-113): reject non-final transactions at mempool
          -- admit.  Mempool holds txs for the *next* block, so check against
          -- tipHeight+1 and the MTP of the current tip per BIP-113.
          -- Mirrors Bitcoin Core MemPoolAccept::PreChecks → CheckFinalTxAtTip
          -- (validation.cpp:819).
          height <- readTVarIO (mpHeight mp)
          mtp    <- readTVarIO (mpMTP mp)
          let nextHeight = height + 1
          if not (isFinalTxCheck tx nextHeight mtp)
            then return $ Left (ErrNonFinal "non-final")
            else do
              -- 2d. BIP-68 sequence locks: reject txs whose relative-locktime
              -- constraints are not satisfied at the next block.  Uses per-input
              -- coin heights from the UTXO set (unconfirmed mempool parents get
              -- synthetic height = tipHeight+1 as Bitcoin Core does).
              -- Mirrors Bitcoin Core MemPoolAccept::PreChecks →
              -- CheckSequenceLocksAtTip (validation.cpp:887).
              seqLockResult <- checkSeqLocksAtTip mp tx height mtp
              case seqLockResult of
                Left err -> return $ Left err
                Right () -> do
                  -- 3. Check for conflicts first (before resolving inputs)
                  conflicts <- getConflicts mp tx

                  if null conflicts
                    -- No conflicts: proceed with normal addition
                    then addTransactionNoConflicts mp tx txid
                    -- Has conflicts: attempt RBF replacement
                    else if mpcRBFEnabled (mpConfig mp)
                      -- Full RBF (mempoolfullrbf=1): all mempool txs are replaceable.
                      -- bitcoin-core/src/policy/rbf.cpp:IsRBFOptIn — in full-RBF mode
                      -- every in-mempool tx is treated as REPLACEABLE_BIP125.
                      then addTransactionWithReplacement mp tx txid conflicts
                      else do
                        -- Legacy BIP-125 mode: attempt replacement only if every
                        -- conflicting tx (or one of its mempool ancestors) signals
                        -- opt-in RBF (nSequence <= 0xfffffffd).
                        -- bitcoin-core/src/policy/rbf.cpp:IsRBFOptIn — checks the
                        -- transaction itself, then walks in-mempool ancestors.
                        rbfOk <- checkAllConflictsRbfReplaceable mp conflicts
                        if rbfOk
                          then addTransactionWithReplacement mp tx txid conflicts
                          else return $ Left (ErrInputSpentInMempool (head conflicts))

-- | Add a transaction with no conflicts (normal case)
addTransactionNoConflicts :: Mempool -> Tx -> TxId -> IO (Either MempoolError TxId)
addTransactionNoConflicts mp tx txid = do
  -- Resolve inputs
  inputResults <- resolveInputs mp tx
  case inputResults of
    Left err -> return $ Left err
    Right inputPairs -> finalizeTransaction mp tx txid inputPairs

-- | Add a transaction that replaces conflicting transactions (RBF)
addTransactionWithReplacement :: Mempool -> Tx -> TxId -> [TxId] -> IO (Either MempoolError TxId)
addTransactionWithReplacement mp tx txid conflictTxIds = do
  -- W96 Gate: EntriesAndTxidsDisjoint (Bitcoin Core
  -- validation.cpp:1356).  After we have the set of all ancestors of
  -- @tx@ + the set of conflicts to be replaced, verify the two sets
  -- are disjoint.  A tx that depends on one of its own conflicts is
  -- pathological — Core classifies this as a consensus failure
  -- (TX_CONSENSUS, "bad-txns-spends-conflicting-tx").  Without this
  -- gate the package would silently corrupt the mempool: the conflict
  -- gets removed (because it's in conflictTxIds) but the new tx still
  -- references it as an unconfirmed ancestor.
  ancestorTxids <- ancestorTxIdsForUnconfirmedTx mp tx
  let conflictSet = Set.fromList conflictTxIds
      overlap = Set.intersection ancestorTxids conflictSet
  case Set.lookupMin overlap of
    Just badId -> return $ Left (ErrSpendsConflictingTx badId)
    Nothing -> addTransactionWithReplacementInner mp tx txid conflictTxIds

-- | Inner body of 'addTransactionWithReplacement' after the disjoint-set
-- check.  Kept separate so the disjoint gate is visually obvious.
addTransactionWithReplacementInner :: Mempool -> Tx -> TxId -> [TxId] -> IO (Either MempoolError TxId)
addTransactionWithReplacementInner mp tx txid conflictTxIds = do
  -- For RBF, we need to resolve inputs differently:
  -- - Conflicting inputs will fail resolveInput, so we need to resolve from UTXO
  -- - Non-conflicting inputs should resolve normally

  -- First, resolve all inputs that are NOT conflicts
  inputResults <- resolveInputsForReplacement mp tx conflictTxIds
  case inputResults of
    Left err -> return $ Left err
    Right inputPairs -> do
      let inputMap = Map.fromList inputPairs
          totalIn = sum $ map (txOutValue . snd) inputPairs
          totalOut = sum $ map txOutValue (txOutputs tx)

      -- Check fee is positive
      if totalIn < totalOut
        then return $ Left ErrInsufficientFee
        else do
          let fee = totalIn - totalOut
              vsize = calculateVSize tx
              feeRate = calculateFeeRate fee vsize

          -- Check minimum fee rate
          if feeRate < mpcMinFeeRate (mpConfig mp)
            then return $ Left (ErrFeeBelowMinimum feeRate (mpcMinFeeRate (mpConfig mp)))
            else do
              -- Attempt replacement with RBF rules
              replaceResult <- attemptReplacement mp tx txid conflictTxIds fee vsize feeRate
              case replaceResult of
                Left err -> return $ Left err
                Right () -> do
                  -- Conflicts removed, now add the new transaction
                  -- Re-resolve inputs now that conflicts are removed
                  inputResults' <- resolveInputs mp tx
                  case inputResults' of
                    Left err -> return $ Left err
                    Right inputPairs' ->
                      finalizeTransaction mp tx txid inputPairs'

-- | Resolve inputs for a replacement transaction
-- For inputs that conflict with mempool txs, resolve from UTXO set only
resolveInputsForReplacement :: Mempool -> Tx -> [TxId] -> IO (Either MempoolError [(OutPoint, TxOut)])
resolveInputsForReplacement mp tx conflictTxIds = do
  let conflictSet = Set.fromList conflictTxIds
  results <- forM (txInputs tx) $ \inp -> do
    let op = txInPrevOutput inp
    -- Check if this input is spent by a conflict
    mSpender <- atomically $ Map.lookup op <$> readTVar (mpByOutpoint mp)
    case mSpender of
      Just spenderTxId | Set.member spenderTxId conflictSet -> do
        -- This input is spent by a conflict - resolve from UTXO only
        mUtxo <- lookupUTXO (mpUTXOCache mp) op
        case mUtxo of
          Just entry -> do
            height <- readTVarIO (mpHeight mp)
            if ueCoinbase entry && height - ueHeight entry < fromIntegral coinbaseMaturity
              then return $ Left (ErrCoinbaseNotMature (ueHeight entry) height)
              else return $ Right (op, ueOutput entry)
          Nothing -> return $ Left (ErrMissingInput op)
      _ -> resolveInput mp op
  return $ sequence results

-- | Finalize adding a transaction (common code for both normal and RBF)
finalizeTransaction :: Mempool -> Tx -> TxId -> [(OutPoint, TxOut)] -> IO (Either MempoolError TxId)
finalizeTransaction mp tx txid inputPairs = do
  let inputMap = Map.fromList inputPairs
      totalIn = sum $ map (txOutValue . snd) inputPairs
      totalOut = sum $ map txOutValue (txOutputs tx)

  -- Check fee is positive
  if totalIn < totalOut
    then return $ Left ErrInsufficientFee
    else do
      let baseFee = totalIn - totalOut
          vsize = calculateVSize tx
      -- W96: modified-fee comes from any active PrioritiseTransaction
      -- delta on this txid. Bitcoin Core stores the delta in
      -- mapDeltas and applies it as `modified_fees = base_fees + delta`
      -- in Workspace::m_modified_fees (validation.cpp:930). Without this
      -- lookup, prioritised txs would still be filtered by the min-relay
      -- fee gate against their base fee, defeating the whole point of
      -- PrioritiseTransaction.
      feeDeltas <- readTVarIO (mpFeeDeltas mp)
      let delta = Map.findWithDefault 0 txid feeDeltas
          -- Saturating add: negative delta cannot make modifiedFee go
          -- below zero (Word64).
          modifiedFee :: Word64
          modifiedFee
            | delta >= 0 = baseFee + fromIntegral delta
            | otherwise =
                let absD = fromIntegral (negate delta) :: Word64
                in if absD > baseFee then 0 else baseFee - absD
          fee = baseFee  -- preserve historical name for the body
          feeRate = calculateFeeRate modifiedFee vsize

      -- Check minimum fee rate (uses modified fee — Core parity).
      if feeRate < mpcMinFeeRate (mpConfig mp)
        then return $ Left (ErrFeeBelowMinimum feeRate (mpcMinFeeRate (mpConfig mp)))
        else
          -- W96 Gate (client-maxfeerate): mirrors Bitcoin Core
          -- validation.cpp:1368
          --   if (args.m_client_maxfeerate &&
          --       CFeeRate(ws.m_modified_fees, ws.m_vsize) > *args.m_client_maxfeerate)
          --       → "max feerate exceeded"
          -- Without this, sendrawtransaction's `maxfeerate` parameter
          -- (default 0.10 BTC/kvB in Core) has no effect — fee-bumping
          -- bugs in wallets can leak large fees into the mempool.
          case mpcMaxFeeRate (mpConfig mp) of
            Just cap | feeRate > cap ->
              return $ Left (ErrMaxFeeRateExceeded feeRate cap)
            _ ->
              -- W96 Gate: ValidateInputsStandardness (Bitcoin Core
              -- validation.cpp:896-901; policy.cpp:214).  Walks each
              -- input's prevout, classifies it, and rejects:
              --   * NONSTANDARD scriptPubKeys
              --     ("input N script unknown")
              --   * WITNESS_UNKNOWN scriptPubKeys
              --     ("input N witness program is undefined")
              --   * P2SH inputs whose redeem-script has more than
              --     MAX_P2SH_SIGOPS=15 sigops.
              -- Without this gate haskoin would relay txs that Core
              -- rejects (TX_INPUTS_NOT_STANDARD,
              -- "bad-txns-nonstandard-inputs").
              case validateInputsStandardness tx inputPairs of
                Left (idx, reason) ->
                  return $ Left (ErrInputsNotStandard idx reason)
                Right () -> do
                  -- IsWitnessStandard: check P2WSH stack limits, tapscript annex,
                  -- and witness-stuffing on P2A. Mirrors Bitcoin Core
                  -- validation.cpp:904 → IsWitnessStandard(tx, m_view).
                  let prevScripts = map (txOutScript . snd) inputPairs
                      witStacks   = txWitness tx
                  case Std.checkWitnessStandard tx prevScripts witStacks of
                    Left wsErr -> return $ Left (ErrNonStandard (renderWitnessStdReason wsErr))
                    Right () ->
                      -- W96 Gate (PreCheckEphemeralTx): a tx with any dust output
                      -- must pay zero fee.  Bitcoin Core
                      -- policy/ephemeral_policy.cpp:23-31:
                      --   if ((base_fee != 0 || mod_fee != 0)
                      --       && !GetDust(tx, dust_relay_rate).empty())
                      --     → "dust" / "tx with dust output must be 0-fee".
                      -- Before this fix `checkEphemeralPreCheck` was only invoked
                      -- via the package path and only checked zero-value P2A
                      -- anchor outputs — general dust on a single-tx submission
                      -- bypassed the gate entirely.  We now run the full
                      -- Core-equivalent check here using
                      -- `Std.isDust` + `dustRelayTxFee`.
                      case generalEphemeralPreCheck tx modifiedFee of
                        Left dustIdx -> return $
                          Left (ErrNonStandard ("dust (output " ++ show dustIdx ++ ")"))
                        Right () ->
                          -- Also retain the P2A-anchor multiplicity check (only
                          -- one anchor per tx).
                          case checkEphemeralPreCheck tx fee of
                            Left ephErr ->
                              return $ Left (ErrEphemeralViolation ephErr)
                            Right () -> do
                              -- MAX_STANDARD_TX_SIGOPS_COST check
                              -- (Bitcoin Core validation.cpp:908,941-943).
                              tipHeight <- readTVarIO (mpHeight mp)
                              let sigopFlags = consensusFlagsAtHeight (mpNetwork mp) (tipHeight + 1)
                                  SigOpCost txSigOpCost = getTransactionSigOpCost tx inputMap sigopFlags
                              if txSigOpCost > maxStandardTxSigOpsCost
                                then return $ Left (ErrNonStandard "bad-txns-too-many-sigops")
                                else do
                                  -- Verify scripts
                                  scriptResult <- verifyAllScripts mp tx inputMap
                                  case scriptResult of
                                    Left err -> return $ Left err
                                    Right () -> do
                                      -- Check ancestor/descendant limits
                                      ancestorResult <- checkAncestorLimits mp tx vsize
                                      case ancestorResult of
                                        Left err -> return $ Left err
                                        Right ancestors ->
                                          -- Check TRUC (v3) policy
                                          handleTruc mp tx txid fee vsize txSigOpCost ancestors

-- | Helper: run TRUC policy check and continue with addition.
-- Extracted to avoid extreme indentation in 'finalizeTransaction'.
handleTruc :: Mempool -> Tx -> TxId -> Word64 -> Int -> Int -> [MempoolEntry]
           -> IO (Either MempoolError TxId)
handleTruc mp tx txid fee vsize txSigOpCost ancestors = do
  trucResult <- checkTrucPolicy tx vsize mp
  case trucResult of
    Left trucErr@(TrucSiblingExists parentId _siblingId) -> do
      mParent <- getTransaction mp parentId
      case mParent of
        Just parent -> do
          evictResult <- attemptSiblingEviction tx fee vsize parent mp
          case evictResult of
            Left _ -> return $ Left (ErrTrucViolation trucErr)
            Right () -> continueAddTransaction mp tx txid fee vsize txSigOpCost ancestors
        Nothing -> return $ Left (ErrTrucViolation trucErr)
    Left trucErr -> return $ Left (ErrTrucViolation trucErr)
    Right _ -> continueAddTransaction mp tx txid fee vsize txSigOpCost ancestors

-- | Continue adding a transaction after all checks pass
continueAddTransaction :: Mempool -> Tx -> TxId -> Word64 -> Int -> Int -> [MempoolEntry] -> IO (Either MempoolError TxId)
continueAddTransaction mp tx txid fee vsize txSigOpCost ancestors = do
  -- Sigop-adjusted virtual size: if sigops inflate the effective weight beyond
  -- the raw BIP-141 weight, use the larger value for fee-rate and entry size.
  -- Mirrors GetVirtualTransactionSize(tx, nSigOpCost, m_opts.m_bytes_per_sigop)
  -- in bitcoin-core/src/policy/policy.cpp:400-403.
  -- The unadjusted `vsize` (weight-only) was used for the min-relay-fee gate;
  -- the adjusted `adjVsize` is what Core stores and uses for fee-rate comparisons.
  let adjVsize = calculateAdjustedVSize tx txSigOpCost
      feeRate = calculateFeeRate fee adjVsize
  -- Build and insert the entry
  now <- round <$> getPOSIXTime
  height <- readTVarIO (mpHeight mp)
  let rbfOptIn = signalsOptInRBF tx
      -- Ancestor counts include this transaction (self is included in all ancestor_ fields)
      ancestorCount = length ancestors + 1
      ancestorSize = sum (map meSize ancestors) + adjVsize
      ancestorFees = sum (map meFee ancestors) + fee
      -- meAncestorSigOps accumulates ancestors' own sigop costs plus self.
      -- Each ancestor's meAncestorSigOps already includes that ancestor's
      -- own sigop cost; we add only self's cost to avoid double-counting.
      -- Reference: Bitcoin Core CTxMemPool nAncestorSigOpCost tracking.
      ancestorSigOps = sum (map meAncestorSigOps ancestors) + txSigOpCost
      wtxid = computeWtxid tx
      entry = MempoolEntry
        { meTransaction = tx
        , meTxId = txid
        , meWtxid = wtxid
        , meFee = fee
        , meFeeRate = feeRate
        , meSize = adjVsize
        , meTime = now
        , meHeight = height
        , meAncestorCount = ancestorCount
        , meAncestorSize = ancestorSize
        , meAncestorFees = ancestorFees
        , meAncestorSigOps = ancestorSigOps
        , meDescendantCount = 1  -- includes self
        , meDescendantSize = adjVsize  -- includes self
        , meDescendantFees = fee  -- includes self
        , meRBFOptIn = rbfOptIn
        }

  -- Insert atomically (BIP-339 dual index: txid + wtxid stay in sync)
  atomically $ do
    modifyTVar' (mpEntries mp) (Map.insert txid entry)
    modifyTVar' (mpByWtxid mp) (Map.insert wtxid txid)
    forM_ (txInputs tx) $ \inp ->
      modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput inp) txid)
    modifyTVar' (mpByFeeRate mp) (Map.insert (feeRate, txid) ())
    modifyTVar' (mpSize mp) (+ adjVsize)

  -- Update ancestor entries with new descendant
  atomically $ forM_ ancestors $ \anc ->
    modifyTVar' (mpEntries mp) $ Map.adjust
      (\e -> e { meDescendantCount = meDescendantCount e + 1
               , meDescendantSize = meDescendantSize e + adjVsize
               , meDescendantFees = meDescendantFees e + fee
               }) (meTxId anc)

  -- Evict if mempool is too large
  totalSize <- readTVarIO (mpSize mp)
  when (totalSize > mpcMaxSize (mpConfig mp)) $
    evictLowestFee mp

  return $ Right txid

-- | Resolve all inputs of a transaction
-- Returns the OutPoint -> TxOut mapping, or an error
resolveInputs :: Mempool -> Tx -> IO (Either MempoolError [(OutPoint, TxOut)])
resolveInputs mp tx = do
  results <- forM (txInputs tx) $ \inp -> do
    let op = txInPrevOutput inp
    resolveInput mp op
  return $ sequence results

-- | Resolve a single input, checking UTXO set and mempool
resolveInput :: Mempool -> OutPoint -> IO (Either MempoolError (OutPoint, TxOut))
resolveInput mp op = do
  -- First check UTXO set
  mUtxo <- lookupUTXO (mpUTXOCache mp) op
  case mUtxo of
    Just entry -> do
      -- Check coinbase maturity
      height <- readTVarIO (mpHeight mp)
      if ueCoinbase entry && height - ueHeight entry < fromIntegral coinbaseMaturity
        then return $ Left (ErrCoinbaseNotMature (ueHeight entry) height)
        else return $ Right (op, ueOutput entry)
    Nothing -> do
      -- Check if spent by another mempool tx (conflict)
      mSpender <- atomically $ Map.lookup op <$> readTVar (mpByOutpoint mp)
      case mSpender of
        Just conflictTxId ->
          if mpcRBFEnabled (mpConfig mp)
            then return $ Left (ErrInputSpentInMempool conflictTxId)
            else return $ Left (ErrInputSpentInMempool conflictTxId)
        Nothing -> do
          -- Check if output of another mempool tx (chained unconfirmed)
          entries <- readTVarIO (mpEntries mp)
          let prevTxId = outPointHash op
              prevIdx = outPointIndex op
          case Map.lookup prevTxId entries of
            Just prevEntry ->
              let prevTx = meTransaction prevEntry
                  outputs = txOutputs prevTx
              in if fromIntegral prevIdx < length outputs
                 then return $ Right (op, outputs !! fromIntegral prevIdx)
                 else return $ Left (ErrMissingInput op)
            Nothing -> return $ Left (ErrMissingInput op)

-- | Verify all scripts for a transaction.
--
-- Pre-collects per-input prevouts (amounts + scriptPubKeys) before
-- verifying each input so Taproot's BIP-341 @sha_amounts@ /
-- @sha_scriptpubkeys@ commitments can be computed correctly. Falls
-- back to script-only behaviour for legacy / SegWit-v0 inputs.
verifyAllScripts :: Mempool -> Tx -> Map OutPoint TxOut -> IO (Either MempoolError ())
verifyAllScripts mp tx inputMap = do
  -- First pass: resolve every input's prevout, fail fast on missing.
  let resolveAll = traverse
        (\inp -> case Map.lookup (txInPrevOutput inp) inputMap of
            Nothing -> Left (ErrMissingInput (txInPrevOutput inp))
            Just prevOut -> Right prevOut)
        (txInputs tx)
  case resolveAll of
    Left err -> return $ Left err
    Right prevs -> do
      -- Use consensus flags for the next block height (mempool admission standard).
      height <- readTVarIO (mpHeight mp)
      let cflags = consensusFlagsAtHeight (mpNetwork mp) (height + 1)
          scriptFlags = consensusFlagsToScriptFlags cflags
          spentAmounts = map txOutValue prevs
          spentScripts = map txOutScript prevs
          indexed = zip [0..] prevs
      results <- forM indexed $ \(idx, prevOut) ->
        case Script.verifyScriptWithFlags scriptFlags tx idx
               (txOutScript prevOut) (txOutValue prevOut)
               spentAmounts spentScripts of
          Left err -> return $ Left (ErrScriptVerificationFailed err)
          Right False -> return $ Left (ErrScriptVerificationFailed "Script returned false")
          Right True -> return $ Right ()
      return $ sequence_ results

-- | Check ancestor, descendant, and cluster size limits.
-- Returns the list of ancestors on success.
--
-- This function enforces both the traditional ancestor/descendant limits
-- (for backward compatibility) and the newer cluster size limit of 101 txs.
-- The ancestor count includes the transaction itself.
checkAncestorLimits :: Mempool -> Tx -> Int -> IO (Either MempoolError [MempoolEntry])
checkAncestorLimits mp tx txVsize = do
  ancestors <- getAncestorsRecursive mp tx
  entries <- readTVarIO (mpEntries mp)
  byOutpoint <- readTVarIO (mpByOutpoint mp)
  let config = mpConfig mp
      -- Ancestor count includes this transaction (+1)
      ancestorCount = length ancestors + 1
      ancestorSize = sum (map meSize ancestors) + txVsize

  -- First, check the new cluster size limit (replaces ancestor/descendant limits)
  -- Pass txVsize so the vbytes gate is also enforced.
  case checkClusterLimit tx entries byOutpoint txVsize of
    Left (ClusterLimitExceeded actual maxSize) ->
      return $ Left (ErrClusterLimitExceeded actual maxSize)
    Left (ClusterSizeExceeded actualVb maxVb) ->
      return $ Left (ErrClusterLimitExceeded actualVb maxVb)
    Right () -> do
      -- Also check traditional ancestor count limit for backward compatibility
      if ancestorCount > mpcMaxAncestors config
        then return $ Left (ErrTooManyAncestors ancestorCount (mpcMaxAncestors config))
        else do
          -- Check ancestor size limit
          if fromIntegral ancestorSize > mpcMaxAncestorSize config
            then return $ Left (ErrAncestorSizeTooLarge (fromIntegral ancestorSize) (mpcMaxAncestorSize config))
            else do
              -- Check that adding this tx won't violate descendant limits for any ancestor
              -- Each ancestor's new descendant count = meDescendantCount + 1 (this tx)
              -- Each ancestor's new descendant size = meDescendantSize + txVsize
              let descendantViolation = any (wouldViolateDescendantLimit config txVsize) ancestors
              if descendantViolation
                then do
                  -- Find the worst violation for the error message
                  let findWorstDescCount = maximum $ map (\a -> meDescendantCount a + 1) ancestors
                  return $ Left (ErrTooManyDescendants findWorstDescCount (mpcMaxDescendants config))
                else return $ Right ancestors
  where
    wouldViolateDescendantLimit :: MempoolConfig -> Int -> MempoolEntry -> Bool
    wouldViolateDescendantLimit cfg vsize entry =
      let newDescCount = meDescendantCount entry + 1
          newDescSize = fromIntegral (meDescendantSize entry) + fromIntegral vsize
      in newDescCount > mpcMaxDescendants cfg ||
         newDescSize > mpcMaxDescendantSize cfg

--------------------------------------------------------------------------------
-- Transaction Removal
--------------------------------------------------------------------------------

-- | Remove a transaction from the mempool
-- Updates descendant counts for all ancestors and ancestor counts for all descendants
removeTransaction :: Mempool -> TxId -> IO ()
removeTransaction mp txid = do
  -- First, get the entry and its related transactions before modifying anything
  mEntry <- atomically $ Map.lookup txid <$> readTVar (mpEntries mp)
  case mEntry of
    Nothing -> return ()
    Just entry -> do
      -- Get ancestors to update their descendant counts
      ancestors <- getAncestorsOfEntry mp entry
      -- Get descendants to update their ancestor counts
      descendants <- getDescendantsOfEntry mp txid

      let vsize = meSize entry
          fee = meFee entry

      atomically $ do
        -- Remove from main index
        modifyTVar' (mpEntries mp) (Map.delete txid)
        -- Remove from wtxid dual index (BIP-339)
        modifyTVar' (mpByWtxid mp) (Map.delete (meWtxid entry))
        -- Remove from outpoint index
        forM_ (txInputs (meTransaction entry)) $ \inp ->
          modifyTVar' (mpByOutpoint mp) (Map.delete (txInPrevOutput inp))
        -- Remove from fee rate index
        modifyTVar' (mpByFeeRate mp) (Map.delete (meFeeRate entry, txid))
        -- Update size
        modifyTVar' (mpSize mp) (subtract vsize)

        -- Update descendant counts for all ancestors
        forM_ ancestors $ \anc ->
          modifyTVar' (mpEntries mp) $ Map.adjust
            (\e -> e { meDescendantCount = meDescendantCount e - 1
                     , meDescendantSize = meDescendantSize e - vsize
                     , meDescendantFees = meDescendantFees e - fee
                     }) (meTxId anc)

        -- Update ancestor counts for all descendants
        forM_ descendants $ \desc ->
          modifyTVar' (mpEntries mp) $ Map.adjust
            (\e -> e { meAncestorCount = meAncestorCount e - 1
                     , meAncestorSize = meAncestorSize e - vsize
                     , meAncestorFees = meAncestorFees e - fee
                     }) (meTxId desc)

-- | Get ancestors of a mempool entry (helper for removal)
getAncestorsOfEntry :: Mempool -> MempoolEntry -> IO [MempoolEntry]
getAncestorsOfEntry mp entry =
  getAncestorsRecursive mp (meTransaction entry)

-- | Get descendants of a transaction (helper for removal)
-- Does not include the transaction itself
getDescendantsOfEntry :: Mempool -> TxId -> IO [MempoolEntry]
getDescendantsOfEntry mp txid = do
  byOutpoint <- readTVarIO (mpByOutpoint mp)
  entries <- readTVarIO (mpEntries mp)

  let go :: Set TxId -> [TxId] -> [MempoolEntry]
      go _ [] = []
      go visited (t:rest)
        | t == txid = go visited rest  -- Skip the original tx
        | Set.member t visited = go visited rest
        | otherwise = case Map.lookup t entries of
            Nothing -> go visited rest
            Just e ->
              let tx = meTransaction e
                  outputOps = [ OutPoint t (fromIntegral i)
                              | i <- [0 .. length (txOutputs tx) - 1] ]
                  childIds = mapMaybe (`Map.lookup` byOutpoint) outputOps
                  newVisited = Set.insert t visited
              in e : go newVisited (childIds ++ rest)

  -- Start from the children of txid
  case Map.lookup txid entries of
    Nothing -> return []
    Just entry -> do
      let tx = meTransaction entry
          outputOps = [ OutPoint txid (fromIntegral i)
                      | i <- [0 .. length (txOutputs tx) - 1] ]
          childIds = mapMaybe (`Map.lookup` byOutpoint) outputOps
      return $ go Set.empty childIds

-- | Remove a transaction and all its descendants
removeWithDescendants :: Mempool -> TxId -> IO ()
removeWithDescendants mp txid = do
  descendants <- getDescendants mp txid
  -- Remove descendants first (in reverse order - children before parents)
  forM_ (reverse descendants) $ removeTransaction mp . meTxId
  removeTransaction mp txid

--------------------------------------------------------------------------------
-- Lookup Operations
--------------------------------------------------------------------------------

-- | Get a transaction from the mempool by TxId
getTransaction :: Mempool -> TxId -> IO (Maybe MempoolEntry)
getTransaction mp txid =
  atomically $ Map.lookup txid <$> readTVar (mpEntries mp)

-- | Get all transaction IDs in the mempool
getMempoolTxIds :: Mempool -> IO [TxId]
getMempoolTxIds mp =
  atomically $ Map.keys <$> readTVar (mpEntries mp)

-- | Get all witness transaction IDs (wtxids) in the mempool.
-- BIP-339 callers (e.g. wtxid-relay 'inv') use this to enumerate
-- announcements without re-deriving wtxids from cached transactions.
getMempoolWtxids :: Mempool -> IO [Wtxid]
getMempoolWtxids mp =
  atomically $ Map.keys <$> readTVar (mpByWtxid mp)

-- | Look up a mempool entry by witness transaction id (BIP-339).
-- Returns Nothing if the wtxid is not in the dual index.
getTransactionByWtxid :: Mempool -> Wtxid -> IO (Maybe MempoolEntry)
getTransactionByWtxid mp wtxid = atomically $ do
  byW <- readTVar (mpByWtxid mp)
  case Map.lookup wtxid byW of
    Nothing   -> return Nothing
    Just txid -> Map.lookup txid <$> readTVar (mpEntries mp)

-- | Resolve a wtxid to its txid (without fetching the full entry).
txIdForWtxid :: Mempool -> Wtxid -> IO (Maybe TxId)
txIdForWtxid mp wtxid =
  atomically $ Map.lookup wtxid <$> readTVar (mpByWtxid mp)

-- | Get mempool size (count, total vsize)
getMempoolSize :: Mempool -> IO (Int, Int)
getMempoolSize mp = atomically $ do
  entries <- readTVar (mpEntries mp)
  size <- readTVar (mpSize mp)
  return (Map.size entries, size)

-- | Get mempool info (count, size, bytes, fee stats)
getMempoolInfo :: Mempool -> IO (Int, Int, Word64, Word64)
getMempoolInfo mp = atomically $ do
  entries <- readTVar (mpEntries mp)
  size <- readTVar (mpSize mp)
  let entryList = Map.elems entries
      totalFees = sum $ map meFee entryList
      minFee = if null entryList then 0 else minimum $ map meFee entryList
  return (Map.size entries, size, totalFees, minFee)

-- | Get the effective minimum fee rate for mempool acceptance (sat/kvB).
-- Returns the maximum of:
--   1. The decayed rolling minimum (bumped by size-limit evictions)
--   2. The static configured minimum relay fee rate
-- The returned value is in sat/kvB for BIP133 feefilter compatibility.
-- Mirrors CTxMemPool::GetMinFee (txmempool.cpp:829-851).
getMempoolMinFeeRate :: Mempool -> IO Word64
getMempoolMinFeeRate mp = do
  rollingKvb <- getMempoolMinFeeRateDecayed mp
  let FeeRate minRate = mpcMinFeeRate (mpConfig mp)
      staticKvb = fromIntegral minRate * 1000  -- sat/vB → sat/kvB
  return (max rollingKvb staticKvb)

--------------------------------------------------------------------------------
-- Ancestor/Descendant Tracking
--------------------------------------------------------------------------------

-- | Get direct unconfirmed ancestors of a transaction
getAncestors :: Mempool -> Tx -> IO [MempoolEntry]
getAncestors mp tx = do
  entries <- readTVarIO (mpEntries mp)
  let parentTxIds = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs tx)
      directParents = Map.elems $ Map.filterWithKey
        (\k _ -> Set.member k parentTxIds) entries
  return directParents

-- | Get all unconfirmed ancestors recursively
getAncestorsRecursive :: Mempool -> Tx -> IO [MempoolEntry]
getAncestorsRecursive mp tx = do
  entries <- readTVarIO (mpEntries mp)
  let go :: Set TxId -> [TxId] -> [MempoolEntry]
      go _ [] = []
      go visited (t:rest)
        | Set.member t visited = go visited rest
        | otherwise = case Map.lookup t entries of
            Nothing -> go visited rest
            Just entry ->
              let parentIds = map (outPointHash . txInPrevOutput) (txInputs (meTransaction entry))
                  newVisited = Set.insert t visited
              in entry : go newVisited (parentIds ++ rest)

      parentIds = map (outPointHash . txInPrevOutput) (txInputs tx)
  return $ go Set.empty parentIds

-- | Set of in-mempool ancestor txids for an *unconfirmed* (not yet
-- inserted) transaction.  Wrapper around 'getAncestorsRecursive' that
-- returns the txids rather than full entries.  Used by W96
-- EntriesAndTxidsDisjoint to detect a replacement whose ancestor set
-- intersects the conflict set.
--
-- Reference: Bitcoin Core validation.cpp:1356
--   if (const auto err_string{EntriesAndTxidsDisjoint(ancestors,
--                                                     ws.m_conflicts,
--                                                     ptx->GetHash())})
ancestorTxIdsForUnconfirmedTx :: Mempool -> Tx -> IO (Set TxId)
ancestorTxIdsForUnconfirmedTx mp tx = do
  ancEntries <- getAncestorsRecursive mp tx
  return $ Set.fromList (map meTxId ancEntries)

-- | Get direct descendants of a transaction
getDescendants :: Mempool -> TxId -> IO [MempoolEntry]
getDescendants mp txid = do
  byOutpoint <- readTVarIO (mpByOutpoint mp)
  entries <- readTVarIO (mpEntries mp)
  case Map.lookup txid entries of
    Nothing -> return []
    Just entry -> do
      let tx = meTransaction entry
          outputOps = [ OutPoint txid (fromIntegral i)
                      | i <- [0 .. length (txOutputs tx) - 1] ]
          childTxIds = mapMaybe (`Map.lookup` byOutpoint) outputOps
      return $ mapMaybe (`Map.lookup` entries) childTxIds

-- | Get all descendants recursively
getDescendantsRecursive :: Mempool -> TxId -> IO [MempoolEntry]
getDescendantsRecursive mp txid = do
  byOutpoint <- readTVarIO (mpByOutpoint mp)
  entries <- readTVarIO (mpEntries mp)

  let go :: Set TxId -> [TxId] -> [MempoolEntry]
      go _ [] = []
      go visited (t:rest)
        | Set.member t visited = go visited rest
        | otherwise = case Map.lookup t entries of
            Nothing -> go visited rest
            Just entry ->
              let tx = meTransaction entry
                  outputOps = [ OutPoint t (fromIntegral i)
                              | i <- [0 .. length (txOutputs tx) - 1] ]
                  childIds = mapMaybe (`Map.lookup` byOutpoint) outputOps
                  newVisited = Set.insert t visited
              in entry : go newVisited (childIds ++ rest)

  return $ go Set.empty [txid]

--------------------------------------------------------------------------------
-- Conflict Detection
--------------------------------------------------------------------------------

-- | Get all transactions that conflict with the given transaction
-- (spend the same inputs)
getConflicts :: Mempool -> Tx -> IO [TxId]
getConflicts mp tx = do
  byOutpoint <- readTVarIO (mpByOutpoint mp)
  let inputOps = map txInPrevOutput (txInputs tx)
      conflicts = mapMaybe (`Map.lookup` byOutpoint) inputOps
  return $ Set.toList $ Set.fromList conflicts

--------------------------------------------------------------------------------
-- Full RBF (Replace-by-Fee)
--------------------------------------------------------------------------------

-- | Check if a mempool transaction is RBF-replaceable
-- In full RBF mode (Bitcoin Core v28+), ALL mempool transactions are replaceable
-- This function checks both direct RBF signaling and ancestor signaling
isRbfReplaceable :: Mempool -> TxId -> IO Bool
isRbfReplaceable mp txid = do
  -- In full RBF mode, all mempool transactions are replaceable
  if mpcRBFEnabled (mpConfig mp)
    then do
      entries <- readTVarIO (mpEntries mp)
      return $ Map.member txid entries
    else do
      -- Legacy mode: check if transaction or any ancestor signals RBF
      entries <- readTVarIO (mpEntries mp)
      case Map.lookup txid entries of
        Nothing -> return False
        Just entry -> do
          if meRBFOptIn entry
            then return True
            else do
              -- Check ancestors for RBF signaling
              ancestors <- getAncestorsRecursive mp (meTransaction entry)
              return $ any meRBFOptIn ancestors

-- | BIP-125 Gate 2: check that every directly-conflicting transaction is
-- RBF-replaceable under legacy BIP-125 rules.  A conflicting tx is replaceable
-- if it or any of its in-mempool ancestors has meRBFOptIn set
-- (nSequence <= 0xfffffffd on at least one input).
--
-- This mirrors bitcoin-core/src/policy/rbf.cpp:IsRBFOptIn, which first tests
-- the tx itself (SignalsOptInRBF) then walks CalculateMemPoolAncestors.
-- Called only when mpcRBFEnabled is False (full-RBF is off).
checkAllConflictsRbfReplaceable :: Mempool -> [TxId] -> IO Bool
checkAllConflictsRbfReplaceable mp conflictTxIds = do
  results <- forM conflictTxIds $ \txid -> isRbfReplaceable mp txid
  return $ and results

-- | Get all transactions that would be evicted by a replacement
-- This includes direct conflicts and all their descendants
getConflictSet :: Mempool -> [TxId] -> IO [MempoolEntry]
getConflictSet mp conflictTxIds = do
  entries <- readTVarIO (mpEntries mp)
  -- Get direct conflicts
  let directConflicts = mapMaybe (`Map.lookup` entries) conflictTxIds
  -- Get all descendants of each conflict
  descendantLists <- forM conflictTxIds $ \txid ->
    getDescendantsRecursive mp txid
  -- Combine and deduplicate by TxId
  let allDescendants = concat descendantLists
      allEntries = directConflicts ++ allDescendants
      allEvictions = Map.elems $ Map.fromList
        [(meTxId e, e) | e <- allEntries]
  return allEvictions

-- | Check if a replacement transaction satisfies RBF rules
-- Rules implemented:
--   Rule 3: New tx must pay >= sum of fees of ALL evicted txs (conflicts + descendants)
--           bitcoin-core/src/validation.cpp:1005-1010 — PaysForRBF receives the
--           accumulated fee over the full all_conflicts set (not just direct conflicts).
--   Rule 3a: New tx feerate must be higher than all directly conflicting txs (full RBF)
--   Rule 4: Additional fee must pay for replacement's bandwidth (incremental relay fee)
--           Rule 4 also compares against ALL evictions, matching Core Rule 3 baseline.
--   Rule 5: Cannot evict more than 100 transactions total (conflicts + descendants)
--           bitcoin-core/src/policy/rbf.h:MAX_REPLACEMENT_CANDIDATES = 100
checkReplacement :: Tx                -- ^ New replacement transaction
                 -> [MempoolEntry]    -- ^ Direct conflicting transactions
                 -> [MempoolEntry]    -- ^ All transactions to evict (conflicts + descendants)
                 -> Word64            -- ^ New transaction fee
                 -> Int               -- ^ New transaction vsize
                 -> FeeRate           -- ^ New transaction feerate
                 -> Either RbfError ()
checkReplacement _tx directConflicts allEvictions newFee newVsize newFeeRate = do
  -- Rule 5: Check eviction count limit
  -- bitcoin-core/src/policy/rbf.cpp:70 — GetEntriesForConflicts checks cluster count <= 100
  let evictionCount = length allEvictions
  when (evictionCount > maxReplacementEvictions) $
    Left $ RbfTooManyEvictions evictionCount maxReplacementEvictions

  -- Rule 3a: New tx feerate must be strictly greater than the feerate of every
  -- directly-conflicting transaction.
  -- bitcoin-core/src/validation.cpp:1018-1026 — PaysMoreThanConflicts:
  --   "New feerate must exceed the feerate of each conflicting transaction."
  -- We find the maximum feerate among direct conflicts and compare.
  case directConflicts of
    [] -> pure ()  -- no direct conflicts: nothing to compare (defensive)
    cs -> do
      let maxConflictFeeRate = maximum (map meFeeRate cs)
      when (newFeeRate <= maxConflictFeeRate) $
        Left $ RbfInsufficientFeeRate newFeeRate maxConflictFeeRate

  -- Rule 3: New tx must pay at least as much as the sum of fees of ALL evicted txs.
  -- Bitcoin Core sums over the entire all_conflicts set (direct conflicts + descendants):
  --   validation.cpp:1005: for (it : all_conflicts) { m_conflicting_fees += it->GetModifiedFee(); }
  --   validation.cpp:1010: PaysForRBF(m_conflicting_fees, ...)
  -- Using only directConflicts here would allow a replacement that pays less than
  -- the total fee removed from the mempool — a DoS vector.
  let conflictTotalFee = sum $ map meFee allEvictions

  -- Rule 3: replacement fees >= original fees (all evictions)
  when (newFee < conflictTotalFee) $
    Left $ RbfInsufficientAbsoluteFee newFee conflictTotalFee

  -- Rule 4: Additional fee must cover bandwidth cost of new tx
  -- Formula: (newFee - conflictFee) >= incrementalRelayFee * newVsize / 1000
  -- bitcoin-core/src/policy/rbf.cpp:117-123
  let additionalFee = newFee - conflictTotalFee
      -- incrementalRelayFeePerKvb is in sat/kvB (1000 sat/kvB = 1 sat/vB)
      requiredRelayFee = (incrementalRelayFeePerKvb * fromIntegral newVsize) `div` 1000
  when (additionalFee < requiredRelayFee) $
    Left $ RbfInsufficientRelayFee additionalFee requiredRelayFee

  Right ()

-- | Check that the replacement tx doesn't spend any of the conflicting txs' outputs
-- This would create a dependency on a tx we're about to remove
checkNoConflictSpending :: Tx -> Set TxId -> Either RbfError ()
checkNoConflictSpending tx conflictTxIds = do
  let spendsTxIds = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs tx)
      intersection = Set.intersection spendsTxIds conflictTxIds
  case Set.toList intersection of
    [] -> Right ()
    (txid:_) -> Left $ RbfSpendingConflict txid

-- | BIP-125 Rule 2: replacement may not introduce *new* unconfirmed inputs.
--
-- The replacement transaction may only spend inputs that are either
-- (a) already confirmed (i.e. not currently in the mempool), or
-- (b) outpoints that were already being spent by one of the transactions
--     being replaced (the @oldUnconfirmedSpends@ set, populated by the
--     caller from the to-be-evicted entries).
--
-- This prevents an attacker from juggling unconfirmed parents in a
-- replacement to side-step the joint replacement-fee accounting that
-- Bitcoin Core enforces in legacy BIP-125 mode. Mirrors the legacy check
-- documented in @bitcoin-core/src/wallet/feebumper.cpp@ ("We cannot source
-- new unconfirmed inputs (bip125 rule 2)") and the per-impl reference
-- implementations in @lunarblock/src/mempool.lua@ and
-- @ouroboros/src/ouroboros/mempool.py@.
--
-- Parameters:
--
-- * The replacement transaction.
-- * The set of @TxId@s currently in the mempool (for "is unconfirmed?" check).
-- * The set of outpoints that the conflicting (to-evict) txs already spent.
--
-- Returns @Right ()@ on success, or @Left (RbfNewUnconfirmedInput parent)@
-- with the offending parent txid.
checkNoNewUnconfirmedInputs :: Tx
                            -> Set TxId          -- ^ Mempool txid set (currently unconfirmed)
                            -> Set OutPoint      -- ^ Outpoints already being spent by conflicts
                            -> Either RbfError ()
checkNoNewUnconfirmedInputs tx mempoolTxIds oldUnconfirmedSpends =
  let go [] = Right ()
      go (inp:rest) =
        let op       = txInPrevOutput inp
            parent   = outPointHash op
            -- Confirmed inputs are always fine (parent not in mempool).
            isUnconfirmed = Set.member parent mempoolTxIds
            -- Already-known spends (i.e. spent by a tx being replaced) are fine.
            wasKnown      = Set.member op oldUnconfirmedSpends
        in if isUnconfirmed && not wasKnown
             then Left $ RbfNewUnconfirmedInput parent
             else go rest
  in go (txInputs tx)

-- | Remove all conflicting transactions and their descendants
-- This is called after successful replacement validation
removeConflicts :: Set TxId -> Mempool -> IO ()
removeConflicts conflictTxIds mp = do
  -- Get all entries to remove (conflicts + descendants)
  allEvictions <- getConflictSet mp (Set.toList conflictTxIds)

  -- Remove in reverse order (descendants first) to maintain consistency
  -- Sort by descendant count descending to remove leaves first
  let sortedEvictions = sortBy (comparing (Down . meDescendantCount)) allEvictions

  forM_ sortedEvictions $ \entry ->
    removeTransaction mp (meTxId entry)

-- | Attempt to replace conflicting transactions with a new transaction
-- This implements full RBF as in Bitcoin Core v28+
attemptReplacement :: Mempool
                   -> Tx
                   -> TxId
                   -> [TxId]         -- ^ Direct conflict TxIds
                   -> Word64         -- ^ New tx fee
                   -> Int            -- ^ New tx vsize
                   -> FeeRate        -- ^ New tx feerate
                   -> IO (Either MempoolError ())
attemptReplacement mp tx _txid conflictTxIds newFee newVsize newFeeRate = do
  entries <- readTVarIO (mpEntries mp)

  -- Get direct conflict entries
  let directConflicts = mapMaybe (`Map.lookup` entries) conflictTxIds

  -- Get all entries that would be evicted
  allEvictions <- getConflictSet mp conflictTxIds

  -- Check that new tx doesn't spend any conflicting tx outputs
  let conflictSet = Set.fromList conflictTxIds
  case checkNoConflictSpending tx conflictSet of
    Left (RbfSpendingConflict txid) ->
      return $ Left $ ErrRBFSpendingConflict txid
    Left _ -> return $ Left $ ErrRBFSpendingConflict (head conflictTxIds)
    Right () -> do
      -- BIP-125 Rule 2: no new unconfirmed inputs.
      -- Build the set of outpoints already spent by the to-be-evicted txs
      -- (direct conflicts + their descendants), and the set of currently-in-
      -- mempool txids. Inputs that point to a confirmed tx (not in
      -- @mempoolTxIds@) or to an outpoint already in @oldSpends@ are fine.
      let mempoolTxIds = Map.keysSet entries
          oldSpends    = Set.fromList
            [ txInPrevOutput inp
            | e <- allEvictions
            , inp <- txInputs (meTransaction e)
            ]
      case checkNoNewUnconfirmedInputs tx mempoolTxIds oldSpends of
        Left (RbfNewUnconfirmedInput parent) ->
          return $ Left $ ErrRBFNewUnconfirmedInput parent
        Left _ ->
          -- Defensive: checkNoNewUnconfirmedInputs only returns RbfNewUnconfirmedInput.
          return $ Left $ ErrRBFNewUnconfirmedInput (head conflictTxIds)
        Right () ->
          -- Apply RBF rules 3, 3a, 4, 5
          case checkReplacement tx directConflicts allEvictions newFee newVsize newFeeRate of
            Left (RbfInsufficientAbsoluteFee newF reqF) ->
              return $ Left $ ErrRBFInsufficientAbsoluteFee newF reqF
            Left (RbfInsufficientFeeRate newR minR) ->
              return $ Left $ ErrRBFInsufficientFeeRate newR minR
            Left (RbfTooManyEvictions count maxC) ->
              return $ Left $ ErrRBFTooManyReplacements count maxC
            Left (RbfInsufficientRelayFee addF reqF) ->
              return $ Left $ ErrRBFInsufficientRelayFee addF reqF
            Left (RbfSpendingConflict txid) ->
              return $ Left $ ErrRBFSpendingConflict txid
            Left (RbfNewUnconfirmedInput parent) ->
              return $ Left $ ErrRBFNewUnconfirmedInput parent
            Right () ->
              -- BUG-9 fix: Wire checkDiagramReplacement (ImprovesFeerateDiagram).
              -- Bitcoin Core v28+ requires that the replacement strictly improves
              -- the mempool feerate diagram (validation.cpp:1031-1044).
              case checkDiagramReplacement allEvictions newFee newVsize newFeeRate of
                Left (RbfInsufficientAbsoluteFee newF reqF) ->
                  return $ Left $ ErrRBFInsufficientAbsoluteFee newF reqF
                Left _ ->
                  -- checkDiagramReplacement only emits RbfInsufficientAbsoluteFee;
                  -- defensive case for future constructor additions.
                  return $ Left $ ErrRBFInsufficientAbsoluteFee newFee 0
                Right () -> do
                  -- Remove all conflicting transactions and descendants
                  removeConflicts conflictSet mp
                  return $ Right ()

--------------------------------------------------------------------------------
-- Block Connection/Disconnection
--------------------------------------------------------------------------------

-- | Handle a newly connected block
-- Removes confirmed transactions and any transactions that conflict
blockConnected :: Mempool -> Block -> IO ()
blockConnected mp block = do
  -- Get all confirmed transaction IDs
  let confirmedTxIds = Set.fromList $ map computeTxId (blockTxns block)

  -- Remove confirmed transactions
  forM_ (Set.toList confirmedTxIds) $ removeTransaction mp

  -- Find and remove conflicting transactions
  let spentByBlock = Set.fromList
        [ txInPrevOutput inp
        | tx <- tail (blockTxns block)  -- Skip coinbase
        , inp <- txInputs tx
        ]

  entries <- readTVarIO (mpEntries mp)
  forM_ (Map.toList entries) $ \(txid, entry) -> do
    let txSpends = Set.fromList $ map txInPrevOutput (txInputs (meTransaction entry))
    unless (Set.null $ Set.intersection txSpends spentByBlock) $
      removeWithDescendants mp txid

  -- Update chain height and MTP (BIP-113).
  -- Prepend the new block's timestamp to the rolling window (capped at 11),
  -- then recompute the median so that IsFinalTx at mempool admit uses the
  -- correct MTP of the new tip, matching Bitcoin Core's CheckFinalTxAtTip.
  let ts = bhTimestamp (blockHeader block)
  atomically $ do
    modifyTVar' (mpHeight mp) (+ 1)
    modifyTVar' (mpRecentTimestamps mp) (\old -> take 11 (ts : old))
    timestamps <- readTVar (mpRecentTimestamps mp)
    writeTVar (mpMTP mp) (computeMTPFromList timestamps)
    -- Signal that a block has connected.  GetMinFee uses this flag to decide
    -- whether to apply exponential decay to the rolling minimum fee rate.
    -- Bitcoin Core: blockSinceLastRollingFeeBump = true (txmempool.cpp set in
    -- CTxMemPool::AddTransactionsUpdated, called from ConnectBlock).
    writeTVar (mpBlockSinceLastFeeBump mp) True

-- | Handle a disconnected block (during reorg)
-- Re-adds transactions from the disconnected block back to mempool
blockDisconnected :: Mempool -> Block -> IO ()
blockDisconnected mp block = do
  -- Decrease chain height and drop the disconnected block's timestamp from
  -- the MTP window. We drop the head (most-recent) and recompute.
  atomically $ do
    modifyTVar' (mpHeight mp) (subtract 1)
    modifyTVar' (mpRecentTimestamps mp) safeDropHead
    timestamps <- readTVar (mpRecentTimestamps mp)
    writeTVar (mpMTP mp) (computeMTPFromList timestamps)

  -- Re-add non-coinbase transactions
  -- (they may fail validation if inputs are now missing)
  forM_ (tail $ blockTxns block) $ \tx ->
    void $ addTransaction mp tx
  where
    void = fmap (const ())

-- | Check BIP-68 sequence locks for mempool admission.
-- For each input, fetch the coin height from the UTXO set (unconfirmed mempool
-- parents get synthetic height tipHeight+1, matching Bitcoin Core's
-- CalculateLockPointsAtTip / CalculatePrevHeights convention).
-- Per-input coin MTP is computed using 'mpGetCoinMtp': for confirmed UTXOs
-- it returns MTP(max(coinHeight-1, 0)); for synthetic mempool-parent UTXOs
-- we use the tip MTP, matching Core's treatment of MEMPOOL_HEIGHT inputs.
-- Returns Right () if all locks are satisfied, Left err otherwise.
-- Mirrors Bitcoin Core MemPoolAccept::PreChecks → CheckSequenceLocksAtTip
-- (validation.cpp:887) + CalculateLockPointsAtTip (validation.cpp:201).
-- Reference: tx_verify.cpp:74 — nCoinTime = GetAncestor(max(H-1,0))->GetMedianTimePast()
checkSeqLocksAtTip :: Mempool -> Tx -> Word32 -> Word32 -> IO (Either MempoolError ())
checkSeqLocksAtTip mp tx tipHeight mtp = do
  let enforce = bip68Active (mpNetwork mp) (tipHeight + 1)
  if not enforce
    then return (Right ())
    else do
      -- Collect per-input coin heights and per-input coin MTPs.
      -- UTXOs in the confirmed set: use confirmed height and MTP(max(H-1,0)).
      -- UTXOs from unconfirmed mempool parents or unknown: use tipHeight+1 and
      -- tip MTP, exactly as Bitcoin Core uses MEMPOOL_HEIGHT inputs.
      heightMTPs <- forM (txInputs tx) $ \inp -> do
        let op = txInPrevOutput inp
        mUtxo <- lookupUTXO (mpUTXOCache mp) op
        case mUtxo of
          Just entry -> do
            -- Confirmed UTXO: get MTP of block max(coinHeight-1, 0) as Core does.
            -- tx_verify.cpp:74: nCoinTime = GetAncestor(max(H-1,0))->GetMedianTimePast()
            let h = ueHeight entry
            coinMtp <- mpGetCoinMtp mp (if h == 0 then 0 else h - 1)
            return (h, coinMtp)
          Nothing ->
            -- Mempool parent or unknown — use tipHeight+1 + tip MTP as Core does
            -- for MEMPOOL_HEIGHT coins (validation.cpp:189-191).
            return (tipHeight + 1, mtp)
      let (prevHeights, prevMTPs) = unzip heightMTPs
          lock = calculateSequenceLocks tx prevHeights prevMTPs True
      if checkSequenceLocks (tipHeight + 1) mtp lock
        then return (Right ())
        else return (Left ErrSeqLockNotSatisfied)

-- | Compute Median Time Past from a list of block timestamps (newest first).
-- Takes the median of the first ≤11 entries — matches Bitcoin Core's
-- GetMedianTimePast() in primitives/block.h.
computeMTPFromList :: [Word32] -> Word32
computeMTPFromList [] = 0
computeMTPFromList ts =
  let window = take 11 ts
      sorted = sort window
  in sorted !! (length sorted `div` 2)

-- | Drop the first element of a list, or return [] if already empty.
safeDropHead :: [a] -> [a]
safeDropHead []     = []
safeDropHead (_:xs) = xs

--------------------------------------------------------------------------------
-- Eviction
--------------------------------------------------------------------------------

-- | Bump the rolling minimum fee rate when a package is removed due to
-- size-limit eviction.  Mirrors CTxMemPool::trackPackageRemoved
-- (txmempool.cpp:853-859).
--
-- If the evicted package's fee rate (already including the incremental relay
-- fee floor) exceeds the current rolling minimum, we adopt it as the new
-- minimum and clear the blockSinceLastFeeBump flag so decay does not start
-- until the next block arrives.
trackPackageRemoved :: Mempool -> Word64 -> IO ()
trackPackageRemoved mp evictedFeeRateKvb = do
  let newRate = fromIntegral evictedFeeRateKvb :: Double
  atomically $ do
    cur <- readTVar (mpRollingMinFeeRate mp)
    when (newRate > cur) $ do
      writeTVar (mpRollingMinFeeRate mp) newRate
      writeTVar (mpBlockSinceLastFeeBump mp) False

-- | Get the effective minimum fee rate for mempool acceptance (sat/kvB).
-- Applies exponential decay to the rolling minimum fee rate and returns the
-- maximum of the decayed rolling value and the static incremental relay fee.
-- Mirrors CTxMemPool::GetMinFee (txmempool.cpp:829-851).
--
-- Decay formula: rollingMin /= 2^((now - lastUpdate) / halflife)
-- Halflife is shortened to 1/2 or 1/4 when the pool is below 50%/25% full,
-- to speed up the decay in light-traffic conditions.
-- Returns 0 (in sat/kvB) when the rolling min has decayed below half the
-- incremental relay fee floor (same threshold as Core).
getMempoolMinFeeRateDecayed :: Mempool -> IO Word64
getMempoolMinFeeRateDecayed mp = do
  rolling    <- readTVarIO (mpRollingMinFeeRate mp)
  blockSince <- readTVarIO (mpBlockSinceLastFeeBump mp)
  if not blockSince || rolling == 0
    then return (floor rolling)
    else do
      now        <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
      lastUpdate <- readTVarIO (mpLastRollingFeeUpdate mp)
      if now > lastUpdate + 10
        then do
          -- Compute adaptive halflife based on pool fullness
          poolSize  <- readTVarIO (mpSize mp)
          let maxSize  = fromIntegral (mpcMaxSize (mpConfig mp)) :: Double
              poolFrac = fromIntegral poolSize / maxSize
              halflife
                | poolFrac < 0.25 = rollingFeeHalflife / 4
                | poolFrac < 0.50 = rollingFeeHalflife / 2
                | otherwise       = rollingFeeHalflife
              elapsed  = fromIntegral (now - lastUpdate) :: Double
              decayed  = rolling / (2 ** (elapsed / halflife))
              floorKvb = fromIntegral incrementalRelayFeePerKvb :: Double
          -- Update state: write decayed rate and timestamp
          atomically $ do
            if decayed < floorKvb / 2
              then do
                writeTVar (mpRollingMinFeeRate mp) 0.0
              else
                writeTVar (mpRollingMinFeeRate mp) decayed
            writeTVar (mpLastRollingFeeUpdate mp) now
          -- Return max(decayed, incrementalRelayFee), or 0 if below floor/2
          if decayed < floorKvb / 2
            then return 0
            else return (max (floor decayed) incrementalRelayFeePerKvb)
        else
          -- Less than 10s since last update: return current without decaying
          return (max (floor rolling) incrementalRelayFeePerKvb)

-- | Trim the mempool to the configured size limit by removing the
-- lowest-feerate transactions, looping until under the limit.
-- Updates the rolling minimum fee rate via 'trackPackageRemoved' each
-- iteration.  Mirrors CTxMemPool::TrimToSize (txmempool.cpp:861-911).
trimToSize :: Mempool -> IO ()
trimToSize mp = loop
  where
    sizelimit = mpcMaxSize (mpConfig mp)
    loop = do
      totalSize <- readTVarIO (mpSize mp)
      when (totalSize > sizelimit) $ do
        feeRateMap <- readTVarIO (mpByFeeRate mp)
        case Map.lookupMin feeRateMap of
          Nothing -> return ()  -- pool is empty, nothing to evict
          Just ((evictedFeeRate, txid), _) -> do
            -- Evicted fee rate in sat/kvB + incremental relay fee floor
            -- (mirrors: removed += m_opts.incremental_relay_feerate)
            let FeeRate fr = evictedFeeRate
                evictedKvb = fr + incrementalRelayFeePerKvb
            trackPackageRemoved mp evictedKvb
            removeWithDescendants mp txid
            loop  -- keep trimming until under limit

-- | Evict the lowest fee-rate transaction (and its descendants) from the
-- mempool and bump the rolling minimum fee rate accordingly.
-- Called from 'finalizeTransaction' when a new entry pushes the pool over
-- its size limit.
evictLowestFee :: Mempool -> IO ()
evictLowestFee = trimToSize

-- | Expire transactions that have been in the mempool longer than the
-- configured expiry window (default 14 days / 336 hours).
-- Also evicts all descendants of each expired transaction.
-- Mirrors CTxMemPool::Expire (txmempool.cpp:811-827).
--
-- Returns the number of transactions removed (including descendants).
expireOldTransactions :: Mempool -> IO Int
expireOldTransactions mp = do
  now     <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
  let expirySeconds = fromIntegral (mpcExpiryHours (mpConfig mp)) * 3600 :: Int64
      cutoff        = now - expirySeconds
  entries <- readTVarIO (mpEntries mp)
  -- Collect all entries whose admission time predates the cutoff
  let expired = [ txid
                | (txid, e) <- Map.toList entries
                , meTime e < cutoff
                ]
  -- Remove each expired entry together with its descendants
  before <- fmap (Map.size) (readTVarIO (mpEntries mp))
  forM_ expired $ \txid -> do
    mEntry <- getTransaction mp txid
    case mEntry of
      Nothing -> return ()  -- already removed as a descendant of an earlier expiry
      Just _  -> removeWithDescendants mp txid
  after  <- fmap Map.size (readTVarIO (mpEntries mp))
  return (before - after)

--------------------------------------------------------------------------------
-- Transaction Selection for Mining
--------------------------------------------------------------------------------

-- | Select transactions for a block template
-- Returns transactions sorted by ancestor fee rate (CPFP-aware)
-- up to the given weight limit
selectTransactions :: Mempool -> Int -> IO [MempoolEntry]
selectTransactions mp maxWeight = do
  entries <- readTVarIO (mpEntries mp)

  -- Calculate ancestor fee rate for each transaction
  let ancestorFeeRate entry =
        let totalFees = meAncestorFees entry
            totalSize = meAncestorSize entry
        in if totalSize == 0 then 0
           else (totalFees * 1000) `div` fromIntegral totalSize

  -- Sort by ancestor fee rate (descending)
  let sorted = sortBy (comparing (Down . ancestorFeeRate)) (Map.elems entries)

  -- Select transactions up to weight limit
  return $ selectWithinWeight sorted 0 maxWeight []
  where
    selectWithinWeight :: [MempoolEntry] -> Int -> Int -> [MempoolEntry]
                       -> [MempoolEntry]
    selectWithinWeight [] _ _ acc = reverse acc
    selectWithinWeight (e:rest) currentWeight limit acc
      | weight > limit = selectWithinWeight rest currentWeight limit acc
      | otherwise = selectWithinWeight rest (currentWeight + weight) limit (e : acc)
      where
        weight = meSize e * witnessScaleFactor

--------------------------------------------------------------------------------
-- Package Relay (BIP-331)
--------------------------------------------------------------------------------

-- | Maximum number of transactions in a package
-- Bitcoin Core: MAX_PACKAGE_COUNT = 25
maxPackageCount :: Int
maxPackageCount = 25

-- | Maximum total weight of a package in weight units
-- Bitcoin Core: MAX_PACKAGE_WEIGHT = 404,000
-- This corresponds to ~101,000 vbytes
maxPackageWeight :: Int
maxPackageWeight = 404000

-- | A transaction package for CPFP fee bumping
-- A package consists of parent transactions and a child that spends them.
-- The child must spend at least one output from a parent.
data TxPackage = TxPackage
  { pkgParents :: ![Tx]       -- ^ Parent transactions (topologically first)
  , pkgChild   :: !Tx         -- ^ Child transaction (must spend parent outputs)
  } deriving (Show, Eq, Generic)

instance NFData TxPackage

-- | Package validation errors
data PackageError
  = PkgTooManyTransactions !Int !Int      -- ^ (actual, max)
  | PkgTooLarge !Int !Int                 -- ^ (actual_weight, max_weight)
  | PkgNotTopoSorted                      -- ^ Parents not before children
  | PkgContainsDuplicates                 -- ^ Duplicate transactions
  | PkgConflictInPackage                  -- ^ Transactions spend same inputs
  | PkgChildNoParentSpend                 -- ^ Child doesn't spend any parent
  | PkgEmptyPackage                       -- ^ No transactions in package
  | PkgTxError !TxId !MempoolError        -- ^ Individual tx validation failed
  | PkgInsufficientFee !FeeRate !FeeRate  -- ^ (package_feerate, min_required)
  | PkgEphemeralError !EphemeralError     -- ^ Ephemeral anchor policy violation
  deriving (Show, Eq, Generic)

instance NFData PackageError

-- | Check if a package is topologically sorted (parents before children)
-- A package is topo-sorted if no transaction spends an output from a
-- transaction that appears later in the list.
isTopoSortedPackage :: [Tx] -> Bool
isTopoSortedPackage txns =
  let -- Build set of txids that come later
      txids = map computeTxId txns
      txidSet = Set.fromList txids

      -- For each tx, check that no input spends a tx that appears later
      checkTx (tx, laterTxids) =
        let inputTxids = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs tx)
        in Set.null (Set.intersection inputTxids laterTxids)

      -- Build list of (tx, txids appearing later)
      txWithLater = zip txns (tail (scanr Set.insert Set.empty txids))

  in all checkTx txWithLater

-- | Check that transactions in a package don't conflict (spend same inputs)
isConsistentPackage :: [Tx] -> Bool
isConsistentPackage txns =
  let -- Collect all inputs
      allInputs = concatMap (map txInPrevOutput . txInputs) txns
      inputSet = Set.fromList allInputs
  in length allInputs == Set.size inputSet

-- | Context-free package validation
-- 1. Package count <= MAX_PACKAGE_COUNT
-- 2. Total weight <= MAX_PACKAGE_WEIGHT
-- 3. Topologically sorted
-- 4. No conflicting transactions
-- 5. No duplicates
isWellFormedPackage :: [Tx] -> Either PackageError ()
isWellFormedPackage [] = Left PkgEmptyPackage
isWellFormedPackage txns = do
  -- Check count
  let count = length txns
  when (count > maxPackageCount) $
    Left $ PkgTooManyTransactions count maxPackageCount

  -- Check total weight
  let totalWeight = sum $ map (\tx -> txBaseSize tx * 3 + txTotalSize tx) txns
  when (totalWeight > maxPackageWeight) $
    Left $ PkgTooLarge totalWeight maxPackageWeight

  -- Check for duplicates
  let txids = map computeTxId txns
      uniqueTxids = Set.fromList txids
  when (Set.size uniqueTxids /= length txids) $
    Left PkgContainsDuplicates

  -- Check topological order
  unless (isTopoSortedPackage txns) $
    Left PkgNotTopoSorted

  -- Check no conflicts
  unless (isConsistentPackage txns) $
    Left PkgConflictInPackage

  Right ()

-- | Check if a package is a child-with-parents structure
-- The last transaction (child) must have all other transactions as parents.
-- Each parent must have at least one output spent by the child.
isChildWithParents :: [Tx] -> Bool
isChildWithParents [] = False
isChildWithParents [_] = False
isChildWithParents txns =
  let parents = init txns
      child = last txns
      parentTxids = Set.fromList $ map computeTxId parents
      -- Child must spend from at least one parent
      childInputTxids = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs child)
  in not (Set.null (Set.intersection parentTxids childInputTxids))

-- | Calculate package fee rate (total fees / total vsize)
calculatePackageFeeRate :: [Tx] -> Map OutPoint TxOut -> Either String FeeRate
calculatePackageFeeRate txns utxoMap = do
  -- Create a map of outputs created by txs in the package
  let pkgOutputs = Map.fromList
        [ (OutPoint (computeTxId tx) (fromIntegral idx), out)
        | tx <- txns
        , (idx, out) <- zip [0..] (txOutputs tx)
        ]
      -- Combined lookup: first check package outputs, then UTXO
      lookupOutput op = case Map.lookup op pkgOutputs of
        Just out -> Just out
        Nothing -> Map.lookup op utxoMap

  -- Calculate fee for each transaction
  fees <- forM txns $ \tx -> do
    let inputs = txInputs tx
    inputValues <- forM inputs $ \inp -> do
      case lookupOutput (txInPrevOutput inp) of
        Just out -> Right (txOutValue out)
        Nothing -> Left $ "Missing input: " ++ show (txInPrevOutput inp)
    let totalIn = sum inputValues
        totalOut = sum $ map txOutValue (txOutputs tx)
    if totalIn < totalOut
      then Left "Insufficient input value"
      else Right (totalIn - totalOut)

  let totalFees = sum fees
      totalVsize = sum $ map calculateVSize txns

  if totalVsize <= 0
    then Right (FeeRate 0)
    else Right $ calculateFeeRate totalFees totalVsize

-- | Accept a package into the mempool
-- Validates the package as a unit using package feerate.
-- A parent with low feerate can be accepted if the package feerate is sufficient.
acceptPackage :: TxPackage -> Mempool -> IO (Either PackageError [TxId])
acceptPackage pkg mp = do
  let allTxns = pkgParents pkg ++ [pkgChild pkg]

  -- 1. Context-free validation
  case isWellFormedPackage allTxns of
    Left err -> return $ Left err
    Right () -> do

      -- 2. Check child-with-parents structure
      if not (isChildWithParents allTxns)
        then return $ Left PkgChildNoParentSpend
        else do
          -- 3. Check for duplicates with mempool
          entries <- readTVarIO (mpEntries mp)
          let txids = map computeTxId allTxns
              duplicates = filter (`Map.member` entries) txids
          case duplicates of
            [] -> acceptPackageInner pkg mp allTxns
            (dup:_) -> return $ Left $ PkgTxError dup ErrAlreadyInMempool

-- | Inner package acceptance after basic validation
acceptPackageInner :: TxPackage -> Mempool -> [Tx] -> IO (Either PackageError [TxId])
acceptPackageInner _pkg mp allTxns = do
  -- Resolve all inputs from UTXO and package itself
  utxoInputs <- resolvePackageInputs mp allTxns
  case utxoInputs of
    Left (txid, err) -> return $ Left $ PkgTxError txid err
    Right utxoMap -> do
      -- Calculate package fee rate and individual fees for ephemeral checks
      case calculatePackageFeeRate allTxns utxoMap of
        Left err -> return $ Left $ PkgTxError (computeTxId (head allTxns)) (ErrValidationFailed err)
        Right pkgFeeRate -> do
          let minFeeRate = mpcMinFeeRate (mpConfig mp)

          -- Check package fee rate meets minimum
          if pkgFeeRate < minFeeRate
            then return $ Left $ PkgInsufficientFee pkgFeeRate minFeeRate
            else do
              -- Ephemeral anchor pre-checks: verify each tx with ephemeral outputs has 0 fee
              let ephemeralPreCheckResult = checkAllEphemeralPreChecks allTxns utxoMap
              case ephemeralPreCheckResult of
                Left err -> return $ Left $ PkgEphemeralError err
                Right () -> do
                  -- Get mempool entries for parents in mempool (not in package)
                  mempoolParents <- getMempoolParentsForPackage mp allTxns
                  -- Check that all ephemeral anchors are spent within the package
                  case checkEphemeralAnchors allTxns mempoolParents of
                    Left err -> return $ Left $ PkgEphemeralError err
                    Right () -> do
                      -- Now add each transaction
                      addedTxIds <- addPackageTransactions mp allTxns utxoMap pkgFeeRate
                      case addedTxIds of
                        Left err -> return $ Left err
                        Right txids -> return $ Right txids

-- | Pre-check all transactions in package for ephemeral policy
checkAllEphemeralPreChecks :: [Tx] -> Map OutPoint TxOut -> Either EphemeralError ()
checkAllEphemeralPreChecks txns utxoMap = do
  -- Build outputs created within the package for fee calculation
  let pkgOutputs = Map.fromList
        [ (OutPoint (computeTxId tx) (fromIntegral idx), out)
        | tx <- txns
        , (idx, out) <- zip [0..] (txOutputs tx)
        ]
      combinedMap = Map.union pkgOutputs utxoMap

  forM_ txns $ \tx -> do
    -- Calculate fee for this transaction
    let inputs = txInputs tx
        inputValues = map (\inp -> maybe 0 txOutValue (Map.lookup (txInPrevOutput inp) combinedMap)) inputs
        totalIn = sum inputValues
        totalOut = sum $ map txOutValue (txOutputs tx)
        fee = if totalIn > totalOut then totalIn - totalOut else 0
    checkEphemeralPreCheck tx fee

-- | Get mempool entries for transactions that are parents of the package
-- but not in the package itself (for ephemeral anchor checking)
getMempoolParentsForPackage :: Mempool -> [Tx] -> IO [MempoolEntry]
getMempoolParentsForPackage mp txns = do
  entries <- readTVarIO (mpEntries mp)
  let pkgTxids = Set.fromList $ map computeTxId txns
      -- Get all parent txids from the package that aren't in the package
      parentTxIds = Set.toList $ Set.difference
        (Set.fromList $ concatMap (map (outPointHash . txInPrevOutput) . txInputs) txns)
        pkgTxids
  return $ mapMaybe (`Map.lookup` entries) parentTxIds

-- | Resolve inputs for all transactions in a package
-- Returns a combined UTXO map from confirmed UTXOs
resolvePackageInputs :: Mempool -> [Tx] -> IO (Either (TxId, MempoolError) (Map OutPoint TxOut))
resolvePackageInputs mp txns = do
  -- Build a map of outputs created within the package
  let pkgTxids = Set.fromList $ map computeTxId txns
      pkgOutputs = Map.fromList
        [ (OutPoint (computeTxId tx) (fromIntegral idx), out)
        | tx <- txns
        , (idx, out) <- zip [0..] (txOutputs tx)
        ]

  -- Resolve external inputs (not from package)
  results <- forM txns $ \tx -> do
    let txid = computeTxId tx
        externalInputs = filter (not . isPackageOutput pkgTxids) (txInputs tx)
    inputResults <- forM externalInputs $ \inp -> do
      let op = txInPrevOutput inp
      mUtxo <- lookupUTXO (mpUTXOCache mp) op
      case mUtxo of
        Just entry -> do
          height <- readTVarIO (mpHeight mp)
          if ueCoinbase entry && height - ueHeight entry < fromIntegral coinbaseMaturity
            then return $ Left (txid, ErrCoinbaseNotMature (ueHeight entry) height)
            else return $ Right (op, ueOutput entry)
        Nothing ->
          -- Check if input is from another mempool tx (ancestor)
          resolveFromMempool mp op txid
    return $ sequence inputResults

  case sequence results of
    Left err -> return $ Left err
    Right inputLists -> return $ Right $ Map.union pkgOutputs (Map.fromList (concat inputLists))
  where
    isPackageOutput :: Set TxId -> TxIn -> Bool
    isPackageOutput pkgTxids inp = Set.member (outPointHash (txInPrevOutput inp)) pkgTxids

    resolveFromMempool :: Mempool -> OutPoint -> TxId -> IO (Either (TxId, MempoolError) (OutPoint, TxOut))
    resolveFromMempool mp' op txid = do
      entries <- readTVarIO (mpEntries mp')
      let prevTxId = outPointHash op
          prevIdx = outPointIndex op
      case Map.lookup prevTxId entries of
        Just prevEntry ->
          let prevTx = meTransaction prevEntry
              outputs = txOutputs prevTx
          in if fromIntegral prevIdx < length outputs
             then return $ Right (op, outputs !! fromIntegral prevIdx)
             else return $ Left (txid, ErrMissingInput op)
        Nothing -> return $ Left (txid, ErrMissingInput op)

-- | Add all transactions in a package to the mempool
addPackageTransactions :: Mempool
                       -> [Tx]
                       -> Map OutPoint TxOut
                       -> FeeRate             -- ^ Package fee rate (for CPFP)
                       -> IO (Either PackageError [TxId])
addPackageTransactions mp txns utxoMap pkgFeeRate = do
  -- Process transactions in order (parents first)
  go txns [] Map.empty
  where
    go [] acc _ = return $ Right (reverse acc)
    go (tx:rest) acc localOutputs = do
      let txid = computeTxId tx
          -- Combine UTXO map with outputs from previously added package txs
          combinedMap = Map.union localOutputs utxoMap

      -- W96 (two-pipeline closure):  the package path historically
      -- jumped straight to script-verify + addTransactionToMempool, which
      -- skipped every ATMP gate that 'addTransaction' runs (coinbase
      -- reject, IsStandardTx, IsFinalTx, BIP-68 sequence-locks,
      -- IsWitnessStandard, MAX_STANDARD_TX_SIGOPS_COST,
      -- ValidateInputsStandardness, PreCheckEphemeralTx).  We now run
      -- those per-tx context-free / coin-aware checks before fee logic.
      -- The package-feerate CPFP allowance only relaxes the *individual
      -- fee gate*, not the standardness gates.
      let coinbaseReject = isCoinbase tx
      if coinbaseReject
        then return $ Left $ PkgTxError txid ErrCoinbaseNotAllowed
        else case validateTransaction tx of
          Left vErr -> return $ Left $ PkgTxError txid (ErrValidationFailed vErr)
          Right () -> case Std.checkStandardTx tx of
            Left stdErr -> return $ Left $ PkgTxError txid
                                       (ErrNonStandard (renderStdReason stdErr))
            Right () -> do
              -- IsFinalTx (BIP-113).
              height <- readTVarIO (mpHeight mp)
              mtp    <- readTVarIO (mpMTP mp)
              let nextHeight = height + 1
              if not (isFinalTxCheck tx nextHeight mtp)
                then return $ Left $ PkgTxError txid (ErrNonFinal "non-final")
                else do
                  -- BIP-68 sequence-locks.
                  seqRes <- checkSeqLocksAtTip mp tx height mtp
                  case seqRes of
                    Left err -> return $ Left $ PkgTxError txid err
                    Right () -> goAfterCtxFree tx txid rest acc localOutputs combinedMap

    -- Continuation once context-free / locktime gates pass.  Resolves
    -- inputs, runs witness/sigops/ephemeral gates, verifies scripts,
    -- then inserts via 'addTransactionToMempool'.
    goAfterCtxFree tx txid rest acc localOutputs combinedMap = do
      let inputPairs = map (\inp -> (txInPrevOutput inp, Map.lookup (txInPrevOutput inp) combinedMap)) (txInputs tx)
          missingInputs = filter (null . snd) inputPairs
      case missingInputs of
        ((op, _):_) -> return $ Left $ PkgTxError txid (ErrMissingInput op)
        [] -> do
          let inputs = [(op, out) | (op, Just out) <- inputPairs]
              totalIn = sum $ map (txOutValue . snd) inputs
              totalOut = sum $ map txOutValue (txOutputs tx)
          if totalIn < totalOut
            then return $ Left $ PkgTxError txid ErrInsufficientFee
            else do
              let fee = totalIn - totalOut
                  vsize = calculateVSize tx
                  individualFeeRate = calculateFeeRate fee vsize
                  -- CPFP allowance: package feerate can rescue a
                  -- low-fee parent.  The *standardness* gates above are
                  -- not relaxed by this — only this min-fee check.
                  effectiveFeeRate = max individualFeeRate pkgFeeRate
                  minFeeRate = mpcMinFeeRate (mpConfig mp)
              if effectiveFeeRate < minFeeRate
                then return $ Left $ PkgInsufficientFee effectiveFeeRate minFeeRate
                else
                  -- ValidateInputsStandardness — non-standard P2SH
                  -- redeem-script sigops, NONSTANDARD prevouts, etc.
                  case validateInputsStandardness tx inputs of
                    Left (idx, reason) -> return $ Left $
                      PkgTxError txid (ErrInputsNotStandard idx reason)
                    Right () ->
                      -- IsWitnessStandard.
                      case Std.checkWitnessStandard tx (map (txOutScript . snd) inputs) (txWitness tx) of
                        Left wsErr -> return $ Left $ PkgTxError txid
                          (ErrNonStandard (renderWitnessStdReason wsErr))
                        Right () -> do
                          -- MAX_STANDARD_TX_SIGOPS_COST.
                          tipH <- readTVarIO (mpHeight mp)
                          let inputMap = Map.fromList inputs
                              sigopFlags = consensusFlagsAtHeight (mpNetwork mp) (tipH + 1)
                              SigOpCost txSigOpCost = getTransactionSigOpCost tx inputMap sigopFlags
                          if txSigOpCost > maxStandardTxSigOpsCost
                            then return $ Left $ PkgTxError txid
                                            (ErrNonStandard "bad-txns-too-many-sigops")
                            else
                              -- PreCheckEphemeralTx (general dust).
                              -- In a package context, dust may legitimately
                              -- be spent by a sibling tx — but a per-tx
                              -- dust + fee combo is still forbidden
                              -- (CheckEphemeralSpends handles the spending
                              -- requirement separately, already run
                              -- in 'acceptPackageInner').
                              case generalEphemeralPreCheck tx fee of
                                Left dustIdx -> return $ Left $ PkgTxError txid
                                  (ErrNonStandard ("dust (output " ++ show dustIdx ++ ")"))
                                Right () -> do
                                  -- Verify scripts.
                                  scriptResult <- verifyAllScripts' mp tx inputMap
                                  case scriptResult of
                                    Left err -> return $ Left $ PkgTxError txid
                                                            (ErrScriptVerificationFailed err)
                                    Right () -> do
                                      result <- addTransactionToMempool mp tx txid inputs fee vsize
                                      case result of
                                        Left err -> return $ Left $ PkgTxError txid err
                                        Right () -> do
                                          let newOutputs = Map.fromList
                                                [ (OutPoint txid (fromIntegral idx), out)
                                                | (idx, out) <- zip [0..] (txOutputs tx)
                                                ]
                                          go rest (txid : acc) (Map.union newOutputs localOutputs)

-- | Verify all scripts for a transaction (variant returning String error).
-- Same Taproot-aware refactor as 'verifyAllScripts': pre-collect prevouts
-- and pass to 'verifyScriptWithFlags' so BIP-341 sighash works.
-- Uses consensus flags for the next block height (mempool admission standard).
verifyAllScripts' :: Mempool -> Tx -> Map OutPoint TxOut -> IO (Either String ())
verifyAllScripts' mp tx inputMap = do
  let resolveAll = traverse
        (\inp -> case Map.lookup (txInPrevOutput inp) inputMap of
            Nothing -> Left $ "Missing input: " ++ show (txInPrevOutput inp)
            Just prevOut -> Right prevOut)
        (txInputs tx)
  case resolveAll of
    Left err -> return $ Left err
    Right prevs -> do
      -- Use consensus flags for the next block height (mempool admission standard).
      height <- readTVarIO (mpHeight mp)
      let cflags = consensusFlagsAtHeight (mpNetwork mp) (height + 1)
          scriptFlags = consensusFlagsToScriptFlags cflags
          spentAmounts = map txOutValue prevs
          spentScripts = map txOutScript prevs
          indexed = zip [0..] prevs
      results <- forM indexed $ \(idx, prevOut) ->
        case Script.verifyScriptWithFlags scriptFlags tx idx
               (txOutScript prevOut) (txOutValue prevOut)
               spentAmounts spentScripts of
          Left err -> return $ Left err
          Right False -> return $ Left "Script returned false"
          Right True -> return $ Right ()
      return $ sequence_ results

-- | Add a single transaction to the mempool (internal helper)
addTransactionToMempool :: Mempool -> Tx -> TxId -> [(OutPoint, TxOut)] -> Word64 -> Int -> IO (Either MempoolError ())
addTransactionToMempool mp tx txid inputPairs fee vsize = do
  -- Check ancestor limits
  ancestorResult <- checkAncestorLimits mp tx vsize
  case ancestorResult of
    Left err -> return $ Left err
    Right ancestors -> do
      now <- round <$> getPOSIXTime
      height <- readTVarIO (mpHeight mp)
      let rbfOptIn = any (\inp -> txInSequence inp < 0xfffffffe) (txInputs tx)
          ancestorCount = length ancestors + 1
          ancestorFees = sum (map meFee ancestors) + fee
          -- Include self's own sigop cost (matches Core ancestor sigop accumulation).
          inputMap = Map.fromList inputPairs
          sigopFlags = consensusFlagsAtHeight (mpNetwork mp) (height + 1)
          SigOpCost selfSigOpCost = getTransactionSigOpCost tx inputMap sigopFlags
          ancestorSigOps = sum (map meAncestorSigOps ancestors) + selfSigOpCost
          -- Sigop-adjusted virtual size (Core parity).
          -- Reference: bitcoin-core/src/policy/policy.cpp:400-403.
          adjVsize = calculateAdjustedVSize tx selfSigOpCost
          feeRate = calculateFeeRate fee adjVsize
          ancestorSize = sum (map meSize ancestors) + adjVsize
          wtxid = computeWtxid tx
          entry = MempoolEntry
            { meTransaction = tx
            , meTxId = txid
            , meWtxid = wtxid
            , meFee = fee
            , meFeeRate = feeRate
            , meSize = adjVsize
            , meTime = now
            , meHeight = height
            , meAncestorCount = ancestorCount
            , meAncestorSize = ancestorSize
            , meAncestorFees = ancestorFees
            , meAncestorSigOps = ancestorSigOps
            , meDescendantCount = 1
            , meDescendantSize = adjVsize
            , meDescendantFees = fee
            , meRBFOptIn = rbfOptIn
            }

      -- Insert atomically (BIP-339 dual index: txid + wtxid stay in sync)
      atomically $ do
        modifyTVar' (mpEntries mp) (Map.insert txid entry)
        modifyTVar' (mpByWtxid mp) (Map.insert wtxid txid)
        forM_ (txInputs tx) $ \inp ->
          modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput inp) txid)
        modifyTVar' (mpByFeeRate mp) (Map.insert (feeRate, txid) ())
        modifyTVar' (mpSize mp) (+ adjVsize)

      -- Update ancestor entries with new descendant
      atomically $ forM_ ancestors $ \anc ->
        modifyTVar' (mpEntries mp) $ Map.adjust
          (\e -> e { meDescendantCount = meDescendantCount e + 1
                   , meDescendantSize = meDescendantSize e + adjVsize
                   , meDescendantFees = meDescendantFees e + fee
                   }) (meTxId anc)

      return $ Right ()

--------------------------------------------------------------------------------
-- v3/TRUC Transaction Policy (BIP 431)
--------------------------------------------------------------------------------

-- | Check if a transaction is a v3 (TRUC) transaction.
-- v3 transactions have restricted topology to enable reliable fee bumping.
isV3 :: Tx -> Bool
isV3 tx = txVersion tx == trucVersion

-- | Get the mempool parent of a transaction (if it has one).
-- Returns the entry for the unconfirmed transaction that produces one of this
-- tx's inputs, if any.
getMempoolParent :: Mempool -> Tx -> IO (Maybe MempoolEntry)
getMempoolParent mp tx = do
  entries <- readTVarIO (mpEntries mp)
  let parentTxIds = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs tx)
      mempoolParents = mapMaybe (`Map.lookup` entries) (Set.toList parentTxIds)
  -- TRUC transactions can have at most 1 unconfirmed parent
  return $ case mempoolParents of
    [parent] -> Just parent
    _ -> Nothing

-- | Get all mempool children of a transaction (direct descendants).
-- Returns entries for all unconfirmed transactions that spend this tx's outputs.
getMempoolChildren :: Mempool -> TxId -> IO [MempoolEntry]
getMempoolChildren mp txid = do
  byOutpoint <- readTVarIO (mpByOutpoint mp)
  entries <- readTVarIO (mpEntries mp)
  case Map.lookup txid entries of
    Nothing -> return []
    Just entry -> do
      let tx = meTransaction entry
          outputOps = [ OutPoint txid (fromIntegral i)
                      | i <- [0 .. length (txOutputs tx) - 1] ]
          childTxIds = mapMaybe (`Map.lookup` byOutpoint) outputOps
          -- Deduplicate in case multiple outputs go to same child
          uniqueChildIds = Set.toList $ Set.fromList childTxIds
      return $ mapMaybe (`Map.lookup` entries) uniqueChildIds

-- | Check TRUC (v3) transaction policy rules.
--
-- Mirrors Bitcoin Core's SingleTRUCChecks (policy/truc_policy.cpp).
-- Gate order matches Core exactly:
--   (a) Version inheritance: v3↔non-v3 mixing is always forbidden (checked first
--       for all txs, before any size/count gates).
--   Then for v3 only:
--   1. A v3 tx must be at most TRUC_MAX_VSIZE (10,000 vbytes)
--   2a. Direct mempool parent count: mempool_parents + 1 <= TRUC_ANCESTOR_LIMIT
--   2b. Parent's own ancestor depth: parent.ancestorCount + 1 <= TRUC_ANCESTOR_LIMIT
--       (Core line: pool.GetAncestorCount(mempool_parents[0]) + 1 > TRUC_ANCESTOR_LIMIT)
--   4. A v3 child must be at most TRUC_CHILD_MAX_VSIZE (1,000 vbytes)
--   3. Descendant limit: parent.descendantCount + 1 <= TRUC_DESCENDANT_LIMIT
--      (sibling eviction may apply when parent has exactly one existing child)
--
-- Returns Right () if all checks pass, or Left TrucError with the violation.
-- Also returns a Maybe MempoolEntry for potential sibling eviction.
checkTrucPolicy :: Tx
                -> Int           -- ^ Transaction vsize
                -> Mempool
                -> IO (Either TrucError (Maybe MempoolEntry))
                   -- ^ Right (Just sibling) means sibling eviction is possible
checkTrucPolicy tx vsize mp = do
  let txid = computeTxId tx

  -- Get mempool parents of this transaction (deduped by txid via Set)
  entries <- readTVarIO (mpEntries mp)
  let parentTxIds = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs tx)
      mempoolParents = mapMaybe (`Map.lookup` entries) (Set.toList parentTxIds)

  -- Gate (a): version inheritance check — applies to ALL transactions, checked
  -- first before any size/count gates (Core truc_policy.cpp:178-191).
  case checkVersionInheritance tx txid mempoolParents of
    Left err -> return $ Left err
    Right () ->
      if isV3 tx
        then checkV3Transaction tx txid vsize mempoolParents mp
        else return $ Right Nothing  -- Non-v3 tx passed inheritance check; no further TRUC gates

-- | Check that TRUC version inheritance rules hold for any transaction.
-- Core checks these FIRST, before size or ancestor-count gates.
-- Rule: v3 tx cannot spend non-v3 unconfirmed parent, and vice-versa.
checkVersionInheritance :: Tx -> TxId -> [MempoolEntry] -> Either TrucError ()
checkVersionInheritance tx txid parents =
  case filter versionMismatch parents of
    [] -> Right ()
    (badParent:_)
      | isV3 tx   -> Left $ TrucV3SpendingNonV3 txid (meTxId badParent)
      | otherwise  -> Left $ TrucNonV3SpendingV3 txid (meTxId badParent)
  where
    -- A parent is a mismatch if it is the opposite TRUC version to tx.
    versionMismatch p = isV3 tx /= isV3 (meTransaction p)

-- | Check rules specific to v3 transactions (called after inheritance gate passes).
-- Gate order mirrors Core SingleTRUCChecks (truc_policy.cpp:200-259):
--   1. vsize <= TRUC_MAX_VSIZE
--   2a. mempool_parents + 1 <= TRUC_ANCESTOR_LIMIT
--   2b. parent.ancestorCount + 1 <= TRUC_ANCESTOR_LIMIT  (MISSING before this fix)
--   4. vsize <= TRUC_CHILD_MAX_VSIZE  (only when has parent)
--   3. parent.descendantCount + 1 <= TRUC_DESCENDANT_LIMIT
checkV3Transaction :: Tx
                   -> TxId
                   -> Int
                   -> [MempoolEntry]  -- ^ Mempool parents
                   -> Mempool
                   -> IO (Either TrucError (Maybe MempoolEntry))
checkV3Transaction _tx txid vsize mempoolParents mp = do
  -- Rule 1: v3 tx must be within TRUC_MAX_VSIZE (Core line 200-204)
  if fromIntegral vsize > trucMaxVsize
    then return $ Left $ TrucTooLarge (fromIntegral vsize) trucMaxVsize
    else do
      -- Rule 2a: direct mempool parent count (Core line 207-211)
      -- TRUC_ANCESTOR_LIMIT = 2 includes self, so max 1 direct parent
      if length mempoolParents + 1 > trucAncestorLimit
        then return $ Left $ TrucTooManyAncestors (length mempoolParents + 1) trucAncestorLimit
        else case mempoolParents of
          [] -> return $ Right Nothing  -- No unconfirmed parents, all checks pass
          [parent] -> checkV3WithParent txid vsize parent mp
          _ -> return $ Left $ TrucTooManyAncestors (length mempoolParents + 1) trucAncestorLimit

-- | Check rules for a v3 transaction that has exactly one unconfirmed parent.
-- At this point version inheritance has already been verified (parent is v3).
checkV3WithParent :: TxId
                  -> Int
                  -> MempoolEntry  -- ^ The single mempool parent (already known to be v3)
                  -> Mempool
                  -> IO (Either TrucError (Maybe MempoolEntry))
checkV3WithParent txid vsize parent mp = do
  let parentTxId = meTxId parent

  -- Rule 2b: parent's own ancestor depth (Core line 217-221).
  -- If the parent itself has an ancestor, adding this tx would create a
  -- 3-generation chain (grandparent→parent→this), violating TRUC_ANCESTOR_LIMIT=2.
  -- Core: pool.GetAncestorCount(mempool_parents[0]) + 1 > TRUC_ANCESTOR_LIMIT
  -- meAncestorCount includes self: a root tx has meAncestorCount=1, so
  -- parent.meAncestorCount + 1 > 2  ↔  parent.meAncestorCount > 1  ↔  parent has ancestor.
  if meAncestorCount parent + 1 > trucAncestorLimit
    then return $ Left $ TrucTooManyAncestors (meAncestorCount parent + 1) trucAncestorLimit
    else do
      -- Rule 4: v3 child must be within TRUC_CHILD_MAX_VSIZE (Core line 223-227)
      if fromIntegral vsize > trucChildMaxVsize
        then return $ Left $ TrucChildTooLarge (fromIntegral vsize) trucChildMaxVsize
        else do
          -- Rule 3: check parent's descendant count (Core line 229-258).
          -- Parent's descendant count includes itself; > 1 means it already has a child.
          existingChildren <- getMempoolChildren mp parentTxId
          case existingChildren of
            [] -> return $ Right Nothing  -- No existing children, all good
            [existingChild] ->
              -- Parent already has one child. Sibling eviction is possible when:
              --   parent.descendantCount == 2  (exactly one existing child)
              --   sibling.ancestorCount == 2   (sibling has no children of its own)
              -- (Core: consider_sibling_eviction condition, lines 249-250)
              if meDescendantCount parent == 2 && meAncestorCount existingChild == 2
                then return $ Left $ TrucSiblingExists parentTxId (meTxId existingChild)
                else return $ Left $ TrucTooManyDescendants (meDescendantCount parent + 1) trucDescendantLimit
            _ ->
              -- Multiple children already exist (reorg edge case with v3)
              return $ Left $ TrucTooManyDescendants (meDescendantCount parent + 1) trucDescendantLimit

-- | Attempt sibling eviction for a v3 transaction.
--
-- When a v3 child would violate the descendant limit because another child
-- already exists, we may evict the existing sibling if:
-- 1. The parent has exactly 1 existing child (descendant count = 2)
-- 2. The existing child has no descendants of its own (ancestor count = 2)
-- 3. The new transaction meets the fee requirements for replacement
--
-- This function checks if sibling eviction is allowed and performs it if so.
attemptSiblingEviction :: Tx                 -- ^ New v3 child transaction
                       -> Word64             -- ^ New transaction fee
                       -> Int                -- ^ New transaction vsize
                       -> MempoolEntry       -- ^ The v3 parent
                       -> Mempool
                       -> IO (Either TrucError ())
attemptSiblingEviction newTx newFee newVsize parent mp = do
  let parentTxId = meTxId parent

  -- Get the existing sibling
  existingChildren <- getMempoolChildren mp parentTxId
  case existingChildren of
    [sibling] -> do
      -- Check sibling has no children (ancestor count = 2 means parent + self)
      if meAncestorCount sibling == 2 && meDescendantCount sibling == 1
        then do
          -- Sibling eviction is allowed!
          -- For v3, we use a relaxed RBF rule: the new child doesn't need to
          -- pay higher total fees, just enough to cover its own relay cost.
          let -- The new tx must pay at least the incremental relay fee
              requiredFee = (incrementalRelayFeePerKvb * fromIntegral newVsize) `div` 1000

          if newFee >= requiredFee
            then do
              -- Evict the sibling
              removeTransaction mp (meTxId sibling)
              return $ Right ()
            else
              return $ Left $ TrucSiblingExists parentTxId (meTxId sibling)
        else
          -- Sibling has descendants, can't do sibling eviction
          return $ Left $ TrucSiblingExists parentTxId (meTxId sibling)
    _ ->
      -- Not exactly one child, shouldn't happen but handle gracefully
      return $ Left $ TrucTooManyDescendants (length existingChildren + 1) trucDescendantLimit

--------------------------------------------------------------------------------
-- Cluster Mempool
--------------------------------------------------------------------------------

-- | Maximum number of transactions in a cluster (count limit).
-- Bitcoin Core: DEFAULT_CLUSTER_LIMIT = 64 (policy/policy.h:72)
-- Note: 101 is the SIZE limit in kvB (DEFAULT_CLUSTER_SIZE_LIMIT_KVB), NOT the count.
maxClusterSize :: Int
maxClusterSize = 64

-- | Maximum total virtual size of a cluster in vbytes.
-- Bitcoin Core: DEFAULT_CLUSTER_SIZE_LIMIT_KVB = 101 → 101,000 vbytes
-- (kernel/mempool_limits.h:22: cluster_size_vbytes = DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000)
maxClusterSizeVbytes :: Int
maxClusterSizeVbytes = 101 * 1000

-- | A chunk is a set of transactions with the same aggregate fee rate,
-- representing an atomic unit for mining selection.
-- Chunks are the building blocks of a linearization.
data Chunk = Chunk
  { chTxIds   :: !(Set TxId)  -- ^ Transactions in this chunk
  , chFee     :: !Word64      -- ^ Total fees in satoshis
  , chSize    :: !Int         -- ^ Total virtual size in vbytes
  , chFeeRate :: !FeeRate     -- ^ Aggregate fee rate (fee / size)
  } deriving (Show, Eq, Generic)

instance NFData Chunk

-- | A cluster is a connected component of transactions in the mempool,
-- connected by spending relationships. Each cluster has a linearization
-- that orders transactions for optimal mining selection.
data Cluster = Cluster
  { clTxIds        :: !(Set TxId)   -- ^ All transactions in the cluster
  , clLinearization :: ![TxId]       -- ^ Topologically sorted transaction order
  , clChunks       :: ![Chunk]       -- ^ Chunked linearization (decreasing fee rate)
  , clTotalFee     :: !Word64        -- ^ Total fees in the cluster
  , clTotalSize    :: !Int           -- ^ Total virtual size of the cluster
  } deriving (Show, Eq, Generic)

instance NFData Cluster

-- | State tracking all clusters in the mempool.
-- This is rebuilt when transactions are added/removed.
data ClusterState = ClusterState
  { csClusters    :: ![Cluster]              -- ^ All clusters
  , csTxToCluster :: !(Map TxId Int)         -- ^ TxId -> cluster index
  , csChunkQueue  :: ![(Int, Chunk)]         -- ^ (cluster_idx, chunk) sorted by fee rate
  } deriving (Show, Eq, Generic)

instance NFData ClusterState

--------------------------------------------------------------------------------
-- Union-Find Data Structure
--------------------------------------------------------------------------------

-- | Union-Find (Disjoint Set Union) for efficient cluster tracking.
-- Uses path compression and union by rank for near O(1) amortized operations.
-- This is a pure, persistent version that maintains the mapping as a Map.
data UnionFind = UnionFind
  { ufParent :: !(Map TxId TxId)  -- ^ Parent pointers (root points to itself)
  , ufRank   :: !(Map TxId Int)   -- ^ Rank for union by rank
  , ufSize   :: !(Map TxId Int)   -- ^ Size of each component (stored at root)
  } deriving (Show, Eq, Generic)

instance NFData UnionFind

-- | Create an empty Union-Find structure
emptyUnionFind :: UnionFind
emptyUnionFind = UnionFind Map.empty Map.empty Map.empty

-- | Add a new singleton element to the Union-Find
ufMakeSet :: TxId -> UnionFind -> UnionFind
ufMakeSet x uf
  | Map.member x (ufParent uf) = uf  -- Already exists
  | otherwise = uf
      { ufParent = Map.insert x x (ufParent uf)
      , ufRank = Map.insert x 0 (ufRank uf)
      , ufSize = Map.insert x 1 (ufSize uf)
      }

-- | Find the root of an element with path compression.
-- Returns the root and the updated Union-Find with compressed paths.
ufFind :: TxId -> UnionFind -> (TxId, UnionFind)
ufFind x uf = case Map.lookup x (ufParent uf) of
  Nothing -> (x, ufMakeSet x uf)  -- Create singleton if not found
  Just parent
    | parent == x -> (x, uf)  -- x is root
    | otherwise ->
        -- Path compression: find root recursively
        let (root, uf') = ufFind parent uf
            -- Update x's parent to point directly to root
            uf'' = uf' { ufParent = Map.insert x root (ufParent uf') }
        in (root, uf'')

-- | Union two elements. Returns the updated Union-Find.
-- Uses union by rank to keep trees balanced.
ufUnion :: TxId -> TxId -> UnionFind -> UnionFind
ufUnion x y uf =
  let (rootX, uf1) = ufFind x uf
      (rootY, uf2) = ufFind y uf1
  in if rootX == rootY
     then uf2  -- Already in same set
     else
       let rankX = Map.findWithDefault 0 rootX (ufRank uf2)
           rankY = Map.findWithDefault 0 rootY (ufRank uf2)
           sizeX = Map.findWithDefault 1 rootX (ufSize uf2)
           sizeY = Map.findWithDefault 1 rootY (ufSize uf2)
           newSize = sizeX + sizeY
       in if rankX < rankY
          -- Attach smaller tree under root of larger tree
          then uf2 { ufParent = Map.insert rootX rootY (ufParent uf2)
                   , ufSize = Map.insert rootY newSize (ufSize uf2) }
          else if rankX > rankY
          then uf2 { ufParent = Map.insert rootY rootX (ufParent uf2)
                   , ufSize = Map.insert rootX newSize (ufSize uf2) }
          else -- Equal ranks: attach y to x and increment x's rank
            uf2 { ufParent = Map.insert rootY rootX (ufParent uf2)
                , ufRank = Map.insert rootX (rankX + 1) (ufRank uf2)
                , ufSize = Map.insert rootX newSize (ufSize uf2) }

-- | Check if two elements are in the same component
ufConnected :: TxId -> TxId -> UnionFind -> Bool
ufConnected x y uf =
  let (rootX, _) = ufFind x uf
      (rootY, _) = ufFind y uf
  in rootX == rootY

-- | Get the size of the component containing the given element
ufGetSize :: TxId -> UnionFind -> Int
ufGetSize x uf =
  let (root, _) = ufFind x uf
  in Map.findWithDefault 1 root (ufSize uf)

-- | Build a Union-Find from mempool entries by connecting related transactions.
-- Two transactions are related if one spends an output of the other.
buildUnionFind :: Map TxId MempoolEntry -> Map OutPoint TxId -> UnionFind
buildUnionFind entries byOutpoint = foldl' addTxRelations initial (Map.toList entries)
  where
    -- Initialize with all transactions as singletons
    initial = foldl' (flip ufMakeSet) emptyUnionFind (Map.keys entries)

    -- Add edges for each transaction
    addTxRelations :: UnionFind -> (TxId, MempoolEntry) -> UnionFind
    addTxRelations uf (txid, entry) =
      let tx = meTransaction entry
          -- Parents: transactions we spend from
          parentIds = [ parentId
                      | inp <- txInputs tx
                      , let parentId = outPointHash (txInPrevOutput inp)
                      , Map.member parentId entries
                      ]
          -- Children: transactions that spend our outputs
          childIds = [ childId
                     | idx <- [0 .. length (txOutputs tx) - 1]
                     , let op = OutPoint txid (fromIntegral idx)
                     , Just childId <- [Map.lookup op byOutpoint]
                     ]
          -- Union this tx with all its neighbors
          neighbors = parentIds ++ childIds
      in foldl' (\u n -> ufUnion txid n u) uf neighbors

-- | Check if adding a transaction would exceed either cluster limit.
-- Returns True if the resulting cluster would violate the count limit
-- (DEFAULT_CLUSTER_LIMIT = 64) or the vbytes limit
-- (DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000 vB).
-- Reference: policy/policy.h:72-74, kernel/mempool_limits.h:20-22.
wouldExceedClusterLimit :: TxId                   -- ^ New transaction to add
                        -> [TxId]                 -- ^ TxIds it would connect to (neighbors)
                        -> UnionFind              -- ^ Current union-find (for count check)
                        -> Map TxId MempoolEntry  -- ^ Entries (for vbytes check)
                        -> Int                    -- ^ Virtual size of the new tx in vbytes
                        -> Bool
wouldExceedClusterLimit _newTxId neighbors uf entries txVsize =
  let -- Count check: distinct clusters merging + 1 for this tx
      clusterCounts = getDistinctClusterSizes neighbors uf
      totalCount    = sum clusterCounts + 1
      -- Vbytes check: find distinct roots and sum vsizes of their members
      distinctRoots = Set.toList $ Set.fromList
                        [fst (ufFind n uf) | n <- neighbors]
      clusterMemberIds = [ txid'
                         | (txid', _) <- Map.toList entries
                         , let (root, _) = ufFind txid' uf
                         , root `elem` distinctRoots
                         ]
      totalVbytes = sum [meSize e | txid' <- clusterMemberIds
                                  , Just e <- [Map.lookup txid' entries]]
                    + txVsize
  in totalCount > maxClusterSize || totalVbytes > maxClusterSizeVbytes

-- | Get sizes of distinct clusters from a list of TxIds
getDistinctClusterSizes :: [TxId] -> UnionFind -> [Int]
getDistinctClusterSizes txids uf = map getClusterSizeForRoot distinctRoots
  where
    -- Find roots, deduplicating
    distinctRoots = Set.toList $ Set.fromList [fst (ufFind txid uf) | txid <- txids]
    getClusterSizeForRoot root = Map.findWithDefault 1 root (ufSize uf)

--------------------------------------------------------------------------------
-- Feerate Diagrams for RBF
--------------------------------------------------------------------------------

-- | A feerate diagram is a list of (cumulative_vsize, cumulative_fee) points
-- representing chunk boundaries in a linearization.
-- The diagram always starts at (0, 0) and each subsequent point represents
-- the cumulative size and fee after including that chunk.
type FeerateDiagram = [(Int64, Int64)]

-- | Build a feerate diagram from a list of chunks.
-- Each point is the cumulative (size, fee) after including chunks up to that point.
buildFeerateDiagram :: [Chunk] -> FeerateDiagram
buildFeerateDiagram chunks = (0, 0) : scanl1 addChunk diagramPoints
  where
    diagramPoints = [(fromIntegral (chSize c), fromIntegral (chFee c)) | c <- chunks]
    addChunk (cumSize, cumFee) (size, fee) = (cumSize + size, cumFee + fee)

-- | Compare two feerate diagrams for RBF replacement.
-- Returns True if the replacement diagram is strictly better than the original.
-- "Strictly better" means at every size point, the cumulative fee is >= original,
-- and strictly greater at at least one point.
compareDiagrams :: FeerateDiagram  -- ^ Original diagram
                -> FeerateDiagram  -- ^ Replacement diagram
                -> Bool            -- ^ True if replacement is strictly better
compareDiagrams original replacement =
  let -- Sample both diagrams at all unique size points
      allSizes = Set.toList $ Set.fromList $
        map fst original ++ map fst replacement
      -- Get fee at a given size by interpolation
      getFeeAtSize :: FeerateDiagram -> Int64 -> Int64
      getFeeAtSize diagram size = interpolate diagram size
      -- Check that replacement is >= at all points and > at least one
      originalFees = map (getFeeAtSize original) allSizes
      replacementFees = map (getFeeAtSize replacement) allSizes
      pairs = zip originalFees replacementFees
      allGe = all (\(o, r) -> r >= o) pairs
      anyGt = any (\(o, r) -> r > o) pairs
  in allGe && anyGt

-- | Interpolate the cumulative fee at a given size from a diagram.
-- Uses linear interpolation between chunk boundaries.
interpolate :: FeerateDiagram -> Int64 -> Int64
interpolate [] _ = 0
interpolate [(_, fee)] _ = fee
interpolate diagram size =
  case findBracket diagram of
    Nothing -> 0
    Just (before, after) ->
      let (s1, f1) = before
          (s2, f2) = after
      in if s1 == s2
         then f1
         else f1 + ((f2 - f1) * (size - s1)) `div` (s2 - s1)
  where
    -- Find the bracket containing the given size
    findBracket :: FeerateDiagram -> Maybe ((Int64, Int64), (Int64, Int64))
    findBracket d = go d
      where
        go [] = Nothing
        go [p] = Just (p, p)  -- Beyond the end
        go (p1:p2:rest)
          | size <= fst p1 = Just (p1, p1)  -- Before start
          | size <= fst p2 = Just (p1, p2)  -- In bracket
          | otherwise = go (p2:rest)

-- | Build diagrams for both the current mempool state and after replacement.
-- Used for RBF comparison.
buildReplacementDiagrams :: [MempoolEntry]    -- ^ Entries being replaced
                         -> MempoolEntry      -- ^ New replacement entry
                         -> (FeerateDiagram, FeerateDiagram)
buildReplacementDiagrams replaced replacement =
  let -- Build diagram for replaced transactions
      replacedChunks = computeChunks
        [(meTxId e, meFee e, meSize e) | e <- replaced]
      -- Build diagram for replacement (single chunk)
      replacementChunks = [Chunk
        { chTxIds = Set.singleton (meTxId replacement)
        , chFee = meFee replacement
        , chSize = meSize replacement
        , chFeeRate = meFeeRate replacement
        }]
  in (buildFeerateDiagram replacedChunks, buildFeerateDiagram replacementChunks)

-- | Check RBF replacement using feerate diagrams.
-- This is a more sophisticated check than simple fee comparison.
checkDiagramReplacement :: [MempoolEntry]    -- ^ All transactions being evicted
                        -> Word64            -- ^ New transaction fee
                        -> Int               -- ^ New transaction vsize
                        -> FeeRate           -- ^ New transaction feerate
                        -> Either RbfError ()
checkDiagramReplacement evicted newFee newVsize newFeeRate = do
  -- Build the diagrams
  let evictedDiagram = buildFeerateDiagram $ computeChunks
        [(meTxId e, meFee e, meSize e) | e <- evicted]
      newChunk = Chunk
        { chTxIds = Set.empty  -- Don't need txids for diagram
        , chFee = newFee
        , chSize = newVsize
        , chFeeRate = newFeeRate
        }
      replacementDiagram = buildFeerateDiagram [newChunk]

  -- Check if replacement is strictly better
  if compareDiagrams evictedDiagram replacementDiagram
    then Right ()
    else
      -- Fall back to traditional fee comparison for error message
      let evictedFee = sum $ map meFee evicted
      in Left $ RbfInsufficientAbsoluteFee newFee evictedFee

--------------------------------------------------------------------------------
-- Cluster Size Limit Error
--------------------------------------------------------------------------------

-- | Error for exceeding cluster size or count limit.
-- Bitcoin Core emits "too-large-cluster" for both violations.
-- (validation.cpp:1343, txmempool.cpp:998-999)
data ClusterLimitError
  = ClusterLimitExceeded           -- ^ Cluster would exceed the transaction COUNT limit
      { cleActualSize :: !Int      -- ^ Resulting cluster size (tx count)
      , cleMaxSize    :: !Int      -- ^ Limit (DEFAULT_CLUSTER_LIMIT = 64)
      }
  | ClusterSizeExceeded            -- ^ Cluster would exceed the vbytes SIZE limit
      { cleActualVbytes :: !Int    -- ^ Resulting cluster vbytes
      , cleMaxVbytes    :: !Int    -- ^ Limit (DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101000)
      }
  deriving (Show, Eq, Generic)

instance NFData ClusterLimitError

-- | Check cluster count and size limits for a new transaction.
-- Returns Left if adding the transaction would exceed either the count limit
-- (DEFAULT_CLUSTER_LIMIT = 64) or the vbytes size limit
-- (DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000 = 101,000 vB).
-- Reference: kernel/mempool_limits.h, policy/policy.h:72-74,
--            txmempool.cpp:1072-1079 (CheckMemPoolPolicyLimits → IsOversized).
checkClusterLimit :: Tx                      -- ^ Transaction being added
                  -> Map TxId MempoolEntry   -- ^ Current mempool entries
                  -> Map OutPoint TxId       -- ^ Outpoint index
                  -> Int                     -- ^ Virtual size of the new transaction in vbytes
                  -> Either ClusterLimitError ()
checkClusterLimit tx entries byOutpoint txVsize =
  let txid = computeTxId tx
      -- Find all mempool transactions this tx connects to (parents only — children
      -- cannot exist yet since this tx is not yet in the pool).
      parentIds = [ parentId
                  | inp <- txInputs tx
                  , let parentId = outPointHash (txInPrevOutput inp)
                  , Map.member parentId entries
                  ]
      -- Build union-find for cluster membership (count check)
      uf = buildUnionFind entries byOutpoint
  in if null parentIds
     then Right ()  -- No connections, will be singleton cluster — always fine
     else
       let -- Count check: sum distinct cluster sizes + 1 for this tx
           clusterTxCounts = getDistinctClusterSizes parentIds uf
           totalTxCount    = sum clusterTxCounts + 1
           -- Vbytes check: sum vsizes of all distinct cluster members + this tx's vsize
           distinctRoots   = Set.toList $ Set.fromList
                               [fst (ufFind parentId uf) | parentId <- parentIds]
           clusterMemberIds = [ txid'
                               | (txid', _) <- Map.toList entries
                               , let (root, _) = ufFind txid' uf
                               , root `elem` distinctRoots
                               ]
           totalVbytes = sum [meSize e | txid' <- clusterMemberIds
                                       , Just e <- [Map.lookup txid' entries]]
                         + txVsize
       in if totalTxCount > maxClusterSize
          then Left $ ClusterLimitExceeded totalTxCount maxClusterSize
          else if totalVbytes > maxClusterSizeVbytes
          then Left $ ClusterSizeExceeded totalVbytes maxClusterSizeVbytes
          else Right ()

--------------------------------------------------------------------------------
-- Cluster Identification
--------------------------------------------------------------------------------

-- | Find the cluster (connected component) containing a given transaction.
-- Uses BFS to find all transactions connected by spending relationships.
-- This is a pure function operating on the mempool entry map.
findCluster :: TxId                       -- ^ Starting transaction
            -> Map TxId MempoolEntry      -- ^ All mempool entries
            -> Map OutPoint TxId          -- ^ Spent outpoint index
            -> Set TxId
findCluster startTxId entries byOutpoint =
  bfs (Set.singleton startTxId) Set.empty
  where
    bfs :: Set TxId -> Set TxId -> Set TxId
    bfs frontier visited
      | Set.null frontier = visited
      | otherwise =
          let -- Get all neighbors of frontier transactions
              neighbors = Set.unions $ map getNeighbors (Set.toList frontier)
              -- Filter out already visited
              newFrontier = neighbors `Set.difference` visited'
              visited' = visited `Set.union` frontier
          in bfs newFrontier visited'

    -- Get all transactions connected to a given transaction
    getNeighbors :: TxId -> Set TxId
    getNeighbors txid = case Map.lookup txid entries of
      Nothing -> Set.empty
      Just entry ->
        let tx = meTransaction entry
            -- Parents: transactions whose outputs we spend
            parentIds = Set.fromList
              [ outPointHash (txInPrevOutput inp)
              | inp <- txInputs tx
              , let parentId = outPointHash (txInPrevOutput inp)
              , Map.member parentId entries  -- Only mempool parents
              ]
            -- Children: transactions that spend our outputs
            childIds = Set.fromList
              [ childTxId
              | idx <- [0 .. length (txOutputs tx) - 1]
              , let op = OutPoint txid (fromIntegral idx)
              , Just childTxId <- [Map.lookup op byOutpoint]
              ]
        in Set.union parentIds childIds

-- | Find all clusters in the mempool.
-- Returns a list of disjoint sets of transaction IDs.
findAllClusters :: Map TxId MempoolEntry
                -> Map OutPoint TxId
                -> [Set TxId]
findAllClusters entries byOutpoint = go (Map.keysSet entries) []
  where
    go :: Set TxId -> [Set TxId] -> [Set TxId]
    go remaining acc
      | Set.null remaining = acc
      | otherwise =
          let startTxId = Set.findMin remaining
              cluster = findCluster startTxId entries byOutpoint
              remaining' = remaining `Set.difference` cluster
          in go remaining' (cluster : acc)

--------------------------------------------------------------------------------
-- Linearization (LIMO-like Algorithm)
--------------------------------------------------------------------------------

-- | Linearize a set of transactions into a topologically valid ordering
-- that produces chunks with decreasing fee rates.
--
-- This implements a simplified version of the LIMO algorithm:
-- 1. Start with all transactions
-- 2. Repeatedly find the highest-feerate topologically-valid prefix
-- 3. Add it to the linearization
-- 4. Remove it from remaining and repeat
--
-- A topologically-valid prefix is a set of transactions where all ancestors
-- are also included.
linearize :: Set TxId                   -- ^ Transactions to linearize
          -> Map TxId MempoolEntry      -- ^ Mempool entries (for fee/size)
          -> [TxId]                     -- ^ Topologically sorted order
linearize txids entries
  | Set.null txids = []
  | otherwise =
      -- Simple greedy linearization: pick transactions with all ancestors satisfied
      -- in decreasing fee rate order
      let -- Build dependency graph within this cluster
          -- For each tx, get its mempool parents
          parents :: Map TxId (Set TxId)
          parents = Map.fromSet getParents txids

          getParents :: TxId -> Set TxId
          getParents txid = case Map.lookup txid entries of
            Nothing -> Set.empty
            Just entry ->
              let tx = meTransaction entry
              in Set.fromList
                   [ parentId
                   | inp <- txInputs tx
                   , let parentId = outPointHash (txInPrevOutput inp)
                   , Set.member parentId txids
                   ]

          -- Get fee rate for ordering
          getFeeRate :: TxId -> FeeRate
          getFeeRate txid = case Map.lookup txid entries of
            Nothing -> FeeRate 0
            Just entry -> meFeeRate entry

          -- Greedy topological sort by fee rate
          topoSort :: Set TxId -> Set TxId -> [TxId] -> [TxId]
          topoSort remaining satisfied acc
            | Set.null remaining = reverse acc
            | otherwise =
                -- Find all transactions whose parents are all satisfied
                let ready = Set.filter isReady remaining
                    isReady txid = case Map.lookup txid parents of
                      Nothing -> True
                      Just ps -> ps `Set.isSubsetOf` satisfied
                in if Set.null ready
                   then reverse acc  -- Cycle detected, shouldn't happen
                   else
                     -- Pick highest fee rate ready transaction
                     let best = maximumBy getFeeRate (Set.toList ready)
                         remaining' = Set.delete best remaining
                         satisfied' = Set.insert best satisfied
                     in topoSort remaining' satisfied' (best : acc)

      in topoSort txids Set.empty []
  where
    maximumBy :: (a -> FeeRate) -> [a] -> a
    maximumBy _ [x] = x
    maximumBy f (x:xs) = foldl' (\best y -> if f y > f best then y else best) x xs
    maximumBy _ [] = error "maximumBy: empty list"

-- | Linearize a cluster, producing both the ordering and the chunks.
linearizeCluster :: Set TxId
                 -> Map TxId MempoolEntry
                 -> ([TxId], [Chunk])
linearizeCluster txids entries =
  let ordering = linearize txids entries
      chunks = chunkLinearization ordering entries
  in (ordering, chunks)

-- | Given a linearization, compute the chunks.
-- Each chunk is a maximal prefix with equal or higher fee rate than the next.
--
-- Algorithm from Bitcoin Core: Process transactions in order, building chunks.
-- When a new transaction has higher fee rate than the current chunk,
-- merge it with the chunk (and possibly previous chunks).
chunkLinearization :: [TxId] -> Map TxId MempoolEntry -> [Chunk]
chunkLinearization [] _ = []
chunkLinearization ordering entries = computeChunks txInfos
  where
    txInfos = mapMaybe getTxInfo ordering
    getTxInfo txid = do
      entry <- Map.lookup txid entries
      return (txid, meFee entry, meSize entry)

-- | Compute chunks from a list of (txid, fee, size) tuples.
-- This is a pure function that implements the Bitcoin Core chunking algorithm.
computeChunks :: [(TxId, Word64, Int)] -> [Chunk]
computeChunks = foldl' addToChunks []
  where
    addToChunks :: [Chunk] -> (TxId, Word64, Int) -> [Chunk]
    addToChunks chunks (txid, fee, size) =
      let newChunk = Chunk
            { chTxIds = Set.singleton txid
            , chFee = fee
            , chSize = size
            , chFeeRate = calculateFeeRate fee size
            }
      in mergeChunks (chunks ++ [newChunk])

    -- Merge chunks from the end while the last chunk has higher fee rate
    -- than the second-to-last
    mergeChunks :: [Chunk] -> [Chunk]
    mergeChunks [] = []
    mergeChunks [c] = [c]
    mergeChunks chunks =
      let lastTwo = drop (length chunks - 2) chunks
          rest = take (length chunks - 2) chunks
      in case lastTwo of
           [c1, c2] | chFeeRate c2 > chFeeRate c1 ->
             -- Merge c2 into c1 and recurse
             let merged = Chunk
                   { chTxIds = Set.union (chTxIds c1) (chTxIds c2)
                   , chFee = chFee c1 + chFee c2
                   , chSize = chSize c1 + chSize c2
                   , chFeeRate = calculateFeeRate (chFee c1 + chFee c2) (chSize c1 + chSize c2)
                   }
             in mergeChunks (rest ++ [merged])
           _ -> chunks

--------------------------------------------------------------------------------
-- Cluster State Construction
--------------------------------------------------------------------------------

-- | Build the cluster state from all mempool entries.
-- This identifies all clusters, linearizes them, and builds the chunk queue.
buildClusterState :: Map TxId MempoolEntry
                  -> Map OutPoint TxId
                  -> ClusterState
buildClusterState entries byOutpoint =
  let -- Find all clusters
      clusterSets = findAllClusters entries byOutpoint

      -- Build cluster objects with linearizations
      clusters = zipWith buildCluster [0..] clusterSets

      buildCluster :: Int -> Set TxId -> Cluster
      buildCluster _idx txids =
        let (ordering, chunks) = linearizeCluster txids entries
            totalFee = sum [meFee e | txid <- Set.toList txids
                          , Just e <- [Map.lookup txid entries]]
            totalSize = sum [meSize e | txid <- Set.toList txids
                           , Just e <- [Map.lookup txid entries]]
        in Cluster
             { clTxIds = txids
             , clLinearization = ordering
             , clChunks = chunks
             , clTotalFee = totalFee
             , clTotalSize = totalSize
             }

      -- Build txid -> cluster index map
      txToCluster = Map.fromList
        [ (txid, idx)
        | (idx, cluster) <- zip [0..] clusters
        , txid <- Set.toList (clTxIds cluster)
        ]

      -- Build chunk queue sorted by fee rate (descending)
      allChunks = concat
        [ [(idx, chunk) | chunk <- clChunks cluster]
        | (idx, cluster) <- zip [0..] clusters
        ]
      chunkQueue = sortBy (comparing (Down . chFeeRate . snd)) allChunks

  in ClusterState
       { csClusters = clusters
       , csTxToCluster = txToCluster
       , csChunkQueue = chunkQueue
       }

-- | Get the cluster containing a specific transaction.
getClusterForTx :: ClusterState -> TxId -> Maybe Cluster
getClusterForTx state txid = do
  idx <- Map.lookup txid (csTxToCluster state)
  if idx < length (csClusters state)
    then Just (csClusters state !! idx)
    else Nothing

-- | Get the aggregate fee rate of a cluster.
getClusterFeeRate :: Cluster -> FeeRate
getClusterFeeRate cluster
  | clTotalSize cluster <= 0 = FeeRate 0
  | otherwise = calculateFeeRate (clTotalFee cluster) (clTotalSize cluster)

--------------------------------------------------------------------------------
-- Mining Selection from Clusters
--------------------------------------------------------------------------------

-- | Select transactions for mining using cluster-aware chunk selection.
-- This selects chunks in fee rate order across all clusters until
-- the weight limit is reached.
--
-- This provides optimal fee extraction because:
-- 1. Chunks are the highest-feerate topologically-valid prefixes
-- 2. Selecting in fee rate order maximizes total fees per byte
selectTransactionsFromClusters :: ClusterState
                               -> Map TxId MempoolEntry
                               -> Int               -- ^ Max weight
                               -> [MempoolEntry]
selectTransactionsFromClusters state entries maxWeight =
  selectFromChunks (csChunkQueue state) 0 Set.empty []
  where
    selectFromChunks :: [(Int, Chunk)] -> Int -> Set TxId -> [MempoolEntry]
                     -> [MempoolEntry]
    selectFromChunks [] _ _ acc = reverse acc
    selectFromChunks ((_, chunk):rest) currentWeight selected acc
      -- Check if we can fit this chunk
      | chunkWeight > maxWeight = selectFromChunks rest currentWeight selected acc
      | currentWeight + chunkWeight > maxWeight =
          -- Try to fit what we can from remaining chunks
          selectFromChunks rest currentWeight selected acc
      | otherwise =
          -- Add this chunk
          let chunkEntries = getChunkEntries chunk
              newWeight = currentWeight + chunkWeight
              newSelected = selected `Set.union` chTxIds chunk
          in selectFromChunks rest newWeight newSelected (chunkEntries ++ acc)
      where
        chunkWeight = chSize chunk * witnessScaleFactor

    getChunkEntries :: Chunk -> [MempoolEntry]
    getChunkEntries chunk =
      mapMaybe (`Map.lookup` entries) (Set.toList (chTxIds chunk))

--------------------------------------------------------------------------------
-- Cluster-Based Eviction
--------------------------------------------------------------------------------

-- | Evict the lowest fee-rate chunk from the lowest fee-rate cluster.
-- This is used when the mempool is full.
evictLowestFeeRateCluster :: Mempool -> IO ()
evictLowestFeeRateCluster mp = do
  entries <- readTVarIO (mpEntries mp)
  byOutpoint <- readTVarIO (mpByOutpoint mp)

  let state = buildClusterState entries byOutpoint
      clusters = csClusters state

  -- Find the cluster with lowest overall fee rate
  case clusters of
    [] -> return ()
    _ ->
      let sortedClusters = sortBy (comparing getClusterFeeRate) clusters
          lowestCluster = head sortedClusters
      in case clChunks lowestCluster of
           [] -> return ()
           chunks ->
             -- Evict the lowest fee-rate chunk from the lowest cluster
             let lowestChunk = last chunks  -- Last chunk has lowest fee rate
                 txidsToEvict = Set.toList (chTxIds lowestChunk)
             in forM_ txidsToEvict $ removeWithDescendants mp

--------------------------------------------------------------------------------
-- Ephemeral Anchors
--------------------------------------------------------------------------------

-- | Check if a transaction has any ephemeral anchor outputs.
-- An ephemeral anchor is a zero-value P2A (Pay-to-Anchor) output.
-- These outputs must be spent in the same package to prevent dust from
-- persisting in the UTXO set.
hasEphemeralAnchor :: Tx -> Bool
hasEphemeralAnchor tx = any isEphemeralOutput (txOutputs tx)
  where
    isEphemeralOutput out =
      txOutValue out == 0 && either (const False) isPayToAnchor (decodeScript (txOutScript out))

-- | Get all ephemeral anchor outputs in a transaction.
-- Returns list of (output_index, TxOut) pairs for all zero-value P2A outputs.
getEphemeralOutputs :: Tx -> [(Word32, TxOut)]
getEphemeralOutputs tx =
  [ (fromIntegral idx, out)
  | (idx, out) <- zip [0..] (txOutputs tx)
  , txOutValue out == 0
  , either (const False) isPayToAnchor (decodeScript (txOutScript out))
  ]

-- | Pre-check for ephemeral transactions (context-less).
-- A transaction with dust (ephemeral anchor) outputs must have zero fee.
-- This prevents miners from having incentives to mine the transaction alone.
--
-- Bitcoin Core reference: PreCheckEphemeralTx in ephemeral_policy.cpp
checkEphemeralPreCheck :: Tx -> Word64 -> Either EphemeralError ()
checkEphemeralPreCheck tx fee = do
  let txid = computeTxId tx
      ephemeralOutputs = getEphemeralOutputs tx

  -- Check that if there are ephemeral outputs, the fee is zero
  when (fee /= 0 && not (null ephemeralOutputs)) $
    Left $ EphemeralDustWithFee txid fee

  -- Check that there's at most one ephemeral anchor output
  let ephemeralCount = length ephemeralOutputs
  when (ephemeralCount > 1) $
    Left $ EphemeralMultipleAnchors txid ephemeralCount

  Right ()

-- | Check that all ephemeral anchors in a package are properly spent.
-- For each transaction in the package (or mempool), if it has ephemeral
-- outputs, those outputs must be spent by another transaction in the package.
--
-- This ensures that zero-value P2A outputs don't persist in the UTXO set.
--
-- Bitcoin Core reference: CheckEphemeralSpends in ephemeral_policy.cpp
checkEphemeralAnchors :: [Tx] -> [MempoolEntry] -> Either EphemeralError ()
checkEphemeralAnchors packageTxns mempoolParents = do
  -- Build a map of txid -> tx for the package
  let packageTxMap = Map.fromList [(computeTxId tx, tx) | tx <- packageTxns]

  -- For each transaction in the package, check if its parents have dust
  -- and verify that dust is spent
  forM_ packageTxns $ \childTx -> do
    -- Get the outpoints this transaction spends
    let spentOutpoints = Set.fromList $ map txInPrevOutput (txInputs childTx)

    -- Get parent transactions (from package or mempool)
    let parentTxIds = Set.fromList $ map (outPointHash . txInPrevOutput) (txInputs childTx)

    -- Check each parent for ephemeral outputs
    forM_ (Set.toList parentTxIds) $ \parentTxId -> do
      -- Find the parent transaction
      let mParentTx = case Map.lookup parentTxId packageTxMap of
            Just tx -> Just tx
            Nothing -> meTransaction <$> findEntry ((== parentTxId) . meTxId) mempoolParents

      case mParentTx of
        Nothing -> Right ()  -- Parent not in package or mempool, skip
        Just parentTx -> do
          -- Get ephemeral outputs from parent
          let ephemeralOuts = getEphemeralOutputs parentTx
              ephemeralOutpoints = [OutPoint parentTxId idx | (idx, _) <- ephemeralOuts]
              unspent = filter (`Set.notMember` spentOutpoints) ephemeralOutpoints

          -- If there are unspent ephemeral outputs, it's an error
          when (not (null unspent)) $
            Left $ EphemeralNotSpent parentTxId unspent
  where
    findEntry :: (a -> Bool) -> [a] -> Maybe a
    findEntry _ [] = Nothing
    findEntry p (x:xs)
      | p x       = Just x
      | otherwise = findEntry p xs

-- | Evict a parent with ephemeral anchor when its child is removed.
-- If a child transaction that spends an ephemeral anchor is removed,
-- the parent transaction must also be removed because its ephemeral
-- output would otherwise persist in the UTXO set unspent.
--
-- This is called when a child is evicted from the mempool.
evictEphemeralParent :: Mempool -> TxId -> IO ()
evictEphemeralParent mp childTxId = do
  entries <- readTVarIO (mpEntries mp)

  case Map.lookup childTxId entries of
    Nothing -> return ()  -- Child already removed
    Just childEntry -> do
      -- Get the parent TxIds that this child spends from
      let childTx = meTransaction childEntry
          parentTxIds = Set.toList $ Set.fromList $
            map (outPointHash . txInPrevOutput) (txInputs childTx)

      -- Check each parent for ephemeral outputs
      forM_ parentTxIds $ \parentTxId -> do
        case Map.lookup parentTxId entries of
          Nothing -> return ()
          Just parentEntry -> do
            let parentTx = meTransaction parentEntry

            -- If parent has ephemeral outputs and this child spends them,
            -- we need to evict the parent too
            when (hasEphemeralAnchor parentTx) $ do
              -- Check if the child is the only one spending the ephemeral outputs
              let ephemeralOuts = getEphemeralOutputs parentTx
                  ephemeralOutpoints = Set.fromList
                    [OutPoint parentTxId idx | (idx, _) <- ephemeralOuts]
                  childInputs = Set.fromList $
                    map txInPrevOutput (txInputs childTx)
                  spendsEphemeral = not $ Set.null $
                    Set.intersection ephemeralOutpoints childInputs

              when spendsEphemeral $ do
                -- Check if there are other children spending the ephemeral
                byOutpoint <- readTVarIO (mpByOutpoint mp)
                let otherSpenders = [ spenderTxId
                                    | op <- Set.toList ephemeralOutpoints
                                    , Just spenderTxId <- [Map.lookup op byOutpoint]
                                    , spenderTxId /= childTxId
                                    ]

                -- If no other children spend the ephemeral, evict parent
                when (null otherSpenders) $
                  removeTransaction mp parentTxId

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Render an Haskoin.Policy.Standard.StandardError as a Bitcoin Core
-- IsStandardTx reason tag (e.g. "tx-size", "scriptpubkey", "dust").
-- These tags appear in Core's RPC error messages and are useful for
-- cross-impl test compatibility.
renderStdReason :: Std.StandardError -> String
renderStdReason e = case e of
  Std.StdBadVersion {}           -> "version"
  Std.StdTxWeight {}             -> "tx-size"
  Std.StdNonWitnessTooSmall {}   -> "tx-size-small"
  Std.StdScriptSigSize {}        -> "scriptsig-size"
  Std.StdScriptSigNotPushOnly {} -> "scriptsig-not-pushonly"
  Std.StdScriptPubKey {}         -> "scriptpubkey"
  Std.StdDataCarrierTooLarge {}  -> "datacarrier"
  Std.StdBareMultisig            -> "bare-multisig"
  Std.StdDust {}                 -> "dust"

-- | Render a 'WitnessStandardError' as a Bitcoin Core reason tag.
-- Core uses "bad-witness-nonstandard" for all IsWitnessStandard failures
-- (validation.cpp:905).
renderWitnessStdReason :: Std.WitnessStandardError -> String
renderWitnessStdReason _ = "bad-witness-nonstandard"

--------------------------------------------------------------------------------
-- ValidateInputsStandardness (W96)
--
-- Mirrors @ValidateInputsStandardness@ in
-- bitcoin-core/src/policy/policy.cpp:214-263 — the
-- AreInputsStandard-equivalent that is run from
-- MemPoolAccept::PreChecks (validation.cpp:896-901) when
-- @require_standard@ is set.
--------------------------------------------------------------------------------

-- | Maximum number of sigops allowed in a P2SH redeem script for it to
-- be considered standard. Bitcoin Core: @MAX_P2SH_SIGOPS = 15@
-- (policy/policy.h:46).
maxP2SHSigOps :: Int
maxP2SHSigOps = 15

-- | A scriptPubKey is a witness program of *unknown* version if its
-- serialised form is exactly @OP_<n> + push(<2..40 bytes>)@ with
-- @n > 1@ (versions 0 and 1 are P2WPKH/P2WSH and P2TR respectively
-- and are classified above). The structural test matches Core's
-- @CScript::IsWitnessProgram@ (script.h:240) for @n >= 2@.
isUnknownWitnessProgram :: ByteString -> Bool
isUnknownWitnessProgram bs
  | BS.length bs < 4 || BS.length bs > 42 = False
  | otherwise =
      let op0 = BS.index bs 0
          progLen = fromIntegral (BS.index bs 1) :: Int
          -- OP_2 .. OP_16 are 0x52..0x60. Versions 0/1 are excluded
          -- (Core classifies those as P2WPKH/P2WSH/P2TR via
          -- standardness).
          isWitnessVerOp = op0 >= 0x52 && op0 <= 0x60
          lenOk = progLen >= 2 && progLen <= 40
               && BS.length bs == 2 + progLen
      in isWitnessVerOp && lenOk

-- | Verify that every input of @tx@ spends a *standard* prevout.
--
-- Walks each input's previous scriptPubKey, classifies it via
-- 'Script.classifyOutput', and rejects:
--
--   * NONSTANDARD scriptPubKeys (anything that doesn't match a known
--     template). Core: @"input N script unknown"@.
--   * WITNESS_UNKNOWN scriptPubKeys (witness version > 1, future
--     soft-fork program shapes). Core:
--     @"input N witness program is undefined"@.
--   * P2SH inputs whose redeem-script contains more than
--     'maxP2SHSigOps' (= 15) sigops in inaccurate-count mode. Core:
--     @"p2sh redeemscript sigops exceed limit"@.
--   * P2SH inputs whose scriptSig fails to decode to a push-only
--     stack (cannot extract the redeem script). Core:
--     @"p2sh scriptsig malformed"@.
--
-- Returns @Left (idx, reason)@ on the first failing input, else
-- @Right ()@. The @idx@ is the input position (0-based), matching
-- Core's error formatting.
--
-- NOTE: this gate is *standardness*, not consensus.  Failures here
-- correspond to @TX_INPUTS_NOT_STANDARD@ in Core; the tx is silently
-- not relayed but a miner can still include it.
validateInputsStandardness
  :: Tx
  -> [(OutPoint, TxOut)]
  -> Either (Int, String) ()
validateInputsStandardness tx inputPairs
  | isCoinbase tx = Right ()
  | otherwise =
      let prevs = zip [0..] (txInputs tx)
          pMap  = Map.fromList inputPairs
      in mapM_ (checkOne pMap) prevs
  where
    checkOne :: Map.Map OutPoint TxOut -> (Int, TxIn) -> Either (Int, String) ()
    checkOne pMap (idx, txin) =
      case Map.lookup (txInPrevOutput txin) pMap of
        Nothing ->
          -- Missing prevout is a different error class (TX_MISSING_INPUTS,
          -- handled by resolveInputs before we get here). Skip silently.
          Right ()
        Just prevOut ->
          case decodeScript (txOutScript prevOut) of
            Left _ ->
              -- Undecodable scriptPubKey is non-standard.
              Left (idx, "input " ++ show idx ++ " script unknown")
            Right scriptPubKey ->
              case Script.classifyOutput scriptPubKey of
                -- haskoin's classifier collapses NONSTANDARD and
                -- WITNESS_UNKNOWN into a single NonStandard bucket.  We
                -- additionally detect the witness-unknown case by
                -- inspecting the raw bytes (OP_<n> + 2..40-byte push,
                -- with n != 0/1) so callers can distinguish — useful
                -- when Core's RPC string is the comparison point.
                Script.NonStandard
                  | isUnknownWitnessProgram (txOutScript prevOut) ->
                      Left (idx, "input " ++ show idx ++ " witness program is undefined")
                  | otherwise ->
                      Left (idx, "input " ++ show idx ++ " script unknown")
                Script.P2SH _ ->
                  -- Decode the scriptSig as a stack (push-only). The
                  -- last item is the redeem-script.
                  case decodeScript (txInScript txin) of
                    Left _ ->
                      Left (idx, "p2sh scriptsig malformed (input "
                                  ++ show idx ++ ")")
                    Right sigScript ->
                      case lastPushBytes sigScript of
                        Nothing ->
                          Left (idx, "input " ++ show idx
                                      ++ " P2SH redeemscript missing")
                        Just redeemBytes ->
                          case decodeScript redeemBytes of
                            Left _ ->
                              Left (idx, "input " ++ show idx
                                          ++ " P2SH redeemscript malformed")
                            Right redeem ->
                              -- Use accurate=True so multisig N-of-M
                              -- counts as N (matches Core's
                              -- GetSigOpCount(true)).
                              let n = Script.countScriptSigops redeem True
                              in if n > maxP2SHSigOps
                                   then Left (idx, "p2sh redeemscript sigops exceed limit (input "
                                                    ++ show idx ++ ": "
                                                    ++ show n ++ " > "
                                                    ++ show maxP2SHSigOps ++ ")")
                                   else Right ()
                _ -> Right ()

    -- Last push-data byte string in a parsed script, if the script is
    -- push-only and non-empty. Mirrors Core's
    -- @stack.back()@ extraction in policy.cpp:253.
    lastPushBytes :: Script.Script -> Maybe ByteString
    lastPushBytes (Script.Script ops)
      | null ops = Nothing
      | otherwise = case last ops of
          Script.OP_PUSHDATA bs _ -> Just bs
          Script.OP_0             -> Just BS.empty
          _                       -> Nothing


--------------------------------------------------------------------------------
-- PreCheckEphemeralTx (W96)
--
-- Mirrors @PreCheckEphemeralTx@ in
-- bitcoin-core/src/policy/ephemeral_policy.cpp:23-31.
--   if ((base_fee != 0 || mod_fee != 0) &&
--       !GetDust(tx, dust_relay_rate).empty())
--     return state.Invalid(TX_NOT_STANDARD, "dust",
--                          "tx with dust output must be 0-fee");
--
-- Before this fix, haskoin's 'checkEphemeralPreCheck' only matched
-- zero-value P2A anchor outputs.  A transaction with general dust
-- outputs (e.g. P2WPKH below the 294-sat threshold) and non-zero fee
-- would slip through.  Note that `Std.checkStandardTx` already caps
-- the *number* of dust outputs, but Core's ephemeral pre-check is a
-- separate gate: any dust + any fee → reject.
--------------------------------------------------------------------------------

-- | Reject the tx (returning the offending output index) if it has any
-- dust output and pays any fee.  Returns 'Right ()' when the tx is
-- either zero-fee OR has no dust outputs.
generalEphemeralPreCheck :: Tx -> Word64 -> Either Word32 ()
generalEphemeralPreCheck tx modFee
  | modFee == 0 = Right ()
  | otherwise =
      case dustIndex of
        Just i  -> Left i
        Nothing -> Right ()
  where
    dustIndex :: Maybe Word32
    dustIndex = listToMaybe
      [ fromIntegral idx
      | (idx, out) <- zip [(0 :: Int)..] (txOutputs tx)
      , isDust out dustRelayTxFee
      ]
    listToMaybe :: [a] -> Maybe a
    listToMaybe []    = Nothing
    listToMaybe (x:_) = Just x

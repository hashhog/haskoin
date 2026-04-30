{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Fee Estimation
--
-- This module implements fee rate estimation based on observed confirmation
-- times, tracking how long transactions at various fee rates take to confirm,
-- and providing fee rate recommendations for target confirmation blocks.
--
-- Key Features:
--   - Logarithmically-spaced fee rate buckets (128 buckets from 1 to ~10000 sat/vB)
--   - Exponential decay to weight recent observations more heavily
--   - 95% confirmation threshold for fee rate selection
--   - Conservative and economical estimation modes
--   - Smart fallback to longer confirmation targets when data is insufficient
--
module Haskoin.FeeEstimator
  ( -- * Fee Estimator
    FeeEstimator(..)
  , newFeeEstimator
    -- * Estimation Modes
  , FeeEstimateMode(..)
    -- * Recording Data
  , trackTransaction
  , recordConfirmation
    -- * Fee Estimation
  , estimateFee
  , estimateSmartFee
  , estimateRawFee
  , RawFeeEstimate(..)
  , RawBucketRange(..)
    -- * Bucket Types
  , FeeBucket(..)
  , PendingTxInfo(..)
    -- * Persistence
  , saveFeeEstimates
  , loadFeeEstimates
    -- * Constants
  , numBuckets
  , maxConfirmBlocks
  , bucketFeeRate
  , feeRateToBucket
  ) where

import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Control.Concurrent.STM
import Control.Exception (catch, SomeException)
import Control.Monad (forM, forM_, when)
import Data.Aeson (ToJSON, FromJSON, encode, eitherDecode')
import qualified Data.ByteString.Lazy as LBS
import Data.Word (Word64, Word32)
import Data.Maybe (fromMaybe, isJust, mapMaybe)
import Data.Text (Text)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import System.Directory (doesFileExist, renameFile)

import Haskoin.Types (TxId)

--------------------------------------------------------------------------------
-- Fee Estimator Configuration Constants
--------------------------------------------------------------------------------

-- | Number of fee rate buckets (logarithmic scale from 1 to ~10000 sat/vB)
numBuckets :: Int
numBuckets = 128

-- | Maximum number of blocks to track for confirmation times
maxConfirmBlocks :: Int
maxConfirmBlocks = 48

-- | Default exponential decay factor applied per block
-- This ensures recent data is weighted more heavily than old data
defaultDecay :: Double
defaultDecay = 0.998

-- | Minimum number of transactions required in a bucket for statistical significance
minTxsForEstimate :: Double
minTxsForEstimate = 10

-- | Confirmation rate threshold (95% of transactions must confirm)
confirmThreshold :: Double
confirmThreshold = 0.95

-- | Fallback fee rate when no estimate is available (1000 sat/vB)
fallbackFeeRate :: Word64
fallbackFeeRate = 1000

--------------------------------------------------------------------------------
-- Fee Bucket Types
--------------------------------------------------------------------------------

-- | A bucket for transactions within a fee rate range
data FeeBucket = FeeBucket
  { fbMinFeeRate    :: !Word64      -- ^ Minimum fee rate for this bucket (sat/vB)
  , fbMaxFeeRate    :: !Word64      -- ^ Maximum fee rate for this bucket
  , fbConfirmations :: ![Double]    -- ^ Count of txs confirmed in 1,2,3,...,48 blocks
  , fbTotalTxs      :: !Double      -- ^ Total transactions in this bucket (with decay)
  , fbInMempool     :: !Double      -- ^ Currently in mempool (with decay)
  } deriving (Show, Eq, Generic)

instance NFData FeeBucket
instance ToJSON FeeBucket
instance FromJSON FeeBucket

-- | Information about a pending transaction being tracked
data PendingTxInfo = PendingTxInfo
  { ptTxId        :: !TxId          -- ^ Transaction ID
  , ptFeeRate     :: !Word64        -- ^ Fee rate in sat/vB
  , ptBucketIdx   :: !Int           -- ^ Index of the fee bucket
  , ptEntryHeight :: !Word32        -- ^ Block height when first seen
  } deriving (Show, Eq, Generic)

instance NFData PendingTxInfo

-- | Fee estimation mode
data FeeEstimateMode
  = FeeConservative     -- ^ Higher fee, more likely to confirm quickly
  | FeeEconomical       -- ^ Lower fee, may take longer to confirm
  deriving (Show, Eq, Generic)

instance NFData FeeEstimateMode

--------------------------------------------------------------------------------
-- Fee Estimator
--------------------------------------------------------------------------------

-- | Fee estimator that tracks confirmation times across fee rate buckets
data FeeEstimator = FeeEstimator
  { feeBuckets     :: !(TVar (Map Int FeeBucket))
      -- ^ Bucketed by fee rate ranges (sat/vB)
  , feePending     :: !(TVar (Map TxId PendingTxInfo))
      -- ^ Transactions waiting for confirmation
  , feeBestHeight  :: !(TVar Word32)
      -- ^ Current best known block height
  , feeTotalTxs    :: !(TVar Int)
      -- ^ Total transactions ever tracked
  , feeDecay       :: !Double
      -- ^ Exponential decay factor (default 0.998)
  }

--------------------------------------------------------------------------------
-- Fee Rate Bucket Functions
--------------------------------------------------------------------------------

-- | Calculate the fee rate for a given bucket index
-- Uses exponential spacing: each bucket is ~1.05x the previous
bucketFeeRate :: Int -> Word64
bucketFeeRate idx =
  let base = 1.0 :: Double
      factor = 1.05 :: Double
  in round (base * factor ^ idx)

-- | Convert a fee rate to its bucket index
-- Inverse of bucketFeeRate, clamped to valid range
feeRateToBucket :: Word64 -> Int
feeRateToBucket rate =
  let logRate = logBase 1.05 (fromIntegral (max 1 rate) :: Double)
  in max 0 $ min (numBuckets - 1) (round logRate)

-- | Create an empty fee bucket at the given index
emptyBucket :: Int -> FeeBucket
emptyBucket i =
  let minRate = bucketFeeRate i
      maxRate = max minRate (bucketFeeRate (i + 1) - 1)
  in FeeBucket
  { fbMinFeeRate    = minRate
  , fbMaxFeeRate    = maxRate
  , fbConfirmations = replicate maxConfirmBlocks 0
  , fbTotalTxs      = 0
  , fbInMempool     = 0
  }

--------------------------------------------------------------------------------
-- Fee Estimator Creation
--------------------------------------------------------------------------------

-- | Create a new fee estimator with empty buckets
newFeeEstimator :: IO FeeEstimator
newFeeEstimator = newFeeEstimatorWithDecay defaultDecay

-- | Create a new fee estimator with a custom decay factor
newFeeEstimatorWithDecay :: Double -> IO FeeEstimator
newFeeEstimatorWithDecay decay = do
  let buckets = Map.fromList [(i, emptyBucket i) | i <- [0..numBuckets-1]]
  FeeEstimator
    <$> newTVarIO buckets
    <*> newTVarIO Map.empty
    <*> newTVarIO 0
    <*> newTVarIO 0
    <*> pure decay

--------------------------------------------------------------------------------
-- Transaction Tracking
--------------------------------------------------------------------------------

-- | Track a transaction entering the mempool
-- Records the fee rate and entry height for later confirmation tracking
trackTransaction :: FeeEstimator -> TxId -> Word64 -> Word32 -> IO ()
trackTransaction fe txid feeRate height = do
  let bucketIdx = feeRateToBucket feeRate
      info = PendingTxInfo txid feeRate bucketIdx height
  atomically $ do
    modifyTVar' (feePending fe) (Map.insert txid info)
    modifyTVar' (feeBuckets fe) $ Map.adjust
      (\b -> b { fbInMempool = fbInMempool b + 1 }) bucketIdx
    modifyTVar' (feeTotalTxs fe) (+ 1)

-- | Record confirmations when a block is connected
-- Updates the fee buckets with confirmation data and applies decay
recordConfirmation :: FeeEstimator -> Word32 -> [TxId] -> IO ()
recordConfirmation fe blockHeight confirmedTxIds = do
  pending <- readTVarIO (feePending fe)
  let confirmed = mapMaybe (`Map.lookup` pending) confirmedTxIds
  atomically $ do
    -- Record each confirmation
    forM_ confirmed $ \info -> do
      let blocksToConfirm = fromIntegral (blockHeight - ptEntryHeight info)
          bucketIdx = ptBucketIdx info
      when (blocksToConfirm > 0 && blocksToConfirm <= maxConfirmBlocks) $ do
        modifyTVar' (feeBuckets fe) $ Map.adjust (\b ->
          let confs = fbConfirmations b
              -- Increment confirmation counts for all targets >= actual blocks
              updated = zipWith (\i c -> if i < blocksToConfirm then c else c + 1)
                          [1..] confs
          in b { fbConfirmations = updated
               , fbTotalTxs = fbTotalTxs b + 1
               , fbInMempool = max 0 (fbInMempool b - 1)
               }) bucketIdx
      -- Remove from pending
      modifyTVar' (feePending fe) (Map.delete (ptTxId info))

    -- Apply decay to all buckets
    modifyTVar' (feeBuckets fe) $ Map.map (\b -> b
      { fbConfirmations = map (* feeDecay fe) (fbConfirmations b)
      , fbTotalTxs = fbTotalTxs b * feeDecay fe
      , fbInMempool = fbInMempool b * feeDecay fe
      })

    writeTVar (feeBestHeight fe) blockHeight

--------------------------------------------------------------------------------
-- Fee Estimation
--------------------------------------------------------------------------------

-- | Estimate fee rate for target confirmation in N blocks
-- Returns Nothing if insufficient data is available
estimateFee :: FeeEstimator -> Int -> IO (Maybe Word64)
estimateFee fe targetBlocks = do
  buckets <- readTVarIO (feeBuckets fe)

  -- Find the lowest fee rate bucket where >= 95% of transactions
  -- confirmed within targetBlocks
  let eligibleBuckets = Map.toDescList $ Map.filter (\b ->
        let totalTxs = fbTotalTxs b
            confirmedInTarget = if targetBlocks > 0 && targetBlocks <= length (fbConfirmations b)
                                then fbConfirmations b !! (targetBlocks - 1)
                                else 0
            rate = if totalTxs > 0 then confirmedInTarget / totalTxs else 0
        in totalTxs >= minTxsForEstimate && rate >= confirmThreshold
        ) buckets

  case eligibleBuckets of
    [] -> return Nothing  -- Not enough data
    bucketList -> return $ Just $ fbMinFeeRate $ snd $ last bucketList

-- | Smart fee estimation with fallbacks
-- Falls back to longer confirmation targets if data is insufficient
-- Returns (fee rate, actual target blocks)
estimateSmartFee :: FeeEstimator -> Int -> FeeEstimateMode -> IO (Word64, Int)
estimateSmartFee fe targetBlocks mode = do
  -- Try exact target first
  result <- estimateFee fe targetBlocks
  case result of
    Just rate -> return (adjustForMode rate mode, targetBlocks)
    Nothing -> do
      -- Try progressively larger targets
      let targets = case mode of
            FeeConservative -> [targetBlocks, targetBlocks + 2 .. maxConfirmBlocks]
            FeeEconomical   -> [targetBlocks, targetBlocks + 1 .. maxConfirmBlocks]
      results <- forM targets $ \t -> do
        r <- estimateFee fe t
        return (t, r)
      case [(t, r) | (t, Just r) <- results] of
        [] -> return (adjustForMode fallbackFeeRate mode, maxConfirmBlocks)  -- Fallback with mode adjustment
        ((t, r):_) -> return (adjustForMode r mode, t)
  where
    -- Conservative mode adds 10% buffer to the fee rate
    adjustForMode :: Word64 -> FeeEstimateMode -> Word64
    adjustForMode rate FeeConservative = rate + (rate `div` 10)
    adjustForMode rate FeeEconomical   = rate

--------------------------------------------------------------------------------
-- Raw fee estimation (per-bucket data, like Bitcoin Core's estimaterawfee)
--------------------------------------------------------------------------------

-- | Per-bucket statistics returned by 'estimateRawFee'.  Mirrors the
-- @pass@/@fail@ objects emitted by Bitcoin Core's @estimaterawfee@ RPC
-- (see @bitcoin-core/src/rpc/fees.cpp@).
data RawBucketRange = RawBucketRange
  { rbrStartRange     :: !Word64   -- ^ Inclusive lower edge, sat/vB
  , rbrEndRange       :: !Word64   -- ^ Inclusive upper edge, sat/vB
  , rbrWithinTarget   :: !Double   -- ^ Tx count confirmed within target
  , rbrTotalConfirmed :: !Double   -- ^ Tx count confirmed at any point
  , rbrInMempool      :: !Double   -- ^ Currently in the mempool
  , rbrLeftMempool    :: !Double   -- ^ Left the mempool unconfirmed
  } deriving (Show, Eq, Generic)

instance NFData RawBucketRange

-- | Result returned by 'estimateRawFee'.  We only operate over a single
-- horizon (the existing 'FeeEstimator' is not bucketed by horizon the way
-- Bitcoin Core's @CBlockPolicyEstimator@ is); RPC layers typically expose
-- this under all three Core horizons by returning the same payload.
data RawFeeEstimate = RawFeeEstimate
  { rfeFeeRate :: !(Maybe Word64)       -- ^ Sat/vB (Nothing = no estimate)
  , rfeDecay   :: !Double               -- ^ Per-block decay
  , rfeScale   :: !Int                  -- ^ Confirmation slot resolution
  , rfePass    :: !RawBucketRange       -- ^ Lowest passing bucket
  , rfeFail    :: !(Maybe RawBucketRange) -- ^ Highest failing bucket
  , rfeErrors  :: ![Text]               -- ^ Errors during estimation
  } deriving (Show, Eq, Generic)

instance NFData RawFeeEstimate

-- | Same per-bucket exposure that @CBlockPolicyEstimator::estimateRawFee@
-- provides.  Walks buckets from highest fee rate to lowest, accumulating
-- confirmation statistics and returning the lowest range whose hit rate
-- meets @threshold@ within @targetBlocks@ confirmations.  When no
-- bucket meets the threshold, @rfeFeeRate@ is @Nothing@ and the
-- highest-rate failing bucket is reported under @rfeFail@.
estimateRawFee :: FeeEstimator -> Int -> Double -> IO RawFeeEstimate
estimateRawFee fe targetBlocks threshold = do
  buckets <- readTVarIO (feeBuckets fe)
  let bucketList = Map.toDescList buckets   -- highest fee rate first
      (mPass, mFail, errors) = walk bucketList
                                emptyRange  -- accumulator
                                Nothing
                                Nothing
  let pass = fromMaybe emptyRange mPass
      feeRate = case mPass of
        Just r  -> Just (rbrStartRange r)
        Nothing -> Nothing
      finalErrors =
        if isJust mPass
          then []
          else "Insufficient data or no feerate found which meets threshold"
                 : errors
  return RawFeeEstimate
    { rfeFeeRate = feeRate
    , rfeDecay   = feeDecay fe
    , rfeScale   = 1
    , rfePass    = pass
    , rfeFail    = mFail
    , rfeErrors  = finalErrors
    }
  where
    -- An empty bucket-range placeholder; matches Core's "start = -1" sentinel
    -- modeling for the case when no bucket data is available.
    emptyRange = RawBucketRange 0 0 0 0 0 0

    -- | Compute pass/fail for a single bucket against the configured target
    -- and threshold, returning a 'RawBucketRange' summary.
    summarize :: FeeBucket -> RawBucketRange
    summarize b =
      let confirmedInTarget =
            if targetBlocks > 0 && targetBlocks <= length (fbConfirmations b)
              then fbConfirmations b !! (targetBlocks - 1)
              else 0
      in RawBucketRange
        { rbrStartRange     = fbMinFeeRate b
        , rbrEndRange       = fbMaxFeeRate b
        , rbrWithinTarget   = confirmedInTarget
        , rbrTotalConfirmed = fbTotalTxs b
        , rbrInMempool      = fbInMempool b
        , rbrLeftMempool    = max 0 (fbTotalTxs b - confirmedInTarget)
        }

    -- | Walk buckets from highest to lowest fee rate; remember the lowest
    -- passing bucket and the highest failing bucket seen so far.
    walk :: [(Int, FeeBucket)]
         -> RawBucketRange
         -> Maybe RawBucketRange
         -> Maybe RawBucketRange
         -> (Maybe RawBucketRange, Maybe RawBucketRange, [Text])
    walk [] _ p f = (p, f, [])
    walk ((_, b) : rest) _ p f =
      let r = summarize b
          totalTxs = fbTotalTxs b
          rate = if totalTxs > 0 then rbrWithinTarget r / totalTxs else 0
          passes = totalTxs >= minTxsForEstimate && rate >= threshold
      in if passes
           then walk rest r (Just r) f
           else
             let f' = case f of
                        Nothing -> Just r
                        Just _  -> f   -- keep highest-rate failing bucket
             in walk rest r p f'

--------------------------------------------------------------------------------
-- Persistence
--------------------------------------------------------------------------------

-- | Serializable snapshot of fee estimator state (buckets only, not pending txs).
data FeeEstimatorSnapshot = FeeEstimatorSnapshot
  { snapBuckets    :: !(Map Int FeeBucket)
  , snapBestHeight :: !Word32
  } deriving (Show, Eq, Generic)

instance ToJSON FeeEstimatorSnapshot
instance FromJSON FeeEstimatorSnapshot

-- | Save fee estimator state to a JSON file.
-- Writes to a temporary file first, then renames for atomicity.
saveFeeEstimates :: FeeEstimator -> FilePath -> IO ()
saveFeeEstimates fe path = do
  let go = do
        (buckets, height) <- atomically $ do
          b <- readTVar (feeBuckets fe)
          h <- readTVar (feeBestHeight fe)
          return (b, h)
        let snapshot = FeeEstimatorSnapshot buckets height
            tmpPath = path ++ ".tmp"
        LBS.writeFile tmpPath (encode snapshot)
        renameFile tmpPath path
  go `catch` (\(_ :: SomeException) -> return ())

-- | Load fee estimator state from a JSON file.
-- Returns without error if the file doesn't exist or is invalid.
loadFeeEstimates :: FeeEstimator -> FilePath -> IO ()
loadFeeEstimates fe path = do
  exists <- doesFileExist path
  when exists $ do
    contents <- LBS.readFile path
    case eitherDecode' contents of
      Left _err -> return ()
      Right snapshot -> do
        let loadedBuckets = snapBuckets snapshot
            loadedHeight  = snapBestHeight snapshot
        when (Map.size loadedBuckets == numBuckets) $
          atomically $ do
            writeTVar (feeBuckets fe) loadedBuckets
            writeTVar (feeBestHeight fe) loadedHeight

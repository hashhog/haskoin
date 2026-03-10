{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

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
    -- * Bucket Types
  , FeeBucket(..)
  , PendingTxInfo(..)
    -- * Constants
  , numBuckets
  , maxConfirmBlocks
  , bucketFeeRate
  , feeRateToBucket
  ) where

import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Control.Concurrent.STM
import Control.Monad (forM, forM_, when)
import Data.Word (Word64, Word32)
import Data.Maybe (mapMaybe)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)

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

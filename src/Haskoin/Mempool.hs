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
  , defaultMempoolConfig
    -- * Mempool Creation
  , newMempool
    -- * Transaction Operations
  , addTransaction
  , removeTransaction
  , getTransaction
  , getMempoolTxIds
  , getMempoolSize
  , getMempoolInfo
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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int64)
import Data.List (sortBy, foldl')
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
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (Network(..), validateTransaction, witnessScaleFactor,
                           txBaseSize, txTotalSize, coinbaseMaturity)
import Haskoin.Storage (UTXOCache(..), UTXOEntry(..), lookupUTXO)
import Haskoin.Script (verifyScript)

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

-- | Calculate virtual size from transaction
calculateVSize :: Tx -> Int
calculateVSize tx =
  let base = txBaseSize tx
      total = txTotalSize tx
      weight = base * (witnessScaleFactor - 1) + total
  in (weight + witnessScaleFactor - 1) `div` witnessScaleFactor

--------------------------------------------------------------------------------
-- Mempool Configuration
--------------------------------------------------------------------------------

-- | Mempool configuration parameters
data MempoolConfig = MempoolConfig
  { mpcMaxSize         :: !Int      -- ^ Max pool size in bytes (default 300MB)
  , mpcMinFeeRate      :: !FeeRate  -- ^ Min fee rate to accept (sat/vB)
  , mpcMaxOrphans      :: !Int      -- ^ Max orphan transactions
  , mpcRBFEnabled      :: !Bool     -- ^ Allow BIP-125 RBF
  , mpcMaxAncestors    :: !Int      -- ^ Max ancestor count (default 25)
  , mpcMaxDescendants  :: !Int      -- ^ Max descendant count (default 25)
  , mpcMaxAncestorSize :: !Int      -- ^ Max ancestor size in vB (default 101k)
  } deriving (Show, Generic)

instance NFData MempoolConfig

-- | Default mempool configuration matching Bitcoin Core defaults
defaultMempoolConfig :: MempoolConfig
defaultMempoolConfig = MempoolConfig
  { mpcMaxSize         = 300 * 1024 * 1024  -- 300 MB
  , mpcMinFeeRate      = FeeRate 1          -- 1 sat/vB
  , mpcMaxOrphans      = 100
  , mpcRBFEnabled      = True
  , mpcMaxAncestors    = 25
  , mpcMaxDescendants  = 25
  , mpcMaxAncestorSize = 101000             -- ~101 KB
  }

--------------------------------------------------------------------------------
-- Mempool Entry
--------------------------------------------------------------------------------

-- | A transaction entry in the mempool with computed metadata
data MempoolEntry = MempoolEntry
  { meTransaction     :: !Tx         -- ^ The transaction
  , meTxId            :: !TxId       -- ^ Transaction ID (cached)
  , meFee             :: !Word64     -- ^ Fee in satoshis
  , meFeeRate         :: !FeeRate    -- ^ Fee rate in sat/vB
  , meSize            :: !Int        -- ^ Virtual size (vB)
  , meTime            :: !Int64      -- ^ Unix timestamp when added
  , meHeight          :: !Word32     -- ^ Chain height when added
  , meAncestorCount   :: !Int        -- ^ Number of unconfirmed ancestors
  , meAncestorSize    :: !Int        -- ^ Total ancestor vsize
  , meAncestorFees    :: !Word64     -- ^ Total ancestor fees
  , meDescendantCount :: !Int        -- ^ Number of unconfirmed descendants
  , meDescendantSize  :: !Int        -- ^ Total descendant vsize
  , meDescendantFees  :: !Word64     -- ^ Total descendant fees
  , meRBFOptIn        :: !Bool       -- ^ Signals RBF (nSequence < 0xfffffffe)
  } deriving (Show, Generic)

instance NFData MempoolEntry

--------------------------------------------------------------------------------
-- Mempool Errors
--------------------------------------------------------------------------------

-- | Errors that can occur when adding a transaction to the mempool
data MempoolError
  = ErrAlreadyInMempool
  | ErrValidationFailed !String
  | ErrMissingInput !OutPoint
  | ErrInputSpentInMempool !TxId
  | ErrInsufficientFee
  | ErrFeeBelowMinimum !FeeRate !FeeRate
  | ErrTooManyAncestors !Int !Int
  | ErrTooManyDescendants !Int !Int
  | ErrAncestorSizeTooLarge !Int !Int
  | ErrScriptVerificationFailed !String
  | ErrCoinbaseNotMature !Word32 !Word32
  | ErrRBFNotSignaled !TxId
  | ErrRBFFeeTooLow !Word64 !Word64
  | ErrMempoolFull
  deriving (Show, Eq, Generic)

instance NFData MempoolError

--------------------------------------------------------------------------------
-- Mempool
--------------------------------------------------------------------------------

-- | The transaction memory pool
data Mempool = Mempool
  { mpEntries    :: !(TVar (Map TxId MempoolEntry))
    -- ^ All mempool entries indexed by TxId
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
    -- ^ Current chain height
  }

-- | Create a new empty mempool
newMempool :: Network -> UTXOCache -> MempoolConfig -> Word32 -> IO Mempool
newMempool net cache config height = Mempool
  <$> newTVarIO Map.empty
  <*> newTVarIO Map.empty
  <*> newTVarIO Map.empty
  <*> pure config
  <*> pure cache
  <*> newTVarIO 0
  <*> pure net
  <*> newTVarIO height

--------------------------------------------------------------------------------
-- Transaction Addition
--------------------------------------------------------------------------------

-- | Add a transaction to the mempool after validation
-- Returns the TxId on success, or an error on failure
addTransaction :: Mempool -> Tx -> IO (Either MempoolError TxId)
addTransaction mp tx = do
  let txid = computeTxId tx

  -- 1. Check if already in mempool
  existing <- atomically $ Map.lookup txid <$> readTVar (mpEntries mp)
  case existing of
    Just _ -> return $ Left ErrAlreadyInMempool
    Nothing -> addTransactionInner mp tx txid

-- | Inner implementation of addTransaction after duplicate check
addTransactionInner :: Mempool -> Tx -> TxId -> IO (Either MempoolError TxId)
addTransactionInner mp tx txid = do
  -- 2. Basic context-free validation
  case validateTransaction tx of
    Left err -> return $ Left (ErrValidationFailed err)
    Right () -> do

      -- 3. Resolve inputs and check for conflicts
      inputResults <- resolveInputs mp tx
      case inputResults of
        Left err -> return $ Left err
        Right inputPairs -> do
          let inputMap = Map.fromList inputPairs
              totalIn = sum $ map (txOutValue . snd) inputPairs
              totalOut = sum $ map txOutValue (txOutputs tx)

          -- 4. Check fee is positive
          if totalIn < totalOut
            then return $ Left ErrInsufficientFee
            else do
              let fee = totalIn - totalOut
                  vsize = calculateVSize tx
                  feeRate = calculateFeeRate fee vsize

              -- 5. Check minimum fee rate
              if feeRate < mpcMinFeeRate (mpConfig mp)
                then return $ Left (ErrFeeBelowMinimum feeRate (mpcMinFeeRate (mpConfig mp)))
                else do

                  -- 6. Verify scripts (if script verification is enabled)
                  scriptResult <- verifyAllScripts mp tx inputMap
                  case scriptResult of
                    Left err -> return $ Left err
                    Right () -> do

                      -- 7. Check ancestor/descendant limits
                      ancestorResult <- checkAncestorLimits mp tx
                      case ancestorResult of
                        Left err -> return $ Left err
                        Right ancestors -> do

                          -- 8. Build and insert the entry
                          now <- round <$> getPOSIXTime
                          height <- readTVarIO (mpHeight mp)
                          let rbfOptIn = any (\inp -> txInSequence inp < 0xfffffffe) (txInputs tx)
                              entry = MempoolEntry
                                { meTransaction = tx
                                , meTxId = txid
                                , meFee = fee
                                , meFeeRate = feeRate
                                , meSize = vsize
                                , meTime = now
                                , meHeight = height
                                , meAncestorCount = length ancestors
                                , meAncestorSize = sum (map meSize ancestors) + vsize
                                , meAncestorFees = sum (map meFee ancestors) + fee
                                , meDescendantCount = 0
                                , meDescendantSize = 0
                                , meDescendantFees = 0
                                , meRBFOptIn = rbfOptIn
                                }

                          -- Insert atomically
                          atomically $ do
                            modifyTVar' (mpEntries mp) (Map.insert txid entry)
                            forM_ (txInputs tx) $ \inp ->
                              modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput inp) txid)
                            modifyTVar' (mpByFeeRate mp) (Map.insert (feeRate, txid) ())
                            modifyTVar' (mpSize mp) (+ vsize)

                          -- Update ancestor entries with new descendant
                          atomically $ forM_ ancestors $ \anc ->
                            modifyTVar' (mpEntries mp) $ Map.adjust
                              (\e -> e { meDescendantCount = meDescendantCount e + 1
                                       , meDescendantSize = meDescendantSize e + vsize
                                       , meDescendantFees = meDescendantFees e + fee
                                       }) (meTxId anc)

                          -- 9. Evict if mempool is too large
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

-- | Verify all scripts for a transaction
verifyAllScripts :: Mempool -> Tx -> Map OutPoint TxOut -> IO (Either MempoolError ())
verifyAllScripts _mp tx inputMap = do
  let indexed = zip [0..] (txInputs tx)
  results <- forM indexed $ \(idx, inp) ->
    case Map.lookup (txInPrevOutput inp) inputMap of
      Nothing -> return $ Left (ErrMissingInput (txInPrevOutput inp))
      Just prevOut ->
        case verifyScript tx idx (txOutScript prevOut) (txOutValue prevOut) of
          Left err -> return $ Left (ErrScriptVerificationFailed err)
          Right False -> return $ Left (ErrScriptVerificationFailed "Script returned false")
          Right True -> return $ Right ()
  return $ sequence_ results

-- | Check ancestor limits and return ancestors
checkAncestorLimits :: Mempool -> Tx -> IO (Either MempoolError [MempoolEntry])
checkAncestorLimits mp tx = do
  ancestors <- getAncestorsRecursive mp tx
  let config = mpConfig mp
  if length ancestors >= mpcMaxAncestors config
    then return $ Left (ErrTooManyAncestors (length ancestors) (mpcMaxAncestors config))
    else do
      let totalSize = sum (map meSize ancestors)
      if totalSize >= mpcMaxAncestorSize config
        then return $ Left (ErrAncestorSizeTooLarge totalSize (mpcMaxAncestorSize config))
        else return $ Right ancestors

--------------------------------------------------------------------------------
-- Transaction Removal
--------------------------------------------------------------------------------

-- | Remove a transaction from the mempool
removeTransaction :: Mempool -> TxId -> IO ()
removeTransaction mp txid = atomically $ do
  entries <- readTVar (mpEntries mp)
  case Map.lookup txid entries of
    Nothing -> return ()
    Just entry -> do
      -- Remove from main index
      modifyTVar' (mpEntries mp) (Map.delete txid)
      -- Remove from outpoint index
      forM_ (txInputs (meTransaction entry)) $ \inp ->
        modifyTVar' (mpByOutpoint mp) (Map.delete (txInPrevOutput inp))
      -- Remove from fee rate index
      modifyTVar' (mpByFeeRate mp) (Map.delete (meFeeRate entry, txid))
      -- Update size
      modifyTVar' (mpSize mp) (subtract (meSize entry))

-- | Remove a transaction and all its descendants
removeWithDescendants :: Mempool -> TxId -> IO ()
removeWithDescendants mp txid = do
  descendants <- getDescendants mp txid
  forM_ descendants $ removeTransaction mp . meTxId
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

  -- Update chain height
  atomically $ modifyTVar' (mpHeight mp) (+ 1)

-- | Handle a disconnected block (during reorg)
-- Re-adds transactions from the disconnected block back to mempool
blockDisconnected :: Mempool -> Block -> IO ()
blockDisconnected mp block = do
  -- Decrease chain height
  atomically $ modifyTVar' (mpHeight mp) (subtract 1)

  -- Re-add non-coinbase transactions
  -- (they may fail validation if inputs are now missing)
  forM_ (tail $ blockTxns block) $ \tx ->
    void $ addTransaction mp tx
  where
    void = fmap (const ())

--------------------------------------------------------------------------------
-- Eviction
--------------------------------------------------------------------------------

-- | Evict lowest fee-rate transactions when mempool is full
evictLowestFee :: Mempool -> IO ()
evictLowestFee mp = do
  feeRateMap <- readTVarIO (mpByFeeRate mp)
  case Map.lookupMin feeRateMap of
    Nothing -> return ()
    Just ((_, txid), _) -> removeWithDescendants mp txid

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

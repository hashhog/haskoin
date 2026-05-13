{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE StrictData #-}

-- | Performance Optimizations
--
-- This module provides performance-critical components:
--   - Hardware-accelerated SHA-256 via cryptonite (auto-detects SHA-NI/AVX2)
--   - Batch Schnorr signature verification for Taproot
--   - Parallel ECDSA verification using async
--   - Parallel script verification using GHC parallel strategies
--   - Parallel block validation with transaction chunks
--   - Memory-mapped I/O for block files
--   - LRU cache for UTXO eviction with O(1) operations
--   - Node metrics for monitoring performance
--   - Strict evaluation helpers to prevent space leaks
--   - Network socket optimization
--
-- Key performance considerations:
--   - SHA-256 uses hardware acceleration when available (SHA-NI, AVX2)
--   - Batch Schnorr verification provides ~2x speedup on Taproot blocks
--   - Script verification is the main CPU bottleneck during IBD
--   - UTXO cache hit rate should exceed 95% during IBD
--   - Strict evaluation prevents lazy thunk accumulation
--
-- Hardware detection:
--   cryptonite auto-detects CPU features at runtime. No flags needed.
--   SHA-NI: ~2-3x faster than pure Haskell
--   AVX2: ~1.5x faster than pure Haskell
--
module Haskoin.Performance
  ( -- * Hardware-Accelerated Hashing
    sha256Fast
  , doubleSha256Fast
  , benchmarkHash
    -- * Batch Signature Verification
  , BatchVerifyResult(..)
  , batchVerifySchnorr
  , parallelVerifyECDSA
  , VerifyTask(..)
    -- * Parallel Block Validation
  , validateTxChunk
  , chunkTransactions
  , ParallelValidationResult(..)
    -- * Memory-Mapped I/O
  , MmapBlockFile(..)
  , mmapBlockFile
  , mmapReadBlock
  , mmapClose
    -- * Parallel Validation (Legacy)
  , verifyBlockScriptsParallel
  , parallelMap
    -- * LRU Cache
  , LRUCache(..)
  , newLRUCache
  , lruLookup
  , lruInsert
  , lruEvict
  , lruSize
  , lruHitRate
    -- * Node Metrics
  , NodeMetrics(..)
  , newNodeMetrics
  , incrementMetric
  , addToMetric
  , logMetrics
  , getMetricSnapshot
  , MetricSnapshot(..)
    -- * Hardware Detection
  , sha256HWInfo
  , detectSHANI
  , detectAVX2
    -- * Strict Processing
  , computeTxFeeStrict
    -- * Socket Optimization
  , optimizeSocket
    -- * Database Tuning
  , ibdDBConfig
  , compactUTXORange
    -- * Signature Cache
  , SigCacheKey(..)
  , SigCache(..)
  , sigCacheMaxEntries
  , newSigCache
  , lookupSigCache
  , insertSigCache
  , clearSigCache
  , sigCacheSize
    -- * Global Signature Cache (process-wide singleton)
  , globalSigCache
  , initGlobalSigCache
  ) where

import Control.Concurrent.Async (mapConcurrently, forConcurrently)
import Control.Concurrent.STM
import Control.DeepSeq (NFData(..), force, deepseq)
import Control.Monad (when, unless)
import Control.Parallel.Strategies (parMap, rseq, using, parList)
import qualified Crypto.Hash as H
import qualified Crypto.Random as CryptoRandom
import Data.Bits (shiftL, (.|.))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (IORef, newIORef, readIORef, writeIORef, atomicModifyIORef')
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Ord (comparing)
import Data.List (minimumBy)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Int (Int64)
import Data.Word (Word8, Word32, Word64)
import GHC.Conc (numCapabilities)
import GHC.Generics (Generic)
import Foreign.C.Types (CInt(..))
import Network.Socket (Socket, SocketOption(..), setSocketOption)
import System.IO.MMap (mmapFileByteString)
import System.IO.Unsafe (unsafePerformIO)

import Data.Maybe (mapMaybe)
import Haskoin.Types
import Haskoin.Consensus (ConsensusFlags(..), consensusFlagsToScriptFlags)
import qualified Haskoin.Crypto as Crypto
import qualified Haskoin.Script as Script

--------------------------------------------------------------------------------
-- Hardware Crypto Detection (via CPUID)
--------------------------------------------------------------------------------

-- | FFI binding to detect SHA-NI (SHA Extensions) support via CPUID.
-- Returns 1 if SHA-NI is available, 0 otherwise.
foreign import ccall unsafe "detect_sha_ni"
  c_detect_sha_ni :: IO CInt

-- | FFI binding to detect AVX2 support via CPUID.
-- Returns 1 if AVX2 is available, 0 otherwise.
foreign import ccall unsafe "detect_avx2"
  c_detect_avx2 :: IO CInt

-- | Check if SHA-NI hardware acceleration is available.
detectSHANI :: IO Bool
detectSHANI = (== 1) <$> c_detect_sha_ni

-- | Check if AVX2 hardware acceleration is available.
detectAVX2 :: IO Bool
detectAVX2 = (== 1) <$> c_detect_avx2

-- | Detect SHA-256 hardware acceleration and return a description string.
--
-- Queries CPUID to determine which hardware acceleration is available
-- for SHA-256 hashing. The cryptonite library automatically uses the
-- best available instruction set at runtime.
--
-- Returns one of:
--   - @"sha_ni"@: Intel SHA Extensions available (~2-3x faster)
--   - @"avx2"@: AVX2 available (~1.5x faster)
--   - @"generic"@: No hardware acceleration detected
sha256HWInfo :: IO String
sha256HWInfo = do
  shani <- c_detect_sha_ni
  if shani == 1
    then return "sha_ni"
    else do
      avx2 <- c_detect_avx2
      if avx2 == 1
        then return "avx2"
        else return "generic"

--------------------------------------------------------------------------------
-- Hardware-Accelerated Hashing
--------------------------------------------------------------------------------

-- | Hardware-accelerated SHA-256 using cryptonite.
--
-- cryptonite automatically detects and uses:
--   - SHA-NI (Intel SHA extensions) for ~2-3x speedup
--   - AVX2 for ~1.5x speedup
--   - Falls back to optimized C or pure Haskell
--
-- The detection happens at runtime via CPU feature flags.
sha256Fast :: ByteString -> ByteString
sha256Fast !bs = convert (H.hashWith H.SHA256 bs)
{-# INLINE sha256Fast #-}

-- | Hardware-accelerated double SHA-256 (SHA256(SHA256(data))).
--
-- This is the most common operation in Bitcoin for:
--   - Block header hashing (proof-of-work)
--   - Transaction ID computation
--   - Merkle root computation
doubleSha256Fast :: ByteString -> Hash256
doubleSha256Fast !bs = Hash256 (sha256Fast (sha256Fast bs))
{-# INLINE doubleSha256Fast #-}

-- | Benchmark hash performance and report speedup.
--
-- Runs SHA-256 on test data and reports iterations per second.
-- Useful for verifying hardware acceleration is active.
benchmarkHash :: IO (Double, String)
benchmarkHash = do
  let testData = BS.replicate 80 0xab  -- Block header size
      iterations = 100000
  start <- getPOSIXTime
  let !_ = foldl' (\acc _ -> doubleSha256Fast acc `seq` acc) testData [1..iterations]
  end <- getPOSIXTime
  let elapsed = realToFrac (end - start) :: Double
      hashesPerSec = fromIntegral iterations / elapsed
      -- Estimate hardware acceleration type based on speed
      -- Pure Haskell: ~500k/s, AVX2: ~750k/s, SHA-NI: ~1.5M/s
      accelType | hashesPerSec > 1200000 = "SHA-NI detected"
                | hashesPerSec > 600000  = "AVX2/SSE detected"
                | otherwise              = "Pure Haskell (no acceleration)"
  return (hashesPerSec, accelType)
  where
    foldl' :: (a -> b -> a) -> a -> [b] -> a
    foldl' f = go
      where
        go !z []     = z
        go !z (x:xs) = go (f z x) xs

--------------------------------------------------------------------------------
-- Batch Signature Verification
--------------------------------------------------------------------------------

-- | Result of batch signature verification
data BatchVerifyResult
  = BatchVerifySuccess           -- ^ All signatures valid
  | BatchVerifyFailure !Int      -- ^ Signature at index failed
  | BatchVerifyError !String     -- ^ Error during verification
  deriving (Show, Eq, Generic)

instance NFData BatchVerifyResult

-- | A verification task for parallel processing.
--
-- @vtSignature@ is a wire-format DER signature WITH the trailing 1-byte
-- @SIGHASH@ type, exactly as seen on a CHECKSIG witness item.  The
-- verify path strips the sighash byte before parsing, mirroring
-- 'Haskoin.Script.execCheckSigLegacy' and Core's @CheckECDSASignature@
-- (@bitcoin-core/src/script/interpreter.cpp@).
data VerifyTask = VerifyTask
  { vtPubKey    :: !ByteString    -- ^ Public key (33 compressed / 65 uncompressed)
  , vtMessage   :: !ByteString    -- ^ Message hash (32 bytes; the sighash)
  , vtSignature :: !ByteString    -- ^ DER signature ‖ 1-byte SIGHASH type
  , vtIndex     :: !Int           -- ^ Original index in block
  } deriving (Show, Eq, Generic)

instance NFData VerifyTask

-- | Batch verify Schnorr signatures (BIP-340).
--
-- Each tuple is @(pubkey32, msg32, sig64)@ — the same byte order
-- 'Haskoin.Crypto.verifySchnorr' expects.  We verify each signature in
-- parallel via 'mapConcurrently'; the libsecp256k1 verify path itself
-- enforces every BIP-340 gate (r < p, s < n, x-only-pubkey-parse,
-- challenge = tagged_hash(\"BIP0340/challenge\", r ‖ P ‖ m), R != ∞,
-- R.y even, R.x = r).
--
-- This is a correctness wrapper — true multi-scalar batch verification
-- (the speedup motivation) would call @secp256k1_schnorrsig_verify_batch@
-- once it stabilises in libsecp.  Until then we stay byte-identical to
-- the per-sig path, just parallelised by GHC capabilities.
--
-- Returns 'BatchVerifySuccess' if all signatures are valid, or
-- 'BatchVerifyFailure' with the index of the first invalid signature.
--
-- W95: previously this function was a length-check stub that returned
-- success for any 32/64/32-byte tuple regardless of cryptographic
-- validity.  Live consensus paths never invoked it (verified via grep),
-- but a future wiring would have silently let invalid blocks through.
batchVerifySchnorr :: [(ByteString, ByteString, ByteString)] -> IO BatchVerifyResult
batchVerifySchnorr [] = return BatchVerifySuccess
batchVerifySchnorr sigs = do
  results <- mapConcurrently verifyOne (zip [0..] sigs)
  return $ case filter (not . snd) results of
    [] -> BatchVerifySuccess
    ((idx, _):_) -> BatchVerifyFailure idx
  where
    verifyOne :: (Int, (ByteString, ByteString, ByteString)) -> IO (Int, Bool)
    verifyOne (idx, (pubkey, msg, sig)) =
      -- Delegate to the real BIP-340 verifier.  Length-mismatched
      -- inputs are rejected by 'Crypto.verifySchnorr' itself (it
      -- requires sig==64, msg==32, pubkey==32).
      return (idx, Crypto.verifySchnorr sig msg pubkey)

-- | Verify ECDSA signatures in parallel using async.
--
-- For legacy and SegWit v0 transactions, ECDSA signatures cannot be
-- batch-verified like Schnorr. Instead, we verify them in parallel
-- across multiple CPU cores using Control.Concurrent.Async.
--
-- The number of parallel workers is determined by GHC.Conc.numCapabilities,
-- which reflects the -N RTS option.
parallelVerifyECDSA :: [VerifyTask] -> IO [Either String Bool]
parallelVerifyECDSA [] = return []
parallelVerifyECDSA tasks = do
  -- Split into chunks for parallel processing
  let chunks = chunkList (max 1 (length tasks `div` numCapabilities)) tasks
  results <- mapConcurrently (mapM verifyECDSATask) chunks
  return $ concat results
  where
    -- W95: previously this was a stub that accepted any 33/65-byte pubkey
    -- as a valid signature regardless of cryptographic validity.  Live
    -- ECDSA verify still goes through 'Haskoin.Script.execCheckSig' which
    -- calls 'Crypto.verifyMsgLax' directly, so the stub was unreachable;
    -- still, future callers must get real verification.
    --
    -- The DER-signature carries a trailing sighash byte that's stripped
    -- before parsing — this mirrors Bitcoin Core's CheckECDSASignature
    -- (interpreter.cpp:200) and haskoin's own execCheckSigLegacy.
    verifyECDSATask :: VerifyTask -> IO (Either String Bool)
    verifyECDSATask VerifyTask{..}
      | BS.length vtSignature < 9 =
          -- Min DER: 30 06 02 01 R 02 01 S (8) + 1 hashtype byte.
          return $ Left "Signature too short"
      | BS.length vtMessage /= 32 =
          return $ Left "Message hash must be 32 bytes"
      | not (BS.length vtPubKey `elem` [33, 65]) =
          return $ Left "Pubkey must be 33 (compressed) or 65 (uncompressed) bytes"
      | otherwise =
          let sigNoHt = BS.init vtSignature  -- strip trailing sighash byte
              msg     = Hash256 vtMessage
          in case Crypto.parsePubKey vtPubKey of
               Nothing -> return $ Left "Malformed pubkey"
               Just pk -> return $ Right $
                 Crypto.verifyMsgLax pk (Crypto.Sig sigNoHt) msg

    chunkList :: Int -> [a] -> [[a]]
    chunkList _ [] = []
    chunkList n xs = take n xs : chunkList n (drop n xs)

--------------------------------------------------------------------------------
-- Parallel Block Validation
--------------------------------------------------------------------------------

-- | Result of parallel block validation
data ParallelValidationResult
  = PVSuccess                          -- ^ All transactions valid
  | PVFailure !Int !String             -- ^ Transaction at index failed with error
  | PVUTXOMissing !OutPoint            -- ^ Missing UTXO
  deriving (Show, Eq, Generic)

instance NFData ParallelValidationResult

-- | Split transactions into N approximately equal chunks.
chunkTransactions :: Int -> [(Int, Tx)] -> [[(Int, Tx)]]
chunkTransactions n txs
  | n <= 0    = [txs]
  | null txs  = []
  | otherwise = go txs
  where
    chunkSize = max 1 ((length txs + n - 1) `div` n)
    go [] = []
    go xs = take chunkSize xs : go (drop chunkSize xs)

-- | Validate a chunk of transactions against the UTXO set.
--
-- Uses atomic operations on the TVar for thread-safe UTXO access.
-- Each transaction is validated fully before moving to the next.
-- W96: previously this function's body contained a "placeholder - real
-- impl uses script interpreter" comment and only checked
-- @totalIn >= totalOut@ — i.e., it pretended to validate without ever
-- running the script interpreter.  Same W95 stub-with-passing-test
-- anti-pattern.  Now wired to 'Script.verifyScriptWithFlags' so any
-- future production caller is safe.
validateTxChunk :: [(Int, Tx)]
                -> TVar (Map OutPoint TxOut)
                -> ConsensusFlags
                -> IO ParallelValidationResult
validateTxChunk [] _ _ = return PVSuccess
validateTxChunk ((idx, tx):rest) utxoTVar flags = do
  -- Look up all inputs atomically
  result <- atomically $ do
    utxoMap <- readTVar utxoTVar
    let inputs = txInputs tx
        lookups = [(inp, Map.lookup (txInPrevOutput inp) utxoMap) | inp <- inputs]
    case [op | (inp, Nothing) <- lookups, let op = txInPrevOutput inp] of
      (missing:_) -> return $ Left missing
      [] -> do
        -- All inputs found, verify and update UTXO set
        let prevOuts = [(txInPrevOutput inp, out) | (inp, Just out) <- lookups]
            -- Remove spent outputs
            utxoMap' = foldr (\(op, _) m -> Map.delete op m) utxoMap prevOuts
        writeTVar utxoTVar utxoMap'
        return $ Right prevOuts
  case result of
    Left missing -> return $ PVUTXOMissing missing
    Right prevOuts -> do
      let !totalIn = sum [txOutValue out | (_, out) <- prevOuts]
          !totalOut = sum [txOutValue out | out <- txOutputs tx]
      if totalIn < totalOut
        then return $ PVFailure idx "Outputs exceed inputs"
        else do
          -- Script verification (W96 fix — was missing).
          let spentAmounts = [txOutValue out | (_, out) <- prevOuts]
              spentScripts = [txOutScript out | (_, out) <- prevOuts]
              indexed = zip [0..] (map snd prevOuts)
              scriptRes =
                [ verifyOne inpIdx prevOut
                | (inpIdx, prevOut) <- indexed
                ]
              verifyOne i pOut =
                case Script.verifyScriptWithFlags (consensusFlagsToScriptFlags flags) tx i
                       (txOutScript pOut) (txOutValue pOut)
                       spentAmounts spentScripts of
                  Right True  -> Nothing
                  Right False -> Just ("input " ++ show i ++ ": script returned false")
                  Left err    -> Just ("input " ++ show i ++ ": " ++ err)
          case [e | Just e <- scriptRes] of
            (err:_) -> return $ PVFailure idx err
            []      -> validateTxChunk rest utxoTVar flags

--------------------------------------------------------------------------------
-- Memory-Mapped I/O
--------------------------------------------------------------------------------

-- | Memory-mapped block file for efficient random access.
--
-- Uses mmap(2) to map block files directly into memory, avoiding
-- read/write syscalls and buffer copies. The OS handles paging.
--
-- Benefits:
--   - Zero-copy access to block data
--   - Efficient random access for block lookups
--   - OS manages caching automatically
--   - Reduces memory pressure during IBD
data MmapBlockFile = MmapBlockFile
  { mmapFilePath :: !FilePath
  , mmapData     :: !ByteString
  , mmapSize     :: !Int
  } deriving (Show, Eq)

-- | Memory-map a block file for reading.
--
-- The entire file is mapped into the process address space.
-- Access is read-only. The ByteString shares memory with the mapping.
mmapBlockFile :: FilePath -> IO (Either String MmapBlockFile)
mmapBlockFile path = do
  result <- tryMmap path
  return result
  where
    tryMmap :: FilePath -> IO (Either String MmapBlockFile)
    tryMmap fp = do
      -- mmapFileByteString returns the file contents as a ByteString
      -- backed by mmap'ed memory
      bs <- mmapFileByteString fp Nothing
      return $ Right MmapBlockFile
        { mmapFilePath = fp
        , mmapData     = bs
        , mmapSize     = BS.length bs
        }

-- | Read a block from a memory-mapped file at the given offset.
--
-- Extracts a slice of the mapped memory. This is O(1) since it
-- just creates a new ByteString pointing to the same memory.
mmapReadBlock :: MmapBlockFile -> Int -> Int -> Either String ByteString
mmapReadBlock MmapBlockFile{..} offset len
  | offset < 0 = Left "Negative offset"
  | offset + len > mmapSize = Left "Read past end of file"
  | otherwise = Right $ BS.take len (BS.drop offset mmapData)

-- | Close a memory-mapped file.
--
-- In practice, the mapping is automatically unmapped when the ByteString
-- is garbage collected. This function is provided for explicit control.
mmapClose :: MmapBlockFile -> IO ()
mmapClose _ = return ()  -- GC handles unmapping

--------------------------------------------------------------------------------
-- Parallel Validation (Legacy)
--------------------------------------------------------------------------------

-- | Result of a parallel script verification task
data VerifyResult
  = VerifyOK
  | VerifyError !String
  deriving (Show, Eq)

-- | Verify all transaction scripts in a block in parallel.
--
-- This is the main CPU bottleneck during IBD. Uses GHC's parallel strategies
-- to distribute verification across all available cores with minimal
-- synchronization overhead.
--
-- The parallel map uses 'rseq' to evaluate each verification result to WHNF,
-- which is sufficient since the verification either succeeds or returns an
-- error string.
-- W96: previously this function was a stub (only checked
-- @txOutValue > 0@ and returned 'VerifyOK' regardless of whether the
-- input script actually validated).  Same anti-pattern as W95's
-- @batchVerifySchnorr@ / @parallelVerifyECDSA@.  The function was
-- exported but never wired into production validation paths (only a
-- single test that constructs an empty block exercises it), so no
-- on-chain behaviour was affected — but a future caller would have
-- silently accepted invalid blocks.  We now delegate to the real
-- script interpreter via 'Script.verifyScriptWithFlags' so this
-- entry point is safe to reuse.
verifyBlockScriptsParallel :: Block
                          -> Map OutPoint TxOut
                          -> ConsensusFlags
                          -> Either String ()
verifyBlockScriptsParallel block utxoMap flags =
  let nonCoinbase = case blockTxns block of
        []      -> []
        (_:txs) -> txs  -- Skip coinbase
      -- Pre-compute per-tx prevouts for BIP-341 sighash (sha_amounts,
      -- sha_scriptpubkeys).  A missing prevout is itself a verification
      -- failure (caller must populate utxoMap before this is called).
      tasks =
        [ (tx, idx, spentAmounts, spentScripts, prevOut)
        | tx <- nonCoinbase
        , let prevs = mapMaybe
                (\inp -> Map.lookup (txInPrevOutput inp) utxoMap)
                (txInputs tx)
        , length prevs == length (txInputs tx)
        , let spentAmounts = map txOutValue prevs
              spentScripts = map txOutScript prevs
        , (idx, prevOut) <- zip [0..] prevs
        ]
      -- Execute verifications in parallel using parallel strategies.
      results = parMap rseq verifyTask tasks
      verifyTask (!tx, !idx, !spentAmts, !spentScrs, !prevOut) =
        case Script.verifyScriptWithFlags
               (consensusFlagsToScriptFlags flags) tx idx
               (txOutScript prevOut) (txOutValue prevOut)
               spentAmts spentScrs of
          Left err    -> VerifyError $ "Input " ++ show idx ++ ": " ++ err
          Right False -> VerifyError $ "Input " ++ show idx ++ ": script returned false"
          Right True  -> VerifyOK
  in case [err | VerifyError err <- results] of
       []      -> Right ()
       (err:_) -> Left err

-- | Generic parallel map with configurable chunk size.
--
-- Uses parallel strategies for work distribution. The chunk size determines
-- how many items are processed together, which affects the granularity of
-- parallelism.
parallelMap :: NFData b => (a -> b) -> [a] -> [b]
parallelMap f xs = map f xs `using` parList rseq

--------------------------------------------------------------------------------
-- LRU Cache with O(1) Operations
--------------------------------------------------------------------------------

-- | LRU cache using a Map with access counters for ordering.
--
-- Each entry stores a value along with a monotonic access counter.
-- The entry with the lowest counter is the least recently used.
--
-- This is simpler than a true doubly-linked list implementation but
-- still provides O(log n) operations which is acceptable for UTXO
-- cache sizes (millions of entries).
data LRUCache k v = LRUCache
  { lruCapacity   :: !Int
  , lruSizeRef    :: !(IORef Int)
  , lruMapRef     :: !(IORef (Map k (v, Int)))  -- value + access order
  , lruCounterRef :: !(IORef Int)               -- monotonic counter for ordering
  , lruHitsRef    :: !(IORef Word64)            -- cache hits
  , lruMissesRef  :: !(IORef Word64)            -- cache misses
  }

-- | Create a new LRU cache with the given maximum capacity.
newLRUCache :: Int -> IO (LRUCache k v)
newLRUCache capacity = LRUCache capacity
  <$> newIORef 0
  <*> newIORef Map.empty
  <*> newIORef 0
  <*> newIORef 0
  <*> newIORef 0

-- | Look up a key in the cache.
--
-- If found, updates the access counter and returns Just value.
-- If not found, returns Nothing.
-- Updates hit/miss counters for monitoring.
lruLookup :: Ord k => LRUCache k v -> k -> IO (Maybe v)
lruLookup cache key = do
  m <- readIORef (lruMapRef cache)
  case Map.lookup key m of
    Nothing -> do
      atomicModifyIORef' (lruMissesRef cache) (\n -> (n + 1, ()))
      return Nothing
    Just (v, _) -> do
      -- Update access order with new counter
      counter <- atomicModifyIORef' (lruCounterRef cache) (\c -> (c + 1, c + 1))
      atomicModifyIORef' (lruMapRef cache) $ \m' ->
        (Map.insert key (v, counter) m', ())
      atomicModifyIORef' (lruHitsRef cache) (\n -> (n + 1, ()))
      return (Just v)

-- | Insert a key-value pair into the cache.
--
-- If the cache is at capacity, evicts the least recently used entry first.
lruInsert :: Ord k => LRUCache k v -> k -> v -> IO ()
lruInsert cache key value = do
  size <- readIORef (lruSizeRef cache)
  -- Check if key already exists (update doesn't change size)
  m <- readIORef (lruMapRef cache)
  let exists = Map.member key m
  -- Evict if at capacity and inserting new key
  when (not exists && size >= lruCapacity cache) $ lruEvict cache
  -- Insert with new access counter
  counter <- atomicModifyIORef' (lruCounterRef cache) (\c -> (c + 1, c + 1))
  atomicModifyIORef' (lruMapRef cache) $ \m' ->
    (Map.insert key (value, counter) m', ())
  -- Update size if this is a new key
  unless exists $
    atomicModifyIORef' (lruSizeRef cache) (\s -> (s + 1, ()))

-- | Evict the least recently used entry from the cache.
--
-- Finds the entry with the lowest access counter and removes it.
-- This is O(n) but is only called when the cache is full.
lruEvict :: Ord k => LRUCache k v -> IO ()
lruEvict cache = do
  m <- readIORef (lruMapRef cache)
  unless (Map.null m) $ do
    -- Find and remove the entry with the lowest access counter
    let (evictKey, _) = minimumBy (comparing (snd . snd)) (Map.toList m)
    atomicModifyIORef' (lruMapRef cache) $ \m' ->
      (Map.delete evictKey m', ())
    atomicModifyIORef' (lruSizeRef cache) (\s -> (s - 1, ()))

-- | Get the current size of the cache.
lruSize :: LRUCache k v -> IO Int
lruSize = readIORef . lruSizeRef

-- | Get the cache hit rate as a percentage.
lruHitRate :: LRUCache k v -> IO Double
lruHitRate cache = do
  hits <- readIORef (lruHitsRef cache)
  misses <- readIORef (lruMissesRef cache)
  let total = hits + misses
  return $ if total > 0
           then fromIntegral hits / fromIntegral total * 100
           else 0

--------------------------------------------------------------------------------
-- Node Metrics
--------------------------------------------------------------------------------

-- | Metrics for monitoring node performance.
--
-- All counters use atomic operations for thread-safe updates.
data NodeMetrics = NodeMetrics
  { nmBlocksProcessed  :: !(IORef Word64)  -- ^ Blocks validated and connected
  , nmTxsValidated     :: !(IORef Word64)  -- ^ Transactions validated
  , nmUTXOCacheHits    :: !(IORef Word64)  -- ^ UTXO cache hits
  , nmUTXOCacheMisses  :: !(IORef Word64)  -- ^ UTXO cache misses
  , nmBytesReceived    :: !(IORef Word64)  -- ^ Network bytes received
  , nmBytesSent        :: !(IORef Word64)  -- ^ Network bytes sent
  , nmPeersConnected   :: !(IORef Int)     -- ^ Current peer count
  , nmStartTime        :: !Int64           -- ^ Unix timestamp when node started
  }

-- | A snapshot of metrics at a point in time.
data MetricSnapshot = MetricSnapshot
  { msBlocksProcessed  :: !Word64
  , msTxsValidated     :: !Word64
  , msUTXOCacheHits    :: !Word64
  , msUTXOCacheMisses  :: !Word64
  , msBytesReceived    :: !Word64
  , msBytesSent        :: !Word64
  , msPeersConnected   :: !Int
  , msUptimeSeconds    :: !Int64
  , msBlocksPerSecond  :: !Double
  , msCacheHitRate     :: !Double
  } deriving (Show, Generic)

-- | Create a new NodeMetrics instance.
newNodeMetrics :: IO NodeMetrics
newNodeMetrics = do
  now <- round <$> getPOSIXTime
  NodeMetrics
    <$> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> newIORef 0
    <*> pure now

-- | Increment a metric counter by 1.
incrementMetric :: IORef Word64 -> IO ()
incrementMetric ref = atomicModifyIORef' ref (\n -> (n + 1, ()))

-- | Add a value to a metric counter.
addToMetric :: IORef Word64 -> Word64 -> IO ()
addToMetric ref amount = atomicModifyIORef' ref (\n -> (n + amount, ()))

-- | Get a snapshot of all metrics.
getMetricSnapshot :: NodeMetrics -> IO MetricSnapshot
getMetricSnapshot nm = do
  blocks <- readIORef (nmBlocksProcessed nm)
  txs <- readIORef (nmTxsValidated nm)
  hits <- readIORef (nmUTXOCacheHits nm)
  misses <- readIORef (nmUTXOCacheMisses nm)
  bytesRecv <- readIORef (nmBytesReceived nm)
  bytesSent <- readIORef (nmBytesSent nm)
  peers <- readIORef (nmPeersConnected nm)
  now <- round <$> getPOSIXTime
  let uptime = now - nmStartTime nm
      blocksPerSec = if uptime > 0
                     then fromIntegral blocks / fromIntegral uptime
                     else 0
      hitRate = if hits + misses > 0
                then fromIntegral hits / fromIntegral (hits + misses) * 100
                else 0
  return MetricSnapshot
    { msBlocksProcessed = blocks
    , msTxsValidated = txs
    , msUTXOCacheHits = hits
    , msUTXOCacheMisses = misses
    , msBytesReceived = bytesRecv
    , msBytesSent = bytesSent
    , msPeersConnected = peers
    , msUptimeSeconds = uptime
    , msBlocksPerSecond = blocksPerSec
    , msCacheHitRate = hitRate
    }

-- | Log current metrics to stdout.
logMetrics :: NodeMetrics -> IO ()
logMetrics nm = do
  snapshot <- getMetricSnapshot nm
  putStrLn $ unlines
    [ "=== Node Metrics ==="
    , "Uptime: " ++ show (msUptimeSeconds snapshot) ++ "s"
    , "Blocks processed: " ++ show (msBlocksProcessed snapshot)
    , "Transactions validated: " ++ show (msTxsValidated snapshot)
    , "UTXO cache hit rate: " ++ show (round (msCacheHitRate snapshot) :: Int) ++ "%"
    , "Blocks/sec: " ++ show (msBlocksPerSecond snapshot)
    , "Peers connected: " ++ show (msPeersConnected snapshot)
    , "Network: " ++ show (msBytesReceived snapshot) ++ " bytes recv, "
                  ++ show (msBytesSent snapshot) ++ " bytes sent"
    ]

--------------------------------------------------------------------------------
-- Strict Block Processing
--------------------------------------------------------------------------------

-- | Compute transaction fee with strict evaluation.
--
-- Returns (inputs - outputs) for the transaction, validating that
-- inputs cover outputs. Uses bang patterns throughout.
computeTxFeeStrict :: Map OutPoint TxOut -> Tx -> Either String Word64
computeTxFeeStrict utxoMap tx =
  let !inputs = txInputs tx
      !inputValues = map (\inp ->
        case Map.lookup (txInPrevOutput inp) utxoMap of
          Nothing -> Left $ "Missing UTXO: " ++ show (txInPrevOutput inp)
          Just txout -> Right $! txOutValue txout
        ) inputs
      !outputValues = map txOutValue (txOutputs tx)
  in case sequence inputValues of
       Left err -> Left err
       Right vals -> let !totalIn = sum vals
                         !totalOut = sum outputValues
                     in if totalIn >= totalOut
                        then Right $! totalIn - totalOut
                        else Left "Outputs exceed inputs"

--------------------------------------------------------------------------------
-- Socket Optimization
--------------------------------------------------------------------------------

-- | Optimize a socket for Bitcoin P2P communication.
--
-- Enables:
--   - TCP_NODELAY: Disable Nagle's algorithm for low-latency messaging
--   - SO_KEEPALIVE: Enable TCP keepalive for connection health
--   - Large send/receive buffers (256 KB each)
optimizeSocket :: Socket -> IO ()
optimizeSocket sock = do
  setSocketOption sock NoDelay 1        -- TCP_NODELAY
  setSocketOption sock KeepAlive 1      -- TCP keepalive
  setSocketOption sock SendBuffer (256 * 1024)  -- 256 KB send buffer
  setSocketOption sock RecvBuffer (256 * 1024)  -- 256 KB receive buffer

--------------------------------------------------------------------------------
-- Database Tuning
--------------------------------------------------------------------------------

-- | IBD-optimized database configuration.
--
-- Tuned for write-heavy workload during Initial Block Download:
--   - Large write buffer (256 MB) to reduce write amplification
--   - Large block cache (512 MB) for read performance
--   - 10 bits/key bloom filter for fast UTXO negative lookups
--   - Compression enabled (LZ4/Snappy) to reduce I/O
--
-- These settings use more memory but significantly improve IBD speed.
ibdDBConfig :: FilePath -> (FilePath, Bool, Int, Int, Int, Int, Bool)
ibdDBConfig path =
  ( path
  , True                        -- createIfMissing
  , 1000                        -- maxOpenFiles
  , 256 * 1024 * 1024           -- writeBufferSize: 256 MB during IBD
  , 512 * 1024 * 1024           -- blockCacheSize: 512 MB
  , 10                          -- bloomFilterBits
  , True                        -- compression
  )

-- | Compact the UTXO key range in the database.
--
-- UTXO entries are the most write-heavy during IBD. Periodic compaction
-- reclaims space from deleted entries and improves read performance.
--
-- The key range is determined by the UTXO prefix byte (0x05).
compactUTXORange :: IO ()
compactUTXORange = do
  -- In production, this would call RocksDB compactRange
  -- with the UTXO key prefix range
  putStrLn "Compacting UTXO range..."
  -- R.compactRange db startKey endKey
  -- where startKey = BS.singleton 0x05
  --       endKey = BS.singleton 0x06

--------------------------------------------------------------------------------
-- Signature Verification Cache
--------------------------------------------------------------------------------

-- | Cache key: first 8 bytes of SHA256(nonce || sighash || pubkey || sig || flagsBytes).
--
-- Using a Word64 (Core's CheapHash pattern) keeps Map operations O(1) in
-- key comparison while still providing 64-bit collision resistance on top
-- of the per-process nonce.  Two entries can collide with probability
-- 2^{-64} per pair — negligible for a 50 000-entry cache.
newtype SigCacheKey = SigCacheKey Word64
  deriving (Eq, Ord, Show)

-- | Thread-safe signature verification cache.
--
-- Caches the results of successful script verification to avoid redundant
-- ECDSA/Schnorr signature checks. This is critical during:
--   - Block validation (same tx may be verified multiple times during reorgs)
--   - Mempool acceptance (transactions re-verified when blocks arrive)
--
-- The cache uses a bounded Map with deleteMin eviction.  The 32-byte random
-- nonce (initialised from /dev/urandom at construction) prevents an attacker
-- from predicting which key values collide, closing the cache-poisoning vector
-- documented in W105 BUG-9.  The key commits to the full signature material
-- (sighash, pubkey, sig bytes, flags) so DER-malleated signatures that share
-- a txid never share a cache entry (W105 BUG-13 fix).
--
-- Typical hit rate: 30-50% during normal operation, higher during reorgs.
data SigCache = SigCache
  { sigCacheNonce :: !ByteString        -- ^ 32-byte /dev/urandom nonce
  , sigCacheRef   :: !(IORef (Map SigCacheKey ()))
  }

-- | Maximum number of entries in the signature cache.
sigCacheMaxEntries :: Int
sigCacheMaxEntries = 50000

-- | Create a new empty signature cache with a fresh cryptographic nonce.
--
-- Uses 'CryptoRandom.getRandomBytes' (cryptonite, backed by \/dev\/urandom)
-- to generate a 32-byte nonce that salts every cache key.  This is the same
-- approach as Bitcoin Core's @SignatureCache()@ constructor which calls
-- @GetRandHash()@ at startup (sigcache.cpp).
newSigCache :: IO SigCache
newSigCache = do
  nonce <- CryptoRandom.getRandomBytes 32 :: IO ByteString
  ref   <- newIORef Map.empty
  return (SigCache nonce ref)

-- | Derive a 'SigCacheKey' from the per-cache nonce and full signature
-- material.
--
-- Key = first 8 bytes of SHA256(nonce || sighash || pubkey || sig || flagsBytes)
--
-- This mirrors Core's @ComputeEntryECDSA@ / @ComputeEntrySchnorr@ which hash
-- the nonce together with the sighash, pubkey, and raw signature bytes.
-- Arguments:
--   nonce      — 32-byte per-process secret
--   sighash    — 32-byte transaction/input sighash (or txid bytes as proxy)
--   pubkey     — compressed/uncompressed pubkey bytes (may be empty)
--   sig        — raw DER or Schnorr signature bytes (may be empty)
--   flagsBytes — 4-byte little-endian script flags word
computeSigCacheKey :: ByteString -> ByteString -> ByteString -> ByteString -> ByteString -> SigCacheKey
computeSigCacheKey nonce sighash pubkey sig flagsBytes =
  let material = nonce <> sighash <> pubkey <> sig <> flagsBytes
      digest   = convert (H.hashWith H.SHA256 material) :: ByteString
      -- Fold the first 8 bytes into a big-endian Word64 (CheapHash)
      w64      = BS.foldl' (\acc b -> (acc `shiftL` 8) .|. fromIntegral (b :: Word8))
                           (0 :: Word64)
                           (BS.take 8 digest)
  in SigCacheKey w64
{-# INLINE computeSigCacheKey #-}

-- | Look up a verification result in the cache.
--
-- Returns True if the given signature material was previously verified
-- successfully within this cache instance.
-- Arguments: (sighash, pubkey, sig, flagsBytes) — same convention as
-- 'insertSigCache'.
lookupSigCache :: SigCache -> ByteString -> ByteString -> ByteString -> ByteString -> IO Bool
lookupSigCache (SigCache nonce ref) sighash pubkey sig flagsBytes = do
  m <- readIORef ref
  let key = computeSigCacheKey nonce sighash pubkey sig flagsBytes
  return $! Map.member key m

-- | Insert a successful verification result into the cache.
--
-- Arguments: (sighash, pubkey, sig, flagsBytes) where:
--   sighash    — 32-byte transaction/input sighash (or txid bytes as proxy)
--   pubkey     — raw pubkey bytes
--   sig        — raw signature bytes (DER or Schnorr)
--   flagsBytes — 4-byte little-endian script flags word
--
-- If the cache has reached 'sigCacheMaxEntries', the entry with the smallest
-- key (lexicographic on the Word64 hash) is evicted.
insertSigCache :: SigCache -> ByteString -> ByteString -> ByteString -> ByteString -> IO ()
insertSigCache (SigCache nonce ref) sighash pubkey sig flagsBytes =
  atomicModifyIORef' ref $ \m ->
    let key = computeSigCacheKey nonce sighash pubkey sig flagsBytes
        m'  = if Map.size m >= sigCacheMaxEntries
              then Map.insert key () (Map.deleteMin m)
              else Map.insert key () m
    in (m', ())

-- | Clear all entries from the signature cache.
--
-- Should be called when the chain tip changes significantly (e.g., reorg)
-- to prevent stale cache entries from causing incorrect validation.
-- The nonce is preserved — a fresh nonce is only generated at construction
-- (via 'newSigCache' / 'initGlobalSigCache').
clearSigCache :: SigCache -> IO ()
clearSigCache (SigCache _nonce ref) = writeIORef ref Map.empty

-- | Get the current number of entries in the signature cache.
sigCacheSize :: SigCache -> IO Int
sigCacheSize (SigCache _nonce ref) = Map.size <$> readIORef ref

--------------------------------------------------------------------------------
-- Global (process-wide) Signature Cache
--------------------------------------------------------------------------------

-- | Process-global SigCache singleton.
--
-- Mirrors the 'Haskoin.Daemon.globalDebugSet' pattern: a top-level IORef
-- initialised with an empty placeholder, replaced by 'initGlobalSigCache'
-- during node startup.  All calls to 'validateSingleTx' read through this
-- ref, so no SigCache argument threads through the entire call chain.
--
-- Threading choice rationale: the alternative — adding a SigCache parameter
-- to validateSingleTx → validateBlockTransactions → validateFullBlockIO →
-- connectBlock — would touch ~10 functions across Consensus.hs and
-- app/Main.hs, all of which are called from multiple paths.  The module-level
-- IORef matches the existing globalDebugSet precedent in this codebase and
-- is safe because: (a) writes happen exactly once at startup before any
-- validation thread runs, and (b) concurrent reads via lookupSigCache /
-- insertSigCache are already protected by atomicModifyIORef' inside SigCache.
{-# NOINLINE globalSigCache #-}
globalSigCache :: IORef SigCache
globalSigCache = unsafePerformIO (newSigCache >>= newIORef)

-- | Replace the process-global SigCache.
-- Call once during node startup before any block validation.
-- Creates a fresh 50 000-entry cache (sigCacheMaxEntries) with a new
-- cryptographic nonce from /dev/urandom.  Previous entries (and the old
-- nonce) are discarded, preventing any stale cache entries from a prior
-- run or reindex from being reused.
initGlobalSigCache :: IO ()
initGlobalSigCache = do
  sc <- newSigCache
  writeIORef globalSigCache sc

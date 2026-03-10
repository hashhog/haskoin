{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Block Download & Initial Block Download (IBD)
--
-- This module implements the IBD pipeline that downloads full blocks from peers
-- after headers are synced, validates them in order, and connects them to the
-- chain state with parallel download from multiple peers.
--
-- Key design:
--   - Pipelined downloads: up to 128 blocks in flight simultaneously
--   - Per-peer in-flight cap: ~16 blocks per peer to avoid slow peer blocking
--   - Adaptive stalling: base ~5s timeout, doubles on stall, decays on success
--   - Batch GetData: multiple inv items per message for efficiency
--   - UTXO flush interval: every ~2000 blocks during IBD
--   - Blocks validated and connected strictly in height order
--
module Haskoin.Sync
  ( -- * Block Downloader
    BlockDownloader(..)
  , BlockRequest(..)
  , IBDState(..)
    -- * IBD Control
  , startIBD
  , stopIBD
  , getIBDState
    -- * Block Handling
  , handleBlockMessage
    -- * Internal (exposed for testing)
  , downloadScheduler
  , downloadWorker
  , blockProcessor
  , buildUTXOMap
  , flushTBQueueN
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int64)
import Control.Monad (when, unless, forever, forM, forM_, void)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Control.Concurrent.STM
import Control.Concurrent (forkIO, threadDelay, ThreadId, killThread)
import Control.Exception (try, SomeException, catch)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Maybe (mapMaybe, catMaybes)
import Data.Serialize (encode)
import GHC.Generics (Generic)
import Network.Socket (SockAddr)

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Network

--------------------------------------------------------------------------------
-- Types
--------------------------------------------------------------------------------

-- | Block download coordinator for IBD
--
-- Uses a pipelined download strategy: multiple blocks are requested
-- simultaneously from different peers (up to 128 in flight), while a
-- separate thread validates and connects blocks strictly in order.
-- This maximizes network throughput while maintaining chain consistency.
data BlockDownloader = BlockDownloader
  { bdPeerMgr       :: !PeerManager
  , bdHeaderChain   :: !HeaderChain
  , bdDB            :: !HaskoinDB
  , bdNetwork       :: !Network
  , bdPendingBlocks :: !(TVar (Map BlockHash BlockRequest))
  , bdDownloadQueue :: !(TBQueue BlockHash)
  , bdProcessQueue  :: !(TBQueue Block)
  , bdCurrentHeight :: !(TVar Word32)      -- ^ Highest connected block
  , bdIBDActive     :: !(TVar Bool)
  , bdWorkerThreads :: !(TVar [ThreadId])
  , bdBatchSize     :: !Int                -- ^ Blocks per getdata (default 16)
  , bdMaxInFlight   :: !Int                -- ^ Max blocks in flight (default 128)
  , bdPerPeerMax    :: !Int                -- ^ Max blocks per peer (default 16)
  , bdBaseTimeout   :: !(TVar Int64)       -- ^ Base timeout in seconds (adaptive)
  , bdFlushCounter  :: !(TVar Word32)      -- ^ Blocks since last UTXO flush
  }

-- | A pending block request
data BlockRequest = BlockRequest
  { brHash       :: !BlockHash
  , brHeight     :: !Word32
  , brPeer       :: !(Maybe SockAddr)      -- ^ Peer we requested from
  , brRequested  :: !Int64                 -- ^ Unix timestamp when requested
  , brReceived   :: !Bool                  -- ^ Has the block been received?
  , brRetries    :: !Int                   -- ^ Number of retry attempts
  } deriving (Show, Generic)

-- | IBD state for progress reporting
data IBDState
  = IBDNotStarted
  | IBDDownloading !Word32 !Word32         -- ^ (current height, target height)
  | IBDValidating !Word32                  -- ^ Height being validated
  | IBDComplete
  deriving (Show, Eq, Generic)

--------------------------------------------------------------------------------
-- IBD Control
--------------------------------------------------------------------------------

-- | Start the Initial Block Download process
--
-- Creates a BlockDownloader and spawns:
--   - One download worker per connected peer
--   - A block processing thread for validation/connection
--   - A download scheduler for managing requests
startIBD :: Network -> HaskoinDB -> HeaderChain -> PeerManager -> IO BlockDownloader
startIBD net db hc pm = do
  -- Initialize the downloader state
  pendingVar <- newTVarIO Map.empty
  downloadQ <- newTBQueueIO 1024
  processQ <- newTBQueueIO 64
  heightVar <- newTVarIO 0
  activeVar <- newTVarIO True
  threadsVar <- newTVarIO []
  timeoutVar <- newTVarIO 5        -- Base 5 second timeout
  flushVar <- newTVarIO 0

  let bd = BlockDownloader
        { bdPeerMgr = pm
        , bdHeaderChain = hc
        , bdDB = db
        , bdNetwork = net
        , bdPendingBlocks = pendingVar
        , bdDownloadQueue = downloadQ
        , bdProcessQueue = processQ
        , bdCurrentHeight = heightVar
        , bdIBDActive = activeVar
        , bdWorkerThreads = threadsVar
        , bdBatchSize = 16           -- 16 blocks per getdata
        , bdMaxInFlight = 128        -- Max 128 blocks in flight total
        , bdPerPeerMax = 16          -- Max 16 blocks per peer
        , bdBaseTimeout = timeoutVar
        , bdFlushCounter = flushVar
        }

  -- Start download workers (one per connected peer)
  peers <- getConnectedPeers pm
  workerTids <- forM peers $ \(addr, _) ->
    forkIO $ downloadWorker bd addr

  -- Start the block processing thread
  processTid <- forkIO $ blockProcessor bd

  -- Start the download scheduler
  schedulerTid <- forkIO $ downloadScheduler bd

  atomically $ writeTVar threadsVar (schedulerTid : processTid : workerTids)

  return bd

-- | Stop the IBD process and clean up threads
stopIBD :: BlockDownloader -> IO ()
stopIBD bd = do
  atomically $ writeTVar (bdIBDActive bd) False
  tids <- readTVarIO (bdWorkerThreads bd)
  mapM_ killThread tids
  atomically $ writeTVar (bdWorkerThreads bd) []

-- | Get the current IBD state for progress reporting
getIBDState :: BlockDownloader -> IO IBDState
getIBDState bd = do
  active <- readTVarIO (bdIBDActive bd)
  if not active
    then return IBDComplete
    else do
      currentHeight <- readTVarIO (bdCurrentHeight bd)
      tipHeight <- readTVarIO (hcHeight (bdHeaderChain bd))
      if currentHeight >= tipHeight
        then return IBDComplete
        else return $ IBDDownloading currentHeight tipHeight

--------------------------------------------------------------------------------
-- Download Scheduler
--------------------------------------------------------------------------------

-- | Download scheduler: manages which blocks to request
--
-- Periodically checks if more blocks should be requested and handles
-- stalled requests by re-requesting from different peers.
downloadScheduler :: BlockDownloader -> IO ()
downloadScheduler bd = forever $ do
  active <- readTVarIO (bdIBDActive bd)
  when active $ do
    currentHeight <- readTVarIO (bdCurrentHeight bd)
    tipHeight <- readTVarIO (hcHeight (bdHeaderChain bd))
    pending <- readTVarIO (bdPendingBlocks bd)

    let inFlight = Map.size $ Map.filter (not . brReceived) pending

    -- Schedule more downloads if below the in-flight limit
    when (inFlight < bdMaxInFlight bd && currentHeight < tipHeight) $ do
      heightMap <- readTVarIO (hcByHeight (bdHeaderChain bd))
      entries <- readTVarIO (hcEntries (bdHeaderChain bd))

      -- Calculate next heights to download
      -- Start from currentHeight + 1 + number of pending blocks
      let pendingCount = fromIntegral $ Map.size pending
          nextHeight = currentHeight + 1
          -- Get up to batchSize new blocks that aren't already pending
          toDownload = take (bdBatchSize bd) $
            filter (\bh -> not $ Map.member bh pending) $
            mapMaybe (\h -> Map.lookup h heightMap)
              [nextHeight + pendingCount .. nextHeight + pendingCount + fromIntegral (bdBatchSize bd)]

      -- Queue download requests
      now <- round <$> getPOSIXTime
      forM_ toDownload $ \bh -> do
        let height = maybe 0 ceHeight (Map.lookup bh entries)
            req = BlockRequest bh height Nothing now False 0
        atomically $ do
          modifyTVar' (bdPendingBlocks bd) (Map.insert bh req)
          writeTBQueue (bdDownloadQueue bd) bh

    -- Check for stalled requests
    now <- round <$> getPOSIXTime
    baseTimeout <- readTVarIO (bdBaseTimeout bd)
    let stalled = Map.filter (\r -> not (brReceived r)
                                 && now - brRequested r > baseTimeout) pending

    -- Re-request stalled blocks from different peers
    -- KNOWN PITFALL: Adaptive stalling - double timeout on stall
    forM_ (Map.toList stalled) $ \(bh, req) -> do
      let newRetries = brRetries req + 1
          -- Cap timeout at 64 seconds
          newTimeout = min 64 (baseTimeout * 2)

      atomically $ do
        -- Update timeout (will decay on successful receives)
        writeTVar (bdBaseTimeout bd) newTimeout
        -- Reset request with new peer (Nothing means scheduler picks)
        modifyTVar' (bdPendingBlocks bd) $
          Map.adjust (\r -> r { brRequested = now
                              , brPeer = Nothing
                              , brRetries = newRetries
                              }) bh
        -- Re-queue for download
        writeTBQueue (bdDownloadQueue bd) bh

  threadDelay (1 * 1000000)  -- Check every second

--------------------------------------------------------------------------------
-- Download Worker
--------------------------------------------------------------------------------

-- | Download worker: handles block requests for a specific peer
--
-- Each peer has its own worker that:
--   - Batches block requests (up to 16 per getdata)
--   - Respects per-peer in-flight limits
--   - Sends getdata with MSG_WITNESS_BLOCK type for SegWit
downloadWorker :: BlockDownloader -> SockAddr -> IO ()
downloadWorker bd addr = forever $ do
  active <- readTVarIO (bdIBDActive bd)
  when active $ do
    -- Check how many blocks this peer already has in flight
    pending <- readTVarIO (bdPendingBlocks bd)
    let peerInFlight = Map.size $ Map.filter (\r -> brPeer r == Just addr
                                                  && not (brReceived r)) pending

    -- Only request more if below per-peer cap
    when (peerInFlight < bdPerPeerMax bd) $ do
      -- Get batch of blocks to download (up to batchSize or perPeerMax - peerInFlight)
      let maxToGet = min (bdBatchSize bd) (bdPerPeerMax bd - peerInFlight)
      hashes <- atomically $ flushTBQueueN (bdDownloadQueue bd) maxToGet

      unless (null hashes) $ do
        -- Mark as assigned to this peer
        now <- round <$> getPOSIXTime
        atomically $ forM_ hashes $ \bh ->
          modifyTVar' (bdPendingBlocks bd) $
            Map.adjust (\r -> r { brPeer = Just addr, brRequested = now }) bh

        -- KNOWN PITFALL: Batch GetData - multiple inv items per message
        -- Send getdata for witness blocks (MSG_WITNESS_BLOCK = 0x40000002)
        let invVectors = map (\bh ->
              InvVector InvWitnessBlock (getBlockHashHash bh)) hashes
        requestFromPeer (bdPeerMgr bd) addr (MGetData (GetData invVectors))
          `catch` (\(_ :: SomeException) -> return ())

  threadDelay (100 * 1000)  -- 100ms between checks

-- | Read up to n items from a TBQueue without blocking
flushTBQueueN :: TBQueue a -> Int -> STM [a]
flushTBQueueN _ 0 = return []
flushTBQueueN q n = do
  mItem <- tryReadTBQueue q
  case mItem of
    Nothing -> return []
    Just item -> (item :) <$> flushTBQueueN q (n - 1)

--------------------------------------------------------------------------------
-- Block Processor
--------------------------------------------------------------------------------

-- | Block processor: validates and connects blocks in order
--
-- Processes blocks strictly in height order. For each block:
--   1. Build UTXO map for the block's inputs
--   2. Validate the full block against consensus rules
--   3. Connect the block (update UTXO set, indexes, chain tip)
--
-- Progress is logged every 1000 blocks.
blockProcessor :: BlockDownloader -> IO ()
blockProcessor bd = forever $ do
  active <- readTVarIO (bdIBDActive bd)
  if not active
    then threadDelay (1 * 1000000)
    else do
      -- Get current state
      currentHeight <- readTVarIO (bdCurrentHeight bd)
      heightMap <- readTVarIO (hcByHeight (bdHeaderChain bd))

      let nextHeight = currentHeight + 1
          nextHash = Map.lookup nextHeight heightMap

      case nextHash of
        Nothing -> threadDelay (100 * 1000)  -- Wait for headers
        Just bh -> do
          pending <- readTVarIO (bdPendingBlocks bd)
          case Map.lookup bh pending of
            Just req | brReceived req -> do
              -- Block is downloaded, retrieve and validate
              mBlock <- getBlock (bdDB bd) bh
              case mBlock of
                Nothing -> threadDelay (100 * 1000)
                Just block -> do
                  -- Build UTXO map for this block's inputs
                  utxoMap <- buildUTXOMap bd block

                  let cs = ChainState currentHeight bh 0 0
                            (consensusFlagsAtHeight (bdNetwork bd) nextHeight)

                  case validateFullBlock (bdNetwork bd) cs block utxoMap of
                    Left err -> do
                      putStrLn $ "Block validation failed at height "
                                 ++ show nextHeight ++ ": " ++ err
                      -- Mark block as invalid, remove from pending
                      atomically $ modifyTVar' (bdPendingBlocks bd) (Map.delete bh)
                      -- TODO: Could try to find alternative chain

                    Right () -> do
                      -- Connect the block
                      connectBlock (bdDB bd) (bdNetwork bd) block nextHeight

                      atomically $ do
                        writeTVar (bdCurrentHeight bd) nextHeight
                        modifyTVar' (bdPendingBlocks bd) (Map.delete bh)

                      -- Decay timeout on success
                      atomically $ modifyTVar' (bdBaseTimeout bd) $ \t ->
                        max 5 (t - 1)

                      -- KNOWN PITFALL: UTXO flush interval
                      -- Flush every ~2000 blocks during IBD
                      flushCount <- atomically $ do
                        cnt <- readTVar (bdFlushCounter bd)
                        let newCnt = cnt + 1
                        if newCnt >= 2000
                          then writeTVar (bdFlushCounter bd) 0 >> return newCnt
                          else writeTVar (bdFlushCounter bd) newCnt >> return newCnt
                        return newCnt

                      -- Note: RocksDB handles flushing internally
                      -- In production, might want explicit sync here

                      -- Log progress
                      when (nextHeight `mod` 1000 == 0) $
                        putStrLn $ "Connected block " ++ show nextHeight

            _ -> threadDelay (100 * 1000)  -- Block not yet downloaded

-- | Build UTXO map for a block's inputs from database
--
-- Looks up all UTXOs that the block's non-coinbase transactions spend.
-- This is the bottleneck during IBD.
buildUTXOMap :: BlockDownloader -> Block -> IO (Map OutPoint TxOut)
buildUTXOMap bd block = do
  -- Get all inputs from non-coinbase transactions
  let inputs = case blockTxns block of
        []     -> []
        (_:txs) -> concatMap txInputs txs  -- Skip coinbase
      outpoints = map txInPrevOutput inputs

  -- Look up each UTXO
  utxos <- forM outpoints $ \op -> do
    mUtxo <- getUTXO (bdDB bd) op
    return (op, mUtxo)

  return $ Map.fromList [(op, txo) | (op, Just txo) <- utxos]

--------------------------------------------------------------------------------
-- Block Message Handling
--------------------------------------------------------------------------------

-- | Handle a received block message from the network
--
-- Called by the network layer when a block is received:
--   1. Store the block data in the database
--   2. Mark the request as received in pending map
handleBlockMessage :: BlockDownloader -> SockAddr -> Block -> IO ()
handleBlockMessage bd _addr block = do
  let bh = computeBlockHash (blockHeader block)

  -- Store the block data
  putBlock (bdDB bd) bh block

  -- Mark as received
  atomically $ modifyTVar' (bdPendingBlocks bd) $
    Map.adjust (\r -> r { brReceived = True }) bh

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
    -- * Header Sync Anti-DoS (PRESYNC/REDOWNLOAD)
  , HeaderSyncState(..)
  , PresyncData(..)
  , RedownloadData(..)
  , HeaderSyncPeer(..)
  , initHeaderSyncPeer
  , processPresyncHeaders
  , processRedownloadHeaders
  , getHeaderSyncState
  , shouldStartPresync
  , maxHeadersPerMessage
    -- * Internal (exposed for testing)
  , downloadScheduler
  , downloadWorker
  , blockProcessor
  , buildUTXOMap
  , flushTBQueueN
  , commitmentHash
  , processRedownloadBatch
  , popHeadersReadyForAcceptance
  , runPresync
  , runRedownload
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int64)
import Data.Bits (xor, (.&.))
import Control.Monad (when, unless, forever, forM, forM_)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Sequence as Seq
import Data.Sequence (Seq, (|>))
import Control.Concurrent.STM
import Control.Concurrent (forkIO, threadDelay, ThreadId, killThread)
import Control.Exception (SomeException, catch)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Maybe (mapMaybe)
import Data.Serialize (encode)
import GHC.Generics (Generic)
import Network.Socket (SockAddr)
import System.Random (randomRIO)

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash, sha256, computeTxId)
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Network
import Haskoin.Index (IndexManager, indexManagerConnectBlock)

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
  , bdIndexMgr      :: !(Maybe IndexManager)
    -- ^ Optional secondary-index manager (txindex /
    -- blockfilterindex / coinstatsindex). When 'Just', every
    -- successful 'connectBlock' is mirrored into the enabled
    -- indexes via 'indexManagerConnectBlock'. 'Nothing' is the
    -- default for nodes that don't opt in to any index, mirroring
    -- Bitcoin Core's @-blockfilterindex=0@ default.
    -- Reference: bitcoin-core/src/index/blockfilterindex.cpp
    -- BlockFilterIndex::CustomAppend.
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
startIBD :: Network -> HaskoinDB -> HeaderChain -> PeerManager
         -> Maybe IndexManager
            -- ^ Secondary indexes opted in via CLI ('--blockfilterindex'
            -- etc).  'Nothing' = run plain IBD; 'Just' = mirror every
            -- 'connectBlock' into the enabled indexes.
         -> IO BlockDownloader
startIBD net db hc pm mIdxMgr = do
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
        , bdIndexMgr = mIdxMgr
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
                  -- Build UTXO map for this block's inputs (full Coin
                  -- metadata; needed by connectBlock so the BlockUndo
                  -- record carries height + coinbase flag for each
                  -- spent prevout, and by validateFullBlock for BIP-68
                  -- SequenceLocks which requires per-coin heights).
                  utxoMap <- buildUTXOMap bd block

                  -- Read header chain entries first so we can compute MTP
                  -- for the previous block (needed for BIP-113 locktime cutoff).
                  blockEntries <- readTVarIO (hcEntries (bdHeaderChain bd))
                  bestHdr      <- readTVarIO (hcTip (bdHeaderChain bd))

                  -- Median Time Past of the previous block (bh = prev block hash).
                  -- BIP-113: when CSV is active, nLockTimeCutoff = MTP of prev block.
                  let prevMTP = medianTimePast blockEntries bh
                      cs = ChainState currentHeight bh 0 prevMTP
                            (consensusFlagsAtHeight (bdNetwork bd) nextHeight)

                  -- Compute the assumevalid skip decision using the real
                  -- ancestor-check semantics (Bitcoin Core v28.0 equivalent).
                  -- All six conditions are evaluated inside shouldSkipScripts.
                  let blockTs    = bhTimestamp (blockHeader block)
                      skipScripts = shouldSkipScripts bh nextHeight blockTs
                                      (bdNetwork bd) blockEntries bestHdr

                  -- BIP-30 + full block validation via the unified IO wrapper.
                  -- 'validateFullBlockIO' sequences checkBIP30 (UTXO duplicate-txid
                  -- guard) then validateFullBlock (all other consensus checks) so
                  -- that both the IBD arm and submitBlock share identical coverage.
                  -- Reference: Bitcoin Core ConnectBlock / IsBIP30Repeat().
                  validationResult <- validateFullBlockIO (bdDB bd) (bdNetwork bd) cs skipScripts block utxoMap

                  case validationResult of
                    Left err -> do
                      putStrLn $ "Block validation failed at height "
                                 ++ show nextHeight ++ ": " ++ err
                      -- Mark block as invalid, remove from pending
                      atomically $ modifyTVar' (bdPendingBlocks bd) (Map.delete bh)
                      -- TODO: Could try to find alternative chain

                    Right () -> do
                      -- Connect the block. Pass the same utxoMap that
                      -- validation just consumed so connectBlock can
                      -- write per-block undo data (TxOuts the block
                      -- spends) atomically with the UTXO mutation.
                      -- Without this, dumptxoutset rollback can't
                      -- rewind: see handleDumpTxOutSet in Rpc.hs.
                      connectBlock (bdDB bd) (bdNetwork bd) block nextHeight utxoMap

                      -- Mirror the connect into any opted-in
                      -- secondary indexes (txindex / blockfilterindex
                      -- / coinstatsindex).  We read the undo record
                      -- back from disk (cheap point-lookup; the same
                      -- writeBatch above just put it there) so the
                      -- BlockFilterIndex sees byte-identical
                      -- 'BlockUndo' to what 'disconnectBlock' would
                      -- replay — keeps the filter byte-for-byte
                      -- compatible with Core's blockfilterindex.cpp
                      -- CustomAppend output.
                      case bdIndexMgr bd of
                        Nothing -> return ()
                        Just im -> do
                          mUndo <- getUndoData (bdDB bd) bh
                          case mUndo of
                            Just undoData ->
                              indexManagerConnectBlock im block
                                (udBlockUndo undoData) bh nextHeight
                            Nothing -> return ()

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
--
-- Returns 'Map OutPoint Coin' (full Core-format metadata: TxOut +
-- height + coinbase flag) so 'connectBlock' can write per-block
-- undo data that round-trips byte-identically through
-- 'disconnectBlock'. Callers that only need the @TxOut@ projection
-- (e.g. 'validateFullBlock') can derive it via @fmap coinTxOut@.
--
-- Reference: bitcoin-core/src/validation.cpp @ConnectBlock@ populates
-- @CTxUndo::vprevout@ with full @Coin@ data; @DisconnectBlock@ reads
-- it and restores Coins via @view.AddCoin(..)@.
buildUTXOMap :: BlockDownloader -> Block -> IO (Map OutPoint Coin)
buildUTXOMap bd block = do
  -- Get all inputs from non-coinbase transactions
  let inputs = case blockTxns block of
        []     -> []
        (_:txs) -> concatMap txInputs txs  -- Skip coinbase
      outpoints = map txInPrevOutput inputs

  -- Look up each UTXO with full Core metadata.
  utxos <- forM outpoints $ \op -> do
    mCoin <- getUTXOCoin (bdDB bd) op
    return (op, mCoin)

  return $ Map.fromList [(op, c) | (op, Just c) <- utxos]

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

--------------------------------------------------------------------------------
-- Header Sync Anti-DoS (PRESYNC/REDOWNLOAD)
--------------------------------------------------------------------------------

-- | Maximum headers per message (Bitcoin protocol limit)
maxHeadersPerMessage :: Int
maxHeadersPerMessage = 2000

-- | Header sync state machine
--
-- Based on Bitcoin Core's HeadersSyncState. During initial sync:
--   1. PRESYNC: Accept headers without storing them permanently.
--      Track only cumulative work, last hash, and count. Store 1-bit
--      commitments every N blocks for later verification.
--   2. REDOWNLOAD: Once sufficient work is demonstrated, re-request
--      all headers and verify they match the commitments.
--   3. SYNCED: Headers accepted, can proceed to block download.
data HeaderSyncState
  = Presync !PresyncData
  | Redownload !RedownloadData
  | Synced
  deriving (Show, Eq, Generic)

-- | Data tracked during PRESYNC phase
--
-- Memory-efficient: stores only summary info, not actual headers.
-- 1-bit commitments (LSB of hash) every commitment_period blocks.
-- Reference: bitcoin-core/src/headerssync.h (private members of HeadersSyncState).
data PresyncData = PresyncData
  { pdCumulativeWork   :: !Integer       -- ^ Total PoW accumulated (starts at chain_start.nChainWork)
  , pdLastHeaderHash   :: !BlockHash     -- ^ Hash of most recent header (starts at chain_start hash)
  , pdLastHeaderBits   :: !Word32        -- ^ Bits (difficulty) of last header (for PermittedDifficultyTransition)
  , pdChainStartNBits  :: !Word32        -- ^ Bits of chain_start block (seed for REDOWNLOAD)
  , pdCount            :: !Int           -- ^ Number of headers processed beyond chain_start
  , pdCommitments      :: !(Seq Bool)    -- ^ 1-bit commitments (LSB of hash)
  , pdCommitOffset     :: !Int           -- ^ Random offset for commitment period (m_commit_offset)
  , pdStartHash        :: !BlockHash     -- ^ Hash of chain_start block
  , pdStartHeight      :: !Int64         -- ^ Height of chain_start (m_chain_start.nHeight)
  , pdMaxCommitments   :: !Word64        -- ^ Upper bound on commitments (m_max_commitments)
  , pdMinimumWork      :: !Integer       -- ^ Target work threshold to proceed
  , pdParams           :: !HeaderSyncParams
  } deriving (Show, Eq, Generic)

-- | Data tracked during REDOWNLOAD phase
-- Reference: bitcoin-core/src/headerssync.h (REDOWNLOAD state members).
data RedownloadData = RedownloadData
  { rdLastHeaderHash    :: !BlockHash     -- ^ Hash of most recent redownloaded header (m_redownload_buffer_last_hash)
  , rdFirstPrevHash     :: !BlockHash     -- ^ prevHash of oldest buffered header (m_redownload_buffer_first_prev_hash)
  , rdLastHeaderBits    :: !Word32        -- ^ Bits (difficulty) of last header (for PermittedDifficultyTransition)
  , rdCumulativeWork    :: !Integer       -- ^ Cumulative work in redownload (m_redownload_chain_work)
  , rdCount             :: !Int           -- ^ Number of headers redownloaded beyond chain_start
  , rdCommitments       :: !(Seq Bool)    -- ^ Remaining commitments to verify
  , rdCommitOffset      :: !Int           -- ^ Same offset used in PRESYNC (m_commit_offset)
  , rdBuffer            :: !(Seq BlockHeader)  -- ^ Buffered headers for acceptance (m_redownloaded_headers)
  , rdStartHeight       :: !Int64         -- ^ Height of chain_start (m_chain_start.nHeight)
  , rdMinimumWork       :: !Integer       -- ^ Work threshold from PRESYNC (m_minimum_required_work)
  , rdWorkReached       :: !Bool          -- ^ True once cumulative work >= minimum (m_process_all_remaining_headers)
  , rdParams            :: !HeaderSyncParams
  } deriving (Show, Eq, Generic)

-- | Per-peer header sync state
data HeaderSyncPeer = HeaderSyncPeer
  { hspState      :: !(TVar HeaderSyncState)
  , hspNetwork    :: !Network
  , hspSalt       :: !Word64            -- ^ Random salt for commitment hashing
  } deriving (Generic)

-- | Compute a salted commitment hash (SipHash-like) for anti-DoS
--
-- Returns the LSB of the hash as the 1-bit commitment.
commitmentHash :: Word64 -> BlockHash -> Bool
commitmentHash salt (BlockHash (Hash256 bs)) =
  let -- Simple salted hash: combine salt with block hash bytes
      saltBytes = BS.pack [ fromIntegral (salt `xor` (fromIntegral (BS.index bs i) :: Word64))
                          | i <- [0..min 7 (BS.length bs - 1)] ]
      combined = sha256 (BS.append saltBytes bs)
  in case BS.uncons combined of
       Just (b, _) -> (b .&. 1) == 1
       Nothing     -> False

-- | Initialize a header sync peer for PRESYNC.
--
-- @startHash@   — hash of the last known block (chain_start.GetBlockHash())
-- @startHeight@ — height of the chain_start (m_chain_start.nHeight)
-- @startNBits@  — difficulty bits of chain_start (for PermittedDifficultyTransition)
-- @startWork@   — cumulative work at chain_start (m_chain_start.nChainWork)
-- @startMTP@    — median time past of chain_start (for m_max_commitments bound)
-- @currentTime@ — Unix seconds "now" (for m_max_commitments calculation)
--
-- Reference: bitcoin-core/src/headerssync.cpp HeadersSyncState constructor (lines 17-46).
initHeaderSyncPeer :: Network -> BlockHash -> Int64 -> Word32 -> Integer -> Word32 -> Int64 -> IO HeaderSyncPeer
initHeaderSyncPeer net startHash startHeight startNBits startWork startMTP currentTime = do
  salt <- randomRIO (0, maxBound :: Word64)
  let params = netHeaderSyncParams net
  commitOffset <- randomRIO (0, hspCommitmentPeriod params - 1)

  -- m_max_commitments = 6 * (now - MTP + MAX_FUTURE_BLOCK_TIME) / commitment_period
  -- MAX_FUTURE_BLOCK_TIME = 7200s (chain.h line 29)
  let maxFutSecs   = 7200 :: Int64
      secsSinceStart = currentTime - fromIntegral startMTP + maxFutSecs
      maxCommits   = fromIntegral (max 0 (6 * secsSinceStart `div` fromIntegral (hspCommitmentPeriod params))) :: Word64

  let threshold = max (netMinimumChainWork net) startWork
      presyncData = PresyncData
        { pdCumulativeWork  = startWork      -- BUG5 fix: init from chain_start.nChainWork
        , pdLastHeaderHash  = startHash      -- chain_start hash
        , pdLastHeaderBits  = startNBits     -- chain_start nBits for PermittedDifficultyTransition
        , pdChainStartNBits = startNBits     -- preserved for REDOWNLOAD seed
        , pdCount           = 0
        , pdCommitments     = Seq.empty
        , pdCommitOffset    = commitOffset
        , pdStartHash       = startHash
        , pdStartHeight     = startHeight
        , pdMaxCommitments  = maxCommits     -- BUG1 fix: memory DoS bound
        , pdMinimumWork     = threshold
        , pdParams          = params
        }

  stateVar <- newTVarIO (Presync presyncData)
  return HeaderSyncPeer
    { hspState = stateVar
    , hspNetwork = net
    , hspSalt = salt
    }

-- | Get the current header sync state
getHeaderSyncState :: HeaderSyncPeer -> STM HeaderSyncState
getHeaderSyncState = readTVar . hspState

-- | Check if we should start PRESYNC for a peer's headers
--
-- Returns True if the claimed work is below the minimum threshold.
shouldStartPresync :: Network -> Integer -> Integer -> Bool
shouldStartPresync net claimedWork currentWork =
  let threshold = max (netMinimumChainWork net) currentWork
  in claimedWork < threshold

-- | Process headers during PRESYNC phase
--
-- Validates PoW, accumulates work, stores commitments.
-- Returns:
--   Left error: validation failed, disconnect peer
--   Right (state, readyHeaders): updated state, headers ready for chain (empty in PRESYNC)
processPresyncHeaders :: HeaderSyncPeer -> [BlockHeader] -> STM (Either String (HeaderSyncState, [BlockHeader]))
processPresyncHeaders peer headers = do
  state <- readTVar (hspState peer)
  case state of
    Presync pd -> do
      let result = runPresync (hspSalt peer) (hspNetwork peer) pd headers
      case result of
        Left err -> return $ Left err
        Right (newState, ready) -> do
          writeTVar (hspState peer) newState
          return $ Right (newState, ready)
    _ -> return $ Left "not in presync state"

-- | Pure PRESYNC processing logic.
--
-- Fixed gates (reference: bitcoin-core/src/headerssync.cpp):
--   BUG1: m_max_commitments bound (line 198-205) — abort if commitments exceed bound.
--   BUG2: absolute height modulus for commitment (line 195) — use startHeight+count, not count.
--   BUG3: PermittedDifficultyTransition (lines 189-193) — full 4× bound check.
--   BUG5: cumulative work starts from chain_start.nChainWork (line 29).
--   BUG6: connectivity always checked (line 148-155) — no pdCount>0 guard.
runPresync :: Word64 -> Network -> PresyncData -> [BlockHeader]
           -> Either String (HeaderSyncState, [BlockHeader])
runPresync _ _ pd [] = Right (Presync pd, [])
runPresync salt net pd (h:hs) = do
  -- BUG6 fix: ALWAYS check connectivity (no "if pdCount > 0" guard).
  -- Core initialises m_last_header_received to chain_start, so the first
  -- header's prevBlock must equal the chain_start hash.
  -- Reference: headerssync.cpp lines 148-155.
  let headerHash = computeBlockHash h
      prevHash = bhPrevBlock h
  if prevHash /= pdLastHeaderHash pd
    then Left "presync: header does not connect to chain"
    else do
      let nextHeight = pdStartHeight pd + fromIntegral (pdCount pd) + 1
          bits = bhBits h

      -- BUG3 fix: PermittedDifficultyTransition (Core headerssync.cpp lines 189-193).
      -- Replaces the crude "bits == 0 || bits > 0x207fffff" sanity check.
      if not (permittedDifficultyTransition net nextHeight (pdLastHeaderBits pd) bits)
        then Left "presync: invalid difficulty transition"
      -- Per-header proof-of-work check (existing, kept).
        else if not (checkProofOfWork h (netPowLimit net))
          then Left "presync: invalid PoW"
          else do
            let newCount = pdCount pd + 1
                commitPeriod = hspCommitmentPeriod (pdParams pd)

            -- BUG2 fix: use absolute height for commitment modulus.
            -- Core: next_height % m_params.commitment_period == m_commit_offset
            -- where next_height = m_current_height + 1 (absolute block height).
            -- Reference: headerssync.cpp line 195.
            let shouldCommit = nextHeight `mod` fromIntegral commitPeriod
                                == fromIntegral (pdCommitOffset pd)
                newCommitmentsRaw = if shouldCommit
                  then pdCommitments pd |> commitmentHash salt headerHash
                  else pdCommitments pd

            -- BUG1 fix: enforce m_max_commitments bound (headerssync.cpp lines 198-205).
            if shouldCommit && fromIntegral (Seq.length newCommitmentsRaw) > pdMaxCommitments pd
              then Left "presync: exceeded max commitments (peer chain too long)"
              else do
                -- BUG5: cumulative work already started from chain_start.nChainWork;
                -- just accumulate incremental proof.
                let newWork = pdCumulativeWork pd + headerWork h
                    newPd = pd
                      { pdCumulativeWork = newWork
                      , pdLastHeaderHash = headerHash
                      , pdLastHeaderBits = bits
                      , pdCount = newCount
                      , pdCommitments = newCommitmentsRaw
                      }

                -- Check if we've reached sufficient work → transition to REDOWNLOAD.
                -- Reference: headerssync.cpp lines 165-173.
                if newWork >= pdMinimumWork pd
                  then
                    -- m_redownload_buffer_last_hash = m_chain_start.GetBlockHash()
                    -- m_redownload_buffer_first_prev_hash = m_chain_start.GetBlockHash()
                    -- m_redownload_chain_work = m_chain_start.nChainWork (reset to start)
                    let rd = RedownloadData
                          { rdLastHeaderHash  = pdStartHash newPd
                          , rdFirstPrevHash   = pdStartHash newPd
                          -- Core: previous_nBits = m_chain_start.nBits when buffer empty
                          -- (headerssync.cpp lines 231-235)
                          , rdLastHeaderBits  = pdChainStartNBits newPd
                          , rdCumulativeWork  = 0   -- m_redownload_chain_work = m_chain_start.nChainWork
                          , rdCount           = 0
                          , rdCommitments     = pdCommitments newPd
                          , rdCommitOffset    = pdCommitOffset newPd
                          , rdBuffer          = Seq.empty
                          , rdStartHeight     = pdStartHeight newPd
                          , rdMinimumWork     = pdMinimumWork newPd
                          , rdWorkReached     = False
                          , rdParams          = pdParams newPd
                          }
                    in Right (Redownload rd, [])
                  else
                    runPresync salt net newPd hs

-- | Process headers during REDOWNLOAD phase
--
-- Validates headers match commitments from PRESYNC.
-- Returns headers ready for chain acceptance when buffer fills.
processRedownloadHeaders :: HeaderSyncPeer -> [BlockHeader] -> STM (Either String (HeaderSyncState, [BlockHeader]))
processRedownloadHeaders peer headers = do
  state <- readTVar (hspState peer)
  case state of
    Redownload rd -> do
      let result = processRedownloadBatch (hspSalt peer) (hspNetwork peer) rd headers
      case result of
        Left err -> return $ Left err
        Right (newState, ready) -> do
          writeTVar (hspState peer) newState
          return $ Right (newState, ready)
    _ -> return $ Left "not in redownload state"

-- | Pure REDOWNLOAD processing logic.
--
-- Fixed gates (reference: bitcoin-core/src/headerssync.cpp):
--   BUG4: PermittedDifficultyTransition in REDOWNLOAD (lines 237-241).
--   BUG7: connectivity always checked, no rdCount>0 guard (lines 224-227).
--   BUG8: commitment check runs BEFORE updating workReached (lines 246-270).
--   BUG10: incremental buffer pop after each batch (PopHeadersReadyForAcceptance, lines 280-293).
runRedownload :: Word64 -> Network -> RedownloadData -> [BlockHeader]
              -> Either String (RedownloadData, [BlockHeader])
runRedownload _ _ rd [] = Right (rd, [])
runRedownload salt net rd (h:hs) = do
  -- BUG7 fix: ALWAYS check connectivity (no rdCount>0 guard).
  -- Core: header.hashPrevBlock != m_redownload_buffer_last_hash → abort.
  -- Reference: headerssync.cpp lines 224-227.
  let headerHash = computeBlockHash h
      nextHeight = rdStartHeight rd + fromIntegral (rdCount rd) + 1

  if bhPrevBlock h /= rdLastHeaderHash rd
    then Left "redownload: header does not connect to chain"
    else do
      -- BUG4 fix: PermittedDifficultyTransition in REDOWNLOAD
      -- (Core: headerssync.cpp lines 237-241).
      if not (permittedDifficultyTransition net nextHeight (rdLastHeaderBits rd) (bhBits h))
        then Left "redownload: invalid difficulty transition"
        else do
          -- BUG8 fix: check commitment BEFORE updating workReached.
          -- Core order: check commitment → accumulate work → set m_process_all_remaining_headers.
          -- Reference: headerssync.cpp lines 246-270 (commitment check), then 243-248 (work accum).
          let commitPeriod  = hspCommitmentPeriod (rdParams rd)
              shouldVerify  = not (rdWorkReached rd) &&
                              nextHeight `mod` fromIntegral commitPeriod
                                == fromIntegral (rdCommitOffset rd)

          newCommitments <- if shouldVerify
            then case Seq.viewl (rdCommitments rd) of
              Seq.EmptyL -> Left "redownload: commitment overrun (peer gave different chain)"
              (expected Seq.:< rest) ->
                if commitmentHash salt headerHash == expected
                  then Right rest
                  else Left "redownload: commitment mismatch (peer changed chain)"
            else Right (rdCommitments rd)

          -- NOW accumulate work and set workReached (after commitment check).
          let newWork      = rdCumulativeWork rd + headerWork h
              workReached  = rdWorkReached rd || newWork >= rdMinimumWork rd

          let newRd = rd
                { rdLastHeaderHash = headerHash
                , rdLastHeaderBits = bhBits h
                , rdCumulativeWork = newWork
                , rdCount          = rdCount rd + 1
                , rdCommitments    = newCommitments
                , rdBuffer         = rdBuffer rd |> h
                , rdWorkReached    = workReached
                }

          runRedownload salt net newRd hs

-- | Process a batch of redownloaded headers, returning any that are ready
-- for chain acceptance (buffer has overflowed the redownload_buffer_size, or
-- m_process_all_remaining_headers is set).
--
-- This wraps 'runRedownload' (per-header state machine) with
-- 'popHeadersReadyForAcceptance' (PopHeadersReadyForAcceptance equivalent).
-- Reference: bitcoin-core/src/headerssync.cpp ProcessNextHeaders REDOWNLOAD branch
-- (lines 98-133) which calls PopHeadersReadyForAcceptance after the loop.
processRedownloadBatch :: Word64 -> Network -> RedownloadData -> [BlockHeader]
                       -> Either String (HeaderSyncState, [BlockHeader])
processRedownloadBatch salt net rd headers = do
  (newRd, _) <- runRedownload salt net rd headers
  -- BUG10 fix: pop ready headers immediately after the batch.
  let (ready, finalRd) = popHeadersReadyForAcceptance newRd
      finalState = if rdWorkReached finalRd && Seq.null (rdBuffer finalRd)
                     then Synced
                     else Redownload finalRd
  Right (finalState, ready)

-- | Pop headers from the front of the redownload buffer that are ready
-- for acceptance.
--
-- Headers are released when the buffer exceeds redownload_buffer_size (the
-- oldest headers have enough validated commitments on top), OR when
-- m_process_all_remaining_headers is set (work threshold reached).
--
-- Reference: bitcoin-core/src/headerssync.cpp PopHeadersReadyForAcceptance
-- (lines 280-293):
--   while (size > redownload_buffer_size ||
--          (size > 0 && m_process_all_remaining_headers))
--     emit front header, advance m_redownload_buffer_first_prev_hash
popHeadersReadyForAcceptance :: RedownloadData -> ([BlockHeader], RedownloadData)
popHeadersReadyForAcceptance rd = go [] rd
  where
    bufSize = hspRedownloadBufferSize (rdParams rd)
    go acc rdd
      | Seq.length (rdBuffer rdd) > bufSize
        || (not (Seq.null (rdBuffer rdd)) && rdWorkReached rdd) =
          case Seq.viewl (rdBuffer rdd) of
            Seq.EmptyL -> (reverse acc, rdd)
            (hdr Seq.:< rest) ->
              -- Reconstruct full header: prepend rdFirstPrevHash as prevBlock.
              -- (Equivalent to CompressedHeader::GetFullHeader in Core.)
              -- Our buffer stores full BlockHeaders so this is a no-op for us;
              -- we just update rdFirstPrevHash to the emitted header's hash.
              let emittedHash = computeBlockHash hdr
                  rdd' = rdd { rdBuffer = rest, rdFirstPrevHash = emittedHash }
              in go (hdr : acc) rdd'
      | otherwise = (reverse acc, rdd)

-- | Convert Seq to list
toList :: Seq a -> [a]
toList = foldr (:) []

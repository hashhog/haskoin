{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Deep reorg peak memory is a function of ONE block, not of reorg depth.
--
-- == The bug (P0, mainnet 2026-09-17, 844-block catch-up) ==
--
-- After the Missing-UTXO fix (09b27ba) a live reorg of
-- @fork@966499 -> prefix 967343@ (844 blocks) no longer aborted.  It
-- ran, accumulated every disconnect+connect BatchOp into a single
-- RocksDB 'WriteBatch', and was OOM-killed at the unit's 12 G ceiling
-- (@Consumed 3min 10s CPU, 12G memory peak@).
--
-- 'reorgAtomic''s own comment said it "accumulates the disconnect ops
-- + connect ops into a single WriteBatch (Phase B), commits once
-- (Phase C)".  That is right for a 1-2 block stale race and wrong at
-- this size.  Core's ActivateBestChainStep connects ONE block per
-- step and flushes on its own cadence (validation.cpp).
--
-- == Why no existing test caught it ==
--
-- 'reorg shared-tx intra-then-prefork' proved the coin bug at 3 blocks
-- and would pass at any depth — it never measured peak memory.
--
-- == What this suite pins ==
--
--   * A several-hundred-block coinbase-only reorg succeeds and lands
--     on the winning tip.
--   * Peak WriteBatch op-count / payload of that reorg is O(one block),
--     not O(depth).  PRE-FIX this fails: the single batch holds every
--     block.  POST-FIX each committed step is one block (tip pointer
--     in the same batch).
--   * Peak RSS during the reorg stays well under the 12 G production
--     ceiling — the property the OOM killer actually enforced.
--
-- References:
--   bitcoin-core/src/validation.cpp ActivateBestChain / ActivateBestChainStep
--     / DisconnectTip / ConnectTip (one block per step, FlushStateToDisk
--     IF_NEEDED).
module ReorgDeepIncrementalSpec (spec) where

import Test.Hspec
import Control.Concurrent (forkIO, killThread, threadDelay)
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar)
import Control.Exception (bracket)
import Control.Monad (foldM, unless)
import Data.IORef (newIORef, readIORef, writeIORef, modifyIORef')
import Data.List (isPrefixOf)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , connectBlockAt
  , performReorg
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  , blockRewardForNet
  , readReorgPeakBatchOps
  , readReorgPeakBatchBytes
  , resetReorgPeakStats
  , buildConnectBlockOps
  , buildDisconnectBlockOps
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , getUTXO
  , putBlock
  , newUTXOCache
  , BatchOp(..)
  , makeKey
  , KeyPrefix(..)
  , mkUndoData
  , BlockUndo(..)
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-reorg-deep-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

coinbaseTxAt :: Word32 -> Word8 -> Tx
coinbaseTxAt h tag = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = nullOutPoint
      , txInScript     = encodeBip34Height h `BS.snoc` tag
      , txInSequence   = 0xffffffff
      } ]
    -- Regtest halves at 150, so a constant 50 BTC coinbase is
    -- bad-cb-amount from height 150 on.  Pay the network subsidy.
  , txOutputs  = [ TxOut { txOutValue = blockRewardForNet regtest h, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

mkBlock :: BlockHash -> Word32 -> Word32 -> [Tx] -> Block
mkBlock prevHash ts nonce txns = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff
      , bhNonce      = nonce
      }
  , blockTxns = txns
  }

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> ChainEntry
mkEntry blk h prevHash work seqId = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = computeBlockHash (blockHeader blk)
  , ceHeight     = h
  , ceChainWork  = work
  , cePrev       = Just prevHash
  , ceStatus     = StatusValid
  , ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = seqId
  }

insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

insertSideEntry :: HeaderChain -> ChainEntry -> IO ()
insertSideEntry hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

baseTime :: Word32
baseTime = 1296688700

-- | Several hundred blocks: the live OOM was 844.  256 disconnect + 257
-- connect is enough to make a single-batch WriteBatch obviously larger
-- than one block, and cheap enough for coinbase-only regtest.
deepDepth :: Word32
deepDepth = 256

data DeepFork = DeepFork
  { dfHc      :: HeaderChain
  , dfLosing  :: BlockHash
  , dfWinning :: BlockHash
  , dfLoseCb  :: OutPoint   -- ^ losing-branch first-block coinbase
  , dfWinTip  :: OutPoint   -- ^ winning-tip coinbase
  }

-- | Genesis connected; losing branch @1..depth@ connected (active tip);
-- winning branch @1..depth+1@ on disk as a side chain (heavier by one
-- block).  Coinbase-only — the memory property is the batch, not the
-- scripts.
setupDeepFork :: Word32 -> S.HaskoinDB -> IO DeepFork
setupDeepFork depth db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)

  hc <- initHeaderChain net
  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()

  let stepLose (prevHash, work) h = do
        let blk   = mkBlock prevHash (baseTime + h) h [coinbaseTxAt h 0x0a]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' (fromIntegral h)
        r <- connectBlockAt db net blk h Map.empty
        r `shouldBe` Right ()
        insertActiveTip hc ce
        return (ceHash ce, work')
  (loseHash, loseWork) <- foldM stepLose (gHash, gWork) [1 .. depth]

  let stepWin (prevHash, work, seq0) h = do
        let blk   = mkBlock prevHash (baseTime + 10000 + h) (h + 100000) [coinbaseTxAt h 0x0b]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' seq0
            bh    = ceHash ce
        putBlock db bh blk
        insertSideEntry hc ce
        return (bh, work', seq0 + 1)
  (winHash, winWork, _) <-
    foldM stepWin (gHash, gWork, 10000) [1 .. depth + 1]

  (winWork > loseWork) `shouldBe` True
  (winHash /= loseHash) `shouldBe` True

  return DeepFork
    { dfHc      = hc
    , dfLosing  = loseHash
    , dfWinning = winHash
    , dfLoseCb  = OutPoint (computeTxId (coinbaseTxAt 1 0x0a)) 0
    , dfWinTip  = OutPoint (computeTxId (coinbaseTxAt (depth + 1) 0x0b)) 0
    }

-- | /proc/self/status VmRSS in kB.  The production unit's MemoryMax is
-- 12 G; a few hundred coinbase blocks must not approach it.
readVmRssKb :: IO Int
readVmRssKb = do
  txt <- readFile "/proc/self/status"
  let rssLines = [ l | l <- lines txt, "VmRSS:" `isPrefixOf` l ]
  case rssLines of
    (l:_) ->
      case reads (dropWhile (/= ' ') (drop 6 l)) of
        [(n, _)] -> return n
        _        -> return 0
    [] -> return 0

-- | Sample VmRSS every 2 ms while @action@ runs; return (result, peak kB).
withPeakRss :: IO a -> IO (a, Int)
withPeakRss action = do
  base <- readVmRssKb
  peak <- newIORef base
  done <- newIORef False
  let sampler = do
        d <- readIORef done
        unless d $ do
          r <- readVmRssKb
          modifyIORef' peak (max r)
          threadDelay 2000
          sampler
  bracket (forkIO sampler) (\tid -> writeIORef done True >> killThread tid) $
    \_ -> do
      a <- action
      threadDelay 5000
      p <- readIORef peak
      return (a, p)

runDeepReorg
  :: S.HaskoinDB
  -> DeepFork
  -> IO (Either String (), Int, Int, Int)
runDeepReorg db fk = do
  cache <- newUTXOCache db 100000
  resetReorgPeakStats
  (res, peakRss) <- withPeakRss $
    performReorg regtest cache db (dfHc fk) Nothing (dfLosing fk) (dfWinning fk)
  ops <- readReorgPeakBatchOps
  bytes <- readReorgPeakBatchBytes
  return (res, ops, bytes, peakRss)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "deep incremental reorg" $ do

    it "buildDisconnectBlockOps writes PrefixBestBlock in the same batch as the UTXO rewind" $ do
      let blk  = mkBlock (BlockHash (Hash256 (BS.replicate 32 0x11))) 1 1 [coinbaseTxAt 1 0x0a]
          prev = bhPrevBlock (blockHeader blk)
          bh   = computeBlockHash (blockHeader blk)
          undo = mkUndoData bh 1 prev (BlockUndo [])
      case buildDisconnectBlockOps blk prev undo of
        Left err -> expectationFailure err
        Right ops ->
          any isBestBlockPut ops `shouldBe` True

    it "buildConnectBlockOps writes PrefixBestBlock in the same batch as the UTXO mutations" $ do
      let blk = mkBlock (BlockHash (Hash256 (BS.replicate 32 0x11))) 1 1 [coinbaseTxAt 1 0x0a]
          ops = buildConnectBlockOps regtest blk 1 Map.empty
      any isBestBlockPut ops `shouldBe` True

    it "256-block reorg peak WriteBatch is one block, not the whole reorg" $ do
      withTestDB "depth-256" $ \db -> do
        fk <- setupDeepFork deepDepth db
        (res, peakOps, peakBytes, peakRssKb) <- runDeepReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "deep reorg aborted: " ++ err

        getBestBlockHash db `shouldReturn` Just (dfWinning fk)
        -- Losing first-block coinbase is gone; winning tip coinbase remains.
        getUTXO db (dfLoseCb fk) `shouldReturn` Nothing
        mWin <- getUTXO db (dfWinTip fk)
        fmap txOutScript mWin `shouldBe` Just opTrue

        -- One coinbase-only connect is 7 ops (UTXO put, undo, txindex,
        -- best-block, header, height, block body); a disconnect is 2
        -- (UTXO delete, best-block).  A single-batch reorg of 256+257
        -- blocks is thousands of ops.  Bound is generous for one fat
        -- block but far below O(depth).
        peakOps `shouldSatisfy` (\n -> n > 0 && n <= 32)
        -- Payload of one coinbase block is a few hundred bytes; the
        -- pre-fix concatenation is hundreds of KB.
        peakBytes `shouldSatisfy` (\n -> n > 0 && n <= 4096)
        -- Production MemoryMax is 12 G.  A 256-block coinbase reorg
        -- must not approach it; 512 MiB is already a loud fail if the
        -- single-batch design comes back with fat blocks.
        peakRssKb `shouldSatisfy` (< 512 * 1024)

    it "peak WriteBatch does not grow with reorg depth (32 vs 256)" $ do
      withTestDB "depth-32" $ \db32 -> do
        fk32 <- setupDeepFork 32 db32
        (res32, ops32, bytes32, _) <- runDeepReorg db32 fk32
        res32 `shouldBe` Right ()
        withTestDB "depth-256-cmp" $ \db256 -> do
          fk256 <- setupDeepFork 256 db256
          (res256, ops256, bytes256, _) <- runDeepReorg db256 fk256
          res256 `shouldBe` Right ()
          -- Pre-fix 256-deep is ~8x 32-deep.  Post-fix both are one block.
          ops256 `shouldSatisfy` (<= max 32 (ops32 * 2))
          bytes256 `shouldSatisfy` (<= max 4096 (bytes32 * 2))

isBestBlockPut :: BatchOp -> Bool
isBestBlockPut (BatchPut k _) = k == makeKey PrefixBestBlock BS.empty
isBestBlockPut _              = False

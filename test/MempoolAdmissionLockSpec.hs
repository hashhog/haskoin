{-# LANGUAGE NumericUnderscores #-}

-- | Mempool admission is serialised, as Core's is.
--
-- Bitcoin Core runs AcceptToMemoryPool / ProcessNewPackage with cs_main AND
-- pool.cs held from the conflict check (PreChecks, validation.cpp) to the
-- insert (Finalize), and every removal (removeForBlock, removeForReorg,
-- TrimToSize, Expire) runs under the same locks.  Two transactions that spend
-- the same outpoint can therefore never both be admitted, however they
-- arrive.
--
-- haskoin's conflict check ('getConflicts') and its insert were two separate
-- STM transactions with no lock around the admission, and 'addTransaction'
-- is called concurrently from every peer's receive thread and from RPC
-- handlers.  Two conflicting spends arriving at the same time on two peers
-- could both pass the conflict check, both be inserted, and leave a double
-- spend in the pool (and in getblocktemplate).
module MempoolAdmissionLockSpec (spec) where

import Test.Hspec
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Monad (forM, forM_)
import Data.Either (isRight)
import Data.Word (Word32, Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import System.Timeout (timeout)

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.Mempool
import Haskoin.Consensus (regtest)
import Haskoin.ChainLock (withChainLock)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB, addUTXO,
                        UTXOEntry(..), UTXOCache(..))

-- | P2WSH(OP_TRUE): standard output, spendable with witness [OP_TRUE].
opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

-- | Spend one outpoint to one output.  @lt@ only varies the txid: every
-- variant pays the same fee, so none of them can replace another (BIP-125
-- rule 3 / Core PaysForRBF needs strictly more fee), and a serialised pool
-- admits exactly one.
spendWith :: OutPoint -> Word64 -> Word32 -> Tx
spendWith op val lt = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn op BS.empty 0xfffffffd ]
  , txOutputs  = [ TxOut val opTrueSpk ]
  , txWitness  = [ [BS.singleton 0x51] ]
  , txLockTime = lt
  }

fundingOp :: Int -> OutPoint
fundingOp n = OutPoint (TxId (Hash256 (BS.replicate 30 0x6b
                                        <> BS.pack [fromIntegral (n `div` 256), fromIntegral n]))) 0

rounds, racers :: Int
rounds = 60
racers = 12

withPool :: Int -> (UTXOCache -> Mempool -> IO a) -> IO a
withPool coins action =
  withSystemTempDirectory "haskoin-admission-lock" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 100_000
      -- confirmed, mature, non-coinbase coins at height 1; tip 200
      atomically $ mapM_ (\n -> addUTXO cache (fundingOp n)
                                   (UTXOEntry (TxOut 1_000_000 opTrueSpk) 1 False False))
                         [0 .. coins - 1]
      mp <- newMempool regtest cache defaultMempoolConfig 200 0 noopCoinMtp
      action cache mp

-- | Fire @racers@ conflicting spends of one coin from separate threads,
-- released together, and return each thread's result.
race :: Mempool -> OutPoint -> IO [(Tx, Either MempoolError TxId)]
race mp op = do
  gate <- newTVarIO False
  let txs = [ spendWith op 990_000 (fromIntegral i) | i <- [1 .. racers] ]
  boxes <- forM txs $ \tx -> do
    box <- newEmptyMVar
    _ <- forkIO $ do
      atomically $ readTVar gate >>= check
      r <- addTransaction mp tx
      putMVar box (tx, r)
    return box
  atomically $ writeTVar gate True
  mapM takeMVar boxes

-- | Pool entries whose inputs include @op@.
spendersOf :: Mempool -> OutPoint -> IO [TxId]
spendersOf mp op = do
  es <- readTVarIO (mpEntries mp)
  return [ t | (t, e) <- Map.toList es
             , op `elem` map txInPrevOutput (txInputs (meTransaction e)) ]

spec :: Spec
spec = describe "mempool admission is serialised (Core: ATMP under cs_main + pool.cs)" $ do

  it "concurrent conflicting spends of one coin: exactly one is admitted, every round" $
    withPool rounds $ \_ mp -> do
      forM_ [0 .. rounds - 1] $ \r -> do
        let op = fundingOp r
        results <- race mp op
        let admitted = [ computeTxId tx | (tx, res) <- results, isRight res ]
        spenders <- spendersOf mp op
        byOp <- Map.lookup op <$> readTVarIO (mpByOutpoint mp)
        (r, length admitted, length spenders) `shouldBe` (r, 1, 1)
        byOp `shouldBe` Just (head spenders)
      -- whole-pool bookkeeping stayed consistent: one entry per coin, the
      -- outpoint index names exactly the pool's spends, and mpSize is the
      -- sum of the entries' sizes.
      es <- readTVarIO (mpEntries mp)
      Map.size es `shouldBe` rounds
      byOutpoint <- readTVarIO (mpByOutpoint mp)
      Map.size byOutpoint `shouldBe` rounds
      forM_ (Map.toList byOutpoint) $ \(op, t) ->
        fmap (map txInPrevOutput . txInputs . meTransaction) (Map.lookup t es)
          `shouldBe` Just [op]
      sz <- readTVarIO (mpSize mp)
      sz `shouldBe` sum (map meSize (Map.elems es))

  it "an admission waits while another thread holds the chain lock (a block connect / reorg)" $
    withPool 1 $ \cache mp -> do
      let tx = spendWith (fundingOp 0) 990_000 0
      holding <- newEmptyMVar
      release <- newEmptyMVar
      seenInside <- newEmptyMVar
      _ <- forkIO $ withChainLock (ucChainLock cache) $ do
        putMVar holding ()
        takeMVar release
        -- still holding the lock: the concurrent admission must not have
        -- touched the pool yet
        inside <- Map.member (computeTxId tx) <$> readTVarIO (mpEntries mp)
        putMVar seenInside inside
      takeMVar holding
      done <- newEmptyMVar
      _ <- forkIO $ addTransaction mp tx >>= putMVar done
      threadDelay 300_000
      putMVar release ()
      takeMVar seenInside `shouldReturn` False
      r <- timeout 10_000_000 (takeMVar done)
      r `shouldBe` Just (Right (computeTxId tx))

  it "removals wait for the lock too (blockConnected / removeTransaction under cs_main)" $
    withPool 1 $ \cache mp -> do
      let tx = spendWith (fundingOp 0) 990_000 0
      addTransaction mp tx `shouldReturn` Right (computeTxId tx)
      holding <- newEmptyMVar
      release <- newEmptyMVar
      seenInside <- newEmptyMVar
      _ <- forkIO $ withChainLock (ucChainLock cache) $ do
        putMVar holding ()
        takeMVar release
        inside <- Map.member (computeTxId tx) <$> readTVarIO (mpEntries mp)
        putMVar seenInside inside
      takeMVar holding
      done <- newEmptyMVar
      _ <- forkIO $ removeTransaction mp (computeTxId tx) >>= putMVar done
      threadDelay 300_000
      putMVar release ()
      takeMVar seenInside `shouldReturn` True
      timeout 10_000_000 (takeMVar done) `shouldReturn` Just ()
      Map.member (computeTxId tx) <$> readTVarIO (mpEntries mp) `shouldReturn` False

  it "control: a caller that already holds the chain lock can still admit and remove (re-entrant)" $
    withPool 1 $ \cache mp -> do
      let tx = spendWith (fundingOp 0) 990_000 0
      r <- timeout 10_000_000 $ withChainLock (ucChainLock cache) $ do
        a <- addTransaction mp tx
        removeTransaction mp (computeTxId tx)
        return a
      r `shouldBe` Just (Right (computeTxId tx))

  it "control: sequential conflicting spends: the first is admitted, an equal-fee rival is refused" $
    withPool 1 $ \_ mp -> do
      let a = spendWith (fundingOp 0) 990_000 1
          b = spendWith (fundingOp 0) 990_000 2
      addTransaction mp a `shouldReturn` Right (computeTxId a)
      rb <- addTransaction mp b
      isRight rb `shouldBe` False
      spendersOf mp (fundingOp 0) `shouldReturn` [computeTxId a]

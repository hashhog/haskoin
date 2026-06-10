{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | prioritisetransaction + fee-estimator untrack behavioural tests
-- (bundle 2026-06-09).
--
-- PART A — prioritisetransaction (Core txmempool.cpp:630-655 +
-- rpc/mining.cpp:502-545 parity, single-entry rank semantics — the fleet
-- bar set by rustoshi FIX-72):
--
--   * a positive fee delta on a low-fee tx MOVES IT AHEAD in mining
--     selection ('selectTransactions' — the exact order
--     'createBlockTemplate' / getblocktemplate emits);
--   * a negative delta makes a tx the size-limit EVICTION victim
--     ('trimToSize' evicts the lowest (meFeeRate, txid) key);
--   * deltas STACK and an accumulated delta of exactly 0 ERASES the
--     mapDeltas entry;
--   * a delta set BEFORE the tx arrives is folded in at admission
--     ('buildMempoolEntry'), Core ChangeSet::StageAddition → ApplyDelta
--     (txmempool.cpp:1014-1023);
--   * the delta SURVIVES eviction (in_mempool=false) but is CLEARED by
--     block confirmation (removeForBlock → ClearPrioritisation,
--     txmempool.cpp:405-421);
--   * 'meFee' (the BASE fee — what the coinbase actually collects in a
--     template) never changes.
--
-- PART B — fee-estimator untrack on NON-mining removal (Core
-- CBlockPolicyEstimator::removeTx via TransactionRemovedFromMempool,
-- which fires for every removal reason except BLOCK):
--
--   * 'untrackTransaction' exactly undoes 'trackTransaction'
--     (feePending entry + fbInMempool counter), is idempotent, and
--     ignores unknown txids;
--   * with the subscriber installed ('setOnRemoveTx'), a non-block
--     'removeTransaction' untracks the tx (churn no longer leaks
--     feePending), while a block-confirmed removal
--     ('removeTransactionForBlock') does NOT untrack.
module PrioritiseTransactionSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Control.Monad (forM_)
import Data.IORef
import Data.Word (Word32, Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Mempool
import Haskoin.FeeEstimator
import Haskoin.Consensus (regtest)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB)

--------------------------------------------------------------------------------
-- Fixtures (same idiom as W106MempoolSpec)
--------------------------------------------------------------------------------

-- | Fresh mempool over a temp RocksDB, with a configurable size cap.
withMempoolCap :: Int -> (Mempool -> IO a) -> IO a
withMempoolCap cap action =
  withSystemTempDirectory "haskoin-priotx-test" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      mp <- newMempool regtest cache
              (defaultMempoolConfig { mpcMaxSize = cap }) 100 0 noopCoinMtp
      action mp

withFreshMempool :: (Mempool -> IO a) -> IO a
withFreshMempool = withMempoolCap (mpcMaxSize defaultMempoolConfig)

dummyTxOut :: Word64 -> TxOut
dummyTxOut v = TxOut { txOutValue = v, txOutScript = "\x51" }

makeTx :: [OutPoint] -> [Word64] -> Tx
makeTx prevouts outValues = Tx
  { txVersion  = 2
  , txInputs   = map (\op -> TxIn { txInPrevOutput = op
                                  , txInScript    = ""
                                  , txInSequence  = 0xffffffff }) prevouts
  , txOutputs  = map dummyTxOut outValues
  , txWitness  = replicate (length prevouts) []
  , txLockTime = 0
  }

coinOutPoint :: Word32 -> OutPoint
coinOutPoint n = OutPoint
  (TxId (Hash256 (BS.replicate 31 0x00 <> BS.singleton (fromIntegral n)))) 0

mkTxId :: Word32 -> TxId
mkTxId n = TxId (Hash256 (BS.replicate 31 0xab <> BS.singleton (fromIntegral n)))

-- | Build a self-consistent single-tx entry (base-fee rank fields).
mkEntry :: Tx -> Word64 -> Int -> MempoolEntry
mkEntry tx fee sz = MempoolEntry
  { meTransaction     = tx
  , meTxId            = computeTxId tx
  , meWtxid           = computeWtxid tx
  , meFee             = fee
  , meFeeRate         = calculateFeeRate fee sz
  , meSize            = sz
  , meTime            = 0
  , meHeight          = 0
  , meAncestorCount   = 1
  , meAncestorSize    = sz
  , meAncestorFees    = fee
  , meAncestorSigOps  = 0
  , meDescendantCount = 1
  , meDescendantSize  = sz
  , meDescendantFees  = fee
  , meRBFOptIn        = False
  }

-- | Insert an entry into every index 'continueAddTransaction' maintains.
insertEntry :: Mempool -> MempoolEntry -> IO ()
insertEntry mp e = atomically $ do
  modifyTVar' (mpEntries mp)    (Map.insert (meTxId e) e)
  modifyTVar' (mpByWtxid mp)    (Map.insert (meWtxid e) (meTxId e))
  forM_ (txInputs (meTransaction e)) $ \inp ->
    modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput inp) (meTxId e))
  modifyTVar' (mpByFeeRate mp)  (Map.insert (meFeeRate e, meTxId e) ())
  modifyTVar' (mpSize mp)       (+ meSize e)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "prioritisetransaction — mining-template effect (Core miner.cpp GetModifiedFee parity)" $ do
    it "a positive delta flips selectTransactions order (template inclusion order)" $
      withFreshMempool $ \mp -> do
        let txA = makeTx [coinOutPoint 1] [9_000]
            txB = makeTx [coinOutPoint 2] [9_000]
            entA = mkEntry txA 5_000 200   -- 25 sat/vB
            entB = mkEntry txB 1_000 200   --  5 sat/vB
        insertEntry mp entA
        insertEntry mp entB
        -- Baseline: higher-feerate A is selected first.
        pre <- selectTransactions mp 3_992_000
        map meTxId pre `shouldBe` [meTxId entA, meTxId entB]
        -- Prioritise B by +100k sats: its modified rank must move it ahead.
        prioritiseTransaction mp (meTxId entB) 100_000
        post <- selectTransactions mp 3_992_000
        map meTxId post `shouldBe` [meTxId entB, meTxId entA]
        -- The BASE fee (what a block template actually accounts for the
        -- coinbase, Core miner.cpp:262-270) is unchanged.
        mB <- getTransaction mp (meTxId entB)
        fmap meFee mB `shouldBe` Just 1_000
        -- and the modified fee is surfaced via getPrioritisedTransactions
        pri <- getPrioritisedTransactions mp
        pri `shouldBe` [(meTxId entB, 100_000, True, Just 101_000)]

    it "a negative delta makes the tx the trimToSize eviction victim" $
      -- Cap fits ONE 200-vB entry: inserting two puts the pool over the
      -- limit and trimToSize must evict exactly the lowest MODIFIED-feerate
      -- entry (Core TrimToSize, txmempool.cpp:861-897).
      withMempoolCap 300 $ \mp -> do
        let txA = makeTx [coinOutPoint 3] [9_000]
            txB = makeTx [coinOutPoint 4] [9_000]
            entA = mkEntry txA 5_000 200   -- high base feerate
            entB = mkEntry txB 1_000 200   -- low base feerate
        insertEntry mp entA
        insertEntry mp entB
        -- WITHOUT a delta, B (lowest feerate) would be evicted.  Push A
        -- below B with a negative delta; A must become the victim.
        prioritiseTransaction mp (meTxId entA) (-4_900)   -- mod fee 100
        trimToSize mp
        entries <- readTVarIO (mpEntries mp)
        Map.member (meTxId entA) entries `shouldBe` False
        Map.member (meTxId entB) entries `shouldBe` True
        -- Eviction does NOT clear the delta (Core: only BLOCK/CONFLICT
        -- removals call ClearPrioritisation).
        pri <- getPrioritisedTransactions mp
        pri `shouldBe` [(meTxId entA, -4_900, False, Nothing)]

    it "deltas stack and an accumulated total of 0 erases the entry" $
      withFreshMempool $ \mp -> do
        let txC  = makeTx [coinOutPoint 5] [9_000]
            entC = mkEntry txC 1_000 200
        insertEntry mp entC
        prioritiseTransaction mp (meTxId entC) 500
        prioritiseTransaction mp (meTxId entC) 500
        pri1 <- getPrioritisedTransactions mp
        pri1 `shouldBe` [(meTxId entC, 1_000, True, Just 2_000)]
        -- Back to exactly 0: mapDeltas entry erased (txmempool.cpp:644-646)
        -- and the entry's rank restored to the base feerate.
        prioritiseTransaction mp (meTxId entC) (-1_000)
        pri2 <- getPrioritisedTransactions mp
        pri2 `shouldBe` []
        mC <- getTransaction mp (meTxId entC)
        fmap meFeeRate mC `shouldBe` Just (calculateFeeRate 1_000 200)
        -- mpByFeeRate re-keyed back too (eviction index consistent)
        byRate <- readTVarIO (mpByFeeRate mp)
        Map.member (calculateFeeRate 1_000 200, meTxId entC) byRate
          `shouldBe` True

    it "a delta set BEFORE arrival is folded in at admission (buildMempoolEntry)" $
      withFreshMempool $ \mp -> do
        let txD   = makeTx [coinOutPoint 6] [9_000]
            txDId = computeTxId txD
        -- Not in the mempool yet: the delta is remembered…
        prioritiseTransaction mp txDId 7_777
        pri <- getPrioritisedTransactions mp
        pri `shouldBe` [(txDId, 7_777, False, Nothing)]
        -- …and applied when the entry is constructed at admission.
        ent <- buildMempoolEntry mp txD txDId 1_000 200 0 []
        meFee ent `shouldBe` 1_000
        meFeeRate ent `shouldBe`
          calculateFeeRate (applyFeeDelta 1_000 7_777) (meSize ent)
        meAncestorFees ent `shouldBe` applyFeeDelta 1_000 7_777

    it "block confirmation CLEARS the delta (removeForBlock → ClearPrioritisation)" $
      withFreshMempool $ \mp -> do
        let txE  = makeTx [coinOutPoint 7] [9_000]
            entE = mkEntry txE 1_000 200
            cb   = makeTx [OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff]
                          [5_000_000_000]
            hdr  = BlockHeader 2 (BlockHash (Hash256 (BS.replicate 32 0)))
                               (Hash256 (BS.replicate 32 0)) 1_700_000_000 0 0
        insertEntry mp entE
        prioritiseTransaction mp (meTxId entE) 12_345
        blockConnected mp (Block hdr [cb, txE])
        entries <- readTVarIO (mpEntries mp)
        Map.member (meTxId entE) entries `shouldBe` False
        pri <- getPrioritisedTransactions mp
        pri `shouldBe` []

  describe "fee-estimator untrack on non-mining removal (Core removeTx / TransactionRemovedFromMempool parity)" $ do
    it "untrackTransaction exactly undoes trackTransaction and is idempotent" $ do
      fe <- newFeeEstimator
      let t1 = mkTxId 1
          t2 = mkTxId 2
          -- NOTE: buckets span ~1..490 sat/vB (1.05^idx, 128 buckets) —
          -- pick rates in DISTINCT buckets so the per-bucket counter
          -- assertion is meaningful (1000 and 50000 both clamp to 127).
          bucket1 = feeRateToBucket 10
      trackTransaction fe t1 10 100
      trackTransaction fe t2 300 100
      pending0 <- readTVarIO (feePending fe)
      Map.size pending0 `shouldBe` 2
      b0 <- readTVarIO (feeBuckets fe)
      fmap fbInMempool (Map.lookup bucket1 b0) `shouldBe` Just 1
      -- untrack: pending entry + bucket counter both undone
      untrackTransaction fe t1
      pending1 <- readTVarIO (feePending fe)
      Map.keys pending1 `shouldBe` [t2]
      b1 <- readTVarIO (feeBuckets fe)
      fmap fbInMempool (Map.lookup bucket1 b1) `shouldBe` Just 0
      -- idempotent: a second untrack of the same txid is a no-op
      untrackTransaction fe t1
      b2 <- readTVarIO (feeBuckets fe)
      fmap fbInMempool (Map.lookup bucket1 b2) `shouldBe` Just 0
      -- unknown txid: no-op
      untrackTransaction fe (mkTxId 99)
      pending2 <- readTVarIO (feePending fe)
      Map.keys pending2 `shouldBe` [t2]

    it "churn through the mempool no longer leaks feePending (subscriber wired via setOnRemoveTx)" $
      withFreshMempool $ \mp -> do
        fe <- newFeeEstimator
        setOnRemoveTx mp (untrackTransaction fe)
        let txF  = makeTx [coinOutPoint 8] [9_000]
            entF = mkEntry txF 1_000 200
        insertEntry mp entF
        trackTransaction fe (meTxId entF) 5_000 100
        -- NON-BLOCK removal (RBF/expiry/eviction/conflict class) → the
        -- subscriber untracks.  Pre-fix, feePending kept this entry forever.
        removeTransaction mp (meTxId entF)
        pendingAfter <- readTVarIO (feePending fe)
        Map.size pendingAfter `shouldBe` 0

    it "block-confirmed removal does NOT untrack (BLOCK reason suppresses the signal)" $
      withFreshMempool $ \mp -> do
        fe <- newFeeEstimator
        setOnRemoveTx mp (untrackTransaction fe)
        let txG  = makeTx [coinOutPoint 9] [9_000]
            entG = mkEntry txG 1_000 200
        insertEntry mp entG
        trackTransaction fe (meTxId entG) 5_000 100
        removeTransactionForBlock mp (meTxId entG)
        pendingAfter <- readTVarIO (feePending fe)
        Map.keys pendingAfter `shouldBe` [meTxId entG]

    it "the removal notification fires once per real removal, never for absent txids" $
      withFreshMempool $ \mp -> do
        seen <- newIORef ([] :: [TxId])
        setOnRemoveTx mp (\txid -> modifyIORef' seen (txid :))
        let txH  = makeTx [coinOutPoint 10] [9_000]
            entH = mkEntry txH 1_000 200
        insertEntry mp entH
        -- absent txid → no notification
        removeTransaction mp (mkTxId 42)
        readIORef seen >>= (`shouldBe` [])
        -- real removal → exactly one notification
        removeTransaction mp (meTxId entH)
        readIORef seen >>= (`shouldBe` [meTxId entH])
        -- already gone → no further notification
        removeTransaction mp (meTxId entH)
        readIORef seen >>= (`shouldBe` [meTxId entH])

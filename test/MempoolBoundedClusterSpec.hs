{-# LANGUAGE NumericUnderscores #-}

-- | The cluster-limit gate reads the candidate's own cluster, not the pool.
--
-- Core keeps clusters in TxGraph and checks the limits of the clusters a new
-- transaction would merge (txgraph.cpp, @total_count > max_count ||
-- total_size > max_size@ at :2059); the cost is the size of those clusters.
--
-- haskoin's 'checkClusterLimit' rebuilt a union-find over EVERY pool entry
-- ('buildUnionFind') whenever the candidate had an in-pool parent, so each
-- CPFP-style admission cost O(N log N) in the pool size and filling the
-- pool cost O(N^2).  The live mainnet pool holds ~30,000 transactions.
-- The verdict only depends on the clusters of the candidate's in-pool
-- parents, which a search from those parents finds directly.
module MempoolBoundedClusterSpec (spec) where

import Test.Hspec
import Control.Exception (evaluate)
import Control.Monad (forM_)
import Data.Bits (shiftR, (.&.))
import Data.List (foldl')
import Data.Word (Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Lazy as ML
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import System.IO (hPutStrLn, stderr)
import Control.Concurrent.STM (atomically, writeTVar)
import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Mempool
import Haskoin.Consensus (regtest)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB)

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

-- | A pool transaction: spends @ins@, has @nOut@ outputs.  @salt@ keeps
-- txids distinct.
poolTx :: Word32 -> [OutPoint] -> Int -> Tx
poolTx salt ins nOut = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn op BS.empty 0xfffffffd | op <- ins' ]
  , txOutputs  = [ TxOut 1_000 BS.empty | _ <- [1 .. nOut] ]
  , txWitness  = []
  , txLockTime = salt
  }
  where
    -- a root spends a confirmed coin that no pool tx creates
    ins' | null ins  = [OutPoint (TxId (Hash256 (BS.replicate 32 0xee))) salt]
         | otherwise = ins

entryFor :: Tx -> Int -> MempoolEntry
entryFor tx w = MempoolEntry
  { meTransaction = tx, meTxId = computeTxId tx, meWtxid = Wtxid (getTxIdHash (computeTxId tx))
  , meFee = 1_000, meFeeRate = FeeRate 0, meSize = (w + 3) `div` 4, meAdjWeight = w
  , meTime = 0, meHeight = 0
  , meAncestorCount = 1, meAncestorSize = 0, meAncestorFees = 0, meAncestorSigOps = 0
  , meDescendantCount = 1, meDescendantSize = 0, meDescendantFees = 0
  , meRBFOptIn = True }

type Pool = (Map TxId MempoolEntry, Map OutPoint TxId)

-- | Index a list of (tx, weight) as the mempool does: entries + outpoint index.
mkPool :: [(Tx, Int)] -> Pool
mkPool txs =
  ( Map.fromList [ (computeTxId t, entryFor t w) | (t, w) <- txs ]
  , Map.fromList [ (txInPrevOutput i, computeTxId t) | (t, _) <- txs, i <- txInputs t ] )

-- | A chain of @n@ txs (each spends output 0 of the previous); returns the
-- txs and the tip's txid.
chain :: Word32 -> Int -> Int -> ([(Tx, Int)], TxId)
chain salt n w = go n Nothing []
  where
    go 0 (Just tip) acc = (reverse acc, tip)
    go 0 Nothing acc = (reverse acc, TxId (Hash256 (BS.replicate 32 0)))
    go k prev acc =
      let ins = maybe [] (\p -> [OutPoint p 0]) prev
          t = poolTx (salt * 1_000 + fromIntegral k) ins 2
      in go (k - 1) (Just (computeTxId t)) ((t, w) : acc)

candidateSpending :: [OutPoint] -> Tx
candidateSpending ops = (poolTx 0xc0ffee ops 1) { txLockTime = 0xc0ffee }

-- | The pre-fix gate, kept verbatim as the reference: a union-find over the
-- whole pool.
referenceClusterLimit :: Tx -> Map TxId MempoolEntry -> Map OutPoint TxId -> Int
                      -> Either ClusterLimitError ()
referenceClusterLimit tx entries byOutpoint txAdjWeight =
  let parentIds = [ p | inp <- txInputs tx, let p = outPointHash (txInPrevOutput inp)
                      , Map.member p entries ]
      uf = buildUnionFind entries byOutpoint
  in if null parentIds then Right () else
     let totalTxCount = sum (getDistinctClusterSizes parentIds uf) + 1
         roots = Set.fromList [ fst (ufFind p uf) | p <- parentIds ]
         totalWeight = Map.foldlWithKey'
                         (\acc t e -> if fst (ufFind t uf) `Set.member` roots
                                        then acc + meAdjWeight e else acc) 0 entries
                       + txAdjWeight
     in if totalTxCount > maxClusterSize
          then Left (ClusterLimitExceeded totalTxCount maxClusterSize)
        else if totalWeight > maxClusterSizeWeight
          then Left (ClusterSizeExceeded totalWeight maxClusterSizeWeight)
        else Right ()

-- | Deterministic LCG (no extra test dependency).
lcg :: Word64 -> Word64
lcg s = s * 6364136223846793005 + 1442695040888963407

-- | A random DAG pool: tx k spends 0-3 still-unspent outputs of earlier txs
-- (each outpoint spent at most once, as in a real pool), and a random
-- candidate spending 0-3 unspent pool outputs.  Weights are drawn so some
-- clusters cross the 404,000 WU size limit and long ones the 64-tx count.
randomCase :: Word64 -> ([(Tx, Int)], Tx, Int)
randomCase seed0 =
  let (n, s1) = (fromIntegral (lcg seed0 `shiftR` 33) `mod` 140 + 1, lcg seed0)
      step (txs, unspent, s) k =
        let s' = lcg s
            nIn = fromIntegral (s' `shiftR` 40) `mod` 4 :: Int
            (ins, unspent', s'') = pick nIn unspent s'
            w = 400 + fromIntegral ((s'' `shiftR` 20) .&. 0x3fff) * (if (s'' `shiftR` 7) .&. 7 == 0 then 6 else 1)
            t = poolTx (fromIntegral k) ins 2
            outs = [ OutPoint (computeTxId t) 0, OutPoint (computeTxId t) 1 ]
        in (txs ++ [(t, w)], unspent' ++ outs, lcg s'')
      (pool, unspentF, sF) = foldl' step ([], [], s1) [1 .. n :: Int]
      (cIns, _, sG) = pick (fromIntegral (sF `shiftR` 50) `mod` 4) unspentF sF
      cW = 400 + fromIntegral ((sG `shiftR` 30) .&. 0xffff)
  in (pool, candidateSpending cIns, cW)
  where
    pick :: Int -> [OutPoint] -> Word64 -> ([OutPoint], [OutPoint], Word64)
    pick 0 us s = ([], us, s)
    pick _ [] s = ([], [], s)
    pick k us s =
      let s' = lcg s
          i = fromIntegral (s' `shiftR` 33) `mod` length us
          (a, b) = splitAt i us
          (rest, us', s'') = pick (k - 1) (a ++ drop 1 b) s'
      in (head b : rest, us', s'')

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "checkClusterLimit searches the candidate's clusters, not the whole pool" $ do

  it "never reads a pool entry outside the clusters the candidate joins" $ do
    -- 3-tx cluster the candidate joins + 5,000 unrelated entries whose
    -- values are bottom.  Any whole-pool traversal forces one of them.
    let (c, tip) = chain 7 3 1_000
        (related, relOps) = mkPool c
        poison = ML.fromList
          [ (TxId (Hash256 (BS.replicate 28 0x77 <> BS.pack [0, fromIntegral (i `div` 65536), fromIntegral (i `div` 256), fromIntegral i])),
             error ("unrelated pool entry " ++ show i ++ " was read"))
          | i <- [1 .. 5_000 :: Int] ]
        entries = ML.union related poison
        cand = candidateSpending [OutPoint tip 0]
    r <- evaluate (checkClusterLimit cand entries relOps 1_000)
    r `shouldBe` Right ()

  it "still rejects at 65 txs with unrelated (unread) entries in the pool" $ do
    let (c, tip) = chain 9 64 100
        (related, relOps) = mkPool c
        poison = ML.fromList
          [ (TxId (Hash256 (BS.replicate 30 0x78 <> BS.pack [fromIntegral (i `div` 256), fromIntegral i])),
             error "unrelated pool entry was read")
          | i <- [1 .. 2_000 :: Int] ]
    r <- evaluate (checkClusterLimit (candidateSpending [OutPoint tip 0])
                                     (ML.union related poison) relOps 100)
    r `shouldBe` Left (ClusterLimitExceeded 65 64)

  it "200 cluster checks against a 30,000-entry pool finish in under 2 s" $ do
    -- 10,000 independent 3-tx chains = 30,000 entries; each check joins one.
    let chains = [ chain (fromIntegral k) 3 800 | k <- [1 .. 10_000 :: Int] ]
        (entries, byOp) = mkPool (concatMap fst chains)
        tips = map snd chains
    _ <- evaluate (Map.size entries + Map.size byOp)
    t0 <- getCurrentTime
    forM_ (zip [0 :: Int ..] (take 200 tips)) $ \(i, tip) -> do
      -- a fresh map per call so nothing can be shared between iterations
      let extra = entryFor (poolTx (fromIntegral i + 900_000) [] 1) 400
          entries' = Map.insert (meTxId extra) extra entries
      r <- evaluate (checkClusterLimit (candidateSpending [OutPoint tip 0]) entries' byOp 800)
      r `shouldBe` Right ()
    t1 <- getCurrentTime
    let secs = realToFrac (diffUTCTime t1 t0) :: Double
    hPutStrLn stderr ("    [bench] 200 checks, 30,000-entry pool: " ++ show secs ++ " s")
    secs `shouldSatisfy` (< 2)

  it "gives the same verdict as the whole-pool union-find on 400 random DAG pools" $
    forM_ [1 .. 400 :: Word64] $ \seed -> do
      let (txs, cand, w) = randomCase (seed * 7919)
          (entries, byOp) = mkPool txs
      (seed, checkClusterLimit cand entries byOp w)
        `shouldBe` (seed, referenceClusterLimit cand entries byOp w)

  it "control: the random cases reach all three verdicts" $ do
    let verdicts = [ case checkClusterLimit cand entries byOp w of
                       Right () -> 0 :: Int
                       Left (ClusterLimitExceeded _ _) -> 1
                       Left (ClusterSizeExceeded _ _) -> 2
                   | seed <- [1 .. 400 :: Word64]
                   , let (txs, cand, w) = randomCase (seed * 7919)
                         (entries, byOp) = mkPool txs ]
    Set.fromList verdicts `shouldBe` Set.fromList [0, 1, 2]

  it "findCluster still returns a tx's whole connected component" $ do
    let (c, _) = chain 11 5 100
        (entries, byOp) = mkPool c
        ids = map (computeTxId . fst) c
    forM_ ids $ \t -> findCluster t entries byOp `shouldBe` Set.fromList ids

  it "getAncestors (direct parents) matches a full scan of the pool" $
    withSystemTempDirectory "haskoin-bounded-cluster" $ \dir ->
      withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
        cache <- newUTXOCache db 1_000
        mp <- newMempool regtest cache defaultMempoolConfig 200 0 noopCoinMtp
        let (c, _) = chain 13 4 100
            txs = map fst c
            child = candidateSpending [ OutPoint (computeTxId (txs !! 3)) 0
                                      , OutPoint (computeTxId (txs !! 1)) 1
                                      , OutPoint (computeTxId (txs !! 3)) 1 ]
            (entries, byOp) = mkPool c
            parentIds = map (outPointHash . txInPrevOutput) (txInputs child)
            expected = [ t | (t, _) <- Map.toList entries, t `elem` parentIds ]
        atomically $ do
          writeTVar (mpEntries mp) entries
          writeTVar (mpByOutpoint mp) byOp
        got <- getAncestors mp child
        map meTxId got `shouldBe` expected
        -- a confirmed (non-pool) parent contributes nothing
        none <- getAncestors mp (candidateSpending [OutPoint (TxId (Hash256 (BS.replicate 32 0x42))) 0])
        none `shouldSatisfy` null

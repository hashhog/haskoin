{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
-- | perf-fix2-haskoin-fork-walk.
--
-- The P2P download path asks "does the header tip descend from the connected
-- tip, and if not, where do they fork?" once per connected block
-- ('fillLinearPipeline' -> 'forkDownloadFloor' -> 'detectP2PFork' in
-- app/Main.hs) and every 0.4 s from the block-gap kicker.  It answered with
-- 'findForkPoint', which walks 'cePrev' one 'Map.lookup' per height from the
-- header tip down to the connected tip.  During IBD that gap is the whole
-- header lead (33k -> 181k steps per call in the 60-min profile, ~940k once
-- the headers reach the mainnet tip), and the memo in front of it missed on
-- every block because its key held the connected tip.  Core answers the same
-- question with CChain / LastCommonAncestor over pskip in O(log n).
--
-- The fix answers it from the best header's height index ('ChainIndex',
-- haskoin#84): only the connected tip's side is walked, and only while it is
-- off the best header's chain.  The answers must equal 'findForkPoint's.
--
-- 'findForkPointIndexed' and 'forkPointWith' exist from the fix commit on;
-- the fix commit sets @HASKOIN_FORK_POINT_INDEX@ in this suite's cabal
-- stanza.  Without it this file still compiles on master: the reference tests
-- run against the old walk, the budget test times the old per-block call
-- ('findForkPoint') and fails on its timeout, and the index tests fail on
-- their assertion.
module Main (main) where

import Control.Concurrent.STM (atomically, writeTVar)
import qualified Data.ByteString as BS
import Data.Bits (shiftR)
import Data.List (foldl')
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import Data.Word (Word32)
import Control.Monad (forM)
import System.Timeout (timeout)
import Test.Hspec
import Test.QuickCheck
#ifdef HASKOIN_FORK_POINT_INDEX
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
#endif

import Haskoin.Consensus
import Haskoin.Types (BlockHash (..), BlockHeader (..), Hash256 (..))

--------------------------------------------------------------------------------
-- Header trees
--------------------------------------------------------------------------------

-- | Hash of node @i@ (distinct for every i).
hashOf :: Int -> BlockHash
hashOf i = BlockHash (Hash256 (BS.pack (map byte [7, 6 .. 0] ++ replicate 24 0x3c)))
  where byte k = fromIntegral (i `shiftR` (8 * k))

zeroHash :: BlockHash
zeroHash = BlockHash (Hash256 (BS.replicate 32 0))

entryFor :: BlockHash -> Word32 -> Maybe BlockHash -> ChainEntry
entryFor h height prev = ChainEntry
  { ceHeader     = BlockHeader 1 (maybe zeroHash id prev) (Hash256 (BS.replicate 32 0))
                     (1000000 + height * 600) 0x207fffff 0
  , ceHash       = h
  , ceHeight     = height
  , ceChainWork  = fromIntegral height + 1
  , cePrev       = prev
  , ceStatus     = StatusHeaderValid
  , ceMedianTime = 1000000 + height * 600
  , ceSequenceId = fromIntegral height
  }

-- | A header tree given as @parents !! (i-1)@ = parent of node i (node 0 is
-- genesis).  Returns the index and each node's height.
buildTree :: [Int] -> (Map BlockHash ChainEntry, Map Int Word32)
buildTree parents = foldl' add (Map.singleton (hashOf 0) (entryFor (hashOf 0) 0 Nothing), Map.singleton 0 0)
                           (zip [1 ..] parents)
  where
    add (m, hs) (i, p) =
      let h = hs Map.! p + 1
      in (Map.insert (hashOf i) (entryFor (hashOf i) h (Just (hashOf p))) m, Map.insert i h hs)

-- | A random tree of 1..n+1 nodes: each node's parent is one of the last
-- few nodes, so there are long chains with frequent forks.
genParents :: Gen [Int]
genParents = do
  n <- choose (0, 150)
  mapM (\i -> do d <- frequency [(6, pure 1), (3, choose (1, 4)), (1, choose (1, 30))]
                 pure (max 0 (i - d)))
       [1 .. n]

-- | Model fork point: the highest common ancestor of nodes @i@ and @j@,
-- from the parent list alone.
modelFork :: [Int] -> Int -> Int -> BlockHash
modelFork parents i j = hashOf (head [ k | k <- up j, Set.member k ancI ])
  where
    up 0 = [0]
    up k = k : up (parents !! (k - 1))
    ancI = Set.fromList (up i)

-- | A straight chain of @n+1@ headers 0..n.
straightChain :: Int -> Map BlockHash ChainEntry
straightChain n = fst (buildTree [0 .. n - 1])

-- | Main chain 0..300 (nodes 0..300) plus a fork that leaves it after height
-- 100 and runs to height 400 (nodes 1101..1400, heights 101..400).
forkFixture :: Map BlockHash ChainEntry
forkFixture = foldl' add (straightChain 300) [101 .. 400]
  where
    add m h = let p = if h == 101 then hashOf 100 else hashOf (1000 + h - 1)
              in Map.insert (hashOf (1000 + h)) (entryFor (hashOf (1000 + h)) (fromIntegral h) (Just p)) m

mainAt, forkAt :: Int -> BlockHash
mainAt = hashOf
forkAt h = hashOf (1000 + h)

-- | A header chain holding exactly @m@.
chainOf :: Map BlockHash ChainEntry -> IO HeaderChain
chainOf m = do
  hc <- initHeaderChain regtest
  atomically (writeTVar (hcEntries hc) m)
  return hc

-- | The old answer: 'findForkPoint' over @m@.
oldFork :: HeaderChain -> BlockHash -> BlockHash -> IO (Maybe BlockHash)
oldFork hc a b = fmap ceHash <$> findForkPoint hc a b

--------------------------------------------------------------------------------
-- The per-block call as app/Main.hs 'detectP2PFork' makes it
--------------------------------------------------------------------------------

-- | Fork point of (connected tip, header tip) the way the live download
-- path asks for it: one header chain for the life of the node, one call per
-- connected block.
perBlockFork :: HeaderChain -> Map BlockHash ChainEntry -> BlockHash -> BlockHash -> IO (Maybe BlockHash)
#ifdef HASKOIN_FORK_POINT_INDEX
perBlockFork hc m connected headerTip =
  fmap ceHash <$> findForkPointIndexed (hcAncestors hc) m connected headerTip
#else
perBlockFork hc _ connected headerTip = oldFork hc connected headerTip
#endif

-- | The scenario table: (connected tip, header tip, expected fork point),
-- in the order a header reorg would present them (the header tip moves
-- main 300 -> fork 400 -> main 300).
scenarios :: [(String, BlockHash, BlockHash, Maybe BlockHash)]
scenarios =
  [ ("linear: header tip descends from the connected tip", mainAt 150, mainAt 300, Just (mainAt 150))
  , ("header tip == connected tip", mainAt 300, mainAt 300, Just (mainAt 300))
  , ("connected tip on a stale side branch", forkAt 150, mainAt 300, Just (mainAt 100))
  , ("header reorg: heavier branch forks BELOW the connected tip", mainAt 250, forkAt 400, Just (mainAt 100))
  , ("header reorg: heavier branch forks ABOVE the connected tip", mainAt 50, forkAt 400, Just (mainAt 50))
  , ("header reorg: connected tip on the new branch", forkAt 200, forkAt 400, Just (forkAt 200))
  , ("header reorg: connected tip == fork point", mainAt 100, forkAt 400, Just (mainAt 100))
  , ("header reorg back: connected tip on the abandoned branch", forkAt 300, mainAt 300, Just (mainAt 100))
  , ("header reorg back: linear again", mainAt 299, mainAt 300, Just (mainAt 299))
  , ("connected tip above the header tip on another branch", forkAt 400, mainAt 120, Just (mainAt 100))
  , ("connected tip is genesis", mainAt 0, forkAt 400, Just (mainAt 0))
  , ("unknown connected tip", hashOf 9999, mainAt 300, Nothing)
  , ("unknown header tip", mainAt 10, hashOf 9999, Nothing)
  ]

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "fork point (reference answers from the old walk)" $ do
    it "the old findForkPoint walk matches the model on random header trees with forks" $
      property $ forAll genParents $ \parents ->
        let (m, _) = buildTree parents
            n = length parents
        in forAll (choose (0, n)) $ \i -> forAll (choose (0, n)) $ \j -> ioProperty $ do
             hc <- chainOf m
             r <- oldFork hc (hashOf i) (hashOf j)
             pure (r === Just (modelFork parents i j))

    it "the old findForkPoint walk gives the scenario table's answers" $ do
      hc <- chainOf forkFixture
      rs <- forM scenarios $ \(_, c, t, _) -> oldFork hc c t
      zip (map (\(d, _, _, _) -> d) scenarios) rs
        `shouldBe` [ (d, e) | (d, _, _, e) <- scenarios ]

  describe "per-block fork point (detectP2PFork's call)" $ do
    it "gives the scenario table's answers through one header chain across header reorgs" $ do
      hc <- chainOf forkFixture
      rs <- forM scenarios $ \(_, c, t, _) -> perBlockFork hc forkFixture c t
      zip (map (\(d, _, _, _) -> d) scenarios) rs
        `shouldBe` [ (d, e) | (d, _, _, e) <- scenarios ]

    it "1000 per-block calls with the header tip 199,000 headers ahead stay within 20 s" $ do
      let n = 200000
          m = straightChain n
      hc <- chainOf m
      t0 <- getCurrentTime
      r <- timeout (20 * 1000000) $ do
        rs <- forM [1 .. 1000] $ \i -> perBlockFork hc m (hashOf i) (hashOf n)
        -- Every connected tip is an ancestor of the header tip, so every
        -- fork point is the connected tip itself: the count proves the
        -- answers were computed, not elided.
        let !k = length [ () | (i, Just f) <- zip [1 ..] rs, f == hashOf i ]
        pure k
      t1 <- getCurrentTime
      putStrLn ("    1000 per-block fork points: " ++ show (diffUTCTime t1 t0))
      r `shouldBe` Just 1000

#ifdef HASKOIN_FORK_POINT_INDEX
    it "findForkPointIndexed equals findForkPoint across random trees, one cache, moving header tips" $
      property $ withMaxSuccess 500 $ forAll genParents $ \parents ->
        let (m, _) = buildTree parents
            n = length parents
        in forAll (listOf1 ((,) <$> choose (0, n) <*> choose (0, n))) $ \queries ->
             ioProperty $ do
               hc <- chainOf m
               rs <- forM queries $ \(c, t) -> do
                 new <- perBlockFork hc m (hashOf c) (hashOf t)
                 old <- oldFork hc (hashOf c) (hashOf t)
                 pure (new === old .&&. new === Just (modelFork parents c t))
               pure (conjoin rs)

    it "a malformed index (a parent whose height is not one less) falls back to the old walk" $ do
      -- Node 3 claims height 10 although its parent (node 2) is at height 2;
      -- nodes 4.. continue from it.  A side branch leaves node 1.
      let bad = Map.fromList $
                  [ (hashOf 0, entryFor (hashOf 0) 0 Nothing)
                  , (hashOf 1, entryFor (hashOf 1) 1 (Just (hashOf 0)))
                  , (hashOf 2, entryFor (hashOf 2) 2 (Just (hashOf 1)))
                  , (hashOf 3, entryFor (hashOf 3) 10 (Just (hashOf 2)))
                  , (hashOf 4, entryFor (hashOf 4) 11 (Just (hashOf 3)))
                  , (hashOf 5, entryFor (hashOf 5) 12 (Just (hashOf 4)))
                  , (hashOf 50, entryFor (hashOf 50) 2 (Just (hashOf 1)))
                  , (hashOf 51, entryFor (hashOf 51) 3 (Just (hashOf 50)))
                  ]
      hc <- chainOf bad
      let pairs = [ (a, b) | a <- [0, 1, 2, 3, 4, 5, 50, 51, 77], b <- [5, 4, 51, 2, 77] ]
      rs <- forM pairs $ \(a, b) -> (,) <$> perBlockFork hc bad (hashOf a) (hashOf b)
                                         <*> oldFork hc (hashOf a) (hashOf b)
      [ (p, new) | (p, (new, old)) <- zip pairs rs, new /= old ] `shouldBe` []

    it "the per-block call does at most O(log n) lookups once the header tip is indexed" $ do
      let n = 200000 :: Int
          m = straightChain n
          -- A 6-deep stale branch off height 150,000.
          side = foldl' (\acc k -> Map.insert (hashOf (900000 + k))
                                     (entryFor (hashOf (900000 + k)) (fromIntegral (150000 + k))
                                       (Just (if k == 1 then hashOf 150000 else hashOf (900000 + k - 1)))) acc)
                        m [1 .. 6]
          logN = ceiling (logBase 2 (fromIntegral n :: Double)) :: Int
      cnt <- newIORef (0 :: Int)
      let look h = modifyIORef' cnt (+ 1) >> pure (Map.lookup h side)
          Just ci = chainIndexSetTip side (hashOf n) Nothing
          countFor c t = do
            writeIORef cnt 0
            r <- forkPointWith look (Just ci) (side Map.! c) (side Map.! t)
            k <- readIORef cnt
            pure (ceHash <$> r, k)
      -- Linear IBD: the connected tip is on the indexed chain.
      lin <- forM [1, 1000, 100000, 199999, 200000] $ \i -> countFor (hashOf i) (hashOf n)
      [ r | (r, _) <- lin ] `shouldBe` map (Just . hashOf) [1, 1000, 100000, 199999, 200000]
      [ k | (_, k) <- lin, k > logN ] `shouldBe` []
      -- The connected tip on a 6-deep stale branch: six steps down to the fork.
      (rf, kf) <- countFor (hashOf 900006) (hashOf n)
      rf `shouldBe` Just (hashOf 150000)
      kf `shouldSatisfy` (<= logN)
      -- The old walk on the same linear question does one lookup per height.
      writeIORef cnt 0
      _ <- forkPointWith look Nothing (side Map.! hashOf 1000) (side Map.! hashOf n)
      kOld <- readIORef cnt
      kOld `shouldSatisfy` (>= n - 1000)
#else
    it "findForkPointIndexed equals findForkPoint across random trees, one cache, moving header tips" $
      expectationFailure "no findForkPointIndexed on this commit: the fork point is a cePrev walk"
    it "a malformed index (a parent whose height is not one less) falls back to the old walk" $
      expectationFailure "no findForkPointIndexed on this commit"
    it "the per-block call does at most O(log n) lookups once the header tip is indexed" $
      expectationFailure "no forkPointWith on this commit: findForkPoint does one Map.lookup per height of the gap"
#endif

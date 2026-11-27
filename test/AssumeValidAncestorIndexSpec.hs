{-# LANGUAGE CPP #-}
{-# LANGUAGE BangPatterns #-}
-- | perf-fix-haskoin-assumevalid-ancestor.
--
-- 'shouldSkipScripts' answers Core's two assumevalid ancestor questions
-- (bitcoin-core/src/validation.cpp ConnectBlock:
-- @it->second.GetAncestor(pindex->nHeight) == pindex@ and
-- @m_chainman.m_best_header->GetAncestor(pindex->nHeight) == pindex@) with
-- 'ancestorAtHeight', which walks 'cePrev' one 'Map.lookup' at a time.  A
-- block at height h costs (assumevalid height - h) + (best header height - h)
-- lookups, so a sync from genesis pays O(height) per block and O(n^2) over
-- the pre-assumevalid range: about 1.9M lookups for each of the first blocks
-- on mainnet.  Core answers the same question in O(log n) with pskip, and
-- the active chain in O(1) with the CChain vector.
--
-- The fix keeps a height-indexed vector of the assumevalid header's ancestry
-- and of the best header's ancestry ('ChainIndex'), updated the way
-- CChain::SetTip is: only the part above the fork point with the previous
-- tip is walked.  The decision logic is unchanged and shared.
--
-- 'ChainIndex', 'AncestorCache' and 'shouldSkipScriptsCached' exist from the
-- fix commit on; the fix commit sets @HASKOIN_AV_ANCESTOR_INDEX@ in this
-- suite's cabal stanza.  Without it this file still compiles on master: the
-- reference tests run against the old walk, the budget test times the old
-- 'shouldSkipScripts' and fails on its timeout, and the index tests fail on
-- their assertion.
module Main (main) where

import qualified Data.ByteString as BS
import Data.Bits (shiftR)
import Data.List (foldl')
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Maybe (fromJust)
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import Data.Word (Word32)
import System.Timeout (timeout)
import Test.Hspec
import Test.QuickCheck
#ifdef HASKOIN_AV_ANCESTOR_INDEX
import Control.Monad (forM, forM_)
import Data.IORef (readIORef)
#endif

import Haskoin.Consensus
import Haskoin.Types (BlockHash (..), BlockHeader (..), Hash256 (..))

--------------------------------------------------------------------------------
-- Header trees
--------------------------------------------------------------------------------

-- | Hash of node @i@ (distinct for every i).
hashOf :: Int -> BlockHash
hashOf i = BlockHash (Hash256 (BS.pack (map byte [7, 6 .. 0] ++ replicate 24 0x5a)))
  where byte k = fromIntegral (i `shiftR` (8 * k))

zeroHash :: BlockHash
zeroHash = BlockHash (Hash256 (BS.replicate 32 0))

-- | Timestamps 100,000 s apart per height, and 333 work units per height at
-- the 0x207fffff difficulty (header work 2, so 333 * 600 / 2 = 99,900 s of
-- work-equivalent time per block): two weeks is ~12 blocks either way, so the
-- 2-week guard (condition 6, Core's GetBlockProofEquivalentTime) is both met
-- and missed inside small trees.
tsAt :: Word32 -> Word32
tsAt h = 1000000 + h * 100000

entryFor :: BlockHash -> Word32 -> Maybe BlockHash -> ChainEntry
entryFor h height prev = ChainEntry
  { ceHeader     = BlockHeader 1 (maybe zeroHash id prev) (Hash256 (BS.replicate 32 0))
                     (tsAt height) 0x207fffff 0
  , ceHash       = h
  , ceHeight     = height
  , ceChainWork  = (fromIntegral height + 1) * 333
  , cePrev       = prev
  , ceStatus     = StatusHeaderValid
  , ceMedianTime = tsAt height
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

-- | Model ancestry: node @i@'s ancestor at height @h@, from the parent list.
modelAncestor :: [Int] -> Map Int Word32 -> Int -> Word32 -> Maybe BlockHash
modelAncestor parents hs i h
  | hi == h   = Just (hashOf i)
  | hi < h    = Nothing
  | otherwise = modelAncestor parents hs (parents !! (i - 1)) h
  where hi = hs Map.! i

-- | The old walk, as the reference answer.
walk :: Map BlockHash ChainEntry -> BlockHash -> Word32 -> Maybe BlockHash
walk m s h = ceHash <$> ancestorAtHeight m s h

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

netWithAV :: BlockHash -> Network
netWithAV av = mainnet { netAssumedValid = Just av, netMinimumChainWork = 0 }

entryOf :: Map BlockHash ChainEntry -> BlockHash -> ChainEntry
entryOf m h = m Map.! h

-- | The reference decision for block @b@ of @m@ under assumevalid @av@ and best header @best@.
oldDecision :: Map BlockHash ChainEntry -> BlockHash -> BlockHash -> BlockHash -> Bool
oldDecision m av best b =
  let e = entryOf m b
  in shouldSkipScripts b (ceHeight e) (tsAt (ceHeight e)) (netWithAV av) m (entryOf m best)

--------------------------------------------------------------------------------
-- The per-block decision as the live MBlock arm makes it
--------------------------------------------------------------------------------

-- | Make @length bs@ decisions over one index, the way app/Main.hs does:
-- one cache for the life of the header chain, one call per block.
liveDecisions :: Network -> Map BlockHash ChainEntry -> ChainEntry -> [ChainEntry] -> IO [Bool]
#ifdef HASKOIN_AV_ANCESTOR_INDEX
liveDecisions net m best bs = do
  cache <- newAncestorCache
  forM bs $ \e -> shouldSkipScriptsCached cache (ceHash e) (ceHeight e) (tsAt (ceHeight e)) net m best
#else
liveDecisions net m best bs =
  pure [ shouldSkipScripts (ceHash e) (ceHeight e) (tsAt (ceHeight e)) net m best | e <- bs ]
#endif

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "assumevalid ancestor check (reference answers from the old walk)" $ do
    it "the old ancestorAtHeight walk matches the model on random header trees with forks" $
      property $ forAll genParents $ \parents ->
        let (m, hs) = buildTree parents
            n = length parents
        in forAll (choose (0, n)) $ \i -> forAll (choose (0, fromIntegral n + 2)) $ \h ->
             walk m (hashOf i) h === modelAncestor parents hs i h

    it "a block on a fork of the assumevalid chain still has its scripts checked" $ do
      let m = forkFixture
          av = mainAt 250
      -- Best header on the assumevalid chain: main blocks below it skip,
      -- fork blocks at the same heights do not.
      oldDecision m av (mainAt 300) (mainAt 110) `shouldBe` True
      oldDecision m av (mainAt 300) (forkAt 110) `shouldBe` False
      oldDecision m av (mainAt 300) (forkAt 101) `shouldBe` False
      -- Best header on the fork: only blocks below the fork point skip.
      oldDecision m av (forkAt 400) (mainAt 50)  `shouldBe` True
      oldDecision m av (forkAt 400) (mainAt 150) `shouldBe` False
      oldDecision m av (forkAt 400) (forkAt 150) `shouldBe` False
      -- Above the assumevalid header nothing skips.
      oldDecision m av (mainAt 300) (mainAt 260) `shouldBe` False
      -- The same answers through the call the live MBlock arm makes.
      let cases = [ (mainAt 300, mainAt 110), (mainAt 300, forkAt 110), (mainAt 300, forkAt 101)
                  , (forkAt 400, mainAt 50), (forkAt 400, mainAt 150), (forkAt 400, forkAt 150)
                  , (mainAt 300, mainAt 260) ]
      live <- mapM (\(best, b) -> head <$> liveDecisions (netWithAV av) m (entryOf m best) [entryOf m b]) cases
      live `shouldBe` [ oldDecision m av best b | (best, b) <- cases ]

  describe "O(1) assumevalid ancestor index" $ do
    it "2000 assumevalid decisions near genesis on a 200,000-header chain stay within 20 s" $ do
      let n = 200000
          m = straightChain n
          net = netWithAV (hashOf (n - 1000))
          best = entryOf m (hashOf n)
          blocks = [ entryOf m (hashOf i) | i <- [1 .. 2000] ]
      Map.size m `shouldBe` n + 1
      t0 <- getCurrentTime
      r <- timeout (20 * 1000000) $ do
        ds <- liveDecisions net m best blocks
        let !k = length (filter id ds)
        pure k
      t1 <- getCurrentTime
      putStrLn ("    2000 decisions: " ++ show (diffUTCTime t1 t0))
      -- Every one of these blocks is below assumevalid on the best chain, so
      -- all 2000 skip: the count proves the decisions were made, not elided.
      r `shouldBe` Just 2000

#ifdef HASKOIN_AV_ANCESTOR_INDEX
    it "the index answer equals the old walk on random header trees with forks" $
      property $ forAll genParents $ \parents ->
        let (m, _) = buildTree parents
            n = length parents
        in forAll (choose (0, n)) $ \i ->
             let ci = fromJust (chainIndexSetTip m (hashOf i) Nothing)
             in conjoin [ ancestorViaIndex m ci h === walk m (hashOf i) h
                        | h <- [0 .. fromIntegral n + 2] ]

    it "an index moved across random reorgs (SetTip reuse) equals the old walk" $
      property $ forAll genParents $ \parents ->
        let (m, _) = buildTree parents
            n = length parents
        in forAll (listOf1 (choose (0, n))) $ \tips ->
             let step (acc, prev) t =
                   let ci = fromJust (chainIndexSetTip m (hashOf t) prev)
                       ok = conjoin [ ancestorViaIndex m ci h === walk m (hashOf t) h
                                    | h <- [0 .. fromIntegral n + 2] ]
                   in (ok : acc, Just ci)
             in conjoin (fst (foldl' step ([], Nothing) tips))

    it "shouldSkipScriptsCached equals shouldSkipScripts across random trees, assumevalid and best headers" $
      property $ withMaxSuccess 1000 $ forAll genParents $ \parents ->
        let (m, _) = buildTree parents
            n = length parents
        in forAll (choose (0, n)) $ \av ->
           forAll (listOf1 ((,) <$> choose (0, n) <*> choose (0, n))) $ \queries ->
             ioProperty $ do
               cache <- newAncestorCache
               let net = netWithAV (hashOf av)
               rs <- forM queries $ \(bestI, bI) -> do
                 let e = entryOf m (hashOf bI)
                 new <- shouldSkipScriptsCached cache (ceHash e) (ceHeight e) (tsAt (ceHeight e))
                          net m (entryOf m (hashOf bestI))
                 pure (new === oldDecision m (hashOf av) (hashOf bestI) (hashOf bI))
               pure (conjoin rs)

    it "the best-header chain index follows a header reorg" $ do
      let m = forkFixture
          net = netWithAV (mainAt 250)
          decide cache best b =
            let e = entryOf m b
            in shouldSkipScriptsCached cache b (ceHeight e) (tsAt (ceHeight e)) net m (entryOf m best)
      cache <- newAncestorCache
      decide cache (mainAt 300) (mainAt 150) `shouldReturn` True
      Just ciA <- readIORef (acBestHeader cache)
      ciTip ciA `shouldBe` mainAt 300
      -- The best header moves to the heavier fork that left the main chain
      -- at height 100: main block 150 is no longer on the best chain.
      decide cache (forkAt 400) (mainAt 150) `shouldReturn` False
      Just ciB <- readIORef (acBestHeader cache)
      ciTip ciB `shouldBe` forkAt 400
      ciTipHeight ciB `shouldBe` 400
      ancestorViaIndex m ciB 150 `shouldBe` Just (forkAt 150)
      ancestorViaIndex m ciB 100 `shouldBe` Just (mainAt 100)
      decide cache (forkAt 400) (mainAt 50) `shouldReturn` True
      -- And back.
      decide cache (mainAt 300) (mainAt 150) `shouldReturn` True
      Just ciA' <- readIORef (acBestHeader cache)
      ciTip ciA' `shouldBe` mainAt 300
      forM_ [0 .. 300] $ \h -> ancestorViaIndex m ciA' h `shouldBe` Just (mainAt (fromIntegral h))
      -- The assumevalid index is built once and kept.
      Just av <- readIORef (acAssumeValid cache)
      ciTip av `shouldBe` mainAt 250
#else
    it "the index answer equals the old walk on random header trees with forks" $
      expectationFailure "no ChainIndex on this commit: ancestry is a cePrev walk"
    it "an index moved across random reorgs (SetTip reuse) equals the old walk" $
      expectationFailure "no ChainIndex on this commit: ancestry is a cePrev walk"
    it "shouldSkipScriptsCached equals shouldSkipScripts across random trees, assumevalid and best headers" $
      expectationFailure "no shouldSkipScriptsCached on this commit"
    it "the best-header chain index follows a header reorg" $
      expectationFailure "no best-header chain index on this commit"
#endif

{-# LANGUAGE CPP #-}
-- | cffix-haskoin-addrman-index-prune.
--
-- The address manager's lookup index ('amAddrIndex') and the flat
-- 'pmKnownAddrs' set grew with every distinct address ever gossiped, not with
-- table capacity:
--
-- 1. 'addAddress' prepends the newcomer to its new bucket and truncates the
--    bucket at 'addrmanBucketSize'.  The entry pushed out of the bucket stayed
--    in 'amAddrIndex' and was still counted in 'amNewCount'.
-- 2. 'markGood' does the same in the tried table: the tried entry pushed out
--    stayed in the index flagged @aiInTried@ and was still counted in
--    'amTriedCount', although no table held it.
-- 3. 'handleAddrMessage' unioned every gossiped address into 'pmKnownAddrs',
--    which nothing ever shrinks, and which the connection loop dials as a
--    fallback that bypasses the address manager.
--
-- Core keeps one record per address in mapInfo/mapAddr and erases it
-- (AddrManImpl::Delete, addrman.cpp) as soon as no table references it
-- (ClearNew on a new-bucket eviction); a tried-table collision moves the old
-- occupant back to the new table (MakeTried).  The index is therefore bounded
-- by table capacity: 1024*64 new + 256*64 tried slots.
--
-- 'mergeKnownAddrs' (the DNS-seed merge with a cap) exists from the fix commit
-- on; the fix commit sets @HASKOIN_KNOWNADDRS_CAP@ in this suite's cabal
-- stanza.  Without it the file still compiles on master and the test for the
-- cap fails on its assertion.
module AddrmanIndexBoundSpec (spec) where

import Control.Concurrent.STM (readTVarIO)
import Control.Exception (bracket)
import Control.Monad (forM_)
import qualified Data.ByteString as BS
import Data.Int (Int64)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket (SockAddr (..), tupleToHostAddress, hostAddressToTuple)
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network
import Haskoin.Types (NetworkAddress (..))

v4 :: Int -> Int -> Int -> Int -> SockAddr
v4 a b c d =
  SockAddrInet 8333
    (tupleToHostAddress (fromIntegral a, fromIntegral b, fromIntegral c, fromIntegral d))

-- | @n@ distinct routable IPv4 addresses (first octet 11.., skipping the
-- non-routable and special-use first octets that could appear).
distinctRoutable :: Int -> [SockAddr]
distinctRoutable n = take n
  [ v4 a b c d
  | a <- [11 .. 99], a `notElem` [10, 100, 127]
  , b <- [0 .. 255], c <- [0 .. 255], d <- [1 .. 254 :: Int]
  , d == 1 + (b + c) `mod` 254 ]

tableCapacity :: Int
tableCapacity =
  addrmanNewBucketCount * addrmanBucketSize
    + addrmanTriedBucketCount * addrmanBucketSize

tableAddrs :: Map.Map Int [AddrInfo] -> [SockAddr]
tableAddrs = concatMap (map aiAddress) . Map.elems

-- | Every invariant Core's mapInfo keeps: the index holds exactly the
-- addresses some table holds, each flagged with the table it is in, and the
-- two counters equal the table populations.
checkConsistent :: AddrMan -> IO ()
checkConsistent am = do
  newT   <- readTVarIO (amNewTable am)
  triedT <- readTVarIO (amTriedTable am)
  idx    <- readTVarIO (amAddrIndex am)
  nc     <- readTVarIO (amNewCount am)
  tc     <- readTVarIO (amTriedCount am)
  let newA   = tableAddrs newT
      triedA = tableAddrs triedT
      stale  = Map.keysSet idx `Set.difference` Set.fromList (newA ++ triedA)
  (Set.size stale, take 3 (Set.toList stale)) `shouldBe` (0, [])
  Map.keysSet idx `shouldBe` Set.fromList (newA ++ triedA)
  nc `shouldBe` Set.size (Set.fromList newA)
  tc `shouldBe` length triedA
  [ a | a <- triedA, maybe True (not . aiInTried) (Map.lookup a idx) ]
    `shouldBe` []
  [ a | a <- newA, maybe True aiInTried (Map.lookup a idx) ]
    `shouldBe` []

toEntry :: Int64 -> SockAddr -> AddrEntry
toEntry now (SockAddrInet _ h) =
  let (a, b, c, d) = hostAddressToTuple h
  in AddrEntry (fromIntegral now)
       (NetworkAddress 0x409
          (BS.pack ([0,0,0,0,0,0,0,0,0,0,0xff,0xff] ++ [a, b, c, d])) 8333)
toEntry _ other = error ("toEntry: not IPv4: " ++ show other)

withPm :: (PeerManager -> IO a) -> IO a
withPm act =
  withSystemTempDirectory "haskoin-addrman-index" $ \dir -> do
    let cfg =
          defaultPeerManagerConfig
            { pmcDataDir = dir
            , pmcDnsSeed = False
            , pmcMaxOutbound = 0
            , pmcMaxBlockRelayOnly = 0
            }
    bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager $ \pm -> do
      -- No dialing from a test: nothing gossiped here is ever contacted.
      _ <- setNetworkActive pm False
      act pm

-- | A distinct source /16 per index (first octet 101..126, 128..).
sourceFor :: Int -> SockAddr
sourceFor i = v4 (101 + i `div` 256) (i `mod` 256) 0 1

chunksOf :: Int -> [a] -> [[a]]
chunksOf _ [] = []
chunksOf n xs = let (h, t) = splitAt n xs in h : chunksOf n t

spec :: Spec
spec = describe "addrman: the index and pmKnownAddrs are bounded by table capacity (Core AddrManImpl::Delete)" $ do

  it "200,000 distinct routable addresses through addAddress leave amAddrIndex within table capacity" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    let addrs = distinctRoutable 200000
    length addrs `shouldBe` 200000
    forM_ addrs $ \a -> addAddress am BS.empty a a 0x409 now
    idx <- readTVarIO (amAddrIndex am)
    Map.size idx `shouldSatisfy` (<= tableCapacity)

  it "after the same flood, amNewCount equals the number of new-table entries and the index holds only tabled addresses" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    forM_ (distinctRoutable 200000) $ \a -> addAddress am BS.empty a a 0x409 now
    newT <- readTVarIO (amNewTable am)
    nc   <- readTVarIO (amNewCount am)
    nc `shouldBe` length (tableAddrs newT)
    checkConsistent am

  it "markGood past a full tried bucket keeps amTriedCount and the index in step with the tables" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    -- 80 addresses in one /16 that all map to the same tried bucket: more
    -- than the 64 slots, so markGood has to displace tried entries.
    let pool   = [ v4 50 60 c d | c <- [0 .. 255], d <- [1 .. 254] ]
        target = getTriedBucket (amKey am) BS.empty (head pool)
        same   = take 80 (filter ((== target) . getTriedBucket (amKey am) BS.empty) pool)
    length same `shouldBe` 80
    -- Each from its own source /16, so the 80 spread over new buckets and
    -- all of them are still in the new table when markGood runs.
    forM_ (zip [0 :: Int ..] same) $ \(i, a) ->
      addAddress am BS.empty a (sourceFor i) 0x409 now
    idx0 <- readTVarIO (amAddrIndex am)
    length (filter (`Map.member` idx0) same) `shouldBe` 80
    forM_ same $ \a -> markGood am BS.empty a now
    triedT <- readTVarIO (amTriedTable am)
    -- The bucket really overflowed: 64 held, 16 displaced back to new.
    length (Map.findWithDefault [] target triedT) `shouldBe` addrmanBucketSize
    newT <- readTVarIO (amNewTable am)
    length (filter (`elem` tableAddrs newT) same) `shouldBe` 80 - addrmanBucketSize
    checkConsistent am

  it "a tried entry displaced by markGood returns to the new table with its attempt history" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    let pool   = [ v4 50 61 c d | c <- [0 .. 255], d <- [1 .. 254] ]
        target = getTriedBucket (amKey am) BS.empty (head pool)
        same   = take 80 (filter ((== target) . getTriedBucket (amKey am) BS.empty) pool)
        (first64, later16) = splitAt addrmanBucketSize same
    forM_ (zip [0 :: Int ..] same) $ \(i, a) ->
      addAddress am BS.empty a (sourceFor i) 0x409 now
    forM_ first64 $ \a -> markGood am BS.empty a now
    -- markAttempt updates only the index record of a tried entry.
    forM_ first64 $ \a -> markAttempt am a now
    forM_ later16 $ \a -> markGood am BS.empty a now
    newT <- readTVarIO (amNewTable am)
    idx  <- readTVarIO (amAddrIndex am)
    let newSet    = Set.fromList (tableAddrs newT)
        displaced = filter (`Set.member` newSet) first64
    length displaced `shouldBe` length later16
    [ (a, fmap aiAttempts (Map.lookup a idx), fmap aiInTried (Map.lookup a idx))
      | a <- displaced ]
      `shouldBe` [ (a, Just 1, Just False) | a <- displaced ]
    checkConsistent am

  it "gossip through handleAddrMessage does not grow pmKnownAddrs" $
    withPm $ \pm -> do
      now <- round <$> getPOSIXTime
      before <- Set.size <$> readTVarIO (pmKnownAddrs pm)
      forM_ (chunksOf 1000 (distinctRoutable 5000)) $ \batch ->
        handleAddrMessage pm (Addr (map (toEntry now) batch))
      after <- Set.size <$> readTVarIO (pmKnownAddrs pm)
      -- The addresses are still learned, by the address manager.
      idx <- readTVarIO (amAddrIndex (pmAddrMan pm))
      Map.size idx `shouldSatisfy` (> 0)
      after `shouldBe` before

  it "the DNS-seed merge into pmKnownAddrs is capped" $ do
#ifdef HASKOIN_KNOWNADDRS_CAP
    let rounds = chunksOf 500 (distinctRoutable 20000)
        final  = foldl mergeKnownAddrs Set.empty rounds
    Set.size final `shouldSatisfy` (<= knownAddrsCap)
    -- The latest seed answer is always kept.
    Set.fromList (last rounds) `shouldSatisfy` (`Set.isSubsetOf` final)
    -- Under the cap nothing is dropped.
    mergeKnownAddrs (Set.fromList (take 10 (head rounds))) (take 10 (drop 10 (head rounds)))
      `shouldBe` Set.fromList (take 20 (head rounds))
#else
    expectationFailure "no cap on pmKnownAddrs: the DNS-seed merge is an unbounded Set.union"
#endif

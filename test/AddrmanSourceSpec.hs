{-# LANGUAGE CPP #-}
-- | cffix-haskoin-addrman-source-and-collision.
--
-- Two addrman defects let one peer flood the new table:
--
-- 1. 'handleAddrMessage' passed each advertised address as its own source
--    (@addAddress … a a@), so the source group was the address's own /16.
--    Core files every address a peer gossips under that peer's address
--    (net_processing.cpp ProcessAddrs: @m_addrman.Add(vAddrOk, pfrom.addr)@),
--    and AddrInfo::GetNewBucket keys the bucket on the source group, so one
--    peer reaches at most ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP = 64 of the
--    1024 new buckets.  With source = self, one peer reached all of them.
--
-- 2. 'addAddress' prepended the newcomer and truncated the bucket list at 64
--    (@take addrmanBucketSize $ info : existing_bucket@), so a full bucket
--    always lost its oldest entry, whatever its state.  Core
--    (addrman.cpp AddrManImpl::AddSingle) computes the newcomer's slot with
--    GetBucketPosition and replaces the slot's occupant only if the occupant
--    IsTerrible or is also referenced from another bucket (nRefCount > 1);
--    otherwise the newcomer is dropped.
--
-- The fix adds a source argument to 'handleAddrMessage'.  The test calls the
-- new signature behind @HASKOIN_ADDRMAN_SOURCE@, which the fix commit sets in
-- this suite's cabal stanza (as GetDataAmplificationSpec does).  Without it
-- the file still compiles against the old signature and each test fails on
-- its assertion.
module AddrmanSourceSpec (spec) where

import Control.Concurrent.STM (atomically, modifyTVar', readTVarIO)
import Control.Exception (bracket)
import Control.Monad (forM_, unless)
import qualified Data.ByteString as BS
import Data.Int (Int64)
import Data.List (foldl')
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket (SockAddr (..), tupleToHostAddress)
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network
import Haskoin.Types (NetworkAddress (..))

v4 :: Int -> Int -> Int -> Int -> SockAddr
v4 a b c d =
  SockAddrInet 8333
    (tupleToHostAddress (fromIntegral a, fromIntegral b, fromIntegral c, fromIntegral d))

-- | The wire form handleAddrMessage decodes: IPv4-mapped IPv6, host-order
-- octets in the last four bytes.
toEntry :: Int64 -> SockAddr -> AddrEntry
toEntry now (SockAddrInet _ h) =
  let (a, b, c, d) = hostAddressToTupleLE h
  in AddrEntry (fromIntegral now)
       (NetworkAddress 0x409
          (BS.pack ([0,0,0,0,0,0,0,0,0,0,0xff,0xff] ++ [a, b, c, d])) 8333)
  where
    hostAddressToTupleLE w =
      ( fromIntegral (w `mod` 0x100)
      , fromIntegral ((w `div` 0x100) `mod` 0x100)
      , fromIntegral ((w `div` 0x10000) `mod` 0x100)
      , fromIntegral ((w `div` 0x1000000) `mod` 0x100) )
toEntry _ other = error ("toEntry: not IPv4: " ++ show other)

withPm :: (PeerManager -> IO a) -> IO a
withPm act =
  withSystemTempDirectory "haskoin-addrman-source" $ \dir -> do
    let cfg =
          defaultPeerManagerConfig
            { pmcDataDir = dir
            , pmcDnsSeed = False
            , pmcMaxOutbound = 0
            , pmcMaxBlockRelayOnly = 0
            }
    bracket (startPeerManager regtest cfg (\_ _ -> pure ())) stopPeerManager $ \pm -> do
      -- No dialing from a test: with networking off the manager loop opens
      -- no feeler, so nothing it does can move an entry new -> tried while
      -- the test runs, and no gossiped (public) address is ever dialled.
      _ <- setNetworkActive pm False
      act pm

-- | Gossip from one peer, through the production entry point, in Core-sized
-- (1000-entry) messages.
gossipFrom :: PeerManager -> SockAddr -> [AddrEntry] -> IO ()
gossipFrom pm _peer entries =
  forM_ (chunks 1000 entries) $ \batch ->
#ifdef HASKOIN_ADDRMAN_SOURCE
    handleAddrMessage pm _peer (Addr batch)
#else
    handleAddrMessage pm (Addr batch)
#endif
  where
    chunks _ [] = []
    chunks n xs = let (h, t) = splitAt n xs in h : chunks n t

-- | The attacking peer.
attacker :: SockAddr
attacker = v4 44 55 66 77

-- | 5,000 attacker-advertised addresses, each in its own /16 (first octet
-- 11..99 minus 44, second octet 0..255): all routable, none honest.
floodAddrs :: [SockAddr]
floodAddrs = take 5000
  [ v4 a b 1 1 | a <- [11 .. 99], a /= 44, b <- [0 .. 255] ]

-- | Honest candidates: first octet 150..199, each gossiped by its own honest
-- source (first octet 201..220).  Disjoint from the flood.
honestCandidates :: [(SockAddr, SockAddr)]
honestCandidates =
  [ (v4 a b c 9, v4 (201 + (b `mod` 20)) c 0 1)
  | a <- [150 .. 199], b <- [0 .. 255], c <- [0, 37 .. 255] ]

newTableAddrs :: AddrMan -> IO (Map.Map Int [SockAddr])
newTableAddrs am = Map.map (map aiAddress) <$> readTVarIO (amNewTable am)

spec :: Spec
spec = describe "addrman: gossip source is the sending peer; a full slot keeps a good occupant" $ do

  it "5,000 addresses from one peer land in at most 64 new buckets (Core ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP)" $
    withPm $ \pm -> do
      now <- round <$> getPOSIXTime
      gossipFrom pm attacker (map (toEntry now) floodAddrs)
      tbl <- newTableAddrs (pmAddrMan pm)
      let floodSet = Set.fromList floodAddrs
          touched  = Map.keys (Map.filter (any (`Set.member` floodSet)) tbl)
      length touched `shouldSatisfy` (<= addrmanNewBucketsPerSourceGroup)

  it "the flood removes no non-terrible honest entry from the new table" $
    withPm $ \pm -> do
      now <- round <$> getPOSIXTime
      let am  = pmAddrMan pm
          key = amKey am
          -- Pick 16 target buckets and fill each with honest entries until it
          -- holds 64 candidates, so that on the old prepend-and-truncate code
          -- any further insert into these buckets pushes an honest entry out.
          targets = Set.fromList [0, 64 .. 1023]
          step acc (a, s) =
            let b = getNewBucket key BS.empty a s
            in if Set.member b targets && length (Map.findWithDefault [] b acc) < addrmanBucketSize
                 then Map.insertWith (++) b [(a, s)] acc
                 else acc
          chosen = concat (Map.elems (foldl' step Map.empty honestCandidates))
      forM_ chosen $ \(a, s) -> addAddress am BS.empty a s 0x409 now
      seeded <- newTableAddrs am
      idx0   <- readTVarIO (amAddrIndex am)
      let honestBefore = Set.fromList (concat (Map.elems seeded))
          good = Set.filter (\a -> maybe False (not . isTerribleAddress now)
                                     (Map.lookup a idx0)) honestBefore
      -- Sanity: the seed really did populate the target buckets.
      Set.size good `shouldSatisfy` (>= 16 * 30)

      gossipFrom pm attacker (map (toEntry now) floodAddrs)

      flooded <- newTableAddrs am
      let present = Set.fromList (concat (Map.elems flooded))
          lost    = Set.toList (good `Set.difference` present)
      unless (null lost) $
        expectationFailure (show (length lost) ++ " non-terrible honest entries evicted, e.g. "
                            ++ show (take 3 lost))

  it "a newcomer whose slot is held by a non-terrible entry is not added, and the occupant stays" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    let key  = amKey am
        src  = v4 201 1 0 1
        occ  = v4 150 1 1 9
        b    = getNewBucket key BS.empty occ src
        pos  = getBucketPosition key True b occ
        -- Same /16 as the occupant and same source, so the same bucket; find
        -- one that also hashes to the occupant's slot.
        rival = head [ x | c <- [0 .. 255], d <- [1 .. 254]
                         , let x = v4 150 1 c d, x /= occ
                         , getNewBucket key BS.empty x src == b
                         , getBucketPosition key True b x == pos ]
    _ <- addAddress am BS.empty occ src 0x409 now
    _ <- addAddress am BS.empty rival src 0x409 now
    tbl <- newTableAddrs am
    let bucket = Map.findWithDefault [] b tbl
    (occ `elem` bucket, rival `elem` bucket) `shouldBe` (True, False)

  it "a newcomer whose slot is held by a terrible entry replaces it" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    let key  = amKey am
        src  = v4 201 1 0 1
        occ  = v4 150 1 1 9
        b    = getNewBucket key BS.empty occ src
        pos  = getBucketPosition key True b occ
        rival = head [ x | c <- [0 .. 255], d <- [1 .. 254]
                         , let x = v4 150 1 c d, x /= occ
                         , getNewBucket key BS.empty x src == b
                         , getBucketPosition key True b x == pos ]
    _ <- addAddress am BS.empty occ src 0x409 now
    -- Three failed attempts, never a success, last try over a minute ago:
    -- Core IsTerrible (nAttempts >= ADDRMAN_RETRIES && nLastSuccess == 0).
    forM_ [1 .. 3 :: Int] $ \i -> markAttempt am occ (now - 3600 - fromIntegral i)
    idx <- readTVarIO (amAddrIndex am)
    fmap (isTerribleAddress now) (Map.lookup occ idx) `shouldBe` Just True
    _ <- addAddress am BS.empty rival src 0x409 now
    tbl <- newTableAddrs am
    idx' <- readTVarIO (amAddrIndex am)
    let bucket = Map.findWithDefault [] b tbl
    (occ `elem` bucket, rival `elem` bucket, Map.member occ idx')
      `shouldBe` (False, True, False)

  it "a newcomer whose slot is held by an entry also in another bucket (nRefCount > 1) takes the slot; the occupant keeps its index entry" $ do
    am <- newAddrMan
    now <- round <$> getPOSIXTime
    let key  = amKey am
        src  = v4 201 1 0 1
        occ  = v4 150 1 1 9
        b    = getNewBucket key BS.empty occ src
        pos  = getBucketPosition key True b occ
        rival = head [ x | c <- [0 .. 255], d <- [1 .. 254]
                         , let x = v4 150 1 c d, x /= occ
                         , getNewBucket key BS.empty x src == b
                         , getBucketPosition key True b x == pos ]
    _ <- addAddress am BS.empty occ src 0x409 now
    -- Stand-in for a second new-bucket reference (Core nRefCount == 2).
    atomically $ modifyTVar' (amAddrIndex am)
      (Map.adjust (\i -> i { aiRefCount = 2 }) occ)
    _ <- addAddress am BS.empty rival src 0x409 now
    tbl <- newTableAddrs am
    idx <- readTVarIO (amAddrIndex am)
    let bucket = Map.findWithDefault [] b tbl
    (occ `elem` bucket, rival `elem` bucket, aiRefCount <$> Map.lookup occ idx)
      `shouldBe` (False, True, Just 1)

-- | Which peers answered @notfound@ for a block we asked them for.
--
-- The linear planner does not ask that peer for that hash again for
-- 'blockNotFoundTtl' seconds, and the kicker releases the in-flight entry so
-- the peer is not then disconnected as a staller for a block it never had.
-- Core never gets here: FindNextBlocksToDownload only asks a peer for blocks
-- on its pindexBestKnownBlock chain; haskoin's planner is header-blind, and
-- a peer that does not have a freshly announced block (the honest peer when
-- another peer announces a block only it holds) was disconnected after 2 s.
--
-- secfix-haskoin-notfound-unsolicited (H6): the @notfound@ handler used to
-- record every block hash in the message, asked for or not, in one global
-- map with no cap; the map is rebuilt on every @notfound@ and read on every
-- planner tick.  One @notfound@ naming 50,000 block hashes put 50,000
-- entries there.  Core (net_processing.cpp, NetMsgType::NOTFOUND) only acts
-- on items that peer has in flight (@ReceivedResponse@ on its own tx
-- requests) and ignores the rest.  Here a @notfound@ entry is recorded only
-- for a hash this node sent that same peer a block @getdata@ for
-- ('noteBlockRequested', called from 'Haskoin.Network.sendMessage', the
-- single send path every block request goes through), and both maps are
-- capped.
module Haskoin.BlockNotFound
  ( blockNotFoundRef
  , blockRequestedRef
  , blockNotFoundTtl
  , blockRequestTtl
  , maxBlockNotFoundEntries
  , maxBlockRequestedEntries
  , noteBlockRequested
  , noteBlockRequestAnswered
  , noteBlockNotFound
  , readBlockNotFound
  , blockNotFoundEntryCount
    -- * Pure core (tests)
  , PeerHashTimes
  , insertRequestedAt
  , recordNotFoundAt
  , dropRequested
  , pruneExpired
  , capEntries
  , entryCount
  ) where

import Control.Monad (unless)
import Data.IORef
import Data.Int (Int64)
import qualified Data.List as L
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket (SockAddr)
import System.IO.Unsafe (unsafePerformIO)

import Haskoin.Types (BlockHash)

-- | hash -> peer -> POSIX seconds.
type PeerHashTimes = Map.Map BlockHash (Map.Map SockAddr Int64)

-- | Live notfound answers for blocks we asked that peer for.
{-# NOINLINE blockNotFoundRef #-}
blockNotFoundRef :: IORef PeerHashTimes
blockNotFoundRef = unsafePerformIO (newIORef Map.empty)

-- | Block getdata this node sent, per peer: the "in flight to this peer"
-- set a notfound is checked against.
{-# NOINLINE blockRequestedRef #-}
blockRequestedRef :: IORef PeerHashTimes
blockRequestedRef = unsafePerformIO (newIORef Map.empty)

blockNotFoundTtl :: Int64
blockNotFoundTtl = 120

-- | How long a sent block request still counts as in flight for the
-- notfound check.  Generous: Core's block download timeout is 10 min base.
blockRequestTtl :: Int64
blockRequestTtl = 600

-- | Caps on (hash, peer) pairs.  Both maps only grow from this node's own
-- requests now; the caps are a backstop so no input can grow them past a
-- fixed size.
maxBlockNotFoundEntries :: Int
maxBlockNotFoundEntries = 16384

maxBlockRequestedEntries :: Int
maxBlockRequestedEntries = 65536

nowSecs :: IO Int64
nowSecs = round <$> getPOSIXTime

-- | Number of (hash, peer) pairs.
entryCount :: PeerHashTimes -> Int
entryCount = Map.foldl' (\n m -> n + Map.size m) 0

-- | Drop entries older than @ttl@ and hashes left with no peer.
pruneExpired :: Int64 -> Int64 -> PeerHashTimes -> PeerHashTimes
pruneExpired ttl now =
  Map.filter (not . Map.null) . Map.map (Map.filter (\t -> now - t < ttl))

-- | Keep at most @cap@ (hash, peer) pairs, dropping the oldest first.
-- Only sorts when over the cap.
capEntries :: Int -> PeerHashTimes -> PeerHashTimes
capEntries cap m
  | entryCount m <= cap = m
  | otherwise =
      let flat = [ (t, h, a) | (h, pm) <- Map.toList m, (a, t) <- Map.toList pm ]
          keep = drop (length flat - cap) (L.sortOn (\(t, _, _) -> t) flat)
      in Map.fromListWith Map.union [ (h, Map.singleton a t) | (t, h, a) <- keep ]

-- | Insert (hash, addr, now) pairs.  The size check is O(1); expired
-- entries are only swept, and the oldest dropped, once the map is over
-- @cap@ hashes, so a send or a notfound never walks the whole map.
insertCapped :: Int64 -> Int -> Int64 -> SockAddr -> [BlockHash]
             -> PeerHashTimes -> PeerHashTimes
insertCapped ttl cap now addr hs m0 =
  let m1 = L.foldl' (\acc h -> Map.insertWith Map.union h (Map.singleton addr now) acc) m0 hs
  in if Map.size m1 <= cap then m1 else capEntries cap (pruneExpired ttl now m1)

-- | Record that we asked @addr@ for these block hashes at @now@.
insertRequestedAt :: Int64 -> SockAddr -> [BlockHash] -> PeerHashTimes -> PeerHashTimes
insertRequestedAt = insertCapped blockRequestTtl maxBlockRequestedEntries

-- | Forget the request for @h@ to @addr@ (answered: block or notfound).
dropRequested :: SockAddr -> BlockHash -> PeerHashTimes -> PeerHashTimes
dropRequested addr = Map.update (\pm -> let pm' = Map.delete addr pm
                                        in if Map.null pm' then Nothing else Just pm')

-- | Apply a notfound from @addr@ naming @hs@: only hashes with a live
-- request to @addr@ are recorded (and that request is consumed);
-- everything else is ignored.  Returns (requested', notfound').
recordNotFoundAt :: Int64 -> SockAddr -> [BlockHash]
                 -> PeerHashTimes -> PeerHashTimes -> (PeerHashTimes, PeerHashTimes)
recordNotFoundAt now addr hs req0 nf0 =
  let live h = case Map.lookup h req0 >>= Map.lookup addr of
                 Just t  -> now - t < blockRequestTtl
                 Nothing -> False
      hits = Set.toList (Set.fromList (filter live hs))
      req1 = L.foldl' (flip (dropRequested addr)) req0 hits
      nf1  = insertCapped blockNotFoundTtl maxBlockNotFoundEntries now addr hits nf0
  in (req1, nf1)

-- | Called for every block getdata handed to a peer's socket.
noteBlockRequested :: SockAddr -> [BlockHash] -> IO ()
noteBlockRequested _ [] = return ()
noteBlockRequested addr hs = do
  now <- nowSecs
  atomicModifyIORef' blockRequestedRef $ \m -> (insertRequestedAt now addr hs m, ())

-- | Called when @addr@ delivers block @h@: the request is answered.
noteBlockRequestAnswered :: SockAddr -> BlockHash -> IO ()
noteBlockRequestAnswered addr h = do
  m <- readIORef blockRequestedRef
  case Map.lookup h m of
    Nothing -> return ()
    Just _  -> atomicModifyIORef' blockRequestedRef $ \r -> (dropRequested addr h r, ())

-- | Called for the block hashes in a peer's notfound.  A notfound naming
-- no hash we asked that peer for changes nothing and rebuilds no map.
noteBlockNotFound :: SockAddr -> [BlockHash] -> IO ()
noteBlockNotFound _ [] = return ()
noteBlockNotFound addr hs = do
  now <- nowSecs
  req <- readIORef blockRequestedRef
  let asked h = maybe False (Map.member addr) (Map.lookup h req)
  case filter asked hs of
    [] -> return ()
    cand -> do
      hits <- atomicModifyIORef' blockRequestedRef $ \r ->
        let (r', nfNew) = recordNotFoundAt now addr cand r Map.empty
        in (r', Map.keys nfNew)
      unless (null hits) $
        atomicModifyIORef' blockNotFoundRef $ \m ->
          (insertCapped blockNotFoundTtl maxBlockNotFoundEntries now addr hits m, ())

-- | Live (unexpired) notfound answers.
readBlockNotFound :: IO PeerHashTimes
readBlockNotFound = do
  now <- nowSecs
  pruneExpired blockNotFoundTtl now <$> readIORef blockNotFoundRef

-- | (hash, peer) pairs currently stored, expired or not.
blockNotFoundEntryCount :: IO Int
blockNotFoundEntryCount = entryCount <$> readIORef blockNotFoundRef

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | BIP-339 wtxid-keyed orphan transaction pool.
--
-- Mirrors Bitcoin Core's @TxOrphanage@ in @src/node/txorphanage.h@.
--
-- Fixes BUG-12 (EraseForPeer) and BUG-13 (EraseForBlock) identified in the
-- W103 tx-relay-flow fleet audit.
--
-- Reference: bitcoin-core/src/node/txorphanage.h
--            bitcoin-core/src/node/txorphanage.cpp

module Haskoin.TxOrphanage
  ( OrphanPool(..)
  , emptyOrphanPool
  , maxOrphanTxs
  , orphanExpireSecs
  , addOrphan
  , expireOrphans
  , eraseOrphansForPeer
  , eraseOrphansForBlock
  ) where

import Data.Int (Int64)
import Data.IORef (IORef, modifyIORef')
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Network.Socket (SockAddr)

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)

-- | In-memory orphan transaction pool.
--
-- Primary key  : Wtxid  (BIP-339 / Bitcoin Core txorphanage.h)
-- Secondary idx: parent TxId → Set of child Wtxid
--               (used for child-resolution on parent accept — mirrors Core's
--                @m_outpoint_to_orphan_it@ map in @txorphanage.h@)
-- Peer attribution: each orphan entry stores the 'SockAddr' of the announcing
--               peer so that 'eraseOrphansForPeer' can purge on disconnect.
--               Mirrors @TxOrphanage::EraseForPeer@ (txorphanage.h:86).
--
-- Core reference: @src/node/txorphanage.h@ — TxOrphanage uses wtxid as the
-- primary key and @AddChildrenToWorkSet(parent)@ for orphan re-queuing.
-- Orphans expire after @ORPHAN_TX_EXPIRE_TIME@ (5 min).
data OrphanPool = OrphanPool
  { orphanPool  :: !(Map.Map Wtxid (Tx, Int64, SockAddr))
    -- ^ Primary wtxid-keyed store.
    --   Value is (tx, insertion-epoch-seconds, announcing-peer-addr).
    --   The SockAddr enables EraseForPeer on peer disconnect (BUG-12 fix).
  , orphanWtxid :: !(Map.Map TxId (Set.Set Wtxid))
    -- ^ Secondary index: parent TxId → Set of child Wtxids.
    -- Populated by 'addOrphan'; used by orphan-resolution to find all orphans
    -- that spend outputs of a newly-accepted parent transaction.
  } deriving (Show)

-- | Empty orphan pool.
emptyOrphanPool :: OrphanPool
emptyOrphanPool = OrphanPool Map.empty Map.empty

-- | Maximum orphan pool size (Bitcoin Core DEFAULT_MAX_ORPHAN_TRANSACTIONS=100).
maxOrphanTxs :: Int
maxOrphanTxs = 100

-- | Orphan expiry in seconds (Bitcoin Core ORPHAN_TX_EXPIRE_TIME=300 = 5 min).
orphanExpireSecs :: Int64
orphanExpireSecs = 300

-- ---------------------------------------------------------------------------
-- Internal helpers
-- ---------------------------------------------------------------------------

-- | Remove a set of evicted wtxids from the secondary index.
pruneWtxidIndex :: Set.Set Wtxid -> Map.Map TxId (Set.Set Wtxid)
                -> Map.Map TxId (Set.Set Wtxid)
pruneWtxidIndex discardWtxids idx =
  Map.filter (not . Set.null) (Map.map (Set.\\ discardWtxids) idx)

-- | Remove the secondary-index entries for a single evicted orphan tx.
removeChildFromIdx :: Wtxid -> Tx -> Map.Map TxId (Set.Set Wtxid)
                   -> Map.Map TxId (Set.Set Wtxid)
removeChildFromIdx evictW evictTx idx =
  let evictParents = map (outPointHash . txInPrevOutput) (txInputs evictTx)
      remove pTxId m =
        Map.alter (\ms -> case ms of
          Nothing -> Nothing
          Just s  -> let s' = Set.delete evictW s
                     in if Set.null s' then Nothing else Just s'
          ) pTxId m
  in foldr remove idx evictParents

-- ---------------------------------------------------------------------------
-- Core operations
-- ---------------------------------------------------------------------------

-- | Add a transaction to the orphan pool keyed by its wtxid (BIP-339).
--
-- * No-op if the wtxid is already present (exact-duplicate dedup).
-- * When the pool is at capacity, the minimum-key entry is evicted first.
-- * The announcing 'SockAddr' is stored for 'eraseOrphansForPeer' (BUG-12 fix).
--
-- Core reference: @TxOrphanage::AddTx@ (txorphanage.cpp).
addOrphan :: IORef OrphanPool -> Tx -> Int64 -> SockAddr -> IO ()
addOrphan ref tx now peerAddr = modifyIORef' ref $ \op ->
  let wtxid     = computeWtxid tx
      parentIds = map (outPointHash . txInPrevOutput) (txInputs tx)
  in if Map.member wtxid (orphanPool op)
       then op  -- already present — deduplicate by wtxid
       else
         -- Evict the minimum-key entry when at capacity
         let op' = if Map.size (orphanPool op) >= maxOrphanTxs
                     then case Map.minViewWithKey (orphanPool op) of
                            Nothing -> op
                            Just ((_evictW, (evictTx, _, _)), m') ->
                              let evictW2  = computeWtxid evictTx
                                  evictIdx = removeChildFromIdx evictW2 evictTx
                                               (orphanWtxid op)
                              in op { orphanPool  = m'
                                    , orphanWtxid = evictIdx
                                    }
                     else op
             -- Insert new orphan into primary store (with peer attribution)
             pool' = Map.insert wtxid (tx, now, peerAddr) (orphanPool op')
             -- Index this orphan under each of its parent TxIds
             addChild pTxId idx =
               Map.insertWith Set.union pTxId (Set.singleton wtxid) idx
             idx' = foldr addChild (orphanWtxid op') parentIds
         in op' { orphanPool  = pool'
                , orphanWtxid = idx'
                }

-- | Remove expired orphans (older than 'orphanExpireSecs') from the pool.
--
-- Core reference: @LimitOrphans@ in @txorphanage.cpp@.
expireOrphans :: IORef OrphanPool -> Int64 -> IO ()
expireOrphans ref now = modifyIORef' ref $ \op ->
  let (keep, discard) = Map.partition (\(_, t, _) -> now - t < orphanExpireSecs)
                          (orphanPool op)
      discardWtxids   = Map.keysSet discard
      cleanIdx        = pruneWtxidIndex discardWtxids (orphanWtxid op)
  in op { orphanPool  = keep
        , orphanWtxid = cleanIdx
        }

-- | BUG-12 FIX: Remove all orphans attributed to a disconnected peer.
--
-- Mirrors @TxOrphanage::EraseForPeer@ in Bitcoin Core
-- (bitcoin-core\/src\/node\/txorphanage.h:86).
--
-- Called from the 'pmOnPeerDisconnect' hook in 'peerManagerLoop' whenever a
-- peer transitions to 'PeerDisconnected' and is removed from the peer map.
-- Without this, a disconnected peer's orphans linger until they expire
-- (up to 'orphanExpireSecs' = 300 s), wasting pool space that blocks
-- legitimate orphans from honest peers.
--
-- Core: "Maybe erase all orphans announced by a peer (eg, after that peer
-- disconnects). If an orphan has been announced by another peer, don't erase,
-- just remove this peer from the list of announcers."
-- (In this simplified single-announcer model we remove the entry entirely.)
eraseOrphansForPeer :: SockAddr -> IORef OrphanPool -> IO ()
eraseOrphansForPeer peerAddr ref = modifyIORef' ref $ \op ->
  let (keep, discard) = Map.partition (\(_, _, a) -> a /= peerAddr)
                          (orphanPool op)
      discardWtxids   = Map.keysSet discard
      cleanIdx        = pruneWtxidIndex discardWtxids (orphanWtxid op)
  in op { orphanPool  = keep
        , orphanWtxid = cleanIdx
        }

-- | BUG-13 FIX: Remove all orphans whose txid was confirmed in a block.
--
-- After 'blockConnected' removes confirmed txs from the mempool, call this
-- to ensure the orphan pool does not retain stale entries for txs that are
-- now on-chain.  Mirrors @TxOrphanage::EraseForBlock@ in Bitcoin Core
-- (bitcoin-core\/src\/node\/txorphanage.h:89 \/ txorphanage.cpp EraseForBlock).
--
-- Core also removes orphans that /conflict/ with the block (spend the same
-- inputs as confirmed txs).  This implementation removes orphans whose own
-- txid appears in the block, covering the primary case.
--
-- The confirmed txid list is computed as @map computeTxId (blockTxns block)@
-- by the caller.
eraseOrphansForBlock :: [TxId] -> IORef OrphanPool -> IO ()
eraseOrphansForBlock confirmedTxIds ref = modifyIORef' ref $ \op ->
  let confirmedSet = Set.fromList confirmedTxIds
      (keep, discard) = Map.partition
        (\(tx, _, _) -> not (Set.member (computeTxId tx) confirmedSet))
        (orphanPool op)
      discardWtxids = Map.keysSet discard
      cleanIdx      = pruneWtxidIndex discardWtxids (orphanWtxid op)
  in op { orphanPool  = keep
        , orphanWtxid = cleanIdx
        }

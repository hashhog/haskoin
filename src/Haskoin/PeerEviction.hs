-- | Pure decision logic for evicting outbound peers, ported from Bitcoin
-- Core's net_processing.cpp: @EvictExtraOutboundPeers@ and
-- @ConsiderEviction@. Nothing here touches a socket or a clock; the
-- caller ('Haskoin.Network.runOutboundEviction') gathers the facts and
-- applies the verdicts.
--
-- Not block validation: it only chooses which peer connections to drop.
module Haskoin.PeerEviction
  ( OutboundKind (..)
  , OutboundEvictCand (..)
  , selectExtraOutboundEvictions
  , ChainSyncTimer (..)
  , noChainSyncTimer
  , ConsiderAction (..)
  , considerEvictionStep
  , evictMinConnectSecs
  , chainSyncTimeoutSecs
  , headersResponseTimeSecs
  , maxProtectedOutbound
  , extraPeerCheckIntervalSecs
  ) where

import Data.Int (Int64)
import Data.List (sortBy)
import Data.Ord (comparing)
import Network.Socket (SockAddr)

-- | Core @MINIMUM_CONNECT_TIME@ (net_processing.cpp:112).
evictMinConnectSecs :: Int64
evictMinConnectSecs = 30

-- | Core @CHAIN_SYNC_TIMEOUT@ (20 min).
chainSyncTimeoutSecs :: Int64
chainSyncTimeoutSecs = 20 * 60

-- | Core @HEADERS_RESPONSE_TIME@ (2 min).
headersResponseTimeSecs :: Int64
headersResponseTimeSecs = 2 * 60

-- | Core @MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT@.
maxProtectedOutbound :: Int
maxProtectedOutbound = 4

-- | Core @EXTRA_PEER_CHECK_INTERVAL@ (net_processing.cpp:110).
extraPeerCheckIntervalSecs :: Int
extraPeerCheckIntervalSecs = 45

data OutboundKind = KindFullRelay | KindBlockRelay | KindManual
  deriving (Eq, Show)

-- | One connected outbound (or manual) peer, as the eviction pass sees it.
data OutboundEvictCand = OutboundEvictCand
  { oecAddr          :: !SockAddr
  , oecKind          :: !OutboundKind
  , oecConnectedAt   :: !Int64   -- ^ unix secs; with the address, Core's node id order
  , oecLastAnnounce  :: !Int64   -- ^ m_last_block_announcement
  , oecLastBlock     :: !Int64   -- ^ m_last_block_time
  , oecBlocksInFlight :: !Int
  , oecProtected     :: !Bool    -- ^ m_chain_sync.m_protect
  , oecNetwork       :: !Int     -- ^ address family class
  } deriving (Show)

-- | Core @EvictExtraOutboundPeers@. Arguments: full-relay target,
-- block-relay-only target, now, candidates. Returns the peers to drop and
-- whether to clear @m_try_another_outbound_peer@.
selectExtraOutboundEvictions :: Int -> Int -> Int64 -> [OutboundEvictCand]
                             -> ([SockAddr], Bool)
selectExtraOutboundEvictions maxFull maxBlockRelay now cands =
  (blockRelayVerdict ++ fullVerdict, clearTry)
  where
    -- Core orders by node id; connect time then address is the stand-in.
    byAge = sortBy (comparing (\c -> (oecConnectedAt c, oecAddr c)))
    blockRelay = byAge [c | c <- cands, oecKind c == KindBlockRelay]
    fullRelay  = [c | c <- cands, oecKind c == KindFullRelay]

    -- Youngest extra block-relay-only peer, unless it gave us a block more
    -- recently than the second youngest, in which case the second youngest.
    blockRelayVerdict
      | length blockRelay <= maxBlockRelay = []
      | otherwise = case reverse blockRelay of
          (y : n : _) ->
            let victim = if oecLastBlock y > oecLastBlock n then n else y
            in [oecAddr victim | oecBlocksInFlight victim == 0
                               , now - oecConnectedAt victim >= evictMinConnectSecs]
          _ -> []

    -- Full-relay: the peer that least recently announced a block; ties go
    -- to the more recent connection. Protected peers, and the only
    -- full-relay/manual connection on a network, are never chosen.
    fullEligible = [ c | c <- fullRelay, not (oecProtected c), multipleOn (oecNetwork c) ]
    multipleOn net = length [ () | c <- cands, oecKind c /= KindBlockRelay
                                 , oecNetwork c == net ] > 1
    worst = case sortBy (comparing (\c -> (oecLastAnnounce c, negate (oecConnectedAt c)))) fullEligible of
      (c : _) -> Just c
      []      -> Nothing
    (fullVerdict, clearTry) = case worst of
      Just w | length fullRelay > maxFull
             , now - oecConnectedAt w > evictMinConnectSecs
             , oecBlocksInFlight w == 0 -> ([oecAddr w], True)
      _ -> ([], False)

-- | Core's @ChainSyncTimeoutState@.
data ChainSyncTimer = ChainSyncTimer
  { cstTimeout       :: !Int64           -- ^ 0 = unset
  , cstWorkTip       :: !(Maybe Integer) -- ^ chain work of our tip when armed
  , cstSentGetHeaders :: !Bool
  } deriving (Eq, Show)

noChainSyncTimer :: ChainSyncTimer
noChainSyncTimer = ChainSyncTimer 0 Nothing False

data ConsiderAction = ConsiderNothing | ConsiderSendGetHeaders | ConsiderDisconnect
  deriving (Eq, Show)

-- | Core @ConsiderEviction@ for one unprotected, sync-started outbound peer:
-- now, our tip's chain work, the peer's best known chain work.
considerEvictionStep :: Int64 -> Integer -> Maybe Integer -> ChainSyncTimer
                     -> (ConsiderAction, ChainSyncTimer)
considerEvictionStep now tipWork peerWork t
  | maybe False (>= tipWork) peerWork =
      (ConsiderNothing, if cstTimeout t /= 0 then noChainSyncTimer else t)
  | cstTimeout t == 0 || caughtUpToArmed =
      (ConsiderNothing, ChainSyncTimer (now + chainSyncTimeoutSecs) (Just tipWork) False)
  | now > cstTimeout t =
      if cstSentGetHeaders t
        then (ConsiderDisconnect, t)
        else ( ConsiderSendGetHeaders
             , t { cstTimeout = now + headersResponseTimeSecs, cstSentGetHeaders = True } )
  | otherwise = (ConsiderNothing, t)
  where
    caughtUpToArmed = case (cstWorkTip t, peerWork) of
      (Just w, Just p) -> p >= w
      _                -> False

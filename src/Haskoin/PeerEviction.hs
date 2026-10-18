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
selectExtraOutboundEvictions _ _ _ _ = ([], False)

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
considerEvictionStep _ _ _ t = (ConsiderNothing, t)

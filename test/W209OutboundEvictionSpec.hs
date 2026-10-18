{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

-- | Extra-outbound eviction and a bounded send queue.
--
-- receipts/haskoin-tip-wedge-2026-10-04.md (Residual): a deaf peer could
-- still hold the background sender and block requests, the send queue was
-- unbounded, and the extra outbound peer opened by the stale-tip check was
-- never evicted (Core EvictExtraOutboundPeers / ConsiderEviction were not
-- ported). Fixtures: a stalled peer (no new blocks announced, blocks in
-- flight, or never catching up) among healthy ones.
module W209OutboundEvictionSpec (spec) where

import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Concurrent.STM (atomically, modifyTVar', newTVarIO, newTBQueueIO, readTVarIO)
import Control.Exception (bracket, finally)
import Control.Monad (replicateM_)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Int (Int64)
import qualified Data.Map.Strict as Map
import Network.Socket
  ( Family (AF_UNIX), SockAddr (..), SocketType (Stream), close, socketPair
  , tupleToHostAddress )
import Control.Concurrent.MVar (newMVar)
import System.Directory (createDirectoryIfMissing, removeDirectoryRecursive)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network
import Haskoin.Types (BlockHash (..), Hash256 (..))

--------------------------------------------------------------------------------
-- Pure fixtures
--------------------------------------------------------------------------------

addrN :: Int -> SockAddr
addrN n = SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, fromIntegral n))

now0 :: Int64
now0 = 100000

cand :: Int -> OutboundKind -> Int64 -> Int64 -> Int -> OutboundEvictCand
cand n k connectedAgo lastAnn inflight = OutboundEvictCand
  { oecAddr = addrN n, oecKind = k
  , oecConnectedAt = now0 - connectedAgo
  , oecLastAnnounce = lastAnn, oecLastBlock = lastAnn
  , oecBlocksInFlight = inflight, oecProtected = False, oecNetwork = 0 }

-- 9 full-relay peers (target 8); peer 3 announced longest ago.
nineFull :: [OutboundEvictCand]
nineFull = [ cand n KindFullRelay (1000 + fromIntegral n) (if n == 3 then 10 else 5000 + fromIntegral n) 0
           | n <- [1 .. 9] ]

--------------------------------------------------------------------------------
-- PeerManager fixtures
--------------------------------------------------------------------------------

withPm :: String -> (PeerManager -> IO a) -> IO a
withPm tag act = bracket
  (do let d = "dist-test-tmp/w209-" ++ tag
      createDirectoryIfMissing True d
      pm <- startPeerManager regtest
              defaultPeerManagerConfig { pmcDataDir = d, pmcDnsSeed = False }
              (\_ _ -> return ())
      return (d, pm))
  (\(d, _) -> removeDirectoryRecursive d)
  (\(_, pm) -> act pm `finally` stopPeerManager pm)

mkConn :: SockAddr -> Int64 -> IO (PeerConnection, IO ())
mkConn a connectedAt = do
  realNow <- round <$> getPOSIXTime
  (ours, theirs) <- socketPair AF_UNIX Stream 0
  info <- newTVarIO PeerInfo
    { piAddress = a, piVersion = Nothing, piState = PeerConnected, piServices = 0
    , piStartHeight = 0, piRelay = True, piLastSeen = realNow, piLastPing = Nothing
    , piPingLatency = Nothing, piBanScore = 0, piBytesSent = 0, piBytesRecv = 0
    , piMsgsSent = 0, piMsgsRecv = 0, piConnectedAt = connectedAt, piTimeOffset = 0
    , piInbound = False, piWantsAddrV2 = False, piWantsHeaders = False
    , piFeeFilterReceived = 0, piFeeFilterSent = 0, piNextFeeFilterSend = 0
    , piBlockOnly = False, piUnconnectingHeaders = 0, piNoBan = False
    , piIsManual = False, piIsLocal = False, piWtxidRelay = False
    , piProvidesCmpct = False, piCmpctHBFrom = False, piGetaddrRecvd = False
    , piAddrTokenBucket = 1.0, piAddrTokenTimestamp = 0 }
  lock <- newMVar ()
  q <- newTBQueueIO 10
  buf <- newIORef BS.empty
  v2 <- newIORef Nothing
  fb <- newIORef Nothing
  return ( PeerConnection
             { pcSocket = ours, pcInfo = info, pcSendLock = lock, pcRecvQueue = q
             , pcSendThread = Nothing, pcRecvThread = Nothing, pcNetwork = regtest
             , pcReadBuffer = buf, pcV2Transport = v2, pcBlockFirstByteAt = fb }
         , close theirs )

stateOf :: PeerConnection -> IO PeerState
stateOf pc = piState <$> readTVarIO (pcInfo pc)

spec :: Spec
spec = describe "outbound-eviction" $ do

  describe "EvictExtraOutboundPeers (pure)" $ do

    it "drops the full-relay peer that announced a block least recently and clears try-new" $ do
      selectExtraOutboundEvictions 8 0 now0 nineFull `shouldBe` ([addrN 3], True)

    it "does nothing at or below the target" $
      selectExtraOutboundEvictions 8 0 now0 (take 8 nineFull) `shouldBe` ([], False)

    it "keeps the stalled peer while a block is in flight from it" $ do
      let cs = [ if oecAddr c == addrN 3 then c { oecBlocksInFlight = 1 } else c | c <- nineFull ]
      selectExtraOutboundEvictions 8 0 now0 cs `shouldBe` ([], False)

    it "keeps a peer connected for 30s or less" $ do
      let cs = [ if oecAddr c == addrN 3 then c { oecConnectedAt = now0 - 30 } else c | c <- nineFull ]
      selectExtraOutboundEvictions 8 0 now0 cs `shouldBe` ([], False)

    it "never picks a protected peer" $ do
      let cs = [ if oecAddr c == addrN 3 then c { oecProtected = True } else c | c <- nineFull ]
          (ev, _) = selectExtraOutboundEvictions 8 0 now0 cs
      ev `shouldSatisfy` (\e -> e /= [addrN 3] && length e == 1)

    it "breaks announcement ties toward the more recent connection" $ do
      let cs = [ c { oecLastAnnounce = 77 } | c <- nineFull ]
      selectExtraOutboundEvictions 8 0 now0 cs `shouldBe` ([addrN 1], True)
      -- addrN 1 was connected longest ago in nineFull?  No: ids rise with
      -- connectedAgo, so addrN 9 connected earliest and addrN 1 latest.

    it "protects the only connection on a network" $ do
      let only = [ (cand 1 KindFullRelay 1000 1 0) { oecNetwork = 1 } ]
          rest = [ cand n KindFullRelay 1000 9000 0 | n <- [2 .. 9] ]
      fst (selectExtraOutboundEvictions 8 0 now0 (only ++ rest)) `shouldSatisfy` (/= [addrN 1])

    it "evicts the youngest extra block-relay-only peer unless it gave a block more recently" $ do
      let br n ago blk = (cand n KindBlockRelay ago blk 0)
          cs = [br 1 5000 10, br 2 4000 10, br 3 3000 10]
      selectExtraOutboundEvictions 0 2 now0 cs `shouldBe` ([addrN 3], False)
      let cs2 = [br 1 5000 10, br 2 4000 10, br 3 3000 900]
      selectExtraOutboundEvictions 0 2 now0 cs2 `shouldBe` ([addrN 2], False)

  describe "ConsiderEviction (pure)" $ do
    let tipWork = 1000 :: Integer
        step n w t = considerEvictionStep n tipWork w t

    it "arms a timer for a peer behind our tip, probes at expiry, drops after the response window" $ do
      let (a1, t1) = step 0 (Just 500) noChainSyncTimer
      a1 `shouldBe` ConsiderNothing
      cstTimeout t1 `shouldBe` chainSyncTimeoutSecs
      let (a2, t2) = step (chainSyncTimeoutSecs + 1) (Just 500) t1
      a2 `shouldBe` ConsiderSendGetHeaders
      cstTimeout t2 `shouldBe` chainSyncTimeoutSecs + 1 + headersResponseTimeSecs
      let (a3, _) = step (chainSyncTimeoutSecs + 2 + headersResponseTimeSecs) (Just 500) t2
      a3 `shouldBe` ConsiderDisconnect

    it "a peer with no known headers at all is also timed out" $ do
      let (_, t1) = step 0 Nothing noChainSyncTimer
          (a2, t2) = step (chainSyncTimeoutSecs + 1) Nothing t1
          (a3, _)  = step (chainSyncTimeoutSecs + headersResponseTimeSecs + 2) Nothing t2
      (a2, a3) `shouldBe` (ConsiderSendGetHeaders, ConsiderDisconnect)

    it "a peer that reaches our tip's work resets the timer" $ do
      let (_, t1) = step 0 (Just 500) noChainSyncTimer
          (a2, t2) = step 10 (Just 1000) t1
      (a2, t2) `shouldBe` (ConsiderNothing, noChainSyncTimer)

  describe "bounded background send queue" $ do

    it "drops fan-out sends past the cap instead of queueing without limit" $
      withPm "queue" $ \pm -> do
        gate <- newEmptyMVar
        enqueueBackgroundSend pm (takeMVar gate)        -- parks the worker
        ran <- newIORef (0 :: Int)
        let n = backgroundSendQueueCap + 500
        replicateM_ n (enqueueBackgroundSend pm (modifyIORef' ran (+ 1)))
        dropped <- backgroundSendsDropped pm
        putMVar gate ()
        dropped `shouldSatisfy` (>= 400)

  describe "runOutboundEviction (stalled-peer fixture)" $ do

    let env inflight = OutboundEvictEnv
          { oeeTipWork = return 1000
          , oeeInFlight = inflight
          , oeeLocator = return [BlockHash (Hash256 (BS.replicate 32 0))] }
        addAll pm n0 = do
          conns <- mapM (\n -> do
                           (pc, closeRemote) <- mkConn (addrN n) (now0 - 1000)
                           atomically $ modifyTVar' (pmPeers pm) (Map.insert (addrN n) pc)
                           -- everyone announces recently, except peer 3
                           noteBlockAnnouncementAt pm (addrN n) (if n == 3 then 10 else 5000 + fromIntegral n) (Just 900)
                           return (n, pc, closeRemote)) [1 .. n0]
          return conns

    it "disconnects the extra outbound peer that stopped announcing blocks and clears the retry flag" $
      withPm "evict" $ \pm -> do
        conns <- addAll pm 9
        requestExtraOutbound pm True
        evicted <- runOutboundEviction pm (env (\_ -> return 0)) now0
        sts <- mapM (\(n, pc, _) -> (,) n <$> stateOf pc) conns
        flag <- extraOutboundRequested pm
        mapM_ (\(_, _, c) -> c) conns
        evicted `shouldBe` [addrN 3]
        [n | (n, st) <- sts, st /= PeerConnected] `shouldBe` [3]
        flag `shouldBe` False

    it "a peer that delivers our new block counts as having announced it (Core ProcessBlock)" $
      withPm "blockrecv" $ \pm -> do
        conns <- addAll pm 9
        -- peer 3 announced longest ago, but just delivered a block to us
        noteBlockReceived pm (addrN 3)
        evicted <- runOutboundEviction pm (env (\_ -> return 0)) now0
        mapM_ (\(_, _, c) -> c) conns
        evicted `shouldBe` [addrN 1]

    it "leaves the stalled peer alone while we wait on a block from it" $
      withPm "inflight" $ \pm -> do
        conns <- addAll pm 9
        evicted <- runOutboundEviction pm (env (\a -> return (if a == addrN 3 then 1 else 0))) now0
        mapM_ (\(_, _, c) -> c) conns
        evicted `shouldBe` []

    it "drops an outbound peer that never reaches our tip's work (ConsiderEviction)" $
      withPm "chainsync" $ \pm -> do
        (good, cg) <- mkConn (addrN 1) (now0 - 1000)
        (slow, cs) <- mkConn (addrN 2) (now0 - 1000)
        atomically $ modifyTVar' (pmPeers pm) (Map.insert (addrN 1) good . Map.insert (addrN 2) slow)
        noteBlockAnnouncementAt pm (addrN 1) now0 (Just 1000)
        noteBestKnownWork pm (addrN 2) 500
        let e = env (\_ -> return 0)
        r0 <- runOutboundEviction pm e now0
        r1 <- runOutboundEviction pm e (now0 + chainSyncTimeoutSecs + 1)
        st1 <- stateOf slow
        r2 <- runOutboundEviction pm e (now0 + chainSyncTimeoutSecs + 2 + headersResponseTimeSecs)
        st2 <- stateOf slow
        stGood <- stateOf good
        cg >> cs
        (r0, r1, r2) `shouldBe` ([], [], [addrN 2])
        (st1, st2, stGood) `shouldBe` (PeerConnected, PeerDisconnected, PeerConnected)

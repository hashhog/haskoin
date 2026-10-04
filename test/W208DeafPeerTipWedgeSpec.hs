{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Tip wedge at mainnet height 969,866 (2026-10-04, deployed 15feda9).
--
-- haskoin stopped at 969,866 for 45+ min with 37 peers while Core went to
-- 969,873. OBSERVED in restart.log: the getheaders backstop (every ~2 min)
-- and the feeler (every ~2-3 min) both stopped near 969,864, and the one
-- backstop line printed afterwards came out at SHUTDOWN, still "from height
-- 969864" - a send that had been parked for ~50 min. The number of peers
-- whose header announcements we processed fell block by block (9, 9, 9, 9,
-- 7, 9, 3, 2, then 0). A dead inbound (159.195.111.12:4739) stayed in the
-- peer table for the whole wedge because the reaper is 'peerManagerLoop'.
--
-- Root cause: 'sendMessage' could block forever. A peer that stops reading
-- (TCP zero window) parks 'sendAll' with 'pcSendLock' held, and every
-- thread that then sends to that peer parks too - including the peer that
-- delivered a block (its recv thread runs 'announceTip' to all peers), so
-- that peer's next announcement is never read. Core never waits on a
-- socket: PushMessage queues, SocketSendData uses MSG_DONTWAIT (net.cpp
-- 1602), and InactivityCheck drops a peer whose sends stall (net.cpp 2013,
-- "socket sending timeout").
--
-- Reproduced end to end on regtest (scratch, repro_tip_wedge.py): a
-- black-hole inbound asks for ~12 MB and never reads; Core mines 4 blocks;
-- 15feda9 connects exactly ONE and stops (WEDGED after 300 s), with the
-- same shutdown-time backstop line as mainnet.
--
-- Control: cabal run haskoin-test --enable-tests -- -m deaf-peer
module W208DeafPeerTipWedgeSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, newMVar, putMVar, takeMVar, tryTakeMVar)
import Control.Concurrent.STM (atomically, modifyTVar', newTVarIO, newTBQueueIO, readTVarIO)
import Control.Exception (IOException, bracket, finally, throwIO, try)
import Control.Monad (void)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Int (Int64)
import Data.List (isInfixOf)
import Data.Maybe (isJust)
import qualified Data.Map.Strict as Map
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket
  ( Family (AF_UNIX), Socket, SockAddr (..), SocketType (Stream)
  , close, socketPair, tupleToHostAddress )
import System.Directory (createDirectoryIfMissing, removeDirectoryRecursive)
import System.Timeout (timeout)
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network
  ( Inv (..)
  , InvType (..)
  , InvVector (..)
  , Message (..)
  , PeerConnection (..)
  , PeerInfo (..)
  , PeerManager (..)
  , PeerManagerConfig (..)
  , PeerState (..)
  , Ping (..)
  , addrRelayCandidates
  , defaultPeerManagerConfig
  , enqueueBackgroundSend
  , formatStaleTipLog
  , sendAllWithStallTimeout
  , sendMessage
  , sendStallTimeoutMicros
  , setSendStallTimeoutMicros
  , staleCheckIntervalSecs
  , startPeerManager
  , stopPeerManager
  , tipMayBeStale
  )
import Haskoin.Types (Hash256 (..))

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

addrDeaf, addrDead, addrLive :: SockAddr
addrDeaf = SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 1))
addrDead = SockAddrInet 4739 (tupleToHostAddress (159, 195, 111, 12))
addrLive = SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 3))

mkInfo :: SockAddr -> PeerState -> Int64 -> PeerInfo
mkInfo a st lastSeen = PeerInfo
  { piAddress             = a
  , piVersion             = Nothing
  , piState               = st
  , piServices            = 0
  , piStartHeight         = 0
  , piRelay               = True
  , piLastSeen            = lastSeen
  , piLastPing            = Nothing
  , piPingLatency         = Nothing
  , piBanScore            = 0
  , piBytesSent           = 0
  , piBytesRecv           = 0
  , piMsgsSent            = 0
  , piMsgsRecv            = 0
  , piConnectedAt         = 0
  , piTimeOffset          = 0
  , piInbound             = True
  , piWantsAddrV2         = False
  , piWantsHeaders        = False
  , piFeeFilterReceived   = 0
  , piFeeFilterSent       = 0
  , piNextFeeFilterSend   = 0
  , piBlockOnly           = False
  , piUnconnectingHeaders = 0
  , piNoBan               = False
  , piIsManual            = False
  , piIsLocal             = False
  , piWtxidRelay          = False
  , piProvidesCmpct       = False
  , piCmpctHBFrom         = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | Our end of a connection whose remote end is OPEN but never reads -
-- the live shape (a peer at TCP zero window), not a hung-up one. The
-- remote socket is returned so the test can close it afterwards.
mkDeafConn :: SockAddr -> PeerState -> Int64 -> IO (PeerConnection, Socket)
mkDeafConn a st lastSeen = do
  (ours, theirs) <- socketPair AF_UNIX Stream 0
  infoVar <- newTVarIO (mkInfo a st lastSeen)
  sendLock <- newMVar ()
  recvQ <- newTBQueueIO 10
  bufRef <- newIORef BS.empty
  v2Ref <- newIORef Nothing
  fbRef <- newIORef Nothing
  return ( PeerConnection
             { pcSocket      = ours
             , pcInfo        = infoVar
             , pcSendLock    = sendLock
             , pcRecvQueue   = recvQ
             , pcSendThread  = Nothing
             , pcRecvThread  = Nothing
             , pcNetwork     = regtest
             , pcReadBuffer  = bufRef
             , pcV2Transport = v2Ref
             , pcBlockFirstByteAt = fbRef
             }
         , theirs )

-- | ~1.8 MB on the wire: far more than an AF_UNIX socket buffers, so a
-- peer that does not read makes the write wait.
bigInv :: Message
bigInv = MInv (Inv (replicate 50000
  (InvVector InvBlock (Hash256 (BS.replicate 32 7)))))

nowSecs :: IO Int64
nowSecs = round <$> getPOSIXTime

withBudget :: Int -> IO a -> IO a
withBudget us act =
  (setSendStallTimeoutMicros us >> act)
    `finally` setSendStallTimeoutMicros sendStallTimeoutMicros

withTmpDir :: String -> (FilePath -> IO a) -> IO a
withTmpDir tag = bracket
  (do let d = "dist-test-tmp/w208-" ++ tag
      createDirectoryIfMissing True d
      return d)
  (\d -> removeDirectoryRecursive d `catchIO` (\_ -> return ()))
  where catchIO :: IO a -> (IOException -> IO a) -> IO a
        catchIO a h = do r <- try a; either h return r

waitUntil :: Int -> IO Bool -> IO Bool
waitUntil secs cond = go (secs * 10)
  where
    go 0 = cond
    go n = do
      ok <- cond
      if ok then return True else threadDelay 100000 >> go (n - 1)

srcFile :: FilePath -> IO String
srcFile = readFile

bindingFrom :: String -> String -> String -> String
bindingFrom src start stop =
  let ls = dropWhile (not . (start `isInfixOf`)) (lines src)
   in unlines (takeWhile (not . (stop `isInfixOf`)) (drop 1 ls))

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "deaf-peer" $ do

  describe "deaf-peer: a write that makes no progress is bounded" $ do

    it "sendMessage to a peer that stopped reading fails within the budget and disconnects it" $ do
      (pc, theirs) <- mkDeafConn addrDeaf PeerConnected 0
      r <- withBudget 1000000 $
             timeout (20 * 1000000) (try (sendMessage pc bigInv))
      close theirs
      case r of
        Nothing -> expectationFailure
          "sendMessage still blocked after 20 s on a peer that does not read (pre-fix: forever)"
        Just (Right ()) -> expectationFailure "1.8 MB went into a socket nobody reads?"
        Just (Left (e :: IOException)) ->
          show e `shouldSatisfy` ("no progress" `isInfixOf`)
      st <- piState <$> readTVarIO (pcInfo pc)
      st `shouldBe` PeerDisconnected

    it "a second sender queued behind the parked one is released too (pcSendLock)" $ do
      (pc, theirs) <- mkDeafConn addrDeaf PeerConnected 0
      done <- newEmptyMVar
      withBudget 1000000 $ do
        _ <- forkIO $ void (try (sendMessage pc bigInv) :: IO (Either IOException ()))
        threadDelay 100000
        _ <- forkIO $ do
          r <- try (sendMessage pc (MPing (Ping 1))) :: IO (Either IOException ())
          putMVar done r
        r <- timeout (20 * 1000000) (takeMVar done)
        close theirs
        -- Pre-fix: the first sender never returns, so neither does this one.
        r `shouldSatisfy` isJust

    it "progress resets the clock: a slow reader is not cut off" $ do
      calls <- newIORef (0 :: Int)
      let slow b = do
            threadDelay 300000          -- each write: 0.3 s, 1 byte
            modifyIORef' calls (+ 1)
            return (min 1 (BS.length b))
      sendAllWithStallTimeout 500000 slow (BS.replicate 5 0)
      readIORef calls `shouldReturn` 5

    it "no progress at all throws after the budget" $ do
      let stuck _ = threadDelay maxBound >> return 0
      r <- timeout (5 * 1000000) (try (sendAllWithStallTimeout 200000 stuck "x"))
      case r of
        Just (Left (_ :: IOException)) -> return ()
        _ -> expectationFailure "stalled write did not fail within 5 s"

  describe "deaf-peer: the peer manager loop is not held by one peer" $ do

    it "a dead entry is reaped while a deaf peer's socket is parked (ping off-loop)" $
      withTmpDir "reap" $ \dir -> withBudget (600 * 1000000) $ do
        -- Budget 600 s: this proves the LOOP does not wait on the peer,
        -- independently of the write timeout.
        let cfg = defaultPeerManagerConfig
                    { pmcDataDir = dir, pmcDnsSeed = False, pmcPingInterval = 1 }
        bracket (startPeerManager regtest cfg (\_ _ -> return ())) stopPeerManager $ \pm -> do
          now <- nowSecs
          (deaf, theirs) <- mkDeafConn addrDeaf PeerConnected (now - 5)
          -- Park a write on the deaf peer (holds pcSendLock).
          _ <- forkIO $ void (try (sendMessage deaf bigInv) :: IO (Either IOException ()))
          threadDelay 200000
          atomically $ modifyTVar' (pmPeers pm) (Map.insert addrDeaf deaf)
          -- Let the loop reach the deaf peer's ping (ticks every 10 s).
          threadDelay (12 * 1000000)
          (dead, theirsDead) <- mkDeafConn addrDead PeerDisconnected now
          atomically $ modifyTVar' (pmPeers pm) (Map.insert addrDead dead)
          reaped <- waitUntil 25 (not . Map.member addrDead <$> readTVarIO (pmPeers pm))
          close theirs
          close theirsDead
          reaped `shouldBe` True

  describe "deaf-peer: fan-out never runs on a peer's receive thread" $ do

    it "enqueueBackgroundSend returns at once even when the send would park" $
      withTmpDir "bg" $ \dir -> do
        let cfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
        bracket (startPeerManager regtest cfg (\_ _ -> return ())) stopPeerManager $ \pm -> do
          gate <- newEmptyMVar
          ran <- newEmptyMVar
          t0 <- getPOSIXTime
          enqueueBackgroundSend pm (takeMVar gate)           -- parks the worker
          enqueueBackgroundSend pm (throwIO (userError "x")) -- must not kill it
          enqueueBackgroundSend pm (putMVar ran ())
          t1 <- getPOSIXTime
          (t1 - t0) `shouldSatisfy` (< 0.05)
          r0 <- tryTakeMVar ran
          r0 `shouldBe` Nothing
          putMVar gate ()
          r <- timeout (5 * 1000000) (takeMVar ran)
          r `shouldBe` Just ()

    it "announceTip and tx relay are queued, not sent inline (app/Main.hs)" $ do
      src <- srcFile "app/Main.hs"
      src `shouldSatisfy` ("enqueueBackgroundSend pm (announceTip pm (blockHeader block) bh)" `isInfixOf`)
      let txArm = bindingFrom src "  MTx tx -> do" "BUG-1 FIX (W114)"
      txArm `shouldSatisfy` ("enqueueBackgroundSend pm $" `isInfixOf`)

    it "peerManagerLoop forks its ping (src/Haskoin/Network.hs)" $ do
      src <- srcFile "src/Haskoin/Network.hs"
      let loopSrc = bindingFrom src "peerManagerLoop pm = forever" "-- | Try to connect to a peer address"
      loopSrc `shouldSatisfy` ("forkIO $\n          sendMessage pc (MPing (Ping nonce))" `isInfixOf`)

  describe "deaf-peer: addr relay only to connected peers (Core RelayAddress)" $ do

    it "drops the source, disconnected and block-relay-only peers" $ do
      let src = addrLive
          ps = [ (addrDead, mkInfo addrDead PeerDisconnected 0)
               , (addrDeaf, mkInfo addrDeaf PeerConnected 0)
               , (addrLive, mkInfo addrLive PeerConnected 0)
               , (SockAddrInet 1 0, (mkInfo (SockAddrInet 1 0) PeerConnected 0) { piBlockOnly = True })
               ]
      addrRelayCandidates src ps `shouldBe` [addrDeaf]

  describe "deaf-peer: stale tip (Core TipMayBeStale / CheckForStaleTipAndEvictPeers)" $ do

    it "stale after 3 target spacings with nothing in flight" $ do
      tipMayBeStale 10000 (10000 - 1801) 600 False `shouldBe` True
      tipMayBeStale 10000 (10000 - 1799) 600 False `shouldBe` False
      tipMayBeStale 10000 (10000 - 5000) 600 True  `shouldBe` False

    it "checks every 10 minutes and logs Core's line" $ do
      staleCheckIntervalSecs `shouldBe` 600
      formatStaleTipLog 2700 `shouldBe`
        "Potential stale tip detected, will try using extra outbound peer (last tip update: 2700 seconds ago)"

    it "the stale-tip flag widens the full-relay target by one (peerManagerLoop)" $ do
      src <- srcFile "src/Haskoin/Network.hs"
      src `shouldSatisfy` ("+ (if tryNewOutbound then 1 else 0)" `isInfixOf`)
      main <- srcFile "app/Main.hs"
      main `shouldSatisfy` ("forkIO $ staleTipWatcher pm' hc db net linearInflightRef" `isInfixOf`)

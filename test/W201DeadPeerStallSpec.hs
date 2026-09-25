{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Dead-peer / killed-drain stall at mainnet height 911,896.
--
-- Live 2026-09-24 (6ef3b2e, 12 h at 911,896, 9-10 peers, headers at tip):
--
--   (1) 68.1.224.37 logged 125 @requestFromPeer ... state=PeerConnected
--       FAILED: ... resource vanished (Broken pipe)@. Only the recv loop
--       ever moved a peer out of 'PeerConnected', and that peer's recv
--       thread was busy inside the MBlock handler, so a socket that
--       could no longer be written stayed selectable. Core
--       @CConnman::SocketSendData@ (net.cpp) calls
--       @CloseSocketDisconnect@ on a send error, and @FinalizeNode@
--       (net_processing.cpp) drops its @vBlocksInFlight@ so the blocks
--       are requested elsewhere.
--
--   (2) That busy recv thread was running the stored-body drain — a
--       recursive MBlock call at the end of the handler — through
--       911890..911896 at 1-4 min per connect. The 20-min inactivity
--       check killThread'd it while it was validating 911897 (its last
--       failing send is 3 min after UpdateTip 911896). 911897 was
--       already in the kicker's have-body set, so the planner never
--       requested it, and nothing re-ran the drain: 3,589 consecutive
--       @next-needed height=911897 fate=not-requested@ and not one
--       further getdata window. Core @ActivateBestChain@ is re-run by
--       every @ProcessNewBlock@ and connects every block that already
--       has data; it is not owned by any peer.
--
-- Control: cabal run haskoin-test --enable-tests -- -m dead-peer-stall
module W201DeadPeerStallSpec (spec) where

import Control.Concurrent (forkIO, killThread, threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, newMVar, putMVar, takeMVar)
import Control.Concurrent.STM (atomically, modifyTVar', newTVarIO, newTBQueueIO, readTVarIO)
import Control.Exception (IOException, SomeException, try)
import qualified Data.ByteString as BS
import Data.IORef
import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Int (Int64)
import Data.Word (Word32)
import Network.Socket
  ( SockAddr (..), Family (AF_UNIX), SocketType (Stream)
  , close, socketPair, tupleToHostAddress )
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network
  ( ForkGetDataPeer (..)
  , Message (..)
  , PeerConnection (..)
  , PeerInfo (..)
  , PeerManager (..)
  , PeerState (..)
  , Ping (..)
  , StoredDrainStop (..)
  , defaultPeerManagerConfig
  , drainStoredBodies
  , dropPeerInflight
  , formatStoredDrain
  , neededLinearHashes
  , planLinearGetData
  , projectStableInflight
  , requestFromPeerChecked
  , sendMessage
  , startPeerManager
  , stopPeerManager
  )
import Haskoin.Types (BlockHash (..), Hash256 (..))

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

addrA, addrB :: SockAddr
addrA = SockAddrInet 8333 (tupleToHostAddress (68, 1, 224, 37))
addrB = SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 2))

mkInfo :: SockAddr -> PeerInfo
mkInfo a = PeerInfo
  { piAddress             = a
  , piVersion             = Nothing
  , piState               = PeerConnected
  , piServices            = 0
  , piStartHeight         = 0
  , piRelay               = True
  , piLastSeen            = 0
  , piLastPing            = Nothing
  , piPingLatency         = Nothing
  , piBanScore            = 0
  , piBytesSent           = 0
  , piBytesRecv           = 0
  , piMsgsSent            = 0
  , piMsgsRecv            = 0
  , piConnectedAt         = 0
  , piTimeOffset          = 0
  , piInbound             = False
  , piWantsAddrV2         = False
  , piWantsHeaders        = False
  , piFeeFilterReceived   = 0
  , piFeeFilterSent       = 0
  , piNextFeeFilterSend   = 0
  , piBlockOnly           = True
  , piUnconnectingHeaders = 0
  , piNoBan               = False
  , piIsManual            = False
  , piIsLocal             = False
  , piWtxidRelay          = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | A PeerConnection whose remote end has already hung up: every write
-- fails with EPIPE ("resource vanished (Broken pipe)"), exactly the live
-- 68.1.224.37 shape. The recv thread is absent, standing in for a recv
-- thread that is busy inside the MBlock handler and not reading.
mkDeadConn :: SockAddr -> IO PeerConnection
mkDeadConn a = do
  (ours, theirs) <- socketPair AF_UNIX Stream 0
  close theirs
  infoVar <- newTVarIO (mkInfo a)
  sendLock <- newMVar ()
  recvQ <- newTBQueueIO 10
  bufRef <- newIORef BS.empty
  v2Ref <- newIORef Nothing
  fbRef <- newIORef Nothing
  return PeerConnection
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

bh :: Int -> BlockHash
bh i = BlockHash (Hash256 (BS.pack (fromIntegral i : replicate 31 0)))

-- | Mirror of app/Main.hs getConnectedPeerList (not importable): the set
-- the kicker plans getdata over.
connectedAddrs :: PeerManager -> IO [SockAddr]
connectedAddrs pm = do
  peers <- readTVarIO (pmPeers pm)
  fmap concat $ mapM (\(a, pc) -> do
      st <- piState <$> readTVarIO (pcInfo pc)
      return [a | st == PeerConnected]) (Map.toList peers)

mainHs :: IO String
mainHs = readFile "app/Main.hs"

bindingFrom :: String -> String -> String -> String
bindingFrom src start stop =
  let ls = dropWhile (not . (start `isInfixOf`)) (lines src)
   in unlines (takeWhile (not . (stop `isInfixOf`)) (drop 1 ls))

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "dead-peer-stall" $ do

  describe "dead-peer-stall: a failed send leaves the connected set" $ do

    it "sendMessage on a hung-up socket throws AND moves the peer out of PeerConnected" $ do
      pc <- mkDeadConn addrA
      r <- try (sendMessage pc (MPing (Ping 1)))
      case r of
        Left (_ :: IOException) -> return ()
        Right () -> expectationFailure "send to a hung-up socket did not fail"
      st <- piState <$> readTVarIO (pcInfo pc)
      st `shouldBe` PeerDisconnected

    it "requestFromPeerChecked (the getdata/addrv2 path) reports False and the peer is no longer selectable" $ do
      pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
      dead <- mkDeadConn addrA
      atomically $ modifyTVar' (pmPeers pm) (Map.insert addrA dead)
      beforeA <- connectedAddrs pm
      beforeA `shouldBe` [addrA]
      ok <- requestFromPeerChecked pm addrA (MPing (Ping 2))
      ok `shouldBe` False
      afterA <- connectedAddrs pm
      -- Live: 16 further getdata to 176.106.242.172 and 125 sends to
      -- 68.1.224.37 all failed while it stayed state=PeerConnected.
      afterA `shouldBe` []
      stopPeerManager pm

    it "a banned peer keeps PeerBanned (a send failure does not launder the ban)" $ do
      pc <- mkDeadConn addrA
      atomically $ modifyTVar' (pcInfo pc) (\i -> i { piState = PeerBanned })
      _ <- try (sendMessage pc (MPing (Ping 3))) :: IO (Either SomeException ())
      st <- piState <$> readTVarIO (pcInfo pc)
      st `shouldBe` PeerBanned

  describe "dead-peer-stall: its in-flight blocks are reassigned" $ do

    it "dropPeerInflight releases every block charged to the failed peer, and only those" $ do
      let inf = Map.fromList
            [ (bh 1, (0, 911897, 100)), (bh 2, (0, 911898, 100))
            , (bh 3, (1, 911899, 100)) ]
      dropPeerInflight 0 inf `shouldBe` Map.fromList [(bh 3, (1, 911899, 100))]

    it "after it leaves the connected set, its inflight comes back orphaned and is planned onto a live peer" $ do
      -- Stored under stable keys (Main.hs linearInflightRef).
      let stored = Map.fromList
            [ (bh 1, (addrA, 911897 :: Word32, 100 :: Int64))
            , (bh 2, (addrA, 911898, 100)) ]
          -- This tick's connected list no longer contains addrA.
          keyToId = Map.fromList [(addrB, 0 :: Int)]
          (view, orphaned) = projectStableInflight keyToId stored
      Map.null view `shouldBe` True
      Set.fromList orphaned `shouldBe` Set.fromList [bh 1, bh 2]
      let heightMap = Map.fromList [(911897, bh 1), (911898, bh 2)]
          needed = neededLinearHashes 911897 911898 heightMap view Set.empty
          plan = planLinearGetData [ForkGetDataPeer 0 0x9] needed 968000 0 Set.empty Map.empty
      plan `shouldBe` [(0, [bh 1, bh 2])]

    it "requestBlockRange does not charge a failed send, and drops the peer's earlier inflight" $ do
      src <- mainHs
      let body = bindingFrom src "requestBlockRange pm hc fromHeight" "fillLinearPipeline pm hc db"
      body `shouldSatisfy` ("dropPeerInflight idx acc" `isInfixOf`)
      body `shouldSatisfy` ("| sendOk    = Map.union added acc" `isInfixOf`)

  describe "dead-peer-stall: the stored-body drain survives a killed drainer" $ do

    it "precondition of the stall: a have-body next-needed height is never re-requested" $ do
      let heightMap = Map.fromList [(911897, bh 7)]
      neededLinearHashes 911897 911897 heightMap (Map.empty :: Map.Map BlockHash ()) (Set.singleton 911897)
        `shouldBe` []

    it "connects stored bodies in height order and stops at the first missing one" $ do
      busy <- newIORef False
      next <- newIORef (911897 :: Word32)
      let disk = Set.fromList [911897, 911898, 911899]
          load h = return (if Set.member h disk then Just h else Nothing)
          connect h = modifyIORef' next (\n -> if h == n then n + 1 else n)
      r <- drainStoredBodies busy (readIORef next) load connect
      r `shouldBe` (3, StoredDrainNoBody 911900)
      readIORef next >>= (`shouldBe` 911900)
      readIORef busy >>= (`shouldBe` False)

    it "a drainer killed mid-connect releases ownership; the next trigger connects 911897" $ do
      busy <- newIORef False
      next <- newIORef (911897 :: Word32)
      entered <- newEmptyMVar
      never <- newEmptyMVar :: IO (MVar ())
      let load h = return (if h <= 911898 then Just h else Nothing)
          -- First drainer: stuck validating 911897 until killed (the
          -- 20-min inactivity killThread on the delivering peer).
          stuck _ = putMVar entered () >> takeMVar never
      tid <- forkIO (() <$ drainStoredBodies busy (readIORef next) load stuck)
      takeMVar entered
      -- While it runs, a second trigger must not start a second drainer.
      r0 <- drainStoredBodies busy (readIORef next) load (\_ -> return ())
      r0 `shouldBe` (0, StoredDrainBusy)
      killThread tid
      threadDelay 20000
      readIORef busy >>= (`shouldBe` False)
      -- The kicker's re-trigger (next-needed in haveBody).
      let connect h = modifyIORef' next (\n -> if h == n then n + 1 else n)
      r <- drainStoredBodies busy (readIORef next) load connect
      r `shouldBe` (2, StoredDrainNoBody 911899)
      readIORef next >>= (`shouldBe` 911899)

    it "a stored body that does not connect is reported so the node evicts it from haveBody" $ do
      busy <- newIORef False
      next <- newIORef (911897 :: Word32)
      r <- drainStoredBodies busy (readIORef next) (return . Just) (\_ -> return ())
      r `shouldBe` (0, StoredDrainNotAdvanced 911897)
      formatStoredDrain 0 (snd r) (Just (911897, "not-connected"))
        `shouldBe` "Stored-body drain: connected=0 stop=not-connected height=911897 evicted=911897 reason=not-connected"

    it "a height another thread connected while its body loaded is not handed to the connector" $ do
      busy <- newIORef False
      next <- newIORef (911897 :: Word32)
      calls <- newIORef ([] :: [Word32])
      let load h = do
            -- The in-order MBlock path connects 911897 meanwhile.
            modifyIORef' next (\n -> if h == 911897 && n == 911897 then 911898 else n)
            return (if h <= 911898 then Just h else Nothing)
          connect h = modifyIORef' calls (h :) >> modifyIORef' next (\n -> if h == n then n + 1 else n)
      r <- drainStoredBodies busy (readIORef next) load connect
      r `shouldBe` (1, StoredDrainNoBody 911899)
      readIORef calls >>= (`shouldBe` [911898])

    it "the node wires it: no recursive drain on the peer thread; the kicker re-runs it on a have-body next-needed" $ do
      src <- mainHs
      src `shouldNotSatisfy` ("(MBlock blkDrain)" `isInfixOf`)
      src `shouldSatisfy` ("join (readIORef storedDrainRef)" `isInfixOf`)
      let kick = bindingFrom src "kicker rot lastConn lastReqTime lastProgAt = do" "in kicker 0 maxBound 0 0"
      kick `shouldSatisfy` ("Set.member nextBlock haveBodyK" `isInfixOf`)
      kick `shouldSatisfy` ("join (readIORef storedDrainRef)" `isInfixOf`)

    it "the connect commit and cursor advance are masked against a peer-thread kill" $ do
      src <- mainHs
      src `shouldSatisfy` ("Right () -> uninterruptibleMask_ $ do" `isInfixOf`)

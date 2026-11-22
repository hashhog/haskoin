{-# LANGUAGE ScopedTypeVariables #-}

-- | cffix-haskoin-eviction-protections: the per-peer facts the inbound
-- eviction protections read are actually recorded, and the netgroup
-- protection is keyed.
--
-- Reference: bitcoin-core/src/net_processing.cpp
--   ProcessMessage PONG: nonce == nPingNonceSent -> ping_time = now -
--     m_ping_start; PingReceived -> m_min_ping_time = min(...);
--     a zero nonce cancels; any other nonce is ignored.
--   ProcessMessage TX (accepted): pfrom.m_last_tx_time = GetTime().
--   ProcessBlock (new block): pfrom.m_last_block_time = GetTime().
-- bitcoin-core/src/net.cpp CalculateKeyedNetGroup:
--   GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(netgroup)
--   with a per-node random seed.
module EvictionTrackingSpec (spec) where

import Control.Concurrent.MVar (newMVar)
import Control.Concurrent.STM (atomically, modifyTVar', newTVarIO, newTBQueueIO, readTVarIO)
import Control.Exception (bracket, finally)
import Control.Monad (forM, forM_)
import qualified Data.ByteString as BS
import Data.IORef (newIORef)
import Data.Int (Int64)
import Data.List (nub)
import qualified Data.Map.Strict as Map
import Data.Word (Word64)
import Network.Socket
  ( Family (AF_UNIX), SockAddr (..), SocketType (Stream), close, socketPair
  , tupleToHostAddress )
import System.Directory (createDirectoryIfMissing, removeDirectoryRecursive)
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network

import EvictionProtectionSpec (scenario, isAttacker)

withPm :: String -> (PeerManager -> IO a) -> IO a
withPm tag act = bracket
  (do let d = "dist-test-tmp/eviction-protection-" ++ tag
      createDirectoryIfMissing True d
      pm <- startPeerManager regtest
              defaultPeerManagerConfig { pmcDataDir = d, pmcDnsSeed = False }
              (\_ _ -> return ())
      return (d, pm))
  (\(d, _) -> removeDirectoryRecursive d)
  (\(_, pm) -> act pm `finally` stopPeerManager pm)

-- | Register an inbound peer at @a@ in the manager's peer map.
addInbound :: PeerManager -> SockAddr -> Int64 -> IO (IO ())
addInbound pm a connectedAt = do
  (ours, theirs) <- socketPair AF_UNIX Stream 0
  info <- newTVarIO PeerInfo
    { piAddress = a, piVersion = Nothing, piState = PeerConnected, piServices = 0x9
    , piStartHeight = 0, piRelay = True, piLastSeen = 9999999999, piLastPing = Nothing
    , piPingLatency = Nothing, piBanScore = 0, piBytesSent = 0, piBytesRecv = 0
    , piMsgsSent = 0, piMsgsRecv = 0, piConnectedAt = connectedAt, piTimeOffset = 0
    , piInbound = True, piWantsAddrV2 = False, piWantsHeaders = False
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
  let pc = PeerConnection
             { pcSocket = ours, pcInfo = info, pcSendLock = lock, pcRecvQueue = q
             , pcSendThread = Nothing, pcRecvThread = Nothing, pcNetwork = regtest
             , pcReadBuffer = buf, pcV2Transport = v2, pcBlockFirstByteAt = fb }
  atomically $ modifyTVar' (pmPeers pm) (Map.insert a pc)
  return (close ours >> close theirs)

addrA :: SockAddr
addrA = SockAddrInet 50001 (tupleToHostAddress (200, 1, 0, 1))

pingOf :: PeerManager -> SockAddr -> IO (Maybe Double, Maybe Word64)
pingOf pm a = do
  peers <- readTVarIO (pmPeers pm)
  case Map.lookup a peers of
    Nothing -> return (Nothing, Nothing)
    Just pc -> do
      i <- readTVarIO (pcInfo pc)
      return (piPingLatency i, piLastPing i)

candidateOf :: PeerManager -> SockAddr -> IO (Maybe EvictionCandidate)
candidateOf pm a = do
  cs <- buildEvictionCandidates pm
  return $ case filter ((== a) . ecAddress) cs of
    (c:_) -> Just c
    []    -> Nothing

spec :: Spec
spec = describe "inbound eviction inputs (Core PONG / m_last_tx_time / m_last_block_time / keyed netgroup)" $ do

  it "a matching pong records the round trip and keeps the minimum" $
    withPm "pong" $ \pm -> do
      cleanup <- addInbound pm addrA 1000
      flip finally cleanup $ do
        pingOf pm addrA `shouldReturn` (Nothing, Nothing)
        notePingSent pm addrA 42 100.0
        pingOf pm addrA `shouldReturn` (Nothing, Just 42)
        recordPong pm addrA 42 100.25
        pingOf pm addrA `shouldReturn` (Just 0.25, Nothing)
        -- a slower round trip does not raise the minimum
        notePingSent pm addrA 43 200.0
        recordPong pm addrA 43 200.5
        pingOf pm addrA `shouldReturn` (Just 0.25, Nothing)
        -- a wrong nonce is ignored and the ping stays outstanding
        notePingSent pm addrA 44 300.0
        recordPong pm addrA 999 300.01
        pingOf pm addrA `shouldReturn` (Just 0.25, Just 44)
        recordPong pm addrA 44 300.125
        pingOf pm addrA `shouldReturn` (Just 0.125, Nothing)
        -- a zero nonce cancels the outstanding ping without a sample
        notePingSent pm addrA 45 400.0
        recordPong pm addrA 0 400.001
        pingOf pm addrA `shouldReturn` (Just 0.125, Nothing)
        -- an unsolicited pong changes nothing
        recordPong pm addrA 45 400.002
        pingOf pm addrA `shouldReturn` (Just 0.125, Nothing)
        fmap ecMinPingTime <$> candidateOf pm addrA `shouldReturn` Just (Just 0.125)

  it "an accepted tx and a connected block from the peer reach its eviction candidate" $
    withPm "txblock" $ \pm -> do
      cleanup <- addInbound pm addrA 1000
      flip finally cleanup $ do
        c0 <- candidateOf pm addrA
        fmap (\c -> (ecLastTxTime c, ecLastBlockTime c)) c0 `shouldBe` Just (0, 0)
        noteTxAcceptedAt pm addrA 123456
        noteBlockReceived pm addrA
        Just c1 <- candidateOf pm addrA
        ecLastTxTime c1 `shouldBe` 123456
        ecLastBlockTime c1 `shouldSatisfy` (> 0)

  it "each peer manager draws its own netgroup key" $
    withPm "key1" $ \pm1 -> withPm "key2" $ \pm2 ->
      pmNetGroupKey pm1 `shouldNotBe` pmNetGroupKey pm2

  it "which netgroups the netgroup step protects depends on the key, not on how low the /16 is" $ do
    -- 28 peers, one per /16.  Unkeyed, the 4 lowest
    -- /16s were always the protected ones.
    let cs = [ c | c <- scenario, isAttacker c ]
              ++ [ c | c <- scenario, not (isAttacker c) ]
        protectedFor k =
          let kept = map ecAddress (protectByNetGroupKeyed k 4 cs)
          in [ ecAddress c | c <- cs, ecAddress c `notElem` kept ]
        sets = [ protectedFor (SipHashKey i (i * 7919 + 1)) | i <- [1 .. 20] ]
    forM_ sets $ \s -> length s `shouldBe` 4
    length (nub sets) `shouldSatisfy` (> 1)
    -- some key leaves at least one of the 4 lowest /16s unprotected
    let lowest4 = map ecAddress (take 4 cs)
    any (\s -> any (`notElem` s) lowest4) sets `shouldBe` True

  it "the attacker scenario evicts an attacker under every key" $ do
    let victims = [ selectEvictionCandidateKeyed (SipHashKey i (i * 31 + 5)) scenario | i <- [1 .. 50] ]
    forM_ victims $ \v -> fmap isAttacker v `shouldBe` Just True

  it "end to end: peers that answered pings and relayed a tx or block are kept; the victim is an attacker" $
    withPm "e2e" $ \pm -> do
      cleanups <- forM scenario $ \c -> addInbound pm (ecAddress c) (ecConnectedAt c)
      flip finally (sequence_ cleanups) $ do
        -- Drive the recorders exactly as the message handlers do.
        forM_ (zip [1 :: Word64 ..] scenario) $ \(n, c) -> do
          let a = ecAddress c
          case ecMinPingTime c of
            Just rtt -> notePingSent pm a n 10.0 >> recordPong pm a n (10.0 + rtt)
            Nothing  -> return ()
          if ecLastTxTime c > 0 then noteTxAcceptedAt pm a (ecLastTxTime c) else return ()
          if ecLastBlockTime c > 0 then noteBlockReceived pm a else return ()
        cands <- buildEvictionCandidates pm
        let victim = selectEvictionCandidateKeyed (pmNetGroupKey pm) cands
        fmap (\v -> isAttacker v) victim `shouldBe` Just True
        -- and the node's own eviction entry point agrees
        Just evicted <- evictConnection pm
        evicted `shouldSatisfy` (\a -> a `elem` [ ecAddress c | c <- scenario, isAttacker c ])

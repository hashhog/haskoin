{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

-- | recvexact-linear-cost: receiving one v1 message whose payload arrives a
-- few bytes at a time must cost memory linear in the payload.
--
-- Core: the payload is appended into the message's vRecv as bytes arrive
-- (V1Transport::ReceivedBytes -> readData, bitcoin-core/src/net.cpp), so a
-- slow sender costs one copy of each byte.
--
-- On haskoin master 'recvExact' asked 'recv' for the whole remaining length
-- on every read (recv allocates that many bytes, then trims) and then
-- appended the new chunk to everything already buffered.  A peer that
-- trickles a 4,000,000-byte payload 100 bytes at a time, before the
-- handshake, made the node allocate and copy on the order of
-- payload^2 / chunk bytes (tens of GB) for one message.
--
-- The test runs 'receiveMessage' (the exported caller of 'recvExact') on one
-- end of a socket pair while a writer thread sends the header and then the
-- payload in 100-byte writes, and measures the reading thread's allocation
-- with the per-thread allocation counter against a budget linear in the
-- payload and in the number of reads ('linearBudget').
module Main (main) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, newMVar, putMVar, takeMVar)
import Control.Concurrent.STM (newTVarIO, newTBQueueIO)
import Control.Monad (forM_, when)
import qualified Data.ByteString as BS
import Data.IORef (newIORef)
import Data.Int (Int64)
import Data.Serialize (runPut, putWord32le)
import Network.Socket
  ( Family (AF_UNIX), SockAddr (..), SocketType (Stream), close, socketPair
  , tupleToHostAddress )
import Network.Socket.ByteString (sendAll)
import System.Mem (getAllocationCounter, setAllocationCounter)
import System.Timeout (timeout)
import Test.Hspec

import Haskoin.Consensus (Network (..), regtest)
import Haskoin.Crypto (doubleSHA256)
import Haskoin.Network
  ( Message (..), PeerConnection (..), PeerInfo (..), PeerState (..)
  , receiveMessage )
import Haskoin.Types (Hash256 (..))

mkInfo :: SockAddr -> PeerInfo
mkInfo a = PeerInfo
  { piAddress = a, piVersion = Nothing, piState = PeerConnected
  , piServices = 0, piStartHeight = 0, piRelay = True
  , piLastSeen = 0, piLastPing = Nothing, piPingLatency = Nothing
  , piBanScore = 0, piBytesSent = 0, piBytesRecv = 0, piMsgsSent = 0
  , piMsgsRecv = 0, piConnectedAt = 0, piTimeOffset = 0, piInbound = True
  , piWantsAddrV2 = False, piWantsHeaders = False, piFeeFilterReceived = 0
  , piFeeFilterSent = 0, piNextFeeFilterSend = 0, piBlockOnly = False
  , piUnconnectingHeaders = 0, piNoBan = False, piIsManual = False
  , piIsLocal = False, piWtxidRelay = False, piProvidesCmpct = False
  , piCmpctHBFrom = False, piGetaddrRecvd = False
  , piAddrTokenBucket = 1.0, piAddrTokenTimestamp = 0
  }

-- | A 24-byte v1 header: magic, 12-byte command, length, checksum.
v1Header :: BS.ByteString -> BS.ByteString -> BS.ByteString
v1Header cmd payload = BS.concat
  [ runPut (putWord32le (netMagic regtest))
  , cmd <> BS.replicate (12 - BS.length cmd) 0
  , runPut (putWord32le (fromIntegral (BS.length payload)))
  , BS.take 4 (getHash256 (doubleSHA256 payload))
  ]

-- | Send the header, then the payload in @chunk@-byte writes, yielding to
-- the reader between writes (a real trickle: one small segment per read).
-- Returns the reading thread's allocation in bytes and the result.
trickle :: Int -> Int -> IO (Int64, Either String Message)
trickle payloadLen chunk = do
  (ours, theirs) <- socketPair AF_UNIX Stream 0
  infoVar <- newTVarIO (mkInfo (SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 9))))
  sendLock <- newMVar ()
  recvQ <- newTBQueueIO 10
  bufRef <- newIORef BS.empty
  v2Ref <- newIORef Nothing
  fbRef <- newIORef Nothing
  let pc = PeerConnection
        { pcSocket = ours, pcInfo = infoVar, pcSendLock = sendLock
        , pcRecvQueue = recvQ, pcSendThread = Nothing, pcRecvThread = Nothing
        , pcNetwork = regtest, pcReadBuffer = bufRef, pcV2Transport = v2Ref
        , pcBlockFirstByteAt = fbRef }
      payload = BS.pack (take payloadLen (cycle [0 .. 250]))
  -- Force the payload and header before the measured region.
  let hdr = v1Header "trickle" payload
  when (BS.length hdr /= 24 || BS.length payload /= payloadLen) $ fail "fixture"
  done <- newEmptyMVar
  _ <- forkIO $ do
    sendAll theirs hdr
    forM_ [0, chunk .. payloadLen - 1] $ \off -> do
      sendAll theirs (BS.take chunk (BS.drop off payload))
      threadDelay 20
    putMVar done ()
  setAllocationCounter maxBound
  allocStart <- getAllocationCounter
  r <- receiveMessage pc
  allocEnd <- getAllocationCounter
  takeMVar done
  close theirs
  close ours
  return (allocStart - allocEnd, r)

-- | The linear budget: three copies of the payload (the received chunks, the
-- one final join, slack) plus 4 KiB for every write the peer made.  The
-- per-read term is the fixed cost of one socket read in GHC (waiting on the
-- fd through the IO manager, the idle 'timeout', the chunk's own header);
-- measured at ~2.5 KB a read, and paid on master too.  A 100-byte trickle
-- is 40,000 reads, so this term, not the payload, is most of the budget
-- there; what it rules out is the payload^2 / chunk term (~160 GB on
-- master for the trickle, ~84 MB for the bulk write).
linearBudget :: Int -> Int -> Int64
linearBudget payloadLen chunk =
  3 * fromIntegral payloadLen
    + 4096 * fromIntegral ((payloadLen + chunk - 1) `div` chunk)

main :: IO ()
main = hspec $
  describe "recvExact (v1 receive path)" $ do
    it "trickled_payload_linear_cost: a 4 MB payload sent 100 bytes at a time allocates under 3x the payload plus 4 KiB per read" $ do
      let payloadLen = 4_000_000
      m <- timeout 240_000_000 (trickle payloadLen 100)
      case m of
        Nothing -> expectationFailure
          "receiveMessage did not finish a 4 MB trickled payload within 240 s"
        Just (alloc, r) -> do
          r `shouldBe` Right (MUnknown "trickle")
          putStrLn ("      allocated " ++ show alloc ++ " bytes for a "
                    ++ show payloadLen ++ "-byte payload ("
                    ++ show (fromIntegral alloc / fromIntegral payloadLen :: Double)
                    ++ "x)")
          alloc `shouldSatisfy` (< linearBudget payloadLen 100)

    -- The same message sent in one write.  The kernel still hands it over
    -- in socket-buffer-sized pieces, and master asked recv for the whole
    -- remaining length on each of them, so this fails there too (~20x),
    -- just less dramatically.
    it "bulk_payload_linear_cost: the same payload sent in one write allocates under 3x the payload plus 4 KiB per read" $ do
      let payloadLen = 4_000_000
      (alloc, r) <- trickle payloadLen payloadLen
      r `shouldBe` Right (MUnknown "trickle")
      alloc `shouldSatisfy` (< linearBudget payloadLen payloadLen)

    -- Bytes past the message stay buffered for the next one, as before.
    it "two messages written back to back are both received intact" $ do
      (ours, theirs) <- socketPair AF_UNIX Stream 0
      infoVar <- newTVarIO (mkInfo (SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 9))))
      sendLock <- newMVar ()
      recvQ <- newTBQueueIO 10
      bufRef <- newIORef BS.empty
      v2Ref <- newIORef Nothing
      fbRef <- newIORef Nothing
      let pc = PeerConnection
            { pcSocket = ours, pcInfo = infoVar, pcSendLock = sendLock
            , pcRecvQueue = recvQ, pcSendThread = Nothing, pcRecvThread = Nothing
            , pcNetwork = regtest, pcReadBuffer = bufRef, pcV2Transport = v2Ref
            , pcBlockFirstByteAt = fbRef }
          p1 = BS.replicate 70_000 7
          p2 = BS.replicate 10 9
      sendAll theirs (v1Header "first" p1 <> p1 <> v1Header "second" p2 <> p2)
      r1 <- receiveMessage pc
      r2 <- receiveMessage pc
      r1 `shouldBe` Right (MUnknown "first")
      r2 `shouldBe` Right (MUnknown "second")
      close theirs
      r3 <- receiveMessage pc
      r3 `shouldBe` Left "Connection closed"
      close ours

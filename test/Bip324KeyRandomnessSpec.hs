{-# LANGUAGE ScopedTypeVariables #-}

-- | bip324-key-randomness: the BIP-324 ephemeral secret key, the ElligatorSwift
-- aux randomness and the garbage must come from a CSPRNG.
--
-- Core: the V2Transport constructor (bitcoin-core/src/net.cpp, V2Transport
-- ctor) passes GenerateRandomKey() and GetRandHash() to BIP324Cipher, and
-- GenerateRandomGarbage() draws the garbage from a FastRandomContext seeded
-- from the CSPRNG.  None of it is reproducible from process state.
--
-- On haskoin master v2InboundHandshake and v2OutboundHandshake built all
-- three from 'randomRIO', i.e. the process-global SplitMix 'StdGen' from
-- System.Random.  SplitMix is not a CSPRNG, and the same generator hands
-- full 64-bit outputs to every peer (version / ping / cmpctblock nonces), so
-- a peer could recover the generator state and from it our BIP-324 secret
-- key.  The visible symptom: reset the global StdGen to a fixed seed and the
-- handshake emits the same ElligatorSwift public key every time.
--
-- The test drives the exported handshakes on a socket pair, reads the
-- 64-byte ElligatorSwift public key each one puts on the wire, then closes
-- the peer end so the handshake returns.
module Main (main) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (newEmptyMVar, newMVar, putMVar, takeMVar)
import Control.Concurrent.STM (newTVarIO, newTBQueueIO)
import Control.Exception (SomeException, try)
import qualified Data.ByteString as BS
import Data.IORef (newIORef)
import Network.Socket
  ( Family (AF_UNIX), SockAddr (..), Socket, SocketType (Stream), close
  , socketPair, tupleToHostAddress )
import Network.Socket.ByteString (recv, sendAll)
import System.Random (getStdGen, mkStdGen, setStdGen)
import System.Timeout (timeout)
import Test.Hspec

import Haskoin.Consensus (regtest)
import Haskoin.Network
  ( PeerConnection (..), PeerInfo (..), PeerState (..)
  , v2InboundHandshake, v2OutboundHandshake )

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

mkConn :: Socket -> IO PeerConnection
mkConn sock = do
  infoVar <- newTVarIO (mkInfo (SockAddrInet 8333 (tupleToHostAddress (10, 0, 0, 9))))
  sendLock <- newMVar ()
  recvQ <- newTBQueueIO 10
  buf <- newIORef BS.empty
  v2 <- newIORef Nothing
  fb <- newIORef Nothing
  return PeerConnection
    { pcSocket = sock, pcInfo = infoVar, pcSendLock = sendLock
    , pcRecvQueue = recvQ, pcSendThread = Nothing, pcRecvThread = Nothing
    , pcNetwork = regtest, pcReadBuffer = buf, pcV2Transport = v2
    , pcBlockFirstByteAt = fb }

recvN :: Socket -> Int -> IO BS.ByteString
recvN sock n = go BS.empty
  where
    go acc
      | BS.length acc >= n = return (BS.take n acc)
      | otherwise = do
          chunk <- recv sock (n - BS.length acc)
          if BS.null chunk then return acc else go (acc <> chunk)

data Side = Outbound | Inbound deriving (Show, Eq)

-- | Run one handshake of the given side on a fresh socket pair and return
-- the 64-byte ElligatorSwift public key it sends.  For the inbound side we
-- first hand it a 64-byte peer key (any 64 bytes decode as ElligatorSwift).
emittedPubKey :: Side -> IO BS.ByteString
emittedPubKey side = do
  (ours, theirs) <- socketPair AF_UNIX Stream 0
  pc <- mkConn ours
  done <- newEmptyMVar
  let run = case side of
        Outbound -> () <$ v2OutboundHandshake pc regtest
        Inbound  -> () <$ v2InboundHandshake pc regtest
  _ <- forkIO $ do
    -- The handshake fails once we close the peer end; only the bytes it
    -- sent before that matter here.
    (_ :: Either SomeException ()) <- try run
    putMVar done ()
  if side == Inbound then sendAll theirs (BS.replicate 64 0x5a) else return ()
  pub <- recvN theirs 64
  close theirs
  _ <- timeout 10000000 (takeMVar done)
  close ours
  return pub

-- | Seed the global StdGen with 42, emit one public key, and report the key
-- plus whether the global StdGen was left untouched.
seededRun :: Side -> IO (BS.ByteString, Bool)
seededRun side = do
  setStdGen (mkStdGen 42)
  pub <- emittedPubKey side
  g <- getStdGen
  return (pub, show g == show (mkStdGen 42))

main :: IO ()
main = hspec $ describe "BIP-324 ephemeral key randomness (Core: GenerateRandomKey / GetRandHash)" $ do
  mapM_ sideSpec [Outbound, Inbound]
  where
    sideSpec side = do
      it (show side ++ " handshake emits a different ellswift pubkey after resetting the global StdGen to the same seed") $ do
        (pub1, _) <- seededRun side
        (pub2, _) <- seededRun side
        BS.length pub1 `shouldBe` 64
        BS.length pub2 `shouldBe` 64
        pub1 `shouldNotBe` pub2
      it (show side ++ " handshake key generation does not advance the global StdGen") $ do
        (pub, untouched) <- seededRun side
        BS.length pub `shouldBe` 64
        untouched `shouldBe` True

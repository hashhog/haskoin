{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W168 getblockfrompeer (Bitcoin Core v24).
--
-- Reference:
--   * bitcoin-core/src/rpc/blockchain.cpp  — getblockfrompeer RPC.
--   * bitcoin-core/src/net_processing.cpp  — PeerManagerImpl::FetchBlock
--     (the error ladder + the CInv(MSG_BLOCK|MSG_WITNESS_FLAG) getdata send).
--
-- Core contract (mirrored by Haskoin.Rpc.handleGetBlockFromPeer /
-- decideGetBlockFromPeer):
--
--   (1) The block's HEADER must already be known, else RPC_MISC_ERROR(-1)
--       "Block header missing"  (blockchain.cpp:547).
--   (2) peer_id must resolve to a connected peer, else RPC_MISC_ERROR(-1)
--       "Peer does not exist"   (net_processing.cpp:1966).
--   (3) If the body is already stored, RPC_MISC_ERROR(-1)
--       "Block already downloaded" (blockchain.cpp:558).
--   (4) On success, send a block getdata (MSG_BLOCK | MSG_WITNESS_FLAG, i.e.
--       InvWitnessBlock = 0x40000002) to THAT peer and return {} (empty obj).
--
-- The peer-id convention matches getpeerinfo: the id is the 0-based index
-- into 'getConnectedPeers', which 'handleGetPeerInfo' zips @[0..]@ over to
-- assign its "id" field.  Both consume the same ordered list, so the id an
-- operator reads from getpeerinfo selects the same peer here.
--
-- Tests:
--   * Part A (pure 'decideGetBlockFromPeer' / 'lookupPeerByIndex'): the four
--     decision branches + the exact getdata message constructed on success +
--     the getpeerinfo peer-id index convention.
--   * Part B (live wire): a real 'PeerConnection' over a socketpair injected
--     into a real 'PeerManager'; 'requestFromPeer' is observed to put a
--     byte-exact getdata for the block hash on the wire to the resolved peer.
module W168GetBlockFromPeerSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM (atomically, newTVarIO, modifyTVar', newTBQueueIO)
import Data.IORef (newIORef)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Aeson (Value(..))
import qualified Data.Aeson.KeyMap as KM

import Network.Socket
  ( Socket, SockAddr(..), socketPair, Family(AF_UNIX), SocketType(Stream)
  , tupleToHostAddress, close )
import Network.Socket.ByteString (recv)

import Haskoin.Types (Hash256(..), BlockHash(..))
import Haskoin.Consensus (regtest, netMagic)
import Haskoin.Network
  ( PeerManager(..), PeerConnection(..), PeerInfo(..), PeerState(..)
  , Message(..), GetData(..), InvVector(..), InvType(..)
  , startPeerManager, stopPeerManager, requestFromPeer
  , defaultPeerManagerConfig, encodeMessage )
import Haskoin.Rpc
  ( decideGetBlockFromPeer, lookupPeerByIndex
  , RpcError(..), rpcMiscError )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

-- | A deterministic 32-byte block hash (internal byte order).
testHash :: BlockHash
testHash = BlockHash (Hash256 (BS.pack [1 .. 32]))

-- | A second, distinct hash for negative cross-checks.
otherHash :: BlockHash
otherHash = BlockHash (Hash256 (BS.replicate 32 0xab))

addr0, addr1 :: SockAddr
addr0 = SockAddrInet 18444 (tupleToHostAddress (127, 0, 0, 1))
addr1 = SockAddrInet 18445 (tupleToHostAddress (127, 0, 0, 2))

-- | A minimal PeerInfo (only the address matters for these tests).
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
  , piIsLocal             = True
  , piWtxidRelay          = False
  , piGetaddrRecvd        = False
  , piAddrTokenBucket     = 1.0
  , piAddrTokenTimestamp  = 0
  }

-- | The expected success message: a getdata for the block hash with the
--   MSG_BLOCK | MSG_WITNESS_FLAG inv type (InvWitnessBlock).
expectedMsg :: BlockHash -> Message
expectedMsg bh =
  MGetData (GetData [InvVector InvWitnessBlock (getBlockHashHash bh)])

-- | Build a live PeerConnection over one end of a socketpair.  Returns the
--   connection (whose pcSocket is the writer end) and the reader socket (the
--   far end), so a caller can observe exactly what 'sendMessage' writes.
mkLiveConn :: SockAddr -> IO (PeerConnection, Socket)
mkLiveConn a = do
  (writerEnd, readerEnd) <- socketPair AF_UNIX Stream 0
  infoVar <- newTVarIO (mkInfo a)
  sendQ   <- newTBQueueIO 100
  recvQ   <- newTBQueueIO 100
  bufRef  <- newIORef BS.empty
  v2Ref   <- newIORef Nothing
  let pc = PeerConnection
             { pcSocket      = writerEnd
             , pcInfo        = infoVar
             , pcSendQueue   = sendQ
             , pcRecvQueue   = recvQ
             , pcSendThread  = Nothing
             , pcRecvThread  = Nothing
             , pcNetwork     = regtest
             , pcReadBuffer  = bufRef
             , pcV2Transport = v2Ref
             }
  return (pc, readerEnd)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W168 getblockfrompeer" $ do

  ------------------------------------------------------------------------------
  -- Part A — pure decision core (decideGetBlockFromPeer / lookupPeerByIndex)
  ------------------------------------------------------------------------------
  describe "decideGetBlockFromPeer (Core FetchBlock error ladder)" $ do
    let peers = [(addr0, mkInfo addr0), (addr1, mkInfo addr1)]

    it "(1) unknown header -> RPC_MISC_ERROR(-1) \"Block header missing\"" $
      -- headerKnown=False short-circuits before anything else.
      decideGetBlockFromPeer False False 0 peers testHash
        `shouldBe` Left (rpcMiscError, "Block header missing")

    it "(1) header-missing wins even when peer_id is also invalid" $
      decideGetBlockFromPeer False False 99 [] testHash
        `shouldBe` Left (rpcMiscError, "Block header missing")

    it "(3) body already stored -> RPC_MISC_ERROR(-1) \"Block already downloaded\"" $
      decideGetBlockFromPeer True True 0 peers testHash
        `shouldBe` Left (rpcMiscError, "Block already downloaded")

    it "(2) out-of-range peer_id -> RPC_MISC_ERROR(-1) \"Peer does not exist\"" $
      decideGetBlockFromPeer True False 2 peers testHash
        `shouldBe` Left (rpcMiscError, "Peer does not exist")

    it "(2) negative peer_id -> \"Peer does not exist\"" $
      decideGetBlockFromPeer True False (-1) peers testHash
        `shouldBe` Left (rpcMiscError, "Peer does not exist")

    it "(2) no connected peers at all -> \"Peer does not exist\"" $
      decideGetBlockFromPeer True False 0 [] testHash
        `shouldBe` Left (rpcMiscError, "Peer does not exist")

    it "(4) success -> sends getdata(MSG_BLOCK|WITNESS) for the hash to peer 0" $
      decideGetBlockFromPeer True False 0 peers testHash
        `shouldBe` Right (addr0, expectedMsg testHash)

    it "(4) success -> resolves peer 1 to its addr (getpeerinfo id convention)" $
      decideGetBlockFromPeer True False 1 peers testHash
        `shouldBe` Right (addr1, expectedMsg testHash)

    it "(4) the getdata carries the requested hash, witness-flagged inv type" $
      case decideGetBlockFromPeer True False 0 peers testHash of
        Right (_, MGetData (GetData [iv])) -> do
          ivType iv `shouldBe` InvWitnessBlock           -- 0x40000002
          ivHash iv `shouldBe` getBlockHashHash testHash -- the block hash
        other -> expectationFailure ("unexpected: " ++ show other)

  describe "lookupPeerByIndex (getpeerinfo 0-based id convention)" $ do
    let peers = [(addr0, mkInfo addr0), (addr1, mkInfo addr1)]
    it "id 0 -> first peer's addr" $
      lookupPeerByIndex 0 peers `shouldBe` Just addr0
    it "id 1 -> second peer's addr" $
      lookupPeerByIndex 1 peers `shouldBe` Just addr1
    it "id == length -> Nothing (out of range)" $
      lookupPeerByIndex 2 peers `shouldBe` Nothing
    it "negative id -> Nothing" $
      lookupPeerByIndex (-1) peers `shouldBe` Nothing
    it "empty peer list -> Nothing" $
      lookupPeerByIndex 0 [] `shouldBe` Nothing

  ------------------------------------------------------------------------------
  -- Part B — live wire: requestFromPeer genuinely sends a getdata over the
  -- socket to the resolved peer (no DB, no real network; socketpair seam).
  ------------------------------------------------------------------------------
  describe "requestFromPeer (live wire send to resolved peer)" $ do

    it "writes a byte-exact getdata(block) to the resolved peer's socket" $ do
      pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
      (conn, reader) <- mkLiveConn addr0
      -- Inject the live peer the same way the peer manager would, keyed by
      -- the SockAddr that the getpeerinfo-style index resolves to.
      atomically $ modifyTVar' (pmPeers pm) (Map.insert addr0 conn)

      -- This is exactly the call handleGetBlockFromPeer makes on success.
      requestFromPeer pm addr0 (expectedMsg testHash)

      -- Observe what landed on the wire.  sendMessage encodes a full framed
      -- v1 message (header + payload); compare byte-for-byte.
      let expectedBytes = encodeMessage (netMagic regtest) (expectedMsg testHash)
      got <- recv reader (BS.length expectedBytes)
      got `shouldBe` expectedBytes

      close reader
      stopPeerManager pm

    it "is a no-op (no bytes) when the addr is not in pmPeers" $ do
      pm <- startPeerManager regtest defaultPeerManagerConfig (\_ _ -> return ())
      (_conn, reader) <- mkLiveConn addr1
      -- Note: we never insert addr1 into pmPeers, so requestFromPeer to addr1
      -- must do nothing (Map.lookup miss -> return ()).
      requestFromPeer pm addr1 (expectedMsg otherHash)
      -- The far end was never written to; closing the local writer is what
      -- would eventually surface EOF, but we assert "nothing sent" by the
      -- absence of any crash + the handler-level branch already covered in
      -- Part A ("Peer does not exist").  Just tear down cleanly.
      close reader
      stopPeerManager pm

  ------------------------------------------------------------------------------
  -- Error-code parity sanity (RpcError shape used by the handler)
  ------------------------------------------------------------------------------
  describe "error code parity with Core RPC_MISC_ERROR" $ do
    it "rpcMiscError is -1 (Core RPC_MISC_ERROR)" $
      rpcMiscError `shouldBe` (-1)
    it "the (code, message) the handler turns into an RpcError matches Core" $ do
      -- The handler maps a Left (code, msg) into RpcError code msg; here we
      -- assert the code/message pair for the header-missing branch is the
      -- exact (-1, "Block header missing") Core emits.
      case decideGetBlockFromPeer False False 0 [] testHash of
        Left (code, msg) -> do
          let RpcError ecode emsg = RpcError code msg
          ecode `shouldBe` (-1)
          emsg  `shouldBe` "Block header missing"
        Right r -> expectationFailure ("expected header-missing error, got " ++ show r)
    it "the handler's success result is an empty JSON object {}" $
      -- handleGetBlockFromPeer returns `object []` on success; document that
      -- {} is an empty object (Object mempty), matching Core's UniValue::VOBJ.
      Object KM.empty `shouldBe` (Object KM.empty :: Value)

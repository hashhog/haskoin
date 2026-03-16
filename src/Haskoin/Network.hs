{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Haskoin.Network
  ( -- * Message Envelope
    MessageHeader(..)
  , Message(..)
  , encodeMessage
  , decodeMessage
  , decodeMessageHeader
    -- * Message Types
  , Version(..)
  , Ping(..)
  , Pong(..)
  , Addr(..)
  , AddrEntry(..)
  , Inv(..)
  , InvVector(..)
  , InvType(..)
  , GetData(..)
  , NotFound(..)
  , GetBlocks(..)
  , GetHeaders(..)
  , Headers(..)
  , Reject(..)
  , RejectCode(..)
  , SendHeaders(..)
  , SendCmpct(..)
  , FeeFilter(..)
    -- * Service Flags
  , ServiceFlag(..)
  , nodeNetwork
  , nodeWitness
  , nodeBloom
  , nodeNetworkLimited
  , combineServices
  , hasService
    -- * Protocol Constants
  , protocolVersion
  , minProtocolVersion
  , userAgent
    -- * Inventory type helpers
  , invTypeToWord32
  , word32ToInvType
    -- * Message command names
  , commandName
    -- * Peer Connection Types
  , PeerState(..)
  , PeerInfo(..)
  , PeerConnection(..)
  , PeerConfig(..)
    -- * Peer Connection Management
  , connectPeer
  , disconnectPeer
    -- * Message I/O
  , sendMessage
  , receiveMessage
    -- * Handshake
  , performHandshake
    -- * Peer Threads
  , startPeerThreads
  , queueMessage
      -- * Peer Manager Types
  , PeerManager(..)
  , PeerManagerConfig(..)
  , defaultPeerManagerConfig
    -- * Peer Manager Operations
  , startPeerManager
  , stopPeerManager
  , discoverPeers
  , broadcastMessage
  , requestFromPeer
  , getPeerCount
  , getConnectedPeers
  , banPeer
  , addBanScore
  , handleAddrMessage
  , buildBlockLocator
    -- * Misbehavior Scoring
  , MisbehaviorReason(..)
  , misbehaviorScore
  , misbehaving
  , isDiscouraged
  , isBanned
  , getBanList
  , clearExpiredBans
  , loadBanList
  , saveBanList
    -- * Pre-Handshake Rejection
  , PreHandshakeResult(..)
  , checkPreHandshake
  , shouldRejectConnection
    -- * Connection Eviction
  , EvictionCandidate(..)
  , evictConnection
  , selectEvictionCandidate
  , peerToEvictionCandidate
  , getNetworkGroup
    -- * Re-exports from Network.Socket
  , SockAddr(..)
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Serialize
import Data.Word
import Data.Int (Int32, Int64)
import Data.Bits ((.&.), (.|.))
import Control.Monad (replicateM, forM_, forM, when, forever, unless, void)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Maybe (mapMaybe, listToMaybe)
import Data.List (sortBy, groupBy, partition)
import Data.Ord (comparing, Down(..))
import Data.Function (on)
import Control.Concurrent (threadDelay)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Aeson as Aeson
import Data.Aeson (ToJSON(..), FromJSON(..), (.=), (.:))
import System.IO (withFile, IOMode(..), hPutStr, hGetContents')

import Network.Socket (Socket, SockAddr(..), AddrInfo(..), getAddrInfo,
                       socket, connect, close, defaultHints, addrFamily,
                       addrSocketType, addrProtocol, addrAddress,
                       SocketType(..), PortNumber)
import Network.Socket.ByteString (recv, sendAll)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Time.Clock.POSIX (getPOSIXTime)
import System.Random (randomIO)
import Control.Concurrent (ThreadId, forkIO, killThread)
import Control.Concurrent.STM
import Control.Exception (try, SomeException, catch, mask_, IOException)

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256)
import Haskoin.Consensus (Network(..))

--------------------------------------------------------------------------------
-- Protocol Constants
--------------------------------------------------------------------------------

-- | Current protocol version (BIP-339 wtxid relay support)
protocolVersion :: Int32
protocolVersion = 70016

-- | Minimum supported protocol version
minProtocolVersion :: Int32
minProtocolVersion = 70015

-- | User agent string identifying this client
userAgent :: ByteString
userAgent = "/Haskoin:0.1.0/"

--------------------------------------------------------------------------------
-- Misbehavior Scoring (matches Bitcoin Core net_processing.cpp)
--------------------------------------------------------------------------------

-- | Reasons for peer misbehavior, with associated ban scores
-- Scores match Bitcoin Core severity levels from net_processing.cpp
data MisbehaviorReason
  = InvalidBlockHeader              -- ^ Invalid proof of work or malformed header (100 - immediate ban)
  | InvalidBlock                    -- ^ Block fails consensus validation (100 - immediate ban)
  | InvalidTransaction              -- ^ Transaction fails validation (10)
  | MalformedMessage                -- ^ Cannot parse message payload (10)
  | WrongNetworkMagic               -- ^ Network magic bytes mismatch (100 - immediate ban)
  | UnsolicitedMessage              -- ^ Received unrequested data (1)
  | TooManyAddrMessages             -- ^ Excessive addr message spam (20)
  | TooLargeInvMessage              -- ^ Inv message exceeds MAX_INV_SZ (20)
  | TooLargeAddrMessage             -- ^ Addr message exceeds limit (20)
  | TooLargeHeadersMessage          -- ^ Headers message exceeds 2000 (20)
  | InvalidCompactBlock             -- ^ Compact block reconstruction failed (100)
  | NonContinuousHeaders            -- ^ Headers not connected to each other (100)
  | ChecksumMismatch                -- ^ Message checksum verification failed (10)
  | PayloadTooLarge                 -- ^ Payload exceeds size limit (10)
  | DuplicateVersion                -- ^ Sent version after handshake (1)
  | ProtocolViolation Text          -- ^ Generic protocol violation with description (10)
  deriving (Show, Eq)

-- | Get the ban score for a misbehavior reason
-- Returns the number of points to add to the peer's misbehavior score
-- When score reaches 100, the peer is banned
misbehaviorScore :: MisbehaviorReason -> Int
misbehaviorScore InvalidBlockHeader       = 100  -- Immediate ban
misbehaviorScore InvalidBlock             = 100  -- Immediate ban
misbehaviorScore InvalidTransaction       = 10
misbehaviorScore MalformedMessage         = 10
misbehaviorScore WrongNetworkMagic        = 100  -- Immediate ban
misbehaviorScore UnsolicitedMessage       = 1
misbehaviorScore TooManyAddrMessages      = 20
misbehaviorScore TooLargeInvMessage       = 20
misbehaviorScore TooLargeAddrMessage      = 20
misbehaviorScore TooLargeHeadersMessage   = 20
misbehaviorScore InvalidCompactBlock      = 100  -- Immediate ban
misbehaviorScore NonContinuousHeaders     = 100  -- Immediate ban
misbehaviorScore ChecksumMismatch         = 10
misbehaviorScore PayloadTooLarge          = 10
misbehaviorScore DuplicateVersion         = 1
misbehaviorScore (ProtocolViolation _)    = 10

-- | Default ban threshold (matches Bitcoin Core)
defaultBanThreshold :: Int
defaultBanThreshold = 100

-- | Default ban duration in seconds (24 hours, matches Bitcoin Core)
defaultBanDuration :: Int64
defaultBanDuration = 86400

--------------------------------------------------------------------------------
-- Service Flags
--------------------------------------------------------------------------------

-- | Service flag bitmask for advertising node capabilities
newtype ServiceFlag = ServiceFlag { getServiceFlag :: Word64 }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)

-- | NODE_NETWORK: full node, can serve full blocks
nodeNetwork :: ServiceFlag
nodeNetwork = ServiceFlag 1

-- | NODE_BLOOM: supports bloom filters (BIP-37)
nodeBloom :: ServiceFlag
nodeBloom = ServiceFlag 4

-- | NODE_WITNESS: supports SegWit (BIP-144)
nodeWitness :: ServiceFlag
nodeWitness = ServiceFlag 8

-- | NODE_NETWORK_LIMITED: serves last 288 blocks (BIP-159)
nodeNetworkLimited :: ServiceFlag
nodeNetworkLimited = ServiceFlag 1024

-- | Combine multiple service flags into a single bitmask
combineServices :: [ServiceFlag] -> Word64
combineServices = foldl (\acc (ServiceFlag s) -> acc .|. s) 0

-- | Check if a service flag is set in a bitmask
hasService :: Word64 -> ServiceFlag -> Bool
hasService flags (ServiceFlag s) = flags .&. s == s

--------------------------------------------------------------------------------
-- Message Header (24 bytes)
--------------------------------------------------------------------------------

-- | P2P message header (24 bytes total)
-- Every Bitcoin P2P message is prefixed with this header
data MessageHeader = MessageHeader
  { mhMagic    :: !Word32       -- ^ Network magic bytes (mainnet: 0xD9B4BEF9)
  , mhCommand  :: !ByteString   -- ^ 12 bytes, null-padded ASCII command name
  , mhLength   :: !Word32       -- ^ Payload length in bytes
  , mhChecksum :: !Word32       -- ^ First 4 bytes of double-SHA256 of payload
  } deriving (Show, Eq, Generic)

instance NFData MessageHeader

instance Serialize MessageHeader where
  put MessageHeader{..} = do
    putWord32le mhMagic
    -- Pad command to exactly 12 bytes with null bytes
    let paddedCmd = BS.take 12 $ mhCommand `BS.append` BS.replicate 12 0
    putByteString paddedCmd
    putWord32le mhLength
    putWord32le mhChecksum

  get = MessageHeader
    <$> getWord32le
    <*> (BS.takeWhile (/= 0) <$> getBytes 12)
    <*> getWord32le
    <*> getWord32le

-- | Decode a message header from 24 bytes
decodeMessageHeader :: ByteString -> Either String MessageHeader
decodeMessageHeader = decode

--------------------------------------------------------------------------------
-- Version Message
--------------------------------------------------------------------------------

-- | Version message - exchanged when establishing a connection
-- The version handshake must complete before other messages are accepted
data Version = Version
  { vVersion     :: !Int32           -- ^ Protocol version
  , vServices    :: !Word64          -- ^ Services supported by sending node
  , vTimestamp   :: !Int64           -- ^ Unix timestamp
  , vAddrRecv    :: !NetworkAddress  -- ^ Address of receiving node
  , vAddrSend    :: !NetworkAddress  -- ^ Address of sending node
  , vNonce       :: !Word64          -- ^ Random nonce to detect self-connections
  , vUserAgent   :: !VarString       -- ^ User agent string
  , vStartHeight :: !Int32           -- ^ Best block height known to sender
  , vRelay       :: !Bool            -- ^ Whether to relay transactions (BIP-37)
  } deriving (Show, Eq, Generic)

instance NFData Version

instance Serialize Version where
  put Version{..} = do
    putWord32le (fromIntegral vVersion)
    putWord64le vServices
    putWord64le (fromIntegral vTimestamp)
    put vAddrRecv
    put vAddrSend
    putWord64le vNonce
    put vUserAgent
    putWord32le (fromIntegral vStartHeight)
    putWord8 (if vRelay then 1 else 0)

  get = Version
    <$> (fromIntegral <$> getWord32le)
    <*> getWord64le
    <*> (fromIntegral <$> getWord64le)
    <*> get
    <*> get
    <*> getWord64le
    <*> get
    <*> (fromIntegral <$> getWord32le)
    <*> (do
          r <- remaining
          if r > 0
            then (== 1) <$> getWord8
            else return True)  -- Relay defaults to true if not present

--------------------------------------------------------------------------------
-- Ping/Pong Messages
--------------------------------------------------------------------------------

-- | Ping message - used to check peer liveness
-- The receiver should respond with a pong containing the same nonce
newtype Ping = Ping { pingNonce :: Word64 }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize Ping where
  put (Ping n) = putWord64le n
  get = Ping <$> getWord64le

-- | Pong message - response to a ping
newtype Pong = Pong { pongNonce :: Word64 }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize Pong where
  put (Pong n) = putWord64le n
  get = Pong <$> getWord64le

--------------------------------------------------------------------------------
-- Inventory Types
--------------------------------------------------------------------------------

-- | Inventory object types
data InvType
  = InvError          -- ^ 0: Any data of unknown type
  | InvTx             -- ^ 1: Hash of a transaction
  | InvBlock          -- ^ 2: Hash of a block
  | InvFilteredBlock  -- ^ 3: Hash of a filtered block (BIP-37)
  | InvCompactBlock   -- ^ 4: Hash of a compact block (BIP-152)
  | InvWitnessTx      -- ^ 0x40000001: SegWit transaction
  | InvWitnessBlock   -- ^ 0x40000002: SegWit block
  deriving (Show, Eq, Generic)

instance NFData InvType

-- | Convert inventory type to wire format
invTypeToWord32 :: InvType -> Word32
invTypeToWord32 InvError         = 0
invTypeToWord32 InvTx            = 1
invTypeToWord32 InvBlock         = 2
invTypeToWord32 InvFilteredBlock = 3
invTypeToWord32 InvCompactBlock  = 4
invTypeToWord32 InvWitnessTx     = 0x40000001
invTypeToWord32 InvWitnessBlock  = 0x40000002

-- | Parse inventory type from wire format
word32ToInvType :: Word32 -> InvType
word32ToInvType 0          = InvError
word32ToInvType 1          = InvTx
word32ToInvType 2          = InvBlock
word32ToInvType 3          = InvFilteredBlock
word32ToInvType 4          = InvCompactBlock
word32ToInvType 0x40000001 = InvWitnessTx
word32ToInvType 0x40000002 = InvWitnessBlock
word32ToInvType _          = InvError

-- | Inventory vector - identifies an object by type and hash
data InvVector = InvVector
  { ivType :: !InvType
  , ivHash :: !Hash256
  } deriving (Show, Eq, Generic)

instance NFData InvVector

instance Serialize InvVector where
  put InvVector{..} = do
    putWord32le (invTypeToWord32 ivType)
    put ivHash
  get = InvVector
    <$> (word32ToInvType <$> getWord32le)
    <*> get

--------------------------------------------------------------------------------
-- Inv, GetData, NotFound Messages
--------------------------------------------------------------------------------

-- | Inv message - announces known transactions or blocks
-- Used to advertise inventory to peers
newtype Inv = Inv { getInvList :: [InvVector] }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize Inv where
  put (Inv vs) = do
    putVarInt (fromIntegral $ length vs)
    mapM_ put vs
  get = do
    n <- getVarInt'
    Inv <$> replicateM (fromIntegral n) get

-- | GetData message - request specific inventory objects
newtype GetData = GetData { getDataList :: [InvVector] }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize GetData where
  put (GetData vs) = do
    putVarInt (fromIntegral $ length vs)
    mapM_ put vs
  get = do
    n <- getVarInt'
    GetData <$> replicateM (fromIntegral n) get

-- | NotFound message - requested data not available
newtype NotFound = NotFound { getNotFoundList :: [InvVector] }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize NotFound where
  put (NotFound vs) = do
    putVarInt (fromIntegral $ length vs)
    mapM_ put vs
  get = do
    n <- getVarInt'
    NotFound <$> replicateM (fromIntegral n) get

--------------------------------------------------------------------------------
-- GetBlocks/GetHeaders Messages
--------------------------------------------------------------------------------

-- | GetBlocks message - request block hashes from a peer
-- Uses block locator to find the fork point
data GetBlocks = GetBlocks
  { gbVersion  :: !Word32        -- ^ Protocol version
  , gbLocators :: ![BlockHash]   -- ^ Block locator hashes (newest first)
  , gbHashStop :: !BlockHash     -- ^ Stop at this hash (or zero for unlimited)
  } deriving (Show, Eq, Generic)

instance NFData GetBlocks

instance Serialize GetBlocks where
  put GetBlocks{..} = do
    putWord32le gbVersion
    putVarInt (fromIntegral $ length gbLocators)
    mapM_ put gbLocators
    put gbHashStop
  get = GetBlocks
    <$> getWord32le
    <*> (do n <- getVarInt'; replicateM (fromIntegral n) get)
    <*> get

-- | GetHeaders message - request block headers from a peer
-- Similar to getblocks but returns headers instead of hashes
data GetHeaders = GetHeaders
  { ghVersion  :: !Word32        -- ^ Protocol version
  , ghLocators :: ![BlockHash]   -- ^ Block locator hashes (newest first)
  , ghHashStop :: !BlockHash     -- ^ Stop at this hash (or zero for unlimited)
  } deriving (Show, Eq, Generic)

instance NFData GetHeaders

instance Serialize GetHeaders where
  put GetHeaders{..} = do
    putWord32le ghVersion
    putVarInt (fromIntegral $ length ghLocators)
    mapM_ put ghLocators
    put ghHashStop
  get = GetHeaders
    <$> getWord32le
    <*> (do n <- getVarInt'; replicateM (fromIntegral n) get)
    <*> get

--------------------------------------------------------------------------------
-- Headers Message
--------------------------------------------------------------------------------

-- | Headers message - response to getheaders
-- Contains up to 2000 block headers
-- Each header is followed by a varint tx_count (always 0)
newtype Headers = Headers { getHeadersList :: [BlockHeader] }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize Headers where
  put (Headers hs) = do
    putVarInt (fromIntegral $ length hs)
    forM_ hs $ \h -> do
      put h
      putVarInt (0 :: Word64)  -- tx_count always 0 in headers msg
  get = do
    n <- getVarInt'
    Headers <$> replicateM (fromIntegral n) (get <* getVarInt')

--------------------------------------------------------------------------------
-- Addr Message
--------------------------------------------------------------------------------

-- | Address entry with timestamp
data AddrEntry = AddrEntry
  { aeTimestamp :: !Word32          -- ^ Unix timestamp when last seen
  , aeAddress   :: !NetworkAddress  -- ^ Network address
  } deriving (Show, Eq, Generic)

instance NFData AddrEntry

instance Serialize AddrEntry where
  put AddrEntry{..} = do
    putWord32le aeTimestamp
    put aeAddress
  get = AddrEntry <$> getWord32le <*> get

-- | Addr message - advertise known network addresses
-- Used for peer discovery
newtype Addr = Addr { getAddrList :: [AddrEntry] }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize Addr where
  put (Addr as) = do
    putVarInt (fromIntegral $ length as)
    mapM_ put as
  get = do
    n <- getVarInt'
    Addr <$> replicateM (fromIntegral n) get

--------------------------------------------------------------------------------
-- SendHeaders Message (BIP-130)
--------------------------------------------------------------------------------

-- | SendHeaders message - request headers-first announcements
-- After receiving this, new blocks are announced via headers instead of inv
data SendHeaders = SendHeaders
  deriving (Show, Eq, Generic)

instance NFData SendHeaders

instance Serialize SendHeaders where
  put _ = return ()
  get = return SendHeaders

--------------------------------------------------------------------------------
-- SendCmpct Message (BIP-152)
--------------------------------------------------------------------------------

-- | SendCmpct message - negotiate compact block relay
data SendCmpct = SendCmpct
  { scAnnounce :: !Bool    -- ^ Whether to announce using cmpctblock
  , scVersion  :: !Word64  -- ^ Compact block version
  } deriving (Show, Eq, Generic)

instance NFData SendCmpct

instance Serialize SendCmpct where
  put SendCmpct{..} = do
    putWord8 (if scAnnounce then 1 else 0)
    putWord64le scVersion
  get = SendCmpct
    <$> ((== 1) <$> getWord8)
    <*> getWord64le

--------------------------------------------------------------------------------
-- FeeFilter Message (BIP-133)
--------------------------------------------------------------------------------

-- | FeeFilter message - set minimum fee rate for tx relay
newtype FeeFilter = FeeFilter { getMinFee :: Word64 }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize FeeFilter where
  put (FeeFilter f) = putWord64le f
  get = FeeFilter <$> getWord64le

--------------------------------------------------------------------------------
-- Reject Message (BIP-61, deprecated but still used)
--------------------------------------------------------------------------------

-- | Rejection reason codes
data RejectCode
  = RejectMalformed     -- ^ 0x01
  | RejectInvalid       -- ^ 0x10
  | RejectObsolete      -- ^ 0x11
  | RejectDuplicate     -- ^ 0x12
  | RejectNonstandard   -- ^ 0x40
  | RejectDust          -- ^ 0x41
  | RejectFee           -- ^ 0x42
  | RejectCheckpoint    -- ^ 0x43
  deriving (Show, Eq, Generic)

instance NFData RejectCode

rejectCodeToWord8 :: RejectCode -> Word8
rejectCodeToWord8 RejectMalformed   = 0x01
rejectCodeToWord8 RejectInvalid     = 0x10
rejectCodeToWord8 RejectObsolete    = 0x11
rejectCodeToWord8 RejectDuplicate   = 0x12
rejectCodeToWord8 RejectNonstandard = 0x40
rejectCodeToWord8 RejectDust        = 0x41
rejectCodeToWord8 RejectFee         = 0x42
rejectCodeToWord8 RejectCheckpoint  = 0x43

word8ToRejectCode :: Word8 -> RejectCode
word8ToRejectCode 0x01 = RejectMalformed
word8ToRejectCode 0x10 = RejectInvalid
word8ToRejectCode 0x11 = RejectObsolete
word8ToRejectCode 0x12 = RejectDuplicate
word8ToRejectCode 0x40 = RejectNonstandard
word8ToRejectCode 0x41 = RejectDust
word8ToRejectCode 0x42 = RejectFee
word8ToRejectCode 0x43 = RejectCheckpoint
word8ToRejectCode _    = RejectInvalid

-- | Reject message - indicate rejection of a message
data Reject = Reject
  { rejectMessage :: !VarString   -- ^ Type of message rejected
  , rejectCode    :: !RejectCode  -- ^ Rejection reason
  , rejectReason  :: !VarString   -- ^ Human-readable reason
  , rejectData    :: !ByteString  -- ^ Optional extra data (e.g., tx hash)
  } deriving (Show, Eq, Generic)

instance NFData Reject

instance Serialize Reject where
  put Reject{..} = do
    put rejectMessage
    putWord8 (rejectCodeToWord8 rejectCode)
    put rejectReason
    putByteString rejectData
  get = do
    msg <- get
    code <- word8ToRejectCode <$> getWord8
    reason <- get
    r <- remaining
    dat <- if r > 0 then getBytes r else return BS.empty
    return $ Reject msg code reason dat

--------------------------------------------------------------------------------
-- Unified Message Type
--------------------------------------------------------------------------------

-- | All P2P message types
data Message
  = MVersion !Version
  | MVerAck
  | MPing !Ping
  | MPong !Pong
  | MAddr !Addr
  | MInv !Inv
  | MGetData !GetData
  | MNotFound !NotFound
  | MGetBlocks !GetBlocks
  | MGetHeaders !GetHeaders
  | MHeaders !Headers
  | MTx !Tx
  | MBlock !Block
  | MReject !Reject
  | MSendHeaders
  | MSendCmpct !SendCmpct
  | MFeeFilter !FeeFilter
  | MGetAddr
  | MMemPool
  deriving (Show, Eq)

-- | Get the command name for a message
commandName :: Message -> ByteString
commandName (MVersion _)    = "version"
commandName MVerAck         = "verack"
commandName (MPing _)       = "ping"
commandName (MPong _)       = "pong"
commandName (MAddr _)       = "addr"
commandName (MInv _)        = "inv"
commandName (MGetData _)    = "getdata"
commandName (MNotFound _)   = "notfound"
commandName (MGetBlocks _)  = "getblocks"
commandName (MGetHeaders _) = "getheaders"
commandName (MHeaders _)    = "headers"
commandName (MTx _)         = "tx"
commandName (MBlock _)      = "block"
commandName (MReject _)     = "reject"
commandName MSendHeaders    = "sendheaders"
commandName (MSendCmpct _)  = "sendcmpct"
commandName (MFeeFilter _)  = "feefilter"
commandName MGetAddr        = "getaddr"
commandName MMemPool        = "mempool"

-- | Encode message payload
encodePayload :: Message -> ByteString
encodePayload (MVersion v)    = encode v
encodePayload MVerAck         = BS.empty
encodePayload (MPing p)       = encode p
encodePayload (MPong p)       = encode p
encodePayload (MAddr a)       = encode a
encodePayload (MInv i)        = encode i
encodePayload (MGetData g)    = encode g
encodePayload (MNotFound n)   = encode n
encodePayload (MGetBlocks g)  = encode g
encodePayload (MGetHeaders g) = encode g
encodePayload (MHeaders h)    = encode h
encodePayload (MTx t)         = encode t
encodePayload (MBlock b)      = encode b
encodePayload (MReject r)     = encode r
encodePayload MSendHeaders    = BS.empty
encodePayload (MSendCmpct s)  = encode s
encodePayload (MFeeFilter f)  = encode f
encodePayload MGetAddr        = BS.empty
encodePayload MMemPool        = BS.empty

-- | Encode a complete message with header
-- Takes network magic and message, returns header + payload bytes
encodeMessage :: Word32 -> Message -> ByteString
encodeMessage magic msg =
  let payload = encodePayload msg
      cmd = commandName msg
      checksumBytes = BS.take 4 $ getHash256 $ doubleSHA256 payload
      checksumW32 = either (const 0) id $ runGet getWord32le checksumBytes
      header = MessageHeader
        { mhMagic = magic
        , mhCommand = cmd
        , mhLength = fromIntegral $ BS.length payload
        , mhChecksum = checksumW32
        }
  in BS.append (encode header) payload

-- | Decode a message from command name and payload
decodeMessage :: ByteString -> ByteString -> Either String Message
decodeMessage cmd payload = case cmd of
  "version"     -> MVersion <$> decode payload
  "verack"      -> Right MVerAck
  "ping"        -> MPing <$> decode payload
  "pong"        -> MPong <$> decode payload
  "addr"        -> MAddr <$> decode payload
  "inv"         -> MInv <$> decode payload
  "getdata"     -> MGetData <$> decode payload
  "notfound"    -> MNotFound <$> decode payload
  "getblocks"   -> MGetBlocks <$> decode payload
  "getheaders"  -> MGetHeaders <$> decode payload
  "headers"     -> MHeaders <$> decode payload
  "tx"          -> MTx <$> decode payload
  "block"       -> MBlock <$> decode payload
  "reject"      -> MReject <$> decode payload
  "sendheaders" -> Right MSendHeaders
  "sendcmpct"   -> MSendCmpct <$> decode payload
  "feefilter"   -> MFeeFilter <$> decode payload
  "getaddr"     -> Right MGetAddr
  "mempool"     -> Right MMemPool
  _             -> Left $ "Unknown command: " ++ C8.unpack cmd

--------------------------------------------------------------------------------
-- Peer State Types
--------------------------------------------------------------------------------

-- | State of a peer connection
data PeerState
  = PeerConnecting      -- ^ TCP connection in progress
  | PeerHandshaking     -- ^ Version handshake in progress
  | PeerConnected       -- ^ Fully connected and ready
  | PeerDisconnecting   -- ^ Disconnect in progress
  | PeerDisconnected    -- ^ Connection closed
  | PeerBanned          -- ^ Peer is banned
  deriving (Show, Eq, Ord, Generic)

instance NFData PeerState

-- | Information about a connected peer
data PeerInfo = PeerInfo
  { piAddress       :: !SockAddr          -- ^ Peer's network address
  , piVersion       :: !(Maybe Version)   -- ^ Their version message
  , piState         :: !PeerState         -- ^ Current connection state
  , piServices      :: !Word64            -- ^ Services advertised by peer
  , piStartHeight   :: !Int32             -- ^ Best block height at connect
  , piRelay         :: !Bool              -- ^ Whether peer relays transactions
  , piLastSeen      :: !Int64             -- ^ Unix timestamp of last message
  , piLastPing      :: !(Maybe Word64)    -- ^ Nonce of last ping sent
  , piPingLatency   :: !(Maybe Double)    -- ^ Round-trip time in seconds
  , piBanScore      :: !Int               -- ^ Misbehavior score
  , piBytesSent     :: !Word64            -- ^ Total bytes sent
  , piBytesRecv     :: !Word64            -- ^ Total bytes received
  , piMsgsSent      :: !Word64            -- ^ Total messages sent
  , piMsgsRecv      :: !Word64            -- ^ Total messages received
  , piConnectedAt   :: !Int64             -- ^ Unix timestamp of connection
  , piInbound       :: !Bool              -- ^ True if peer connected to us
  } deriving (Show, Generic)

instance NFData PeerInfo

-- | A live peer connection with socket and threads
data PeerConnection = PeerConnection
  { pcSocket      :: !Socket              -- ^ TCP socket
  , pcInfo        :: !(TVar PeerInfo)     -- ^ Peer info (mutable)
  , pcSendQueue   :: !(TBQueue Message)   -- ^ Outbound message queue
  , pcRecvQueue   :: !(TBQueue Message)   -- ^ Inbound message queue
  , pcSendThread  :: !(Maybe ThreadId)    -- ^ Send thread ID
  , pcRecvThread  :: !(Maybe ThreadId)    -- ^ Receive thread ID
  , pcNetwork     :: !Network             -- ^ Network configuration
  , pcReadBuffer  :: !(IORef ByteString)  -- ^ Buffered partial reads
  }

-- | Configuration for establishing peer connections
data PeerConfig = PeerConfig
  { pcfgNetwork      :: !Network      -- ^ Network (mainnet/testnet/regtest)
  , pcfgServices     :: !Word64       -- ^ Services we advertise
  , pcfgBestHeight   :: !Int32        -- ^ Our best block height
  , pcfgUserAgent    :: !ByteString   -- ^ Our user agent string
  , pcfgRelay        :: !Bool         -- ^ Whether we want tx relay
  , pcfgConnTimeout  :: !Int          -- ^ Connection timeout in seconds
  , pcfgQueueSize    :: !Int          -- ^ Max queued messages
  } deriving (Show)

-- | Default peer configuration
defaultPeerConfig :: Network -> PeerConfig
defaultPeerConfig net = PeerConfig
  { pcfgNetwork      = net
  , pcfgServices     = combineServices [nodeNetwork, nodeWitness]
  , pcfgBestHeight   = 0
  , pcfgUserAgent    = userAgent
  , pcfgRelay        = True
  , pcfgConnTimeout  = 30
  , pcfgQueueSize    = 100
  }

--------------------------------------------------------------------------------
-- TCP Connection Management
--------------------------------------------------------------------------------

-- | Establish a TCP connection to a peer
connectPeer :: PeerConfig -> String -> Int -> IO (Either String PeerConnection)
connectPeer config host port = do
  result <- try @SomeException $ do
    let hints = defaultHints { addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just host) (Just (show port))
    case addrs of
      [] -> fail $ "Cannot resolve: " ++ host
      (addr:_) -> do
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        connect sock (addrAddress addr)
        now <- round <$> getPOSIXTime
        let info = PeerInfo
              { piAddress       = addrAddress addr
              , piVersion       = Nothing
              , piState         = PeerConnecting
              , piServices      = 0
              , piStartHeight   = 0
              , piRelay         = True
              , piLastSeen      = now
              , piLastPing      = Nothing
              , piPingLatency   = Nothing
              , piBanScore      = 0
              , piBytesSent     = 0
              , piBytesRecv     = 0
              , piMsgsSent      = 0
              , piMsgsRecv      = 0
              , piConnectedAt   = now
              , piInbound       = False
              }
        infoVar <- newTVarIO info
        sendQ <- newTBQueueIO (fromIntegral $ pcfgQueueSize config)
        recvQ <- newTBQueueIO (fromIntegral $ pcfgQueueSize config)
        bufRef <- newIORef BS.empty
        return PeerConnection
          { pcSocket      = sock
          , pcInfo        = infoVar
          , pcSendQueue   = sendQ
          , pcRecvQueue   = recvQ
          , pcSendThread  = Nothing
          , pcRecvThread  = Nothing
          , pcNetwork     = pcfgNetwork config
          , pcReadBuffer  = bufRef
          }
  case result of
    Left e   -> return $ Left (show e)
    Right pc -> return $ Right pc

-- | Disconnect from a peer, cleaning up threads and socket
disconnectPeer :: PeerConnection -> IO ()
disconnectPeer pc = do
  atomically $ modifyTVar' (pcInfo pc) (\i -> i { piState = PeerDisconnected })
  -- Kill threads if they exist
  mapM_ killThread (pcSendThread pc)
  mapM_ killThread (pcRecvThread pc)
  -- Close socket
  close (pcSocket pc)

--------------------------------------------------------------------------------
-- Message I/O with Buffered Reads
--------------------------------------------------------------------------------

-- | Send a message to a peer
sendMessage :: PeerConnection -> Message -> IO ()
sendMessage pc msg = do
  let magic = netMagic (pcNetwork pc)
      encoded = encodeMessage magic msg
  sendAll (pcSocket pc) encoded
  atomically $ modifyTVar' (pcInfo pc) $ \i ->
    i { piBytesSent = piBytesSent i + fromIntegral (BS.length encoded)
      , piMsgsSent = piMsgsSent i + 1
      }

-- | Receive exactly n bytes from the socket, buffering partial reads
-- KNOWN PITFALL: Uses mask_ to prevent async exceptions from desyncing TCP stream
recvExact :: PeerConnection -> Int -> IO (Maybe ByteString)
recvExact pc n = mask_ $ do
  buf <- readIORef (pcReadBuffer pc)
  if BS.length buf >= n
    then do
      let (result, rest) = BS.splitAt n buf
      writeIORef (pcReadBuffer pc) rest
      return (Just result)
    else do
      -- Need more data
      chunk <- recv (pcSocket pc) (max 4096 (n - BS.length buf))
      if BS.null chunk
        then return Nothing  -- Connection closed
        else do
          writeIORef (pcReadBuffer pc) (BS.append buf chunk)
          recvExact pc n

-- | Receive a complete message from a peer
-- Returns Left on error, Right on success
receiveMessage :: PeerConnection -> IO (Either String Message)
receiveMessage pc = do
  -- Read 24-byte header
  mHeader <- recvExact pc 24
  case mHeader of
    Nothing -> return $ Left "Connection closed"
    Just headerBytes ->
      case decodeMessageHeader headerBytes of
        Left err -> return $ Left $ "Header parse error: " ++ err
        Right header
          -- Verify network magic
          | mhMagic header /= netMagic (pcNetwork pc) ->
              return $ Left "Wrong network magic"
          -- Check payload size limit (32 MB)
          | mhLength header > 32 * 1024 * 1024 ->
              return $ Left "Payload too large"
          | otherwise -> do
              -- Read payload
              let payloadLen = fromIntegral (mhLength header)
              mPayload <- recvExact pc payloadLen
              case mPayload of
                Nothing -> return $ Left "Connection closed during payload"
                Just payload -> do
                  -- Verify checksum
                  let checkBytes = BS.take 4 $ getHash256 $ doubleSHA256 payload
                      checksumOk = either (const False) (== mhChecksum header)
                                     (runGet getWord32le checkBytes)
                  if not checksumOk
                    then return $ Left "Checksum mismatch"
                    else do
                      -- Update stats
                      atomically $ modifyTVar' (pcInfo pc) $ \i ->
                        i { piBytesRecv = piBytesRecv i + fromIntegral (24 + payloadLen)
                          , piMsgsRecv = piMsgsRecv i + 1
                          }
                      return $ decodeMessage (mhCommand header) payload

--------------------------------------------------------------------------------
-- Version Handshake
--------------------------------------------------------------------------------

-- | Perform the Bitcoin version handshake
-- Protocol: we send version -> they send version -> both send verack
-- Returns their version message on success
performHandshake :: PeerConfig -> PeerConnection -> IO (Either String Version)
performHandshake config pc = do
  -- Update state to handshaking
  atomically $ modifyTVar' (pcInfo pc) (\i -> i { piState = PeerHandshaking })

  -- Build our version message
  now <- round <$> getPOSIXTime
  nonce <- randomIO

  let ourVersion = Version
        { vVersion     = protocolVersion
        , vServices    = pcfgServices config
        , vTimestamp   = now
        , vAddrRecv    = NetworkAddress 0 (BS.replicate 16 0) 0
        , vAddrSend    = NetworkAddress (pcfgServices config) (BS.replicate 16 0) 0
        , vNonce       = nonce
        , vUserAgent   = VarString (pcfgUserAgent config)
        , vStartHeight = pcfgBestHeight config
        , vRelay       = pcfgRelay config
        }

  -- Send our version
  sendMessage pc (MVersion ourVersion)

  -- Receive their version
  r1 <- receiveMessage pc
  case r1 of
    Left err -> return $ Left $ "Handshake failed: " ++ err
    Right (MVersion theirVersion)
      -- Validate their version
      | vVersion theirVersion < minProtocolVersion ->
          return $ Left "Protocol version too low"
      -- Check for self-connection
      | vNonce theirVersion == nonce ->
          return $ Left "Self-connection detected"
      | otherwise -> do
          -- Send verack
          sendMessage pc MVerAck

          -- Receive verack
          r2 <- receiveMessage pc
          case r2 of
            Right MVerAck -> do
              -- Update peer info with their version data
              atomically $ modifyTVar' (pcInfo pc) $ \i ->
                i { piState       = PeerConnected
                  , piVersion     = Just theirVersion
                  , piServices    = vServices theirVersion
                  , piStartHeight = vStartHeight theirVersion
                  , piRelay       = vRelay theirVersion
                  }

              -- Send post-handshake feature negotiation messages
              sendMessage pc MSendHeaders
              sendMessage pc (MSendCmpct (SendCmpct False 2))

              return $ Right theirVersion

            Right other -> return $ Left $ "Expected verack, got: " ++ msgTypeName other
            Left err -> return $ Left $ "Verack failed: " ++ err

    Right other -> return $ Left $ "Expected version, got: " ++ msgTypeName other

-- | Get a descriptive name for a message type (for error messages)
msgTypeName :: Message -> String
msgTypeName (MVersion _)    = "version"
msgTypeName MVerAck         = "verack"
msgTypeName (MPing _)       = "ping"
msgTypeName (MPong _)       = "pong"
msgTypeName (MAddr _)       = "addr"
msgTypeName (MInv _)        = "inv"
msgTypeName (MGetData _)    = "getdata"
msgTypeName (MNotFound _)   = "notfound"
msgTypeName (MGetBlocks _)  = "getblocks"
msgTypeName (MGetHeaders _) = "getheaders"
msgTypeName (MHeaders _)    = "headers"
msgTypeName (MTx _)         = "tx"
msgTypeName (MBlock _)      = "block"
msgTypeName (MReject _)     = "reject"
msgTypeName MSendHeaders    = "sendheaders"
msgTypeName (MSendCmpct _)  = "sendcmpct"
msgTypeName (MFeeFilter _)  = "feefilter"
msgTypeName MGetAddr        = "getaddr"
msgTypeName MMemPool        = "mempool"

--------------------------------------------------------------------------------
-- Send/Receive Threads
--------------------------------------------------------------------------------

-- | Start send and receive threads for a peer connection
-- The handler function is called for each received message
startPeerThreads :: PeerConnection -> (Message -> IO ()) -> IO PeerConnection
startPeerThreads pc handler = do
  -- Send thread: reads from queue and sends to socket
  sendTid <- forkIO $ forever $ do
    msg <- atomically $ readTBQueue (pcSendQueue pc)
    sendMessage pc msg `catch` (\(_ :: SomeException) -> disconnectPeer pc)

  -- Receive thread: reads from socket and calls handler
  recvTid <- forkIO $ forever $ do
    result <- receiveMessage pc
    case result of
      Right msg -> do
        -- Update last seen timestamp
        now <- round <$> getPOSIXTime
        atomically $ modifyTVar' (pcInfo pc) (\i -> i { piLastSeen = now })
        -- Also put in receive queue for async processing
        atomically $ writeTBQueue (pcRecvQueue pc) msg
        -- Call handler
        handler msg
      Left _ -> disconnectPeer pc

  return pc { pcSendThread = Just sendTid, pcRecvThread = Just recvTid }

-- | Queue a message to be sent by the send thread
queueMessage :: PeerConnection -> Message -> STM ()
queueMessage pc msg = writeTBQueue (pcSendQueue pc) msg

--------------------------------------------------------------------------------
-- Peer Manager
--------------------------------------------------------------------------------

-- | Peer manager for maintaining multiple peer connections
-- Handles peer discovery, connection management, and message routing
data PeerManager = PeerManager
  { pmPeers          :: !(TVar (Map SockAddr PeerConnection))
  , pmKnownAddrs     :: !(TVar (Set.Set SockAddr))
  , pmBannedAddrs    :: !(TVar (Map SockAddr Int64))
  , pmConfig         :: !PeerManagerConfig
  , pmNetwork        :: !Network
  , pmBestHeight     :: !(TVar Int32)
  , pmManagerThread  :: !(TVar (Maybe ThreadId))
  , pmMessageHandler :: !(SockAddr -> Message -> IO ())
  }

-- | Configuration for the peer manager
data PeerManagerConfig = PeerManagerConfig
  { pmcMaxOutbound    :: !Int        -- ^ Maximum outbound connections (default 8)
  , pmcMaxInbound     :: !Int        -- ^ Maximum inbound connections (default 117)
  , pmcMaxTotal       :: !Int        -- ^ Maximum total connections (default 125)
  , pmcBanDuration    :: !Int64      -- ^ Ban duration in seconds (default 86400 = 24h)
  , pmcBanThreshold   :: !Int        -- ^ Ban score threshold (default 100)
  , pmcPingInterval   :: !Int        -- ^ Ping interval in seconds (default 120)
  , pmcConnectTimeout :: !Int        -- ^ Connection timeout in seconds (default 5)
  } deriving (Show)

-- | Default peer manager configuration (matches Bitcoin Core defaults)
defaultPeerManagerConfig :: PeerManagerConfig
defaultPeerManagerConfig = PeerManagerConfig
  { pmcMaxOutbound    = 8
  , pmcMaxInbound     = 117
  , pmcMaxTotal       = 125
  , pmcBanDuration    = 86400    -- 24 hours
  , pmcBanThreshold   = 100
  , pmcPingInterval   = 120      -- 2 minutes
  , pmcConnectTimeout = 5
  }

--------------------------------------------------------------------------------
-- DNS Seed Discovery
--------------------------------------------------------------------------------

-- | Hardcoded fallback peer addresses for when DNS seeds fail
-- KNOWN PITFALL: DNS seeds unreliable for testnet4, use fallback addresses
fallbackMainnetPeers :: [SockAddr]
fallbackMainnetPeers =
  [ SockAddrInet 8333 0x0a000001  -- placeholder IPs
  ]

fallbackTestnetPeers :: [SockAddr]
fallbackTestnetPeers =
  [ SockAddrInet 18333 0x0a000001
  ]

-- | Discover peers via DNS seeds with fallback to hardcoded addresses
discoverPeers :: Network -> IO [SockAddr]
discoverPeers net = do
  results <- forM (netDNSSeeds net) $ \seed -> do
    result <- try @SomeException $ do
      addrInfos <- getAddrInfo Nothing (Just seed) (Just (show (netDefaultPort net)))
      return $ map addrAddress addrInfos
    case result of
      Left _     -> return []
      Right addrs -> return addrs
  let discovered = concat results
  -- Fall back to hardcoded addresses if DNS resolution fails
  if null discovered
    then return $ if netDefaultPort net == 8333
                  then fallbackMainnetPeers
                  else fallbackTestnetPeers
    else return discovered

--------------------------------------------------------------------------------
-- Peer Manager Operations
--------------------------------------------------------------------------------

-- | Start the peer manager background thread
startPeerManager :: Network -> PeerManagerConfig
                 -> (SockAddr -> Message -> IO ()) -> IO PeerManager
startPeerManager net config handler = do
  pm <- PeerManager
    <$> newTVarIO Map.empty
    <*> newTVarIO Set.empty
    <*> newTVarIO Map.empty
    <*> pure config
    <*> pure net
    <*> newTVarIO 0
    <*> newTVarIO Nothing
    <*> pure handler
  tid <- forkIO $ peerManagerLoop pm
  atomically $ writeTVar (pmManagerThread pm) (Just tid)
  return pm

-- | Stop the peer manager and disconnect all peers
stopPeerManager :: PeerManager -> IO ()
stopPeerManager pm = do
  mTid <- readTVarIO (pmManagerThread pm)
  mapM_ killThread mTid
  peers <- readTVarIO (pmPeers pm)
  mapM_ disconnectPeer (Map.elems peers)

-- | Main peer manager loop - maintains connections and handles timeouts
peerManagerLoop :: PeerManager -> IO ()
peerManagerLoop pm = forever $ do
  -- Maintain target outbound connections
  peers <- readTVarIO (pmPeers pm)
  let outboundCount = Map.size peers  -- simplified: count all as outbound
      target = pmcMaxOutbound (pmConfig pm)

  when (outboundCount < target) $ do
    known <- readTVarIO (pmKnownAddrs pm)
    banned <- readTVarIO (pmBannedAddrs pm)
    now <- round <$> getPOSIXTime

    -- Filter out expired bans
    let activeBans = Map.filter (> now) banned
        connected = Map.keysSet peers
        candidates = Set.toList $
          Set.difference known (Set.union connected (Map.keysSet activeBans))

    -- If no known addresses, discover via DNS
    candidates' <- if null candidates
      then discoverPeers (pmNetwork pm)
      else return candidates

    -- Connect to candidates
    let toConnect = take (target - outboundCount) candidates'
    mapM_ (void . forkIO . tryConnect pm) toConnect

  -- Ping peers and disconnect stale ones
  now <- round <$> getPOSIXTime
  peers' <- readTVarIO (pmPeers pm)

  forM_ (Map.toList peers') $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)
    when (piState info == PeerConnected) $ do
      -- Send ping if no recent activity
      when (now - piLastSeen info > fromIntegral (pmcPingInterval (pmConfig pm))) $ do
        nonce <- randomIO
        atomically $ modifyTVar' (pcInfo pc) (\i -> i { piLastPing = Just nonce })
        sendMessage pc (MPing (Ping nonce)) `catch` (\(_ :: IOException) -> return ())

      -- Disconnect if no response for 5 minutes
      -- KNOWN PITFALL: Re-queue in-flight blocks immediately on disconnect
      when (now - piLastSeen info > 300) $ do
        disconnectPeer pc
        atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)

  -- Check ban scores and disconnect misbehaving peers
  forM_ (Map.toList peers') $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)
    when (piBanScore info >= pmcBanThreshold (pmConfig pm)) $ do
      banPeer pm addr
      disconnectPeer pc
      atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)

  -- Sleep before next iteration
  threadDelay (10 * 1000000)  -- 10 seconds

-- | Try to connect to a peer address
-- Checks if address is banned before attempting connection
tryConnect :: PeerManager -> SockAddr -> IO ()
tryConnect pm addr = do
  -- Check if address is discouraged/banned before connecting
  discouraged <- isDiscouraged pm addr
  unless discouraged $ do
    let net = pmNetwork pm
        config = PeerConfig
          { pcfgNetwork     = net
          , pcfgServices    = combineServices [nodeNetwork, nodeWitness]
          , pcfgBestHeight  = 0
          , pcfgUserAgent   = userAgent
          , pcfgRelay       = True
          , pcfgConnTimeout = pmcConnectTimeout (pmConfig pm)
          , pcfgQueueSize   = 100
          }
        -- Extract host and port from SockAddr
        (host, port) = sockAddrToHostPort addr (netDefaultPort net)

    result <- connectPeer config host port
    case result of
      Left _ -> return ()
      Right pc -> do
        hsResult <- performHandshake config pc
        case hsResult of
          Left _ -> disconnectPeer pc
          Right ver -> do
            -- Verify peer supports required services
            unless (hasService (vServices ver) nodeNetwork) $ disconnectPeer pc

            -- Add to peer map
            atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc)

            -- Start peer threads with message handler
            pc' <- startPeerThreads pc (pmMessageHandler pm addr)
            atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc')

            -- Request addresses from peer
            sendMessage pc' MGetAddr `catch` (\(_ :: IOException) -> return ())

-- | Convert SockAddr to host string and port
sockAddrToHostPort :: SockAddr -> Int -> (String, Int)
sockAddrToHostPort addr defaultPort = case addr of
  SockAddrInet port hostAddr ->
    let a = fromIntegral hostAddr :: Word32
        b1 = a .&. 0xff
        b2 = (a `div` 0x100) .&. 0xff
        b3 = (a `div` 0x10000) .&. 0xff
        b4 = (a `div` 0x1000000) .&. 0xff
    in (show b1 ++ "." ++ show b2 ++ "." ++ show b3 ++ "." ++ show b4,
        fromIntegral port)
  _ -> ("127.0.0.1", defaultPort)  -- Fallback for IPv6, etc.

--------------------------------------------------------------------------------
-- Peer Manager API
--------------------------------------------------------------------------------

-- | Broadcast a message to all connected peers
broadcastMessage :: PeerManager -> Message -> IO ()
broadcastMessage pm msg = do
  peers <- readTVarIO (pmPeers pm)
  forM_ (Map.elems peers) $ \pc -> do
    info <- readTVarIO (pcInfo pc)
    when (piState info == PeerConnected) $
      sendMessage pc msg `catch` (\(_ :: IOException) -> return ())

-- | Send a message to a specific peer
requestFromPeer :: PeerManager -> SockAddr -> Message -> IO ()
requestFromPeer pm addr msg = do
  peers <- readTVarIO (pmPeers pm)
  case Map.lookup addr peers of
    Nothing -> return ()
    Just pc -> sendMessage pc msg `catch` (\(_ :: IOException) -> return ())

-- | Get the number of connected peers
getPeerCount :: PeerManager -> IO Int
getPeerCount pm = Map.size <$> readTVarIO (pmPeers pm)

-- | Get information about all connected peers
getConnectedPeers :: PeerManager -> IO [(SockAddr, PeerInfo)]
getConnectedPeers pm = do
  peers <- readTVarIO (pmPeers pm)
  forM (Map.toList peers) $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)
    return (addr, info)

-- | Ban a peer for the configured duration
banPeer :: PeerManager -> SockAddr -> IO ()
banPeer pm addr = do
  now <- round <$> getPOSIXTime
  let expiry = now + pmcBanDuration (pmConfig pm)
  atomically $ modifyTVar' (pmBannedAddrs pm) (Map.insert addr expiry)

-- | Add to a peer's ban score for misbehavior
-- Invalid messages typically add 10-100 points
addBanScore :: PeerManager -> SockAddr -> Int -> String -> IO ()
addBanScore pm addr score _reason = do
  peers <- readTVarIO (pmPeers pm)
  case Map.lookup addr peers of
    Nothing -> return ()
    Just pc -> atomically $ modifyTVar' (pcInfo pc) $ \i ->
      i { piBanScore = piBanScore i + score }

--------------------------------------------------------------------------------
-- Misbehavior Scoring API
--------------------------------------------------------------------------------

-- | Record misbehavior for a peer (STM version for atomic operations)
-- Increments the peer's ban score based on the misbehavior reason.
-- When score reaches threshold (default 100), peer is marked for banning.
-- Returns the new total score and whether the peer should be banned.
misbehaving :: PeerManager -> SockAddr -> MisbehaviorReason -> IO (Int, Bool)
misbehaving pm addr reason = do
  let score = misbehaviorScore reason
      threshold = pmcBanThreshold (pmConfig pm)

  peers <- readTVarIO (pmPeers pm)
  case Map.lookup addr peers of
    Nothing -> return (0, False)
    Just pc -> do
      (newScore, shouldBan) <- atomically $ do
        info <- readTVar (pcInfo pc)
        let oldScore = piBanScore info
            newScore = oldScore + score
            shouldBan = newScore >= threshold
        -- Update the ban score
        modifyTVar' (pcInfo pc) $ \i ->
          i { piBanScore = newScore
            , piState = if shouldBan then PeerBanned else piState i
            }
        return (newScore, shouldBan)

      -- If threshold reached, add to ban list
      when shouldBan $ do
        banPeer pm addr
        -- Disconnect the peer
        disconnectPeer pc
        atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)

      return (newScore, shouldBan)

-- | Check if an address is currently discouraged/banned
-- Used before accepting new connections
isDiscouraged :: PeerManager -> SockAddr -> IO Bool
isDiscouraged pm addr = do
  now <- round <$> getPOSIXTime
  banned <- readTVarIO (pmBannedAddrs pm)
  case Map.lookup addr banned of
    Nothing -> return False
    Just expiry -> return (now < expiry)

-- | Check if an address is banned (alias for isDiscouraged)
isBanned :: PeerManager -> SockAddr -> IO Bool
isBanned = isDiscouraged

-- | Get the current ban list with expiry times
getBanList :: PeerManager -> IO (Map SockAddr Int64)
getBanList pm = readTVarIO (pmBannedAddrs pm)

-- | Remove expired bans from the ban list
clearExpiredBans :: PeerManager -> IO Int
clearExpiredBans pm = do
  now <- round <$> getPOSIXTime
  atomically $ do
    banned <- readTVar (pmBannedAddrs pm)
    let (expired, active) = Map.partition (<= now) banned
    writeTVar (pmBannedAddrs pm) active
    return (Map.size expired)

--------------------------------------------------------------------------------
-- Ban List Persistence
--------------------------------------------------------------------------------

-- | JSON representation of a ban entry for persistence
data BanEntry = BanEntry
  { beAddress :: !String  -- ^ IP address as string
  , bePort    :: !Int     -- ^ Port number
  , beExpiry  :: !Int64   -- ^ Unix timestamp when ban expires
  } deriving (Show, Eq)

instance ToJSON BanEntry where
  toJSON be = Aeson.object
    [ "address" .= beAddress be
    , "port"    .= bePort be
    , "expiry"  .= beExpiry be
    ]

instance FromJSON BanEntry where
  parseJSON = Aeson.withObject "BanEntry" $ \o -> BanEntry
    <$> o .: "address"
    <*> o .: "port"
    <*> o .: "expiry"

-- | Convert SockAddr to BanEntry
sockAddrToBanEntry :: SockAddr -> Int64 -> Maybe BanEntry
sockAddrToBanEntry addr expiry = case addr of
  SockAddrInet port hostAddr ->
    let a = fromIntegral hostAddr :: Word32
        b1 = a .&. 0xff
        b2 = (a `div` 0x100) .&. 0xff
        b3 = (a `div` 0x10000) .&. 0xff
        b4 = (a `div` 0x1000000) .&. 0xff
        addrStr = show b1 ++ "." ++ show b2 ++ "." ++ show b3 ++ "." ++ show b4
    in Just $ BanEntry addrStr (fromIntegral port) expiry
  _ -> Nothing  -- IPv6 not supported for persistence yet

-- | Convert BanEntry back to SockAddr
banEntryToSockAddr :: BanEntry -> Maybe SockAddr
banEntryToSockAddr be =
  case parseIPv4 (beAddress be) of
    Just hostAddr -> Just $ SockAddrInet (fromIntegral $ bePort be) hostAddr
    Nothing -> Nothing
  where
    parseIPv4 :: String -> Maybe Word32
    parseIPv4 s = case map read' (splitOn '.' s) of
      [b1, b2, b3, b4] | all validByte [b1, b2, b3, b4] ->
        Just $ fromIntegral b1 + fromIntegral b2 * 0x100
             + fromIntegral b3 * 0x10000 + fromIntegral b4 * 0x1000000
      _ -> Nothing

    read' :: String -> Int
    read' str = case reads str of
      [(n, "")] -> n
      _ -> -1

    validByte :: Int -> Bool
    validByte n = n >= 0 && n <= 255

    splitOn :: Char -> String -> [String]
    splitOn _ [] = [""]
    splitOn c (x:xs)
      | c == x    = "" : splitOn c xs
      | otherwise = let (h:t) = splitOn c xs in (x:h) : t

-- | Save the ban list to a JSON file
saveBanList :: PeerManager -> FilePath -> IO ()
saveBanList pm path = do
  banned <- readTVarIO (pmBannedAddrs pm)
  let entries = mapMaybe (uncurry sockAddrToBanEntry) (Map.toList banned)
  withFile path WriteMode $ \h ->
    hPutStr h (C8.unpack $ LBS.toStrict $ Aeson.encode entries)

-- | Load the ban list from a JSON file
loadBanList :: PeerManager -> FilePath -> IO (Either String Int)
loadBanList pm path = do
  result <- try @IOException $ withFile path ReadMode hGetContents'
  case result of
    Left _ -> return $ Left "Could not read ban list file"
    Right contents ->
      case Aeson.decodeStrict (C8.pack contents) of
        Nothing -> return $ Left "Invalid JSON in ban list"
        Just (entries :: [BanEntry]) -> do
          now <- round <$> getPOSIXTime
          let validEntries = filter (\e -> beExpiry e > now) entries
              banMap = Map.fromList $ mapMaybe toBanPair validEntries
          atomically $ modifyTVar' (pmBannedAddrs pm) (Map.union banMap)
          return $ Right (Map.size banMap)
  where
    toBanPair :: BanEntry -> Maybe (SockAddr, Int64)
    toBanPair be = do
      addr <- banEntryToSockAddr be
      return (addr, beExpiry be)

--------------------------------------------------------------------------------
-- Addr Message Handling
--------------------------------------------------------------------------------

-- | Handle an addr message by adding addresses to the known pool
handleAddrMessage :: PeerManager -> Addr -> IO ()
handleAddrMessage pm (Addr entries) = do
  let addrs = mapMaybe (addrToSockAddr . aeAddress) entries
  atomically $ modifyTVar' (pmKnownAddrs pm) $
    Set.union (Set.fromList addrs)
  where
    -- Convert NetworkAddress to SockAddr
    addrToSockAddr :: NetworkAddress -> Maybe SockAddr
    addrToSockAddr na =
      let port = fromIntegral (naPort na) :: PortNumber
          -- Extract IPv4 address from IPv6-mapped format (last 4 bytes)
          addrBytes = naAddress na
          ipv4Bytes = BS.drop 12 addrBytes
      in if BS.length ipv4Bytes == 4
         then let [b1, b2, b3, b4] = BS.unpack ipv4Bytes
                  hostAddr = fromIntegral b1
                           + fromIntegral b2 * 0x100
                           + fromIntegral b3 * 0x10000
                           + fromIntegral b4 * 0x1000000
              in Just $ SockAddrInet port hostAddr
         else Nothing

--------------------------------------------------------------------------------
-- Block Locator
--------------------------------------------------------------------------------

-- | Build a block locator from a chain of (height, hash) pairs
-- Uses exponentially-spaced block hashes to efficiently find fork points
-- Input should be sorted newest-first (highest height first)
buildBlockLocator :: [(Word32, BlockHash)] -> [BlockHash]
buildBlockLocator chain =
  let -- We need oldest-first for processing, so reverse
      reversed = reverse chain
      go :: [(Word32, BlockHash)] -> Int -> Int -> [BlockHash]
      go [] _ _ = []
      go ((_, bh):rest) idx gap
        | idx < 10  = bh : go rest (idx + 1) 1
        | otherwise = bh : go (drop (gap - 1) rest) (idx + 1) (gap * 2)
  in go reversed (0 :: Int) (1 :: Int)

--------------------------------------------------------------------------------
-- Pre-Handshake Rejection (Phase 16)
--------------------------------------------------------------------------------

-- | Result of pre-handshake connection check
-- Reference: Bitcoin Core net.cpp AcceptConnection
data PreHandshakeResult
  = AcceptConnection                    -- ^ Connection can proceed
  | RejectBanned                        -- ^ Peer IP is banned
  | RejectDiscouraged                   -- ^ Peer is discouraged and slots are nearly full
  | RejectMaxConnections                -- ^ Total connection limit reached
  | RejectMaxInbound                    -- ^ Inbound connection limit reached (no eviction candidate)
  | AcceptAfterEviction SockAddr        -- ^ Accept after evicting the specified peer
  deriving (Show, Eq)

-- | Check whether to accept a new inbound connection before handshake
-- This saves resources by rejecting known-bad connections early
-- Reference: Bitcoin Core net.cpp CConnman::AcceptConnection
checkPreHandshake :: PeerManager -> SockAddr -> IO PreHandshakeResult
checkPreHandshake pm addr = do
  now <- round <$> getPOSIXTime
  banned <- readTVarIO (pmBannedAddrs pm)
  peers <- readTVarIO (pmPeers pm)

  let config = pmConfig pm
      totalCount = Map.size peers

  -- Count inbound connections
  inboundCount <- countInboundPeers pm

  -- Check 1: Is the peer banned?
  case Map.lookup addr banned of
    Just expiry | expiry > now -> return RejectBanned
    _ -> do
      -- Check 2: Is the peer discouraged and slots nearly full?
      -- Bitcoin Core allows discouraged peers when there's room
      discouraged <- isDiscouraged pm addr
      if discouraged && inboundCount + 1 >= pmcMaxInbound config
        then return RejectDiscouraged
        else do
          -- Check 3: Total connection limit
          if totalCount >= pmcMaxTotal config
            then return RejectMaxConnections
            else do
              -- Check 4: Inbound limit with eviction
              if inboundCount >= pmcMaxInbound config
                then do
                  -- Try to evict an existing connection
                  candidates <- buildEvictionCandidates pm
                  case selectEvictionCandidate candidates of
                    Nothing -> return RejectMaxInbound
                    Just candidate -> return $ AcceptAfterEviction (ecAddress candidate)
                else return AcceptConnection

-- | Simple check for whether to reject a connection
-- Returns True if the connection should be rejected
shouldRejectConnection :: PeerManager -> SockAddr -> IO Bool
shouldRejectConnection pm addr = do
  result <- checkPreHandshake pm addr
  case result of
    AcceptConnection       -> return False
    AcceptAfterEviction _  -> return False
    _                      -> return True

-- | Count inbound peer connections
countInboundPeers :: PeerManager -> IO Int
countInboundPeers pm = do
  peers <- readTVarIO (pmPeers pm)
  counts <- forM (Map.elems peers) $ \pc -> do
    info <- readTVarIO (pcInfo pc)
    return $ if piInbound info then 1 else 0
  return $ sum counts

--------------------------------------------------------------------------------
-- Connection Eviction (Phase 16)
--------------------------------------------------------------------------------

-- | Eviction candidate with scoring data
-- Reference: Bitcoin Core node/eviction.h NodeEvictionCandidate
data EvictionCandidate = EvictionCandidate
  { ecAddress         :: !SockAddr          -- ^ Peer address (used as ID)
  , ecConnectedAt     :: !Int64             -- ^ Unix timestamp when connected
  , ecMinPingTime     :: !(Maybe Double)    -- ^ Minimum observed ping time (seconds)
  , ecLastBlockTime   :: !Int64             -- ^ Last time peer sent us a novel block
  , ecLastTxTime      :: !Int64             -- ^ Last time peer sent us a novel transaction
  , ecServices        :: !Word64            -- ^ Services advertised
  , ecRelaysTxs       :: !Bool              -- ^ Whether peer relays transactions
  , ecNetworkGroup    :: !Word32            -- ^ /16 network group for IPv4
  , ecInbound         :: !Bool              -- ^ Is this an inbound connection?
  , ecNoBan           :: !Bool              -- ^ Has NoBan permission (never evict)
  } deriving (Show, Eq)

-- | Convert a PeerInfo to an EvictionCandidate
peerToEvictionCandidate :: SockAddr -> PeerInfo -> EvictionCandidate
peerToEvictionCandidate addr info = EvictionCandidate
  { ecAddress       = addr
  , ecConnectedAt   = piConnectedAt info
  , ecMinPingTime   = piPingLatency info
  , ecLastBlockTime = 0  -- Would need to track this in PeerInfo
  , ecLastTxTime    = 0  -- Would need to track this in PeerInfo
  , ecServices      = piServices info
  , ecRelaysTxs     = piRelay info
  , ecNetworkGroup  = getNetworkGroup addr
  , ecInbound       = piInbound info
  , ecNoBan         = False  -- Would need permission system
  }

-- | Extract /16 network group from an IP address
-- For IPv4: use first two octets (e.g., 192.168.x.x -> 192.168)
-- Reference: Bitcoin Core netaddress.cpp GetGroup
getNetworkGroup :: SockAddr -> Word32
getNetworkGroup (SockAddrInet _ hostAddr) =
  -- hostAddr is in network byte order (big-endian on wire, but stored as host order)
  -- For /16 grouping, we want the first two bytes
  let a = fromIntegral hostAddr :: Word32
      -- First two octets (in host byte order)
      octet1 = a .&. 0xff
      octet2 = (a `div` 0x100) .&. 0xff
  in octet1 * 256 + octet2
getNetworkGroup (SockAddrInet6 _ _ (h1, h2, _, _) _) =
  -- For IPv6, use first 32 bits as a simplification
  fromIntegral $ h1 `div` 0x10000
getNetworkGroup _ = 0  -- Unix sockets, etc.

-- | Build list of eviction candidates from current peers
buildEvictionCandidates :: PeerManager -> IO [EvictionCandidate]
buildEvictionCandidates pm = do
  peers <- readTVarIO (pmPeers pm)
  forM (Map.toList peers) $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)
    return $ peerToEvictionCandidate addr info

-- | Select a peer to evict using Bitcoin Core's eviction algorithm
-- Returns Nothing if no suitable candidate exists
-- Reference: Bitcoin Core node/eviction.cpp SelectNodeToEvict
selectEvictionCandidate :: [EvictionCandidate] -> Maybe EvictionCandidate
selectEvictionCandidate candidates =
  let -- Step 1: Filter to only inbound, non-NoBan connections
      inboundCandidates = filter (\c -> ecInbound c && not (ecNoBan c)) candidates

      -- Step 2: Protect peers by various criteria
      afterProtection = applyProtections inboundCandidates

  in case afterProtection of
       [] -> Nothing
       remaining ->
         -- Step 3: Evict youngest peer from most-connected network group
         selectFromNetworkGroup remaining

-- | Apply Bitcoin Core's protection rules to filter eviction candidates
-- Reference: Bitcoin Core node/eviction.cpp SelectNodeToEvict
applyProtections :: [EvictionCandidate] -> [EvictionCandidate]
applyProtections candidates =
  let -- Protect 4 peers by deterministic network group selection
      afterNetGroup = protectByNetGroup 4 candidates

      -- Protect 8 peers with lowest ping time
      afterPing = protectByPingTime 8 afterNetGroup

      -- Protect 4 peers that most recently sent transactions
      afterTx = protectByLastTxTime 4 afterPing

      -- Protect 4 peers that most recently sent blocks
      afterBlock = protectByLastBlockTime 4 afterTx

      -- Protect 50% of remaining by connection longevity
      afterLongevity = protectByLongevity afterBlock

  in afterLongevity

-- | Protect N peers from distinct network groups (deterministic selection)
protectByNetGroup :: Int -> [EvictionCandidate] -> [EvictionCandidate]
protectByNetGroup n candidates =
  let -- Group by network group and take one peer from each of the first N groups
      grouped = groupBy ((==) `on` ecNetworkGroup) $
                sortBy (comparing ecNetworkGroup) candidates
      -- Take one peer from each of first N groups (protect them)
      protectedGroups = take n grouped
      protectedAddrs = Set.fromList $ map (ecAddress . head) protectedGroups
  in filter (\c -> not $ Set.member (ecAddress c) protectedAddrs) candidates

-- | Protect N peers with lowest ping time
protectByPingTime :: Int -> [EvictionCandidate] -> [EvictionCandidate]
protectByPingTime n candidates =
  let -- Sort by ping time (Nothing goes to end, lowest first)
      sortedByPing = sortBy (comparing ecMinPingTime) candidates
      -- Protect the N with lowest ping
      protected = take n sortedByPing
      protectedAddrs = Set.fromList $ map ecAddress protected
  in filter (\c -> not $ Set.member (ecAddress c) protectedAddrs) candidates

-- | Protect N peers that most recently sent transactions
protectByLastTxTime :: Int -> [EvictionCandidate] -> [EvictionCandidate]
protectByLastTxTime n candidates =
  let -- Sort by last tx time descending (most recent first)
      sortedByTx = sortBy (comparing (Down . ecLastTxTime)) candidates
      -- Protect the N most recent
      protected = take n sortedByTx
      protectedAddrs = Set.fromList $ map ecAddress protected
  in filter (\c -> not $ Set.member (ecAddress c) protectedAddrs) candidates

-- | Protect N peers that most recently sent blocks
protectByLastBlockTime :: Int -> [EvictionCandidate] -> [EvictionCandidate]
protectByLastBlockTime n candidates =
  let -- Sort by last block time descending (most recent first)
      sortedByBlock = sortBy (comparing (Down . ecLastBlockTime)) candidates
      -- Protect the N most recent
      protected = take n sortedByBlock
      protectedAddrs = Set.fromList $ map ecAddress protected
  in filter (\c -> not $ Set.member (ecAddress c) protectedAddrs) candidates

-- | Protect 50% of remaining peers by connection longevity
protectByLongevity :: [EvictionCandidate] -> [EvictionCandidate]
protectByLongevity candidates =
  let -- Sort by connection time ascending (oldest first)
      sortedByAge = sortBy (comparing ecConnectedAt) candidates
      -- Protect the oldest 50%
      n = length candidates `div` 2
      protected = take n sortedByAge
      protectedAddrs = Set.fromList $ map ecAddress protected
  in filter (\c -> not $ Set.member (ecAddress c) protectedAddrs) candidates

-- | Select peer to evict from the most-connected network group
-- Evicts the youngest (most recently connected) peer from that group
selectFromNetworkGroup :: [EvictionCandidate] -> Maybe EvictionCandidate
selectFromNetworkGroup [] = Nothing
selectFromNetworkGroup candidates =
  let -- Group by network group
      grouped = groupBy ((==) `on` ecNetworkGroup) $
                sortBy (comparing ecNetworkGroup) candidates
      -- Find the group with most connections
      -- Tie-breaker: prefer group with youngest member
      largestGroups = sortBy compareGroups grouped
      compareGroups g1 g2 =
        case compare (length g2) (length g1) of  -- Descending by size
          EQ -> compare (youngestInGroup g1) (youngestInGroup g2)  -- Then by youngest
          other -> other
      youngestInGroup = maximum . map ecConnectedAt
  in case largestGroups of
       [] -> Nothing
       (group:_) ->
         -- Evict the youngest peer in the largest group
         listToMaybe $ sortBy (comparing (Down . ecConnectedAt)) group

-- | Evict a connection from the peer manager if needed
-- Returns the evicted peer's address if eviction occurred
evictConnection :: PeerManager -> IO (Maybe SockAddr)
evictConnection pm = do
  candidates <- buildEvictionCandidates pm
  case selectEvictionCandidate candidates of
    Nothing -> return Nothing
    Just candidate -> do
      let addr = ecAddress candidate
      -- Disconnect the evicted peer
      peers <- readTVarIO (pmPeers pm)
      case Map.lookup addr peers of
        Nothing -> return Nothing
        Just pc -> do
          disconnectPeer pc
          atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)
          return (Just addr)

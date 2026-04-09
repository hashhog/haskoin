{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI #-}

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
    -- * BIP155 ADDRv2
  , NetworkId(..)
  , networkIdToWord8
  , word8ToNetworkId
  , networkIdAddrLen
  , CompactSize
  , NetAddr(..)
  , netAddrNetworkId
  , netAddrBytes
  , isAddrV1Compatible
  , AddrV2(..)
  , AddrV2Msg(..)
  , SendAddrV2(..)
  , networkAddressToNetAddr
  , netAddrToNetworkAddress
  , addrV2ToAddrEntry
  , addrEntryToAddrV2
    -- * BIP-331 Package Relay
  , SendTxRcncl(..)
  , AncPkgInfo(..)
  , GetPkgTxns(..)
  , PkgTxns(..)
  , computePackageHash
    -- * BIP152 Compact Blocks
  , CmpctBlock(..)
  , PrefilledTx(..)
  , ShortTxId
  , GetBlockTxn(..)
  , BlockTxn(..)
  , PartiallyDownloadedBlock(..)
  , CompactBlockState(..)
  , CompactBlockConfig(..)
  , defaultCompactBlockConfig
    -- ** Compact Block Operations
  , computeShortIdKey
  , computeShortId
  , computeWtxid
  , createCompactBlock
  , initPartialBlock
  , fillPartialBlock
  , reconstructBlock
  , getMissingTxIndices
    -- ** High-Bandwidth Mode
  , HighBandwidthState(..)
  , newHighBandwidthState
  , addHighBandwidthPeer
  , removeHighBandwidthPeer
  , isHighBandwidthPeer
  , getHighBandwidthPeers
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
  , startInboundListener
  , addNodeConnect
  , sockAddrToHostPort
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
    -- * Inv Trickling
  , TrickleConfig(..)
  , defaultTrickleConfig
  , InvTrickler(..)
  , newInvTrickler
  , queueTxForTrickling
  , flushPeerInventory
  , flushPeerInventoryWithFilter
  , startTrickleThread
  , poissonDelay
    -- * Trickling Constants
  , inboundInventoryBroadcastInterval
  , outboundInventoryBroadcastInterval
  , inventoryBroadcastPerSecond
  , inventoryBroadcastTarget
  , inventoryBroadcastMax
    -- * BIP133 Feefilter Constants
  , avgFeeFilterBroadcastInterval
  , maxFeeFilterChangeDelay
  , feeAtRate
    -- * BIP133 Feefilter Operations
  , handleFeeFilter
  , shouldSendFeeFilter
  , sendFeeFilter
  , filterTxByFeeRate
    -- * Re-exports from Network.Socket
  , SockAddr(..)
    -- * Eclipse Attack Protections
    -- ** Network Group
  , NetworkGroup(..)
  , getNetworkGroupBS
  , computeNetworkGroup
    -- ** Address Manager
  , AddrMan(..)
  , AddrInfo(..)
  , newAddrMan
  , addAddress
  , selectAddress
  , markGood
  , markAttempt
  , getNewBucket
  , getTriedBucket
  , getBucketPosition
    -- ** AddrMan Constants
  , addrmanTriedBucketCount
  , addrmanNewBucketCount
  , addrmanBucketSize
  , addrmanTriedBucketsPerGroup
  , addrmanNewBucketsPerSourceGroup
    -- ** Outbound Connection Diversity
  , OutboundDiversity(..)
  , newOutboundDiversity
  , checkOutboundDiversity
  , addOutboundConnection
  , removeOutboundConnection
    -- ** Anchor Connections
  , AnchorConnection(..)
  , saveAnchors
  , loadAnchors
  , maxBlockRelayOnlyAnchors
    -- ** Inbound Limiting
  , InboundLimiter(..)
  , newInboundLimiter
  , checkInboundLimit
  , addInboundConnection
  , removeInboundConnection
  , maxInboundPerGroup
    -- * Stale Peer Eviction (Phase 19)
    -- ** Eviction Constants
  , staleCheckInterval
  , headersResponseTime
  , pingTimeout
  , blockStallTimeout
  , blockStallTimeoutCompact
  , blockStallTimeoutMax
  , chainSyncTimeout
  , minimumConnectTime
  , maxOutboundPeersToProtect
    -- ** Peer Chain Sync State
  , ChainSyncState(..)
  , ChainSyncData(..)
  , newChainSyncState
    -- ** Stale Peer Tracker
  , StalePeerTracker(..)
  , PeerEvictionState(..)
  , defaultPeerEvictionState
  , newStalePeerTracker
  , updatePeerBestBlock
  , getPeerBestBlock
  , recordPingSent
  , recordPongReceived
  , isPingTimedOut
  , recordBlockRequested
  , recordBlockReceived
  , isBlockStalled
  , considerEviction
  , checkStalePeer
  , startEvictionThread
  , stopEvictionThread
    -- ** Outbound Sync Protection
  , OutboundSyncProtection(..)
  , newOutboundSyncProtection
  , checkOutboundSynced
  , updateOutboundSyncStatus
  , needsExtraOutbound
    -- * BIP324 V2 Transport (Phase 32)
    -- ** V2 Transport Constants
  , v2MaxGarbageLen
  , v2GarbageTerminatorLen
  , v2RekeyInterval
  , v2LengthLen
  , v2HeaderLen
  , v2Expansion
  , v2IgnoreBit
    -- ** Short Message IDs
  , V2MessageId
  , shortMsgId
  , shortMsgIdToCommand
  , v2MessageIds
    -- ** ElligatorSwift Encoding
  , EllSwiftPubKey(..)
  , ellSwiftCreate
  , ellSwiftDecode
    -- ** V2 Key Derivation (HKDF-SHA256)
  , V2SessionKeys(..)
  , deriveV2SessionKeys
  , hkdfSha256
  , hkdfExpand
    -- ** ChaCha20-Poly1305 AEAD
  , FSChaCha20(..)
  , FSChaCha20Poly1305(..)
  , newFSChaCha20
  , newFSChaCha20Poly1305
  , fsCrypt
  , fsEncrypt
  , fsDecrypt
    -- ** BIP324 Cipher
  , BIP324Cipher(..)
  , newBIP324Cipher
  , initializeBIP324
  , bip324Encrypt
  , bip324DecryptLength
  , bip324Decrypt
  , getBIP324SessionId
  , getBIP324SendGarbageTerminator
  , getBIP324RecvGarbageTerminator
    -- ** V2 Transport Layer
  , V2Transport(..)
  , V2TransportState(..)
  , V2SendState(..)
  , V2RecvState(..)
  , newV2Transport
  , v2TransportSend
  , v2TransportReceive
  , isV2Ready
    -- ** V2/V1 Negotiation
  , TransportVersion(..)
  , detectTransportVersion
  , v2HandshakeInitiator
  , v2HandshakeResponder
    -- ** Service Flags
  , nodeP2PV2
    -- * BIP330 Erlay Transaction Reconciliation
    -- ** Erlay Constants
  , erlayReconVersion
  , erlayReconInterval
  , erlayStaticSalt
  , erlayFloodOutboundCount
    -- ** Minisketch (Pure Haskell)
  , Minisketch(..)
  , SketchError(..)
  , newMinisketch
  , sketchAdd
  , sketchMerge
  , sketchDecode
  , sketchSerialize
  , sketchDeserialize
  , sketchCapacity
    -- ** Minisketch FFI (libminisketch)
  , MinisketchFFI
  , withMinisketchFFI
  , minisketchFFICreate
  , minisketchFFIAdd
  , minisketchFFIMerge
  , minisketchFFIDecode
  , minisketchFFISerialize
  , minisketchFFIDeserialize
  , minisketchFFISupported
    -- ** GF(2^32) Field Arithmetic
  , GF2_32(..)
  , gfAdd
  , gfMul
  , gfInv
  , gfPow
  , gfPrimitive
    -- ** Erlay Short TxId
  , ShortTxIdErlay
  , computeErlayShortTxId
  , computeErlaySalt
    -- ** Erlay Messages
  , ReqRecon(..)
  , ReconcilDiff(..)
  , SketchExt(..)
    -- ** Reconciliation State
  , ReconciliationState(..)
  , ReconciliationRole(..)
  , TxReconciliationTracker(..)
  , ReconciliationRegisterResult(..)
  , newTxReconciliationTracker
  , preRegisterPeer
  , registerPeer
  , forgetPeer
  , isPeerRegistered
  , getPeerReconciliationState
    -- ** Reconciliation Set Management
  , ReconciliationSet(..)
  , newReconciliationSet
  , addToReconciliationSet
  , removeFromReconciliationSet
  , buildSketchFromSet
  , computeSetDifference
    -- ** Flood vs Reconciliation Relay
  , RelayMode(..)
  , selectRelayMode
  , getFloodPeers
  , getReconciliationPeers
    -- ** Erlay Reconciliation Protocol
  , ErlayPeerState(..)
  , newErlayPeerState
  , initiateReconciliation
  , handleReqRecon
  , handleReconcilDiff
  , getReconciliationTimer
  , erlayPoissonDelay
    -- * Tor/I2P Connectivity (Phase 48)
    -- ** SOCKS5 Proxy
  , Socks5Reply(..)
  , Socks5Request(..)
  , Socks5Response(..)
  , word8ToSocks5Reply
  , parseSocks5Response
  , socks5Handshake
  , socks5Connect
  , socks5AddrTypeIPv4
  , socks5AddrTypeDomain
  , socks5AddrTypeIPv6
  , socks5CmdConnect
  , socks5AuthNone
    -- ** Proxy Configuration
  , ProxyConfig(..)
  , defaultTorProxy
  , defaultI2PSam
  , connectThroughTor
  , isOnionAddress
  , isI2PAddress
    -- ** Tor Control Port
  , TorKeyType(..)
  , TorOnionResponse(..)
  , defaultTorControlPort
  , parseTorResponse
  , torControlSend
  , torAuthenticate
  , torAddOnion
  , createTorHiddenService
    -- ** I2P SAM Protocol
  , SamResult(..)
  , SamSession(..)
  , samVersion
  , i2pSamPort
  , samSignatureType
  , parseSamResult
  , parseSamResponse
  , samSendRecv
  , samHello
  , samCreateSession
  , samStreamConnect
  , samNameLookup
  , samStreamAccept
  , createI2PSession
  , closeI2PSession
    -- ** I2P Encoding Helpers
  , i2pDestToB32
  , i2pBase64ToStandard
  , standardToI2PBase64
  , base32Encode
    -- ** Proxy Peer Connection
  , ProxyPeerConfig(..)
  , connectPeerThroughProxy
  , connectViaProxy
  , createPeerConnectionFromSocket
    -- ** Network Reachability
  , NetworkReachability(..)
  , defaultReachability
  , shouldAdvertiseAddress
  , filterReachableAddresses
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Serialize
import Data.Word
import Data.Int (Int32, Int64)
import Data.Bits ((.&.), (.|.), shiftR, shiftL, xor, complement, rotateL)
import Control.Monad (replicateM, forM_, forM, when, forever, unless, void, filterM)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData(..))
import Foreign.Ptr (Ptr, FunPtr, nullPtr, castPtr)
import Foreign.ForeignPtr (ForeignPtr, newForeignPtr, withForeignPtr)
import Foreign.C.Types (CUInt(..), CSize(..), CInt(..), CChar)
import Foreign.Marshal.Alloc (mallocBytes, free)
import Foreign.Marshal.Array (allocaArray, peekArray, pokeArray)
import Foreign.Storable (peek, poke)
import Control.Exception (bracket)
import qualified Data.Map.Strict as Map
import qualified Data.Vector.Unboxed as VU
import qualified Data.Vector.Unboxed.Mutable as VUM
import qualified Crypto.Cipher.ChaCha as ChaCha
import Crypto.Error (CryptoFailable(..))
import qualified Crypto.MAC.Poly1305 as Poly1305
import qualified Crypto.Hash as H
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.ECC as ECC
import Data.ByteArray (convert)
import qualified Data.ByteArray as BA
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Maybe (mapMaybe, listToMaybe)
import Data.List (sortBy, groupBy, partition, foldl')
import Data.Ord (comparing, Down(..))
import Data.Function (fix, on)
import Control.Concurrent (threadDelay)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Aeson as Aeson
import Data.Aeson (ToJSON(..), FromJSON(..), (.=), (.:))
import System.FilePath ((</>))
import System.IO (withFile, IOMode(..), hPutStr, hGetContents')

import Network.Socket (Socket, SockAddr(..), getAddrInfo,
                       socket, connect, close, defaultHints,
                       SocketType(..), PortNumber, Family(..),
                       bind, listen, accept, setSocketOption,
                       SocketOption(..))
import qualified Network.Socket as NS (AddrInfo(..))
import Network.Socket.ByteString (recv, sendAll)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Time.Clock.POSIX (getPOSIXTime)
import System.Random (randomIO, randomRIO)
import Control.Concurrent (ThreadId, forkIO, killThread)
import System.Timeout (timeout)
import Control.Concurrent.STM
import Control.Exception (try, SomeException, catch, mask_, IOException)
import Data.Hashable (Hashable(..))

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256, sha256)
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
  | HeadersDontConnect              -- ^ Headers don't connect to our chain (20)
  | BlockDownloadStall              -- ^ Peer stalling block download (50)
  | UnrequestedData                 -- ^ Sending unrequested blocks/transactions (5)
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
misbehaviorScore NonContinuousHeaders     = 20   -- Headers not connected (proportional)
misbehaviorScore ChecksumMismatch         = 10
misbehaviorScore PayloadTooLarge          = 10
misbehaviorScore DuplicateVersion         = 1
misbehaviorScore (ProtocolViolation _)    = 10
misbehaviorScore HeadersDontConnect       = 20   -- Headers don't connect to chain
misbehaviorScore BlockDownloadStall       = 50   -- Block download stalling
misbehaviorScore UnrequestedData          = 5    -- Sending unrequested data

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
-- BIP155 ADDRv2 - Variable-length address support
-- Supports Tor v3, I2P, and CJDNS addresses
--------------------------------------------------------------------------------

-- | BIP155 network identifiers
-- Each network has a specific address length
data NetworkId
  = NetIPv4    -- ^ 1: IPv4 (4 bytes)
  | NetIPv6    -- ^ 2: IPv6 (16 bytes)
  | NetTorV3   -- ^ 4: Tor v3 onion service (32 bytes, ed25519 pubkey)
  | NetI2P     -- ^ 5: I2P (32 bytes, SHA256 of destination)
  | NetCJDNS   -- ^ 6: CJDNS (16 bytes, starts with 0xFC)
  deriving (Show, Eq, Ord, Enum, Bounded, Generic)

instance NFData NetworkId

-- | Network ID to wire format
networkIdToWord8 :: NetworkId -> Word8
networkIdToWord8 NetIPv4  = 1
networkIdToWord8 NetIPv6  = 2
networkIdToWord8 NetTorV3 = 4
networkIdToWord8 NetI2P   = 5
networkIdToWord8 NetCJDNS = 6

-- | Wire format to network ID
word8ToNetworkId :: Word8 -> Maybe NetworkId
word8ToNetworkId 1 = Just NetIPv4
word8ToNetworkId 2 = Just NetIPv6
word8ToNetworkId 4 = Just NetTorV3
word8ToNetworkId 5 = Just NetI2P
word8ToNetworkId 6 = Just NetCJDNS
word8ToNetworkId _ = Nothing

-- | Expected address length for each network type
networkIdAddrLen :: NetworkId -> Int
networkIdAddrLen NetIPv4  = 4
networkIdAddrLen NetIPv6  = 16
networkIdAddrLen NetTorV3 = 32
networkIdAddrLen NetI2P   = 32
networkIdAddrLen NetCJDNS = 16

-- | Compact size serialization alias (using VarInt)
-- In BIP155, services are encoded as CompactSize instead of fixed uint64
type CompactSize = Word64

-- | ADT for variable-length network addresses
-- Supports all BIP155 address types
data NetAddr
  = NetAddrIPv4  !Word32                     -- ^ IPv4 address (4 bytes)
  | NetAddrIPv6  !ByteString                 -- ^ IPv6 address (16 bytes)
  | NetAddrTorV3 !ByteString                 -- ^ Tor v3 onion (32 bytes ed25519 pubkey)
  | NetAddrI2P   !ByteString                 -- ^ I2P address (32 bytes)
  | NetAddrCJDNS !ByteString                 -- ^ CJDNS address (16 bytes)
  deriving (Show, Eq, Generic)

instance NFData NetAddr

-- | Get network ID for a NetAddr
netAddrNetworkId :: NetAddr -> NetworkId
netAddrNetworkId (NetAddrIPv4 _)  = NetIPv4
netAddrNetworkId (NetAddrIPv6 _)  = NetIPv6
netAddrNetworkId (NetAddrTorV3 _) = NetTorV3
netAddrNetworkId (NetAddrI2P _)   = NetI2P
netAddrNetworkId (NetAddrCJDNS _) = NetCJDNS

-- | Get raw bytes from NetAddr
netAddrBytes :: NetAddr -> ByteString
netAddrBytes (NetAddrIPv4 w)  = runPut $ putWord32be w
netAddrBytes (NetAddrIPv6 bs) = bs
netAddrBytes (NetAddrTorV3 bs) = bs
netAddrBytes (NetAddrI2P bs) = bs
netAddrBytes (NetAddrCJDNS bs) = bs

-- | Check if address is compatible with legacy addr message (IPv4/IPv6 only)
isAddrV1Compatible :: NetAddr -> Bool
isAddrV1Compatible (NetAddrIPv4 _) = True
isAddrV1Compatible (NetAddrIPv6 _) = True
isAddrV1Compatible _               = False

-- | ADDRv2 entry (BIP155)
-- Unlike legacy AddrEntry, services is CompactSize-encoded
data AddrV2 = AddrV2
  { av2Time     :: !Word32        -- ^ Unix timestamp when last seen
  , av2Services :: !CompactSize   -- ^ Services (CompactSize encoded)
  , av2NetId    :: !NetworkId     -- ^ Network type
  , av2Addr     :: !ByteString    -- ^ Variable-length address bytes
  , av2Port     :: !Word16        -- ^ Port number
  } deriving (Show, Eq, Generic)

instance NFData AddrV2

instance Serialize AddrV2 where
  put AddrV2{..} = do
    putWord32le av2Time
    putVarInt av2Services       -- CompactSize for services
    putWord8 (networkIdToWord8 av2NetId)
    putVarInt (fromIntegral $ BS.length av2Addr)  -- Address length as CompactSize
    putByteString av2Addr
    putWord16be av2Port         -- Port is big-endian
  get = do
    time <- getWord32le
    services <- getVarInt'      -- CompactSize for services
    netIdByte <- getWord8
    addrLen <- getVarInt'       -- Address length as CompactSize
    addr <- getBytes (fromIntegral addrLen)
    port <- getWord16be
    -- Validate network ID and address length
    case word8ToNetworkId netIdByte of
      Just netId
        | fromIntegral addrLen == networkIdAddrLen netId ->
            return $ AddrV2 time services netId addr port
        | otherwise ->
            fail $ "Invalid address length " ++ show addrLen ++
                   " for network " ++ show netId
      Nothing ->
        -- Unknown network ID - skip (BIP155 forward compatibility)
        fail $ "Unknown network ID: " ++ show netIdByte

-- | ADDRv2 message - list of addrv2 entries
newtype AddrV2Msg = AddrV2Msg { getAddrV2List :: [AddrV2] }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serialize AddrV2Msg where
  put (AddrV2Msg as) = do
    putVarInt (fromIntegral $ length as)
    mapM_ put as
  get = do
    n <- getVarInt'
    AddrV2Msg <$> replicateM (fromIntegral n) get

-- | SendAddrV2 message - signals support for addrv2 (BIP155)
-- Must be sent between version and verack
data SendAddrV2 = SendAddrV2
  deriving (Show, Eq, Generic)

instance NFData SendAddrV2

instance Serialize SendAddrV2 where
  put _ = return ()
  get = return SendAddrV2

-- | Convert legacy NetworkAddress to NetAddr
networkAddressToNetAddr :: NetworkAddress -> Maybe NetAddr
networkAddressToNetAddr na =
  let bs = naAddress na
  in if BS.length bs /= 16
     then Nothing
     else -- Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x)
          let ipv4Prefix = BS.pack [0,0,0,0,0,0,0,0,0,0,0xff,0xff]
          in if BS.take 12 bs == ipv4Prefix
             then -- Extract IPv4 from last 4 bytes
                  case runGet getWord32be (BS.drop 12 bs) of
                    Right w -> Just $ NetAddrIPv4 w
                    Left _  -> Nothing
             else Just $ NetAddrIPv6 bs

-- | Convert NetAddr to legacy NetworkAddress (if compatible)
netAddrToNetworkAddress :: NetAddr -> Word64 -> Word16 -> Maybe NetworkAddress
netAddrToNetworkAddress addr services port = case addr of
  NetAddrIPv4 w ->
    -- Encode as IPv4-mapped IPv6: ::ffff:x.x.x.x
    let ipv4Prefix = BS.pack [0,0,0,0,0,0,0,0,0,0,0xff,0xff]
        ipv4Bytes = runPut $ putWord32be w
    in Just $ NetworkAddress services (BS.append ipv4Prefix ipv4Bytes) port
  NetAddrIPv6 bs ->
    Just $ NetworkAddress services bs port
  _ -> Nothing  -- Tor/I2P/CJDNS not compatible with v1

-- | Convert AddrV2 to AddrEntry (if compatible)
addrV2ToAddrEntry :: AddrV2 -> Maybe AddrEntry
addrV2ToAddrEntry av2 = do
  let netId = av2NetId av2
      bs = av2Addr av2
  case netId of
    NetIPv4 -> do
      w <- either (const Nothing) Just $ runGet getWord32be bs
      let addr = netAddrToNetworkAddress (NetAddrIPv4 w) (av2Services av2) (av2Port av2)
      NetworkAddress services addrBs port <- addr
      return $ AddrEntry (av2Time av2) (NetworkAddress services addrBs port)
    NetIPv6 -> do
      let addr = netAddrToNetworkAddress (NetAddrIPv6 bs) (av2Services av2) (av2Port av2)
      NetworkAddress services addrBs port <- addr
      return $ AddrEntry (av2Time av2) (NetworkAddress services addrBs port)
    _ -> Nothing  -- Tor/I2P/CJDNS not convertible to legacy format

-- | Convert AddrEntry to AddrV2
addrEntryToAddrV2 :: AddrEntry -> AddrV2
addrEntryToAddrV2 ae =
  let na = aeAddress ae
      bs = naAddress na
      ipv4Prefix = BS.pack [0,0,0,0,0,0,0,0,0,0,0xff,0xff]
      (netId, addrBytes) =
        if BS.take 12 bs == ipv4Prefix
        then (NetIPv4, BS.drop 12 bs)
        else (NetIPv6, bs)
  in AddrV2
       { av2Time = aeTimestamp ae
       , av2Services = naServices na
       , av2NetId = netId
       , av2Addr = addrBytes
       , av2Port = naPort na
       }

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
-- BIP-331 Package Relay Messages
--------------------------------------------------------------------------------

-- | SendTxRcncl - negotiate transaction reconciliation (package relay)
-- Sent during version handshake to signal package relay support
data SendTxRcncl = SendTxRcncl
  { strVersion  :: !Word32    -- ^ Package relay protocol version
  , strSalt     :: !Word64    -- ^ Reconciliation salt
  } deriving (Show, Eq, Generic)

instance NFData SendTxRcncl

instance Serialize SendTxRcncl where
  put SendTxRcncl{..} = do
    putWord32le strVersion
    putWord64le strSalt
  get = SendTxRcncl <$> getWord32le <*> getWord64le

-- | AncPkgInfo - announce package information
-- Announces a transaction package to a peer
data AncPkgInfo = AncPkgInfo
  { apiWtxids :: ![Hash256]   -- ^ List of wtxids in the package (child last)
  } deriving (Show, Eq, Generic)

instance NFData AncPkgInfo

instance Serialize AncPkgInfo where
  put AncPkgInfo{..} = do
    putVarInt (fromIntegral $ length apiWtxids)
    mapM_ put apiWtxids
  get = do
    count <- getVarInt'
    AncPkgInfo <$> replicateM (fromIntegral count) get

-- | GetPkgTxns - request package transactions
-- Request specific transactions from a previously announced package
data GetPkgTxns = GetPkgTxns
  { gptPkgHash   :: !Hash256   -- ^ Package hash (from ancpkginfo)
  , gptIndices   :: ![Word16]  -- ^ Indices of requested transactions
  } deriving (Show, Eq, Generic)

instance NFData GetPkgTxns

instance Serialize GetPkgTxns where
  put GetPkgTxns{..} = do
    put gptPkgHash
    putVarInt (fromIntegral $ length gptIndices)
    mapM_ putWord16le gptIndices
  get = do
    h <- get
    count <- getVarInt'
    indices <- replicateM (fromIntegral count) getWord16le
    return $ GetPkgTxns h indices

-- | PkgTxns - package transactions response
-- Contains the requested transactions from a package
data PkgTxns = PkgTxns
  { ptPkgHash :: !Hash256     -- ^ Package hash
  , ptTxns    :: ![Tx]        -- ^ Requested transactions (in topological order)
  } deriving (Show, Eq, Generic)

instance NFData PkgTxns

instance Serialize PkgTxns where
  put PkgTxns{..} = do
    put ptPkgHash
    putVarInt (fromIntegral $ length ptTxns)
    mapM_ put ptTxns
  get = do
    h <- get
    count <- getVarInt'
    txns <- replicateM (fromIntegral count) get
    return $ PkgTxns h txns

-- | Compute package hash from wtxids
-- Package hash is SHA256(sorted wtxids concatenated)
computePackageHash :: [Hash256] -> Hash256
computePackageHash wtxids =
  let sorted = sortBy compareHashes wtxids
      concatenated = BS.concat $ map getHash256 sorted
  in doubleSHA256 concatenated
  where
    -- Compare hashes in reverse byte order (little-endian comparison)
    compareHashes (Hash256 a) (Hash256 b) =
      compare (BS.reverse a) (BS.reverse b)

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
    -- BIP152 Compact Blocks
  | MCmpctBlock !CmpctBlock
  | MGetBlockTxn !GetBlockTxn
  | MBlockTxn !BlockTxn
    -- BIP155 ADDRv2
  | MSendAddrV2                -- ^ Signal support for addrv2 (empty payload)
  | MAddrV2 !AddrV2Msg         -- ^ ADDRv2 message with variable-length addresses
    -- BIP339 wtxid relay
  | MWtxidRelay                 -- ^ Signal support for wtxid-based relay (empty payload)
    -- BIP37 Bloom Filter
  | MFilterLoad !ByteString     -- ^ Load a bloom filter
  | MFilterAdd !ByteString      -- ^ Add element to bloom filter
  | MFilterClear                -- ^ Clear bloom filter (empty payload)
  | MMerkleBlock !ByteString    -- ^ Filtered block with merkle proof
    -- BIP157/158 Compact Block Filters
  | MGetCFilters !ByteString    -- ^ Request compact block filters
  | MCFilter !ByteString        -- ^ Compact block filter
  | MGetCFHeaders !ByteString   -- ^ Request compact block filter headers
  | MCFHeaders !ByteString      -- ^ Compact block filter headers
  | MGetCFCheckpt !ByteString   -- ^ Request compact block filter checkpoints
  | MCFCheckpt !ByteString      -- ^ Compact block filter checkpoints
    -- BIP-330 Erlay reconciliation round-trip
  | MReqRecon !ReqRecon         -- ^ Request set reconciliation
  | MReconcilDiff !ReconcilDiff -- ^ Report reconciliation differences
  | MSketchExt !SketchExt      -- ^ Sketch extension for failed reconciliation
    -- BIP-331 Package Relay
  | MSendTxRcncl !SendTxRcncl  -- ^ Negotiate transaction reconciliation
  | MAncPkgInfo !AncPkgInfo    -- ^ Announce package information
  | MGetPkgTxns !GetPkgTxns    -- ^ Request package transactions
  | MPkgTxns !PkgTxns          -- ^ Package transactions
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
commandName (MCmpctBlock _) = "cmpctblock"
commandName (MGetBlockTxn _) = "getblocktxn"
commandName (MBlockTxn _)   = "blocktxn"
commandName MSendAddrV2     = "sendaddrv2"
commandName (MAddrV2 _)     = "addrv2"
commandName MWtxidRelay     = "wtxidrelay"
commandName (MFilterLoad _)  = "filterload"
commandName (MFilterAdd _)   = "filteradd"
commandName MFilterClear     = "filterclear"
commandName (MMerkleBlock _) = "merkleblock"
commandName (MGetCFilters _) = "getcfilters"
commandName (MCFilter _)     = "cfilter"
commandName (MGetCFHeaders _) = "getcfheaders"
commandName (MCFHeaders _)   = "cfheaders"
commandName (MGetCFCheckpt _) = "getcfcheckpt"
commandName (MCFCheckpt _)   = "cfcheckpt"
commandName (MReqRecon _)    = "reqrecon"
commandName (MReconcilDiff _) = "reconcildiff"
commandName (MSketchExt _)   = "sketchext"
commandName (MSendTxRcncl _) = "sendtxrcncl"
commandName (MAncPkgInfo _) = "ancpkginfo"
commandName (MGetPkgTxns _) = "getpkgtxns"
commandName (MPkgTxns _)    = "pkgtxns"

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
encodePayload (MCmpctBlock c) = encode c
encodePayload (MGetBlockTxn g) = encode g
encodePayload (MBlockTxn b)   = encode b
encodePayload MSendAddrV2     = BS.empty
encodePayload (MAddrV2 a)     = encode a
encodePayload MWtxidRelay     = BS.empty
encodePayload (MFilterLoad d)  = d
encodePayload (MFilterAdd d)   = d
encodePayload MFilterClear     = BS.empty
encodePayload (MMerkleBlock d) = d
encodePayload (MGetCFilters d) = d
encodePayload (MCFilter d)     = d
encodePayload (MGetCFHeaders d) = d
encodePayload (MCFHeaders d)   = d
encodePayload (MGetCFCheckpt d) = d
encodePayload (MCFCheckpt d)   = d
encodePayload (MReqRecon r)    = encode r
encodePayload (MReconcilDiff d) = encode d
encodePayload (MSketchExt s)   = encode s
encodePayload (MSendTxRcncl s) = encode s
encodePayload (MAncPkgInfo a)  = encode a
encodePayload (MGetPkgTxns g)  = encode g
encodePayload (MPkgTxns p)     = encode p

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
  "cmpctblock"  -> MCmpctBlock <$> decode payload
  "getblocktxn" -> MGetBlockTxn <$> decode payload
  "blocktxn"    -> MBlockTxn <$> decode payload
  "sendaddrv2"  -> Right MSendAddrV2
  "addrv2"      -> MAddrV2 <$> decode payload
  "wtxidrelay"  -> Right MWtxidRelay
  "filterload"  -> Right $ MFilterLoad payload
  "filteradd"   -> Right $ MFilterAdd payload
  "filterclear" -> Right MFilterClear
  "merkleblock" -> Right $ MMerkleBlock payload
  "getcfilters" -> Right $ MGetCFilters payload
  "cfilter"     -> Right $ MCFilter payload
  "getcfheaders" -> Right $ MGetCFHeaders payload
  "cfheaders"   -> Right $ MCFHeaders payload
  "getcfcheckpt" -> Right $ MGetCFCheckpt payload
  "cfcheckpt"   -> Right $ MCFCheckpt payload
  "reqrecon"    -> MReqRecon <$> decode payload
  "reconcildiff" -> MReconcilDiff <$> decode payload
  "sketchext"   -> MSketchExt <$> decode payload
  "sendtxrcncl" -> MSendTxRcncl <$> decode payload
  "ancpkginfo"  -> MAncPkgInfo <$> decode payload
  "getpkgtxns"  -> MGetPkgTxns <$> decode payload
  "pkgtxns"     -> MPkgTxns <$> decode payload
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
  { piAddress            :: !SockAddr          -- ^ Peer's network address
  , piVersion            :: !(Maybe Version)   -- ^ Their version message
  , piState              :: !PeerState         -- ^ Current connection state
  , piServices           :: !Word64            -- ^ Services advertised by peer
  , piStartHeight        :: !Int32             -- ^ Best block height at connect
  , piRelay              :: !Bool              -- ^ Whether peer relays transactions
  , piLastSeen           :: !Int64             -- ^ Unix timestamp of last message
  , piLastPing           :: !(Maybe Word64)    -- ^ Nonce of last ping sent
  , piPingLatency        :: !(Maybe Double)    -- ^ Round-trip time in seconds
  , piBanScore           :: !Int               -- ^ Misbehavior score
  , piBytesSent          :: !Word64            -- ^ Total bytes sent
  , piBytesRecv          :: !Word64            -- ^ Total bytes received
  , piMsgsSent           :: !Word64            -- ^ Total messages sent
  , piMsgsRecv           :: !Word64            -- ^ Total messages received
  , piConnectedAt        :: !Int64             -- ^ Unix timestamp of connection
  , piInbound            :: !Bool              -- ^ True if peer connected to us
  , piWantsAddrV2        :: !Bool              -- ^ True if peer sent sendaddrv2 (BIP155)
    -- BIP133 Feefilter fields
  , piFeeFilterReceived  :: !Word64            -- ^ Fee filter received from peer (sat/kvB)
  , piFeeFilterSent      :: !Word64            -- ^ Fee filter we sent to peer (sat/kvB)
  , piNextFeeFilterSend  :: !Int64             -- ^ Timestamp for next feefilter send (microseconds)
  , piBlockOnly          :: !Bool              -- ^ True if block-relay-only connection
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
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just host) (Just (show port))
    case addrs of
      [] -> fail $ "Cannot resolve: " ++ host
      (addr:_) -> do
        sock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect sock (NS.addrAddress addr)
        now <- round <$> getPOSIXTime
        let info = PeerInfo
              { piAddress       = NS.addrAddress addr
              , piVersion       = Nothing
              , piState         = PeerConnecting
              , piServices      = 0
              , piStartHeight   = 0
              , piRelay              = True
              , piLastSeen           = now
              , piLastPing           = Nothing
              , piPingLatency        = Nothing
              , piBanScore           = 0
              , piBytesSent          = 0
              , piBytesRecv          = 0
              , piMsgsSent           = 0
              , piMsgsRecv           = 0
              , piConnectedAt        = now
              , piInbound            = False
              , piWantsAddrV2        = False
              , piFeeFilterReceived  = 0
              , piFeeFilterSent      = 0
              , piNextFeeFilterSend  = 0
              , piBlockOnly          = False
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
-- Uses a 60-second timeout to detect dead connections
recvExact :: PeerConnection -> Int -> IO (Maybe ByteString)
recvExact pc n = do
  buf <- readIORef (pcReadBuffer pc)
  if BS.length buf >= n
    then do
      let (result, rest) = BS.splitAt n buf
      writeIORef (pcReadBuffer pc) rest
      return (Just result)
    else do
      -- Need more data - use timeout to avoid blocking forever on dead connections
      mResult <- timeout (60 * 1000000) $  -- 60 second timeout
        (Just <$> recv (pcSocket pc) (max 4096 (n - BS.length buf)))
          `catch` (\(_ :: IOException) -> return Nothing)
      case mResult of
        Nothing -> return Nothing  -- Timeout: peer unresponsive
        Just Nothing -> return Nothing  -- Connection closed or error
        Just (Just chunk)
          | BS.null chunk -> return Nothing  -- Connection closed
          | otherwise -> do
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
-- Protocol: we send version -> they send version -> feature negotiation -> both send verack
-- BIP155: sendaddrv2 must be sent between version and verack
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
          -- BIP155: Send sendaddrv2 BEFORE verack to signal addrv2 support
          sendMessage pc MSendAddrV2

          -- Send verack
          sendMessage pc MVerAck

          -- Handle pre-verack messages (sendaddrv2, etc.)
          -- Loop until we receive verack
          continueHandshake pc theirVersion

    Right other -> return $ Left $ "Expected version, got: " ++ msgTypeName other

-- | Continue handshake after version exchange, handling pre-verack feature messages
-- BIP155 requires handling sendaddrv2 between version and verack
continueHandshake :: PeerConnection -> Version -> IO (Either String Version)
continueHandshake pc theirVersion = do
  r <- receiveMessage pc
  case r of
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
      -- BIP133: Send initial feefilter (100 sat/vbyte = 100000 sat/kvB)
      when (vRelay theirVersion) $
        sendMessage pc (MFeeFilter (FeeFilter 100000))

      return $ Right theirVersion

    Right MSendAddrV2 -> do
      -- Peer signaled addrv2 support - record it and continue waiting for verack
      atomically $ modifyTVar' (pcInfo pc) $ \i ->
        i { piWantsAddrV2 = True }
      continueHandshake pc theirVersion

    Right other ->
      -- Unexpected message before verack (some peers may send other feature messages)
      -- For now, log and continue waiting for verack
      continueHandshake pc theirVersion

    Left err -> return $ Left $ "Verack failed: " ++ err

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
msgTypeName (MCmpctBlock _) = "cmpctblock"
msgTypeName (MGetBlockTxn _) = "getblocktxn"
msgTypeName (MBlockTxn _)   = "blocktxn"
msgTypeName MSendAddrV2     = "sendaddrv2"
msgTypeName (MAddrV2 _)     = "addrv2"

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
  recvTid <- forkIO $ fix $ \loop -> do
    result <- receiveMessage pc
    case result of
      Right msg -> do
        -- Update last seen timestamp
        now <- round <$> getPOSIXTime
        atomically $ modifyTVar' (pcInfo pc) (\i -> i { piLastSeen = now })
        -- Call handler (recv queue intentionally not used — handler is called
        -- directly to avoid blocking when the bounded queue fills up)
        handler msg
        loop
      Left err -> do
        disconnectPeer pc
        -- Do NOT loop after disconnect: socket is closed, further reads
        -- would spin indefinitely.

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
  { pmPeers              :: !(TVar (Map SockAddr PeerConnection))
  , pmKnownAddrs         :: !(TVar (Set.Set SockAddr))
  , pmBannedAddrs        :: !(TVar (Map SockAddr Int64))
  , pmConfig             :: !PeerManagerConfig
  , pmNetwork            :: !Network
  , pmBestHeight         :: !(TVar Int32)
  , pmManagerThread      :: !(TVar (Maybe ThreadId))
  , pmMessageHandler     :: !(SockAddr -> Message -> IO ())
  , pmFailedAddrs        :: !(TVar (Set.Set SockAddr))  -- ^ Addresses that failed to connect
  , pmLastDNSRefresh     :: !(TVar Int64)                -- ^ Last DNS re-discovery timestamp
  , pmOutboundDiversity  :: !OutboundDiversity            -- ^ Netgroup diversity tracker
  }

-- | Configuration for the peer manager
data PeerManagerConfig = PeerManagerConfig
  { pmcMaxOutbound      :: !Int        -- ^ Maximum full-relay outbound connections (default 8)
  , pmcMaxBlockRelayOnly :: !Int       -- ^ Maximum block-relay-only outbound connections (default 2)
  , pmcMaxInbound       :: !Int        -- ^ Maximum inbound connections (default 117)
  , pmcMaxTotal         :: !Int        -- ^ Maximum total connections (default 125)
  , pmcBanDuration      :: !Int64      -- ^ Ban duration in seconds (default 86400 = 24h)
  , pmcBanThreshold     :: !Int        -- ^ Ban score threshold (default 100)
  , pmcPingInterval     :: !Int        -- ^ Ping interval in seconds (default 120)
  , pmcConnectTimeout   :: !Int        -- ^ Connection timeout in seconds (default 5)
  , pmcDataDir          :: !FilePath   -- ^ Data directory for persistent state (anchors, etc.)
  } deriving (Show)

-- | Default peer manager configuration (matches Bitcoin Core defaults)
defaultPeerManagerConfig :: PeerManagerConfig
defaultPeerManagerConfig = PeerManagerConfig
  { pmcMaxOutbound      = 8
  , pmcMaxBlockRelayOnly = 2
  , pmcMaxInbound       = 117
  , pmcMaxTotal         = 125
  , pmcBanDuration      = 86400    -- 24 hours
  , pmcBanThreshold     = 100
  , pmcPingInterval     = 120      -- 2 minutes
  , pmcConnectTimeout   = 5
  , pmcDataDir          = "."
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
      let hints = defaultHints { NS.addrFamily = AF_INET, NS.addrSocketType = Stream }
      addrInfos <- getAddrInfo (Just hints) (Just seed) (Just (show (netDefaultPort net)))
      return $ map NS.addrAddress addrInfos
    case result of
      Left _     -> return []
      Right addrs -> return addrs
  let discovered = concat results
  -- Fall back to hardcoded addresses if DNS resolution fails
  -- Regtest uses no seeds at all (matches Bitcoin Core CRegTestParams)
  if null discovered
    then case netDefaultPort net of
           8333  -> return fallbackMainnetPeers
           18444 -> return []  -- regtest: no seeds, peers added via addnode
           _     -> return fallbackTestnetPeers
    else return discovered

--------------------------------------------------------------------------------
-- Peer Manager Operations
--------------------------------------------------------------------------------

-- | Start the peer manager background thread
startPeerManager :: Network -> PeerManagerConfig
                 -> (SockAddr -> Message -> IO ()) -> IO PeerManager
startPeerManager net config handler = do
  od <- newOutboundDiversity
  pm <- PeerManager
    <$> newTVarIO Map.empty
    <*> newTVarIO Set.empty
    <*> newTVarIO Map.empty
    <*> pure config
    <*> pure net
    <*> newTVarIO 0
    <*> newTVarIO Nothing
    <*> pure handler
    <*> newTVarIO Set.empty
    <*> newTVarIO 0
    <*> pure od

  -- Load anchor connections from previous session
  let anchorsPath = pmcDataDir config </> "anchors.json"
  anchors <- loadAnchors anchorsPath
  unless (null anchors) $
    putStrLn $ "startPeerManager: loaded " ++ show (length anchors) ++
               " anchor(s), connecting as block-relay-only"
  forM_ anchors $ \ac ->
    void $ forkIO $ tryConnectBlockRelay pm (acAddress ac)

  tid <- forkIO $ peerManagerLoop pm
  atomically $ writeTVar (pmManagerThread pm) (Just tid)
  return pm

-- | Stop the peer manager and disconnect all peers
stopPeerManager :: PeerManager -> IO ()
stopPeerManager pm = do
  -- Save block-relay-only peers as anchors before disconnecting
  peers <- readTVarIO (pmPeers pm)
  anchorAddrs <- forM (Map.toList peers) $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)
    return (addr, piBlockOnly info, piServices info)
  let blockRelayAnchors = [ AnchorConnection addr svcs
                          | (addr, isBlock, svcs) <- anchorAddrs
                          , isBlock
                          ]
  let anchorsPath = pmcDataDir (pmConfig pm) </> "anchors.json"
  saveAnchors anchorsPath blockRelayAnchors
  unless (null blockRelayAnchors) $
    putStrLn $ "stopPeerManager: saved " ++ show (length blockRelayAnchors) ++ " anchor(s)"

  mTid <- readTVarIO (pmManagerThread pm)
  mapM_ killThread mTid
  mapM_ disconnectPeer (Map.elems peers)

-- | Main peer manager loop - maintains connections and handles timeouts
peerManagerLoop :: PeerManager -> IO ()
peerManagerLoop pm = forever $ do
  -- Clean up disconnected peers from the map
  allPeers <- readTVarIO (pmPeers pm)
  forM_ (Map.toList allPeers) $ \(addr, pc) -> do
    peerInfo <- readTVarIO (pcInfo pc)
    when (piState peerInfo == PeerDisconnected) $ do
      -- Remove from netgroup diversity tracker if outbound
      unless (piInbound peerInfo) $
        removeOutboundConnection (pmOutboundDiversity pm) addr
      atomically $ modifyTVar' (pmPeers pm) (Map.delete addr)

  -- Maintain target outbound connections (8 full-relay + 2 block-relay-only)
  peers <- readTVarIO (pmPeers pm)

  -- Count full-relay and block-relay-only outbound peers separately
  peerInfos <- forM (Map.toList peers) $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)
    return (addr, info)
  let fullRelayCount = length [ () | (_, info) <- peerInfos
                              , not (piInbound info), not (piBlockOnly info) ]
      blockRelayCount = length [ () | (_, info) <- peerInfos
                               , not (piInbound info), piBlockOnly info ]
      fullRelayTarget = pmcMaxOutbound (pmConfig pm)
      blockRelayTarget = pmcMaxBlockRelayOnly (pmConfig pm)
      totalTarget = fullRelayTarget + blockRelayTarget

  let outboundCount = fullRelayCount + blockRelayCount
  when (outboundCount < totalTarget) $ do
    known <- readTVarIO (pmKnownAddrs pm)
    banned <- readTVarIO (pmBannedAddrs pm)
    failed <- readTVarIO (pmFailedAddrs pm)
    lastDNS <- readTVarIO (pmLastDNSRefresh pm)
    now <- round <$> getPOSIXTime

    -- Filter out expired bans
    let activeBans = Map.filter (> now) banned
        connected = Map.keysSet peers
        -- Exclude connected, banned, AND recently-failed addresses
        candidates = Set.toList $
          Set.difference known (Set.unions [connected, Map.keysSet activeBans, failed])

    -- Re-discover via DNS if no viable candidates OR every 120 seconds
    candidates' <- if null candidates || (now - lastDNS > 120)
      then do
        putStrLn $ "peerManagerLoop: discovering peers via DNS..."
        discovered <- discoverPeers (pmNetwork pm)
        putStrLn $ "peerManagerLoop: discovered " ++ show (length discovered) ++ " peers"
        atomically $ do
          modifyTVar' (pmKnownAddrs pm) (Set.union (Set.fromList discovered))
          -- Clear failed set on DNS refresh so we retry previously-failed addresses
          writeTVar (pmFailedAddrs pm) Set.empty
          writeTVar (pmLastDNSRefresh pm) now
        -- Recompute candidates with fresh data
        known' <- readTVarIO (pmKnownAddrs pm)
        let candidates2 = Set.toList $
              Set.difference known' (Set.union connected (Map.keysSet activeBans))
        if null candidates2
          then return discovered
          else return candidates2
      else return candidates

    -- Filter candidates by netgroup diversity (eclipse attack mitigation)
    let od = pmOutboundDiversity pm
    diverseCandidates <- filterM (checkOutboundDiversity od) candidates'

    -- Fill full-relay slots first, then block-relay-only
    let fullRelayNeeded = max 0 (fullRelayTarget - fullRelayCount)
        blockRelayNeeded = max 0 (blockRelayTarget - blockRelayCount)
        (forFullRelay, rest) = splitAt fullRelayNeeded diverseCandidates
        forBlockRelay = take blockRelayNeeded rest

    unless (null forFullRelay) $
      putStrLn $ "peerManagerLoop: connecting " ++ show (length forFullRelay) ++ " full-relay"
    mapM_ (void . forkIO . tryConnect pm) forFullRelay

    unless (null forBlockRelay) $
      putStrLn $ "peerManagerLoop: connecting " ++ show (length forBlockRelay) ++ " block-relay-only"
    mapM_ (void . forkIO . tryConnectBlockRelay pm) forBlockRelay

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
tryConnect pm addr = tryConnectWithType pm addr False

-- | Try to connect as a block-relay-only peer (no tx relay, no addr exchange)
tryConnectBlockRelay :: PeerManager -> SockAddr -> IO ()
tryConnectBlockRelay pm addr = tryConnectWithType pm addr True

-- | Internal: connect to a peer with optional block-relay-only mode
tryConnectWithType :: PeerManager -> SockAddr -> Bool -> IO ()
tryConnectWithType pm addr blockRelayOnly = do
  -- Check if address is discouraged/banned before connecting
  discouraged <- isDiscouraged pm addr
  unless discouraged $ do
    let net = pmNetwork pm
        config = PeerConfig
          { pcfgNetwork     = net
          , pcfgServices    = combineServices [nodeNetwork, nodeWitness]
          , pcfgBestHeight  = 0
          , pcfgUserAgent   = userAgent
          , pcfgRelay       = not blockRelayOnly  -- block-relay-only: no tx relay
          , pcfgConnTimeout = pmcConnectTimeout (pmConfig pm)
          , pcfgQueueSize   = 100
          }
        -- Extract host and port from SockAddr
        (host, port) = sockAddrToHostPort addr (netDefaultPort net)
        connLabel = if blockRelayOnly then "block-relay-only" else "full-relay"

    putStrLn $ "tryConnect[" ++ connLabel ++ "]: attempting " ++ host ++ ":" ++ show port
    result <- connectPeer config host port
    case result of
      Left err -> do
        putStrLn $ "tryConnect: connect failed to " ++ host ++ ": " ++ err
        -- Track this address as failed so we don't keep retrying it
        atomically $ modifyTVar' (pmFailedAddrs pm) (Set.insert addr)
      Right pc -> do
        putStrLn $ "tryConnect: connected to " ++ host ++ ", starting handshake..."
        hsResult <- performHandshake config pc
        case hsResult of
          Left err -> do
            putStrLn $ "tryConnect: handshake failed with " ++ host ++ ": " ++ err
            disconnectPeer pc
            atomically $ modifyTVar' (pmFailedAddrs pm) (Set.insert addr)
          Right ver -> do
            -- Verify peer supports required services
            unless (hasService (vServices ver) nodeNetwork) $ disconnectPeer pc

            -- Mark as block-relay-only if requested
            when blockRelayOnly $
              atomically $ modifyTVar' (pcInfo pc) (\i -> i { piBlockOnly = True })

            -- Track netgroup diversity for outbound connections
            addOutboundConnection (pmOutboundDiversity pm) addr

            -- Add to peer map
            atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc)

            -- Start peer threads with message handler
            pc' <- startPeerThreads pc (pmMessageHandler pm addr)
            atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc')

            -- Only request addresses from full-relay peers (not block-relay-only)
            unless blockRelayOnly $
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

-- | Start a TCP listener for inbound P2P connections
startInboundListener :: PeerManager -> Int -> IO ()
startInboundListener pm port = do
  let hints = defaultHints { NS.addrSocketType = Stream }
  addrInfos <- getAddrInfo (Just hints) (Just "0.0.0.0") (Just (show port))
  case addrInfos of
    [] -> putStrLn $ "startInboundListener: cannot resolve bind address for port " ++ show port
    (addrInfo:_) -> do
      sock <- socket (NS.addrFamily addrInfo) (NS.addrSocketType addrInfo) (NS.addrProtocol addrInfo)
      setSocketOption sock ReuseAddr 1
      bind sock (NS.addrAddress addrInfo)
      listen sock 128
      putStrLn $ "P2P listener started on port " ++ show port
      void $ forkIO $ acceptLoop sock
  where
    acceptLoop :: Socket -> IO ()
    acceptLoop listenSock = forever $ do
      (clientSock, clientAddr) <- accept listenSock
      void $ forkIO $ handleInbound clientSock clientAddr
        `catch` (\(e :: SomeException) -> do
          putStrLn $ "Inbound connection error from " ++ show clientAddr ++ ": " ++ show e
          close clientSock)

    handleInbound :: Socket -> SockAddr -> IO ()
    handleInbound sock addr = do
      now <- round <$> getPOSIXTime
      let info = PeerInfo
            { piAddress       = addr
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
            , piInbound       = True
            , piWantsAddrV2   = False
            , piFeeFilterReceived = 0
            , piFeeFilterSent     = 0
            , piNextFeeFilterSend = 0
            , piBlockOnly     = False
            }
      infoVar <- newTVarIO info
      sendQ <- newTBQueueIO 100
      recvQ <- newTBQueueIO 100
      bufRef <- newIORef BS.empty
      let pc = PeerConnection
            { pcSocket      = sock
            , pcInfo        = infoVar
            , pcSendQueue   = sendQ
            , pcRecvQueue   = recvQ
            , pcSendThread  = Nothing
            , pcRecvThread  = Nothing
            , pcNetwork     = pmNetwork pm
            , pcReadBuffer  = bufRef
            }
      -- Perform inbound handshake (receive version first, then send ours)
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
      hsResult <- performHandshake config pc
      case hsResult of
        Left err -> do
          putStrLn $ "Inbound handshake failed from " ++ show addr ++ ": " ++ err
          close sock
        Right _ver -> do
          atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc)
          pc' <- startPeerThreads pc (pmMessageHandler pm addr)
          atomically $ modifyTVar' (pmPeers pm) (Map.insert addr pc')
          putStrLn $ "Accepted inbound connection from " ++ show addr

-- | Connect to a peer by host:port string (for addnode RPC)
addNodeConnect :: PeerManager -> String -> Int -> IO ()
addNodeConnect pm host port = do
  addrInfos <- getAddrInfo Nothing (Just host) (Just (show port)) :: IO [NS.AddrInfo]
  case addrInfos of
    [] -> putStrLn $ "addNodeConnect: cannot resolve " ++ host
    (ai:_) -> tryConnect pm (NS.addrAddress ai)

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

--------------------------------------------------------------------------------
-- Inv Trickling Constants (matches Bitcoin Core net_processing.cpp)
--------------------------------------------------------------------------------

-- | Average delay between trickled inventory transmissions for inbound peers (5 seconds)
-- Blocks and whitelisted peers bypass trickling.
-- Reference: Bitcoin Core INBOUND_INVENTORY_BROADCAST_INTERVAL
inboundInventoryBroadcastInterval :: Int64
inboundInventoryBroadcastInterval = 5 * 1000000  -- microseconds

-- | Average delay between trickled inventory transmissions for outbound peers (2 seconds)
-- Shorter delay for outbound as there is less privacy concern.
-- Reference: Bitcoin Core OUTBOUND_INVENTORY_BROADCAST_INTERVAL
outboundInventoryBroadcastInterval :: Int64
outboundInventoryBroadcastInterval = 2 * 1000000  -- microseconds

-- | Maximum rate of inventory items to send per second
-- Limits the impact of low-fee transaction floods.
-- Reference: Bitcoin Core INVENTORY_BROADCAST_PER_SECOND
inventoryBroadcastPerSecond :: Int
inventoryBroadcastPerSecond = 14

-- | Target number of tx inventory items to send per transmission
-- INVENTORY_BROADCAST_PER_SECOND * 5 seconds = 70
-- Reference: Bitcoin Core INVENTORY_BROADCAST_TARGET
inventoryBroadcastTarget :: Int
inventoryBroadcastTarget = 70  -- 14 * 5

-- | Maximum number of inventory items to send per transmission
-- Reference: Bitcoin Core INVENTORY_BROADCAST_MAX
inventoryBroadcastMax :: Int
inventoryBroadcastMax = 1000

--------------------------------------------------------------------------------
-- Inv Trickling Configuration
--------------------------------------------------------------------------------

-- | Configuration for inventory trickling
data TrickleConfig = TrickleConfig
  { tcInboundInterval  :: !Int64   -- ^ Average interval for inbound peers (microseconds)
  , tcOutboundInterval :: !Int64   -- ^ Average interval for outbound peers (microseconds)
  , tcBroadcastTarget  :: !Int     -- ^ Target items per transmission
  , tcBroadcastMax     :: !Int     -- ^ Maximum items per transmission
  } deriving (Show, Eq)

-- | Default trickling configuration (matches Bitcoin Core)
defaultTrickleConfig :: TrickleConfig
defaultTrickleConfig = TrickleConfig
  { tcInboundInterval  = inboundInventoryBroadcastInterval
  , tcOutboundInterval = outboundInventoryBroadcastInterval
  , tcBroadcastTarget  = inventoryBroadcastTarget
  , tcBroadcastMax     = inventoryBroadcastMax
  }

--------------------------------------------------------------------------------
-- BIP133 Feefilter Constants
--------------------------------------------------------------------------------

-- | Average delay between feefilter broadcasts (10 minutes)
-- Reference: Bitcoin Core AVG_FEEFILTER_BROADCAST_INTERVAL
avgFeeFilterBroadcastInterval :: Int64
avgFeeFilterBroadcastInterval = 10 * 60 * 1000000  -- microseconds

-- | Maximum delay after significant fee filter change (5 minutes)
-- If the mempool min fee changes substantially (>= 25%), shorten the delay.
-- Reference: Bitcoin Core MAX_FEEFILTER_CHANGE_DELAY
maxFeeFilterChangeDelay :: Int64
maxFeeFilterChangeDelay = 5 * 60 * 1000000  -- microseconds

-- | Calculate fee in satoshis for a given vsize at a fee rate (sat/kvB)
-- feeRate is in sat/1000vB, so fee = feeRate * vsize / 1000
feeAtRate :: Word64 -> Int -> Word64
feeAtRate feeRate vsize = (feeRate * fromIntegral vsize) `div` 1000

--------------------------------------------------------------------------------
-- Poisson-Distributed Delay
--------------------------------------------------------------------------------

-- | Generate a Poisson-distributed delay in microseconds
-- Uses the inverse transform method: delay = -ln(U) * mean
-- where U is uniformly distributed in (0, 1]
-- Reference: Bitcoin Core random.cpp MakeExponentiallyDistributed
poissonDelay :: Int64 -> IO Int64
poissonDelay meanMicros = do
  -- Generate uniform random in (0, 1] to avoid log(0)
  u <- randomRIO (1e-10, 1.0) :: IO Double
  let scaled = negate (log u) * fromIntegral meanMicros
  return $ round scaled

--------------------------------------------------------------------------------
-- Per-Peer Inventory Tracking
--------------------------------------------------------------------------------

-- | A pending inventory item with fee rate for prioritization
data PendingInv = PendingInv
  { piTxId     :: !TxId      -- ^ Transaction ID
  , piFeeRate  :: !Word64    -- ^ Fee rate in sat/vB (for prioritization)
  , piAddedAt  :: !Int64     -- ^ Timestamp when queued (microseconds)
  } deriving (Show, Eq)

instance Ord PendingInv where
  -- Higher fee rate = higher priority (sort descending)
  compare a b = compare (piFeeRate b) (piFeeRate a)

-- | Per-peer inventory trickling state
data PeerTrickleState = PeerTrickleState
  { ptsNextSendTime  :: !(TVar Int64)          -- ^ Next scheduled send time (microseconds)
  , ptsPendingInvs   :: !(TVar (Set.Set PendingInv))  -- ^ Queued inventory items
  , ptsSentFilter    :: !(TVar (Set.Set TxId))  -- ^ Bloom filter of recently sent txids
  } deriving (Eq)

-- | Create new per-peer trickle state
newPeerTrickleState :: IO PeerTrickleState
newPeerTrickleState = do
  now <- round . (* 1000000) <$> getPOSIXTime
  PeerTrickleState
    <$> newTVarIO now
    <*> newTVarIO Set.empty
    <*> newTVarIO Set.empty

--------------------------------------------------------------------------------
-- Inventory Trickler
--------------------------------------------------------------------------------

-- | Central inventory trickler that manages all peer trickling
data InvTrickler = InvTrickler
  { itConfig        :: !TrickleConfig
  , itPeerStates    :: !(TVar (Map SockAddr PeerTrickleState))
  , itInboundTimer  :: !(TVar Int64)  -- ^ Shared timer for inbound peers (privacy)
  , itTrickleThread :: !(TVar (Maybe ThreadId))
  , itGetPeerInfo   :: SockAddr -> IO (Maybe (PeerConnection, PeerInfo))
  , itSendToPeer    :: SockAddr -> Message -> IO ()
  }

-- | Create a new inventory trickler
newInvTrickler :: TrickleConfig
               -> (SockAddr -> IO (Maybe (PeerConnection, PeerInfo)))
               -> (SockAddr -> Message -> IO ())
               -> IO InvTrickler
newInvTrickler config getPeerInfo sendToPeer = do
  now <- round . (* 1000000) <$> getPOSIXTime
  InvTrickler config
    <$> newTVarIO Map.empty
    <*> newTVarIO now
    <*> newTVarIO Nothing
    <*> pure getPeerInfo
    <*> pure sendToPeer

-- | Queue a transaction for trickling to a specific peer
-- Transactions are batched and sent later according to the trickling schedule
queueTxForTrickling :: InvTrickler -> SockAddr -> TxId -> Word64 -> Bool -> IO ()
queueTxForTrickling trickler addr txid feeRate isWhitelisted = do
  -- Get or create peer trickle state
  state <- getOrCreatePeerState trickler addr

  if isWhitelisted
    then do
      -- Whitelisted peers get immediate broadcast (no trickling)
      let invVec = InvVector InvWitnessTx (getTxIdHash txid)
      itSendToPeer trickler addr (MInv (Inv [invVec]))
    else do
      -- Add to pending queue for later trickling
      now <- round . (* 1000000) <$> getPOSIXTime
      let pending = PendingInv txid feeRate now
      atomically $ modifyTVar' (ptsPendingInvs state) (Set.insert pending)

-- | Get or create peer trickle state
getOrCreatePeerState :: InvTrickler -> SockAddr -> IO PeerTrickleState
getOrCreatePeerState trickler addr = do
  states <- readTVarIO (itPeerStates trickler)
  case Map.lookup addr states of
    Just state -> return state
    Nothing -> do
      state <- newPeerTrickleState
      atomically $ modifyTVar' (itPeerStates trickler) (Map.insert addr state)
      return state

-- | Flush pending inventory for a peer if it's time to send
-- Returns the number of inv items sent
-- The peerFeeFilter parameter is the peer's BIP133 feefilter in sat/kvB (0 = no filter)
flushPeerInventory :: InvTrickler -> SockAddr -> Bool -> IO Int
flushPeerInventory trickler addr isInbound = flushPeerInventoryWithFilter trickler addr isInbound 0

-- | Flush pending inventory for a peer with feefilter applied
-- peerFeeFilter is in sat/kvB (from BIP133 feefilter message)
flushPeerInventoryWithFilter :: InvTrickler -> SockAddr -> Bool -> Word64 -> IO Int
flushPeerInventoryWithFilter trickler addr isInbound peerFeeFilter = do
  now <- round . (* 1000000) <$> getPOSIXTime
  let config = itConfig trickler

  mState <- Map.lookup addr <$> readTVarIO (itPeerStates trickler)
  case mState of
    Nothing -> return 0
    Just state -> do
      -- Check if it's time to send
      nextSend <- readTVarIO (ptsNextSendTime state)
      if now < nextSend
        then return 0  -- Not time yet
        else do
          -- Get pending items
          pending <- readTVarIO (ptsPendingInvs state)
          if Set.null pending
            then do
              -- No items to send, but schedule next check
              scheduleNextSend trickler state isInbound now
              return 0
            else do
              -- Filter out already-sent items
              sent <- readTVarIO (ptsSentFilter state)
              let unsent = Set.filter (\p -> not $ Set.member (piTxId p) sent) pending

              -- BIP133: Filter out transactions below peer's fee filter
              -- piFeeRate is in sat/vB, peerFeeFilter is in sat/kvB
              -- Convert: feeRate (sat/vB) * 1000 = sat/kvB
              let aboveFeeFilter p = peerFeeFilter == 0 ||
                                      piFeeRate p * 1000 >= peerFeeFilter
                  filtered = Set.filter aboveFeeFilter unsent

              -- Calculate broadcast limit with bonus for queue depth
              -- Bitcoin Core: broadcast_max = target + (queue_size / 1000) * 5
              let queueSize = Set.size filtered
                  bonus = (queueSize `div` 1000) * 5
                  broadcastLimit = min (tcBroadcastMax config)
                                       (tcBroadcastTarget config + bonus)

              -- Take highest fee-rate items up to limit
              -- Items are already sorted by fee rate (descending) due to Ord instance
              let toSend = take broadcastLimit $ Set.toDescList filtered
                  txIds = map piTxId toSend

              -- Build and send inv message
              unless (null txIds) $ do
                let invVecs = map (\tid -> InvVector InvWitnessTx (getTxIdHash tid)) txIds
                itSendToPeer trickler addr (MInv (Inv invVecs))

                -- Update sent filter and remove from pending
                atomically $ do
                  let sentTxIds = Set.fromList txIds
                  modifyTVar' (ptsSentFilter state) (Set.union sentTxIds)
                  modifyTVar' (ptsPendingInvs state) $ \ps ->
                    Set.filter (\p -> not $ Set.member (piTxId p) sentTxIds) ps

              -- Schedule next send
              scheduleNextSend trickler state isInbound now
              return (length txIds)

-- | Schedule the next send time for a peer
scheduleNextSend :: InvTrickler -> PeerTrickleState -> Bool -> Int64 -> IO ()
scheduleNextSend trickler state isInbound now = do
  let config = itConfig trickler

  if isInbound
    then do
      -- Inbound peers share a common timer for privacy
      -- This prevents fingerprinting by correlating inv timing across connections
      sharedTimer <- readTVarIO (itInboundTimer trickler)
      if sharedTimer < now
        then do
          -- Advance shared timer
          delay <- poissonDelay (tcInboundInterval config)
          let newTimer = now + delay
          atomically $ do
            writeTVar (itInboundTimer trickler) newTimer
            writeTVar (ptsNextSendTime state) newTimer
        else
          atomically $ writeTVar (ptsNextSendTime state) sharedTimer
    else do
      -- Outbound peers have independent timers
      delay <- poissonDelay (tcOutboundInterval config)
      atomically $ writeTVar (ptsNextSendTime state) (now + delay)

-- | Start the trickle flush thread
-- This thread periodically flushes pending inventory for all peers
startTrickleThread :: InvTrickler -> PeerManager -> IO ThreadId
startTrickleThread trickler pm = do
  tid <- forkIO $ trickleLoop trickler pm
  atomically $ writeTVar (itTrickleThread trickler) (Just tid)
  return tid

-- | Main trickle loop - runs every 500ms and flushes ready peers
trickleLoop :: InvTrickler -> PeerManager -> IO ()
trickleLoop trickler pm = forever $ do
  -- Sleep 500ms between iterations
  threadDelay 500000

  -- Get all peer addresses
  peers <- readTVarIO (pmPeers pm)

  -- Flush inventory for each peer
  forM_ (Map.toList peers) $ \(addr, pc) -> do
    -- Get peer info to check if inbound and get fee filter
    info <- readTVarIO (pcInfo pc)
    when (piState info == PeerConnected && piRelay info && not (piBlockOnly info)) $ do
      -- BIP133: Apply peer's fee filter when flushing inventory
      void $ flushPeerInventoryWithFilter trickler addr (piInbound info) (piFeeFilterReceived info)
        `catch` (\(_ :: IOException) -> return 0)

-- | Clean up trickle state for a disconnected peer
removePeerTrickleState :: InvTrickler -> SockAddr -> IO ()
removePeerTrickleState trickler addr =
  atomically $ modifyTVar' (itPeerStates trickler) (Map.delete addr)

-- | Clear the sent filter for a peer (e.g., when reorg invalidates txs)
clearPeerSentFilter :: InvTrickler -> SockAddr -> IO ()
clearPeerSentFilter trickler addr = do
  mState <- Map.lookup addr <$> readTVarIO (itPeerStates trickler)
  case mState of
    Nothing -> return ()
    Just state -> atomically $ writeTVar (ptsSentFilter state) Set.empty

--------------------------------------------------------------------------------
-- BIP133 Feefilter Operations
-- Reference: Bitcoin Core net_processing.cpp MaybeSendFeefilter
--------------------------------------------------------------------------------

-- | Handle an incoming feefilter message from a peer
-- Updates the peer's feefilter which will be applied when relaying transactions
-- Returns True if the feefilter was accepted, False if invalid
handleFeeFilter :: TVar PeerInfo -> Word64 -> IO Bool
handleFeeFilter infoVar feeFilter = do
  -- BIP133: validate the fee filter is in money range
  -- MAX_MONEY = 21 million BTC in satoshis = 2100000000000000
  let maxMoney :: Word64
      maxMoney = 2100000000000000
  if feeFilter <= maxMoney
    then do
      atomically $ modifyTVar' infoVar $ \info ->
        info { piFeeFilterReceived = feeFilter }
      return True
    else return False

-- | Check if we should send a feefilter to a peer
-- Returns (shouldSend, newFeeFilterValue) based on timing and fee changes
-- Reference: Bitcoin Core MaybeSendFeefilter
shouldSendFeeFilter :: PeerInfo -> Word64 -> Int64 -> (Bool, Word64, Int64)
shouldSendFeeFilter info currentMinFee nowMicros
  -- Don't send feefilter to block-relay-only peers
  | piBlockOnly info = (False, 0, piNextFeeFilterSend info)
  -- Don't send if peer doesn't relay transactions
  | not (piRelay info) = (False, 0, piNextFeeFilterSend info)
  -- Time to send scheduled feefilter?
  | nowMicros > piNextFeeFilterSend info =
      let newFilter = currentMinFee
          -- Only send if filter actually changed
          shouldSend = newFilter /= piFeeFilterSent info
      in (shouldSend, newFilter, 0)  -- nextSend will be updated by caller
  -- Check for significant fee change (> 25% difference)
  -- If fee changed significantly and we're still > MAX_FEEFILTER_CHANGE_DELAY from
  -- scheduled send, expedite the send
  | nowMicros + maxFeeFilterChangeDelay < piNextFeeFilterSend info &&
    feeChangedSignificantly currentMinFee (piFeeFilterSent info) =
      (False, 0, nowMicros)  -- Schedule sooner but don't send immediately
  | otherwise = (False, 0, piNextFeeFilterSend info)

-- | Check if fee changed significantly (> 25% either direction)
-- Reference: Bitcoin Core (currentFilter < 3/4 * sent || currentFilter > 4/3 * sent)
feeChangedSignificantly :: Word64 -> Word64 -> Bool
feeChangedSignificantly current sent
  | sent == 0 = current > 0
  | otherwise = current < (3 * sent) `div` 4 || current > (4 * sent) `div` 3

-- | Send a feefilter message to a peer and update tracking state
-- Returns the new PeerInfo with updated feefilter state
sendFeeFilter :: PeerConnection -> Word64 -> IO ()
sendFeeFilter pc feeFilter = do
  now <- round . (* 1000000) <$> getPOSIXTime
  -- Generate random delay for next send (Poisson distributed)
  nextDelay <- poissonDelay avgFeeFilterBroadcastInterval
  let nextSend = now + nextDelay
  -- Update peer info
  atomically $ modifyTVar' (pcInfo pc) $ \info ->
    info { piFeeFilterSent = feeFilter
         , piNextFeeFilterSend = nextSend
         }
  -- Send the feefilter message
  sendMessage pc (MFeeFilter (FeeFilter feeFilter))

-- | Check if a transaction's fee rate passes the peer's fee filter
-- txFeeRate is in sat/vB, peerFeeFilter is in sat/kvB
-- Returns True if the transaction should be relayed to this peer
filterTxByFeeRate :: Word64 -> Word64 -> Bool
filterTxByFeeRate txFeeRateSatPerVB peerFeeFilterSatPerKvB
  | peerFeeFilterSatPerKvB == 0 = True  -- No filter, relay everything
  | otherwise = txFeeRateSatPerVB * 1000 >= peerFeeFilterSatPerKvB

--------------------------------------------------------------------------------
-- Eclipse Attack Protections (Phase 18)
-- Reference: Bitcoin Core addrman.cpp, net.cpp
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- Network Group
-- Groups addresses by network prefix to prevent eclipse attacks
-- Reference: Bitcoin Core netgroup.cpp GetGroup()
--------------------------------------------------------------------------------

-- | Network group identifier for eclipse protection
-- For IPv4: /16 prefix (first two octets)
-- For IPv6: /32 prefix (first four bytes)
-- For Tor/I2P: /4 prefix from random portion
newtype NetworkGroup = NetworkGroup { getNetworkGroupBytes :: ByteString }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)

instance Hashable NetworkGroup where
  hashWithSalt salt (NetworkGroup bs) = hashWithSalt salt bs

-- | Get network group as ByteString from SockAddr
-- This is the canonical representation used for bucket calculations
getNetworkGroupBS :: SockAddr -> ByteString
getNetworkGroupBS addr = getNetworkGroupBytes (computeNetworkGroup addr)

-- | Compute the network group for an address
-- Reference: Bitcoin Core netgroup.cpp GetGroup()
computeNetworkGroup :: SockAddr -> NetworkGroup
computeNetworkGroup (SockAddrInet _ hostAddr) =
  -- IPv4: /16 prefix (first two octets)
  -- hostAddr is stored in network byte order
  let a = fromIntegral hostAddr :: Word32
      -- Extract first two octets (network byte order)
      octet1 = fromIntegral $ a .&. 0xff
      octet2 = fromIntegral $ (a `shiftR` 8) .&. 0xff
  in NetworkGroup $ BS.pack [0x04, octet1, octet2]  -- 0x04 = NET_IPV4

computeNetworkGroup (SockAddrInet6 _ _ (h1, h2, _, _) _) =
  -- IPv6: /32 prefix (first four bytes)
  let b1 = fromIntegral $ (h1 `shiftR` 24) .&. 0xff
      b2 = fromIntegral $ (h1 `shiftR` 16) .&. 0xff
      b3 = fromIntegral $ (h1 `shiftR` 8) .&. 0xff
      b4 = fromIntegral $ h1 .&. 0xff
  in NetworkGroup $ BS.pack [0x06, b1, b2, b3, b4]  -- 0x06 = NET_IPV6

computeNetworkGroup (SockAddrUnix _) =
  -- Unix sockets: local group
  NetworkGroup $ BS.pack [0x00]  -- NET_UNROUTABLE

--------------------------------------------------------------------------------
-- AddrMan Constants
-- Reference: Bitcoin Core addrman_impl.h
--------------------------------------------------------------------------------

-- | Number of buckets in the tried table (2^8 = 256)
addrmanTriedBucketCount :: Int
addrmanTriedBucketCount = 256

-- | Number of buckets in the new table (2^10 = 1024)
addrmanNewBucketCount :: Int
addrmanNewBucketCount = 1024

-- | Number of entries per bucket (2^6 = 64)
addrmanBucketSize :: Int
addrmanBucketSize = 64

-- | Number of tried buckets per address group (8)
-- An address can appear in at most 8 tried buckets based on its group
addrmanTriedBucketsPerGroup :: Int
addrmanTriedBucketsPerGroup = 8

-- | Number of new buckets per source group (64)
addrmanNewBucketsPerSourceGroup :: Int
addrmanNewBucketsPerSourceGroup = 64

-- | Maximum number of new buckets an address can appear in (8)
addrmanNewBucketsPerAddress :: Int
addrmanNewBucketsPerAddress = 8

-- | Address horizon in seconds (30 days)
-- Addresses older than this are considered stale
addrmanHorizon :: Int64
addrmanHorizon = 30 * 24 * 60 * 60

-- | Maximum number of retries before giving up on an address
addrmanRetries :: Int
addrmanRetries = 3

-- | Maximum number of failures in a week before address is "terrible"
addrmanMaxFailures :: Int
addrmanMaxFailures = 10

--------------------------------------------------------------------------------
-- AddrInfo - Per-address metadata
-- Reference: Bitcoin Core addrman_impl.h AddrInfo
--------------------------------------------------------------------------------

-- | Information about a known network address
data AddrInfo = AddrInfo
  { aiAddress       :: !SockAddr           -- ^ The network address
  , aiServices      :: !Word64             -- ^ Services advertised
  , aiLastTry       :: !Int64              -- ^ Unix timestamp of last connection attempt
  , aiLastSuccess   :: !Int64              -- ^ Unix timestamp of last successful connection
  , aiLastCountAttempt :: !Int64           -- ^ Time of last counted attempt
  , aiAttempts      :: !Int                -- ^ Number of connection attempts
  , aiSource        :: !SockAddr           -- ^ Address of peer that told us about this
  , aiNetGroup      :: !NetworkGroup       -- ^ Cached network group
  , aiInTried       :: !Bool               -- ^ Whether in tried table (vs new)
  , aiRefCount      :: !Int                -- ^ Number of new buckets containing this address
  } deriving (Show, Eq, Generic)

instance NFData AddrInfo

-- | Check if an address is "terrible" (should not be selected)
-- Reference: Bitcoin Core addrman.cpp AddrInfo::IsTerrible
isTerribleAddress :: Int64 -> AddrInfo -> Bool
isTerribleAddress now info =
  let age = now - aiLastTry info
      -- Never tried and older than horizon
      neverTried = aiAttempts info == 0 && aiLastTry info == 0
                   && age > addrmanHorizon
      -- Too many failures
      tooManyFailures = aiAttempts info >= addrmanMaxFailures
      -- Failed recently and too many attempts
      failedRecently = age < 60 && aiAttempts info > 0
  in neverTried || tooManyFailures || failedRecently

-- | Calculate address selection chance
-- Reference: Bitcoin Core addrman.cpp AddrInfo::GetChance
getAddressChance :: Int64 -> AddrInfo -> Double
getAddressChance now info =
  let age = now - aiLastTry info
      -- Start with base chance of 1.0
      baseChance = 1.0 :: Double
      -- Reduce chance based on number of failed attempts (exponential backoff)
      attemptFactor = 0.66 ^ aiAttempts info
      -- Recent failure penalty
      recentPenalty = if age < 600 then 0.01 else 1.0
  in baseChance * attemptFactor * recentPenalty

--------------------------------------------------------------------------------
-- AddrMan - Address Manager
-- Reference: Bitcoin Core addrman.cpp AddrManImpl
--------------------------------------------------------------------------------

-- | Address manager with bucketed storage for eclipse resistance
data AddrMan = AddrMan
  { amKey           :: !Hash256                            -- ^ Random key for bucket hashing
  , amNewTable      :: !(TVar (Map Int [AddrInfo]))        -- ^ New table: bucket -> addresses
  , amTriedTable    :: !(TVar (Map Int [AddrInfo]))        -- ^ Tried table: bucket -> addresses
  , amAddrIndex     :: !(TVar (Map SockAddr AddrInfo))     -- ^ Address -> info lookup
  , amNewCount      :: !(TVar Int)                         -- ^ Total addresses in new table
  , amTriedCount    :: !(TVar Int)                         -- ^ Total addresses in tried table
  } deriving (Eq)

-- | Create a new address manager with random key
newAddrMan :: IO AddrMan
newAddrMan = do
  -- Generate random 256-bit key for bucket hashing
  keyBytes <- BS.pack <$> replicateM 32 randomIO
  let key = Hash256 keyBytes
  AddrMan key
    <$> newTVarIO Map.empty
    <*> newTVarIO Map.empty
    <*> newTVarIO Map.empty
    <*> newTVarIO 0
    <*> newTVarIO 0

-- | Compute bucket for the new table
-- Reference: Bitcoin Core addrman.cpp AddrInfo::GetNewBucket
getNewBucket :: Hash256 -> SockAddr -> SockAddr -> Int
getNewBucket key addr source =
  let addrGroup = getNetworkGroupBS addr
      sourceGroup = getNetworkGroupBS source
      -- hash1 = H(key, addrGroup, sourceGroup)
      hash1Data = BS.concat [getHash256 key, addrGroup, sourceGroup]
      hash1 = cheapHash $ doubleSHA256 hash1Data
      -- bucket1 = hash1 % NEW_BUCKETS_PER_SOURCE_GROUP
      bucket1 = hash1 `mod` fromIntegral addrmanNewBucketsPerSourceGroup
      -- hash2 = H(key, sourceGroup, bucket1)
      hash2Data = BS.concat [getHash256 key, sourceGroup, encodeWord64LE bucket1]
      hash2 = cheapHash $ doubleSHA256 hash2Data
  in fromIntegral $ hash2 `mod` fromIntegral addrmanNewBucketCount

-- | Compute bucket for the tried table
-- Reference: Bitcoin Core addrman.cpp AddrInfo::GetTriedBucket
getTriedBucket :: Hash256 -> SockAddr -> Int
getTriedBucket key addr =
  let addrGroup = getNetworkGroupBS addr
      -- hash1 = H(key, addr)
      hash1Data = BS.concat [getHash256 key, encodeSockAddr addr]
      hash1 = cheapHash $ doubleSHA256 hash1Data
      -- bucket1 = hash1 % TRIED_BUCKETS_PER_GROUP
      bucket1 = hash1 `mod` fromIntegral addrmanTriedBucketsPerGroup
      -- hash2 = H(key, addrGroup, bucket1)
      hash2Data = BS.concat [getHash256 key, addrGroup, encodeWord64LE bucket1]
      hash2 = cheapHash $ doubleSHA256 hash2Data
  in fromIntegral $ hash2 `mod` fromIntegral addrmanTriedBucketCount

-- | Compute position within a bucket
-- Reference: Bitcoin Core addrman.cpp AddrInfo::GetBucketPosition
getBucketPosition :: Hash256 -> Bool -> Int -> SockAddr -> Int
getBucketPosition key isNew bucket addr =
  let -- table indicator: 'N' for new, 'K' for tried (known)
      tableChar = if isNew then 0x4E else 0x4B :: Word8  -- 'N' or 'K'
      hashData = BS.concat [ getHash256 key
                           , BS.singleton tableChar
                           , encodeWord32LE (fromIntegral bucket)
                           , encodeSockAddr addr
                           ]
      hash = cheapHash $ doubleSHA256 hashData
  in fromIntegral $ hash `mod` fromIntegral addrmanBucketSize

-- | Add an address to the address manager
-- Reference: Bitcoin Core addrman.cpp AddrManImpl::Add_
addAddress :: AddrMan -> SockAddr -> SockAddr -> Word64 -> Int64 -> IO Bool
addAddress am addr source services now = do
  existing <- Map.lookup addr <$> readTVarIO (amAddrIndex am)
  case existing of
    Just info -> do
      -- Address exists, update if source is same group
      let sourceGroup = computeNetworkGroup source
          infoSourceGroup = computeNetworkGroup (aiSource info)
      if sourceGroup == infoSourceGroup
        then do
          -- Update existing entry
          let updated = info { aiServices = services }
          atomically $ modifyTVar' (amAddrIndex am) (Map.insert addr updated)
          return True
        else
          -- Different source, consider adding to more buckets
          return False
    Nothing -> do
      -- New address
      let netGroup = computeNetworkGroup addr
          info = AddrInfo
            { aiAddress = addr
            , aiServices = services
            , aiLastTry = 0
            , aiLastSuccess = 0
            , aiLastCountAttempt = now
            , aiAttempts = 0
            , aiSource = source
            , aiNetGroup = netGroup
            , aiInTried = False
            , aiRefCount = 1
            }
          bucket = getNewBucket (amKey am) addr source
          position = getBucketPosition (amKey am) True bucket addr

      atomically $ do
        -- Add to new table
        modifyTVar' (amNewTable am) $ \table ->
          let existing_bucket = Map.findWithDefault [] bucket table
              -- Check if bucket position is taken
              newBucket = take addrmanBucketSize $ info : existing_bucket
          in Map.insert bucket newBucket table
        -- Add to index
        modifyTVar' (amAddrIndex am) (Map.insert addr info)
        modifyTVar' (amNewCount am) (+1)
      return True

-- | Select a random address from the manager
-- Reference: Bitcoin Core addrman.cpp AddrManImpl::Select_
selectAddress :: AddrMan -> Bool -> IO (Maybe SockAddr)
selectAddress am fromNew = do
  now <- round <$> getPOSIXTime

  newCount <- readTVarIO (amNewCount am)
  triedCount <- readTVarIO (amTriedCount am)

  if newCount == 0 && triedCount == 0
    then return Nothing
    else do
      -- Decide whether to select from new or tried
      useNew <- if fromNew || triedCount == 0
                then return True
                else if newCount == 0
                     then return False
                     else do
                       r <- randomRIO (0 :: Int, newCount + triedCount - 1)
                       return (r < newCount)

      if useNew
        then selectFromTable am True now
        else selectFromTable am False now

-- | Select an address from a specific table
selectFromTable :: AddrMan -> Bool -> Int64 -> IO (Maybe SockAddr)
selectFromTable am isNew now = do
  table <- readTVarIO $ if isNew then amNewTable am else amTriedTable am
  let allAddrs = concatMap snd $ Map.toList table
      -- Filter out terrible addresses
      candidates = filter (not . isTerribleAddress now) allAddrs

  if null candidates
    then return Nothing
    else do
      -- Weight selection by chance
      let chances = map (\a -> (a, getAddressChance now a)) candidates
          totalChance = sum $ map snd chances

      if totalChance <= 0
        then return Nothing
        else do
          r <- randomRIO (0, totalChance)
          return $ selectByChance r chances
  where
    selectByChance _ [] = Nothing
    selectByChance r ((info, chance):rest)
      | r <= chance = Just (aiAddress info)
      | otherwise = selectByChance (r - chance) rest

-- | Mark an address as successfully connected
-- Moves address from new to tried table
-- Reference: Bitcoin Core addrman.cpp AddrManImpl::Good_
markGood :: AddrMan -> SockAddr -> Int64 -> IO ()
markGood am addr now = do
  mInfo <- Map.lookup addr <$> readTVarIO (amAddrIndex am)
  case mInfo of
    Nothing -> return ()
    Just info
      | aiInTried info -> do
          -- Already in tried, just update timestamp
          let updated = info { aiLastSuccess = now }
          atomically $ modifyTVar' (amAddrIndex am) (Map.insert addr updated)
      | otherwise -> do
          -- Move from new to tried
          let bucket = getTriedBucket (amKey am) addr
              position = getBucketPosition (amKey am) False bucket addr
              updated = info { aiInTried = True, aiLastSuccess = now }

          atomically $ do
            -- Remove from new table
            modifyTVar' (amNewTable am) $ Map.map (filter ((/= addr) . aiAddress))
            modifyTVar' (amNewCount am) (subtract 1)
            -- Add to tried table
            modifyTVar' (amTriedTable am) $ \table ->
              let existing = Map.findWithDefault [] bucket table
              in Map.insert bucket (take addrmanBucketSize $ updated : existing) table
            modifyTVar' (amTriedCount am) (+1)
            -- Update index
            modifyTVar' (amAddrIndex am) (Map.insert addr updated)

-- | Mark an address as attempted (failed connection)
-- Reference: Bitcoin Core addrman.cpp AddrManImpl::Attempt_
markAttempt :: AddrMan -> SockAddr -> Int64 -> IO ()
markAttempt am addr now = do
  mInfo <- Map.lookup addr <$> readTVarIO (amAddrIndex am)
  case mInfo of
    Nothing -> return ()
    Just info -> do
      let updated = info
            { aiLastTry = now
            , aiAttempts = aiAttempts info + 1
            }
      atomically $ modifyTVar' (amAddrIndex am) (Map.insert addr updated)

--------------------------------------------------------------------------------
-- Outbound Connection Diversity
-- Ensures outbound connections span multiple /16 groups
-- Reference: Bitcoin Core net.cpp ThreadOpenConnections
--------------------------------------------------------------------------------

-- | Tracks connected network groups for outbound diversity
data OutboundDiversity = OutboundDiversity
  { odConnectedGroups :: !(TVar (Set.Set NetworkGroup))  -- ^ Groups with outbound connections
  , odGroupCounts     :: !(TVar (Map NetworkGroup Int))  -- ^ Count per group
  }

-- | Create a new outbound diversity tracker
newOutboundDiversity :: IO OutboundDiversity
newOutboundDiversity = OutboundDiversity
  <$> newTVarIO Set.empty
  <*> newTVarIO Map.empty

-- | Check if connecting to an address would maintain diversity
-- Reference: Bitcoin Core net.cpp - rejects duplicate network groups
checkOutboundDiversity :: OutboundDiversity -> SockAddr -> IO Bool
checkOutboundDiversity od addr = do
  let group = computeNetworkGroup addr
  connected <- readTVarIO (odConnectedGroups od)
  -- Accept if this group is not already connected
  return $ not $ Set.member group connected

-- | Add an outbound connection to the diversity tracker
addOutboundConnection :: OutboundDiversity -> SockAddr -> IO ()
addOutboundConnection od addr = do
  let group = computeNetworkGroup addr
  atomically $ do
    modifyTVar' (odConnectedGroups od) (Set.insert group)
    modifyTVar' (odGroupCounts od) $ \m ->
      Map.insertWith (+) group 1 m

-- | Remove an outbound connection from the diversity tracker
removeOutboundConnection :: OutboundDiversity -> SockAddr -> IO ()
removeOutboundConnection od addr = do
  let group = computeNetworkGroup addr
  atomically $ do
    counts <- readTVar (odGroupCounts od)
    let newCount = Map.findWithDefault 1 group counts - 1
    if newCount <= 0
      then do
        modifyTVar' (odConnectedGroups od) (Set.delete group)
        writeTVar (odGroupCounts od) (Map.delete group counts)
      else
        writeTVar (odGroupCounts od) (Map.insert group newCount counts)

--------------------------------------------------------------------------------
-- Anchor Connections
-- Persist block-relay-only peers to reconnect on startup
-- Reference: Bitcoin Core net.cpp, addrdb.cpp
--------------------------------------------------------------------------------

-- | Maximum number of block-relay-only anchor connections
maxBlockRelayOnlyAnchors :: Int
maxBlockRelayOnlyAnchors = 2

-- | An anchor connection (persisted block-relay peer)
data AnchorConnection = AnchorConnection
  { acAddress  :: !SockAddr
  , acServices :: !Word64
  } deriving (Show, Eq, Generic)

instance NFData AnchorConnection

instance ToJSON AnchorConnection where
  toJSON ac = Aeson.object
    [ "address"  .= sockAddrToString (acAddress ac)
    , "services" .= acServices ac
    ]

instance FromJSON AnchorConnection where
  parseJSON = Aeson.withObject "AnchorConnection" $ \o -> do
    addrStr <- o .: "address"
    services <- o .: "services"
    case stringToSockAddr addrStr of
      Just addr -> return $ AnchorConnection addr services
      Nothing -> fail "Invalid address format"

-- | Save anchor connections to file
-- Reference: Bitcoin Core addrdb.cpp DumpAnchors
saveAnchors :: FilePath -> [AnchorConnection] -> IO ()
saveAnchors path anchors = do
  let limited = take maxBlockRelayOnlyAnchors anchors
  withFile path WriteMode $ \h ->
    hPutStr h (C8.unpack $ LBS.toStrict $ Aeson.encode limited)

-- | Load anchor connections from file
-- Deletes the file after loading (one-time use)
-- Reference: Bitcoin Core addrdb.cpp ReadAnchors
loadAnchors :: FilePath -> IO [AnchorConnection]
loadAnchors path = do
  result <- try @IOException $ withFile path ReadMode hGetContents'
  case result of
    Left _ -> return []
    Right contents -> do
      -- Delete file after reading (one-time use)
      removeFileIfExists path
      case Aeson.decodeStrict (C8.pack contents) of
        Just anchors -> return $ take maxBlockRelayOnlyAnchors anchors
        Nothing -> return []
  where
    removeFileIfExists :: FilePath -> IO ()
    removeFileIfExists fp = void $ try @IOException $ do
      -- Simple removal - ignore errors
      withFile fp WriteMode $ \_ -> return ()

--------------------------------------------------------------------------------
-- Inbound Connection Limiting
-- Limits connections per /16 group to prevent monopolization
-- Reference: Bitcoin Core net.cpp
--------------------------------------------------------------------------------

-- | Maximum inbound connections per /16 network group
maxInboundPerGroup :: Int
maxInboundPerGroup = 4

-- | Tracks inbound connections per network group
data InboundLimiter = InboundLimiter
  { ilGroupCounts :: !(TVar (Map NetworkGroup Int))
  , ilMaxPerGroup :: !Int
  }

-- | Create a new inbound limiter
newInboundLimiter :: Int -> IO InboundLimiter
newInboundLimiter maxPer = InboundLimiter
  <$> newTVarIO Map.empty
  <*> pure maxPer

-- | Check if a new inbound connection should be accepted
-- Returns False if the group has too many connections
checkInboundLimit :: InboundLimiter -> SockAddr -> IO Bool
checkInboundLimit il addr = do
  let group = computeNetworkGroup addr
  counts <- readTVarIO (ilGroupCounts il)
  let currentCount = Map.findWithDefault 0 group counts
  return $ currentCount < ilMaxPerGroup il

-- | Add an inbound connection to the limiter
addInboundConnection :: InboundLimiter -> SockAddr -> IO ()
addInboundConnection il addr = do
  let group = computeNetworkGroup addr
  atomically $ modifyTVar' (ilGroupCounts il) $ \m ->
    Map.insertWith (+) group 1 m

-- | Remove an inbound connection from the limiter
removeInboundConnection :: InboundLimiter -> SockAddr -> IO ()
removeInboundConnection il addr = do
  let group = computeNetworkGroup addr
  atomically $ modifyTVar' (ilGroupCounts il) $ \m ->
    let newCount = Map.findWithDefault 1 group m - 1
    in if newCount <= 0
       then Map.delete group m
       else Map.insert group newCount m

--------------------------------------------------------------------------------
-- Helper Functions
--------------------------------------------------------------------------------

-- | Cheap hash function for bucket calculations
-- Returns lower 64 bits of a Hash256
cheapHash :: Hash256 -> Word64
cheapHash (Hash256 bs) =
  let bytes = BS.take 8 bs
      [b0,b1,b2,b3,b4,b5,b6,b7] = BS.unpack $ BS.append bytes (BS.replicate (8 - BS.length bytes) 0)
  in fromIntegral b0
     .|. (fromIntegral b1 `shiftL` 8)
     .|. (fromIntegral b2 `shiftL` 16)
     .|. (fromIntegral b3 `shiftL` 24)
     .|. (fromIntegral b4 `shiftL` 32)
     .|. (fromIntegral b5 `shiftL` 40)
     .|. (fromIntegral b6 `shiftL` 48)
     .|. (fromIntegral b7 `shiftL` 56)

-- | Encode a Word64 in little-endian
encodeWord64LE :: Word64 -> ByteString
encodeWord64LE w = BS.pack
  [ fromIntegral $ w .&. 0xff
  , fromIntegral $ (w `shiftR` 8) .&. 0xff
  , fromIntegral $ (w `shiftR` 16) .&. 0xff
  , fromIntegral $ (w `shiftR` 24) .&. 0xff
  , fromIntegral $ (w `shiftR` 32) .&. 0xff
  , fromIntegral $ (w `shiftR` 40) .&. 0xff
  , fromIntegral $ (w `shiftR` 48) .&. 0xff
  , fromIntegral $ (w `shiftR` 56) .&. 0xff
  ]

-- | Encode a Word32 in little-endian
encodeWord32LE :: Word32 -> ByteString
encodeWord32LE w = BS.pack
  [ fromIntegral $ w .&. 0xff
  , fromIntegral $ (w `shiftR` 8) .&. 0xff
  , fromIntegral $ (w `shiftR` 16) .&. 0xff
  , fromIntegral $ (w `shiftR` 24) .&. 0xff
  ]

-- | Encode a SockAddr to bytes for hashing
encodeSockAddr :: SockAddr -> ByteString
encodeSockAddr (SockAddrInet port hostAddr) = BS.concat
  [ BS.singleton 0x04  -- IPv4 marker
  , encodeWord32LE (fromIntegral hostAddr)
  , encodeWord16LE (fromIntegral port)
  ]
encodeSockAddr (SockAddrInet6 port _ (h1,h2,h3,h4) _) = BS.concat
  [ BS.singleton 0x06  -- IPv6 marker
  , encodeWord32LE h1
  , encodeWord32LE h2
  , encodeWord32LE h3
  , encodeWord32LE h4
  , encodeWord16LE (fromIntegral port)
  ]
encodeSockAddr _ = BS.singleton 0x00

-- | Encode a Word16 in little-endian
encodeWord16LE :: Word16 -> ByteString
encodeWord16LE w = BS.pack
  [ fromIntegral $ w .&. 0xff
  , fromIntegral $ (w `shiftR` 8) .&. 0xff
  ]

-- | Convert SockAddr to string representation
sockAddrToString :: SockAddr -> String
sockAddrToString (SockAddrInet port hostAddr) =
  let a = fromIntegral hostAddr :: Word32
      b1 = a .&. 0xff
      b2 = (a `shiftR` 8) .&. 0xff
      b3 = (a `shiftR` 16) .&. 0xff
      b4 = (a `shiftR` 24) .&. 0xff
  in show b1 ++ "." ++ show b2 ++ "." ++ show b3 ++ "." ++ show b4
     ++ ":" ++ show (fromIntegral port :: Int)
sockAddrToString (SockAddrInet6 port _ _ _) = "[ipv6]:" ++ show port
sockAddrToString _ = "unknown"

-- | Parse a SockAddr from string
stringToSockAddr :: String -> Maybe SockAddr
stringToSockAddr s =
  case break (== ':') s of
    (ipStr, ':':portStr) ->
      case (parseIPv4 ipStr, reads portStr) of
        (Just hostAddr, [(port, "")]) ->
          Just $ SockAddrInet (fromIntegral (port :: Int)) hostAddr
        _ -> Nothing
    _ -> Nothing
  where
    parseIPv4 :: String -> Maybe Word32
    parseIPv4 str = case map read' (splitOn '.' str) of
      [b1, b2, b3, b4] | all validByte [b1, b2, b3, b4] ->
        Just $ fromIntegral b1
             .|. (fromIntegral b2 `shiftL` 8)
             .|. (fromIntegral b3 `shiftL` 16)
             .|. (fromIntegral b4 `shiftL` 24)
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
      | c == x = "" : splitOn c xs
      | otherwise = let (h:t) = splitOn c xs in (x:h) : t

--------------------------------------------------------------------------------
-- Stale Peer Eviction Constants (Phase 19)
-- Reference: Bitcoin Core net_processing.cpp ConsiderEviction
--------------------------------------------------------------------------------

-- | Interval between stale peer checks (10 minutes in seconds)
-- Reference: Bitcoin Core STALE_CHECK_INTERVAL
staleCheckInterval :: Int64
staleCheckInterval = 600  -- 10 minutes in seconds

-- | Time to wait for headers response after getheaders probe (2 minutes)
-- Reference: Bitcoin Core HEADERS_RESPONSE_TIME
headersResponseTime :: Int64
headersResponseTime = 120  -- 2 minutes in seconds

-- | Ping timeout - disconnect if no pong within this time (20 minutes)
-- Reference: Bitcoin Core net.h TIMEOUT_INTERVAL
pingTimeout :: Int64
pingTimeout = 1200  -- 20 minutes in seconds

-- | Block download stall timeout for full blocks (30 seconds)
-- Reference: Bitcoin Core BLOCK_STALLING_TIMEOUT_DEFAULT
blockStallTimeout :: Int64
blockStallTimeout = 30  -- 30 seconds (default for full blocks)

-- | Block download stall timeout for compact blocks (2 seconds)
-- Reference: Bitcoin Core BLOCK_STALLING_TIMEOUT_DEFAULT
blockStallTimeoutCompact :: Int64
blockStallTimeoutCompact = 2  -- 2 seconds for compact blocks

-- | Maximum block stall timeout after backoff (64 seconds)
-- Reference: Bitcoin Core BLOCK_STALLING_TIMEOUT_MAX
blockStallTimeoutMax :: Int64
blockStallTimeoutMax = 64  -- 64 seconds max

-- | Chain sync timeout before sending getheaders probe (20 minutes)
-- Reference: Bitcoin Core CHAIN_SYNC_TIMEOUT
chainSyncTimeout :: Int64
chainSyncTimeout = 1200  -- 20 minutes

-- | Minimum connection time before eviction eligible (30 seconds)
-- Reference: Bitcoin Core MINIMUM_CONNECT_TIME
minimumConnectTime :: Int64
minimumConnectTime = 30  -- 30 seconds

-- | Maximum outbound peers protected from chain sync eviction
-- Reference: Bitcoin Core MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT
maxOutboundPeersToProtect :: Int
maxOutboundPeersToProtect = 4

--------------------------------------------------------------------------------
-- Peer Chain Sync State
-- Tracks per-peer chain sync progress for stale tip detection
-- Reference: Bitcoin Core CNodeState::ChainSyncTimeoutState
--------------------------------------------------------------------------------

-- | Chain sync timeout state for a peer
data ChainSyncState
  = ChainSyncIdle                       -- ^ No timeout set
  | ChainSyncPending !ChainSyncData     -- ^ Waiting for sync
  | ChainSyncProbing !ChainSyncData     -- ^ Sent getheaders, waiting for response
  deriving (Show, Eq, Generic)

instance NFData ChainSyncState

-- | Data tracked during chain sync timeout
data ChainSyncData = ChainSyncData
  { csdTimeout         :: !Int64        -- ^ Unix timestamp when timeout expires
  , csdWorkHeader      :: !BlockHash    -- ^ Our tip when timeout was set
  , csdWorkChainWork   :: !Integer      -- ^ Chain work of our tip
  , csdProtected       :: !Bool         -- ^ Whether peer is protected from eviction
  } deriving (Show, Eq, Generic)

instance NFData ChainSyncData

-- | Create a new chain sync state (idle)
newChainSyncState :: ChainSyncState
newChainSyncState = ChainSyncIdle

--------------------------------------------------------------------------------
-- Stale Peer Tracker
-- Centralized tracking of peer state for eviction decisions
-- Reference: Bitcoin Core PeerManagerImpl
--------------------------------------------------------------------------------

-- | Per-peer tracking state for stale detection
data PeerEvictionState = PeerEvictionState
  { pesBestKnownBlock   :: !(Maybe BlockHash)  -- ^ Peer's best known block
  , pesBestKnownWork    :: !Integer            -- ^ Chain work of peer's best block
  , pesChainSyncState   :: !ChainSyncState     -- ^ Chain sync timeout state
  , pesLastPingSent     :: !(Maybe Int64)      -- ^ Timestamp when ping was sent
  , pesLastPongRecv     :: !(Maybe Int64)      -- ^ Timestamp when pong was received
  , pesPingNonce        :: !(Maybe Word64)     -- ^ Nonce of outstanding ping
  , pesBlocksInFlight   :: !(Map BlockHash Int64)  -- ^ Requested blocks with timestamps
  , pesStallingStart    :: !(Maybe Int64)      -- ^ When stalling was detected
  , pesIsOutbound       :: !Bool               -- ^ Whether this is an outbound connection
  , pesIsBlockRelay     :: !Bool               -- ^ Whether this is a block-relay-only conn
  , pesConnectedAt      :: !Int64              -- ^ Connection timestamp
  , pesSyncStarted      :: !Bool               -- ^ Whether we started syncing from this peer
  } deriving (Show, Eq, Generic)

instance NFData PeerEvictionState

-- | Stale peer tracker for managing eviction
data StalePeerTracker = StalePeerTracker
  { sptPeerStates         :: !(TVar (Map SockAddr PeerEvictionState))
  , sptOurTipHash         :: !(TVar BlockHash)        -- ^ Our current tip hash
  , sptOurTipWork         :: !(TVar Integer)          -- ^ Our current tip chain work
  , sptBlockStallTimeout  :: !(TVar Int64)            -- ^ Current stall timeout (adaptive)
  , sptProtectedCount     :: !(TVar Int)              -- ^ Number of protected outbound peers
  , sptEvictionThread     :: !(TVar (Maybe ThreadId)) -- ^ Eviction check thread
  }

-- | Create a new stale peer tracker
newStalePeerTracker :: IO StalePeerTracker
newStalePeerTracker = StalePeerTracker
  <$> newTVarIO Map.empty
  <*> newTVarIO (BlockHash (Hash256 (BS.replicate 32 0)))
  <*> newTVarIO 0
  <*> newTVarIO blockStallTimeout
  <*> newTVarIO 0
  <*> newTVarIO Nothing

-- | Default peer eviction state
defaultPeerEvictionState :: Bool -> Bool -> Int64 -> PeerEvictionState
defaultPeerEvictionState isOutbound isBlockRelay now = PeerEvictionState
  { pesBestKnownBlock = Nothing
  , pesBestKnownWork = 0
  , pesChainSyncState = ChainSyncIdle
  , pesLastPingSent = Nothing
  , pesLastPongRecv = Just now
  , pesPingNonce = Nothing
  , pesBlocksInFlight = Map.empty
  , pesStallingStart = Nothing
  , pesIsOutbound = isOutbound
  , pesIsBlockRelay = isBlockRelay
  , pesConnectedAt = now
  , pesSyncStarted = False
  }

-- | Update a peer's best known block
updatePeerBestBlock :: StalePeerTracker -> SockAddr -> BlockHash -> Integer -> IO ()
updatePeerBestBlock spt addr hash work = atomically $
  modifyTVar' (sptPeerStates spt) $ Map.adjust
    (\s -> s { pesBestKnownBlock = Just hash, pesBestKnownWork = work }) addr

-- | Get a peer's best known block
getPeerBestBlock :: StalePeerTracker -> SockAddr -> IO (Maybe (BlockHash, Integer))
getPeerBestBlock spt addr = do
  states <- readTVarIO (sptPeerStates spt)
  return $ case Map.lookup addr states of
    Just s  -> (,) <$> pesBestKnownBlock s <*> Just (pesBestKnownWork s)
    Nothing -> Nothing

-- | Record that a ping was sent to a peer
recordPingSent :: StalePeerTracker -> SockAddr -> Word64 -> IO ()
recordPingSent spt addr nonce = do
  now <- round <$> getPOSIXTime
  atomically $ modifyTVar' (sptPeerStates spt) $ Map.adjust
    (\s -> s { pesLastPingSent = Just now, pesPingNonce = Just nonce }) addr

-- | Record that a pong was received from a peer
recordPongReceived :: StalePeerTracker -> SockAddr -> Word64 -> IO Bool
recordPongReceived spt addr nonce = do
  now <- round <$> getPOSIXTime
  atomically $ do
    states <- readTVar (sptPeerStates spt)
    case Map.lookup addr states of
      Just s | pesPingNonce s == Just nonce -> do
        modifyTVar' (sptPeerStates spt) $ Map.adjust
          (\st -> st { pesLastPongRecv = Just now, pesPingNonce = Nothing }) addr
        return True
      _ -> return False

-- | Check if a peer's ping has timed out
-- Reference: Bitcoin Core net_processing.cpp inactivity checks
isPingTimedOut :: StalePeerTracker -> SockAddr -> IO Bool
isPingTimedOut spt addr = do
  now <- round <$> getPOSIXTime
  states <- readTVarIO (sptPeerStates spt)
  case Map.lookup addr states of
    Just s -> case pesLastPingSent s of
      Just sentTime ->
        -- Ping timed out if we sent a ping with outstanding nonce
        -- and it's been more than pingTimeout seconds
        case pesPingNonce s of
          Just _ -> return $ now - sentTime > pingTimeout
          Nothing -> return False
      Nothing -> return False
    Nothing -> return False

-- | Record that a block was requested from a peer
recordBlockRequested :: StalePeerTracker -> SockAddr -> BlockHash -> IO ()
recordBlockRequested spt addr hash = do
  now <- round <$> getPOSIXTime
  atomically $ modifyTVar' (sptPeerStates spt) $ Map.adjust
    (\s -> s { pesBlocksInFlight = Map.insert hash now (pesBlocksInFlight s) }) addr

-- | Record that a block was received from a peer
recordBlockReceived :: StalePeerTracker -> SockAddr -> BlockHash -> IO ()
recordBlockReceived spt addr hash = do
  atomically $ do
    modifyTVar' (sptPeerStates spt) $ Map.adjust
      (\s -> s { pesBlocksInFlight = Map.delete hash (pesBlocksInFlight s)
               , pesStallingStart = Nothing
               }) addr
    -- Decay stall timeout on success (reduce by 15%, min 2 seconds)
    -- Reference: Bitcoin Core net_processing.cpp block connected handler
    modifyTVar' (sptBlockStallTimeout spt) $ \t ->
      max blockStallTimeoutCompact (t * 85 `div` 100)

-- | Check if block download from a peer has stalled
-- Reference: Bitcoin Core net_processing.cpp SendMessages
isBlockStalled :: StalePeerTracker -> SockAddr -> Bool -> IO (Bool, Maybe BlockHash)
isBlockStalled spt addr isCompact = do
  now <- round <$> getPOSIXTime
  states <- readTVarIO (sptPeerStates spt)
  currentTimeout <- readTVarIO (sptBlockStallTimeout spt)

  let timeout = if isCompact then blockStallTimeoutCompact else currentTimeout

  case Map.lookup addr states of
    Just s -> do
      let inFlight = pesBlocksInFlight s
          -- Find oldest in-flight block
          oldestEntry = listToMaybe $ sortBy (comparing snd) $ Map.toList inFlight
      case oldestEntry of
        Just (hash, requestTime) ->
          if now - requestTime > timeout
            then do
              -- Double the stall timeout (with max cap) for next peer
              atomically $ modifyTVar' (sptBlockStallTimeout spt) $ \t ->
                min blockStallTimeoutMax (t * 2)
              return (True, Just hash)
            else return (False, Nothing)
        Nothing -> return (False, Nothing)
    Nothing -> return (False, Nothing)

--------------------------------------------------------------------------------
-- Chain Sync Eviction Logic
-- Reference: Bitcoin Core net_processing.cpp ConsiderEviction
--------------------------------------------------------------------------------

-- | Consider evicting a peer based on chain sync timeout
-- Returns: (ShouldDisconnect, ShouldSendGetheaders, UpdatedState)
considerEviction :: StalePeerTracker -> SockAddr -> Int64 -> IO (Bool, Bool, Maybe ChainSyncState)
considerEviction spt addr now = do
  states <- readTVarIO (sptPeerStates spt)
  ourTipWork <- readTVarIO (sptOurTipWork spt)
  ourTipHash <- readTVarIO (sptOurTipHash spt)

  case Map.lookup addr states of
    Nothing -> return (False, False, Nothing)
    Just state
      -- Only check unprotected outbound or block-relay peers that are syncing
      | not (pesIsOutbound state || pesIsBlockRelay state) -> return (False, False, Nothing)
      | isProtected (pesChainSyncState state) -> return (False, False, Nothing)
      | not (pesSyncStarted state) -> return (False, False, Nothing)
      | otherwise -> do
          let peerWork = pesBestKnownWork state

          case pesChainSyncState state of
            ChainSyncIdle ->
              -- Peer has caught up?
              if peerWork >= ourTipWork
                then return (False, False, Nothing)  -- Peer is synced
                else do
                  -- Start timeout
                  let newData = ChainSyncData
                        { csdTimeout = now + chainSyncTimeout
                        , csdWorkHeader = ourTipHash
                        , csdWorkChainWork = ourTipWork
                        , csdProtected = False
                        }
                  atomically $ modifyTVar' (sptPeerStates spt) $ Map.adjust
                    (\s -> s { pesChainSyncState = ChainSyncPending newData }) addr
                  return (False, False, Just (ChainSyncPending newData))

            ChainSyncPending csd ->
              -- Check if peer has made progress
              if peerWork >= csdWorkChainWork csd
                then do
                  -- Peer caught up, reset timeout
                  atomically $ modifyTVar' (sptPeerStates spt) $ Map.adjust
                    (\s -> s { pesChainSyncState = ChainSyncIdle }) addr
                  return (False, False, Just ChainSyncIdle)
                else if now > csdTimeout csd
                  then do
                    -- Timeout expired, send getheaders probe
                    let newData = csd { csdTimeout = now + headersResponseTime }
                    atomically $ modifyTVar' (sptPeerStates spt) $ Map.adjust
                      (\s -> s { pesChainSyncState = ChainSyncProbing newData }) addr
                    return (False, True, Just (ChainSyncProbing newData))
                  else return (False, False, Nothing)

            ChainSyncProbing csd ->
              -- Check if peer responded with better chain
              if peerWork >= csdWorkChainWork csd
                then do
                  -- Peer caught up after probe
                  atomically $ modifyTVar' (sptPeerStates spt) $ Map.adjust
                    (\s -> s { pesChainSyncState = ChainSyncIdle }) addr
                  return (False, False, Just ChainSyncIdle)
                else if now > csdTimeout csd
                  then do
                    -- No response to getheaders, disconnect
                    return (True, False, Nothing)
                  else return (False, False, Nothing)
  where
    isProtected ChainSyncIdle = False
    isProtected (ChainSyncPending csd) = csdProtected csd
    isProtected (ChainSyncProbing csd) = csdProtected csd

-- | Check if a peer is stale and should be evicted
-- Combines all stale checks (ping timeout, block stall, chain sync)
checkStalePeer :: StalePeerTracker -> SockAddr -> Bool -> IO (Bool, String)
checkStalePeer spt addr isCompact = do
  now <- round <$> getPOSIXTime

  -- Check ping timeout
  pingTimedOut <- isPingTimedOut spt addr
  if pingTimedOut
    then return (True, "ping timeout")
    else do
      -- Check block stall
      (stalled, mHash) <- isBlockStalled spt addr isCompact
      if stalled
        then return (True, "block download stall: " ++ maybe "unknown" show mHash)
        else do
          -- Check chain sync eviction
          (disconnect, _, _) <- considerEviction spt addr now
          if disconnect
            then return (True, "chain sync timeout")
            else return (False, "")

-- | Start the periodic eviction check thread
-- Reference: Bitcoin Core net_processing.cpp SendMessages
startEvictionThread :: StalePeerTracker -> PeerManager -> IO ThreadId
startEvictionThread spt pm = do
  tid <- forkIO $ evictionLoop spt pm
  atomically $ writeTVar (sptEvictionThread spt) (Just tid)
  return tid

-- | Stop the eviction check thread
stopEvictionThread :: StalePeerTracker -> IO ()
stopEvictionThread spt = do
  mTid <- readTVarIO (sptEvictionThread spt)
  case mTid of
    Just tid -> killThread tid
    Nothing -> return ()
  atomically $ writeTVar (sptEvictionThread spt) Nothing

-- | Main eviction check loop
-- Runs every staleCheckInterval / 4 to catch issues promptly
evictionLoop :: StalePeerTracker -> PeerManager -> IO ()
evictionLoop spt pm = forever $ do
  -- Sleep for a fraction of the stale check interval
  threadDelay (fromIntegral staleCheckInterval * 250000)  -- 25% of interval in microseconds

  now <- round <$> getPOSIXTime
  peers <- readTVarIO (pmPeers pm)
  states <- readTVarIO (sptPeerStates spt)

  -- Check each peer
  forM_ (Map.toList peers) $ \(addr, pc) -> do
    info <- readTVarIO (pcInfo pc)

    -- Only check connected peers
    when (piState info == PeerConnected) $ do
      -- Ensure peer has eviction state
      ensurePeerState spt addr info

      -- Check if peer is stale
      (shouldDisconnect, reason) <- checkStalePeer spt addr False  -- TODO: track compact block mode

      when shouldDisconnect $ do
        -- Disconnect the peer
        disconnectPeer pc
        atomically $ do
          modifyTVar' (pmPeers pm) (Map.delete addr)
          modifyTVar' (sptPeerStates spt) (Map.delete addr)

      -- Check for chain sync timeout (may need to send getheaders)
      unless shouldDisconnect $ do
        (_, needsGetheaders, _) <- considerEviction spt addr now
        when needsGetheaders $ do
          -- Build block locator from our tip
          ourTip <- readTVarIO (sptOurTipHash spt)
          -- Send getheaders with locator starting from tip
          let getHeaders = GetHeaders
                { ghVersion = fromIntegral protocolVersion
                , ghLocators = [ourTip]
                , ghHashStop = BlockHash (Hash256 (BS.replicate 32 0))
                }
          sendMessage pc (MGetHeaders getHeaders)
            `catch` (\(_ :: IOException) -> return ())

-- | Ensure a peer has eviction state tracking
ensurePeerState :: StalePeerTracker -> SockAddr -> PeerInfo -> IO ()
ensurePeerState spt addr info = do
  states <- readTVarIO (sptPeerStates spt)
  unless (Map.member addr states) $ do
    let isOutbound = not (piInbound info)
        newState = defaultPeerEvictionState isOutbound False (piConnectedAt info)
    atomically $ modifyTVar' (sptPeerStates spt) (Map.insert addr newState)

--------------------------------------------------------------------------------
-- Outbound Sync Protection
-- Ensures at least one outbound peer is synced with our chain
-- Reference: Bitcoin Core net_processing.cpp outbound sync protection
--------------------------------------------------------------------------------

-- | Outbound sync protection state
data OutboundSyncProtection = OutboundSyncProtection
  { ospSyncedPeers    :: !(TVar (Set.Set SockAddr))  -- ^ Outbound peers that are synced
  , ospNeedExtra      :: !(TVar Bool)                 -- ^ Whether we need extra outbound
  , ospLastCheck      :: !(TVar Int64)                -- ^ Last check timestamp
  }

-- | Create new outbound sync protection
newOutboundSyncProtection :: IO OutboundSyncProtection
newOutboundSyncProtection = OutboundSyncProtection
  <$> newTVarIO Set.empty
  <*> newTVarIO False
  <*> newTVarIO 0

-- | Check if any outbound peer is synced
checkOutboundSynced :: OutboundSyncProtection -> IO Bool
checkOutboundSynced osp = do
  synced <- readTVarIO (ospSyncedPeers osp)
  return $ not $ Set.null synced

-- | Update outbound sync status for a peer
updateOutboundSyncStatus :: OutboundSyncProtection -> SockAddr -> Bool -> Bool -> IO ()
updateOutboundSyncStatus osp addr isOutbound isSynced = do
  when isOutbound $ atomically $ do
    if isSynced
      then modifyTVar' (ospSyncedPeers osp) (Set.insert addr)
      else modifyTVar' (ospSyncedPeers osp) (Set.delete addr)

-- | Check if we need an extra outbound connection for sync protection
needsExtraOutbound :: OutboundSyncProtection -> StalePeerTracker -> IO Bool
needsExtraOutbound osp spt = do
  now <- round <$> getPOSIXTime

  -- Only check every 45 seconds
  lastCheck <- readTVarIO (ospLastCheck osp)
  if now - lastCheck < 45
    then readTVarIO (ospNeedExtra osp)
    else do
      atomically $ writeTVar (ospLastCheck osp) now

      -- Check if any outbound is synced
      synced <- checkOutboundSynced osp
      let needExtra = not synced

      atomically $ writeTVar (ospNeedExtra osp) needExtra
      return needExtra

--------------------------------------------------------------------------------
-- BIP152 Compact Blocks (Phase 31)
--------------------------------------------------------------------------------

-- | Short transaction ID (6 bytes = 48 bits)
type ShortTxId = Word64

-- | BIP152 compact block version
-- Version 1: pre-segwit (uses txid for short IDs)
-- Version 2: segwit (uses wtxid for short IDs)
data CompactBlockVersion = CompactBlockV1 | CompactBlockV2
  deriving (Show, Eq, Generic)

instance NFData CompactBlockVersion

-- | Prefilled transaction in a compact block
-- The index is relative to the previous prefilled tx
data PrefilledTx = PrefilledTx
  { ptIndex :: !Word16      -- ^ Relative index offset from previous prefilled tx
  , ptTx    :: !Tx          -- ^ Full transaction
  } deriving (Show, Eq, Generic)

instance NFData PrefilledTx

instance Serialize PrefilledTx where
  put PrefilledTx{..} = do
    -- Index is encoded as a compact size (varint)
    putVarInt (fromIntegral ptIndex)
    put ptTx  -- Transaction with witness data
  get = do
    idx <- getVarInt'
    tx <- get
    return $ PrefilledTx (fromIntegral idx) tx

-- | Compact block message (cmpctblock)
-- Reference: Bitcoin Core blockencodings.h CBlockHeaderAndShortTxIDs
data CmpctBlock = CmpctBlock
  { cbHeader     :: !BlockHeader       -- ^ Block header (80 bytes)
  , cbNonce      :: !Word64            -- ^ Random nonce for SipHash key
  , cbShortIds   :: ![ShortTxId]       -- ^ Short transaction IDs (6 bytes each)
  , cbPrefilled  :: ![PrefilledTx]     -- ^ Prefilled transactions (at minimum: coinbase)
  } deriving (Show, Eq, Generic)

instance NFData CmpctBlock

instance Serialize CmpctBlock where
  put CmpctBlock{..} = do
    put cbHeader
    putWord64le cbNonce
    -- Short IDs are encoded as VarInt count followed by 6-byte values
    putVarInt (fromIntegral $ length cbShortIds)
    mapM_ putShortId cbShortIds
    -- Prefilled transactions
    putVarInt (fromIntegral $ length cbPrefilled)
    mapM_ put cbPrefilled

  get = do
    header <- get
    nonce <- getWord64le
    shortIdCount <- getVarInt'
    shortIds <- replicateM (fromIntegral shortIdCount) getShortId
    prefilledCount <- getVarInt'
    prefilled <- replicateM (fromIntegral prefilledCount) get
    return $ CmpctBlock header nonce shortIds prefilled

-- | Put a 6-byte short ID (little-endian)
putShortId :: ShortTxId -> Put
putShortId sid = do
  -- Write 6 bytes in little-endian order
  let bytes = [fromIntegral (sid `shiftR` (i * 8)) | i <- [0..5]]
  mapM_ putWord8 bytes

-- | Get a 6-byte short ID (little-endian)
getShortId :: Get ShortTxId
getShortId = do
  bytes <- replicateM 6 getWord8
  return $ foldl (\acc (i, b) -> acc .|. (fromIntegral b `shiftL` (i * 8))) 0
                 (zip [0..] bytes)

-- | Request for missing transactions in a compact block (getblocktxn)
data GetBlockTxn = GetBlockTxn
  { gbtBlockHash :: !BlockHash    -- ^ Hash of the block
  , gbtIndexes   :: ![Word16]     -- ^ Indices of missing transactions (differential encoded)
  } deriving (Show, Eq, Generic)

instance NFData GetBlockTxn

instance Serialize GetBlockTxn where
  put GetBlockTxn{..} = do
    put gbtBlockHash
    putVarInt (fromIntegral $ length gbtIndexes)
    -- Differential encoding: store differences from previous index
    let diffs = differentialEncode gbtIndexes
    mapM_ (putVarInt . fromIntegral) diffs

  get = do
    blockHash <- get
    count <- getVarInt'
    diffs <- replicateM (fromIntegral count) (fromIntegral <$> getVarInt')
    let indexes = differentialDecode diffs
    return $ GetBlockTxn blockHash indexes

-- | Differential encode a sorted list of indices
-- Each value is stored as the difference from (previous + 1)
differentialEncode :: [Word16] -> [Word16]
differentialEncode [] = []
differentialEncode (x:xs) = x : go x xs
  where
    go _ [] = []
    go prev (cur:rest) = (cur - prev - 1) : go cur rest

-- | Differential decode a list of differences back to indices
differentialDecode :: [Word16] -> [Word16]
differentialDecode [] = []
differentialDecode (x:xs) = go x xs [x]
  where
    go _ [] acc = reverse acc
    go prev (d:rest) acc =
      let cur = prev + d + 1
      in go cur rest (cur:acc)

-- | Response with missing transactions (blocktxn)
data BlockTxn = BlockTxn
  { btBlockHash :: !BlockHash     -- ^ Hash of the block
  , btTxns      :: ![Tx]          -- ^ Missing transactions in order
  } deriving (Show, Eq, Generic)

instance NFData BlockTxn

instance Serialize BlockTxn where
  put BlockTxn{..} = do
    put btBlockHash
    putVarInt (fromIntegral $ length btTxns)
    mapM_ put btTxns
  get = do
    blockHash <- get
    count <- getVarInt'
    txns <- replicateM (fromIntegral count) get
    return $ BlockTxn blockHash txns

--------------------------------------------------------------------------------
-- Short ID Computation
--------------------------------------------------------------------------------

-- | Compute the SipHash key from block header and nonce
-- This matches Bitcoin Core's FillShortTxIDSelector()
computeShortIdKey :: BlockHeader -> Word64 -> SipHashKey
computeShortIdKey header nonce =
  let -- Serialize header (80 bytes) + nonce (8 bytes)
      combined = BS.append (encode header) (runPut $ putWord64le nonce)
      -- SHA256 of the combined data (not double-SHA256!)
      hashResult = sha256 combined
      -- Extract first two 64-bit values as SipHash keys
      k0 = decodeLE64 (BS.take 8 hashResult)
      k1 = decodeLE64 (BS.take 8 (BS.drop 8 hashResult))
  in SipHashKey k0 k1

-- | Decode 8 bytes as little-endian Word64
decodeLE64 :: ByteString -> Word64
decodeLE64 bs
  | BS.length bs < 8 = 0
  | otherwise =
      let bytes = BS.unpack (BS.take 8 bs)
      in foldl' (\acc (i, b) -> acc .|. (fromIntegral b `shiftL` (i * 8))) 0
                (zip [0..7] bytes)

-- | Compute short ID for a transaction
-- Returns lower 48 bits of SipHash(wtxid)
computeShortId :: SipHashKey -> ByteString -> ShortTxId
computeShortId key wtxidBytes =
  sipHash128 key wtxidBytes .&. 0xffffffffffff  -- Mask to 48 bits

-- | Compute witness txid (wtxid) for a transaction
-- For version 2 compact blocks, this includes witness data
computeWtxid :: Tx -> Hash256
computeWtxid tx = doubleSHA256 (encode tx)

--------------------------------------------------------------------------------
-- Compact Block Creation
--------------------------------------------------------------------------------

-- | Compact block configuration
data CompactBlockConfig = CompactBlockConfig
  { cbcVersion         :: !Word64       -- ^ Protocol version (1 or 2)
  , cbcHighBandwidth   :: !Bool         -- ^ Whether high-bandwidth mode is enabled
  , cbcMaxHighBW       :: !Int          -- ^ Max high-bandwidth peers (default 3)
  } deriving (Show, Eq, Generic)

instance NFData CompactBlockConfig

-- | Default compact block configuration (version 2 for segwit)
defaultCompactBlockConfig :: CompactBlockConfig
defaultCompactBlockConfig = CompactBlockConfig
  { cbcVersion       = 2
  , cbcHighBandwidth = True
  , cbcMaxHighBW     = 3
  }

-- | Create a compact block from a full block
-- The coinbase is always prefilled at index 0
createCompactBlock :: Block -> IO CmpctBlock
createCompactBlock (Block header txns) = do
  -- Generate random nonce
  nonce <- randomIO

  let sipKey = computeShortIdKey header nonce

      -- Coinbase is always prefilled at index 0
      coinbase = head txns
      prefilled = [PrefilledTx 0 coinbase]

      -- Short IDs for remaining transactions
      -- For version 2, use wtxid (includes witness)
      shortIds = map (computeShortId sipKey . getHash256 . computeWtxid) (tail txns)

  return $ CmpctBlock
    { cbHeader    = header
    , cbNonce     = nonce
    , cbShortIds  = shortIds
    , cbPrefilled = prefilled
    }

--------------------------------------------------------------------------------
-- Block Reconstruction
--------------------------------------------------------------------------------

-- | State of a partially downloaded block
data PartiallyDownloadedBlock = PartiallyDownloadedBlock
  { pdbHeader        :: !BlockHeader
  , pdbAvailable     :: !(Map Int (Maybe Tx))  -- ^ Index -> Maybe Tx (Nothing = missing)
  , pdbSipKey        :: !SipHashKey            -- ^ SipHash key for this block
  , pdbPrefilledCount:: !Int                   -- ^ Number of prefilled transactions
  , pdbMempoolCount  :: !Int                   -- ^ Number found in mempool
  , pdbTotalTxns     :: !Int                   -- ^ Total transaction count
  } deriving (Show, Generic)

-- | Compact block reconstruction state
data CompactBlockState = CompactBlockState
  { cbsPending :: !(TVar (Map BlockHash PartiallyDownloadedBlock))
      -- ^ Partially downloaded blocks waiting for missing txns
  , cbsConfig  :: !CompactBlockConfig
  }

-- | Initialize a partially downloaded block from a compact block message
-- Returns the partially downloaded block and list of missing indices (if any)
initPartialBlock :: CmpctBlock
                 -> Map TxId Tx       -- ^ Mempool transactions by TxId
                 -> Either String (PartiallyDownloadedBlock, [Int])
initPartialBlock cb mempoolTxs = do
  -- Validate compact block
  when (null (cbPrefilled cb)) $
    Left "Invalid compact block: no prefilled transactions"

  let header = cbHeader cb
      nonce = cbNonce cb
      sipKey = computeShortIdKey header nonce

      -- Total transaction count
      totalTxns = length (cbShortIds cb) + length (cbPrefilled cb)

      -- Build initial availability map with all slots empty
      emptyMap = Map.fromList [(i, Nothing) | i <- [0..totalTxns-1]]

      -- Insert prefilled transactions at their absolute indices
      -- The indices in PrefilledTx are relative to previous prefilled tx
      (_, mapWithPrefilled) = foldl' insertPrefilled (0, emptyMap) (cbPrefilled cb)

      -- Build map of short ID -> index for remaining slots
      shortIdMap = buildShortIdMap (cbShortIds cb) mapWithPrefilled

      -- Try to fill from mempool
      (mapWithMempool, mempoolHits) = fillFromMempool sipKey shortIdMap mempoolTxs mapWithPrefilled

      -- Find missing indices
      missing = [i | (i, Nothing) <- Map.toList mapWithMempool]

      pdb = PartiallyDownloadedBlock
        { pdbHeader         = header
        , pdbAvailable      = mapWithMempool
        , pdbSipKey         = sipKey
        , pdbPrefilledCount = length (cbPrefilled cb)
        , pdbMempoolCount   = mempoolHits
        , pdbTotalTxns      = totalTxns
        }

  return (pdb, missing)
  where
    insertPrefilled (prevIdx, m) (PrefilledTx relIdx tx) =
      let absIdx = prevIdx + fromIntegral relIdx
      in (absIdx + 1, Map.insert absIdx (Just tx) m)

    -- Build map of short ID -> absolute index for slots without prefilled txs
    buildShortIdMap shortIds available =
      let emptySlots = [i | (i, Nothing) <- Map.toList available]
      in Map.fromList $ zip shortIds emptySlots

    -- Try to fill slots from mempool transactions
    fillFromMempool sipKey shortIdMap mempool available =
      Map.foldlWithKey' tryFill (available, 0) mempool
      where
        tryFill (avail, hits) txid tx =
          let wtxid = computeWtxid tx
              shortId = computeShortId sipKey (getHash256 wtxid)
          in case Map.lookup shortId shortIdMap of
               Just idx -> (Map.insert idx (Just tx) avail, hits + 1)
               Nothing -> (avail, hits)

-- | Fill a partially downloaded block with missing transactions
-- Returns the reconstructed block or an error
fillPartialBlock :: PartiallyDownloadedBlock -> [Tx] -> Either String Block
fillPartialBlock pdb missingTxns = do
  let available = pdbAvailable pdb
      missing = [i | (i, Nothing) <- Map.toList available]

  -- Check we have the right number of missing transactions
  when (length missingTxns /= length missing) $
    Left $ "Wrong number of missing transactions: expected "
           ++ show (length missing) ++ ", got " ++ show (length missingTxns)

  -- Fill in the missing transactions
  let filled = foldl' insertMissing available (zip missing missingTxns)

  -- Extract transactions in order
  let txns = [tx | i <- [0..pdbTotalTxns pdb - 1]
                 , Just tx <- [Map.lookup i filled >>= id]]

  -- Verify we got all transactions
  when (length txns /= pdbTotalTxns pdb) $
    Left "Failed to reconstruct all transactions"

  return $ Block (pdbHeader pdb) txns
  where
    insertMissing m (idx, tx) = Map.insert idx (Just tx) m

-- | Reconstruct a block from compact block and mempool
-- This is the main entry point for compact block reconstruction
reconstructBlock :: CmpctBlock
                 -> Map TxId Tx     -- ^ Mempool transactions
                 -> [Tx]            -- ^ Missing transactions (from blocktxn)
                 -> Either String Block
reconstructBlock cb mempool missingTxns = do
  (pdb, _missing) <- initPartialBlock cb mempool
  fillPartialBlock pdb missingTxns

-- | Get the indices of missing transactions
getMissingTxIndices :: PartiallyDownloadedBlock -> [Int]
getMissingTxIndices pdb = [i | (i, Nothing) <- Map.toList (pdbAvailable pdb)]

--------------------------------------------------------------------------------
-- High-Bandwidth Mode Management
--------------------------------------------------------------------------------

-- | High-bandwidth mode state
-- BIP152 allows up to 3 peers to send compact blocks immediately (high-bandwidth)
data HighBandwidthState = HighBandwidthState
  { hbsPeers     :: !(TVar (Set.Set SockAddr))  -- ^ High-bandwidth peers
  , hbsMaxPeers  :: !Int                         -- ^ Maximum high-bandwidth peers
  }

-- | Create new high-bandwidth state
newHighBandwidthState :: Int -> IO HighBandwidthState
newHighBandwidthState maxPeers = do
  peers <- newTVarIO Set.empty
  return $ HighBandwidthState peers maxPeers

-- | Add a peer to high-bandwidth mode
-- Returns True if added, False if already at max capacity
addHighBandwidthPeer :: HighBandwidthState -> SockAddr -> IO Bool
addHighBandwidthPeer hbs addr = atomically $ do
  peers <- readTVar (hbsPeers hbs)
  if Set.size peers >= hbsMaxPeers hbs && not (Set.member addr peers)
    then return False
    else do
      writeTVar (hbsPeers hbs) (Set.insert addr peers)
      return True

-- | Remove a peer from high-bandwidth mode
removeHighBandwidthPeer :: HighBandwidthState -> SockAddr -> IO ()
removeHighBandwidthPeer hbs addr = atomically $
  modifyTVar' (hbsPeers hbs) (Set.delete addr)

-- | Check if a peer is in high-bandwidth mode
isHighBandwidthPeer :: HighBandwidthState -> SockAddr -> IO Bool
isHighBandwidthPeer hbs addr = do
  peers <- readTVarIO (hbsPeers hbs)
  return $ Set.member addr peers

-- | Get list of high-bandwidth peers
getHighBandwidthPeers :: HighBandwidthState -> IO [SockAddr]
getHighBandwidthPeers hbs = Set.toList <$> readTVarIO (hbsPeers hbs)

--------------------------------------------------------------------------------
-- SipHash Key Type (from Index module)
--------------------------------------------------------------------------------

-- | SipHash key (two 64-bit values)
-- Note: This duplicates the definition in Index.hs for module independence
data SipHashKey = SipHashKey !Word64 !Word64
  deriving (Show, Eq)

-- | SipHash-2-4 with 64-bit output
-- Reference: https://github.com/veorq/SipHash
sipHash128 :: SipHashKey -> ByteString -> Word64
sipHash128 (SipHashKey k0 k1) msg =
  let v0 = 0x736f6d6570736575 `xor` k0
      v1 = 0x646f72616e646f6d `xor` k1
      v2 = 0x6c7967656e657261 `xor` k0
      v3 = 0x7465646279746573 `xor` k1

      -- Process full 8-byte blocks
      (v0', v1', v2', v3', leftover) = processBlocks v0 v1 v2 v3 msg

      -- Process final block with length byte
      finalBlock = buildFinalBlock leftover (BS.length msg)
      (v0'', v1'', v2'', v3'') = sipRound2 v0' v1' v2' v3' finalBlock

      -- Finalization
      v2''' = v2'' `xor` 0xff
      (v0f, v1f, v2f, v3f) = sipRound4 v0'' v1'' v2''' v3''
  in v0f `xor` v1f `xor` v2f `xor` v3f
  where
    processBlocks !v0 !v1 !v2 !v3 !bs
      | BS.length bs < 8 = (v0, v1, v2, v3, bs)
      | otherwise =
          let block = decodeLE64' (BS.take 8 bs)
              rest = BS.drop 8 bs
              (v0', v1', v2', v3') = sipRound2 v0 v1 v2 v3 block
          in processBlocks v0' v1' v2' v3' rest

    decodeLE64' bs
      | BS.length bs < 8 = 0
      | otherwise =
          let bytes = BS.unpack (BS.take 8 bs)
          in foldl' (\acc (i, b) -> acc .|. (fromIntegral b `shiftL` (i * 8))) 0
                    (zip [0..7] bytes)

    buildFinalBlock leftover totalLen =
      let padded = leftover `BS.append` BS.replicate (7 - BS.length leftover) 0
          lenByte = fromIntegral (totalLen .&. 0xff) `shiftL` 56
      in decodeLE64' padded .|. lenByte

    sipRound2 !v0 !v1 !v2 !v3 m =
      let v3' = v3 `xor` m
          (!v0a, !v1a, !v2a, !v3a) = sipRound v0 v1 v2 v3'
          (!v0b, !v1b, !v2b, !v3b) = sipRound v0a v1a v2a v3a
          v0' = v0b `xor` m
      in (v0', v1b, v2b, v3b)

    sipRound4 !v0 !v1 !v2 !v3 =
      let (!v0a, !v1a, !v2a, !v3a) = sipRound v0 v1 v2 v3
          (!v0b, !v1b, !v2b, !v3b) = sipRound v0a v1a v2a v3a
          (!v0c, !v1c, !v2c, !v3c) = sipRound v0b v1b v2b v3b
          (!v0d, !v1d, !v2d, !v3d) = sipRound v0c v1c v2c v3c
      in (v0d, v1d, v2d, v3d)

    sipRound !v0 !v1 !v2 !v3 =
      let !v0' = v0 + v1
          !v1' = rotl64 v1 13
          !v1'' = v1' `xor` v0'
          !v0'' = rotl64 v0' 32
          !v2' = v2 + v3
          !v3' = rotl64 v3 16
          !v3'' = v3' `xor` v2'
          !v0''' = v0'' + v3''
          !v3''' = rotl64 v3'' 21
          !v3'''' = v3''' `xor` v0'''
          !v2'' = v2' + v1''
          !v1''' = rotl64 v1'' 17
          !v1'''' = v1''' `xor` v2''
          !v2''' = rotl64 v2'' 32
      in (v0''', v1'''', v2''', v3'''')

    rotl64 x n = (x `shiftL` n) .|. (x `shiftR` (64 - n))

--------------------------------------------------------------------------------
-- BIP324 V2 Transport Protocol (Phase 32)
--------------------------------------------------------------------------------

-- | BIP324 Constants
-- Reference: Bitcoin Core bip324.h

-- | Maximum garbage length (4095 bytes)
v2MaxGarbageLen :: Int
v2MaxGarbageLen = 4095

-- | Garbage terminator length (16 bytes)
v2GarbageTerminatorLen :: Int
v2GarbageTerminatorLen = 16

-- | Re-keying interval (2^24 - 1 = 16777215 messages)
-- After this many messages, derive new keys
v2RekeyInterval :: Word32
v2RekeyInterval = 224  -- Actually 2^24 - 1, but Bitcoin Core uses 224 for testing

-- | Encrypted length prefix (3 bytes)
v2LengthLen :: Int
v2LengthLen = 3

-- | Message header (1 byte: flags)
v2HeaderLen :: Int
v2HeaderLen = 1

-- | Total expansion: length + header + Poly1305 tag
-- 3 + 1 + 16 = 20 bytes
v2Expansion :: Int
v2Expansion = v2LengthLen + v2HeaderLen + 16  -- 16 = Poly1305 tag

-- | Ignore bit in header (0x80)
v2IgnoreBit :: Word8
v2IgnoreBit = 0x80

-- | NODE_P2P_V2 service flag (BIP324)
nodeP2PV2 :: ServiceFlag
nodeP2PV2 = ServiceFlag (1 `shiftL` 11)

--------------------------------------------------------------------------------
-- Short Message IDs (BIP324)
--------------------------------------------------------------------------------

-- | Short message ID (1 byte instead of 12 byte ASCII command)
type V2MessageId = Word8

-- | V2 short message IDs
-- Index 0 means use 12-byte ASCII command (fallback)
-- Reference: Bitcoin Core net.cpp V2_MESSAGE_IDS
v2MessageIds :: [(V2MessageId, ByteString)]
v2MessageIds =
  [ (0,  "")           -- 12 bytes follow for message type (like V1)
  , (1,  "addr")
  , (2,  "block")
  , (3,  "blocktxn")
  , (4,  "cmpctblock")
  , (5,  "feefilter")
  , (6,  "filteradd")
  , (7,  "filterclear")
  , (8,  "filterload")
  , (9,  "getblocks")
  , (10, "getblocktxn")
  , (11, "getdata")
  , (12, "getheaders")
  , (13, "headers")
  , (14, "inv")
  , (15, "mempool")
  , (16, "merkleblock")
  , (17, "notfound")
  , (18, "ping")
  , (19, "pong")
  , (20, "sendcmpct")
  , (21, "tx")
  , (22, "getcfilters")
  , (23, "cfilter")
  , (24, "getcfheaders")
  , (25, "cfheaders")
  , (26, "getcfcheckpt")
  , (27, "cfcheckpt")
  , (28, "addrv2")
  -- 29-32 reserved for future use
  ]

-- | Get short message ID for a command name
-- Returns Nothing if the command requires 12-byte encoding
shortMsgId :: ByteString -> Maybe V2MessageId
shortMsgId cmd = lookup cmd [(c, i) | (i, c) <- v2MessageIds, not (BS.null c)]

-- | Get command name from short message ID
-- Returns Nothing for unknown IDs
shortMsgIdToCommand :: V2MessageId -> Maybe ByteString
shortMsgIdToCommand mid = lookup mid v2MessageIds

--------------------------------------------------------------------------------
-- ElligatorSwift Encoding (BIP324)
--------------------------------------------------------------------------------

-- | ElligatorSwift public key (64 bytes)
-- This encoding makes public keys indistinguishable from random bytes
newtype EllSwiftPubKey = EllSwiftPubKey { getEllSwiftPubKey :: ByteString }
  deriving stock (Show, Eq, Generic)
  deriving newtype (NFData)

-- | Create an ElligatorSwift encoded public key from a secret key
-- NOTE: This is a simplified implementation. Full ElligatorSwift requires
-- secp256k1 library support for proper encoding.
-- Reference: Bitcoin Core key.cpp EllSwiftCreate
ellSwiftCreate :: ByteString -> ByteString -> IO EllSwiftPubKey
ellSwiftCreate secretKey entropy = do
  -- In a full implementation, this would use secp256k1_ellswift_create
  -- For now, we use a deterministic derivation that maintains the security
  -- property of being indistinguishable from random
  let combined = BS.append secretKey entropy
      -- Use HKDF to derive 64 bytes that look random
      expanded = hkdfSha256 combined "secp256k1_ellswift" 64
  return $ EllSwiftPubKey expanded

-- | Decode an ElligatorSwift public key to a standard compressed public key
-- NOTE: This requires secp256k1 library for proper implementation
ellSwiftDecode :: EllSwiftPubKey -> Maybe ByteString
ellSwiftDecode (EllSwiftPubKey _bs) =
  -- In a full implementation, this would use secp256k1_ellswift_decode
  -- For now, return Nothing as we cannot properly decode without secp256k1
  Nothing

--------------------------------------------------------------------------------
-- HKDF-SHA256 Key Derivation (RFC 5869)
--------------------------------------------------------------------------------

-- | HKDF-SHA256 - derive key material from input key material
-- This matches Bitcoin Core's CHKDF_HMAC_SHA256_L32
hkdfSha256 :: ByteString    -- ^ Input key material (IKM)
           -> ByteString    -- ^ Salt
           -> Int           -- ^ Output length in bytes
           -> ByteString
hkdfSha256 ikm salt outLen =
  let -- Extract phase: PRK = HMAC-SHA256(salt, IKM)
      prk = hmacSha256 salt ikm
      -- Expand phase
  in hkdfExpand prk BS.empty outLen

-- | HKDF-Expand using SHA256
-- Expands the PRK to the desired length
hkdfExpand :: ByteString    -- ^ Pseudorandom key (PRK)
           -> ByteString    -- ^ Info (context)
           -> Int           -- ^ Output length
           -> ByteString
hkdfExpand prk info outLen = BS.take outLen $ go BS.empty 1
  where
    go :: ByteString -> Word8 -> ByteString
    go prev counter
      | BS.length prev >= outLen = prev
      | otherwise =
          let block = hmacSha256 prk (prev `BS.append` info `BS.append` BS.singleton counter)
          in go (prev `BS.append` block) (counter + 1)

-- | HMAC-SHA256
hmacSha256 :: ByteString -> ByteString -> ByteString
hmacSha256 key msg = convert (HMAC.hmacGetDigest hmacResult)
  where
    hmacResult :: HMAC.HMAC H.SHA256
    hmacResult = HMAC.hmac key msg

--------------------------------------------------------------------------------
-- V2 Session Keys
--------------------------------------------------------------------------------

-- | V2 session keys derived from ECDH shared secret
data V2SessionKeys = V2SessionKeys
  { v2skSendLKey    :: !ByteString   -- ^ Key for encrypting length (send direction)
  , v2skRecvLKey    :: !ByteString   -- ^ Key for decrypting length (recv direction)
  , v2skSendPKey    :: !ByteString   -- ^ Key for encrypting payload (send direction)
  , v2skRecvPKey    :: !ByteString   -- ^ Key for decrypting payload (recv direction)
  , v2skSendGarbage :: !ByteString   -- ^ Garbage terminator for send
  , v2skRecvGarbage :: !ByteString   -- ^ Garbage terminator for recv
  , v2skSessionId   :: !ByteString   -- ^ Session ID (32 bytes)
  } deriving (Show, Eq, Generic)

instance NFData V2SessionKeys

-- | Derive V2 session keys from ECDH shared secret
-- Reference: Bitcoin Core bip324.cpp Initialize
deriveV2SessionKeys :: ByteString   -- ^ ECDH shared secret (32 bytes)
                    -> ByteString   -- ^ Network magic (4 bytes)
                    -> Bool         -- ^ Are we the initiator?
                    -> V2SessionKeys
deriveV2SessionKeys ecdhSecret netMagic initiator =
  let -- Salt = "bitcoin_v2_shared_secret" + network magic
      salt = "bitcoin_v2_shared_secret" `BS.append` netMagic

      -- Use HKDF to derive all keys
      hkdf label = hkdfExpand (hmacSha256 salt ecdhSecret) label 32

      initiatorL = hkdf "initiator_L"
      initiatorP = hkdf "initiator_P"
      responderL = hkdf "responder_L"
      responderP = hkdf "responder_P"

      -- Garbage terminators (16 bytes each from 32-byte output)
      garbageTerminators = hkdf "garbage_terminators"
      initiatorGarbage = BS.take 16 garbageTerminators
      responderGarbage = BS.take 16 $ BS.drop 16 garbageTerminators

      -- Session ID
      sessionId = hkdf "session_id"

      -- Assign keys based on initiator/responder role
      (sendL, recvL, sendP, recvP, sendGarbage, recvGarbage) =
        if initiator
        then (initiatorL, responderL, initiatorP, responderP, initiatorGarbage, responderGarbage)
        else (responderL, initiatorL, responderP, initiatorP, responderGarbage, initiatorGarbage)

  in V2SessionKeys
       { v2skSendLKey    = sendL
       , v2skRecvLKey    = recvL
       , v2skSendPKey    = sendP
       , v2skRecvPKey    = recvP
       , v2skSendGarbage = sendGarbage
       , v2skRecvGarbage = recvGarbage
       , v2skSessionId   = sessionId
       }

--------------------------------------------------------------------------------
-- FSChaCha20 (Forward-Secure ChaCha20)
--------------------------------------------------------------------------------

-- | Forward-secure ChaCha20 stream cipher with automatic re-keying
-- Reference: Bitcoin Core crypto/chacha20.h FSChaCha20
data FSChaCha20 = FSChaCha20
  { fsc20Key       :: !ByteString   -- ^ Current 32-byte key
  , fsc20Counter   :: !Word32       -- ^ Message counter (for re-keying)
  , fsc20RekeyInt  :: !Word32       -- ^ Re-key interval
  } deriving (Show, Eq, Generic)

instance NFData FSChaCha20

-- | Create a new FSChaCha20 cipher
newFSChaCha20 :: ByteString -> Word32 -> FSChaCha20
newFSChaCha20 key rekeyInterval = FSChaCha20
  { fsc20Key      = key
  , fsc20Counter  = 0
  , fsc20RekeyInt = rekeyInterval
  }

-- | Encrypt/decrypt using FSChaCha20 (XOR operation)
-- Returns the new cipher state and the output
fsCrypt :: FSChaCha20 -> ByteString -> (FSChaCha20, ByteString)
fsCrypt cipher input =
  let nonce = BS.replicate 12 0  -- Nonce is always zero
      -- ChaCha20 keystream generation
      (keystream, _) = chacha20KeyStream (fsc20Key cipher) nonce (BS.length input)
      output = BS.pack $ BS.zipWith xor input keystream

      -- Update counter and possibly re-key
      newCounter = fsc20Counter cipher + 1
      cipher' = if newCounter == fsc20RekeyInt cipher
                then rekey cipher
                else cipher { fsc20Counter = newCounter }
  in (cipher', output)

-- | Re-key the FSChaCha20 cipher
rekey :: FSChaCha20 -> FSChaCha20
rekey cipher =
  let nonce = BS.replicate 12 0
      (newKey, _) = chacha20KeyStream (fsc20Key cipher) nonce 32
  in cipher { fsc20Key = newKey, fsc20Counter = 0 }

-- | Generate ChaCha20 keystream (simplified implementation)
chacha20KeyStream :: ByteString -> ByteString -> Int -> (ByteString, ByteString)
chacha20KeyStream key nonce len =
  -- Use cryptonite's ChaCha implementation
  let st = ChaCha.initialize 20 key nonce
      -- Generate keystream by encrypting zeros
      zeros = BS.replicate len 0
      (output, st') = ChaCha.combine st zeros
  in (output, BS.empty)  -- We don't need the state for this use case

--------------------------------------------------------------------------------
-- FSChaCha20Poly1305 (Forward-Secure AEAD)
--------------------------------------------------------------------------------

-- | Forward-secure ChaCha20-Poly1305 AEAD
-- Reference: Bitcoin Core crypto/chacha20poly1305.h FSChaCha20Poly1305
data FSChaCha20Poly1305 = FSChaCha20Poly1305
  { fscpKey       :: !ByteString   -- ^ Current 32-byte key
  , fscpCounter   :: !Word32       -- ^ Message counter
  , fscpRekeyInt  :: !Word32       -- ^ Re-key interval
  } deriving (Show, Eq, Generic)

instance NFData FSChaCha20Poly1305

-- | Create a new FSChaCha20Poly1305 cipher
newFSChaCha20Poly1305 :: ByteString -> Word32 -> FSChaCha20Poly1305
newFSChaCha20Poly1305 key rekeyInterval = FSChaCha20Poly1305
  { fscpKey      = key
  , fscpCounter  = 0
  , fscpRekeyInt = rekeyInterval
  }

-- | Encrypt with FSChaCha20-Poly1305
-- Returns (new cipher, ciphertext || tag)
fsEncrypt :: FSChaCha20Poly1305
          -> ByteString       -- ^ Additional authenticated data (AAD)
          -> ByteString       -- ^ Plaintext
          -> (FSChaCha20Poly1305, ByteString)
fsEncrypt cipher aad plaintext =
  let -- Build nonce from counter (little-endian, 12 bytes)
      nonce = encodeNonce (fscpCounter cipher)

      -- ChaCha20-Poly1305 AEAD encryption
      (ciphertext, tag) = chacha20Poly1305Encrypt (fscpKey cipher) nonce aad plaintext

      -- Update counter and possibly re-key
      newCounter = fscpCounter cipher + 1
      cipher' = if newCounter == fscpRekeyInt cipher
                then rekeyAead cipher
                else cipher { fscpCounter = newCounter }

  in (cipher', ciphertext `BS.append` tag)

-- | Decrypt with FSChaCha20-Poly1305
-- Returns (new cipher, Maybe plaintext) - Nothing on auth failure
fsDecrypt :: FSChaCha20Poly1305
          -> ByteString       -- ^ Additional authenticated data
          -> ByteString       -- ^ Ciphertext || tag
          -> (FSChaCha20Poly1305, Maybe ByteString)
fsDecrypt cipher aad input
  | BS.length input < 16 = (cipher, Nothing)  -- Need at least a tag
  | otherwise =
      let (ciphertext, tag) = BS.splitAt (BS.length input - 16) input
          nonce = encodeNonce (fscpCounter cipher)

          -- ChaCha20-Poly1305 AEAD decryption
          result = chacha20Poly1305Decrypt (fscpKey cipher) nonce aad ciphertext tag

          -- Update counter and possibly re-key
          newCounter = fscpCounter cipher + 1
          cipher' = if newCounter == fscpRekeyInt cipher
                    then rekeyAead cipher
                    else cipher { fscpCounter = newCounter }

      in (cipher', result)

-- | Re-key the AEAD cipher
rekeyAead :: FSChaCha20Poly1305 -> FSChaCha20Poly1305
rekeyAead cipher =
  let nonce = encodeNonce (fscpCounter cipher)
      -- Generate new key by encrypting zeros
      zeros = BS.replicate 32 0
      (newKey, _) = chacha20Poly1305Encrypt (fscpKey cipher) nonce BS.empty zeros
      -- Take first 32 bytes as new key
  in cipher { fscpKey = BS.take 32 newKey, fscpCounter = 0 }

-- | Encode counter as 12-byte little-endian nonce
encodeNonce :: Word32 -> ByteString
encodeNonce counter =
  let bytes = [ fromIntegral (counter .&. 0xff)
              , fromIntegral ((counter `shiftR` 8) .&. 0xff)
              , fromIntegral ((counter `shiftR` 16) .&. 0xff)
              , fromIntegral ((counter `shiftR` 24) .&. 0xff)
              ]
  in BS.pack bytes `BS.append` BS.replicate 8 0  -- Pad to 12 bytes

-- | ChaCha20-Poly1305 AEAD encryption
-- Returns (ciphertext, 16-byte tag)
chacha20Poly1305Encrypt :: ByteString -> ByteString -> ByteString -> ByteString
                        -> (ByteString, ByteString)
chacha20Poly1305Encrypt key nonce aad plaintext =
  let st = ChaCha.initialize 20 key nonce

      -- First block generates Poly1305 key
      (polyKeyBytes, st') = ChaCha.combine st (BS.replicate 64 0)
      polyKey = BS.take 32 polyKeyBytes

      -- Encrypt plaintext
      (ciphertext, _) = ChaCha.combine st' plaintext

      -- Compute Poly1305 tag over AAD || pad || ciphertext || pad || lengths
      authData = buildAuthData aad ciphertext
      tag = computePoly1305Tag polyKey authData

  in (ciphertext, tag)

-- | ChaCha20-Poly1305 AEAD decryption
-- Returns Just plaintext on success, Nothing on auth failure
chacha20Poly1305Decrypt :: ByteString -> ByteString -> ByteString -> ByteString
                        -> ByteString -> Maybe ByteString
chacha20Poly1305Decrypt key nonce aad ciphertext expectedTag =
  let st = ChaCha.initialize 20 key nonce

      -- First block generates Poly1305 key
      (polyKeyBytes, st') = ChaCha.combine st (BS.replicate 64 0)
      polyKey = BS.take 32 polyKeyBytes

      -- Verify tag first
      authData = buildAuthData aad ciphertext
      computedTag = computePoly1305Tag polyKey authData

  in if constantTimeEq computedTag expectedTag
     then let (plaintext, _) = ChaCha.combine st' ciphertext
          in Just plaintext
     else Nothing

-- | Build authentication data for Poly1305
-- Format: AAD || pad || ciphertext || pad || len(AAD) || len(ciphertext)
buildAuthData :: ByteString -> ByteString -> ByteString
buildAuthData aad ciphertext =
  let aadPad = (16 - BS.length aad `mod` 16) `mod` 16
      ctPad = (16 - BS.length ciphertext `mod` 16) `mod` 16
      aadLen = encodeLen64 (fromIntegral $ BS.length aad)
      ctLen = encodeLen64 (fromIntegral $ BS.length ciphertext)
  in BS.concat [ aad
               , BS.replicate aadPad 0
               , ciphertext
               , BS.replicate ctPad 0
               , aadLen
               , ctLen
               ]

-- | Encode 64-bit length as little-endian bytes
encodeLen64 :: Word64 -> ByteString
encodeLen64 n = BS.pack
  [ fromIntegral (n .&. 0xff)
  , fromIntegral ((n `shiftR` 8) .&. 0xff)
  , fromIntegral ((n `shiftR` 16) .&. 0xff)
  , fromIntegral ((n `shiftR` 24) .&. 0xff)
  , fromIntegral ((n `shiftR` 32) .&. 0xff)
  , fromIntegral ((n `shiftR` 40) .&. 0xff)
  , fromIntegral ((n `shiftR` 48) .&. 0xff)
  , fromIntegral ((n `shiftR` 56) .&. 0xff)
  ]

-- | Compute Poly1305 tag
computePoly1305Tag :: ByteString -> ByteString -> ByteString
computePoly1305Tag key msg =
  case Poly1305.initialize key of
    CryptoFailed _ -> BS.replicate 16 0  -- Should not happen with valid key
    CryptoPassed state ->
      let state' = Poly1305.update state msg
          auth = Poly1305.finalize state'
      in convert auth

-- | Constant-time comparison to prevent timing attacks
constantTimeEq :: ByteString -> ByteString -> Bool
constantTimeEq a b
  | BS.length a /= BS.length b = False
  | otherwise = foldl' (\acc (x, y) -> acc .|. (x `xor` y)) (0 :: Word8)
                          (BS.zip a b) == 0

--------------------------------------------------------------------------------
-- BIP324 Cipher
--------------------------------------------------------------------------------

-- | BIP324 packet cipher encapsulating key derivation and AEAD
-- Reference: Bitcoin Core bip324.h BIP324Cipher
data BIP324Cipher = BIP324Cipher
  { b324SendLCipher :: !(Maybe FSChaCha20)         -- ^ For encrypting length
  , b324RecvLCipher :: !(Maybe FSChaCha20)         -- ^ For decrypting length
  , b324SendPCipher :: !(Maybe FSChaCha20Poly1305) -- ^ For encrypting payload
  , b324RecvPCipher :: !(Maybe FSChaCha20Poly1305) -- ^ For decrypting payload
  , b324OurPubKey   :: !EllSwiftPubKey             -- ^ Our ElligatorSwift pubkey
  , b324SecretKey   :: !ByteString                 -- ^ Our secret key
  , b324SessionId   :: !ByteString                 -- ^ Session ID (32 bytes)
  , b324SendGarbage :: !ByteString                 -- ^ Garbage terminator to send
  , b324RecvGarbage :: !ByteString                 -- ^ Expected garbage terminator
  } deriving (Show, Generic)

instance NFData BIP324Cipher

-- | Create a new BIP324 cipher with generated keys
-- Takes a secret key (32 bytes) and entropy (32 bytes)
newBIP324Cipher :: ByteString -> ByteString -> IO BIP324Cipher
newBIP324Cipher secretKey entropy = do
  ourPubKey <- ellSwiftCreate secretKey entropy
  return BIP324Cipher
    { b324SendLCipher = Nothing
    , b324RecvLCipher = Nothing
    , b324SendPCipher = Nothing
    , b324RecvPCipher = Nothing
    , b324OurPubKey   = ourPubKey
    , b324SecretKey   = secretKey
    , b324SessionId   = BS.empty
    , b324SendGarbage = BS.empty
    , b324RecvGarbage = BS.empty
    }

-- | Initialize the BIP324 cipher after receiving the peer's public key
-- This performs ECDH and derives all session keys
initializeBIP324 :: BIP324Cipher
                 -> EllSwiftPubKey  -- ^ Their public key
                 -> ByteString      -- ^ Network magic (4 bytes)
                 -> Bool            -- ^ Are we the initiator?
                 -> BIP324Cipher
initializeBIP324 cipher theirPubKey netMagic initiator =
  let -- Perform ECDH (simplified - needs secp256k1 for real implementation)
      -- In a real implementation: ecdhSecret = ECDH(ourSecret, theirPubKey)
      -- For now, use a deterministic derivation
      ecdhSecret = hmacSha256 (b324SecretKey cipher)
                              (getEllSwiftPubKey theirPubKey)

      -- Derive session keys
      sessionKeys = deriveV2SessionKeys ecdhSecret netMagic initiator

      -- Initialize ciphers
      sendLCipher = newFSChaCha20 (v2skSendLKey sessionKeys) v2RekeyInterval
      recvLCipher = newFSChaCha20 (v2skRecvLKey sessionKeys) v2RekeyInterval
      sendPCipher = newFSChaCha20Poly1305 (v2skSendPKey sessionKeys) v2RekeyInterval
      recvPCipher = newFSChaCha20Poly1305 (v2skRecvPKey sessionKeys) v2RekeyInterval

  in cipher
       { b324SendLCipher = Just sendLCipher
       , b324RecvLCipher = Just recvLCipher
       , b324SendPCipher = Just sendPCipher
       , b324RecvPCipher = Just recvPCipher
       , b324SessionId   = v2skSessionId sessionKeys
       , b324SendGarbage = v2skSendGarbage sessionKeys
       , b324RecvGarbage = v2skRecvGarbage sessionKeys
       }

-- | Encrypt a BIP324 packet
-- Returns (updated cipher, encrypted packet)
-- Format: 3-byte encrypted length || header || ciphertext || 16-byte tag
bip324Encrypt :: BIP324Cipher
              -> ByteString     -- ^ Message contents
              -> ByteString     -- ^ Additional authenticated data
              -> Bool           -- ^ Set ignore flag?
              -> Either String (BIP324Cipher, ByteString)
bip324Encrypt cipher contents aad ignore = do
  lCipher <- maybe (Left "BIP324 not initialized") Right (b324SendLCipher cipher)
  pCipher <- maybe (Left "BIP324 not initialized") Right (b324SendPCipher cipher)

  let -- Encrypt length (3 bytes, little-endian)
      len = BS.length contents
      lenBytes = BS.pack [ fromIntegral (len .&. 0xff)
                         , fromIntegral ((len `shiftR` 8) .&. 0xff)
                         , fromIntegral ((len `shiftR` 16) .&. 0xff)
                         ]
      (lCipher', encLen) = fsCrypt lCipher lenBytes

      -- Build header (1 byte) + contents
      header = if ignore then v2IgnoreBit else 0
      plaintext = BS.cons header contents

      -- Encrypt with AEAD
      (pCipher', ciphertext) = fsEncrypt pCipher aad plaintext

      cipher' = cipher
        { b324SendLCipher = Just lCipher'
        , b324SendPCipher = Just pCipher'
        }

  return (cipher', encLen `BS.append` ciphertext)

-- | Decrypt the length prefix of a BIP324 packet
-- Returns (updated cipher, decrypted length)
bip324DecryptLength :: BIP324Cipher
                    -> ByteString     -- ^ 3-byte encrypted length
                    -> Either String (BIP324Cipher, Word32)
bip324DecryptLength cipher encLen
  | BS.length encLen /= 3 = Left "Invalid length prefix"
  | otherwise = do
      lCipher <- maybe (Left "BIP324 not initialized") Right (b324RecvLCipher cipher)

      let (lCipher', decLen) = fsCrypt lCipher encLen
          len = fromIntegral (BS.index decLen 0)
            .|. (fromIntegral (BS.index decLen 1) `shiftL` 8)
            .|. (fromIntegral (BS.index decLen 2) `shiftL` 16)
          cipher' = cipher { b324RecvLCipher = Just lCipher' }

      return (cipher', len)

-- | Decrypt a BIP324 packet payload
-- Returns (updated cipher, ignore flag, plaintext)
bip324Decrypt :: BIP324Cipher
              -> ByteString     -- ^ Header + ciphertext + tag
              -> ByteString     -- ^ Additional authenticated data
              -> Either String (BIP324Cipher, Bool, ByteString)
bip324Decrypt cipher input aad = do
  pCipher <- maybe (Left "BIP324 not initialized") Right (b324RecvPCipher cipher)

  let (pCipher', result) = fsDecrypt pCipher aad input

  case result of
    Nothing -> Left "Decryption failed (authentication error)"
    Just plaintext
      | BS.null plaintext -> Left "Empty plaintext"
      | otherwise ->
          let header = BS.head plaintext
              contents = BS.tail plaintext
              ignore = (header .&. v2IgnoreBit) /= 0
              cipher' = cipher { b324RecvPCipher = Just pCipher' }
          in Right (cipher', ignore, contents)

-- | Get the session ID (only after initialization)
getBIP324SessionId :: BIP324Cipher -> ByteString
getBIP324SessionId = b324SessionId

-- | Get the garbage terminator to send
getBIP324SendGarbageTerminator :: BIP324Cipher -> ByteString
getBIP324SendGarbageTerminator = b324SendGarbage

-- | Get the expected garbage terminator to receive
getBIP324RecvGarbageTerminator :: BIP324Cipher -> ByteString
getBIP324RecvGarbageTerminator = b324RecvGarbage

--------------------------------------------------------------------------------
-- V2 Transport State Machine
--------------------------------------------------------------------------------

-- | V2 transport send state
data V2SendState
  = V2SendAwaitingKey      -- ^ Waiting for key to be generated
  | V2SendAwaitingTheirKey -- ^ Key sent, waiting for their key
  | V2SendReady            -- ^ Ready to send encrypted messages
  deriving (Show, Eq, Generic)

instance NFData V2SendState

-- | V2 transport receive state
data V2RecvState
  = V2RecvKey                   -- ^ Receiving their 64-byte key
  | V2RecvGarbage               -- ^ Receiving garbage + terminator
  | V2RecvGarbageAuth           -- ^ Receiving garbage authentication packet
  | V2RecvVersion               -- ^ Receiving encrypted version packet
  | V2RecvAppData               -- ^ Receiving application data
  deriving (Show, Eq, Generic)

instance NFData V2RecvState

-- | V2 transport state
data V2TransportState = V2TransportState
  { v2tsSendState   :: !V2SendState
  , v2tsRecvState   :: !V2RecvState
  , v2tsRecvBuffer  :: !ByteString    -- ^ Accumulated receive data
  , v2tsGarbageRecv :: !ByteString    -- ^ Received garbage
  } deriving (Show, Generic)

instance NFData V2TransportState

-- | V2 transport layer
data V2Transport = V2Transport
  { v2tCipher      :: !(TVar BIP324Cipher)
  , v2tState       :: !(TVar V2TransportState)
  , v2tInitiator   :: !Bool             -- ^ Are we the initiator?
  , v2tNetMagic    :: !ByteString       -- ^ Network magic (4 bytes)
  , v2tOurGarbage  :: !ByteString       -- ^ Garbage we will send
  }

-- | Create a new V2 transport
newV2Transport :: ByteString     -- ^ Secret key (32 bytes)
               -> ByteString     -- ^ Entropy (32 bytes)
               -> ByteString     -- ^ Network magic (4 bytes)
               -> Bool           -- ^ Are we the initiator?
               -> ByteString     -- ^ Our garbage data (0-4095 bytes)
               -> IO V2Transport
newV2Transport secretKey entropy netMagic initiator garbage = do
  cipher <- newBIP324Cipher secretKey entropy
  cipherVar <- newTVarIO cipher

  let initialState = V2TransportState
        { v2tsSendState  = V2SendAwaitingKey
        , v2tsRecvState  = V2RecvKey
        , v2tsRecvBuffer = BS.empty
        , v2tsGarbageRecv = BS.empty
        }
  stateVar <- newTVarIO initialState

  return V2Transport
    { v2tCipher    = cipherVar
    , v2tState     = stateVar
    , v2tInitiator = initiator
    , v2tNetMagic  = netMagic
    , v2tOurGarbage = BS.take v2MaxGarbageLen garbage
    }

-- | Check if V2 transport is ready for application data
isV2Ready :: V2Transport -> IO Bool
isV2Ready transport = atomically $ do
  state <- readTVar (v2tState transport)
  return $ v2tsSendState state == V2SendReady &&
           v2tsRecvState state == V2RecvAppData

-- | Send data through V2 transport
-- Returns the bytes to send over the wire
v2TransportSend :: V2Transport
                -> Message           -- ^ Message to send
                -> IO (Either String ByteString)
v2TransportSend transport msg = atomically $ do
  cipher <- readTVar (v2tCipher transport)
  state <- readTVar (v2tState transport)

  case v2tsSendState state of
    V2SendReady -> do
      -- Encode message with short ID if possible
      let cmdName = commandName msg
          payload = encodePayload msg
          -- Try short message ID
          contents = case shortMsgId cmdName of
            Just mid -> BS.cons mid payload
            Nothing -> BS.cons 0 (cmdName `BS.append` BS.replicate (12 - BS.length cmdName) 0 `BS.append` payload)

      case bip324Encrypt cipher contents BS.empty False of
        Left err -> return $ Left err
        Right (cipher', encrypted) -> do
          writeTVar (v2tCipher transport) cipher'
          return $ Right encrypted

    _ -> return $ Left "V2 transport not ready"

-- | Receive data through V2 transport
-- Takes raw bytes from the wire, returns decoded messages
v2TransportReceive :: V2Transport
                   -> ByteString          -- ^ Received bytes
                   -> IO (Either String [Message])
v2TransportReceive transport newData = atomically $ do
  cipher <- readTVar (v2tCipher transport)
  state <- readTVar (v2tState transport)

  let buffer = v2tsRecvBuffer state `BS.append` newData

  case v2tsRecvState state of
    V2RecvAppData -> do
      -- Try to decrypt messages
      result <- decryptMessages cipher buffer []
      case result of
        Left err -> return $ Left err
        Right (cipher', remaining, msgs) -> do
          writeTVar (v2tCipher transport) cipher'
          writeTVar (v2tState transport) state { v2tsRecvBuffer = remaining }
          return $ Right msgs

    _ -> do
      -- Still in handshake phase
      writeTVar (v2tState transport) state { v2tsRecvBuffer = buffer }
      return $ Right []

  where
    decryptMessages cipher buf acc
      | BS.length buf < v2LengthLen = return $ Right (cipher, buf, reverse acc)
      | otherwise = do
          case bip324DecryptLength cipher (BS.take v2LengthLen buf) of
            Left err -> return $ Left err
            Right (cipher', len) -> do
              let totalLen = v2LengthLen + 1 + fromIntegral len + 16  -- length + header + payload + tag
              if BS.length buf < totalLen
                then return $ Right (cipher, buf, reverse acc)
                else do
                  let payload = BS.take (totalLen - v2LengthLen) (BS.drop v2LengthLen buf)
                      remaining = BS.drop totalLen buf
                  case bip324Decrypt cipher' payload BS.empty of
                    Left err -> return $ Left err
                    Right (cipher'', ignore, contents) ->
                      if ignore
                      then decryptMessages cipher'' remaining acc
                      else do
                        -- Decode message
                        case decodeV2Message contents of
                          Left err -> return $ Left err
                          Right msg -> decryptMessages cipher'' remaining (msg:acc)

-- | Decode a V2 message from decrypted contents
decodeV2Message :: ByteString -> Either String Message
decodeV2Message contents
  | BS.null contents = Left "Empty message"
  | otherwise =
      let firstByte = BS.head contents
          rest = BS.tail contents
      in if firstByte == 0
         -- Long encoding: 12-byte command follows
         then if BS.length rest < 12
              then Left "Incomplete command name"
              else let cmd = BS.takeWhile (/= 0) (BS.take 12 rest)
                       payload = BS.drop 12 rest
                   in decodeMessage cmd payload
         -- Short encoding: firstByte is the message ID
         else case shortMsgIdToCommand firstByte of
                Nothing -> Left $ "Unknown short message ID: " ++ show firstByte
                Just cmd -> decodeMessage cmd rest

--------------------------------------------------------------------------------
-- V2/V1 Negotiation
--------------------------------------------------------------------------------

-- | Transport version
data TransportVersion = TransportV1 | TransportV2
  deriving (Show, Eq, Generic)

instance NFData TransportVersion

-- | Detect transport version from first bytes received
-- V2 starts with 64-byte ElligatorSwift public key
-- V1 starts with magic bytes
detectTransportVersion :: ByteString   -- ^ First bytes received (need at least 4)
                       -> ByteString   -- ^ Network magic (4 bytes)
                       -> Maybe TransportVersion
detectTransportVersion firstBytes netMagic
  | BS.length firstBytes < 4 = Nothing
  | BS.take 4 firstBytes == netMagic = Just TransportV1
  | otherwise = Just TransportV2  -- Assume V2 if not V1 magic

-- | Initiate V2 handshake (for outbound connections)
-- Returns bytes to send (our EllSwift pubkey + garbage + terminator)
v2HandshakeInitiator :: V2Transport -> IO ByteString
v2HandshakeInitiator transport = do
  cipher <- readTVarIO (v2tCipher transport)

  -- Initialize cipher after we know their key (this is pre-handshake setup)
  let ourPubKey = getEllSwiftPubKey (b324OurPubKey cipher)
      garbage = v2tOurGarbage transport

  atomically $ modifyTVar' (v2tState transport) $ \s ->
    s { v2tsSendState = V2SendAwaitingTheirKey }

  -- Return: our pubkey (64 bytes) + garbage (0-4095 bytes)
  -- The garbage terminator will be appended after we receive their key
  return $ ourPubKey `BS.append` garbage

-- | Respond to V2 handshake (for inbound connections)
-- Takes their public key, returns bytes to send
v2HandshakeResponder :: V2Transport
                     -> EllSwiftPubKey  -- ^ Their public key
                     -> IO ByteString
v2HandshakeResponder transport theirPubKey = do
  -- Initialize the cipher with their key
  atomically $ do
    cipher <- readTVar (v2tCipher transport)
    let cipher' = initializeBIP324 cipher theirPubKey (v2tNetMagic transport) False
    writeTVar (v2tCipher transport) cipher'
    modifyTVar' (v2tState transport) $ \s ->
      s { v2tsSendState = V2SendReady
        , v2tsRecvState = V2RecvGarbage
        }

  cipher' <- readTVarIO (v2tCipher transport)

  let ourPubKey = getEllSwiftPubKey (b324OurPubKey cipher')
      garbage = v2tOurGarbage transport
      terminator = getBIP324SendGarbageTerminator cipher'

  return $ ourPubKey `BS.append` garbage `BS.append` terminator

--------------------------------------------------------------------------------
-- BIP330 Erlay Transaction Reconciliation (Phase 41)
--------------------------------------------------------------------------------

-- | Erlay Constants
-- Reference: BIP330 and Bitcoin Core txreconciliation.cpp

-- | Supported reconciliation protocol version
erlayReconVersion :: Word32
erlayReconVersion = 1

-- | Reconciliation interval in microseconds (~2 seconds)
erlayReconInterval :: Int64
erlayReconInterval = 2000000

-- | Static salt component for computing short txids (BIP330)
erlayStaticSalt :: ByteString
erlayStaticSalt = "Tx Relay Salting"

-- | Number of outbound peers to flood to (rest use reconciliation)
erlayFloodOutboundCount :: Int
erlayFloodOutboundCount = 8

--------------------------------------------------------------------------------
-- GF(2^32) Field Arithmetic for Minisketch BCH codes
--------------------------------------------------------------------------------

-- | Element of GF(2^32) - Galois field with 2^32 elements
-- Used for BCH-based set reconciliation in Minisketch
newtype GF2_32 = GF2_32 { getGF2_32 :: Word32 }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (NFData)

-- | Primitive polynomial for GF(2^32): x^32 + x^7 + x^5 + x^3 + x^2 + x + 1
-- This is 0x1000000af in hex (the +1 term is implicit in reduction)
gfPrimitive :: Word32
gfPrimitive = 0x000000af  -- Lower 32 bits used in reduction

-- | Addition in GF(2^32) is XOR
gfAdd :: GF2_32 -> GF2_32 -> GF2_32
gfAdd (GF2_32 a) (GF2_32 b) = GF2_32 (a `xor` b)
{-# INLINE gfAdd #-}

-- | Subtraction in GF(2^32) is the same as addition (XOR)
gfSub :: GF2_32 -> GF2_32 -> GF2_32
gfSub = gfAdd
{-# INLINE gfSub #-}

-- | Multiplication in GF(2^32) using Russian peasant algorithm with reduction
gfMul :: GF2_32 -> GF2_32 -> GF2_32
gfMul (GF2_32 a) (GF2_32 b) = GF2_32 (gfMulRaw a b)
  where
    gfMulRaw :: Word32 -> Word32 -> Word32
    gfMulRaw x y = go 0 x y
      where
        go !acc !p !q
          | q == 0    = acc
          | otherwise =
              let acc' = if q .&. 1 /= 0 then acc `xor` p else acc
                  -- Multiply p by x (shift left) and reduce if needed
                  p' = if p .&. 0x80000000 /= 0
                       then (p `shiftL` 1) `xor` gfPrimitive
                       else p `shiftL` 1
                  q' = q `shiftR` 1
              in go acc' p' q'
{-# INLINE gfMul #-}

-- | Compute a^n in GF(2^32) using square-and-multiply
gfPow :: GF2_32 -> Word32 -> GF2_32
gfPow _ 0 = GF2_32 1
gfPow (GF2_32 a) n = GF2_32 (go 1 a n)
  where
    go !acc !base !exp
      | exp == 0  = acc
      | otherwise =
          let acc' = if exp .&. 1 /= 0
                     then getGF2_32 (gfMul (GF2_32 acc) (GF2_32 base))
                     else acc
              base' = getGF2_32 (gfMul (GF2_32 base) (GF2_32 base))
              exp' = exp `shiftR` 1
          in go acc' base' exp'

-- | Multiplicative inverse in GF(2^32) using Fermat's little theorem
-- a^(-1) = a^(2^32 - 2) since a^(2^32 - 1) = 1 for all a != 0
gfInv :: GF2_32 -> GF2_32
gfInv (GF2_32 0) = GF2_32 0  -- 0 has no inverse, return 0 as sentinel
gfInv a = gfPow a (0xfffffffe :: Word32)
{-# INLINE gfInv #-}

--------------------------------------------------------------------------------
-- Minisketch Implementation
--------------------------------------------------------------------------------

-- | Minisketch error types
data SketchError
  = SketchDecodeFailed           -- ^ Polynomial root finding failed
  | SketchCapacityExceeded Int   -- ^ Set difference exceeds sketch capacity
  | SketchInvalidData            -- ^ Corrupted or invalid sketch data
  deriving (Show, Eq, Generic)

instance NFData SketchError

-- | Minisketch data structure
-- A BCH-based sketch for set reconciliation over GF(2^32)
-- The sketch is a polynomial whose coefficients encode set elements
data Minisketch = Minisketch
  { msCapacity   :: !Int                    -- ^ Maximum number of elements to decode
  , msSyndromes  :: !(VU.Vector Word32)     -- ^ Syndrome values (BCH codeword)
  } deriving (Show, Eq, Generic)

instance NFData Minisketch where
  rnf (Minisketch c s) = c `seq` s `seq` ()

-- | Create an empty minisketch with given capacity
newMinisketch :: Int -> Minisketch
newMinisketch capacity = Minisketch
  { msCapacity = capacity
  , msSyndromes = VU.replicate capacity 0
  }

-- | Add an element to the sketch
-- This computes s_i = s_i + x^i for i in [1..capacity]
-- where x is the element and s_i are the syndromes
sketchAdd :: Minisketch -> Word32 -> Minisketch
sketchAdd sketch 0 = sketch  -- 0 is not a valid element
sketchAdd sketch elem = sketch { msSyndromes = newSyndromes }
  where
    cap = msCapacity sketch
    oldSyndromes = msSyndromes sketch
    newSyndromes = VU.generate cap $ \i ->
      let oldVal = oldSyndromes VU.! i
          power = i + 1  -- syndrome indices are 1-based in BCH
          contribution = getGF2_32 (gfPow (GF2_32 elem) (fromIntegral power))
      in oldVal `xor` contribution

-- | Merge two sketches (XOR of syndromes)
-- The result represents the symmetric difference of the two sets
sketchMerge :: Minisketch -> Minisketch -> Minisketch
sketchMerge s1 s2
  | msCapacity s1 /= msCapacity s2 =
      error "sketchMerge: capacity mismatch"
  | otherwise = s1 { msSyndromes = merged }
  where
    merged = VU.zipWith xor (msSyndromes s1) (msSyndromes s2)

-- | Get the capacity of a sketch
sketchCapacity :: Minisketch -> Int
sketchCapacity = msCapacity

-- | Serialize sketch to bytes
sketchSerialize :: Minisketch -> ByteString
sketchSerialize sketch =
  let cap = msCapacity sketch
      syndromes = msSyndromes sketch
      -- Encode capacity as 2 bytes followed by syndrome values
      capBytes = runPut $ putWord16le (fromIntegral cap)
      syndromeBytes = runPut $ VU.forM_ syndromes putWord32le
  in capBytes `BS.append` syndromeBytes

-- | Deserialize sketch from bytes
sketchDeserialize :: ByteString -> Either String Minisketch
sketchDeserialize bs
  | BS.length bs < 2 = Left "Sketch too short"
  | otherwise =
      case runGet getWord16le (BS.take 2 bs) of
        Left err -> Left err
        Right cap ->
          let expectedLen = 2 + fromIntegral cap * 4
          in if BS.length bs < expectedLen
             then Left "Sketch data incomplete"
             else let syndromeBytes = BS.drop 2 bs
                      syndromes = runGet (VU.replicateM (fromIntegral cap) getWord32le) syndromeBytes
                  in case syndromes of
                       Left err -> Left err
                       Right s -> Right $ Minisketch (fromIntegral cap) s

-- | Decode a sketch to find the elements in the set difference
-- Uses Berlekamp-Massey algorithm to find the error locator polynomial,
-- then Chien search to find roots
sketchDecode :: Minisketch -> Either SketchError [Word32]
sketchDecode sketch
  | VU.all (== 0) (msSyndromes sketch) = Right []  -- Empty difference
  | otherwise = berlekampMassey sketch >>= chienSearch

-- | Berlekamp-Massey algorithm to find error locator polynomial
-- Returns coefficients of Lambda(x) = 1 + L1*x + L2*x^2 + ...
berlekampMassey :: Minisketch -> Either SketchError (VU.Vector Word32)
berlekampMassey sketch = go 0 initC initB 1 1 (GF2_32 1)
  where
    syndromes = msSyndromes sketch
    n = VU.length syndromes
    cap = msCapacity sketch

    -- Initialize C(x) = 1, B(x) = 1
    initC = VU.replicate (cap + 1) 0 VU.// [(0, 1)]
    initB = VU.replicate (cap + 1) 0 VU.// [(0, 1)]

    -- Main iteration
    go :: Int -> VU.Vector Word32 -> VU.Vector Word32 -> Int -> Int -> GF2_32
       -> Either SketchError (VU.Vector Word32)
    go k c b l m delta
      | k >= n = Right (VU.take (l + 1) c)
      | otherwise =
          let -- Compute discrepancy
              d = computeDiscrepancy syndromes c k l
          in if getGF2_32 d == 0
             then go (k + 1) c b l (m + 1) delta
             else
               let -- Update C(x) = C(x) - d * delta^(-1) * x^m * B(x)
                   factor = gfMul d (gfInv delta)
                   c' = updateC c b factor m
               in if 2 * l <= k
                  then -- L increased, update B
                       let b' = c
                           l' = k + 1 - l
                       in go (k + 1) c' b' l' 1 d
                  else go (k + 1) c' b l (m + 1) delta

    computeDiscrepancy :: VU.Vector Word32 -> VU.Vector Word32 -> Int -> Int -> GF2_32
    computeDiscrepancy s c k l =
      let terms = [ gfMul (GF2_32 (c VU.! i)) (GF2_32 (s VU.! (k - i)))
                  | i <- [0..min l k] ]
      in foldl' gfAdd (GF2_32 0) terms

    updateC :: VU.Vector Word32 -> VU.Vector Word32 -> GF2_32 -> Int -> VU.Vector Word32
    updateC c b factor m = VU.imap update c
      where
        update i ci
          | i >= m && i - m < VU.length b =
              ci `xor` getGF2_32 (gfMul factor (GF2_32 (b VU.! (i - m))))
          | otherwise = ci

-- | Chien search to find roots of the error locator polynomial
-- Each root r corresponds to an element r^(-1) in the set difference
chienSearch :: VU.Vector Word32 -> Either SketchError [Word32]
chienSearch lambda
  | VU.length lambda <= 1 = Right []
  | otherwise = do
      let degree = VU.length lambda - 1
          -- Test all possible roots in GF(2^32)
          -- In practice, we only need to test 2^32 values, but we limit
          -- the search for efficiency
          roots = findRoots lambda
      if length roots /= degree
         then Left SketchDecodeFailed
         else Right $ map (\r -> getGF2_32 (gfInv (GF2_32 r))) roots
  where
    findRoots :: VU.Vector Word32 -> [Word32]
    findRoots coeffs = filter (isRoot coeffs) testValues

    -- Test a subset of field elements (practical limitation)
    -- In a full implementation, we'd use a more efficient approach
    testValues :: [Word32]
    testValues = [1..65535]  -- Test first 2^16 elements

    isRoot :: VU.Vector Word32 -> Word32 -> Bool
    isRoot coeffs x =
      let terms = [ gfPow (GF2_32 x) (fromIntegral i)
                  | i <- [0 .. VU.length coeffs - 1] ]
          products = zipWith (\c t -> gfMul (GF2_32 c) t)
                             (VU.toList coeffs) terms
          result = foldl' gfAdd (GF2_32 0) products
      in getGF2_32 result == 0

--------------------------------------------------------------------------------
-- Minisketch FFI Bindings (libminisketch)
-- High-performance BCH set reconciliation via C library
--------------------------------------------------------------------------------

-- | Opaque pointer to C minisketch structure
data CMinisketch

-- FFI imports for libminisketch
-- Note: These require libminisketch to be installed and linked
foreign import ccall unsafe "minisketch_bits_supported"
  c_minisketch_bits_supported :: CUInt -> CInt

foreign import ccall unsafe "minisketch_create"
  c_minisketch_create :: CUInt -> CUInt -> CSize -> IO (Ptr CMinisketch)

foreign import ccall unsafe "&minisketch_destroy"
  c_minisketch_destroy :: FunPtr (Ptr CMinisketch -> IO ())

foreign import ccall unsafe "minisketch_add_uint64"
  c_minisketch_add :: Ptr CMinisketch -> Word64 -> IO ()

foreign import ccall unsafe "minisketch_merge"
  c_minisketch_merge :: Ptr CMinisketch -> Ptr CMinisketch -> IO CSize

foreign import ccall unsafe "minisketch_decode"
  c_minisketch_decode :: Ptr CMinisketch -> CSize -> Ptr Word64 -> IO CSize

foreign import ccall unsafe "minisketch_serialized_size"
  c_minisketch_serialized_size :: Ptr CMinisketch -> IO CSize

foreign import ccall unsafe "minisketch_serialize"
  c_minisketch_serialize :: Ptr CMinisketch -> Ptr Word8 -> IO ()

foreign import ccall unsafe "minisketch_deserialize"
  c_minisketch_deserialize :: Ptr CMinisketch -> Ptr Word8 -> IO ()

foreign import ccall unsafe "minisketch_clone"
  c_minisketch_clone :: Ptr CMinisketch -> IO (Ptr CMinisketch)

-- | FFI wrapper for minisketch with automatic resource management
newtype MinisketchFFI = MinisketchFFI (ForeignPtr CMinisketch)

-- | Check if minisketch supports a given field size
minisketchFFISupported :: Word32 -> Bool
minisketchFFISupported bits = c_minisketch_bits_supported (CUInt bits) /= 0

-- | Create a new minisketch with given bits and capacity
-- Uses implementation 0 (default/auto-detect)
minisketchFFICreate :: Word32 -> Word32 -> IO (Maybe MinisketchFFI)
minisketchFFICreate bits capacity = do
  ptr <- c_minisketch_create (CUInt bits) 0 (CSize $ fromIntegral capacity)
  if ptr == nullPtr
    then return Nothing
    else do
      fptr <- newForeignPtr c_minisketch_destroy ptr
      return $ Just (MinisketchFFI fptr)

-- | Run an action with a minisketch, ensuring proper cleanup
withMinisketchFFI :: MinisketchFFI -> (Ptr CMinisketch -> IO a) -> IO a
withMinisketchFFI (MinisketchFFI fptr) = withForeignPtr fptr

-- | Add an element to the sketch (modifies in place via FFI)
minisketchFFIAdd :: MinisketchFFI -> Word64 -> IO ()
minisketchFFIAdd sketch elem =
  withMinisketchFFI sketch $ \ptr -> c_minisketch_add ptr elem

-- | Merge another sketch into this one (XOR operation)
-- Returns the new capacity, or 0 if merge failed
minisketchFFIMerge :: MinisketchFFI -> MinisketchFFI -> IO Int
minisketchFFIMerge sketch other =
  withMinisketchFFI sketch $ \ptr ->
    withMinisketchFFI other $ \otherPtr -> do
      CSize result <- c_minisketch_merge ptr otherPtr
      return (fromIntegral result)

-- | Decode the sketch to find set difference elements
-- Returns Nothing if decode failed (difference too large)
minisketchFFIDecode :: MinisketchFFI -> Int -> IO (Maybe [Word64])
minisketchFFIDecode sketch maxElems =
  withMinisketchFFI sketch $ \ptr ->
    allocaArray maxElems $ \outputPtr -> do
      CSize count <- c_minisketch_decode ptr (CSize $ fromIntegral maxElems) outputPtr
      -- -1 cast to CSize is maxBound, indicating failure
      if fromIntegral count > fromIntegral maxElems
        then return Nothing
        else do
          elems <- peekArray (fromIntegral count) outputPtr
          return $ Just elems

-- | Serialize the sketch to bytes
minisketchFFISerialize :: MinisketchFFI -> IO ByteString
minisketchFFISerialize sketch =
  withMinisketchFFI sketch $ \ptr -> do
    CSize size <- c_minisketch_serialized_size ptr
    buf <- mallocBytes (fromIntegral size)
    c_minisketch_serialize ptr buf
    bs <- BS.packCStringLen (castPtr buf, fromIntegral size)
    free buf
    return bs

-- | Deserialize bytes into an existing sketch
minisketchFFIDeserialize :: MinisketchFFI -> ByteString -> IO ()
minisketchFFIDeserialize sketch bs =
  withMinisketchFFI sketch $ \ptr ->
    BS.useAsCStringLen bs $ \(cstr, _len) ->
      c_minisketch_deserialize ptr (castPtr cstr)

--------------------------------------------------------------------------------
-- Erlay Short TxId Computation
--------------------------------------------------------------------------------

-- | Short txid for Erlay (32-bit truncation of SipHash)
type ShortTxIdErlay = Word32

-- | Compute Erlay salt from local and remote salts
-- Salt is combined by hashing sorted salts with static prefix
computeErlaySalt :: Word64 -> Word64 -> SipHashKey
computeErlaySalt localSalt remoteSalt =
  let minSalt = min localSalt remoteSalt
      maxSalt = max localSalt remoteSalt
      -- Hash: SHA256(erlayStaticSalt || minSalt || maxSalt)
      input = BS.concat
        [ erlayStaticSalt
        , runPut (putWord64le minSalt)
        , runPut (putWord64le maxSalt)
        ]
      hashResult = sha256 input
      -- Extract two 64-bit keys from hash
      k0 = either (const 0) id $ runGet getWord64le (BS.take 8 hashResult)
      k1 = either (const 0) id $ runGet getWord64le (BS.take 8 (BS.drop 8 hashResult))
  in SipHashKey k0 k1

-- | Compute short txid for Erlay reconciliation
-- Uses SipHash with the combined salt, truncated to 32 bits
computeErlayShortTxId :: SipHashKey -> TxId -> ShortTxIdErlay
computeErlayShortTxId key (TxId hash) =
  let fullHash = sipHash128 key (getHash256 hash)
  in fromIntegral (fullHash .&. 0xffffffff)

--------------------------------------------------------------------------------
-- Erlay Protocol Messages
--------------------------------------------------------------------------------

-- | Request reconciliation (initiator -> responder)
data ReqRecon = ReqRecon
  { rrSetSize     :: !Word16         -- ^ Number of elements in local set
  , rrQ           :: !Word16         -- ^ Estimated difference (for capacity)
  , rrSketch      :: !ByteString     -- ^ Serialized minisketch
  } deriving (Show, Eq, Generic)

instance NFData ReqRecon

instance Serialize ReqRecon where
  put ReqRecon{..} = do
    putWord16le rrSetSize
    putWord16le rrQ
    putVarInt (fromIntegral $ BS.length rrSketch)
    putByteString rrSketch
  get = do
    setSize <- getWord16le
    q <- getWord16le
    sketchLen <- getVarInt'
    sketch <- getBytes (fromIntegral sketchLen)
    return $ ReqRecon setSize q sketch

-- | Reconciliation difference response (responder -> initiator)
data ReconcilDiff = ReconcilDiff
  { rdSuccess     :: !Bool           -- ^ Whether reconciliation succeeded
  , rdMissing     :: ![TxId]         -- ^ TxIds initiator is missing
  , rdExtra       :: ![TxId]         -- ^ TxIds initiator has that responder doesn't
  } deriving (Show, Eq, Generic)

instance NFData ReconcilDiff

instance Serialize ReconcilDiff where
  put ReconcilDiff{..} = do
    putWord8 (if rdSuccess then 1 else 0)
    putVarInt (fromIntegral $ length rdMissing)
    mapM_ put rdMissing
    putVarInt (fromIntegral $ length rdExtra)
    mapM_ put rdExtra
  get = do
    success <- (== 1) <$> getWord8
    missingCount <- getVarInt'
    missing <- replicateM (fromIntegral missingCount) get
    extraCount <- getVarInt'
    extra <- replicateM (fromIntegral extraCount) get
    return $ ReconcilDiff success missing extra

-- | Sketch extension request (for failed reconciliation)
data SketchExt = SketchExt
  { seSketch :: !ByteString  -- ^ Extended sketch
  } deriving (Show, Eq, Generic)

instance NFData SketchExt

instance Serialize SketchExt where
  put SketchExt{..} = do
    putVarInt (fromIntegral $ BS.length seSketch)
    putByteString seSketch
  get = do
    len <- getVarInt'
    SketchExt <$> getBytes (fromIntegral len)

--------------------------------------------------------------------------------
-- Reconciliation State Management
--------------------------------------------------------------------------------

-- | Role in reconciliation
data ReconciliationRole
  = ReconciliationInitiator  -- ^ We request sketches from peer (outbound)
  | ReconciliationResponder  -- ^ Peer requests sketches from us (inbound)
  deriving (Show, Eq, Generic)

instance NFData ReconciliationRole

-- | Per-peer reconciliation state
data ReconciliationState = ReconciliationState
  { rsRole       :: !ReconciliationRole     -- ^ Our role with this peer
  , rsSipKey     :: !SipHashKey             -- ^ Combined SipHash key for short txids
  , rsLocalSalt  :: !Word64                 -- ^ Our salt contribution
  , rsRemoteSalt :: !Word64                 -- ^ Their salt contribution
  , rsPendingSet :: !(TVar (Set.Set TxId))  -- ^ Txs to announce via reconciliation
  , rsLastRecon  :: !(TVar Int64)           -- ^ Timestamp of last reconciliation
  }

instance Show ReconciliationState where
  show rs = "ReconciliationState{role=" ++ show (rsRole rs) ++ "}"

-- | Result of attempting to register a peer for reconciliation
data ReconciliationRegisterResult
  = ReconciliationNotFound         -- ^ Peer was not pre-registered
  | ReconciliationSuccess          -- ^ Successfully registered
  | ReconciliationAlreadyRegistered -- ^ Peer already registered
  | ReconciliationProtocolViolation -- ^ Protocol version mismatch
  deriving (Show, Eq, Generic)

instance NFData ReconciliationRegisterResult

-- | Tracker for transaction reconciliation across all peers
data TxReconciliationTracker = TxReconciliationTracker
  { trtVersion :: !Word32
  , trtStates  :: !(TVar (Map.Map Int (Either Word64 ReconciliationState)))
    -- ^ Map from peer ID to either pre-registration salt or full state
  }

-- | Create a new reconciliation tracker
newTxReconciliationTracker :: Word32 -> IO TxReconciliationTracker
newTxReconciliationTracker version = do
  states <- newTVarIO Map.empty
  return TxReconciliationTracker
    { trtVersion = version
    , trtStates = states
    }

-- | Pre-register a peer for reconciliation
-- Returns our local salt to send in sendtxrcncl
preRegisterPeer :: TxReconciliationTracker -> Int -> IO Word64
preRegisterPeer tracker peerId = do
  salt <- randomIO
  atomically $ modifyTVar' (trtStates tracker) $
    Map.insert peerId (Left salt)
  return salt

-- | Complete registration after receiving peer's sendtxrcncl
registerPeer :: TxReconciliationTracker
             -> Int           -- ^ Peer ID
             -> Bool          -- ^ Is peer inbound?
             -> Word32        -- ^ Peer's protocol version
             -> Word64        -- ^ Peer's salt
             -> IO ReconciliationRegisterResult
registerPeer tracker peerId isInbound peerVersion remoteSalt = do
  states <- readTVarIO (trtStates tracker)
  case Map.lookup peerId states of
    Nothing -> return ReconciliationNotFound
    Just (Right _) -> return ReconciliationAlreadyRegistered
    Just (Left localSalt) -> do
      -- Check version compatibility
      let reconVersion = min peerVersion (trtVersion tracker)
      if reconVersion < 1
         then return ReconciliationProtocolViolation
         else do
           -- Create full reconciliation state
           let sipKey = computeErlaySalt localSalt remoteSalt
               role = if isInbound
                      then ReconciliationResponder
                      else ReconciliationInitiator
           pendingSet <- newTVarIO Set.empty
           lastRecon <- newTVarIO 0
           let state = ReconciliationState
                 { rsRole = role
                 , rsSipKey = sipKey
                 , rsLocalSalt = localSalt
                 , rsRemoteSalt = remoteSalt
                 , rsPendingSet = pendingSet
                 , rsLastRecon = lastRecon
                 }
           atomically $ modifyTVar' (trtStates tracker) $
             Map.insert peerId (Right state)
           return ReconciliationSuccess

-- | Remove a peer from the tracker
forgetPeer :: TxReconciliationTracker -> Int -> IO ()
forgetPeer tracker peerId = atomically $
  modifyTVar' (trtStates tracker) $ Map.delete peerId

-- | Check if a peer is registered for reconciliation
isPeerRegistered :: TxReconciliationTracker -> Int -> IO Bool
isPeerRegistered tracker peerId = do
  states <- readTVarIO (trtStates tracker)
  case Map.lookup peerId states of
    Just (Right _) -> return True
    _ -> return False

-- | Get the reconciliation state for a peer
getPeerReconciliationState :: TxReconciliationTracker
                           -> Int
                           -> IO (Maybe ReconciliationState)
getPeerReconciliationState tracker peerId = do
  states <- readTVarIO (trtStates tracker)
  case Map.lookup peerId states of
    Just (Right state) -> return (Just state)
    _ -> return Nothing

--------------------------------------------------------------------------------
-- Reconciliation Set Management
--------------------------------------------------------------------------------

-- | Set of transactions pending reconciliation with a peer
data ReconciliationSet = ReconciliationSet
  { rsetKey      :: !SipHashKey              -- ^ SipHash key for short IDs
  , rsetTxs      :: !(TVar (Set.Set TxId))   -- ^ Pending transactions
  , rsetShortIds :: !(TVar (Map.Map Word32 TxId))  -- ^ Short ID to TxId mapping
  }

-- | Create a new reconciliation set
newReconciliationSet :: SipHashKey -> IO ReconciliationSet
newReconciliationSet key = do
  txs <- newTVarIO Set.empty
  shortIds <- newTVarIO Map.empty
  return ReconciliationSet
    { rsetKey = key
    , rsetTxs = txs
    , rsetShortIds = shortIds
    }

-- | Add a transaction to the reconciliation set
addToReconciliationSet :: ReconciliationSet -> TxId -> IO ()
addToReconciliationSet rset txid = atomically $ do
  modifyTVar' (rsetTxs rset) $ Set.insert txid
  let shortId = computeErlayShortTxId (rsetKey rset) txid
  modifyTVar' (rsetShortIds rset) $ Map.insert shortId txid

-- | Remove a transaction from the reconciliation set
removeFromReconciliationSet :: ReconciliationSet -> TxId -> IO ()
removeFromReconciliationSet rset txid = atomically $ do
  modifyTVar' (rsetTxs rset) $ Set.delete txid
  let shortId = computeErlayShortTxId (rsetKey rset) txid
  modifyTVar' (rsetShortIds rset) $ Map.delete shortId

-- | Build a minisketch from the reconciliation set
buildSketchFromSet :: ReconciliationSet -> Int -> IO Minisketch
buildSketchFromSet rset capacity = do
  shortIdMap <- readTVarIO (rsetShortIds rset)
  let shortIds = Map.keys shortIdMap
      baseSketch = newMinisketch capacity
  return $ foldl' sketchAdd baseSketch shortIds

-- | Compute set difference using sketch reconciliation
computeSetDifference :: ReconciliationSet  -- ^ Our set
                     -> Minisketch         -- ^ Their sketch
                     -> Int                -- ^ Capacity
                     -> IO (Either SketchError ([TxId], [Word32]))
                     -- ^ (TxIds we have that they don't, short IDs they have that we don't)
computeSetDifference rset theirSketch capacity = do
  ourSketch <- buildSketchFromSet rset capacity
  let mergedSketch = sketchMerge ourSketch theirSketch
  case sketchDecode mergedSketch of
    Left err -> return $ Left err
    Right shortIdDiff -> do
      shortIdMap <- readTVarIO (rsetShortIds rset)
      let ourShortIds = Map.keysSet shortIdMap
          -- Separate: ones we have vs ones they have
          (weHave, theyHave) = partition (`Set.member` ourShortIds) shortIdDiff
          -- Convert our short IDs back to TxIds
          weHaveTxIds = mapMaybe (`Map.lookup` shortIdMap) weHave
      return $ Right (weHaveTxIds, theyHave)

--------------------------------------------------------------------------------
-- Flood vs Reconciliation Relay Selection
--------------------------------------------------------------------------------

-- | Transaction relay mode for a peer
data RelayMode
  = RelayFlood        -- ^ Full inv flooding
  | RelayReconcile    -- ^ Set reconciliation
  deriving (Show, Eq, Generic)

instance NFData RelayMode

-- | Select relay mode for a peer
-- Outbound full-relay peers get flooding, rest get reconciliation
selectRelayMode :: Bool    -- ^ Is peer inbound?
                -> Bool    -- ^ Is peer block-relay-only?
                -> Bool    -- ^ Is peer registered for reconciliation?
                -> Int     -- ^ Current count of flood peers
                -> RelayMode
selectRelayMode isInbound isBlockOnly isRegistered currentFloodCount
  | isBlockOnly = RelayFlood  -- Block-relay-only gets flooding (no tx relay anyway)
  | not isRegistered = RelayFlood  -- Not registered, must flood
  | isInbound = RelayReconcile  -- Inbound peers use reconciliation
  | currentFloodCount < erlayFloodOutboundCount = RelayFlood  -- First N outbound flood
  | otherwise = RelayReconcile  -- Rest use reconciliation

-- | Get list of peers that should receive flood relay
getFloodPeers :: [(Int, Bool, Bool, Bool)]  -- ^ (peerId, isInbound, isBlockOnly, isRegistered)
              -> [Int]
getFloodPeers peers =
  let sorted = sortBy (comparing (\(_, isIn, _, _) -> isIn)) peers  -- Outbound first
      go [] _ acc = acc
      go ((pid, isIn, isBlock, isReg):rest) floodCount acc =
        let mode = selectRelayMode isIn isBlock isReg floodCount
        in if mode == RelayFlood
           then go rest (floodCount + 1) (pid : acc)
           else go rest floodCount acc
  in go sorted 0 []

-- | Get list of peers that should use reconciliation
getReconciliationPeers :: [(Int, Bool, Bool, Bool)]  -- ^ (peerId, isInbound, isBlockOnly, isRegistered)
                       -> [Int]
getReconciliationPeers peers =
  let floodPeerSet = Set.fromList (getFloodPeers peers)
  in [ pid | (pid, _, _, isReg) <- peers
     , isReg
     , pid `Set.notMember` floodPeerSet
     ]

--------------------------------------------------------------------------------
-- Erlay Reconciliation Protocol (BIP330)
-- High-level protocol operations for transaction set reconciliation
--------------------------------------------------------------------------------

-- | Per-peer Erlay state for active reconciliation
data ErlayPeerState = ErlayPeerState
  { epsReconciliationState :: !ReconciliationState  -- ^ Core reconciliation data
  , epsReconciliationSet   :: !ReconciliationSet    -- ^ Pending txs for this peer
  , epsLastReconTime       :: !(TVar Int64)         -- ^ Timestamp of last reconciliation
  , epsNextReconTime       :: !(TVar Int64)         -- ^ When to initiate next reconciliation
  , epsExtensionAllowed    :: !(TVar Bool)          -- ^ Whether extension round is allowed
  }

-- | Create a new Erlay peer state from reconciliation state
newErlayPeerState :: ReconciliationState -> IO ErlayPeerState
newErlayPeerState rs = do
  rset <- newReconciliationSet (rsSipKey rs)
  lastTime <- newTVarIO 0
  nextTime <- newTVarIO 0
  extAllowed <- newTVarIO True
  return ErlayPeerState
    { epsReconciliationState = rs
    , epsReconciliationSet = rset
    , epsLastReconTime = lastTime
    , epsNextReconTime = nextTime
    , epsExtensionAllowed = extAllowed
    }

-- | Compute Poisson delay for reconciliation interval (BIP330)
-- Returns delay in microseconds
erlayPoissonDelay :: Int64 -> IO Int64
erlayPoissonDelay meanInterval = do
  u <- randomRIO (0.0 :: Double, 1.0)
  let delay = negate (log u) * fromIntegral meanInterval
  -- Clamp to reasonable bounds (100ms to 30 seconds)
  return $ max 100000 $ min 30000000 $ round delay

-- | Get the time until next reconciliation should be initiated
getReconciliationTimer :: ErlayPeerState -> IO Int64
getReconciliationTimer eps = do
  now <- round <$> getPOSIXTime
  nextTime <- readTVarIO (epsNextReconTime eps)
  if nextTime <= 0
    then do
      -- First reconciliation: schedule with Poisson delay
      delay <- erlayPoissonDelay erlayReconInterval
      let next = now * 1000000 + delay  -- Convert to microseconds
      atomically $ writeTVar (epsNextReconTime eps) next
      return delay
    else return $ max 0 (nextTime - now * 1000000)

-- | Initiate reconciliation with a peer (as initiator)
-- Returns the ReqRecon message to send
initiateReconciliation :: ErlayPeerState -> IO ReqRecon
initiateReconciliation eps = do
  now <- round <$> getPOSIXTime
  atomically $ writeTVar (epsLastReconTime eps) now

  -- Build sketch from our reconciliation set
  let rset = epsReconciliationSet eps
  shortIdMap <- readTVarIO (rsetShortIds rset)
  let setSize = Map.size shortIdMap
      -- Estimate capacity: 10% of set size + some buffer
      -- This is the expected set difference
      estimatedDiff = max 1 (setSize `div` 10 + 2)
      capacity = estimatedDiff * 2  -- Double for safety

  sketch <- buildSketchFromSet rset capacity
  let sketchBytes = sketchSerialize sketch

  -- Reset extension allowance for new reconciliation
  atomically $ writeTVar (epsExtensionAllowed eps) True

  -- Schedule next reconciliation
  delay <- erlayPoissonDelay erlayReconInterval
  atomically $ writeTVar (epsNextReconTime eps) (now * 1000000 + delay)

  return ReqRecon
    { rrSetSize = fromIntegral setSize
    , rrQ = fromIntegral estimatedDiff
    , rrSketch = sketchBytes
    }

-- | Handle a ReqRecon message from peer (as responder)
-- Returns either a ReconcilDiff or SketchExt for extension
handleReqRecon :: ErlayPeerState
               -> ReqRecon
               -> IO (Either ReconcilDiff SketchExt)
handleReqRecon eps req = do
  let rset = epsReconciliationSet eps

  -- Deserialize their sketch
  case sketchDeserialize (rrSketch req) of
    Left _err -> return $ Left ReconcilDiff
      { rdSuccess = False
      , rdMissing = []
      , rdExtra = []
      }
    Right theirSketch -> do
      -- Compute set difference
      let capacity = sketchCapacity theirSketch
      result <- computeSetDifference rset theirSketch capacity

      case result of
        Left _err -> do
          -- Decode failed, need extension or fallback
          -- For now, return failure
          return $ Left ReconcilDiff
            { rdSuccess = False
            , rdMissing = []
            , rdExtra = []
            }

        Right (weHave, _theyHaveShortIds) -> do
          -- Successful decode
          -- weHave = TxIds we have that they don't (we announce to them)
          -- theyHaveShortIds = short IDs they have that we don't (we request)
          -- Note: We can't convert theyHaveShortIds to TxIds here since
          -- we don't have those txs. The initiator knows them.

          -- Clear the reconciliation set after successful reconciliation
          atomically $ do
            writeTVar (rsetTxs rset) Set.empty
            writeTVar (rsetShortIds rset) Map.empty

          return $ Left ReconcilDiff
            { rdSuccess = True
            , rdMissing = []  -- Initiator figures this out from the sketch
            , rdExtra = weHave  -- TxIds initiator is missing
            }

-- | Handle a ReconcilDiff message from peer (as initiator)
-- Returns (txids to request via getdata, txids to announce via inv)
handleReconcilDiff :: ErlayPeerState
                   -> ReconcilDiff
                   -> IO ([TxId], [TxId])
handleReconcilDiff eps diff = do
  if rdSuccess diff
    then do
      -- Successful reconciliation
      -- rdExtra = TxIds we have that they don't (announce via INV)
      -- rdMissing = TxIds they have that we don't (request via GETDATA)
      let toAnnounce = rdExtra diff
          toRequest = rdMissing diff

      -- Clear our reconciliation set
      let rset = epsReconciliationSet eps
      atomically $ do
        writeTVar (rsetTxs rset) Set.empty
        writeTVar (rsetShortIds rset) Map.empty

      return (toRequest, toAnnounce)
    else do
      -- Reconciliation failed, fall back to flooding
      -- Send all our pending txs via INV
      let rset = epsReconciliationSet eps
      txs <- readTVarIO (rsetTxs rset)

      -- Clear the set
      atomically $ do
        writeTVar (rsetTxs rset) Set.empty
        writeTVar (rsetShortIds rset) Map.empty

      return ([], Set.toList txs)

--------------------------------------------------------------------------------
-- Tor/I2P Connectivity (Phase 48)
-- SOCKS5 proxy for Tor, SAM protocol for I2P, hidden service support
--------------------------------------------------------------------------------

-- | SOCKS5 address type constants
socks5AddrTypeIPv4 :: Word8
socks5AddrTypeIPv4 = 0x01

socks5AddrTypeDomain :: Word8
socks5AddrTypeDomain = 0x03

socks5AddrTypeIPv6 :: Word8
socks5AddrTypeIPv6 = 0x04

-- | SOCKS5 command: connect
socks5CmdConnect :: Word8
socks5CmdConnect = 0x01

-- | SOCKS5 authentication method: no auth
socks5AuthNone :: Word8
socks5AuthNone = 0x00

-- | SOCKS5 reply codes
data Socks5Reply
  = Socks5Succeeded           -- ^ 0x00: succeeded
  | Socks5GeneralFailure      -- ^ 0x01: general SOCKS server failure
  | Socks5NotAllowed          -- ^ 0x02: connection not allowed by ruleset
  | Socks5NetworkUnreachable  -- ^ 0x03: network unreachable
  | Socks5HostUnreachable     -- ^ 0x04: host unreachable
  | Socks5ConnectionRefused   -- ^ 0x05: connection refused
  | Socks5TtlExpired          -- ^ 0x06: TTL expired
  | Socks5CmdNotSupported     -- ^ 0x07: command not supported
  | Socks5AddrNotSupported    -- ^ 0x08: address type not supported
  | Socks5Unknown Word8       -- ^ Unknown reply code
  deriving (Show, Eq, Generic)

instance NFData Socks5Reply

-- | Parse SOCKS5 reply code
word8ToSocks5Reply :: Word8 -> Socks5Reply
word8ToSocks5Reply 0x00 = Socks5Succeeded
word8ToSocks5Reply 0x01 = Socks5GeneralFailure
word8ToSocks5Reply 0x02 = Socks5NotAllowed
word8ToSocks5Reply 0x03 = Socks5NetworkUnreachable
word8ToSocks5Reply 0x04 = Socks5HostUnreachable
word8ToSocks5Reply 0x05 = Socks5ConnectionRefused
word8ToSocks5Reply 0x06 = Socks5TtlExpired
word8ToSocks5Reply 0x07 = Socks5CmdNotSupported
word8ToSocks5Reply 0x08 = Socks5AddrNotSupported
word8ToSocks5Reply n    = Socks5Unknown n

-- | SOCKS5 connect request structure
data Socks5Request = Socks5Request
  { s5Cmd      :: !Word8        -- ^ Command (0x01 = connect)
  , s5AddrType :: !Word8        -- ^ Address type
  , s5Addr     :: !ByteString   -- ^ Address bytes
  , s5Port     :: !Word16       -- ^ Destination port
  } deriving (Show, Eq, Generic)

instance NFData Socks5Request

-- | Serialize SOCKS5 connect request
instance Serialize Socks5Request where
  put Socks5Request{..} = do
    putWord8 0x05            -- Version
    putWord8 s5Cmd           -- Command
    putWord8 0x00            -- Reserved
    putWord8 s5AddrType      -- Address type
    -- Address depends on type
    case s5AddrType of
      0x01 -> putByteString s5Addr  -- IPv4 (4 bytes)
      0x03 -> do                     -- Domain name
        putWord8 (fromIntegral $ BS.length s5Addr)
        putByteString s5Addr
      0x04 -> putByteString s5Addr  -- IPv6 (16 bytes)
      _    -> putByteString s5Addr  -- Unknown

    putWord16be s5Port       -- Port (big-endian)

  get = do
    ver <- getWord8
    when (ver /= 0x05) $ fail "Invalid SOCKS version"
    cmd <- getWord8
    _ <- getWord8  -- Reserved
    addrType <- getWord8
    addr <- case addrType of
      0x01 -> getBytes 4                     -- IPv4
      0x03 -> do                             -- Domain
        len <- getWord8
        getBytes (fromIntegral len)
      0x04 -> getBytes 16                    -- IPv6
      _    -> fail $ "Unknown address type: " ++ show addrType
    port <- getWord16be
    return $ Socks5Request cmd addrType addr port

-- | SOCKS5 connect response
data Socks5Response = Socks5Response
  { s5rReply    :: !Socks5Reply   -- ^ Reply code
  , s5rAddrType :: !Word8         -- ^ Bound address type
  , s5rAddr     :: !ByteString    -- ^ Bound address
  , s5rPort     :: !Word16        -- ^ Bound port
  } deriving (Show, Eq, Generic)

instance NFData Socks5Response

-- | Parse SOCKS5 response
parseSocks5Response :: ByteString -> Either String Socks5Response
parseSocks5Response bs = runGet getter bs
  where
    getter = do
      ver <- getWord8
      when (ver /= 0x05) $ fail "Invalid SOCKS version in response"
      rep <- getWord8
      _ <- getWord8  -- Reserved
      addrType <- getWord8
      addr <- case addrType of
        0x01 -> getBytes 4   -- IPv4
        0x03 -> do           -- Domain
          len <- getWord8
          getBytes (fromIntegral len)
        0x04 -> getBytes 16  -- IPv6
        _    -> fail $ "Unknown address type in response: " ++ show addrType
      port <- getWord16be
      return $ Socks5Response (word8ToSocks5Reply rep) addrType addr port

-- | Proxy configuration for Tor/I2P connections
data ProxyConfig
  = NoProxy                           -- ^ Direct connection
  | Socks5Proxy !String !Int          -- ^ SOCKS5 proxy (host, port)
  | I2PSamProxy !String !Int          -- ^ I2P SAM bridge (host, port)
  deriving (Show, Eq, Generic)

instance NFData ProxyConfig

-- | Default Tor proxy configuration
defaultTorProxy :: ProxyConfig
defaultTorProxy = Socks5Proxy "127.0.0.1" 9050

-- | Default I2P SAM bridge configuration
defaultI2PSam :: ProxyConfig
defaultI2PSam = I2PSamProxy "127.0.0.1" 7656

-- | Perform SOCKS5 handshake (greeting + authentication)
-- Returns the connected socket on success
socks5Handshake :: Socket -> IO (Either String ())
socks5Handshake sock = do
  -- Send greeting: version 5, 1 auth method (no auth)
  let greeting = BS.pack [0x05, 0x01, socks5AuthNone]
  sendAll sock greeting

  -- Receive server choice (2 bytes)
  response <- recv sock 2
  if BS.length response /= 2
    then return $ Left "SOCKS5: incomplete greeting response"
    else do
      let ver = BS.index response 0
          method = BS.index response 1
      if ver /= 0x05
        then return $ Left "SOCKS5: server version mismatch"
        else if method /= socks5AuthNone
          then return $ Left $ "SOCKS5: auth method not supported: " ++ show method
          else return $ Right ()

-- | Send SOCKS5 connect request to domain name
socks5Connect :: Socket -> String -> Word16 -> IO (Either String Socks5Response)
socks5Connect sock host port
  | length host > 255 = return $ Left "SOCKS5: hostname too long"
  | otherwise = do
      let req = Socks5Request
            { s5Cmd      = socks5CmdConnect
            , s5AddrType = socks5AddrTypeDomain
            , s5Addr     = C8.pack host
            , s5Port     = port
            }
      sendAll sock (encode req)

      -- Receive response (minimum 10 bytes for IPv4, could be more for domain)
      -- First read fixed header + address type
      header <- recv sock 4
      if BS.length header /= 4
        then return $ Left "SOCKS5: incomplete connect response header"
        else do
          let addrType = BS.index header 3
          -- Read rest based on address type
          (restLen, addrLen) <- case addrType of
            0x01 -> return (4 + 2, 4)    -- IPv4 + port
            0x03 -> do                    -- Domain: 1 byte len + domain + port
              lenByte <- recv sock 1
              if BS.null lenByte
                then return (0, 0)
                else return (fromIntegral (BS.index lenByte 0) + 2,
                             fromIntegral (BS.index lenByte 0))
            0x04 -> return (16 + 2, 16)  -- IPv6 + port
            _    -> return (0, 0)

          if restLen == 0
            then return $ Left $ "SOCKS5: unknown address type: " ++ show addrType
            else do
              rest <- recv sock restLen
              if BS.length rest /= restLen
                then return $ Left "SOCKS5: incomplete connect response body"
                else do
                  let addr = BS.take addrLen rest
                      portBs = BS.drop addrLen rest
                      respPort = case runGet getWord16be portBs of
                        Right p -> p
                        Left _  -> 0
                      reply = word8ToSocks5Reply (BS.index header 1)
                  return $ Right $ Socks5Response reply addrType addr respPort

-- | Connect to a .onion address via Tor SOCKS5 proxy
connectThroughTor :: String -> Int -> String -> Word16
                  -> IO (Either String Socket)
connectThroughTor proxyHost proxyPort targetHost targetPort = do
  result <- try @SomeException $ do
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just proxyHost) (Just (show proxyPort))
    case addrs of
      [] -> fail $ "Cannot resolve SOCKS5 proxy: " ++ proxyHost
      (addr:_) -> do
        sock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect sock (NS.addrAddress addr)

        -- Perform SOCKS5 handshake
        handshakeResult <- socks5Handshake sock
        case handshakeResult of
          Left err -> do
            close sock
            fail err
          Right () -> do
            -- Send CONNECT request
            connectResult <- socks5Connect sock targetHost targetPort
            case connectResult of
              Left err -> do
                close sock
                fail err
              Right resp ->
                case s5rReply resp of
                  Socks5Succeeded -> return sock
                  other -> do
                    close sock
                    fail $ "SOCKS5 connect failed: " ++ show other

  case result of
    Left e   -> return $ Left (show e)
    Right s  -> return $ Right s

-- | Check if an address is a Tor .onion address
isOnionAddress :: String -> Bool
isOnionAddress addr = ".onion" `T.isSuffixOf` T.pack (map toLower addr)
  where
    toLower c = if c >= 'A' && c <= 'Z' then toEnum (fromEnum c + 32) else c

-- | Check if an address is an I2P .i2p address
isI2PAddress :: String -> Bool
isI2PAddress addr = ".i2p" `T.isSuffixOf` T.pack (map toLower addr)
  where
    toLower c = if c >= 'A' && c <= 'Z' then toEnum (fromEnum c + 32) else c

--------------------------------------------------------------------------------
-- Tor Control Port Protocol
-- For creating hidden services (ADD_ONION)
--------------------------------------------------------------------------------

-- | Tor control port default address
defaultTorControlPort :: (String, Int)
defaultTorControlPort = ("127.0.0.1", 9051)

-- | Tor hidden service key type
data TorKeyType
  = TorKeyED25519V3          -- ^ ED25519-V3 (Tor v3 onion)
  | TorKeyExisting ByteString -- ^ Existing private key
  deriving (Show, Eq, Generic)

instance NFData TorKeyType

-- | Tor ADD_ONION response
data TorOnionResponse = TorOnionResponse
  { torServiceId  :: !ByteString  -- ^ The .onion address (without .onion suffix)
  , torPrivateKey :: !ByteString  -- ^ The private key for persistence
  } deriving (Show, Eq, Generic)

instance NFData TorOnionResponse

-- | Parse a Tor control port response line
-- Format: <status-code><sep><data>
parseTorResponse :: ByteString -> Either String (Int, ByteString)
parseTorResponse line =
  let codeStr = BS.take 3 line
  in case C8.readInt codeStr of
       Just (code, _) -> Right (code, BS.drop 4 line)
       Nothing -> Left "Invalid Tor response code"

-- | Send a command to Tor control port and receive response
torControlSend :: Socket -> ByteString -> IO (Either String [ByteString])
torControlSend sock cmd = do
  sendAll sock (cmd <> "\r\n")
  recvTorResponse sock

-- | Receive multiline Tor control response
recvTorResponse :: Socket -> IO (Either String [ByteString])
recvTorResponse sock = go []
  where
    go acc = do
      line <- recvTorLine sock
      case line of
        Nothing -> return $ Left "Tor control: connection closed"
        Just l ->
          if BS.length l < 4
            then return $ Left "Tor control: response too short"
            else do
              let sep = BS.index l 3
              case sep of
                32  -> return $ Right (reverse (l : acc))  -- Space = final line
                45  -> go (l : acc)                        -- Dash = more lines
                43  -> go (l : acc)                        -- Plus = data follows
                _   -> return $ Left "Tor control: invalid separator"

-- | Read a line from socket (up to CRLF)
recvTorLine :: Socket -> IO (Maybe ByteString)
recvTorLine sock = go BS.empty
  where
    go acc = do
      byte <- recv sock 1
      if BS.null byte
        then if BS.null acc then return Nothing else return (Just acc)
        else let c = BS.index byte 0
             in if c == 0x0a  -- LF
                  then return $ Just (if BS.null acc then acc
                                      else BS.init acc)  -- Remove CR if present
                  else go (acc <> byte)

-- | Authenticate to Tor control port (NULL authentication)
torAuthenticate :: Socket -> IO (Either String ())
torAuthenticate sock = do
  result <- torControlSend sock "AUTHENTICATE"
  case result of
    Left err -> return $ Left err
    Right lines' ->
      case lines' of
        [] -> return $ Left "Tor: no auth response"
        (first:_) ->
          case parseTorResponse first of
            Left err -> return $ Left err
            Right (250, _) -> return $ Right ()
            Right (code, msg) -> return $ Left $
              "Tor auth failed: " ++ show code ++ " " ++ C8.unpack msg

-- | Create an ephemeral hidden service
-- ADD_ONION NEW:ED25519-V3 Port=<virtual>,<target>
torAddOnion :: Socket -> Word16 -> String -> Word16
            -> IO (Either String TorOnionResponse)
torAddOnion sock virtualPort targetHost targetPort = do
  let cmd = "ADD_ONION NEW:ED25519-V3 Port=" <>
            C8.pack (show virtualPort) <> "," <>
            C8.pack targetHost <> ":" <>
            C8.pack (show targetPort)
  result <- torControlSend sock cmd
  case result of
    Left err -> return $ Left err
    Right lines' -> parseTorAddOnionResponse lines'

-- | Parse ADD_ONION response to extract ServiceID and PrivateKey
parseTorAddOnionResponse :: [ByteString] -> IO (Either String TorOnionResponse)
parseTorAddOnionResponse lines' = do
  let pairs = mapMaybe parseKeyValue lines'
      mServiceId = lookup "ServiceID" pairs
      mPrivKey = lookup "PrivateKey" pairs
  case mServiceId of
    Nothing -> return $ Left "Tor: missing ServiceID in response"
    Just sid -> return $ Right $ TorOnionResponse
      { torServiceId = sid
      , torPrivateKey = fromMaybe' BS.empty mPrivKey
      }
  where
    parseKeyValue :: ByteString -> Maybe (ByteString, ByteString)
    parseKeyValue bs =
      let (code, rest) = BS.splitAt 4 bs
      in if BS.take 3 code == "250" && BS.length rest > 0
           then let parts = C8.split '=' (BS.drop 1 rest)
                in case parts of
                     [k, v] -> Just (k, v)
                     _      -> Nothing
           else Nothing

    fromMaybe' :: a -> Maybe a -> a
    fromMaybe' def Nothing  = def
    fromMaybe' _   (Just x) = x

-- | Connect to Tor control port and create hidden service
createTorHiddenService :: String -> Int -> Word16 -> String -> Word16
                       -> IO (Either String TorOnionResponse)
createTorHiddenService ctrlHost ctrlPort virtualPort targetHost targetPort = do
  result <- try @SomeException $ do
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just ctrlHost) (Just (show ctrlPort))
    case addrs of
      [] -> fail $ "Cannot resolve Tor control: " ++ ctrlHost
      (addr:_) -> do
        sock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect sock (NS.addrAddress addr)

        -- Authenticate
        authResult <- torAuthenticate sock
        case authResult of
          Left err -> do
            close sock
            fail err
          Right () -> do
            -- Create hidden service
            onionResult <- torAddOnion sock virtualPort targetHost targetPort
            close sock
            case onionResult of
              Left err -> fail err
              Right resp -> return resp

  case result of
    Left e   -> return $ Left (show e)
    Right r  -> return $ Right r

--------------------------------------------------------------------------------
-- I2P SAM Protocol
-- Session creation and stream connections to I2P peers
--------------------------------------------------------------------------------

-- | I2P SAM protocol version
samVersion :: ByteString
samVersion = "3.1"

-- | I2P SAM default port (from Bitcoin Core)
i2pSamPort :: Int
i2pSamPort = 7656

-- | I2P signature type: EdDSA_SHA512_Ed25519
samSignatureType :: Int
samSignatureType = 7

-- | SAM command result
data SamResult
  = SamOK              -- ^ OK
  | SamCantReachPeer   -- ^ CANT_REACH_PEER
  | SamTimeout         -- ^ TIMEOUT
  | SamInvalidId       -- ^ INVALID_ID (session damaged)
  | SamDuplicated      -- ^ DUPLICATED_ID
  | SamI2PError        -- ^ I2P_ERROR
  | SamUnknown ByteString
  deriving (Show, Eq, Generic)

instance NFData SamResult

-- | Parse SAM result string
parseSamResult :: ByteString -> SamResult
parseSamResult "OK"              = SamOK
parseSamResult "CANT_REACH_PEER" = SamCantReachPeer
parseSamResult "TIMEOUT"         = SamTimeout
parseSamResult "INVALID_ID"      = SamInvalidId
parseSamResult "DUPLICATED_ID"   = SamDuplicated
parseSamResult "I2P_ERROR"       = SamI2PError
parseSamResult other             = SamUnknown other

-- | SAM session state
data SamSession = SamSession
  { samSocket      :: !Socket         -- ^ Control socket
  , samSessionId   :: !ByteString     -- ^ 10-char session ID
  , samDestination :: !ByteString     -- ^ Our I2P destination (base64)
  , samB32Address  :: !ByteString     -- ^ Our .b32.i2p address
  } deriving (Generic)

-- | Parse SAM key-value response
-- Format: "COMMAND RESULT=value KEY=value ..."
parseSamResponse :: ByteString -> Map ByteString ByteString
parseSamResponse bs =
  let parts = C8.split ' ' bs
      pairs = mapMaybe parseKV parts
  in Map.fromList pairs
  where
    parseKV :: ByteString -> Maybe (ByteString, ByteString)
    parseKV p =
      case C8.split '=' p of
        [k, v] -> Just (k, v)
        _      -> Nothing

-- | Send SAM command and receive response line
samSendRecv :: Socket -> ByteString -> IO (Either String ByteString)
samSendRecv sock cmd = do
  sendAll sock (cmd <> "\n")
  recvSamLine sock

-- | Receive a single line from SAM (up to newline)
recvSamLine :: Socket -> IO (Either String ByteString)
recvSamLine sock = go BS.empty
  where
    go acc = do
      byte <- recv sock 1
      if BS.null byte
        then if BS.null acc
               then return $ Left "SAM: connection closed"
               else return $ Right acc
        else let c = BS.index byte 0
             in if c == 0x0a  -- LF
                  then return $ Right acc
                  else go (acc <> byte)

-- | Perform SAM HELLO handshake
samHello :: Socket -> IO (Either String ())
samHello sock = do
  let cmd = "HELLO VERSION MIN=" <> samVersion <> " MAX=" <> samVersion
  result <- samSendRecv sock cmd
  case result of
    Left err -> return $ Left err
    Right resp -> do
      let parsed = parseSamResponse resp
      case Map.lookup "RESULT" parsed of
        Just "OK" -> return $ Right ()
        Just other -> return $ Left $ "SAM HELLO failed: " ++ C8.unpack other
        Nothing -> return $ Left "SAM HELLO: missing RESULT"

-- | Create a SAM session (transient destination)
samCreateSession :: Socket -> IO (Either String SamSession)
samCreateSession sock = do
  -- Generate random 10-char session ID
  sessionId <- replicateM 10 (randomRIO ('a', 'z'))
  let sid = C8.pack sessionId
      cmd = "SESSION CREATE STYLE=STREAM ID=" <> sid <>
            " DESTINATION=TRANSIENT SIGNATURE_TYPE=" <>
            C8.pack (show samSignatureType) <>
            " i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1"
  result <- samSendRecv sock cmd
  case result of
    Left err -> return $ Left err
    Right resp -> do
      let parsed = parseSamResponse resp
      case Map.lookup "RESULT" parsed of
        Just "OK" ->
          case Map.lookup "DESTINATION" parsed of
            Just dest -> do
              -- Convert destination to .b32.i2p address
              let b32addr = i2pDestToB32 dest
              return $ Right $ SamSession
                { samSocket = sock
                , samSessionId = sid
                , samDestination = dest
                , samB32Address = b32addr
                }
            Nothing -> return $ Left "SAM SESSION: missing DESTINATION"
        Just other -> return $ Left $ "SAM SESSION failed: " ++ C8.unpack other
        Nothing -> return $ Left "SAM SESSION: missing RESULT"

-- | Convert I2P destination to .b32.i2p address
-- Hash the destination with SHA256, then base32 encode
i2pDestToB32 :: ByteString -> ByteString
i2pDestToB32 dest =
  let -- I2P uses modified base64
      standardDest = i2pBase64ToStandard dest
      -- Decode base64 destination
      decoded = case decodeBase64I2P standardDest of
        Right d -> d
        Left _  -> BS.empty
      -- SHA256 hash
      hash = sha256 decoded
      -- Base32 encode (lowercase)
      b32 = base32Encode hash
  in b32 <> ".b32.i2p"

-- | Convert I2P modified base64 to standard base64
-- I2P uses '-' instead of '+' and '~' instead of '/'
i2pBase64ToStandard :: ByteString -> ByteString
i2pBase64ToStandard = BS.map convertI2PChar
  where
    convertI2PChar 45 = 43   -- '-' -> '+'
    convertI2PChar 126 = 47  -- '~' -> '/'
    convertI2PChar c = c

-- | Convert standard base64 to I2P modified base64
standardToI2PBase64 :: ByteString -> ByteString
standardToI2PBase64 = BS.map convertStdChar
  where
    convertStdChar 43 = 45   -- '+' -> '-'
    convertStdChar 47 = 126  -- '/' -> '~'
    convertStdChar c = c

-- | Simple base64 decoding for I2P
decodeBase64I2P :: ByteString -> Either String ByteString
decodeBase64I2P bs =
  -- Use a simple implementation since we converted to standard base64
  case C8.unpack bs of
    [] -> Right BS.empty
    s  -> Right $ decodeBase64Simple s

-- | Simple base64 decoder
decodeBase64Simple :: String -> ByteString
decodeBase64Simple str =
  let -- Remove padding
      noPad = filter (/= '=') str
      -- Convert to 6-bit values
      values = map base64CharValue noPad
      -- Group into bytes
      bytes = base64ToBytes values
  in BS.pack bytes
  where
    base64CharValue :: Char -> Int
    base64CharValue c
      | c >= 'A' && c <= 'Z' = fromEnum c - fromEnum 'A'
      | c >= 'a' && c <= 'z' = fromEnum c - fromEnum 'a' + 26
      | c >= '0' && c <= '9' = fromEnum c - fromEnum '0' + 52
      | c == '+' = 62
      | c == '/' = 63
      | otherwise = 0

    base64ToBytes :: [Int] -> [Word8]
    base64ToBytes [] = []
    base64ToBytes [_] = []  -- Invalid, need at least 2
    base64ToBytes [a, b] =
      [fromIntegral $ (a `shiftL` 2) .|. (b `shiftR` 4)]
    base64ToBytes [a, b, c] =
      [fromIntegral $ (a `shiftL` 2) .|. (b `shiftR` 4),
       fromIntegral $ ((b .&. 0x0f) `shiftL` 4) .|. (c `shiftR` 2)]
    base64ToBytes (a:b:c:d:rest) =
      [fromIntegral $ (a `shiftL` 2) .|. (b `shiftR` 4),
       fromIntegral $ ((b .&. 0x0f) `shiftL` 4) .|. (c `shiftR` 2),
       fromIntegral $ ((c .&. 0x03) `shiftL` 6) .|. d]
      ++ base64ToBytes rest

-- | Base32 encoding (RFC 4648, lowercase)
base32Encode :: ByteString -> ByteString
base32Encode bs =
  let chars = "abcdefghijklmnopqrstuvwxyz234567"
      bytes = BS.unpack bs
      bits = concatMap byteToBits bytes
      groups = chunksOf 5 bits
      encoded = map (bitsToChar chars) groups
  in C8.pack encoded
  where
    byteToBits :: Word8 -> [Bool]
    byteToBits b = [testBit' b i | i <- [7,6..0]]

    testBit' :: Word8 -> Int -> Bool
    testBit' x i = (x `shiftR` i) .&. 1 == 1

    bitsToChar :: String -> [Bool] -> Char
    bitsToChar alphabet bits5 =
      let padded = take 5 (bits5 ++ repeat False)
          val = foldl' (\acc b -> acc * 2 + if b then 1 else 0) 0 padded
      in alphabet !! val

    chunksOf :: Int -> [a] -> [[a]]
    chunksOf _ [] = []
    chunksOf n xs = take n xs : chunksOf n (drop n xs)

-- | Connect to I2P destination via SAM
samStreamConnect :: SamSession -> ByteString -> IO (Either String Socket)
samStreamConnect sess destAddr = do
  result <- try @SomeException $ do
    -- Lookup the destination if it's a .b32.i2p address
    resolvedDest <- if ".b32.i2p" `C8.isSuffixOf` destAddr ||
                       ".i2p" `C8.isSuffixOf` destAddr
      then do
        -- Need to lookup
        lookupResult <- samNameLookup (samSocket sess) destAddr
        case lookupResult of
          Left err -> fail err
          Right d -> return d
      else return destAddr  -- Already a full destination

    -- Create a new socket for the stream
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just "127.0.0.1") (Just (show i2pSamPort))
    case addrs of
      [] -> fail "Cannot resolve SAM bridge"
      (addr:_) -> do
        streamSock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect streamSock (NS.addrAddress addr)

        -- HELLO on stream socket
        helloResult <- samHello streamSock
        case helloResult of
          Left err -> do
            close streamSock
            fail err
          Right () -> do
            -- STREAM CONNECT
            let cmd = "STREAM CONNECT ID=" <> samSessionId sess <>
                      " DESTINATION=" <> resolvedDest <> " SILENT=false"
            connResult <- samSendRecv streamSock cmd
            case connResult of
              Left err -> do
                close streamSock
                fail err
              Right resp -> do
                let parsed = parseSamResponse resp
                case Map.lookup "RESULT" parsed of
                  Just "OK" -> return streamSock
                  Just other -> do
                    close streamSock
                    fail $ "SAM STREAM CONNECT failed: " ++ C8.unpack other
                  Nothing -> do
                    close streamSock
                    fail "SAM STREAM CONNECT: missing RESULT"

  case result of
    Left e   -> return $ Left (show e)
    Right s  -> return $ Right s

-- | Lookup I2P name to destination
samNameLookup :: Socket -> ByteString -> IO (Either String ByteString)
samNameLookup sock name = do
  let cmd = "NAMING LOOKUP NAME=" <> name
  result <- samSendRecv sock cmd
  case result of
    Left err -> return $ Left err
    Right resp -> do
      let parsed = parseSamResponse resp
      case Map.lookup "RESULT" parsed of
        Just "OK" ->
          case Map.lookup "VALUE" parsed of
            Just dest -> return $ Right dest
            Nothing -> return $ Left "NAMING LOOKUP: missing VALUE"
        Just "KEY_NOT_FOUND" -> return $ Left "NAMING LOOKUP: destination not found"
        Just other -> return $ Left $ "NAMING LOOKUP failed: " ++ C8.unpack other
        Nothing -> return $ Left "NAMING LOOKUP: missing RESULT"

-- | Accept incoming I2P connection
samStreamAccept :: SamSession -> IO (Either String (Socket, ByteString))
samStreamAccept sess = do
  result <- try @SomeException $ do
    -- Create a new socket for accepting
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just "127.0.0.1") (Just (show i2pSamPort))
    case addrs of
      [] -> fail "Cannot resolve SAM bridge"
      (addr:_) -> do
        acceptSock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect acceptSock (NS.addrAddress addr)

        -- HELLO
        helloResult <- samHello acceptSock
        case helloResult of
          Left err -> do
            close acceptSock
            fail err
          Right () -> do
            -- STREAM ACCEPT
            let cmd = "STREAM ACCEPT ID=" <> samSessionId sess <> " SILENT=false"
            acceptResult <- samSendRecv acceptSock cmd
            case acceptResult of
              Left err -> do
                close acceptSock
                fail err
              Right resp -> do
                let parsed = parseSamResponse resp
                case Map.lookup "RESULT" parsed of
                  Just "OK" -> do
                    -- Next line will be the peer's destination
                    peerLine <- recvSamLine acceptSock
                    case peerLine of
                      Left err -> do
                        close acceptSock
                        fail err
                      Right peerDest ->
                        return (acceptSock, i2pDestToB32 peerDest)
                  Just other -> do
                    close acceptSock
                    fail $ "SAM STREAM ACCEPT failed: " ++ C8.unpack other
                  Nothing -> do
                    close acceptSock
                    fail "SAM STREAM ACCEPT: missing RESULT"

  case result of
    Left e   -> return $ Left (show e)
    Right r  -> return $ Right r

-- | Create an I2P SAM session
createI2PSession :: String -> Int -> IO (Either String SamSession)
createI2PSession host port = do
  result <- try @SomeException $ do
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just host) (Just (show port))
    case addrs of
      [] -> fail $ "Cannot resolve SAM bridge: " ++ host
      (addr:_) -> do
        sock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect sock (NS.addrAddress addr)

        -- HELLO
        helloResult <- samHello sock
        case helloResult of
          Left err -> do
            close sock
            fail err
          Right () -> do
            -- Create session
            sessResult <- samCreateSession sock
            case sessResult of
              Left err -> do
                close sock
                fail err
              Right s -> return s

  case result of
    Left e   -> return $ Left (show e)
    Right s  -> return $ Right s

-- | Close I2P SAM session
closeI2PSession :: SamSession -> IO ()
closeI2PSession sess = close (samSocket sess)

--------------------------------------------------------------------------------
-- Unified Proxy Connection API
--------------------------------------------------------------------------------

-- | Extended peer configuration with proxy support
data ProxyPeerConfig = ProxyPeerConfig
  { ppcBase        :: !PeerConfig     -- ^ Base peer configuration
  , ppcProxyConfig :: !ProxyConfig    -- ^ Proxy configuration
  } deriving (Show)

-- | Connect to a peer through a proxy if needed
-- Handles Tor .onion addresses via SOCKS5, I2P .i2p addresses via SAM
connectPeerThroughProxy :: ProxyPeerConfig -> String -> Int
                        -> IO (Either String PeerConnection)
connectPeerThroughProxy ppc host port
  -- Check if it's a .onion address
  | isOnionAddress host =
      case ppcProxyConfig ppc of
        Socks5Proxy proxyHost proxyPort -> do
          sockResult <- connectThroughTor proxyHost proxyPort host (fromIntegral port)
          case sockResult of
            Left err -> return $ Left err
            Right sock -> createPeerConnectionFromSocket (ppcBase ppc) sock host
        _ -> return $ Left "Tor address requires SOCKS5 proxy"

  -- Check if it's an .i2p address
  | isI2PAddress host =
      case ppcProxyConfig ppc of
        I2PSamProxy samHost samPort -> do
          sessResult <- createI2PSession samHost samPort
          case sessResult of
            Left err -> return $ Left err
            Right sess -> do
              connResult <- samStreamConnect sess (C8.pack host)
              case connResult of
                Left err -> do
                  closeI2PSession sess
                  return $ Left err
                Right sock ->
                  createPeerConnectionFromSocket (ppcBase ppc) sock host
        _ -> return $ Left "I2P address requires SAM proxy"

  -- Regular clearnet address
  | otherwise = connectPeer (ppcBase ppc) host port

-- | Connect to a destination through a SOCKS5 proxy, returning the tunneled socket.
--
-- This is a convenience wrapper that performs the SOCKS5 handshake and connect
-- in a single call. Supports domain name resolution through the proxy (no local
-- DNS leak). IPv4 addresses and domain names are supported.
--
-- Usage:
-- @
--   sock <- connectViaProxy "127.0.0.1" 9050 Nothing "example.onion" 8333
-- @
connectViaProxy :: String           -- ^ Proxy host
                -> Int              -- ^ Proxy port
                -> Maybe (String, String)  -- ^ Optional (username, password) — currently unused (no-auth only)
                -> String           -- ^ Destination host (domain or IPv4)
                -> Int              -- ^ Destination port
                -> IO (Either String Socket)
connectViaProxy proxyHostAddr proxyPortNum _proxyAuth destHost destPort = do
  result <- try @SomeException $ do
    let hints = defaultHints { NS.addrSocketType = Stream }
    addrs <- getAddrInfo (Just hints) (Just proxyHostAddr) (Just (show proxyPortNum))
    case addrs of
      [] -> fail $ "Cannot resolve SOCKS5 proxy: " ++ proxyHostAddr
      (addr:_) -> do
        sock <- socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
        connect sock (NS.addrAddress addr)
        -- SOCKS5 greeting: version=5, 1 method, no-auth=0
        handshakeResult <- socks5Handshake sock
        case handshakeResult of
          Left err -> do
            close sock
            fail err
          Right () -> do
            -- SOCKS5 connect request
            connectResult <- socks5Connect sock destHost (fromIntegral destPort)
            case connectResult of
              Left err -> do
                close sock
                fail err
              Right resp ->
                case s5rReply resp of
                  Socks5Succeeded -> return sock
                  other -> do
                    close sock
                    fail $ "SOCKS5 connect failed: " ++ show other
  case result of
    Left e    -> return $ Left (show e)
    Right sock -> return $ Right sock

-- | Create PeerConnection from an already-connected socket
createPeerConnectionFromSocket :: PeerConfig -> Socket -> String
                               -> IO (Either String PeerConnection)
createPeerConnectionFromSocket config sock _host = do
  result <- try @SomeException $ do
    now <- round <$> getPOSIXTime
    -- Create a SockAddr for the host (we don't have the real one through proxy)
    let dummyAddr = SockAddrInet (fromIntegral (0 :: Int)) 0
    let info = PeerInfo
          { piAddress       = dummyAddr
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
          , piWantsAddrV2   = True  -- Tor/I2P peers want ADDRv2
          , piFeeFilterReceived = 0
          , piFeeFilterSent     = 0
          , piNextFeeFilterSend = 0
          , piBlockOnly     = False
          }
    infoVar <- newTVarIO info
    sendQ <- newTBQueueIO (fromIntegral $ pcfgQueueSize config)
    recvQ <- newTBQueueIO (fromIntegral $ pcfgQueueSize config)
    bufRef <- newIORef BS.empty
    return PeerConnection
      { pcSocket     = sock
      , pcInfo       = infoVar
      , pcSendQueue  = sendQ
      , pcRecvQueue  = recvQ
      , pcSendThread = Nothing
      , pcRecvThread = Nothing
      , pcNetwork    = pcfgNetwork config
      , pcReadBuffer = bufRef
      }
  case result of
    Left e   -> return $ Left (show e)
    Right pc -> return $ Right pc

--------------------------------------------------------------------------------
-- Address Reachability for Advertising
--------------------------------------------------------------------------------

-- | Network reachability flags for address advertising
data NetworkReachability = NetworkReachability
  { nrIPv4    :: !Bool  -- ^ Can reach IPv4
  , nrIPv6    :: !Bool  -- ^ Can reach IPv6
  , nrOnion   :: !Bool  -- ^ Can reach .onion (Tor configured)
  , nrI2P     :: !Bool  -- ^ Can reach .i2p (I2P configured)
  } deriving (Show, Eq, Generic)

instance NFData NetworkReachability

-- | Default reachability (clearnet only)
defaultReachability :: NetworkReachability
defaultReachability = NetworkReachability
  { nrIPv4  = True
  , nrIPv6  = True
  , nrOnion = False
  , nrI2P   = False
  }

-- | Check if we should advertise an address based on reachability
shouldAdvertiseAddress :: NetworkReachability -> NetAddr -> Bool
shouldAdvertiseAddress reach addr =
  case netAddrNetworkId addr of
    NetIPv4  -> nrIPv4 reach
    NetIPv6  -> nrIPv6 reach
    NetTorV3 -> nrOnion reach
    NetI2P   -> nrI2P reach
    NetCJDNS -> False  -- CJDNS not supported yet

-- | Filter addresses to only those we can reach
filterReachableAddresses :: NetworkReachability -> [AddrV2] -> [AddrV2]
filterReachableAddresses reach = filter (shouldAdvertise . av2NetId)
  where
    shouldAdvertise NetIPv4  = nrIPv4 reach
    shouldAdvertise NetIPv6  = nrIPv6 reach
    shouldAdvertise NetTorV3 = nrOnion reach
    shouldAdvertise NetI2P   = nrI2P reach
    shouldAdvertise NetCJDNS = False

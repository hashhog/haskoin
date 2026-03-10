{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

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
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Serialize
import Data.Word
import Data.Int (Int32, Int64)
import Data.Bits ((.&.), (.|.))
import Control.Monad (replicateM, forM_)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256)

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

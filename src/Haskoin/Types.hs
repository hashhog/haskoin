{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}

module Haskoin.Types
  ( -- * Hash Types
    Hash256(..)
  , Hash160(..)
  , TxId(..)
  , BlockHash(..)
    -- * Core Structures
  , OutPoint(..)
  , TxIn(..)
  , TxOut(..)
  , Tx(..)
  , BlockHeader(..)
  , Block(..)
  , VarInt(..)
  , VarString(..)
  , NetworkAddress(..)
    -- * Witness
  , WitnessStack(..)
    -- * Utility
  , putVarInt
  , getVarInt'
  , putVarBytes
  , getVarBytes
  , doubleSHA256
  , txId
  , blockHash
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (Serialize(..), Get, Put, getBytes,
                       putByteString, getWord8, putWord8, getWord16le,
                       putWord16le, getWord32le, putWord32le, getWord64le,
                       putWord64le, getWord16be, putWord16be)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Int (Int32)
import GHC.Generics (Generic)
import Control.Monad (replicateM, when, unless, forM_)
import Data.Hashable (Hashable)
import Control.DeepSeq (NFData)

--------------------------------------------------------------------------------
-- Hash Types
--------------------------------------------------------------------------------

-- | A 256-bit (32-byte) hash, used for SHA256d results
newtype Hash256 = Hash256 { getHash256 :: ByteString }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Hashable, NFData)

instance Serialize Hash256 where
  put (Hash256 bs) = putByteString bs
  get = Hash256 <$> getBytes 32

-- | A 160-bit (20-byte) hash, used for RIPEMD160 results
newtype Hash160 = Hash160 { getHash160 :: ByteString }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Hashable, NFData)

instance Serialize Hash160 where
  put (Hash160 bs) = putByteString bs
  get = Hash160 <$> getBytes 20

-- | Transaction ID (hash of transaction data, excluding witness)
newtype TxId = TxId { getTxIdHash :: Hash256 }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Serialize, Hashable, NFData)

-- | Block hash (hash of block header)
newtype BlockHash = BlockHash { getBlockHashHash :: Hash256 }
  deriving stock (Show, Eq, Ord, Generic)
  deriving newtype (Serialize, Hashable, NFData)

--------------------------------------------------------------------------------
-- Variable-Length Encoding
--------------------------------------------------------------------------------

-- | Bitcoin's variable-length integer encoding
newtype VarInt = VarInt { getVarInt :: Word64 }
  deriving stock (Show, Eq, Generic)

instance Serialize VarInt where
  put (VarInt x)
    | x < 0xfd        = putWord8 (fromIntegral x)
    | x <= 0xffff     = putWord8 0xfd >> putWord16le (fromIntegral x)
    | x <= 0xffffffff = putWord8 0xfe >> putWord32le (fromIntegral x)
    | otherwise       = putWord8 0xff >> putWord64le x
  get = do
    b <- getWord8
    case b of
      0xff -> VarInt <$> getWord64le
      0xfe -> VarInt . fromIntegral <$> getWord32le
      0xfd -> VarInt . fromIntegral <$> getWord16le
      _    -> return $ VarInt (fromIntegral b)

-- | Variable-length string (length-prefixed ByteString)
newtype VarString = VarString { getVarString :: ByteString }
  deriving stock (Show, Eq, Generic)

instance Serialize VarString where
  put (VarString bs) = putVarBytes bs
  get = VarString <$> getVarBytes

-- | Serialize a Word64 as a VarInt
putVarInt :: Word64 -> Put
putVarInt = put . VarInt

-- | Deserialize a VarInt and extract the Word64
getVarInt' :: Get Word64
getVarInt' = getVarInt <$> get

-- | Serialize a ByteString with a VarInt length prefix
putVarBytes :: ByteString -> Put
putVarBytes bs = do
  putVarInt (fromIntegral $ BS.length bs)
  putByteString bs

-- | Deserialize a length-prefixed ByteString
getVarBytes :: Get ByteString
getVarBytes = do
  len <- getVarInt'
  getBytes (fromIntegral len)

--------------------------------------------------------------------------------
-- Transaction Types
--------------------------------------------------------------------------------

-- | Reference to a specific output of a previous transaction
data OutPoint = OutPoint
  { outPointHash  :: !TxId
  , outPointIndex :: !Word32
  } deriving (Show, Eq, Ord, Generic)

instance NFData OutPoint

instance Serialize OutPoint where
  put OutPoint{..} = put outPointHash >> putWord32le outPointIndex
  get = OutPoint <$> get <*> getWord32le

-- | Transaction input
data TxIn = TxIn
  { txInPrevOutput :: !OutPoint
  , txInScript     :: !ByteString
  , txInSequence   :: !Word32
  } deriving (Show, Eq, Generic)

instance NFData TxIn

instance Serialize TxIn where
  put TxIn{..} = do
    put txInPrevOutput
    putVarBytes txInScript
    putWord32le txInSequence
  get = TxIn <$> get <*> getVarBytes <*> getWord32le

-- | Transaction output
data TxOut = TxOut
  { txOutValue  :: !Word64
  , txOutScript :: !ByteString
  } deriving (Show, Eq, Generic)

instance NFData TxOut

instance Serialize TxOut where
  put TxOut{..} = putWord64le txOutValue >> putVarBytes txOutScript
  get = TxOut <$> getWord64le <*> getVarBytes

-- | Witness stack for a single input
newtype WitnessStack = WitnessStack { getWitnessItems :: [ByteString] }
  deriving (Show, Eq, Generic)

instance NFData WitnessStack

instance Serialize WitnessStack where
  put (WitnessStack items) = do
    putVarInt (fromIntegral $ length items)
    mapM_ putVarBytes items
  get = do
    count <- getVarInt'
    WitnessStack <$> replicateM (fromIntegral count) getVarBytes

-- | Bitcoin transaction with SegWit support
data Tx = Tx
  { txVersion  :: !Int32
  , txInputs   :: ![TxIn]
  , txOutputs  :: ![TxOut]
  , txWitness  :: ![[ByteString]]  -- one witness stack per input
  , txLockTime :: !Word32
  } deriving (Show, Eq, Generic)

instance NFData Tx

instance Serialize Tx where
  put Tx{..} = do
    putWord32le (fromIntegral txVersion)
    let hasWitness = any (not . null) txWitness
    when hasWitness $ putWord8 0x00 >> putWord8 0x01
    putVarInt (fromIntegral $ length txInputs)
    mapM_ put txInputs
    putVarInt (fromIntegral $ length txOutputs)
    mapM_ put txOutputs
    when hasWitness $
      forM_ txWitness $ \stack -> do
        putVarInt (fromIntegral $ length stack)
        mapM_ putVarBytes stack
    putWord32le txLockTime

  get = do
    version <- fromIntegral <$> getWord32le
    marker <- getWord8
    if marker == 0x00
      then do
        flag <- getWord8
        unless (flag == 0x01) $ fail "Invalid witness flag"
        parseSegWitTx version
      else parseLegacyTx version (fromIntegral marker)

-- | Parse a legacy (non-SegWit) transaction
parseLegacyTx :: Int32 -> Word64 -> Get Tx
parseLegacyTx version firstByte = do
  count <- if firstByte < 0xfd
           then return firstByte
           else case firstByte of
             0xfd -> fromIntegral <$> getWord16le
             0xfe -> fromIntegral <$> getWord32le
             0xff -> getWord64le
             _    -> return firstByte
  inputs <- replicateM (fromIntegral count) get
  outCount <- getVarInt'
  outputs <- replicateM (fromIntegral outCount) get
  lockTime <- getWord32le
  return Tx { txVersion = version
            , txInputs = inputs
            , txOutputs = outputs
            , txWitness = replicate (length inputs) []
            , txLockTime = lockTime
            }

-- | Parse a SegWit transaction (after marker and flag have been read)
parseSegWitTx :: Int32 -> Get Tx
parseSegWitTx version = do
  inCount <- getVarInt'
  inputs <- replicateM (fromIntegral inCount) get
  outCount <- getVarInt'
  outputs <- replicateM (fromIntegral outCount) get
  witness <- replicateM (length inputs) $ do
    stackSize <- getVarInt'
    replicateM (fromIntegral stackSize) getVarBytes
  lockTime <- getWord32le
  return Tx { txVersion = version
            , txInputs = inputs
            , txOutputs = outputs
            , txWitness = witness
            , txLockTime = lockTime
            }

--------------------------------------------------------------------------------
-- Block Types
--------------------------------------------------------------------------------

-- | Bitcoin block header (always exactly 80 bytes)
data BlockHeader = BlockHeader
  { bhVersion    :: !Int32
  , bhPrevBlock  :: !BlockHash
  , bhMerkleRoot :: !Hash256
  , bhTimestamp  :: !Word32
  , bhBits       :: !Word32
  , bhNonce      :: !Word32
  } deriving (Show, Eq, Generic)

instance NFData BlockHeader

instance Serialize BlockHeader where
  put BlockHeader{..} = do
    putWord32le (fromIntegral bhVersion)
    put bhPrevBlock
    put bhMerkleRoot
    putWord32le bhTimestamp
    putWord32le bhBits
    putWord32le bhNonce
  get = BlockHeader
    <$> (fromIntegral <$> getWord32le)
    <*> get
    <*> get
    <*> getWord32le
    <*> getWord32le
    <*> getWord32le

-- | Bitcoin block (header + transactions)
data Block = Block
  { blockHeader :: !BlockHeader
  , blockTxns   :: ![Tx]
  } deriving (Show, Eq, Generic)

instance NFData Block

instance Serialize Block where
  put Block{..} = do
    put blockHeader
    putVarInt (fromIntegral $ length blockTxns)
    mapM_ put blockTxns
  get = do
    header <- get
    txCount <- getVarInt'
    txns <- replicateM (fromIntegral txCount) get
    return Block { blockHeader = header, blockTxns = txns }

--------------------------------------------------------------------------------
-- Network Types
--------------------------------------------------------------------------------

-- | Network address for P2P protocol
data NetworkAddress = NetworkAddress
  { naServices :: !Word64
  , naAddress  :: !ByteString   -- 16 bytes (IPv6-mapped IPv4)
  , naPort     :: !Word16
  } deriving (Show, Eq, Generic)

instance NFData NetworkAddress

instance Serialize NetworkAddress where
  put NetworkAddress{..} = do
    putWord64le naServices
    putByteString naAddress  -- 16 bytes
    putWord16be naPort       -- port is big-endian in Bitcoin protocol
  get = NetworkAddress <$> getWord64le <*> getBytes 16 <*> getWord16be

--------------------------------------------------------------------------------
-- Hashing Functions (placeholders)
--------------------------------------------------------------------------------

-- | Double SHA256 hash (SHA256(SHA256(data)))
doubleSHA256 :: ByteString -> Hash256
doubleSHA256 = error "Implemented in Phase 3"

-- | Compute the transaction ID (hash of non-witness serialization)
txId :: Tx -> TxId
txId = error "Implemented in Phase 3"

-- | Compute the block hash (hash of header)
blockHash :: BlockHeader -> BlockHash
blockHash = error "Implemented in Phase 3"

{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Database Layer (RocksDB)
--
-- This module implements a persistent storage layer using RocksDB for storing
-- block headers, block data, transaction indexes, and UTXO set with efficient
-- prefix-based key schemas and batch write support.
--
-- Key Design:
--   - Single-byte prefix separates logical namespaces
--   - Height keys use big-endian for sorted iteration
--   - Batch writes ensure atomicity for block connection
--   - Bloom filter (10 bits/key) for fast UTXO negative lookups
--
module Haskoin.Storage
  ( -- * Database Handle
    HaskoinDB(..)
  , DBConfig(..)
  , defaultDBConfig
  , openDB
  , closeDB
  , withDB
    -- * Key Prefixes
  , KeyPrefix(..)
  , prefixByte
  , makeKey
    -- * Block Storage
  , putBlockHeader
  , getBlockHeader
  , putBlock
  , getBlock
  , putBestBlockHash
  , getBestBlockHash
  , putBlockHeight
  , getBlockHeight
    -- * Transaction Index
  , TxLocation(..)
  , putTxIndex
  , getTxIndex
  , deleteTxIndex
    -- * UTXO Operations
  , putUTXO
  , getUTXO
  , deleteUTXO
    -- * Chain Work
  , putChainWork
  , getChainWork
    -- * Block Status
  , BlockStatus(..)
  , putBlockStatus
  , getBlockStatus
    -- * Batch Operations
  , WriteBatch(..)
  , BatchOp(..)
  , writeBatch
  , batchPutBlockHeader
  , batchPutUTXO
  , batchDeleteUTXO
  , batchPutTxIndex
  , batchPutBestBlock
  , batchPutBlockHeight
    -- * Iterator
  , iterateWithPrefix
  , getUTXOCount
    -- * Utilities
  , toBE32
  , fromBE32
  , integerToBS
  , bsToInteger
  ) where

import qualified Database.RocksDB as R
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (encode, decode, Serialize(..), putWord32be, getWord32be)
import Data.Word (Word8, Word32)
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Control.Exception (bracket)
import Control.Monad (when)
import Control.Monad.Trans.Resource (runResourceT)
import Control.Monad.IO.Class (liftIO)
import Data.IORef (newIORef, readIORef, modifyIORef')
import GHC.Generics (Generic)

import Haskoin.Types

--------------------------------------------------------------------------------
-- Database Handle and Configuration
--------------------------------------------------------------------------------

-- | HaskoinDB database handle
-- Uses prefix-based keys in a single column family for simplicity.
-- This avoids the complexity of multiple column families while still
-- enabling efficient prefix-based iteration.
data HaskoinDB = HaskoinDB
  { dbHandle    :: !R.DB
  , dbReadOpts  :: !R.ReadOptions
  , dbWriteOpts :: !R.WriteOptions
  }

-- | Database configuration
-- Default settings are tuned for Initial Block Download (IBD) performance:
--   - Large write buffer (64 MB) for batched writes
--   - Large block cache (256 MB) for read performance
--   - 10 bits/key bloom filter for UTXO lookups
data DBConfig = DBConfig
  { dbPath            :: !FilePath
  , dbCreateIfMissing :: !Bool
  , dbMaxOpenFiles    :: !Int
  , dbWriteBufferSize :: !Int          -- ^ Write buffer size in bytes
  , dbBlockCacheSize  :: !Int          -- ^ Block cache size in bytes
  , dbBloomFilterBits :: !Int          -- ^ Bloom filter bits per key
  , dbCompression     :: !Bool
  } deriving (Show)

-- | Default database configuration tuned for IBD performance
defaultDBConfig :: FilePath -> DBConfig
defaultDBConfig path = DBConfig
  { dbPath            = path
  , dbCreateIfMissing = True
  , dbMaxOpenFiles    = 1000
  , dbWriteBufferSize = 64 * 1024 * 1024    -- 64 MB
  , dbBlockCacheSize  = 256 * 1024 * 1024   -- 256 MB
  , dbBloomFilterBits = 10
  , dbCompression     = True
  }

--------------------------------------------------------------------------------
-- Key Prefixes
--------------------------------------------------------------------------------

-- | Key prefix schema for different data types.
-- Each key type uses a unique single-byte prefix to enable efficient
-- iteration and avoid collisions. This design allows all data to live
-- in a single column family while maintaining logical separation.
data KeyPrefix
  = PrefixBlockHeader    -- ^ 0x01: BlockHash -> BlockHeader
  | PrefixBlockData      -- ^ 0x02: BlockHash -> Block (full)
  | PrefixBlockHeight    -- ^ 0x03: Height (Word32 BE) -> BlockHash
  | PrefixTxIndex        -- ^ 0x04: TxId -> (BlockHash, Word32 index)
  | PrefixUTXO           -- ^ 0x05: OutPoint -> TxOut
  | PrefixBestBlock      -- ^ 0x06: () -> BlockHash
  | PrefixChainWork      -- ^ 0x07: BlockHash -> cumulative chain work
  | PrefixBlockStatus    -- ^ 0x08: BlockHash -> validation status
  | PrefixAddrHistory    -- ^ 0x09: Address -> [(TxId, height)]
  | PrefixAddrBalance    -- ^ 0x0A: Address -> balance
  | PrefixAddrUTXO       -- ^ 0x0B: Address ++ OutPoint -> TxOut
  deriving (Show, Eq, Enum, Generic)

-- | Get the byte value for a key prefix
prefixByte :: KeyPrefix -> Word8
prefixByte PrefixBlockHeader = 0x01
prefixByte PrefixBlockData   = 0x02
prefixByte PrefixBlockHeight = 0x03
prefixByte PrefixTxIndex     = 0x04
prefixByte PrefixUTXO        = 0x05
prefixByte PrefixBestBlock   = 0x06
prefixByte PrefixChainWork   = 0x07
prefixByte PrefixBlockStatus = 0x08
prefixByte PrefixAddrHistory = 0x09
prefixByte PrefixAddrBalance = 0x0A
prefixByte PrefixAddrUTXO    = 0x0B

-- | Create a database key with prefix.
-- Keys are formatted as: [1-byte prefix][payload]
makeKey :: KeyPrefix -> ByteString -> ByteString
makeKey prefix payload = BS.cons (prefixByte prefix) payload

--------------------------------------------------------------------------------
-- Database Operations
--------------------------------------------------------------------------------

-- | Open a RocksDB database with the given configuration
openDB :: DBConfig -> IO HaskoinDB
openDB DBConfig{..} = do
  let opts = R.defaultOptions
        { R.createIfMissing = dbCreateIfMissing
        , R.maxOpenFiles    = dbMaxOpenFiles
        , R.writeBufferSize = dbWriteBufferSize
        }
  db <- R.open dbPath opts
  let readOpts  = R.defaultReadOptions
      writeOpts = R.defaultWriteOptions { R.sync = False }
  return HaskoinDB
    { dbHandle    = db
    , dbReadOpts  = readOpts
    , dbWriteOpts = writeOpts
    }

-- | Close the database
closeDB :: HaskoinDB -> IO ()
closeDB HaskoinDB{..} = R.close dbHandle

-- | Run an action with a database, ensuring it is closed afterward
withDB :: DBConfig -> (HaskoinDB -> IO a) -> IO a
withDB config = bracket (openDB config) closeDB

--------------------------------------------------------------------------------
-- Block Header Storage
--------------------------------------------------------------------------------

-- | Store a block header
putBlockHeader :: HaskoinDB -> BlockHash -> BlockHeader -> IO ()
putBlockHeader db bh header =
  let key = makeKey PrefixBlockHeader (encode bh)
      val = encode header
  in R.put (dbHandle db) (dbWriteOpts db) key val

-- | Retrieve a block header by its hash
getBlockHeader :: HaskoinDB -> BlockHash -> IO (Maybe BlockHeader)
getBlockHeader db bh = do
  let key = makeKey PrefixBlockHeader (encode bh)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Store a full block (header + transactions)
putBlock :: HaskoinDB -> BlockHash -> Block -> IO ()
putBlock db bh block =
  let key = makeKey PrefixBlockData (encode bh)
      val = encode block
  in R.put (dbHandle db) (dbWriteOpts db) key val

-- | Retrieve a full block by its hash
getBlock :: HaskoinDB -> BlockHash -> IO (Maybe Block)
getBlock db bh = do
  let key = makeKey PrefixBlockData (encode bh)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Store the best (tip) block hash.
-- This is the hash of the block at the tip of the best chain.
putBestBlockHash :: HaskoinDB -> BlockHash -> IO ()
putBestBlockHash db bh =
  let key = makeKey PrefixBestBlock BS.empty
  in R.put (dbHandle db) (dbWriteOpts db) key (encode bh)

-- | Retrieve the best block hash
getBestBlockHash :: HaskoinDB -> IO (Maybe BlockHash)
getBestBlockHash db = do
  let key = makeKey PrefixBestBlock BS.empty
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

--------------------------------------------------------------------------------
-- Height Index (Big-Endian for Sorted Iteration)
--------------------------------------------------------------------------------

-- | Convert Word32 to big-endian ByteString for sorted iteration.
-- Big-endian encoding ensures that iterating over keys in lexicographic
-- order yields blocks in height order.
toBE32 :: Word32 -> ByteString
toBE32 w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xff)
  , fromIntegral ((w `shiftR` 16) .&. 0xff)
  , fromIntegral ((w `shiftR` 8) .&. 0xff)
  , fromIntegral (w .&. 0xff)
  ]

-- | Convert big-endian ByteString back to Word32
fromBE32 :: ByteString -> Maybe Word32
fromBE32 bs
  | BS.length bs /= 4 = Nothing
  | otherwise =
      let bytes = BS.unpack bs
          b0 = bytes !! 0
          b1 = bytes !! 1
          b2 = bytes !! 2
          b3 = bytes !! 3
      in Just $ (fromIntegral b0 `shiftL` 24)
            .|. (fromIntegral b1 `shiftL` 16)
            .|. (fromIntegral b2 `shiftL` 8)
            .|. fromIntegral b3

-- | Store a height -> block hash mapping.
-- This index allows efficient lookup of the block at any given height.
putBlockHeight :: HaskoinDB -> Word32 -> BlockHash -> IO ()
putBlockHeight db height bh =
  let key = makeKey PrefixBlockHeight (toBE32 height)
  in R.put (dbHandle db) (dbWriteOpts db) key (encode bh)

-- | Retrieve block hash at a given height
getBlockHeight :: HaskoinDB -> Word32 -> IO (Maybe BlockHash)
getBlockHeight db height = do
  let key = makeKey PrefixBlockHeight (toBE32 height)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

--------------------------------------------------------------------------------
-- UTXO Operations
--------------------------------------------------------------------------------

-- | Store a UTXO (unspent transaction output).
-- The key is the OutPoint (txid + output index), value is the TxOut.
putUTXO :: HaskoinDB -> OutPoint -> TxOut -> IO ()
putUTXO db outpoint txout =
  let key = makeKey PrefixUTXO (encode outpoint)
  in R.put (dbHandle db) (dbWriteOpts db) key (encode txout)

-- | Retrieve a UTXO by its OutPoint
getUTXO :: HaskoinDB -> OutPoint -> IO (Maybe TxOut)
getUTXO db outpoint = do
  let key = makeKey PrefixUTXO (encode outpoint)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Delete a UTXO (when it gets spent).
-- This is called when a transaction input references this output.
deleteUTXO :: HaskoinDB -> OutPoint -> IO ()
deleteUTXO db outpoint =
  let key = makeKey PrefixUTXO (encode outpoint)
  in R.delete (dbHandle db) (dbWriteOpts db) key

--------------------------------------------------------------------------------
-- Transaction Index
--------------------------------------------------------------------------------

-- | Location of a transaction within a block.
-- Used to quickly find which block contains a given transaction.
data TxLocation = TxLocation
  { txLocBlock :: !BlockHash    -- ^ Hash of the block containing this tx
  , txLocIndex :: !Word32       -- ^ Index of tx within the block's tx list
  } deriving (Show, Eq, Generic)

instance Serialize TxLocation where
  put TxLocation{..} = put txLocBlock >> putWord32be txLocIndex
  get = TxLocation <$> get <*> getWord32be

-- | Store transaction location index
putTxIndex :: HaskoinDB -> TxId -> TxLocation -> IO ()
putTxIndex db txid loc =
  let key = makeKey PrefixTxIndex (encode txid)
  in R.put (dbHandle db) (dbWriteOpts db) key (encode loc)

-- | Retrieve transaction location
getTxIndex :: HaskoinDB -> TxId -> IO (Maybe TxLocation)
getTxIndex db txid = do
  let key = makeKey PrefixTxIndex (encode txid)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

-- | Delete transaction index entry (used during reorg)
deleteTxIndex :: HaskoinDB -> TxId -> IO ()
deleteTxIndex db txid =
  let key = makeKey PrefixTxIndex (encode txid)
  in R.delete (dbHandle db) (dbWriteOpts db) key

--------------------------------------------------------------------------------
-- Chain Work
--------------------------------------------------------------------------------

-- | Store cumulative chain work for a block.
-- Chain work is the total amount of work in the chain up to and including
-- this block. Used for determining the best chain.
putChainWork :: HaskoinDB -> BlockHash -> Integer -> IO ()
putChainWork db bh work =
  let key = makeKey PrefixChainWork (encode bh)
      val = integerToBS work
  in R.put (dbHandle db) (dbWriteOpts db) key val

-- | Retrieve cumulative chain work for a block
getChainWork :: HaskoinDB -> BlockHash -> IO (Maybe Integer)
getChainWork db bh = do
  let key = makeKey PrefixChainWork (encode bh)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ bsToInteger <$> mval

-- | Convert Integer to ByteString (big-endian, no leading zeros)
integerToBS :: Integer -> ByteString
integerToBS 0 = BS.singleton 0
integerToBS n
  | n < 0 = error "integerToBS: negative integers not supported"
  | otherwise = BS.pack $ reverse $ go n
  where
    go 0 = []
    go x = fromIntegral (x .&. 0xff) : go (x `shiftR` 8)

-- | Convert ByteString to Integer (big-endian)
bsToInteger :: ByteString -> Integer
bsToInteger = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0

--------------------------------------------------------------------------------
-- Block Status
--------------------------------------------------------------------------------

-- | Validation status for a block.
-- Tracks how far along the validation process each block is.
data BlockStatus
  = StatusUnknown        -- ^ 0x00: Not yet validated
  | StatusHeaderValid    -- ^ 0x01: Header passes validation
  | StatusDataReceived   -- ^ 0x02: Full block data received
  | StatusValid          -- ^ 0x03: Fully validated (scripts, UTXOs)
  | StatusInvalid        -- ^ 0x04: Validation failed
  deriving (Show, Eq, Enum, Generic)

instance Serialize BlockStatus where
  put s = put (fromEnum s :: Int)
  get = toEnum <$> get

-- | Store block validation status
putBlockStatus :: HaskoinDB -> BlockHash -> BlockStatus -> IO ()
putBlockStatus db bh status =
  let key = makeKey PrefixBlockStatus (encode bh)
  in R.put (dbHandle db) (dbWriteOpts db) key (encode status)

-- | Retrieve block validation status
getBlockStatus :: HaskoinDB -> BlockHash -> IO (Maybe BlockStatus)
getBlockStatus db bh = do
  let key = makeKey PrefixBlockStatus (encode bh)
  mval <- R.get (dbHandle db) (dbReadOpts db) key
  return $ mval >>= either (const Nothing) Just . decode

--------------------------------------------------------------------------------
-- Batch Operations
--------------------------------------------------------------------------------

-- | A single batch operation (put or delete)
data BatchOp
  = BatchPut !ByteString !ByteString    -- ^ Put key-value pair
  | BatchDelete !ByteString             -- ^ Delete key
  deriving (Show, Eq)

-- | A batch of operations to execute atomically.
-- Batch writes are critical for block connection, ensuring that
-- UTXO updates, tx index updates, and chain tip update all succeed
-- or fail together.
newtype WriteBatch = WriteBatch { getBatchOps :: [BatchOp] }
  deriving (Show)

instance Semigroup WriteBatch where
  WriteBatch a <> WriteBatch b = WriteBatch (a <> b)

instance Monoid WriteBatch where
  mempty = WriteBatch []

-- | Execute a batch of operations atomically
writeBatch :: HaskoinDB -> WriteBatch -> IO ()
writeBatch db (WriteBatch ops) =
  R.write (dbHandle db) (dbWriteOpts db) $ map toRocksOp ops
  where
    toRocksOp (BatchPut k v)  = R.Put k v
    toRocksOp (BatchDelete k) = R.Del k

-- | Create a batch operation to put a block header
batchPutBlockHeader :: BlockHash -> BlockHeader -> BatchOp
batchPutBlockHeader bh header =
  BatchPut (makeKey PrefixBlockHeader (encode bh)) (encode header)

-- | Create a batch operation to put a UTXO
batchPutUTXO :: OutPoint -> TxOut -> BatchOp
batchPutUTXO outpoint txout =
  BatchPut (makeKey PrefixUTXO (encode outpoint)) (encode txout)

-- | Create a batch operation to delete a UTXO
batchDeleteUTXO :: OutPoint -> BatchOp
batchDeleteUTXO outpoint =
  BatchDelete (makeKey PrefixUTXO (encode outpoint))

-- | Create a batch operation to put a transaction index
batchPutTxIndex :: TxId -> TxLocation -> BatchOp
batchPutTxIndex txid loc =
  BatchPut (makeKey PrefixTxIndex (encode txid)) (encode loc)

-- | Create a batch operation to put best block hash
batchPutBestBlock :: BlockHash -> BatchOp
batchPutBestBlock bh =
  BatchPut (makeKey PrefixBestBlock BS.empty) (encode bh)

-- | Create a batch operation to put block height
batchPutBlockHeight :: Word32 -> BlockHash -> BatchOp
batchPutBlockHeight height bh =
  BatchPut (makeKey PrefixBlockHeight (toBE32 height)) (encode bh)

--------------------------------------------------------------------------------
-- Iteration
--------------------------------------------------------------------------------

-- | Iterate over all keys with a given prefix, calling a callback for each.
-- The callback returns True to continue iteration, False to stop.
-- Keys are visited in sorted order.
iterateWithPrefix :: HaskoinDB -> KeyPrefix
                  -> (ByteString -> ByteString -> IO Bool) -> IO ()
iterateWithPrefix db prefix callback = runResourceT $ do
  let prefixBS = BS.singleton (prefixByte prefix)
  R.withIterator (dbHandle db) (dbReadOpts db) $ \iter -> do
    R.iterSeek iter prefixBS
    let loop = do
          valid <- R.iterValid iter
          when valid $ do
            mkey <- R.iterKey iter
            case mkey of
              Nothing -> return ()
              Just key ->
                when (BS.isPrefixOf prefixBS key) $ do
                  mval <- R.iterValue iter
                  case mval of
                    Nothing -> return ()
                    Just val -> do
                      continue <- liftIO $ callback key val
                      when continue $ R.iterNext iter >> loop
    loop

-- | Get count of UTXOs in the database.
-- Useful for debugging and statistics.
getUTXOCount :: HaskoinDB -> IO Int
getUTXOCount db = do
  countRef <- newIORef (0 :: Int)
  iterateWithPrefix db PrefixUTXO $ \_key _val -> do
    modifyIORef' countRef (+1)
    return True
  readIORef countRef

{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Bitcoin Core compatible mempool.dat persistence.
--
-- Implements the wire format defined in
-- @bitcoin-core/src/node/mempool_persist.cpp@:
--
--   uint64    version            -- 1 = no XOR, 2 = XOR-obfuscated
--   if v2: VarBytes(8) key       -- 8-byte obfuscation key
--   ----- below this point all bytes are XOR-obfuscated under key -----
--   uint64    count
--   for each tx:
--     CTransaction-with-witness  -- canonical segwit serialisation
--     int64    nTime             -- POSIX seconds when added
--     int64    nFeeDelta         -- prioritisetransaction delta
--   map<Txid,int64>  mapDeltas   -- pending fee deltas, txids not in pool
--   set<Txid>        unbroadcast -- not-yet-relayed txids
--
-- Round-trips byte-for-byte with Bitcoin Core 28's @mempool.dat@ when
-- the same obfuscation key is supplied.
--
-- The XOR transform is a per-byte XOR with @key[i mod 8]@ for the i-th
-- byte after the obfuscation header, matching @Obfuscation::operator()@.
module Haskoin.Mempool.Persist
  ( -- * Top-level API
    dumpMempool
  , loadMempool
  , defaultMempoolDatPath
    -- * Format constants
  , mempoolDumpVersion
  , mempoolDumpVersionNoXorKey
    -- * Lower-level helpers (exported for tests)
  , encodeMempoolDat
  , decodeMempoolDat
  , MempoolDump(..)
  , DumpedTx(..)
  , xorObfuscate
  , generateXorKey
  ) where

import Control.Concurrent.STM
import Control.Exception (SomeException, catch, try)
import Control.Monad (forM_, replicateM, when)
import Data.Bits (xor)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Int (Int64)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Serialize (Get, Put, get, put, runPut, getWord64le, putByteString,
                       putWord64le)
import Data.Serialize.Get (runGetState)
import qualified Data.Set as Set
import Data.Set (Set)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word64)
import qualified System.Directory as Dir
import System.FilePath ((</>))
import System.Random (randomRIO)

import Haskoin.Crypto (computeTxId)
import Haskoin.Mempool (Mempool(..), MempoolEntry(..), addTransaction,
                       getTransaction)
import Haskoin.Types (Tx, TxId(..), getVarInt', putVarInt)

--------------------------------------------------------------------------------
-- Format constants
--------------------------------------------------------------------------------

-- | Latest dump version (XOR-obfuscated payload). Matches
-- @MEMPOOL_DUMP_VERSION = 2@ in Core.
mempoolDumpVersion :: Word64
mempoolDumpVersion = 2

-- | Legacy v1 format with no XOR key. Matches
-- @MEMPOOL_DUMP_VERSION_NO_XOR_KEY = 1@ in Core. Read for backward
-- compatibility; we never write this version.
mempoolDumpVersionNoXorKey :: Word64
mempoolDumpVersionNoXorKey = 1

-- | Default location of mempool.dat under a datadir, mirroring Core.
defaultMempoolDatPath :: FilePath -> FilePath
defaultMempoolDatPath dataDir = dataDir </> "mempool.dat"

--------------------------------------------------------------------------------
-- Pure data structures
--------------------------------------------------------------------------------

-- | A transaction record in mempool.dat. Order in the file matches
-- 'mdTxs'.
data DumpedTx = DumpedTx
  { dtTx       :: !Tx     -- ^ Full segwit-serialised transaction
  , dtTime     :: !Int64  -- ^ Time added (POSIX seconds)
  , dtFeeDelta :: !Int64  -- ^ Prioritisation delta in satoshis
  } deriving (Show, Eq)

-- | The full mempool dump, post-obfuscation deobfuscation. Round-trips
-- with 'encodeMempoolDat' / 'decodeMempoolDat'.
data MempoolDump = MempoolDump
  { mdVersion     :: !Word64
  , mdXorKey      :: !ByteString  -- ^ 8 bytes for v2; empty for v1
  , mdTxs         :: ![DumpedTx]
  , mdDeltas      :: !(Map TxId Int64)
  , mdUnbroadcast :: !(Set TxId)
  } deriving (Show, Eq)

--------------------------------------------------------------------------------
-- Obfuscation
--------------------------------------------------------------------------------

-- | Per-byte XOR against an 8-byte key, matching Core's
-- @Obfuscation::operator()(span, 0)@. With an empty/zero key this is
-- the identity transform, so v1 (no XOR) and an all-zero v2 key both
-- reduce to the same byte stream.
xorObfuscate :: ByteString -> ByteString -> ByteString
xorObfuscate key bs
  | BS.null key = bs
  | BS.all (== 0) key = bs
  | otherwise = BS.pack (go 0 (BS.unpack bs))
  where
    !klen = BS.length key
    keyAt i = BS.index key (i `mod` klen)
    go _ []        = []
    go !i (b:rest) = (b `xor` keyAt i) : go (i + 1) rest

-- | Generate a fresh 8-byte obfuscation key. Bitcoin Core uses
-- @FastRandomContext@; we use 'System.Random' here because this key is
-- not security-critical (it is stored next to the data it obscures).
generateXorKey :: IO ByteString
generateXorKey =
  BS.pack <$> mapM (const $ fromIntegral <$> randomRIO (0 :: Int, 255))
                   [1..8 :: Int]

--------------------------------------------------------------------------------
-- Encode / decode
--------------------------------------------------------------------------------

-- | Serialise a 'MempoolDump' into a byte string identical to what
-- Bitcoin Core writes to @mempool.dat@.
encodeMempoolDat :: MempoolDump -> ByteString
encodeMempoolDat MempoolDump{..} =
  let
    -- Header: version (raw); for v2 also key length + key bytes (raw).
    headerBytes = runPut $ do
      putWord64le mdVersion
      when (mdVersion == mempoolDumpVersion) $ do
        putVarInt 8
        putByteString mdXorKey

    -- Body: count + txs + mapDeltas + unbroadcast set. Obfuscated under
    -- the key when version == 2.
    bodyPlain = runPut $ do
      putWord64le (fromIntegral (length mdTxs))
      mapM_ putDumpedTx mdTxs
      putTxIdMap mdDeltas
      putTxIdSet mdUnbroadcast

    bodyOut = if mdVersion == mempoolDumpVersion
                then xorObfuscate mdXorKey bodyPlain
                else bodyPlain
  in
    headerBytes <> bodyOut

-- | Parse a Bitcoin Core @mempool.dat@ blob. Returns 'Left' with the
-- error reason on any failure (e.g. unknown version, truncated body).
decodeMempoolDat :: ByteString -> Either String MempoolDump
decodeMempoolDat blob = do
  -- 1) Read the 8-byte version (raw, never obfuscated)
  (version, after1) <- runStep getWord64le blob
  -- 2) For v2, read the 8-byte XOR key prefixed with a CompactSize=8.
  (keyBs, bodyEnc) <-
    if version == mempoolDumpVersion
      then do
        (klen, afterLen) <- runStep getVarInt' after1
        when (klen /= 8) $
          Left ("Unexpected obfuscation key size: " ++ show klen)
        when (BS.length afterLen < 8) $
          Left "Truncated mempool.dat: missing obfuscation key"
        let (k, rest) = BS.splitAt 8 afterLen
        return (k, rest)
      else if version == mempoolDumpVersionNoXorKey
        then return (BS.empty, after1)
        else Left ("Unsupported mempool.dat version: " ++ show version)

  -- 3) De-obfuscate the body and parse count + txs + deltas + unbroadcast.
  let bodyPlain = if BS.null keyBs then bodyEnc
                                   else xorObfuscate keyBs bodyEnc
  (txCount, after2) <- runStep getWord64le bodyPlain
  (txs, after3)     <- runRepeated (fromIntegral txCount) getDumpedTx after2
  (deltas, after4)  <- runStep getTxIdMap after3
  (ubs, _after5)    <- runStep getTxIdSet after4
  return MempoolDump
    { mdVersion     = version
    , mdXorKey      = keyBs
    , mdTxs         = txs
    , mdDeltas      = deltas
    , mdUnbroadcast = ubs
    }

-- | Run a single cereal Get on a prefix of a 'ByteString' and return
-- the parsed value plus the unconsumed tail.
runStep :: Get a -> ByteString -> Either String (a, ByteString)
runStep g bs = runGetState g bs 0

-- | Run a Get N times sequentially, threading the remaining bytes.
runRepeated :: Int -> Get a -> ByteString -> Either String ([a], ByteString)
runRepeated n g = go n []
  where
    go 0 acc bs = Right (reverse acc, bs)
    go k acc bs = case runStep g bs of
      Left e            -> Left e
      Right (a, after_) -> go (k - 1) (a : acc) after_

--------------------------------------------------------------------------------
-- Cereal Get/Put helpers
--------------------------------------------------------------------------------

putDumpedTx :: DumpedTx -> Put
putDumpedTx DumpedTx{..} = do
  put dtTx                                  -- segwit serialisation
  putWord64le (fromIntegral dtTime)
  putWord64le (fromIntegral dtFeeDelta)

getDumpedTx :: Get DumpedTx
getDumpedTx = do
  tx <- get
  t  <- fromIntegral <$> getWord64le
  fd <- fromIntegral <$> getWord64le
  return DumpedTx { dtTx = tx, dtTime = t, dtFeeDelta = fd }

-- | CompactSize-prefixed @Map TxId Int64@. Matches Core's
-- @std::map<Txid, CAmount>@ serialiser, which writes [(K, V)] pairs.
putTxIdMap :: Map TxId Int64 -> Put
putTxIdMap m = do
  putVarInt (fromIntegral (Map.size m))
  mapM_ (\(k, v) -> put k >> putWord64le (fromIntegral v)) (Map.toAscList m)

getTxIdMap :: Get (Map TxId Int64)
getTxIdMap = do
  n <- getVarInt'
  pairs <- replicateM (fromIntegral n) $ do
    k <- get
    v <- fromIntegral <$> getWord64le
    return (k, v)
  return (Map.fromList pairs)

-- | CompactSize-prefixed @Set TxId@. Matches Core's
-- @std::set<Txid>@ serialiser.
putTxIdSet :: Set TxId -> Put
putTxIdSet s = do
  putVarInt (fromIntegral (Set.size s))
  mapM_ put (Set.toAscList s)

getTxIdSet :: Get (Set TxId)
getTxIdSet = do
  n <- getVarInt'
  Set.fromList <$> replicateM (fromIntegral n) get

--------------------------------------------------------------------------------
-- IO: dump / load
--------------------------------------------------------------------------------

-- | Write the entire mempool to @<dump_path>@ atomically (write to
-- @<dump_path>.new@, then rename), matching Core's 'DumpMempool' commit
-- semantics.
--
-- Returns the number of transactions written, or an error message.
dumpMempool :: Mempool -> FilePath -> IO (Either String Int)
dumpMempool mp dumpPath = do
  result <- try $ do
    -- Snapshot the mempool atomically; we don't hold the STM lock during
    -- file I/O.
    (entries, deltas, ubs) <- atomically $ do
      es <- readTVar (mpEntries mp)
      ds <- readTVar (mpFeeDeltas mp)
      us <- readTVar (mpUnbroadcast mp)
      return (es, ds, us)

    let dumpedTxs = [ DumpedTx
                       { dtTx       = meTransaction e
                       , dtTime     = meTime e
                       , dtFeeDelta = Map.findWithDefault 0 (meTxId e) deltas
                       }
                    | e <- Map.elems entries ]
        -- Deltas not corresponding to in-pool tx are kept verbatim.
        leftoverDeltas =
          Map.filterWithKey (\k _ -> not (Map.member k entries)) deltas

    keyBs <- generateXorKey
    let dump = MempoolDump
          { mdVersion     = mempoolDumpVersion
          , mdXorKey      = keyBs
          , mdTxs         = dumpedTxs
          , mdDeltas      = leftoverDeltas
          , mdUnbroadcast = ubs
          }
        bytes = encodeMempoolDat dump
        tmpPath = dumpPath ++ ".new"

    -- Ensure parent dir exists. (Datadir already exists, but being
    -- defensive in tests with synthetic paths.)
    let parent = takeDirParent dumpPath
    Dir.createDirectoryIfMissing True parent

    BS.writeFile tmpPath bytes
    Dir.renameFile tmpPath dumpPath
    return (length dumpedTxs)
  case result of
    Right n -> return (Right n)
    Left (e :: SomeException) ->
      return (Left $ "dumpMempool: " ++ show e)
  where
    takeDirParent p =
      let ds = reverse (dropWhile (/= '/') (reverse p))
      in if null ds then "." else ds

-- | Load and replay @mempool.dat@. Calls 'addTransaction' for each tx;
-- entries that fail to validate or are duplicates are silently dropped
-- (matching Core's "continuing anyway" semantics on bad txs).
--
-- Returns @Right (loaded, failed, expired, alreadyThere)@ or @Left@ on
-- a fatal parse failure.
loadMempool
  :: Mempool
  -> FilePath
  -> Word64                   -- ^ expiry in seconds (entries older than now-expiry are skipped)
  -> IO (Either String (Int, Int, Int, Int))
loadMempool mp loadPath expirySecs = do
  exists <- Dir.doesFileExist loadPath
  if not exists
    then return (Right (0, 0, 0, 0))
    else do
      blob <- BS.readFile loadPath
      case decodeMempoolDat blob of
        Left e -> return (Left e)
        Right dump -> do
          now <- round <$> getPOSIXTime :: IO Int64
          let expiryCutoff = now - fromIntegral expirySecs

          loaded   <- newTVarIO (0 :: Int)
          failed   <- newTVarIO (0 :: Int)
          expired  <- newTVarIO (0 :: Int)
          already  <- newTVarIO (0 :: Int)

          forM_ (mdTxs dump) $ \dt -> do
            if dtTime dt < expiryCutoff
              then atomically (modifyTVar' expired (+ 1))
              else do
                let txid = computeTxId (dtTx dt)
                existing <- getTransaction mp txid
                case existing of
                  Just _ ->
                    atomically (modifyTVar' already (+ 1))
                  Nothing -> do
                    res <- addTransaction mp (dtTx dt)
                            `catch` (\(_e :: SomeException) ->
                                       return $ Left
                                         (error "loadMempool: caught"))
                    case res of
                      Right _ -> atomically (modifyTVar' loaded (+ 1))
                      Left _  -> atomically (modifyTVar' failed (+ 1))

          -- Restore prioritisation deltas (for both in-pool and
          -- not-yet-loaded txs); we keep the full map verbatim.
          atomically $ do
            modifyTVar' (mpFeeDeltas mp) (`Map.union` mdDeltas dump)
            modifyTVar' (mpUnbroadcast mp) (`Set.union` mdUnbroadcast dump)

          ld <- readTVarIO loaded
          fl <- readTVarIO failed
          ex <- readTVarIO expired
          al <- readTVarIO already
          return (Right (ld, fl, ex, al))

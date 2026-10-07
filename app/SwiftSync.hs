{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | @haskoin swiftsync-pass@ -- a fully-validating SwiftSync batch pass.
--
-- Hashhog meta-repo design: @receipts/swiftsync-design-2026-10-05.md@
-- (§1.2 protocol P, §2 soundness, §2.4 controls, §3 "How nodes consume it"),
-- ratified as TRUST-ANCHOR "SwiftSync-verified" (2026-10-05). Draft BIP 457.
-- Structure copied from the reference pass, rustoshi @swiftsync-pass@
-- (@receipts/swiftsync-step2-rustoshi-2026-10-07.md@); the hash construction,
-- the pack readers, the result.json contract and the control names are the
-- same, so @tools/swiftsync-close.py@ / @swiftsync-combine.py@ /
-- @swiftsync-refval.py@ accept this pass unchanged.
--
-- The pass validates a height range of the chain WITHOUT a UTXO set. Spent
-- coins come from Bitcoin Core's undo data (@undo.pack@, untrusted); which
-- outputs survive comes from a hints file (untrusted). Both are bound to this
-- node's own parse of the chain by a salted 256-bit additive hash aggregate:
--
-- >  Agg_in  = Σ H(salt ‖ code ‖ amount ‖ script ‖ prevout)   over every input
-- >  Agg_out = Σ H(salt ‖ code ‖ amount ‖ script ‖ outpoint)  over every created,
-- >            spendable, NOT-hinted output
--
-- = Path identity -- the production connect arm, with supplied coins
--
-- Every block goes through EXACTLY the calls haskoin's live P2P connect arm
-- makes for a block (@app/Main.hs@, @syncMessageHandler@ @MBlock@):
--
-- 1. 'addHeaderAt' (the arm calls @addHeader net hc hdr False@ = @addHeaderAt
--    … False Nothing@): PoW, time-too-old, BIP94, time-too-new, bad-diffbits,
--    checkpoints -- here run once per header in phase 0 over the header chain
--    read from the blk files, with @now@ fixed at pass start;
-- 2. @validateBlockGuarded ctx (validateFullBlockIO db net cs getMtpBg
--    skipScripts block spent)@ with
--    @cs = ChainState (height - 1) parentHash (ceChainWork entry) prevMTP
--    (consensusFlagsAtHeight net height)@,
--    @prevMTP = medianTimePast blockEntries parentHash@,
--    @getMtpBg = getMtpAtHeightFromEntries blockEntries byHeightBg@ --
--    built exactly as the arm builds them -- and @skipScripts = False@
--    (the literal; 'shouldSkipScripts' / assumevalid is never consulted).
--
-- The only differences from production are where the inputs come from:
-- @spent@ is this block's undo coins (instead of 'buildSpentUtxoMapCached'
-- over the chainstate), the header chain is the blk-file chain, and @db@ is
-- an EMPTY scratch RocksDB holding only the BIP34 anchor row (height 227931
-- -> its hash from the header chain), so 'checkBIP30' runs its production
-- gates and its UTXO probe is vacuous -- replaced, as the design requires, by
-- the driver's coinbase-txid cache.
--
-- = The three mandatory soundness extensions (TRUST-ANCHOR ruling 1)
--
-- * P-ORD: a supplied coin's height must be < h, or == h with the prevout
--   created by an EARLIER tx of this block with identical data.
-- * completeness: every height of the range processed exactly once.
-- * BIP30: the coinbase outputs of 91722 and 91812 are unspendable, and
--   coinbase txids below BIP34 (227,931) are unique (91842/91880 exempt);
--   the txids are written out for the cross-range check in swiftsync-combine.
module SwiftSync (runSwiftSyncPass) where

import Control.Concurrent (forkIO, killThread, threadDelay, getNumCapabilities, setNumCapabilities)
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Exception (SomeException, try, evaluate, bracket)
import Control.Monad
import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Unsafe as BSU
import qualified Data.ByteString.Short as SBS
import qualified Data.ByteString.Base16 as B16
import Data.ByteString (ByteString)
import Data.IORef
import Data.Int (Int64)
import Data.List (sort, sortOn, nub, isPrefixOf)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Serialize (Get, runGetState, runGetLazyState, get)
import qualified Data.Vector as V
import qualified Data.Vector.Unboxed as VU
import qualified Data.Vector.Unboxed.Mutable as VUM
import qualified Data.Vector.Algorithms.Intro as Intro
import Data.Word (Word8, Word32, Word64)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import System.Directory (createDirectoryIfMissing, listDirectory, removeFile, doesDirectoryExist, removeDirectoryRecursive)
import System.Exit (ExitCode(..))
import System.FilePath ((</>))
import System.IO
import System.Posix.IO (openFd, closeFd, defaultFileFlags, OpenMode(ReadOnly))
import System.Posix.Types (Fd(..))
import Foreign.C.Types (CInt(..), CSize(..), CLong(..))
import Foreign.Ptr (Ptr)
import Text.Printf (printf)
import Text.Read (readMaybe)
import qualified Data.Aeson as A
import qualified Data.Aeson.Key as AK
import qualified Data.Aeson.KeyMap as AKM
import qualified Data.Text as T

import Haskoin.Types
import Haskoin.Crypto (sha256, computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( Network(..), mainnet, regtest, ChainState(..), ChainEntry(..), HeaderChain(..)
  , BlockStatus(..), initHeaderChain, addHeaderAt, medianTimePast
  , getMtpAtHeightFromEntries, consensusFlagsAtHeight, validateFullBlockIO
  , validateBlockGuarded, readScriptChecksTotal, setConfiguredPar
  , startGlobalScriptCheckQueue, initGlobalSigCache )
import Haskoin.Storage
  ( HaskoinDB, openDB, closeDB, defaultDBConfig, putBlockHeight, Coin(..)
  , TxInUndo(..), TxUndo(..), BlockUndo(..), isUnspendable, getCoreCoin
  , SnapshotMetadata(..) )

--------------------------------------------------------------------------------
-- arguments
--------------------------------------------------------------------------------

data Args = Args
  { aNetwork   :: !String
  , aPack      :: !FilePath
  , aBlocks    :: !(Maybe FilePath)
  , aHints     :: !(Maybe FilePath)
  , aFrom      :: !Word32
  , aTo        :: !Word32
  , aOut       :: !FilePath
  , aThreads   :: !Int
  , aSaltFile  :: !(Maybe FilePath)
  , aStartSnap :: !(Maybe FilePath)
  , aControl   :: !String
  , aBlockFile :: ![String]
  , aMaxErrors :: !Int
  , aPar       :: !Int
  }

usage :: String
usage = unlines
  [ "usage: haskoin swiftsync-pass --pack DIR --from A --to B --out DIR"
  , "         [--network mainnet|regtest] [--blocks DIR] [--hints DIR] [--threads N]"
  , "         [--salt-file F] [--start-snapshot F] [--control C,...] [--block-file H=PATH]"
  , "         [--max-errors N] [--par N]"
  , "  --threads N   block workers (default 8); each drains its block's script"
  , "                checks on the serial branch of dispatchScriptChecks"
  , "  --par N       instead start the production persistent ScriptCheckQueue"
  , "                (--par semantics) and dispatch every block's checks to it"
  , "controls: field:<amount|script|height|coinbase|vout>[/<p2pkh|p2wpkh|p2pk>]@H,"
  , "  hint-drop@H, hint-add@H, drop-block@H, dup-block@H, forge-order@H,"
  , "  drop-coin@H, no-pord, bip30-spendable, bip30-noexempt" ]

parseArgs :: [String] -> Either String Args
parseArgs = go (Args "mainnet" "" Nothing Nothing 0 0 "" 8 Nothing Nothing "" [] 200 0) (False, False, False, False)
  where
    go a (p, f, t, o) [] =
      if p && f && t && o then Right a else Left "missing one of --pack --from --to --out"
    go a s@(p, f, t, o) (k:v:rest) = case k of
      "--network"        -> go a { aNetwork = v } s rest
      "--pack"           -> go a { aPack = v } (True, f, t, o) rest
      "--blocks"         -> go a { aBlocks = Just v } s rest
      "--hints"          -> go a { aHints = Just v } s rest
      "--from"           -> num v >>= \n -> go a { aFrom = n } (p, True, t, o) rest
      "--to"             -> num v >>= \n -> go a { aTo = n } (p, f, True, o) rest
      "--out"            -> go a { aOut = v } (p, f, t, True) rest
      "--threads"        -> num v >>= \n -> go a { aThreads = n } s rest
      "--salt-file"      -> go a { aSaltFile = Just v } s rest
      "--start-snapshot" -> go a { aStartSnap = Just v } s rest
      "--control"        -> go a { aControl = v } s rest
      "--block-file"     -> go a { aBlockFile = aBlockFile a ++ [v] } s rest
      "--max-errors"     -> num v >>= \n -> go a { aMaxErrors = n } s rest
      "--par"            -> num v >>= \n -> go a { aPar = n } s rest
      _                  -> Left ("unknown argument " ++ k)
    go _ _ [k] = Left ("argument " ++ k ++ " needs a value")
    num :: Read n => String -> Either String n
    num v = maybe (Left ("not a number: " ++ v)) Right (readMaybe v)

--------------------------------------------------------------------------------
-- controls (in-memory mutations; nothing on disk is modified)
--------------------------------------------------------------------------------

data Controls = Controls
  { cField          :: !(Maybe (String, Word32, String))
  , cHintDrop       :: !(Maybe Word32)
  , cHintAdd        :: !(Maybe Word32)
  , cDropBlock      :: !(Maybe Word32)
  , cDupBlock       :: !(Maybe Word32)
  , cForgeOrder     :: !(Maybe Word32)
  , cNoPord         :: !Bool
  , cBip30Spendable :: !Bool
  , cBip30NoExempt  :: !Bool
  , cDropCoin       :: !(Maybe Word32)
  }

noControls :: Controls
noControls = Controls Nothing Nothing Nothing Nothing Nothing Nothing False False False Nothing

parseControls :: String -> Either String Controls
parseControls s = foldM step noControls (filter (not . null) (splitOn ',' s))
  where
    step c part = do
      let (name, rest) = break (== '@') part
      arg <- case rest of
        ('@':n) -> maybe (Left (part ++ ": bad height")) (Right . Just) (readMaybe n)
        _       -> Right Nothing
      let need = maybe (Left (name ++ " needs @HEIGHT")) Right arg
      if "field:" `isPrefixOf` name
        then do
          let body = drop 6 name
              (f, cl) = case break (== '/') body of
                          (x, '/':y) -> (x, y)
                          (x, _)     -> (x, "p2pkh")
          unless (f `elem` ["amount", "script", "height", "coinbase", "vout"]) $ Left ("unknown field " ++ f)
          unless (cl `elem` ["p2pkh", "p2wpkh", "p2pk"]) $ Left ("unknown coin class " ++ cl)
          h <- need
          return c { cField = Just (f, h, cl) }
        else case name of
          "hint-drop"       -> need >>= \h -> return c { cHintDrop = Just h }
          "hint-add"        -> need >>= \h -> return c { cHintAdd = Just h }
          "drop-block"      -> need >>= \h -> return c { cDropBlock = Just h }
          "dup-block"       -> need >>= \h -> return c { cDupBlock = Just h }
          "forge-order"     -> need >>= \h -> return c { cForgeOrder = Just h }
          "drop-coin"       -> need >>= \h -> return c { cDropCoin = Just h }
          "no-pord"         -> return c { cNoPord = True }
          "bip30-spendable" -> return c { cBip30Spendable = True }
          "bip30-noexempt"  -> return c { cBip30NoExempt = True }
          _                 -> Left ("unknown control " ++ name)

splitOn :: Char -> String -> [String]
splitOn d str = case break (== d) str of
  (a, [])     -> [a]
  (a, _:rest) -> a : splitOn d rest

--------------------------------------------------------------------------------
-- little-endian helpers and positional reads
--------------------------------------------------------------------------------

u32At :: ByteString -> Int -> Word32
u32At b o = fromIntegral (BSU.unsafeIndex b o)
        .|. (fromIntegral (BSU.unsafeIndex b (o + 1)) `shiftL` 8)
        .|. (fromIntegral (BSU.unsafeIndex b (o + 2)) `shiftL` 16)
        .|. (fromIntegral (BSU.unsafeIndex b (o + 3)) `shiftL` 24)

u64At :: ByteString -> Int -> Word64
u64At b o = foldr (\i acc -> (acc `shiftL` 8) .|. fromIntegral (BSU.unsafeIndex b (o + i))) 0 [0 .. 7]

openRO :: FilePath -> IO Fd
openRO p = openFd p ReadOnly defaultFileFlags

foreign import ccall safe "pread" c_pread :: CInt -> Ptr Word8 -> CSize -> CLong -> IO CLong

-- | pread exactly @n@ bytes at @off@ (loops on short reads).
preadExact :: Fd -> Int -> Integer -> IO ByteString
preadExact (Fd fd) n off = BSI.create n $ \dst ->
  let go !got
        | got >= n = return ()
        | otherwise = do
            r <- c_pread fd (dst `plusPtr` got) (fromIntegral (n - got)) (fromIntegral (off + fromIntegral got))
            when (r <= 0) $ ioError (userError ("pread short/failed at " ++ show off ++ " (r=" ++ show r ++ ")"))
            go (got + fromIntegral r)
  in go 0

--------------------------------------------------------------------------------
-- pack readers
--------------------------------------------------------------------------------

data BEnt = BEnt { beHash :: !ByteString, beFile :: !Word32, bePos :: !Word32, beSize :: !Word32 }

data Pack = Pack
  { pkH        :: !Word32
  , pkXor      :: !ByteString
  , pkBase     :: !ByteString
  , pkEnts     :: !(V.Vector BEnt)
  , pkUndoFrom :: !Word32
  , pkUndoIdx  :: !(V.Vector (Word64, Word32, Word32))
  , pkUndoPath :: !FilePath
  }

openPack :: FilePath -> IO (Either String Pack)
openPack dir = do
  b <- BS.readFile (dir </> "blocks.idx")
  if BS.take 8 b /= "HHSSB1\0\0" then return (Left "bad blocks.idx magic") else do
    let h = u32At b 12
        xorK = BS.copy (BS.take 8 (BS.drop 16 b))
        base = BS.copy (BS.take 32 (BS.drop 24 b))
    if BS.length b /= 64 + 64 * (fromIntegral h + 1) then return (Left "blocks.idx size") else do
      let ents = V.generate (fromIntegral h + 1) $ \i ->
            let o = 64 + 64 * i
            in BEnt (BS.copy (BS.take 32 (BS.drop o b))) (u32At b (o + 32)) (u32At b (o + 36)) (u32At b (o + 40))
      u <- BS.readFile (dir </> "undo.idx")
      if BS.take 8 u /= "HHSSU1\0\0" then return (Left "bad undo.idx magic")
      else if u32At u 12 /= h then return (Left "undo.idx height != blocks.idx height")
      else do
        let ufrom = u32At u 16
            n = (BS.length u - 32) `div` 16
            uidx = V.generate n $ \i -> let o = 32 + 16 * i in (u64At u o, u32At u (o + 8), u32At u (o + 12))
        _ <- evaluate (V.length ents) >> evaluate (V.foldl' (\a e -> a `seq` beSize e `seq` a) () ents)
        _ <- evaluate (V.foldl' (\a (x, _, _) -> a `seq` x `seq` a) () uidx)
        return (Right (Pack h xorK base ents ufrom uidx (dir </> "undo.pack")))

undoEntry :: Pack -> Word32 -> Maybe (Word64, Word32, Word32)
undoEntry p h
  | h < pkUndoFrom p = Nothing
  | otherwise = pkUndoIdx p V.!? fromIntegral (h - pkUndoFrom p)

data Hints = Hints { hnH :: !Word32, hnStarts :: !(VU.Vector Word64), hnPath :: !FilePath }

openHints :: FilePath -> IO (Either String Hints)
openHints dir = do
  b <- BS.readFile (dir </> "hints.idx")
  if BS.take 8 b /= "HHSSH1\0\0" then return (Left "bad hints.idx magic") else do
    let h = u32At b 12
        starts = VU.generate (fromIntegral h + 2) (\i -> u64At b (32 + 8 * i))
    _ <- evaluate (VU.sum starts)
    return (Right (Hints h starts (dir </> "hints.pack")))

hintsCountRange :: Hints -> Word32 -> Word32 -> Word64
hintsCountRange hn a b0 =
  let b = min b0 (hnH hn)
  in if a > b then 0 else hnStarts hn VU.! (fromIntegral b + 1) - hnStarts hn VU.! fromIntegral a

hintsAt :: Hints -> Fd -> Word32 -> IO [(ByteString, Word32)]
hintsAt hn fd h
  | h > hnH hn = return []
  | otherwise = do
      let s = hnStarts hn VU.! fromIntegral h
          e = hnStarts hn VU.! (fromIntegral h + 1)
      if e == s then return [] else do
        raw <- preadExact fd (fromIntegral ((e - s) * 36)) (fromIntegral (s * 36))
        return [ (BS.copy (BS.take 32 r), u32At r 32)
               | i <- [0 .. fromIntegral (e - s) - 1], let r = BS.drop (36 * i) raw ]

-- | Per-worker blk-file reader (read-only; de-XORs with Core's xor.dat key).
data BlkReader = BlkReader { brDir :: !FilePath, brXor :: !ByteString, brFiles :: !(IORef (Map.Map Word32 Fd)) }

newBlkReader :: FilePath -> ByteString -> IO BlkReader
newBlkReader d x = BlkReader d x <$> newIORef Map.empty

closeBlkReader :: BlkReader -> IO ()
closeBlkReader br = readIORef (brFiles br) >>= mapM_ closeFd . Map.elems

blkRead :: BlkReader -> Word32 -> Word32 -> Int -> IO ByteString
blkRead br file pos len = do
  m <- readIORef (brFiles br)
  fd <- case Map.lookup file m of
    Just fd -> return fd
    Nothing -> do
      when (Map.size m >= 64) $ do
        mapM_ closeFd (Map.elems m)
        writeIORef (brFiles br) Map.empty
      fd <- openRO (brDir br </> printf "blk%05d.dat" file)
      modifyIORef' (brFiles br) (Map.insert file fd)
      return fd
  raw <- preadExact fd len (fromIntegral pos)
  return $! if BS.all (== 0) (brXor br) then raw else xorAt (brXor br) (fromIntegral pos) raw

xorAt :: ByteString -> Int -> ByteString -> ByteString
xorAt key pos raw = BSI.unsafeCreate n $ \dst ->
  BSU.unsafeUseAsCString raw $ \src ->
    let loop !i
          | i >= n = return ()
          | otherwise = do
              (b :: Word8) <- peekByteOff src i
              pokeByteOff dst i (b `xor` BSU.unsafeIndex key ((pos + i) `mod` 8))
              loop (i + 1)
    in loop 0
  where n = BS.length raw

--------------------------------------------------------------------------------
-- aggregate (4 x 64-bit little-endian limbs, mod 2^256)
--------------------------------------------------------------------------------

data Agg = Agg !Word64 !Word64 !Word64 !Word64 deriving (Eq)

aggZero :: Agg
aggZero = Agg 0 0 0 0

aggAdd :: Agg -> Agg -> Agg
aggAdd (Agg a0 a1 a2 a3) (Agg b0 b1 b2 b3) =
  let (s0, c0) = adc a0 b0 0
      (s1, c1) = adc a1 b1 c0
      (s2, c2) = adc a2 b2 c1
      (s3, _)  = adc a3 b3 c2
  in Agg s0 s1 s2 s3
  where
    adc :: Word64 -> Word64 -> Word64 -> (Word64, Word64)
    adc x y c = let s = x + y; c1 = if s < x then 1 else 0
                    s' = s + c; c2 = if s' < s then 1 else 0
                in (s', c1 + c2)

aggOfDigest :: ByteString -> Agg
aggOfDigest d = Agg (u64At d 0) (u64At d 8) (u64At d 16) (u64At d 24)

aggHex :: Agg -> String
aggHex (Agg a0 a1 a2 a3) = printf "%016x%016x%016x%016x" a3 a2 a1 a0

compactSize :: Int -> BB.Builder
compactSize n
  | n < 0xfd = BB.word8 (fromIntegral n)
  | n <= 0xffff = BB.word8 0xfd <> BB.word16LE (fromIntegral n)
  | otherwise = BB.word8 0xfe <> BB.word32LE (fromIntegral n)

-- | @H(c) = SHA256(salt ‖ code u32 ‖ amount i64 ‖ CompactSize(len) ‖ script ‖ txid ‖ vout u32)@,
-- @code = height*2 + coinbase@ -- byte-identical to rustoshi's @coin_hash@ and
-- tools/swiftsync-refval.py, so a revealed salt can be re-checked.
coinHash :: ByteString -> Word32 -> Word64 -> ByteString -> ByteString -> Word32 -> Agg
coinHash salt code amount script txid vout =
  aggOfDigest $ sha256 $ BL.toStrict $ BB.toLazyByteString $
    BB.byteString salt <> BB.word32LE code <> BB.int64LE (fromIntegral amount)
      <> compactSize (BS.length script) <> BB.byteString script
      <> BB.byteString txid <> BB.word32LE vout

-- | TxOutSer record (kernel/coinstats.cpp), the spill format swiftsync-close.py reads.
txOutSer :: ByteString -> Word32 -> Word32 -> Word64 -> ByteString -> BB.Builder
txOutSer txid vout code amount script =
  BB.byteString txid <> BB.word32LE vout <> BB.word32LE code <> BB.int64LE (fromIntegral amount)
    <> compactSize (BS.length script) <> BB.byteString script

--------------------------------------------------------------------------------
-- per-block partial results
--------------------------------------------------------------------------------

data Partial = Partial
  { pAggIn :: !Agg, pAggOut :: !Agg
  , pBlocks, pTxs, pInputs, pInputsConnected, pOutputs, pHinted, pAggOutTerms, pSkipped, pSameBlock :: !Word64 }

pZero :: Partial
pZero = Partial aggZero aggZero 0 0 0 0 0 0 0 0 0

pMerge :: Partial -> Partial -> Partial
pMerge a b = Partial (aggAdd (pAggIn a) (pAggIn b)) (aggAdd (pAggOut a) (pAggOut b))
  (pBlocks a + pBlocks b) (pTxs a + pTxs b) (pInputs a + pInputs b)
  (pInputsConnected a + pInputsConnected b) (pOutputs a + pOutputs b) (pHinted a + pHinted b)
  (pAggOutTerms a + pAggOutTerms b) (pSkipped a + pSkipped b) (pSameBlock a + pSameBlock b)

data Errors = Errors { erList :: !(IORef [(String, Word32, String)]), erCount :: !(IORef Int), erMax :: !Int }

pushErr :: Errors -> String -> Word32 -> String -> IO ()
pushErr e kind h msg0 = do
  !msg <- evaluate (length msg0 `seq` msg0)
  n <- atomicModifyIORef' (erCount e) (\c -> (c + 1, c))
  when (n < erMax e) $ atomicModifyIORef' (erList e) (\l -> ((kind, h, msg) : l, ()))

data Ctx = Ctx
  { cxNet        :: !Network
  , cxPack       :: !Pack
  , cxHints      :: !Hints
  , cxDB         :: !HaskoinDB
  , cxEntries    :: !(Map.Map BlockHash ChainEntry)
  , cxByHeight   :: !(Map.Map Word32 BlockHash)
  , cxHdrHashes  :: !(V.Vector BlockHash)   -- label height -> phase-0 header hash
  , cxSalt       :: !ByteString
  , cxCtl        :: !Controls
  , cxRelabel    :: !(Map.Map Word32 Word32)
  , cxOverrides  :: !(Map.Map Word32 FilePath)
  , cxErrors     :: !Errors
  , cxApplied    :: !(IORef [String])
  , cxBip34      :: !Word32
  , cxBip30Exempt :: ![Word32]
  , cxBip30Over  :: ![Word32]
  , cxGenesis    :: !BlockHash
  }

phys :: Ctx -> Word32 -> Word32
phys cx h = Map.findWithDefault h h (cxRelabel cx)

data Worker = Worker
  { wkBlk   :: !BlkReader
  , wkUndo  :: !Fd
  , wkHints :: !Fd
  , wkSpill :: !Handle
  , wkCbs   :: !(IORef [(SBS.ShortByteString, Word32)])
  , wkSeen  :: !(IORef [Word32])
  , wkPart  :: !(IORef Partial)
  }

data UCoin = UCoin { ucHeight :: !Word32, ucCoinbase :: !Bool, ucValue :: !Word64, ucScript :: !ByteString }

hashBytes :: BlockHash -> ByteString
hashBytes (BlockHash (Hash256 b)) = b

txidBytes :: TxId -> ByteString
txidBytes (TxId (Hash256 b)) = b

showHash :: ByteString -> String
showHash = BC.unpack . B16.encode . BS.reverse

isP2PKH, isP2WPKH, isP2PK :: ByteString -> Bool
isP2PKH s = BS.length s == 25 && BS.take 3 s == BS.pack [0x76, 0xa9, 0x14]
isP2WPKH s = BS.length s == 22 && BS.take 2 s == BS.pack [0x00, 0x14]
isP2PK s = (BS.length s == 35 && BS.head s == 33) || (BS.length s == 67 && BS.head s == 65)

flipByte :: Int -> ByteString -> ByteString
flipByte k s = BS.take k s <> BS.singleton (BS.index s k `xor` 1) <> BS.drop (k + 1) s

--------------------------------------------------------------------------------
-- one height
--------------------------------------------------------------------------------

-- | Validate one height. @h@ is the LABEL height (what the pass believes).
processHeight :: Ctx -> Worker -> Word32 -> IO Partial
processHeight cx wk h = do
  r <- try (processHeight' cx wk h)
  case r of
    Right p -> return p
    Left (e :: SomeException) -> do
      pushErr (cxErrors cx) "exception" h (show e)
      return pZero

processHeight' :: Ctx -> Worker -> Word32 -> IO Partial
processHeight' cx wk h = do
  let errs = cxErrors cx
      err kind msg = pushErr errs kind h msg
      applied s = atomicModifyIORef' (cxApplied cx) (\l -> (s : l, ()))
      ph = phys cx h
      ent = cxPack cx `seq` pkEnts (cxPack cx) V.! fromIntegral ph
      net = cxNet cx
  -- block bytes, parsed by the node's own decoder (Serialize Block)
  mraw <- case Map.lookup h (cxOverrides cx) of
    Just p -> do
      applied ("block-file h=" ++ show h ++ " from " ++ p)
      Right <$> BS.readFile p
    Nothing -> do
      r <- try (blkRead (wkBlk wk) (beFile ent) (bePos ent) (fromIntegral (beSize ent)))
      return $ either (\(e :: SomeException) -> Left (show e)) Right r
  case mraw of
    Left e -> err "io" e >> return pZero
    Right raw -> case runGetState (get :: Get Block) raw 0 of
      Left e -> err "parse" ("block decode: " ++ e) >> return pZero
      Right (block, rest) -> do
        unless (BS.null rest) $ err "parse" "trailing bytes after block"
        processBlock cx wk h ph block

processBlock :: Ctx -> Worker -> Word32 -> Word32 -> Block -> IO Partial
processBlock cx wk h ph block = do
  let errs = cxErrors cx
      err kind msg = pushErr errs kind h msg
      applied s = atomicModifyIORef' (cxApplied cx) (\l -> (s : l, ()))
      net = cxNet cx
      ctl = cxCtl cx
      hdr = blockHeader block
      bh = computeBlockHash hdr
      txns = blockTxns block
      txids = map (txidBytes . computeTxId) txns
      nTx = length txns
  -- header binds to the chain: hash == blocks.idx[h] == phase-0 header chain
  when (hashBytes bh /= beHash (pkEnts (cxPack cx) V.! fromIntegral h)
        || bh /= cxHdrHashes cx V.! fromIntegral h) $
    err "header" ("block hash " ++ showHash (hashBytes bh) ++ " != blocks.idx[" ++ show h ++ "]")
  let p0 = pZero { pBlocks = 1, pTxs = fromIntegral nTx }
  if h == 0
    then do
      -- genesis: no inputs; its output is unspendable (never in the set)
      when (bh /= cxGenesis cx) $ err "header" "genesis hash mismatch"
      let nOut = fromIntegral (sum (map (length . txOutputs) txns))
      return p0 { pOutputs = nOut, pSkipped = nOut }
    else case undoEntry (cxPack cx) ph of
      Nothing -> err "undo" ("no undo.idx entry for " ++ show ph) >> return p0
      Just (uoff, ulen, unin) -> do
        uraw <- preadExact (wkUndo wk) (fromIntegral ulen) (fromIntegral uoff)
        -- undo coins (untrusted), node's own Core TxInUndo decoder
        case runGetState (get :: Get BlockUndo) uraw 0 of
          Left e -> err "undo-parse" e >> return p0
          Right (_, rest) | not (BS.null rest) ->
            err "undo-parse" (show (BS.length rest) ++ " trailing bytes") >> return p0
          Right (BlockUndo tus, _) -> do
            let undo0 = [ [ UCoin (tuHeight c) (tuCoinbase c) (txOutValue (tuOutput c)) (txOutScript (tuOutput c))
                          | c <- tuPrevOutputs tu ] | tu <- tus ]
            if length undo0 + 1 /= nTx
              then err "undo-count" (show (length undo0) ++ " CTxUndo for " ++ show (nTx - 1) ++ " txs") >> return p0
              else do
                let bad = [ i | (i, tx, tu) <- zip3 [1 :: Int ..] (drop 1 txns) undo0, length tu /= length (txInputs tx) ]
                    nin = fromIntegral (sum (map length undo0)) :: Word64
                case bad of
                  (i:_) -> err "undo-count" ("tx " ++ show i ++ " inputs != undo coins") >> return p0
                  [] -> do
                    when (nin /= fromIntegral unin) $
                      err "undo-count" ("undo.idx n_inputs " ++ show unin ++ " != coins " ++ show nin)
                    processWithUndo cx wk h ph block bh txids undo0 nin p0

processWithUndo :: Ctx -> Worker -> Word32 -> Word32 -> Block -> BlockHash -> [ByteString]
                -> [[UCoin]] -> Word64 -> Partial -> IO Partial
processWithUndo cx wk h ph block bh txids undo0 nin0 p0 = do
  let errs = cxErrors cx
      err kind msg = pushErr errs kind h msg
      applied s = atomicModifyIORef' (cxApplied cx) (\l -> (s : l, ()))
      net = cxNet cx
      ctl = cxCtl cx
      hdr = blockHeader block
      txns = blockTxns block
      ntxs = drop 1 txns
  -- controls on the supplied coins
  let undo1 = if Map.null (cxRelabel cx) then undo0
              else [ [ c { ucHeight = Map.findWithDefault (ucHeight c) (ucHeight c) (cxRelabel cx) } | c <- tu ] | tu <- undo0 ]
  (undo2, voutFlip) <- case cField ctl of
    Just (f, fh, cls) | fh == h -> do
      let classOk s = case cls of
            "p2pkh" -> isP2PKH s
            "p2wpkh" -> isP2WPKH s
            "p2pk" -> isP2PK s
            _ -> False
          cands = [ (i, j) | (i, tu) <- zip [0 :: Int ..] undo1, (j, c) <- zip [0 :: Int ..] tu
                           , not (ucCoinbase c), classOk (ucScript c), ucHeight c < h, h - ucHeight c > 100 ]
      case cands of
        [] -> return (undo1, Nothing)
        ((i, j):_) -> do
          let c = undo1 !! i !! j
              c' = case f of
                "amount" -> c { ucValue = ucValue c + 1 }
                "script" -> let k = if cls == "p2pk" then 10 else BS.length (ucScript c) - 3
                            in c { ucScript = flipByte k (ucScript c) }
                "height" -> c { ucHeight = ucHeight c - 1 }
                "coinbase" -> c { ucCoinbase = not (ucCoinbase c) }
                _ -> c
              upd = [ if i' == i then [ if j' == j then c' else x | (j', x) <- zip [0 ..] tu ] else tu
                    | (i', tu) <- zip [0 ..] undo1 ]
          applied ("field:" ++ f ++ "/" ++ cls ++ " h=" ++ show h ++ " tx=" ++ show (i + 1) ++ " in=" ++ show j
                   ++ " coin_height=" ++ show (ucHeight c') ++ " value=" ++ show (ucValue c'))
          return (upd, if f == "vout" then Just (i + 1, j) else Nothing)
    _ -> return (undo1, Nothing)
  undo <- if cDropCoin ctl == Just h
    then case break (not . null) undo2 of
      (pre, tu:post) -> do
        applied ("drop-coin h=" ++ show h)
        return (pre ++ (init tu : post))
      _ -> return undo2
    else return undo2
  let mism = [ i | (i, tx, tu) <- zip3 [1 :: Int ..] ntxs undo, length tu /= length (txInputs tx) ]
  case mism of
    (i:_) -> err "undo-count" ("tx " ++ show i ++ " inputs != undo coins") >> return p0
    [] -> do
      -- P-ORD [extension a] + the supplied coin map
      let pairs = [ (i, j, txInPrevOutput inp, c)
                  | (i, tx, tu) <- zip3 [1 :: Int ..] ntxs undo, (j, inp, c) <- zip3 [0 :: Int ..] (txInputs tx) tu ]
          toCoin c = Coin (TxOut (ucValue c) (ucScript c)) (ucHeight c) (ucCoinbase c)
          sameBlock = [ (i, j, op, c) | (i, j, op, c) <- pairs, ucHeight c == h ]
          supplied = Map.fromList
            [ (op, toCoin c) | (_, _, op, c) <- pairs, ucHeight c /= h || cNoPord ctl ]
      unless (cNoPord ctl) $
        forM_ pairs $ \(i, j, _, c) ->
          when (ucHeight c > h && ucHeight c /= h) $
            err "P-ORD" ("tx " ++ show i ++ " in " ++ show j ++ " spends a coin created at "
                         ++ show (ucHeight c) ++ " > " ++ show h)
      -- THE production connect arm (Main.hs syncMessageHandler MBlock):
      -- addHeader ran in phase 0; here validateBlockGuarded (validateFullBlockIO ...)
      let entries     = cxEntries cx
          byHeightBg  = cxByHeight cx
          parentHash  = bhPrevBlock hdr
          entryWork   = maybe 0 ceChainWork
                          (Map.lookup bh entries
                            `orElseM` (Map.lookup (cxHdrHashes cx V.! fromIntegral h) entries))
          prevMTP     = medianTimePast entries parentHash
          skipScripts = False
          cs          = ChainState (h - 1) parentHash entryWork prevMTP
                          (consensusFlagsAtHeight net h)
          getMtpBg    = getMtpAtHeightFromEntries entries byHeightBg
      vr <- validateBlockGuarded ("block " ++ show h ++ " " ++ showHash (hashBytes bh))
              (validateFullBlockIO (cxDB cx) net cs getMtpBg skipScripts block supplied)
      let pConn = case vr of
            Right () -> nin0
            Left _ -> 0
      case vr of
        Left e -> err "node" e
        Right () -> return ()
      -- P-ORD, same-block half: created by an EARLIER tx with identical data
      let txidPos = Map.fromList (zip txids [0 :: Int ..])
      sb <- if cNoPord ctl then return 0 else do
        forM_ sameBlock $ \(i, j, op, c) ->
          case Map.lookup (txidBytes (outPointHash op)) txidPos of
            Just k | k < i -> do
              let outs = txOutputs (txns !! k)
                  v = fromIntegral (outPointIndex op)
                  ok = v < length outs
                       && txOutValue (outs !! v) == ucValue c
                       && txOutScript (outs !! v) == ucScript c
                       && ucCoinbase c == (k == 0)
              unless ok $ err "P-ORD" ("tx " ++ show i ++ " in " ++ show j ++ ": same-block coin data != created output")
            _ -> err "P-ORD" ("tx " ++ show i ++ " in " ++ show j ++ ": coin height == h but prevout not created earlier in block")
        return (fromIntegral (length sameBlock))
      -- Agg_in over every input (supplied coin, prevout from the BLOCK)
      let salt = cxSalt cx
          aggIn = foldl aggAdd aggZero
            [ coinHash salt (ucHeight c * 2 + (if ucCoinbase c then 1 else 0)) (ucValue c) (ucScript c)
                       (txidBytes (outPointHash op)) vout
            | (i, j, op, c) <- pairs
            , let vout = if voutFlip == Just (i, j) then outPointIndex op `xor` 1 else outPointIndex op ]
      -- outputs: unspendable skip / hinted -> spill / else Agg_out
      hl0 <- hintsAt (cxHints cx) (wkHints wk) ph
      hl <- if cHintDrop ctl == Just h && not (null hl0)
        then do
          let (dt, dv) = head hl0
          applied ("hint-drop " ++ showHash dt ++ ":" ++ show dv ++ " h=" ++ show h)
          return (tail hl0)
        else return hl0
      let hset0 = Set.fromList hl
      when (Set.size hset0 /= length hl) $ err "hints" "duplicate hint"
      hset <- if cHintAdd ctl == Just h
        then do
          let order = drop 1 (zip3 [0 :: Int ..] txids txns) ++ take 1 (zip3 [0 ..] txids txns)
              cand = [ (t, fromIntegral v) | (_, t, tx) <- order, (v, o) <- zip [0 :: Int ..] (txOutputs tx)
                                           , not (Set.member (t, fromIntegral v) hset0), not (isUnspendable (txOutScript o)) ]
          case cand of
            (k@(t, v):_) -> do
              applied ("hint-add " ++ showHash t ++ ":" ++ show v ++ " h=" ++ show h)
              return (Set.insert k hset0)
            [] -> return hset0
        else return hset0
      let overwrittenCb = h `elem` cxBip30Over cx && not (cBip30Spendable ctl)
          outs = [ (k, t, fromIntegral v, o) | (k, t, tx) <- zip3 [0 :: Int ..] txids txns, (v, o) <- zip [0 :: Int ..] (txOutputs tx) ]
          step (!spill, !hits, !aout, !nterm, !nskip) (k, t, v, o)
            | (k == 0 && overwrittenCb) || isUnspendable (txOutScript o) = (spill, hits, aout, nterm, nskip + 1)
            | Set.member (t, v) hset =
                (spill <> txOutSer t v code (txOutValue o) (txOutScript o), hits + 1, aout, nterm, nskip)
            | otherwise =
                (spill, hits, aggAdd aout (coinHash salt code (txOutValue o) (txOutScript o) t v), nterm + 1, nskip)
            where code = h * 2 + (if k == 0 then 1 else 0)
          (spillB, nHits, aggOut, nTerms, nSkip) = foldl step (mempty, 0 :: Int, aggZero, 0 :: Word64, 0 :: Word64) outs
      when (nHits /= Set.size hset) $
        err "hint-count" ("hint hits " ++ show nHits ++ " != |hints[" ++ show h ++ "]| " ++ show (Set.size hset))
      when (nHits > 0) $ BB.hPutBuilder (wkSpill wk) spillB
      -- BIP30 coinbase-txid cache [extension c]
      -- (forced: an unevaluated `head txids` would retain the whole parsed
      -- block, and its blk buffer, for every block below BIP34)
      when (h < cxBip34 cx && (cBip30NoExempt ctl || h `notElem` cxBip30Exempt cx)) $ do
        -- (unpinned ShortByteString: a long-lived 32-byte pinned copy would
        -- pin a whole 4 KiB pinned block per entry)
        !cb <- evaluate (SBS.toShort (head txids))
        modifyIORef' (wkCbs wk) ((cb, h) :)
      return p0 { pAggIn = aggIn, pAggOut = aggOut, pInputs = fromIntegral (length pairs)
                , pInputsConnected = pConn, pOutputs = fromIntegral (length outs)
                , pHinted = fromIntegral nHits, pAggOutTerms = nTerms, pSkipped = nSkip, pSameBlock = sb }
  where
    orElseM (Just x) _ = Just x
    orElseM Nothing y = y

--------------------------------------------------------------------------------
-- start set (standalone ranges)
--------------------------------------------------------------------------------

type Key = (Word64, Word64, Word64, Word64, Word32)

keyOf :: ByteString -> Word32 -> Key
keyOf t v = (be 0, be 8, be 16, be 24, v)
  where be o = foldl (\acc i -> (acc `shiftL` 8) .|. fromIntegral (BSU.unsafeIndex t (o + i))) 0 [0 .. 7]

data StartSet = StartSet { ssCoins, ssSurvivors, ssSpent, ssHintsBelow :: !Word64, ssAggOut :: !Agg }

processStartSet :: Ctx -> FilePath -> Word32 -> FilePath -> IO (Either String StartSet)
processStartSet cx path from spillDir = do
  let hn = cxHints cx
      nKeys = fromIntegral (hintsCountRange hn 0 (from - 1)) :: Int
  hfd <- openRO (hnPath hn)
  mv <- VUM.new nKeys
  let fill !h !i
        | h >= from || h > hnH hn = return i
        | otherwise = do
            l <- hintsAt hn hfd h
            foldM_ (\k (t, v) -> VUM.write mv k (keyOf t v) >> return (k + 1)) i l
            fill (h + 1) (i + length l)
  n <- fill 0 0
  closeFd hfd
  if n /= nKeys then return (Left "hint count mismatch") else do
    Intro.sort mv
    keys <- VU.unsafeFreeze mv
    matched <- VUM.replicate nKeys False
    lbs <- BL.readFile path
    case runGetLazyState (get :: Get SnapshotMetadata) lbs of
      Left e -> return (Left ("start snapshot metadata: " ++ e))
      Right (meta, body)
        | smNetworkMagic meta /= netMagic (cxNet cx) -> return (Left "start snapshot: network magic")
        | smBaseBlockHash meta /= cxHdrHashes cx V.! fromIntegral (from - 1) ->
            return (Left ("start snapshot base " ++ showHash (hashBytes (smBaseBlockHash meta))
                          ++ " != header chain [" ++ show (from - 1) ++ "]"))
        | otherwise -> do
            out <- openBinaryFile (spillDir </> "startset-survivors.bin") WriteMode
            hSetBuffering out (BlockBuffering (Just (1 `shiftL` 20)))
            let salt = cxSalt cx
                search k = bs 0 (VU.length keys)
                  where bs lo hi | lo >= hi = Nothing
                                 | otherwise = let m = (lo + hi) `div` 2; x = keys VU.! m
                                               in if x == k then Just m else if x < k then bs (m + 1) hi else bs lo m
                goGroups !remaining !coins !surv !spent !agg rest
                  | remaining == 0 = return (Right (coins, surv, spent, agg, rest))
                  | BL.null rest = return (Left ("start snapshot: short, " ++ show remaining ++ " coins missing"))
                  | otherwise = case runGetLazyState groupGet rest of
                      Left e -> return (Left ("start snapshot coin: " ++ e))
                      Right ((t, cs), rest') -> do
                        (s1, sp1, a1, dup) <- foldM (\(!s, !sp, !a, !d) (v, c) -> do
                            let code = coinHeight c * 2 + (if coinIsCoinbase c then 1 else 0)
                                val = txOutValue (coinTxOut c)
                                scr = txOutScript (coinTxOut c)
                            case search (keyOf t v) of
                              Just i -> do
                                m <- VUM.read matched i
                                VUM.write matched i True
                                BB.hPutBuilder out (txOutSer t v code val scr)
                                return (s + 1, sp, a, d || m)
                              Nothing -> return (s, sp + 1, aggAdd a (coinHash salt code val scr t v), d)
                          ) (surv, spent, agg, False) cs
                        if dup then return (Left ("start set: duplicate coin " ++ showHash t))
                        else goGroups (remaining - fromIntegral (length cs)) (coins + fromIntegral (length cs)) s1 sp1 a1 rest'
            r <- goGroups (smCoinsCount meta) 0 0 0 aggZero body
            hClose out
            case r of
              Left e -> return (Left e)
              Right (coins, surv, spent, agg, rest)
                | not (BL.null rest) -> return (Left "start snapshot: trailing bytes")
                | otherwise -> do
                    unmatched <- VU.length . VU.filter not <$> VU.freeze matched
                    if unmatched /= 0
                      then return (Left (show unmatched ++ " hints below --from are not coins of S(from-1)"))
                      else return (Right (StartSet coins surv spent (fromIntegral nKeys) agg))
  where
    -- Core snapshot txid group: txid32, CompactSize n, n x (CompactSize vout, Coin) --
    -- the node's own parseSnapshotCoinGroup shape over its getCoreCoin decoder.
    groupGet :: Get (ByteString, [(Word32, Coin)])
    groupGet = do
      TxId (Hash256 t) <- get
      VarInt n <- get
      cs <- replicateM (fromIntegral n) $ do
        VarInt v <- get
        c <- getCoreCoin
        return (fromIntegral v, c)
      return (t, cs)

--------------------------------------------------------------------------------
-- driver
--------------------------------------------------------------------------------

vmHwmKb :: IO Integer
vmHwmKb = do
  s <- readFile "/proc/self/status"
  let ls = [ l | l <- lines s, "VmHWM:" `isPrefixOf` l ]
  length s `seq` return $ case ls of
    (l:_) -> fromMaybe 0 (readMaybe (words l !! 1))
    [] -> 0

exeSha256 :: IO String
exeSha256 = do
  b <- BS.readFile "/proc/self/exe"
  return (BC.unpack (B16.encode (sha256 b)))

readSalt :: Maybe FilePath -> IO ByteString
readSalt (Just p) = do
  s <- BS.readFile p
  case B16.decode (BC.filter (`notElem` (" \n\r\t" :: String)) s) of
    Right b | BS.length b == 32 -> return b
    _ -> ioError (userError "salt must be 32 bytes hex")
readSalt Nothing = withBinaryFile "/dev/urandom" ReadMode (\hd -> BS.hGet hd 32)

-- | Entry point. Returns the process exit code (0 = PASS).
runSwiftSyncPass :: [String] -> IO ExitCode
runSwiftSyncPass argv = case parseArgs argv of
  Left e -> hPutStrLn stderr ("swiftsync-pass: " ++ e) >> hPutStr stderr usage >> return (ExitFailure 2)
  Right a -> do
    r <- try (runInner a)
    case r of
      Right True -> return ExitSuccess
      Right False -> return (ExitFailure 1)
      Left (e :: SomeException) -> do
        hPutStrLn stderr ("swiftsync-pass: FATAL: " ++ show e)
        return (ExitFailure 2)

fatal :: String -> IO a
fatal = ioError . userError

runInner :: Args -> IO Bool
runInner a = do
  hSetBuffering stdout LineBuffering
  hSetBuffering stderr LineBuffering
  t0 <- getPOSIXTime
  net <- case aNetwork a of
    "mainnet" -> return mainnet
    "regtest" -> return regtest
    n -> fatal ("--network " ++ n ++ ": only mainnet and regtest are supported")
  ctl <- either fatal return (parseControls (aControl a))
  pack <- openPack (aPack a) >>= either fatal return
  hints <- openHints (fromMaybe (aPack a) (aHints a)) >>= either fatal return
  let from = aFrom a
      to = aTo a
  when (to > pkH pack || from > to) $ fatal ("bad range " ++ show from ++ ".." ++ show to ++ " (pack H=" ++ show (pkH pack) ++ ")")
  when (to > hnH hints) $ fatal ("hints describe height " ++ show (hnH hints) ++ " < --to " ++ show to)
  blocksDir <- case aBlocks a of
    Just b -> return b
    Nothing -> do
      m <- BL.readFile (aPack a </> "MANIFEST.json")
      case A.decode m :: Maybe A.Value of
        Just (A.Object o) | Just (A.Object s) <- lookupKey "sources" o
                          , Just (A.String p) <- lookupKey "core_blocks" s -> return (show' p)
        _ -> fatal "MANIFEST sources.core_blocks"
  salt <- readSalt (aSaltFile a)
  let threads = max 1 (min 32 (aThreads a))
  caps <- getNumCapabilities
  when (caps < threads) $ setNumCapabilities threads
  -- production startup steps the connect arm depends on (Main.hs runCommand)
  initGlobalSigCache
  scriptMode <- if aPar a /= 0
    then do
      setConfiguredPar (aPar a)
      extra <- startGlobalScriptCheckQueue
      return ("persistent ScriptCheckQueue (--par " ++ show (aPar a) ++ ", " ++ show extra ++ " extra workers)")
    else return "serial branch of dispatchScriptChecks on each block worker (no global queue)"
  createDirectoryIfMissing True (aOut a </> "spill")
  listDirectory (aOut a </> "spill") >>= mapM_ (\f -> removeFile (aOut a </> "spill" </> f))
  let relabel = case cForgeOrder ctl of
        Just k -> Map.fromList [(k, k + 1), (k + 1, k)]
        Nothing -> Map.empty
  overrides <- fmap Map.fromList $ forM (aBlockFile a) $ \s -> case break (== '=') s of
    (hs, '=':p) | Just hh <- readMaybe hs -> return (hh, p)
    _ -> fatal "--block-file H=PATH"
  hPutStrLn stderr $ "swiftsync-pass: range " ++ show from ++ ".." ++ show to ++ " hints@" ++ show (hnH hints)
    ++ " threads=" ++ show threads ++ " control=" ++ show (aControl a) ++ " pack=" ++ aPack a
    ++ " scripts=" ++ scriptMode

  -- ---- phase 0: header chain 0..=to through the node's addHeaderAt (PoW,
  -- time-too-old, BIP94, time-too-new, bad-diffbits, checkpoints)
  tp <- getPOSIXTime
  now <- (round <$> getPOSIXTime) :: IO Int64
  hdrErrs <- newIORef ([] :: [String])
  let hdrErr s = modifyIORef' hdrErrs (s :)
  br0 <- newBlkReader blocksDir (pkXor pack)
  headers <- V.generateM (fromIntegral to + 1) $ \i -> do
    let e = pkEnts pack V.! fromIntegral (Map.findWithDefault (fromIntegral i) (fromIntegral i) relabel)
    raw <- blkRead br0 (beFile e) (bePos e) 80
    case runGetState (get :: Get BlockHeader) raw 0 of
      Left err -> fatal ("header " ++ show i ++ ": " ++ err)
      Right (hd, _) -> return $! hd
  closeBlkReader br0
  let hashes = V.map computeBlockHash headers
      genesisHash = computeBlockHash (blockHeader (netGenesisBlock net))
  when (V.head hashes /= genesisHash) $ hdrErr "header 0 is not the network genesis"
  hc <- initHeaderChain net
  forM_ [1 .. to] $ \h -> do
    let hd = headers V.! fromIntegral h
        hh = hashes V.! fromIntegral h
    r <- addHeaderAt net hc hd False (Just now)
    case r of
      Right e | ceHeight e == h && ceHash e == hh -> return ()
      Right e -> hdrErr ("header " ++ show h ++ ": addHeader placed it at height " ++ show (ceHeight e))
      Left e -> do
        hdrErr ("header " ++ show h ++ ": " ++ e)
        -- control path only (e.g. forge-order): keep a chain entry so phase 1
        -- can still show which other checks see the forgery
        atomically $ do
          ents <- readTVar (hcEntries hc)
          let ce = ChainEntry hd hh h 0 (Just (bhPrevBlock hd)) StatusHeaderValid 0 0
              ents' = Map.insert hh ce ents
              ce' = ce { ceMedianTime = medianTimePast ents' hh }
          writeTVar (hcEntries hc) (Map.insert hh ce' ents)
          modifyTVar' (hcByHeight hc) (Map.insert h hh)
  entries <- readTVarIO (hcEntries hc)
  byHeight <- readTVarIO (hcByHeight hc)
  forM_ [0 .. to] $ \h -> do
    let hh = hashes V.! fromIntegral h
    when (hashBytes hh /= beHash (pkEnts pack V.! fromIntegral h)) $ hdrErr ("header " ++ show h ++ ": hash != blocks.idx")
    when (Map.lookup h byHeight /= Just hh) $ hdrErr ("header " ++ show h ++ ": not on the header chain's active index")
  when (to == pkH pack && hashBytes (hashes V.! fromIntegral to) /= pkBase pack) $ hdrErr "tip != pack base hash"
  hdrErrList <- reverse <$> readIORef hdrErrs
  tp1 <- getPOSIXTime
  let phase0 = realToFrac (tp1 - tp) :: Double
  hPutStrLn stderr $ printf "swiftsync-pass: phase 0: %d headers through addHeaderAt in %.1fs, %d header errors"
    (to + 1) phase0 (length hdrErrList)

  -- scratch chainstate DB for validateFullBlockIO's checkBIP30: EMPTY except the
  -- BIP34 anchor row (height-index entry at netBIP34Height, from the header chain)
  let dbDir = aOut a </> "bip30-scratch-db"
  ex <- doesDirectoryExist dbDir
  when ex $ removeDirectoryRecursive dbDir
  db <- openDB (defaultDBConfig dbDir)
  let bip34H = netBIP34Height net
  when (to >= bip34H) $ putBlockHeight db bip34H (hashes V.! fromIntegral bip34H)

  errsL <- newIORef []
  errsC <- newIORef 0
  appliedRef <- newIORef []
  let ctx = Ctx
        { cxNet = net, cxPack = pack, cxHints = hints, cxDB = db
        , cxEntries = entries, cxByHeight = byHeight, cxHdrHashes = hashes
        , cxSalt = salt, cxCtl = ctl, cxRelabel = relabel, cxOverrides = overrides
        , cxErrors = Errors errsL errsC (aMaxErrors a), cxApplied = appliedRef
        , cxBip34 = bip34H
        , cxBip30Exempt = if aNetwork a == "mainnet" then [91842, 91880] else []
        , cxBip30Over = if aNetwork a == "mainnet" then [91722, 91812] else []
        , cxGenesis = genesisHash }
  forM_ (take 20 hdrErrList) $ \e -> pushErr (cxErrors ctx) "header-chain" 0 e
  when (length hdrErrList > 20) $ pushErr (cxErrors ctx) "header-chain" 0 (show (length hdrErrList - 20) ++ " more")

  -- ---- phase 1: every height of the range, out of order, on the workers
  let heights0 = [from .. to]
      heights1 = maybe heights0 (\d -> filter (/= d) heights0) (cDropBlock ctl)
      heights = V.fromList (heights1 ++ maybe [] (: []) (cDupBlock ctl))
  forM_ (cDropBlock ctl) $ \d -> atomicModifyIORef' appliedRef (\l -> (("drop-block " ++ show d) : l, ()))
  forM_ (cDupBlock ctl) $ \d -> atomicModifyIORef' appliedRef (\l -> (("dup-block " ++ show d) : l, ()))
  nextRef <- newIORef (0 :: Int)
  doneRef <- newIORef (0 :: Int)
  scriptBase <- readScriptChecksTotal
  tw <- getPOSIXTime
  let total = V.length heights
  prog <- forkIO $ forever $ do
    threadDelay 60000000
    d <- readIORef doneRef
    sc <- readScriptChecksTotal
    tn <- getPOSIXTime
    rss <- vmHwmKb
    ne <- readIORef errsC
    hPutStrLn stderr $ printf "swiftsync-pass: %d/%d blocks, %.0fs, scripts %d , rss %d MiB, errors %d"
      d total (realToFrac (tn - tw) :: Double) (sc - scriptBase) (rss `div` 1024) ne
  let nspill = threads
      spillName t = aOut a </> "spill" </> printf "r%07d-%07d-t%02d.bin" from to t
  results <- forM [0 .. nspill - 1] $ \t -> do
    mv <- newEmptyMVar
    _ <- forkIO $ do
      r <- try $ bracket
        (do br <- newBlkReader blocksDir (pkXor pack)
            ufd <- openRO (pkUndoPath pack)
            hfd <- openRO (hnPath hints)
            sp <- openBinaryFile (spillName t) WriteMode
            hSetBuffering sp (BlockBuffering (Just (1 `shiftL` 20)))
            Worker br ufd hfd sp <$> newIORef [] <*> newIORef [] <*> newIORef pZero)
        (\w -> do closeBlkReader (wkBlk w); closeFd (wkUndo w); closeFd (wkHints w); hClose (wkSpill w))
        (\w -> do
            let loop = do
                  i <- atomicModifyIORef' nextRef (\x -> (x + 1, x))
                  when (i < total) $ do
                    let h = heights V.! i
                    modifyIORef' (wkSeen w) (h :)
                    p <- processHeight ctx w h
                    modifyIORef' (wkPart w) (`pMerge` p)
                    atomicModifyIORef' doneRef (\x -> (x + 1, ()))
                    loop
            loop
            (,,) <$> readIORef (wkPart w) <*> readIORef (wkCbs w) <*> readIORef (wkSeen w))
      putMVar mv r
    return mv
  outs <- mapM takeMVar results
  killThread prog
  tw1 <- getPOSIXTime
  let phase1 = realToFrac (tw1 - tw) :: Double
  scriptEnd <- readScriptChecksTotal
  let scriptsRun = scriptEnd - scriptBase
  (part, cbs0, seenL) <- foldM (\(p, c, s) r -> case r of
      Right (p', c', s') -> return (pMerge p p', c' ++ c, s' ++ s)
      Left (e :: SomeException) -> do
        pushErr (cxErrors ctx) "worker" 0 (show e)
        return (p, c, s)) (pZero, [], []) outs
  closeDB db
  removeDirectoryRecursive dbDir

  -- ---- start set (standalone range)
  (aggOut, startJson) <- case (from > 0, aStartSnap a) of
    (True, Just p) -> do
      r <- processStartSet ctx p from (aOut a </> "spill")
      case r of
        Right ss -> return (aggAdd (pAggOut part) (ssAggOut ss), A.object
          [ "snapshot" A..= p, "coins" A..= ssCoins ss, "survivors" A..= ssSurvivors ss
          , "spent_in_range" A..= ssSpent ss, "hints_below_from" A..= ssHintsBelow ss ])
        Left e -> pushErr (cxErrors ctx) "startset" from e >> return (pAggOut part, A.Null)
    _ -> return (pAggOut part, A.Null)

  -- ---- completeness [extension b]
  let seenCount = Map.fromListWith (+) [ (h, 1 :: Int) | h <- seenL ]
      missing = [ h | h <- [from .. to], Map.notMember h seenCount ]
      dups = [ h | (h, c) <- Map.toList seenCount, c > 1 ]
  unless (null missing) $ pushErr (cxErrors ctx) "completeness" (head missing)
    (show (length missing) ++ " heights never processed, first " ++ show (take 5 missing))
  unless (null dups) $ pushErr (cxErrors ctx) "completeness" (head dups)
    (show (length dups) ++ " heights processed twice: " ++ show (take 5 dups))
  -- ---- BIP30 coinbase-txid uniqueness [extension c]
  let cbs = [ (SBS.fromShort t, hh) | (t, hh) <- sort cbs0 ]
  forM_ (zip cbs (drop 1 cbs)) $ \((t1, h1), (t2, h2)) ->
    when (t1 == t2) $ pushErr (cxErrors ctx) "BIP30" h2
      ("duplicate coinbase txid " ++ showHash t1 ++ " at " ++ show h1 ++ " and " ++ show h2)
  BL.writeFile (aOut a </> "bip30-coinbase.bin") $ BB.toLazyByteString $
    mconcat [ BB.byteString t <> BB.word32LE hh | (t, hh) <- cbs ]

  -- ---- verdict
  let expectedInputs = sum [ fromIntegral n | h <- [max 1 from .. to], Just (_, _, n) <- [undoEntry pack h] ] :: Word64
      standalone = from == 0 || maybe False (const True) (aStartSnap a)
      completeToHints = to == hnH hints
  errs <- reverse <$> readIORef errsL
  nErrors <- readIORef errsC
  let fired0 = nub (sort [ k | (k, _, _) <- errs ])
      aggEqual = pAggIn part == aggOut
      fired1 = fired0
        ++ [ "aggregate" | standalone && completeToHints && not aggEqual ]
        ++ [ "aggregate-zero" | standalone && completeToHints && (pAggIn part == aggZero || aggOut == aggZero) ]
      -- script-count denominator: every input consumed from U was dispatched to
      -- the node's script checker (recordScriptChecks counts at dispatch), and
      -- the inputs consumed equal Σ n_inputs of undo.idx over the range
      scriptCountBad = scriptsRun /= pInputs part
        || (pInputs part /= expectedInputs && cDropBlock ctl == Nothing && cDupBlock ctl == Nothing)
      fired = fired1 ++ [ "script-count" | scriptCountBad ]
      verdict = if null fired then "PASS" else "FAIL" :: String
  appliedL <- reverse <$> readIORef appliedRef
  exe <- exeSha256
  rss <- vmHwmKb
  t1 <- getPOSIXTime
  let totalS = realToFrac (t1 - t0) :: Double
      errStr (k, hh, m) = k ++ " @" ++ show hh ++ ": " ++ m
      res = A.object
        [ "tool" A..= ("haskoin swiftsync-pass" :: String)
        , "node" A..= ("haskoin" :: String)
        , "network" A..= aNetwork a
        , "exe_sha256" A..= exe
        , "validation_path" A..= ("app/Main.hs syncMessageHandler MBlock connect arm: addHeader (phase 0, addHeaderAt) + validateBlockGuarded (validateFullBlockIO db net cs getMtpBg skipScripts=False block spent) -> checkBIP30, validateFullBlock (maturity, checkpoints, CheckBlock, ContextualCheckBlock, IsFinal/BIP113, BIP68, validateBlockTransactions + script checks, subsidy, sigops, witness commitment)" :: String)
        , "script_dispatch" A..= scriptMode
        , "range" A..= [from, to]
        , "hints_height" A..= hnH hints
        , "hints_dir" A..= fromMaybe (aPack a) (aHints a)
        , "standalone" A..= standalone
        , "composes" A..= not standalone
        , "control" A..= (if null (aControl a) then A.Null else A.toJSON (aControl a))
        , "block_file" A..= aBlockFile a
        , "control_applied" A..= appliedL
        , "salt" A..= BC.unpack (B16.encode salt)
        , "agg_in" A..= aggHex (pAggIn part)
        , "agg_out" A..= aggHex aggOut
        , "agg_out_blocks_only" A..= aggHex (pAggOut part)
        , "agg_equal" A..= aggEqual
        , "scripts_run" A..= scriptsRun
        , "scripts_counter" A..= ("Haskoin.Consensus.readScriptChecksTotal (recordScriptChecks: input script checks dispatched by validateBlockTransactions)" :: String)
        , "inputs" A..= pInputs part
        , "inputs_connected" A..= pInputsConnected part
        , "expected_inputs_undo_idx" A..= expectedInputs
        , "missing_heights" A..= length missing
        , "duplicate_heights" A..= length dups
        , "start_set" A..= startJson
        , "stats" A..= A.object
            [ "blocks" A..= pBlocks part, "txs" A..= pTxs part, "outputs" A..= pOutputs part
            , "hinted" A..= pHinted part, "agg_out_terms" A..= pAggOutTerms part, "skipped" A..= pSkipped part
            , "same_block" A..= pSameBlock part, "bip30_coinbases" A..= length cbs
            , "hints_in_range" A..= hintsCountRange hints from to ]
        , "fired" A..= fired
        , "errors" A..= map errStr errs
        , "n_errors" A..= nErrors
        , "threads" A..= threads
        , "timing_s" A..= A.object [ "phase0_headers" A..= phase0, "phase1_blocks" A..= phase1, "total" A..= totalS ]
        , "throughput" A..= A.object
            [ "blocks_per_s" A..= (fromIntegral (pBlocks part) / max 1e-9 phase1 :: Double)
            , "inputs_per_s" A..= (fromIntegral (pInputs part) / max 1e-9 phase1 :: Double) ]
        , "rss_peak_kib" A..= rss
        , "verdict" A..= verdict ]
  BL.writeFile (aOut a </> "result.json") (A.encode res)
  BL.putStr $ A.encode (A.object
    [ "range" A..= [from, to], "verdict" A..= verdict, "fired" A..= fired, "agg_equal" A..= aggEqual
    , "scripts_run" A..= scriptsRun, "inputs" A..= pInputs part, "expected_inputs_undo_idx" A..= expectedInputs
    , "n_errors" A..= nErrors, "first_error" A..= fmap errStr (if null errs then Nothing else Just (head errs))
    , "elapsed_s" A..= totalS ])
  putStrLn ""
  return (verdict == "PASS")
  where
    lookupKey k o = AKM.lookup (AK.fromString k) o
    show' = T.unpack

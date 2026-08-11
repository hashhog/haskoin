{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | EXECUTED before/after proof for the reworked restart-path header
-- reload gate + chainstate rewind (rework of the reverted b6694c4 gate,
-- whose truncate-only behaviour wedged block download on the 2026-08
-- mainnet deploy).
--
-- What this proves, on a REAL on-disk RocksDB seeded exclusively through
-- the production writer ('connectBlock' — which persists header, height
-- row, body, undo record and best-block pointer in one atomic batch):
--
--   1. WEDGE REPRO (the reverted deploy's failure, executed): with the
--      gate truncating at a poisoned bad-diffbits row at height 3 but NO
--      chainstate rewind (b6694c4 behaviour), the boot reconciliation
--      re-stamps the best-block pointer backward to hash(2) while the
--      UTXO set still reflects height 5 — and the re-downloaded block 4
--      (which spends block 1's coinbase) is REJECTED by the real
--      'connectBlock' (G19 missing prevout: its input was already spent
--      when block 4 first connected).  nextBlock can never advance past
--      it: the frozen-connected-tip wedge, reproduced.
--
--   2. FIX (the rework, executed against the REAL library function):
--      same poisoned DB, gate truncates at height 2 (fail-closed
--      preserved), then the REAL 'rewindChainstateToPrefix' disconnects
--      blocks 5,4,3 via their undo records, deletes their stale undo +
--      height-index rows, restores block 1's coinbase coin, and leaves
--      best-block == hash(2) — a normal boot of a 2-high node.  The
--      simulated P2P re-download then re-connects blocks 3,4,5 through
--      the real 'connectBlock' ALL-GREEN to the tip.  "Reload truncates
--      at a bad header -> node still downloads blocks to tip."
--
--   3. CONTROL: an all-valid DB loads fully with no truncation signal,
--      and a rewind against a full prefix is a no-op (Right 0).
--
--   4. SNAPSHOT FLOOR: a chainstate resting on an assumeutxo snapshot
--      base outside the validated prefix makes the rewind fail Left
--      (fail-hard, refuse-to-start) instead of silently booting into
--      the wedge.
--
-- The reload loop below is a faithful transcription of the reworked
-- Main.hs `go` loop; the gate checks are copied VERBATIM and call the
-- real library functions.  'rewindChainstateToPrefix', 'connectBlock',
-- 'disconnectBlockAt' (via the rewind), 'buildSpentUtxoMapFromDB' are
-- the REAL production functions, not transcriptions.
--
-- Run: cabal test reload-rewind-test   (or cabal run reload-rewind-test)
module Main (main) where

import Haskoin.Types
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Data.Word (Word32, Word64, Word8)
import Data.Maybe (isJust, isNothing)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Numeric (showHex)
import System.Directory (doesDirectoryExist, removeDirectoryRecursive,
                         createDirectoryIfMissing, getTemporaryDirectory)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hSetBuffering, stdout, BufferMode(..))
import Control.Monad (when, unless, forM_, foldM)
import Data.IORef (newIORef, modifyIORef', readIORef)

--------------------------------------------------------------------------------
-- Custom regtest-shaped net: genesis runs at a "real" (hard) difficulty,
-- so a min-difficulty header is strictly EASIER = the exploit direction
-- (the camlcoin shape the original audit flagged).  netPowNoRetargeting =
-- True on regtest => difficultyAdjustment returns the parent's bits, so
-- every child's expected bits = hardBits and the planted min-diff header
-- fails bad-diffbits.
--------------------------------------------------------------------------------

hardTarget :: Integer
hardTarget = 2 ^ (252 :: Int)

hardBits :: Word32
hardBits = targetToBits hardTarget

minDiffBits :: Word32
minDiffBits = targetToBits (netPowLimit regtest)

customNet :: Network
customNet =
  let g0  = netGenesisBlock regtest
      hdr = (blockHeader g0) { bhBits = hardBits }
  in regtest { netName = "regtest-hardgen"
             , netGenesisBlock = g0 { blockHeader = hdr } }

genesisBlk :: Block
genesisBlk = netGenesisBlock customNet

genesisHdr :: BlockHeader
genesisHdr = blockHeader genesisBlk

genesisHash :: BlockHash
genesisHash = computeBlockHash genesisHdr

--------------------------------------------------------------------------------
-- Real blocks: coinbases with distinct txids + one NON-COINBASE SPEND
-- (block 4 spends block 1's coinbase) — the spend is what makes the
-- truncate-only wedge visible; a coinbase-only chain would reconnect.
--------------------------------------------------------------------------------

spkSeeded :: Word8 -> BS.ByteString
spkSeeded seed = BS.concat
  [ BS.pack [0x76, 0xa9, 20], BS.replicate 20 seed, BS.pack [0x88, 0xac] ]

mkCoinbase :: Word32 -> Word64 -> Word8 -> Tx
mkCoinbase height val seed = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
      , txInScript     = BS.pack [ 0x03
                                 , fromIntegral (height `mod` 256)
                                 , fromIntegral ((height `div` 256) `mod` 256)
                                 , fromIntegral ((height `div` 65536) `mod` 256) ]
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut val (spkSeeded seed) ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

mkSpend :: OutPoint -> Word64 -> Word8 -> Tx
mkSpend prev val seed = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn { txInPrevOutput = prev
                        , txInScript     = BS.pack [0x51]
                        , txInSequence   = 0xffffffff } ]
  , txOutputs  = [ TxOut val (spkSeeded seed) ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

grindHeader :: BlockHash -> Word32 -> Word32 -> BlockHeader
grindHeader prev bits ts = go 0
  where
    mk n = BlockHeader
      { bhVersion    = 1
      , bhPrevBlock  = prev
      , bhMerkleRoot = bhMerkleRoot genesisHdr
      , bhTimestamp  = ts
      , bhBits       = bits
      , bhNonce      = n
      }
    go n = let h = mk n
           in if checkProofOfWork h (netPowLimit customNet) then h else go (n + 1)

cb1, cb2, cb3, cb4, cb5, spendTx :: Tx
cb1 = mkCoinbase 1 5000000000 0x11
cb2 = mkCoinbase 2 5000000000 0x22
cb3 = mkCoinbase 3 5000000000 0x33
cb4 = mkCoinbase 4 5000000000 0x44
cb5 = mkCoinbase 5 5000000000 0x55

-- Block 4 spends block 1's coinbase output — the non-coinbase spend.
c1Outpoint :: OutPoint
c1Outpoint = OutPoint (computeTxId cb1) 0

spendTx = mkSpend c1Outpoint 4999000000 0x99

b1, b2, b3, b4, b5 :: Block
b1 = Block (grindHeader genesisHash            hardBits 1300000100) [cb1]
b2 = Block (grindHeader (blkHash b1)           hardBits 1300000200) [cb2]
b3 = Block (grindHeader (blkHash b2)           hardBits 1300000300) [cb3]
b4 = Block (grindHeader (blkHash b3)           hardBits 1300000400) [cb4, spendTx]
b5 = Block (grindHeader (blkHash b4)           hardBits 1300000500) [cb5]

blkHash :: Block -> BlockHash
blkHash = computeBlockHash . blockHeader

-- The planted exploit header at height 3: min-difficulty, forking off b2.
plantedBad :: BlockHeader
plantedBad = grindHeader (blkHash b2) minDiffBits 1300000300

--------------------------------------------------------------------------------
-- Seeding: EXCLUSIVELY through the production writer.
--------------------------------------------------------------------------------

seedConnectedChain :: HaskoinDB -> IO (Either String ())
seedConnectedChain db = do
  r0 <- connectBlock db customNet genesisBlk 0 Map.empty
  case r0 of
    Left e -> return (Left ("genesis: " <> e))
    Right () ->
      foldM
        (\acc (h, blk) -> case acc of
            Left e -> return (Left e)
            Right () -> do
              spent <- buildSpentUtxoMapFromDB db blk
              r <- connectBlock db customNet blk h spent
              return $ either (Left . (("block " <> show h <> ": ") <>)) Right r)
        (Right ())
        (zip [1 ..] [b1, b2, b3, b4, b5])

-- Overwrite the height-3 row with the poisoned header (the torn/poisoned
-- on-disk shape the gate exists to refuse).  The chainstate (undo records,
-- best pointer at b5, UTXO set) is left exactly as connectBlock wrote it.
plantPoison :: HaskoinDB -> IO ()
plantPoison db = do
  let badHash = computeBlockHash plantedBad
  putBlockHeader db badHash plantedBad
  putBlockHeight db 3 badHash

--------------------------------------------------------------------------------
-- Faithful transcription of the reworked Main.hs initHeaderChainFromDB
-- `go` loop.  Gate checks VERBATIM; returns (entries, prefixTip, Maybe
-- truncatedAtEntry) like the reworked loop's truncation signal.
--------------------------------------------------------------------------------

reloadLoop :: HaskoinDB
           -> IO (Map.Map BlockHash ChainEntry, ChainEntry, Maybe ChainEntry)
reloadLoop db = do
  let genesisEntry = ChainEntry
        { ceHeader     = genesisHdr
        , ceHash       = genesisHash
        , ceHeight     = 0
        , ceChainWork  = headerWork genesisHdr
        , cePrev       = Nothing
        , ceStatus     = StatusValid
        , ceMedianTime = bhTimestamp genesisHdr
        , ceSequenceId = seqIdBestChainFromDisk
        }
  go (Map.singleton genesisHash genesisEntry) 1 genesisEntry
  where
    go entriesSoFar height prevEntry = do
      mHash <- getBlockHeight db height
      case mHash of
        Nothing -> return (entriesSoFar, prevEntry, Nothing)
        Just bh -> do
          mHeader <- getBlockHeader db bh
          case mHeader of
            Nothing     -> return (entriesSoFar, prevEntry, Just prevEntry)
            Just header -> do
              let refuse _reason = return (entriesSoFar, prevEntry, Just prevEntry)
                  admit = do
                    let work  = ceChainWork prevEntry + headerWork header
                        entry = ChainEntry
                          { ceHeader     = header
                          , ceHash       = bh
                          , ceHeight     = height
                          , ceChainWork  = work
                          , cePrev       = Just (ceHash prevEntry)
                          , ceStatus     = StatusValid
                          , ceMedianTime = bhTimestamp header
                          , ceSequenceId = seqIdBestChainFromDisk
                          }
                    go (Map.insert bh entry entriesSoFar) (height + 1) entry
              -- ==== VERBATIM from app/Main.hs initHeaderChainFromDB ====
              if bhPrevBlock header /= ceHash prevEntry
                then refuse "prev-hash does not link to loaded parent"
              else if computeBlockHash header /= bh
                then refuse "stored hash does not match header hash"
              else if not (checkProofOfWork header (netPowLimit customNet))
                then refuse "proof of work check failed"
              else if bhBits header
                      /= difficultyAdjustment customNet entriesSoFar
                           prevEntry header
                then refuse "bad-diffbits"
              else admit

-- Transcription of the reconciliation's connected-tip probe (Main.hs
-- findConnectedTip): binary search over undo records, capped at the
-- LOADED header tip — the cap is what turned truncation into the wedge.
findConnectedTipCapped :: HaskoinDB -> Word32 -> IO Word32
findConnectedTipCapped db headerTip = do
  let blockIsConnected h = do
        mh <- getBlockHeight db h
        case mh of
          Nothing -> return False
          Just bh -> isJust <$> getUndoData db bh
      search lo hi
        | lo >= hi  = return lo
        | otherwise = do
            let mid = lo + (hi - lo + 1) `div` 2
            c <- blockIsConnected mid
            if c then search mid hi else search lo (mid - 1)
  if headerTip == 0
    then return 0
    else do
      one <- blockIsConnected 1
      if not one then return 0 else search 1 headerTip

--------------------------------------------------------------------------------
-- Assertion plumbing
--------------------------------------------------------------------------------

check :: Show a => Eq a => String -> a -> a -> IO Bool
check label got expected = do
  let ok = got == expected
  putStrLn $ "  [" ++ (if ok then "PASS" else "FAIL") ++ "] " ++ label
           ++ (if ok then "" else "  got=" ++ show got
                                 ++ " expected=" ++ show expected)
  return ok

checkBool :: String -> Bool -> IO Bool
checkBool label ok = do
  putStrLn $ "  [" ++ (if ok then "PASS" else "FAIL") ++ "] " ++ label
  return ok

freshDB :: FilePath -> String -> IO HaskoinDB
freshDB baseDir name = do
  let path = baseDir ++ "/" ++ name
  ex <- doesDirectoryExist path
  when ex $ removeDirectoryRecursive path
  createDirectoryIfMissing True path
  openDB (defaultDBConfig path)

--------------------------------------------------------------------------------

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  tmp <- getTemporaryDirectory
  let baseDir = tmp ++ "/haskoin-reload-rewind-test"
  createDirectoryIfMissing True baseDir
  failures <- newIORef (0 :: Int)
  let run label ios = do
        putStrLn $ "\n===== " ++ label ++ " ====="
        oks <- sequence ios
        unless (and oks) $ modifyIORef' failures (+ length (filter not oks))

  putStrLn $ "hardBits=0x" ++ showHex hardBits ""
           ++ " minDiffBits=0x" ++ showHex minDiffBits ""
           ++ " (planted header claims min-diff off a real-difficulty parent)"

  ------------------------------------------------------------------
  -- ARM 1: WEDGE REPRO — truncate-only (b6694c4 deploy behaviour).
  ------------------------------------------------------------------
  db1 <- freshDB baseDir "wedge-repro"
  s1 <- seedConnectedChain db1
  plantPoison db1
  (_, prefixTip1, mTrunc1) <- reloadLoop db1
  -- Reconciliation as at HEAD: cap the connected-tip probe at the
  -- truncated header tip and re-stamp best-block BACKWARD (no rewind).
  connTip1 <- findConnectedTipCapped db1 (ceHeight prefixTip1)
  mRow2 <- getBlockHeight db1 connTip1
  forM_ mRow2 (putBestBlockHash db1)
  -- Simulated P2P re-download of the gap through the REAL connect path.
  spent3 <- buildSpentUtxoMapFromDB db1 b3
  r3pre  <- connectBlock db1 customNet b3 3 spent3
  spent4 <- buildSpentUtxoMapFromDB db1 b4
  r4pre  <- connectBlock db1 customNet b4 4 spent4
  run "ARM 1: truncate-only (reverted deploy) WEDGES block re-download"
    [ checkBool "chain seeded through real connectBlock" (s1 == Right ())
    , check "gate refuses poisoned row; truncates at height"
        (ceHeight prefixTip1) 2
    , checkBool "truncation signalled" (isJust mTrunc1)
    , check "capped reconciliation reports connected tip = truncated tip"
        connTip1 2
    , checkBool
        ("re-download WEDGES: block 4 (spends b1 coinbase) REJECTED by "
         ++ "connectBlock (inputs already spent; G19)")
        (case r4pre of Left _ -> True; Right () -> False)
    , checkBool "(block 3, coinbase-only, reconnects — the spend is what wedges)"
        (r3pre == Right ())
    ]

  ------------------------------------------------------------------
  -- ARM 2: THE FIX — gate + REAL rewindChainstateToPrefix, then the
  -- node downloads blocks to tip.
  ------------------------------------------------------------------
  db2 <- freshDB baseDir "fix"
  s2 <- seedConnectedChain db2
  plantPoison db2
  (entries2, prefixTip2, mTrunc2) <- reloadLoop db2
  preBest <- getBestBlockHash db2
  rw <- rewindChainstateToPrefix db2 (`Map.member` entries2)
          (ceHeight prefixTip2) Nothing
  postBest  <- getBestBlockHash db2
  undo3     <- getUndoData db2 (blkHash b3)
  undo4     <- getUndoData db2 (blkHash b4)
  undo5     <- getUndoData db2 (blkHash b5)
  row3      <- getBlockHeight db2 3
  row4      <- getBlockHeight db2 4
  row5      <- getBlockHeight db2 5
  c1coin    <- getUTXOCoin db2 c1Outpoint
  connTip2  <- findConnectedTipCapped db2 (ceHeight prefixTip2)
  -- Simulated P2P re-download of the tail through the REAL connect path
  -- (headers-first sync re-fetches 3..5 through the live gate; the
  -- block-gap kicker then getdatas the bodies; MBlock connects them).
  reconnect <- foldM
    (\acc (h, blk) -> case acc of
        Left e -> return (Left e)
        Right () -> do
          spent <- buildSpentUtxoMapFromDB db2 blk
          r <- connectBlock db2 customNet blk h spent
          return $ either (Left . (("block " <> show h <> ": ") <>)) Right r)
    (Right ())
    (zip [3 ..] [b3, b4, b5])
  tipBest  <- getBestBlockHash db2
  c1spent  <- getUTXOCoin db2 c1Outpoint
  undo5b   <- getUndoData db2 (blkHash b5)
  row5b    <- getBlockHeight db2 5
  run "ARM 2: rework — gate refuses, rewind restores, node re-downloads to TIP"
    [ checkBool "chain seeded through real connectBlock" (s2 == Right ())
    , check "gate still refuses poisoned row (fail-closed); truncates at"
        (ceHeight prefixTip2) 2
    , checkBool "truncation signalled" (isJust mTrunc2)
    , check "pre-rewind best-block was the (stale) height-5 tip"
        preBest (Just (blkHash b5))
    , check "rewindChainstateToPrefix disconnected exactly blocks 5,4,3"
        rw (Right 3)
    , check "best-block re-stamped to validated prefix tip hash(2) BY the rewind"
        postBest (Just (blkHash b2))
    , checkBool "stale undo records 3/4/5 deleted"
        (isNothing undo3 && isNothing undo4 && isNothing undo5)
    , checkBool "stale height-index rows 3/4/5 deleted"
        (isNothing row3 && isNothing row4 && isNothing row5)
    , checkBool "block 1 coinbase coin RESTORED (spend undone)" (isJust c1coin)
    , check "reconciliation now agrees: connected tip == header tip == 2"
        connTip2 2
    , check "re-download CONNECTS 3,4,5 through real connectBlock (no wedge)"
        reconnect (Right ())
    , check "node reaches the tip: best-block == hash(5)"
        tipBest (Just (blkHash b5))
    , checkBool "block 1 coinbase re-spent at tip (state converged)"
        (isNothing c1spent)
    , checkBool "undo + height rows re-written for the re-connected tail"
        (isJust undo5b && row5b == Just (blkHash b5))
    ]

  ------------------------------------------------------------------
  -- ARM 3: CONTROL — all-valid DB: no truncation, rewind is a no-op.
  ------------------------------------------------------------------
  db3 <- freshDB baseDir "control"
  s3 <- seedConnectedChain db3
  (entries3, prefixTip3, mTrunc3) <- reloadLoop db3
  rwNoop <- rewindChainstateToPrefix db3 (`Map.member` entries3)
              (ceHeight prefixTip3) Nothing
  best3 <- getBestBlockHash db3
  run "ARM 3: control — all-valid chain loads fully; rewind no-op"
    [ checkBool "chain seeded" (s3 == Right ())
    , check "loads fully to height 5" (ceHeight prefixTip3) 5
    , checkBool "no truncation signal" (isNothing mTrunc3)
    , check "rewind against full prefix = Right 0 (no-op)" rwNoop (Right 0)
    , check "best-block untouched" best3 (Just (blkHash b5))
    ]

  ------------------------------------------------------------------
  -- ARM 4: SNAPSHOT FLOOR — chainstate on an assumeutxo base outside
  -- the prefix must fail Left (refuse-to-start), never boot wedged.
  ------------------------------------------------------------------
  db4 <- freshDB baseDir "snapshot-floor"
  s4 <- seedConnectedChain db4
  rwSnap <- rewindChainstateToPrefix db4
              (== genesisHash)  -- prefix = genesis only
              0
              (Just (blkHash b5))  -- best (b5) IS the snapshot base
  run "ARM 4: snapshot base outside prefix -> rewind refuses (fail-hard)"
    [ checkBool "chain seeded" (s4 == Right ())
    , checkBool "Left mentioning the snapshot base"
        (case rwSnap of
           Left e  -> "snapshot" `elemSub` e
           Right _ -> False)
    ]

  closeDB db1
  closeDB db2
  closeDB db3
  closeDB db4

  n <- readIORef failures
  putStrLn $ "\n================== SUMMARY =================="
  if n == 0
    then do
      putStrLn "ALL PASS — wedge reproduced under truncate-only, GONE under rework."
      exitSuccess
    else do
      putStrLn $ show n ++ " CHECK(S) FAILED"
      exitFailure
  where
    elemSub needle hay = any (needle `isPrefixOfStr`) (suffixes hay)
    suffixes s = case s of [] -> [[]]; (_:rest) -> s : suffixes rest
    isPrefixOfStr p s = take (length p) s == p

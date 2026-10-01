{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | EXECUTED proof for the boot-reconciliation forward-move guard
-- (mainnet 2026-10-01: haskoin re-stamped its tip from 961631 to 966500
-- over 4,869 blocks whose UTXO effects were never applied, then failed
-- every connect of 966501 with "Missing UTXO").
--
-- Shape reproduced, on a REAL RocksDB seeded only through the production
-- writer 'connectBlock':
--   OLD CHAIN  : blocks 1..5 connected (undo records 1..5 written).
--   RE-BOOTSTRAP: 'wipeChainstate' (the -reindex-chainstate step run before
--                 --load-snapshot), then the NEW chain reconnects 1..2.
--   => coin set at height 2, but undo records for 3..5 survive if the wipe
--      does not purge them, and the undo-record binary search says 5.
--
-- ARM 1 (fix 1): wipeChainstate must purge the undo records.
--        PRE-FIX: FAILS (3..5 survive).
-- ARM 2 (wedge repro, old reconciliation): planting the stale undo
--        records directly, the verbatim old behaviour (re-stamp to the
--        undo estimate) re-stamps best-block to hash(5) and the real
--        connectBlock of block 6 (spends block 3's coinbase) fails.
-- ARM 3 (fix 2): capConnectedTipByUtxo keeps the pointer at 2, purges
--        undo 3..5, and blocks 3..6 then connect through connectBlock.
-- ARM 4 (control, W162 recovery preserved): best-block reset to genesis
--        on an intact coin set at 5 -> forward move to 5 is PROVEN, kept.
-- ARM 5 (control): healthy node -> (5, 0), nothing purged.
-- ARM 6 (fail closed): unproven estimate + unresolvable pointer -> Left.
module Main (main) where

import Haskoin.Types
import Haskoin.Consensus
import Haskoin.Storage
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Data.Word (Word32, Word64, Word8)
import Data.Maybe (isJust, isNothing)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import System.Directory (doesDirectoryExist, removeDirectoryRecursive,
                         createDirectoryIfMissing, getTemporaryDirectory)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hSetBuffering, stdout, BufferMode(..))
import Control.Monad (when, unless, foldM, forM)
import Data.IORef (newIORef, modifyIORef', readIORef)

hardTarget :: Integer
hardTarget = 2 ^ (252 :: Int)

hardBits :: Word32
hardBits = targetToBits hardTarget


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


cb6 :: Tx
cb6 = mkCoinbase 6 5000000000 0x66

-- Block 6 spends block 3's coinbase: present iff block 3 was applied.
spend3 :: Tx
spend3 = mkSpend (OutPoint (computeTxId cb3) 0) 4999000000 0x98

b6 :: Block
b6 = Block (grindHeader (blkHash b5) hardBits 1300000600) [cb6, spend3]

allBlocks :: [Block]
allBlocks = [b1, b2, b3, b4, b5, b6]

connectRange :: HaskoinDB -> [(Word32, Block)] -> IO (Either String ())
connectRange db = foldM step (Right ())
  where
    step (Left e) _ = return (Left e)
    step (Right ()) (h, blk) = do
      spent <- buildSpentUtxoMapFromDB db blk
      r <- connectBlock db customNet blk h spent
      return $ either (Left . (("block " <> show h <> ": ") <>)) Right r

-- Transcription of Main.hs findConnectedTip (genesis-up branch).
undoEstimate :: HaskoinDB -> Word32 -> IO Word32
undoEstimate db headerTip = do
  let isConn h = do
        mh <- getBlockHeight db h
        case mh of
          Nothing -> return False
          Just bh -> isJust <$> getUndoData db bh
      search lo hi
        | lo >= hi  = return lo
        | otherwise = do
            let mid = lo + (hi - lo + 1) `div` 2
            c <- isConn mid
            if c then search mid hi else search lo (mid - 1)
  one <- isConn 1
  if not one then return 0 else search 1 headerTip

-- Height-index rows for the whole header chain 1..6 (headers-first: the
-- MHeaders handler persists these ahead of block connection).
writeHeaderRows :: HaskoinDB -> IO ()
writeHeaderRows db =
  mapM_ (\(h, blk) -> do putBlockHeader db (blkHash blk) (blockHeader blk)
                         putBlockHeight db h (blkHash blk))
        (zip [1 ..] allBlocks)

-- Old chain to 5, then re-bootstrap: wipe + reconnect 1..2.
seedRebootstrapped :: HaskoinDB -> IO (Either String ())
seedRebootstrapped db = do
  s <- seedConnectedChain db
  case s of
    Left e -> return (Left e)
    Right () -> do
      _ <- wipeChainstate db
      g <- connectBlock db customNet genesisBlk 0 Map.empty
      case g of
        Left e -> return (Left ("genesis: " <> e))
        Right () -> connectRange db (zip [1 ..] [b1, b2])

-- Same coin-set shape, but with undo records 3..5 RE-PLANTED (as a
-- pre-fix wipe leaves them), so arms 2/3 are independent of fix 1.
seedStaleUndo :: HaskoinDB -> IO (Either String ())
seedStaleUndo db = do
  s <- seedConnectedChain db
  case s of
    Left e -> return (Left e)
    Right () -> do
      saved <- forM [b3, b4, b5] $ \blk -> do
        u <- getUndoData db (blkHash blk)
        return (blkHash blk, u)
      _ <- wipeChainstate db
      mapM_ (\(bh, mu) -> maybe (return ()) (putUndoData db bh) mu) saved
      g <- connectBlock db customNet genesisBlk 0 Map.empty
      case g of
        Left e -> return (Left ("genesis: " <> e))
        Right () -> do
          r <- connectRange db (zip [1 ..] [b1, b2])
          writeHeaderRows db
          return r

check :: (Show a, Eq a) => String -> a -> a -> IO Bool
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

main :: IO ()
main = do
  hSetBuffering stdout NoBuffering
  tmp <- getTemporaryDirectory
  let baseDir = tmp ++ "/haskoin-reconcile-forward-test"
  createDirectoryIfMissing True baseDir
  failures <- newIORef (0 :: Int)
  total <- newIORef (0 :: Int)
  let run label ios = do
        putStrLn $ "\n===== " ++ label ++ " ====="
        oks <- sequence ios
        modifyIORef' total (+ length oks)
        unless (and oks) $ modifyIORef' failures (+ length (filter not oks))
      hashAt db = getBlockHeight db

  -- ARM 1 -----------------------------------------------------------
  db1 <- freshDB baseDir "wipe-purges-undo"
  s1 <- seedRebootstrapped db1
  u1 <- mapM (\b -> isJust <$> getUndoData db1 (blkHash b)) [b1, b2, b3, b4, b5]
  run "ARM 1: wipeChainstate purges undo records of the wiped coin set"
    [ checkBool "seeded (old chain 1..5, wipe, new chain 1..2)" (s1 == Right ())
    , check "undo present for [b1..b5] after re-bootstrap"
        u1 [True, True, False, False, False]
    ]

  -- ARM 2 -----------------------------------------------------------
  db2 <- freshDB baseDir "old-reconcile-wedge"
  s2 <- seedStaleUndo db2
  est2 <- undoEstimate db2 6
  cb3in2 <- coinbaseApplied db2 3 (blkHash b3)
  -- verbatim OLD behaviour: re-stamp best-block to the estimate.
  Just t2 <- getBlockHeight db2 est2
  putBestBlockHash db2 t2
  c6 <- connectRange db2 [(6, b6)]
  run "ARM 2: wedge repro — old reconciliation trusts stale undo"
    [ checkBool "seeded" (s2 == Right ())
    , check "undo-record estimate claims tip 5 (coin set is at 2)" est2 5
    , check "block 3 coinbase NOT in coin set" cb3in2 (Just False)
    , checkBool "block 6 (spends cb3) REJECTED after re-stamp to 5 (the wedge)"
        (either (const True) (const False) c6)
    ]

  -- ARM 3 -----------------------------------------------------------
  db3 <- freshDB baseDir "fixed-reconcile"
  s3 <- seedStaleUndo db3
  est3 <- undoEstimate db3 6
  capped3 <- capConnectedTipByUtxo db3 (hashAt db3) (Just 2) est3
  undoAfter <- mapM (\b -> isJust <$> getUndoData db3 (blkHash b)) [b3, b4, b5]
  est3b <- undoEstimate db3 6
  best3 <- getBestBlockHash db3
  rc <- connectRange db3 (zip [3 ..] [b3, b4, b5, b6])
  best3b <- getBestBlockHash db3
  run "ARM 3: fix — forward move refused, stale undo purged, sync resumes"
    [ checkBool "seeded" (s3 == Right ())
    , check "estimate still 5 before the guard" est3 5
    , check "guard keeps pointer: Right (2, 3 purged)" capped3 (Right (2, 3))
    , check "undo for b3..b5 gone" undoAfter [False, False, False]
    , check "next boot's estimate is honest (2)" est3b 2
    , check "best-block untouched at hash(2)" best3 (Just (blkHash b2))
    , check "blocks 3..6 connect through real connectBlock" rc (Right ())
    , check "tip reaches hash(6)" best3b (Just (blkHash b6))
    ]

  -- ARM 4 -----------------------------------------------------------
  db4 <- freshDB baseDir "w162-genesis-pointer"
  s4 <- seedConnectedChain db4
  putBestBlockHash db4 genesisHash
  est4 <- undoEstimate db4 5
  capped4 <- capConnectedTipByUtxo db4 (hashAt db4) (Just 0) est4
  u4 <- isJust <$> getUndoData db4 (blkHash b5)
  run "ARM 4: control — W162 genesis-reset pointer still recovers forward"
    [ checkBool "seeded" (s4 == Right ())
    , check "estimate 5" est4 5
    , check "proven forward move kept: Right (5, 0)" capped4 (Right (5, 0))
    , checkBool "undo b5 kept" u4
    ]

  -- ARM 5 -----------------------------------------------------------
  db5 <- freshDB baseDir "healthy"
  s5 <- seedConnectedChain db5
  est5 <- undoEstimate db5 5
  capped5 <- capConnectedTipByUtxo db5 (hashAt db5) (Just 5) est5
  run "ARM 5: control — healthy node unchanged"
    [ checkBool "seeded" (s5 == Right ())
    , check "Right (5, 0)" capped5 (Right (5, 0))
    ]

  -- ARM 6 -----------------------------------------------------------
  db6 <- freshDB baseDir "unprovable"
  s6 <- seedStaleUndo db6
  capped6 <- capConnectedTipByUtxo db6 (hashAt db6) Nothing 5
  run "ARM 6: unprovable state fails closed"
    [ checkBool "seeded" (s6 == Right ())
    , checkBool "Left (refuse to start)"
        (either (const True) (const False) capped6)
    ]

  mapM_ closeDB [db1, db2, db3, db4, db5, db6]
  n <- readIORef failures
  t <- readIORef total
  putStrLn $ "\n" ++ show t ++ " checks, " ++ show n ++ " failed"
  if n == 0 && t > 0 then exitSuccess else exitFailure

-- | OFFLINE chainstate repair for a best-block pointer that the boot
-- reconciliation moved FORWARD over blocks whose UTXO effects were never
-- applied (mainnet 2026-10-01: pointer 966500, coin set at 961631).
--
-- The node MUST be stopped (RocksDB LOCK enforces it: openDB fails while
-- the node holds the DB).  Dry-run by default; nothing is written without
-- --apply.  Every gate is evidence read from the coin set itself:
--
--   G1  height-index row at H == the operator-supplied hash (Core's hash)
--   G2  coinbase of H is in the coin set at height H     (H applied)
--   G3  coinbase of H+1 is NOT in the coin set            (H+1 not applied)
--
-- With all three green, --apply (one WriteBatch, then a sync flush):
--   * PrefixBestBlock := hash(H)
--   * delete the undo record of every active-chain block H+1 .. (first
--     height-index hole) — stale records from a previous coin set, which
--     the reconciliation would otherwise read as "connected" again
--   * with --scan-utxo: delete every coin whose height is > H (e.g. tip
--     outputs written by the tip-hole healer against the wrong tip)
--
-- usage: reconcile-repair <chainstate-dir> <H> <hash-hex> [--scan-utxo] [--apply]
module Main (main) where

import qualified Data.ByteString as BS
import Data.IORef
import Data.Serialize (decode, encode)
import Data.Word (Word32)
import Control.Monad (forM_, unless, when)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import Haskoin.Types
import Haskoin.Storage
import Haskoin.Consensus (coinbaseApplied, hashFromHex, blockHashToHex)

main :: IO ()
main = do
  args <- getArgs
  let flags = filter ((== "--") . take 2) args
      pos   = filter ((/= "--") . take 2) args
      apply = "--apply" `elem` flags
      scanU = "--scan-utxo" `elem` flags
  (dir, h, want) <- case pos of
    [d, hs, hx] -> return (d, read hs :: Word32, hashFromHex hx)
    _ -> putStrLn "usage: reconcile-repair <chainstate-dir> <H> <hash-hex> [--scan-utxo] [--apply]"
         >> exitFailure
  db <- openDB (defaultDBConfig dir) { dbCreateIfMissing = False }
  best <- getBestBlockHash db
  putStrLn $ "current best-block: " ++ maybe "<none>" blockHashToHex best
  row <- getBlockHeight db h
  let g1 = row == Just want
  putStrLn $ "G1 height-index[" ++ show h ++ "] = " ++ maybe "<none>" blockHashToHex row
           ++ " == supplied hash: " ++ show g1
  g2 <- coinbaseApplied db h want
  putStrLn $ "G2 coinbase(" ++ show h ++ ") applied: " ++ show g2
  rowN <- getBlockHeight db (h + 1)
  g3 <- maybe (return Nothing) (coinbaseApplied db (h + 1)) rowN
  putStrLn $ "G3 coinbase(" ++ show (h + 1) ++ ") applied: " ++ show g3
           ++ "  (must be Just False)"
  -- Stale undo records on the active chain above H.
  staleRef <- newIORef ([] :: [BlockHash])
  let walk k = do
        mh <- getBlockHeight db k
        case mh of
          Nothing -> return k
          Just bh -> do
            u <- getUndoData db bh
            when (maybe False (const True) u) $ modifyIORef' staleRef (bh :)
            walk (k + 1)
  holeAt <- walk (h + 1)
  stale <- readIORef staleRef
  putStrLn $ "undo records on the active chain in " ++ show (h + 1) ++ ".."
           ++ show (holeAt - 1) ++ ": " ++ show (length stale)
  -- Coins stamped above H.
  coinsRef <- newIORef ([] :: [BS.ByteString])
  when scanU $ do
    n <- newIORef (0 :: Int)
    iterateWithPrefix db PrefixUTXO $ \k v -> do
      modifyIORef' n (+ 1)
      c <- readIORef n
      when (c `mod` 20000000 == 0) $ putStrLn $ "  scanned " ++ show c ++ " coins"
      case decode v of
        Right coin | coinHeight coin > h -> modifyIORef' coinsRef (k :)
        _ -> return ()
      return True
  above <- readIORef coinsRef
  when scanU $ putStrLn $ "coins with height > " ++ show h ++ ": " ++ show (length above)
  let ok = g1 && g2 == Just True && g3 == Just False
  unless ok $ do
    putStrLn "REFUSING: a gate is not green; nothing written."
    closeDB db >> exitFailure
  if not apply
    then putStrLn "dry-run: all gates green; re-run with --apply to write."
    else do
      let ops = [BatchPut (makeKey PrefixBestBlock BS.empty) (encodeHash want)]
             ++ [BatchDelete (BS.cons 0x10 (encodeHash bh)) | bh <- stale]
             ++ [BatchDelete k | k <- above]
      writeBatch db (WriteBatch ops)
      syncFlush db
      best' <- getBestBlockHash db
      putStrLn $ "APPLIED " ++ show (length ops) ++ " op(s); best-block now "
               ++ maybe "<none>" blockHashToHex best'
      forM_ (take 3 stale) $ \bh -> do
        u <- getUndoData db bh
        putStrLn $ "  post-check undo " ++ blockHashToHex bh ++ " gone: "
                 ++ show (maybe True (const False) u)
  closeDB db
  where
    encodeHash :: BlockHash -> BS.ByteString
    encodeHash = encode

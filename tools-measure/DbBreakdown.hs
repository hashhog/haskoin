-- Measure which key prefix owns the chainstate bytes.
--
-- WHY: haskoin's rig held 508 GB of live chainstate having validated 200,000
-- blocks, where Core's whole UTXO DB at the 958,794 anchor is 11 GB and
-- nimrod's finished rig matches that exactly. Two hypotheses were floated and
-- BOTH were wrong when checked (an unbounded fetch window; a verbose derived
-- encoding — the Serialize Block instance is in fact the plain wire format).
-- This measures instead of inferring: total bytes and entry count per prefix,
-- read through haskoin's own storage layer.
module Main (main) where

import qualified Data.ByteString as BS
import Data.IORef
import Data.List (sortOn)
import Text.Printf (printf)
import System.Environment (getArgs)
import Haskoin.Storage

prefixes :: [(String, KeyPrefix)]
prefixes =
  [ ("BlockData (full blocks)", PrefixBlockData)
  , ("UTXO",                    PrefixUTXO)
  , ("TxIndex",                 PrefixTxIndex)
  , ("BlockHeader",             PrefixBlockHeader)
  , ("BlockHeight",             PrefixBlockHeight)
  , ("BlockStatus",             PrefixBlockStatus)
  , ("ChainWork",               PrefixChainWork)
  ]

main :: IO ()
main = do
  args <- getArgs
  let dir = case args of (d:_) -> d; _ -> error "usage: db-breakdown <datadir>"
  -- createIfMissing = False ON PURPOSE. defaultDBConfig sets it True, and the
  -- first run of this tool was pointed one directory too high: RocksDB happily
  -- CREATED an empty database there and the tool reported 0 entries, 0.00 GB,
  -- exit 0. A measurement that silently invents its own subject is worse than
  -- one that crashes. Now a wrong path fails loudly.
  let cfg = (defaultDBConfig dir) { dbCreateIfMissing = False }
  db <- openDB cfg
  rows <- mapM (measure db) prefixes
  let total = sum (map (\(_,b,_) -> b) rows)
  putStrLn "prefix                    entries        bytes     share"
  putStrLn "------------------------------------------------------------"
  mapM_ (report total) (reverse (sortOn (\(_,b,_) -> b) rows))
  printf "%-24s %10s %12.2f GB\n" "TOTAL" "" (fromIntegral total / 1e9 :: Double)
  closeDB db
 where
  measure db (name, p) = do
    nRef <- newIORef (0 :: Int)
    bRef <- newIORef (0 :: Integer)
    iterateWithPrefix db p $ \k v -> do
      modifyIORef' nRef (+1)
      modifyIORef' bRef (+ fromIntegral (BS.length k + BS.length v))
      return True   -- keep iterating
    n <- readIORef nRef
    b <- readIORef bRef
    return (name, b, n)
  report total (name, b, n) =
    printf "%-24s %10d %10.2f GB  %5.1f%%\n" name n
           (fromIntegral b / 1e9 :: Double)
           (100 * fromIntegral b / fromIntegral (max 1 total) :: Double)

{-# LANGUAGE ScopedTypeVariables #-}
-- | Inert fault-injection points for the chain-lock reproducers
-- (receipts/arch-concurrency-liveness-audit-2026-10-07.md, HK-2..HK-6).
--
-- A hook only ever SLEEPS at a fixed point, and only when armed, so it makes
-- a race deterministic without changing what the code does.  Production is
-- unaffected: unless @HASKOIN_TEST_HOOK_DIR@ is set in the environment every
-- 'hookPoint' is one pure 'Nothing' match.
--
-- Arming: the harness writes a file @<dir>/<name>@ containing a number of
-- milliseconds.  The first thread to reach @hookPoint name@ claims it with an
-- atomic rename (so it fires exactly once), touches @<dir>/<name>.hit@ so the
-- harness knows a thread is parked there, and sleeps.
module Haskoin.TestHooks
  ( hookPoint
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (IOException, try)
import Control.Monad (when)
import System.Directory (doesFileExist, renameFile)
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import System.IO.Unsafe (unsafePerformIO)
import Text.Read (readMaybe)

{-# NOINLINE hookDir #-}
hookDir :: Maybe FilePath
hookDir = unsafePerformIO (lookupEnv "HASKOIN_TEST_HOOK_DIR")

-- | Park the calling thread at @name@ if (and only if) the harness armed it.
hookPoint :: String -> IO ()
hookPoint name = case hookDir of
  Nothing -> return ()
  Just d -> do
    let f = d </> name
        claimed = f ++ ".claimed"
    armed <- doesFileExist f
    when armed $ do
      r <- try (renameFile f claimed)
      case r of
        Left (_ :: IOException) -> return ()       -- another thread won it
        Right () -> do
          s <- readFile claimed
          let ms = maybe 5000 id (readMaybe (takeWhile (/= '\n') s)) :: Int
          length s `seq` writeFile (f ++ ".hit") (show ms)
          threadDelay (ms * 1000)
          writeFile (f ++ ".done") ""

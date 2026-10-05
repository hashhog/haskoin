{-# LANGUAGE ScopedTypeVariables #-}

-- | gate-6: system faults are never consensus verdicts.
--
-- Two pieces every validation path shares:
--
-- * Exception classification. Only SYNCHRONOUS exceptions may be turned
--   into a value. An asynchronous one (anything wrapped in
--   'SomeAsyncException': 'ThreadKilled', 'UserInterrupt', Warp's
--   @TimeoutThread@, async's @AsyncCancelled@, System.Timeout's @Timeout@,
--   'StackOverflow', 'HeapOverflow') is a request to stop the thread and is
--   ALWAYS rethrown. Catching @SomeException@ around validation is how a
--   killed recv thread used to turn into "script verify failed (input i):
--   thread killed" — a verdict that marked a valid block failed on disk.
--
-- * The fatal latch (Core @AbortNode@ / @FatalError@, validation.cpp). A
--   fault that survives one retry halts the node instead of being guessed
--   at: no verdict, no punishment, no further connects, submitblock -25,
--   mempool refuses, shutdown skips the cache flush and the process exits 1
--   (the unit's Restart=on-failure + StartLimitBurst keeps it down and the
--   fleet monitor alerts).
module Haskoin.Fatal
  ( -- * Exception classification
    isAsyncException
  , syncOnly
  , trySync
  , catchSync
    -- * Internal (non-verdict) reject strings
  , internalErrorMarker
  , internalReject
  , isInternalReject
    -- * Fatal latch (AbortNode)
  , setFatalLatch
  , readFatalLatch
  , isFatalLatched
  , fatalLatchedReject
  , installFatalShutdownHook
  , resetFatalLatchForTest
  ) where

import Control.Exception
  ( SomeException, SomeAsyncException, Exception (..), tryJust, catch, throwIO )
import Control.Monad (join, when)
import Data.IORef
import Data.List (isInfixOf)
import Data.Maybe (isJust)
import System.IO (hFlush, hPutStrLn, stderr, stdout)
import System.IO.Unsafe (unsafePerformIO)

-- | True for every asynchronous exception type (the 'SomeAsyncException'
-- hierarchy), not only 'AsyncException'.
isAsyncException :: SomeException -> Bool
isAsyncException e = isJust (fromException e :: Maybe SomeAsyncException)

-- | 'tryJust' selector: synchronous exceptions only.
syncOnly :: SomeException -> Maybe SomeException
syncOnly e
  | isAsyncException e = Nothing
  | otherwise = Just e

-- | 'try' for synchronous exceptions; asynchronous ones propagate.
trySync :: IO a -> IO (Either SomeException a)
trySync = tryJust syncOnly

-- | 'catch' that rethrows every asynchronous exception.
catchSync :: IO a -> (SomeException -> IO a) -> IO a
catchSync act h = act `catch` \e ->
  if isAsyncException e then throwIO e else h e

-- | Marker carried by every reject string that is a local fault rather than
-- a judgement on the block. 'classifyBlockReject' lists it first among the
-- non-verdict markers.
internalErrorMarker :: String
internalErrorMarker = "internal-error"

internalReject :: String -> String
internalReject what = internalErrorMarker ++ ": " ++ what

isInternalReject :: String -> Bool
isInternalReject s = internalErrorMarker `isInfixOf` s

{-# NOINLINE fatalLatchRef #-}
fatalLatchRef :: IORef (Maybe String)
fatalLatchRef = unsafePerformIO (newIORef Nothing)

{-# NOINLINE fatalShutdownHookRef #-}
fatalShutdownHookRef :: IORef (IO ())
fatalShutdownHookRef = unsafePerformIO (newIORef (return ()))

-- | Latch the node as halted (first reason wins) and request shutdown.
setFatalLatch :: String -> IO ()
setFatalLatch why = do
  first <- atomicModifyIORef' fatalLatchRef $ \m -> case m of
    Nothing -> (Just why, True)
    Just _  -> (m, False)
  when first $ do
    let msg = "FATAL (AbortNode): " ++ why
              ++ " -- halting: no verdict, no further connects; "
              ++ "shutdown will skip the cache flush and exit 1"
    putStrLn msg
    hPutStrLn stderr msg
    hFlush stdout
    join (readIORef fatalShutdownHookRef)
      `catchSync` (\e -> hPutStrLn stderr ("fatal shutdown hook error: " ++ show e))

readFatalLatch :: IO (Maybe String)
readFatalLatch = readIORef fatalLatchRef

isFatalLatched :: IO Bool
isFatalLatched = isJust <$> readFatalLatch

-- | The reject every connect entry returns once the latch is set.
fatalLatchedReject :: String -> String
fatalLatchedReject why = internalReject ("node halted after a fatal internal error: " ++ why)

-- | Install the action that starts shutdown (main: tryPutMVar shutdownVar).
-- Runs it at once if the latch was set before the hook existed.
installFatalShutdownHook :: IO () -> IO ()
installFatalShutdownHook act = do
  writeIORef fatalShutdownHookRef act
  latched <- isFatalLatched
  when latched act

-- | Tests only.
resetFatalLatchForTest :: IO ()
resetFatalLatchForTest = do
  writeIORef fatalLatchRef Nothing
  writeIORef fatalShutdownHookRef (return ())

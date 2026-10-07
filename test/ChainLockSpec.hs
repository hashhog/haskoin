{-# LANGUAGE ScopedTypeVariables #-}

-- | The chain lock (haskoin's cs_main, "Haskoin.ChainLock"): mutual exclusion,
-- re-entrancy, release on exception, FIFO hand-off -- and that the chainstate
-- writers reachable from the RPC server actually take it (HK-3/HK-6/HK-7:
-- before, only the P2P arm did).
module ChainLockSpec (spec) where

import Test.Hspec
import Control.Concurrent
import Control.Concurrent.MVar
import Control.Exception (try, throwIO, ErrorCall(..), evaluate)
import Control.Monad (forM_, replicateM_, when)
import Data.IORef
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))
import Control.Exception (bracket)

import Haskoin.ChainLock
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, flushCache, UTXOCache(..))

-- | Run @act@ in a thread; True if it finished within @us@ microseconds.
finishesWithin :: Int -> IO () -> IO (Bool, MVar ())
finishesWithin us act = do
  done <- newEmptyMVar
  _ <- forkIO (act >> putMVar done ())
  r <- timeoutWait us done
  return (r, done)
  where
    timeoutWait n mv = go (n `div` 1000)
      where go 0 = not <$> isEmptyMVar mv
            go k = do
              e <- isEmptyMVar mv
              if not e then return True else threadDelay 1000 >> go (k - 1)

withCache :: (UTXOCache -> IO ()) -> IO ()
withCache action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-chainlock-") removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db ->
      newUTXOCache db 1000 >>= action

spec :: Spec
spec = describe "ChainLock (cs_main)" $ do

  it "excludes a second thread while held, and admits it after release" $ do
    cl <- newChainLock
    gate <- newEmptyMVar
    _ <- forkIO $ withChainLock cl (takeMVar gate)
    threadDelay 20000
    chainLockHeld cl `shouldReturn` True
    (inTime, done) <- finishesWithin 200000 (withChainLock cl (return ()))
    inTime `shouldBe` False                    -- blocked while held
    putMVar gate ()
    takeMVar done                              -- admitted after release
    chainLockHeld cl `shouldReturn` False

  it "is re-entrant for the owning thread (no self-deadlock)" $ do
    cl <- newChainLock
    (ok, _) <- finishesWithin 1000000 $
      withChainLock cl $ withChainLock cl $ withChainLock cl $ do
        me <- chainLockHeldByMe cl
        when (not me) $ throwIO (ErrorCall "not owner")
    ok `shouldBe` True
    chainLockHeld cl `shouldReturn` False

  it "releases on exception (and a nested throw releases the outer hold too)" $ do
    cl <- newChainLock
    r <- try (withChainLock cl $ withChainLock cl $ throwIO (ErrorCall "boom"))
    case r of
      Left (ErrorCall m) -> m `shouldBe` "boom"
      Right () -> expectationFailure "no exception"
    chainLockHeld cl `shouldReturn` False
    chainLockHeldByMe cl `shouldReturn` False

  it "serialises a read-check-write critical section (no lost update under contention)" $ do
    cl <- newChainLock
    ref <- newIORef (0 :: Int)
    dones <- mapM (const newEmptyMVar) [1 .. 8 :: Int]
    forM_ dones $ \d -> forkIO $ do
      replicateM_ 500 $ withChainLock cl $ do
        v <- readIORef ref
        yield                                  -- invite an interleaving
        writeIORef ref (v + 1)
      putMVar d ()
    mapM_ takeMVar dones
    readIORef ref `shouldReturn` 4000

  it "is FIFO: waiters are admitted in arrival order" $ do
    cl <- newChainLock
    gate <- newEmptyMVar
    order <- newIORef []
    _ <- forkIO $ withChainLock cl (takeMVar gate)
    threadDelay 20000
    dones <- mapM (const newEmptyMVar) [1 .. 5 :: Int]
    forM_ (zip [1 :: Int ..] dones) $ \(i, d) -> do
      _ <- forkIO $ withChainLock cl (modifyIORef' order (i :)) >> putMVar d ()
      threadDelay 20000                        -- arrive in order
    putMVar gate ()
    mapM_ takeMVar dones
    reverse <$> readIORef order `shouldReturn'` [1, 2, 3, 4, 5]

  it "HK-7: flushCache takes the chain lock (waits while another writer holds it)" $
    withCache $ \cache -> do
      gate <- newEmptyMVar
      _ <- forkIO $ withChainLock (ucChainLock cache) (takeMVar gate)
      threadDelay 20000
      (inTime, done) <- finishesWithin 300000 (flushCache cache)
      inTime `shouldBe` False
      putMVar gate ()
      takeMVar done

  it "HK-7 control: flushCache by the lock's owner does not self-deadlock" $
    withCache $ \cache -> do
      (ok, _) <- finishesWithin 2000000 $
        withChainLock (ucChainLock cache) (flushCache cache)
      ok `shouldBe` True
  where
    shouldReturn' act want = act >>= (`shouldBe` want)

-- silence unused-import warnings on older GHCs
_unused :: IO ()
_unused = evaluate () >> return ()

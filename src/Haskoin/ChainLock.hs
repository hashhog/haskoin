{-# LANGUAGE ScopedTypeVariables #-}
-- | haskoin's @cs_main@: ONE re-entrant, FIFO chain lock that every
-- chainstate writer takes.
--
-- Core holds @cs_main@ across ProcessNewBlock's validate-then-connect
-- (validation.cpp ProcessNewBlock :4398 -> AcceptBlock -> ActivateBestChain
-- :3323 -> ConnectTip :3005, each step under @LOCK(cs_main)@), across
-- InvalidateBlock (:3521) / PreciousBlock (:3490) / the dumptxoutset
-- TemporaryRollback, and around FlushStateToDisk (:2702).  Before this module
-- haskoin had a @connectLock :: MVar ()@ that only the P2P connect arm and
-- the P2P reorg kicker took (app/Main.hs); the RPC writers (submitblock,
-- generate*, invalidate/reconsider/precious, the dumptxoutset rollback) and
-- every 'flushCache' ran without it (audit HK-3..HK-7).
--
-- The lock lives in the 'UTXOCache' record ('ucChainLock') because that is
-- the one object every writer -- P2P arm, RPC server, flush timer, shutdown,
-- the library's reorg engine -- already shares.
--
-- Re-entrant: the owning thread may take it again (the reorg engine calls
-- 'flushCache', which locks; an RPC handler that already holds it calls
-- 'submitBlock', which locks).  Re-entry is detected by 'ThreadId'; only the
-- owner ever writes its own id into 'clOwner', so another thread can never
-- mistake itself for the owner.
--
-- FIFO: GHC 'MVar' wake-ups are FIFO, so a waiting P2P connect cannot be
-- starved by a stream of RPC writers (or vice versa).
--
-- LOCK ORDER (documented here because this is the outermost lock):
--
--   linearLock (app/Main.hs download planner)
--     -> ChainLock (this)
--       -> STM (hc*, uc*, rc*, mempool TVars -- never block)
--       -> RocksDB
--
-- Nothing that holds the chain lock may wait on 'linearLock', on a wallet
-- lock, or on network I/O.  Peer sends made while it is held go through
-- 'enqueueBackgroundSend' (a TQueue drained by its own thread); wallet scans
-- run after it is released.
module Haskoin.ChainLock
  ( ChainLock
  , newChainLock
  , withChainLock
  , chainLockHeld
  , chainLockHeldByMe
  ) where

import Control.Concurrent (ThreadId, myThreadId)
import Control.Concurrent.MVar
import Control.Exception (mask, onException)
import Data.IORef

data ChainLock = ChainLock
  { clMVar  :: !(MVar ())
  , clOwner :: !(IORef (Maybe ThreadId))
  }

newChainLock :: IO ChainLock
newChainLock = ChainLock <$> newMVar () <*> newIORef Nothing

-- | Run an action holding the chain lock (re-entrant).
withChainLock :: ChainLock -> IO a -> IO a
withChainLock cl act = do
  me <- myThreadId
  owner <- readIORef (clOwner cl)
  if owner == Just me
    then act
    else mask $ \restore -> do
      takeMVar (clMVar cl)                 -- interruptible wait
      writeIORef (clOwner cl) (Just me)
      r <- restore act `onException` release
      release
      return r
  where
    release = do
      writeIORef (clOwner cl) Nothing
      putMVar (clMVar cl) ()

-- | Is ANY thread holding the lock right now (diagnostics only).
chainLockHeld :: ChainLock -> IO Bool
chainLockHeld cl = isEmptyMVar (clMVar cl)

-- | Does the CALLING thread hold the lock.
chainLockHeldByMe :: ChainLock -> IO Bool
chainLockHeldByMe cl = do
  me <- myThreadId
  (== Just me) <$> readIORef (clOwner cl)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | sm-fix-haskoin-reorg-readd-bypass-limits: a transaction from a
-- disconnected block is re-added to the mempool with Core's bypass_limits
-- (the fee-rate floor does not apply), and when a re-add still fails, the
-- in-pool spenders of its outputs leave with their descendants.
--
-- Core: Chainstate::MaybeUpdateMempoolForReorg (bitcoin-core/src/
-- validation.cpp) calls AcceptToMemoryPool(..., bypass_limits=true), which
-- skips CheckFeeRate in MemPoolAccept::PreChecks, and on any failure calls
-- m_mempool->removeRecursive(tx, MemPoolRemovalReason::REORG).
--
-- The basic case is sm-reorg-readd-bypass-limits in test/SmSweepSpec.hs.
-- This suite adds the live-tip variant, the failed-re-add arm (a
-- non-standard confirmed parent: the re-add must still fail, so bypass does
-- not open other gates, and its child and grandchild must leave), and a
-- check that normal admission keeps the fee floor after the reorg.  It is its
-- own suite so it does not touch the shared sm-sweep file other fix branches
-- also edit.  Each case runs with a bare mempool (counter tip) and with the
-- live node's tip source ('initNodeMempool').
module Main (main) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO)
import Data.IORef (newIORef)
import Data.Int (Int32)
import Data.Word (Word32, Word64)
import Data.Maybe (isJust)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Aeson as A
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus
  ( regtest, ChainEntry(..), getValidatedChainTip, blockHashToHex )
import Haskoin.HeaderReload (initHeaderChainFromDB)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock )
import Haskoin.Mempool
  ( newMempool, initNodeMempool, defaultMempoolConfig, addTransaction, getTransaction
  , MempoolError(..) )
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..)
  , handleInvalidateBlock, generateSingleBlock )

noopHandler :: a -> Message -> IO ()
noopHandler _ _ = return ()

-- | A regtest node on a fresh datadir.  @live@ builds the mempool the way
-- app/Main.hs does ('initNodeMempool': the tip is read from the active
-- chain); otherwise a bare 'newMempool' whose tip is the connect/disconnect
-- counter.
withLive :: Bool -> (RpcServer -> IO ()) -> IO ()
withLive live action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-sm-readd-bypass-") removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChainFromDB db regtest
      cache <- newUTXOCache db 1000
      mp    <- if live
                 then initNodeMempool regtest db hc cache defaultMempoolConfig
                 else newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg noopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
        action RpcServer
          { rsConfig = cfg, rsDB = db, rsHeaderChain = hc, rsPeerMgr = pm
          , rsMempool = mp, rsFeeEst = fe, rsUTXOCache = cache
          , rsNetwork = regtest, rsBlockStore = Nothing
          , rsThread = threadVar, rsMockTime = mockTimeVar
          , rsWalletMgr = Nothing, rsStartTime = 0
          , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
          , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
          , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
          , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
          , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
          }

-- | 0x00 0x20 sha256(0x51): P2WSH(OP_TRUE)
p2wshTrue :: BS.ByteString
p2wshTrue = BS.pack ([0x00, 0x20] ++
  [ 0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00, 0x09, 0x45
  , 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3, 0x32, 0x60 ])

mine :: RpcServer -> [Tx] -> IO BlockHash
mine s txs = either (fail . show) return =<< generateSingleBlock s p2wshTrue txs

-- | A 1-in spend of a P2WSH(OP_TRUE) coin paying @value@ back to
-- P2WSH(OP_TRUE), padded past tx-size-small.
spendWith :: OutPoint -> Word64 -> Tx
spendWith = spendWithVersion 2

-- | 'spendWith' with an explicit nVersion.  Version 4 is valid by consensus
-- but not standard (Core IsStandardTx "version"), so a miner can confirm it
-- while the mempool refuses it, also on a bypass_limits re-add.
spendWithVersion :: Int32 -> OutPoint -> Word64 -> Tx
spendWithVersion ver op value = Tx
  { txVersion = ver
  , txInputs  = [TxIn op BS.empty 0xfffffffd]
  , txOutputs = [ TxOut value p2wshTrue
                , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
  , txWitness = [ [BS.pack [0x51]] ]
  , txLockTime = 0
  }

coinbaseOut :: RpcServer -> BlockHash -> IO OutPoint
coinbaseOut s h = do
  mb <- getBlock (rsDB s) h
  cb <- maybe (fail "block body missing") (return . head . blockTxns) mb
  return (OutPoint (computeTxId cb) 0)

inPool :: RpcServer -> Tx -> IO Bool
inPool s t = isJust <$> getTransaction (rsMempool s) (computeTxId t)

accepted :: RpcServer -> Tx -> Expectation
accepted s t = addTransaction (rsMempool s) t >>= (`shouldSatisfy` either (const False) (const True))

tipHeight :: RpcServer -> IO Word32
tipHeight s = ceHeight <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)

invalidateTip :: RpcServer -> IO ()
invalidateTip s = invalidateAt s . ceHash =<< getValidatedChainTip (rsDB s) (rsHeaderChain s)

invalidateAt :: RpcServer -> BlockHash -> IO ()
invalidateAt s h = () <$ handleInvalidateBlock s (A.toJSON [blockHashToHex h])


belowMinFee :: Either MempoolError a -> Bool
belowMinFee (Left (ErrFeeBelowMinimum _ _)) = True
belowMinFee _ = False

nonStandard :: Either MempoolError a -> Bool
nonStandard (Left (ErrNonStandard _)) = True
nonStandard _ = False

-- | A 0-fee parent (below the min relay fee) is refused by admission but
-- mined; its child is admitted.  Invalidating the parent's block must put
-- the parent back (bypass_limits) and keep the child.  A new, unrelated
-- 0-fee tx is still refused afterwards: the bypass is for re-adds only.
bypassCase :: RpcServer -> Expectation
bypassCase s = do
  hs <- mapM (const (mine s [])) [1 .. 102 :: Int]
  op1 <- coinbaseOut s (hs !! 0)
  op2 <- coinbaseOut s (hs !! 1)
  let parent = spendWith op1 5_000_000_000
      child  = spendWith (OutPoint (computeTxId parent) 0) 4_999_000_000
      other  = spendWith op2 5_000_000_000
  addTransaction (rsMempool s) parent >>= (`shouldSatisfy` belowMinFee)
  blk <- mine s [parent]
  accepted s child
  invalidateAt s blk
  tipHeight s `shouldReturn` 102
  (,) <$> inPool s parent <*> inPool s child `shouldReturn` (True, True)
  addTransaction (rsMempool s) other >>= (`shouldSatisfy` belowMinFee)

-- | A non-standard (nVersion 4) parent is mined; its child and grandchild
-- are admitted.  Invalidating the parent's block: the re-add fails
-- (standardness is not bypassed), so Core's removeRecursive drops the child
-- and the grandchild, which would otherwise spend a coin that exists
-- neither in the UTXO set nor in the pool.
failedReaddCase :: RpcServer -> Expectation
failedReaddCase s = do
  hs <- mapM (const (mine s [])) [1 .. 102 :: Int]
  op1 <- coinbaseOut s (hs !! 0)
  let parent = spendWithVersion 4 op1 4_999_000_000
      child  = spendWith (OutPoint (computeTxId parent) 0) 4_998_000_000
      grand  = spendWith (OutPoint (computeTxId child) 0) 4_997_000_000
  addTransaction (rsMempool s) parent >>= (`shouldSatisfy` nonStandard)
  blk <- mine s [parent]
  accepted s child
  accepted s grand
  invalidateAt s blk
  tipHeight s `shouldReturn` 102
  (,,) <$> inPool s parent <*> inPool s child <*> inPool s grand
    `shouldReturn` (False, False, False)

main :: IO ()
main = hspec $ describe "sm-fix-haskoin-reorg-readd-bypass-limits" $ do
  it "sm-reorg-readd-bypass-limits-live: a below-min-fee tx from a disconnected block is re-added and its child kept, with the live node's mempool (initNodeMempool); normal admission keeps the floor" $
    withLive True bypassCase
  it "sm-reorg-readd-bypass-limits-floor-kept: the same with a bare mempool; a new 0-fee tx is still refused after the reorg" $
    withLive False bypassCase
  it "sm-reorg-readd-failed-removes-descendants: a disconnected tx whose re-add fails (non-standard) takes its in-pool child and grandchild with it" $
    withLive False failedReaddCase
  it "sm-reorg-readd-failed-removes-descendants-live: the same with the live node's mempool (initNodeMempool)" $
    withLive True failedReaddCase

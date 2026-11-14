{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | sm-fix-haskoin-reorg-immature-coinbase: after the tip moves down, the
-- mempool drops spends of coinbase outputs that are immature for the next
-- block on the NEW tip, with their descendants, and keeps the ones that are
-- still mature.
--
-- Core: Chainstate::MaybeUpdateMempoolForReorg → removeForReorg(
-- filter_final_and_mature), coinbase arm (bitcoin-core/src/validation.cpp):
-- (tip+1) - coin.nHeight < COINBASE_MATURITY removes the entry, and
-- CTxMemPool::removeForReorg (txmempool.cpp) removes its descendants too.
--
-- The single-spend case is sm-reorg-immature-coinbase-spend in
-- test/SmSweepSpec.hs.  This suite adds the boundary (a spend exactly at
-- maturity on the new tip must STAY: the pass must not evict a valid tx)
-- and the descendant arm, and the deep case where the coinbase's own block
-- is disconnected (Core removeRecursive of the coinbase).  It is its own suite so it does not touch the
-- shared sm-sweep file other fix branches also edit.  Each case runs twice:
-- with the counter tip of a bare mempool and with the live node's tip source.
module Main (main) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO)
import Data.IORef (newIORef)
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
  (newMempool, initNodeMempool, defaultMempoolConfig, addTransaction, getTransaction)
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
  bracket (createTempDirectory base "haskoin-sm-immature-") removeDirectoryRecursive $ \dir ->
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

mine :: RpcServer -> IO BlockHash
mine s = either (fail . show) return =<< generateSingleBlock s p2wshTrue []

-- | A 1-in spend of a P2WSH(OP_TRUE) coin paying @value@ back to
-- P2WSH(OP_TRUE), padded past tx-size-small.
spendWith :: OutPoint -> Word64 -> Tx
spendWith op value = Tx
  { txVersion = 2
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

-- | At tip 101 admit spends of the height-1 and height-2 coinbases and a
-- child of the second, then invalidate the tip (new tip 100, next block 101).
mixedCase :: RpcServer -> Expectation
mixedCase s = do
  hs <- mapM (const (mine s)) [1 .. 101 :: Int]
  tipHeight s `shouldReturn` 101
  op1 <- coinbaseOut s (hs !! 0)   -- coinbase at height 1
  op2 <- coinbaseOut s (hs !! 1)   -- coinbase at height 2
  -- next block 102: 102-1 = 101 and 102-2 = 100, both mature
  let spend1 = spendWith op1 4_999_000_000
      spend2 = spendWith op2 4_999_000_000
      child2 = spendWith (OutPoint (computeTxId spend2) 0) 4_998_000_000
  accepted s spend1
  accepted s spend2
  accepted s child2
  invalidateTip s
  tipHeight s `shouldReturn` 100
  -- next block 101: 101-1 = 100 (mature, stays: the boundary), 101-2 = 99
  -- (immature: Core removeForReorg drops it and its descendant).
  (,,) <$> inPool s spend1 <*> inPool s spend2 <*> inPool s child2
    `shouldReturn` (True, False, False)

-- | At tip 101 admit a spend of the height-1 coinbase and a child of it,
-- then invalidate block 1 itself (new tip 0).  The coin is gone, not just
-- immature: Core's removeRecursive of the never-re-added coinbase drops the
-- spend and its child.
deepCase :: RpcServer -> Expectation
deepCase s = do
  hs <- mapM (const (mine s)) [1 .. 101 :: Int]
  op1 <- coinbaseOut s (hs !! 0)
  let spend1 = spendWith op1 4_999_000_000
      child1 = spendWith (OutPoint (computeTxId spend1) 0) 4_998_000_000
  accepted s spend1
  accepted s child1
  invalidateAt s (hs !! 0)
  tipHeight s `shouldReturn` 0
  (,) <$> inPool s spend1 <*> inPool s child1 `shouldReturn` (False, False)

main :: IO ()
main = hspec $ describe "sm-fix-haskoin-reorg-immature-coinbase" $ do
  it "sm-reorg-immature-coinbase-mixed: invalidateblock keeps a spend still mature at the new tip, evicts one now immature and its child" $
    withLive False mixedCase
  it "sm-reorg-immature-coinbase-mixed-live: the same with the live node's mempool (initNodeMempool, tip read from the active chain)" $
    withLive True mixedCase
  it "sm-reorg-immature-coinbase-disconnected: invalidating the coinbase's own block evicts its spend and the spend's child" $
    withLive False deepCase
  it "sm-reorg-immature-coinbase-disconnected-live: the same with the live node's mempool (initNodeMempool)" $
    withLive True deepCase

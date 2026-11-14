{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | sm-fix-haskoin-reorg-nonfinal-after-invalidate: after the tip moves down,
-- the mempool drops entries whose nLockTime is no longer final for the next
-- block on the NEW tip, with their descendants, and keeps the ones that are
-- still final.
--
-- Core: Chainstate::MaybeUpdateMempoolForReorg -> removeForReorg(
-- filter_final_and_mature), finality arm (bitcoin-core/src/validation.cpp):
-- !CheckFinalTxAtTip(tip, tx) removes the entry, and
-- CTxMemPool::removeForReorg (txmempool.cpp) removes its descendants too.
--
-- The single-tx case is sm-reorg-nonfinal-after-invalidate in
-- test/SmSweepSpec.hs.  This suite adds the boundaries (nLockTime equal to
-- the new tip height, and a non-zero nLockTime with every input at
-- SEQUENCE_FINAL, must STAY: the pass must not evict a valid tx) and the
-- descendant arm.  It is its own suite so it does not touch the shared
-- sm-sweep file other fix branches also edit.
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
  (newMempool, defaultMempoolConfig, addTransaction, getTransaction, MempoolError(..))
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

withLive :: (RpcServer -> IO ()) -> IO ()
withLive action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-sm-nonfinal-") removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChainFromDB db regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
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
-- P2WSH(OP_TRUE), padded past tx-size-small, with the given nSequence and
-- nLockTime.
spendWith :: OutPoint -> Word64 -> Word32 -> Word32 -> Tx
spendWith op value sequ lockTime = Tx
  { txVersion = 2
  , txInputs  = [TxIn op BS.empty sequ]
  , txOutputs = [ TxOut value p2wshTrue
                , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
  , txWitness = [ [BS.pack [0x51]] ]
  , txLockTime = lockTime
  }

-- | nSequence that leaves nLockTime enforced and BIP-68 disabled (bit 31 set)
-- -- the anti-fee-sniping wallet shape.
seqLockTime :: Word32
seqLockTime = 0xfffffffd

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
invalidateTip s = do
  tip <- ceHash <$> getValidatedChainTip (rsDB s) (rsHeaderChain s)
  () <$ handleInvalidateBlock s (A.toJSON [blockHashToHex tip])

main :: IO ()
main = hspec $ describe "sm-fix-haskoin-reorg-nonfinal-after-invalidate" $ do
  it "sm-reorg-nonfinal-mixed: invalidateblock evicts a tx no longer final at the new tip and its child, keeps the final ones" $
    withLive $ \s -> do
      hs <- mapM (const (mine s)) [1 .. 110 :: Int]
      tipHeight s `shouldReturn` 110
      -- coinbases at heights 1..3: mature at the next block on both tips
      -- (111 and 110), so only finality decides here.
      [op1, op2, op3] <- mapM (coinbaseOut s . (hs !!)) [0, 1, 2]
      -- next block 111: every nLockTime below 111 is final; all accepted.
      let atOldTip  = spendWith op1 4_999_000_000 seqLockTime 110  -- anti-fee-sniping
          child     = spendWith (OutPoint (computeTxId atOldTip) 0) 4_998_000_000 seqLockTime 0
          atNewTip  = spendWith op2 4_999_000_000 seqLockTime 109
          seqFinal  = spendWith op3 4_999_000_000 0xffffffff 110
      accepted s atOldTip
      accepted s child
      accepted s atNewTip
      accepted s seqFinal
      invalidateTip s
      tipHeight s `shouldReturn` 109
      -- next block 110: nLockTime 110 is not < 110, so atOldTip is not final
      -- (Core removeForReorg drops it and its child); 109 < 110 stays (the
      -- boundary); seqFinal stays because every input is SEQUENCE_FINAL
      -- (IsFinalTx ignores nLockTime then).
      (,,,) <$> inPool s atOldTip <*> inPool s child <*> inPool s atNewTip <*> inPool s seqFinal
        `shouldReturn` (False, False, True, True)

  it "sm-reorg-nonfinal-readmit: the evicted tx is refused at the new tip with non-final, as admission would" $
    withLive $ \s -> do
      hs <- mapM (const (mine s)) [1 .. 110 :: Int]
      op1 <- coinbaseOut s (head hs)
      let atOldTip = spendWith op1 4_999_000_000 seqLockTime 110
      accepted s atOldTip
      invalidateTip s
      inPool s atOldTip `shouldReturn` False
      r <- addTransaction (rsMempool s) atOldTip
      r `shouldSatisfy` either (\e -> e == ErrNonFinal "non-final") (const False)

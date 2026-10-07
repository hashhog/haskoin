{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | HK-4 / HK-5 (receipts/arch-concurrency-liveness-audit-2026-10-07.md):
-- the submitblock paths must leave the coin caches exactly as the disk
-- commit left the chainstate.
--
--   HK-4  submitblock's side-branch reorg committed one WriteBatch and then
--         MIRRORED the reorg into the lookupUTXO cache: 'unapplyBlock'
--         re-added every restored coin DIRTY-unspent, then
--         'applyBlockToCache' re-spent per connected block with its Left
--         ignored.  Its lookups ran against the post-reorg disk, so a
--         connected tx with an uncached input the reorg had already spent
--         returned Left before mutating, and the restored coin it also spends
--         stayed unspent in ucDirty -> gettxout / mempool saw it unspent, the
--         next flushCache wrote it back to disk.  (Core: one coins view,
--         updated by the reorg itself.)
--   HK-5  the submitblock active-tip arm never invalidated the read-through
--         mirror (rcEntries) for the prevouts it spent; a coin left there by
--         an earlier read (a failed P2P connect of a sibling) was then served
--         to the P2P arm, which ACCEPTED a block double-spending it.
--
-- Both are deterministic (no race).  This module compiles against the
-- deployed tree too, so it is the fail-before / pass-after pin.
module CacheBookkeepingSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Monad (replicateM_)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Either (isLeft, isRight)
import Data.Maybe (isJust)
import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash, sha256, doubleSHA256)
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..), ChainState(..), addHeader
  , getValidatedChainTip, validateFullBlockIO, connectBlock
  , consensusFlagsAtHeight, getMtpFromAncestry, computeWtxId )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getUTXO
  , getBlock, lookupUTXO, flushCache, buildSpentUtxoMapCached
  , getUTXOCoinCached, noteBlockConnectedOnDisk, UTXOCache(..), UTXOEntry(..) )
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..)
  , generateSingleBlock, buildRegtestCoinbase, findRegtestNonce )

noop :: a -> Message -> IO ()
noop _ _ = return ()

withServer :: (RpcServer -> IO ()) -> IO ()
withServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-hk45-") removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 100000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg noop) stopPeerManager $ \pm -> do
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

opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

spendTx :: [OutPoint] -> Word64 -> Tx
spendTx ops outV = Tx
  { txVersion  = 2
  , txInputs   = [TxIn op BS.empty 0xfffffffd | op <- ops]
  , txOutputs  = [TxOut outV opTrueSpk]
  , txWitness  = [[BS.singleton 0x51] | _ <- ops]
  , txLockTime = 0
  }

-- | A valid regtest block on @parentHash@; @tag@ makes sibling coinbases
-- (and so sibling block hashes) distinct.
mkBlock :: RpcServer -> BlockHash -> Word64 -> [Tx] -> IO Block
mkBlock server parentHash tag txs = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1 + fromIntegral tag
      wtxids    = TxId (Hash256 (BS.replicate 32 0)) : map computeWtxId txs
      commit    = getHash256 $ doubleSHA256
                    (getHash256 (computeMerkleRoot wtxids) <> BS.replicate 32 0)
      coinbase  = buildRegtestCoinbase height (blockReward height) opTrueSpk blockTime
                    (if null txs then Nothing else Just commit)
      allTxs    = coinbase : txs
      hdr = BlockHeader
        { bhVersion    = 0x20000000
        , bhPrevBlock  = parentHash
        , bhMerkleRoot = computeMerkleRoot (map computeTxId allTxs)
        , bhTimestamp  = blockTime
        , bhBits       = 0x207fffff
        , bhNonce      = 0
        }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce") (\h -> return (Block h allTxs)) mSolved

submit :: RpcServer -> Block -> IO (Either String ())
submit server =
  submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
              (rsPeerMgr server) (rsMempool server) (rsIndexMgr server)

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

-- | The P2P MBlock arm's library sequence (app/Main.hs): prevouts through the
-- read-through cache, full validation, commit, cache notification.
p2pConnect :: RpcServer -> Block -> IO (Either String ())
p2pConnect server block = do
  let db = rsDB server
      hc = rsHeaderChain server
      cache = rsUTXOCache server
      parentHash = bhPrevBlock (blockHeader block)
  hr <- addHeader regtest hc (blockHeader block) False
  case hr of
    Left e -> return (Left ("header: " ++ e))
    Right _ -> do
      entries <- readTVarIO (hcEntries hc)
      parent <- maybe (fail "parent") return (Map.lookup parentHash entries)
      let height = ceHeight parent + 1
          cs = ChainState (height - 1) parentHash (ceChainWork parent)
                          (medianTimePast entries parentHash)
                          (consensusFlagsAtHeight regtest height)
      spent <- buildSpentUtxoMapCached cache block
      vr <- validateFullBlockIO db regtest cs (getMtpFromAncestry entries parentHash)
                                False block spent
      case vr of
        Left e -> return (Left e)
        Right () -> do
          noteBlockConnectedOnDisk cache block
          rC <- connectBlock db regtest block height spent
          noteBlockConnectedOnDisk cache block
          return rC

-- | 102 blocks through the miner; the coinbases of heights 1 and 2 (C, D),
-- both mature at the next block.  The caches are flushed so nothing is
-- cached (D must be UNCACHED for HK-4).
setupTwoCoins :: RpcServer -> IO (OutPoint, OutPoint)
setupTwoCoins server = do
  Right h1 <- generateSingleBlock server opTrueSpk []
  Right h2 <- generateSingleBlock server opTrueSpk []
  replicateM_ 100 $ do
    Right _ <- generateSingleBlock server opTrueSpk []
    return ()
  Just b1 <- getBlock (rsDB server) h1
  Just b2 <- getBlock (rsDB server) h2
  flushCache (rsUTXOCache server)
  return ( OutPoint (computeTxId (head (blockTxns b1))) 0
         , OutPoint (computeTxId (head (blockTxns b2))) 0 )

coin :: Word64
coin = 5_000_000_000

-- | HK-4 scenario.  @useTPrime@: the heavier branch spends C together with
-- the uncached D (the hazard); otherwise it re-confirms T itself (control).
sideBranchReorg :: Bool -> RpcServer -> IO ()
sideBranchReorg useTPrime server = do
  let db = rsDB server
      cache = rsUTXOCache server
  (c, d) <- setupTwoCoins server
  tip0 <- getValidatedChainTip db (rsHeaderChain server)
  let t  = spendTx [c] (coin - 10_000)
      t' = spendTx [c, d] (2 * coin - 20_000)
  blkA <- mkBlock server (ceHash tip0) 0 [t]
  submit server blkA `shouldReturn` Right ()
  blkB1 <- mkBlock server (ceHash tip0) 1 []
  submit server blkB1 >>= (`shouldSatisfy` isLeft)       -- "inconclusive"
  blkB2 <- mkBlock server (hashOf blkB1) 0 [if useTPrime then t' else t]
  rB2 <- submit server blkB2
  rB2 `shouldBe` Right ()
  vt <- getValidatedChainTip db (rsHeaderChain server)
  ceHash vt `shouldBe` hashOf blkB2                       -- control: reorged
  getUTXO db c >>= (`shouldBe` Nothing)                   -- control: disk spent C
  live <- lookupUTXO cache c
  dirty <- Map.lookup c <$> readTVarIO (ucDirty cache)
  putStrLn ("    [HK-4] after the reorg: lookupUTXO C = "
            ++ (if isJust live then "UNSPENT (resurrected)" else "spent")
            ++ "; ucDirty C = " ++ show (fmap ueSpent dirty))
  live `shouldSatisfy` (not . isJust)
  flushCache cache
  onDisk <- getUTXO db c
  putStrLn ("    [HK-4] after flushCache: C on disk = "
            ++ if isJust onDisk then "PRESENT (written back)" else "absent")
  onDisk `shouldBe` Nothing
  -- And a block re-spending C must be rejected.
  blkB3 <- mkBlock server (hashOf blkB2) 0 [spendTx [c] (coin - 30_000)]
  rB3 <- submit server blkB3
  putStrLn ("    [HK-4] submitblock(B3 re-spending C): " ++ show rB3)
  rB3 `shouldSatisfy` isLeft

spec :: Spec
spec = describe "HK-4/HK-5: submitblock keeps the coin caches equal to the commit" $ do

  it "HK-4: a side-branch reorg whose new branch spends a restored coin + an uncached coin leaves the restored coin spent (cache, flush, re-spend)" $
    withServer (sideBranchReorg True)

  it "HK-4 control: the new branch re-confirming the same spend leaves the coin spent" $
    withServer (sideBranchReorg False)

  it "HK-5: a coin in the read-through mirror spent by submitblock is not served to a later P2P connect (double spend rejected)" $
    withServer $ \server -> do
      let db = rsDB server
          cache = rsUTXOCache server
      (x, _) <- setupTwoCoins server
      -- A failed P2P connect of a sibling (or any read through the P2P arm)
      -- leaves X in rcEntries.
      getUTXOCoinCached cache x >>= (`shouldSatisfy` isJust)
      inMirror0 <- Map.member x <$> readTVarIO (rcEntries cache)
      inMirror0 `shouldBe` True                                   -- control
      tip0 <- getValidatedChainTip db (rsHeaderChain server)
      blkA <- mkBlock server (ceHash tip0) 0 [spendTx [x] (coin - 10_000)]
      submit server blkA `shouldReturn` Right ()
      getUTXO db x >>= (`shouldBe` Nothing)                       -- control
      inMirror <- Map.member x <$> readTVarIO (rcEntries cache)
      putStrLn ("    [HK-5] after submitblock spent X: rcEntries has X = " ++ show inMirror)
      blkX <- mkBlock server (hashOf blkA) 0 [spendTx [x] (coin - 20_000)]
      rX <- p2pConnect server blkX
      putStrLn ("    [HK-5] P2P connect of a block re-spending X: " ++ show rX)
      inMirror `shouldBe` False
      rX `shouldSatisfy` isLeft

  it "HK-5 control: without the stale mirror entry the double spend is rejected" $
    withServer $ \server -> do
      let db = rsDB server
      (x, _) <- setupTwoCoins server
      tip0 <- getValidatedChainTip db (rsHeaderChain server)
      blkA <- mkBlock server (ceHash tip0) 0 [spendTx [x] (coin - 10_000)]
      submit server blkA `shouldReturn` Right ()
      blkX <- mkBlock server (hashOf blkA) 0 [spendTx [x] (coin - 20_000)]
      p2pConnect server blkX >>= (`shouldSatisfy` isLeft)
      blkOk <- mkBlock server (hashOf blkA) 1 []
      p2pConnect server blkOk >>= (`shouldSatisfy` isRight)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | F0 coin-cache RESURRECTION (receipts/arch-f6-f7-design-2026-10-05.md §0,
-- invariant I5): a coin the UTXO cache holds as unspent must never outlive
-- the block that spends it.
--
-- Core: there is ONE coins view (CCoinsViewCache over CCoinsViewDB).  A spend
-- turns the cached entry into a DIRTY spent entry (coins.cpp SpendCoin
-- :142-171) and FetchCoin never re-reads a coin the cache has seen spent
-- (:69-82); every reader (mempool, gettxout, submitblock) holds cs_main.
--
-- haskoin has two: the P2P connect arm (app/Main.hs) validates against disk
-- (+ the generation-guarded rcEntries mirror) and commits with
-- 'connectBlock' straight to RocksDB, while 'lookupUTXO' — the reader for the
-- mempool, gettxout, block templates and the submitblock coin map
-- ('buildBlockUTXOMap') — serves 'ucEntries'.  Pre-fix nothing told
-- 'ucEntries' (or its write-back set 'ucDirty') about a P2P connect, so:
--
--   (1) a coin a reader had cached stayed "unspent" after a P2P block spent
--       it: the mempool accepted a second spend, and submitblock CONNECTED a
--       block double-spending it;
--   (2) a coin created through the cache path (submitblock /
--       generatetoaddress -> applyBlockToCache marks it dirty) and then spent
--       by a P2P block was written BACK to disk by the next 'flushCache' —
--       resurrected in the chainstate itself.
--
-- The P2P arm is app code; 'p2pConnect' below reproduces its sequence with
-- the same library calls (buildSpentUtxoMapCached -> validateFullBlockIO ->
-- connectBlock -> post-commit cache notification -> blockConnected).
module CoinCacheResurrectionSpec (spec) where

import Test.Hspec
import Control.Exception (bracket, finally)
import Control.Monad (replicateM_)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Control.Monad (when)
import Data.IORef (newIORef, readIORef, writeIORef)
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
  , noteBlockConnectedOnDisk, lookupUTXOReadHookRef, UTXOCache(..), UTXOEntry(..) )
import Haskoin.Mempool
  ( Mempool, newMempool, initNodeMempool, defaultMempoolConfig, addTransaction
  , blockConnected )
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

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-f0-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 100000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg liveNoopHandler) stopPeerManager $ \pm -> do
        threadVar     <- newTVarIO Nothing
        mockTimeVar   <- newTVarIO Nothing
        pauseVar      <- newTVarIO False
        payjoinOffers <- newTVarIO Map.empty
        orphanRef     <- newIORef emptyOrphanPool
        assumeUtxoVar <- newIORef Nothing
        let cfg = defaultRpcConfig { rpcDataDir = dir }
            server = RpcServer
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
        action server

-- | P2WSH(OP_TRUE): standard, spendable with witness [OP_TRUE].
opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

-- | Spend @op@ (a 50 BTC regtest coinbase output) to @outV@ sats.
spendTx :: OutPoint -> Word64 -> Tx
spendTx op outV = Tx
  { txVersion  = 2
  , txInputs   = [TxIn op BS.empty 0xfffffffd]
  , txOutputs  = [TxOut outV opTrueSpk]
  , txWitness  = [[BS.singleton 0x51]]
  , txLockTime = 0
  }

-- | A valid regtest block on @parentHash@ carrying @txs@ (with the BIP-141
-- commitment), built exactly as 'generateSingleBlock' builds one, but NOT
-- submitted.
mkBlock :: RpcServer -> BlockHash -> [Tx] -> IO Block
mkBlock server parentHash txs = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1
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
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h allTxs)) mSolved

-- | The P2P MBlock connect arm (app/Main.hs), step for step: header first,
-- prevouts through the read-through cache, full validation, the disk commit
-- 'connectBlock', the post-commit cache notification, then the mempool.
p2pConnect :: RpcServer -> Mempool -> Block -> IO (Either String ())
p2pConnect server mp block = do
  let db    = rsDB server
      hc    = rsHeaderChain server
      cache = rsUTXOCache server
      hdr   = blockHeader block
      parentHash = bhPrevBlock hdr
  hr <- addHeader regtest hc hdr False
  case hr of
    Left e -> return (Left ("header: " ++ e))
    Right _ -> do
      entries <- readTVarIO (hcEntries hc)
      parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
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
          -- Main.hs: pre-commit cache notification (F0).
          noteBlockConnectedOnDisk cache block
          rC <- connectBlock db regtest block height spent
          case rC of
            Left e -> return (Left e)
            Right () -> do
              -- Main.hs: the post-commit cache notification (F0; it also
              -- does the rcEntries invalidation Main did before).
              noteBlockConnectedOnDisk cache block
              blockConnected mp block
              return (Right ())

submit :: RpcServer -> Block -> IO (Either String ())
submit server =
  submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
              (rsPeerMgr server) (rsMempool server) (rsIndexMgr server)

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

-- | Mine 101 blocks through the RPC miner (submitblock arm) and return the
-- height-1 coinbase output: mature at the next block.
setupMatureCoin :: RpcServer -> IO OutPoint
setupMatureCoin server = do
  Right h1 <- generateSingleBlock server opTrueSpk []
  replicateM_ 100 $ do
    Right _ <- generateSingleBlock server opTrueSpk []
    return ()
  Just b1 <- getBlock (rsDB server) h1
  return (OutPoint (computeTxId (head (blockTxns b1))) 0)

nodeMempool :: RpcServer -> IO Mempool
nodeMempool server = initNodeMempool regtest (rsDB server) (rsHeaderChain server)
                                     (rsUTXOCache server) defaultMempoolConfig

spec :: Spec
spec = describe "F0 coin-cache resurrection: a P2P-connected spend reaches every coin reader" $ do

  it "(1) a coin a reader cached is spent by a P2P block: mempool and submitblock must reject a second spend" $
    withLiveServer $ \server -> do
      let db = rsDB server
          cache = rsUTXOCache server
      x <- setupMatureCoin server
      -- Start from a clean cache: everything on disk, nothing cached.
      flushCache cache
      mp <- nodeMempool server
      -- A reader (mempool / gettxout / getblocktemplate) looks X up: miss ->
      -- disk -> cached as clean unspent in ucEntries.
      lookupUTXO cache x >>= (`shouldSatisfy` isJust)
      -- A peer delivers block B spending X; the P2P arm connects it.
      tip0 <- getValidatedChainTip db (rsHeaderChain server)
      let t1 = spendTx x 4_999_990_000
      blkB <- mkBlock server (ceHash tip0) [t1]
      rB <- p2pConnect server mp blkB
      rB `shouldBe` Right ()
      -- CONTROL: disk really spent X (the connect worked).
      getUTXO db x >>= (`shouldBe` Nothing)
      -- The reader must now see X as spent (Core: DIRTY spent entry).
      rLook <- lookupUTXO cache x
      putStrLn ("    [F0] lookupUTXO X after the P2P spend: "
                ++ if isJust rLook then "UNSPENT (stale)" else "spent")
      -- Second spend of X, relayed to the mempool.
      let t2 = spendTx x 4_999_980_000
      rMp <- addTransaction mp t2
      putStrLn ("    [F0] mempool addTransaction(T2 re-spending X): " ++ show rMp)
      -- ... and mined into block C on top of B, handed to submitblock.
      blkC <- mkBlock server (hashOf blkB) [t2]
      rC <- submit server blkC
      vt <- getValidatedChainTip db (rsHeaderChain server)
      putStrLn ("    [F0] submitblock(C double-spending X): " ++ show rC
                ++ "; validated tip = " ++ (if ceHash vt == hashOf blkC then "C" else "B"))
      rLook `shouldSatisfy` (not . isJust)
      rMp `shouldSatisfy` isLeft
      rC `shouldSatisfy` isLeft
      ceHash vt `shouldBe` hashOf blkB

  it "(2) a cache-created coin spent by a P2P block is not written back by the next flush" $
    withLiveServer $ \server -> do
      let db = rsDB server
          cache = rsUTXOCache server
      -- No flush: X was created through submitblock's applyBlockToCache and
      -- sits in ucEntries/ucDirty as a dirty unspent entry.
      x <- setupMatureCoin server
      mp <- nodeMempool server
      tip0 <- getValidatedChainTip db (rsHeaderChain server)
      blkB <- mkBlock server (ceHash tip0) [spendTx x 4_999_990_000]
      p2pConnect server mp blkB `shouldReturn` Right ()
      getUTXO db x >>= (`shouldBe` Nothing)            -- control
      flushCache cache
      onDisk <- getUTXO db x
      putStrLn ("    [F0] after flushCache, X on disk: "
                ++ if isJust onDisk then "PRESENT (resurrected)" else "absent")
      onDisk `shouldBe` Nothing
      -- And a block re-spending X must be rejected.
      blkC <- mkBlock server (hashOf blkB) [spendTx x 4_999_980_000]
      rC <- submit server blkC
      putStrLn ("    [F0] submitblock(C double-spending X) after the flush: " ++ show rC)
      rC `shouldSatisfy` isLeft

  it "(3) control: a block spending a coin once is accepted on both arms" $
    withLiveServer $ \server -> do
      let db = rsDB server
          cache = rsUTXOCache server
      x <- setupMatureCoin server
      flushCache cache
      mp <- nodeMempool server
      lookupUTXO cache x >>= (`shouldSatisfy` isJust)
      tip0 <- getValidatedChainTip db (rsHeaderChain server)
      -- The mempool accepts the first spend; submitblock connects it.
      let t1 = spendTx x 4_999_990_000
      addTransaction mp t1 >>= (`shouldSatisfy` isRight)
      blkB <- mkBlock server (ceHash tip0) [t1]
      submit server blkB >>= (`shouldSatisfy` isRight)
      getUTXO db x >>= (`shouldBe` Nothing)
      lookupUTXO cache x >>= (`shouldBe` Nothing)

  it "(4) race: a lookupUTXO disk read straddling a P2P spend+commit is not installed (ucGen guard)" $
    withLiveServer $ \server -> do
      let db = rsDB server
          cache = rsUTXOCache server
      x <- setupMatureCoin server
      flushCache cache
      mp <- nodeMempool server
      tip0 <- getValidatedChainTip db (rsHeaderChain server)
      blkB <- mkBlock server (ceHash tip0) [spendTx x 4_999_990_000]
      fired <- newIORef False
      -- Deterministic interleaving: the reader has read X from disk (still
      -- unspent there); before it installs, block B spending X is connected
      -- and committed by the P2P arm.
      writeIORef lookupUTXOReadHookRef $ \op -> when (op == x) $ do
        done <- readIORef fired
        when (not done) $ do
          writeIORef fired True
          p2pConnect server mp blkB >>= (`shouldBe` Right ())
      r <- lookupUTXO cache x
             `finally` writeIORef lookupUTXOReadHookRef (\_ -> return ())
      readIORef fired `shouldReturn` True
      getUTXO db x >>= (`shouldBe` Nothing)            -- control: B committed
      cached <- Map.lookup x <$> readTVarIO (ucEntries cache)
      putStrLn ("    [F0] racing lookupUTXO returned " ++ show (fmap ueSpent r)
                ++ "; cached entry: " ++ show (fmap ueSpent cached))
      r `shouldBe` Nothing
      cached `shouldSatisfy` maybe True ueSpent
      blkC <- mkBlock server (hashOf blkB) [spendTx x 4_999_980_000]
      submit server blkC >>= (`shouldSatisfy` isLeft)

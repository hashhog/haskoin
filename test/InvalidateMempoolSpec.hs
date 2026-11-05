{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | invalidateblock puts the disconnected blocks' transactions back in the
-- mempool (Core Chainstate::DisconnectTip -> MaybeUpdateMempoolForReorg,
-- validation.cpp).
--
-- The Core regtest ratchet (warden_d, warden_e) confirms a chain of spends
-- one per block, invalidates the first of those blocks and asks
-- getmempoolentry for each spend.  Core answers; haskoin answered -5
-- "Transaction not in mempool" because the invalidateblock RPC rewound the
-- chain without touching the mempool.
module InvalidateMempoolSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import Data.Aeson (toJSON)
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (blockHashToHex, regtest, initHeaderChain, getValidatedChainTip, ChainEntry(..))
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock )
import Haskoin.Mempool (newMempool, defaultMempoolConfig, addTransaction, getTransaction)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..),
  handleInvalidateBlock, handleReconsiderBlock, generateSingleBlock )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-vfork-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
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


-- | A 1-in-1-out spend of @op@ to a P2WSH(OP_TRUE) output.  @wit@ is the
-- witness for the input: empty for the raw-OP_TRUE coinbase coin, the
-- witness script for a P2WSH(OP_TRUE) coin.  The OP_RETURN output pads the
-- tx past the 65-byte minimum (tx-size-small).
spendOf :: OutPoint -> Word -> Tx
spendOf op salt = Tx
  { txVersion = 2
  , txInputs  = [TxIn op BS.empty 0xfffffffd]
  , txOutputs = [ TxOut (4_999_000_000 - fromIntegral salt * 10_000) p2wshTrue
                , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
  , txWitness = [ [BS.pack [0x51]] ]
  , txLockTime = 0
  }

-- | 0x00 0x20 sha256(0x51)
p2wshTrue :: BS.ByteString
p2wshTrue = BS.pack ([0x00, 0x20] ++
  [ 0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00, 0x09, 0x45
  , 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3, 0x32, 0x60 ])

invalidateRpc :: RpcServer -> BlockHash -> IO ()
invalidateRpc server h = do
  _ <- handleInvalidateBlock server (toJSON [blockHashToHex h])
  return ()

spec :: Spec
spec = describe "invalidateblock re-admits the disconnected blocks' transactions (Core)" $ do
  it "a chain of spends confirmed one per block is back in the mempool, parents first" $
    withLiveServer $ \server -> do
      let mine = either (fail . show) return =<< generateSingleBlock server p2wshTrue []
      -- block 1's coinbase matures once the tip is 101
      b1 <- mine
      mapM_ (const mine) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let tx0 = spendOf (OutPoint (computeTxId cb) 0) 1
          tx1 = spendOf (OutPoint (computeTxId tx0) 0) 2
          tx2 = spendOf (OutPoint (computeTxId tx1) 0) 3
      mapM_ (\t -> addTransaction (rsMempool server) t >>= (`shouldSatisfy` isRight')) [tx0, tx1, tx2]
      blk102 <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx0]
      _ <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx1]
      _ <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx2]
      mapM_ (\t -> getTransaction (rsMempool server) (computeTxId t) >>= (`shouldSatisfy` isNothing')) [tx0, tx1, tx2]
      invalidateRpc server blk102
      tip <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
      ceHeight tip `shouldBe` 101
      mapM_ (\(n, t) -> do
                m <- getTransaction (rsMempool server) (computeTxId t)
                (n, fmap (const ()) m) `shouldBe` (n :: String, Just ()))
            [("tx0", tx0), ("tx1", tx1), ("tx2", tx2)]

  it "reconsiderblock reconnects them and removes them from the mempool again" $
    withLiveServer $ \server -> do
      let mine = either (fail . show) return =<< generateSingleBlock server p2wshTrue []
      b1 <- mine
      mapM_ (const mine) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let tx0 = spendOf (OutPoint (computeTxId cb) 0) 1
      _ <- addTransaction (rsMempool server) tx0
      blk102 <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [tx0]
      invalidateRpc server blk102
      (fmap (const ()) <$> getTransaction (rsMempool server) (computeTxId tx0)) `shouldReturn` Just ()
      _ <- handleReconsiderBlock server (toJSON [blockHashToHex blk102])
      tip <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
      ceHeight tip `shouldBe` 102
      (fmap (const ()) <$> getTransaction (rsMempool server) (computeTxId tx0)) `shouldReturn` Nothing
  -- Core warden_e: a parent with 64 children whose own block is invalidated.
  -- The children are still in the pool, so re-adding the parent makes one
  -- cluster of 65.  Core re-adds with bypass_limits, then TrimToSize() drops
  -- the cheapest child; the cluster ends at 64 with the parent kept.
  it "an over-limit cluster formed by the re-add is trimmed to 64, cheapest child first" $
    withLiveServer $ \server -> do
      let mine = either (fail . show) return =<< generateSingleBlock server p2wshTrue []
      b1 <- mine
      mapM_ (const mine) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let each = (5_000_000_000 - 10_000) `div` 64
          parent = Tx { txVersion = 2
                      , txInputs = [TxIn (OutPoint (computeTxId cb) 0) BS.empty 0xfffffffd]
                      , txOutputs = replicate 64 (TxOut each p2wshTrue)
                      , txWitness = [[BS.pack [0x51]]], txLockTime = 0 }
          pid = computeTxId parent
          child i = Tx { txVersion = 2
                       , txInputs = [TxIn (OutPoint pid i) BS.empty 0xfffffffd]
                       , txOutputs = [ TxOut (each - (fromIntegral i + 1) * 1000) p2wshTrue
                                     , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
                       , txWitness = [[BS.pack [0x51]]], txLockTime = 0 }
          children = map child [0 .. 63]
      blk102 <- either (fail . show) return =<< generateSingleBlock server p2wshTrue [parent]
      mapM_ (\t -> addTransaction (rsMempool server) t >>= (`shouldSatisfy` isRight')) children
      invalidateRpc server blk102
      let present t = fmap (const ()) <$> getTransaction (rsMempool server) (computeTxId t)
      present parent `shouldReturn` Just ()
      present (head children) `shouldReturn` Nothing
      mapM present (tail children) >>= (`shouldBe` replicate 63 (Just ()))
  where
    isRight' (Right _) = True
    isRight' _ = False
    isNothing' Nothing = True
    isNothing' _ = False

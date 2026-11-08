{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | fix-haskoin-reorg-readd-mempoolentry: the entries invalidateblock puts
-- back in the mempool carry Core's height and ancestor/descendant aggregates.
--
-- Core (validation.cpp Chainstate::InvalidateBlock) disconnects one block at
-- a time and runs MaybeUpdateMempoolForReorg after EACH DisconnectTip, so a
-- re-added transaction is accepted while the tip is its own block's parent:
-- CTxMemPoolEntry::entryHeight is m_chain.Height() at that moment (102 for
-- the spend confirmed in 103).  The re-added transactions are linked to the
-- in-pool children that were re-added before them by
-- CTxMemPool::UpdateTransactionsFromBlock (txmempool.cpp), so the
-- ancestor/descendant aggregates span the whole re-added chain.
--
-- Core regtest ratchet group warden_d: three spends confirmed at 102, 103 and
-- 104, invalidateblock 102.  Core: tx0 height 101 descendantcount 3, tx1
-- height 102, tx2 height 103 ancestorcount 3.  haskoin stamped 101 on all
-- three and left tx0 with 2 descendants and tx2 with 2 ancestors.
module ReorgReaddEntrySpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO)
import Data.IORef (newIORef)
import Data.Word (Word32)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Aeson (toJSON, Value(..), decodeStrict)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Text.Encoding as TE
import System.Directory (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus (blockHashToHex, regtest, initHeaderChain, getValidatedChainTip, ChainEntry(..))
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock)
import Haskoin.Mempool (newMempool, defaultMempoolConfig, addTransaction, getTransaction, MempoolEntry(..))
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network (startPeerManager, stopPeerManager, Message, defaultPeerManagerConfig, PeerManagerConfig(..))
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc (RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..), handleInvalidateBlock
                  , handleGetMempoolEntry, generateSingleBlock)

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
invalidateRpc server h = () <$ handleInvalidateBlock server (toJSON [blockHashToHex h])

-- | (name, height, ancestorcount, ancestorsize, descendantcount, descendantsize)
type Row = (String, Word32, Int, Int, Int, Int)

entryRow :: RpcServer -> (String, Tx) -> IO Row
entryRow server (n, t) = do
  m <- getTransaction (rsMempool server) (computeTxId t)
  case m of
    Nothing -> return (n ++ " not in mempool", 0, 0, 0, 0, 0)
    Just e  -> return (n, meHeight e, meAncestorCount e, meAncestorSize e
                      , meDescendantCount e, meDescendantSize e)

-- | getmempoolentry's (height, ancestorcount, ancestorsize, descendantcount,
-- descendantsize) for @t@, read off the RPC's JSON.
rpcRow :: RpcServer -> (String, Tx) -> IO Row
rpcRow server (n, t) = do
  r <- handleGetMempoolEntry server (toJSON [txHex (computeTxId t)])
  let obj = case resResult r of
        String raw | Just body <- T.stripPrefix "__RAWJSON__:" raw
                   , Just (Object o) <- decodeStrict (TE.encodeUtf8 body) -> Just o
        Object o -> Just o
        _ -> Nothing
      int k = case obj >>= KM.lookup k of
        Just (Number x) -> truncate x
        _ -> -1 :: Int
  return ( maybe (n ++ ": " ++ show (resError r)) (const n) obj
         , fromIntegral (int "height"), int "ancestorcount", int "ancestorsize"
         , int "descendantcount", int "descendantsize")
  where
    txHex (TxId (Hash256 bs)) = TE.decodeUtf8 (B16.encode (BS.reverse bs))

-- | Core warden_d: three spends, each in the pool and then confirmed one per
-- block at 102, 103, 104; invalidateblock 102.  Returns the spends and the
-- vsize s they share (one shape).
wardenD :: RpcServer -> IO ([(String, Tx)], Int)
wardenD server = do
  let mine txs = either (fail . show) return =<< generateSingleBlock server p2wshTrue txs
  b1 <- mine []
  mapM_ (const (mine [])) [2 .. 101 :: Int]
  Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
  let tx0 = spendOf (OutPoint (computeTxId cb) 0) 1
      tx1 = spendOf (OutPoint (computeTxId tx0) 0) 2
      tx2 = spendOf (OutPoint (computeTxId tx1) 0) 3
  blk102 <- addTransaction (rsMempool server) tx0 >> mine [tx0]
  _ <- addTransaction (rsMempool server) tx1 >> mine [tx1]
  _ <- addTransaction (rsMempool server) tx2 >> mine [tx2]
  invalidateRpc server blk102
  tip <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
  ceHeight tip `shouldBe` 101
  Just e0 <- getTransaction (rsMempool server) (computeTxId tx0)
  return ([("tx0", tx0), ("tx1", tx1), ("tx2", tx2)], meSize e0)

spec :: Spec
spec = describe "invalidateblock re-adds entries with Core's height and aggregates (warden_d)" $ do
  it "reorg-readd-height: each re-added spend records its block's parent height (101, 102, 103)" $
    withLiveServer $ \server -> do
      (named, _) <- wardenD server
      let want = [("tx0", 101), ("tx1", 102), ("tx2", 103)]
      rows <- mapM (entryRow server) named
      [ (n, h) | (n, h, _, _, _, _) <- rows ] `shouldBe` want
      -- and getmempoolentry's "height" (the ratchet row)
      rpc <- mapM (rpcRow server) named
      [ (n, h) | (n, h, _, _, _, _) <- rpc ] `shouldBe` want

  it "reorg-readd-rpc-aggregates: getmempoolentry counts all in-pool ancestors and descendants" $
    withLiveServer $ \server -> do
      (named, s) <- wardenD server
      rows <- mapM (rpcRow server) named
      [ (n, ac, as, dc, ds) | (n, _, ac, as, dc, ds) <- rows ] `shouldBe`
        [ ("tx0", 1, s,     3, 3 * s)
        , ("tx1", 2, 2 * s, 2, 2 * s)
        , ("tx2", 3, 3 * s, 1, s) ]

  -- Core warden_e's shape: the children never left the pool, the parent's
  -- block is invalidated.  Admission of the parent sees no in-pool children,
  -- so without UpdateTransactionsFromBlock the children keep ancestorcount 1
  -- and the parent descendantcount 1.
  it "reorg-readd-relink: a parent re-added under its in-pool children is linked to them" $
    withLiveServer $ \server -> do
      let mine txs = either (fail . show) return =<< generateSingleBlock server p2wshTrue txs
      b1 <- mine []
      mapM_ (const (mine [])) [2 .. 101 :: Int]
      Just cb <- fmap (head . blockTxns) <$> getBlock (rsDB server) b1
      let each = (5_000_000_000 - 10_000) `div` 2
          parent = Tx { txVersion = 2
                      , txInputs = [TxIn (OutPoint (computeTxId cb) 0) BS.empty 0xfffffffd]
                      , txOutputs = replicate 2 (TxOut each p2wshTrue)
                      , txWitness = [[BS.pack [0x51]]], txLockTime = 0 }
          child i = Tx { txVersion = 2
                       , txInputs = [TxIn (OutPoint (computeTxId parent) i) BS.empty 0xfffffffd]
                       , txOutputs = [ TxOut (each - 1000) p2wshTrue
                                     , TxOut 0 (BS.pack (0x6a : 0x28 : replicate 40 0xab)) ]
                       , txWitness = [[BS.pack [0x51]]], txLockTime = 0 }
          kids = [("child0", child 0), ("child1", child 1)]
      blk102 <- mine [parent]
      mapM_ (\(_, t) -> addTransaction (rsMempool server) t) kids
      invalidateRpc server blk102
      Just pe <- getTransaction (rsMempool server) (computeTxId parent)
      kidRows <- mapM (entryRow server) kids
      let ps = meSize pe
          cs = case kidRows of ((_, _, _, _, _, d) : _) -> d; _ -> 0
      (meAncestorCount pe, meDescendantCount pe, meDescendantSize pe) `shouldBe` (1, 3, ps + 2 * cs)
      -- the children were admitted at tip 102, before the invalidate
      kidRows `shouldBe` [ ("child0", 102, 2, ps + cs, 1, cs), ("child1", 102, 2, ps + cs, 1, cs) ]

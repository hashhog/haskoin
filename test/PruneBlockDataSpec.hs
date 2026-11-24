{-# LANGUAGE OverloadedStrings #-}

-- | fix-haskoin-prune-noop: -prune must delete the block data haskoin
-- actually stores.
--
-- haskoin keeps block bodies (PrefixBlockData, 0x02) and undo records
-- (0x10) in RocksDB.  The prune code deleted blk*.dat / rev*.dat files that
-- nothing writes, so a pruned node kept every body and every undo record:
-- pruneblockchain answered a height and freed nothing, auto-prune never
-- fired (no file ever had a size), getblockchaininfo said pruneheight 0.
--
-- Core reference (v31.1):
--   * rpc/blockchain.cpp pruneblockchain: -8 "Negative block height.",
--     -1 "Blockchain is too short for pruning." (below PruneAfterHeight,
--     1000 on regtest), -8 "Blockchain is shorter than the attempted prune
--     height.", a height within MIN_BLOCKS_TO_KEEP (288) of the tip is
--     clamped to tip-288, and the answer is GetPruneHeight (last pruned).
--   * getblockchaininfo pruneheight = GetPruneHeight + 1.
--   * getblock of a pruned block: -1 "Block not available (pruned data)".
--   * node/blockstorage.cpp FindFilesToPrune: prune the oldest data until
--     the rest is under the target; never the last 288 blocks.
--   * init.cpp: no -txindex with -prune; without the index,
--     getrawtransaction(txid) answers -5 "No such mempool transaction. Use
--     -txindex ...".
--
-- TEETH: every "deletes"/"reports"/"answers" case below fails on master
-- (bodies and undo are still there, pruneheight 0, pruneblockchain errors
-- or answers the requested height).  The "nothing below the target" case
-- and the 288-block reorg are controls that pass on both trees.
module PruneBlockDataSpec (spec) where

import Test.Hspec
import Control.Concurrent (threadDelay)
import Control.Exception (bracket)
import Control.Monad (forM, forM_, replicateM)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Int (Int64)
import Data.Maybe (isJust, catMaybes)
import Data.Word (Word32)
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Map.Strict as Map
import qualified Data.Serialize as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import qualified Database.RocksDB as R
import System.Directory
  ( getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive
  , listDirectory, getFileSize, doesFileExist )
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, initHeaderChain, netGenesisBlock, medianTimePast
  , blockRewardForNet, computeMerkleRoot, netPowLimit, ChainEntry(..)
  , HeaderChain(..), getValidatedChainTip )
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Storage
  ( HaskoinDB(..), defaultDBConfig, withDB, newUTXOCache, getBlock
  , getUndoData, getBlockHeight, putBlockHeight, putBlock, getTxIndex, newBlockStore
  , BlockStore, autoPruneIfNeeded, PruneConfig(..), parsePruneArg
  , defaultPruneConfig, makeKey, KeyPrefix(..), toBE32 )
import Haskoin.HeaderReload (estimateUndoConnectedTip)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..), handleBatchRequest
  , generateSingleBlock, buildRegtestCoinbase, findRegtestNonce )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

-- | Regtest wire magic (FA BF B5 DA), as Main hands newBlockStore.
regtestMagic :: BS.ByteString
regtestMagic = BS.pack [0xfa, 0xbf, 0xb5, 0xda]

manualPrune :: PruneConfig
manualPrune = either error id (parsePruneArg 1)

chainLength :: Word32
chainLength = 1100

-- | A regtest RPC server in prune mode (-prune=1: a BlockStore exists, as
-- Main builds one iff --prune), with @chainLength@ blocks mined on it.
withMinedPrunedChain :: ((RpcServer, [BlockHash]) -> IO ()) -> IO ()
withMinedPrunedChain = withPrunedChainOf chainLength

-- | 'withMinedPrunedChain' with @n@ blocks.
withPrunedChainOf :: Word32 -> ((RpcServer, [BlockHash]) -> IO ()) -> IO ()
withPrunedChainOf n action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-prune-blockdata-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      bs    <- newBlockStore (dir </> "blocks") regtestMagic db
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
              , rsNetwork = regtest, rsBlockStore = Just bs
              , rsThread = threadVar, rsMockTime = mockTimeVar
              , rsWalletMgr = Nothing, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = manualPrune, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
            genesis = netGenesisBlock regtest
        -- As Main does for a fresh datadir: genesis body + height row.
        putBlock db (computeBlockHash (blockHeader genesis)) genesis
        putBlockHeight db 0 (computeBlockHash (blockHeader genesis))
        hashes <- mineBlocks server opTrue n
        action (server, hashes)

opTrue :: BS.ByteString
opTrue = BS.singleton 0x51

-- | Mine @n@ coinbase-only blocks on the validated tip, paying @spk@, and
-- hand them to submitblock ('submitBlock', the RPC connect path).  The
-- chain is built here rather than through the RPC miner so the prune cases
-- run on any tree: master's 'generateSingleBlock' paid mainnet's subsidy
-- and could not mine past regtest height 150 (the separate halving case
-- below covers that).
mineBlocks :: RpcServer -> BS.ByteString -> Word32 -> IO [BlockHash]
mineBlocks server spk n = replicateM (fromIntegral n) $ do
  let hc = rsHeaderChain server
  tip <- getValidatedChainTip (rsDB server) hc
  entries <- readTVarIO (hcEntries hc)
  let height    = ceHeight tip + 1
      parentH   = ceHash tip
      blockTime = medianTimePast entries parentH + 1
      coinbase  = buildRegtestCoinbase height (blockRewardForNet regtest height)
                    spk blockTime Nothing
      hdr = BlockHeader
        { bhVersion    = 0x20000000
        , bhPrevBlock  = parentH
        , bhMerkleRoot = computeMerkleRoot [computeTxId coinbase]
        , bhTimestamp  = blockTime
        , bhBits       = 0x207fffff
        , bhNonce      = 0
        }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  solved <- maybe (fail "could not solve regtest nonce") return mSolved
  let block = Block solved [coinbase]
  r <- submitBlock regtest (rsDB server) hc (rsUTXOCache server)
                   (rsPeerMgr server) (rsMempool server) (rsIndexMgr server) block
  either (\e -> fail ("submitblock at " ++ show height ++ ": " ++ e)) return r
  return (computeBlockHash solved)

-- | The reorg branch pays elsewhere: a block mined on 812 to 'opTrue' in the
-- same second as the invalidated 813 would BE that block (duplicate-invalid).
opTwo :: BS.ByteString
opTwo = BS.singleton 0x52

hashHex :: BlockHash -> T.Text
hashHex (BlockHash (Hash256 b)) = TE.decodeUtf8 (B16.encode (BS.reverse b))

txHex :: TxId -> T.Text
txHex (TxId (Hash256 b)) = TE.decodeUtf8 (B16.encode (BS.reverse b))

-- | (result, error) of one RPC call.
call :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
call server method params = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method)
        , ("params", A.Array (V.fromList params)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

errCodeMsg :: A.Value -> Maybe (A.Value, A.Value)
errCodeMsg (A.Object o) = (,) <$> KM.lookup "code" o <*> KM.lookup "message" o
errCodeMsg _ = Nothing

-- | Blocks at height h (1-based) in the mined list.
at :: [BlockHash] -> Word32 -> BlockHash
at hs h = hs !! (fromIntegral h - 1)

------------------------------------------------------------------------
-- Synthetic store for the auto-prune target cases: an active chain of
-- 1100 height-index rows whose bodies are 64 KiB and undo records 4 KiB,
-- written straight under haskoin's keys (prune touches only these keys).
------------------------------------------------------------------------

synthHash :: Word32 -> BlockHash
synthHash h = BlockHash (Hash256 (BS.replicate 28 0xab <> toBE32 h))

bodyBytes, undoBytes :: Int
bodyBytes = 65536
undoBytes = 4096

bodyKey, undoKey :: BlockHash -> BS.ByteString
bodyKey bh = makeKey PrefixBlockData (S.encode bh)
undoKey bh = BS.cons 0x10 (S.encode bh)

withSyntheticStore :: (FilePath -> HaskoinDB -> BlockStore -> IO ()) -> IO ()
withSyntheticStore action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-prune-synth-")
    removeDirectoryRecursive $ \dir -> do
    let dbDir = dir </> "chainstate"
    withDB (defaultDBConfig dbDir) $ \db -> do
      forM_ [0 .. chainLength] $ \h -> do
        let bh = synthHash h
        putBlockHeight db h bh
        R.put (dbHandle db) (dbWriteOpts db) (bodyKey bh) (BS.replicate bodyBytes 0x5a)
        R.put (dbHandle db) (dbWriteOpts db) (undoKey bh) (BS.replicate undoBytes 0x5b)
      bs <- newBlockStore (dir </> "blocks") regtestMagic db
      action dbDir db bs

hasBody, hasUndo :: HaskoinDB -> BlockHash -> IO Bool
hasBody db bh = isJust <$> R.get (dbHandle db) (dbReadOpts db) (bodyKey bh)
hasUndo db bh = isJust <$> R.get (dbHandle db) (dbReadOpts db) (undoKey bh)

storedHeights :: HaskoinDB -> IO [Word32]
storedHeights db = fmap catMaybes $ forM [0 .. chainLength] $ \h -> do
  b <- hasBody db (synthHash h)
  return (if b then Just h else Nothing)

dirBytes :: FilePath -> IO Integer
dirBytes d = do
  names <- listDirectory d
  sizes <- forM names $ \n -> do
    let p = d </> n
    isFile <- doesFileExist p
    if isFile then getFileSize p else return 0
  return (sum sizes)

autoTarget :: Int64 -> PruneConfig
autoTarget bytes = defaultPruneConfig { pcPruneTarget = Just bytes }

mib :: Int64
mib = 1024 * 1024

spec :: Spec
spec = do
  -- A pruned regtest chain must be longer than PruneAfterHeight (1000),
  -- so the RPC miner has to get past regtest's first halvings (every 150
  -- blocks, Core consensus.nSubsidyHalvingInterval).  It paid the mainnet
  -- schedule (50 BTC until 210,000), and block 150 failed validation with
  -- "Coinbase value exceeds allowed amount".
  describe "generatetoaddress on regtest pays regtest's subsidy (halving every 150 blocks)" $
    it "blocks 149 and 150 pay 50 and 25 BTC" $
      withPrunedChainOf 148 $ \(server, _) -> do
        r149 <- generateSingleBlock server opTrue []
        r150 <- generateSingleBlock server opTrue []
        let cbValue r = case r of
              Left e -> fail ("generate: " ++ e) >> return 0
              Right bh -> do
                Just b <- getBlock (rsDB server) bh
                return (sum (map txOutValue (txOutputs (head (blockTxns b)))))
        either (const False) (const True) r149 `shouldBe` True
        either Left (const (Right ())) r150 `shouldBe` Right ()
        v149 <- cbValue r149
        v150 <- cbValue r150
        v149 `shouldBe` 5000000000
        v150 `shouldBe` 2500000000

  describe "pruneblockchain on a pruned regtest node deletes the stored block data (Core -prune=1)" $
    aroundAll withMinedPrunedChain $ do

    it "txindex is off in prune mode: no index row for a mined coinbase, getrawtransaction(txid) answers Core's -5" $
      \(server, hs) -> do
        Just b500 <- getBlock (rsDB server) (at hs 500)
        let cbTxid = computeTxId (head (blockTxns b500))
        mLoc <- getTxIndex (rsDB server) cbTxid
        mLoc `shouldBe` Nothing
        (_, e) <- call server "getrawtransaction" [A.String (txHex cbTxid)]
        fmap fst (errCodeMsg e) `shouldBe` Just (A.Number (-5))

    it "pruneblockchain of a negative height is -8 Negative block height." $
      \(server, _) -> do
        (_, e) <- call server "pruneblockchain" [A.Number (-1)]
        errCodeMsg e `shouldBe` Just (A.Number (-8), A.String "Negative block height.")

    it "pruneblockchain above the tip is -8 Blockchain is shorter than the attempted prune height." $
      \(server, _) -> do
        (_, e) <- call server "pruneblockchain" [A.Number (fromIntegral chainLength + 1)]
        errCodeMsg e `shouldBe`
          Just (A.Number (-8), A.String "Blockchain is shorter than the attempted prune height.")

    it "pruneblockchain(tip) is clamped to tip-288 and returns the last pruned height, 812" $
      \(server, _) -> do
        (r, e) <- call server "pruneblockchain" [A.Number (fromIntegral chainLength)]
        e `shouldBe` A.Null
        r `shouldBe` A.Number 812

    it "the body and undo record of every block at heights 1..812 are deleted" $
      \(server, hs) -> do
        let db = rsDB server
        forM_ [1, 2, 400, 811, 812] $ \h -> do
          mb <- getBlock db (at hs h)
          (h, isJust mb) `shouldBe` (h, False)
          mu <- getUndoData db (at hs h)
          (h, isJust mu) `shouldBe` (h, False)

    it "genesis and the last 288 blocks (813..1100) keep their body and undo" $
      \(server, hs) -> do
        let db = rsDB server
            genesis = netGenesisBlock regtest
        mg <- getBlock db (computeBlockHash (blockHeader genesis))
        isJust mg `shouldBe` True
        forM_ [813, 814, 1000, 1100] $ \h -> do
          mb <- getBlock db (at hs h)
          (h, isJust mb) `shouldBe` (h, True)
          mu <- getUndoData db (at hs h)
          (h, isJust mu) `shouldBe` (h, True)

    -- Boot-time reconciliation (app/Main.hs) re-derives the connected tip
    -- from the undo records and re-stamps the best-block pointer to it.
    -- Prune deletes the undo of 1..812; those blocks were connected, so
    -- the estimate must stay at the tip, not fall to 0 (block 1 has no
    -- undo any more), or every restart of a pruned node rewinds its
    -- cursor to block 1.
    it "after pruning, the boot-time connected-tip estimate is still the tip (1100), not 0" $
      \(server, _) -> do
        h <- estimateUndoConnectedTip (rsDB server) (rsHeaderChain server) Nothing
        h `shouldBe` chainLength

    -- Same estimate on a snapshot-started chainstate (base B).  With the
    -- prune height (812) above B, the undo search must start above the
    -- prune height: starting at B+1 finds no undo and answers B, which the
    -- boot code would re-stamp as the best block, below the coin set.
    it "after pruning past a snapshot base (B=500), the boot estimate is still the tip, not B" $
      \(server, _) -> do
        h <- estimateUndoConnectedTip (rsDB server) (rsHeaderChain server) (Just 500)
        h `shouldBe` chainLength

    it "control: with the snapshot base above the prune height (B=900) the estimate is the tip" $
      \(server, _) -> do
        h <- estimateUndoConnectedTip (rsDB server) (rsHeaderChain server) (Just 900)
        h `shouldBe` chainLength

    it "getblock of a pruned block answers -1 Block not available (pruned data)" $
      \(server, hs) -> do
        (_, e) <- call server "getblock" [A.String (hashHex (at hs 100))]
        errCodeMsg e `shouldBe`
          Just (A.Number (-1), A.String "Block not available (pruned data)")

    it "getblockchaininfo reports pruned and pruneheight 813 (GetPruneHeight + 1)" $
      \(server, _) -> do
        (r, e) <- call server "getblockchaininfo" []
        e `shouldBe` A.Null
        case r of
          A.Object o -> do
            KM.lookup "pruned" o `shouldBe` Just (A.Bool True)
            KM.lookup "pruneheight" o `shouldBe` Just (A.Number 813)
            KM.lookup "automatic_pruning" o `shouldBe` Just (A.Bool False)
          other -> expectationFailure ("not an object: " ++ show other)

    it "control: the pruned node still reorgs 288 blocks deep (invalidate 813, mine 289, reconsider)" $
      \(server, hs) -> do
        (_, e1) <- call server "invalidateblock" [A.String (hashHex (at hs 813))]
        e1 `shouldBe` A.Null
        (c1, _) <- call server "getblockcount" []
        c1 `shouldBe` A.Number 812
        newHs <- mineBlocks server opTwo 289
        (best, _) <- call server "getbestblockhash" []
        best `shouldBe` A.String (hashHex (last newHs))
        (_, e2) <- call server "reconsiderblock" [A.String (hashHex (at hs 813))]
        e2 `shouldBe` A.Null
        -- The old branch (288 blocks above 812) has less work than the
        -- new one (289): the tip stays on the new branch.
        (best2, _) <- call server "getbestblockhash" []
        best2 `shouldBe` A.String (hashHex (last newHs))
        (c2, _) <- call server "getblockcount" []
        c2 `shouldBe` A.Number 1101

  describe "auto prune (-prune=N) keeps the stored block data under the target (Core FindFilesToPrune)" $ do

    it "control: below the target nothing is pruned" $
      withSyntheticStore $ \_ db bs -> do
        n <- autoPruneIfNeeded bs chainLength (autoTarget (200 * mib))
        n `shouldBe` 0
        hs <- storedHeights db
        length hs `shouldBe` fromIntegral chainLength + 1

    it "above the target it deletes the oldest bodies and undo until the rest fits, keeping more than 288" $
      withSyntheticStore $ \_ db bs -> do
        let target = 40 * mib
        n <- autoPruneIfNeeded bs chainLength (autoTarget target)
        n `shouldSatisfy` (> 0)
        hs <- storedHeights db
        -- genesis is never pruned; the rest is one contiguous run up to the tip
        let kept = filter (> 0) hs
            lowest = minimum kept
            keptBytes = fromIntegral (length kept) * fromIntegral (bodyBytes + undoBytes)
        kept `shouldBe` [lowest .. chainLength]
        length kept `shouldSatisfy` (> 288)
        (keptBytes :: Int64) `shouldSatisfy` (< target)
        -- and it did not throw away far more than needed
        keptBytes `shouldSatisfy` (> target `div` 2)
        undoGone <- hasUndo db (synthHash (lowest - 1))
        undoGone `shouldBe` False
        undoKept <- hasUndo db (synthHash lowest)
        undoKept `shouldBe` True

    it "never prunes within 288 blocks of the tip, however small the target" $
      withSyntheticStore $ \_ db bs -> do
        _ <- autoPruneIfNeeded bs chainLength (autoTarget mib)
        hs <- storedHeights db
        hs `shouldBe` (0 : [chainLength - 287 .. chainLength])

    it "does nothing at or below PruneAfterHeight (1000 on regtest)" $
      withSyntheticStore $ \_ db bs -> do
        n <- autoPruneIfNeeded bs 1000 (autoTarget mib)
        n `shouldBe` 0
        hs <- storedHeights db
        length hs `shouldBe` fromIntegral chainLength + 1

    it "the space is returned: the chainstate directory shrinks by more than half" $
      withSyntheticStore $ \dbDir _ bs -> do
        before <- dirBytes dbDir
        _ <- autoPruneIfNeeded bs chainLength (autoTarget mib)
        -- RocksDB removes obsolete WAL/SST files right after the
        -- compaction; allow it a moment.
        let poll :: Int -> IO Integer
            poll 0 = dirBytes dbDir
            poll k = do
              sz <- dirBytes dbDir
              if sz * 2 < before then return sz
                else threadDelay 200000 >> poll (k - 1)
        after <- poll 25
        putStrLn ("    chainstate bytes before prune " ++ show before
                  ++ ", after " ++ show after)
        (after * 2) `shouldSatisfy` (< before)

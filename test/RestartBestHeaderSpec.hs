{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | getblockchaininfo.headers across a restart: a best header that came in
-- through submitheader survives the reload (core-regtest
-- warden_invalidated_submit/{restart,p2p-header}/info:headers and
-- warden_invalidated_submit/p2p-header/valid:confirmations).
--
-- Core: AcceptBlockHeader adds the index entry and moves m_best_header
-- (validation.cpp ChainstateManager::AcceptBlockHeader); at startup
-- LoadBlockIndex walks every DB_BLOCK_INDEX entry and sets m_best_header to
-- the most-work valid one (node/blockstorage.cpp BlockManager::LoadBlockIndex,
-- "if (pindex->IsValid(BLOCK_VALID_TREE) && (m_best_header == nullptr ||
-- CBlockIndexWorkComparator()(m_best_header, pindex)))").  getblockchaininfo
-- reports m_best_header->nHeight as "headers" (rpc/blockchain.cpp).
--
-- haskoin rebuilds the best header above the connected tip from the
-- persisted height index (Storage.collectPersistedHeadersAbove).  The P2P
-- headers handler writes those rows (app/Main.hs); submitheader wrote only
-- the header row, so after a restart a submitheader-only best header was
-- reloaded as an off-chain entry and "headers" fell back to the connected
-- tip (core-regtest: Core 210, haskoin 208).
module RestartBestHeaderSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Word (Word32, Word64)
import Data.Maybe (fromMaybe)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Vector as V
import qualified Data.Serialize as S
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, Network(..), ChainEntry(..), HeaderChain(..)
  , getValidatedChainTip )
import Haskoin.HeaderReload (initHeaderChainFromDB)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, putBlockHeight )
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
  , handleBatchRequest, generateSingleBlock, buildRegtestCoinbase
  , findRegtestNonce )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

-- | Run @before@ on a fresh datadir, close the database, reopen it and run
-- @after@ on a header chain rebuilt by the restart-path reload, as a
-- restarted node does (app/Main.hs).
withRestart :: (RpcServer -> IO a) -> (a -> RpcServer -> IO ()) -> IO ()
withRestart before after = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-restart-best-header-")
    removeDirectoryRecursive $ \dir -> do
      x <- withServer dir before
      withServer dir (after x)

withServer :: FilePath -> (RpcServer -> IO a) -> IO a
withServer dir action =
  withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
    hc    <- initHeaderChainFromDB db regtest
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

-- | An unsolved coinbase-only regtest header on @parentHash@.
mkHeader :: RpcServer -> BlockHash -> BS.ByteString -> (Word32 -> Word64)
         -> IO (BlockHeader, Tx)
mkHeader server parentHash spk reward = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1
      coinbase  = buildRegtestCoinbase height (reward height) spk blockTime Nothing
  return ( BlockHeader
             { bhVersion    = 0x20000000
             , bhPrevBlock  = parentHash
             , bhMerkleRoot = computeMerkleRoot [computeTxId coinbase]
             , bhTimestamp  = blockTime
             , bhBits       = 0x207fffff
             , bhNonce      = 0
             }
         , coinbase )

mkChildPaying :: RpcServer -> BlockHash -> BS.ByteString -> (Word32 -> Word64) -> IO Block
mkChildPaying server parentHash spk reward = do
  (hdr, coinbase) <- mkHeader server parentHash spk reward
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h [coinbase])) mSolved

mkChild :: RpcServer -> BlockHash -> BS.ByteString -> IO Block
mkChild server parentHash spk = mkChildPaying server parentHash spk blockReward

submit :: RpcServer -> Block -> IO (Either String ())
submit server =
  submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
              (rsPeerMgr server) (rsMempool server) (rsIndexMgr server)

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

hex :: BlockHash -> T.Text
hex (BlockHash (Hash256 bs)) = TE.decodeUtf8 (B16.encode (BS.reverse bs))

validatedHash :: RpcServer -> IO BlockHash
validatedHash server = ceHash <$> getValidatedChainTip (rsDB server) (rsHeaderChain server)

chainN :: RpcServer -> Int -> IO [BlockHash]
chainN server n =
  mapM (\_ -> either (fail . show) return =<< generateSingleBlock server (BS.pack [0x51]) [])
       [1 .. n]

-- | One JSON-RPC call through the real dispatcher; (result, error).
rpc :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
rpc server method params = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method), ("params", A.Array (V.fromList params)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  -- encode resolves the pre-encoded result sentinel into plain JSON
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( fromMaybe A.Null (KM.lookup "result" o)
                         , fromMaybe A.Null (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

rpcOk :: RpcServer -> T.Text -> [A.Value] -> IO A.Value
rpcOk server method params = do
  (res, err) <- rpc server method params
  err `shouldBe` A.Null
  return res

hashArg :: BlockHash -> A.Value
hashArg = A.String . hex

-- | Submit @blk@'s header through the real submitheader RPC.
submitHeader :: RpcServer -> Block -> IO ()
submitHeader s blk = do
  let hdrHex = TE.decodeUtf8 (B16.encode (S.encode (blockHeader blk)))
  res <- rpcOk s "submitheader" [A.String hdrHex]
  res `shouldBe` A.Null

-- | (blocks, headers) from getblockchaininfo.
blocksHeaders :: RpcServer -> IO (Int, Int)
blocksHeaders s = do
  res <- rpcOk s "getblockchaininfo" []
  case res of
    A.Object o
      | Just (A.Number b) <- KM.lookup "blocks" o
      , Just (A.Number h) <- KM.lookup "headers" o -> return (round b, round h)
    other -> fail ("unexpected getblockchaininfo: " ++ show other)

confirmations :: RpcServer -> BlockHash -> IO Int
confirmations s h = do
  res <- rpcOk s "getblockheader" [hashArg h]
  case res of
    A.Object o | Just (A.Number c) <- KM.lookup "confirmations" o -> return (round c)
    other -> fail ("unexpected getblockheader: " ++ show other)

bestHeader :: RpcServer -> IO BlockHash
bestHeader s = ceHash <$> readTVarIO (hcTip (rsHeaderChain s))

spec :: Spec
spec = describe "best header across a restart (Core LoadBlockIndex sets m_best_header)" $ do
  it "restart-submitheader-best-header keeps getblockchaininfo.headers at the submitheader tip" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          b4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s b4
          b5 <- mkChild s (hashOf b4) (BS.pack [0x61])
          submitHeader s b5
          blocksHeaders s `shouldReturn` (3, 5)
          return (h3, hashOf b5))
      (\(h3, b5) s -> do
          -- the connected chain is untouched; only the best header is kept
          validatedHash s `shouldReturn` h3
          bestHeader s `shouldReturn` b5
          blocksHeaders s `shouldReturn` (3, 5))

  it "restart-submitheader-best-header: a valid sibling header after the restart has confirmations -1 and leaves headers alone" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          b4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s b4
          b5 <- mkChild s (hashOf b4) (BS.pack [0x61])
          submitHeader s b5
          return h3)
      (\h3 s -> do
          -- core-regtest warden_invalidated_submit/p2p-header: a header on the
          -- connected tip that is not on the best header chain.  Core: headers
          -- stays at the best header, confirmations -1 (not in the active chain).
          sib <- mkChild s h3 (BS.pack [0x62])
          submitHeader s sib
          blocksHeaders s `shouldReturn` (3, 5)
          confirmations s (hashOf sib) `shouldReturn` (-1))

  it "restart-submitheader-best-header follows a side header branch that became best" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          a4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s a4
          -- equal work to a4: stored, not the best header
          c4 <- mkChild s h3 (BS.pack [0x63])
          submitHeader s c4
          bestHeader s `shouldReturn` hashOf a4
          -- c5 makes the c-branch the best header
          c5 <- mkChild s (hashOf c4) (BS.pack [0x64])
          submitHeader s c5
          bestHeader s `shouldReturn` hashOf c5
          return (h3, hashOf c5))
      (\(h3, c5) s -> do
          validatedHash s `shouldReturn` h3
          bestHeader s `shouldReturn` c5
          blocksHeaders s `shouldReturn` (3, 5))

  it "restart-submitheader-best-header does not connect a header-only block; its body still connects" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          b4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s b4
          return (h3, b4))
      (\(h3, b4) s -> do
          -- a persisted best-header row must not read as a connected block
          validatedHash s `shouldReturn` h3
          (res, err) <- rpc s "getblockhash" [A.Number 4]
          res `shouldBe` A.Null
          err `shouldNotBe` A.Null
          -- the body then connects through the normal path (Core: the
          -- header-only index entry gets data and becomes the active tip)
          submit s b4 `shouldReturn` Right ()
          validatedHash s `shouldReturn` hashOf b4
          blocksHeaders s `shouldReturn` (4, 4))

  it "restart-submitheader-best-header rewrites a stale ancestor row below a row that already matches" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          b4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s b4
          b5 <- mkChild s (hashOf b4) (BS.pack [0x61])
          submitHeader s b5
          -- a stored equal-work sibling of b4 ...
          a4 <- mkChild s h3 (BS.pack [0x65])
          submitHeader s a4
          bestHeader s `shouldReturn` hashOf b5
          -- ... whose row replaced b4's (the P2P handler writes one row
          -- per header, so a lower row can name another branch while the
          -- row above it is already right)
          putBlockHeight (rsDB s) 4 (hashOf a4)
          b6 <- mkChild s (hashOf b5) (BS.pack [0x66])
          submitHeader s b6
          return (h3, hashOf b6))
      (\(h3, b6) s -> do
          validatedHash s `shouldReturn` h3
          bestHeader s `shouldReturn` b6
          blocksHeaders s `shouldReturn` (3, 6))

  -- sm-fix-haskoin-restart-best-header-recompute: the reload used to take the
  -- best header from the persisted height rows only (stopping at the first
  -- failed row) and never recomputed it over the loaded index.  Core
  -- ChainstateManager::LoadBlockIndex: m_best_header = the most-work
  -- IsValid(BLOCK_VALID_TREE) entry.
  it "restart-best-header-after-invalidate: the best header is the valid equal-work sibling, not the fork point" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          a4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s a4
          a5 <- mkChild s (hashOf a4) (BS.pack [0x61])
          submitHeader s a5
          c4 <- mkChild s h3 (BS.pack [0x63])
          submitHeader s c4
          bestHeader s `shouldReturn` hashOf a5
          _ <- rpcOk s "invalidateblock" [hashArg (hashOf a4)]
          -- control: in memory the best header moves to the valid sibling
          bestHeader s `shouldReturn` hashOf c4
          blocksHeaders s `shouldReturn` (3, 4)
          return (h3, hashOf c4))
      (\(h3, c4) s -> do
          bestHeader s `shouldReturn` c4
          blocksHeaders s `shouldReturn` (3, 4)
          -- the connected chain is untouched; c4 is header-only
          validatedHash s `shouldReturn` h3)

  it "restart-best-header-stale-rows: rows naming a lower-work branch do not hold the best header there" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          a4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s a4
          a5 <- mkChild s (hashOf a4) (BS.pack [0x61])
          submitHeader s a5
          c4 <- mkChild s h3 (BS.pack [0x63])
          submitHeader s c4
          c5 <- mkChild s (hashOf c4) (BS.pack [0x64])
          submitHeader s c5
          c6 <- mkChild s (hashOf c5) (BS.pack [0x65])
          submitHeader s c6
          bestHeader s `shouldReturn` hashOf c6
          -- the rows still name the a-branch below c6's row: the shape a P2P
          -- overtake (one row per header) or a kill mid-reorg leaves behind
          putBlockHeight (rsDB s) 4 (hashOf a4)
          putBlockHeight (rsDB s) 5 (hashOf a5)
          return (h3, hashOf c6))
      (\(h3, c6) s -> do
          bestHeader s `shouldReturn` c6
          blocksHeaders s `shouldReturn` (3, 6)
          validatedHash s `shouldReturn` h3)

  -- Control (passes before and after the fix): a failed branch is never
  -- the best header after a restart, even when it out-works every valid
  -- entry; with no valid sibling the best header is the connected tip.
  it "restart-best-header-failed-branch-only: an invalidated header branch leaves the best header at the connected tip" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          a4 <- mkChild s h3 (BS.pack [0x60])
          submitHeader s a4
          a5 <- mkChild s (hashOf a4) (BS.pack [0x61])
          submitHeader s a5
          _ <- rpcOk s "invalidateblock" [hashArg (hashOf a4)]
          bestHeader s `shouldReturn` h3
          return h3)
      (\h3 s -> do
          bestHeader s `shouldReturn` h3
          blocksHeaders s `shouldReturn` (3, 3)
          validatedHash s `shouldReturn` h3)

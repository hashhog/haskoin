{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | submitblock answers "prev-blk-not-found" for a well-formed block whose
-- parent is not in the block index, as Core does.
--
-- Core (validation.cpp ChainstateManager::AcceptBlockHeader):
--     BlockMap::iterator mi{m_blockman.m_block_index.find(block.hashPrevBlock)};
--     if (mi == m_blockman.m_block_index.end()) {
--         return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found");
-- and rpc/mining.cpp BIP22ValidationResult returns state.GetRejectReason()
-- verbatim, so submitblock's result is the string "prev-blk-not-found".
-- Core regtest row: chain/submit/prev-not-found:$ (Core prev-blk-not-found,
-- haskoin "rejected" on master 58016d3).
--
-- TEETH (master 58016d3): submitBlock's Left is
-- "Block validation failed: parent ... not in block index"; bip22ResultString
-- strips the wrapper, finds no rule for the rest and answers "rejected".
module SubmitPrevNotFoundSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..)
  , getValidatedChainTip, invalidateBlock )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig, getBlock )
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
  , generateSingleBlock, buildRegtestCoinbase, findRegtestNonce
  , submitBlockLeftResponse, bip22ResultString )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-prevnf-")
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

-- | A valid coinbase-only regtest block on @parent@ (which must already be
-- in the header index), paying to @spk@ so branches get distinct txids.
mkChild :: RpcServer -> BlockHash -> BS.ByteString -> IO Block
mkChild server parentHash spk = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1
      coinbase  = buildRegtestCoinbase height (blockReward height) spk blockTime Nothing
      hdr = BlockHeader
        { bhVersion    = 0x20000000
        , bhPrevBlock  = parentHash
        , bhMerkleRoot = computeMerkleRoot [computeTxId coinbase]
        , bhTimestamp  = blockTime
        , bhBits       = 0x207fffff
        , bhNonce      = 0
        }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h [coinbase])) mSolved

submit :: RpcServer -> Block -> IO (Either String ())
submit server =
  submitBlock regtest (rsDB server) (rsHeaderChain server) (rsUTXOCache server)
              (rsPeerMgr server) (rsMempool server) (rsIndexMgr server)

hashOf :: Block -> BlockHash
hashOf = computeBlockHash . blockHeader

validatedHash :: RpcServer -> IO BlockHash
validatedHash server = ceHash <$> getValidatedChainTip (rsDB server) (rsHeaderChain server)

invalidate :: RpcServer -> BlockHash -> IO ()
invalidate server h = do
  r <- invalidateBlock regtest (rsUTXOCache server) (rsDB server) (rsHeaderChain server) Nothing h
  r `shouldBe` Right ()

-- | Blocks 1..6 connected; returns their hashes (index 0 = height 1).
chain6 :: RpcServer -> IO [BlockHash]
chain6 server = mapM (\_ -> either (fail . show) return =<< generateSingleBlock server (BS.pack [0x51]) [])
                     [1 .. 6 :: Int]

-- | @blk@ with a wrong merkle root in its header, re-solved so the header's
-- proof of work is valid: only CheckMerkleRoot can object to it.
badMerkle :: Block -> IO Block
badMerkle blk = do
  let hdr = (blockHeader blk) { bhMerkleRoot = Hash256 (BS.replicate 32 0x77), bhNonce = 0 }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h (blockTxns blk))) mSolved

spec :: Spec
spec = describe "submitblock: unknown parent answers prev-blk-not-found (Core AcceptBlockHeader)" $ do
  it "submitblock-prev-not-found: a well-formed block on an unknown parent answers prev-blk-not-found" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      good <- mkChild server (last hs) (BS.pack [0x71])
      orphan <- reparent good (BlockHash (Hash256 (BS.replicate 32 0x11)))
      r <- submit server orphan
      case r of
        Right () -> expectationFailure "a block on an unknown parent was accepted"
        Left err -> submitBlockLeftResponse err `shouldBe` Right "prev-blk-not-found"
      validatedHash server `shouldReturn` last hs
      getBlock (rsDB server) (hashOf orphan) >>= (`shouldSatisfy` maybe True (const False))

  it "submitblock-prev-not-found control: a bad merkle root on an unknown parent still answers bad-txnmrklroot" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      good <- mkChild server (last hs) (BS.pack [0x72])
      orphan <- reparent good (BlockHash (Hash256 (BS.replicate 32 0x12)))
      bad <- badMerkle orphan
      r <- submit server bad
      either submitBlockLeftResponse (const (Right "accepted")) r
        `shouldBe` Right "bad-txnmrklroot"

  it "submitblock-prev-not-found control: a block on a failed parent still answers bad-prevblk" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      invalidate server (hs !! 3)
      good <- mkChild server (hs !! 3) (BS.pack [0x73])
      r <- submit server good
      either submitBlockLeftResponse (const (Right "accepted")) r
        `shouldBe` Right "bad-prevblk"

  it "submitblock-prev-not-found control: a block on a known parent is accepted (null)" $
    withLiveServer $ \server -> do
      hs <- chain6 server
      good <- mkChild server (last hs) (BS.pack [0x74])
      submit server good `shouldReturn` Right ()
      validatedHash server `shouldReturn` hashOf good

  it "bip22ResultString passes Core's prev-blk-not-found token through" $
    bip22ResultString "prev-blk-not-found" `shouldBe` "prev-blk-not-found"

-- | @blk@ moved onto @prev@ (re-solved; the body still commits to the
-- header's merkle root, so only the parent lookup can object).
reparent :: Block -> BlockHash -> IO Block
reparent blk prev = do
  let hdr = (blockHeader blk) { bhPrevBlock = prev, bhNonce = 0 }
  mSolved <- findRegtestNonce hdr (netPowLimit regtest)
  maybe (fail "could not solve regtest nonce")
        (\h -> return (Block h (blockTxns blk))) mSolved

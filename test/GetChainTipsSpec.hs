{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | getchaintips: the active tip is the connected tip, and a block whose
-- body was rejected is listed "invalid" (QUEUES haskoin, 2026-10-03 BIP68
-- agent; core-regtest chain/tips/final rows).
--
-- Core (rpc/blockchain.cpp getchaintips): the tips are the blocks off the
-- active chain with no child, plus the active tip; status is "active" for the
-- active chain, then "invalid" (BLOCK_FAILED_*), "headers-only" (no data),
-- "valid-fork" (BLOCK_VALID_SCRIPTS: connected once), "valid-headers"
-- (stored, never connected).  submitblock of a body that fails CheckBlock /
-- ConnectBlock stores the header and marks it BLOCK_FAILED_VALID
-- (validation.cpp AcceptBlock, InvalidBlockFound).
--
-- TEETH (master 336bc38): a header ahead of the connected tip is reported
-- "active" and the connected tip is not listed; a bad-cb-amount block given
-- to submitblock is not listed at all; a lesser-work side block that was
-- never connected is "valid-fork".
module GetChainTipsSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Word (Word32, Word64)
import Data.List (sort, isInfixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash)
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, Network(..), ChainEntry(..), HeaderChain(..), addHeader
  , getValidatedChainTip )
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.BlockTemplate (submitBlock)
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleBatchRequest, generateSingleBlock, buildRegtestCoinbase
  , findRegtestNonce )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-chaintips-")
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

-- | A coinbase-only regtest block on @parentHash@ paying @reward@ to @spk@.
mkChildPaying :: RpcServer -> BlockHash -> BS.ByteString -> (Word32 -> Word64) -> IO Block
mkChildPaying server parentHash spk reward = do
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  parent <- maybe (fail "parent not in index") return (Map.lookup parentHash entries)
  let height    = ceHeight parent + 1
      blockTime = medianTimePast entries parentHash + 1
      coinbase  = buildRegtestCoinbase height (reward height) spk blockTime Nothing
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

bestHeader :: RpcServer -> IO BlockHash
bestHeader server = ceHash <$> readTVarIO (hcTip (rsHeaderChain server))

chainN :: RpcServer -> Int -> IO [BlockHash]
chainN server n =
  mapM (\_ -> either (fail . show) return =<< generateSingleBlock server (BS.pack [0x51]) [])
       [1 .. n]

-- | getchaintips through the real dispatcher, as sorted
-- (hash, height, branchlen, status) rows.
chainTips :: RpcServer -> IO [(T.Text, Int, Int, T.Text)]
chainTips server = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String "getchaintips"), ("params", A.Array V.empty) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  resError resp `shouldBe` A.Null
  -- encode resolves the pre-encoded result sentinel into plain JSON
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  rows <- case body of
    A.Object o | Just (A.Array xs) <- KM.lookup "result" o -> return (V.toList xs)
    other -> fail ("unexpected getchaintips response: " ++ show other)
  sort <$> mapM row rows
  where
    row (A.Object o)
      | Just (A.String h) <- KM.lookup "hash" o
      , Just (A.Number height) <- KM.lookup "height" o
      , Just (A.Number bl) <- KM.lookup "branchlen" o
      , Just (A.String st) <- KM.lookup "status" o
      = return (h, round height, round bl, st)
    row v = fail ("bad tip row: " ++ show v)

expectTips :: RpcServer -> [(BlockHash, Int, Int, T.Text)] -> IO ()
expectTips server want = do
  got <- chainTips server
  got `shouldBe` sort [ (hex h, height, bl, st) | (h, height, bl, st) <- want ]

spec :: Spec
spec = describe "getchaintips (Core rpc/blockchain.cpp)" $ do
  it "a header ahead of the connected tip is headers-only; the connected tip is active" $
    withLiveServer $ \server -> do
      [_h1, _h2, h3] <- chainN server 3
      b4 <- mkChild server h3 (BS.pack [0x52])
      -- headers-first: the header is accepted, its body never connects
      Right _ <- addHeader regtest (rsHeaderChain server) (blockHeader b4) False
      bestHeader server `shouldReturn` hashOf b4
      validatedHash server `shouldReturn` h3
      expectTips server [ (h3, 3, 0, "active"), (hashOf b4, 4, 1, "headers-only") ]

  it "a body submitblock rejects with bad-cb-amount is listed invalid; tip and best header stay" $
    withLiveServer $ \server -> do
      [_h1, _h2, h3] <- chainN server 3
      bad4 <- mkChildPaying server h3 (BS.pack [0x53]) (\h -> blockReward h + 1)
      r <- submit server bad4
      r `shouldSatisfy` either (const True) (const False)
      validatedHash server `shouldReturn` h3
      bestHeader server `shouldReturn` h3
      expectTips server [ (h3, 3, 0, "active"), (hashOf bad4, 4, 1, "invalid") ]
      -- Core: the stored failed entry answers duplicate-invalid
      submit server bad4 `shouldReturn` Left "duplicate-invalid"
      validatedHash server `shouldReturn` h3
      -- a valid block at the same height still connects
      good4 <- mkChild server h3 (BS.pack [0x54])
      submit server good4 `shouldReturn` Right ()
      validatedHash server `shouldReturn` hashOf good4
      expectTips server [ (hashOf good4, 4, 0, "active"), (hashOf bad4, 4, 1, "invalid") ]

  it "a mutated body (non-verdict) stores nothing: the same header with its real body connects" $
    withLiveServer $ \server -> do
      [_h1, _h2, h3] <- chainN server 3
      good4 <- mkChild server h3 (BS.pack [0x55])
      other <- mkChild server h3 (BS.pack [0x56])
      -- good4's header with another coinbase: merkle-root mismatch (mutated)
      let mutated = Block (blockHeader good4) (blockTxns other)
      r <- submit server mutated
      r `shouldSatisfy` either (\e -> not ("duplicate" `isInfixOf` e)) (const False)
      expectTips server [ (h3, 3, 0, "active") ]
      submit server good4 `shouldReturn` Right ()
      validatedHash server `shouldReturn` hashOf good4
      expectTips server [ (hashOf good4, 4, 0, "active") ]

  it "a lesser-work side block stored by submitblock is valid-headers (never connected)" $
    withLiveServer $ \server -> do
      [_h1, _h2, h3] <- chainN server 3
      side1 <- mkChild server genesisHash (BS.pack [0x57])
      submit server side1 `shouldReturn` Left "inconclusive"
      validatedHash server `shouldReturn` h3
      expectTips server [ (h3, 3, 0, "active"), (hashOf side1, 1, 1, "valid-headers") ]

  it "after a valid reorg the new tip is active and the old branch is valid-fork" $
    withLiveServer $ \server -> do
      [_h1, h2, h3] <- chainN server 3
      s3 <- mkChild server h2 (BS.pack [0x58])
      submit server s3 `shouldReturn` Left "inconclusive"
      s4 <- mkChild server (hashOf s3) (BS.pack [0x59])
      submit server s4 `shouldReturn` Right ()
      validatedHash server `shouldReturn` hashOf s4
      bestHeader server `shouldReturn` hashOf s4
      expectTips server [ (hashOf s4, 4, 0, "active"), (h3, 3, 1, "valid-fork") ]
  where
    genesisHash = hashOf (netGenesisBlock regtest)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | getchaintips across a restart: blocks off the active chain survive the
-- reload (core-regtest failed_reorg/*/tips, warden_invalidated_submit/
-- {restart,p2p-header}/tips rows).
--
-- Core loads EVERY block index entry at startup, not only the active chain
-- (node/blockstorage.cpp BlockTreeDB::LoadBlockIndexGuts walks the whole
-- DB_BLOCK_INDEX keyspace; BlockManager::LoadBlockIndex re-links pprev and
-- marks every descendant of a BLOCK_FAILED_VALID entry failed too).  So a
-- failed, invalidated, side or reorged-away block is still a getchaintips
-- tip after a restart, with the status it had before.
--
-- TEETH (master 50649e8): the reload ('initHeaderChainFromDB') walked only
-- the active chain down from the best-block pointer, so after a restart
-- every off-chain tip was gone and reconsiderblock answered "Block not
-- found" for an invalidated block.  submitblock also never wrote the
-- header row of a rejected block or of a stored side-branch block, so
-- there was nothing on disk to reload them from.  A header built on a
-- failed block is refused "bad-prevblk" (Core AcceptBlockHeader), after a
-- restart too.
module RestartChainTipsSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.IORef (newIORef)
import Data.Word (Word32, Word64)
import Data.List (sort)
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
  ( regtest, medianTimePast, blockReward, computeMerkleRoot, checkProofOfWork
  , netPowLimit, Network(..), ChainEntry(..), HeaderChain(..)
  , getValidatedChainTip, addHeader )
import Haskoin.HeaderReload (initHeaderChainFromDB)
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig
  , putBlockHeader, getBlockHeader )
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

-- | Run @before@ on a fresh datadir, close the database, reopen it and run
-- @after@ on a header chain rebuilt by the restart-path reload, as a
-- restarted node does (app/Main.hs).
withRestart :: (RpcServer -> IO a) -> (a -> RpcServer -> IO ()) -> IO ()
withRestart before after = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-restart-tips-")
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

-- | A header on @parentHash@ whose hash does NOT meet its target.
mkBadPowHeader :: RpcServer -> BlockHash -> IO BlockHeader
mkBadPowHeader server parentHash = do
  (hdr, _) <- mkHeader server parentHash (BS.pack [0x5f]) blockReward
  case [ h | n <- [0 ..], let h = hdr { bhNonce = n }
           , not (checkProofOfWork h (netPowLimit regtest)) ] of
    (h : _) -> return h
    []      -> fail "no failing nonce"

overReward :: Word32 -> Word64
overReward h = blockReward h + 1

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

-- | getchaintips as sorted (hash, height, branchlen, status) rows.
chainTips :: RpcServer -> IO [(T.Text, Int, Int, T.Text)]
chainTips server = do
  res <- rpcOk server "getchaintips" []
  rows <- case res of
    A.Array xs -> return (V.toList xs)
    other -> fail ("unexpected getchaintips result: " ++ show other)
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

hashArg :: BlockHash -> A.Value
hashArg = A.String . hex

spec :: Spec
spec = describe "getchaintips after a restart (Core LoadBlockIndexGuts loads every index entry)" $ do
  it "restart keeps a block submitblock rejected with bad-cb-amount listed invalid" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          bad4 <- mkChildPaying s h3 (BS.pack [0x53]) overReward
          r <- submit s bad4
          r `shouldSatisfy` either (const True) (const False)
          expectTips s [ (h3, 3, 0, "active"), (hashOf bad4, 4, 1, "invalid") ]
          return (h3, bad4))
      (\(h3, bad4) s -> do
          validatedHash s `shouldReturn` h3
          expectTips s [ (h3, 3, 0, "active"), (hashOf bad4, 4, 1, "invalid") ]
          -- Core: the reloaded failed entry still answers duplicate-invalid
          submit s bad4 `shouldReturn` Left "duplicate-invalid"
          -- and a header built on it is bad-prevblk (AcceptBlockHeader)
          (c5, _) <- mkHeader s (hashOf bad4) (BS.pack [0x5e]) blockReward
          Just c5s <- findRegtestNonce c5 (netPowLimit regtest)
          r5 <- addHeader regtest (rsHeaderChain s) c5s False
          either id (const "accepted") r5 `shouldBe` "bad-prevblk"
          -- and the active tip still extends
          good4 <- mkChild s h3 (BS.pack [0x54])
          submit s good4 `shouldReturn` Right ()
          validatedHash s `shouldReturn` hashOf good4)

  it "restart keeps a side block that failed to connect in a reorg invalid (failed_reorg a)" $
    withRestart
      (\s -> do
          [_h1, h2, h3] <- chainN s 3
          s3 <- mkChild s h2 (BS.pack [0x58])
          submit s s3 `shouldReturn` Left "inconclusive"
          -- s4bad outweighs h3: the reorg connects s3, fails s4bad, returns to h3
          s4bad <- mkChildPaying s (hashOf s3) (BS.pack [0x59]) overReward
          _ <- submit s s4bad
          validatedHash s `shouldReturn` h3
          expectTips s [ (h3, 3, 0, "active"), (hashOf s4bad, 4, 2, "invalid") ]
          -- a header on the failed block, stored with no status of its own
          (c5, _) <- mkHeader s (hashOf s4bad) (BS.pack [0x5a]) blockReward
          Just c5s <- findRegtestNonce c5 (netPowLimit regtest)
          putBlockHeader (rsDB s) (computeBlockHash c5s) c5s
          return (h3, s3, s4bad, c5s))
      (\(h3, s3, _s4bad, c5) s -> do
          validatedHash s `shouldReturn` h3
          -- every descendant of a failed block is failed (Core LoadBlockIndex)
          expectTips s [ (h3, 3, 0, "active"), (computeBlockHash c5, 5, 3, "invalid") ]
          -- the valid prefix s3 is still known: a valid s4 on it outweighs h3
          -- and the node reorgs onto it, as Core does
          s4 <- mkChild s (hashOf s3) (BS.pack [0x5b])
          submit s s4 `shouldReturn` Right ()
          validatedHash s `shouldReturn` hashOf s4
          -- c5's fork point with the new active chain is s3: branchlen 2
          expectTips s [ (hashOf s4, 4, 0, "active"), (h3, 3, 1, "valid-fork")
                       , (computeBlockHash c5, 5, 2, "invalid") ])

  it "restart keeps a lesser-work side block valid-headers and a reorged-away branch valid-fork" $
    withRestart
      (\s -> do
          [_h1, h2, h3] <- chainN s 3
          side1 <- mkChild s genesisHash (BS.pack [0x57])
          submit s side1 `shouldReturn` Left "inconclusive"
          s3 <- mkChild s h2 (BS.pack [0x5c])
          submit s s3 `shouldReturn` Left "inconclusive"
          s4 <- mkChild s (hashOf s3) (BS.pack [0x5d])
          submit s s4 `shouldReturn` Right ()
          let want = [ (hashOf s4, 4, 0, "active"), (h3, 3, 1, "valid-fork")
                     , (hashOf side1, 1, 1, "valid-headers") ]
          expectTips s want
          return (hashOf s4, want))
      (\(tip, want) s -> do
          validatedHash s `shouldReturn` tip
          expectTips s want)

  it "restart keeps an invalidateblock'd block invalid and reconsiderblock still finds it" $
    withRestart
      (\s -> do
          [_h1, h2, h3] <- chainN s 3
          _ <- rpcOk s "invalidateblock" [hashArg h3]
          validatedHash s `shouldReturn` h2
          expectTips s [ (h2, 2, 0, "active"), (h3, 3, 1, "invalid") ]
          return (h2, h3))
      (\(h2, h3) s -> do
          validatedHash s `shouldReturn` h2
          expectTips s [ (h2, 2, 0, "active"), (h3, 3, 1, "invalid") ]
          _ <- rpcOk s "reconsiderblock" [hashArg h3]
          validatedHash s `shouldReturn` h3
          expectTips s [ (h3, 3, 0, "active") ])

  it "restart keeps a headers-only tip that came in through submitheader" $
    withRestart
      (\s -> do
          [_h1, _h2, h3] <- chainN s 3
          b4 <- mkChild s h3 (BS.pack [0x60])
          let hdrHex = TE.decodeUtf8 (B16.encode (S.encode (blockHeader b4)))
          _ <- rpcOk s "submitheader" [A.String hdrHex]
          -- the header row is on disk (Core: the block index entry)
          getBlockHeader (rsDB s) (hashOf b4) `shouldReturn` Just (blockHeader b4)
          let want = [ (h3, 3, 0, "active"), (hashOf b4, 4, 1, "headers-only") ]
          expectTips s want
          return (h3, want))
      (\(h3, want) s -> do
          validatedHash s `shouldReturn` h3
          expectTips s want)

  it "restart does not load a stored side header that fails proof of work" $
    withRestart
      (\s -> do
          [_h1, h2, h3] <- chainN s 3
          bad <- mkBadPowHeader s h2
          putBlockHeader (rsDB s) (computeBlockHash bad) bad
          return (h3, bad))
      (\(h3, bad) s -> do
          validatedHash s `shouldReturn` h3
          entries <- readTVarIO (hcEntries (rsHeaderChain s))
          Map.member (computeBlockHash bad) entries `shouldBe` False
          expectTips s [ (h3, 3, 0, "active") ])
  where
    genesisHash = hashOf (netGenesisBlock regtest)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | gettxoutsetinfo must label the coins it hashed, not a later tip.
--
-- Live 2026-09-18 940000→950000 gate: getblockcount was 940062 while
-- gettxoutsetinfo returned height 940000 with hash 118da7d0… — neither
-- the rung commitment 7cfc16fc… the importer had just printed, nor a
-- hash of the 940062 coin set.  Receipt:
-- receipts/haskoin-bad-base-read-940000-stale-height-label-2026-09-18.md
--
-- Cause: the at-tip arm captured 'PrefixBestBlock' then walked
-- 'PrefixUTXO' on a later iterator (and hashed on a third).  Blocks
-- that connected in between advanced the coins without advancing the
-- label, so the range-runner's skip-if-past-base guard saw height ==
-- base and graded the mixed hash as BAD-BASE-READ.
--
-- Core: kernel/coinstats.cpp ComputeUTXOStats takes cs_main only to
-- create the coins-view cursor (a leveldb snapshot) and to read
-- pcursor->GetBestBlock(); both the height and the hash come from that
-- snapshot.
--
-- Controls:
--   * after 50 post-base connects, getblockcount / getblockchaininfo /
--     gettxoutsetinfo agree on height (the operator discriminator)
--   * a mid-scan connect of 50 further blocks must not change the
--     (height, hash) pair the in-flight scan returns
module GetTxOutSetInfoSnapshotSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM (atomically, modifyTVar', newTVarIO, readTVarIO, writeTVar)
import Control.Exception (bracket)
import Control.Monad (foldM_, when)
import Data.Aeson (Value(..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Scientific as Sci
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32, Word64)
import System.Directory (removeDirectoryRecursive, getTemporaryDirectory)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Types
  ( Block(..), BlockHeader(..), BlockHash(..), Hash256(..), Tx(..), TxIn(..)
  , TxOut(..), OutPoint(..), TxId(..)
  )
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
  ( regtest, netGenesisBlock, headerWork, connectBlockAt
  , initHeaderChain, HeaderChain(..), ChainEntry(..), BlockStatus(..)
  , mkCandidateKey, getValidatedChainTip
  )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig
  , getBestBlockHash
  )
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..)
  )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc
  ( RpcServer(..), RpcConfig(..), defaultRpcConfig, RpcResponse(..)
  , handleGetTxOutSetInfo, handleGetBlockCount, handleGetBlockchainInfo
  , computeTxOutSetAtTip
  )

--------------------------------------------------------------------------------
-- Harness
--------------------------------------------------------------------------------

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-gtxo-snap-")
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

coinbaseBlock :: BlockHash -> Word32 -> Word32 -> Block
coinbaseBlock prevHash nonce ts = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = Hash256 (BS.replicate 32 0x00)
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff
      , bhNonce      = nonce
      }
  , blockTxns = [ coinbaseTx nonce ]
  }

coinbaseTx :: Word32 -> Tx
coinbaseTx nonce = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff
      , txInScript     = BS.pack [0x51, fromIntegral (nonce `mod` 256)]
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut
      { txOutValue  = 5000000000 :: Word64
      , txOutScript = BS.pack [0x51]
      } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

-- | Connect @n@ coinbase-only blocks on top of the current validated
-- tip (connecting genesis first if PrefixBestBlock is unset).
connectNBlocks :: RpcServer -> Word32 -> IO ()
connectNBlocks server n = do
  let db  = rsDB server
      hc  = rsHeaderChain server
      net = rsNetwork server
      genesisBlk = netGenesisBlock net
  genesisCe <- readTVarIO (hcTip hc)
  mBest <- getBestBlockHash db
  start <- case mBest of
    Nothing -> do
      r <- connectBlockAt db net genesisBlk 0 Map.empty
      case r of
        Right () -> return genesisCe
        Left e   -> fail ("connect genesis: " ++ e)
    Just bh -> do
      entries <- readTVarIO (hcEntries hc)
      case Map.lookup bh entries of
        Just ce -> return ce
        Nothing -> return genesisCe
  foldM_ (\prev _ -> do
            let h   = ceHeight prev + 1
                blk = coinbaseBlock (ceHash prev) h (1296688700 + h)
                hdr = blockHeader blk
                ce  = ChainEntry
                  { ceHeader     = hdr
                  , ceHash       = computeBlockHash hdr
                  , ceHeight     = h
                  , ceChainWork  = ceChainWork prev + headerWork hdr
                  , cePrev       = Just (ceHash prev)
                  , ceStatus     = StatusValid
                  , ceMedianTime = bhTimestamp hdr
                  , ceSequenceId = fromIntegral h + 2
                  }
            r <- connectBlockAt db net blk h Map.empty
            case r of
              Right () -> return ()
              Left e   -> fail ("connectBlockAt " ++ show h ++ ": " ++ e)
            insertActiveTip hc ce
            return ce)
         start [1 .. n]

--------------------------------------------------------------------------------
-- JSON helpers
--------------------------------------------------------------------------------

decodeRawResult :: Value -> IO Value
decodeRawResult (String s) =
  let magic = "__RAWJSON__:"
      payload = if magic `T.isPrefixOf` s then T.drop (T.length magic) s else s
  in case Aeson.decode (BL.fromStrict (TE.encodeUtf8 payload)) of
       Just v  -> return v
       Nothing -> fail ("could not decode raw JSON: " ++ T.unpack payload)
decodeRawResult v =
  case v of
    Object _ -> return v
    Number _ -> return v
    _        -> fail ("unexpected RPC result shape: " ++ show v)

field :: T.Text -> Value -> Maybe Value
field k (Object o) = KM.lookup (K.fromText k) o
field _ _          = Nothing

asWord32 :: Value -> Maybe Word32
asWord32 (Number n) = Sci.toBoundedInteger n
asWord32 _          = Nothing

asText :: Value -> Maybe T.Text
asText (String t) = Just t
asText _          = Nothing

rpcHeight :: RpcResponse -> IO Word32
rpcHeight resp = do
  when (resError resp /= Null) $
    fail ("RPC error: " ++ show (resError resp))
  v <- decodeRawResult (resResult resp)
  case asWord32 v of
    Just h -> return h
    Nothing -> case field "blocks" v >>= asWord32 of
      Just h -> return h
      Nothing -> case field "height" v >>= asWord32 of
        Just h -> return h
        Nothing -> fail ("no height in " ++ show v)

rpcTxOutSet :: RpcResponse -> IO (Word32, T.Text)
rpcTxOutSet resp = do
  when (resError resp /= Null) $
    fail ("gettxoutsetinfo error: " ++ show (resError resp))
  v <- decodeRawResult (resResult resp)
  let mh = field "height" v >>= asWord32
      hs = field "hash_serialized_3" v >>= asText
  case (mh, hs) of
    (Just h, Just s) -> return (h, s)
    _ -> fail ("gettxoutsetinfo missing height/hash: " ++ show v)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "gettxoutsetinfo snapshot consistency" $ do

    it "after 50 post-base connects, getblockcount, getblockchaininfo and gettxoutsetinfo agree on height" $ do
      withLiveServer $ \server -> do
        -- Snapshot-like base (10 connected blocks) then 50 more, matching
        -- the operator discriminator: call the three RPCs in one breath.
        connectNBlocks server 10
        connectNBlocks server 50
        countH <- handleGetBlockCount server >>= rpcHeight
        infoH  <- handleGetBlockchainInfo server >>= rpcHeight
        (setH, _) <- handleGetTxOutSetInfo server Null >>= rpcTxOutSet
        countH `shouldBe` 60
        infoH  `shouldBe` countH
        setH   `shouldBe` countH

    it "height labels the coins hashed even if the chain moves mid-scan" $ do
      withLiveServer $ \server -> do
        connectNBlocks server 10
        (h0, hash0) <- handleGetTxOutSetInfo server Null >>= rpcTxOutSet
        h0 `shouldBe` 10
        -- Connect 50 more BETWEEN capturing the tip and hashing the coins
        -- (the production seam 'computeTxOutSetAtTip' exposes).
        resp <- computeTxOutSetAtTip server True False (connectNBlocks server 50)
        (h1, hash1) <- rpcTxOutSet resp
        liveH <- getValidatedChainTip (rsDB server) (rsHeaderChain server)
        ceHeight liveH `shouldBe` 60
        -- The in-flight scan must still report the frozen (height, hash)
        -- pair from before the 50 connects.  Pre-fix this is height 10
        -- with the height-60 hash (the BAD-BASE-READ shape).
        h1    `shouldBe` h0
        hash1 `shouldBe` hash0

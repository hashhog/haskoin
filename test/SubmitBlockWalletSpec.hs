{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | submitblock must credit loaded wallets (batch5-haskoin-node_error).
--
-- Core's CWallet::blockConnected fires for every block ConnectTip connects,
-- whoever submitted it.  haskoin only scanned wallets from generatetoaddress,
-- so the Core regtest wallet group (101 blocks fed by submitblock, coinbase
-- paying the wallet's own address) saw getbalance 0 where Core reports 50,
-- and sendtoaddress failed "Insufficient funds" where Core succeeds.
--
-- TEETH: before the change the wallet's tx history stays empty after
-- submitblock; after it the coinbase is recorded at the block's height.
module SubmitBlockWalletSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Data.Aeson (toJSON, Value(Null, String), Value, encode, decode)
import qualified Data.ByteString.Lazy as BL
import Data.Aeson.Key (fromText)
import qualified Data.Aeson.KeyMap as KM
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Serialize as S
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Data.List (sort)
import Haskoin.Crypto (computeTxId, computeBlockHash, Address(..))
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..) )
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Wallet
  ( WalletManager, WalletState(..), newWalletManager, createManagedWallet
  , getNewAddress, AddressType(..), getWalletTxHistory, getChangeAddress
  , scanBlockForWallet, WalletTxHistoryEntry(..), WalletTxDetail(..)
  , removeWalletUTXO, recordSentTx )
import Haskoin.Rpc
  ( RpcServer(..), RpcResponse(..), defaultRpcConfig, RpcConfig(..)
  , handleSubmitBlock, handleListUnspent, handleGetBalances, buildRegtestCoinbase, findRegtestNonce )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withWalletServer :: (RpcServer -> WalletManager -> IO ()) -> IO ()
withWalletServer action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-sbwallet-")
    removeDirectoryRecursive $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 0 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      wm    <- newWalletManager (dir </> "wallets") regtest
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
              , rsWalletMgr = Just wm, rsStartTime = 0
              , rsCookieFile = dir </> ".cookie", rsCookiePassword = T.empty
              , rsBlockSubmissionPaused = pauseVar, rsIndexMgr = Nothing
              , rsPruneConfig = defaultPruneConfig, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
        action server wm

-- | A valid coinbase-only regtest block on @parentHash@ paying to @spk@.
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

p2wpkhScript :: Address -> BS.ByteString
p2wpkhScript (WitnessPubKeyAddress (Hash160 h)) = BS.pack [0x00, 0x14] <> h
p2wpkhScript a = error ("not a P2WPKH address: " ++ show a)

submitHex :: RpcServer -> Block -> IO RpcResponse
submitHex server blk =
  handleSubmitBlock server (toJSON [TE.decodeUtf8 (B16.encode (S.encode blk))])

spec :: Spec
spec = describe "submitblock credits loaded wallets (Core CWallet::blockConnected)" $ do
  it "a block paying the wallet's address, fed via submitblock, lands in its tx history" $
    withWalletServer $ \server wm -> do
      Right ws <- createManagedWallet wm "w" False False
      addr <- getNewAddress AddrP2WPKH (wsWallet ws)
      tip <- readTVarIO (hcTip (rsHeaderChain server))
      blk <- mkChild server (ceHash tip) (p2wpkhScript addr)
      resp <- submitHex server blk
      resError resp `shouldBe` Null
      tipAfter <- readTVarIO (hcTip (rsHeaderChain server))
      ceHash tipAfter `shouldBe` computeBlockHash (blockHeader blk)
      hist <- getWalletTxHistory (wsWallet ws)
      length hist `shouldBe` 1

  it "CONTROL: a block paying a foreign script leaves the wallet history empty" $
    withWalletServer $ \server wm -> do
      Right ws <- createManagedWallet wm "w" False False
      tip <- readTVarIO (hcTip (rsHeaderChain server))
      blk <- mkChild server (ceHash tip) (BS.pack [0x51])
      _ <- submitHex server blk
      hist <- getWalletTxHistory (wsWallet ws)
      length hist `shouldBe` 0

  -- Core: an immature coinbase (depth <= COINBASE_MATURITY) is not listed by
  -- listunspent (AvailableCoins) and is counted as immature, not trusted, by
  -- getbalances (GetBlocksToMaturity = COINBASE_MATURITY + 1 - depth).
  it "listunspent and getbalances treat a coinbase as mature only at depth 101" $
    withWalletServer $ \server wm -> do
      Right ws <- createManagedWallet wm "w" False False
      addr <- getNewAddress AddrP2WPKH (wsWallet ws)
      let spk = p2wpkhScript addr
          extend n = mapM_ (\_ -> do
            t <- readTVarIO (hcTip (rsHeaderChain server))
            b <- mkChild server (ceHash t) spk
            _ <- submitHex server b
            return ()) [1 .. n :: Int]
      extend 100   -- tip 100: block 1 has depth 100, still immature
      lu100 <- handleListUnspent server (toJSON ([] :: [Int]))
      listLen (resResult lu100) `shouldBe` 0
      extend 1     -- tip 101: block 1 has depth 101, mature
      lu101 <- handleListUnspent server (toJSON ([] :: [Int]))
      listLen (resResult lu101) `shouldBe` 1
      bals <- handleGetBalances server (toJSON ([] :: [Int]))
      mineField "trusted" (resResult bals) `shouldBe` Just 50
      mineField "immature" (resResult bals) `shouldBe` Just 5000
  -- Core CachedTxGetAmounts: on a tx the wallet funded, change is not
  -- reported; every other output gets a "send" row, and one paying the wallet
  -- itself also gets its "receive" row (gettransaction details of a
  -- send-to-self = [receive 1, send -1], not [receive 1, receive 49]).
  it "a send-to-self reports send+receive for the payee and nothing for change" $
    withWalletServer $ \_ wm -> do
      Right ws <- createManagedWallet wm "w" False False
      let w = wsWallet ws
      a <- getNewAddress AddrP2WPKH w
      b <- getNewAddress AddrP2WPKH w
      c <- getChangeAddress w
      let funding = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 7))) 0) BS.empty 0xffffffff]
                       [TxOut 5000000000 (p2wpkhScript a)] [] 0
          spend = Tx 2 [TxIn (OutPoint (computeTxId funding) 0) BS.empty 0xfffffffd]
                      [TxOut 100000000 (p2wpkhScript b), TxOut 4899999000 (p2wpkhScript c)] [] 0
          hdr = BlockHeader 0x20000000 (BlockHash (Hash256 (BS.replicate 32 0))) (Hash256 (BS.replicate 32 0)) 0 0x207fffff 0
      scanBlockForWallet w (Block hdr [funding]) 1
      -- what sendtoaddress does before the tx confirms (commitWalletSpend):
      -- drop the spent coin from the ledger, keep it in the sent-tx record
      let prevOp = OutPoint (computeTxId funding) 0
      removeWalletUTXO w prevOp
      recordSentTx w spend [(prevOp, head (txOutputs funding))] (Just 1) (Just c) 1000
      scanBlockForWallet w (Block hdr [funding, spend]) 2
      hist <- getWalletTxHistory w
      let [e] = [ x | x <- hist, wthTxId x == computeTxId spend ]
      sort [ (wtdCategory d, wtdAmount d) | d <- wthDetails e ]
        `shouldBe` [("receive", 100000000), ("send", -100000000)]
      -- the debit was booked, so the tx reads as funded by us (fee, from-me)
      wthDebit e `shouldBe` 5000000000
  where
    -- results of the streaming handlers arrive as "__RAWJSON__:<json>"
    unraw :: Value -> Value
    unraw (String t) | Just j <- T.stripPrefix "__RAWJSON__:" t
                     , Just v <- decode (BL.fromStrict (TE.encodeUtf8 j)) = v
    unraw v = v
    listLen v = case decode (encode (unraw v)) :: Maybe [Value] of
      Just xs -> length xs
      Nothing -> -1
    mineField k v = do
      o <- decode (encode (unraw v)) :: Maybe (KM.KeyMap Value)
      m <- KM.lookup (fromText "mine") o
      mo <- decode (encode m) :: Maybe (KM.KeyMap Value)
      x <- KM.lookup (fromText k) mo
      decode (encode x) :: Maybe Double

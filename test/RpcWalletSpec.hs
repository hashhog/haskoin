{-# LANGUAGE OverloadedStrings #-}

-- | secfix-haskoin-wallet-passphrase-unenforced (C5): an encrypted, locked
-- wallet must refuse every RPC that exports or signs with a private key.
--
-- Core: wallet/rpc/util.cpp EnsureWalletIsUnlocked throws
-- RPC_WALLET_UNLOCK_NEEDED (-13) "Error: Please enter the wallet passphrase
-- with walletpassphrase first." from dumpprivkey (legacy), importprivkey
-- (legacy), importdescriptors, signmessage, signrawtransactionwithwallet,
-- sendtoaddress/sendmany (SendMoney) and walletprocesspsbt when sign=true.
-- bumpfee and psbtbumpfee (one Core helper, bumpfee_helper) refuse the
-- same way after parsing the txid.
--
-- TEETH: on the base commit encryptwallet + walletlock changed nothing —
-- dumpprivkey returned the WIF, sendtoaddress broadcast a signed spend.
-- Every case is driven through the real dispatcher ('handleBatchRequest'),
-- by method name, exactly as an RPC client reaches it.
module RpcWalletSpec (spec) where

import Test.Hspec
import Control.Exception (bracket)
import Control.Concurrent.STM (newTVarIO, readTVarIO)
import Control.Monad (forM_, replicateM_)
import qualified Data.Aeson as A
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import Data.IORef (newIORef, readIORef, writeIORef, atomicModifyIORef')
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Types (statusCode)
import Network.Socket (SockAddr(..), tupleToHostAddress)
import Network.Wai
  ( Request(..), defaultRequest, responseStatus, responseToStream
  , setRequestBodyChunks )
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Serialize as S
import qualified Data.Vector as V
import System.Directory
  (getTemporaryDirectory, createDirectoryIfMissing, removeDirectoryRecursive)
import System.IO.Temp (createTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, Address(..))
import Haskoin.Consensus
  ( regtest, initHeaderChain, medianTimePast, blockReward, computeMerkleRoot
  , netPowLimit, ChainEntry(..), HeaderChain(..) )
import Haskoin.Storage (defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig)
import Haskoin.Mempool (newMempool, defaultMempoolConfig, getMempoolTxIds)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Network
  ( startPeerManager, stopPeerManager, Message
  , defaultPeerManagerConfig, PeerManagerConfig(..) )
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Payjoin (defaultPayjoinConfig, PayjoinConfig(..))
import Haskoin.Wallet
  ( WalletManager, WalletState(..), newWalletManager, createManagedWallet
  , getDefaultWallet
  , getNewAddress, getChangeAddress, AddressType(..), addressToTextW
  , recordSentTx )
import Haskoin.Rpc
  ( RpcServer(..), defaultRpcConfig, RpcConfig(..), handleBatchRequest
  , buildRegtestCoinbase, findRegtestNonce, combinedApp )

liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withWalletServer :: (RpcServer -> WalletManager -> IO ()) -> IO ()
withWalletServer = withWalletServerPj defaultPayjoinConfig

withWalletServerPj :: PayjoinConfig -> (RpcServer -> WalletManager -> IO ()) -> IO ()
withWalletServerPj pjCfg action = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket
    (createTempDirectory base "haskoin-rpcwallet-")
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
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = pjCfg
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
        action server wm

-- | One JSON-RPC call through the real dispatcher: (result, error).
call :: RpcServer -> T.Text -> [A.Value] -> IO (A.Value, A.Value)
call server method ps = do
  let req = A.Object $ KM.fromList
        [ ("jsonrpc", A.String "1.0"), ("id", A.Number 1)
        , ("method", A.String method), ("params", A.Array (V.fromList ps)) ]
  resps <- handleBatchRequest server [req]
  resp <- case resps of
    [r] -> return r
    _   -> fail "expected one response"
  body <- maybe (fail "response is not JSON") return (A.decode (A.encode resp))
  case body of
    A.Object o -> return ( maybe A.Null id (KM.lookup "result" o)
                         , maybe A.Null id (KM.lookup "error" o) )
    other -> fail ("unexpected response: " ++ show other)

errCode :: A.Value -> Maybe Int
errCode (A.Object o) = case KM.lookup "code" o of
  Just (A.Number n) -> Just (round n)
  _ -> Nothing
errCode _ = Nothing

errMsg :: A.Value -> Maybe T.Text
errMsg (A.Object o) = case KM.lookup "message" o of
  Just (A.String t) -> Just t
  _ -> Nothing
errMsg _ = Nothing

unlockNeededMsg :: T.Text
unlockNeededMsg = "Error: Please enter the wallet passphrase with walletpassphrase first."

-- | The call must answer Core's RPC_WALLET_UNLOCK_NEEDED.
shouldNeedUnlock :: (A.Value, A.Value) -> Expectation
shouldNeedUnlock (res, err) = do
  (errCode err, errMsg err) `shouldBe` (Just (-13), Just unlockNeededMsg)
  res `shouldBe` A.Null

-- | The call must not be refused for the lock.
shouldNotNeedUnlock :: (A.Value, A.Value) -> Expectation
shouldNotNeedUnlock (_, err) = errCode err `shouldNotBe` Just (-13)

str :: T.Text -> A.Value
str = A.String

encryptAndLock :: RpcServer -> IO ()
encryptAndLock server = do
  (_, e1) <- call server "encryptwallet" [str "correct horse"]
  e1 `shouldBe` A.Null
  (_, e2) <- call server "walletlock" []
  e2 `shouldBe` A.Null

unlock :: RpcServer -> IO ()
unlock server = do
  (_, e) <- call server "walletpassphrase" [str "correct horse", A.Number 600]
  e `shouldBe` A.Null

-- | A wallet with one fresh P2WPKH address and that address's WIF, read
-- while the wallet is still unencrypted.
freshWallet :: RpcServer -> WalletManager -> IO (Address, T.Text)
freshWallet server wm = do
  Right ws <- createManagedWallet wm "w" False False
  addr <- getNewAddress AddrP2WPKH (wsWallet ws)
  (wif, e) <- call server "dumpprivkey" [str (addrText addr)]
  e `shouldBe` A.Null
  case wif of
    A.String t -> return (addr, t)
    other -> fail ("dumpprivkey returned " ++ show other)

addrText :: Address -> T.Text
addrText = addressToTextW regtest

p2wpkhScript :: Address -> BS.ByteString
p2wpkhScript (WitnessPubKeyAddress (Hash160 h)) = BS.pack [0x00, 0x14] <> h
p2wpkhScript a = error ("not a P2WPKH address: " ++ show a)

-- | Mine one coinbase-only block paying @spk@ through submitblock.
mineTo :: RpcServer -> BS.ByteString -> IO ()
mineTo server spk = do
  tip <- readTVarIO (hcTip (rsHeaderChain server))
  entries <- readTVarIO (hcEntries (rsHeaderChain server))
  let parentHash = ceHash tip
      height    = ceHeight tip + 1
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
  h <- maybe (fail "could not solve regtest nonce") return mSolved
  (_, e) <- call server "submitblock"
              [str (TE.decodeUtf8 (B16.encode (S.encode (Block h [coinbase]))))]
  e `shouldBe` A.Null

-- | sendtoaddress with an explicit fee_rate (params[9], sat/vB) so the
-- fresh chain's empty fee estimator is not consulted.
sendArgs :: Address -> [A.Value]
sendArgs dest =
  [ str (addrText dest), A.Number 1, str "", str "", A.Bool False
  , A.Bool True, A.Null, str "unset", A.Null, A.Number 5 ]

spec :: Spec
spec = describe "encrypted wallet: key-exporting and signing RPCs require unlock (Core EnsureWalletIsUnlocked)" $ do

  it "dumpprivkey_requires_unlock" $ withWalletServer $ \server wm -> do
    (addr, wif) <- freshWallet server wm
    let a = str (addrText addr)
    encryptAndLock server
    call server "dumpprivkey" [a] >>= shouldNeedUnlock
    unlock server
    (r, e) <- call server "dumpprivkey" [a]
    (r, e) `shouldBe` (str wif, A.Null)
    _ <- call server "walletlock" []
    call server "dumpprivkey" [a] >>= shouldNeedUnlock

  it "dumpprivkey_requires_unlock right after encryptwallet (Core leaves it locked)" $
    withWalletServer $ \server wm -> do
      (addr, _) <- freshWallet server wm
      (_, e) <- call server "encryptwallet" [str "correct horse"]
      e `shouldBe` A.Null
      call server "dumpprivkey" [str (addrText addr)] >>= shouldNeedUnlock

  it "CONTROL: an unencrypted wallet is never refused for the lock" $
    withWalletServer $ \server wm -> do
      (addr, wif) <- freshWallet server wm
      (r, e) <- call server "dumpprivkey" [str (addrText addr)]
      (r, e) `shouldBe` (str wif, A.Null)
      call server "signmessage" [str wif, str "hello"] >>= \(r2, e2) -> do
        e2 `shouldBe` A.Null
        r2 `shouldNotBe` A.Null

  it "signmessage_requires_unlock (signmessagewithprivkey, wallet-free, still works)" $
    withWalletServer $ \server wm -> do
      (_, wif) <- freshWallet server wm
      encryptAndLock server
      call server "signmessage" [str wif, str "hello"] >>= shouldNeedUnlock
      (r, e) <- call server "signmessagewithprivkey" [str wif, str "hello"]
      e `shouldBe` A.Null
      r `shouldNotBe` A.Null
      unlock server
      (r2, e2) <- call server "signmessage" [str wif, str "hello"]
      (r2, e2) `shouldBe` (r, A.Null)

  it "importprivkey_requires_unlock" $ withWalletServer $ \server wm -> do
    (_, wif) <- freshWallet server wm
    encryptAndLock server
    call server "importprivkey" [str wif, str "", A.Bool False] >>= shouldNeedUnlock
    unlock server
    call server "importprivkey" [str wif, str "", A.Bool False] >>= \(_, e) ->
      e `shouldBe` A.Null

  it "importdescriptors_requires_unlock" $ withWalletServer $ \server wm -> do
    (_, wif) <- freshWallet server wm
    encryptAndLock server
    let req = A.object [ ("desc", str ("wpkh(" <> wif <> ")"))
                       , ("timestamp", str "now") ]
    call server "importdescriptors" [A.Array (V.fromList [req])] >>= shouldNeedUnlock
    unlock server
    call server "importdescriptors" [A.Array (V.fromList [req])] >>= shouldNotNeedUnlock

  it "signrawtransactionwithwallet_requires_unlock" $ withWalletServer $ \server wm -> do
    (addr, _) <- freshWallet server wm
    let input = A.object [ ("txid", str (T.replicate 64 "1")), ("vout", A.Number 0) ]
        output = A.Object (KM.fromList [(K.fromText (addrText addr), A.Number 0.1)])
    (hex, e0) <- call server "createrawtransaction"
                   [A.Array (V.fromList [input]), A.Array (V.fromList [output])]
    e0 `shouldBe` A.Null
    encryptAndLock server
    call server "signrawtransactionwithwallet" [hex] >>= shouldNeedUnlock
    unlock server
    call server "signrawtransactionwithwallet" [hex] >>= shouldNotNeedUnlock

  it "walletprocesspsbt_requires_unlock when signing; sign=false fills locked" $
    withWalletServer $ \server wm -> do
      (addr, _) <- freshWallet server wm
      let input = A.object [ ("txid", str (T.replicate 64 "1")), ("vout", A.Number 0) ]
          output = A.Object (KM.fromList [(K.fromText (addrText addr), A.Number 0.1)])
      (psbt, e0) <- call server "createpsbt"
                      [A.Array (V.fromList [input]), A.Array (V.fromList [output])]
      e0 `shouldBe` A.Null
      encryptAndLock server
      call server "walletprocesspsbt" [psbt] >>= shouldNeedUnlock
      call server "walletprocesspsbt" [psbt, A.Bool True] >>= shouldNeedUnlock
      (r, e) <- call server "walletprocesspsbt" [psbt, A.Bool False]
      e `shouldBe` A.Null
      r `shouldNotBe` A.Null
      unlock server
      call server "walletprocesspsbt" [psbt] >>= shouldNotNeedUnlock

  it "sendpayjoinrequest_requires_unlock" $ withWalletServer $ \server wm -> do
    (addr, _) <- freshWallet server wm
    encryptAndLock server
    let uri = "bitcoin:" <> addrText addr <> "?amount=0.1&pj=https://example.invalid/pj"
    call server "sendpayjoinrequest" [str uri] >>= shouldNeedUnlock

  -- Core bumpfee_helper serves bumpfee and psbtbumpfee and calls
  -- EnsureWalletIsUnlocked for both, after ParseHashV(txid) and before the
  -- replacement is built (wallet/rpc/spend.cpp).
  it "bumpfee_requires_unlock (and psbtbumpfee, same Core helper)" $
    withWalletServer $ \server wm -> do
      (a, _) <- freshWallet server wm
      Just ws <- fmap fst (getDefaultWallet wm)
      let w = wsWallet ws
      b <- getNewAddress AddrP2WPKH w
      c <- getChangeAddress w
      -- A wallet-sent, unconfirmed, BIP-125-signalling spend with change:
      -- what sendtoaddress records (as in SubmitBlockWalletSpec).
      let funding = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 7))) 0) BS.empty 0xffffffff]
                       [TxOut 5000000000 (p2wpkhScript a)] [] 0
          prevOp = OutPoint (computeTxId funding) 0
          spend = Tx 2 [TxIn prevOp BS.empty 0xfffffffd]
                      [TxOut 100000000 (p2wpkhScript b), TxOut 4899999000 (p2wpkhScript c)] [] 0
          TxId (Hash256 tb) = computeTxId spend
          txid = str (TE.decodeUtf8 (B16.encode (BS.reverse tb)))
      recordSentTx w spend [(prevOp, head (txOutputs funding))] (Just 1) (Just c) 1000
      encryptAndLock server
      call server "bumpfee" [txid] >>= shouldNeedUnlock
      call server "psbtbumpfee" [txid] >>= shouldNeedUnlock
      -- A malformed txid is rejected by its parse before the lock check.
      (_, ep) <- call server "bumpfee" [str "zz"]
      errCode ep `shouldNotBe` Just (-13)
      ep `shouldNotBe` A.Null
      unlock server
      (rp, ep2) <- call server "psbtbumpfee" [txid]
      ep2 `shouldBe` A.Null
      rp `shouldNotBe` A.Null
      (ru, eu) <- call server "bumpfee" [txid]
      eu `shouldBe` A.Null
      ru `shouldNotBe` A.Null

  -- The BIP-78 receiver signs the input it contributes with wallet keys,
  -- for any HTTP client that POSTs an Original PSBT.  Locked, it must stop
  -- before any processing and answer "unavailable" (its no-wallet answer).
  it "payjoin_receiver_requires_unlock: /payjoin answers unavailable while locked" $
    withWalletServerPj defaultPayjoinConfig { pcEnabled = True } $ \server wm -> do
      _ <- freshWallet server wm
      -- CONTROL: unlocked (unencrypted), the receiver processes the body
      -- and rejects it on its own merits.
      (st0, body0) <- postPayjoin server "not-a-psbt"
      st0 `shouldBe` 400
      body0 `shouldNotBe` "unavailable\r\n"
      encryptAndLock server
      (st1, body1) <- postPayjoin server "not-a-psbt"
      (st1, body1) `shouldBe` (400, "unavailable\r\n")
      unlock server
      (_, body2) <- postPayjoin server "not-a-psbt"
      body2 `shouldBe` body0

  it "sendtoaddress_requires_unlock, send_requires_unlock (funded wallet; nothing reaches the mempool)" $
    withWalletServer $ \server wm -> do
      (addr, _) <- freshWallet server wm
      replicateM_ 101 (mineTo server (p2wpkhScript addr))
      dest <- do
        (d, e) <- call server "getnewaddress" []
        e `shouldBe` A.Null
        return d
      let destAddr = case dest of
            A.String t -> t
            _ -> error "getnewaddress"
          sendTo = str destAddr : drop 1 (sendArgs addr)
      -- CONTROL: unlocked, the funded send goes through.
      (txid0, e0) <- call server "sendtoaddress" sendTo
      e0 `shouldBe` A.Null
      encryptAndLock server
      mpBefore <- getMempoolTxIds (rsMempool server)
      call server "sendtoaddress" sendTo >>= shouldNeedUnlock
      call server "send"
        [ A.Array (V.fromList [A.Object (KM.fromList [(K.fromText destAddr, A.Number 1)])])
        , A.Null, str "unset", A.Number 5 ]
        >>= shouldNeedUnlock
      -- Nothing was signed or broadcast while locked.
      mpAfter <- getMempoolTxIds (rsMempool server)
      length mpAfter `shouldBe` length mpBefore
      -- Unlocked, the same send goes through.
      unlock server
      (txid1, e1) <- call server "sendtoaddress" sendTo
      e1 `shouldBe` A.Null
      txid1 `shouldNotBe` A.Null
      forM_ [txid0, txid1] $ \t -> t `shouldNotBe` A.Null

-- | POST @body@ to /payjoin through 'combinedApp' from a loopback client;
-- return the status code and response body.
postPayjoin :: RpcServer -> BS.ByteString -> IO (Int, BL.ByteString)
postPayjoin server body = do
  bodyRef <- newIORef [body]
  let nextChunk = atomicModifyIORef' bodyRef $ \cs -> case cs of
        []       -> ([], BS.empty)
        (c:rest) -> (rest, c)
      req = setRequestBodyChunks nextChunk defaultRequest
              { requestMethod  = "POST"
              , rawPathInfo    = "/payjoin"
              , rawQueryString = "?v=1"
              , requestHeaders = [("Content-Type", "text/plain")]
              , remoteHost     = SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1))
              }
  out <- newIORef (0, BL.empty)
  _ <- combinedApp server req $ \resp -> do
    let (_, _, withBody) = responseToStream resp
    chunks <- newIORef mempty
    withBody $ \stream -> stream (\b -> atomicModifyIORef' chunks (\acc -> (acc <> b, ()))) (return ())
    b <- readIORef chunks
    writeIORef out (statusCode (responseStatus resp), toLazyByteString b)
    return undefined
  readIORef out

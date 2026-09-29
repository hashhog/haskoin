{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W207 R3 honesty: haskoin answers RPCs only from its own state.
--
-- Three RPC paths used to open raw HTTP connections to a live Bitcoin Core
-- at 127.0.0.1:8332, authenticated with Core's cookie
-- (/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie, or the testnet4 one),
-- and hand Core's answer back as haskoin's own:
--
--   * getblock            -- the whole request, whenever no body was stored
--   * getrawtransaction   -- the whole request, for every verbosity >= 2
--   * getblockheader nTx  -- a Core getblockheader, whenever no body was stored
--
-- All three now answer from haskoin's own state with Core's semantics when
-- the data is absent (rpc/blockchain.cpp CheckBlockDataAvailability,
-- rpc/rawtransaction.cpp getrawtransaction, blockheaderToJSON nTx).
--
-- The source guard reads src/ and app/ as BYTES: GNU grep treats most of
-- this tree as binary (UTF-8 em-dashes under a C locale) and silently skips
-- it, which is how a grep-based survey could miss these call sites.
module W207NoCoreProxySpec (spec) where

import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket)
import Control.Monad (forM)
import Data.Aeson (Value(..), eitherDecode)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import Data.Char (isDigit)
import Data.IORef (newIORef)
import qualified Data.Map.Strict as Map
import Data.Maybe (isJust)
import qualified Data.Scientific as Sci
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import System.Directory (createDirectoryIfMissing, doesDirectoryExist,
                         doesFileExist, getTemporaryDirectory, listDirectory,
                         removeDirectoryRecursive)
import System.FilePath ((</>), takeExtension)
import System.IO.Temp (createTempDirectory)
import Test.Hspec

import Haskoin.Consensus (initHeaderChain, regtest, netGenesisBlock)
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (defaultMempoolConfig, newMempool)
import Haskoin.Network (Message, PeerManagerConfig(..),
                        defaultPeerManagerConfig, startPeerManager,
                        stopPeerManager)
import Haskoin.Payjoin (defaultPayjoinConfig)
import Haskoin.Rpc (RpcConfig(..), RpcResponse(..), RpcServer(..),
                    defaultRpcConfig, handleBatchRequest,
                    blockDataUnavailableMsg, nTxFromStoredBody)
import Haskoin.Storage (BlockUndo(..), PruneConfig(..), TxInUndo(..),
                        TxUndo(..), UndoData(..), defaultDBConfig,
                        defaultPruneConfig, getBlock, newUTXOCache, putBlock,
                        putBlockHeader, putUndoData, withDB)
import Haskoin.TxOrphanage (emptyOrphanPool)
import Haskoin.Types

spec :: Spec
spec = describe "W207 R3: no live-Bitcoin-Core RPC proxy" $ do
  sourceGuardSpec
  pureSpec
  liveSpec

--------------------------------------------------------------------------------
-- Source guard
--------------------------------------------------------------------------------

-- | Lines of haskoin source that break the rule, with file:line.
--   * any mention of Core's cookie path (bitcoin-core/.cookie);
--   * any literal 8332 / 48343 (Core's mainnet / fleet-testnet4 RPC ports)
--     EXCEPT a line that is haskoin's OWN rpcport default/option;
--   * any hand-rolled outbound HTTP Basic-auth request.
sourceViolations :: [(FilePath, BS.ByteString)] -> [String]
sourceViolations files =
  [ f ++ ":" ++ show n ++ ": " ++ C8.unpack (BS.take 120 l)
  | (f, body) <- files
  , (n, l) <- zip [(1 :: Int) ..] (C8.lines body)
  , bad l ]
  where
    bad l =  "bitcoin-core/.cookie" `BS.isInfixOf` l
          || "Authorization: Basic" `BS.isInfixOf` l
          || hasPort "48343" l
          || (hasPort "8332" l && not (ownRpcPortLine l) && not (helpExampleUrlDef l))
    ownRpcPortLine l = any (`BS.isInfixOf` l) ["rpcPort", "RpcPort", "rpcport"]
    -- Core's HelpExampleRpc URL is part of byte-identical help text (e.g. the
    -- addnode unknown-command error).  Only its one DEFINITION line is exempt.
    helpExampleUrlDef l = "coreHelpExampleRpcUrl = \"http://127.0.0.1:8332/\"" == l
    -- The port as a whole number: not 18332 / 28332 / 83321.
    hasPort p l = any standalone (BS.breakSubstring p `iter` l)
      where
        standalone (pre, post) =
          not (BS.null post)
          && not (lastIsDigit pre)
          && not (firstIsDigit (BS.drop (BS.length p) post))
        lastIsDigit b  = not (BS.null b) && isDigit (C8.last b)
        firstIsDigit a = not (BS.null a) && isDigit (C8.head a)
    -- every (prefix, rest-starting-at-match) split of l on p
    iter brk s = go BS.empty s
      where
        go acc t = case brk t of
          (pre, rest) | BS.null rest -> []
                      | otherwise ->
                          (acc <> pre, rest)
                            : go (acc <> pre <> BS.take 1 rest) (BS.drop 1 rest)

haskellFilesUnder :: FilePath -> IO [FilePath]
haskellFilesUnder dir = do
  ok <- doesDirectoryExist dir
  if not ok then return [] else do
    names <- listDirectory dir
    fmap concat $ forM names $ \n -> do
      let p = dir </> n
      isDir <- doesDirectoryExist p
      if isDir then haskellFilesUnder p
        else return [p | takeExtension p == ".hs"]

sourceGuardSpec :: Spec
sourceGuardSpec = describe "source guard" $ do
  it "src/ and app/ contain no Core cookie path, no 8332/48343 client, no outbound Basic-auth request" $ do
    -- cabal runs the suite from the package root; fail (not skip) otherwise,
    -- so a wrong cwd cannot turn this into a vacuous pass.
    here <- doesFileExist ("src" </> "Haskoin" </> "Rpc.hs")
    here `shouldBe` True
    paths <- (++) <$> haskellFilesUnder "src" <*> haskellFilesUnder "app"
    files <- forM paths $ \p -> (,) p <$> BS.readFile p
    -- Denominator: the scan really read the tree, including Rpc.hs.
    length files `shouldSatisfy` (>= 25)
    (("src" </> "Haskoin" </> "Rpc.hs") `elem` paths) `shouldBe` True
    sourceViolations files `shouldBe` []

  it "the guard itself flags each forbidden pattern (instrument check)" $ do
    let flagged s = not (null (sourceViolations [("x.hs", s)]))
    flagged "  let p = [\"/data/nvme1/hashhog-mainnet/bitcoin-core/.cookie\"]" `shouldBe` True
    flagged "  let port = 8332 :: Int"                         `shouldBe` True
    flagged "  connectTo \"127.0.0.1\" 48343"                   `shouldBe` True
    flagged "  \"\\r\\nAuthorization: Basic \" <> cred"         `shouldBe` True
    -- haskoin's own listen-port default and other ports stay legal
    flagged "  , rpcPort     = 8332"                           `shouldBe` False
    flagged "  { noRpcPort    = if noRpcPort n == 8332"         `shouldBe` False
    flagged "  <$> option auto (long \"rpcport\" <> value 8332" `shouldBe` False
    flagged "  zmq tcp://127.0.0.1:28332"                       `shouldBe` False
    flagged "  testnet 18332"                                   `shouldBe` False
    -- Core's help-example URL: only its exact definition line is exempt;
    -- the same URL anywhere else (e.g. inline, or dialed) still flags.
    flagged "coreHelpExampleRpcUrl = \"http://127.0.0.1:8332/\"" `shouldBe` False
    flagged "  httpPost \"http://127.0.0.1:8332/\" body"          `shouldBe` True
    flagged "  coreHelpExampleRpcUrl = \"http://127.0.0.1:8332/\"" `shouldBe` True

--------------------------------------------------------------------------------
-- Pure helpers
--------------------------------------------------------------------------------

pureSpec :: Spec
pureSpec = describe "pure helpers" $ do
  it "blockDataUnavailableMsg: Core CheckBlockDataAvailability strings" $ do
    blockDataUnavailableMsg True  True  `shouldBe` "Block not available (pruned data)"
    blockDataUnavailableMsg True  False `shouldBe` "Block not available (not fully downloaded)"
    blockDataUnavailableMsg False True  `shouldBe` "Block not available (not fully downloaded)"
    blockDataUnavailableMsg False False `shouldBe` "Block not available (not fully downloaded)"
  it "nTxFromStoredBody: 0 without a body, tx count with one" $ do
    nTxFromStoredBody Nothing `shouldBe` 0
    nTxFromStoredBody (Just fixtureBlock) `shouldBe` 2

--------------------------------------------------------------------------------
-- Behaviour through the real dispatcher (regtest, scratch DB, no network)
--------------------------------------------------------------------------------

liveSpec :: Spec
liveSpec = describe "RPC behaviour with block data absent" $ do
  it "getblock: header known, body absent -> -1 not fully downloaded (every verbosity)" $
    withServer defaultPruneConfig $ \server -> do
      putBlockHeader (rsDB server) headerOnlyHash headerOnly
      mapM_ (\v -> call server "getblock" [hashV headerOnlyHash, Number v]
                     >>= (`shouldBe` Left (-1, "Block not available (not fully downloaded)")))
            [0, 1, 2, 3]

  it "getblock: unknown hash -> -5 Block not found" $
    withServer defaultPruneConfig $ \server ->
      call server "getblock" [hashV unknownHash, Number 1]
        >>= (`shouldBe` Left (-5, "Block not found"))

  it "getblock: active-chain block without a body in prune mode -> -1 pruned data" $
    withServer pruning $ \server -> do
      let g = computeBlockHash (blockHeader (netGenesisBlock regtest))
      -- precondition: the scratch DB holds no genesis body
      (isJust <$> getBlock (rsDB server) g) >>= (`shouldBe` False)
      call server "getblock" [hashV g, Number 1]
        >>= (`shouldBe` Left (-1, "Block not available (pruned data)"))

  it "getblockheader: nTx is 0 for a header without a stored body" $
    withServer defaultPruneConfig $ \server -> do
      putBlockHeader (rsDB server) headerOnlyHash headerOnly
      r <- call server "getblockheader" [hashV headerOnlyHash, Bool True]
      field "nTx" r `shouldBe` Just (Number 0)

  it "getblockheader: nTx counts a stored body" $
    withServer defaultPruneConfig $ \server -> do
      storeFixture server False
      r <- call server "getblockheader" [hashV fixtureHash, Bool True]
      field "nTx" r `shouldBe` Just (Number 2)

  it "getrawtransaction blockhash known but body absent -> -1 Block not available" $
    withServer defaultPruneConfig $ \server -> do
      putBlockHeader (rsDB server) headerOnlyHash headerOnly
      mapM_ (\v -> call server "getrawtransaction"
                     [txidV spendTx, Number v, hashV headerOnlyHash]
                     >>= (`shouldBe` Left (-1, "Block not available")))
            [0, 1, 2]

  it "getrawtransaction blockhash unknown -> -5 Block hash not found" $
    withServer defaultPruneConfig $ \server ->
      call server "getrawtransaction" [txidV spendTx, Number 2, hashV unknownHash]
        >>= (`shouldBe` Left (-5, "Block hash not found"))

  it "getrawtransaction verbosity 2 with local undo -> prevout + fee from own undo" $
    withServer defaultPruneConfig $ \server -> do
      storeFixture server True
      r <- call server "getrawtransaction" [txidV spendTx, Number 2, hashV fixtureHash]
      field "fee" r `shouldBe` Just (Number 0.0001)
      let prevout = field "vin" r >>= firstElem >>= fieldOf "prevout"
      (prevout >>= fieldOf "value")     `shouldBe` Just (Number 1)
      (prevout >>= fieldOf "height")    `shouldBe` Just (Number 7)
      (prevout >>= fieldOf "generated") `shouldBe` Just (Bool False)

  it "getrawtransaction verbosity 2 without undo -> answered, fee/prevout omitted" $
    withServer defaultPruneConfig $ \server -> do
      storeFixture server False
      r <- call server "getrawtransaction" [txidV spendTx, Number 2, hashV fixtureHash]
      field "txid" r `shouldBe` Just (String (txidHex spendTx))
      field "fee" r `shouldBe` Nothing
      (field "vin" r >>= firstElem >>= fieldOf "prevout") `shouldBe` Nothing

  it "getrawtransaction verbosity 2 on the coinbase -> no fee (Core skips coinbase)" $
    withServer defaultPruneConfig $ \server -> do
      storeFixture server True
      r <- call server "getrawtransaction" [txidV coinbaseTx, Number 2, hashV fixtureHash]
      field "txid" r `shouldBe` Just (String (txidHex coinbaseTx))
      field "fee" r `shouldBe` Nothing
  where
    pruning = defaultPruneConfig { pcPruneTarget = Just maxBound }

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

unknownHash :: BlockHash
unknownHash = BlockHash (Hash256 (BS.replicate 32 0x5a))

headerOnly :: BlockHeader
headerOnly = BlockHeader 4 (BlockHash (Hash256 (BS.replicate 32 0x11)))
                         (Hash256 (BS.replicate 32 0x22)) 1_700_000_000
                         0x207fffff 7

headerOnlyHash :: BlockHash
headerOnlyHash = computeBlockHash headerOnly

coinbaseTx :: Tx
coinbaseTx = Tx
  { txVersion  = 2
  , txInputs   = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff)
                       (BS.pack [0x01, 0x08]) 0xffffffff]
  , txOutputs  = [TxOut 5_000_000_000 (BS.pack [0x51])]
  , txWitness  = [[]]
  , txLockTime = 0
  }

spendTx :: Tx
spendTx = Tx
  { txVersion  = 2
  , txInputs   = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0xab))) 0)
                       (BS.pack [0x51]) 0xfffffffd]
  , txOutputs  = [TxOut 99_990_000 (BS.pack [0x51])]
  , txWitness  = [[]]
  , txLockTime = 0
  }

fixtureBlock :: Block
fixtureBlock = Block
  (BlockHeader 4 (BlockHash (Hash256 (BS.replicate 32 0x33)))
               (Hash256 (BS.replicate 32 0x44)) 1_700_000_100 0x207fffff 9)
  [coinbaseTx, spendTx]

fixtureHash :: BlockHash
fixtureHash = computeBlockHash (blockHeader fixtureBlock)

-- | Store the fixture body (+ header), and optionally its undo data: the
-- spent input was a 1 BTC non-coinbase output created at height 7.
storeFixture :: RpcServer -> Bool -> IO ()
storeFixture server withUndo = do
  putBlockHeader (rsDB server) fixtureHash (blockHeader fixtureBlock)
  putBlock (rsDB server) fixtureHash fixtureBlock
  if withUndo
    then putUndoData (rsDB server) fixtureHash UndoData
      { udBlockHash = fixtureHash, udHeight = 8
      , udBlockUndo = BlockUndo [TxUndo [TxInUndo (TxOut 100_000_000 (BS.pack [0x51])) 7 False]]
      , udChecksum  = Hash256 (BS.replicate 32 0) }
    else return ()

--------------------------------------------------------------------------------
-- Plumbing
--------------------------------------------------------------------------------

hexHash :: BS.ByteString -> T.Text
hexHash h = TE.decodeUtf8 (B16.encode (BS.reverse h))

hashV :: BlockHash -> Value
hashV (BlockHash (Hash256 h)) = String (hexHash h)

txidHex :: Tx -> T.Text
txidHex tx = let TxId (Hash256 h) = computeTxId tx in hexHash h

txidV :: Tx -> Value
txidV = String . txidHex

field :: T.Text -> Either (Int, T.Text) Value -> Maybe Value
field k (Right v) = fieldOf k v
field _ (Left _)  = Nothing

fieldOf :: T.Text -> Value -> Maybe Value
fieldOf k (Object o) = KM.lookup (K.fromText k) o
fieldOf _ _          = Nothing

firstElem :: Value -> Maybe Value
firstElem (Array a) | not (V.null a) = Just (V.head a)
firstElem _ = Nothing

-- | One call through the real dispatcher: Right result | Left (code, msg).
-- A raw-encoded result (streaming path) is re-parsed so fields can be read.
call :: RpcServer -> T.Text -> [Value] -> IO (Either (Int, T.Text) Value)
call server method params = do
  let req = Object $ KM.fromList
        [ (K.fromText "jsonrpc", String "2.0")
        , (K.fromText "id",      Number 1)
        , (K.fromText "method",  String method)
        , (K.fromText "params",  Array (V.fromList params))
        ]
  resps <- handleBatchRequest server [req]
  case resps of
    (r:_) -> case resError r of
      Object o -> do
        let code = case KM.lookup "code" o of
              Just (Number c) -> maybe 0 id (Sci.toBoundedInteger c)
              _               -> 0
            msg = case KM.lookup "message" o of
              Just (String s) -> s
              _               -> T.empty
        return (Left (code, msg))
      _ -> return (Right (reparse (resResult r)))
    [] -> fail "no response"
  where
    -- A streaming-path result is the "__RAWJSON__:<json>" sentinel string;
    -- parse its payload so fields can be read.
    reparse v@(String t)
      | Just payload <- T.stripPrefix "__RAWJSON__:" t =
          either (const v) id (eitherDecode (BL.fromStrict (TE.encodeUtf8 payload)))
    reparse v = v

withServer :: PruneConfig -> (RpcServer -> IO ()) -> IO ()
withServer pruneCfg action =
  withTmpDir $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      hc    <- initHeaderChain regtest
      cache <- newUTXOCache db 1000
      mp    <- newMempool regtest cache defaultMempoolConfig 200 0 (\_ -> return 0)
      fe    <- newFeeEstimator
      let pmCfg = defaultPeerManagerConfig { pmcDataDir = dir, pmcDnsSeed = False }
      bracket (startPeerManager regtest pmCfg noopHandler) stopPeerManager $ \pm -> do
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
              , rsPruneConfig = pruneCfg, rsAsmapData = BS.empty
              , rsPayjoinOffers = payjoinOffers, rsPayjoinConfig = defaultPayjoinConfig
              , rsOrphanPool = orphanRef, rsAssumeUtxo = assumeUtxoVar
              }
        action server
  where
    noopHandler :: a -> Message -> IO ()
    noopHandler _ _ = return ()

withTmpDir :: (FilePath -> IO ()) -> IO ()
withTmpDir act = do
  base <- getTemporaryDirectory
  createDirectoryIfMissing True base
  bracket (createTempDirectory base "haskoin-w207-") removeDirectoryRecursive act

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W172 getchainstates — JSON-shape parity for haskoin.
--
-- Reference: bitcoin-core/src/rpc/blockchain.cpp getchainstates
-- (RPCHelpForChainstate :3449-3460 + make_chain_data :3485-3507).
--
-- Core returns an object:
--
-- @
--   { "headers": <int>,                 -- m_best_header->nHeight, or -1 if none
--     "chainstates": [                  -- ordered by work, ACTIVE (most-work) LAST
--       { "blocks": <int>,
--         "bestblockhash": <hex>,
--         "bits": <hex>,
--         "target": <hex>,
--         "difficulty": <num>,
--         "verificationprogress": <num>,
--         "coins_db_cache_bytes": <int>,
--         "coins_tip_cache_bytes": <int>,
--         "snapshot_blockhash": <hex>,  -- OPTIONAL, from-snapshot only
--         "validated": <bool> } ] }
-- @
--
-- haskoin runs a SINGLE fully-validated chainstate, so @chainstates@ is
-- a 1-element array with @validated == true@, @snapshot_blockhash@
-- OMITTED, and the active chainstate trivially last.  These tests drive
-- the pure core 'chainStatesResultEnc' / 'chainStateEntryEnc' (the exact
-- code 'handleGetChainStates' runs) over a real 'ChainEntry' (the
-- regtest genesis entry, built exactly like 'initHeaderChain'), then
-- parse the emitted JSON and assert the field set / types.
module W172GetChainStatesSpec (spec) where

import Test.Hspec

import Control.Concurrent.STM (newTVarIO)
import Control.Exception (bracket)
import Data.Aeson (Value(..), decode)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as K
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.IORef (newIORef)
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Scientific as Sci
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32)
import System.Directory (removeDirectoryRecursive, getTemporaryDirectory)
import System.FilePath ((</>))
import System.IO.Temp (createTempDirectory)

import Haskoin.Types (Block(..), BlockHeader(..))
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
  ( regtest, netGenesisBlock, headerWork, seqIdBestChainFromDisk
  , ChainEntry(..), BlockStatus(..)
  , initHeaderChain
  )
import Haskoin.Storage
  ( defaultDBConfig, withDB, newUTXOCache, defaultPruneConfig
  , putSnapshotBaseHash
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
  ( chainStatesResultEnc, chainStateEntryEnc
  , chainStatesResultEncWithSnapshot, chainstateSnapshotReport
  , handleGetChainStates, RpcServer(..), RpcConfig(..), defaultRpcConfig
  , RpcResponse(..)
  )

-- | Build the regtest genesis 'ChainEntry' exactly the way
-- 'Haskoin.Consensus.initHeaderChain' does, so the test exercises the
-- handler over a genuine validated-tip value.
genesisEntry :: ChainEntry
genesisEntry =
  let net     = regtest
      genesis = blockHeader (netGenesisBlock net)
      gHash   = computeBlockHash genesis
  in ChainEntry
       { ceHeader     = genesis
       , ceHash       = gHash
       , ceHeight     = 0
       , ceChainWork  = headerWork genesis
       , cePrev       = Nothing
       , ceStatus     = StatusValid
       , ceMedianTime = bhTimestamp genesis
       , ceSequenceId = seqIdBestChainFromDisk
       }

-- | Decode the getchainstates result encoding into an aeson 'Object'.
decodeResult :: Word32 -> Int -> Value
decodeResult headerHeight dbCacheMb =
  let enc = chainStatesResultEnc regtest genesisEntry headerHeight dbCacheMb
      bs  = encodingToLazyByteString enc
  in case decode bs of
       Just v  -> v
       Nothing -> error ("getchainstates JSON failed to parse: " ++ show bs)

-- | Object-field lookup helper.
field :: T.Text -> Value -> Maybe Value
field k (Object o) = KM.lookup (K.fromText k) o
field _ _          = Nothing

isNumber :: Maybe Value -> Bool
isNumber (Just (Number _)) = True
isNumber _                 = False

isString :: Maybe Value -> Bool
isString (Just (String _)) = True
isString _                 = False

-- | True iff the JSON number has no fractional part (an integer-valued
-- number — Core emits @blocks@ / @headers@ / the cache bytes as ints).
isIntegral :: Maybe Value -> Bool
isIntegral (Just (Number n)) = Sci.isInteger n
isIntegral _                 = False

spec :: Spec
spec = describe "W172 getchainstates — Core make_chain_data shape parity" $ do

  let dbCacheMb = 450 :: Int   -- Core DEFAULT_DB_CACHE
      result    = decodeResult 0 dbCacheMb

  describe "top-level object" $ do

    it "is a JSON object with exactly {headers, chainstates}" $ do
      case result of
        Object o -> KM.keys o `shouldMatchList` [K.fromText "headers", K.fromText "chainstates"]
        _        -> expectationFailure "getchainstates did not return a JSON object"

    it "headers is an integer-valued number" $ do
      isIntegral (field "headers" result) `shouldBe` True

    it "chainstates is a 1-element array (single validated chainstate)" $ do
      case field "chainstates" result of
        Just (Array arr) -> length arr `shouldBe` 1
        other            -> expectationFailure ("chainstates not a 1-element array: " ++ show other)

  describe "the single chainstate entry" $ do

    -- Pull element 0 of the chainstates array (the sole, active,
    -- validated chainstate).
    let firstEntry = case field "chainstates" result of
                       Just (Array arr) ->
                         case foldr (:) [] arr of
                           (x:_) -> x
                           []    -> error "empty chainstates array"
                       _ -> error "chainstates is not an array"

    it "has all REQUIRED fields, none missing" $ do
      let e = firstEntry
      isIntegral (field "blocks" e)               `shouldBe` True
      isString  (field "bestblockhash" e)         `shouldBe` True
      isString  (field "bits" e)                  `shouldBe` True
      isString  (field "target" e)                `shouldBe` True
      isNumber  (field "difficulty" e)            `shouldBe` True
      isNumber  (field "verificationprogress" e)  `shouldBe` True
      isIntegral (field "coins_db_cache_bytes" e) `shouldBe` True
      isIntegral (field "coins_tip_cache_bytes" e) `shouldBe` True

    it "validated == true" $ do
      field "validated" firstEntry `shouldBe` Just (Bool True)

    it "OMITS snapshot_blockhash (no active snapshot)" $ do
      field "snapshot_blockhash" firstEntry `shouldBe` Nothing

    it "blocks == genesis height (0) and bestblockhash is a hex string" $ do
      field "blocks" firstEntry `shouldSatisfy` \mv -> case mv of
        Just (Number n) -> Sci.toBoundedInteger n == Just (0 :: Int)
        _               -> False
      isString (field "bestblockhash" firstEntry) `shouldBe` True

    it "bits is the 8-hex-char compact target; target is 64-hex-char uint256" $ do
      case field "bits" firstEntry of
        Just (String s) -> T.length s `shouldBe` 8
        _               -> expectationFailure "bits not a hex string"
      case field "target" firstEntry of
        Just (String s) -> T.length s `shouldBe` 64
        _               -> expectationFailure "target not a 64-char hex string"

    it "coins_db_cache_bytes == dbcache budget in bytes (450 MiB)" $ do
      field "coins_db_cache_bytes" firstEntry `shouldSatisfy` \mv -> case mv of
        Just (Number n) -> Sci.toBoundedInteger n == Just (450 * 1024 * 1024 :: Int)
        _               -> False

    it "coins_tip_cache_bytes == configured budget (same as coins_db here)" $ do
      field "coins_tip_cache_bytes" firstEntry `shouldSatisfy` \mv -> case mv of
        Just (Number n) -> Sci.toBoundedInteger n == Just (450 * 1024 * 1024 :: Int)
        _               -> False

  describe "headers field tracks the header-tip height argument" $ do

    it "reports the supplied header-tip height (e.g. 12345)" $ do
      let r = decodeResult 12345 dbCacheMb
      field "headers" r `shouldSatisfy` \mv -> case mv of
        Just (Number n) -> Sci.toBoundedInteger n == Just (12345 :: Int)
        _               -> False

  describe "snapshot_blockhash is OPTIONAL (Core pushKV only when from-snapshot)" $ do

    it "the entry helper EMITS snapshot_blockhash when a snapshot base is given" $ do
      let snapHash = ceHash genesisEntry
          enc      = chainStateEntryEnc regtest genesisEntry dbCacheMb False (Just snapHash) 0
          bs       = encodingToLazyByteString enc
          v        = maybe (error "snapshot entry parse fail") id (decode bs)
      isString (field "snapshot_blockhash" v) `shouldBe` True
      -- and the snapshot chainstate reports validated=false (the arg)
      field "validated" v `shouldBe` Just (Bool False)

    it "the entry helper OMITS snapshot_blockhash when no snapshot base" $ do
      let enc = chainStateEntryEnc regtest genesisEntry dbCacheMb True Nothing 0
          bs  = encodingToLazyByteString enc
          v   = maybe (error "no-snapshot entry parse fail") id (decode bs)
      field "snapshot_blockhash" v `shouldBe` Nothing
      field "validated" v          `shouldBe` Just (Bool True)

  -- QUEUES.md haskoin item 2.  Core: validated = (cs.m_assumeutxo ==
  -- VALIDATED).  --load-snapshot promotes in place without
  -- MaybeCompleteSnapshotValidation, so a persisted snapshot-base marker
  -- must surface as snapshot_blockhash + validated=false until the live
  -- loadtxoutset path records a matching re-derivation.
  describe "getchainstates validated" $ do

    it "handleGetChainStates consults getSnapshotBaseHash for --load-snapshot" $ do
      src <- readFile "src/Haskoin/Rpc.hs"
      let ls = dropWhile (not . isPrefixOf "handleGetChainStates ::") (lines src)
          body = unlines $ take 50 ls
      ("getSnapshotBaseHash" `isInfixOf` body) `shouldBe` True
      ("chainstateSnapshotReport" `isInfixOf` body) `shouldBe` True

    it "is true for a from-genesis chainstate (no snapshot marker)" $
      withLiveServer $ \server -> do
        cs <- getChainStatesEntry server
        field "validated" cs `shouldBe` Just (Bool True)
        field "snapshot_blockhash" cs `shouldBe` Nothing
        isIntegral (field "script_checks" cs) `shouldBe` True

    it "is false for a --load-snapshot chainstate until independent re-derivation" $
      withLiveServer $ \server -> do
        putSnapshotBaseHash (rsDB server) (ceHash genesisEntry)
        cs <- getChainStatesEntry server
        field "validated" cs `shouldBe` Just (Bool False)
        case field "snapshot_blockhash" cs of
          Just (String s) | T.length s == 64 -> return ()
          other -> expectationFailure
            ("expected snapshot_blockhash 64-char hex, got " ++ show other)

    it "is true after snapshot re-derivation (live AssumeUtxo wins over the marker)" $ do
      let h = ceHash genesisEntry
      chainstateSnapshotReport (Just (h, True)) (Just h)
        `shouldBe` Just (h, True)
      chainstateSnapshotReport Nothing (Just h)
        `shouldBe` Just (h, False)
      chainstateSnapshotReport Nothing Nothing
        `shouldBe` Nothing

    it "emits script_checks from the supplied counter" $ do
      let enc = chainStatesResultEncWithSnapshot
                  regtest genesisEntry 0 dbCacheMb Nothing 42
          bs  = encodingToLazyByteString enc
          v   = maybe (error "script_checks parse fail") id (decode bs)
          e   = case field "chainstates" v of
                  Just (Array arr) -> case foldr (:) [] arr of
                    (x:_) -> x
                    []    -> error "empty chainstates"
                  _ -> error "chainstates not an array"
      field "script_checks" e `shouldSatisfy` \mv -> case mv of
        Just (Number n) -> Sci.toBoundedInteger n == Just (42 :: Int)
        _               -> False

-- | Minimal live RpcServer over a temp RocksDB (mirrors W186).
liveNoopHandler :: a -> Message -> IO ()
liveNoopHandler _ _ = return ()

withLiveServer :: (RpcServer -> IO ()) -> IO ()
withLiveServer action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-w172-")
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

-- | Drive handleGetChainStates and return the single chainstate entry.
getChainStatesEntry :: RpcServer -> IO Value
getChainStatesEntry server = do
  resp <- handleGetChainStates server
  v <- decodeRawResult (resResult resp)
  case field "chainstates" v of
    Just (Array arr) -> case foldr (:) [] arr of
      (e:_) -> return e
      []    -> fail "getchainstates returned an empty chainstates array"
    other -> fail ("getchainstates chainstates not an array: " ++ show other)

decodeRawResult :: Value -> IO Value
decodeRawResult (String s) =
  let magic = "__RAWJSON__:"
      payload = if magic `T.isPrefixOf` s then T.drop (T.length magic) s else s
  in case Aeson.decode (BL.fromStrict (TE.encodeUtf8 payload)) of
       Just v  -> return v
       Nothing -> fail ("could not decode getchainstates raw JSON: " ++ T.unpack payload)
decodeRawResult v =
  case v of
    Object _ -> return v
    _        -> fail ("unexpected getchainstates result shape: " ++ show v)

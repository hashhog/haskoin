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

import Data.Aeson (Value(..), decode)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as K
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.Scientific as Sci
import qualified Data.Text as T
import Data.Word (Word32)

import Haskoin.Types (Block(..), BlockHeader(..))
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
  ( regtest, netGenesisBlock, headerWork, seqIdBestChainFromDisk
  , ChainEntry(..), BlockStatus(..)
  )
import Haskoin.Rpc (chainStatesResultEnc, chainStateEntryEnc)

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
          enc      = chainStateEntryEnc regtest genesisEntry dbCacheMb False (Just snapHash)
          bs       = encodingToLazyByteString enc
          v        = maybe (error "snapshot entry parse fail") id (decode bs)
      isString (field "snapshot_blockhash" v) `shouldBe` True
      -- and the snapshot chainstate reports validated=false (the arg)
      field "validated" v `shouldBe` Just (Bool False)

    it "the entry helper OMITS snapshot_blockhash when no snapshot base" $ do
      let enc = chainStateEntryEnc regtest genesisEntry dbCacheMb True Nothing
          bs  = encodingToLazyByteString enc
          v   = maybe (error "no-snapshot entry parse fail") id (decode bs)
      field "snapshot_blockhash" v `shouldBe` Nothing
      field "validated" v          `shouldBe` Just (Bool True)

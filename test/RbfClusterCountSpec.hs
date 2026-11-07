{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | BIP-125 Rule 5 under cluster mempool: Core v31.1 counts the DISTINCT
-- CLUSTERS the replacement conflicts with directly, not the evicted
-- transactions (bitcoin-core/src/policy/rbf.cpp GetEntriesForConflicts:
-- GetUniqueClusterCount(iters_conflicting) > MAX_REPLACEMENT_CANDIDATES).
module RbfClusterCountSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (atomically, modifyTVar')
import Data.Word (Word32, Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Mempool
import Haskoin.Consensus (testnet4)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB)

withFreshMempool :: (Mempool -> IO a) -> IO a
withFreshMempool action =
  withSystemTempDirectory "haskoin-rbfcluster-test" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      mp    <- newMempool testnet4 cache defaultMempoolConfig 100 0 noopCoinMtp
      action mp

mkTx :: [OutPoint] -> Int -> Tx
mkTx ops nOut = Tx
  { txVersion = 2
  , txInputs = [TxIn o "" 0xfffffffd | o <- ops]
  , txOutputs = replicate nOut (TxOut 1_000 "\x51")
  , txWitness = replicate (length ops) []
  , txLockTime = 0 }

coin :: Word32 -> OutPoint
coin n = OutPoint (TxId (Hash256 (BS.replicate 31 0x00 <> BS.singleton (fromIntegral n)))) 0

mkE :: Tx -> Word64 -> Int -> Word64 -> Bool -> MempoolEntry
mkE tx fee sz feeRateKvb rbf = MempoolEntry
  { meTransaction     = tx
  , meTxId            = computeTxId tx
  , meWtxid           = computeWtxid tx
  , meFee             = fee
  , meFeeRate         = FeeRate feeRateKvb
  , meSize            = sz
  , meAdjWeight       = sz * 4
  , meTime            = 0
  , meHeight          = 0
  , meAncestorCount   = 1
  , meAncestorSize    = sz
  , meAncestorFees    = fee
  , meAncestorSigOps  = 0
  , meDescendantCount = 1
  , meDescendantSize  = sz
  , meDescendantFees  = fee
  , meRBFOptIn        = rbf
  }


addE :: Mempool -> Tx -> IO TxId
addE mp tx = do
  let txid = computeTxId tx
  atomically $ do
    modifyTVar' (mpEntries mp) (Map.insert txid (mkE tx 1000 100 10_000 True))
    mapM_ (\i -> modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput i) txid)) (txInputs tx)
  return txid

-- | n clusters, each a root with 20 children (21 txs).  Returns the roots.
seedClusters :: Mempool -> Word32 -> IO [TxId]
seedClusters mp n = mapM one [1..n]
  where
    one i = do
      let root = mkTx [coin i] 20
          rid = computeTxId root
      _ <- addE mp root
      mapM_ (\v -> addE mp (mkTx [OutPoint rid v] 1)) [0..19]
      return rid

spec :: Spec
spec = describe "BIP-125 Rule 5 counts conflicting clusters (Core v31 GetEntriesForConflicts)" $ do
  it "5 clusters / 105 evictions: accepted (Core counts 5 clusters)" $
    withFreshMempool $ \mp -> do
      roots <- seedClusters mp 5
      let repl = mkTx (map coin [1..5]) 1
      r <- evaluateReplacementRules mp repl roots 200_000 200 (FeeRate 1_000_000)
      r `shouldBe` Right ()

  it "101 conflicting clusters: rejected with too-many-replacements" $
    withFreshMempool $ \mp -> do
      roots <- mapM (\i -> addE mp (mkTx [coin i] 1)) [1..101]
      let repl = mkTx (map coin [1..101]) 1
      r <- evaluateReplacementRules mp repl roots 5_000_000 200 (FeeRate 100_000_000)
      r `shouldBe` Left (ErrRBFTooManyReplacements 101 100)

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | getblocktemplate parity with Core v31.1 (rpc/mining.cpp, node/miner.cpp):
--
--   * template transactions are in topological order (a parent before its
--     children) even when the child's ancestor fee rate is higher;
--   * a child whose in-mempool parent was not selected is not selected;
--   * "depends" holds 1-based positions in the transactions array;
--   * "default_witness_commitment" is the 0x6a24aa21a9ed output script.
module GbtOrderSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Control.Monad (forM_)
import Data.Word (Word32, Word64)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Mempool
import Haskoin.BlockTemplate (BlockTemplate(..), TemplateTransaction(..), buildTemplateTx)
import Haskoin.Rpc (buildWitnessCommitmentScript)
import Haskoin.Consensus (regtest)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB)

withFreshMempool :: (Mempool -> IO a) -> IO a
withFreshMempool action =
  withSystemTempDirectory "haskoin-gbtorder-test" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      mp <- newMempool regtest cache defaultMempoolConfig 100 0 noopCoinMtp
      action mp

makeTx :: [OutPoint] -> [Word64] -> Tx
makeTx prevouts outValues = Tx
  { txVersion  = 2
  , txInputs   = map (\op -> TxIn { txInPrevOutput = op
                                  , txInScript    = ""
                                  , txInSequence  = 0xffffffff }) prevouts
  , txOutputs  = map (\v -> TxOut v "\x51") outValues
  , txWitness  = replicate (length prevouts) []
  , txLockTime = 0
  }

coinOutPoint :: Word32 -> OutPoint
coinOutPoint n = OutPoint
  (TxId (Hash256 (BS.replicate 31 0x00 <> BS.singleton (fromIntegral n)))) 0

-- | Single-tx entry with explicit ancestor totals.
mkEntry :: Tx -> Word64 -> Int -> (Int, Int, Word64) -> MempoolEntry
mkEntry tx fee sz (ancN, ancSz, ancFee) = MempoolEntry
  { meTransaction     = tx
  , meTxId            = computeTxId tx
  , meWtxid           = computeWtxid tx
  , meFee             = fee
  , meFeeRate         = calculateFeeRate fee sz
  , meSize            = sz
  , meAdjWeight       = sz * 4
  , meTime            = 0
  , meHeight          = 0
  , meAncestorCount   = ancN
  , meAncestorSize    = ancSz
  , meAncestorFees    = ancFee
  , meAncestorSigOps  = 0
  , meDescendantCount = 1
  , meDescendantSize  = sz
  , meDescendantFees  = fee
  , meRBFOptIn        = False
  }

insertEntry :: Mempool -> MempoolEntry -> IO ()
insertEntry mp e = atomically $ do
  modifyTVar' (mpEntries mp)    (Map.insert (meTxId e) e)
  modifyTVar' (mpByWtxid mp)    (Map.insert (meWtxid e) (meTxId e))
  forM_ (txInputs (meTransaction e)) $ \inp ->
    modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput inp) (meTxId e))
  modifyTVar' (mpByFeeRate mp)  (Map.insert (meFeeRate e, meTxId e) ())
  modifyTVar' (mpSize mp)       (+ meSize e)

-- parent (fee 9, 200 vB), child spending it (fee 50_000, 100 vB), and an
-- unrelated tx (fee 2_000, 200 vB) — the shape of the regtest gbt scenario.
parentTx, childTx, otherTx :: Tx
parentTx = makeTx [coinOutPoint 1] [9_000]
childTx  = makeTx [OutPoint (computeTxId parentTx) 0] [8_000]
otherTx  = makeTx [coinOutPoint 2] [9_000]

parentE, childE, otherE :: MempoolEntry
parentE = mkEntry parentTx 9 200 (1, 200, 9)
childE  = mkEntry childTx 50_000 100 (2, 300, 50_009)
otherE  = mkEntry otherTx 2_000 200 (1, 200, 2_000)

spec :: Spec
spec = do
  describe "getblocktemplate transaction order (Core node/miner.cpp)" $ do
    it "selectTransactions puts a parent before its higher-feerate child" $
      withFreshMempool $ \mp -> do
        mapM_ (insertEntry mp) [parentE, childE, otherE]
        sel <- selectTransactions mp 3_992_000
        map meTxId sel `shouldBe` [meTxId parentE, meTxId childE, meTxId otherE]

    it "does not select a child whose in-mempool parent did not fit" $
      withFreshMempool $ \mp -> do
        mapM_ (insertEntry mp) [parentE, childE]
        -- parent = 800 WU, child = 400 WU: only the child fits in 500 WU.
        sel <- selectTransactions mp 500
        map meTxId sel `shouldBe` []

  describe "getblocktemplate depends (Core rpc/mining.cpp: 1-based)" $ do
    it "child depends on the parent's 1-based position" $ do
      let es   = [parentE, childE, otherE]
          ids  = Set.fromList (map meTxId es)
          tts  = zipWith (buildTemplateTx ids es) [0 ..] es
      map ttDepends tts `shouldBe` [[], [1], []]

  describe "getblocktemplate default_witness_commitment" $ do
    it "is OP_RETURN <36 bytes: aa21a9ed || commitment>" $ do
      let c  = BS.pack [1 .. 32]
          bt = BlockTemplate
                 { btVersion = 0, btPreviousBlock = BlockHash (Hash256 (BS.replicate 32 0))
                 , btTransactions = [], btCoinbaseValue = 0, btBits = 0
                 , btHeight = 1, btCurTime = 0, btMinTime = 0, btMaxTime = 0
                 , btSigopLimit = 0, btWeightLimit = 0
                 , btCoinbaseTxn = makeTx [] [], btWitnessCommitment = c
                 , btDefaultWitnessNonce = BS.replicate 32 0 }
      buildWitnessCommitmentScript bt
        `shouldBe` BS.pack [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed] <> c

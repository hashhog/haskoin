{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | RBF replacement inputs resolve through a mempool-backed coins view.
--
-- Bitcoin Core's MemPoolAccept::PreChecks reads every input through
-- CCoinsViewMemPool (txmempool.cpp:742-763): an output of a transaction
-- still in the mempool is a coin (height MEMPOOL_HEIGHT), whether or not
-- another mempool transaction spends it — for a replacement that spender is
-- exactly the conflict being evicted.
--
-- Pre-fix haskoin resolved an input spent by a conflict from the chain UTXO
-- set ONLY ('resolveInputsForReplacement'), so a fee-bump of a child of an
-- unconfirmed parent came back ErrMissingInput and was lost (orphaned on the
-- relay path, never promotable because the "missing" parent is in the pool).
module RbfMempoolParentSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.Mempool
import Haskoin.Consensus (regtest)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB, addUTXO, UTXOEntry(..))

-- | P2WSH(OP_TRUE): standard output, spendable with witness [OP_TRUE].
opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

spendTx :: [OutPoint] -> [Word64] -> Tx
spendTx ops vals = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn op BS.empty 0xfffffffd | op <- ops ]
  , txOutputs  = [ TxOut v opTrueSpk | v <- vals ]
  , txWitness  = [ [BS.singleton 0x51] | _ <- ops ]
  , txLockTime = 0
  }

fundingOp :: Int -> OutPoint
fundingOp n = OutPoint (TxId (Hash256 (BS.replicate 31 0x5a <> BS.singleton (fromIntegral n)))) 0

withPool :: (Mempool -> IO a) -> IO a
withPool action =
  withSystemTempDirectory "haskoin-rbf-parent" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      -- two confirmed, mature, non-coinbase coins at height 1; tip 200
      atomically $ mapM_ (\n -> addUTXO cache (fundingOp n)
                                   (UTXOEntry (TxOut 1_000_000 opTrueSpk) 1 False False)) [0, 1]
      mp <- newMempool regtest cache defaultMempoolConfig 200 0 noopCoinMtp
      action mp

accepted :: Mempool -> Tx -> IO ()
accepted mp tx = do
  r <- addTransaction mp tx
  r `shouldBe` Right (computeTxId tx)

inPool :: Mempool -> Tx -> IO Bool
inPool mp tx = Map.member (computeTxId tx) <$> readTVarIO (mpEntries mp)

spec :: Spec
spec = describe "RBF: replacement inputs resolve through the mempool view (Core CCoinsViewMemPool)" $ do
  let parent  = spendTx [fundingOp 0] [990_000]                 -- fee 10,000
      pOut    = OutPoint (computeTxId parent) 0
      child   = spendTx [pOut] [989_000]                        -- fee 1,000
      bump    = spendTx [pOut] [985_000]                        -- fee 5,000

  it "a fee-bump of a child of an unconfirmed parent replaces the child" $ withPool $ \mp -> do
    accepted mp parent
    accepted mp child
    r <- addTransaction mp bump
    r `shouldBe` Right (computeTxId bump)
    inPool mp child  `shouldReturn` False
    inPool mp bump   `shouldReturn` True
    inPool mp parent `shouldReturn` True

  it "testmempoolaccept (dry run) accepts the same fee-bump and mutates nothing" $ withPool $ \mp -> do
    accepted mp parent
    accepted mp child
    r <- testAcceptTransaction mp bump
    fmap meFee r `shouldBe` Right 5_000
    inPool mp child `shouldReturn` True
    inPool mp bump  `shouldReturn` False

  it "the replacement's fee is computed from the parent's REAL output value" $ withPool $ \mp -> do
    -- overspends the mempool parent's 990,000-sat output → not a missing
    -- input, a fee failure (the view returns the real coin, not a stub)
    accepted mp parent
    accepted mp child
    r <- addTransaction mp (spendTx [pOut] [990_001])
    r `shouldBe` Left ErrInsufficientFee
    inPool mp child `shouldReturn` True

  it "control: a replacement of a tx spending a CONFIRMED coin still works" $ withPool $ \mp -> do
    let x  = spendTx [fundingOp 1] [999_000]
        x' = spendTx [fundingOp 1] [995_000]
    accepted mp x
    r <- addTransaction mp x'
    r `shouldBe` Right (computeTxId x')
    inPool mp x `shouldReturn` False

  it "control: a replacement spending an outpoint nobody has is still missing-inputs" $ withPool $ \mp -> do
    accepted mp parent
    accepted mp child
    let ghost = OutPoint (TxId (Hash256 (BS.replicate 32 0x9e))) 0  -- no such tx anywhere
    r <- addTransaction mp (spendTx [pOut, ghost] [985_000])
    r `shouldBe` Left (ErrMissingInput ghost)

{-# LANGUAGE OverloadedStrings #-}

-- | getblocktemplate @sigops@ parity with Core v31.1 (rpc/mining.cpp:927-932):
-- the value is the full GetTransactionSigOpCost, so a P2WPKH spend reports 1
-- (witness sigop), not the legacy-only 0.
module GbtSigopsSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Mempool
import Haskoin.BlockTemplate (TemplateTransaction(..), applyTemplateSigops,
                              templateReportedSigops, buildTemplateTx)
import Haskoin.Consensus (regtest, consensusFlagsAtHeight, ConsensusFlags(..))
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB)
import qualified Data.Set as Set

-- OP_0 <20 zero bytes>
p2wpkh :: BS.ByteString
p2wpkh = BS.pack (0x00 : 0x14 : replicate 20 0)

parentTx, childTx :: Tx
parentTx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 7))) 0) "" 0xffffffff]
              [TxOut 10000 p2wpkh] [[]] 0
childTx  = Tx 2 [TxIn (OutPoint (computeTxId parentTx) 0) "" 0xffffffff]
              [TxOut 9000 p2wpkh]
              [[BS.replicate 71 1, BS.replicate 33 2]] 0

entry :: Tx -> MempoolEntry
entry tx = MempoolEntry
  { meTransaction = tx, meTxId = computeTxId tx, meWtxid = computeWtxid tx
  , meFee = 1000, meFeeRate = calculateFeeRate 1000 110, meSize = 110
  , meAdjWeight = 440, meTime = 0, meHeight = 0
  , meAncestorCount = 1, meAncestorSize = 110, meAncestorFees = 1000
  , meAncestorSigOps = 0, meDescendantCount = 1, meDescendantSize = 110
  , meDescendantFees = 1000, meRBFOptIn = False }

spec :: Spec
spec = describe "getblocktemplate sigops (Core rpc/mining.cpp)" $ do
  it "a P2WPKH spend reports 1 sigop (witness cost), not legacy-only 0" $
    withSystemTempDirectory "haskoin-gbtsigops" $ \dir ->
      withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
        cache <- newUTXOCache db 1000
        mp <- newMempool regtest cache defaultMempoolConfig 100 0 noopCoinMtp
        let pe = entry parentTx; ce = entry childTx
        atomically $ mapM_ (\e -> modifyTVar' (mpEntries mp) (Map.insert (meTxId e) e)) [pe, ce]
        let es  = [pe, ce]
            ids = Set.fromList (map meTxId es)
            tts = zipWith (buildTemplateTx ids es) [0 ..] es
        out <- applyTemplateSigops regtest mp cache 200 tts
        -- child spends the in-mempool P2WPKH parent output -> 1
        map ttSigops out `shouldBe` [0, 1]

  it "a legacy OP_CHECKSIG output costs 4 post-segwit and 1 pre-segwit" $ do
    let tx    = parentTx { txOutputs = [TxOut 1 (BS.pack [0xac])] }
        post  = (consensusFlagsAtHeight regtest 200)
        pre   = post { flagSegWit = False }
    templateReportedSigops post Map.empty tx `shouldBe` 4
    templateReportedSigops pre  Map.empty tx `shouldBe` 1

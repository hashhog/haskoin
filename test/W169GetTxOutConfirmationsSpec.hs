{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W169 gettxout confirmation depth + chainstate-served fields.
--
-- Reference: bitcoin-core/src/rpc/blockchain.cpp gettxout
--   * bestblock      = active tip hash (coins_view->GetBestBlock()), :1244-1245
--   * confirmations  = pindex->nHeight - coin->nHeight + 1,          :1249
--   * value/scriptPubKey/coinbase                                    :1251-1255
--   * absent UTXO    -> JSON null (UniValue::VNULL)                  :1242
--
-- Before this fix the native gettxout arm hard-coded bestblock="" and
-- confirmations=0 and proxied unknown UTXOs to a local Bitcoin Core.  The
-- handler now serves entirely from haskoin's own chainstate.  These tests
-- pin the pure confirmation-depth helper that drives the "confirmations"
-- field, which is the part the gettxout harness was flagging.
module W169GetTxOutConfirmationsSpec (spec) where

import Test.Hspec
import Test.QuickCheck

import Haskoin.Rpc (gettxoutConfirmations)

import Data.Word (Word32)

spec :: Spec
spec = describe "W169 gettxout confirmation depth (Core parity)" $ do

  it "a UTXO mined in the current tip block has 1 confirmation" $
    -- Core: tip 952740, coin at 952740 -> 952740 - 952740 + 1 = 1.
    gettxoutConfirmations 952740 952740 `shouldBe` 1

  it "confirmations = tip_height - coin_height + 1 (mainnet-scale)" $
    -- Core: tip 952740, coin at 952600 -> 141 confirmations.
    gettxoutConfirmations 952740 952600 `shouldBe` 141

  it "genesis-coinbase coin at a high tip reports tip+1 confirmations" $
    -- coin_height 0, tip 952740 -> 952741 confirmations.
    gettxoutConfirmations 952740 0 `shouldBe` 952741

  it "matches Core for the depth-byte boundary (100-conf coinbase maturity)" $
    -- coin at H, tip at H+99 -> exactly 100 confirmations (mature).
    gettxoutConfirmations (500000 + 99) 500000 `shouldBe` 100

  it "never wraps to ~4 billion on a stale-tip read (coin ahead of tip)" $
    -- Word32 subtraction would wrap; the Int helper must stay small/negative
    -- rather than report ~4.29e9 confirmations.
    gettxoutConfirmations 100 105 `shouldBe` (-4)

  it "equals the Int-arithmetic reference for arbitrary heights" $
    property $ \(t :: Word32) (c :: Word32) ->
      gettxoutConfirmations t c
        === (fromIntegral t - fromIntegral c + 1 :: Int)

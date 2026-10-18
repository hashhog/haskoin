{-# LANGUAGE OverloadedStrings #-}

-- | -fallbackfee for wallet sends (Core wallet/fees.cpp GetMinimumFeeRate and
-- wallet/spend.cpp CreateTransaction).  On a fresh regtest chain the fee
-- estimator has no data, so a send with no explicit fee rate must fail with
-- Core's text unless -fallbackfee is set.
module W209FallbackFeeSpec (spec) where

import Test.Hspec
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (FeeRate(..))
import Haskoin.Rpc (parseFallbackFee, resolveWalletFeeRate, defaultRpcConfig, RpcConfig(..))

spec :: Spec
spec = describe "W209 -fallbackfee" $ do
  it "default is disabled (Core DEFAULT_FALLBACK_FEE = 0)" $
    rpcFallbackFee defaultRpcConfig `shouldBe` 0

  it "fresh regtest chain, fallbackfee disabled: send fails with Core's text" $ do
    fe <- newFeeEstimator
    r <- resolveWalletFeeRate fe 0 100 Nothing
    r `shouldBe` Left
      "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee."

  it "fresh regtest chain, fallbackfee set: send gets the fallback rate" $ do
    fe <- newFeeEstimator
    r <- resolveWalletFeeRate fe 20000 100 Nothing
    r `shouldBe` Right (FeeRate 20000)

  it "fallback is raised to the mempool minimum fee" $ do
    fe <- newFeeEstimator
    r <- resolveWalletFeeRate fe 50 1000 Nothing
    r `shouldBe` Right (FeeRate 1000)

  it "an explicit fee rate bypasses estimation and the fallback check" $ do
    fe <- newFeeEstimator
    r <- resolveWalletFeeRate fe 0 100 (Just (FeeRate 5000))
    r `shouldBe` Right (FeeRate 5000)

  it "parseFallbackFee converts BTC/kvB to sat/kvB like ParseMoney" $ do
    parseFallbackFee "0.00020000" `shouldBe` Right 20000
    parseFallbackFee "0.0002" `shouldBe` Right 20000
    parseFallbackFee "0" `shouldBe` Right 0
    parseFallbackFee "1" `shouldBe` Right 100000000
    parseFallbackFee ".5" `shouldBe` Right 50000000
    parseFallbackFee "abc" `shouldSatisfy` either (const True) (const False)
    parseFallbackFee "-1" `shouldSatisfy` either (const True) (const False)
    parseFallbackFee "0.123456789" `shouldSatisfy` either (const True) (const False)
    parseFallbackFee "" `shouldSatisfy` either (const True) (const False)

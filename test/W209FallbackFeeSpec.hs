{-# LANGUAGE OverloadedStrings #-}

-- | -fallbackfee for wallet sends (Core wallet/fees.cpp GetMinimumFeeRate and
-- wallet/spend.cpp CreateTransaction).  On a fresh regtest chain the fee
-- estimator has no data, so a send with no explicit fee rate must fail with
-- Core's text unless -fallbackfee is set.
module W209FallbackFeeSpec (spec) where

import Test.Hspec
import Data.Aeson (Value(..), toJSON)
import Haskoin.FeeEstimator (newFeeEstimator)
import Haskoin.Mempool (FeeRate(..))
import Haskoin.Rpc (parseFallbackFee, resolveWalletFeeRate, sendToAddressFeeRate,
                    defaultRpcConfig, RpcConfig(..))

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

  -- Core v31.1 sendtoaddress: params[8] is avoid_reuse, params[9] is
  -- fee_rate (wallet/rpc/spend.cpp SetFeeEstimateMode(..., request.params[9]),
  -- rpc/client.cpp {"sendtoaddress", 9, "fee_rate"}).
  it "sendtoaddress reads fee_rate from params[9] (Core's help example)" $
    -- sendtoaddress "addr" 0.1 "" "" false true null "unset" null 1.1
    sendToAddressFeeRate (toJSON
      [ String "addr", Number 0.1, String "", String "", Bool False
      , Bool True, Null, String "unset", Null, Number 1.1 ])
      `shouldBe` Just (FeeRate 1100)

  it "sendtoaddress does not read avoid_reuse (params[8]) as a fee rate" $
    sendToAddressFeeRate (toJSON
      [ String "addr", Number 0.1, String "", String "", Bool False
      , Bool True, Null, String "unset", Number 5 ])
      `shouldBe` Nothing

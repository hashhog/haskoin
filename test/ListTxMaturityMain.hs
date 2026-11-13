{-# LANGUAGE OverloadedStrings #-}
-- | listtransactions coinbase category at the maturity boundary
-- (wallet-cause-E).  Core: IsTxImmatureCoinBase = GetBlocksToMaturity() > 0,
-- GetBlocksToMaturity = COINBASE_MATURITY + 1 - depth, so depth 100 is still
-- "immature" and depth 101 is the first "generate".
module Main (main) where

import Test.Hspec
import Haskoin.Rpc (coinbaseCategory)

main :: IO ()
main = hspec $ describe "coinbaseCategory" $ do
  it "depth 1 is immature"            $ coinbaseCategory 1   `shouldBe` "immature"
  it "depth 99 is immature"           $ coinbaseCategory 99  `shouldBe` "immature"
  it "depth 100 is immature (Core)"   $ coinbaseCategory 100 `shouldBe` "immature"
  it "depth 101 is generate"          $ coinbaseCategory 101 `shouldBe` "generate"

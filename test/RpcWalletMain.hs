module Main (main) where

import Test.Hspec (hspec)
import qualified RpcWalletSpec

main :: IO ()
main = hspec RpcWalletSpec.spec

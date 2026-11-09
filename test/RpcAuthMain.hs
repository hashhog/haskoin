module Main (main) where

import Test.Hspec (hspec)
import qualified RpcAuthSpec

main :: IO ()
main = hspec RpcAuthSpec.spec

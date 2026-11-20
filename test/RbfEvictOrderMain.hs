module Main (main) where

import Test.Hspec (hspec)
import qualified RbfEvictOrderSpec

main :: IO ()
main = hspec RbfEvictOrderSpec.spec

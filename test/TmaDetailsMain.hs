module Main (main) where

import Test.Hspec (hspec)
import qualified TmaDetailsSpec

main :: IO ()
main = hspec TmaDetailsSpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified InvalidateMempoolSpec

main :: IO ()
main = hspec InvalidateMempoolSpec.spec

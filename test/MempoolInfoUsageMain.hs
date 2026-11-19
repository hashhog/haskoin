module Main (main) where

import Test.Hspec (hspec)
import qualified MempoolInfoUsageSpec

main :: IO ()
main = hspec MempoolInfoUsageSpec.spec

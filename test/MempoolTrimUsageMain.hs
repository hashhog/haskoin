module Main (main) where

import Test.Hspec (hspec)
import qualified MempoolTrimUsageSpec

main :: IO ()
main = hspec MempoolTrimUsageSpec.spec

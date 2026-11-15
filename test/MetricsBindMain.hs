module Main (main) where

import Test.Hspec (hspec)
import qualified MetricsBindSpec

main :: IO ()
main = hspec MetricsBindSpec.spec

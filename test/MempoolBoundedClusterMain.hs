module Main (main) where

import Test.Hspec (hspec)
import qualified MempoolBoundedClusterSpec

main :: IO ()
main = hspec MempoolBoundedClusterSpec.spec

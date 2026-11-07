module Main (main) where

import Test.Hspec (hspec)
import qualified RestMempoolInfoSpec

main :: IO ()
main = hspec RestMempoolInfoSpec.spec

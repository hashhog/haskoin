module Main (main) where

import Test.Hspec (hspec)
import qualified MaxMempoolArgSpec

main :: IO ()
main = hspec MaxMempoolArgSpec.spec

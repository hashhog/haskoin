module Main (main) where

import Test.Hspec (hspec)
import qualified GetRawMempoolVerboseSpec

main :: IO ()
main = hspec GetRawMempoolVerboseSpec.spec

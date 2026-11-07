module Main (main) where

import Test.Hspec (hspec)
import qualified RawTxNotFoundSpec

main :: IO ()
main = hspec RawTxNotFoundSpec.spec

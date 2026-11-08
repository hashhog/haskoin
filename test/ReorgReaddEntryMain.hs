module Main (main) where

import Test.Hspec (hspec)
import qualified ReorgReaddEntrySpec

main :: IO ()
main = hspec ReorgReaddEntrySpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified ReorgOldTipSpec

main :: IO ()
main = hspec ReorgOldTipSpec.spec

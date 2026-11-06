module Main (main) where

import Test.Hspec (hspec)
import qualified GetBlockBoolSpec

main :: IO ()
main = hspec GetBlockBoolSpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified SpentbyOrderSpec

main :: IO ()
main = hspec SpentbyOrderSpec.spec

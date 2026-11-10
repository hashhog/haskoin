module Main (main) where

import Test.Hspec (hspec)
import qualified GetDataAmplificationSpec

main :: IO ()
main = hspec GetDataAmplificationSpec.spec

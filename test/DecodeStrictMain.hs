module Main (main) where

import Test.Hspec (hspec)
import qualified DecodeStrictSpec

main :: IO ()
main = hspec DecodeStrictSpec.spec

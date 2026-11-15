module Main (main) where

import Test.Hspec (hspec)
import qualified NotFoundUnsolicitedSpec

main :: IO ()
main = hspec NotFoundUnsolicitedSpec.spec

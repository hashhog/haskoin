module Main (main) where

import Test.Hspec (hspec)
import qualified GbtSigopsSpec

main :: IO ()
main = hspec GbtSigopsSpec.spec

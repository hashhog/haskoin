module Main (main) where

import Test.Hspec (hspec)
import qualified RegtestIbdSpec

main :: IO ()
main = hspec RegtestIbdSpec.spec

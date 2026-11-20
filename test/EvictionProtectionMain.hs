module Main (main) where

import Test.Hspec (hspec)
import qualified EvictionProtectionSpec

main :: IO ()
main = hspec EvictionProtectionSpec.spec

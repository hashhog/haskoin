module Main (main) where

import Test.Hspec (hspec)
import qualified EvictionProtectionSpec
import qualified EvictionTrackingSpec

main :: IO ()
main = hspec $ do
  EvictionProtectionSpec.spec
  EvictionTrackingSpec.spec

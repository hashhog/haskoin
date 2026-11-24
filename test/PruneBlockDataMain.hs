module Main (main) where

import Test.Hspec (hspec)
import qualified PruneBlockDataSpec

main :: IO ()
main = hspec PruneBlockDataSpec.spec

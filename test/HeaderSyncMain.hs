module Main (main) where

import Test.Hspec (hspec)
import qualified HeaderSyncSpec

main :: IO ()
main = hspec HeaderSyncSpec.spec

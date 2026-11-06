module Main (main) where

import Test.Hspec (hspec)
import qualified UnbroadcastSetSpec

main :: IO ()
main = hspec UnbroadcastSetSpec.spec

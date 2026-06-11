module Main (main) where

import Test.Hspec (hspec)
import qualified ServiceFlagsAdvertiseSpec

main :: IO ()
main = hspec ServiceFlagsAdvertiseSpec.spec

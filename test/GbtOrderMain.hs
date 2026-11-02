module Main (main) where

import Test.Hspec (hspec)
import qualified GbtOrderSpec

main :: IO ()
main = hspec GbtOrderSpec.spec

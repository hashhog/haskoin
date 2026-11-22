module Main (main) where

import Test.Hspec (hspec)
import qualified AddrmanSourceSpec

main :: IO ()
main = hspec AddrmanSourceSpec.spec

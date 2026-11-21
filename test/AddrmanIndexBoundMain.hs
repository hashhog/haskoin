module Main (main) where

import Test.Hspec (hspec)
import qualified AddrmanIndexBoundSpec

main :: IO ()
main = hspec AddrmanIndexBoundSpec.spec

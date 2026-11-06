module Main (main) where

import Test.Hspec (hspec)
import qualified PackageAcceptChildSpec

main :: IO ()
main = hspec PackageAcceptChildSpec.spec

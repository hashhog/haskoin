module Main (main) where

import Test.Hspec (hspec)
import qualified PackageConflictSpec

main :: IO ()
main = hspec PackageConflictSpec.spec

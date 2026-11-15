module Main (main) where

import Test.Hspec (hspec)
import qualified SubmitPackageResultsSpec

main :: IO ()
main = hspec SubmitPackageResultsSpec.spec

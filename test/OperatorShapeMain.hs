module Main (main) where

import Test.Hspec (hspec)
import qualified OperatorShapeSpec

main :: IO ()
main = hspec OperatorShapeSpec.spec

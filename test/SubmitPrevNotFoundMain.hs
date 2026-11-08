module Main (main) where

import Test.Hspec (hspec)
import qualified SubmitPrevNotFoundSpec

main :: IO ()
main = hspec SubmitPrevNotFoundSpec.spec

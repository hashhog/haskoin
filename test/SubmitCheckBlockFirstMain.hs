module Main (main) where

import Test.Hspec (hspec)
import qualified SubmitCheckBlockFirstSpec

main :: IO ()
main = hspec SubmitCheckBlockFirstSpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified SendRawErrorsSpec

main :: IO ()
main = hspec SendRawErrorsSpec.spec

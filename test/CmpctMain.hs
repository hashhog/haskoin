module Main (main) where

import Test.Hspec (hspec)
import qualified CmpctSpec

main :: IO ()
main = hspec CmpctSpec.spec

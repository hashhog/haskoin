module Main (main) where

import Test.Hspec (hspec)
import qualified RestartBestHeaderSpec

main :: IO ()
main = hspec RestartBestHeaderSpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified BanKeyedByIpSpec

main :: IO ()
main = hspec BanKeyedByIpSpec.spec

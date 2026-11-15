module Main (main) where

import Test.Hspec (hspec)
import qualified WalletPersistSpec

main :: IO ()
main = hspec WalletPersistSpec.spec

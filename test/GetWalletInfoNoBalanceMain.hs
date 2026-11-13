module Main (main) where

import Test.Hspec (hspec)
import qualified GetWalletInfoNoBalanceSpec

main :: IO ()
main = hspec GetWalletInfoNoBalanceSpec.spec

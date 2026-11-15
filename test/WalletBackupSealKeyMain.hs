module Main (main) where

import Test.Hspec (hspec)
import qualified WalletBackupSealKeySpec

main :: IO ()
main = hspec WalletBackupSealKeySpec.spec

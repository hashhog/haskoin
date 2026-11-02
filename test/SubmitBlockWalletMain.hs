module Main (main) where

import Test.Hspec (hspec)
import qualified SubmitBlockWalletSpec

main :: IO ()
main = hspec SubmitBlockWalletSpec.spec

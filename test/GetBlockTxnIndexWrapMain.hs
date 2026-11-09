module Main (main) where

import Test.Hspec (hspec)
import qualified GetBlockTxnIndexWrapSpec

main :: IO ()
main = hspec GetBlockTxnIndexWrapSpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified GetMempoolEntrySpec

main :: IO ()
main = hspec GetMempoolEntrySpec.spec

module Main (main) where

import Test.Hspec (hspec)
import qualified RawTxMessagesSpec

main :: IO ()
main = hspec RawTxMessagesSpec.spec

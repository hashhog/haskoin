module Main (main) where

import Test.Hspec (hspec)
import qualified Bip68MtpP2PArmSpec

main :: IO ()
main = hspec Bip68MtpP2PArmSpec.spec

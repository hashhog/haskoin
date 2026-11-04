module Main (main) where

import Test.Hspec (hspec)
import qualified MempoolAdmissionLockSpec

main :: IO ()
main = hspec MempoolAdmissionLockSpec.spec

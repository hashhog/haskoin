module Main (main) where

import System.Environment (lookupEnv)
import Test.Hspec (hspec)
import qualified SmSweepSpec

-- SM_SWEEP_RUN=1 runs the gap tests; otherwise they are pending.
main :: IO ()
main = do
  run <- (== Just "1") <$> lookupEnv "SM_SWEEP_RUN"
  hspec (SmSweepSpec.spec run)

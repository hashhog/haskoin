module Main (main) where
import Control.Monad (when)
import GHC.Conc (getNumCapabilities, setNumCapabilities)
import Test.Hspec
import qualified Gate6Spec
import qualified Gate6PostSpec
main :: IO ()
main = do
  caps <- getNumCapabilities
  when (caps < 8) $ setNumCapabilities 8
  -- PostSpec first: Gate6Spec's last example (G6-HK-6) sets the latch.
  hspec $ do
    Gate6PostSpec.spec
    Gate6Spec.spec

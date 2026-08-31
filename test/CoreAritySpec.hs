{-# LANGUAGE OverloadedStrings #-}

-- | #103 -- Core's central argument-count gate.
--
-- Core validates argument COUNT in one place, after the method lookup and
-- before any handler runs (rpc\/util.cpp:644 -> IsValidNumArgs, :733):
--
-- > required <= n <= declared
--
-- A violation throws the help text, which surfaces as error -1. haskoin
-- dispatched straight into its handler case, so surplus positional arguments
-- were silently dropped.
--
-- Verified read-only against the live Core oracle on 2026-08-31:
--
-- > getblockhash []           -> code=-1 "getblockhash height"
-- > getblockcount ["surplus"] -> code=-1 "getblockcount"
-- > getblockhash [1]          -> OK (control)
--
-- Live evidence that haskoin had the gap, same day:
--
-- > savemempool ["ARITY-WRITER-PROBE-haskoin"]
-- >   -> {"result":{"filename":"/data/nvme1/hashhog-mainnet/haskoin/main/mempool.dat"}}
module CoreAritySpec (spec) where

import Test.Hspec
import qualified Data.Map.Strict as Map
import Data.Text (Text)

import Haskoin.CoreArity (coreArityTable, lookupCoreArity)
import Haskoin.Rpc (coreArityViolation, haskoinMethodNames)
import Data.Aeson (Value (..), toJSON)
import qualified Data.Vector as V

-- | Build a positional params value of the given length.
posParams :: Int -> Value
posParams n = Array (V.replicate n (toJSON ("x" :: Text)))

spec :: Spec
spec = describe "#103 Core argument-count gate" $ do

  -- Guard: every assertion below is vacuous if the compiled-in table is empty.
  describe "the compiled-in table" $ do
    it "is populated" $ do
      Map.size coreArityTable `shouldSatisfy` (>= 80)

    it "carries Core's counts" $ do
      lookupCoreArity "savemempool"        `shouldBe` Just (0, 0)
      lookupCoreArity "clearbanned"        `shouldBe` Just (0, 0)
      lookupCoreArity "gettxout"           `shouldBe` Just (2, 3)
      lookupCoreArity "sendrawtransaction" `shouldBe` Just (1, 3)

    it "returns Nothing for an unlisted method (callers must fail OPEN)" $
      -- Coverage is 87 of 103.
      lookupCoreArity "definitely-not-an-rpc" `shouldBe` Nothing

  describe "the served-method list" $ do
    it "holds bare names, not signatures or section headers" $ do
      length haskoinMethodNames `shouldSatisfy` (>= 40)
      haskoinMethodNames `shouldSatisfy` elem "getblockcount"
      haskoinMethodNames `shouldSatisfy` elem "getblockhash"
      haskoinMethodNames `shouldSatisfy` notElem ""

  describe "violations" $ do
    it "rejects a surplus argument" $ do
      coreArityViolation "savemempool"   (posParams 1) `shouldBe` True
      coreArityViolation "getblockcount" (posParams 1) `shouldBe` True

    it "rejects a missing required argument" $ do
      coreArityViolation "getblockhash" (posParams 0) `shouldBe` True
      coreArityViolation "gettxout"     (posParams 1) `shouldBe` True

    it "rejects one argument past the declared maximum" $
      coreArityViolation "gettxout" (posParams 4) `shouldBe` True

  -- The CONTROLS. Without these, a gate that refused everything would satisfy
  -- every expectation above.
  describe "controls" $ do
    it "accepts every legal count from required..declared" $ do
      coreArityViolation "savemempool"   (posParams 0) `shouldBe` False
      coreArityViolation "getblockcount" (posParams 0) `shouldBe` False
      coreArityViolation "getblockhash"  (posParams 1) `shouldBe` False
      coreArityViolation "gettxout"      (posParams 2) `shouldBe` False
      coreArityViolation "gettxout"      (posParams 3) `shouldBe` False

    it "leaves an unknown method alone, so it stays -32601 not -1" $
      -- Core resolves the method first. haskoin's case both resolves and
      -- executes, so the gate deliberately fires only for served methods.
      coreArityViolation "definitely-not-an-rpc" (posParams 5) `shouldBe` False

    it "leaves methods Core declares but haskoin does not serve alone" $ do
      let unserved = [ m | m <- Map.keys coreArityTable
                         , m `notElem` haskoinMethodNames ]
      mapM_ (\m -> coreArityViolation m (posParams 6) `shouldBe` False) unserved

    it "exempts named params, which Core resolves by name" $
      coreArityViolation "getblockhash" (Object mempty) `shouldBe` False

  -- The gate only fires for methods 'haskoinMethodNames' says we serve, so a
  -- method that is dispatched but missing from the help listing is invisible to
  -- it. That was true of 31 methods, savemempool among them: haskoin answered
  -- savemempool ["path"] on mainnet while `help` never mentioned it.
  describe "help listing covers what the dispatcher serves" $
    it "lists savemempool and the rest of the previously-unlisted set" $ do
      let mustList = [ "savemempool", "clearbanned", "createmultisig"
                     , "deriveaddresses", "getnetworkhashps", "scantxoutset"
                     , "gettxspendingprevout", "importmempool"
                     , "combinerawtransaction", "verifytxoutproof"
                     , "joinpsbts", "getdescriptorinfo" ]
      mapM_ (\m -> haskoinMethodNames `shouldSatisfy` elem m) mustList

    -- ...and with it listed, the gate reaches it.
  describe "the gate reaches a previously-unlisted method" $
    it "rejects savemempool with a surplus argument" $
      coreArityViolation "savemempool" (posParams 1) `shouldBe` True

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Download-path instrumentation after e8a03a9's 8x RATE regression.
--
-- Live 2026-09-20: receipt-refill + 128-cap dropped 106 -> 13 blk/min.
-- The previous diagnosis ("progress refill is not firing") was wrong;
-- making it fire made throughput worse. This spec does not guess a
-- replacement cause. It pins the two logs the next measurement needs:
--
--   (1) every issued getdata window names its branch
--       (progress / stall / receipt)
--   (2) every block that arrives and is not connected is counted
--       and logged with a reason (G1 out-of-order is the obvious
--       candidate, not a claim)
--
-- Control: cabal run haskoin-test --enable-tests -- -m download-instrument
--
-- The live rate is still the RATE control; this is the instrument the
-- live rate was missing. Do not treat a green here as a rate fix.
module W197DownloadInstrumentSpec (spec) where

import Test.Hspec
import Data.List (isInfixOf, isPrefixOf)

import Haskoin.Network
  ( LinearFillBranch (..)
  , linearFillBranchTag
  , selectLinearFillBranch
  , formatKickerWindow
  )
import Haskoin.Consensus
  ( UnconnectedReason (..)
  , unconnectedReasonTag
  , classifyConnectReject
  , formatUnconnectedArrival
  )

mainHs :: IO String
mainHs = readFile "app/Main.hs"

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "download-instrument: kicker branch" $ do
    it "progress / stall / receipt tags are distinct and stable" $ do
      linearFillBranchTag FillProgress `shouldBe` "progress"
      linearFillBranchTag FillStall `shouldBe` "stall"
      linearFillBranchTag FillReceipt `shouldBe` "receipt"
      let p = formatKickerWindow FillProgress 16 6635 6650 1
          s = formatKickerWindow FillStall 16 6635 6650 1
          r = formatKickerWindow FillReceipt 128 6299 6426 1
      ("Block-gap kicker: pipelining" `isInfixOf` p) `shouldBe` True
      ("branch=progress" `isInfixOf` p) `shouldBe` True
      ("branch=stall" `isInfixOf` s) `shouldBe` True
      ("branch=receipt" `isInfixOf` r) `shouldBe` True
      -- Prefix stays so greps for "Block-gap kicker: pipelining" still hit.
      ("Block-gap kicker: pipelining 16 blocks (heights 6635-6650) to 1 peer(s)"
         `isPrefixOf` p)
        `shouldBe` True
      p `shouldNotBe` s
      s `shouldNotBe` r

    it "selectLinearFillBranch: receipt wins, then progress, then stall" $ do
      -- Receipt path is fillLinearPipeline; it must not be mis-tagged
      -- as progress even if the tip just advanced.
      selectLinearFillBranch True True True False False False
        `shouldBe` FillReceipt
      selectLinearFillBranch False True True False False False
        `shouldBe` FillProgress
      selectLinearFillBranch False False True False False False
        `shouldBe` FillStall
      selectLinearFillBranch False False False True False False
        `shouldBe` FillMute
      selectLinearFillBranch False False False False True False
        `shouldBe` FillOrphaned
      selectLinearFillBranch False False False False False True
        `shouldBe` FillNeedNew

    it "Main.hs window log goes through formatKickerWindow with a branch" $ do
      src <- mainHs
      ("formatKickerWindow" `isInfixOf` src) `shouldBe` True
      ("selectLinearFillBranch" `isInfixOf` src) `shouldBe` True
      ("FillReceipt" `isInfixOf` src) `shouldBe` True
      -- Untagged putStrLn is the e8a03a9 hole: receipt and kicker
      -- issued identical "Block-gap kicker: pipelining" lines, so the
      -- 18 windows/60s could not say which branch fired.
      ("putStrLn $ \"Block-gap kicker: pipelining \"" `isInfixOf` src)
        `shouldBe` False

    it "fillLinearPipeline tags its window as receipt, not kicker-progress" $ do
      src <- mainHs
      let afterFill =
            dropWhile (not . ("fillLinearPipeline pm hc db" `isInfixOf`))
                      (lines src)
          body = unlines (take 50 afterFill)
      ("FillReceipt" `isInfixOf` body) `shouldBe` True
      ("requestBlockRange" `isInfixOf` body) `shouldBe` True

  describe "download-instrument: unconnected arrival" $ do
    it "G19 is not classified as G1 (Core G1 is a prefix of Core G19)" $ do
      -- W163 already paid for this: matching "Core G1" also hits G19.
      classifyConnectReject
        "connectBlockAt h: missing prevout op (Core G19 — validation.cpp:2007 assert(is_spent))"
        `shouldBe` UnconnG19MissingPrevout
      classifyConnectReject
        "connectBlockAt h: prevHash p does not equal current BestBlock b (Core G1 — validation.cpp:2333)"
        `shouldBe` UnconnG1OutOfOrder
      classifyConnectReject
        "Core full-block validation: bad-cb-amount"
        `shouldBe` UnconnValidation
      classifyConnectReject "something else" `shouldBe` UnconnOther
      unconnectedReasonTag UnconnG1OutOfOrder `shouldBe` "g1-out-of-order"
      unconnectedReasonTag UnconnG19MissingPrevout `shouldBe` "g19-missing-prevout"
      unconnectedReasonTag UnconnTooFarAhead `shouldBe` "too-far-ahead"
      unconnectedReasonTag UnconnHeaderRejected `shouldBe` "header-rejected"

    it "format carries height, next-needed, reason, running count" $ do
      let line =
            formatUnconnectedArrival (Just 6710) 6300 UnconnG1OutOfOrder 127
      ("Block arrived unconnected:" `isPrefixOf` line) `shouldBe` True
      ("height=6710" `isInfixOf` line) `shouldBe` True
      ("next-needed=6300" `isInfixOf` line) `shouldBe` True
      ("reason=g1-out-of-order" `isInfixOf` line) `shouldBe` True
      ("count=127" `isInfixOf` line) `shouldBe` True
      let unknown =
            formatUnconnectedArrival Nothing 6300 UnconnHeaderRejected 1
      ("height=?" `isInfixOf` unknown) `shouldBe` True
      ("reason=header-rejected" `isInfixOf` unknown) `shouldBe` True

    it "count in the line is the running total (growth is visible)" $ do
      let a = formatUnconnectedArrival (Just 10) 9 UnconnG1OutOfOrder 1
          b = formatUnconnectedArrival (Just 11) 9 UnconnG1OutOfOrder 128
      ("count=1" `isInfixOf` a) `shouldBe` True
      ("count=128" `isInfixOf` b) `shouldBe` True

    it "MBlock Left-connect logs every unconnected arrival, not only next-needed" $ do
      src <- mainHs
      ("formatUnconnectedArrival" `isInfixOf` src) `shouldBe` True
      let afterLeft =
            dropWhile (not . ("Left cbErr" `isInfixOf`)) (lines src)
          untilPut =
            takeWhile (not . ("putBlock db bh block" `isInfixOf`)) afterLeft
      unlines untilPut `shouldSatisfy` ("formatUnconnectedArrival" `isInfixOf`)
      -- Must not be gated on next-needed: a 128-deep out-of-order flood
      -- used to connect nothing and say nothing.
      ("when (height == nb) $\n                putStrLn $\n                  formatUnconnectedArrival" `isInfixOf` src)
        `shouldBe` False

    it "too-far-ahead and header-reject also count as unconnected arrivals" $ do
      src <- mainHs
      ("UnconnTooFarAhead" `isInfixOf` src) `shouldBe` True
      ("UnconnHeaderRejected" `isInfixOf` src) `shouldBe` True
      ("unconnectedCountRef" `isInfixOf` src) `shouldBe` True

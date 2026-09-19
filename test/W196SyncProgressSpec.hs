{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Sync-progress heartbeat. Live 2026-09-19 the only height-bearing
-- periodic line was `Periodic WAL fsync at height=` which printed
-- hcHeight (the header tip, 967684) while getblockcount was 910150.
-- Combined with no UpdateTip on the deployed 2ab99af binary, a
-- log-based blk/h was unusable and the post-deploy rate had to be
-- reconstructed from getblockcount polls.
--
-- Control: cabal run haskoin-test --enable-tests -- -m 'sync progress'
--
-- Rate uses elapsed POSIX seconds (two samples of the same clock).
-- Never a log timestamp minus the operator's UTC clock — this box
-- runs EDT and the logs print local time.
module W196SyncProgressSpec (spec) where

import Test.Hspec
import Data.List (isInfixOf, isPrefixOf)

import Haskoin.Consensus
  ( formatSyncProgress
  , syncProgressBlkPerHour
  , syncProgressIntervalSecs
  )

mainHs, consensusHs :: IO String
mainHs = readFile "app/Main.hs"
consensusHs = readFile "src/Haskoin/Consensus.hs"

spec :: Spec
spec = do
  describe "sync progress line format (validated, headers, POSIX rate)" $ do
    it "starts with Sync progress: and carries every required field" $ do
      let line = formatSyncProgress 910150 967684 4 1800
      ("Sync progress: " `isPrefixOf` line) `shouldBe` True
      ("validated=910150" `isInfixOf` line) `shouldBe` True
      ("headers=967684" `isInfixOf` line) `shouldBe` True
      ("delta=4" `isInfixOf` line) `shouldBe` True
      ("window=1800s" `isInfixOf` line) `shouldBe` True
      ("rate=8.0 blk/h" `isInfixOf` line) `shouldBe` True

    it "does not label the header tip as height=" $ do
      let line = formatSyncProgress 910150 967684 4 1800
      ("height=967684" `isInfixOf` line) `shouldBe` False
      ("height=910150" `isInfixOf` line) `shouldBe` False
      ("validated=" `isInfixOf` line) `shouldBe` True

    it "4 blocks in 1800 POSIX seconds is 8.0 blk/h" $ do
      syncProgressBlkPerHour 4 1800 `shouldBe` 8.0

    it "zero delta over a minute is 0.0 (a stall is visible, not silent)" $ do
      let line = formatSyncProgress 910150 967684 0 60
      ("delta=0" `isInfixOf` line) `shouldBe` True
      ("rate=0.0 blk/h" `isInfixOf` line) `shouldBe` True
      syncProgressBlkPerHour 0 60 `shouldBe` 0.0

    it "zero POSIX window is 0.0 blk/h, not Infinity" $ do
      let line = formatSyncProgress 910150 967684 26 0
      ("rate=0.0 blk/h" `isInfixOf` line) `shouldBe` True
      syncProgressBlkPerHour 26 0 `shouldBe` 0.0
      syncProgressBlkPerHour 26 (-1) `shouldBe` 0.0

    it "live 2ab99af clean window 26 blocks / 11779s is 7.9 blk/h, not 34" $ do
      -- 04:37:16Z height 910124 (headers settled) -> 07:53:35Z 910150.
      -- Same pid, same 2ab99af binary, no restart. Pre-deploy baseline
      -- was 80 blocks / 8520s = 33.8 blk/h. This is the discriminator
      -- the UNMEASURED queue item asked for: holding near 7.7, not
      -- recovering toward 34, so warmup is dead.
      let line = formatSyncProgress 910150 967684 26 11779
      ("rate=7.9 blk/h" `isInfixOf` line) `shouldBe` True
      let pre = formatSyncProgress 910120 967631 80 8520
      ("rate=33.8 blk/h" `isInfixOf` pre) `shouldBe` True

    it "heartbeat interval is 60 POSIX seconds" $ do
      syncProgressIntervalSecs `shouldBe` 60

  describe "sync progress is wired into the live heartbeat, not header height" $ do
    it "Main.hs flush timer calls formatSyncProgress" $ do
      src <- mainHs
      ("formatSyncProgress" `isInfixOf` src) `shouldBe` True
      ("lastProgressHeightRef" `isInfixOf` src) `shouldBe` True
      ("syncProgressIntervalSecs" `isInfixOf` src) `shouldBe` True

    it "Main.hs WAL logs validated= and headers=, not a header-only height=" $ do
      src <- mainHs
      ("Periodic WAL fsync at validated=" `isInfixOf` src) `shouldBe` True
      ("Periodic WAL fsync at height=" `isInfixOf` src) `shouldBe` False

    it "Consensus.hs defines formatSyncProgress with validated= not height=" $ do
      src <- consensusHs
      ("formatSyncProgress" `isInfixOf` src) `shouldBe` True
      ("syncProgressBlkPerHour" `isInfixOf` src) `shouldBe` True
      ("\"Sync progress: validated=\"" `isInfixOf` src) `shouldBe` True

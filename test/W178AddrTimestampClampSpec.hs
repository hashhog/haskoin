{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W178 — ADDR/ADDRV2 timestamp clamping (Finding 3G)
--
-- Bitcoin Core net_processing.cpp:5678-5680 (ProcessAddrs):
--   if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_time + 10min)
--       addr.nTime = current_time - 5*24h;
--
-- A peer-advertised timestamp that is pre-2001 (unix <= 100,000,000) or
-- more than 10 minutes in the future is bogus.  Both cases are clamped to
-- "5 days ago" before the address is stored in AddrMan so that:
--   - the address is still stored (not dropped), matching Core behaviour;
--   - it is treated as stale, making relay unlikely (Core relays only when
--     nTime > now - 10min);
--   - an attacker cannot inject a far-future timestamp to make an address
--     appear perpetually fresh and bias selection / relay.
--
-- These tests are NON-VACUOUS: the tested function (clampAddrTimestamp) did
-- not exist before the fix.  Every test below would fail on the pre-fix
-- codebase with a compile error, which is the strongest possible signal that
-- the fix is load-bearing.
--
-- Reference: bitcoin-core/src/net_processing.cpp:5678-5680

module W178AddrTimestampClampSpec (spec) where

import Test.Hspec
import Data.Int  (Int64)
import Data.Word (Word32)

import Haskoin.Network (clampAddrTimestamp)

--------------------------------------------------------------------------------
-- Constants (mirroring Core)
--------------------------------------------------------------------------------

-- | Core: nTime <= 100_000_000 is considered bogus (pre-2001-03-05 UTC).
preEpochThreshold :: Word32
preEpochThreshold = 100_000_000

-- | Core: clamped value = current_time - 5*24h
fiveDaysSecs :: Int64
fiveDaysSecs = 5 * 24 * 60 * 60   -- 432000

-- | Core: 10 minutes in seconds (the future threshold)
tenMinSecs :: Int64
tenMinSecs = 600

-- | A representative "now" in the middle of the valid Bitcoin era
sampleNow :: Int64
sampleNow = 1_700_000_000   -- 2023-11-14 22:13:20 UTC

--------------------------------------------------------------------------------
-- G1: pre-2001 timestamps are clamped
--------------------------------------------------------------------------------

spec_G1 :: Spec
spec_G1 = describe "G1 pre-2001 timestamp (<=100000000) is clamped to now-5d" $ do
  it "timestamp 0 (year 1970) → now - 5 days" $
    clampAddrTimestamp sampleNow 0
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "timestamp 1 → now - 5 days" $
    clampAddrTimestamp sampleNow 1
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "timestamp 100000000 (exactly the bogus threshold) → now - 5 days" $
    clampAddrTimestamp sampleNow preEpochThreshold
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "timestamp 50000000 → now - 5 days" $
    clampAddrTimestamp sampleNow 50_000_000
      `shouldBe` (sampleNow - fiveDaysSecs)

--------------------------------------------------------------------------------
-- G2: far-future timestamps are clamped
--------------------------------------------------------------------------------

spec_G2 :: Spec
spec_G2 = describe "G2 far-future timestamp (> now+10min) is clamped to now-5d" $ do
  it "timestamp now+601 (just over 10 min) → now - 5 days" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + tenMinSecs + 1))
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "timestamp now+3600 (1 hour ahead) → now - 5 days" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 3600))
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "timestamp now+86400 (1 day ahead) → now - 5 days" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 86400))
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "Word32 max (year ~2106) → now - 5 days" $
    clampAddrTimestamp sampleNow (maxBound :: Word32)
      `shouldBe` (sampleNow - fiveDaysSecs)

--------------------------------------------------------------------------------
-- G3: valid timestamps pass through unchanged
--------------------------------------------------------------------------------

spec_G3 :: Spec
spec_G3 = describe "G3 valid timestamp passes through unchanged" $ do
  it "timestamp now-30s → unchanged" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow - 30))
      `shouldBe` (sampleNow - 30)

  it "timestamp now-7d → unchanged (within 30d addrman horizon)" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow - 7 * 24 * 3600))
      `shouldBe` (sampleNow - 7 * 24 * 3600)

  it "timestamp now+300 (5 min ahead, within 10-min window) → unchanged" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 300))
      `shouldBe` (sampleNow + 300)

  it "timestamp now+599 (just under 10 min) → unchanged" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 599))
      `shouldBe` (sampleNow + 599)

--------------------------------------------------------------------------------
-- G4: exact boundary — now+600 (10 minutes exactly) is NOT clamped
-- Core: "nTime > current_time + 10min" — the boundary is exclusive.
-- ts == now+600 does NOT satisfy ">", so it is not clamped.
-- ts == now+601 DOES satisfy ">", so it is clamped.
--------------------------------------------------------------------------------

spec_G4 :: Spec
spec_G4 = describe "G4 future-timestamp boundary is exclusive (> not >=)" $ do
  it "timestamp now+600 (exactly 10 min) → NOT clamped (boundary is exclusive)" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 600))
      `shouldBe` (sampleNow + 600)

  it "timestamp now+601 (10 min + 1 s) → clamped (just over boundary)" $
    clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 601))
      `shouldBe` (sampleNow - fiveDaysSecs)

--------------------------------------------------------------------------------
-- G5: exact boundary — 100000000 is bogus but 100000001 is valid
-- Core: "nTime <= 100000000" — the boundary is inclusive (<=).
-- ts == 100000000 IS clamped; ts == 100000001 is NOT.
--------------------------------------------------------------------------------

spec_G5 :: Spec
spec_G5 = describe "G5 pre-epoch boundary is inclusive (<= not <)" $ do
  it "timestamp 100000000 (exactly the threshold) → clamped" $
    clampAddrTimestamp sampleNow 100_000_000
      `shouldBe` (sampleNow - fiveDaysSecs)

  it "timestamp 100000001 (one above threshold) → NOT clamped" $
    clampAddrTimestamp sampleNow 100_000_001
      `shouldBe` 100_000_001

--------------------------------------------------------------------------------
-- G6: clamped value is exactly now - 5*24*60*60 (not some other fallback)
--------------------------------------------------------------------------------

spec_G6 :: Spec
spec_G6 = describe "G6 clamped value is exactly now - 432000 seconds" $ do
  it "pre-epoch: now - result == 432000" $
    (sampleNow - clampAddrTimestamp sampleNow 0) `shouldBe` fiveDaysSecs

  it "future: now - result == 432000" $
    (sampleNow - clampAddrTimestamp sampleNow (fromIntegral (sampleNow + 9999)))
      `shouldBe` fiveDaysSecs

--------------------------------------------------------------------------------
-- G7: clamping is idempotent w.r.t. the fixed-point now-5d
-- If the clamped value (now-5d) is passed back in, it must not be re-clamped
-- (it is a valid past timestamp, well above 100000000 for reasonable 'now').
--------------------------------------------------------------------------------

spec_G7 :: Spec
spec_G7 = describe "G7 clamped value (now-5d) is itself a valid timestamp" $ do
  it "clampAddrTimestamp (now - 5d) → returned unchanged" $ do
    let clamped = fromIntegral (sampleNow - fiveDaysSecs) :: Word32
        result  = clampAddrTimestamp sampleNow clamped
    -- now-5d is a perfectly valid past timestamp; it must not be re-clamped.
    result `shouldBe` (sampleNow - fiveDaysSecs)

--------------------------------------------------------------------------------
-- Main spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W178 ADDR/ADDRV2 timestamp clamping — Finding 3G" $ do
  spec_G1
  spec_G2
  spec_G3
  spec_G4
  spec_G5
  spec_G6
  spec_G7

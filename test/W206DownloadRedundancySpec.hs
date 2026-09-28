{-# LANGUAGE ScopedTypeVariables #-}

-- | Block-download redundancy: never re-request a block that is in
-- flight on a live peer (Core FindNextBlocksToDownload +
-- BLOCK_STALLING_TIMEOUT).
--
-- Replay harness 2026-09-27 (base-910000, one --connect feeder, cap
-- 128, 1f73e73): the feeder served 11,156 blocks to connect 199 (56x);
-- the node log had 3,104 "re-requesting 128 stalling-next-needed
-- hash(es)" lines. 'stallingNextNeeded' charged a stall to the peer
-- holding next-needed 2 s after the REQUEST, and the rotation re-sent
-- that peer's whole window to the same live socket (with one peer,
-- "every peer failed" reset the failed set). The block had usually
-- already ARRIVED and was being validated on that peer's recv thread.
--
-- Core: a block leaves mapBlocksInFlight when it arrives
-- (RemoveBlockRequest); a staller exists only when ANOTHER peer with an
-- empty queue cannot be given anything because the window is exhausted
-- (waitingfor != peer.m_id); its m_stalling_since starts then, resets
-- when it delivers any block, and past the (adaptive 2..64 s) timeout
-- the staller is DISCONNECTED, which releases its blocks.
--
-- Control: cabal run haskoin-test --enable-tests -- -m download-redundancy
module W206DownloadRedundancySpec (spec) where

import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Test.Hspec

import Haskoin.Network
  ( PipelineInflight (..)
  , StallClock (..)
  , blockStallingTimeout
  , blockStallingTimeoutMax
  , findBlockStaller
  , initialStallClock
  , muteClockView
  , mutePipelineHeads
  , muteRotationAllowed
  , simulateSingleFeeder
  , stallClockConnected
  , stallClockDelivered
  , stallClockStep
  )

spec :: Spec
spec = describe "download-redundancy: Core in-flight / staller semantics" $ do

  describe "single --connect feeder (replay harness shape)" $ do
    it "requests every block exactly once while blocks take 3 ticks to validate" $ do
      let (tip, reqs) = simulateSingleFeeder 1 3 400 5000
      tip `shouldBe` 400
      Map.size reqs `shouldBe` 400
      Map.filter (/= 1) reqs `shouldBe` Map.empty

    it "still requests each block once when validation is slower than the mute timeout" $ do
      -- 20-tick blocks (> 16 s first-byte mute, > 2 s stall): the feeder's
      -- socket is unread the whole time; that is our thread, not the peer.
      let (tip, reqs) = simulateSingleFeeder 1 20 150 5000
      tip `shouldBe` 150
      Map.filter (/= 1) reqs `shouldBe` Map.empty

    it "still requests each block once when the feeder is slower than the stall timeout" $ do
      -- 6 ticks per block from the feeder, 1 to validate: the node waits
      -- on the socket longer than 2 s between blocks. A lone peer is not
      -- a staller (Core waitingfor != peer.m_id), so nothing is re-sent.
      let (tip, reqs) = simulateSingleFeeder 6 1 150 5000
      tip `shouldBe` 150
      Map.filter (/= 1) reqs `shouldBe` Map.empty

  describe "node wiring (app/Main.hs)" $ do
    it "the MBlock arm takes an arrived block out of in-flight before validating it" $ do
      src <- readFile "app/Main.hs"
      let flat = unwords (words src)
          arm = unwords (words (unlines (takeWhile (not . ("MTx tx ->" `isInfixOf`))
                  (dropWhile (not . ("MBlock block ->" `isInfixOf`)) (lines src)))))
          beforeConnect = fst (breakOn "connectBlock db net block height spent" arm)
      flat `shouldSatisfy` ("modifyIORef' linearInflightRef (Map.delete rbh)" `isInfixOf`)
      beforeConnect `shouldSatisfy` ("receiptDone <- blockReceipt addr bh" `isInfixOf`)
      beforeConnect `shouldSatisfy` ("flip finally receiptDone" `isInfixOf`)
    it "the kicker disconnects a staller and never calls the old request-age rule" $ do
      src <- readFile "app/Main.hs"
      let flat = unwords (words src)
      flat `shouldSatisfy` ("findBlockStaller eligibleIds windowExhausted" `isInfixOf`)
      flat `shouldSatisfy` ("muteRotationAllowed (length peers) failed0 mutePids0" `isInfixOf`)
      flat `shouldSatisfy` ("haveBody = haveBodyStored `Set.union` receivingK" `isInfixOf`)
      flat `shouldSatisfy` ("haveBody = haveBodyStored `Set.union` Map.keysSet receivingNow" `isInfixOf`)

  describe "findBlockStaller (Core nodeStaller)" $ do
    let inf = [ PipelineInflight 0 101 0 Nothing
              , PipelineInflight 0 102 0 Nothing
              , PipelineInflight 1 103 0 Nothing ]
    it "a lone peer is never its own staller" $
      findBlockStaller [0] True [ x | x <- inf, pifPeer x == 0 ] `shouldBe` Nothing
    it "no staller while the window still has blocks to request" $
      findBlockStaller [0, 1, 2] False inf `shouldBe` Nothing
    it "no staller when every other peer still has blocks in flight" $
      findBlockStaller [0, 1] True inf `shouldBe` Nothing
    it "the holder of the first in-flight block stalls an idle peer" $
      findBlockStaller [0, 1, 2] True inf `shouldBe` Just 0
    it "an idle peer that is failed/mute does not count" $
      findBlockStaller [0, 1] True inf `shouldBe` Nothing

  describe "stall clock (m_stalling_since + adaptive timeout)" $ do
    let live = Set.fromList ["a", "b"]
    it "starts when the staller is first seen, not at request time" $ do
      let (f1, c1) = stallClockStep 100 live Set.empty (Just "a") initialStallClock
      f1 `shouldBe` Nothing
      Map.lookup "a" (scSince c1) `shouldBe` Just 100
      let (f2, _) = stallClockStep 102 live Set.empty (Just "a") c1
      f2 `shouldBe` Nothing
      let (f3, c3) = stallClockStep 103 live Set.empty (Just "a") c1
      f3 `shouldBe` Just "a"
      scTimeout c3 `shouldBe` 4
    it "a delivered block resets the clock" $ do
      let (_, c1) = stallClockStep 100 live Set.empty (Just "a") initialStallClock
          c2 = stallClockDelivered "a" c1
          (f, c3) = stallClockStep 103 live Set.empty (Just "a") c2
      f `shouldBe` Nothing
      Map.lookup "a" (scSince c3) `shouldBe` Just 103
    it "a peer whose block we are validating has no clock" $ do
      let (_, c1) = stallClockStep 100 live Set.empty (Just "a") initialStallClock
          (f, c2) = stallClockStep 200 live (Set.singleton "a") (Just "a") c1
      f `shouldBe` Nothing
      Map.member "a" (scSince c2) `shouldBe` False
    it "a peer that left has no clock" $ do
      let (_, c1) = stallClockStep 100 live Set.empty (Just "a") initialStallClock
          (f, c2) = stallClockStep 200 (Set.singleton "b") Set.empty Nothing c1
      f `shouldBe` Nothing
      scSince c2 `shouldBe` Map.empty
    it "timeout doubles to at most 64 s and decays by 0.85 per connected block to 2 s" $ do
      let fire c = snd (stallClockStep 10000 live Set.empty (Just "a")
                          (snd (stallClockStep 0 live Set.empty (Just "a") c)))
          cs = iterate fire (initialStallClock :: StallClock String)
      map scTimeout (take 8 cs) `shouldBe` [2, 4, 8, 16, 32, 64, 64, 64]
      scTimeout (stallClockConnected 1 (cs !! 5)) `shouldBe` 64 * 0.85
      scTimeout (stallClockConnected 1000 (cs !! 5)) `shouldBe` 2
      blockStallingTimeout `shouldBe` 2
      blockStallingTimeoutMax `shouldBe` 64

  describe "mute head" $ do
    it "a peer whose block we are validating is not mute" $ do
      let inf = [ PipelineInflight 0 101 0 Nothing ]
      fst (mutePipelineHeads 30 inf) `shouldBe` [0]
      fst (mutePipelineHeads 30 (muteClockView (Set.singleton 0) Map.empty 30 inf))
        `shouldBe` []
    it "its clock restarts when our processing of its last block finished" $ do
      let inf = [ PipelineInflight 0 101 0 Nothing ]
      fst (mutePipelineHeads 30 (muteClockView Set.empty (Map.singleton 0 20) 30 inf))
        `shouldBe` []
      fst (mutePipelineHeads 40 (muteClockView Set.empty (Map.singleton 0 20) 40 inf))
        `shouldBe` [0]
    it "never rotates a mute peer's blocks back onto itself" $ do
      muteRotationAllowed 1 Set.empty [0] `shouldBe` False
      muteRotationAllowed 2 Set.empty [0] `shouldBe` True
      muteRotationAllowed 2 (Set.singleton 1) [0] `shouldBe` False

breakOn :: String -> String -> (String, String)
breakOn pat = go ""
  where
    go acc rest@(c : cs)
      | pat `isPrefixOf'` rest = (reverse acc, rest)
      | otherwise = go (c : acc) cs
    go acc [] = (reverse acc, [])
    isPrefixOf' p xs = take (length p) xs == p

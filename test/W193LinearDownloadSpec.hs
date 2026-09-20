{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Linear block-download RATE: do not pin the pipeline to one peer.
--
-- Live symptom (receipt haskoin-postrebuild-download-stall-2026-09-18):
-- verified chainstate at 910000, headers at 967625, 7 peers connected,
-- then the tip froze at 910023. The kicker logged
--
--   Block-gap kicker: pipelining 128 blocks (heights 910024-910151) to 1 peer
--
-- on a loop with stall-recover rotating the SAME 128-hash window onto
-- another single peer. That is requestBlockRange. It is not a UTXO-set
-- problem.
--
-- Shape copied from blockbrew 9ccaa90 / adda3c0 (not the Go):
--   (1) extend in-flight across peers, 16 per peer, skip mute/LIMITED
--   (2) first-byte timeout applies to the pipeline HEAD only — siblings
--       queued behind a live head are not mute
--
-- Control: a 7-peer set with peer 0 deliberately mute must still advance
-- the connected tip (RATE), not stall waiting on that one peer.
module W193LinearDownloadSpec (spec) where

import Test.Hspec
import Data.List (isInfixOf)
import Data.Word (Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import Haskoin.Types (BlockHash (..), Hash256 (..))
import Haskoin.Network
  ( nodeNetwork
  , nodeNetworkLimited
  , nodeWitness
  , combineServices
  , ForkGetDataPeer (..)
  , planLinearGetData
  , planLinearGetDataWithCap
  , maxBlocksInTransitPerPeer
  , maxBlocksInFlightTotal
  , singleConnectBlocksInFlightPerPeer
  , resolveBlocksInFlightPerPeer
  , PipelineInflight (..)
  , blockFirstByteTimeout
  , mutePipelineHeads
  , LinearDownloadState (..)
  , simulateLinearDownloadRate
  , simulateLinearDownloadRateChurn
  , simulateLinearDownloadRateChurnByIndex
  , linearFillPipeline
  , linearDropReceived
  , simulateLinearReceipt
  , projectStableInflight
  , storeStableInflight
  )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

fullNode, limitedNode :: Word64
fullNode    = combineServices [nodeNetwork, nodeWitness]
limitedNode = combineServices [nodeNetworkLimited, nodeWitness]

mkH :: Word32 -> BlockHash
mkH n = BlockHash (Hash256 (BS.pack (replicate 28 0 ++ bytes)))
  where
    bytes =
      [ fromIntegral (n `div` 16777216)
      , fromIntegral ((n `div` 65536) `mod` 256)
      , fromIntegral ((n `div` 256) `mod` 256)
      , fromIntegral (n `mod` 256)
      ]

neededN :: Word32 -> [(BlockHash, Word32)]
neededN n = [ (mkH h, h) | h <- [1 .. n] ]

sevenFull :: [ForkGetDataPeer]
sevenFull = [ ForkGetDataPeer i fullNode | i <- [0 .. 6] ]

assigned :: Int -> [(Int, [BlockHash])] -> Maybe [BlockHash]
assigned pid plan = lookup pid plan

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "linear-download planner does not pin 128 bodies to one peer" $ do
    it "spreads 128 hashes across 7 NODE_NETWORK peers at 16 each" $ do
      let plan = planLinearGetData sevenFull (neededN 128) 967625 0 Set.empty Map.empty
          counts = map (length . snd) plan
      length plan `shouldSatisfy` (> 1)
      maximum counts `shouldSatisfy` (<= maxBlocksInTransitPerPeer)
      sum counts `shouldBe` 7 * maxBlocksInTransitPerPeer

    it "skips a mute/failed peer instead of giving it the whole window" $ do
      let plan = planLinearGetData sevenFull (neededN 128) 967625 0 (Set.singleton 0) Map.empty
      assigned 0 plan `shouldBe` Nothing
      length plan `shouldSatisfy` (> 0)

    it "does not hand a 57k-deep historical hash to NODE_NETWORK_LIMITED" $ do
      -- Live shape: tip 967625, next-needed 910024. rot=0 would previously
      -- pin the whole window on peer 0, which may be LIMITED.
      let limited = ForkGetDataPeer 0 limitedNode
          full    = ForkGetDataPeer 1 fullNode
          hDeep   = mkH 910024
          plan    = planLinearGetData [limited, full]
                                      [(hDeep, 910024)]
                                      967625
                                      0
                                      Set.empty
                                      Map.empty
      assigned 0 plan `shouldBe` Nothing
      assigned 1 plan `shouldBe` Just [hDeep]

  describe "linear-download first-byte timeout is pipeline-head only" $ do
    it "does not first-byte-timeout siblings queued behind a live head" $ do
      -- adda3c0: head streaming (first-byte at t=1), siblings have no
      -- first-byte at t=17. They are waiting on the same connection.
      let inf =
            [ PipelineInflight 0 1 0 (Just 1)
            , PipelineInflight 0 2 0 Nothing
            , PipelineInflight 0 3 0 Nothing
            , PipelineInflight 0 4 0 Nothing
            ]
          (peers, heights) = mutePipelineHeads 17 inf
      peers `shouldBe` []
      heights `shouldBe` []
      blockFirstByteTimeout `shouldBe` 16

    it "rotates the whole peer pipeline when the head is mute" $ do
      let inf =
            [ PipelineInflight 0 1 0 Nothing
            , PipelineInflight 0 2 0 Nothing
            , PipelineInflight 0 3 0 Nothing
            , PipelineInflight 0 4 0 Nothing
            ]
          (peers, heights) = mutePipelineHeads 17 inf
      peers `shouldBe` [0]
      heights `shouldMatchList` [1, 2, 3, 4]

  describe "linear-download RATE with one mute peer must not stall" $ do
    it "advances the connected tip when 1 of 7 peers is mute" $ do
      -- Peer 0 mute, rot starts at 0 so the OLD planner gives it the
      -- whole 128-hash window. After 40s the OLD tip is the 16s mute
      -- timeout plus one peer's 1-body-per-2-ticks trickle (~12). The
      -- NEW planner fills the other six peers immediately; after the
      -- mute head is reassigned the already-received suffix drains.
      let mute = True : replicate 6 False
          st   = simulateLinearDownloadRate mute 128 40
      ldsTip st `shouldSatisfy` (>= 32)
      Set.member 0 (ldsFailed st) `shouldBe` True

  describe "linear-download re-plan is incremental, not from-scratch" $ do
    -- Rate-verdict 2026-09-19: "does planLinearGetData re-plan from
    -- scratch on every kicker tick, and what is the cost at 128 × 6?"
    -- Answer: no. needed already excludes in-flight; a second plan
    -- with `already` filled does not reshuffle the first window.
    -- 128 × 6 is a few hundred lookups, not the 110% core.
    it "does not reshuffle hashes already in flight on a second plan" $ do
      let plan1 = planLinearGetData sevenFull (neededN 128) 967625 0 Set.empty Map.empty
          used = Map.fromList [(pid, length hs) | (pid, hs) <- plan1]
          assigned = Set.fromList [h | (_, hs) <- plan1, h <- hs]
          leftover = [x | x <- neededN 128, fst x `Set.notMember` assigned]
          plan2 = planLinearGetData sevenFull leftover 967625 0 Set.empty used
          reshuffled =
            Set.fromList [h | (_, hs) <- plan2, h <- hs] `Set.intersection` assigned
      sum (map (length . snd) plan1) `shouldBe` 7 * maxBlocksInTransitPerPeer
      -- 7 peers × 16 = 112 of 128; leftover 16 cannot be placed (all
      -- peers at cap), so the second plan is empty — not a reshuffle.
      plan2 `shouldBe` []
      reshuffled `shouldBe` Set.empty
      Set.size assigned `shouldBe` 112

    it "a 128-hash × 6-peer plan fills at most 16 slots per peer" $ do
      let six = take 6 sevenFull
          plan = planLinearGetData six (neededN 128) 967625 0 Set.empty Map.empty
          counts = map (length . snd) plan
      sum counts `shouldBe` 6 * maxBlocksInTransitPerPeer
      maximum counts `shouldBe` maxBlocksInTransitPerPeer

  describe "linear-download inflight identity survives peer-list prepend" $ do
    -- 2ab99af stored zip [0..] of Map.elems across kicker ticks. A
    -- newly-connected lower address becomes index 0 and reattributes
    -- every in-flight hash. Live 2026-09-19: stall-and-kick, 16-minute
    -- flats, 4.4× slower than 53fe052 on a matched window.
    it "projectStableInflight keeps a hash on the same peer after a prepend" $ do
      let h = mkH 42
          stored = Map.singleton h (20 :: Int, 42, 0)
          keyToId0 = Map.fromList [(10, 0), (20, 1), (30, 2)]
          keyToId1 = Map.fromList [(99, 0), (10, 1), (20, 2), (30, 3)]
          (view0, gone0) = projectStableInflight keyToId0 stored
          (view1, gone1) = projectStableInflight keyToId1 stored
      gone0 `shouldBe` []
      gone1 `shouldBe` []
      Map.lookup h view0 `shouldBe` Just (1, 42, 0)
      Map.lookup h view1 `shouldBe` Just (2, 42, 0)

    it "a dropped peer's in-flight hashes are orphaned for re-request" $ do
      let h = mkH 7
          stored = Map.singleton h (20 :: Int, 7, 0)
          keyToId = Map.fromList [(10, 0), (30, 1)]  -- 20 gone
          (view, gone) = projectStableInflight keyToId stored
      Map.null view `shouldBe` True
      gone `shouldBe` [h]

    it "store then project is identity on a stable peer list" $ do
      let h = mkH 9
          view = Map.singleton h (1, 9, 3)
          idToKey = Map.fromList [(0, 10), (1, 20), (2, 30)] :: Map.Map Int Int
          stored = storeStableInflight idToKey view
          keyToId = Map.fromList [(10, 0), (20, 1), (30, 2)]
          (view', gone) = projectStableInflight keyToId stored
      gone `shouldBe` []
      view' `shouldBe` view

    it "index-stored inflight under prepend is the 2ab99af RATE hole" $ do
      -- Negative control: the instrument must see the stall. If this
      -- ever passes (>= 32) the churn model is not modelling production.
      let mute = replicate 6 False
          st = simulateLinearDownloadRateChurnByIndex mute 128 40
      ldsTip st `shouldSatisfy` (< 32)

    it "stable-key inflight under prepend advances the connected tip" $ do
      let mute = replicate 6 False
          st = simulateLinearDownloadRateChurn mute 128 40
      ldsTip st `shouldSatisfy` (>= 32)

  describe "single-feeder in-flight cap and receipt refill" $ do
    -- Campaign: one --connect replay peer. rustoshi 57df6634 /
    -- receipts/feeder-cap-ab-rustoshi-2026-09-11.md. Live haskoin
    -- 2026-09-20 bottom-chain 6299→12650: cap 16, kicker-only refill,
    -- 96 blk/min vs nimrod 3,260 / beamchain 2,590 on the same feeder.
    it "single --connect defaults the per-peer cap to 128" $ do
      resolveBlocksInFlightPerPeer 1 Nothing
        `shouldBe` singleConnectBlocksInFlightPerPeer
      resolveBlocksInFlightPerPeer 0 Nothing
        `shouldBe` maxBlocksInTransitPerPeer
      resolveBlocksInFlightPerPeer 2 Nothing
        `shouldBe` maxBlocksInTransitPerPeer
      resolveBlocksInFlightPerPeer 1 (Just "16") `shouldBe` 16
      resolveBlocksInFlightPerPeer 1 (Just "64") `shouldBe` 64
      resolveBlocksInFlightPerPeer 1 (Just "999")
        `shouldBe` singleConnectBlocksInFlightPerPeer
      resolveBlocksInFlightPerPeer 1 (Just "nope")
        `shouldBe` singleConnectBlocksInFlightPerPeer
      singleConnectBlocksInFlightPerPeer `shouldBe` maxBlocksInFlightTotal

    it "a 128-cap on one peer fills 128 hashes, not 16" $ do
      let one = [ForkGetDataPeer 0 fullNode]
          plan = planLinearGetDataWithCap 128 one (neededN 128) 967625 0 Set.empty Map.empty
          counts = map (length . snd) plan
      sum counts `shouldBe` 128
      maximum counts `shouldBe` 128

    it "dropping a received height without refill is the kicker-only hole" $ do
      -- Negative control: MBlock used to only advance nextBlockRef.
      -- Inflight goes 16 → 15 until the 0.4s kicker poll. If this ever
      -- passes (length == 16) the drop helper is refilling and the
      -- instrument is not seeing the hole.
      let filled = linearFillPipeline maxBlocksInTransitPerPeer 32
          dropped = linearDropReceived 1 filled
      length (ldsInflight filled) `shouldBe` maxBlocksInTransitPerPeer
      length (ldsInflight dropped) `shouldBe` maxBlocksInTransitPerPeer - 1
      ldsTip dropped `shouldBe` 1

    it "a received block refills in-flight without a kicker tick" $ do
      -- rustoshi received_block_refills_in_flight_without_a_tick:
      -- after one body arrives, inflight is still at cap. The caller
      -- does not invoke the kicker poll.
      let st = simulateLinearReceipt maxBlocksInTransitPerPeer 32
      length (ldsInflight st) `shouldBe` maxBlocksInTransitPerPeer
      ldsTip st `shouldBe` 1
      Set.member 1 (ldsHaveBody st) `shouldBe` True

    it "MBlock success path refills the pipeline (not kicker-only)" $ do
      -- Production wiring: the MBlock Right () arm must call
      -- fillLinearPipeline so a local feeder does not wait for the
      -- 0.4s poll (live: 19 kicker lines / 274 UpdateTips).
      src <- readFile "app/Main.hs"
      let afterTip =
            dropWhile (not . ("formatUpdateTip" `isInfixOf`)) (lines src)
      unlines (take 40 afterTip)
        `shouldSatisfy` ("fillLinearPipeline" `isInfixOf`)

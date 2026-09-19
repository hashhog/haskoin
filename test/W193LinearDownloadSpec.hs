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
  , maxBlocksInTransitPerPeer
  , PipelineInflight (..)
  , blockFirstByteTimeout
  , mutePipelineHeads
  , LinearDownloadState (..)
  , simulateLinearDownloadRate
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

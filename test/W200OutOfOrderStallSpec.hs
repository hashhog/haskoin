{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Out-of-order AcceptBlock + next-needed stall reassignment.
--
-- Live 2026-09-24 after e2c8e70 (height 911872 -> 911876, 10 peers):
--
--   (1) Every unconnected arrival was reason=validation
--       err=Core full-block validation: Missing UTXO, and every one
--       was AHEAD of next-needed (911889/911905/… vs 911874). Those
--       bodies spend outputs created by the intermediate blocks, so
--       ConnectBlock against the current UTXO must fail. Core's
--       ProcessNewBlock runs CheckBlock + AcceptBlock (store) for
--       every body and ConnectBlock only from ActivateBestChain when
--       the parent is the tip. Discriminator: after that failure, is
--       the hash marked invalid? If yes the stall is permanent. This
--       spec pins stored=yes invalid=no, and the live path must not
--       call validateFullBlockIO (skipConnectChecks=False) on a body
--       ahead of next-needed, nor insert hcInvalidated.
--
--   (2) 6 of 8 next-needed fates were already-inflight, all to one
--       address (71.191.251.202:8333). Sends were fine
--       (25 connected-at-send=yes send=ok). The peer answers later
--       heights (first-byte stamps, mutePipelineHeads never fires)
--       and never the head. Core BLOCK_STALLING_TIMEOUT (2s)
--       disconnects that staller and reassigns. haskoin's 16s
--       first-byte mute does not.
--
-- Control: cabal run haskoin-test --enable-tests -- -m out-of-order
--
-- Not a deploy. Do not restart.
module W200OutOfOrderStallSpec (spec) where

import Data.List (isInfixOf, isPrefixOf)
import Data.Word (Word32)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Test.Hspec

import Haskoin.Consensus
  ( ChainState (..)
  , UnconnectedReason (..)
  , classifyConnectReject
  , computeMerkleRoot
  , consensusFlagsAtHeight
  , encodeBip34Height
  , formatOutOfOrderStored
  , formatUnconnectedArrival
  , regtest
  , unconnectedReasonTag
  , validateFullBlock
  )
import Haskoin.Crypto (computeTxId)
import Haskoin.Network
  ( LinearDownloadState (..)
  , PipelineInflight (..)
  , blockStallingTimeout
  , mutePipelineHeads
  , neededLinearHashes
  , simulateStallingNextNeeded
  , stallingNextNeeded
  )
import Haskoin.Storage (Coin (..))
import Haskoin.Types
  ( Block (..)
  , BlockHash (..)
  , BlockHeader (..)
  , Hash256 (..)
  , OutPoint (..)
  , Tx (..)
  , TxId (..)
  , TxIn (..)
  , TxOut (..)
  )

flat :: String -> String
flat = unwords . words

mainHs :: IO String
mainHs = readFile "app/Main.hs"

bindingBody :: String -> String -> String -> String
bindingBody src equation nextName =
  let dropped = dropWhile (not . (equation `isInfixOf`)) (lines src)
      body = takeWhile (not . (nextName `isInfixOf`)) dropped
   in unlines body

mkH :: Word32 -> BlockHash
mkH n = BlockHash (Hash256 (BS.pack (replicate 28 0 ++ bytes)))
  where
    bytes =
      [ fromIntegral (n `div` 16777216)
      , fromIntegral ((n `div` 65536) `mod` 256)
      , fromIntegral ((n `div` 256) `mod` 256)
      , fromIntegral (n `mod` 256)
      ]

-- | A non-coinbase spend of an outpoint that is NOT in the UTXO map.
-- skipConnectChecks=False (ConnectBlock) must Missing-UTXO;
-- skipConnectChecks=True (AcceptBlock) must not.
aheadSpendBlock :: (Block, ChainState)
aheadSpendBlock =
  let missingOp = OutPoint (TxId (Hash256 (BS.replicate 32 0xcc))) 0
      nullOp = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
      cbIn = TxIn nullOp (encodeBip34Height 2 <> BS.singleton 0x00) 0xffffffff
      coinbase = Tx 1 [cbIn] [TxOut 2500000000 "cbout"] [[]] 0
      spendIn = TxIn missingOp BS.empty 0xffffffff
      spendTx = Tx 1 [spendIn] [TxOut 100000000 "spendout"] [[]] 0
      merkle = computeMerkleRoot [computeTxId coinbase, computeTxId spendTx]
      parent = BlockHash (Hash256 (BS.replicate 32 0xab))
      header = BlockHeader 4 parent merkle 1700000100 0x207fffff 0
      block = Block header [coinbase, spendTx]
      cs = ChainState 1 parent 0 0 (consensusFlagsAtHeight regtest 2)
   in (block, cs)

spec :: Spec
spec = describe "out-of-order" $ do
  describe "out-of-order-accept: store without ConnectBlock" $ do
    it "awaiting-parent is a distinct reason, not validation" $ do
      unconnectedReasonTag UnconnAwaitingParent `shouldBe` "awaiting-parent"
      unconnectedReasonTag UnconnValidation `shouldBe` "validation"
      UnconnAwaitingParent `shouldNotBe` UnconnValidation
      classifyConnectReject
        "Core full-block validation: Missing UTXO: OutPoint {outPointHash = 00, outPointIndex = 0}"
        `shouldBe` UnconnValidation

    it "stored=yes invalid=no on an ahead body (the 911889 discriminator)" $ do
      let line = formatOutOfOrderStored (Just 911889) 911874 7
      ("Block arrived unconnected:" `isPrefixOf` line) `shouldBe` True
      line `shouldSatisfy` ("height=911889" `isInfixOf`)
      line `shouldSatisfy` ("next-needed=911874" `isInfixOf`)
      line `shouldSatisfy` ("reason=awaiting-parent" `isInfixOf`)
      line `shouldSatisfy` ("count=7" `isInfixOf`)
      line `shouldSatisfy` ("stored=yes" `isInfixOf`)
      line `shouldSatisfy` ("invalid=no" `isInfixOf`)
      line `shouldSatisfy` (not . ("reason=validation" `isInfixOf`))
      -- Prefix matches the existing unconnected grep.
      let base = formatUnconnectedArrival (Just 911889) 911874 UnconnAwaitingParent 7
      (base `isPrefixOf` line) `shouldBe` True

    it "AcceptBlock (skipConnectChecks) does not Missing-UTXO an ahead spend" $ do
      let (block, cs) = aheadSpendBlock
          empty = Map.empty :: Map.Map OutPoint Coin
      case validateFullBlock regtest cs (const 0) False False block empty of
        Left err -> err `shouldSatisfy` ("Missing UTXO" `isInfixOf`)
        Right () ->
          expectationFailure
            "ConnectBlock against the current set must fail Missing UTXO \
            \(the live 911889 shape); got accept"
      case validateFullBlock regtest cs (const 0) False True block empty of
        Right () -> return ()
        Left err ->
          whenMissing err $
            expectationFailure $
              "AcceptBlock must not run UTXO checks: " ++ err

    it "MBlock stores an ahead body and does not mark it invalid" $ do
      src <- mainHs
      let afterMBlock =
            dropWhile (not . ("MBlock block ->" `isInfixOf`)) (lines src)
          untilMTx = takeWhile (not . ("MTx tx ->" `isInfixOf`)) afterMBlock
          body = unlines untilMTx
          afterAhead =
            dropWhile (not . ("height > nextNeededNow" `isInfixOf`)) untilMTx
          -- The else of `if height > nextNeededNow` is the connect path.
          aheadArm = unlines (takeWhile (not . ("else do" `isInfixOf`)) afterAhead)
      body `shouldSatisfy` ("height > nextNeededNow" `isInfixOf`)
      body `shouldSatisfy` ("formatOutOfOrderStored" `isInfixOf`)
      aheadArm `shouldSatisfy` ("True block Map.empty" `isInfixOf`)
      -- validateFullBlockIO hardcodes skipConnectChecks=False (ConnectBlock).
      aheadArm `shouldSatisfy` (not . ("validateFullBlockIO" `isInfixOf`))
      aheadArm `shouldSatisfy` (not . ("hcInvalidated" `isInfixOf`))
      aheadArm `shouldSatisfy` (not . ("tryP2PReorg" `isInfixOf`))
      aheadArm `shouldSatisfy` ("putBlock db bh block" `isInfixOf`)

    it "neededLinearHashes skips a height whose body is already stored" $ do
      -- After AcceptBlock, the hash must not occupy an inflight slot
      -- and must not be re-getdata'd (Core BLOCK_HAVE_DATA).
      let heightMap =
            Map.fromList [(h, mkH h) | h <- [911874 .. 911876] :: [Word32]]
          have = Set.singleton (911889 :: Word32)
          have2 = Set.singleton (911874 :: Word32)
          inflight = Map.empty :: Map.Map BlockHash ()
          allThree =
            neededLinearHashes 911874 911876 heightMap inflight Set.empty
          skipHead =
            neededLinearHashes 911874 911876 heightMap inflight have2
          skipMissing =
            neededLinearHashes 911874 911876 heightMap inflight have
      map snd allThree `shouldBe` [911874, 911875, 911876]
      map snd skipHead `shouldBe` [911875, 911876]
      map snd skipMissing `shouldBe` [911874, 911875, 911876]

  describe "out-of-order-stall: reassign a mute-looking next-needed" $ do
    it "stalling timeout is Core BLOCK_STALLING_TIMEOUT_DEFAULT (2s)" $ do
      blockStallingTimeout `shouldBe` 2

    it "first-byte stamped does not excuse a next-needed that never arrives" $ do
      -- Live shape: peer sends 911889 (ahead) so first-byte is stamped;
      -- mutePipelineHeads sees a live head; next-needed 911874 stays
      -- already-inflight forever.
      let inf =
            [ PipelineInflight 2 911874 0 (Just 1)
            , PipelineInflight 2 911889 0 (Just 1)
            ]
      mutePipelineHeads 3 inf `shouldBe` ([], [])
      stallingNextNeeded 1 911874 inf `shouldBe` ([], [])
      let (pids, heights) = stallingNextNeeded 3 911874 inf
      pids `shouldBe` [2]
      heights `shouldMatchList` [911874, 911889]

    it "a peer that skips next-needed is rotated so another peer can take it" $ do
      -- Two peers, 16 each. Peer 0 is assigned 1..16 and delivers only
      -- heights > next-needed (stamping first-byte). Without
      -- stallingNextNeeded the tip stays 0. With it, peer 0 is failed
      -- at t=2 and peer 1 takes the head.
      let st = simulateStallingNextNeeded 40 128
      ldsTip st `shouldSatisfy` (>= 1)
      Set.member 0 (ldsFailed st) `shouldBe` True

    it "kicker unions stallingNextNeeded with mute and requestBlockRange skips stored bodies" $ do
      src <- mainHs
      let fill = bindingBody src "fillLinearPipeline pm hc db" "P2P fork-aware"
          req = bindingBody src "requestBlockRange pm hc fromHeight" "fillLinearPipeline"
          srcFlat = flat src
      srcFlat `shouldSatisfy` ("stallingNextNeeded" `isInfixOf`)
      srcFlat `shouldSatisfy` ("stalling-next-needed" `isInfixOf`)
      flat req `shouldSatisfy` ("neededLinearHashes" `isInfixOf`)
      srcFlat `shouldSatisfy`
        ("requestBlockRange pm' hc refillFrom windowEnd rot failed2 infAfterMute nowKick perPeerCap branch nextBlock haveBody" `isInfixOf`)
      srcFlat `shouldSatisfy`
        ("requestBlockRange pm hc nextBlock windowEnd rot failed0 infPruned nowKick cap FillReceipt nextBlock haveBody" `isInfixOf`)
      flat fill `shouldSatisfy` ("haveBodyRef" `isInfixOf`)
      -- A failed send still records inflight (e2c8e70 instrumentation).
      flat req `shouldSatisfy` ("Map.union added" `isInfixOf`)

whenMissing :: String -> Expectation -> Expectation
whenMissing err act
  | "Missing UTXO" `isInfixOf` err
      || "missingorspent" `isInfixOf` err
      || "missing" `isInfixOf` err = act
  | otherwise = return ()

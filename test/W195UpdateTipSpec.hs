{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | UpdateTip connect log. Live 2026-09-19: every distinct message
-- prefix across 3,079 lines of a run that WAS connecting blocks was
-- either `Block-gap kicker` or `Periodic WAL fsync at height=`. The
-- MBlock success path logged `Connected block at height` only when
-- height%500==0, with no hash, no connect ms, no tx/input counts.
-- Grep for `Received block` / `Connected` returned 0 and that zero
-- was published as evidence.
--
-- Control: cabal run haskoin-test --enable-tests -- -m 'UpdateTip'
--
-- Reference: bitcoin-core/src/validation.cpp UpdateTipLog
--   "UpdateTip: new best=%s height=%d ... tx=%lu ..."
module W195UpdateTipSpec (spec) where

import Test.Hspec
import Data.List (isInfixOf, isPrefixOf)
import qualified Data.ByteString as BS

import Haskoin.Types
  ( Block (..), BlockHash (..), BlockHeader (..), Hash256 (..),
    OutPoint (..), Tx (..), TxId (..), TxIn (..), TxOut (..),
  )
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
  ( blockHashToHex
  , blockInputCount
  , formatUpdateTip
  , genesisBlock
  , hashFromHex
  , shouldLogUpdateTip
  , updateTipBulkInterval
  )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

genesisHashHex :: String
genesisHashHex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

mkIn :: Int -> TxIn
mkIn n =
  TxIn
    { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) (fromIntegral n)
    , txInScript = BS.empty
    , txInSequence = 0xffffffff
    }

mkTx :: Int -> Tx
mkTx nIn =
  Tx
    { txVersion = 1
    , txInputs = map mkIn [1 .. nIn]
    , txOutputs = [TxOut 50 BS.empty]
    , txWitness = []
    , txLockTime = 0
    }

mkBlock :: [Int] -> Block
mkBlock nIns =
  Block
    { blockHeader =
        BlockHeader
          { bhVersion = 1
          , bhPrevBlock = BlockHash (Hash256 (BS.replicate 32 0))
          , bhMerkleRoot = Hash256 (BS.replicate 32 0)
          , bhTimestamp = 1231006505
          , bhBits = 0x1d00ffff
          , bhNonce = 0
          }
    , blockTxns = map mkTx nIns
    }

mainHs, syncHs :: IO String
mainHs = readFile "app/Main.hs"
syncHs = readFile "src/Haskoin/Sync.hs"

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "UpdateTip line format (height, hash, connect ms, tx, inputs)" $ do
    it "starts with UpdateTip: and carries every required field" $ do
      let bh = hashFromHex genesisHashHex
          line = formatUpdateTip 910121 bh 345 2500 8900
      ("UpdateTip: " `isPrefixOf` line) `shouldBe` True
      (("new best=" ++ genesisHashHex) `isInfixOf` line) `shouldBe` True
      ("height=910121" `isInfixOf` line) `shouldBe` True
      ("connect=345ms" `isInfixOf` line) `shouldBe` True
      ("tx=2500" `isInfixOf` line) `shouldBe` True
      ("inputs=8900" `isInfixOf` line) `shouldBe` True

    it "renders the hash in Core display order (byte-reversed hex)" $ do
      blockHashToHex (hashFromHex genesisHashHex) `shouldBe` genesisHashHex
      -- genesisBlock's header hash must round-trip through the same hex
      -- the operator pastes into an explorer.
      let gh = computeBlockHash (blockHeader genesisBlock)
      blockHashToHex gh `shouldBe` genesisHashHex
      length (blockHashToHex gh) `shouldBe` 64

    it "counts every vin including coinbase" $ do
      -- 1-in coinbase + 2-in + 3-in = 6
      blockInputCount (mkBlock [1, 2, 3]) `shouldBe` 6
      blockInputCount genesisBlock `shouldBe` 1

  describe "UpdateTip cadence: every block at the tip, every N during bulk IBD" $ do
    it "logs every connected block once headers are complete (not IBD)" $ do
      -- Live shape: Header sync complete, then catch-up at 910k.
      -- 910121 % 500 != 0 so the old log was silent.
      shouldLogUpdateTip False 910121 967631 `shouldBe` True
      shouldLogUpdateTip False 1 967631 `shouldBe` True
      shouldLogUpdateTip False 910000 967631 `shouldBe` True

    it "logs every block that has caught the header tip, even in IBD" $ do
      shouldLogUpdateTip True 967631 967631 `shouldBe` True
      shouldLogUpdateTip True 50 50 `shouldBe` True

    it "during bulk IBD logs only every updateTipBulkInterval heights" $ do
      updateTipBulkInterval `shouldBe` 100
      shouldLogUpdateTip True 0 967631 `shouldBe` True
      shouldLogUpdateTip True 100 967631 `shouldBe` True
      shouldLogUpdateTip True 200 967631 `shouldBe` True
      shouldLogUpdateTip True 910121 967631 `shouldBe` False
      shouldLogUpdateTip True 910123 967631 `shouldBe` False
      shouldLogUpdateTip True 99 967631 `shouldBe` False

  describe "UpdateTip is wired into the live connect paths" $ do
    it "Main.hs MBlock success path calls formatUpdateTip, not height%500" $ do
      src <- mainHs
      ("formatUpdateTip" `isInfixOf` src) `shouldBe` True
      ("shouldLogUpdateTip" `isInfixOf` src) `shouldBe` True
      -- The defect: only every 500th height, and only the height number.
      let oldGate = "when (height `mod` 500 == 0)"
          oldLine = "Connected block at height"
      (oldGate `isInfixOf` src) `shouldBe` False
      (oldLine `isInfixOf` src) `shouldBe` False

    it "Sync.hs blockProcessor calls formatUpdateTip, not height%1000" $ do
      src <- syncHs
      ("formatUpdateTip" `isInfixOf` src) `shouldBe` True
      ("when (nextHeight `mod` 1000 == 0)" `isInfixOf` src) `shouldBe` False
      ("Connected block " `isInfixOf` src) `shouldBe` False

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | A consensus-invalid block delivered over P2P (2026-10-03 instrument
-- tools/p2p-invalid-block-feed.py, scenarios "before" / "after").
--
-- OBSERVED pre-fix (a4b9866, badcb, 20-block post-IBD prefix):
--   before: the invalid B1 (h+1) stayed the best header ('active' in
--     getchaintips), was requested 14x, and the valid B1' at the same
--     height was never fetched.
--   after:  B1' was the tip; X sent B1 + B2x (heavier, invalid ancestor).
--     The fork reorg disconnected B1', failed to connect B1 and LEFT THE
--     CHAINSTATE AT THE FORK POINT (height h); B2x stayed 'valid-headers'.
--
-- Core (validation.cpp): InvalidBlockFound marks the block
-- BLOCK_FAILED_VALID (descendants BLOCK_FAILED_CHILD), RecalculateBestHeader
-- moves the best header off it, and ActivateBestChain returns to the
-- most-work VALID chain after a failed step.  BLOCK_MUTATED and other
-- non-verdicts are never marked.
module InvalidBlockP2PSpec (spec) where

import Test.Hspec
import Control.Monad (foldM)
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar, readTVarIO)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , connectBlockAt
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  , BlockRejectKind(..)
  , classifyBlockReject
  , invalidBlockFound
  , performReorgActivating
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB, getBestBlockHash, putBlock, newUTXOCache )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-invalid-p2p-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

-- | Coinbase paying @value@ (regtest subsidy below 150 is 50 BTC).
coinbaseTx :: Word32 -> Word8 -> Word64 -> Tx
coinbaseTx h tag value = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn nullOutPoint (encodeBip34Height h `BS.snoc` tag) 0xffffffff ]
  , txOutputs  = [ TxOut value opTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

subsidy :: Word64
subsidy = 5000000000

mkBlock :: BlockHash -> Word32 -> [Tx] -> Block
mkBlock prevHash ts txns = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff
      , bhNonce      = 0
      }
  , blockTxns = txns
  }

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> BlockStatus -> ChainEntry
mkEntry blk h prevHash work seqId st = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = computeBlockHash (blockHeader blk)
  , ceHeight     = h
  , ceChainWork  = work
  , cePrev       = Just prevHash
  , ceStatus     = st
  , ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = seqId
  }

insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

-- | A header learned from a peer (addHeader shape: entries only).
insertHeader :: HeaderChain -> ChainEntry -> IO ()
insertHeader hc ce = atomically $
  modifyTVar' (hcEntries hc) (Map.insert (ceHash ce) ce)

-- | addHeader's tip move for a strictly heavier header.
setBestHeader :: HeaderChain -> ChainEntry -> IO ()
setBestHeader hc ce = atomically $ do
  modifyTVar' (hcByHeight hc) (Map.insert (ceHeight ce) (ceHash ce))
  writeTVar (hcTip hc) ce
  writeTVar (hcHeight hc) (ceHeight ce)

baseTime :: Word32
baseTime = 1296688700

prefixHeight :: Word32
prefixHeight = 20

-- | Genesis + 1..20 connected on disk and in the header chain.
-- Returns (hc, prefix tip hash, prefix tip work).
setupPrefix :: S.HaskoinDB -> IO (HeaderChain, BlockHash, Integer)
setupPrefix db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
  hc <- initHeaderChain net
  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()
  let step (prevHash, work) h = do
        let blk   = mkBlock prevHash (baseTime + h) [coinbaseTx h 0x01 subsidy]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' (fromIntegral h) StatusValid
        r <- connectBlockAt db net blk h Map.empty
        r `shouldBe` Right ()
        insertActiveTip hc ce
        return (ceHash ce, work')
  (tipHash, tipWork) <-
    foldM step (gHash, headerWork (blockHeader genesis)) [1 .. prefixHeight]
  return (hc, tipHash, tipWork)

statusOf :: HeaderChain -> BlockHash -> IO (Maybe BlockStatus)
statusOf hc h = fmap ceStatus . Map.lookup h <$> readTVarIO (hcEntries hc)

tipHashOf :: HeaderChain -> IO BlockHash
tipHashOf hc = ceHash <$> readTVarIO (hcTip hc)

-- | The "after" shape: B1' (valid) connected at 21; B1 (sibling at 21,
-- @b1Txns@) and B2x (22, on B1) on disk; header tip B2x (heavier).
data After = After
  { afHc :: HeaderChain, afPrefix :: BlockHash
  , afB1v :: BlockHash, afB1 :: BlockHash, afB2x :: BlockHash }

setupAfter :: [Tx] -> S.HaskoinDB -> IO After
setupAfter b1Extra db = do
  (hc, pHash, pWork) <- setupPrefix db
  let h1 = prefixHeight + 1
      b1v   = mkBlock pHash (baseTime + 100) [coinbaseTx h1 0x0a subsidy]
      b1vCe = mkEntry b1v h1 pHash (pWork + headerWork (blockHeader b1v)) 1001 StatusHeaderValid
  rV <- connectBlockAt db regtest b1v h1 Map.empty
  rV `shouldBe` Right ()
  insertActiveTip hc b1vCe
  let b1    = mkBlock pHash (baseTime + 101)
                (coinbaseTx h1 0x0b (if null b1Extra then subsidy + 1 else subsidy) : b1Extra)
      b1Ce  = mkEntry b1 h1 pHash (pWork + headerWork (blockHeader b1)) 1002 StatusHeaderValid
      b2x   = mkBlock (ceHash b1Ce) (baseTime + 102) [coinbaseTx (h1 + 1) 0x0c subsidy]
      b2xCe = mkEntry b2x (h1 + 1) (ceHash b1Ce)
                (ceChainWork b1Ce + headerWork (blockHeader b2x)) 1003 StatusHeaderValid
  putBlock db (ceHash b1Ce) b1
  putBlock db (ceHash b2xCe) b2x
  insertHeader hc b1Ce
  insertHeader hc b2xCe
  setBestHeader hc b2xCe
  return After { afHc = hc, afPrefix = pHash, afB1v = ceHash b1vCe
               , afB1 = ceHash b1Ce, afB2x = ceHash b2xCe }

runActivating :: S.HaskoinDB -> After -> IO (Either String ())
runActivating db af = do
  cache <- newUTXOCache db 100000
  performReorgActivating regtest cache db (afHc af) Nothing (afB1v af) (afB2x af)

spec :: Spec
spec = describe "invalid block over P2P (Core InvalidBlockFound / ActivateBestChain)" $ do

  it "after: failed reorg onto an invalid branch marks it and RECONNECTS the valid tip" $
    withTestDB "after" $ \db -> do
      af  <- setupAfter [] db                      -- B1 overpays its coinbase
      res <- runActivating db af
      res `shouldSatisfy` either (const True) (const False)
      -- Pre-fix: the chainstate stayed at the fork point (height 20).
      getBestBlockHash db `shouldReturn` Just (afB1v af)
      statusOf (afHc af) (afB1 af)  `shouldReturn` Just StatusFailedValid
      statusOf (afHc af) (afB2x af) `shouldReturn` Just StatusFailedChild
      -- Best header is back on the valid chain; the invalid branch is off
      -- the height index, so nothing re-requests it.
      tipHashOf (afHc af) `shouldReturn` afB1v af
      bh <- readTVarIO (hcByHeight (afHc af))
      Map.lookup (prefixHeight + 1) bh `shouldBe` Just (afB1v af)
      Map.lookup (prefixHeight + 2) bh `shouldBe` Nothing

  it "before: a verdict on the best-header block moves the best header to the valid sibling" $
    withTestDB "before" $ \db -> do
      (hc, pHash, pWork) <- setupPrefix db
      let h1 = prefixHeight + 1
          b1    = mkBlock pHash (baseTime + 101) [coinbaseTx h1 0x0b (subsidy + 1)]
          b1Ce  = mkEntry b1 h1 pHash (pWork + headerWork (blockHeader b1)) 2001 StatusHeaderValid
          b2x   = mkBlock (ceHash b1Ce) (baseTime + 102) [coinbaseTx (h1 + 1) 0x0c subsidy]
          b2xCe = mkEntry b2x (h1 + 1) (ceHash b1Ce)
                    (ceChainWork b1Ce + headerWork (blockHeader b2x)) 2002 StatusHeaderValid
          b1v   = mkBlock pHash (baseTime + 100) [coinbaseTx h1 0x0a subsidy]
          b1vCe = mkEntry b1v h1 pHash (pWork + headerWork (blockHeader b1v)) 2003 StatusHeaderValid
      -- X announced B1 then B2x first; H's equal-work B1' arrived later.
      insertHeader hc b1Ce
      setBestHeader hc b1Ce
      insertHeader hc b2xCe
      setBestHeader hc b2xCe
      insertHeader hc b1vCe
      marked <- invalidBlockFound db hc (ceHash b1Ce)
      marked `shouldBe` True
      statusOf hc (ceHash b1Ce)  `shouldReturn` Just StatusFailedValid
      statusOf hc (ceHash b2xCe) `shouldReturn` Just StatusFailedChild
      -- Core RecalculateBestHeader: B1' is now the best header (it gets
      -- fetched); pre-fix the best header stayed on the invalid branch.
      tipHashOf hc `shouldReturn` ceHash b1vCe
      bh <- readTVarIO (hcByHeight hc)
      Map.lookup h1 bh `shouldBe` Just (ceHash b1vCe)
      Map.lookup (h1 + 1) bh `shouldBe` Nothing
      getBestBlockHash db `shouldReturn` Just pHash

  it "never marks a block on the connected chain" $
    withTestDB "connected" $ \db -> do
      (hc, pHash, _) <- setupPrefix db
      invalidBlockFound db hc pHash `shouldReturn` False
      statusOf hc pHash `shouldReturn` Just StatusValid

  describe "non-verdicts stay unmarked" $ do
    it "classifies mutated / missing-input / internal rejects as non-verdicts" $ do
      let nonVerdicts =
            [ "Merkle root mismatch", "bad-txns-duplicate"
            , "bad-witness-merkle-match", "bad-witness-nonce-size"
            , "unexpected-witness"
            , "Missing UTXO: OutPoint {..}", "bad-txns-inputs-missingorspent"
            , "exception: user error", "Core full-block validation: exception: x"
            , "connectBlockAt X: block's prevHash ... (Core G1 — validation.cpp:2333)"
            , "Missing block data for reorg: X", "Undo data error for X: y"
            , "some new error nobody classified" ]
      mapM_ (\e -> (e, classifyBlockReject e) `shouldBe` (e, BlockRejectNonVerdict))
            nonVerdicts
      let verdicts =
            [ "Coinbase value exceeds allowed amount", "bad-txns-nonfinal"
            , "bad-cb-height", "bad-blk-sigops", "bad-txns-inputs-duplicate"
            , "script verify failed (input 0): script returned false"
            , "Core full-block validation: Coinbase value exceeds allowed amount" ]
      mapM_ (\e -> (e, classifyBlockReject e) `shouldBe` (e, BlockRejectVerdict))
            verdicts

    it "a reorg connect failing on a missing input does not mark the block and restores the old tip" $
      withTestDB "missing" $ \db -> do
        let ghost = OutPoint (TxId (Hash256 (BS.replicate 32 0x77))) 0
            spend = Tx 1 [TxIn ghost BS.empty 0xffffffff] [TxOut 1000 opTrue] [[]] 0
        af  <- setupAfter [spend] db
        res <- runActivating db af
        res `shouldSatisfy` either (const True) (const False)
        statusOf (afHc af) (afB1 af)  `shouldReturn` Just StatusHeaderValid
        statusOf (afHc af) (afB2x af) `shouldReturn` Just StatusHeaderValid
        -- Chainstate back on the tip it had; the (unmarked) heavier header
        -- stays the best header so the caller's backoff retries it.
        getBestBlockHash db `shouldReturn` Just (afB1v af)
        tipHashOf (afHc af) `shouldReturn` afB2x af

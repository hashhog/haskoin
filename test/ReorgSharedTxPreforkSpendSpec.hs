{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Reorg connect must see a pre-fork coin that BOTH branches spend,
-- even when the shared tx also spends an INTRA-BLOCK prevout first.
--
-- == The bug (P0, mainnet 2026-09-17, height 966500) ==
--
-- Live 1-block stale race: haskoin connected the losing 966500
-- (@000000000000000000011ada…@) and then tried to reorg onto Core's
-- 966500 (@000000000000000000002b9b…@).  Both blocks contain tx
-- @b587dffb…@, which spends pre-fork coin @f8ee1cc1…:0@ at vin 2, with
-- vin 0, 1, 3 spending outputs of @fe8694d7…@ created EARLIER IN THE
-- SAME BLOCK (tx index 967/841, immediately before the spender).
--
-- The live connect path writes undo from @spentUtxos@ built against the
-- PRE-BLOCK UTXO set, so intra-block prevouts are omitted
-- (@mapMaybe mkTxInUndo@).  Disconnect then positionally @zip@s
-- @txInputs@ with the shorter @tuPrevOutputs@:
--
-- @
--   vin = [intra, intra, f8ee1cc1:0, intra]
--   undo = [Coin of f8ee1cc1:0]          -- the one external input
--   zip  = [(vin0, that coin)]           -- vin2 is silently dropped
-- @
--
-- The pre-fork coin is never restored into the reorg overlay.
-- @reorgLookup@ therefore returns Nothing, @spentUtxos0@ omits it, and
-- @validateFullBlock@ aborts the first connect block with
-- @"Missing UTXO: OutPoint <f8ee1cc1> 0"@ — the live log line.  The
-- receipt's spent-before-added hypothesis does not fire here: the coin
-- is not in @roSpent@ at all; it is simply absent from @roAdded@.
--
-- == Why no existing test caught it ==
--
--   * W165ReorgAtomicSpec builds coinbase-only blocks (empty prevouts).
--   * ReorgIntraBlockChainSpec's LOSING branch is coinbase-only, so the
--     disconnect zip never runs over a mixed-input tx.
--   * ReorgSharedTxRecreatedCoinSpec's shared tx has a SINGLE pre-fork
--     input — zip length matches, so the pre-fork coin is restored.
--
-- == What this suite pins ==
--
--   * C1 (CONTROL) — both branches share a tx that spends ONLY a
--     pre-fork coin (no intra-block vin).  Passes pre- and post-fix.
--   * C2 — the same tx spends an intra-block output FIRST, then a
--     pre-fork coin (mainnet 966500 vin shape).  FAILS pre-fix with
--     @"Missing UTXO"@ of the pre-fork outpoint; PASSES post-fix.
--   * C3 — post-reorg chainstate: winning tip, pre-fork coins spent,
--     intra-block output spent, shared tx's output unspent.
--
-- References:
--   bitcoin-core/src/validation.cpp:2228-2236
--     DisconnectBlock requires vprevout.size() == vin.size() and
--     indexes undo by vin position (Core writes one CTxInUndo per vin,
--     including intra-block spends).
--   receipts/haskoin-reorg-missing-utxo-966500-2026-09-17.md
module ReorgSharedTxPreforkSpendSpec (spec) where

import Test.Hspec
import Control.Monad (foldM)
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar)
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
  , performReorg
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  , reorgValidationBackoffSecs
  , reorgShouldRetry
  )
import Data.Time.Clock.POSIX (POSIXTime)
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , getUTXO
  , putBlock
  , newUTXOCache
  , Coin(..)
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- Helpers (same idioms as ReorgSharedTxRecreatedCoinSpec)
--------------------------------------------------------------------------------

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-reorg-prefork-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

coinbaseTxAt :: Word32 -> Word8 -> Tx
coinbaseTxAt h tag = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = nullOutPoint
      , txInScript     = encodeBip34Height h `BS.snoc` tag
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

commonCoinbaseCoin :: Word32 -> Coin
commonCoinbaseCoin h = Coin
  { coinTxOut      = head (txOutputs (coinbaseTxAt h 0x01))
  , coinHeight     = h
  , coinIsCoinbase = True
  }

-- | Spend one OP_TRUE output, re-paying the whole 50 BTC (fee 0).
spendTx :: OutPoint -> Tx
spendTx op = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = op
      , txInScript     = BS.empty
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Two-input spend: vin0 then vin1, re-paying 100 BTC (fee 0).  This is
-- the mainnet shape — an intra-block prevout FIRST, a pre-fork prevout
-- SECOND — that makes a positional zip of the short (external-only) undo
-- restore the undo coin onto vin0 and drop vin1.
spendTwo :: OutPoint -> OutPoint -> Tx
spendTwo op0 op1 = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = op0
      , txInScript     = BS.empty
      , txInSequence   = 0xffffffff
      }
    , TxIn
      { txInPrevOutput = op1
      , txInScript     = BS.empty
      , txInSequence   = 0xffffffff
      }
    ]
  , txOutputs  = [ TxOut { txOutValue = 10000000000, txOutScript = opTrue } ]
  , txWitness  = [[], []]
  , txLockTime = 0
  }

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

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> ChainEntry
mkEntry blk h prevHash work seqId = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = computeBlockHash (blockHeader blk)
  , ceHeight     = h
  , ceChainWork  = work
  , cePrev       = Just prevHash
  , ceStatus     = StatusValid
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

insertSideEntry :: HeaderChain -> ChainEntry -> IO ()
insertSideEntry hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

baseTime :: Word32
baseTime = 1296688700

-- | Last common block.  Contest height is 102, so the height-1 AND
-- height-2 coinbases are both mature (regtest COINBASE_MATURITY = 100).
forkHeight :: Word32
forkHeight = 101

data Fork = Fork
  { fkHc       :: HeaderChain
  , fkLosing   :: BlockHash
  , fkWinning  :: BlockHash
  , fkMature1  :: OutPoint
  , fkMature2  :: OutPoint
  , fkTxA      :: Maybe Tx     -- ^ intra-block creator; Nothing in C1
  , fkTxS      :: Tx           -- ^ the SHARED spend (in both L and W1)
  , fkTxSOut   :: OutPoint
  }

-- | @intraThenPrefork@:
--
--   * False (C1) — L and W1 = [cb, txS], txS spends only the height-1
--     coinbase.  Positional undo zip is 1:1.  Passes pre- and post-fix.
--   * True  (C2) — L and W1 = [cb, txA, txS], txA spends height-1,
--     txS vin0 = txA:0 (intra-block), vin1 = height-2 (pre-fork).
--     Live connect writes one undo entry for txS; zip binds it to vin0
--     and the pre-fork coin is never restored.
setupFork :: Bool -> S.HaskoinDB -> IO Fork
setupFork intraThenPrefork db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)

  hc <- initHeaderChain net

  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()

  let step (prevHash, work) h = do
        let blk   = mkBlock prevHash (baseTime + h) [coinbaseTxAt h 0x01]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' (fromIntegral h)
        r <- connectBlockAt db net blk h Map.empty
        r `shouldBe` Right ()
        insertActiveTip hc ce
        return (ceHash ce, work')
  (forkHash, forkWork) <- foldM step (gHash, gWork) [1 .. forkHeight]

  let mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
      mature2 = OutPoint (computeTxId (coinbaseTxAt 2 0x01)) 0
      txA     = spendTx mature1
      txAOut  = OutPoint (computeTxId txA) 0
      txS     = if intraThenPrefork
                  then spendTwo txAOut mature2
                  else spendTx mature1
      txSOut  = OutPoint (computeTxId txS) 0
      lTxns   = if intraThenPrefork
                  then [coinbaseTxAt 102 0x0a, txA, txS]
                  else [coinbaseTxAt 102 0x0a, txS]
      wTxns   = if intraThenPrefork
                  then [coinbaseTxAt 102 0x0b, txA, txS]
                  else [coinbaseTxAt 102 0x0b, txS]
      -- Live path: spentUtxos is the pre-block UTXO set.  Intra-block
      -- prevouts (txA:0) are NOT in this map — G19 accepts them via
      -- blockCreated, and mkTxInUndo mapMaybe-omits them from undo.
      lSpent  = if intraThenPrefork
                  then Map.fromList
                         [ (mature1, commonCoinbaseCoin 1)
                         , (mature2, commonCoinbaseCoin 2)
                         ]
                  else Map.singleton mature1 (commonCoinbaseCoin 1)

  let lBlk  = mkBlock forkHash (baseTime + forkHeight + 1) lTxns
      lWork = forkWork + headerWork (blockHeader lBlk)
      lCe   = mkEntry lBlk 102 forkHash lWork 1001
  rL <- connectBlockAt db net lBlk 102 lSpent
  rL `shouldBe` Right ()
  insertActiveTip hc lCe

  let w1Blk  = mkBlock forkHash (baseTime + 300) wTxns
      w1Work = forkWork + headerWork (blockHeader w1Blk)
      w1Ce   = mkEntry w1Blk 102 forkHash w1Work 2001
      w1Hash = ceHash w1Ce
      w2Blk  = mkBlock w1Hash (baseTime + 301) [coinbaseTxAt 103 0x0c]
      w2Work = w1Work + headerWork (blockHeader w2Blk)
      w2Ce   = mkEntry w2Blk 103 w1Hash w2Work 2002
      w2Hash = ceHash w2Ce

  putBlock db w1Hash w1Blk
  putBlock db w2Hash w2Blk
  insertSideEntry hc w1Ce
  insertSideEntry hc w2Ce

  (w1Hash /= ceHash lCe) `shouldBe` True
  (txS `elem` blockTxns lBlk && txS `elem` blockTxns w1Blk) `shouldBe` True
  (w2Work > lWork) `shouldBe` True

  return Fork
    { fkHc      = hc
    , fkLosing  = ceHash lCe
    , fkWinning = w2Hash
    , fkMature1 = mature1
    , fkMature2 = mature2
    , fkTxA     = if intraThenPrefork then Just txA else Nothing
    , fkTxS     = txS
    , fkTxSOut  = txSOut
    }

runReorg :: S.HaskoinDB -> Fork -> IO (Either String ())
runReorg db fk = do
  cache <- newUTXOCache db 100000
  performReorg regtest cache db (fkHc fk) Nothing (fkLosing fk) (fkWinning fk)

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "reorg shared-tx intra-then-prefork" $ do

    it "C1 (CONTROL): shared tx spends only a pre-fork coin" $ do
      -- Both branches carry the same single-input spend of the height-1
      -- coinbase.  Undo has one entry per input, zip aligns, the overlay
      -- restore is visible.  Passes pre- AND post-fix — scaffolding check.
      withTestDB "control" $ \db -> do
        fk  <- setupFork False db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "CONTROL reorg (shared pre-fork-only spend) aborted: " ++ err
        getBestBlockHash db `shouldReturn` Just (fkWinning fk)
        getUTXO db (fkMature1 fk) `shouldReturn` Nothing
        mTxS <- getUTXO db (fkTxSOut fk)
        fmap txOutScript mTxS `shouldBe` Just opTrue

    it "C2: shared tx spends intra-block THEN a pre-fork coin" $ do
      -- THE REGRESSION.  Matches mainnet 966500 tx b587dffb: vin0 is
      -- created earlier in the same block, vin1 is a coin created before
      -- the fork.  Live-path undo records only vin1's coin; positional
      -- zip restores it onto vin0; connect looks up the pre-fork coin
      -- and reports Missing UTXO.  Post-fix the disconnect pairs undo
      -- with the EXTERNAL inputs (or writes complete undo) so the
      -- pre-fork coin is visible to reorgLookup.
      withTestDB "intra-then-prefork" $ \db -> do
        fk  <- setupFork True db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "reorg aborted on a shared tx that spends a pre-fork coin after an intra-block vin: " ++ err

    it "C3: the post-reorg on-disk chainstate is correct" $ do
      withTestDB "chainstate" $ \db -> do
        fk  <- setupFork True db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $ "reorg aborted: " ++ err

        getBestBlockHash db `shouldReturn` Just (fkWinning fk)
        -- Both pre-fork coinbases consumed (txA spends h1, txS spends h2).
        getUTXO db (fkMature1 fk) `shouldReturn` Nothing
        getUTXO db (fkMature2 fk) `shouldReturn` Nothing
        -- Intra-block output consumed by txS vin0.
        txA <- case fkTxA fk of
          Just t  -> return t
          Nothing -> fail "setupFork True must carry txA"
        getUTXO db (OutPoint (computeTxId txA) 0) `shouldReturn` Nothing
        -- Shared spend's output survives on the winning branch.
        mTxS <- getUTXO db (fkTxSOut fk)
        fmap txOutScript mTxS `shouldBe` Just opTrue
        -- Losing coinbase is gone; winning coinbases remain.
        getUTXO db (OutPoint (computeTxId (coinbaseTxAt 102 0x0a)) 0)
          `shouldReturn` Nothing
        mW1 <- getUTXO db (OutPoint (computeTxId (coinbaseTxAt 102 0x0b)) 0)
        fmap txOutScript mW1 `shouldBe` Just opTrue
        mW2 <- getUTXO db (OutPoint (computeTxId (coinbaseTxAt 103 0x0c)) 0)
        fmap txOutScript mW2 `shouldBe` Just opTrue

    it "backoff: 15s, 30s, 60s, 120s, cap 300s" $ do
      map reorgValidationBackoffSecs [0, 1, 2, 3, 4, 5, 6, 99]
        `shouldBe` [0, 15, 30, 60, 120, 300, 300, 300]

    it "backoff: same tip waits, different tip retries immediately" $ do
      let a  = BlockHash (Hash256 (BS.replicate 32 0x01))
          b  = BlockHash (Hash256 (BS.replicate 32 0x02))
          c  = BlockHash (Hash256 (BS.replicate 32 0x03))
          t0 = 1000 :: POSIXTime
          st = Just (a, b, 1, t0)
      reorgShouldRetry a b (t0 + 1)  st      `shouldBe` False
      reorgShouldRetry a b (t0 + 15) st      `shouldBe` True
      reorgShouldRetry a c (t0 + 1)  st      `shouldBe` True
      reorgShouldRetry a b 0         Nothing `shouldBe` True

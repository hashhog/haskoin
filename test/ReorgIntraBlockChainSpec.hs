{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Reorg connect path must tolerate INTRA-BLOCK transaction chains.
--
-- == The bug (P0, mainnet 2026-08-24, height 963853) ==
--
-- 'Haskoin.Consensus.reorgConBuild' — the connect arm of the atomic reorg
-- core — resolved every non-coinbase prevout of each block it was about to
-- connect through @overlay -> cache -> disk@ and HARD-FAILED the whole reorg
-- the moment one could not be found:
--
-- @
--   Nothing -> return $ Left $ "Reorg connect: missing prevout " ++ show op ...
-- @
--
-- But a transaction may legally spend an output created by an EARLIER
-- transaction in the SAME block.  Bitcoin's only ordering rule is that the
-- creating transaction precede the spending one; such an outpoint has never
-- been in the persistent UTXO set (and never will be, if it is also spent in
-- that block), so it is legitimately absent from overlay, cache AND disk.
--
-- The LIVE (straight-line) connect path never had this problem: its
-- @spentUtxos@ builders — 'Haskoin.Storage.buildSpentUtxoMapFromDB'
-- (Storage.hs:569) and 'Haskoin.Storage.buildSpentUtxoMapCached'
-- (Storage.hs:784) — SILENTLY OMIT unresolvable inputs ("The caller is the
-- place that decides whether that's a fatal error"), because
-- 'Haskoin.Consensus.validateBlockTransactions' is already intra-block-aware
-- (Consensus.hs:3671, "updating UTXO map for intra-block spending") and
-- resolves the chained prevout itself.  'connectBlockAt' likewise accepts
-- block-created outpoints at its G19 gate (the W163 fix).  Only the reorg
-- arm still hard-failed.
--
-- Consequence: on 2026-08-24 haskoin lost a routine 1-block race at mainnet
-- height 963853 and every reorg attempt aborted on the FIRST intra-block
-- chain — 15,681 identical failures over ~7 hours, unrecoverable, because
-- the condition is structural (that block has 6,084 chained inputs), not
-- transient.
--
-- == Why no existing test caught it ==
--
-- Every regtest reorg spec (notably "W165ReorgAtomicSpec") builds
-- COINBASE-ONLY blocks.  A coinbase has no real prevouts, so @prevouts@ is
-- empty and the failing fold ran ZERO times.  This suite therefore builds a
-- winning branch whose block carries a real chained pair:
--
--   * @txA@ spends a MATURE coinbase output (created at height 1, spent at
--     height 101 — regtest COINBASE_MATURITY is 100);
--   * @txB@ spends @txA@'s output — the intra-block chain.
--
-- == What this suite pins ==
--
--   * A1 (CONTROL) — a competing block with a NON-chained spend reorgs in.
--     This passes both pre- and post-fix; it proves the harness (merkle
--     roots, BIP-34 coinbase height, maturity, subsidy, OP_TRUE scripts,
--     undo records) is sound, so a failure in A2/A3 can only be the chain.
--   * A2 — the SAME scenario plus @txB@ (the intra-block chain) must reorg
--     in.  FAILS pre-fix with "Reorg connect: missing prevout"; PASSES
--     post-fix.
--   * A3 — after that reorg the on-disk chainstate is correct: best-block
--     names the winning tip, the spent coins are gone and only the last
--     link of the chain survives in the UTXO set.
--
-- References:
--   bitcoin-core/src/validation.cpp  ConnectBlock / UpdateCoins (intra-block
--                                    spends resolve from the in-flight view)
--   src/Haskoin/Storage.hs:569,784   buildSpentUtxoMap* (omit, do not fail)
--   src/Haskoin/Consensus.hs:3671    validateBlockTransactions intra-block fold
module ReorgIntraBlockChainSpec (spec) where

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
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , getUTXO
  , putBlock
  , newUTXOCache
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

-- ============================================================
-- Helpers
-- ============================================================

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-reorg-intrablock-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

-- | OP_TRUE.  Spendable with an EMPTY scriptSig under every consensus
-- script flag regtest turns on at height 101 (P2SH | DERSIG | CLTV | CSV |
-- WITNESS | NULLDUMMY | TAPROOT — none of which is CLEANSTACK), so the
-- test needs no signing.  Same script "W165ReorgAtomicSpec" uses.
opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

-- | Null outpoint (the coinbase input marker).
nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

-- | Coinbase for @h@, paying the full regtest subsidy to OP_TRUE.
--
-- The scriptSig is @encodeBip34Height h@ followed by a one-byte @tag@:
--
--   * the BIP-34 PREFIX is what 'validateCoinbaseHeightConsensus' checks
--     (Consensus.hs:~3222, "bad-cb-height"), and it is enforced on regtest
--     from height 1 (@netBIP34Height regtest == 1@);
--   * the tag makes the two COMPETING height-101 coinbases (losing branch
--     vs winning branch) distinct transactions, so their txids — and hence
--     their merkle roots and created outpoints — differ;
--   * height 1..16 encodes to a single byte, so the tag also keeps the
--     scriptSig at the 2-byte minimum Core's "bad-cb-length" gate demands.
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

-- | A transaction spending exactly one OP_TRUE output and re-paying the
-- whole amount to OP_TRUE (fee 0, so the winning block's coinbase may claim
-- the bare subsidy and still satisfy the "bad-cb-amount" gate).
--
-- Version 1 + nSequence 0xffffffff: BIP-68 is disabled for this input under
-- both the version gate and SEQUENCE_LOCKTIME_DISABLE_FLAG, and nLockTime 0
-- is final at any height, so neither lock-time arm of 'validateFullBlock'
-- can interfere with what this suite is measuring.
spendTx :: OutPoint -> Tx
spendTx op = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = op
      , txInScript     = BS.empty      -- OP_TRUE needs no scriptSig
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Assemble a block with a CORRECT merkle root — 'validateFullBlock' step 3
-- (Consensus.hs:~3201, "Merkle root mismatch") is on the reorg-connect path,
-- unlike 'connectBlockAt', which does not check it.
--
-- bhBits is the regtest powLimit; PoW itself is not verified by the reorg
-- connect path, but 'headerWork' needs a sane compact target.
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
    -- Synthetic MTP: the timestamps below increase by 1 per height, so
    -- stamping MTP = own timestamp keeps the "timestamp not after median
    -- time past" gate (validateFullBlock step 6) satisfied for every block
    -- the reorg connects.
  , ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = seqId
  }

-- | Insert a connected entry and make it the active tip.
insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

-- | Insert a SIDE-BRANCH entry: known to the header chain (so
-- 'findForkPoint' and the reorg list builders can walk it) but NOT the
-- active tip and NOT in the active height index.
insertSideEntry :: HeaderChain -> ChainEntry -> IO ()
insertSideEntry hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

-- | Base timestamp; comfortably above the regtest genesis timestamp.
baseTime :: Word32
baseTime = 1296688700

-- | Height of the last COMMON block (the fork point).  101 = forkHeight + 1
-- is the first contested height, and regtest COINBASE_MATURITY is 100, so a
-- coinbase created at height 1 is spendable exactly at height 101.
forkHeight :: Word32
forkHeight = 100

-- | Everything a reorg scenario needs.
data Fork = Fork
  { fkHc       :: HeaderChain
  , fkLosing   :: BlockHash    -- ^ active tip before the reorg (height 101)
  , fkWinning  :: BlockHash    -- ^ new tip to reorg onto (height 102)
  , fkTxA      :: Tx           -- ^ spends the mature height-1 coinbase
  , fkTxB      :: Maybe Tx     -- ^ spends txA (the intra-block chain)
  , fkMatureOp :: OutPoint     -- ^ the height-1 coinbase output txA spends
  }

-- | Build the whole scenario on a fresh DB.
--
--   genesis .. 100      common, coinbase-only, CONNECTED (live path)
--        \-- 101 L      losing branch, coinbase-only, CONNECTED + active tip
--        \-- 101 W      winning branch, body on disk only (side branch)
--            102 W2     winning branch tip, body on disk only
--
-- @chained@ decides whether W carries just @txA@ (control) or @txA@ + @txB@
-- (the regression).  The winning branch is one block LONGER than the losing
-- one, so — regtest difficulty being fixed — it carries strictly more
-- cumulative work, which is what makes it the branch a real node would
-- adopt.
setupFork :: Bool -> S.HaskoinDB -> IO Fork
setupFork chained db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)

  hc <- initHeaderChain net

  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()

  -- --- common chain, heights 1..100 -------------------------------------
  let step (prevHash, work) h = do
        let blk  = mkBlock prevHash (baseTime + h) [coinbaseTxAt h 0x01]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' (fromIntegral h)
        r <- connectBlockAt db net blk h Map.empty
        r `shouldBe` Right ()
        insertActiveTip hc ce
        return (ceHash ce, work')
  (forkHash, forkWork) <- foldM step (gHash, gWork) [1 .. forkHeight]

  -- The height-1 coinbase is now exactly COINBASE_MATURITY (100) blocks
  -- deep at height 101, so spending it there is legal.
  let matureOp = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0

  -- --- losing branch: L @ 101 (coinbase only), connected + active tip ---
  let lBlk  = mkBlock forkHash (baseTime + forkHeight + 1) [coinbaseTxAt 101 0x0a]
      lWork = forkWork + headerWork (blockHeader lBlk)
      lCe   = mkEntry lBlk 101 forkHash lWork 1001
  rL <- connectBlockAt db net lBlk 101 Map.empty
  rL `shouldBe` Right ()
  insertActiveTip hc lCe

  -- --- winning branch: W @ 101 (with the spends), W2 @ 102 --------------
  let txA   = spendTx matureOp
      txB   = spendTx (OutPoint (computeTxId txA) 0)
      wTxns = [coinbaseTxAt 101 0x0b, txA] ++ [ txB | chained ]
      wBlk  = mkBlock forkHash (baseTime + 200) wTxns
      wWork = forkWork + headerWork (blockHeader wBlk)
      wCe   = mkEntry wBlk 101 forkHash wWork 2001
      wHash = ceHash wCe
      w2Blk = mkBlock wHash (baseTime + 201) [coinbaseTxAt 102 0x0c]
      w2Work = wWork + headerWork (blockHeader w2Blk)
      w2Ce  = mkEntry w2Blk 102 wHash w2Work 2002
      w2Hash = ceHash w2Ce

  -- The reorg list builders read side-branch BODIES from disk
  -- ('buildReorgConnectList' -> 'getBlock'), so store them — but do NOT
  -- connect them: they are a side branch until the reorg adopts them.
  putBlock db wHash  wBlk
  putBlock db w2Hash w2Blk
  insertSideEntry hc wCe
  insertSideEntry hc w2Ce

  -- Sanity: the winning branch really does out-work the losing one.
  (w2Work > lWork) `shouldBe` True

  return Fork
    { fkHc       = hc
    , fkLosing   = ceHash lCe
    , fkWinning  = w2Hash
    , fkTxA      = txA
    , fkTxB      = if chained then Just txB else Nothing
    , fkMatureOp = matureOp
    }

-- | Drive the reorg through the exported 'performReorg' (the same entry
-- point the tip-activation kicker and @invalidateblock@'s sibling path use),
-- surfacing the abort reason verbatim on failure.
runReorg :: S.HaskoinDB -> Fork -> IO (Either String ())
runReorg db fk = do
  cache <- newUTXOCache db 100000
  performReorg regtest cache db (fkHc fk) Nothing (fkLosing fk) (fkWinning fk)

-- ============================================================
-- Spec
-- ============================================================

spec :: Spec
spec = do
  describe "reorg connect path vs intra-block transaction chains" $ do

    it "A1 (CONTROL): reorgs onto a branch whose block has a NON-chained spend" $ do
      -- No intra-block chain: every prevout resolves from disk, so this
      -- passes BOTH pre- and post-fix.  Its job is to prove the scaffolding
      -- (merkle root, BIP-34 coinbase height, coinbase maturity, subsidy,
      -- OP_TRUE script verification, undo records, side-branch bodies) is
      -- sound — so an A2 failure can only be the intra-block chain.
      withTestDB "control" $ \db -> do
        fk  <- setupFork False db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "CONTROL reorg (no intra-block chain) aborted: " ++ err
        getBestBlockHash db `shouldReturn` Just (fkWinning fk)

    it "A2: reorgs onto a branch whose block contains an INTRA-BLOCK chain" $ do
      -- THE REGRESSION.  W now also carries txB, which spends txA's output
      -- in the same block.  That outpoint is in neither the overlay, the
      -- cache nor on disk — legitimately so.  Pre-fix 'reorgConBuild'
      -- hard-fails here with "Reorg connect: missing prevout"; post-fix it
      -- omits the unresolvable prevout (exactly as the live connect path's
      -- buildSpentUtxoMap* do) and 'validateBlockTransactions' resolves the
      -- chain itself.
      withTestDB "chained" $ \db -> do
        fk  <- setupFork True db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "reorg aborted on a LEGAL intra-block transaction chain: " ++ err

    it "A3: the post-reorg on-disk chainstate is correct" $ do
      -- The reorg must not merely succeed: the winning tip must be the
      -- on-disk best block, and the UTXO set must reflect the chain of
      -- spends — the mature coinbase and txA's output both consumed, only
      -- txB's output (the last link) left unspent.
      withTestDB "chainstate" $ \db -> do
        fk  <- setupFork True db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $ "reorg aborted: " ++ err

        getBestBlockHash db `shouldReturn` Just (fkWinning fk)

        let txA = fkTxA fk
        txB <- case fkTxB fk of
          Just t  -> return t
          Nothing -> fail "setupFork True must carry the chained tx"
        -- Spent: the mature height-1 coinbase (by txA) ...
        getUTXO db (fkMatureOp fk) `shouldReturn` Nothing
        -- ... and txA's output (by txB, intra-block).
        getUTXO db (OutPoint (computeTxId txA) 0) `shouldReturn` Nothing
        -- Unspent: the tail of the chain.
        mTxB <- getUTXO db (OutPoint (computeTxId txB) 0)
        fmap txOutScript mTxB `shouldBe` Just opTrue

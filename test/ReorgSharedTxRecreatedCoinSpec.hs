{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | The reorg connect side must REVIVE a coin the disconnect side
-- tombstoned, when the connected branch re-creates it.
--
-- == The bug (P0, mainnet 2026-08-24, height 963853/963854) ==
--
-- The atomic reorg core threads a virtual UTXO overlay
-- ('Haskoin.Consensus.ReorgOverlay') through the pure batch build:
--
--   * 'reorgDisBuildPure' (the DISCONNECT arm) restores each disconnected
--     block's spent prevouts into @roAdded@ and marks every coin that block
--     CREATED into @roSpent@ — right, because those coins cease to exist;
--   * 'reorgConBuild' (the CONNECT arm) then adds the coins the connected
--     blocks create into @roAdded@;
--   * 'reorgLookup' tests @roSpent@ BEFORE @roAdded@.
--
-- Pre-fix the connect arm never REMOVED a tombstone for an outpoint it
-- re-created, so a coin the disconnect had marked dead stayed invisible no
-- matter what the connect side added.  The disconnect arm already had the
-- mirror of this rule ("a restored prevout shadows any prior overlay-spent
-- mark"); the connect arm simply lacked it.
--
-- == Why it fires in reality: COMPETING BLOCKS SHARE TRANSACTIONS ==
--
-- Both branches of a routine 1-block race are built from the same mempool,
-- so the branch being disconnected routinely created the very coins the
-- branch being connected re-creates.  Observed on mainnet 2026-08-24: tx
-- @80b0673e2a5e386958277dded1afaf8af3dc3d655c040ec2a6c063b64cab8f8f@ sits at
-- index 2 of BOTH haskoin's stale 963853 AND Core's 963853.  The disconnect
-- tombstoned its vout 3, the connect re-created it, and block 963854 — which
-- spends it — failed @"Missing UTXO"@, aborting the reorg.
--
-- == Why no existing test caught it ==
--
--   * "W165ReorgAtomicSpec" builds COINBASE-ONLY blocks: the disconnected
--     block creates only its own coinbase output, which no connected block
--     ever re-creates or spends.
--   * "ReorgIntraBlockChainSpec" pins a DIFFERENT defect (the connect arm
--     hard-failing on intra-block transaction chains).  Its losing branch is
--     coinbase-only, so nothing is tombstoned, and its winning branch is a
--     SINGLE contested block, so no connected block ever spends a coin an
--     earlier connected block re-created.  It passes either way on this one.
--
-- Reaching this defect needs BOTH properties at once, which is what this
-- suite adds:
--
--   1. the losing block and a winning block share a transaction (byte
--      identical, hence the same txid, hence the same created outpoints), and
--   2. a LATER winning block spends the coin that shared transaction creates
--      — so the tombstone is actually consulted.
--
-- == What this suite pins ==
--
--   * B1 (CONTROL) — identical setup, except @W2@ spends a different,
--     PRE-EXISTING on-disk coin (the height-2 coinbase) that no branch
--     re-creates.  Differs from B2 by exactly one field ('fkW2Spends').
--     Passes BOTH pre- and post-fix, so it proves the scaffolding (merkle
--     roots, BIP-34 coinbase heights, maturity, subsidy, OP_TRUE scripts,
--     undo records, two-block connect list) is sound — a B2 failure can then
--     only be the tombstone.
--   * B2 — @W2@ spends @txA:0@, the coin the DISCONNECTED block L also
--     created.  FAILS pre-fix with @"Missing UTXO: OutPoint <txA> 0"@;
--     PASSES post-fix.
--   * B3 — the post-reorg on-disk chainstate is correct: best block is @W2@,
--     @txA:0@ is consumed, and the height-1 coinbase is consumed.
--
-- References:
--   bitcoin-core/src/validation.cpp  ConnectBlock / DisconnectBlock (Core
--                                    rebuilds the view from the fork point,
--                                    so a re-created coin is simply present)
--   src/Haskoin/Consensus.hs         reorgLookup / reorgDisBuildPure /
--                                    reorgConBuild ('prevoutSet' / @ov''@)
module ReorgSharedTxRecreatedCoinSpec (spec) where

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
  , Coin(..)
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

-- ============================================================
-- Helpers  (same idioms as "ReorgIntraBlockChainSpec")
-- ============================================================

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-reorg-sharedtx-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

-- | OP_TRUE.  Spendable with an EMPTY scriptSig under every consensus script
-- flag regtest turns on at heights 101/102, so the test needs no signing.
opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

-- | Null outpoint (the coinbase input marker).
nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

-- | Coinbase for @h@, paying the full regtest subsidy to OP_TRUE.  The
-- scriptSig is @encodeBip34Height h@ plus a one-byte @tag@ that makes
-- competing coinbases at the same height distinct transactions (and keeps
-- the scriptSig at the 2-byte "bad-cb-length" minimum).
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

-- | The 'Coin' the common chain's height-@h@ coinbase created.  Fed to
-- 'connectBlockAt' as the @spentUtxos@ map so the losing block's UNDO record
-- carries a full Core-format prevout — without it 'buildDisconnectBlockOps'
-- refuses the disconnect on its TxUndo/tx count-equality gate and the reorg
-- would never reach the code under test.
commonCoinbaseCoin :: Word32 -> Coin
commonCoinbaseCoin h = Coin
  { coinTxOut      = head (txOutputs (coinbaseTxAt h 0x01))
  , coinHeight     = h
  , coinIsCoinbase = True
  }

-- | Spend exactly one OP_TRUE output, re-paying the whole amount to OP_TRUE
-- (fee 0, so each block's coinbase may claim the bare subsidy).  Version 1 +
-- nSequence 0xffffffff + nLockTime 0 keeps BIP-68 and BIP-113 out of the way.
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

-- | Assemble a block with a CORRECT merkle root — 'validateFullBlock' checks
-- it on the reorg-connect path (unlike 'connectBlockAt').
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
    -- Synthetic MTP: timestamps increase monotonically below, so stamping
    -- MTP = own timestamp satisfies the "timestamp not after median time
    -- past" gate for every block the reorg connects.
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

-- | Insert a SIDE-BRANCH entry: known to the header chain (so 'findForkPoint'
-- and the reorg list builders can walk it) but NOT the active tip and NOT in
-- the active height index.
insertSideEntry :: HeaderChain -> ChainEntry -> IO ()
insertSideEntry hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

-- | Base timestamp; comfortably above the regtest genesis timestamp.
baseTime :: Word32
baseTime = 1296688700

-- | Height of the last COMMON block (the fork point).  Regtest
-- COINBASE_MATURITY is 100, so the height-1 coinbase is spendable exactly at
-- height 101 and the height-2 coinbase exactly at height 102.
forkHeight :: Word32
forkHeight = 100

-- | Everything a reorg scenario needs.
data Fork = Fork
  { fkHc        :: HeaderChain
  , fkLosing    :: BlockHash   -- ^ active tip before the reorg (L @ 101)
  , fkWinning   :: BlockHash   -- ^ new tip to reorg onto (W2 @ 102)
  , fkTxA       :: Tx          -- ^ the SHARED tx: in BOTH L and W1
  , fkTxAOut    :: OutPoint    -- ^ txA:0 — created by L, re-created by W1
  , fkMature1   :: OutPoint    -- ^ height-1 coinbase output (txA spends it)
  , fkMature2   :: OutPoint    -- ^ height-2 coinbase output
  , fkW2Spends  :: OutPoint    -- ^ THE ONE FIELD B1 and B2 differ in
  , fkTxC       :: Tx          -- ^ W2's spend of 'fkW2Spends'
  }

-- | Build the whole scenario on a fresh DB.
--
-- @
--   genesis .. 100        common, coinbase-only, CONNECTED (live path)
--        \\-- 101 L        losing branch  [cbL,  txA]   CONNECTED + active tip
--        \\-- 101 W1       winning branch [cbW1, txA]   body on disk only
--            102 W2       winning branch [cbW2, txC]   body on disk only
-- @
--
-- @txA@ is byte-identical in L and W1 — the same transaction, therefore the
-- same txid and the same created outpoint @txA:0@.  That is the crux: the
-- disconnect of L tombstones @txA:0@ and the connect of W1 re-creates it.
--
-- @shareRecreatedCoin@ picks what W2's @txC@ spends:
--
--   * 'True'  (B2/B3)     — @txA:0@, the re-created coin: the regression.
--   * 'False' (B1 CONTROL) — the height-2 coinbase, a pre-existing on-disk
--     coin no branch re-creates, so no tombstone is ever consulted.
--
-- Everything else is identical between the two, including L and W1 both
-- carrying @txA@.
--
-- The winning branch is one block LONGER, so — regtest difficulty being
-- fixed — it carries strictly more cumulative work.
setupFork :: Bool -> S.HaskoinDB -> IO Fork
setupFork shareRecreatedCoin db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)

  hc <- initHeaderChain net

  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()

  -- --- common chain, heights 1..100 -------------------------------------
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

  -- --- the SHARED transaction ------------------------------------------
  let txA    = spendTx mature1
      txAOut = OutPoint (computeTxId txA) 0

  -- --- losing branch: L @ 101 = [cbL, txA], connected + active tip ------
  -- The spentUtxos map is what puts a real prevout into L's UNDO record, so
  -- the reorg's disconnect arm can restore the height-1 coinbase (and,
  -- crucially for this suite, tombstone txA:0 as a coin L created).
  let lBlk  = mkBlock forkHash (baseTime + forkHeight + 1)
                      [coinbaseTxAt 101 0x0a, txA]
      lWork = forkWork + headerWork (blockHeader lBlk)
      lCe   = mkEntry lBlk 101 forkHash lWork 1001
  rL <- connectBlockAt db net lBlk 101 (Map.singleton mature1 (commonCoinbaseCoin 1))
  rL `shouldBe` Right ()
  insertActiveTip hc lCe

  -- --- winning branch: W1 @ 101 = [cbW1, txA], W2 @ 102 = [cbW2, txC] ---
  let w2Spends = if shareRecreatedCoin then txAOut else mature2
      txC      = spendTx w2Spends
      w1Blk    = mkBlock forkHash (baseTime + 200) [coinbaseTxAt 101 0x0b, txA]
      w1Work   = forkWork + headerWork (blockHeader w1Blk)
      w1Ce     = mkEntry w1Blk 101 forkHash w1Work 2001
      w1Hash   = ceHash w1Ce
      w2Blk    = mkBlock w1Hash (baseTime + 201) [coinbaseTxAt 102 0x0c, txC]
      w2Work   = w1Work + headerWork (blockHeader w2Blk)
      w2Ce     = mkEntry w2Blk 102 w1Hash w2Work 2002
      w2Hash   = ceHash w2Ce

  -- The reorg list builders read side-branch BODIES from disk
  -- ('buildReorgConnectList' -> 'getBlock'), so store them — but do NOT
  -- connect them: they are a side branch until the reorg adopts them.
  putBlock db w1Hash w1Blk
  putBlock db w2Hash w2Blk
  insertSideEntry hc w1Ce
  insertSideEntry hc w2Ce

  -- Sanity: L and W1 really are DIFFERENT blocks that share txA.
  (w1Hash /= ceHash lCe) `shouldBe` True
  (txA `elem` blockTxns lBlk && txA `elem` blockTxns w1Blk) `shouldBe` True
  -- Sanity: the winning branch really does out-work the losing one.
  (w2Work > lWork) `shouldBe` True

  return Fork
    { fkHc       = hc
    , fkLosing   = ceHash lCe
    , fkWinning  = w2Hash
    , fkTxA      = txA
    , fkTxAOut   = txAOut
    , fkMature1  = mature1
    , fkMature2  = mature2
    , fkW2Spends = w2Spends
    , fkTxC      = txC
    }

-- | Drive the reorg through the exported 'performReorg' (the same entry point
-- the tip-activation kicker and @invalidateblock@'s sibling path use),
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
  describe "reorg connect must revive a coin the disconnect tombstoned" $ do

    it "B1 (CONTROL): W2 spends a pre-existing coin no branch re-creates" $ do
      -- Identical to B2 except that txC spends the height-2 coinbase (a coin
      -- that only ever lived on disk) instead of txA:0.  Nothing the connect
      -- side re-creates is ever looked up, so the disconnect tombstone is
      -- never consulted: this passes BOTH pre- and post-fix.  Its job is to
      -- prove the scaffolding is sound, so a B2 failure can only be the
      -- tombstone.
      withTestDB "control" $ \db -> do
        fk <- setupFork False db
        fkW2Spends fk `shouldBe` fkMature2 fk   -- the one differing field
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "CONTROL reorg (W2 spends a never-tombstoned coin) aborted: " ++ err
        getBestBlockHash db `shouldReturn` Just (fkWinning fk)
        -- Consumed: the height-1 coinbase (by txA, inside W1) and the
        -- height-2 coinbase (by txC, inside W2).
        getUTXO db (fkMature1 fk) `shouldReturn` Nothing
        getUTXO db (fkMature2 fk) `shouldReturn` Nothing
        -- Unspent: txA:0, re-created by W1 and spent by nobody.
        mTxA <- getUTXO db (fkTxAOut fk)
        fmap txOutScript mTxA `shouldBe` Just opTrue

    it "B2: W2 spends the coin the DISCONNECTED block also created" $ do
      -- THE REGRESSION.  L (being disconnected) and W1 (being connected)
      -- share txA, so the disconnect tombstones txA:0 in 'roSpent' and the
      -- connect re-creates it in 'roAdded'.  'reorgLookup' tests 'roSpent'
      -- first, so pre-fix W2's prevout resolves to Nothing, is omitted from
      -- spentUtxos, and 'validateFullBlock' rejects W2 with
      -- "Missing UTXO: OutPoint <txA> 0" — exactly the mainnet 963854 abort.
      -- Post-fix, reorgConBuild's ov'' clears the tombstone for every coin
      -- the block creates and does not itself spend, so the lookup succeeds.
      withTestDB "shared" $ \db -> do
        fk <- setupFork True db
        fkW2Spends fk `shouldBe` fkTxAOut fk    -- the one differing field
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "reorg aborted on a coin the connected branch re-creates: " ++ err

    it "B3: the post-reorg on-disk chainstate is correct" $ do
      -- The reorg must not merely succeed: the winning tip must be the
      -- on-disk best block, and the UTXO set must reflect the whole chain of
      -- spends across the two connected blocks.
      withTestDB "chainstate" $ \db -> do
        fk  <- setupFork True db
        res <- runReorg db fk
        case res of
          Right () -> return ()
          Left err -> expectationFailure $ "reorg aborted: " ++ err

        -- The contested coin, derived from the SHARED transaction itself.
        let txAOut = OutPoint (computeTxId (fkTxA fk)) 0
        txAOut `shouldBe` fkTxAOut fk

        -- Best block is W2, the winning branch's tip.
        getBestBlockHash db `shouldReturn` Just (fkWinning fk)
        -- Consumed: the height-1 coinbase (by txA, re-created inside W1) ...
        getUTXO db (fkMature1 fk) `shouldReturn` Nothing
        -- ... and txA:0 itself (by txC, inside W2).
        getUTXO db txAOut `shouldReturn` Nothing
        -- Untouched: the height-2 coinbase, which only the CONTROL spends.
        mM2 <- getUTXO db (fkMature2 fk)
        fmap txOutScript mM2 `shouldBe` Just opTrue
        -- Unspent: the tail of the chain, txC's output.
        mTxC <- getUTXO db (OutPoint (computeTxId (fkTxC fk)) 0)
        fmap txOutScript mTxC `shouldBe` Just opTrue

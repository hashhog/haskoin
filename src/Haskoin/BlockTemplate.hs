{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Block Template Construction for Mining
--
-- This module implements block template construction for mining, including
-- transaction selection by fee rate, coinbase transaction generation, and
-- the getblocktemplate interface compatible with mining software.
--
-- Key Design:
--   - Templates select transactions from mempool by ancestor fee rate
--   - Coinbase transaction includes BIP-34 height encoding
--   - Witness commitment computed per BIP-141
--   - Block version uses 0x20000000 base for BIP-9 version bits
--
module Haskoin.BlockTemplate
  ( -- * Block Template Types
    BlockTemplate(..)
  , TemplateTransaction(..)
    -- * Template Creation
  , createBlockTemplate
    -- * Block Assembly
  , assembleBlock
    -- * Block Submission
  , submitBlock
    -- * Coinbase Construction
  , buildCoinbase
  , encodeHeight
    -- * Witness Commitment
  , computeWitnessCommitment
  , buildBlockUTXOMap
    -- * Transaction Finality (Locktime)
  , isFinalTx
  , locktimeThreshold
  , sequenceFinal
    -- * Anti-Fee-Sniping
  , setAntiFeeSniping
    -- * Sigop Budget Enforcement
  , templateLegacySigOpCost
  , selectWithinSigopBudget
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int32)
import Data.Bits (shiftR, (.&.))
import Control.Monad (forM, forM_, void)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import qualified Data.Set as Set
import Data.Set (Set)
import Control.Concurrent.STM
import Data.Time.Clock.POSIX (getPOSIXTime)
import GHC.Generics (Generic)
import Control.DeepSeq (NFData)
import qualified Data.Serialize as S

import Haskoin.Types
import Haskoin.Crypto (doubleSHA256, computeTxId, computeBlockHash)
import Haskoin.Consensus (Network(..), validateFullBlock, validateFullBlockIO, blockReward,
                           maxBlockWeight, maxBlockSigops, maxBlockSigOpsCost,
                           witnessScaleFactor,
                           txBaseSize, txTotalSize, difficultyAdjustment,
                           medianTimePast, ChainEntry(..), HeaderChain(..),
                           addHeader, addSideBranchHeader, computeMerkleRoot, ChainState(..),
                           consensusFlagsAtHeight, connectBlock, disconnectBlock,
                           cumulativeWork, unapplyBlock,
                           getLegacySigOpCount)
import Haskoin.Storage (HaskoinDB, UTXOCache(..), UTXOEntry(..),
                         lookupUTXO, UndoData(..), addUTXO, spendUTXO,
                         TxInUndo(..), TxUndo(..), BlockUndo(..), mkUndoData,
                         putBlock, getBlock, getUndoDataVerified, Coin(..))
import Haskoin.Mempool (Mempool(..), MempoolEntry(..), selectTransactions)
import Haskoin.Network (PeerManager, broadcastMessage, Message(..),
                         Inv(..), InvVector(..), InvType(..))

--------------------------------------------------------------------------------
-- Transaction Finality Constants
--------------------------------------------------------------------------------

-- | Locktime threshold: values below this are block heights, above are timestamps
-- LOCKTIME_THRESHOLD = 500000000 (Tue Nov 5 00:53:20 1985 UTC)
locktimeThreshold :: Word32
locktimeThreshold = 500000000

-- | SEQUENCE_FINAL: if all inputs have this sequence, nLockTime is ignored
sequenceFinal :: Word32
sequenceFinal = 0xffffffff

--------------------------------------------------------------------------------
-- Transaction Finality Check
--------------------------------------------------------------------------------

-- | Check if a transaction is final at the given block height and time.
-- A transaction is final if:
--   1. nLockTime == 0, OR
--   2. nLockTime < threshold (height-based: nLockTime < nBlockHeight), OR
--      nLockTime < nBlockTime (time-based: nLockTime >= 500000000), OR
--   3. All inputs have nSequence == 0xFFFFFFFF (SEQUENCE_FINAL)
--
-- This is a pure function matching Bitcoin Core's IsFinalTx().
isFinalTx :: Tx       -- ^ Transaction to check
          -> Word32   -- ^ Block height
          -> Word32   -- ^ Block time (median time past for mining)
          -> Bool
isFinalTx tx blockHeight blockTime
  -- Case 1: nLockTime == 0 means always final
  | txLockTime tx == 0 = True
  -- Case 2: Check if locktime constraint is satisfied
  | isLockTimeSatisfied = True
  -- Case 3: All inputs have SEQUENCE_FINAL (0xFFFFFFFF)
  | otherwise = all (\inp -> txInSequence inp == sequenceFinal) (txInputs tx)
  where
    lockTime = txLockTime tx
    -- If lockTime < 500000000, it's a block height; otherwise it's a timestamp
    isLockTimeSatisfied
      | lockTime < locktimeThreshold = lockTime < blockHeight
      | otherwise                    = lockTime < blockTime

--------------------------------------------------------------------------------
-- Block Template Types
--------------------------------------------------------------------------------

-- | Block template for mining
-- Contains all information needed to construct a valid block
data BlockTemplate = BlockTemplate
  { btVersion           :: !Int32         -- ^ Block version (with version bits)
  , btPreviousBlock     :: !BlockHash     -- ^ Previous block hash
  , btTransactions      :: ![TemplateTransaction] -- ^ Selected transactions
  , btCoinbaseValue     :: !Word64        -- ^ Total available for coinbase
  , btBits              :: !Word32        -- ^ Difficulty target (compact)
  , btHeight            :: !Word32        -- ^ Height of the block being built
  , btCurTime           :: !Word32        -- ^ Current timestamp for block
  , btMinTime           :: !Word32        -- ^ Median time past + 1
  , btMaxTime           :: !Word32        -- ^ Current time + 2 hours
  , btSigopLimit        :: !Int           -- ^ Maximum sigops allowed
  , btWeightLimit       :: !Int           -- ^ Maximum weight allowed
  , btCoinbaseTxn       :: !Tx            -- ^ Template coinbase (miner fills in)
  , btWitnessCommitment :: !ByteString    -- ^ Witness commitment for coinbase
  , btDefaultWitnessNonce :: !ByteString  -- ^ 32-byte witness nonce
  } deriving (Show, Generic)

instance NFData BlockTemplate

-- | A transaction in the template with metadata
data TemplateTransaction = TemplateTransaction
  { ttTx       :: !Tx         -- ^ The transaction
  , ttTxId     :: !TxId       -- ^ Transaction ID (cached)
  , ttFee      :: !Word64     -- ^ Fee in satoshis
  , ttSigops   :: !Int        -- ^ Signature operations count
  , ttWeight   :: !Int        -- ^ Transaction weight
  , ttRequired :: !Bool       -- ^ Must be included (for dependencies)
  , ttDepends  :: ![Int]      -- ^ Indices of parent transactions in template
  } deriving (Show, Generic)

instance NFData TemplateTransaction

--------------------------------------------------------------------------------
-- Block Template Creation
--------------------------------------------------------------------------------

-- | Create a block template for mining
-- Selects transactions from the mempool and constructs a template that
-- mining software can use to produce valid blocks.
createBlockTemplate :: Network           -- ^ Network configuration
                    -> HeaderChain       -- ^ Current header chain
                    -> Mempool           -- ^ Transaction mempool
                    -> UTXOCache         -- ^ UTXO cache for validation
                    -> ByteString        -- ^ Coinbase scriptPubKey (payout address)
                    -> ByteString        -- ^ Extra nonce space
                    -> IO BlockTemplate
createBlockTemplate net hc mp _cache coinbaseScript extraNonce = do
  -- Get current chain tip
  tip <- readTVarIO (hcTip hc)
  let height = ceHeight tip + 1
      prevHash = ceHash tip

  -- Calculate difficulty for the new block
  entries <- readTVarIO (hcEntries hc)
  let expectedBits = difficultyAdjustment net entries tip

  -- Calculate timestamps
  now <- (round :: Double -> Word32) . realToFrac <$> getPOSIXTime
  let mtp = medianTimePast entries prevHash
      minTime = mtp + 1
      maxTime = now + 7200  -- current time + 2 hours
      curTime = max minTime now

  -- Select transactions from mempool (highest ancestor fee rate first)
  -- Reserve some weight for coinbase (~4000 weight units)
  let reservedWeight = 4000
  allEntries <- selectTransactions mp (maxBlockWeight - reservedWeight)

  -- Filter out transactions that are not final at this height/time
  -- For block template, use MTP (median time past) as the time threshold
  let mtpFinalEntries = filter (isFinalEntry height mtp) allEntries

  -- Enforce the per-block sigop cost budget (BIP-141 / MAX_BLOCK_SIGOPS_COST = 80,000).
  -- Without UTXO-resolved prevouts at template time we use the legacy sigop count
  -- (scriptSig + scriptPubKey) scaled by WITNESS_SCALE_FACTOR. This is the same
  -- conservative lower bound Bitcoin Core uses as a starting point in
  -- GetTransactionSigOpCost (consensus/tx_verify.cpp:143-162) before adding
  -- P2SH/witness sigops once prevouts are known. Mining a block whose legacy
  -- cost alone would exceed the limit is always invalid, so we drop those txs
  -- here and skip any tx that would push the running total over 80k. See
  -- node/miner.cpp:239-247 (TestChunkBlockLimits) for Core's analogous gate.
  let finalEntries = selectWithinSigopBudget mtpFinalEntries

  -- Build template transactions with dependency tracking
  let txIdSet = Set.fromList $ map meTxId finalEntries
      templateTxs = zipWith (buildTemplateTx txIdSet finalEntries) [0..] finalEntries

  -- Calculate total fees from selected transactions
  let totalFees = sum $ map meFee finalEntries
      reward = blockReward height
      coinbaseValue = reward + totalFees

  -- Calculate witness commitment
  let wtxids = TxId (Hash256 (BS.replicate 32 0))  -- coinbase wtxid is zeros
               : map (computeWtxIdFromEntry) finalEntries
      witnessRoot = computeMerkleRoot wtxids
      witnessNonce = BS.replicate 32 0
      witnessCommitment = getHash256 $
        doubleSHA256 (BS.append (getHash256 witnessRoot) witnessNonce)

  -- Rebuild coinbase with correct witness commitment
  let finalCoinbase = buildCoinbase height coinbaseValue coinbaseScript extraNonce
                        witnessCommitment

  return BlockTemplate
    { btVersion = 0x20000000  -- BIP-9 version bits signaling
    , btPreviousBlock = prevHash
    , btTransactions = templateTxs
    , btCoinbaseValue = coinbaseValue
    , btBits = expectedBits
    , btHeight = height
    , btCurTime = curTime
    , btMinTime = minTime
    , btMaxTime = maxTime
    , btSigopLimit = maxBlockSigops
    , btWeightLimit = maxBlockWeight
    , btCoinbaseTxn = finalCoinbase
    , btWitnessCommitment = witnessCommitment
    , btDefaultWitnessNonce = witnessNonce
    }

-- | Check if a mempool entry is final at the given height and time
isFinalEntry :: Word32 -> Word32 -> MempoolEntry -> Bool
isFinalEntry height mtp entry = isFinalTx (meTransaction entry) height mtp

-- | Lower-bound legacy sigop cost for a transaction in template-construction
-- context.  Counts sigops in scriptSig + scriptPubKey (inaccurate counting,
-- so OP_CHECKMULTISIG counts as MAX_PUBKEYS_PER_MULTISIG = 20) and scales by
-- WITNESS_SCALE_FACTOR to match the per-block cost units defined by
-- 'maxBlockSigOpsCost'.  This matches the legacy term in Bitcoin Core's
-- GetTransactionSigOpCost (consensus/tx_verify.cpp:145).  P2SH redeem-script
-- and witness-script sigops are not added here because they require
-- UTXO-resolved prevouts which are not available at template time.
templateLegacySigOpCost :: Tx -> Int
templateLegacySigOpCost tx = getLegacySigOpCount tx * witnessScaleFactor

-- | Greedy filter that drops mempool entries whose legacy sigop cost would
-- push the running block total past 'maxBlockSigOpsCost' (80,000).  Order is
-- preserved (highest ancestor fee rate first, as supplied by
-- 'selectTransactions').  Mirrors the chunk-level gate in Bitcoin Core's
-- BlockAssembler::TestChunkBlockLimits (node/miner.cpp:239-247).
selectWithinSigopBudget :: [MempoolEntry] -> [MempoolEntry]
selectWithinSigopBudget = go 0
  where
    go _      []           = []
    go !running (e : rest) =
      let cost     = templateLegacySigOpCost (meTransaction e)
          running' = running + cost
      in if running' > maxBlockSigOpsCost
         then go running rest          -- skip this tx; keep scanning
         else e : go running' rest

-- | Build a TemplateTransaction from a MempoolEntry
-- Tracks which other transactions in the template this one depends on
buildTemplateTx :: Set TxId           -- ^ Set of all TxIds in the template
                -> [MempoolEntry]      -- ^ All mempool entries (for lookup)
                -> Int                 -- ^ Index of this transaction
                -> MempoolEntry        -- ^ The mempool entry
                -> TemplateTransaction
buildTemplateTx txIdSet allEntries idx entry =
  let tx = meTransaction entry
      -- Find which template transactions this depends on
      parentTxIds = map (outPointHash . txInPrevOutput) (txInputs tx)
      depends = [ i | (i, e) <- zip [0..] allEntries
                , meTxId e `elem` parentTxIds
                , Set.member (meTxId e) txIdSet
                , i < idx  -- Can only depend on earlier transactions
                ]
      -- Calculate transaction weight
      base = txBaseSize tx
      total = txTotalSize tx
      weight = base * (witnessScaleFactor - 1) + total
      -- Per-tx legacy sigop cost (matches the budget enforced in
      -- selectWithinSigopBudget, so consumers reading 'btTransactions' see
      -- the same units the template was built against).
      sigops = templateLegacySigOpCost tx
  in TemplateTransaction
    { ttTx = tx
    , ttTxId = meTxId entry
    , ttFee = meFee entry
    , ttSigops = sigops
    , ttWeight = weight
    , ttRequired = False
    , ttDepends = depends
    }

-- | Compute the witness transaction ID (wtxid) from a mempool entry
-- For other transactions, it's the hash of the full serialization including witness.
computeWtxIdFromEntry :: MempoolEntry -> TxId
computeWtxIdFromEntry entry =
  let tx = meTransaction entry
  in TxId (doubleSHA256 (S.encode tx))

-- | Compute witness commitment
computeWitnessCommitment :: [TxId] -> ByteString -> Hash256
computeWitnessCommitment wtxids witnessNonce =
  let witnessRoot = computeMerkleRoot wtxids
  in doubleSHA256 (BS.append (getHash256 witnessRoot) witnessNonce)

--------------------------------------------------------------------------------
-- Coinbase Transaction Construction
--------------------------------------------------------------------------------

-- | Build a coinbase transaction
-- Follows BIP-34 for height encoding and BIP-141 for witness commitment
buildCoinbase :: Word32           -- ^ Block height
              -> Word64           -- ^ Total value (reward + fees)
              -> ByteString       -- ^ Output scriptPubKey (payout address)
              -> ByteString       -- ^ Extra nonce space (for miner entropy)
              -> ByteString       -- ^ Witness commitment (32 bytes)
              -> Tx
buildCoinbase height value coinbaseScript extraNonce witnessCommitment =
  let -- BIP-34: height in coinbase scriptSig
      heightBytes = encodeHeight height
      scriptSig = BS.concat [heightBytes, extraNonce]

      -- Coinbase input with null prevout
      coinbaseInput = TxIn
        { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
        , txInScript = scriptSig
        , txInSequence = 0xffffffff
        }

      -- Main output: reward + fees to miner's address
      mainOutput = TxOut value coinbaseScript

      -- Witness commitment output (OP_RETURN)
      -- Format: OP_RETURN OP_PUSHBYTES_36 <aa21a9ed><32-byte commitment>
      witnessOutput = TxOut 0 $ BS.concat
        [ BS.pack [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]  -- OP_RETURN OP_PUSHBYTES_36 prefix
        , witnessCommitment
        ]

  in Tx
    { txVersion = 2
    , txInputs = [coinbaseInput]
    , txOutputs = [mainOutput, witnessOutput]
    , txWitness = [[BS.replicate 32 0]]  -- Witness nonce (32 zeros)
    , txLockTime = 0
    }

-- | Encode block height as CScriptNum for BIP-34 coinbase
-- Uses minimal push encoding
encodeHeight :: Word32 -> ByteString
encodeHeight h
  | h == 0     = BS.pack [1, 0]  -- Push 1 byte of zero
  | h <= 16    = BS.pack [0x50 + fromIntegral h]  -- OP_1 through OP_16
  | h <= 0x7f  = BS.pack [1, fromIntegral h]
  | h <= 0x7fff = BS.pack [2, fromIntegral (h .&. 0xff),
                              fromIntegral ((h `shiftR` 8) .&. 0xff)]
  | h <= 0x7fffff = BS.pack [3, fromIntegral (h .&. 0xff),
                                fromIntegral ((h `shiftR` 8) .&. 0xff),
                                fromIntegral ((h `shiftR` 16) .&. 0xff)]
  | otherwise = BS.pack [4, fromIntegral (h .&. 0xff),
                            fromIntegral ((h `shiftR` 8) .&. 0xff),
                            fromIntegral ((h `shiftR` 16) .&. 0xff),
                            fromIntegral ((h `shiftR` 24) .&. 0xff)]

--------------------------------------------------------------------------------
-- Block Assembly
--------------------------------------------------------------------------------

-- | Assemble a complete block from the template and miner's solution
-- The miner provides the nonce that makes the block hash meet the target
assembleBlock :: BlockTemplate -> Word32 -> Block
assembleBlock bt nonce =
  let -- Combine coinbase with selected transactions
      allTxs = btCoinbaseTxn bt : map ttTx (btTransactions bt)

      -- Compute merkle root from all transaction IDs
      merkleRoot = computeMerkleRoot (map computeTxId allTxs)

      -- Build block header
      header = BlockHeader
        { bhVersion = btVersion bt
        , bhPrevBlock = btPreviousBlock bt
        , bhMerkleRoot = merkleRoot
        , bhTimestamp = btCurTime bt
        , bhBits = btBits bt
        , bhNonce = nonce
        }
  in Block header allTxs

--------------------------------------------------------------------------------
-- Block Submission
--------------------------------------------------------------------------------

-- | Submit a mined block to the network
-- Validates the block, connects it to the chain, and broadcasts to peers
submitBlock :: Network         -- ^ Network configuration
            -> HaskoinDB       -- ^ Database handle
            -> HeaderChain     -- ^ Header chain
            -> UTXOCache       -- ^ UTXO cache
            -> PeerManager     -- ^ Peer manager for broadcasting
            -> Block           -- ^ The mined block
            -> IO (Either String ())
submitBlock net db hc cache pm block = do
  let bh = computeBlockHash (blockHeader block)
      header = blockHeader block
      prevHash = bhPrevBlock header

  -- Pattern X fix (CORE-PARITY-AUDIT
  -- _reorg-via-submitblock-fleet-result-2026-05-05.md):
  -- Derive the block's height from its OWN parent in the in-memory block
  -- index, NOT from the active chain tip.  Bitcoin Core's
  -- ContextualCheckBlockHeader (validation.cpp) uses
  -- @pindexPrev->nHeight + 1@ where @pindexPrev@ is the parent in the
  -- block index — for a side-branch block this is NOT the active tip.
  --
  -- Pre-fix: BIP-34 derived @height = ceHeight tip + 1@ which equalled
  -- the active tip's next height, so a side-branch block whose coinbase
  -- correctly encoded its own (smaller) height was rejected with
  -- bad-cb-height.  Surfaced by the corpus entry
  -- @tools/diff-test-corpus/regression/reorg-via-submitblock@: when B1
  -- (parent = base@h=110) is submitted while the active tip is A2@h=112,
  -- the active-tip-relative arithmetic gave height=113 and the B1
  -- coinbase encoded h=111 — bad-cb-height.
  --
  -- Cross-impl reference: camlcoin 22667c2, rustoshi 68a422b.
  entries <- readTVarIO (hcEntries hc)
  tip <- readTVarIO (hcTip hc)
  case Map.lookup prevHash entries of
    Nothing -> return $ Left $
      "Block validation failed: parent " ++ show prevHash ++
      " not in block index"
    Just parent -> do
      let height = ceHeight parent + 1
          -- MTP at the BLOCK's parent (BIP-113), not the active tip.
          parentMTP = medianTimePast entries prevHash
          parentChainWork = ceChainWork parent
          parentHash = ceHash parent

      -- Build UTXO map for validation. We carry full Core-format
      -- 'Coin' (TxOut + height + coinbase flag) so 'connectBlock' can
      -- record byte-identical undo entries, and so validateFullBlock can
      -- perform BIP-68 SequenceLocks checks (which require per-coin heights).
      utxoMap <- buildBlockUTXOMap cache block

      -- Build chain state for validation, anchored on the BLOCK's
      -- parent (not the active tip).  csHeight carries the parent's
      -- height per the existing convention (validateFullBlock derives
      -- @height = csHeight cs + 1@; checkBIP30 uses the same arithmetic).
      let cs = ChainState
            { csHeight = ceHeight parent
            , csBestBlock = parentHash
            , csChainWork = parentChainWork
            , csMedianTime = parentMTP
            , csFlags = consensusFlagsAtHeight net height
            }

      -- Validate the block (always verify scripts for locally minted blocks).
      -- 'validateFullBlockIO' sequences BIP-30 (UTXO duplicate-txid guard, requires
      -- DB IO) followed by the pure 'validateFullBlock' checks, ensuring submitBlock
      -- and the IBD path share identical BIP-30 enforcement.
      -- Reference: Bitcoin Core ConnectBlock() / IsBIP30Repeat(), validation.cpp.
      -- Wave-29 audit (0d56486): checkBIP30 was previously only wired in Sync.hs:386.
      validationResult <- validateFullBlockIO db net cs False block utxoMap
      case validationResult of
        Left err -> return $ Left $ "Block validation failed: " ++ err
        Right () ->
          -- Pattern Y companion (CORE-PARITY-AUDIT
          -- _reorg-via-submitblock-fleet-result-2026-05-05.md): the
          -- earlier Pattern X fix (haskoin 04c0136) corrected the BIP-34
          -- height-derivation site but stopped short of side-branch
          -- storage + reorg dispatch.  Pre-fix, parent /= tip was
          -- surfaced as a distinct rejection so the active UTXO didn't
          -- get clobbered; post-fix we route side-branch blocks through
          -- the storage decoupling Core does in
          -- @BlockManager::AcceptBlock@ (validation.cpp): every accepted
          -- block gets a 'CBlockIndex' entry regardless of which chain
          -- it lives on, and 'ActivateBestChain' separately picks the
          -- best-work tip.
          --
          -- Cross-impl reference: nimrod 7196d41
          -- (putBlockIndexHashOnly + handleSubmitBlock else-arm),
          -- camlcoin 22667c2 (register_side_branch_header +
          -- try_attach_side_branch_and_reorg), rustoshi 68a422b.
          if ceHash parent /= ceHash tip
            then submitBlockSideBranch net db hc cache pm block parent
            else do
              -- Apply block to in-memory UTXO cache (drives maturity check + builds
              -- the BlockUndo record). Cache mutation lets a follow-on submitBlock
              -- spend an output created earlier in the same session without round-
              -- tripping through disk.
              undoResult <- applyBlockToCache cache net block height
              case undoResult of
                Left err -> return $ Left err
                Right _undo -> do
                  -- Persist UTXOs + undo data + header + height + best-block in a
                  -- single atomic write batch via 'connectBlock' (the same path
                  -- IBD uses; see 'Sync.connectBlock' wiring). This is the FIX
                  -- for dumptxoutset emitting a 0-coin snapshot: 'applyBlockToCache'
                  -- only mutates STM TVars and never reaches RocksDB, so the
                  -- legacy PrefixUTXO keyspace stayed empty unless a periodic
                  -- 'flushCache' ran. dumptxoutset iterates PrefixUTXO directly,
                  -- so it saw nothing. Routing through connectBlock writes
                  -- Core-format Coins to PrefixUTXO immediately, which is also
                  -- the on-disk format 'getUTXOCoin' / 'dumpTxOutSetFromDB'
                  -- expect. The Coin map carries height/coinbase metadata so the
                  -- per-block undo record round-trips through 'disconnectBlock'.
                  --
                  -- connectBlock also handles per-block undo data (so we drop the
                  -- separate 'putUndoData'), block-index keys (so we drop
                  -- 'putBlockHeader' / 'putBlockHeight'), and best-block pointer.
                  -- The only thing left for us is the full block body and the
                  -- in-memory header chain update.
                  connectBlock db net block height utxoMap

                  -- Persist the full block body (separate keyspace from headers
                  -- so that getblock can return raw bytes).
                  putBlock db bh block

                  -- Add header to chain (in-memory index + tip update)
                  void $ addHeader net hc (blockHeader block)

                  -- Broadcast to peers
                  let invVec = InvVector InvBlock (getBlockHashHash bh)
                  broadcastMessage pm $ MInv $ Inv [invVec]

                  return $ Right ()

-- | Side-branch arm of 'submitBlock'.  Runs after 'validateFullBlockIO'
-- has approved the block but its parent is NOT the active tip (so a
-- direct 'connectBlock' would corrupt the active chain's UTXO + best
-- block pointers).
--
-- Mirrors 'BlockManager::AcceptBlock' + 'ActivateBestChain'
-- (validation.cpp): persist the block + a side-branch index entry
-- regardless of which chain wins, then pick the best-work tip
-- separately.
--
-- BIP-22 result mapping (matches Bitcoin Core):
--
--   * heavier than active chain → reorg succeeds → 'Right ()' (= null
--     RPC result, "accept onto best chain")
--   * lighter or equal           → 'Left "inconclusive"'
--   * heavier but reorg failed (missing undo / side-branch ancestor
--     body) → 'Left "inconclusive"' (block is on disk; operator can
--     re-trigger via reconsiderblock once any blocking issue clears,
--     same shape Core uses when AcceptBlock succeeds but a later
--     ConnectTip fails inside ActivateBestChain).
--
-- Cross-impl reference templates:
--   * nimrod 7196d41   (handleSubmitBlock else-arm + putBlockIndexHashOnly)
--   * camlcoin 22667c2 (try_attach_side_branch_and_reorg + register_side_branch_header)
--   * rustoshi 68a422b (Pattern Y proof of shape)
submitBlockSideBranch :: Network -> HaskoinDB -> HeaderChain -> UTXOCache
                      -> PeerManager -> Block -> ChainEntry
                      -> IO (Either String ())
submitBlockSideBranch net db hc cache pm block parent = do
  let header   = blockHeader block
      bh       = computeBlockHash header
      -- 'cumulativeWork' = parentWork + headerWork (Consensus.hs).
      newWork  = cumulativeWork (ceChainWork parent) header

  -- Step 1: storage decoupling.  Persist the block body and a hash-
  -- keyed header-chain entry that does NOT touch hcByHeight (the
  -- height -> active-chain-hash map).  These two writes are what let
  -- a follow-up child block on the same side-branch find its parent
  -- via the in-memory index — without them, B2 (parent = B1) would
  -- be rejected as orphan even though B1 is "accepted" by the prior
  -- submitblock call.
  putBlock db bh block
  _sideEntry <- addSideBranchHeader hc header

  -- Step 2: best-chain selection.
  currentTip     <- readTVarIO (hcTip hc)
  let activeWork = ceChainWork currentTip
  if newWork <= activeWork
    then
      -- Side-branch with insufficient work.  BIP-22 / Core convention:
      -- "inconclusive" = block accepted into the index, not yet known
      -- to be on the best chain (rpc/mining.cpp:1100).
      return $ Left "inconclusive"
    else do
      -- Step 3: reorg dispatch.  Side-branch has STRICTLY more work
      -- than the active chain — flip tip.  We bypass the
      -- 'performReorg' top-level helper because it does not maintain
      -- the on-disk PrefixUTXO / PrefixBestBlock / PrefixBlockHeight
      -- entries that 'gettxoutsetinfo' / restart recovery rely on
      -- (it routes through 'applyBlock' / 'unapplyBlock' which only
      -- touch the cache TVar).  Inlining the disconnect+connect loop
      -- here lets us call 'disconnectBlock' (disk) +
      -- 'unapplyBlock' (cache) on the way down, and 'connectBlock'
      -- (disk) + 'applyBlockToCache' (cache) on the way up — same
      -- atomic-pair pattern Sync.hs and the active-tip arm above use.
      reorgRes <- doSideBranchReorg net db hc cache parent block newWork
      case reorgRes of
        Left err -> do
          -- Block + side-branch index entry are already persisted;
          -- the operator can call reconsiderblock once any blocking
          -- issue is fixed.  Surface as inconclusive rather than a
          -- hard failure so peers see the partial-accept signal.
          putStrLn $ "submitBlock side-branch reorg failed: " ++ err
          return $ Left "inconclusive"
        Right () -> do
          -- Reorg succeeded; mempool / peer-broadcast bookkeeping the
          -- happy-path arm normally handles.  Mempool integration
          -- (removing confirmed transactions) is out of scope for the
          -- corpus entry — it doesn't query mempool — and matches the
          -- nimrod 7196d41 commentary which marked mempool refresh as
          -- best-effort.  Broadcast the new tip so peers see the
          -- reorg-induced INV.
          let invVec = InvVector InvBlock (getBlockHashHash bh)
          broadcastMessage pm $ MInv $ Inv [invVec]
          return $ Right ()

-- | Walk back from the new side-branch tip until we hit a block hash
-- that the active chain owns at that height — that's the fork point.
-- Returns the (forkHash, [blocks-to-disconnect-tip-to-fork],
-- [blocks-to-connect-fork+1-to-newtip]) triple, or Left on a missing
-- ancestor body (which means the side-branch can't be activated).
--
-- Both block lists are returned in DISCONNECT/CONNECT order:
--   * disconnect list: oldTip first, fork-child last (so iterating
--     forward unwinds tip-to-fork)
--   * connect list:    fork-child first, newTip last (so iterating
--     forward applies fork-to-newTip)
findSideBranchForkPoint :: HeaderChain -> HaskoinDB -> ChainEntry
                        -> Block -> IO (Either String (BlockHash, [Block], [Block]))
findSideBranchForkPoint hc db parent newTipBlock = do
  byHeight <- readTVarIO (hcByHeight hc)
  entries  <- readTVarIO (hcEntries hc)

  -- Walk back along the side-branch from the new tip's parent
  -- collecting block bodies until we find a block hash that
  -- @hcByHeight@ owns at that height — that's the fork point.
  let go :: BlockHash -> [Block] -> IO (Either String (BlockHash, [Block]))
      go walkHash acc =
        case Map.lookup walkHash entries of
          Nothing ->
            return $ Left $ "Side-branch ancestor "
              ++ show walkHash ++ " missing from header index"
          Just walkEntry ->
            case Map.lookup (ceHeight walkEntry) byHeight of
              Just activeAtHeight | activeAtHeight == walkHash ->
                -- Hit the fork point — walkHash is on the active chain.
                return $ Right (walkHash, acc)
              _ -> do
                -- Not on the active chain at this height; keep walking.
                mWalkBlk <- getBlock db walkHash
                case mWalkBlk of
                  Nothing -> return $ Left $
                    "Side-branch ancestor body missing: " ++ show walkHash
                  Just walkBlk ->
                    case cePrev walkEntry of
                      Nothing  -> return $ Left
                        "Side-branch walked past genesis without finding fork"
                      Just prv -> go prv (walkBlk : acc)

  -- newTipBlock is the deepest side-branch block; its parent
  -- (passed in as @parent@) is where we start the walk.
  forkRes <- go (ceHash parent) []
  case forkRes of
    Left e -> return (Left e)
    Right (forkHash, parentChain) ->
      -- 'parentChain' walks from fork-child .. parent of newTipBlock.
      -- Append newTipBlock to get the full connect list.
      let connectList = parentChain ++ [newTipBlock]
      in do
        -- Build disconnect list: walk active chain from current tip
        -- back to (but excluding) forkHash.  Read fresh tip in case
        -- another thread shifted it (we hold no global lock here, but
        -- submitblock is serialised at the RPC layer).
        currentTip <- readTVarIO (hcTip hc)
        disconnectRes <- buildDisconnectList db (ceHash currentTip) forkHash []
        case disconnectRes of
          Left e   -> return (Left e)
          Right ds -> return $ Right (forkHash, ds, connectList)
  where
    buildDisconnectList :: HaskoinDB -> BlockHash -> BlockHash -> [Block]
                       -> IO (Either String [Block])
    buildDisconnectList _ curHash forkH acc
      | curHash == forkH = return (Right (reverse acc))
    buildDisconnectList dbh curHash forkH acc = do
      mBlk <- getBlock dbh curHash
      case mBlk of
        Nothing -> return $ Left $
          "Active-chain block body missing during reorg: " ++ show curHash
        Just blk -> do
          let prv = bhPrevBlock (blockHeader blk)
          buildDisconnectList dbh prv forkH (blk : acc)

-- | Execute the side-branch reorg: disconnect old-tip..fork, connect
-- fork..new-tip.  Updates both the disk chainstate (via
-- 'disconnectBlock' / 'connectBlock') AND the in-memory header chain
-- (hcTip / hcHeight / hcByHeight) so subsequent 'submitblock' /
-- 'getbestblockhash' queries see the new tip.
doSideBranchReorg :: Network -> HaskoinDB -> HeaderChain -> UTXOCache
                  -> ChainEntry  -- ^ parent of the new tip
                  -> Block       -- ^ new tip block
                  -> Integer     -- ^ new tip's cumulative work
                  -> IO (Either String ())
doSideBranchReorg net db hc cache parent newTipBlock _newWork = do
  forkRes <- findSideBranchForkPoint hc db parent newTipBlock
  case forkRes of
    Left err -> return (Left err)
    Right (_forkHash, disconnectList, connectList) -> do
      -- Phase 1: disconnect tip..fork+1 (oldTip first, fork-child last).
      disResult <- disconnectMany db cache disconnectList
      case disResult of
        Left err -> return (Left err)
        Right () -> do
          -- Phase 2: connect fork+1..newTip (fork-child first, newTip last).
          conResult <- connectMany net db cache connectList
          case conResult of
            Left err -> return (Left err)
            Right () -> do
              -- Phase 3: rewrite hcTip / hcHeight / hcByHeight to
              -- reflect the new active chain.
              entries <- readTVarIO (hcEntries hc)
              let newTipHash   = computeBlockHash (blockHeader newTipBlock)
              case Map.lookup newTipHash entries of
                Nothing -> return $ Left $
                  "New tip not in header index after reorg: "
                  ++ show newTipHash
                Just newTipEntry -> do
                  atomically $ do
                    -- Drop the height -> hash entries for the
                    -- disconnected (old) chain.
                    forM_ disconnectList $ \blk ->
                      let h = computeBlockHash (blockHeader blk)
                      in case Map.lookup h entries of
                           Just ce -> modifyTVar' (hcByHeight hc)
                             (Map.delete (ceHeight ce))
                           Nothing -> return ()
                    -- Install the height -> hash entries for the
                    -- newly-connected chain.
                    forM_ connectList $ \blk ->
                      let h = computeBlockHash (blockHeader blk)
                      in case Map.lookup h entries of
                           Just ce -> modifyTVar' (hcByHeight hc)
                             (Map.insert (ceHeight ce) h)
                           Nothing -> return ()
                    writeTVar (hcTip hc) newTipEntry
                    writeTVar (hcHeight hc) (ceHeight newTipEntry)
                  return (Right ())
  where
    disconnectMany :: HaskoinDB -> UTXOCache -> [Block]
                   -> IO (Either String ())
    disconnectMany _ _ [] = return (Right ())
    disconnectMany dbh ch (blk : rest) = do
      let bh   = computeBlockHash (blockHeader blk)
          prv  = bhPrevBlock (blockHeader blk)
      -- Read undo, apply to cache via unapplyBlock, then write disk.
      undoR <- getUndoDataVerified dbh bh prv
      case undoR of
        Left err -> return $ Left $ "undo read failed for "
                                     ++ show bh ++ ": " ++ err
        Right undo -> do
          unapplyBlock ch blk undo
          dRes <- disconnectBlock dbh blk prv
          case dRes of
            Left err -> return (Left err)
            Right () -> disconnectMany dbh ch rest

    connectMany :: Network -> HaskoinDB -> UTXOCache -> [Block]
                -> IO (Either String ())
    connectMany _ _ _ [] = return (Right ())
    connectMany n dbh ch (blk : rest) = do
      -- Look up the per-block height from the header chain.
      entries <- readTVarIO (hcEntries hc)
      let bh = computeBlockHash (blockHeader blk)
      case Map.lookup bh entries of
        Nothing -> return $ Left $
          "Connect: block " ++ show bh ++ " missing from header index"
        Just ce -> do
          -- Build utxoMap from the cache (post-disconnect state).
          utxoMap <- buildBlockUTXOMap ch blk
          appRes <- applyBlockToCache ch n blk (ceHeight ce)
          case appRes of
            Left err -> return $ Left $
              "Connect: applyBlockToCache failed at "
              ++ show (ceHeight ce) ++ ": " ++ err
            Right _undo -> do
              -- Write to disk: PrefixUTXO + PrefixBlockHeader +
              -- PrefixBlockHeight + PrefixBestBlock + per-block undo.
              connectBlock dbh n blk (ceHeight ce) utxoMap
              connectMany n dbh ch rest

-- | Build a UTXO map for block validation.
--
-- Returns 'Map OutPoint Coin' (full Core-format metadata: TxOut +
-- height + coinbase flag). Validation paths that only consume the
-- 'TxOut' (e.g. 'validateFullBlock') project via @fmap coinTxOut@.
-- 'connectBlock' uses the metadata to populate 'BlockUndo' so that
-- 'disconnectBlock' restores byte-identical UTXO entries.
--
-- The metadata is sourced from the in-memory 'UTXOCache'
-- ('UTXOEntry'), which carries the height and coinbase flag the
-- block originally created the output at.
buildBlockUTXOMap :: UTXOCache -> Block -> IO (Map OutPoint Coin)
buildBlockUTXOMap cache block = do
  -- Collect all inputs from non-coinbase transactions
  let inputs = concatMap txInputs (tail $ blockTxns block)
      outpoints = map txInPrevOutput inputs

  -- Look up each outpoint, lifting UTXOEntry → Coin so the metadata
  -- (height, coinbase flag) flows into the connectBlock undo record.
  utxos <- forM outpoints $ \op -> do
    mEntry <- lookupUTXO cache op
    return (op, fmap entryToCoin mEntry)

  return $ Map.fromList [(op, c) | (op, Just c) <- utxos]
  where
    entryToCoin e = Coin { coinTxOut      = ueOutput e
                         , coinHeight     = ueHeight e
                         , coinIsCoinbase = ueCoinbase e
                         }

-- | Apply a block to the UTXO cache, generating undo data
applyBlockToCache :: UTXOCache -> Network -> Block -> Word32
                  -> IO (Either String UndoData)
applyBlockToCache cache net block height = do
  let bh = computeBlockHash (blockHeader block)
      txns = blockTxns block
      prevHash = bhPrevBlock (blockHeader block)

  -- Collect TxUndo for each non-coinbase transaction
  txUndosRef <- newTVarIO []

  -- Process each transaction
  results <- forM (zip [0..] txns) $ \(txIdx :: Int, tx) -> do
    if txIdx == 0  -- Coinbase
      then do
        -- Coinbase: only create outputs, no undo data
        atomically $ forM_ (zip [(0::Word32)..] (txOutputs tx)) $ \(outIdx, txout) -> do
          let op = OutPoint (computeTxId tx) outIdx
              entry = UTXOEntry txout height True False
          addUTXO cache op entry
        return (Right ())
      else do
        -- Regular transaction: spend inputs, create outputs
        -- Collect TxInUndo for each input
        inputUndosRef <- newTVarIO []

        inputResults <- forM (txInputs tx) $ \inp -> do
          let op = txInPrevOutput inp
          mEntry <- lookupUTXO cache op
          case mEntry of
            Nothing -> return $ Left $ "Missing UTXO: " ++ show op
            Just entry -> do
              -- Check coinbase maturity
              if ueCoinbase entry && height - ueHeight entry < fromIntegral (netCoinbaseMaturity net)
                then return $ Left "Coinbase not yet mature"
                else do
                  -- Build TxInUndo from the spent UTXO
                  let txInUndo = TxInUndo
                        { tuOutput   = ueOutput entry
                        , tuHeight   = ueHeight entry
                        , tuCoinbase = ueCoinbase entry
                        }
                  atomically $ do
                    void $ spendUTXO cache op
                    modifyTVar' inputUndosRef (txInUndo :)
                  return (Right ())

        case sequence inputResults of
          Left err -> return (Left err)
          Right _ -> do
            -- Collect the TxUndo for this transaction
            inputUndos <- readTVarIO inputUndosRef
            let txUndo = TxUndo { tuPrevOutputs = reverse inputUndos }
            atomically $ modifyTVar' txUndosRef (txUndo :)

            -- Create outputs
            atomically $ forM_ (zip [(0::Word32)..] (txOutputs tx)) $ \(outIdx, txout) -> do
              let op = OutPoint (computeTxId tx) outIdx
                  entry = UTXOEntry txout height False False
              addUTXO cache op entry
            return (Right ())

  case sequence results of
    Left err -> return (Left err)
    Right _ -> do
      txUndos <- readTVarIO txUndosRef
      let blockUndo = BlockUndo { buTxUndo = reverse txUndos }
      return $ Right $ mkUndoData bh height prevHash blockUndo

--------------------------------------------------------------------------------
-- Anti-Fee-Sniping
--------------------------------------------------------------------------------

-- | Set anti-fee-sniping parameters on a transaction for wallet use.
-- This sets nLockTime to the current block height, which prevents
-- the transaction from being mined in any block before this height.
--
-- Anti-fee-sniping discourages miners from reorging the chain to
-- steal fees from transactions in recent blocks, since those
-- transactions would not be valid in the reorged chain.
--
-- The transaction's inputs should NOT have nSequence == 0xFFFFFFFF
-- (SEQUENCE_FINAL) to ensure the locktime is enforced.
--
-- Arguments:
--   - currentHeight: The current chain tip height
--   - tx: The transaction to modify
--
-- Returns the transaction with nLockTime set to currentHeight.
setAntiFeeSniping :: Word32 -> Tx -> Tx
setAntiFeeSniping currentHeight tx = tx { txLockTime = currentHeight }

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
  , applyBlockToCache
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
    -- * Miner constants (exported for testing)
  , blockReservedWeight
  , maxSequenceNonFinal
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Data.Int (Int32)
import Data.Bits (shiftR, (.&.))
import Control.Monad (forM, forM_, foldM, void, unless)
import Data.IORef (newIORef, readIORef, writeIORef, modifyIORef')
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
                           getLegacySigOpCount,
                           getTransactionSigOpCost, SigOpCost(..),
                           maxMoney, isCoinbase,
                           bip68Active,
                           calculateSequenceLocks, checkSequenceLocks,
                           SequenceLock(..),
                           buildConnectBlockOps, buildDisconnectBlockOps,
                           maxReorgDepth,
                           encodeBip34Height,
                           Deployment, DeploymentCache,
                           computeBlockVersionFromChain,
                           taprootDeployment)
import Haskoin.Storage (HaskoinDB, UTXOCache(..), UTXOEntry(..),
                         lookupUTXO, UndoData(..), addUTXO, spendUTXO,
                         TxInUndo(..), TxUndo(..), BlockUndo(..), mkUndoData,
                         putBlock, getBlock, getUndoData, getUndoDataVerified, Coin(..),
                         WriteBatch(..), BatchOp, writeBatch, isUnspendable)
import Haskoin.Index (IndexManager, indexManagerConnectBlock,
                       indexManagerDisconnectBlock)
import Haskoin.Mempool (Mempool(..), MempoolEntry(..), selectTransactions,
                         blockDisconnected)
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

-- | MAX_SEQUENCE_NONFINAL: coinbase input nSequence.  Must be < SEQUENCE_FINAL
-- so that the coinbase nLockTime is enforced (anti-timewarp).
-- Bitcoin Core miner.cpp:171 — CTxIn::MAX_SEQUENCE_NONFINAL = 0xfffffffe.
maxSequenceNonFinal :: Word32
maxSequenceNonFinal = 0xfffffffe

-- | BLOCK_RESERVED_WEIGHT: weight units reserved for the block header, tx-count
-- varint, and coinbase transaction.  Bitcoin Core policy/policy.h:27 —
-- DEFAULT_BLOCK_RESERVED_WEIGHT = 8000.
blockReservedWeight :: Int
blockReservedWeight = 8000

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

  -- Calculate timestamps first (needed for testnet min-difficulty rule).
  entries <- readTVarIO (hcEntries hc)
  now <- (round :: Double -> Word32) . realToFrac <$> getPOSIXTime
  let mtp = medianTimePast entries prevHash
      minTime = mtp + 1
      maxTime = now + 7200  -- current time + 2 hours
      curTime = max minTime now

  -- Calculate difficulty for the new block.
  -- For testnet (netAllowMinDiffBlocks) difficultyAdjustment needs the
  -- candidate timestamp to evaluate the 20-minute min-difficulty rule.
  -- We use curTime as the representative timestamp.
  let candidateHdrForBits = BlockHeader 0 prevHash (Hash256 (BS.replicate 32 0)) curTime 0 0
      expectedBits = difficultyAdjustment net entries tip candidateHdrForBits

  -- Select transactions from mempool (highest ancestor fee rate first).
  -- Reserve DEFAULT_BLOCK_RESERVED_WEIGHT (8000) weight units for the block
  -- header, tx-count varint, and coinbase transaction.
  -- Bitcoin Core: policy/policy.h:27 DEFAULT_BLOCK_RESERVED_WEIGHT = 8000;
  -- BlockAssembler::resetBlock() seeds nBlockWeight with this value so
  -- transactions can only use (MAX_BLOCK_WEIGHT - 8000) = 3,992,000 weight.
  allEntries <- selectTransactions mp (maxBlockWeight - blockReservedWeight)

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

  -- Compute block version: VERSIONBITS_TOP_BITS | signaling bits for STARTED/LOCKED_IN.
  -- Reference: Bitcoin Core versionbits.cpp ComputeBlockVersion (lines 265-279).
  -- Previously hardcoded to 0x20000000, which always missed deployment bits.
  let activeDeployments :: [(Deployment, DeploymentCache)]
      activeDeployments = [(taprootDeployment net, Map.empty)]
      (blockVersion, _) = computeBlockVersionFromChain activeDeployments entries tip

  return BlockTemplate
    { btVersion = blockVersion  -- BIP-9 version bits with deployment signaling
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
  let -- BIP-34: height in coinbase scriptSig.  Use encodeBip34Height (from
      -- Consensus.hs) which mirrors CScript() << nHeight exactly, including
      -- the OP_0 encoding for height=0 and OP_1..OP_16 for heights 1-16.
      heightBytes = encodeBip34Height height
      scriptSig = BS.concat [heightBytes, extraNonce]

      -- Coinbase input with null prevout.
      -- nSequence MUST be MAX_SEQUENCE_NONFINAL (0xfffffffe) so that the
      -- coinbase nLockTime below is actually enforced by IsFinalTx().
      -- If nSequence == SEQUENCE_FINAL (0xffffffff) the locktime would be
      -- ignored entirely, defeating the anti-timewarp defence.
      -- Bitcoin Core: node/miner.cpp:171 — CTxIn::MAX_SEQUENCE_NONFINAL.
      coinbaseInput = TxIn
        { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
        , txInScript = scriptSig
        , txInSequence = maxSequenceNonFinal  -- 0xfffffffe; NOT 0xffffffff
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
    -- nLockTime = nHeight - 1 (anti-timewarp, BIP-68/anti-fee-sniping defence).
    -- With nSequence = 0xfffffffe the locktime IS enforced, meaning this
    -- coinbase is invalid in any block at height < nHeight.  This prevents a
    -- miner from back-dating a template coinbase into an earlier block.
    -- Bitcoin Core: node/miner.cpp:196 — nLockTime = nHeight - 1.
    -- Guard: for height=0 we keep lockTime=0 (genesis; cannot subtract 1 from 0).
    , txLockTime = if height > 0 then height - 1 else 0
    }

-- | Encode block height as CScriptNum for BIP-34 coinbase.
-- Delegates to 'encodeBip34Height' (Consensus.hs) which mirrors Core's
-- CScript() << nHeight exactly (including OP_0 for height=0 and OP_1..OP_16
-- for heights 1-16).  The previous inline implementation diverged at h=0:
-- it produced a 2-byte \x01\x00 push instead of the canonical single-byte
-- OP_0 (0x00), so the 'validateCoinbaseHeightConsensus' prefix-check would
-- have failed for any h=0 coinbase.  Kept for backward-compat / external
-- callers; new code should import 'encodeBip34Height' directly.
encodeHeight :: Word32 -> ByteString
encodeHeight = encodeBip34Height

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
            -> Mempool         -- ^ Mempool (for refill on side-branch reorg)
            -> Maybe IndexManager
               -- ^ Secondary indexes (txindex / blockfilterindex /
               -- coinstatsindex). Mirrored on every successful
               -- 'connectBlock' / disconnect during a reorg.
            -> Block           -- ^ The mined block
            -> IO (Either String ())
submitBlock net db hc cache pm mp mIdxMgr block = do
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
            then submitBlockSideBranch net db hc cache pm mp mIdxMgr block parent
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
                  --
                  -- W97/W99-G18: connectBlock now returns Either String ()
                  -- and refuses to overwrite BestBlock when prevHash does
                  -- not extend the current tip.  Here we are inside the
                  -- `parent == tip` branch (line 565 guard), so the G1
                  -- gate is structurally guaranteed to pass; if it ever
                  -- fires we surface as Left rather than silently
                  -- corrupting the tip.
                  cbR <- connectBlock db net block height utxoMap
                  case cbR of
                    Left cbErr -> return $ Left $
                      "submitBlock connectBlock failed (should be unreachable "
                      <> "from the parent==tip arm): " <> cbErr
                    Right () -> do
                      -- Mirror the connect into any opted-in secondary
                      -- indexes.  Read the freshly-persisted undo record
                      -- back from disk so the BlockFilterIndex sees the
                      -- exact bytes 'disconnectBlock' would; this keeps
                      -- the GCS filter byte-for-byte compatible with
                      -- Bitcoin Core's blockfilterindex.cpp output.
                      case mIdxMgr of
                        Nothing -> return ()
                        Just im -> do
                          mUndo <- getUndoData db bh
                          case mUndo of
                            Just undoData ->
                              indexManagerConnectBlock im block
                                (udBlockUndo undoData) bh height
                            Nothing -> return ()

                      -- Persist the full block body (separate keyspace from
                      -- headers so that getblock can return raw bytes).
                      putBlock db bh block

                      -- Add header to chain (in-memory index + tip update).
                      -- minPowChecked=False: validateFullBlockIO has already
                      -- verified PoW, but we still run the too-little-chainwork
                      -- gate to reject submitblock calls that would import a
                      -- low-work fork tip (W97 G8).
                      void $ addHeader net hc (blockHeader block) False

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
                      -> PeerManager -> Mempool -> Maybe IndexManager
                      -> Block -> ChainEntry
                      -> IO (Either String ())
submitBlockSideBranch net db hc cache pm mp mIdxMgr block parent = do
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
      reorgRes <- doSideBranchReorg net db hc cache mp mIdxMgr parent block newWork
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
-- fork..new-tip.
--
-- == Pattern D — Multi-Block Atomicity (single-batch reorg) ==
--
-- The reorg accumulates ALL of the disconnect + connect 'BatchOp's
-- across the entire sequence and commits them in a SINGLE
-- 'writeBatch' at the end.  This delivers the atomicity property
-- the audit's "paradoxically safest" claim ASSUMED but the prior
-- (per-block 'connectBlock' / 'disconnectBlock') implementation
-- did NOT actually have:
--
--   * Crash before the final 'writeBatch'  → on-disk state unchanged
--     → restart sees pre-reorg chainstate, no partial reorg.
--   * Crash after the final 'writeBatch'   → on-disk state is fully
--     post-reorg → restart sees the new tip, no partial reorg.
--
-- The cache (UTXOCache) is mutated AFTER the disk commit succeeds,
-- so a process crash mid-mutation still leaves disk consistent and
-- the next process incarnation re-derives cache from disk.
--
-- During the build phase we maintain a virtual UTXO overlay
-- ('reorgOverlay') that tracks the post-disconnect / mid-connect
-- UTXO state without touching the cache or disk.  Connect-block
-- input lookups consult overlay → cache → disk (in that order),
-- so a tx in the connect chain that spends a UTXO restored by
-- the disconnect chain resolves correctly.
--
-- Reference: bitcoin-core/src/validation.cpp ActivateBestChain +
-- the Pattern D atomicity audit
-- (CORE-PARITY-AUDIT/_post-reorg-consistency-fleet-result-2026-05-05.md).
-- The cap on reorg size is 'maxReorgDepth' (=100) on the SUM of
-- disconnect + connect blocks.
doSideBranchReorg :: Network -> HaskoinDB -> HeaderChain -> UTXOCache
                  -> Mempool     -- ^ Mempool (for refill on disconnect; Pattern B)
                  -> Maybe IndexManager
                                 -- ^ Optional secondary indexes; mirrored
                                 --   block-by-block during the reorg so the
                                 --   BlockFilterIndex tracks the active chain.
                  -> ChainEntry  -- ^ parent of the new tip
                  -> Block       -- ^ new tip block
                  -> Integer     -- ^ new tip's cumulative work
                  -> IO (Either String ())
doSideBranchReorg net db hc cache mp mIdxMgr parent newTipBlock _newWork = do
  forkRes <- findSideBranchForkPoint hc db parent newTipBlock
  case forkRes of
    Left err -> return (Left err)
    Right (_forkHash, disconnectList, connectList) -> do
      let totalDepth = length disconnectList + length connectList
      if totalDepth > maxReorgDepth
        then return $ Left $
          "Reorg too deep: " ++ show totalDepth
          ++ " blocks (disconnect=" ++ show (length disconnectList)
          ++ "+connect=" ++ show (length connectList)
          ++ ") exceeds maxReorgDepth=" ++ show maxReorgDepth
        else do
          -- Phase A — pre-load undo data for every disconnect block.
          -- Fail fast on missing/corrupt undo before mutating anything.
          undoLoaded <- loadDisconnectUndo db disconnectList
          case undoLoaded of
            Left err -> return (Left err)
            Right disconnectUndo ->
              -- Phase B — pure batch build with virtual UTXO overlay.
              do
                buildRes <- buildReorgBatch net db cache hc
                              disconnectList disconnectUndo connectList
                case buildRes of
                  Left err -> return (Left err)
                  Right (allOps, newTipEntry) -> do
                    -- Phase C — single atomic disk commit.  Any
                    -- crash before this point leaves disk fully at
                    -- pre-reorg state.  Once this returns, the
                    -- reorg is durable.
                    writeBatch db (WriteBatch allOps)

                    -- Phase D — mirror the disk state into the
                    -- in-memory cache + header chain + mempool.
                    -- These mutations are local to this process;
                    -- if the process dies between writeBatch and
                    -- here, the next incarnation re-derives cache
                    -- from disk and the header chain from
                    -- PrefixBlockHeight.  No "split-brain" between
                    -- disk and the next live process.
                    forM_ (zip disconnectList disconnectUndo) $ \(blk, undo) ->
                      unapplyBlock cache blk undo
                    forM_ connectList $ \blk -> do
                      let bh = computeBlockHash (blockHeader blk)
                      entries <- readTVarIO (hcEntries hc)
                      case Map.lookup bh entries of
                        Just ce -> do
                          appRes <- applyBlockToCache cache net blk (ceHeight ce)
                          case appRes of
                            Right _ -> return ()
                            Left _  -> return ()  -- already validated; cache may have stale spend
                        Nothing -> return ()

                    -- Header chain pointer flip — same shape as the
                    -- pre-Pattern-D dispatcher.
                    atomically $ do
                      entries <- readTVar (hcEntries hc)
                      forM_ disconnectList $ \blk ->
                        let h = computeBlockHash (blockHeader blk)
                        in case Map.lookup h entries of
                             Just ce -> modifyTVar' (hcByHeight hc)
                               (Map.delete (ceHeight ce))
                             Nothing -> return ()
                      forM_ connectList $ \blk ->
                        let h = computeBlockHash (blockHeader blk)
                        in case Map.lookup h entries of
                             Just ce -> modifyTVar' (hcByHeight hc)
                               (Map.insert (ceHeight ce) h)
                             Nothing -> return ()
                      writeTVar (hcTip hc) newTipEntry
                      writeTVar (hcHeight hc) (ceHeight newTipEntry)

                    -- Pattern B — re-admit disconnected non-coinbase
                    -- txs into the mempool against the new tip.  Same
                    -- semantics as the pre-refactor inline call
                    -- inside disconnectMany (Mempool.hs:1290).  Done
                    -- AFTER the atomic disk commit so the mempool
                    -- never sees a tx whose corresponding chainstate
                    -- has not yet been persisted.
                    forM_ disconnectList $ \blk ->
                      blockDisconnected mp blk

                    -- Mirror the reorg into any opted-in secondary
                    -- indexes.  Disconnect-side first (delete entries
                    -- top-down so the in-memory chain pointer rewinds
                    -- to the fork point), then connect-side (append
                    -- entries bottom-up so each new entry chains off
                    -- the previous).  The IndexManager is intolerant
                    -- of out-of-order appends: doing this in the
                    -- wrong order produces a filter header that
                    -- doesn't match Core's chained recompute.
                    case mIdxMgr of
                      Nothing -> return ()
                      Just im -> do
                        -- Disconnect: oldTip first → fork-child last,
                        -- which matches @disconnectList@'s order.
                        forM_ disconnectList $ \blk -> do
                          let bh = computeBlockHash (blockHeader blk)
                          entries <- readTVarIO (hcEntries hc)
                          case Map.lookup bh entries of
                            Just ce ->
                              indexManagerDisconnectBlock im (ceHeight ce)
                            Nothing -> return ()
                        -- Connect: fork-child first → newTip last,
                        -- which matches @connectList@'s order.
                        forM_ connectList $ \blk -> do
                          let bh = computeBlockHash (blockHeader blk)
                          entries <- readTVarIO (hcEntries hc)
                          case Map.lookup bh entries of
                            Just ce -> do
                              mUndo <- getUndoData db bh
                              case mUndo of
                                Just u ->
                                  indexManagerConnectBlock im blk
                                    (udBlockUndo u) bh (ceHeight ce)
                                Nothing -> return ()
                            Nothing -> return ()

                    return (Right ())
  where
    -- | Pre-load + checksum-verify undo data for every disconnect
    -- block, failing fast if any is missing.  Returns the list in
    -- the same order as the input (disconnect order: oldTip first).
    loadDisconnectUndo :: HaskoinDB -> [Block]
                       -> IO (Either String [UndoData])
    loadDisconnectUndo _   []             = return (Right [])
    loadDisconnectUndo dbh (blk : rest) = do
      let bh  = computeBlockHash (blockHeader blk)
          prv = bhPrevBlock (blockHeader blk)
      undoR <- getUndoDataVerified dbh bh prv
      case undoR of
        Left err -> return $ Left $ "undo read failed for "
                                     ++ show bh ++ ": " ++ err
        Right u  -> do
          restR <- loadDisconnectUndo dbh rest
          return $ case restR of
            Left e   -> Left e
            Right us -> Right (u : us)

-- | Reorg-overlay state — virtual UTXO view used during batch build.
--
-- 'overlayAdded' carries entries the disconnect side restored OR
-- the connect side created.  'overlaySpent' carries outpoints the
-- connect side has consumed (or the disconnect side has removed
-- via "remove the outputs this block created").  Lookup order is
-- overlay → cache → disk; an overlay-spent entry shadows the cache
-- and disk so a connect block can spend a UTXO that exists on
-- disk but was consumed earlier in the reorg sequence.
data ReorgOverlay = ReorgOverlay
  { overlayAdded :: !(Map OutPoint Coin)
  , overlaySpent :: !(Set OutPoint)
  }

emptyOverlay :: ReorgOverlay
emptyOverlay = ReorgOverlay Map.empty Set.empty

-- | Look up an outpoint via overlay → cache → disk.  Returns the
-- 'Coin' (full Core-format with height + coinbase metadata) if the
-- outpoint is currently spendable in the virtual reorg state.
lookupOverlay :: ReorgOverlay -> UTXOCache -> HaskoinDB
              -> OutPoint -> IO (Maybe Coin)
lookupOverlay ov cache _db op
  | Set.member op (overlaySpent ov) = return Nothing
  | otherwise =
      case Map.lookup op (overlayAdded ov) of
        Just c  -> return (Just c)
        Nothing -> do
          mEntry <- lookupUTXO cache op
          return $ fmap entryToCoin mEntry
  where
    entryToCoin e = Coin { coinTxOut      = ueOutput e
                         , coinHeight     = ueHeight e
                         , coinIsCoinbase = ueCoinbase e
                         }

-- | Walk the disconnect+connect lists, building 'BatchOp's purely
-- (no disk writes, no cache mutation) and tracking a virtual UTXO
-- overlay.  The single returned 'BatchOp' list is the union of all
-- per-block disconnect+connect ops, ready for one 'writeBatch'.
--
-- @newTipEntry@ is returned alongside so the caller can flip the
-- in-memory tip pointer post-commit.
buildReorgBatch :: Network -> HaskoinDB -> UTXOCache -> HeaderChain
                -> [Block]      -- ^ disconnect list (oldTip first)
                -> [UndoData]   -- ^ undo data, parallel to disconnect list
                -> [Block]      -- ^ connect list (fork-child first)
                -> IO (Either String ([BatchOp], ChainEntry))
buildReorgBatch net db cache hc disList disUndos conList = do
  -- Phase 1: build disconnect ops + post-disconnect overlay.
  let disResult = disBuildPure (zip disList disUndos)
                               ([], emptyOverlay)
  case disResult of
    Left err -> return (Left err)
    Right (disOps, ov1) -> do
      -- Phase 2: build connect ops, threading the overlay so that
      -- a connect-side spend of a disconnect-side restoration
      -- resolves correctly.
      conResult <- buildConnectChain cache db hc net conList ov1 []
      case conResult of
        Left err -> return (Left err)
        Right (conOps, _ov2) -> do
          -- Validate the new tip is in the header index.
          entries <- readTVarIO (hcEntries hc)
          case conList of
            [] -> return $ Left "buildReorgBatch: empty connect list"
            _  -> do
              let newTipBlock = last conList
                  newTipHash  = computeBlockHash (blockHeader newTipBlock)
              case Map.lookup newTipHash entries of
                Nothing -> return $ Left $
                  "New tip not in header index: " ++ show newTipHash
                Just newTipEntry ->
                  return $ Right (disOps ++ conOps, newTipEntry)
  where
    -- Pure folder for the disconnect side.  Each step:
    --   * runs 'buildDisconnectBlockOps' for the (block, undo) pair
    --   * adds restored UTXOs to overlay
    --   * removes the block's own created UTXOs from overlay
    disBuildPure :: [(Block, UndoData)]
                 -> ([BatchOp], ReorgOverlay)
                 -> Either String ([BatchOp], ReorgOverlay)
    disBuildPure []                acc = Right acc
    disBuildPure ((blk, u) : rest) (opsAcc, ov) =
      let prevHash = bhPrevBlock (blockHeader blk)
      in case buildDisconnectBlockOps blk prevHash u of
        Left e   -> Left e
        Right bo ->
          let txns        = blockTxns blk
              nonCoinbase = drop 1 txns
              txUndos     = buTxUndo (udBlockUndo u)
              -- Restored prevouts go into the overlay (post-
              -- disconnect they're spendable again).
              restored =
                [ (txInPrevOutput inp,
                   Coin (tuOutput tin) (tuHeight tin) (tuCoinbase tin))
                | (tx, txUndo) <- zip nonCoinbase txUndos
                , (inp, tin)   <- zip (txInputs tx) (tuPrevOutputs txUndo)
                ]
              -- The block's own outputs cease to exist on the new
              -- chain — mark them spent in the overlay.
              created =
                [ OutPoint (computeTxId tx) (fromIntegral i)
                | tx       <- txns
                , (i, _)   <- zip [0 :: Int ..] (txOutputs tx)
                ]
              ov' = ov
                { overlayAdded =
                    foldr (\(op, c) m -> Map.insert op c m)
                          (overlayAdded ov)
                          restored
                , overlaySpent =
                    foldr Set.insert (overlaySpent ov) created
                }
              -- A restored prevout shadows any prior overlaySpent.
              ov'' = ov'
                { overlaySpent =
                    foldr (\(op, _) -> Set.delete op)
                          (overlaySpent ov') restored
                }
          in disBuildPure rest (opsAcc ++ bo, ov'')

    -- IO-flavoured folder for the connect side: needs cache reads
    -- to populate the spent-UTXO map for inputs that aren't in the
    -- overlay.
    buildConnectChain :: UTXOCache -> HaskoinDB -> HeaderChain
                      -> Network -> [Block] -> ReorgOverlay
                      -> [BatchOp]
                      -> IO (Either String ([BatchOp], ReorgOverlay))
    buildConnectChain _ _   _   _ []           ov ops = return (Right (ops, ov))
    buildConnectChain c dbh hc' n (blk : rest) ov ops = do
      entries <- readTVarIO (hcEntries hc')
      let bh = computeBlockHash (blockHeader blk)
      case Map.lookup bh entries of
        Nothing -> return $ Left $
          "Connect build: block " ++ show bh ++ " missing from header index"
        Just ce -> do
          let txns        = blockTxns blk
              nonCoinbase = drop 1 txns
              prevouts    = [ txInPrevOutput inp
                            | tx <- nonCoinbase, inp <- txInputs tx ]
          -- Resolve every prevout via overlay → cache → disk.
          spentRes <- foldM
            (\acc op -> case acc of
                Left e -> return (Left e)
                Right m -> do
                  mc <- lookupOverlay ov c dbh op
                  case mc of
                    Just c' -> return $ Right (Map.insert op c' m)
                    Nothing -> return $ Left $
                      "Connect build: missing prevout "
                      ++ show op ++ " for block " ++ show bh)
            (Right Map.empty)
            prevouts
          case spentRes of
            Left e        -> return (Left e)
            Right spentUtxos -> do
              let blockOps = buildConnectBlockOps n blk (ceHeight ce) spentUtxos
                  -- Newly created (non-unspendable) UTXOs go into
                  -- overlay so a follow-on connect block in the
                  -- same reorg can spend them.
                  txids = map computeTxId txns
                  coinbaseFlag txIdx = txIdx == (0 :: Int)
                  created =
                    [ ( OutPoint txid (fromIntegral i)
                      , Coin txout (ceHeight ce) (coinbaseFlag txIdx)
                      )
                    | (txIdx, txid, tx) <- zip3 [0..] txids txns
                    , (i, txout) <- zip [0..] (txOutputs tx)
                    , not (isUnspendable (txOutScript txout))
                    ]
                  ov' = ov
                    { overlayAdded =
                        foldr (\(op, c') m -> Map.insert op c' m)
                              (overlayAdded ov) created
                    -- Inputs are now spent in the virtual world.
                    , overlaySpent =
                        foldr Set.insert (overlaySpent ov) prevouts
                    }
                  ov'' = ov'
                    { overlayAdded =
                        foldr (\op m -> Map.delete op m)
                              (overlayAdded ov') prevouts
                    }
              buildConnectChain c dbh hc' n rest ov'' (ops ++ blockOps)

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

-- | Apply a block to the UTXO cache, generating undo data.
--
-- W93 audit (ConnectBlock + ConnectTip + UpdateCoins comprehensive):
-- this function used to skip a number of Bitcoin Core ConnectBlock
-- gates entirely.  It is the cache-path analog of 'connectBlock' and
-- gets called from the submitBlock arm and the side-branch reorg
-- dispatcher; it MUST mirror Core's per-tx checks or the cache and
-- the on-disk view drift on otherwise-rejectable blocks (the
-- on-disk path is gated by 'validateFullBlockIO' upstream, but the
-- cache path was bypassing every consensus check that Core does
-- inside ConnectBlock).  Gates added (Core validation.cpp:2295-2673):
--
--   * G3+G4 IsUnspendable filter on output insertion (AddCoins skip).
--   * G5    sigop cost accumulation + MAX_BLOCK_SIGOPS_COST.
--   * G6    bad-cb-amount (coinbase > subsidy + fees).
--   * G7    per-input MoneyRange (bad-txns-inputvalues-outofrange).
--   * G8    nValueIn >= valueOut (bad-txns-in-belowout).
--   * G9    accumulated-fee-outofrange.
--   * G12   BIP-68 sequence locks (Core 2549-2561).
--
-- Reference: bitcoin-core/src/validation.cpp:2295-2673 (ConnectBlock),
-- consensus/tx_verify.cpp:164-214 (CheckTxInputs).
applyBlockToCache :: UTXOCache -> Network -> Block -> Word32
                  -> IO (Either String UndoData)
applyBlockToCache cache net block height = do
  let bh = computeBlockHash (blockHeader block)
      txns = blockTxns block
      prevHash = bhPrevBlock (blockHeader block)
      flags = consensusFlagsAtHeight net height
      enforceBIP68 = bip68Active net height

  -- Collect TxUndo for each non-coinbase transaction
  txUndosRef <- newTVarIO []

  -- W93 Gate G9: running fee accumulator (also used for G6 bad-cb-amount).
  feesRef <- newIORef (0 :: Word64)
  -- W93 Gate G5: running sigop-cost accumulator.
  sigOpsRef <- newIORef (0 :: Int)
  -- In-flight TxOut view (drives sigop counting + intra-block spends).
  utxoViewRef <- newIORef (Map.empty :: Map OutPoint TxOut)

  -- Process each transaction
  results <- forM (zip [0..] txns) $ \(txIdx :: Int, tx) -> do
    if txIdx == 0  -- Coinbase
      then do
        -- W93 Gate G3: filter unspendable outputs from cache insertion
        -- (Core AddCoins: coins.cpp:91 — IsUnspendable scripts never
        -- enter the UTXO set; the BIP-141 witness-commitment OP_RETURN
        -- is the canonical case).
        atomically $ forM_ (zip [(0::Word32)..] (txOutputs tx)) $ \(outIdx, txout) ->
          unless (isUnspendable (txOutScript txout)) $ do
            let op = OutPoint (computeTxId tx) outIdx
                entry = UTXOEntry txout height True False
            addUTXO cache op entry
        let cbId = computeTxId tx
        modifyIORef' utxoViewRef $ \m ->
          Map.union m $ Map.fromList
            [ (OutPoint cbId (fromIntegral i), txout)
            | (i, txout) <- zip [0 :: Int ..] (txOutputs tx)
            ]
        -- W93 Gate G5: count coinbase sigops (legacy only — coinbase
        -- has no prevouts, so P2SH/witness components are zero).
        -- Check against MAX_BLOCK_SIGOPS_COST immediately because the
        -- non-coinbase branch may never execute (coinbase-only block).
        view <- readIORef utxoViewRef
        let SigOpCost c = getTransactionSigOpCost tx view flags
        acc0 <- readIORef sigOpsRef
        let acc1 = acc0 + c
        if acc1 > maxBlockSigOpsCost
          then return $ Left "bad-blk-sigops"
          else do
            writeIORef sigOpsRef acc1
            return (Right ())
      else do
        -- Regular transaction: spend inputs, create outputs
        -- Collect TxInUndo for each input
        inputUndosRef <- newTVarIO []

        -- Step 1: resolve all prevouts up front so we can run the
        -- value/range gates before any cache mutation.
        prevoutResults <- forM (txInputs tx) $ \inp -> do
          let op = txInPrevOutput inp
          mEntry <- lookupUTXO cache op
          return (op, mEntry)

        let missing = [op | (op, Nothing) <- prevoutResults]
        if not (null missing)
          then return $ Left $ "Missing UTXO: " ++ show (head missing)
          else do
            let resolved = [(op, e) | (op, Just e) <- prevoutResults]
                -- Check coinbase maturity (preserved from original).
                immature = [() | (_, e) <- resolved
                          , ueCoinbase e
                          , height - ueHeight e < fromIntegral (netCoinbaseMaturity net)]
            if not (null immature)
              then return $ Left "Coinbase not yet mature"
              else do
                -- W93 Gate G7: per-input MoneyRange.
                let inputValues = [ txOutValue (ueOutput e) | (_, e) <- resolved ]
                    sumInputs   = foldl (+) 0 inputValues
                    badInputs   = any (> maxMoney) inputValues
                                   || sumInputs > maxMoney
                if badInputs
                  then return $ Left "bad-txns-inputvalues-outofrange"
                  else do
                    let valueOut = sum (map txOutValue (txOutputs tx))
                    -- W93 Gate G8: nValueIn >= valueOut.
                    if sumInputs < valueOut
                      then return $ Left "bad-txns-in-belowout"
                      else do
                        let txfee = sumInputs - valueOut
                        accFees0 <- readIORef feesRef
                        let accFees1 = accFees0 + txfee
                        -- W93 Gate G9: accumulated-fee-outofrange.
                        if accFees1 > maxMoney
                          then return $ Left "bad-txns-accumulated-fee-outofrange"
                          else do
                            writeIORef feesRef accFees1
                            -- W93 Gate G12: BIP-68 sequence locks
                            -- (height-only — see applyBlock comment;
                            -- the time-based component is deferred to
                            -- BIP-112 OP_CSV in the script interpreter).
                            let seqOk
                                  | not enforceBIP68 = True
                                  | txVersion tx < 2 = True
                                  | otherwise =
                                      let prevHeights = [ueHeight e | (_, e) <- resolved]
                                          prevMTPs    = map (const 0) prevHeights
                                          lock = calculateSequenceLocks tx prevHeights prevMTPs True
                                          mh   = slMinHeight lock
                                      in mh < 0 || fromIntegral height > mh
                            if not seqOk
                              then return $ Left "bad-txns-nonfinal"
                              else do
                                -- W93 Gate G5: per-tx sigop cost.
                                view <- readIORef utxoViewRef
                                let SigOpCost c = getTransactionSigOpCost tx view flags
                                acc <- readIORef sigOpsRef
                                let acc' = acc + c
                                if acc' > maxBlockSigOpsCost
                                  then return $ Left "bad-blk-sigops"
                                  else do
                                    writeIORef sigOpsRef acc'
                                    -- Spend inputs.
                                    forM_ resolved $ \(op, entry) -> do
                                      let txInUndo = TxInUndo
                                            { tuOutput   = ueOutput entry
                                            , tuHeight   = ueHeight entry
                                            , tuCoinbase = ueCoinbase entry
                                            }
                                      atomically $ do
                                        void $ spendUTXO cache op
                                        modifyTVar' inputUndosRef (txInUndo :)

                                    -- Collect TxUndo
                                    inputUndos <- readTVarIO inputUndosRef
                                    let txUndo = TxUndo { tuPrevOutputs = reverse inputUndos }
                                    atomically $ modifyTVar' txUndosRef (txUndo :)

                                    -- W93 Gate G4: IsUnspendable filter
                                    -- on output insertion (Core AddCoins skip).
                                    atomically $ forM_ (zip [(0::Word32)..] (txOutputs tx)) $ \(outIdx, txout) ->
                                      unless (isUnspendable (txOutScript txout)) $ do
                                        let op = OutPoint (computeTxId tx) outIdx
                                            entry = UTXOEntry txout height False False
                                        addUTXO cache op entry
                                    -- Update in-flight view.
                                    let txid = computeTxId tx
                                        newView = Map.fromList
                                          [ (OutPoint txid (fromIntegral i), txout)
                                          | (i, txout) <- zip [0 :: Int ..] (txOutputs tx)
                                          ]
                                        spent = [op | (op, _) <- resolved]
                                    modifyIORef' utxoViewRef $ \m ->
                                      foldr Map.delete (Map.union newView m) spent
                                    return (Right ())

  case sequence results of
    Left err -> return (Left err)
    Right _ -> do
      -- W93 Gate G6: bad-cb-amount (Core 2611-2614).
      totalFees <- readIORef feesRef
      let maxCoinbase = blockReward height + totalFees
          cbValueOut  = sum (map txOutValue (txOutputs (head txns)))
      if cbValueOut > maxCoinbase
        then return $ Left $
          "bad-cb-amount: coinbase pays too much (actual=" ++ show cbValueOut
          ++ " vs limit=" ++ show maxCoinbase ++ ")"
        else do
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

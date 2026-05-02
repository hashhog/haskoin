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
import Haskoin.Consensus (Network(..), validateFullBlock, blockReward,
                           maxBlockWeight, maxBlockSigops, maxBlockSigOpsCost,
                           witnessScaleFactor,
                           txBaseSize, txTotalSize, difficultyAdjustment,
                           medianTimePast, ChainEntry(..), HeaderChain(..),
                           addHeader, computeMerkleRoot, ChainState(..),
                           consensusFlagsAtHeight, connectBlock,
                           getLegacySigOpCount)
import Haskoin.Storage (HaskoinDB, UTXOCache(..), UTXOEntry(..),
                         lookupUTXO, UndoData(..), addUTXO, spendUTXO,
                         TxInUndo(..), TxUndo(..), BlockUndo(..), mkUndoData,
                         putBlock, Coin(..))
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

  -- Get current chain state for validation
  tip <- readTVarIO (hcTip hc)
  let height = ceHeight tip + 1

  -- Build UTXO map for validation. We carry full Core-format
  -- 'Coin' (TxOut + height + coinbase flag) so 'connectBlock' can
  -- record byte-identical undo entries; 'validateFullBlock' only
  -- needs the TxOut projection.
  utxoMap <- buildBlockUTXOMap cache block
  let utxoTxOutMap = fmap coinTxOut utxoMap

  -- Build chain state for validation
  let cs = ChainState
        { csHeight = ceHeight tip
        , csBestBlock = ceHash tip
        , csChainWork = ceChainWork tip
        , csMedianTime = ceMedianTime tip
        , csFlags = consensusFlagsAtHeight net height
        }

  -- Validate the block (always verify scripts for locally minted blocks)
  case validateFullBlock net cs False block utxoTxOutMap of
    Left err -> return $ Left $ "Block validation failed: " ++ err
    Right () -> do
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

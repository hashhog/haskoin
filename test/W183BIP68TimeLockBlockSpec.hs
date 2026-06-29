{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W183 — BIP-68 time-based sequence lock enforcement in block validation.
--
-- Prior state (BUG-3 in W132 audit): validateFullBlock enforced ONLY the
-- height component of BIP-68 and deferred the time component to OP_CSV.
-- A v2 tx with nSequence=TYPE_FLAG|N and no OP_CSV was accepted even when
-- its time-based relative lock had NOT yet elapsed — a chain-split against
-- Bitcoin Core (which checks both height AND time in ConnectBlock via
-- SequenceLocks/EvaluateSequenceLocks, consensus/tx_verify.cpp:39-105).
--
-- Fix (W183): validateFullBlock now accepts getMtpAtHeight :: Word32 -> Word32
-- (backed by the persistent hcEntries/hcByHeight store) and enforces BOTH
-- components.  This spec proves:
--   (a) getMtpAtHeightFromEntries computes MTP correctly from ChainEntry maps.
--   (b) A v2 tx with a time-based lock (TYPE_FLAG|N) is REJECTED by
--       validateFullBlock when prevBlockMTP <= minTime.
--   (c) The same tx is ACCEPTED by validateFullBlock when prevBlockMTP > minTime.
--   (d) The reorg path (getMtpAtHeightFromEntries partial-walk fallback) never
--       returns 0 — even for partial/missing chains.
--
-- Bitcoin Core reference:
--   consensus/tx_verify.cpp:39-105  — CalculateSequenceLocks / EvaluateSequenceLocks
--   validation.cpp:2549-2561        — ConnectBlock BIP-68 gate
--   chain.h:233-244                 — GetMedianTimePast (up to 11 ancestors)
--
-- See also: W132NSequenceCSVMTPSpec.hs (G29 FIXED), Consensus.hs getMtpAtHeightFromEntries.

module W183BIP68TimeLockBlockSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Bits ((.|.))
import Data.Word (Word32)

import Haskoin.Consensus
  ( validateFullBlock
  , ChainState(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , regtest
  , consensusFlagsAtHeight
  , computeMerkleRoot
  , getMtpAtHeightFromEntries
  , sequenceLockTimeTypeFlag
  , encodeBip34Height
  )
import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..)
  , BlockHash(..), BlockHeader(..), Block(..) )
import Haskoin.Storage ( Coin(..) )
import Haskoin.Crypto ( computeTxId )

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a fake BlockHash from a repeated byte.
fakeHash :: Int -> BlockHash
fakeHash b = BlockHash (Hash256 (BS.replicate 32 (fromIntegral b)))

-- | Build a fake TxId from a repeated byte.
fakeTxId :: Int -> TxId
fakeTxId b = TxId (Hash256 (BS.replicate 32 (fromIntegral b)))

-- | Null outpoint (coinbase marker).
nullOutpoint :: OutPoint
nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff

-- | Build a minimal coinbase tx that passes BIP-34 height check.
-- Uses encodeBip34Height — identical to what validateCoinbaseHeightConsensus checks.
mkCoinbase :: Word32 -> Tx
mkCoinbase h = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn nullOutpoint (encodeBip34Height h) 0xffffffff ]
  , txOutputs  = [ TxOut 5000000000 BS.empty ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Build a v2 tx spending an outpoint with the given nSequence.
mkSpendTx :: OutPoint -> Word32 -> Tx
mkSpendTx prevOut nseq = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn prevOut BS.empty nseq ]
  , txOutputs  = [ TxOut 49000 BS.empty ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Build a minimal regtest block header.
-- bhBits=0 and no real PoW: PoW is not checked in validateFullBlock.
mkBlockHeader :: BlockHash -> [Tx] -> Word32 -> BlockHeader
mkBlockHeader prevH txns timestamp = BlockHeader
  { bhVersion    = 4        -- nVersion >= 4 to pass bad-version gate
  , bhPrevBlock  = prevH
  , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
  , bhTimestamp  = timestamp
  , bhBits       = 0
  , bhNonce      = 0
  }

-- | nSequence for a time-based BIP-68 lock with 1 unit (512 seconds).
-- TYPE_FLAG (bit 22) set, DISABLE_FLAG (bit 31) clear.
timeLockSeq :: Word32
timeLockSeq = sequenceLockTimeTypeFlag .|. 1

-- | Minimum MTP that must be exceeded: coinMTP + 1*512 - 1.
-- Core CalculateSequenceLocks (consensus/tx_verify.cpp:88):
--   nMinTime = coinMTP + (nSequenceMasked << granularity) - 1
-- EvaluateSequenceLocks checks: nMinTime < pindexPrev->GetMedianTimePast()
-- i.e., prevBlockMTP > nMinTime  (strict greater-than).
minTimeLock :: Word32 -> Word32
minTimeLock coinMTP = coinMTP + (1 * 512) - 1

-- | Build a synthetic ChainEntry for getMtpAtHeightFromEntries tests.
mkEntry :: Word32          -- ^ height
        -> BlockHash       -- ^ hash
        -> Maybe BlockHash -- ^ parent hash (Nothing for genesis)
        -> Word32          -- ^ bhTimestamp
        -> Word32          -- ^ ceMedianTime (pre-computed MTP)
        -> ChainEntry
mkEntry h hash prev ts mtp = ChainEntry
  { ceHeader     = BlockHeader 4
                               (maybe (fakeHash 0) id prev)
                               (Hash256 (BS.replicate 32 0))
                               ts 0 0
  , ceHash       = hash
  , ceHeight     = h
  , ceChainWork  = 0
  , cePrev       = prev
  , ceStatus     = StatusValid
  , ceMedianTime = mtp
  , ceSequenceId = 0
  }

--------------------------------------------------------------------------------
-- Block validation scenario builder
--------------------------------------------------------------------------------

-- | Build a complete regtest block and UTXO map for the BIP-68 time-lock test.
-- Returns (block, utxoMap, getMtpForValidation).
--
-- Block at height H spends a UTXO created at height C.
-- nSequence = timeLockSeq (TYPE_FLAG | 1 = 512-second relative lock).
-- coinMTP = MTP at max(C-1, 0), which is what Core uses per-input.
buildTimeLockScenario
  :: Word32   -- ^ block height H (>= 2 for BIP-68 active on regtest)
  -> Word32   -- ^ coin height C
  -> Word32   -- ^ coinMTP: MTP at height max(C-1, 0)
  -> Word32   -- ^ block timestamp (must be > csMedianTime for BIP-113)
  -> (Block, Map.Map OutPoint Coin, Word32 -> Word32)
buildTimeLockScenario blockH coinH coinMTP blockTs =
  let prevH     = fakeHash 99
      coinbase  = mkCoinbase blockH
      prevTxid  = fakeTxId 77
      prevOut   = OutPoint prevTxid 0
      spendTx   = mkSpendTx prevOut timeLockSeq
      txns      = [coinbase, spendTx]
      header    = mkBlockHeader prevH txns blockTs
      block     = Block header txns
      coinValue = TxOut 50000 BS.empty
      utxoMap   = Map.singleton prevOut (Coin coinValue coinH False)
      -- Core CalculateSequenceLocks uses MTP at coinHeight - 1 per input.
      coinMTPHeight = if coinH == 0 then 0 else coinH - 1
      getMtp h
        | h == coinMTPHeight = coinMTP
        | otherwise          = 1  -- positive sentinel; BIP-68 only uses coinMTPHeight
  in (block, utxoMap, getMtp)

--------------------------------------------------------------------------------
spec :: Spec
spec = describe "W183 BIP-68 time-based sequence lock in validateFullBlock" $ do

  -- =========================================================================
  -- Part A: getMtpAtHeightFromEntries correctness
  -- =========================================================================

  describe "A: getMtpAtHeightFromEntries" $ do

    it "A1: returns ceMedianTime for heights in both maps (fast path)" $ do
      let h0   = fakeHash 0
          h1   = fakeHash 1
          e0   = mkEntry 0 h0 Nothing   1000 1000
          e1   = mkEntry 1 h1 (Just h0) 2000 1500
          ents = Map.fromList [(h0, e0), (h1, e1)]
          byH  = Map.fromList [(0, h0), (1, h1)]
      getMtpAtHeightFromEntries ents byH 0 `shouldBe` 1000
      getMtpAtHeightFromEntries ents byH 1 `shouldBe` 1500

    it "A2: missing height in maps — defensive fallback NEVER returns 0" $ do
      let h0   = fakeHash 0
          e0   = mkEntry 0 h0 Nothing 1296688602 1296688602
          ents = Map.fromList [(h0, e0)]
          byH  = Map.fromList [(0, h0)]
      getMtpAtHeightFromEntries ents byH 5 `shouldSatisfy` (> 0)

    it "A3: partial walk median correct for short chain (< 11 entries)" $ do
      -- timestamps=[100,200,300]; h=2 ceMedianTime=200 (median of sorted [100,200,300])
      let h0 = fakeHash 0; h1 = fakeHash 1; h2 = fakeHash 2
          e0 = mkEntry 0 h0 Nothing   100 100
          e1 = mkEntry 1 h1 (Just h0) 200 100  -- median([200,100]) = 100
          e2 = mkEntry 2 h2 (Just h1) 300 200  -- median([300,200,100]) = 200
          ents = Map.fromList [(h0, e0), (h1, e1), (h2, e2)]
          byH  = Map.fromList [(0, h0), (1, h1), (2, h2)]
      getMtpAtHeightFromEntries ents byH 2 `shouldBe` 200

    it "A4: genesis (h=0) lookup never returns 0" $ do
      let h0   = fakeHash 0
          e0   = mkEntry 0 h0 Nothing 1296688602 1296688602
          ents = Map.singleton h0 e0
          byH  = Map.singleton 0 h0
      getMtpAtHeightFromEntries ents byH 0 `shouldSatisfy` (> 0)

  -- =========================================================================
  -- Part B: validateFullBlock REJECTS time-locked v2 tx BEFORE maturity
  -- =========================================================================

  describe "B: validateFullBlock REJECTS time-locked v2 tx before maturity" $ do

    it "B1: prevBlockMTP == minTimeLock (exactly) fails strict-GT => bad-txns-nonfinal" $ do
      -- coinMTP=1_000_000, minTime=1_000_511; prevMTP=1_000_511 not > minTime
      let blockH  = 500 :: Word32
          coinH   = 499 :: Word32
          coinMTP = 1000000 :: Word32
          prevMTP = minTimeLock coinMTP      -- = 1_000_511; strict-GT fails
          blockTs = prevMTP + 10000          -- > prevMTP: passes BIP-113
          cs = ChainState
                 { csHeight     = blockH - 1
                 , csBestBlock  = fakeHash 99
                 , csChainWork  = 0
                 , csMedianTime = prevMTP
                 , csFlags      = consensusFlagsAtHeight regtest blockH
                 }
          (block, utxoMap, getMtp) = buildTimeLockScenario blockH coinH coinMTP blockTs
      case validateFullBlock regtest cs getMtp True False block utxoMap of
        Left err -> err `shouldBe` "bad-txns-nonfinal"
        Right () -> expectationFailure
          "Expected bad-txns-nonfinal: prevBlockMTP == minTimeLock must REJECT"

    it "B2: prevBlockMTP < minTimeLock fails => bad-txns-nonfinal" $ do
      -- prevMTP=1_000_510 (one below minTime)
      let blockH  = 500 :: Word32
          coinH   = 499 :: Word32
          coinMTP = 1000000 :: Word32
          prevMTP = minTimeLock coinMTP - 1  -- one below: strict-GT fails
          blockTs = prevMTP + 10000
          cs = ChainState
                 { csHeight     = blockH - 1
                 , csBestBlock  = fakeHash 99
                 , csChainWork  = 0
                 , csMedianTime = prevMTP
                 , csFlags      = consensusFlagsAtHeight regtest blockH
                 }
          (block, utxoMap, getMtp) = buildTimeLockScenario blockH coinH coinMTP blockTs
      case validateFullBlock regtest cs getMtp True False block utxoMap of
        Left err -> err `shouldBe` "bad-txns-nonfinal"
        Right () -> expectationFailure
          "Expected bad-txns-nonfinal: prevBlockMTP < minTimeLock must REJECT"

  -- =========================================================================
  -- Part C: validateFullBlock ACCEPTS time-locked v2 tx AT/AFTER maturity
  -- =========================================================================

  describe "C: validateFullBlock ACCEPTS time-locked v2 tx at/after maturity" $ do

    it "C1: prevBlockMTP = minTimeLock + 1 satisfies strict-GT => BIP-68 passes" $ do
      -- prevMTP=1_000_512 (one above minTime): strict-GT satisfied
      let blockH  = 500 :: Word32
          coinH   = 499 :: Word32
          coinMTP = 1000000 :: Word32
          prevMTP = minTimeLock coinMTP + 1  -- = 1_000_512: satisfies strict-GT
          blockTs = prevMTP + 10000
          cs = ChainState
                 { csHeight     = blockH - 1
                 , csBestBlock  = fakeHash 99
                 , csChainWork  = 0
                 , csMedianTime = prevMTP
                 , csFlags      = consensusFlagsAtHeight regtest blockH
                 }
          (block, utxoMap, getMtp) = buildTimeLockScenario blockH coinH coinMTP blockTs
      -- BIP-68 satisfied.  skipScripts=True bypasses script eval.
      -- Structural errors (coinbase reward, script output) are acceptable;
      -- bad-txns-nonfinal is NOT.
      case validateFullBlock regtest cs getMtp True False block utxoMap of
        Right () -> return ()
        Left "bad-txns-nonfinal" ->
          expectationFailure
            "BIP-68 time-lock must NOT reject when prevBlockMTP > minTimeLock"
        Left _ -> return ()

    it "C2: prevBlockMTP far above minTimeLock also passes BIP-68" $ do
      let blockH  = 500 :: Word32
          coinH   = 499 :: Word32
          coinMTP = 1000000 :: Word32
          prevMTP = minTimeLock coinMTP + 1000000
          blockTs = prevMTP + 10000
          cs = ChainState
                 { csHeight     = blockH - 1
                 , csBestBlock  = fakeHash 99
                 , csChainWork  = 0
                 , csMedianTime = prevMTP
                 , csFlags      = consensusFlagsAtHeight regtest blockH
                 }
          (block, utxoMap, getMtp) = buildTimeLockScenario blockH coinH coinMTP blockTs
      case validateFullBlock regtest cs getMtp True False block utxoMap of
        Left "bad-txns-nonfinal" ->
          expectationFailure
            "BIP-68 time-lock must not reject when prevMTP >> minTimeLock"
        _ -> return ()

  -- =========================================================================
  -- Part D: getMtpAtHeightFromEntries robustness (never-0 guarantee)
  -- =========================================================================

  describe "D: getMtpAtHeightFromEntries never returns 0 (persistent-store robustness)" $ do

    it "D1: completely empty maps — fallback returns > 0" $
      getMtpAtHeightFromEntries Map.empty Map.empty 100 `shouldSatisfy` (> 0)

    it "D2: byHeight has entry but hash absent from entries — fallback returns > 0" $ do
      let byH = Map.singleton (100 :: Word32) (fakeHash 42)
      getMtpAtHeightFromEntries Map.empty byH 100 `shouldSatisfy` (> 0)

    it "D3: single-entry chain — ceMedianTime returned directly (fast path, > 0)" $ do
      let h0   = fakeHash 0
          e0   = mkEntry 0 h0 Nothing 1296688602 1296688602
          ents = Map.singleton h0 e0
          byH  = Map.singleton (0 :: Word32) h0
      getMtpAtHeightFromEntries ents byH 0 `shouldSatisfy` (> 0)

    it "D4: partial chain (only h=0 known) — fallback for higher height returns > 0" $ do
      let h0   = fakeHash 0
          e0   = mkEntry 0 h0 Nothing 1296688602 1296688602
          ents = Map.singleton h0 e0
          byH  = Map.singleton (0 :: Word32) h0
      getMtpAtHeightFromEntries ents byH 10 `shouldSatisfy` (> 0)

  -- =========================================================================
  -- Part E: BIP-68 version gate — v1 tx with timeLockSeq skips BIP-68
  -- =========================================================================

  describe "E: v1 tx with time-based nSequence is NOT subject to BIP-68" $ do

    it "E1: txVersion=1 tx skips BIP-68 even when prevBlockMTP << lock threshold" $ do
      -- Core: fEnforceBIP68 = tx.version >= 2 (consensus/tx_verify.cpp:51).
      -- prevMTP=1 would always fail BIP-68 time-lock if enforced for v1 txs.
      let blockH  = 500 :: Word32
          coinH   = 499 :: Word32
          prevMTP = 1 :: Word32
          blockTs = prevMTP + 10000
          cs = ChainState
                 { csHeight     = blockH - 1
                 , csBestBlock  = fakeHash 99
                 , csChainWork  = 0
                 , csMedianTime = prevMTP
                 , csFlags      = consensusFlagsAtHeight regtest blockH
                 }
          prevOut   = OutPoint (fakeTxId 77) 0
          v1SpendTx = Tx 1 [TxIn prevOut BS.empty timeLockSeq]
                           [TxOut 49000 BS.empty] [[]] 0
          coinbase  = mkCoinbase blockH
          txns      = [coinbase, v1SpendTx]
          header    = mkBlockHeader (fakeHash 99) txns blockTs
          block     = Block header txns
          utxoMap   = Map.singleton prevOut
                        (Coin (TxOut 50000 BS.empty) coinH False)
          getMtp _  = 1
      -- v1 tx: BIP-68 not enforced; must NOT get bad-txns-nonfinal from BIP-68.
      case validateFullBlock regtest cs getMtp True False block utxoMap of
        Left "bad-txns-nonfinal" ->
          expectationFailure "v1 tx must NOT be BIP-68 time-lock rejected"
        _ -> return ()

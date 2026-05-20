{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W163 — assumeUTXO snapshot-recovery code-prep regression suite.
--
-- This suite pins the two code prerequisites that had to be in place
-- before haskoin's mainnet node could recover from the W162 chainstate
-- corruption (UTXO-view best-block stuck at genesis) by loading a
-- Core-format assumeUTXO snapshot at height 944183.
--
-- == Prerequisite 1 — the 944183 assumeUTXO checkpoint ==
--
-- '--load-snapshot' validates a snapshot's base height + base blockhash
-- + serialized-UTXO hash against the hardcoded 'netAssumeUtxo' table
-- ('checkAssumeutxoWhitelist' / 'verifySnapshot'), exactly like
-- rustoshi's 'assumeutxo_for_blockhash' strict check.  haskoin's
-- mainnet table previously held only the four Core entries
-- (840k/880k/910k/935k); the hashhog-local recovery snapshot at 944183
-- had to be added.  Canonical values (cross-checked against rustoshi
-- crates/consensus/src/params.rs and blockbrew
-- internal/consensus/assumeutxo.go):
--
--   height           944183
--   base blockhash   0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817
--   txoutset hash    2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8
--   chain tx count   1334000000
--
-- == Prerequisite 2 — snapshot-base handling on the recovery path ==
--
-- rustoshi and ouroboros both had a BIP-113 median-time-past bug when
-- loading an assumeUTXO snapshot: the first post-snapshot block's MTP
-- walk reached below the snapshot base, where no headers are stored,
-- and the MTP collapsed.
--
-- haskoin's MTP functions ('medianTimePast' / 'computeEntryMtp') do NOT
-- have that bug.  They walk the in-memory header chain, which
-- 'initHeaderChainFromDB' loads strictly sequentially from genesis and
-- 'addHeader' only ever extends from a present parent — so the chain is
-- ALWAYS genesis-contiguous; there is no way for block 944183 to be
-- present without its 10 ancestors.  '--load-snapshot' additionally
-- REQUIRES the snapshot base header to already be in that chain
-- (app/Main.hs ~853).  Therefore block 944184's 11-block MTP window
-- [944173..944183] is fully populated and the median is exact.  The G1
-- tests below pin that property AND pin Core 'GetMedianTimePast'
-- parity for a genuinely-partial window near genesis (defense in
-- depth).
--
-- haskoin's REAL snapshot-recovery bug was different: the W162 startup
-- reconciliation recovers the connected-block tip from per-block undo
-- records, assuming they occupy a contiguous range [1..U].  A snapshot
-- import writes the UTXO set + the best-block pointer but NO undo
-- records, so the undo range is actually [base+1 .. U].  The plain
-- search probed block 1, found no undo record, reported tip = 0, and
-- seeded block download from height 1 — every downloaded block then
-- failed the ConnectBlock G1 gate (hashPrevBlock == GetBestBlock(),
-- validation.cpp:2333) and the node wedged.  The fix records the
-- snapshot base hash durably ('putSnapshotBaseHash', Core's
-- chainstate_snapshot/base_blockhash analogue) and uses it as the
-- undo-record search floor.  The G2 tests below pin that resume-height
-- logic via 'reconcileTipPure' (a faithful mirror of the snapshot-aware
-- branch in app/Main.hs's startup reconciliation) and pin the durable
-- snapshot-base storage round-trip.
--
-- References:
--   bitcoin-core/src/chain.h:233-244        GetMedianTimePast
--   bitcoin-core/src/validation.cpp:2333    ConnectBlock G1 assert
--   bitcoin-core/src/validation.cpp:4546    Chainstate::LoadChainTip
--   bitcoin-core/src/node/utxo_snapshot.cpp WriteSnapshotBaseBlockhash
--   bitcoin-core/src/kernel/chainparams.cpp m_assumeutxo_data
module W163SnapshotRecoverySpec (spec) where

import Test.Hspec
import Control.Monad (forM_)
import Data.List (sort)
import Data.Word (Word8, Word32)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

import Haskoin.Types (BlockHash(..), Hash256(..), BlockHeader(..))
import Haskoin.Consensus
  ( mainnet
  , netAssumeUtxo
  , AssumeUtxoParams(..)
  , assumeUtxoForHeight
  , assumeUtxoForBlockHash
  , checkAssumeutxoWhitelist
  , hexToBS
  , hashFromHex
  , ChainEntry(..)
  , BlockStatus(..)
  , medianTimePast
  , computeEntryMtp
  )
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , putSnapshotBaseHash, getSnapshotBaseHash, deleteSnapshotBaseHash
  )
import qualified Haskoin.Storage as S

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

-- ============================================================
-- Canonical 944183 snapshot constants (cross-impl pinned)
-- ============================================================

snap944183HashHex :: String
snap944183HashHex =
  "0000000000000000000146180a1603839d0e9ac6c00d17a5ab45323398ced817"

snap944183TxoutsetHex :: String
snap944183TxoutsetHex =
  "2eaf71725669a83c1c7947517b84c09b0d65f4e7c813087c74840320bcbc88a8"

snap944183Height :: Word32
snap944183Height = 944183

snap944183TxCount :: Word32
snap944183TxCount = 1334000000

-- ============================================================
-- Helpers
-- ============================================================

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-w163-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

-- | Build a 'Hash256' from a display-order hex string WITHOUT reversal
-- — identical to 'Haskoin.Consensus.hexToHash256' (which is not
-- exported).  This is how 'aupHashSerialized' is stored for every
-- mainnet assumeUTXO entry.
hexToHash256 :: String -> Hash256
hexToHash256 = Hash256 . hexToBS

-- | 32 deterministic, distinct bytes for a height — used to fabricate
-- block hashes for the synthetic MTP-walk chains.  Distinctness across
-- heights is all that matters (the entries map is keyed by hash).
synthHash :: Word32 -> BlockHash
synthHash h = BlockHash (Hash256 (BS.pack bytes))
  where
    b :: Int -> Word8
    b shft = fromIntegral ((h `div` (2 ^ (shft * 8))) `mod` 256)
    -- 4 height-derived bytes, padded to 32 with the height's low byte +1
    -- so even height 0 yields a non-zero hash.
    bytes = [b 0, b 1, b 2, b 3]
         ++ replicate 28 (fromIntegral (h `mod` 255) + 1)

-- | Build a genesis-contiguous 'ChainEntry' map from a list of
-- (height, timestamp) pairs (ascending by height), threaded by
-- 'cePrev'.  This mirrors exactly the shape 'initHeaderChainFromDB' /
-- 'addHeader' produce: every non-genesis entry's 'cePrev' points at a
-- present entry.  Returns the map plus the highest hash.
buildChain :: [(Word32, Word32)] -> (Map.Map BlockHash ChainEntry, BlockHash)
buildChain pairs =
  let go _ [] = []
      go mPrev ((h, ts) : rest) =
        let hh = synthHash h
            ce = ChainEntry
                   { ceHeader = BlockHeader
                       { bhVersion    = 0x20000000
                       , bhPrevBlock  = maybe (synthHash 0) id mPrev
                       , bhMerkleRoot = Hash256 (BS.replicate 32 0x11)
                       , bhTimestamp  = ts
                       , bhBits       = 0x17000000
                       , bhNonce      = 0
                       }
                   , ceHash       = hh
                   , ceHeight     = h
                   , ceChainWork  = fromIntegral h
                   , cePrev       = mPrev
                   , ceStatus     = StatusValid
                   , ceMedianTime = ts  -- not consulted by medianTimePast
                   }
        in (hh, ce) : go (Just hh) rest
      entries = go Nothing pairs
  in (Map.fromList entries, fst (last entries))

-- | Reference median-time-past: Bitcoin Core 'GetMedianTimePast'
-- semantics — median of the last (up to) 11 block timestamps, stopping
-- early at a null parent.  Used as the oracle for 'medianTimePast'.
refMTP :: [Word32] -> Word32
refMTP windowDescending =
  let s = sort (take 11 windowDescending)
  in s !! (length s `div` 2)

-- ============================================================
-- Pure mirror of the snapshot-aware startup reconciliation
-- ============================================================

-- | Faithful pure mirror of the connected-tip computation in
-- app/Main.hs's startup reconciliation (the snapshot-aware branch
-- added for W163).
--
-- Inputs:
--   * 'mSnapBaseHeight' — height of the snapshot base IF a snapshot
--     base hash is recorded under the 0x53 key ('getSnapshotBaseHash'),
--     else Nothing.
--   * 'undoAt' — does the block at this height have a persisted undo
--     record?  Block connection writes the undo record atomically with
--     the UTXO mutations, so undo records form a contiguous range:
--     [1..U] for a genesis-up chainstate, [base+1..U] for a
--     snapshot-bootstrapped one.
--   * 'headerTip' — highest known header height.
--
-- Output: the connected-block tip the node will resume download from
-- (download starts at result+1).
reconcileTipPure
  :: Maybe Word32       -- ^ snapshot base height, if recorded
  -> (Word32 -> Bool)   -- ^ undo record present at this height?
  -> Word32             -- ^ header-chain tip height
  -> Word32             -- ^ recovered connected-block tip
reconcileTipPure mSnapBaseHeight undoAt headerTip
  | headerTip == 0 = 0
  | otherwise =
      case mSnapBaseHeight of
        Just base
          | base >= headerTip       -> base
          | not (undoAt (base + 1)) -> base                 -- no post-snapshot block yet
          | otherwise               -> search (base + 1) headerTip
        Nothing
          | not (undoAt 1)          -> 0                     -- UTXO set never left genesis
          | otherwise               -> search 1 headerTip
  where
    -- highest contiguous height with an undo record, in [lo..hi]
    search lo hi
      | lo >= hi  = lo
      | otherwise =
          let mid = lo + (hi - lo + 1) `div` 2
          in if undoAt mid then search mid hi else search lo (mid - 1)

-- ============================================================
-- Spec
-- ============================================================

spec :: Spec
spec = do

  ----------------------------------------------------------------
  describe "W163 Prerequisite 1 — 944183 assumeUTXO checkpoint" $ do

    it "G1.1: netAssumeUtxo mainnet contains a 944183 entry" $
      lookup 944183 (netAssumeUtxo mainnet) `shouldNotBe` Nothing

    it "G1.2: assumeUtxoForHeight mainnet 944183 returns the entry" $
      case assumeUtxoForHeight mainnet 944183 of
        Just p  -> aupHeight p `shouldBe` 944183
        Nothing -> expectationFailure "mainnet 944183 missing from netAssumeUtxo"

    it "G1.3: checkAssumeutxoWhitelist accepts 944183 (the load gate)" $
      -- This is the exact gate '--load-snapshot' runs (app/Main.hs:864).
      -- Without the new entry it would FATAL with the Core-strict
      -- "refusing to load snapshot" message.
      checkAssumeutxoWhitelist mainnet 944183 `shouldBe` Right ()

    it "G1.4: 944183 base blockhash matches the verified snapshot file" $
      case assumeUtxoForHeight mainnet 944183 of
        Just p  -> aupBlockHash p `shouldBe` hashFromHex snap944183HashHex
        Nothing -> expectationFailure "mainnet 944183 missing"

    it "G1.5: 944183 serialized-UTXO hash matches the verified snapshot file" $
      -- 'verifySnapshot' compares this byte-for-byte against
      -- 'computeUtxoHash' of the loaded coin set.  Display (uint256)
      -- order, matching the four Core entries and rustoshi/blockbrew.
      case assumeUtxoForHeight mainnet 944183 of
        Just p  -> aupHashSerialized p `shouldBe` hexToHash256 snap944183TxoutsetHex
        Nothing -> expectationFailure "mainnet 944183 missing"

    it "G1.6: 944183 chain-tx count is the cross-impl value 1334000000" $
      case assumeUtxoForHeight mainnet 944183 of
        Just p  -> aupChainTxCount p `shouldBe` fromIntegral snap944183TxCount
        Nothing -> expectationFailure "mainnet 944183 missing"

    it "G1.7: height-first and hash-first lookups agree for 944183" $
      -- 'verifySnapshot' / 'activateSnapshot' consult both; they must
      -- name the same entry.
      case assumeUtxoForHeight mainnet 944183 of
        Just p ->
          fmap aupHeight (assumeUtxoForBlockHash mainnet (aupBlockHash p))
            `shouldBe` Just 944183
        Nothing -> expectationFailure "mainnet 944183 missing"

    it "G1.8: the four original Core entries are still present & intact" $ do
      -- Guard against an accidental edit to the existing table.
      let heights = map fst (netAssumeUtxo mainnet)
      forM_ [840000, 880000, 910000, 935000] $ \h ->
        (h `elem` heights) `shouldBe` True

    it "G1.9: every mainnet assumeUTXO entry's stored height matches its key" $
      forM_ (netAssumeUtxo mainnet) $ \(k, p) ->
        aupHeight p `shouldBe` k

  ----------------------------------------------------------------
  describe "W163 Prerequisite 2a — BIP-113 MTP over the snapshot base" $ do

    it "G2.1: medianTimePast medians the full 11-block window straddling 944183" $ do
      -- Block 944184's MTP (BIP-113 / IsFinalTx nLockTimeCutoff) is the
      -- median of timestamps for heights 944173..944183.  haskoin's
      -- header chain is genesis-contiguous, so all 11 are present and
      -- the median is exact — NOT collapsed to 0 (the rustoshi/
      -- ouroboros snapshot-base bug).
      let -- 11 ancestors with strictly increasing, irregular timestamps.
          tss   = [ 1775649000, 1775649300, 1775649520, 1775649900
                  , 1775650050, 1775650208, 1775650400, 1775650600
                  , 1775650810, 1775651000, 1775651300 ]
          pairs = zip [944173 ..] tss
          (entries, tipHash) = buildChain pairs
          got = medianTimePast entries tipHash
      -- 11 timestamps -> median is the 6th smallest = index 5.
      got `shouldBe` refMTP (reverse tss)
      got `shouldBe` (tss !! 5)

    it "G2.2: medianTimePast over a 4193xx-style window is exact" $ do
      -- Spot-check at an unrelated mid-chain height to confirm the walk
      -- is not height-sensitive.
      let tss   = [ 1700000000, 1700000600, 1700001200, 1700001800
                  , 1700002400, 1700003000, 1700003600, 1700004200
                  , 1700004800, 1700005400, 1700006000 ]
          pairs = zip [419320 ..] tss
          (entries, tipHash) = buildChain pairs
      medianTimePast entries tipHash `shouldBe` (tss !! 5)

    it "G2.3: computeEntryMtp for new block 944184 uses its 10 ancestors + own ts" $ do
      -- 'addHeader' calls 'computeEntryMtp entries <944183-hash> <944184-ts>'
      -- to stamp the new entry's ceMedianTime.  Median of
      -- (944184-ts : ts[944174..944183]) — 11 values.
      let ancTss = [ 1775649300, 1775649520, 1775649900, 1775650050
                   , 1775650208, 1775650400, 1775650600, 1775650810
                   , 1775651000, 1775651300 ]            -- heights 944174..944183
          pairs  = zip [944174 ..] ancTss
          (entries, parentHash) = buildChain pairs
          newTs  = 1775651800                            -- block 944184
          got    = computeEntryMtp entries parentHash newTs
          window = newTs : reverse ancTss
      got `shouldBe` refMTP window
      got `shouldBe` sort (newTs : ancTss) !! 5

    it "G2.4: medianTimePast medians a genuinely-PARTIAL window near genesis" $ do
      -- Core 'GetMedianTimePast' walks `nMedianTimeSpan && pindex`,
      -- stopping at a null pprev, and medians WHATEVER blocks exist —
      -- it never returns 0 for a short chain.  haskoin's 'collectTimestamps'
      -- stops cleanly at genesis's `cePrev = Nothing` (the timestamp of
      -- the found block is still included).  Chain of 6 blocks [0..5]:
      -- median is the 3rd smallest (index 3 of 6).
      let tss   = [ 1231006505, 1231006600, 1231006700, 1231006800
                  , 1231006900, 1231007000 ]             -- heights 0..5
          pairs = zip [0 ..] tss
          (entries, tipHash) = buildChain pairs
          got = medianTimePast entries tipHash
      got `shouldBe` refMTP (reverse tss)
      got `shouldBe` (sort tss !! 3)
      -- The decisive anti-regression: a partial window must NOT collapse.
      got `shouldNotBe` 0

    it "G2.5: medianTimePast on a single-block (genesis-only) chain = genesis ts" $ do
      let (entries, tipHash) = buildChain [(0, 1231006505)]
      medianTimePast entries tipHash `shouldBe` 1231006505

    it "G2.6: an absent block hash yields 0 (caller's snapshot precondition guards this)" $ do
      -- '--load-snapshot' refuses to proceed unless the base header is
      -- already in the chain (app/Main.hs:853), so this 0 is never
      -- reached on the recovery path — but pin the raw behavior.
      let (entries, _) = buildChain [(0, 1231006505)]
      medianTimePast entries (synthHash 999999) `shouldBe` 0

  ----------------------------------------------------------------
  describe "W163 Prerequisite 2b — snapshot-aware startup reconciliation" $ do

    it "G2.7: fresh snapshot load (no undo records) -> tip = snapshot base" $ do
      -- Immediately after '--load-snapshot': UTXO set + best-block
      -- pointer at 944183, ZERO undo records.  The connected tip must
      -- be recognised as 944183 so download resumes at 944184 — NOT 0
      -- (which would make haskoin try to connect block 1 and wedge on
      -- the ConnectBlock G1 gate).
      let headerTip = 944183
          undoAt _  = False           -- no undo records anywhere
          tip = reconcileTipPure (Just snap944183Height) undoAt headerTip
      tip `shouldBe` 944183
      (tip + 1) `shouldBe` 944184     -- the resume height

    it "G2.8: snapshot loaded, headers ahead of base, still no post-snap blocks" $ do
      -- Headers synced past 944183 but no block above the base has
      -- connected yet -> tip is still exactly the base.
      let headerTip = 944300
          undoAt _  = False
          tip = reconcileTipPure (Just snap944183Height) undoAt headerTip
      tip `shouldBe` 944183

    it "G2.9: snapshot bootstrapped, some post-snapshot blocks connected" $ do
      -- Steady state after recovery: undo records occupy [944184..U],
      -- heights [1..944183] permanently empty.  Reconciliation must
      -- recover U from the [base+1 ..] range, NOT collapse to 0.
      let u         = 944260
          headerTip = 944300
          -- undo records only above the snapshot base.
          undoAt h  = h > snap944183Height && h <= u
          tip = reconcileTipPure (Just snap944183Height) undoAt headerTip
      tip `shouldBe` u
      (headerTip - tip) `shouldBe` 40       -- blocks still to download

    it "G2.10: snapshot bootstrapped, fully caught up (U == headerTip)" $ do
      let headerTip = 944300
          undoAt h  = h > snap944183Height && h <= headerTip
          tip = reconcileTipPure (Just snap944183Height) undoAt headerTip
      tip `shouldBe` headerTip

    it "G2.11: NO snapshot marker -> classic genesis-up [1..U] search" $ do
      -- The non-snapshot path is unchanged: undo records start at 1.
      let u         = 949000
          headerTip = 950194
          undoAt h  = h >= 1 && h <= u
          tip = reconcileTipPure Nothing undoAt headerTip
      tip `shouldBe` u

    it "G2.12: NO snapshot marker, UTXO set never advanced -> tip 0" $ do
      let headerTip = 950194
          tip = reconcileTipPure Nothing (const False) headerTip
      tip `shouldBe` 0

    it "G2.13: header chain itself only at genesis -> tip 0 (both modes)" $ do
      reconcileTipPure Nothing            (const True) 0 `shouldBe` 0
      reconcileTipPure (Just 944183)      (const True) 0 `shouldBe` 0

    it "G2.14: boundary sweep — snapshot search lands exactly on U" $ do
      -- Exhaustively check the [base+1..U] binary search for many U
      -- positions; guards against an off-by-one in the midpoint.
      let base      = snap944183Height
          headerTip = 944400
      forM_ [ base, base + 1, base + 2, base + 3, base + 7
            , base + 100, headerTip - 1, headerTip ] $ \u -> do
        let undoAt h = h > base && h <= u
        reconcileTipPure (Just base) undoAt headerTip `shouldBe` u

  ----------------------------------------------------------------
  describe "W163 Prerequisite 2b — durable snapshot-base marker" $ do

    it "G2.15: putSnapshotBaseHash / getSnapshotBaseHash round-trip" $
      -- '--load-snapshot' records the base hash; the startup
      -- reconciliation reads it back.  This is the durable signal that
      -- survives restarts (Core's chainstate_snapshot/base_blockhash).
      withTestDB "snap-marker-rt" $ \db -> do
        pre <- getSnapshotBaseHash db
        pre `shouldBe` Nothing
        let baseHash = hashFromHex snap944183HashHex
        putSnapshotBaseHash db baseHash
        post <- getSnapshotBaseHash db
        post `shouldBe` Just baseHash

    it "G2.16: recorded base hash resolves back to height 944183" $
      -- The reconciliation resolves the stored hash to a height via the
      -- assumeUTXO whitelist fallback; confirm the round-trip closes.
      withTestDB "snap-marker-height" $ \db -> do
        let baseHash = hashFromHex snap944183HashHex
        putSnapshotBaseHash db baseHash
        mh <- getSnapshotBaseHash db
        case mh of
          Just h  ->
            fmap aupHeight (assumeUtxoForBlockHash mainnet h)
              `shouldBe` Just 944183
          Nothing -> expectationFailure "snapshot base marker not persisted"

    it "G2.17: deleteSnapshotBaseHash clears the marker" $
      withTestDB "snap-marker-del" $ \db -> do
        putSnapshotBaseHash db (hashFromHex snap944183HashHex)
        deleteSnapshotBaseHash db
        getSnapshotBaseHash db `shouldReturn` Nothing

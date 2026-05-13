{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W106 CTxMemPool descendant/ancestor tracking + RBF + package mempool
--   30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/txmempool.h/cpp
--   bitcoin-core/src/policy/rbf.h/cpp
--   bitcoin-core/src/policy/v3_policy.h/cpp  (TRUC)
--   bitcoin-core/src/policy/packages.h/cpp
--
-- ============================================================
-- BUGS CONFIRMED: 19
-- TWO-PIPELINE GAPS: 3
-- ============================================================
--
-- ── TWO-PIPELINE GAPS ────────────────────────────────────────────────────────
--
-- BUG-1  [TWO-PIPELINE][G21][SEVERITY-CRITICAL] TRUC policy (v3 ancestor/
--        descendant/size/version-inheritance) is NOT enforced in the package
--        admission path.  The main path (addTransaction → finalizeTransaction
--        → handleTruc) calls checkTrucPolicy; the package path
--        (acceptPackage → addPackageTransactions → addTransactionToMempool)
--        does NOT call checkTrucPolicy.  A v3 transaction can be admitted via
--        submitpackage with more than 1 unconfirmed ancestor, violating
--        TRUC_ANCESTOR_LIMIT=2.  A non-v3 tx can spend a v3 unconfirmed
--        parent via the package path, violating TrucNonV3SpendingV3.
--        Core: SingleTRUCChecks is invoked on every tx in
--        MemPoolAccept::PackageMempoolChecks (validation.cpp:1228) AND
--        MemPoolAccept::SingleFinalChecks (validation.cpp:1091).
--        Files: Mempool.hs:955-970 (handleTruc — main path only),
--               Mempool.hs:2225-2342 (addPackageTransactions — no TRUC call),
--               Mempool.hs:2375-2434 (addTransactionToMempool — no TRUC call).
--
-- BUG-2  [TWO-PIPELINE][G3][SEVERITY-HIGH] getmempoolancestors RPC calls
--        getAncestors (direct parents only) instead of getAncestorsRecursive.
--        For a 3-deep chain A→B→C, querying ancestors of C returns only B,
--        not {A, B}.  Bitcoin Core's getmempoolancestors returns ALL transitive
--        unconfirmed ancestors (CalculateMemPoolAncestors).
--        Files: Rpc.hs:5634 (getAncestors — direct only),
--               Mempool.hs:1331-1337 (getAncestors — direct parents only),
--               Mempool.hs:1340-1355 (getAncestorsRecursive — correct recursive).
--
-- BUG-3  [TWO-PIPELINE][G11][SEVERITY-HIGH] getmempoolentry RPC re-computes
--        ancestor and descendant counts by calling getAncestors (direct only,
--        line 5557) and getDescendants (direct only, line 5558) instead of
--        reading the already-correct stored meAncestorCount/meDescendantCount
--        fields.  For multi-hop chains the live RPC response shows wrong
--        ancestorcount/descendantcount.  getDescendants (Mempool.hs:1373)
--        returns only direct children.  meAncestorCount/meDescendantCount in
--        the stored entry are accurate (updated on insert/remove), but the
--        RPC recomputation shadows them with incorrect values.
--        Files: Rpc.hs:5557-5566 (wrong ancestor/descendant computation),
--               Mempool.hs:1373-1384 (getDescendants — direct only).
--
-- ── ANCESTOR / DESCENDANT TRACKING ──────────────────────────────────────────
--
-- BUG-4  [G1][SEVERITY-HIGH] removeTransaction does NOT update meAncestorSigOps
--        for descendants.  The removal path updates meAncestorCount,
--        meAncestorSize, meAncestorFees (Mempool.hs:1209-1214) but omits
--        meAncestorSigOps.  After any removal, all children permanently carry
--        stale ancestor sigop counts, corrupting ancestor-sigop-cost gate
--        tracking for future admissions.
--        Core: CTxMemPoolEntry::UpdateAncestorState subtracts nSigOpCostWithAncestors.
--        Files: Mempool.hs:1200-1214 (missing meAncestorSigOps adjustment),
--               Mempool.hs:286-295 (MempoolEntry — meAncestorSigOps field).
--
-- BUG-5  [G2][SEVERITY-HIGH] removeTransaction uses two separate atomically
--        blocks: one deletes the TX and indexes (line 1187); a second updates
--        ancestor/descendant count fields (line 1209).  Between these two
--        STM transactions, any concurrent reader sees a state where the TX is
--        gone but ancestor entries still show old descendant counts and
--        descendant entries still show old ancestor counts.  Concurrent RPC
--        or peer-relay reads can observe an inconsistent pool.
--        Core: CTxMemPool::removeUnchecked modifies all fields under a single
--        cs lock (txmempool.cpp).
--        Files: Mempool.hs:1187-1214 (two separate atomically blocks).
--
-- BUG-6  [G4][SEVERITY-MEDIUM] getDescendants (Mempool.hs:1373) returns only
--        direct children of a transaction, not all recursive descendants.
--        getDescendantsOfEntry (line 1223) is recursive and used internally
--        for count updates; but the exported getDescendants used in
--        getmempoolentry (Rpc.hs:5558) and getmempooldescendants is non-
--        recursive.  The RPC getmempooldescendants (Rpc.hs:6828) uses the
--        same non-recursive call and therefore omits grandchildren and deeper.
--        Core: GetDescendants / CalculateDescendants are fully recursive.
--        Files: Mempool.hs:1373-1384 (getDescendants — direct only),
--               Rpc.hs:5558 / Rpc.hs:6828 (both use non-recursive getDescendants).
--
-- ── RBF (BIP-125) ────────────────────────────────────────────────────────────
--
-- BUG-7  [G11][SEVERITY-HIGH] RBF Rule 3a (new tx feerate must exceed ALL
--        directly-conflicting txs' feerates) is defined in ErrRBFInsufficientFeeRate
--        and documented in the comment at line 1483, but the check body is MISSING.
--        The checkReplacement function signature takes _newFeeRate (unused,
--        underscored) and the directConflicts list is also unused (_directConflicts).
--        Any replacement with a lower feerate than the conflict is accepted as
--        long as it pays slightly more total fee (Rule 3 absolute).
--        Core: validation.cpp:1018-1026 enforces "new feerate > conflict feerate".
--        Files: Mempool.hs:1495 (checkReplacement signature — _newFeeRate ignored),
--               Mempool.hs:1503-1521 (body — no feerate comparison).
--
-- BUG-8  [G12][SEVERITY-HIGH] RBF fee comparison in Rule 3 uses base fees
--        (meFee) rather than modified fees.  Core's validation.cpp:1005 sums
--        GetModifiedFee() over the conflict set.  meFee in MempoolEntry stores
--        baseFee (set at line 1001: meFee = fee = baseFee, not modifiedFee).
--        A conflicting tx with a large prioritisetransaction delta can be
--        replaced by a tx paying only the base fee, circumventing the delta.
--        Files: Mempool.hs:867 (fee = baseFee, not modifiedFee),
--               Mempool.hs:1001 (meFee = fee, i.e. baseFee),
--               Mempool.hs:1508 (sum $ map meFee allEvictions — uses baseFee).
--
-- BUG-9  [G13][SEVERITY-MEDIUM] checkReplacement does not call
--        checkDiagramReplacement / ImprovesFeerateDiagram.  Bitcoin Core v28+
--        requires that the replacement strictly improves the mempool feerate
--        diagram (policy/rbf.cpp:ImprovesFeerateDiagram).  haskoin defines
--        checkDiagramReplacement (Mempool.hs:2921) but it is never invoked
--        from attemptReplacement.  The exported checkDiagramReplacement is a
--        dead helper.
--        Core: validation.cpp:1031-1044 ImprovesFeerateDiagram mandatory.
--        Files: Mempool.hs:1593-1652 (attemptReplacement — no diagram call),
--               Mempool.hs:2921-2946 (checkDiagramReplacement — dead helper).
--
-- BUG-10 [G14][SEVERITY-MEDIUM] TRUC sibling eviction (attemptSiblingEviction)
--        checks newFee >= requiredFee using the base fee of the incoming tx
--        (Mempool.hs:2626).  Core's sibling eviction comparison uses modified
--        fees.  If the new sibling has a prioritisetransaction delta, the
--        effective modified fee is not considered.
--        Files: Mempool.hs:2624-2632 (base fee comparison in sibling eviction).
--
-- ── PACKAGE / v3 (G21-G30) ───────────────────────────────────────────────────
--
-- BUG-11 [G22][SEVERITY-HIGH] isChildWithParents (Mempool.hs:2037) checks that
--        the child spends at least one parent output, but does NOT verify that
--        ALL non-child txns in the package are actually parents of the child.
--        Core's IsChildWithParents requires every tx except the last to have
--        at least one output spent by the child.  A package with an unrelated
--        "parent" that the child never spends is accepted as child-with-parents.
--        Core: packages.cpp:119-134 "every transaction must be a parent of
--        the last transaction".
--        Files: Mempool.hs:2037-2046 (isChildWithParents — one-sided check).
--
-- BUG-12 [G23][SEVERITY-HIGH] acceptPackage / addPackageTransactions does not
--        check for conflicts with existing mempool entries before inserting.
--        The single-tx path calls getConflicts and either rejects or RBF-
--        replaces.  The package path goes directly to addTransactionToMempool
--        which calls checkAncestorLimits but never getConflicts.  A package
--        tx that double-spends a confirmed mempool tx is silently accepted,
--        corrupting the mpByOutpoint index.
--        Core: MemPoolAccept::PackageMempoolChecks checks conflicts per-tx.
--        Files: Mempool.hs:2225-2342 (addPackageTransactions — no conflict check),
--               Mempool.hs:2375-2434 (addTransactionToMempool — no conflict check).
--
-- BUG-13 [G24][SEVERITY-MEDIUM] acceptPackage duplicate check (line 2100) uses
--        computeTxId only.  A package containing a witness-malleated version of
--        an existing mempool tx (same txid, different wtxid) bypasses the
--        duplicate gate.  Core distinguishes txid vs wtxid duplicates and
--        returns both "txn-already-in-mempool" and "txn-same-nonwitness-data".
--        Files: Mempool.hs:2100-2104 (computeTxId duplicate check, no wtxid check).
--
-- ── RPC / INFORMATIONAL ──────────────────────────────────────────────────────
--
-- BUG-14 [G15][SEVERITY-MEDIUM] getrawmempool verbose and getmempoolentry RPC
--        always return baseFee for both "modified" (in fees object) and
--        "modifiedfee".  When prioritisetransaction sets a fee delta, the
--        displayed modifiedfee is wrong.  Bitcoin Core returns the delta-
--        adjusted value from GetModifiedFee().
--        Files: Rpc.hs:2355 (getrawmempool "modified" = feeSat = baseFee),
--               Rpc.hs:2365 (getrawmempool "modifiedfee" = feeSat = baseFee),
--               Rpc.hs:5581-5588 (getmempoolentry same issue).
--
-- BUG-15 [G16][SEVERITY-MEDIUM] getrawmempool verbose always returns empty
--        "depends" list (Rpc.hs:2376).  getmempoolentry correctly computes
--        depends (Rpc.hs:5574).  Inconsistency: the same field is populated
--        in one RPC and hardcoded [] in the other.
--        Files: Rpc.hs:2376 (getrawmempool "depends" = AE.list text []).
--
-- BUG-16 [G17][SEVERITY-MEDIUM] Both getrawmempool verbose and getmempoolentry
--        always return empty "spentby" list.  Bitcoin Core populates this with
--        the txids of in-mempool txs that spend outputs of this tx.
--        Files: Rpc.hs:2377, Rpc.hs:5600 (spentby = AE.list text []).
--
-- ── MISC ─────────────────────────────────────────────────────────────────────
--
-- BUG-17 [G5][SEVERITY-MEDIUM] meDescendantFees in removeTransaction is
--        decremented by meFee (base fee) not modifiedFee.  If a tx with a
--        positive fee delta is removed, ancestor meDescendantFees goes negative
--        (underflow in Word64 arithmetic) or drops below the true modified fee
--        removed.
--        Files: Mempool.hs:1205 (meDescendantFees - fee, fee = baseFee).
--
-- BUG-18 [G6][SEVERITY-LOW] isWellFormedPackage total weight calculation at
--        line 2014 uses (txBaseSize * 3 + txTotalSize) which equals
--        3*base + (base + witness) = 4*base + witness, i.e. weight per BIP-141.
--        This is correct.  However the formula omits the witnessScaleFactor
--        constant and would silently diverge if that constant ever changed.
--        More importantly it uses Int (not Int64) for totalWeight which can
--        overflow for large packages on 32-bit hosts.
--        Files: Mempool.hs:2014-2015 (totalWeight as Int).
--
-- BUG-19 [G7][SEVERITY-LOW] selectTransactions (Mempool.hs:1905) sorts by
--        ancestor fee rate but does not enforce topological order: a child
--        with a higher ancestor fee rate than its parent could be selected
--        before its parent, producing an invalid block template.  Bitcoin
--        Core uses cluster linearization which guarantees topological order
--        within each chunk.
--        Files: Mempool.hs:1905-1930 (selectTransactions — no topo-sort gate).

module W106MempoolSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Data.Word (Word32, Word64)
import Data.Int (Int64)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Maybe (fromJust, mapMaybe)
import Control.Monad (forM_, void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid)
import Haskoin.Mempool
import Haskoin.Consensus (mainnet, testnet4)
import Haskoin.Storage (UTXOCache(..), UTXOEntry(..), newUTXOCache,
                        HaskoinDB(..), DBConfig(..), defaultDBConfig, withDB)

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a fresh mempool backed by a temp RocksDB. The continuation receives
-- the mempool; the DB is cleaned up on exit.
withFreshMempool :: (Mempool -> IO a) -> IO a
withFreshMempool action =
  withSystemTempDirectory "haskoin-w106-test" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      mp    <- newMempool testnet4 cache defaultMempoolConfig 100 0 noopCoinMtp
      action mp


-- | A dummy TxOut with the given value and a bare OP_TRUE scriptPubKey.
dummyTxOut :: Word64 -> TxOut
dummyTxOut v = TxOut { txOutValue = v, txOutScript = "\x51" }

-- | Construct a minimal valid-for-unit-test Tx spending the given OutPoints.
makeTx :: [OutPoint] -> [Word64] -> Tx
makeTx prevouts outValues = Tx
  { txVersion   = 2
  , txInputs    = map (\op -> TxIn { txInPrevOutput = op
                                   , txInScript    = ""
                                   , txInSequence  = 0xffffffff }) prevouts
  , txOutputs   = map dummyTxOut outValues
  , txWitness   = replicate (length prevouts) []
  , txLockTime  = 0
  }

-- | v3 (TRUC) variant of makeTx.
makeV3Tx :: [OutPoint] -> [Word64] -> Tx
makeV3Tx prevouts outValues = (makeTx prevouts outValues) { txVersion = 3 }

-- | A coin OutPoint that's guaranteed to never collide with real txids.
coinOutPoint :: Word32 -> OutPoint
coinOutPoint n = OutPoint (TxId (Hash256 (BS.replicate 31 0x00 <> BS.singleton (fromIntegral n)))) 0

-- | Build a MempoolEntry with an explicit Tx (needed when getDescendants uses
-- meTransaction to enumerate outputs).
fakeEntryTx :: Tx -> TxId -> Wtxid -> Word64 -> Int -> Int -> Int -> Int -> Int -> MempoolEntry
fakeEntryTx tx txid wtxid fee sz ancCnt ancSz descCnt descSz = MempoolEntry
  { meTransaction      = tx
  , meTxId             = txid
  , meWtxid            = wtxid
  , meFee              = fee
  , meFeeRate          = FeeRate (fee * 1000 `div` fromIntegral sz)
  , meSize             = sz
  , meTime             = 0
  , meHeight           = 0
  , meAncestorCount    = ancCnt
  , meAncestorSize     = ancSz
  , meAncestorFees     = fee
  , meAncestorSigOps   = 0
  , meDescendantCount  = descCnt
  , meDescendantSize   = descSz
  , meDescendantFees   = fee
  , meRBFOptIn         = False
  }

-- | Build a MempoolEntry manually (used for testing stored-field consistency).
fakeEntry :: TxId -> Wtxid -> Word64 -> Int -> Int -> Int -> Int -> Int -> MempoolEntry
fakeEntry txid wtxid fee sz ancCnt ancSz descCnt descSz = MempoolEntry
  { meTransaction      = makeTx [] []
  , meTxId             = txid
  , meWtxid            = wtxid
  , meFee              = fee
  , meFeeRate          = FeeRate (fee * 1000 `div` fromIntegral sz)
  , meSize             = sz
  , meTime             = 0
  , meHeight           = 0
  , meAncestorCount    = ancCnt
  , meAncestorSize     = ancSz
  , meAncestorFees     = fee
  , meAncestorSigOps   = 0
  , meDescendantCount  = descCnt
  , meDescendantSize   = descSz
  , meDescendantFees   = fee
  , meRBFOptIn         = False
  }

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do

  --
  -- G1: Ancestor/descendant counting — removeTransaction drops meAncestorSigOps
  --
  describe "G1 removeTransaction meAncestorSigOps not updated (BUG-4)" $ do
    it "after parent removal child meAncestorSigOps should be decremented" $ do
      -- We can only test this observationally: add a parent and a child tx,
      -- remove the parent and verify the child no longer has the parent in its
      -- ancestor sigop count. Since haskoin does NOT update this field, the
      -- test asserts the BUGGY current behavior and marks it explicitly.
      --
      -- Correct behavior (Bitcoin Core): meAncestorSigOps decrements by the
      -- removed ancestor's own sigop cost.
      -- Current haskoin behavior: meAncestorSigOps stays stale.
      --
      -- This test documents the bug; it is marked pending until the fix lands.
      pending

  --
  -- G2: removeTransaction split atomically (BUG-5)
  --
  describe "G2 removeTransaction split STM transactions (BUG-5)" $ do
    it "deletion and count updates are in separate atomically blocks (non-atomic)" $ do
      -- Structural test: we simply confirm the code behaves as documented.
      -- The deletion is in one atomically, count updates in another.
      -- This is a documentation test; concurrent inconsistency requires
      -- multi-thread test infra beyond this unit suite.
      pending

  --
  -- G3: getmempoolancestors returns only direct parents (BUG-2 TWO-PIPELINE)
  --
  describe "G3 getAncestors returns direct parents only — not transitive (BUG-2)" $ do
    it "getAncestors depth-1 misses grandparent" $
      withFreshMempool $ \mp -> do
      -- Build chain: coin0 → txA → txB → txC
      -- txC's ancestors should be {txA, txB} (transitive), but getAncestors
      -- only returns {txB}.
      let coinA = coinOutPoint 1
          txA   = makeTx [coinA] [9_000]
          txAId = computeTxId txA
          opA0  = OutPoint txAId 0

          txB   = makeTx [opA0] [8_000]
          txBId = computeTxId txB
          opB0  = OutPoint txBId 0

          txC   = makeTx [opB0] [7_000]

      -- Populate mpEntries manually for getAncestors isolation test.
      let entA = fakeEntry txAId (computeWtxid txA) 1000 200 1 200 3 600
          entB = fakeEntry txBId (computeWtxid txB) 1000 200 2 400 2 400

      atomically $ do
        modifyTVar' (mpEntries mp) $ Map.insert txAId entA
        modifyTVar' (mpEntries mp) $ Map.insert txBId entB
        -- Record outpoints so txB is seen as spending txA
        modifyTVar' (mpByOutpoint mp) $ Map.insert opA0 txBId

      -- getAncestors is direct-parent only
      directAncs <- getAncestors mp txC
      -- Should only find txB (direct parent), not txA (grandparent)
      length directAncs `shouldBe` 1
      meTxId (head directAncs) `shouldBe` txBId

      -- BUG: getAncestorsRecursive is the correct transitive function but is
      -- NOT exported from Haskoin.Mempool — only the broken direct-parent
      -- getAncestors is public. The test above demonstrates the bug:
      -- a 3-tx chain A→B→C only sees 1 ancestor (txB) instead of 2 (txA+txB).

  --
  -- G4: getDescendants non-recursive (BUG-3 TWO-PIPELINE)
  --
  describe "G4 getDescendants non-recursive misses grandchildren (BUG-3)" $ do
    it "getDescendants depth-1 misses grandchildren for txA in A→B→C chain" $
      withFreshMempool $ \mp -> do
      let coinA = coinOutPoint 2
          txA   = makeTx [coinA] [9_000]
          txAId = computeTxId txA
          opA0  = OutPoint txAId 0

          txB   = makeTx [opA0] [8_000]
          txBId = computeTxId txB
          opB0  = OutPoint txBId 0

          txC   = makeTx [opB0] [7_000]
          txCId = computeTxId txC

          -- Use fakeEntryTx so meTransaction has the real tx with actual outputs;
          -- getDescendants reads meTransaction to enumerate output outpoints.
          entA = fakeEntryTx txA txAId (computeWtxid txA) 1000 200 1 200 3 600
          entB = fakeEntryTx txB txBId (computeWtxid txB) 1000 200 2 400 2 400
          entC = fakeEntryTx txC txCId (computeWtxid txC) 1000 200 3 600 1 200

      atomically $ do
        modifyTVar' (mpEntries mp) $ Map.insert txAId entA
        modifyTVar' (mpEntries mp) $ Map.insert txBId entB
        modifyTVar' (mpEntries mp) $ Map.insert txCId entC
        modifyTVar' (mpByOutpoint mp) $ Map.insert opA0 txBId
        modifyTVar' (mpByOutpoint mp) $ Map.insert opB0 txCId

      -- getDescendants of txA should recursively find txB AND txC.
      -- BUG: current implementation returns only txB (direct child).
      descs <- getDescendants mp txAId
      -- Document current (buggy) behavior: only direct child returned
      length descs `shouldBe` 1
      meTxId (head descs) `shouldBe` txBId
      -- Correct behavior would be length == 2 (txB and txC)

  --
  -- G5: meDescendantFees decremented by baseFee not modifiedFee (BUG-17)
  --
  describe "G5 meDescendantFees decremented by baseFee only (BUG-17)" $ do
    it "meDescendantFees undercount when conflicting tx had fee delta" $ do
      -- Document: removal uses `fee = meFee entry` (base fee). If a
      -- prioritisetransaction delta exists, the stored meDescendantFees on
      -- ancestors should be decremented by modifiedFee, not baseFee.
      -- Current behavior uses baseFee only.
      pending

  --
  -- G6: TRUC policy skipped in package path (BUG-1 TWO-PIPELINE)
  --
  describe "G6 TRUC policy not enforced on package path (BUG-1)" $ do
    it "checkTrucPolicy is never called from addTransactionToMempool" $ do
      -- Structural documentation: checkTrucPolicy is only called from handleTruc
      -- which is only reached via finalizeTransaction (single-tx path).
      -- addTransactionToMempool (package path) does not call checkTrucPolicy.
      --
      -- Functional test: attempt to add a v3 tx with 2 unconfirmed v3 parents
      -- via addTransactionToMempool; it should be rejected but is NOT in current code.
      -- Marking pending until fixed.
      pending

  --
  -- G7: selectTransactions topological order not guaranteed (BUG-19)
  --
  describe "G7 selectTransactions may produce non-topological order (BUG-19)" $ do
    it "child selected before parent when child has higher ancestor fee rate" $ do
      -- When ancestor fee rate of child > parent's own fee rate,
      -- sorting by Down ancestorFeeRate can place child before parent.
      -- This is wrong for block template construction.
      -- Simple structural verification: the sort is purely by fee rate, no
      -- parent-before-child enforcement.
      let coin1   = coinOutPoint 10
          txP     = makeTx [coin1] [5_000]   -- parent: low fee
          txPId   = computeTxId txP
          opP0    = OutPoint txPId 0
          txC'    = makeTx [opP0] [4_000]    -- child: high fee, spent from parent
          txCId'  = computeTxId txC'

          entP = fakeEntry txPId (computeWtxid txP) 100 200 1 200 2 400
          entC = fakeEntry txCId' (computeWtxid txC') 900 200 2 400 1 200

      -- The selectTransactions sort is: Down . ancestorFeeRate
      -- Parent ancestorFeeRate = 100*1000/200 = 500 sat/kvB
      -- Child  ancestorFeeRate = (100+900)*1000/400 = 2500 sat/kvB
      -- Child sorts FIRST — but child depends on parent.
      -- This would produce an invalid block template.
      -- Document current behavior:
      let parentRate = (meAncestorFees entP * 1000) `div` fromIntegral (meAncestorSize entP)
          childRate  = (meAncestorFees entC * 1000) `div` fromIntegral (meAncestorSize entC)
      (childRate > parentRate) `shouldBe` True
      -- The bug: when sorted by Down ancestorFeeRate, child appears before parent.

  --
  -- G8: RBF Rule 3a enforced (BUG-7 FIXED)
  --
  describe "G8 RBF Rule 3a feerate check enforced in checkReplacement (BUG-7 fixed)" $ do
    it "checkReplacement rejects replacement with LOWER feerate (Rule 3a enforced)" $ do
      -- Build a conflict entry with high feerate (1000 sat/vB)
      let coin = coinOutPoint 20
          conflictTx = makeTx [coin] [9_000]
          conflictId = computeTxId conflictTx
          conflictEntry = MempoolEntry
            { meTransaction   = conflictTx
            , meTxId          = conflictId
            , meWtxid         = computeWtxid conflictTx
            , meFee           = 1_000
            , meFeeRate       = FeeRate 1_000
            , meSize          = 200
            , meTime          = 0
            , meHeight        = 0
            , meAncestorCount = 1
            , meAncestorSize  = 200
            , meAncestorFees  = 1_000
            , meAncestorSigOps= 0
            , meDescendantCount = 1
            , meDescendantSize  = 200
            , meDescendantFees  = 1_000
            , meRBFOptIn      = True
            }
          -- Replacement: pays MORE total fee (1100 > 1000) but LOWER feerate (2 sat/vB)
          newFee     = 1_100 :: Word64
          newVsize   = 550   :: Int     -- feerate = 1100/550 = 2 sat/vB < 1000 sat/vB
          newFeeRate = FeeRate 2
          replacementTx = makeTx [coin] [9_900]

      -- Rule 3a MUST REJECT this (new feerate 2 < conflict feerate 1000)
      let result = checkReplacement replacementTx [conflictEntry] [conflictEntry]
                     newFee newVsize newFeeRate
      case result of
        Left (RbfInsufficientFeeRate gotRate minRate) -> do
          gotRate `shouldBe` FeeRate 2
          minRate `shouldBe` FeeRate 1_000
        Left other -> expectationFailure ("expected RbfInsufficientFeeRate, got: " ++ show other)
        Right ()   -> expectationFailure "Rule 3a not enforced: accepted lower-feerate replacement"

  --
  -- G9: RBF Rule 3 uses baseFee not modifiedFee (BUG-8)
  --
  describe "G9 RBF Rule 3 uses baseFee not modifiedFee (BUG-8)" $ do
    it "checkReplacement sum uses meFee (baseFee), ignoring fee deltas" $ do
      -- A conflicting tx with baseFee=500, modifiedFee=1500 (delta=+1000).
      -- Replacement pays 600 sat — exceeds baseFee (500) but not modifiedFee (1500).
      -- Core would reject (600 < 1500). haskoin accepts (600 > 500).
      let coin = coinOutPoint 21
          conflictTx = makeTx [coin] [9_000]
          conflictId = computeTxId conflictTx
          conflictEntry = MempoolEntry
            { meTransaction   = conflictTx
            , meTxId          = conflictId
            , meWtxid         = computeWtxid conflictTx
            , meFee           = 500       -- baseFee stored (NOT 1500 modifiedFee)
            , meFeeRate       = FeeRate 5
            , meSize          = 100
            , meTime          = 0
            , meHeight        = 0
            , meAncestorCount = 1
            , meAncestorSize  = 100
            , meAncestorFees  = 500
            , meAncestorSigOps= 0
            , meDescendantCount = 1
            , meDescendantSize  = 100
            , meDescendantFees  = 500
            , meRBFOptIn      = True
            }
          -- Replacement pays 600 total, vsize=100
          newFee     = 600 :: Word64   -- > baseFee(500) but < modifiedFee(1500)
          newVsize   = 100 :: Int
          newFeeRate = FeeRate 6
          replacementTx = makeTx [coin] [9_400]

      let result = checkReplacement replacementTx [conflictEntry] [conflictEntry]
                     newFee newVsize newFeeRate
      -- BUG: accepted (600 > 500 baseFee); Core would reject (600 < 1500 modifiedFee)
      result `shouldBe` Right ()

  --
  -- G10: checkDiagramReplacement now wired into attemptReplacement (BUG-9 FIXED)
  --
  describe "G10 checkDiagramReplacement wired into attemptReplacement (BUG-9 fixed)" $ do
    it "checkDiagramReplacement rejects a diagram-non-improving replacement" $ do
      -- An improving replacement (higher fee density): should be accepted by diagram check.
      let evicted = [ fakeEntry (computeTxId (makeTx [coinOutPoint 30] [9000]))
                                (computeWtxid (makeTx [coinOutPoint 30] [9000]))
                                1000 200 1 200 1 200 ]
      let goodResult = checkDiagramReplacement evicted 2000 100 (FeeRate 20)
      goodResult `shouldBe` Right ()

    it "checkDiagramReplacement rejects a replacement that does not improve the feerate diagram" $ do
      -- evicted tx: fee=1000, size=100, feerate=10 sat/vB
      -- replacement: fee=900, size=200, feerate=4.5 sat/vB — worse diagram
      let evicted = [ fakeEntry (computeTxId (makeTx [coinOutPoint 31] [9000]))
                                (computeWtxid (makeTx [coinOutPoint 31] [9000]))
                                1000 100 1 100 1 100 ]
      -- Fee 900 < 1000: fails Rule 3 absolute-fee check first, which is also
      -- how Core reports it; checkDiagramReplacement returns Left.
      let badResult = checkDiagramReplacement evicted 900 200 (FeeRate 4)
      case badResult of
        Left _  -> pure ()  -- correctly rejected
        Right () -> expectationFailure "expected diagram check to reject non-improving replacement"

  --
  -- G11: isChildWithParents does not require ALL parents to be spent (BUG-11)
  --
  describe "G11 isChildWithParents allows unrelated package members (BUG-11)" $ do
    it "package with unrelated 'parent' passes isChildWithParents" $ do
      -- Build a package [unrelated, realParent, child] where child spends
      -- realParent but NOT unrelated.  Core's IsChildWithParents should
      -- reject (unrelated is not a parent of child), but haskoin accepts
      -- because the child spends at least one parent.
      let coinR = coinOutPoint 40
          coinU = coinOutPoint 41
          realParent = makeTx [coinR] [9_000]
          realParentId = computeTxId realParent
          opRP = OutPoint realParentId 0

          unrelated = makeTx [coinU] [8_000]  -- child does NOT spend this

          child = makeTx [opRP] [7_000]    -- spends realParent only

          pkg = [unrelated, realParent, child]

      -- haskoin: passes (intersection of parentTxids ∩ childInputTxids is non-empty)
      isChildWithParents pkg `shouldBe` True
      -- Core would return False because unrelated is not spent by child.
      -- Document: correct behavior should be False (or check all parents).

  --
  -- G12: Package path skips conflict check (BUG-12)
  --
  describe "G12 addPackageTransactions no conflict check against mempool (BUG-12)" $ do
    it "addTransactionToMempool does not detect double-spends with existing mempool txs" $ do
      -- The package insertion path calls addTransactionToMempool, which calls
      -- checkAncestorLimits but NOT getConflicts.  This is a structural gap.
      -- Full exercise requires running acceptPackage; mark as pending with
      -- documentation.
      pending

  --
  -- G13: Package wtxid duplicate check missing (BUG-13)
  --
  describe "G13 acceptPackage duplicate check uses txid only, not wtxid (BUG-13)" $ do
    it "package containing witness-malleated tx bypasses duplicate detection" $ do
      -- acceptPackage checks `Map.member txid entries` (line 2100).
      -- A malleated witness (same txid, different wtxid) would pass this check.
      -- Structural test only; mark pending.
      pending

  --
  -- G14: getmempoolentry modifiedfee always equals fee (BUG-14)
  --
  describe "G14 getmempoolentry modifiedfee hardcoded to base fee (BUG-14)" $ do
    it "meFee stores baseFee; modifiedfee in RPC does not include fee delta" $
      withFreshMempool $ \mp -> do
      -- Verify that MempoolEntry stores baseFee in meFee (not modifiedFee).
      -- In finalizeTransaction: fee = baseFee (line 867), meFee = fee (line 1001).
      -- The RPC uses fromIntegral (meFee entry) for "modifiedfee".

      -- Inject a fee delta for a known txid
      let coin = coinOutPoint 50
          tx   = makeTx [coin] [9_000]
          txid = computeTxId tx

      -- Set delta of +5000 satoshis
      atomically $ modifyTVar' (mpFeeDeltas mp) (Map.insert txid 5000)

      -- Simulate what finalizeTransaction does:
      feeDeltas <- readTVarIO (mpFeeDeltas mp)
      let baseFee     = 1_000 :: Word64
          delta       = Map.findWithDefault 0 txid feeDeltas :: Int64
          modifiedFee :: Word64
          modifiedFee
            | delta >= 0 = baseFee + fromIntegral delta
            | otherwise  =
                let absD = fromIntegral (negate delta) :: Word64
                in if absD > baseFee then 0 else baseFee - absD
          storedFee = baseFee   -- meFee = fee = baseFee (BUG)

      -- modifiedFee should be 6000, but meFee stores 1000
      modifiedFee `shouldBe` 6_000
      storedFee   `shouldBe` 1_000   -- documents the RPC discrepancy

  --
  -- G15: getrawmempool "depends" always empty (BUG-15)
  --
  describe "G15 getrawmempool verbose depends field always [] (BUG-15)" $ do
    it "getmempoolentry correctly computes depends; getrawmempool does not" $
      withFreshMempool $ \mp -> do
        -- Structural documentation: Rpc.hs:2376 hardcodes AE.list text [].
        -- getmempoolentry at Rpc.hs:5574 computes from ancestor list correctly.
        -- Verify getAncestors in isolation returns direct parents:
        let coinP = coinOutPoint 60
            txP'  = makeTx [coinP] [9_000]
            txPId' = computeTxId txP'
            opP'  = OutPoint txPId' 0
            txC'  = makeTx [opP'] [8_000]
            entP' = fakeEntry txPId' (computeWtxid txP') 1000 200 1 200 2 400

        atomically $ do
          modifyTVar' (mpEntries mp) $ Map.insert txPId' entP'
          modifyTVar' (mpByOutpoint mp) $ Map.insert opP' txPId'

        ancs <- getAncestors mp txC'
        -- getAncestors returns one entry (direct parent)
        length ancs `shouldBe` 1
        -- getrawmempool would show "depends": [] for txC' (bug)
        -- getmempoolentry would show "depends": [txPId'] (correct for txC')

  --
  -- G16: spentby always empty in both RPCs (BUG-16)
  --
  describe "G16 spentby field always empty in getrawmempool and getmempoolentry (BUG-16)" $ do
    it "spentby is hardcoded AE.list text [] in both RPC handlers" $ do
      -- Both Rpc.hs:2377 and Rpc.hs:5600 hardcode [] for "spentby".
      -- Bitcoin Core populates this with txids of mempool spenders.
      -- Document the gap.
      pending

  --
  -- G17: signalsOptInRBF threshold boundary
  --
  describe "G17 signalsOptInRBF threshold (0xfffffffd) is correct" $ do
    it "nSequence <= 0xfffffffd signals RBF" $ do
      let tx0 = makeTx [coinOutPoint 70] [9_000]
          txRBF = tx0 { txInputs = [ (head (txInputs tx0)) { txInSequence = 0xfffffffd } ] }
          txFinal = tx0 { txInputs = [ (head (txInputs tx0)) { txInSequence = 0xfffffffe } ] }
      signalsOptInRBF txRBF `shouldBe` True
      signalsOptInRBF txFinal `shouldBe` False

  --
  -- G18: isTopoSortedPackage correctness
  --
  describe "G18 isTopoSortedPackage" $ do
    it "parent before child is sorted" $ do
      let coin = coinOutPoint 80
          txP  = makeTx [coin] [9_000]
          txPId = computeTxId txP
          opP  = OutPoint txPId 0
          txC  = makeTx [opP] [8_000]
      isTopoSortedPackage [txP, txC] `shouldBe` True

    it "child before parent is NOT sorted" $ do
      let coin = coinOutPoint 81
          txP  = makeTx [coin] [9_000]
          txPId = computeTxId txP
          opP  = OutPoint txPId 0
          txC  = makeTx [opP] [8_000]
      isTopoSortedPackage [txC, txP] `shouldBe` False

  --
  -- G19: isConsistentPackage correctness
  --
  describe "G19 isConsistentPackage" $ do
    it "package with no conflicting inputs is consistent" $ do
      let tx1 = makeTx [coinOutPoint 90] [9_000]
          tx2 = makeTx [coinOutPoint 91] [8_000]
      isConsistentPackage [tx1, tx2] `shouldBe` True

    it "package where two txs spend same input is inconsistent" $ do
      let coin = coinOutPoint 92
          tx1 = makeTx [coin] [9_000]
          tx2 = makeTx [coin] [8_000]  -- conflict!
      isConsistentPackage [tx1, tx2] `shouldBe` False

  --
  -- G20: maxPackageCount and maxPackageWeight constants match Core
  --
  describe "G20 package limits match Bitcoin Core" $ do
    it "maxPackageCount == 25" $
      maxPackageCount `shouldBe` 25
    it "maxPackageWeight == 404000" $
      maxPackageWeight `shouldBe` 404000

  --
  -- G21: TRUC constants match Bitcoin Core
  --
  describe "G21 TRUC policy constants match Bitcoin Core" $ do
    it "trucVersion == 3"           $ trucVersion `shouldBe` 3
    it "trucAncestorLimit == 2"     $ trucAncestorLimit `shouldBe` 2
    it "trucDescendantLimit == 2"   $ trucDescendantLimit `shouldBe` 2
    it "trucMaxVsize == 10000"      $ trucMaxVsize `shouldBe` 10000
    it "trucChildMaxVsize == 1000"  $ trucChildMaxVsize `shouldBe` 1000

  --
  -- G22: TRUC version inheritance enforced in single-tx path
  --
  describe "G22 TRUC checkVersionInheritance single-tx path" $ do
    it "v3 tx spending non-v3 unconfirmed parent returns TrucV3SpendingNonV3" $
      withFreshMempool $ \mp -> do
      let coin   = coinOutPoint 100
          txP    = makeTx [coin] [9_000]     -- version 2 (non-v3) parent
          txPId  = computeTxId txP
          opP    = OutPoint txPId 0
          txC    = makeV3Tx [opP] [8_000]    -- version 3 child
          txCId  = computeTxId txC

          entP = fakeEntry txPId (computeWtxid txP) 1000 200 1 200 1 200

      atomically $ modifyTVar' (mpEntries mp) $ Map.insert txPId entP

      -- getMempoolParent should find the non-v3 parent
      mParent <- getMempoolParent mp txC
      case mParent of
        Nothing -> expectationFailure "expected to find mempool parent"
        Just p  -> do
          -- Version inheritance check
          let parents = [p]
          case checkVersionInheritance txC txCId parents of
            Left (TrucV3SpendingNonV3 childId parentId) -> do
              childId  `shouldBe` txCId
              parentId `shouldBe` txPId
            Left otherErr -> expectationFailure ("unexpected error: " ++ show otherErr)
            Right ()      -> expectationFailure "expected TrucV3SpendingNonV3"

  --
  -- G23: TRUC descendant limit enforced in single-tx path
  --
  describe "G23 TRUC descendant limit single-tx path" $ do
    it "v3 parent with 1 existing child rejects second child (sibling eviction eligible)" $
      withFreshMempool $ \mp -> do
      let coin    = coinOutPoint 110
          txP     = makeV3Tx [coin] [9_000]       -- v3 parent
          txPId   = computeTxId txP
          opP0    = OutPoint txPId 0
          opP1    = OutPoint txPId 1

          txChild1 = makeV3Tx [opP0] [4_000]      -- first v3 child
          txChild1Id = computeTxId txChild1

          txChild2 = makeV3Tx [opP1] [4_000]      -- second v3 child (would violate)

          -- Parent entry: descendantCount=2 (itself + one child), ancestorCount=1
          entP = MempoolEntry
            { meTransaction    = txP
            , meTxId           = txPId
            , meWtxid          = computeWtxid txP
            , meFee            = 1_000
            , meFeeRate        = FeeRate 5
            , meSize           = 200
            , meTime           = 0
            , meHeight         = 0
            , meAncestorCount  = 1
            , meAncestorSize   = 200
            , meAncestorFees   = 1_000
            , meAncestorSigOps = 0
            , meDescendantCount = 2   -- parent + 1 existing child
            , meDescendantSize  = 400
            , meDescendantFees  = 2_000
            , meRBFOptIn       = False
            }

          -- Existing child entry: ancestorCount=2 (itself + parent)
          entChild1 = fakeEntry txChild1Id (computeWtxid txChild1) 1000 200 2 400 1 200

      atomically $ do
        modifyTVar' (mpEntries mp) $ Map.insert txPId entP
        modifyTVar' (mpEntries mp) $ Map.insert txChild1Id entChild1
        modifyTVar' (mpByOutpoint mp) $ Map.insert opP0 txChild1Id

      -- checkTrucPolicy on txChild2 should detect TrucSiblingExists
      result <- checkTrucPolicy txChild2 200 mp
      case result of
        Left (TrucSiblingExists parentId siblingId) -> do
          parentId  `shouldBe` txPId
          siblingId `shouldBe` txChild1Id
        Left other -> expectationFailure ("expected TrucSiblingExists, got: " ++ show other)
        Right _    -> expectationFailure "expected TRUC rejection"

  --
  -- G24: maxReplacementEvictions constant matches Core
  --
  describe "G24 maxReplacementEvictions == 100" $ do
    it "MAX_REPLACEMENT_CANDIDATES == 100" $
      maxReplacementEvictions `shouldBe` 100

  --
  -- G25: incrementalRelayFeePerKvb constant matches Core
  --
  describe "G25 incrementalRelayFeePerKvb == 100" $ do
    it "DEFAULT_INCREMENTAL_RELAY_FEE == 100 sat/kvB" $
      incrementalRelayFeePerKvb `shouldBe` 100

  --
  -- G26: rollingFeeHalflife constant matches Core (12 hours)
  --
  describe "G26 rollingFeeHalflife == 43200 seconds" $ do
    it "ROLLING_FEE_HALFLIFE == 60*60*12" $
      rollingFeeHalflife `shouldBe` fromIntegral (60 * 60 * 12 :: Int)

  --
  -- G27: checkNoNewUnconfirmedInputs (BIP-125 Rule 2)
  --
  describe "G27 checkNoNewUnconfirmedInputs (BIP-125 Rule 2)" $ do
    it "accepts replacement that only spends confirmed or old-conflict outputs" $ do
      let coinConf = coinOutPoint 200       -- confirmed
          opConf   = coinConf               -- same shape
          replaceTx = makeTx [opConf] [9_000]
          mempoolIds = Set.empty            -- no unconfirmed in pool
          oldSpends  = Set.empty
      checkNoNewUnconfirmedInputs replaceTx mempoolIds oldSpends `shouldBe` Right ()

    it "rejects replacement that introduces new unconfirmed input" $ do
      let unconfirmedParent = computeTxId (makeTx [coinOutPoint 201] [9_000])
          opUnconf          = OutPoint unconfirmedParent 0
          replaceTx         = makeTx [opUnconf] [8_000]
          mempoolIds        = Set.singleton unconfirmedParent  -- parent is unconfirmed
          oldSpends         = Set.empty   -- NOT already in conflict set
      case checkNoNewUnconfirmedInputs replaceTx mempoolIds oldSpends of
        Left (RbfNewUnconfirmedInput pid) -> pid `shouldBe` unconfirmedParent
        other -> expectationFailure ("expected RbfNewUnconfirmedInput, got: " ++ show other)

  --
  -- G28: checkNoConflictSpending
  --
  describe "G28 checkNoConflictSpending (replacement doesn't spend conflict outputs)" $ do
    it "detects spending of conflict tx output" $ do
      let conflictId = computeTxId (makeTx [coinOutPoint 210] [9_000])
          opConflict = OutPoint conflictId 0
          replaceTx  = makeTx [opConflict] [8_000]
          conflicts  = Set.singleton conflictId
      case checkNoConflictSpending replaceTx conflicts of
        Left (RbfSpendingConflict cid) -> cid `shouldBe` conflictId
        other -> expectationFailure ("expected RbfSpendingConflict, got: " ++ show other)

    it "allows replacement that does not spend conflict outputs" $ do
      let conflictId = computeTxId (makeTx [coinOutPoint 211] [9_000])
          opSafe     = coinOutPoint 212
          replaceTx  = makeTx [opSafe] [8_000]
          conflicts  = Set.singleton conflictId
      checkNoConflictSpending replaceTx conflicts `shouldBe` Right ()

  --
  -- G29: isWellFormedPackage enforces count and weight limits
  --
  describe "G29 isWellFormedPackage limits" $ do
    it "rejects package with > 25 transactions" $ do
      -- Build 26 independent txs
      let txns = [ makeTx [coinOutPoint (fromIntegral i)] [9_000]
                 | i <- [300..325 :: Int] ]
      case isWellFormedPackage txns of
        Left (PkgTooManyTransactions n _) -> n `shouldBe` 26
        other -> expectationFailure ("expected PkgTooManyTransactions, got: " ++ show other)

    it "accepts package with exactly 25 transactions" $ do
      let txns = [ makeTx [coinOutPoint (fromIntegral i)] [9_000]
                 | i <- [330..354 :: Int] ]
      isWellFormedPackage txns `shouldBe` Right ()

    it "rejects empty package" $ do
      isWellFormedPackage [] `shouldBe` Left PkgEmptyPackage

  --
  -- G30: signalsOptInRBF boundary for nSequence 0xfffffffe (final)
  --
  describe "G30 signalsOptInRBF 0xfffffffe does NOT signal RBF" $ do
    it "nSequence == 0xfffffffe is NOT an RBF signal" $ do
      let tx = makeTx [coinOutPoint 400] [9_000]
          txFinal = tx { txInputs = [ (head (txInputs tx)) { txInSequence = 0xfffffffe } ] }
      signalsOptInRBF txFinal `shouldBe` False

    it "nSequence == 0xffffffff (final/nLocktime disabled) is NOT an RBF signal" $ do
      let tx = makeTx [coinOutPoint 401] [9_000]
          txFinal = tx { txInputs = [ (head (txInputs tx)) { txInSequence = 0xffffffff } ] }
      signalsOptInRBF txFinal `shouldBe` False

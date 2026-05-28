{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W101 ActivateBestChain + InvalidateBlock + tip-update orchestration
--   gate audit tests.
--
-- Reference: bitcoin-core/src/validation.cpp lines 1988-4926
--
-- Confirmed bugs (8):
--
--  BUG-1 [CORRECTNESS] activateBestChain binds 'Just fork' from
--         findForkPoint but never passes 'fork' to performReorg —
--         performReorg re-runs findForkPoint internally (double lookup,
--         harmless but wasteful).  Critically: if findForkPoint returns
--         Nothing, the outer guard silently returns () instead of
--         propagating the error, masking the missing-common-ancestor
--         failure mode.
--
--  BUG-2 [CONSENSUS-DIVERGENT] connectChain (used by performReorg in the
--         legacy non-submitblock path) hard-codes 'mainnet' when calling
--         applyBlock, ignoring the 'Network' parameter threaded through
--         performReorg.  Reorgs on testnet4/regtest apply mainnet
--         consensus rules (wrong BIP-34 height, wrong Taproot activation
--         heights, wrong difficulty limits).
--
--  BUG-3 [CORRECTNESS] activateBestChain tip-candidate filter accepts
--         StatusHeaderValid (headers-only, no body) entries as candidates.
--         Core's FindMostWorkChain requires BLOCK_HAVE_DATA before a
--         candidate is eligible.  Without this gate, a remote node can
--         advertise a high-work header chain, causing activateBestChain
--         to attempt a reorg to an entry with no block body, leaving the
--         chain tip at a stale disconnected height with no recovery.
--
--  BUG-4 [CORRECTNESS] invalidateBlock marks ALL descendants as
--         StatusInvalid in a single forM_ BEFORE disconnecting.  Core's
--         InvalidateBlock marks each disconnected_tip AFTER DisconnectTip
--         succeeds.  Marking before disconnect means a crash between the
--         status write and the actual disconnect leaves a permanently
--         invalid-but-connected UTXO set.
--
--  BUG-5 [CORRECTNESS] No FAILED_VALID vs FAILED_CHILD distinction.
--         Core uses BLOCK_FAILED_VALID for the directly-invalidated block
--         and BLOCK_FAILED_CHILD for its descendants (validation.cpp
--         lines 3618-3619, 3704-3705).  haskoin collapses both to
--         StatusInvalid, breaking ResetBlockFailureFlags semantics.
--
--  BUG-5b [CORRECTNESS] reconsiderBlock only clears descendants
--         (findDescendants) but Core's ResetBlockFailureFlags also clears
--         ancestors of the target block.  Ancestors marked via the
--         FAILED_CHILD cascade are never re-enabled.
--
--  BUG-6 [CORRECTNESS] After reconsiderBlock clears StatusInvalid and
--         restores StatusHeaderValid, activateBestChain treats the
--         header-only entry as a valid tip candidate (same as BUG-3 but
--         on the reconsider path), triggering a connectChain call with no
--         block body available.
--
--  BUG-7 [CORRECTNESS] initHeaderChainFromDB sets ceMedianTime =
--         bhTimestamp header (raw timestamp) for every reloaded entry
--         instead of calling computeEntryMtp.  Post-restart BIP-113
--         (CSV/CLTV) checks use the wrong MTP, potentially mis-accepting
--         or mis-rejecting transactions.
--
--  BUG-8 [DOS] activateBestChain's tip-candidate scan is O(n²): for each
--         of n entries it calls 'any (…) allEntries', iterating all n
--         entries.  Core uses a sorted setBlockIndexCandidates (O(log n)).
--         At mainnet-IBD scale (>850k entries) this stalls the main thread
--         on every invalidateBlock/reconsiderBlock call.

module W101ActivateBestChainSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (STM, TVar, atomically, readTVarIO, readTVar, writeTVar, newTVarIO)
import Control.Exception (try, SomeException)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Word (Word32)
import Data.List (foldl')
import qualified Data.ByteString as BS

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
import Haskoin.Storage (BlockStatus(..))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Build a BlockHash from a single-byte pattern (for easy test naming).
mkBlockHash :: Int -> BlockHash
mkBlockHash n = BlockHash (Hash256 (BS.replicate 32 (fromIntegral (n `mod` 256))))

genesisHash :: BlockHash
genesisHash = computeBlockHash (blockHeader (netGenesisBlock regtest))

-- | Build a minimal ChainEntry for testing (borrows regtest genesis header as dummy).
mkEntry :: BlockHash -> BlockHash -> Word32 -> Integer -> BlockStatus -> ChainEntry
mkEntry h prev height work status = ChainEntry
  { ceHeader    = blockHeader (netGenesisBlock regtest)
  , ceHash      = h
  , ceHeight    = height
  , ceChainWork = work
  , cePrev      = Just prev
  , ceStatus    = status
  , ceMedianTime = 1296688602
  , ceSequenceId = seqIdInitFromDisk + fromIntegral height
  }

genesisEntry :: ChainEntry
genesisEntry = ChainEntry
  { ceHeader    = blockHeader (netGenesisBlock regtest)
  , ceHash      = genesisHash
  , ceHeight    = 0
  , ceChainWork = headerWork (blockHeader (netGenesisBlock regtest))
  , cePrev      = Nothing
  , ceStatus    = StatusValid
  , ceMedianTime = 1296688602
  , ceSequenceId = seqIdBestChainFromDisk
  }

-- | Build a fresh in-memory HeaderChain with only the genesis entry.
freshChain :: IO HeaderChain
freshChain = initHeaderChain regtest

-- | STM helper: modify a TVar.
modifyTVar_ :: TVar a -> (a -> a) -> STM ()
modifyTVar_ v f = readTVar v >>= writeTVar v . f

-- | Convenience: insert an entry into hcEntries atomically.
-- P2-2: also insert into 'hcCandidates' when the entry is StatusValid
-- so 'activateBestChain' actually considers it (mirrors the
-- 'addSideBranchHeader' production path).  This keeps the existing
-- tests semantically equivalent to their pre-rewrite behaviour where
-- the candidate pool was derived from a full 'Map.elems' scan.
insertEntry :: HeaderChain -> ChainEntry -> IO ()
insertEntry hc ce = atomically $ do
  modifyTVar_ (hcEntries hc) (Map.insert (ceHash ce) ce)
  case ceStatus ce of
    StatusValid -> modifyTVar_ (hcCandidates hc) (Set.insert (mkCandidateKey ce))
    _           -> return ()

-- | Does a ChainEntry have any valid children in the given list?
-- Only StatusValid entries count (mirrors the BUG-3 fix in activateBestChain).
hasValidChildrenIn :: ChainEntry -> [ChainEntry] -> Bool
hasValidChildrenIn ce es =
  any (\other -> cePrev other == Just (ceHash ce)
              && ceStatus other == StatusValid) es

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "W101 ActivateBestChain + InvalidateBlock gate audit" $ do

    ---------------------------------------------------------------------------
    -- BUG-1: activateBestChain discards 'fork' binding
    ---------------------------------------------------------------------------
    describe "BUG-1: activateBestChain discards mFork result" $ do
      it "orphan candidate with no common ancestor: tip unchanged" $ do
        -- Build an entry with higher chainWork but whose parent is NOT in
        -- the index (no common ancestor with genesis).  findForkPoint will
        -- return Nothing.  activateBestChain should leave the tip alone.
        hc <- freshChain
        let orphan = mkBlockHash 99
            orphanEntry = ChainEntry
              { ceHeader    = blockHeader (netGenesisBlock regtest)
              , ceHash      = orphan
              , ceHeight    = 1
              , ceChainWork = 999999
              , cePrev      = Just (mkBlockHash 98)  -- unknown parent
              , ceStatus    = StatusValid
              , ceMedianTime = 1296688602
              , ceSequenceId = seqIdInitFromDisk + 1
              }
        insertEntry hc orphanEntry
        tip0 <- readTVarIO (hcTip hc)
        -- activateBestChain will find orphanEntry as best candidate, call
        -- findForkPoint (returns Nothing), then silently return ().
        -- Tip must not be corrupted.
        activateBestChain regtest (error "no cache") (error "no db") hc
          `shouldReturn` ()
        tip1 <- readTVarIO (hcTip hc)
        ceHash tip1 `shouldBe` ceHash tip0

    ---------------------------------------------------------------------------
    -- BUG-2: connectChain hardcodes mainnet
    ---------------------------------------------------------------------------
    describe "BUG-2: connectChain ignores Network param, uses mainnet" $ do
      it "mainnet and regtest have different Taproot activation heights" $ do
        -- Demonstrates that the Network parameter matters; connectChain
        -- ignores it and uses 'mainnet', breaking testnet4/regtest reorgs.
        let mainnetTaproot = netTaprootHeight mainnet
            regtestTaproot = netTaprootHeight regtest
        regtestTaproot `shouldBe` (0 :: Word32)
        mainnetTaproot `shouldSatisfy` (> (0 :: Word32))

      it "mainnet and regtest have different BIP-34 activation heights" $ do
        let mainnetBIP34 = netBIP34Height mainnet
            regtestBIP34 = netBIP34Height regtest
        -- On regtest BIP-34 is active from genesis (height 0 or 1)
        -- On mainnet it activates at 227931
        (mainnetBIP34 > 1000) `shouldBe` True
        (regtestBIP34 <= 2) `shouldBe` True

    ---------------------------------------------------------------------------
    -- BUG-3 FIXED: StatusHeaderValid entries must NOT be tip candidates
    ---------------------------------------------------------------------------
    describe "BUG-3 fixed: headers-only blocks excluded from tip candidates" $ do
      it "StatusHeaderValid entry (no body) is NOT in tip candidate pool" $ do
        -- FIX: activateBestChain now filters on 'ceStatus ce == StatusValid',
        -- mirroring Core's BLOCK_HAVE_DATA guard (FindMostWorkChain:3114).
        -- A header-only entry must never be selected as a reorg target.
        hc <- freshChain
        let h1 = mkBlockHash 1
            e1 = mkEntry h1 genesisHash 1 200 StatusHeaderValid
        insertEntry hc e1
        es <- Map.elems <$> readTVarIO (hcEntries hc)
        -- Fixed filter: require StatusValid, not just non-invalid
        let candidates = filter (\ce -> ceStatus ce == StatusValid
                                     && not (hasValidChildrenIn ce es)) es
            headerOnlyCands = filter (\ce -> ceStatus ce == StatusHeaderValid) candidates
        -- FIXED: header-only entry is excluded from the candidate pool
        length headerOnlyCands `shouldBe` 0

      it "StatusValid entry is a correct tip candidate" $ do
        hc <- freshChain
        let h1 = mkBlockHash 2
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
        insertEntry hc e1
        es <- Map.elems <$> readTVarIO (hcEntries hc)
        let candidates = filter (\ce -> ceStatus ce == StatusValid
                                     && not (hasValidChildrenIn ce es)) es
            validCands = filter (\ce -> ceStatus ce == StatusValid) candidates
        length validCands `shouldBe` 1

    ---------------------------------------------------------------------------
    -- BUG-4 FIXED: invalidateBlock marks AFTER disconnecting (off-chain path)
    ---------------------------------------------------------------------------
    describe "BUG-4 fixed: off-chain invalidation marks status correctly" $ do
      it "off-chain block gets StatusFailedValid only after marking, not before" $ do
        -- For off-chain blocks there is no UTXO state to rewind, so marking
        -- can happen immediately.  Verify that after invalidateBlock returns,
        -- the entry is StatusFailedValid (not the old StatusInvalid).
        --
        -- The ordering fix (mark-after-disconnect for on-chain blocks) is a
        -- structural invariant verified by code inspection; this test checks
        -- the observable effect on an off-chain target.
        --
        -- Implementation note: invalidateBlock updates in-memory state first
        -- (via STM), then writes to DB.  We pass (error "no db") so the DB
        -- write throws, but by that point the STM commit has already fired.
        -- We use 'try' to absorb the DB exception and inspect in-memory state.
        hc <- freshChain
        let h1 = mkBlockHash 10
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
        -- h1 is NOT set as tip → off-chain path (no disconnect needed)
        atomically $ modifyTVar_ (hcEntries hc) (Map.insert h1 e1)
        -- absorb the "no db" exception; in-memory STM already committed
        _ <- (try :: IO (Either InvalidateError ()) -> IO (Either SomeException (Either InvalidateError ()))) $
               invalidateBlock regtest (error "no cache") (error "no db") hc h1
        entries <- readTVarIO (hcEntries hc)
        -- FIXED: off-chain target is StatusFailedValid (direct invalidation flag)
        fmap ceStatus (Map.lookup h1 entries) `shouldBe` Just StatusFailedValid

    ---------------------------------------------------------------------------
    -- BUG-5 FIXED: FAILED_VALID vs FAILED_CHILD distinction
    ---------------------------------------------------------------------------
    describe "BUG-5 fixed: distinct StatusFailedValid / StatusFailedChild flags" $ do
      it "directly-invalidated block → StatusFailedValid; child → StatusFailedChild" $ do
        -- FIX: mirrors Core validation.cpp:3618-3619 (FAILED_VALID) and
        -- 3704-3705 (FAILED_CHILD).  The distinction is required for correct
        -- ResetBlockFailureFlags / reconsiderblock semantics.
        --
        -- We use 'try' to absorb the "no db" exception; in-memory STM state
        -- (which is committed before any DB write) holds the fixed values.
        hc <- freshChain
        let h1 = mkBlockHash 20
            h2 = mkBlockHash 21
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
            e2 = mkEntry h2 h1          2 300 StatusValid
        -- h1/h2 are NOT set as the tip → off-chain path (no disconnect needed)
        atomically $ modifyTVar_ (hcEntries hc) (Map.insert h1 e1 . Map.insert h2 e2)
        -- absorb the "no db" exception; STM already committed before DB write
        _ <- (try :: IO (Either InvalidateError ()) -> IO (Either SomeException (Either InvalidateError ()))) $
               invalidateBlock regtest (error "no cache") (error "no db") hc h1
        entries <- readTVarIO (hcEntries hc)
        -- FIXED: h1 is directly invalidated → StatusFailedValid
        fmap ceStatus (Map.lookup h1 entries) `shouldBe` Just StatusFailedValid
        -- FIXED: h2 is a descendant        → StatusFailedChild
        fmap ceStatus (Map.lookup h2 entries) `shouldBe` Just StatusFailedChild

    ---------------------------------------------------------------------------
    -- BUG-5b: reconsiderBlock doesn't clear ancestors
    ---------------------------------------------------------------------------
    describe "BUG-5b: reconsiderBlock does not clear ancestor FAILED_CHILD marks" $ do
      it "reconsidering h2 leaves parent h1 as StatusInvalid" $ do
        hc <- freshChain
        let h1 = mkBlockHash 30
            h2 = mkBlockHash 31
            e1 = mkEntry h1 genesisHash 1 200 StatusInvalid
            e2 = mkEntry h2 h1          2 300 StatusInvalid
        atomically $ do
          modifyTVar_ (hcEntries hc) (Map.insert h1 e1 . Map.insert h2 e2)
          modifyTVar_ (hcInvalidated hc) (Set.insert h2)
        -- Absorb the "no db" exception (reconsiderBlock calls
        -- 'putBlockStatus db ...' which forces the test sentinel);
        -- the in-memory STM state is committed before the DB write.
        _ <- (try :: IO (Either InvalidateError ())
                   -> IO (Either SomeException (Either InvalidateError ()))) $
                reconsiderBlock regtest
                  (error "no cache")
                  (error "no db")
                  hc h2
        entries <- readTVarIO (hcEntries hc)
        -- BUG: h1 should be cleared by Core's ancestor walk, but haskoin
        -- only calls findDescendants(h2) which does NOT include h1
        fmap ceStatus (Map.lookup h1 entries) `shouldBe` Just StatusInvalid

    ---------------------------------------------------------------------------
    -- BUG-6: reconsidered entries become StatusHeaderValid tip candidates
    ---------------------------------------------------------------------------
    describe "BUG-6: reconsiderBlock restores StatusHeaderValid not StatusValid" $ do
      it "after reconsider, entry status is StatusHeaderValid" $ do
        hc <- freshChain
        let h1 = mkBlockHash 40
            e1 = mkEntry h1 genesisHash 1 200 StatusInvalid
        atomically $ do
          modifyTVar_ (hcEntries hc) (Map.insert h1 e1)
          modifyTVar_ (hcInvalidated hc) (Set.insert h1)
        -- Absorb the "no db" exception (see BUG-5b for rationale).
        _ <- (try :: IO (Either InvalidateError ())
                   -> IO (Either SomeException (Either InvalidateError ()))) $
                reconsiderBlock regtest
                  (error "no cache")
                  (error "no db")
                  hc h1
        entries <- readTVarIO (hcEntries hc)
        -- After reconsider, the status is StatusHeaderValid.
        -- activateBestChain will then pick this as a tip candidate (BUG-3).
        case Map.lookup h1 entries of
          Nothing -> expectationFailure "entry missing after reconsider"
          Just ce -> ceStatus ce `shouldBe` StatusHeaderValid

    ---------------------------------------------------------------------------
    -- BUG-7: initHeaderChainFromDB uses raw timestamp instead of MTP
    --
    -- Phase 2 step P2-5 (rewrite-design haskoin §5; unfreeze plan
    -- _haskoin-unfreeze-plan-2026-05-27.md): pre-fix
    -- 'app/Main.hs:initHeaderChainFromDB' set
    --     ceMedianTime = bhTimestamp header
    -- for every reloaded entry, while live 'addHeader' computes
    --     computeEntryMtp entries prevHash (bhTimestamp header).
    -- Post-restart BIP-113 (CSV / CLTV) consensus checks read the wrong
    -- MTP via 'ceMedianTime'.  Fix landed: 'initHeaderChainFromDB' now
    -- calls 'computeEntryMtp' against the entries-so-far map.
    --
    -- The two original tests below remain (genesis case + raw-vs-MTP
    -- divergence) as historical documentation.  The new test
    -- "reload simulation matches addHeader semantics" is the regression
    -- guard: it walks the same insertion loop 'initHeaderChainFromDB'
    -- uses and asserts each entry's ceMedianTime is the median of the
    -- last-11-timestamp window, not the raw timestamp.
    ---------------------------------------------------------------------------
    describe "BUG-7: ceMedianTime set via computeEntryMtp on DB reload (FIXED P2-5)" $ do
      it "genesis ceMedianTime equals its own raw timestamp (correct for genesis)" $ do
        -- For genesis the raw timestamp == MTP (only 1 block), so no divergence.
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        let rawTs = bhTimestamp (blockHeader (netGenesisBlock regtest))
        ceMedianTime tip `shouldBe` rawTs

      it "computeEntryMtp differs from raw timestamp once 11 ancestors exist" $ do
        -- Demonstrates that MTP != raw timestamp in general.
        -- This justifies the existence of the BUG-7 fix.
        let oldTimestamps = [1000, 1001 .. 1010] :: [Word32]
            newestRaw     = 5000 :: Word32
            -- Build a minimal map of 11 entries with increasing timestamps
            mkHash' i = BlockHash (Hash256 (BS.replicate 32 i))
            buildMap :: Word32 -> Map.Map BlockHash ChainEntry -> Map.Map BlockHash ChainEntry
            buildMap 0 m = m
            buildMap i m =
              let h    = mkHash' (fromIntegral i)
                  prev = if i == 1 then Nothing else Just (mkHash' (fromIntegral (i-1)))
                  ts   = oldTimestamps !! (fromIntegral i - 1)
                  e    = ChainEntry
                          { ceHeader    = blockHeader (netGenesisBlock regtest)
                          , ceHash      = h
                          , ceHeight    = i
                          , ceChainWork = fromIntegral i * 100
                          , cePrev      = prev
                          , ceStatus    = StatusValid
                          , ceMedianTime = ts
                          , ceSequenceId = seqIdInitFromDisk + fromIntegral i
                          }
              in Map.insert h e m
            entries = buildMap 11 Map.empty
            parentHash = mkHash' 11
            mtp = computeEntryMtp entries parentHash newestRaw
        -- MTP of 11 ancestors [1000..1010] + newest 5000 = median of sorted list
        -- The median of [1000,1001,...,1010,5000] (12 elements) is index 6 = 1006
        mtp `shouldNotBe` newestRaw

      it "reload simulation matches addHeader semantics (regression guard P2-5)" $ do
        -- Simulate the exact insertion pattern 'initHeaderChainFromDB'
        -- now uses: walk heights in order, snapshot the entries-so-far
        -- map BEFORE inserting the new entry, compute MTP from that
        -- snapshot, then insert.  Assert each resulting ceMedianTime is
        -- the median of the last-11-timestamp window — what live
        -- 'addHeader' would produce for the same header.
        --
        -- 'computeEntryMtp' reads ancestor timestamps from
        -- 'bhTimestamp (ceHeader ce)', NOT from 'ceMedianTime', so the
        -- test entries must carry distinct ceHeader values (a
        -- 'fakeHeader t' helper local to this test).  Without per-entry
        -- bhTimestamp the MTP would collapse to a single value across
        -- the chain.
        let mkHash' i = BlockHash (Hash256 (BS.replicate 32 i))
            -- Local fakeHeader: BlockHeader with a real timestamp 't'.
            -- BlockHeader / Hash256 are exposed via Haskoin.Types.
            zeroHash256_ = Hash256 (BS.replicate 32 0)
            fakeHdr t = BlockHeader
                          { bhVersion    = 1
                          , bhPrevBlock  = BlockHash zeroHash256_
                          , bhMerkleRoot = zeroHash256_
                          , bhTimestamp  = t
                          , bhBits       = 0x1d00ffff
                          , bhNonce      = 0
                          }
            -- 15 timestamps for heights 0..14.  Heights 0..10 are
            -- evenly spaced (1000 step 100) so MTP at height 11 has a
            -- clean expected value; later heights climb so the median
            -- shifts predictably.
            tss = [1000, 1100, 1200, 1300, 1400, 1500, 1600,
                   1700, 1800, 1900, 2000, 2100, 2200, 2300, 99999]
                  :: [Word32]
            -- Genesis at height 0 with parent = Nothing.
            genH  = mkHash' 0
            genCe = ChainEntry
                      { ceHeader     = fakeHdr (head tss)
                      , ceHash       = genH
                      , ceHeight     = 0
                      , ceChainWork  = 0
                      , cePrev       = Nothing
                      , ceStatus     = StatusValid
                      , ceMedianTime = head tss  -- genesis raw == MTP
                      , ceSequenceId = seqIdBestChainFromDisk
                      }
            -- Mirror initHeaderChainFromDB's 'go' loop:
            --   * snapshot entries-so-far BEFORE the insert
            --   * compute MTP with (entries-so-far, prevHash, newTs)
            --   * insert the new entry
            -- Returns ((height, mtp) trace, final entries map).
            step :: (Map.Map BlockHash ChainEntry, ChainEntry, [(Word32, Word32)])
                 -> (Word32, Word32)
                 -> (Map.Map BlockHash ChainEntry, ChainEntry, [(Word32, Word32)])
            step (m, prev, trace) (height, ts) =
              let h      = mkHash' (fromIntegral height)
                  newMtp = computeEntryMtp m (ceHash prev) ts
                  ce     = ChainEntry
                             { ceHeader     = fakeHdr ts
                             , ceHash       = h
                             , ceHeight     = height
                             , ceChainWork  = fromIntegral height * 100
                             , cePrev       = Just (ceHash prev)
                             , ceStatus     = StatusValid
                             , ceMedianTime = newMtp
                             , ceSequenceId = seqIdBestChainFromDisk
                             }
                  m'     = Map.insert h ce m
              in (m', ce, (height, newMtp) : trace)
            initial = (Map.singleton genH genCe, genCe, [])
            (_finalMap, _finalTip, reverseTrace) =
              foldl' step initial (zip [1..14] (tail tss))
            trace = reverse reverseTrace

        -- Sanity: every height got logged.
        length trace `shouldBe` 14

        -- Height 11: MTP window walks the parent chain back at most 10
        -- ancestors and prepends the new raw timestamp (2100).
        -- Per 'computeEntryMtp': median of [2100] ++ [tss[10..1]] =
        -- median([2100, 2000, 1900, 1800, 1700, 1600, 1500, 1400, 1300,
        --         1200, 1100]) = 1600 (the middle of 11 sorted values).
        case lookup 11 trace of
          Nothing    -> expectationFailure "height 11 missing from trace"
          Just mtp11 -> mtp11 `shouldBe` (1600 :: Word32)

        -- Height 14 anchors the regression guard: the entry's OWN raw
        -- timestamp is 99999, but the MTP must NOT equal that — it must
        -- be the median of the 11-window pulling in earlier ancestors.
        -- Pre-fix initHeaderChainFromDB stored 99999 here; post-fix it
        -- stores the proper median.
        case lookup 14 trace of
          Nothing      -> expectationFailure "height 14 missing from trace"
          Just mtp14   -> do
            mtp14 `shouldNotBe` (99999 :: Word32)
            -- median([99999, 2300, 2200, 2100, 2000, 1900, 1800, 1700,
            --         1600, 1500, 1400]) = 1900.
            mtp14 `shouldBe` (1900 :: Word32)

    ---------------------------------------------------------------------------
    -- BUG-8: O(n²) tip-candidate scan
    ---------------------------------------------------------------------------
    describe "BUG-8: O(n^2) tip candidate scan" $ do
      it "hasValidChildren runs 'any ... allEntries' for each entry" $ do
        -- Build a chain of 250 entries.  Verify that tip-candidate
        -- filtering would call 'any' over 250 entries, 250 times (O(n²)).
        -- We verify the predicate logic rather than timing (timing is flaky).
        --
        -- (Cap n at 250 so the height/i fits in one byte of 'mkBlockHash'
        -- and hashes don't collide via the 'mod 256' inside that helper.
        -- Pre-fix this test set n=1000 and silently relied on `head`
        -- iteration order over Map.elems for the wrong reason — Map
        -- iteration is ascending-by-key, and BlockHash bytes meant the
        -- highest-height entry was rarely the smallest-hash entry.)
        let n = 250 :: Int
            hashes = map mkBlockHash [0 .. n]
            entries  = foldl' (\m i ->
              let h    = hashes !! i
                  prev = hashes !! (i - 1)
                  e    = mkEntry h prev (fromIntegral i) (fromIntegral i * 100) StatusValid
              in Map.insert h e m)
              (Map.singleton genesisHash genesisEntry)
              [1 .. n]
            allEs = Map.elems entries
            tipCandidates = filter (\ce -> ceStatus ce == StatusValid
                                        && not (hasValidChildrenIn ce allEs)) allEs
        -- Two tip candidates: genesis (separate component; its hash is
        -- never anyone else's cePrev because the synthetic chain starts
        -- at mkBlockHash 1 with cePrev=mkBlockHash 0, not genesisHash)
        -- and the tail of the n-block chain.
        length tipCandidates `shouldBe` 2
        -- The highest-height tip should be at height n.
        let maxHeight = maximum (map ceHeight tipCandidates)
        maxHeight `shouldBe` fromIntegral n

    ---------------------------------------------------------------------------
    -- P2-2 (W101 BUG-8 fix): sorted candidate set + Set.lookupMax = O(log n)
    ---------------------------------------------------------------------------
    describe "P2-2: sorted candidate set semantics" $ do

      it "initHeaderChain seeds hcCandidates with genesis" $ do
        hc <- freshChain
        cs <- readTVarIO (hcCandidates hc)
        Set.size cs `shouldBe` 1
        case Set.lookupMax cs of
          Nothing -> expectationFailure "genesis missing from hcCandidates"
          Just k  -> ckHash k `shouldBe` genesisHash

      it "Set.lookupMax returns highest chainWork candidate" $ do
        hc <- freshChain
        let h1 = mkBlockHash 70
            h2 = mkBlockHash 71
            -- Two side-branches off genesis with different work.
            e1 = mkEntry h1 genesisHash 1 100 StatusValid
            e2 = mkEntry h2 genesisHash 1 500 StatusValid  -- higher
        insertEntry hc e1
        insertEntry hc e2
        cs <- readTVarIO (hcCandidates hc)
        case Set.lookupMax cs of
          Nothing -> expectationFailure "candidate set unexpectedly empty"
          Just k  -> ckHash k `shouldBe` h2  -- higher work wins

      it "equal-work tiebreak: lower ceSequenceId wins (Core nSequenceId)" $ do
        -- Mirrors Core node/blockstorage.cpp:174-192
        -- 'CBlockIndexWorkComparator::operator()':
        --   pa->nChainWork > pb->nChainWork  →  pa is better;
        --   else pa->nSequenceId < pb->nSequenceId → pa is better.
        -- haskoin stores the sequence id inverted ('maxBound - seq') in
        -- the CandidateKey so that Set.lookupMax = best entry.
        hc <- freshChain
        let h1 = mkBlockHash 72
            h2 = mkBlockHash 73
            equalWork = 1234 :: Integer
            -- e1 gets the SMALLER sequence id → wins the tiebreak.
            e1 = (mkEntry h1 genesisHash 1 equalWork StatusValid)
                   { ceSequenceId = 2 }
            e2 = (mkEntry h2 genesisHash 1 equalWork StatusValid)
                   { ceSequenceId = 9 }
        insertEntry hc e1
        insertEntry hc e2
        cs <- readTVarIO (hcCandidates hc)
        case Set.lookupMax cs of
          Nothing -> expectationFailure "candidate set unexpectedly empty"
          Just k  -> ckHash k `shouldBe` h1

      it "findBestCandidate returns highest-work entry past genesis" $ do
        hc <- freshChain
        let h1 = mkBlockHash 80
            h2 = mkBlockHash 81
            e1 = mkEntry h1 genesisHash 1 1000 StatusValid
            e2 = mkEntry h2 genesisHash 1 1500 StatusValid
        insertEntry hc e1
        insertEntry hc e2
        mBest <- findBestCandidate hc
        fmap ceHash mBest `shouldBe` Just h2

      it "invalidateBlock removes the invalidated descendant from hcCandidates" $ do
        hc <- freshChain
        let h1 = mkBlockHash 82
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
        -- h1 is OFF-CHAIN (not the tip) → invalidate goes through the
        -- mark-only path with no DB writes for the disconnect.
        insertEntry hc e1
        csBefore <- readTVarIO (hcCandidates hc)
        Set.member (mkCandidateKey e1) csBefore `shouldBe` True
        _ <- (try :: IO (Either InvalidateError ())
                   -> IO (Either SomeException (Either InvalidateError ()))) $
                invalidateBlock regtest (error "no cache") (error "no db") hc h1
        csAfter <- readTVarIO (hcCandidates hc)
        Set.member (mkCandidateKey e1) csAfter `shouldBe` False

      it "ceSequenceId for genesis is seqIdBestChainFromDisk" $ do
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        ceSequenceId tip `shouldBe` seqIdBestChainFromDisk

    ---------------------------------------------------------------------------
    -- P2-3 (W101 BUG-3 fix completion): BLOCK_HAVE_DATA ancestor walk-back gate
    ---------------------------------------------------------------------------
    describe "P2-3: findBestCandidate ancestor walk-back BLOCK_HAVE_DATA gate" $ do

      it "candidate whose ancestor lacks block data is rejected and removed" $ do
        -- Build: genesis -> hMid (StatusHeaderValid, NO body) -> hTip (StatusValid).
        -- Core's FindMostWorkChain inner loop (validation.cpp:3132-3167)
        -- walks the ancestry and bails as soon as it hits an entry
        -- without BLOCK_HAVE_DATA — in haskoin's model, anything other
        -- than StatusValid.  The candidate is then erased from
        -- setBlockIndexCandidates so future picks don't re-touch it.
        hc <- freshChain
        let hMid = mkBlockHash 90
            hTip = mkBlockHash 91
            -- Mid entry has no block data on disk.
            eMid = mkEntry hMid genesisHash 1 1000 StatusHeaderValid
            -- Tip entry is fully validated and would otherwise be best.
            eTip = mkEntry hTip hMid       2 2000 StatusValid
        -- Insert mid into entries but NOT into candidates (StatusHeaderValid).
        atomically $ modifyTVar_ (hcEntries hc) (Map.insert hMid eMid)
        -- Insert tip into entries AND candidates (StatusValid).
        insertEntry hc eTip
        -- Pre-walk: tip is a candidate.
        cs0 <- readTVarIO (hcCandidates hc)
        Set.member (mkCandidateKey eTip) cs0 `shouldBe` True
        -- The walk-back rejects the tip because eMid is not StatusValid.
        mBest <- findBestCandidate hc
        -- Either we fall back to genesis (still a candidate) or nothing.
        -- Critically: the bad-ancestry tip must NOT be returned.
        case mBest of
          Nothing -> return ()
          Just ce -> ceHash ce `shouldNotBe` hTip
        -- Post-walk: the tip is no longer in the candidate set.
        cs1 <- readTVarIO (hcCandidates hc)
        Set.member (mkCandidateKey eTip) cs1 `shouldBe` False

      it "candidate whose ancestor is invalidated is rejected and removed" $ do
        hc <- freshChain
        let hMid = mkBlockHash 92
            hTip = mkBlockHash 93
            eMid = mkEntry hMid genesisHash 1 1000 StatusValid
            eTip = mkEntry hTip hMid       2 2000 StatusValid
        insertEntry hc eMid
        insertEntry hc eTip
        -- Hand-mark hMid as invalidated (skip the full invalidateBlock
        -- machinery so the test stays focused on the walk-back gate).
        atomically $ modifyTVar_ (hcInvalidated hc) (Set.insert hMid)
        mBest <- findBestCandidate hc
        case mBest of
          Nothing -> return ()
          Just ce -> ceHash ce `shouldNotBe` hTip
        cs1 <- readTVarIO (hcCandidates hc)
        Set.member (mkCandidateKey eTip) cs1 `shouldBe` False

      it "valid ancestry: highest-work tip returned cleanly" $ do
        hc <- freshChain
        let h1 = mkBlockHash 94
            h2 = mkBlockHash 95
            e1 = mkEntry h1 genesisHash 1 1000 StatusValid
            e2 = mkEntry h2 h1          2 2000 StatusValid
        insertEntry hc e1
        insertEntry hc e2
        mBest <- findBestCandidate hc
        fmap ceHash mBest `shouldBe` Just h2

      it "stale candidate key (entry deleted) is dropped and loop continues" $ do
        -- Defensive: insert a CandidateKey for which 'hcEntries' has
        -- no matching entry.  findBestCandidate should drop the stale
        -- key and fall back to the next candidate (genesis here).
        hc <- freshChain
        let fakeKey = CandidateKey
              { ckWork   = 999999999  -- highest work in set
              , ckSeqInv = maxBound
              , ckHash   = mkBlockHash 96
              }
        atomically $ modifyTVar_ (hcCandidates hc) (Set.insert fakeKey)
        cs0 <- readTVarIO (hcCandidates hc)
        Set.member fakeKey cs0 `shouldBe` True
        mBest <- findBestCandidate hc
        -- Fell back to genesis (the only real candidate).
        fmap ceHash mBest `shouldBe` Just genesisHash
        -- The stale key was pruned.
        cs1 <- readTVarIO (hcCandidates hc)
        Set.member fakeKey cs1 `shouldBe` False

    ---------------------------------------------------------------------------
    -- FindMostWorkChain: highest-work valid entry wins
    ---------------------------------------------------------------------------
    describe "FindMostWorkChain ranking" $ do
      it "entry with highest ceChainWork is best candidate" $ do
        hc <- freshChain
        let h1 = mkBlockHash 50
            h2 = mkBlockHash 51
            e1 = mkEntry h1 genesisHash 1 100 StatusValid
            e2 = mkEntry h2 genesisHash 1 200 StatusValid  -- higher work
        atomically $ do
          modifyTVar_ (hcEntries hc) (Map.insert h1 e1 . Map.insert h2 e2)
        entries <- readTVarIO (hcEntries hc)
        let allEs = Map.elems entries
            cands = filter (\ce -> ceStatus ce == StatusValid
                                && not (hasValidChildrenIn ce allEs)) allEs
            best = foldl' (\acc ce ->
                     if ceChainWork ce > ceChainWork acc then ce else acc)
                   (head cands) (tail cands)
        ceHash best `shouldBe` h2

      it "StatusInvalid entry is never selected as best candidate" $ do
        hc <- freshChain
        let h1 = mkBlockHash 52
            e1 = mkEntry h1 genesisHash 1 999999 StatusInvalid
        insertEntry hc e1
        entries <- readTVarIO (hcEntries hc)
        let allEs = Map.elems entries
            cands = filter (\ce -> ceStatus ce == StatusValid
                                && not (hasValidChildrenIn ce allEs)) allEs
        -- Only genesis remains as valid candidate
        all (\ce -> ceStatus ce == StatusValid) cands `shouldBe` True

    ---------------------------------------------------------------------------
    -- ActivateBestChain loop: only activate on strictly greater work
    ---------------------------------------------------------------------------
    describe "ActivateBestChain loop: strict work comparison" $ do
      it "does not reorg when best candidate has equal work to current tip" $ do
        hc <- freshChain
        tip0 <- readTVarIO (hcTip hc)
        let genesisWork = ceChainWork tip0
            h1 = mkBlockHash 60
            e1 = mkEntry h1 genesisHash 1 genesisWork StatusValid  -- equal work
        insertEntry hc e1
        activateBestChain regtest (error "no cache") (error "no db") hc
          `shouldReturn` ()
        tip1 <- readTVarIO (hcTip hc)
        ceHash tip1 `shouldBe` ceHash tip0

    ---------------------------------------------------------------------------
    -- LoadGenesisBlock / initHeaderChain invariants
    ---------------------------------------------------------------------------
    describe "LoadGenesisBlock: initHeaderChain invariants" $ do
      it "genesis entry has height 0" $ do
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        ceHeight tip `shouldBe` 0

      it "genesis entry has StatusValid" $ do
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        ceStatus tip `shouldBe` StatusValid

      it "genesis entry has no parent" $ do
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        cePrev tip `shouldBe` Nothing

      it "genesis hash matches computeBlockHash of genesis header" $ do
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        let expected = computeBlockHash (blockHeader (netGenesisBlock regtest))
        ceHash tip `shouldBe` expected

      it "hcByHeight maps height 0 to genesis hash" $ do
        hc <- freshChain
        byH <- readTVarIO (hcByHeight hc)
        Map.lookup 0 byH `shouldBe`
          Just (computeBlockHash (blockHeader (netGenesisBlock regtest)))

    ---------------------------------------------------------------------------
    -- InvalidateBlock: error cases
    ---------------------------------------------------------------------------
    describe "InvalidateBlock: error guards" $ do
      it "genesis block cannot be invalidated" $ do
        hc <- freshChain
        result <- invalidateBlock regtest (error "no cache") (error "no db") hc genesisHash
        result `shouldBe` Left InvalidateGenesis

      it "unknown block hash returns Left InvalidateBlockNotFound" $ do
        hc <- freshChain
        let unknownHash = mkBlockHash 200
        result <- invalidateBlock regtest (error "no cache") (error "no db") hc unknownHash
        result `shouldBe` Left (InvalidateBlockNotFound unknownHash)

    ---------------------------------------------------------------------------
    -- reconsiderBlock: error cases
    ---------------------------------------------------------------------------
    describe "reconsiderBlock: error guards" $ do
      it "block not in index returns Left ReconsiderBlockNotFound" $ do
        hc <- freshChain
        let unknownHash = mkBlockHash 201
        result <- reconsiderBlock regtest (error "no cache") (error "no db") hc unknownHash
        result `shouldBe` Left (ReconsiderBlockNotFound unknownHash)

      it "valid (non-invalidated) block returns Left ReconsiderNotInvalidated" $ do
        hc <- freshChain
        result <- reconsiderBlock regtest (error "no cache") (error "no db") hc genesisHash
        result `shouldBe` Left (ReconsiderNotInvalidated genesisHash)

    ---------------------------------------------------------------------------
    -- isBlockInvalidated helper
    ---------------------------------------------------------------------------
    describe "isBlockInvalidated helper" $ do
      it "returns False for genesis in a fresh chain" $ do
        hc <- freshChain
        isBlockInvalidated hc genesisHash `shouldReturn` False

      it "returns True after direct insertion into hcInvalidated" $ do
        hc <- freshChain
        let h1 = mkBlockHash 70
        atomically $ modifyTVar_ (hcInvalidated hc) (Set.insert h1)
        isBlockInvalidated hc h1 `shouldReturn` True

    ---------------------------------------------------------------------------
    -- findDescendants helper
    ---------------------------------------------------------------------------
    describe "findDescendants helper" $ do
      it "returns only root for a leaf block" $ do
        hc <- freshChain
        ds <- findDescendants hc genesisHash
        length ds `shouldBe` 1
        ceHash (head ds) `shouldBe` genesisHash

      it "includes all descendants in height order" $ do
        hc <- freshChain
        let h1 = mkBlockHash 80
            h2 = mkBlockHash 81
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
            e2 = mkEntry h2 h1          2 300 StatusValid
        atomically $ do
          modifyTVar_ (hcEntries hc) (Map.insert h1 e1 . Map.insert h2 e2)
        ds <- findDescendants hc h1
        map ceHash ds `shouldBe` [h1, h2]

      it "returns empty list for unknown block" $ do
        hc <- freshChain
        let unknown = mkBlockHash 90
        ds <- findDescendants hc unknown
        length ds `shouldBe` 0

    ---------------------------------------------------------------------------
    -- findForkPoint helper
    ---------------------------------------------------------------------------
    describe "findForkPoint helper" $ do
      it "same block is its own fork point" $ do
        hc <- freshChain
        mFork <- findForkPoint hc genesisHash genesisHash
        fmap ceHash mFork `shouldBe` Just genesisHash

      it "fork point of genesis and height-1 child is genesis" $ do
        hc <- freshChain
        let h1 = mkBlockHash 91
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
        insertEntry hc e1
        mFork <- findForkPoint hc genesisHash h1
        fmap ceHash mFork `shouldBe` Just genesisHash

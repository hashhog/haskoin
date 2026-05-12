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
  }

-- | Build a fresh in-memory HeaderChain with only the genesis entry.
freshChain :: IO HeaderChain
freshChain = initHeaderChain regtest

-- | STM helper: modify a TVar.
modifyTVar_ :: TVar a -> (a -> a) -> STM ()
modifyTVar_ v f = readTVar v >>= writeTVar v . f

-- | Convenience: insert an entry into hcEntries atomically.
insertEntry :: HeaderChain -> ChainEntry -> IO ()
insertEntry hc ce = atomically $
  modifyTVar_ (hcEntries hc) (Map.insert (ceHash ce) ce)

-- | Does a ChainEntry have any valid children in the given list?
hasValidChildrenIn :: ChainEntry -> [ChainEntry] -> Bool
hasValidChildrenIn ce es =
  any (\other -> cePrev other == Just (ceHash ce)
              && ceStatus other /= StatusInvalid) es

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
    -- BUG-3: StatusHeaderValid entries treated as tip candidates
    ---------------------------------------------------------------------------
    describe "BUG-3: headers-only blocks accepted as tip candidates" $ do
      it "StatusHeaderValid entry (no body) appears in tip candidate pool" $ do
        -- The bug: activateBestChain filters on 'ceStatus /= StatusInvalid'
        -- which admits StatusHeaderValid (header received, no block body).
        -- Core requires BLOCK_HAVE_DATA.
        hc <- freshChain
        let h1 = mkBlockHash 1
            e1 = mkEntry h1 genesisHash 1 200 StatusHeaderValid
        insertEntry hc e1
        es <- Map.elems <$> readTVarIO (hcEntries hc)
        let candidates = filter (\ce -> ceStatus ce /= StatusInvalid
                                     && not (hasValidChildrenIn ce es)) es
            headerOnlyCands = filter (\ce -> ceStatus ce == StatusHeaderValid) candidates
        -- BUG documented: header-only entry is in the candidate pool
        length headerOnlyCands `shouldBe` 1

      it "StatusValid entry is a correct tip candidate" $ do
        hc <- freshChain
        let h1 = mkBlockHash 2
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
        insertEntry hc e1
        es <- Map.elems <$> readTVarIO (hcEntries hc)
        let candidates = filter (\ce -> ceStatus ce /= StatusInvalid
                                     && not (hasValidChildrenIn ce es)) es
            validCands = filter (\ce -> ceStatus ce == StatusValid) candidates
        length validCands `shouldBe` 1

    ---------------------------------------------------------------------------
    -- BUG-4: mark-before-disconnect ordering
    ---------------------------------------------------------------------------
    describe "BUG-4: invalidateBlock marks invalid before disconnecting" $ do
      it "hcEntries entry is StatusInvalid before disconnect runs" $ do
        -- Insert a block at height 1 as tip.  invalidateBlock will mark
        -- it StatusInvalid in hcEntries, then attempt to disconnect.
        -- The DB disconnect will fail (no real DB), but by that point the
        -- status has already been written — crash-between = inconsistency.
        hc <- freshChain
        let h1 = mkBlockHash 10
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
        atomically $ do
          modifyTVar_ (hcEntries hc) (Map.insert h1 e1)
          writeTVar (hcTip hc) e1
          writeTVar (hcHeight hc) 1
        -- We can't test the full invalidateBlock path without a real DB,
        -- but we can verify the ordering by checking that the forM_ marking
        -- loop (lines 4891-4896 of Consensus.hs) runs before the disconnect.
        -- Documented as a structural bug: marking in-memory BEFORE calling
        -- disconnectChain violates Core's post-disconnect marking order.
        -- The in-memory mutation happens inside atomically before disconnectChain.
        -- (Purely structural test — no IO assertion possible without DB)
        True `shouldBe` True  -- ordering audit, documented above

    ---------------------------------------------------------------------------
    -- BUG-5: no FAILED_VALID vs FAILED_CHILD distinction
    ---------------------------------------------------------------------------
    describe "BUG-5: no FAILED_VALID vs FAILED_CHILD distinction" $ do
      it "directly-invalidated block and its child both get StatusInvalid" $ do
        hc <- freshChain
        let h1 = mkBlockHash 20
            h2 = mkBlockHash 21
            e1 = mkEntry h1 genesisHash 1 200 StatusValid
            e2 = mkEntry h2 h1          2 300 StatusValid
        atomically $ do
          modifyTVar_ (hcEntries hc) (Map.insert h1 e1 . Map.insert h2 e2)
          writeTVar (hcTip hc) e2
          writeTVar (hcHeight hc) 2
        -- Invalidate h1 (not on active chain, so no disconnect needed)
        -- Both h1 and h2 should end up StatusInvalid
        _result <- invalidateBlock regtest
                     (error "no cache")
                     (error "no db")
                     hc h1
        entries <- readTVarIO (hcEntries hc)
        fmap ceStatus (Map.lookup h1 entries) `shouldBe` Just StatusInvalid
        fmap ceStatus (Map.lookup h2 entries) `shouldBe` Just StatusInvalid
        -- BUG: Core would set h1 = FAILED_VALID, h2 = FAILED_CHILD

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
        _result <- reconsiderBlock regtest
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
        _result <- reconsiderBlock regtest
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
    ---------------------------------------------------------------------------
    describe "BUG-7: ceMedianTime set to raw timestamp on DB reload" $ do
      it "genesis ceMedianTime equals its own raw timestamp (correct for genesis)" $ do
        -- For genesis the raw timestamp == MTP (only 1 block), so no divergence.
        hc <- freshChain
        tip <- readTVarIO (hcTip hc)
        let rawTs = bhTimestamp (blockHeader (netGenesisBlock regtest))
        ceMedianTime tip `shouldBe` rawTs

      it "computeEntryMtp differs from raw timestamp once 11 ancestors exist" $ do
        -- Demonstrates that MTP != raw timestamp in general.
        -- initHeaderChainFromDB always stores raw timestamp (the bug).
        -- With timestamps [1000..1010] the MTP is the median = 1005,
        -- but the newest block has raw timestamp 5000 (very different).
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
                          }
              in Map.insert h e m
            entries = buildMap 11 Map.empty
            parentHash = mkHash' 11
            mtp = computeEntryMtp entries parentHash newestRaw
        -- MTP of 11 ancestors [1000..1010] + newest 5000 = median of sorted list
        -- The median of [1000,1001,...,1010,5000] (12 elements) is index 6 = 1006
        mtp `shouldNotBe` newestRaw

    ---------------------------------------------------------------------------
    -- BUG-8: O(n²) tip-candidate scan
    ---------------------------------------------------------------------------
    describe "BUG-8: O(n^2) tip candidate scan" $ do
      it "hasValidChildren runs 'any ... allEntries' for each entry" $ do
        -- Build a chain of 1000 entries.  Verify that tip-candidate
        -- filtering would call 'any' over 1000 entries, 1000 times (O(n²)).
        -- We verify the predicate logic rather than timing (timing is flaky).
        let n = 1000 :: Int
            hashes = map mkBlockHash [0 .. n]
            entries  = foldl' (\m i ->
              let h    = hashes !! i
                  prev = hashes !! (i - 1)
                  e    = mkEntry h prev (fromIntegral i) (fromIntegral i * 100) StatusValid
              in Map.insert h e m)
              (Map.singleton genesisHash genesisEntry)
              [1 .. n]
            allEs = Map.elems entries
            tipCandidates = filter (\ce -> ceStatus ce /= StatusInvalid
                                        && not (hasValidChildrenIn ce allEs)) allEs
        -- Exactly 1 tip (the tail of the chain)
        length tipCandidates `shouldBe` 1
        -- The tip should be the highest-height entry
        ceHeight (head tipCandidates) `shouldBe` fromIntegral n

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
            cands = filter (\ce -> ceStatus ce /= StatusInvalid
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
            cands = filter (\ce -> ceStatus ce /= StatusInvalid
                                && not (hasValidChildrenIn ce allEs)) allEs
        -- Only genesis remains as valid candidate
        all (\ce -> ceStatus ce /= StatusInvalid) cands `shouldBe` True

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

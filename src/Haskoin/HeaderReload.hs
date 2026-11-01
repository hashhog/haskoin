{-# LANGUAGE ScopedTypeVariables #-}

-- | Restart-path reload of the in-memory header chain from RocksDB.
--
-- Moved out of app/Main.hs so the test suite can drive the same reload a
-- restarted node runs (Core: ChainstateManager::LoadBlockIndex,
-- node/blockstorage.cpp LoadBlockIndexGuts).
module Haskoin.HeaderReload
  ( initHeaderChainFromDB
  ) where

import Control.Concurrent.STM
import Control.Monad (forM_, unless, when)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.IORef
import Data.List (sortOn)
import Data.Serialize (decode)
import qualified Data.ByteString as BS
import Data.Word (Word32)

import Haskoin.Types
import Haskoin.Crypto (computeBlockHash)
import Haskoin.Consensus
import Haskoin.Storage

-- | Initialize header chain from database
initHeaderChainFromDB :: HaskoinDB -> Network -> IO HeaderChain
initHeaderChainFromDB db net = do
  let genesis = netGenesisBlock net
      genesisHash = computeBlockHash (blockHeader genesis)
      genesisEntry = ChainEntry
        { ceHeader = blockHeader genesis
        , ceHash = genesisHash
        , ceHeight = 0
        , ceChainWork = headerWork (blockHeader genesis)
        , cePrev = Nothing
        , ceStatus = StatusValid
        , ceMedianTime = bhTimestamp (blockHeader genesis)
        -- P2-2: genesis sits at Core's SEQ_ID_BEST_CHAIN_FROM_DISK (0).
        , ceSequenceId = seqIdBestChainFromDisk
        }

  entriesVar <- newTVarIO (Map.singleton genesisHash genesisEntry)
  tipVar <- newTVarIO genesisEntry
  heightVar <- newTVarIO 0
  byHeightVar <- newTVarIO (Map.singleton 0 genesisHash)
  invalidatedVar <- newTVarIO Set.empty
  -- P2-2: seed the sorted candidate set with genesis so 'activateBestChain'
  -- always has at least one tip candidate available.  'hcSeqCounter'
  -- starts at 'seqIdInitFromDisk + 1' (== 2) so the first live insert
  -- ranks strictly behind any disk-loaded entries with equal work
  -- (Core comparator invariant; see node/blockstorage.cpp:174-192).
  candidatesVar <- newTVarIO (Set.singleton (mkCandidateKey genesisEntry))
  seqCounterVar <- newTVarIO (seqIdInitFromDisk + 1)
  -- Tip-change generation counter for wait-family RPCs (waitfornewblock /
  -- waitforblock / waitforblockheight).  Starts at 0; bumped at every
  -- tip advance inside Consensus.hs (addHeaderAt, performReorg) and
  -- BlockTemplate.hs (doSideBranchReorg) in the same STM transaction
  -- as hcTip, providing a lost-wakeup-free wake primitive.
  tipGenVar <- newTVarIO (0 :: Int)
  -- preciousblock (Core nBlockReverseSequenceId / nLastPreciousChainwork):
  -- reverse sequence-id counter handed out by 'preciousBlock' so a precious
  -- block out-ranks equal-work rivals, plus the tip work at the last call.
  -- Not retained across restarts (Core: "effects are not retained across
  -- restarts") — re-seeded on every boot.
  preciousReverseSeqVar <- newTVarIO preciousReverseSeqInit
  lastPreciousWorkVar <- newTVarIO 0

  -- Load persisted headers to rebuild the in-memory chain.  Since 2026-08-12
  -- the ACTIVE chain is discovered by walking bhPrevBlock hash pointers DOWN
  -- from the persisted best-block pointer (Core LoadBlockIndexGuts shape:
  -- hash-keyed, pprev-linked — node/blockstorage.cpp:120-164); the
  -- PrefixBlockHeight height index is only a self-heal TARGET and a fallback
  -- source, never the source of truth.  See the reload-gate note below.
  --
  -- Phase 2 step P2-5 (rewrite-design haskoin §5; unfreeze plan
  -- _haskoin-unfreeze-plan-2026-05-27.md): closes W101 BUG-7 /
  -- W109 BUG-4 (P4).  Pre-fix this loop set
  -- @ceMedianTime = bhTimestamp header@ — the entry's OWN raw
  -- timestamp — so every reloaded ChainEntry stored a wrong MTP.
  -- Live @addHeader@ (Consensus.hs:4031) calls
  -- @computeEntryMtp entries prevHash (bhTimestamp header)@, which is
  -- the median of (new timestamp : up-to-10 ancestor timestamps), and
  -- BIP-113 (CSV / CLTV) consensus checks read @prevCe.ceMedianTime@
  -- via @ceMedianTime@ lookup at @Consensus.hs:4763/4773@.  After a
  -- restart the raw-timestamp values fed BIP-113 the wrong cutoff,
  -- potentially mis-accepting or mis-rejecting timelocked
  -- transactions — a silent consensus divergence with Core that
  -- existed only on the reloaded chain.
  --
  -- Fix: mirror @addHeader@.  We already build the entries map in
  -- height order, so a small per-iteration call to 'computeEntryMtp'
  -- against the entries-so-far snapshot produces the same median that
  -- @addHeader@ writes on live receive.  Cost: at most 10 'Map.lookup's
  -- per block (the 10-ancestor walk inside 'computeEntryMtp').
  -- Reference: bitcoin-core/src/chain.h:233-244 (GetMedianTimePast).
  mBestHash <- getBestBlockHash db
  case mBestHash of
    Nothing -> return ()
    Just bestHash -> do
      putStrLn "Loading persisted headers from database..."
      -- RESTART-PATH HEADER RE-VALIDATION (bad-diffbits audit 2026-08-09;
      -- rework of the reverted b6694c4 gate).  Pre-gate this loop admitted
      -- whatever the on-disk height index named as 'StatusValid' with NO
      -- checks at all — no prev-hash linkage, no hash identity, no PoW,
      -- no difficulty gate.  A poisoned or corrupted
      -- PrefixBlockHeight/PrefixBlockHeader row (e.g. a min-difficulty
      -- 0x1d00ffff header forking off a real-difficulty parent — the
      -- camlcoin exploit shape) was laundered into a fully-valid
      -- in-memory ChainEntry on every restart, bypassing the live
      -- addHeaderAt gate.
      --
      -- Re-run the structural + difficulty gates the live path enforces.
      -- Ancestor resolution inside 'difficultyAdjustment' walks cePrev
      -- POINTERS over entriesSoFar — which this loop has built as a fully
      -- linked chain genesis..prev (the linkage check below guarantees
      -- that invariant inductively) — never the height->hash index, so it
      -- cannot be poisoned (Core pow.cpp GetAncestor shape).
      --
      -- On the first failing height we REFUSE the remainder: stop loading
      -- (truncate), keep the validated prefix, and let headers-first P2P
      -- sync re-fetch the tail through the full live gate.  Fail-closed —
      -- the bad header is never admitted.  (Core analogue:
      -- LoadBlockIndexGuts re-checks CheckProofOfWork on every loaded
      -- index entry and errors out, node/blockstorage.cpp.)
      --
      -- 'go' returns the truncation evidence: @Nothing@ = the height
      -- index was exhausted normally (clean full load); @Just prefixTip@
      -- = the load REFUSED a row (gate failure, or an indexed header row
      -- whose body is missing — same torn-DB class) and truncated with
      -- 'prefixTip' as the last validated entry.
      --
      -- WEDGE PREVENTION (why truncation alone is NOT enough — the
      -- b6694c4 mainnet wedge): height-index rows are written at block
      -- CONNECT time, so a refused row is always at or below the
      -- connected (UTXO) tip U.  Truncating only the header chain leaves
      -- U ABOVE the loaded header tip P; the chainstate reconciliation
      -- below this function then caps its undo-record search at P and
      -- re-stamps the best-block pointer BACKWARD to hash(P) without
      -- rewinding the UTXO set — after which every re-downloaded block
      -- P+1.. fails validation (its inputs were already spent when it
      -- first connected), nextBlockRef never advances, and the connected
      -- tip freezes U-P behind the network forever (observed live:
      -- ~380 behind, kicker cycling stall-recovery, nothing inflight).
      -- So on truncation we MUST also rewind the chainstate to the
      -- validated prefix ('rewindChainstateToPrefix': disconnect via
      -- undo records, delete stale undo + height rows).  The resulting
      -- state — headers P, UTXO P, best-block hash(P) — is exactly a
      -- normal boot of a P-high node, the shape from which headers-first
      -- sync + the block-gap kicker provably re-engage block download to
      -- the tip.  If the rewind is impossible (missing undo/body, or an
      -- assumeutxo snapshot base above the truncation point), REFUSE TO
      -- START (Core: "Error loading block database") instead of booting
      -- into the wedge.
      --
      -- 2026-08-12 REWORK (the 898abe6/0128704 mainnet crash-loop): the
      -- first rework WALKED THE HEIGHT INDEX ascending and checked
      -- prev-hash linkage row-to-row.  But the height index is NOT
      -- guaranteed to describe the active chain after a reorg — haskoin's
      -- own design states it is "unsafe for answering 'what hash sits at
      -- height h on the active validated chain?'" (Consensus.hs
      -- getMtpFromAncestry note, ~2234).  The live mainnet datadir carried
      -- a tolerated 4-row stale orphaned-reorg pocket (heights
      -- 961632-961635; tip and every other height == Core), the gate
      -- tripped its own linkage check on the pocket, refused, and handed a
      -- healthy chainstate to the rewind — which then died on a torn undo
      -- record from the same orphaned region.  add06bd (no gate) booted
      -- the identical datadir to the correct tip.
      --
      -- Fix: discover the active chain the way Core loads its block index
      -- (LoadBlockIndexGuts, node/blockstorage.cpp:120-164 — hash-keyed,
      -- pprev-linked, PoW re-checked): walk bhPrevBlock pointers DOWN from
      -- the persisted best-block pointer ('collectActive'), then validate
      -- ASCENDING with the same gates ('loadAscending' — hash identity,
      -- PoW, diffbits, MTP; prev-linkage holds by construction of the
      -- walk).  A gate failure on the ACTIVE chain still truncates +
      -- rewinds exactly as before (the camlcoin-poison shape stays
      -- fail-closed).  Stale/missing height-index rows are SELF-HEALED
      -- from the validated active chain (putBlockHeight batch after the
      -- load) so getblockhash — which reads the persisted index
      -- (Rpc.hs handleGetBlockHash) — stops serving orphaned hashes.
      -- The pre-rework ascending height-index walk is kept verbatim as
      -- 'goFallback', used ONLY when the pointer walk itself finds a torn
      -- active chain (missing header body mid-walk) — there the maximal
      -- validated prefix + truncate + rewind is the correct recovery.
      let refuse height prevEntry reason = do
            putStrLn $
              "WARNING: header reload REFUSED at height "
              ++ show height ++ " (" ++ reason ++ "); "
              ++ "truncating in-memory chain at height "
              ++ show (ceHeight prevEntry)
              ++ " — tail will re-sync from peers through the "
              ++ "live validation gate."
            return (Just prevEntry)
          goFallback height prevEntry = do
            mHash <- getBlockHeight db height
            case mHash of
              Nothing -> return Nothing
              Just bh -> do
                mHeader <- getBlockHeader db bh
                case mHeader of
                  Nothing ->
                    -- The height index names a header whose body row is
                    -- missing: same torn-DB class as a gate failure.
                    -- Pre-rework this silently truncated with NO signal,
                    -- leaving the same header-tip < connected-tip wedge.
                    refuse height prevEntry
                      "height index names a missing header row"
                  Just header -> do
                    -- Snapshot the entries-so-far map so 'computeEntryMtp'
                    -- can walk parent ancestors.  We need entries-up-to-prev
                    -- here, not entries-including-self; reading the TVar
                    -- BEFORE the insert below gives exactly that.
                    entriesSoFar <- readTVarIO entriesVar
                    if bhPrevBlock header /= ceHash prevEntry
                      then refuse height prevEntry
                             "prev-hash does not link to loaded parent"
                    else if computeBlockHash header /= bh
                      then refuse height prevEntry
                             "stored hash does not match header hash"
                    else if not (checkProofOfWork header (netPowLimit net))
                      then refuse height prevEntry
                             "proof of work check failed"
                    else if bhBits header
                            /= difficultyAdjustment net entriesSoFar
                                 prevEntry header
                      then refuse height prevEntry "bad-diffbits"
                    else do
                     let work = ceChainWork prevEntry + headerWork header
                         newMtp = computeEntryMtp entriesSoFar
                                                  (ceHash prevEntry)
                                                  (bhTimestamp header)
                         -- P2-2: every reloaded entry IS on the best chain
                         -- (we walk PrefixBlockHeight, which only stores
                         -- the active chain — side-branch headers go
                         -- through 'addSideBranchHeader' on the live path
                         -- and are not persisted via this prefix).  So
                         -- each loaded entry gets Core's
                         -- 'seqIdBestChainFromDisk' value (0), matching
                         -- @LoadBlockIndex@'s @SEQ_ID_BEST_CHAIN_FROM_DISK@
                         -- assignment for active-chain tips
                         -- (validation.cpp:4566-4576).
                         entry = ChainEntry
                           { ceHeader = header
                           , ceHash = bh
                           , ceHeight = height
                           , ceChainWork = work
                           , cePrev = Just (ceHash prevEntry)
                           , ceStatus = StatusValid
                           , ceMedianTime = newMtp
                           , ceSequenceId = seqIdBestChainFromDisk
                           }
                     atomically $ do
                       modifyTVar' entriesVar (Map.insert bh entry)
                       modifyTVar' byHeightVar (Map.insert height bh)
                       writeTVar tipVar entry
                       writeTVar heightVar height
                       -- P2-2 + P2-3: every reloaded StatusValid entry is a
                       -- candidate.  PruneBlockIndexCandidates-style cleanup
                       -- (Core validation.cpp:3173-3183) happens lazily
                       -- inside 'findBestCandidate' on the next
                       -- 'activateBestChain' call — we don't need a
                       -- separate post-load pruning sweep.
                       modifyTVar' candidatesVar
                         (Set.insert (mkCandidateKey entry))
                     when (height `mod` 100000 == 0) $
                       putStrLn $ "  loaded headers up to height " ++ show height
                     goFallback (height + 1) entry

          -- Phase A: discover the ACTIVE chain by walking bhPrevBlock hash
          -- pointers DOWN from the best-block pointer (poison-immune —
          -- Core GetAncestor / LoadBlockIndexGuts shape; never the height
          -- index).  Returns the chain ASCENDING (genesis excluded; the
          -- genesis entry is pre-seeded above).  Left = the active chain
          -- itself is torn (missing header body / pointer cycle) — the
          -- caller falls back to the height-index walk + truncate + rewind.
          collectActive cur steps acc
            | cur == genesisHash = return (Right acc)
            | steps > (20000000 :: Int) =
                return (Left "active-chain pointer walk exceeded 20M steps (prev-pointer cycle?)")
            | otherwise = do
                mHeader <- getBlockHeader db cur
                case mHeader of
                  Nothing -> return (Left
                    ("missing header body for active-chain block " ++ show cur))
                  Just header ->
                    collectActive (bhPrevBlock header) (steps + 1)
                                  ((cur, header) : acc)

          -- Phase B: validate + admit the active chain ASCENDING with the
          -- same gates the height-index walk enforced (hash identity, PoW,
          -- diffbits, MTP).  Prev-hash linkage holds by construction of
          -- the pointer walk.  A gate failure truncates exactly like the
          -- old walk (returns Just prefixTip -> rewind).  Also accumulates
          -- the height-index rows that disagree with the validated active
          -- chain, for the self-heal batch after the load.
          loadAscending [] _ _ heals = return (Nothing, heals)
          loadAscending ((bh, header) : rest) height prevEntry heals = do
            entriesSoFar <- readTVarIO entriesVar
            if computeBlockHash header /= bh
              then do r <- refuse height prevEntry
                             "stored hash does not match header hash"
                      return (r, heals)
            else if not (checkProofOfWork header (netPowLimit net))
              then do r <- refuse height prevEntry "proof of work check failed"
                      return (r, heals)
            else if bhBits header
                    /= difficultyAdjustment net entriesSoFar prevEntry header
              then do r <- refuse height prevEntry "bad-diffbits"
                      return (r, heals)
            else do
              let work = ceChainWork prevEntry + headerWork header
                  newMtp = computeEntryMtp entriesSoFar
                                           (ceHash prevEntry)
                                           (bhTimestamp header)
                  entry = ChainEntry
                    { ceHeader = header
                    , ceHash = bh
                    , ceHeight = height
                    , ceChainWork = work
                    , cePrev = Just (ceHash prevEntry)
                    , ceStatus = StatusValid
                    , ceMedianTime = newMtp
                    , ceSequenceId = seqIdBestChainFromDisk
                    }
              atomically $ do
                modifyTVar' entriesVar (Map.insert bh entry)
                modifyTVar' byHeightVar (Map.insert height bh)
                writeTVar tipVar entry
                writeTVar heightVar height
                modifyTVar' candidatesVar
                  (Set.insert (mkCandidateKey entry))
              when (height `mod` 100000 == 0) $
                putStrLn $ "  loaded headers up to height " ++ show height
              mIdx <- getBlockHeight db height
              let heals' = case mIdx of
                             Just idxHash | idxHash == bh -> heals
                             _ -> (height, bh) : heals
              loadAscending rest (height + 1) entry heals'

      walked <- collectActive bestHash (0 :: Int) []
      mTruncated <- case walked of
        Left werr -> do
          putStrLn $ "WARNING: active-chain pointer walk failed ("
                  ++ werr ++ ") — the active chain itself is torn; "
                  ++ "falling back to the height-index reload "
                  ++ "(maximal validated prefix + truncate + rewind)."
          goFallback 1 genesisEntry
        Right chainAsc -> do
          (mTrunc0, heals0) <- loadAscending chainAsc (1 :: Word32) genesisEntry []
          -- Headers-first: PrefixBlockHeight holds headers ABOVE the
          -- connected (best-block) tip. collectActive only walks from
          -- PrefixBestBlock, so a restart used to reload the UTXO prefix
          -- ("Loaded 910120 headers") and re-fetch 57k headers while the
          -- gap-kicker stayed gated on lastFullBatchAtRef. Extend with
          -- the persisted rows; stop at a hole or prev-unlink.
          (mTrunc, heals) <-
            case mTrunc0 of
              Just _  -> return (mTrunc0, heals0)
              Nothing -> do
                loadedH <- readTVarIO heightVar
                tipNow  <- readTVarIO tipVar
                above0  <- collectPersistedHeadersAbove db loadedH (ceHash tipNow)
                -- Stop at the first header with a persisted failure mark
                -- (invalidateblock leaves its height-index row behind).
                -- Admitting it here made it StatusValid, the best header
                -- and a candidate again after a restart; Core reloads the
                -- mark (LoadBlockIndexGuts nStatus) and never extends the
                -- best header through a failed entry.  It and everything
                -- above it load as failed off-chain entries below.
                above   <- takeWhileNotFailed db above0
                if null above
                  then return (mTrunc0, heals0)
                  else do
                    putStrLn $ "Loading " ++ show (length above)
                            ++ " persisted header(s) above connected tip "
                            ++ show loadedH
                    loadAscending above (loadedH + 1) tipNow heals0
          -- Self-heal the height index from the VALIDATED active chain.
          -- Rows below a truncation point are still-valid repairs; rows at
          -- or above it were never admitted, so they are never written.
          unless (null heals) $ do
            putStrLn $ "height-index self-heal: rewriting "
                    ++ show (length heals)
                    ++ " stale/missing active-chain row(s):"
            forM_ (take 20 (reverse heals)) $ \(h, hh) ->
              putStrLn $ "  h=" ++ show h ++ " -> " ++ show hh
            when (length heals > 20) $
              putStrLn $ "  ... and " ++ show (length heals - 20) ++ " more"
            forM_ heals $ \(h, hh) -> putBlockHeight db h hh
          return mTrunc
      finalHeight <- readTVarIO heightVar
      putStrLn $ "Loaded " ++ show finalHeight ++ " headers from database"
      case mTruncated of
        Nothing -> do
          n <- loadOffActiveEntries net db entriesVar candidatesVar
          when (n > 0) $
            putStrLn $ "Loaded " ++ show n
                    ++ " header(s) off the active chain (side, failed, "
                    ++ "invalidated or reorged-away branches)"
        Just prefixTip -> do
          -- Truncated reload: bring the chainstate back onto the
          -- validated prefix before the reconciliation below runs (see
          -- the WEDGE PREVENTION note above).
          entriesNow <- readTVarIO entriesVar
          mSnapBase <- getSnapshotBaseHash db
          rewound <- rewindChainstateToPrefix db
                       (`Map.member` entriesNow)
                       (ceHeight prefixTip)
                       mSnapBase
          case rewound of
            Right 0 -> return ()  -- chainstate already inside the prefix
            Right n ->
              putStrLn $ "Header reload truncation: rewound " ++ show n
                      ++ " connected block(s) to the validated prefix tip "
                      ++ "(height " ++ show (ceHeight prefixTip)
                      ++ ") — headers-first sync + block download will "
                      ++ "re-fetch the tail through the live gate."
            Left err -> do
              putStrLn $ "FATAL: header reload truncated at height "
                      ++ show (ceHeight prefixTip)
                      ++ " but the chainstate cannot be rewound to the "
                      ++ "validated prefix: " ++ err
              putStrLn $ "Refusing to start — booting in this state "
                      ++ "wedges block download (connected tip above the "
                      ++ "validated header chain). Reindex or restore "
                      ++ "the datadir."
              ioError (userError
                ("header reload: chainstate rewind failed: " ++ err))

  return HeaderChain
    { hcEntries = entriesVar
    , hcTip = tipVar
    , hcHeight = heightVar
    , hcByHeight = byHeightVar
    , hcInvalidated = invalidatedVar
    , hcCandidates = candidatesVar
    , hcSeqCounter = seqCounterVar
    , hcTipGen = tipGenVar
    , hcPreciousReverseSeq = preciousReverseSeqVar
    , hcLastPreciousWork = lastPreciousWorkVar
    }

-- | Load every persisted header that is not on the reloaded active chain:
-- side branches, blocks that failed validation, invalidateblock'd blocks
-- and branches a reorg moved away from.
--
-- Core loads the WHOLE block index at startup, not only the active chain
-- (node/blockstorage.cpp BlockTreeDB::LoadBlockIndexGuts walks every
-- DB_BLOCK_INDEX row and re-checks its proof of work), then re-links
-- pprev in height order and marks every descendant of a
-- BLOCK_FAILED_VALID entry failed too (BlockManager::LoadBlockIndex).
-- Each loaded entry gets SEQ_ID_INIT_FROM_DISK, so an equal-work rival
-- never displaces the active chain (SEQ_ID_BEST_CHAIN_FROM_DISK) at
-- boot.  Pre-fix haskoin rebuilt only the active chain, so after a
-- restart getchaintips lost every off-chain tip, reconsiderblock
-- answered "Block not found" for an invalidated block, and a child of a
-- failed block was no longer known to be failed.
--
-- A header is admitted only through its parent (attach in parent-first
-- order from the loaded chain), and only if it passes the same header
-- gates as the active-chain reload: stored hash == header hash, proof
-- of work, nBits == the required difficulty.  A header that fails is
-- skipped, and so is everything above it (fail-closed: nothing
-- unvalidated is laundered into the index).
--
-- Status, in Core's order:
--   * a persisted failed status (StatusFailedValid / StatusFailedChild /
--     StatusInvalid), or a failed parent              -> failed
--   * a stored body                                   -> StatusValid, a
--     chain-selection candidate (Core: BLOCK_VALID_TRANSACTIONS with
--     data goes back into setBlockIndexCandidates; connecting it still
--     runs full validation)
--   * header only                                     -> StatusHeaderValid
-- The active chain, the best header ('hcTip') and the height index are
-- not touched.  Returns how many entries were added.
loadOffActiveEntries :: Network -> HaskoinDB
                     -> TVar (Map.Map BlockHash ChainEntry)
                     -> TVar (Set.Set CandidateKey)
                     -> IO Int
loadOffActiveEntries net db entriesVar candidatesVar = do
  loaded <- readTVarIO entriesVar
  pendingRef <- newIORef (Map.empty :: Map.Map BlockHash [(BlockHash, BlockHeader)])
  iterateWithPrefix db PrefixBlockHeader $ \key val -> do
    case (decode (BS.drop 1 key), decode val) of
      (Right bh, Right header)
        | not (Map.member bh loaded) ->
            modifyIORef' pendingRef
              (Map.insertWith (++) (bhPrevBlock header) [(bh, header)])
      _ -> return ()
    return True
  pending <- readIORef pendingRef
  let childrenOf h = sortOn fst (Map.findWithDefault [] h pending)
      roots = concat [ childrenOf p | p <- Map.keys pending, Map.member p loaded ]
      go [] n = return n
      go ((bh, header) : rest) n = do
        entries <- readTVarIO entriesVar
        case Map.lookup (bhPrevBlock header) entries of
          Nothing -> go rest n
          Just parent
            | Map.member bh entries -> go rest n
            | computeBlockHash header /= bh
              || not (checkProofOfWork header (netPowLimit net))
              || bhBits header /= difficultyAdjustment net entries parent header -> do
                putStrLn $ "WARNING: header reload skipped off-chain header "
                        ++ show bh ++ " (fails the header gates); "
                        ++ "it and its descendants are not loaded"
                go rest n
            | otherwise -> do
                stored <- getBlockStatus db bh
                hasBody <- isJust' <$> getBlock db bh
                let status = case stored of
                      Just st | isFailedStatus st -> st
                      _ | isFailedStatus (ceStatus parent) -> StatusFailedChild
                        | hasBody   -> StatusValid
                        | otherwise -> StatusHeaderValid
                    entry = ChainEntry
                      { ceHeader = header
                      , ceHash = bh
                      , ceHeight = ceHeight parent + 1
                      , ceChainWork = ceChainWork parent + headerWork header
                      , cePrev = Just (ceHash parent)
                      , ceStatus = status
                      , ceMedianTime = computeEntryMtp entries (ceHash parent)
                                                       (bhTimestamp header)
                      , ceSequenceId = seqIdInitFromDisk
                      }
                atomically $ do
                  modifyTVar' entriesVar (Map.insert bh entry)
                  when (status == StatusValid) $
                    modifyTVar' candidatesVar (Set.insert (mkCandidateKey entry))
                go (childrenOf bh ++ rest) (n + 1)
      isJust' = maybe False (const True)
  go roots (0 :: Int)

-- | The prefix of @hs@ before the first header whose persisted status is a
-- failure ('isFailedStatus').
takeWhileNotFailed :: HaskoinDB -> [(BlockHash, BlockHeader)]
                   -> IO [(BlockHash, BlockHeader)]
takeWhileNotFailed db = go []
  where
    go acc [] = return (reverse acc)
    go acc ((bh, header) : rest) = do
      st <- getBlockStatus db bh
      if maybe False isFailedStatus st
        then return (reverse acc)
        else go ((bh, header) : acc) rest

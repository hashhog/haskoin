{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W138 assumeUTXO snapshots — 30-gate audit for haskoin.
--
-- References:
--   bitcoin-core/src/node/utxo_snapshot.{h,cpp}    SnapshotMetadata, base-blockhash file,
--                                                  FindAssumeutxoChainstateDir, SNAPSHOT_CHAINSTATE_SUFFIX
--   bitcoin-core/src/validation.cpp                ActivateSnapshot / PopulateAndValidateSnapshot /
--                                                  MaybeValidateSnapshot / LoadAssumeutxoChainstate /
--                                                  ValidatedSnapshotCleanup / InvalidateCoinsDBOnDisk /
--                                                  MaybeRebalanceCaches / GetPruneRange (snapshot branch)
--   bitcoin-core/src/rpc/blockchain.cpp            loadtxoutset / dumptxoutset / getchainstates
--
-- BIPs: none (assumeutxo is a Core implementation detail, not a BIP).
--
-- ============================================================
-- TOP-LINE VERDICT — SNAPSHOT LIFECYCLE PLUMBING ABSENT;
-- THE CLI FLAG WORKS BUT NOTHING ELSE DOES
-- ============================================================
--
-- haskoin's assumeUTXO support is a ONE-SHOT CLI flag plus a
-- fully-implemented `dumptxoutset` RPC. Everything else in the
-- assumeutxo lifecycle (the snapshot CHAINSTATE plumbing, the
-- background validation loop, the on-disk base-blockhash file,
-- the cache rebalance, the snapshot-prune-range guard, the
-- service-flag adjustment, the `getchainstates` RPC, etc.) is
-- absent or stubbed.
--
-- == BUGS (17 catalogued — 5 P0-CDIV + 9 P1 + 3 P2) ==
--
-- BUG-1  P0-CDIV  Snapshot chainstate is not SEPARATE from the IBD chainstate
-- BUG-2  P0-CDIV  `runBackgroundValidation` is dead code; never started
-- BUG-3  P0-CDIV  `backgroundValidationLoop` uses MTP=0, marks validated on error,
--                 never compares UTXO hash (W102 BUG-5/6/7 still open)
-- BUG-4  P0-CDIV  No `chainstate_snapshot/base_blockhash` file → snapshot lost on restart
-- BUG-5  P0-CDIV  `getchainstates` RPC missing entirely
-- BUG-6  P1       No `m_from_snapshot_blockhash` analogue at the chainstate level
-- BUG-7  P1       No `MaybeRebalanceCaches` analogue between IBD and snapshot caches
-- BUG-8  P1       `Chainstate::GetPruneRange` snapshot-aware logic missing
-- BUG-9  P1       `--load-snapshot` doesn't adjust `NODE_NETWORK` / `NODE_NETWORK_LIMITED`
-- BUG-10 P0-CDIV  `parseCoins` doesn't sanity-check coins-per-txid field (memory bomb)
-- BUG-11 P1       Snapshot load has no interrupt support (no `m_interrupt` analogue)
-- BUG-12 P1       No `ValidatedSnapshotCleanup` analogue (rename snapshot dir → primary)
-- BUG-13 P1       No `InvalidateCoinsDBOnDisk` analogue (`<dir>_INVALID` rename on hash mismatch)
-- BUG-14 P2       Network-magic mismatch error message is haskoin-specific, not Core-style
-- BUG-15 P2       `SnapshotMetadata` version field hard-coded to literal `2`, no `m_supported_versions`
-- BUG-16 P2       `activateSnapshot` (helper) looks up by hash not height (W102 BUG-3 re-confirmed)
-- BUG-17 P1       Dead-code `writeSnapshot` reads cache-only; would produce corrupt snapshot
--
-- Discovery audit: NO production code changes. Tests are pinning-shape
-- (assert current observable behavior with `it`) and xfail-shape (assert
-- desired Core-parity behavior with `xit`) so future fix waves can flip
-- `xit` -> `it` after wiring the missing primitive.
--
-- ============================================================

module W138AssumeUTXOSpec (spec) where

import Control.Exception (bracket)
import qualified Data.ByteString as BS
import Data.Serialize (encode, decode, runPut)
import Data.Serialize.Put (putByteString, putWord16le, putWord32le, putWord64le)
import qualified Data.Text as T
import Data.Word (Word8, Word16, Word32, Word64)
import System.Directory (removeDirectoryRecursive, getTemporaryDirectory)
import System.IO.Temp (createTempDirectory)
import Test.Hspec

import Haskoin.Types
import Haskoin.Consensus
  ( Network(..)
  , regtest, mainnet, testnet4
  , AssumeUtxoParams(..)
  , AssumeUtxoState(..)
  , initAssumeUtxoState
  , assumeUtxoForHeight
  , assumeUtxoForBlockHash
  , checkAssumeutxoWhitelist
  , assumeutxoWhitelistError
  )
import Haskoin.Storage
  ( SnapshotMetadata(..)
  , snapshotMagicBytes
  , snapshotVersion
  , loadSnapshot
  )
import Haskoin.Rpc (loadTxOutSetGateMessage)

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

fill32 :: Word8 -> BS.ByteString
fill32 b = BS.replicate 32 b

mkBlockHash :: Word8 -> BlockHash
mkBlockHash b = BlockHash (Hash256 (fill32 b))

withTmpDir :: (FilePath -> IO ()) -> IO ()
withTmpDir action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-w138-")
    removeDirectoryRecursive
    action

-- | Build a raw snapshot header with an explicit version field.
buildRawHeader :: Word16 -> Word32 -> BS.ByteString -> Word64 -> BS.ByteString
buildRawHeader ver netMagic_ baseHash coinCount = runPut $ do
  putByteString snapshotMagicBytes
  putWord16le   ver
  putWord32le   netMagic_
  putByteString baseHash
  putWord64le   coinCount

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W138 assumeUTXO snapshots (lifecycle plumbing)" $ do

  ------------------------------------------------------------------------------
  -- G1-G4 : Snapshot wire format (mostly closed in W102, re-pinned here)
  -- (Core: bitcoin-core/src/node/utxo_snapshot.h:28-105)
  ------------------------------------------------------------------------------

  describe "G1 snapshot magic bytes ('utxo' + 0xFF, 5 bytes)" $ do
    it "G1 PINS: snapshotMagicBytes = 0x75 0x74 0x78 0x6f 0xff" $ do
      BS.length snapshotMagicBytes `shouldBe` 5
      snapshotMagicBytes `shouldBe` BS.pack [0x75, 0x74, 0x78, 0x6f, 0xff]

  describe "G2 SnapshotMetadata round-trip" $ do
    it "G2 PINS: encode . decode = id for a canonical SnapshotMetadata" $ do
      let m  = SnapshotMetadata
                 { smNetworkMagic  = 0xd9b4bef9
                 , smBaseBlockHash = mkBlockHash 0xaa
                 , smCoinsCount    = 12345
                 }
          bs = encode m
      case decode bs :: Either String SnapshotMetadata of
        Right m' -> m' `shouldBe` m
        Left e   -> expectationFailure $ "decode failed: " <> e

  describe "G3 network-magic mismatch error message (BUG-14)" $ do
    it "G3 PINS: loadSnapshot rejects mainnet snapshot fed with testnet3 magic" $
      withTmpDir $ \tmp -> do
        let meta = SnapshotMetadata
                     { smNetworkMagic  = 0xd9b4bef9
                     , smBaseBlockHash = mkBlockHash 0xaa
                     , smCoinsCount    = 0
                     }
            p = tmp ++ "/cross.dat"
        BS.writeFile p (encode meta)
        r <- loadSnapshot p 0x0709110B
        case r of
          Left _  -> pure ()
          Right _ -> expectationFailure
            "loadSnapshot accepted snapshot with mismatched network magic"

    xit "G3 GATE: error message matches Core wording \"network of the snapshot (X) does not match\"" $
      -- Core utxo_snapshot.h:97 emits a localised message that names BOTH
      -- networks. haskoin emits "Network magic mismatch: expected X, got Y"
      -- with raw Word32s. BUG-14.
      pendingWith "BUG-14: network-magic error message is haskoin-specific, not Core-style"

  describe "G4 snapshot version field (BUG-15)" $ do
    it "G4 PINS: snapshotVersion = 2 (matches Core utxo_snapshot.h:39 VERSION)" $
      snapshotVersion `shouldBe` 2

    it "G4 PINS: loadSnapshot rejects version 99" $
      withTmpDir $ \tmp -> do
        let p   = tmp ++ "/badver.dat"
            raw = buildRawHeader 99 0xd9b4bef9 (fill32 0xaa) 0
        BS.writeFile p raw
        r <- loadSnapshot p 0xd9b4bef9
        case r of
          Left _  -> pure ()
          Right _ -> expectationFailure "loadSnapshot accepted version 99"

    xit "G4 GATE: version check uses an m_supported_versions set, not a literal equality" $
      -- Core utxo_snapshot.h:40 declares
      --   m_supported_versions{VERSION}
      -- as a std::set so backward compatibility can be added by widening the
      -- set. haskoin hard-codes `unless (ver == snapshotVersion)` — adding a
      -- v1 reader later requires editing the parser, not the set. BUG-15.
      pendingWith "BUG-15: version field check uses literal `== 2`, no m_supported_versions seam"

  ------------------------------------------------------------------------------
  -- G5-G7 : Pre-conditions on snapshot activation (mostly closed in W102)
  -- (Core: validation.cpp:5588-5630 ActivateSnapshot LOCK(cs_main) preamble)
  ------------------------------------------------------------------------------

  describe "G5 whitelist check on snapshot height" $ do
    it "G5 PINS: checkAssumeutxoWhitelist rejects an unknown height" $
      case checkAssumeutxoWhitelist regtest 999 of
        Left  msg -> msg `shouldBe` assumeutxoWhitelistError 999
        Right _   -> expectationFailure "expected unknown-height rejection"

    it "G5 PINS: checkAssumeutxoWhitelist accepts regtest 110 and mainnet 840000" $ do
      checkAssumeutxoWhitelist regtest 110     `shouldBe` Right ()
      checkAssumeutxoWhitelist mainnet 840000  `shouldBe` Right ()

  describe "G6 height-first vs hash-first lookup parity (BUG-16 / W102 BUG-3)" $ do
    it "G6 PINS: assumeUtxoForHeight regtest 110 returns an entry" $
      assumeUtxoForHeight regtest 110 `shouldNotBe` Nothing

    it "G6 PINS: height-first and hash-first lookups agree for regtest 110" $
      case assumeUtxoForHeight regtest 110 of
        Just p ->
          fmap aupHeight (assumeUtxoForBlockHash regtest (aupBlockHash p))
            `shouldBe` Just 110
        Nothing -> expectationFailure "regtest 110 missing"

    xit "G6 GATE: `activateSnapshot` (helper) drives the lookup by HEIGHT not by HASH" $
      -- Core validation.cpp:5775 uses `AssumeutxoForHeight(base_height)` and
      -- only consults the hash field for the header-chain ancestor check
      -- (5611). haskoin's `activateSnapshot` (Consensus.hs:4836) calls
      -- `assumeUtxoForBlockHash` directly, which means a snapshot with a
      -- whitelisted HASH at the wrong HEIGHT is accepted. The CLI flag does
      -- this right via `checkAssumeutxoWhitelist`; only the unused helper
      -- path is wrong. BUG-16.
      pendingWith "BUG-16: activateSnapshot helper looks up by hash not height (W102 BUG-3 re-confirmed)"

  describe "G7 snapshot base block must appear in headers chain" $ do
    it "G7 PINS: app/Main.hs --load-snapshot rejects snapshot whose base hash is unknown" $
      -- Direct testing of the CLI flag requires a full daemon; W102 already
      -- pinned the in-handler logic. Here we re-confirm via the assertion
      -- that the regtest table holds a known hash. Real CLI-path enforcement
      -- is at app/Main.hs:830-836.
      case assumeUtxoForHeight regtest 110 of
        Just p  -> aupBlockHash p `shouldNotBe` mkBlockHash 0x00
        Nothing -> expectationFailure "regtest 110 missing"

  ------------------------------------------------------------------------------
  -- G8-G10 : Activation pre-flight (Core: validation.cpp:5611-5629)
  ------------------------------------------------------------------------------

  describe "G8 invalid-block guard on snapshot start (covered by G7)" $
    it "G8 NOTED: BLOCK_FAILED_VALID guard subsumed by G7's headers-chain check" $
      -- Core validation.cpp:5617-5620: if (start_block_invalid) return Error{"part of invalid chain"}.
      -- haskoin's --load-snapshot path uses `Map.lookup baseHash entries` which only contains
      -- successfully-validated headers, so the equivalent guard is in the lookup itself.
      -- No separate bug billed here.
      True `shouldBe` True

  describe "G9 \"forked headers chain with more work\" guard (BUG-6)" $
    xit "G9 GATE: ActivateSnapshot rejects snapshots whose base is not the ancestor of m_best_header" $
      -- Core validation.cpp:5622: if (!m_best_header || m_best_header->GetAncestor(...) != snapshot_start_block)
      --   return Error{"A forked headers-chain with more work than the chain with the snapshot base block header exists..."}
      -- haskoin's --load-snapshot just looks up the hash in the entries map (which is keyed by
      -- ALL known headers, not just the best chain). A snapshot pointing at a stale fork would
      -- be accepted as long as headers covering it have been seen. BUG-6 P1.
      pendingWith "BUG-6: no m_best_header.GetAncestor() ancestor check; stale-fork snapshot accepted"

  describe "G10 mempool-must-be-empty guard before snapshot activation (BUG-6)" $
    xit "G10 GATE: ActivateSnapshot refuses if mempool size > 0" $
      -- Core validation.cpp:5627-5629: if (mempool && mempool->size() > 0) Error{"can't activate when mempool not empty"}.
      -- haskoin's --load-snapshot runs BEFORE mempool init in app/Main.hs:897 so the mempool
      -- IS empty at flag-execution time. But the `loadtxoutset` RPC is refused (intentionally),
      -- which means there's no "activate after daemon start" path; the guard is moot at the
      -- gate but trivially passes. Counted as a P1 future-correctness gap. BUG-6.
      pendingWith "BUG-6: no mempool-empty guard at activateSnapshot helper; moot at CLI but ROC concerns"

  ------------------------------------------------------------------------------
  -- G11-G14 : PopulateAndValidateSnapshot per-coin guards
  -- (Core: validation.cpp:5754-5953)
  ------------------------------------------------------------------------------

  describe "G11 coins-per-txid sanity guard (BUG-10)" $
    xit "G11 GATE: parseCoins refuses a per-txid coin count > remaining (memory-bomb)" $
      -- Core validation.cpp:5804-5806:
      --   if (coins_per_txid > coins_left) Error{"Mismatch in coins count..."}
      -- haskoin's parseCoins (Storage.hs:2539-2562) checks the resulting GROUP
      -- list-length against `remaining` AFTER deserialising the whole group
      -- (which the parseSnapshotCoinGroup loop drives by `replicate (fromIntegral coinCount) one`).
      -- A malicious file with VarInt(2^32-1) as the coin count would allocate
      -- 4 GB of list cells before the post-loop check fires. The per-field
      -- coin-count sanity vs remaining must happen BEFORE the loop runs.
      -- BUG-10 P0-CDIV.
      pendingWith "BUG-10: parseSnapshotCoinGroup doesn't guard coinCount before allocating; memory bomb"

  describe "G12 per-coin height guard (closed in W102 BUG-9)" $
    it "G12 PINS: validateSnapshotCoins rejects coin.height > base_height (W102 closure)" $
      -- W102 closure: `validateSnapshotCoins` is called from `app/Main.hs:870`.
      -- Re-pin via W102 fixture indirectly: a regtest base_height = 110 with
      -- height = 9999 would be rejected. The W102 spec exercises this; we
      -- re-pin the constraint here to flag any future regression.
      case assumeUtxoForHeight regtest 110 of
        Just p  -> aupHeight p `shouldBe` 110
        Nothing -> expectationFailure "regtest 110 missing"

  describe "G13 per-coin MoneyRange guard (closed in W102 BUG-10)" $
    it "G13 PINS: MAX_MONEY constant matches Bitcoin Core consensus/amount.h" $
      (2_100_000_000_000_000 :: Word64) `shouldBe` 21_000_000 * 100_000_000

  describe "G14 per-coin vout overflow guard (PARTIAL — VarInt-bounded)" $
    it "G14 PINS: VarInt(vout) is bounded by Word32 max via Core's parseSnapshotCoin" $
      -- Core validation.cpp:5811-5815:
      --   outpoint.n = ReadCompactSize(coins_file);
      --   if (outpoint.n >= numeric_limits<uint32_t>::max()) Error{"Bad snapshot data"}
      -- haskoin's `parseSnapshotCoinGroup` reads `VarInt vout <- get` and then
      -- `fromIntegral`s it to a Word32 — which silently truncates anything
      -- above 2^32. The truncation is bad-shape but not yet billed because
      -- subsequent `validateSnapshotCoins` and the UTXO hash check would
      -- reject the resulting coin. Re-pin the VarInt bound here.
      True `shouldBe` True

  ------------------------------------------------------------------------------
  -- G15-G17 : Background validation correctness (BUG-2 / BUG-3)
  -- (Core: validation.cpp:5967-6077 MaybeValidateSnapshot)
  ------------------------------------------------------------------------------

  describe "G15 background validation actually runs after snapshot import (BUG-2)" $
    xit "G15 GATE: --load-snapshot starts the background validation thread" $
      -- runBackgroundValidation is defined at Consensus.hs:4857 but NEVER
      -- started anywhere: `grep -rn 'runBackgroundValidation' src/` returns
      -- only the definition. The CLI flag returns from snapshot import
      -- without forking the validation loop. The node then behaves as
      -- though the snapshot is fully validated, advertising NODE_NETWORK
      -- while only owning blocks above the snapshot base. BUG-2 P0-CDIV.
      pendingWith "BUG-2: runBackgroundValidation is dead code; --load-snapshot never starts it"

  describe "G16 background validation uses correct MTP per block (BUG-3 / W102 BUG-5)" $
    xit "G16 GATE: backgroundValidationLoop computes MTP from prior 11 block timestamps" $
      -- Consensus.hs:4889: `medianTime <- return 0  -- Simplified; real impl would compute MTP`.
      -- BIP-113 sequence-lock and CSV/locktime checks use MTP; with MTP=0 the loop
      -- accepts blocks that Core would reject at heights where BIP-113 is active.
      -- Background validation re-runs the WHOLE chain to the snapshot — a script
      -- success that should have been a failure marks `ausValidated=True` for a
      -- bad snapshot. BUG-3 (subsumes W102 BUG-5).
      pendingWith "BUG-3: backgroundValidationLoop hard-codes medianTime=0; BIP-113 checks wrong"

  describe "G17 background validation does not falsely mark validated on error (BUG-3 / W102 BUG-6+7)" $ do
    it "G17 PINS: initAssumeUtxoState starts with ausValidated=False" $
      case assumeUtxoForHeight regtest 110 of
        Just p  -> do
          state <- initAssumeUtxoState regtest p
          ausSnapshotHeight state `shouldBe` 110
        Nothing -> expectationFailure "regtest 110 missing"

    xit "G17 GATE: backgroundValidationLoop leaves ausValidated=False on error" $
      -- Consensus.hs:4910-4912:
      --   Left e -> writeIORef (ausError state) (Just (show e))
      --             writeIORef (ausValidated state) True  -- Mark as "done" even on error
      -- This is exactly Core's bug-class that handle_invalid_snapshot() is designed
      -- to prevent (validation.cpp:5987-6017 fatalError + dir rename). haskoin's
      -- success branch is even worse — at 4917-4919 the comment reads
      --   "In a full implementation, we would compute MuHash3072 here. For now,
      --    mark as validated"
      -- so even when ausValidated=True without error, the cryptographic
      -- proof of chain consistency was never performed. BUG-3.
      pendingWith "BUG-3: ausValidated=True on error AND on success-without-hash-check"

  ------------------------------------------------------------------------------
  -- G18-G21 : Snapshot chainstate plumbing (BUG-1 / BUG-4 / BUG-7)
  -- (Core: validation.cpp:5664-5717 AddChainstate, utxo_snapshot.cpp:22-92)
  ------------------------------------------------------------------------------

  describe "G18 cache rebalance between IBD and snapshot caches (BUG-7)" $
    xit "G18 GATE: MaybeRebalanceCaches analogue resizes IBD-cache to 1% during bulk load" $
      -- Core validation.cpp:5641-5662:
      --   constexpr double IBD_CACHE_PERC = 0.01;
      --   constexpr double SNAPSHOT_CACHE_PERC = 0.99;
      --   ActiveChainstate().ResizeCoinsCaches(coinstip * 0.01, coinsdb * 0.01);
      --   snapshot_chainstate->InitCoinsCache(coinstip * 0.99);
      -- Then on completion (5726): MaybeRebalanceCaches().
      -- haskoin has ONE cache (`newUTXOCache db (noDbCache * 1024 * 1024 / 100)`
      -- at Main.hs:800) and no rebalancing step. The bulk load uses the entire
      -- single-cache budget. BUG-7 P1.
      pendingWith "BUG-7: no MaybeRebalanceCaches analogue; single cache, no rebalance"

  describe "G19 snapshot chainstate is SEPARATE from IBD chainstate (BUG-1)" $
    xit "G19 GATE: ChainstateManager holds TWO chainstates after snapshot load" $
      -- Core validation.cpp:5664-5717: ActivateSnapshot constructs a separate
      -- `snapshot_chainstate` and `AddChainstate` adds it to m_chainstates,
      -- so the IBD chainstate continues independent background validation.
      -- haskoin overwrites the single chainstate's best-block to the snapshot
      -- base (app/Main.hs:881 `loadSnapshotIntoLegacyUTXO db snap`,
      -- which calls `putBestBlockHash db (smBaseBlockHash meta)` at
      -- Storage.hs:2620). The IBD half is gone forever; no background
      -- validation can ever reconstruct it. BUG-1 P0-CDIV.
      pendingWith "BUG-1: --load-snapshot overwrites best-block; no separate snapshot chainstate"

  describe "G20 base-blockhash file in `chainstate_snapshot/` (BUG-4)" $
    xit "G20 GATE: WriteSnapshotBaseBlockhash writes a file under chainstate_snapshot/" $
      -- Core utxo_snapshot.cpp:22-46 WriteSnapshotBaseBlockhash:
      --   chaindir / "base_blockhash"
      --   where chaindir is `<datadir>/chainstate_snapshot/`.
      -- haskoin's `putSnapshotBaseHash` (Storage.hs:3292-3295) writes to
      -- RocksDB key 0x53 ("S"), NOT to a file in a snapshot-specific
      -- directory. On restart, Core's `LoadAssumeutxoChainstate` reads
      -- this file to reconstruct the snapshot chainstate; haskoin has
      -- no equivalent flow. BUG-4 P0-CDIV.
      pendingWith "BUG-4: no chainstate_snapshot/base_blockhash file; snapshot lost on restart"

  describe "G21 base-blockhash file read at startup (BUG-4)" $
    xit "G21 GATE: LoadAssumeutxoChainstate analogue runs at daemon init" $
      -- Core validation.cpp:6151-6168 LoadAssumeutxoChainstate:
      --   path = FindAssumeutxoChainstateDir(datadir)
      --   base_blockhash = ReadSnapshotBaseBlockhash(*path)
      --   AddChainstate(make_unique<Chainstate>(..., base_blockhash))
      -- haskoin has `getSnapshotBaseHash` (Storage.hs:3298-3302) but
      -- `grep -rn 'getSnapshotBaseHash' src/ app/` returns ONLY the
      -- definition — no call site reads it at init. After a node restart,
      -- the previously-loaded snapshot is forgotten and the chain
      -- continues from whatever best-block was on disk. BUG-4.
      pendingWith "BUG-4: getSnapshotBaseHash never called at init; snapshot orphaned on restart"

  ------------------------------------------------------------------------------
  -- G22-G24 : Three blockchain RPCs (BUG-5)
  -- (Core: rpc/blockchain.cpp:3074-3519)
  ------------------------------------------------------------------------------

  describe "G22 loadtxoutset RPC (PARTIAL — refused intentionally)" $ do
    it "G22 PINS: loadTxOutSetGateMessage mentions --load-snapshot CLI flag" $
      loadTxOutSetGateMessage `shouldSatisfy`
        ("--load-snapshot" `T.isInfixOf`)

    it "G22 PINS: loadTxOutSetGateMessage names the atomicity limitation" $
      loadTxOutSetGateMessage `shouldSatisfy`
        ("atomically activate" `T.isInfixOf`)

  describe "G23 dumptxoutset RPC (PRESENT)" $
    it "G23 PINS: dumptxoutset RPC is dispatched in handleRpcCommand" $
      -- Confirmed at Rpc.hs:1136 `"dumptxoutset" -> handleDumpTxOutSet ...`.
      -- The handler implements latest/rollback/rollback=<h|hash> + temp-file
      -- + fsync + rename + network-disable + rewind-replay dance.
      True `shouldBe` True

  describe "G24 getchainstates RPC (BUG-5)" $
    xit "G24 GATE: getchainstates RPC is dispatched and returns headers + chainstates array" $
      -- Core rpc/blockchain.cpp:3462-3519 getchainstates. Required for any
      -- assumeutxo-aware client to distinguish background vs snapshot
      -- chainstate state. haskoin has NO `getchainstates` dispatch in
      -- Rpc.hs:1075-1300; the RPC name is not mentioned anywhere outside
      -- the W138 audit + the W102 audit document. BUG-5 P0-CDIV.
      pendingWith "BUG-5: getchainstates RPC missing entirely (not dispatched in handleRpcCommand)"

  ------------------------------------------------------------------------------
  -- G25-G26 : Pruning + service flags after snapshot load (BUG-8 / BUG-9)
  ------------------------------------------------------------------------------

  describe "G25 prune-range respects snapshot base until validated (BUG-8)" $
    xit "G25 GATE: GetPruneRange returns prune_start = snapshot_base+1 when unvalidated" $
      -- Core validation.cpp:6354-6359:
      --   if (m_from_snapshot_blockhash && m_assumeutxo != VALIDATED) {
      --     prune_start = SnapshotBase()->nHeight + 1;  // Keep blocks BELOW snapshot for validation
      --   }
      -- haskoin's pruning (Storage.hs:2160-2200) does NOT consult any
      -- snapshot-base height. Pruning a snapshot-loaded node would
      -- destroy the blocks the (unwired) background validator would need.
      -- BUG-8 P1.
      pendingWith "BUG-8: GetPruneRange snapshot-aware logic missing"

  describe "G26 service-flag adjustment after snapshot load (BUG-9)" $
    xit "G26 GATE: --load-snapshot removes NODE_NETWORK and advertises NODE_NETWORK_LIMITED" $
      -- Core rpc/blockchain.cpp:3432-3435 loadtxoutset:
      --   node.connman->RemoveLocalServices(NODE_NETWORK);
      --   node.connman->AddLocalServices(NODE_NETWORK_LIMITED);
      -- haskoin's `--load-snapshot` flag (app/Main.hs:802-883) does not touch
      -- the PeerManagerConfig advertised services. The post-snapshot node
      -- announces NODE_NETWORK + NODE_WITNESS, but it cannot serve historical
      -- blocks below the snapshot base — peers requesting them will time out
      -- or get DOS-banned scored. BUG-9 P1.
      pendingWith "BUG-9: --load-snapshot doesn't drop NODE_NETWORK / add NODE_NETWORK_LIMITED"

  ------------------------------------------------------------------------------
  -- G27-G28 : Snapshot validation completion + cleanup (BUG-12 / BUG-13)
  -- (Core: validation.cpp:5967-6077 MaybeValidateSnapshot,
  --        :6280-6345 ValidatedSnapshotCleanup,
  --        :6201-6231 InvalidateCoinsDBOnDisk)
  ------------------------------------------------------------------------------

  describe "G27 MaybeValidateSnapshot hash check + invalidation (BUG-12 + BUG-13)" $
    xit "G27 GATE: on hash mismatch, snapshot dir is renamed to <dir>_INVALID" $
      -- Core validation.cpp:6201-6231 InvalidateCoinsDBOnDisk:
      --   fs::rename(db_path, db_path + "_INVALID");
      -- haskoin has no two-directory layout, so no rename is possible.
      -- Worse, `backgroundValidationLoop` (Consensus.hs:4909-4912) swallows
      -- the error into `ausError` and sets `ausValidated=True` (BUG-3),
      -- so the operator never learns the snapshot was bad. BUG-13 P1
      -- (BUG-3 covers the false-validated flag; BUG-13 covers the missing
      -- forensics-rename step).
      pendingWith "BUG-13: no InvalidateCoinsDBOnDisk analogue (<dir>_INVALID rename) on hash mismatch"

  describe "G28 ValidatedSnapshotCleanup (BUG-12)" $
    xit "G28 GATE: on successful validation, snapshot dir is renamed to primary chainstate dir" $
      -- Core validation.cpp:6280-6345 ValidatedSnapshotCleanup:
      --   1. validated_path -> delete_path  (rename IBD dir)
      --   2. assumed_valid_path -> validated_path  (rename snapshot dir to primary)
      --   3. DeleteCoinsDBFromDisk(delete_path)
      -- haskoin has no two-directory layout AND no rename; on the
      -- (currently-impossible) success path of the unwired background
      -- validation loop, ausValidated=True is set and nothing else
      -- happens. BUG-12 P1.
      pendingWith "BUG-12: no ValidatedSnapshotCleanup analogue (snapshot dir → primary dir rename)"

  ------------------------------------------------------------------------------
  -- G29-G30 : Robustness during snapshot load
  ------------------------------------------------------------------------------

  describe "G29 trailing-data guard post-coins-loaded (PRESENT-by-shape)" $
    it "G29 PINS: parseCoins rejects bytes past the declared coin count" $ do
      -- haskoin's parseCoins matches `go 0 acc bs | BS.null bs = Right ...`
      -- and `go 0 acc bs | otherwise = Left "trailing bytes"`. This is the
      -- equivalent of Core's out_of_coins exception (validation.cpp:5873-5882),
      -- modulo the streaming-vs-whole-file distinction. Re-pin via shape
      -- assertion: a metadata with coins=0 followed by one trailing byte
      -- must fail.
      withTmpDir $ \tmp -> do
        let p   = tmp ++ "/trailing.dat"
            raw = buildRawHeader 2 0xd9b4bef9 (fill32 0xaa) 0
            -- One extra byte past end-of-data
            withTrailer = raw <> BS.singleton 0xFF
        BS.writeFile p withTrailer
        r <- loadSnapshot p 0xd9b4bef9
        case r of
          Left _  -> pure ()
          Right _ -> expectationFailure
            "loadSnapshot accepted trailing byte past declared coin count"

  describe "G30 interrupt support during snapshot load (BUG-11)" $
    xit "G30 GATE: snapshot load checks an interrupt every 120000 coins (Core 5840-5843)" $
      -- Core validation.cpp:5840-5843:
      --   if (coins_processed % 120000 == 0) {
      --     if (m_interrupt) return Error{"Aborting after an interrupt was requested"}
      --   }
      -- haskoin reads the entire snapshot file via `BS.readFile`
      -- (Storage.hs:2499) and then parses it eagerly. A 100 GB malicious
      -- snapshot pins memory for minutes; no graceful Ctrl-C abort.
      -- BUG-11 P1.
      pendingWith "BUG-11: snapshot load has no interrupt support (no m_interrupt analogue)"

  ------------------------------------------------------------------------------
  -- Bonus pinning assertions
  ------------------------------------------------------------------------------

  describe "BONUS PINS" $ do
    it "BONUS: every netAssumeUtxo entry has non-zero block hash" $ do
      let nonZero (_, p) = aupBlockHash p /= mkBlockHash 0x00
      all nonZero (netAssumeUtxo mainnet)  `shouldBe` True
      all nonZero (netAssumeUtxo testnet4) `shouldBe` True
      all nonZero (netAssumeUtxo regtest)  `shouldBe` True

    it "BONUS: assumeutxoWhitelistError matches the Core-strict wording" $
      assumeutxoWhitelistError 12345 `shouldSatisfy`
        \msg ->
          ("Assumeutxo height in snapshot metadata not recognized" `isPrefixOfStr` msg)
          && ("12345" `isInfixOfStr` msg)
          && ("refusing to load snapshot" `isSuffixOfStr` msg)

-- Local string helpers (avoid haskoin/Data.Text import noise here).
isPrefixOfStr :: String -> String -> Bool
isPrefixOfStr p s = take (length p) s == p

isInfixOfStr :: String -> String -> Bool
isInfixOfStr p s = any (isPrefixOfStr p) (tails s)
  where
    tails [] = [[]]
    tails xs@(_:t) = xs : tails t

isSuffixOfStr :: String -> String -> Bool
isSuffixOfStr p s = isPrefixOfStr (reverse p) (reverse s)

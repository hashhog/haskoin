# W146 Block storage layer (blkXXXXX.dat + rev*.dat + block-index leveldb) — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** Bitcoin Core's flat-file block storage layer (`blkNNNNN.dat`
data files, `revNNNNN.dat` undo files, plus the `blocks/index/` LevelDB
keyspace with prefixes `'b'`/`'f'`/`'l'`/`'F'`/`'R'`/`'t'`).  Covers the
8 wave behaviours: file format (4-byte magic + 4-byte LE size + body),
`rev*.dat` undo format (magic + size + serialised `CBlockUndo`),
`FindBlockPos` rotation at `MAX_BLOCKFILE_SIZE` (128 MiB) with
`BLOCKFILE_CHUNK_SIZE` (16 MiB) pre-allocation, fsync discipline at
`FlushBlockFile` / `FlushUndoFile`, block-index leveldb key schema,
WriteBlock atomicity (disk write+fsync FIRST, leveldb commit SECOND),
ReadBlockFromDisk magic-checksum gate, and recovery on partial write
(bad-magic-prefix = truncation; `'R'` flag triggers full replay).

**Out of scope:** UTXO snapshot file format (W138 assumeUTXO), the
RocksDB UTXO keyspace (W100 UTXO cache), txindex / coinstatsindex /
blockfilterindex implementations (W133 index DBs), pruning policy
(W124 pruning), `-reindex-chainstate` UTXO replay path (covered by W138
and the rebuild walker in `app/Main.hs:690`).

**Sources audited:**

- `src/Haskoin/Storage.hs:1711-2068` — the entire "Flat File Block
  Storage" section, including `MAX_BLOCKFILE_SIZE`, `BLOCKFILE_CHUNK_SIZE`,
  `FlatFilePos`, `BlockFileInfo`, `BlockIndex`, `BlockStore`,
  `newBlockStore`, `findNextBlockPos`, `writeBlockToDisk`,
  `readBlockFromDisk`, `preAllocateFile`.
- `src/Haskoin/Storage.hs:1264-1387` — `TxUndo`, `BlockUndo`, `UndoData`
  (the undo data DEFINED but persisted only in RocksDB, not in
  `rev*.dat`).
- `src/Haskoin/Storage.hs:1832-1949` — DB prefix bytes for the block
  index keyspace (`prefixBlockIndex` = 0x62 / `prefixFileInfo` = 0x66 /
  `prefixLastBlockFile` = 0x6c) and `putBlockIndex` / `putFileInfo` /
  `getLastBlockFile`.
- `src/Haskoin/Storage.hs:315-350` — the PRODUCTION block keyspace
  (`PrefixBlockData` = 0x02 etc.) — note the orthogonal numeric
  prefixes used for block storage in RocksDB, distinct from the
  Bitcoin-Core ASCII prefixes in the unused flat-file index.
- `src/Haskoin/Storage.hs:399-403, 1683-1708, 2620-2625` — `syncFlush`
  WAL-level fsync via the sentinel-key write trick.
- `src/Haskoin/Storage.hs:2129-2400` — the pruning-support helpers
  (`pruneOneBlockFile`, `findFilesToPrune`, `revFilePath`, etc.) which
  reference `blkNNNNN.dat` + `revNNNNN.dat` filenames but operate on
  an empty `bsFileInfos` map because nothing populates it.
- `src/Haskoin/Storage.hs:1389-1456` — `PersistedChainState` (separate
  best-block sentinel — non-Core layout).
- `app/Main.hs:564-580, 961-974, 1862-1872` — the only call-site that
  ever constructs a `BlockStore` (lazy-creates only when `-prune` is
  enabled; comments admit "Most haskoin block I/O still flows through
  RocksDB, so the BlockStore is not on the hot path").
- `app/Main.hs:738-789` — the `-reindex-chainstate` replay walker that
  fetches blocks via `getBlock db bh` (RocksDB path) and TODOs the
  flat-file alternative; comment explicitly says
  "look them up via BlockIndex / readBlockFromDisk here. For now we
  honestly stop".
- `bitcoin-core/src/node/blockstorage.h:56-95` — `CBlockFileInfo`
  schema (7 VARINT-encoded fields).
- `bitcoin-core/src/node/blockstorage.h:119-129` — `BLOCKFILE_CHUNK_SIZE`
  16 MiB, `UNDOFILE_CHUNK_SIZE` 1 MiB, `MAX_BLOCKFILE_SIZE` 128 MiB,
  `STORAGE_HEADER_BYTES` = 8.
- `bitcoin-core/src/node/blockstorage.cpp:732-768` — `FlushBlockFile`
  / `FlushUndoFile` (fsync on rotation).
- `bitcoin-core/src/node/blockstorage.cpp:833-920` —
  `FindNextBlockPos` (rotation logic, calls FlushBlockFile on the
  previous file BEFORE allocating in the new one).
- `bitcoin-core/src/node/blockstorage.cpp:967-1033` — `WriteBlockUndo`
  (writes magic + size + body + SHA256 checksum to `revNNNNN.dat`).
- `bitcoin-core/src/node/blockstorage.cpp:1134-1165` — `WriteBlock`
  (writes magic + size + body to `blkNNNNN.dat`).
- `bitcoin-core/src/chain.h:325-360` — `CDiskBlockIndex` schema
  (VARINT-encoded fields conditional on `BLOCK_HAVE_DATA` /
  `BLOCK_HAVE_UNDO` flags).
- `bitcoin-core/src/kernel/chainparams.cpp:117-120, 235-238, 335-338,
  560-563` — network magic bytes (mainnet `f9 be b4 d9`, testnet3
  `0b 11 09 07`, testnet4 `1c 16 3f 28`, regtest `fa bf b5 da`).

**Result:** out of the 8 wave behaviours, **none are present on the
production hot path** — every block read/write actually goes through
the RocksDB `PrefixBlockData` keyspace via `putBlock` / `getBlock`
(Storage.hs:423-435), not through the flat-file API.  The flat-file
API is fully scaffolded (~370 LOC plus undo + pruning helpers) but
nothing in the production code path calls `writeBlockToDisk` and
nothing calls `readBlockFromDisk`.  This is the cleanest "dead-class
fleet pattern" instance observed in haskoin since W138's
`ChainstateManager` / `runBackgroundValidation` dead-helper cluster.

**Bugs found:** 23 (1 P0-CDIV / 4 P0 / 9 P1 / 6 P2 / 3 P3).

## Top-line verdict

Haskoin has a **two-pipeline storage architecture** where one pipeline
(RocksDB key-value, prefix `0x02`) is fully wired and used by every
production path, while the second pipeline (Core's flat-file
`blkNNNNN.dat` + `revNNNNN.dat` + block-index leveldb) is fully
DEFINED, EXPORTED from the module, ACKNOWLEDGED in `Main.hs`
comments — and never executed.  The whole BlockStore subsystem ships
in a state where:

1.  `newBlockStore` is only invoked under `-prune=N` (Main.hs:968).
2.  When invoked, it initialises a `bsFileInfos` map from disk; the
    map starts empty and stays empty because nothing ever calls
    `writeBlockToDisk`.
3.  `pruneOneBlockFile` / `autoPruneIfNeeded` then walk that empty
    map and prune zero files — pruning RPC is silently a no-op even
    under `-prune=550`.
4.  `revFilePath` is referenced only by `pruneOneBlockFile`, which
    deletes a non-existent file.

In addition to the dead-class problem, the flat-file scaffolding
itself has substantive divergences from Core (wrong CBlockFileInfo
schema, wrong CDiskBlockIndex schema, no fsync on rotation, no
HashWriter checksum on undo body, no posix_fallocate space reservation,
no concurrency protection on the cursor state, no `'R'` reindex flag,
no signet magic), so the moment the wire-up is added the existing
implementation will diverge.

## Fleet patterns observed

- **Dead-class / dead-subsystem fleet pattern** (W138-style): an
  entire 370-LOC subsystem (`writeBlockToDisk`, `readBlockFromDisk`,
  `findNextBlockPos`, `BlockStore`, `BlockIndex`, `BlockFileInfo`,
  `FlatFilePos`) is defined, exported, and never called from
  production code.  Only test code (`W109BlockIndexSpec.hs`,
  `W100UTXOCacheSpec.hs`) exercises it.  This mirrors the W138
  `runBackgroundValidation` is-dead-code pattern and W137 PSBT
  `PsbtError.DuplicateKey` enum-with-zero-raisers pattern.
- **Comment-as-confession** (W138-style): `Main.hs:962` literally
  reads "Most haskoin block I/O still flows through RocksDB, so the
  BlockStore is not on the hot path; we only create it when prune
  RPC / auto-prune triggers need it" — an explicit, written
  acknowledgement that the production storage path bypasses the
  Core-style block-file layer.  `Main.hs:751-756` likewise admits
  "TODO(reindex): if haskoin is configured to store block bodies in
  the flat-file store (writeBlockToDisk), look them up via
  BlockIndex / readBlockFromDisk here. For now we honestly stop".
- **Two-pipeline / fork-in-the-road** (W126/W128-style): two
  COMPLETE storage stacks (`PrefixBlockData` RocksDB path vs.
  `writeBlockToDisk` flat-file path) coexist with the dead path
  serving no production purpose.  The two pipelines use DIFFERENT
  prefix-byte schemes (numeric 0x02 vs ASCII `'b'`), so re-wiring
  one to the other would not collide on the keyspace — but would
  also break any operator who relied on the existing data layout.

## Bugs

### BUG-1: Flat-file block storage entire subsystem is DEAD CODE — no production caller [P0-CDIV]

**File:** `src/Haskoin/Storage.hs:1995-2068, 2071-2126`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:1134-1165, 484-664`

**Description:** `writeBlockToDisk` and `readBlockFromDisk` are
exported (Storage.hs:154-155) but never called from any non-test code
in the entire repository.  Production block writes go through
`putBlock db bh block` (Storage.hs:424-428) which stores a
`PrefixBlockData` (0x02) RocksDB key; production block reads go
through the matching `getBlock`.  All 370 LOC of flat-file scaffolding
(BlockStore, BlockIndex, BlockFileInfo, FlatFilePos, findNextBlockPos,
preAllocateFile, blockFilePath, revFilePath, the file-info iterator,
the per-file pruning helpers) execute only from `test/`.

**Excerpt:** Direct grep across `src/` and `app/` for callers of the
flat-file write/read primitives:
```
$ grep -rn "writeBlockToDisk\|readBlockFromDisk" src/ app/
src/Haskoin/Storage.hs:154:  , writeBlockToDisk
src/Haskoin/Storage.hs:155:  , readBlockFromDisk
src/Haskoin/Storage.hs:1995:writeBlockToDisk :: BlockStore -> Block -> ...
src/Haskoin/Storage.hs:2071:readBlockFromDisk :: BlockStore -> BlockIndex -> ...
app/Main.hs:753:                        -- (writeBlockToDisk), look them up via
app/Main.hs:754:                        -- BlockIndex / readBlockFromDisk here. For
```
The only `src/` references are the export list and the definitions
themselves.  The only `app/Main.hs` reference is a TODO comment.

**Impact:** P0-CDIV.  Haskoin's on-disk block layout is fundamentally
incompatible with any other Bitcoin node — no `blkNNNNN.dat` or
`revNNNNN.dat` files exist after a full IBD.  An operator who tries
to import a `blocks/` directory from Bitcoin Core, knots, or any of
the other 9 haskoin sibling implementations cannot do so.  An
operator who tries to export haskoin's `blocks/` for use elsewhere
will find a single RocksDB with the entire chain in one keyspace
instead of the canonical layout.  This also implicates the pruning
RPC (BUG-2) and the `-reindex` flag (BUG-9) — both are
non-functional in their current form.

### BUG-2: pruneblockchain / -prune=N silently a no-op — operates on empty bsFileInfos [P0]

**File:** `src/Haskoin/Storage.hs:2249-2257, 2281-2302`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:264-291, 333-380`

**Description:** `autoPruneIfNeeded` and `pruneBlockchain` walk
`bsFileInfos` to decide what to prune.  `bsFileInfos` is populated
ONLY by `writeBlockToDisk` (Storage.hs:2042-2050).  Since
`writeBlockToDisk` is never called (BUG-1), `bsFileInfos` stays
empty for the lifetime of the daemon and `findFilesToPrune` returns
`[]` on every invocation.

**Excerpt:**
```haskell
-- Storage.hs:2249
autoPruneIfNeeded :: BlockStore -> Word32 -> PruneConfig -> IO Int
autoPruneIfNeeded store tipHeight cfg =
  case pruneConfigAutoTarget cfg of
    Nothing     -> return 0  -- disabled or manual
    Just target -> do
      fileInfos <- readIORef (bsFileInfos store)   -- always Map.empty
      let toPrune = findFilesToPrune tipHeight target fileInfos
      forM_ toPrune (pruneOneBlockFile store)      -- forM_ over []
      return (length toPrune)                       -- always 0
```
And the trigger site in `Main.hs:1866` happily logs zero pruned
files every time it fires.

**Impact:** P0.  Operators who enable `-prune=550` to keep disk usage
below 550 MiB will silently see their RocksDB grow without bound,
since the only path that DOES write the actual block bodies
(`putBlock`) has no corresponding prune step.  Disk-full crashes are
the eventual symptom.

### BUG-3: BlockFileInfo schema only has 4 fields — missing nUndoSize / nTimeFirst / nTimeLast [P0]

**File:** `src/Haskoin/Storage.hs:1758-1786`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:56-95`

**Description:** Core's `CBlockFileInfo` carries 7 fields: nBlocks,
nSize, **nUndoSize**, nHeightFirst, nHeightLast, **nTimeFirst**,
**nTimeLast** — all serialised as VARINT.  Haskoin's `BlockFileInfo`
defines only 4: `bfiNumBlocks`, `bfiSize`, `bfiMinHeight`,
`bfiMaxHeight` — and serialises them as fixed-width `Word32`/`Word64`
LE.  This means haskoin cannot track undo-file size for pruning
correctness, cannot tell when a file is finalised by time-bucket, and
its on-disk `'f'`-prefix records would be byte-incompatible with any
Core implementation even if the wire-up were added.

**Excerpt:**
```haskell
-- Storage.hs:1758
data BlockFileInfo = BlockFileInfo
  { bfiNumBlocks  :: !Int        -- ^ Number of blocks stored in this file
  , bfiSize       :: !Int64      -- ^ Total bytes used in this file
  , bfiMinHeight  :: !Word32     -- ^ Minimum block height in this file
  , bfiMaxHeight  :: !Word32     -- ^ Maximum block height in this file
  } deriving (Show, Eq, Generic)
-- ... compare with Core:
-- uint32_t nBlocks, nSize, nUndoSize, nHeightFirst, nHeightLast;
-- uint64_t nTimeFirst, nTimeLast;
```

**Impact:** P0.  `nUndoSize` is what `CalculateCurrentUsage` adds to
`nSize` to get the real disk footprint — haskoin's pruner therefore
under-counts disk usage by the full size of all undo data, so
auto-prune fires later than Core does for the same target.  When the
wire-up between `putBlock` and `writeBlockToDisk` lands, the
operator-visible file-info entries will be byte-incompatible with
Core: a haskoin block-index leveldb cannot be opened by Bitcoin Core
and vice versa.

### BUG-4: BlockIndex schema uses fixed-width LE instead of CDiskBlockIndex VARINT layout [P0]

**File:** `src/Haskoin/Storage.hs:1788-1809`
**Core ref:** `bitcoin-core/src/chain.h:325-360`

**Description:** Core's `CDiskBlockIndex` schema is:
`VARINT(_nVersion=259900) || VARINT(nHeight) || VARINT(nStatus) ||
VARINT(nTx) || [if BLOCK_HAVE_DATA|UNDO: VARINT(nFile)] ||
[if BLOCK_HAVE_DATA: VARINT(nDataPos)] || [if BLOCK_HAVE_UNDO:
VARINT(nUndoPos)] || nVersion(4LE) || hashPrev(32B) ||
hashMerkleRoot(32B) || nTime(4LE) || nBits(4LE) || nNonce(4LE)`.
Haskoin's `BlockIndex` stores only 4 fixed-width fields (fileNum LE
Word32, dataPos LE Word64, undoPos LE Word64, height LE Word32) and
NONE of the header fields, nStatus, nTx, or version-tag.

**Excerpt:**
```haskell
-- Storage.hs:1788
data BlockIndex = BlockIndex
  { biFileNumber :: !Int        -- ^ File number where block data is stored
  , biDataPos    :: !Int64      -- ^ Position of block data within the file
  , biUndoPos    :: !Int64      -- ^ Position of undo data (0 if not stored)
  , biHeight     :: !Word32     -- ^ Block height
  }
-- Missing: nStatus (BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO / VALIDATED
-- bits), nTx, the entire 80-byte serialised header, the DUMMY_VERSION
-- tag, and the conditional-encoding pattern.
```

**Impact:** P0.  Haskoin cannot reconstruct a block header from its
on-disk index alone — every "give me the header at height H" request
must round-trip through `PrefixBlockHeader` (a separate keyspace),
implying double the disk reads of Core for header-only RPCs.
On-disk byte incompatibility with Core compounds BUG-3.

### BUG-5: Block-index DB prefix bytes do NOT match Core's ASCII scheme ('b'/'f'/'l') [P1]

**File:** `src/Haskoin/Storage.hs:1832-1842`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp`, prefix uses
char literals `'b'` / `'f'` / `'l'` / `'F'` / `'R'` / `'t'`.

**Description:** Haskoin's `prefixBlockIndex = 0x62`, `prefixFileInfo
= 0x66`, `prefixLastBlockFile = 0x6c` are the correct ASCII codepoints
for `'b'` / `'f'` / `'l'` IF you only look at the block-index sub-DB.
However, NONE of the other Core prefixes are defined: no `'F'`
(flags), no `'R'` (reindexing flag), no `'t'` (txindex).  And the
PRODUCTION block keyspace (`PrefixBlockData` = 0x02 — Storage.hs:336)
is a completely orthogonal numeric scheme that has nothing to do
with Core's layout.

**Excerpt:**
```haskell
-- Storage.hs:1832 (flat-file dead-code path, ASCII)
prefixBlockIndex     = 0x62  -- 'b'
prefixFileInfo       = 0x66  -- 'f'
prefixLastBlockFile  = 0x6c  -- 'l'
-- Storage.hs:335 (RocksDB live path, numeric — incompatible with Core)
prefixByte PrefixBlockHeader = 0x01
prefixByte PrefixBlockData   = 0x02
prefixByte PrefixBlockHeight = 0x03
prefixByte PrefixTxIndex     = 0x04
...
```
The two schemes coexist in the SAME RocksDB column family with no
collision check.  If a numeric-prefix key and an ASCII-prefix key
happen to share a leading byte (e.g. 0x02 = ASCII `STX`, no
collision; but 0x62 = `'b'` = currently unused on the numeric path —
trivial collision risk if either scheme is extended).

**Impact:** P1.  Cross-implementation tooling that expects to read
Core's `blocks/index/` LevelDB cannot consume haskoin's DB.  The
dual-scheme coexistence is a latent foot-gun for future extensions.

### BUG-6: No 'R' reindex flag persisted — recovery on partial write impossible [P1]

**File:** missing from `src/Haskoin/Storage.hs` entirely
**Core ref:** `bitcoin-core/src/node/blockstorage.h:104-105`,
`BlockTreeDB::WriteReindexing` / `ReadReindexing`

**Description:** Core writes a single boolean `'R'`-prefix key into
`blocks/index/` whenever a reindex is in progress.  On startup, if
that key is present, `LoadBlockIndexDB` triggers a full block-file
replay rather than trusting the index.  Haskoin has no such flag and
no equivalent recovery hook: `app/Main.hs:118-119` defines
`noReindex` / `noReindexChainstate` CLI booleans, but the
`-reindex` arm is explicitly TODO (Main.hs:699-700) and falls
through to `-reindex-chainstate` which never touches the flat-file
store.

**Excerpt:**
```
$ grep -rn "'R'\|prefixReindex\|reindex_flag" src/Haskoin/Storage.hs
(no matches)
```

**Impact:** P1.  A crash mid-block-file rotation cannot be detected
on the next startup; without the `'R'` flag haskoin will silently
continue from a half-corrupted file.  Compounds BUG-1 (since the
flat-file path is never written there is nothing for the flag to
guard) but blocks any future wire-up.

### BUG-7: writeBlockToDisk does not fsync the block file before committing the leveldb index entry [P1]

**File:** `src/Haskoin/Storage.hs:2006-2068`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:742-768,
833-905, 1134-1165`

**Description:** Core's invariant is **fsync the block file FIRST,
THEN write the leveldb index entry**, so a crash between the two
leaves a fully-on-disk block whose only consequence is a re-download.
Haskoin's `writeBlockToDisk` does `hFlush h` (a stdio buffer flush —
not an fsync) and then `hClose h` (also not an fsync on Linux), then
calls `putBlockIndex` against the asynchronous-WAL RocksDB
configuration (`dbWriteOpts = R.defaultWriteOptions { sync = False }`
— Storage.hs:367).  Neither side is durable when the function
returns.

**Excerpt:**
```haskell
-- Storage.hs:2026
hPut h blockData
hFlush h          -- stdio flush only; does not fsync(2)
hClose h          -- does not fsync(2) on Linux either
-- ...
putBlockIndex (bsDB store) blockHash idx
-- ^ async write under sync=False; lands in WAL buffer, not on disk
```
Compare with Core, where `FlushBlockFile` runs
`m_block_file_seq.Flush` (which fsyncs) before any subsequent
`m_dirty_blockindex` flush.

**Impact:** P1.  A power-loss crash between `writeBlockToDisk`
returning and the next `syncFlush` can leave both the block data and
the index entry in volatile kernel buffers, recoverable from the WAL
but only if the WAL itself was flushed.  In the current path (block
storage in RocksDB, not flat files) the same hazard exists at the
RocksDB layer because the production write path also uses
`sync=False` and only periodically calls `syncFlush`.

### BUG-8: Block-file rotation in findNextBlockPos does not FlushBlockFile the previous file [P1]

**File:** `src/Haskoin/Storage.hs:1970-1991`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:886-901`

**Description:** Core's `FindNextBlockPos` (line 886) explicitly
calls `FlushBlockFile(last_blockfile, fFinalize=true, finalize_undo)`
BEFORE bumping the cursor to the new file, ensuring the file being
left behind is durable.  Haskoin's `findNextBlockPos` just bumps the
counter:
```haskell
-- Storage.hs:1979
if currentPos + totalSize > maxBlockFileSize
  then do
    let newFile = currentFile + 1
    writeIORef (bsCurrentFile store) newFile
    writeIORef (bsCurrentPos store) 0
    modifyIORef' (bsFileInfos store) (Map.insert newFile emptyBlockFileInfo)
    putLastBlockFile (bsDB store) newFile           -- async leveldb put
    return $ FlatFilePos newFile 0
```
There is no `hSync` or `syncFlush` of the previous file's last
write.

**Impact:** P1.  A crash immediately after rotation can leave the
last block(s) of the previous file in kernel buffers only; on
restart their `BlockIndex` entries point at byte ranges that may not
yet exist on disk.  Compounds BUG-7.

### BUG-9: -reindex CLI option is acknowledged TODO; flat-file replay impossible [P1]

**File:** `app/Main.hs:118-119, 259-262, 690-761`
**Core ref:** `bitcoin-core/src/init.cpp` — `-reindex` triggers a
full re-walk of `blocks/blkNNNNN.dat` against the genesis chainstate.

**Description:** The `--reindex` flag is parsed but only triggers
`-reindex-chainstate` semantics (Main.hs:259-262).  The actual
"rebuild block-index from blk*.dat" path is documented as TODO
(Main.hs:699-700).  Combined with BUG-1, there are no blk*.dat
files for `-reindex` to walk even if the code path were written.

**Excerpt:**
```haskell
-- Main.hs:259
<*> switch (long "reindex"
         <> help "Rebuild block index from blk*.dat (TODO: \
                \today this implies --reindex-chainstate; full block-index \
                \rebuild from blk*.dat is not yet implemented).")
-- Main.hs:751-756
-- TODO(reindex): if haskoin is configured to store block bodies in
-- the flat-file store (writeBlockToDisk), look them up via
-- BlockIndex / readBlockFromDisk here. For now we honestly stop,
-- matching Core's "missing block data, exiting" log.
```

**Impact:** P1.  Operators who experience block-index corruption have
no recovery primitive beyond a full IBD from genesis: they cannot
salvage block bodies from an existing `blocks/` directory because no
such directory is populated.

### BUG-10: rev*.dat undo file format never produced — undo data lives in RocksDB only [P1]

**File:** `src/Haskoin/Storage.hs:1331-1356, 2260-2262`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:967-1033`

**Description:** Haskoin's `putUndoData db bh undo` (Storage.hs:1331)
serialises the entire `UndoData` (including a checksum field) and
stores it under a `0x10`-prefixed RocksDB key.  No `revNNNNN.dat`
file is ever produced; `revFilePath` is referenced only by
`pruneOneBlockFile` (Storage.hs:2314), which deletes a file that
doesn't exist.  Core's `WriteBlockUndo` writes `magic || size ||
serialised_undo || SHA256(prev_block_hash || serialised_undo)` to a
flat file, so haskoin cannot read or write Core-format undo data.

**Excerpt:**
```haskell
-- Storage.hs:1331
putUndoData :: HaskoinDB -> BlockHash -> UndoData -> IO ()
putUndoData db bh undo =
  let key = BS.cons 0x10 (encode bh)
  in R.put (dbHandle db) (dbWriteOpts db) key (encode undo)
-- vs Core blockstorage.cpp:991:
--   fileout << GetParams().MessageStart() << blockundo_size;
--   pos.nPos += STORAGE_HEADER_BYTES;
--   HashWriter hasher{};
--   hasher << block.pprev->GetBlockHash() << blockundo;
--   fileout << blockundo << hasher.GetHash();
```

**Impact:** P1.  Same cross-implementation incompatibility as BUG-1.
A reorg on haskoin pulls undo records from RocksDB (production
path); a Core-compatible undo file dump would require a separate
exporter.

### BUG-11: readBlockFromDisk has no size sanity check — memory bomb potential [P1]

**File:** `src/Haskoin/Storage.hs:2102-2110`
**Core ref:** `bitcoin-core/src/streams.h` `CAutoFile`, plus the
`MAX_BLOCK_SERIALIZED_SIZE` (4 MB) bound enforced by BufferedReader.

**Description:** `readBlockFromDisk` reads a 4-byte LE size from
disk and then unconditionally allocates a `ByteString` of that size:
```haskell
-- Storage.hs:2103
blockSize <- case runGet getWord32le sizeBytes of
  Left err -> ...
  Right s -> return (fromIntegral s :: Int)
-- ...
blockData <- hGet h blockSize  -- allocates blockSize bytes
```
A corrupted on-disk size field of 0xFFFFFFFF = 4 GiB will allocate
4 GiB before any sanity check.  Compare BUG-10 in W138 (haskoin's
loadtxoutset memory-bomb via VarInt) — same primitive failure mode.

**Impact:** P1.  Crash-during-write that leaves a partially-written
size field is enough to OOM the node on the next startup.  Currently
unreachable in production because no flat-file blocks exist (BUG-1),
but is a latent foot-gun the moment the wire-up lands.

### BUG-12: No bracket discipline — file handle leak on exception path [P1]

**File:** `src/Haskoin/Storage.hs:2006-2068, 2083-2114`
**Core ref:** `bitcoin-core/src/streams.h` `AutoFile` RAII guard.

**Description:** `writeBlockToDisk` uses `openBinaryFile filePath
ReadWriteMode \`catch\` ...` followed by raw `hSeek` / `hPut` / `hFlush`
/ `hClose`.  The `try` wrapping is OUTSIDE the open: if any inner
operation throws after `openBinaryFile` succeeds, the handle leaks.
`readBlockFromDisk` is structurally identical.  Core's `AutoFile`
wrapper closes on RAII destruction; idiomatic Haskell uses
`bracket` / `withBinaryFile`.

**Excerpt:**
```haskell
-- Storage.hs:2006
result <- try $ do
  h <- openBinaryFile filePath ReadWriteMode `catch` ...
  -- if pre-allocate, hSeek, hPut throw, h leaks
  ...
  hFlush h
  hClose h
  return ()
```

**Impact:** P1.  Long-running daemon with intermittent disk errors
will accumulate file-handle leaks until it hits the ulimit.

### BUG-13: findNextBlockPos / writeBlockToDisk have no lock — concurrent writers race [P1]

**File:** `src/Haskoin/Storage.hs:1970-1991, 2001-2050`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:835`
(`LOCK(cs_LastBlockFile);`).

**Description:** Core wraps the entire `FindNextBlockPos` body in
`LOCK(cs_LastBlockFile)`.  Haskoin's `findNextBlockPos` reads three
IORefs, decides, then writes three IORefs without any atomic
guard.  Two concurrent calls can both see the same `currentFile`
and `currentPos`, both decide rotation is needed, and both bump
`currentFile := currentFile + 1` — but the writes race, so one
caller's `FlatFilePos` may point at the same offset another
caller is about to write to.  The subsequent `bsFileInfos` update
(Storage.hs:2042) uses `modifyIORef'` which is atomic for the read-
modify-write, but the gap between `findNextBlockPos` returning and
`modifyIORef'` running is wide open.

**Excerpt:**
```haskell
-- Storage.hs:1971
findNextBlockPos store blockSize height = do
  currentFile <- readIORef (bsCurrentFile store)
  currentPos <- readIORef (bsCurrentPos store)
  fileInfos <- readIORef (bsFileInfos store)
  -- ^^^ three non-atomic reads, no MVar/TVar
  let totalSize = fromIntegral (blockSize + storageHeaderBytes)
  if currentPos + totalSize > maxBlockFileSize
    then do
      let newFile = currentFile + 1
      writeIORef (bsCurrentFile store) newFile      -- non-atomic
      writeIORef (bsCurrentPos store) 0             -- non-atomic
      ...
```

**Impact:** P1.  Block-corruption hazard on multi-threaded paths
(currently theoretical because of BUG-1 — but a latent bug for the
day the wire-up lands).  Compounds BUG-8.

### BUG-14: preAllocateFile uses hSetFileSize instead of posix_fallocate [P2]

**File:** `src/Haskoin/Storage.hs:1960-1966`
**Core ref:** `bitcoin-core/src/node/blockstorage.cpp:910`
(`m_block_file_seq.Allocate` → `AllocateFileRange` → posix_fallocate).

**Description:** Haskoin uses `hSetFileSize h (fromIntegral newSize)`
to "pre-allocate" space.  On Linux this expands the file via a
truncate(2) syscall, which creates a sparse file — no actual disk
blocks are reserved.  Core uses `posix_fallocate(2)` which reserves
real disk blocks, so an out-of-space condition is detected at
allocation time rather than at first write.

**Excerpt:**
```haskell
-- Storage.hs:1960
preAllocateFile :: Handle -> Int64 -> Int64 -> IO ()
preAllocateFile h currentSize targetSize = do
  let currentChunks = (currentSize + blockFileChunkSize - 1) `div` blockFileChunkSize
      targetChunks  = (targetSize + blockFileChunkSize - 1) `div` blockFileChunkSize
  when (targetChunks > currentChunks) $ do
    let newSize = targetChunks * blockFileChunkSize
    hSetFileSize h (fromIntegral newSize)  -- sparse; no real allocation
```

**Impact:** P2.  On a disk-full condition haskoin would write
successfully for a while (kernel buffers absorbing the writes) and
then EIO-fail mid-block.  Core would fail the FindNextBlockPos call
immediately.  Also produces a sparse file that confuses `du(1)` /
filesystem-monitor tooling.

### BUG-15: No UNDOFILE_CHUNK_SIZE constant; no undo-file pre-allocation [P2]

**File:** `src/Haskoin/Storage.hs` — missing entirely
**Core ref:** `bitcoin-core/src/node/blockstorage.h:121`
(`UNDOFILE_CHUNK_SIZE = 0x100000 = 1 MiB`).

**Description:** Core pre-allocates undo files in 1 MiB chunks (not
16 MiB — undo files are much smaller than block files).  Haskoin
has `blockFileChunkSize = 16 MiB` but no analogue for undo files.
Combined with BUG-10 (rev*.dat never produced) this is currently
moot, but the constant is part of Core's storage contract and is
missing from haskoin's `Storage.hs` constants block (Storage.hs:1711-
1729).

**Impact:** P2.  Latent constant gap; will surface as soon as
undo-file storage is wired.

### BUG-16: STORAGE_HEADER_BYTES is hard-coded 8 with no link to MessageStart size [P2]

**File:** `src/Haskoin/Storage.hs:1727-1729`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:126`
(`STORAGE_HEADER_BYTES = std::tuple_size_v<MessageStartChars> +
sizeof(unsigned int)`).

**Description:** Core derives the 8-byte storage header from
`size_of(MessageStartChars) + size_of(unsigned int) = 4 + 4`, so if
the magic-byte width changed (e.g. an extended magic for a new
network) the constant would auto-track.  Haskoin's
`storageHeaderBytes = 8` is hard-coded; it relies on
`bsNetworkMagic :: ByteString` being exactly 4 bytes, but nothing
in `newBlockStore` enforces that.

**Excerpt:**
```haskell
-- Storage.hs:1727
storageHeaderBytes :: Int
storageHeaderBytes = 8
-- but bsNetworkMagic is "ByteString" not "Vector 4 Word8"; a 5-byte
-- magic would silently corrupt the on-disk framing
```

**Impact:** P2.  Soft API hazard.  A future "5-byte network magic"
extension would silently corrupt all on-disk blocks.

### BUG-17: No size validation in readBlockFromDisk against MAX_BLOCK_SERIALIZED_SIZE [P2]

**File:** `src/Haskoin/Storage.hs:2102-2113`
**Core ref:** `bitcoin-core/src/streams.h` BufferedReader rejects
oversized reads; `bitcoin-core/src/node/blockstorage.cpp:484-606`
ReadBlockFromDisk indirectly enforces the bound via the
`BlockValidationState` gate.

**Description:** After reading the 4-byte size field, haskoin
accepts any 32-bit value (up to ~4 GiB) and proceeds to read that
many bytes.  Core enforces `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000`
upstream and rejects oversized reads.

**Excerpt:**
```haskell
-- Storage.hs:2103
blockSize <- case runGet getWord32le sizeBytes of
  Left err -> ...
  Right s -> return (fromIntegral s :: Int)
-- No check: blockSize <= maxBlockSerializedSize?
blockData <- hGet h blockSize
```

**Impact:** P2.  Memory bomb on corrupted on-disk data (compounds
BUG-11).  Defence-in-depth missing.

### BUG-18: Magic bytes are passed in by hand from app/Main.hs via netMagicBytesLE — not derived inside newBlockStore [P2]

**File:** `app/Main.hs:568-580, 970` and `src/Haskoin/Storage.hs:1851`
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:117-120,
235-238, 335-338, 560-563` (per-network magic baked into chainparams).

**Description:** `newBlockStore :: FilePath -> ByteString -> HaskoinDB
-> IO BlockStore` takes the magic bytes as a `ByteString` argument
rather than reading them from a `Network` value.  `Main.hs:573`
re-implements the LE conversion (`netMagicBytesLE`) instead of
calling the existing `Haskoin.Network.netMagicBytes` (Network.hs:
2314), as called out by a comment that admits the duplication is
intentional "to avoid widening that module's export list".  This
adds a fourth duplicated little-endian conversion to the codebase
(Network.hs has one; this is the second; Consensus.hs:1044-1283
comments include the third and fourth — though those are comments
only).

**Impact:** P2.  Maintenance hazard; mismatched magic-byte
conversions across modules.  Latent bug if one site updates and the
other doesn't.

### BUG-19: No signet chainparams — netMagic table only covers mainnet/testnet3/testnet4/regtest [P2]

**File:** `src/Haskoin/Consensus.hs:1044, 1138, 1190, 1283`
**Core ref:** `bitcoin-core/src/kernel/chainparams.cpp:476-480`
(`std::copy_n(hash.begin(), 4, pchMessageStart.begin())` —
signet's magic is computed from the challenge script hash).

**Description:** Haskoin defines per-network `netMagic` for the
four "fixed-magic" networks but has no signet parameter set at all.
The `loadSnapshot` and `BlockStore` APIs accept any
`bsNetworkMagic :: ByteString`, so signet support would in theory
be a config-file addition — but the wire-up is missing.

**Impact:** P2.  Operators cannot connect haskoin to a custom
signet without forking the chainparams table.

### BUG-20: getLastBlockFile uses fromBE32 — disagrees with how the file number was written (putBlockIndex uses BE too, but Map.lookup uses Int directly) [P2]

**File:** `src/Haskoin/Storage.hs:1913-1929`
**Core ref:** `bitcoin-core/src/dbwrapper.h` (uses native int).

**Description:** `getLastBlockFile` reads a 4-byte big-endian value
(`fromBE32 val`) and `putLastBlockFile` writes the same way
(`toBE32 (fromIntegral fileNum)`).  This is internally consistent but
the on-disk encoding (big-endian) is the opposite of every other
file-pos integer in the impl (LE) and the opposite of Core's
`CDBWrapper` which serialises file numbers as
`VARINT(nFile)`.  In the file-info iterator (Storage.hs:1899-1908)
the same BE encoding is used as a key payload — again internally
consistent, but consciously divergent from any "open Core's DB and
read it" path.

**Impact:** P2.  Format gap.

### BUG-21: Empty BlockFileInfo bfiMinHeight = maxBound silently survives a zero-block file [P3]

**File:** `src/Haskoin/Storage.hs:1780-1786, 2042-2050`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:83-94`
(`AddBlock` only updates min when `nBlocks == 0 || nHeightFirst >
nHeightIn`).

**Description:** `emptyBlockFileInfo` initialises `bfiMinHeight =
maxBound :: Word32 = 0xFFFFFFFF` so that the `min` in the file-info
update path picks up the first inserted height.  This is the same
pattern Core uses logically, but the encoded `BlockFileInfo` on a
zero-block file will serialise `bfiMinHeight = 0xFFFFFFFF` to disk
(via the `putWord32le` in the Serialize instance — Storage.hs:1771)
— a value that, if ever read by other tooling, looks like "this file
contains height 4_294_967_295".  Core's VARINT-encoded
`nHeightFirst` starts at zero and only ever takes real heights.

**Impact:** P3.  Cosmetic / interop hazard; survives only because
the zero-block case is not observed in practice.

### BUG-22: Hard-coded mainnet magic in W100UTXOCacheSpec test obscures cross-network coverage [P3]

**File:** `test/W100UTXOCacheSpec.hs:674` (cross-cite)
**Core ref:** `bitcoin-core/src/test/blockstorage_tests.cpp`
covers each network.

**Description:**
```haskell
bs <- newBlockStore blocksDir (BS.pack [0xf9,0xbe,0xb4,0xd9]) db
```
The test uses the mainnet magic byte literal directly rather than
calling `netMagicBytesLE mainnet`.  No testnet4 or regtest test
exists for the block store at all.

**Impact:** P3.  Test coverage gap; per-network rotation /
magic-mismatch path is untested.

### BUG-23: bsFileInfos persistence is per-file via individual R.put — no batched WriteBatchSync [P3]

**File:** `src/Haskoin/Storage.hs:1931-1935, 2052-2056`
**Core ref:** `bitcoin-core/src/node/blockstorage.h:102`
(`BlockTreeDB::WriteBatchSync(fileInfo, nLastFile, blockinfo)`).

**Description:** Core batches all dirty `CBlockFileInfo`,
`CDiskBlockIndex`, and `nLastBlockFile` updates into a single
synchronous LevelDB write.  Haskoin's
`putFileInfo` is invoked once per block via the asynchronous
`dbWriteOpts` (Storage.hs:1934), and `putLastBlockFile` likewise.
There is no batch primitive for the file-info / last-file pair.

**Impact:** P3.  Performance gap (more leveldb roundtrips than Core)
and a subtle atomicity divergence (Core's batch lands as a single
WAL entry; haskoin's two puts can interleave with crash mid-way).

## Suggested fix waves

Given the scope of dead code, splitting into incremental wave-fix
deliverables is more useful than a single mega-fix:

1.  **W146-FIX-A (1-line + comment):** Add a startup ERROR log
    when `-prune=N` is passed (BUG-2) explaining that pruning is
    silently a no-op until the flat-file storage is wired.  Keeps
    operator expectations honest.
2.  **W146-FIX-B (1-line):** Add a `MAX_BLOCK_SERIALIZED_SIZE`
    sanity check in `readBlockFromDisk` (BUG-11, BUG-17) to fix the
    memory-bomb hazard before any wire-up.
3.  **W146-FIX-C (~30 LOC):** Replace `IORef` cursor state in
    `BlockStore` with `MVar` + `bracket` discipline (BUG-12, BUG-13)
    so concurrent writers serialise.
4.  **W146-FIX-D (~30 LOC):** Add an `'R'` reindex-flag key
    (BUG-6) so a future `-reindex` can detect a partial write on
    startup.
5.  **W146-FIX-E (large):** Bring `BlockFileInfo` / `BlockIndex`
    into VARINT-encoded Core-compatible layout (BUG-3, BUG-4) and
    wire `writeBlockToDisk` / `readBlockFromDisk` into
    `putBlock` / `getBlock` (closes BUG-1).  Same wave should
    add `posix_fallocate` (BUG-14), `FlushBlockFile` on rotation
    (BUG-7, BUG-8), and rev*.dat undo-file output (BUG-10, BUG-15).
6.  **W146-FIX-F (cleanup):** Tighten exports of dead-code
    primitives (`writeBlockToDisk`, `readBlockFromDisk`,
    `revFilePath`) once they are wired, and delete the unused
    `LegacyUndoData` (Storage.hs:1376-1387) and dead enum branches
    that have accumulated.

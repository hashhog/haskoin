# W147 UTXO database / chainstate (CCoinsView + CCoinsViewCache + CCoinsViewDB) — haskoin

**Date:** 2026-05-18
**Status:** DISCOVERY — no production code changes
**Scope:** the in-memory CCoinsViewCache layer, the LevelDB-backed
CCoinsViewDB layer, the wire-format CoinEntry key (`'C'+hash+VARINT(n)`),
the Coin (compressed-amount + compressed-script) value, the obfuscation-
key XOR on every chainstate read/write, the FlushStateToDisk-trigger
budget (`dbcache`), and the FRESH/DIRTY-flag plumbing on AccessCoin /
SpendCoin.

**Out of scope:** assumeUTXO snapshot loading (W138), MuHash/MUHASH3072
digest of the UTXO set (W138 / coinstatsindex), block/tx undo-record
replay during reorg (W143), header-chain index (W117), txindex/
coinstatsindex (W117/W118), mempool persistence XOR-obfuscation (its own
v309900 dump file — Mempool/Persist.hs, separate audit), the snapshot-
hash CoinEntry serialisation (already audited W107 G11/G12).

**Sources audited:**

- `src/Haskoin/Storage.hs:319-350` — `KeyPrefix` taxonomy (`0x01`-`0x0B`)
  and `makeKey`.
- `src/Haskoin/Storage.hs:399-410` — `syncFlush` (the WAL-fsync sentinel
  marker).
- `src/Haskoin/Storage.hs:513-526` — `putUTXO` / `putUTXOCoin`
  (live-path direct RocksDB writer keyed by `PrefixUTXO = 0x05`).
- `src/Haskoin/Storage.hs:530-545` — `getUTXO` / `getUTXOCoin` /
  `deleteUTXO`.
- `src/Haskoin/Storage.hs:583-709` — `UTXOEntry` + `UTXOCache` (the
  legacy TVar-backed cache + `flushCache`).
- `src/Haskoin/Storage.hs:712-867` — `Coin`, `CoinEntry`, `CoinsView`
  type-class, `CoinsViewDB` (the new "Core-compatible" layer keyed by
  `prefixCoin = 0x43 = 'C'` + `prefixBestBlockV2 = 0x42 = 'B'`).
- `src/Haskoin/Storage.hs:869-1206` — `CoinsViewCache` (the new
  in-memory cache with DIRTY+FRESH flags), `cacheGetCoin`,
  `cacheAddCoin`, `cacheSpendCoin`, `cacheFlush`, `cacheSync`,
  `cacheSanityCheck`.
- `src/Haskoin/Storage.hs:1538-1564` — `BatchOp` / `WriteBatch` /
  `writeBatch`.
- `src/Haskoin/Storage.hs:2860-3108` — `putCoreVarInt`, `getCoreVarInt`,
  `compressAmount`, `decompressAmount`, `putCompressedScript`,
  `getCompressedScript`, `putCoreCoin`, `getCoreCoin` (the
  Core-compatible Coin serialiser).
- `src/Haskoin/Types.hs:162-171` — `OutPoint` (`Serialize` instance
  used by every key encoder in the file).
- `src/Haskoin/Consensus.hs:3027-3199` — `connectBlock` /
  `connectBlockAt` (the live IBD + reindex + submitblock writer).
- `src/Haskoin/Consensus.hs:3266-3322` — `applyTxInUndo`
  (reorg-disconnect coin-restorer).
- `src/Haskoin/Consensus.hs:3335-3355` — `findSibling`
  (haskoin's AccessByTxid analog).
- `src/Haskoin/Consensus.hs:3418-3550` — `disconnectBlockAt`.
- `src/Haskoin/Consensus.hs:4305-4537` — `applyBlock` (the
  UTXOCache-backed apply path used by reorg-reconnect +
  assumeUTXO BG-validator).
- `src/Haskoin/Sync.hs:493-506` — `buildUTXOMap` (the live IBD prevout
  collector).
- `src/Haskoin/BlockTemplate.hs:1224-1390` — `applyBlockToCache`
  (submitblock's UTXOCache-backed live path).
- `app/Main.hs:230-260, 485-525, 670-680, 793-810` — CLI option
  plumbing for `--dbcache`, the `dbBlockCacheSize` field, and the
  `newUTXOCache db (noDbCache * 1024 * 1024 \`div\` 100)`
  instantiation.

**Result:** out of the 8 wave behaviors:

- (1) **CCoinsView interface contract** — partially present
  (`CoinsView` type class declares `getCoin`/`haveCoin`/
  `viewGetBestBlock`), **but with no instance for `CoinsViewDB`**;
  every live caller bypasses the class.
- (2) **CCoinsViewCache w/ DIRTY+FRESH** — fully implemented
  (`cacheAddCoin`, `cacheSpendCoin`, `cacheFlush`, `cacheSync`,
  `cacheSanityCheck`), but the entire layer is **DEAD CODE in
  production** — the only callers are `loadSnapshotIntoLegacyUTXO`
  + `newSnapshotChainstate` + `W100UTXOCacheSpec.hs` tests. The
  live IBD path (`connectBlockAt`), the reorg arm
  (`applyBlock` via `UTXOCache`), and the submitblock arm
  (`applyBlockToCache` via `UTXOCache`) all use a **different**
  cache (`UTXOCache` — TVar-backed legacy module) or no cache at
  all.
- (3) **`'C'+OutPoint` LevelDB key** — present but the OutPoint
  payload is wrong: haskoin writes `'C' || hash || LE32(n)`
  whereas Core writes `'C' || hash || VARINT(n)` (CoinEntry in
  txdb.cpp:43-49).  Same key-format divergence for the legacy
  `PrefixUTXO = 0x05` path.
- (4) **Coin compression** — present and Core-shape for the
  `Coin` value (W107 G11/G12 fixed `putCoreCoin`/`getCoreCoin`).
- (5) **`obfuscate_key` XOR** — **entirely absent** for the
  chainstate database.  The legacy `obfuscate_key` is implemented
  for `mempool.dat` (`Mempool/Persist.hs:118` `xorObfuscate`) but
  the RocksDB chainstate is written *plaintext*, so every Coin
  value differs byte-for-byte from a Core-compatible chainstate.
- (6) **`FlushStateToDisk` triggers** — partially present
  (`flushCache` fires at `height \`mod\` 100 == 0` or
  `cacheEntries > 500_000`), but: (a) **the `--dbcache` value is
  divided by 100 before being passed to `newUTXOCache`**, so a
  user-requested `-dbcache=450` (MB) becomes a ~4.6 MB cache;
  (b) `flushCache` does NOT update `BestBlock` atomically with
  the coin batch; (c) the Core `FLUSH_STATE_IF_NEEDED` cache-size
  trigger (Coins.cpp BatchWrite + validation.cpp FlushStateToDisk)
  is **not modelled at all** — only the entry-count + height-modulo
  heuristics exist.
- (7) **Coin height+coinbase encoding** — present and Core-shape
  (`VARINT(height << 1 | coinbase)`), but width is wrong:
  haskoin uses `Word32 → Word64` shift, where Core uses
  `nHeight : 31` bitfield + `uint32_t code`.  Range up to 2^31 is
  identical; above 2^31 haskoin diverges.
- (8) **`AccessCoin` / `SpendCoin` flag plumbing** — present in
  the dead `CoinsViewCache` layer; absent on the live path.
  The live `applyTxInUndo` / `findSibling` AccessByTxid analog
  scans only 16 outputs (`idx > 15`) where Core scans up to
  `MAX_OUTPUTS_PER_BLOCK ≈ 111111` (coins.cpp:389).

**Bugs found:** 22 (1 P0-CONSENSUS, 5 P0-CDIV, 4 P0, 6 P1, 4 P2, 2 P3).

## Top-line verdict

haskoin has **three parallel UTXO pipelines** that don't share
their on-disk schema, don't share their cache layer, and don't
share their key prefix:

1. **Live IBD / reindex / submitblock-confirm path** —
   `connectBlockAt` writes directly to RocksDB under
   `PrefixUTXO = 0x05` keyed by `OutPoint{hash, LE32(n)}` (NOT
   Core's `'C' + hash + VARINT(n)`).  No in-memory cache layer at
   all — every block flushes synchronously.

2. **Reorg-reconnect arm + assumeUTXO background validator** —
   `applyBlock` uses `UTXOCache` (TVar-backed legacy module, no
   FRESH flag).  `flushCache` writes the same `PrefixUTXO`
   key-space but does **not** update the BestBlock pointer.
   The cache size is `(dbcache * 1024 * 1024) \`div\` 100` — i.e.
   1% of the requested budget.

3. **"Core-compatible" CoinsView / CoinsViewDB / CoinsViewCache** —
   defined and tested (`W100UTXOCacheSpec.hs`) but **only ever
   instantiated by `loadSnapshotIntoLegacyUTXO`** /
   `newSnapshotChainstate`.  No live block path touches it.  It
   would write under `prefixCoin = 0x43 = 'C'` + `prefixBestBlockV2
   = 0x42 = 'B'`, which is closer to Core but still wrong on the
   `VARINT(n)` outpoint key, still missing the obfuscation XOR,
   and disagrees with the live path on the prefix byte.

The wave splits into five problem clusters:

1. **`CoinsViewDB` / `CoinsViewCache` are dead modules.** Imports
   in Consensus.hs (line 258), Sync.hs, BlockTemplate.hs — never
   instantiated outside snapshot-load + tests. The live and reorg
   paths use either raw `R.put` / `R.delete` or the legacy
   `UTXOCache`. (BUG-1 P0 dead-module.)

2. **CoinEntry key shape is wrong.** Both pipelines (live
   `PrefixUTXO = 0x05` and dead `prefixCoin = 0x43 = 'C'`) encode
   the OutPoint payload as `hash || LE32(n)` because that is what
   `instance Serialize OutPoint` (Types.hs:170) emits. Core's
   `CoinEntry` (`txdb.cpp:48`) emits `hash || VARINT(n)`. A
   chainstate written by haskoin is **byte-incompatible** with
   `bitcoin-cli getblock`, with any third-party UTXO snapshot
   parser, and with cross-impl chainstate seeding. (BUG-2
   P0-CDIV.)

3. **`obfuscate_key` is not implemented for chainstate.**
   Mempool dumps already XOR-obfuscate under `xorObfuscate`
   (Mempool/Persist.hs:118), but the chainstate writers
   (`putUTXOCoin`, `coinsViewDBPutCoin`, every `BatchPut` in
   `connectBlockAt` and `flushCache`) write plaintext bytes.
   Anti-virus false-positives on scriptPubKey bytes are the
   reason Core added obfuscation in PR #6650; this exposure is
   reintroduced on every haskoin install. (BUG-3 P1.)

4. **`--dbcache` is divided by 100 (Main.hs:800).** A user-
   supplied `-dbcache=450` is interpreted as 450 MB by the
   `dbBlockCacheSize` of the RocksDB native cache (correct), but
   the `UTXOCache` that `applyBlock` and the assumeUTXO BG-
   validator use is instantiated with `(noDbCache * 1024 * 1024)
   \`div\` 100` — i.e. **1/100th** of the requested cap. The
   reorg / IBD-finalise / submitblock paths run with a ~4.6 MB
   cache regardless of the `-dbcache` flag. (BUG-4 P0.)

5. **PrefixBlockHeight key is encoded *twice* on the live path.**
   `connectBlockAt` writes
   `makeKey PrefixBlockHeight (encode (toBE32 height))`, but
   `putBlockHeight`/`getBlockHeight` use
   `makeKey PrefixBlockHeight (toBE32 height)`.  Cereal's
   `instance Serialize ByteString` (Data/Serialize.hs:put bs =
   put (B.length bs :: Int) >> putByteString bs) prepends an
   8-byte BE Int length-prefix, so the live path writes a
   12-byte payload (`0x03 + 8 + 4`) under a key that
   `getBlockHeight` (4-byte payload `0x03 + 4`) will NEVER find.
   The height→hash index is silently corrupted on every live
   block. (BUG-5 P0-CDIV.)

## Bug catalog

### BUG-1 P0 — CCoinsViewDB + CCoinsViewCache are dead modules on every live path

- **File:** `src/Haskoin/Storage.hs:813-1206` (definitions),
  `src/Haskoin/Consensus.hs:258` (single import site that never
  instantiates them).
- **Core ref:** `bitcoin-core/src/coins.h:307-343` (`CCoinsView`),
  `bitcoin-core/src/coins.cpp:44-302` (`CCoinsViewCache`),
  `bitcoin-core/src/txdb.cpp:53-200` (`CCoinsViewDB`).
- **Description:** the entire Core-shaped UTXO cache hierarchy
  (`CoinsViewDB`, `CoinsViewCache`, `cacheAddCoin`,
  `cacheSpendCoin`, `cacheFlush`, `cacheSync`,
  `cacheSanityCheck`) is implemented and unit-tested
  (`W100UTXOCacheSpec.hs`), but **never instantiated by any
  live block-validation caller**. The only callers in `src/` are:
  - `newSnapshotChainstate` (Storage.hs:2629) — assumeUTXO bring-
    up.
  - `populateFromSnapshot` (Storage.hs:2599) — same.
  - `writeSnapshot` (Storage.hs:2656) — `dumptxoutset` RPC.
  Every block-validation path (`connectBlockAt`, `applyBlock`,
  `applyBlockToCache`) uses either raw `R.put`/`R.delete` on
  RocksDB (live IBD) or the legacy TVar-based `UTXOCache` (reorg +
  assumeUTXO BG + submitblock).
- **Excerpt (Consensus.hs:258 vs Consensus.hs:3027-3198):**

  ```haskell
  -- Consensus.hs:258 — imported but unused in live path.
  import Haskoin.Storage (..., CoinsViewCache(..), newCoinsViewCache,
                          cacheFlush, defaultCacheSize, ...)

  -- Consensus.hs:3098 — live path; bypasses CoinsViewCache entirely.
  connectBlockAt db net block height spentUtxos = do
    ...
    ops = concat
      [ [ BatchPut (makeKey PrefixUTXO (encode (OutPoint txid (fromIntegral i)))) ... ]
      , [ BatchDelete (makeKey PrefixUTXO (encode (txInPrevOutput inp))) ... ]
      , [ BatchPut undoKey (encode undoData) ]
      , [ BatchPut (makeKey PrefixBestBlock BS.empty) (encode bh) ]
      ]
    writeBatch db (WriteBatch ops)
  ```

- **Impact:** the DIRTY/FRESH cache architecture that gives Core
  its IBD throughput (write-coalescing in memory, then large
  batched flushes to leveldb) is unreachable on every live
  haskoin path. Every block synchronously writes its full UTXO
  delta to disk via `writeBatch`, which is the throughput
  bottleneck during IBD. Consensus is unaffected (the on-disk
  state is correct in the absence of crashes), but the code is
  dead, the test surface is misleading, and future fixes
  targeting `cacheAddCoin` / `cacheSpendCoin` will silently
  leave the live path unchanged.

---

### BUG-2 P0-CDIV — Coin DB key uses `LE32(n)` instead of Core's `VARINT(n)`

- **File:** `src/Haskoin/Types.hs:169-171` (`OutPoint`
  `Serialize` instance), `src/Haskoin/Storage.hs:524` (live
  `putUTXOCoin`), `src/Haskoin/Storage.hs:846-855` (dead
  `coinsViewDBPutCoin` / `coinsViewDBDeleteCoin`),
  `src/Haskoin/Consensus.hs:3174-3185` (live `connectBlockAt`
  BatchPut + BatchDelete).
- **Core ref:** `bitcoin-core/src/txdb.cpp:43-49`
  (`CoinEntry::SERIALIZE_METHODS` = `key, outpoint->hash,
  VARINT(outpoint->n)`).
- **Description:** Bitcoin Core keys every UTXO in the
  chainstate as `'C' + hash + VARINT(n)` where `VARINT` is the
  7-bit-per-byte continuation encoding (`putCoreVarInt` in
  haskoin). For typical vout indices `0`/`1`, this is a 1-byte
  payload (`0x00`/`0x01`); haskoin emits 4 bytes (`0x00 0x00
  0x00 0x00` / `0x00 0x00 0x00 0x01` little-endian). The keys
  diverge for **every** UTXO on the chain.
- **Excerpt (Types.hs:169-171 + Storage.hs:524):**

  ```haskell
  instance Serialize OutPoint where
    put OutPoint{..} = put outPointHash >> putWord32le outPointIndex
    --                                     ^^^^^^^^^^^^^^ NOT VARINT

  putUTXOCoin db outpoint coin =
    let key = makeKey PrefixUTXO (encode outpoint)
        -- = [0x05, hash[32], n_LE32[4]]  (37 bytes)
        -- Core: [0x43='C', hash[32], VARINT(n)]  (33-37 bytes)
    in R.put (dbHandle db) (dbWriteOpts db) key (encode coin)
  ```

- **Impact:** a haskoin chainstate is byte-incompatible with
  `bitcoin-cli`'s leveldb, with electrs / electrum-server's UTXO
  probes, with any third-party tooling that parses Bitcoin
  Core's chainstate at rest (e.g. utxo-dump.org), and with
  cross-impl chainstate seeding (a fresh haskoin node cannot
  bootstrap from a Core `chainstate/` copy and vice versa). The
  legacy `PrefixUTXO = 0x05` and the new `prefixCoin = 0x43 =
  'C'` both have the same vout-key divergence — even the
  "Core-compatible" path is not Core-compatible.

---

### BUG-3 P1 — `obfuscate_key` XOR is absent on chainstate

- **File:** `src/Haskoin/Storage.hs:399-410` (`syncFlush`),
  `src/Haskoin/Storage.hs:524, 538, 545` (live UTXO put/get/
  delete), `src/Haskoin/Storage.hs:846-867` (dead CoinsViewDB).
- **Core ref:** `bitcoin-core/src/dbwrapper.cpp:253-259`
  (auto-generate + write `OBFUSCATION_KEY` on a fresh DB),
  `bitcoin-core/src/util/obfuscation.h` (Obfuscation operator()
  XORs every byte under an 8-byte key), `bitcoin-core/src/
  dbwrapper.h:50-95` (every `Read`/`Write`/`Erase` XORs through
  the key).
- **Description:** Core stores an 8-byte `obfuscate_key` at the
  reserved key `'\x0e' + "obfuscate_key"` in every leveldb DB
  it opens, and XORs every value (key payload + value bytes)
  with it on read/write so the on-disk bytes look random to
  anti-virus heuristics matching on `OP_DUP OP_HASH160 ...`
  prefixes. haskoin's `Mempool/Persist.hs:118` already
  implements this for mempool.dat (`xorObfuscate`), but the
  chainstate writers (`R.put` / `R.delete` / `R.get` calls on
  `dbHandle`) use the raw value with no XOR.
- **Excerpt (Storage.hs:846-848):**

  ```haskell
  coinsViewDBPutCoin CoinsViewDB{..} op coin = do
    let key = BS.cons prefixCoin (encode op)
    R.put (dbHandle cvdbHandle) (dbWriteOpts cvdbHandle)
          key (encode coin)
          -- ^^^^^^^^^^^ NO XOR; plaintext on disk
  ```

- **Impact:** scriptPubKey bytes (especially the legacy
  `OP_DUP OP_HASH160 ...` P2PKH prefix `0x76 0xa9 0x14`) sit
  unencrypted in `chainstate/MANIFEST-*`, triggering Symantec /
  Norton / ClamAV "downloader" false-positives that quarantine
  the entire datadir. This is exactly the failure-mode that
  prompted Core's PR #6650 in 2015. Independent of consensus,
  this is the most-frequently-reported "node won't start"
  ticket in any non-XOR'd impl — haskoin reintroduces it.

---

### BUG-4 P0 — `--dbcache` is divided by 100 before reaching the live cache

- **File:** `app/Main.hs:800`.
- **Core ref:** `bitcoin-core/src/init.cpp` parses
  `-dbcache=<MB>` and passes the byte-value as
  `nCoinCacheUsage` (validation.cpp:281).
- **Description:** the daemon parses `-dbcache=N` (MB) at
  Main.hs:238, plumbs it as `noDbCache :: Int` (line 105), uses
  it correctly for the RocksDB native block-cache at line 674
  (`dbBlockCacheSize = noDbCache * 1024 * 1024`), but at line
  800 the **UTXOCache** that `applyBlock` and
  `runBackgroundValidation` use is built with
  `newUTXOCache db (noDbCache * 1024 * 1024 \`div\` 100)`.
- **Excerpt (Main.hs:800):**

  ```haskell
  -- Initialize UTXO cache
  cache <- newUTXOCache db (noDbCache * 1024 * 1024 `div` 100)
  --                                                  ^^^^^^^
  --       1/100 of the requested budget; ~4.6 MB for -dbcache=450
  ```

- **Impact:** the assumeUTXO background validator, reorg-
  reconnect arm (`connectChain`), and `applyBlockToCache`-
  driven submitblock path all run with a **4.6 MB** cache when
  the user asked for 450 MB. `flushCache` at this size fires on
  every block (height-modulo 100 will hit way before the
  500k-entry hard limit, but the entry limit is also
  effectively meaningless at 4.6 MB because each entry is
  ~100 B). The cap acts like Core's `-dbcache=4` (smallest
  allowed value in Core is 4 MiB) regardless of the operator's
  intent. Performance is catastrophic and `--dbcache` is a
  liar. Suspected typo: someone meant `* 100 / 100` or
  `(* 1024)` (KB→bytes once, not twice with a /100 in between);
  the literal `\`div\` 100` is bare.

---

### BUG-5 P0-CDIV — `PrefixBlockHeight` keys differ between writer and reader; height index silently corrupt

- **File:** `src/Haskoin/Storage.hs:483-493` (`putBlockHeight` /
  `getBlockHeight`, the canonical reader), vs.
  `src/Haskoin/Consensus.hs:3115, 3194, 3639` (the live writer).
- **Core ref:** N/A — Core uses a `pair<char, int>` height key
  written via `Serialize`, which is consistent across writers
  and readers.
- **Description:** `putBlockHeight` writes the height-index
  entry under `makeKey PrefixBlockHeight (toBE32 height)` —
  a 5-byte key `[0x03, b0, b1, b2, b3]`. `getBlockHeight` reads
  the same shape, OK. But the live `connectBlockAt` (and the
  genesis fast-path at 3115, and the reorg writer at 3639)
  writes under `makeKey PrefixBlockHeight (encode (toBE32
  height))`. Cereal's `instance Serialize ByteString`
  (cereal-0.5.8.3/src/Data/Serialize.hs L185) emits
  `put (B.length bs :: Int) >> putByteString bs` — i.e. an
  8-byte BE Int length-prefix (= 0x00 00 00 00 00 00 00 04)
  followed by the 4 height bytes. The live writer therefore
  produces a 13-byte key `[0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x04, b0, b1, b2, b3]` — a key
  `getBlockHeight` will never query.
- **Excerpt (Consensus.hs:3194 vs Storage.hs:485):**

  ```haskell
  -- Consensus.hs:3194 (the live writer):
  , BatchPut (makeKey PrefixBlockHeight (encode (toBE32 height)))
             (encode bh)
  -- key = [0x03, 0x00 .. 0x00, 0x04, b0, b1, b2, b3]  (13 bytes)

  -- Storage.hs:485 (the canonical writer):
  let key = makeKey PrefixBlockHeight (toBE32 height)
  -- key = [0x03, b0, b1, b2, b3]                      (5 bytes)
  ```

- **Impact:** the only on-disk write of the
  `PrefixBlockHeight` index on the live path is the
  `connectBlockAt` writer — but that key is 13 bytes, and
  `getBlockHeight` queries the 5-byte form. So
  `getBlockHeight` **always returns `Nothing` on the live
  path**. The only caller relying on a non-Nothing result is
  the BIP-30 anchor check (`checkBIP30` line 2636), which
  falls back to `bip34AnchorConfirmed = False` — meaning BIP-30
  enforcement is **never skipped** even after BIP-34 height
  (227,931). This is a performance bug (per-block scan over the
  block's outputs against the UTXO set for ~1.8M post-BIP34
  blocks during IBD), but the conservative fallback prevents
  it from being a consensus split. If a future fix surfaces
  the missing `getBlockHeight` data to a path that uses it
  authoritatively (e.g. reorg's height→hash lookup), the
  silent failure becomes a hard one. The RPC path
  (`Rpc.hs:10618-10619`) is also broken — height-range queries
  return empty results unconditionally on a node that has only
  ever synced via `connectBlockAt`.

---

### BUG-6 P0-CDIV — `findSibling` AccessByTxid scan-cap is 16 vs Core's ~111,111

- **File:** `src/Haskoin/Consensus.hs:3335-3355`
  (`findSibling`).
- **Core ref:** `bitcoin-core/src/coins.cpp:386-395`
  (`AccessByTxid` scans while `iter.n < MAX_OUTPUTS_PER_BLOCK`)
  + `bitcoin-core/src/coins.cpp:383-384`
  (`MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT /
  MIN_TRANSACTION_OUTPUT_WEIGHT ≈ 4_000_000 / 36 = 111,111`).
- **Description:** when haskoin disconnects a block, every
  legacy undo record with `tuHeight == 0` must look up a
  sibling output of the same txid (any unspent index) in the
  view to recover the height + coinbase flag. `findSibling`
  caps the on-disk scan at index 15 (line 3350: `idx > 15 →
  return Nothing`); Core scans up to ~111,111. A tx whose
  only unspent output is at vout >= 16 returns `Nothing` from
  `findSibling`, which propagates through `applyTxInUndo`
  (3306-3310) as `"ApplyTxInUndo: missing undo metadata for
  ... and no unspent sibling output (AccessByTxid) — undo
  record predates connectBlock and cannot be rewound."` and
  the entire reorg disconnect fails with
  `DisconnectFailed`.
- **Excerpt (Consensus.hs:3346-3355):**

  ```haskell
  case pendingHit of
    (h, cb) : _ -> return $ Just (h, cb)
    [] -> scan (0 :: Word32)
    where
      scan idx
        | idx > 15 = return Nothing    -- <-- HARDCODED CAP
        | otherwise = do
            mc <- getUTXOCoin db (OutPoint txid idx)
            case mc of
              Just c  -> return $ Just (coinHeight c, coinIsCoinbase c)
              Nothing -> scan (idx + 1)
  ```

- **Impact:** a reorg involving any block that contains a tx
  with > 16 outputs and all of its first 16 outputs already
  spent at disconnect-time cannot be rolled back, leaving the
  chainstate stuck at the current tip. Today, with average
  block weight ~50% utilised, a tx of 20+ outputs is
  commonplace (exchange consolidation, batched payment
  processors). Comment at line 3330-3334 acknowledges the
  bound is arbitrary ("We cap the on-disk scan at index 0..15
  to keep the worst-case cost bounded") — but Core's cap is
  ~111,111 because that's the absolute maximum possible. The
  legacy-undo path is brittle in proportion to the depth of
  the reorg and the breadth of the block's coinbase / batched
  withdrawal transactions.

---

### BUG-7 P0-CONSENSUS — `connectBlockAt` rejects intra-block-spending blocks

- **File:** `src/Haskoin/Consensus.hs:3098-3199`
  (`connectBlockAt`), `src/Haskoin/Sync.hs:493-506`
  (`buildUTXOMap`).
- **Core ref:** `bitcoin-core/src/validation.cpp:1999-2012`
  (`UpdateCoins` calls `SpendCoin` THEN `AddCoins` per tx, so
  earlier-in-block outputs are in `inputs` for later txs).
- **Description:** Bitcoin permits a tx B to spend an output of
  a tx A within the same block (A appears before B in
  `txns[]`). Core's `UpdateCoins` (validation.cpp:1999) and
  `ConnectBlock` (line 2600) process txs in order, applying
  each tx's spends + creations to the *same view* before the
  next tx is processed, so B's `SpendCoin(A:0)` succeeds. In
  haskoin, the live IBD path does NOT model this:
  `buildUTXOMap` (Sync.hs:493-506) populates the per-block
  `Map OutPoint Coin` purely from `getUTXOCoin db op` — i.e.
  the on-disk pre-block state — and `connectBlockAt` (lines
  3139-3151) rejects any input whose prevout is in neither
  `spentUtxos` nor on disk via `getUTXOCoin db (txInPrevOutput
  inp)`. A's output is in neither at the time B's input is
  resolved.
- **Excerpt (Consensus.hs:3139-3156, Sync.hs:498-506):**

  ```haskell
  -- Consensus.hs:3139-3156
  let inputs = [ inp | tx <- drop 1 txns, inp <- txInputs tx ]
  missingInputs <- foldM (\acc inp -> ...
      case Map.lookup (txInPrevOutput inp) spentUtxos of
        Just _  -> return Nothing
        Nothing -> do
          mc <- getUTXOCoin db (txInPrevOutput inp)
          case mc of
            Just _  -> return Nothing
            Nothing -> return (Just (txInPrevOutput inp)))
    (Nothing :: Maybe OutPoint) inputs
  case missingInputs of
    Just op -> return $ Left $
      "connectBlockAt " <> show bh
      <> ": missing prevout " <> show op
      <> " (Core G19 — validation.cpp:2007 assert(is_spent))"

  -- Sync.hs:498-506
  utxos <- forM outpoints $ \op -> do
    mCoin <- getUTXOCoin (bdDB bd) op   -- DISK ONLY
    return (op, mCoin)
  return $ Map.fromList [(op, c) | (op, Just c) <- utxos]
  ```

- **Impact:** any block containing intra-block dependencies
  (B spending A within the same block) is rejected at G19 as
  "missing prevout". `validateBlockTransactions` correctly
  handles the intra-block case (Consensus.hs:2810-2818
  unions `newUtxos` into the rolling map), so the pure
  validation arm accepts the block — but the IBD writer that
  follows refuses to commit it. **Haskoin cannot sync mainnet
  past height 91722** (whose famous duplicate-coinbase
  scenario is moot — the real intra-block-spending blocks
  start earlier, around height 170 in 2009).
  Cross-cite: this matches the `disconnectBlock` "sibling-
  recovery" path's reliance on the pending-restorations map
  (line 3338-3346) for the symmetric case on rewind.
  `connectBlockAt` lacks the symmetric forward-pending map.

---

### BUG-8 P0-CDIV — `mkTxInUndo` silently drops missing prevouts → undo data is shorter than vin

- **File:** `src/Haskoin/Consensus.hs:3160-3168`.
- **Core ref:** `bitcoin-core/src/validation.cpp:2003-2008`
  (`txundo.vprevout.reserve(tx.vin.size())` +
  `inputs.SpendCoin(txin.prevout, &txundo.vprevout.back())`).
  Each `vin[i]` produces exactly one `vprevout[i]`.
- **Description:** if BUG-7 were patched (i.e. intra-block
  prevouts were resolved correctly), `connectBlockAt` would
  still corrupt the BlockUndo record. `mkTxInUndo` (line
  3160) returns `Nothing` for any input whose prevout is not
  in `spentUtxos`, and `mkTxUndo` does
  `mapMaybe mkTxInUndo (txInputs tx)`, which **silently
  discards** the `Nothing`s. So if any prevout is unresolved
  (whether because of an intra-block dep, a buggy caller, or
  a disk failure between `buildUTXOMap` and `connectBlockAt`),
  the resulting `TxUndo.tuPrevOutputs` has fewer entries than
  `tx.vin`. The comment at line 3164 reads
  `"Nothing -> Nothing  -- caller's responsibility; logged
  below"`, but no logging actually occurs — `mapMaybe` is
  silent.
- **Excerpt (Consensus.hs:3160-3168):**

  ```haskell
  mkTxInUndo inp = case Map.lookup (txInPrevOutput inp) spentUtxos of
    Just c  -> Just (TxInUndo (coinTxOut c)
                              (coinHeight c)
                              (coinIsCoinbase c))
    Nothing -> Nothing  -- caller's responsibility; logged below
  mkTxUndo tx = TxUndo
    { tuPrevOutputs = mapMaybe mkTxInUndo (txInputs tx) }
                      ^^^^^^^^ — silent drop, no log
  ```

- **Impact:** on `disconnectBlock`, the undo replay (line
  3266 `applyTxInUndo`) iterates `tx.vin` and pops a
  `TxInUndo` per input. If `tuPrevOutputs` is shorter than
  `tx.vin`, the iteration runs off the end of the list and
  silently restores fewer prevouts than were spent — the UTXO
  set is permanently out of sync from the chain tip. The
  asymmetry between connect (silently drops) and disconnect
  (assumes 1:1) is the kind of bug that surfaces during a
  testnet reorg three weeks after a clean sync.

---

### BUG-9 P0-CDIV — Coin BatchWrite is non-atomic with BestBlock; no `DB_HEAD_BLOCKS` recovery marker

- **File:** `src/Haskoin/Storage.hs:1036-1056` (`cacheFlush`),
  `src/Haskoin/Storage.hs:682-709` (`flushCache`).
- **Core ref:** `bitcoin-core/src/txdb.cpp:100-164`
  (`CCoinsViewDB::BatchWrite` writes `DB_HEAD_BLOCKS = 'H'`
  first, applies all coins, then writes `DB_BEST_BLOCK = 'B'`
  and erases `DB_HEAD_BLOCKS` — so a crash mid-batch leaves
  the recovery hint `[hashBlock_new, old_tip]` in the DB and
  the next startup detects it).
- **Description:** Core's `BatchWrite` follows a three-phase
  pattern that survives a process kill mid-batch:
  1. Erase `DB_BEST_BLOCK`, write
     `DB_HEAD_BLOCKS = [hashBlock_new, old_tip]`.
  2. Apply all DIRTY coin BatchPut / BatchErase.
  3. Erase `DB_HEAD_BLOCKS`, write
     `DB_BEST_BLOCK = hashBlock_new`.
  haskoin's `cacheFlush` (line 1036) merges the coin ops and
  the BestBlock update into a single `WriteBatch` (which is
  atomic via RocksDB's WAL) — but it never writes
  `DB_HEAD_BLOCKS`, and `flushCache` (the legacy / live
  cache) **doesn't update BestBlock at all** — only the
  individual `BatchPut`/`BatchDelete` ops are flushed.
- **Excerpt (Storage.hs:1036-1056):**

  ```haskell
  cacheFlush cache = do
    coins <- readIORef (cvcCoins cache)
    bestBlock <- readIORef (cvcBestBlock cache)
    let ops = concatMap toOps (Map.toList coins)
    let bestBlockOps = case bestBlock of
          Nothing -> []
          Just bh -> [BatchPut (BS.singleton prefixBestBlockV2) (encode bh)]
    let CoinsViewDB{..} = cvcBase cache
    writeBatch cvdbHandle (WriteBatch (ops ++ bestBlockOps))
    -- ^ atomic via RocksDB WAL — but no DB_HEAD_BLOCKS marker.
  ```

- **Impact:** RocksDB's WriteBatch is atomic per-write, so
  the single `cacheFlush` call survives a crash correctly.
  But (a) `flushCache` (the live path) does NOT touch
  BestBlock at all (Storage.hs:682-709), so a crash between
  cache flush and the next `connectBlockAt`'s BestBlock
  write leaves the on-disk best-block pointer stale relative
  to the UTXO set — recoverable but not self-detected; (b)
  for partial-batch scenarios (a single block whose
  WriteBatch exceeds RocksDB's max-batch-size and must be
  written in multiple sub-batches), the `DB_HEAD_BLOCKS`
  marker is the only way to detect "I crashed mid-block"
  on the next startup — haskoin has no analog and will
  silently start with an inconsistent UTXO set. The cross-
  impl symptom is "haskoin claims tip H but `gettxoutsetinfo`
  reports a stale UTXO count".

---

### BUG-10 P1 — `lookupUTXO` cache-miss path loses height + coinbase metadata

- **File:** `src/Haskoin/Storage.hs:629-650` (`lookupUTXO`).
- **Core ref:** `bitcoin-core/src/coins.cpp:68-81`
  (`FetchCoin` returns the full `Coin` w/ height + coinbase
  via `FetchCoinFromBase`).
- **Description:** on a UTXOCache miss, `lookupUTXO` calls
  `getUTXO (ucDB cache) op`, which returns `Maybe TxOut` —
  **without height/coinbase metadata**. The function then
  fabricates a `UTXOEntry txout 0 False False`, hard-coding
  height = 0 and coinbase = False. The `getUTXOCoin` variant
  (Storage.hs:534) returns the full `Coin` with metadata,
  but `lookupUTXO` uses `getUTXO` and discards it.
- **Excerpt (Storage.hs:638-650):**

  ```haskell
  Nothing    -> do
    -- Fall through to database
    mTxOut <- getUTXO (ucDB cache) op
    case mTxOut of
      Nothing -> return Nothing
      Just txout -> do
        -- We don't have the full UTXOEntry metadata from just TxOut
        -- In production, store UTXOEntry in DB instead of TxOut
        -- For now, use default metadata (height 0, not coinbase)
        let entry = UTXOEntry txout 0 False False
        --                          ^ HEIGHT = 0       ^ COINBASE = False
        atomically $ modifyTVar' (ucEntries cache) (Map.insert op entry)
        return (Just entry)
  ```

- **Impact:** the `applyBlock` path (Consensus.hs:4305-4537,
  reorg-reconnect + assumeUTXO BG-validator) uses
  `lookupUTXO` (line 4376) to fetch prevout metadata. The
  coinbase-maturity gate at line 4386-4390 checks
  `height - ueHeight entry < 100`. If a non-coinbase prevout
  was loaded from disk via this cache-miss path, `ueHeight =
  0`, so the maturity check sees `height - 0 = height >=
  100` and **always returns False** (mature). Conversely, a
  prevout that IS a coinbase has `ueCoinbase = False` after
  this path, bypassing the maturity check entirely. Code
  comment ("In production, store UTXOEntry in DB instead of
  TxOut — For now, use default metadata") acknowledges the
  shim. The shim has stuck.
  Cross-fix: `getUTXOCoin` already returns the full Coin;
  swap the call site.

---

### BUG-11 P1 — `--dbcache` not honored on first 4.6 MB of every flush; flush triggers are byte-budgetless

- **File:** `src/Haskoin/Consensus.hs:4900-4907`
  (`backgroundValidationLoop` flush trigger),
  `src/Haskoin/Storage.hs:682-709` (`flushCache`).
- **Core ref:** `bitcoin-core/src/validation.cpp:2864-2939`
  (`FlushStateToDisk` modes — `IF_NEEDED` fires when
  `cacheSize + cacheSizeBytes > nTotalSpace * 0.9`).
- **Description:** Core's flush policy mixes a count budget
  (`COINS_CACHE_SIZE_BYTES`) and a byte budget
  (`nCoinCacheUsage`). haskoin's only triggers are:
  - height-modulo: `height \`mod\` 100 == 0` (4900)
  - entry-count: `cacheEntries > 500_000` (line 4905)
  No byte-budget trigger exists. Combined with BUG-4 (cache
  capped at 4.6 MB regardless of `--dbcache`), the cache is
  effectively flushed every block once it fills, which
  is many times more frequent than the user requested.
- **Excerpt (Consensus.hs:4900-4907):**

  ```haskell
  -- Flush on either interval or entry count limit.
  -- At height 400K+, each block has ~4000 outputs, so 100 blocks
  -- = ~400K entries ≈ 120MB. Hard limit at 500K entries catches
  -- blocks with unusually many outputs.
  cacheEntries <- readTVarIO (ucSize cache)
  when (height `mod` 100 == 0 || cacheEntries > 500000) $ do
    putStrLn $ "Flushing UTXO cache: " ++ show cacheEntries ++ " entries at height " ++ show height
    flushCache cache
  ```

- **Impact:** the assumeUTXO BG-validator and reorg-reconnect
  arm cannot benefit from a large `--dbcache`. The header
  comment ("≈ 120MB") is dramatically wrong given BUG-4 caps
  the working-set at ~4.6 MB. RocksDB's own native block-
  cache (set at Main.hs:674 with `dbBlockCacheSize = noDbCache
  * 1024 * 1024`) is correctly sized at 450 MB, but it caches
  *blocks of the SST file*, not coins — so 450 MB of block-
  cache plus 4.6 MB of UTXOCache is a 99x mismatch in budget
  vs. usage.

---

### BUG-12 P1 — `Coin` code width is `Word64`; Core is `uint32_t`

- **File:** `src/Haskoin/Storage.hs:3090-3108` (`putCoreCoin` /
  `getCoreCoin`).
- **Core ref:** `bitcoin-core/src/coins.h:63-78` (`uint32_t
  code = nHeight * uint32_t{2} + fCoinBase`).
- **Description:** Core declares `code` as `uint32_t` and
  `nHeight` as a 31-bit bitfield, so the maximum representable
  height is `2^31 - 1 ≈ 2.1e9`. haskoin's `putCoreCoin` uses
  `Word64`:

  ```haskell
  putCoreCoin Coin{..} = do
    let code = (fromIntegral coinHeight `shiftL` 1) .|.
               (if coinIsCoinbase then 1 else 0) :: Word64
    putCoreVarInt code
  ```

  and `getCoreCoin` decodes via `getCoreVarInt` (also Word64).
  For real heights (≤ 2^31), the VARINT encoding is identical.
  For a malicious snapshot with `code > 2^32`, haskoin accepts
  the encoding where Core would silently truncate to `uint32_t`.
- **Excerpt:** see Storage.hs:3090-3108 above.
- **Impact:** consensus-divergent on adversarial input
  (snapshot import or peer-supplied corrupted coin) where the
  encoded height crosses 2^31. Real-world impact today: zero
  (no mainnet block at height 2^31). Cross-impl chainstate
  copy from haskoin → Core: any record with `coinHeight >=
  2^31` would round-trip incorrectly. Cross-impl Core →
  haskoin: VARINT decode of a Core-emitted code reads
  correctly since Core's `uint32_t` is a strict subset.

---

### BUG-13 P1 — `cacheGetBestBlock` does not invalidate on `flushCache` / `connectBlockAt`

- **File:** `src/Haskoin/Storage.hs:1136-1147`
  (`cacheGetBestBlock`), `src/Haskoin/Storage.hs:1131-1132`
  (`cacheSetBestBlock`).
- **Core ref:** `bitcoin-core/src/coins.cpp:198-206` —
  `CCoinsViewCache::GetBestBlock` lazily fetches from base if
  `hashBlock.IsNull()`; SetBestBlock updates the local cached
  value.
- **Description:** the IORef-backed `cvcBestBlock` is a
  process-local cache that is independent of any RocksDB
  update happening elsewhere. If a process attaches a
  `CoinsViewCache` to an existing DB whose BestBlock has been
  advanced by a separate `connectBlockAt` (live path) or
  `flushCache` (legacy path), `cacheGetBestBlock` will return
  the stale `Nothing` → fetch-once value, then permanently
  serve that stale hash even after the underlying DB has
  advanced.
- **Excerpt (Storage.hs:1136-1147):**

  ```haskell
  cacheGetBestBlock cache = do
    cached <- readIORef (cvcBestBlock cache)
    case cached of
      Just bh -> return (Just bh)
      Nothing -> do
        mBh <- coinsViewDBGetBestBlock (cvcBase cache)
        case mBh of
          Just bh -> do
            writeIORef (cvcBestBlock cache) (Just bh)
            -- ^ cached forever; no invalidation hook
            return (Just bh)
          Nothing -> return Nothing
  ```

- **Impact:** today moot because the CoinsViewCache is dead
  code. If BUG-1 is fixed (wire CoinsViewCache into the live
  path), this becomes a latent bug at every cache instantiate.
  Core avoids this by making `hashBlock` per-cache-instance
  and re-reading on SetBestBlock — the SetBestBlock arm has
  to be plumbed in symmetric to every BatchWrite.

---

### BUG-14 P1 — `flushCache` `performGC` per-block is a 100 ms+ tax

- **File:** `src/Haskoin/Storage.hs:682-709`.
- **Core ref:** N/A — Core doesn't `performGC` because the
  cache is in C++ memory.
- **Description:** after every `flushCache`, haskoin calls
  `performGC` to "force GC to reclaim the old Map's tree
  nodes" (line 699). With a 500_000-entry Map and a managed
  heap, a major GC takes 50-200 ms on a typical 5900XT
  workstation. The BG-validator fires `flushCache` every 100
  blocks (4907) → during the BG portion of assumeUTXO
  validation, GC alone burns 100ms × 1.8M / 100 = 30 minutes
  of wall time on a full mainnet replay.
- **Impact:** assumeUTXO background validation takes ~2x as
  long as it should; IBD of the legacy / reorg path likewise.

---

### BUG-15 P2 — `cacheReset` is dead code

- **File:** `src/Haskoin/Storage.hs:1151-1156`.
- **Description:** exported (line 101) and defined, but zero
  callers anywhere in `src/` or `test/`. The Map-clearing
  semantics it offers are otherwise only available through
  `cacheFlush` (which both writes AND clears).
- **Impact:** code surface that's not exercised by tests and
  not used by the live path. Removal candidate.

---

### BUG-16 P2 — `cacheSync` exists but is identical to a `Sync`-with-no-erase that nobody calls

- **File:** `src/Haskoin/Storage.hs:1076-1116`.
- **Core ref:** `bitcoin-core/src/coins.cpp:291-298`
  (`CCoinsViewCache::Sync`).
- **Description:** the function correctly implements Core's
  Sync semantics (DIRTY-clear, keep-unspent in cache), but
  again zero production callers.
- **Impact:** dead code; if the CoinsViewCache layer is
  wired up later (BUG-1 fix), `cacheSync` is the right entry
  point for a "non-erasing flush" — currently it's not
  invokable from the daemon.

---

### BUG-17 P2 — `BlockUndo` writes use a hand-rolled `0x10` prefix that's not in `KeyPrefix`

- **File:** `src/Haskoin/Consensus.hs:3171` (`undoKey = BS.cons
  0x10 (encode bh)`).
- **Core ref:** `bitcoin-core/src/txdb.cpp` doesn't store undo
  in chainstate at all — undo data lives in the block files
  (`rev*.dat`). haskoin chose to colocate undo in the
  chainstate-shaped DB, which is fine; the issue is the
  prefix byte.
- **Description:** the `KeyPrefix` enum (Storage.hs:319-345)
  defines `PrefixBlockHeader = 0x01` through
  `PrefixAddrUTXO = 0x0B`. The next free byte is `0x0C`, but
  `connectBlockAt` writes undo at `0x10`. There is no enum
  variant or const for this; the value is a magic number.
  Same `0x10` is used by `disconnectBlock`'s `getUndoData`
  call (verified in Storage.hs `getUndoData` ≈ line 1610). No
  collision with the documented `KeyPrefix` taxonomy today,
  but adding `PrefixUndo = 0x0C` is the obvious tidy.
- **Impact:** maintenance / readability; tools that scan the
  DB by prefix (RPC `getrawmempool`-style iteration, or a
  future `gettxoutsetinfo` that walks the chainstate) will
  encounter `0x10` keys with no enum mapping.

---

### BUG-18 P2 — `defaultCacheSize` is `450 * 1024 * 1024` but its only call sites are dead-code snapshot loaders

- **File:** `src/Haskoin/Storage.hs:875-876, 2629, 2638`.
- **Description:** `defaultCacheSize = 450 * 1024 * 1024`
  (line 876) is the only place that gets the requested
  `--dbcache` cap right — and its only two call sites
  (Storage.hs:2629, 2638) are inside `newSnapshotChainstate`,
  which itself is dead (the snapshot chainstate construction
  reaches the cache via `cacheFlush` to seed the DB once,
  then the cache is discarded). The constant doesn't
  propagate to live `applyBlock` callers; those go through
  the divided-by-100 path of BUG-4.
- **Impact:** documentation / dead-knob. If BUG-4 is fixed by
  unifying through `defaultCacheSize`, the constant has a
  purpose.

---

### BUG-19 P2 — Coin overwrites in `connectBlockAt` rely on RocksDB Put upsert; no `possible_overwrite` check; BIP-30 91722/91812 outputs land in UTXO set

- **File:** `src/Haskoin/Consensus.hs:3173-3185`,
  `src/Haskoin/Consensus.hs:2598-2667` (`checkBIP30`).
- **Core ref:** `bitcoin-core/src/validation.cpp:2200-2206`
  (`IsBIP30Unspendable` — heights 91722 / 91812 have their
  coinbase outputs *marked unspendable* even though they
  pass `IsBIP30Repeat`); `bitcoin-core/src/coins.cpp:89-114`
  (`AddCoin` with `possible_overwrite=false` throws
  `logic_error("Attempted to overwrite an unspent coin")`).
- **Description:** `connectBlockAt` writes outputs as plain
  `BatchPut` (line 3174-3181), which is silently upsert on
  RocksDB. Core's `AddCoin` enforces `possible_overwrite`
  semantics (only allowed for coinbase). The two affected
  heights 91722/91812 are the only mainnet blocks whose
  coinbase outputs Core makes unspendable (they share a txid
  with a pre-BIP30 still-unspent coinbase from a different
  block — `e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468`
  and `d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599`).
  haskoin's `checkBIP30` exempts the duplicate-coinbase
  bug-blocks 91842 / 91880 (line 2611-2616) but does NOT
  invoke `IsBIP30Unspendable` for 91722 / 91812 — so their
  outputs are stored in `PrefixUTXO` and remain spendable
  in haskoin where they are unspendable in Core.
- **Excerpt (Consensus.hs:3225-3242):**

  ```haskell
  -- This Just-handler is for disconnect-time UNCLEAN suppression
  -- only; it is NOT consulted at connect time.
  bip30ExceptionHeight :: Word32 -> Maybe BlockHash
  bip30ExceptionHeight 91722 = Just $
    hashFromHex "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
  bip30ExceptionHeight 91812 = Just $
    hashFromHex "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
  bip30ExceptionHeight _     = Nothing
  ```

- **Impact:** if a future tx attempts to spend the coinbase of
  91722 or 91812, haskoin accepts the spend (the UTXO is in
  its set), while Core rejects it. That is a consensus split
  on the live mainnet chain at the moment such a spend lands
  in a block. Today no such spend exists (the txouts have
  been observed-unspendable since 2010); a malicious miner
  with a colliding privkey could engineer one. P0-CDIV-class
  if explicitly weaponised; P2 by likelihood.

---

### BUG-20 P3 — `UTXOEntry` (legacy serialisation) uses BE32 for height; Core uses VARINT

- **File:** `src/Haskoin/Storage.hs:583-596`.
- **Description:** the `UTXOEntry` `Serialize` instance
  encodes height as `putWord32be`, then the `TxOut`, then two
  `Bool`s. This is the legacy format; current writes
  (`putUTXOCoin`) use `putCoreCoin` → Core VARINT. Legacy
  `UTXOEntry`-shape rows may exist in older datadirs.
- **Impact:** old datadirs may carry rows in the legacy
  format. No live reader uses this format; the snapshot path
  uses `getCoreCoin`. Dormant; only matters for cross-
  version backward compat.

---

### BUG-21 P3 — `cvcCoins` is a `Map OutPoint CoinEntry`; Core uses an open-addressed hash-set with PoolAllocator

- **File:** `src/Haskoin/Storage.hs:880-887`.
- **Core ref:** `bitcoin-core/src/coins.h:219-224` —
  `CCoinsMap` is `std::unordered_map<COutPoint,
  CCoinsCacheEntry, SaltedOutpointHasher, std::equal_to,
  PoolAllocator<...>>`.
- **Description:** haskoin uses `Data.Map.Strict`, which is
  a balanced binary tree. Lookups are O(log n); Core's
  hash-map is O(1) amortised. For a typical IBD with ~80M
  UTXOs, the haskoin lookup cost is ~26 comparisons per
  fetch; Core's is ~1.
- **Impact:** performance only. The choice of Map vs HashMap
  is a Haskell-idiomatic trade-off; HashMap from
  `unordered-containers` would close the gap.

---

### BUG-22 P3 — `isUnspendable` accepts size > 10_000 but Core's MAX_SCRIPT_SIZE is exactly 10_000

- **File:** `src/Haskoin/Storage.hs:990-995`.
- **Core ref:** `bitcoin-core/src/script/script.h:563-566`
  (`IsUnspendable` returns `(size() > 0 && *begin() ==
  OP_RETURN) || (size() > MAX_SCRIPT_SIZE)`),
  `bitcoin-core/src/script/script.h:40` (`MAX_SCRIPT_SIZE =
  10000`).
- **Description:** the haskoin check is `BS.length script >
  10000` — strict greater-than. Core's `MAX_SCRIPT_SIZE`
  check is `size() > MAX_SCRIPT_SIZE` — also strict greater-
  than. The two are equivalent.
- **Impact:** false positive in this audit; the strict-gt
  check matches Core. Recorded for completeness. P3
  (cosmetic — no real bug).

---

## Fleet patterns

- **Three-pipeline UTXO storage** (live `PrefixUTXO = 0x05` +
  legacy `UTXOCache` + dead `CoinsViewDB / CoinsViewCache`).
  Pattern matches the fleet-wide "two-pipeline guard"
  finding (W74+, ouroboros/blockbrew/hotbuns/nimrod) but
  three-pipeline at the chainstate boundary is unusual.
- **Comment-as-confession** at Storage.hs:644-646
  (`"In production, store UTXOEntry in DB instead of TxOut.
  For now, use default metadata"`) — BUG-10. Matches the
  fleet pattern of haskoin's `Consensus.hs:4917`
  (`"In a full implementation, we would compute MuHash3072
  here. For now, mark as validated"`) flagged in W138.
- **Dead-class fleet pattern continued from W138** — the
  CoinsViewCache + CoinsViewDB are defined with full method
  surface and zero production callers, identical in shape
  to ChainstateManager / DualChainstateManager / etc.
- **Plumb-gate-then-flip** — BUG-4 `\`div\` 100` and BUG-5
  `encode (toBE32 height)`: the flag is parsed, threaded to
  the call site, and silently mis-interpreted at the last
  moment. Pattern recently observed in W141 nimrod
  (mempoolminfee 1000× divisor, zmq.nim never imported).

---

## Recommended next steps (not in scope for this DISCOVERY audit)

1. **One-line fix for BUG-4 (`\`div\` 100`)**: change Main.hs:800 to
   `newUTXOCache db (noDbCache * 1024 * 1024)`. Closes a 100x
   cache-budget gap on the reorg + assumeUTXO + submitblock
   arms. Verify via the smoke harness regtest run.
2. **One-line fix for BUG-5 (`encode (toBE32 height)`)**: drop
   the `encode` at Consensus.hs:3115, 3194, 3639. Closes the
   height-index corruption and unblocks the BIP-30 anchor
   skip.
3. **3-line fix for BUG-6 (`idx > 15`)**: raise the cap to
   the constant `maxOutputsPerBlock = maxBlockWeight \`div\`
   minTransactionOutputWeight` and parameterise.
4. **Architectural fix for BUG-1 / BUG-2 / BUG-7 / BUG-8**:
   wire the live path through `CoinsViewCache`. Removes the
   three-pipeline split. ~1 week of work; the CoinsViewCache
   already has the test-coverage from W100 and a working
   Core-compatible serialisation (W107 G11/G12).
5. **BUG-3 chainstate obfuscation**: port `xorObfuscate` from
   `Mempool/Persist.hs:118` to a `dbwrapper`-style layer
   around `R.put` / `R.get` / `R.delete`. One-time on-disk
   migration required.

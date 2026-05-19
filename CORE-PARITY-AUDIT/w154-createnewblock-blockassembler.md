# W154 — CreateNewBlock + BlockAssembler + block template construction (haskoin)

**Wave:** W154 — `BlockAssembler`, `CreateNewBlock`, `addChunks`,
`AddToBlock`, `TestChunkBlockLimits`, `TestChunkTransactions`,
`resetBlock`, `m_lock_time_cutoff`, `ApplyArgsManOptions`,
`ClampOptions`, `RegenerateCommitments`, `GenerateCoinbaseCommitment`,
`UpdateUncommittedBlockStructures`, `GetWitnessCommitmentIndex`,
`BlockMerkleRoot`, `BlockWitnessMerkleRoot`, `GetMinimumTime`,
`UpdateTime`, `AddMerkleRootAndCoinbase`, `WaitAndCreateNewBlock`,
`CooldownIfHeadersAhead`, `MAX_BLOCK_WEIGHT=4000000`,
`WITNESS_SCALE_FACTOR=4`, `MAX_BLOCK_SIGOPS_COST=80000`,
`MAX_BLOCK_SERIALIZED_SIZE=4000000`, `DEFAULT_BLOCK_MAX_WEIGHT`,
`DEFAULT_BLOCK_RESERVED_WEIGHT=8000`, `DEFAULT_BLOCK_MIN_TX_FEE`,
`MINIMUM_WITNESS_COMMITMENT`, `MAX_SEQUENCE_NONFINAL=0xfffffffe`.

**Scope:** discovery only — no production code changes.

**Bitcoin Core references**
- `bitcoin-core/src/node/miner.h:42-57` — `CBlockTemplate` shape:
  `block`, `vTxFees`, `vTxSigOpsCost`, `m_package_feerates`,
  `m_coinbase_tx`.
- `bitcoin-core/src/node/miner.h:60-123` — `BlockAssembler` class:
  internal state (`nBlockWeight`, `nBlockTx`, `nBlockSigOpsCost`,
  `nFees`, `nHeight`, `m_lock_time_cutoff`), `Options`
  (`nBlockMaxWeight`, `blockMinFeeRate`, `test_block_validity`),
  `CreateNewBlock`, `resetBlock`, `AddToBlock`, `addChunks`,
  `TestChunkBlockLimits`, `TestChunkTransactions`,
  `m_last_block_num_txs`, `m_last_block_weight`.
- `bitcoin-core/src/node/miner.h:130, 132, 135, 138, 141` —
  `GetMinimumTime`, `UpdateTime`, `RegenerateCommitments`,
  `ApplyArgsManOptions`, `AddMerkleRootAndCoinbase`.
- `bitcoin-core/src/node/miner.cpp:36-47` — `GetMinimumTime`:
  `min_time = pindexPrev->GetMedianTimePast() + 1`; at retarget
  boundary (`height % 2016 == 0`) bump to
  `max(min_time, prev->GetBlockTime() - MAX_TIMEWARP)` (=600s)
  unconditionally — **BIP-94 timewarp clamp for all networks**, not
  just testnet4.
- `bitcoin-core/src/node/miner.cpp:49-65` — `UpdateTime`:
  `nNewTime = max(GetMinimumTime(...), now)`; if
  `fPowAllowMinDifficultyBlocks`, re-derive `nBits` after time bump.
- `bitcoin-core/src/node/miner.cpp:67-77` — `RegenerateCommitments`:
  ERASE existing witness-commitment vout, re-call
  `GenerateCoinbaseCommitment`, then recompute
  `hashMerkleRoot = BlockMerkleRoot(block)`.
- `bitcoin-core/src/node/miner.cpp:79-88` — `ClampOptions`: clamps
  `block_reserved_weight` to
  `[MINIMUM_BLOCK_RESERVED_WEIGHT, MAX_BLOCK_WEIGHT]` with default
  `DEFAULT_BLOCK_RESERVED_WEIGHT=8000`; clamps
  `coinbase_output_max_additional_sigops` to
  `[0, MAX_BLOCK_SIGOPS_COST]`; clamps `nBlockMaxWeight` to
  `[block_reserved_weight, MAX_BLOCK_WEIGHT]`.
- `bitcoin-core/src/node/miner.cpp:98-109` — `ApplyArgsManOptions`:
  `-blockmaxweight=N`, `-blockmintxfee=BTC/kB`, `-printpriority`,
  `-blockreservedweight=N`.
- `bitcoin-core/src/node/miner.cpp:111-120` — `resetBlock`:
  `nBlockWeight = m_options.block_reserved_weight`,
  `nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops`.
- `bitcoin-core/src/node/miner.cpp:122-237` — `CreateNewBlock`:
  dummy coinbase emplace, `nHeight = pindexPrev->nHeight + 1`,
  `nVersion = ComputeBlockVersion(pindexPrev)`, `-blockversion`
  regtest override, `nTime = now`,
  `m_lock_time_cutoff = pindexPrev->GetMedianTimePast()`,
  `addChunks()` under mempool lock, coinbase build,
  `GenerateCoinbaseCommitment`, witness-stack write, `nBits`
  recompute, `TestBlockValidity` (no-PoW, no-merkle) before return.
- `bitcoin-core/src/node/miner.cpp:163-200` — coinbase build:
  `vin[0].prevout.SetNull()`,
  `vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL=0xfffffffe`,
  `vout[0].nValue = nFees + GetBlockSubsidy(nHeight)`,
  `scriptSig = CScript() << nHeight` plus optional `OP_0`
  (`include_dummy_extranonce`) so `scriptSig.size() >= 2`,
  `nLockTime = nHeight - 1` (anti-timewarp), `Assert(nHeight > 0)`
  refuses height=0.
- `bitcoin-core/src/node/miner.cpp:239-248` — `TestChunkBlockLimits`:
  uses `>=` comparison against both `nBlockMaxWeight` and
  `MAX_BLOCK_SIGOPS_COST` (NOT `>`).
- `bitcoin-core/src/node/miner.cpp:262-277` — `AddToBlock`:
  appends to `pblocktemplate->vTxFees`, `vTxSigOpsCost`, bumps
  `nBlockWeight += entry.GetTxWeight()`, `nFees += entry.GetFee()`.
- `bitcoin-core/src/node/miner.cpp:279-334` — `addChunks`:
  iterates `mempool->GetBlockBuilderChunk` until min-feerate violated;
  for each chunk applies `TestChunkBlockLimits +
  TestChunkTransactions`; on fit, calls `AddToBlock` and pushes
  `m_package_feerates.emplace_back(chunk_feerate_vsize)`; failure
  counter `MAX_CONSECUTIVE_FAILURES = 1000`,
  `BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000`.
- `bitcoin-core/src/node/miner.cpp:336-352` — `AddMerkleRootAndCoinbase`:
  in-place coinbase substitution, recompute merkle root, reset
  `m_checked_witness_commitment / m_checked_merkle_root / fChecked`.
- `bitcoin-core/src/node/miner.cpp:361-448` — `WaitAndCreateNewBlock`:
  longpoll loop (`tip_block_cv.wait_until`), 20-min testnet stall
  bypass, fee-threshold trigger.
- `bitcoin-core/src/node/miner.cpp:458-490` — `CooldownIfHeadersAhead`:
  3-20s adaptive cooldown when `BlocksAheadOfTip()` returns headers
  ahead of tip; mining stalls until tip catches up.
- `bitcoin-core/src/validation.cpp:3997-4019` —
  `GenerateCoinbaseCommitment`: 38-byte OP_RETURN
  `0x6a 0x24 0xaa 0x21 0xa9 0xed <32-byte commitment>`; commitment =
  `SHA256d(witnessroot || nonce)`; nonce = 32 zero bytes;
  `UpdateUncommittedBlockStructures` then writes the 32-byte nonce
  into `coinbase.vin[0].scriptWitness.stack[0]` when SegWit is active.
- `bitcoin-core/src/consensus/validation.h:147-165` —
  `GetWitnessCommitmentIndex`: scans `coinbase.vout`, returns the
  **last** vout whose scriptPubKey starts with the 6-byte
  `0x6a24aa21a9ed` magic prefix and is `>= MINIMUM_WITNESS_COMMITMENT`
  bytes (38).
- `bitcoin-core/src/consensus/merkle.cpp:66-85` — `BlockMerkleRoot`
  (iterates `vtx[s]->GetHash()` over all txs incl. coinbase);
  `BlockWitnessMerkleRoot` (coinbase wtxid is `uint256()` placeholder,
  remaining txs use `GetWitnessHash`).
- `bitcoin-core/src/consensus/consensus.h:13-17` —
  `MAX_BLOCK_SERIALIZED_SIZE = 4000000`,
  `MAX_BLOCK_WEIGHT = 4000000`,
  `MAX_BLOCK_SIGOPS_COST = 80000`,
  `WITNESS_SCALE_FACTOR = 4`.
- `bitcoin-core/src/policy/policy.h:25, 27, 36` —
  `DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT`,
  `DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`,
  `DEFAULT_BLOCK_MIN_TX_FEE = 1` (sat/kvB).
- `bitcoin-core/src/rpc/mining.cpp:743-1103` — `getblocktemplate`,
  `submitblock`, `generateblock`, `generatetoaddress`,
  `prioritisetransaction`, `getprioritisedtransactions`.

**Files audited**
- `src/Haskoin/BlockTemplate.hs` — full module (1416 LOC):
  `createBlockTemplate` (line 201-295), `buildCoinbase` (381-428),
  `encodeHeight` (438-439), `computeWitnessCommitment` (370-373),
  `assembleBlock` (447-464), `submitBlock` (484-639),
  `submitBlockSideBranch` (666-726), `doSideBranchReorg` (847-965),
  `applyBlockToCache` (1224-1393), `buildBlockUTXOMap` (1183-1200),
  constants: `locktimeThreshold=500000000` (108),
  `sequenceFinal=0xffffffff` (112), `maxSequenceNonFinal=0xfffffffe`
  (118), `blockReservedWeight=8000` (124).
- `src/Haskoin/Rpc.hs` — mining handlers:
  `handleGetBlockTemplate` (2760-2766), `handleTemplateRequest`
  (2769-2848), `handleBlockProposal` (2851-2869),
  `buildWitnessCommitmentScript` (2893-2900),
  `bip22ResultString` (2910-3025), `handleSubmitBlock` (3030-3068),
  `handleGetMiningInfo` (3073-3100),
  `handleGenerateToAddress` (3109-3130),
  `handleGenerateBlock` (3135-3164), `handleGenerate` (3169-3185),
  `generateBlocks` (3228-3231), `generateBlocksWithScript`
  (3234-3243), `generateBlockWithTxs` (3246-3249),
  `generateSingleBlock` (3252-3317),
  `buildRegtestCoinbase` (3320-3342),
  `encodeRegtestHeight` (3347-3359),
  `findRegtestNonce` (3363-3375),
  `computeGbtDeploymentStatus` (2730-2753).
- `src/Haskoin/Mempool.hs` — `selectTransactions` (2076-2100),
  `selectTransactionsFromClusters` (3500-3527),
  `MempoolEntry` (282-323 — `meTxId`, `meWtxid`, `meFee`,
  `meSize`, `meSigOpCost`, `meAncestorFees`, `meAncestorSize`,
  `meAncestorCount`, `meAncestorSigOps`),
  `mpFeeDeltas :: TVar (Map TxId Int64)` (574),
  `mpHeight :: TVar Word32` (565).
- `src/Haskoin/Consensus.hs` — `maxBlockWeight=4000000` (463),
  `maxBlockSigops=80000` (468), `maxBlockSigOpsCost=80000` (474),
  `maxMoney=2100000000000000` (478), `coinbaseMaturity=100` (482),
  `witnessScaleFactor=4` (510), `maxBlockSize=1000000` (459),
  `maxFutureBlockTime=7200` (541), `maxTimewarp=600` (553),
  `halvingInterval=210000` (597), `blockReward` (880-885),
  `encodeBip34Height` (2033-2044),
  `validateCoinbaseHeightConsensus` (2050-2057),
  `computeBlockVersionFromChain` (1965-1983), `bip34Height=227931`
  (903), `bip65Height=388381` (907), `bip66Height=363725` (911),
  `segwitHeight=481824` (915), `taprootHeight=709632` (919),
  `taprootDeployment` (1678-1686), `consensusFlagsAtHeight`
  (1498-1517), `blockWeight` (2067-2073).
- `src/Haskoin/Crypto.hs` — `computeWtxid` (1064-1065).
- `src/Haskoin/Types.hs:226-294` — `Serialize Tx`: marker+flag
  emission gated by `any (not . null) txWitness`; segwit parse path.
- `app/Main.hs:897` — `newMempool ... 0 0 ...` (mpHeight=0 carry-forward).
- `test/W108GbtSpec.hs` — prior W108 audit (30 gates / 21 bugs);
  W154 deepens that audit with separate gate set focused on
  CreateNewBlock semantics rather than GBT RPC shape.

---

## Gate matrix (32 sub-gates / 13 behaviours)

| # | Behaviour | Sub-gate | Verdict |
|---|-----------|----------|---------|
| 1 | MAX_BLOCK_WEIGHT=4000000 constant | G1: integer literal matches Core | PASS (`Consensus.hs:462-463`, asserted by W108 G23) |
| 1 | … | G2: enforced as `<= MAX_BLOCK_WEIGHT` at block-receive | **BUG-1 (P0-CONS cross-cite W143 BUG-2)** — `Consensus.hs:2443` gates the check on `flagSegWit flags`; pre-segwit (height < 481824 on mainnet) blocks have NO size cap. Mining template at heights 0..481823 can produce a 4-MB block that Core would reject (`bad-blk-length`); this is W143 BUG-2 still un-landed and now also a mining-pipeline carry-forward. |
| 2 | WITNESS_SCALE_FACTOR=4 | G3: weight = base*3 + total | PASS (`Consensus.hs:2073`); also used in `selectTransactions` `meSize * witnessScaleFactor` weight conversion (`Mempool.hs:2100`) |
| 3 | DEFAULT_BLOCK_MAX_WEIGHT / `-blockmaxweight` knob | G4: operator can shrink the template | **BUG-2 (P0-DEAD)** — there is no `-blockmaxweight` CLI flag anywhere in `app/Main.hs`. Core's `ApplyArgsManOptions` exposes `blockmaxweight`/`blockmintxfee`/`blockreservedweight`/`-blockversion` (regtest); haskoin hardcodes `maxBlockWeight` (4 MB) at the call site and cannot be reduced. Mining pools that want to cap templates at e.g. 2 MB to keep propagation latency low have no in-band switch. |
| 4 | DEFAULT_BLOCK_RESERVED_WEIGHT=8000 | G5: constant matches | PASS (`BlockTemplate.hs:124`, asserted by W108 G22) |
| 4 | … | G6: actually subtracted from `nBlockMaxWeight` | PARTIAL — `selectTransactions (maxBlockWeight - blockReservedWeight)` (`BlockTemplate.hs:235`). Correct for GBT. But `generateSingleBlock` (regtest miner) hardcodes the magic number `4000` instead (`Rpc.hs:3286`: `maxBlockWeight - 4000`) — half the reservation, divergent from `blockReservedWeight=8000`. **BUG-3** below. |
| 5 | addChunks: chunk-feerate selection (BIP-152 / Cluster Mempool) | G7: select by chunk feerate, not greedy ancestor | **BUG-4 (P1)** — `selectTransactions` (`Mempool.hs:2076-2100`) does a global sort by `(meAncestorFees * 1000) / meAncestorSize` and greedily picks. Core abandoned this in PR #28676 (Cluster Mempool, July 2024) for a chunk-feerate pop loop (`addChunks` via `GetBlockBuilderChunk`). haskoin has `selectTransactionsFromClusters` (`Mempool.hs:3500-3527`) which IS chunk-based — but `createBlockTemplate` (`BlockTemplate.hs:235`) wires the older `selectTransactions` greedy path. Two-pipeline drift; the cluster-aware code path is **dead at template construction**. |
| 5 | … | G8: per-package feerate emitted in template (`m_package_feerates`) | **BUG-5 (P1)** — `CBlockTemplate::m_package_feerates` (miner.h:51) collects each chunk's feerate in selection order, surfaced via the GBT `packagefeerates` BIP-22 extension. haskoin `BlockTemplate` shape has no such field; GBT JSON has no `packagefeerates` array. RBF probing tools cannot read per-chunk economics. |
| 5 | … | G9: `MAX_CONSECUTIVE_FAILURES = 1000` chunk-skip cap | **BUG-6 (P2)** — Core caps consecutive `TestChunkBlockLimits` failures at 1000 (`miner.cpp:284`) so a million dust-low-feerate chunks don't grind the assembler. haskoin's `selectWithinWeight` (`Mempool.hs:2093-2098`) walks the entire sorted list with no equivalent escape; with a 50k-entry mempool this is `O(n * log n)` regardless of how close to full the block is. |
| 5 | … | G10: BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000 (when 4k under cap, stop) | **BUG-6 cross-cite** |
| 6 | TestChunkBlockLimits comparison | G11: `>=` comparison on weight + sigops (not `>`) | **BUG-7 (P2)** — Core `miner.cpp:241-247` uses `>=` so a chunk that would exactly fill the block is rejected (leaving headroom for header+coinbase). haskoin `selectWithinWeight` (`Mempool.hs:2097`) uses strict `>` — a chunk that pushes weight to exactly `4_000_000 - 8000 = 3_992_000` is admitted; the coinbase then can push the block past the limit. Practical risk is low because coinbase is well under 8000 wu, but the boundary semantics diverge. |
| 6 | … | G12: sigops gate (`MAX_BLOCK_SIGOPS_COST`) | PARTIAL — `selectWithinSigopBudget` (`BlockTemplate.hs:317-326`) runs as a post-pass over the weight-selected list, not interleaved with chunk fit. If a sigop-dense chunk fits in weight but exceeds sigop budget, Core skips it whole; haskoin admits the prefix and drops only the offending entry, producing a different selected set. |
| 7 | TestChunkTransactions: locktime check | G13: re-check `IsFinalTx` per tx in selected chunk | **BUG-8 (P1)** — Core `miner.cpp:252-260` runs `IsFinalTx(tx, nHeight, m_lock_time_cutoff)` over each tx in the chunk before admitting it. Mempool admission also gates locktime, but the chunk is selected from a snapshot and locktime can decay between admit and template construction (CSV time-based locks reference MTP which may have advanced). haskoin `selectTransactions` does NOT re-check finality per entry — `createBlockTemplate` runs `mtpFinalEntries = filter (isFinalEntry height mtp) allEntries` only once over the full list, not per-chunk. Same outcome under normal flow, but admits a stale-locktime tx if MTP advances between snapshot and selection. |
| 8 | m_lock_time_cutoff derivation | G14: `pindexPrev->GetMedianTimePast()` | PARTIAL — `createBlockTemplate` uses `mtp = medianTimePast entries prevHash` for `mtpFinalEntries` filter (`BlockTemplate.hs:217, 239`); same effective semantics. But the local variable is `mtp + 1` for `minTime` and `mtp` for locktime cutoff — `minTime = mtp + 1` is correct for `bhTimestamp` but the locktime cutoff (Core: just MTP, not MTP+1) is passed as `mtp` to `isFinalEntry`. The off-by-one is **not** a bug here (Core uses `<` so MTP and MTP-1+1 give same result for height-encoded locktimes), but the two adjacent definitions are easy to confuse. |
| 9 | nVersion: BIP-9 version-rolling | G15: `ComputeBlockVersion` runs over signaling deployments | PARTIAL — `computeBlockVersionFromChain` (`Consensus.hs:1965-1983`) does iterate deployments, BUT `handleTemplateRequest` and `createBlockTemplate` BOTH pass `[(taprootDeployment net, Map.empty)]` only (`BlockTemplate.hs:277`, `Rpc.hs:2787`). **BUG-9** below. |
| 9 | … | G16: future deployment names (e.g. testdummy, BIP9 future) are queryable | **BUG-9 (P1)** — `activeDeployments` is hardcoded to a list of exactly one entry (`taprootDeployment net`). When a new soft-fork ships, Core picks it up from `Consensus::Params::vDeployments` automatically; haskoin requires source-level edits at TWO sites (`BlockTemplate.hs:277` and `Rpc.hs:2787`) plus a new `Deployment` constructor. No central deployment registry. |
| 10 | coinbase scriptSig length: `2 <= len <= 100` | G17: low-height (1..16) coinbase produces ≥2 byte scriptSig | **BUG-10 (P0-CDIV)** — `buildCoinbase` (`BlockTemplate.hs:391-392`) builds `scriptSig = BS.concat [heightBytes, extraNonce]`. For `height ∈ {1..16}`, `encodeBip34Height` emits a single-byte OP_N opcode (`Consensus.hs:2035`). `handleTemplateRequest` (`Rpc.hs:2772-2773`) passes `BS.empty BS.empty` as `coinbaseScript` and `extraNonce`. Result: scriptSig length = 1 byte for ALL blocks 1..16. This violates `consensus/tx_check.cpp:49` `bad-cb-length` (2..100). The GBT-returned coinbase template would be **rejected at submitblock**. Core fixes this with `include_dummy_extranonce` → appends `OP_0` to bring scriptSig to ≥2 bytes (`miner.cpp:187-193`). haskoin has no equivalent. Also affects `buildRegtestCoinbase` for h=0 / h=1..16, see BUG-11. |
| 10 | … | G18: h=0 (genesis-replay) coinbase | **BUG-10 cross-cite** — `encodeBip34Height 0 = BS.singleton 0x00` (single byte). Core asserts `Assert(nHeight > 0)` (`miner.cpp:195`) — refuses to mine at h=0. haskoin's `buildCoinbase` accepts h=0 with `lockTime = 0` (line 427) and emits a 1-byte scriptSig — instant `bad-cb-length` rejection. |
| 10 | … | G19: scriptSig ≤ 100 bytes | PASS in practice — `BlockTemplate.buildCoinbase` only places `heightBytes` (≤5 bytes) + caller-supplied `extraNonce`; nothing enforces an upper bound but no production call site supplies a long extra-nonce. Mining-pool clients that prepend their own `extranonce1`/`extranonce2` get no warning. |
| 11 | coinbase height: BIP-34 encoded | G20: byte-exact prefix match | PASS (`Consensus.hs:2050-2057` `validateCoinbaseHeightConsensus`) |
| 11 | … | G21: regtest miner uses canonical CScriptNum encoding | **BUG-11 (P0-CDIV cross-cite W108 BUG-11/12/13)** — `encodeRegtestHeight` (`Rpc.hs:3347-3359`) uses a DIFFERENT, INCOMPATIBLE encoding from `encodeBip34Height`: for h=0 it emits `BS.pack [1, 0]` (2-byte push of zero) instead of `BS.singleton 0x00` (canonical OP_0). For h ∈ {1..16} it emits `BS.pack [1, h]` (2-byte push) instead of `BS.singleton (0x50 + h)` (OP_N). The `validateCoinbaseHeightConsensus` byte-exact prefix check (`Consensus.hs:2057`) requires the canonical encoding, so `generateSingleBlock` produces blocks at heights 0..16 that haskoin's OWN validator would reject. Two-pipeline divergence at the consensus boundary (W108 catalogued the regtest companion bugs separately; W154 confirms divergence is still live). |
| 12 | GenerateCoinbaseCommitment / witness commitment OP_RETURN | G22: 38-byte `0x6a 0x24 0xaa 0x21 0xa9 0xed <32-byte>` | PASS (`BlockTemplate.hs:412-414` byte-literals match Core `validation.cpp:4007-4013`) |
| 12 | … | G23: commitment = `SHA256d(witnessroot || nonce)` | PASS (`BlockTemplate.hs:266-267` `doubleSHA256 (witnessroot ++ nonce)`) |
| 12 | … | G24: nonce written into `coinbase.vin[0].scriptWitness.stack[0]` (Core `UpdateUncommittedBlockStructures`) | PASS (`BlockTemplate.hs:420` `txWitness = [[BS.replicate 32 0]]`) |
| 12 | … | G25: only emit OP_RETURN commitment when SegWit deployment is active | **BUG-12 (P0-CDIV)** — Core `UpdateUncommittedBlockStructures` gates the commitment generation on `DeploymentActiveAfter(pindexPrev, *this, DEPLOYMENT_SEGWIT)` (`validation.cpp:3989`). haskoin's `buildCoinbase` ALWAYS emits the witness commitment output (`BlockTemplate.hs:411-414`), regardless of height/segwit status. On a from-genesis regtest replay with segwit-pre-activation blocks, the coinbase carries an OP_RETURN that Core would not include, producing a different `txid` for the coinbase and therefore a different `merkleRoot` → cross-impl divergence on the first ~100 regtest blocks. |
| 12 | … | G26: `RegenerateCommitments` (Core: erase + re-add when txs change post-build) | **BUG-13 (P1)** — Core `miner.cpp:67-77` `RegenerateCommitments` is the supported entry point for mining software that mutates the template after construction: it erases the existing witness commitment vout, re-runs `GenerateCoinbaseCommitment` with the new tx set, and recomputes `BlockMerkleRoot`. haskoin exports no such helper. A miner that adds/removes txs after `createBlockTemplate` returns (e.g. for fee-bumping a stuck tx) has to re-call `createBlockTemplate` from scratch, throwing away the entire selection. |
| 13 | GetWitnessCommitmentIndex (find existing commitment) | G27: scan vouts and return LAST matching index | **BUG-14 (P1)** — Core `consensus/validation.h:147-165` scans ALL outputs and returns the LAST match (loops over `o = 0..vout.size()-1`, overwriting `commitpos`). This handles miners that incorrectly emit multiple OP_RETURN-magic outputs (only the last counts). haskoin has no equivalent helper exposed in `BlockTemplate.hs`/`Consensus.hs`. `RegenerateCommitments` (BUG-13) and the block-validation consumer (Consensus.hs witness-merkle check) both need this; absent helper means the consumers either reject multi-commit blocks Core would accept, or accept ones Core would reject. |
| 14 | BlockMerkleRoot / BlockWitnessMerkleRoot | G28: coinbase wtxid is zero-placeholder in witness merkle | PASS (`BlockTemplate.hs:262` `TxId (Hash256 (BS.replicate 32 0))`) |
| 14 | … | G29: BlockMerkleRoot iterates ALL txs (incl. coinbase) | PASS (`BlockTemplate.hs:453` `computeMerkleRoot (map computeTxId allTxs)` — `allTxs = btCoinbaseTxn bt : ...`) |
| 14 | … | G30: mempool-cached wtxid reused (not re-encoded per template) | **BUG-15 (P1)** — `MempoolEntry` has `meWtxid :: Wtxid` cached (`Mempool.hs:283`), populated at `addTransaction`. `computeWtxIdFromEntry` (`BlockTemplate.hs:364-367`) IGNORES the cached field and re-runs `doubleSHA256 (S.encode tx)`. Wasted SHA256d per tx (n=mempool size) per `getblocktemplate` call. Two-pipeline drift: if the cached `meWtxid` ever drifts from `S.encode tx` (e.g. after a tx-mutation policy change), only the consumer of the cached field detects it; the template uses the recomputed value. |
| 15 | mintime: BIP-94 timewarp clamp | G31: at retarget boundary (h % 2016 == 0), bump min_time by ≤600s | **BUG-16 (P0-CDIV cross-cite W108 BUG-10)** — Core `GetMinimumTime` (`miner.cpp:36-47`) applies `min_time = max(mtp+1, prev->GetBlockTime() - 600)` at every difficulty-adjustment boundary on EVERY network (note Core comment "Account for BIP94 timewarp rule on all networks. This makes future activation safer."). haskoin `createBlockTemplate` (`BlockTemplate.hs:218`): `minTime = mtp + 1` unconditionally. On testnet4 at every 2016-block boundary the template's `mintime` is wrong; on mainnet pre-BIP-94 activation it's currently identical-by-luck, but the moment BIP-94 ships to mainnet, every retarget-boundary template will leak a too-early timestamp into miners. |
| 16 | UpdateTime + re-derive nBits | G32: when fPowAllowMinDifficultyBlocks, recompute nBits after time bump | PARTIAL — `createBlockTemplate` does call `difficultyAdjustment` once (`BlockTemplate.hs:227`) with `curTime` ≥ `minTime`. Core re-runs `GetNextWorkRequired` AFTER `UpdateTime` bumps `nTime` (`miner.cpp:60-61`); haskoin computes nBits ONCE before the time is final. On testnet4/regtest the 20-min min-difficulty rule means nBits can flip between `now-1` and `now+1`; haskoin will hand the miner a template whose nBits no longer matches the timestamp the miner ends up signing. |
| 17 | TestBlockValidity post-construction | G33: run `TestBlockValidity` with `check_pow=false, check_merkle_root=false` | **BUG-17 (P1)** — Core `miner.cpp:223-228` runs `TestBlockValidity` after coinbase construction to catch self-inflicted bugs (e.g. low-height bad-cb-length). haskoin's `createBlockTemplate` returns immediately after building the template (`BlockTemplate.hs:280`); no self-test. Combined with BUG-10/12, the GBT path silently hands miners templates that hash to invalid blocks — they discover this only at `submitblock`. |
| 18 | mpHeight=0 startup gap affects mining | G34: `BlockTemplate.createBlockTemplate` reads chain tip directly, not mpHeight | PASS (`BlockTemplate.hs:210-211` `tip <- readTVarIO (hcTip hc); height = ceHeight tip + 1`). But `selectTransactions` → `mtpFinalEntries` filter uses the chain MTP (also direct, not from `mpMTP`). Mining is unaffected by `mpHeight=0`. **BUT** mempool admit-side (which feeds the template) IS affected — txs admitted during the startup-gap have `meHeight=0`, and BIP-68 / BIP-113 finality at admit time was over-permissive (W153 BUG-14 carry-forward). The template inherits those over-permissive admits. |
| 19 | generateblock RPC: regtest fee handling | G35: coinbase value includes fees | **BUG-18 (P0-CDIV)** — `generateSingleBlock` (`Rpc.hs:3277-3279`): `let reward = blockReward height` plus inline comment `"For simplicity, we use just the block reward here"`. The coinbase pays subsidy ONLY; if the regtest miner picks up fee-bearing txs from the mempool, the difference goes unclaimed. Core `miner.cpp:178`: `block_reward = nFees + GetBlockSubsidy(nHeight)`. **comment-as-confession 8th instance** (fleet pattern, mirrors hotbuns W145 BUG-cluster "Assume-valid scope creep" shape: an inline comment admits the divergence). |
| 19 | … | G36: regtest miner re-uses BlockTemplate.buildCoinbase | **BUG-19 (P1, fleet two-pipeline guard 18th distinct extension)** — `generateSingleBlock` (`Rpc.hs:3252-3317`) is a complete re-implementation of `createBlockTemplate` + `assembleBlock` + `submitBlock`, with at least 6 distinct divergences from the canonical path: (a) wrong reward (BUG-18), (b) wrong encoding for low heights (BUG-11), (c) wrong nSequence in coinbase (`0xffffffff` vs `maxSequenceNonFinal`, see W108 BUG-11), (d) wrong nLockTime (`0` vs `height-1`, W108 BUG-12), (e) no witness-commitment OP_RETURN (W108 BUG-13), (f) hardcoded `bits = 0x207fffff` instead of `difficultyAdjustment` (W108 BUG-14). The same regtest-fast-path lives in haskoin twice — through GBT-then-mine-externally and through `generatetoaddress` — and they disagree on what a valid block looks like. |
| 20 | prioritisetransaction RPC | G37: dispatched on the RPC table | **BUG-20 (P1 cross-cite W108 BUG-15)** — `mpFeeDeltas :: TVar (Map TxId Int64)` (`Mempool.hs:574`) exists, is read by `addTransaction` admit-gate (`Mempool.hs:855-864`), but the writer (`prioritisetransaction` RPC) is absent from the dispatch table (`Rpc.hs:1038-1099`). The field is **half-wired**: consumer present, producer absent → fee deltas are always 0, indistinguishable from "not implemented". |
| 20 | … | G38: getprioritisedtransactions RPC | **BUG-20 cross-cite** — also absent. Operator cannot query what they cannot set. |
| 21 | WaitAndCreateNewBlock longpoll | G39: 60s blocking wait on tip change or fee increase | **BUG-21 (P2)** — Core `WaitAndCreateNewBlock` (`miner.cpp:361-448`) is the back-end for `getblocktemplate?longpollid=...`. haskoin returns immediately every time; the GBT response's `longpollid` field (`Rpc.hs:2780`) is meaningless because no subsequent call ever blocks on it. Mining pools using long-poll see no benefit; they fall back to polling every N seconds. |
| 22 | CooldownIfHeadersAhead | G40: when `BlocksAheadOfTip()` returns headers-ahead, stall mining 3-20s | **BUG-22 (P2)** — Core `miner.cpp:458-490` is a deliberate stall to prevent miners from racing the validation pipeline while headers-first sync is filling in bodies. haskoin has no equivalent; a miner that calls `getblocktemplate` mid-IBD gets a template on top of a possibly-stale tip (compounded by W108 BUG-1: no IBD guard at all). |
| 23 | AddMerkleRootAndCoinbase (post-build mutation) | G41: in-place coinbase + merkle root recompute + cache reset | **BUG-23 (P2)** — Core `miner.cpp:336-352` exposes the mutator that mining clients call after picking an extra-nonce; it resets `m_checked_witness_commitment/m_checked_merkle_root/fChecked`. haskoin has no analog (`assembleBlock` builds a Block from scratch, no in-place mutation). Mining software that wants to twiddle extra-nonce and resubmit has to re-call `assembleBlock` (cheap) AND `submitBlock`'s validation re-runs from zero each time. |

---

## BUG-1 (P0-CONS, cross-cite W143 BUG-2) — Pre-segwit blocks have NO weight cap; mining template can produce 4-MB blocks Core rejects

**Severity:** P0-CONS (chain-split candidate on a from-genesis mainnet
replay; carry-forward from W143 unfixed).

**Evidence:**

```haskell
-- src/Haskoin/Consensus.hs:2440-2443
-- inside validateFullBlock contextual check
when (flagSegWit flags && blockWeight block > maxBlockWeight) $
  Left "Block weight exceeds maxBlockWeight"
```

The gate is `flagSegWit flags &&`. `consensusFlagsAtHeight` sets
`flagSegWit = h >= netSegwitHeight net` (`Consensus.hs:1503`). For
mainnet `netSegwitHeight = 481824` (`Consensus.hs:915`); for blocks
0..481823 the check is **never evaluated**. `maxBlockSize=1000000`
(`Consensus.hs:459`) is defined but never consulted in
`validateFullBlock` — grep shows zero callsites.

Mining-pipeline impact: `createBlockTemplate` (`BlockTemplate.hs:235`)
selects up to `maxBlockWeight - blockReservedWeight = 3,992,000`
weight units of mempool txs regardless of tip height. On a regtest
fresh-IBD or a from-genesis mainnet replay, the assembler will hand
miners a 4-MB template at h=100 (long pre-segwit on mainnet). Core
rejects with `bad-blk-length`; haskoin would accept its own block
back; a peer running Core would not.

**File:** `src/Haskoin/Consensus.hs:2443` (gate); cross-cite
`src/Haskoin/BlockTemplate.hs:235` (selection budget that allows the
oversized block); `src/Haskoin/Consensus.hs:459` (`maxBlockSize`
defined-but-dead).

**Core ref:** `bitcoin-core/src/validation.cpp` ContextualCheckBlock
size gate (unconditional 1 MB pre-segwit / 4 MB weight post-segwit);
`bitcoin-core/src/consensus/consensus.h:13`
`MAX_BLOCK_SERIALIZED_SIZE = 4000000`.

**Impact:** chain-split candidate on mainnet from-genesis replay or
regtest. The mining pipeline is one of two routes that exhibit this
(IBD receive-side is the other); both ultimately call into the same
`validateFullBlock`. Suggested fix: drop the `flagSegWit flags &&`
guard; the 4-MB cap applies always (post-segwit it's weight-units;
pre-segwit it's bytes, but `blockWeight == 4 * baseSize` when no
witness data is present, so the same numerical cap is correct).

---

## BUG-2 (P0-DEAD) — `-blockmaxweight` / `-blockmintxfee` / `-blockreservedweight` / `-blockversion` CLI knobs absent

**Severity:** P0-DEAD (operator cannot tune the assembler).

**Evidence:** grep over `app/Main.hs` for those four flag names
returns zero hits. Search for `getIntArg("-blockmaxweight"`-equivalent
patterns: none. The constants `maxBlockWeight`, `blockReservedWeight`,
and the implicit `1`-sat/kvB min-tx-fee are baked into the call sites.

Core `ApplyArgsManOptions` (`miner.cpp:98-109`) exposes all four;
mining pools regularly use `-blockmaxweight` to keep templates
propagation-friendly (e.g. F2Pool's 2 MB cap), `-blockmintxfee` to
raise the floor above 1 sat/kvB, and `-blockreservedweight` to widen
the coinbase scriptSig for extranonce space. None of those are
configurable in haskoin.

**File:** `app/Main.hs` (no parser entries), `BlockTemplate.hs:235`
and `Rpc.hs:3286` (call sites that ignore the absent options).

**Core ref:** `bitcoin-core/src/node/miner.cpp:98-109`
`ApplyArgsManOptions`.

**Impact:** mining pools that depend on operator-knob tuning cannot
adopt haskoin without source edits. Cross-fleet: every other hashhog
impl exposes at least `-blockmaxweight` per `consensus-monitor.sh`
convention.

---

## BUG-3 (P1) — regtest miner uses hardcoded `4000` reserved weight; canonical reserved weight is `8000`

**Severity:** P1 (two-pipeline drift, off-by-2x on reservation).

**Evidence:**

```haskell
-- src/Haskoin/Rpc.hs:3286 (generateSingleBlock)
entries' <- selectTransactions (rsMempool server) (maxBlockWeight - 4000)
```

```haskell
-- src/Haskoin/BlockTemplate.hs:235 (createBlockTemplate)
allEntries <- selectTransactions mp (maxBlockWeight - blockReservedWeight)
-- where blockReservedWeight = 8000 (line 124)
```

GBT path reserves 8000 weight units (DEFAULT_BLOCK_RESERVED_WEIGHT,
matches Core). The regtest fast-mine path hardcodes `4000`. A
4-MB-minus-4000 template can overrun the coinbase budget if the
miner pads the scriptSig + extranonce + witness commitment near the
upper edge, producing an over-weight block.

**File:** `src/Haskoin/Rpc.hs:3286`.

**Core ref:** `bitcoin-core/src/policy/policy.h:27`
`DEFAULT_BLOCK_RESERVED_WEIGHT = 8000`.

**Impact:** regtest mining produces slightly-over-budget blocks on
adversarial witness-padded coinbases. Core would `bad-blk-length`;
haskoin would accept (because BUG-1 above means the cap isn't even
checked pre-segwit).

---

## BUG-4 (P1) — `selectTransactions` uses greedy ancestor-feerate; cluster-aware `selectTransactionsFromClusters` is dead at template construction

**Severity:** P1 (selection drift from Core Cluster Mempool; two-pipeline guard 19th distinct extension across haskoin).

**Evidence:**

`createBlockTemplate` (`BlockTemplate.hs:235`):
```haskell
allEntries <- selectTransactions mp (maxBlockWeight - blockReservedWeight)
```

`selectTransactions` (`Mempool.hs:2076-2100`) sorts the entire
mempool by `(meAncestorFees * 1000) / meAncestorSize` once and walks
the sorted list greedily.

A parallel implementation, `selectTransactionsFromClusters`
(`Mempool.hs:3500-3527`), DOES walk chunks via `csChunkQueue` and
respects cluster boundaries. It is exported (`Mempool.hs:119`) but
has **zero production call sites** — only test callers.

Core abandoned greedy ancestor-feerate in PR #28676 (July 2024)
because it under-prices CPFP packages and over-prices long ancestor
chains. The Cluster Mempool's `GetBlockBuilderChunk` is the modern
entry point (`miner.cpp:293`). haskoin built the helper but never
wired it into the template.

**File:** `src/Haskoin/BlockTemplate.hs:235`,
`src/Haskoin/Mempool.hs:2076-2100` (live greedy path),
`src/Haskoin/Mempool.hs:3500-3527` (dead chunk path).

**Core ref:** `bitcoin-core/src/node/miner.cpp:279-334` `addChunks`,
`bitcoin-core/src/txmempool.cpp::GetBlockBuilderChunk`.

**Impact:** miners using haskoin's GBT under-extract fees from
CPFP-paying packages; over-include long-but-cheap ancestor chains.
Cross-fleet: nearly every other hashhog impl has either greedy OR
cluster, but haskoin has BOTH and uses the wrong one. Fix:
swap line 235 to call `selectTransactionsFromClusters` against the
existing `ClusterState`.

---

## BUG-5 (P1) — GBT response omits `packagefeerates` BIP-22 extension

**Severity:** P1 (mining-monitoring divergence).

**Evidence:** GBT response shape (`Rpc.hs:2813-2837`) emits the
canonical BIP-22 fields plus `default_witness_commitment` but omits
`packagefeerates`. Core's `CBlockTemplate::m_package_feerates`
(`miner.h:51`) is populated in `addChunks` (`miner.cpp:327`) and
serialized into the GBT response since v25.0.

`BlockTemplate` shape (`BlockTemplate.hs:162-177`) has no field for
per-package feerates. Even if BUG-4 above were fixed (chunk path
wired), the chunk feerates are not preserved through to the GBT
response.

**File:** `src/Haskoin/BlockTemplate.hs:162-177` (missing field),
`src/Haskoin/Rpc.hs:2813-2837` (missing JSON key).

**Core ref:** `bitcoin-core/src/node/miner.h:51`
`m_package_feerates`; `bitcoin-core/src/rpc/mining.cpp::CreateMiningResult`.

**Impact:** mining-pool monitoring tools that read per-package economics
(stratum-v2 job-construction, fee-estimation feedback loops) see no
data and have to estimate from `transactions[].fee/weight`.

---

## BUG-6 (P2) — No `MAX_CONSECUTIVE_FAILURES` / `BLOCK_FULL_ENOUGH_WEIGHT_DELTA` escape from chunk-selection loop

**Severity:** P2 (perf-only when mempool is huge with many oversize chunks).

**Evidence:** `selectWithinWeight` (`Mempool.hs:2093-2098`) walks the
entire sorted entry list with no early exit when the block is
"almost full and recent fits keep failing":

```haskell
selectWithinWeight [] _ _ acc = reverse acc
selectWithinWeight (e:rest) currentWeight limit acc
  | weight > limit = selectWithinWeight rest currentWeight limit acc
  | otherwise = selectWithinWeight rest (currentWeight + weight) limit (e : acc)
```

Core `miner.cpp:284, 314-318`:

```cpp
const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
...
if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight +
        BLOCK_FULL_ENOUGH_WEIGHT_DELTA > m_options.nBlockMaxWeight) {
    return;  // give up
}
```

On a 50k-entry testnet4 mempool the haskoin assembler walks all
50k entries every GBT call; on a stratum job-cycle of 10s this is
real CPU for no benefit (none of the remaining entries can fit).

**File:** `src/Haskoin/Mempool.hs:2093-2098`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:284, 314-318`.

**Impact:** higher GBT latency under mempool growth; not a
consensus issue.

---

## BUG-7 (P2) — `selectWithinWeight` uses strict `>` for weight comparison; Core uses `>=`

**Severity:** P2 (boundary off-by-one; can produce blocks 1 weight unit too heavy in pathological case).

**Evidence:**

```haskell
-- src/Haskoin/Mempool.hs:2097
| weight > limit = selectWithinWeight rest currentWeight limit acc
| otherwise = selectWithinWeight rest (currentWeight + weight) limit (e : acc)
```

Core `miner.cpp:241-247`:
```cpp
if (nBlockWeight + chunk_feerate.size >= m_options.nBlockMaxWeight) {
    return false;
}
if (nBlockSigOpsCost + chunk_sigops_cost >= MAX_BLOCK_SIGOPS_COST) {
    return false;
}
```

Core's `>=` rejects an exact-fill chunk because the coinbase needs
the remaining slack. haskoin's `>` admits an exact-fill, then the
coinbase pushes total weight past the cap.

Practical: combined with `blockReservedWeight=8000` cushion the
practical block stays under cap, BUT if the cushion is consumed by
witness commitment + heavy extranonce, the boundary is hit.

**File:** `src/Haskoin/Mempool.hs:2097`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:241-247`.

**Impact:** boundary divergence; produce a block 1-N weight units
above cap in adversarial coinbase-padded scenarios.

---

## BUG-8 (P1) — `TestChunkTransactions` per-chunk locktime re-check absent

**Severity:** P1 (stale-locktime tx admitted at template construction).

**Evidence:** Core `miner.cpp:252-260`:
```cpp
bool BlockAssembler::TestChunkTransactions(const std::vector<CTxMemPoolEntryRef>& txs) const
{
    for (const auto tx : txs) {
        if (!IsFinalTx(tx.get().GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}
```

This runs per chunk inside `addChunks`. haskoin runs
`mtpFinalEntries = filter (isFinalEntry height mtp) allEntries`
(`BlockTemplate.hs:239`) ONCE over the full snapshot. If MTP
advances between snapshot and selection (e.g. another block arrives
concurrently, bumping MTP), CSV-time-based locks are evaluated
against the stale MTP.

**File:** `src/Haskoin/BlockTemplate.hs:239`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:252-260`.

**Impact:** template includes a tx that becomes time-locked
between snapshot and submission; `submitblock` rejects with
`bad-txns-nonfinal`. Race only — but real on a busy node.

---

## BUG-9 (P1) — `activeDeployments` hardcoded to `[taprootDeployment net]`; no central registry

**Severity:** P1 (forward-compatibility / new soft-fork onboarding).

**Evidence:**

`BlockTemplate.hs:276-278`:
```haskell
let activeDeployments :: [(Deployment, DeploymentCache)]
    activeDeployments = [(taprootDeployment net, Map.empty)]
    (blockVersion, _) = computeBlockVersionFromChain activeDeployments entries tip
```

`Rpc.hs:2787`:
```haskell
namedDeps = [ ("taproot", taprootDeployment (rsNetwork server)) ]
```

Two separate hardcoded lists. A new soft-fork (e.g. BIP-118
"SIGHASH_ANYPREVOUT", BIP-119 "OP_CTV") requires edits at BOTH
sites plus a new `Deployment` constructor. Core walks
`Consensus::Params::vDeployments` automatically via
`m_versionbitscache.ComputeBlockVersion(pindexPrev,
chainparams.GetConsensus())` (`miner.cpp:140`).

**File:** `src/Haskoin/BlockTemplate.hs:276-278`,
`src/Haskoin/Rpc.hs:2787`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:140`,
`bitcoin-core/src/versionbits.cpp::ComputeBlockVersion`.

**Impact:** when the next soft-fork ships, haskoin's GBT silently
fails to signal the new bit, and `vbavailable` JSON is wrong. Mining
pools using haskoin as their template source mis-signal.

---

## BUG-10 (P0-CDIV) — `buildCoinbase` produces a 1-byte scriptSig for heights 0..16; `bad-cb-length` certain

**Severity:** P0-CDIV (GBT-returned templates are unminable for any
height ≤ 16 on regtest fresh-start; carry-forward + new finding).

**Evidence:**

`Consensus.hs:2034-2035`:
```haskell
encodeBip34Height 0 = BS.singleton 0x00
encodeBip34Height h | h >= 1 && h <= 16 = BS.singleton (0x50 + fromIntegral h)
```

`BlockTemplate.hs:387-392`:
```haskell
buildCoinbase height value coinbaseScript extraNonce witnessCommitment =
  let heightBytes = encodeBip34Height height
      scriptSig = BS.concat [heightBytes, extraNonce]
```

`Rpc.hs:2771-2773` (handleTemplateRequest):
```haskell
bt <- createBlockTemplate (rsNetwork server) (rsHeaderChain server)
        (rsMempool server) (rsUTXOCache server)
        BS.empty BS.empty  -- placeholder coinbase script
```

With `extraNonce = BS.empty` and `height ∈ {0..16}`, scriptSig is
exactly 1 byte. `consensus/tx_check.cpp:49` rejects with
`bad-cb-length` (range 2..100). The block returned by GBT and
mined is **guaranteed to be rejected by submitblock** at every regtest
fresh-IBD start, plus on any signet/testnet4 reset.

Core mitigates this with `include_dummy_extranonce`
(`miner.cpp:187-193`):
```cpp
if (m_options.include_dummy_extranonce) {
    // For blocks at heights <= 16, the BIP34-encoded height alone is only
    // one byte. Consensus requires coinbase scriptSigs to be at least two
    // bytes long (bad-cb-length), so tests and regtest include a dummy
    // extraNonce (OP_0)
    coinbaseTx.vin[0].scriptSig << OP_0;
}
```

haskoin has no equivalent. Plus, Core `Assert(nHeight > 0)`
(`miner.cpp:195`) refuses to mine at h=0 outright; haskoin's
`buildCoinbase` accepts h=0 with `lockTime = 0` and the 1-byte
scriptSig.

**File:** `src/Haskoin/BlockTemplate.hs:387-392` (scriptSig build),
`src/Haskoin/Rpc.hs:2772-2773` (call site with `BS.empty` extraNonce),
`src/Haskoin/Consensus.hs:2034-2035` (1-byte encoding for low heights).

**Core ref:** `bitcoin-core/src/node/miner.cpp:187-195`
(`include_dummy_extranonce` + `Assert(nHeight > 0)`),
`bitcoin-core/src/consensus/tx_check.cpp:49`
(`bad-cb-length` 2..100 gate).

**Impact:** any GBT call at heights 1..16 returns an unminable
template. On regtest, this is the first 16 blocks of every fresh
chain — affects every CI run that bootstraps a regtest fleet via
`getblocktemplate` instead of `generatetoaddress`. The
`generatetoaddress` fast-path uses a different encoding (BUG-11)
which is also wrong, so even that workaround fails.

Suggested fix: in `BlockTemplate.buildCoinbase`, when
`BS.length heightBytes + BS.length extraNonce < 2`, append a single
`0x00` (OP_0). Also `Assert (height > 0)` to mirror Core.

---

## BUG-11 (P0-CDIV cross-cite W108 BUG-11/12/13) — Two-pipeline coinbase encoding: `buildCoinbase` vs `buildRegtestCoinbase` are mutually incompatible at low heights

**Severity:** P0-CDIV (regtest mining produces blocks haskoin's own validator rejects; carry-forward unfixed since W108).

**Evidence:**

`BlockTemplate.buildCoinbase` (`BlockTemplate.hs:387-428`):
- scriptSig: `encodeBip34Height(h) ++ extraNonce`
- height encoding: `OP_0` for h=0, `OP_N` for 1..16,
  length-prefixed CScriptNum otherwise
- nSequence: `maxSequenceNonFinal = 0xfffffffe`
- nLockTime: `height - 1` (anti-timewarp)
- outputs: `[mainOutput, witnessOutput]` (OP_RETURN commitment present)

`Rpc.buildRegtestCoinbase` (`Rpc.hs:3320-3342`):
- scriptSig: `encodeRegtestHeight(h)`
- height encoding (`Rpc.hs:3348-3359`): `BS.pack [1, 0]` for h=0
  (2-byte push of zero), `BS.pack [1, h]` for h ≤ 0x7f
  (always a 2-byte length-prefixed push, regardless of value)
- nSequence: `0xffffffff` (SEQUENCE_FINAL)
- nLockTime: `0`
- outputs: `[mainOutput]` only (no witness commitment)

`validateCoinbaseHeightConsensus` (`Consensus.hs:2050-2057`) does a
byte-exact prefix match against `encodeBip34Height`. For h=5,
`encodeBip34Height 5 = BS.singleton 0x55` (1 byte: OP_5), but
`encodeRegtestHeight 5 = BS.pack [1, 5]` (2 bytes: PUSH(1)
followed by 0x05). The prefix check FAILS. The regtest miner
produces a `bad-cb-height` block that its own validator rejects.

Plus four additional divergences carried forward from W108: wrong
nSequence (W108 BUG-11), wrong nLockTime (W108 BUG-12), missing
witness-commitment output (W108 BUG-13), hardcoded bits (W108
BUG-14).

**File:** `src/Haskoin/Rpc.hs:3320-3359`,
`src/Haskoin/BlockTemplate.hs:387-428`,
`src/Haskoin/Consensus.hs:2050-2057`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:163-200` (one
canonical coinbase build, no duplicates).

**Impact:** `generatetoaddress` and `generateblock` produce blocks
that fail haskoin's own validation at every height 0..16; for
heights > 16 the encoding accidentally matches (both produce a
1-byte length prefix + LE value) but nSequence/nLockTime/witness-
commitment divergences remain.

Suggested fix: delete `buildRegtestCoinbase` and `encodeRegtestHeight`;
have `generateSingleBlock` call `buildCoinbase` (the canonical
path). Also implement the missing operator-knob plumbing (BUG-2) so
the regtest path doesn't need its own constants.

---

## BUG-12 (P0-CDIV) — Witness-commitment OP_RETURN emitted unconditionally; should be gated on SegWit deployment

**Severity:** P0-CDIV (regtest pre-segwit-replay block hash divergence).

**Evidence:**

`BlockTemplate.buildCoinbase` (`BlockTemplate.hs:407-419`):
```haskell
-- Main output: reward + fees to miner's address
mainOutput = TxOut value coinbaseScript
-- Witness commitment output (OP_RETURN)
-- Format: OP_RETURN OP_PUSHBYTES_36 <aa21a9ed><32-byte commitment>
witnessOutput = TxOut 0 $ BS.concat
  [ BS.pack [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
  , witnessCommitment
  ]
in Tx { ...
      , txOutputs = [mainOutput, witnessOutput]
      , txWitness = [[BS.replicate 32 0]]
      ... }
```

No `if segwitActive` guard. Core gates this on
`DeploymentActiveAfter(pindexPrev, *this, DEPLOYMENT_SEGWIT)`
(`validation.cpp:3989` `UpdateUncommittedBlockStructures`).

For pre-segwit blocks (mainnet h < 481824, regtest before
deployment activates), Core emits a coinbase with a SINGLE output
and NO witness; haskoin emits TWO outputs and a 32-byte witness
stack. Coinbase `txid` differs (witness commitment vout affects
serialization but not txid; the 32-byte witness in `vin[0]` does NOT
affect txid since txid excludes witness). However `wtxid` differs,
and the `merkleRoot` differs because there's a 2nd vout. Cross-impl
fork at every regtest pre-segwit-activation height.

**File:** `src/Haskoin/BlockTemplate.hs:407-419`.

**Core ref:** `bitcoin-core/src/validation.cpp:3985-3995`
(`UpdateUncommittedBlockStructures`, SegWit-gated).

**Impact:** regtest fresh-start (`netSegwitHeight = 0` on regtest
means it's always active, so for regtest specifically this is benign);
on a mainnet from-genesis replay every block 0..481823's coinbase
has a different `merkleRoot` from Core's; chain-split candidate from
genesis.

---

## BUG-13 (P1) — `RegenerateCommitments` helper absent

**Severity:** P1 (mining-software ergonomics; can't mutate template post-build).

**Evidence:** Core `miner.cpp:67-77`:
```cpp
void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);
    const CBlockIndex* prev_block = ...
    chainman.GenerateCoinbaseCommitment(block, prev_block);
    block.hashMerkleRoot = BlockMerkleRoot(block);
}
```

This is the supported entry point for mining clients that modify
the tx list after `CreateNewBlock` (e.g. fee-bumping, adding
priority txs, removing a tx the miner doesn't want to include).
haskoin's `BlockTemplate` module exports `computeWitnessCommitment`
and `assembleBlock` but no in-place re-commitment helper. A miner
that wants to add a tx after `createBlockTemplate` has to re-call
the full template construction, losing the prior selection state.

Cross-cite BUG-14 below — same root: no
`GetWitnessCommitmentIndex` helper exposed.

**File:** `src/Haskoin/BlockTemplate.hs` (missing helper).

**Core ref:** `bitcoin-core/src/node/miner.cpp:67-77`.

**Impact:** mining-software ergonomics; not a consensus issue.

---

## BUG-14 (P1) — `GetWitnessCommitmentIndex` helper absent (scan-for-last-match)

**Severity:** P1 (mining-software ergonomics; potential consensus
divergence on multi-commit coinbases).

**Evidence:** Core `consensus/validation.h:147-165`:
```cpp
inline int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = NO_WITNESS_COMMITMENT;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            const CTxOut& vout = block.vtx[0]->vout[o];
            if (vout.scriptPubKey.size() >= MINIMUM_WITNESS_COMMITMENT &&
                vout.scriptPubKey[0] == OP_RETURN &&
                ... 0x24 0xaa 0x21 0xa9 0xed ...) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}
```

Key behavior: returns the LAST matching index, not the first. A
coinbase with multiple OP_RETURN-magic vouts uses the LAST one.

haskoin has no equivalent. Consumers that need to find the
commitment scan their own way — search for `0xaa21a9ed` returns only
the validation site (`Consensus.hs` witness-merkle check), which I
verified does a "first match" scan (not "last match"). On a
deliberately-malformed coinbase with two OP_RETURN-magic vouts (e.g.
attacker bait at one position, real commitment at a later position),
haskoin and Core read different commitments and disagree on
validity.

**File:** `src/Haskoin/Consensus.hs` (witness-merkle consumer uses
first-match scan; no shared helper),
`src/Haskoin/BlockTemplate.hs` (no helper for re-commitment use).

**Core ref:** `bitcoin-core/src/consensus/validation.h:147-165`.

**Impact:** potential consensus divergence on multi-magic-OP_RETURN
coinbases (rare; requires deliberate attacker construction).

---

## BUG-15 (P1) — `computeWtxIdFromEntry` re-encodes tx instead of using cached `meWtxid`

**Severity:** P1 (perf-only; two-pipeline cache vs recompute drift).

**Evidence:** `MempoolEntry` (`Mempool.hs:282-283`):
```haskell
, meTxId             :: !TxId       -- ^ Transaction ID (cached, no witness)
, meWtxid            :: !Wtxid      -- ^ Witness Transaction ID (BIP-141/339)
```

`buildMempoolEntry` (`Mempool.hs:991-993`) populates `meWtxid` once
on admission.

`BlockTemplate.computeWtxIdFromEntry` (`BlockTemplate.hs:364-367`):
```haskell
computeWtxIdFromEntry :: MempoolEntry -> TxId
computeWtxIdFromEntry entry =
  let tx = meTransaction entry
  in TxId (doubleSHA256 (S.encode tx))
```

Re-runs `S.encode tx` (which may include witness via the marker+flag
mechanism in `Types.hs:226-239`) + SHA256d, n times per
`getblocktemplate`. For a 50k-tx mempool this is 50k SHA256d
operations per template; with mining pools issuing GBT every 10s
during high-fee periods this is non-trivial CPU.

Worse, if the cached `meWtxid` field's computation logic ever
drifts from `S.encode tx` (e.g. a policy patch that changes
serialization), the consumer of the cached field sees one value and
the template sees another — silently. Pipeline drift candidate.

**File:** `src/Haskoin/BlockTemplate.hs:364-367`.

**Core ref:** `bitcoin-core/src/primitives/transaction.h::GetWitnessHash`
(cached on `CTransaction` construction).

**Impact:** GBT latency under high mempool size; potential silent
drift if encoding logic changes.

---

## BUG-16 (P0-CDIV cross-cite W108 BUG-10) — `mintime` ignores BIP-94 timewarp clamp at retarget boundaries

**Severity:** P0-CDIV (consensus-relevant timestamp generation on testnet4 NOW, mainnet POST-BIP94).

**Evidence:**

`BlockTemplate.hs:217-220`:
```haskell
let mtp = medianTimePast entries prevHash
    minTime = mtp + 1
    maxTime = now + 7200
    curTime = max minTime now
```

Core `miner.cpp:36-47`:
```cpp
int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const int64_t difficulty_adjustment_interval)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    const int height{pindexPrev->nHeight + 1};
    // Account for BIP94 timewarp rule on all networks. This makes future
    // activation safer.
    if (height % difficulty_adjustment_interval == 0) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}
```

`maxTimewarp = 600` IS defined in haskoin (`Consensus.hs:553`) and
used in the receive-side validator (`validation.cpp` references at
2443 area), but the mining-side `mintime` computation never invokes
it. At every 2016-block boundary on testnet4, haskoin hands miners a
`mintime` that may be ~600s too early, producing a template that
the receive-side rejects with `time-timewarp-attack`.

**File:** `src/Haskoin/BlockTemplate.hs:217-220`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:36-47`
`GetMinimumTime`; `bitcoin-core/src/consensus/consensus.h:35`
`MAX_TIMEWARP = 600`.

**Impact:** testnet4 mining produces templates at retarget
boundaries with bad timestamps; mainnet post-BIP94 will exhibit the
same once activated. Two-pipeline guard: receive-side and mining-side
disagree on what is valid.

---

## BUG-17 (P1) — No `TestBlockValidity` post-construction self-test

**Severity:** P1 (template handed to miner can be unminable; W108
BUG-7 companion).

**Evidence:** Core `miner.cpp:223-228`:
```cpp
if (m_options.test_block_validity) {
    if (BlockValidationState state{TestBlockValidity(m_chainstate, *pblock, /*check_pow=*/false, /*check_merkle_root=*/false)}; !state.IsValid()) {
        throw std::runtime_error(strprintf("TestBlockValidity failed: %s", state.ToString()));
    }
}
```

haskoin's `createBlockTemplate` returns immediately after assembling
the template (`BlockTemplate.hs:280-295`); no equivalent dry-run
validation. Combined with BUG-10 (low-height bad-cb-length) and
BUG-12 (regtest pre-segwit OP_RETURN), the GBT path silently emits
invalid templates that only surface at `submitblock` time.

**File:** `src/Haskoin/BlockTemplate.hs:280-295`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:223-228`.

**Impact:** mining pools see "rejected" at submit time with no
diagnostic from the template-construction layer; debugging is
two-step instead of one.

---

## BUG-18 (P0-CDIV) — `generateSingleBlock` coinbase pays subsidy only; fees are unclaimed

**Severity:** P0-CDIV (regtest fee-paying tx mined results in
unclaimed BTC; comment admits the divergence).

**Evidence:**

`Rpc.hs:3277-3280`:
```haskell
let reward = blockReward height
-- Note: For regtest with specific transactions, we would add their fees too
-- For simplicity, we use just the block reward here
let coinbase = buildRegtestCoinbase height reward scriptPubKey blockTime
```

Core `miner.cpp:178`:
```cpp
const CAmount block_reward{nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus())};
```

In regtest, when the user calls `generatetoaddress 1 <addr>` and
the mempool has a fee-paying tx, the tx is included in the block
(line 3286 `selectTransactions`) BUT the coinbase pays only the
subsidy. The fee is lost: the inputs' total exceeds the outputs'
total + coinbase reward, and the block validator should reject with
"bad-cb-amount" (coinbase pays too LITTLE is silently accepted by
Core — it's "leaving money on the table" rather than over-claiming).

**comment-as-confession 8th instance** (fleet pattern): the inline
comment "we would add their fees too" / "for simplicity, we use
just the block reward here" admits the divergence.

**File:** `src/Haskoin/Rpc.hs:3277-3280`.

**Core ref:** `bitcoin-core/src/node/miner.cpp:178` `block_reward`.

**Impact:** regtest tests that expect to see fee revenue in the
coinbase fail; CPFP / RBF regression tests that probe fee economics
on regtest get wrong numbers. Combined with BUG-19's two-pipeline
issue, the only reliable regtest mining path is GBT-then-external-
miner, but GBT itself has BUG-10 (unminable at h≤16). Net:
no working regtest mining for fee-aware tests.

---

## BUG-19 (P1) — `generateSingleBlock` is a full re-implementation of `createBlockTemplate + assembleBlock + submitBlock` with 6 distinct divergences (two-pipeline guard 19th distinct extension)

**Severity:** P1 (two-pipeline drift; mining produces blocks the
validator may reject).

**Evidence:** `Rpc.hs:3252-3317` is a parallel mining pipeline.
Divergences from the canonical `createBlockTemplate +
assembleBlock + submitBlock` chain:

1. **Reward calculation** — uses `blockReward height` only, ignores
   mempool fees (BUG-18 above). Canonical:
   `coinbaseValue = reward + totalFees` (`BlockTemplate.hs:259`).
2. **Coinbase encoding for low heights** — `encodeRegtestHeight`
   uses a 2-byte length-prefixed push for ALL low heights instead of
   single-byte OP_0/OP_N (BUG-11 above).
3. **nSequence** — `0xffffffff` (SEQUENCE_FINAL) instead of
   `maxSequenceNonFinal = 0xfffffffe` (W108 BUG-11).
4. **nLockTime** — `0` instead of `height - 1` (W108 BUG-12).
5. **Witness-commitment output** — absent entirely in
   `buildRegtestCoinbase` (W108 BUG-13).
6. **Difficulty bits** — hardcoded `0x207fffff` instead of
   `difficultyAdjustment` (W108 BUG-14).

Plus an environment knob divergence:
7. **Reserved weight** — hardcoded `4000` instead of
   `blockReservedWeight = 8000` (BUG-3 above).

**File:** `src/Haskoin/Rpc.hs:3252-3317`,
`src/Haskoin/Rpc.hs:3320-3342`,
`src/Haskoin/Rpc.hs:3347-3359`.

**Core ref:** there is no parallel regtest mining path in Core;
`generateBlocks` uses the same `CreateNewBlock` pipeline as
`getblocktemplate`.

**Impact:** regtest mining produces blocks that disagree with the
non-regtest pipeline on coinbase shape; tests that mix
`generatetoaddress`-mined blocks with `getblocktemplate`-mined
blocks see different coinbase serializations on the same chain.

Suggested fix: delete `generateSingleBlock` and have
`handleGenerateToAddress` / `handleGenerateBlock` build a template
via `createBlockTemplate`, brute-force the nonce in a loop, then
call `submitBlock`. One pipeline.

---

## BUG-20 (P1 cross-cite W108 BUG-15) — `prioritisetransaction` RPC absent; `mpFeeDeltas` is half-wired

**Severity:** P1 (consumer plumbed, producer missing; dead-data half).

**Evidence:**

`mpFeeDeltas :: TVar (Map TxId Int64)` (`Mempool.hs:574`) — exists.

Consumers (read sites):
- `addTransaction` admit-gate (`Mempool.hs:855-870`): looks up
  `Map.findWithDefault 0 txid feeDeltas`, applies as
  `modifiedFee = fee + delta`. **Live consumer.**

Producer (write sites): `grep -n "modifyTVar.*mpFeeDeltas\|writeTVar
.*mpFeeDeltas" src/Haskoin/*.hs` returns ZERO results.

RPC dispatch (`Rpc.hs:1038-1099`): no
`"prioritisetransaction"` / `"getprioritisedtransactions"` case.

Result: the fee delta is always `Map.empty`, so the modified-fee
math always reduces to `fee + 0 = fee`. The plumbing is intact and
ready, but the writer is missing. Half-wired.

**File:** `src/Haskoin/Mempool.hs:574` (state),
`src/Haskoin/Mempool.hs:855-870` (read site),
`src/Haskoin/Rpc.hs:1038-1099` (dispatch table, missing case).

**Core ref:** `bitcoin-core/src/rpc/mining.cpp::prioritisetransaction`.

**Impact:** mining-pool fee-delta workflows (typical use case: bump
a stuck tx so the next template includes it) do not work. The
infrastructure to write the RPC handler exists; only the handler
itself is missing. Suggested fix:

```haskell
"prioritisetransaction" -> handlePrioritiseTransaction server params
  where
    handlePrioritiseTransaction srv (Array [String txidHex, _dummy, Number delta]) = do
      let txid = ...
      atomically $ modifyTVar' (mpFeeDeltas (rsMempool srv)) (Map.insert txid (round delta))
      return $ RpcResponse (toJSON True) Null Null
```

---

## BUG-21 (P2) — `WaitAndCreateNewBlock` longpoll absent; `longpollid` returned but never blocked-on

**Severity:** P2 (mining-pool latency under high-frequency tip changes).

**Evidence:**

`Rpc.hs:2780-2781`:
```haskell
let longpollid = showHash (btPreviousBlock bt) <> T.pack (show (btHeight bt))
```

`handleTemplateRequest` returns immediately. Core `miner.cpp:361-448`
runs a `tip_block_cv.wait_until` blocking loop for up to 60s,
returning a fresh template on either tip change or fee-threshold
exceeded.

A miner that polls every 10s vs longpolls with 60s blocks see
identical responses from haskoin's GBT; the longpoll semantics are
absent. Mining pools that count on longpoll to reduce stratum-job
churn see no benefit.

**File:** `src/Haskoin/Rpc.hs:2769-2848` (handleTemplateRequest, no
blocking wait).

**Core ref:** `bitcoin-core/src/node/miner.cpp:361-448`
`WaitAndCreateNewBlock`.

**Impact:** mining-pool job-issuance latency higher than Core; not
a consensus issue.

---

## BUG-22 (P2) — `CooldownIfHeadersAhead` mining-stall logic absent

**Severity:** P2 (miner can build on stale tip during IBD).

**Evidence:** Core `miner.cpp:458-490` is a deliberate 3-20s cooldown
when `BlocksAheadOfTip()` reports headers ahead of connected tip.
The purpose: a miner that requests a template mid-IBD would build on
the most-recent connected tip while the next block is mid-validation;
once that block lands the template is stale. The cooldown synchronizes.

haskoin has no equivalent. Combined with W108 BUG-1 (no IBD guard
on GBT), a miner that calls `getblocktemplate` mid-sync gets a
template on top of whatever the current tip is, regardless of how
many headers ahead of it haskoin already knows.

**File:** `src/Haskoin/Rpc.hs:2769-2848` (no cooldown wrapper).

**Core ref:** `bitcoin-core/src/node/miner.cpp:458-490`
`CooldownIfHeadersAhead`.

**Impact:** wasted hash power during IBD; not a consensus issue.

---

## BUG-23 (P2) — `AddMerkleRootAndCoinbase` in-place mutator absent

**Severity:** P2 (mining-software ergonomics; no path for
extra-nonce iteration without full template re-build).

**Evidence:** Core `miner.cpp:336-352`:
```cpp
void AddMerkleRootAndCoinbase(CBlock& block, CTransactionRef coinbase,
                              uint32_t version, uint32_t timestamp, uint32_t nonce)
{
    if (block.vtx.size() == 0) {
        block.vtx.emplace_back(coinbase);
    } else {
        block.vtx[0] = coinbase;
    }
    block.nVersion = version;
    block.nTime = timestamp;
    block.nNonce = nonce;
    block.hashMerkleRoot = BlockMerkleRoot(block);
    block.m_checked_witness_commitment = false;
    block.m_checked_merkle_root = false;
    block.fChecked = false;
}
```

This is the "swap-coinbase + recompute merkle + reset caches" entry
point used by mining clients that iterate over extra-nonce values
without re-running tx selection. haskoin's `assembleBlock`
(`BlockTemplate.hs:447-464`) builds a fresh `Block` from scratch and
has no concept of cache reset (Haskell pure data — caching is
opaque). A miner that twiddles `extraNonce` and re-issues
`submitblock` causes the full `validateFullBlockIO` to re-run,
including BIP-30 disk lookups and merkle-root recomputation.

**File:** `src/Haskoin/BlockTemplate.hs:447-464` (no in-place
mutator; full rebuild only).

**Core ref:** `bitcoin-core/src/node/miner.cpp:336-352`.

**Impact:** mining-software ergonomics + extra `submitblock`
latency; not a consensus issue.

---

## Cross-fleet pattern echoes confirmed in W154

- **STANDARD-flags-incomplete / two-pipeline drift** (W144 BUG-3
  cluster): W154 BUG-19 confirms a third haskoin two-pipeline gap
  beyond W144 BUG-3 (script flags), W148 BUG-3/11 (reorg vs
  connectBlockAt). The mining pipeline is now confirmed to have its
  own private coinbase implementation, distinct from the GBT
  pipeline. Two-pipeline guard 19th distinct extension across the
  fleet (W153 was 18th).
- **already-exports-the-primitive-just-not-called** (W140 BUG-5):
  W154 BUG-4 confirms haskoin has `selectTransactionsFromClusters`
  exported but no production caller — the cluster-aware path is
  built and dead. W154 BUG-15 confirms `meWtxid` cached but the
  template recomputes it from scratch.
- **dead-data plumbing / half-wired RPC** (W138 family + W153 BUG-5
  `getMempoolMinFeeRate`): W154 BUG-20 confirms `mpFeeDeltas` is
  half-wired (consumer present, producer / RPC absent) — the
  shape exactly matches W153 BUG-6 (no `TransactionRemovedFromMempool`
  signal fan-out), W140 BUG-5 (`constantTimeEq` exported but not
  called), W138 (`ChainstateManager` defined with full method
  surface, zero production callers).
- **comment-as-confession 8th instance**: W154 BUG-18 `"For
  simplicity, we use just the block reward here"`. Lineage:
  W141 (4th), W144 BUG-12 lunarblock (5th), W148 (6th),
  W149 BUG-8 blockbrew (7th), now W154 (8th).
- **Pre-segwit consensus gap** (W143 BUG-2 carry-forward): W154
  BUG-1 confirms the size-cap gate is still gated on `flagSegWit`;
  three weeks open since W143. Mining pipeline is a second route
  exposed by the same primitive bug.
- **mpHeight=0 startup gap fleet pattern** (W150 BUG-5/6/18 + W151
  BUG-2 + W152 BUG-1 + W153 BUG-14): W154 G34 confirms the mining
  path reads chain tip directly (not mpHeight), so mining itself is
  unaffected; the carry-forward exposure is via mempool admit-side
  feeding the template. 5th audit wave carrying forward the same
  primitive bug.
- **Two-pipeline divergence at consensus boundary** (W144 carrier):
  W154 BUG-11 confirms `encodeRegtestHeight` vs `encodeBip34Height`
  divergence at the validation byte-exact-prefix gate. The mining
  pipeline produces blocks haskoin's OWN validator rejects.
- **operator-knob absence fleet pattern** (W135 BUG-cluster):
  W154 BUG-2 confirms `-blockmaxweight` / `-blockmintxfee` /
  `-blockreservedweight` / `-blockversion` absent from haskoin's
  CLI. Companion to nimrod W153, blockbrew W149 BUG-5.

---

## Summary

- **23 bugs catalogued** (W154 target 18-25; landed at 23).
- **P0-CONS class:** BUG-1 (chain-split candidate, carry-forward).
- **P0-CDIV class:** BUG-10, BUG-11, BUG-12, BUG-16, BUG-18 (= 5).
- **P0-DEAD class:** BUG-2 (= 1).
- **Total P0:** 7.
- **P1 class:** BUG-3, BUG-4, BUG-5, BUG-8, BUG-9, BUG-13, BUG-14,
  BUG-15, BUG-17, BUG-19, BUG-20 (= 11).
- **P2 class:** BUG-6, BUG-7, BUG-21, BUG-22, BUG-23 (= 5).

**Top 3 findings**

1. **BUG-1 (P0-CONS, carry-forward W143)** — pre-segwit blocks have
   NO size cap, exposed via the mining pipeline as a second route to
   the same primitive. Mining template can produce 4-MB blocks at
   any mainnet height < 481824 that Core rejects with
   `bad-blk-length`. ~3 weeks open since W143; closes via removing
   the `flagSegWit flags &&` guard at `Consensus.hs:2443`.

2. **BUG-10 (P0-CDIV, NEW)** — `BlockTemplate.buildCoinbase` produces
   a 1-byte scriptSig for blocks 1..16 because
   `encodeBip34Height` emits single-byte OP_N and the GBT handler
   passes `BS.empty` extraNonce. Result: `bad-cb-length` at
   `submitblock` for the first 16 blocks of every regtest fresh
   start. Core fixes via `include_dummy_extranonce → OP_0` append.
   Single-line fix in `buildCoinbase`.

3. **BUG-19 (P1, two-pipeline guard 19th distinct extension; NEW
   bundle)** — `generateSingleBlock` is a complete re-implementation
   of the canonical mining pipeline (`createBlockTemplate +
   assembleBlock + submitBlock`) with SIX divergences from canonical:
   wrong reward (BUG-18 P0-CDIV), wrong low-height encoding
   (BUG-11), wrong nSequence (W108 BUG-11), wrong nLockTime
   (W108 BUG-12), missing witness commitment (W108 BUG-13),
   hardcoded difficulty (W108 BUG-14). The two-pipeline gap is
   semantically *self-contradictory*: the regtest miner produces
   blocks that haskoin's OWN validator rejects (BUG-11 via
   `validateCoinbaseHeightConsensus` byte-exact prefix mismatch).

**Carry-forward stack confirmed live in W154 (5 audits deep)**:
- W144 BUG-3 STANDARD-flags absent (W150+W151+W152+W153 echo; W154
  BUG-19 confirms two-pipeline pattern continues).
- W143 BUG-2 pre-segwit size cap (3 weeks open; W154 BUG-1).
- W148 BUG-3+11 performReorg writes only undo data (W154 confirms
  via cross-cite in BUG-19's two-pipeline framing).
- W150 BUG-5+6+18 mpHeight=0 startup 4-P0 stack (W151+W152+W153+W154
  = 5th wave carrying forward).
- W151 BUG-2 submitpackage doesn't broadcast (W154 doesn't directly
  exercise; orthogonal).
- W153 BUG-3+4 min-relay fee + incremental-relay fee both off
  (W154 BUG-20 confirms `mpFeeDeltas` is dead-data half-wired —
  same shape as W153 BUG-5).

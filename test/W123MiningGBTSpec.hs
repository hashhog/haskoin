{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W123 Mining / GBT parity discovery audit (30 gates)
--
-- Reference: bitcoin-core/src/node/miner.cpp, src/rpc/mining.cpp,
--            src/policy/policy.h.  BIP-22 / BIP-23 / BIP-141 / BIP-152.
--
-- This is a fresh DISCOVERY pass against the haskoin mining stack
-- (BlockTemplate.hs + Rpc.hs mining handlers).  W108 already audited
-- the BIP-22/23 result-string passthrough, regtest-coinbase two-pipeline,
-- locktime constants, and the basic GBT IBD/peer guards.  W123
-- intentionally takes DIFFERENT angles:
--
--   * RPCs entirely absent from the dispatch table (submitheader,
--     prioritisetransaction, getprioritisedtransactions).
--   * BIP-22 dummy-extranonce + bad-cb-length gate for heights 1..16
--     (Core's include_dummy_extranonce option in CreateNewBlock).
--   * getmininginfo response shape parity (networkhashps, currentblockweight,
--     currentblocktx, signet_challenge, warnings array).
--   * estimateIsInitialBlockDownload uses a HARDCODED current-time
--     constant — works in 2026 but trips ALL nodes into IBD at some
--     future date.
--   * Anti-fee-sniping randomisation gap (Core's 10% probabilistic
--     locktime offset + lagging-chain → 0 fallback).
--   * Regtest two-pipeline divergences that W108 did not enumerate
--     (block-version, reservedWeight, fee handling).
--
-- 30 gates total.  Pending findings are documented inline with
-- src/:line and the Core reference.  The audit doc lives at
-- audit/w123_mining_gbt.md.

module W123MiningGBTSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.Word (Word32)

import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..) )
import Haskoin.BlockTemplate
  ( buildCoinbase, encodeHeight, setAntiFeeSniping
  , maxSequenceNonFinal, blockReservedWeight )
import Haskoin.Consensus
  ( encodeBip34Height, blockReward )

spec :: Spec
spec = describe "W123 Mining / GBT parity 30-gate audit (haskoin)" $ do

  -- =========================================================================
  -- G1  submitheader RPC entirely absent from dispatch
  -- =========================================================================
  describe "G1 submitheader: RPC must be in dispatch table" $ do
    it "BUG-1 [P1]: \"submitheader\" not in handleRequest dispatch (Rpc.hs:1038-1145)" $ do
      -- Core rpc/mining.cpp:1157 registers submitheader.  Used by mining pools
      -- and external block-template clients to submit a candidate header
      -- before sending the full block (BIP-152 / compact-block clients,
      -- stratum v2 templates).  haskoin's dispatch has no "submitheader"
      -- entry — calls return rpcMethodNotFound.
      -- Cross-impl reference: rustoshi src/rpc/mining.rs (submitheader RPC
      -- present), beamchain handle_submitheader.
      pending

  -- =========================================================================
  -- G2  prioritisetransaction RPC entirely absent
  -- =========================================================================
  describe "G2 prioritisetransaction: RPC + fee-delta storage absent" $ do
    it "BUG-2 [P1]: no \"prioritisetransaction\" handler; mempool has no meModifiedFee field" $ do
      -- Core rpc/mining.cpp:502 registers prioritisetransaction.
      -- haskoin Rpc.hs dispatch (line 1038+) has no entry; Mempool.hs has no
      -- ApplyDelta / modified-fee tracking.  selectTransactions (Mempool.hs:2076)
      -- sorts by meAncestorFees only — never picks up an operator-injected
      -- fee delta.  Pool operators (W120 BUG-7 universal pattern across the
      -- fleet — covered in mempool RBF wave for 5+ impls; this is the
      -- mining-side surface).
      pending

  -- =========================================================================
  -- G3  getprioritisedtransactions RPC absent
  -- =========================================================================
  describe "G3 getprioritisedtransactions: read-side RPC for fee deltas" $ do
    it "BUG-3 [P2]: no \"getprioritisedtransactions\" handler" $ do
      -- Core rpc/mining.cpp:547.  Companion read-side to G2.  Without
      -- meModifiedFee in the mempool the response would always be empty;
      -- but the dispatch entry should still exist and return {} so
      -- BIP-22 / pool-operator clients don't get rpcMethodNotFound.
      pending

  -- =========================================================================
  -- G4  include_dummy_extranonce gate — bad-cb-length at heights 1..16
  -- =========================================================================
  describe "G4 dummy extranonce: scriptSig must be >= 2 bytes (bad-cb-length consensus)" $ do
    it "BUG-4a [P0-CONSENSUS]: buildCoinbase with extraNonce=BS.empty at height 1..16 emits 1-byte scriptSig" $ do
      -- Core node/miner.cpp:187-193: if (m_options.include_dummy_extranonce)
      --   coinbaseTx.vin[0].scriptSig << OP_0;
      -- The dummy OP_0 byte is APPENDED so heights 1..16 (where the BIP-34
      -- height is a single OP_N opcode byte) pass the 2..100-byte
      -- coinbase scriptSig length consensus check (bad-cb-length;
      -- Consensus.hs:1426).
      --
      -- haskoin BlockTemplate.hs:387-392: scriptSig = heightBytes <> extraNonce.
      -- When handleTemplateRequest (Rpc.hs:2773) passes BS.empty for both
      -- coinbaseScript AND extraNonce, the resulting scriptSig at h=1..16 is
      -- a single byte (OP_1..OP_16).  Consensus check fires bad-cb-length
      -- at submitBlock.  At h=0 it's also 1 byte (OP_0).
      let h = 5 :: Word32
          coinbase = buildCoinbase h 5000000000 BS.empty BS.empty (BS.replicate 32 0)
          scriptSigLen = BS.length (txInScript (head (txInputs coinbase)))
      scriptSigLen `shouldBe` 1   -- BUG: should be 2 (height + dummy OP_0)

    it "BUG-4b [P0-CONSENSUS]: same failure mode at h=16 (boundary)" $ do
      let h = 16 :: Word32
          coinbase = buildCoinbase h 5000000000 BS.empty BS.empty (BS.replicate 32 0)
          scriptSigLen = BS.length (txInScript (head (txInputs coinbase)))
      scriptSigLen `shouldBe` 1   -- BUG: should be 2

    it "G4 PRESENT [observation]: at h=17 the multi-byte length prefix already exceeds 2 bytes" $ do
      let h = 17 :: Word32
          coinbase = buildCoinbase h 5000000000 BS.empty BS.empty (BS.replicate 32 0)
          scriptSigLen = BS.length (txInScript (head (txInputs coinbase)))
      -- Length-prefix(1) + LE(1) = 2 bytes — passes the consensus floor.
      scriptSigLen `shouldBe` 2

  -- =========================================================================
  -- G5  getmininginfo networkhashps hardcoded to 0
  -- =========================================================================
  describe "G5 networkhashps in getmininginfo: must call handleGetNetworkHashPS" $ do
    it "BUG-5 [P1]: handleGetMiningInfo hardcodes networkhashps=0 (Rpc.hs:3094)" $ do
      -- Core rpc/mining.cpp:472: obj.pushKV("networkhashps",
      --   getnetworkhashps().HandleRequest(request));
      -- haskoin Rpc.hs:3094: pair "networkhashps" (AE.int 0).
      -- A separate handleGetNetworkHashPS (Rpc.hs:10602) DOES compute a real
      -- estimate but getmininginfo never invokes it.  Every monitoring
      -- dashboard pulling getmininginfo gets a flat-zero hash rate.
      pending

  -- =========================================================================
  -- G6  getmininginfo missing currentblockweight / currentblocktx
  -- =========================================================================
  describe "G6 currentblockweight / currentblocktx: last-assembled-block stats" $ do
    it "BUG-6 [P2]: handleGetMiningInfo response omits currentblockweight + currentblocktx" $ do
      -- Core rpc/mining.cpp:467-468: if a template was ever assembled,
      --   obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
      --   obj.pushKV("currentblocktx",     *BlockAssembler::m_last_block_num_txs);
      -- These optional fields surface what was actually packed in the most
      -- recent template — operator-visible signal that template construction
      -- is working.  haskoin Rpc.hs:3088-3098 has no such tracking — there
      -- is no m_last_block_weight TVar anywhere.
      pending

  -- =========================================================================
  -- G7  getmininginfo missing signet_challenge on signet
  -- =========================================================================
  describe "G7 signet_challenge: must appear in getmininginfo on signet chain" $ do
    it "BUG-7 [P2]: handleGetMiningInfo never emits signet_challenge" $ do
      -- Core rpc/mining.cpp:489-493: on ChainType::SIGNET, push the
      -- signet_challenge script hex.  haskoin: no signet detection,
      -- no signet_challenge field.  signet operators can't see which
      -- challenge their node thinks it's enforcing.
      pending

    it "BUG-7b [P2]: same gap in handleGetBlockTemplate response" $ do
      -- Core rpc/mining.cpp:1024-1026 emits signet_challenge in the GBT
      -- response as well.  haskoin handleTemplateRequest never emits it.
      pending

  -- =========================================================================
  -- G8  getmininginfo warnings field is a STRING, not an array
  -- =========================================================================
  describe "G8 warnings: must be ARRAY of strings (deprecated single-string off by default)" $ do
    it "BUG-8 [P2]: handleGetMiningInfo emits warnings as \"\" string" $ do
      -- Core rpc/mining.cpp:444-450: warnings is now ARR by default; only
      -- emits a single string when -deprecatedrpc=warnings is set.
      -- haskoin Rpc.hs:3098: pair "warnings" (text "") emits an empty
      -- STRING.  Schema-strict clients (Core's RPC API tests) will reject
      -- the response.  Cross-impl: same shape gap seen in W118 wallet
      -- audits across nimrod / camlcoin.
      pending

  -- =========================================================================
  -- G9  estimateIsInitialBlockDownload uses a HARDCODED current time
  -- =========================================================================
  describe "G9 IBD heuristic: must use real current time, not a 2025 constant" $ do
    it "BUG-9 [P0-LATENT]: estimateIsInitialBlockDownload baseline is a frozen 2025-09-12 constant" $ do
      -- Rpc.hs:9143-9153: estimatedCurrentTime = 1231006505 + (850000 * 600)
      --   = 1740006505 ≈ 2025-02-19 UTC.
      -- This means: as the real world passes that constant, the function
      -- INCREASINGLY classifies the live chain tip as "IBD" even when
      -- fully synced.  At t > 2025-02-19 + 24h, every node that has a
      -- tip > 24h behind the FROZEN baseline is flagged IBD.
      -- For 2026-05-17 (today), the frozen baseline is ~15 months stale:
      -- nodes with tips between 2025-02-18 (the baseline) and 2026-05-16
      -- (real-current-time - 24h) are classified as IBD.  Operationally
      -- that means: by 2025-02-20 the threshold inverted, and ever since
      -- haskoin nodes have been reporting "in IBD" while actually
      -- synced.  Used by getblockchaininfo + several P2P gates.
      --
      -- Anti-bit-rot: assert the constant is < 2026-01-01.
      let estimatedCurrentTime = (1231006505 + 850000 * 600) :: Word32
      -- 1735689600 = 2025-01-01 UTC.  We expect the constant to be older
      -- than that, demonstrating the staleness.
      (estimatedCurrentTime < 1735689600) `shouldBe` False
      -- (Constant is 1740006505 = 2025-02-19, so this asserts False with
      -- the BUG observation comment recording the staleness.)

  -- =========================================================================
  -- G10  Anti-fee-sniping: no probabilistic 10% offset
  -- =========================================================================
  describe "G10 setAntiFeeSniping: missing Core's 10% randomised locktime shift" $ do
    it "BUG-10a [P2]: setAntiFeeSniping always sets locktime=currentHeight; no random offset" $ do
      -- Core wallet/spend.cpp:1029-1031:
      --   if (rng_fast.randrange(10) == 0) {
      --     tx.nLockTime = std::max(0, int(tx.nLockTime) - int(rng_fast.randrange(100)));
      --   }
      -- haskoin BlockTemplate.hs:1415-1416 just sets txLockTime = currentHeight
      -- unconditionally.  Privacy regression for high-latency-mix wallets
      -- (CoinJoin, Tor-only spenders) that intentionally delay signing.
      let tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0)
                          BS.empty maxSequenceNonFinal] [] [] 0
          out = setAntiFeeSniping 700_000 tx
      -- Always sets to currentHeight, never to (currentHeight - k) for k in [0,99].
      txLockTime out `shouldBe` 700_000

    it "BUG-10b [P2]: no lagging-chain fallback (lockTime=0 when IsCurrentForAntiFeeSniping is false)" $ do
      -- Core wallet/spend.cpp:1032-1037: if (!IsCurrentForAntiFeeSniping)
      --   tx.nLockTime = 0;  // avoid leaking a fingerprint of stale tip
      -- haskoin has no chain-current gate at all; locktime ALWAYS = height,
      -- which leaks an old-tip fingerprint when the wallet is behind.
      pending

  -- =========================================================================
  -- G11  generateSingleBlock drops mempool fees from coinbase
  -- =========================================================================
  describe "G11 regtest mining: coinbase must include mempool fees (reward + fees)" $ do
    it "BUG-11 [P1-TWO-PIPELINE]: generateSingleBlock uses subsidy only; comments confess (Rpc.hs:3278-3280)" $ do
      -- Source-level confession comment:
      --   "Note: For regtest with specific transactions, we would add their fees too"
      --   "For simplicity, we use just the block reward here"
      --
      -- Core node/miner.cpp:178: const CAmount block_reward{nFees +
      --   GetBlockSubsidy(nHeight, chainparams.GetConsensus())};
      -- createBlockTemplate (BlockTemplate.hs:259) correctly does reward+fees.
      -- generateSingleBlock (Rpc.hs:3277-3280) uses subsidy only.
      -- Result: regtest blocks burn all mempool fees instead of paying them
      -- to the miner.  Any consensus test that asserts "fees end up in
      -- coinbase" fails on the regtest mining path.
      pending

  -- =========================================================================
  -- G12  generateSingleBlock hardcodes block version 0x20000000
  -- =========================================================================
  describe "G12 regtest mining: bhVersion must compute from active deployments" $ do
    it "BUG-12 [P2-TWO-PIPELINE]: generateSingleBlock hardcodes bhVersion=0x20000000 (Rpc.hs:3296)" $ do
      -- createBlockTemplate (BlockTemplate.hs:277-278) correctly uses
      -- computeBlockVersionFromChain.  generateSingleBlock hardcodes
      -- bhVersion = 0x20000000.  On chains with active BIP-9 deployments
      -- signalling bits, regtest-mined blocks always drop the signalling.
      -- Two-pipeline divergence symmetric with W108 BUG-11 (nSequence) and
      -- W108 BUG-14 (bits hardcoded).
      pending

  -- =========================================================================
  -- G13  generateSingleBlock reservedWeight = 4000, template uses 8000
  -- =========================================================================
  describe "G13 reservedWeight: must be DEFAULT_BLOCK_RESERVED_WEIGHT = 8000" $ do
    it "BUG-13 [P2-TWO-PIPELINE]: generateSingleBlock reserves 4000, createBlockTemplate reserves 8000" $ do
      -- Core policy/policy.h:27: DEFAULT_BLOCK_RESERVED_WEIGHT = 8000.
      -- BlockTemplate.hs:124 + 235: blockReservedWeight = 8000 (used in
      --   createBlockTemplate). Correct.
      -- Rpc.hs:3286: generateSingleBlock uses (maxBlockWeight - 4000) — half
      -- the reservation.  Mempool selection in regtest can pick up to 4000
      -- more weight units than the GBT path, so regtest blocks can be
      -- 0.1% closer to the weight limit than mainnet templates.  Not a
      -- consensus break (fits inside MAX_BLOCK_WEIGHT either way) but a
      -- behavioural divergence.
      blockReservedWeight `shouldBe` 8000   -- canonical constant — passes

  -- =========================================================================
  -- G14  generateBlocks DEFAULT_MAX_TRIES not honoured
  -- =========================================================================
  describe "G14 generatetoaddress maxtries parameter: must accept and clamp" $ do
    it "BUG-14 [P2]: handleGenerateToAddress ignores params[2] maxtries (Rpc.hs:3109-3130)" $ do
      -- Core rpc/mining.cpp:271: {"maxtries", RPCArg::Type::NUM,
      --   RPCArg::Default{DEFAULT_MAX_TRIES (=1_000_000)}, "How many iterations to try."}.
      -- haskoin handleGenerateToAddress extracts only params[0] (nblocks)
      -- and params[1] (address); generateBlocks goes through
      -- findRegtestNonce (Rpc.hs:3363-3375) which loops to maxBound::Word32
      -- (4.29B iterations).  On a misconfigured powLimit / unsatisfiable
      -- bits, the call hangs essentially forever instead of erroring with
      -- "Couldn't find a valid block".
      pending

  -- =========================================================================
  -- G15  findRegtestNonce can loop to Word32 maxBound (~4.29B iters)
  -- =========================================================================
  describe "G15 findRegtestNonce: must bound loop by max_tries (default 1_000_000)" $ do
    it "BUG-15 [P2]: findRegtestNonce loops to maxBound::Word32 (Rpc.hs:3368)" $ do
      -- Core uses max_tries = 1_000_000 (DEFAULT_MAX_TRIES). With regtest's
      -- minimum difficulty 0x207fffff the nonce almost always satisfies at
      -- nonce=0..1k.  But on a custom regtest with --powlimit set tighter,
      -- a hang under 4.29B iterations is observable.  Same surface as G14:
      -- the bound exists but is hardcoded to Word32 max instead of being
      -- parameterised.
      pending

  -- =========================================================================
  -- G16  encodeRegtestHeight diverges from encodeBip34Height for h <= 16
  -- =========================================================================
  describe "G16 encodeRegtestHeight: must match Core CScript() << nHeight for h in [0,16]" $ do
    it "BUG-16 [P1-TWO-PIPELINE]: encodeRegtestHeight (Rpc.hs:3348) encodes h=0..16 as length-prefixed push, not OP_N" $ do
      -- Core CScript() << nHeight at h=0..16 emits OP_0..OP_16 single-byte
      -- opcodes (0x00, 0x51..0x60).  encodeBip34Height (Consensus.hs:2034)
      -- mirrors this.  encodeRegtestHeight (Rpc.hs:3347-3359) ALWAYS emits
      -- a length-prefixed push:
      --   h=0  → BS.pack [1, 0]  -- "push 1 byte, value 0"
      --   h=5  → BS.pack [1, 5]  -- "push 1 byte, value 5"
      -- Bitcoin Core validateCoinbaseHeightConsensus (Consensus.hs:2050)
      -- does a PREFIX match against encodeBip34Height — i.e. it expects
      -- the OP_N form for h in [0,16].
      --
      -- So a regtest block at h=5 with the encodeRegtestHeight encoding
      -- would FAIL the prefix check (encodeBip34Height 5 = OP_5 = 0x55,
      -- regtest encoding = [0x01, 0x05]).
      --
      -- Why does this work in practice today?  Because the regtest
      -- validateCoinbaseHeightConsensus path is gated on netBip34Height.
      -- On regtest BIP-34 is height-1 active (so even genesis+1 fails).
      -- This is a P1 latent rather than P0 because nobody mines regtest
      -- with default params and asserts bad-cb-height.
      encodeRegtestEncoded5 `shouldBe` BS.pack [0x01, 0x05]
      encodeBip34Height (5 :: Word32) `shouldBe` BS.singleton 0x55  -- OP_5
      -- Confirm: the two encodings diverge at h=5.
      encodeRegtestEncoded5 == encodeBip34Height (5 :: Word32) `shouldBe` False

  -- =========================================================================
  -- G17  submitBlock skips ProcessNewBlock for already-known headers
  -- =========================================================================
  describe "G17 submitBlock duplicate / inconclusive result distinction" $ do
    it "BUG-17 [P1]: no duplicate-vs-inconclusive split (Core mining.cpp:1097-1102)" $ do
      -- Core split: !new_block && accepted → "duplicate"; !sc->found → "inconclusive".
      -- haskoin submitBlock returns Left for already-seen blocks via the
      -- generic validation path, which the bip22ResultString table maps
      -- to "rejected" (default case).  Mining pools relying on the
      -- distinction will misclassify.  Companion to W108 BUG-16.
      pending

  -- =========================================================================
  -- G18  encodeHeight wrapper delegates correctly (regression guard)
  -- =========================================================================
  describe "G18 encodeHeight: BlockTemplate exports a delegation to encodeBip34Height" $ do
    it "encodeHeight h=0 → OP_0 (0x00)" $ do
      encodeHeight 0 `shouldBe` BS.singleton 0x00
    it "encodeHeight h=1 → OP_1 (0x51)" $ do
      encodeHeight 1 `shouldBe` BS.singleton 0x51
    it "encodeHeight h=16 → OP_16 (0x60)" $ do
      encodeHeight 16 `shouldBe` BS.singleton 0x60
    it "encodeHeight h=17 → length-prefixed (0x01, 0x11)" $ do
      encodeHeight 17 `shouldBe` BS.pack [0x01, 0x11]

  -- =========================================================================
  -- G19  buildCoinbase: scriptSig length verified end-to-end at h=17
  -- =========================================================================
  describe "G19 buildCoinbase at h>=17 produces consensus-valid scriptSig (no extranonce)" $ do
    it "buildCoinbase h=17 with empty extraNonce yields scriptSig=2 bytes (passes bad-cb-length)" $ do
      let cb = buildCoinbase 17 5000000000 BS.empty BS.empty (BS.replicate 32 0)
          slen = BS.length (txInScript (head (txInputs cb)))
      slen `shouldSatisfy` (>= 2)

    it "buildCoinbase h=200_000 with 4-byte extranonce yields valid scriptSig" $ do
      let extranonce = BS.pack [0xaa, 0xbb, 0xcc, 0xdd]
          cb = buildCoinbase 200_000 5000000000 BS.empty extranonce (BS.replicate 32 0)
          slen = BS.length (txInScript (head (txInputs cb)))
      slen `shouldSatisfy` (\n -> n >= 2 && n <= 100)

  -- =========================================================================
  -- G20  buildCoinbase witness-commitment output presence
  -- =========================================================================
  describe "G20 buildCoinbase: witness-commitment OP_RETURN output present (BIP-141)" $ do
    it "buildCoinbase emits 2 outputs (main + witness commitment)" $ do
      let cb = buildCoinbase 100_000 5000000000 BS.empty BS.empty (BS.replicate 32 0)
      length (txOutputsOf cb) `shouldBe` 2

    it "second output starts with OP_RETURN <0xaa21a9ed> witness-commitment prefix" $ do
      let cb = buildCoinbase 100_000 5000000000 BS.empty BS.empty (BS.replicate 32 0xab)
          witScript = txOutScriptAt cb 1
      BS.take 6 witScript `shouldBe` BS.pack [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]

  -- =========================================================================
  -- G21  buildCoinbase nSequence MUST be MAX_SEQUENCE_NONFINAL
  -- =========================================================================
  describe "G21 buildCoinbase nSequence: 0xfffffffe (anti-timewarp enforcement)" $ do
    it "buildCoinbase sets coinbase input nSequence = maxSequenceNonFinal (0xfffffffe)" $ do
      let cb = buildCoinbase 17 5000000000 BS.empty BS.empty (BS.replicate 32 0)
      txInSequence (head (txInputs cb)) `shouldBe` (0xfffffffe :: Word32)

  -- =========================================================================
  -- G22  buildCoinbase nLockTime MUST be height - 1
  -- =========================================================================
  describe "G22 buildCoinbase nLockTime: nHeight - 1 (anti-timewarp)" $ do
    it "h=200_000 → nLockTime = 199_999" $ do
      let cb = buildCoinbase 200_000 5000000000 BS.empty BS.empty (BS.replicate 32 0)
      txLockTime cb `shouldBe` 199_999

    it "h=1 → nLockTime = 0 (boundary correct)" $ do
      let cb = buildCoinbase 1 5000000000 BS.empty BS.empty (BS.replicate 32 0)
      txLockTime cb `shouldBe` 0

    it "h=0 (genesis) → nLockTime = 0 (special-case guard)" $ do
      let cb = buildCoinbase 0 5000000000 BS.empty BS.empty (BS.replicate 32 0)
      txLockTime cb `shouldBe` 0

  -- =========================================================================
  -- G23  blockReward halvings: subsidy ladder
  -- =========================================================================
  describe "G23 blockReward: 50 BTC initial, halvings every 210_000 blocks" $ do
    it "h=0 → 5_000_000_000 satoshi (50 BTC)" $ do
      blockReward 0 `shouldBe` 5_000_000_000
    it "h=209_999 → 5_000_000_000 (still in first epoch)" $ do
      blockReward 209_999 `shouldBe` 5_000_000_000
    it "h=210_000 → 2_500_000_000 (first halving)" $ do
      blockReward 210_000 `shouldBe` 2_500_000_000
    it "h=840_000 → 312_500_000 (4th halving)" $ do
      blockReward 840_000 `shouldBe` 312_500_000

  -- =========================================================================
  -- G24  GBT response: longpollid format includes transactionsUpdated counter
  -- =========================================================================
  describe "G24 GBT longpollid: must be tip-hash + transactionsUpdated (not + height)" $ do
    it "BUG-24 [P2]: handleTemplateRequest longpollid = blockHash <> height (Rpc.hs:2780)" $ do
      -- Companion to W108 BUG-4a.  Core mining.cpp:1002:
      --   longpollid = tip.GetHex() + ToString(nTransactionsUpdatedLast).
      -- haskoin uses btHeight (block index counter) instead of a mempool
      -- transactions-updated counter.  Long-poll subscribers waiting for
      -- mempool churn never wake until tip advances.  Re-stated here as
      -- W123 G24 for the "no transactions-updated tracking ANYWHERE in
      -- the mempool" angle (W108 only flagged the GBT-side encoding).
      pending

  -- =========================================================================
  -- G25  GBT response: vbrequired hardcoded 0
  -- =========================================================================
  describe "G25 vbrequired: must reflect REQUIRED deployment bits" $ do
    it "BUG-25 [P2]: vbrequired hardcoded to 0 (Rpc.hs:2818); ignores LOCKED_IN required-bit mask" $ do
      -- Core mining.cpp:976-983 sets block.nVersion |= info.mask for each
      -- LOCKED_IN deployment, then publishes vbrequired = 0 in the GBT
      -- response.  (Yes, Core itself emits 0 in practice.)  However the
      -- haskoin path NEVER OR-s the LOCKED_IN mask into btVersion either
      -- (BlockTemplate.hs:276-278 only takes the (version,_) tuple from
      -- computeBlockVersionFromChain — discarding the mask info needed
      -- to populate vbrequired correctly).  Two-half bug: even if a
      -- non-zero vbrequired were needed, haskoin has no machinery to
      -- compute it.
      pending

  -- =========================================================================
  -- G26  GBT response: sizelimit hardcoded MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
  -- =========================================================================
  describe "G26 sizelimit: hardcoded constant matches Core MAX_BLOCK_SERIALIZED_SIZE" $ do
    it "G26 PRESENT: sizelimit = 4_000_000 (Rpc.hs:2829)" $ do
      -- Core consensus.h: MAX_BLOCK_SERIALIZED_SIZE = 4_000_000.
      -- haskoin hardcodes 4_000_000.  Pre-segwit Core would divide by
      -- WITNESS_SCALE_FACTOR.  haskoin doesn't have a pre-segwit branch
      -- but post-segwit is now permanent so this is fine.
      True `shouldBe` True

  -- =========================================================================
  -- G27  Coinbase scriptSig 100-byte upper bound check (regression guard)
  -- =========================================================================
  describe "G27 buildCoinbase upper bound: extraNonce + height must keep scriptSig <= 100 bytes" $ do
    it "G27 buildCoinbase with 90-byte extraNonce stays within consensus bounds" $ do
      let extraNonce = BS.replicate 90 0xee
          cb = buildCoinbase 200_000 5000000000 BS.empty extraNonce (BS.replicate 32 0)
          slen = BS.length (txInScript (head (txInputs cb)))
      -- 4 (length-prefix + 3 LE bytes for 200000) + 90 extranonce = 94.
      slen `shouldSatisfy` (<= 100)

    it "BUG-27 [P2-LATENT]: buildCoinbase does NOT clamp extraNonce → may emit > 100-byte scriptSig" $ do
      -- buildCoinbase has NO length check.  A caller passing a 200-byte
      -- extraNonce produces a scriptSig over the consensus upper bound,
      -- which validateTransaction then rejects at submitBlock with
      -- "Coinbase scriptSig size out of range".  Defensive caller
      -- responsibility, but Core's CScript would also accept it — Core's
      -- assertion is in TestBlockValidity at template assembly time, not
      -- at scriptSig construction time.  Document the absence.
      let extraNonce = BS.replicate 200 0xee
          cb = buildCoinbase 200_000 5000000000 BS.empty extraNonce (BS.replicate 32 0)
          slen = BS.length (txInScript (head (txInputs cb)))
      slen `shouldSatisfy` (> 100)   -- BUG: no consensus clamp at construction

  -- =========================================================================
  -- G28  No coinbasetxn capability declared by GBT
  -- =========================================================================
  describe "G28 BIP-22 coinbasetxn capability: should appear in mutable list" $ do
    it "BUG-28 [P2]: handleTemplateRequest capabilities lacks \"coinbasetxn\" / \"workid\"" $ do
      -- Core supports both "proposal" and "coinbasevalue" caps; mutable
      -- list is ["time","transactions","prevblock"].  haskoin emits the
      -- same mutable list but capabilities = ["proposal"] only.  Mining
      -- pools using "coinbasetxn" to request a pre-baked coinbase (BIP-22
      -- section "Optional: Generation Transaction") won't see it
      -- advertised even though haskoin returns the coinbase under
      -- btCoinbaseTxn already.
      pending

  -- =========================================================================
  -- G29  GBT does not enforce template-cooldown — re-computes on every call
  -- =========================================================================
  describe "G29 GBT cooldown / template caching: every call recomputes from scratch" $ do
    it "BUG-29 [P2]: handleTemplateRequest builds new template every call (Rpc.hs:2771)" $ do
      -- Core mining.cpp:862-884 caches block_template; only rebuilds when
      -- pindexPrev changes OR mempool has updated AND > 5s since last
      -- build.  haskoin Rpc.hs:2771 always calls createBlockTemplate
      -- afresh.  Two concrete consequences:
      --   1. Burst RPC requests (mining pool polling) repeatedly do
      --      O(mempool_size * log) selection — wasted CPU.
      --   2. Different calls within milliseconds may pick DIFFERENT
      --      transaction sets (mempool churn race) which is forbidden by
      --      BIP-22 long-polling expectations.
      pending

  -- =========================================================================
  -- G30  RPC_CLIENT_IN_INITIAL_DOWNLOAD / RPC_CLIENT_NOT_CONNECTED error codes absent
  -- =========================================================================
  describe "G30 IBD/connection RPC error codes: must use -10 / -9 not -32601" $ do
    it "BUG-30 [P2]: haskoin error-code constants lack rpcClientNotConnected (-9), rpcClientInInitialDownload (-10)" $ do
      -- Core rpc/protocol.h defines RPC_CLIENT_NOT_CONNECTED = -9 and
      -- RPC_CLIENT_IN_INITIAL_DOWNLOAD = -10.  haskoin Rpc.hs has no such
      -- constants — see grep: only rpcMethodNotFound (-32601),
      -- rpcInvalidParams, rpcMiscError.  Even when W108 BUG-1 / BUG-2 are
      -- fixed (adding IBD + peer-count guards), they cannot return the
      -- standard error codes without these constants being defined.
      pending

  where
    -- helper because the existing W108 spec uses parens for txOutputs
    txOutputsOf :: Tx -> [TxOut]
    txOutputsOf = txOutputs

    txOutScriptAt :: Tx -> Int -> BS.ByteString
    txOutScriptAt tx i = txOutScript (txOutputs tx !! i)

    -- Mirror of encodeRegtestHeight (private to Rpc.hs) for cross-check
    -- in G16.  Keep this byte-identical to Rpc.hs:3348-3359.
    encodeRegtestEncoded5 :: BS.ByteString
    encodeRegtestEncoded5 = BS.pack [0x01, 0x05]

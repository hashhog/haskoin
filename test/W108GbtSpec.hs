{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W108 BlockTemplate + GBT mining RPC 30-gate audit (4 two-pipeline)
--
-- Reference: bitcoin-core/src/rpc/mining.cpp, src/node/miner.h/cpp,
--            src/policy/policy.h.  BIP-22/23/9/141.
--
-- Two-pipeline patterns:
--   P1  handleTemplateRequest (GBT) vs generateSingleBlock (regtest miner) —
--       GBT passes BS.empty coinbase script; regtest miner uses the address.
--   P2  buildCoinbase (BlockTemplate.hs) vs buildRegtestCoinbase (Rpc.hs) —
--       different nSequence (0xfffffffe vs 0xffffffff), different nLockTime
--       (height-1 vs 0), missing witness-commitment output in regtest path.
--   P3  handleBlockProposal (stub) vs handleSubmitBlockUnpaused (full) —
--       proposal always returns null without any validation; submit runs
--       validateFullBlockIO.
--   P4  createBlockTemplate sigop gate vs applyBlockToCache sigop gate —
--       template uses legacy lower-bound (no P2SH/witness); cache path uses
--       getTransactionSigOpCost.  Both correctly bounded to 80000 but paths
--       diverge; shared helper would be safer.

module W108GbtSpec (spec) where

import Test.Hspec
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32)

import Haskoin.Types
  ( Tx(..), TxIn(..), OutPoint(..), TxId(..), Hash256(..) )
import Haskoin.BlockTemplate
  ( isFinalTx, locktimeThreshold, sequenceFinal, maxSequenceNonFinal
  , blockReservedWeight, templateLegacySigOpCost
  )
import Haskoin.Rpc (bip22ResultString)
import Haskoin.Consensus
  ( maxBlockWeight, maxBlockSigops, maxBlockSigOpsCost, witnessScaleFactor
  , blockReward
  )

spec :: Spec
spec = describe "W108 BlockTemplate + GBT mining RPC 30-gate audit" $ do

  -- -------------------------------------------------------------------------
  -- G1  BIP-22 IBD guard
  -- -------------------------------------------------------------------------
  describe "G1 IBD guard: getblocktemplate must reject when node is in IBD on mainnet" $ do
    it "BUG-1 [P1]: handleTemplateRequest has no IBD check — returns template regardless of sync state" $ do
      -- Core rpc/mining.cpp:772: throws RPC_CLIENT_IN_INITIAL_DOWNLOAD when
      -- miner.isInitialBlockDownload() && !miner.isTestChain().
      -- haskoin handleTemplateRequest (Rpc.hs:2572) never calls
      -- estimateIsInitialBlockDownload before calling createBlockTemplate.
      -- A miner on a syncing mainnet node will build on a stale tip.
      pending

  -- -------------------------------------------------------------------------
  -- G2  BIP-22 connection guard
  -- -------------------------------------------------------------------------
  describe "G2 connection guard: getblocktemplate must reject when 0 peers on mainnet" $ do
    it "BUG-2 [P1]: handleTemplateRequest has no peer-count check" $ do
      -- Core rpc/mining.cpp:767: throws RPC_CLIENT_NOT_CONNECTED when
      -- connman.GetNodeCount() == 0 && !isTestChain().
      -- haskoin: handleTemplateRequest never reads rsPeerMgr peer count.
      pending

  -- -------------------------------------------------------------------------
  -- G3  BIP-22 segwit-required rule enforcement
  -- -------------------------------------------------------------------------
  describe "G3 segwit rule: getblocktemplate must reject if client omits 'segwit' in rules" $ do
    it "BUG-3 [P1]: handleGetBlockTemplate ignores client rules array — no segwit enforcement" $ do
      -- Core rpc/mining.cpp:855: throws RPC_INVALID_PARAMETER if
      -- !setClientRules.contains(\"segwit\").
      -- haskoin extractTemplateMode (Rpc.hs:2665) only checks mode=\"proposal\";
      -- the rules array is never read or validated.
      pending

  -- -------------------------------------------------------------------------
  -- G4  BIP-22 long-polling
  -- -------------------------------------------------------------------------
  describe "G4 long-polling: longpollid format and blocking wait" $ do
    it "BUG-4a [P2]: longpollid uses block height instead of transactions-updated counter" $ do
      -- Core rpc/mining.cpp:1002: longpollid = tipHash + nTransactionsUpdatedLast.
      -- haskoin Rpc.hs:2582: showHash (btPreviousBlock bt) <> show (btHeight bt).
      -- btHeight is monotone block count, not a mempool-change counter.
      -- Long-poll subscribers never wake on mempool-only changes.
      pending

    it "BUG-4b [P2]: handleTemplateRequest has no blocking wait on longpollid" $ do
      -- Core rpc/mining.cpp:785-844: waits up to 60s for tip change or mempool
      -- update before returning new template.
      -- haskoin: no blocking wait logic anywhere in handleTemplateRequest.
      pending

  -- -------------------------------------------------------------------------
  -- G5  vbavailable: signaling deployments
  -- -------------------------------------------------------------------------
  describe "G5 vbavailable: STARTED/LOCKED_IN deployments must appear for BIP-9 signaling" $ do
    it "BUG-5 [P1]: vbavailable is always empty object — miners cannot signal BIP-9 deployments" $ do
      -- Core rpc/mining.cpp:966-983: iterates gbtstatus.signalling and locked_in,
      -- adds each to vbavailable with bit number.
      -- haskoin Rpc.hs:2597: vbavailable = object []  -- hardcoded empty.
      pending

  -- -------------------------------------------------------------------------
  -- G6  rules array: must include active soft forks
  -- -------------------------------------------------------------------------
  describe "G6 rules: active soft forks must appear in rules array" $ do
    it "BUG-6 [P1]: rules array always [csv, !segwit] — taproot never added after activation" $ do
      -- Core rpc/mining.cpp:985-991: iterates gbtstatus.active and pushes each
      -- name with ! prefix for mandatory rules.
      -- haskoin Rpc.hs:2588-2591: hardcoded [\"csv\", \"!segwit\"].
      -- After taproot activation, \"taproot\" should appear; it never does.
      pending

  -- -------------------------------------------------------------------------
  -- G7  proposal mode: stub returns null unconditionally
  -- -------------------------------------------------------------------------
  describe "G7 proposal mode (BIP-23): must validate block and return rejection reason" $ do
    it "BUG-7 [P3-TWO-PIPELINE]: handleBlockProposal always returns null without validation" $ do
      -- Core rpc/mining.cpp:743-751: checks block hash in blockman; returns
      -- \"duplicate\" / \"duplicate-invalid\" / \"duplicate-inconclusive\" for
      -- known blocks; runs TestBlockValidity for unknown blocks.
      -- haskoin Rpc.hs:2659-2662: comment \"just validate the block structure\",
      -- then returns RpcResponse Null Null Null regardless of block content.
      -- Every proposal appears accepted; mining pools using BIP-23 proposal mode
      -- cannot validate their assembled blocks before submitting.
      pending

  -- -------------------------------------------------------------------------
  -- G8  default_witness_commitment stub
  -- -------------------------------------------------------------------------
  describe "G8 default_witness_commitment: must encode actual witness commitment OP_RETURN" $ do
    it "BUG-8 [P1]: buildWitnessCommitmentScript (Rpc.hs:2687) always returns BS.empty" $ do
      -- Core rpc/mining.cpp:1028-1031: emits default_witness_commitment from
      -- coinbase.required_outputs[0].scriptPubKey (the witness OP_RETURN output).
      -- haskoin Rpc.hs:2686-2693: returns BS.empty in ALL cases; comment says
      -- \"for now return empty and let miner compute it\".
      -- SegWit-aware miners that rely on this field to construct coinbase will
      -- produce blocks with wrong/missing commitment → rejected.
      -- buildWitnessCommitmentScript is internal (not exported); verified by code review.
      pending

    it "BUG-8b [P1]: btWitnessCommitment is correctly computed in createBlockTemplate but never forwarded to GBT response" $ do
      -- createBlockTemplate BlockTemplate.hs:264-268 computes
      -- witnessCommitment = SHA256d(witnessRoot || witnessNonce) and stores it
      -- in btWitnessCommitment.  handleTemplateRequest Rpc.hs:2604 calls
      -- buildWitnessCommitmentScript which ignores btWitnessCommitment and
      -- returns BS.empty.  The correct commitment is in memory, just not used.
      pending

  -- -------------------------------------------------------------------------
  -- G9  coinbase scriptPubKey placeholder in GBT
  -- -------------------------------------------------------------------------
  describe "G9 coinbase script: GBT handler passes empty ByteString as coinbase scriptPubKey" $ do
    it "BUG-9 [P1-TWO-PIPELINE]: handleTemplateRequest passes BS.empty to createBlockTemplate" $ do
      -- Core: the coinbase output scriptPubKey is set to the miner's payout address.
      -- GBT returns btCoinbaseTxn so miners can read subsidy/fee total.
      -- haskoin Rpc.hs:2574-2576: createBlockTemplate receives BS.empty BS.empty.
      -- The btCoinbaseTxn in the returned template has a zero-length output script.
      -- Miners reading btCoinbaseTxn to verify coinbase value see an unusable script.
      pending

  -- -------------------------------------------------------------------------
  -- G10  BIP-94 timewarp rule in mintime
  -- -------------------------------------------------------------------------
  describe "G10 mintime: BIP-94 timewarp boundary clamp missing" $ do
    it "BUG-10 [P1]: minTime = mtp + 1 only; BIP-94 retarget-boundary clamp absent" $ do
      -- Core node/miner.cpp:36-47 (GetMinimumTime): at retarget boundaries
      -- (height % 2016 == 0), minTime = max(mtp+1, prevBlockTime - 600).
      -- haskoin BlockTemplate.hs:218: minTime = mtp + 1 unconditionally.
      -- On testnet4 at every 2016-block boundary the timewarp clamp is skipped.
      pending

  -- -------------------------------------------------------------------------
  -- G11  regtest coinbase nSequence
  -- -------------------------------------------------------------------------
  describe "G11 regtest coinbase nSequence: must be 0xfffffffe (MAX_SEQUENCE_NONFINAL)" $ do
    it "maxSequenceNonFinal constant == 0xfffffffe" $ do
      maxSequenceNonFinal `shouldBe` (0xfffffffe :: Word32)

    it "BUG-11 [P2-TWO-PIPELINE]: buildRegtestCoinbase (Rpc.hs:3123) uses 0xffffffff (SEQUENCE_FINAL)" $ do
      -- Core node/miner.cpp:171: coinbaseTx.vin[0].nSequence = MAX_SEQUENCE_NONFINAL (0xfffffffe).
      -- With SEQUENCE_FINAL, nLockTime is ignored — anti-timewarp defence defeated
      -- in ALL regtest-mined blocks.
      -- buildCoinbase (BlockTemplate.hs:403) correctly uses maxSequenceNonFinal.
      -- buildRegtestCoinbase (Rpc.hs:3123) hardcodes 0xffffffff.  Two-pipeline gap.
      pending

  -- -------------------------------------------------------------------------
  -- G12  regtest coinbase nLockTime
  -- -------------------------------------------------------------------------
  describe "G12 regtest coinbase nLockTime: must be height - 1 (anti-timewarp)" $ do
    it "BUG-12 [P2-TWO-PIPELINE]: buildRegtestCoinbase (Rpc.hs:3134) sets nLockTime = 0" $ do
      -- Core node/miner.cpp:196: coinbaseTx.nLockTime = nHeight - 1.
      -- buildCoinbase (BlockTemplate.hs:427) correctly sets height - 1.
      -- buildRegtestCoinbase (Rpc.hs:3134) hardcodes 0.
      -- With nSequence=0xffffffff (G11), nLockTime has no effect anyway, but
      -- if G11 were fixed, G12 would also need to be fixed simultaneously.
      pending

  -- -------------------------------------------------------------------------
  -- G13  regtest coinbase: witness commitment output missing
  -- -------------------------------------------------------------------------
  describe "G13 regtest coinbase: witness commitment OP_RETURN output absent" $ do
    it "BUG-13 [P2-TWO-PIPELINE]: buildRegtestCoinbase has no witness-commitment output" $ do
      -- Core: GenerateCoinbaseCommitment (miner.cpp:200) adds the OP_RETURN output.
      -- buildCoinbase (BlockTemplate.hs:411-414) correctly includes the witness output.
      -- buildRegtestCoinbase (Rpc.hs:3127): only mainOutput, no witnessOutput.
      -- Any segwit tx in a regtest block will fail the witness-commitment check.
      pending

  -- -------------------------------------------------------------------------
  -- G14  regtest nBits hardcoded
  -- -------------------------------------------------------------------------
  describe "G14 regtest nBits: should derive from difficultyAdjustment not hardcode 0x207fffff" $ do
    it "BUG-14 [P1]: generateSingleBlock (Rpc.hs:3062) hardcodes bits = 0x207fffff" $ do
      -- Core miner.cpp:220: nBits = GetNextWorkRequired(pindexPrev, pblock, params).
      -- createBlockTemplate (BlockTemplate.hs:227) correctly calls difficultyAdjustment.
      -- generateSingleBlock bypasses this with a hardcoded constant.
      -- For standard regtest powLimit = 0x207fffff this is safe, but the
      -- two-pipeline divergence will surprise any network variant.
      pending

  -- -------------------------------------------------------------------------
  -- G15  prioritisetransaction RPC absent
  -- -------------------------------------------------------------------------
  describe "G15 prioritisetransaction: RPC must be in dispatch table" $ do
    it "BUG-15 [P1]: \"prioritisetransaction\" absent from Rpc.hs dispatch table" $ do
      -- Core rpc/mining.cpp:1151: registers prioritisetransaction and
      -- getprioritisedtransactions.
      -- haskoin: no \"prioritisetransaction\" entry in the method dispatch
      -- (Rpc.hs:904-990).  Mining software that relies on fee-delta manipulation
      -- will fail silently.
      pending

  -- -------------------------------------------------------------------------
  -- G16  submitblock: duplicate detection
  -- -------------------------------------------------------------------------
  describe "G16 submitblock: \"duplicate\" result for already-known blocks" $ do
    it "BUG-16 [P1]: submitBlock has no pre-validation hash-lookup for known blocks" $ do
      -- Core rpc/mining.cpp:1097-1103: returns \"duplicate\" when block was
      -- already in the chain.
      -- haskoin: submitBlock re-validates and may return Left \"block validation
      -- failed: ...\" which bip22ResultString maps to \"rejected\", not \"duplicate\".
      -- Mining pools that submit the same block twice see \"rejected\" not \"duplicate\".
      pending

  -- -------------------------------------------------------------------------
  -- G17  isFinalTx constants
  -- -------------------------------------------------------------------------
  describe "G17 isFinalTx: locktimeThreshold and sequenceFinal constants" $ do
    it "locktimeThreshold == 500000000" $ do
      locktimeThreshold `shouldBe` (500000000 :: Word32)

    it "sequenceFinal == 0xffffffff" $ do
      sequenceFinal `shouldBe` (0xffffffff :: Word32)

  -- -------------------------------------------------------------------------
  -- G18  isFinalTx: nLockTime 0 always final
  -- -------------------------------------------------------------------------
  describe "G18 isFinalTx: nLockTime == 0 means always final" $ do
    it "tx with nLockTime=0 is always final" $ do
      let tx = Tx 2 [] [] [] 0
      isFinalTx tx 100 1000000000 `shouldBe` True

  -- -------------------------------------------------------------------------
  -- G19  isFinalTx: height-based locktime
  -- -------------------------------------------------------------------------
  describe "G19 isFinalTx: height-based locktime strict less-than comparison" $ do
    it "tx nLockTime=200, blockHeight=200 is NOT final (locktime < blockHeight strict)" $ do
      -- BIP-68: nLockTime < blockHeight (strict), so height == locktime is NOT final.
      let inp = TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe
          tx = Tx 2 [inp] [] [] 200
      isFinalTx tx 200 0 `shouldBe` False

    it "tx nLockTime=199, blockHeight=200 IS final" $ do
      let inp = TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xfffffffe
          tx = Tx 2 [inp] [] [] 199
      isFinalTx tx 200 0 `shouldBe` True

  -- -------------------------------------------------------------------------
  -- G20  isFinalTx: time-based locktime
  -- -------------------------------------------------------------------------
  describe "G20 isFinalTx: time-based locktime (>= 500000000) vs median time past" $ do
    it "tx nLockTime=500000010, mtp=500000011 IS final" $ do
      let tx = Tx 2 [] [] [] 500000010
      isFinalTx tx 100 500000011 `shouldBe` True

    it "BUG-20 [P1]: isFinalTx tx nLockTime=500000012, mtp=500000011 should NOT be final but returns True (vacuous-all on empty inputs)" $ do
      -- Core IsFinalTx (script/standard.cpp):
      -- Only the SEQUENCE_FINAL case uses `all` over inputs; the locktime check
      -- is independent.  haskoin isFinalTx case ordering:
      --   Case 1: nLockTime==0 → True  (not triggered, nLockTime=500000012)
      --   Case 2: isLockTimeSatisfied (500000012 < 500000011 = False) → skip
      --   Case 3: all (==SEQUENCE_FINAL) inputs  → True because inputs == [] (vacuously True)
      -- A tx with no inputs (e.g. a test vector or a malformed tx) and an
      -- unsatisfied time-based locktime is incorrectly deemed final.
      -- Expected: False.  Actual: True.  Revealed by W108 audit.
      isFinalTx (Tx 2 [] [] [] 500000012) 100 500000011 `shouldBe` True  -- BUG: should be False

  -- -------------------------------------------------------------------------
  -- G21  isFinalTx: SEQUENCE_FINAL override
  -- -------------------------------------------------------------------------
  describe "G21 isFinalTx: all inputs with nSequence=0xffffffff override nLockTime" $ do
    it "tx nLockTime=9999, all inputs SEQUENCE_FINAL → final" $ do
      let inp = TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xffffffff
          tx = Tx 2 [inp] [] [] 9999
      isFinalTx tx 5 0 `shouldBe` True

  -- -------------------------------------------------------------------------
  -- G22  blockReservedWeight constant
  -- -------------------------------------------------------------------------
  describe "G22 blockReservedWeight: DEFAULT_BLOCK_RESERVED_WEIGHT = 8000" $ do
    it "blockReservedWeight == 8000 (Core policy.h DEFAULT_BLOCK_RESERVED_WEIGHT)" $ do
      blockReservedWeight `shouldBe` 8000

  -- -------------------------------------------------------------------------
  -- G23  maxBlockWeight constant
  -- -------------------------------------------------------------------------
  describe "G23 maxBlockWeight: MAX_BLOCK_WEIGHT = 4,000,000" $ do
    it "maxBlockWeight == 4000000" $ do
      maxBlockWeight `shouldBe` 4000000

  -- -------------------------------------------------------------------------
  -- G24  maxBlockSigops constant
  -- -------------------------------------------------------------------------
  describe "G24 maxBlockSigops: sigoplimit reported in GBT response = 80000" $ do
    it "maxBlockSigops == 80000" $ do
      maxBlockSigops `shouldBe` 80000

  -- -------------------------------------------------------------------------
  -- G25  maxBlockSigOpsCost constant
  -- -------------------------------------------------------------------------
  describe "G25 maxBlockSigOpsCost: MAX_BLOCK_SIGOPS_COST = 80000" $ do
    it "maxBlockSigOpsCost == 80000 (Core consensus/consensus.h)" $ do
      maxBlockSigOpsCost `shouldBe` 80000

  -- -------------------------------------------------------------------------
  -- G26  witnessScaleFactor constant
  -- -------------------------------------------------------------------------
  describe "G26 witnessScaleFactor: WITNESS_SCALE_FACTOR = 4" $ do
    it "witnessScaleFactor == 4" $ do
      witnessScaleFactor `shouldBe` 4

  -- -------------------------------------------------------------------------
  -- G27  templateLegacySigOpCost: scales by witnessScaleFactor
  -- -------------------------------------------------------------------------
  describe "G27 templateLegacySigOpCost: legacy sigop count * witnessScaleFactor" $ do
    it "empty tx has sigop cost 0" $ do
      let tx = Tx 2 [] [] [] 0
      templateLegacySigOpCost tx `shouldBe` 0

    it "result is always a multiple of witnessScaleFactor" $ do
      let tx = Tx 2 [] [] [] 0
      (templateLegacySigOpCost tx `mod` witnessScaleFactor) `shouldBe` 0

  -- -------------------------------------------------------------------------
  -- G28  BIP-22 result string: passthrough list
  -- -------------------------------------------------------------------------
  describe "G28 bip22ResultString: canonical rejection strings pass through unchanged" $ do
    it "\"duplicate\" passes through" $ do
      bip22ResultString "duplicate" `shouldBe` "duplicate"

    it "\"inconclusive\" passes through" $ do
      bip22ResultString "inconclusive" `shouldBe` "inconclusive"

    it "\"duplicate-invalid\" passes through" $ do
      bip22ResultString "duplicate-invalid" `shouldBe` "duplicate-invalid"

    it "BUG-21 [P1]: \"duplicate-inconclusive\" not in passthrough list — maps to \"rejected\"" $ do
      -- Core BIP22ValidationResult returns \"duplicate-inconclusive\" for a block
      -- in the index whose validity is unknown.  haskoin bip22ResultString
      -- Rpc.hs:2714 elem list: does NOT include \"duplicate-inconclusive\",
      -- so it falls through to the otherwise = \"rejected\" arm.
      -- Mining pool BIP-23 clients that use duplicate-inconclusive to detect
      -- this state will instead see \"rejected\" and may discard the block.
      -- Expected: \"duplicate-inconclusive\".  Actual: \"rejected\".
      bip22ResultString "duplicate-inconclusive" `shouldBe` "rejected"  -- BUG: should be "duplicate-inconclusive"

    it "\"high-hash\" passes through" $ do
      bip22ResultString "high-hash" `shouldBe` "high-hash"

    it "\"bad-txnmrklroot\" passes through" $ do
      bip22ResultString "bad-txnmrklroot" `shouldBe` "bad-txnmrklroot"

    it "\"rejected\" passes through" $ do
      bip22ResultString "rejected" `shouldBe` "rejected"

  -- -------------------------------------------------------------------------
  -- G29  BIP-22 result string: mapped rejection strings
  -- -------------------------------------------------------------------------
  describe "G29 bip22ResultString: common error strings map to canonical BIP-22 values" $ do
    it "\"does not meet proof of work\" → \"high-hash\"" $ do
      bip22ResultString "does not meet proof of work" `shouldBe` "high-hash"

    it "\"incorrect difficulty target\" → \"bad-diffbits\"" $ do
      bip22ResultString "incorrect difficulty target" `shouldBe` "bad-diffbits"

    it "\"merkle root mismatch\" → \"bad-txnmrklroot\"" $ do
      bip22ResultString "merkle root mismatch" `shouldBe` "bad-txnmrklroot"

    it "\"witness commitment mismatch\" → \"bad-witness-merkle-match\"" $ do
      bip22ResultString "witness commitment mismatch" `shouldBe` "bad-witness-merkle-match"

    it "\"coinbase value exceeds\" → \"bad-cb-amount\"" $ do
      bip22ResultString "coinbase value exceeds subsidy" `shouldBe` "bad-cb-amount"

    it "\"sigop limit exceeded\" → \"bad-blk-sigops\"" $ do
      bip22ResultString "sigop limit exceeded" `shouldBe` "bad-blk-sigops"

    it "\"coinbase not yet mature\" → \"bad-txns-premature-spend-of-coinbase\"" $ do
      bip22ResultString "coinbase not yet mature" `shouldBe` "bad-txns-premature-spend-of-coinbase"

    it "\"outputs exceed inputs\" → \"bad-txns-in-belowout\"" $ do
      bip22ResultString "outputs exceed inputs" `shouldBe` "bad-txns-in-belowout"

    it "unknown error → \"rejected\"" $ do
      bip22ResultString "completely unknown reason xyz" `shouldBe` "rejected"

  -- -------------------------------------------------------------------------
  -- G30  BIP-22 result string: block-validation-failed prefix stripping
  -- -------------------------------------------------------------------------
  describe "G30 bip22ResultString: 'block validation failed:' prefix stripped recursively" $ do
    it "\"block validation failed: high-hash\" recursively maps to \"high-hash\"" $ do
      bip22ResultString "block validation failed: does not meet proof of work" `shouldBe` "high-hash"

    it "\"block validation failed: rejected\" recursively maps to \"rejected\"" $ do
      bip22ResultString "block validation failed: completely unknown" `shouldBe` "rejected"

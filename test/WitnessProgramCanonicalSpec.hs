{-# LANGUAGE OverloadedStrings #-}
-- | Witness-program detection must be Core's byte-exact test, in sigop
-- counting and in script classification.
--
-- Bitcoin Core @CScript::IsWitnessProgram@ (script/script.cpp:249):
--
-- >  size in [4, 42]; byte[0] is OP_0 or OP_1..OP_16; byte[1] + 2 == size
--
-- i.e. the program is ONE DIRECT push.  @CountWitnessSigOps@
-- (script/interpreter.cpp:2139) counts witness sigops only for scripts that
-- pass it (natively, and for the last scriptSig push of a P2SH spend), and
-- Core's Solver uses the same test, so @OP_0 OP_PUSHDATA1 0x14 <20>@ is
-- NONSTANDARD, not WITNESS_V0_KEYHASH.
--
-- Before the fix 'classifyOutput' matched @[OP_0, OP_PUSHDATA h _]@ (any
-- push encoding) as P2WPKH/P2WSH, and the same for P2TR/P2A.
-- 'countWitnessSigOps' consulted 'classifyOutput', so every spend of
-- @00 4c 14 <20>@ cost 1 witness sigop in haskoin and 0 in Core.  A block at
-- exactly MAX_BLOCK_SIGOPS_COST under Core's rule was rejected bad-blk-sigops
-- by haskoin: a consensus split (diff-test corpus
-- tools/diff-test-corpus/sigops-witness-noncanonical, Core v31.99 ACCEPTs).
module WitnessProgramCanonicalSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

import Haskoin.Types (Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..),
                      Hash256(..), Hash160(..))
import Haskoin.Crypto (hash160)
import Haskoin.Script (ScriptType(..), classifyOutput, decodeScript,
                       isWitnessProgram)
import Haskoin.Consensus (getTransactionSigOpCost, SigOpCost(..),
                          consensusFlagsAtHeight, regtest)

prog20, prog32 :: BS.ByteString
prog20 = BS.replicate 20 0x11
prog32 = BS.replicate 32 0x22

-- Canonical (direct push) and non-canonical (OP_PUSHDATA1) forms.
p2wpkhDirect, p2wpkhPd1, p2wshDirect, p2wshPd1, p2trDirect, p2trPd1,
  p2aDirect, p2aPd1 :: BS.ByteString
p2wpkhDirect = BS.concat [BS.pack [0x00, 0x14], prog20]
p2wpkhPd1    = BS.concat [BS.pack [0x00, 0x4c, 0x14], prog20]
p2wshDirect  = BS.concat [BS.pack [0x00, 0x20], prog32]
p2wshPd1     = BS.concat [BS.pack [0x00, 0x4c, 0x20], prog32]
p2trDirect   = BS.concat [BS.pack [0x51, 0x20], prog32]
p2trPd1      = BS.concat [BS.pack [0x51, 0x4c, 0x20], prog32]
p2aDirect    = BS.pack [0x51, 0x02, 0x4e, 0x73]
p2aPd1       = BS.pack [0x51, 0x4c, 0x02, 0x4e, 0x73]

classify :: BS.ByteString -> ScriptType
classify bs = either (error . ("decodeScript: " ++)) classifyOutput (decodeScript bs)

p2shOf :: BS.ByteString -> BS.ByteString
p2shOf redeem = BS.concat [BS.pack [0xa9, 0x14], getHash160 (hash160 redeem), BS.pack [0x87]]

-- | Witness-sigop cost of ONE input spending @spk@ with @scriptSig@/@witness@.
-- The tx has a single OP_TRUE output, so its legacy count is 0 and the P2SH
-- count of these redeemScripts is 0: the whole cost is the witness count.
spendCost :: BS.ByteString -> BS.ByteString -> [BS.ByteString] -> Int
spendCost spk scriptSig witness =
  let op = OutPoint (TxId (Hash256 (BS.replicate 32 0xab))) 0
      tx = Tx { txVersion = 2
              , txInputs = [TxIn op scriptSig 0xffffffff]
              , txOutputs = [TxOut 1000 (BS.pack [0x51])]
              , txWitness = [witness]
              , txLockTime = 0 }
      SigOpCost c = getTransactionSigOpCost tx (Map.singleton op (TxOut 2000 spk))
                                            (consensusFlagsAtHeight regtest 200)
  in c

-- push of a <= 75-byte item (direct push)
pushDirect :: BS.ByteString -> BS.ByteString
pushDirect b = BS.cons (fromIntegral (BS.length b)) b

spec :: Spec
spec = do
  describe "WitnessProgramCanonical witness sigops need a DIRECT-push program" $ do
    -- Positive controls: the canonical forms DO count (the counter is live).
    it "canonical P2WPKH spend costs 1 (control)" $
      spendCost p2wpkhDirect "" ["sig", "pubkey"] `shouldBe` 1
    it "canonical P2SH-P2WPKH spend costs 1 (control)" $
      spendCost (p2shOf p2wpkhDirect) (pushDirect p2wpkhDirect) ["sig", "pubkey"]
        `shouldBe` 1
    it "canonical P2WSH spend counts the witnessScript (2 x CHECKSIG = 2, control)" $
      spendCost p2wshDirect "" [BS.pack [0xac, 0xac]] `shouldBe` 2

    -- The split: Core's IsWitnessProgram rejects these, CountWitnessSigOps = 0.
    it "OP_0 OP_PUSHDATA1 <20> spend costs 0 (Core: not a witness program)" $
      spendCost p2wpkhPd1 "" [] `shouldBe` 0
    it "P2SH-wrapped OP_0 OP_PUSHDATA1 <20> spend costs 0" $
      spendCost (p2shOf p2wpkhPd1) (pushDirect p2wpkhPd1) [] `shouldBe` 0
    it "OP_0 OP_PUSHDATA1 <32> spend with a witness costs 0" $
      spendCost p2wshPd1 "" [BS.pack [0xac, 0xac]] `shouldBe` 0
    it "P2SH-wrapped OP_0 OP_PUSHDATA1 <32> spend with a witness costs 0" $
      spendCost (p2shOf p2wshPd1) (pushDirect p2wshPd1) [BS.pack [0xac, 0xac]]
        `shouldBe` 0

  describe "WitnessProgramCanonical classifyOutput matches Core's Solver" $ do
    it "direct forms keep their types" $ do
      classify p2wpkhDirect `shouldBe` P2WPKH (Hash160 prog20)
      classify p2wshDirect  `shouldBe` P2WSH (Hash256 prog32)
      classify p2trDirect   `shouldBe` P2TR (Hash256 prog32)
      classify p2aDirect    `shouldBe` P2A
    it "OP_PUSHDATA1 forms are NONSTANDARD, not witness types" $ do
      classify p2wpkhPd1 `shouldBe` NonStandard
      classify p2wshPd1  `shouldBe` NonStandard
      classify p2trPd1   `shouldBe` NonStandard
      classify p2aPd1    `shouldBe` NonStandard
    it "isWitnessProgram agrees (byte[1] + 2 == size)" $ do
      fmap isWitnessProgram (decodeScript p2wpkhPd1) `shouldBe` Right Nothing
      fmap isWitnessProgram (decodeScript p2wpkhDirect) `shouldBe` Right (Just (0, prog20))
    it "P2PKH / P2PK with a non-direct push are NONSTANDARD (Core MatchPayToPubkeyHash/MatchPayToPubkey)" $ do
      let pkh = BS.concat [BS.pack [0x76, 0xa9, 0x4c, 0x14], prog20, BS.pack [0x88, 0xac]]
          pk  = BS.concat [BS.pack [0x4c, 0x21, 0x02], BS.replicate 32 0x33, BS.pack [0xac]]
      classify pkh `shouldBe` NonStandard
      classify pk  `shouldBe` NonStandard
      classify (BS.concat [BS.pack [0x76, 0xa9, 0x14], prog20, BS.pack [0x88, 0xac]])
        `shouldBe` P2PKH (Hash160 prog20)

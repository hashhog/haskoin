{-# LANGUAGE OverloadedStrings #-}

-- | Bug-hunt 2026-06-14 (WITNESS_MALLEATED_P2SH, findings 3B/4A/5A).
-- Core (interpreter.cpp:2082-2086) requires a P2SH-wrapped witness scriptSig to be
-- EXACTLY the minimal canonical push of the redeemScript; a non-canonical push
-- (OP_PUSHDATA1 of a 22-byte program) must be rejected with WITNESS_MALLEATED_P2SH.
-- haskoin's guard was @Script [OP_PUSHDATA d _] | d == wpBytes@ which ignored the
-- push TYPE, so an OP_PUSHDATA1 push of the redeemScript was wrongly ACCEPTED.
-- MINIMALDATA is policy-only (not in block flags), so this byte-exact check is the
-- only guard under block validation -> a malleated-scriptSig block split the chain.
module W179P2SHMalleationSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.Set as Set
import Data.Word (Word64)
import Haskoin.Types (Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..), Hash160(..))
import Haskoin.Crypto (computeTxId, hash160)
import Haskoin.Script

-- Minimal tx builders (mirrors test/ScriptVectors.hs, which is `module Main`).
buildCreditingTx :: BS.ByteString -> Word64 -> Tx
buildCreditingTx spk amount = Tx
  { txVersion  = 1
  , txInputs   = [TxIn
      { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
      , txInScript     = BS.pack [0x00, 0x00]
      , txInSequence   = 0xffffffff }]
  , txOutputs  = [TxOut { txOutValue = amount, txOutScript = spk }]
  , txWitness  = [[]]
  , txLockTime = 0 }

buildSpendingTx :: Tx -> BS.ByteString -> [[BS.ByteString]] -> Word64 -> Tx
buildSpendingTx credit ssig wit amount = Tx
  { txVersion  = 1
  , txInputs   = [TxIn
      { txInPrevOutput = OutPoint (computeTxId credit) 0
      , txInScript     = ssig
      , txInSequence   = 0xffffffff }]
  , txOutputs  = [TxOut { txOutValue = amount, txOutScript = BS.empty }]
  , txWitness  = wit
  , txLockTime = 0 }

spec :: Spec
spec = describe "W179 WITNESS_MALLEATED_P2SH (P2SH-wrapped witness scriptSig must be canonical)" $ do
  let keyHash      = BS.replicate 20 0xab
      w            = BS.pack [0x00, 0x14] <> keyHash            -- redeemScript: OP_0 <20-byte hash> (22 bytes)
      Hash160 h160 = hash160 w
      spk          = BS.pack [0xa9, 0x14] <> h160 <> BS.pack [0x87]  -- OP_HASH160 <h> OP_EQUAL
      canonical    = BS.pack [0x16] <> w                        -- minimal direct push (0x16 = 22)
      malleated    = BS.pack [0x4c, 0x16] <> w                  -- OP_PUSHDATA1 22 <w> (non-canonical)
      amount       = 100000000 :: Word64
      witStack     = [BS.replicate 72 0x30, BS.cons 0x02 (BS.replicate 32 0x01)]  -- dummy [sig, pubkey]
      flags        = Set.fromList [VerifyP2SH, VerifyWitness]   -- block-validation flags (MINIMALDATA off)
      verify ssig  = let credit = buildCreditingTx spk amount
                         tx     = buildSpendingTx credit ssig [witStack] amount
                     in verifyScriptWithFlags flags tx 0 spk amount [amount] [spk]
      malleatedErr = Left "P2SH witness scriptSig malleated" :: Either String Bool

  it "rejects a non-canonical OP_PUSHDATA1 push of the redeemScript" $
    verify malleated `shouldBe` malleatedErr

  it "does not raise the malleation error for the canonical direct push" $
    verify canonical `shouldNotBe` malleatedErr

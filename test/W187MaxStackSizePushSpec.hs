{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W187 MAX_STACK_SIZE enforcement after PUSH opcodes — Core parity.
--
-- Reference: bitcoin-core/src/script/interpreter.cpp:1221-1223
--   `if (stack.size() + altstack.size() > MAX_STACK_SIZE)  // MAX_STACK_SIZE=1000`
-- runs at the END of EVERY loop iteration, INCLUDING pushes (the push branch
-- falls through with no continue/break), returning SCRIPT_ERR_STACK_SIZE.
--
-- Finding (_glassbox-interpreter-findings-2026-07-01.md, MEDIUM, Script.hs:1357):
-- haskoin's push handlers (OP_0, OP_PUSHDATA, OP_1..OP_16) called pushStack
-- WITHOUT checkStackSize, and evalWithPosition had no post-op cap, so a
-- scriptPubKey of 1001 push opcodes left a 1001-element stack unchecked; the
-- truthy top element made verifyScript accept where Core rejects
-- (node-accepts / Core-rejects consensus split).
--
-- The fix adds the Core check at the end of every evalWithPosition iteration.
-- These tests FAIL pre-fix (1001 pushes returned Right True) and PASS post-fix
-- (Left "Stack size exceeded"), while the legitimate 1000-element boundary
-- still ACCEPTS.
module W187MaxStackSizePushSpec (spec) where

import Test.Hspec
import Data.Word (Word64)
import qualified Data.ByteString as BS

import Haskoin.Types (Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..))
import Haskoin.Script (Script(..), ScriptOp(..), emptyFlags, evalScriptWithFlags)

-- A minimal spending transaction. OP_16 pushes never invoke the sighash, so
-- the tx contents are irrelevant to the stack-size path.
dummyTx :: Tx
dummyTx =
  Tx 2
     [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xffffffff]
     [TxOut 0 BS.empty]
     [[]]
     0

-- Evaluate: empty scriptSig, scriptPubKey = n copies of OP_16.
-- CLEANSTACK is absent (emptyFlags), so acceptance is decided purely by the
-- truthy top element unless the stack-size limit fires.
evalNPushes :: Int -> Either String Bool
evalNPushes n =
  evalScriptWithFlags emptyFlags dummyTx 0 (0 :: Word64)
    (Script [])                       -- scriptSig
    (Script (replicate n OP_16))      -- scriptPubKey

spec :: Spec
spec = describe "W187 MAX_STACK_SIZE enforced after push opcodes (Core parity)" $ do

  it "REJECTS a scriptPubKey of 1001 OP_16 pushes (Core: SCRIPT_ERR_STACK_SIZE)" $
    -- Pre-fix this returned Right True (ACCEPT). Core rejects at the 1001st push.
    evalNPushes 1001 `shouldBe` Left "Stack size exceeded"

  it "ACCEPTS exactly 1000 pushes (boundary: 1000 is OK, not a regression)" $
    -- 1000 elements == MAX_STACK_SIZE, `> 1000` is false, top element truthy.
    evalNPushes 1000 `shouldBe` Right True

  it "REJECTS 1002 pushes as well (limit is a hard cap, not off-by-one)" $
    evalNPushes 1002 `shouldBe` Left "Stack size exceeded"

  it "ACCEPTS a small script (10 pushes) — no false positive under the cap" $
    evalNPushes 10 `shouldBe` Right True

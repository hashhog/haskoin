-- | cffix-haskoin-unbalanced-if-block
--
-- Core's EvalScript ends every script with
--
-- > if (!vfExec.empty()) return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
--
-- (bitcoin-core/src/script/interpreter.cpp, end of EvalScript). That one
-- check covers every script Core evaluates: scriptSig, scriptPubKey, the
-- P2SH redeem script, the witness v0 witnessScript and the tapscript leaf
-- (both reach EvalScript through ExecuteWitnessScript).
--
-- haskoin made the check at each CALL SITE instead, and only three of the
-- five call sites had it (scriptSig, scriptPubKey, P2SH redeem script).
-- 'verifyP2WSHWithFlags' and the tapscript branch of
-- 'verifyTaprootWithFlags' went straight from evaluation to the cleanstack
-- test, so a witness script that left an OP_IF open and one true item on
-- the stack verified. The R3 generating differential fuzzer found both on
-- its first night (2026-11-23, gen-baselines/haskoin.json):
--
--   * block/verdict/script/UNBALANCED_CONDITIONAL|accept,
--     p2wsh witnessScript @[8080 IFDUP IF]@: Core rejects the block,
--     haskoin accepted it (a consensus split).
--   * mempool/verdict/script-policy/UNBALANCED_CONDITIONAL|accept,
--     tapscript leaf @[1 1 IF]@: Core rejects, haskoin accepted (and the
--     same leaf in a block is the same split).
--
-- Each case below is run with the flags block connect uses
-- ('getBlockScriptFlags' on regtest, through 'consensusFlagsToScriptFlags')
-- and with the standard policy flags, through 'verifyScriptWithFlags',
-- the function both block connect and mempool acceptance call per input.
-- Every unbalanced case has a balanced control that must verify, so a
-- reject for an unrelated reason (a broken spend builder) cannot pass.
module Main (main) where

import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (isInfixOf)
import Data.Word (Word64)
import Test.Hspec

import Haskoin.Consensus (consensusFlagsToScriptFlags, getBlockScriptFlags,
                          regtest)
import Haskoin.Crypto (computeTapTweakHash, hash160, sha256,
                       xonlyPubkeyFromSeckey, xonlyPubkeyTweakAdd)
import Haskoin.Script
import Haskoin.TaprootSighash (tapleafHashWith)
import Haskoin.Types

--------------------------------------------------------------------------------
-- Flags
--------------------------------------------------------------------------------

-- | The flags block connect applies to a regtest block at height 200 (all
-- soft forks active). No MINIMALIF: it is policy, so a non-minimal IF
-- argument such as 0x8080 is allowed in a block.
blockFlags :: ScriptFlags
blockFlags = consensusFlagsToScriptFlags
  (getBlockScriptFlags regtest (BlockHash (Hash256 (BS.replicate 32 0x42))) 200)

-- | Standard policy flags (the mempool rows), including MINIMALIF and
-- CLEANSTACK.
policyFlags :: ScriptFlags
policyFlags = flagSet
  [ VerifyP2SH, VerifyWitness, VerifyTaproot, VerifyDERSig
  , VerifyCheckLockTimeVerify, VerifyCheckSequenceVerify, VerifyNullDummy
  , VerifyMinimalIf, VerifyCleanStack, VerifyNullFail, VerifyMinimalData
  , VerifyStrictEncoding, VerifyLowS, VerifyWitnessPubkeyType ]

--------------------------------------------------------------------------------
-- Spends of one funding output
--------------------------------------------------------------------------------

data Spend = SBare | SP2SH | SP2WSH | SP2SHP2WSH | STapscript
  deriving (Show, Eq, Enum, Bounded)

push :: ByteString -> ScriptOp
push bs
  | BS.null bs = OP_0
  | otherwise  = OP_PUSHDATA bs OPCODE   -- every push here is < 76 bytes

amount :: Word64
amount = 100000

mkTx :: ByteString -> [ByteString] -> Tx
mkTx sig wit = Tx
  { txVersion = 2
  , txInputs = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0x11))) 0) sig 0xfffffffe]
  , txOutputs = [TxOut 90000 (BS.pack [0x51])]
  , txWitness = if null wit then [] else [wit]
  , txLockTime = 0 }

-- | Spend an output locked by @script@ (bare: the scriptPubKey itself;
-- otherwise the redeem / witness script / leaf) with @items@ as the initial
-- stack (bottom first), under @flags@.
spend :: ScriptFlags -> Spend -> [ScriptOp] -> [ByteString] -> Either String Bool
spend flags how ops items =
  let sb = encodeScript (Script ops)
      itemPushes = encodeScript (Script (map push items))
  in case how of
    SBare ->
      run (mkTx itemPushes []) sb
    SP2SH ->
      run (mkTx (itemPushes <> encodeScript (Script [push sb])) [])
          (encodeScript (encodeP2SH (hash160 sb)))
    SP2WSH ->
      run (mkTx BS.empty (items ++ [sb]))
          (encodeScript (encodeP2WSH (Hash256 (sha256 sb))))
    SP2SHP2WSH ->
      let wp = encodeScript (encodeP2WSH (Hash256 (sha256 sb)))
      in run (mkTx (encodeScript (Script [push wp])) (items ++ [sb]))
             (encodeScript (encodeP2SH (hash160 wp)))
    STapscript ->
      let internal = case xonlyPubkeyFromSeckey (BS.replicate 32 0x01) of
                       Just k -> k
                       Nothing -> error "xonlyPubkeyFromSeckey failed"
          tweak = computeTapTweakHash internal (tapleafHashWith 0xc0 sb)
          (outKey, parity) = case xonlyPubkeyTweakAdd internal tweak of
                               Just r -> r
                               Nothing -> error "xonlyPubkeyTweakAdd failed"
          control = BS.cons (0xc0 .|. fromIntegral parity) internal
      in run (mkTx BS.empty (items ++ [sb, control]))
             (encodeScript (encodeP2TR (Hash256 outKey)))
  where
    run tx spk = verifyScriptWithFlags flags tx 0 spk amount [amount] [spk]

-- | Accepted, as block connect / mempool acceptance would count it.
accepted :: Either String Bool -> Bool
accepted = (== Right True)

-- | Rejected for an unbalanced condition stack (end of script, or OP_ELSE /
-- OP_ENDIF with an empty condition stack), not for some other reason.
unbalanced :: Either String Bool -> Bool
unbalanced (Left e) = "Unbalanced" `isInfixOf` e || "without OP_IF" `isInfixOf` e
unbalanced _ = False

nonMinimalTrue :: ByteString
nonMinimalTrue = BS.pack [0x80, 0x80]   -- CastToBool true, not MINIMALIF

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "R3 minimised cases (gen-baselines/haskoin.json, 2026-11-23)" $ do
    it "block: p2wsh witnessScript [8080 IFDUP IF] is rejected (Core: UNBALANCED_CONDITIONAL)" $
      spend blockFlags SP2WSH [push nonMinimalTrue, OP_IFDUP, OP_IF] []
        `shouldSatisfy` unbalanced
    it "control: p2wsh [8080 IFDUP IF ENDIF] verifies under block flags" $
      spend blockFlags SP2WSH [push nonMinimalTrue, OP_IFDUP, OP_IF, OP_ENDIF] []
        `shouldSatisfy` accepted
    it "mempool: tapscript leaf [1 1 IF] is rejected (Core: UNBALANCED_CONDITIONAL)" $
      spend policyFlags STapscript [OP_1, OP_1, OP_IF] []
        `shouldSatisfy` unbalanced
    it "block: tapscript leaf [1 1 IF] is rejected" $
      spend blockFlags STapscript [OP_1, OP_1, OP_IF] []
        `shouldSatisfy` unbalanced
    it "control: tapscript leaf [1 1 IF ENDIF] verifies (block and policy flags)" $ do
      spend blockFlags STapscript [OP_1, OP_1, OP_IF, OP_ENDIF] [] `shouldSatisfy` accepted
      spend policyFlags STapscript [OP_1, OP_1, OP_IF, OP_ENDIF] [] `shouldSatisfy` accepted

  describe "end-of-script check on every spend path (block flags)" $ do
    let allSpends = [minBound .. maxBound] :: [Spend]
    -- [1 1 IF]: the IF is taken, one true item is left, so only the
    -- condition stack can make it fail. Witness paths also need cleanstack,
    -- which it meets.
    it "[1 1 IF] (open, taken branch) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_1, OP_IF] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 0 IF] (open, untaken branch) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_0, OP_IF] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 1 NOTIF] (open NOTIF) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_1, OP_NOTIF] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 1 IF ELSE] (open after ELSE) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_1, OP_IF, OP_ELSE] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 1 IF 1 IF ENDIF] (one of two left open) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_1, OP_IF, OP_1, OP_IF, OP_ENDIF] [])
      | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[IF] with a true item from the witness / scriptSig is rejected on every path" $
      [ (s, spend blockFlags s [OP_IF] [BS.singleton 1, BS.singleton 1]) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "control: the balanced forms verify on every path" $ do
      [ (s, spend blockFlags s [OP_1, OP_1, OP_IF, OP_ENDIF] []) | s <- allSpends ]
        `shouldSatisfy` all (accepted . snd)
      [ (s, spend blockFlags s [OP_1, OP_0, OP_IF, OP_ENDIF] []) | s <- allSpends ]
        `shouldSatisfy` all (accepted . snd)
      [ (s, spend blockFlags s [OP_1, OP_1, OP_NOTIF, OP_ELSE, OP_ENDIF] []) | s <- allSpends ]
        `shouldSatisfy` all (accepted . snd)
      [ (s, spend blockFlags s [OP_1, OP_IF, OP_1, OP_IF, OP_ENDIF, OP_ENDIF]
                   [BS.singleton 1]) | s <- allSpends ]
        `shouldSatisfy` all (accepted . snd)

  describe "OP_ELSE / OP_ENDIF with an empty condition stack (block flags)" $ do
    let allSpends = [minBound .. maxBound] :: [Spend]
    it "[1 ELSE] is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_ELSE] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 ENDIF] is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_ENDIF] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 1 IF ENDIF ENDIF] (extra ENDIF) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_1, OP_IF, OP_ENDIF, OP_ENDIF] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)
    it "[1 0 IF ENDIF ELSE] (ELSE after the IF closed) is rejected on every path" $
      [ (s, spend blockFlags s [OP_1, OP_0, OP_IF, OP_ENDIF, OP_ELSE] []) | s <- allSpends ]
        `shouldSatisfy` all (unbalanced . snd)

  describe "the condition stack does not carry across scripts" $ do
    -- Core runs scriptSig and scriptPubKey as separate EvalScript calls,
    -- each with its own vfExec: an IF opened in the scriptSig cannot be
    -- closed by the scriptPubKey.
    it "bare: scriptSig [1 IF] + scriptPubKey [ENDIF 1] is rejected" $
      verifyScriptWithFlags (flagSet [VerifyWitness, VerifyTaproot])
        (mkTx (encodeScript (Script [OP_1, OP_IF])) []) 0
        (encodeScript (Script [OP_ENDIF, OP_1])) amount [] []
        `shouldSatisfy` unbalanced
  describe "error order: the condition stack is checked before cleanstack" $ do
    -- ExecuteWitnessScript runs EvalScript (which ends with the
    -- UNBALANCED_CONDITIONAL check) before its one-item cleanstack test, so
    -- a witnessScript [1 IF] (empty stack, IF open) fails as unbalanced.
    it "p2wsh: [1 IF] fails as unbalanced, not as a cleanstack failure" $
      spend blockFlags SP2WSH [OP_1, OP_IF] [] `shouldSatisfy` unbalanced
    it "tapscript: [1 IF] fails as unbalanced, not as a cleanstack failure" $
      spend blockFlags STapscript [OP_1, OP_IF] [] `shouldSatisfy` unbalanced

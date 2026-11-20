{-# OPTIONS_GHC -fno-full-laziness -fno-cse #-}
-- | cffix-haskoin-tapscript-ifstack-quadratic
--
-- Tapscript lifts both the 201-opcode limit and the 10,000-byte script-size
-- limit, and nothing bounds the depth of the OP_IF condition stack. Core
-- keeps that stack as a (size, first-false-position) pair (ConditionStack,
-- bitcoin-core/src/script/interpreter.cpp:273-318) so the per-opcode
-- "are we executing?" test is O(1). haskoin evaluated @all id@ over a
-- @[Bool]@ before every opcode, so the Core-valid leaf
--
-- > (OP_1 OP_IF)*d (OP_ENDIF)*d OP_1
--
-- cost about 1.5*d^2 list steps: one input of a standard 400k-WU
-- transaction (d ~ 130k) reached ~2.5e10 steps, through mempool acceptance
-- and block connect alike.
--
-- Group 1 builds a real P2TR script-path spend of that leaf and checks it
-- verifies, and that the d=20,000 run costs less than 20x the d=2,000 run
-- (linear; the quadratic interpreter is ~100x).
--
-- Group 2 is the consensus guard for the new structure: every sequence of
-- OP_0 / OP_1 / OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF / OP_RETURN up to
-- length 7 (exhaustive, balanced and unbalanced) plus random longer ones is
-- run through the real interpreter and compared, result for result, with a
-- reference interpreter in this file that keeps the condition stack as a
-- plain list of Bools (the pre-fix model). OP_RETURN acts as a probe: it
-- fails the script exactly when it sits in an executing branch, so every
-- position's executing/not-executing truth value is observed.
module Main (main) where

import Control.Exception (evaluate)
import Control.Monad (forM, forM_)
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
import Data.Word (Word64)
import System.CPUTime (getCPUTime)
import Test.Hspec
import Test.QuickCheck

import Haskoin.Crypto (computeTapTweakHash, xonlyPubkeyFromSeckey,
                       xonlyPubkeyTweakAdd)
import Haskoin.Script
import Haskoin.TaprootSighash (tapleafHashWith)
import Haskoin.Types

--------------------------------------------------------------------------------
-- P2TR script-path spend of an arbitrary tapscript leaf
--------------------------------------------------------------------------------

taprootFlags :: ScriptFlags
taprootFlags = flagSet
  [ VerifyP2SH, VerifyWitness, VerifyTaproot, VerifyMinimalIf
  , VerifyNullFail, VerifyDERSig, VerifyCheckLockTimeVerify
  , VerifyCheckSequenceVerify, VerifyNullDummy ]

-- | Verify a one-input tx spending a single-leaf P2TR output whose only
-- leaf is @leaf@, via the script path with an empty initial stack.
spendLeaf :: [ScriptOp] -> Either String Bool
spendLeaf leaf =
  let leafBytes = encodeScript (Script leaf)
      internal = case xonlyPubkeyFromSeckey (BS.replicate 32 0x01) of
                   Just k -> k
                   Nothing -> error "xonlyPubkeyFromSeckey failed"
      leafHash = tapleafHashWith 0xc0 leafBytes
      tweak = computeTapTweakHash internal leafHash
      (outKey, parity) = case xonlyPubkeyTweakAdd internal tweak of
                           Just r -> r
                           Nothing -> error "xonlyPubkeyTweakAdd failed"
      control = BS.cons (0xc0 .|. fromIntegral parity) internal
      spk = encodeScript (encodeP2TR (Hash256 outKey))
      amt = 100000 :: Word64
      tx = Tx { txVersion = 2
              , txInputs = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0x11))) 0)
                                 BS.empty 0xffffffff]
              , txOutputs = [TxOut 90000 (BS.pack [0x51])]
              , txWitness = [[leafBytes, control]]
              , txLockTime = 0 }
  in verifyScriptWithFlags taprootFlags tx 0 spk amt [amt] [spk]

-- | (OP_1 OP_IF)*d (OP_ENDIF)*d OP_1 -- every level executing.
nestedTrue :: Int -> [ScriptOp]
nestedTrue d = concat (replicate d [OP_1, OP_IF]) ++ replicate d OP_ENDIF ++ [OP_1]

-- | Same depth, but the innermost IF takes the false branch.
nestedFalseInner :: Int -> [ScriptOp]
nestedFalseInner d =
  concat (replicate (d - 1) [OP_1, OP_IF]) ++ [OP_0, OP_IF]
  ++ replicate d OP_ENDIF ++ [OP_1]

-- | Minimum CPU picoseconds over 3 runs of a verification.
cpuCost :: [ScriptOp] -> IO (Integer, Either String Bool)
cpuCost leaf = do
  runs <- forM [1 :: Int .. 3] $ \_ -> do
    -- The op list is shared across runs, but the verification itself is
    -- re-run: 'spendLeaf' is applied afresh inside each timed region.
    _ <- evaluate (length leaf)
    t0 <- getCPUTime
    r <- evaluate (spendLeaf leaf)
    _ <- evaluate (either length fromEnum r)
    t1 <- getCPUTime
    pure (t1 - t0, r)
  pure (minimum (map fst runs), snd (head runs))

linearity :: String -> (Int -> [ScriptOp]) -> Spec
linearity name build =
  it (name ++ ": d=20000 costs < 20x d=2000 (linear, not quadratic)") $ do
    -- warm-up: libsecp context, CAFs
    _ <- evaluate (spendLeaf (build 10))
    (tSmall, rSmall) <- cpuCost (build 2000)
    (tBig, rBig) <- cpuCost (build 20000)
    rSmall `shouldBe` Right True
    rBig `shouldBe` Right True
    let ratio = fromIntegral tBig / fromIntegral (max 1 tSmall) :: Double
    putStrLn ("    " ++ name ++ ": d=2000 " ++ show (tSmall `div` 1000000) ++ "us, d=20000 "
              ++ show (tBig `div` 1000000) ++ "us, ratio " ++ show ratio)
    ratio `shouldSatisfy` (< 20)

--------------------------------------------------------------------------------
-- Reference interpreter: condition stack as a plain [Bool]
--------------------------------------------------------------------------------

data Tok = T0 | T1 | TIf | TNotIf | TElse | TEndIf | TRet
  deriving (Show, Eq, Enum, Bounded)

instance Arbitrary Tok where
  arbitrary = frequency
    [ (3, pure T0), (3, pure T1), (3, pure TIf), (2, pure TNotIf)
    , (2, pure TElse), (3, pure TEndIf), (1, pure TRet) ]

tokOp :: Tok -> ScriptOp
tokOp t = case t of
  T0 -> OP_0; T1 -> OP_1; TIf -> OP_IF; TNotIf -> OP_NOTIF
  TElse -> OP_ELSE; TEndIf -> OP_ENDIF; TRet -> OP_RETURN

-- | Expected 'evalScriptWithFlags' result for the script, as a scriptPubKey
-- with an empty scriptSig and no flags.
model :: [Tok] -> Either String Bool
model = go [] []
  where
    go :: [Bool] -> [Bool] -> [Tok] -> Either String Bool
    go vals conds [] =
      if not (null conds) then Left "Unbalanced IF/ENDIF"
      else case vals of
        [] -> Right False
        (v:_) -> Right v
    go vals conds (t:ts) =
      let exec = and conds in
      case t of
        T0 | exec -> go (False : vals) conds ts
        T1 | exec -> go (True : vals) conds ts
        TRet | exec -> Left "OP_RETURN encountered"
        TIf -> ifLike id
        TNotIf -> ifLike not
        TElse -> case conds of
          [] -> Left "OP_ELSE without OP_IF"
          (c:cs) -> go vals (not c : cs) ts
        TEndIf -> case conds of
          [] -> Left "OP_ENDIF without OP_IF"
          (_:cs) -> go vals cs ts
        _ -> go vals conds ts
      where
        ifLike f
          | and conds = case vals of
              [] -> Left "Stack underflow"
              (v:vs) -> go vs (f v : conds) ts
          | otherwise = go vals (False : conds) ts

real :: [Tok] -> Either String Bool
real toks = evalScriptWithFlags emptyFlags dummyTx 0 0 (Script []) (Script (map tokOp toks))
  where
    dummyTx = Tx 1 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) BS.empty 0xffffffff]
                 [] [] 0

allSeqs :: Int -> [[Tok]]
allSeqs n = concatMap (\k -> sequence (replicate k [minBound .. maxBound])) [0 .. n]

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "tapscript OP_IF nesting (cffix-haskoin-tapscript-ifstack-quadratic)" $ do
    it "(OP_1 OP_IF)*d (OP_ENDIF)*d OP_1 verifies for d=2000 and d=20000" $ do
      spendLeaf (nestedTrue 2000) `shouldBe` Right True
      spendLeaf (nestedTrue 20000) `shouldBe` Right True
    it "control: innermost OP_0 OP_IF still verifies at both depths" $ do
      spendLeaf (nestedFalseInner 2000) `shouldBe` Right True
      spendLeaf (nestedFalseInner 20000) `shouldBe` Right True
    -- (An unbalanced leaf is not used as a control here: the tapscript and
    -- P2WSH paths skip Core's end-of-script UNBALANCED_CONDITIONAL check,
    -- a separate consensus bug filed as its own item. The exhaustive
    -- group below covers unbalanced sequences through the legacy path.)
    it "control: same nesting with a final OP_0 does not verify" $ do
      let d = 2000
      spendLeaf (concat (replicate d [OP_1, OP_IF]) ++ replicate d OP_ENDIF ++ [OP_0])
        `shouldSatisfy` either (const True) not
    it "control: a false IF condition skips the branch (OP_RETURN unreached)" $ do
      let d = 2000
      spendLeaf (concat (replicate (d - 1) [OP_1, OP_IF]) ++ [OP_0, OP_IF, OP_RETURN]
                 ++ replicate d OP_ENDIF ++ [OP_1])
        `shouldBe` Right True
      spendLeaf (concat (replicate (d - 1) [OP_1, OP_IF]) ++ [OP_1, OP_IF, OP_RETURN]
                 ++ replicate d OP_ENDIF ++ [OP_1])
        `shouldSatisfy` either (const True) not
    linearity "all-true nesting" nestedTrue
    linearity "innermost-false nesting" nestedFalseInner

  describe "condition stack matches the [Bool] model" $ do
    it "every token sequence up to length 7 (exhaustive)" $ do
      let seqs = allSeqs 7
          bad = [ (s, real s, model s) | s <- seqs, real s /= model s ]
      forM_ (take 5 bad) print
      length seqs `shouldBe` sum [7 ^ k | k <- [0 .. 7 :: Int]]
      length bad `shouldBe` 0
    it "random sequences up to length 200" $
      property $ forAll (resize 200 (listOf arbitrary)) $ \toks ->
        real toks === model toks
    it "model sanity: it is not vacuous (all four outcomes occur)" $ do
      let rs = map model (allSeqs 5)
      any (== Right True) rs `shouldBe` True
      any (== Right False) rs `shouldBe` True
      any (== Left "OP_RETURN encountered") rs `shouldBe` True
      any (== Left "Unbalanced IF/ENDIF") rs `shouldBe` True

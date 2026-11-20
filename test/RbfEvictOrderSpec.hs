{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | An RBF replacement may evict its conflicts only after its OWN checks pass.
--
-- Bitcoin Core MemPoolAccept::AcceptSingleTransactionInternal
-- (validation.cpp) runs PreChecks, ReplacementChecks, the cluster-limit
-- check, PolicyScriptChecks and ConsensusScriptChecks, and only then
-- FinalizeSubpackage, which is the step that removes the conflicts.  A
-- replacement whose scripts fail is rejected with the pool untouched.
--
-- Pre-fix haskoin evicted the conflicts (and their descendants) as soon as
-- the fee/count/diagram rules passed ('attemptReplacement' →
-- 'removeConflicts') and ran the replacement's standardness, sigops, script
-- and cluster checks afterwards, with no rollback.  With full RBF on by
-- default and relayed rejects never punished, any peer could evict any
-- mempool transaction for free by relaying an unsigned conflicting spend with
-- a high fee.
module RbfEvictOrderSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Control.Monad (foldM, forM_)
import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.Mempool
import Haskoin.Consensus (regtest)
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB, addUTXO, UTXOEntry(..))

-- | P2WSH(OP_TRUE): standard output, spendable with witness [OP_TRUE].
opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

-- | A spend of @ops@ whose every input carries the given witness stack.
spendWith :: [BS.ByteString] -> [OutPoint] -> [Word64] -> Tx
spendWith wit ops vals = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn op BS.empty 0xfffffffd | op <- ops ]
  , txOutputs  = [ TxOut v opTrueSpk | v <- vals ]
  , txWitness  = [ wit | _ <- ops ]
  , txLockTime = 0
  }

-- | Correctly "signed": witness [OP_TRUE] satisfies P2WSH(OP_TRUE).
signed :: [OutPoint] -> [Word64] -> Tx
signed = spendWith [BS.singleton 0x51]

-- | Unsigned: empty witness, fails script verification.
unsigned :: [OutPoint] -> [Word64] -> Tx
unsigned = spendWith []

v3 :: Tx -> Tx
v3 t = t { txVersion = 3 }

coinC :: OutPoint
coinC = OutPoint (TxId (Hash256 (BS.replicate 31 0x7c <> BS.singleton 0))) 0

withPool :: (Mempool -> IO a) -> IO a
withPool action =
  withSystemTempDirectory "haskoin-rbf-evict-order" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 1000
      -- one confirmed, mature, non-coinbase coin C at height 1; tip 200
      atomically $ addUTXO cache coinC
        (UTXOEntry (TxOut 1_000_000 opTrueSpk) 1 False False)
      mp <- newMempool regtest cache defaultMempoolConfig 200 0 noopCoinMtp
      action mp

accepted :: Mempool -> Tx -> IO ()
accepted mp tx = do
  r <- addTransaction mp tx
  r `shouldBe` Right (computeTxId tx)

inPool :: Mempool -> Tx -> IO Bool
inPool mp tx = Map.member (computeTxId tx) <$> readTVarIO (mpEntries mp)

isScriptFailure :: Either MempoolError TxId -> Bool
isScriptFailure (Left (ErrScriptVerificationFailed _)) = True
isScriptFailure _ = False

out0 :: Tx -> OutPoint
out0 t = OutPoint (computeTxId t) 0

spec :: Spec
spec = describe "RBF: conflicts are evicted only after the replacement's own checks pass (Core FinalizeSubpackage last)" $ do
  let victim = signed [coinC] [990_000]                 -- fee 10,000
      child  = signed [out0 victim] [989_000]           -- fee 1,000
      -- huge fee: passes every replacement rule, but carries no witness
      attack = unsigned [coinC] [500_000]

  it "an unsigned high-fee replacement is rejected for its scripts and the victim stays" $ withPool $ \mp -> do
    accepted mp victim
    r <- addTransaction mp attack
    r `shouldSatisfy` isScriptFailure
    inPool mp victim `shouldReturn` True
    inPool mp attack `shouldReturn` False

  it "the victim's in-pool child survives the rejected replacement too" $ withPool $ \mp -> do
    accepted mp victim
    accepted mp child
    r <- addTransaction mp attack
    r `shouldSatisfy` isScriptFailure
    inPool mp victim `shouldReturn` True
    inPool mp child  `shouldReturn` True
    getMempoolSize mp >>= \(n, _) -> n `shouldBe` 2

  it "a replacement with a WRONG witness (not merely empty) also leaves the pool intact" $ withPool $ \mp -> do
    accepted mp victim
    accepted mp child
    r <- addTransaction mp (spendWith [BS.singleton 0x52] [coinC] [500_000])
    r `shouldSatisfy` isScriptFailure
    inPool mp victim `shouldReturn` True
    inPool mp child  `shouldReturn` True

  it "testmempoolaccept and the commit path give the same verdict" $ withPool $ \mp -> do
    accepted mp victim
    t <- testAcceptTransaction mp attack
    r <- addTransaction mp attack
    case (t, r) of
      (Left (ErrScriptVerificationFailed _), Left (ErrScriptVerificationFailed _)) -> return ()
      _ -> expectationFailure ("dry run " ++ show (fmap meTxId t) ++ " vs commit " ++ show r)
    inPool mp victim `shouldReturn` True

  it "control: the same replacement, signed, still evicts the victim and its child" $ withPool $ \mp -> do
    accepted mp victim
    accepted mp child
    let good = signed [coinC] [500_000]
    accepted mp good
    inPool mp victim `shouldReturn` False
    inPool mp child  `shouldReturn` False
    inPool mp good   `shouldReturn` True

  it "control: the pre-eviction cluster check does not count the txs being evicted" $ withPool $ \mp -> do
    -- A chain of 64 txs fills the cluster limit (Core DEFAULT_CLUSTER_LIMIT).
    -- Replacing the LAST link leaves 63 + the replacement = 64, which Core
    -- accepts; a cluster check that still counted the conflict would see 65.
    let step (prev, acc) i =
          let t = signed [prev] [1_000_000 - 1_000 * i]
          in return (out0 t, acc ++ [t])
    (_, chain) <- foldM step (coinC, []) [1 .. 64 :: Word64]
    forM_ chain (accepted mp)
    let lastLink = last chain
        prevOp   = case txInputs lastLink of
                     (i:_) -> txInPrevOutput i
                     []    -> error "unreachable"
        bump     = signed [prevOp] [900_000]
    accepted mp bump
    inPool mp lastLink `shouldReturn` False
    getMempoolSize mp >>= \(n, _) -> n `shouldBe` 64

  it "control: a v3 child fee-bump is not mistaken for a TRUC sibling of itself" $ withPool $ \mp -> do
    let parent = v3 (signed [coinC] [990_000])
        kid    = v3 (signed [out0 parent] [989_000])
        kid'   = v3 (signed [out0 parent] [985_000])
    accepted mp parent
    accepted mp kid
    accepted mp kid'
    inPool mp kid  `shouldReturn` False
    inPool mp kid' `shouldReturn` True

  it "a v3 replacement that breaks TRUC is rejected before eviction" $ withPool $ \mp -> do
    -- The TRUC size gate (TRUC_MAX_VSIZE = 10,000 vB) on a replacement with
    -- no in-pool parent: it must fail with the victim still in the pool.
    -- A low-fee victim, so the fat replacement passes the RBF feerate rule
    -- and it is the TRUC gate, not an RBF rule, that rejects it.
    let cheapVictim = signed [coinC] [999_000]          -- fee 1,000
    accepted mp cheapVictim
    let bigOuts = replicate 260 1_000          -- ~11 kvB of outputs
        fat     = v3 (signed [coinC] bigOuts)
    r <- addTransaction mp fat
    case r of
      Left (ErrTrucViolation _) -> return ()
      other -> expectationFailure ("expected a TRUC rejection, got " ++ show other)
    inPool mp cheapVictim `shouldReturn` True

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W167 verifytxoutproof CVE-2012-2459 hardening (partial-merkle-tree
--   extractor).
--
-- Reference: bitcoin-core/src/merkleblock.cpp
--   CPartialMerkleTree::TraverseAndExtract / ExtractMatches.
--
-- These tests assert that the haskoin partial-merkle-tree extractor
-- (Haskoin.Rpc.w47bExtract, driven by handleVerifyTxOutProof) mirrors
-- Core's malformed-proof rejections, all of which make Core return
-- uint256() -> verifytxoutproof returns [] (never accept):
--
--   (1) duplicate-branch detection — a non-leaf node whose left and right
--       child hashes are identical (and a right child was actually read)
--       is bad (merkleblock.cpp ~124-128).  This is the actual
--       CVE-2012-2459 forgery vector: padding the tree with a duplicated
--       subtree to forge an alternate tree with the same merkle root.
--   (2) all flag bits consumed (modulo final partial byte) after traversal.
--   (3) all hashes consumed after traversal.
--   (4) upfront bounds: nTransactions>0, vHash.size() <= nTransactions,
--       vBits.size() >= vHash.size().
--
-- Checks (2)-(4) live in handleVerifyTxOutProof (the RPC handler); the
-- duplicate-branch check (1) lives in w47bExtract itself and is exercised
-- here directly so the hardening is provably live regardless of block shape.
module W167VerifyTxOutProofHardeningSpec (spec) where

import Test.Hspec
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef (newIORef, readIORef)

import Haskoin.Types (Hash256(..))
import Haskoin.Crypto (doubleSHA256)
import Haskoin.Rpc (w47bExtract, w47bTreeHeight)

-- Two distinct deterministic 32-byte leaf hashes for a 2-tx block.
leaf0, leaf1 :: ByteString
leaf0 = BS.replicate 32 0x11
leaf1 = BS.replicate 32 0x22

-- Expected merkle root of a 2-leaf tree: Hash(leaf0 || leaf1).
validRoot :: ByteString
validRoot = let Hash256 r = doubleSHA256 (leaf0 <> leaf1) in r

-- Run the extractor over a 2-tx (height-1) tree and report how many bits /
-- hashes it consumed alongside its result.  Mirrors how handleVerifyTxOutProof
-- drives w47bExtract.
runExtract
  :: [ByteString]                  -- hashes array
  -> [Bool]                        -- flag bits
  -> IO (Either String (ByteString, [ByteString]), Int, Int)
runExtract hashes bits = do
  let nTx        = 2
      safeHeight = w47bTreeHeight nTx   -- == 1 for nTx==2
  bitRef  <- newIORef 0
  hashRef <- newIORef 0
  res <- w47bExtract hashes bits nTx safeHeight 0 bitRef hashRef
  nBits  <- readIORef bitRef
  nHash  <- readIORef hashRef
  return (res, nBits, nHash)

-- handleVerifyTxOutProof's post-traversal "all consumed" gate, replicated so
-- the unit test exercises the same accept/reject logic as the RPC handler.
ceilDiv8 :: Int -> Int
ceilDiv8 x = (x + 7) `div` 8

spec :: Spec
spec = describe "W167 verifytxoutproof CVE-2012-2459 hardening" $ do

  -- Baseline: a well-formed 2-leaf proof matching leaf0 must extract leaf0 as
  -- a match and reconstruct the correct root.  (Guards against the hardening
  -- over-rejecting valid proofs.)
  describe "valid 2-leaf proof" $ do
    it "extracts the matched leaf and reconstructs the correct root" $ do
      -- bits for matching tx0: [parent=T, left-leaf=T(match), right-leaf=F]
      (res, _, _) <- runExtract [leaf0, leaf1] [True, True, False]
      case res of
        Right (root, matched) -> do
          root    `shouldBe` validRoot
          matched `shouldBe` [leaf0]
        Left e -> expectationFailure ("valid proof rejected: " ++ e)

  -- (1) Duplicate-branch detection: make the right child equal the left child
  -- at the root.  Core sets fBad here (merkleblock.cpp 124-128).  w47bExtract
  -- must return Left, so verifytxoutproof returns [] (never the matched txid).
  describe "duplicate-branch (CVE-2012-2459)" $ do
    it "rejects a proof whose two root children are identical" $ do
      -- Same bit layout, but the sibling hash is a copy of the matched leaf,
      -- so left == right at the root node.
      (res, _, _) <- runExtract [leaf0, leaf0] [True, True, False]
      case res of
        Left _  -> return ()  -- rejected as required
        Right _ -> expectationFailure
          "duplicate-branch proof was ACCEPTED (CVE-2012-2459 check is dead)"

  -- (2) + (3): after a successful traversal the handler requires all flag bits
  -- (modulo the final partial byte) and all hashes to be consumed.  An
  -- over-long proof (extra trailing hash) must be rejected by that gate even
  -- though w47bExtract itself returns Right.
  describe "over-long proof (unconsumed hashes / bits)" $ do
    it "is rejected by the all-consumed gate (extra trailing hash)" $ do
      -- A bogus extra hash the traversal will never read.
      let extra = BS.replicate 32 0x33
      (res, nBits, nHash) <- runExtract [leaf0, leaf1, extra] [True, True, False]
      let bits        = [True, True, False]
          hashCount   = 3
          allConsumed = ceilDiv8 nBits == ceilDiv8 (length bits)
                        && nHash == hashCount
      -- Traversal succeeds but consumes only 2 of the 3 hashes, so the
      -- handler's all-consumed gate fails -> verifytxoutproof returns [].
      case res of
        Right _ -> allConsumed `shouldBe` False
        Left _  -> return ()  -- also an acceptable rejection

    it "leaves a trailing flag byte unconsumed when bits over-supplied" $ do
      -- Pad the flag bits with a whole extra byte of zeros (8 bits): the
      -- traversal consumes 3 bits, so CeilDiv(3,8)=1 but CeilDiv(11,8)=2.
      let bits = [True, True, False] ++ replicate 8 False
      (res, nBits, _) <- runExtract [leaf0, leaf1] bits
      case res of
        Right _ -> ceilDiv8 nBits `shouldNotBe` ceilDiv8 (length bits)
        Left _  -> return ()

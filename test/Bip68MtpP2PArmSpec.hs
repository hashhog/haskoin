{-# LANGUAGE OverloadedStrings #-}

-- | cffix-haskoin-bip68-mtp-p2p-arm: the per-coin BIP-68 MTP that the P2P
-- @MBlock@ arms (app/Main.hs) hand to 'validateFullBlockIO' must come from
-- the connecting block's OWN ancestry, not from the best-header height index
-- 'hcByHeight'.
--
-- Core, consensus/tx_verify.cpp CalculateSequenceLocks:74:
--
-- >   nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast()
--
-- where @block@ is the block being connected.
--
-- 'hcByHeight' is not the active chain: 'addHeaderAt' rewrites a slot only
-- for a STRICTLY heavier header and only at that header's own height,
-- 'connectBlockAt' never writes it, and 'recalculateBestHeader' rewrites only
-- heights above the connected tip.  So with equal-work siblings A and B at
-- height N where A's header arrived first, @hcByHeight[N] = A@ even after B's
-- body is connected and C (N+1) is built on B.  A block D spending a coin
-- created at N+1 with a time-based nSequence is then judged against MTP(A)
-- instead of MTP(B).
--
-- Fixture (all on regtest, BIP-68 active from height 1):
--
-- >  G - 1 - 2 - 3 - P4 - A5          (header only, hcByHeight[5] = A5)
-- >                    \
-- >                     B5 - C6 - D7  (active branch; coin created in C6)
--
-- D7 spends the C6 coin with nSequence = TYPE_FLAG|1 (512 s), so its lock
-- is @MTP(height 5 on D7's ancestry) + 511 < MTP(C6)@.  The two MTPs are
-- placed so that the 512-second boundary lies between MTP(A5)+511 and
-- MTP(B5)+511.
module Bip68MtpP2PArmSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar)
import Data.Bits ((.|.))
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , ChainState(..)
  , BlockStatus(..)
  , consensusFlagsAtHeight
  , computeMerkleRoot
  , encodeBip34Height
  , sequenceLockTimeTypeFlag
  , validateFullBlock
  , p2pBlockArmMtpResolver
  )
import Haskoin.Storage (Coin(..))

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

coinbaseTx :: Word32 -> Word8 -> Word64 -> Tx
coinbaseTx h tag value = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn nullOutPoint (encodeBip34Height h `BS.snoc` tag) 0xffffffff ]
  , txOutputs  = [ TxOut value opTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

mkBlock :: BlockHash -> Word32 -> [Tx] -> Block
mkBlock prevHash ts txns = Block
  { blockHeader = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff
      , bhNonce      = 0
      }
  , blockTxns = txns
  }

blockHashOf :: Block -> BlockHash
blockHashOf = computeBlockHash . blockHeader

-- | Header-chain entry for @blk@ at height @h@ with an explicit MTP.  Work is
-- one unit per height, so A5 and B5 carry EQUAL work.
mkEntry :: Block -> Word32 -> BlockHash -> Word32 -> ChainEntry
mkEntry blk h prevHash mtp = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = blockHashOf blk
  , ceHeight     = h
  , ceChainWork  = fromIntegral h + 1
  , cePrev       = Just prevHash
  , ceStatus     = StatusValid
  , ceMedianTime = mtp
  , ceSequenceId = 0
  }

subsidy :: Word64
subsidy = 5000000000

coinValue, spendValue :: Word64
coinValue  = 50000
spendValue = 49000

timeLockSeq :: Word32
timeLockSeq = sequenceLockTimeTypeFlag .|. 1   -- 1 unit = 512 s

baseTime :: Word32
baseTime = 1296688700

-- | MTP of C6 (D7's parent), i.e. D7's prevBlockMTP.
mtpC6 :: Word32
mtpC6 = baseTime + 2000

data Fixture = Fixture
  { fxHc       :: HeaderChain
  , fxA5       :: BlockHash
  , fxB5       :: BlockHash
  , fxC6       :: BlockHash
  , fxD7       :: Block
  , fxCoins    :: Map.Map OutPoint Coin
  , fxCs       :: ChainState
  }

-- | Build the fork fixture.  @mtpA@ / @mtpB@ are the MTPs of the two
-- equal-work siblings at height 5.  @indexNames@ chooses which sibling the
-- height index names at 5 (A in the bug scenario).
buildFixture :: Word32 -> Word32 -> (Fixture -> BlockHash) -> IO Fixture
buildFixture mtpA mtpB indexNames = do
  let net     = regtest
      gHash   = blockHashOf (netGenesisBlock net)
  hc <- initHeaderChain net
  -- Prefix 1..4 (shared ancestry).
  let goPrefix (prev, acc) h =
        let blk = mkBlock prev (baseTime + h) [coinbaseTx h 0 subsidy]
            ce  = mkEntry blk h prev (baseTime + h)
        in (blockHashOf blk, acc ++ [ce])
      (p4Hash, prefix) = foldl goPrefix (gHash, []) [1 .. 4]
      blkA5 = mkBlock p4Hash (baseTime + 5) [coinbaseTx 5 0xa5 subsidy]
      blkB5 = mkBlock p4Hash (baseTime + 6) [coinbaseTx 5 0xb5 subsidy]
      eA5   = mkEntry blkA5 5 p4Hash mtpA
      eB5   = mkEntry blkB5 5 p4Hash mtpB
      blkC6 = mkBlock (ceHash eB5) (baseTime + 7) [coinbaseTx 6 0 subsidy]
      eC6   = mkEntry blkC6 6 (ceHash eB5) mtpC6
      -- The coin D7 spends: created at height 6 (in C6's branch).
      coinOp  = OutPoint (TxId (Hash256 (BS.replicate 32 0x66))) 0
      coins   = Map.singleton coinOp (Coin (TxOut coinValue opTrue) 6 False)
      spendTx = Tx
        { txVersion  = 2
        , txInputs   = [ TxIn coinOp BS.empty timeLockSeq ]
        , txOutputs  = [ TxOut spendValue opTrue ]
        , txWitness  = [[]]
        , txLockTime = 0
        }
      blkD7 = mkBlock (ceHash eC6) (mtpC6 + 1000)
                [coinbaseTx 7 0 (subsidy + coinValue - spendValue), spendTx]
      cs = ChainState
        { csHeight     = 6
        , csBestBlock  = ceHash eC6
        , csChainWork  = ceChainWork eC6
        , csMedianTime = mtpC6
        , csFlags      = consensusFlagsAtHeight net 7
        }
      fx = Fixture hc (ceHash eA5) (ceHash eB5) (ceHash eC6) blkD7 coins cs
      allEntries = prefix ++ [eA5, eB5, eC6]
  atomically $ do
    modifyTVar' (hcEntries hc) $ \m ->
      foldr (\ce -> Map.insert (ceHash ce) ce) m allEntries
    -- Best-header height index: the shared prefix, then whichever sibling
    -- arrived first at 5 (B5 tied, so addHeaderAt never rewrote it), then C6
    -- (strictly heavier, so addHeaderAt wrote its own height only).
    modifyTVar' (hcByHeight hc) $ \m ->
      Map.insert 6 (ceHash eC6)
        (Map.insert 5 (indexNames fx)
          (foldr (\ce -> Map.insert (ceHeight ce) (ceHash ce)) m prefix))
    writeTVar (hcTip hc) eC6
    writeTVar (hcHeight hc) 6
  return fx

-- | Validate D7 exactly as the P2P MBlock linear-connect arm does: the
-- resolver comes from 'p2pBlockArmMtpResolver' for D7's parent.
validateD7 :: Fixture -> IO (Either String ())
validateD7 fx = do
  getMtp <- p2pBlockArmMtpResolver (fxHc fx) (bhPrevBlock (blockHeader (fxD7 fx)))
  return $! validateFullBlock regtest (fxCs fx) getMtp False False (fxD7 fx) (fxCoins fx)

spec :: Spec
spec = describe "cffix-haskoin-bip68-mtp-p2p-arm: P2P MBlock BIP-68 coin MTP from the block's own ancestry" $ do

  -- Lock: MTP(height 5) + 511 < mtpC6 (= baseTime + 2000).
  --   MTP(B5) = baseTime + 1000  -> 1000+511 < 2000  -> lock satisfied (Core accepts)
  --   MTP(A5) = baseTime + 1800  -> 1800+511 >= 2000 -> lock NOT satisfied
  it "accepts D7 when its own ancestry (B5) satisfies the time lock but the height index names A5 (Core accepts)" $ do
    fx <- buildFixture (baseTime + 1800) (baseTime + 1000) fxA5
    r <- validateD7 fx
    r `shouldBe` Right ()

  -- Reverse: MTP(A5) = baseTime + 1000 (index would accept),
  --          MTP(B5) = baseTime + 1800 (own ancestry: lock not yet met).
  it "rejects D7 with bad-txns-nonfinal when its own ancestry (B5) does not satisfy the time lock but A5 would (Core rejects)" $ do
    fx <- buildFixture (baseTime + 1000) (baseTime + 1800) fxA5
    r <- validateD7 fx
    r `shouldBe` Left "bad-txns-nonfinal"

  -- Controls: with the index naming D7's own ancestor the answer is the same
  -- for either resolver, which shows the fixture's block is otherwise valid
  -- and the lock boundary is where the two cases above put it.
  it "control: accepts D7 when the height index already names its own ancestor (B5) and the lock is met" $ do
    fx <- buildFixture (baseTime + 1800) (baseTime + 1000) fxB5
    r <- validateD7 fx
    r `shouldBe` Right ()

  it "control: rejects D7 when the height index names its own ancestor (B5) and the lock is not met" $ do
    fx <- buildFixture (baseTime + 1000) (baseTime + 1800) fxB5
    r <- validateD7 fx
    r `shouldBe` Left "bad-txns-nonfinal"

  it "the resolver returns D7's own height-5 ancestor's MTP, not the index's" $ do
    fx <- buildFixture (baseTime + 1800) (baseTime + 1000) fxA5
    getMtp <- p2pBlockArmMtpResolver (fxHc fx) (fxC6 fx)
    getMtp 5 `shouldBe` baseTime + 1000

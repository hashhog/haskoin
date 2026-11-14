{-# LANGUAGE OverloadedStrings #-}

-- | secfix-haskoin-mutation-recheck-race (H1).
--
-- The P2P MBlock arm (app/Main.hs syncMessageHandler) runs Core's
-- IsBlockMutated on receipt only when the block's parent header is known
-- ('mutationOnReceipt'), then calls 'addHeader', then validates the body
-- and marks the block failed on a VERDICT ('classifyBlockReject' +
-- 'invalidBlockFound').  When the parent header arrives on another peer
-- thread between the receipt check and 'addHeader', the receipt check is
-- skipped and the body goes straight to validation.  On master
-- 'validateFullBlock' checked the merkle root third and witness malleation
-- last, so a junk body for an honest header failed a structural check
-- first ("First transaction is not coinbase", "bad-blk-length",
-- "Block exceeds maximum weight") — a verdict — and the honest block was
-- persisted BLOCK_FAILED_VALID.
--
-- Core (validation.cpp): CheckBlock runs CheckMerkleRoot before any
-- structural check, the P2P path runs IsBlockMutated first, and
-- InvalidBlockFound never caches BLOCK_MUTATED.
--
-- Each case drives the library calls in the arm's order with the race
-- interleaving made deterministic: the step marked HOOK runs between the
-- receipt check and addHeader.  'p2pAhead' / 'p2pTip' mirror the arm's two
-- validate-and-mark branches (height > next-needed: pure validateFullBlock,
-- skipConnectChecks; height == next-needed: validateFullBlockIO).
module Main (main) where

import Test.Hspec
import Control.Concurrent.STM (readTVarIO)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( Network(..), regtest, netGenesisBlock
  , connectBlockAt, initHeaderChain, addHeader
  , HeaderChain(..), ChainEntry(..), ChainState(..)
  , checkProofOfWork, computeMerkleRoot, encodeBip34Height
  , consensusFlagsAtHeight, medianTimePast, blockMutation
  , validateFullBlock, validateFullBlockIO
  , BlockRejectKind(..), classifyBlockReject, invalidBlockFound
  , isFailedStatus
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage (defaultDBConfig, withDB)

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

net :: Network
net = regtest

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-mutation-race-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

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

-- | A non-coinbase tx (base size > 64 bytes, so the 64-byte-tx mutation
-- rule does not apply) spending a made-up outpoint.
spendTx :: Word8 -> [BS.ByteString] -> Tx
spendTx tag wit = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 tag))) 0) BS.empty 0xffffffff ]
  , txOutputs  = [ TxOut 1000 (BS.replicate 20 0x51) ]
  , txWitness  = [wit]
  , txLockTime = 0
  }

subsidy :: Word64
subsidy = 5000000000

-- | Header over @txns@, nonce ground until regtest PoW passes (addHeader
-- checks it).
mkBlock :: BlockHash -> Word32 -> [Tx] -> Block
mkBlock prevHash ts txns = Block (mine 0) txns
  where
    hdr n = BlockHeader
      { bhVersion    = 0x20000000
      , bhPrevBlock  = prevHash
      , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
      , bhTimestamp  = ts
      , bhBits       = 0x207fffff
      , bhNonce      = n
      }
    mine n | checkProofOfWork (hdr n) (netPowLimit net) = hdr n
           | otherwise                                  = mine (n + 1)

genesisHash :: BlockHash
genesisHash = computeBlockHash (blockHeader (netGenesisBlock net))

baseTime :: Word32
baseTime = bhTimestamp (blockHeader (netGenesisBlock net)) + 600

-- | P (height 1, on genesis) and the honest B (height 2, on P).
blockP :: Block
blockP = mkBlock genesisHash baseTime [coinbaseTx 1 0x01 subsidy]

blockB :: Block
blockB = mkBlock (computeBlockHash (blockHeader blockP)) (baseTime + 600)
           [coinbaseTx 2 0x02 subsidy, spendTx 0x22 []]

-- | Junk body under B's (honest) header.
withBody :: Block -> [Tx] -> Block
withBody b txns = b { blockTxns = txns }

-- | 'mutationOnReceipt' (app/Main.hs): the check runs only when the parent
-- header is known.  @Nothing@ = not checked.
receiptCheck :: HeaderChain -> Block -> IO (Maybe (Maybe String))
receiptCheck hc blk = do
  entries <- readTVarIO (hcEntries hc)
  return $ case Map.lookup (bhPrevBlock (blockHeader blk)) entries of
    Nothing    -> Nothing
    Just prevE -> Just (blockMutation (ceHeight prevE + 1 >= netSegwitHeight net) blk)

chainStateFor :: HeaderChain -> ChainEntry -> Block -> IO ChainState
chainStateFor hc entry blk = do
  entries <- readTVarIO (hcEntries hc)
  let h      = ceHeight entry
      parent = bhPrevBlock (blockHeader blk)
  return $ ChainState (h - 1) parent (ceChainWork entry)
                      (medianTimePast entries parent) (consensusFlagsAtHeight net h)

-- | Mark iff a verdict, as the arm does.  Returns (reject, marked).
markOnVerdict :: S.HaskoinDB -> HeaderChain -> BlockHash -> Either String ()
              -> IO (Either String (), Bool)
markOnVerdict db hc bh r = case r of
  Left err | classifyBlockReject err == BlockRejectVerdict -> do
    m <- invalidBlockFound db hc bh
    return (r, m)
  _ -> return (r, False)

-- | The arm's ahead branch (height > next-needed).
p2pAhead :: S.HaskoinDB -> HeaderChain -> ChainEntry -> Block -> IO (Either String (), Bool)
p2pAhead db hc entry blk = do
  cs <- chainStateFor hc entry blk
  markOnVerdict db hc (ceHash entry) (validateFullBlock net cs (const 0) False True blk Map.empty)

-- | The arm's next-needed branch (parent is the connected tip).
p2pTip :: S.HaskoinDB -> HeaderChain -> ChainEntry -> Block -> IO (Either String (), Bool)
p2pTip db hc entry blk = do
  cs <- chainStateFor hc entry blk
  r  <- validateFullBlockIO db net cs (const 0) False blk Map.empty
  markOnVerdict db hc (ceHash entry) r

-- | The race: B's body arrives while P's header is unknown; HOOK = P's
-- header arrives on another peer thread; then addHeader(B).  Returns B's
-- header-chain entry.
raceToEntry :: S.HaskoinDB -> HeaderChain -> Bool -> Block -> IO ChainEntry
raceToEntry db hc connectP body = do
  rc <- receiptCheck hc body
  rc `shouldBe` Nothing                       -- receipt check skipped
  rP <- addHeader net hc (blockHeader blockP) False   -- HOOK
  either (\e -> expectationFailure ("addHeader P: " ++ e)) (const (return ())) rP
  if connectP
    then connectBlockAt db net blockP 1 Map.empty `shouldReturn` Right ()
    else return ()
  rB <- addHeader net hc (blockHeader body) False
  case rB of
    Left e      -> expectationFailure ("addHeader B: " ++ e) >> fail "unreachable"
    Right entry -> return entry

setup :: S.HaskoinDB -> IO HeaderChain
setup db = do
  connectBlockAt db net (netGenesisBlock net) 0 Map.empty `shouldReturn` Right ()
  initHeaderChain net

statusOf :: HeaderChain -> BlockHash -> IO (Maybe Bool)
statusOf hc h = fmap (isFailedStatus . ceStatus) . Map.lookup h <$> readTVarIO (hcEntries hc)

-- | Expect a non-verdict reject and no failed mark on B.
notMarked :: HeaderChain -> ChainEntry -> (Either String (), Bool) -> Expectation
notMarked hc entry (r, marked) = do
  case r of
    Left err -> classifyBlockReject err `shouldBe` BlockRejectNonVerdict
    Right () -> expectationFailure "junk body was accepted"
  marked `shouldBe` False
  statusOf hc (ceHash entry) `shouldReturn` Just False

junkNoCoinbase, junkEmpty, junkWitnessStuffed :: [Tx]
junkNoCoinbase     = [spendTx 0x33 []]
junkEmpty          = []
-- B's own transactions (txids, so the merkle root, unchanged) with a
-- 4.1 MB witness on the spend: weight > 4M.  Pre-fix the weight verdict
-- (step 4) ran before the witness check (step 10).
junkWitnessStuffed = [coinbaseTx 2 0x02 subsidy, spendTx 0x22 [BS.replicate 4100000 0x00]]

main :: IO ()
main = hspec $ describe "IsBlockMutated survives the parent-header race (H1)" $ do

  it "mutated_body_unknown_parent_then_parent_arrives_not_marked" $
    withTestDB "ahead" $ \db -> do
      hc    <- setup db
      let body = withBody blockB junkNoCoinbase
      entry <- raceToEntry db hc False body
      p2pAhead db hc entry body >>= notMarked hc entry

  it "mutated_body_unknown_parent_then_parent_arrives_not_marked (next-needed, validateFullBlockIO)" $
    withTestDB "tip" $ \db -> do
      hc    <- setup db
      let body = withBody blockB junkNoCoinbase
      entry <- raceToEntry db hc True body
      p2pTip db hc entry body >>= notMarked hc entry

  it "empty body under a non-null merkle root is mutated, not bad-blk-length" $
    withTestDB "empty" $ \db -> do
      hc    <- setup db
      let body = withBody blockB junkEmpty
      entry <- raceToEntry db hc False body
      p2pAhead db hc entry body >>= notMarked hc entry

  it "witness-stuffed honest body is unexpected-witness, not a weight verdict" $
    withTestDB "witness" $ \db -> do
      hc    <- setup db
      let body = withBody blockB junkWitnessStuffed
      entry <- raceToEntry db hc False body
      r@(res, _) <- p2pAhead db hc entry body
      res `shouldBe` Left "unexpected-witness"
      notMarked hc entry r

  -- Consensus controls: mutation-first must not turn a verdict into a
  -- non-verdict, nor a valid block into an invalid one.
  describe "controls" $ do
    it "the honest body is still accepted" $
      withTestDB "honest" $ \db -> do
        hc    <- setup db
        entry <- raceToEntry db hc False blockB
        (r, marked) <- p2pAhead db hc entry blockB
        r `shouldBe` Right ()
        marked `shouldBe` False

    it "correct merkle root, first tx not a coinbase: still a verdict, still marked" $
      withTestDB "badstruct" $ \db -> do
        hc <- setup db
        let bad = mkBlock (computeBlockHash (blockHeader blockP)) (baseTime + 601) junkNoCoinbase
        entry <- raceToEntry db hc False bad
        (r, marked) <- p2pAhead db hc entry bad
        r `shouldBe` Left "First transaction is not coinbase"
        marked `shouldBe` True
        statusOf hc (ceHash entry) `shouldReturn` Just True

    it "correct merkle root, coinbase overpays: still a verdict, still marked (validateFullBlockIO)" $
      withTestDB "overpay" $ \db -> do
        hc <- setup db
        let bad = mkBlock (computeBlockHash (blockHeader blockP)) (baseTime + 602)
                    [coinbaseTx 2 0x03 (subsidy + 1)]
        entry <- raceToEntry db hc True bad
        (r, marked) <- p2pTip db hc entry bad
        fmap (const ()) r `shouldSatisfy` either (const True) (const False)
        either (\e -> classifyBlockReject e `shouldBe` BlockRejectVerdict) (const (return ())) r
        marked `shouldBe` True
        statusOf hc (ceHash entry) `shouldReturn` Just True

    it "a merkle-mismatched body is still rejected (Merkle root mismatch, non-verdict)" $ do
      cs <- withTestDB "mm" $ \db -> do
        hc <- setup db
        entry <- raceToEntry db hc False blockB
        chainStateFor hc entry blockB
      let body = withBody blockB [coinbaseTx 2 0x09 subsidy]
      validateFullBlock net cs (const 0) False True body Map.empty
        `shouldBe` Left "Merkle root mismatch"

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | The mempool judges every transaction against the ACTIVE chain tip.
--
-- Bitcoin Core reads m_active_chainstate.m_chain.Tip() for every admission
-- check: CheckFinalTxAtTip (tip height+1, tip MTP), CalculateLockPointsAtTip
-- / CheckSequenceLocksAtTip (a mempool coin at height tip+1 with time = tip
-- MTP; a confirmed coin's time = MTP of its block's PARENT), CheckTxInputs at
-- nSpendHeight = Height()+1, and BIP-68 always on (STANDARD_LOCKTIME_VERIFY_
-- FLAGS).
--
-- Pre-fix the live node built its mempool with height/MTP 0/0
-- (app/Main.hs) and only blockConnected (+1) / blockDisconnected (-1) moved
-- them, so the mempool's "tip" was the number of blocks since boot, its MTP
-- a median of the timestamps seen since boot, and the per-coin MTP closure
-- subtracted 1 twice.  Every spec here builds the node's mempool exactly as
-- the node does ('initNodeMempool') over a header chain + chainstate whose
-- tip is far from 0.
module MempoolActiveTipSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Control.Monad (forM_)
import Data.Word (Word32, Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeWtxid, computeBlockHash, sha256)
import Haskoin.Consensus
  ( Network, mainnet, regtest, initHeaderChain, HeaderChain(..)
  , ChainEntry(..), BlockStatus(..), medianTimePast, computeMerkleRoot )
import Haskoin.Storage
  ( HaskoinDB, UTXOCache, newUTXOCache, defaultDBConfig, withDB, addUTXO
  , UTXOEntry(..), putBestBlockHash )
import Haskoin.Mempool
import Haskoin.BlockTemplate (createBlockTemplate, BlockTemplate(..), TemplateTransaction(..))

--------------------------------------------------------------------------------
-- Fixture: a header chain + chainstate at a realistic height
--------------------------------------------------------------------------------

-- | P2WSH(OP_TRUE): standard output, spendable with witness [OP_TRUE].
opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

t0 :: Word32
t0 = 1_700_000_000

-- | Block timestamps are 600 s apart, so MTP(h) = ts(h-5) once 11 deep.
tsAt :: Word32 -> Word32 -> Word32
tsAt base h = t0 + 600 * (h - base)

data Fx = Fx
  { fxNet   :: Network
  , fxDb    :: HaskoinDB
  , fxHc    :: HeaderChain
  , fxCache :: UTXOCache
  , fxBase  :: Word32      -- ^ first fake block height
  , fxTip   :: Word32      -- ^ tip height at boot
  }

mkHeaderBlock :: BlockHash -> Word32 -> Block
mkHeaderBlock prev ts =
  let cb = Tx 1 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff)
                      (BS.pack [0x03, 0x01, 0x02, 0x03] <> encodeTs ts) 0xffffffff]
                 [TxOut 0 (BS.singleton 0x6a)] [[]] 0
  in Block (BlockHeader 0x20000000 prev (computeMerkleRoot [computeTxId cb]) ts 0x207fffff 0) [cb]
  where encodeTs t = BS.pack [fromIntegral t, fromIntegral (t `div` 256)]

-- | Append a block at height @h@ on top of the current tip; it becomes the
-- active tip (header chain AND the chainstate's best block).
appendBlock :: Fx -> Word32 -> IO Block
appendBlock fx h = do
  tip <- readTVarIO (hcTip (fxHc fx))
  let blk = mkHeaderBlock (ceHash tip) (tsAt (fxBase fx) h)
      bh  = computeBlockHash (blockHeader blk)
      ce  = ChainEntry { ceHeader = blockHeader blk, ceHash = bh, ceHeight = h
                       , ceChainWork = ceChainWork tip + 2, cePrev = Just (ceHash tip)
                       , ceStatus = StatusValid, ceMedianTime = tsAt (fxBase fx) h
                       , ceSequenceId = 0 }
  atomically $ do
    modifyTVar' (hcEntries (fxHc fx))  (Map.insert bh ce)
    modifyTVar' (hcByHeight (fxHc fx)) (Map.insert h bh)
    writeTVar (hcTip (fxHc fx)) ce
    writeTVar (hcHeight (fxHc fx)) h
  putBestBlockHash (fxDb fx) bh
  return blk

withFx :: Network -> Word32 -> Word32 -> (Fx -> IO a) -> IO a
withFx net base tipH action =
  withSystemTempDirectory "haskoin-mp-activetip" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 4096
      hc <- initHeaderChain net
      let fx = Fx net db hc cache base tipH
      forM_ [base .. tipH] (appendBlock fx)
      action fx

addCoin :: Fx -> OutPoint -> Word32 -> Bool -> IO ()
addCoin fx op h cb = atomically $
  addUTXO (fxCache fx) op (UTXOEntry (TxOut 1_000_000 opTrueSpk) h cb False)

coinOp :: Int -> OutPoint
coinOp n = OutPoint (TxId (Hash256 (BS.replicate 31 0x3c <> BS.singleton (fromIntegral n)))) 0

spend :: [(OutPoint, Word32)] -> Word64 -> Word32 -> Tx
spend ins outV lockTime = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn op BS.empty sq | (op, sq) <- ins ]
  , txOutputs  = [ TxOut outV opTrueSpk ]
  , txWitness  = [ [BS.singleton 0x51] | _ <- ins ]
  , txLockTime = lockTime
  }

-- | The node's mempool, built exactly as app/Main.hs builds it.
nodeMempool :: Fx -> IO Mempool
nodeMempool fx = initNodeMempool (fxNet fx) (fxDb fx) (fxHc fx) (fxCache fx) defaultMempoolConfig

isNonFinal :: Either MempoolError a -> Bool
isNonFinal (Left (ErrNonFinal _)) = True
isNonFinal _ = False

-- regtest chain 1..300; mainnet chain 899,700..900,000 (BIP-68 / SegWit
-- active, CSV height 419,328 far above any "blocks since boot" count)
withRegtest, withMainnet :: (Fx -> IO a) -> IO a
withRegtest = withFx regtest 1 300
withMainnet = withFx mainnet 899_700 900_000

--------------------------------------------------------------------------------

spec :: Spec
spec = describe "mempool uses the ACTIVE tip (Core CheckFinalTxAtTip / CalculateLockPointsAtTip)" $ do

  it "(1) anti-fee-sniping: nLockTime = tip height is final for the next block" $ withMainnet $ \fx -> do
    mp <- nodeMempool fx
    addCoin fx (coinOp 1) (fxTip fx - 50) False
    let tx = spend [(coinOp 1, 0xfffffffd)] 990_000 (fxTip fx)
    r <- addTransaction mp tx
    r `shouldBe` Right (computeTxId tx)

  it "(1b) control: nLockTime = tip height + 1 is non-final" $ withMainnet $ \fx -> do
    mp <- nodeMempool fx
    addCoin fx (coinOp 1) (fxTip fx - 50) False
    r <- addTransaction mp (spend [(coinOp 1, 0xfffffffd)] 990_000 (fxTip fx + 1))
    r `shouldSatisfy` isNonFinal

  it "(2) a matured time-type relative lock is accepted" $ withRegtest $ \fx -> do
    mp <- nodeMempool fx
    let coinH = fxTip fx - 20
    addCoin fx (coinOp 2) coinH False
    -- 1 unit = 512 s; coin MTP = MTP(coinH-1), tip MTP is 21 blocks later
    let tx = spend [(coinOp 2, 0x00400001)] 990_000 0
    r <- addTransaction mp tx
    r `shouldBe` Right (computeTxId tx)

  it "(3) a child of an unconfirmed parent with relative height lock 1 is not BIP68-final" $ withMainnet $ \fx -> do
    mp <- nodeMempool fx
    addCoin fx (coinOp 3) (fxTip fx - 50) False
    let parent = spend [(coinOp 3, 0xfffffffd)] 990_000 0
        pOut   = OutPoint (computeTxId parent) 0
    addTransaction mp parent `shouldReturn` Right (computeTxId parent)
    -- the parent's coin counts at height tip+1: lock 1 -> earliest tip+2
    r <- addTransaction mp (spend [(pOut, 1)] 980_000 0)
    r `shouldBe` Left ErrSeqLockNotSatisfied
    -- control: relative lock disabled (bit 31) -> accepted
    let child' = spend [(pOut, 0xfffffffd)] 980_000 0
    addTransaction mp child' `shouldReturn` Right (computeTxId child')

  it "(4) after a block connects, nLockTime between tip MTP and the tip's own timestamp is non-final" $ withMainnet $ \fx -> do
    mp <- nodeMempool fx
    let newH = fxTip fx + 1
    blk <- appendBlock fx newH
    blockConnected mp blk
    entries <- readTVarIO (hcEntries (fxHc fx))
    let tipMtp = medianTimePast entries (computeBlockHash (blockHeader blk))
        lockT  = tipMtp + 1
    lockT < tsAt (fxBase fx) newH `shouldBe` True       -- fixture sanity
    addCoin fx (coinOp 4) (fxTip fx - 50) False
    r <- addTransaction mp (spend [(coinOp 4, 0xfffffffd)] 990_000 lockT)
    r `shouldSatisfy` isNonFinal
    -- control: locktime below the tip MTP is final
    let ok = spend [(coinOp 4, 0xfffffffd)] 990_000 (tipMtp - 1)
    addTransaction mp ok `shouldReturn` Right (computeTxId ok)

  it "(5) per-coin MTP is the MTP of the block AT the given height (no second -1)" $ withRegtest $ \fx -> do
    mp <- nodeMempool fx
    entries  <- readTVarIO (hcEntries (fxHc fx))
    byHeight <- readTVarIO (hcByHeight (fxHc fx))
    forM_ [150, 299] $ \b -> do
      got <- mpGetCoinMtp mp b
      Just bh <- return (Map.lookup b byHeight)
      got `shouldBe` medianTimePast entries bh

  it "(5b) a time lock satisfied only under MTP(H-2) is rejected (coin in the tip block)" $ withRegtest $ \fx -> do
    mp <- nodeMempool fx
    addCoin fx (coinOp 5) (fxTip fx) False
    -- 2 units = 1024 s; MTP(tip-1) + 1023 > MTP(tip) = MTP(tip-1) + 600
    r <- addTransaction mp (spend [(coinOp 5, 0x00400002)] 990_000 0)
    r `shouldBe` Left ErrSeqLockNotSatisfied
    -- control: 1 unit (512 s) is satisfied
    let ok = spend [(coinOp 5, 0x00400001)] 990_000 0
    addTransaction mp ok `shouldReturn` Right (computeTxId ok)

  it "(6) coinbase maturity at spend height tip+1 (100 deep spendable, 99 deep not)" $ withMainnet $ \fx -> do
    mp <- nodeMempool fx
    addCoin fx (coinOp 6) (fxTip fx - 98) True     -- (tip+1) - h = 99
    addCoin fx (coinOp 7) (fxTip fx - 99) True     -- (tip+1) - h = 100
    r <- addTransaction mp (spend [(coinOp 6, 0xfffffffd)] 990_000 0)
    case r of
      Left (ErrCoinbaseNotMature _ _) -> return ()
      other -> expectationFailure ("immature coinbase spend: " ++ show other)
    let ok = spend [(coinOp 7, 0xfffffffd)] 990_000 0
    addTransaction mp ok `shouldReturn` Right (computeTxId ok)

  it "(7) mempool scripts run with the tip's SegWit rules (an empty-witness P2WPKH spend is refused)" $ withMainnet $ \fx -> do
    mp <- nodeMempool fx
    let p2wpkh = BS.pack [0x00, 0x14] <> BS.replicate 20 0x42
    atomically $ addUTXO (fxCache fx) (coinOp 8)
      (UTXOEntry (TxOut 1_000_000 p2wpkh) (fxTip fx - 50) False False)
    let theft = Tx 2 [TxIn (coinOp 8) BS.empty 0xfffffffd] [TxOut 990_000 opTrueSpk] [[]] 0
    r <- addTransaction mp theft
    r `shouldSatisfy` either (const True) (const False)

  it "(8) the template re-checks BIP-68 and drops the failing tx with its descendants" $ withRegtest $ \fx -> do
    mp <- nodeMempool fx
    addCoin fx (coinOp 9) (fxTip fx) False
    addCoin fx (coinOp 10) (fxTip fx - 50) False
    let stale = spend [(coinOp 9, 5)] 990_000 0         -- height lock 5 on a tip coin
        child = spend [(OutPoint (computeTxId stale) 0, 0xfffffffd)] 980_000 0
        good  = spend [(coinOp 10, 0xfffffffd)] 990_000 0
    -- 'stale' (and its child) can only be in the pool if admitted against a
    -- wrong tip; put them in directly, as a pre-fix node could have.
    forM_ [(stale, 10_000), (child, 10_000), (good, 10_000)] $ \(t, fee) ->
      atomically $ do
        let e = rawEntry t fee
        modifyTVar' (mpEntries mp) (Map.insert (meTxId e) e)
        modifyTVar' (mpByWtxid mp) (Map.insert (meWtxid e) (meTxId e))
        forM_ (txInputs t) $ \i ->
          modifyTVar' (mpByOutpoint mp) (Map.insert (txInPrevOutput i) (meTxId e))
        modifyTVar' (mpByFeeRate mp) (Map.insert (meFeeRate e, meTxId e) ())
    bt <- createBlockTemplate (fxNet fx) (fxHc fx) mp (fxCache fx) opTrueSpk BS.empty
    map ttTxId (btTransactions bt) `shouldBe` [computeTxId good]

  it "(9) the tip follows the chain through connect AND unmatched disconnect hooks" $ withRegtest $ \fx -> do
    mp <- nodeMempool fx
    blk <- appendBlock fx (fxTip fx + 1)
    blockConnected mp blk
    blockConnected mp blk                    -- a duplicate connect hook
    blockDisconnected mp blk                 -- a disconnect the chain never made
    (h, m) <- refreshMempoolTip mp
    entries <- readTVarIO (hcEntries (fxHc fx))
    h `shouldBe` fxTip fx + 1
    m `shouldBe` medianTimePast entries (computeBlockHash (blockHeader blk))
    readTVarIO (mpHeight mp) `shouldReturn` fxTip fx + 1
  where
    rawEntry t fee =
      let sz = 120 in MempoolEntry
        { meTransaction = t, meTxId = computeTxId t, meWtxid = computeWtxid t
        , meFee = fee, meFeeRate = calculateFeeRate fee sz, meSize = sz
        , meAdjWeight = sz * 4, meTime = 0, meHeight = 0
        , meAncestorCount = 1, meAncestorSize = sz, meAncestorFees = fee
        , meAncestorSigOps = 0, meDescendantCount = 1, meDescendantSize = sz
        , meDescendantFees = fee, meRBFOptIn = False }

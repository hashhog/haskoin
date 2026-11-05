{-# LANGUAGE NumericUnderscores #-}

-- | -maxmempool limits Core's DynamicMemoryUsage(), not the vsize total.
--
-- Bitcoin Core trims while @DynamicMemoryUsage() > sizelimit@
-- (CTxMemPool::TrimToSize, txmempool.cpp:868) and picks the rolling-fee
-- halflife from the same figure (GetMinFee, txmempool.cpp:837-840).  For a
-- witness-heavy spend the in-memory size is ~6x its vsize (an 800-input
-- P2WSH spend: vsize 66,244, Core usage 397,512), so a pool haskoin sized
-- by vsize held transactions Core had already evicted, and never bumped the
-- rolling minimum fee.
--
-- The scenario is the Core regtest harness's warden_invalidated_submit
-- pressure phase: -maxmempool=5, fourteen 800-input spends at fees
-- 20,000 + 5,000*i.  Core v31.1 evicts the two cheapest and keeps twelve.
module MempoolTrimUsageSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Control.Monad (forM)
import Data.Either (isRight)
import Data.Int (Int64)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word64)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.Mempool
import Haskoin.Consensus (regtest, Network(..))
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB, addUTXO,
                        UTXOEntry(..))

-- | OP_DROP OP_1 OP_DROP: the harness's DROP_SCRIPT.
dropScript :: BS.ByteString
dropScript = BS.pack [0x75, 0x51, 0x75]

dropSpk :: BS.ByteString
dropSpk = BS.pack [0x00, 0x20] <> sha256 dropScript

-- | The harness's HEAVY_SCRIPT (P2WPKH of 0x11 * 20).
heavySpk :: BS.ByteString
heavySpk = BS.pack [0x00, 0x14] <> BS.replicate 20 0x11

inputsPerTx, txCount :: Int
inputsPerTx = 800
txCount = 14

coinValue :: Word64
coinValue = 20_000

coinOp :: Int -> OutPoint
coinOp n = OutPoint (TxId (Hash256 (BS.replicate 28 0x5c
                                     <> BS.pack [ fromIntegral (n `div` 65536)
                                                , fromIntegral (n `div` 256)
                                                , fromIntegral n, 0x01 ]))) 0

-- | Spend coins [i*800 .. i*800+799] with fee 20,000 + 5,000*i; each
-- witness is two 80-byte items and the script (harness drop_spend).
pressureTx :: Int -> (Tx, Word64)
pressureTx i = (tx, fee)
  where
    fee = 20_000 + 5_000 * fromIntegral i
    ops = [ coinOp n | n <- [i * inputsPerTx .. (i + 1) * inputsPerTx - 1] ]
    tx = Tx
      { txVersion  = 2
      , txInputs   = [ TxIn op BS.empty 0xfffffffd | op <- ops ]
      , txOutputs  = [ TxOut (fromIntegral inputsPerTx * coinValue - fee) heavySpk ]
      , txWitness  = [ [BS.replicate 80 0x11, BS.replicate 80 0x22, dropScript] | _ <- ops ]
      , txLockTime = 0
      }

withPressurePool :: (Mempool -> IO a) -> IO a
withPressurePool action =
  withSystemTempDirectory "haskoin-trim-usage" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 100_000
      atomically $ mapM_ (\n -> addUTXO cache (coinOp n)
                                   (UTXOEntry (TxOut coinValue dropSpk) 1 False False))
                         [0 .. inputsPerTx * txCount - 1]
      -- -maxmempool=5 (the harness's rest_p2p profile)
      cfg <- either fail return (applyMaxMempoolMb 5 defaultMempoolConfig)
      mp <- newMempool regtest cache cfg 200 0 noopCoinMtp
      action mp

sendAll :: Mempool -> IO [(TxId, Word64)]
sendAll mp = forM [0 .. txCount - 1] $ \i -> do
  let (tx, fee) = pressureTx i
  r <- addTransaction mp tx
  isRight r `shouldBe` True
  return (computeTxId tx, fee)

spec :: Spec
spec = describe "-maxmempool trims by Core's DynamicMemoryUsage (txmempool.cpp TrimToSize / GetMinFee)" $ do

  it "maxmempool-pressure: fourteen 800-input spends under -maxmempool=5 leave twelve; the two cheapest are evicted" $
    withPressurePool $ \mp -> do
      sent <- sendAll mp
      pool <- readTVarIO (mpEntries mp)
      let kept    = [ t | (t, _) <- sent, Map.member t pool ]
          evicted = [ t | (t, _) <- sent, not (Map.member t pool) ]
      (length kept, evicted) `shouldBe` (12, map fst (take 2 sent))

  it "maxmempool-pressure: eviction bumps mempoolminfee to the evicted feerate + incrementalrelayfee" $
    withPressurePool $ \mp -> do
      sent <- sendAll mp
      let (_, fee1) = sent !! 1
          vsize1 = calculateVSize (fst (pressureTx 1))
          evictedKvb = (fee1 * 1000) `div` fromIntegral vsize1 + incrementalRelayFeePerKvb
      getMempoolMinFeeRate mp `shouldReturn` evictedKvb

  it "maxmempool-pressure-decay: 12h after a block the rolling fee halves (pool over half full: full 12h halflife)" $
    withPressurePool $ \mp -> do
      _ <- sendAll mp
      rolling <- readTVarIO (mpRollingMinFeeRate mp)
      rolling `shouldSatisfy` (> 0)
      now <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
      -- the state Core's removeForBlock leaves, 12h + 11s before now
      let elapsed = 43_200 + 11 :: Int64
      atomically $ do
        writeTVar (mpBlockSinceLastFeeBump mp) True
        writeTVar (mpLastRollingFeeUpdate mp) (now - elapsed)
      let expected = floor (rolling / (2 ** (fromIntegral elapsed / 43_200))) :: Word64
      getMempoolMinFeeRate mp `shouldReturn` expected

  it "maxmempool-pressure-decay: a connected block restarts the rolling-fee clock (Core removeForBlock: lastRollingFeeUpdate = GetTime())" $
    withPressurePool $ \mp -> do
      atomically $ writeTVar (mpLastRollingFeeUpdate mp) 0
      blockConnected mp (netGenesisBlock regtest)
      now <- (round :: Double -> Int64) . realToFrac <$> getPOSIXTime
      t <- readTVarIO (mpLastRollingFeeUpdate mp)
      t `shouldSatisfy` (\x -> x <= now && x >= now - 60)

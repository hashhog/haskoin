{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}

-- | The mempool follows the chain through invalidateblock, reconsiderblock
-- and a reorg -- driven by the REAL reorg engine ('invalidateBlock',
-- 'reconsiderBlock', 'performReorg' -> 'reorgAtomic') over a real chainstate,
-- with the mempool built exactly as the node builds it ('initNodeMempool').
--
-- Core (validation.cpp):
--   * DisconnectTip -> disconnectpool->AddTransactionsFromBlock
--   * ConnectTip    -> m_mempool->removeForBlock (confirmed txs + conflicts,
--                      recursively) for EVERY connected block
--   * MaybeUpdateMempoolForReorg: re-accept the disconnected txs earliest
--     first (bypass_limits), removeRecursive what fails, then removeForReorg
--     (non-final / sequence-locked / immature-coinbase at tip+1).
--
-- Pre-fix (haskoin 45a1524) the reorg engine never touched the mempool:
--   R1 invalidateblock returned none of the block's txs to the pool;
--   R2 a reorg whose new branch double-spends a block tx and a pool tx
--      left the pool tx and the block tx's child in the pool (a
--      getblocktemplate with a double spend and a missing input);
--   R3 reconsiderblock did not re-activate the chain (the reset blocks never
--      re-entered the candidate set).
-- Mirrors tools/mempool-reorg-sweep.py (a)/(c)/(b).
module MempoolReorgSpec (spec) where

import Test.Hspec
import Control.Concurrent.STM
import Control.Monad (foldM, forM_)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

import Haskoin.Types
import Haskoin.Crypto (computeTxId, computeBlockHash, hash160)
import Haskoin.Consensus
  ( regtest, netGenesisBlock, connectBlockAt, performReorg
  , invalidateBlock, reconsiderBlock
  , initHeaderChain, HeaderChain(..), ChainEntry(..), BlockStatus(..)
  , mkCandidateKey, headerWork, computeMerkleRoot, encodeBip34Height )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB, getBestBlockHash, putBlock, newUTXOCache
  , UTXOCache, Coin(..) )
import Haskoin.Mempool
import Haskoin.BlockTemplate (createBlockTemplate, BlockTemplate(..), TemplateTransaction(..))

--------------------------------------------------------------------------------
-- Fixture
--------------------------------------------------------------------------------

-- | P2SH(OP_TRUE): standard, spendable with scriptSig = push(OP_TRUE), no
-- witness (so blocks need no witness commitment).
p2shTrue :: BS.ByteString
p2shTrue = BS.concat [BS.pack [0xa9, 0x14], getHash160 (hash160 (BS.singleton 0x51)), BS.pack [0x87]]

p2shTrueSig :: BS.ByteString
p2shTrueSig = BS.pack [0x01, 0x51]

subsidy :: Word64
subsidy = 5_000_000_000

fee :: Word64
fee = 10_000

baseTime :: Word32
baseTime = 1_700_000_000

coinbaseAt :: Word32 -> Word8 -> Tx
coinbaseAt h tag = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff)
                        (encodeBip34Height h `BS.snoc` tag) 0xffffffff ]
  , txOutputs  = [ TxOut subsidy p2shTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Spend output 0 of @prev@ (value @v@); @extra@ makes a distinct txid for
-- a double spend of the same input.
spendOf :: Tx -> Word64 -> Word64 -> Tx
spendOf prev v extra = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn (OutPoint (computeTxId prev) 0) p2shTrueSig 0xfffffffe ]
  , txOutputs  = [ TxOut (v - fee - extra) p2shTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

mkBlock :: BlockHash -> Word32 -> [Tx] -> Block
mkBlock prev ts txns = Block
  { blockHeader = BlockHeader 0x20000000 prev
                    (computeMerkleRoot (map computeTxId txns)) ts 0x207fffff 0
  , blockTxns = txns }

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> ChainEntry
mkEntry blk h prev work sq = ChainEntry
  { ceHeader = blockHeader blk, ceHash = computeBlockHash (blockHeader blk)
  , ceHeight = h, ceChainWork = work, cePrev = Just prev
  , ceStatus = StatusValid, ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = sq }

insertActive :: HeaderChain -> ChainEntry -> IO ()
insertActive hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc) ce
  writeTVar (hcHeight hc) (ceHeight ce)

insertSide :: HeaderChain -> ChainEntry -> IO ()
insertSide hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

data Fx = Fx
  { fxDb    :: S.HaskoinDB
  , fxHc    :: HeaderChain
  , fxCache :: UTXOCache
  , fxMp    :: Mempool
  , fxCb    :: Word32 -> Tx              -- ^ main-chain coinbase at height h
  , fxHash  :: Map.Map Word32 BlockHash  -- ^ main chain by height (0..112)
  , fxWork  :: Map.Map Word32 Integer
  , fxTx    :: Map.Map String Tx
  }

-- | Main chain: 1..110 coinbase only,
--   111 = [cb, A1 <- cb1, P <- cb2]
--   112 = [cb, A2 <- cb3, C <- P, IMM <- cb12]
-- IMM spends a coinbase that is immature at 111 (111 - 12 = 99).
withChain :: (Fx -> IO a) -> IO a
withChain act =
  withSystemTempDirectory "haskoin-mempool-reorg" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      let net = regtest
          genesis = netGenesisBlock net
          gHash = computeBlockHash (blockHeader genesis)
          gWork = headerWork (blockHeader genesis)
          cb h = coinbaseAt h 0x01
          coinOf h = Coin (head (txOutputs (cb h))) h True
          a1  = spendOf (cb 1) subsidy 0
          p   = spendOf (cb 2) subsidy 0
          a2  = spendOf (cb 3) subsidy 0
          c   = spendOf p (subsidy - fee) 0
          imm = spendOf (cb 12) subsidy 0
          extra 111 = [a1, p]
          extra 112 = [a2, c, imm]
          extra _   = []
          spent 111 = Map.fromList [ (OutPoint (computeTxId (cb 1)) 0, coinOf 1)
                                   , (OutPoint (computeTxId (cb 2)) 0, coinOf 2) ]
          spent 112 = Map.fromList [ (OutPoint (computeTxId (cb 3)) 0, coinOf 3)
                                   , (OutPoint (computeTxId p) 0, Coin (head (txOutputs p)) 111 False)
                                   , (OutPoint (computeTxId (cb 12)) 0, coinOf 12) ]
          spent _   = Map.empty
      hc <- initHeaderChain net
      connectBlockAt db net genesis 0 Map.empty `shouldReturn` Right ()
      let step (prev, work, hs, ws) h = do
            let blk = mkBlock prev (baseTime + 60 * h) (cb h : extra h)
                work' = work + headerWork (blockHeader blk)
                ce = mkEntry blk h prev work' (fromIntegral h)
            connectBlockAt db net blk h (spent h) `shouldReturn` Right ()
            insertActive hc ce
            return (ceHash ce, work', Map.insert h (ceHash ce) hs, Map.insert h work' ws)
      (_, _, hashes, works) <- foldM step (gHash, gWork, Map.singleton 0 gHash, Map.singleton 0 gWork) [1 .. 112]
      cache <- newUTXOCache db 100_000
      mp <- initNodeMempool net db hc cache defaultMempoolConfig
      act Fx { fxDb = db, fxHc = hc, fxCache = cache, fxMp = mp, fxCb = cb
             , fxHash = hashes, fxWork = works
             , fxTx = Map.fromList [("A1", a1), ("P", p), ("A2", a2), ("C", c), ("IMM", imm)] }

txOf :: Fx -> String -> Tx
txOf fx k = fxTx fx Map.! k

pool :: Fx -> [(String, Tx)] -> IO (Set.Set String)
pool fx named = do
  ids <- Set.fromList <$> getMempoolTxIds (fxMp fx)
  let byId = Map.fromList [ (computeTxId t, n) | (n, t) <- named ]
  return $ Set.map (\i -> Map.findWithDefault ("?" ++ show i) i byId) ids

admit :: Fx -> Tx -> IO ()
admit fx t = addTransaction (fxMp fx) t `shouldReturn` Right (computeTxId t)

--------------------------------------------------------------------------------

spec :: Spec
spec = describe "mempool follows the chain through the reorg engine (Core MaybeUpdateMempoolForReorg)" $ do

  it "R1: invalidateblock returns the disconnected txs earliest-first and runs removeForReorg" $ withChain $ \fx -> do
    let m1 = spendOf (txOf fx "A2") (subsidy - fee) 0   -- child of a 112 tx
        m2 = spendOf (txOf fx "A1") (subsidy - fee) 0   -- child of a 111 tx
        named = ("M1", m1) : ("M2", m2) : Map.toList (fxTx fx)
    admit fx m1
    admit fx m2
    r <- invalidateBlock regtest (fxCache fx) (fxDb fx) (fxHc fx) Nothing (fxHash fx Map.! 111)
    r `shouldBe` Right ()
    getBestBlockHash (fxDb fx) `shouldReturn` Just (fxHash fx Map.! 110)
    -- C (child of P, confirmed in the block ABOVE P) is back: parents first.
    -- IMM spends cb12, immature at 111 -> not returned.
    pool fx named `shouldReturn` Set.fromList ["A1", "P", "A2", "C", "M1", "M2"]
    -- UpdateTransactionsFromBlock: the re-added parent and its pooled child
    -- count each other.
    Just eA1 <- getTransaction (fxMp fx) (computeTxId (txOf fx "A1"))
    Just eM2 <- getTransaction (fxMp fx) (computeTxId m2)
    meDescendantCount eA1 `shouldBe` 2
    meAncestorCount eM2 `shouldBe` 2
    -- (d) the template is the pool, every parent before its child.
    bt <- createBlockTemplate regtest (fxHc fx) (fxMp fx) (fxCache fx) p2shTrue BS.empty
    let order = map ttTxId (btTransactions bt)
        pos t = length (takeWhile (/= computeTxId t) order)
    Set.fromList order `shouldBe` Set.fromList (map computeTxId
      [txOf fx "A1", txOf fx "P", txOf fx "A2", txOf fx "C", m1, m2])
    forM_ [(txOf fx "P", txOf fx "C"), (txOf fx "A1", m2), (txOf fx "A2", m1)] $ \(par, ch) ->
      (pos par < pos ch) `shouldBe` True

  it "R2: a reorg drops the pooled double spend and the child of a conflicted block tx" $ withChain $ \fx -> do
    let a1 = txOf fx "A1"
        m2 = spendOf a1 (subsidy - fee) 0                -- child of A1
        m2c = spendOf m2 (subsidy - 2 * fee) 0           -- grandchild of A1
        m3 = spendOf (fxCb fx 6) subsidy 0               -- pool-only
        m3c = spendOf m3 (subsidy - fee) 0               -- child of M3
        x  = spendOf (fxCb fx 1) subsidy 1               -- conflicts A1
        z  = spendOf (fxCb fx 6) subsidy 1               -- conflicts M3
        named = [("M2", m2), ("M2c", m2c), ("M3", m3), ("M3c", m3c), ("X", x), ("Z", z)]
                ++ Map.toList (fxTx fx)
    mapM_ (admit fx) [m2, m2c, m3, m3c]
    -- branch off 110: 111b [cb, X], 112b [cb, P], 113b [cb, Z]
    let h110 = fxHash fx Map.! 110
        w110 = fxWork fx Map.! 110
        mk (prev, work) (h, txs) = do
          let blk = mkBlock prev (baseTime + 60 * h + 7) (coinbaseAt h 0x0b : txs)
              work' = work + headerWork (blockHeader blk)
              ce = mkEntry blk h prev work' (1000 + fromIntegral h)
          putBlock (fxDb fx) (ceHash ce) blk
          insertSide (fxHc fx) ce
          return (ceHash ce, work')
    (tipB, _) <- foldM mk (h110, w110)
                      [(111, [x]), (112, [txOf fx "P"]), (113, [z])]
    r <- performReorg regtest (fxCache fx) (fxDb fx) (fxHc fx) Nothing (fxHash fx Map.! 112) tipB
    r `shouldBe` Right ()
    getBestBlockHash (fxDb fx) `shouldReturn` Just tipB
    -- Core: {A2, C, IMM}.  A1 fails (cb1 spent by X) -> M2 and M2c removed
    -- with it (removeRecursive); M3 conflicts Z (removeForBlock) and takes
    -- M3c; P re-confirmed in 112b.
    pool fx named `shouldReturn` Set.fromList ["A2", "C", "IMM"]

  it "R3: reconsiderblock re-activates the chain and removeForBlock clears the pool" $ withChain $ \fx -> do
    let m2 = spendOf (txOf fx "A1") (subsidy - fee) 0
        named = ("M2", m2) : Map.toList (fxTx fx)
    admit fx m2
    invalidateBlock regtest (fxCache fx) (fxDb fx) (fxHc fx) Nothing (fxHash fx Map.! 111)
      `shouldReturn` Right ()
    getBestBlockHash (fxDb fx) `shouldReturn` Just (fxHash fx Map.! 110)
    reconsiderBlock regtest (fxCache fx) (fxDb fx) (fxHc fx) Nothing (fxHash fx Map.! 111)
      `shouldReturn` Right ()
    getBestBlockHash (fxDb fx) `shouldReturn` Just (fxHash fx Map.! 112)
    pool fx named `shouldReturn` Set.fromList ["M2"]

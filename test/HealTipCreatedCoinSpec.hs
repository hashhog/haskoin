{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Linear connect must see a coin the current tip CREATED but never
-- wrote to PrefixUTXO — disconnect cannot restore it, because the
-- stale block never spent it.
--
-- == Live control (mainnet 2026-09-18, deployed 042d357) ==
--
-- Disconnect of the stale 966500 succeeded (tip 966500 -> 966499).
-- Linear connect of Core's 966500 then failed eight times:
--
-- @
-- [W163 diag] next-needed block 966500 rejected by connectBlock:
--   Core full-block validation: Missing UTXO:
--   OutPoint {outPointHash = 5bcc4f93…, outPointIndex = 6}
-- @
--
-- Parent tx 5bcc4f93… was CREATED in the fork-point block 966499
-- (tx index 1981, 8 outputs).  Vout 6 is the only P2PKH; 0-5 and 7
-- are P2WPKH.  The stale 966500 spent only :2; Core's 966500 spends
-- :6 first (tx index 2) then :2 (tx index 3010).  After disconnect,
-- PrefixUTXO held {0,1,2,3,4,5,7} and not 6.  Disconnect restored
-- :2 and could not restore :6 — it was never inserted when 966499
-- connected.
--
-- The queue's "already present" restore-skip does not fire here:
-- applyTxInUndo / buildDisconnectBlockOps never see :6.  The rule
-- that decides which coin is missing is "created by the current tip
-- and omitted from PrefixUTXO", not "spent by the stale block".
--
-- == What this suite pins ==
--
--   * H1 — after punching :6 of an 8-output tip tx (P2PKH at 6,
--     P2WPKH elsewhere), buildSpentUtxoMapFromDB for a child that
--     spends :6 contains :6.  PRE-FIX: omitted (Missing UTXO).
--   * H2 — connectBlockAt of that child succeeds; :6 is spent.
--   * H3 — a vout the tip itself spent is NOT resurrected.
--   * H4 — N pre-fork coins spent by BOTH branches are all restored
--     by disconnect (N=1,3,8; spends at front/mid/back).  Passes
--     pre- and post-fix — the restore path is not the live hole.
--
-- References:
--   receipts/haskoin-reorg-missing-utxo-966500-2026-09-17.md
--   bitcoin-core/src/validation.cpp ConnectBlock / DisconnectBlock
module HealTipCreatedCoinSpec (spec) where

import Test.Hspec
import Control.Monad (foldM, forM_)
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar)
import Data.Maybe (isJust)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeBlockHash, computeTxId)
import Haskoin.Consensus
  ( regtest, netGenesisBlock
  , connectBlockAt
  , performReorg
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  , isAlreadyConnected
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , getUTXOCoin
  , deleteUTXO
  , putBlock
  , newUTXOCache
  , buildSpentUtxoMapFromDB
  , buildSpentUtxoMapCached
  , readHealTipAttempts
  , Coin(..)
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-heal-tip-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

-- | 22-byte P2WPKH template (OP_0 PUSH20).  Matches vouts 0-5,7 of
-- live 5bcc4f93….
p2wpkh :: Word8 -> BS.ByteString
p2wpkh tag = BS.pack (0x00 : 0x14 : replicate 20 tag)

-- | 25-byte P2PKH (OP_DUP OP_HASH160 PUSH20 OP_EQUALVERIFY OP_CHECKSIG).
-- Live vout 6.
p2pkh :: Word8 -> BS.ByteString
p2pkh tag = BS.pack ([0x76, 0xa9, 20] ++ replicate 20 tag ++ [0x88, 0xac])

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

coinbaseTxAt :: Word32 -> Word8 -> Tx
coinbaseTxAt h tag = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = nullOutPoint
      , txInScript     = encodeBip34Height h `BS.snoc` tag
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

commonCoinbaseCoin :: Word32 -> Coin
commonCoinbaseCoin h = Coin
  { coinTxOut      = head (txOutputs (coinbaseTxAt h 0x01))
  , coinHeight     = h
  , coinIsCoinbase = True
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

mkEntry :: Block -> Word32 -> BlockHash -> Integer -> Word64 -> ChainEntry
mkEntry blk h prevHash work seqId = ChainEntry
  { ceHeader     = blockHeader blk
  , ceHash       = computeBlockHash (blockHeader blk)
  , ceHeight     = h
  , ceChainWork  = work
  , cePrev       = Just prevHash
  , ceStatus     = StatusValid
  , ceMedianTime = bhTimestamp (blockHeader blk)
  , ceSequenceId = seqId
  }

insertActiveTip :: HeaderChain -> ChainEntry -> IO ()
insertActiveTip hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcByHeight hc)   (Map.insert (ceHeight ce) (ceHash ce))
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))
  writeTVar (hcTip hc)    ce
  writeTVar (hcHeight hc) (ceHeight ce)

insertSideEntry :: HeaderChain -> ChainEntry -> IO ()
insertSideEntry hc ce = atomically $ do
  modifyTVar' (hcEntries hc)    (Map.insert (ceHash ce) ce)
  modifyTVar' (hcCandidates hc) (Set.insert (mkCandidateKey ce))

baseTime :: Word32
baseTime = 1296688700

-- | Height-1 coinbase is mature at 102 (regtest COINBASE_MATURITY = 100).
forkHeight :: Word32
forkHeight = 101

-- | 8 outputs, values sum to 50 BTC.  @scriptAt 6@ is P2PKH in the live
-- shape; N-restore uses OP_TRUE so performReorg's script verify is a
-- no-op (empty scriptSig).
eightOutTxWith :: (Int -> BS.ByteString) -> OutPoint -> Tx
eightOutTxWith scriptAt op =
  let mkOut i
        | i == 6    = TxOut 400000000 (scriptAt i)
        | otherwise = TxOut 657142857 (scriptAt i)
      -- 7 * 657142857 + 400000000 = 4_599_999_999 + 400_000_000 = 4_999_999_999
      -- short 1 sat vs 50 BTC; bump vout 0.
      outs0 = [mkOut i | i <- [0 :: Int .. 7]]
      outs  = case outs0 of
        (TxOut v s : rest) -> TxOut (v + 1) s : rest
        [] -> []
  in Tx
    { txVersion  = 1
    , txInputs   = [ TxIn
        { txInPrevOutput = op
        , txInScript     = BS.empty
        , txInSequence   = 0xffffffff
        } ]
    , txOutputs  = outs
    , txWitness  = [[]]
    , txLockTime = 0
    }

eightOutTx :: OutPoint -> Tx
eightOutTx = eightOutTxWith $ \i ->
  if i == 6 then p2pkh (fromIntegral i) else p2wpkh (fromIntegral i)

eightOutOpTrue :: OutPoint -> Tx
eightOutOpTrue = eightOutTxWith (const opTrue)

spendOut :: OutPoint -> Word64 -> Tx
spendOut op val = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = op
      , txInScript     = BS.empty
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = val, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

connectChainToFork :: S.HaskoinDB -> IO (HeaderChain, BlockHash, Integer)
connectChainToFork db = do
  let net     = regtest
      genesis = netGenesisBlock net
      gHash   = computeBlockHash (blockHeader genesis)
      gWork   = headerWork (blockHeader genesis)
  hc <- initHeaderChain net
  rG <- connectBlockAt db net genesis 0 Map.empty
  rG `shouldBe` Right ()
  let step (prevHash, work) h = do
        let blk   = mkBlock prevHash (baseTime + h) [coinbaseTxAt h 0x01]
            work' = work + headerWork (blockHeader blk)
            ce    = mkEntry blk h prevHash work' (fromIntegral h)
        r <- connectBlockAt db net blk h Map.empty
        r `shouldBe` Right ()
        insertActiveTip hc ce
        return (ceHash ce, work')
  (forkHash, forkWork) <- foldM step (gHash, gWork) [1 .. forkHeight]
  return (hc, forkHash, forkWork)

parentEightWith :: Tx -> S.HaskoinDB -> HeaderChain -> BlockHash -> Integer
                -> IO (Block, Tx, OutPoint)
parentEightWith parent db hc forkHash forkWork = do
  let net     = regtest
      mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
      pTxns   = [coinbaseTxAt 102 0x0a, parent]
      pBlk    = mkBlock forkHash (baseTime + forkHeight + 1) pTxns
      pWork   = forkWork + headerWork (blockHeader pBlk)
      pCe     = mkEntry pBlk 102 forkHash pWork 1001
      spent   = Map.singleton mature1 (commonCoinbaseCoin 1)
  r <- connectBlockAt db net pBlk 102 spent
  r `shouldBe` Right ()
  insertActiveTip hc pCe
  let parentId = computeTxId parent
  return (pBlk, parent, OutPoint parentId 6)

parentEight :: S.HaskoinDB -> HeaderChain -> BlockHash -> Integer
            -> IO (Block, Tx, OutPoint)
parentEight = parentEightWith (eightOutTx (OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0))

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "heal tip-created missing coin" $ do

    it "H1: spent map contains punched P2PKH :6 of an 8-output tip tx" $ do
      withTestDB "h1" $ \db -> do
        (hc, forkHash, forkWork) <- connectChainToFork db
        (_, parent, op6) <- parentEight db hc forkHash forkWork
        -- Precondition: connect wrote all eight, including P2PKH :6.
        let parentId = computeTxId parent
        forM_ [0 :: Word32 .. 7] $ \i -> do
          mc <- getUTXOCoin db (OutPoint parentId i)
          mc `shouldSatisfy` isJust
        -- Punch the live hole.
        deleteUTXO db op6
        getUTXOCoin db op6 `shouldReturn` Nothing
        -- Child spends :6 (live 966500 tx index 2).
        mTip <- getBestBlockHash db
        tip <- maybe (expectationFailure "no tip" >> return (error "no tip"))
                     return mTip
        let childTx = spendOut op6 400000000
            child   = mkBlock tip (baseTime + forkHeight + 2)
                        [coinbaseTxAt 103 0x0b, childTx]
        spent <- buildSpentUtxoMapFromDB db child
        Map.lookup op6 spent `shouldSatisfy` isJust

    it "H2: connectBlockAt of the child spends the healed :6" $ do
      withTestDB "h2" $ \db -> do
        (hc, forkHash, forkWork) <- connectChainToFork db
        (_, _, op6) <- parentEight db hc forkHash forkWork
        deleteUTXO db op6
        mTip <- getBestBlockHash db
        tip <- maybe (expectationFailure "no tip" >> return (error "no tip"))
                     return mTip
        let childTx = spendOut op6 400000000
            child   = mkBlock tip (baseTime + forkHeight + 2)
                        [coinbaseTxAt 103 0x0b, childTx]
        spent <- buildSpentUtxoMapFromDB db child
        case Map.lookup op6 spent of
          Nothing -> expectationFailure
            "H2: spent map omitted punched :6 (heal did not run)"
          Just c  -> do
            r <- connectBlockAt db regtest child 103 (Map.singleton op6 c)
            r `shouldBe` Right ()
            getUTXOCoin db op6 `shouldReturn` Nothing

    it "H3: does not resurrect a vout the tip itself spent" $ do
      withTestDB "h3" $ \db -> do
        (hc, forkHash, forkWork) <- connectChainToFork db
        -- Parent creates 8 outputs AND spends :2 intra-block.
        let net     = regtest
            mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
            parent  = eightOutTx mature1
            parentId = computeTxId parent
            op2     = OutPoint parentId 2
            intra   = spendOut op2 657142857
            pTxns   = [coinbaseTxAt 102 0x0a, parent, intra]
            pBlk    = mkBlock forkHash (baseTime + forkHeight + 1) pTxns
            pWork   = forkWork + headerWork (blockHeader pBlk)
            pCe     = mkEntry pBlk 102 forkHash pWork 1001
            spent   = Map.singleton mature1 (commonCoinbaseCoin 1)
        r <- connectBlockAt db net pBlk 102 spent
        r `shouldBe` Right ()
        insertActiveTip hc pCe
        -- :2 was created and spent in the tip; it must stay absent.
        getUTXOCoin db op2 `shouldReturn` Nothing
        let child = mkBlock (computeBlockHash (blockHeader pBlk))
                            (baseTime + forkHeight + 2)
                            [coinbaseTxAt 103 0x0b, spendOut op2 657142857]
        spentC <- buildSpentUtxoMapFromDB db child
        Map.lookup op2 spentC `shouldBe` Nothing

  describe "reorg prefork N-restore" $ do
    -- Queue-required control: losing and winning blocks spend the SAME
    -- N pre-fork coins; after reorg every one is spent (restored then
    -- re-spent), none missing.  Pre-fork coins are the 8 outputs of
    -- the height-102 parent (non-coinbase, immediately spendable) so
    -- this does not trip coinbase maturity.  Passes on 042d357 —
    -- disconnect restore is not the live :6 hole.
    forM_ [(1, [0]), (3, [0, 1, 2]), (8, [0, 1, 2, 3, 4, 5, 6, 7])] $ \(n, positions) ->
      it ("N=" ++ show n ++ " shared prefork spends at " ++ show positions) $
        withTestDB ("n" ++ show n) $ \db -> do
          (hc, forkHash, forkWork) <- connectChainToFork db
          let mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
          (pBlk, parent, _) <- parentEightWith (eightOutOpTrue mature1) db hc forkHash forkWork
          let net      = regtest
              parentId = computeTxId parent
              pHash    = computeBlockHash (blockHeader pBlk)
              outVal i
                | i == 6    = 400000000
                | i == 0    = 657142858
                | otherwise = 657142857
              pick i   = OutPoint parentId (fromIntegral i)
              spends   = [spendOut (pick i) (outVal i) | i <- positions]
              lTxns    = coinbaseTxAt 103 0x0a : spends
              wTxns    = coinbaseTxAt 103 0x0b : spends
              lBlk     = mkBlock pHash (baseTime + forkHeight + 2) lTxns
              w1Blk    = mkBlock pHash (baseTime + 400) wTxns
              lWork    = headerWork (blockHeader lBlk)
              w1Work   = headerWork (blockHeader w1Blk)
              w1Hash   = computeBlockHash (blockHeader w1Blk)
              w2Blk    = mkBlock w1Hash (baseTime + 401) [coinbaseTxAt 104 0x0c]
              w2Work   = w1Work + headerWork (blockHeader w2Blk)
              lCe      = mkEntry lBlk 103 pHash lWork 1002
              w1Ce     = mkEntry w1Blk 103 pHash w1Work 2002
              w2Ce     = mkEntry w2Blk 104 w1Hash w2Work 2003
          -- Parent already connected; build spent map from disk.
          spentL <- buildSpentUtxoMapFromDB db lBlk
          rL <- connectBlockAt db net lBlk 103 spentL
          rL `shouldBe` Right ()
          insertActiveTip hc lCe
          putBlock db (ceHash w1Ce) w1Blk
          putBlock db (ceHash w2Ce) w2Blk
          insertSideEntry hc w1Ce
          insertSideEntry hc w2Ce
          cache <- newUTXOCache db 100000
          res <- performReorg net cache db hc Nothing (ceHash lCe) (ceHash w2Ce)
          case res of
            Right () -> return ()
            Left err -> expectationFailure $
              "N=" ++ show n ++ " reorg aborted: " ++ err
          getBestBlockHash db `shouldReturn` Just (ceHash w2Ce)
          forM_ positions $ \i ->
            getUTXOCoin db (pick i) `shouldReturn` Nothing

  -- H5/H6: an intra-block spend (prevout created by an earlier tx of the
  -- SAME block) must not take the tip-repair path. Core resolves it from
  -- the in-memory view that UpdateCoins fills tx-by-tx
  -- (validation.cpp:2600); the repair scan decodes the whole tip block per
  -- call and can never find it. Live 911,955: 4,372 such inputs,
  -- connect=521,585 ms. The spent map itself must be unchanged.
  describe "intra-block spends skip the tip-repair scan" $ do

    it "H5: both builders return the same map with zero repair scans" $ do
      withTestDB "h5" $ \db -> do
        (hc, forkHash, forkWork) <- connectChainToFork db
        (_, parent, _) <- parentEight db hc forkHash forkWork
        mTip <- getBestBlockHash db
        tip <- maybe (expectationFailure "no tip" >> return (error "no tip"))
                     return mTip
        let parentId = computeTxId parent
            opA      = OutPoint parentId 0          -- on disk
            txA      = spendOut opA 600000000
            opB      = OutPoint (computeTxId txA) 0 -- created in THIS block
            txB      = spendOut opB 500000000
            opC      = OutPoint (computeTxId txB) 0 -- chained twice
            txC      = spendOut opC 400000000
            child    = mkBlock tip (baseTime + forkHeight + 2)
                         [coinbaseTxAt 103 0x0b, txA, txB, txC]
        Just coinA <- getUTXOCoin db opA
        cache <- newUTXOCache db 100000
        n0 <- readHealTipAttempts
        spentDB <- buildSpentUtxoMapFromDB db child
        spentC  <- buildSpentUtxoMapCached cache child
        n1 <- readHealTipAttempts
        spentDB `shouldBe` Map.singleton opA coinA
        spentC  `shouldBe` Map.singleton opA coinA
        (n1 - n0) `shouldBe` 0
        -- connect still resolves the chained spends from the block itself
        r <- connectBlockAt db regtest child 103 spentC
        r `shouldBe` Right ()
        getUTXOCoin db opB `shouldReturn` Nothing
        mC <- getUTXOCoin db (OutPoint (computeTxId txC) 0)
        mC `shouldSatisfy` isJust

    it "H6: control - a genuine miss still takes the repair scan" $ do
      withTestDB "h6" $ \db -> do
        (hc, forkHash, forkWork) <- connectChainToFork db
        _ <- parentEight db hc forkHash forkWork
        mTip <- getBestBlockHash db
        tip <- maybe (expectationFailure "no tip" >> return (error "no tip"))
                     return mTip
        let ghost = OutPoint (TxId (Hash256 (BS.replicate 32 0x7e))) 3
            child = mkBlock tip (baseTime + forkHeight + 2)
                      [coinbaseTxAt 103 0x0b, spendOut ghost 1]
        cache <- newUTXOCache db 100000
        n0 <- readHealTipAttempts
        spentDB <- buildSpentUtxoMapFromDB db child
        spentC  <- buildSpentUtxoMapCached cache child
        n1 <- readHealTipAttempts
        spentDB `shouldBe` Map.empty
        spentC  `shouldBe` Map.empty
        (n1 - n0) `shouldBe` 2

    it "H7: N genuine misses in one block decode the tip once per builder" $ do
      withTestDB "h7" $ \db -> do
        (hc, forkHash, forkWork) <- connectChainToFork db
        _ <- parentEight db hc forkHash forkWork
        mTip <- getBestBlockHash db
        tip <- maybe (expectationFailure "no tip" >> return (error "no tip"))
                     return mTip
        let ghost i = OutPoint (TxId (Hash256 (BS.replicate 32 (0x60 + i)))) 0
            spends  = [ spendOut (ghost i) 1 | i <- [0 .. 4] ]
            child   = mkBlock tip (baseTime + forkHeight + 2)
                        (coinbaseTxAt 103 0x0b : spends)
        cache <- newUTXOCache db 100000
        n0 <- readHealTipAttempts
        spentDB <- buildSpentUtxoMapFromDB db child
        spentC  <- buildSpentUtxoMapCached cache child
        n1 <- readHealTipAttempts
        spentDB `shouldBe` Map.empty
        spentC  `shouldBe` Map.empty
        (n1 - n0) `shouldBe` 2

  -- Core AcceptBlock: if (fAlreadyHave) return true; (validation.cpp:4335)
  describe "isAlreadyConnected (duplicate of a connected block)" $ do
    let h1 = BlockHash (Hash256 (BS.replicate 32 0x11))
        h2 = BlockHash (Hash256 (BS.replicate 32 0x22))
    it "D1: same hash below next-needed is a duplicate" $
      isAlreadyConnected 100 99 (Just h1) h1 `shouldBe` True
    it "D2: a different hash at a connected height is NOT (fork block)" $
      isAlreadyConnected 100 99 (Just h1) h2 `shouldBe` False
    it "D3: next-needed itself is never a duplicate" $
      isAlreadyConnected 100 100 (Just h1) h1 `shouldBe` False
    it "D4: no stored hash is not a duplicate" $
      isAlreadyConnected 100 50 Nothing h1 `shouldBe` False

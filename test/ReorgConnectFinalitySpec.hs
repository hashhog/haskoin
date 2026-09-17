{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Reorg connect must use the CONNECTING block's height/MTP for
-- IsFinalTx / BIP-68, and must not disguise a missing prefork coin as
-- @bad-txns-nonfinal@.
--
-- == Live control (mainnet 2026-09-17, deployed f317c18) ==
--
-- Connecting Core's 966500
-- (@000000000000000000002b9b942ee9ae9da493eed410ea71340241ea3e273d0a@)
-- aborted with @bad-txns-nonfinal@, then a later attempt aborted at
-- 966501 with @Missing UTXO@ of a coin BOTH 966500s create
-- (@412968ee…:0@ / internal @c698c53f…@).
--
-- Core's 966500 is IsFinalTx-clean at height 966500 (75 txs with
-- nLockTime=966499, none with time-based nLockTime).  23 of its 26
-- BIP-68 (seq=1) inputs are ALSO spent on the losing 966500.  When
-- those coins are absent from @spentUtxos@, 'validateFullBlock' used
-- the connecting block's height as the coin height:
--
-- @
--   slMinHeight = 966500 + 1 - 1 = 966500
--   checkSequenceLocks 966500  =>  966500 > 966500  = False
--   => "bad-txns-nonfinal"
-- @
--
-- Core's AccessCoin on a missing coin returns nHeight=0, so SequenceLocks
-- would pass and ConnectBlock would report the missing input.  The
-- @height@ fallback turned a Missing-UTXO into a finality rejection —
-- which is why the operator saw @bad-txns-nonfinal@ on a block whose
-- nLockTime/MTP are fine.
--
-- == What this suite pins ==
--
--   * F1 — a v2 seq=1 spend whose prevout is NOT in spentUtxos is
--     @Missing UTXO@, not @bad-txns-nonfinal@.  PRE-FIX: nonfinal.
--   * F2 — IsFinalTx during performReorg uses the connecting block's
--     height, not the fork / stale tip (nLockTime = connectingHeight-1
--     with nSequence != SEQUENCE_FINAL).
--   * F3 — a BIP-68 seq=1 spend of a prefork coin that BOTH branches
--     spend reorgs in (the 23-input live shape).
--   * F4 — a shared tx re-created by the first connected block and
--     spent by the SECOND (live 966501 / c698c53f).
--
-- References:
--   bitcoin-core/src/consensus/tx_verify.cpp IsFinalTx / SequenceLocks
--   bitcoin-core/src/validation.cpp ContextualCheckBlock (nHeight,
--     nLockTimeCutoff = pindexPrev->GetMedianTimePast())
--   bitcoin-core/src/coins.h AccessCoin (missing coin nHeight = 0)
module ReorgConnectFinalitySpec (spec) where

import Test.Hspec
import Control.Monad (foldM)
import Control.Concurrent.STM (atomically, modifyTVar', writeTVar)
import Data.List (isInfixOf)
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
  , validateFullBlock
  , ChainState(..)
  , consensusFlagsAtHeight
  , initHeaderChain
  , HeaderChain(..)
  , ChainEntry(..)
  , BlockStatus(..)
  , mkCandidateKey
  , headerWork
  , computeMerkleRoot
  , encodeBip34Height
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage
  ( defaultDBConfig, withDB
  , getBestBlockHash
  , getUTXO
  , putBlock
  , newUTXOCache
  , Coin(..)
  )

import System.IO.Temp (withSystemTempDirectory)
import System.FilePath ((</>))

--------------------------------------------------------------------------------
-- Shared helpers
--------------------------------------------------------------------------------

withTestDB :: String -> (S.HaskoinDB -> IO a) -> IO a
withTestDB tag action =
  withSystemTempDirectory ("haskoin-reorg-finality-" ++ tag) $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

fakeHash :: Word8 -> BlockHash
fakeHash b = BlockHash (Hash256 (BS.replicate 32 b))

fakeTxId :: Word8 -> TxId
fakeTxId b = TxId (Hash256 (BS.replicate 32 b))

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

spendTx :: OutPoint -> Tx
spendTx op = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = op
      , txInScript     = BS.empty
      , txInSequence   = 0xffffffff
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | v2 spend with BIP-68 relative height lock (seq=1, disable-flag clear).
bip68SpendTx :: OutPoint -> Tx
bip68SpendTx op = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn
      { txInPrevOutput = op
      , txInScript     = BS.empty
      , txInSequence   = 1
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Anti-fee-sniping shape: nLockTime = height-1, nSequence not FINAL,
-- so IsFinalTx actually consults the block height.
lockTimeSpendTx :: OutPoint -> Word32 -> Tx
lockTimeSpendTx op lt = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn
      { txInPrevOutput = op
      , txInScript     = BS.empty
      , txInSequence   = 0xfffffffe
      } ]
  , txOutputs  = [ TxOut { txOutValue = 5000000000, txOutScript = opTrue } ]
  , txWitness  = [[]]
  , txLockTime = lt
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

forkHeight :: Word32
forkHeight = 100

runReorg :: S.HaskoinDB -> HeaderChain -> BlockHash -> BlockHash
         -> IO (Either String ())
runReorg db hc lose win = do
  cache <- newUTXOCache db 100000
  performReorg regtest cache db hc Nothing lose win

--------------------------------------------------------------------------------
-- F1: synthetic validateFullBlock
--------------------------------------------------------------------------------

-- | Minimal v2 seq=1 block at height 500.  Merkle/BIP-34/timestamp are
-- well-formed so we reach the BIP-68 / Missing-UTXO gates.
mkNonfinalProbe :: (Block, OutPoint)
mkNonfinalProbe =
  let h       = 500 :: Word32
      prevH   = fakeHash 99
      cb      = Tx
        { txVersion  = 1
        , txInputs   = [ TxIn nullOutPoint (encodeBip34Height h) 0xffffffff ]
        , txOutputs  = [ TxOut 5000000000 BS.empty ]
        , txWitness  = [[]]
        , txLockTime = 0
        }
      prevOut = OutPoint (fakeTxId 77) 0
      spend   = Tx
        { txVersion  = 2
        , txInputs   = [ TxIn prevOut BS.empty 1 ]
        , txOutputs  = [ TxOut 49000 BS.empty ]
        , txWitness  = [[]]
        , txLockTime = 0
        }
      txns    = [cb, spend]
      hdr     = BlockHeader
        { bhVersion    = 4
        , bhPrevBlock  = prevH
        , bhMerkleRoot = computeMerkleRoot (map computeTxId txns)
        , bhTimestamp  = 2000000
        , bhBits       = 0
        , bhNonce      = 0
        }
  in (Block hdr txns, prevOut)

--------------------------------------------------------------------------------
-- Fork scenarios for F2/F3/F4
--------------------------------------------------------------------------------

data Fork = Fork
  { fkHc      :: HeaderChain
  , fkLosing  :: BlockHash
  , fkWinning :: BlockHash
  , fkMature  :: OutPoint
  , fkTxA     :: Tx
  , fkTxAOut  :: OutPoint
  }

-- | Common 1..forkHeight chain, losing L @ 101, winning W1 @ 101 + W2 @ 102.
-- @w1Txns@ / @lTxns@ are the non-coinbase txs of the contested height.
setupContested
  :: [Tx] -> [Tx] -> Maybe Tx -> S.HaskoinDB -> IO Fork
setupContested lExtra w1Extra mw2Spend db = do
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

  let mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
      -- spentUtxos for the losing block: every extra tx's first vin, if
      -- it names a prefork coinbase we know about.  Tests pass the
      -- height-1 coinbase explicitly.
      lSpent  = Map.singleton mature1 (commonCoinbaseCoin 1)

  let lBlk  = mkBlock forkHash (baseTime + forkHeight + 1)
                      (coinbaseTxAt 101 0x0a : lExtra)
      lWork = forkWork + headerWork (blockHeader lBlk)
      lCe   = mkEntry lBlk 101 forkHash lWork 1001
  rL <- connectBlockAt db net lBlk 101 lSpent
  rL `shouldBe` Right ()
  insertActiveTip hc lCe

  let w1Blk  = mkBlock forkHash (baseTime + 300)
                       (coinbaseTxAt 101 0x0b : w1Extra)
      w1Work = forkWork + headerWork (blockHeader w1Blk)
      w1Ce   = mkEntry w1Blk 101 forkHash w1Work 2001
      w1Hash = ceHash w1Ce
      w2Txns = case mw2Spend of
        Just t  -> [coinbaseTxAt 102 0x0c, t]
        Nothing -> [coinbaseTxAt 102 0x0c]
      w2Blk  = mkBlock w1Hash (baseTime + 301) w2Txns
      w2Work = w1Work + headerWork (blockHeader w2Blk)
      w2Ce   = mkEntry w2Blk 102 w1Hash w2Work 2002
      w2Hash = ceHash w2Ce

  putBlock db w1Hash w1Blk
  putBlock db w2Hash w2Blk
  insertSideEntry hc w1Ce
  insertSideEntry hc w2Ce
  (w2Work > lWork) `shouldBe` True

  let txA = case w1Extra of
        (t:_) -> t
        []    -> spendTx mature1
  return Fork
    { fkHc      = hc
    , fkLosing  = ceHash lCe
    , fkWinning = w2Hash
    , fkMature  = mature1
    , fkTxA     = txA
    , fkTxAOut  = OutPoint (computeTxId txA) 0
    }

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = do
  describe "reorg connect finality" $ do

    it "F1: missing BIP-68 prevout is Missing UTXO, not bad-txns-nonfinal" $ do
      -- THE REGRESSION.  Live 966500: 23 seq=1 inputs whose coins were
      -- absent from spentUtxos after the disconnect.  Pre-fix the BIP-68
      -- gate stuffed connecting-block height in as coinHeight and
      -- rejected with bad-txns-nonfinal.  Core AccessCoin nHeight=0
      -- would let SequenceLocks pass and ConnectBlock report the miss.
      let (block, prevOut) = mkNonfinalProbe
          cs = ChainState
            { csHeight     = 499
            , csBestBlock  = fakeHash 99
            , csChainWork  = 0
            , csMedianTime = 1000000
            , csFlags      = consensusFlagsAtHeight regtest 500
            }
          -- skipScripts: we are measuring the BIP-68 / UTXO-existence
          -- gates, not script eval.  skipConnectChecks=False so BIP-68
          -- actually runs.
      case validateFullBlock regtest cs (const 1) True False block Map.empty of
        Left err -> do
          err `shouldNotBe` "bad-txns-nonfinal"
          err `shouldSatisfy` ("Missing UTXO" `isInfixOf`)
          err `shouldSatisfy` (show prevOut `isInfixOf`)
        Right () -> expectationFailure
          "empty spentUtxos must not accept a seq=1 spend"

    it "F2: IsFinalTx uses connecting height, not the fork" $ do
      -- Winning 101 carries nLockTime=100 with nSequence=0xfffffffe.
      -- Final at height 101 (100 < 101), NOT at fork height 100.
      withTestDB "locktime-height" $ \db -> do
        let mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
            txL     = spendTx mature1
            txW     = lockTimeSpendTx mature1 100
        fk  <- setupContested [txL] [txW] Nothing db
        res <- runReorg db (fkHc fk) (fkLosing fk) (fkWinning fk)
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "reorg aborted on nLockTime=connectingHeight-1: " ++ err
        getBestBlockHash db `shouldReturn` Just (fkWinning fk)

    it "F3: BIP-68 seq=1 spend of a prefork coin both branches spend" $ do
      -- Live 966500 shape: both branches spend the same prefork coin,
      -- winning side with nSequence=1 (relative height lock of 1).
      withTestDB "bip68-shared" $ \db -> do
        let mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
            txL     = spendTx mature1
            txW     = bip68SpendTx mature1
        fk  <- setupContested [txL] [txW] Nothing db
        res <- runReorg db (fkHc fk) (fkLosing fk) (fkWinning fk)
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "reorg aborted on BIP-68 seq=1 shared prefork spend: " ++ err
        getUTXO db mature1 `shouldReturn` Nothing

    it "F4: shared tx re-created by W1, spent by W2 (live c698c53f)" $ do
      -- Both L and W1 carry txA (byte-identical).  W2 spends txA:0.
      -- Disconnect of L deletes txA:0; connect of W1 must put it back
      -- so W2's lookup succeeds.  This is the 966501 Missing UTXO.
      withTestDB "recreated-next" $ \db -> do
        let mature1 = OutPoint (computeTxId (coinbaseTxAt 1 0x01)) 0
            txA     = spendTx mature1
            txAOut  = OutPoint (computeTxId txA) 0
            txC     = spendTx txAOut
        fk  <- setupContested [txA] [txA] (Just txC) db
        res <- runReorg db (fkHc fk) (fkLosing fk) (fkWinning fk)
        case res of
          Right () -> return ()
          Left err -> expectationFailure $
            "reorg aborted on shared-tx coin spent in the NEXT block: " ++ err
        getBestBlockHash db `shouldReturn` Just (fkWinning fk)
        getUTXO db txAOut `shouldReturn` Nothing
        mTxC <- getUTXO db (OutPoint (computeTxId txC) 0)
        fmap txOutScript mTxC `shouldBe` Just opTrue

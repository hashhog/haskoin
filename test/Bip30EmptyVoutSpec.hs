{-# LANGUAGE NumericUnderscores #-}

-- | cffix-haskoin-bip30-empty-vout-underflow.
--
-- 'checkBIP30' built the outpoints to look up as
-- @[0 .. fromIntegral (length (txOutputs tx) - 1)] :: [Word32]@.  For a tx
-- with no outputs @length - 1@ is @-1 :: Int@, which 'fromIntegral' turns
-- into @4294967295 :: Word32@, so the scan did 2^32 RocksDB reads (about an
-- hour, under the chain lock on the P2P and submitblock paths) before
-- 'validateTransaction' ever got to say "bad-txns-vout-empty".
--
-- BIP30 is enforced on every regtest / testnet4 block (netBIP34Hash is the
-- zero hash there), so any such block reaches the loop.
--
-- Core (validation.cpp ConnectBlock, the BIP30 loop):
--   for (size_t o = 0; o < tx->vout.size(); o++)
-- zero outputs = zero lookups.  And CheckBlock's CheckTransaction rejects
-- "bad-txns-vout-empty" (consensus/tx_check.cpp) before any UTXO work.
--
-- Every call below is wrapped in a 5 s 'timeout'.  On the base commit the
-- empty-vout cases time out (the assertion fails by name); on the fix they
-- return at once.  The controls pin that the scan still covers EXACTLY the
-- tx's outputs: a coin at the last vout is still caught (no vout dropped,
-- so no BIP30 overwrite becomes valid) and a coin one past the last vout is
-- not (no lookup beyond the last output).
module Main (main) where

import Test.Hspec
import Control.Exception (evaluate)
import Data.Word (Word8, Word32, Word64)
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import System.Directory (createDirectoryIfMissing)
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import System.IO.Temp (withTempDirectory)
import System.Timeout (timeout)

import Haskoin.Types
  ( BlockHash(..), Hash256(..), TxId(..), Block(..), BlockHeader(..)
  , Tx(..), TxIn(..), TxOut(..), OutPoint(..)
  )
import Haskoin.Crypto (computeTxId)
import Haskoin.Consensus
  ( Network(..), regtest, netGenesisBlock
  , ChainState(..)
  , checkProofOfWork, computeMerkleRoot, encodeBip34Height
  , consensusFlagsAtHeight
  , checkBIP30, validateFullBlockIO
  )
import qualified Haskoin.Storage as S
import Haskoin.Storage (Coin(..), defaultDBConfig, withDB, putUTXOCoin)
import Haskoin.Rpc (bip22ResultString)

net :: Network
net = regtest

-- | The suite's own scratch directory (not /tmp, which is RAM on maxbox).
-- Override with HASKOIN_TEST_SCRATCH; each DB is a fresh temp dir inside it,
-- removed when the case ends.
withTestDB :: (S.HaskoinDB -> IO a) -> IO a
withTestDB action = do
  root <- maybe ("dist-newstyle" </> "test-scratch" </> "bip30-empty-vout") id
            <$> lookupEnv "HASKOIN_TEST_SCRATCH"
  createDirectoryIfMissing True root
  withTempDirectory root "db-" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) action

-- | 5 s: the fixed scan does at most a handful of reads; the 2^32 scan on
-- the base commit cannot finish in it.
limitUs :: Int
limitUs = 5_000_000

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

nullOutPoint :: OutPoint
nullOutPoint = OutPoint (TxId (Hash256 (BS.replicate 32 0x00))) 0xffffffff

subsidy :: Word64
subsidy = 5000000000

-- | Coinbase valid for regtest height @h@: BIP34 height push, value equal
-- to the subsidy (no fees are claimed).
coinbaseTx :: Word32 -> Tx
coinbaseTx h = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn nullOutPoint (encodeBip34Height h `BS.snoc` 0x00) 0xffffffff ]
  , txOutputs  = [ TxOut subsidy opTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | A non-coinbase tx with one input and @n@ outputs.  The scriptSig pads
-- the base size past 64 bytes so the 64-byte-tx mutation rule never fires.
spendTx :: Word8 -> Int -> Tx
spendTx tag n = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 tag))) 0)
                        (BS.replicate 24 0x51) 0xffffffff ]
  , txOutputs  = replicate n (TxOut 1000 opTrue)
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Block over @txns@ on @prev@ with a correct merkle root and regtest PoW,
-- so 'mutationFirst' and the header checks pass and the per-tx checks are
-- what decide.
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

genesisTime :: Word32
genesisTime = bhTimestamp (blockHeader (netGenesisBlock net))

-- | Parent at height 1 (only its hash is used; nothing is connected).
parentHash :: BlockHash
parentHash = BlockHash (Hash256 (BS.replicate 32 0x11))

-- | Height-2 block whose second tx is @tx@.
blockWith :: Tx -> Block
blockWith tx = mkBlock parentHash (genesisTime + 1200) [coinbaseTx 2, tx]

-- | Tip at height 1, so the block under test is height 2.
tipState :: ChainState
tipState = ChainState
  { csHeight     = 1
  , csBestBlock  = parentHash
  , csChainWork  = 0
  , csMedianTime = genesisTime
  , csFlags      = consensusFlagsAtHeight net 2
  }

-- | A pre-existing unspent coin at (txid tx, vout).
seedCoin :: S.HaskoinDB -> Tx -> Word32 -> IO ()
seedCoin db tx vout =
  putUTXOCoin db (OutPoint (computeTxId tx) vout)
    (Coin (TxOut 1000 opTrue) 1 False)

bip30Within :: S.HaskoinDB -> Block -> IO (Maybe (Either String ()))
bip30Within db blk = timeout limitUs (checkBIP30 db net 2 blk >>= evaluate)

fullWithin :: S.HaskoinDB -> Block -> IO (Maybe (Either String ()))
fullWithin db blk =
  timeout limitUs (validateFullBlockIO db net tipState (const genesisTime) False blk Map.empty >>= evaluate)

isBip30Reject :: Either String () -> Bool
isBip30Reject (Left e) = bip22ResultString e == "bad-txns-BIP30"
isBip30Reject _        = False

main :: IO ()
main = hspec $ do
  describe "checkBIP30 on a tx with zero outputs (regtest h=2, BIP30 enforced)" $ do
    it "returns Right () within 5 s instead of scanning 2^32 outpoints" $
      withTestDB $ \db -> do
        r <- bip30Within db (blockWith (spendTx 0x22 0))
        r `shouldBe` Just (Right ())

    it "validateFullBlockIO rejects the block as bad-txns-vout-empty within 5 s" $
      withTestDB $ \db -> do
        r <- fullWithin db (blockWith (spendTx 0x22 0))
        fmap (either bip22ResultString (const "accepted")) r
          `shouldBe` Just "bad-txns-vout-empty"

  describe "checkBIP30 controls: the scan covers exactly the tx's outputs" $ do
    it "1 output, coin at vout 0: refused bad-txns-BIP30" $
      withTestDB $ \db -> do
        let tx = spendTx 0x33 1
        seedCoin db tx 0
        r <- bip30Within db (blockWith tx)
        fmap isBip30Reject r `shouldBe` Just True

    it "1 output, coin at vout 1 (past the last output): not looked up, Right ()" $
      withTestDB $ \db -> do
        let tx = spendTx 0x33 1
        seedCoin db tx 1
        r <- bip30Within db (blockWith tx)
        r `shouldBe` Just (Right ())

    it "3 outputs, coin at vout 2 (the last output): refused bad-txns-BIP30" $
      withTestDB $ \db -> do
        let tx = spendTx 0x44 3
        seedCoin db tx 2
        r <- bip30Within db (blockWith tx)
        fmap isBip30Reject r `shouldBe` Just True

    it "3 outputs, coin at vout 3 (past the last output): not looked up, Right ()" $
      withTestDB $ \db -> do
        let tx = spendTx 0x44 3
        seedCoin db tx 3
        r <- bip30Within db (blockWith tx)
        r `shouldBe` Just (Right ())

    it "3 outputs, no pre-existing coin: Right ()" $
      withTestDB $ \db -> do
        r <- bip30Within db (blockWith (spendTx 0x44 3))
        r `shouldBe` Just (Right ())

    it "duplicate coinbase (coin at the coinbase's vout 0): refused bad-txns-BIP30" $
      withTestDB $ \db -> do
        seedCoin db (coinbaseTx 2) 0
        r <- bip30Within db (blockWith (spendTx 0x44 3))
        fmap isBip30Reject r `shouldBe` Just True

    it "validateFullBlockIO: a BIP30 duplicate whose tx has outputs is still refused bad-txns-BIP30" $
      withTestDB $ \db -> do
        let tx = spendTx 0x55 3
        seedCoin db tx 1
        r <- fullWithin db (blockWith tx)
        fmap (either bip22ResultString (const "accepted")) r
          `shouldBe` Just "bad-txns-BIP30"

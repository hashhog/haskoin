{-# LANGUAGE OverloadedStrings #-}

-- | An UNSPENDABLE output created in a block is never a coin — not even for a
-- later transaction of the SAME block.
--
-- == Core ==
--
-- @CCoinsViewCache::AddCoin@ (coins.cpp:84-91) returns early when
-- @coin.out.scriptPubKey.IsUnspendable()@ (script.h: first byte OP_RETURN, or
-- size > MAX_SCRIPT_SIZE = 10000), so @UpdateCoins@ never puts such an output
-- into the view.  ConnectBlock's serial loop (validation.cpp ~2526-2600) runs
-- @Consensus::CheckTxInputs@ against that view, so a later tx of the same
-- block that spends the output fails @HaveInputs@:
-- @bad-txns-inputs-missingorspent@.  This holds with AND without assumevalid
-- (the input check is not a script check).
--
-- == haskoin (4242ba1) ==
--
-- The intra-block maps in 'validateFullBlock' — 'validateBlockTransactions'
-- (Consensus.hs:4367), 'getBlockSigOpCost' (:3130) and the BIP-68 height map
-- (:3481, :3517) — added EVERY output of each tx, unspendable or not.  The
-- DB write path already filtered (connectBlock :5144), so the UTXO set was
-- right; only the in-block view was wrong.  Consequences:
--
--   * assumevalid ('skipScripts' = True, the IBD path below the AV block):
--     the spend was ACCEPTED (no script runs to fail it) — a consensus split;
--   * scripts on: rejected, but as a SCRIPT failure, not missing-inputs;
--   * a BIP-68-locked spend of such an output: rejected bad-txns-nonfinal
--     (intra-block height) where Core says missing-inputs.
module UnspendableIntraBlockSpendSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.List (isPrefixOf)
import Data.Word (Word32)

import Haskoin.Consensus
  ( validateFullBlock
  , ChainState(..)
  , regtest
  , consensusFlagsAtHeight
  , computeMerkleRoot
  , encodeBip34Height
  )
import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..)
  , BlockHash(..), BlockHeader(..), Block(..) )
import Haskoin.Storage ( Coin(..) )
import Haskoin.Crypto ( computeTxId )

opTrue :: BS.ByteString
opTrue = BS.pack [0x51]

-- | OP_RETURN <1 byte>.
opReturn :: BS.ByteString
opReturn = BS.pack [0x6a, 0x01, 0x00]

-- | 10,001 bytes of OP_TRUE: not OP_RETURN-prefixed, unspendable by size.
oversized :: BS.ByteString
oversized = BS.replicate 10001 0x51

nullOutpoint :: OutPoint
nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff

blockH :: Word32
blockH = 120   -- regtest subsidy still 50 BTC (halving at 150); CSV active

coinbaseAt :: Word32 -> Tx
coinbaseAt h = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn nullOutpoint (encodeBip34Height h `BS.snoc` 0x00) 0xffffffff ]
  , txOutputs  = [ TxOut 1000 opTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

fundingOut :: OutPoint
fundingOut = OutPoint (TxId (Hash256 (BS.replicate 32 0x77))) 0

-- | txA spends the pre-block coin; output 0 has @scriptA@.
txA :: BS.ByteString -> Tx
txA scriptA = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn fundingOut BS.empty 0xffffffff ]
  , txOutputs  = [ TxOut 90000 scriptA ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | txB spends txA:0 with @nSeq@.
txB :: Tx -> Word32 -> Tx
txB a nSeq = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn (OutPoint (computeTxId a) 0) BS.empty nSeq ]
  , txOutputs  = [ TxOut 80000 opTrue ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

-- | Validate [coinbase, txA(scriptA), txB] at 'blockH'.
run :: Bool -> BS.ByteString -> Word32 -> Either String ()
run skipScripts scriptA nSeq =
  let a     = txA scriptA
      txns  = [coinbaseAt blockH, a, txB a nSeq]
      hdr   = BlockHeader 4 (BlockHash (Hash256 (BS.replicate 32 0x99)))
                          (computeMerkleRoot (map computeTxId txns)) 2000000 0 0
      cs    = ChainState { csHeight = blockH - 1
                         , csBestBlock = BlockHash (Hash256 (BS.replicate 32 0x99))
                         , csChainWork = 0
                         , csMedianTime = 1000000
                         , csFlags = consensusFlagsAtHeight regtest blockH }
      utxo  = Map.singleton fundingOut (Coin (TxOut 100000 opTrue) 10 False)
  in validateFullBlock regtest cs (const 1000000) skipScripts False (Block hdr txns) utxo

-- | Core: CheckTxInputs -> bad-txns-inputs-missingorspent.  haskoin's
-- missing-input verdict is "Missing UTXO: ..." (bip22ResultString maps it to
-- bad-txns-inputs-missingorspent).
shouldBeMissingInput :: Either String () -> Expectation
shouldBeMissingInput r = case r of
  Left e | "Missing UTXO" `isPrefixOf` e -> pure ()
  Left e  -> expectationFailure ("expected Missing UTXO (Core bad-txns-inputs-missingorspent), got: " ++ e)
  Right () -> expectationFailure "ACCEPTED a block spending an unspendable output (Core: bad-txns-inputs-missingorspent)"

spec :: Spec
spec = describe "Unspendable outputs never enter the intra-block view (Core AddCoin IsUnspendable)" $ do
  it "C1 control: intra-block spend of an OP_TRUE output connects (assumevalid)" $
    run True opTrue 0xffffffff `shouldBe` Right ()
  it "C2 control: intra-block spend of an OP_TRUE output connects (scripts on)" $
    run False opTrue 0xffffffff `shouldBe` Right ()
  it "U1: spend of a same-block OP_RETURN output under assumevalid -> missing inputs" $
    shouldBeMissingInput (run True opReturn 0xffffffff)
  it "U2: spend of a same-block OP_RETURN output, scripts on -> missing inputs (not a script error)" $
    shouldBeMissingInput (run False opReturn 0xffffffff)
  it "U3: spend of a same-block >10000-byte output under assumevalid -> missing inputs" $
    shouldBeMissingInput (run True oversized 0xffffffff)
  it "U4: BIP-68-locked (nSequence=1) spend of a same-block OP_RETURN output -> missing inputs, not nonfinal" $
    shouldBeMissingInput (run True opReturn 1)

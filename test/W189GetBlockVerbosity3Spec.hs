{-# LANGUAGE OverloadedStrings #-}

-- | W189 getblock verbosity=2 / verbosity=3 JSON shape (Core parity).
--
-- Reference: bitcoin-core/src/rpc/blockchain.cpp getblock + blockToJSON,
--            bitcoin-core/src/core_io.cpp TxToUniv.
--   * verbosity=2 (TxVerbosity::SHOW_DETAILS): each tx is a full decoded tx
--     object (txid,hash,version,size,vsize,weight,locktime,vin,vout,[fee],hex).
--   * verbosity=3 (TxVerbosity::SHOW_DETAILS_AND_PREVOUT): same as v2 PLUS,
--     for each non-coinbase input, a "prevout" object
--     {generated, height, value, scriptPubKey{asm,desc,hex,[address],type}}
--     inserted between txinwitness and sequence (core_io.cpp TxToUniv).
--
-- Before this fix the local-block getblock path handled only verbosity==2
-- (`case verbosity of 2 -> ...; _ -> Nothing`), so verbosity=3 silently fell
-- back to the bare txid list (verbosity=1 shape) and never emitted prevout.
-- These tests pin the pure tx[] encoders that back both levels.
module W189GetBlockVerbosity3Spec (spec) where

import Test.Hspec

import Haskoin.Types
import Haskoin.Consensus (regtest)
import Haskoin.Storage (TxUndo(..), TxInUndo(..))
import Haskoin.Rpc (buildBlockTxArrayEnc, buildBlockTxArrayEncV3)

import Data.Aeson (Value(..), decode)
import qualified Data.Aeson.KeyMap as KM
import qualified Data.Aeson.Key as AKey
import qualified Data.Vector as Vec
import Data.Aeson.Encoding (encodingToLazyByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Maybe (isJust)

-- ---------------------------------------------------------------------------
-- Fixtures
-- ---------------------------------------------------------------------------

zeroHash :: Hash256
zeroHash = Hash256 (BS.replicate 32 0)

-- A canonical P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
p2pkhScript :: BS.ByteString
p2pkhScript = BS.pack ([0x76, 0xa9, 0x14] ++ replicate 20 0xab ++ [0x88, 0xac])

-- Coinbase input: prevout hash all-zero, index 0xffffffff (Core's null prevout).
coinbaseTx :: Tx
coinbaseTx = Tx
  { txVersion  = 1
  , txInputs   = [ TxIn (OutPoint (TxId zeroHash) 0xffffffff) (BS.pack [0x03, 1, 2, 3]) 0xffffffff ]
  , txOutputs  = [ TxOut 5000000000 p2pkhScript ]
  , txWitness  = [ [BS.replicate 32 0] ]   -- coinbase witness reserved value
  , txLockTime = 0
  }

-- A normal spending tx: 1 input (value 1 BTC) -> 1 output (0.9 BTC), fee 0.1 BTC.
spendingTx :: Tx
spendingTx = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0x11))) 0) (BS.pack [0x47]) 0xfffffffe ]
  , txOutputs  = [ TxOut 90000000 p2pkhScript ]
  , txWitness  = [ [] ]
  , txLockTime = 0
  }

-- Undo for the spending tx: one spent output, value 1 BTC, height 42, not coinbase.
spendingUndo :: TxUndo
spendingUndo = TxUndo { tuPrevOutputs = [ TxInUndo (TxOut 100000000 p2pkhScript) 42 False ] }

testBlock :: Block
testBlock = Block
  (BlockHeader 0x20000000 (BlockHash zeroHash) zeroHash 1234567890 0x207fffff 0)
  [coinbaseTx, spendingTx]

-- ---------------------------------------------------------------------------
-- JSON navigation helpers
-- ---------------------------------------------------------------------------

field :: Text -> Value -> Maybe Value
field k (Object o) = KM.lookup (AKey.fromText k) o
field _ _          = Nothing

idx :: Int -> Value -> Maybe Value
idx i (Array v) = v Vec.!? i
idx _ _         = Nothing

v2, v3 :: Maybe Value
v2 = decode (encodingToLazyByteString (buildBlockTxArrayEnc   regtest testBlock [spendingUndo]))
v3 = decode (encodingToLazyByteString (buildBlockTxArrayEncV3 regtest testBlock [spendingUndo]))

-- ---------------------------------------------------------------------------
-- Spec
-- ---------------------------------------------------------------------------

spec :: Spec
spec = describe "W189 getblock verbosity=2/3 tx[] JSON shape (Core parity)" $ do

  it "both encoders emit a 2-element tx array" $ do
    (v2 >>= \x -> case x of Array a -> Just (Vec.length a); _ -> Nothing) `shouldBe` Just 2
    (v3 >>= \x -> case x of Array a -> Just (Vec.length a); _ -> Nothing) `shouldBe` Just 2

  it "each tx is a full decoded object (txid/version/vin/vout/hex), not a bare txid" $ do
    let tx1 = v3 >>= idx 1
    (isJust (tx1 >>= field "txid"))    `shouldBe` True
    (isJust (tx1 >>= field "version")) `shouldBe` True
    (isJust (tx1 >>= field "vin"))     `shouldBe` True
    (isJust (tx1 >>= field "vout"))    `shouldBe` True
    (isJust (tx1 >>= field "hex"))     `shouldBe` True

  it "verbosity=2: non-coinbase tx carries fee but NO prevout" $ do
    let vin0 = v2 >>= idx 1 >>= field "vin" >>= idx 0
    (v2 >>= idx 1 >>= field "fee")  `shouldBe` Just (Number 0.1)   -- 0.1 BTC
    (vin0 >>= field "prevout")      `shouldBe` Nothing

  it "verbosity=3: non-coinbase input gains a prevout object" $ do
    let prevout = v3 >>= idx 1 >>= field "vin" >>= idx 0 >>= field "prevout"
    (prevout >>= field "generated") `shouldBe` Just (Bool False)
    (prevout >>= field "height")    `shouldBe` Just (Number 42)
    (prevout >>= field "value")     `shouldBe` Just (Number 1.0)   -- 1 BTC
    (isJust (prevout >>= field "scriptPubKey")) `shouldBe` True

  it "verbosity=3: prevout.scriptPubKey has Core's asm/desc/hex/type fields" $ do
    let spk = v3 >>= idx 1 >>= field "vin" >>= idx 0 >>= field "prevout" >>= field "scriptPubKey"
    (isJust (spk >>= field "asm"))  `shouldBe` True
    (isJust (spk >>= field "desc")) `shouldBe` True
    (isJust (spk >>= field "hex"))  `shouldBe` True
    (spk >>= field "type")          `shouldBe` Just (String "pubkeyhash")

  it "verbosity=3: fee is still present alongside prevout" $
    (v3 >>= idx 1 >>= field "fee") `shouldBe` Just (Number 0.1)

  it "verbosity=3: coinbase tx has a coinbase input and NO prevout/fee" $ do
    let cbVin0 = v3 >>= idx 0 >>= field "vin" >>= idx 0
    (isJust (cbVin0 >>= field "coinbase")) `shouldBe` True
    (cbVin0 >>= field "prevout")           `shouldBe` Nothing
    (v3 >>= idx 0 >>= field "fee")          `shouldBe` Nothing

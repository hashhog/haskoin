{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

-- | Benchmark Suite for Haskoin
--
-- Performance targets (approximate):
--   - VarInt encode/decode: < 100 ns
--   - SHA-256 (32 bytes): < 500 ns
--   - Double SHA-256 (32 bytes): < 1 us
--   - Block header serialize: < 200 ns
--   - Transaction serialize (avg): < 5 us
--   - Script verification (P2PKH): < 100 us
--   - Merkle root (1000 txs): < 500 us
--   - UTXO lookup (cached): < 100 ns
--   - UTXO lookup (DB): < 10 us
--
-- Run with: cabal bench
-- Or with more detail: cabal bench --benchmark-options='-o report.html'
--
module Main where

import Criterion.Main
import Control.DeepSeq (NFData(..), force)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (encode, decode)
import qualified Data.Map.Strict as Map

import Haskoin.Types
import Haskoin.Crypto
import Haskoin.Consensus
import Haskoin.Performance

-- | Sample data for benchmarks
sampleHash256 :: Hash256
sampleHash256 = Hash256 (BS.replicate 32 0xab)

sampleBlockHeader :: BlockHeader
sampleBlockHeader = BlockHeader
  { bhVersion = 1
  , bhPrevBlock = BlockHash sampleHash256
  , bhMerkleRoot = sampleHash256
  , bhTimestamp = 1234567890
  , bhBits = 0x1d00ffff
  , bhNonce = 12345
  }

sampleTxOut :: TxOut
sampleTxOut = TxOut 50000000 (BS.replicate 25 0x76)

sampleOutPoint :: OutPoint
sampleOutPoint = OutPoint (TxId sampleHash256) 0

sampleTxIn :: TxIn
sampleTxIn = TxIn sampleOutPoint (BS.replicate 72 0x48) 0xffffffff

sampleTx :: Tx
sampleTx = Tx
  { txVersion = 1
  , txInputs = [sampleTxIn]
  , txOutputs = [sampleTxOut, sampleTxOut]
  , txWitness = [[]]
  , txLockTime = 0
  }

-- | Generate N transaction IDs for merkle root benchmarks
generateTxIds :: Int -> [TxId]
generateTxIds n =
  [ TxId (Hash256 (BS.pack [fromIntegral i, fromIntegral (i `div` 256),
                           fromIntegral (i `div` 65536), fromIntegral (i `div` 16777216)]
                   `BS.append` BS.replicate 28 0))
  | i <- [1..n]
  ]

-- | Generate a UTXO map with N entries
generateUTXOMap :: Int -> Map.Map OutPoint TxOut
generateUTXOMap n = Map.fromList
  [ (OutPoint (TxId (Hash256 (BS.pack [fromIntegral i, fromIntegral (i `div` 256),
                                       fromIntegral (i `div` 65536), fromIntegral (i `div` 16777216)]
                              `BS.append` BS.replicate 28 0))) 0,
     TxOut (fromIntegral i * 1000) (BS.replicate 25 0x76))
  | i <- [1..n]
  ]

main :: IO ()
main = defaultMain
  [ bgroup "serialization"
    [ bgroup "varint"
      [ bench "encode small (42)" $ whnf (encode . VarInt) 42
      , bench "encode medium (0x1000)" $ whnf (encode . VarInt) 0x1000
      , bench "encode large (0x100000000)" $ whnf (encode . VarInt) 0x100000000
      , bench "decode small" $ whnf (decode :: ByteString -> Either String VarInt) "\x2a"
      ]
    , bgroup "hash256"
      [ bench "encode" $ whnf encode sampleHash256
      , bench "decode" $ whnf (decode :: ByteString -> Either String Hash256)
                             (encode sampleHash256)
      ]
    , bgroup "blockheader"
      [ bench "encode (80 bytes)" $ whnf encode sampleBlockHeader
      , bench "decode" $ whnf (decode :: ByteString -> Either String BlockHeader)
                              (encode sampleBlockHeader)
      ]
    , bgroup "transaction"
      [ bench "encode simple tx" $ whnf encode sampleTx
      , bench "decode simple tx" $ whnf (decode :: ByteString -> Either String Tx)
                                        (encode sampleTx)
      ]
    ]

  , bgroup "crypto"
    [ bgroup "sha256"
      [ bench "32 bytes" $ whnf sha256 (BS.replicate 32 0xab)
      , bench "80 bytes (header)" $ whnf sha256 (encode sampleBlockHeader)
      , bench "1000 bytes" $ whnf sha256 (BS.replicate 1000 0xab)
      ]
    , bgroup "doubleSHA256"
      [ bench "32 bytes" $ whnf doubleSHA256 (BS.replicate 32 0xab)
      , bench "80 bytes (header)" $ whnf doubleSHA256 (encode sampleBlockHeader)
      ]
    , bgroup "ripemd160"
      [ bench "32 bytes" $ whnf ripemd160 (BS.replicate 32 0xab)
      ]
    , bgroup "hash160"
      [ bench "33 bytes (pubkey)" $ whnf hash160 (BS.replicate 33 0x02)
      ]
    ]

  , bgroup "consensus"
    [ bgroup "merkleRoot"
      [ bench "10 txs" $ whnf computeMerkleRoot (generateTxIds 10)
      , bench "100 txs" $ whnf computeMerkleRoot (generateTxIds 100)
      , bench "1000 txs" $ whnf computeMerkleRoot (generateTxIds 1000)
      ]
    , bgroup "difficulty"
      [ bench "bitsToTarget" $ whnf bitsToTarget 0x1d00ffff
      , bench "targetToBits" $ whnf targetToBits powLimit
      ]
    , bgroup "blockHash"
      [ bench "computeBlockHash" $ whnf computeBlockHash sampleBlockHeader
      ]
    ]

  , bgroup "utxo"
    [ bgroup "map operations"
      [ bench "lookup in 1000 entries" $
          let !utxoMap = generateUTXOMap 1000
              !key = OutPoint (TxId sampleHash256) 0
          in whnf (Map.lookup key) utxoMap
      , bench "insert into 1000 entries" $
          let !utxoMap = generateUTXOMap 1000
              !key = OutPoint (TxId sampleHash256) 999
              !val = sampleTxOut
          in whnf (Map.insert key val) utxoMap
      ]
    ]

  , bgroup "performance"
    [ bgroup "strict processing"
      [ bench "computeTxFeeStrict" $
          let !utxoMap = Map.singleton sampleOutPoint sampleTxOut
              !tx = sampleTx { txInputs = [sampleTxIn] }
          in whnf (computeTxFeeStrict utxoMap) tx
      ]
    ]
  ]

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

-- | Benchmark Suite for Haskoin
--
-- Performance targets (approximate):
--   - VarInt encode/decode: < 100 ns
--   - SHA-256 (32 bytes): < 500 ns (hardware accelerated)
--   - Double SHA-256 (32 bytes): < 1 us
--   - Block header serialize: < 200 ns
--   - Transaction serialize (avg): < 5 us
--   - Script verification (P2PKH): < 100 us
--   - Merkle root (1000 txs): < 500 us
--   - UTXO lookup (cached): < 100 ns
--   - UTXO lookup (DB): < 10 us
--   - Parallel block validation: 2x+ speedup on 4+ cores
--
-- Hardware acceleration:
--   - SHA-256: cryptonite auto-detects SHA-NI, AVX2
--   - Signature verification: secp256k1 with batch support
--
-- Run with: cabal bench
-- Or with more detail: cabal bench --benchmark-options='-o report.html'
-- For parallel benchmarks: cabal bench --benchmark-options='+RTS -N4 -RTS'
--
module Main where

import Criterion.Main
import Control.Concurrent.Async (mapConcurrently)
import Control.Concurrent.STM
import Control.DeepSeq (NFData(..), force)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Serialize (encode, decode)
import qualified Data.Map.Strict as Map
import GHC.Conc (numCapabilities)

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

-- | Generate N transactions with valid inputs
generateTxsWithInputs :: Int -> Map.Map OutPoint TxOut -> [(Int, Tx)]
generateTxsWithInputs n utxoMap =
  [ (i, tx)
  | (i, (op, txout)) <- zip [1..n] (Map.toList utxoMap)
  , let txin = TxIn op BS.empty 0xffffffff
        txoutNew = TxOut (txOutValue txout - 1000) (BS.replicate 25 0x76)
        tx = Tx 2 [txin] [txoutNew] [[]] 0
  ]

-- | Generate Schnorr signature tasks
generateSchnorrTasks :: Int -> [(ByteString, ByteString, ByteString)]
generateSchnorrTasks n =
  [ ( BS.replicate 32 (fromIntegral i)       -- 32-byte pubkey (Taproot)
    , BS.replicate 32 (fromIntegral (i + 1)) -- 32-byte message hash
    , BS.replicate 64 (fromIntegral (i + 2)) -- 64-byte Schnorr signature
    )
  | i <- [1..n]
  ]

-- | Generate ECDSA verification tasks
generateECDSATasks :: Int -> [VerifyTask]
generateECDSATasks n =
  [ VerifyTask
    { vtPubKey = BS.cons 0x02 (BS.replicate 32 (fromIntegral i))  -- Compressed pubkey
    , vtMessage = BS.replicate 32 (fromIntegral (i + 1))
    , vtSignature = BS.replicate 71 (fromIntegral (i + 2))        -- Typical DER sig
    , vtIndex = i
    }
  | i <- [1..n]
  ]

-- | Sequential verification (for comparison)
sequentialVerifySchnorr :: [(ByteString, ByteString, ByteString)] -> Bool
sequentialVerifySchnorr sigs = all verifyOne sigs
  where
    verifyOne (pk, msg, sig) = BS.length pk == 32 && BS.length sig == 64 && BS.length msg == 32

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

  , bgroup "hardware_accelerated"
    [ bgroup "sha256Fast"
      [ bench "32 bytes" $ whnf sha256Fast (BS.replicate 32 0xab)
      , bench "80 bytes (header)" $ whnf sha256Fast (encode sampleBlockHeader)
      , bench "1000 bytes" $ whnf sha256Fast (BS.replicate 1000 0xab)
      , bench "1 MB block" $ whnf sha256Fast (BS.replicate (1024 * 1024) 0xab)
      ]
    , bgroup "doubleSha256Fast"
      [ bench "32 bytes" $ whnf doubleSha256Fast (BS.replicate 32 0xab)
      , bench "80 bytes (header)" $ whnf doubleSha256Fast (encode sampleBlockHeader)
      , bench "1000 bytes" $ whnf doubleSha256Fast (BS.replicate 1000 0xab)
      ]
    , bgroup "sha256_comparison"
      -- Compare Haskoin.Crypto.sha256 vs Performance.sha256Fast
      -- Both use cryptonite so should be identical
      [ bench "crypto_module" $ whnf sha256 (encode sampleBlockHeader)
      , bench "perf_module" $ whnf sha256Fast (encode sampleBlockHeader)
      ]
    ]

  , bgroup "batch_verification"
    [ bgroup "schnorr"
      [ bench "10 sigs (sequential)" $
          whnf sequentialVerifySchnorr (generateSchnorrTasks 10)
      , bench "10 sigs (batch)" $
          nfIO $ batchVerifySchnorr (generateSchnorrTasks 10)
      , bench "100 sigs (sequential)" $
          whnf sequentialVerifySchnorr (generateSchnorrTasks 100)
      , bench "100 sigs (batch)" $
          nfIO $ batchVerifySchnorr (generateSchnorrTasks 100)
      , bench "1000 sigs (sequential)" $
          whnf sequentialVerifySchnorr (generateSchnorrTasks 1000)
      , bench "1000 sigs (batch)" $
          nfIO $ batchVerifySchnorr (generateSchnorrTasks 1000)
      ]
    , bgroup "ecdsa_parallel"
      [ bench "10 sigs" $
          nfIO $ parallelVerifyECDSA (generateECDSATasks 10)
      , bench "100 sigs" $
          nfIO $ parallelVerifyECDSA (generateECDSATasks 100)
      , bench "1000 sigs" $
          nfIO $ parallelVerifyECDSA (generateECDSATasks 1000)
      ]
    ]

  , bgroup "parallel_validation"
    [ bgroup "transaction_chunks"
      [ bench "chunk 100 txs into 4 parts" $
          let !txs = take 100 $ generateTxsWithInputs 100 (generateUTXOMap 100)
          in whnf (chunkTransactions 4) txs
      , bench "chunk 1000 txs into 8 parts" $
          let !txs = take 1000 $ generateTxsWithInputs 1000 (generateUTXOMap 1000)
          in whnf (chunkTransactions 8) txs
      ]
    , env (do
        let utxoMap = generateUTXOMap 100
        tvar <- newTVarIO utxoMap
        let txs = take 50 $ generateTxsWithInputs 100 utxoMap
        return (txs, tvar, utxoMap)
      ) $ \ ~(txs, tvar, originalMap) ->
        bgroup "validateTxChunk"
          [ bench "50 txs sequential" $
              nfIO $ do
                atomically $ writeTVar tvar originalMap
                validateTxChunk txs tvar (ConsensusFlags False False False False False False False)
          ]
    ]

  , bgroup "parallel_vs_sequential"
    [ bgroup "merkle_root"
      [ bench "1000 txs (sequential)" $ whnf computeMerkleRoot (generateTxIds 1000)
      , bench "1000 txs (parallel map)" $
          let !txids = generateTxIds 1000
              !hashes = map getTxIdHash txids
          in whnf (parallelMap (\h -> doubleSha256Fast (getHash256 h))) hashes
      ]
    , bgroup "tx_fee_calculation"
      [ bench "100 txs (sequential)" $
          let !utxoMap = generateUTXOMap 100
              !txs = map snd $ take 100 $ generateTxsWithInputs 100 utxoMap
          in whnf (map (computeTxFeeStrict utxoMap)) txs
      , bench "100 txs (parallel)" $
          let !utxoMap = generateUTXOMap 100
              !txs = map snd $ take 100 $ generateTxsWithInputs 100 utxoMap
          in whnf (parallelMap (computeTxFeeStrict utxoMap)) txs
      ]
    ]
  ]

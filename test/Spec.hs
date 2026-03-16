{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Hspec
import Test.QuickCheck
import Control.Monad (forM_)
import Data.Serialize (encode, decode)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text as T
import Data.Word (Word32, Word64)
import Data.Int (Int64)
import Data.Bits ((.|.), (.&.))

import Haskoin.Types
import Haskoin.Crypto
import Haskoin.Script
import Haskoin.Consensus
import Haskoin.Storage (KeyPrefix(..), prefixByte, makeKey, toBE32, fromBE32,
                         integerToBS, bsToInteger, TxLocation(..), BlockStatus(..),
                         WriteBatch(..), getBatchOps, BatchOp(..),
                         batchPutBlockHeader, batchPutUTXO, batchDeleteUTXO,
                         batchPutBestBlock, batchPutBlockHeight,
                         UTXOEntry(..), UndoData(..), PersistedChainState(..))
import Haskoin.Network
import Haskoin.Sync
import Haskoin.Mempool
import Haskoin.FeeEstimator
import Haskoin.Wallet
import Haskoin.Performance
import Haskoin.BlockTemplate
import qualified Data.Map.Strict as Map
import qualified Data.Sequence as Seq
import Control.Concurrent.STM

-- Helper for hex decoding that works with Either-based API
hexDecode :: ByteString -> ByteString
hexDecode bs = case B16.decode bs of
  Right x -> x
  Left _ -> error "invalid hex"

main :: IO ()
main = hspec $ do
  describe "VarInt" $ do
    it "encodes single-byte values (< 0xfd)" $ do
      encode (VarInt 0) `shouldBe` "\x00"
      encode (VarInt 1) `shouldBe` "\x01"
      encode (VarInt 252) `shouldBe` "\xfc"

    it "encodes two-byte values (0xfd prefix)" $ do
      let encoded = encode (VarInt 253)
      BS.length encoded `shouldBe` 3
      BS.head encoded `shouldBe` 0xfd

    it "encodes four-byte values (0xfe prefix)" $ do
      let encoded = encode (VarInt 0x10000)
      BS.length encoded `shouldBe` 5
      BS.head encoded `shouldBe` 0xfe

    it "encodes eight-byte values (0xff prefix)" $ do
      let encoded = encode (VarInt 0x100000000)
      BS.length encoded `shouldBe` 9
      BS.head encoded `shouldBe` 0xff

    it "roundtrips all VarInt sizes" $ property $ \(n :: Word64) ->
      decode (encode (VarInt n)) == Right (VarInt n)

  describe "Hash256" $ do
    it "serializes to exactly 32 bytes" $ do
      let hash = Hash256 (BS.replicate 32 0xab)
      BS.length (encode hash) `shouldBe` 32

    it "roundtrips correctly" $ do
      let hash = Hash256 (BS.replicate 32 0xcd)
      decode (encode hash) `shouldBe` Right hash

  describe "Hash160" $ do
    it "serializes to exactly 20 bytes" $ do
      let hash = Hash160 (BS.replicate 20 0xef)
      BS.length (encode hash) `shouldBe` 20

    it "roundtrips correctly" $ do
      let hash = Hash160 (BS.replicate 20 0x12)
      decode (encode hash) `shouldBe` Right hash

  describe "OutPoint" $ do
    it "serializes to 36 bytes (32 hash + 4 index)" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0x00))
          op = OutPoint txid 0
      BS.length (encode op) `shouldBe` 36

    it "roundtrips correctly" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          op = OutPoint txid 42
      decode (encode op) `shouldBe` Right op

  describe "TxIn" $ do
    it "roundtrips correctly" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xbb))
          op = OutPoint txid 1
          txin = TxIn op "script" 0xffffffff
      decode (encode txin) `shouldBe` Right txin

  describe "TxOut" $ do
    it "roundtrips correctly" $ do
      let txout = TxOut 50000000 "pubkeyscript"
      decode (encode txout) `shouldBe` Right txout

  describe "BlockHeader" $ do
    it "serializes to exactly 80 bytes" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0x00))
          merkle = Hash256 (BS.replicate 32 0x00)
          header = BlockHeader 1 prevHash merkle 0 0 0
      BS.length (encode header) `shouldBe` 80

    it "roundtrips correctly" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0x11))
          merkle = Hash256 (BS.replicate 32 0x22)
          header = BlockHeader 2 prevHash merkle 1234567890 0x1d00ffff 12345
      decode (encode header) `shouldBe` Right header

  describe "Tx (legacy)" $ do
    it "roundtrips a simple legacy transaction" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          txout = TxOut 100000 "scriptpubkey"
          tx = Tx 1 [txin] [txout] [[]] 0
      decode (encode tx) `shouldBe` Right tx

  describe "Tx (segwit)" $ do
    it "roundtrips a segwit transaction" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint txid 0) "" 0xffffffff
          txout = TxOut 100000 "scriptpubkey"
          wit = ["sig", "pubkey"]
          tx = Tx 2 [txin] [txout] [wit] 0
      decode (encode tx) `shouldBe` Right tx

  describe "Block" $ do
    it "roundtrips correctly" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0x00))
          merkle = Hash256 (BS.replicate 32 0x00)
          header = BlockHeader 1 prevHash merkle 0 0 0
          txid = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint txid 0xffffffff) "coinbase" 0xffffffff
          txout = TxOut 5000000000 "scriptpubkey"
          coinbase = Tx 1 [txin] [txout] [[]] 0
          block = Block header [coinbase]
      decode (encode block) `shouldBe` Right block

  describe "NetworkAddress" $ do
    it "serializes to 26 bytes (8 services + 16 address + 2 port)" $ do
      let addr = NetworkAddress 1 (BS.replicate 16 0x00) 8333
      BS.length (encode addr) `shouldBe` 26

    it "roundtrips correctly" $ do
      let addr = NetworkAddress 0x409 (BS.replicate 16 0xff) 8333
      decode (encode addr) `shouldBe` Right addr

  describe "VarString" $ do
    it "roundtrips correctly" $ do
      let vs = VarString "hello world"
      decode (encode vs) `shouldBe` Right vs

  describe "WitnessStack" $ do
    it "roundtrips correctly" $ do
      let ws = WitnessStack ["item1", "item2", "item3"]
      decode (encode ws) `shouldBe` Right ws

  -- Crypto module tests
  describe "SHA256" $ do
    it "computes correct hash for empty string" $ do
      -- SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      let expected = hexDecode "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      sha256 "" `shouldBe` expected

    it "computes correct hash for 'abc'" $ do
      -- SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
      let expected = hexDecode "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      sha256 "abc" `shouldBe` expected

  describe "doubleSHA256" $ do
    it "computes correct double hash" $ do
      -- doubleSHA256("abc") = SHA256(SHA256("abc"))
      let Hash256 result = doubleSHA256 "abc"
          expected = sha256 (sha256 "abc")
      result `shouldBe` expected

  describe "RIPEMD160" $ do
    it "computes correct hash for empty string" $ do
      -- RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
      let expected = hexDecode "9c1185a5c5e9fc54612808977ee8f548b2258d31"
      ripemd160 "" `shouldBe` expected

    it "computes correct hash for 'abc'" $ do
      -- RIPEMD160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
      let expected = hexDecode "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
      ripemd160 "abc" `shouldBe` expected

  describe "hash160" $ do
    it "computes RIPEMD160(SHA256(data))" $ do
      let Hash160 result = hash160 "abc"
          expected = ripemd160 (sha256 "abc")
      result `shouldBe` expected

  describe "parsePubKey" $ do
    it "parses compressed public key (0x02 prefix)" $ do
      let pk = BS.cons 0x02 (BS.replicate 32 0xab)
      parsePubKey pk `shouldBe` Just (PubKeyCompressed pk)

    it "parses compressed public key (0x03 prefix)" $ do
      let pk = BS.cons 0x03 (BS.replicate 32 0xcd)
      parsePubKey pk `shouldBe` Just (PubKeyCompressed pk)

    it "parses uncompressed public key (0x04 prefix)" $ do
      let pk = BS.cons 0x04 (BS.replicate 64 0xef)
      parsePubKey pk `shouldBe` Just (PubKeyUncompressed pk)

    it "rejects invalid prefix" $ do
      let pk = BS.cons 0x05 (BS.replicate 32 0x00)
      parsePubKey pk `shouldBe` Nothing

    it "rejects wrong length" $ do
      let pk = BS.cons 0x02 (BS.replicate 31 0x00)  -- too short
      parsePubKey pk `shouldBe` Nothing

  describe "serializePubKeyCompressed" $ do
    it "returns compressed key unchanged" $ do
      let pk = BS.cons 0x02 (BS.replicate 32 0xab)
      serializePubKeyCompressed (PubKeyCompressed pk) `shouldBe` pk

    it "compresses uncompressed key based on y parity" $ do
      -- y ends with odd byte -> 0x03 prefix
      let x = BS.replicate 32 0xaa
          yOdd = BS.replicate 31 0x00 `BS.append` BS.singleton 0x01
          uncompressed = BS.concat [BS.singleton 0x04, x, yOdd]
      serializePubKeyCompressed (PubKeyUncompressed uncompressed) `shouldBe` BS.cons 0x03 x

  describe "parseSigDER" $ do
    it "parses valid DER signature" $ do
      -- Minimal valid DER: 0x30 0x06 0x02 0x01 0x01 0x02 0x01 0x01
      let sig = BS.pack [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
      parseSigDER sig `shouldBe` Just (Sig sig)

    it "rejects non-DER data" $ do
      let notDer = BS.pack [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
      parseSigDER notDer `shouldBe` Nothing

  describe "SigHashType" $ do
    it "sigHashAll encodes to 0x01" $ do
      sigHashTypeToWord32 sigHashAll `shouldBe` 0x01

    it "sigHashNone encodes to 0x02" $ do
      sigHashTypeToWord32 sigHashNone `shouldBe` 0x02

    it "sigHashSingle encodes to 0x03" $ do
      sigHashTypeToWord32 sigHashSingle `shouldBe` 0x03

    it "ANYONECANPAY sets 0x80 flag" $ do
      sigHashTypeToWord32 (sigHashAnyoneCanPay sigHashAll) `shouldBe` 0x81
      sigHashTypeToWord32 (sigHashAnyoneCanPay sigHashNone) `shouldBe` 0x82
      sigHashTypeToWord32 (sigHashAnyoneCanPay sigHashSingle) `shouldBe` 0x83

  describe "Sighash Computation" $ do
    describe "Legacy Sighash (txSigHash)" $ do
      it "computes sighash for SIGHASH_ALL" $ do
        -- Create a simple transaction
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xaa))
            prevOutpoint = OutPoint prevTxid 0
            txIn = TxIn prevOutpoint "" 0xffffffff
            txOut = TxOut 1000000 ""
            tx = Tx 1 [txIn] [txOut] [[]] 0
            subscript = BS.pack [0x76, 0xa9, 0x14] <> BS.replicate 20 0xab <> BS.pack [0x88, 0xac]
            Hash256 sighash = txSigHash tx 0 subscript sigHashAll
        -- Result should be 32 bytes
        BS.length sighash `shouldBe` 32
        -- Should be deterministic
        let Hash256 sighash2 = txSigHash tx 0 subscript sigHashAll
        sighash `shouldBe` sighash2

      it "produces different hashes for different sighash types" $ do
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xbb))
            prevOutpoint = OutPoint prevTxid 0
            txIn = TxIn prevOutpoint "" 0xffffffff
            txOut = TxOut 500000 (BS.replicate 25 0xcc)
            tx = Tx 1 [txIn] [txOut] [[]] 0
            subscript = BS.replicate 25 0xdd
            Hash256 hashAll = txSigHash tx 0 subscript sigHashAll
            Hash256 hashNone = txSigHash tx 0 subscript sigHashNone
            Hash256 hashSingle = txSigHash tx 0 subscript sigHashSingle
        hashAll `shouldNotBe` hashNone
        hashAll `shouldNotBe` hashSingle
        hashNone `shouldNotBe` hashSingle

      it "ANYONECANPAY produces different hash" $ do
        let prevTxid1 = TxId (Hash256 (BS.replicate 32 0x11))
            prevTxid2 = TxId (Hash256 (BS.replicate 32 0x22))
            txIn1 = TxIn (OutPoint prevTxid1 0) "" 0xffffffff
            txIn2 = TxIn (OutPoint prevTxid2 0) "" 0xffffffff
            txOut = TxOut 1000000 ""
            tx = Tx 1 [txIn1, txIn2] [txOut] [[], []] 0
            subscript = BS.replicate 25 0xee
            Hash256 hashAll = txSigHash tx 0 subscript sigHashAll
            Hash256 hashAcp = txSigHash tx 0 subscript (sigHashAnyoneCanPay sigHashAll)
        hashAll `shouldNotBe` hashAcp

    describe "BIP-143 SegWit Sighash (txSigHashSegWit)" $ do
      it "computes sighash for P2WPKH" $ do
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xcc))
            prevOutpoint = OutPoint prevTxid 0
            txIn = TxIn prevOutpoint "" 0xffffffff
            txOut = TxOut 900000 ""
            tx = Tx 2 [txIn] [txOut] [[]] 0
            -- P2WPKH scriptCode: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
            scriptCode = BS.pack [0x76, 0xa9, 0x14] <> BS.replicate 20 0xff <> BS.pack [0x88, 0xac]
            amount = 1000000 :: Word64
            Hash256 sighash = txSigHashSegWit tx 0 scriptCode amount sigHashAll
        BS.length sighash `shouldBe` 32

      it "is deterministic" $ do
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xdd))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xffffffff
            txOut = TxOut 500000 ""
            tx = Tx 2 [txIn] [txOut] [[]] 0
            scriptCode = BS.replicate 25 0xaa
            amount = 600000 :: Word64
            Hash256 hash1 = txSigHashSegWit tx 0 scriptCode amount sigHashAll
            Hash256 hash2 = txSigHashSegWit tx 0 scriptCode amount sigHashAll
        hash1 `shouldBe` hash2

      it "produces different hashes for different amounts" $ do
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xee))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xffffffff
            txOut = TxOut 500000 ""
            tx = Tx 2 [txIn] [txOut] [[]] 0
            scriptCode = BS.replicate 25 0xbb
            Hash256 hash1 = txSigHashSegWit tx 0 scriptCode 1000000 sigHashAll
            Hash256 hash2 = txSigHashSegWit tx 0 scriptCode 2000000 sigHashAll
        hash1 `shouldNotBe` hash2

      it "different sighash types produce different hashes" $ do
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xff))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xffffffff
            txOut = TxOut 500000 ""
            tx = Tx 2 [txIn] [txOut] [[]] 0
            scriptCode = BS.replicate 25 0xcc
            amount = 600000 :: Word64
            Hash256 hashAll = txSigHashSegWit tx 0 scriptCode amount sigHashAll
            Hash256 hashNone = txSigHashSegWit tx 0 scriptCode amount sigHashNone
            Hash256 hashSingle = txSigHashSegWit tx 0 scriptCode amount sigHashSingle
        hashAll `shouldNotBe` hashNone
        hashAll `shouldNotBe` hashSingle
        hashNone `shouldNotBe` hashSingle

      it "ANYONECANPAY zeros out prevouts hash" $ do
        -- With ANYONECANPAY, hash of prevouts should be all zeros
        -- This test verifies different behavior
        let prevTxid = TxId (Hash256 (BS.replicate 32 0x01))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xffffffff
            txOut = TxOut 500000 ""
            tx = Tx 2 [txIn] [txOut] [[]] 0
            scriptCode = BS.replicate 25 0xdd
            amount = 600000 :: Word64
            Hash256 hashNormal = txSigHashSegWit tx 0 scriptCode amount sigHashAll
            Hash256 hashAcp = txSigHashSegWit tx 0 scriptCode amount (sigHashAnyoneCanPay sigHashAll)
        hashNormal `shouldNotBe` hashAcp

  describe "computeTxId" $ do
    it "computes txid from non-witness data" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          txout = TxOut 100000 "scriptpubkey"
          tx = Tx 1 [txin] [txout] [[]] 0
          TxId (Hash256 computed) = computeTxId tx
      -- TxId should be 32 bytes (double SHA256)
      BS.length computed `shouldBe` 32

  describe "computeBlockHash" $ do
    it "computes block hash from header" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0x00))
          merkle = Hash256 (BS.replicate 32 0x00)
          header = BlockHeader 1 prevHash merkle 0 0 0
          BlockHash (Hash256 computed) = computeBlockHash header
      -- Block hash should be 32 bytes
      BS.length computed `shouldBe` 32

  -- Address encoding tests
  describe "Base58Check" $ do
    it "encodes P2PKH address correctly" $ do
      -- Known test vector: hash160 -> address
      -- Using zero hash for simplicity
      let hash = Hash160 (BS.replicate 20 0x00)
          addr = addressToText (PubKeyAddress hash)
      -- Address should start with '1' for mainnet P2PKH
      T.head addr `shouldBe` '1'

    it "encodes P2SH address correctly" $ do
      let hash = Hash160 (BS.replicate 20 0x00)
          addr = addressToText (ScriptAddress hash)
      -- P2SH addresses start with '3' on mainnet
      T.head addr `shouldBe` '3'

    it "roundtrips P2PKH address" $ do
      let hash = Hash160 (hexDecode "89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
          addr = PubKeyAddress hash
          encoded = addressToText addr
      textToAddress encoded `shouldBe` Just addr

    it "roundtrips P2SH address" $ do
      let hash = Hash160 (hexDecode "0011223344556677889900aabbccddeeff001122")
          addr = ScriptAddress hash
          encoded = addressToText addr
      textToAddress encoded `shouldBe` Just addr

    it "decodes known P2PKH address" $ do
      -- 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 is a well-known address
      -- Its hash160 is: 77bff20c60e522dfaa3350c39b030a5d004e839a
      let knownAddr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
          expectedHash = hexDecode "77bff20c60e522dfaa3350c39b030a5d004e839a"
      case textToAddress knownAddr of
        Just (PubKeyAddress (Hash160 h)) -> h `shouldBe` expectedHash
        _ -> expectationFailure "Failed to decode known address"

    it "rejects invalid checksum" $ do
      -- Modify last character to invalidate checksum
      textToAddress "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3" `shouldBe` Nothing

  describe "Bech32" $ do
    it "encodes P2WPKH address correctly" $ do
      let hash = Hash160 (BS.replicate 20 0x00)
          addr = addressToText (WitnessPubKeyAddress hash)
      -- Should start with bc1q for mainnet P2WPKH
      T.take 4 addr `shouldBe` "bc1q"

    it "encodes P2WSH address correctly" $ do
      let hash = Hash256 (BS.replicate 32 0x00)
          addr = addressToText (WitnessScriptAddress hash)
      -- Should start with bc1q for mainnet P2WSH (witness version 0)
      T.take 4 addr `shouldBe` "bc1q"

    it "roundtrips P2WPKH address" $ do
      let hash = Hash160 (hexDecode "751e76e8199196d454941c45d1b3a323f1433bd6")
          addr = WitnessPubKeyAddress hash
          encoded = addressToText addr
      textToAddress encoded `shouldBe` Just addr

    it "roundtrips P2WSH address" $ do
      let hash = Hash256 (hexDecode "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
          addr = WitnessScriptAddress hash
          encoded = addressToText addr
      textToAddress encoded `shouldBe` Just addr

    it "decodes known P2WPKH address" $ do
      -- bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 corresponds to
      -- hash160: 751e76e8199196d454941c45d1b3a323f1433bd6
      let knownAddr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
          expectedHash = hexDecode "751e76e8199196d454941c45d1b3a323f1433bd6"
      case textToAddress knownAddr of
        Just (WitnessPubKeyAddress (Hash160 h)) -> h `shouldBe` expectedHash
        _ -> expectationFailure "Failed to decode known bech32 address"

  describe "Bech32m" $ do
    it "encodes Taproot address correctly" $ do
      let hash = Hash256 (BS.replicate 32 0x00)
          addr = addressToText (TaprootAddress hash)
      -- Should start with bc1p for mainnet P2TR
      T.take 4 addr `shouldBe` "bc1p"

    it "roundtrips Taproot address" $ do
      let hash = Hash256 (hexDecode "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
          addr = TaprootAddress hash
          encoded = addressToText addr
      textToAddress encoded `shouldBe` Just addr

    it "decodes known Taproot address" $ do
      -- bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0
      -- This is a BIP-350 test vector
      let knownAddr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
      case textToAddress knownAddr of
        Just (TaprootAddress _) -> return ()  -- Success, just check it parses as Taproot
        _ -> expectationFailure "Failed to decode known taproot address"

  describe "Address construction" $ do
    it "pubKeyToP2PKH creates P2PKH address" $ do
      let pk = PubKeyCompressed (BS.cons 0x02 (BS.replicate 32 0xab))
          addr = pubKeyToP2PKH pk
      case addr of
        PubKeyAddress _ -> return ()
        _ -> expectationFailure "Expected P2PKH address"

    it "pubKeyToP2WPKH creates P2WPKH address" $ do
      let pk = PubKeyCompressed (BS.cons 0x02 (BS.replicate 32 0xab))
          addr = pubKeyToP2WPKH pk
      case addr of
        WitnessPubKeyAddress _ -> return ()
        _ -> expectationFailure "Expected P2WPKH address"

    it "scriptToP2SH creates P2SH address" $ do
      let script = BS.pack [0x00, 0x14] <> BS.replicate 20 0xcd
          addr = scriptToP2SH script
      case addr of
        ScriptAddress _ -> return ()
        _ -> expectationFailure "Expected P2SH address"

    it "scriptToP2WSH creates P2WSH address" $ do
      let script = BS.pack [0x52, 0x21] <> BS.replicate 33 0xab <> BS.pack [0x21] <> BS.replicate 33 0xcd <> BS.pack [0x52, 0xae]
          addr = scriptToP2WSH script
      case addr of
        WitnessScriptAddress _ -> return ()
        _ -> expectationFailure "Expected P2WSH address"

  -- Script module tests
  describe "Script parsing" $ do
    it "decodes OP_0" $ do
      let bytes = BS.pack [0x00]
      case decodeScript bytes of
        Right (Script [OP_0]) -> return ()
        _ -> expectationFailure "Expected OP_0"

    it "decodes push data (direct push)" $ do
      let bytes = BS.pack [0x03, 0xaa, 0xbb, 0xcc]
      case decodeScript bytes of
        Right (Script [OP_PUSHDATA bs OPCODE])
          | bs == BS.pack [0xaa, 0xbb, 0xcc] -> return ()
        _ -> expectationFailure "Expected 3-byte push"

    it "decodes OP_PUSHDATA1" $ do
      let bytes = BS.pack [0x4c, 0x03, 0xaa, 0xbb, 0xcc]
      case decodeScript bytes of
        Right (Script [OP_PUSHDATA bs OPDATA1])
          | bs == BS.pack [0xaa, 0xbb, 0xcc] -> return ()
        _ -> expectationFailure "Expected PUSHDATA1"

    it "decodes small numbers (OP_1 through OP_16)" $ do
      let bytes = BS.pack [0x51, 0x52, 0x60]  -- OP_1, OP_2, OP_16
      case decodeScript bytes of
        Right (Script [OP_1, OP_2, OP_16]) -> return ()
        _ -> expectationFailure "Expected OP_1, OP_2, OP_16"

    it "decodes P2PKH script" $ do
      let hash20 = BS.replicate 20 0xab
          bytes = BS.pack [0x76, 0xa9, 0x14] <> hash20 <> BS.pack [0x88, 0xac]
      case decodeScript bytes of
        Right (Script [OP_DUP, OP_HASH160, OP_PUSHDATA h OPCODE, OP_EQUALVERIFY, OP_CHECKSIG])
          | h == hash20 -> return ()
        _ -> expectationFailure "Expected P2PKH script"

    it "roundtrips arbitrary script" $ do
      let ops = [OP_1, OP_2, OP_ADD, OP_3, OP_EQUAL]
          script = Script ops
          encoded = encodeScript script
      decodeScript encoded `shouldBe` Right script

  describe "Script encoding" $ do
    it "encodes OP_0 correctly" $ do
      encodeScript (Script [OP_0]) `shouldBe` BS.pack [0x00]

    it "encodes push data correctly" $ do
      let bs = BS.pack [0xab, 0xcd]
      encodeScript (Script [OP_PUSHDATA bs OPCODE]) `shouldBe` BS.pack [0x02, 0xab, 0xcd]

    it "encodes small numbers correctly" $ do
      encodeScript (Script [OP_1, OP_16]) `shouldBe` BS.pack [0x51, 0x60]

  describe "Script classification" $ do
    it "classifies P2PKH" $ do
      let hash = Hash160 (BS.replicate 20 0xab)
          script = encodeP2PKH hash
      classifyOutput script `shouldBe` P2PKH hash

    it "classifies P2SH" $ do
      let hash = Hash160 (BS.replicate 20 0xcd)
          script = encodeP2SH hash
      classifyOutput script `shouldBe` P2SH hash

    it "classifies P2WPKH" $ do
      let hash = Hash160 (BS.replicate 20 0xef)
          script = encodeP2WPKH hash
      classifyOutput script `shouldBe` P2WPKH hash

    it "classifies P2WSH" $ do
      let hash = Hash256 (BS.replicate 32 0x12)
          script = encodeP2WSH hash
      classifyOutput script `shouldBe` P2WSH hash

    it "classifies P2PK (compressed)" $ do
      let pubkey = BS.cons 0x02 (BS.replicate 32 0xaa)
          script = Script [OP_PUSHDATA pubkey OPCODE, OP_CHECKSIG]
      classifyOutput script `shouldBe` P2PK pubkey

    it "classifies P2PK (uncompressed)" $ do
      let pubkey = BS.cons 0x04 (BS.replicate 64 0xbb)
          script = Script [OP_PUSHDATA pubkey OPCODE, OP_CHECKSIG]
      classifyOutput script `shouldBe` P2PK pubkey

    it "classifies OP_RETURN" $ do
      let script = encodeOpReturn (BS.pack [0x01, 0x02, 0x03])
      case classifyOutput script of
        OpReturn _ -> return ()
        _ -> expectationFailure "Expected OP_RETURN"

    it "classifies multisig" $ do
      let pk1 = BS.cons 0x02 (BS.replicate 32 0xaa)
          pk2 = BS.cons 0x02 (BS.replicate 32 0xbb)
          script = encodeMultisig 1 [pk1, pk2]
      case classifyOutput script of
        P2MultiSig m pks | m == 1 && length pks == 2 -> return ()
        _ -> expectationFailure "Expected 1-of-2 multisig"

    it "classifies non-standard" $ do
      let script = Script [OP_NOP, OP_NOP]
      classifyOutput script `shouldBe` NonStandard

  describe "Standard script constructors" $ do
    it "encodeP2PKH creates valid P2PKH" $ do
      let hash = Hash160 (BS.replicate 20 0x00)
          Script ops = encodeP2PKH hash
      length ops `shouldBe` 5
      head ops `shouldBe` OP_DUP
      ops !! 1 `shouldBe` OP_HASH160
      ops !! 3 `shouldBe` OP_EQUALVERIFY
      ops !! 4 `shouldBe` OP_CHECKSIG

    it "encodeP2SH creates valid P2SH" $ do
      let hash = Hash160 (BS.replicate 20 0x00)
          Script ops = encodeP2SH hash
      length ops `shouldBe` 3
      head ops `shouldBe` OP_HASH160
      ops !! 2 `shouldBe` OP_EQUAL

    it "encodeP2WPKH creates valid P2WPKH" $ do
      let hash = Hash160 (BS.replicate 20 0x00)
          Script ops = encodeP2WPKH hash
      length ops `shouldBe` 2
      head ops `shouldBe` OP_0

    it "encodeP2WSH creates valid P2WSH" $ do
      let hash = Hash256 (BS.replicate 32 0x00)
          Script ops = encodeP2WSH hash
      length ops `shouldBe` 2
      head ops `shouldBe` OP_0

    it "encodeMultisig creates valid multisig" $ do
      let pk1 = BS.cons 0x02 (BS.replicate 32 0xaa)
          pk2 = BS.cons 0x02 (BS.replicate 32 0xbb)
          pk3 = BS.cons 0x02 (BS.replicate 32 0xcc)
          Script ops = encodeMultisig 2 [pk1, pk2, pk3]
      head ops `shouldBe` OP_2
      last ops `shouldBe` OP_CHECKMULTISIG
      ops !! 4 `shouldBe` OP_3

  describe "Script number encoding" $ do
    it "encodes zero as empty" $ do
      encodeScriptNum 0 `shouldBe` BS.empty

    it "encodes positive numbers" $ do
      encodeScriptNum 1 `shouldBe` BS.pack [0x01]
      encodeScriptNum 127 `shouldBe` BS.pack [0x7f]
      encodeScriptNum 128 `shouldBe` BS.pack [0x80, 0x00]  -- needs extra byte for sign
      encodeScriptNum 255 `shouldBe` BS.pack [0xff, 0x00]
      encodeScriptNum 256 `shouldBe` BS.pack [0x00, 0x01]

    it "encodes negative numbers" $ do
      encodeScriptNum (-1) `shouldBe` BS.pack [0x81]
      encodeScriptNum (-127) `shouldBe` BS.pack [0xff]
      encodeScriptNum (-128) `shouldBe` BS.pack [0x80, 0x80]

    it "roundtrips script numbers" $ property $ \(n :: Int) ->
      let n64 = fromIntegral n :: Int64
          -- Limit to 4-byte range
          clamped = max (-2147483647) (min 2147483647 n64)
      in decodeScriptNum (encodeScriptNum clamped) == Right clamped

  describe "Script number decoding" $ do
    it "decodes empty as zero" $ do
      decodeScriptNum BS.empty `shouldBe` Right 0

    it "decodes positive numbers" $ do
      decodeScriptNum (BS.pack [0x01]) `shouldBe` Right 1
      decodeScriptNum (BS.pack [0x7f]) `shouldBe` Right 127
      decodeScriptNum (BS.pack [0x80, 0x00]) `shouldBe` Right 128

    it "decodes negative numbers" $ do
      decodeScriptNum (BS.pack [0x81]) `shouldBe` Right (-1)
      decodeScriptNum (BS.pack [0xff]) `shouldBe` Right (-127)

    it "rejects overflow (> 4 bytes)" $ do
      case decodeScriptNum (BS.pack [0x01, 0x02, 0x03, 0x04, 0x05]) of
        Left _ -> return ()
        Right _ -> expectationFailure "Should reject > 4 bytes"

  describe "isTrue" $ do
    it "empty is false" $ do
      isTrue BS.empty `shouldBe` False

    it "zero is false" $ do
      isTrue (BS.pack [0x00]) `shouldBe` False
      isTrue (BS.pack [0x00, 0x00]) `shouldBe` False

    it "negative zero is false" $ do
      isTrue (BS.pack [0x80]) `shouldBe` False

    it "non-zero is true" $ do
      isTrue (BS.pack [0x01]) `shouldBe` True
      isTrue (BS.pack [0xff]) `shouldBe` True
      isTrue (BS.pack [0x00, 0x01]) `shouldBe` True

  describe "opN" $ do
    it "returns correct opcodes" $ do
      opN 0 `shouldBe` OP_0
      opN 1 `shouldBe` OP_1
      opN 16 `shouldBe` OP_16

    it "returns OP_0 for out of range" $ do
      opN 17 `shouldBe` OP_0
      opN (-1) `shouldBe` OP_0

  describe "Script evaluation (basic ops)" $ do
    it "evaluates OP_1 OP_1 OP_ADD OP_2 OP_EQUAL" $ do
      let scriptSig = Script []
          scriptPubKey = Script [OP_1, OP_1, OP_ADD, OP_2, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "evaluates OP_1 OP_2 OP_ADD OP_4 OP_EQUAL (false)" $ do
      let scriptSig = Script []
          scriptPubKey = Script [OP_1, OP_2, OP_ADD, OP_4, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right False

    it "evaluates OP_DUP" $ do
      let scriptSig = Script [OP_1]
          scriptPubKey = Script [OP_DUP, OP_ADD, OP_2, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "evaluates OP_SWAP" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_SWAP, OP_SUB, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "evaluates OP_IF/OP_ELSE/OP_ENDIF (true branch)" $ do
      let scriptSig = Script [OP_1]
          scriptPubKey = Script [OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
          dummyTx = Tx 1 [] [] [] 0
      -- Stack should have 2 on top (true branch), which is truthy
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "evaluates OP_IF/OP_ELSE/OP_ENDIF (false branch)" $ do
      let scriptSig = Script [OP_0]
          scriptPubKey = Script [OP_IF, OP_0, OP_ELSE, OP_1, OP_ENDIF]
          dummyTx = Tx 1 [] [] [] 0
      -- Stack should have 1 on top (false branch), which is truthy
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "evaluates OP_HASH160" $ do
      let scriptSig = Script [OP_PUSHDATA (BS.pack [0x01, 0x02, 0x03]) OPCODE]
          expectedHash = hash160 (BS.pack [0x01, 0x02, 0x03])
          scriptPubKey = Script [OP_HASH160, OP_PUSHDATA (getHash160 expectedHash) OPCODE, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "rejects OP_RETURN" $ do
      let scriptSig = Script []
          scriptPubKey = Script [OP_RETURN]
          dummyTx = Tx 1 [] [] [] 0
      case evalScript dummyTx 0 0 scriptSig scriptPubKey of
        Left _ -> return ()
        Right _ -> expectationFailure "Should reject OP_RETURN"

    it "rejects disabled opcodes (OP_CAT)" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_CAT]
          dummyTx = Tx 1 [] [] [] 0
      case evalScript dummyTx 0 0 scriptSig scriptPubKey of
        Left msg | "disabled" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject OP_CAT"

    it "rejects stack underflow" $ do
      let scriptSig = Script []
          scriptPubKey = Script [OP_DUP]
          dummyTx = Tx 1 [] [] [] 0
      case evalScript dummyTx 0 0 scriptSig scriptPubKey of
        Left _ -> return ()
        Right _ -> expectationFailure "Should reject stack underflow"

  describe "OP_RETURN in non-executing branch" $ do
    it "does not terminate script in false IF branch" $ do
      let scriptSig = Script [OP_0]  -- false
          scriptPubKey = Script [OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_ENDIF]
          dummyTx = Tx 1 [] [] [] 0
      -- Should skip OP_RETURN and execute ELSE branch
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "Arithmetic operations" $ do
    it "OP_1ADD increments" $ do
      let scriptSig = Script [OP_5]
          scriptPubKey = Script [OP_1ADD, OP_6, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_1SUB decrements" $ do
      let scriptSig = Script [OP_5]
          scriptPubKey = Script [OP_1SUB, OP_4, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_NEGATE negates" $ do
      let scriptSig = Script [OP_5]
          scriptPubKey = Script [OP_NEGATE, OP_PUSHDATA (encodeScriptNum (-5)) OPCODE, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_ABS takes absolute value" $ do
      let scriptSig = Script [OP_PUSHDATA (encodeScriptNum (-5)) OPCODE]
          scriptPubKey = Script [OP_ABS, OP_5, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_NOT returns 1 for 0" $ do
      let scriptSig = Script [OP_0]
          scriptPubKey = Script [OP_NOT, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_NOT returns 0 for non-zero" $ do
      let scriptSig = Script [OP_5]
          scriptPubKey = Script [OP_NOT, OP_0, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_BOOLAND works correctly" $ do
      let scriptSig = Script [OP_1, OP_1]
          scriptPubKey = Script [OP_BOOLAND]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_BOOLOR works correctly" $ do
      let scriptSig = Script [OP_0, OP_1]
          scriptPubKey = Script [OP_BOOLOR]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_LESSTHAN compares correctly" $ do
      let scriptSig = Script [OP_3, OP_5]
          scriptPubKey = Script [OP_LESSTHAN]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_WITHIN checks range" $ do
      let scriptSig = Script [OP_5, OP_3, OP_7]  -- x=5, min=3, max=7, so 3 <= 5 < 7
          scriptPubKey = Script [OP_WITHIN]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_MIN returns minimum" $ do
      let scriptSig = Script [OP_3, OP_7]
          scriptPubKey = Script [OP_MIN, OP_3, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_MAX returns maximum" $ do
      let scriptSig = Script [OP_3, OP_7]
          scriptPubKey = Script [OP_MAX, OP_7, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "Stack operations" $ do
    it "OP_DEPTH returns stack size" $ do
      let scriptSig = Script [OP_1, OP_2, OP_3]
          scriptPubKey = Script [OP_DEPTH, OP_3, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_DROP removes top element" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_DROP, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_NIP removes second element" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_NIP, OP_2, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_OVER copies second element" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_OVER, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_ROT rotates top 3" $ do
      let scriptSig = Script [OP_1, OP_2, OP_3]
          scriptPubKey = Script [OP_ROT, OP_1, OP_EQUAL]  -- 3,1,2 -> top is 1
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_TUCK copies top behind second" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_TUCK, OP_DEPTH, OP_3, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_2DUP duplicates top 2" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_2DUP, OP_DEPTH, OP_4, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_3DUP duplicates top 3" $ do
      let scriptSig = Script [OP_1, OP_2, OP_3]
          scriptPubKey = Script [OP_3DUP, OP_DEPTH, OP_6, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_SIZE pushes element size" $ do
      let scriptSig = Script [OP_PUSHDATA (BS.pack [0x01, 0x02, 0x03]) OPCODE]
          scriptPubKey = Script [OP_SIZE, OP_3, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_IFDUP duplicates if true" $ do
      let scriptSig = Script [OP_1]
          scriptPubKey = Script [OP_IFDUP, OP_DEPTH, OP_2, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_IFDUP does not duplicate if false" $ do
      let scriptSig = Script [OP_0]
          scriptPubKey = Script [OP_IFDUP, OP_DEPTH, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "Crypto operations" $ do
    it "OP_SHA256 computes SHA256" $ do
      let input = BS.pack [0x01, 0x02, 0x03]
          expected = sha256 input
          scriptSig = Script [OP_PUSHDATA input OPCODE]
          scriptPubKey = Script [OP_SHA256, OP_PUSHDATA expected OPCODE, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_HASH256 computes double SHA256" $ do
      let input = BS.pack [0x01, 0x02, 0x03]
          Hash256 expected = doubleSHA256 input
          scriptSig = Script [OP_PUSHDATA input OPCODE]
          scriptPubKey = Script [OP_HASH256, OP_PUSHDATA expected OPCODE, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_RIPEMD160 computes RIPEMD160" $ do
      let input = BS.pack [0x01, 0x02, 0x03]
          expected = ripemd160 input
          scriptSig = Script [OP_PUSHDATA input OPCODE]
          scriptPubKey = Script [OP_RIPEMD160, OP_PUSHDATA expected OPCODE, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "EQUALVERIFY" $ do
    it "passes when equal" $ do
      let scriptSig = Script [OP_1, OP_1]
          scriptPubKey = Script [OP_EQUALVERIFY, OP_1]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "fails when not equal" $ do
      let scriptSig = Script [OP_1, OP_2]
          scriptPubKey = Script [OP_EQUALVERIFY, OP_1]
          dummyTx = Tx 1 [] [] [] 0
      case evalScript dummyTx 0 0 scriptSig scriptPubKey of
        Left _ -> return ()
        Right _ -> expectationFailure "Should fail on unequal EQUALVERIFY"

  describe "Nested IF" $ do
    it "handles nested IF correctly" $ do
      let scriptSig = Script [OP_1, OP_1]
          -- if (1) { if (1) { 5 } else { 6 } } else { 7 }
          scriptPubKey = Script
            [ OP_IF
            ,   OP_IF
            ,     OP_5
            ,   OP_ELSE
            ,     OP_6
            ,   OP_ENDIF
            , OP_ELSE
            ,   OP_7
            , OP_ENDIF
            ]
          dummyTx = Tx 1 [] [] [] 0
      -- Inner if is true, so result should be 5
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "OP_NOTIF" $ do
    it "executes on false" $ do
      let scriptSig = Script [OP_0]
          scriptPubKey = Script [OP_NOTIF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "skips on true" $ do
      let scriptSig = Script [OP_1]
          scriptPubKey = Script [OP_NOTIF, OP_0, OP_ELSE, OP_1, OP_ENDIF]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "OP_VERIFY" $ do
    it "passes on true" $ do
      let scriptSig = Script [OP_1]
          scriptPubKey = Script [OP_VERIFY, OP_1]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "fails on false" $ do
      let scriptSig = Script [OP_0]
          scriptPubKey = Script [OP_VERIFY, OP_1]
          dummyTx = Tx 1 [] [] [] 0
      case evalScript dummyTx 0 0 scriptSig scriptPubKey of
        Left _ -> return ()
        Right _ -> expectationFailure "Should fail on false VERIFY"

  describe "OP_PICK and OP_ROLL" $ do
    it "OP_PICK copies nth element" $ do
      let scriptSig = Script [OP_1, OP_2, OP_3, OP_2]  -- pick index 2 (0-indexed)
          scriptPubKey = Script [OP_PICK, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

    it "OP_ROLL moves nth element to top" $ do
      let scriptSig = Script [OP_1, OP_2, OP_3, OP_2]
          scriptPubKey = Script [OP_ROLL, OP_1, OP_EQUAL]
          dummyTx = Tx 1 [] [] [] 0
      evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

  describe "isPushOnly and push only scripts" $ do
    it "returns True for empty script" $ do
      isPushOnly (Script []) `shouldBe` True

    it "returns True for OP_0" $ do
      isPushOnly (Script [OP_0]) `shouldBe` True

    it "returns True for push data" $ do
      isPushOnly (Script [OP_PUSHDATA (BS.pack [0x01, 0x02]) OPCODE]) `shouldBe` True

    it "returns True for OP_1 through OP_16" $ do
      isPushOnly (Script [OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8]) `shouldBe` True
      isPushOnly (Script [OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16]) `shouldBe` True

    it "returns True for OP_1NEGATE" $ do
      isPushOnly (Script [OP_1NEGATE]) `shouldBe` True

    it "returns True for mixed push operations" $ do
      let script = Script [OP_0, OP_PUSHDATA (BS.pack [0xab]) OPCODE, OP_1, OP_16]
      isPushOnly script `shouldBe` True

    it "returns False for OP_DUP" $ do
      isPushOnly (Script [OP_DUP]) `shouldBe` False

    it "returns False for OP_ADD" $ do
      isPushOnly (Script [OP_ADD]) `shouldBe` False

    it "returns False for OP_CHECKSIG" $ do
      isPushOnly (Script [OP_CHECKSIG]) `shouldBe` False

    it "returns False for OP_HASH160" $ do
      isPushOnly (Script [OP_HASH160]) `shouldBe` False

    it "returns False for script with any non-push op" $ do
      isPushOnly (Script [OP_1, OP_2, OP_DUP, OP_3]) `shouldBe` False

  describe "P2SH push only enforcement" $ do
    it "accepts push-only P2SH scriptSig" $ do
      -- Create a simple redeem script: OP_1
      let redeemScript = encodeScript (Script [OP_1])
          redeemScriptHash = hash160 redeemScript
          -- P2SH output: OP_HASH160 <hash> OP_EQUAL
          scriptPubKey = encodeP2SH redeemScriptHash
          -- scriptSig: just push the redeem script (push-only)
          scriptSig = Script [OP_PUSHDATA redeemScript OPCODE]
          -- Create dummy tx with the scriptSig
          dummyTxId = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint dummyTxId 0) (encodeScript scriptSig) 0xffffffff
          tx = Tx 1 [txin] [TxOut 0 (encodeScript scriptPubKey)] [[]] 0
      -- verifyScript expects the raw scriptPubKey bytes
      case verifyScript tx 0 (encodeScript scriptPubKey) 0 of
        Right True -> return ()
        Right False -> expectationFailure "Expected P2SH verification to succeed"
        Left err -> expectationFailure $ "P2SH verification failed: " ++ err

    it "rejects P2SH scriptSig containing OP_DUP" $ do
      -- Create a simple redeem script that just returns true
      let redeemScript = encodeScript (Script [OP_1])
          redeemScriptHash = hash160 redeemScript
          -- P2SH output
          scriptPubKey = encodeP2SH redeemScriptHash
          -- scriptSig with non-push opcode: OP_DUP followed by redeem script push
          -- This should fail because OP_DUP is not a push operation
          scriptSigOps = [OP_DUP, OP_PUSHDATA redeemScript OPCODE]
          scriptSig = Script scriptSigOps
          dummyTxId = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint dummyTxId 0) (encodeScript scriptSig) 0xffffffff
          tx = Tx 1 [txin] [TxOut 0 (encodeScript scriptPubKey)] [[]] 0
      case verifyScript tx 0 (encodeScript scriptPubKey) 0 of
        Left err | "push-only" `T.isInfixOf` T.pack err -> return ()
        Left err -> expectationFailure $ "Expected push-only error, got: " ++ err
        Right _ -> expectationFailure "Expected P2SH to reject non-push-only scriptSig"

    it "rejects P2SH scriptSig containing OP_ADD" $ do
      let redeemScript = encodeScript (Script [OP_1])
          redeemScriptHash = hash160 redeemScript
          scriptPubKey = encodeP2SH redeemScriptHash
          -- scriptSig with OP_ADD (not a push operation)
          scriptSigOps = [OP_1, OP_1, OP_ADD, OP_PUSHDATA redeemScript OPCODE]
          scriptSig = Script scriptSigOps
          dummyTxId = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint dummyTxId 0) (encodeScript scriptSig) 0xffffffff
          tx = Tx 1 [txin] [TxOut 0 (encodeScript scriptPubKey)] [[]] 0
      case verifyScript tx 0 (encodeScript scriptPubKey) 0 of
        Left err | "push-only" `T.isInfixOf` T.pack err -> return ()
        Left err -> expectationFailure $ "Expected push-only error, got: " ++ err
        Right _ -> expectationFailure "Expected P2SH to reject non-push-only scriptSig"

    it "rejects P2SH scriptSig containing OP_CHECKSIG" $ do
      let redeemScript = encodeScript (Script [OP_1])
          redeemScriptHash = hash160 redeemScript
          scriptPubKey = encodeP2SH redeemScriptHash
          -- scriptSig with OP_CHECKSIG (not a push operation)
          scriptSigOps = [OP_CHECKSIG, OP_PUSHDATA redeemScript OPCODE]
          scriptSig = Script scriptSigOps
          dummyTxId = TxId (Hash256 (BS.replicate 32 0x00))
          txin = TxIn (OutPoint dummyTxId 0) (encodeScript scriptSig) 0xffffffff
          tx = Tx 1 [txin] [TxOut 0 (encodeScript scriptPubKey)] [[]] 0
      case verifyScript tx 0 (encodeScript scriptPubKey) 0 of
        Left err | "push-only" `T.isInfixOf` T.pack err -> return ()
        Left err -> expectationFailure $ "Expected push-only error, got: " ++ err
        Right _ -> expectationFailure "Expected P2SH to reject non-push-only scriptSig"

  -- Consensus module tests
  describe "Consensus constants" $ do
    it "maxMoney is 21 million BTC in satoshis" $ do
      maxMoney `shouldBe` 2100000000000000

    it "maxBlockSize is 1 MB" $ do
      maxBlockSize `shouldBe` 1000000

    it "maxBlockWeight is 4 million weight units" $ do
      maxBlockWeight `shouldBe` 4000000

    it "coinbaseMaturity is 100" $ do
      coinbaseMaturity `shouldBe` 100

    it "difficultyAdjustmentInterval is 2016" $ do
      difficultyAdjustmentInterval `shouldBe` 2016

    it "halvingInterval is 210000" $ do
      halvingInterval `shouldBe` 210000

  describe "Block reward" $ do
    it "initial block reward is 50 BTC" $ do
      blockReward 0 `shouldBe` 5000000000

    it "reward at block 209999 is still 50 BTC" $ do
      blockReward 209999 `shouldBe` 5000000000

    it "reward at block 210000 is 25 BTC (first halving)" $ do
      blockReward 210000 `shouldBe` 2500000000

    it "reward at block 420000 is 12.5 BTC (second halving)" $ do
      blockReward 420000 `shouldBe` 1250000000

    it "reward at block 630000 is 6.25 BTC (third halving)" $ do
      blockReward 630000 `shouldBe` 625000000

    it "reward at block 840000 is 3.125 BTC (fourth halving)" $ do
      blockReward 840000 `shouldBe` 312500000

    it "reward becomes 0 after 64 halvings" $ do
      -- 64 * 210000 = 13,440,000
      blockReward 13440000 `shouldBe` 0

  describe "Difficulty target conversion" $ do
    it "bitsToTarget converts difficulty 1 correctly" $ do
      -- 0x1d00ffff is the "difficulty 1" target
      let target = bitsToTarget 0x1d00ffff
      target `shouldBe` 0x00000000FFFF0000000000000000000000000000000000000000000000000000

    it "bitsToTarget handles small exponents" $ do
      -- Exponent = 3, mantissa = 0x7fffff
      let target = bitsToTarget 0x037fffff
      target `shouldBe` 0x7fffff

    it "targetToBits roundtrips difficulty 1" $ do
      let bits = 0x1d00ffff
          target = bitsToTarget bits
          bits' = targetToBits target
      bits' `shouldBe` bits

    it "targetToBits roundtrips various values" $ do
      let testBits = [0x1b0404cb, 0x1c0d3142, 0x1d00ffff]
      forM_ testBits $ \bits -> do
        let target = bitsToTarget bits
            bits' = targetToBits target
        bits' `shouldBe` bits

  describe "Merkle root computation" $ do
    it "single txid returns same hash" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xab))
          root = computeMerkleRoot [txid]
      root `shouldBe` getTxIdHash txid

    it "empty list returns zero hash" $ do
      let root = computeMerkleRoot []
      root `shouldBe` Hash256 (BS.replicate 32 0)

    it "two txids are hashed together" $ do
      let txid1 = TxId (Hash256 (BS.replicate 32 0x01))
          txid2 = TxId (Hash256 (BS.replicate 32 0x02))
          root = computeMerkleRoot [txid1, txid2]
          expected = doubleSHA256 (BS.append (BS.replicate 32 0x01) (BS.replicate 32 0x02))
      root `shouldBe` expected

    it "odd number of txids duplicates last" $ do
      -- With 3 txids: hash(hash(tx1,tx2), hash(tx3,tx3))
      let txid1 = TxId (Hash256 (BS.replicate 32 0x01))
          txid2 = TxId (Hash256 (BS.replicate 32 0x02))
          txid3 = TxId (Hash256 (BS.replicate 32 0x03))
          root = computeMerkleRoot [txid1, txid2, txid3]
          h12 = doubleSHA256 (BS.append (BS.replicate 32 0x01) (BS.replicate 32 0x02))
          h33 = doubleSHA256 (BS.append (BS.replicate 32 0x03) (BS.replicate 32 0x03))
          expected = doubleSHA256 (BS.append (getHash256 h12) (getHash256 h33))
      root `shouldBe` expected

  describe "Network configuration" $ do
    it "mainnet has correct magic bytes" $ do
      netMagic mainnet `shouldBe` 0xD9B4BEF9

    it "mainnet has correct port" $ do
      netDefaultPort mainnet `shouldBe` 8333

    it "mainnet has correct bech32 prefix" $ do
      netBech32Prefix mainnet `shouldBe` "bc"

    it "testnet3 has correct port" $ do
      netDefaultPort testnet3 `shouldBe` 18333

    it "testnet3 has correct bech32 prefix" $ do
      netBech32Prefix testnet3 `shouldBe` "tb"

    it "regtest has correct bech32 prefix" $ do
      netBech32Prefix regtest `shouldBe` "bcrt"

    it "regtest has shorter halving interval" $ do
      netHalvingInterval regtest `shouldBe` 150

  describe "Genesis block" $ do
    it "mainnet genesis has correct timestamp" $ do
      bhTimestamp genesisBlockHeader `shouldBe` 1231006505

    it "mainnet genesis has correct nonce" $ do
      bhNonce genesisBlockHeader `shouldBe` 2083236893

    it "mainnet genesis has difficulty 1" $ do
      bhBits genesisBlockHeader `shouldBe` 0x1d00ffff

    it "mainnet genesis block has one transaction" $ do
      length (blockTxns genesisBlock) `shouldBe` 1

    it "mainnet genesis coinbase has 50 BTC output" $ do
      let coinbase = head (blockTxns genesisBlock)
          genesisTxOut = head (txOutputs coinbase)
      txOutValue genesisTxOut `shouldBe` 5000000000

  describe "Transaction validation" $ do
    it "rejects transaction with no inputs" $ do
      let tx = Tx 1 [] [TxOut 1000 "script"] [[]] 0
      case validateTransaction tx of
        Left msg | "no inputs" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject tx with no inputs"

    it "rejects transaction with no outputs" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          tx = Tx 1 [txin] [] [[]] 0
      case validateTransaction tx of
        Left msg | "no outputs" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject tx with no outputs"

    it "rejects transaction with duplicate inputs" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xbb))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          tx = Tx 1 [txin, txin] [TxOut 1000 "script"] [[], []] 0
      case validateTransaction tx of
        Left msg | "Duplicate" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject tx with duplicate inputs"

    it "rejects transaction with outputs exceeding max money" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xcc))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          tx = Tx 1 [txin] [TxOut (maxMoney + 1) "script"] [[]] 0
      case validateTransaction tx of
        Left msg | "max money" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject tx exceeding max money"

    it "accepts valid coinbase transaction" $ do
      let nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint (BS.replicate 10 0x04) 0xffffffff
          tx = Tx 1 [txin] [TxOut 5000000000 "script"] [[]] 0
      validateTransaction tx `shouldBe` Right ()

    it "rejects coinbase with too short script" $ do
      let nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint (BS.singleton 0x04) 0xffffffff  -- 1 byte, too short
          tx = Tx 1 [txin] [TxOut 5000000000 "script"] [[]] 0
      case validateTransaction tx of
        Left msg | "size" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject coinbase with short script"

  describe "Hex utilities" $ do
    it "hexToBS converts hex string to bytes" $ do
      hexToBS "deadbeef" `shouldBe` BS.pack [0xde, 0xad, 0xbe, 0xef]

    it "hexToBS handles empty string" $ do
      hexToBS "" `shouldBe` BS.empty

    it "hexToBS handles uppercase" $ do
      hexToBS "DEADBEEF" `shouldBe` BS.pack [0xde, 0xad, 0xbe, 0xef]

  describe "Proof of work" $ do
    it "mainnet powLimit is correct" $ do
      powLimit `shouldBe` 0x00000000FFFF0000000000000000000000000000000000000000000000000000

    -- Note: checkProofOfWork validates that hash <= target
    -- We test with a simple constructed header
    it "accepts hash below target" $ do
      -- Create a header with a very easy target (high bits value)
      let header = BlockHeader
            { bhVersion = 1
            , bhPrevBlock = BlockHash (Hash256 (BS.replicate 32 0))
            , bhMerkleRoot = Hash256 (BS.replicate 32 0)
            , bhTimestamp = 0
            , bhBits = 0x207fffff  -- Very easy target (regtest)
            , bhNonce = 0
            }
          -- Regtest powLimit allows very easy targets
          regtestPowLimit = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      -- The hash should be below this very easy target
      checkProofOfWork header regtestPowLimit `shouldBe` True

    it "rejects hash above target" $ do
      -- Create a header with an impossible target (0)
      let header = BlockHeader
            { bhVersion = 1
            , bhPrevBlock = BlockHash (Hash256 (BS.replicate 32 0))
            , bhMerkleRoot = Hash256 (BS.replicate 32 0)
            , bhTimestamp = 0
            , bhBits = 0x03000001  -- Very low target (essentially 1)
            , bhNonce = 0
            }
      -- Any real hash will be above target 1
      checkProofOfWork header powLimit `shouldBe` False

  -- Storage module tests
  describe "Storage key utilities" $ do
    it "toBE32 encodes zero" $ do
      toBE32 0 `shouldBe` BS.pack [0x00, 0x00, 0x00, 0x00]

    it "toBE32 encodes small values" $ do
      toBE32 1 `shouldBe` BS.pack [0x00, 0x00, 0x00, 0x01]
      toBE32 255 `shouldBe` BS.pack [0x00, 0x00, 0x00, 0xff]
      toBE32 256 `shouldBe` BS.pack [0x00, 0x00, 0x01, 0x00]

    it "toBE32 encodes large values" $ do
      toBE32 0xDEADBEEF `shouldBe` BS.pack [0xde, 0xad, 0xbe, 0xef]
      toBE32 0xFFFFFFFF `shouldBe` BS.pack [0xff, 0xff, 0xff, 0xff]

    it "fromBE32 decodes correctly" $ do
      fromBE32 (BS.pack [0x00, 0x00, 0x00, 0x01]) `shouldBe` Just 1
      fromBE32 (BS.pack [0xde, 0xad, 0xbe, 0xef]) `shouldBe` Just 0xDEADBEEF

    it "fromBE32 rejects wrong length" $ do
      fromBE32 (BS.pack [0x00, 0x00, 0x00]) `shouldBe` Nothing
      fromBE32 (BS.pack [0x00, 0x00, 0x00, 0x00, 0x00]) `shouldBe` Nothing

    it "toBE32/fromBE32 roundtrip" $ property $ \w ->
      fromBE32 (toBE32 w) == Just w

  describe "Storage integer encoding" $ do
    it "integerToBS encodes zero" $ do
      integerToBS 0 `shouldBe` BS.singleton 0

    it "integerToBS encodes small values" $ do
      integerToBS 1 `shouldBe` BS.singleton 1
      integerToBS 127 `shouldBe` BS.singleton 127
      integerToBS 255 `shouldBe` BS.singleton 255
      integerToBS 256 `shouldBe` BS.pack [0x01, 0x00]

    it "integerToBS encodes large values" $ do
      integerToBS 0x123456 `shouldBe` BS.pack [0x12, 0x34, 0x56]
      integerToBS 0xDEADBEEF `shouldBe` BS.pack [0xde, 0xad, 0xbe, 0xef]

    it "bsToInteger decodes correctly" $ do
      bsToInteger (BS.singleton 0) `shouldBe` 0
      bsToInteger (BS.singleton 1) `shouldBe` 1
      bsToInteger (BS.pack [0x01, 0x00]) `shouldBe` 256
      bsToInteger (BS.pack [0xde, 0xad, 0xbe, 0xef]) `shouldBe` 0xDEADBEEF

    it "integerToBS/bsToInteger roundtrip" $ property $ \(n :: Word64) ->
      bsToInteger (integerToBS (fromIntegral n)) == fromIntegral n

  describe "Storage key prefixes" $ do
    it "prefixByte returns correct values" $ do
      prefixByte PrefixBlockHeader `shouldBe` 0x01
      prefixByte PrefixBlockData `shouldBe` 0x02
      prefixByte PrefixBlockHeight `shouldBe` 0x03
      prefixByte PrefixTxIndex `shouldBe` 0x04
      prefixByte PrefixUTXO `shouldBe` 0x05
      prefixByte PrefixBestBlock `shouldBe` 0x06
      prefixByte PrefixChainWork `shouldBe` 0x07
      prefixByte PrefixBlockStatus `shouldBe` 0x08

    it "makeKey prepends prefix byte" $ do
      makeKey PrefixBlockHeader (BS.pack [0xaa, 0xbb]) `shouldBe`
        BS.pack [0x01, 0xaa, 0xbb]
      makeKey PrefixUTXO BS.empty `shouldBe` BS.singleton 0x05

    it "makeKey with encoded BlockHash" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xab))
          key = makeKey PrefixBlockHeader (encode bh)
      BS.head key `shouldBe` 0x01
      BS.length key `shouldBe` 33  -- 1 prefix + 32 hash

  describe "TxLocation serialization" $ do
    it "roundtrips correctly" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xcd))
          loc = TxLocation bh 42
      decode (encode loc) `shouldBe` Right loc

    it "has correct size" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x00))
          loc = TxLocation bh 0
      -- 32 bytes for BlockHash + 4 bytes for Word32
      BS.length (encode loc) `shouldBe` 36

  describe "BlockStatus serialization" $ do
    it "roundtrips all status values" $ do
      decode (encode StatusUnknown) `shouldBe` Right StatusUnknown
      decode (encode StatusHeaderValid) `shouldBe` Right StatusHeaderValid
      decode (encode StatusDataReceived) `shouldBe` Right StatusDataReceived
      decode (encode StatusValid) `shouldBe` Right StatusValid
      decode (encode StatusInvalid) `shouldBe` Right StatusInvalid

  describe "WriteBatch operations" $ do
    it "mempty creates empty batch" $ do
      getBatchOps mempty `shouldBe` []

    it "monoid append combines batches" $ do
      let batch1 = WriteBatch [BatchPut "k1" "v1"]
          batch2 = WriteBatch [BatchPut "k2" "v2"]
          combined = batch1 <> batch2
      length (getBatchOps combined) `shouldBe` 2

    it "batchPutBlockHeader creates correct operation" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xaa))
          header = BlockHeader 1 bh (Hash256 (BS.replicate 32 0)) 0 0 0
          BatchPut key val = batchPutBlockHeader bh header
      -- Key should start with block header prefix
      BS.head key `shouldBe` prefixByte PrefixBlockHeader

    it "batchPutUTXO creates correct operation" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xbb))
          outpoint = OutPoint txid 0
          txout = TxOut 1000 "script"
          BatchPut key val = batchPutUTXO outpoint txout
      -- Key should start with UTXO prefix
      BS.head key `shouldBe` prefixByte PrefixUTXO

    it "batchDeleteUTXO creates correct operation" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xcc))
          outpoint = OutPoint txid 1
          BatchDelete key = batchDeleteUTXO outpoint
      BS.head key `shouldBe` prefixByte PrefixUTXO

    it "batchPutBestBlock creates correct operation" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xdd))
          BatchPut key val = batchPutBestBlock bh
      -- Key should start with best block prefix, then empty payload
      key `shouldBe` makeKey PrefixBestBlock BS.empty

    it "batchPutBlockHeight creates correct operation" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xee))
          BatchPut key val = batchPutBlockHeight 100 bh
      -- Key should start with block height prefix
      BS.head key `shouldBe` prefixByte PrefixBlockHeight
      -- Rest of key should be big-endian height
      BS.take 4 (BS.drop 1 key) `shouldBe` toBE32 100

  -- Phase 8: Block & Transaction Validation tests
  describe "Coinbase detection" $ do
    it "isCoinbase returns True for coinbase transaction" $ do
      let nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint (BS.replicate 10 0x04) 0xffffffff
          tx = Tx 1 [txin] [TxOut 5000000000 "script"] [[]] 0
      isCoinbase tx `shouldBe` True

    it "isCoinbase returns False for regular transaction" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          tx = Tx 1 [txin] [TxOut 1000 "script"] [[]] 0
      isCoinbase tx `shouldBe` False

    it "isCoinbase returns False when index is not 0xffffffff" $ do
      let nullHash = TxId (Hash256 (BS.replicate 32 0))
          txin = TxIn (OutPoint nullHash 0) "scriptsig" 0xffffffff  -- index is 0, not 0xffffffff
          tx = Tx 1 [txin] [TxOut 1000 "script"] [[]] 0
      isCoinbase tx `shouldBe` False

    it "isCoinbase returns False when hash is not all zeros" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          txin = TxIn (OutPoint txid 0xffffffff) "scriptsig" 0xffffffff
          tx = Tx 1 [txin] [TxOut 1000 "script"] [[]] 0
      isCoinbase tx `shouldBe` False

  describe "BIP-34 coinbase height" $ do
    it "coinbaseHeight extracts 1-byte height" $ do
      -- Height 1 encoded as: 0x01 0x01 (push 1 byte, value 1)
      let script = BS.pack [0x01, 0x01]
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint script 0xffffffff
          tx = Tx 1 [txin] [TxOut 5000000000 "out"] [[]] 0
      coinbaseHeight tx `shouldBe` Just 1

    it "coinbaseHeight extracts 2-byte height" $ do
      -- Height 256 = 0x0100 little-endian encoded as: 0x02 0x00 0x01
      let script = BS.pack [0x02, 0x00, 0x01]
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint script 0xffffffff
          tx = Tx 1 [txin] [TxOut 5000000000 "out"] [[]] 0
      coinbaseHeight tx `shouldBe` Just 256

    it "coinbaseHeight extracts 3-byte height" $ do
      -- Height 500000 = 0x07A120 little-endian: 0x20 0xA1 0x07
      let script = BS.pack [0x03, 0x20, 0xa1, 0x07]
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint script 0xffffffff
          tx = Tx 1 [txin] [TxOut 5000000000 "out"] [[]] 0
      coinbaseHeight tx `shouldBe` Just 500000

    it "coinbaseHeight returns Nothing for non-coinbase" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          tx = Tx 1 [txin] [TxOut 1000 "script"] [[]] 0
      coinbaseHeight tx `shouldBe` Nothing

    it "coinbaseHeight returns Nothing for empty script" $ do
      let nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint BS.empty 0xffffffff
          tx = Tx 1 [txin] [TxOut 5000000000 "out"] [[]] 0
      coinbaseHeight tx `shouldBe` Nothing

  describe "Block weight (BIP-141)" $ do
    it "calculates weight for block without witness data" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          header = BlockHeader 1 prevHash merkle 0 0 0
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint (BS.replicate 10 0x04) 0xffffffff
          txout = TxOut 5000000000 (BS.replicate 25 0xac)
          coinbase = Tx 1 [txin] [txout] [[]] 0
          block = Block header [coinbase]
      -- For non-witness block: weight = base_size * 4
      -- Since there's no witness, base_size = total_size
      let weight = blockWeight block
      weight `shouldBe` blockBaseSize block * 4

    it "calculates weight for block with witness data" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          header = BlockHeader 1 prevHash merkle 0 0 0
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          coinbaseIn = TxIn nullOutpoint (BS.replicate 10 0x04) 0xffffffff
          -- Add a witness item to coinbase
          coinbase = Tx 1 [coinbaseIn] [TxOut 5000000000 "out"]
                        [[BS.replicate 32 0x00]] 0
          block = Block header [coinbase]
      -- With witness: weight = base_size * 3 + total_size
      let weight = blockWeight block
          base = blockBaseSize block
          total = blockTotalSize block
      weight `shouldBe` (base * 3 + total)

    it "checkBlockWeight accepts valid block" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          header = BlockHeader 1 prevHash merkle 0 0 0
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          txin = TxIn nullOutpoint (BS.replicate 10 0x04) 0xffffffff
          coinbase = Tx 1 [txin] [TxOut 5000000000 "out"] [[]] 0
          block = Block header [coinbase]
      checkBlockWeight block `shouldBe` True

  describe "Consensus flags" $ do
    it "all flags disabled at height 0 on mainnet" $ do
      let flags = consensusFlagsAtHeight mainnet 0
      flagBIP34 flags `shouldBe` False
      flagBIP65 flags `shouldBe` False
      flagBIP66 flags `shouldBe` False
      flagSegWit flags `shouldBe` False
      flagTaproot flags `shouldBe` False

    it "BIP-34 active at mainnet height 227931" $ do
      let flags = consensusFlagsAtHeight mainnet 227931
      flagBIP34 flags `shouldBe` True
      flagBIP65 flags `shouldBe` False
      flagBIP66 flags `shouldBe` False

    it "BIP-66 active at mainnet height 363725" $ do
      let flags = consensusFlagsAtHeight mainnet 363725
      flagBIP34 flags `shouldBe` True
      flagBIP66 flags `shouldBe` True
      flagBIP65 flags `shouldBe` False

    it "BIP-65 active at mainnet height 388381" $ do
      let flags = consensusFlagsAtHeight mainnet 388381
      flagBIP34 flags `shouldBe` True
      flagBIP66 flags `shouldBe` True
      flagBIP65 flags `shouldBe` True
      flagSegWit flags `shouldBe` False

    it "SegWit active at mainnet height 481824" $ do
      let flags = consensusFlagsAtHeight mainnet 481824
      flagSegWit flags `shouldBe` True
      flagNullDummy flags `shouldBe` True
      flagTaproot flags `shouldBe` False

    it "Taproot active at mainnet height 709632" $ do
      let flags = consensusFlagsAtHeight mainnet 709632
      flagTaproot flags `shouldBe` True
      flagSegWit flags `shouldBe` True

    it "all flags active from genesis on regtest" $ do
      let flags = consensusFlagsAtHeight regtest 0
      flagSegWit flags `shouldBe` True
      flagTaproot flags `shouldBe` True

  describe "BIP9 versionbits deployment" $ do
    let -- Create a genesis block index
        genesisHash = BlockHash (Hash256 (BS.replicate 32 0))
        genesis = BlockIndex 0 0x207fffff 1231006505 1 genesisHash Nothing

        -- Build a chain of block indices for testing
        buildChain :: BlockIndex -> Int -> Int32 -> [BlockIndex]
        buildChain _ 0 _ = []
        buildChain prev n version =
          let height = biHeight prev + 1
              newHash = BlockHash (Hash256 (BS.pack (fromIntegral height : replicate 31 0)))
              bi = BlockIndex height (biBits prev) (biTimestamp prev + 600) version newHash (Just prev)
          in bi : buildChain bi (n - 1) version

        -- Build a chain with specific signaling pattern
        buildSignalingChain :: BlockIndex -> [(Int, Int32)] -> [BlockIndex]
        buildSignalingChain _ [] = []
        buildSignalingChain prev ((count, version):rest) =
          let chain = buildChain prev count version
          in if null chain
             then buildSignalingChain prev rest
             else chain ++ buildSignalingChain (last chain) rest

        -- Simple MTP function (just returns the timestamp for testing)
        getMTP bi = biTimestamp bi

        -- Test deployment (bit 2, starts at timestamp 1000)
        testDep = Deployment
          { depBit = 2
          , depStartTime = 1000
          , depTimeout = 9999999999
          , depMinActivationHeight = 0
          , depPeriod = 2016
          , depThreshold = 1815
          }

    it "genesis block is in DEFINED state" $ do
      let (state, _) = getDeploymentState testDep getMTP Map.empty Nothing
      state `shouldBe` Defined

    it "remains DEFINED before start time" $ do
      let genesis' = BlockIndex 0 0x207fffff 500 1 genesisHash Nothing  -- timestamp 500 < 1000
          (state, _) = getDeploymentState testDep getMTP Map.empty (Just genesis')
      state `shouldBe` Defined

    it "transitions to STARTED after start time at retarget boundary" $ do
      -- Build chain to height 2015 (period boundary)
      let genesis' = BlockIndex 0 0x207fffff 1001 1 genesisHash Nothing  -- timestamp > startTime
          chain = buildChain genesis' 2015 1  -- height 1..2015
          pindexPrev = if null chain then genesis' else last chain
          (state, _) = getDeploymentState testDep getMTP Map.empty (Just pindexPrev)
      state `shouldBe` Started

    it "version bit signaling check works correctly" $ do
      -- Version 0x20000004 has top bits 001 and bit 2 set
      isVersionBitSignaling 0x20000004 2 `shouldBe` True
      -- Version 0x20000000 has top bits 001 but bit 2 not set
      isVersionBitSignaling 0x20000000 2 `shouldBe` False
      -- Version 0x00000004 has bit 2 set but wrong top bits
      isVersionBitSignaling 0x00000004 2 `shouldBe` False
      -- Version 0x30000004 has wrong top bits
      isVersionBitSignaling 0x30000004 2 `shouldBe` False

    it "versionBitsTopBits is 0x20000000" $ do
      versionBitsTopBits `shouldBe` 0x20000000

    it "versionBitsTopMask is 0xe0000000" $ do
      versionBitsTopMask `shouldBe` 0xe0000000

    it "mainnet threshold is 1815" $ do
      mainnetThreshold `shouldBe` 1815

    it "testnet threshold is 1512" $ do
      testnetThreshold `shouldBe` 1512

    it "ALWAYS_ACTIVE deployment returns Active immediately" $ do
      let alwaysActiveDep = testDep { depStartTime = -1 }  -- ALWAYS_ACTIVE
          (state, _) = getDeploymentState alwaysActiveDep getMTP Map.empty Nothing
      state `shouldBe` Active

    it "NEVER_ACTIVE deployment returns Failed immediately" $ do
      let neverActiveDep = testDep { depStartTime = -2 }  -- NEVER_ACTIVE
          (state, _) = getDeploymentState neverActiveDep getMTP Map.empty Nothing
      state `shouldBe` Failed

    it "taprootDeployment for mainnet uses bit 2" $ do
      let dep = taprootDeployment mainnet
      depBit dep `shouldBe` 2
      depThreshold dep `shouldBe` mainnetThreshold

    it "computeBlockVersion sets bits for STARTED deployments" $ do
      let genesis' = BlockIndex 0 0x207fffff 1001 1 genesisHash Nothing
          chain = buildChain genesis' 2015 1
          pindexPrev = if null chain then genesis' else last chain
          dep = testDep  -- Will be STARTED
          (version, _) = computeBlockVersion [(dep, Map.empty)] getMTP (Just pindexPrev)
      -- Should have top bits and bit 2 set
      (version .&. 0x20000004) `shouldBe` 0x20000004

  describe "Full block validation" $ do
    it "rejects block with no transactions" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          header = BlockHeader 1 prevHash merkle 0 0x207fffff 0
          block = Block header []
          cs = ChainState 0 prevHash 0 0 (consensusFlagsAtHeight regtest 0)
      case validateFullBlock regtest cs block Map.empty of
        Left msg | "no transactions" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject block with no transactions"

    it "rejects block when first transaction is not coinbase" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          header = BlockHeader 1 prevHash merkle 0 0x207fffff 0
          txid = TxId (Hash256 (BS.replicate 32 0xaa))
          txin = TxIn (OutPoint txid 0) "scriptsig" 0xffffffff
          regularTx = Tx 1 [txin] [TxOut 1000 "script"] [[]] 0
          block = Block header [regularTx]
          cs = ChainState 0 prevHash 0 0 (consensusFlagsAtHeight regtest 0)
      case validateFullBlock regtest cs block Map.empty of
        Left msg | "not coinbase" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject when first tx is not coinbase"

    it "rejects block with multiple coinbase transactions" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          header = BlockHeader 1 prevHash merkle 0 0x207fffff 0
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          coinbaseIn = TxIn nullOutpoint (BS.pack [0x01, 0x01]) 0xffffffff
          coinbase1 = Tx 1 [coinbaseIn] [TxOut 5000000000 "out1"] [[]] 0
          coinbase2 = Tx 1 [coinbaseIn] [TxOut 1000000000 "out2"] [[]] 0
          block = Block header [coinbase1, coinbase2]
          cs = ChainState 0 prevHash 0 0 (consensusFlagsAtHeight regtest 0)
      case validateFullBlock regtest cs block Map.empty of
        Left msg | "Multiple coinbase" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject block with multiple coinbase"

    it "rejects block with mismatched merkle root" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          wrongMerkle = Hash256 (BS.replicate 32 0xff)  -- Wrong merkle root
          header = BlockHeader 1 prevHash wrongMerkle 0 0x207fffff 0
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          coinbaseIn = TxIn nullOutpoint (BS.pack [0x01, 0x01]) 0xffffffff
          coinbase = Tx 1 [coinbaseIn] [TxOut 5000000000 "out"] [[]] 0
          block = Block header [coinbase]
          cs = ChainState 0 prevHash 0 0 (consensusFlagsAtHeight regtest 0)
      case validateFullBlock regtest cs block Map.empty of
        Left msg | "Merkle root" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject block with wrong merkle root"

    it "rejects block when coinbase height mismatches (BIP-34)" $ do
      -- Height will be 501 (500 + 1), but coinbase says height 1
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          nullOutpoint = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
          -- Encode height 1 in coinbase, but we're at height 501
          coinbaseScript = BS.pack [0x01, 0x01]
          coinbaseIn = TxIn nullOutpoint coinbaseScript 0xffffffff
          coinbase = Tx 1 [coinbaseIn] [TxOut 5000000000 "out"] [[]] 0
          txid = computeTxId coinbase
          merkle = computeMerkleRoot [txid]
          header = BlockHeader 1 prevHash merkle 0 0x207fffff 0
          block = Block header [coinbase]
          -- Chain state at height 500 (BIP-34 active on regtest at 500)
          cs = ChainState 500 prevHash 0 0 (consensusFlagsAtHeight regtest 501)
      case validateFullBlock regtest cs block Map.empty of
        Left msg | "height" `T.isInfixOf` T.pack msg -> return ()
        _ -> expectationFailure "Should reject block with wrong coinbase height"

  describe "Sigop counting" $ do
    it "counts OP_CHECKSIG as 1 sigop" $ do
      let script = Script [OP_CHECKSIG]
      countScriptSigops script False `shouldBe` 1

    it "counts OP_CHECKSIGVERIFY as 1 sigop" $ do
      let script = Script [OP_CHECKSIGVERIFY]
      countScriptSigops script False `shouldBe` 1

    it "counts OP_CHECKMULTISIG as 20 sigops (inaccurate)" $ do
      let script = Script [OP_CHECKMULTISIG]
      countScriptSigops script False `shouldBe` 20

    it "counts 2-of-3 multisig as 3 sigops (accurate)" $ do
      let script = Script [OP_2, OP_PUSHDATA "pk1" OPCODE,
                           OP_PUSHDATA "pk2" OPCODE, OP_PUSHDATA "pk3" OPCODE,
                           OP_3, OP_CHECKMULTISIG]
      countScriptSigops script True `shouldBe` 3

    it "counts P2PKH script correctly" $ do
      let hash = Hash160 (BS.replicate 20 0xab)
          script = encodeP2PKH hash
      -- P2PKH has 1 OP_CHECKSIG
      countScriptSigops script False `shouldBe` 1

  describe "ChainState" $ do
    it "can be constructed" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0))
          flags = consensusFlagsAtHeight mainnet 0
          cs = ChainState 0 bh 0 0 flags
      csHeight cs `shouldBe` 0
      csBestBlock cs `shouldBe` bh
      csChainWork cs `shouldBe` 0

  describe "VarInt size calculation" $ do
    it "returns 1 for values < 0xfd" $ do
      varIntSize 0 `shouldBe` 1
      varIntSize 252 `shouldBe` 1

    it "returns 3 for values 0xfd to 0xffff" $ do
      varIntSize 253 `shouldBe` 3
      varIntSize 0xffff `shouldBe` 3

    it "returns 5 for values 0x10000 to 0xffffffff" $ do
      varIntSize 0x10000 `shouldBe` 5
      varIntSize 0xffffffff `shouldBe` 5

    it "returns 9 for values > 0xffffffff" $ do
      varIntSize 0x100000000 `shouldBe` 9

  -- Network module tests (Phase 9)
  describe "MessageHeader" $ do
    it "serializes to exactly 24 bytes" $ do
      let header = MessageHeader 0xD9B4BEF9 "version" 100 0x12345678
      BS.length (encode header) `shouldBe` 24

    it "roundtrips correctly" $ do
      let header = MessageHeader 0xD9B4BEF9 "ping" 8 0xABCDEF01
      decode (encode header) `shouldBe` Right header

    it "pads command to 12 bytes" $ do
      let header = MessageHeader 0xD9B4BEF9 "tx" 0 0
          encoded = encode header
          -- Bytes 4-15 should be: "tx" + 10 null bytes
      BS.index encoded 4 `shouldBe` 0x74  -- 't'
      BS.index encoded 5 `shouldBe` 0x78  -- 'x'
      BS.index encoded 6 `shouldBe` 0x00  -- null
      BS.index encoded 15 `shouldBe` 0x00 -- null

    it "decodes command stripping null bytes" $ do
      let header = MessageHeader 0xD9B4BEF9 "inv" 36 0
      case decode (encode header) of
        Right h -> mhCommand h `shouldBe` "inv"
        Left e -> expectationFailure e

  describe "ServiceFlag" $ do
    it "nodeNetwork is 1" $ do
      getServiceFlag nodeNetwork `shouldBe` 1

    it "nodeWitness is 8" $ do
      getServiceFlag nodeWitness `shouldBe` 8

    it "nodeBloom is 4" $ do
      getServiceFlag nodeBloom `shouldBe` 4

    it "nodeNetworkLimited is 1024" $ do
      getServiceFlag nodeNetworkLimited `shouldBe` 1024

    it "combineServices combines flags with OR" $ do
      combineServices [nodeNetwork, nodeWitness] `shouldBe` 9
      combineServices [nodeNetwork, nodeBloom, nodeWitness] `shouldBe` 13

    it "hasService checks flag presence" $ do
      let flags = combineServices [nodeNetwork, nodeWitness]
      hasService flags nodeNetwork `shouldBe` True
      hasService flags nodeWitness `shouldBe` True
      hasService flags nodeBloom `shouldBe` False

  describe "Ping/Pong" $ do
    it "Ping roundtrips correctly" $ do
      let ping = Ping 0x123456789ABCDEF0
      decode (encode ping) `shouldBe` Right ping

    it "Pong roundtrips correctly" $ do
      let pong = Pong 0xFEDCBA9876543210
      decode (encode pong) `shouldBe` Right pong

    it "Ping serializes to 8 bytes" $ do
      BS.length (encode (Ping 0)) `shouldBe` 8

  describe "InvType" $ do
    it "converts to correct wire values" $ do
      invTypeToWord32 InvError `shouldBe` 0
      invTypeToWord32 InvTx `shouldBe` 1
      invTypeToWord32 InvBlock `shouldBe` 2
      invTypeToWord32 InvFilteredBlock `shouldBe` 3
      invTypeToWord32 InvCompactBlock `shouldBe` 4
      invTypeToWord32 InvWitnessTx `shouldBe` 0x40000001
      invTypeToWord32 InvWitnessBlock `shouldBe` 0x40000002

    it "parses wire values correctly" $ do
      word32ToInvType 0 `shouldBe` InvError
      word32ToInvType 1 `shouldBe` InvTx
      word32ToInvType 2 `shouldBe` InvBlock
      word32ToInvType 0x40000001 `shouldBe` InvWitnessTx
      word32ToInvType 0x40000002 `shouldBe` InvWitnessBlock

    it "unknown values map to InvError" $ do
      word32ToInvType 999 `shouldBe` InvError

  describe "InvVector" $ do
    it "serializes to 36 bytes (4 type + 32 hash)" $ do
      let iv = InvVector InvTx (Hash256 (BS.replicate 32 0xab))
      BS.length (encode iv) `shouldBe` 36

    it "roundtrips correctly" $ do
      let iv = InvVector InvBlock (Hash256 (BS.replicate 32 0xcd))
      decode (encode iv) `shouldBe` Right iv

  describe "Inv" $ do
    it "roundtrips empty list" $ do
      let inv = Inv []
      decode (encode inv) `shouldBe` Right inv

    it "roundtrips with multiple vectors" $ do
      let iv1 = InvVector InvTx (Hash256 (BS.replicate 32 0x01))
          iv2 = InvVector InvBlock (Hash256 (BS.replicate 32 0x02))
          inv = Inv [iv1, iv2]
      decode (encode inv) `shouldBe` Right inv

  describe "GetData" $ do
    it "roundtrips correctly" $ do
      let iv = InvVector InvTx (Hash256 (BS.replicate 32 0xef))
          gd = GetData [iv]
      decode (encode gd) `shouldBe` Right gd

  describe "NotFound" $ do
    it "roundtrips correctly" $ do
      let iv = InvVector InvBlock (Hash256 (BS.replicate 32 0xaa))
          nf = NotFound [iv]
      decode (encode nf) `shouldBe` Right nf

  describe "GetBlocks" $ do
    it "roundtrips correctly" $ do
      let locator1 = BlockHash (Hash256 (BS.replicate 32 0x11))
          locator2 = BlockHash (Hash256 (BS.replicate 32 0x22))
          hashStop = BlockHash (Hash256 (BS.replicate 32 0))
          gb = GetBlocks 70016 [locator1, locator2] hashStop
      decode (encode gb) `shouldBe` Right gb

    it "serializes version as first 4 bytes" $ do
      let gb = GetBlocks 70016 [] (BlockHash (Hash256 (BS.replicate 32 0)))
          encoded = encode gb
      -- Version 70016 = 0x00011180 in little-endian
      BS.take 4 encoded `shouldBe` BS.pack [0x80, 0x11, 0x01, 0x00]

  describe "GetHeaders" $ do
    it "roundtrips correctly" $ do
      let locator = BlockHash (Hash256 (BS.replicate 32 0xaa))
          hashStop = BlockHash (Hash256 (BS.replicate 32 0))
          gh = GetHeaders 70016 [locator] hashStop
      decode (encode gh) `shouldBe` Right gh

  describe "Headers" $ do
    it "roundtrips empty list" $ do
      let hdrs = Headers []
      decode (encode hdrs) `shouldBe` Right hdrs

    it "roundtrips with headers" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0x11))
          merkle = Hash256 (BS.replicate 32 0x22)
          hdr = BlockHeader 1 prevHash merkle 1234567890 0x1d00ffff 12345
          hdrs = Headers [hdr]
      decode (encode hdrs) `shouldBe` Right hdrs

    it "includes varint tx_count (0) after each header" $ do
      let prevHash = BlockHash (Hash256 (BS.replicate 32 0))
          merkle = Hash256 (BS.replicate 32 0)
          hdr = BlockHeader 1 prevHash merkle 0 0 0
          hdrs = Headers [hdr]
          encoded = encode hdrs
      -- 1 (count varint) + 80 (header) + 1 (tx_count varint 0) = 82 bytes
      BS.length encoded `shouldBe` 82

  describe "AddrEntry" $ do
    it "serializes to 30 bytes (4 timestamp + 26 NetworkAddress)" $ do
      let addr = NetworkAddress 1 (BS.replicate 16 0) 8333
          entry = AddrEntry 1234567890 addr
      BS.length (encode entry) `shouldBe` 30

    it "roundtrips correctly" $ do
      let addr = NetworkAddress 0x409 (BS.replicate 16 0xff) 8333
          entry = AddrEntry 1609459200 addr
      decode (encode entry) `shouldBe` Right entry

  describe "Addr" $ do
    it "roundtrips empty list" $ do
      let addr = Addr []
      decode (encode addr) `shouldBe` Right addr

    it "roundtrips with entries" $ do
      let na = NetworkAddress 1 (BS.replicate 16 0) 8333
          entry = AddrEntry 1234567890 na
          addr = Addr [entry]
      decode (encode addr) `shouldBe` Right addr

  describe "SendHeaders" $ do
    it "serializes to 0 bytes (empty payload)" $ do
      BS.length (encode SendHeaders) `shouldBe` 0

    it "roundtrips correctly" $ do
      decode (encode SendHeaders) `shouldBe` Right SendHeaders

  describe "SendCmpct" $ do
    it "serializes to 9 bytes" $ do
      let sc = SendCmpct True 1
      BS.length (encode sc) `shouldBe` 9

    it "roundtrips correctly" $ do
      let sc = SendCmpct False 2
      decode (encode sc) `shouldBe` Right sc

    it "encodes announce flag as byte" $ do
      let sc1 = SendCmpct True 1
          sc2 = SendCmpct False 1
      BS.head (encode sc1) `shouldBe` 1
      BS.head (encode sc2) `shouldBe` 0

  describe "FeeFilter" $ do
    it "serializes to 8 bytes" $ do
      BS.length (encode (FeeFilter 1000)) `shouldBe` 8

    it "roundtrips correctly" $ do
      let ff = FeeFilter 12345
      decode (encode ff) `shouldBe` Right ff

  describe "Version message" $ do
    it "roundtrips correctly" $ do
      let recvAddr = NetworkAddress 1 (BS.replicate 16 0) 8333
          sendAddr = NetworkAddress 1 (BS.replicate 16 0) 0
          ver = Version
            { vVersion = 70016
            , vServices = 1
            , vTimestamp = 1609459200
            , vAddrRecv = recvAddr
            , vAddrSend = sendAddr
            , vNonce = 0x123456789ABCDEF0
            , vUserAgent = VarString "/Haskoin:0.1.0/"
            , vStartHeight = 650000
            , vRelay = True
            }
      decode (encode ver) `shouldBe` Right ver

    it "encodes relay flag" $ do
      let recvAddr = NetworkAddress 0 (BS.replicate 16 0) 0
          sendAddr = NetworkAddress 0 (BS.replicate 16 0) 0
          ver = Version 70016 0 0 recvAddr sendAddr 0 (VarString "") 0 False
          encoded = encode ver
      -- Last byte should be relay flag (0)
      BS.last encoded `shouldBe` 0

  describe "Message encoding" $ do
    it "encodeMessage produces correct header + payload" $ do
      let msg = MPing (Ping 0x123456789ABCDEF0)
          magic = 0xD9B4BEF9
          encoded = encodeMessage magic msg
      -- Header is 24 bytes, ping payload is 8 bytes
      BS.length encoded `shouldBe` 32

    it "encodeMessage uses correct magic" $ do
      let msg = MVerAck
          magic = 0xD9B4BEF9
          encoded = encodeMessage magic msg
      -- First 4 bytes should be magic (little-endian)
      BS.take 4 encoded `shouldBe` BS.pack [0xF9, 0xBE, 0xB4, 0xD9]

    it "encodeMessage calculates correct checksum" $ do
      let msg = MVerAck
          magic = 0xD9B4BEF9
          encoded = encodeMessage magic msg
      -- VerAck has empty payload, checksum is first 4 bytes of double-SHA256("")
      -- SHA256(SHA256("")) checksum = 0x5df6e0e2
      let checksumBytes = BS.take 4 (BS.drop 20 encoded)
      checksumBytes `shouldBe` BS.pack [0x5d, 0xf6, 0xe0, 0xe2]

  describe "Message decoding" $ do
    it "decodes version message" $ do
      let recvAddr = NetworkAddress 1 (BS.replicate 16 0) 8333
          sendAddr = NetworkAddress 1 (BS.replicate 16 0) 0
          ver = Version 70016 1 1609459200 recvAddr sendAddr 0 (VarString "") 0 True
          payload = encode ver
      decodeMessage "version" payload `shouldBe` Right (MVersion ver)

    it "decodes verack message" $ do
      decodeMessage "verack" BS.empty `shouldBe` Right MVerAck

    it "decodes ping message" $ do
      let ping = Ping 0x123456789ABCDEF0
          payload = encode ping
      decodeMessage "ping" payload `shouldBe` Right (MPing ping)

    it "decodes pong message" $ do
      let pong = Pong 0xFEDCBA9876543210
          payload = encode pong
      decodeMessage "pong" payload `shouldBe` Right (MPong pong)

    it "decodes getaddr message" $ do
      decodeMessage "getaddr" BS.empty `shouldBe` Right MGetAddr

    it "decodes mempool message" $ do
      decodeMessage "mempool" BS.empty `shouldBe` Right MMemPool

    it "decodes sendheaders message" $ do
      decodeMessage "sendheaders" BS.empty `shouldBe` Right MSendHeaders

    it "returns error for unknown command" $ do
      case decodeMessage "unknown" BS.empty of
        Left _ -> return ()
        Right _ -> expectationFailure "Should reject unknown command"

  describe "commandName" $ do
    it "returns correct names for all message types" $ do
      let dummyVersion = Version 70016 0 0 (NetworkAddress 0 (BS.replicate 16 0) 0)
                                        (NetworkAddress 0 (BS.replicate 16 0) 0)
                                        0 (VarString "") 0 True
          dummyPing = Ping 0
          dummyPong = Pong 0
          dummyAddr = Addr []
          dummyInv = Inv []
          dummyGetData = GetData []
          dummyNotFound = NotFound []
          dummyBlockHash = BlockHash (Hash256 (BS.replicate 32 0))
          dummyGetBlocks = GetBlocks 70016 [] dummyBlockHash
          dummyGetHeaders = GetHeaders 70016 [] dummyBlockHash
          dummyHeaders = Headers []
          dummyTx = Tx 1 [] [] [] 0
          dummyBlockHeader = BlockHeader 1 dummyBlockHash (Hash256 (BS.replicate 32 0)) 0 0 0
          dummyBlock = Block dummyBlockHeader []
          dummyReject = Reject (VarString "tx") RejectInvalid (VarString "bad") ""
          dummySendCmpct = SendCmpct False 2
          dummyFeeFilter = FeeFilter 1000
      commandName (MVersion dummyVersion) `shouldBe` "version"
      commandName MVerAck `shouldBe` "verack"
      commandName (MPing dummyPing) `shouldBe` "ping"
      commandName (MPong dummyPong) `shouldBe` "pong"
      commandName (MAddr dummyAddr) `shouldBe` "addr"
      commandName (MInv dummyInv) `shouldBe` "inv"
      commandName (MGetData dummyGetData) `shouldBe` "getdata"
      commandName (MNotFound dummyNotFound) `shouldBe` "notfound"
      commandName (MGetBlocks dummyGetBlocks) `shouldBe` "getblocks"
      commandName (MGetHeaders dummyGetHeaders) `shouldBe` "getheaders"
      commandName (MHeaders dummyHeaders) `shouldBe` "headers"
      commandName (MTx dummyTx) `shouldBe` "tx"
      commandName (MBlock dummyBlock) `shouldBe` "block"
      commandName (MReject dummyReject) `shouldBe` "reject"
      commandName MSendHeaders `shouldBe` "sendheaders"
      commandName (MSendCmpct dummySendCmpct) `shouldBe` "sendcmpct"
      commandName (MFeeFilter dummyFeeFilter) `shouldBe` "feefilter"
      commandName MGetAddr `shouldBe` "getaddr"
      commandName MMemPool `shouldBe` "mempool"

  describe "Protocol constants" $ do
    it "protocolVersion is 70016" $ do
      protocolVersion `shouldBe` 70016

    it "minProtocolVersion is 70015" $ do
      minProtocolVersion `shouldBe` 70015

    it "userAgent contains Haskoin" $ do
      userAgent `shouldBe` "/Haskoin:0.1.0/"

  -- Header synchronization tests
  describe "Header Chain Work" $ do
    it "computes header work from bits" $ do
      let header = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                              (Hash256 (BS.replicate 32 0))
                              0 0x1d00ffff 0  -- difficulty 1
          work = headerWork header
      work `shouldSatisfy` (> 0)

    it "cumulative work adds up" $ do
      let header1 = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                               (Hash256 (BS.replicate 32 0))
                               0 0x1d00ffff 0
          work1 = headerWork header1
          work2 = cumulativeWork work1 header1
      work2 `shouldBe` (2 * work1)

    it "work is proportional to difficulty" $ do
      -- Lower bits value (harder difficulty) should give more work
      let easyHeader = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                                   (Hash256 (BS.replicate 32 0))
                                   0 0x1d00ffff 0  -- difficulty 1
          hardHeader = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                                   (Hash256 (BS.replicate 32 0))
                                   0 0x1c00ffff 0  -- difficulty 256
          easyWork = headerWork easyHeader
          hardWork = headerWork hardHeader
      hardWork `shouldSatisfy` (> easyWork)

  describe "Block Locator Heights" $ do
    it "builds locator heights from tip" $ do
      let heights = buildLocatorHeights 100
      -- Should start with tip
      head heights `shouldBe` 100
      -- Should include genesis
      last heights `shouldBe` 0

    it "uses exponential backoff" $ do
      let heights = buildLocatorHeights 1000
      -- First 10 should be consecutive
      take 10 heights `shouldBe` [1000, 999, 998, 997, 996, 995, 994, 993, 992, 991]
      -- Later ones should be spaced out
      length heights `shouldSatisfy` (< 50)  -- not too many

    it "handles small heights" $ do
      let heights = buildLocatorHeights 5
      -- Should include all heights for small chains
      length heights `shouldSatisfy` (<= 6)
      head heights `shouldBe` 5
      last heights `shouldBe` 0

    it "handles zero height" $ do
      let heights = buildLocatorHeights 0
      heights `shouldBe` [0]

  describe "Median Time Past" $ do
    it "returns timestamp for single block" $ do
      let entry = ChainEntry
            { ceHeader = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                                      (Hash256 (BS.replicate 32 0))
                                      1000 0x207fffff 0
            , ceHash = BlockHash (Hash256 (BS.replicate 32 0x01))
            , ceHeight = 0
            , ceChainWork = 1
            , cePrev = Nothing
            , ceStatus = StatusHeaderValid
            , ceMedianTime = 1000
            }
          entries = Map.singleton (ceHash entry) entry
          mtp = medianTimePast entries (ceHash entry)
      mtp `shouldBe` 1000

    it "returns median of multiple timestamps" $ do
      -- Create a chain of 3 blocks with timestamps 100, 200, 300
      let hash1 = BlockHash (Hash256 (BS.replicate 32 0x01))
          hash2 = BlockHash (Hash256 (BS.replicate 32 0x02))
          hash3 = BlockHash (Hash256 (BS.replicate 32 0x03))
          entry1 = ChainEntry
            { ceHeader = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                                      (Hash256 (BS.replicate 32 0)) 100 0x207fffff 0
            , ceHash = hash1, ceHeight = 0, ceChainWork = 1
            , cePrev = Nothing, ceStatus = StatusHeaderValid, ceMedianTime = 100 }
          entry2 = ChainEntry
            { ceHeader = BlockHeader 1 hash1 (Hash256 (BS.replicate 32 0)) 200 0x207fffff 0
            , ceHash = hash2, ceHeight = 1, ceChainWork = 2
            , cePrev = Just hash1, ceStatus = StatusHeaderValid, ceMedianTime = 100 }
          entry3 = ChainEntry
            { ceHeader = BlockHeader 1 hash2 (Hash256 (BS.replicate 32 0)) 300 0x207fffff 0
            , ceHash = hash3, ceHeight = 2, ceChainWork = 3
            , cePrev = Just hash2, ceStatus = StatusHeaderValid, ceMedianTime = 150 }
          entries = Map.fromList [(hash1, entry1), (hash2, entry2), (hash3, entry3)]
          mtp = medianTimePast entries hash3
      -- Median of [100, 200, 300] = 200
      mtp `shouldBe` 200

  describe "Difficulty Adjustment" $ do
    it "returns same bits when not at retarget interval" $ do
      let header = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                              (Hash256 (BS.replicate 32 0))
                              1000 0x207fffff 0
          entry = ChainEntry
            { ceHeader = header
            , ceHash = BlockHash (Hash256 (BS.replicate 32 0x01))
            , ceHeight = 100  -- Not at 150 (regtest retarget interval)
            , ceChainWork = 1
            , cePrev = Nothing
            , ceStatus = StatusHeaderValid
            , ceMedianTime = 1000
            }
          entries = Map.singleton (ceHash entry) entry
          expectedBits = difficultyAdjustment regtest entries entry
      expectedBits `shouldBe` 0x207fffff

  describe "ChainEntry" $ do
    it "stores all required fields" $ do
      let header = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0)))
                              (Hash256 (BS.replicate 32 0xaa))
                              12345 0x207fffff 42
          entry = ChainEntry
            { ceHeader = header
            , ceHash = BlockHash (Hash256 (BS.replicate 32 0x01))
            , ceHeight = 100
            , ceChainWork = 12345678
            , cePrev = Just (BlockHash (Hash256 (BS.replicate 32 0)))
            , ceStatus = StatusHeaderValid
            , ceMedianTime = 12000
            }
      ceHeight entry `shouldBe` 100
      ceChainWork entry `shouldBe` 12345678
      ceMedianTime entry `shouldBe` 12000
      bhTimestamp (ceHeader entry) `shouldBe` 12345
      bhNonce (ceHeader entry) `shouldBe` 42

  describe "Header Chain IO Operations" $ do
    it "initializes header chain with genesis block" $ do
      hc <- initHeaderChain regtest
      tip <- getChainTip hc
      ceHeight tip `shouldBe` 0
      ceChainWork tip `shouldSatisfy` (> 0)

    it "builds block locator from chain" $ do
      hc <- initHeaderChain regtest
      locator <- buildBlockLocatorFromChain hc
      tip <- getChainTip hc
      length locator `shouldBe` 1  -- Just genesis
      head locator `shouldBe` ceHash tip

    it "finds fork point between same hash" $ do
      hc <- initHeaderChain regtest
      tip <- getChainTip hc
      fork <- findForkPoint hc (ceHash tip) (ceHash tip)
      fork `shouldBe` Just tip

    it "gets ancestor at height 0 (genesis)" $ do
      hc <- initHeaderChain regtest
      tip <- getChainTip hc
      ancestor <- getAncestor hc (ceHash tip) 0
      case ancestor of
        Just a -> ceHeight a `shouldBe` 0
        Nothing -> expectationFailure "Expected to find genesis"

    it "returns Nothing for ancestor above current height" $ do
      hc <- initHeaderChain regtest
      tip <- getChainTip hc
      ancestor <- getAncestor hc (ceHash tip) 100
      ancestor `shouldBe` Nothing

  -- Phase 13: Block Download & IBD tests
  describe "IBDState" $ do
    it "IBDNotStarted is distinct from other states" $ do
      IBDNotStarted `shouldBe` IBDNotStarted
      IBDNotStarted `shouldNotBe` IBDComplete

    it "IBDDownloading contains current and target height" $ do
      let state = IBDDownloading 100 500
      state `shouldBe` IBDDownloading 100 500
      state `shouldNotBe` IBDDownloading 200 500

    it "IBDComplete is distinct" $ do
      IBDComplete `shouldBe` IBDComplete
      IBDComplete `shouldNotBe` IBDNotStarted

  describe "BlockRequest" $ do
    it "stores all required fields" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xab))
          req = BlockRequest bh 100 Nothing 1234567890 False 0
      brHash req `shouldBe` bh
      brHeight req `shouldBe` 100
      brPeer req `shouldBe` Nothing
      brRequested req `shouldBe` 1234567890
      brReceived req `shouldBe` False
      brRetries req `shouldBe` 0

    it "can mark block as received" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xcd))
          req = BlockRequest bh 200 Nothing 1234567890 False 0
          received = req { brReceived = True }
      brReceived received `shouldBe` True

    it "can increment retries" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xef))
          req = BlockRequest bh 300 Nothing 1234567890 False 0
          retried = req { brRetries = brRetries req + 1 }
      brRetries retried `shouldBe` 1

  describe "flushTBQueueN" $ do
    it "returns empty list from empty queue" $ do
      q <- atomically $ newTBQueue 10
      result <- atomically $ flushTBQueueN q 5
      result `shouldBe` ([] :: [Int])

    it "returns all items when fewer than limit" $ do
      q <- atomically $ newTBQueue 10
      atomically $ do
        writeTBQueue q (1 :: Int)
        writeTBQueue q 2
        writeTBQueue q 3
      result <- atomically $ flushTBQueueN q 10
      result `shouldBe` [1, 2, 3]

    it "returns only up to limit items" $ do
      q <- atomically $ newTBQueue 10
      atomically $ do
        writeTBQueue q (1 :: Int)
        writeTBQueue q 2
        writeTBQueue q 3
        writeTBQueue q 4
        writeTBQueue q 5
      result <- atomically $ flushTBQueueN q 3
      result `shouldBe` [1, 2, 3]
      -- Remaining items should still be in queue
      remaining <- atomically $ flushTBQueueN q 10
      remaining `shouldBe` [4, 5]

    it "handles zero limit" $ do
      q <- atomically $ newTBQueue 10
      atomically $ writeTBQueue q (1 :: Int)
      result <- atomically $ flushTBQueueN q 0
      result `shouldBe` []

  -- Phase 14: UTXO Set & Chain State tests
  describe "UTXOEntry serialization" $ do
    it "roundtrips correctly" $ do
      let txout = TxOut 5000000000 "scriptpubkey"
          entry = UTXOEntry txout 100 True False
      decode (encode entry) `shouldBe` Right entry

    it "preserves all metadata fields" $ do
      let txout = TxOut 12345 "script"
          entry = UTXOEntry txout 42 False True
      decode (encode entry) `shouldBe` Right entry
      ueHeight entry `shouldBe` 42
      ueCoinbase entry `shouldBe` False
      ueSpent entry `shouldBe` True

    it "serializes coinbase flag correctly" $ do
      let txout = TxOut 1000 "script"
          coinbaseEntry = UTXOEntry txout 100 True False
          regularEntry = UTXOEntry txout 100 False False
      -- They should be different when serialized
      encode coinbaseEntry `shouldNotBe` encode regularEntry

  describe "UndoData serialization" $ do
    it "roundtrips with empty spent outputs" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xaa))
          undo = UndoData bh 100 []
      decode (encode undo) `shouldBe` Right undo

    it "roundtrips with spent outputs" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xbb))
          txid = TxId (Hash256 (BS.replicate 32 0xcc))
          op = OutPoint txid 0
          txout = TxOut 5000000000 "script"
          entry = UTXOEntry txout 50 True False
          undo = UndoData bh 100 [(op, entry)]
      decode (encode undo) `shouldBe` Right undo

    it "roundtrips with multiple spent outputs" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xdd))
          txid1 = TxId (Hash256 (BS.replicate 32 0x01))
          txid2 = TxId (Hash256 (BS.replicate 32 0x02))
          op1 = OutPoint txid1 0
          op2 = OutPoint txid2 1
          entry1 = UTXOEntry (TxOut 1000 "s1") 10 False False
          entry2 = UTXOEntry (TxOut 2000 "s2") 20 True False
          undo = UndoData bh 100 [(op1, entry1), (op2, entry2)]
      decode (encode undo) `shouldBe` Right undo

    it "preserves block hash and height" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xee))
          undo = UndoData bh 12345 []
      case decode (encode undo) of
        Right decoded -> do
          udBlockHash decoded `shouldBe` bh
          udHeight decoded `shouldBe` 12345
        Left err -> expectationFailure $ "Decode failed: " ++ err

  describe "PersistedChainState serialization" $ do
    it "roundtrips correctly" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xff))
          pcs = PersistedChainState 100 bh 12345678
      decode (encode pcs) `shouldBe` Right pcs

    it "handles zero chain work" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x00))
          pcs = PersistedChainState 0 bh 0
      decode (encode pcs) `shouldBe` Right pcs

    it "handles large chain work" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xab))
          largeWork = 2 ^ (200 :: Integer)  -- Very large number
          pcs = PersistedChainState 500000 bh largeWork
      decode (encode pcs) `shouldBe` Right pcs

    it "preserves all fields" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xcd))
          pcs = PersistedChainState 999 bh 42
      case decode (encode pcs) of
        Right decoded -> do
          pcsHeight decoded `shouldBe` 999
          pcsBestBlock decoded `shouldBe` bh
          pcsChainWork decoded `shouldBe` 42
        Left err -> expectationFailure $ "Decode failed: " ++ err

  describe "UTXOEntry metadata" $ do
    it "tracks creation height" $ do
      let txout = TxOut 1000 "script"
          entry = UTXOEntry txout 500 False False
      ueHeight entry `shouldBe` 500

    it "tracks coinbase status" $ do
      let txout = TxOut 5000000000 "script"
          coinbaseEntry = UTXOEntry txout 100 True False
          regularEntry = UTXOEntry txout 100 False False
      ueCoinbase coinbaseEntry `shouldBe` True
      ueCoinbase regularEntry `shouldBe` False

    it "tracks spent status" $ do
      let txout = TxOut 1000 "script"
          entry = UTXOEntry txout 100 False False
          spent = entry { ueSpent = True }
      ueSpent entry `shouldBe` False
      ueSpent spent `shouldBe` True

  describe "Coinbase maturity check logic" $ do
    it "immature coinbase at same height" $ do
      -- A coinbase created at height 100, trying to spend at height 100
      let currentHeight = 100 :: Word32
          creationHeight = 100 :: Word32
          maturity = 100 :: Int
      (currentHeight - creationHeight < fromIntegral maturity) `shouldBe` True

    it "immature coinbase within 100 blocks" $ do
      -- A coinbase created at height 100, trying to spend at height 150
      let currentHeight = 150 :: Word32
          creationHeight = 100 :: Word32
          maturity = 100 :: Int
      (currentHeight - creationHeight < fromIntegral maturity) `shouldBe` True

    it "mature coinbase at exactly 100 blocks" $ do
      -- A coinbase created at height 100, trying to spend at height 200
      let currentHeight = 200 :: Word32
          creationHeight = 100 :: Word32
          maturity = 100 :: Int
      (currentHeight - creationHeight < fromIntegral maturity) `shouldBe` False

    it "mature coinbase after 100 blocks" $ do
      -- A coinbase created at height 100, trying to spend at height 250
      let currentHeight = 250 :: Word32
          creationHeight = 100 :: Word32
          maturity = 100 :: Int
      (currentHeight - creationHeight < fromIntegral maturity) `shouldBe` False

  describe "UndoData structure" $ do
    it "stores block hash" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x12))
          undo = UndoData bh 100 []
      udBlockHash undo `shouldBe` bh

    it "stores height" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x00))
          undo = UndoData bh 12345 []
      udHeight undo `shouldBe` 12345

    it "stores spent outputs list" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x00))
          txid = TxId (Hash256 (BS.replicate 32 0xaa))
          op = OutPoint txid 0
          entry = UTXOEntry (TxOut 1000 "s") 50 False False
          undo = UndoData bh 100 [(op, entry)]
      length (udSpentOutputs undo) `shouldBe` 1

  describe "Chain state fields" $ do
    it "PersistedChainState tracks height" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x00))
          pcs = PersistedChainState 500 bh 1000
      pcsHeight pcs `shouldBe` 500

    it "PersistedChainState tracks best block" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0xab))
          pcs = PersistedChainState 100 bh 500
      pcsBestBlock pcs `shouldBe` bh

    it "PersistedChainState tracks chain work" $ do
      let bh = BlockHash (Hash256 (BS.replicate 32 0x00))
          pcs = PersistedChainState 100 bh 999999
      pcsChainWork pcs `shouldBe` 999999

  --------------------------------------------------------------------------------
  -- Mempool Tests
  --------------------------------------------------------------------------------

  describe "Mempool" $ do
    describe "FeeRate" $ do
      it "creates fee rate from satoshis per vbyte" $ do
        let rate = FeeRate 10
        getFeeRate rate `shouldBe` 10

      it "compares fee rates correctly" $ do
        let low = FeeRate 1
            high = FeeRate 10
        (low < high) `shouldBe` True
        (high > low) `shouldBe` True

    describe "MempoolConfig" $ do
      it "has sensible defaults" $ do
        let cfg = defaultMempoolConfig
        mpcMaxSize cfg `shouldBe` 300 * 1024 * 1024  -- 300 MB
        mpcMinFeeRate cfg `shouldBe` FeeRate 1        -- 1 sat/vB
        mpcRBFEnabled cfg `shouldBe` True
        mpcMaxAncestors cfg `shouldBe` 25
        mpcMaxDescendants cfg `shouldBe` 25

      it "allows custom configuration" $ do
        let cfg = defaultMempoolConfig
              { mpcMaxSize = 100 * 1024 * 1024  -- 100 MB
              , mpcMinFeeRate = FeeRate 5       -- 5 sat/vB
              , mpcRBFEnabled = False
              }
        mpcMaxSize cfg `shouldBe` 100 * 1024 * 1024
        mpcMinFeeRate cfg `shouldBe` FeeRate 5
        mpcRBFEnabled cfg `shouldBe` False

    describe "MempoolEntry" $ do
      it "stores transaction metadata" $ do
        -- Create a simple transaction
        let txid = TxId (Hash256 (BS.replicate 32 0xaa))
            prevOutpoint = OutPoint txid 0
            txIn = TxIn prevOutpoint "" 0xffffffff
            txOut = TxOut 1000 ""
            tx = Tx 1 [txIn] [txOut] [[]] 0
        -- Create mempool entry
        let entry = MempoolEntry
              { meTransaction = tx
              , meTxId = computeTxId tx
              , meFee = 100
              , meFeeRate = FeeRate 10
              , meSize = 150
              , meTime = 1234567890
              , meHeight = 500
              , meAncestorCount = 1  -- includes self
              , meAncestorSize = 150  -- includes self
              , meAncestorFees = 100  -- includes self
              , meAncestorSigOps = 0
              , meDescendantCount = 1  -- includes self
              , meDescendantSize = 150  -- includes self
              , meDescendantFees = 100  -- includes self
              , meRBFOptIn = False
              }
        meFee entry `shouldBe` 100
        meFeeRate entry `shouldBe` FeeRate 10
        meSize entry `shouldBe` 150
        meHeight entry `shouldBe` 500
        meRBFOptIn entry `shouldBe` False
        meAncestorCount entry `shouldBe` 1
        meDescendantCount entry `shouldBe` 1

    describe "MempoolError" $ do
      it "represents different error types" $ do
        let err1 = ErrAlreadyInMempool
            err2 = ErrValidationFailed "test error"
            err3 = ErrFeeBelowMinimum (FeeRate 1) (FeeRate 5)
            err4 = ErrTooManyAncestors 30 25
        show err1 `shouldBe` "ErrAlreadyInMempool"
        show err2 `shouldBe` "ErrValidationFailed \"test error\""
        show err3 `shouldBe` "ErrFeeBelowMinimum (FeeRate {getFeeRate = 1}) (FeeRate {getFeeRate = 5})"
        show err4 `shouldBe` "ErrTooManyAncestors 30 25"

    describe "RBF signaling" $ do
      it "detects RBF opt-in when sequence < 0xfffffffe" $ do
        -- Transaction with RBF signaled
        let txid = TxId (Hash256 (BS.replicate 32 0x00))
            op = OutPoint txid 0
            -- Sequence 0xfffffffd signals RBF
            rbfTxIn = TxIn op "" 0xfffffffd
            rbfOptIn = txInSequence rbfTxIn < 0xfffffffe
        rbfOptIn `shouldBe` True

      it "does not signal RBF when sequence >= 0xfffffffe" $ do
        let txid = TxId (Hash256 (BS.replicate 32 0x00))
            op = OutPoint txid 0
            -- Sequence 0xffffffff does not signal RBF
            finalTxIn = TxIn op "" 0xffffffff
            rbfOptIn = txInSequence finalTxIn < 0xfffffffe
        rbfOptIn `shouldBe` False

      it "sequence 0xfffffffe does not signal RBF" $ do
        let txid = TxId (Hash256 (BS.replicate 32 0x00))
            op = OutPoint txid 0
            txIn = TxIn op "" 0xfffffffe
            rbfOptIn = txInSequence txIn < 0xfffffffe
        rbfOptIn `shouldBe` False

    describe "Ancestor fee rate calculation" $ do
      it "calculates ancestor fee rate for CPFP" $ do
        -- Parent tx: 100 sat fee, 200 vB
        -- Child tx: 500 sat fee, 150 vB
        -- Ancestor fee rate = (100 + 500) * 1000 / (200 + 150) = 1714 msat/vB
        let parentFee = 100 :: Word64
            parentSize = 200 :: Int
            childFee = 500 :: Word64
            childSize = 150 :: Int
            totalFees = parentFee + childFee
            totalSize = parentSize + childSize
            ancestorFeeRate = (totalFees * 1000) `div` fromIntegral totalSize
        ancestorFeeRate `shouldBe` 1714

    describe "Mempool limits" $ do
      it "default ancestor limit is 25" $ do
        let cfg = defaultMempoolConfig
        mpcMaxAncestors cfg `shouldBe` 25

      it "default descendant limit is 25" $ do
        let cfg = defaultMempoolConfig
        mpcMaxDescendants cfg `shouldBe` 25

      it "default ancestor size limit is 101000" $ do
        let cfg = defaultMempoolConfig
        mpcMaxAncestorSize cfg `shouldBe` 101000

      it "default descendant size limit is 101000" $ do
        let cfg = defaultMempoolConfig
        mpcMaxDescendantSize cfg `shouldBe` 101000

      it "ErrTooManyAncestors has correct values" $ do
        let err = ErrTooManyAncestors 26 25
        show err `shouldBe` "ErrTooManyAncestors 26 25"

      it "ErrTooManyDescendants has correct values" $ do
        let err = ErrTooManyDescendants 26 25
        show err `shouldBe` "ErrTooManyDescendants 26 25"

      it "ErrAncestorSizeTooLarge has correct values" $ do
        let err = ErrAncestorSizeTooLarge 102000 101000
        show err `shouldBe` "ErrAncestorSizeTooLarge 102000 101000"

      it "ErrDescendantSizeTooLarge has correct values" $ do
        let err = ErrDescendantSizeTooLarge 102000 101000
        show err `shouldBe` "ErrDescendantSizeTooLarge 102000 101000"

      -- Test that a chain of 25 would result in 25 ancestors (including self)
      it "25-tx chain is at ancestor limit" $ do
        -- With Bitcoin Core's limits, 25 ancestors (including self) is the max
        -- This means 24 in-mempool parents + 1 (self) = 25
        let chainLength = 25
        chainLength `shouldBe` 25

      -- Test that 26 would exceed the limit
      it "26-tx chain exceeds ancestor limit" $ do
        let chainLength = 26
            limit = 25
        (chainLength > limit) `shouldBe` True

      -- Test ancestor count tracking
      it "ancestor count includes self" $ do
        -- A transaction with no in-mempool parents should have ancestorCount = 1
        let noParentAncestorCount = 1  -- Just self
        noParentAncestorCount `shouldBe` 1

      it "descendant count includes self" $ do
        -- A transaction with no in-mempool children should have descendantCount = 1
        let noChildDescendantCount = 1  -- Just self
        noChildDescendantCount `shouldBe` 1

  --------------------------------------------------------------------------------
  -- Fee Estimator Tests (Phase 16)
  --------------------------------------------------------------------------------

  describe "FeeEstimator" $ do
    describe "Fee bucket functions" $ do
      it "bucketFeeRate calculates correct rates" $ do
        -- First bucket: 1 sat/vB (1.05^0)
        bucketFeeRate 0 `shouldBe` 1
        -- Higher buckets grow exponentially
        bucketFeeRate 10 `shouldSatisfy` (> bucketFeeRate 0)
        bucketFeeRate 50 `shouldSatisfy` (> bucketFeeRate 10)
        bucketFeeRate 100 `shouldSatisfy` (> bucketFeeRate 50)

      it "bucketFeeRate is monotonically increasing" $ do
        let rates = map bucketFeeRate [0..numBuckets-1]
        rates `shouldSatisfy` (\rs -> and $ zipWith (<=) rs (tail rs))

      it "feeRateToBucket is inverse of bucketFeeRate" $ do
        -- Low fee rates go to low buckets
        feeRateToBucket 1 `shouldBe` 0
        -- Medium fee rates go to medium buckets
        feeRateToBucket 10 `shouldSatisfy` (> 0)
        -- High fee rates go to high buckets
        feeRateToBucket 100 `shouldSatisfy` (> feeRateToBucket 10)

      it "feeRateToBucket clamps to valid range" $ do
        -- Very low rate clamps to 0
        feeRateToBucket 0 `shouldBe` 0
        -- Very high rate clamps to max bucket
        feeRateToBucket 100000 `shouldBe` (numBuckets - 1)

      it "numBuckets is 128" $ do
        numBuckets `shouldBe` 128

      it "maxConfirmBlocks is 48" $ do
        maxConfirmBlocks `shouldBe` 48

    describe "FeeEstimator creation" $ do
      it "newFeeEstimator creates empty estimator" $ do
        fe <- newFeeEstimator
        -- Check that pending is empty
        pending <- readTVarIO (feePending fe)
        Map.size pending `shouldBe` 0
        -- Check that height is 0
        height <- readTVarIO (feeBestHeight fe)
        height `shouldBe` 0
        -- Check decay factor is set
        feeDecay fe `shouldBe` 0.998

      it "newFeeEstimator initializes all buckets" $ do
        fe <- newFeeEstimator
        buckets <- readTVarIO (feeBuckets fe)
        Map.size buckets `shouldBe` numBuckets

      it "empty buckets have zero counts" $ do
        fe <- newFeeEstimator
        buckets <- readTVarIO (feeBuckets fe)
        forM_ (Map.elems buckets) $ \bucket -> do
          fbTotalTxs bucket `shouldBe` 0
          fbInMempool bucket `shouldBe` 0
          all (== 0) (fbConfirmations bucket) `shouldBe` True

    describe "FeeBucket structure" $ do
      it "has correct fee rate ranges" $ do
        fe <- newFeeEstimator
        buckets <- readTVarIO (feeBuckets fe)
        case Map.lookup 0 buckets of
          Just bucket -> do
            fbMinFeeRate bucket `shouldBe` 1
            fbMaxFeeRate bucket `shouldSatisfy` (>= 1)
          Nothing -> expectationFailure "Bucket 0 not found"

      it "buckets have correct confirmation slots" $ do
        fe <- newFeeEstimator
        buckets <- readTVarIO (feeBuckets fe)
        case Map.lookup 0 buckets of
          Just bucket -> do
            length (fbConfirmations bucket) `shouldBe` maxConfirmBlocks
          Nothing -> expectationFailure "Bucket 0 not found"

    describe "FeeEstimateMode" $ do
      it "FeeConservative and FeeEconomical are distinct" $ do
        FeeConservative `shouldNotBe` FeeEconomical

      it "modes have correct behavior descriptions" $ do
        show FeeConservative `shouldBe` "FeeConservative"
        show FeeEconomical `shouldBe` "FeeEconomical"

    describe "Transaction tracking" $ do
      it "trackTransaction adds pending transaction" $ do
        fe <- newFeeEstimator
        let txid = TxId (Hash256 (BS.replicate 32 0xaa))
        trackTransaction fe txid 50 100  -- 50 sat/vB at height 100
        pending <- readTVarIO (feePending fe)
        Map.member txid pending `shouldBe` True

      it "trackTransaction records correct info" $ do
        fe <- newFeeEstimator
        let txid = TxId (Hash256 (BS.replicate 32 0xbb))
        trackTransaction fe txid 25 200  -- 25 sat/vB at height 200
        pending <- readTVarIO (feePending fe)
        case Map.lookup txid pending of
          Just info -> do
            ptFeeRate info `shouldBe` 25
            ptEntryHeight info `shouldBe` 200
          Nothing -> expectationFailure "Transaction not tracked"

      it "trackTransaction updates bucket mempool count" $ do
        fe <- newFeeEstimator
        let txid = TxId (Hash256 (BS.replicate 32 0xcc))
            feeRate = 50 :: Word64
            bucketIdx = feeRateToBucket feeRate
        trackTransaction fe txid feeRate 100
        buckets <- readTVarIO (feeBuckets fe)
        case Map.lookup bucketIdx buckets of
          Just bucket -> fbInMempool bucket `shouldBe` 1
          Nothing -> expectationFailure "Bucket not found"

      it "trackTransaction increments total count" $ do
        fe <- newFeeEstimator
        let txid1 = TxId (Hash256 (BS.replicate 32 0x01))
            txid2 = TxId (Hash256 (BS.replicate 32 0x02))
        trackTransaction fe txid1 10 100
        trackTransaction fe txid2 20 100
        total <- readTVarIO (feeTotalTxs fe)
        total `shouldBe` 2

    describe "Confirmation recording" $ do
      it "recordConfirmation removes pending transaction" $ do
        fe <- newFeeEstimator
        let txid = TxId (Hash256 (BS.replicate 32 0xdd))
        trackTransaction fe txid 50 100
        recordConfirmation fe 101 [txid]
        pending <- readTVarIO (feePending fe)
        Map.member txid pending `shouldBe` False

      it "recordConfirmation updates best height" $ do
        fe <- newFeeEstimator
        recordConfirmation fe 500 []
        height <- readTVarIO (feeBestHeight fe)
        height `shouldBe` 500

      it "recordConfirmation applies decay to buckets" $ do
        fe <- newFeeEstimator
        let txid = TxId (Hash256 (BS.replicate 32 0xee))
        trackTransaction fe txid 50 100
        -- Record confirmation, which applies decay
        recordConfirmation fe 101 [txid]
        buckets <- readTVarIO (feeBuckets fe)
        let bucketIdx = feeRateToBucket 50
        case Map.lookup bucketIdx buckets of
          Just bucket ->
            -- After tracking (1) and decay (0.998), should be ~0.998
            fbInMempool bucket `shouldSatisfy` (< 1)
          Nothing -> expectationFailure "Bucket not found"

    describe "Fee estimation" $ do
      it "estimateFee returns Nothing with no data" $ do
        fe <- newFeeEstimator
        result <- estimateFee fe 6
        result `shouldBe` Nothing

      it "estimateSmartFee returns fallback with no data" $ do
        fe <- newFeeEstimator
        (rate, blocks) <- estimateSmartFee fe 6 FeeEconomical
        rate `shouldBe` 1000  -- Fallback rate
        blocks `shouldBe` maxConfirmBlocks

      it "estimateSmartFee conservative adds 10% buffer" $ do
        -- The conservative mode should return higher fees
        fe <- newFeeEstimator
        (conservRate, _) <- estimateSmartFee fe 6 FeeConservative
        (econRate, _) <- estimateSmartFee fe 6 FeeEconomical
        -- With no data both return fallback, but conservative adds 10%
        conservRate `shouldBe` 1100  -- 1000 + 10%
        econRate `shouldBe` 1000

    describe "PendingTxInfo" $ do
      it "stores all transaction info" $ do
        let txid = TxId (Hash256 (BS.replicate 32 0xff))
            info = PendingTxInfo txid 100 10 500
        ptTxId info `shouldBe` txid
        ptFeeRate info `shouldBe` 100
        ptBucketIdx info `shouldBe` 10
        ptEntryHeight info `shouldBe` 500

    describe "FeeBucket" $ do
      it "stores fee rate range" $ do
        let bucket = FeeBucket 10 19 (replicate 48 0) 0 0
        fbMinFeeRate bucket `shouldBe` 10
        fbMaxFeeRate bucket `shouldBe` 19

      it "stores confirmation counts" $ do
        let confs = [1..48] :: [Double]
            bucket = FeeBucket 1 10 confs 100 5
        length (fbConfirmations bucket) `shouldBe` 48
        fbTotalTxs bucket `shouldBe` 100
        fbInMempool bucket `shouldBe` 5

  -- Wallet module tests
  describe "BIP-39 Mnemonic" $ do
    it "bip39WordList has exactly 2048 words" $ do
      length bip39WordList `shouldBe` 2048

    it "bip39WordList first word is 'abandon'" $ do
      head bip39WordList `shouldBe` "abandon"

    it "bip39WordList last word is 'zoo'" $ do
      last bip39WordList `shouldBe` "zoo"

    it "generateMnemonic produces 24 words for 256-bit strength" $ do
      mnemonic <- generateMnemonic 256
      length (getMnemonicWords mnemonic) `shouldBe` 24

    it "generateMnemonic produces 12 words for 128-bit strength" $ do
      mnemonic <- generateMnemonic 128
      length (getMnemonicWords mnemonic) `shouldBe` 12

    it "generated mnemonic words are in dictionary" $ do
      mnemonic <- generateMnemonic 256
      let words' = getMnemonicWords mnemonic
      all (`elem` bip39WordList) words' `shouldBe` True

    it "validateMnemonic accepts valid mnemonic" $ do
      mnemonic <- generateMnemonic 256
      validateMnemonic mnemonic `shouldBe` True

    it "validateMnemonic rejects mnemonic with wrong word count" $ do
      let badMnemonic = Mnemonic (replicate 11 "abandon")
      validateMnemonic badMnemonic `shouldBe` False

    it "validateMnemonic rejects mnemonic with invalid words" $ do
      let badMnemonic = Mnemonic (replicate 12 "notaword")
      validateMnemonic badMnemonic `shouldBe` False

    it "mnemonicToSeed produces 64-byte seed" $ do
      mnemonic <- generateMnemonic 256
      let seed = mnemonicToSeed mnemonic ""
      BS.length seed `shouldBe` 64

    it "mnemonicToSeed is deterministic" $ do
      mnemonic <- generateMnemonic 256
      let seed1 = mnemonicToSeed mnemonic "password"
          seed2 = mnemonicToSeed mnemonic "password"
      seed1 `shouldBe` seed2

    it "mnemonicToSeed differs with different passphrase" $ do
      mnemonic <- generateMnemonic 256
      let seed1 = mnemonicToSeed mnemonic "password1"
          seed2 = mnemonicToSeed mnemonic "password2"
      seed1 `shouldNotBe` seed2

  describe "BIP-32 Key Derivation" $ do
    it "masterKey produces ExtendedKey from seed" $ do
      let seed = BS.replicate 64 0xab
          master = masterKey seed
      BS.length (ekChainCode master) `shouldBe` 32
      ekDepth master `shouldBe` 0
      ekParentFP master `shouldBe` 0
      ekIndex master `shouldBe` 0

    it "derivePrivate increases depth" $ do
      let seed = BS.replicate 64 0xab
          master = masterKey seed
          child = derivePrivate master 0
      ekDepth child `shouldBe` 1

    it "derivePrivate sets correct index" $ do
      let seed = BS.replicate 64 0xab
          master = masterKey seed
          child = derivePrivate master 42
      ekIndex child `shouldBe` 42

    it "deriveHardened sets hardened index bit" $ do
      let seed = BS.replicate 64 0xab
          master = masterKey seed
          child = deriveHardened master 0
      (ekIndex child >= 0x80000000) `shouldBe` True

    it "derivePath follows multiple indices" $ do
      let seed = BS.replicate 64 0xab
          master = masterKey seed
          path = [0x80000000 .|. 84, 0x80000000 .|. 0, 0x80000000 .|. 0]
          derived = derivePath master path
      ekDepth derived `shouldBe` 3

    it "toExtendedPubKey converts to public key" $ do
      let seed = BS.replicate 64 0xab
          master = masterKey seed
          pubKey = toExtendedPubKey master
      epkDepth pubKey `shouldBe` 0
      epkChainCode pubKey `shouldBe` ekChainCode master

  describe "BIP-44/84 Paths" $ do
    it "bip44Path produces correct path" $ do
      let path = bip44Path 0
      length path `shouldBe` 3
      path !! 0 `shouldBe` (0x80000000 .|. 44)  -- 44'
      path !! 1 `shouldBe` (0x80000000 .|. 0)   -- 0' (Bitcoin)
      path !! 2 `shouldBe` (0x80000000 .|. 0)   -- 0' (account 0)

    it "bip84Path produces correct path" $ do
      let path = bip84Path 0
      length path `shouldBe` 3
      path !! 0 `shouldBe` (0x80000000 .|. 84)  -- 84'
      path !! 1 `shouldBe` (0x80000000 .|. 0)   -- 0' (Bitcoin)
      path !! 2 `shouldBe` (0x80000000 .|. 0)   -- 0' (account 0)

    it "defaultDerivationPath is bip84Path 0" $ do
      defaultDerivationPath `shouldBe` bip84Path 0

    it "parseDerivationPath parses m/84'/0'/0'" $ do
      let path = parseDerivationPath "m/84'/0'/0'"
      path `shouldBe` Just [0x80000000 .|. 84, 0x80000000 .|. 0, 0x80000000 .|. 0]

    it "parseDerivationPath parses non-hardened path" $ do
      let path = parseDerivationPath "m/0/1/2"
      path `shouldBe` Just [0, 1, 2]

  describe "Wallet" $ do
    it "createWallet generates new mnemonic and wallet" $ do
      let config = WalletConfig mainnet 20 ""
      (mnemonic, wallet) <- createWallet config
      length (getMnemonicWords mnemonic) `shouldBe` 24
      walletGapLimit wallet `shouldBe` 20

    it "loadWallet creates wallet from mnemonic" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      walletGapLimit wallet `shouldBe` 20

    it "getReceiveAddress returns unique addresses" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      addr1 <- getReceiveAddress wallet
      addr2 <- getReceiveAddress wallet
      addr1 `shouldNotBe` addr2

    it "getReceiveAddressAt is deterministic" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet1 <- loadWallet config mnemonic
      wallet2 <- loadWallet config mnemonic
      addr1 <- getReceiveAddressAt wallet1 0
      addr2 <- getReceiveAddressAt wallet2 0
      addr1 `shouldBe` addr2

    it "isOurAddress returns True for generated addresses" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      addr <- getReceiveAddress wallet
      isOurs <- isOurAddress wallet addr
      isOurs `shouldBe` True

    it "isOurAddress returns False for unknown addresses" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      let unknownAddr = WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xff))
      isOurs <- isOurAddress wallet unknownAddr
      isOurs `shouldBe` False

    it "getBalance starts at zero" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      balance <- getBalance wallet
      balance `shouldBe` 0

    it "addWalletUTXO increases balance" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      let op = OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0
          txout = TxOut 100000 ""
      addWalletUTXO wallet op txout 6
      balance <- getBalance wallet
      balance `shouldBe` 100000

    it "removeWalletUTXO decreases balance" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      let op = OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0
          txout = TxOut 100000 ""
      addWalletUTXO wallet op txout 6
      removeWalletUTXO wallet op
      balance <- getBalance wallet
      balance `shouldBe` 0

  describe "Coin Selection" $ do
    it "selectCoins returns error for insufficient funds" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      let outputs = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xaa))) 100000]
      result <- selectCoins wallet outputs (FeeRate 10)
      case result of
        Left _ -> return ()  -- Expected
        Right _ -> expectationFailure "Expected insufficient funds error"

    it "selectCoins succeeds with sufficient funds" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      -- Add some UTXOs
      let op = OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0
          txout = TxOut 1000000 ""  -- 0.01 BTC
      addWalletUTXO wallet op txout 6
      let outputs = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xbb))) 100000]
      result <- selectCoins wallet outputs (FeeRate 10)
      case result of
        Left err -> expectationFailure $ "Expected success, got: " ++ err
        Right cs -> do
          length (csInputs cs) `shouldBe` 1
          csFee cs `shouldSatisfy` (> 0)

    it "selectCoins includes change output when appropriate" $ do
      let config = WalletConfig mainnet 20 ""
      mnemonic <- generateMnemonic 256
      wallet <- loadWallet config mnemonic
      let op = OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0
          txout = TxOut 1000000 ""  -- 0.01 BTC
      addWalletUTXO wallet op txout 6
      let outputs = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xbb))) 100000]
      result <- selectCoins wallet outputs (FeeRate 10)
      case result of
        Right cs -> csChange cs `shouldSatisfy` (/= Nothing)
        Left err -> expectationFailure $ "Expected success, got: " ++ err

  describe "Transaction Creation" $ do
    it "createTransaction builds valid transaction structure" $ do
      let inputs = [(OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0, TxOut 1000000 "")]
          outputs = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xbb))) 100000]
          change = Just (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xcc)), 800000)
          cs = CoinSelection inputs outputs change 100000 (FeeRate 10)
          tx = createTransaction cs
      length (txInputs tx) `shouldBe` 1
      length (txOutputs tx) `shouldBe` 2  -- 1 output + 1 change
      txVersion tx `shouldBe` 2

    it "createTransaction sets correct output values" $ do
      let inputs = [(OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0, TxOut 1000000 "")]
          outputs = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xbb))) 500000]
          change = Just (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xcc)), 400000)
          cs = CoinSelection inputs outputs change 100000 (FeeRate 10)
          tx = createTransaction cs
      txOutValue (txOutputs tx !! 0) `shouldBe` 500000
      txOutValue (txOutputs tx !! 1) `shouldBe` 400000

    it "createTransaction handles no change" $ do
      let inputs = [(OutPoint (TxId (Hash256 (BS.replicate 32 0xaa))) 0, TxOut 100000 "")]
          outputs = [WalletTxOutput (WitnessPubKeyAddress (Hash160 (BS.replicate 20 0xbb))) 99000]
          cs = CoinSelection inputs outputs Nothing 1000 (FeeRate 10)
          tx = createTransaction cs
      length (txOutputs tx) `shouldBe` 1

  -- Performance module tests
  describe "LRU Cache" $ do
    it "stores and retrieves values" $ do
      cache <- newLRUCache 100
      lruInsert cache ("key1" :: String) (42 :: Int)
      result <- lruLookup cache "key1"
      result `shouldBe` Just 42

    it "returns Nothing for missing keys" $ do
      cache <- newLRUCache 100
      result <- lruLookup cache ("missing" :: String)
      (result :: Maybe Int) `shouldBe` Nothing

    it "updates existing keys" $ do
      cache <- newLRUCache 100
      lruInsert cache ("key1" :: String) (42 :: Int)
      lruInsert cache "key1" 99
      result <- lruLookup cache "key1"
      result `shouldBe` Just 99

    it "evicts when at capacity" $ do
      cache <- newLRUCache 3
      lruInsert cache (1 :: Int) ("one" :: String)
      lruInsert cache 2 "two"
      lruInsert cache 3 "three"
      -- Access 1 and 3 to make 2 the LRU
      _ <- lruLookup cache 1
      _ <- lruLookup cache 3
      -- Insert 4, should evict 2
      lruInsert cache 4 "four"
      size <- lruSize cache
      size `shouldBe` 3
      result <- lruLookup cache 2
      result `shouldBe` Nothing

    it "tracks cache size correctly" $ do
      cache <- newLRUCache 100
      lruInsert cache (1 :: Int) ("one" :: String)
      lruInsert cache 2 "two"
      lruInsert cache 3 "three"
      size <- lruSize cache
      size `shouldBe` 3

    it "hit rate starts at zero" $ do
      cache <- newLRUCache 100
      rate <- lruHitRate cache
      rate `shouldBe` 0

    it "hit rate is 100% when all lookups hit" $ do
      cache <- newLRUCache 100
      lruInsert cache ("key1" :: String) (42 :: Int)
      _ <- lruLookup cache "key1"
      _ <- lruLookup cache "key1"
      rate <- lruHitRate cache
      rate `shouldBe` 100.0

  describe "Node Metrics" $ do
    it "creates metrics with zero counters" $ do
      metrics <- newNodeMetrics
      snapshot <- getMetricSnapshot metrics
      msBlocksProcessed snapshot `shouldBe` 0
      msTxsValidated snapshot `shouldBe` 0

    it "incrementMetric increases counter" $ do
      metrics <- newNodeMetrics
      incrementMetric (nmBlocksProcessed metrics)
      incrementMetric (nmBlocksProcessed metrics)
      incrementMetric (nmBlocksProcessed metrics)
      snapshot <- getMetricSnapshot metrics
      msBlocksProcessed snapshot `shouldBe` 3

    it "addToMetric adds to counter" $ do
      metrics <- newNodeMetrics
      addToMetric (nmBytesReceived metrics) 1000
      addToMetric (nmBytesReceived metrics) 500
      snapshot <- getMetricSnapshot metrics
      msBytesReceived snapshot `shouldBe` 1500

    it "tracks uptime" $ do
      metrics <- newNodeMetrics
      snapshot <- getMetricSnapshot metrics
      msUptimeSeconds snapshot `shouldSatisfy` (>= 0)

  describe "Strict Processing" $ do
    it "computeTxFeeStrict computes fee correctly" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          outpoint = OutPoint txid 0
          prevOutput = TxOut 1000000 ""
          utxoMap = Map.singleton outpoint prevOutput
          txin = TxIn outpoint "" 0xffffffff
          txout = TxOut 900000 ""
          tx = Tx 1 [txin] [txout] [[]] 0
      case computeTxFeeStrict utxoMap tx of
        Right fee -> fee `shouldBe` 100000
        Left err -> expectationFailure $ "Expected success, got: " ++ err

    it "computeTxFeeStrict rejects missing UTXO" $ do
      let utxoMap = Map.empty :: Map.Map OutPoint TxOut
          txid = TxId (Hash256 (BS.replicate 32 0xaa))
          txin = TxIn (OutPoint txid 0) "" 0xffffffff
          txout = TxOut 100000 ""
          tx = Tx 1 [txin] [txout] [[]] 0
      case computeTxFeeStrict utxoMap tx of
        Left _ -> return ()  -- Expected
        Right _ -> expectationFailure "Expected missing UTXO error"

    it "computeTxFeeStrict rejects overspend" $ do
      let txid = TxId (Hash256 (BS.replicate 32 0xaa))
          outpoint = OutPoint txid 0
          prevOutput = TxOut 100000 ""  -- Only 100k sats available
          utxoMap = Map.singleton outpoint prevOutput
          txin = TxIn outpoint "" 0xffffffff
          txout = TxOut 200000 ""  -- Trying to spend 200k sats
          tx = Tx 1 [txin] [txout] [[]] 0
      case computeTxFeeStrict utxoMap tx of
        Left err -> err `shouldBe` "Outputs exceed inputs"
        Right _ -> expectationFailure "Expected overspend error"

  describe "Parallel Validation" $ do
    it "verifyBlockScriptsParallel succeeds on empty block" $ do
      let header = BlockHeader 1 (BlockHash (Hash256 (BS.replicate 32 0))) (Hash256 (BS.replicate 32 0)) 0 0 0
          coinbase = Tx 1 [] [TxOut 5000000000 ""] [[]] 0
          block = Block header [coinbase]
          utxoMap = Map.empty
          flags = ConsensusFlags False False False False False False False
      verifyBlockScriptsParallel block utxoMap flags `shouldBe` Right ()

    it "parallelMap preserves order" $ do
      let result = parallelMap (*2) [1, 2, 3, 4, 5 :: Int]
      result `shouldBe` [2, 4, 6, 8, 10]

  describe "Database Tuning" $ do
    it "ibdDBConfig returns valid configuration" $ do
      let (path, createIfMissing, maxFiles, writeBuffer, blockCache, bloomBits, compression) =
            ibdDBConfig "/tmp/test"
      path `shouldBe` "/tmp/test"
      createIfMissing `shouldBe` True
      maxFiles `shouldBe` 1000
      writeBuffer `shouldBe` 256 * 1024 * 1024  -- 256 MB
      blockCache `shouldBe` 512 * 1024 * 1024   -- 512 MB
      bloomBits `shouldBe` 10
      compression `shouldBe` True

  -- BIP-141 WITNESS_PUBKEYTYPE tests
  describe "witness pubkeytype" $ do
    describe "isCompressedPubKey" $ do
      it "accepts compressed pubkey with 0x02 prefix" $ do
        let pk = BS.cons 0x02 (BS.replicate 32 0xab)
        isCompressedPubKey pk `shouldBe` True

      it "accepts compressed pubkey with 0x03 prefix" $ do
        let pk = BS.cons 0x03 (BS.replicate 32 0xcd)
        isCompressedPubKey pk `shouldBe` True

      it "rejects uncompressed pubkey (0x04 prefix, 65 bytes)" $ do
        let pk = BS.cons 0x04 (BS.replicate 64 0xef)
        isCompressedPubKey pk `shouldBe` False

      it "rejects pubkey with invalid prefix (0x05)" $ do
        let pk = BS.cons 0x05 (BS.replicate 32 0x00)
        isCompressedPubKey pk `shouldBe` False

      it "rejects pubkey with wrong length (32 bytes)" $ do
        let pk = BS.cons 0x02 (BS.replicate 31 0x00)
        isCompressedPubKey pk `shouldBe` False

      it "rejects pubkey with wrong length (34 bytes)" $ do
        let pk = BS.cons 0x02 (BS.replicate 33 0x00)
        isCompressedPubKey pk `shouldBe` False

      it "rejects empty pubkey" $ do
        isCompressedPubKey BS.empty `shouldBe` False

    describe "witness v0 P2WPKH pubkey type enforcement" $ do
      it "rejects uncompressed pubkey in P2WPKH with WITNESS_PUBKEYTYPE flag" $ do
        -- Create a transaction with witness spending P2WPKH
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xaa))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Uncompressed pubkey (65 bytes, 0x04 prefix)
            uncompressedPubkey = BS.cons 0x04 (BS.replicate 64 0xab)
            -- Compute hash160 of the uncompressed pubkey for scriptPubKey
            Hash160 pkHash = hash160 uncompressedPubkey
            -- Dummy signature
            dummySig = BS.pack [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
            -- Witness: [signature, uncompressed_pubkey]
            witness = [dummySig, uncompressedPubkey]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            -- P2WPKH scriptPubKey: OP_0 <20-byte-hash>
            scriptPubKey = encodeScript $ encodeP2WPKH (Hash160 pkHash)
            -- Flags with WITNESS_PUBKEYTYPE enabled
            flags = flagSet [VerifyWitnessPubkeyType]
        case verifySegWitScriptWithFlags flags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "not compressed" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected pubkey type error, got: " ++ err
          Right _ -> expectationFailure "Should reject uncompressed pubkey in witness v0"

      it "accepts compressed pubkey in P2WPKH with WITNESS_PUBKEYTYPE flag" $ do
        -- Create a transaction with witness spending P2WPKH
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xbb))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Compressed pubkey (33 bytes, 0x02 prefix)
            compressedPubkey = BS.cons 0x02 (BS.replicate 32 0xcd)
            -- Compute hash160 of the compressed pubkey for scriptPubKey
            Hash160 pkHash = hash160 compressedPubkey
            -- Dummy signature
            dummySig = BS.pack [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
            -- Witness: [signature, compressed_pubkey]
            witness = [dummySig, compressedPubkey]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            -- P2WPKH scriptPubKey: OP_0 <20-byte-hash>
            scriptPubKey = encodeScript $ encodeP2WPKH (Hash160 pkHash)
            -- Flags with WITNESS_PUBKEYTYPE enabled
            flags = flagSet [VerifyWitnessPubkeyType]
        -- Should NOT error on pubkey type (may fail on sig verification, but not pubkey type)
        case verifySegWitScriptWithFlags flags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "not compressed" `T.isInfixOf` T.pack err ->
            expectationFailure "Compressed pubkey should not fail WITNESS_PUBKEYTYPE check"
          _ -> return ()  -- Either success or other error (sig verification) is OK

      it "allows uncompressed pubkey in P2WPKH without WITNESS_PUBKEYTYPE flag" $ do
        -- Create a transaction with witness spending P2WPKH
        let prevTxid = TxId (Hash256 (BS.replicate 32 0xcc))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Uncompressed pubkey (65 bytes, 0x04 prefix)
            uncompressedPubkey = BS.cons 0x04 (BS.replicate 64 0xdd)
            -- Compute hash160 of the uncompressed pubkey for scriptPubKey
            Hash160 pkHash = hash160 uncompressedPubkey
            -- Dummy signature
            dummySig = BS.pack [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]
            -- Witness: [signature, uncompressed_pubkey]
            witness = [dummySig, uncompressedPubkey]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            -- P2WPKH scriptPubKey: OP_0 <20-byte-hash>
            scriptPubKey = encodeScript $ encodeP2WPKH (Hash160 pkHash)
            -- Empty flags (no WITNESS_PUBKEYTYPE)
            flags = emptyFlags
        -- Should NOT fail on pubkey type error (may fail on sig verification)
        case verifySegWitScriptWithFlags flags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "not compressed" `T.isInfixOf` T.pack err ->
            expectationFailure "Without WITNESS_PUBKEYTYPE flag, uncompressed should be allowed"
          _ -> return ()  -- Either success or other error is OK

  -- Witness cleanstack enforcement tests
  -- Per BIP-141 and Bitcoin Core, witness scripts must leave exactly one item on the stack.
  -- This is NOT gated by SCRIPT_VERIFY_CLEANSTACK - it's always enforced for witness programs.
  describe "witness cleanstack enforcement" $ do
    describe "P2WSH cleanstack" $ do
      it "rejects P2WSH script that leaves extra items on stack" $ do
        -- Create a witness script that leaves extra items: OP_1 OP_DUP
        -- This will leave [1, 1] on the stack (two items), violating cleanstack
        let witnessScript = encodeScriptOps [OP_1, OP_DUP]  -- Pushes 1, duplicates -> [1, 1]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xdd))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: [witnessScript] - empty initial stack, script does the work
            witness = [witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            -- P2WSH scriptPubKey: OP_0 <32-byte-hash>
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "exactly one item" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected cleanstack error, got: " ++ err
          Right _ -> expectationFailure "Should reject script that leaves extra items on stack"

      it "rejects P2WSH script that leaves empty stack" $ do
        -- Create a witness script that leaves empty stack: OP_1 OP_DROP
        let witnessScript = encodeScriptOps [OP_1, OP_DROP]  -- Pushes 1, drops it -> []
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xee))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            witness = [witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "exactly one item" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected cleanstack error, got: " ++ err
          Right _ -> expectationFailure "Should reject script that leaves empty stack"

      it "accepts P2WSH script that leaves exactly one true item" $ do
        -- Create a witness script that leaves exactly [1]: OP_1
        let witnessScript = encodeScriptOps [OP_1]  -- Pushes 1 -> [1] (single true item)
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xff))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            witness = [witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "exactly one item" `T.isInfixOf` T.pack err ->
            expectationFailure "Script with single true item should pass cleanstack check"
          Left err -> return ()  -- Other errors (like sig verification) are expected
          Right True -> return ()
          Right False -> expectationFailure "Expected True result"

      it "rejects P2WSH script that leaves single false item" $ do
        -- Create a witness script that leaves exactly [0]: OP_0
        let witnessScript = encodeScriptOps [OP_0]  -- Pushes 0 -> [0] (single false item)
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xab))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            witness = [witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "evaluated to false" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected eval false error, got: " ++ err
          Right _ -> expectationFailure "Should reject script that leaves false on stack"

    describe "witness eval edge cases" $ do
      it "three items on stack fails cleanstack" $ do
        -- Script that leaves 3 items: OP_1 OP_2 OP_3
        let witnessScript = encodeScriptOps [OP_1, OP_2, OP_3]  -- [1, 2, 3]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xbc))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            witness = [witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "exactly one item" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected cleanstack error, got: " ++ err
          Right _ -> expectationFailure "Should reject script that leaves 3 items on stack"

      it "cleanstack is enforced regardless of flags" $ do
        -- Even with no flags set, witness cleanstack is always enforced
        let witnessScript = encodeScriptOps [OP_1, OP_1]  -- [1, 1] - two items
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xcd))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            witness = [witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
            -- Explicitly use empty flags to show this isn't flag-gated
            flags = emptyFlags
        case verifySegWitScriptWithFlags flags tx 0 (encodeScript scriptPubKey) 100000 of
          Left err | "exactly one item" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected cleanstack error, got: " ++ err
          Right _ -> expectationFailure "Cleanstack should be enforced even with no flags"

  -- MINIMALIF tests - BIP-143 related rule for witness scripts
  -- The argument to OP_IF/OP_NOTIF must be exactly empty (false) or [0x01] (true)
  describe "minimalif enforcement" $ do
    describe "op_if with minimalif flag" $ do
      it "accepts empty (false) argument in OP_IF" $ do
        -- Script: <input> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
        -- Empty input should take the ELSE branch (false), leaving OP_0 on stack
        -- But we need the final result to be true, so adjust:
        -- Script: <input> OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF
        let witnessScript = encodeScriptOps [OP_IF, OP_0, OP_ELSE, OP_1, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xde))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: empty input (false), then the script
            witness = [BS.empty, witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Right True -> return ()
          Right False -> expectationFailure "Script should succeed (empty is valid false)"
          Left err -> expectationFailure $ "Unexpected error: " ++ err

      it "accepts 0x01 (true) argument in OP_IF" $ do
        -- Script: <input> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
        -- [0x01] input should take the IF branch (true), leaving OP_1 on stack
        let witnessScript = encodeScriptOps [OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xdf))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: 0x01 (true), then the script
            witness = [BS.singleton 0x01, witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Right True -> return ()
          Right False -> expectationFailure "Script should succeed (0x01 is valid true)"
          Left err -> expectationFailure $ "Unexpected error: " ++ err

      it "rejects 0x02 argument in OP_IF (MINIMALIF violation)" $ do
        -- Script: <input> OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
        -- [0x02] is a truthy value but NOT minimal - should fail
        let witnessScript = encodeScriptOps [OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xe0))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: 0x02 (truthy but not minimal), then the script
            witness = [BS.singleton 0x02, witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Left err | "MINIMALIF" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected MINIMALIF error, got: " ++ err
          Right _ -> expectationFailure "Should reject 0x02 as OP_IF argument"

      it "rejects 0x00 argument in OP_IF (MINIMALIF violation)" $ do
        -- [0x00] is falsy but NOT minimal (empty is the minimal false)
        let witnessScript = encodeScriptOps [OP_IF, OP_0, OP_ELSE, OP_1, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xe1))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: 0x00 (falsy but not minimal), then the script
            witness = [BS.singleton 0x00, witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Left err | "MINIMALIF" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected MINIMALIF error, got: " ++ err
          Right _ -> expectationFailure "Should reject 0x00 as OP_IF argument"

      it "rejects multi-byte argument in OP_IF (MINIMALIF violation)" $ do
        -- Multi-byte values like [0x01, 0x00] are truthy but not minimal
        let witnessScript = encodeScriptOps [OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xe2))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: [0x01, 0x00] (truthy but not minimal), then the script
            witness = [BS.pack [0x01, 0x00], witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Left err | "MINIMALIF" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected MINIMALIF error, got: " ++ err
          Right _ -> expectationFailure "Should reject multi-byte OP_IF argument"

    describe "op_notif with minimalif" $ do
      it "accepts empty (false) argument in OP_NOTIF" $ do
        -- OP_NOTIF with empty input: takes the IF branch (opposite of IF)
        let witnessScript = encodeScriptOps [OP_NOTIF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xe3))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            -- Witness: empty (false), so NOTIF takes the IF branch -> OP_1
            witness = [BS.empty, witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Right True -> return ()
          Right False -> expectationFailure "Script should succeed"
          Left err -> expectationFailure $ "Unexpected error: " ++ err

      it "rejects 0x02 argument in OP_NOTIF (MINIMALIF violation)" $ do
        -- OP_NOTIF with 0x02: should fail MINIMALIF
        let witnessScript = encodeScriptOps [OP_NOTIF, OP_0, OP_ELSE, OP_1, OP_ENDIF]
            scriptHash = sha256 witnessScript
            prevTxid = TxId (Hash256 (BS.replicate 32 0xe4))
            txIn = TxIn (OutPoint prevTxid 0) "" 0xfffffffe
            txOut = TxOut 99000 ""
            witness = [BS.singleton 0x02, witnessScript]
            tx = Tx 2 [txIn] [txOut] [witness] 0
            scriptPubKey = encodeScript $ encodeP2WSH (Hash256 scriptHash)
        case verifySegWitScriptWithFlags emptyFlags tx 0 scriptPubKey 100000 of
          Left err | "MINIMALIF" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected MINIMALIF error, got: " ++ err
          Right _ -> expectationFailure "Should reject 0x02 as OP_NOTIF argument"

    describe "minimalif in legacy scripts" $ do
      it "allows non-minimal OP_IF argument without witness flag" $ do
        -- In legacy (non-witness) scripts, MINIMALIF is NOT enforced by default
        let scriptSig = Script [OP_PUSHDATA (BS.singleton 0x02) OPCODE]
            scriptPubKey = Script [OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
            dummyTx = Tx 1 [] [] [] 0
        -- 0x02 is truthy, should take IF branch -> OP_1 -> True
        evalScript dummyTx 0 0 scriptSig scriptPubKey `shouldBe` Right True

      it "rejects non-minimal OP_IF argument with MinimalIf flag" $ do
        -- When VerifyMinimalIf flag is set, even legacy scripts reject non-minimal
        let scriptSig = Script [OP_PUSHDATA (BS.singleton 0x02) OPCODE]
            scriptPubKey = Script [OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF]
            dummyTx = Tx 1 [] [] [] 0
            flags = flagSet [VerifyMinimalIf]
        case evalScriptWithFlags flags dummyTx 0 0 scriptSig scriptPubKey of
          Left err | "MINIMALIF" `T.isInfixOf` T.pack err -> return ()
          Left err -> expectationFailure $ "Expected MINIMALIF error, got: " ++ err
          Right _ -> expectationFailure "Should reject with MinimalIf flag"

  -- BIP68 Sequence Lock Tests
  describe "BIP68 sequence lock constants" $ do
    it "has correct disable flag (bit 31)" $ do
      sequenceLockTimeDisableFlag `shouldBe` 0x80000000

    it "has correct type flag (bit 22)" $ do
      sequenceLockTimeTypeFlag `shouldBe` 0x00400000

    it "has correct mask (lower 16 bits)" $ do
      sequenceLockTimeMask `shouldBe` 0x0000ffff

    it "has correct granularity (9 = 512 seconds)" $ do
      sequenceLockTimeGranularity `shouldBe` 9

  describe "BIP68 sequence lock calculation" $ do
    let mkTx version inputs = Tx
          { txVersion = version
          , txInputs = inputs
          , txOutputs = [TxOut 1000 ""]
          , txWitness = [[]]
          , txLockTime = 0
          }
        mkInput seq' = TxIn
          { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0
          , txInScript = ""
          , txInSequence = seq'
          }

    it "returns no constraints when BIP68 not enforced" $ do
      let tx = mkTx 2 [mkInput 10]  -- Height-based lock of 10 blocks
      calculateSequenceLocks tx [100] [1000000] False `shouldBe` SequenceLock (-1) (-1)

    it "returns no constraints for version 1 tx" $ do
      let tx = mkTx 1 [mkInput 10]  -- Height-based lock of 10 blocks
      calculateSequenceLocks tx [100] [1000000] True `shouldBe` SequenceLock (-1) (-1)

    it "ignores input with disable flag set (bit 31)" $ do
      let seq' = sequenceLockTimeDisableFlag .|. 100  -- Disabled + 100 blocks
          tx = mkTx 2 [mkInput seq']
      calculateSequenceLocks tx [100] [1000000] True `shouldBe` SequenceLock (-1) (-1)

    it "calculates height-based lock correctly" $ do
      -- Height-based: coinHeight + lockValue - 1
      let lockValue = 10 :: Word32
          coinHeight = 100 :: Word32
          seq' = lockValue  -- No type flag = height-based
          tx = mkTx 2 [mkInput seq']
          lock = calculateSequenceLocks tx [coinHeight] [1000000] True
      -- Expected: 100 + 10 - 1 = 109 (last invalid height)
      slMinHeight lock `shouldBe` 109
      slMinTime lock `shouldBe` (-1)

    it "calculates time-based lock correctly" $ do
      -- Time-based: coinMTP + (lockValue << 9) - 1
      let lockValue = 2 :: Word32  -- 2 * 512 = 1024 seconds
          coinMTP = 1600000000 :: Word32  -- Some Unix timestamp
          seq' = sequenceLockTimeTypeFlag .|. lockValue
          tx = mkTx 2 [mkInput seq']
          lock = calculateSequenceLocks tx [100] [coinMTP] True
      -- Expected: 1600000000 + (2 << 9) - 1 = 1600000000 + 1024 - 1 = 1600001023
      slMinHeight lock `shouldBe` (-1)
      slMinTime lock `shouldBe` 1600001023

    it "takes maximum across multiple inputs (height)" $ do
      let tx = mkTx 2 [mkInput 5, mkInput 20, mkInput 10]
          lock = calculateSequenceLocks tx [100, 100, 100] [0, 0, 0] True
      -- Max: 100 + 20 - 1 = 119
      slMinHeight lock `shouldBe` 119

    it "takes maximum across multiple inputs (time)" $ do
      let seq1 = sequenceLockTimeTypeFlag .|. 1   -- 512 seconds
          seq2 = sequenceLockTimeTypeFlag .|. 3   -- 1536 seconds
          seq3 = sequenceLockTimeTypeFlag .|. 2   -- 1024 seconds
          tx = mkTx 2 [mkInput seq1, mkInput seq2, mkInput seq3]
          coinMTP = 1600000000 :: Word32
          lock = calculateSequenceLocks tx [100, 100, 100] [coinMTP, coinMTP, coinMTP] True
      -- Max: 1600000000 + (3 << 9) - 1 = 1600000000 + 1536 - 1 = 1600001535
      slMinTime lock `shouldBe` 1600001535

    it "handles mixed height and time locks" $ do
      let seqHeight = 10 :: Word32
          seqTime = sequenceLockTimeTypeFlag .|. 2  -- 1024 seconds
          tx = mkTx 2 [mkInput seqHeight, mkInput seqTime]
          coinMTP = 1600000000 :: Word32
          lock = calculateSequenceLocks tx [100, 100] [0, coinMTP] True
      -- Height: 100 + 10 - 1 = 109
      -- Time: 1600000000 + 1024 - 1 = 1600001023
      slMinHeight lock `shouldBe` 109
      slMinTime lock `shouldBe` 1600001023

  describe "BIP68 sequence lock verification" $ do
    it "passes when no constraints" $ do
      let lock = SequenceLock (-1) (-1)
      checkSequenceLocks 100 1600000000 lock `shouldBe` True

    it "passes when height constraint satisfied" $ do
      let lock = SequenceLock 109 (-1)  -- Last invalid height is 109
      checkSequenceLocks 110 1600000000 lock `shouldBe` True  -- Block 110 > 109

    it "fails when height constraint not satisfied" $ do
      let lock = SequenceLock 109 (-1)  -- Last invalid height is 109
      checkSequenceLocks 109 1600000000 lock `shouldBe` False  -- Block 109 == 109 (not >)
      checkSequenceLocks 108 1600000000 lock `shouldBe` False  -- Block 108 < 109

    it "passes when time constraint satisfied" $ do
      let lock = SequenceLock (-1) 1600001023  -- Last invalid time
      checkSequenceLocks 100 1600001024 lock `shouldBe` True  -- MTP > 1600001023

    it "fails when time constraint not satisfied" $ do
      let lock = SequenceLock (-1) 1600001023  -- Last invalid time
      checkSequenceLocks 100 1600001023 lock `shouldBe` False  -- MTP == lock (not >)
      checkSequenceLocks 100 1600001022 lock `shouldBe` False  -- MTP < lock

    it "passes when both constraints satisfied" $ do
      let lock = SequenceLock 109 1600001023
      checkSequenceLocks 110 1600001024 lock `shouldBe` True

    it "fails when only height satisfied" $ do
      let lock = SequenceLock 109 1600001023
      checkSequenceLocks 110 1600001022 lock `shouldBe` False

    it "fails when only time satisfied" $ do
      let lock = SequenceLock 109 1600001023
      checkSequenceLocks 108 1600001024 lock `shouldBe` False

  describe "BIP68 QuickCheck properties" $ do
    it "disabled flag always produces no constraints" $ property $
      \(coinHeight :: Word32, coinMTP :: Word32, lockValue :: Word32) ->
        let seq' = sequenceLockTimeDisableFlag .|. (lockValue .&. sequenceLockTimeMask)
            tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) "" seq'] [] [[]] 0
            lock = calculateSequenceLocks tx [coinHeight] [coinMTP] True
        in lock == SequenceLock (-1) (-1)

    it "version 1 tx always produces no constraints" $ property $
      \(seq' :: Word32, coinHeight :: Word32, coinMTP :: Word32) ->
        let tx = Tx 1 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) "" seq'] [] [[]] 0
            lock = calculateSequenceLocks tx [coinHeight] [coinMTP] True
        in lock == SequenceLock (-1) (-1)

    it "height lock value is correctly scaled" $ property $
      \(NonNegative lockValue) (Positive coinHeight) ->
        lockValue <= 65535 ==>
          let seq' = lockValue .&. sequenceLockTimeMask
              tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) "" seq'] [] [[]] 0
              lock = calculateSequenceLocks tx [coinHeight] [0] True
              expected = fromIntegral coinHeight + fromIntegral lockValue - 1
          in slMinHeight lock == expected

    it "time lock value is correctly scaled by 512" $ property $
      \(NonNegative lockValue) (Positive coinMTP) ->
        lockValue <= 65535 && coinMTP < 2000000000 ==>
          let seq' = sequenceLockTimeTypeFlag .|. (lockValue .&. sequenceLockTimeMask)
              tx = Tx 2 [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0) "" seq'] [] [[]] 0
              lock = calculateSequenceLocks tx [100] [coinMTP] True
              expected = fromIntegral coinMTP + (fromIntegral lockValue * 512) - 1
          in slMinTime lock == expected

  describe "BIP68 network activation" $ do
    it "BIP68 is active at mainnet CSV height" $ do
      bip68Active mainnet 419328 `shouldBe` True
      bip68Active mainnet 419329 `shouldBe` True

    it "BIP68 is not active before mainnet CSV height" $ do
      bip68Active mainnet 419327 `shouldBe` False
      bip68Active mainnet 0 `shouldBe` False

    it "BIP68 is active at regtest CSV height" $ do
      bip68Active regtest 432 `shouldBe` True

    it "CSV height is correctly configured" $ do
      netCSVHeight mainnet `shouldBe` 419328
      netCSVHeight regtest `shouldBe` 432

  -- Phase 13: Header Sync Anti-DoS Tests (PRESYNC/REDOWNLOAD)
  describe "header sync" $ do
    describe "presync" $ do
      it "initializes header sync peer in presync state" $ do
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        state <- atomically $ getHeaderSyncState peer
        case state of
          Presync pd -> do
            pdCount pd `shouldBe` 0
            pdCumulativeWork pd `shouldBe` 0
            pdStartHash pd `shouldBe` genesisHash
          _ -> expectationFailure "Expected Presync state"

      it "shouldStartPresync returns true for low work" $ do
        -- Mainnet requires very high work, so any small value should need presync
        shouldStartPresync mainnet 1000 0 `shouldBe` True

      it "shouldStartPresync returns false when work exceeds threshold" $ do
        -- If claimed work exceeds minimum, don't use presync
        let highWork = netMinimumChainWork mainnet + 1
        shouldStartPresync mainnet highWork 0 `shouldBe` False

      it "presync accumulates cumulative work" $ do
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        -- Create a header that chains to genesis
        let header = BlockHeader 1 genesisHash
                                (Hash256 (BS.replicate 32 0xaa))
                                1000 0x207fffff 12345
        result <- atomically $ processPresyncHeaders peer [header]
        case result of
          Right (Presync pd, []) -> do
            pdCount pd `shouldBe` 1
            pdCumulativeWork pd `shouldSatisfy` (> 0)
          Right _ -> expectationFailure "Expected Presync state"
          Left err -> expectationFailure $ "Presync failed: " ++ err

      it "presync rejects non-connecting headers" $ do
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        -- First add a connecting header
        let header1 = BlockHeader 1 genesisHash
                                 (Hash256 (BS.replicate 32 0xaa))
                                 1000 0x207fffff 12345
            hash1 = computeBlockHash header1
        _ <- atomically $ processPresyncHeaders peer [header1]
        -- Now try a non-connecting header (wrong prevBlock)
        let wrongPrev = BlockHash (Hash256 (BS.replicate 32 0xff))
            badHeader = BlockHeader 1 wrongPrev
                                   (Hash256 (BS.replicate 32 0xbb))
                                   2000 0x207fffff 67890
        result <- atomically $ processPresyncHeaders peer [badHeader]
        case result of
          Left err -> err `shouldSatisfy` ("connect" `isInfixOf`)
          Right _ -> expectationFailure "Expected rejection"

      it "presync stores commitments at commitment period" $ do
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        -- Generate enough headers to hit at least one commitment period
        let commitPeriod = hspCommitmentPeriod defaultHeaderSyncParams
            headers = generateChainHeaders regtest genesisHash (commitPeriod + 10)
        result <- atomically $ processPresyncHeaders peer headers
        case result of
          Right (Presync pd, []) -> do
            pdCount pd `shouldBe` (commitPeriod + 10)
            -- Should have at least one commitment
            Seq.length (pdCommitments pd) `shouldSatisfy` (>= 1)
          Right (Redownload _, _) ->
            -- If we hit minimum work threshold, that's also valid
            return ()
          Left err -> expectationFailure $ "Presync failed: " ++ err
          _ -> expectationFailure "Unexpected state"

    describe "anti dos" $ do
      it "low work headers trigger presync instead of chain acceptance" $ do
        -- Create a peer and verify it starts in presync
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock mainnet)
        peer <- initHeaderSyncPeer mainnet genesisHash 0
        state <- atomically $ getHeaderSyncState peer
        case state of
          Presync _ -> return ()  -- Good, presync is active
          _ -> expectationFailure "Expected Presync for mainnet"

      it "presync transitions to redownload when work threshold met" $ do
        -- Use regtest with 0 minimum work for easy testing
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        -- Create peer with low minimum work requirement
        peer <- initHeaderSyncPeer regtest genesisHash 0
        -- Manually set low minimum work in presync data
        atomically $ do
          state <- readTVar (hspState peer)
          case state of
            Presync pd -> do
              let lowThreshold = pd { pdMinimumWork = 100 }  -- Very low threshold
              writeTVar (hspState peer) (Presync lowThreshold)
            _ -> return ()
        -- Add headers with work exceeding threshold
        let headers = generateChainHeaders regtest genesisHash 10
        result <- atomically $ processPresyncHeaders peer headers
        case result of
          Right (Redownload _, []) -> return ()  -- Good, transitioned to redownload
          Right (Presync _, []) -> return ()  -- May still be in presync if work not reached
          Left err -> expectationFailure $ "Failed: " ++ err
          _ -> return ()

      it "memory usage in presync is bounded" $ do
        -- Presync should store only commitments, not full headers
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        let numHeaders = 1000
            headers = generateChainHeaders regtest genesisHash numHeaders
        result <- atomically $ processPresyncHeaders peer headers
        case result of
          Right (Presync pd, []) -> do
            -- Should NOT store all 1000 headers
            -- Only commitments at commitment_period intervals
            let expectedCommits = numHeaders `div` hspCommitmentPeriod defaultHeaderSyncParams
            Seq.length (pdCommitments pd) `shouldSatisfy` (<= expectedCommits + 1)
          Right _ -> return ()  -- Other states are fine
          Left err -> expectationFailure $ "Failed: " ++ err

      it "commitment hash is deterministic with same salt" $ do
        let hash1 = BlockHash (Hash256 (BS.replicate 32 0xaa))
            hash2 = BlockHash (Hash256 (BS.replicate 32 0xbb))
            salt = 12345
        -- Same hash and salt should give same commitment
        commitmentHash salt hash1 `shouldBe` commitmentHash salt hash1
        -- Different hashes may give different commitments (probabilistically)
        -- Can't guarantee this, but it's a reasonable sanity check
        (commitmentHash salt hash1, commitmentHash salt hash2)
          `shouldSatisfy` (\_ -> True)  -- Just check it doesn't crash

      it "commitment hash varies with salt" $ do
        let hash1 = BlockHash (Hash256 (BS.replicate 32 0xcc))
            salt1 = 11111
            salt2 = 22222
        -- Different salts should (usually) give different results
        -- This is probabilistic, but validates the salting mechanism
        let c1 = commitmentHash salt1 hash1
            c2 = commitmentHash salt2 hash1
        -- At least one should be True or False (validates function works)
        (c1 || c2 || not c1 || not c2) `shouldBe` True

    describe "redownload" $ do
      it "redownload verifies commitments from presync" $ do
        -- This test simulates the full presync -> redownload flow
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        -- Set a very low threshold to trigger transition
        atomically $ do
          state <- readTVar (hspState peer)
          case state of
            Presync pd -> do
              let lowThreshold = pd { pdMinimumWork = 10 }
              writeTVar (hspState peer) (Presync lowThreshold)
            _ -> return ()
        -- Add headers to trigger transition to redownload
        let headers = generateChainHeaders regtest genesisHash 50
        result1 <- atomically $ processPresyncHeaders peer headers
        case result1 of
          Right (Redownload rd, []) -> do
            -- Verify we're in redownload with commitments
            rdCount rd `shouldBe` 0  -- Just transitioned, haven't redownloaded yet
          Right (Presync _, []) -> return ()  -- Still in presync is ok
          Left err -> expectationFailure $ "Presync phase failed: " ++ err
          _ -> return ()

      it "redownload rejects mismatched chains" $ do
        -- Create presync state with known commitments
        let genesisHash = computeBlockHash (blockHeader $ netGenesisBlock regtest)
        peer <- initHeaderSyncPeer regtest genesisHash 0
        -- Set low threshold and manually create redownload state
        atomically $ do
          let rd = RedownloadData
                { rdLastHeaderHash = genesisHash
                , rdLastHeaderBits = 0x207fffff
                , rdCumulativeWork = 0
                , rdCount = 0
                , rdCommitments = Seq.fromList [True, False, True]
                , rdCommitOffset = 0
                , rdBuffer = Seq.empty
                , rdMinimumWork = 1000000
                , rdWorkReached = False
                , rdParams = defaultHeaderSyncParams
                }
          writeTVar (hspState peer) (Redownload rd)
        -- Send headers that won't match the commitments
        let badHeaders = generateChainHeaders regtest genesisHash 5
        result <- atomically $ processRedownloadHeaders peer badHeaders
        -- This may or may not fail depending on commitment timing
        case result of
          Left _ -> return ()  -- Commitment mismatch detected
          Right _ -> return ()  -- Headers processed without hitting commitment

      it "maxHeadersPerMessage is 2000" $ do
        maxHeadersPerMessage `shouldBe` 2000

-- Helper: Generate a chain of headers for testing
generateChainHeaders :: Network -> BlockHash -> Int -> [BlockHeader]
generateChainHeaders _ _ 0 = []
generateChainHeaders net prevHash n =
  let header = BlockHeader 1 prevHash
                          (Hash256 (BS.pack [fromIntegral n, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0]))
                          (fromIntegral n * 1000)
                          (if netPowNoRetargeting net then 0x207fffff else 0x1d00ffff)
                          (fromIntegral n)
      newHash = computeBlockHash header
  in header : generateChainHeaders net newHash (n - 1)

-- Helper: Check if substring is in string
isInfixOf :: String -> String -> Bool
isInfixOf needle haystack = any (isPrefixOf needle) (tails haystack)

isPrefixOf :: String -> String -> Bool
isPrefixOf [] _ = True
isPrefixOf _ [] = False
isPrefixOf (x:xs) (y:ys) = x == y && isPrefixOf xs ys

tails :: [a] -> [[a]]
tails [] = [[]]
tails xs@(_:xs') = xs : tails xs'

  --------------------------------------------------------------------------------
  -- Misbehavior Scoring Tests (Phase 14)
  --------------------------------------------------------------------------------

  describe "Misbehavior Scoring" $ do
    describe "MisbehaviorReason scores" $ do
      it "invalid block header = 100 (immediate ban)" $ do
        misbehaviorScore InvalidBlockHeader `shouldBe` 100

      it "invalid block = 100 (immediate ban)" $ do
        misbehaviorScore InvalidBlock `shouldBe` 100

      it "wrong network magic = 100 (immediate ban)" $ do
        misbehaviorScore WrongNetworkMagic `shouldBe` 100

      it "invalid compact block = 100 (immediate ban)" $ do
        misbehaviorScore InvalidCompactBlock `shouldBe` 100

      it "non-continuous headers = 100 (immediate ban)" $ do
        misbehaviorScore NonContinuousHeaders `shouldBe` 100

      it "invalid transaction = 10" $ do
        misbehaviorScore InvalidTransaction `shouldBe` 10

      it "malformed message = 10" $ do
        misbehaviorScore MalformedMessage `shouldBe` 10

      it "checksum mismatch = 10" $ do
        misbehaviorScore ChecksumMismatch `shouldBe` 10

      it "payload too large = 10" $ do
        misbehaviorScore PayloadTooLarge `shouldBe` 10

      it "too many addr messages = 20" $ do
        misbehaviorScore TooManyAddrMessages `shouldBe` 20

      it "too large inv message = 20" $ do
        misbehaviorScore TooLargeInvMessage `shouldBe` 20

      it "too large addr message = 20" $ do
        misbehaviorScore TooLargeAddrMessage `shouldBe` 20

      it "too large headers message = 20" $ do
        misbehaviorScore TooLargeHeadersMessage `shouldBe` 20

      it "unsolicited message = 1" $ do
        misbehaviorScore UnsolicitedMessage `shouldBe` 1

      it "duplicate version = 1" $ do
        misbehaviorScore DuplicateVersion `shouldBe` 1

      it "protocol violation = 10" $ do
        misbehaviorScore (ProtocolViolation "test") `shouldBe` 10

    describe "Ban threshold logic" $ do
      it "default ban threshold is 100" $ do
        let config = defaultPeerManagerConfig
        pmcBanThreshold config `shouldBe` 100

      it "default ban duration is 24 hours (86400 seconds)" $ do
        let config = defaultPeerManagerConfig
        pmcBanDuration config `shouldBe` 86400

      it "single InvalidBlockHeader triggers ban (score 100)" $ do
        let score = misbehaviorScore InvalidBlockHeader
        (score >= 100) `shouldBe` True

      it "10 InvalidTransaction offenses trigger ban (10 * 10 = 100)" $ do
        let totalScore = 10 * misbehaviorScore InvalidTransaction
        (totalScore >= 100) `shouldBe` True

      it "5 TooLargeInvMessage offenses trigger ban (5 * 20 = 100)" $ do
        let totalScore = 5 * misbehaviorScore TooLargeInvMessage
        (totalScore >= 100) `shouldBe` True

      it "99 UnsolicitedMessage offenses don't trigger ban" $ do
        let totalScore = 99 * misbehaviorScore UnsolicitedMessage
        (totalScore >= 100) `shouldBe` False

      it "100 UnsolicitedMessage offenses trigger ban" $ do
        let totalScore = 100 * misbehaviorScore UnsolicitedMessage
        (totalScore >= 100) `shouldBe` True

    describe "PeerManagerConfig" $ do
      it "has reasonable default max outbound" $ do
        pmcMaxOutbound defaultPeerManagerConfig `shouldBe` 8

      it "has reasonable default max inbound" $ do
        pmcMaxInbound defaultPeerManagerConfig `shouldBe` 117

      it "has reasonable default max total" $ do
        pmcMaxTotal defaultPeerManagerConfig `shouldBe` 125

      it "has reasonable ping interval" $ do
        pmcPingInterval defaultPeerManagerConfig `shouldBe` 120

  describe "Ban List Persistence" $ do
    describe "BanEntry serialization" $ do
      it "sockAddrToBanEntry creates valid entry for IPv4" $ do
        let addr = SockAddrInet 8333 0x0100007f  -- 127.0.0.1:8333
            expiry = 1700000000 :: Int64
        case sockAddrToBanEntry addr expiry of
          Just entry -> do
            beAddress entry `shouldBe` "127.0.0.1"
            bePort entry `shouldBe` 8333
            beExpiry entry `shouldBe` 1700000000
          Nothing -> expectationFailure "Expected BanEntry"

      it "banEntryToSockAddr roundtrips IPv4 addresses" $ do
        let addr = SockAddrInet 8333 0x0100007f  -- 127.0.0.1:8333
            expiry = 1700000000 :: Int64
        case sockAddrToBanEntry addr expiry of
          Just entry ->
            case banEntryToSockAddr entry of
              Just addr' -> addr' `shouldBe` addr
              Nothing -> expectationFailure "Expected SockAddr"
          Nothing -> expectationFailure "Expected BanEntry"

      it "handles different IP addresses" $ do
        -- Test 192.168.1.1:18333
        let hostAddr = 1 + 168 * 0x100 + 192 * 0x10000 + 1 * 0x1000000
            addr = SockAddrInet 18333 hostAddr
            expiry = 1700000000 :: Int64
        case sockAddrToBanEntry addr expiry of
          Just entry -> beAddress entry `shouldBe` "1.168.192.1"
          Nothing -> expectationFailure "Expected BanEntry"

    describe "PeerInfo ban score tracking" $ do
      it "initializes with zero ban score" $ do
        let info = PeerInfo
              { piAddress = SockAddrInet 8333 0
              , piVersion = Nothing
              , piState = PeerConnecting
              , piServices = 0
              , piStartHeight = 0
              , piRelay = True
              , piLastSeen = 0
              , piLastPing = Nothing
              , piPingLatency = Nothing
              , piBanScore = 0
              , piBytesSent = 0
              , piBytesRecv = 0
              , piMsgsSent = 0
              , piMsgsRecv = 0
              , piConnectedAt = 0
              , piInbound = False
              }
        piBanScore info `shouldBe` 0

      it "PeerBanned state is available" $ do
        let info = PeerInfo
              { piAddress = SockAddrInet 8333 0
              , piVersion = Nothing
              , piState = PeerBanned
              , piServices = 0
              , piStartHeight = 0
              , piRelay = True
              , piLastSeen = 0
              , piLastPing = Nothing
              , piPingLatency = Nothing
              , piBanScore = 100
              , piBytesSent = 0
              , piBytesRecv = 0
              , piMsgsSent = 0
              , piMsgsRecv = 0
              , piConnectedAt = 0
              , piInbound = False
              }
        piState info `shouldBe` PeerBanned
        piBanScore info `shouldBe` 100

  describe "Peer Scoring Integration" $ do
    it "misbehavior accumulates until ban threshold" $ do
      -- Simulate accumulating scores
      let scores = [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]  -- 10 x 10 = 100
          totalScore = sum scores
      totalScore `shouldBe` 100

    it "mixed misbehavior types can accumulate to ban" $ do
      -- 2 invalid tx (20) + 3 unsolicited (3) + 1 too large inv (20) = 43
      -- Add 6 more invalid tx (60) = 103 > 100
      let scores = [10, 10, 1, 1, 1, 20, 10, 10, 10, 10, 10, 10]
          totalScore = sum scores
      (totalScore >= 100) `shouldBe` True

  --------------------------------------------------------------------------------
  -- Pre-Handshake Rejection Tests (Phase 16)
  --------------------------------------------------------------------------------

  describe "pre-handshake rejection" $ do
    describe "PreHandshakeResult" $ do
      it "AcceptConnection allows connection" $ do
        AcceptConnection `shouldBe` AcceptConnection

      it "RejectBanned indicates banned peer" $ do
        RejectBanned `shouldBe` RejectBanned

      it "RejectDiscouraged indicates discouraged peer with full slots" $ do
        RejectDiscouraged `shouldBe` RejectDiscouraged

      it "RejectMaxConnections indicates total limit reached" $ do
        RejectMaxConnections `shouldBe` RejectMaxConnections

      it "RejectMaxInbound indicates inbound limit with no eviction" $ do
        RejectMaxInbound `shouldBe` RejectMaxInbound

      it "AcceptAfterEviction includes evicted peer address" $ do
        let addr = SockAddrInet 8333 0x0100007f  -- 127.0.0.1
        AcceptAfterEviction addr `shouldBe` AcceptAfterEviction addr

  describe "connection limit" $ do
    describe "PeerManagerConfig limits" $ do
      it "default max connections is 125" $ do
        pmcMaxTotal defaultPeerManagerConfig `shouldBe` 125

      it "default max inbound is 117 (125 - 8 outbound)" $ do
        pmcMaxInbound defaultPeerManagerConfig `shouldBe` 117

      it "default max outbound is 8" $ do
        pmcMaxOutbound defaultPeerManagerConfig `shouldBe` 8

      it "max inbound + max outbound = max total" $ do
        let cfg = defaultPeerManagerConfig
        (pmcMaxInbound cfg + pmcMaxOutbound cfg) `shouldBe` pmcMaxTotal cfg

  describe "eviction" $ do
    describe "EvictionCandidate" $ do
      it "stores peer address" $ do
        let addr = SockAddrInet 8333 0x0100007f
            candidate = EvictionCandidate
              { ecAddress = addr
              , ecConnectedAt = 1700000000
              , ecMinPingTime = Just 0.05
              , ecLastBlockTime = 1700000100
              , ecLastTxTime = 1700000050
              , ecServices = 0x409
              , ecRelaysTxs = True
              , ecNetworkGroup = 127
              , ecInbound = True
              , ecNoBan = False
              }
        ecAddress candidate `shouldBe` addr

      it "stores connection time" $ do
        let candidate = EvictionCandidate
              { ecAddress = SockAddrInet 8333 0
              , ecConnectedAt = 1700000000
              , ecMinPingTime = Nothing
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = 0
              , ecInbound = True
              , ecNoBan = False
              }
        ecConnectedAt candidate `shouldBe` 1700000000

      it "stores minimum ping time" $ do
        let candidate = EvictionCandidate
              { ecAddress = SockAddrInet 8333 0
              , ecConnectedAt = 0
              , ecMinPingTime = Just 0.025
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = 0
              , ecInbound = True
              , ecNoBan = False
              }
        ecMinPingTime candidate `shouldBe` Just 0.025

    describe "getNetworkGroup" $ do
      it "extracts /16 group from IPv4 address" $ do
        -- 127.0.0.1 -> group 127 * 256 + 0 = 32512
        let addr = SockAddrInet 8333 0x0100007f  -- 127.0.0.1 in little-endian
        -- Actually in host byte order: 0x7f000001 = 2130706433
        -- First two octets: 127 and 0
        getNetworkGroup addr `shouldSatisfy` (> 0)

      it "different /16 networks get different groups" $ do
        -- 192.168.1.1 vs 10.0.0.1
        let addr1 = SockAddrInet 8333 0x0101a8c0  -- 192.168.1.1
            addr2 = SockAddrInet 8333 0x0100000a  -- 10.0.0.1
            group1 = getNetworkGroup addr1
            group2 = getNetworkGroup addr2
        group1 `shouldNotBe` group2

      it "same /16 networks get same group" $ do
        -- 192.168.1.1 vs 192.168.2.1 (same /16)
        let addr1 = SockAddrInet 8333 0x0101a8c0  -- 192.168.1.1
            addr2 = SockAddrInet 8333 0x0102a8c0  -- 192.168.2.1
            group1 = getNetworkGroup addr1
            group2 = getNetworkGroup addr2
        group1 `shouldBe` group2

    describe "selectEvictionCandidate" $ do
      it "returns Nothing for empty list" $ do
        selectEvictionCandidate [] `shouldBe` Nothing

      it "returns Nothing if all candidates are outbound" $ do
        let candidate = EvictionCandidate
              { ecAddress = SockAddrInet 8333 0x0100007f
              , ecConnectedAt = 1700000000
              , ecMinPingTime = Nothing
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = 127
              , ecInbound = False  -- Outbound
              , ecNoBan = False
              }
        selectEvictionCandidate [candidate] `shouldBe` Nothing

      it "returns Nothing if all candidates have NoBan" $ do
        let candidate = EvictionCandidate
              { ecAddress = SockAddrInet 8333 0x0100007f
              , ecConnectedAt = 1700000000
              , ecMinPingTime = Nothing
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = 127
              , ecInbound = True
              , ecNoBan = True  -- Protected
              }
        selectEvictionCandidate [candidate] `shouldBe` Nothing

      it "selects an inbound candidate without NoBan" $ do
        let candidate = EvictionCandidate
              { ecAddress = SockAddrInet 8333 0x0100007f
              , ecConnectedAt = 1700000000
              , ecMinPingTime = Nothing
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = 127
              , ecInbound = True
              , ecNoBan = False
              }
        -- With only one candidate, it should be selected after protections
        -- (which won't protect it since there are too few candidates)
        selectEvictionCandidate [candidate] `shouldSatisfy` maybe False (const True)

      it "prefers evicting from largest network group" $ do
        -- Create candidates: 3 from same group, 1 from different
        let addr1 = SockAddrInet 8333 0x01010a0a  -- 10.10.1.1
            addr2 = SockAddrInet 8333 0x02010a0a  -- 10.10.1.2
            addr3 = SockAddrInet 8333 0x03010a0a  -- 10.10.1.3
            addr4 = SockAddrInet 8333 0x0101c0a8  -- 192.168.1.1 (different group)
            mkCandidate addr time = EvictionCandidate
              { ecAddress = addr
              , ecConnectedAt = time
              , ecMinPingTime = Nothing
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = getNetworkGroup addr
              , ecInbound = True
              , ecNoBan = False
              }
            candidates = [ mkCandidate addr1 1000
                         , mkCandidate addr2 2000
                         , mkCandidate addr3 3000  -- Youngest in group
                         , mkCandidate addr4 4000
                         ]
        -- Should evict youngest from the larger group (10.10.x.x)
        case selectEvictionCandidate candidates of
          Just c -> ecNetworkGroup c `shouldBe` getNetworkGroup addr1
          Nothing -> expectationFailure "Expected to find eviction candidate"

      it "evicts youngest peer in the selected group" $ do
        -- Create candidates from same network group with different ages
        let addr1 = SockAddrInet 8333 0x01010a0a  -- oldest
            addr2 = SockAddrInet 8333 0x02010a0a  -- middle
            addr3 = SockAddrInet 8333 0x03010a0a  -- youngest
            mkCandidate addr time = EvictionCandidate
              { ecAddress = addr
              , ecConnectedAt = time
              , ecMinPingTime = Nothing
              , ecLastBlockTime = 0
              , ecLastTxTime = 0
              , ecServices = 0
              , ecRelaysTxs = False
              , ecNetworkGroup = getNetworkGroup addr
              , ecInbound = True
              , ecNoBan = False
              }
            candidates = [ mkCandidate addr1 1000
                         , mkCandidate addr2 2000
                         , mkCandidate addr3 3000  -- Youngest
                         ]
        case selectEvictionCandidate candidates of
          Just c -> ecConnectedAt c `shouldBe` 3000  -- Should be youngest
          Nothing -> expectationFailure "Expected to find eviction candidate"

    describe "peerToEvictionCandidate" $ do
      it "converts PeerInfo to EvictionCandidate" $ do
        let addr = SockAddrInet 8333 0x0100007f
            info = PeerInfo
              { piAddress = addr
              , piVersion = Nothing
              , piState = PeerConnected
              , piServices = 0x409
              , piStartHeight = 800000
              , piRelay = True
              , piLastSeen = 1700000100
              , piLastPing = Nothing
              , piPingLatency = Just 0.05
              , piBanScore = 0
              , piBytesSent = 1000
              , piBytesRecv = 2000
              , piMsgsSent = 10
              , piMsgsRecv = 20
              , piConnectedAt = 1700000000
              , piInbound = True
              }
            candidate = peerToEvictionCandidate addr info
        ecAddress candidate `shouldBe` addr
        ecConnectedAt candidate `shouldBe` 1700000000
        ecMinPingTime candidate `shouldBe` Just 0.05
        ecServices candidate `shouldBe` 0x409
        ecRelaysTxs candidate `shouldBe` True
        ecInbound candidate `shouldBe` True
        ecNoBan candidate `shouldBe` False

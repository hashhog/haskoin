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
import Data.Word (Word64)
import Data.Int (Int64)

import Haskoin.Types
import Haskoin.Crypto
import Haskoin.Script
import Haskoin.Consensus
import Haskoin.Storage
import qualified Data.Map.Strict as Map

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

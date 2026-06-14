{-# LANGUAGE OverloadedStrings #-}

-- | W177 BUG-4 (P0-CDIV) — "Superfluous witness record" rejection
--
-- Bitcoin Core ref: primitives/transaction.h:228-231
--
--   if (!tx.HasWitness()) {
--       /* It's illegal to encode witnesses when all witness stacks are empty. */
--       throw std::ios_base::failure("Superfluous witness record");
--   }
--
-- A transaction serialized with BIP-144 segwit marker (0x00) + flag (0x01)
-- but with ALL input witness stacks empty is INVALID.  Without the fix,
-- haskoin accepted the extended encoding and produced the same txid/merkle
-- root as the equivalent legacy encoding — a consensus split.
--
-- This test asserts that the 63-byte hex tx below (valid BIP-144 framing,
-- but zero-item witness on the single input) is REJECTED at deserialize.
-- The test FAILS on the unfixed code (decode returns Right) and PASSES after
-- the fix (decode returns Left containing "Superfluous witness record").
--
-- Tx breakdown (63 bytes):
--   01000000       version = 1
--   00             marker = 0x00  (BIP-144 segwit)
--   01             flag   = 0x01
--   01             vin count = 1
--   0000..0000     prev txid (32 zero bytes)
--   00000000       prev index = 0
--   00             scriptSig length = 0
--   ffffffff       sequence
--   01             vout count = 1
--   00f2052a01000000  value = 5000000000 (50 BTC)
--   00             scriptPubKey length = 0
--   00             witness stack for input 0: stack_size = 0  (EMPTY)
--   00000000       locktime = 0
module W177SuperfluousWitnessSpec (spec) where

import Test.Hspec
import Data.Serialize (decode)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString as BS

import Haskoin.Types (Tx)

-- | The superfluous-witness tx: BIP-144 marker+flag present, but the single
-- input's witness stack is empty (varint 0x00 = zero items).
-- Provided in the BUG-4 finding and confirmed against Core's test vectors.
superfluousWitnessTxHex :: BS.ByteString
superfluousWitnessTxHex =
  "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000000000000000"

-- | The same transaction in legacy (non-segwit) encoding: no marker/flag,
-- no witness field.  Core accepts this.  Haskoin must also accept this.
-- version(4) vin-count(1) txin(41) vout-count(1) txout(9) locktime(4) = 60 bytes
legacyTxBytes :: BS.ByteString
legacyTxBytes = BS.pack
  [ 0x01, 0x00, 0x00, 0x00  -- version = 1 (LE)
  , 0x01                     -- vin count = 1
  -- TxIn: prev outpoint (txid 32 zero bytes + index 0)
  , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  , 0x00, 0x00, 0x00, 0x00  -- prev index = 0 (LE)
  , 0x00                     -- scriptSig length = 0
  , 0xff, 0xff, 0xff, 0xff  -- sequence = 0xffffffff
  , 0x01                     -- vout count = 1
  -- TxOut: value 5000000000 (50 BTC) LE, empty scriptPubKey
  , 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00
  , 0x00                     -- scriptPubKey length = 0
  , 0x00, 0x00, 0x00, 0x00  -- locktime = 0
  ]

spec :: Spec
spec = describe "W177 Superfluous witness record (BUG-4 P0-CDIV)" $ do

  it "rejects a segwit-framed tx whose every witness stack is empty" $ do
    let raw = case B16.decode superfluousWitnessTxHex of
                Right bs -> bs
                Left err -> error $ "hex decode failed: " ++ show err
    -- The deserializer must reject this; result must be Left.
    let result = decode raw :: Either String Tx
    case result of
      Left msg ->
        -- Core says "Superfluous witness record"; our fail uses the same text.
        msg `shouldContain` "Superfluous witness record"
      Right _ ->
        expectationFailure
          "Expected decode to fail with 'Superfluous witness record', \
          \but it succeeded — BUG-4 not fixed"

  it "still accepts the same tx in legacy (non-segwit) encoding" $ do
    -- Sanity: the equivalent tx without the BIP-144 wrapper must still parse.
    let result = decode legacyTxBytes :: Either String Tx
    case result of
      Left err ->
        expectationFailure $
          "Expected legacy tx to parse successfully, got: " ++ err
      Right _ -> return ()

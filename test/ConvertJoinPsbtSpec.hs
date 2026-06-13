{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | converttopsbt + joinpsbts (Bitcoin Core v31.99) — focused, offline
-- (no node / no regtest) functional test.
--
-- Reference:
--   bitcoin-core/src/rpc/rawtransaction.cpp converttopsbt (1663) / joinpsbts (1778)
--   bitcoin-core/src/core_io.cpp           DecodeTx (156)  — full-consumption gate
--   bitcoin-core/src/psbt.cpp              AddInput (52)   — sig-field clearing +
--                                                            full-CTxIn duplicate check
--
-- The tests exercise the SERVER-INDEPENDENT pure cores 'convertToPsbt' and
-- 'joinPsbts' (the functions the 'handleConvertToPsbt' / 'handleJoinPsbts'
-- RPCs wrap), so they need neither a running node nor a regtest harness.
--
-- joinpsbts shuffles its output order with a random context in Core, so byte
-- exactness across impls is impossible by construction; 'joinPsbts' itself
-- returns deterministic concatenation order and these tests compare SETS, as
-- the Core authors intend.
module ConvertJoinPsbtSpec (spec) where

import Test.Hspec
import Data.List (sort)
import qualified Data.Map.Strict as Map
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32, Word64)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.Serialize as S

import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..) )
import Haskoin.Wallet
  ( Psbt(..), PsbtGlobal(..), PsbtInput(..)
  , emptyPsbt, emptyPsbtInput, encodePsbt, decodePsbt )
import Haskoin.Crypto (PubKey(..))
import Haskoin.Rpc
  ( convertToPsbt, decodeTxFullConsume, joinPsbts )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

-- | rpc error codes (mirrors Haskoin.Rpc; re-stated to keep the assertions
-- self-documenting).
rpcDeserializationError, rpcInvalidParameter :: Int
rpcDeserializationError = -22
rpcInvalidParameter     = -8

unhex :: ByteString -> ByteString
unhex h = case B16.decode h of
  Right bs -> bs
  Left e   -> error ("bad fixture hex: " ++ e)

b64 :: ByteString -> ByteString
b64 = B64.encode

-- | The empty-vin / single-OP_RETURN-output regression transaction.
--
-- Witness-decoded it consumes only the first 12 bytes (a 0-in / 0-out segwit
-- tx) and leaves the OP_RETURN trailing bytes unconsumed; legacy-decoded it
-- is a 0-in / 1-out tx whose sole output is OP_RETURN 00010203.  Accepting the
-- (partial) witness decode would SILENTLY DROP the output — the bug this gate
-- guards against.
emptyVinRawHex :: ByteString
emptyVinRawHex = "0200000000010000000000000000066a040001020300000000"

-- | The exact base64 PSBT Core produces for 'emptyVinRawHex' (heuristic /
-- iswitness=false): magic + global unsigned-tx (the 25-byte LEGACY tx) +
-- separators, 0 inputs, 1 output map.
emptyVinExpectedB64 :: ByteString
emptyVinExpectedB64 = "cHNidP8BABkCAAAAAAEAAAAAAAAAAAZqBAABAgMAAAAAAAA="

-- | A deterministic outpoint with the given txid-fill byte and vout.
opAt :: Word32 -> Word32 -> OutPoint
opAt fill n = OutPoint (TxId (Hash256 (BS.replicate 32 (fromIntegral fill)))) n

-- | A minimal unsigned tx with the given inputs + outputs (no witness).
mkTx :: Word32 -> [TxIn] -> [TxOut] -> Word32 -> Tx
mkTx ver ins outs lt = Tx
  { txVersion  = fromIntegral ver
  , txInputs   = ins
  , txOutputs  = outs
  , txWitness  = replicate (length ins) []
  , txLockTime = lt
  }

txInAt :: OutPoint -> Word32 -> TxIn
txInAt op s = TxIn { txInPrevOutput = op, txInScript = BS.empty, txInSequence = s }

p2wpkhOut :: Word64 -> TxOut
p2wpkhOut v = TxOut
  { txOutValue  = v
  , txOutScript = BS.concat [BS.pack [0x00, 0x14], BS.replicate 20 0xAB] }

-- | A blank PSBT built from a tx, used as a single join operand.
psbtOf :: Tx -> Psbt
psbtOf = emptyPsbt

-- | An order-independent key for a single 'TxIn': (prevout-txid-bytes,
-- vout, nSequence).  Two inputs with the same key are Core-equal under
-- CTxIn::operator==.
inputKeyOf :: TxIn -> (ByteString, Word32, Word32)
inputKeyOf i =
  ( case outPointHash (txInPrevOutput i) of TxId (Hash256 b) -> b
  , outPointIndex (txInPrevOutput i)
  , txInSequence i )

-- | The keys for all of a PSBT's inputs.
inputKeys :: Psbt -> [(ByteString, Word32, Word32)]
inputKeys p = map inputKeyOf (txInputs (pgTx (psbtGlobal p)))

-- | The set of (value, scriptPubKey) keys for a PSBT's outputs.
outputKeys :: Psbt -> [(Word64, ByteString)]
outputKeys p = [ (txOutValue o, txOutScript o) | o <- txOutputs (pgTx (psbtGlobal p)) ]

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "converttopsbt + joinpsbts (haskoin, Core v31.99)" $ do

  ----------------------------------------------------------------------------
  describe "converttopsbt" $ do

    it "rejects sigdata with -22 when permitsigdata is false" $ do
      -- A 1-in / 1-out tx whose single input carries a non-empty scriptSig.
      let tx = (mkTx 2 [ (txInAt (opAt 0x01 0) 0xffffffff)
                           { txInScript = BS.pack [0x51] } ]  -- OP_1
                       [ p2wpkhOut 50_000 ] 0)
          raw = encodeTx tx
      case convertToPsbt raw False Nothing of
        Left (code, _) -> code `shouldBe` rpcDeserializationError
        Right _        -> expectationFailure "expected -22 for sigdata input"

    it "clears sigdata + builds blank maps when permitsigdata is true" $ do
      let tx = (mkTx 2 [ (txInAt (opAt 0x01 0) 0xfffffffd)
                           { txInScript = BS.pack [0x51, 0x52] } ]
                       [ p2wpkhOut 50_000 ] 0)
          raw = encodeTx tx
      case convertToPsbt raw True Nothing of
        Left e     -> expectationFailure ("unexpected error: " ++ show e)
        Right psbt -> do
          -- scriptSig cleared on the embedded tx
          map txInScript (txInputs (pgTx (psbtGlobal psbt)))
            `shouldBe` [BS.empty]
          -- one blank per-input map + one blank per-output map
          psbtInputs  psbt `shouldBe` [emptyPsbtInput]
          length (psbtOutputs psbt) `shouldBe` 1

    describe "empty-vin full-consumption regression (Core DecodeTx gate)" $ do

      it "decodeTxFullConsume rejects the witness-only decode (leftover bytes)" $
        -- witness attempt only; the segwit decode consumes 12 of 25 bytes
        decodeTxFullConsume True False (unhex emptyVinRawHex)
          `shouldSatisfy` either (const True) (const False)

      it "decodeTxFullConsume accepts the legacy decode (preserves the output)" $
        case decodeTxFullConsume False True (unhex emptyVinRawHex) of
          Left e   -> expectationFailure ("legacy decode failed: " ++ show e)
          Right tx -> do
            txInputs tx `shouldBe` []
            map txOutScript (txOutputs tx)
              `shouldBe` [unhex "6a0400010203"]   -- OP_RETURN 00010203, survives

      it "heuristic converttopsbt matches Core base64 (OP_RETURN output survives)" $
        case convertToPsbt (unhex emptyVinRawHex) False Nothing of
          Left e     -> expectationFailure ("unexpected error: " ++ show e)
          Right psbt -> do
            b64 (encodePsbt psbt) `shouldBe` emptyVinExpectedB64
            -- the output must survive (0 inputs, 1 OP_RETURN output)
            txInputs (pgTx (psbtGlobal psbt)) `shouldBe` []
            map txOutScript (txOutputs (pgTx (psbtGlobal psbt)))
              `shouldBe` [unhex "6a0400010203"]

      it "iswitness=false matches the same Core base64" $
        case convertToPsbt (unhex emptyVinRawHex) False (Just False) of
          Left e     -> expectationFailure ("unexpected error: " ++ show e)
          Right psbt -> b64 (encodePsbt psbt) `shouldBe` emptyVinExpectedB64

      it "iswitness=true fails with -22 (witness decode does not fully consume)" $
        case convertToPsbt (unhex emptyVinRawHex) False (Just True) of
          Left (code, _) -> code `shouldBe` rpcDeserializationError
          Right _        -> expectationFailure "expected -22 for witness-only decode"

  ----------------------------------------------------------------------------
  describe "joinpsbts" $ do

    it "requires >= 2 PSBTs (else -8)" $ do
      let p = psbtOf (mkTx 2 [txInAt (opAt 0x10 0) 0xffffffff] [p2wpkhOut 1000] 0)
      case joinPsbts [p] of
        Left (code, _) -> code `shouldBe` rpcInvalidParameter
        Right _        -> expectationFailure "expected -8 for a single PSBT"

    it "rejects a full-TxIn duplicate (same prevout + scriptSig + nSequence) with -8" $ do
      let inA = txInAt (opAt 0x20 0) 0xffffffff
          pa  = psbtOf (mkTx 2 [inA] [p2wpkhOut 1000] 0)
          pb  = psbtOf (mkTx 2 [inA] [p2wpkhOut 2000] 0)  -- identical TxIn
      case joinPsbts [pa, pb] of
        Left (code, _) -> code `shouldBe` rpcInvalidParameter
        Right _        -> expectationFailure "expected -8 for duplicate full TxIn"

    it "keeps BOTH inputs that share an outpoint but differ in nSequence" $ do
      -- Core CTxIn::operator== compares prevout AND scriptSig AND nSequence,
      -- so these two are NOT equal and both must be kept.
      let in1 = txInAt (opAt 0x30 0) 0xffffffff
          in2 = txInAt (opAt 0x30 0) 0xfffffffe   -- same outpoint, diff seq
          pa  = psbtOf (mkTx 2 [in1] [p2wpkhOut 1000] 0)
          pb  = psbtOf (mkTx 2 [in2] [p2wpkhOut 2000] 0)
      case joinPsbts [pa, pb] of
        Left e       -> expectationFailure ("unexpected error: " ++ show e)
        Right merged -> do
          length (txInputs (pgTx (psbtGlobal merged))) `shouldBe` 2
          sort (inputKeys merged)
            `shouldBe` sort [ inputKeyOf in1, inputKeyOf in2 ]

    it "is a set-union of inputs + outputs with max-version / min-locktime" $ do
      let inA = txInAt (opAt 0x41 0) 0xffffffff
          inB = txInAt (opAt 0x42 0) 0xfffffffd
          outA = p2wpkhOut 11_111
          outB = p2wpkhOut 22_222
          pa = psbtOf (mkTx 1 [inA] [outA] 500)     -- version 1, locktime 500
          pb = psbtOf (mkTx 3 [inB] [outB] 100)     -- version 3, locktime 100
      case joinPsbts [pa, pb] of
        Left e       -> expectationFailure ("unexpected error: " ++ show e)
        Right merged -> do
          -- max version, min locktime
          txVersion  (pgTx (psbtGlobal merged)) `shouldBe` 3
          txLockTime (pgTx (psbtGlobal merged)) `shouldBe` 100
          -- input + output SET union (order-independent)
          sort (inputKeys merged)
            `shouldBe` sort [inputKeyOf inA, inputKeyOf inB]
          sort (outputKeys merged)
            `shouldBe` sort [ (txOutValue outA, txOutScript outA)
                            , (txOutValue outB, txOutScript outB) ]
          -- the merged PSBT must round-trip the codec (proves the global-tx
          -- vin/vout count stays aligned with the per-input / per-output maps)
          (decodePsbt (encodePsbt merged)) `shouldBe` Right merged

    it "CLEARS partial_sigs / final_script_sig / final_script_witness on merged signed inputs" $ do
      -- Core AddInput (psbt.cpp:58-60) unconditionally clears these three
      -- sig fields on every input it adds.
      let inA = txInAt (opAt 0x51 0) 0xffffffff
          inB = txInAt (opAt 0x52 0) 0xffffffff
          -- Build a SIGNED operand: its single per-input map has all three
          -- sig fields populated (a partial sig, a final scriptSig, and a
          -- final witness stack).
          dummyPubKey = PubKeyCompressed (BS.cons 0x02 (BS.replicate 32 0x77))
          signedInput = emptyPsbtInput
            { piPartialSigs        = Map.singleton dummyPubKey
                                        (BS.pack [0x30, 0x44, 0x02])
            , piFinalScriptSig     = Just (BS.pack [0x47, 0x30, 0x44])
            , piFinalScriptWitness = Just [BS.pack [0x30, 0x44], BS.pack [0x02]]
            }
          paBase = psbtOf (mkTx 2 [inA] [p2wpkhOut 1000] 0)
          pa = paBase { psbtInputs = [signedInput] }
          pb = psbtOf (mkTx 2 [inB] [p2wpkhOut 2000] 0)
      case joinPsbts [pa, pb] of
        Left e       -> expectationFailure ("unexpected error: " ++ show e)
        Right merged -> do
          let allCleared i =
                Map.null (piPartialSigs i)
                  && piFinalScriptSig i == Nothing
                  && piFinalScriptWitness i == Nothing
          all allCleared (psbtInputs merged) `shouldBe` True

-- | Serialize a tx with the library's own codec ('Serialize Tx'); legacy
-- (no-marker) form when no input carries witness data.
encodeTx :: Tx -> ByteString
encodeTx = S.encode

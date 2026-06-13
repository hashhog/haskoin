{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W176 signrawtransactionwithkey (Bitcoin Core v31.99) — focused
-- functional test.
--
-- Reference:
--   bitcoin-core/src/rpc/rawtransaction.cpp signrawtransactionwithkey (672)
--   + SignTransaction (the engine shared with signrawtransactionwithwallet).
--
-- signrawtransactionwithkey is the wallet-less sibling of
-- signrawtransactionwithwallet: it builds a TEMPORARY keystore from the
-- explicit WIF private keys + the optional prevtxs array, then runs the
-- SAME BIP-143 / BIP-341 sighash + ECDSA / Schnorr signing engine the
-- wallet path uses ('Haskoin.Wallet.signPsbt' → 'signInput' →
-- 'addSignature' → 'signWithKey', which in turn calls the real
-- 'Haskoin.Crypto.signMsg').  The engine under test is the
-- server-independent 'signRawTxWithKeys' (Rpc.hs), the same function the
-- 'handleSignRawTransactionWithKey' RPC wraps.
--
-- This spec proves, for a P2WPKH input whose key is supplied:
--   1. {complete = True} and the result is fully signed,
--   2. ⭐ the produced witness signature VERIFIES against the prevout
--      scriptPubKey + the correct BIP-143 sighash — by decoding the
--      signed tx and running it through the impl's OWN script verifier
--      ('verifyScriptWithFlags' with P2SH+WITNESS flags), NOT merely
--      asserting the witness stack is non-empty,
--   3. a missing-key input (a DIFFERENT key is provided) yields
--      {complete = False} plus an errors[] entry for that input.
module W176SignRawTxWithKeySpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word64)
import qualified Data.Serialize as S

import Haskoin.Crypto
  ( SecKey(..), derivePubKey, serializePubKeyCompressed, hash160 )
import Haskoin.Types
  ( Tx(..), TxIn(..), TxOut(..), OutPoint(..), TxId(..), Hash256(..)
  , Hash160(..) )
import Haskoin.Wallet (wifEncode, wifDecode)
import Haskoin.Script
  ( verifyScriptWithFlags, flagSet, ScriptVerifyFlag(..) )
import Haskoin.Rpc
  ( signRawTxWithKeys, SignKeyPrevout(..), SignTxResult(..) )

--------------------------------------------------------------------------------
-- Fixtures
--------------------------------------------------------------------------------

-- | A deterministic, valid secp256k1 secret key (any 32-byte value in
-- the curve order works; this fixed pattern is well below n).
secKeyFor :: Word8 -> SecKey
secKeyFor seed = SecKey (BS.pack (seed : replicate 31 0x11))

-- | Compressed pubkey bytes for a SecKey.
pubKeyBytesOf :: SecKey -> ByteString
pubKeyBytesOf = serializePubKeyCompressed . derivePubKey

-- | The 20-byte HASH160 of a SecKey's compressed pubkey.
pkh :: SecKey -> ByteString
pkh sk = getHash160 (hash160 (pubKeyBytesOf sk))

-- | P2WPKH scriptPubKey: OP_0 <20-byte pubkey-hash>.
p2wpkhScript :: ByteString -> ByteString
p2wpkhScript h20 = BS.concat [BS.pack [0x00, 0x14], h20]

-- | The single prevout this tx spends (txid display order = all-0x07s).
prevOutPoint :: OutPoint
prevOutPoint =
  OutPoint (TxId (Hash256 (BS.replicate 32 0x07))) 0

prevAmount :: Word64
prevAmount = 100_000_000  -- 1 BTC, in satoshis

-- | An unsigned 1-in / 1-out tx spending @prevOutPoint@.  Outputs a
-- P2WPKH to an arbitrary key so the tx is well-formed.
unsignedTx :: ByteString -> Tx
unsignedTx destPkh = Tx
  { txVersion  = 2
  , txInputs   = [ TxIn { txInPrevOutput = prevOutPoint
                        , txInScript     = BS.empty
                        , txInSequence   = 0xffffffff } ]
  , txOutputs  = [ TxOut { txOutValue  = prevAmount - 1000  -- 1000 sat fee
                         , txOutScript = p2wpkhScript destPkh } ]
  , txWitness  = [[]]
  , txLockTime = 0
  }

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W176 signrawtransactionwithkey (haskoin)" $ do

  let signer    = secKeyFor 0x21          -- key that owns the prevout
      otherKey  = secKeyFor 0x55          -- a DIFFERENT key (missing-key case)
      ownerPkh  = pkh signer
      destPkh   = pkh (secKeyFor 0x99)
      spk       = p2wpkhScript ownerPkh
      wif       = wifEncode signer
      prevout   = SignKeyPrevout
                    { skpOutPoint      = prevOutPoint
                    , skpScriptPubKey  = spk
                    , skpAmount        = prevAmount
                    , skpRedeemScript  = Nothing
                    , skpWitnessScript = Nothing }
      tx        = unsignedTx destPkh

  describe "WIF round-trip (temporary keystore)" $
    it "wifEncode/wifDecode preserves the signing key" $
      wifDecode wif `shouldBe` Just signer

  describe "happy path: P2WPKH input with the matching key" $ do

    let result = signRawTxWithKeys tx [signer] [prevout] 0x01

    it "(a) reports complete = True with no errors" $ do
      strComplete result `shouldBe` True
      strErrors result `shouldBe` []

    it "(a) leaves a non-empty witness on the input (sanity)" $ do
      let signed = strTx result
      (length <$> safeHead (txWitness signed)) `shouldBe` Just 2

    it "(b) ⭐ the produced signature VERIFIES under the prevout \
       \scriptPubKey + BIP-143 sighash via the impl's own verifier" $ do
      let signed = strTx result
          flags  = flagSet [VerifyP2SH, VerifyWitness, VerifyWitnessPubkeyType]
          -- The verifier runs OP_CHECKSIG over the BIP-143 sighash; it
          -- only returns Right True if the witness signature is a GENUINE
          -- signature over the correct sighash for THIS scriptPubKey +
          -- amount.  A fabricated / zero signature fails here.
          verdict = verifyScriptWithFlags flags signed 0 spk prevAmount
                      [prevAmount] [spk]
      verdict `shouldBe` Right True

    it "(b') the signed tx round-trips through serialize/deserialize" $ do
      let signed = strTx result
          bytes  = S.encode signed
      S.decode bytes `shouldBe` (Right signed :: Either String Tx)

  describe "missing-key path: only an unrelated key supplied" $ do

    let result = signRawTxWithKeys tx [otherKey] [prevout] 0x01

    it "(c) reports complete = False" $
      strComplete result `shouldBe` False

    it "(c) emits an errors[] entry for the unsigned input (index 0)" $ do
      map (\(i, op, _) -> (i, op)) (strErrors result)
        `shouldBe` [(0, prevOutPoint)]

    it "(c) the wrong key does NOT verify under the prevout script" $ do
      let signed  = strTx result
          flags   = flagSet [VerifyP2SH, VerifyWitness, VerifyWitnessPubkeyType]
          verdict = verifyScriptWithFlags flags signed 0 spk prevAmount
                      [prevAmount] [spk]
      -- Either the witness is empty (not finalized) or, if a stack is
      -- present, it must NOT satisfy the script.  In both cases the
      -- verifier must reject (Left _ or Right False).
      (verdict == Right True) `shouldBe` False

  describe "no-key path: empty keystore" $ do

    let result = signRawTxWithKeys tx [] [prevout] 0x01

    it "leaves the input unsigned (complete = False + errors)" $ do
      strComplete result `shouldBe` False
      map (\(i, _, _) -> i) (strErrors result) `shouldBe` [0]

safeHead :: [a] -> Maybe a
safeHead (x:_) = Just x
safeHead []    = Nothing

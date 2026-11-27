-- | verify-neon-haskoin-findings, script interpreter (Neon audit findings 1-5).
--
-- Five places where haskoin's interpreter answers differently from Core's
-- (bitcoin-core/src/script/interpreter.cpp, src/pubkey.cpp) for one flag
-- combination each. Every case has a control that both implementations
-- answer the same way, so a reject for an unrelated reason (a broken spend
-- builder) cannot pass.
--
--  1. P2WPKH: ExecuteWitnessScript rejects any initial witness stack item
--     over MAX_SCRIPT_ELEMENT_SIZE (520) with SCRIPT_ERR_PUSH_SIZE, for
--     P2WPKH as for P2WSH. haskoin checked it only for P2WSH and taproot.
--     A valid signature padded to 521 bytes (lax DER, no DERSIG) verified.
--  2. EvalScript: with CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY not
--     enabled, OP_NOP2 / OP_NOP3 are plain NOPs ("not enabled; treat as a
--     NOP2"): DISCOURAGE_UPGRADABLE_NOPS is not consulted.
--  3. VerifyWitnessProgram: a native v1 32-byte program without TAPROOT
--     returns success before the DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM test.
--  4. EvalChecksigTapscript (OP_CHECKSIGADD too): an unknown (non-empty,
--     non-32-byte) pubkey fails under DISCOURAGE_UPGRADABLE_PUBKEYTYPE
--     whether or not the signature is empty.
--  5. CPubKey::CheckLowS parses with ecdsa_signature_parse_der_lax, which
--     zeroes an R or S >= the curve order; a zero S is low. haskoin compared
--     the raw S bytes with n/2.
module Main (main) where

import Data.Bits ((.|.), shiftR)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.List (isInfixOf)
import Data.Word (Word8, Word64)
import Test.Hspec

import Haskoin.Crypto (SecKey(..), Sig(..), computeTapTweakHash, derivePubKey, sha256,
                       hash160, serializePubKeyCompressed, sigHashAll, signMsg,
                       txSigHashSegWit, xonlyPubkeyFromSeckey,
                       xonlyPubkeyTweakAdd)
import Haskoin.Script
import Haskoin.TaprootSighash (tapleafHashWith)
import Haskoin.Types

--------------------------------------------------------------------------------
-- Builders
--------------------------------------------------------------------------------

push :: ByteString -> ScriptOp
push bs
  | BS.null bs = OP_0
  | otherwise  = OP_PUSHDATA bs OPCODE   -- every push here is < 76 bytes

amount :: Word64
amount = 100000

mkTx :: ByteString -> [ByteString] -> Tx
mkTx sig wit = Tx
  { txVersion = 2
  , txInputs = [TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0x11))) 0) sig 0xfffffffe]
  , txOutputs = [TxOut 90000 (BS.pack [0x51])]
  , txWitness = if null wit then [] else [wit]
  , txLockTime = 0 }

run :: ScriptFlags -> Tx -> ByteString -> Either String Bool
run flags tx spk = verifyScriptWithFlags flags tx 0 spk amount [amount] [spk]

accepted :: Either String Bool -> Bool
accepted = (== Right True)

rejected :: Either String Bool -> Bool
rejected = not . accepted

failsWith :: String -> Either String Bool -> Bool
failsWith needle (Left e) = needle `isInfixOf` e
failsWith _ _ = False

-- | A tapscript leaf spend of @leaf@ with @items@ as the initial stack.
tapSpend :: ScriptFlags -> [ScriptOp] -> [ByteString] -> Either String Bool
tapSpend flags ops items =
  let sb = encodeScript (Script ops)
      internal = case xonlyPubkeyFromSeckey (BS.replicate 32 0x01) of
                   Just k -> k
                   Nothing -> error "xonlyPubkeyFromSeckey failed"
      tweak = computeTapTweakHash internal (tapleafHashWith 0xc0 sb)
      (outKey, parity) = case xonlyPubkeyTweakAdd internal tweak of
                           Just r -> r
                           Nothing -> error "xonlyPubkeyTweakAdd failed"
      control = BS.cons (0xc0 .|. fromIntegral parity) internal
  in run flags (mkTx BS.empty (items ++ [sb, control]))
         (encodeScript (encodeP2TR (Hash256 outKey)))

--------------------------------------------------------------------------------
-- 1. P2WPKH with an oversized (lax-DER padded) signature
--------------------------------------------------------------------------------

secKey :: SecKey
secKey = SecKey (BS.replicate 31 0 <> BS.singleton 0x07)

pubKey :: ByteString
pubKey = serializePubKeyCompressed (derivePubKey secKey)

p2wpkhSpk :: ByteString
p2wpkhSpk = encodeScript (encodeP2WPKH (hash160 pubKey))

-- | The unsigned spend of the P2WPKH output (the witness is filled in later;
-- BIP-143 does not commit to it).
p2wpkhTx :: [ByteString] -> Tx
p2wpkhTx = mkTx BS.empty

-- | A valid strict-DER signature (with SIGHASH_ALL byte) for 'p2wpkhTx'.
strictSig :: ByteString
strictSig =
  let scriptCode = encodeScript (encodeP2PKH (hash160 pubKey))
      h = txSigHashSegWit (p2wpkhTx []) 0 scriptCode amount 1 sigHashAll
      Sig der = signMsg secKey h
  in der <> BS.singleton 0x01

-- | Re-encode a strict DER signature (with hashtype) in long form, with R
-- padded by leading zero bytes, so the whole item is @total@ bytes. The lax
-- parser Core verifies with (ecdsa_signature_parse_der_lax) skips the
-- sequence length, reads long-form integer lengths and ignores leading
-- zeroes in R, so the signature still verifies.
padSig :: Int -> ByteString -> ByteString
padSig total sigWithType =
  let der   = BS.init sigWithType
      ht    = BS.last sigWithType
      rLen  = fromIntegral (BS.index der 3)
      r     = BS.take rLen (BS.drop 4 der)
      sPart = BS.drop (4 + rLen) der            -- 0x02 sLen S
      pad   = total - (4 + 4 + rLen + BS.length sPart + 1)
      r'    = BS.replicate pad 0 <> r
      len2 :: Int -> [Word8]
      len2 n = [0x82, fromIntegral (n `shiftR` 8), fromIntegral n]
      body  = BS.pack (0x02 : len2 (BS.length r')) <> r' <> sPart
  in BS.pack (0x30 : len2 (BS.length body)) <> body <> BS.singleton ht

-- | WITNESS (and P2SH) only: no DERSIG, no STRICTENC, no LOW_S.
witnessNoDer :: ScriptFlags
witnessNoDer = flagSet [VerifyP2SH, VerifyWitness]

p2wpkhRun :: ByteString -> Either String Bool
p2wpkhRun sig = run witnessNoDer (p2wpkhTx [sig, pubKey]) p2wpkhSpk

--------------------------------------------------------------------------------
-- 5. LOW_S on R or S at or above the curve order
--------------------------------------------------------------------------------

curveOrder :: [Word8]
curveOrder =
  [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
  , 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B
  , 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41 ]

minus1 :: [Word8] -> [Word8]
minus1 = reverse . go . reverse
  where go (0:xs) = 0xFF : go xs
        go (x:xs) = (x - 1) : xs
        go [] = []

-- | A strict-DER integer for a big-endian magnitude (adds the 0x00 sign pad).
derInt :: [Word8] -> [Word8]
derInt v = let v' = dropWhile (== 0) v
               v'' = case v' of
                       (b:_) | b >= 0x80 -> 0 : v'
                       [] -> [0]
                       _ -> v'
           in 0x02 : fromIntegral (length v'') : v''

derSig :: [Word8] -> [Word8] -> ByteString
derSig r s = let body = derInt r ++ derInt s
             in BS.pack (0x30 : fromIntegral (length body) : body ++ [0x01])

-- | Bare scriptPubKey @<pk> CHECKSIG NOT@ spent by @<sig>@: a failing
-- signature leaves false, NOT makes it true, so only an encoding gate can
-- reject it.
checksigNot :: ScriptFlags -> ByteString -> Either String Bool
checksigNot flags sig =
  run flags (mkTx (encodeScript (Script [push sig])) [])
            (encodeScript (Script [push pubKey, OP_CHECKSIG, OP_NOT]))

lowSOnly :: ScriptFlags
lowSOnly = flagSet [VerifyLowS]

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "finding 1: P2WPKH initial witness items over 520 bytes (Core: PUSH_SIZE)" $ do
    it "control: the strict signature verifies (WITNESS without DERSIG)" $
      p2wpkhRun strictSig `shouldSatisfy` accepted
    it "control: the signature padded to 520 bytes still verifies (lax DER)" $
      p2wpkhRun (padSig 520 strictSig) `shouldSatisfy` accepted
    it "the same signature padded to 521 bytes is rejected as PUSH_SIZE" $
      p2wpkhRun (padSig 521 strictSig) `shouldSatisfy` failsWith "520"
    it "control: P2WSH already rejects a 521-byte initial item" $ do
      let ws = encodeScript (Script [OP_DROP, OP_1])
          spk = encodeScript (encodeP2WSH (Hash256 (sha256 ws)))
      run witnessNoDer (mkTx BS.empty [BS.replicate 521 1, ws]) spk
        `shouldSatisfy` failsWith "520"

  describe "finding 2: disabled CLTV / CSV are NOPs, not upgradable NOPs" $ do
    let nops = flagSet [VerifyDiscourageUpgradableNops]
        bare ops = run nops (mkTx BS.empty []) (encodeScript (Script ops))
    it "[1 CHECKLOCKTIMEVERIFY] verifies under DISCOURAGE_UPGRADABLE_NOPS without CLTV" $
      bare [OP_1, OP_CHECKLOCKTIMEVERIFY] `shouldSatisfy` accepted
    it "[1 CHECKSEQUENCEVERIFY] verifies under DISCOURAGE_UPGRADABLE_NOPS without CSV" $
      bare [OP_1, OP_CHECKSEQUENCEVERIFY] `shouldSatisfy` accepted
    it "control: [1 NOP1], [1 NOP4] and [1 NOP10] stay discouraged" $ do
      bare [OP_1, OP_NOP1] `shouldSatisfy` rejected
      bare [OP_1, OP_NOP4] `shouldSatisfy` rejected
      bare [OP_1, OP_NOP10] `shouldSatisfy` rejected
    it "control: without the flag all of them verify" $ do
      let plain ops = run emptyFlags (mkTx BS.empty []) (encodeScript (Script ops))
      mapM_ (\op -> plain [OP_1, op] `shouldSatisfy` accepted)
        [OP_NOP1, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_NOP4]

  describe "finding 3: native v1+32 without TAPROOT succeeds before the discourage test" $ do
    let disc = flagSet [VerifyP2SH, VerifyWitness, VerifyDiscourageUpgradableWitnessProgram]
        prog = BS.replicate 32 0x5a
        v1   = encodeScript (Script [OP_1, push prog])
    it "native OP_1 <32 bytes> verifies under DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" $
      run disc (mkTx BS.empty [BS.singleton 1]) v1 `shouldSatisfy` accepted
    it "control: native OP_2 <32 bytes> is still discouraged" $
      run disc (mkTx BS.empty [BS.singleton 1]) (encodeScript (Script [OP_2, push prog]))
        `shouldSatisfy` failsWith "discouraged"
    it "control: native OP_1 <20 bytes> is still discouraged" $
      run disc (mkTx BS.empty [BS.singleton 1])
          (encodeScript (Script [OP_1, push (BS.replicate 20 0x5a)]))
        `shouldSatisfy` failsWith "discouraged"
    it "control: P2SH-wrapped OP_1 <32 bytes> is still discouraged" $ do
      let spk = encodeScript (encodeP2SH (hash160 v1))
      run disc (mkTx (encodeScript (Script [push v1])) [BS.singleton 1]) spk
        `shouldSatisfy` failsWith "discouraged"

  describe "finding 4: OP_CHECKSIGADD with an empty sig and an unknown pubkey type" $ do
    let tapFlags = flagSet [VerifyP2SH, VerifyWitness, VerifyTaproot]
        disc = tapFlags <> flagSet [VerifyDiscourageUpgradablePubkeyType]
        pk33 = BS.replicate 33 0x02
        addLeaf = [OP_0, OP_0, push pk33, OP_CHECKSIGADD, OP_0, OP_EQUAL]
        sigLeaf = [OP_0, push pk33, OP_CHECKSIG, OP_NOT]
    it "[<> 0 <33-byte pk> CHECKSIGADD 0 EQUAL] fails under DISCOURAGE_UPGRADABLE_PUBKEYTYPE" $
      tapSpend disc addLeaf [] `shouldSatisfy` failsWith "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"
    it "control: OP_CHECKSIG with the same empty sig and pubkey already fails" $
      tapSpend disc sigLeaf [] `shouldSatisfy` failsWith "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"
    it "control: without the flag both leaves verify" $ do
      tapSpend tapFlags addLeaf [] `shouldSatisfy` accepted
      tapSpend tapFlags sigLeaf [] `shouldSatisfy` accepted
    it "control: an empty pubkey is still TAPSCRIPT_EMPTY_PUBKEY" $
      tapSpend disc [OP_0, OP_0, OP_0, OP_CHECKSIGADD, OP_0, OP_EQUAL] []
        `shouldSatisfy` failsWith "EMPTY_PUBKEY"

  describe "finding 5: LOW_S on R or S at or above the curve order (Core: low)" $ do
    let n  = curveOrder
        n1 = minus1 curveOrder
        halfPlus1 = [0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
                    ,0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA1]
    it "(R=1, S=n) passes LOW_S and fails only the signature: CHECKSIG NOT verifies" $
      checksigNot lowSOnly (derSig [1] n) `shouldSatisfy` accepted
    it "(R=1, S=0xff..ff) passes LOW_S" $
      checksigNot lowSOnly (derSig [1] (replicate 32 0xFF)) `shouldSatisfy` accepted
    it "(R=n, S=n-1) passes LOW_S (R overflow zeroes both)" $
      checksigNot lowSOnly (derSig n n1) `shouldSatisfy` accepted
    it "control: (R=1, S=n-1) is high-S and rejected" $
      checksigNot lowSOnly (derSig [1] n1) `shouldSatisfy` failsWith "high"
    it "control: (R=1, S=n/2+1) is high-S and rejected" $
      checksigNot lowSOnly (derSig [1] halfPlus1) `shouldSatisfy` failsWith "high"
    it "control: (R=1, S=1) is low and verifies (CHECKSIG NOT)" $
      checksigNot lowSOnly (derSig [1] [1]) `shouldSatisfy` accepted
    it "with NULLFAIL the S=n signature fails as NULLFAIL (Core), not as high-S" $
      checksigNot (lowSOnly <> flagSet [VerifyNullFail]) (derSig [1] n)
        `shouldSatisfy` failsWith "NULLFAIL"

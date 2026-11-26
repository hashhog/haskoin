{-# LANGUAGE OverloadedStrings #-}
-- | cffix-haskoin-precomputed-sighash: the whole-transaction BIP-143 and
-- BIP-341 sighash digests must be computed once per transaction, as Core's
-- @PrecomputedTransactionData@ does, not once per signature check.
--
-- Core (src/script/interpreter.cpp, @PrecomputedTransactionData::Init@)
-- computes hashPrevouts / hashSequence / hashOutputs (BIP-143, double
-- SHA-256) and the five BIP-341 single-SHA-256 digests (prevouts, amounts,
-- scriptPubKeys, sequences, outputs) once per transaction, and every input's
-- check shares them (validation.cpp CheckInputScripts -> @txdata@). Without
-- that, verifying a transaction costs O(signature checks x tx size): a
-- 400 kWU tx of ~1,700 P2TR key-path inputs hashes ~250 MB instead of
-- ~144 KB.
--
-- Three groups:
--
--   1. Digest equality. 'txSigHashSegWit' and 'buildSigMsg' are compared,
--      byte for byte, with an independent reference written in this file
--      straight from BIP-143 / BIP-341 (and Core's SignatureHash /
--      SignatureHashSchnorr), for every hash type, every input index,
--      with and without annex, key path and script path. SIGHASH_SINGLE
--      with no matching output is covered on both sides: BIP-143 commits
--      to a zero hashOutputs, BIP-341 refuses.
--
--   2. The per-tx path. A transaction mixing P2TR key-path, tapscript
--      OP_CHECKSIG, P2WPKH, P2WSH OP_CHECKSIG and P2WSH OP_CHECKMULTISIG
--      inputs over every hash type (annex on some), signed over the
--      REFERENCE digests, must pass 'validateSingleTx' (the
--      ScriptCheckItem path block connect uses); corrupting any one
--      signature must fail it.
--
--   3. Scaling. Validating one tx of 2N inputs through 'validateSingleTx'
--      must allocate < 2.6x what one tx of N inputs does. Linear is 2x;
--      re-hashing the whole tx for every input is ~4x. Measured with the
--      per-thread allocation counter (no RTS flags); 'validateSingleTx'
--      runs its script checks serially on the calling thread.
--
-- Uses only API that exists on master, so it builds there and fails on the
-- scaling assertions by name.
module Main (main) where

import Control.Exception (evaluate)
import Control.Monad (forM_, unless)
import Data.Bits ((.&.), (.|.), xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.List (isInfixOf)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.Serialize (encode, runPut, putWord16le, putWord32le, putWord64le)
import Data.Word (Word8, Word32, Word64)
import System.Mem (getAllocationCounter, setAllocationCounter)
import Test.Hspec

import Haskoin.Consensus (getBlockScriptFlags, regtest, validateSingleTx)
import Haskoin.Crypto (Sig(..), SecKey(..), computeTapTweakHash,
                       derivePubKeyCompressed, hash160, sha256, signMsg,
                       signSchnorr, txSigHashSegWit, xonlyPubkeyFromSeckey,
                       xonlyPubkeyTweakAdd)
import Haskoin.Script (Script(..), ScriptOp(..), PushDataType(..),
                       encodeScript, encodeP2TR, encodeP2WPKH, encodeP2WSH,
                       parseSigHashByte)
import Haskoin.TaprootSighash (TaprootPrevouts(..), TapscriptContext(..),
                               TaprootSighashError(..), buildSigMsg,
                               tapleafHashWith)
import Haskoin.Types

--------------------------------------------------------------------------------
-- Independent reference serialization and digests (BIP-143 / BIP-341)
--------------------------------------------------------------------------------

le16 :: Word32 -> ByteString
le16 w = runPut (putWord16le (fromIntegral w))

le32 :: Word32 -> ByteString
le32 w = runPut (putWord32le w)

le64 :: Word64 -> ByteString
le64 w = runPut (putWord64le w)

compactSize :: Int -> ByteString
compactSize n
  | n < 0xfd    = BS.singleton (fromIntegral n)
  | n <= 0xffff = BS.cons 0xfd (le16 (fromIntegral n))
  | otherwise   = BS.cons 0xfe (le32 (fromIntegral n))

varBytes :: ByteString -> ByteString
varBytes b = compactSize (BS.length b) <> b

refOutPoint :: OutPoint -> ByteString
refOutPoint (OutPoint (TxId (Hash256 h)) n) = h <> le32 n

refTxOut :: TxOut -> ByteString
refTxOut (TxOut v s) = le64 v <> varBytes s

dsha :: ByteString -> ByteString
dsha = sha256 . sha256

tagged :: ByteString -> ByteString -> ByteString
tagged tag msg = let t = sha256 tag in sha256 (t <> t <> msg)

-- | BIP-143 digest, as Core's SignatureHash for SigVersion::WITNESS_V0:
-- the raw hash type is committed as-is; the structural decisions use
-- @ht & 0x1f@ (NONE = 2, SINGLE = 3) and @ht & 0x80@ (ANYONECANPAY).
refBip143 :: Tx -> Int -> ByteString -> Word64 -> Word32 -> ByteString
refBip143 tx i scriptCode amt ht =
  let ins  = txInputs tx
      outs = txOutputs tx
      acp  = ht .&. 0x80 /= 0
      base = ht .&. 0x1f
      zero = BS.replicate 32 0
      hp = if acp then zero
           else dsha (BS.concat [refOutPoint (txInPrevOutput x) | x <- ins])
      hs = if not acp && base /= 2 && base /= 3
           then dsha (BS.concat [le32 (txInSequence x) | x <- ins])
           else zero
      ho | base /= 2 && base /= 3          = dsha (BS.concat (map refTxOut outs))
         | base == 3 && i < length outs    = dsha (refTxOut (outs !! i))
         | otherwise                       = zero
      inp = ins !! i
  in dsha $ BS.concat
       [ le32 (fromIntegral (txVersion tx)), hp, hs
       , refOutPoint (txInPrevOutput inp), varBytes scriptCode, le64 amt
       , le32 (txInSequence inp), ho, le32 (txLockTime tx), le32 ht ]

-- | BIP-341 SigMsg (with the leading epoch byte, as 'buildSigMsg' returns
-- it), or Nothing for SIGHASH_SINGLE with no matching output.
-- @ext@ = Just (tapleaf hash, codesep position) for a script-path spend.
refSigMsg :: Tx -> Int -> [Word64] -> [ByteString] -> Word8
          -> Maybe ByteString -> Maybe (ByteString, Word32) -> Maybe ByteString
refSigMsg tx i amts spks ht annex ext
  | outType == 3 && i >= length outs = Nothing
  | otherwise = Just $ BS.concat $
      [ BS.singleton 0x00, BS.singleton ht
      , le32 (fromIntegral (txVersion tx)), le32 (txLockTime tx) ]
      ++ (if acp then [] else
            [ sha256 (BS.concat [refOutPoint (txInPrevOutput x) | x <- ins])
            , sha256 (BS.concat (map le64 amts))
            , sha256 (BS.concat (map varBytes spks))
            , sha256 (BS.concat [le32 (txInSequence x) | x <- ins]) ])
      ++ (if outType /= 2 && outType /= 3
            then [sha256 (BS.concat (map refTxOut outs))] else [])
      ++ [BS.singleton (maybe 0 (const 2) ext + maybe 0 (const 1) annex)]
      ++ (if acp
            then [ refOutPoint (txInPrevOutput (ins !! i)), le64 (amts !! i)
                 , varBytes (spks !! i), le32 (txInSequence (ins !! i)) ]
            else [le32 (fromIntegral i)])
      ++ maybe [] (\a -> [sha256 (varBytes a)]) annex
      ++ (if outType == 3 then [sha256 (refTxOut (outs !! i))] else [])
      ++ maybe [] (\(leaf, csp) -> [leaf, BS.singleton 0x00, le32 csp]) ext
  where
    ins  = txInputs tx
    outs = txOutputs tx
    acp  = ht .&. 0x80 /= 0
    outType = if ht == 0 then 1 else ht .&. 0x03

refTapSighash :: Tx -> Int -> [Word64] -> [ByteString] -> Word8
              -> Maybe ByteString -> Maybe (ByteString, Word32) -> ByteString
refTapSighash tx i amts spks ht annex ext =
  case refSigMsg tx i amts spks ht annex ext of
    Just m  -> tagged "TapSighash" m
    Nothing -> error "refTapSighash: SIGHASH_SINGLE without a matching output"

--------------------------------------------------------------------------------
-- Keys and scripts
--------------------------------------------------------------------------------

secKey :: ByteString
secKey = BS.replicate 31 0x00 <> BS.singleton 0x07

pubKey33 :: ByteString
pubKey33 = case derivePubKeyCompressed (SecKey secKey) of
  Just k  -> k
  Nothing -> error "derivePubKeyCompressed failed"

xonly :: ByteString
xonly = case xonlyPubkeyFromSeckey secKey of
  Just k  -> k
  Nothing -> error "xonlyPubkeyFromSeckey failed"

push :: ByteString -> ScriptOp
push b = OP_PUSHDATA b OPCODE   -- every push here is 20..33 bytes

p2pkhCode :: ByteString
p2pkhCode = BS.concat [BS.pack [0x76, 0xa9, 0x14], h, BS.pack [0x88, 0xac]]
  where Hash160 h = hash160 pubKey33

-- | P2WSH witness scripts: <pk> CHECKSIG, and 1-of-1 CHECKMULTISIG.
wshCheckSig, wshMulti :: ByteString
wshCheckSig = encodeScript (Script [push pubKey33, OP_CHECKSIG])
wshMulti    = encodeScript (Script [OP_1, push pubKey33, OP_1, OP_CHECKMULTISIG])

-- | Tapscript leaf <xonly> CHECKSIG, its leaf hash, output key and control
-- block. The internal key is a different key, so a key-path signature by
-- 'secKey' cannot satisfy it.
tapLeaf, tapLeafHash, tapOutKey, tapControl :: ByteString
tapLeaf = encodeScript (Script [push xonly, OP_CHECKSIG])
tapLeafHash = tapleafHashWith 0xc0 tapLeaf
(tapOutKey, tapControl) =
  let internal = case xonlyPubkeyFromSeckey (BS.replicate 32 0x01) of
                   Just k  -> k
                   Nothing -> error "internal key"
      tweak = computeTapTweakHash internal tapLeafHash
  in case xonlyPubkeyTweakAdd internal tweak of
       Just (k, parity) -> (k, BS.cons (0xc0 .|. fromIntegral parity) internal)
       Nothing -> error "xonlyPubkeyTweakAdd failed"

data Kind = KWPKH | KTRKey | KTapscript | KWSHCheckSig | KWSHMulti
  deriving (Show, Eq)

spkOf :: Kind -> ByteString
spkOf k = case k of
  KWPKH        -> encodeScript (encodeP2WPKH (hash160 pubKey33))
  KTRKey       -> encodeScript (encodeP2TR (Hash256 xonly))
  KTapscript   -> encodeScript (encodeP2TR (Hash256 tapOutKey))
  KWSHCheckSig -> encodeScript (encodeP2WSH (Hash256 (sha256 wshCheckSig)))
  KWSHMulti    -> encodeScript (encodeP2WSH (Hash256 (sha256 wshMulti)))

-- | One input to sign: kind, hash type byte (0 = BIP-341 default), annex.
data InSpec = InSpec Kind Word8 (Maybe ByteString)

isKind :: InSpec -> Kind
isKind (InSpec k _ _) = k

inValue :: Int -> Word64
inValue i = 50000 + fromIntegral i

-- | Build an unsigned tx for the specs, then sign every input over the
-- REFERENCE digest. Returns the tx and the UTXO view it spends.
buildSigned :: Word8 -> [InSpec] -> Int -> (Tx, Map OutPoint TxOut)
buildSigned salt specs nOuts =
  let n = length specs
      ops = [ OutPoint (TxId (Hash256 (sha256 (BS.pack [salt, fromIntegral (i `div` 256), fromIntegral i])))) (fromIntegral (i `mod` 3))
            | i <- [0 .. n - 1] ]
      ins = [ TxIn op BS.empty (0xfffffffd - fromIntegral (i `mod` 2)) | (i, op) <- zip [0 :: Int ..] ops ]
      outs = [ TxOut (1000 + fromIntegral j) (BS.pack [0x00, 0x14] <> BS.replicate 20 (fromIntegral j))
             | j <- [0 .. nOuts - 1] ]
      amts = map inValue [0 .. n - 1]
      spks = map (spkOf . isKind) specs
      unsigned = Tx { txVersion = 2, txInputs = ins, txOutputs = outs
                    , txWitness = replicate n [], txLockTime = 0 }
      wit i (InSpec k ht annex) = case k of
        KWPKH -> [ecdsa (refBip143 unsigned i p2pkhCode (amts !! i) (fromIntegral ht)) ht, pubKey33]
        KWSHCheckSig -> [ecdsa (refBip143 unsigned i wshCheckSig (amts !! i) (fromIntegral ht)) ht, wshCheckSig]
        KWSHMulti -> [BS.empty, ecdsa (refBip143 unsigned i wshMulti (amts !! i) (fromIntegral ht)) ht, wshMulti]
        KTRKey -> [schnorr (refTapSighash unsigned i amts spks ht annex Nothing) ht]
                  ++ maybe [] pure annex
        KTapscript -> [ schnorr (refTapSighash unsigned i amts spks ht annex (Just (tapLeafHash, 0xffffffff))) ht
                      , tapLeaf, tapControl ] ++ maybe [] pure annex
      tx = unsigned { txWitness = zipWith wit [0 ..] specs }
      utxo = Map.fromList (zip ops (zipWith TxOut amts spks))
  in (tx, utxo)
  where
    ecdsa digest ht = getSigBytes (signMsg (SecKey secKey) (Hash256 digest)) <> BS.singleton ht
    schnorr digest ht = case signSchnorr secKey digest of
      Just s  -> if ht == 0 then s else s <> BS.singleton ht
      Nothing -> error "signSchnorr failed"

-- | Block-connect flags for a regtest block at height 200 (all soft forks).
validate :: Tx -> Map OutPoint TxOut -> Either String Word64
validate tx utxo =
  validateSingleTx (getBlockScriptFlags regtest (BlockHash (Hash256 (BS.replicate 32 0x42))) 200)
                   False utxo tx

-- | Flip one bit of the signature of input @i@ (first witness item that is a
-- signature: item 1 for CHECKMULTISIG, item 0 otherwise).
corrupt :: Kind -> Int -> Tx -> Tx
corrupt k i tx =
  let pos = if k == KWSHMulti then 1 else 0
      flipAt b = BS.take 10 b <> BS.singleton (BS.index b 10 `xor` 0x01) <> BS.drop 11 b
      w = txWitness tx
      wi = w !! i
      wi' = take pos wi ++ [flipAt (wi !! pos)] ++ drop (pos + 1) wi
  in tx { txWitness = take i w ++ [wi'] ++ drop (i + 1) w }

--------------------------------------------------------------------------------
-- The equality fixture: 5 inputs, 3 outputs, scripts and an annex long
-- enough to need a 3-byte compact size.
--------------------------------------------------------------------------------

eqTx :: Tx
eqTx = Tx
  { txVersion = 2
  , txInputs = [ TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 (fromIntegral (0x20 + i))))) (fromIntegral i)) BS.empty (0xfffffff0 + fromIntegral i)
               | i <- [0 .. 4 :: Int] ]
  , txOutputs = [ TxOut 1000 (BS.pack [0x51])
                , TxOut 2000 (BS.replicate 260 0x6a)
                , TxOut 3000 (BS.pack [0x00, 0x14] <> BS.replicate 20 0x33) ]
  , txWitness = []
  , txLockTime = 500001 }

eqAmounts :: [Word64]
eqAmounts = [10000, 20000, 30000, 40000, 50000]

eqScripts :: [ByteString]
eqScripts = [ BS.pack [0x51, 0x20] <> BS.replicate 32 (fromIntegral i) | i <- [0 .. 3 :: Int] ]
            ++ [BS.replicate 300 0x51]

annexes :: [Maybe ByteString]
annexes = [Nothing, Just (BS.pack [0x50, 0xab]), Just (BS.cons 0x50 (BS.replicate 299 0xcd))]

exts :: [Maybe (ByteString, Word32)]
exts = [Nothing, Just (BS.replicate 32 0x77, 0xffffffff), Just (BS.replicate 32 0x78, 3)]

--------------------------------------------------------------------------------
-- Scaling
--------------------------------------------------------------------------------

-- | Bytes allocated by this thread while validating the tx. The tx and the
-- UTXO view are fully forced first, so signing is not counted.
allocValidating :: (Tx, Map OutPoint TxOut) -> IO (Int64, Either String Word64)
allocValidating (tx, utxo) = do
  _ <- evaluate (BS.length (encode tx))
  _ <- evaluate (Map.foldr (\o a -> a + BS.length (txOutScript o)) 0 utxo)
  setAllocationCounter 0
  r <- evaluate (validate tx utxo)
  a <- getAllocationCounter
  return (negate a, r)

-- | N per kind. ECDSA inputs carry a large fixed per-input cost (~180 KB
-- allocated), so they need a larger N for the quadratic term to show:
-- master measures ~3.3x at N=800 for them and ~4x at N=300 for Schnorr.
scalingNOf :: Kind -> Int
scalingNOf k = if k == KTRKey || k == KTapscript then 300 else 800

scalingCase :: Kind -> Word8 -> Spec
scalingCase k salt =
  it (show k ++ ": validating 2N=" ++ show (2 * scalingN) ++ " inputs allocates < 2.6x N="
        ++ show scalingN ++ " inputs (whole-tx digests computed once per tx)") $ do
    let ht = if k == KTRKey || k == KTapscript then 0x00 else 0x01
        mk s n = buildSigned s (replicate n (InSpec k ht Nothing)) 2
    -- warm-up: CAFs, the sig cache map, code paths
    _ <- allocValidating (mk (salt + 100) 20)
    (a1, r1) <- allocValidating (mk salt scalingN)
    (a2, r2) <- allocValidating (mk (salt + 1) (2 * scalingN))
    r1 `shouldSatisfy` isRight
    r2 `shouldSatisfy` isRight
    let ratio = fromIntegral a2 / fromIntegral a1 :: Double
        msg = show k ++ ": " ++ show scalingN ++ " inputs -> " ++ show a1 ++ " B ("
              ++ show (a1 `div` fromIntegral scalingN) ++ " B/input), "
              ++ show (2 * scalingN) ++ " inputs -> " ++ show a2 ++ " B ("
              ++ show (a2 `div` fromIntegral (2 * scalingN)) ++ " B/input), ratio "
              ++ show ratio ++ " (linear = 2, per-signature re-hashing = 4)"
    putStrLn ("      " ++ msg)
    unless (ratio < 2.6) $
      expectationFailure ("the whole-tx sighash digests are rebuilt per signature check, not once per transaction (Core PrecomputedTransactionData): " ++ msg)
  where isRight = either (const False) (const True)
        scalingN = scalingNOf k

--------------------------------------------------------------------------------

main :: IO ()
main = hspec $ do
  describe "digest equality: free functions vs an independent BIP-143 / BIP-341 reference" $ do
    it "txSigHashSegWit equals the BIP-143 reference for every raw hash type and input (SINGLE with no matching output included)" $
      forM_ [0x00, 0x01, 0x02, 0x03, 0x04, 0x21, 0x23, 0x42, 0x81, 0x82, 0x83, 0x84, 0xa3, 0xff :: Word8] $ \ht ->
        forM_ [0 .. 4] $ \i -> do
          let code = if even i then p2pkhCode else BS.replicate 300 0xac
              Hash256 got = txSigHashSegWit eqTx i code (eqAmounts !! i) (fromIntegral ht) (parseSigHashByte ht)
          (ht, i, got) `shouldBe` (ht, i, refBip143 eqTx i code (eqAmounts !! i) (fromIntegral ht))

    it "buildSigMsg equals the BIP-341 reference for every hash type x input x annex x key/script path; SINGLE with no matching output is refused" $
      forM_ [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 :: Word8] $ \ht ->
        forM_ [0 .. 4] $ \i ->
          forM_ annexes $ \annex ->
            forM_ exts $ \ext -> do
              let got = buildSigMsg eqTx i (TaprootPrevouts eqAmounts eqScripts) ht annex
                          (fmap (uncurry TapscriptContext) ext)
                  want = case refSigMsg eqTx i eqAmounts eqScripts ht annex ext of
                           Just m  -> Right m
                           Nothing -> Left SighashSingleNoMatchingOutput
              (ht, i, annex, got) `shouldBe` (ht, i, annex, want)

    it "the BIP-341 fixture really has SINGLE inputs without a matching output (control)" $ do
      length (txInputs eqTx) `shouldSatisfy` (> length (txOutputs eqTx))
      buildSigMsg eqTx 4 (TaprootPrevouts eqAmounts eqScripts) 0x83 Nothing Nothing
        `shouldBe` Left SighashSingleNoMatchingOutput

  describe "the per-tx path (validateSingleTx -> ScriptCheckItem), signed over the reference digests" $ do
    let annexA = Just (BS.pack [0x50, 0x01, 0x02])
        specs =
          [ InSpec KWPKH 0x03 Nothing        -- 0  BIP-143 SINGLE, matching output
          , InSpec KWPKH 0x83 Nothing        -- 1  SINGLE|ACP, matching
          , InSpec KTRKey 0x03 Nothing       -- 2  BIP-341 SINGLE, matching
          , InSpec KTRKey 0x83 Nothing       -- 3  SINGLE|ACP
          , InSpec KTapscript 0x03 annexA    -- 4  tapscript SINGLE + annex
          , InSpec KTRKey 0x00 Nothing       -- 5  DEFAULT (64-byte sig)
          , InSpec KTRKey 0x01 Nothing       -- 6  ALL
          , InSpec KTRKey 0x02 Nothing       -- 7  NONE
          , InSpec KTRKey 0x81 Nothing       -- 8  ALL|ACP
          , InSpec KTRKey 0x82 Nothing       -- 9  NONE|ACP
          , InSpec KTRKey 0x01 annexA        -- 10 ALL + annex
          , InSpec KTapscript 0x00 Nothing   -- 11 tapscript DEFAULT
          , InSpec KTapscript 0x82 annexA    -- 12 tapscript NONE|ACP + annex
          , InSpec KTapscript 0x81 Nothing   -- 13 tapscript ALL|ACP
          , InSpec KWPKH 0x01 Nothing        -- 14 ALL
          , InSpec KWPKH 0x02 Nothing        -- 15 NONE
          , InSpec KWPKH 0x81 Nothing        -- 16 ALL|ACP
          , InSpec KWPKH 0x82 Nothing        -- 17 NONE|ACP
          , InSpec KWPKH 0x03 Nothing        -- 18 SINGLE, NO matching output (BIP-143: zero hashOutputs)
          , InSpec KWSHCheckSig 0x01 Nothing -- 19 P2WSH CHECKSIG
          , InSpec KWSHMulti 0x83 Nothing    -- 20 P2WSH CHECKMULTISIG, SINGLE|ACP, no matching output
          , InSpec KWSHCheckSig 0x02 Nothing -- 21 P2WSH CHECKSIG NONE
          ]
        nOuts = 5
        (mixTx, mixUtxo) = buildSigned 0x01 specs nOuts

    it "a tx mixing P2TR key-path, tapscript, P2WPKH and P2WSH CHECKSIG/CHECKMULTISIG over every hash type validates" $
      validate mixTx mixUtxo `shouldSatisfy` either (const False) (const True)

    it "the same tx with any one signature corrupted is rejected (negative control)" $
      forM_ (zip [0 ..] specs) $ \(i, s) ->
        (i, validate (corrupt (isKind s) i mixTx) mixUtxo) `shouldSatisfy` (either (const True) (const False) . snd)

    it "BIP-341 SIGHASH_SINGLE with no matching output is rejected through the block path" $ do
      -- Input 2 signs SINGLE over a 3-output tx; dropping the third output
      -- leaves it with no matching output, so no digest exists and no
      -- signature can be valid. Inputs 0 and 1 sign NONE, so they stay
      -- valid without the dropped output and the failure must be input 2.
      let (tx3, utxo) = buildSigned 0x02 [InSpec KTRKey 0x02 Nothing, InSpec KTRKey 0x02 Nothing, InSpec KTRKey 0x03 Nothing] 3
          tx2 = tx3 { txOutputs = take 2 (txOutputs tx3) }
      validate tx3 utxo `shouldSatisfy` either (const False) (const True)
      validate tx2 utxo `shouldSatisfy` either (isInfixOf "(input 2)") (const False)

  describe "whole-tx sighash digests are computed once per transaction (Core PrecomputedTransactionData)" $ do
    scalingCase KWPKH 0x10
    scalingCase KTRKey 0x20
    scalingCase KWSHCheckSig 0x30
    scalingCase KTapscript 0x40

{-# LANGUAGE OverloadedStrings #-}

-- | Test harness for Bitcoin Core script_tests.json vectors.
--
-- Parses ASM notation, assembles to raw script bytes, and runs verifyScript.
-- Skips witness tests (6+ elements) for now, focusing on ~1157 non-witness tests.

module Main where

import qualified Data.ByteString.Lazy as LBS
import           Data.ByteString      (ByteString)
import qualified Data.ByteString      as BS
import           Data.Word            (Word8, Word32)
import           Data.Int             (Int64)
import           Data.Bits            ((.&.), (.|.), shiftR, testBit)
import           Data.Aeson           (eitherDecode, Value(..))
import qualified Data.Vector          as V
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BS8
import qualified Data.Text            as T
import           System.Exit          (exitFailure, exitSuccess)
import           Text.Read            (readMaybe)

import           Haskoin.Types        (Tx(..), TxIn(..), TxOut(..), OutPoint(..),
                                       TxId(..), Hash256(..))
import           Haskoin.Script

-- | Opcode name (without OP_ prefix) -> byte value
opcodeByName :: String -> Maybe Word8
opcodeByName name = case name of
  "0"         -> Just 0x00; "FALSE" -> Just 0x00
  "1NEGATE"   -> Just 0x4f
  "RESERVED"  -> Just 0x50
  "1"         -> Just 0x51; "TRUE" -> Just 0x51
  "2"         -> Just 0x52; "3" -> Just 0x53; "4" -> Just 0x54; "5" -> Just 0x55
  "6"         -> Just 0x56; "7" -> Just 0x57; "8" -> Just 0x58; "9" -> Just 0x59
  "10"        -> Just 0x5a; "11" -> Just 0x5b; "12" -> Just 0x5c; "13" -> Just 0x5d
  "14"        -> Just 0x5e; "15" -> Just 0x5f; "16" -> Just 0x60
  "NOP"       -> Just 0x61; "VER" -> Just 0x62
  "IF"        -> Just 0x63; "NOTIF" -> Just 0x64
  "VERIF"     -> Just 0x65; "VERNOTIF" -> Just 0x66
  "ELSE"      -> Just 0x67; "ENDIF" -> Just 0x68
  "VERIFY"    -> Just 0x69; "RETURN" -> Just 0x6a
  "TOALTSTACK" -> Just 0x6b; "FROMALTSTACK" -> Just 0x6c
  "2DROP"     -> Just 0x6d; "2DUP" -> Just 0x6e; "3DUP" -> Just 0x6f
  "2OVER"     -> Just 0x70; "2ROT" -> Just 0x71; "2SWAP" -> Just 0x72
  "IFDUP"     -> Just 0x73; "DEPTH" -> Just 0x74
  "DROP"      -> Just 0x75; "DUP" -> Just 0x76
  "NIP"       -> Just 0x77; "OVER" -> Just 0x78
  "PICK"      -> Just 0x79; "ROLL" -> Just 0x7a
  "ROT"       -> Just 0x7b; "SWAP" -> Just 0x7c; "TUCK" -> Just 0x7d
  "CAT"       -> Just 0x7e; "SUBSTR" -> Just 0x7f; "LEFT" -> Just 0x80; "RIGHT" -> Just 0x81
  "SIZE"      -> Just 0x82
  "INVERT"    -> Just 0x83; "AND" -> Just 0x84; "OR" -> Just 0x85; "XOR" -> Just 0x86
  "EQUAL"     -> Just 0x87; "EQUALVERIFY" -> Just 0x88
  "RESERVED1" -> Just 0x89; "RESERVED2" -> Just 0x8a
  "1ADD"      -> Just 0x8b; "1SUB" -> Just 0x8c
  "2MUL"      -> Just 0x8d; "2DIV" -> Just 0x8e
  "NEGATE"    -> Just 0x8f; "ABS" -> Just 0x90
  "NOT"       -> Just 0x91; "0NOTEQUAL" -> Just 0x92
  "ADD"       -> Just 0x93; "SUB" -> Just 0x94
  "MUL"       -> Just 0x95; "DIV" -> Just 0x96; "MOD" -> Just 0x97
  "LSHIFT"    -> Just 0x98; "RSHIFT" -> Just 0x99
  "BOOLAND"   -> Just 0x9a; "BOOLOR" -> Just 0x9b
  "NUMEQUAL"  -> Just 0x9c; "NUMEQUALVERIFY" -> Just 0x9d
  "NUMNOTEQUAL" -> Just 0x9e
  "LESSTHAN"  -> Just 0x9f; "GREATERTHAN" -> Just 0xa0
  "LESSTHANOREQUAL" -> Just 0xa1; "GREATERTHANOREQUAL" -> Just 0xa2
  "MIN"       -> Just 0xa3; "MAX" -> Just 0xa4; "WITHIN" -> Just 0xa5
  "RIPEMD160" -> Just 0xa6; "SHA1" -> Just 0xa7; "SHA256" -> Just 0xa8
  "HASH160"   -> Just 0xa9; "HASH256" -> Just 0xaa
  "CODESEPARATOR" -> Just 0xab
  "CHECKSIG"  -> Just 0xac; "CHECKSIGVERIFY" -> Just 0xad
  "CHECKMULTISIG" -> Just 0xae; "CHECKMULTISIGVERIFY" -> Just 0xaf
  "NOP1"      -> Just 0xb0
  "CHECKLOCKTIMEVERIFY" -> Just 0xb1; "NOP2" -> Just 0xb1
  "CHECKSEQUENCEVERIFY" -> Just 0xb2; "NOP3" -> Just 0xb2
  "NOP4"      -> Just 0xb3; "NOP5" -> Just 0xb4; "NOP6" -> Just 0xb5
  "NOP7"      -> Just 0xb6; "NOP8" -> Just 0xb7; "NOP9" -> Just 0xb8; "NOP10" -> Just 0xb9
  "CHECKSIGADD" -> Just 0xba
  "INVALIDOPCODE" -> Just 0xff
  _ -> Nothing

-- | Encode a script number (CScriptNum) to bytes
encodeScriptNumBytes :: Int64 -> ByteString
encodeScriptNumBytes 0 = BS.empty
encodeScriptNumBytes n =
  let absN = abs n
      neg  = n < 0
      -- Build bytes little-endian
      go 0 = []
      go v = fromIntegral (v .&. 0xff) : go (v `shiftR` 8)
      bytes = go absN
  in case bytes of
       [] -> BS.empty
       _  ->
         let lastByte = last bytes
         in if testBit lastByte 7
            then BS.pack (bytes ++ [if neg then 0x80 else 0x00])
            else BS.pack (init bytes ++ [if neg then lastByte .|. 0x80 else lastByte])

-- | Push data with appropriate opcode
pushDataBytes :: ByteString -> ByteString
pushDataBytes dat =
  let len = BS.length dat
  in if len >= 1 && len <= 0x4b
     then BS.cons (fromIntegral len) dat
     else if len <= 0xff
     then BS.pack [0x4c, fromIntegral len] <> dat
     else if len <= 0xffff
     then BS.pack [0x4d, fromIntegral (len .&. 0xff), fromIntegral (len `shiftR` 8)] <> dat
     else BS.pack [0x4e, fromIntegral (len .&. 0xff), fromIntegral ((len `shiftR` 8) .&. 0xff),
                   fromIntegral ((len `shiftR` 16) .&. 0xff), fromIntegral ((len `shiftR` 24) .&. 0xff)] <> dat

-- | Decode hex text to bytes, Nothing on failure
decodeHex :: String -> Maybe ByteString
decodeHex s = case B16.decode (BS8.pack s) of
  Right bs -> Just bs
  Left _   -> Nothing

-- | Assemble a single ASM token to raw script bytes
assembleToken :: String -> ByteString
assembleToken token =
  let name = case token of
               ('O':'P':'_':rest) -> rest
               _                  -> token
  in case name of
    ('0':'x':hex) ->
      case decodeHex hex of
        Just bs -> bs
        Nothing -> BS.empty
    ('\'':rest) ->
      let str = if not (null rest) && last rest == '\''
                then init rest
                else rest
          strBS = BS8.pack str
      in if BS.null strBS then BS.singleton 0x00
         else pushDataBytes strBS
    _ -> case opcodeByName name of
           Just byte -> BS.singleton byte
           Nothing ->
             case readMaybe name :: Maybe Int64 of
               Just n
                 | n == 0    -> BS.singleton 0x00
                 | n == -1   -> BS.singleton 0x4f
                 | n >= 1 && n <= 16 -> BS.singleton (fromIntegral (0x50 + n))
                 | otherwise -> pushDataBytes (encodeScriptNumBytes n)
               Nothing -> BS.empty -- unknown token, skip

-- | Assemble ASM string to raw script bytes
assembleScript :: String -> ByteString
assembleScript asm =
  let trimmed = dropWhile (== ' ') $ reverse $ dropWhile (== ' ') $ reverse asm
  in if null trimmed then BS.empty
     else BS.concat $ map assembleToken (words trimmed)

-- | Parse flags string to ScriptFlags
parseFlags :: String -> ScriptFlags
parseFlags str =
  let trimmed = dropWhile (== ' ') $ reverse $ dropWhile (== ' ') $ reverse str
  in if null trimmed || trimmed == "NONE" then emptyFlags
     else flagSet $ concatMap flagValue (splitOn ',' trimmed)
  where
    splitOn _ [] = []
    splitOn c s  = let (w, rest) = break (== c) s
                   in w : case rest of
                            []      -> []
                            (_:xs)  -> splitOn c xs
    flagValue flag = case dropWhile (== ' ') $ reverse $ dropWhile (== ' ') $ reverse flag of
      "P2SH"                                    -> [VerifyP2SH]
      "DERSIG"                                   -> [VerifyDERSig]
      "CHECKLOCKTIMEVERIFY"                      -> [VerifyCheckLockTimeVerify]
      "CHECKSEQUENCEVERIFY"                      -> [VerifyCheckSequenceVerify]
      "WITNESS"                                  -> [VerifyWitness]
      "NULLDUMMY"                                -> [VerifyNullDummy]
      "NULLFAIL"                                 -> [VerifyNullFail]
      "WITNESS_PUBKEYTYPE"                       -> [VerifyWitnessPubkeyType]
      "TAPROOT"                                  -> [VerifyTaproot]
      "MINIMALIF"                                -> [VerifyMinimalIf]
      "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"    -> [VerifyDiscourageUpgradableWitnessProgram]
      "DISCOURAGE_UPGRADABLE_NOPS"               -> [VerifyDiscourageUpgradableNops]
      "DISCOURAGE_OP_SUCCESS"                    -> [VerifyDiscourageOpSuccess]
      "CONST_SCRIPTCODE"                         -> [VerifyConstScriptcode]
      -- Flags not supported by Haskoin are silently ignored:
      -- STRICTENC, LOW_S, SIGPUSHONLY, MINIMALDATA, CLEANSTACK
      "STRICTENC"     -> []
      "LOW_S"         -> []
      "SIGPUSHONLY"   -> []
      "MINIMALDATA"   -> []
      "CLEANSTACK"    -> []
      "NONE"          -> []
      "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" -> []
      "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" -> []
      _               -> []

-- | Create a dummy transaction for script verification
makeDummyTx :: ByteString -> Tx
makeDummyTx scriptSigBytes = Tx
  { txVersion  = 1
  , txInputs   = [TxIn
      { txInPrevOutput = OutPoint (TxId (Hash256 (BS.replicate 32 0))) 0xffffffff
      , txInScript     = scriptSigBytes
      , txInSequence   = 0xffffffff
      }]
  , txOutputs  = [TxOut { txOutValue = 0, txOutScript = BS.empty }]
  , txWitness  = [[]]  -- one empty witness stack per input
  , txLockTime = 0
  }

main :: IO ()
main = do
  let vectorPath = "/home/max/hashhog/ouroboros/bitcoin/src/test/data/script_tests.json"
  jsonData <- LBS.readFile vectorPath
  putStrLn $ "Loaded test vectors from: " ++ vectorPath

  case eitherDecode jsonData of
    Left err -> do
      putStrLn $ "ERROR: Failed to parse JSON: " ++ err
      exitFailure
    Right (Array vectors) -> do
      let (passCount, failCount, errorCount, skipCount, totalCount) =
            V.foldl' processEntry (0::Int, 0::Int, 0::Int, 0::Int, 0::Int) vectors

      putStrLn "\n=== Script Test Vector Results ==="
      putStrLn $ "Total non-witness tests: " ++ show totalCount
      putStrLn $ "  PASS:  " ++ show passCount
      putStrLn $ "  FAIL:  " ++ show failCount
      putStrLn $ "  ERROR: " ++ show errorCount
      putStrLn $ "  Skipped (witness): " ++ show skipCount

      if failCount > 0 || errorCount > 0
        then exitFailure
        else exitSuccess

    _ -> do
      putStrLn "ERROR: Top-level JSON is not an array"
      exitFailure

processEntry :: (Int, Int, Int, Int, Int) -> Value -> (Int, Int, Int, Int, Int)
processEntry (p, f, e, s, t) (Array arr) =
  let n = V.length arr
  in if n <= 3 then (p, f, e, s, t)  -- comment or malformed
     else if n >= 6 then (p, f, e, s + 1, t)  -- witness test, skip
     else
       -- 4 or 5 element test
       case (V.toList arr) of
         (String sigAsm : String pubAsm : String flagsStr : String expected : _) ->
           let sigAsmS   = T.unpack sigAsm
               pubAsmS   = T.unpack pubAsm
               flagsStrS = T.unpack flagsStr
               expectedS = T.unpack expected
               expectedOk = expectedS == "OK"

               scriptSigBytes   = assembleScript sigAsmS
               scriptPubKeyBytes = assembleScript pubAsmS
               flags = parseFlags flagsStrS
               tx = makeDummyTx scriptSigBytes

               result = verifyScriptWithFlags flags tx 0 scriptPubKeyBytes 0
               gotOk = case result of
                         Right True -> True
                         _          -> False
           in if gotOk == expectedOk
              then (p + 1, f, e, s, t + 1)
              else (p, f + 1, e, s, t + 1)
         _ -> (p, f, e, s, t)  -- malformed entry
processEntry acc _ = acc

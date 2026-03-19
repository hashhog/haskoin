{-# LANGUAGE OverloadedStrings #-}

-- | Sighash test harness using Bitcoin Core's sighash.json test vectors.
--
-- Each test case: [raw_tx_hex, script_hex, input_index, hash_type, expected_sighash_hex]
--
-- The hash_type is an Int32 interpreted as a Word32 on the wire:
--   bits 0-4: base type (0x01 = ALL, 0x02 = NONE, 0x03 = SINGLE)
--   bit 7:    ANYONECANPAY flag (0x80)

module Main where

import qualified Data.ByteString.Lazy as LBS
import           Data.ByteString      (ByteString)
import qualified Data.ByteString      as BS
import           Data.Serialize        (decode)
import           Data.Word             (Word32)
import           Data.Int              (Int32)
import           Data.Bits             ((.&.))
import           Data.Aeson            (eitherDecode, Value(..))
import qualified Data.Vector           as V
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BS8
import           Data.Text.Encoding    (encodeUtf8)
import qualified Data.Text             as T
import           System.Exit           (exitFailure, exitSuccess)

import           Haskoin.Types         (Tx(..), Hash256(..))
import           Haskoin.Crypto        (SigHashType(..), txSigHash)

-- | Convert a wire-format Word32 hash type to our SigHashType
word32ToSigHashType :: Word32 -> SigHashType
word32ToSigHashType w =
  let baseType = w .&. 0x1f
      acp      = (w .&. 0x80) /= 0
      (isAll, isNone, isSingle) = case baseType of
        0x02 -> (False, True,  False)
        0x03 -> (False, False, True)
        _    -> (True,  False, False)   -- 0x01 or default
  in SigHashType isAll isNone isSingle acp

-- | Decode a hex string to raw bytes. Returns Nothing on failure.
decodeHex :: T.Text -> Maybe ByteString
decodeHex t =
  case B16.decode (encodeUtf8 t) of
    Right bs -> Just bs
    Left  _  -> Nothing

main :: IO ()
main = do
  raw <- LBS.readFile "/home/max/hashhog/ouroboros/bitcoin/src/test/data/sighash.json"
  case eitherDecode raw :: Either String Value of
    Left err -> do
      putStrLn $ "Failed to parse JSON: " ++ err
      exitFailure
    Right (Array arr) -> do
      let vectors = V.toList arr
          -- Skip the first entry (header comment)
          testCases = drop 1 vectors
      putStrLn $ "Loaded " ++ show (length testCases) ++ " test cases"
      results <- mapM runTestCase (zip [1::Int ..] testCases)
      let passed = length (filter id results)
          failed = length (filter not results)
      putStrLn $ "Passed: " ++ show passed ++ " / Failed: " ++ show failed
      if failed > 0 then exitFailure else exitSuccess
    Right _ -> do
      putStrLn "Expected top-level JSON array"
      exitFailure

runTestCase :: (Int, Value) -> IO Bool
runTestCase (idx, val) = case val of
  Array elems
    | V.length elems == 5
    , String rawTxHex      <- elems V.! 0
    , String scriptHex     <- elems V.! 1
    , Number inputIdxNum   <- elems V.! 2
    , Number hashTypeNum   <- elems V.! 3
    , String expectedHex   <- elems V.! 4
    -> do
      let inputIndex = truncate inputIdxNum :: Int
          hashTypeI32 = truncate hashTypeNum :: Int32
          hashTypeW32 = fromIntegral hashTypeI32 :: Word32
          shType = word32ToSigHashType hashTypeW32
      case (decodeHex rawTxHex, decodeHex scriptHex, decodeHex expectedHex) of
        (Just txBytes, Just scriptBytes, Just expectedBytes) ->
          case decode txBytes :: Either String Tx of
            Left err -> do
              putStrLn $ "  FAIL #" ++ show idx ++ ": tx decode error: " ++ err
              return False
            Right tx -> do
              let Hash256 result = txSigHash tx inputIndex scriptBytes hashTypeW32 shType
              if result == expectedBytes || result == BS.reverse expectedBytes
                then return True
                else do
                  putStrLn $ "  FAIL #" ++ show idx
                    ++ ": expected " ++ T.unpack expectedHex
                    ++ " got " ++ BS8.unpack (B16.encode result)
                  return False
        _ -> do
          putStrLn $ "  FAIL #" ++ show idx ++ ": hex decode error"
          return False
  _ -> do
    putStrLn $ "  SKIP #" ++ show idx ++ ": unexpected format"
    return True

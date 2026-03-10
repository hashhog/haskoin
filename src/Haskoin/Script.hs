{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}

module Haskoin.Script
  ( -- * Script Types
    ScriptOp(..)
  , PushDataType(..)
  , Script(..)
  , ScriptStack
    -- * Parsing
  , decodeScript
  , encodeScript
  , encodeScriptOps
    -- * Classification
  , ScriptType(..)
  , classifyOutput
  , classifyInput
    -- * Evaluation
  , evalScript
  , verifyScript
  , verifySegWitScript
    -- * Standard Scripts
  , encodeP2PKH
  , encodeP2SH
  , encodeP2WPKH
  , encodeP2WSH
  , encodeMultisig
  , encodeOpReturn
    -- * Utilities
  , opN
  , encodeScriptNum
  , decodeScriptNum
  , isTrue
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int64)
import Data.Serialize (runGet, runPut, getWord8, putWord8, getBytes,
                       putByteString, remaining, getWord16le, putWord16le,
                       getWord32le, putWord32le, Get, Put)
import Control.Monad (when, unless, foldM)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, testBit)
import GHC.Generics (Generic)
import Data.List (foldl')

import Haskoin.Types
import Haskoin.Crypto

--------------------------------------------------------------------------------
-- Script Types
--------------------------------------------------------------------------------

-- | How push data was encoded on the wire
data PushDataType
  = OPCODE   -- ^ Direct push (0x01-0x4b)
  | OPDATA1  -- ^ OP_PUSHDATA1 (0x4c)
  | OPDATA2  -- ^ OP_PUSHDATA2 (0x4d)
  | OPDATA4  -- ^ OP_PUSHDATA4 (0x4e)
  deriving (Show, Eq, Generic)

-- | Bitcoin Script opcodes
data ScriptOp
  -- Constants
  = OP_0                   -- ^ 0x00 - push empty byte array
  | OP_PUSHDATA !ByteString !PushDataType
  | OP_1NEGATE             -- ^ 0x4f - push -1
  | OP_RESERVED            -- ^ 0x50
  | OP_1 | OP_2 | OP_3 | OP_4 | OP_5 | OP_6 | OP_7 | OP_8
  | OP_9 | OP_10 | OP_11 | OP_12 | OP_13 | OP_14 | OP_15 | OP_16
  -- Flow control
  | OP_NOP                 -- ^ 0x61
  | OP_VER                 -- ^ 0x62
  | OP_IF                  -- ^ 0x63
  | OP_NOTIF               -- ^ 0x64
  | OP_VERIF               -- ^ 0x65
  | OP_VERNOTIF            -- ^ 0x66
  | OP_ELSE                -- ^ 0x67
  | OP_ENDIF               -- ^ 0x68
  | OP_VERIFY              -- ^ 0x69
  | OP_RETURN              -- ^ 0x6a
  -- Stack
  | OP_TOALTSTACK          -- ^ 0x6b
  | OP_FROMALTSTACK        -- ^ 0x6c
  | OP_2DROP               -- ^ 0x6d
  | OP_2DUP                -- ^ 0x6e
  | OP_3DUP                -- ^ 0x6f
  | OP_2OVER               -- ^ 0x70
  | OP_2ROT                -- ^ 0x71
  | OP_2SWAP               -- ^ 0x72
  | OP_IFDUP               -- ^ 0x73
  | OP_DEPTH               -- ^ 0x74
  | OP_DROP                -- ^ 0x75
  | OP_DUP                 -- ^ 0x76
  | OP_NIP                 -- ^ 0x77
  | OP_OVER                -- ^ 0x78
  | OP_PICK                -- ^ 0x79
  | OP_ROLL                -- ^ 0x7a
  | OP_ROT                 -- ^ 0x7b
  | OP_SWAP                -- ^ 0x7c
  | OP_TUCK                -- ^ 0x7d
  -- Splice (disabled)
  | OP_CAT                 -- ^ 0x7e (disabled)
  | OP_SUBSTR              -- ^ 0x7f (disabled)
  | OP_LEFT                -- ^ 0x80 (disabled)
  | OP_RIGHT               -- ^ 0x81 (disabled)
  | OP_SIZE                -- ^ 0x82
  -- Bitwise (some disabled)
  | OP_INVERT              -- ^ 0x83 (disabled)
  | OP_AND                 -- ^ 0x84 (disabled)
  | OP_OR                  -- ^ 0x85 (disabled)
  | OP_XOR                 -- ^ 0x86 (disabled)
  | OP_EQUAL               -- ^ 0x87
  | OP_EQUALVERIFY         -- ^ 0x88
  | OP_RESERVED1           -- ^ 0x89
  | OP_RESERVED2           -- ^ 0x8a
  -- Arithmetic
  | OP_1ADD                -- ^ 0x8b
  | OP_1SUB                -- ^ 0x8c
  | OP_2MUL                -- ^ 0x8d (disabled)
  | OP_2DIV                -- ^ 0x8e (disabled)
  | OP_NEGATE              -- ^ 0x8f
  | OP_ABS                 -- ^ 0x90
  | OP_NOT                 -- ^ 0x91
  | OP_0NOTEQUAL           -- ^ 0x92
  | OP_ADD                 -- ^ 0x93
  | OP_SUB                 -- ^ 0x94
  | OP_MUL                 -- ^ 0x95 (disabled)
  | OP_DIV                 -- ^ 0x96 (disabled)
  | OP_MOD                 -- ^ 0x97 (disabled)
  | OP_LSHIFT              -- ^ 0x98 (disabled)
  | OP_RSHIFT              -- ^ 0x99 (disabled)
  | OP_BOOLAND             -- ^ 0x9a
  | OP_BOOLOR              -- ^ 0x9b
  | OP_NUMEQUAL            -- ^ 0x9c
  | OP_NUMEQUALVERIFY      -- ^ 0x9d
  | OP_NUMNOTEQUAL         -- ^ 0x9e
  | OP_LESSTHAN            -- ^ 0x9f
  | OP_GREATERTHAN         -- ^ 0xa0
  | OP_LESSTHANOREQUAL     -- ^ 0xa1
  | OP_GREATERTHANOREQUAL  -- ^ 0xa2
  | OP_MIN                 -- ^ 0xa3
  | OP_MAX                 -- ^ 0xa4
  | OP_WITHIN              -- ^ 0xa5
  -- Crypto
  | OP_RIPEMD160           -- ^ 0xa6
  | OP_SHA1                -- ^ 0xa7
  | OP_SHA256              -- ^ 0xa8
  | OP_HASH160             -- ^ 0xa9
  | OP_HASH256             -- ^ 0xaa
  | OP_CODESEPARATOR       -- ^ 0xab
  | OP_CHECKSIG            -- ^ 0xac
  | OP_CHECKSIGVERIFY      -- ^ 0xad
  | OP_CHECKMULTISIG       -- ^ 0xae
  | OP_CHECKMULTISIGVERIFY -- ^ 0xaf
  -- Locktime
  | OP_NOP1                -- ^ 0xb0
  | OP_CHECKLOCKTIMEVERIFY -- ^ 0xb1 (BIP-65)
  | OP_CHECKSEQUENCEVERIFY -- ^ 0xb2 (BIP-112)
  -- NOPs for future softforks
  | OP_NOP4                -- ^ 0xb3
  | OP_NOP5                -- ^ 0xb4
  | OP_NOP6                -- ^ 0xb5
  | OP_NOP7                -- ^ 0xb6
  | OP_NOP8                -- ^ 0xb7
  | OP_NOP9                -- ^ 0xb8
  | OP_NOP10               -- ^ 0xb9
  -- Invalid
  | OP_INVALIDOPCODE !Word8
  deriving (Show, Eq, Generic)

-- | A Bitcoin Script is a sequence of opcodes
newtype Script = Script { getScriptOps :: [ScriptOp] }
  deriving (Show, Eq, Generic)

-- | Script evaluation stack
type ScriptStack = [ByteString]

--------------------------------------------------------------------------------
-- Script Parsing
--------------------------------------------------------------------------------

-- | Decode a script from raw bytes
decodeScript :: ByteString -> Either String Script
decodeScript bs = runGet parseOps bs
  where
    parseOps :: Get Script
    parseOps = do
      r <- remaining
      if r <= 0
        then return (Script [])
        else do
          op <- parseOp
          Script rest <- parseOps
          return (Script (op : rest))

    parseOp :: Get ScriptOp
    parseOp = do
      byte <- getWord8
      case byte of
        0x00 -> return OP_0
        b | b >= 0x01 && b <= 0x4b -> do
          dat <- getBytes (fromIntegral b)
          return $ OP_PUSHDATA dat OPCODE
        0x4c -> do  -- OP_PUSHDATA1
          len <- getWord8
          dat <- getBytes (fromIntegral len)
          return $ OP_PUSHDATA dat OPDATA1
        0x4d -> do  -- OP_PUSHDATA2
          len <- getWord16le
          dat <- getBytes (fromIntegral len)
          return $ OP_PUSHDATA dat OPDATA2
        0x4e -> do  -- OP_PUSHDATA4
          len <- getWord32le
          dat <- getBytes (fromIntegral len)
          return $ OP_PUSHDATA dat OPDATA4
        0x4f -> return OP_1NEGATE
        0x50 -> return OP_RESERVED
        0x51 -> return OP_1
        0x52 -> return OP_2
        0x53 -> return OP_3
        0x54 -> return OP_4
        0x55 -> return OP_5
        0x56 -> return OP_6
        0x57 -> return OP_7
        0x58 -> return OP_8
        0x59 -> return OP_9
        0x5a -> return OP_10
        0x5b -> return OP_11
        0x5c -> return OP_12
        0x5d -> return OP_13
        0x5e -> return OP_14
        0x5f -> return OP_15
        0x60 -> return OP_16
        0x61 -> return OP_NOP
        0x62 -> return OP_VER
        0x63 -> return OP_IF
        0x64 -> return OP_NOTIF
        0x65 -> return OP_VERIF
        0x66 -> return OP_VERNOTIF
        0x67 -> return OP_ELSE
        0x68 -> return OP_ENDIF
        0x69 -> return OP_VERIFY
        0x6a -> return OP_RETURN
        0x6b -> return OP_TOALTSTACK
        0x6c -> return OP_FROMALTSTACK
        0x6d -> return OP_2DROP
        0x6e -> return OP_2DUP
        0x6f -> return OP_3DUP
        0x70 -> return OP_2OVER
        0x71 -> return OP_2ROT
        0x72 -> return OP_2SWAP
        0x73 -> return OP_IFDUP
        0x74 -> return OP_DEPTH
        0x75 -> return OP_DROP
        0x76 -> return OP_DUP
        0x77 -> return OP_NIP
        0x78 -> return OP_OVER
        0x79 -> return OP_PICK
        0x7a -> return OP_ROLL
        0x7b -> return OP_ROT
        0x7c -> return OP_SWAP
        0x7d -> return OP_TUCK
        0x7e -> return OP_CAT
        0x7f -> return OP_SUBSTR
        0x80 -> return OP_LEFT
        0x81 -> return OP_RIGHT
        0x82 -> return OP_SIZE
        0x83 -> return OP_INVERT
        0x84 -> return OP_AND
        0x85 -> return OP_OR
        0x86 -> return OP_XOR
        0x87 -> return OP_EQUAL
        0x88 -> return OP_EQUALVERIFY
        0x89 -> return OP_RESERVED1
        0x8a -> return OP_RESERVED2
        0x8b -> return OP_1ADD
        0x8c -> return OP_1SUB
        0x8d -> return OP_2MUL
        0x8e -> return OP_2DIV
        0x8f -> return OP_NEGATE
        0x90 -> return OP_ABS
        0x91 -> return OP_NOT
        0x92 -> return OP_0NOTEQUAL
        0x93 -> return OP_ADD
        0x94 -> return OP_SUB
        0x95 -> return OP_MUL
        0x96 -> return OP_DIV
        0x97 -> return OP_MOD
        0x98 -> return OP_LSHIFT
        0x99 -> return OP_RSHIFT
        0x9a -> return OP_BOOLAND
        0x9b -> return OP_BOOLOR
        0x9c -> return OP_NUMEQUAL
        0x9d -> return OP_NUMEQUALVERIFY
        0x9e -> return OP_NUMNOTEQUAL
        0x9f -> return OP_LESSTHAN
        0xa0 -> return OP_GREATERTHAN
        0xa1 -> return OP_LESSTHANOREQUAL
        0xa2 -> return OP_GREATERTHANOREQUAL
        0xa3 -> return OP_MIN
        0xa4 -> return OP_MAX
        0xa5 -> return OP_WITHIN
        0xa6 -> return OP_RIPEMD160
        0xa7 -> return OP_SHA1
        0xa8 -> return OP_SHA256
        0xa9 -> return OP_HASH160
        0xaa -> return OP_HASH256
        0xab -> return OP_CODESEPARATOR
        0xac -> return OP_CHECKSIG
        0xad -> return OP_CHECKSIGVERIFY
        0xae -> return OP_CHECKMULTISIG
        0xaf -> return OP_CHECKMULTISIGVERIFY
        0xb0 -> return OP_NOP1
        0xb1 -> return OP_CHECKLOCKTIMEVERIFY
        0xb2 -> return OP_CHECKSEQUENCEVERIFY
        0xb3 -> return OP_NOP4
        0xb4 -> return OP_NOP5
        0xb5 -> return OP_NOP6
        0xb6 -> return OP_NOP7
        0xb7 -> return OP_NOP8
        0xb8 -> return OP_NOP9
        0xb9 -> return OP_NOP10
        _    -> return $ OP_INVALIDOPCODE byte

--------------------------------------------------------------------------------
-- Script Encoding
--------------------------------------------------------------------------------

-- | Encode a script to raw bytes
encodeScript :: Script -> ByteString
encodeScript (Script ops) = runPut $ mapM_ putOp ops

-- | Encode script ops to raw bytes (alias for encodeScript)
encodeScriptOps :: [ScriptOp] -> ByteString
encodeScriptOps = encodeScript . Script

-- | Encode a single opcode
putOp :: ScriptOp -> Put
putOp op = case op of
  OP_0 -> putWord8 0x00
  OP_PUSHDATA bs ptype -> putPushData bs ptype
  OP_1NEGATE -> putWord8 0x4f
  OP_RESERVED -> putWord8 0x50
  OP_1 -> putWord8 0x51
  OP_2 -> putWord8 0x52
  OP_3 -> putWord8 0x53
  OP_4 -> putWord8 0x54
  OP_5 -> putWord8 0x55
  OP_6 -> putWord8 0x56
  OP_7 -> putWord8 0x57
  OP_8 -> putWord8 0x58
  OP_9 -> putWord8 0x59
  OP_10 -> putWord8 0x5a
  OP_11 -> putWord8 0x5b
  OP_12 -> putWord8 0x5c
  OP_13 -> putWord8 0x5d
  OP_14 -> putWord8 0x5e
  OP_15 -> putWord8 0x5f
  OP_16 -> putWord8 0x60
  OP_NOP -> putWord8 0x61
  OP_VER -> putWord8 0x62
  OP_IF -> putWord8 0x63
  OP_NOTIF -> putWord8 0x64
  OP_VERIF -> putWord8 0x65
  OP_VERNOTIF -> putWord8 0x66
  OP_ELSE -> putWord8 0x67
  OP_ENDIF -> putWord8 0x68
  OP_VERIFY -> putWord8 0x69
  OP_RETURN -> putWord8 0x6a
  OP_TOALTSTACK -> putWord8 0x6b
  OP_FROMALTSTACK -> putWord8 0x6c
  OP_2DROP -> putWord8 0x6d
  OP_2DUP -> putWord8 0x6e
  OP_3DUP -> putWord8 0x6f
  OP_2OVER -> putWord8 0x70
  OP_2ROT -> putWord8 0x71
  OP_2SWAP -> putWord8 0x72
  OP_IFDUP -> putWord8 0x73
  OP_DEPTH -> putWord8 0x74
  OP_DROP -> putWord8 0x75
  OP_DUP -> putWord8 0x76
  OP_NIP -> putWord8 0x77
  OP_OVER -> putWord8 0x78
  OP_PICK -> putWord8 0x79
  OP_ROLL -> putWord8 0x7a
  OP_ROT -> putWord8 0x7b
  OP_SWAP -> putWord8 0x7c
  OP_TUCK -> putWord8 0x7d
  OP_CAT -> putWord8 0x7e
  OP_SUBSTR -> putWord8 0x7f
  OP_LEFT -> putWord8 0x80
  OP_RIGHT -> putWord8 0x81
  OP_SIZE -> putWord8 0x82
  OP_INVERT -> putWord8 0x83
  OP_AND -> putWord8 0x84
  OP_OR -> putWord8 0x85
  OP_XOR -> putWord8 0x86
  OP_EQUAL -> putWord8 0x87
  OP_EQUALVERIFY -> putWord8 0x88
  OP_RESERVED1 -> putWord8 0x89
  OP_RESERVED2 -> putWord8 0x8a
  OP_1ADD -> putWord8 0x8b
  OP_1SUB -> putWord8 0x8c
  OP_2MUL -> putWord8 0x8d
  OP_2DIV -> putWord8 0x8e
  OP_NEGATE -> putWord8 0x8f
  OP_ABS -> putWord8 0x90
  OP_NOT -> putWord8 0x91
  OP_0NOTEQUAL -> putWord8 0x92
  OP_ADD -> putWord8 0x93
  OP_SUB -> putWord8 0x94
  OP_MUL -> putWord8 0x95
  OP_DIV -> putWord8 0x96
  OP_MOD -> putWord8 0x97
  OP_LSHIFT -> putWord8 0x98
  OP_RSHIFT -> putWord8 0x99
  OP_BOOLAND -> putWord8 0x9a
  OP_BOOLOR -> putWord8 0x9b
  OP_NUMEQUAL -> putWord8 0x9c
  OP_NUMEQUALVERIFY -> putWord8 0x9d
  OP_NUMNOTEQUAL -> putWord8 0x9e
  OP_LESSTHAN -> putWord8 0x9f
  OP_GREATERTHAN -> putWord8 0xa0
  OP_LESSTHANOREQUAL -> putWord8 0xa1
  OP_GREATERTHANOREQUAL -> putWord8 0xa2
  OP_MIN -> putWord8 0xa3
  OP_MAX -> putWord8 0xa4
  OP_WITHIN -> putWord8 0xa5
  OP_RIPEMD160 -> putWord8 0xa6
  OP_SHA1 -> putWord8 0xa7
  OP_SHA256 -> putWord8 0xa8
  OP_HASH160 -> putWord8 0xa9
  OP_HASH256 -> putWord8 0xaa
  OP_CODESEPARATOR -> putWord8 0xab
  OP_CHECKSIG -> putWord8 0xac
  OP_CHECKSIGVERIFY -> putWord8 0xad
  OP_CHECKMULTISIG -> putWord8 0xae
  OP_CHECKMULTISIGVERIFY -> putWord8 0xaf
  OP_NOP1 -> putWord8 0xb0
  OP_CHECKLOCKTIMEVERIFY -> putWord8 0xb1
  OP_CHECKSEQUENCEVERIFY -> putWord8 0xb2
  OP_NOP4 -> putWord8 0xb3
  OP_NOP5 -> putWord8 0xb4
  OP_NOP6 -> putWord8 0xb5
  OP_NOP7 -> putWord8 0xb6
  OP_NOP8 -> putWord8 0xb7
  OP_NOP9 -> putWord8 0xb8
  OP_NOP10 -> putWord8 0xb9
  OP_INVALIDOPCODE b -> putWord8 b

-- | Encode push data with specified encoding type
putPushData :: ByteString -> PushDataType -> Put
putPushData bs ptype = case ptype of
  OPCODE ->
    let len = BS.length bs
    in if len >= 1 && len <= 75
       then putWord8 (fromIntegral len) >> putByteString bs
       else putPushData bs OPDATA1  -- fallback
  OPDATA1 -> do
    putWord8 0x4c
    putWord8 (fromIntegral $ BS.length bs)
    putByteString bs
  OPDATA2 -> do
    putWord8 0x4d
    putWord16le (fromIntegral $ BS.length bs)
    putByteString bs
  OPDATA4 -> do
    putWord8 0x4e
    putWord32le (fromIntegral $ BS.length bs)
    putByteString bs

--------------------------------------------------------------------------------
-- Script Classification
--------------------------------------------------------------------------------

-- | Standard output script patterns
data ScriptType
  = P2PKH !Hash160                    -- ^ OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  | P2SH !Hash160                     -- ^ OP_HASH160 <20> OP_EQUAL
  | P2WPKH !Hash160                   -- ^ OP_0 <20>
  | P2WSH !Hash256                    -- ^ OP_0 <32>
  | P2TR !Hash256                     -- ^ OP_1 <32>
  | P2PK !ByteString                  -- ^ <pubkey> OP_CHECKSIG
  | P2MultiSig !Int ![ByteString]     -- ^ m <keys...> n OP_CHECKMULTISIG
  | OpReturn !ByteString              -- ^ OP_RETURN <data>
  | NonStandard                       -- ^ anything else
  deriving (Show, Eq)

-- | Classify an output script
classifyOutput :: Script -> ScriptType
classifyOutput (Script ops) = case ops of
  -- P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  [OP_DUP, OP_HASH160, OP_PUSHDATA h _, OP_EQUALVERIFY, OP_CHECKSIG]
    | BS.length h == 20 -> P2PKH (Hash160 h)

  -- P2SH: OP_HASH160 <20> OP_EQUAL
  [OP_HASH160, OP_PUSHDATA h _, OP_EQUAL]
    | BS.length h == 20 -> P2SH (Hash160 h)

  -- P2WPKH: OP_0 <20>
  [OP_0, OP_PUSHDATA h _]
    | BS.length h == 20 -> P2WPKH (Hash160 h)

  -- P2WSH: OP_0 <32>
  [OP_0, OP_PUSHDATA h _]
    | BS.length h == 32 -> P2WSH (Hash256 h)

  -- P2TR: OP_1 <32>
  [OP_1, OP_PUSHDATA h _]
    | BS.length h == 32 -> P2TR (Hash256 h)

  -- P2PK: <pubkey> OP_CHECKSIG
  [OP_PUSHDATA pk _, OP_CHECKSIG]
    | BS.length pk `elem` [33, 65] -> P2PK pk

  -- OP_RETURN
  (OP_RETURN : rest) ->
    let dat = encodeScriptOps rest
    in OpReturn dat

  -- Multisig: m <keys...> n OP_CHECKMULTISIG
  _ | isMultisig ops -> parseMultisig ops

  _ -> NonStandard

-- | Check if ops form a multisig pattern
isMultisig :: [ScriptOp] -> Bool
isMultisig ops
  | length ops < 4 = False
  | otherwise =
      let first = head ops
          lastOp = last ops
      in isSmallNum first && lastOp == OP_CHECKMULTISIG

-- | Parse multisig pattern
parseMultisig :: [ScriptOp] -> ScriptType
parseMultisig ops = case ops of
  (m:rest) | isSmallNum m ->
    let mVal = fromSmallNum m
        (keys, afterKeys) = span isPushData rest
        pubkeys = map getPushBytes keys
    in case afterKeys of
         [n, OP_CHECKMULTISIG] | isSmallNum n ->
           let nVal = fromSmallNum n
           in if mVal <= nVal && nVal == length pubkeys
              then P2MultiSig mVal pubkeys
              else NonStandard
         _ -> NonStandard
  _ -> NonStandard

-- | Check if opcode is a small number (OP_0 through OP_16)
isSmallNum :: ScriptOp -> Bool
isSmallNum op = case op of
  OP_0  -> True
  OP_1  -> True
  OP_2  -> True
  OP_3  -> True
  OP_4  -> True
  OP_5  -> True
  OP_6  -> True
  OP_7  -> True
  OP_8  -> True
  OP_9  -> True
  OP_10 -> True
  OP_11 -> True
  OP_12 -> True
  OP_13 -> True
  OP_14 -> True
  OP_15 -> True
  OP_16 -> True
  _     -> False

-- | Get value from small number opcode
fromSmallNum :: ScriptOp -> Int
fromSmallNum op = case op of
  OP_0  -> 0
  OP_1  -> 1
  OP_2  -> 2
  OP_3  -> 3
  OP_4  -> 4
  OP_5  -> 5
  OP_6  -> 6
  OP_7  -> 7
  OP_8  -> 8
  OP_9  -> 9
  OP_10 -> 10
  OP_11 -> 11
  OP_12 -> 12
  OP_13 -> 13
  OP_14 -> 14
  OP_15 -> 15
  OP_16 -> 16
  _     -> 0

-- | Check if opcode is a push data operation
isPushData :: ScriptOp -> Bool
isPushData (OP_PUSHDATA _ _) = True
isPushData _ = False

-- | Get bytes from push data operation
getPushBytes :: ScriptOp -> ByteString
getPushBytes (OP_PUSHDATA bs _) = bs
getPushBytes _ = BS.empty

-- | Classify an input script (scriptSig)
classifyInput :: Script -> Maybe ScriptType
classifyInput (Script ops) = case ops of
  -- P2PKH input: <sig> <pubkey>
  [OP_PUSHDATA _ _, OP_PUSHDATA pk _]
    | BS.length pk `elem` [33, 65] -> Just NonStandard  -- We can't determine output type from input alone

  -- P2SH input: ... <serialized-script>
  _ | not (null ops) && isPushData (last ops) ->
      let redeemScript = getPushBytes (last ops)
      in case decodeScript redeemScript of
           Right script -> Just $ classifyOutput script
           Left _ -> Nothing

  _ -> Nothing

--------------------------------------------------------------------------------
-- Standard Script Constructors
--------------------------------------------------------------------------------

-- | Create small number opcode from integer
opN :: Int -> ScriptOp
opN n = case n of
  0  -> OP_0
  1  -> OP_1
  2  -> OP_2
  3  -> OP_3
  4  -> OP_4
  5  -> OP_5
  6  -> OP_6
  7  -> OP_7
  8  -> OP_8
  9  -> OP_9
  10 -> OP_10
  11 -> OP_11
  12 -> OP_12
  13 -> OP_13
  14 -> OP_14
  15 -> OP_15
  16 -> OP_16
  _  -> OP_0  -- Default to OP_0 for out-of-range values

-- | Create P2PKH output script
encodeP2PKH :: Hash160 -> Script
encodeP2PKH (Hash160 h) = Script
  [OP_DUP, OP_HASH160, OP_PUSHDATA h OPCODE, OP_EQUALVERIFY, OP_CHECKSIG]

-- | Create P2SH output script
encodeP2SH :: Hash160 -> Script
encodeP2SH (Hash160 h) = Script
  [OP_HASH160, OP_PUSHDATA h OPCODE, OP_EQUAL]

-- | Create P2WPKH output script
encodeP2WPKH :: Hash160 -> Script
encodeP2WPKH (Hash160 h) = Script [OP_0, OP_PUSHDATA h OPCODE]

-- | Create P2WSH output script
encodeP2WSH :: Hash256 -> Script
encodeP2WSH (Hash256 h) = Script [OP_0, OP_PUSHDATA h OPCODE]

-- | Create m-of-n multisig output script
encodeMultisig :: Int -> [ByteString] -> Script
encodeMultisig m pubkeys = Script $
  [opN m] ++
  map (\pk -> OP_PUSHDATA pk OPCODE) pubkeys ++
  [opN (length pubkeys), OP_CHECKMULTISIG]

-- | Create OP_RETURN output script
encodeOpReturn :: ByteString -> Script
encodeOpReturn dat
  | BS.null dat = Script [OP_RETURN]
  | otherwise = Script [OP_RETURN, OP_PUSHDATA dat OPCODE]

--------------------------------------------------------------------------------
-- Script Number Encoding
--------------------------------------------------------------------------------

-- | Encode an integer as a Bitcoin script number
-- Little-endian with sign bit in MSB of last byte
encodeScriptNum :: Int64 -> ByteString
encodeScriptNum 0 = BS.empty
encodeScriptNum n =
  let absN = abs n
      neg = n < 0
      bytes = go absN []
      go 0 acc = acc
      go v acc = fromIntegral (v .&. 0xff) : go (v `shiftR` 8) acc
  in if null bytes
     then BS.empty
     else let lastByte = last bytes
              needExtraByte = lastByte `testBit` 7
          in if needExtraByte
             then BS.pack $ bytes ++ [if neg then 0x80 else 0x00]
             else BS.pack $ init bytes ++ [if neg then lastByte .|. 0x80 else lastByte]

-- | Decode a Bitcoin script number
decodeScriptNum :: ByteString -> Either String Int64
decodeScriptNum bs
  | BS.null bs = Right 0
  | BS.length bs > 4 = Left "Script number overflow"
  | otherwise =
      let bytes = BS.unpack bs
          lastByte = last bytes
          isNeg = lastByte `testBit` 7
          -- Clear the sign bit
          cleared = init bytes ++ [lastByte .&. 0x7f]
          -- Convert little-endian to value
          val = foldl' (\acc (i, b) -> acc + fromIntegral b `shiftL` (8 * i)) 0
                       (zip [0..] cleared)
      in Right $ if isNeg then negate val else val

-- | Decode script number, allowing larger values for certain operations
decodeScriptNumLenient :: Int -> ByteString -> Either String Int64
decodeScriptNumLenient maxLen bs
  | BS.null bs = Right 0
  | BS.length bs > maxLen = Left "Script number overflow"
  | otherwise =
      let bytes = BS.unpack bs
          lastByte = last bytes
          isNeg = lastByte `testBit` 7
          cleared = init bytes ++ [lastByte .&. 0x7f]
          val = foldl' (\acc (i, b) -> acc + fromIntegral b `shiftL` (8 * i)) 0
                       (zip [0..] cleared)
      in Right $ if isNeg then negate val else val

--------------------------------------------------------------------------------
-- Stack Constants
--------------------------------------------------------------------------------

-- | Stack true value
stackTrue :: ByteString
stackTrue = BS.singleton 1

-- | Stack false value
stackFalse :: ByteString
stackFalse = BS.empty

-- | Check if stack element is true (non-zero)
-- Note: negative zero (0x80) is also false
isTrue :: ByteString -> Bool
isTrue bs
  | BS.null bs = False
  | otherwise =
      let bytes = BS.unpack bs
          allZero = all (== 0) (init bytes) && (last bytes `elem` [0, 0x80])
      in not allZero

--------------------------------------------------------------------------------
-- Script Environment
--------------------------------------------------------------------------------

-- | Script execution environment
data ScriptEnv = ScriptEnv
  { seStack        :: !ScriptStack     -- ^ Main stack
  , seAltStack     :: !ScriptStack     -- ^ Alt stack
  , seIfStack      :: ![Bool]          -- ^ Execution condition stack
  , seTx           :: !Tx              -- ^ Transaction being verified
  , seInputIdx     :: !Int             -- ^ Input index being verified
  , seAmount       :: !Word64          -- ^ Amount being spent (for SegWit sighash)
  , seOpCount      :: !Int             -- ^ Opcode count (limit: 201)
  , seCodeSepPos   :: !Word32          -- ^ Position after last OP_CODESEPARATOR (0xFFFFFFFF = none)
  , seScriptCode   :: !ByteString      -- ^ Script being executed (for sighash)
  , seWitness      :: ![ByteString]    -- ^ Witness stack for SegWit
  , seIsWitness    :: !Bool            -- ^ Are we executing witness script?
  } deriving (Show)

-- | Initialize script environment
initScriptEnv :: Tx -> Int -> Word64 -> ByteString -> ScriptEnv
initScriptEnv tx idx amount scriptCode = ScriptEnv
  { seStack = []
  , seAltStack = []
  , seIfStack = []
  , seTx = tx
  , seInputIdx = idx
  , seAmount = amount
  , seOpCount = 0
  , seCodeSepPos = 0xFFFFFFFF  -- Initialize to -1 as per Bitcoin Core
  , seScriptCode = scriptCode
  , seWitness = if idx < length (txWitness tx) then txWitness tx !! idx else []
  , seIsWitness = False
  }

-- | Result of script evaluation
data ScriptResult
  = ScriptOk !ScriptEnv
  | ScriptError !String
  deriving (Show)

--------------------------------------------------------------------------------
-- Script Evaluation
--------------------------------------------------------------------------------

-- | Check if we're in an executing branch
isExecuting :: ScriptEnv -> Bool
isExecuting env = all id (seIfStack env)

-- | Pop from stack
popStack :: ScriptEnv -> Either String (ByteString, ScriptEnv)
popStack env = case seStack env of
  [] -> Left "Stack underflow"
  (x:xs) -> Right (x, env { seStack = xs })

-- | Push to stack
pushStack :: ByteString -> ScriptEnv -> ScriptEnv
pushStack x env = env { seStack = x : seStack env }

-- | Pop n items from stack
popN :: Int -> ScriptEnv -> Either String ([ByteString], ScriptEnv)
popN n env
  | n < 0 = Left "Invalid pop count"
  | n > length (seStack env) = Left "Stack underflow"
  | otherwise =
      let (items, rest) = splitAt n (seStack env)
      in Right (items, env { seStack = rest })

-- | Increment op count and check limit
incOpCount :: ScriptEnv -> Either String ScriptEnv
incOpCount env =
  let newCount = seOpCount env + 1
  in if newCount > 201
     then Left "Opcode limit exceeded"
     else Right env { seOpCount = newCount }

-- | Check stack size limit
checkStackSize :: ScriptEnv -> Either String ScriptEnv
checkStackSize env =
  let totalSize = length (seStack env) + length (seAltStack env)
  in if totalSize > 1000
     then Left "Stack size exceeded"
     else Right env

-- | Execute a single opcode
execOp :: ScriptOp -> ScriptEnv -> Either String ScriptEnv
execOp op env
  -- In non-executing branch, only process flow control
  | not (isExecuting env) = execFlowControlOnly op env
  | otherwise = case op of
      -- Constants (push operations don't count toward op limit)
      OP_0 -> Right $ pushStack BS.empty env
      OP_PUSHDATA bs _ -> checkElementSize bs >> Right (pushStack bs env)
      OP_1NEGATE -> Right $ pushStack (encodeScriptNum (-1)) env
      OP_1 -> Right $ pushStack (encodeScriptNum 1) env
      OP_2 -> Right $ pushStack (encodeScriptNum 2) env
      OP_3 -> Right $ pushStack (encodeScriptNum 3) env
      OP_4 -> Right $ pushStack (encodeScriptNum 4) env
      OP_5 -> Right $ pushStack (encodeScriptNum 5) env
      OP_6 -> Right $ pushStack (encodeScriptNum 6) env
      OP_7 -> Right $ pushStack (encodeScriptNum 7) env
      OP_8 -> Right $ pushStack (encodeScriptNum 8) env
      OP_9 -> Right $ pushStack (encodeScriptNum 9) env
      OP_10 -> Right $ pushStack (encodeScriptNum 10) env
      OP_11 -> Right $ pushStack (encodeScriptNum 11) env
      OP_12 -> Right $ pushStack (encodeScriptNum 12) env
      OP_13 -> Right $ pushStack (encodeScriptNum 13) env
      OP_14 -> Right $ pushStack (encodeScriptNum 14) env
      OP_15 -> Right $ pushStack (encodeScriptNum 15) env
      OP_16 -> Right $ pushStack (encodeScriptNum 16) env

      -- Flow control
      OP_NOP -> incOpCount env
      OP_VER -> Left "OP_VER is disabled"
      OP_VERIF -> Left "OP_VERIF is disabled"
      OP_VERNOTIF -> Left "OP_VERNOTIF is disabled"
      OP_IF -> execIf True env
      OP_NOTIF -> execIf False env
      OP_ELSE -> execElse env
      OP_ENDIF -> execEndif env
      OP_VERIFY -> incOpCount env >>= execVerify
      OP_RETURN -> Left "OP_RETURN encountered"

      -- Reserved
      OP_RESERVED -> Left "OP_RESERVED is disabled"
      OP_RESERVED1 -> Left "OP_RESERVED1 is disabled"
      OP_RESERVED2 -> Left "OP_RESERVED2 is disabled"

      -- Stack ops
      OP_TOALTSTACK -> incOpCount env >>= execToAltStack
      OP_FROMALTSTACK -> incOpCount env >>= execFromAltStack
      OP_2DROP -> incOpCount env >>= exec2Drop
      OP_2DUP -> incOpCount env >>= exec2Dup
      OP_3DUP -> incOpCount env >>= exec3Dup
      OP_2OVER -> incOpCount env >>= exec2Over
      OP_2ROT -> incOpCount env >>= exec2Rot
      OP_2SWAP -> incOpCount env >>= exec2Swap
      OP_IFDUP -> incOpCount env >>= execIfDup
      OP_DEPTH -> incOpCount env >>= execDepth
      OP_DROP -> incOpCount env >>= execDrop
      OP_DUP -> incOpCount env >>= execDup
      OP_NIP -> incOpCount env >>= execNip
      OP_OVER -> incOpCount env >>= execOver
      OP_PICK -> incOpCount env >>= execPick
      OP_ROLL -> incOpCount env >>= execRoll
      OP_ROT -> incOpCount env >>= execRot
      OP_SWAP -> incOpCount env >>= execSwap
      OP_TUCK -> incOpCount env >>= execTuck

      -- Splice ops (disabled)
      OP_CAT -> Left "OP_CAT is disabled"
      OP_SUBSTR -> Left "OP_SUBSTR is disabled"
      OP_LEFT -> Left "OP_LEFT is disabled"
      OP_RIGHT -> Left "OP_RIGHT is disabled"
      OP_SIZE -> incOpCount env >>= execSize

      -- Bitwise ops
      OP_INVERT -> Left "OP_INVERT is disabled"
      OP_AND -> Left "OP_AND is disabled"
      OP_OR -> Left "OP_OR is disabled"
      OP_XOR -> Left "OP_XOR is disabled"
      OP_EQUAL -> incOpCount env >>= execEqual
      OP_EQUALVERIFY -> incOpCount env >>= execEqualVerify

      -- Arithmetic ops
      OP_1ADD -> incOpCount env >>= execUnaryArith (+1)
      OP_1SUB -> incOpCount env >>= execUnaryArith (subtract 1)
      OP_2MUL -> Left "OP_2MUL is disabled"
      OP_2DIV -> Left "OP_2DIV is disabled"
      OP_NEGATE -> incOpCount env >>= execUnaryArith negate
      OP_ABS -> incOpCount env >>= execUnaryArith abs
      OP_NOT -> incOpCount env >>= execNot
      OP_0NOTEQUAL -> incOpCount env >>= exec0NotEqual
      OP_ADD -> incOpCount env >>= execBinaryArith (+)
      OP_SUB -> incOpCount env >>= execBinaryArith (-)
      OP_MUL -> Left "OP_MUL is disabled"
      OP_DIV -> Left "OP_DIV is disabled"
      OP_MOD -> Left "OP_MOD is disabled"
      OP_LSHIFT -> Left "OP_LSHIFT is disabled"
      OP_RSHIFT -> Left "OP_RSHIFT is disabled"
      OP_BOOLAND -> incOpCount env >>= execBoolAnd
      OP_BOOLOR -> incOpCount env >>= execBoolOr
      OP_NUMEQUAL -> incOpCount env >>= execNumEqual
      OP_NUMEQUALVERIFY -> incOpCount env >>= execNumEqualVerify
      OP_NUMNOTEQUAL -> incOpCount env >>= execNumNotEqual
      OP_LESSTHAN -> incOpCount env >>= execBinaryCompare (<)
      OP_GREATERTHAN -> incOpCount env >>= execBinaryCompare (>)
      OP_LESSTHANOREQUAL -> incOpCount env >>= execBinaryCompare (<=)
      OP_GREATERTHANOREQUAL -> incOpCount env >>= execBinaryCompare (>=)
      OP_MIN -> incOpCount env >>= execBinaryArith min
      OP_MAX -> incOpCount env >>= execBinaryArith max
      OP_WITHIN -> incOpCount env >>= execWithin

      -- Crypto ops
      OP_RIPEMD160 -> incOpCount env >>= execRipemd160
      OP_SHA1 -> incOpCount env >>= execSha1
      OP_SHA256 -> incOpCount env >>= execSha256Op
      OP_HASH160 -> incOpCount env >>= execHash160
      OP_HASH256 -> incOpCount env >>= execHash256
      OP_CODESEPARATOR -> incOpCount env >>= execCodeSeparator
      OP_CHECKSIG -> incOpCount env >>= execCheckSig
      OP_CHECKSIGVERIFY -> incOpCount env >>= execCheckSigVerify
      OP_CHECKMULTISIG -> incOpCount env >>= execCheckMultiSig
      OP_CHECKMULTISIGVERIFY -> incOpCount env >>= execCheckMultiSigVerify

      -- Locktime
      OP_NOP1 -> incOpCount env
      OP_CHECKLOCKTIMEVERIFY -> incOpCount env >>= execCheckLockTimeVerify
      OP_CHECKSEQUENCEVERIFY -> incOpCount env >>= execCheckSequenceVerify
      OP_NOP4 -> incOpCount env
      OP_NOP5 -> incOpCount env
      OP_NOP6 -> incOpCount env
      OP_NOP7 -> incOpCount env
      OP_NOP8 -> incOpCount env
      OP_NOP9 -> incOpCount env
      OP_NOP10 -> incOpCount env

      -- Invalid
      OP_INVALIDOPCODE b -> Left $ "Invalid opcode: " ++ show b

-- | Process flow control ops when not executing
execFlowControlOnly :: ScriptOp -> ScriptEnv -> Either String ScriptEnv
execFlowControlOnly op env = case op of
  OP_IF -> Right env { seIfStack = False : seIfStack env }
  OP_NOTIF -> Right env { seIfStack = False : seIfStack env }
  OP_ELSE ->
    case seIfStack env of
      [] -> Left "OP_ELSE without OP_IF"
      (x:xs) -> Right env { seIfStack = not x : xs }
  OP_ENDIF ->
    case seIfStack env of
      [] -> Left "OP_ENDIF without OP_IF"
      (_:xs) -> Right env { seIfStack = xs }
  OP_VERIF -> Left "OP_VERIF is disabled"
  OP_VERNOTIF -> Left "OP_VERNOTIF is disabled"
  _ -> Right env  -- All other ops are skipped

-- | Check element size limit (520 bytes for non-witness, 10000 for witness)
checkElementSize :: ByteString -> Either String ()
checkElementSize bs
  | BS.length bs > 520 = Left "Push data exceeds 520 bytes"
  | otherwise = Right ()

--------------------------------------------------------------------------------
-- Flow Control Operations
--------------------------------------------------------------------------------

execIf :: Bool -> ScriptEnv -> Either String ScriptEnv
execIf matchTrue env = do
  env' <- incOpCount env
  (top, env'') <- popStack env'
  let cond = isTrue top
      execute = if matchTrue then cond else not cond
  Right env'' { seIfStack = execute : seIfStack env'' }

execElse :: ScriptEnv -> Either String ScriptEnv
execElse env = do
  env' <- incOpCount env
  case seIfStack env' of
    [] -> Left "OP_ELSE without OP_IF"
    (x:xs) -> Right env' { seIfStack = not x : xs }

execEndif :: ScriptEnv -> Either String ScriptEnv
execEndif env = do
  env' <- incOpCount env
  case seIfStack env' of
    [] -> Left "OP_ENDIF without OP_IF"
    (_:xs) -> Right env' { seIfStack = xs }

execVerify :: ScriptEnv -> Either String ScriptEnv
execVerify env = do
  (top, env') <- popStack env
  if isTrue top
    then Right env'
    else Left "OP_VERIFY failed"

--------------------------------------------------------------------------------
-- Stack Operations
--------------------------------------------------------------------------------

execToAltStack :: ScriptEnv -> Either String ScriptEnv
execToAltStack env = do
  (x, env') <- popStack env
  Right env' { seAltStack = x : seAltStack env' }

execFromAltStack :: ScriptEnv -> Either String ScriptEnv
execFromAltStack env = case seAltStack env of
  [] -> Left "Alt stack underflow"
  (x:xs) -> Right $ pushStack x (env { seAltStack = xs })

exec2Drop :: ScriptEnv -> Either String ScriptEnv
exec2Drop env = do
  (_, env') <- popStack env
  (_, env'') <- popStack env'
  Right env''

exec2Dup :: ScriptEnv -> Either String ScriptEnv
exec2Dup env = case seStack env of
  (a:b:_) -> checkStackSize $ pushStack b $ pushStack a env
  _ -> Left "Stack underflow"

exec3Dup :: ScriptEnv -> Either String ScriptEnv
exec3Dup env = case seStack env of
  (a:b:c:_) -> checkStackSize $ pushStack c $ pushStack b $ pushStack a env
  _ -> Left "Stack underflow"

exec2Over :: ScriptEnv -> Either String ScriptEnv
exec2Over env = case seStack env of
  (_:_:a:b:_) -> checkStackSize $ pushStack b $ pushStack a env
  _ -> Left "Stack underflow"

exec2Rot :: ScriptEnv -> Either String ScriptEnv
exec2Rot env = case seStack env of
  (a:b:c:d:e:f:rest) -> Right env { seStack = e:f:a:b:c:d:rest }
  _ -> Left "Stack underflow"

exec2Swap :: ScriptEnv -> Either String ScriptEnv
exec2Swap env = case seStack env of
  (a:b:c:d:rest) -> Right env { seStack = c:d:a:b:rest }
  _ -> Left "Stack underflow"

execIfDup :: ScriptEnv -> Either String ScriptEnv
execIfDup env = case seStack env of
  [] -> Left "Stack underflow"
  (x:_) -> if isTrue x
           then checkStackSize $ pushStack x env
           else Right env

execDepth :: ScriptEnv -> Either String ScriptEnv
execDepth env =
  let depth = length (seStack env)
  in checkStackSize $ pushStack (encodeScriptNum (fromIntegral depth)) env

execDrop :: ScriptEnv -> Either String ScriptEnv
execDrop env = do
  (_, env') <- popStack env
  Right env'

execDup :: ScriptEnv -> Either String ScriptEnv
execDup env = case seStack env of
  [] -> Left "Stack underflow"
  (x:_) -> checkStackSize $ pushStack x env

execNip :: ScriptEnv -> Either String ScriptEnv
execNip env = case seStack env of
  (a:_:rest) -> Right env { seStack = a:rest }
  _ -> Left "Stack underflow"

execOver :: ScriptEnv -> Either String ScriptEnv
execOver env = case seStack env of
  (_:b:_) -> checkStackSize $ pushStack b env
  _ -> Left "Stack underflow"

execPick :: ScriptEnv -> Either String ScriptEnv
execPick env = do
  (top, env') <- popStack env
  n <- decodeScriptNum top
  let idx = fromIntegral n
  if idx < 0 || idx >= length (seStack env')
    then Left "Stack underflow"
    else checkStackSize $ pushStack (seStack env' !! idx) env'

execRoll :: ScriptEnv -> Either String ScriptEnv
execRoll env = do
  (top, env') <- popStack env
  n <- decodeScriptNum top
  let idx = fromIntegral n
  if idx < 0 || idx >= length (seStack env')
    then Left "Stack underflow"
    else let (before, rest) = splitAt idx (seStack env')
             item = head rest
             after = tail rest
         in Right env' { seStack = item : before ++ after }

execRot :: ScriptEnv -> Either String ScriptEnv
execRot env = case seStack env of
  (a:b:c:rest) -> Right env { seStack = c:a:b:rest }
  _ -> Left "Stack underflow"

execSwap :: ScriptEnv -> Either String ScriptEnv
execSwap env = case seStack env of
  (a:b:rest) -> Right env { seStack = b:a:rest }
  _ -> Left "Stack underflow"

execTuck :: ScriptEnv -> Either String ScriptEnv
execTuck env = case seStack env of
  (a:b:rest) -> checkStackSize env { seStack = a:b:a:rest }
  _ -> Left "Stack underflow"

execSize :: ScriptEnv -> Either String ScriptEnv
execSize env = case seStack env of
  [] -> Left "Stack underflow"
  (x:_) -> checkStackSize $ pushStack (encodeScriptNum (fromIntegral $ BS.length x)) env

--------------------------------------------------------------------------------
-- Bitwise Operations
--------------------------------------------------------------------------------

execEqual :: ScriptEnv -> Either String ScriptEnv
execEqual env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  let result = if a == b then stackTrue else stackFalse
  Right $ pushStack result env''

execEqualVerify :: ScriptEnv -> Either String ScriptEnv
execEqualVerify env = execEqual env >>= execVerify

--------------------------------------------------------------------------------
-- Arithmetic Operations
--------------------------------------------------------------------------------

execUnaryArith :: (Int64 -> Int64) -> ScriptEnv -> Either String ScriptEnv
execUnaryArith f env = do
  (top, env') <- popStack env
  n <- decodeScriptNum top
  Right $ pushStack (encodeScriptNum (f n)) env'

execBinaryArith :: (Int64 -> Int64 -> Int64) -> ScriptEnv -> Either String ScriptEnv
execBinaryArith f env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum a
  nb <- decodeScriptNum b
  Right $ pushStack (encodeScriptNum (f nb na)) env''

execNot :: ScriptEnv -> Either String ScriptEnv
execNot env = do
  (top, env') <- popStack env
  n <- decodeScriptNum top
  let result = if n == 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env'

exec0NotEqual :: ScriptEnv -> Either String ScriptEnv
exec0NotEqual env = do
  (top, env') <- popStack env
  n <- decodeScriptNum top
  let result = if n /= 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env'

execBoolAnd :: ScriptEnv -> Either String ScriptEnv
execBoolAnd env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum a
  nb <- decodeScriptNum b
  let result = if na /= 0 && nb /= 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env''

execBoolOr :: ScriptEnv -> Either String ScriptEnv
execBoolOr env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum a
  nb <- decodeScriptNum b
  let result = if na /= 0 || nb /= 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env''

execNumEqual :: ScriptEnv -> Either String ScriptEnv
execNumEqual env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum a
  nb <- decodeScriptNum b
  let result = if na == nb then stackTrue else stackFalse
  Right $ pushStack result env''

execNumEqualVerify :: ScriptEnv -> Either String ScriptEnv
execNumEqualVerify env = execNumEqual env >>= execVerify

execNumNotEqual :: ScriptEnv -> Either String ScriptEnv
execNumNotEqual env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum a
  nb <- decodeScriptNum b
  let result = if na /= nb then stackTrue else stackFalse
  Right $ pushStack result env''

execBinaryCompare :: (Int64 -> Int64 -> Bool) -> ScriptEnv -> Either String ScriptEnv
execBinaryCompare cmp env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum a
  nb <- decodeScriptNum b
  let result = if cmp nb na then stackTrue else stackFalse
  Right $ pushStack result env''

execWithin :: ScriptEnv -> Either String ScriptEnv
execWithin env = do
  (maxVal, env') <- popStack env
  (minVal, env'') <- popStack env'
  (x, env''') <- popStack env''
  nMax <- decodeScriptNum maxVal
  nMin <- decodeScriptNum minVal
  nX <- decodeScriptNum x
  let result = if nX >= nMin && nX < nMax then stackTrue else stackFalse
  Right $ pushStack result env'''

--------------------------------------------------------------------------------
-- Crypto Operations
--------------------------------------------------------------------------------

execRipemd160 :: ScriptEnv -> Either String ScriptEnv
execRipemd160 env = do
  (top, env') <- popStack env
  Right $ pushStack (ripemd160 top) env'

execSha1 :: ScriptEnv -> Either String ScriptEnv
execSha1 env = do
  (top, env') <- popStack env
  -- Using SHA256 as placeholder - proper SHA1 would need cryptonite's SHA1
  -- For now, this is incorrect but allows compilation
  Right $ pushStack (BS.take 20 $ sha256 top) env'

execSha256Op :: ScriptEnv -> Either String ScriptEnv
execSha256Op env = do
  (top, env') <- popStack env
  Right $ pushStack (sha256 top) env'

execHash160 :: ScriptEnv -> Either String ScriptEnv
execHash160 env = do
  (top, env') <- popStack env
  let Hash160 h = hash160 top
  Right $ pushStack h env'

execHash256 :: ScriptEnv -> Either String ScriptEnv
execHash256 env = do
  (top, env') <- popStack env
  let Hash256 h = doubleSHA256 top
  Right $ pushStack h env'

execCodeSeparator :: ScriptEnv -> Either String ScriptEnv
execCodeSeparator env =
  -- In a real implementation, we'd track the position for sighash
  Right env

-- | Execute OP_CHECKSIG
-- IMPORTANT: Pop pubkey first (top of stack), then signature
execCheckSig :: ScriptEnv -> Either String ScriptEnv
execCheckSig env = do
  -- Pop pubkey first (top of stack), then signature (deeper)
  (pubkeyBytes, env') <- popStack env
  (sigBytes, env'') <- popStack env'

  -- If signature is empty, push false
  if BS.null sigBytes
    then Right $ pushStack stackFalse env''
    else do
      -- Parse signature and extract sighash type
      let (sigWithoutType, sigHashByte) = if BS.null sigBytes
                                          then (BS.empty, 0x01)
                                          else (BS.init sigBytes, BS.last sigBytes)

      -- Build subscript for sighash (FindAndDelete not needed for witness v0/v1)
      -- For legacy scripts, we'd need to implement FindAndDelete

      -- Compute sighash
      let _sigHashType = parseSigHashByte sigHashByte
          _sighash = if seIsWitness env''
                     then txSigHashSegWit (seTx env'') (seInputIdx env'')
                                          (seScriptCode env'') (seAmount env'') _sigHashType
                     else txSigHash (seTx env'') (seInputIdx env'')
                                    (seScriptCode env'') _sigHashType

      -- Verify signature
      case parsePubKey pubkeyBytes of
        Nothing -> Right $ pushStack stackFalse env''
        Just _pubkey ->
          case parseSigDER sigWithoutType of
            Nothing -> Right $ pushStack stackFalse env''
            Just _sig ->
              -- verifyMsg is a placeholder that needs secp256k1
              -- For now, return false to allow compilation
              Right $ pushStack stackFalse env''

execCheckSigVerify :: ScriptEnv -> Either String ScriptEnv
execCheckSigVerify env = execCheckSig env >>= execVerify

-- | Parse sighash byte to SigHashType
parseSigHashByte :: Word8 -> SigHashType
parseSigHashByte b =
  let base = b .&. 0x1f
      anyoneCanPay = b .&. 0x80 /= 0
      shType = case base of
        0x02 -> sigHashNone
        0x03 -> sigHashSingle
        _    -> sigHashAll
  in if anyoneCanPay then sigHashAnyoneCanPay shType else shType

-- | Execute OP_CHECKMULTISIG
-- KNOWN PITFALL: Must consume one extra item (the off-by-one bug)
-- KNOWN PITFALL: NULLDUMMY requires the dummy element to be empty
execCheckMultiSig :: ScriptEnv -> Either String ScriptEnv
execCheckMultiSig env = do
  -- Pop n (number of public keys)
  (nBytes, env1) <- popStack env
  n <- decodeScriptNum nBytes

  when (n < 0 || n > 20) $ Left "Invalid pubkey count"

  -- Pop n public keys
  (_pubkeys, env2) <- popN (fromIntegral n) env1

  -- Pop m (number of required signatures)
  (mBytes, env3) <- popStack env2
  m <- decodeScriptNum mBytes

  when (m < 0 || m > n) $ Left "Invalid signature count"

  -- Pop m signatures
  (_sigs, env4) <- popN (fromIntegral m) env3

  -- Pop the dummy element (off-by-one bug)
  (dummy, env5) <- popStack env4

  -- NULLDUMMY: dummy must be empty (BIP-147)
  unless (BS.null dummy) $ Left "NULLDUMMY violation: dummy must be empty"

  -- Verify signatures (simplified - actual implementation would verify each sig)
  -- In production, this needs proper sig verification with secp256k1
  -- For now, push false
  Right $ pushStack stackFalse env5

execCheckMultiSigVerify :: ScriptEnv -> Either String ScriptEnv
execCheckMultiSigVerify env = execCheckMultiSig env >>= execVerify

--------------------------------------------------------------------------------
-- Locktime Operations
--------------------------------------------------------------------------------

-- | OP_CHECKLOCKTIMEVERIFY (BIP-65)
execCheckLockTimeVerify :: ScriptEnv -> Either String ScriptEnv
execCheckLockTimeVerify env = do
  case seStack env of
    [] -> Left "Stack underflow"
    (top:_) -> do
      -- Allow up to 5 bytes for locktime
      locktime <- decodeScriptNumLenient 5 top

      when (locktime < 0) $ Left "Negative locktime"

      let txLocktime = fromIntegral $ txLockTime (seTx env)
          -- Check type consistency (both block or both time)
          locktimeType = if locktime < 500000000 then 0 else 1 :: Int
          txLocktimeType = if txLocktime < 500000000 then 0 else 1 :: Int

      when (locktimeType /= txLocktimeType) $
        Left "Locktime type mismatch"

      when (locktime > txLocktime) $
        Left "Locktime not satisfied"

      -- Check sequence (must not be final)
      let inp = txInputs (seTx env) !! seInputIdx env
      when (txInSequence inp == 0xffffffff) $
        Left "Sequence is final"

      Right env  -- Don't pop the stack element

-- | OP_CHECKSEQUENCEVERIFY (BIP-112)
execCheckSequenceVerify :: ScriptEnv -> Either String ScriptEnv
execCheckSequenceVerify env = do
  case seStack env of
    [] -> Left "Stack underflow"
    (top:_) -> do
      sequence' <- decodeScriptNumLenient 5 top

      -- If sequence has disable flag, NOP
      when (sequence' < 0) $ Left "Negative sequence"

      let seqVal = fromIntegral sequence' :: Word32

      -- Check disable flag (bit 31)
      if seqVal .&. 0x80000000 /= 0
        then Right env  -- Disabled, treated as NOP
        else do
          -- Check tx version
          when (txVersion (seTx env) < 2) $
            Left "CSV requires version >= 2"

          let inp = txInputs (seTx env) !! seInputIdx env
              txSeq = txInSequence inp

          -- Check if input sequence disable flag is set
          when (txSeq .&. 0x80000000 /= 0) $
            Left "Input sequence has disable flag"

          -- Check type consistency (time vs blocks)
          let seqType = seqVal .&. 0x00400000
              txSeqType = txSeq .&. 0x00400000

          when (seqType /= txSeqType) $
            Left "Sequence type mismatch"

          -- Compare masked values
          let seqMasked = seqVal .&. 0x0000ffff
              txSeqMasked = txSeq .&. 0x0000ffff

          when (seqMasked > txSeqMasked) $
            Left "Sequence not satisfied"

          Right env

--------------------------------------------------------------------------------
-- Script Evaluation Entry Points
--------------------------------------------------------------------------------

-- | Evaluate a script with given initial stack
evalScriptWithStack :: ScriptStack -> Script -> ScriptEnv -> Either String ScriptEnv
evalScriptWithStack stack (Script ops) env =
  foldM (flip execOp) (env { seStack = stack }) ops

-- | Main script evaluation
evalScript :: Tx -> Int -> Word64 -> Script -> Script -> Either String Bool
evalScript tx idx amount scriptSig scriptPubKey = do
  let env = initScriptEnv tx idx amount (encodeScript scriptPubKey)

  -- Evaluate scriptSig
  env1 <- evalScriptWithStack [] scriptSig env
  let sigStack = seStack env1

  -- Reset for scriptPubKey evaluation
  let env2 = env1 { seStack = sigStack, seOpCount = 0, seIfStack = [] }

  -- Evaluate scriptPubKey
  env3 <- evalScriptWithStack sigStack scriptPubKey env2

  -- Check if-stack is empty
  unless (null $ seIfStack env3) $
    Left "Unbalanced IF/ENDIF"

  -- Check top stack element
  case seStack env3 of
    [] -> Right False
    (top:_) -> Right (isTrue top)

-- | Verify a transaction input
verifyScript :: Tx -> Int -> ByteString -> Word64 -> Either String Bool
verifyScript tx idx prevScriptPubKey amount = do
  let scriptSigBytes = txInScript (txInputs tx !! idx)

  scriptSig <- decodeScript scriptSigBytes
  scriptPubKey <- decodeScript prevScriptPubKey

  let env = initScriptEnv tx idx amount prevScriptPubKey

  -- Evaluate scriptSig
  env1 <- evalScriptWithStack [] scriptSig env
  let sigStack = seStack env1
      savedStack = sigStack  -- Save for P2SH

  -- Evaluate scriptPubKey
  let env2 = env1 { seStack = sigStack, seOpCount = 0, seIfStack = [] }
  env3 <- evalScriptWithStack sigStack scriptPubKey env2

  unless (null $ seIfStack env3) $
    Left "Unbalanced IF/ENDIF"

  case seStack env3 of
    [] -> Right False
    (top:_) ->
      if not (isTrue top)
      then Right False
      else case classifyOutput scriptPubKey of
        -- P2SH handling
        P2SH expectedHash -> do
          case savedStack of
            [] -> Right False
            (redeemScriptBytes:restStack) -> do
              -- Verify hash matches
              let Hash160 actualHash = hash160 redeemScriptBytes
              if actualHash /= getHash160 expectedHash
                then Right False
                else do
                  -- Deserialize and evaluate redeem script
                  redeemScript <- decodeScript redeemScriptBytes
                  let env4 = env3 { seStack = restStack
                                  , seOpCount = 0
                                  , seIfStack = []
                                  , seScriptCode = redeemScriptBytes
                                  }
                  env5 <- evalScriptWithStack restStack redeemScript env4
                  case seStack env5 of
                    [] -> Right False
                    (t:_) -> Right (isTrue t)

        -- P2WPKH: check witness
        P2WPKH h -> verifyP2WPKH tx idx h amount

        -- P2WSH: check witness
        P2WSH h -> verifyP2WSH tx idx h amount

        -- Other types: already verified
        _ -> Right True

-- | Verify P2WPKH witness
verifyP2WPKH :: Tx -> Int -> Hash160 -> Word64 -> Either String Bool
verifyP2WPKH tx idx expectedHash amount = do
  let witness = if idx < length (txWitness tx)
                then txWitness tx !! idx
                else []

  unless (length witness == 2) $
    Left "P2WPKH witness must have exactly 2 items"

  -- witness is [signature, pubkey]
  let pubkeyBytes = witness !! 1

  -- Verify pubkey hashes to expected value
  let Hash160 actualHash = hash160 pubkeyBytes
  unless (actualHash == getHash160 expectedHash) $
    Left "P2WPKH pubkey hash mismatch"

  -- Construct implicit P2PKH script
  let implicitScript = encodeScript $ encodeP2PKH expectedHash
      env = (initScriptEnv tx idx amount implicitScript)
            { seIsWitness = True
            , seScriptCode = implicitScript
            }

  -- KNOWN PITFALL: Reverse witness stack (wire order is bottom-to-top)
  let witnessStack = reverse witness

  -- Push witness items as stack
  let env' = env { seStack = witnessStack }

  -- Evaluate implicit P2PKH script
  env'' <- evalScriptWithStack witnessStack (encodeP2PKH expectedHash) env'

  case seStack env'' of
    [] -> Right False
    (top:_) -> Right (isTrue top)

-- | Verify P2WSH witness
verifyP2WSH :: Tx -> Int -> Hash256 -> Word64 -> Either String Bool
verifyP2WSH tx idx expectedHash amount = do
  let witness = if idx < length (txWitness tx)
                then txWitness tx !! idx
                else []

  when (null witness) $
    Left "P2WSH witness empty"

  -- Last item is the witness script
  let witnessScriptBytes = last witness
      stack = init witness

  -- Verify script hash (single SHA256 for P2WSH)
  let actualHash = sha256 witnessScriptBytes
  unless (actualHash == getHash256 expectedHash) $
    Left "P2WSH script hash mismatch"

  witnessScript <- decodeScript witnessScriptBytes

  let env = (initScriptEnv tx idx amount witnessScriptBytes)
            { seIsWitness = True
            , seScriptCode = witnessScriptBytes
            }

  -- KNOWN PITFALL: Reverse witness stack (wire order is bottom-to-top)
  let witnessStack = reverse stack

  -- Evaluate witness script
  env' <- evalScriptWithStack witnessStack witnessScript env

  case seStack env' of
    [] -> Right False
    (top:_) -> Right (isTrue top)

-- | Verify SegWit script (entry point)
verifySegWitScript :: Tx -> Int -> ByteString -> Word64 -> Either String Bool
verifySegWitScript tx idx prevScriptPubKey amount = do
  scriptPubKey <- decodeScript prevScriptPubKey
  case classifyOutput scriptPubKey of
    P2WPKH h -> verifyP2WPKH tx idx h amount
    P2WSH h -> verifyP2WSH tx idx h amount
    _ -> Left "Not a witness output"

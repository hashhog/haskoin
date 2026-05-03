{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}

module Haskoin.Script
  ( -- * Script Types
    ScriptOp(..)
  , PushDataType(..)
  , Script(..)
  , ScriptStack
    -- * Script Verification Flags
  , ScriptVerifyFlag(..)
  , ScriptFlags
  , hasFlag
  , emptyFlags
  , flagSet
    -- * Script Errors
  , ScriptError(..)
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
  , evalScriptWithFlags
  , verifyScript
  , verifyScriptWithFlags
  , verifySegWitScript
  , verifySegWitScriptWithFlags
    -- * Standard Scripts
  , encodeP2PKH
  , encodeP2SH
  , encodeP2WPKH
  , encodeP2WSH
  , encodeP2TR
  , encodeP2A
  , encodeMultisig
  , encodeOpReturn
    -- * Pay-to-Anchor (P2A)
  , isPayToAnchor
  , p2aWitnessProgram
  , p2aDustThreshold
    -- * Utilities
  , opN
  , encodeScriptNum
  , decodeScriptNum
  , isTrue
  , isCompressedPubKey
    -- * Tapscript OP_SUCCESS (BIP-342)
  , isTapscriptSuccess
    -- * Sigop Counting
  , countScriptSigops
    -- * Witness Program Detection
  , isWitnessProgram
    -- * Push-Only Check
  , isPushOnly
  , isPushOp
    -- * Miniscript
  , Miniscript(..)
  , MiniscriptType(..)
  , MiniscriptProps(..)
  , MiniscriptContext(..)
  , MiniscriptError(..)
  , SatisfactionContext(..)
  , Witness
  , miniscriptType
  , miniscriptProps
  , checkMiniscriptType
  , compileMiniscript
  , miniscriptSize
  , satisfyMiniscript
  , dissatisfyMiniscript
  , parseMiniscript
  , miniscriptToText
    -- * Internal (test-only) entry points for BIP-342 / Tapscript
    -- These are exposed so the test suite can construct a Tapscript
    -- 'ScriptEnv' directly and exercise opcode handlers (e.g. CHECKSIGADD)
    -- without going through full witness-v1 verification. Not a stable API.
  , ScriptEnv(..)
  , initScriptEnvWithFlags
  , execCheckSigAdd
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Word (Word8, Word32, Word64)
import Data.Int (Int64)
import Data.Serialize (runGet, runPut, getWord8, putWord8, getBytes,
                       putByteString, remaining, getWord16le, putWord16le,
                       getWord32le, putWord32le, Get, Put)
import Control.Monad (when, unless, foldM, forM_)
import Data.Bits ((.&.), (.|.), shiftL, shiftR, testBit)
import GHC.Generics (Generic)
import Data.List (foldl', sortBy)
import Data.Maybe (mapMaybe)
import qualified Data.Set as Set
import Data.Set (Set)
import qualified Data.Map.Strict as Map

import Haskoin.Types
import Haskoin.Crypto
import qualified Haskoin.Crypto as Crypto
import qualified Haskoin.TaprootSighash as TS

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
  -- Tapscript (BIP-342)
  | OP_CHECKSIGADD         -- ^ 0xba (Tapscript only; OP_SUCCESS in non-tapscript? No: per BIP-342, 0xba is allocated to CHECKSIGADD and is a forbidden opcode in legacy/witness-v0)
  -- Invalid
  | OP_INVALIDOPCODE !Word8
  deriving (Show, Eq, Generic)

-- | A Bitcoin Script is a sequence of opcodes
newtype Script = Script { getScriptOps :: [ScriptOp] }
  deriving (Show, Eq, Generic)

-- | Script evaluation stack
type ScriptStack = [ByteString]

--------------------------------------------------------------------------------
-- Script Verification Flags
--------------------------------------------------------------------------------

-- | Flags that control script verification behavior.
-- These correspond to Bitcoin Core's SCRIPT_VERIFY_* flags.
-- Only consensus-critical flags are included; policy flags are excluded.
data ScriptVerifyFlag
  = VerifyP2SH           -- ^ BIP-16: Evaluate P2SH subscripts
  | VerifyDERSig         -- ^ BIP-66: Strict DER signature encoding
  | VerifyCheckLockTimeVerify  -- ^ BIP-65: OP_CHECKLOCKTIMEVERIFY
  | VerifyCheckSequenceVerify  -- ^ BIP-112/113: OP_CHECKSEQUENCEVERIFY
  | VerifyWitness        -- ^ BIP-141: Segregated Witness
  | VerifyNullDummy      -- ^ BIP-147: Dummy element in CHECKMULTISIG must be empty
  | VerifyNullFail       -- ^ BIP-146: Failed sig checks must have empty signature
  | VerifyWitnessPubkeyType  -- ^ BIP-141: Witness v0 pubkeys must be compressed
  | VerifyTaproot        -- ^ BIP-341/342: Taproot
  | VerifyMinimalData    -- ^ BIP-62: Require minimal encoding for script numbers
  | VerifyMinimalIf      -- ^ Minimal IF/NOTIF: argument must be empty or 0x01
  | VerifyDiscourageUpgradableWitnessProgram  -- ^ Fail on unknown witness versions (policy)
  | VerifyDiscourageUpgradableNops            -- ^ Fail on upgradable NOPs (policy)
  | VerifyDiscourageOpSuccess                 -- ^ Fail on OP_SUCCESS opcodes (policy)
  | VerifyConstScriptcode                    -- ^ OP_CODESEPARATOR forbidden in witness v0
  | VerifyStrictEncoding                     -- ^ BIP-62: Strict signature/pubkey encoding
  | VerifyLowS                              -- ^ BIP-62: Low-S signatures
  | VerifySigPushOnly                        -- ^ BIP-62: scriptSig must be push-only
  | VerifyCleanStack                         -- ^ BIP-62: Stack must be clean after evaluation
  deriving (Show, Eq, Ord, Enum, Bounded, Generic)

-- | A set of script verification flags
type ScriptFlags = Set ScriptVerifyFlag

-- | Check if a flag is present in a flag set
hasFlag :: ScriptFlags -> ScriptVerifyFlag -> Bool
hasFlag = flip Set.member

-- | Empty flag set
emptyFlags :: ScriptFlags
emptyFlags = Set.empty

-- | Create a flag set from a list of flags
flagSet :: [ScriptVerifyFlag] -> ScriptFlags
flagSet = Set.fromList

--------------------------------------------------------------------------------
-- Script Errors
--------------------------------------------------------------------------------

-- | Script execution errors
data ScriptError
  = ScriptErrOK                    -- ^ No error (success)
  | ScriptErrUnknown               -- ^ Unknown error
  | ScriptErrEvalFalse             -- ^ Script evaluated to false
  | ScriptErrOpReturn              -- ^ OP_RETURN encountered
  | ScriptErrStackSize             -- ^ Stack size exceeded limit
  | ScriptErrScriptSize            -- ^ Script size exceeded limit
  | ScriptErrPushSize              -- ^ Push data size exceeded limit
  | ScriptErrOpCount               -- ^ Op count exceeded limit
  | ScriptErrDisabledOpcode        -- ^ Disabled opcode encountered
  | ScriptErrInvalidStackOperation -- ^ Invalid stack operation
  | ScriptErrUnbalancedConditional -- ^ Unbalanced IF/ELSE/ENDIF
  | ScriptErrNegativeLocktime      -- ^ Negative locktime
  | ScriptErrLocktime              -- ^ Locktime requirement not satisfied
  | ScriptErrVerify                -- ^ OP_VERIFY failed
  | ScriptErrEqualVerify           -- ^ OP_EQUALVERIFY failed
  | ScriptErrCheckSigVerify        -- ^ OP_CHECKSIGVERIFY failed
  | ScriptErrCheckMultiSigVerify   -- ^ OP_CHECKMULTISIGVERIFY failed
  | ScriptErrPubKeyCount           -- ^ Invalid pubkey count in CHECKMULTISIG
  | ScriptErrSigCount              -- ^ Invalid signature count in CHECKMULTISIG
  | ScriptErrSigDER                -- ^ Invalid DER signature encoding
  | ScriptErrSigNullDummy          -- ^ NULLDUMMY violation: dummy must be empty
  | ScriptErrSigNullFail           -- ^ NULLFAIL violation: failed sig must be empty
  | ScriptErrWitnessPubkeyType     -- ^ Witness v0 pubkey not compressed
  | ScriptErrCleanStack            -- ^ Witness script left extra items on stack
  | ScriptErrSigPushOnly           -- ^ P2SH scriptSig must be push-only
  | ScriptErrMinimalIf             -- ^ MINIMALIF violation: OP_IF/NOTIF arg must be empty or 0x01
  | ScriptErrMissing String        -- ^ Missing UTXO or other data
  | ScriptErrOther String          -- ^ Other error with message
  deriving (Show, Eq, Generic)

-- | Convert ScriptError to a descriptive string
scriptErrorMessage :: ScriptError -> String
scriptErrorMessage err = case err of
  ScriptErrOK -> "No error"
  ScriptErrUnknown -> "Unknown error"
  ScriptErrEvalFalse -> "Script evaluated to false"
  ScriptErrOpReturn -> "OP_RETURN encountered"
  ScriptErrStackSize -> "Stack size exceeded limit"
  ScriptErrScriptSize -> "Script size exceeded limit"
  ScriptErrPushSize -> "Push data size exceeded limit"
  ScriptErrOpCount -> "Op count exceeded limit"
  ScriptErrDisabledOpcode -> "Disabled opcode encountered"
  ScriptErrInvalidStackOperation -> "Invalid stack operation"
  ScriptErrUnbalancedConditional -> "Unbalanced IF/ELSE/ENDIF"
  ScriptErrNegativeLocktime -> "Negative locktime"
  ScriptErrLocktime -> "Locktime requirement not satisfied"
  ScriptErrVerify -> "OP_VERIFY failed"
  ScriptErrEqualVerify -> "OP_EQUALVERIFY failed"
  ScriptErrCheckSigVerify -> "OP_CHECKSIGVERIFY failed"
  ScriptErrCheckMultiSigVerify -> "OP_CHECKMULTISIGVERIFY failed"
  ScriptErrPubKeyCount -> "Invalid pubkey count in CHECKMULTISIG"
  ScriptErrSigCount -> "Invalid signature count in CHECKMULTISIG"
  ScriptErrSigDER -> "Invalid DER signature encoding"
  ScriptErrSigNullDummy -> "NULLDUMMY violation: dummy must be empty"
  ScriptErrSigNullFail -> "NULLFAIL violation: failed sig must be empty"
  ScriptErrWitnessPubkeyType -> "Witness pubkey not compressed"
  ScriptErrCleanStack -> "Witness script must leave exactly one item on stack"
  ScriptErrSigPushOnly -> "P2SH scriptSig must contain only push operations"
  ScriptErrMinimalIf -> "MINIMALIF violation: OP_IF/NOTIF argument must be empty or 0x01"
  ScriptErrMissing s -> "Missing: " ++ s
  ScriptErrOther s -> s

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
        0xba -> return OP_CHECKSIGADD
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
  OP_CHECKSIGADD -> putWord8 0xba
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

-- | Get the byte size of an encoded opcode
-- Used for tracking script position during evaluation
opByteSize :: ScriptOp -> Int
opByteSize op = case op of
  OP_PUSHDATA bs ptype -> case ptype of
    OPCODE -> 1 + BS.length bs  -- length byte + data
    OPDATA1 -> 2 + BS.length bs  -- 0x4c + 1 byte len + data
    OPDATA2 -> 3 + BS.length bs  -- 0x4d + 2 byte len + data
    OPDATA4 -> 5 + BS.length bs  -- 0x4e + 4 byte len + data
  _ -> 1  -- All other opcodes are single bytes

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
  | P2A                               -- ^ OP_1 <0x4e73> (Pay-to-Anchor, anyone-can-spend)
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
  -- Must use direct push (OPCODE type), matching Bitcoin Core's IsPayToScriptHash()
  -- which requires exactly 23 bytes: 0xa9 0x14 <20 bytes> 0x87
  [OP_HASH160, OP_PUSHDATA h OPCODE, OP_EQUAL]
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

  -- P2A (Pay-to-Anchor): OP_1 <0x4e73> (witness v1, 2-byte program)
  -- Anyone-can-spend anchor output for Lightning Network commitment transactions
  [OP_1, OP_PUSHDATA h _]
    | h == p2aWitnessProgram -> P2A

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

-- | Check if a script is a witness program (BIP-141).
-- A witness program is: version byte (OP_0 to OP_16) + single direct push of 2-40 bytes.
-- Returns Just (version, program) or Nothing.
isWitnessProgram :: Script -> Maybe (Int, ByteString)
isWitnessProgram (Script [versionOp, OP_PUSHDATA prog OPCODE])
  | len >= 2 && len <= 40 = case versionOp of
      OP_0 -> Just (0, prog)
      OP_1 -> Just (1, prog)
      OP_2 -> Just (2, prog)
      OP_3 -> Just (3, prog)
      OP_4 -> Just (4, prog)
      OP_5 -> Just (5, prog)
      OP_6 -> Just (6, prog)
      OP_7 -> Just (7, prog)
      OP_8 -> Just (8, prog)
      OP_9 -> Just (9, prog)
      OP_10 -> Just (10, prog)
      OP_11 -> Just (11, prog)
      OP_12 -> Just (12, prog)
      OP_13 -> Just (13, prog)
      OP_14 -> Just (14, prog)
      OP_15 -> Just (15, prog)
      OP_16 -> Just (16, prog)
      _     -> Nothing
  where len = BS.length prog
isWitnessProgram _ = Nothing

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

--------------------------------------------------------------------------------
-- Push-Only Check (BIP-16 P2SH requirement)
--------------------------------------------------------------------------------

-- | Check if a script contains only push operations.
-- This is required for P2SH scriptSigs (BIP-16 consensus rule).
-- Push operations include:
--   - OP_0 (0x00)
--   - Direct pushes (0x01-0x4b)
--   - OP_PUSHDATA1/2/4 (0x4c-0x4e)
--   - OP_1NEGATE (0x4f)
--   - OP_RESERVED (0x50) - technically a push, but fails on execution
--   - OP_1 through OP_16 (0x51-0x60)
--
-- Reference: Bitcoin Core script/script.cpp IsPushOnly()
isPushOnly :: Script -> Bool
isPushOnly (Script ops) = all isPushOp ops

-- | Check if a single opcode is a push operation.
-- An opcode is a push if its byte value is <= OP_16 (0x60).
-- This matches Bitcoin Core's IsPushOnly() which checks: opcode > OP_16 -> false
--
-- Note: OP_RESERVED (0x50) is technically considered a push by this check,
-- but execution of OP_RESERVED fails anyway, so it's not relevant for
-- P2SH/BIP62 as the scriptSig would fail prior to P2SH special validation.
isPushOp :: ScriptOp -> Bool
isPushOp op = case op of
  -- OP_0 through all push data variants
  OP_0 -> True
  OP_PUSHDATA _ _ -> True
  OP_1NEGATE -> True
  OP_RESERVED -> True  -- Considered push, but execution would fail anyway
  -- OP_1 through OP_16
  OP_1 -> True
  OP_2 -> True
  OP_3 -> True
  OP_4 -> True
  OP_5 -> True
  OP_6 -> True
  OP_7 -> True
  OP_8 -> True
  OP_9 -> True
  OP_10 -> True
  OP_11 -> True
  OP_12 -> True
  OP_13 -> True
  OP_14 -> True
  OP_15 -> True
  OP_16 -> True
  -- Everything else (> OP_16) is not a push
  _ -> False

-- | Check that a push opcode uses the minimal encoding (BIP-62 MINIMALDATA).
-- Returns True if the push is minimally encoded, False otherwise.
-- Reference: Bitcoin Core script/interpreter.cpp CheckMinimalPush()
checkMinimalPush :: ScriptOp -> Bool
checkMinimalPush op = case op of
  OP_PUSHDATA bs OPCODE ->
    let len = BS.length bs
    in if len == 0
       then False  -- Should have used OP_0
       else if len == 1
            then let b = BS.index bs 0
                 in if b >= 1 && b <= 16
                    then False  -- Should have used OP_1..OP_16
                    else if b == 0x81
                         then False  -- Should have used OP_1NEGATE
                         else True
            else if len <= 75
                 then True  -- OPCODE is correct for 1..75 bytes
                 else False -- Should have used OPDATA1/2/4
  OP_PUSHDATA bs OPDATA1 ->
    -- OPDATA1 is only minimal if len > 75
    BS.length bs > 75
  OP_PUSHDATA bs OPDATA2 ->
    -- OPDATA2 is only minimal if len > 255
    BS.length bs > 255
  OP_PUSHDATA bs OPDATA4 ->
    -- OPDATA4 is only minimal if len > 65535
    BS.length bs > 65535
  -- Non-push ops and OP_0, OP_1NEGATE, OP_1..OP_16 are always minimal
  _ -> True

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

-- | Create P2TR (Taproot) output script
-- OP_1 <32-byte x-only pubkey>
encodeP2TR :: Hash256 -> Script
encodeP2TR (Hash256 h) = Script [OP_1, OP_PUSHDATA h OPCODE]

-- | P2A (Pay-to-Anchor) witness program bytes: 0x4e73
-- This is a witness v1 program with a 2-byte program (shorter than normal
-- Taproot's 32 bytes), designed to be anyone-can-spend for anchor outputs.
p2aWitnessProgram :: ByteString
p2aWitnessProgram = BS.pack [0x4e, 0x73]

-- | Create P2A (Pay-to-Anchor) output script
-- OP_1 <0x4e73> (witness v1, 2-byte program, anyone-can-spend)
-- Used for anchor outputs in Lightning Network commitment transactions.
encodeP2A :: Script
encodeP2A = Script [OP_1, OP_PUSHDATA p2aWitnessProgram OPCODE]

-- | Check if a script is a Pay-to-Anchor (P2A) output.
-- P2A is exactly: OP_1 OP_PUSHBYTES_2 0x4e73 (4 bytes total)
isPayToAnchor :: Script -> Bool
isPayToAnchor (Script [OP_1, OP_PUSHDATA h _]) = h == p2aWitnessProgram
isPayToAnchor _ = False

-- | P2A dust threshold in satoshis.
-- P2A outputs have a lower dust threshold (240 sats) than typical witness outputs
-- because they're designed to be spent with minimal witness data (empty witness).
p2aDustThreshold :: Word64
p2aDustThreshold = 240

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
decodeScriptNum :: Bool -> ByteString -> Either String Int64
decodeScriptNum requireMinimal bs
  | BS.null bs = Right 0
  | BS.length bs > 4 = Left "Script number overflow"
  | requireMinimal && BS.length bs > 0
    && (BS.last bs .&. 0x7f) == 0
    && (BS.length bs <= 1 || not (BS.index bs (BS.length bs - 2) `testBit` 7))
    = Left "Non-minimal script number encoding"
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
-- Pubkey Encoding Checks
--------------------------------------------------------------------------------

-- | Check if a public key is compressed (33 bytes, starts with 0x02 or 0x03)
-- Used for SCRIPT_VERIFY_WITNESS_PUBKEYTYPE enforcement in witness v0 programs.
isCompressedPubKey :: ByteString -> Bool
isCompressedPubKey pk =
  BS.length pk == 33 && (BS.head pk == 0x02 || BS.head pk == 0x03)

-- | Check if a public key has valid encoding for STRICTENC.
-- Valid encodings: compressed (33 bytes, 02/03 prefix) or
-- uncompressed (65 bytes, 04 prefix).
isValidPubKeyEncoding :: ByteString -> Bool
isValidPubKeyEncoding pk
  | BS.null pk = False
  | BS.length pk == 33 = BS.head pk == 0x02 || BS.head pk == 0x03
  | BS.length pk == 65 = BS.head pk == 0x04
  | otherwise = False

-- | Check pubkey encoding for witness v0 scripts.
-- If WITNESS_PUBKEYTYPE flag is set and we're in witness v0, pubkey must be compressed.
checkWitnessPubkeyType :: ScriptFlags -> ByteString -> Either ScriptError ()
checkWitnessPubkeyType flags pk
  | hasFlag flags VerifyWitnessPubkeyType && not (isCompressedPubKey pk) =
      Left ScriptErrWitnessPubkeyType
  | otherwise = Right ()

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
  , seIsTapscript  :: !Bool            -- ^ Are we executing tapscript (witness v1 script-path)?
  , seFlags        :: !ScriptFlags     -- ^ Script verification flags
    -- Taproot context (BIP-341/342). Only meaningful when seIsWitness or
    -- seIsTapscript is True; ignored for legacy / SegWit-v0.
  , seSpentAmounts :: ![Word64]        -- ^ per-input amounts (for sha_amounts)
  , seSpentScripts :: ![ByteString]    -- ^ per-input scriptPubKeys (for sha_scriptpubkeys)
  , seTapleafHash  :: !(Maybe ByteString) -- ^ tapleaf hash for ext_flag=1 sighash
  , seTaprootAnnex :: !(Maybe ByteString) -- ^ witness annex (with leading 0x50)
  } deriving (Show)

-- | Initialize script environment
initScriptEnv :: Tx -> Int -> Word64 -> ByteString -> ScriptEnv
initScriptEnv tx idx amount scriptCode = initScriptEnvWithFlags tx idx amount scriptCode emptyFlags

-- | Initialize script environment with verification flags
initScriptEnvWithFlags :: Tx -> Int -> Word64 -> ByteString -> ScriptFlags -> ScriptEnv
initScriptEnvWithFlags tx idx amount scriptCode flags = ScriptEnv
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
  , seIsTapscript = False
  , seFlags = flags
  , seSpentAmounts = []
  , seSpentScripts = []
  , seTapleafHash  = Nothing
  , seTaprootAnnex = Nothing
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
      OP_PUSHDATA bs pdt -> do
        checkElementSize bs
        when (hasFlag (seFlags env) VerifyMinimalData && not (checkMinimalPush (OP_PUSHDATA bs pdt))) $
          Left "Non-minimal push encoding"
        Right (pushStack bs env)
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
      OP_CHECKSIGADD -> incOpCount env >>= execCheckSigAdd

      -- Locktime
      OP_NOP1 -> incOpCount env >>= checkDiscourageNop
      OP_CHECKLOCKTIMEVERIFY -> do
        env' <- incOpCount env
        if hasFlag (seFlags env') VerifyCheckLockTimeVerify
          then execCheckLockTimeVerify env'
          else checkDiscourageNop env'
      OP_CHECKSEQUENCEVERIFY -> do
        env' <- incOpCount env
        if hasFlag (seFlags env') VerifyCheckSequenceVerify
          then execCheckSequenceVerify env'
          else checkDiscourageNop env'
      OP_NOP4 -> incOpCount env >>= checkDiscourageNop
      OP_NOP5 -> incOpCount env >>= checkDiscourageNop
      OP_NOP6 -> incOpCount env >>= checkDiscourageNop
      OP_NOP7 -> incOpCount env >>= checkDiscourageNop
      OP_NOP8 -> incOpCount env >>= checkDiscourageNop
      OP_NOP9 -> incOpCount env >>= checkDiscourageNop
      OP_NOP10 -> incOpCount env >>= checkDiscourageNop

      -- Invalid
      OP_INVALIDOPCODE b -> Left $ "Invalid opcode: " ++ show b

-- | Check DISCOURAGE_UPGRADABLE_NOPS flag and fail if set
checkDiscourageNop :: ScriptEnv -> Either String ScriptEnv
checkDiscourageNop env
  | hasFlag (seFlags env) VerifyDiscourageUpgradableNops =
      Left "discouraged upgradable NOP"
  | otherwise = Right env

-- | Check if an opcode is a non-push opcode (counts toward 201 limit)
isCountedOp :: ScriptOp -> Bool
isCountedOp op = case op of
  OP_0 -> False
  OP_PUSHDATA _ _ -> False
  OP_1NEGATE -> False
  OP_RESERVED -> False
  OP_1  -> False; OP_2  -> False; OP_3  -> False; OP_4  -> False
  OP_5  -> False; OP_6  -> False; OP_7  -> False; OP_8  -> False
  OP_9  -> False; OP_10 -> False; OP_11 -> False; OP_12 -> False
  OP_13 -> False; OP_14 -> False; OP_15 -> False; OP_16 -> False
  _ -> True

-- | Process flow control ops when not executing
execFlowControlOnly :: ScriptOp -> ScriptEnv -> Either String ScriptEnv
execFlowControlOnly op env = do
  -- Count non-push opcodes even in non-executing branches
  env' <- if isCountedOp op then incOpCount env else Right env
  case op of
    OP_IF -> Right env' { seIfStack = False : seIfStack env' }
    OP_NOTIF -> Right env' { seIfStack = False : seIfStack env' }
    OP_ELSE ->
      case seIfStack env' of
        [] -> Left "OP_ELSE without OP_IF"
        (x:xs) -> Right env' { seIfStack = not x : xs }
    OP_ENDIF ->
      case seIfStack env' of
        [] -> Left "OP_ENDIF without OP_IF"
        (_:xs) -> Right env' { seIfStack = xs }
    OP_VERIF -> Left "OP_VERIF is disabled"
    OP_VERNOTIF -> Left "OP_VERNOTIF is disabled"
    -- Disabled opcodes must fail even in unexecuted branches
    OP_CAT -> Left "OP_CAT is disabled"
    OP_SUBSTR -> Left "OP_SUBSTR is disabled"
    OP_LEFT -> Left "OP_LEFT is disabled"
    OP_RIGHT -> Left "OP_RIGHT is disabled"
    OP_INVERT -> Left "OP_INVERT is disabled"
    OP_AND -> Left "OP_AND is disabled"
    OP_OR -> Left "OP_OR is disabled"
    OP_XOR -> Left "OP_XOR is disabled"
    OP_2MUL -> Left "OP_2MUL is disabled"
    OP_2DIV -> Left "OP_2DIV is disabled"
    OP_MUL -> Left "OP_MUL is disabled"
    OP_DIV -> Left "OP_DIV is disabled"
    OP_MOD -> Left "OP_MOD is disabled"
    OP_LSHIFT -> Left "OP_LSHIFT is disabled"
    OP_RSHIFT -> Left "OP_RSHIFT is disabled"
    -- Push data size must be checked even in non-executing branches
    -- (Bitcoin Core checks this during instruction read, before fExec)
    OP_PUSHDATA bs _ -> do
      checkElementSize bs
      Right env'
    _ -> Right env'  -- All other ops are skipped

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
  -- MINIMALIF check: enforce minimal IF/NOTIF inputs for witness scripts
  -- In witness v0/v1 (tapscript), the argument must be exactly empty or [0x01]
  -- Reference: Bitcoin Core interpreter.cpp OP_IF handler
  -- MINIMALIF is mandatory in segwit (witness v0/v1), or when the flag is set
  let minimalIfRequired = seIsWitness env'' || hasFlag (seFlags env'') VerifyMinimalIf
  -- Check for valid minimal IF argument when required
  _ <- if minimalIfRequired
       then case BS.unpack top of
              []     -> Right ()  -- Empty is acceptable (false)
              [0x01] -> Right ()  -- Single byte 0x01 is acceptable (true)
              _      -> Left "MINIMALIF violation: OP_IF/NOTIF argument must be empty or 0x01"
       else Right ()
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
  (a:b:_) -> checkStackSize $ pushStack a $ pushStack b env
  _ -> Left "Stack underflow"

exec3Dup :: ScriptEnv -> Either String ScriptEnv
exec3Dup env = case seStack env of
  (a:b:c:_) -> checkStackSize $ pushStack a $ pushStack b $ pushStack c env
  _ -> Left "Stack underflow"

exec2Over :: ScriptEnv -> Either String ScriptEnv
exec2Over env = case seStack env of
  (_:_:a:b:_) -> checkStackSize $ pushStack a $ pushStack b env
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
  n <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) top
  let idx = fromIntegral n
  if idx < 0 || idx >= length (seStack env')
    then Left "Stack underflow"
    else checkStackSize $ pushStack (seStack env' !! idx) env'

execRoll :: ScriptEnv -> Either String ScriptEnv
execRoll env = do
  (top, env') <- popStack env
  n <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) top
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
  n <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) top
  Right $ pushStack (encodeScriptNum (f n)) env'

execBinaryArith :: (Int64 -> Int64 -> Int64) -> ScriptEnv -> Either String ScriptEnv
execBinaryArith f env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) a
  nb <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) b
  Right $ pushStack (encodeScriptNum (f nb na)) env''

execNot :: ScriptEnv -> Either String ScriptEnv
execNot env = do
  (top, env') <- popStack env
  n <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) top
  let result = if n == 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env'

exec0NotEqual :: ScriptEnv -> Either String ScriptEnv
exec0NotEqual env = do
  (top, env') <- popStack env
  n <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) top
  let result = if n /= 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env'

execBoolAnd :: ScriptEnv -> Either String ScriptEnv
execBoolAnd env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) a
  nb <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) b
  let result = if na /= 0 && nb /= 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env''

execBoolOr :: ScriptEnv -> Either String ScriptEnv
execBoolOr env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) a
  nb <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) b
  let result = if na /= 0 || nb /= 0 then 1 else 0
  Right $ pushStack (encodeScriptNum result) env''

execNumEqual :: ScriptEnv -> Either String ScriptEnv
execNumEqual env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) a
  nb <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) b
  let result = if na == nb then stackTrue else stackFalse
  Right $ pushStack result env''

execNumEqualVerify :: ScriptEnv -> Either String ScriptEnv
execNumEqualVerify env = execNumEqual env >>= execVerify

execNumNotEqual :: ScriptEnv -> Either String ScriptEnv
execNumNotEqual env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) a
  nb <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) b
  let result = if na /= nb then stackTrue else stackFalse
  Right $ pushStack result env''

execBinaryCompare :: (Int64 -> Int64 -> Bool) -> ScriptEnv -> Either String ScriptEnv
execBinaryCompare cmp env = do
  (a, env') <- popStack env
  (b, env'') <- popStack env'
  na <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) a
  nb <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) b
  let result = if cmp nb na then stackTrue else stackFalse
  Right $ pushStack result env''

execWithin :: ScriptEnv -> Either String ScriptEnv
execWithin env = do
  (maxVal, env') <- popStack env
  (minVal, env'') <- popStack env'
  (x, env''') <- popStack env''
  nMax <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) maxVal
  nMin <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) minVal
  nX <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) x
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
  Right $ pushStack (sha1 top) env'

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

-- | Execute OP_CODESEPARATOR
-- This opcode marks the position in the script where the scriptCode for
-- signature checking should begin. In legacy scripts, when CHECKSIG/CHECKMULTISIG
-- is executed, the scriptCode used for sighash is everything after the last
-- executed OP_CODESEPARATOR.
--
-- The actual position tracking is done in evalWithPosition, which updates
-- seCodeSepPos to point to the byte position after this opcode.
--
-- NOTE: For witness v0 scripts, OP_CODESEPARATOR doesn't affect the scriptCode
-- (but it does affect tapscript's codesep_pos). This distinction is handled
-- in CHECKSIG.
execCodeSeparator :: ScriptEnv -> Either String ScriptEnv
execCodeSeparator env =
  -- In witness v0, OP_CODESEPARATOR is forbidden if CONST_SCRIPTCODE is set
  -- (In tapscript, OP_CODESEPARATOR is valid and updates codesep_pos)
  if seIsWitness env && hasFlag (seFlags env) VerifyConstScriptcode
    then Left "OP_CODESEPARATOR in witness v0 script"
    else
      -- Position tracking is handled in evalWithPosition
      -- This just returns success
      Right env

-- | Execute OP_CHECKSIG
-- IMPORTANT: Pop pubkey first (top of stack), then signature
-- BIP-146 NULLFAIL: If sig check fails and NULLFAIL flag is set,
-- the signature must be empty. Otherwise, script fails entirely.
-- BIP-141 WITNESS_PUBKEYTYPE: In witness v0, pubkey must be compressed.
--
-- For legacy (non-witness) scripts:
-- 1. Apply OP_CODESEPARATOR position: use script after last CODESEPARATOR
-- 2. Remove all OP_CODESEPARATOR opcodes from scriptCode
-- 3. FindAndDelete: remove all occurrences of the signature from scriptCode
--
-- For witness v0 scripts, no FindAndDelete is applied.
execCheckSig :: ScriptEnv -> Either String ScriptEnv
execCheckSig env = do
  -- Pop pubkey first (top of stack), then signature (deeper)
  (pubkeyBytes, env') <- popStack env
  (sigBytes, env'') <- popStack env'

  -- BIP-342: Tapscript CHECKSIG rules
  if seIsTapscript env''
    then do
      -- Empty pubkey is an error in tapscript
      when (BS.null pubkeyBytes) $
        Left "TAPSCRIPT_EMPTY_PUBKEY"
      -- For non-empty, non-32-byte pubkeys: unknown pubkey type
      if BS.length pubkeyBytes /= 32
        then
          -- Unknown pubkey type: if sig is non-empty, push true; if empty, push false
          -- (BIP-342 soft-fork-safe forward compatibility)
          if BS.null sigBytes
            then Right $ pushStack stackFalse env''
            else Right $ pushStack stackTrue env''
        else
          -- 32-byte pubkey: BIP-340 Schnorr signature verification with
          -- BIP-341 ext_flag=1 sighash (tapleaf_hash + codesep_pos).
          if BS.null sigBytes
            then Right $ pushStack stackFalse env''
            else case verifyTapscriptSchnorr env'' sigBytes pubkeyBytes of
              Right True  -> Right $ pushStack stackTrue env''
              Right False -> Left "Tapscript Schnorr verify failed (NULLFAIL)"
              Left err    -> Left err
    else execCheckSigLegacy env'' pubkeyBytes sigBytes

-- | Verify a Schnorr signature inside a tapscript leaf (BIP-342).
-- Computes the BIP-341 sighash with ext_flag=1 using the env's
-- spent prevouts, tapleaf hash, codesep_pos, and annex.
verifyTapscriptSchnorr :: ScriptEnv -> ByteString -> ByteString -> Either String Bool
verifyTapscriptSchnorr env sigBytesRaw pubkey32 = do
  let sigLen = BS.length sigBytesRaw
  when (sigLen /= 64 && sigLen /= 65) $
    Left "Tapscript sig must be 64 or 65 bytes"
  let (sig64, ht) = if sigLen == 65
                    then (BS.take 64 sigBytesRaw, BS.last sigBytesRaw)
                    else (sigBytesRaw, TS.sighashDefault)
  when (sigLen == 65 && ht == TS.sighashDefault) $
    Left "Tapscript: explicit SIGHASH_DEFAULT byte"
  tlh <- case seTapleafHash env of
    Just h -> Right h
    Nothing -> Left "Tapscript checksig: tapleaf_hash missing in env"
  let prevouts = TS.TaprootPrevouts (seSpentAmounts env) (seSpentScripts env)
  when (length (seSpentAmounts env) /= length (txInputs (seTx env)) ||
        length (seSpentScripts env) /= length (txInputs (seTx env))) $
    Left "Tapscript checksig: per-input prevouts missing in env"
  let sp = TS.TapscriptContext
             { TS.tapleafHash = tlh
             , TS.codesepPos = seCodeSepPos env
             }
  sighash <- case TS.computeTaprootSighash (seTx env) (seInputIdx env)
                    prevouts ht (seTaprootAnnex env) (Just sp) of
    Right h -> Right h
    Left  e -> Left ("Tapscript sighash: " ++ show e)
  pure $ Crypto.verifySchnorr sig64 sighash pubkey32

-- | Legacy/witness-v0 CHECKSIG path (non-tapscript)
execCheckSigLegacy :: ScriptEnv -> ByteString -> ByteString -> Either String ScriptEnv
execCheckSigLegacy env'' pubkeyBytes sigBytes = do
  -- BIP-141 WITNESS_PUBKEYTYPE: In witness v0 scripts, check pubkey is compressed
  when (seIsWitness env'' && hasFlag (seFlags env'') VerifyWitnessPubkeyType) $
    unless (isCompressedPubKey pubkeyBytes) $
      Left "Witness pubkey not compressed"

  -- Encoding checks happen BEFORE the empty sig shortcut, matching Bitcoin Core.
  -- CheckSignatureEncoding passes for empty sigs, then CheckPubKeyEncoding is checked.
  unless (BS.null sigBytes) $ do
    -- STRICTENC / DERSIG: validate DER encoding of the signature
    -- The signature includes the sighash type byte at the end
    when (hasFlag (seFlags env'') VerifyStrictEncoding || hasFlag (seFlags env'') VerifyDERSig) $ do
      unless (isValidDERSignature sigBytes) $
        Left "Non-canonical DER signature"

    -- STRICTENC: validate sighash type byte
    when (hasFlag (seFlags env'') VerifyStrictEncoding) $ do
      let sigHashByte = BS.last sigBytes
      unless (isDefinedSigHashType sigHashByte) $
        Left "Invalid sighash type"

  -- STRICTENC: validate pubkey encoding (checked even with empty sig)
  when (hasFlag (seFlags env'') VerifyStrictEncoding) $ do
    unless (isValidPubKeyEncoding pubkeyBytes) $
      Left "Invalid public key encoding"

  -- If signature is empty, push false (this is always valid, even with NULLFAIL)
  if BS.null sigBytes
    then Right $ pushStack stackFalse env''
    else do

      -- LOW_S: validate S value is low
      when (hasFlag (seFlags env'') VerifyLowS) $ do
        unless (isLowDERSignature sigBytes) $
          Left "Non-canonical signature: S value is unnecessarily high"

      -- Parse sighash type byte from the signature
      let sigHashByte = BS.last sigBytes
          sigHashType = parseSigHashByte sigHashByte

      -- Build scriptCode for sighash computation
      let scriptCode = if seIsWitness env''
                       then seScriptCode env''
                       else scriptCodeForSighash
                              (seScriptCode env'')
                              (seCodeSepPos env'')
                              sigBytes

      -- Compute sighash
      let sigHashW32 = fromIntegral sigHashByte :: Word32
          _sighash = if seIsWitness env''
                    then txSigHashSegWit (seTx env'') (seInputIdx env'')
                                         scriptCode (seAmount env'') sigHashType
                    else txSigHash (seTx env'') (seInputIdx env'') scriptCode sigHashW32 sigHashType

      -- Signature without the sighash type byte for verification
      let _sigWithoutType = BS.init sigBytes

      -- Verify signature using secp256k1 with lax DER parsing
      -- (matches Bitcoin Core's CPubKey::Verify which uses ecdsa_signature_parse_der_lax)
      let sigCheckResult = case parsePubKey pubkeyBytes of
            Nothing -> False
            Just pubkey ->
              let sig = Sig _sigWithoutType
              in verifyMsgLax pubkey sig _sighash

      -- BIP-146 NULLFAIL: If signature check failed and we have NULLFAIL flag,
      -- the signature must be empty. Since we already checked for empty sig above,
      -- if we reach here with a failed check, the sig is non-empty -> error.
      if not sigCheckResult && hasFlag (seFlags env'') VerifyNullFail
        then Left "NULLFAIL: non-empty signature must not fail CHECKSIG"
        else Right $ pushStack (if sigCheckResult then stackTrue else stackFalse) env''

execCheckSigVerify :: ScriptEnv -> Either String ScriptEnv
execCheckSigVerify env = execCheckSig env >>= execVerify

-- | Execute OP_CHECKSIGADD (BIP-342, opcode 0xBA, Tapscript only).
--
-- Stack (bottom → top): @sig num pubkey@.
-- Pop order is pubkey, num, sig. The result @num + (success ? 1 : 0)@ is pushed.
--
-- This opcode is forbidden outside Tapscript (legacy / witness-v0): in those
-- contexts it must fail with SCRIPT_ERR_BAD_OPCODE.
--
-- Reference: bitcoin-core/src/script/interpreter.cpp ~L1086-L1116
--
-- Tapscript Schnorr verification reuses 'verifyTapscriptSchnorr' so the
-- semantics for empty sig (skip verify, success=false) and 32-byte/other
-- pubkey forms match OP_CHECKSIG.
execCheckSigAdd :: ScriptEnv -> Either String ScriptEnv
execCheckSigAdd env = do
  -- BIP-342: OP_CHECKSIGADD is only valid in Tapscript (witness v1 script-path).
  -- In legacy/witness-v0 it must be a hard error (SCRIPT_ERR_BAD_OPCODE).
  unless (seIsTapscript env) $
    Left "OP_CHECKSIGADD only valid in Tapscript (BAD_OPCODE)"

  -- Stack-size check: need at least 3 items (sig, num, pubkey).
  when (length (seStack env) < 3) $
    Left "OP_CHECKSIGADD: invalid stack operation"

  -- Pop pubkey (top), num, sig in that order.
  (pubkeyBytes, env1) <- popStack env
  (numBytes, env2)    <- popStack env1
  (sigBytes, env3)    <- popStack env2

  -- Decode num as a script number. Tapscript permits up to 4-byte script
  -- numbers (Int32 range), and BIP-342 calls for a 4-byte CScriptNum here
  -- with the standard MINIMALDATA gating, identical to other arithmetic
  -- opcodes in the interpreter.
  num <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) numBytes

  -- Bitcoin Core checks: num > INT64_MAX - 1 || num < INT64_MIN, but since
  -- decodeScriptNum returns Int64 already constrained to a 4-byte CScriptNum
  -- (|n| < 2^31), we can never overflow. Still, guard explicitly to mirror
  -- the Core consensus error and to satisfy a future relaxation of the
  -- decoder bounds.
  when (num > maxBound - 1) $
    Left "OP_CHECKSIGADD: num overflow"

  -- Verify the signature in tapscript context. Empty sig short-circuits to
  -- success = False (no Schnorr verify performed). Other failures (bad sig
  -- length, missing prevouts, etc.) propagate as errors and abort the script.
  success <- if BS.null sigBytes
    then
      -- Empty pubkey is still an error in tapscript even if sig is empty
      -- (matches OP_CHECKSIG's TAPSCRIPT_EMPTY_PUBKEY rule).
      if BS.null pubkeyBytes
        then Left "TAPSCRIPT_EMPTY_PUBKEY"
        else Right False
    else
      -- Non-empty signature: verify per tapscript rules.
      if BS.null pubkeyBytes
        then Left "TAPSCRIPT_EMPTY_PUBKEY"
        else if BS.length pubkeyBytes /= 32
          then
            -- Unknown pubkey type with non-empty sig: forward-compat success
            -- (matches OP_CHECKSIG path for non-32-byte tapscript pubkeys).
            Right True
          else case verifyTapscriptSchnorr env3 sigBytes pubkeyBytes of
            Right True  -> Right True
            Right False -> Left "Tapscript Schnorr verify failed (NULLFAIL)"
            Left err    -> Left err

  -- Push num + (success ? 1 : 0).
  let result = num + (if success then 1 else 0)
  Right $ pushStack (encodeScriptNum result) env3

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
-- BIP-342: OP_CHECKMULTISIG is disabled in tapscript
-- KNOWN PITFALL: Must consume one extra item (the off-by-one bug)
-- KNOWN PITFALL: NULLDUMMY requires the dummy element to be empty
-- BIP-146 NULLFAIL: If multisig check fails and NULLFAIL is set,
-- ALL signature arguments must be empty. Otherwise, script fails entirely.
-- BIP-141 WITNESS_PUBKEYTYPE: In witness v0, all pubkeys must be compressed.
--
-- For legacy (non-witness) scripts:
-- 1. Apply OP_CODESEPARATOR position: use script after last CODESEPARATOR
-- 2. Remove all OP_CODESEPARATOR opcodes from scriptCode
-- 3. FindAndDelete: remove ALL signatures from scriptCode before computing each sighash
--    (Bitcoin Core removes each signature as it iterates through them)
--
-- For witness v0 scripts, no FindAndDelete is applied.
execCheckMultiSig :: ScriptEnv -> Either String ScriptEnv
execCheckMultiSig env = do
  -- BIP-342: OP_CHECKMULTISIG is disabled in tapscript
  when (seIsTapscript env) $
    Left "OP_CHECKMULTISIG disabled in tapscript"
  -- Pop n (number of public keys)
  (nBytes, env1) <- popStack env
  n <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) nBytes

  when (n < 0 || n > 20) $ Left "Invalid pubkey count"

  -- Pop n public keys
  (pubkeys, env2) <- popN (fromIntegral n) env1

  -- Add nKeysCount to opcount (CHECKMULTISIG counts pubkeys toward limit)
  let newOpCount = seOpCount env2 + fromIntegral n
  when (newOpCount > 201) $ Left "Opcode limit exceeded"
  let env2' = env2 { seOpCount = newOpCount }

  -- Note: BIP-141 WITNESS_PUBKEYTYPE check is done inside the matching loop,
  -- only for pubkeys that are actually compared against a signature.
  -- This matches Bitcoin Core's behavior.

  -- Pop m (number of required signatures)
  (mBytes, env3) <- popStack env2'
  m <- decodeScriptNum (hasFlag (seFlags env) VerifyMinimalData) mBytes

  when (m < 0 || m > n) $ Left "Invalid signature count"

  -- Pop m signatures
  (sigs, env4) <- popN (fromIntegral m) env3

  -- Pop the dummy element (off-by-one bug)
  (dummy, env5) <- popStack env4

  -- NULLDUMMY: dummy must be empty (BIP-147)
  -- Note: NULLDUMMY is always enforced unconditionally post-SegWit
  when (hasFlag (seFlags env5) VerifyNullDummy && not (BS.null dummy)) $
    Left "NULLDUMMY violation: dummy must be empty"

  -- Build scriptCode for sighash computation
  -- For legacy scripts, we need to:
  -- 1. Start from after last OP_CODESEPARATOR
  -- 2. Remove all OP_CODESEPARATOR opcodes
  -- 3. Remove ALL signatures from the scriptCode (FindAndDelete)
  let baseScriptCode = if seIsWitness env5
                       then seScriptCode env5  -- Witness v0: no FindAndDelete
                       else
                         -- For legacy: start with CODESEP handling and remove CODESEPs
                         let sc = scriptCodeForSighash (seScriptCode env5)
                                                       (seCodeSepPos env5)
                                                       BS.empty  -- Don't remove sig yet
                         -- Then remove ALL signatures from the scriptCode
                         in foldl' (\s sig -> findAndDelete s (encodePushData sig)) sc sigs

  -- Verify signatures against pubkeys in order.
  -- Bitcoin Core's algorithm: two cursors walk forward through sigs and pubkeys.
  -- For each sig, try pubkeys from current position. If match, advance both.
  -- If no match, advance pubkey cursor only. Fail if remaining pubkeys < remaining sigs.
  --
  -- IMPORTANT: Encoding checks (STRICTENC, DERSIG, LOW_S) happen INSIDE the
  -- iteration loop, not before it. This matches Bitcoin Core's behavior where
  -- pubkey and signature encoding are only checked when they are actually
  -- compared during the iteration. If there are 0 signatures, no checks happen.
  let verifyMultiSig :: [ByteString] -> [ByteString] -> Int -> Either String Bool
      verifyMultiSig [] _ _ = Right True  -- All sigs verified
      verifyMultiSig (_:_) [] _ = Right False  -- Sigs left but no pubkeys
      verifyMultiSig sigsLeft@(s:restSigs) (pk:restPks) nSigsRemaining =
        -- Check if enough pubkeys remain for the sigs we still need
        if length (pk:restPks) < nSigsRemaining
        then Right False
        else if BS.null s
             -- Empty signatures never match; just advance pubkey cursor
             then verifyMultiSig sigsLeft restPks nSigsRemaining
             else do
               -- Encoding checks for non-empty signatures (matching Bitcoin Core's
               -- CheckSignatureEncoding/CheckPubKeyEncoding inside the while loop)

               -- STRICTENC / DERSIG: validate DER encoding of current signature
               when (hasFlag (seFlags env5) VerifyStrictEncoding || hasFlag (seFlags env5) VerifyDERSig) $
                 unless (isValidDERSignature s) $
                   Left "Non-canonical DER signature"

               -- STRICTENC: validate sighash type byte
               when (hasFlag (seFlags env5) VerifyStrictEncoding) $
                 unless (isDefinedSigHashType (BS.last s)) $
                   Left "Invalid sighash type"

               -- STRICTENC: validate pubkey encoding
               when (hasFlag (seFlags env5) VerifyStrictEncoding) $
                 unless (isValidPubKeyEncoding pk) $
                   Left "Invalid public key encoding"

               -- BIP-141 WITNESS_PUBKEYTYPE: In witness v0 scripts, pubkey must be compressed
               when (seIsWitness env5 && hasFlag (seFlags env5) VerifyWitnessPubkeyType) $
                 unless (isCompressedPubKey pk) $
                   Left "Witness pubkey not compressed"

               -- LOW_S: validate S value is low
               when (hasFlag (seFlags env5) VerifyLowS) $
                 unless (isLowDERSignature s) $
                   Left "Non-canonical signature: S value is unnecessarily high"

               -- Attempt verification only if sig has at least 2 bytes (hashtype + data)
               let matched = if BS.length s < 2
                    then False  -- Too short to be a valid signature
                    else let sigHashByte = BS.last s
                             sigWithoutType = BS.init s
                             sigHashType = parseSigHashByte sigHashByte
                             sigHashW32 = fromIntegral sigHashByte :: Word32
                             sighash = if seIsWitness env5
                                       then txSigHashSegWit (seTx env5) (seInputIdx env5)
                                                             baseScriptCode (seAmount env5) sigHashType
                                       else txSigHash (seTx env5) (seInputIdx env5) baseScriptCode sigHashW32 sigHashType
                         in case parsePubKey pk of
                              Nothing -> False
                              Just pubkey ->
                                verifyMsgLax pubkey (Sig sigWithoutType) sighash
               if matched
                  then verifyMultiSig restSigs restPks (nSigsRemaining - 1)
                  else verifyMultiSig sigsLeft restPks nSigsRemaining
  fSuccess <- verifyMultiSig sigs pubkeys (length sigs)

  -- BIP-146 NULLFAIL: If the operation failed, ALL signatures must be empty
  -- This is critical: if fSuccess is False and NULLFAIL is enabled,
  -- we must check that every signature in sigs is an empty ByteString
  when (not fSuccess && hasFlag (seFlags env5) VerifyNullFail) $ do
    let nonEmptySigs = filter (not . BS.null) sigs
    unless (null nonEmptySigs) $
      Left "NULLFAIL: all signatures must be empty when CHECKMULTISIG fails"

  Right $ pushStack (if fSuccess then stackTrue else stackFalse) env5

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
-- Tapscript OP_SUCCESS Detection (BIP-342)
--------------------------------------------------------------------------------

-- | Check if a raw opcode byte is an OP_SUCCESS in tapscript context.
--
-- Per BIP-342, the following opcodes are redefined as OP_SUCCESSx in tapscript:
--   0x50, 0x62, 0x7e-0x81, 0x83-0x86, 0x89-0x8a, 0x8d-0x8e,
--   0x95-0xb9, 0xbb-0xfe
--
-- When any of these opcodes appears in a tapscript, the script succeeds
-- unconditionally (unless DISCOURAGE_OP_SUCCESS flag is set, in which
-- case it fails for policy enforcement).
--
-- Note: 0xba (OP_CHECKSIGADD) is NOT OP_SUCCESS -- it is a valid
-- tapscript opcode for Schnorr multisig.
isTapscriptSuccess :: Word8 -> Bool
isTapscriptSuccess op =
  op == 0x50 || op == 0x62 ||
  (op >= 0x7e && op <= 0x81) ||
  (op >= 0x83 && op <= 0x86) ||
  (op >= 0x89 && op <= 0x8a) ||
  (op >= 0x8d && op <= 0x8e) ||
  (op >= 0x95 && op <= 0x99) ||
  (op >= 0xbb && op <= 0xfe)

--------------------------------------------------------------------------------
-- Script Evaluation Entry Points
--------------------------------------------------------------------------------

-- | Evaluate a script with given initial stack
-- Tracks byte position for OP_CODESEPARATOR handling
evalScriptWithStack :: ScriptStack -> Script -> ScriptEnv -> Either String ScriptEnv
evalScriptWithStack stack (Script ops) env = do
  -- Check script size limit (10000 bytes)
  let scriptBytes = encodeScriptOps ops
  when (BS.length scriptBytes > 10000) $ Left "Script size exceeds 10000 bytes"
  evalWithPosition ops 0 (env { seStack = stack })
  where
    -- Evaluate ops while tracking byte position
    evalWithPosition :: [ScriptOp] -> Int -> ScriptEnv -> Either String ScriptEnv
    evalWithPosition [] _ e = Right e
    evalWithPosition (op:rest) pos e = do
      -- For OP_CODESEPARATOR, update the position before executing
      let opSize = opByteSize op
          -- Position after this opcode
          nextPos = pos + opSize
          -- Update seCodeSepPos if this is OP_CODESEPARATOR
          e' = case op of
                 OP_CODESEPARATOR
                   | isExecuting e ->  -- Only update when actually executing
                       e { seCodeSepPos = fromIntegral nextPos }
                 _ -> e
      -- Execute the opcode
      e'' <- execOp op e'
      evalWithPosition rest nextPos e''

-- | Main script evaluation (without flags, for backward compatibility)
evalScript :: Tx -> Int -> Word64 -> Script -> Script -> Either String Bool
evalScript = evalScriptWithFlags emptyFlags

-- | Main script evaluation with verification flags
evalScriptWithFlags :: ScriptFlags -> Tx -> Int -> Word64 -> Script -> Script -> Either String Bool
evalScriptWithFlags flags tx idx amount scriptSig scriptPubKey = do
  let env = initScriptEnvWithFlags tx idx amount (encodeScript scriptPubKey) flags

  -- Evaluate scriptSig
  env1 <- evalScriptWithStack [] scriptSig env
  let sigStack = seStack env1

  -- Clear altstack between scriptSig and scriptPubKey evaluation
  -- Reset for scriptPubKey evaluation
  let env2 = env1 { seStack = sigStack, seOpCount = 0, seIfStack = [], seAltStack = [] }

  -- Evaluate scriptPubKey
  env3 <- evalScriptWithStack sigStack scriptPubKey env2

  -- Check if-stack is empty
  unless (null $ seIfStack env3) $
    Left "Unbalanced IF/ENDIF"

  -- Check top stack element
  case seStack env3 of
    [] -> Right False
    (top:_) -> Right (isTrue top)

-- | Verify a transaction input (without flags, for backward compatibility).
-- Pre-Taproot use only — passes empty prevouts so any Taproot input fails
-- closed. Use 'verifyScriptWithPrevouts' for Taproot-correct verification.
verifyScript :: Tx -> Int -> ByteString -> Word64 -> Either String Bool
verifyScript tx idx prevScriptPubKey amount =
  verifyScriptWithFlags emptyFlags tx idx prevScriptPubKey amount [] []

-- | Verify a transaction input with verification flags.
-- 'spentAmounts' and 'spentScripts' are the per-input prevouts of the
-- whole transaction (one entry per 'txInputs' element). Required by
-- BIP-341's @sha_amounts@ and @sha_scriptpubkeys@ for Taproot inputs;
-- ignored for legacy / SegWit-v0. Empty lists fail Taproot inputs closed.
verifyScriptWithFlags :: ScriptFlags -> Tx -> Int -> ByteString -> Word64
                      -> [Word64] -> [ByteString] -> Either String Bool
verifyScriptWithFlags flags tx idx prevScriptPubKey amount spentAmounts spentScripts = do
  let scriptSigBytes = txInScript (txInputs tx !! idx)

  scriptSig <- decodeScript scriptSigBytes
  scriptPubKey <- decodeScript prevScriptPubKey

  let env = initScriptEnvWithFlags tx idx amount prevScriptPubKey flags

  -- SIGPUSHONLY: When flag is set, scriptSig must be push-only
  when (hasFlag flags VerifySigPushOnly && not (isPushOnly scriptSig)) $
    Left "scriptSig is not push-only"

  -- BIP-16 P2SH: P2SH scriptSig MUST be push-only (checked before execution)
  -- Bitcoin Core checks this before evaluating the scriptSig to avoid
  -- executing non-push opcodes that might fail for other reasons first.
  let isP2SHPubKey = hasFlag flags VerifyP2SH && case classifyOutput scriptPubKey of
                     P2SH _ -> True
                     _      -> False
  when (isP2SHPubKey && not (isPushOnly scriptSig)) $
    Left "P2SH scriptSig must be push-only"

  -- Evaluate scriptSig
  env1 <- evalScriptWithStack [] scriptSig env
  let sigStack = seStack env1
      savedStack = sigStack  -- Save for P2SH

  -- Check for unbalanced IF/ENDIF in scriptSig
  unless (null $ seIfStack env1) $
    Left "Unbalanced IF/ENDIF"

  -- Clear altstack between scriptSig and scriptPubKey evaluation
  -- Reset for scriptPubKey evaluation
  let env2 = env1 { seStack = sigStack, seOpCount = 0, seIfStack = [], seAltStack = [] }
  env3 <- evalScriptWithStack sigStack scriptPubKey env2

  unless (null $ seIfStack env3) $
    Left "Unbalanced IF/ENDIF"

  case seStack env3 of
    [] -> Right False
    (top:_) ->
      if not (isTrue top)
      then Right False
      else do
        -- CLEANSTACK: after scriptPubKey evaluation (and P2SH if applicable),
        -- the stack must have exactly one element
        let checkClean finalStack = do
              when (hasFlag flags VerifyCleanStack && length finalStack /= 1) $
                Left "Stack not clean after evaluation"
              Right True
        let witness = if idx < length (txWitness tx)
                     then txWitness tx !! idx
                     else []
        -- P2SH handling is only active when VerifyP2SH flag is set
        let isP2SHOutput = hasFlag flags VerifyP2SH && case classifyOutput scriptPubKey of
                        P2SH _ -> True
                        _      -> False

        -- Track whether we found a witness program (for WITNESS_UNEXPECTED check)
        let verifyWitnessProgram :: ByteString -> Bool -> Either String Bool
            verifyWitnessProgram wpBytes isP2SHWrapped = do
              wpScript <- decodeScript wpBytes
              case isWitnessProgram wpScript of
                Nothing -> if isP2SHWrapped
                           then checkClean (seStack env3)
                           else checkClean (seStack env3)
                Just (ver, prog) -> do
                  -- For native witness: scriptSig must be empty
                  when (not isP2SHWrapped && not (BS.null scriptSigBytes)) $
                    Left "Witness program scriptSig must be empty"
                  -- For P2SH-wrapped witness: scriptSig must be exactly the push of the witness program
                  when (isP2SHWrapped && not (isPushOnly scriptSig)) $
                    Left "P2SH witness scriptSig must be push-only"
                  when isP2SHWrapped $ do
                    -- scriptSig must be exactly one push that equals the witness program
                    case scriptSig of
                      Script [OP_PUSHDATA d _] | d == wpBytes -> return ()
                      _ -> Left "P2SH witness scriptSig malleated"
                  -- Dispatch on witness version
                  case ver of
                    0 -> do
                      let progLen = BS.length prog
                      if progLen == 20
                        then verifyP2WPKHWithFlags flags tx idx (Hash160 prog) amount
                        else if progLen == 32
                          then verifyP2WSHWithFlags flags tx idx (Hash256 prog) amount
                          else Left "Witness program wrong length"
                    1 | BS.length prog == 32 && hasFlag flags VerifyTaproot ->
                      -- BIP-341: Taproot witness v1
                      verifyTaprootWithFlags flags tx idx prog witness amount spentAmounts spentScripts
                    _ -> do
                      -- Unknown witness version
                      when (hasFlag flags VerifyDiscourageUpgradableWitnessProgram) $
                        Left "Upgradable witness program discouraged"
                      -- Unknown witness versions succeed if WITNESS flag is set
                      -- (they're treated as anyone-can-spend)
                      when (not (null witness) || not (BS.null scriptSigBytes)) $
                        return ()
                      Right True

        if isP2SHOutput
          then case classifyOutput scriptPubKey of
            P2SH expectedHash -> do
              -- BIP-16: P2SH scriptSig MUST be push-only.
              unless (isPushOnly scriptSig) $
                Left "P2SH scriptSig must be push-only"

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
                      unless (null $ seIfStack env5) $
                        Left "Unbalanced IF/ENDIF"
                      case seStack env5 of
                        [] -> Right False
                        (t:_) ->
                          if not (isTrue t) then Right False
                          else do
                            -- Check for P2SH-wrapped witness program
                            if hasFlag flags VerifyWitness
                              then case decodeScript redeemScriptBytes of
                                Right redeemS -> case isWitnessProgram redeemS of
                                  Just _ -> verifyWitnessProgram redeemScriptBytes True
                                  Nothing -> do
                                    -- Not a witness program; check WITNESS_UNEXPECTED
                                    when (hasFlag flags VerifyWitness && not (null witness)) $
                                      Left "Witness unexpected"
                                    checkClean (seStack env5)
                                Left _ -> checkClean (seStack env5)
                              else checkClean (seStack env5)
            _ -> checkClean (seStack env3)  -- Can't happen
          else do
            -- Not P2SH: check for native witness program
            if hasFlag flags VerifyWitness
              then case isWitnessProgram scriptPubKey of
                Just _ -> verifyWitnessProgram prevScriptPubKey False
                Nothing -> do
                  -- Not a witness program; check WITNESS_UNEXPECTED
                  when (not (null witness)) $
                    Left "Witness unexpected"
                  checkClean (seStack env3)
              else checkClean (seStack env3)

-- | Verify P2WPKH witness (without flags, for backward compatibility)
verifyP2WPKH :: Tx -> Int -> Hash160 -> Word64 -> Either String Bool
verifyP2WPKH = verifyP2WPKHWithFlags emptyFlags

-- | Verify P2WPKH witness with verification flags
verifyP2WPKHWithFlags :: ScriptFlags -> Tx -> Int -> Hash160 -> Word64 -> Either String Bool
verifyP2WPKHWithFlags flags tx idx expectedHash amount = do
  let witness = if idx < length (txWitness tx)
                then txWitness tx !! idx
                else []

  unless (length witness == 2) $
    Left "P2WPKH witness must have exactly 2 items"

  -- witness is [signature, pubkey]
  let pubkeyBytes = witness !! 1

  -- BIP-141 WITNESS_PUBKEYTYPE: In witness v0, pubkey must be compressed
  case checkWitnessPubkeyType flags pubkeyBytes of
    Left ScriptErrWitnessPubkeyType -> Left "Witness pubkey not compressed"
    Left err -> Left (show err)
    Right () -> return ()

  -- Verify pubkey hashes to expected value
  let Hash160 actualHash = hash160 pubkeyBytes
  unless (actualHash == getHash160 expectedHash) $
    Left "P2WPKH pubkey hash mismatch"

  -- Construct implicit P2PKH script
  let implicitScript = encodeScript $ encodeP2PKH expectedHash
      env = (initScriptEnvWithFlags tx idx amount implicitScript flags)
            { seIsWitness = True
            , seScriptCode = implicitScript
            }

  -- KNOWN PITFALL: Reverse witness stack (wire order is bottom-to-top)
  let witnessStack = reverse witness

  -- Push witness items as stack
  let env' = env { seStack = witnessStack }

  -- Evaluate implicit P2PKH script
  env'' <- evalScriptWithStack witnessStack (encodeP2PKH expectedHash) env'

  -- Witness scripts implicitly require cleanstack: exactly one item on stack
  -- This is NOT gated by a flag - it's always enforced for witness programs.
  -- Reference: Bitcoin Core interpreter.cpp ExecuteWitnessScript
  case seStack env'' of
    [top] | isTrue top -> Right True
    [_]   -> Left "Script evaluated to false"
    _     -> Left "Witness script must leave exactly one item on stack"

-- | Verify P2WSH witness (without flags, for backward compatibility)
verifyP2WSH :: Tx -> Int -> Hash256 -> Word64 -> Either String Bool
verifyP2WSH = verifyP2WSHWithFlags emptyFlags

-- | Verify P2WSH witness with verification flags
verifyP2WSHWithFlags :: ScriptFlags -> Tx -> Int -> Hash256 -> Word64 -> Either String Bool
verifyP2WSHWithFlags flags tx idx expectedHash amount = do
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

  let env = (initScriptEnvWithFlags tx idx amount witnessScriptBytes flags)
            { seIsWitness = True
            , seScriptCode = witnessScriptBytes
            }

  -- KNOWN PITFALL: Reverse witness stack (wire order is bottom-to-top)
  let witnessStack = reverse stack

  -- Evaluate witness script
  env' <- evalScriptWithStack witnessStack witnessScript env

  -- Witness scripts implicitly require cleanstack: exactly one item on stack
  -- This is NOT gated by a flag - it's always enforced for witness programs.
  -- Reference: Bitcoin Core interpreter.cpp ExecuteWitnessScript
  case seStack env' of
    [top] | isTrue top -> Right True
    [_]   -> Left "Script evaluated to false"
    _     -> Left "Witness script must leave exactly one item on stack"

-- | Verify Taproot (BIP-341/342) witness v1 program.
-- Handles both key-path (single witness element = Schnorr sig) and
-- script-path (witness stack + script + control block).
verifyTaprootWithFlags :: ScriptFlags -> Tx -> Int -> ByteString -> [ByteString] -> Word64 -> [Word64] -> [ByteString] -> Either String Bool
verifyTaprootWithFlags flags tx idx outputKeyBytes witness amount spentAmounts spentScripts = do
  when (null witness) $
    Left "Taproot witness empty"

  -- Check for annex: if >= 2 items and last starts with 0x50
  let (effectiveWitness, annex) =
        if length witness >= 2 && not (BS.null (last witness)) && BS.head (last witness) == 0x50
        then (init witness, Just (last witness))
        else (witness, Nothing)

  case effectiveWitness of
    [sig] -> do
      -- Key-path spend: single element is a 64- or 65-byte Schnorr sig
      -- verified against the witness program (the tweaked output key Q)
      -- under BIP-341 sighash with ext_flag = 0.
      let sigLen = BS.length sig
      when (sigLen /= 64 && sigLen /= 65) $
        Left "Taproot key-path sig length must be 64 or 65"
      let (sigBytes, hashType) =
            if sigLen == 65
            then (BS.take 64 sig, BS.last sig)
            else (sig, TS.sighashDefault)
      -- Strict: explicit SIGHASH_DEFAULT byte (0x00) is invalid; the
      -- 64-byte form must be used for default.
      when (sigLen == 65 && hashType == TS.sighashDefault) $
        Left "Taproot: explicit SIGHASH_DEFAULT byte"
      -- Need full prevouts; if the caller didn't supply them, fail closed.
      when (length spentAmounts /= length (txInputs tx) ||
            length spentScripts /= length (txInputs tx)) $
        Left "Taproot: caller did not supply per-input prevouts"
      let _ = amount  -- subsumed by spentAmounts !! idx for Taproot
      let prevouts = TS.TaprootPrevouts spentAmounts spentScripts
      sighash <- case TS.computeTaprootSighash tx idx prevouts hashType annex Nothing of
        Right h -> Right h
        Left e  -> Left ("Taproot sighash: " ++ show e)
      when (BS.length outputKeyBytes /= 32) $
        Left "Taproot: witness program is not 32 bytes"
      if Crypto.verifySchnorr sigBytes sighash outputKeyBytes
        then Right True
        else Left "Taproot key-path Schnorr verify failed"

    _ | length effectiveWitness >= 2 -> do
      -- Script-path spend: [...stack items..., script, control_block]
      let controlBlock = last effectiveWitness
          tapscriptBytes = effectiveWitness !! (length effectiveWitness - 2)
          stack = take (length effectiveWitness - 2) effectiveWitness

      -- Control block must be >= 33 bytes and (len - 33) must be multiple of 32
      when (BS.length controlBlock < 33) $
        Left "Taproot control block too short"
      when ((BS.length controlBlock - 33) `mod` 32 /= 0) $
        Left "Taproot control block invalid length"

      let leafVersion = BS.head controlBlock .&. 0xfe
          parityBit   = BS.head controlBlock .&. 0x01
          internalKey = BS.take 32 (BS.drop 1 controlBlock)

      -- Compute the BIP-341 TapLeaf hash for this leaf. Reused below for
      -- the merkle path verify and threaded into ScriptEnv so tapscript
      -- OP_CHECKSIG can compute ext_flag=1 sighash.
      let tapleafHashBytes =
            taggedHash (BC.pack "TapLeaf")
              (BS.singleton leafVersion <>
               serVarBytesPrefix tapscriptBytes)

      -- BIP-341 control-block verification (was previously stubbed
      -- with a "We trust the test vector construction here" comment).
      -- Walks the merkle path bottom-up, then checks that internal_key
      -- tweaked by tagged_hash("TapTweak", internal_key || merkle_root)
      -- equals outputKeyBytes, with the parity bit matching control[0].
      when (BS.length outputKeyBytes /= 32) $
        Left "Taproot: witness program is not 32 bytes"
      let merkleRoot = walkMerklePath tapleafHashBytes
                         (drop33Chunks controlBlock)
          tweakHash  = taggedHash (BC.pack "TapTweak") (internalKey <> merkleRoot)
      case xonlyPubkeyTweakAdd internalKey tweakHash of
        Nothing -> Left "Taproot: tweak failed"
        Just (tweakedKey, parity) -> do
          when (tweakedKey /= outputKeyBytes) $
            Left "Taproot: control block does not match output key"
          when (fromIntegral parityBit /= parity) $
            Left "Taproot: control block parity mismatch"

      -- Need full prevouts before we exec the tapscript so OP_CHECKSIG
      -- inside it can compute ext_flag=1 sighash.
      when (length spentAmounts /= length (txInputs tx) ||
            length spentScripts /= length (txInputs tx)) $
        Left "Taproot script-path: caller did not supply per-input prevouts"

      -- Check leaf version: 0xc0 = tapscript (BIP-342)
      if leafVersion == 0xc0
        then do
          -- BIP-342: Check for OP_SUCCESS opcodes before full evaluation
          let rawBytes = tapscriptBytes
              hasOpSuccess = any isTapscriptSuccess (BS.unpack rawBytes)

          if hasOpSuccess
            then do
              -- OP_SUCCESS: script succeeds unconditionally
              when (hasFlag flags VerifyDiscourageOpSuccess) $
                Left "OP_SUCCESS discouraged"
              Right True
            else do
              -- Decode and evaluate the tapscript
              tapscript <- decodeScript tapscriptBytes

              let env = (initScriptEnvWithFlags tx idx amount tapscriptBytes flags)
                        { seIsWitness = True
                        , seIsTapscript = True
                        , seScriptCode = tapscriptBytes
                        , seSpentAmounts = spentAmounts
                        , seSpentScripts = spentScripts
                        , seTapleafHash  = Just tapleafHashBytes
                        , seTaprootAnnex = annex
                        }

              -- Evaluate tapscript with the witness stack (reversed for wire order)
              let witnessStack = reverse stack
              env' <- evalScriptWithStack witnessStack tapscript env

              -- Must leave exactly one true item on stack
              case seStack env' of
                [top] | isTrue top -> Right True
                [_]   -> Left "EVAL_FALSE"
                _     -> Left "Tapscript must leave exactly one item on stack"
        else do
          -- Unknown leaf version: succeed (future soft-fork compatibility)
          Right True

    _ -> Left "Taproot witness invalid"

-- | Strip the first 33 bytes (leaf_version + internal_key) of a
-- taproot control block and return the merkle path as a list of
-- 32-byte sibling hashes (length is ((len - 33) / 32)).
drop33Chunks :: ByteString -> [ByteString]
drop33Chunks ctrl = go (BS.drop 33 ctrl)
  where
    go b
      | BS.null b = []
      | otherwise = BS.take 32 b : go (BS.drop 32 b)

-- | Walk a BIP-341 merkle path from a leaf hash and a list of
-- 32-byte sibling hashes, returning the root.
-- Each step: k = tagged_hash("TapBranch", min(k, sib) || max(k, sib))
walkMerklePath :: ByteString -> [ByteString] -> ByteString
walkMerklePath = foldl' step
  where
    step k sib =
      let (lo, hi) = if k <= sib then (k, sib) else (sib, k)
      in taggedHash (BC.pack "TapBranch") (lo <> hi)

-- | Encode a ByteString as compact-size length prefix || bytes.
-- Used for the @compact_size(script_len) || script@ portion of the
-- BIP-341 TapLeaf hash preimage.
serVarBytesPrefix :: ByteString -> ByteString
serVarBytesPrefix bs =
  runPut (putVarInt (fromIntegral (BS.length bs)) >> putByteString bs)

-- | Verify SegWit script (entry point, without flags, for backward compatibility)
verifySegWitScript :: Tx -> Int -> ByteString -> Word64 -> Either String Bool
verifySegWitScript = verifySegWitScriptWithFlags emptyFlags

-- | Verify SegWit script with verification flags
verifySegWitScriptWithFlags :: ScriptFlags -> Tx -> Int -> ByteString -> Word64 -> Either String Bool
verifySegWitScriptWithFlags flags tx idx prevScriptPubKey amount = do
  scriptPubKey <- decodeScript prevScriptPubKey
  case classifyOutput scriptPubKey of
    P2WPKH h -> verifyP2WPKHWithFlags flags tx idx h amount
    P2WSH h -> verifyP2WSHWithFlags flags tx idx h amount
    _ -> Left "Not a witness output"

--------------------------------------------------------------------------------
-- Sigop Counting
--------------------------------------------------------------------------------

-- | Count signature operations in a script.
-- The accurate parameter indicates whether to count accurate sigops (P2SH/witness)
-- or use the simple legacy counting.
--
-- For P2SH and witness scripts, the sigops are counted in the redeemed/witness script
-- rather than the scriptPubKey. The 'accurate' flag indicates we're counting from
-- a scriptSig/witness where we know the redeemed script.
countScriptSigops :: Script -> Bool -> Int
countScriptSigops (Script ops) accurate = go ops 0 Nothing
  where
    go [] acc _ = acc
    go (op:rest) acc lastOp = case op of
      OP_CHECKSIG -> go rest (acc + 1) (Just op)
      OP_CHECKSIGVERIFY -> go rest (acc + 1) (Just op)
      OP_CHECKMULTISIG ->
        -- If accurate and last push was a small number, use that for key count
        -- Otherwise assume worst case of 20 keys
        let keyCount = if accurate
                       then maybe 20 getPushNum lastOp
                       else 20
        in go rest (acc + keyCount) (Just op)
      OP_CHECKMULTISIGVERIFY ->
        let keyCount = if accurate
                       then maybe 20 getPushNum lastOp
                       else 20
        in go rest (acc + keyCount) (Just op)
      _ -> go rest acc (Just op)

    -- Get the numeric value from a small number opcode for accurate multisig counting
    getPushNum :: ScriptOp -> Int
    getPushNum op = case op of
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
      _     -> 20  -- Default to worst case

--------------------------------------------------------------------------------
-- Miniscript: A Structured Subset of Bitcoin Script
--------------------------------------------------------------------------------
-- Reference: BIP-379, https://bitcoin.sipa.be/miniscript/
-- Bitcoin Core: /src/script/miniscript.cpp

-- | Miniscript expression type.
-- Represents the structured subset of Bitcoin Script that enables static analysis.
data Miniscript
  -- Atomic expressions
  = MsTrue                                    -- ^ Just 1 (OP_1)
  | MsFalse                                   -- ^ Just 0 (OP_0)
  | MsPk !ByteString                          -- ^ pk_k(key) - <key>
  | MsPkH !ByteString                         -- ^ pk_h(key) - OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY
  | MsOlder !Word32                           -- ^ older(n) - <n> OP_CHECKSEQUENCEVERIFY
  | MsAfter !Word32                           -- ^ after(n) - <n> OP_CHECKLOCKTIMEVERIFY
  -- Hash preimage checks
  | MsSha256 !ByteString                      -- ^ sha256(h) - OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <h> OP_EQUAL
  | MsHash256 !ByteString                     -- ^ hash256(h) - OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 <h> OP_EQUAL
  | MsRipemd160 !ByteString                   -- ^ ripemd160(h) - OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 <h> OP_EQUAL
  | MsHash160 !ByteString                     -- ^ hash160(h) - OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <h> OP_EQUAL
  -- Connectives
  | MsAndV !Miniscript !Miniscript            -- ^ and_v(X,Y) - [X] [Y]
  | MsAndB !Miniscript !Miniscript            -- ^ and_b(X,Y) - [X] [Y] OP_BOOLAND
  | MsOrB !Miniscript !Miniscript             -- ^ or_b(X,Y) - [X] [Y] OP_BOOLOR
  | MsOrC !Miniscript !Miniscript             -- ^ or_c(X,Y) - [X] OP_NOTIF [Y] OP_ENDIF
  | MsOrD !Miniscript !Miniscript             -- ^ or_d(X,Y) - [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
  | MsOrI !Miniscript !Miniscript             -- ^ or_i(X,Y) - OP_IF [X] OP_ELSE [Y] OP_ENDIF
  | MsAndOr !Miniscript !Miniscript !Miniscript -- ^ andor(X,Y,Z) - [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
  -- Threshold
  | MsThresh !Int ![Miniscript]               -- ^ thresh(k,X1,...,Xn) - [X1] ... [Xn] OP_ADD ... <k> OP_EQUAL
  | MsMulti !Int ![ByteString]                -- ^ multi(k,keys) - <k> <keys...> <n> OP_CHECKMULTISIG
  | MsSortedMulti !Int ![ByteString]          -- ^ sortedmulti(k,keys) - like multi but with sorted keys
  | MsMultiA !Int ![ByteString]               -- ^ multi_a(k,keys) - tapscript CHECKSIGADD multisig
  | MsSortedMultiA !Int ![ByteString]         -- ^ sortedmulti_a(k,keys) - sorted tapscript multisig
  -- Wrappers (these modify sub-expressions)
  | MsA !Miniscript                           -- ^ a:X - OP_TOALTSTACK [X] OP_FROMALTSTACK
  | MsS !Miniscript                           -- ^ s:X - OP_SWAP [X]
  | MsC !Miniscript                           -- ^ c:X - [X] OP_CHECKSIG
  | MsD !Miniscript                           -- ^ d:X - OP_DUP OP_IF [X] OP_ENDIF
  | MsV !Miniscript                           -- ^ v:X - [X] OP_VERIFY (or use -VERIFY variant)
  | MsJ !Miniscript                           -- ^ j:X - OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
  | MsN !Miniscript                           -- ^ n:X - [X] OP_0NOTEQUAL
  | MsL !Miniscript                           -- ^ l:X - OP_IF OP_0 OP_ELSE [X] OP_ENDIF
  | MsU !Miniscript                           -- ^ u:X - OP_IF [X] OP_ELSE OP_0 OP_ENDIF
  | MsT !Miniscript                           -- ^ t:X - and_v(X,1)
  deriving (Show, Eq, Generic)

-- | Miniscript basic type (B, V, K, W)
-- These determine how the expression interacts with the stack.
data MiniscriptType
  = TypeB   -- ^ Base: consumes args from stack, pushes 0/nonzero
  | TypeV   -- ^ Verify: consumes args, pushes nothing, cannot fail nonzero
  | TypeK   -- ^ Key: pushes a public key, becomes B with OP_CHECKSIG
  | TypeW   -- ^ Wrapped: like B but operates one below top of stack
  deriving (Show, Eq, Ord, Enum, Bounded, Generic)

-- | Miniscript type properties.
-- These boolean flags describe additional constraints on expressions.
data MiniscriptProps = MiniscriptProps
  { propZ :: !Bool   -- ^ z (zero-arg): consumes exactly 0 stack elements
  , propO :: !Bool   -- ^ o (one-arg): consumes exactly 1 stack element
  , propN :: !Bool   -- ^ n (nonzero): satisfaction never requires zero top element
  , propD :: !Bool   -- ^ d (dissatisfiable): has a dissatisfaction
  , propU :: !Bool   -- ^ u (unit): on satisfaction pushes exactly 1 (not just nonzero)
  , propE :: !Bool   -- ^ e (expression): dissatisfaction is non-malleable
  , propF :: !Bool   -- ^ f (forced): dissatisfaction requires signature
  , propS :: !Bool   -- ^ s (safe): satisfaction requires signature
  , propM :: !Bool   -- ^ m (nonmalleable): every satisfaction has non-malleable form
  , propX :: !Bool   -- ^ x (expensive verify): last opcode is not EQUAL/CHECKSIG/etc
  , propG :: !Bool   -- ^ g: contains relative time timelock
  , propH :: !Bool   -- ^ h: contains relative height timelock
  , propI :: !Bool   -- ^ i: contains absolute time timelock
  , propJ :: !Bool   -- ^ j: contains absolute height timelock
  , propK :: !Bool   -- ^ k: no conflicting timelocks
  } deriving (Show, Eq, Generic)

-- | Default (empty) properties
emptyProps :: MiniscriptProps
emptyProps = MiniscriptProps
  { propZ = False, propO = False, propN = False, propD = False
  , propU = False, propE = False, propF = False, propS = False
  , propM = False, propX = False, propG = False, propH = False
  , propI = False, propJ = False, propK = True
  }

-- | Miniscript context (P2WSH vs Tapscript)
data MiniscriptContext
  = ContextP2WSH      -- ^ Witness Script Hash context
  | ContextTapscript  -- ^ Taproot script-path context
  deriving (Show, Eq, Ord, Enum, Generic)

-- | Miniscript errors
data MiniscriptError
  = MsTypeError !String         -- ^ Type checking failed
  | MsContextError !String      -- ^ Invalid in this context
  | MsSatisfactionError !String -- ^ Cannot find satisfaction
  | MsParseError !String        -- ^ Parsing failed
  | MsResourceError !String     -- ^ Resource limit exceeded
  deriving (Show, Eq, Generic)

-- | Context for satisfaction: what signatures/preimages are available
data SatisfactionContext = SatisfactionContext
  { satSignatures :: !(Map.Map ByteString ByteString)  -- ^ pubkey -> signature
  , satPreimages  :: !(Map.Map ByteString ByteString)  -- ^ hash -> preimage
  , satContext    :: !MiniscriptContext                -- ^ P2WSH or Tapscript
  } deriving (Show, Eq)

-- | A witness stack (list of stack items)
type Witness = [ByteString]

-- | Internal satisfaction result: witness stack and cost
data SatResult = SatResult
  { satWitness   :: !Witness     -- ^ Witness stack items
  , satCost      :: !Int         -- ^ Total serialized size
  , satHasSig    :: !Bool        -- ^ Contains at least one signature
  , satMalleable :: !Bool        -- ^ Is this satisfaction malleable?
  } deriving (Show, Eq)

-- | Satisfaction unavailable
satUnavailable :: SatResult
satUnavailable = SatResult [] maxBound False True

-- | Combine satisfaction results (concatenate witnesses)
satConcat :: SatResult -> SatResult -> SatResult
satConcat a b
  | satCost a == maxBound || satCost b == maxBound = satUnavailable
  | otherwise = SatResult
      { satWitness = satWitness a ++ satWitness b
      , satCost = satCost a + satCost b
      , satHasSig = satHasSig a || satHasSig b
      , satMalleable = satMalleable a || satMalleable b
      }

-- | Choose cheaper satisfaction
satChoice :: SatResult -> SatResult -> SatResult
satChoice a b
  | satCost a == maxBound = b
  | satCost b == maxBound = a
  | satCost a <= satCost b = a
  | otherwise = b

--------------------------------------------------------------------------------
-- Type Checking
--------------------------------------------------------------------------------

-- | Get the basic type of a miniscript expression
miniscriptType :: Miniscript -> MiniscriptType
miniscriptType ms = case ms of
  MsTrue       -> TypeB
  MsFalse      -> TypeB
  MsPk _       -> TypeK
  MsPkH _      -> TypeK
  MsOlder _    -> TypeB
  MsAfter _    -> TypeB
  MsSha256 _   -> TypeB
  MsHash256 _  -> TypeB
  MsRipemd160 _ -> TypeB
  MsHash160 _  -> TypeB
  MsAndV x y   -> if miniscriptType y == TypeV then TypeV else miniscriptType y
  MsAndB _ _   -> TypeB
  MsOrB _ _    -> TypeB
  MsOrC _ _    -> TypeV
  MsOrD _ _    -> TypeB
  MsOrI x y    ->
    let tx = miniscriptType x
        ty = miniscriptType y
    in if tx == ty then tx else TypeB  -- Both must have same type
  MsAndOr _ y _ -> miniscriptType y
  MsThresh _ _  -> TypeB
  MsMulti _ _   -> TypeB
  MsSortedMulti _ _ -> TypeB
  MsMultiA _ _  -> TypeB
  MsSortedMultiA _ _ -> TypeB
  -- Wrappers
  MsA x        -> TypeW  -- a: converts B to W
  MsS x        -> TypeW  -- s: converts Bo to W
  MsC x        -> TypeB  -- c: converts K to B via CHECKSIG
  MsD x        -> TypeB  -- d: converts Vz to B
  MsV x        -> TypeV  -- v: converts B to V via VERIFY
  MsJ x        -> TypeB  -- j: converts Bn to B
  MsN x        -> TypeB  -- n: keeps as B
  MsL x        -> if miniscriptType x == TypeB then TypeB else TypeV
  MsU x        -> TypeB
  MsT x        -> TypeV  -- t: = and_v(X, 1) -> V

-- | Get the type properties of a miniscript expression
miniscriptProps :: Miniscript -> MiniscriptProps
miniscriptProps ms = case ms of
  MsTrue -> emptyProps
    { propZ = True, propU = True, propF = True, propM = True, propK = True }

  MsFalse -> emptyProps
    { propZ = True, propU = True, propD = True, propE = True, propM = True
    , propS = True, propK = True }

  MsPk _ -> emptyProps
    { propO = True, propN = True, propD = True, propU = True, propE = True
    , propM = True, propS = True, propK = True }

  MsPkH _ -> emptyProps
    { propN = True, propD = True, propU = True, propE = True, propM = True
    , propS = True, propK = True }

  MsOlder n -> emptyProps
    { propZ = True, propF = True, propM = True
    , propH = isRelativeHeight n, propG = isRelativeTime n, propK = True }

  MsAfter n -> emptyProps
    { propZ = True, propF = True, propM = True
    , propJ = isAbsoluteHeight n, propI = isAbsoluteTime n, propK = True }

  MsSha256 _ -> hashProps
  MsHash256 _ -> hashProps
  MsRipemd160 _ -> hashProps
  MsHash160 _ -> hashProps

  MsAndV x y ->
    let px = miniscriptProps x
        py = miniscriptProps y
    in emptyProps
      { propZ = propZ px && propZ py
      , propO = (propZ px && propO py) || (propO px && propZ py)
      , propN = propN px || (propZ px && propN py)
      , propD = False  -- and_v cannot be dissatisfied
      , propU = propU py
      , propE = False
      , propF = propF px || propF py
      , propS = propS px || propS py
      , propM = propM px && propM py && (propS px || propE py)
      , propX = propX py
      , propG = propG px || propG py
      , propH = propH px || propH py
      , propI = propI px || propI py
      , propJ = propJ px || propJ py
      , propK = propK px && propK py && noTimelockConflict px py
      }

  MsAndB x y ->
    let px = miniscriptProps x
        py = miniscriptProps y
    in emptyProps
      { propZ = propZ px && propZ py
      , propO = (propZ px && propO py) || (propO px && propZ py)
      , propN = propN px || propN py
      , propD = propD px && propD py
      , propU = True
      , propE = (propE px && propE py) || (propE px && propD py) || (propD px && propE py)
      , propF = propF px || propF py
      , propS = propS px || propS py
      , propM = propM px && propM py && (propS px || propE py)
      , propX = True
      , propG = propG px || propG py
      , propH = propH px || propH py
      , propI = propI px || propI py
      , propJ = propJ px || propJ py
      , propK = propK px && propK py && noTimelockConflict px py
      }

  MsOrB x y ->
    let px = miniscriptProps x
        py = miniscriptProps y
    in emptyProps
      { propZ = propZ px && propZ py
      , propO = (propZ px && propO py) || (propO px && propZ py)
      , propN = False
      , propD = propD px && propD py
      , propU = True
      , propE = propE px && propE py
      , propF = False
      , propS = propS px && propS py
      , propM = propM px && propM py && propE px && propE py
      , propX = True
      , propG = propG px || propG py
      , propH = propH px || propH py
      , propI = propI px || propI py
      , propJ = propJ px || propJ py
      , propK = propK px && propK py && noTimelockConflict px py
      }

  MsOrC x y ->
    let px = miniscriptProps x
        py = miniscriptProps y
    in emptyProps
      { propZ = propZ px && propZ py
      , propO = propO px && propZ py
      , propN = False
      , propD = False
      , propU = False
      , propE = False
      , propF = propF py
      , propS = propS px && propS py
      , propM = propM px && propM py && propE px && propS py
      , propX = True
      , propG = propG px || propG py
      , propH = propH px || propH py
      , propI = propI px || propI py
      , propJ = propJ px || propJ py
      , propK = propK px && propK py && noTimelockConflict px py
      }

  MsOrD x y ->
    let px = miniscriptProps x
        py = miniscriptProps y
    in emptyProps
      { propZ = propZ px && propZ py
      , propO = propO px && propZ py
      , propN = False
      , propD = propD py
      , propU = propU py
      , propE = propE py
      , propF = propF py
      , propS = propS px && propS py
      , propM = propM px && propM py && propE px && propS py
      , propX = True
      , propG = propG px || propG py
      , propH = propH px || propH py
      , propI = propI px || propI py
      , propJ = propJ px || propJ py
      , propK = propK px && propK py && noTimelockConflict px py
      }

  MsOrI x y ->
    let px = miniscriptProps x
        py = miniscriptProps y
    in emptyProps
      { propZ = False
      , propO = propZ px && propZ py
      , propN = False
      , propD = propD px || propD py
      , propU = propU px && propU py
      , propE = (propF px && propF py) || (propD px && propE py) || (propE px && propD py)
      , propF = propF px && propF py
      , propS = propS px || propS py
      , propM = propM px && propM py && (propS px || propE py)
      , propX = True
      , propG = propG px || propG py
      , propH = propH px || propH py
      , propI = propI px || propI py
      , propJ = propJ px || propJ py
      , propK = propK px && propK py && noTimelockConflict px py
      }

  MsAndOr x y z ->
    let px = miniscriptProps x
        py = miniscriptProps y
        pz = miniscriptProps z
    in emptyProps
      { propZ = propZ px && propZ py && propZ pz
      , propO = (propZ px && propO py && propO pz) || (propO px && propZ py && propZ pz)
      , propN = propN px || (propZ px && propN py) || (propZ px && propN pz)
      , propD = propD pz
      , propU = propU py && propU pz
      , propE = propE pz && (propS px || propF pz)
      , propF = propF py && propF pz
      , propS = (propS px || propS py) && propS pz
      , propM = propM px && propM py && propM pz && propE px && (propS px || propF pz || propS py)
      , propX = propX py || propX pz
      , propG = propG px || propG py || propG pz
      , propH = propH px || propH py || propH pz
      , propI = propI px || propI py || propI pz
      , propJ = propJ px || propJ py || propJ pz
      , propK = propK px && propK py && propK pz && noTimelockConflict3 px py pz
      }

  MsThresh k subs ->
    let ps = map miniscriptProps subs
        n = length subs
        allZ = all propZ ps
        countO = length (filter propO ps)
        restZ = length (filter propZ ps)
        allE = all propE ps
        allM = all propM ps
        anyS = any propS ps
    in emptyProps
      { propZ = allZ
      , propO = countO == 1 && restZ == n - 1
      , propN = False
      , propD = k < n
      , propU = True
      , propE = if k == n then allE else allE && k == 1
      , propF = k == n && any propF ps
      , propS = k <= length (filter propS ps)
      , propM = allM && (k == 1 || k == n) && allE
      , propX = True
      , propG = any propG ps
      , propH = any propH ps
      , propI = any propI ps
      , propJ = any propJ ps
      , propK = all propK ps && noTimelockConflictList ps
      }

  MsMulti _ _ -> emptyProps
    { propN = True, propD = True, propU = True, propE = True, propM = True
    , propS = True, propK = True }

  MsSortedMulti _ _ -> emptyProps
    { propN = True, propD = True, propU = True, propE = True, propM = True
    , propS = True, propK = True }

  MsMultiA _ _ -> emptyProps
    { propN = True, propD = True, propU = True, propE = True, propM = True
    , propS = True, propK = True }

  MsSortedMultiA _ _ -> emptyProps
    { propN = True, propD = True, propU = True, propE = True, propM = True
    , propS = True, propK = True }

  -- Wrappers
  MsA x ->
    let px = miniscriptProps x
    in px { propO = propZ px }  -- a: converts z to o

  MsS x ->
    let px = miniscriptProps x
    in px  -- s: keeps most properties

  MsC x ->
    let px = miniscriptProps x
    in emptyProps
      { propZ = False
      , propO = propO px
      , propN = propN px
      , propD = True
      , propU = True
      , propE = True
      , propF = propF px
      , propS = True
      , propM = propM px
      , propX = False
      , propG = propG px
      , propH = propH px
      , propI = propI px
      , propJ = propJ px
      , propK = propK px
      }

  MsD x ->
    let px = miniscriptProps x
    in emptyProps
      { propZ = True  -- d: consumes nothing extra
      , propO = propZ px
      , propN = True
      , propD = True
      , propU = propU px
      , propE = True
      , propF = propF px
      , propS = propS px
      , propM = propM px
      , propX = True
      , propG = propG px
      , propH = propH px
      , propI = propI px
      , propJ = propJ px
      , propK = propK px
      }

  MsV x ->
    let px = miniscriptProps x
    in emptyProps
      { propZ = propZ px
      , propO = propO px
      , propN = propN px
      , propD = False  -- V cannot be dissatisfied
      , propU = False  -- V pushes nothing
      , propE = False
      , propF = True   -- V always "forced"
      , propS = propS px
      , propM = propM px
      , propX = propX px
      , propG = propG px
      , propH = propH px
      , propI = propI px
      , propJ = propJ px
      , propK = propK px
      }

  MsJ x ->
    let px = miniscriptProps x
    in emptyProps
      { propZ = False
      , propO = propO px
      , propN = True
      , propD = True
      , propU = propU px
      , propE = propF px  -- e = f (the dissatisfaction is non-malleable if forcing)
      , propF = propF px
      , propS = propS px
      , propM = propM px
      , propX = True
      , propG = propG px
      , propH = propH px
      , propI = propI px
      , propJ = propJ px
      , propK = propK px
      }

  MsN x ->
    let px = miniscriptProps x
    in px { propU = True }  -- n: forces unit output

  MsL x ->
    let px = miniscriptProps x
    in px { propZ = False, propO = propZ px, propD = True, propE = propF px }

  MsU x ->
    let px = miniscriptProps x
    in px { propZ = False, propO = propZ px, propD = True, propE = propF px }

  MsT x -> miniscriptProps (MsAndV x MsTrue)
  where
    hashProps = emptyProps
      { propO = True, propN = True, propD = True, propU = True
      , propM = True, propK = True }

-- | Check if a value represents a relative height lock
isRelativeHeight :: Word32 -> Bool
isRelativeHeight n = (n .&. 0x00400000) == 0 && n > 0

-- | Check if a value represents a relative time lock
isRelativeTime :: Word32 -> Bool
isRelativeTime n = (n .&. 0x00400000) /= 0

-- | Check if a value represents an absolute height lock
isAbsoluteHeight :: Word32 -> Bool
isAbsoluteHeight n = n < 500000000 && n > 0

-- | Check if a value represents an absolute time lock
isAbsoluteTime :: Word32 -> Bool
isAbsoluteTime n = n >= 500000000

-- | Check for timelock conflicts between two property sets
noTimelockConflict :: MiniscriptProps -> MiniscriptProps -> Bool
noTimelockConflict p1 p2 =
  -- Cannot mix relative time and height
  not ((propG p1 || propG p2) && (propH p1 || propH p2)) &&
  -- Cannot mix absolute time and height
  not ((propI p1 || propI p2) && (propJ p1 || propJ p2))

-- | Check for timelock conflicts among three property sets
noTimelockConflict3 :: MiniscriptProps -> MiniscriptProps -> MiniscriptProps -> Bool
noTimelockConflict3 p1 p2 p3 =
  noTimelockConflict p1 p2 && noTimelockConflict p2 p3 && noTimelockConflict p1 p3

-- | Check for timelock conflicts in a list of property sets
noTimelockConflictList :: [MiniscriptProps] -> Bool
noTimelockConflictList [] = True
noTimelockConflictList [_] = True
noTimelockConflictList (p:ps) = all (noTimelockConflict p) ps && noTimelockConflictList ps

-- | Type check a miniscript expression
checkMiniscriptType :: MiniscriptContext -> Miniscript -> Either MiniscriptError ()
checkMiniscriptType ctx ms = do
  -- Top-level must be type B
  let tp = miniscriptType ms
  unless (tp == TypeB) $
    Left $ MsTypeError $ "Top-level must be type B, got " ++ show tp
  -- Check context-specific restrictions
  case ctx of
    ContextP2WSH -> checkP2WSHRestrictions ms
    ContextTapscript -> checkTapscriptRestrictions ms
  -- Check k property (no conflicting timelocks)
  let props = miniscriptProps ms
  unless (propK props) $
    Left $ MsTypeError "Conflicting timelocks"
  -- Check that expression is satisfiable (has signature path)
  unless (propS props || propF props) $
    Left $ MsTypeError "Expression has no satisfaction with signatures"
  return ()

-- | Check P2WSH-specific restrictions
checkP2WSHRestrictions :: Miniscript -> Either MiniscriptError ()
checkP2WSHRestrictions ms = case ms of
  MsMultiA _ _ -> Left $ MsContextError "multi_a not allowed in P2WSH"
  MsSortedMultiA _ _ -> Left $ MsContextError "sortedmulti_a not allowed in P2WSH"
  MsA x -> checkP2WSHRestrictions x
  MsS x -> checkP2WSHRestrictions x
  MsC x -> checkP2WSHRestrictions x
  MsD x -> checkP2WSHRestrictions x
  MsV x -> checkP2WSHRestrictions x
  MsJ x -> checkP2WSHRestrictions x
  MsN x -> checkP2WSHRestrictions x
  MsL x -> checkP2WSHRestrictions x
  MsU x -> checkP2WSHRestrictions x
  MsT x -> checkP2WSHRestrictions x
  MsAndV x y -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y
  MsAndB x y -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y
  MsOrB x y -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y
  MsOrC x y -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y
  MsOrD x y -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y
  MsOrI x y -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y
  MsAndOr x y z -> checkP2WSHRestrictions x >> checkP2WSHRestrictions y >> checkP2WSHRestrictions z
  MsThresh _ subs -> mapM_ checkP2WSHRestrictions subs
  _ -> return ()

-- | Check Tapscript-specific restrictions
checkTapscriptRestrictions :: Miniscript -> Either MiniscriptError ()
checkTapscriptRestrictions ms = case ms of
  MsMulti _ _ -> Left $ MsContextError "multi not allowed in Tapscript (use multi_a)"
  MsSortedMulti _ _ -> Left $ MsContextError "sortedmulti not allowed in Tapscript (use sortedmulti_a)"
  MsA x -> checkTapscriptRestrictions x
  MsS x -> checkTapscriptRestrictions x
  MsC x -> checkTapscriptRestrictions x
  MsD x -> checkTapscriptRestrictions x
  MsV x -> checkTapscriptRestrictions x
  MsJ x -> checkTapscriptRestrictions x
  MsN x -> checkTapscriptRestrictions x
  MsL x -> checkTapscriptRestrictions x
  MsU x -> checkTapscriptRestrictions x
  MsT x -> checkTapscriptRestrictions x
  MsAndV x y -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y
  MsAndB x y -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y
  MsOrB x y -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y
  MsOrC x y -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y
  MsOrD x y -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y
  MsOrI x y -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y
  MsAndOr x y z -> checkTapscriptRestrictions x >> checkTapscriptRestrictions y >> checkTapscriptRestrictions z
  MsThresh _ subs -> mapM_ checkTapscriptRestrictions subs
  _ -> return ()

--------------------------------------------------------------------------------
-- Compilation to Script
--------------------------------------------------------------------------------

-- | Compile a miniscript to a Script
compileMiniscript :: MiniscriptContext -> Miniscript -> Script
compileMiniscript ctx ms = Script (compileOps ctx False ms)

-- | Internal compilation with verify flag
-- The 'verify' flag indicates whether the sub-expression's final opcode
-- should use a -VERIFY variant if possible
compileOps :: MiniscriptContext -> Bool -> Miniscript -> [ScriptOp]
compileOps ctx verify ms = case ms of
  MsTrue -> [OP_1]
  MsFalse -> [OP_0]

  MsPk pk -> [pushData pk]

  MsPkH pk ->
    let Hash160 h = hash160 pk
    in [OP_DUP, OP_HASH160, pushData h, OP_EQUALVERIFY]

  MsOlder n ->
    [pushNum (fromIntegral n), OP_CHECKSEQUENCEVERIFY]

  MsAfter n ->
    [pushNum (fromIntegral n), OP_CHECKLOCKTIMEVERIFY]

  MsSha256 h ->
    [OP_SIZE, pushNum 32, OP_EQUALVERIFY, OP_SHA256, pushData h] ++
    if verify then [OP_EQUALVERIFY] else [OP_EQUAL]

  MsHash256 h ->
    [OP_SIZE, pushNum 32, OP_EQUALVERIFY, OP_HASH256, pushData h] ++
    if verify then [OP_EQUALVERIFY] else [OP_EQUAL]

  MsRipemd160 h ->
    [OP_SIZE, pushNum 32, OP_EQUALVERIFY, OP_RIPEMD160, pushData h] ++
    if verify then [OP_EQUALVERIFY] else [OP_EQUAL]

  MsHash160 h ->
    [OP_SIZE, pushNum 32, OP_EQUALVERIFY, OP_HASH160, pushData h] ++
    if verify then [OP_EQUALVERIFY] else [OP_EQUAL]

  MsAndV x y ->
    compileOps ctx True x ++ compileOps ctx verify y

  MsAndB x y ->
    compileOps ctx False x ++ compileOps ctx False y ++
    if verify then [OP_BOOLAND, OP_VERIFY] else [OP_BOOLAND]

  MsOrB x y ->
    compileOps ctx False x ++ compileOps ctx False y ++
    if verify then [OP_BOOLOR, OP_VERIFY] else [OP_BOOLOR]

  MsOrC x y ->
    compileOps ctx False x ++ [OP_NOTIF] ++ compileOps ctx True y ++ [OP_ENDIF]

  MsOrD x y ->
    compileOps ctx False x ++ [OP_IFDUP, OP_NOTIF] ++ compileOps ctx verify y ++ [OP_ENDIF]

  MsOrI x y ->
    [OP_IF] ++ compileOps ctx verify x ++ [OP_ELSE] ++ compileOps ctx verify y ++ [OP_ENDIF]

  MsAndOr x y z ->
    compileOps ctx False x ++ [OP_NOTIF] ++
    compileOps ctx verify z ++ [OP_ELSE] ++
    compileOps ctx verify y ++ [OP_ENDIF]

  MsThresh k subs ->
    let compiled = map (compileOps ctx False) subs
        -- First expression, then ADD between rest
        addOps = case compiled of
                   [] -> []
                   (first:rest) -> first ++ concatMap (\ops -> ops ++ [OP_ADD]) rest
    in addOps ++ [pushNum (fromIntegral k)] ++
       if verify then [OP_EQUALVERIFY] else [OP_EQUAL]

  MsMulti k pks ->
    [pushNum (fromIntegral k)] ++
    map pushData pks ++
    [pushNum (fromIntegral (length pks))] ++
    if verify then [OP_CHECKMULTISIGVERIFY] else [OP_CHECKMULTISIG]

  MsSortedMulti k pks ->
    let sortedPks = sortPubKeys pks
    in [pushNum (fromIntegral k)] ++
       map pushData sortedPks ++
       [pushNum (fromIntegral (length pks))] ++
       if verify then [OP_CHECKMULTISIGVERIFY] else [OP_CHECKMULTISIG]

  MsMultiA k pks ->
    -- Tapscript: <key0> OP_CHECKSIG <key1> OP_CHECKSIGADD ... <k> OP_NUMEQUAL
    case pks of
      [] -> [pushNum (fromIntegral k), OP_NUMEQUAL]
      [pk] -> [pushData pk] ++
              if verify then [OP_CHECKSIGVERIFY] else [OP_CHECKSIG]
      (pk:rest) ->
        [pushData pk, OP_CHECKSIG] ++
        concatMap (\p -> [pushData p, opChecksigAdd]) rest ++
        [pushNum (fromIntegral k)] ++
        if verify then [OP_NUMEQUALVERIFY] else [OP_NUMEQUAL]
    where
      -- OP_CHECKSIGADD (0xBA), Tapscript-only (BIP-342)
      opChecksigAdd = OP_CHECKSIGADD

  MsSortedMultiA k pks ->
    compileOps ctx verify (MsMultiA k (sortPubKeys pks))

  -- Wrappers
  MsA x ->
    [OP_TOALTSTACK] ++ compileOps ctx False x ++ [OP_FROMALTSTACK]

  MsS x ->
    [OP_SWAP] ++ compileOps ctx verify x

  MsC x ->
    compileOps ctx False x ++
    if verify then [OP_CHECKSIGVERIFY] else [OP_CHECKSIG]

  MsD x ->
    [OP_DUP, OP_IF] ++ compileOps ctx True x ++ [OP_ENDIF]

  MsV x ->
    let ops = compileOps ctx False x
    in if canUseVerify (last ops)
       then init ops ++ [toVerify (last ops)]
       else ops ++ [OP_VERIFY]

  MsJ x ->
    [OP_SIZE, OP_0NOTEQUAL, OP_IF] ++ compileOps ctx True x ++ [OP_ENDIF]

  MsN x ->
    compileOps ctx False x ++ [OP_0NOTEQUAL]

  MsL x ->
    [OP_IF, OP_0, OP_ELSE] ++ compileOps ctx verify x ++ [OP_ENDIF]

  MsU x ->
    [OP_IF] ++ compileOps ctx verify x ++ [OP_ELSE, OP_0, OP_ENDIF]

  MsT x ->
    compileOps ctx True x  -- t: = and_v(X, 1), just make X verify
  where
    -- Push data with optimal encoding
    pushData :: ByteString -> ScriptOp
    pushData bs = OP_PUSHDATA bs OPCODE

    -- Push number with optimal encoding
    pushNum :: Int64 -> ScriptOp
    pushNum n
      | n == 0 = OP_0
      | n == -1 = OP_1NEGATE
      | n >= 1 && n <= 16 = opN (fromIntegral n)
      | otherwise = OP_PUSHDATA (encodeScriptNum n) OPCODE

    -- Sort public keys lexicographically
    sortPubKeys :: [ByteString] -> [ByteString]
    sortPubKeys = sortBy compare

    -- Check if an opcode can be converted to a -VERIFY variant
    canUseVerify :: ScriptOp -> Bool
    canUseVerify op = case op of
      OP_EQUAL -> True
      OP_CHECKSIG -> True
      OP_CHECKMULTISIG -> True
      OP_NUMEQUAL -> True
      _ -> False

    -- Convert an opcode to its -VERIFY variant
    toVerify :: ScriptOp -> ScriptOp
    toVerify op = case op of
      OP_EQUAL -> OP_EQUALVERIFY
      OP_CHECKSIG -> OP_CHECKSIGVERIFY
      OP_CHECKMULTISIG -> OP_CHECKMULTISIGVERIFY
      OP_NUMEQUAL -> OP_NUMEQUALVERIFY
      _ -> op

-- | Calculate the script size of a miniscript
miniscriptSize :: MiniscriptContext -> Miniscript -> Int
miniscriptSize ctx ms = BS.length (encodeScript (compileMiniscript ctx ms))

--------------------------------------------------------------------------------
-- Satisfaction
--------------------------------------------------------------------------------

-- | Find the minimal-cost satisfaction for a miniscript
satisfyMiniscript :: SatisfactionContext -> Miniscript -> Either MiniscriptError Witness
satisfyMiniscript ctx ms = do
  let result = satisfy ctx ms
  if satCost result == maxBound
    then Left $ MsSatisfactionError "Cannot satisfy miniscript"
    else Right (satWitness result)

-- | Find a dissatisfaction for a miniscript
dissatisfyMiniscript :: SatisfactionContext -> Miniscript -> Either MiniscriptError Witness
dissatisfyMiniscript ctx ms = do
  let result = dissatisfy ctx ms
  if satCost result == maxBound
    then Left $ MsSatisfactionError "Cannot dissatisfy miniscript"
    else Right (satWitness result)

-- | Internal satisfaction function
satisfy :: SatisfactionContext -> Miniscript -> SatResult
satisfy ctx ms = case ms of
  MsTrue -> SatResult [] 0 False False

  MsFalse -> satUnavailable  -- Cannot satisfy false

  MsPk pk ->
    case Map.lookup pk (satSignatures ctx) of
      Just sig -> SatResult [sig] (BS.length sig + 1) True False
      Nothing -> satUnavailable

  MsPkH pk ->
    case Map.lookup pk (satSignatures ctx) of
      Just sig -> SatResult [sig, pk] (BS.length sig + BS.length pk + 2) True False
      Nothing -> satUnavailable

  MsOlder _ -> SatResult [] 0 False False  -- Time-based, no witness needed

  MsAfter _ -> SatResult [] 0 False False  -- Time-based, no witness needed

  MsSha256 h -> satisfyHash ctx h
  MsHash256 h -> satisfyHash ctx h
  MsRipemd160 h -> satisfyHash ctx h
  MsHash160 h -> satisfyHash ctx h

  MsAndV x y ->
    satConcat (satisfy ctx y) (satisfy ctx x)  -- Y first (top of stack)

  MsAndB x y ->
    satConcat (satisfy ctx y) (satisfy ctx x)

  MsOrB x y ->
    -- Either satisfy x and dissatisfy y, or vice versa
    satChoice
      (satConcat (dissatisfy ctx y) (satisfy ctx x))
      (satConcat (satisfy ctx y) (dissatisfy ctx x))

  MsOrC x y ->
    satChoice (satisfy ctx x) (satisfy ctx y)

  MsOrD x y ->
    satChoice (satisfy ctx x) (satisfy ctx y)

  MsOrI x y ->
    -- Choose branch with OP_IF selector
    let satX = satisfy ctx x
        satY = satisfy ctx y
        withX = satConcat (SatResult [BS.singleton 1] 2 False False) satX
        withY = satConcat (SatResult [BS.empty] 1 False False) satY
    in satChoice withX withY

  MsAndOr x y z ->
    -- If X satisfied, use Y. Otherwise use Z.
    satChoice
      (satConcat (satisfy ctx y) (satisfy ctx x))
      (satConcat (satisfy ctx z) (dissatisfy ctx x))

  MsThresh k subs ->
    satisfyThresh ctx k subs

  MsMulti k pks ->
    satisfyMulti ctx k pks

  MsSortedMulti k pks ->
    satisfyMulti ctx k (sortBy compare pks)

  MsMultiA k pks ->
    satisfyMultiA ctx k pks

  MsSortedMultiA k pks ->
    satisfyMultiA ctx k (sortBy compare pks)

  -- Wrappers
  MsA x -> satisfy ctx x
  MsS x -> satisfy ctx x
  MsC x -> satisfy ctx x
  MsD x ->
    let sat = satisfy ctx x
    in satConcat (SatResult [BS.singleton 1] 2 False False) sat
  MsV x -> satisfy ctx x
  MsJ x -> satisfy ctx x
  MsN x -> satisfy ctx x
  MsL x -> satisfy ctx x
  MsU x -> satisfy ctx x
  MsT x -> satisfy ctx x

-- | Internal dissatisfaction function
dissatisfy :: SatisfactionContext -> Miniscript -> SatResult
dissatisfy ctx ms = case ms of
  MsTrue -> satUnavailable  -- Cannot dissatisfy true
  MsFalse -> SatResult [] 0 False False

  MsPk _ -> SatResult [BS.empty] 1 False False  -- Empty signature

  MsPkH pk ->
    SatResult [BS.empty, pk] (1 + BS.length pk + 1) False False

  MsOlder _ -> satUnavailable  -- Cannot dissatisfy timelock
  MsAfter _ -> satUnavailable

  MsSha256 _ -> dissatisfyHash
  MsHash256 _ -> dissatisfyHash
  MsRipemd160 _ -> dissatisfyHash
  MsHash160 _ -> dissatisfyHash

  MsAndV _ _ -> satUnavailable  -- Cannot dissatisfy and_v

  MsAndB x y ->
    -- Dissatisfy either or both
    satChoice
      (satConcat (dissatisfy ctx y) (dissatisfy ctx x))
      (satChoice
        (satConcat (dissatisfy ctx y) (satisfy ctx x))
        (satConcat (satisfy ctx y) (dissatisfy ctx x)))

  MsOrB x y ->
    satConcat (dissatisfy ctx y) (dissatisfy ctx x)

  MsOrC _ _ -> satUnavailable  -- or_c produces V, cannot dissatisfy

  MsOrD x y ->
    satConcat (dissatisfy ctx y) (dissatisfy ctx x)

  MsOrI x y ->
    -- Dissatisfy whichever branch we can
    let dsatX = dissatisfy ctx x
        dsatY = dissatisfy ctx y
        withX = satConcat (SatResult [BS.singleton 1] 2 False False) dsatX
        withY = satConcat (SatResult [BS.empty] 1 False False) dsatY
    in satChoice withX withY

  MsAndOr _ _ z ->
    -- Dissatisfy: need X to fail and Z to fail
    satConcat (dissatisfy ctx z) (dissatisfy ctx (MsFalse))

  MsThresh k subs ->
    dissatisfyThresh ctx k subs

  MsMulti _ pks ->
    -- All empty signatures + dummy
    SatResult (replicate (length pks + 1) BS.empty) (length pks + 1) False False

  MsSortedMulti _ pks ->
    SatResult (replicate (length pks + 1) BS.empty) (length pks + 1) False False

  MsMultiA _ pks ->
    SatResult (replicate (length pks) BS.empty) (length pks) False False

  MsSortedMultiA _ pks ->
    SatResult (replicate (length pks) BS.empty) (length pks) False False

  -- Wrappers
  MsA x -> dissatisfy ctx x
  MsS x -> dissatisfy ctx x
  MsC x -> dissatisfy ctx x
  MsD _ -> SatResult [BS.empty] 1 False False  -- Push 0 to skip IF
  MsV _ -> satUnavailable  -- V cannot be dissatisfied
  MsJ _ -> SatResult [BS.empty] 1 False False  -- Push empty to fail SIZE check
  MsN x -> dissatisfy ctx x
  MsL x -> dissatisfy ctx x
  MsU x -> dissatisfy ctx x
  MsT _ -> satUnavailable  -- t: = and_v, cannot dissatisfy

-- | Satisfy a hash preimage check
satisfyHash :: SatisfactionContext -> ByteString -> SatResult
satisfyHash ctx h =
  case Map.lookup h (satPreimages ctx) of
    Just preimage -> SatResult [preimage] (BS.length preimage + 1) False False
    Nothing -> satUnavailable

-- | Dissatisfy a hash check (32-byte non-preimage)
dissatisfyHash :: SatResult
dissatisfyHash = SatResult [BS.replicate 32 0] 33 False True

-- | Satisfy threshold
satisfyThresh :: SatisfactionContext -> Int -> [Miniscript] -> SatResult
satisfyThresh ctx k subs =
  -- Use dynamic programming to find best combination
  let results = map (\s -> (satisfy ctx s, dissatisfy ctx s)) subs
      -- Start with dissatisfying all, then upgrade k to satisfied
      initial = foldl' satConcat (SatResult [] 0 False False)
                       (map snd results)
      -- Try different combinations (simplified: greedy approach)
      sortedByGain = sortBy (\(s1, d1) (s2, d2) ->
        compare (satCost s1 - satCost d1) (satCost s2 - satCost d2)) results
      -- Take k cheapest satisfactions
      chosen = take k sortedByGain
      rest = drop k sortedByGain
  in foldl' satConcat (SatResult [] 0 False False)
            (map fst chosen ++ map snd rest)

-- | Dissatisfy threshold
dissatisfyThresh :: SatisfactionContext -> Int -> [Miniscript] -> SatResult
dissatisfyThresh ctx k subs
  | k == length subs =
      -- Need to dissatisfy at least one
      let dsats = map (dissatisfy ctx) subs
          sats = map (satisfy ctx) subs
          -- Try dissatisfying one, satisfying rest
          options = [ satConcat d (foldl' satConcat (SatResult [] 0 False False)
                        (take i sats ++ drop (i+1) sats))
                    | (i, d) <- zip [0..] dsats ]
      in foldl' satChoice satUnavailable options
  | otherwise =
      -- Dissatisfy all
      foldl' satConcat (SatResult [] 0 False False) (map (dissatisfy ctx) subs)

-- | Satisfy multisig
satisfyMulti :: SatisfactionContext -> Int -> [ByteString] -> SatResult
satisfyMulti ctx k pks =
  let sigs = mapMaybe (\pk -> Map.lookup pk (satSignatures ctx)) pks
  in if length sigs >= k
     then let chosen = take k sigs
              -- Add dummy element for CHECKMULTISIG bug
              witness = BS.empty : chosen
              cost = sum (map (\s -> BS.length s + 1) chosen) + 1
          in SatResult witness cost True False
     else satUnavailable

-- | Satisfy multi_a (tapscript)
satisfyMultiA :: SatisfactionContext -> Int -> [ByteString] -> SatResult
satisfyMultiA ctx k pks =
  -- In tapscript, we provide k signatures for k keys
  let sigResults = map (\pk ->
        case Map.lookup pk (satSignatures ctx) of
          Just sig -> (sig, True)
          Nothing -> (BS.empty, False)) pks
      validCount = length (filter snd sigResults)
  in if validCount >= k
     then let witness = map fst sigResults
              cost = sum (map (\(s, _) -> BS.length s + 1) sigResults)
          in SatResult witness cost True False
     else satUnavailable

--------------------------------------------------------------------------------
-- Parsing and Serialization
--------------------------------------------------------------------------------

-- | Parse a miniscript from text notation
parseMiniscript :: String -> Either MiniscriptError Miniscript
parseMiniscript input = parseExpr (filter (not . isSpace) input)
  where
    parseExpr :: String -> Either MiniscriptError Miniscript
    parseExpr s
      | s == "1" = Right MsTrue
      | s == "0" = Right MsFalse
      | "pk(" `isPrefixOf` s = parsePk s
      | "pk_h(" `isPrefixOf` s = parsePkH s
      | "older(" `isPrefixOf` s = parseOlder s
      | "after(" `isPrefixOf` s = parseAfter s
      | "sha256(" `isPrefixOf` s = parseSha256 s
      | "hash256(" `isPrefixOf` s = parseHash256 s
      | "ripemd160(" `isPrefixOf` s = parseRipemd160 s
      | "hash160(" `isPrefixOf` s = parseHash160 s
      | "and_v(" `isPrefixOf` s = parseAndV s
      | "and_b(" `isPrefixOf` s = parseAndB s
      | "or_b(" `isPrefixOf` s = parseOrB s
      | "or_c(" `isPrefixOf` s = parseOrC s
      | "or_d(" `isPrefixOf` s = parseOrD s
      | "or_i(" `isPrefixOf` s = parseOrI s
      | "andor(" `isPrefixOf` s = parseAndOr s
      | "thresh(" `isPrefixOf` s = parseThresh s
      | "multi(" `isPrefixOf` s = parseMulti s
      | "sortedmulti(" `isPrefixOf` s = parseSortedMulti s
      | "multi_a(" `isPrefixOf` s = parseMultiA s
      | "sortedmulti_a(" `isPrefixOf` s = parseSortedMultiA s
      -- Wrappers
      | "a:" `isPrefixOf` s = MsA <$> parseExpr (drop 2 s)
      | "s:" `isPrefixOf` s = MsS <$> parseExpr (drop 2 s)
      | "c:" `isPrefixOf` s = MsC <$> parseExpr (drop 2 s)
      | "d:" `isPrefixOf` s = MsD <$> parseExpr (drop 2 s)
      | "v:" `isPrefixOf` s = MsV <$> parseExpr (drop 2 s)
      | "j:" `isPrefixOf` s = MsJ <$> parseExpr (drop 2 s)
      | "n:" `isPrefixOf` s = MsN <$> parseExpr (drop 2 s)
      | "l:" `isPrefixOf` s = MsL <$> parseExpr (drop 2 s)
      | "u:" `isPrefixOf` s = MsU <$> parseExpr (drop 2 s)
      | "t:" `isPrefixOf` s = MsT <$> parseExpr (drop 2 s)
      | otherwise = Left $ MsParseError $ "Unknown expression: " ++ take 20 s

    isPrefixOf :: String -> String -> Bool
    isPrefixOf prefix str = take (length prefix) str == prefix

    parsePk s = do
      let inner = extractInner "pk(" s
      case hexToBS inner of
        Just pk -> Right $ MsPk pk
        Nothing -> Left $ MsParseError "Invalid hex in pk()"

    parsePkH s = do
      let inner = extractInner "pk_h(" s
      case hexToBS inner of
        Just pk -> Right $ MsPkH pk
        Nothing -> Left $ MsParseError "Invalid hex in pk_h()"

    parseOlder s = do
      let inner = extractInner "older(" s
      case reads inner of
        [(n, "")] -> Right $ MsOlder n
        _ -> Left $ MsParseError "Invalid number in older()"

    parseAfter s = do
      let inner = extractInner "after(" s
      case reads inner of
        [(n, "")] -> Right $ MsAfter n
        _ -> Left $ MsParseError "Invalid number in after()"

    parseSha256 s = do
      let inner = extractInner "sha256(" s
      case hexToBS inner of
        Just h | BS.length h == 32 -> Right $ MsSha256 h
        _ -> Left $ MsParseError "Invalid hash in sha256()"

    parseHash256 s = do
      let inner = extractInner "hash256(" s
      case hexToBS inner of
        Just h | BS.length h == 32 -> Right $ MsHash256 h
        _ -> Left $ MsParseError "Invalid hash in hash256()"

    parseRipemd160 s = do
      let inner = extractInner "ripemd160(" s
      case hexToBS inner of
        Just h | BS.length h == 20 -> Right $ MsRipemd160 h
        _ -> Left $ MsParseError "Invalid hash in ripemd160()"

    parseHash160 s = do
      let inner = extractInner "hash160(" s
      case hexToBS inner of
        Just h | BS.length h == 20 -> Right $ MsHash160 h
        _ -> Left $ MsParseError "Invalid hash in hash160()"

    parseAndV s = do
      let inner = extractInner "and_v(" s
      case splitArgs inner of
        [a, b] -> MsAndV <$> parseExpr a <*> parseExpr b
        _ -> Left $ MsParseError "and_v requires 2 arguments"

    parseAndB s = do
      let inner = extractInner "and_b(" s
      case splitArgs inner of
        [a, b] -> MsAndB <$> parseExpr a <*> parseExpr b
        _ -> Left $ MsParseError "and_b requires 2 arguments"

    parseOrB s = do
      let inner = extractInner "or_b(" s
      case splitArgs inner of
        [a, b] -> MsOrB <$> parseExpr a <*> parseExpr b
        _ -> Left $ MsParseError "or_b requires 2 arguments"

    parseOrC s = do
      let inner = extractInner "or_c(" s
      case splitArgs inner of
        [a, b] -> MsOrC <$> parseExpr a <*> parseExpr b
        _ -> Left $ MsParseError "or_c requires 2 arguments"

    parseOrD s = do
      let inner = extractInner "or_d(" s
      case splitArgs inner of
        [a, b] -> MsOrD <$> parseExpr a <*> parseExpr b
        _ -> Left $ MsParseError "or_d requires 2 arguments"

    parseOrI s = do
      let inner = extractInner "or_i(" s
      case splitArgs inner of
        [a, b] -> MsOrI <$> parseExpr a <*> parseExpr b
        _ -> Left $ MsParseError "or_i requires 2 arguments"

    parseAndOr s = do
      let inner = extractInner "andor(" s
      case splitArgs inner of
        [a, b, c] -> MsAndOr <$> parseExpr a <*> parseExpr b <*> parseExpr c
        _ -> Left $ MsParseError "andor requires 3 arguments"

    parseThresh s = do
      let inner = extractInner "thresh(" s
      case splitArgs inner of
        (k:subs) -> do
          kVal <- case reads k of
                    [(n, "")] -> Right n
                    _ -> Left $ MsParseError "Invalid threshold k"
          subExprs <- mapM parseExpr subs
          Right $ MsThresh kVal subExprs
        _ -> Left $ MsParseError "thresh requires k and sub-expressions"

    parseMulti s = do
      let inner = extractInner "multi(" s
      case splitArgs inner of
        (k:pks) -> do
          kVal <- case reads k of
                    [(n, "")] -> Right n
                    _ -> Left $ MsParseError "Invalid multi k"
          pkBytes <- mapM (\h -> maybe (Left $ MsParseError "Invalid key") Right (hexToBS h)) pks
          Right $ MsMulti kVal pkBytes
        _ -> Left $ MsParseError "multi requires k and keys"

    parseSortedMulti s = do
      let inner = extractInner "sortedmulti(" s
      case splitArgs inner of
        (k:pks) -> do
          kVal <- case reads k of
                    [(n, "")] -> Right n
                    _ -> Left $ MsParseError "Invalid sortedmulti k"
          pkBytes <- mapM (\h -> maybe (Left $ MsParseError "Invalid key") Right (hexToBS h)) pks
          Right $ MsSortedMulti kVal pkBytes
        _ -> Left $ MsParseError "sortedmulti requires k and keys"

    parseMultiA s = do
      let inner = extractInner "multi_a(" s
      case splitArgs inner of
        (k:pks) -> do
          kVal <- case reads k of
                    [(n, "")] -> Right n
                    _ -> Left $ MsParseError "Invalid multi_a k"
          pkBytes <- mapM (\h -> maybe (Left $ MsParseError "Invalid key") Right (hexToBS h)) pks
          Right $ MsMultiA kVal pkBytes
        _ -> Left $ MsParseError "multi_a requires k and keys"

    parseSortedMultiA s = do
      let inner = extractInner "sortedmulti_a(" s
      case splitArgs inner of
        (k:pks) -> do
          kVal <- case reads k of
                    [(n, "")] -> Right n
                    _ -> Left $ MsParseError "Invalid sortedmulti_a k"
          pkBytes <- mapM (\h -> maybe (Left $ MsParseError "Invalid key") Right (hexToBS h)) pks
          Right $ MsSortedMultiA kVal pkBytes
        _ -> Left $ MsParseError "sortedmulti_a requires k and keys"

    -- Extract inner contents between "func(" and matching ")"
    extractInner :: String -> String -> String
    extractInner prefix s =
      let afterPrefix = drop (length prefix) s
          -- Find matching closing paren
          findMatch :: Int -> String -> String
          findMatch 0 _ = ""
          findMatch _ "" = ""
          findMatch n (')':xs)
            | n == 1 = ""
            | otherwise = ')' : findMatch (n-1) xs
          findMatch n ('(':xs) = '(' : findMatch (n+1) xs
          findMatch n (x:xs) = x : findMatch n xs
      in findMatch 1 afterPrefix

    -- Split arguments by comma, respecting nested parentheses
    splitArgs :: String -> [String]
    splitArgs s = go 0 "" s
      where
        go _ acc "" = [reverse acc]
        go depth acc ('(':xs) = go (depth+1) ('(':acc) xs
        go depth acc (')':xs) = go (depth-1) (')':acc) xs
        go 0 acc (',':xs) = reverse acc : go 0 "" xs
        go depth acc (x:xs) = go depth (x:acc) xs

    -- Convert hex string to ByteString
    hexToBS :: String -> Maybe ByteString
    hexToBS hex
      | odd (length hex) = Nothing
      | all isHexChar hex = Just $ BS.pack $ hexPairs hex
      | otherwise = Nothing

    isHexChar :: Char -> Bool
    isHexChar c = c `elem` ("0123456789abcdefABCDEF" :: String)

    hexPairs :: String -> [Word8]
    hexPairs [] = []
    hexPairs (a:b:rest) = fromIntegral (hexVal a * 16 + hexVal b) : hexPairs rest
    hexPairs _ = []

    hexVal :: Char -> Int
    hexVal c
      | c >= '0' && c <= '9' = fromEnum c - fromEnum '0'
      | c >= 'a' && c <= 'f' = fromEnum c - fromEnum 'a' + 10
      | c >= 'A' && c <= 'F' = fromEnum c - fromEnum 'A' + 10
      | otherwise = 0

    isSpace :: Char -> Bool
    isSpace c = c `elem` (" \t\n\r" :: String)

-- | Convert a miniscript to text notation
miniscriptToText :: Miniscript -> String
miniscriptToText ms = case ms of
  MsTrue -> "1"
  MsFalse -> "0"
  MsPk pk -> "pk(" ++ toHex pk ++ ")"
  MsPkH pk -> "pk_h(" ++ toHex pk ++ ")"
  MsOlder n -> "older(" ++ show n ++ ")"
  MsAfter n -> "after(" ++ show n ++ ")"
  MsSha256 h -> "sha256(" ++ toHex h ++ ")"
  MsHash256 h -> "hash256(" ++ toHex h ++ ")"
  MsRipemd160 h -> "ripemd160(" ++ toHex h ++ ")"
  MsHash160 h -> "hash160(" ++ toHex h ++ ")"
  MsAndV x y -> "and_v(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ ")"
  MsAndB x y -> "and_b(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ ")"
  MsOrB x y -> "or_b(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ ")"
  MsOrC x y -> "or_c(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ ")"
  MsOrD x y -> "or_d(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ ")"
  MsOrI x y -> "or_i(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ ")"
  MsAndOr x y z -> "andor(" ++ miniscriptToText x ++ "," ++ miniscriptToText y ++ "," ++ miniscriptToText z ++ ")"
  MsThresh k subs -> "thresh(" ++ show k ++ "," ++ intercalate "," (map miniscriptToText subs) ++ ")"
  MsMulti k pks -> "multi(" ++ show k ++ "," ++ intercalate "," (map toHex pks) ++ ")"
  MsSortedMulti k pks -> "sortedmulti(" ++ show k ++ "," ++ intercalate "," (map toHex pks) ++ ")"
  MsMultiA k pks -> "multi_a(" ++ show k ++ "," ++ intercalate "," (map toHex pks) ++ ")"
  MsSortedMultiA k pks -> "sortedmulti_a(" ++ show k ++ "," ++ intercalate "," (map toHex pks) ++ ")"
  MsA x -> "a:" ++ miniscriptToText x
  MsS x -> "s:" ++ miniscriptToText x
  MsC x -> "c:" ++ miniscriptToText x
  MsD x -> "d:" ++ miniscriptToText x
  MsV x -> "v:" ++ miniscriptToText x
  MsJ x -> "j:" ++ miniscriptToText x
  MsN x -> "n:" ++ miniscriptToText x
  MsL x -> "l:" ++ miniscriptToText x
  MsU x -> "u:" ++ miniscriptToText x
  MsT x -> "t:" ++ miniscriptToText x
  where
    toHex :: ByteString -> String
    toHex = concatMap (printf "%02x") . BS.unpack

    intercalate :: String -> [String] -> String
    intercalate _ [] = ""
    intercalate _ [x] = x
    intercalate sep (x:xs) = x ++ sep ++ intercalate sep xs

    printf :: String -> Word8 -> String
    printf _ b =
      let hi = b `shiftR` 4
          lo = b .&. 0x0f
          hexChar n = if n < 10 then toEnum (fromEnum '0' + fromIntegral n)
                      else toEnum (fromEnum 'a' + fromIntegral (n - 10))
      in [hexChar hi, hexChar lo]

{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | Bitcoin transaction standardness policy (relay-time, not consensus).
--
-- Mirrors @bitcoin-core/src/policy/policy.cpp:IsStandardTx@. These rules
-- gate which transactions a node will accept into its mempool and relay,
-- but do NOT affect consensus / block validity. A non-standard but
-- otherwise consensus-valid transaction can still be mined directly.
--
-- Constants and decisions match Bitcoin Core's defaults as of v28.
module Haskoin.Policy.Standard
  ( -- * Top-level checks
    isStandardTx
  , checkStandardTx
  , StandardError(..)
    -- * Constants (Bitcoin Core defaults)
  , maxStandardTxWeight
  , txMinStandardVersion
  , txMaxStandardVersion
  , maxStandardScriptSigSize
  , maxOpReturnRelay
  , dustRelayTxFee
  , maxDustOutputsPerTx
  , maxStandardP2WSHScriptSize
  , minStandardTxNonWitnessSize
  , witnessScaleFactor'
    -- * Sub-checks
  , isStandardScriptPubKey
  , dustThreshold
  , isDust
  , txWeight
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Int (Int32)
import Data.Word (Word64)
import Data.Serialize (encode)

import Haskoin.Types
  ( Tx(..)
  , TxIn(..)
  , TxOut(..)
  )
import Haskoin.Script
  ( Script(..)
  , ScriptType(..)
  , classifyOutput
  , decodeScript
  , isPushOnly
  )
import Haskoin.Consensus (witnessScaleFactor, txBaseSize, txTotalSize)

--------------------------------------------------------------------------------
-- Constants (Bitcoin Core defaults)
--
-- Source of truth: bitcoin-core/src/policy/policy.h.
--------------------------------------------------------------------------------

-- | Maximum transaction weight that we will relay/mine (BIP141 weight).
-- @MAX_STANDARD_TX_WEIGHT = 400_000@ in bitcoin-core/src/policy/policy.h:38.
maxStandardTxWeight :: Int
maxStandardTxWeight = 400_000

-- | Minimum standard tx version. Core: @TX_MIN_STANDARD_VERSION = 1@.
txMinStandardVersion :: Int32
txMinStandardVersion = 1

-- | Maximum standard tx version. Core: @TX_MAX_STANDARD_VERSION = 3@.
-- Version 3 is reserved for TRUC (BIP-431) transactions.
txMaxStandardVersion :: Int32
txMaxStandardVersion = 3

-- | Maximum scriptSig size for any input.
-- Core: @MAX_STANDARD_SCRIPTSIG_SIZE = 1650@.
maxStandardScriptSigSize :: Int
maxStandardScriptSigSize = 1650

-- | Maximum size of an OP_RETURN data carrier output (per-output, in bytes).
-- Core: @MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR@.
maxOpReturnRelay :: Int
maxOpReturnRelay = maxStandardTxWeight `div` witnessScaleFactor

-- | Dust relay fee in sat/kvB. Core: @DUST_RELAY_TX_FEE = 3000@.
dustRelayTxFee :: Word64
dustRelayTxFee = 3000

-- | Maximum number of dust (ephemeral) outputs allowed per tx.
-- Core: @MAX_DUST_OUTPUTS_PER_TX = 1@. Bitcoin Core 28 changed from 0 to 1
-- to support BIP-431 ephemeral anchors; we follow that.
maxDustOutputsPerTx :: Int
maxDustOutputsPerTx = 1

-- | Maximum size in bytes of a standard P2WSH witness script.
-- Core: @MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600@.
maxStandardP2WSHScriptSize :: Int
maxStandardP2WSHScriptSize = 3600

-- | Smallest non-witness serialised tx that we'll relay.
-- Core: @MIN_STANDARD_TX_NONWITNESS_SIZE = 65@.
minStandardTxNonWitnessSize :: Int
minStandardTxNonWitnessSize = 65

-- | Local copy of the consensus witness scale factor (4) for clarity.
witnessScaleFactor' :: Int
witnessScaleFactor' = witnessScaleFactor

--------------------------------------------------------------------------------
-- Errors
--------------------------------------------------------------------------------

-- | Reasons a transaction can fail standardness. The string in
-- 'StandardError' mirrors the @reason@ value Bitcoin Core's IsStandardTx
-- writes through its out-parameter, for parity in RPC error messages.
data StandardError
  = StdBadVersion !Int32
    -- ^ "version" — version outside [1,3]
  | StdTxWeight !Int !Int
    -- ^ "tx-size" — weight > MAX_STANDARD_TX_WEIGHT (actual, max)
  | StdNonWitnessTooSmall !Int
    -- ^ "tx-size-small" — non-witness serialisation < 65 bytes (BIP-141)
  | StdScriptSigSize !Int !Int
    -- ^ "scriptsig-size" — input scriptSig > 1650 bytes (idx, size)
  | StdScriptSigNotPushOnly !Int
    -- ^ "scriptsig-not-pushonly" — scriptSig contains a non-push opcode
  | StdScriptPubKey !Int
    -- ^ "scriptpubkey" — output script not a known standard pattern
  | StdDataCarrierTooLarge !Int !Int
    -- ^ "datacarrier" — OP_RETURN data > MAX_OP_RETURN_RELAY (size, max)
  | StdMultipleOpReturns !Int
    -- ^ "multi-op-return" — more than one OP_RETURN output in tx (count)
  | StdBareMultisig
    -- ^ "bare-multisig" — bare multisig output (without -permitbaremultisig)
  | StdDust !Int
    -- ^ "dust" — too many dust outputs (count)
  deriving (Show, Eq)

-- | Render a 'StandardError' to the same short tag Core writes to its
-- @reason@ out-parameter; useful for matching test vectors / RPC error
-- text.
stdReasonTag :: StandardError -> String
stdReasonTag = \case
  StdBadVersion {}            -> "version"
  StdTxWeight {}              -> "tx-size"
  StdNonWitnessTooSmall {}    -> "tx-size-small"
  StdScriptSigSize {}         -> "scriptsig-size"
  StdScriptSigNotPushOnly {}  -> "scriptsig-not-pushonly"
  StdScriptPubKey {}          -> "scriptpubkey"
  StdDataCarrierTooLarge {}   -> "datacarrier"
  StdMultipleOpReturns {}     -> "multi-op-return"
  StdBareMultisig             -> "bare-multisig"
  StdDust {}                  -> "dust"

--------------------------------------------------------------------------------
-- Tx weight
--------------------------------------------------------------------------------

-- | Compute BIP-141 transaction weight: @baseSize * 3 + totalSize@.
-- Equivalent to Core's @GetTransactionWeight@.
txWeight :: Tx -> Int
txWeight tx =
  let !base  = txBaseSize tx
      !total = txTotalSize tx
  in base * (witnessScaleFactor - 1) + total

--------------------------------------------------------------------------------
-- Dust
--------------------------------------------------------------------------------

-- | Compute the dust threshold for a given output, mirroring
-- @GetDustThreshold@ in bitcoin-core/src/policy/policy.cpp.
--
--   * Unspendable outputs (OP_RETURN data carriers) have threshold 0.
--   * Witness programs (segwit) get the 75%-discounted spend cost
--     (32 + 4 + 1 + (107 / 4) + 4) = 67.75 bytes added to output size.
--   * Other outputs get the 148-byte legacy spend cost added.
--   * Threshold = (size * dustRelayFee) / 1000  (sat/kvB units).
dustThreshold :: TxOut -> Word64 -> Word64
dustThreshold txOut dustFeeSatPerKvB
  | isUnspendableScriptPubKey (txOutScript txOut) = 0
  | otherwise =
      let !outSerSize = fromIntegral $ BS.length (encode txOut) :: Int
          !witExtra   = case isWitnessProgramScript (txOutScript txOut) of
            -- segwit spend: ~67 bytes (with witness discount applied)
            Just _  -> 32 + 4 + 1 + (107 `div` witnessScaleFactor) + 4
            -- legacy spend: full 148 bytes
            Nothing -> 32 + 4 + 1 + 107 + 4
          !sz = outSerSize + witExtra
      in (fromIntegral sz * dustFeeSatPerKvB) `div` 1000

-- | An output is "dust" if its value is below the spend-cost threshold.
isDust :: TxOut -> Word64 -> Bool
isDust txOut dustFee = txOutValue txOut < dustThreshold txOut dustFee

-- | Detect unspendable scriptPubKeys (OP_RETURN-prefixed). Core:
-- @CScript::IsUnspendable@.
isUnspendableScriptPubKey :: ByteString -> Bool
isUnspendableScriptPubKey bs
  | BS.null bs = True
  | BS.head bs == 0x6a = True  -- OP_RETURN
  | otherwise = False

-- | Identify a witness program (BIP-141): version byte + direct
-- 2-40-byte push. Returns the witness version on success.
isWitnessProgramScript :: ByteString -> Maybe Int
isWitnessProgramScript bs = case decodeScript bs of
  Right script -> case classifyOutput script of
    P2WPKH _ -> Just 0
    P2WSH  _ -> Just 0
    P2TR   _ -> Just 1
    P2A      -> Just 1
    _        -> Nothing
  Left _ -> Nothing

--------------------------------------------------------------------------------
-- ScriptPubKey standardness
--------------------------------------------------------------------------------

-- | Is this scriptPubKey a known-standard pattern?
-- Returns Just the classified ScriptType when standard.
isStandardScriptPubKey :: ByteString -> Maybe ScriptType
isStandardScriptPubKey bs = case decodeScript bs of
  Left _ -> Nothing
  Right script -> case classifyOutput script of
    NonStandard       -> Nothing
    P2MultiSig m keys ->
      let n = length keys
      in if n >= 1 && n <= 3 && m >= 1 && m <= n
            then Just (P2MultiSig m keys)
            else Nothing
    other -> Just other

--------------------------------------------------------------------------------
-- Top-level standardness predicate
--------------------------------------------------------------------------------

-- | Boolean version of the standardness check (drops the error reason).
isStandardTx :: Tx -> Bool
isStandardTx tx = case checkStandardTx tx of
  Right () -> True
  Left _   -> False

-- | Check whether a transaction is standard for relay/mempool. Returns
-- the first failure as a 'StandardError', or '()' on success.
--
-- Mirrors Bitcoin Core's @IsStandardTx@ in src/policy/policy.cpp:100,
-- with the following defaults:
--
--   * permit_bare_multisig = True (Core default DEFAULT_PERMIT_BAREMULTISIG)
--   * max_datacarrier_bytes = MAX_OP_RETURN_RELAY
--   * dust_relay_fee = DUST_RELAY_TX_FEE (3000 sat/kvB)
--
-- The version, tx-weight, scriptSig-pushonly, scriptPubKey-standard,
-- OP_RETURN-budget, multiple-OP_RETURN, and dust checks are all
-- enforced. Coinbase transactions are assumed never to enter this path
-- (Core only calls IsStandardTx on non-coinbase candidates).
checkStandardTx :: Tx -> Either StandardError ()
checkStandardTx tx = do
  -- 1. version range
  let v = txVersion tx
  if v < txMinStandardVersion || v > txMaxStandardVersion
    then Left (StdBadVersion v)
    else Right ()

  -- 2. weight cap
  let w = txWeight tx
  if w > maxStandardTxWeight
    then Left (StdTxWeight w maxStandardTxWeight)
    else Right ()

  -- 3. minimum non-witness serialised size (BIP-141 anti-malleability;
  --    matches Core's MIN_STANDARD_TX_NONWITNESS_SIZE check in
  --    AcceptToMemoryPool).
  let !nws = txBaseSize tx
  if nws < minStandardTxNonWitnessSize
    then Left (StdNonWitnessTooSmall nws)
    else Right ()

  -- 4. each input's scriptSig must be small and push-only
  let inputs = zip [0..] (txInputs tx)
  mapM_ checkInput inputs

  -- 5. each output's scriptPubKey must be standard; bound OP_RETURN data;
  --    count OP_RETURNs.
  let outputs = zip [0..] (txOutputs tx)
  carriers <- countOpReturnsAndCheck outputs

  if carriers > 1
    then Left (StdMultipleOpReturns carriers)
    else Right ()

  -- 6. dust budget
  let dustCount = length [ () | o <- txOutputs tx, isDust o dustRelayTxFee ]
  if dustCount > maxDustOutputsPerTx
    then Left (StdDust dustCount)
    else Right ()

  return ()
  where
    checkInput :: (Int, TxIn) -> Either StandardError ()
    checkInput (idx, txin) = do
      let !sz = BS.length (txInScript txin)
      if sz > maxStandardScriptSigSize
        then Left (StdScriptSigSize idx sz)
        else Right ()
      case decodeScript (txInScript txin) of
        Left _ -> Left (StdScriptSigNotPushOnly idx)
        Right script ->
          if isPushOnly script
            then Right ()
            else Left (StdScriptSigNotPushOnly idx)

    -- Walk outputs, classify each scriptPubKey, enforce data-carrier
    -- budget on OP_RETURN entries, and count them so we can reject
    -- multi-OP_RETURN transactions per Core's relay policy.
    countOpReturnsAndCheck :: [(Int, TxOut)] -> Either StandardError Int
    countOpReturnsAndCheck = go 0
      where
        go !n [] = Right n
        go !n ((idx, out):rest) =
          case isStandardScriptPubKey (txOutScript out) of
            Nothing -> Left (StdScriptPubKey idx)
            Just t -> case t of
              OpReturn _ -> do
                let !sz = BS.length (txOutScript out)
                if sz > maxOpReturnRelay
                  then Left (StdDataCarrierTooLarge sz maxOpReturnRelay)
                  else go (n + 1) rest
              _ -> go n rest

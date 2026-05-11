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
  , checkStandardTxWith
  , StandardError(..)
  , WitnessStandardError(..)
  , checkWitnessStandard
    -- * Constants (Bitcoin Core defaults)
  , maxStandardTxWeight
  , maxStandardTxSigOpsCost
  , txMinStandardVersion
  , txMaxStandardVersion
  , maxStandardScriptSigSize
  , maxOpReturnRelay
  , dustRelayTxFee
  , maxDustOutputsPerTx
  , maxStandardP2WSHScriptSize
  , maxStandardP2WSHStackItems
  , maxStandardP2WSHStackItemSize
  , maxStandardTapscriptStackItemSize
  , annexTag
  , minStandardTxNonWitnessSize
  , witnessScaleFactor'
  , defaultBytesPerSigop
    -- * Weight / vsize helpers
  , getSigOpsAdjustedWeight
  , getVirtualTransactionSize
  , getVirtualTransactionSizeWithSigops
    -- * Sub-checks
  , isStandardScriptPubKey
  , dustThreshold
  , isDust
  , txWeight
  ) where

import Control.Monad (when)
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Int (Int32)
import Data.Word (Word8, Word64)
import Data.Serialize (encode)

import Haskoin.Types
  ( Tx(..)
  , TxIn(..)
  , TxOut(..)
  , Hash160(..)
  , Hash256(..)
  )
import Haskoin.Script
  ( Script(..)
  , ScriptOp(..)
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

-- | Maximum sigop cost for a single transaction to be accepted into the mempool.
-- @MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST / 5 = 16_000@.
-- Reference: bitcoin-core/src/policy/policy.h:44.
-- Bitcoin Core validation.cpp:941-943: "bad-txns-too-many-sigops".
-- Legacy and P2SH sigops count as WITNESS_SCALE_FACTOR (4) each;
-- witness sigops count as 1 each.
maxStandardTxSigOpsCost :: Int
maxStandardTxSigOpsCost = 16_000

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

-- | Maximum number of witness stack items in a standard P2WSH script.
-- Core: @MAX_STANDARD_P2WSH_STACK_ITEMS = 100@.
maxStandardP2WSHStackItems :: Int
maxStandardP2WSHStackItems = 100

-- | Maximum size in bytes of each witness stack item in a standard P2WSH script.
-- Core: @MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80@.
maxStandardP2WSHStackItemSize :: Int
maxStandardP2WSHStackItemSize = 80

-- | Maximum size in bytes of each witness stack item in a standard tapscript spend.
-- Core: @MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80@.
maxStandardTapscriptStackItemSize :: Int
maxStandardTapscriptStackItemSize = 80

-- | BIP-341 annex tag: first byte of the annex element.
-- Core: @ANNEX_TAG = 0x50@.
annexTag :: Word8
annexTag = 0x50

-- | Smallest non-witness serialised tx that we'll relay.
-- Core: @MIN_STANDARD_TX_NONWITNESS_SIZE = 65@.
minStandardTxNonWitnessSize :: Int
minStandardTxNonWitnessSize = 65

-- | Local copy of the consensus witness scale factor (4) for clarity.
witnessScaleFactor' :: Int
witnessScaleFactor' = witnessScaleFactor

-- | Default bytes-per-sigop for virtual-size sigop adjustment.
-- @DEFAULT_BYTES_PER_SIGOP = 20@.
-- Reference: bitcoin-core/src/policy/policy.h:50.
-- Used in 'getSigOpsAdjustedWeight' to compute the sigop-inflated
-- virtual size that Core uses for mempool fee-rate calculations.
defaultBytesPerSigop :: Int
defaultBytesPerSigop = 20

--------------------------------------------------------------------------------
-- Weight / vsize helpers
--------------------------------------------------------------------------------

-- | Sigop-adjusted weight.  If the transaction's sigop cost, when
-- scaled by @bytesPerSigop@, exceeds the raw BIP-141 weight, the
-- effective weight is inflated to that sigop cost × bytesPerSigop.
--
-- @GetSigOpsAdjustedWeight(weight, sigopCost, bytesPerSigop)@
-- = @max weight (sigopCost * bytesPerSigop)@.
--
-- Reference: bitcoin-core/src/policy/policy.cpp:390-393.
getSigOpsAdjustedWeight :: Int  -- ^ Raw BIP-141 transaction weight
                        -> Int  -- ^ Transaction sigop cost (scaled)
                        -> Int  -- ^ Bytes per sigop (default: 20)
                        -> Int
getSigOpsAdjustedWeight weight sigopCost bytesPerSigop =
  max weight (sigopCost * bytesPerSigop)

-- | Virtual transaction size (weight units reinterpreted as bytes),
-- with optional sigop-cost adjustment.
--
-- @GetVirtualTransactionSize(weight, sigopCost, bytesPerSigop)@
-- = @ceil(getSigOpsAdjustedWeight(weight, sigopCost, bytesPerSigop) / WITNESS_SCALE_FACTOR)@
-- = @(adjustedWeight + 3) \`div\` 4@.
--
-- Reference: bitcoin-core/src/policy/policy.cpp:395-398.
--
-- Pass @sigopCost=0, bytesPerSigop=0@ (or use 'getVirtualTransactionSize')
-- for the no-adjustment path.
getVirtualTransactionSizeWithSigops :: Int -> Int -> Int -> Int
getVirtualTransactionSizeWithSigops weight sigopCost bytesPerSigop =
  (getSigOpsAdjustedWeight weight sigopCost bytesPerSigop + witnessScaleFactor - 1)
    `div` witnessScaleFactor

-- | Virtual transaction size without sigop adjustment.
--
-- Equivalent to @GetVirtualTransactionSize(weight, 0, 0)@ in Core:
-- @vsize = ceil(weight \/ 4) = (weight + 3) \`div\` 4@.
--
-- Reference: bitcoin-core/src/policy/policy.h:186-188.
getVirtualTransactionSize :: Int -> Int
getVirtualTransactionSize weight =
  (weight + witnessScaleFactor - 1) `div` witnessScaleFactor

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
    -- ^ "datacarrier" — cumulative OP_RETURN bytes exceed MAX_OP_RETURN_RELAY
    --   (cumulative_size, max). Core uses a shared budget across all
    --   OP_RETURN outputs per-tx, not a per-output cap; multiple OP_RETURN
    --   outputs are allowed as long as the total fits.
  | StdBareMultisig
    -- ^ "bare-multisig" — bare multisig output (without -permitbaremultisig)
  | StdDust !Int
    -- ^ "dust" — too many dust outputs (count)
  deriving (Show, Eq)

-- | Reasons a witness fails IsWitnessStandard checks.
-- Mirrors @IsWitnessStandard@ in bitcoin-core/src/policy/policy.cpp:265.
data WitnessStandardError
  = WitnessNonWitnessProgram !Int
    -- ^ Input has witness but spending script is not a witness program.
  | WitnessP2AStuffed !Int
    -- ^ P2A input has witness data (witness stuffing). Core rejects these.
  | WitnessP2WSHScriptTooLarge !Int !Int
    -- ^ P2WSH witness script exceeds MAX_STANDARD_P2WSH_SCRIPT_SIZE.
    --   (input_idx, script_size)
  | WitnessP2WSHTooManyStackItems !Int !Int
    -- ^ P2WSH witness has more than MAX_STANDARD_P2WSH_STACK_ITEMS items
    --   (not counting the script itself). (input_idx, count)
  | WitnessP2WSHStackItemTooLarge !Int !Int
    -- ^ A P2WSH witness stack item exceeds MAX_STANDARD_P2WSH_STACK_ITEM_SIZE.
    --   (input_idx, item_size)
  | WitnessTaprootAnnex !Int
    -- ^ Taproot spend has an annex (nonstandard, BIP-341 §Annexes).
  | WitnessTaprootScriptStackItemTooLarge !Int !Int
    -- ^ Tapscript (leaf version 0xc0) stack item exceeds
    --   MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE. (input_idx, item_size)
  | WitnessTaprootEmptyStack !Int
    -- ^ Taproot spend has 0 witness items (already invalid by consensus).
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
-- OP_RETURN-budget, bare-multisig, and dust checks are all enforced.
-- Coinbase transactions are assumed never to enter this path
-- (Core only calls IsStandardTx on non-coinbase candidates).
checkStandardTx :: Tx -> Either StandardError ()
checkStandardTx = checkStandardTxWith True

-- | Full-parameter variant of 'checkStandardTx'. Exposed for callers that
-- need non-default policy knobs (e.g. @-permitbaremultisig=0@).
--
--   * @permitBareMultisig@ — when False, bare m-of-n CHECKMULTISIG outputs
--     are rejected with "bare-multisig".  Core default: True.
checkStandardTxWith :: Bool -> Tx -> Either StandardError ()
checkStandardTxWith permitBareMultisig tx = do
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

  -- 5. each output's scriptPubKey must be standard; enforce the cumulative
  --    OP_RETURN data-carrier budget (Bitcoin Core IsStandardTx).
  --
  --    Core policy (policy.cpp:137-155): initialise datacarrier_bytes_left =
  --    MAX_OP_RETURN_RELAY; for each NULL_DATA output deduct its total script
  --    size from the budget and reject ("datacarrier") if it would go
  --    negative. Multiple OP_RETURN outputs are explicitly allowed as long as
  --    the sum of their script sizes fits in the budget. There is NO
  --    "multi-op-return" reject in Bitcoin Core.
  let outputs = zip [0..] (txOutputs tx)
  checkOutputsWithBudget outputs

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

    -- Walk outputs, classify each scriptPubKey, and enforce the cumulative
    -- OP_RETURN data-carrier budget, and bare-multisig policy.
    -- Mirrors Bitcoin Core policy.cpp:137-155:
    --   unsigned int datacarrier_bytes_left = max_datacarrier_bytes.value_or(0);
    --   for each NULL_DATA output:
    --     if (size > datacarrier_bytes_left) → reject "datacarrier"
    --     datacarrier_bytes_left -= size;
    --   for MULTISIG output (when !permit_bare_multisig):
    --     → reject "bare-multisig"
    -- Multiple OP_RETURN outputs are allowed; only the cumulative byte sum is
    -- capped. Non-OP_RETURN non-standard outputs are rejected "scriptpubkey".
    checkOutputsWithBudget :: [(Int, TxOut)] -> Either StandardError ()
    checkOutputsWithBudget = go maxOpReturnRelay
      where
        go !_budget [] = Right ()
        go !budget ((idx, out):rest) =
          case isStandardScriptPubKey (txOutScript out) of
            Nothing -> Left (StdScriptPubKey idx)
            Just t -> case t of
              OpReturn _ -> do
                let !sz = BS.length (txOutScript out)
                if sz > budget
                  then Left (StdDataCarrierTooLarge (maxOpReturnRelay - budget + sz) maxOpReturnRelay)
                  else go (budget - sz) rest
              -- Bare m-of-n multisig: reject unless -permitbaremultisig (Core default: True).
              -- Core: policy.cpp:152-155:
              --   } else if ((whichType == TxoutType::MULTISIG) && (!permit_bare_multisig)) {
              --       reason = "bare-multisig"; return false; }
              P2MultiSig _ _ ->
                if permitBareMultisig
                  then go budget rest
                  else Left StdBareMultisig
              _ -> go budget rest

--------------------------------------------------------------------------------
-- IsWitnessStandard
--------------------------------------------------------------------------------

-- | Check witness standardness for a transaction, given prevout scripts.
--
-- Mirrors @IsWitnessStandard@ in bitcoin-core/src/policy/policy.cpp:265.
-- Must be called after 'checkStandardTx' (which guarantees scriptSigs are
-- push-only, making P2SH redeemScript extraction here safe).
--
-- Parameters:
--   * @tx@ — the transaction to check
--   * @prevScripts@ — one prevout scriptPubKey per input (same order as vin)
--   * @witness@ — one witness stack per input (same order as vin); use
--                 @txWitness tx@ from 'Haskoin.Types.Tx'
--
-- Returns 'Right ()' if the witness is standard, or 'Left' the first
-- 'WitnessStandardError' found.
checkWitnessStandard
  :: Tx
  -> [ByteString]      -- ^ prevout scriptPubKey per input (vin order)
  -> [[ByteString]]    -- ^ witness stack per input (vin order)
  -> Either WitnessStandardError ()
checkWitnessStandard tx prevScripts witness =
  mapM_ checkOne (zip3 [0..] prevScripts witness)
  where
    checkOne :: (Int, ByteString, [ByteString]) -> Either WitnessStandardError ()
    checkOne (idx, prevSpk, witStack) = do
      -- Inputs with an empty witness are fine; nothing to check.
      if null witStack
        then return ()
        else do
          -- Determine the effective spending script. For P2SH we unwrap
          -- the redeemScript from the scriptSig stack, matching Core's
          -- EvalScript call in IsWitnessStandard.
          let (effScript, isP2SH) = resolveEffectiveScript prevSpk (txInputs tx !! idx)

          -- Resolve the witness program from the effective script.
          case resolveWitnessProgram effScript of
            Nothing ->
              -- Non-witness program with witness data: reject.
              -- Core: "Non-witness program must not be associated with any witness"
              Left (WitnessNonWitnessProgram idx)
            Just (wver, wprog) ->
              checkWitnessProgram idx wver wprog witStack isP2SH

    -- Extract (effectiveScript, isP2SH). For a P2SH prevout we take the
    -- last push of scriptSig as the redeemScript (Core does the same with
    -- EvalScript on SCRIPT_VERIFY_NONE). On EvalScript failure or an
    -- empty stack we fall through to the raw prevout (which will then
    -- fail the witness-program check, matching Core's "return false").
    resolveEffectiveScript :: ByteString -> TxIn -> (ByteString, Bool)
    resolveEffectiveScript prevSpk txin =
      case decodeScript prevSpk of
        Right sc | isP2SHScript sc ->
          -- Try to extract the redeemScript from scriptSig pushes.
          case extractLastPush (txInScript txin) of
            Just rs -> (rs, True)
            Nothing -> (prevSpk, False)
        _ -> (prevSpk, False)

    -- Check if a decoded Script is P2SH.
    isP2SHScript :: Script -> Bool
    isP2SHScript sc = case classifyOutput sc of
      P2SH _ -> True
      _       -> False

    -- Extract the last push from a scriptSig (the redeemScript in P2SH).
    -- Returns Nothing when the scriptSig is empty or malformed.
    extractLastPush :: ByteString -> Maybe ByteString
    extractLastPush scriptSigBytes =
      case decodeScript scriptSigBytes of
        Left _  -> Nothing
        Right sc -> extractLastPushFromScript sc

    extractLastPushFromScript :: Script -> Maybe ByteString
    extractLastPushFromScript (Script ops) =
      case mapM extractPushData ops of
        Nothing   -> Nothing
        Just []   -> Nothing
        Just pushes -> Just (last pushes)

    extractPushData :: ScriptOp -> Maybe ByteString
    extractPushData (OP_PUSHDATA d _) = Just d
    extractPushData OP_0              = Just BS.empty
    extractPushData _                 = Nothing

    -- Identify a witness program: returns (version, program) on success.
    -- Mirrors CScript::IsWitnessProgram in Core.
    resolveWitnessProgram :: ByteString -> Maybe (Int, ByteString)
    resolveWitnessProgram spk =
      case decodeScript spk of
        Left _ -> Nothing
        Right sc -> case classifyOutput sc of
          P2WPKH (Hash160 h) -> Just (0, h)
          P2WSH  (Hash256 h) -> Just (0, h)
          P2TR   (Hash256 h) -> Just (1, h)
          P2A               -> Just (1, p2aProgram)
          _                  -> Nothing

    -- The P2A witness program bytes (OP_1 <0x4e73>).
    p2aProgram :: ByteString
    p2aProgram = BS.pack [0x4e, 0x73]

    -- Main per-input witness check.
    checkWitnessProgram
      :: Int -> Int -> ByteString -> [ByteString] -> Bool
      -> Either WitnessStandardError ()
    checkWitnessProgram idx wver wprog witStack _isP2SH = do
      -- P2A: witness stuffing is nonstandard.
      -- Core: if (prevScript.IsPayToAnchor()) return false;
      if wver == 1 && wprog == BS.pack [0x4e, 0x73]
        then Left (WitnessP2AStuffed idx)
        else return ()

      case (wver, BS.length wprog) of
        -- P2WSH (version 0, 32-byte program)
        (0, 32) -> checkP2WSHWitness idx witStack
        -- P2TR (version 1, 32-byte program), not P2SH-wrapped
        (1, 32) -> checkTaprootWitness idx witStack
        -- Everything else (P2WPKH, unknown versions): no stack-level limits.
        _       -> return ()

    -- P2WSH witness checks.
    -- Core policy.cpp:309-319:
    --   witnessScript size ≤ MAX_STANDARD_P2WSH_SCRIPT_SIZE (3600)
    --   stack items (excluding script) ≤ MAX_STANDARD_P2WSH_STACK_ITEMS (100)
    --   each stack item ≤ MAX_STANDARD_P2WSH_STACK_ITEM_SIZE (80) bytes
    checkP2WSHWitness :: Int -> [ByteString] -> Either WitnessStandardError ()
    checkP2WSHWitness idx witStack = do
      -- The witness script is the last element.
      let witnessScript = last witStack
          stackItems    = init witStack   -- all but the script
      -- Script size limit.
      when (BS.length witnessScript > maxStandardP2WSHScriptSize) $
        Left (WitnessP2WSHScriptTooLarge idx (BS.length witnessScript))
      -- Stack item count limit.
      when (length stackItems > maxStandardP2WSHStackItems) $
        Left (WitnessP2WSHTooManyStackItems idx (length stackItems))
      -- Per-item size limit.
      mapM_ (\item ->
        when (BS.length item > maxStandardP2WSHStackItemSize) $
          Left (WitnessP2WSHStackItemTooLarge idx (BS.length item))
        ) stackItems

    -- Taproot witness checks.
    -- Core policy.cpp:324-349.
    checkTaprootWitness :: Int -> [ByteString] -> Either WitnessStandardError ()
    checkTaprootWitness idx witStack = do
      let stack = witStack
      -- Strip optional annex (last element whose first byte == ANNEX_TAG).
      let (strippedStack, hasAnnex) = stripAnnex stack
      -- Annex is nonstandard.
      when hasAnnex $
        Left (WitnessTaprootAnnex idx)
      case length strippedStack of
        0 ->
          -- 0 stack elements: invalid by consensus (policy can flag it).
          Left (WitnessTaprootEmptyStack idx)
        1 ->
          -- Key-path spend: no additional policy limits.
          return ()
        _ -> do
          -- Script-path spend: check tapscript stack items.
          -- Core: control_block = pop, script = pop, remaining = stack.
          -- strippedStack is [item0 .. itemN-2, script, control_block].
          let controlBlock   = last strippedStack
              withoutControl = init strippedStack
              _script        = last withoutControl
              scriptItems    = init withoutControl
          -- Empty control block is invalid.
          when (BS.null controlBlock) $
            Left (WitnessTaprootEmptyStack idx)
          -- Leaf version 0xc0 = Tapscript (BIP-342).
          -- TAPROOT_LEAF_MASK = 0xfe, TAPROOT_LEAF_TAPSCRIPT = 0xc0.
          let leafVersion = BS.head controlBlock .&. 0xfe
          when (leafVersion == 0xc0) $
            mapM_ (\item ->
              when (BS.length item > maxStandardTapscriptStackItemSize) $
                Left (WitnessTaprootScriptStackItemTooLarge idx (BS.length item))
              ) scriptItems

    -- If the last element is an annex (non-empty, first byte == annexTag),
    -- return (stack without annex, True), else (stack, False).
    stripAnnex :: [ByteString] -> ([ByteString], Bool)
    stripAnnex [] = ([], False)
    stripAnnex stk =
      let top = last stk
      in if not (BS.null top) && BS.head top == annexTag && length stk >= 2
           then (init stk, True)
           else (stk, False)

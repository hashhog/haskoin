{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NumericUnderscores #-}

-- | W175 fundrawtransaction (Bitcoin Core v31.99) — focused functional test.
--
-- Reference:
--   bitcoin-core/src/wallet/rpc/spend.cpp  fundrawtransaction (706) / FundTransaction (470)
--
-- fundrawtransaction is the raw-tx sibling of walletcreatefundedpsbt: both run
-- the SAME coin-selection engine ('selectCoinsWithHeight', Wallet.hs:2430).
-- This spec exercises 'fundRawTx' (Rpc.hs) — the server-independent engine the
-- 'handleFundRawTransaction' RPC wraps — over a funded wallet fixture built the
-- way the W113 coin-selection spec does (mkWallet + addUtxo).
--
-- It proves the default no-options path:
--   1. start from a raw tx with ONE output (P2WPKH) and NO inputs,
--   2. fund it,
--   3. assert inputs were added (vin non-empty),
--   4. a change output exists (changepos /= -1) and is consistent with the hex,
--   5. fee > 0,
--   6. the returned hex decodes to a tx whose selected input value covers
--      outputs + fee (sum(inputs) == sum(outputs) + fee).
module W175FundRawTransactionSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8, Word64)
import qualified Data.Serialize as S

import Haskoin.Wallet
  ( Wallet, WalletConfig(..), loadWallet, generateMnemonic, addWalletUTXO )
import Haskoin.Consensus (regtest)
import Haskoin.Types
  ( TxId(..), Hash256(..), OutPoint(..)
  , TxIn(..), TxOut(..), Tx(..) )
import Haskoin.Rpc (fundRawTx, FundOptions(..), defaultFundOptions)

--------------------------------------------------------------------------------
-- Fixtures (mirror W113CoinSelectionSpec mkWallet / addUtxo)
--------------------------------------------------------------------------------

-- | A minimal regtest wallet.
mkWallet :: IO Wallet
mkWallet = do
  m <- generateMnemonic 256
  loadWallet (WalletConfig regtest 20 "") m

-- | P2WPKH scriptPubKey for a 20-byte pubkey hash: OP_0 <20-byte push>.
--   This is the form 'fundRawTx' recovers an address from, so the funded
--   outputs round-trip through the coin selector.
p2wpkh :: Word8 -> ByteString
p2wpkh b = BS.concat [BS.pack [0x00, 0x14], BS.replicate 20 b]

-- | Add a P2WPKH UTXO of @val@ satoshis to the wallet.
addUtxo :: Wallet -> Int -> Word64 -> IO ()
addUtxo wallet seed val = do
  let op  = OutPoint (TxId (Hash256 (BS.replicate 32 (fromIntegral seed)))) 0
      txo = TxOut val (p2wpkh (fromIntegral seed))
  addWalletUTXO wallet op txo 6

-- | Build the unfunded raw tx: 1 P2WPKH output, 0 inputs.
mkUnfundedTx :: Word64 -> Tx
mkUnfundedTx payAmt = Tx
  { txVersion  = 2
  , txInputs   = []
  , txOutputs  = [ TxOut payAmt (p2wpkh 0xcc) ]
  , txWitness  = []
  , txLockTime = 0
  }

sumIns :: [TxOut] -> Word64
sumIns = sum . map txOutValue

--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W175 fundrawtransaction (Core v31.99 parity)" $ do

  it "default path: adds inputs + change, real fee, hex decodes, inputs cover outputs+fee" $ do
    wallet <- mkWallet
    -- Fund the wallet with a single 1 BTC UTXO; pay 0.5 BTC.
    addUtxo wallet 1 100_000_000
    let payAmt = 50_000_000 :: Word64
        baseTx = mkUnfundedTx payAmt
    res <- fundRawTx wallet 200 defaultFundOptions baseTx
    case res of
      Left (code, msg) ->
        expectationFailure $ "fundRawTx failed: code=" ++ show code ++ " msg=" ++ show msg
      Right (fundedTx, feeSat, changePos) -> do
        -- (3) inputs were added (vin non-empty).
        txInputs fundedTx `shouldNotSatisfy` null
        -- (5) fee > 0.
        feeSat `shouldSatisfy` (> 0)
        -- (4) a change output exists (no exact match for a 1-BTC coin).
        changePos `shouldNotBe` (-1)
        let outs = txOutputs fundedTx
        -- changepos in range and points at a real output.
        changePos `shouldSatisfy` (\p -> p >= 0 && p < length outs)
        -- The original payment output is preserved with its amount intact.
        map txOutValue outs `shouldContain` [payAmt]
        -- (6) hex round-trips: serialize then decode back to the same tx.
        let hexBytes = S.encode fundedTx
        case S.decode hexBytes :: Either String Tx of
          Left e  -> expectationFailure $ "funded tx hex did not decode: " ++ e
          Right decoded -> do
            txInputs  decoded `shouldBe` txInputs  fundedTx
            txOutputs decoded `shouldBe` txOutputs fundedTx
            -- The selected input value covers ALL outputs + the fee exactly.
            -- The wallet held a single 1-BTC coin, so the only selected input
            -- has that value; Core's funding identity is then:
            --   sum(selected inputs) == sum(all outputs) + fee.
            let inputValue = 100_000_000 :: Word64          -- the lone funded coin
                totalOut   = sumIns (txOutputs decoded)     -- payment + change
            (totalOut + feeSat) `shouldBe` inputValue
            -- Equivalently, change = inputs - payment - fee, and it lands at
            -- exactly the reported changepos.
            let changeAmount = inputValue - payAmt - feeSat
            txOutValue (txOutputs decoded !! changePos) `shouldBe` changeAmount
            -- changepos points at the change output, not the payment output.
            txOutValue (txOutputs decoded !! changePos) `shouldNotBe` payAmt

  it "insufficient funds: returns the wallet insufficient-funds error (-6)" $ do
    wallet <- mkWallet
    addUtxo wallet 1 10_000               -- 0.0001 BTC available
    let baseTx = mkUnfundedTx 50_000_000  -- want 0.5 BTC
    res <- fundRawTx wallet 200 defaultFundOptions baseTx
    case res of
      Left (code, _msg) -> code `shouldBe` (-6)  -- RPC_WALLET_INSUFFICIENT_FUNDS
      Right _ -> expectationFailure "expected insufficient-funds error, got a funded tx"

  it "existing inputs are preserved and appear before the selected inputs" $ do
    wallet <- mkWallet
    addUtxo wallet 1 100_000_000
    let preIn = TxIn (OutPoint (TxId (Hash256 (BS.replicate 32 0xee))) 7) BS.empty 0xffffffff
        baseTx = (mkUnfundedTx 50_000_000) { txInputs = [preIn] }
    res <- fundRawTx wallet 200 defaultFundOptions baseTx
    case res of
      Left (code, msg) ->
        expectationFailure $ "fundRawTx failed: code=" ++ show code ++ " msg=" ++ show msg
      Right (fundedTx, _fee, _cp) -> do
        -- The caller-supplied input is kept and stays first.
        head (txInputs fundedTx) `shouldBe` preIn
        -- At least one input was added on top of it.
        length (txInputs fundedTx) `shouldSatisfy` (> 1)

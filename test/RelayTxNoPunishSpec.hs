{-# LANGUAGE OverloadedStrings #-}

-- | A rejected relayed transaction never charges the relaying peer.
--
-- Current Bitcoin Core PeerManagerImpl::ProcessInvalidTx
-- (net_processing.cpp:3119) has no Misbehaving call for any
-- TxValidationResult.  haskoin's P2P tx handler (app/Main.hs) routes its
-- only tx-punishment decision through 'punishRelayedTxReject'.
--
-- Pre-fix the handler punished (+10) whenever the rendered error contained
-- "consensus" / "invalid" / "bad-", which caught policy-only rejects:
-- bad-witness-nonstandard (IsWitnessStandard) and bad-txns-too-many-sigops
-- (MAX_STANDARD_TX_SIGOPS_COST) — honest peers relaying consensus-valid,
-- non-standard transactions were walked towards a ban.
module RelayTxNoPunishSpec (spec) where

import Test.Hspec
import qualified Data.ByteString as BS

import Haskoin.Types
import Haskoin.Mempool

spec :: Spec
spec = describe "relayed tx rejection never punishes the peer (Core ProcessInvalidTx)" $ do
  let tid = TxId (Hash256 (BS.replicate 32 0x11))
  it "policy-only: bad-witness-nonstandard is not punished" $
    punishRelayedTxReject (ErrNonStandard "bad-witness-nonstandard") `shouldBe` False
  it "policy-only: bad-txns-too-many-sigops is not punished" $
    punishRelayedTxReject (ErrNonStandard "bad-txns-too-many-sigops") `shouldBe` False
  it "policy-only: non-mandatory script failure is not punished" $
    punishRelayedTxReject (ErrScriptVerificationFailed "non-mandatory-script-verify-flag (invalid signature)")
      `shouldBe` False
  it "consensus rejects are not punished either (current Core, not <= v27)" $ do
    punishRelayedTxReject (ErrValidationFailed "bad-txns-vout-negative") `shouldBe` False
    punishRelayedTxReject (ErrSpendsConflictingTx tid) `shouldBe` False
    punishRelayedTxReject ErrCoinbaseNotAllowed `shouldBe` False
  it "soft rejects stay unpunished (control)" $ do
    punishRelayedTxReject ErrInsufficientFee `shouldBe` False
    punishRelayedTxReject ErrMempoolFull `shouldBe` False
    punishRelayedTxReject (ErrInputSpentInMempool tid) `shouldBe` False

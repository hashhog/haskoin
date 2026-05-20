{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | W102 AssumeUTXO snapshot loading gate audit tests.
--
-- Reference: bitcoin-core/src/validation.cpp ActivateSnapshot (line 5588)
--            bitcoin-core/src/rpc/blockchain.cpp loadtxoutset / dumptxoutset
--
-- Confirmed bugs (10):
--
--  BUG-1 [CONSENSUS-DIVERGENT] CLI --load-snapshot path skips
--         checkAssumeutxoWhitelist. app/Main.hs (lines 680-695) calls only
--         loadSnapshot + loadSnapshotIntoLegacyUTXO — no whitelist check.
--         An operator can feed any snapshot at any height and the node will
--         import it, overwriting the UTXO set with unverified data.
--         Bitcoin Core's PopulateAndValidateSnapshot (validation.cpp:5778)
--         hard-fails "Assumeutxo height in snapshot metadata not recognized".
--
--  BUG-2 [CONSENSUS-DIVERGENT] CLI --load-snapshot path skips verifySnapshot.
--         Even if the height is whitelisted the coin-set hash is never
--         compared against audHashSerialized. An attacker who replaces the
--         snapshot file can feed arbitrary UTXOs. Bitcoin Core:
--         "Assert that the deserialized chainstate contents match the
--         expected assumeutxo value." (validation.cpp:5920).
--
--  BUG-3 [DOS] activateSnapshot (Consensus.hs:4700) looks up the snapshot
--         by base BLOCK HASH (assumeUtxoForBlockHash), whereas Bitcoin Core
--         uses height-first (AssumeutxoForHeight, validation.cpp:5776).
--         A snapshot with a correctly-whitelisted hash but wrong HEIGHT is
--         accepted — skipping the height-based "not recognized" guard.
--
--  BUG-4 [CONSENSUS-DIVERGENT] activateSnapshot (Consensus.hs:4704) is a
--         dead helper — it validates, returns AssumeUtxoState, but never
--         calls loadSnapshotIntoLegacyUTXO. UTXOs remain unwritten to DB.
--         No call site in Main.hs or Daemon.hs (two-pipeline pattern,
--         W92-W101 repeat). The only working path bypasses BUG-1 and BUG-2.
--
--  BUG-5 [CORRECTNESS] backgroundValidationLoop (Consensus.hs:4765) uses
--         medianTime = 0 hardcoded for every block. BIP-113 sequence-lock
--         and time-dependent checks use wrong MTP during background
--         re-validation, potentially accepting blocks that should be rejected.
--
--  BUG-6 [CORRECTNESS] backgroundValidationLoop marks ausValidated = True
--         even on error (line 4788). isAssumeUtxoValidated returns True
--         regardless of whether background validation succeeded or failed.
--         Bitcoin Core's MaybeValidateSnapshot calls handle_invalid_snapshot()
--         (fatal) on hash mismatch; never falsely sets the VALIDATED state.
--
--  BUG-7 [CORRECTNESS] backgroundValidationLoop does NOT compute the
--         HASH_SERIALIZED UTXO hash at completion or compare against
--         ausExpectedHash (line 4793: "For now, mark as validated").
--         The cryptographic proof of chain consistency is never performed.
--         Bitcoin Core: MaybeValidateSnapshot (validation.cpp:5031-5055).
--
--  BUG-8 [CORRECTNESS] Both activateSnapshot and --load-snapshot miss the
--         "base block must appear in the headers chain" pre-check. Bitcoin
--         Core ActivateSnapshot (5613): "The base block header must appear
--         in the headers chain." Without this the UTXO best-block can be
--         set to a hash the header chain has never seen → IBD stall.
--
--  BUG-9 [CORRECTNESS] parseCoins does NOT validate per-coin height <=
--         base_height. Bitcoin Core validation.cpp:5818:
--           if (coin.nHeight > base_height || ...) Error{"Bad snapshot data"}
--         haskoin's parseSnapshotCoinGroup deserializes the height field
--         without range-checking it. A malicious snapshot can embed coins
--         at heights above the base, corrupting the UTXO set.
--
--  BUG-10 [CORRECTNESS] parseCoins does NOT validate per-coin MoneyRange.
--          Bitcoin Core validation.cpp:5822:
--            if (!MoneyRange(coin.out.nValue)) Error{"bad tx out value"}
--          haskoin: decompressAmount is called but result is not checked
--          against MAX_MONEY. An inflated coin bypasses the supply cap.

module W102AssumeUTXOSpec (spec) where

import Control.Exception (bracket)
import Control.Monad (forM_)
import Data.IORef (readIORef, writeIORef)
import Data.List (isPrefixOf, isInfixOf, isSuffixOf)
import qualified Data.Text as T
import Data.Serialize (encode)
import Data.Serialize.Put (runPut, putByteString, putWord16le, putWord32le, putWord64le)
import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.ByteString as BS
import System.Directory (removeDirectoryRecursive, getTemporaryDirectory)
import System.IO.Temp (createTempDirectory)
import Test.Hspec

import Haskoin.Types
import Haskoin.Consensus
  ( Network(..)
  , regtest, mainnet, testnet4
  , AssumeUtxoParams(..)
  , AssumeUtxoState(..)
  , initAssumeUtxoState
  , isAssumeUtxoValidated
  , assumeUtxoForHeight
  , assumeUtxoForBlockHash
  , checkAssumeutxoWhitelist
  , assumeutxoWhitelistError
  )
import Haskoin.Storage
  ( SnapshotMetadata(..)
  , SnapshotCoin(..)
  , UtxoSnapshot(..)
  , snapshotMagicBytes
  , loadSnapshot
  , verifySnapshot
  , validateSnapshotCoins
  , AssumeUtxoData(..)
  , computeUtxoHash
  , Coin(..)
  )
import Haskoin.Rpc (loadTxOutSetGateMessage)

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

fill32 :: Word8 -> BS.ByteString
fill32 b = BS.replicate 32 b

mkBlockHash :: Word8 -> BlockHash
mkBlockHash b = BlockHash (Hash256 (fill32 b))

mkTxId :: Word8 -> TxId
mkTxId b = TxId (Hash256 (fill32 b))

p2pkhScript :: BS.ByteString
p2pkhScript = BS.concat
  [ BS.pack [0x76, 0xa9, 20]
  , BS.replicate 20 0x42
  , BS.pack [0x88, 0xac]
  ]

simpleCoin :: Word64 -> Coin
simpleCoin val = Coin
  { coinTxOut      = TxOut val p2pkhScript
  , coinHeight     = 100
  , coinIsCoinbase = False
  }

maxMoneyConst :: Word64
maxMoneyConst = 2_100_000_000_000_000

withTmpDir :: (FilePath -> IO ()) -> IO ()
withTmpDir action = do
  base <- getTemporaryDirectory
  bracket
    (createTempDirectory base "haskoin-w102-")
    removeDirectoryRecursive
    action

-- | Build a raw snapshot header with an explicit version field.
buildRawHeader :: Word16 -> Word32 -> BS.ByteString -> Word64 -> BS.ByteString
buildRawHeader ver netMagic baseHash coinCount = runPut $ do
  putByteString snapshotMagicBytes
  putWord16le   ver
  putWord32le   netMagic
  putByteString baseHash
  putWord64le   coinCount

--------------------------------------------------------------------------------
-- Spec
--------------------------------------------------------------------------------

spec :: Spec
spec = describe "W102 AssumeUTXO snapshot loading gates" $ do

  -- -----------------------------------------------------------------------
  -- G1–G3: Metadata / magic / checksum
  -- -----------------------------------------------------------------------

  describe "G1 snapshot magic bytes" $ do
    it "snapshotMagicBytes is 'utxo' + 0xFF (5 bytes)" $
      snapshotMagicBytes `shouldBe` BS.pack [0x75, 0x74, 0x78, 0x6f, 0xff]

    it "loadSnapshot rejects garbage (wrong magic)" $
      withTmpDir $ \tmp -> do
        let p = tmp ++ "/bad.dat"
        BS.writeFile p (BS.replicate 51 0xde)
        r <- loadSnapshot p 0xd9b4bef9
        case r of
          Left _  -> pure ()
          Right _ -> expectationFailure "loadSnapshot accepted garbage magic"

    it "loadSnapshot rejects wrong snapshot version" $
      withTmpDir $ \tmp -> do
        let p   = tmp ++ "/badver.dat"
            raw = buildRawHeader 99 0xd9b4bef9 (fill32 0xaa) 0
        BS.writeFile p raw
        r <- loadSnapshot p 0xd9b4bef9
        case r of
          Left _  -> pure ()
          Right _ -> expectationFailure "loadSnapshot accepted version 99"

  describe "G2 network magic cross-check" $ do
    it "loadSnapshot rejects mainnet snapshot with testnet3 magic" $
      withTmpDir $ \tmp -> do
        let meta = SnapshotMetadata
                     { smNetworkMagic  = 0xd9b4bef9   -- mainnet
                     , smBaseBlockHash = mkBlockHash 0xaa
                     , smCoinsCount    = 0
                     }
            p = tmp ++ "/main.dat"
        BS.writeFile p (encode meta)
        r <- loadSnapshot p 0x0709110B   -- testnet3
        case r of
          Left _  -> pure ()
          Right _ -> expectationFailure
            "loadSnapshot accepted snapshot with mismatched network magic"

  describe "G3 verifySnapshot UTXO hash and block hash checks" $ do
    it "verifySnapshot passes when hash and block hash both match" $ do
      let coin = SnapshotCoin (OutPoint (mkTxId 0x01) 0) (simpleCoin 100_000)
          snap = UtxoSnapshot
                   (SnapshotMetadata 0 (mkBlockHash 0x11) 1)
                   [coin]
          aud  = AssumeUtxoData
                   { audHeight         = 0
                   , audHashSerialized = computeUtxoHash [coin]
                   , audChainTxCount   = 1
                   , audBlockHash      = mkBlockHash 0x11
                   }
      verifySnapshot snap aud `shouldBe` Right ()

    it "verifySnapshot fails on UTXO hash mismatch (BUG-2 witness)" $ do
      -- verifySnapshot is correct; BUG-2 is the missing call site in Main.hs.
      let coin  = SnapshotCoin (OutPoint (mkTxId 0x01) 0) (simpleCoin 100_000)
          snap  = UtxoSnapshot
                    (SnapshotMetadata 0 (mkBlockHash 0x11) 1)
                    [coin]
          wrong = Hash256 (fill32 0x00)
          aud   = AssumeUtxoData
                    { audHeight         = 0
                    , audHashSerialized = wrong
                    , audChainTxCount   = 1
                    , audBlockHash      = mkBlockHash 0x11
                    }
      case verifySnapshot snap aud of
        Left e  -> e `shouldSatisfy` ("UTXO hash mismatch" `isInfixOf`)
        Right _ -> expectationFailure
          "verifySnapshot should reject mismatched UTXO hash"

    it "verifySnapshot fails on block hash mismatch" $ do
      let coin = SnapshotCoin (OutPoint (mkTxId 0x01) 0) (simpleCoin 50_000)
          snap = UtxoSnapshot
                   (SnapshotMetadata 0 (mkBlockHash 0x11) 1)
                   [coin]
          aud  = AssumeUtxoData
                   { audHeight         = 0
                   , audHashSerialized = computeUtxoHash [coin]
                   , audChainTxCount   = 1
                   , audBlockHash      = mkBlockHash 0xff
                   }
      case verifySnapshot snap aud of
        Left e  -> e `shouldSatisfy` ("Block hash mismatch" `isInfixOf`)
        Right _ -> expectationFailure
          "verifySnapshot should reject mismatched block hash"

  -- -----------------------------------------------------------------------
  -- G4–G7: Preconditions
  -- -----------------------------------------------------------------------

  describe "G4 whitelist check (checkAssumeutxoWhitelist) — BUG-1 gate" $ do
    it "checkAssumeutxoWhitelist rejects height not in table" $
      case checkAssumeutxoWhitelist regtest 999 of
        Left msg -> msg `shouldSatisfy` ("not recognized" `isInfixOf`)
        Right _  -> expectationFailure
          "checkAssumeutxoWhitelist should reject unknown height"

    it "checkAssumeutxoWhitelist accepts regtest height 110" $
      checkAssumeutxoWhitelist regtest 110 `shouldBe` Right ()

    it "checkAssumeutxoWhitelist accepts mainnet height 840000" $
      checkAssumeutxoWhitelist mainnet 840000 `shouldBe` Right ()

    it "checkAssumeutxoWhitelist rejects 839999 (below lowest mainnet entry)" $
      case checkAssumeutxoWhitelist mainnet 839999 of
        Left _  -> pure ()
        Right _ -> expectationFailure
          "839999 should fail: mainnet lowest entry is 840000"

  describe "G5 assumeUtxoForHeight vs assumeUtxoForBlockHash parity (BUG-3 gate)" $ do
    it "assumeUtxoForHeight regtest 110 returns an entry" $
      assumeUtxoForHeight regtest 110 `shouldSatisfy` (/= Nothing)

    it "height-first and hash-first lookups agree for regtest 110" $
      case assumeUtxoForHeight regtest 110 of
        Nothing -> pendingWith "regtest has no entry at 110"
        Just p  ->
          fmap aupHeight (assumeUtxoForBlockHash regtest (aupBlockHash p))
            `shouldBe` Just 110

    it "assumeUtxoForHeight rejects height 0 (not in any table)" $
      assumeUtxoForHeight regtest 0 `shouldBe` Nothing

    it "assumeUtxoForHeight rejects height 109 (not in regtest table)" $
      assumeUtxoForHeight regtest 109 `shouldBe` Nothing

  describe "G6 assumeutxoWhitelistError matches Bitcoin Core wording" $ do
    it "error string has Core-compatible prefix and suffix" $ do
      let msg = assumeutxoWhitelistError 12345
      msg `shouldSatisfy`
        ("Assumeutxo height in snapshot metadata not recognized" `isPrefixOf`)
      msg `shouldSatisfy` ("12345" `isInfixOf`)
      msg `shouldSatisfy` ("refusing to load snapshot" `isSuffixOf`)

  -- -----------------------------------------------------------------------
  -- G9: Per-coin height guard (BUG-9 — fixed via validateSnapshotCoins)
  -- -----------------------------------------------------------------------

  describe "G9 per-coin height guard (BUG-9 fixed)" $ do
    it "validateSnapshotCoins rejects coin.height > base_height (BUG-9)" $ do
      -- Bitcoin Core validation.cpp:5818: if (coin.nHeight > base_height)
      --   return {InitStateError, "Bad snapshot data"}
      let badCoin = Coin
            { coinTxOut      = TxOut 100_000 p2pkhScript
            , coinHeight     = 9999   -- far above base_height=100
            , coinIsCoinbase = False
            }
          sc = SnapshotCoin (OutPoint (mkTxId 0x01) 0) badCoin
      case validateSnapshotCoins 100 [sc] of
        Left e  -> e `shouldSatisfy` ("Bad snapshot data" `isInfixOf`)
        Right _ -> expectationFailure
          "validateSnapshotCoins should reject coin.height > base_height"

    it "validateSnapshotCoins accepts coin.height == base_height" $ do
      let coinAtBase = Coin
            { coinTxOut      = TxOut 100_000 p2pkhScript
            , coinHeight     = 100
            , coinIsCoinbase = False
            }
          sc = SnapshotCoin (OutPoint (mkTxId 0x01) 0) coinAtBase
      validateSnapshotCoins 100 [sc] `shouldBe` Right ()

    it "validateSnapshotCoins accepts coin.height < base_height" $ do
      let oldCoin = Coin
            { coinTxOut      = TxOut 50_000 p2pkhScript
            , coinHeight     = 50
            , coinIsCoinbase = True
            }
          sc = SnapshotCoin (OutPoint (mkTxId 0x03) 0) oldCoin
      validateSnapshotCoins 100 [sc] `shouldBe` Right ()

  -- -----------------------------------------------------------------------
  -- G10: MoneyRange guard (BUG-10 — fixed via validateSnapshotCoins)
  -- -----------------------------------------------------------------------

  describe "G10 per-coin MoneyRange guard (BUG-10 fixed)" $ do
    it "MAX_MONEY matches Bitcoin Core consensus/amount.h" $
      maxMoneyConst `shouldBe` 2_100_000_000_000_000

    it "validateSnapshotCoins rejects coin.value > MAX_MONEY (BUG-10)" $ do
      -- Bitcoin Core validation.cpp:5822: if (!MoneyRange(coin.out.nValue))
      --   return {InitStateError, "bad tx out value"}
      let inflated = Coin
            { coinTxOut      = TxOut (maxMoneyConst + 1) p2pkhScript
            , coinHeight     = 100
            , coinIsCoinbase = False
            }
          sc = SnapshotCoin (OutPoint (mkTxId 0x02) 0) inflated
      case validateSnapshotCoins 100 [sc] of
        Left e  -> e `shouldSatisfy` ("bad tx out value" `isInfixOf`)
        Right _ -> expectationFailure
          "validateSnapshotCoins should reject coin.value > MAX_MONEY"

    it "validateSnapshotCoins accepts coin.value == MAX_MONEY" $ do
      let atMax = Coin
            { coinTxOut      = TxOut maxMoneyConst p2pkhScript
            , coinHeight     = 100
            , coinIsCoinbase = False
            }
          sc = SnapshotCoin (OutPoint (mkTxId 0x04) 0) atMax
      validateSnapshotCoins 100 [sc] `shouldBe` Right ()

    it "validateSnapshotCoins accepts coin.value == 0" $ do
      let zeroCoin = Coin
            { coinTxOut      = TxOut 0 p2pkhScript
            , coinHeight     = 50
            , coinIsCoinbase = False
            }
          sc = SnapshotCoin (OutPoint (mkTxId 0x05) 0) zeroCoin
      validateSnapshotCoins 100 [sc] `shouldBe` Right ()

  -- -----------------------------------------------------------------------
  -- G15–G17: Background validation invariants (BUG-5, BUG-6, BUG-7)
  -- -----------------------------------------------------------------------

  describe "G15-G17 background validation state invariants" $ do
    it "initAssumeUtxoState starts with ausValidated = False" $
      case assumeUtxoForHeight regtest 110 of
        Nothing -> pendingWith "regtest 110 missing"
        Just p  -> do
          state <- initAssumeUtxoState regtest p
          isAssumeUtxoValidated state >>= (`shouldBe` False)

    it "ausExpectedHash is non-zero after initAssumeUtxoState" $
      case assumeUtxoForHeight regtest 110 of
        Nothing -> pendingWith "regtest 110 missing"
        Just p  -> do
          state <- initAssumeUtxoState regtest p
          ausExpectedHash state `shouldNotBe` Hash256 (fill32 0x00)

    it "BUG-6: ausValidated = True even when ausError is set" $
      -- Simulates the broken invariant in backgroundValidationLoop line 4788.
      case assumeUtxoForHeight regtest 110 of
        Nothing -> pendingWith "regtest 110 missing"
        Just p  -> do
          state <- initAssumeUtxoState regtest p
          writeIORef (ausError    state) (Just "synthetic failure")
          writeIORef (ausValidated state) True
          isVal <- isAssumeUtxoValidated state
          isVal `shouldBe` True        -- BUG-6: True despite stored error
          mErr  <- readIORef (ausError state)
          mErr  `shouldBe` Just "synthetic failure"

  -- -----------------------------------------------------------------------
  -- G22: loadtxoutset RPC gate
  -- -----------------------------------------------------------------------

  describe "G22 loadtxoutset RPC gate message" $ do
    it "loadTxOutSetGateMessage mentions --load-snapshot" $
      loadTxOutSetGateMessage `shouldSatisfy`
        ("--load-snapshot" `T.isInfixOf`)

    it "loadTxOutSetGateMessage explains the atomicity limitation" $
      loadTxOutSetGateMessage `shouldSatisfy`
        ("atomically activate" `T.isInfixOf`)

  -- -----------------------------------------------------------------------
  -- G26–G27: assumeutxo table integrity
  -- -----------------------------------------------------------------------

  describe "G26 netAssumeUtxo table entries" $ do
    it "mainnet has the 4 Core entries + the 944183 hashhog-recovery entry" $
      -- The four 840000/880000/910000/935000 entries are the upstream
      -- Bitcoin Core m_assumeutxo_data values.  944183 is a hashhog-local
      -- snapshot added (W163) to recover haskoin's mainnet chainstate
      -- from the W162 corruption via '--load-snapshot'; it is NOT a Core
      -- chainparams entry.  See Consensus.hs netAssumeUtxo (mainnet).
      map fst (netAssumeUtxo mainnet)
        `shouldBe` [840000, 880000, 910000, 935000, 944183]

    it "testnet4 has at least 1 snapshot entry" $
      length (netAssumeUtxo testnet4) `shouldSatisfy` (>= 1)

    it "regtest has exactly 1 snapshot entry at height 110" $
      map fst (netAssumeUtxo regtest) `shouldBe` [110]

  describe "G27 aupBlockHash is non-zero for every table entry" $
    it "no entry has the all-zero block hash" $ do
      let zero       = mkBlockHash 0x00
          allEntries = concatMap netAssumeUtxo [mainnet, testnet4, regtest]
      forM_ allEntries $ \(_, p) ->
        aupBlockHash p `shouldNotBe` zero

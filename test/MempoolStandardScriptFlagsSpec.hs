-- | r3fix-haskoin-mempool-standard-script-flags (R3 night 1, seed 739943,
-- triage group G2 "mempool-runs-consensus-flags-only").
--
-- Core v31.1 checks a transaction's scripts for its mempool with
-- STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h:118-131, applied in
-- MemPoolAccept::PolicyScriptChecks, validation.cpp:1146 in v31.1): the seven
-- mandatory (consensus) flags plus fourteen standard-only ones.  haskoin's
-- mempool passed the consensus flags only, so a spend that breaks a
-- standard-only rule was accepted by testmempoolaccept, sendrawtransaction,
-- relay and the package path, where Core refuses it with
-- "mempool-script-verify-flag-failed (...)".
--
-- Every policy fixture below is refused by Core v31.1's mempool (the Core
-- answer is in the test name, measured on the pinned 31.1 bitcoind through the
-- R3 harness's own Core/node pair, tools/diff-fuzz/difffuzz/gen/world.py) and
-- is accepted in a block by Core (a policy rule, not consensus).  The R-numbered fixtures are the stored examples of haskoin's
-- night-1 gen-baseline verdict rows (tools/diff-fuzz/gen-baselines/haskoin.json),
-- byte for byte.  R53's stored example is an unbalanced [IF 1], which master
-- already refuses since haskoin#85 (UNBALANCED_CONDITIONAL is consensus), so
-- the MINIMALIF rule is pinned with the balanced [IF 1 ENDIF] instead.  LOW_S,
-- NULLFAIL, WITNESS_PUBKEYTYPE and DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM had
-- no night-1 verdict row; they are hand-built with the generator's case
-- builder.  The witness-program cases are P2SH-wrapped programs spent with no
-- witness at all (P2SH-wrapped P2A, and v2): with a witness, haskoin's
-- IsWitnessStandard refuses a P2SH-wrapped unknown version before the script
-- check, where Core's lets it through (a separate standardness gap).
--
-- Pay-to-Anchor is the one witness program Core exempts from
-- DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, and only when native
-- (interpreter.cpp:1990): control_p2a_native, alone and as a package child,
-- must stay accepted under the standard flags.
--
-- The controls are standard spends Core accepts; they must stay accepted, so
-- a refusal for an unrelated reason (a broken fixture, a funding mistake) cannot
-- pass as a fix.  The block-flag test pins that block validation is untouched:
-- every fixture, policy and control (the native P2A anchor spend included),
-- still verifies under the block script flags.
module Main (main) where

import Control.Concurrent.STM (atomically)
import Control.Monad (forM_)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BS8
import qualified Data.Serialize as S
import Data.Word (Word64)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec

import Haskoin.Consensus (regtest, getBlockScriptFlags, consensusFlagsToScriptFlags)
import Haskoin.Crypto (computeTxId, sha256)
import Haskoin.Mempool
import qualified Haskoin.Script as Script
import Haskoin.Storage (newUTXOCache, defaultDBConfig, withDB, addUTXO, UTXOEntry(..))
import Haskoin.Types

data Fixture = Fixture
  { fxName  :: String
  , fxCore  :: String   -- ^ Core v31.1's testmempoolaccept reject-reason ("" = allowed)
  , fxSpk   :: String   -- ^ scriptPubKey of the coin input 0 spends
  , fxValue :: Word64   -- ^ value of that coin
  , fxTx    :: String   -- ^ the spend, as gen_fuzz sent it
  }

hex :: String -> BS.ByteString
hex s = either (error . ("bad hex: " ++)) id (B16.decode (BS8.pack s))

txOf :: Fixture -> Tx
txOf f = either (error . ("bad tx: " ++)) id (S.decode (hex (fxTx f)))

coinOf :: Fixture -> (OutPoint, TxOut)
coinOf f = (txInPrevOutput (head (txInputs (txOf f))), TxOut (fxValue f) (hex (fxSpk f)))

-- | A pool at tip 200 holding the given confirmed, mature, non-coinbase coins.
withCoins :: [(OutPoint, TxOut)] -> (Mempool -> IO a) -> IO a
withCoins coins action =
  withSystemTempDirectory "haskoin-std-script-flags" $ \dir ->
    withDB (defaultDBConfig (dir </> "chainstate")) $ \db -> do
      cache <- newUTXOCache db 100000
      atomically $ mapM_ (\(op, o) -> addUTXO cache op (UTXOEntry o 1 False False)) coins
      mp <- newMempool regtest cache defaultMempoolConfig 200 0 noopCoinMtp
      action mp

-- | What the pool said, without the entry (MempoolEntry has no Show).
said :: Either MempoolError a -> Either MempoolError ()
said = fmap (const ())

scriptRefused :: Either MempoolError () -> Bool
scriptRefused (Left (ErrScriptVerificationFailed _)) = True
scriptRefused _ = False

pkgScriptRefused :: Either PackageError a -> Bool
pkgScriptRefused (Left (PkgTxError _ (ErrScriptVerificationFailed _))) = True
pkgScriptRefused _ = False

-- | P2WSH(OP_TRUE), spent with the witness [OP_TRUE].
opTrueSpk :: BS.ByteString
opTrueSpk = BS.pack [0x00, 0x20] <> sha256 (BS.singleton 0x51)

-- | A parent spending a P2WSH(OP_TRUE) coin into an output locked by @spk@
-- (plus a P2WSH(OP_TRUE) output, so a parent paying to the 4-byte P2A script
-- is not under Core's 65-byte MIN_STANDARD_TX_NONWITNESS_SIZE), and the
-- fixture's spend re-pointed at output 0 (no signature in the fixtures used
-- here, so the re-pointed spend is still well formed).
packageFor :: Fixture -> ((OutPoint, TxOut), TxPackage)
packageFor f =
  let fundOp = OutPoint (TxId (Hash256 (BS.replicate 32 0x6b))) 0
      parent = Tx { txVersion = 2
                  , txInputs = [TxIn fundOp BS.empty 0xfffffffd]
                  , txOutputs = [TxOut (fxValue f) (hex (fxSpk f)), TxOut 1000 opTrueSpk]
                  , txWitness = [[BS.singleton 0x51]]
                  , txLockTime = 0 }
      child0 = txOf f
      repoint (i : rest) = i { txInPrevOutput = OutPoint (computeTxId parent) 0 } : rest
      repoint [] = []
      child = child0 { txInputs = repoint (txInputs child0) }
  in ((fundOp, TxOut (fxValue f + 2000) opTrueSpk), TxPackage [parent] child)

policyFixtures :: [Fixture]
policyFixtures =
  [ Fixture
      { fxName  = "R51 mempool/verdict/script-policy/DISCOURAGE_OP_SUCCESS|accept (tapscript script=[RESERVED])"
      , fxCore  = "mempool-script-verify-flag-failed (OP_SUCCESSx reserved for soft-fork upgrades)"
      , fxSpk   = "5120b24dd91099ea57f2f942a0177f1ab650eb5bec51083311ed9e1d115092ba81af"
      , fxValue = 100000
      , fxTx    = "020000000001012fa39640da2989ed60401e5e7c337a89874d94612beff57415cefa5f3d26ab500000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326002015021c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
      }
  , Fixture
      { fxName  = "R52 mempool/verdict/script-policy/DISCOURAGE_UPGRADABLE_TAPROOT_VERSION|accept (tapscript script=[] leaf=0xfe ctl+=0 flip=False)"
      , fxCore  = "mempool-script-verify-flag-failed (Taproot version reserved for soft-fork upgrades)"
      , fxSpk   = "5120949c87360d9b4a9312d79b8071b446e543999bdb66447ec9c08becd97803658a"
      , fxValue = 100000
      , fxTx    = "02000000000101f3ed25901d3664e2ba2a50cdd38b542b3f05a6c12fbfa838d6d3f97627a581170000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020021ff79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
      }
  , Fixture
      { fxName  = "R54 mempool/verdict/script-policy/SIG_HASHTYPE|accept (p2sh script=[<pk> CHECKSIG] sig=[<sig>] hashtype=0x04)"
      , fxCore  = "mempool-script-verify-flag-failed (Signature hash type missing or not understood)"
      , fxSpk   = "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187"
      , fxValue = 100000
      , fxTx    = "02000000013c36c7f344c2daa3285ba65abc610cc734f933a494630c64a4a4b09305286f42000000006c473044022040ccd929346d119e72d1d80bd6bc55ccf6f1c5755b407c19f61d68d391ffd80a02201ce66f3bcc2f1363248b94f821d43425ae601e6205241359696f15599704c9c10423210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798acfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "R55 mempool/verdict/script-policy/CLEANSTACK|accept (p2sh script=[0 11 SWAP SWAP SWAP SWAP])"
      , fxCore  = "mempool-script-verify-flag-failed (Stack size must be exactly one after execution)"
      , fxSpk   = "a914597fc0331a5ab794f8712587108db88afccda44487"
      , fxValue = 100000
      , fxTx    = "02000000014281cedb4b23f544e4652df8bdcd9ca9966d6e631c2f21a5d502292d94f91b21000000000706005b7c7c7c7cfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "R57 mempool/verdict/script-policy/MINIMALDATA|accept (p2sh script=[1] sig=[PUSHDATA1:<>])"
      , fxCore  = "mempool-script-verify-flag-failed (Data push larger than necessary)"
      , fxSpk   = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"
      , fxValue = 100000
      , fxTx    = "02000000012b44ee8810dc9698871e431c924b233e94fd71525ce162fded6fa9602280d0f300000000044c000151feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "R58 mempool/verdict/script-policy/PUBKEYTYPE|accept (p2wsh script=[0 0 CHECKSIG DROP 0 0 CHECKSIG DROP 0 0 CHECKSIG DROP 0 0 CHECKSIG DROP 0 0 CHECKSIG DROP 1])"
      , fxCore  = "mempool-script-verify-flag-failed (Public key is neither compressed or uncompressed)"
      , fxSpk   = "0020ac3b947221ea320dc3c19ff81e37bcf4e7fd62c3e8c3598d684a8355de8af5a8"
      , fxValue = 100000
      , fxTx    = "02000000000101877c00ec5ee1fdbc8a5dd76e7b07faab30dc776513c2fa802d9cbe53ff1b75990000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001150000ac750000ac750000ac750000ac750000ac755100000000"
      }
  , Fixture
      { fxName  = "R59 mempool/verdict/script-policy/SIG_FINDANDDELETE|accept (p2sh script=[0 0 CHECKSIG DROP] sig=[1])"
      , fxCore  = "mempool-script-verify-flag-failed (Signature is found in scriptCode)"
      , fxSpk   = "a914405e3d101e8bc12215ee63f8d2d952131005850187"
      , fxValue = 100000
      , fxTx    = "0200000001f04eafd5ac07d15ccceb8e1cf40da83bcce7726e0c04cd909fec4a7337174f89000000000651040000ac75feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "R60 mempool/verdict/script-policy/DISCOURAGE_UPGRADABLE_NOPS|accept (p2sh script=[NOP10] sig=[1])"
      , fxCore  = "mempool-script-verify-flag-failed (NOPx reserved for soft-fork upgrades)"
      , fxSpk   = "a91415727299b05b45fdaf9ac9ecf7565cfe27c3e56787"
      , fxValue = 100000
      , fxTx    = "0200000001de289a9b3f7dcb5bd53f0c552b36bc34fedc5b4affddf6beeee99f991803c8cf00000000035101b9feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "R61 mempool/verdict/script-policy/DISCOURAGE_UPGRADABLE_PUBKEYTYPE|accept (tapscript script=[30 13 CHECKSIG])"
      , fxCore  = "mempool-script-verify-flag-failed (Public key version reserved for soft-fork upgrades)"
      , fxSpk   = "512074d9922e095b9b190c0eec6e2419cbe10348c8d3aeba5e712cc743823e901617"
      , fxValue = 100000
      , fxTx    = "020000000001012bbe772ef8309dc40b8f43f7c9e4bb5fb0d5d74d41d8028b4f6dabeb289d29a00000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020401305dac21c179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
      }
  , Fixture
      { fxName  = "R62 mempool/verdict/script-policy/OP_CODESEPARATOR|accept (p2sh script=[CODESEPARATOR 31])"
      , fxCore  = "mempool-script-verify-flag-failed (Using OP_CODESEPARATOR in non-witness script)"
      , fxSpk   = "a914f9a1803aba8b8b7a7648b908f9c6b7f4e24204a987"
      , fxValue = 100000
      , fxTx    = "02000000014ad851ec994c2ec722b87e0b83c5166b7fc9bdd45c3ac6c09995e99ac57c1da3000000000403ab0131feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "LOW_S (p2wsh script=[0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 CHECKSIG NOT] wit=['3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414001'])"
      , fxCore  = "mempool-script-verify-flag-failed (Non-canonical signature: S value is unnecessarily high)"
      , fxSpk   = "002099e3bf577c2879d1b0e7288434d2fba1466254be329ce616da18af08acc712b7"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326002293026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641400124210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac9100000000"
      }
  , Fixture
      { fxName  = "NULLFAIL (p2wsh script=[0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 CHECKSIG NOT] wit=['300602010102010101'])"
      , fxCore  = "mempool-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"
      , fxSpk   = "002099e3bf577c2879d1b0e7288434d2fba1466254be329ce616da18af08acc712b7"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020930060201010201010124210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac9100000000"
      }
  , Fixture
      { fxName  = "WITNESS_PUBKEYTYPE (p2wsh script=[0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG NOT] wit=[''])"
      , fxCore  = "mempool-script-verify-flag-failed (Using non-compressed keys in segwit)"
      , fxSpk   = "00206896f88237015ef28a702a53fc24e792511b56843cd575d0b7712b2b75111f12"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020044410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac9100000000"
      }
  , Fixture
      { fxName  = "MINIMALIF_balanced (p2sh-p2wsh script=[IF 1 ENDIF] wit=['02'])"
      , fxCore  = "mempool-script-verify-flag-failed (OP_IF/NOTIF argument must be minimal)"
      , fxSpk   = "a9149b27ee6d9010c21bf837b334d043be5d150e7ba787"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000023220020c7eaf06d5ae01a58e376e126eb1e6fab2036076922b96b2711ffbec1e590665dfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600201020363516800000000"
      }
  , Fixture
      { fxName  = "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_p2sh_p2a (p2sh script=[1 4e73], no witness)"
      , fxCore  = "mempool-script-verify-flag-failed (Witness version reserved for soft-fork upgrades)"
      , fxSpk   = "a9143b68dd0468ddab9d6b7d341e721ec1b386aa29b987"
      , fxValue = 100000
      , fxTx    = "02000000015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00000000050451024e73feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM_p2sh_v2_nowit (p2sh script=[2 1111111111111111111111111111111111111111111111111111111111111111], no witness)"
      , fxCore  = "mempool-script-verify-flag-failed (Witness version reserved for soft-fork upgrades)"
      , fxSpk   = "a914bd36a36cbcbdf52ad0420a31112a7b10bd99a15087"
      , fxValue = 100000
      , fxTx    = "02000000015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00000000232252201111111111111111111111111111111111111111111111111111111111111111feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  ]

controlFixtures :: [Fixture]
controlFixtures =
  [ Fixture
      { fxName  = "control_p2sh_true (p2sh script=[1])"
      , fxCore  = "allowed"
      , fxSpk   = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"
      , fxValue = 100000
      , fxTx    = "02000000015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00000000020151feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "control_p2wsh_emptysig_checksig_not (p2wsh script=[0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 CHECKSIG NOT] wit=[''])"
      , fxCore  = "allowed"
      , fxSpk   = "002099e3bf577c2879d1b0e7288434d2fba1466254be329ce616da18af08acc712b7"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260020024210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac9100000000"
      }
  , Fixture
      { fxName  = "control_p2sh_signed_checksig (p2sh script=[<pk> CHECKSIG] sig=[<sig>])"
      , fxCore  = "allowed"
      , fxSpk   = "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187"
      , fxValue = 100000
      , fxTx    = "02000000015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000000006d483045022100abbebcd99d56f467ed4b602c9c8d319a36d6b62eeb9b4022152bc67aa049d73f02205501a9011ca8444f120d994d6e2506cea70d3b22f5914469c873f224bdd98a960123210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798acfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  , Fixture
      { fxName  = "control_p2sh_p2wsh_minimal_if (p2sh-p2wsh script=[IF 1 ENDIF] wit=['01'])"
      , fxCore  = "allowed"
      , fxSpk   = "a9149b27ee6d9010c21bf837b334d043be5d150e7ba787"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000023220020c7eaf06d5ae01a58e376e126eb1e6fab2036076922b96b2711ffbec1e590665dfeffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600201010363516800000000"
      }
  , Fixture
      { fxName  = "control_tapscript_true (tapscript script=[1])"
      , fxCore  = "allowed"
      , fxSpk   = "51209b6ce0db0707e29f92bf8893ed1911d397e3d2d76bbc68110c49da2ceec8be23"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326002015121c079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
      }
  , Fixture
      { fxName  = "control_tapscript_signed (tapscript script=[<pk> CHECKSIG] wit=['<sig>'])"
      , fxCore  = "allowed"
      , fxSpk   = "51202d2f7b2a700ab270dd515ef7a02f25c5a344066641fcac563e1b53eca4a456d3"
      , fxValue = 100000
      , fxTx    = "020000000001015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600340941ee67bb0103312578e618eb6438d6a78f781ef1d54f9b8847163ca6ebfc16fea49d52afb09b29ccf28eb62f1c95373e0776b9eaedeca0dd0b84bdc4ee1edc9222079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac21c179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000"
      }
  , Fixture
      { fxName  = "control_p2a_native (bare script=[1 4e73])"
      , fxCore  = ""
      , fxSpk   = "51024e73"
      , fxValue = 100000
      , fxTx    = "02000000015a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0000000000feffffff01d07e0100000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000"
      }
  ]

-- | R60, the item's minimised case: p2sh script=[NOP10] sig=[1].
nopsFixture :: Fixture
nopsFixture = head [ f | f <- policyFixtures, take 4 (fxName f) == "R60 " ]

-- | control_p2sh_true: p2sh script=[1].
p2shTrueFixture :: Fixture
p2shTrueFixture = head [ f | f <- controlFixtures, take 17 (fxName f) == "control_p2sh_true" ]

-- | control_p2a_native: bare script=[1 4e73], the Pay-to-Anchor output.
p2aFixture :: Fixture
p2aFixture = head [ f | f <- controlFixtures, take 18 (fxName f) == "control_p2a_native" ]

main :: IO ()
main = hspec $ do
  describe "mempool checks scripts with Core v31.1's STANDARD_SCRIPT_VERIFY_FLAGS (policy.h:118-131)" $ do
    forM_ policyFixtures $ \f ->
      it (fxName f ++ ": refused by testmempoolaccept and sendrawtransaction, as Core (" ++ fxCore f ++ ")") $
        withCoins [coinOf f] $ \mp -> do
          dry <- said <$> testAcceptTransaction mp (txOf f)
          dry `shouldSatisfy` scriptRefused
          real <- said <$> addTransaction mp (txOf f)
          real `shouldSatisfy` scriptRefused

    forM_ controlFixtures $ \f ->
      it ("control " ++ fxName f ++ ": accepted, as Core") $
        withCoins [coinOf f] $ \mp -> do
          dry <- said <$> testAcceptTransaction mp (txOf f)
          dry `shouldBe` Right ()
          real <- said <$> addTransaction mp (txOf f)
          real `shouldBe` Right ()

    it "R60 via the package path (submitpackage): the child is refused on its script, as Core" $ do
      let (coin, pkg) = packageFor nopsFixture
      withCoins [coin] $ \mp -> do
        r <- acceptPackage pkg mp
        r `shouldSatisfy` pkgScriptRefused

    it "control via the package path: a parent + native P2A anchor-spend child is accepted" $ do
      let (coin, pkg) = packageFor p2aFixture
      withCoins [coin] $ \mp -> do
        r <- acceptPackage pkg mp
        fmap length r `shouldBe` Right 2

    it "control via the package path: a parent + standard p2sh [1] child is accepted" $ do
      let (coin, pkg) = packageFor p2shTrueFixture
      withCoins [coin] $ \mp -> do
        r <- acceptPackage pkg mp
        fmap length r `shouldBe` Right 2

  describe "block validation is unchanged: every fixture is consensus-valid" $
    forM_ (policyFixtures ++ controlFixtures) $ \f ->
      it (fxName f ++ ": verifies under the block script flags at height 201") $ do
        let tx = txOf f
            (_, coin) = coinOf f
            flags = consensusFlagsToScriptFlags
                      (getBlockScriptFlags regtest (BlockHash (Hash256 (BS.replicate 32 0))) 201)
        Script.verifyScriptWithFlags flags tx 0 (txOutScript coin) (txOutValue coin)
                                     [txOutValue coin] [txOutScript coin]
          `shouldBe` Right True

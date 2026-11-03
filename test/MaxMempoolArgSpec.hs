-- | @-maxmempool=<n>@ sets the mempool size limit, as in Bitcoin Core.
--
-- Core: node/mempool_args.cpp ApplyArgsManOptions sets
-- @max_size_bytes = n * 1'000'000@; txmempool.cpp Flatten refuses a negative
-- value, or a positive one below 40 x the cluster size limit
-- (101 kvB, policy.h DEFAULT_CLUSTER_SIZE_LIMIT_KVB), with
-- "-maxmempool must be at least 5 MB".  getmempoolinfo.maxmempool then
-- reports max_size_bytes.  The Core regtest harness runs its pressure
-- groups at -maxmempool=5, and haskoin answered 300000000 there because it
-- had no such option.
module MaxMempoolArgSpec (spec) where

import Test.Hspec
import Haskoin.Mempool (MempoolConfig (..), applyMaxMempoolMb, defaultMempoolConfig)

maxSizeFor :: Int -> Either String Int
maxSizeFor mb = mpcMaxSize <$> applyMaxMempoolMb mb defaultMempoolConfig

spec :: Spec
spec = describe "-maxmempool (Core node/mempool_args.cpp, txmempool.cpp Flatten)" $ do
  it "maxmempool=5 sets the limit to 5000000 bytes (the Core regtest pressure groups)" $
    maxSizeFor 5 `shouldBe` Right 5000000

  it "maxmempool=300 is Core's default 300000000 bytes (megabytes are 10^6)" $
    maxSizeFor 300 `shouldBe` Right 300000000

  it "maxmempool=17 sets 17000000 bytes, not a value fixed at 5 or 300" $
    maxSizeFor 17 `shouldBe` Right 17000000

  it "maxmempool=4 is refused: below 40 x the 101 kvB cluster limit (\"must be at least 5 MB\")" $
    maxSizeFor 4 `shouldBe` Left "-maxmempool must be at least 5 MB"

  it "maxmempool=-1 is refused" $
    maxSizeFor (-1) `shouldBe` Left "-maxmempool must be at least 5 MB"

  it "maxmempool=0 is accepted as 0 bytes (Flatten only checks a positive value)" $
    maxSizeFor 0 `shouldBe` Right 0

  it "leaves the rest of the config alone" $
    fmap mpcMaxDescendantSize (applyMaxMempoolMb 5 defaultMempoolConfig)
      `shouldBe` Right (mpcMaxDescendantSize defaultMempoolConfig)

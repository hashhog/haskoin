{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | ASMap (Autonomous System Map) interpreter and loader.
--
-- Provides a compressed mapping from IP address prefixes to Autonomous
-- System Numbers (ASNs) using a binary trie encoded as bytecode
-- instructions (RETURN, JUMP, MATCH, DEFAULT).
--
-- References:
--   bitcoin-core/src/util/asmap.h
--   bitcoin-core/src/util/asmap.cpp
--   bitcoin-core/src/netgroup.cpp  (GetMappedAS, GetGroup)
--   bitcoin-core/src/init.cpp      (-asmap loading, MAX_ASMAP_FILESIZE)
--
-- Key design points:
--   * ASMap bytecode bits are read LSB-first within each byte.
--   * IP address bits are read MSB-first (network byte order).
--   * DecodeBits uses a variable-length class encoding described in asmap.cpp.
--   * ASN 0 is the "not found" / error sentinel (RFC 7607 reserves AS0).
module Haskoin.ASMap
  ( -- * Constants
    maxAsmapFileSize
    -- * Loading
  , loadAsmap
    -- * Interpreter
  , interpret
  , getMappedAS
    -- * Sanity check
  , sanityCheckAsmap
  , checkStandardAsmap
    -- * IPv4-in-IPv6 padding
  , ipv4InIpv6Prefix
  , padIpv4ToIpv6
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Bits (shiftR, (.&.))
import Data.Word (Word8, Word32)
import Control.Exception (try, IOException)

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

-- | Maximum allowed asmap file size (8 MiB).
-- Reference: bitcoin-core/src/init.cpp (MAX_ASMAP_FILESIZE).
maxAsmapFileSize :: Int
maxAsmapFileSize = 8 * 1024 * 1024  -- 8 388 608 bytes

-- | Sentinel returned by DecodeBits on any parse error.
-- Also the value returned by interpret() on any decode failure.
-- Reference: asmap.cpp anonymous namespace INVALID = 0xFFFFFFFF.
invalidAsn :: Word32
invalidAsn = 0xFFFFFFFF

-- | IPv4-in-IPv6 prefix: 10 zero bytes followed by two 0xFF bytes.
-- Reference: bitcoin-core/src/netgroup.cpp GetMappedAS IPv4 padding.
ipv4InIpv6Prefix :: ByteString
ipv4InIpv6Prefix = BS.pack (replicate 10 0x00 ++ [0xFF, 0xFF])

-- | Pad a 4-byte IPv4 address to a 16-byte IPv4-in-IPv6 address.
-- Reference: bitcoin-core/src/netgroup.cpp:88-96.
padIpv4ToIpv6 :: ByteString -> ByteString
padIpv4ToIpv6 ipv4 = ipv4InIpv6Prefix <> ipv4

--------------------------------------------------------------------------------
-- Loading
--------------------------------------------------------------------------------

-- | Read an asmap file from disk.
-- Returns Left error message on failure (file not found, too large, invalid).
-- The returned ByteString is the raw bytecode; call 'sanityCheckAsmap' before use.
-- Reference: bitcoin-core/src/util/asmap.cpp DecodeAsmap.
loadAsmap :: FilePath -> IO (Either String ByteString)
loadAsmap path = do
  result <- try @IOException (BS.readFile path)
  case result of
    Left e -> return $ Left ("Failed to read asmap file: " ++ show e)
    Right bs
      | BS.length bs > maxAsmapFileSize ->
          return $ Left ("asmap file exceeds MAX_ASMAP_FILESIZE ("
                      ++ show maxAsmapFileSize ++ " bytes): "
                      ++ show (BS.length bs) ++ " bytes")
      | not (checkStandardAsmap bs) ->
          return $ Left "asmap sanity check failed (invalid bytecode)"
      | otherwise ->
          return $ Right bs

--------------------------------------------------------------------------------
-- Bit-reading primitives
--------------------------------------------------------------------------------

-- | Read one bit from the asmap bytecode using LSB-first bit ordering.
-- Returns (bit, newBitPos).
-- Reference: asmap.cpp ConsumeBitLE.
consumeBitLE :: Int -> ByteString -> (Bool, Int)
consumeBitLE !bitpos !bytes =
  let byteIdx = bitpos `div` 8
      bitIdx  = bitpos `mod` 8
      byte    = BS.index bytes byteIdx
      bit     = (byte `shiftR` bitIdx) .&. 1 /= 0
  in (bit, bitpos + 1)

-- | Read one bit from an IP address using MSB-first bit ordering.
-- Returns (bit, newBitPos).
-- Reference: asmap.cpp ConsumeBitBE.
consumeBitBE :: Int -> ByteString -> (Bool, Int)
consumeBitBE !bitpos !ip =
  let byteIdx = bitpos `div` 8
      bitIdx  = bitpos `mod` 8
      byte    = BS.index ip byteIdx
      bit     = (byte `shiftR` (7 - bitIdx)) .&. 1 /= 0
  in (bit, bitpos + 1)

--------------------------------------------------------------------------------
-- Variable-length integer decoder
--------------------------------------------------------------------------------

-- | Decode a variable-length integer from the asmap bytecode.
--
-- The encoding works as follows (from asmap.cpp comment):
-- Given minval and bit_sizes = [s0, s1, ..., sk]:
--   Class 0: 0-bit (encoded [0]), then s0-bit big-endian value in [minval, minval + 2^s0 - 1]
--   Class 1: 1-bit then 0-bit ([1,0]), then s1-bit value in [minval+2^s0, ...]
--   ...
--   Class k (last): no continuation bit, just sk-bit value
--
-- Returns 'invalidAsn' (0xFFFFFFFF) if EOF is reached.
-- Reference: asmap.cpp DecodeBits.
decodeBits :: Int        -- ^ current bit position in asmap
           -> ByteString -- ^ asmap bytecode
           -> Word32     -- ^ minval
           -> [Int]      -- ^ bit_sizes array
           -> (Word32, Int)  -- ^ (decoded value, new bitpos)
decodeBits !pos !bytes !minval !bitSizes = go pos minval bitSizes
  where
    totalBits = BS.length bytes * 8

    go !curPos !val [] =
      -- Reached EOF in the exponent loop — should not happen in valid data
      (invalidAsn, curPos)

    go !curPos !val [lastSz] =
      -- Last class: no continuation bit; decode lastSz-bit BE value
      readMantissa curPos val lastSz

    go !curPos !val (sz : rest) =
      -- Read continuation bit
      if curPos >= totalBits
        then (invalidAsn, curPos)
        else
          let (contBit, nextPos) = consumeBitLE curPos bytes
          in if contBit
               then go nextPos (val + fromIntegral (1 `shiftL'` sz)) rest
               else readMantissa nextPos val sz

    readMantissa !curPos !val !sz =
      -- Read `sz` bits big-endian and add to val
      let go2 !cp !acc !b
            | b >= sz   = (acc, cp)
            | cp >= totalBits = (invalidAsn, cp)
            | otherwise =
                let (bit, np) = consumeBitLE cp bytes
                    bitVal = if bit then 1 `shiftL'` (sz - 1 - b) else 0
                in go2 np (acc + fromIntegral bitVal) (b + 1)
      in go2 curPos val 0

    shiftL' :: Int -> Int -> Int
    shiftL' x n = x * (2 ^ n)

-- Encoding tables from asmap.cpp
typeBitSizes :: [Int]
typeBitSizes = [0, 0, 1]  -- RETURN=0, JUMP=10, MATCH=110, DEFAULT=111

asnBitSizes :: [Int]
asnBitSizes = [15, 16, 17, 18, 19, 20, 21, 22, 23, 24]

matchBitSizes :: [Int]
matchBitSizes = [1, 2, 3, 4, 5, 6, 7, 8]

jumpBitSizes :: [Int]
jumpBitSizes = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                21, 22, 23, 24, 25, 26, 27, 28, 29, 30]

-- | Decode instruction type from bytecode (LSB-first).
-- Returns (opcode, newBitPos) where opcode: 0=RETURN, 1=JUMP, 2=MATCH, 3=DEFAULT.
-- 0xFFFFFFFF signals EOF.
decodeType :: Int -> ByteString -> (Word32, Int)
decodeType pos bytes = decodeBits pos bytes 0 typeBitSizes

decodeASN :: Int -> ByteString -> (Word32, Int)
decodeASN pos bytes = decodeBits pos bytes 1 asnBitSizes

decodeMatch :: Int -> ByteString -> (Word32, Int)
decodeMatch pos bytes = decodeBits pos bytes 2 matchBitSizes

decodeJump :: Int -> ByteString -> (Word32, Int)
decodeJump pos bytes = decodeBits pos bytes 17 jumpBitSizes

--------------------------------------------------------------------------------
-- Interpreter
--------------------------------------------------------------------------------

-- | Execute the ASMap bytecode to find the ASN for an IP address.
--
-- @interpret asmap ip@ walks the bit-trie encoded in @asmap@, using bits
-- from @ip@ (MSB-first) to navigate, and returns:
--   * The matched ASN (> 0) on a RETURN leaf.
--   * 0 on a MATCH failure with no DEFAULT set.
--   * The most-recent DEFAULT value on a MATCH failure.
--   * 0 on any decode error or unexpected EOF.
--
-- @asmap@ is raw bytecode (from 'loadAsmap'); @ip@ should be 16 bytes for
-- IPv6 (or IPv4 padded via 'padIpv4ToIpv6').
--
-- Reference: bitcoin-core/src/util/asmap.cpp Interpret().
interpret :: ByteString  -- ^ ASMap bytecode
          -> ByteString  -- ^ IP address (16 bytes, big-endian / network order)
          -> Word32      -- ^ ASN (0 = not found or error)
interpret !asmap !ip = go 0 0 0
  where
    asmapBits = BS.length asmap * 8
    ipBits    = BS.length ip * 8

    go !pos !ipBit !defaultAsn
      | pos >= asmapBits = 0  -- Reached EOF without RETURN
      | otherwise =
          let (opcode, pos1) = decodeType pos asmap
          in case opcode of
               0 -> -- RETURN: return decoded ASN
                 let (asn, _) = decodeASN pos1 asmap
                 in if asn == invalidAsn then 0 else asn

               1 -> -- JUMP: binary branch on next IP bit
                 let (jump, pos2) = decodeJump pos1 asmap
                 in if jump == invalidAsn then 0
                    else if ipBit >= ipBits then 0
                    else if fromIntegral jump >= asmapBits - pos2 then 0
                    else
                      let (ipBitVal, newIpBit) = consumeBitBE ipBit ip
                          newPos = if ipBitVal then pos2 + fromIntegral jump else pos2
                      in go newPos newIpBit defaultAsn

               2 -> -- MATCH: compare multiple IP bits against a pattern
                 let (matchVal, pos2) = decodeMatch pos1 asmap
                 in if matchVal == invalidAsn then 0
                    else
                      let matchLen = bitWidth matchVal - 1
                      in if ipBit + matchLen > ipBits then 0
                         else matchLoop pos2 ipBit defaultAsn matchVal matchLen 0

               3 -> -- DEFAULT: set default ASN and continue
                 let (asn, pos2) = decodeASN pos1 asmap
                 in if asn == invalidAsn then 0
                    else go pos2 ipBit asn

               _ -> 0  -- EOF / unknown (decode returned INVALID)

    matchLoop !pos !ipBit !def !matchVal !matchLen !bit
      | bit >= matchLen = go pos ipBit def
      | otherwise =
          let (ipBitVal, newIpBit) = consumeBitBE ipBit ip
              expected = fromIntegral (matchVal `shiftR` (matchLen - 1 - bit)) .&. 1 /= (0 :: Word32)
          in if ipBitVal /= expected
               then def  -- Pattern mismatch: use default
               else matchLoop pos newIpBit def matchVal matchLen (bit + 1)

-- | Count the position of the highest set bit (equivalent to floor(log2(x))+1
-- for x > 0), i.e. std::bit_width in C++20.
bitWidth :: Word32 -> Int
bitWidth 0 = 0
bitWidth x = 1 + bitWidth (x `shiftR` 1)

-- | Look up the ASN for a 16-byte (IPv6 or IPv4-mapped) address.
-- Returns 0 if no mapping found or asmap is empty.
getMappedAS :: ByteString  -- ^ Raw asmap bytecode
            -> ByteString  -- ^ 16-byte IP address (network byte order)
            -> Word32      -- ^ ASN (0 = not found)
getMappedAS asmap ip
  | BS.null asmap = 0
  | BS.length ip /= 16 = 0
  | otherwise = interpret asmap ip

--------------------------------------------------------------------------------
-- Sanity check
--------------------------------------------------------------------------------

-- | Validate all execution paths in the ASMap bytecode.
-- Returns True iff the bytecode is well-formed for @bits@-bit inputs.
-- Reference: bitcoin-core/src/util/asmap.cpp SanityCheckAsmap.
sanityCheckAsmap :: ByteString  -- ^ ASMap bytecode
                 -> Int         -- ^ Input bit width (128 for IPv6)
                 -> Bool
sanityCheckAsmap !asmap !inputBits = go 0 inputBits 1 [] False  -- prevIsJump=1 (Instruction::JUMP)
  where
    endpos = BS.length asmap * 8

    go !pos !bits !prevOpcode !jumps !hadIncompleteMatch
      | pos == endpos = False  -- Reached EOF without RETURN
      | otherwise =
          -- Check: jump target should not land inside a previous instruction
          case jumps of
            ((jt, _):_) | pos > jt -> False
            _ ->
              let (opcode, pos1) = decodeType pos asmap
              in case opcode of
                   0 ->  -- RETURN
                     if prevOpcode == 3  -- prev was DEFAULT → could be combined
                       then False
                       else
                         let (asn, pos2) = decodeASN pos1 asmap
                         in if asn == invalidAsn then False
                            else case jumps of
                              [] ->
                                -- Nothing left; check padding ≤ 7 bits, all zero
                                if endpos - pos2 > 7 then False
                                else checkPadding pos2
                              ((jt, savedBits):rest) ->
                                if pos2 /= jt then False  -- unreachable code
                                else go jt savedBits 1 rest False

                   1 ->  -- JUMP
                     let (jump, pos2) = decodeJump pos1 asmap
                     in if jump == invalidAsn then False
                        else if fromIntegral jump > fromIntegral (endpos - pos2) then False
                        else if bits == 0 then False
                        else
                          let newBits  = bits - 1
                              jumpTarget = pos2 + fromIntegral jump
                          in case jumps of
                               ((jt, _):_) | jumpTarget >= jt -> False
                               _ ->
                                 go pos2 newBits 1 ((jumpTarget, newBits) : jumps) False

                   2 ->  -- MATCH
                     let (matchVal, pos2) = decodeMatch pos1 asmap
                     in if matchVal == invalidAsn then False
                        else
                          let matchLen = bitWidth matchVal - 1
                              hadInc   = if prevOpcode /= 2 then False else hadIncompleteMatch
                          in if matchLen < 8 && hadInc then False
                             else if bits < matchLen then False
                             else go pos2 (bits - matchLen) 2 jumps (matchLen < 8)

                   3 ->  -- DEFAULT
                     if prevOpcode == 3 then False  -- two successive DEFAULTs
                     else
                       let (asn, pos2) = decodeASN pos1 asmap
                       in if asn == invalidAsn then False
                          else go pos2 bits 3 jumps False

                   _ -> False  -- decode returned INVALID (EOF in type)

    checkPadding !pos
      | pos == endpos = True
      | otherwise =
          let (bit, pos') = consumeBitLE pos asmap
          in if bit then False else checkPadding pos'

-- | Validate asmap for standard 128-bit (IPv6) inputs.
-- Reference: bitcoin-core/src/util/asmap.cpp CheckStandardAsmap.
checkStandardAsmap :: ByteString -> Bool
checkStandardAsmap asmap = sanityCheckAsmap asmap 128

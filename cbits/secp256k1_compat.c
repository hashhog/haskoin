/*
 * secp256k1 compatibility and utility functions for haskoin.
 *
 * 1. Provides deprecated secp256k1_ec_privkey_* shims for secp256k1-haskell 1.4.6.
 * 2. Provides ecdsa_verify_lax: lax DER parsing + normalization + verification,
 *    matching Bitcoin Core's CPubKey::Verify behavior.
 */

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_recovery.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/* Entropy source for secp256k1_context_randomize (side-channel blinding).
 * Mirrors Core's ECC_Start (src/key.cpp:572-587) which seeds the context with
 * 32 strong-random bytes after every context_create. Per secp256k1.h:286-290
 * this is "highly recommended" to protect scalar multiplications in signing
 * paths from cache-timing / EM / power side-channels. */
#if defined(__linux__)
  #include <sys/random.h>  /* getrandom(2) */
#endif

/* Fill `out` with 32 bytes of strong entropy. Returns 1 on success,
 * 0 on failure. Same pattern as beamchain/c_src/beamchain_crypto_nif.c
 * (commit a41e0bc): prefer getrandom(2) on Linux, fall back to /dev/urandom
 * on EINTR / older kernels / non-Linux. */
static int haskoin_get_entropy_32(unsigned char out[32]) {
#if defined(__linux__)
    ssize_t n = getrandom(out, 32, 0);
    if (n == 32) return 1;
    /* Fall through to /dev/urandom on EINTR / older kernels */
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t got = fread(out, 1, 32, f);
    fclose(f);
    return got == 32 ? 1 : 0;
}

/* Side-channel-blind `ctx` with 32 fresh bytes from haskoin_get_entropy_32.
 * Returns 1 on success, 0 on failure (and the caller should destroy the
 * context and refuse to run, matching Core's assert(ret) posture). */
static int haskoin_randomize_ctx(secp256k1_context *ctx) {
    unsigned char seed32[32];
    if (!haskoin_get_entropy_32(seed32)) {
        return 0;
    }
    int ok = secp256k1_context_randomize(ctx, seed32);
    /* Wipe the seed from the stack ASAP. */
    memset(seed32, 0, sizeof(seed32));
    return ok;
}

/* ---- Deprecated API shims ------------------------------------------------ */

int secp256k1_ec_privkey_negate(
    const secp256k1_context *ctx,
    unsigned char *seckey
) {
    return secp256k1_ec_seckey_negate(ctx, seckey);
}

int secp256k1_ec_privkey_tweak_add(
    const secp256k1_context *ctx,
    unsigned char *seckey,
    const unsigned char *tweak32
) {
    return secp256k1_ec_seckey_tweak_add(ctx, seckey, tweak32);
}

int secp256k1_ec_privkey_tweak_mul(
    const secp256k1_context *ctx,
    unsigned char *seckey,
    const unsigned char *tweak32
) {
    return secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak32);
}

/* ---- Lax DER parsing (from Bitcoin Core's src/pubkey.cpp) ---------------- */

/*
 * This function is adapted from Bitcoin Core's ecdsa_signature_parse_der_lax.
 * It is more permissive than strict DER: tolerates non-minimal length encodings,
 * allows non-minimal padding, doesn't require exact length matches, etc.
 * Returns 1 on success, 0 on failure.
 */
static int ecdsa_signature_parse_der_lax(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *input,
    size_t inputlen
) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a valid empty signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte; /* Just skip the length bytes */
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        /* Overflow check (4 bytes max for length) */
        if (lenbyte >= 4) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= 4) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value, right-aligned in 32 bytes */
    if (rlen > 32) {
        overflow = 1;
    } else if (rlen > 0) {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value, right-aligned in 32 bytes */
    if (slen > 32) {
        overflow = 1;
    } else if (slen > 0) {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
         * signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

/* ---- High-level verify with lax DER -------------------------------------- */

/*
 * Thread-local (or global) context for verification.
 * We lazily create it on first use.
 */
static secp256k1_context *g_verify_ctx = NULL;

static secp256k1_context *get_verify_ctx(void) {
    if (g_verify_ctx == NULL) {
        g_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    }
    return g_verify_ctx;
}

/*
 * Verify an ECDSA signature with lax DER parsing and normalization.
 * Matches Bitcoin Core's CPubKey::Verify behavior:
 * 1. Parse public key
 * 2. Parse signature with lax DER
 * 3. Normalize signature (low-S)
 * 4. Verify
 *
 * Returns 1 on success, 0 on failure.
 */
int haskoin_ecdsa_verify_lax(
    const unsigned char *pubkey_data, size_t pubkey_len,
    const unsigned char *sig_data, size_t sig_len,
    const unsigned char *msghash32
) {
    secp256k1_context *ctx = get_verify_ctx();
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    if (!ctx) return 0;

    /* Parse public key */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_data, pubkey_len)) {
        return 0;
    }

    /* Parse signature with lax DER */
    if (!ecdsa_signature_parse_der_lax(ctx, &sig, sig_data, sig_len)) {
        return 0;
    }

    /* Normalize to low-S form (secp256k1_ecdsa_verify only accepts low-S) */
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    /* Verify */
    return secp256k1_ecdsa_verify(ctx, &sig, msghash32, &pubkey);
}

/* ---- X-only pubkey tweak for Taproot (BIP-341) -------------------------- */

/*
 * Compute tweaked x-only public key for Taproot.
 *
 * Given a 32-byte x-only internal public key and a 32-byte tweak,
 * computes the tweaked public key: output_key = internal_key + tweak * G
 *
 * Returns:
 *   1 on success (output_pubkey32 filled with 32-byte x-only tweaked key,
 *                  output_parity set to 0 or 1)
 *   0 on failure
 */
int haskoin_xonly_pubkey_tweak_add(
    const unsigned char *internal_pubkey32,
    const unsigned char *tweak32,
    unsigned char *output_pubkey32,
    int *output_parity
) {
    secp256k1_context *ctx = get_verify_ctx();
    secp256k1_xonly_pubkey internal_pk;
    secp256k1_pubkey tweaked_pk;
    secp256k1_xonly_pubkey tweaked_xonly;

    if (!ctx) return 0;

    /* W95: defensive NULL guard.  The Haskell wrapper enforces 32-byte
     * lengths and passes pinned pointers, but the C ABI is exposed to
     * any future FFI caller and a NULL deref inside libsecp's strict-arg
     * macros aborts the process. */
    if (!internal_pubkey32 || !tweak32 || !output_pubkey32 || !output_parity) {
        return 0;
    }

    /* Parse the 32-byte x-only internal public key */
    if (!secp256k1_xonly_pubkey_parse(ctx, &internal_pk, internal_pubkey32)) {
        return 0;
    }

    /* Tweak the internal key: tweaked_pk = internal_pk + tweak * G */
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pk, &internal_pk, tweak32)) {
        return 0;
    }

    /* Convert the tweaked full pubkey to x-only and get parity */
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, output_parity, &tweaked_pk)) {
        return 0;
    }

    /* Serialize the x-only tweaked key to 32 bytes */
    if (!secp256k1_xonly_pubkey_serialize(ctx, output_pubkey32, &tweaked_xonly)) {
        return 0;
    }

    return 1;
}

/* ---- BIP-340 Schnorr signature verification ------------------------------ */

/*
 * Verify a 64-byte BIP-340 Schnorr signature.
 *
 * sig64:        64-byte signature
 * msg32:        32-byte message digest (typically the BIP-341 sighash)
 * pubkey_x32:   32-byte x-only public key (for Taproot, the witness program
 *               for key-path or the tweaked output key for tapscript)
 *
 * Returns 1 on valid signature, 0 otherwise.
 */
int haskoin_schnorrsig_verify(
    const unsigned char *sig64,
    const unsigned char *msg32,
    const unsigned char *pubkey_x32
) {
    secp256k1_context *ctx = get_verify_ctx();
    secp256k1_xonly_pubkey xonly;

    if (!ctx) return 0;

    /* W95: defensive NULL guard.  Same rationale as
     * haskoin_xonly_pubkey_tweak_add: the Haskell wrapper enforces
     * 64/32/32-byte lengths and pins the ByteStrings before the FFI
     * crossing, but a future caller via this C ABI gets a clean
     * 0-return on NULL instead of an ARG_CHECK assertion inside libsecp. */
    if (!sig64 || !msg32 || !pubkey_x32) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly, pubkey_x32)) {
        return 0;
    }

    return secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &xonly);
}

/* ---- BIP-324 ElligatorSwift bindings ------------------------------------- */

/*
 * Lazily-allocated context with VERIFY|SIGN flags for ellswift_create
 * (which performs a private-key derivation step internally).  Reused for
 * ellswift_xdh as well, which only needs VERIFY but is fine with both.
 */
static secp256k1_context *g_ellswift_ctx = NULL;

static secp256k1_context *get_ellswift_ctx(void) {
    if (g_ellswift_ctx == NULL) {
        secp256k1_context *ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
        if (!ctx) return NULL;
        /* W159 BUG-3 fix: side-channel-blind the context immediately after
         * creation. ellswift_create derives a private-key value internally
         * (BIP-324 handshake), so the same blinding requirement that applies
         * to g_sign_ctx applies here. Fail-loud (destroy + NULL) rather than
         * silently running unblinded if entropy is unavailable. */
        if (!haskoin_randomize_ctx(ctx)) {
            secp256k1_context_destroy(ctx);
            return NULL;
        }
        g_ellswift_ctx = ctx;
    }
    return g_ellswift_ctx;
}

/*
 * Wrap secp256k1_ellswift_create.  Produces a 64-byte ElligatorSwift-encoded
 * public key from a 32-byte secret key and 32-byte aux randomness.
 * Returns 1 on success, 0 on failure.
 */
int haskoin_ellswift_create(
    const unsigned char *seckey32,
    const unsigned char *auxrnd32,
    unsigned char *ell64
) {
    secp256k1_context *ctx = get_ellswift_ctx();
    if (!ctx) return 0;
    return secp256k1_ellswift_create(ctx, ell64, seckey32, auxrnd32);
}

/*
 * Wrap secp256k1_ellswift_xdh with the BIP-324 hash function.
 * Produces a 32-byte shared secret given our seckey and both ellswift pubkeys.
 *
 * party = 0 if we are the initiator (ell_a = our pubkey, ell_b = peer pubkey)
 * party = 1 if we are the responder (ell_a = peer pubkey, ell_b = our pubkey)
 *
 * Returns 1 on success, 0 on failure.
 */
int haskoin_ellswift_xdh_bip324(
    const unsigned char *ell_a64,
    const unsigned char *ell_b64,
    const unsigned char *seckey32,
    int party,
    unsigned char *output32
) {
    secp256k1_context *ctx = get_ellswift_ctx();
    if (!ctx) return 0;
    return secp256k1_ellswift_xdh(
        ctx,
        output32,
        ell_a64,
        ell_b64,
        seckey32,
        party,
        secp256k1_ellswift_xdh_hash_function_bip324,
        NULL
    );
}

/* ---- ECDSA signing (recoverable + standard) ----------------------------- */

/*
 * Lazily-allocated context with VERIFY|SIGN flags for signing operations.
 */
static secp256k1_context *g_sign_ctx = NULL;

static secp256k1_context *get_sign_ctx(void) {
    if (g_sign_ctx == NULL) {
        secp256k1_context *ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
        if (!ctx) return NULL;
        /* W159 BUG-3 fix: side-channel-blind the context immediately after
         * creation. Per Core src/key.cpp:572-587 and secp256k1.h:286-290,
         * randomizing the sign context with fresh 32-byte entropy is the
         * defence against cache-timing / EM / power side-channels on the
         * scalar-mul step of ECDSA / ellswift sign. Fail-loud rather than
         * silently running unblinded. */
        if (!haskoin_randomize_ctx(ctx)) {
            secp256k1_context_destroy(ctx);
            return NULL;
        }
        g_sign_ctx = ctx;
    }
    return g_sign_ctx;
}

/*
 * Derive the public key for a 32-byte secret key.
 * Writes 33 bytes (compressed) or 65 bytes (uncompressed) to output.
 *
 * Returns 1 on success (output filled, *out_len set), 0 on failure
 * (e.g. invalid seckey).
 */
int haskoin_ec_pubkey_create(
    const unsigned char *seckey32,
    int compressed,
    unsigned char *output,
    size_t *out_len
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_pubkey pubkey;

    if (!ctx) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey32)) {
        return 0;
    }
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED
                                    : SECP256K1_EC_UNCOMPRESSED;
    *out_len = compressed ? 33 : 65;
    return secp256k1_ec_pubkey_serialize(ctx, output, out_len, &pubkey, flags);
}

/*
 * BIP-32 CKDpub: child pubkey = parent_pubkey + tweak*G.
 *
 * Parses a 33-byte compressed parent pubkey, applies the 32-byte scalar
 * tweak via libsecp256k1's `secp256k1_ec_pubkey_tweak_add` (which is
 * exactly the operation Bitcoin Core's `CPubKey::Derive` uses in
 * `bitcoin-core/src/pubkey.cpp:341`), and serializes the result as
 * 33-byte compressed.
 *
 * Returns 1 on success, 0 on failure (invalid parent parse, tweak >=
 * curve order, point-at-infinity result, or any other libsecp failure).
 * The BIP-32 spec instructs the caller to advance the child index and
 * retry on failure.
 */
int haskoin_ec_pubkey_tweak_add(
    const unsigned char *parent_pubkey33,
    const unsigned char *tweak32,
    unsigned char *output33
) {
    secp256k1_context *ctx = get_verify_ctx();
    secp256k1_pubkey pubkey;
    size_t out_len = 33;

    if (!ctx) return 0;
    if (!parent_pubkey33 || !tweak32 || !output33) return 0;

    /* Parse the 33-byte compressed parent pubkey. */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, parent_pubkey33, 33)) {
        return 0;
    }

    /* Apply the scalar tweak: pubkey += tweak*G.
     * Rejects tweak >= curve order and point-at-infinity result. */
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak32)) {
        return 0;
    }

    /* Serialize as 33-byte compressed. */
    if (!secp256k1_ec_pubkey_serialize(ctx, output33, &out_len, &pubkey,
                                        SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    return out_len == 33 ? 1 : 0;
}

/*
 * Produce a Bitcoin "compact recoverable" ECDSA signature, as used by
 * signmessage / verifymessage.  Output buffer must be 65 bytes; the layout
 * is: [header_byte][R(32)][S(32)] where header = 27 + recid + (4 if compressed).
 *
 * Matches Bitcoin Core's CKey::SignCompact (src/key.cpp:250).
 *
 * Returns 1 on success, 0 on failure.
 */
int haskoin_ecdsa_sign_recoverable_compact(
    const unsigned char *seckey32,
    const unsigned char *msghash32,
    int compressed,
    unsigned char *out65
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_ecdsa_recoverable_signature rsig;
    int recid = -1;

    if (!ctx) return 0;

    if (!secp256k1_ecdsa_sign_recoverable(
            ctx, &rsig, msghash32, seckey32,
            secp256k1_nonce_function_rfc6979, NULL)) {
        return 0;
    }

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx, out65 + 1, &recid, &rsig)) {
        return 0;
    }

    if (recid < 0 || recid > 3) {
        return 0;
    }

    out65[0] = (unsigned char)(27 + recid + (compressed ? 4 : 0));
    return 1;
}

/*
 * Recover the public key from a 65-byte compact recoverable ECDSA signature
 * (header byte + 64 byte R||S) and a 32-byte message hash.
 *
 * The caller supplies an output buffer of 33 bytes (compressed) or 65 bytes
 * (uncompressed); compression is selected via the `compressed` flag, which
 * MUST match the encoding implied by the header byte (header & 4).
 *
 * Returns 1 on success (output filled, *out_len set), 0 on failure.
 */
int haskoin_ecdsa_recover_compact(
    const unsigned char *sig65,
    const unsigned char *msghash32,
    int compressed,
    unsigned char *output,
    size_t *out_len
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_ecdsa_recoverable_signature rsig;
    secp256k1_pubkey pubkey;
    unsigned char header = sig65[0];
    int recid;

    if (!ctx) return 0;

    /* Header byte must be in [27..34]. recid = (header - 27) & 3. */
    if (header < 27 || header > 34) return 0;
    recid = (header - 27) & 3;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &rsig, sig65 + 1, recid)) {
        return 0;
    }

    if (!secp256k1_ecdsa_recover(ctx, &pubkey, &rsig, msghash32)) {
        return 0;
    }

    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED
                                    : SECP256K1_EC_UNCOMPRESSED;
    *out_len = compressed ? 33 : 65;
    return secp256k1_ec_pubkey_serialize(ctx, output, out_len, &pubkey, flags);
}

/* ---- Pubkey decompression for ScriptCompression tags 0x04/0x05 ---------- */

/*
 * Recover the full uncompressed (65-byte) form of a compressed public key.
 *
 * Used by Storage.hs `getCompressedScript` to inflate Core's
 * ScriptCompression tags 0x04 / 0x05 (which store only the X coordinate
 * plus the uncompressed-form Y parity) back into a 65-byte P2PK key, so
 * that ancient Satoshi-era P2PK coinbase outputs round-trip correctly out
 * of `loadtxoutset` snapshots.
 *
 * Reference: bitcoin-core/src/compressor.cpp `DecompressScript`, which:
 *   - Builds a 33-byte compressed key as `(0x02 | (tag - 0x02)) + x[32]`.
 *   - Calls `secp256k1_ec_pubkey_parse` on those 33 bytes.
 *   - Calls `secp256k1_ec_pubkey_serialize` with SECP256K1_EC_UNCOMPRESSED
 *     to produce the 65-byte form.
 *
 * Inputs:
 *   compressed33 : 33-byte compressed pubkey (must start with 0x02 or 0x03).
 *   out65        : 65-byte output buffer (will be filled with 0x04 + X + Y).
 *
 * Returns 1 on success, 0 on failure (e.g. X not on the curve).
 */
int haskoin_ec_pubkey_decompress(
    const unsigned char *compressed33,
    unsigned char *out65
) {
    secp256k1_context *ctx = get_verify_ctx();
    secp256k1_pubkey pubkey;
    size_t out_len = 65;

    if (!ctx) return 0;

    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed33, 33)) {
        return 0;
    }

    return secp256k1_ec_pubkey_serialize(
        ctx, out65, &out_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
}

/* ---- ECDSA DER signing (transaction-spend path) ------------------------- */

/*
 * Helper: little-endian 32-bit write into the extra-entropy buffer.  Mirrors
 * Core's WriteLE32 used in CKey::Sign.
 */
static void write_le32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8)  & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

/*
 * Test whether an ECDSA signature has a "low R" value (top bit of R clear).
 * Mirrors Bitcoin Core's SigHasLowR (key.cpp).  Operates on the DER-encoded
 * compact form of the signature.
 */
static int sig_has_low_r(
    const secp256k1_context *ctx,
    const secp256k1_ecdsa_signature *sig
) {
    unsigned char compact[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, compact, sig);
    /* compact layout: [R(32) || S(32)].  R is "low" iff its top bit is 0. */
    return (compact[0] & 0x80) == 0;
}

/*
 * Produce a DER-encoded ECDSA signature with RFC-6979 deterministic-k.
 *
 * This mirrors Bitcoin Core's CKey::Sign (src/key.cpp:209-235):
 *   - RFC-6979 deterministic nonce.
 *   - Optional low-R grind: bump 32-bit LE counter in extra_entropy until
 *     the resulting R has its top bit clear.  When grind=1, this matches
 *     Core's wallet output byte-for-byte.
 *   - Self-verify before returning (defense-in-depth).
 *
 * Inputs:
 *   seckey32   : 32-byte secret key (must be a valid scalar in [1, n-1]).
 *   msghash32  : 32-byte message digest (sighash).
 *   grind      : non-zero to grind for low-R (matches Core's wallet default).
 *   out_buf    : output buffer.  Must be at least 72 bytes (max DER length
 *                for a non-low-R signature; low-R can shrink to ~70-71).
 *   out_len    : in: capacity of out_buf; out: actual DER length written.
 *
 * Returns 1 on success (out_buf filled, *out_len set), 0 on failure
 * (e.g. invalid seckey, self-verify mismatch).
 */
int haskoin_ecdsa_sign_der(
    const unsigned char *seckey32,
    const unsigned char *msghash32,
    int grind,
    unsigned char *out_buf,
    size_t *out_len
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_ecdsa_signature sig;
    unsigned char extra_entropy[32] = {0};
    uint32_t counter = 0;
    int ret;

    if (!ctx) return 0;
    if (!seckey32 || !msghash32 || !out_buf || !out_len) return 0;

    ret = secp256k1_ecdsa_sign(
        ctx, &sig, msghash32, seckey32,
        secp256k1_nonce_function_rfc6979, NULL);
    if (!ret) return 0;

    /* Grind for low R.  Counter starts at 0 and is bumped on each retry,
     * matching key.cpp's increment-then-write order (`++counter`). */
    while (grind && !sig_has_low_r(ctx, &sig)) {
        counter++;
        write_le32(extra_entropy, counter);
        ret = secp256k1_ecdsa_sign(
            ctx, &sig, msghash32, seckey32,
            secp256k1_nonce_function_rfc6979, extra_entropy);
        if (!ret) return 0;
    }

    /* Serialize as DER. */
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, out_buf, out_len, &sig)) {
        return 0;
    }

    /* Self-verify: derive the pubkey we just signed under and check the
     * signature roundtrips.  Catches RAM-corruption / library-mismatch
     * regressions before the bad bytes leak into a tx. */
    {
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, seckey32)) return 0;
        if (!secp256k1_ecdsa_verify(ctx, &sig, msghash32, &pk)) return 0;
    }

    return 1;
}

/* ---- BIP-340 Schnorr signing (Taproot key-path) ------------------------- */

/*
 * Produce a 64-byte BIP-340 Schnorr signature over a 32-byte message digest,
 * matching @KeyPair::SignSchnorr@ in @bitcoin-core/src/key.cpp@ which itself
 * wraps @secp256k1_schnorrsig_sign32@.
 *
 * The signing key is a 32-byte secret scalar; the signing primitive
 * internally lifts it into a @secp256k1_keypair@ via
 * @secp256k1_keypair_create@, which negates the seckey if its associated
 * x-only pubkey has odd y-parity (the BIP-340 sign-side normalization).
 *
 * Inputs:
 *   seckey32   : 32-byte secret key (must be a valid scalar in [1, n-1]).
 *                For Taproot key-path spends this is the *output* (tweaked)
 *                seckey, not the internal key — see @haskoin_taproot_tweak_seckey@.
 *   msg32      : 32-byte message digest (e.g. the BIP-341 sighash).
 *   aux_rand32 : 32-byte aux-randomness, or NULL.  Core's @CreateSchnorrSig@
 *                passes @uint256{}@ (all zeros) for byte-identity with the
 *                wallet's tx-hex output (`bitcoin-core/src/script/sign.cpp:88`).
 *                BIP-340 explicitly permits NULL == all-zeros; libsecp will
 *                substitute zeros internally.  Production callers can pass
 *                fresh randomness for the BIP-340 hardening recommendation.
 *   out_sig64  : 64-byte output buffer.
 *
 * Returns 1 on success (out_sig64 filled), 0 on failure (e.g. invalid seckey).
 *
 * Reference: @bitcoin-core/src/secp256k1/src/modules/schnorrsig/main_impl.h
 * secp256k1_schnorrsig_sign32@.
 */
int haskoin_schnorrsig_sign(
    const unsigned char *seckey32,
    const unsigned char *msg32,
    const unsigned char *aux_rand32,
    unsigned char *out_sig64
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_keypair keypair;

    if (!ctx) return 0;
    if (!seckey32 || !msg32 || !out_sig64) return 0;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }

    /* aux_rand32 == NULL is BIP-340 spec-equivalent to all-zeros, which is
     * exactly what Core's CreateSchnorrSig passes via @uint256{}@. */
    if (!secp256k1_schnorrsig_sign32(ctx, out_sig64, msg32, &keypair, aux_rand32)) {
        return 0;
    }

    return 1;
}

/* ---- BIP-341 key-path Taproot tweak (seckey side) ----------------------- */

/*
 * Apply a precomputed 32-byte BIP-341 tweak to a 32-byte secret key, returning
 * the tweaked seckey suitable for direct use with @haskoin_schnorrsig_sign@.
 *
 * Per @KeyPair::Create@ in @bitcoin-core/src/key.cpp@, the algorithm is:
 *   1. Lift seckey into a keypair (negates seckey internally if its x-only
 *      pubkey has odd y-parity — the BIP-340 sign-side normalization).
 *   2. Apply @secp256k1_keypair_xonly_tweak_add@: keypair' = keypair + t·G
 *      using libsecp's curve operations (handles the tweak-overflow case
 *      and the conditional negation when t·G's parity flips the output).
 *   3. Extract the tweaked seckey via @secp256k1_keypair_sec@.
 *
 * The TapTweak hash itself is computed Haskell-side via 'computeTapTweakHash'
 * in @Crypto.hs@, which calls into the existing 'taggedHash' BIP-340 helper.
 * We do *not* recompute it inside libsecp because the public secp256k1.h
 * headers do not expose @secp256k1_sha256_*@; the BIP-340 tagged-hash
 * primitive is byte-identical regardless of which SHA-256 implementation
 * computes it.
 *
 * Inputs:
 *   seckey32     : 32-byte internal secret key.
 *   tweak32      : 32-byte BIP-341 tweak — typically
 *                    @TaggedHash("TapTweak", P [|| merkle_root])@,
 *                  with @P@ the x-only pubkey of @seckey32@.  For BIP-86
 *                  single-key key-path spends (no script tree), the tweak
 *                  is @TaggedHash("TapTweak", P)@.
 *   out_seckey32 : 32-byte output buffer for the tweaked seckey.
 *
 * Returns 1 on success, 0 on failure (e.g. invalid seckey, tweak >= n).
 */
int haskoin_taproot_tweak_seckey(
    const unsigned char *seckey32,
    const unsigned char *tweak32,
    unsigned char *out_seckey32
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_keypair keypair;

    if (!ctx) return 0;
    if (!seckey32 || !tweak32 || !out_seckey32) return 0;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }

    if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak32)) {
        return 0;
    }

    if (!secp256k1_keypair_sec(ctx, out_seckey32, &keypair)) {
        return 0;
    }

    return 1;
}

/*
 * Convenience: derive the x-only pubkey (32 bytes) of a 32-byte seckey.
 * Wraps @secp256k1_keypair_create@ + @secp256k1_keypair_xonly_pub@ +
 * @secp256k1_xonly_pubkey_serialize@.  This is the @P@ that goes into the
 * TapTweak preimage, taking care of the BIP-340 even-y normalization
 * implicitly via the keypair construction.
 *
 * Returns 1 on success (out_xonly32 filled), 0 on failure.
 */
int haskoin_xonly_pubkey_from_seckey(
    const unsigned char *seckey32,
    unsigned char *out_xonly32
) {
    secp256k1_context *ctx = get_sign_ctx();
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly;

    if (!ctx) return 0;
    if (!seckey32 || !out_xonly32) return 0;

    if (!secp256k1_keypair_create(ctx, &keypair, seckey32)) {
        return 0;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &keypair)) {
        return 0;
    }
    if (!secp256k1_xonly_pubkey_serialize(ctx, out_xonly32, &xonly)) {
        return 0;
    }
    return 1;
}

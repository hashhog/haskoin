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
        g_ellswift_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
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
        g_sign_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
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

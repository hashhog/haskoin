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

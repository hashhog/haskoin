/* format_double.c
 * Exposes C's printf("%.16g") for use from Haskell via FFI.
 * This is needed because Haskell's Text.Printf and Numeric.showFFloat
 * do not match C's %.16g rounding for all doubles (e.g. the showFFloat
 * rounding bug for values near a half-ulp boundary at large magnitude).
 *
 * Used by Bitcoin Core getblockheader difficulty formatting (W57).
 * Reference: bitcoin-core/src/rpc/util.cpp UniValue setFloat,
 *            which ultimately calls std::setprecision(16) << d.
 */
#include <stdio.h>
#include <string.h>

/* Format d with %.16g into buf (must be at least 64 bytes).
 * Returns number of characters written (not including NUL). */
int format_difficulty_g16(double d, char *buf, int buflen) {
    int n = snprintf(buf, (size_t)buflen, "%.16g", d);
    if (n < 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }
    if (n >= buflen) {
        n = buflen - 1;
        buf[n] = '\0';
    }
    return n;
}

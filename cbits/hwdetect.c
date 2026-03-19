/* Hardware SHA-256 acceleration detection via CPUID.
 *
 * Checks for SHA-NI (SHA Extensions) support on x86_64 processors.
 * SHA-NI is indicated by CPUID leaf 7, sub-leaf 0, ECX bit 29 (SHA).
 *
 * Note: The actual bit is EBX bit 29 for SHA on leaf 7.
 * Intel SDM Vol 2A, Table 3-8: EBX bit 29 = SHA.
 */

#ifdef __x86_64__
#include <cpuid.h>

int detect_sha_ni(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        /* SHA extensions: CPUID.(EAX=07H,ECX=0):EBX[bit 29] */
        return (ebx >> 29) & 1;
    }
    return 0;
}

int detect_avx2(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        /* AVX2: CPUID.(EAX=07H,ECX=0):EBX[bit 5] */
        return (ebx >> 5) & 1;
    }
    return 0;
}

#else

int detect_sha_ni(void) { return 0; }
int detect_avx2(void) { return 0; }

#endif

#include "zfex.h"
#include "zfex_pp.h"
#include "zfex_macros.h"
#include "zfex_bytemask.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#if (ZFEX_INTEL_SSSE3_FEATURE == 1)
#pragma message "Using SSSE3-accelerated FEC"
const char* zfex_opt = "SSSE3";
#include <emmintrin.h>
#include <tmmintrin.h>


#elif (ZFEX_ARM_NEON_FEATURE == 1)
#pragma message "Using NEON-accelerated FEC"
const char* zfex_opt = "NEON";
#include <arm_neon.h>

#else
#pragma message "Using non-accelerated FEC"
const char* zfex_opt = "noaccel";
#endif

/*
 * Primitive polynomials - see Lin & Costello, Appendix A,
 * and  Lee & Messerschmitt, p. 453.
 */
static const char*const Pp="101110001";


/*
 * To speed up computations, we have tables for logarithm, exponent and
 * inverse of a number.  We use a table for multiplication as well (it takes
 * 64K, no big deal even on a PDA, especially because it can be
 * pre-initialized an put into a ROM!), otherwhise we use a table of
 * logarithms. In any case the macro gf_mul(x,y) takes care of
 * multiplications.
 */

static gf gf_exp[510];  /* index->poly form conversion table    */
static int gf_log[256]; /* Poly->index form conversion table    */
static gf inverse[256]; /* inverse of field elem.               */
                                /* inv[\alpha**i]=\alpha**(GF_SIZE-i-1) */

/*
 * modnn(x) computes x % GF_SIZE, where GF_SIZE is 2**GF_BITS - 1,
 * without a slow divide.
 */
static gf
modnn(int x) {
    while (x >= 255) {
        x -= 255;
        x = (x >> 8) + (x & 255);
    }
    return x;
}

/*
 * gf_mul(x,y) multiplies two numbers.  It is much faster to use a
 * multiplication table.
 *
 * USE_GF_MULC, GF_MULC0(c) and GF_ADDMULC(x) can be used when multiplying
 * many numbers by the same constant. In this case the first call sets the
 * constant, and others perform the multiplications.  A value related to the
 * multiplication is held in a local variable declared with USE_GF_MULC . See
 * usage in _addmul1().
 */
static
#ifdef _MSC_VER
__declspec (align (ZFEX_SIMD_ALIGNMENT))
#endif
gf gf_mul_table[256][256]
#ifdef __GNUC__
__attribute__ ((aligned (ZFEX_SIMD_ALIGNMENT)))
#endif
;

static
#ifdef _MSC_VER
__declspec (align (ZFEX_SIMD_ALIGNMENT))
#endif
gf gf_mul_table_16[256][16]
#ifdef __GNUC__
__attribute__ ((aligned (ZFEX_SIMD_ALIGNMENT)))
#endif
;

#define gf_mul(x,y) gf_mul_table[x][y]

#define USE_GF_MULC register gf * __gf_mulc_

#define GF_MULC0(c) __gf_mulc_ = gf_mul_table[c]
#define GF_ADDMULC(dst, x) dst ^= __gf_mulc_[x]

/*
 * Generate GF(2**m) from the irreducible polynomial p(X) in p[0]..p[m]
 * Lookup tables:
 *     index->polynomial form		gf_exp[] contains j= \alpha^i;
 *     polynomial form -> index form	gf_log[ j = \alpha^i ] = i
 * \alpha=x is the primitive element of GF(2^m)
 *
 * For efficiency, gf_exp[] has size 2*GF_SIZE, so that a simple
 * multiplication of two numbers can be resolved without calling modnn
 */
static void
_init_mul_table(void) {
  int i, j;
  for (i = 0; i < 256; i++)
      for (j = 0; j < 256; j++)
          gf_mul_table[i][j] = gf_exp[modnn (gf_log[i] + gf_log[j])];

  for (j = 0; j < 256; j++)
      gf_mul_table[0][j] = gf_mul_table[j][0] = 0;

  for (i = 0; i < 256; i++)
      for (j = 0; j < 16; j++)
          gf_mul_table_16[i][j] = gf_mul_table[i][j << 4];
}

#define NEW_GF_MATRIX(rows, cols) \
    (gf*)malloc((size_t)rows * (size_t)cols)

/*
 * initialize the data structures used for computations in GF.
 */
static void
generate_gf (void) {
    int i;
    gf mask;

    mask = 1;                     /* x ** 0 = 1 */
    gf_exp[8] = 0;          /* will be updated at the end of the 1st loop */
    /*
     * first, generate the (polynomial representation of) powers of \alpha,
     * which are stored in gf_exp[i] = \alpha ** i .
     * At the same time build gf_log[gf_exp[i]] = i .
     * The first 8 powers are simply bits shifted to the left.
     */
    for (i = 0; i < 8; i++, mask <<= 1) {
        gf_exp[i] = mask;
        gf_log[gf_exp[i]] = i;
        /*
         * If Pp[i] == 1 then \alpha ** i occurs in poly-repr
         * gf_exp[8] = \alpha ** 8
         */
        if (Pp[i] == '1')
            gf_exp[8] ^= mask;
    }
    /*
     * now gf_exp[8] = \alpha ** 8 is complete, so can also
     * compute its inverse.
     */
    gf_log[gf_exp[8]] = 8;
    /*
     * Poly-repr of \alpha ** (i+1) is given by poly-repr of
     * \alpha ** i shifted left one-bit and accounting for any
     * \alpha ** 8 term that may occur when poly-repr of
     * \alpha ** i is shifted.
     */
    mask = 1 << 7;
    for (i = 9; i < 255; i++) {
        if (gf_exp[i - 1] >= mask)
            gf_exp[i] = gf_exp[8] ^ ((gf_exp[i - 1] ^ mask) << 1);
        else
            gf_exp[i] = gf_exp[i - 1] << 1;
        gf_log[gf_exp[i]] = i;
    }
    /*
     * log(0) is not defined, so use a special value
     */
    gf_log[0] = 255;
    /* set the extended gf_exp values for fast multiply */
    for (i = 0; i < 255; i++)
        gf_exp[i + 255] = gf_exp[i];

    /*
     * again special cases. 0 has no inverse. This used to
     * be initialized to 255, but it should make no difference
     * since noone is supposed to read from here.
     */
    inverse[0] = 0;
    inverse[1] = 1;
    for (i = 2; i <= 255; i++)
        inverse[i] = gf_exp[255 - gf_log[i]];
}

/*
 * Various linear algebra operations that i use often.
 */

#if (ZFEX_ARM_NEON_FEATURE == 1)
static inline
void addmul_neon_kernel(
    uint8_t *dst,
    uint8_t const *src,
    uint8x16_t const vmul_lo,
    uint8x16_t const vmul_hi,
    uint8x16_t const mask_0F)
{
    dst = ZFEX_ASSUME_ALIGNED(dst, ZFEX_SIMD_ALIGNMENT);
    src = ZFEX_ASSUME_ALIGNED(src, ZFEX_SIMD_ALIGNMENT);

    register uint8x16_t q2  = vld1q_u8(src);
    register uint8x16_t q1  = vld1q_u8(dst);

    register uint8x16_t q9  = q2 & mask_0F;
    register uint8x16_t q10  = q2 >> 4;

#ifdef __aarch64__
    q9 = vqtbl1q_u8(vmul_lo, q9);
    q10 = vqtbl1q_u8(vmul_hi, q10);
#else
    __asm__ ("vtbl.8 %e[x], {%q[t]}, %e[x]" : [x]"+w"(q9) : [t]"w"(vmul_lo));
    __asm__ ("vtbl.8 %f[x], {%q[t]}, %f[x]" : [x]"+w"(q9) : [t]"w"(vmul_lo));
    __asm__ ("vtbl.8 %e[x], {%q[t]}, %e[x]" : [x]"+w"(q10) : [t]"w"(vmul_hi));
    __asm__ ("vtbl.8 %f[x], {%q[t]}, %f[x]" : [x]"+w"(q10) : [t]"w"(vmul_hi));
#endif
    vst1q_u8(dst, q1 ^ q9 ^ q10);
}
#endif /* (ZFEX_ARM_NEON_FEATURE == 1) */

#if (ZFEX_INTEL_SSSE3_FEATURE == 1)
static inline
void addmul_ssse3_kernel_aligned(
    uint8_t *dst,
    uint8_t const *src,
    __m128i const vmul_lo,
    __m128i const vmul_hi,
    __v16qu const mask_0F)
{
    dst = ZFEX_ASSUME_ALIGNED(dst, ZFEX_SIMD_ALIGNMENT);
    src = ZFEX_ASSUME_ALIGNED(src, ZFEX_SIMD_ALIGNMENT);

    register __v16qu const vsrc = (__v16qu)_mm_load_si128((__m128i const *)src);
    register __v16qu const vsrc_lo = vsrc & mask_0F;
    register __v16qu const vsrc_hi = (__v16qu)((__v8hu)vsrc >> 4) & mask_0F;

    register __m128i const to_xor = _mm_shuffle_epi8(vmul_lo, (__m128i)vsrc_lo) ^ _mm_shuffle_epi8(vmul_hi, (__m128i)vsrc_hi);

    _mm_store_si128((__m128i *)dst, to_xor ^ _mm_load_si128((__m128i const *)dst));
}


static inline
void addmul_ssse3_kernel_unaligned(
    uint8_t *dst,
    uint8_t const *src,
    __m128i const vmul_lo,
    __m128i const vmul_hi,
    __v16qu const mask_0F)
{
    register __v16qu const vsrc = (__v16qu)_mm_lddqu_si128((__m128i const *)src);
    register __v16qu const vsrc_lo = vsrc & mask_0F;
    register __v16qu const vsrc_hi = (__v16qu)((__v8hu)vsrc >> 4) & mask_0F;

    register __m128i const to_xor = _mm_shuffle_epi8(vmul_lo, (__m128i)vsrc_lo) ^ _mm_shuffle_epi8(vmul_hi, (__m128i)vsrc_hi);

    _mm_storeu_si128((__m128i *)dst, to_xor ^ _mm_lddqu_si128((__m128i const *)dst));
}
#endif /* (ZFEX_INTEL_SSSE3_FEATURE == 1) */


/*
 * addmul() computes dst[] = dst[] + c * src[]
 * This is used often, so better optimize it! Currently the loop is
 * unrolled 16 times, a good value for 486 and pentium-class machines.
 * The case c=0 is also optimized, whereas c=1 is not. These
 * calls are unfrequent in my typical apps so I did not bother.
 */
#define addmul(dst, src, c, sz)                 \
    if (c != 0) _addmul1(dst, src, c, sz)

static
#if (ZFEX_INLINE_ADDMUL_FEATURE == 1)
inline
#endif /* ZFEX_INLINE_ADDMUL_FEATURE */
void _addmul1(register gf* ZFEX_RESTRICT dst, register const gf* ZFEX_RESTRICT src, gf c, size_t sz)
{
    // Don't use SSE for unaligned data (for matrix inversion)
    // It will be more slow than non-optimized version

#if 0  //(ZFEX_INTEL_SSSE3_FEATURE == 1)
    enum { ZFEX_UNROLL_ADDMUL_UNIT = sizeof (__m128i) };
    enum { ZFEX_UNROLL_ADDMUL_TILE_1 = ZFEX_UNROLL_ADDMUL_UNIT };
    enum { ZFEX_UNROLL_ADDMUL_TILE = ZFEX_UNROLL_ADDMUL_UNIT * (ZFEX_UNROLL_ADDMUL_SIMD) };

    const gf* lim = &dst[sz];

    register __m128i const vmul_lo = _mm_load_si128((__m128i const *)gf_mul_table[c]);
    register __m128i const vmul_hi = _mm_load_si128((__m128i const *)gf_mul_table_16[c]);

    register __v16qu const mask0F = (__v16qu)_mm_set1_epi8(0x0F);

#if (ZFEX_UNROLL_ADDMUL_SIMD > 1)
    lim -= ZFEX_UNROLL_ADDMUL_TILE - 1;
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE, src += ZFEX_UNROLL_ADDMUL_TILE)
    {
#define KERNEL(i) addmul_ssse3_kernel_unaligned(dst + i * ZFEX_UNROLL_ADDMUL_UNIT, src + i * ZFEX_UNROLL_ADDMUL_UNIT, vmul_lo, vmul_hi, mask0F);
        PP_REPEAT(ZFEX_UNROLL_ADDMUL_SIMD, KERNEL)
#undef KERNEL
    }
    lim += ZFEX_UNROLL_ADDMUL_TILE - 1;
#endif /* (ZFEX_UNROLL_ADDMUL_SIMD > 1) */

    lim -= ZFEX_UNROLL_ADDMUL_TILE_1 - 1;
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE_1, src += ZFEX_UNROLL_ADDMUL_TILE_1)
    {
        addmul_ssse3_kernel_unaligned(dst, src, vmul_lo, vmul_hi, mask0F);
    }
    lim += ZFEX_UNROLL_ADDMUL_TILE_1 - 1;

    if (dst < lim)
    {
        register __v16qu const vsrc = (__v16qu)_mm_lddqu_si128((__m128i const *)src);
        register __v16qu const vsrc_lo = vsrc & mask0F;
        register __v16qu const vsrc_hi = (__v16qu)((__v8hu)vsrc >> 4) & mask0F;

        register __m128i const tail_mask = mask_to_u128_SSSE3(0xFFFF >> (16 - (lim - dst)));

        register __m128i const to_xor = (_mm_shuffle_epi8(vmul_lo, (__m128i)vsrc_lo) ^ _mm_shuffle_epi8(vmul_hi, (__m128i)vsrc_hi));

        _mm_maskmoveu_si128(to_xor ^ _mm_lddqu_si128((__m128i const *)dst), tail_mask, (char *)dst);
    }

#else /* not ZFEX_INTEL_SSSE3_FEATURE */
    enum { ZFEX_UNROLL_ADDMUL_UNIT = 1 };
    enum { ZFEX_UNROLL_ADDMUL_TILE = ZFEX_UNROLL_ADDMUL_UNIT * (ZFEX_UNROLL_ADDMUL) };

    USE_GF_MULC;
    const gf* lim = &dst[sz - ZFEX_UNROLL_ADDMUL_TILE + 1];

    GF_MULC0 (c);

#if (ZFEX_UNROLL_ADDMUL > 1)
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE, src += ZFEX_UNROLL_ADDMUL_TILE)
    {
#define KERNEL(i) GF_ADDMULC (dst[i], src[i]);
        PP_REPEAT(ZFEX_UNROLL_ADDMUL, KERNEL)
#undef KERNEL
    }
#endif

    lim += ZFEX_UNROLL_ADDMUL_TILE - 1;
    for (; dst < lim; dst++, src++)       /* final components */
    {
        GF_ADDMULC (*dst, *src);
    }
#endif
}


#define addmul_simd(dst, src, c, sz)                 \
    if (c != 0) _addmul1_simd(dst, src, c, sz)

static
#if (ZFEX_INLINE_ADDMUL_SIMD_FEATURE == 1)
inline
#endif /* ZFEX_INLINE_ADDMUL_SIMD_FEATURE */
void _addmul1_simd(register gf * ZFEX_RESTRICT dst, register const gf * ZFEX_RESTRICT src, gf c, size_t sz)
{
    dst = ZFEX_ASSUME_ALIGNED(dst, ZFEX_SIMD_ALIGNMENT);
    src = ZFEX_ASSUME_ALIGNED(src, ZFEX_SIMD_ALIGNMENT);

#if (ZFEX_INTEL_SSSE3_FEATURE == 1)
    enum { ZFEX_UNROLL_ADDMUL_UNIT = sizeof (__m128i) };
    enum { ZFEX_UNROLL_ADDMUL_TILE_1 = ZFEX_UNROLL_ADDMUL_UNIT };
    enum { ZFEX_UNROLL_ADDMUL_TILE = ZFEX_UNROLL_ADDMUL_UNIT * (ZFEX_UNROLL_ADDMUL_SIMD) };

    const gf* lim = &dst[sz];

    register __m128i const vmul_lo = _mm_load_si128((__m128i const *)gf_mul_table[c]);
    register __m128i const vmul_hi = _mm_load_si128((__m128i const *)gf_mul_table_16[c]);

    register __v16qu const mask0F = (__v16qu)_mm_set1_epi8(0x0F);

#if (ZFEX_UNROLL_ADDMUL_SIMD > 1)
    lim -= ZFEX_UNROLL_ADDMUL_TILE - 1;
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE, src += ZFEX_UNROLL_ADDMUL_TILE)
    {
#define KERNEL(i) addmul_ssse3_kernel_aligned(dst + i * ZFEX_UNROLL_ADDMUL_UNIT, src + i * ZFEX_UNROLL_ADDMUL_UNIT, vmul_lo, vmul_hi, mask0F);
        PP_REPEAT(ZFEX_UNROLL_ADDMUL_SIMD, KERNEL)
#undef KERNEL
    }
    lim += ZFEX_UNROLL_ADDMUL_TILE - 1;
#endif /* (ZFEX_UNROLL_ADDMUL_SIMD > 1) */

    lim -= ZFEX_UNROLL_ADDMUL_TILE_1 - 1;
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE_1, src += ZFEX_UNROLL_ADDMUL_TILE_1)
    {
        addmul_ssse3_kernel_aligned(dst, src, vmul_lo, vmul_hi, mask0F);
    }
    lim += ZFEX_UNROLL_ADDMUL_TILE_1 - 1;

    if (dst < lim)
    {
        register __v16qu const vsrc = (__v16qu)_mm_load_si128((__m128i const *)src);
        register __v16qu const vsrc_lo = vsrc & mask0F;
        register __v16qu const vsrc_hi = (__v16qu)((__v8hu)vsrc >> 4) & mask0F;

        register __m128i const tail_mask = mask_to_u128_SSSE3(0xFFFF >> (16 - (lim - dst)));

        register __m128i const to_xor = (_mm_shuffle_epi8(vmul_lo, (__m128i)vsrc_lo) ^ _mm_shuffle_epi8(vmul_hi, (__m128i)vsrc_hi));

        _mm_maskmoveu_si128(to_xor ^ _mm_load_si128((__m128i const *)dst), tail_mask, (char *)dst);
    }

#elif (ZFEX_ARM_NEON_FEATURE == 1)
    enum { ZFEX_UNROLL_ADDMUL_UNIT = sizeof (uint8x16_t) };
    enum { ZFEX_UNROLL_ADDMUL_TILE_1 = ZFEX_UNROLL_ADDMUL_UNIT };
    enum { ZFEX_UNROLL_ADDMUL_TILE = ZFEX_UNROLL_ADDMUL_UNIT * (ZFEX_UNROLL_ADDMUL_SIMD) };

    const gf* lim = &dst[sz];

    register uint8x16_t q0  = {0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F};
    register uint8x16_t q3  = vld1q_u8(gf_mul_table[c]);
    register uint8x16_t q8  = vld1q_u8(gf_mul_table_16[c]);

#if (ZFEX_UNROLL_ADDMUL_SIMD > 1)
    lim -= ZFEX_UNROLL_ADDMUL_TILE - 1;
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE, src += ZFEX_UNROLL_ADDMUL_TILE)
    {
#define KERNEL(i) addmul_neon_kernel(dst + i * ZFEX_UNROLL_ADDMUL_UNIT, src + i * ZFEX_UNROLL_ADDMUL_UNIT, q3, q8, q0);
        PP_REPEAT(ZFEX_UNROLL_ADDMUL_SIMD, KERNEL)
#undef KERNEL
    }
    lim += ZFEX_UNROLL_ADDMUL_TILE - 1;
#endif /* (ZFEX_UNROLL_ADDMUL_SIMD > 1) */

    lim -= ZFEX_UNROLL_ADDMUL_TILE_1 - 1;
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE_1, src += ZFEX_UNROLL_ADDMUL_TILE_1)
    {
        addmul_neon_kernel(dst, src, q3, q8, q0);
    }
    lim += ZFEX_UNROLL_ADDMUL_TILE_1 - 1;

    if (dst < lim)
    {
        register uint8x16_t q2 = vld1q_u8(src);
        register uint8x16_t q1 = vld1q_u8(dst);

        register uint8x16_t q9 = q2 & q0;
        register uint8x16_t q10 = q2 >> 4;

#ifdef __aarch64__
        q9  = vqtbl1q_u8(q3, q9);
        q10 = vqtbl1q_u8(q8, q10);
#else
        __asm__ ("vtbl.8 %e[x], {%q[t]}, %e[x]" : [x]"+w"(q9) : [t]"w"(q3));
        __asm__ ("vtbl.8 %f[x], {%q[t]}, %f[x]" : [x]"+w"(q9) : [t]"w"(q3));
        __asm__ ("vtbl.8 %e[x], {%q[t]}, %e[x]" : [x]"+w"(q10) : [t]"w"(q8));
        __asm__ ("vtbl.8 %f[x], {%q[t]}, %f[x]" : [x]"+w"(q10) : [t]"w"(q8));
#endif

#if (ZFEX_IS_LITTLE_ENDIAN == 1)
        uint16_t const bitmask = 0xFFFF >> (16 - (lim - dst));
        register uint8x16_t const tail_mask = mask_to_u128_NEON(bitmask);
#else
        /*
         * On big endian ARM we need to take care of two things:
         * 1. Loads with vld1q are always executed into a pair of dN registers.
         *    Their order is always the same and endianness only matters within
         *    each of them. As a result, we need to swap higher and lower part
         *    of the mask (since the bitmask is 16-bit byteswap is needed).
         * 2. Endianness means that to generate the mask we need to shift in
         *    the opposite direction.
         * TODO: at some point it would be interesting checking how does simple
         * LUT would perform to get the bytemask we need.
         */
        uint16_t const bitmask = 0xFFFF << (16 - (lim - dst));
        register uint8x16_t const tail_mask = mask_to_u128_NEON(
            (bitmask << 8) | (bitmask >> 8)
        );
#endif
        vst1q_u8(dst, q1 ^ ((q9 ^ q10) & tail_mask));
    }

#else /* not ZFEX_INTEL_SSSE3_FEATURE && not ZFEX_ARM_NEON_FEATURE */
    enum { ZFEX_UNROLL_ADDMUL_UNIT = 1 };
    enum { ZFEX_UNROLL_ADDMUL_TILE = ZFEX_UNROLL_ADDMUL_UNIT * (ZFEX_UNROLL_ADDMUL) };

    USE_GF_MULC;
    const gf* lim = &dst[sz - ZFEX_UNROLL_ADDMUL_TILE + 1];

    GF_MULC0 (c);

#if (ZFEX_UNROLL_ADDMUL > 1)
    for (; dst < lim; dst += ZFEX_UNROLL_ADDMUL_TILE, src += ZFEX_UNROLL_ADDMUL_TILE)
    {
#define KERNEL(i) GF_ADDMULC (dst[i], src[i]);
        PP_REPEAT(ZFEX_UNROLL_ADDMUL, KERNEL)
#undef KERNEL
    }
#endif

    lim += ZFEX_UNROLL_ADDMUL_TILE - 1;
    for (; dst < lim; dst++, src++)       /* final components */
    {
        GF_ADDMULC (*dst, *src);
    }
#endif
}

/*
 * computes C = AB where A is n*k, B is k*m, C is n*m
 */
static void
_matmul(gf * a, gf * b, gf * c, unsigned n, unsigned k, unsigned m) {
    unsigned row, col, i;

    for (row = 0; row < n; row++) {
        for (col = 0; col < m; col++) {
            gf *pa = &a[row * k];
            gf *pb = &b[col];
            gf acc = 0;
            for (i = 0; i < k; i++, pa++, pb += m)
                acc ^= gf_mul (*pa, *pb);
            c[row * m + col] = acc;
        }
    }
}

/*
 * _invert_mat() takes a matrix and produces its inverse
 * k is the size of the matrix.
 * (Gauss-Jordan, adapted from Numerical Recipes in C)
 * Return non-zero if singular.
 */
static void
_invert_mat(gf* src, size_t k)
{
#define SWAP(a, b, Tp) {Tp t = a; a = b; b = t;}

    gf c;
    size_t irow = 0;
    size_t icol = 0;
    size_t row, col, i, ix;

    unsigned* indxc = (unsigned*) malloc (k * sizeof(unsigned));
    unsigned* indxr = (unsigned*) malloc (k * sizeof(unsigned));
    unsigned* ipiv = (unsigned*) malloc (k * sizeof(unsigned));
    gf *id_row = NEW_GF_MATRIX (1, k);

    memset (id_row, '\0', k * sizeof (gf));
    /*
     * ipiv marks elements already used as pivots.
     */
    for (i = 0; i < k; i++)
        ipiv[i] = 0;

    for (col = 0; col < k; col++) {
        gf *pivot_row;
        /*
         * Zeroing column 'col', look for a non-zero element.
         * First try on the diagonal, if it fails, look elsewhere.
         */
        if (ipiv[col] != 1 && src[col * k + col] != 0) {
            irow = col;
            icol = col;
            goto found_piv;
        }
        for (row = 0; row < k; row++) {
            if (ipiv[row] != 1) {
                for (ix = 0; ix < k; ix++) {
                    if (ipiv[ix] == 0) {
                        if (src[row * k + ix] != 0) {
                            irow = row;
                            icol = ix;
                            goto found_piv;
                        }
                    } else
                        assert (ipiv[ix] <= 1);
                }
            }
        }
      found_piv:
        ++(ipiv[icol]);
        /*
         * swap rows irow and icol, so afterwards the diagonal
         * element will be correct. Rarely done, not worth
         * optimizing.
         */
        if (irow != icol)
            for (ix = 0; ix < k; ix++)
                SWAP (src[irow * k + ix], src[icol * k + ix], gf);
        indxr[col] = irow;
        indxc[col] = icol;
        pivot_row = &src[icol * k];
        c = pivot_row[icol];
        assert (c != 0);
        if (c != 1) {                       /* otherwhise this is a NOP */
            /*
             * this is done often , but optimizing is not so
             * fruitful, at least in the obvious ways (unrolling)
             */
            c = inverse[c];
            pivot_row[icol] = 1;
            for (ix = 0; ix < k; ix++)
                pivot_row[ix] = gf_mul (c, pivot_row[ix]);
        }
        /*
         * from all rows, remove multiples of the selected row
         * to zero the relevant entry (in fact, the entry is not zero
         * because we know it must be zero).
         * (Here, if we know that the pivot_row is the identity,
         * we can optimize the addmul).
         */
        id_row[icol] = 1;
        if (memcmp (pivot_row, id_row, k * sizeof (gf)) != 0) {
            gf *p = src;
            for (ix = 0; ix < k; ix++, p += k) {
                if (ix != icol) {
                    c = p[icol];
                    p[icol] = 0;
                    addmul (p, pivot_row, c, k);
                }
            }
        }
        id_row[icol] = 0;
    }                           /* done all columns */
    for (col = k; col > 0; col--)
        if (indxr[col-1] != indxc[col-1])
            for (row = 0; row < k; row++)
                SWAP (src[row * k + indxr[col-1]], src[row * k + indxc[col-1]], gf);
    free(indxc);
    free(indxr);
    free(ipiv);
    free(id_row);
#undef SWAP
}

/*
 * fast code for inverting a vandermonde matrix.
 *
 * NOTE: It assumes that the matrix is not singular and _IS_ a vandermonde
 * matrix. Only uses the second column of the matrix, containing the p_i's.
 *
 * Algorithm borrowed from "Numerical recipes in C" -- sec.2.8, but largely
 * revised for my purposes.
 * p = coefficients of the matrix (p_i)
 * q = values of the polynomial (known)
 */
static void
_invert_vdm (gf* src, unsigned k) {
    unsigned i, j, row, col;
    gf *b, *c, *p;

    if (k == 1)                   /* degenerate case, matrix must be p^0 = 1 */
        return;
    /*
     * c holds the coefficient of P(x) = Prod (x - p_i), i=0..k-1
     * b holds the coefficient for the matrix inversion
     */
    c = NEW_GF_MATRIX (1, k);
    b = NEW_GF_MATRIX (1, k);

    p = NEW_GF_MATRIX (1, k);

    for (j = 1, i = 0; i < k; i++, j += k) {
        c[i] = 0;
        p[i] = src[j];            /* p[i] */
    }
    /*
     * construct coeffs. recursively. We know c[k] = 1 (implicit)
     * and start P_0 = x - p_0, then at each stage multiply by
     * x - p_i generating P_i = x P_{i-1} - p_i P_{i-1}
     * After k steps we are done.
     */
    c[k - 1] = p[0];              /* really -p(0), but x = -x in GF(2^m) */
    for (i = 1; i < k; i++) {
        gf p_i = p[i];            /* see above comment */
        for (j = k - 1 - (i - 1); j < k - 1; j++)
            c[j] ^= gf_mul (p_i, c[j + 1]);
        c[k - 1] ^= p_i;
    }

    for (row = 0; row < k; row++) {
        /*
         * synthetic division etc.
         */
        gf xx = p[row];
        gf t = 1;
        b[k - 1] = 1;             /* this is in fact c[k] */
        for (i = k - 1; i > 0; i--) {
            b[i-1] = c[i] ^ gf_mul (xx, b[i]);
            t = gf_mul (xx, t) ^ b[i-1];
        }
        for (col = 0; col < k; col++)
            src[col * k + row] = gf_mul (inverse[t], b[col]);
    }
    free (c);
    free (b);
    free (p);
    return;
}

static int fec_initialized = 0;
static void
init_fec (void) {
    generate_gf();
    _init_mul_table();
    fec_initialized = 1;
}

/*
 * This section contains the proper FEC encoding/decoding routines.
 * The encoding matrix is computed starting with a Vandermonde matrix,
 * and then transforming it into a systematic matrix.
 */


zfex_status_code_t
fec_free (fec_t *p)
{
    assert (p != NULL);
    free (p->enc_matrix);
    free (p);

    return ZFEX_SC_OK;
}

zfex_status_code_t
fec_new(uint16_t k, uint16_t n, fec_t **out_fec_pp)
{
    if (out_fec_pp == NULL)
    {
        return ZFEX_SC_NULL_POINTER_INPUT;
    }

    unsigned row, col;
    gf *p, *tmp_m;

    fec_t *retval;

    assert(k >= 1);
    assert(n >= 1);
    assert(n < 256);
    assert(k <= n);

    if (fec_initialized == 0)
        init_fec ();

    retval = (fec_t *) malloc (sizeof (fec_t));
    retval->k = k;
    retval->n = n;
    retval->enc_matrix = NEW_GF_MATRIX (n, k);
    tmp_m = NEW_GF_MATRIX (n, k);
    /*
     * fill the matrix with powers of field elements, starting from 0.
     * The first row is special, cannot be computed with exp. table.
     */
    tmp_m[0] = 1;
    for (col = 1; col < k; col++)
        tmp_m[col] = 0;
    for (p = tmp_m + k, row = 0; row + 1 < n; row++, p += k)
        for (col = 0; col < k; col++)
            p[col] = gf_exp[modnn (row * col)];

    /*
     * quick code to build systematic matrix: invert the top
     * k*k vandermonde matrix, multiply right the bottom n-k rows
     * by the inverse, and construct the identity matrix at the top.
     */
    _invert_vdm (tmp_m, k);        /* much faster than _invert_mat */
    _matmul(tmp_m + k * k, tmp_m, retval->enc_matrix + k * k, n - k, k, k);
    /*
     * the upper matrix is I so do not bother with a slow multiply
     */
    memset (retval->enc_matrix, '\0',(size_t)k * (size_t)k * sizeof(gf));

    for (p = retval->enc_matrix, col = 0; col < k; col++, p += k + 1)
    {
        *p = 1;
    }

    free (tmp_m);
    *out_fec_pp = retval;

    return ZFEX_SC_OK;
}

zfex_status_code_t fec_encode_simd(
    fec_t const *code,
    gf const * ZFEX_RESTRICT const * ZFEX_RESTRICT const inpkts,
    gf * ZFEX_RESTRICT const * ZFEX_RESTRICT const fecs,
    size_t const sz)
{

    /* Verify input blocks addresses */
    for (size_t ix = 0; ix < code->k; ++ix)
    {
        if (((uintptr_t)inpkts[ix] % ZFEX_SIMD_ALIGNMENT) != 0)
        {
            return ZFEX_SC_BAD_INPUT_BLOCK_ALIGNMENT;
        }
    }

    /* Verify output blocks addresses */
    for (size_t ix = 0; ix < (code->n - code->k); ++ix)
    {
        if (((uintptr_t)fecs[ix] % ZFEX_SIMD_ALIGNMENT) != 0)
        {
            return ZFEX_SC_BAD_OUTPUT_BLOCK_ALIGNMENT;
        }
    }

    for (size_t k = 0; k < sz; k += ZFEX_STRIDE)
    {
        size_t const stride = ((sz - k) < ZFEX_STRIDE) ? (sz - k) : ZFEX_STRIDE;

        for (unsigned int i = 0; i < (code->n - code->k); ++i)
        {
            unsigned int fecnum = i + code->k;
            memset(fecs[i] + k, 0, stride);

            gf const *p = &(code->enc_matrix[fecnum * code->k]);

            for (unsigned int j = 0; j < code->k; ++j)
            {
                addmul_simd(fecs[i] + k, inpkts[j] + k, p[j], stride);
            }
        }
    }

    return ZFEX_SC_OK;
}

static zfex_status_code_t
shuffle(gf const **pkt, unsigned int *index, unsigned int k)
{
    unsigned int i = 0;

    for (i = 0; i < k; /* nop */)
    {
        if ((index[i] >= k) || (index[i] == i))
        {
            ++i;
        }
        else
        {
            /*
             * put pkt in the right position (first check for conflicts).
             */
            unsigned int const c = index[i];

            if (index[c] == c)
            {
                return ZFEX_SC_DECODE_INVALID_BLOCK_INDEX;
            }
#define SWAP(a, b, Tp) {Tp t = a; a = b; b = t;}
            SWAP(index[i], index[c], unsigned int);
            SWAP(pkt[i], pkt[c], gf const *);
#undef SWAP
        }
    }
    return ZFEX_SC_OK;
}

/**
 * Build decode matrix into some memory space.
 *
 * @param matrix a space allocated for a k by k matrix
 */
void
build_decode_matrix_into_space(const fec_t* ZFEX_RESTRICT const code, const unsigned*const ZFEX_RESTRICT index, const uint16_t k, gf* ZFEX_RESTRICT const matrix)
{
    gf* p = matrix;
    for (uint16_t i=0; i < k; i++, p += k)
    {
        if (index[i] < k) {
            memset(p, 0, k);
            p[i] = 1;
        } else {
            memcpy(p, &(code->enc_matrix[index[i] * code->k]), k);
        }
    }
    _invert_mat (matrix, k);
}


zfex_status_code_t
fec_decode_simd(
    fec_t const *code,
    gf const **inpkts,
    gf * const *outpkts,
    unsigned int *index,
    size_t const sz)
{
    gf *m_dec = (gf *)alloca((size_t)code->k * (size_t)code->k);
    uint16_t outix = 0;

    zfex_status_code_t const shuffle_sc = shuffle(inpkts, index, code->k);
    if (shuffle_sc != ZFEX_SC_OK)
    {
        return shuffle_sc;
    }

    build_decode_matrix_into_space(code, index, code->k, m_dec);

    /* Verify input blocks addresses */
    for (uint16_t col = 0; col < code->k; ++col)
    {
        if (((uintptr_t)inpkts[col] % ZFEX_SIMD_ALIGNMENT) != 0)
        {
            return ZFEX_SC_BAD_INPUT_BLOCK_ALIGNMENT;
        }
    }

    for (uint16_t row = 0; row < code->k; ++row)
    {
        assert((index[row] >= code->k) || (index[row] == row)); /* If the block whose number is i is present, then it is required to be in the i'th element. */

        if (index[row] >= code->k)
        {
            if (((uintptr_t)outpkts[outix] % ZFEX_SIMD_ALIGNMENT) != 0)
            {
                return ZFEX_SC_BAD_OUTPUT_BLOCK_ALIGNMENT;
            }

            memset(outpkts[outix], 0, sz);
            for (uint16_t col = 0; col < code->k; ++col)
            {
                addmul_simd(outpkts[outix], inpkts[col], m_dec[row * code->k + col], sz);
            }
            ++outix;
        }
    }

    return ZFEX_SC_OK;
}

/**
 * zfex -- fast forward error correction library with Python interface
 *
 * Copyright (C) 2007-2010 Zooko Wilcox-O'Hearn
 * Author: Zooko Wilcox-O'Hearn
 * Copyright (C) 2022 Wojciech Migda
 *
 * This file is part of zfex.
 *
 * See README.rst for licensing information.
 *
 * Modifications by Wojciech Migda (see commits in
 * github.com/WojciechMigda/zfex repository for their scope).
 * Modifications (C) 2022 Wojciech Migda (github.com/WojciechMigda)
 */

/*
 * This work is derived from the "fec" software by Luigi Rizzo, et al., the
 * copyright notice and licence terms of which are included below for reference.
 * fec.c -- forward error correction based on Vandermonde matrices 980624 (C)
 * 1997-98 Luigi Rizzo (luigi@iet.unipi.it)
 *
 * Portions derived from code by Phil Karn (karn@ka9q.ampr.org),
 * Robert Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari
 * Thirumoorthy (harit@spectra.eng.hawaii.edu), Aug 1995
 *
 * Modifications by Dan Rubenstein (see Modifications.txt for
 * their description.
 * Modifications (C) 1998 Dan Rubenstein (drubenst@cs.umass.edu)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

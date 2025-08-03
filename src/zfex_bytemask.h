#ifndef __ZFEX_BYTEMASK_H
#define __ZFEX_BYTEMASK_H

/**
 * zfex -- fast forward error correction library with Python interface
 *
 * Copyright (C) 2022 Wojciech Migda
 *
 * This file is part of zfex.
 *
 * See README.rst for licensing information.
 */

#include "zfex_macros.h"

#include <stdint.h>

#if (ZFEX_INTEL_SSSE3_FEATURE == 1)
#include <emmintrin.h>
#include <tmmintrin.h>
#endif /* ZFEX_INTEL_SSSE3_FEATURE == 1 */

#if (ZFEX_ARM_NEON_FEATURE == 1)
#include <arm_neon.h>
#endif /* ZFEX_ARM_NEON_FEATURE */


#ifdef __cplusplus
extern "C"
{
#endif


#if (ZFEX_INTEL_SSSE3_FEATURE == 1)
/*
 * Convert 16-bit mask into __v16qu, in which each bit of the
 * mask [0, 1] is converted into [0, FF] byte.
 * Author: Peter Cordes, https://stackoverflow.com/a/67203617/2003487
 */
static inline
__m128i mask_to_u128_SSSE3(uint16_t const bitmap)
{
    register __m128i const shuffle = _mm_setr_epi32(0, 0, 0x01010101, 0x01010101);
    register __m128i v = _mm_shuffle_epi8(_mm_cvtsi32_si128(bitmap), shuffle);

    register __m128i const bitselect = _mm_setr_epi8(
        1, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1U << 7,
        1, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1U << 7);
    v = _mm_and_si128(v, bitselect);
    v = _mm_cmpeq_epi8(v, bitselect);

    return v;
}
#endif /* ZFEX_INTEL_SSSE3_FEATURE == 1 */


#if (ZFEX_ARM_NEON_FEATURE == 1)
/*
 * Convert 16-bit mask into uint8x16_t, in which each bit of the
 * mask [0, 1] is converted into [0, FF] byte.
 * Based on: Peter Cordes, https://stackoverflow.com/a/67203617/2003487
 */
static inline
uint8x16_t mask_to_u128_NEON(uint16_t const bitmap)
{
    register uint8x16_t const shuffle = (uint8x16_t)(uint64x2_t){0, 0x0101010101010101};
    register uint8x16_t const vbitmap = (uint8x16_t)(uint16x8_t){bitmap, 0, 0, 0, 0, 0, 0, 0};
    register uint8x16_t v;

    __asm__ ("vtbl.8 %e[out], {%q[t]}, %e[x]" : [out]"=w"(v) : [x]"w"(shuffle), [t]"w"(vbitmap));
    __asm__ ("vtbl.8 %f[out], {%q[t]}, %f[x]" : [out]"+w"(v) : [x]"w"(shuffle), [t]"w"(vbitmap));

    register uint8x16_t const bitselect = {
        1, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1U << 7,
        1, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1U << 7};

    v &= bitselect;
    v = vceqq_u8(v, bitselect);

    return v;
}
#endif /* ZFEX_ARM_NEON_FEATURE == 1 */


#ifdef __cplusplus
}
#endif


#endif /* __ZFEX_BYTEMASK_H */

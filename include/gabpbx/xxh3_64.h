/*
 * xxh3_64.h - explicit, self-contained XXH3 64-bit hash (single-shot, scalar).
 *
 * Extracted verbatim from xxHash 0.8.3 (https://github.com/Cyan4973/xxHash),
 * keeping ONLY the XXH3 64-bit one-shot scalar path used by GABpbx's string hash.
 * The other variants (XXH32/XXH64/XXH128, streaming, SIMD dispatch) are intentionally
 * omitted. Algorithm and constants are byte-for-byte identical to upstream and are
 * guarded by a reproducible byte-exact comparison test against the official header.
 *
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2012-2023 Yann Collet
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice, this
 *     list of conditions and the following disclaimer in the documentation and/or
 *     other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" ...
 */
#ifndef GABPBX_XXH3_64_H
#define GABPBX_XXH3_64_H

#include <stdint.h>
#include <string.h>

typedef uint8_t  xxh_u8;
typedef uint32_t xxh_u32;
typedef uint64_t xxh_u64;
typedef struct { xxh_u64 low64; xxh_u64 high64; } XXH128_hash_t;

/* Macros to keep the small routines inlined (no call jumps on the hot path). */
#define XXH_FORCE_INLINE static inline __attribute__((always_inline))
#define XXH_NO_INLINE    static __attribute__((noinline))
#define XXH_RESTRICT     __restrict
#define XXH_ASSERT(c)    ((void)0)
#define XXH_likely(x)    __builtin_expect(!!(x), 1)
#define XXH_unlikely(x)  __builtin_expect(!!(x), 0)
#define XXH_COMPILER_GUARD(v) ((void)0)
#define XXH_ALIGN(n)     __attribute__((aligned(n)))

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#  define XXH3_IS_BE 1
#else
#  define XXH3_IS_BE 0
#endif

/* primes / constants (xxHash 0.8.3) */
#define XXH_PRIME32_1 0x9E3779B1U
#define XXH_PRIME32_2 0x85EBCA77U
#define XXH_PRIME32_3 0xC2B2AE3DU
#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL
static const xxh_u64 XXH_PRIME_MX1 = 0x165667919E3779F9ULL;
static const xxh_u64 XXH_PRIME_MX2 = 0x9FB21C651E98DF25ULL;

#define XXH_STRIPE_LEN 64
#define XXH_SECRET_CONSUME_RATE 8
#define XXH_ACC_NB (XXH_STRIPE_LEN / sizeof(xxh_u64))
#define XXH3_SECRET_SIZE_MIN 136
#define XXH3_MIDSIZE_MAX 240
#define XXH3_MIDSIZE_STARTOFFSET 3
#define XXH3_MIDSIZE_LASTOFFSET  17
#define XXH_SECRET_DEFAULT_SIZE 192
#define XXH_SECRET_LASTACC_START 7
#define XXH_SECRET_MERGEACCS_START 11
#define XXH3_INIT_ACC { XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3, \
                        XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1 }

XXH_ALIGN(64) static const xxh_u8 XXH3_kSecret[XXH_SECRET_DEFAULT_SIZE] = {
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

/* ---- byte access (memcpy = no alignment/aliasing UB) ---- */
XXH_FORCE_INLINE xxh_u32 XXH_read32(const void *p){ xxh_u32 v; memcpy(&v, p, sizeof(v)); return v; }
XXH_FORCE_INLINE xxh_u64 XXH_read64(const void *p){ xxh_u64 v; memcpy(&v, p, sizeof(v)); return v; }
XXH_FORCE_INLINE xxh_u32 XXH_swap32(xxh_u32 x){
    return ((x << 24) & 0xff000000U) | ((x << 8) & 0x00ff0000U)
         | ((x >> 8) & 0x0000ff00U) | ((x >> 24) & 0x000000ffU);
}
XXH_FORCE_INLINE xxh_u64 XXH_swap64(xxh_u64 x){
    return ((x << 56) & 0xff00000000000000ULL) | ((x << 40) & 0x00ff000000000000ULL)
         | ((x << 24) & 0x0000ff0000000000ULL) | ((x <<  8) & 0x000000ff00000000ULL)
         | ((x >>  8) & 0x00000000ff000000ULL) | ((x >> 24) & 0x0000000000ff0000ULL)
         | ((x >> 40) & 0x000000000000ff00ULL) | ((x >> 56) & 0x00000000000000ffULL);
}
XXH_FORCE_INLINE xxh_u32 XXH_readLE32(const void *p){ return XXH3_IS_BE ? XXH_swap32(XXH_read32(p)) : XXH_read32(p); }
XXH_FORCE_INLINE xxh_u64 XXH_readLE64(const void *p){ return XXH3_IS_BE ? XXH_swap64(XXH_read64(p)) : XXH_read64(p); }
XXH_FORCE_INLINE void XXH_writeLE64(void *dst, xxh_u64 v){ if (XXH3_IS_BE) v = XXH_swap64(v); memcpy(dst, &v, sizeof(v)); }
#define XXH_rotl64(x,r) (((x) << (r)) | ((x) >> (64 - (r))))

/* ---- 64x64->128 multiply: __uint128_t when available, else the portable scalar fallback ---- */
XXH_FORCE_INLINE XXH128_hash_t XXH_mult64to128(xxh_u64 lhs, xxh_u64 rhs){
    XXH128_hash_t r;
#if defined(__SIZEOF_INT128__) || (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 128)
    __uint128_t const product = (__uint128_t)lhs * (__uint128_t)rhs;
    r.low64  = (xxh_u64)product;
    r.high64 = (xxh_u64)(product >> 64);
#else
    xxh_u64 const lo_lo = (xxh_u64)(xxh_u32)lhs        * (xxh_u64)(xxh_u32)rhs;
    xxh_u64 const hi_lo = (xxh_u64)(xxh_u32)(lhs >> 32) * (xxh_u64)(xxh_u32)rhs;
    xxh_u64 const lo_hi = (xxh_u64)(xxh_u32)lhs        * (xxh_u64)(xxh_u32)(rhs >> 32);
    xxh_u64 const hi_hi = (xxh_u64)(xxh_u32)(lhs >> 32) * (xxh_u64)(xxh_u32)(rhs >> 32);
    xxh_u64 const cross = (lo_lo >> 32) + (xxh_u32)hi_lo + lo_hi;
    xxh_u64 const upper = (hi_lo >> 32) + (cross >> 32) + hi_hi;
    xxh_u64 const lower = (cross << 32) | (xxh_u32)lo_lo;
    r.low64 = lower; r.high64 = upper;
#endif
    return r;
}
XXH_FORCE_INLINE xxh_u64 XXH_mult32to64_add64(xxh_u64 lhs, xxh_u64 rhs, xxh_u64 acc){
    return ((xxh_u64)(xxh_u32)lhs * (xxh_u64)(xxh_u32)rhs) + acc;
}
XXH_FORCE_INLINE xxh_u64 XXH3_mul128_fold64(xxh_u64 lhs, xxh_u64 rhs){
    XXH128_hash_t product = XXH_mult64to128(lhs, rhs);
    return product.low64 ^ product.high64;
}
XXH_FORCE_INLINE xxh_u64 XXH_xorshift64(xxh_u64 v64, int shift){ return v64 ^ (v64 >> shift); }

XXH_FORCE_INLINE xxh_u64 XXH64_avalanche(xxh_u64 hash){
    hash ^= hash >> 33; hash *= XXH_PRIME64_2;
    hash ^= hash >> 29; hash *= XXH_PRIME64_3;
    hash ^= hash >> 32; return hash;
}
XXH_FORCE_INLINE xxh_u64 XXH3_avalanche(xxh_u64 h64){
    h64 = XXH_xorshift64(h64, 37); h64 *= XXH_PRIME_MX1; h64 = XXH_xorshift64(h64, 32); return h64;
}
XXH_FORCE_INLINE xxh_u64 XXH3_rrmxmx(xxh_u64 h64, xxh_u64 len){
    h64 ^= XXH_rotl64(h64, 49) ^ XXH_rotl64(h64, 24);
    h64 *= XXH_PRIME_MX2;
    h64 ^= (h64 >> 35) + len;
    h64 *= XXH_PRIME_MX2;
    return XXH_xorshift64(h64, 28);
}

/* ---- short keys (0..240) ---- */
XXH_FORCE_INLINE xxh_u64 XXH3_len_1to3_64b(const xxh_u8 *input, size_t len, const xxh_u8 *secret, xxh_u64 seed){
    xxh_u8  const c1 = input[0];
    xxh_u8  const c2 = input[len >> 1];
    xxh_u8  const c3 = input[len - 1];
    xxh_u32 const combined = ((xxh_u32)c1 << 16) | ((xxh_u32)c2 << 24)
                           | ((xxh_u32)c3 <<  0) | ((xxh_u32)len << 8);
    xxh_u64 const bitflip = (XXH_readLE32(secret) ^ XXH_readLE32(secret + 4)) + seed;
    xxh_u64 const keyed = (xxh_u64)combined ^ bitflip;
    return XXH64_avalanche(keyed);
}
XXH_FORCE_INLINE xxh_u64 XXH3_len_4to8_64b(const xxh_u8 *input, size_t len, const xxh_u8 *secret, xxh_u64 seed){
    seed ^= (xxh_u64)XXH_swap32((xxh_u32)seed) << 32;
    {   xxh_u32 const input1 = XXH_readLE32(input);
        xxh_u32 const input2 = XXH_readLE32(input + len - 4);
        xxh_u64 const bitflip = (XXH_readLE64(secret + 8) ^ XXH_readLE64(secret + 16)) - seed;
        xxh_u64 const input64 = input2 + (((xxh_u64)input1) << 32);
        xxh_u64 const keyed = input64 ^ bitflip;
        return XXH3_rrmxmx(keyed, len);
    }
}
XXH_FORCE_INLINE xxh_u64 XXH3_len_9to16_64b(const xxh_u8 *input, size_t len, const xxh_u8 *secret, xxh_u64 seed){
    xxh_u64 const bitflip1 = (XXH_readLE64(secret + 24) ^ XXH_readLE64(secret + 32)) + seed;
    xxh_u64 const bitflip2 = (XXH_readLE64(secret + 40) ^ XXH_readLE64(secret + 48)) - seed;
    xxh_u64 const input_lo = XXH_readLE64(input)           ^ bitflip1;
    xxh_u64 const input_hi = XXH_readLE64(input + len - 8) ^ bitflip2;
    xxh_u64 const acc = len + XXH_swap64(input_lo) + input_hi + XXH3_mul128_fold64(input_lo, input_hi);
    return XXH3_avalanche(acc);
}
XXH_FORCE_INLINE xxh_u64 XXH3_len_0to16_64b(const xxh_u8 *input, size_t len, const xxh_u8 *secret, xxh_u64 seed){
    if (XXH_likely(len >  8)) return XXH3_len_9to16_64b(input, len, secret, seed);
    if (XXH_likely(len >= 4)) return XXH3_len_4to8_64b(input, len, secret, seed);
    if (len) return XXH3_len_1to3_64b(input, len, secret, seed);
    return XXH64_avalanche(seed ^ (XXH_readLE64(secret + 56) ^ XXH_readLE64(secret + 64)));
}
XXH_FORCE_INLINE xxh_u64 XXH3_mix16B(const xxh_u8 *XXH_RESTRICT input, const xxh_u8 *XXH_RESTRICT secret, xxh_u64 seed64){
    xxh_u64 const input_lo = XXH_readLE64(input);
    xxh_u64 const input_hi = XXH_readLE64(input + 8);
    return XXH3_mul128_fold64(input_lo ^ (XXH_readLE64(secret)     + seed64),
                              input_hi ^ (XXH_readLE64(secret + 8) - seed64));
}
XXH_FORCE_INLINE xxh_u64 XXH3_len_17to128_64b(const xxh_u8 *XXH_RESTRICT input, size_t len,
                                              const xxh_u8 *XXH_RESTRICT secret, size_t secretSize, xxh_u64 seed){
    (void)secretSize;
    {   xxh_u64 acc = len * XXH_PRIME64_1;
        if (len > 32) {
            if (len > 64) {
                if (len > 96) {
                    acc += XXH3_mix16B(input + 48, secret + 96, seed);
                    acc += XXH3_mix16B(input + len - 64, secret + 112, seed);
                }
                acc += XXH3_mix16B(input + 32, secret + 64, seed);
                acc += XXH3_mix16B(input + len - 48, secret + 80, seed);
            }
            acc += XXH3_mix16B(input + 16, secret + 32, seed);
            acc += XXH3_mix16B(input + len - 32, secret + 48, seed);
        }
        acc += XXH3_mix16B(input + 0, secret + 0, seed);
        acc += XXH3_mix16B(input + len - 16, secret + 16, seed);
        return XXH3_avalanche(acc);
    }
}
XXH_NO_INLINE xxh_u64 XXH3_len_129to240_64b(const xxh_u8 *XXH_RESTRICT input, size_t len,
                                            const xxh_u8 *XXH_RESTRICT secret, size_t secretSize, xxh_u64 seed){
    (void)secretSize;
    {   xxh_u64 acc = len * XXH_PRIME64_1;
        xxh_u64 acc_end;
        unsigned int const nbRounds = (unsigned int)len / 16;
        unsigned int i;
        for (i = 0; i < 8; i++) acc += XXH3_mix16B(input + (16 * i), secret + (16 * i), seed);
        acc_end = XXH3_mix16B(input + len - 16, secret + XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET, seed);
        acc = XXH3_avalanche(acc);
        for (i = 8; i < nbRounds; i++)
            acc_end += XXH3_mix16B(input + (16 * i), secret + (16 * (i - 8)) + XXH3_MIDSIZE_STARTOFFSET, seed);
        return XXH3_avalanche(acc + acc_end);
    }
}

/* ---- long keys (>240): scalar accumulate / scramble ---- */
XXH_FORCE_INLINE void XXH3_scalarRound(void *XXH_RESTRICT acc, const void *XXH_RESTRICT input,
                                       const void *XXH_RESTRICT secret, size_t lane){
    xxh_u64 *xacc = (xxh_u64 *)acc;
    const xxh_u8 *xinput  = (const xxh_u8 *)input;
    const xxh_u8 *xsecret = (const xxh_u8 *)secret;
    xxh_u64 const data_val = XXH_readLE64(xinput + lane * 8);
    xxh_u64 const data_key = data_val ^ XXH_readLE64(xsecret + lane * 8);
    xacc[lane ^ 1] += data_val;
    xacc[lane] = XXH_mult32to64_add64(data_key, data_key >> 32, xacc[lane]);
}
XXH_FORCE_INLINE void XXH3_accumulate_512(void *XXH_RESTRICT acc, const void *XXH_RESTRICT input, const void *XXH_RESTRICT secret){
    size_t i;
    for (i = 0; i < XXH_ACC_NB; i++) XXH3_scalarRound(acc, input, secret, i);
}
XXH_FORCE_INLINE void XXH3_scalarScrambleRound(void *XXH_RESTRICT acc, const void *XXH_RESTRICT secret, size_t lane){
    xxh_u64 *const xacc = (xxh_u64 *)acc;
    const xxh_u8 *const xsecret = (const xxh_u8 *)secret;
    xxh_u64 const key64 = XXH_readLE64(xsecret + lane * 8);
    xxh_u64 acc64 = xacc[lane];
    acc64 = XXH_xorshift64(acc64, 47);
    acc64 ^= key64;
    acc64 *= XXH_PRIME32_1;
    xacc[lane] = acc64;
}
XXH_FORCE_INLINE void XXH3_scrambleAcc(void *XXH_RESTRICT acc, const void *XXH_RESTRICT secret){
    size_t i;
    for (i = 0; i < XXH_ACC_NB; i++) XXH3_scalarScrambleRound(acc, secret, i);
}
XXH_FORCE_INLINE void XXH3_accumulate(xxh_u64 *XXH_RESTRICT acc, const xxh_u8 *XXH_RESTRICT input,
                                      const xxh_u8 *XXH_RESTRICT secret, size_t nbStripes){
    size_t n;
    for (n = 0; n < nbStripes; n++)
        XXH3_accumulate_512(acc, input + n * XXH_STRIPE_LEN, secret + n * XXH_SECRET_CONSUME_RATE);
}
XXH_FORCE_INLINE void XXH3_hashLong_internal_loop(xxh_u64 *XXH_RESTRICT acc, const xxh_u8 *XXH_RESTRICT input,
                                                  size_t len, const xxh_u8 *XXH_RESTRICT secret, size_t secretSize){
    size_t const nbStripesPerBlock = (secretSize - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE;
    size_t const block_len = XXH_STRIPE_LEN * nbStripesPerBlock;
    size_t const nb_blocks = (len - 1) / block_len;
    size_t n;
    for (n = 0; n < nb_blocks; n++) {
        XXH3_accumulate(acc, input + n * block_len, secret, nbStripesPerBlock);
        XXH3_scrambleAcc(acc, secret + secretSize - XXH_STRIPE_LEN);
    }
    {   size_t const nbStripes = ((len - 1) - (block_len * nb_blocks)) / XXH_STRIPE_LEN;
        XXH3_accumulate(acc, input + nb_blocks * block_len, secret, nbStripes);
        {   const xxh_u8 *const p = input + len - XXH_STRIPE_LEN;
            XXH3_accumulate_512(acc, p, secret + secretSize - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START);
        }
    }
}
XXH_FORCE_INLINE xxh_u64 XXH3_mix2Accs(const xxh_u64 *XXH_RESTRICT acc, const xxh_u8 *XXH_RESTRICT secret){
    return XXH3_mul128_fold64(acc[0] ^ XXH_readLE64(secret), acc[1] ^ XXH_readLE64(secret + 8));
}
XXH_FORCE_INLINE xxh_u64 XXH3_mergeAccs(const xxh_u64 *XXH_RESTRICT acc, const xxh_u8 *XXH_RESTRICT secret, xxh_u64 start){
    xxh_u64 result64 = start;
    size_t i;
    for (i = 0; i < 4; i++) result64 += XXH3_mix2Accs(acc + 2 * i, secret + 16 * i);
    return XXH3_avalanche(result64);
}
XXH_FORCE_INLINE xxh_u64 XXH3_hashLong_64b_internal(const void *XXH_RESTRICT input, size_t len,
                                                    const void *XXH_RESTRICT secret, size_t secretSize){
    XXH_ALIGN(64) xxh_u64 acc[XXH_ACC_NB] = XXH3_INIT_ACC;
    XXH3_hashLong_internal_loop(acc, (const xxh_u8 *)input, len, (const xxh_u8 *)secret, secretSize);
    return XXH3_mergeAccs(acc, (const xxh_u8 *)secret + XXH_SECRET_MERGEACCS_START, (xxh_u64)len * XXH_PRIME64_1);
}
XXH_NO_INLINE xxh_u64 XXH3_hashLong_64b_default(const void *XXH_RESTRICT input, size_t len){
    return XXH3_hashLong_64b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret));
}
XXH_FORCE_INLINE void XXH3_initCustomSecret(xxh_u8 *customSecret, xxh_u64 seed64){
    int const nbRounds = XXH_SECRET_DEFAULT_SIZE / 16;
    int i;
    for (i = 0; i < nbRounds; i++) {
        xxh_u64 lo = XXH_readLE64(XXH3_kSecret + 16 * i)     + seed64;
        xxh_u64 hi = XXH_readLE64(XXH3_kSecret + 16 * i + 8) - seed64;
        XXH_writeLE64(customSecret + 16 * i,     lo);
        XXH_writeLE64(customSecret + 16 * i + 8, hi);
    }
}
XXH_NO_INLINE xxh_u64 XXH3_hashLong_64b_withSeed(const void *XXH_RESTRICT input, size_t len, xxh_u64 seed){
    if (seed == 0) return XXH3_hashLong_64b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret));
    {   XXH_ALIGN(64) xxh_u8 secret[XXH_SECRET_DEFAULT_SIZE];
        XXH3_initCustomSecret(secret, seed);
        return XXH3_hashLong_64b_internal(input, len, secret, sizeof(secret));
    }
}

/* ---- public one-shot entry points ---- */
XXH_FORCE_INLINE xxh_u64 XXH3_64bits(const void *input, size_t len){
    const xxh_u8 *secret = XXH3_kSecret;
    if (len <= 16)  return XXH3_len_0to16_64b((const xxh_u8 *)input, len, secret, 0);
    if (len <= 128) return XXH3_len_17to128_64b((const xxh_u8 *)input, len, secret, sizeof(XXH3_kSecret), 0);
    if (len <= XXH3_MIDSIZE_MAX) return XXH3_len_129to240_64b((const xxh_u8 *)input, len, secret, sizeof(XXH3_kSecret), 0);
    return XXH3_hashLong_64b_default(input, len);
}
XXH_FORCE_INLINE xxh_u64 XXH3_64bits_withSeed(const void *input, size_t len, xxh_u64 seed){
    const xxh_u8 *secret = XXH3_kSecret;
    if (len <= 16)  return XXH3_len_0to16_64b((const xxh_u8 *)input, len, secret, seed);
    if (len <= 128) return XXH3_len_17to128_64b((const xxh_u8 *)input, len, secret, sizeof(XXH3_kSecret), seed);
    if (len <= XXH3_MIDSIZE_MAX) return XXH3_len_129to240_64b((const xxh_u8 *)input, len, secret, sizeof(XXH3_kSecret), seed);
    return XXH3_hashLong_64b_withSeed(input, len, seed);
}

#endif /* GABPBX_XXH3_64_H */

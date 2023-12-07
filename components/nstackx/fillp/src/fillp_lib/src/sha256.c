/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include "log.h"
#include "utils.h"
#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* right rotate */
#define FILLP_ROTR32(_x, _n) (((_x) >> (_n)) | ((_x) << (32 - (_n))))
/* byte endian swap */
#define FILLP_SWAP32(_x) ((FILLP_ROTR32((_x), 24) & 0x00ff00ff) | (FILLP_ROTR32((_x), 8) & 0xff00ff00))

#ifdef FILLP_LITTLE_ENDIAN
#define FILLP_SWAP_32_ARRAY(_array, _arySize)                    \
    do {                                                         \
        FILLP_UINT32 _index = (_arySize);                        \
        FILLP_UINT32 *_arrayPtr = (FILLP_UINT32 *)(_array);      \
        while (_index--) {                                       \
            _arrayPtr[_index] = FILLP_SWAP32(_arrayPtr[_index]); \
        }                                                        \
    } while (0)
#else
#define FILLP_SWAP_32_ARRAY(_array, _arySize)
#endif

#define FILLP_SHA256_MASK (FILLP_SHA256_BLOCK_SIZE - 1)

#define FILLP_CH(x, y, z)       ((z) ^ ((x) & ((y) ^ (z))))
#define FILLP_MAJ(x, y, z)      (((x) & (y)) | ((z) & ((x) ^ (y))))

/* round transforms for SHA256 and SHA512 compression functions */
#define FILLP_S_0(x)  (FILLP_ROTR32((x),  2) ^ FILLP_ROTR32((x), 13) ^ FILLP_ROTR32((x), 22))
#define FILLP_S_1(x)  (FILLP_ROTR32((x),  6) ^ FILLP_ROTR32((x), 11) ^ FILLP_ROTR32((x), 25))
#define FILLP_G_0(x)  (FILLP_ROTR32((x),  7) ^ FILLP_ROTR32((x), 18) ^ ((x) >>  3))
#define FILLP_G_1(x)  (FILLP_ROTR32((x), 17) ^ FILLP_ROTR32((x), 19) ^ ((x) >> 10))

#define FILLP_G_K256_ARRAY_SZ 64
#define FILLP_HASH_ARRAY_SZ 8
#define FILLP_HASH_ARRAY_SZ_MOD 7
#define FILLP_SHAWK_ARRAY_SZ 16
#define FILLP_SHAWK_ARRAY_SZ_MOD 15
#define FILLP_SHA_TWO_PAR 2
#define FILLP_SHA_THREE_PAR 3
#define FILLP_SHA_FOUR_PAR 4
#define FILLP_SHA_FIVE_PAR 5
#define FILLP_SHA_SIX_PAR 6
#define FILLP_SHA_SEVEN_PAR 7
#define FILLP_SHA_EIGHT_PAR 8
#define FILLP_SHA_NINE_PAR 9
#define FILLP_SHA_FOURTEEN_PAR 14
#define FILLP_SHA_FIVETEEN_PAR 15
#define FILLP_SHA_29_PAR 29
#define FILLP_SHA_60_PAR 60
/* SHA256 mixing data, used to mix with data to create SHA256 key. */
static const FILLP_UINT32 g_k256[FILLP_G_K256_ARRAY_SZ] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

/* initial data for SHA256 digest calculation */
static const FILLP_UINT32 g_i256[FILLP_HASH_ARRAY_SZ] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/* ===========================================================================*\
    Function    :FillpSha256Compile
    Description : This function generates the digest value for SHA256.
                      sCompile 64 bytes of hash data into SHA256 digest value
    Parameters  :
        ctx[1]
    Note        : this routine assumes that the byte order in the
                    ctx->wbuf[] at this point is such that low address bytes in
                    the ORIGINAL byte stream will go into the high end of
                    words on BOTH big and little endian systems.
\*=========================================================================== */
static void FillpSha256Compile(FillpSha256Ctx ctx[1])
{
    FILLP_UINT32 jdex;
    FILLP_UINT32 index;
    FILLP_UINT32 key0;
    FILLP_UINT32 key1;
    FILLP_UINT32 key2;
    FILLP_UINT32 key3;
    FILLP_UINT32 *buf = ctx->wbuf;
    FILLP_UINT32 hash[FILLP_HASH_ARRAY_SZ];

    FillpErrorType err = memcpy_s(hash, sizeof(hash), ctx->hash, sizeof(ctx->hash));
    if (err != EOK) {
        FILLP_LOGERR("FillpSha256Compile memcpy_s hash failed : %d", err);
        return;
    }

    for (jdex = 0; jdex < FILLP_G_K256_ARRAY_SZ; jdex += FILLP_SHAWK_ARRAY_SZ) {
        for (index = 0; index < FILLP_SHAWK_ARRAY_SZ; index++) {
            if (jdex > 0) {
                key0 = ((FILLP_UINT32)(index + FILLP_SHA_FOURTEEN_PAR)) & FILLP_SHAWK_ARRAY_SZ_MOD;
                key1 = ((FILLP_UINT32)(index + FILLP_SHA_NINE_PAR)) & FILLP_SHAWK_ARRAY_SZ_MOD;
                key2 = ((FILLP_UINT32)(index + 1)) & FILLP_SHAWK_ARRAY_SZ_MOD;
                key3 = index & FILLP_SHA_FIVETEEN_PAR;
                buf[key3] += FILLP_G_1(buf[key0]) + buf[key1] + FILLP_G_0(buf[key2]);
            } else {
                key3 = index;
            }

            key0 = ((FILLP_UINT32)(FILLP_SHA_SEVEN_PAR - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            hash[key0] += buf[key3];

            key1 = index + jdex;
            hash[key0] += g_k256[key1];

            key1 = ((FILLP_UINT32)(FILLP_SHA_FOUR_PAR - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            hash[key0] += FILLP_S_1(hash[key1]);

            key2 = ((FILLP_UINT32)(FILLP_SHA_FIVE_PAR - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            key3 = ((FILLP_UINT32)(FILLP_SHA_SIX_PAR - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            hash[key0] += FILLP_CH(hash[key1], hash[key2], hash[key3]);

            key1 = ((FILLP_UINT32)(FILLP_SHA_THREE_PAR - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            hash[key1] += hash[key0];

            key1 = ((FILLP_UINT32)(0 - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            hash[key0] += FILLP_S_0(hash[key1]);

            key2 = ((FILLP_UINT32)(1 - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            key3 = ((FILLP_UINT32)(FILLP_SHA_TWO_PAR - index)) & FILLP_HASH_ARRAY_SZ_MOD;
            hash[key0] += FILLP_MAJ(hash[key1], hash[key2], hash[key3]);
        }
    }

    /* update the context */
    for (jdex = 0; jdex < FILLP_HASH_ARRAY_SZ; jdex++) {
        ctx->hash[jdex] += hash[jdex];
    }
}

void FillpSha256Set(FillpSha256Ctx ctx[1])
{
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    FillpErrorType err = memcpy_s(ctx->hash, sizeof(ctx->hash), g_i256, sizeof(g_i256));
    if (err != EOK) {
        FILLP_LOGERR("FillpSha256Set memcpy_s hash failed : %d", err);
    }
}


void FillpSha256Upd(FillpSha256Ctx ctx[1], const FILLP_UINT8 data[], size_t len)
{
    FILLP_UINT32 offset = (FILLP_UINT32)(ctx->count[0] & FILLP_SHA256_MASK);
    FILLP_UINT32 freeSize = FILLP_SHA256_BLOCK_SIZE - offset;
    const FILLP_UINT8 *dataPtr = data;
    FillpErrorType err;

    if ((ctx->count[0] += (FILLP_UINT32)len) < len) {
        ++(ctx->count[1]);
    }

    while (len >= (size_t)freeSize) {
        err = memcpy_s(((FILLP_UINT8 *)ctx->wbuf) + offset, freeSize, dataPtr, freeSize);
        if (err != EOK) {
            FILLP_LOGERR("FillpSha256Upd memcpy_s 1 failed : %d, freeSize = %u", err, freeSize);
            return;
        }

        dataPtr += freeSize;
        len -= freeSize;
        freeSize = FILLP_SHA256_BLOCK_SIZE;
        offset = 0;
        FILLP_SWAP_32_ARRAY(ctx->wbuf, FILLP_SHA256_BLOCK_SIZE >> FILLP_SHA_TWO_PAR);
        FillpSha256Compile(ctx);
    }

    if (len != 0) {
        err = memcpy_s(((FILLP_UINT8 *)ctx->wbuf) + offset, freeSize, dataPtr, (FILLP_UINT32)len);
        if (err != EOK) {
            FILLP_LOGERR("FillpSha256Upd memcpy_s 2 failed : %d, freeSize = %u, len = %zu", err, freeSize, len);
        }
    }
}

void FillpSha256Fin(FillpSha256Ctx ctx[1], FILLP_UINT8 hashVal[], FILLP_UINT32 hashValLen)
{
    FILLP_UINT32 offset = (FILLP_UINT32)(ctx->count[0] & FILLP_SHA256_MASK);
    FILLP_UINT32 shfBits;

    /* put bytes in the buffer in big endian */
    FILLP_SWAP_32_ARRAY(ctx->wbuf, (offset + FILLP_SHA_THREE_PAR) >> FILLP_SHA_TWO_PAR);

    /* mask valid bytes and add the padding, */
    /* a single 1 bit and as many zero bits as necessary. */
    shfBits = (FILLP_SHA_EIGHT_PAR * (~offset & FILLP_SHA_THREE_PAR));
    ctx->wbuf[offset >> FILLP_SHA_TWO_PAR] &= (FILLP_UINT32)0xffffff80 << shfBits;
    ctx->wbuf[offset >> FILLP_SHA_TWO_PAR] |= (FILLP_UINT32)0x00000080 << shfBits;

    /* need 9 or more empty positions, one for the padding byte  */
    /* (above) and 8 for the length count */
    if (offset > (FILLP_SHA256_BLOCK_SIZE - FILLP_SHA_NINE_PAR)) {
        if (offset < FILLP_SHA_60_PAR) {
            ctx->wbuf[FILLP_SHAWK_ARRAY_SZ_MOD] = 0;
        }

        FillpSha256Compile(ctx);
        offset = 0;
    } else {
        offset = (offset >> FILLP_SHA_TWO_PAR) + 1; /* compute a word index for the empty buffer positions  */
    }

    while (offset < FILLP_SHA_FOURTEEN_PAR) {
        /* and zero pad all but last two positions        */
        ctx->wbuf[offset++] = 0;
    }

    ctx->wbuf[FILLP_SHA_FOURTEEN_PAR] = (ctx->count[1] << FILLP_SHA_THREE_PAR) | (ctx->count[0] >> FILLP_SHA_29_PAR);
    ctx->wbuf[FILLP_SHA_FIVETEEN_PAR] = ctx->count[0] << FILLP_SHA_THREE_PAR;
    FillpSha256Compile(ctx);

    for (offset = 0; offset < hashValLen; ++offset) {
        shfBits = (FILLP_SHA_EIGHT_PAR * (~offset & FILLP_SHA_THREE_PAR));
        hashVal[offset] = (FILLP_UINT8)(ctx->hash[offset >> FILLP_SHA_TWO_PAR] >> shfBits);
    }
}


#ifdef __cplusplus
}
#endif


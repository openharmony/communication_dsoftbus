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

#include "log.h"
#include "utils.h"
#include "fillp_function.h"
#include "spunge.h"
#include "hmac.h"

#ifdef __cplusplus
extern "C" {
#endif
#define CSE_DATA_ONE_PAR 17
#define CSE_DATA_TWO_PAR 63
/*
Description: Internal data for cleansing the data
Value Range: None
Access: Used to store internal data for cleansing the data
*/
/*****************************************************************************
Function       :void FillpCleanSedata(void *ptr, size_t len)

Description    : Clean and fill the memory with random bytes

Input          : ptr - Pointer to buffer which needs to be cleansed.
                   len - Length of the buffer.

Output         : NA
Return         : NA

******************************************************************************/
static void FillpCleanSedata(void *ptr, size_t len, struct SpungeInstance *pcbInst)
{
    if (ptr == FILLP_NULL_PTR) {
        return;
    }

    FILLP_UINT8 *pptr = ptr;
    size_t loop = len;
    size_t ctr = pcbInst->cleanseDataCtr;

    while (loop > 0) {
        *(pptr++) = (FILLP_UINT8)ctr;
        ctr += (CSE_DATA_ONE_PAR + ((size_t)(uintptr_t)pptr & 0xF));
        loop--;
    }

    pptr = FILLP_MEMCHR(ptr, (FILLP_UINT8)ctr, len);
    if (pptr != FILLP_NULL_PTR) {
        ctr += (CSE_DATA_TWO_PAR + (size_t)(uintptr_t)pptr);
    }

    pcbInst->cleanseDataCtr = (FILLP_UINT8)ctr;
}

void FillpHmacSha256Init(OUT FillpHmacSha256 ctx[1], IN FILLP_UINT8 *key, FILLP_UINT32 klen,
    struct SpungeInstance *pcbInst)
{
    FillpHmacSha256Ctx *tempCtx = (FillpHmacSha256Ctx *)ctx;

    /* inner padding - key XORed with ipad */
    FILLP_UINT8 keyIpad[FILLP_SHA256_BLOCK_SIZE];

    /* outer padding - key XORed with opad */
    FILLP_UINT8 keyOpad[FILLP_SHA256_BLOCK_SIZE];
    FILLP_UINT8 tk[FILLP_SHA256_DIGEST_SIZE];
    FILLP_UINT i;

    /* Null context */
    if (tempCtx == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpHmacSha256Init - Null Context ");
        return;
    }
    if ((key == FILLP_NULL_PTR) || (klen == 0)) {
        FILLP_LOGERR("FillpHmacSha256Init - Invalid Parameters passed ");
        return;
    }
    if (klen > FILLP_SHA256_BLOCK_SIZE) {
        FillpSha256Ctx tctx;
        FillpSha256Set(&tctx);
        FillpSha256Upd(&tctx, key, klen);
        FillpSha256Fin(&tctx, tk, FILLP_SHA256_DIGEST_SIZE);
        key = (FILLP_UINT8 *)tk;
        klen = FILLP_SHA256_DIGEST_SIZE;
        FILLP_UNUSED_PARA(tctx);
    }
    (void)memset_s(keyIpad, FILLP_SHA256_BLOCK_SIZE, 0, FILLP_SHA256_BLOCK_SIZE);
    (void)memset_s(keyOpad, FILLP_SHA256_BLOCK_SIZE, 0, FILLP_SHA256_BLOCK_SIZE);
    FillpErrorType err = memcpy_s(keyIpad, klen, key, klen);
    if (err != EOK) {
        FILLP_LOGERR("FillpHmacSha256Init memcpy_s keyIpad failed: %d ", err);
        return;
    }
    err = memcpy_s(keyOpad, klen, key, klen);
    if (err != EOK) {
        FILLP_LOGERR("FillpHmacSha256Init memcpy_s keyOpad failed: %d ", err);
        return;
    }
    for (i = 0; i < FILLP_SHA256_BLOCK_SIZE; i++) {
        keyIpad[i] = keyIpad[i] ^ FILLP_HMAC_IPAD;
        keyOpad[i] = keyOpad[i] ^ FILLP_HMAC_OPAD;
    }

    FillpSha256Set(tempCtx->hashki);
    FillpSha256Upd(tempCtx->hashki, keyIpad, FILLP_SHA256_BLOCK_SIZE);
    FillpSha256Set(tempCtx->hashko);
    FillpSha256Upd(tempCtx->hashko, keyOpad, FILLP_SHA256_BLOCK_SIZE);

    FillpCleanSedata((void *)tk, sizeof(tk), pcbInst);
    FillpCleanSedata((void *)keyIpad, sizeof(keyIpad), pcbInst);
    FillpCleanSedata((void *)keyOpad, sizeof(keyOpad), pcbInst);
}


void FillpHmacSha256Update(IO FillpHmacSha256 ctx[1], FILLP_CONST FILLP_UINT8 *data, FILLP_UINT32 dlen)
{
    FillpHmacSha256Ctx *tempCtx = (FillpHmacSha256Ctx *)ctx;

    /* Null context */
    if (tempCtx == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpHmacSha256Update - Null Context ");
        return;
    }

    if ((dlen == 0) && (data == FILLP_NULL_PTR)) {
        FILLP_UINT8 x = 0;
        FillpSha256Upd(tempCtx->hashki, &x, 0);
        FILLP_UNUSED_PARA(x);
    } else if (data == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpHmacSha256Update - Null data ");
        return;
    } else {
        FillpSha256Upd(tempCtx->hashki, data, dlen);
    }
}

void FillpHmacSha256Final(IO FillpHmacSha256 ctx[1],
    OUT FILLP_UINT8 digest[FILLP_SHA256_DIGEST_SIZE], FILLP_UINT32 size)
{
    FillpHmacSha256Ctx *tempCtx = (FillpHmacSha256Ctx *)ctx;
    if (tempCtx == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpHmacSha256Final - Null Context ");
        return;
    }

    if (digest == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpHmacSha256Final - invalid argument ");
        return;
    }

    FillpSha256Fin(tempCtx->hashki, digest, size);
    FillpSha256Upd(tempCtx->hashko, digest, size);
    FillpSha256Fin(tempCtx->hashko, digest, size);
}


#ifdef __cplusplus
}
#endif


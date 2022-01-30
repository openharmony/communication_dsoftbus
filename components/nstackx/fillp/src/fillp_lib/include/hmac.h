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

#ifndef FILLP_HMAC_H
#define FILLP_HMAC_H
#include "sha256.h"
#include "spunge.h"

#ifdef __cplusplus
extern "C" {
#endif


/* HMAC PAD value */
#define FILLP_HMAC_IPAD 0x36u

/* HMAC PAD value */
#define FILLP_HMAC_OPAD 0x5Cu


#define FILLP_HMAC_SHA256_CTX_SIZE 208

typedef struct {
    FillpSha256Ctx hashki[1];
    FillpSha256Ctx hashko[1];
} FillpHmacSha256Ctx;


/**
* @defgroup FillpHmacSha256
* @ingroup sec_cryptoStructures
* @par Prototype
* @code
* typedef struct
{
    SEC_UCHAR data[FILLP_HMAC_SHA256_CTX_SIZE];
}FillHmacSha256CtxOld;
* @endcode
*
* @datastruct data[FILLP_HMAC_SHA256_CTX_SIZE] Represents the buffer for
* HMAC SHA256
* context.
*/

typedef struct {
    FILLP_UINT8 data[FILLP_HMAC_SHA256_CTX_SIZE];
} FillpHmacSha256;


void FillpHmacSha256Init(OUT FillpHmacSha256 ctx[1], IN FILLP_UINT8 *key, FILLP_UINT32 klen,
    struct SpungeInstance *pcbInst);

void FillpHmacSha256Update(IO FillpHmacSha256 ctx[1], FILLP_CONST FILLP_UINT8 *data, FILLP_UINT32 dlen);

void FillpHmacSha256Final(IO FillpHmacSha256 ctx[1], OUT FILLP_UINT8 digest[FILLP_SHA256_DIGEST_SIZE],
    FILLP_UINT32 size);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_HMAC_H */

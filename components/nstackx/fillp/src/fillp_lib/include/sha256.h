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

#ifndef FILLP_SHA256_H
#define FILLP_SHA256_H

#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_SHA256_DIGEST_SIZE  32 /* hash size in bytes 8 * sizeof(FILLP_UINT32) */
#define FILLP_SHA256_BLOCK_SIZE   64 /* wbuf size in bytes 16 * sizeof(FILLP_UINT32) */

typedef struct {
    FILLP_UINT32 count[2];
    FILLP_UINT32 hash[8];
    FILLP_UINT32 wbuf[16];
} FillpSha256Ctx;

/*******************************************************************************
    Function     : FillpSha256Set
    Description : init sha256 context

    Input         :
                    ctx[1] : Partition number
    Output       :None
 *******************************************************************************/
void FillpSha256Set(FillpSha256Ctx ctx[1]);

/*******************************************************************************
    Function     : FillpSha256Upd
    Description : update sha256 context with data in an array of bytes

    Input         :
                    ctx[1] : sha256 context
                    data[] : data to calculate
                    len : size in byte of data array
    Output       :None
 *******************************************************************************/
void FillpSha256Upd(FillpSha256Ctx ctx[1], const FILLP_UINT8 data[], size_t len);

/*******************************************************************************
    Function     : FillpSha256Set
    Description : Final padding and digest calculation

    Input         :
                    ctx[1] : sha256 context
    Output       :
                    hashVal[]: hash value
 *******************************************************************************/
void FillpSha256Fin(FillpSha256Ctx ctx[1], FILLP_UINT8 hashVal[], FILLP_UINT32 hashValLen);


#ifdef __cplusplus
}
#endif


#endif /* FILLP_SHA256_H */


/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_SEQUENCE_VERIFICATION_H
#define SOFTBUS_SEQUENCE_VERIFICATION_H

#include <stdbool.h>
#include <stdint.h>
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* when receive seq < minSeq, the package is duplicated.
   when receive seq == minSeq, update minSeq.
   when minSeq < receive seq < maxSeq, Check whether duplicate package exist, record the package in bitmap.
   when receive seq >= maxSeq, update maxSeq, record the package in bitmap.
*/
typedef struct {
    int32_t maxSeq;
    int32_t minSeq;
    uint64_t recvBitmap;
} SeqVerifyInfo;

/* When the received package is an ACK packet, this function does not need to be called for verification. */
bool IsPassSeqCheck(SeqVerifyInfo *seqVerifyInfo, int32_t recvSeq);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // !SOFTBUS_SEQUENCE_VERIFICATION_H

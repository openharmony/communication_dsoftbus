/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_ASSEMBLE_TLV_H
#define CLIENT_TRANS_ASSEMBLE_TLV_H

#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t magicNum;
    uint8_t tlvCount;
    uint8_t *tlvElement;
} DataHead;

typedef struct {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
} TlvElement;

typedef enum {
    TLV_TYPE_INNER_SEQ = 0,
    TLV_TYPE_DATA_SEQ,
    TLV_TYPE_FLAG,
    TLV_TYPE_NEED_ACK,
    TLV_TYPE_DATA_LEN,
    TLV_TYPE_BUFF,
} TlvHeadType;

int32_t TransAssembleTlvData(DataHead *pktHead, uint8_t type, uint8_t *buffer, uint8_t bufferLen, int32_t *bufferSize);
void ReleaseTlvValueBuffer(DataHead *pktHead);

#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_ASSEMBLE_TLV_H

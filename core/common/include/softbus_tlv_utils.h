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

#ifndef SOFTBUS_TLV_UTILS_H
#define SOFTBUS_TLV_UTILS_H

#include <stdint.h>
#include "common_list.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

enum BasicSize {
    UINT8_T = 1,
    UINT16_T = 2,
    UINT32_T = 4,
};

typedef struct {
    uint8_t tSize; // the number of bytes occupied by the type filed
    uint8_t lSize; // the number of bytes occupied by the length filed
    uint8_t *buffer; // tlv binary buffer
    uint32_t size; // the size of buffer
    ListNode mList; // tlv member list
} TlvObject;

TlvObject *CreateTlvObject(uint8_t tSize, uint8_t lSize);
void DestroyTlvObject(TlvObject *obj);

int32_t AddTlvMember(TlvObject *obj, uint32_t type, uint32_t length, const uint8_t *value);
// note: the memory of value no need to be released, it will be released while DestroyTlvObject() called.
int32_t GetTlvMember(TlvObject *obj, uint32_t type, uint32_t *length, uint8_t **value);

// note: the memory of output no need to be released, it will be released while DestroyTlvObject() called.
int32_t GetTlvBinary(TlvObject *obj, uint8_t **output, uint32_t *outputSize);
int32_t SetTlvBinary(TlvObject *obj, const uint8_t *input, uint32_t inputSize);

// note: buffer is [IN] param.
int32_t GetTlvMemberWithSpecifiedBuffer(TlvObject *obj, uint32_t type, uint8_t *buffer, uint32_t size);
// note: buffer is [IN] param, size is [IN/OUT] param.
int32_t GetTlvMemberWithEstimatedBuffer(TlvObject *obj, uint32_t type, uint8_t *buffer, uint32_t *size);

// note: while calling the following API, no need to handle 'Network Byte Order'.
int32_t AddTlvMemberU16(TlvObject *obj, uint32_t type, uint16_t value);
int32_t GetTlvMemberU16(TlvObject *obj, uint32_t type, uint16_t *value);

int32_t AddTlvMemberU32(TlvObject *obj, uint32_t type, uint32_t value);
int32_t GetTlvMemberU32(TlvObject *obj, uint32_t type, uint32_t *value);

int32_t AddTlvMemberU64(TlvObject *obj, uint32_t type, uint64_t value);
int32_t GetTlvMemberU64(TlvObject *obj, uint32_t type, uint64_t *value);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // SOFTBUS_TLV_UTILS_H

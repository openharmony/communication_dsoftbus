/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_CLOUD_QUERY_FRAGMENT_H_H
#define LNN_CLOUD_QUERY_FRAGMENT_H_H

#include <stdint.h>

#include "lnn_event.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MSG_ID (0xFFFFFFFF)

typedef struct {
    uint32_t msgId;
    uint32_t size;
    uint32_t offset;
    uint32_t total;
} DataFragmentInfo;

typedef struct {
    const uint8_t *data;
    uint32_t dataLen;
    uint32_t sliceLen;
    uint32_t msgId;
} DataFragmentMsgInfo;

void DataFragmentInit(void);

int32_t DataSlice(const char *udid, const DataFragmentMsgInfo *info, LnnEventExtra *extra,
    bool isAckMsg);

int32_t DataAggregate(const uint8_t *data, uint32_t dataLen, uint8_t **assembledData, uint32_t *assembledLen,
    uint32_t *msgId);

uint32_t GenerateMsgId(void);

int32_t WriteFragmentHeader(uint8_t *buffer, uint32_t bufferLen, const DataFragmentInfo *header);

int32_t ParseFragmentHeader(const uint8_t *data, uint32_t dataLen, DataFragmentInfo *header);

#ifdef __cplusplus
}
#endif
#endif // LNN_CLOUD_QUERY_FRAGMENT_H_H
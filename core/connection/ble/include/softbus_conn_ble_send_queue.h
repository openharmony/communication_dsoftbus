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

#ifndef SOFTBUS_CONNBLE_SEND_QUEUE_H
#define SOFTBUS_CONNBLE_SEND_QUEUE_H

#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t connectionId;
    int32_t pid;
    int32_t flag;
    int32_t module;
    int64_t seq;
    uint32_t dataLen;
    uint8_t *data;
    void (*onPostBytesFinished)(uint32_t connectionId, int32_t error);
} SendQueueNode;

int32_t ConnBleInitSendQueue(void);
void ConnBleDeinitSendQueue(void);
int32_t ConnBleEnqueueNonBlock(const void *msg);
int32_t ConnBleDequeueBlock(void **msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONNBLE_SEND_QUEUE_H */
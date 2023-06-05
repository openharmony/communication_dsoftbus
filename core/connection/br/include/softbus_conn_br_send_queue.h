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

#ifndef CONN_BR_SEND_QUEUE_H
#define CONN_BR_SEND_QUEUE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t connectionId;
    int32_t pid;
    int32_t flag;
    bool isInner;
    int32_t module;
    int64_t seq;
    uint32_t len;
    uint8_t *data;
} SendBrQueueNode;

int32_t ConnBrInnerQueueInit(void);
void ConnBrInnerQueueDeinit(void);
int32_t ConnBrEnqueueNonBlock(const void *msg);
int32_t ConnBrDequeueBlock(void **msg);
bool ConnBrIsQueueEmpty(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CONN_BR_SEND_QUEUE_H */
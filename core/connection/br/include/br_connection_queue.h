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

#ifndef BR_CONNECTION_QUEUE_H
#define BR_CONNECTION_QUEUE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    uint32_t connectionId;
    int32_t pid;
    int32_t flag;
    bool isInner;
    int32_t module;
    uint64_t seq;
    uint32_t len;
    const char *data;
    void (*listener)(uint32_t connId, uint64_t seq, int32_t module, int32_t result);
} SendBrQueueNode;

int32_t BrInnerQueueInit(void);
void BrInnerQueueDeinit(void);
int32_t BrEnqueueNonBlock(const void *msg);
int32_t BrDequeueBlock(void **msg);
bool IsBrQueueEmpty(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* BR_CONNECTION_QUEUE_H */
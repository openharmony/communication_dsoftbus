/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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

#include "comm_log.h"
#include "softbus_queue.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define IS_POWER_OF_2(x) ((((x) - 1) & (x)) == 0)
#define QUEUE_HEADER_MAGIC 0xccddddcc
#define QUEUE_SIZE_MAX 8192
#define CACHE_LINE_SIZE 64

int32_t QueueInit(LockFreeQueue* queue, uint32_t unitNum)
{
    if (queue == NULL) {
        COMM_LOGE(COMM_UTILS, "queue is null");
        return QUEUE_INVAL;
    }
    if (unitNum < 1 || !IS_POWER_OF_2(unitNum)) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return QUEUE_INVAL;
    }

    (void)memset_s(queue, sizeof(LockFreeQueue), 0, sizeof(LockFreeQueue));

    queue->magic = QUEUE_HEADER_MAGIC;
    queue->producer.size = unitNum;
    queue->consumer.size = unitNum;
    queue->producer.mask = unitNum - 1;
    queue->consumer.mask = unitNum - 1;
    queue->producer.head = 0;
    queue->consumer.head = 0;
    queue->producer.tail = 0;
    queue->consumer.tail = 0;
    queue->unitNum = unitNum;

    return 0;
}

int32_t QueueSizeCalc(uint32_t unitNum, uint32_t* queueSize)
{
    uint32_t size;

    if (queueSize == NULL) {
        COMM_LOGE(COMM_UTILS, "queueSize is null");
        return QUEUE_INVAL;
    }
    if (unitNum > QUEUE_SIZE_MAX) {
        COMM_LOGE(COMM_UTILS, "unitNum is invalid param unitNum=%{public}u", unitNum);
        return QUEUE_INVAL;
    }

    size = sizeof(uintptr_t) * unitNum + sizeof(LockFreeQueue);
    *queueSize = ((size + CACHE_LINE_SIZE - 1) & (~(CACHE_LINE_SIZE - 1)));
    return 0;
}

int32_t QueueCountGet(const LockFreeQueue* queue, uint32_t* count)
{
    uint32_t producerTail;
    uint32_t consumerTail;
    uint32_t mask;

    if (queue == NULL || count == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return QUEUE_INVAL;
    }
    producerTail = queue->producer.tail;
    consumerTail = queue->consumer.tail;
    mask = queue->producer.mask;

    *count = ((producerTail - consumerTail) & mask);
    return 0;
}

LockFreeQueue* CreateQueue(uint32_t unitNum)
{
    if (unitNum < 1 || !IS_POWER_OF_2(unitNum)) {
        return NULL;
    }
    uint32_t queueSize;
    int ret = QueueSizeCalc(unitNum, &queueSize);
    if (ret != 0) {
        return NULL;
    }
    LockFreeQueue *queue = (LockFreeQueue *)SoftBusCalloc(queueSize);
    if (queue == NULL) {
        COMM_LOGE(COMM_UTILS, "SoftBusCalloc fail");
        return NULL;
    }
    ret = QueueInit(queue, unitNum);
    if (ret != 0) {
        COMM_LOGE(COMM_UTILS, "QueueInit fail");
        SoftBusFree(queue);
        return NULL;
    }
    return queue;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
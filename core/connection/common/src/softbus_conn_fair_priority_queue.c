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

#include "softbus_conn_fair_priority_queue.h"

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_queue.h"

#include "conn_log.h"

#define FACTOR_S_MS_US 1000

void ConnQueueItemConstruct(struct ConnQueueItem *item, int32_t id, ConnPriority priority)
{
    CONN_CHECK_AND_RETURN_LOGE(item != NULL, CONN_COMMON, "item is null");
    item->id = id;
    item->priority = priority;
}

void ConnQueueItemDestruct(struct ConnQueueItem *item)
{
    CONN_CHECK_AND_RETURN_LOGE(item != NULL, CONN_COMMON, "item is null");
    (void)item;
}

struct PriorityQueue {
    ListNode node;

    int32_t id;
    LockFreeQueue *queue[CONN_PRIORITY_BUTT];
    uint32_t size;
};

static struct PriorityQueue *CreatePriorityQueue(int32_t id, uint32_t size)
{
    struct PriorityQueue *pq = SoftBusCalloc(sizeof(struct PriorityQueue));
    CONN_CHECK_AND_RETURN_RET_LOGE(pq != NULL, NULL, CONN_COMMON, "malloc fail");

    ListInit(&pq->node);
    pq->id = id;
    pq->size = size;

    return pq;
}

static void DestroyPriorityQueue(struct PriorityQueue *queue)
{
    CONN_CHECK_AND_RETURN_LOGE(queue != NULL, CONN_COMMON, "queue is null");
    for (ConnPriority i = 0; i < CONN_PRIORITY_BUTT; i++) {
        LockFreeQueue *lfq = queue->queue[i];
        SoftBusFree(lfq);
        queue->queue[i] = NULL;
    }
    SoftBusFree(queue);
}

static LockFreeQueue *GetQueue(struct PriorityQueue *queue, ConnPriority priority, bool createIfEmpty)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        priority < CONN_PRIORITY_BUTT, NULL, CONN_COMMON, "priority out of bound: priority=%{public}d", priority);

    LockFreeQueue *lfq = queue->queue[priority];
    if (!createIfEmpty || lfq != NULL) {
        return lfq;
    }
    lfq = CreateQueue(queue->size);
    CONN_CHECK_AND_RETURN_RET_LOGE(lfq != NULL, NULL, CONN_COMMON, "create queue fail");
    queue->queue[priority] = lfq;
    return lfq;
}

static int32_t Enqueue(struct PriorityQueue *queue, struct ConnQueueItem *item)
{
    ConnPriority priority = item->priority;
    LockFreeQueue *lfq = GetQueue(queue, priority, true);
    CONN_CHECK_AND_RETURN_RET_LOGE(lfq != NULL, SOFTBUS_MALLOC_ERR, CONN_COMMON,
        "get queue fail, id=%{public}d, priority=%{public}d", item->id, priority);
    int32_t ret = QueueMultiProducerEnqueue(lfq, item);
    return ret;
}

static int32_t Dequeue(struct PriorityQueue *queue, ConnPriority least, struct ConnQueueItem **out)
{
    for (ConnPriority priority = 0; priority <= least; priority++) {
        LockFreeQueue *lfq = GetQueue(queue, (ConnPriority)priority, false);
        if (lfq == NULL) {
            continue;
        }
        int32_t ret = QueueSingleConsumerDequeue(lfq, (void **)out);
        if (ret == QUEUE_EMPTY) {
            continue;
        }
        return ret;
    }
    return QUEUE_EMPTY;
}

struct ConnFairPriorityQueue {
    uint32_t size;

    SoftBusMutex lock;
    SoftBusCond enqueueCondition;
    SoftBusCond dequeueCondition;

    ListNode queues;
    struct PriorityQueue *innerQueue;
};

ConnFairPriorityQueue *ConnCreateQueue(uint32_t size)
{
    ConnFairPriorityQueue *queue = SoftBusCalloc(sizeof(ConnFairPriorityQueue));
    CONN_CHECK_AND_RETURN_RET_LOGE(queue != NULL, NULL, CONN_COMMON, "malloc fail");

    queue->size = size;
    SoftBusMutexAttr attr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&queue->lock, &attr);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "init lock fail: error=%{public}d", ret);
        goto CLEANUP;
    }
    ret = SoftBusCondInit(&queue->dequeueCondition);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "init dequeue condition fail: error=%{public}d", ret);
        goto CLEANUP;
    }
    ret = SoftBusCondInit(&queue->enqueueCondition);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "init dequeue condition fail: error=%{public}d", ret);
        goto CLEANUP;
    }
    ListInit(&queue->queues);
    queue->innerQueue = CreatePriorityQueue(0, queue->size);
    if (queue->innerQueue == NULL) {
        CONN_LOGE(CONN_COMMON, "create inner priority queue fail");
        goto CLEANUP;
    }
    return queue;
CLEANUP:
    SoftBusMutexDestroy(&queue->lock);
    SoftBusCondDestroy(&queue->dequeueCondition);
    SoftBusCondDestroy(&queue->enqueueCondition);
    DestroyPriorityQueue(queue->innerQueue);
    SoftBusFree(queue);
    return NULL;
}

void ConnDestroyQueue(ConnFairPriorityQueue *queue)
{
    CONN_CHECK_AND_RETURN_LOGE(queue != NULL, CONN_COMMON, "queue is null");

    SoftBusMutexDestroy(&queue->lock);
    SoftBusCondDestroy(&queue->enqueueCondition);
    SoftBusCondDestroy(&queue->dequeueCondition);

    struct PriorityQueue *it = NULL;
    struct PriorityQueue *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &queue->queues, struct PriorityQueue, node) {
        ListDelete(&it->node);
        DestroyPriorityQueue(it);
    }
    DestroyPriorityQueue(queue->innerQueue);
    SoftBusFree(queue);
}

static struct PriorityQueue *GetOrCreatePriorityQueue(ConnFairPriorityQueue *queue, int32_t id)
{
    if (id == 0) {
        return queue->innerQueue;
    }
    struct PriorityQueue *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &queue->queues, struct PriorityQueue, node) {
        if (it->id == id) {
            return it;
        }
    }

    struct PriorityQueue *pq = CreatePriorityQueue(id, queue->size);
    CONN_CHECK_AND_RETURN_RET_LOGE(pq != NULL, NULL, CONN_COMMON, "create priority queue fail");
    ListTailInsert(&queue->queues, &pq->node);
    return pq;
}

static int32_t WaitCondition(SoftBusCond *condition, SoftBusMutex *mutex, int32_t timeoutMs)
{
    if (timeoutMs < 0) {
        return SoftBusCondWait(condition, mutex, NULL);
    }
    SoftBusSysTime now = { 0 };
    int32_t ret = SoftBusGetTime(&now);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_COMMON, "get time fail: error=%{public}d", ret);

    int64_t us = timeoutMs * FACTOR_S_MS_US + now.usec;
    now.sec += us / (FACTOR_S_MS_US * FACTOR_S_MS_US);
    now.usec = us % (FACTOR_S_MS_US * FACTOR_S_MS_US);
    return SoftBusCondWait(condition, mutex, &now);
}

int32_t ConnEnqueue(ConnFairPriorityQueue *queue, struct ConnQueueItem *item, int32_t timeoutMs)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(queue != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "queue is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(item != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "item is null");

    int32_t code = SoftBusMutexLock(&queue->lock);
    CONN_CHECK_AND_RETURN_RET_LOGW(code == SOFTBUS_OK, code, CONN_COMMON, "lock queue fail: error=%{public}d", code);
    bool afterWait = false;
    do {
        struct PriorityQueue *pq = GetOrCreatePriorityQueue(queue, item->id);
        if (pq == NULL) {
            code = SOFTBUS_MALLOC_ERR;
            CONN_LOGE(CONN_COMMON,
                "enqueue fail: get queue fail, id=%{public}d, priority=%{public}d, error=%{public}d", item->id,
                item->priority, code);
            break;
        }
        code = Enqueue(pq, item);
        if (code == SOFTBUS_OK) {
            break;
        }
        if (code != QUEUE_FULL) {
            CONN_LOGE(CONN_COMMON, "enqueue fail: id=%{public}d, priority=%{public}d, error=%{public}d", item->id,
                item->priority, code);
            break;
        }
        if (afterWait) {
            CONN_LOGE(CONN_COMMON, "can not enqueue item after being awake up");
            code = SOFTBUS_CONN_INTERNAL_ERR;
            break;
        }
        CONN_LOGE(CONN_COMMON, "queue is full, id=%{public}d, priority=%{public}d", item->id, item->priority);
        code = WaitCondition(&queue->enqueueCondition, &queue->lock, timeoutMs);
        if (code != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON,
                "wait enqueue condition fail: id=%{public}d, priority=%{public}d, error=%{public}d", item->id,
                item->priority, code);
            break;
        }
        afterWait = true;
    } while (true);
    if (code == SOFTBUS_OK) {
        SoftBusCondBroadcast(&queue->dequeueCondition);
    }
    (void)SoftBusMutexUnlock(&queue->lock);
    return code;
}

static int32_t DequeueInner(ConnFairPriorityQueue *queue, ConnPriority least, struct ConnQueueItem **outMsg)
{
    int32_t ret = Dequeue(queue->innerQueue, least, outMsg);
    if (ret != SOFTBUS_OK && ret != QUEUE_EMPTY) {
        CONN_LOGE(CONN_COMMON, "get item from inner queue fail: error=%{public}d", ret);
    }
    return ret;
}

static int32_t DequeueFairly(ConnFairPriorityQueue *queue, struct ConnQueueItem **outMsg)
{
    struct PriorityQueue *it = NULL;
    struct PriorityQueue *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &queue->queues, struct PriorityQueue, node) {
        ListDelete(&it->node);
        int32_t ret = Dequeue(it, CONN_PRIORITY_LOW, outMsg);
        if (ret == QUEUE_EMPTY) {
            DestroyPriorityQueue(it);
            continue;
        }
        ListTailInsert(&queue->queues, &it->node);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "get item from queue fail: pid=%{public}d, error=%{public}d", it->id, ret);
        }
        return ret;
    }
    return QUEUE_EMPTY;
}

int32_t ConnDequeue(ConnFairPriorityQueue *queue, struct ConnQueueItem **outMsg, int32_t timeoutMs)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(queue != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "queue is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(outMsg != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "out item is null");

    int32_t code = SoftBusMutexLock(&queue->lock);
    CONN_CHECK_AND_RETURN_RET_LOGW(code == SOFTBUS_OK, code, CONN_COMMON, "lock queue fail: error=%{public}d", code);
    bool afterWait = false;
    do {
        code = DequeueInner(queue, CONN_PRIORITY_MIDDLE, outMsg);
        if (code != QUEUE_EMPTY) {
            break;
        }
        code = DequeueFairly(queue, outMsg);
        if (code != QUEUE_EMPTY) {
            break;
        }
        code = DequeueInner(queue, CONN_PRIORITY_LOW, outMsg);
        if (code != QUEUE_EMPTY) {
            break;
        }
        if (afterWait) {
            CONN_LOGE(CONN_COMMON, "can not dequeue item after being awake up");
            code = SOFTBUS_CONN_INTERNAL_ERR;
            break;
        }

        code = WaitCondition(&queue->dequeueCondition, &queue->lock, timeoutMs);
        if (code == SOFTBUS_TIMOUT) {
            CONN_LOGE(CONN_COMMON, "wait dequeue condition timeout");
            break;
        }
        if (code != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "wait dequeue condition fail: error=%{public}d", code);
            break;
        }
        afterWait = true;
    } while (true);
    if (code == SOFTBUS_OK) {
        SoftBusCondBroadcast(&queue->enqueueCondition);
    }
    (void)SoftBusMutexUnlock(&queue->lock);
    return code;
}

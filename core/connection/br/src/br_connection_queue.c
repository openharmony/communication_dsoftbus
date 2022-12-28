/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "br_connection_queue.h"

#include "common_list.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_queue.h"
#include "softbus_type_def.h"

#define HIGH_PRIORITY_DEFAULT_LIMIT 32
#define MIDDLE_PRIORITY_DEFAULT_LIMIT 32
#define LOW_PRIORITY_DEFAULT_LIMIT 32
#define WAIT_QUEUE_BUFFER_PERIOD_LEN 2

typedef enum {
    HIGH_PRIORITY = 0,
    MIDDLE_PRIORITY,
    LOW_PRIORITY,
    QUEUE_NUM_PER_PID,
} QueuePriority;

typedef struct {
    ListNode node;
    int32_t pid;
    LockFreeQueue *queue[QUEUE_NUM_PER_PID];
} BrQueue;

static const uint32_t QUEUE_LIMIT[QUEUE_NUM_PER_PID] = {
    HIGH_PRIORITY_DEFAULT_LIMIT,
    MIDDLE_PRIORITY_DEFAULT_LIMIT,
    LOW_PRIORITY_DEFAULT_LIMIT
};
static LIST_HEAD(g_brQueueList);
static SoftBusMutex g_brQueueLock;
static BrQueue *g_innerQueue = NULL;

static SoftBusCond g_sendWaitCond;
static SoftBusCond g_sendCond;

static BrQueue *CreateBrQueue(int32_t pid)
{
    BrQueue *queue = (BrQueue *)SoftBusCalloc(sizeof(BrQueue));
    if (queue == NULL) {
        return NULL;
    }
    queue->pid = pid;
    int32_t i;
    for (i = 0; i < QUEUE_NUM_PER_PID; i++) {
        queue->queue[i] = CreateQueue(QUEUE_LIMIT[i]);
        if (queue->queue[i] == NULL) {
            goto ERR_RETURN;
        }
    }
    return queue;
ERR_RETURN:
    for (i--; i >= 0; i--) {
        SoftBusFree(queue->queue[i]);
    }
    SoftBusFree(queue);
    return NULL;
}

static void DestroyBrQueue(BrQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    for (uint32_t i = 0; i < QUEUE_NUM_PER_PID; i++) {
        SoftBusFree(queue->queue[i]);
    }
    SoftBusFree(queue);
}

static int GetPriority(int32_t flag)
{
    switch (flag) {
        case CONN_HIGH:
            return HIGH_PRIORITY;
        case CONN_MIDDLE:
            return MIDDLE_PRIORITY;
        default:
            return LOW_PRIORITY;
    }
}

static int32_t BrSoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis)
{
#define USECTONSEC 1000LL
    if (timeMillis == 0) {
        return SoftBusCondWait(cond, mutex, NULL);
    }
    SoftBusSysTime now;
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrSoftBusCondWait SoftBusGetTime failed");
        return SOFTBUS_ERR;
    }
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + timeMillis * USECTONSEC;
    SoftBusSysTime tv;
    tv.sec = time / USECTONSEC / USECTONSEC;
    tv.usec = time % (USECTONSEC * USECTONSEC);
    return SoftBusCondWait(cond, mutex, &tv);
}

static int32_t WaitQueueLength(const LockFreeQueue *lockFreeQueue, uint32_t maxLen, uint32_t diffLen, int32_t pid)
{
#define WAIT_RETRY_NUM 2
#define WAIT_QUEUE_DELAY 1000
    int32_t retry = 0;
    uint32_t queueCount = 0;
    while (true) {
        if (QueueCountGet(lockFreeQueue, &queueCount) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "wait get queue count fail");
            break;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br pid = %d, queue count = %d", pid, queueCount);
        if (queueCount < (maxLen - diffLen)) {
            break;
        }
        retry++;
        if (retry > WAIT_RETRY_NUM) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "wait queue length retry over");
            if (queueCount < maxLen) {
                return SOFTBUS_OK;
            }
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL!!");
            return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Wait g_sendWaitCond");
        if (BrSoftBusCondWait(&g_sendWaitCond, &g_brQueueLock, WAIT_QUEUE_DELAY) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "wait queue length cond wait fail");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

bool IsBrQueueEmpty(void)
{
    uint32_t queueCount = 0;
    for (uint32_t i = 0; i < QUEUE_NUM_PER_PID; i++) {
        if (QueueCountGet(g_innerQueue->queue[i], &queueCount) != 0) {
            continue;
        }
        if (queueCount > 0) {
            return false;
        }
    }
    return IsListEmpty(&g_brQueueList);
}

int32_t BrEnqueueNonBlock(const void *msg)
{
    if (msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    SendBrQueueNode *queueNode = (SendBrQueueNode *)msg;
    int32_t priority = GetPriority(queueNode->flag);
    if (SoftBusMutexLock(&g_brQueueLock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    bool isListEmpty = true;
    if (queueNode->pid == 0 && queueNode->isInner) {
        ret = WaitQueueLength(g_innerQueue->queue[priority], QUEUE_LIMIT[priority], WAIT_QUEUE_BUFFER_PERIOD_LEN, 0);
        if (ret == SOFTBUS_OK) {
            ret = QueueMultiProducerEnqueue(g_innerQueue->queue[priority], msg);
        }
        goto END;
    }
    if (!IsListEmpty(&g_brQueueList)) {
        isListEmpty = false;
    }
    LockFreeQueue *lockFreeQueue = NULL;
    BrQueue *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_brQueueList, BrQueue, node) {
        if (item->pid == queueNode->pid) {
            lockFreeQueue = item->queue[priority];
            break;
        }
    }
    if (lockFreeQueue == NULL) {
        BrQueue *newQueue = CreateBrQueue(queueNode->pid);
        if (newQueue == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "br enqueue create queue fail");
            goto END;
        }
        ListTailInsert(&g_brQueueList, &(newQueue->node));
        lockFreeQueue = newQueue->queue[priority];
    } else {
        ret = WaitQueueLength(lockFreeQueue, QUEUE_LIMIT[priority], WAIT_QUEUE_BUFFER_PERIOD_LEN, queueNode->pid);
        if (ret != SOFTBUS_OK) {
            goto END;
        }
    }
    if (QueueMultiProducerEnqueue(lockFreeQueue, msg) != 0) {
        goto END;
    }
    ret = SOFTBUS_OK;
END:
    if (isListEmpty) {
        (void)SoftBusCondBroadcast(&g_sendCond);
    }
    (void)SoftBusMutexUnlock(&g_brQueueLock);
    return ret;
}

static int32_t GetMsg(BrQueue *queue, void **msg, bool *isFull)
{
    uint32_t queueCount;
    for (uint32_t i = 0; i < QUEUE_NUM_PER_PID; i++) {
        if (QueueCountGet(queue->queue[i], &queueCount) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetMsg get queue count fail");
            continue;
        }
        if (queueCount >= (QUEUE_LIMIT[i] - WAIT_QUEUE_BUFFER_PERIOD_LEN)) {
            (*isFull) = true;
        } else {
            (*isFull) = false;
        }
        if (QueueSingleConsumerDequeue(queue->queue[i], msg) != 0) {
            continue;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int32_t BrDequeueBlock(void **msg)
{
    bool isFull = false;
    int32_t status = SOFTBUS_ERR;
    BrQueue *item = NULL;
    BrQueue *next = NULL;

    if (msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_brQueueLock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    do {
        if (GetMsg(g_innerQueue, msg, &isFull) == SOFTBUS_OK) {
            status = SOFTBUS_OK;
            break;
        }
        LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_brQueueList, BrQueue, node) {
            ListDelete(&(item->node));
            if (GetMsg(item, msg, &isFull) == SOFTBUS_OK) {
                ListTailInsert(&g_brQueueList, &(item->node));
                status = SOFTBUS_OK;
                break;
            }
            DestroyBrQueue(item);
        }
        if (status == SOFTBUS_OK) {
            break;
        }
        CLOGI("br queue is empty, dequeue start wait ...");
        if (SoftBusCondWait(&g_sendCond, &g_brQueueLock, NULL) != SOFTBUS_OK) {
            CLOGI("BrSendCondWait failed");
            status = SOFTBUS_ERR;
            break;
        }
    } while (true);

    if (isFull) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Broadcast g_sendWaitCond");
        (void)SoftBusCondBroadcast(&g_sendWaitCond);
    }
    (void)SoftBusMutexUnlock(&g_brQueueLock);
    return status;
}

int32_t BrInnerQueueInit(void)
{
    if (SoftBusMutexInit(&g_brQueueLock, NULL) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&g_sendWaitCond) != SOFTBUS_OK) {
        (void)SoftBusMutexDestroy(&g_brQueueLock);
        return SOFTBUS_ERR;
    }
    if (SoftBusCondInit(&g_sendCond) != SOFTBUS_OK) {
        (void)SoftBusMutexDestroy(&g_brQueueLock);
        (void)SoftBusCondDestroy(&g_sendWaitCond);
        return SOFTBUS_ERR;
    }
    g_innerQueue = CreateBrQueue(0);
    if (g_innerQueue == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrInnerQueueInit CreateBrQueue(0) failed");
        (void)SoftBusMutexDestroy(&g_brQueueLock);
        (void)SoftBusCondDestroy(&g_sendWaitCond);
        (void)SoftBusCondDestroy(&g_sendCond);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void BrInnerQueueDeinit(void)
{
    (void)SoftBusMutexDestroy(&g_brQueueLock);
    (void)SoftBusCondDestroy(&g_sendWaitCond);
    (void)SoftBusCondDestroy(&g_sendCond);
    DestroyBrQueue(g_innerQueue);
    g_innerQueue = NULL;
}
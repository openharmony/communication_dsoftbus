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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "common_list.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_ble_queue.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_queue.h"
#include "softbus_type_def.h"

#define QUEUE_NUM_PER_PID 3
#define HIGH_PRIORITY_DEFAULT_LIMIT 32
#define MIDDLE_PRIORITY_DEFAULT_LIMIT 32
#define LOW_PRIORITY_DEFAULT_LIMIT 16

typedef struct {
    ListNode node;
    int32_t pid;
    LockFreeQueue *queue[QUEUE_NUM_PER_PID];
} BleQueue;

typedef enum {
    HIGH_PRIORITY = 0,
    MIDDLE_PRIORITY,
    LOW_PRIORITY,
    PRIORITY_BOUNDARY
} QueuePriority;

static const int32_t QUEUE_LIMIT[QUEUE_NUM_PER_PID] = {
    HIGH_PRIORITY_DEFAULT_LIMIT,
    MIDDLE_PRIORITY_DEFAULT_LIMIT,
    LOW_PRIORITY_DEFAULT_LIMIT
};
static LIST_HEAD(g_bleQueueList);
static SoftBusMutex g_bleQueueLock;
static BleQueue *g_innerQueue = NULL;
static SoftBusCond g_sendCond;

static BleQueue *CreateBleQueue(int32_t pid)
{
    BleQueue *queue = (BleQueue *)SoftBusCalloc(sizeof(BleQueue));
    if (queue == NULL) {
        return NULL;
    }
    queue->pid = pid;
    int i;
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

static void DestroyBleQueue(BleQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    for (int i = 0; i < QUEUE_NUM_PER_PID; i++) {
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

int BleEnqueueNonBlock(const void *msg)
{
    if (msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    SendQueueNode *queueNode = (SendQueueNode *)msg;
    int32_t priority = GetPriority(queueNode->flag);
    if (SoftBusMutexLock(&g_bleQueueLock) != EOK) {
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    bool isListEmpty = true;
    if (queueNode->pid == 0) {
        ret = QueueMultiProducerEnqueue(g_innerQueue->queue[priority], msg);
        goto END;
    }

    if (!IsListEmpty(&g_bleQueueList)) {
        isListEmpty = false;
    }
    LockFreeQueue *lockFreeQueue = NULL;
    BleQueue *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_bleQueueList, BleQueue, node) {
        if (item->pid == queueNode->pid) {
            lockFreeQueue = item->queue[priority];
            break;
        }
    }
    if (lockFreeQueue == NULL) {
        BleQueue *newQueue = CreateBleQueue(queueNode->pid);
        if (newQueue == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleEnqueueNonBlock CreateBleQueue failed");
            goto END;
        }
        ListTailInsert(&g_bleQueueList, &(newQueue->node));
        lockFreeQueue = newQueue->queue[priority];
    }
    ret = QueueMultiProducerEnqueue(lockFreeQueue, msg);
END:
    if (isListEmpty) {
        (void)SoftBusCondBroadcast(&g_sendCond);
    }
    (void)SoftBusMutexUnlock(&g_bleQueueLock);
    return ret;
}

static int GetMsg(BleQueue *queue, void **msg)
{
    for (int i = 0; i < QUEUE_NUM_PER_PID; i++) {
        if (QueueSingleConsumerDequeue(queue->queue[i], msg) == 0) {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}

int BleDequeueBlock(void **msg)
{
    int32_t status = SOFTBUS_ERR;
    BleQueue *item = NULL;
    BleQueue *next = NULL;

    if (msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_bleQueueLock) != EOK) {
        return SOFTBUS_LOCK_ERR;
    }
    do {
        if (GetMsg(g_innerQueue, msg) == SOFTBUS_OK) {
            status = SOFTBUS_OK;
            break;
        }
        LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_bleQueueList, BleQueue, node) {
            ListDelete(&(item->node));
            if (GetMsg(item, msg) == SOFTBUS_OK) {
                ListTailInsert(&g_bleQueueList, &(item->node));
                status = SOFTBUS_OK;
                break;
            }
            DestroyBleQueue(item);
        }
        if (status == SOFTBUS_OK) {
            break;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ble queue is empty, dequeue start wait...");
        if (SoftBusCondWait(&g_sendCond, &g_bleQueueLock, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleSendCondWait failed");
            status = SOFTBUS_ERR;
            break;
        }
    } while (true);
    (void)SoftBusMutexUnlock(&g_bleQueueLock);
    return status;
}

int BleInnerQueueInit(void)
{
    if (SoftBusMutexInit(&g_bleQueueLock, NULL) != 0) {
        return SOFTBUS_ERR;
    }
    if (SoftBusCondInit(&g_sendCond) != SOFTBUS_OK) {
        (void)SoftBusMutexDestroy(&g_bleQueueLock);
        return SOFTBUS_ERR;
    }
    g_innerQueue = CreateBleQueue(0);
    if (g_innerQueue == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BleQueueInit CreateBleQueue(0) failed");
        (void)SoftBusMutexDestroy(&g_bleQueueLock);
        (void)SoftBusCondDestroy(&g_sendCond);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void BleInnerQueueDeinit(void)
{
    (void)SoftBusMutexDestroy(&g_bleQueueLock);
    (void)SoftBusCondDestroy(&g_sendCond);
    DestroyBleQueue(g_innerQueue);
    g_innerQueue = NULL;
}
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
#include "softbus_conn_br_send_queue.h"

#include <stdbool.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_common.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_queue.h"

static LIST_HEAD(g_brQueueList);
static SoftBusMutex g_brQueueLock;
static ConnectionQueue *g_innerQueue = NULL;

static SoftBusCond g_sendWaitCond;
static SoftBusCond g_sendCond;

static ConnectionQueue *CreateBrQueue(int32_t pid)
{
    ConnectionQueue *queue = (ConnectionQueue *)SoftBusCalloc(sizeof(ConnectionQueue));
    if (queue == NULL) {
        return NULL;
    }
    queue->pid = pid;
    int32_t i;
    for (i = 0; i < QUEUE_NUM_PER_PID; i++) {
        queue->queue[i] = CreateQueue(GetQueueLimit(i));
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

static void DestroyBrQueue(ConnectionQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    for (uint32_t i = 0; i < QUEUE_NUM_PER_PID; i++) {
        SoftBusFree(queue->queue[i]);
    }
    SoftBusFree(queue);
}

static int32_t GetPriority(int32_t flag)
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

bool ConnBrIsQueueEmpty(void)
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

int32_t ConnBrEnqueueNonBlock(const void *msg)
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
        ret = WaitQueueLength(g_innerQueue->queue[priority], GetQueueLimit(priority), WAIT_QUEUE_BUFFER_PERIOD_LEN,
            &g_sendWaitCond, &g_brQueueLock);
        if (ret == SOFTBUS_OK) {
            ret = QueueMultiProducerEnqueue(g_innerQueue->queue[priority], msg);
        }
        goto END;
    }
    if (!IsListEmpty(&g_brQueueList)) {
        isListEmpty = false;
    }
    LockFreeQueue *lockFreeQueue = NULL;
    ConnectionQueue *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_brQueueList, ConnectionQueue, node) {
        if (item->pid == queueNode->pid) {
            lockFreeQueue = item->queue[priority];
            break;
        }
    }
    if (lockFreeQueue == NULL) {
        ConnectionQueue *newQueue = CreateBrQueue(queueNode->pid);
        if (newQueue == NULL) {
            CONN_LOGE(CONN_BR, "create queue fail");
            goto END;
        }
        ListTailInsert(&g_brQueueList, &(newQueue->node));
        lockFreeQueue = newQueue->queue[priority];
    } else {
        ret = WaitQueueLength(
            lockFreeQueue, GetQueueLimit(priority), WAIT_QUEUE_BUFFER_PERIOD_LEN, &g_sendWaitCond, &g_brQueueLock);
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

int32_t ConnBrDequeueBlock(void **msg)
{
    bool isFull = false;
    int32_t status = SOFTBUS_ERR;
    ConnectionQueue *item = NULL;
    ConnectionQueue *next = NULL;

    if (msg == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_brQueueLock) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    do {
        if (GetMsg(g_innerQueue, msg, &isFull, MIDDLE_PRIORITY) == SOFTBUS_OK) {
            status = SOFTBUS_OK;
            break;
        }
        LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_brQueueList, ConnectionQueue, node) {
            ListDelete(&(item->node));
            if (GetMsg(item, msg, &isFull, LOW_PRIORITY) == SOFTBUS_OK) {
                ListTailInsert(&g_brQueueList, &(item->node));
                status = SOFTBUS_OK;
                break;
            }
            DestroyBrQueue(item);
        }
        if (status == SOFTBUS_OK) {
            break;
        }
        if (GetMsg(g_innerQueue, msg, &isFull, LOW_PRIORITY) == SOFTBUS_OK) {
            status = SOFTBUS_OK;
            break;
        }
        CONN_LOGD(CONN_BR, "br queue is empty, dequeue start wait ...");
        if (SoftBusCondWait(&g_sendCond, &g_brQueueLock, NULL) != SOFTBUS_OK) {
            CONN_LOGD(CONN_BR, "BrSendCondWait failed");
            status = SOFTBUS_ERR;
            break;
        }
    } while (true);

    if (isFull) {
        (void)SoftBusCondBroadcast(&g_sendWaitCond);
    }
    (void)SoftBusMutexUnlock(&g_brQueueLock);
    return status;
}

int32_t ConnBrInnerQueueInit(void)
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
        CONN_LOGE(CONN_BR, "CreateBrQueue failed");
        (void)SoftBusMutexDestroy(&g_brQueueLock);
        (void)SoftBusCondDestroy(&g_sendWaitCond);
        (void)SoftBusCondDestroy(&g_sendCond);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void ConnBrInnerQueueDeinit(void)
{
    (void)SoftBusMutexDestroy(&g_brQueueLock);
    (void)SoftBusCondDestroy(&g_sendWaitCond);
    (void)SoftBusCondDestroy(&g_sendCond);
    DestroyBrQueue(g_innerQueue);
    g_innerQueue = NULL;
}
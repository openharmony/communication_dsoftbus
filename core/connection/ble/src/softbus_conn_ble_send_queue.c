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

#include "common_list.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_common.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_queue.h"

static LIST_HEAD(g_bleQueueList);
static SoftBusMutex g_bleQueueLock;
static ConnectionQueue *g_innerQueue = NULL;
static SoftBusCond g_sendCond;
static SoftBusCond g_sendWaitCond;

static ConnectionQueue *CreateBleQueue(int32_t pid)
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

static void DestroyBleQueue(ConnectionQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    for (int32_t i = 0; i < QUEUE_NUM_PER_PID; i++) {
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

int32_t ConnBleEnqueueNonBlock(const void *msg)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(msg != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "msg is null");
    SendQueueNode *queueNode = (SendQueueNode *)msg;
    int32_t priority = GetPriority(queueNode->flag);
    if (SoftBusMutexLock(&g_bleQueueLock) != EOK) {
        CONN_LOGE(CONN_BLE, "Lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    bool isListEmpty = true;
    int32_t ret = SOFTBUS_ERR;
    if (queueNode->pid == 0) {
        ret = WaitQueueLength(g_innerQueue->queue[priority], GetQueueLimit(priority), WAIT_QUEUE_BUFFER_PERIOD_LEN,
            &g_sendWaitCond, &g_bleQueueLock);
        if (ret == SOFTBUS_OK) {
            ret = QueueMultiProducerEnqueue(g_innerQueue->queue[priority], msg);
        }
        goto END;
    }
    isListEmpty = IsListEmpty(&g_bleQueueList);
    LockFreeQueue *lockFreeQueue = NULL;
    ConnectionQueue *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_bleQueueList, ConnectionQueue, node) {
        if (item->pid == queueNode->pid) {
            lockFreeQueue = item->queue[priority];
            break;
        }
    }
    if (lockFreeQueue == NULL) {
        ConnectionQueue *newQueue = CreateBleQueue(queueNode->pid);
        if (newQueue == NULL) {
            CONN_LOGE(CONN_BLE, "ConnBleEnqueueNonBlock CreateBleQueue failed");
            goto END;
        }
        ListTailInsert(&g_bleQueueList, &(newQueue->node));
        lockFreeQueue = newQueue->queue[priority];
    } else {
        ret = WaitQueueLength(
            lockFreeQueue, GetQueueLimit(priority), WAIT_QUEUE_BUFFER_PERIOD_LEN, &g_sendWaitCond, &g_bleQueueLock);
        if (ret != SOFTBUS_OK) {
            goto END;
        }
    }
    ret = QueueMultiProducerEnqueue(lockFreeQueue, msg);
END:
    if (isListEmpty) {
        (void)SoftBusCondBroadcast(&g_sendCond);
    }
    (void)SoftBusMutexUnlock(&g_bleQueueLock);
    return ret;
}

int32_t ConnBleDequeueBlock(void **msg)
{
    bool isFull = false;
    int32_t status = SOFTBUS_ERR;
    ConnectionQueue *item = NULL;
    ConnectionQueue *next = NULL;
    if (msg == NULL) {
        CONN_LOGE(CONN_BLE, "msg is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_bleQueueLock) != EOK) {
        return SOFTBUS_LOCK_ERR;
    }
    do {
        if (GetMsg(g_innerQueue, msg, &isFull, MIDDLE_PRIORITY) == SOFTBUS_OK) {
            status = SOFTBUS_OK;
            break;
        }
        LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_bleQueueList, ConnectionQueue, node) {
            ListDelete(&(item->node));
            if (GetMsg(item, msg, &isFull, LOW_PRIORITY) == SOFTBUS_OK) {
                ListTailInsert(&g_bleQueueList, &(item->node));
                status = SOFTBUS_OK;
                break;
            }
            DestroyBleQueue(item);
        }
        if (status == SOFTBUS_OK) {
            break;
        }
        if (GetMsg(g_innerQueue, msg, &isFull, LOW_PRIORITY) == SOFTBUS_OK) {
            status = SOFTBUS_OK;
            break;
        }
        CONN_LOGI(CONN_BLE, "ble queue is empty, dequeue start wait...");
        if (SoftBusCondWait(&g_sendCond, &g_bleQueueLock, NULL) != SOFTBUS_OK) {
            CONN_LOGI(CONN_BLE, "BleSendCondWait failed");
            status = SOFTBUS_ERR;
            break;
        }
    } while (true);
    if (isFull) {
        (void)SoftBusCondBroadcast(&g_sendWaitCond);
    }
    (void)SoftBusMutexUnlock(&g_bleQueueLock);
    return status;
}

int32_t ConnBleInitSendQueue(void)
{
    if (SoftBusMutexInit(&g_bleQueueLock, NULL) != 0) {
        CONN_LOGE(CONN_INIT, "Mutex Init failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusCondInit(&g_sendWaitCond) != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "cond Init failed");
        (void)SoftBusMutexDestroy(&g_bleQueueLock);
        return SOFTBUS_ERR;
    }
    if (SoftBusCondInit(&g_sendCond) != SOFTBUS_OK) {
        (void)SoftBusMutexDestroy(&g_bleQueueLock);
        (void)SoftBusCondDestroy(&g_sendWaitCond);
        return SOFTBUS_ERR;
    }
    g_innerQueue = CreateBleQueue(0);
    if (g_innerQueue == NULL) {
        CONN_LOGE(CONN_INIT, "BleQueueInit CreateBleQueue(0) failed");
        (void)SoftBusMutexDestroy(&g_bleQueueLock);
        (void)SoftBusCondDestroy(&g_sendWaitCond);
        (void)SoftBusCondDestroy(&g_sendCond);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void ConnBleDeinitSendQueue(void)
{
    (void)SoftBusMutexDestroy(&g_bleQueueLock);
    (void)SoftBusCondDestroy(&g_sendWaitCond);
    (void)SoftBusCondDestroy(&g_sendCond);
    DestroyBleQueue(g_innerQueue);
    g_innerQueue = NULL;
}
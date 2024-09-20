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

#include "softbus_conn_common.h"

#include "securec.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_socket.h"
#include "softbus_type_def.h"
#include "anonymizer.h"

#define HIGH_PRIORITY_DEFAULT_LIMIT   32
#define MIDDLE_PRIORITY_DEFAULT_LIMIT 32
#define LOW_PRIORITY_DEFAULT_LIMIT    32

#define MICROSECONDS 1000000

static const int32_t QUEUE_LIMIT[QUEUE_NUM_PER_PID] = {
    HIGH_PRIORITY_DEFAULT_LIMIT,
    MIDDLE_PRIORITY_DEFAULT_LIMIT,
    LOW_PRIORITY_DEFAULT_LIMIT,
};

static void AnonymizeData(char *outAnomize, uint32_t anomizeLen, const char *data)
{
    char *temp = NULL;
    Anonymize(data, &temp);
    if (strcpy_s(outAnomize, anomizeLen, AnonymizeWrapper(temp)) != EOK) {
        CONN_LOGE(CONN_COMMON, "copy anonymize data fail");
        AnonymizeFree(temp);
        return;
    }
    AnonymizeFree(temp);
}

int32_t ConnStartActionAsync(void *arg, void *(*runnable)(void *), const char *taskName)
{
    SoftBusThreadAttr attr;
    SoftBusThreadAttrInit(&attr);
    attr.detachState = SOFTBUS_THREAD_DETACH;
    attr.taskName = taskName;
    SoftBusThread actionAsyncThread;
    int32_t status = SoftBusThreadCreate(&actionAsyncThread, &attr, runnable, arg);
    return status;
}

void ConvertAnonymizeMacAddress(char *outAnomize, uint32_t anomizeLen, const char *mac, uint32_t macLen)
{
    if (anomizeLen < BT_MAC_LEN || macLen != BT_MAC_LEN) {
        return;
    }
    AnonymizeData(outAnomize, anomizeLen, mac);
}

void ConvertAnonymizeIpAddress(char *outAnomize, uint32_t anomizeLen, const char *ip, uint32_t ipLen)
{
    if (anomizeLen < IP_LEN || ipLen != IP_LEN) {
        return;
    }
    AnonymizeData(outAnomize, anomizeLen, ip);
}

void ConvertAnonymizeSensitiveString(char *outAnomize, uint32_t anomizeLen, const char *origin)
{
    if (outAnomize == NULL || origin == NULL) {
        return;
    }
    AnonymizeData(outAnomize, anomizeLen, origin);
}

static void ConnFreeMessage(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOGW(msg != NULL, CONN_COMMON, "ATTENTION UNEXPECTED ERROR, try to free a null msg");
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

int32_t ConnPostMsgToLooper(
    SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1, uint64_t arg2, void *obj, uint64_t delayMillis)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    CONN_CHECK_AND_RETURN_RET_LOGE(msg != NULL, SOFTBUS_MEM_ERR, CONN_COMMON,
        "ATTENTION, calloc message object failed: what=%{public}d", what);
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &wrapper->handler;
    msg->FreeMessage = ConnFreeMessage;
    msg->obj = obj;
    wrapper->handler.looper->PostMessageDelay(wrapper->handler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}

void ConnRemoveMsgFromLooper(
    const SoftBusHandlerWrapper *wrapper, int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage ctx = {
        .what = what,
        .arg1 = arg1,
        .arg2 = arg2,
        .obj = obj,
    };
    wrapper->handler.looper->RemoveMessageCustom(
        wrapper->handler.looper, &wrapper->handler, wrapper->eventCompareFunc, &ctx);
}

int32_t ConnNewLimitedBuffer(LimitedBuffer **outLimiteBuffer, uint32_t capacity)
{
    LimitedBuffer *tmpLimiteBuffer = (LimitedBuffer *)SoftBusCalloc(sizeof(LimitedBuffer));
    uint8_t *tmpByteBuffer = (uint8_t *)SoftBusCalloc(capacity * sizeof(uint8_t));
    if (tmpLimiteBuffer == NULL || tmpByteBuffer == NULL) {
        SoftBusFree(tmpLimiteBuffer);
        SoftBusFree(tmpByteBuffer);
        return SOFTBUS_MEM_ERR;
    }
    tmpLimiteBuffer->buffer = tmpByteBuffer;
    tmpLimiteBuffer->capacity = capacity;
    tmpLimiteBuffer->length = 0;
    *outLimiteBuffer = tmpLimiteBuffer;
    return SOFTBUS_OK;
}

void ConnDeleteLimitedBuffer(LimitedBuffer **limiteBuffer)
{
    LimitedBuffer *tmp = *limiteBuffer;
    if (tmp == NULL) {
        return;
    }
    if (tmp->buffer != NULL) {
        SoftBusFree(tmp->buffer);
        tmp->buffer = NULL;
    }
    SoftBusFree(tmp);
    *limiteBuffer = NULL;
}

static int32_t ConnectSoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis)
{
#define USECTONSEC 1000LL
    if (timeMillis == 0) {
        return SoftBusCondWait(cond, mutex, NULL);
    }
    SoftBusSysTime now;
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get time failed");
        return SOFTBUS_CONN_GET_TIME_FAIL;
    }
    now.sec += (now.usec + ((int32_t)timeMillis * USECTONSEC)) / MICROSECONDS;
    now.usec = (now.usec + ((int32_t)timeMillis * USECTONSEC)) % MICROSECONDS;

    return SoftBusCondWait(cond, mutex, &now);
}

int32_t WaitQueueLength(
    const LockFreeQueue *lockFreeQueue, uint32_t maxLen, uint32_t diffLen, SoftBusCond *cond, SoftBusMutex *mutex)
{
#define WAIT_QUEUE_DELAY 1000
    uint32_t queueCount = 0;
    while (true) {
        if (QueueCountGet(lockFreeQueue, &queueCount) != 0) {
            CONN_LOGE(CONN_COMMON, "wait get queue count fail");
            break;
        }
        CONN_LOGD(CONN_COMMON, "queue count=%{public}d", queueCount);
        if (queueCount < (maxLen - diffLen)) {
            break;
        }
        int32_t status = ConnectSoftBusCondWait(cond, mutex, WAIT_QUEUE_DELAY);
        if (status != SOFTBUS_OK && status != SOFTBUS_TIMOUT) {
            CONN_LOGE(CONN_COMMON, "wait queue length cond wait fail");
            return SOFTBUS_CONN_COND_WAIT_FAIL;
        }
    }
    return SOFTBUS_OK;
}

int32_t GetMsg(ConnectionQueue *queue, void **msg, bool *isFull, QueuePriority leastPriority)
{
    uint32_t queueCount;
    for (uint32_t i = 0; i <= leastPriority; i++) {
        if (QueueCountGet(queue->queue[i], &queueCount) != 0) {
            CONN_LOGW(CONN_COMMON, "get queue count fail");
            continue;
        }
        if ((int32_t)queueCount >= (QUEUE_LIMIT[i] - WAIT_QUEUE_BUFFER_PERIOD_LEN)) {
            (*isFull) = true;
        } else {
            (*isFull) = false;
        }
        if (QueueSingleConsumerDequeue(queue->queue[i], msg) != 0) {
            continue;
        }
        return SOFTBUS_OK;
    }
    return SOFTBUS_CONN_GET_MSG_FAIL;
}

uint32_t GetQueueLimit(int32_t index)
{
    if (index >= QUEUE_NUM_PER_PID || index < 0) {
        CONN_LOGE(CONN_COMMON, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    return QUEUE_LIMIT[index];
}
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

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

int32_t ConnStartActionAsync(void *arg, void *(*runnable)(void *))
{
    SoftBusThreadAttr attr;
    SoftBusThreadAttrInit(&attr);
    SoftBusThread ignore;
    int32_t status = SoftBusThreadCreate(&ignore, &attr, runnable, arg);
    return status;
}

void ConvertAnonymizeMacAddress(char *outAnomize, uint32_t anomizeLen, const char *mac, uint32_t macLen)
{
    if (anomizeLen < BT_MAC_LEN || macLen != BT_MAC_LEN) {
        return;
    }

    if (strcpy_s(outAnomize, anomizeLen, mac) != EOK) {
        return;
    }
    // anomize format: 11:**:**:**:44:55
    outAnomize[3] = '*';
    outAnomize[4] = '*';
    outAnomize[6] = '*';
    outAnomize[7] = '*';
    outAnomize[9] = '*';
    outAnomize[10] = '*';
}

void ConvertAnonymizeIpAddress(char *outAnomize, uint32_t anomizeLen, const char *ip, uint32_t ipLen)
{
    if (anomizeLen < IP_LEN || ipLen != IP_LEN) {
        return;
    }

    if (strcpy_s(outAnomize, anomizeLen, ip) != EOK) {
        return;
    }

    uint32_t dotCnt = 0;
    for (uint32_t i = 0; i < anomizeLen; i++) {
        if (outAnomize[i] == '\0') {
            break;
        }

        if (outAnomize[i] == '.') {
            dotCnt += 1;
        } else if (dotCnt >= 1 && dotCnt <= 2) {
            outAnomize[i] = '*';
        }
    }
}

void ConvertAnonymizeSensitiveString(char *outAnomize, uint32_t anomizeLen, const char *origin)
{
    if (outAnomize == NULL || origin == NULL) {
        return;
    }
    uint32_t originStrLen = strlen(origin);
    if (anomizeLen < originStrLen + 1) {
        return;
    }
    if (strcpy_s(outAnomize, anomizeLen, origin) != EOK) {
        return;
    }

    uint32_t anomizeSize = originStrLen / 3;
    for (uint32_t i = anomizeSize; i < originStrLen - anomizeSize; i++) {
        outAnomize[i] = '*';
    }
}

static void ConnFreeMessage(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOG(msg != NULL, "ATTENTION UNEXPECTED ERROR, try to free a null msg");
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
    CONN_CHECK_AND_RETURN_RET_LOG(
        msg != NULL, SOFTBUS_MEM_ERR, "ATTENTION, calloc message object failed: what=%d", what);
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
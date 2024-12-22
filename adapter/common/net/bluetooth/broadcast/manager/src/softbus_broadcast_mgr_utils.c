/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_broadcast_mgr_utils.h"
#include "softbus_error_code.h"

#define BLE_ASYNC_CALLBACK_HANDLER_NAME "BleAsyncHandler"

typedef struct {
    SoftBusMessage msg;
    SoftBusHandler handler;
    BleAsyncCallbackFunc callback;
    void *cbPara;
} AsyncCallbackInfo;

static void AsyncCallbackHandler(SoftBusMessage *msg)
{
    AsyncCallbackInfo *info = NULL;

    DISC_CHECK_AND_RETURN_LOGE(msg != NULL, DISC_BROADCAST, "msg is null");

    info = (AsyncCallbackInfo *)msg->obj;
    DISC_CHECK_AND_RETURN_LOGE(info != NULL, DISC_BROADCAST, "info is null");
    DISC_CHECK_AND_RETURN_LOGE(info->callback != NULL, DISC_BROADCAST, "info callback is null");

    info->callback(info->cbPara);
}

static void FreeAsyncCallbackMessage(SoftBusMessage *msg)
{
    AsyncCallbackInfo *info = NULL;

    DISC_CHECK_AND_RETURN_LOGE(msg != NULL, DISC_BROADCAST, "msg is null");
    DISC_CHECK_AND_RETURN_LOGE(msg->obj != NULL, DISC_BROADCAST, "msg obj is null");

    info = (AsyncCallbackInfo *)msg->obj;
    SoftBusFree(info);
}

static void InitAsyncCallbackMessage(SoftBusMessage *msg, int32_t what, void *obj, SoftBusHandler *handler)
{
    msg->what = what;
    msg->obj = obj;
    msg->handler = handler;
    msg->FreeMessage = FreeAsyncCallbackMessage;
}

static void InitAsyncCallbackHandler(SoftBusHandler *handler, SoftBusLooper *looper)
{
    handler->name = BLE_ASYNC_CALLBACK_HANDLER_NAME;
    handler->looper = looper;
    handler->HandleMessage = AsyncCallbackHandler;
}

static AsyncCallbackInfo *CreateAsyncCallbackInfo(SoftBusLooper *looper, BleAsyncCallbackFunc callback,
    void *para, int32_t msgType)
{
    AsyncCallbackInfo *info = NULL;

    info = SoftBusCalloc(sizeof(AsyncCallbackInfo));
    DISC_CHECK_AND_RETURN_RET_LOGE(info != NULL, info, DISC_BROADCAST, "info is null");

    info->callback = callback;
    info->cbPara = para;
    InitAsyncCallbackHandler(&info->handler, looper);
    InitAsyncCallbackMessage(&info->msg, msgType, (void *)info, &info->handler);
    return info;
}

int32_t BleAsyncCallbackHelper(SoftBusLooper *looper, BleAsyncCallbackFunc callback, void *para)
{
    AsyncCallbackInfo *info = NULL;

    DISC_CHECK_AND_RETURN_RET_LOGE(looper != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "looper is null");
    DISC_CHECK_AND_RETURN_RET_LOGE(callback != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "callback is null");

    info = CreateAsyncCallbackInfo(looper, callback, para, 0);
    DISC_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_MEM_ERR, DISC_BROADCAST, "create callback info failed");

    looper->PostMessage(looper, &info->msg);
    return SOFTBUS_OK;
}

int32_t BleAsyncCallbackDelayHelper(SoftBusLooper *looper, BleAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    AsyncCallbackInfo *info = NULL;

    DISC_CHECK_AND_RETURN_RET_LOGE(looper != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "looper is null");
    DISC_CHECK_AND_RETURN_RET_LOGE(callback != NULL, SOFTBUS_INVALID_PARAM, DISC_BROADCAST, "callback is null");

    info = CreateAsyncCallbackInfo(looper, callback, para, 0);
    DISC_CHECK_AND_RETURN_RET_LOGE(info != NULL, SOFTBUS_MEM_ERR, DISC_BROADCAST, "create callback info failed");

    looper->PostMessageDelay(looper, &info->msg, delayMillis);
    return SOFTBUS_OK;
}

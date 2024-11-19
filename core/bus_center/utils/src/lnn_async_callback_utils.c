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

#include "lnn_async_callback_utils.h"

#include "common_list.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define LNN_ASYNC_CALLBACK_HANDLER_NAME "LnnAsyncHandler"

#define LNN_ASYNC_CALLBACK_REG 0

typedef struct {
    SoftBusMessage msg;
    SoftBusHandler handler;
    LnnAsyncCallbackFunc callback;
    void *cbPara;
} AsyncCallbackInfo;

#define TO_ASYNC_CALLBACK_INFO(cb) CONTAINER_OF(cb, AsyncCallbackInfo, callback)

static void AsyncCallbackHandler(SoftBusMessage *msg)
{
    AsyncCallbackInfo *info = NULL;

    if (msg == NULL) {
        LNN_LOGE(LNN_STATE, "fail async callback recv null msg");
        return;
    }
    info = (AsyncCallbackInfo *)msg->obj;
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "fail async callback recv null info");
        return;
    }
    if (info->callback == NULL) {
        LNN_LOGE(LNN_STATE, "fail async callback function is null");
        return;
    }
    info->callback(info->cbPara);
}

static void FreeAsyncCallbackMessage(SoftBusMessage *msg)
{
    AsyncCallbackInfo *info = NULL;

    if (msg == NULL || msg->obj == NULL) {
        LNN_LOGE(LNN_STATE, "fail: looper or callback is null");
        return;
    }
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
    handler->name = LNN_ASYNC_CALLBACK_HANDLER_NAME;
    handler->looper = looper;
    handler->HandleMessage = AsyncCallbackHandler;
}

static AsyncCallbackInfo *CreateAsyncCallbackInfo(SoftBusLooper *looper,
    LnnAsyncCallbackFunc callback, void *para, int32_t msgType)
{
    AsyncCallbackInfo *info = NULL;

    info = SoftBusCalloc(sizeof(AsyncCallbackInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "fail to malloc async callback info");
        return NULL;
    }
    info->callback = callback;
    info->cbPara = para;
    InitAsyncCallbackHandler(&info->handler, looper);
    InitAsyncCallbackMessage(&info->msg, msgType, (void *)info, &info->handler);
    return info;
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    AsyncCallbackInfo *info = NULL;

    if (looper == NULL || callback == NULL) {
        LNN_LOGE(LNN_STATE, "fail: looper or callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    info = CreateAsyncCallbackInfo(looper, callback, para, LNN_ASYNC_CALLBACK_REG);
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "fail to create async callback info");
        return SOFTBUS_MEM_ERR;
    }
    looper->PostMessage(looper, &info->msg);
    return SOFTBUS_OK;
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    AsyncCallbackInfo *info = NULL;

    if (looper == NULL || callback == NULL) {
        LNN_LOGE(LNN_STATE, "fail: looper or callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    info = CreateAsyncCallbackInfo(looper, callback, para, LNN_ASYNC_CALLBACK_REG);
    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "fail to create async callback info");
        return SOFTBUS_MEM_ERR;
    }
    looper->PostMessageDelay(looper, &info->msg, delayMillis);
    return SOFTBUS_OK;
}

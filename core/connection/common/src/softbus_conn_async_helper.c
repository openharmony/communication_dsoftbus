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

#include "softbus_conn_async_helper.h"

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#include "conn_log.h"

struct AsyncContext {
    ConnAsyncFunction function;
    void *arg;
};

struct CancelContext {
    int32_t callId;
    ConnAsyncFreeHook freeHook;
};

static void FreeMessageHook(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOGE(msg != NULL, CONN_COMMON, "msg is null");
    CONN_CHECK_AND_RETURN_LOGE(msg->obj != NULL, CONN_COMMON, "obj is null");

    struct AsyncContext *ctx = (struct AsyncContext *)msg->obj;
    SoftBusFree(ctx);
    msg->obj = NULL;
    SoftBusFree(msg);
}

static void HandleMessage(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOGE(msg != NULL, CONN_COMMON, "msg is null");
    CONN_CHECK_AND_RETURN_LOGE(msg->obj != NULL, CONN_COMMON, "obj is null");

    struct AsyncContext *ctx = (struct AsyncContext *)msg->obj;
    ctx->function(msg->what, ctx->arg);
    //  it is caller's responsibility to release 'arg'
    ctx->arg = NULL;
    // 'msg' and 'ctx' will be release by 'FreeMessageHook' later
}

int32_t ConnAsyncConstruct(const char *name, ConnAsync *async, SoftBusLooper *looper)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(name != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "name is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(async != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "async is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(looper != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "looper is null");

    async->handler.name = (char *)name;
    async->handler.looper = looper;
    async->handler.HandleMessage = HandleMessage;

    return SOFTBUS_OK;
}

static int32_t RemoveAllAsyncCall(const SoftBusMessage *msg, void *ignore)
{
    (void)ignore;
    CONN_LOGE(CONN_COMMON, "MEMORY LEAK WARNING, it should cancel before destroying, call id=%{public}d", msg->what);
    // 0 stand for match success
    return 0;
}

void ConnAsyncDestruct(ConnAsync *async)
{
    CONN_CHECK_AND_RETURN_LOGE(async != NULL, CONN_COMMON, "async is null");

    SoftBusHandler *handler = &async->handler;
    SoftBusLooper *looper = handler->looper;
    looper->RemoveMessageCustom(looper, handler, RemoveAllAsyncCall, NULL);

    async->handler.name = NULL;
    async->handler.looper = NULL;
    async->handler.HandleMessage = NULL;
}

int32_t ConnAsyncCall(ConnAsync *async, ConnAsyncFunction function, void *arg, uint64_t delayMs)
{
    static uint16_t callIdGenerator = 0;

    CONN_CHECK_AND_RETURN_RET_LOGE(async != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "async is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(function != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "function is null");
    // arg is nullable

    int32_t callId = (++callIdGenerator);
    struct AsyncContext *ctx = SoftBusCalloc(sizeof(struct AsyncContext));
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx, SOFTBUS_MEM_ERR, CONN_COMMON, "malloc async ctx fail");
    ctx->function = function;
    ctx->arg = arg;

    SoftBusMessage *msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        CONN_LOGE(CONN_COMMON, "malloc softbus message fail");
        SoftBusFree(ctx);
        return SOFTBUS_MEM_ERR;
    }
    msg->what = callId;
    msg->obj = ctx;
    msg->handler = &async->handler;
    msg->FreeMessage = FreeMessageHook;

    SoftBusLooper *looper = async->handler.looper;
    looper->PostMessageDelay(looper, msg, delayMs);

    CONN_LOGI(CONN_COMMON, "receive async call, call id=%{public}d, delay=%{public}" PRIu64 "ms", callId, delayMs);
    return callId;
}

static int32_t FreeAsyncCallArg(const SoftBusMessage *msg, void *args)
{
    struct CancelContext *cancelCtx = (struct CancelContext *)args;
    if (msg->what != cancelCtx->callId) {
        // 1 stand for mismatch
        return 1;
    }
    struct AsyncContext *asyncCtx = (struct AsyncContext *)msg->obj;
    if (asyncCtx->arg != NULL) {
        if (cancelCtx->freeHook != NULL) {
            cancelCtx->freeHook(asyncCtx->arg);
            asyncCtx->arg = NULL;
        } else {
            CONN_LOGE(CONN_COMMON, "MEMORY LEAK WARNING, it should provide hook to free memory, call id=%{public}d",
                msg->what);
        }
    }
    // 0 stand for match success
    return 0;
}

void ConnAsyncCancel(ConnAsync *async, int32_t callId, ConnAsyncFreeHook hook)
{
    CONN_CHECK_AND_RETURN_LOGE(async != NULL, CONN_COMMON, "async is null");
    // free hook is nullable

    CONN_LOGI(CONN_COMMON, "cancel async call, call id=%{public}d", callId);
    struct CancelContext ctx = {
        .callId = callId,
        .freeHook = hook,
    };
    SoftBusHandler *handler = &async->handler;
    SoftBusLooper *looper = handler->looper;
    looper->RemoveMessageCustom(looper, handler, FreeAsyncCallArg, &ctx);
}

ConnAsync *ConnAsyncGetInstance(void)
{
    static ConnAsync async = { 0 };
    return &async;
}

int32_t ConnAsyncInit(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_CONN);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        looper, SOFTBUS_INVALID_PARAM, CONN_COMMON, "connection looper is null, init looper module first");

    ConnAsync *async = ConnAsyncGetInstance();
    return ConnAsyncConstruct("conn_async", async, looper);
}

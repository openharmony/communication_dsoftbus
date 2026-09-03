/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "conn_log.h"
#include "softbus_error_code.h"

int32_t ConnAsyncConstruct(const char *name, ConnAsync *async, SoftBusLooper *looper)
{
    (void)name;
    (void)async;
    (void)looper;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void ConnAsyncDestruct(ConnAsync *async)
{
    (void)async;
    CONN_LOGE(CONN_COMMON, "not support");
}

int32_t ConnAsyncCall(ConnAsync *async, ConnAsyncFunction function, void *arg, uint64_t delayMs)
{
    (void)async;
    (void)function;
    (void)arg;
    (void)delayMs;
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void ConnAsyncCancel(ConnAsync *async, int32_t callId, ConnAsyncFreeHook hook)
{
    (void)async;
    (void)callId;
    (void)hook;
    CONN_LOGE(CONN_COMMON, "not support");
}

ConnAsync *ConnAsyncGetInstance(void)
{
    static ConnAsync async = { 0 };
    return &async;
}

int32_t ConnAsyncInit(void)
{
    CONN_LOGE(CONN_COMMON, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

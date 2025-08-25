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

#ifndef SOFTBUS_CONN_ASYNC_HELPER_H
#define SOFTBUS_CONN_ASYNC_HELPER_H

#include "stdint.h"

#include "message_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SoftBusHandler handler;
} ConnAsync;

typedef void (*ConnAsyncFunction)(int32_t callId, void *arg);
typedef void (*ConnAsyncFreeHook)(void *arg);

int32_t ConnAsyncConstruct(const char *name, ConnAsync *async, SoftBusLooper *looper);
void ConnAsyncDestruct(ConnAsync *async);

int32_t ConnAsyncCall(ConnAsync *async, ConnAsyncFunction function, void *arg, uint64_t delayMs);
void ConnAsyncCancel(ConnAsync *async, int32_t callId, ConnAsyncFreeHook hook);

ConnAsync *ConnAsyncGetInstance(void);
int32_t ConnAsyncInit(void);

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_CONN_ASYNC_HELPER_H

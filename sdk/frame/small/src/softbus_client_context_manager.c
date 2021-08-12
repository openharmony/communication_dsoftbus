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

#include "softbus_client_context_manager.h"

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

typedef struct {
    unsigned int handle;
    unsigned int token;
    unsigned int cookie;
    void *ctx;
} SoftBusClientContext;

static SoftBusClientContext *g_clientCtx = NULL;

int ClientContextInit(void)
{
    if (g_clientCtx != NULL) {
        return SOFTBUS_OK;
    }
    g_clientCtx = SoftBusCalloc(sizeof(SoftBusClientContext));
    if (g_clientCtx == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

void ClientContextDeinit(void)
{
    if (g_clientCtx == NULL) {
        return;
    }

    SoftBusFree(g_clientCtx);
    g_clientCtx = NULL;
}

void SetClientIdentity(unsigned int handle, unsigned int token, unsigned int cookie, void *ctx)
{
    if (g_clientCtx == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client ctx not init");
        return;
    }

    g_clientCtx->handle = handle;
    g_clientCtx->token = token;
    g_clientCtx->cookie = cookie;
    g_clientCtx->ctx = ctx;
}

int GetClientIdentity(unsigned int *handle, unsigned int *token, unsigned int *cookie, void **ctx)
{
    if (handle == NULL || token == NULL || cookie == NULL || ctx == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }

    if (g_clientCtx == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client ctx not init");
        return SOFTBUS_ERR;
    }

    *handle = g_clientCtx->handle;
    *token = g_clientCtx->token;
    *cookie = g_clientCtx->cookie;
    *ctx = g_clientCtx->ctx;

    return SOFTBUS_OK;
}

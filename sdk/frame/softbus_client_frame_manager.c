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

#include "softbus_client_frame_manager.h"

#include "securec.h"
#include "softbus_client_frame_manager_weak.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_utils.h"
#ifndef SOFTBUS_WATCH
#include "trans_pending_pkt.h"
#endif
struct SoftBusClientContext {
    char serviceName[PKG_NAME_SIZE_MAX];
    unsigned int handle;
    unsigned int token;
    unsigned int cookie;
    void *ctx;
};

static struct SoftBusClientContext *g_clientCtx = NULL;
static bool g_isInited = false;
static pthread_mutex_t g_isInitedLock = PTHREAD_MUTEX_INITIALIZER;

static void ClientModuleDeinit(void)
{
    EventClientDeinit();
    BusCenterClientDeinit();
    DiscClientDeinit();
    TransClientDeinit();
#ifndef SOFTBUS_WATCH
    PendingDeinit(PENDING_TYPE_DIRECT);
#endif
}

void SetClientIdentity(unsigned int handle, unsigned int token, unsigned int cookie, void *ctx)
{
    if (g_clientCtx == NULL) {
        LOG_ERR("client ctx not init");
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
        LOG_ERR("invalid param");
        return SOFTBUS_ERR;
    }

    if (g_clientCtx == NULL) {
        LOG_ERR("client ctx not init");
        return SOFTBUS_ERR;
    }

    *handle = g_clientCtx->handle;
    *token = g_clientCtx->token;
    *cookie = g_clientCtx->cookie;
    *ctx = g_clientCtx->ctx;

    return SOFTBUS_OK;
}

int GetSoftBusClientName(char *name, unsigned int len)
{
    if (name == NULL || len < PKG_NAME_SIZE_MAX) {
        LOG_ERR("invalid param");
        return SOFTBUS_ERR;
    }

    if (g_clientCtx == NULL) {
        LOG_ERR("ctx not init");
        return SOFTBUS_ERR;
    }

    if (strncpy_s(name, len, g_clientCtx->serviceName, strlen(g_clientCtx->serviceName)) != EOK) {
        LOG_ERR("strcpy fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int ClientModuleInit(const char *pkgName)
{
    g_clientCtx = SoftBusCalloc(sizeof(struct SoftBusClientContext));
    if (g_clientCtx == NULL) {
        LOG_ERR("init ctx fail");
        return SOFTBUS_ERR;
    }

    if (strcpy_s(g_clientCtx->serviceName, sizeof(g_clientCtx->serviceName), pkgName) != EOK) {
        LOG_ERR("strcpy fail");
        SoftBusFree(g_clientCtx);
        return SOFTBUS_ERR;
    }

    if (EventClientInit() == SOFTBUS_ERR) {
        LOG_ERR("init event manager failed");
        goto ERR_EXIT;
    }

    if (BusCenterClientInit() == SOFTBUS_ERR) {
        LOG_ERR("init bus center failed");
        goto ERR_EXIT;
    }

    if (DiscClientInit() == SOFTBUS_ERR) {
        LOG_ERR("init service manager failed");
        goto ERR_EXIT;
    }

    if (TransClientInit() == SOFTBUS_ERR) {
        LOG_ERR("init connect manager failed");
        goto ERR_EXIT;
    }
#ifndef SOFTBUS_WATCH
    if (PendingInit(PENDING_TYPE_DIRECT) == SOFTBUS_ERR) {
        LOG_ERR("trans pending init failed.s");
        goto ERR_EXIT;
    }
#endif
    return SOFTBUS_OK;

ERR_EXIT:
    LOG_ERR("softbus sdk frame init failed.");
    ClientModuleDeinit();
    SoftBusFree(g_clientCtx);
    g_clientCtx = NULL;
    return SOFTBUS_ERR;
}

int InitSoftBus(const char *pkgName)
{
    if (pkgName == NULL || strlen(pkgName) >= PKG_NAME_SIZE_MAX) {
        LOG_ERR("init softbus sdk fail.");
        return SOFTBUS_ERR;
    }

    if (g_isInited == true) {
        return SOFTBUS_OK;
    }

    if (pthread_mutex_lock(&g_isInitedLock) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_isInited == true) {
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_OK;
    }

    if (ClientModuleInit(pkgName) != SOFTBUS_OK) {
        LOG_ERR("ctx init fail");
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    if (ServerProvideInterfaceInit() != SOFTBUS_OK) {
        LOG_ERR("service init fail");
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    if (ClientProvideInterfaceImplInit() != SOFTBUS_OK) {
        LOG_ERR("service init fail");
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    g_isInited = true;
    pthread_mutex_unlock(&g_isInitedLock);
    LOG_INFO("softbus sdk frame init success.");
    return SOFTBUS_OK;
}


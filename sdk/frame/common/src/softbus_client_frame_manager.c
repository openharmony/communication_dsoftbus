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

#include <securec.h>

#include <string.h>
#include "client_bus_center_manager.h"
#include "client_disc_manager.h"
#include "client_trans_session_manager.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static bool g_isInited = false;
static pthread_mutex_t g_isInitedLock = PTHREAD_MUTEX_INITIALIZER;
static char g_pkgName[PKG_NAME_SIZE_MAX] = {0};

static void ClientModuleDeinit(void)
{
    EventClientDeinit();
    BusCenterClientDeinit();
    TransClientDeinit();
    DiscClientDeinit();
}

static int32_t ClientModuleInit()
{
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

    return SOFTBUS_OK;

ERR_EXIT:
    LOG_ERR("softbus sdk frame init failed.");
    ClientModuleDeinit();
    return SOFTBUS_ERR;
}

int32_t InitSoftBus(const char *pkgName)
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

    if (strcpy_s(g_pkgName, sizeof(g_pkgName), pkgName) != EOK) {
        pthread_mutex_unlock(&g_isInitedLock);
        LOG_ERR("strcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (ClientModuleInit() != SOFTBUS_OK) {
        LOG_ERR("ctx init fail");
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    if (ClientStubInit() != SOFTBUS_OK) {
        LOG_ERR("service init fail");
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    g_isInited = true;
    pthread_mutex_unlock(&g_isInitedLock);
    LOG_INFO("softbus sdk frame init success.");
    return SOFTBUS_OK;
}

int32_t GetSoftBusClientName(char *name, uint32_t len)
{
    if (name == NULL || len < PKG_NAME_SIZE_MAX) {
        LOG_ERR("invalid param");
        return SOFTBUS_ERR;
    }

    if (strncpy_s(name, len, g_pkgName, strlen(g_pkgName)) != EOK) {
        LOG_ERR("strcpy fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t CheckPackageName(const char *pkgName)
{
    char clientPkgName[PKG_NAME_SIZE_MAX] = {0};
    if (GetSoftBusClientName(clientPkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK) {
        LOG_ERR("GetSoftBusClientName err");
        return SOFTBUS_INVALID_PKGNAME;
    }
    if (strcmp(clientPkgName, pkgName) != 0) {
        return SOFTBUS_INVALID_PKGNAME;
    }
    return SOFTBUS_OK;
}


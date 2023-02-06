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
#include "softbus_adapter_mem.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static bool g_isInited = false;
static pthread_mutex_t g_isInitedLock = PTHREAD_MUTEX_INITIALIZER;

typedef struct PkgNameInfo {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
} PkgNameInfo;

static pthread_mutex_t g_pkgNameLock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(g_pkgNameList);

static bool CheckPkgNameInfo(const char *pkgName)
{
    ListNode *item = NULL;
    PkgNameInfo *info = NULL;
    uint32_t totalNum = 0;
    LIST_FOR_EACH(item, &g_pkgNameList) {
        totalNum++;
        info = LIST_ENTRY(item, PkgNameInfo, node);
        if (strcmp(info->pkgName, pkgName) == 0) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "exist same pkg name");
            return false;
        }
    }
    if (totalNum > SOFTBUS_PKGNAME_MAX_NUM) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "number of pkgName exceeds maximum");
        return false;
    }
    return true;
}

static int32_t AddClientPkgName(const char *pkgName, bool isInit)
{
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (CheckPkgNameInfo(pkgName) == false) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Add CheckPkgNameInfo failed.");
        (void)pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_ERR;
    }
    PkgNameInfo *info = (PkgNameInfo *)SoftBusCalloc(sizeof(PkgNameInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Create PkgNameInfo malloc fail.");
        pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Add strcpy_s failed.");
        SoftBusFree(info);
        (void)pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_pkgNameList, &info->node);
    if (!isInit) {
        (void)pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_OK;
    }
    int32_t ret = ClientRegisterService(info->pkgName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientRegisterService failed. ret = %d", ret);
        ListDelete(&info->node);
        SoftBusFree(info);
        (void)pthread_mutex_unlock(&g_pkgNameLock);
        return ret;
    }
    (void)pthread_mutex_unlock(&g_pkgNameLock);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientRegisterService success");
    return SOFTBUS_OK;
}

static void FreeClientPkgName(void)
{
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    PkgNameInfo *info = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_pkgNameList) {
        info = LIST_ENTRY(item, PkgNameInfo, node);
        ListDelete(&info->node);
        SoftBusFree(info);
    }
    (void)pthread_mutex_unlock(&g_pkgNameLock);
}

static void ClientModuleDeinit(void)
{
    EventClientDeinit();
    BusCenterClientDeinit();
    TransClientDeinit();
    DiscClientDeinit();
}

static int32_t ClientModuleInit(void)
{
    SoftbusConfigInit();
    if (EventClientInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init event manager failed");
        goto ERR_EXIT;
    }

    if (BusCenterClientInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init bus center failed");
        goto ERR_EXIT;
    }

    if (DiscClientInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init service manager failed");
        goto ERR_EXIT;
    }

    if (TransClientInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init connect manager failed");
        goto ERR_EXIT;
    }

    return SOFTBUS_OK;

ERR_EXIT:
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus sdk frame init failed.");
    ClientModuleDeinit();
    return SOFTBUS_ERR;
}

int32_t InitSoftBus(const char *pkgName)
{
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init softbus sdk fail.");
        return SOFTBUS_ERR;
    }

    if (g_isInited == true) {
        (void)pthread_mutex_lock(&g_isInitedLock);
        (void)AddClientPkgName(pkgName, g_isInited);
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_OK;
    }

    if (pthread_mutex_lock(&g_isInitedLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return SOFTBUS_LOCK_ERR;
    }

    if (g_isInited == true) {
        (void)AddClientPkgName(pkgName, g_isInited);
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_OK;
    }

    if (AddClientPkgName(pkgName, g_isInited) != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_isInitedLock);
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "AddClientPkgName failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusTimerInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client timer init fail");
        FreeClientPkgName();
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    if (ClientModuleInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ctx init fail");
        FreeClientPkgName();
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    if (ClientStubInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "service init fail");
        FreeClientPkgName();
        pthread_mutex_unlock(&g_isInitedLock);
        return SOFTBUS_ERR;
    }

    g_isInited = true;
    pthread_mutex_unlock(&g_isInitedLock);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus sdk frame init success.");
    return SOFTBUS_OK;
}

uint32_t GetSoftBusClientNameList(char *pkgList[], uint32_t len)
{
    if (pkgList == NULL || len == 0) {
        return 0;
    }
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return 0;
    }
    ListNode *item = NULL;
    uint32_t subscript = 0;
    LIST_FOR_EACH(item, &g_pkgNameList) {
        PkgNameInfo *info = LIST_ENTRY(item, PkgNameInfo, node);
        char *pkgName = (char *)SoftBusCalloc(PKG_NAME_SIZE_MAX);
        if (pkgName == NULL) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get client name malloc fail");
            goto EXIT;
        }
        if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX, info->pkgName) != EOK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "get client name strcpy_s failed");
            SoftBusFree(pkgName);
            goto EXIT;
        }
        pkgList[subscript] = pkgName;
        subscript++;
        if (subscript >= len) {
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_pkgNameLock);
    return subscript;

EXIT:
    for (uint32_t i = 0; i < subscript; i++) {
        SoftBusFree(pkgList[i]);
    }
    (void)pthread_mutex_unlock(&g_pkgNameLock);
    return 0;
}

int32_t CheckPackageName(const char *pkgName)
{
#ifdef __LITEOS_M__
    return SOFTBUS_OK;
#endif
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return SOFTBUS_INVALID_PKGNAME;
    }
    ListNode *item = NULL;
    PkgNameInfo *info = NULL;
    LIST_FOR_EACH(item, &g_pkgNameList) {
        info = LIST_ENTRY(item, PkgNameInfo, node);
        if (strcmp(info->pkgName, pkgName) == 0) {
            (void)pthread_mutex_unlock(&g_pkgNameLock);
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&g_pkgNameLock);
    return SOFTBUS_INVALID_PKGNAME;
}


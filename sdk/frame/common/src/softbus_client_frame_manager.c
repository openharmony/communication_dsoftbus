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
#include "softbus_adapter_thread.h"
#include "softbus_base_listener.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_socket.h"
#include "softbus_utils.h"

static bool g_isInited = false;
static SoftBusMutex g_isInitedLock;
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
            return false;
        }
    }
    if (totalNum >= SOFTBUS_PKGNAME_MAX_NUM) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "number of pkgName exceeds maximum");
        return false;
    }
    return true;
}

static int32_t AddClientPkgName(const char *pkgName)
{
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (CheckPkgNameInfo(pkgName) == false) {
        (void)pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_INVALID_PARAM;
    }
    PkgNameInfo *info = (PkgNameInfo *)SoftBusCalloc(sizeof(PkgNameInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Create PkgNameInfo malloc fail.");
        pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Add strcpy_s failed.");
        SoftBusFree(info);
        (void)pthread_mutex_unlock(&g_pkgNameLock);
        return SOFTBUS_MEM_ERR;
    }
    ListInit(&info->node);
    ListAdd(&g_pkgNameList, &info->node);
    (void)pthread_mutex_unlock(&g_pkgNameLock);
    return SOFTBUS_OK;
}

static void DelClientPkgName(const char *pkgName)
{
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "del lock init failed");
        return;
    }
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    PkgNameInfo *info = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_pkgNameList) {
        info = LIST_ENTRY(item, PkgNameInfo, node);
        if (strcmp(pkgName, info->pkgName) == 0) {
            ListDelete(&info->node);
            SoftBusFree(info);
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_pkgNameLock);
}

static int32_t ClientRegisterPkgName(const char *pkgName)
{
    if (AddClientPkgName(pkgName) != SOFTBUS_OK) {
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = ClientRegisterService(pkgName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientRegisterService failed. ret = %d", ret);
        DelClientPkgName(pkgName);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "ClientRegisterService success");
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

static void ConnClientDeinit(void)
{
    (void)DeinitBaseListener();
    (void)ConnDeinitSockets();
}

static void ClientModuleDeinit(void)
{
    EventClientDeinit();
    BusCenterClientDeinit();
    TransClientDeinit();
    ConnClientDeinit();
    DiscClientDeinit();
}

static int32_t ConnClientInit(void)
{
    int32_t ret = ConnInitSockets();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnInitSockets failed!ret=%" PRId32 " \r\n", ret);
        return ret;
    }

    ret = InitBaseListener();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "InitBaseListener failed!ret=%" PRId32 " \r\n", ret);
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "init conn client success");
    return ret;
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

    if (ConnClientInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init connect manager failed");
        goto ERR_EXIT;
    }

    if (TransClientInit() == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init trans manager failed");
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
    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
                   "init softbus sdk fail. Package name is empty or length exceeds");
        return SOFTBUS_INVALID_PARAM;
    }

    if ((g_isInited == false) && (SoftBusMutexInit(&g_isInitedLock, NULL) != SOFTBUS_OK)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return SOFTBUS_LOCK_ERR;
    }

    if (SoftBusMutexLock(&g_isInitedLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_isInited == true) {
        (void)ClientRegisterPkgName(pkgName);
        SoftBusMutexUnlock(&g_isInitedLock);
        return SOFTBUS_OK;
    }

    if (AddClientPkgName(pkgName) != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_isInitedLock);
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "AddClientPkgName failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusTimerInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "client timer init fail");
        goto EXIT;
    }

    if (ClientModuleInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ctx init fail");
        goto EXIT;
    }

    if (ClientStubInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "service init fail");
        goto EXIT;
    }
    if (ClientRegisterService(pkgName) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "ClientRegisterService fail");
        goto EXIT;
    }
    g_isInited = true;
    SoftBusMutexUnlock(&g_isInitedLock);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus sdk frame init success.");
    return SOFTBUS_OK;
EXIT:
    FreeClientPkgName();
    SoftBusMutexUnlock(&g_isInitedLock);
    return SOFTBUS_ERR;
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
    (void)pkgName;
#ifdef __LITEOS_M__
    return SOFTBUS_OK;
#else
    if (pthread_mutex_lock(&g_pkgNameLock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "lock init failed");
        return SOFTBUS_LOCK_ERR;
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
#endif
}


/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_base_listener.h"
#include "softbus_client_event_manager.h"
#include "softbus_client_stub_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_utils.h"

static bool g_isInited = false;
static SoftBusMutex g_isInitedLock;
typedef struct PkgNameInfo {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
} PkgNameInfo;

static SoftBusMutex g_pkgNameLock;
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
        COMM_LOGI(COMM_SDK, "number of pkgName exceeds maximum");
        return false;
    }
    return true;
}

static int32_t AddClientPkgName(const char *pkgName)
{
    if (!CheckPkgNameInfo(pkgName)) {
        COMM_LOGD(COMM_SDK, "check PkgNameInfo invalid.");
        return SOFTBUS_INVALID_PKGNAME;
    }
    if (SoftBusMutexLock(&g_pkgNameLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "lock init failed");
        return SOFTBUS_LOCK_ERR;
    }
    PkgNameInfo *info = (PkgNameInfo *)SoftBusCalloc(sizeof(PkgNameInfo));
    if (info == NULL) {
        COMM_LOGE(COMM_SDK, "Create PkgNameInfo malloc fail.");
        SoftBusMutexUnlock(&g_pkgNameLock);
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(info->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        COMM_LOGE(COMM_SDK, "strcpy_s pkgName failed.");
        SoftBusFree(info);
        SoftBusMutexUnlock(&g_pkgNameLock);
        return SOFTBUS_STRCPY_ERR;
    }
    ListInit(&info->node);
    ListAdd(&g_pkgNameList, &info->node);
    SoftBusMutexUnlock(&g_pkgNameLock);
    return SOFTBUS_OK;
}

static void DelClientPkgName(const char *pkgName)
{
    if (SoftBusMutexLock(&g_pkgNameLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "del lock init failed");
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
    SoftBusMutexUnlock(&g_pkgNameLock);
}

static int32_t ClientRegisterPkgName(const char *pkgName)
{
    int32_t ret = AddClientPkgName(pkgName);
    if (ret != SOFTBUS_OK) {
        COMM_LOGD(COMM_SDK, "AddClientPkgName failed. ret=%{public}d", ret);
        return ret;
    }
    ret = ClientRegisterService(pkgName);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "ClientRegisterService failed. ret=%{public}d", ret);
        DelClientPkgName(pkgName);
        return ret;
    }
    COMM_LOGD(COMM_SDK, "ClientRegisterService success");
    return SOFTBUS_OK;
}

static void FreeClientPkgName(void)
{
    if (SoftBusMutexLock(&g_pkgNameLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "lock init failed");
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
    SoftBusMutexUnlock(&g_pkgNameLock);
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
}

static int32_t ConnClientInit(void)
{
    int32_t ret = ConnInitSockets();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "ConnInitSockets failed! ret=%{public}d", ret);
        return ret;
    }

    ret = InitBaseListener();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_EVENT, "InitBaseListener failed! ret=%{public}d", ret);
        return ret;
    }
    COMM_LOGD(COMM_EVENT, "init conn client success");
    return ret;
}

static int32_t ClientModuleInit(void)
{
    SoftbusConfigInit();
    if (EventClientInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "init event manager failed");
        goto ERR_EXIT;
    }

    if (BusCenterClientInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "init bus center failed");
        goto ERR_EXIT;
    }

    if (ConnClientInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "init connect manager failed");
        goto ERR_EXIT;
    }

    if (TransClientInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "init trans manager failed");
        goto ERR_EXIT;
    }

    return SOFTBUS_OK;

ERR_EXIT:
    COMM_LOGD(COMM_SDK, "softbus sdk frame init failed.");
    ClientModuleDeinit();
    return SOFTBUS_NO_INIT;
}

int32_t InitSoftBus(const char *pkgName)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1),
        SOFTBUS_INVALID_PKGNAME, COMM_SDK, "init softbus sdk fail.Package name is empty or length exceeds");

    COMM_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexInit(
        &g_pkgNameLock, NULL) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_SDK, "lock init pkgName failed");

    COMM_CHECK_AND_RETURN_RET_LOGE((g_isInited || SoftBusMutexInit(
        &g_isInitedLock, NULL) == SOFTBUS_OK), SOFTBUS_LOCK_ERR, COMM_SDK, "lock init failed");

    COMM_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_isInitedLock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, COMM_SDK, "lock failed");

    if (g_isInited) {
        (void)ClientRegisterPkgName(pkgName);
        SoftBusMutexUnlock(&g_isInitedLock);
        return SOFTBUS_OK;
    }
    if (AddClientPkgName(pkgName) != SOFTBUS_OK) {
        SoftBusMutexUnlock(&g_isInitedLock);
        COMM_LOGE(COMM_SDK, "AddClientPkgName failed.");
        return SOFTBUS_INVALID_PKGNAME;
    }
    if (SoftBusTimerInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "client timer init fail");
        goto EXIT;
    }
    if (ClientModuleInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "ctx init fail");
        goto EXIT;
    }
    if (ClientStubInit() != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "service init fail");
        goto EXIT;
    }

    if (ClientRegisterService(pkgName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "ClientRegisterService fail");
        goto EXIT;
    }
    g_isInited = true;
    SoftBusMutexUnlock(&g_isInitedLock);
    COMM_LOGD(COMM_SDK, "softbus sdk frame init success.");
    return SOFTBUS_OK;
EXIT:
    FreeClientPkgName();
    SoftBusMutexUnlock(&g_isInitedLock);
    return SOFTBUS_NO_INIT;
}

uint32_t GetSoftBusClientNameList(char *pkgList[], uint32_t len)
{
    if (pkgList == NULL || len == 0) {
        return 0;
    }
    if (SoftBusMutexLock(&g_pkgNameLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "lock init failed");
        return 0;
    }
    ListNode *item = NULL;
    uint32_t subscript = 0;
    LIST_FOR_EACH(item, &g_pkgNameList) {
        PkgNameInfo *info = LIST_ENTRY(item, PkgNameInfo, node);
        char *pkgName = (char *)SoftBusCalloc(PKG_NAME_SIZE_MAX);
        if (pkgName == NULL) {
            COMM_LOGE(COMM_SDK, "get client name malloc fail");
            goto EXIT;
        }
        if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX, info->pkgName) != EOK) {
            COMM_LOGE(COMM_SDK, "get client name strcpy_s failed");
            SoftBusFree(pkgName);
            goto EXIT;
        }
        pkgList[subscript] = pkgName;
        subscript++;
        if (subscript >= len) {
            break;
        }
    }
    SoftBusMutexUnlock(&g_pkgNameLock);
    return subscript;

EXIT:
    for (uint32_t i = 0; i < subscript; i++) {
        SoftBusFree(pkgList[i]);
    }
    SoftBusMutexUnlock(&g_pkgNameLock);
    return 0;
}

int32_t CheckPackageName(const char *pkgName)
{
    (void)pkgName;
#ifdef __LITEOS_M__
    return SOFTBUS_OK;
#else
    if (SoftBusMutexLock(&g_pkgNameLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SDK, "lock init failed");
        return SOFTBUS_LOCK_ERR;
    }
    ListNode *item = NULL;
    PkgNameInfo *info = NULL;
    LIST_FOR_EACH(item, &g_pkgNameList) {
        info = LIST_ENTRY(item, PkgNameInfo, node);
        if (strcmp(info->pkgName, pkgName) == 0) {
            SoftBusMutexUnlock(&g_pkgNameLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_pkgNameLock);
    return SOFTBUS_INVALID_PKGNAME;
#endif
}

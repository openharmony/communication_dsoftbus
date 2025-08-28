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

#include <securec.h>

#include "access_control.h"
#include "br_proxy.h"
#include "br_proxy_common.h"
#include "br_proxy_server_manager.h"
#include "bus_center_event.h"
#include "hap_uninstall_observer.h"
#include "proxy_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_channel_common.h"
#include "trans_client_proxy.h"
#include "trans_log.h"

#define DEFAULT_INVALID_CHANNEL_ID  (-1)
#define DEFAULT_INVALID_REQ_ID      10000000
#define BR_PROXY_MAX_WAIT_TIME_MS   10000    // 10000ms
#define SINGLE_TIME_MAX_BYTES       4096
#define HAP_NAME_MAX_LEN            256
#define IS_CONNECTED                true
#define IS_DISCONNECTED             false

typedef struct {
    char brMac[BR_MAC_LEN];
    char uuid[UUID_LEN];
} ProxyBaseInfo;

typedef struct {
    pid_t uid;
    uint32_t cnt;
    ListNode node;
}RetryInfo;

typedef struct {
    ProxyBaseInfo proxyInfo;
    char bundleName[HAP_NAME_MAX_LEN];
    char abilityName[HAP_NAME_MAX_LEN];
    int32_t channelId;
    pid_t uid;
    bool isEnable;
    bool isConnected;
    struct ProxyChannel channel;
    ListNode node;
} BrProxyInfo;

typedef struct {
    pid_t callingPid;
    pid_t callingUid;
    uint32_t callingTokenId;
    int32_t channelId;
    uint32_t requestId;
    ProxyBaseInfo proxyInfo;
    bool isReceiveCbSet;
    bool isChannelStateCbSet;
    ListNode node;
    struct ProxyChannel channel;
} ServerBrProxyChannelInfo;

typedef struct {
    uint32_t dataLen;
    char brMac[BR_MAC_LEN];
    char uuid[UUID_LEN];
    uint8_t *data;
    ListNode node;
} ServerDataInfo;

typedef enum {
    PRIORITY_HIGH = 1,
    PRIORITY_LOW,
    PRIORITY_DEFAULT
} RECEIVE_DATA_PRI;

static SoftBusList *g_serverList = NULL;
static SoftBusList *g_dataList = NULL;
static SoftBusList *g_proxyList = NULL;
static SoftBusList *g_retryList = NULL;
static SoftBusMutex g_channelIdLock;
static void ClearCountInRetryList(pid_t uid);

bool IsBrProxy(const char *bundleName)
{
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return false;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(bundleName, nodeInfo->bundleName) != 0) {
            continue;
        }
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return false;
}

static int32_t GetServerListCount(int32_t *count)
{
    if (count == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    *count = g_serverList->cnt;
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return SOFTBUS_OK;
}

static int32_t GetChannelIdFromServerList(int32_t *channelId)
{
    if (channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        *channelId = nodeInfo->channelId;
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return SOFTBUS_NOT_FIND;
}

static int32_t CloseAllBrProxy()
{
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    BrProxyInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_proxyList->list), BrProxyInfo, node) {
        if (nodeInfo->isEnable && nodeInfo->channel.close != NULL) {
            nodeInfo->channel.close(&nodeInfo->channel);
        }
        ListDelete(&nodeInfo->node);
        SoftBusFree(nodeInfo);
        g_proxyList->cnt--;
        TRANS_LOGI(TRANS_SVC, "[br_proxy] brproxy is close");
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_OK;
}

void CloseAllConnect()
{
    int32_t count = 0;
    int32_t ret = GetServerListCount(&count);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get list conut failed! ret:%{public}d", ret);
        return;
    }
    int32_t channelId = 0;
    for (int32_t i = 0; i < count; i++) {
        ret = GetChannelIdFromServerList(&channelId);
        if (ret != SOFTBUS_OK) {
            continue;
        }
        ret = TransCloseBrProxy(channelId, true);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] close brproxy failed! ret:%{public}d, channelId:%{public}d",
                ret, channelId);
            continue;
        }
        TRANS_LOGI(TRANS_SVC, "[br_proxy] close brproxy success! channelId:%{public}d", channelId);
    }
    // if client died, need clear g_proxyList
    CloseAllBrProxy();
}

static void UserSwitchedHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_SWITCHED) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserSwitchState userSwitchState = (SoftBusUserSwitchState)event->status;
    switch (userSwitchState) {
        case SOFTBUS_USER_SWITCHED:
            TRANS_LOGE(TRANS_SVC, "[br_proxy] SOFTBUS_USER_SWITCHED");
            CloseAllConnect();
            break;
        default:
            return;
    }
}

static int32_t RegisterUserSwitchEvent()
{
    static bool flag = true;
    if (!flag) {
        return SOFTBUS_OK;
    }
    int32_t ret = LnnRegisterEventHandler(LNN_EVENT_USER_SWITCHED, UserSwitchedHandler);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] register user switch event success!");
    flag = false;
    return ret;
}

static bool PermissionCheckPass(const char *bundleName)
{
    if (bundleName == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] bundleName is null");
        return false;
    }
    bool isEmpowered = false;
    int32_t ret = ClientIpcQueryPermission(COMM_PKGNAME_PUSH, bundleName, &isEmpowered);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] query permission from push_service failed! ret:%{public}d", ret);
        return false;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] query permission:%{public}s", isEmpowered ? "accept":"denied");
    return isEmpowered;
}

static int32_t GetNewChannelId(int32_t *channelId)
{
    if (channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    static int32_t g_channelId = 0;
    int32_t id = 0;

    if (SoftBusMutexLock(&g_channelIdLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get channelId lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    id = ++g_channelId;
    (void)SoftBusMutexUnlock(&g_channelIdLock);
    *channelId = id;
    return SOFTBUS_OK;
}

static int32_t BrProxyServerInit(void)
{
    if (g_serverList == NULL) {
        g_serverList = CreateSoftBusList();
    }
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] init server list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    if (g_dataList == NULL) {
        g_dataList = CreateSoftBusList();
    }
    if (g_dataList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] init data list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    if (g_proxyList == NULL) {
        g_proxyList = CreateSoftBusList();
    }
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] init proxy list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }

    static bool lockInited = false;
    if (lockInited) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] init trans server success");
        return SOFTBUS_OK;
    }
    int32_t ret = RegisterHapUninstallEvent();
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    if (SoftBusMutexInit(&g_channelIdLock, &mutexAttr) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] init lock failed");
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    lockInited = true;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] init trans server success, channleIdLock init success");
    return SOFTBUS_OK;
}

static int32_t ServerAddDataToList(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen)
{
    if (baseInfo == NULL || data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    ServerDataInfo *info = (ServerDataInfo *)SoftBusCalloc(sizeof(ServerDataInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(info->brMac, sizeof(info->brMac), baseInfo->brMac) != EOK ||
        strcpy_s(info->uuid, sizeof(info->uuid), baseInfo->uuid) != EOK) {
        ret = SOFTBUS_MEM_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    info->data = (uint8_t *)SoftBusCalloc(dataLen * sizeof(uint8_t));
    if (info->data == NULL) {
        ret = SOFTBUS_MEM_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    if (memcpy_s(info->data, dataLen, data, dataLen) != EOK) {
        ret = SOFTBUS_MEM_ERR;
        goto EXIT_WITH_FREE_DATA;
    }
    info->dataLen = dataLen;
    ListInit(&info->node);
    if (SoftBusMutexLock(&(g_dataList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT_WITH_FREE_DATA;
    }
    ListTailInsert(&g_dataList->list, &info->node);
    g_dataList->cnt++;
    (void)SoftBusMutexUnlock(&g_dataList->lock);
    return SOFTBUS_OK;

EXIT_WITH_FREE_DATA:
    SoftBusFree(info->data);
EXIT_WITH_FREE_INFO:
    SoftBusFree(info);
    return ret;
}

static bool IsBrProxyEnable(pid_t uid)
{
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return false;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (nodeInfo->uid != uid) {
            continue;
        }
        bool flag = nodeInfo->isEnable;
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return flag;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return false;
}

static int32_t GetBrProxy(const char *brMac, const char *uuid, BrProxyInfo *info)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL || info == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        int32_t ret = memcpy_s(info, sizeof(BrProxyInfo), nodeInfo, sizeof(BrProxyInfo));
        if (ret != EOK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] memcpy failed! ret=%{public}d", ret);
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_NOT_FIND;
}

static int32_t UpdateBrProxy(const char *brMac, const char *uuid, struct ProxyChannel *channel,
    bool updateChannelId, int32_t channelId)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL || channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        nodeInfo->isEnable = true;
        if (updateChannelId) {
            nodeInfo->channelId = channelId;
            TRANS_LOGI(TRANS_SVC, "[br_proxy] channelId:%{public}d", channelId);
        }
        int32_t ret = memcpy_s(&nodeInfo->channel, sizeof(struct ProxyChannel), channel, sizeof(struct ProxyChannel));
        if (ret != EOK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] memcpy failed! ret:%{public}d", ret);
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    TRANS_LOGE(TRANS_SVC, "[br_proxy] update failed!");
    return SOFTBUS_NOT_FIND;
}

static int32_t UpdateConnectState(const char *brMac, const char *uuid, bool isConnect)
{
    if (brMac == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        nodeInfo->isConnected = isConnect;
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_NOT_FIND;
}

static bool IsBrProxyExist(const char *brMac, const char *uuid) // brmac and uuid determine the unique proxy
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return false;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        TRANS_LOGI(TRANS_SVC, "[br_proxy] the proxy is exist!");
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return false;
}

static int32_t GetCallerInfoAndVerifyPermission(BrProxyInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = GetCallerHapInfo(info->bundleName, HAP_NAME_MAX_LEN, info->abilityName, HAP_NAME_MAX_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get caller hap info failed! ret=%{public}d", ret);
        return ret;
    }
    if (!PermissionCheckPass(info->bundleName)) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get caller hap info failed! ret=%{public}d", ret);
        return SOFTBUS_TRANS_BR_PROXY_CALLER_RESTRICTED;
    }
    return SOFTBUS_OK;
}

static int32_t ServerAddProxyToList(const char *brMac, const char *uuid)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsBrProxyExist(brMac, uuid)) {
        return SOFTBUS_OK;
    }
    int32_t ret = SOFTBUS_OK;
    BrProxyInfo *info = (BrProxyInfo *)SoftBusCalloc(sizeof(BrProxyInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }

    ret = GetCallerInfoAndVerifyPermission(info);
    if (ret != SOFTBUS_OK) {
        goto EXIT_WITH_FREE_INFO;
    }
    if (strcpy_s(info->proxyInfo.brMac, sizeof(info->proxyInfo.brMac), brMac) != EOK ||
        strcpy_s(info->proxyInfo.uuid, sizeof(info->proxyInfo.uuid), uuid) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] copy brMac or uuid failed");
        ret = SOFTBUS_STRCPY_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    info->uid = GetCallerUid();
    info->isEnable = false;
    info->isConnected = IS_DISCONNECTED;
    ListInit(&info->node);
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    ListAdd(&g_proxyList->list, &info->node);
    g_proxyList->cnt++;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] serverInfo add success, cnt:%{public}d", g_proxyList->cnt);
    (void)SoftBusMutexUnlock(&g_proxyList->lock);
    return SOFTBUS_OK;

EXIT_WITH_FREE_INFO:
    SoftBusFree(info);
    return ret;
}

static int32_t ServerDeleteProxyFromList(const char *brMac, const char *uuid)
{
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    BrProxyInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(brMac, nodeInfo->proxyInfo.brMac) != 0 || strcmp(uuid, nodeInfo->proxyInfo.uuid) != 0) {
            continue;
        }
        ListDelete(&nodeInfo->node);
        SoftBusFree(nodeInfo);
        g_proxyList->cnt--;
        TRANS_LOGI(TRANS_SVC, "[br_proxy] brproxy is close");
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_NOT_FIND;
}

static bool IsSessionExist(const char *brMac, const char *uuid)
{
    if (brMac == NULL || uuid == NULL || g_serverList == NULL) {
        return false;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return false;
}

static int32_t ServerAddChannelToList(const char *brMac, const char *uuid, int32_t channelId, uint32_t requestId)
{
    if (brMac == NULL || uuid == NULL || g_serverList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsSessionExist(brMac, uuid)) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] the session is reopen");
        return SOFTBUS_OK;
    }
    int32_t ret = SOFTBUS_OK;
    ServerBrProxyChannelInfo *info = (ServerBrProxyChannelInfo *)SoftBusCalloc(sizeof(ServerBrProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(info->proxyInfo.brMac, sizeof(info->proxyInfo.brMac), brMac) != EOK ||
        strcpy_s(info->proxyInfo.uuid, sizeof(info->proxyInfo.uuid), uuid) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] copy brMac or uuid failed");
        ret = SOFTBUS_STRCPY_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    info->channelId = channelId;
    info->requestId = requestId;
    info->callingPid = GetCallerPid();
    info->callingUid = GetCallerUid();
    info->callingTokenId = GetCallerTokenId();
    ListInit(&info->node);
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    ListAdd(&g_serverList->list, &info->node);
    g_serverList->cnt++;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] serverInfo channelId:%{public}d, cnt:%{public}d", channelId, g_serverList->cnt);
    (void)SoftBusMutexUnlock(&g_serverList->lock);
    return SOFTBUS_OK;

EXIT_WITH_FREE_INFO:
    SoftBusFree(info);
    return ret;
}

static int32_t ServerDeleteChannelFromList(int32_t channelId)
{
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    ServerBrProxyChannelInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (nodeInfo->channelId != channelId) {
            continue;
        }
        ListDelete(&nodeInfo->node);
        SoftBusFree(nodeInfo);
        g_serverList->cnt--;
        TRANS_LOGI(TRANS_SVC, "[br_proxy] by channelId:%{public}d delete node success, cnt%{public}d",
            channelId, g_serverList->cnt);
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return SOFTBUS_NOT_FIND;
}

static int32_t UpdateProxyChannel(const char *brMac, const char *uuid, struct ProxyChannel *channel)
{
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ServerBrProxyChannelInfo *info = NULL;
    LIST_FOR_EACH_ENTRY(info, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (strcmp(brMac, info->proxyInfo.brMac) != 0 || strcmp(uuid, info->proxyInfo.uuid) != 0) {
            continue;
        }
        int32_t ret = memcpy_s(&info->channel, sizeof(struct ProxyChannel), channel, sizeof(struct ProxyChannel));
        if (ret != EOK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] memcpy failed! ret:%{public}d", ret);
            (void)SoftBusMutexUnlock(&(g_serverList->lock));
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    char *tmpName = NULL;
    Anonymize(brMac, &tmpName);
    TRANS_LOGE(TRANS_SVC, "[br_proxy] update failed! brMac=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    return SOFTBUS_NOT_FIND;
}

static int32_t GetChannelInfo(const char *brMac, const char *uuid, int32_t channelId,
    uint32_t requestId, ServerBrProxyChannelInfo *info)
{
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (channelId != DEFAULT_INVALID_CHANNEL_ID) {
            if (nodeInfo->channelId != channelId) {
                continue;
            }
        } else if (requestId != DEFAULT_INVALID_REQ_ID) {
            if (nodeInfo->requestId != requestId) {
                continue;
            }
        } else if (brMac != NULL) {
            if (strcmp(brMac, nodeInfo->proxyInfo.brMac) != 0 || strcmp(uuid, nodeInfo->proxyInfo.uuid) != 0) {
                continue;
            }
        } else {
            continue;
        }
        int32_t ret = memcpy_s(info, sizeof(ServerBrProxyChannelInfo), nodeInfo, sizeof(ServerBrProxyChannelInfo));
        if (ret != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_serverList->lock));
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    char *tmpName = NULL;
    Anonymize(brMac, &tmpName);
    TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! brMac:%{public}s, requestId:%{public}d, channelId:%{public}d",
        AnonymizeWrapper(tmpName), requestId, channelId);
    AnonymizeFree(tmpName);
    if (channelId != DEFAULT_INVALID_CHANNEL_ID) {
        return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
    }
    return SOFTBUS_NOT_FIND;
}

static void onOpenSuccess(uint32_t requestId, struct ProxyChannel *channel)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] channel is null");
        return;
    }
    char *tmpName = NULL;
    Anonymize(channel->brMac, &tmpName);
    TRANS_LOGI(TRANS_SVC, "[br_proxy] OpenSuccess! requestId=%{public}d, brMac:%{public}s", requestId, tmpName);
    AnonymizeFree(tmpName);

    ServerBrProxyChannelInfo nodeInfo = {0};
    int32_t ret = GetChannelInfo(channel->brMac, channel->uuid,
        DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        return;
    }

    ret = UpdateProxyChannel(channel->brMac, channel->uuid, channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }

    ret = UpdateBrProxy(channel->brMac, channel->uuid, channel, true, nodeInfo.channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    ret = UpdateConnectState(channel->brMac, channel->uuid, IS_CONNECTED);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }

    ret = ClientIpcBrProxyOpened(COMM_PKGNAME_BRPROXY, nodeInfo.channelId,
        (const char *)nodeInfo.proxyInfo.brMac, (const char *)nodeInfo.proxyInfo.uuid, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    ClearCountInRetryList(nodeInfo.callingUid);
}

void onOpenFail(uint32_t requestId, int32_t reason)
{
    TRANS_LOGE(TRANS_SVC, "[br_proxy] OpenFail requestId=%{public}d, reason = %{public}d",
        requestId, reason);
    ServerBrProxyChannelInfo info = {0};
    int32_t ret = GetChannelInfo(NULL, NULL, DEFAULT_INVALID_CHANNEL_ID, requestId, &info);
    if (ret != SOFTBUS_OK) {
        return;
    }
    ret = ServerDeleteChannelFromList(info.channelId);
    if (ret != SOFTBUS_OK) {
        return;
    }
    if (!IsBrProxyEnable(info.callingUid)) {
        ret = ServerDeleteProxyFromList(info.proxyInfo.brMac, info.proxyInfo.uuid);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret:%{public}d", ret);
            return;
        }
    }

    ret = ClientIpcBrProxyOpened(COMM_PKGNAME_BRPROXY, DEFAULT_INVALID_CHANNEL_ID,
        (const char *)info.proxyInfo.brMac, (const char *)info.proxyInfo.uuid, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
}

static OpenProxyChannelCallback g_channelOpen = {
    .onOpenSuccess = onOpenSuccess,
    .onOpenFail = onOpenFail,
};

static int32_t ConnectPeerDevice(const char *brMac, const char *uuid, uint32_t *requestId)
{
    ProxyChannelManager *proxyMgr = GetProxyChannelManager();
    if (proxyMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    *requestId = proxyMgr->generateRequestId();
    ProxyChannelParam param;
    param.requestId = *requestId;

    if (strcpy_s(param.brMac, sizeof(param.brMac), brMac) != EOK ||
        strcpy_s(param.uuid, sizeof(param.uuid), uuid) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] copy brMac or uuid failed");
        return SOFTBUS_MEM_ERR;
    }

    param.timeoutMs = BR_PROXY_MAX_WAIT_TIME_MS;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] open br, requestId=%{public}d", *requestId);
    int32_t ret = proxyMgr->openProxyChannel(&param, &g_channelOpen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] openProxyChannel failed, ret=%{public}d", ret);
        return ret;
    }
    return ret;
}

static int32_t GetChannelId(const char *mac, const char *uuid, int32_t *channelId)
{
    if (mac == NULL || uuid == NULL || g_proxyList == NULL || channelId == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, mac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        if (nodeInfo->isEnable) {
            *channelId = nodeInfo->channelId;
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            TRANS_LOGI(TRANS_SVC, "[br_proxy] channelId:%{public}d is exist!", *channelId);
            return SOFTBUS_OK;
        } else {
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    int32_t  ret = GetNewChannelId(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get new channelId failed! ret:%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] new channelId:%{public}d!", *channelId);
    return SOFTBUS_OK;
}

int32_t TransOpenBrProxy(const char *brMac, const char *uuid)
{
    if (brMac == NULL || uuid == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] brMac or uuid is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = BrProxyServerInit();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = RegisterUserSwitchEvent();
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = ServerAddProxyToList(brMac, uuid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return ret;
    }

    uint32_t requestId = 0;
    ret = ConnectPeerDevice(brMac, uuid, &requestId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    int32_t channelId = 0;
    ret = GetChannelId(brMac, uuid, &channelId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = ServerAddChannelToList(brMac, uuid, channelId, requestId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return ret;
    }
    char *brMactmpName = NULL;
    char *uuidtmpName = NULL;
    Anonymize(brMac, &brMactmpName);
    Anonymize(uuid, &uuidtmpName);
    TRANS_LOGI(TRANS_SVC, "[br_proxy] brproxy open! brMac:%{public}s,uuid:%{public}s", brMactmpName, uuidtmpName);
    AnonymizeFree(brMactmpName);
    AnonymizeFree(uuidtmpName);
    return SOFTBUS_OK;
}

int32_t TransCloseBrProxy(int32_t channelId, bool isInnerCall)
{
    TRANS_LOGI(TRANS_SVC, "[br_proxy] enter, channelId:%{public}d", channelId);
    ServerBrProxyChannelInfo info;
    int32_t ret = GetChannelInfo(NULL, NULL, channelId, DEFAULT_INVALID_REQ_ID, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret:%{public}d, channelId:%{public}d", ret, channelId);
        return ret;
    }
    if (!isInnerCall) {
        uint32_t tokenId = GetCallerTokenId();
        if (tokenId != info.callingTokenId) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] tokenid check failed");
            return SOFTBUS_TRANS_BR_PROXY_TOKENID_ERR;
        }
    }
    ret = ServerDeleteProxyFromList(info.proxyInfo.brMac, info.proxyInfo.uuid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret:%{public}d, channelId:%{public}d", ret, channelId);
        return ret;
    }
    ret = ServerDeleteChannelFromList(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret:%{public}d, channelId:%{public}d", ret, channelId);
        return ret;
    }
    info.channel.close(&info.channel);
    return SOFTBUS_OK;
}

int32_t TransSendBrProxyData(int32_t channelId, char* data, uint32_t dataLen)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] enter, channelId:%{public}d, dataLen:%{public}d", channelId, dataLen);

    ServerBrProxyChannelInfo info = {0};
    int32_t ret = GetChannelInfo(NULL, NULL, channelId, DEFAULT_INVALID_REQ_ID, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return ret;
    }
    uint32_t tokenId = GetCallerTokenId();
    if (tokenId != info.callingTokenId) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] tokenid check failed");
        return SOFTBUS_TRANS_BR_PROXY_TOKENID_ERR;
    }
    ret = info.channel.send(&info.channel, (const uint8_t *)data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t SetListenerStateByChannelId(int32_t channelId, ListenerType type, bool isEnable)
{
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (type != DATA_RECEIVE && type != CHANNEL_STATE) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] wrong type:%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (nodeInfo->channelId != channelId) {
            continue;
        }
        switch (type) {
            case DATA_RECEIVE:
                nodeInfo->isReceiveCbSet = isEnable;
                break;
            case CHANNEL_STATE:
                nodeInfo->isChannelStateCbSet = isEnable;
                break;
            default:
                break;
        }
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid channelId:%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

static int32_t SelectClient(ProxyBaseInfo *baseInfo, pid_t *pid, int32_t *channelId)
{
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (strcmp(baseInfo->brMac, nodeInfo->proxyInfo.brMac) != 0 ||
            strcmp(baseInfo->uuid, nodeInfo->proxyInfo.uuid) != 0 || !nodeInfo->isReceiveCbSet) {
            continue;
        }
        *channelId = nodeInfo->channelId;
        *pid = nodeInfo->callingPid;
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return SOFTBUS_NOT_FIND;
}

static void GetDataFromList(ProxyBaseInfo *baseInfo, uint8_t *data, uint32_t dataLen, uint32_t *realLen, bool *isEmpty)
{
    if (g_dataList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return;
    }
    if (SoftBusMutexLock(&(g_dataList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    int32_t ret;
    *isEmpty = true;
    ServerDataInfo *nodeInfo = NULL;
    ServerDataInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_dataList->list), ServerDataInfo, node) {
        if (strcmp(baseInfo->brMac, nodeInfo->brMac) != 0 ||
            strcmp(baseInfo->uuid, nodeInfo->uuid) != 0) {
            continue;
        }
        ret = memcpy_s(data, dataLen, nodeInfo->data, nodeInfo->dataLen);
        if (ret != EOK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] memcpy_s failed! ret:%{public}d", ret);
            (void)SoftBusMutexUnlock(&(g_dataList->lock));
            return;
        }
        *realLen = nodeInfo->dataLen;
        ListDelete(&nodeInfo->node);
        SoftBusFree(nodeInfo->data);
        SoftBusFree(nodeInfo);
        g_dataList->cnt--;
        *isEmpty = false;
        break;
    }
    (void)SoftBusMutexUnlock(&(g_dataList->lock));
    return;
}

static void CleanUpDataListWithSameMac(ProxyBaseInfo *baseInfo, int32_t channelId, pid_t pid)
{
    bool isEmpty = false;
    while (!isEmpty) {
        uint8_t data[SINGLE_TIME_MAX_BYTES] = {0};
        uint32_t realLen = 0;
        GetDataFromList(baseInfo, data, sizeof(data), &realLen, &isEmpty);
        if (isEmpty) {
            return;
        }
        ClientIpcBrProxyReceivedData(COMM_PKGNAME_BRPROXY, channelId, (const uint8_t *)data, realLen);
    }
}

static bool IsForegroundProcess(ProxyBaseInfo *baseInfo)
{
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return false;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (strcmp(baseInfo->brMac, nodeInfo->proxyInfo.brMac) != 0 &&
            strcmp(baseInfo->uuid, nodeInfo->proxyInfo.uuid) != 0) {
            continue;
        }
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    TRANS_LOGI(TRANS_SVC, "[br_proxy] is dead");
    return false;
}

static void DealDataWhenForeground(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen)
{
    pid_t pid = 0;
    int32_t channelId = 0;
    int32_t ret = SelectClient(baseInfo, &pid, &channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] select pid failed! ret:%{public}d", ret);
        return;
    }
    ret = ServerAddDataToList(baseInfo, data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] add data to list failed! ret:%{public}d", ret);
        return;
    }
    CleanUpDataListWithSameMac(baseInfo, channelId, pid);
}

static void DealDataWhenBackground(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen)
{
    int32_t ret = ServerAddDataToList(baseInfo, data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] add to datalist failed. ret:%{public}d", ret);
        return;
    }
    BrProxyInfo info;
    ret = GetBrProxy(baseInfo->brMac, baseInfo->uuid, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get brproxy failed. ret:%{public}d", ret);
        return;
    }
    PullUpHap(info.bundleName, info.abilityName);
}

static void DealWithDataRecv(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen)
{
    bool isForeground = IsForegroundProcess(baseInfo);
    if (isForeground) {
        DealDataWhenForeground(baseInfo, data, dataLen);
    } else {
        DealDataWhenBackground(baseInfo, data, dataLen);
    }
}

static void OnDataReceived(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    if (channel == NULL || data == NULL || dataLen == 0 || dataLen > BR_PROXY_SEND_MAX_LEN) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] channle or data is null or invalid dataLen:%{public}u", dataLen);
        return;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] data recv, requestId:%{public}u, dataLen:%{public}u",
        channel->requestId, dataLen);

    ProxyBaseInfo info;
    if (strcpy_s(info.brMac, sizeof(info.brMac), channel->brMac) != EOK ||
        strcpy_s(info.uuid, sizeof(info.uuid), channel->uuid) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] strcpy failed");
        return;
    }

    DealWithDataRecv(&info, data, dataLen);
}

static void OnDisconnected(struct ProxyChannel *channel, int32_t reason)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] channle is null");
        return;
    }
    char *tmpMacName = NULL;
    char *tmpUuidName = NULL;
    Anonymize(channel->brMac, &tmpMacName);
    Anonymize(channel->uuid, &tmpUuidName);
    TRANS_LOGE(TRANS_SVC, "[br_proxy] disconnect enter! brMac:%{public}s, uuid:%{public}s, reason:%{public}d",
        AnonymizeWrapper(tmpMacName), AnonymizeWrapper(tmpUuidName), reason);
    AnonymizeFree(tmpMacName);
    AnonymizeFree(tmpUuidName);

    ServerBrProxyChannelInfo info = {0};
    int32_t ret = GetChannelInfo(channel->brMac, channel->uuid,
        DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
    if (ret != SOFTBUS_OK) {
        // client is died
        goto EXIT;
    }
    ClientIpcBrProxyStateChanged(COMM_PKGNAME_BRPROXY, info.channelId, reason);
EXIT:
    if (reason == SOFTBUS_CONN_BR_UNPAIRED || reason == SOFTBUS_CONN_PROXY_RETRY_FAILED) {
        CloseAllConnect();
    }
    ret = UpdateConnectState(channel->brMac, channel->uuid, IS_DISCONNECTED);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d", ret);
    }
}

static void OnReconnected(char *addr, struct ProxyChannel *channel)
{
    if (channel == NULL || addr == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] channel or addr is null");
        return;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] reconnect ok");
    int32_t ret = UpdateConnectState(channel->brMac, channel->uuid, IS_CONNECTED);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Update ConnectState failed! ret=%{public}d", ret);
        return;
    }
    if (IsSessionExist(channel->brMac, channel->uuid)) {
        ServerBrProxyChannelInfo info = {0};
        ret = GetChannelInfo(channel->brMac, channel->uuid, DEFAULT_INVALID_CHANNEL_ID, DEFAULT_INVALID_REQ_ID, &info);
        if (ret != SOFTBUS_OK) {
            return;
        }
        ClientIpcBrProxyStateChanged(COMM_PKGNAME_BRPROXY, info.channelId, SOFTBUS_OK);
        UpdateProxyChannel(channel->brMac, channel->uuid, channel);
        UpdateBrProxy(channel->brMac, channel->uuid, channel, false, 0);
        return;
    }
    // the client is dead
    UpdateBrProxy(channel->brMac, channel->uuid, channel, false, 0);
    BrProxyInfo info;
    ret = GetBrProxy(channel->brMac, channel->uuid, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get brproxy failed. ret:%{public}d", ret);
        return;
    }
    PullUpHap(info.bundleName, info.abilityName);
}

static ProxyConnectListener g_channelListener = {
    .onProxyChannelDataReceived = OnDataReceived,
    .onProxyChannelDisconnected = OnDisconnected,
    .onProxyChannelReconnected = OnReconnected,
};

static void SendDataIfExistsInList(int32_t channelId)
{
    ServerBrProxyChannelInfo info = {0};
    int32_t ret = GetChannelInfo(NULL, NULL, channelId, DEFAULT_INVALID_REQ_ID, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return;
    }
    ProxyBaseInfo baseInfo;
    if (strcpy_s(baseInfo.brMac, sizeof(baseInfo.brMac), info.proxyInfo.brMac) != EOK ||
        strcpy_s(baseInfo.uuid, sizeof(baseInfo.uuid), info.proxyInfo.uuid) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] strcpy failed");
        return;
    }
    CleanUpDataListWithSameMac(&baseInfo, channelId, info.callingPid);
}

int32_t TransSetListenerState(int32_t channelId, int32_t type, bool isEnable)
{
    ServerBrProxyChannelInfo info;
    int32_t ret = GetChannelInfo(NULL, NULL, channelId, DEFAULT_INVALID_REQ_ID, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return ret;
    }
    uint32_t tokenId = GetCallerTokenId();
    if (tokenId != info.callingTokenId) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] tokenid check failed");
        return SOFTBUS_TRANS_BR_PROXY_TOKENID_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy], chanId:%{public}d, type:%{public}d, type_desc:%{public}s, isEnable:%{public}s",
        channelId, type, type == DATA_RECEIVE ? "receiveData":"receiveChannelStatus", isEnable ? "on" : "off");
    ret = SetListenerStateByChannelId(channelId, (ListenerType)type, isEnable);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    static bool flag = true;
    if (flag) {
        flag = false;
        ProxyChannelManager *proxyMgr = GetProxyChannelManager();
        proxyMgr->registerProxyChannelListener(&g_channelListener);
    }
    if ((ListenerType)type == DATA_RECEIVE && isEnable) {
        SendDataIfExistsInList(channelId);
    }
    return SOFTBUS_OK;
}

static void ServerDeleteChannelByPid(pid_t callingPid)
{
    TRANS_LOGE(TRANS_SVC, "[br_proxy] enter");
    if (g_serverList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    ServerBrProxyChannelInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] by pid:%{public}d  pid:%{public}d",
            callingPid, nodeInfo->callingPid);
        if (nodeInfo->callingPid != callingPid) {
            continue;
        }
        ListDelete(&nodeInfo->node);
        SoftBusFree(nodeInfo);
        g_serverList->cnt--;
        TRANS_LOGI(TRANS_SVC, "[br_proxy] by pid:%{public}d delete node success, cnt%{public}d",
            callingPid, g_serverList->cnt);
        break;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return;
}

void BrProxyClientDeathClearResource(pid_t callingPid)
{
    ServerDeleteChannelByPid(callingPid);
}

static bool CheckSessionExistByUid(pid_t uid)
{
    if (g_proxyList == NULL) {
        return false;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (nodeInfo->uid != uid) {
            continue;
        }
        bool flag = nodeInfo->isConnected;
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return flag;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return false;
}

static int32_t RetryListInit()
{
    if (g_retryList != NULL) {
        return SOFTBUS_OK;
    }
    g_retryList = CreateSoftBusList();
    if (g_retryList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] init retry list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsUidExist(pid_t uid)
{
    if (g_retryList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return false;
    }
    if (SoftBusMutexLock(&(g_retryList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    RetryInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_retryList->list), RetryInfo, node) {
        if (nodeInfo->uid != uid) {
            continue;
        }
        (void)SoftBusMutexUnlock(&(g_retryList->lock));
        TRANS_LOGI(TRANS_SVC, "[br_proxy] the uid is exist!");
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_retryList->lock));
    return false;
}

static int32_t AddToRetryList(pid_t uid)
{
    if (g_retryList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsUidExist(uid)) {
        return SOFTBUS_OK;
    }
    int32_t ret = SOFTBUS_OK;
    RetryInfo *info = (RetryInfo *)SoftBusCalloc(sizeof(RetryInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }

    info->uid = uid;
    info->cnt = 0;
    ListInit(&info->node);
    if (SoftBusMutexLock(&(g_retryList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT_WITH_FREE_INFO;
    }
    ListAdd(&g_retryList->list, &info->node);
    g_retryList->cnt++;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] retry info add success, cnt:%{public}d", g_retryList->cnt);
    (void)SoftBusMutexUnlock(&g_retryList->lock);
    return SOFTBUS_OK;

EXIT_WITH_FREE_INFO:
    SoftBusFree(info);
    return ret;
}

static int32_t GetCountFromRetryList(pid_t uid, uint32_t *cnt)
{
    if (g_retryList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (cnt == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] cnt is null!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_retryList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    RetryInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_retryList->list), RetryInfo, node) {
        if (nodeInfo->uid != uid) {
            continue;
        }
        *cnt = nodeInfo->cnt;
        nodeInfo->cnt++;
        (void)SoftBusMutexUnlock(&(g_retryList->lock));
        TRANS_LOGI(TRANS_SVC, "[br_proxy] the uid is exist!, cnt:%{public}d", *cnt);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_retryList->lock));
    return SOFTBUS_NOT_FIND;
}

static void ClearCountInRetryList(pid_t uid)
{
    if (g_retryList == NULL) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] no need clear cnt!");
        return;
    }

    if (SoftBusMutexLock(&(g_retryList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    RetryInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_retryList->list), RetryInfo, node) {
        if (nodeInfo->uid != uid) {
            continue;
        }
        nodeInfo->cnt = 0;
        (void)SoftBusMutexUnlock(&(g_retryList->lock));
        TRANS_LOGI(TRANS_SVC, "[br_proxy] the cnt is clear!");
        return;
    }
    (void)SoftBusMutexUnlock(&(g_retryList->lock));
    return;
}

bool TransIsProxyChannelEnabled(pid_t uid)
{
    #define PUSH_MAX_RETRY_TIME 3
    if (CheckSessionExistByUid(uid)) {
        return true;
    }
    int32_t ret = RetryListInit();
    if (ret != SOFTBUS_OK) {
        return false;
    }
    ret = AddToRetryList(uid);
    if (ret != SOFTBUS_OK) {
        return false;
    }
    uint32_t cnt = 0;
    ret = GetCountFromRetryList(uid, &cnt);
    if (ret != SOFTBUS_OK) {
        return false;
    }
    if (cnt < PUSH_MAX_RETRY_TIME) {
        return true;
    }
    return false;
}

int32_t TransRegisterPushHook()
{
    return CheckPushPermission();
}
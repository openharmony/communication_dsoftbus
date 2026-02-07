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
#include "br_proxy_storage.h"
#include "bus_center_event.h"
#include "hap_uninstall_observer.h"
#include "lnn_ohos_account_adapter.h"
#include "proxy_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_channel_common.h"
#include "trans_client_proxy.h"
#include "trans_log.h"

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
    int32_t appIndex;
    int32_t userId;
    uint32_t requestId;
    pid_t uid;
    pid_t pid;
    bool isEnable;
    bool isConnected;
    bool isVirtualConnect;
    bool isRecovery;
    bool isLastConnect;
    struct ProxyChannel channel;
    ListNode node;
} BrProxyInfo;

typedef struct {
    pid_t callingPid;
    pid_t callingUid;
    uint32_t callingTokenId;
    int32_t channelId;
    int32_t appIndex;
    int32_t userId;
    uint32_t requestId;
    ProxyBaseInfo proxyInfo;
    bool isReceiveCbSet;
    bool isChannelStateCbSet;
    ListNode node;
    struct ProxyChannel channel;
} ServerBrProxyChannelInfo;

typedef struct {
    int32_t userId;
    uint32_t dataLen;
    char brMac[BR_MAC_LEN];
    char uuid[UUID_LEN];
    uint8_t *data;
    ListNode node;
} ServerDataInfo;

static SoftBusList *g_serverList = NULL;
static SoftBusList *g_dataList = NULL;
static SoftBusList *g_proxyList = NULL;
static SoftBusList *g_retryList = NULL;
static SoftBusMutex g_channelIdLock;
static void ClearCountInRetryList(pid_t uid);
static int32_t GetCallerInfoAndVerifyPermission(BrProxyInfo *info);
static void OnOpenSuccess(uint32_t requestId, struct ProxyChannel *channel);
static void OnOpenFail(uint32_t requestId, int32_t reason, const char *brMac);
static void OnDataReceived(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen);
static void OnDisconnected(struct ProxyChannel *channel, int32_t reason);
static void OnReconnected(char *addr, struct ProxyChannel *channel);

static OpenProxyChannelCallback g_channelOpen = {
    .onOpenSuccess = OnOpenSuccess,
    .onOpenFail = OnOpenFail,
};

static ProxyConnectListener g_channelListener = {
    .onProxyChannelDataReceived = OnDataReceived,
    .onProxyChannelDisconnected = OnDisconnected,
    .onProxyChannelReconnected = OnReconnected,
};

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
            nodeInfo->channel.close(&nodeInfo->channel, true);
        }
        ListDelete(&nodeInfo->node);
        SoftBusFree(nodeInfo);
        g_proxyList->cnt--;
        TRANS_LOGI(TRANS_SVC, "[br_proxy] brproxy is close");
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_OK;
}

static void CloseAllConnect()
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

static void ListMemFree(ListNode *list)
{
    BrProxyInfo *info = NULL;
    BrProxyInfo *infoNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(info, infoNext, list, BrProxyInfo, node) {
        ListDelete(&info->node);
        SoftBusFree(info);
    }
}

static void CloseOtherUser(int32_t userId)
{
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return;
    }
    ListNode closeList;
    ListInit(&closeList);
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (nodeInfo->userId == userId) {
            continue;
        }
        nodeInfo->isRecovery = true;
        BrProxyInfo *closeInfo = (BrProxyInfo *)SoftBusCalloc(sizeof(BrProxyInfo));
        if (closeInfo == NULL) {
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            ListMemFree(&closeList);
            TRANS_LOGE(TRANS_SVC, "[br_proxy] mem alloc failed");
            return;
        }
        int32_t ret = memcpy_s(closeInfo, sizeof(BrProxyInfo), nodeInfo, sizeof(BrProxyInfo));
        if (ret != EOK) {
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            SoftBusFree(closeInfo);
            ListMemFree(&closeList);
            TRANS_LOGE(TRANS_SVC, "[br_proxy] mem cpy failed, ret=%{public}d", ret);
            return;
        }
        ListAdd(&closeList, &(closeInfo->node));
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));

    BrProxyInfo *info = NULL;
    BrProxyInfo *infoNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(info, infoNext, &closeList, BrProxyInfo, node) {
        if (info->channel.close != NULL) {
            info->channel.close(&info->channel, true);
        }
        ListDelete(&info->node);
        SoftBusFree(info);
    }
}

static int32_t RecoveryConnect(const char *brMac, const char *uuid, uint32_t requestId)
{
    ProxyChannelManager *proxyMgr = GetProxyChannelManager();
    if (proxyMgr == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get proxyMgr failed");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelParam param;
    param.requestId = requestId;

    if (strcpy_s(param.brMac, sizeof(param.brMac), brMac) != EOK ||
        strcpy_s(param.uuid, sizeof(param.uuid), uuid) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] copy brMac or uuid failed");
        return SOFTBUS_MEM_ERR;
    }
    param.timeoutMs = BR_PROXY_MAX_WAIT_TIME_MS;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] recovery connect, requestId=%{public}d", requestId);

    int32_t ret = proxyMgr->openProxyChannel(&param, &g_channelOpen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] openProxyChannel failed, ret=%{public}d", ret);
        return ret;
    }
    return ret;
}

static void RecoveryCurrentUser(int32_t userId)
{
    if (g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return;
    }
    bool flag = false;
    BrProxyInfo recoveryInfo;
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (nodeInfo->userId != userId) {
            continue;
        }
        if (!nodeInfo->isLastConnect) {
            continue;
        }
        int32_t ret = memcpy_s(&recoveryInfo, sizeof(BrProxyInfo), nodeInfo, sizeof(BrProxyInfo));
        if (ret != EOK) {
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            TRANS_LOGE(TRANS_SVC, "[br_proxy] mem cpy failed, ret=%{public}d", ret);
            return;
        }
        flag = true;
        break;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));

    if (!flag) {
        return;
    }

    RecoveryConnect(recoveryInfo.proxyInfo.brMac, recoveryInfo.proxyInfo.uuid, recoveryInfo.requestId);
}

static void BrProxyUserSwitch()
{
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    TRANS_LOGI(TRANS_SVC, "[br_proxy] current userId=%{public}d", userId);
    CloseOtherUser(userId);
    RecoveryCurrentUser(userId);
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
            BrProxyUserSwitch();
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
    static int32_t gChannelId = 0;
    int32_t id = 0;

    if (SoftBusMutexLock(&g_channelIdLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get channelId lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    id = ++gChannelId;
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
    static bool flag = true;
    if (flag) {
        flag = false;
        ProxyChannelManager *proxyMgr = GetProxyChannelManager();
        proxyMgr->registerProxyChannelListener(&g_channelListener);
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
    TRANS_LOGI(TRANS_SVC, "[br_proxy] init trans server success, channelIdLock init success");
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
    info->userId = JudgeDeviceTypeAndGetOsAccountIds();
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

static int32_t GetBrProxy(const char *brMac, const char *uuid, uint32_t requestId, BrProxyInfo *info)
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
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            nodeInfo->requestId != requestId) {
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

static int32_t UpdateBrProxy(ProxyBaseInfo *proxyInfo, int32_t appIndex, struct ProxyChannel *channel,
    bool updateChannelId, int32_t channelId)
{
    if (proxyInfo == NULL || g_proxyList == NULL || channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, proxyInfo->brMac) != 0 ||
            strcmp(nodeInfo->proxyInfo.uuid, proxyInfo->uuid) != 0 ||
            nodeInfo->appIndex != appIndex || nodeInfo->requestId != channel->requestId) {
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

static int32_t UpdateConnectState(const char *brMac, const char *uuid,
    struct ProxyChannel *channel, bool isConnect)
{
    if (brMac == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    bool flag = false;
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            (nodeInfo->requestId != channel->requestId)) {
            continue;
        }
        nodeInfo->isConnected = isConnect;
        if (isConnect == IS_CONNECTED) {
            nodeInfo->isVirtualConnect = false;
            nodeInfo->isRecovery = false;
        }
        flag = true;
        int32_t ret = memcpy_s(&nodeInfo->channel, sizeof(struct ProxyChannel), channel, sizeof(struct ProxyChannel));
        if (ret != EOK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] memcpy failed! ret:%{public}d", ret);
        }
        break;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    if (flag) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

static bool TryToUpdateBrProxy(const char *brMac, const char *uuid, int32_t *appIndex)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return false;
    }
    BrProxyInfo info;
    int32_t ret = GetCallerInfoAndVerifyPermission(&info);
    if (ret != SOFTBUS_OK) {
        return false;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    BrProxyInfo *nodeInfo = NULL;
    BrProxyInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            nodeInfo->appIndex != info.appIndex || nodeInfo->userId != userId) {
            continue;
        }
        nodeInfo->uid = GetCallerUid();
        nodeInfo->pid = GetCallerPid();
        nodeInfo->isRecovery = false;
        *appIndex = info.appIndex;
        if (strcpy_s(nodeInfo->bundleName, HAP_NAME_MAX_LEN, info.bundleName) != EOK ||
            strcpy_s(nodeInfo->abilityName, HAP_NAME_MAX_LEN, info.abilityName) != EOK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] copy bundleName or abilityName failed");
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            return false;
        }
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        TRANS_LOGI(TRANS_SVC, "[br_proxy] the proxy update appindex=%{public}d success!", *appIndex);
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
    int32_t ret = GetCallerHapInfo(info->bundleName, HAP_NAME_MAX_LEN,
        info->abilityName, HAP_NAME_MAX_LEN, &info->appIndex);
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

static int32_t ServerAddProxyToList(const char *brMac, const char *uuid, int32_t *appIndex)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (TryToUpdateBrProxy(brMac, uuid, appIndex)) {
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
    *appIndex = info->appIndex;
    info->uid = GetCallerUid();
    info->pid = GetCallerPid();
    info->userId = JudgeDeviceTypeAndGetOsAccountIds();
    info->isRecovery = false;
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
    TRANS_LOGI(TRANS_SVC, "[br_proxy] serverInfo add success, appIndex:%{public}d, userId:%{public}d, cnt:%{public}d",
        *appIndex, info->userId, g_proxyList->cnt);
    (void)SoftBusMutexUnlock(&g_proxyList->lock);
    return SOFTBUS_OK;

EXIT_WITH_FREE_INFO:
    SoftBusFree(info);
    return ret;
}

static int32_t ServerDisableProxyFromList(uint32_t requestId)
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
        if (nodeInfo->requestId != requestId) {
            continue;
        }
        TRANS_LOGI(TRANS_SVC, "[br_proxy] disable proxy appIndex=%{public}d, userId=%{public}d",
            nodeInfo->appIndex, nodeInfo->userId);
        nodeInfo->isConnected = IS_DISCONNECTED;
        nodeInfo->isEnable = false;
        nodeInfo->isLastConnect = false;
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_NOT_FIND;
}

static bool IsPidExist(ProxyBaseInfo *baseInfo, uint32_t requestId, pid_t pid)
{
    if (g_serverList == NULL) {
        return false;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (strcmp(baseInfo->brMac, nodeInfo->proxyInfo.brMac) != 0 ||
            strcmp(baseInfo->uuid, nodeInfo->proxyInfo.uuid) != 0 ||
            nodeInfo->requestId != requestId || nodeInfo->callingPid != pid) {
            continue;
        }
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return false;
}

static bool IsSessionExist(const char *brMac, const char *uuid, uint32_t requestId, bool needPid)
{
    if (brMac == NULL || uuid == NULL || g_serverList == NULL) {
        return false;
    }
    pid_t callerPid = 0;
    if (needPid) {
        callerPid = GetCallerPid();
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return false;
    }
    ServerBrProxyChannelInfo *nodeInfo = NULL;
    ServerBrProxyChannelInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            (needPid && nodeInfo->callingPid != callerPid)) {
            continue;
        }
        nodeInfo->requestId = requestId;
        (void)SoftBusMutexUnlock(&(g_serverList->lock));
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
    return false;
}

static int32_t ServerAddChannelToList(const char *brMac, const char *uuid,
    int32_t channelId, uint32_t requestId, int32_t appIndex)
{
    if (brMac == NULL || uuid == NULL || g_serverList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsSessionExist(brMac, uuid, requestId, true)) {
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
    info->appIndex = appIndex;
    info->userId = JudgeDeviceTypeAndGetOsAccountIds();
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
    TRANS_LOGI(TRANS_SVC, "[br_proxy] add channel channelId:%{public}d, cnt:%{public}d, appIndex:%{public}d",
        channelId, g_serverList->cnt, appIndex);
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
        if (strcmp(brMac, info->proxyInfo.brMac) != 0 || strcmp(uuid, info->proxyInfo.uuid) != 0 ||
            info->requestId != channel->requestId) {
            continue;
        }
        TRANS_LOGI(TRANS_SVC, "[br_proxy] update appIndex:%{public}d", info->appIndex);
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
    TRANS_LOGE(TRANS_SVC, "[br_proxy] update failed! brMac=%{public}s, requestId=%{public}d",
        tmpName, channel->requestId);
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

static int32_t MarkLastConnect(const char *brMac, const char *uuid, uint32_t requestId)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    bool flag = false;
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            nodeInfo->requestId != requestId) {
            nodeInfo->isLastConnect = false;
            continue;
        }
        nodeInfo->isLastConnect = true;
        flag = true;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    if (flag) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

static void StorageInfo(BrProxyInfo *proxyInfo)
{
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    info.userId = proxyInfo->userId;
    info.appIndex = proxyInfo->appIndex;
    info.uid = proxyInfo->uid;
    int32_t ret = memcpy_s(info.bundleName, sizeof(info.bundleName),
        proxyInfo->bundleName, sizeof(proxyInfo->bundleName));
    if (ret != EOK) {
        return;
    }
    ret = memcpy_s(info.abilityName, sizeof(info.abilityName),
        proxyInfo->abilityName, sizeof(proxyInfo->abilityName));
    if (ret != EOK) {
        return;
    }
    TransBrProxyStorageWrite(TransBrProxyStorageGetInstance(), &info);
}

static void OnOpenSuccess(uint32_t requestId, struct ProxyChannel *channel)
{
    TRANS_CHECK_AND_RETURN_LOGE(channel != NULL, TRANS_SVC, "[br_proxy] channel is null");
    char *tmpName = NULL;
    Anonymize(channel->brMac, &tmpName);
    TRANS_LOGI(TRANS_SVC, "[br_proxy] OpenSuccess! requestId=%{public}d, brMac:%{public}s", requestId, tmpName);
    AnonymizeFree(tmpName);
    ServerBrProxyChannelInfo nodeInfo = {0};
    int32_t ret = GetChannelInfo(NULL, NULL, DEFAULT_INVALID_CHANNEL_ID, channel->requestId, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        return;
    }
    BrProxyInfo info;
    ret = GetBrProxy(channel->brMac, channel->uuid, channel->requestId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    ret = UpdateProxyChannel(channel->brMac, channel->uuid, channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    ret = MarkLastConnect(channel->brMac, channel->uuid, channel->requestId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    ret = UpdateBrProxy(&nodeInfo.proxyInfo, nodeInfo.appIndex, channel, true, nodeInfo.channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    ret = UpdateConnectState(channel->brMac, channel->uuid, channel, IS_CONNECTED);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
    if (!info.isRecovery) {
        ret = ClientIpcBrProxyOpened(nodeInfo.callingPid, nodeInfo.channelId,
            (const char *)nodeInfo.proxyInfo.brMac, (const char *)nodeInfo.proxyInfo.uuid, SOFTBUS_OK);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
            return;
        }
    } else {
        ClientIpcBrProxyStateChanged(nodeInfo.callingPid, nodeInfo.channelId, SOFTBUS_OK);
    }
    ClearCountInRetryList(nodeInfo.callingUid);
    StorageInfo(&info);
}

static int32_t SetCurrentConnect(const char *brMac, const char *uuid, uint32_t requestId, bool isVirtualConnect)
{
    if (brMac == NULL || uuid == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Something that couldn't have happened!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            nodeInfo->requestId != requestId) {
            continue;
        }
        nodeInfo->isVirtualConnect = isVirtualConnect;
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_NOT_FIND;
}

static void OnOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    (void)brMac;
    TRANS_LOGE(TRANS_SVC, "[br_proxy] OpenFail requestId=%{public}d, reason = %{public}d",
        requestId, reason);
    ServerBrProxyChannelInfo info = {0};
    int32_t ret = GetChannelInfo(NULL, NULL, DEFAULT_INVALID_CHANNEL_ID, requestId, &info);
    if (ret != SOFTBUS_OK) {
        return;
    }
    BrProxyInfo proxyInfo;
    ret = GetBrProxy(info.proxyInfo.brMac, info.proxyInfo.uuid, info.requestId, &proxyInfo);
    if (ret == SOFTBUS_OK && proxyInfo.isEnable) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] the connecet requestId=%{public}d is virtual connect", requestId);
        (void)SetCurrentConnect(info.proxyInfo.brMac, info.proxyInfo.uuid, requestId, true);
        ClientIpcBrProxyOpened(info.callingPid, info.channelId,
            (const char *)info.proxyInfo.brMac, (const char *)info.proxyInfo.uuid, SOFTBUS_OK);
        return;
    }
    if (proxyInfo.isRecovery) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] recovery open fail requestId=%{public}d, reason = %{public}d",
            requestId, reason);
        return;
    }
    ret = ServerDeleteChannelFromList(info.channelId);
    if (ret != SOFTBUS_OK) {
        return;
    }
    ret = ClientIpcBrProxyOpened(info.callingPid, DEFAULT_INVALID_CHANNEL_ID,
        (const char *)info.proxyInfo.brMac, (const char *)info.proxyInfo.uuid, reason);
    TransBrProxyRemoveObject(info.callingPid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed! ret=%{public}d requestId=%{public}d", ret, requestId);
        return;
    }
}

static int32_t UpdateBrProxyRequestId(const char *mac, const char *uuid, int32_t appIndex,
    uint32_t requestId, uint32_t *oldRequestId)
{
    if (mac == NULL || uuid == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, mac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            nodeInfo->appIndex != appIndex || nodeInfo->userId != userId) {
            continue;
        }
        *oldRequestId = nodeInfo->requestId;
        nodeInfo->requestId = requestId;
        (void)SoftBusMutexUnlock(&(g_proxyList->lock));
        TRANS_LOGI(TRANS_SVC, "[br_proxy] update appIndex:%{public}d, requestId:%{public}d", appIndex, requestId);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    return SOFTBUS_NOT_FIND;
}

static int32_t GetChannelId(const char *mac, const char *uuid, int32_t *channelId, int32_t appIndex);
static int32_t ConnectPeerDevice(const char *brMac, const char *uuid, uint32_t *requestId, int32_t appIndex)
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

    uint32_t oldRequestId = UINT32_MAX;
    int32_t ret = UpdateBrProxyRequestId(brMac, uuid, appIndex, *requestId, &oldRequestId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }

    int32_t channelId = 0;
    ret = GetChannelId(brMac, uuid, &channelId, appIndex);
    if (ret != SOFTBUS_OK) {
        (void)UpdateBrProxyRequestId(brMac, uuid, appIndex, oldRequestId, &oldRequestId);
        return ret;
    }
    ret = ServerAddChannelToList(brMac, uuid, channelId, *requestId, appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        (void)UpdateBrProxyRequestId(brMac, uuid, appIndex, oldRequestId, &oldRequestId);
        return ret;
    }

    ret = proxyMgr->openProxyChannel(&param, &g_channelOpen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] openProxyChannel failed, ret=%{public}d", ret);
        (void)UpdateBrProxyRequestId(brMac, uuid, appIndex, oldRequestId, &oldRequestId);
        (void)ServerDeleteChannelFromList(channelId);
        return ret;
    }
    return ret;
}

static int32_t GetChannelId(const char *mac, const char *uuid, int32_t *channelId, int32_t appIndex)
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
    BrProxyInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, mac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0) {
            continue;
        }
        if (nodeInfo->channel.close != NULL) {
            nodeInfo->channel.close(&nodeInfo->channel, false);
            TRANS_LOGI(TRANS_SVC, "[br_proxy] appIndex:%{public}d close channel!", nodeInfo->appIndex);
        }
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    int32_t  ret = GetNewChannelId(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get new channelId failed! ret:%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] new channelId:%{public}d! appIndex:%{public}d", *channelId, appIndex);
    return SOFTBUS_OK;
}

static int32_t GetChannelIdAndUserId(const char *mac, const char *uuid, int32_t *channelId, int32_t *userId)
{
    if (mac == NULL || uuid == NULL || channelId == NULL || userId == NULL || g_proxyList == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    BrProxyInfo *nodeInfo = NULL;
    BrProxyInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_proxyList->list), BrProxyInfo, node) {
        if (strcmp(nodeInfo->proxyInfo.brMac, mac) == 0 && strcmp(nodeInfo->proxyInfo.uuid, uuid) == 0) {
            *channelId = nodeInfo->channelId;
            *userId = nodeInfo->userId;
            (void)SoftBusMutexUnlock(&(g_proxyList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));
    TRANS_LOGI(TRANS_SVC, "[br_proxy] not find");
    return SOFTBUS_NOT_FIND;
}

static void PrintSession(const char *brMac, const char *uuid)
{
    if (brMac == NULL || uuid == NULL) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] brMac or uuid is NULL");
        return;
    }
    char *brMactmpName = NULL;
    char *uuidtmpName = NULL;
    Anonymize(brMac, &brMactmpName);
    Anonymize(uuid, &uuidtmpName);
    TRANS_LOGI(TRANS_SVC, "[br_proxy] brproxy open! brMac=%{public}s,uuid=%{public}s", brMactmpName, uuidtmpName);
    AnonymizeFree(brMactmpName);
    AnonymizeFree(uuidtmpName);
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
    BrProxyLoopInit();
    int32_t appIndex = DEFAULT_APPINDEX;
    ret = ServerAddProxyToList(brMac, uuid, &appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret=%{public}d", ret);
        return ret;
    }
    TransEventExtra extra = {0};
    uint32_t requestId = 0;
    int32_t channelId = 0;
    int32_t userId = 0;
    ret = ConnectPeerDevice(brMac, uuid, &requestId, appIndex);
    GetChannelIdAndUserId(brMac, uuid, &channelId, &userId);
    extra.errcode = ret;
    extra.channelId = channelId;
    extra.requestId = requestId;
    extra.userId = userId;
    extra.appIndex = appIndex;
    if (ret != SOFTBUS_OK) {
        extra.result = EVENT_STAGE_RESULT_FAILED;
        TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_OPEN_CHANNEL, extra);
        return ret;
    }
    extra.result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_OPEN_CHANNEL, extra);
    PrintSession(brMac, uuid);
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
    if (info.channel.close != NULL) {
        info.channel.close(&info.channel, true);
        TRANS_LOGE(TRANS_SVC, "[br_proxy] close channel");
    }
    TransBrProxyRemoveObject(info.callingPid);
    ServerDisableProxyFromList(info.requestId);
    ServerDeleteChannelFromList(channelId);
    TransBrProxyStorageClear(TransBrProxyStorageGetInstance());
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
    if (info.channel.send == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] send method is null");
        return SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL;
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

static int32_t SelectClient(ProxyBaseInfo *baseInfo, pid_t *pid, int32_t *channelId, uint32_t requestId)
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
            strcmp(baseInfo->uuid, nodeInfo->proxyInfo.uuid) != 0 || !nodeInfo->isReceiveCbSet ||
            nodeInfo->requestId != requestId) {
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

static void GetDataFromList(ProxyBaseInfo *baseInfo, uint8_t **data, uint32_t *realLen, bool *isEmpty)
{
    if (g_dataList == NULL || baseInfo == NULL || realLen == NULL || isEmpty == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] not init");
        return;
    }
    if (SoftBusMutexLock(&(g_dataList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    int32_t ret;
    *isEmpty = true;
    ServerDataInfo *nodeInfo = NULL;
    ServerDataInfo *nodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(nodeInfo, nodeNext, &(g_dataList->list), ServerDataInfo, node) {
        if (strcmp(baseInfo->brMac, nodeInfo->brMac) != 0 ||
            strcmp(baseInfo->uuid, nodeInfo->uuid) != 0 || nodeInfo->userId != userId) {
            continue;
        }
        *data = (uint8_t *)SoftBusCalloc(nodeInfo->dataLen * sizeof(uint8_t));
        if (*data == NULL) {
            TRANS_LOGE(TRANS_SVC, "[br_proxy] calloc failed!");
            (void)SoftBusMutexUnlock(&(g_dataList->lock));
            return;
        }
        ret = memcpy_s(*data, nodeInfo->dataLen, nodeInfo->data, nodeInfo->dataLen);
        if (ret != EOK) {
            SoftBusFree(*data);
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

static int32_t PostStopAppEvent(const char *bundleName, pid_t pid, pid_t uid)
{
    StopAppInfo *info = (StopAppInfo *)SoftBusCalloc(sizeof(StopAppInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    errno_t result = strcpy_s(info->bundleName, sizeof(info->bundleName), bundleName);
    if (result != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] cpy bundle name failed:%{public}d", result);
        SoftBusFree(info);
        return SOFTBUS_STRCPY_ERR;
    }
    info->pid = pid;
    info->uid = uid;
    int32_t ret = BrProxyPostMsgToLooper(LOOP_STOP_APP_MSG, 0, 0, info, BR_PROXY_STOP_APP_DELAY_MS);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] post to looper failed:%{public}d", ret);
        SoftBusFree(info);
    }
    return ret;
}

int32_t ApplyForUnrestricted(int32_t channelId)
{
    ServerBrProxyChannelInfo info;
    int32_t ret = GetChannelInfo(NULL, NULL, channelId, DEFAULT_INVALID_REQ_ID, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] failed, ret:%{public}d, channelId:%{public}d", ret, channelId);
        return ret;
    }

    BrProxyInfo proxyInfo;
    ret = GetBrProxy(info.proxyInfo.brMac, info.proxyInfo.uuid, info.requestId, &proxyInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get brproxy failed. ret:%{public}d", ret);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] channelId:%{public}d, pid:%{public}d, uid:%{public}d",
        channelId, info.callingPid, info.callingUid);
    BrProxyRemoveMsgFromLooper(LOOP_STOP_APP_MSG, 0, 0, NULL);
    ret = BrProxyUnrestricted(proxyInfo.bundleName, info.callingPid, info.callingUid, true);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret,
        TRANS_SVC, "[br_proxy] BrProxyUnrestricted err=%{public}d", ret);
    return PostStopAppEvent(proxyInfo.bundleName, info.callingPid, info.callingUid);
}

static void CleanUpDataListWithSameMac(ProxyBaseInfo *baseInfo, int32_t channelId, pid_t pid)
{
    bool isEmpty = false;
    while (!isEmpty) {
        uint8_t *data = NULL;
        uint32_t realLen = 0;
        GetDataFromList(baseInfo, &data, &realLen, &isEmpty);
        if (isEmpty) {
            return;
        }
        ClientIpcBrProxyReceivedData(pid, channelId, (const uint8_t *)data, realLen);
        SoftBusFree(data);
    }
}

static void DealDataWhenForeground(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen, uint32_t requestId)
{
    pid_t pid = 0;
    int32_t channelId = 0;
    int32_t ret = ServerAddDataToList(baseInfo, data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] add data to list failed! ret:%{public}d", ret);
        return;
    }
    ret = SelectClient(baseInfo, &pid, &channelId, requestId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] select pid failed! ret:%{public}d", ret);
        return;
    }

    CleanUpDataListWithSameMac(baseInfo, channelId, pid);
}

static void DealDataWhenBackground(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen, uint32_t requestId)
{
    int32_t ret = ServerAddDataToList(baseInfo, data, dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] add to datalist failed. ret:%{public}d", ret);
        return;
    }

    BrProxyInfo info;
    ret = GetBrProxy(baseInfo->brMac, baseInfo->uuid, requestId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get brproxy failed. ret:%{public}d", ret);
        return;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] start pull up hap");
    ret = PullUpHap(info.bundleName, info.abilityName, info.appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] pull up hap failed. ret:%{public}d", ret);
        return;
    }
}

static bool IsProcExist(ProxyBaseInfo *baseInfo, uint32_t requestId)
{
    if (baseInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] baseInfo is nullptr");
        return false;
    }
    BrProxyInfo info;
    int32_t ret = GetBrProxy(baseInfo->brMac, baseInfo->uuid, requestId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get brproxy failed. ret:%{public}d", ret);
        return false;
    }
    pid_t pid = 0;
    if (CommonGetRunningProcessInformation(info.bundleName, info.userId, info.uid, &pid) &&
        IsPidExist(baseInfo, requestId, pid)) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] pid:%{public}d exist, appIndex:%{public}d", pid, info.appIndex);
        return true;
    }
    return false;
}

static void DealWithDataRecv(ProxyBaseInfo *baseInfo, const uint8_t *data, uint32_t dataLen, uint32_t requestId)
{
    bool isForeground = IsProcExist(baseInfo, requestId);
    if (isForeground) {
        DealDataWhenForeground(baseInfo, data, dataLen, requestId);
    } else {
        DealDataWhenBackground(baseInfo, data, dataLen, requestId);
    }
}

static void OnDataReceived(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    if (channel == NULL || data == NULL || dataLen == 0 || dataLen > BR_PROXY_SEND_MAX_LEN) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] channel or data is null or invalid dataLen:%{public}u", dataLen);
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

    DealWithDataRecv(&info, data, dataLen, channel->requestId);
}

static void OnDisconnected(struct ProxyChannel *channel, int32_t reason)
{
    if (channel == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] channel is null");
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
    TransEventExtra extra = {0};
    ServerBrProxyChannelInfo info = {0};
    int32_t ret = GetChannelInfo(NULL, NULL,
        DEFAULT_INVALID_CHANNEL_ID, channel->requestId, &info);
    if (ret != SOFTBUS_OK) {
        // client is died
        goto EXIT;
    }
    ClientIpcBrProxyStateChanged(info.callingPid, info.channelId, reason);
    extra.result = EVENT_STAGE_RESULT_OK;
    extra.errcode = reason;
    extra.channelId = channel->channelId;
    extra.requestId = channel->requestId;
    TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_DISCONNECT, extra);
EXIT:
    if (reason == SOFTBUS_CONN_BR_UNPAIRED) {
        CloseAllConnect();
    }
    ret = UpdateConnectState(channel->brMac, channel->uuid, channel, IS_DISCONNECTED);
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
    TRANS_LOGI(TRANS_SVC, "[br_proxy] reconnect ok, reqId=%{public}d, channelId=%{public}d",
        channel->requestId, channel->channelId);
    int32_t ret = UpdateConnectState(channel->brMac, channel->uuid, channel, IS_CONNECTED);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] Update ConnectState failed! ret=%{public}d", ret);
        return;
    }
    ServerBrProxyChannelInfo info = {0};
    ret = GetChannelInfo(NULL, NULL, DEFAULT_INVALID_CHANNEL_ID, channel->requestId, &info);
    if (ret != SOFTBUS_OK) {
        return;
    }
    UpdateProxyChannel(channel->brMac, channel->uuid, channel);
    ClientIpcBrProxyStateChanged(info.callingPid, info.channelId, SOFTBUS_OK);
    TransEventExtra extra = {0};
    extra.channelId = channel->channelId;
    extra.requestId = channel->requestId;
    TRANS_EVENT(EVENT_SCENE_TRANS_BR_PROXY, EVENT_STAGE_RECONNECT, extra);
}

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

static int32_t GetBrProxyByPid(const char *brMac, const char *uuid, pid_t pid, BrProxyInfo *info)
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
        if (strcmp(nodeInfo->proxyInfo.brMac, brMac) != 0 || strcmp(nodeInfo->proxyInfo.uuid, uuid) != 0 ||
            nodeInfo->pid != pid) {
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

static void NotifyChannelState(const char *brMac, const char *uuid, int32_t channelId, pid_t pid)
{
    BrProxyInfo info;
    int32_t ret = GetBrProxyByPid(brMac, uuid, pid, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get brproxy failed. ret:%{public}d", ret);
        return;
    }
    if (info.isVirtualConnect) {
        ClientIpcBrProxyStateChanged(pid, channelId, SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED);
    }
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
    if ((ListenerType)type == DATA_RECEIVE && isEnable) {
        SendDataIfExistsInList(channelId);
    }
    if ((ListenerType)type == CHANNEL_STATE && isEnable) {
        NotifyChannelState(info.proxyInfo.brMac, info.proxyInfo.uuid, channelId, GetCallerPid());
    }
    return SOFTBUS_OK;
}

static void ServerDeleteChannelByPid(pid_t callingPid)
{
    if (g_serverList == NULL) {
        TRANS_LOGD(TRANS_SVC, "[br_proxy] not init");
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
        TransBrProxyRemoveObject(callingPid);
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
        if (nodeInfo->uid != uid || !nodeInfo->isConnected) {
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
    #define PUSH_MAX_RETRY_TIME 1
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

void TransBrProxyRemoveObject(int32_t pid)
{
    int32_t ret = BrProxyRemoveObject(COMM_PKGNAME_BRPROXY, pid);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] remove object failed! ret=%{public}d", ret);
    }
}

void UninstallHandler(const char *bundleName, int32_t appIndex, int32_t userId)
{
    (void)bundleName;
    if (g_proxyList == NULL) {
        TRANS_LOGW(TRANS_SVC, "[br_proxy] proxy list not init!");
        return;
    }
    if (SoftBusMutexLock(&(g_proxyList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    BrProxyInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_proxyList->list), BrProxyInfo, node) {
        if (nodeInfo->appIndex != appIndex || nodeInfo->userId != userId) {
            continue;
        }
        nodeInfo->isEnable = false;
        nodeInfo->channel.close(&nodeInfo->channel, true);
        TRANS_LOGI(TRANS_SVC, "[br_proxy] close channel, uinstall appIndex=%{public}d, userId=%{public}d",
            appIndex, userId);
    }
    (void)SoftBusMutexUnlock(&(g_proxyList->lock));

    if (g_serverList == NULL) {
        TRANS_LOGD(TRANS_SVC, "[br_proxy] not init");
        return;
    }
    if (SoftBusMutexLock(&(g_serverList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] lock failed");
        return;
    }
    ServerBrProxyChannelInfo *info = NULL;
    ServerBrProxyChannelInfo *infoNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(info, infoNext, &(g_serverList->list), ServerBrProxyChannelInfo, node) {
        if (info->appIndex != appIndex || info->userId != userId) {
            continue;
        }
        ListDelete(&info->node);
        TransBrProxyRemoveObject(info->callingPid);
        SoftBusFree(info);
        g_serverList->cnt--;
        TRANS_LOGI(TRANS_SVC, "[br_proxy] del node, uinstall cnt=%{public}d, appIndex=%{public}d, userId=%{public}d",
            g_serverList->cnt, appIndex, userId);
    }
    (void)SoftBusMutexUnlock(&(g_serverList->lock));
}

void TransBrProxyInit(void)
{
    DynamicLoadInit();
    TransBrProxyStorageInfo info;
    (void)memset_s(&info, sizeof(TransBrProxyStorageInfo), 0, sizeof(TransBrProxyStorageInfo));
    bool flag = TransBrProxyStorageRead(TransBrProxyStorageGetInstance(), &info);
    if (!flag) {
        return;
    }
    int32_t ret = PullUpHap(info.bundleName, info.abilityName, info.appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] pull up hap failed. ret:%{public}d", ret);
        return;
    }
}
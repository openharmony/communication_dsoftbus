/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "client_bus_center_manager.h"

#include <pthread.h>
#include <securec.h>

#include "bus_center_server_proxy.h"
#include "common_list.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#define DEFAULT_NODE_STATE_CB_CNT 10
#define MAX_IPC_LEN 1024

static int32_t g_maxNodeStateCbCount;

typedef struct {
    ListNode node;
    ConnectionAddr addr;
    OnJoinLNNResult cb;
} JoinLNNCbListItem;

typedef struct {
    ListNode node;
    char networkId[NETWORK_ID_BUF_LEN];
    OnLeaveLNNResult cb;
} LeaveLNNCbListItem;

typedef struct {
    ListNode node;
    char networkId[NETWORK_ID_BUF_LEN];
    ITimeSyncCb cb;
} TimeSyncCallbackItem;

typedef struct {
    ListNode node;
    INodeStateCb cb;
    char pkgName[PKG_NAME_SIZE_MAX];
} NodeStateCallbackItem;

typedef struct {
    ListNode joinLNNCbList;
    ListNode leaveLNNCbList;
    ListNode nodeStateCbList;
    ListNode timeSyncCbList;
    int32_t nodeStateCbListCnt;
    IPublishCb publishCb;
    IRefreshCallback refreshCb;
    bool isInit;
    SoftBusMutex lock;
} BusCenterClient;

static BusCenterClient g_busCenterClient = {
    .nodeStateCbListCnt = 0,
    .publishCb.OnPublishResult = NULL,
    .refreshCb.OnDeviceFound = NULL,
    .refreshCb.OnDiscoverResult = NULL,
    .isInit = false,
};

static bool IsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2)
{
    if (addr1->type != addr2->type) {
        return false;
    }
    if (addr1->type == CONNECTION_ADDR_BR) {
        return strncmp(addr1->info.br.brMac, addr2->info.br.brMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_BLE) {
        for (uint32_t i = 0; i <= UDID_HASH_LEN; i++) {
            if (addr2->info.ble.udidHash[i] == 0) {
                continue;
            }
            return memcmp(addr1->info.ble.udidHash, addr2->info.ble.udidHash, UDID_HASH_LEN) == 0 ||
                strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
        }
        return strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_WLAN || addr1->type == CONNECTION_ADDR_ETH) {
        return (strncmp(addr1->info.ip.ip, addr2->info.ip.ip, IP_STR_MAX_LEN) == 0)
            && (addr1->info.ip.port == addr2->info.ip.port);
    }
    if (addr1->type == CONNECTION_ADDR_SESSION) {
        return ((addr1->info.session.sessionId == addr2->info.session.sessionId) &&
            (addr1->info.session.channelId == addr2->info.session.channelId) &&
            (addr1->info.session.type == addr2->info.session.type));
    }
    return false;
}

static JoinLNNCbListItem *FindJoinLNNCbItem(ConnectionAddr *addr, OnJoinLNNResult cb)
{
    JoinLNNCbListItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.joinLNNCbList, JoinLNNCbListItem, node) {
        if (IsSameConnectionAddr(&item->addr, addr) &&
            (cb == NULL || cb == item->cb)) {
            return item;
        }
    }
    return NULL;
}

static int32_t AddJoinLNNCbItem(ConnectionAddr *target, OnJoinLNNResult cb)
{
    JoinLNNCbListItem *item = NULL;

    item = (JoinLNNCbListItem *)SoftBusMalloc(sizeof(*item));
    if (item == NULL) {
        LNN_LOGE(LNN_STATE, "malloc join LNN cb item fail");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    item->addr = *target;
    item->cb = cb;
    ListAdd(&g_busCenterClient.joinLNNCbList, &item->node);
    return SOFTBUS_OK;
}

static LeaveLNNCbListItem *FindLeaveLNNCbItem(const char *networkId, OnLeaveLNNResult cb)
{
    LeaveLNNCbListItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.leaveLNNCbList, LeaveLNNCbListItem, node) {
        if (strcmp(item->networkId, networkId) == 0 &&
            (cb == NULL || cb == item->cb)) {
            return item;
        }
    }
    return NULL;
}

static int32_t AddLeaveLNNCbItem(const char *networkId, OnLeaveLNNResult cb)
{
    LeaveLNNCbListItem *item = NULL;

    item = (LeaveLNNCbListItem *)SoftBusMalloc(sizeof(*item));
    if (item == NULL) {
        LNN_LOGE(LNN_STATE, "malloc join LNN cb item fail");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    if (strncpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LNN_LOGE(LNN_STATE, "strcpy network id fail");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    item->cb = cb;
    ListAdd(&g_busCenterClient.leaveLNNCbList, &item->node);
    return SOFTBUS_OK;
}

static TimeSyncCallbackItem *FindTimeSyncCbItem(const char *networkId, ITimeSyncCb *cb)
{
    TimeSyncCallbackItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.timeSyncCbList, TimeSyncCallbackItem, node) {
        if (strcmp(item->networkId, networkId) == 0 &&
            (cb == NULL || cb->onTimeSyncResult == item->cb.onTimeSyncResult)) {
            return item;
        }
    }
    return NULL;
}

static int32_t AddTimeSyncCbItem(const char *networkId, ITimeSyncCb *cb)
{
    TimeSyncCallbackItem *item = NULL;

    item = (TimeSyncCallbackItem *)SoftBusMalloc(sizeof(*item));
    if (item == NULL) {
        LNN_LOGE(LNN_STATE, "malloc time sync cb item fail");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    if (strncpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LNN_LOGE(LNN_STATE, "strcpy network id fail");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    item->cb = *cb;
    ListAdd(&g_busCenterClient.timeSyncCbList, &item->node);
    return SOFTBUS_OK;
}

static void ClearJoinLNNList(void)
{
    JoinLNNCbListItem *item = NULL;
    JoinLNNCbListItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_busCenterClient.joinLNNCbList, JoinLNNCbListItem, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static void ClearLeaveLNNList(void)
{
    LeaveLNNCbListItem *item = NULL;
    LeaveLNNCbListItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_busCenterClient.leaveLNNCbList, LeaveLNNCbListItem, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static void ClearTimeSyncList(ListNode *list)
{
    TimeSyncCallbackItem *item = NULL;
    TimeSyncCallbackItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, TimeSyncCallbackItem, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static void ClearNodeStateCbList(ListNode *list)
{
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, NodeStateCallbackItem, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static void DuplicateNodeStateCbList(ListNode *list)
{
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *copyItem = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.nodeStateCbList, NodeStateCallbackItem, node) {
        copyItem = (NodeStateCallbackItem *)SoftBusCalloc(sizeof(NodeStateCallbackItem));
        if (copyItem == NULL) {
            LNN_LOGE(LNN_STATE, "malloc node state callback item fail");
            continue;
        }
        if (strncpy_s(copyItem->pkgName, PKG_NAME_SIZE_MAX, item->pkgName, PKG_NAME_SIZE_MAX - 1) != EOK) {
            LNN_LOGE(LNN_STATE, "copy pkgName fail");
            SoftBusFree(copyItem);
            continue;
        }
        ListInit(&copyItem->node);
        copyItem->cb = item->cb;
        ListAdd(list, &copyItem->node);
    }
}

static void DuplicateTimeSyncResultCbList(ListNode *list, const char *networkId)
{
    TimeSyncCallbackItem *item = NULL;
    TimeSyncCallbackItem *copyItem = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.timeSyncCbList, TimeSyncCallbackItem, node) {
        if (strcmp(item->networkId, networkId) != 0) {
            continue;
        }
        copyItem = (TimeSyncCallbackItem *)SoftBusMalloc(sizeof(TimeSyncCallbackItem));
        if (copyItem == NULL) {
            LNN_LOGE(LNN_STATE, "malloc time sync callback item fail");
            continue;
        }
        copyItem->cb = item->cb;
        ListInit(&copyItem->node);
        if (strncpy_s(copyItem->networkId, NETWORK_ID_BUF_LEN, item->networkId, strlen(item->networkId)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy networkId fail");
            SoftBusFree(copyItem);
            continue;
        }
        ListAdd(list, &copyItem->node);
    }
}

void BusCenterClientDeinit(void)
{
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "lock in deinit");
        return;
    }
    ClearJoinLNNList();
    ClearLeaveLNNList();
    ClearTimeSyncList(&g_busCenterClient.timeSyncCbList);
    ClearNodeStateCbList(&g_busCenterClient.nodeStateCbList);
    g_busCenterClient.nodeStateCbListCnt = 0;
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "unlock in deinit");
    }
    BusCenterServerProxyDeInit();
}

int BusCenterClientInit(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_NODE_STATE_CB_CNT,
        (unsigned char *)&g_maxNodeStateCbCount, sizeof(g_maxNodeStateCbCount)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "Cannot get NodeStateCbCount from config file");
        g_maxNodeStateCbCount = DEFAULT_NODE_STATE_CB_CNT;
    }
    LNN_LOGI(LNN_INIT, "NodeStateCbCount=%{public}u", g_maxNodeStateCbCount);

    if (SoftBusMutexInit(&g_busCenterClient.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "g_busCenterClient.lock init failed");
        return SOFTBUS_ERR;
    }

    ListInit(&g_busCenterClient.joinLNNCbList);
    ListInit(&g_busCenterClient.leaveLNNCbList);
    ListInit(&g_busCenterClient.nodeStateCbList);
    ListInit(&g_busCenterClient.timeSyncCbList);
    g_busCenterClient.isInit = true;
    if (BusCenterServerProxyInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "bus center server proxy init failed");
        BusCenterClientDeinit();
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_INIT, "BusCenterClientInit init OK");
    return SOFTBUS_OK;
}

int32_t GetAllNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    int ret = ServerIpcGetAllOnlineNodeInfo(pkgName, (void **)info, sizeof(NodeBasicInfo), infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server GetAllOnlineNodeInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t GetLocalNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo *info)
{
    int ret = ServerIpcGetLocalDeviceInfo(pkgName, info, sizeof(*info));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server GetLocalNodeDeviceInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t GetNodeKeyInfoInner(const char *pkgName, const char *networkId, NodeDeviceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    int ret = ServerIpcGetNodeKeyInfo(pkgName, networkId, key, info, infoLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server GetNodeKeyInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t SetNodeDataChangeFlagInner(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    int ret = ServerIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server SetNodeDataChangeFlag failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t JoinLNNInner(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    if (target == NULL) {
        LNN_LOGE(LNN_STATE, "target is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock join lnn cb list in join");
        return SOFTBUS_LOCK_ERR;
    }

    do {
        if (FindJoinLNNCbItem(target, cb) != NULL) {
            LNN_LOGE(LNN_STATE, "join request already exist");
            rc = SOFTBUS_ALREADY_EXISTED;
            break;
        }
        rc = ServerIpcJoinLNN(pkgName, target, sizeof(*target));
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "request join lnn failed, ret=%{public}d", rc);
        } else {
            rc = AddJoinLNNCbItem(target, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock join lnn cb list in join");
    }
    return rc;
}

int32_t LeaveLNNInner(const char *pkgName, const char *networkId, OnLeaveLNNResult cb)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_STATE, "networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock leave lnn cb list in leave");
        return SOFTBUS_LOCK_ERR;
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindLeaveLNNCbItem(networkId, cb) != NULL) {
            LNN_LOGE(LNN_STATE, "leave request already exist");
            break;
        }
        rc = ServerIpcLeaveLNN(pkgName, networkId);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "request leave lnn failed, ret=%{public}d", rc);
        } else {
            rc = AddLeaveLNNCbItem(networkId, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock leave lnn cb list in leave");
    }
    return rc;
}

static bool IsSameNodeStateCb(const INodeStateCb *callback1, const INodeStateCb *callback2)
{
    if (callback1->events != callback2->events) {
        return false;
    }
    if ((callback1->events & EVENT_NODE_STATE_ONLINE) &&
        callback1->onNodeOnline != callback2->onNodeOnline) {
        return false;
    }
    if ((callback1->events & EVENT_NODE_STATE_OFFLINE) &&
        callback1->onNodeOffline != callback2->onNodeOffline) {
        return false;
    }
    if ((callback1->events & EVENT_NODE_STATE_INFO_CHANGED) &&
        callback1->onNodeBasicInfoChanged != callback2->onNodeBasicInfoChanged) {
        return false;
    }
    if ((callback1->events & EVENT_NODE_STATUS_CHANGED) &&
        callback1->onNodeStatusChanged != callback2->onNodeStatusChanged) {
        return false;
    }
    return true;
}

int32_t RegNodeDeviceStateCbInner(const char *pkgName, INodeStateCb *callback)
{
    if (callback == NULL) {
        LNN_LOGE(LNN_STATE, "callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeStateCallbackItem *item = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        LNN_LOGE(LNN_STATE, "Package name is empty or length exceeds");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock node state cb list in reg");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.nodeStateCbList, NodeStateCallbackItem, node) {
        if (IsSameNodeStateCb(&item->cb, callback)) {
            (void)SoftBusMutexUnlock(&g_busCenterClient.lock);
            LNN_LOGI(LNN_STATE, "warn: reg node state callback repeatedly");
            return SOFTBUS_OK;
        }
    }
    do {
        if (g_busCenterClient.nodeStateCbListCnt >= g_maxNodeStateCbCount) {
            break;
        }
        item = (NodeStateCallbackItem *)SoftBusCalloc(sizeof(*item));
        if (item == NULL) {
            rc = SOFTBUS_MALLOC_ERR;
            break;
        }
        (void)strncpy_s(item->pkgName, PKG_NAME_SIZE_MAX, pkgName, PKG_NAME_SIZE_MAX - 1);
        ListInit(&item->node);
        item->cb = *callback;
        ListAdd(&g_busCenterClient.nodeStateCbList, &item->node);
        g_busCenterClient.nodeStateCbListCnt++;
        rc = SOFTBUS_OK;
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock node state cb list");
    }
    return rc;
}

int32_t UnregNodeDeviceStateCbInner(INodeStateCb *callback)
{
    if (callback == NULL) {
        LNN_LOGE(LNN_STATE, "callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *next = NULL;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock node state cb list in unreg");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_busCenterClient.nodeStateCbList, NodeStateCallbackItem, node) {
        if (IsSameNodeStateCb(&item->cb, callback)) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_busCenterClient.nodeStateCbListCnt--;
            break;
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock node state cb list in unreg");
    }
    return SOFTBUS_OK;
}

int32_t StartTimeSyncInner(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb)
{
    int32_t rc = SOFTBUS_ERR;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock time sync cb list");
        return SOFTBUS_LOCK_ERR;
    }
    
    do {
        if (FindTimeSyncCbItem(targetNetworkId, cb) != NULL) {
            LNN_LOGE(LNN_STATE, "repeat pkgName request, StopTimeSync first! pkgName=%{public}s", pkgName);
            break;
        }
        rc = ServerIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "start time sync failed, ret=%{public}d", rc);
        } else {
            rc = AddTimeSyncCbItem(targetNetworkId, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock time sync cb list");
    }
    return rc;
}

int32_t StopTimeSyncInner(const char *pkgName, const char *targetNetworkId)
{
    int32_t rc = SOFTBUS_ERR;
    TimeSyncCallbackItem *item = NULL;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock time sync cb list");
        return SOFTBUS_LOCK_ERR;
    }
    
    while ((item = FindTimeSyncCbItem(targetNetworkId, NULL)) != NULL) {
        rc = ServerIpcStopTimeSync(pkgName, targetNetworkId);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "stop time sync failed, ret=%{public}d", rc);
        } else {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock time sync cb list");
    }
    return rc;
}

int32_t PublishLNNInner(const char *pkgName, const PublishInfo *info, const IPublishCb *cb)
{
    g_busCenterClient.publishCb = *cb;
    int32_t ret = ServerIpcPublishLNN(pkgName, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server PublishLNNInner failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t StopPublishLNNInner(const char *pkgName, int32_t publishId)
{
    int32_t ret = ServerIpcStopPublishLNN(pkgName, publishId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server StopPublishLNNInner failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t RefreshLNNInner(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb)
{
    g_busCenterClient.refreshCb = *cb;
    int32_t ret = ServerIpcRefreshLNN(pkgName, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server RefreshLNNInner failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t StopRefreshLNNInner(const char *pkgName, int32_t refreshId)
{
    int32_t ret = ServerIpcStopRefreshLNN(pkgName, refreshId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server StopRefreshLNNInner failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t ActiveMetaNodeInner(const char *pkgName, const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return ServerIpcActiveMetaNode(pkgName, info, metaNodeId);
}

int32_t DeactiveMetaNodeInner(const char *pkgName, const char *metaNodeId)
{
    return ServerIpcDeactiveMetaNode(pkgName, metaNodeId);
}

int32_t GetAllMetaNodeInfoInner(const char *pkgName, MetaNodeInfo *infos, int32_t *infoNum)
{
    return ServerIpcGetAllMetaNodeInfo(pkgName, infos, infoNum);
}

int32_t ShiftLNNGearInner(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    return ServerIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode)
{
    JoinLNNCbListItem *item = NULL;
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;

    if (connAddr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock join lnn cb list in join result");
        return SOFTBUS_LOCK_ERR;
    }
    while ((item = FindJoinLNNCbItem((ConnectionAddr *)addr, NULL)) != NULL) {
        ListDelete(&item->node);
        if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "unlock join lnn cb list in join result");
        }
        if (item->cb != NULL) {
            item->cb(connAddr, networkId, retCode);
        }
        SoftBusFree(item);
        if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "lock join lnn cb list in join result");
            return SOFTBUS_LOCK_ERR;
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock join lnn cb list in join result");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode)
{
    LeaveLNNCbListItem *item = NULL;

    if (networkId == NULL) {
        LNN_LOGE(LNN_STATE, "networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock leave lnn cb list fail");
        return SOFTBUS_LOCK_ERR;
    }
    while ((item = FindLeaveLNNCbItem(networkId, NULL)) != NULL) {
        ListDelete(&item->node);
        if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "unlock leave lnn cb list fail");
        }
        if (item->cb != NULL) {
            item->cb(networkId, retCode);
        }
        SoftBusFree(item);
        if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "lock leave lnn cb list fail");
            return SOFTBUS_LOCK_ERR;
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock leave lnn cb list fail");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info)
{
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;
    ListNode dupList;

    if (basicInfo == NULL || pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock node state cb list in notify");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock node state cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (isOnline == true) {
            if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
                (item->cb.events & EVENT_NODE_STATE_ONLINE) != 0) {
                item->cb.onNodeOnline(basicInfo);
            }
        } else {
            if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
                (item->cb.events & EVENT_NODE_STATE_OFFLINE) != 0) {
                item->cb.onNodeOffline(basicInfo);
            }
        }
    }
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnNodeBasicInfoChanged(const char *pkgName, void *info, int32_t type)
{
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;
    ListNode dupList;

    if (basicInfo == NULL || pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "info or pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_ERR;
    }

    if ((type < 0) || (type > TYPE_NETWORK_INFO)) {
        LNN_LOGE(LNN_STATE, "OnNodeBasicInfoChanged invalid type. type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock node basic info cb list in notify");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock node basic info cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
            (item->cb.events & EVENT_NODE_STATE_INFO_CHANGED) != 0) {
            item->cb.onNodeBasicInfoChanged((NodeBasicInfoType)type, basicInfo);
        }
    }
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnTimeSyncResult(const void *info, int retCode)
{
    TimeSyncCallbackItem *item = NULL;
    TimeSyncResultInfo *basicInfo = (TimeSyncResultInfo *)info;
    ListNode dupList;

    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock time sync cb list in time sync result");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateTimeSyncResultCbList(&dupList, basicInfo->target.targetNetworkId);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock time sync cb list in time sync result");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, TimeSyncCallbackItem, node) {
        if (item->cb.onTimeSyncResult != NULL) {
            item->cb.onTimeSyncResult((TimeSyncResultInfo *)info, retCode);
        }
    }
    ClearTimeSyncList(&dupList);
    return SOFTBUS_OK;
}

void LnnOnPublishLNNResult(int32_t publishId, int32_t reason)
{
    if (g_busCenterClient.publishCb.OnPublishResult != NULL) {
        g_busCenterClient.publishCb.OnPublishResult(publishId, (PublishResult)reason);
    }
}

void LnnOnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    if (g_busCenterClient.refreshCb.OnDiscoverResult != NULL) {
        g_busCenterClient.refreshCb.OnDiscoverResult(refreshId, (RefreshResult)reason);
    }
}

void LnnOnRefreshDeviceFound(const void *device)
{
    if (g_busCenterClient.refreshCb.OnDeviceFound != NULL) {
        g_busCenterClient.refreshCb.OnDeviceFound((const DeviceInfo *)device);
    }
}

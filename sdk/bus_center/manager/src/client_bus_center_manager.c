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

#include "client_bus_center_manager.h"

#include <pthread.h>
#include <securec.h>

#include "bus_center_server_proxy.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"

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
    ConnectionAddr addr;
    OnJoinMetaNodeResult cb;
} JoinMetaNodeCbListItem;

typedef struct {
    ListNode node;
    char networkId[NETWORK_ID_BUF_LEN];
    OnLeaveLNNResult cb;
} LeaveLNNCbListItem;

typedef struct {
    ListNode node;
    char networkId[NETWORK_ID_BUF_LEN];
    OnLeaveMetaNodeResult cb;
} LeaveMetaNodeCbListItem;

typedef struct {
    ListNode node;
    char networkId[NETWORK_ID_BUF_LEN];
    ITimeSyncCb cb;
} TimeSyncCallbackItem;

typedef struct {
    ListNode node;
    INodeStateCb cb;
} NodeStateCallbackItem;

typedef struct {
    ListNode joinLNNCbList;
    ListNode joinMetaNodeCbList;
    ListNode leaveLNNCbList;
    ListNode leaveMetaNodeCbList;
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
        return strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_WLAN || addr1->type == CONNECTION_ADDR_ETH) {
        return (strncmp(addr1->info.ip.ip, addr2->info.ip.ip, strlen(addr1->info.ip.ip)) == 0)
            && (addr1->info.ip.port == addr2->info.ip.port);
    }
    if (addr1->type == CONNECTION_ADDR_SESSION) {
        return ((addr1->info.session.sessionId == addr2->info.session.sessionId) &&
            (addr1->info.session.channelId == addr2->info.session.channelId) &&
            (addr1->type == addr2->type));
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

static JoinMetaNodeCbListItem *FindJoinMetaNodeCbItem(ConnectionAddr *addr, OnJoinMetaNodeResult cb)
{
    JoinMetaNodeCbListItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.joinMetaNodeCbList, JoinMetaNodeCbListItem, node) {
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc join LNN cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    item->addr = *target;
    item->cb = cb;
    ListAdd(&g_busCenterClient.joinLNNCbList, &item->node);
    return SOFTBUS_OK;
}

static int32_t AddJoinMetaNodeCbItem(ConnectionAddr *target, OnJoinMetaNodeResult cb)
{
    JoinMetaNodeCbListItem *item = NULL;

    item = (JoinMetaNodeCbListItem *)SoftBusMalloc(sizeof(*item));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc join MetaNode cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    item->addr = *target;
    item->cb = cb;
    ListAdd(&g_busCenterClient.joinMetaNodeCbList, &item->node);
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

static LeaveMetaNodeCbListItem *FindLeaveMetaNodeCbItem(const char *networkId, OnLeaveMetaNodeResult cb)
{
    LeaveMetaNodeCbListItem *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.leaveMetaNodeCbList, LeaveMetaNodeCbListItem, node) {
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc join LNN cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    if (strncpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy network id fail");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    item->cb = cb;
    ListAdd(&g_busCenterClient.leaveLNNCbList, &item->node);
    return SOFTBUS_OK;
}

static int32_t AddLeaveMetaNodeCbItem(const char *networkId, OnLeaveMetaNodeResult cb)
{
    LeaveMetaNodeCbListItem *item = NULL;

    item = (LeaveMetaNodeCbListItem *)SoftBusMalloc(sizeof(*item));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc join MetaNode cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    if (strncpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy network id fail");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    item->cb = cb;
    ListAdd(&g_busCenterClient.leaveMetaNodeCbList, &item->node);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc time sync cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    if (strncpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strcpy network id fail");
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
        copyItem = SoftBusMalloc(sizeof(NodeStateCallbackItem));
        if (copyItem == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc node state callback item fail");
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
        copyItem = SoftBusMalloc(sizeof(TimeSyncCallbackItem));
        if (copyItem == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc time sync callback item fail");
            continue;
        }
        copyItem->cb = item->cb;
        ListInit(&copyItem->node);
        if (strncpy_s(copyItem->networkId, NETWORK_ID_BUF_LEN, item->networkId, strlen(item->networkId)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
            SoftBusFree(copyItem);
            continue;
        }
        ListAdd(list, &copyItem->node);
    }
}

static int32_t ConvertPublishInfoToVoid(const PublishInfo *pubInfo, void **info, int32_t *infoLen)
{
    *info = SoftBusMalloc(MAX_IPC_LEN);
    if (*info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc info fail");
        return SOFTBUS_ERR;
    }
    (void)memset_s(*info, MAX_IPC_LEN, 0, MAX_IPC_LEN);
    char *buf = (char *)*info;
    *(int32_t *)buf = pubInfo->publishId;
    buf += sizeof(int32_t);
    *(DiscoverMode *)buf = pubInfo->mode;
    buf += sizeof(DiscoverMode);
    *(ExchangeMedium *)buf = pubInfo->medium;
    buf += sizeof(ExchangeMedium);
    *(ExchangeFreq *)buf = pubInfo->freq;
    buf += sizeof(ExchangeFreq);
    if (memcpy_s(buf, strlen(pubInfo->capability), pubInfo->capability, strlen(pubInfo->capability)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s pubInfo->capability fail");
        SoftBusFree(*info);
        return SOFTBUS_ERR;
    }
    buf += strlen(pubInfo->capability) + 1;
    *(int32_t *)buf = pubInfo->dataLen;
    buf += sizeof(int32_t);
    if (pubInfo->dataLen > 0) {
        if (memcpy_s(buf, pubInfo->dataLen, (char *)pubInfo->capabilityData, pubInfo->dataLen) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s pubInfo->capabilityData fail");
            SoftBusFree(*info);
            return SOFTBUS_ERR;
        }
        buf += pubInfo->dataLen + 1;
    }
    *(bool *)buf = pubInfo->ranging;
    buf += sizeof(bool);
    *infoLen = buf - (char *)*info;
    return SOFTBUS_OK;
}

static int32_t ConvertSubscribeInfoToVoid(const SubscribeInfo *subInfo, void **info, int32_t *infoLen)
{
    *info = SoftBusMalloc(MAX_IPC_LEN);
    if (*info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc info fail");
        return SOFTBUS_ERR;
    }
    (void)memset_s(*info, MAX_IPC_LEN, 0, MAX_IPC_LEN);
    char *buf = (char *)*info;
    *(int32_t *)buf = subInfo->subscribeId;
    buf += sizeof(int32_t);
    *(DiscoverMode *)buf = subInfo->mode;
    buf += sizeof(DiscoverMode);
    *(ExchangeMedium *)buf = subInfo->medium;
    buf += sizeof(ExchangeMedium);
    *(ExchangeFreq *)buf = subInfo->freq;
    buf += sizeof(ExchangeFreq);
    *(bool *)buf = subInfo->isSameAccount;
    buf += sizeof(bool);
    *(bool *)buf = subInfo->isWakeRemote;
    buf += sizeof(bool);
    if (memcpy_s(buf, strlen(subInfo->capability), subInfo->capability, strlen(subInfo->capability)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s subInfo->capability fail");
        SoftBusFree(*info);
        return SOFTBUS_ERR;
    }
    buf += strlen(subInfo->capability) + 1;
    *(int32_t *)buf = subInfo->dataLen;
    buf += sizeof(int32_t);
    *infoLen = buf - (char *)*info;
    if (subInfo->dataLen > 0) {
        if (memcpy_s(buf, subInfo->dataLen, (char *)subInfo->capabilityData, subInfo->dataLen) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy_s subInfo->capabilityData fail");
            SoftBusFree(*info);
            return SOFTBUS_ERR;
        }
        *infoLen += subInfo->dataLen + 1;
    }
    return SOFTBUS_OK;
}

void BusCenterClientDeinit(void)
{
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock in deinit");
    }
    ClearJoinLNNList();
    ClearLeaveLNNList();
    ClearNodeStateCbList(&g_busCenterClient.nodeStateCbList);
    g_busCenterClient.nodeStateCbListCnt = 0;
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock in deinit");
    }
    BusCenterServerProxyDeInit();
}

int BusCenterClientInit(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_NODE_STATE_CB_CNT,
        (unsigned char*)&g_maxNodeStateCbCount, sizeof(g_maxNodeStateCbCount)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Cannot get NodeStateCbCount from config file");
        g_maxNodeStateCbCount = DEFAULT_NODE_STATE_CB_CNT;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "NodeStateCbCount is %u", g_maxNodeStateCbCount);

    if (SoftBusMutexInit(&g_busCenterClient.lock, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "g_busCenterClient.lock init failed.");
        BusCenterClientDeinit();
        return SOFTBUS_ERR;
    }

    ListInit(&g_busCenterClient.joinLNNCbList);
    ListInit(&g_busCenterClient.joinMetaNodeCbList);
    ListInit(&g_busCenterClient.leaveLNNCbList);
    ListInit(&g_busCenterClient.leaveMetaNodeCbList);
    ListInit(&g_busCenterClient.nodeStateCbList);
    ListInit(&g_busCenterClient.timeSyncCbList);
    g_busCenterClient.isInit = true;
    if (BusCenterServerProxyInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center server proxy init failed.");
        BusCenterClientDeinit();
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "BusCenterClientInit init OK!");
    return SOFTBUS_OK;
}

int32_t GetAllNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    int ret = ServerIpcGetAllOnlineNodeInfo(pkgName, (void **)info, sizeof(NodeBasicInfo), infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Server GetAllOnlineNodeInfo failed, ret = %d", ret);
    }
    return ret;
}

int32_t GetLocalNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo *info)
{
    int ret = ServerIpcGetLocalDeviceInfo(pkgName, info, sizeof(*info));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Server GetLocalNodeDeviceInfo failed, ret = %d", ret);
    }
    return ret;
}

int32_t GetNodeKeyInfoInner(const char *pkgName, const char *networkId, NodeDeviceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    int ret = ServerIpcGetNodeKeyInfo(pkgName, networkId, key, info, infoLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Server GetNodeKeyInfo failed, ret = %d", ret);
    }
    return ret;
}

int32_t SetNodeDataChangeFlagInner(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    int ret = ServerIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Server SetNodeDataChangeFlag failed, ret = %d", ret);
    }
    return ret;
}

int32_t JoinLNNInner(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : join lnn not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join lnn cb list in join");
    }

    do {
        if (FindJoinLNNCbItem(target, cb) != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : join request already exist");
            rc = SOFTBUS_ALREADY_EXISTED;
            break;
        }
        rc = ServerIpcJoinLNN(pkgName, target, sizeof(*target));
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : request join lnn");
        } else {
            rc = AddJoinLNNCbItem(target, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join lnn cb list in join");
    }
    return rc;
}

int32_t JoinMetaNodeInner(const char *pkgName, ConnectionAddr *target, CustomData *customData, OnJoinLNNResult cb)
{
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : join MetaNode not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join MetaNode cb list in join");
    }

    do {
        if (FindJoinMetaNodeCbItem(target, cb) != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : join request already exist");
            rc = SOFTBUS_ALREADY_EXISTED;
            break;
        }
        rc = ServerIpcJoinMetaNode(pkgName, target, customData, sizeof(*target));
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : request join MetaNode");
        } else {
            rc = AddJoinMetaNodeCbItem(target, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join MetaNode cb list in join");
    }
    return rc;
}

int32_t LeaveLNNInner(const char *pkgName, const char *networkId, OnLeaveLNNResult cb)
{
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : leave lnn not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave lnn cb list in leave");
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindLeaveLNNCbItem(networkId, cb) != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : leave request already exist");
            break;
        }
        rc = ServerIpcLeaveLNN(pkgName, networkId);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : request leave lnn");
        } else {
            rc = AddLeaveLNNCbItem(networkId, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave lnn cb list in leave");
    }
    return rc;
}

int32_t LeaveMetaNodeInner(const char *pkgName, const char *networkId, OnLeaveMetaNodeResult cb)
{
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : leave MetaNode not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave MetaNode cb list in leave");
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindLeaveMetaNodeCbItem(networkId, cb) != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : leave request already exist");
            break;
        }
        rc = ServerIpcLeaveMetaNode(pkgName, networkId);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : request leave MetaNode");
        } else {
            rc = AddLeaveMetaNodeCbItem(networkId, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave MetaNode cb list in leave");
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
    return true;
}

int32_t RegNodeDeviceStateCbInner(const char *pkgName, INodeStateCb *callback)
{
    NodeStateCallbackItem *item = NULL;
    int32_t rc = SOFTBUS_ERR;

    (void)pkgName;
    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: reg node state cb not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node state cb list in reg");
    }
    LIST_FOR_EACH_ENTRY(item, &g_busCenterClient.nodeStateCbList, NodeStateCallbackItem, node) {
        if (IsSameNodeStateCb(&item->cb, callback)) {
            (void)SoftBusMutexUnlock(&g_busCenterClient.lock);
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "warn: reg node state callback repeatedly");
            return SOFTBUS_OK;
        }
    }
    do {
        if (g_busCenterClient.nodeStateCbListCnt >= g_maxNodeStateCbCount) {
            break;
        }
        item = (NodeStateCallbackItem *)SoftBusMalloc(sizeof(*item));
        if (item == NULL) {
            rc = SOFTBUS_MALLOC_ERR;
            break;
        }
        ListInit(&item->node);
        item->cb = *callback;
        ListAdd(&g_busCenterClient.nodeStateCbList, &item->node);
        g_busCenterClient.nodeStateCbListCnt++;
        rc = SOFTBUS_OK;
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node state cb list");
    }
    return rc;
}

int32_t UnregNodeDeviceStateCbInner(INodeStateCb *callback)
{
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *next = NULL;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unreg node state cb not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node state cb list in unreg");
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_busCenterClient.nodeStateCbList, NodeStateCallbackItem, node) {
        if (IsSameNodeStateCb(&item->cb, callback)) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_busCenterClient.nodeStateCbListCnt--;
            break;
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node state cb list in unreg");
    }
    return SOFTBUS_OK;
}

int32_t StartTimeSyncInner(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb)
{
    int32_t rc;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : start time sync not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock time sync cb list");
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindTimeSyncCbItem(targetNetworkId, cb) != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "repeat request from %s, StopTimeSync first!", pkgName);
            break;
        }
        rc = ServerIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : start time sync");
        } else {
            rc = AddTimeSyncCbItem(targetNetworkId, cb);
        }
    } while (false);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock time sync cb list");
    }
    return rc;
}

int32_t StopTimeSyncInner(const char *pkgName, const char *targetNetworkId)
{
    int32_t rc;
    TimeSyncCallbackItem *item = NULL;

    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : stop time sync cb list not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock time sync cb list");
    }
    rc = SOFTBUS_ERR;
    while ((item = FindTimeSyncCbItem(targetNetworkId, NULL)) != NULL) {
        rc = ServerIpcStopTimeSync(pkgName, targetNetworkId);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : stop time sync");
        } else {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }

    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock time sync cb list");
    }
    return rc;
}

int32_t PublishLNNInner(const char *pkgName, const PublishInfo *info, const IPublishCb *cb)
{
    g_busCenterClient.publishCb = *cb;
    int32_t bufLen = 0;
    void *buf = NULL;
    if (ConvertPublishInfoToVoid(info, &buf, &bufLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ConvertPublishInfoToVoid fail");
        return SOFTBUS_ERR;
    }
    int32_t ret = ServerIpcPublishLNN(pkgName, buf, bufLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Server PublishLNNInner failed, ret = %d", ret);
    }
    SoftBusFree(buf);
    return ret;
}

int32_t StopPublishLNNInner(const char *pkgName, int32_t publishId)
{
    int32_t ret = ServerIpcStopPublishLNN(pkgName, publishId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Server StopPublishLNNInner failed, ret = %d", ret);
    }

    return ret;
}

int32_t RefreshLNNInner(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb)
{
    g_busCenterClient.refreshCb = *cb;
    int32_t bufLen = 0;
    void *buf = NULL;
    if (ConvertSubscribeInfoToVoid(info, &buf, &bufLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ConvertSubscribeInfoToVoid fail");
        return SOFTBUS_ERR;
    }
    int32_t ret = ServerIpcRefreshLNN(pkgName, buf, bufLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Server RefreshLNNInner failed, ret = %d", ret);
    }
    SoftBusFree(buf);
    return ret;
}

int32_t StopRefreshLNNInner(const char *pkgName, int32_t refreshId)
{
    int32_t ret = ServerIpcStopRefreshLNN(pkgName, refreshId);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "Server StopRefreshLNNInner failed, ret = %d", ret);
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
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join lnn cb list in join result");
    }
    while ((item = FindJoinLNNCbItem(addr, NULL)) != NULL) {
        ListDelete(&item->node);
        if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join lnn cb list in join result");
        }
        if (item->cb != NULL) {
            item->cb(connAddr, networkId, retCode);
        }
        SoftBusFree(item);
        if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join lnn cb list in join result");
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join lnn cb list in join result");
    }
    return SOFTBUS_OK;
}

int32_t MetaNodeOnJoinResult(void *addr, const char *networkId, int32_t retCode)
{
    JoinMetaNodeCbListItem *item = NULL;
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;

    if (connAddr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join MetaNode cb list in join result");
    }
    while ((item = FindJoinMetaNodeCbItem(addr, NULL)) != NULL) {
        ListDelete(&item->node);
        if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join MetaNode cb list in join result");
        }
        if (item->cb != NULL) {
            item->cb(connAddr, networkId, retCode);
        }
        SoftBusFree(item);
        if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join MetaNode cb list in join result");
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join MetaNode cb list in join result");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode)
{
    LeaveLNNCbListItem *item = NULL;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: leave cb not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave lnn cb list in leave result");
    }
    while ((item = FindLeaveLNNCbItem(networkId, NULL)) != NULL) {
        ListDelete(&item->node);
        if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave lnn cb list in leave result");
        }
        if (item->cb != NULL) {
            item->cb(networkId, retCode);
        }
        SoftBusFree(item);
        if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave lnn cb list in leave result");
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave lnn cb list in leave result");
    }
    return SOFTBUS_OK;
}

int32_t MetaNodeOnLeaveResult(const char *networkId, int32_t retCode)
{
    LeaveMetaNodeCbListItem *item = NULL;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: leave cb not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave MetaNode cb list in leave result");
    }
    while ((item = FindLeaveMetaNodeCbItem(networkId, NULL)) != NULL) {
        ListDelete(&item->node);
        if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave MetaNode cb list in leave result");
        }
        if (item->cb != NULL) {
            item->cb(networkId, retCode);
        }
        SoftBusFree(item);
        if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave MetaNode cb list in leave result");
        }
    }
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave MetaNode cb list in leave result");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnNodeOnlineStateChanged(bool isOnline, void *info)
{
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;
    ListNode dupList;

    if (basicInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node state cb list in notify");
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node state cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (isOnline == true) {
            if ((item->cb.events & EVENT_NODE_STATE_ONLINE) != 0) {
                item->cb.onNodeOnline(basicInfo);
            }
        } else {
            if ((item->cb.events & EVENT_NODE_STATE_OFFLINE) != 0) {
                item->cb.onNodeOffline(basicInfo);
            }
        }
    }
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnNodeBasicInfoChanged(void *info, int32_t type)
{
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;
    ListNode dupList;

    if (basicInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        return SOFTBUS_ERR;
    }

    if ((type < 0) || (type > TYPE_DEVICE_NAME)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChanged invalid type: %d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node basic info cb list in notify");
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node basic info cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if ((item->cb.events & EVENT_NODE_STATE_INFO_CHANGED) != 0) {
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: time sync cb not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock time sync cb list in time sync result");
    }
    ListInit(&dupList);
    DuplicateTimeSyncResultCbList(&dupList, basicInfo->target.targetNetworkId);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock time sync cb list in time sync result");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, TimeSyncCallbackItem, node) {
        if (item->cb.onTimeSyncResult != NULL) {
            item->cb.onTimeSyncResult(info, retCode);
        }
    }
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
        g_busCenterClient.refreshCb.OnDeviceFound(device);
    }
}

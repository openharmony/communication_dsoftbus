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

#include "client_bus_center_manager.h"

#include <pthread.h>
#include <securec.h>

#include "anonymizer.h"
#include "bus_center_server_proxy.h"
#include "common_list.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

#define DEFAULT_NODE_STATE_CB_CNT 10
#define MAX_IPC_LEN 1024

static int32_t g_maxNodeStateCbCount;
static SoftBusList *g_publishMsgList = NULL;
static SoftBusList *g_discoveryMsgList = NULL;
static bool g_isInited = false;
static SoftBusMutex g_isInitedLock;
static char g_regDataLevelChangePkgName[PKG_NAME_SIZE_MAX] = {0};

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
    IDataLevelCb dataLevelCb;
    bool isInit;
    SoftBusMutex lock;
} BusCenterClient;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    PublishInfo *info;
    ListNode node;
} DiscPublishMsg;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    SubscribeInfo *info;
    ListNode node;
} DiscSubscribeMsg;

static BusCenterClient g_busCenterClient = {
    .nodeStateCbListCnt = 0,
    .publishCb.OnPublishResult = NULL,
    .refreshCb.OnDeviceFound = NULL,
    .refreshCb.OnDiscoverResult = NULL,
    .dataLevelCb.onDataLevelChanged = NULL,
    .isInit = false,
};

static bool IsUdidHashEmpty(const ConnectionAddr *addr)
{
    for (uint32_t i = 0; i < UDID_HASH_LEN; i++) {
        if (addr->info.ble.udidHash[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool IsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2)
{
    if (addr1->type != addr2->type) {
        return false;
    }
    if (addr1->type == CONNECTION_ADDR_BR) {
        return strncmp(addr1->info.br.brMac, addr2->info.br.brMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_BLE) {
        if (IsUdidHashEmpty(addr2)) {
            return strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
        }
        return memcmp(addr1->info.ble.udidHash, addr2->info.ble.udidHash, UDID_HASH_LEN) == 0 ||
            strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
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
        return SOFTBUS_MEM_ERR;
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
        return SOFTBUS_MEM_ERR;
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

static void FreeDiscPublishMsg(DiscPublishMsg **msgNode)
{
    if (*msgNode != NULL && (*msgNode)->info != NULL) {
        SoftBusFree((char *)(*msgNode)->info->capability);
        SoftBusFree((*msgNode)->info->capabilityData);
        SoftBusFree((*msgNode)->info);
    }
    SoftBusFree(*msgNode);
    *msgNode = NULL;
}

static void FreeDiscSubscribeMsg(DiscSubscribeMsg **msgNode)
{
    if (*msgNode != NULL && (*msgNode)->info != NULL) {
        SoftBusFree((char *)(*msgNode)->info->capability);
        SoftBusFree((*msgNode)->info->capabilityData);
        SoftBusFree((*msgNode)->info);
    }
    SoftBusFree(*msgNode);
    *msgNode = NULL;
}

static int32_t BuildDiscPublishMsg(DiscPublishMsg **msgNode, const PublishInfo *info, const char *pkgName)
{
    *msgNode = (DiscPublishMsg *)SoftBusCalloc(sizeof(DiscPublishMsg));
    if (*msgNode == NULL) {
        LNN_LOGE(LNN_STATE, "calloc msgNode failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (*msgNode)->info = (PublishInfo *)SoftBusCalloc(sizeof(PublishInfo));
    if ((*msgNode)->info == NULL) {
        FreeDiscPublishMsg(msgNode);
        LNN_LOGE(LNN_STATE, "calloc info failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (*msgNode)->info->capability = (char *)SoftBusCalloc(strlen(info->capability) + 1);
    if ((*msgNode)->info->capability == NULL) {
        FreeDiscPublishMsg(msgNode);
        LNN_LOGE(LNN_STATE, "calloc capability failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (*msgNode)->info->publishId = info->publishId;
    (*msgNode)->info->mode = info->mode;
    (*msgNode)->info->medium = info->medium;
    (*msgNode)->info->freq = info->freq;
    (*msgNode)->info->dataLen = info->dataLen;
    (*msgNode)->info->ranging = info->ranging;
    if (strcpy_s((char *)(*msgNode)->info->capability, strlen(info->capability) + 1, info->capability) != EOK ||
        strcpy_s((*msgNode)->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        FreeDiscPublishMsg(msgNode);
        LNN_LOGE(LNN_STATE, "copy capability or pkgName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (info->dataLen > 0) {
        (*msgNode)->info->capabilityData = (unsigned char *)SoftBusCalloc(info->dataLen + 1);
        if ((*msgNode)->info->capabilityData == NULL) {
            FreeDiscPublishMsg(msgNode);
            LNN_LOGE(LNN_STATE, "calloc failed");
            return SOFTBUS_MALLOC_ERR;
        }
        if (strcpy_s((char *)(*msgNode)->info->capabilityData, info->dataLen + 1,
            (const char *)info->capabilityData) != EOK) {
            FreeDiscPublishMsg(msgNode);
            LNN_LOGE(LNN_STATE, "copy capabilityData failed");
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t BuildDiscSubscribeMsg(DiscSubscribeMsg **msgNode, const SubscribeInfo *info, const char *pkgName)
{
    *msgNode = (DiscSubscribeMsg *)SoftBusCalloc(sizeof(DiscSubscribeMsg));
    if (*msgNode == NULL) {
        LNN_LOGE(LNN_STATE, "calloc msgNode failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (*msgNode)->info = (SubscribeInfo *)SoftBusCalloc(sizeof(SubscribeInfo));
    if ((*msgNode)->info == NULL) {
        FreeDiscSubscribeMsg(msgNode);
        LNN_LOGE(LNN_STATE, "calloc info failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (*msgNode)->info->capability = (char *)SoftBusCalloc(strlen(info->capability) + 1);
    if ((*msgNode)->info->capability == NULL) {
        FreeDiscSubscribeMsg(msgNode);
        LNN_LOGE(LNN_STATE, "calloc capability failed");
        return SOFTBUS_MALLOC_ERR;
    }
    (*msgNode)->info->subscribeId = info->subscribeId;
    (*msgNode)->info->mode = info->mode;
    (*msgNode)->info->medium = info->medium;
    (*msgNode)->info->freq = info->freq;
    (*msgNode)->info->dataLen = info->dataLen;
    if (strcpy_s((char *)(*msgNode)->info->capability, strlen(info->capability) + 1, info->capability) != EOK ||
        strcpy_s((*msgNode)->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        FreeDiscSubscribeMsg(msgNode);
        LNN_LOGE(LNN_STATE, "copy capability or pkgName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (info->dataLen > 0) {
        (*msgNode)->info->capabilityData = (unsigned char *)SoftBusCalloc(info->dataLen + 1);
        if ((*msgNode)->info->capabilityData == NULL) {
            FreeDiscSubscribeMsg(msgNode);
            LNN_LOGE(LNN_STATE, "calloc failed");
            return SOFTBUS_MALLOC_ERR;
        }
        if (strcpy_s((char *)(*msgNode)->info->capabilityData, info->dataLen + 1,
            (const char *)info->capabilityData) != EOK) {
            FreeDiscSubscribeMsg(msgNode);
            LNN_LOGE(LNN_STATE, "copy capabilityData failed");
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t AddDiscPublishMsg(const char *pkgName, const PublishInfo *info)
{
    LNN_CHECK_AND_RETURN_RET_LOGW(g_isInited, SOFTBUS_NO_INIT, LNN_STATE, "disc publish list not init");
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_publishMsgList->lock)) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock failed");

    DiscPublishMsg *msgNode = NULL;
    LIST_FOR_EACH_ENTRY(msgNode, &(g_publishMsgList->list), DiscPublishMsg, node) {
        if (msgNode->info->publishId == info->publishId &&
            strcmp(msgNode->info->capability, info->capability) == 0 && strcmp(msgNode->pkgName, pkgName) == 0) {
            (void)SoftBusMutexUnlock(&(g_publishMsgList->lock));
            return SOFTBUS_OK;
        }
    }

    if (BuildDiscPublishMsg(&msgNode, info, pkgName) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_publishMsgList->lock));
        LNN_LOGE(LNN_STATE, "build DiscPublishMsg failed");
        return SOFTBUS_NETWORK_BUILD_PUBLISH_MSG_FAILED;
    }
    ListTailInsert(&(g_publishMsgList->list), &(msgNode->node));
    (void)SoftBusMutexUnlock(&(g_publishMsgList->lock));
    return SOFTBUS_OK;
}

static int32_t DeleteDiscPublishMsg(const char *pkgName, int32_t publishId)
{
    LNN_CHECK_AND_RETURN_RET_LOGW(g_isInited, SOFTBUS_NO_INIT, LNN_STATE, "disc publish list not init");
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_publishMsgList->lock)) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock failed");

    DiscPublishMsg *msgNode = NULL;
    DiscPublishMsg *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(msgNode, next, &(g_publishMsgList->list), DiscPublishMsg, node) {
        if (msgNode->info->publishId == publishId && strcmp(msgNode->pkgName, pkgName) == 0) {
            ListDelete(&(msgNode->node));
            FreeDiscPublishMsg(&msgNode);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_publishMsgList->lock));
    return SOFTBUS_OK;
}

static int32_t AddDiscSubscribeMsg(const char *pkgName, const SubscribeInfo *info)
{
    LNN_CHECK_AND_RETURN_RET_LOGW(g_isInited, SOFTBUS_NO_INIT, LNN_STATE, "disc subscribe list not init");
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_discoveryMsgList->lock)) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock failed");

    DiscSubscribeMsg *msgNode = NULL;
    LIST_FOR_EACH_ENTRY(msgNode, &(g_discoveryMsgList->list), DiscSubscribeMsg, node) {
        if (msgNode->info->subscribeId == info->subscribeId &&
            strcmp(msgNode->info->capability, info->capability) == 0 && strcmp(msgNode->pkgName, pkgName) == 0) {
            (void)SoftBusMutexUnlock(&(g_discoveryMsgList->lock));
            return SOFTBUS_OK;
        }
    }

    if (BuildDiscSubscribeMsg(&msgNode, info, pkgName) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_discoveryMsgList->lock));
        LNN_LOGE(LNN_STATE, "build DiscSubscribeMsg failed");
        return SOFTBUS_NETWORK_BUILD_SUB_MSG_FAILED;
    }
    ListTailInsert(&(g_discoveryMsgList->list), &(msgNode->node));
    (void)SoftBusMutexUnlock(&(g_discoveryMsgList->lock));
    return SOFTBUS_OK;
}

static int32_t DeleteDiscSubscribeMsg(const char *pkgName, int32_t refreshId)
{
    LNN_CHECK_AND_RETURN_RET_LOGW(g_isInited, SOFTBUS_NO_INIT, LNN_STATE, "disc subscribe list not init");
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_discoveryMsgList->lock)) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock failed");

    DiscSubscribeMsg *msgNode = NULL;
    DiscSubscribeMsg *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(msgNode, next, &(g_discoveryMsgList->list), DiscSubscribeMsg, node) {
        if (msgNode->info->subscribeId == refreshId && strcmp(msgNode->pkgName, pkgName) == 0) {
            ListDelete(&(msgNode->node));
            FreeDiscSubscribeMsg(&msgNode);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_discoveryMsgList->lock));
    return SOFTBUS_OK;
}

static int32_t DiscoveryMsgListInit()
{
    if (g_isInited) {
        LNN_LOGI(LNN_STATE, "disc msg list already init");
        return SOFTBUS_OK;
    }
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexInit(&g_isInitedLock, NULL) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock init failed");
    if (SoftBusMutexLock(&g_isInitedLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock failed");
        (void)SoftBusMutexDestroy(&g_isInitedLock);
        return SOFTBUS_LOCK_ERR;
    }
    g_publishMsgList = CreateSoftBusList();
    g_discoveryMsgList = CreateSoftBusList();
    if (g_publishMsgList == NULL || g_discoveryMsgList == NULL) {
        LNN_LOGE(LNN_STATE, "init disc msg list failed");
        DestroySoftBusList(g_publishMsgList);
        DestroySoftBusList(g_discoveryMsgList);
        g_publishMsgList = NULL;
        g_discoveryMsgList = NULL;
        (void)SoftBusMutexUnlock(&g_isInitedLock);
        return SOFTBUS_MALLOC_ERR;
    }
    g_isInited = true;
    (void)SoftBusMutexUnlock(&g_isInitedLock);
    static uint32_t callCount = 0;
    LNN_LOGI(LNN_STATE, "disc list init success, callCount=%{public}u", callCount++);
    return SOFTBUS_OK;
}

static int32_t DiscoveryMsgListDeInit()
{
    if (!g_isInited) {
        LNN_LOGI(LNN_STATE, "disc msg list no need deInit");
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexDestroy(&g_isInitedLock);
    DestroySoftBusList(g_publishMsgList);
    DestroySoftBusList(g_discoveryMsgList);
    g_publishMsgList = NULL;
    g_discoveryMsgList = NULL;
    g_isInited = false;

    LNN_LOGI(LNN_STATE, "disc list deinit success");
    return SOFTBUS_OK;
}

void BusCenterClientDeinit(void)
{
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "lock in deinit");
        return;
    }
    if (DiscoveryMsgListDeInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "DiscoveryMsgListDeInit fail");
        (void)SoftBusMutexUnlock(&g_busCenterClient.lock);
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
    g_busCenterClient.dataLevelCb.onDataLevelChanged = NULL;
    SoftBusMutexDestroy(&g_busCenterClient.lock);
    BusCenterServerProxyDeInit();
}

int32_t BusCenterClientInit(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_NODE_STATE_CB_CNT,
        (unsigned char *)&g_maxNodeStateCbCount, sizeof(g_maxNodeStateCbCount)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "Cannot get NodeStateCbCount from config file");
        g_maxNodeStateCbCount = DEFAULT_NODE_STATE_CB_CNT;
    }
    LNN_LOGI(LNN_INIT, "NodeStateCbCount=%{public}u", g_maxNodeStateCbCount);

    if (SoftBusMutexInit(&g_busCenterClient.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "g_busCenterClient.lock init failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (DiscoveryMsgListInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "DiscoveryMsgListInit fail");
        return SOFTBUS_MALLOC_ERR;
    }

    ListInit(&g_busCenterClient.joinLNNCbList);
    ListInit(&g_busCenterClient.leaveLNNCbList);
    ListInit(&g_busCenterClient.nodeStateCbList);
    ListInit(&g_busCenterClient.timeSyncCbList);
    g_busCenterClient.isInit = true;
    if (BusCenterServerProxyInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "bus center server proxy init failed");
        BusCenterClientDeinit();
        return SOFTBUS_SERVER_NOT_INIT;
    }
    LNN_LOGI(LNN_INIT, "BusCenterClientInit init OK");
    return SOFTBUS_OK;
}

int32_t GetAllNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    int32_t ret = ServerIpcGetAllOnlineNodeInfo(pkgName, (void **)info, sizeof(NodeBasicInfo), infoNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server GetAllOnlineNodeInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t GetLocalNodeDeviceInfoInner(const char *pkgName, NodeBasicInfo *info)
{
    int32_t ret = ServerIpcGetLocalDeviceInfo(pkgName, info, sizeof(*info));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server GetLocalNodeDeviceInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t GetNodeKeyInfoInner(const char *pkgName, const char *networkId, NodeDeviceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    int32_t ret = ServerIpcGetNodeKeyInfo(pkgName, networkId, key, info, infoLen);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server GetNodeKeyInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t SetNodeDataChangeFlagInner(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    int32_t ret = ServerIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server SetNodeDataChangeFlag failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t RegDataLevelChangeCbInner(const char *pkgName, IDataLevelCb *callback)
{
    LNN_LOGI(LNN_STATE, "enter");
    g_busCenterClient.dataLevelCb = *callback;
    if (strcpy_s(g_regDataLevelChangePkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        LNN_LOGE(LNN_STATE, "copy pkgName fail");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = ServerIpcRegDataLevelChangeCb(pkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server RegDataLevelChangeCb failed, ret=%{public}d", ret);
    }
    return ret;
}

void RestartRegDataLevelChange(void)
{
    LNN_LOGI(LNN_STATE, "enter");
    if (g_regDataLevelChangePkgName[0] == '\0') {
        LNN_LOGI(LNN_STATE, "restart regDataLevelChange is not used");
        return;
    }
    int32_t ret = ServerIpcRegDataLevelChangeCb(g_regDataLevelChangePkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server RegDataLevelChangeCb failed, ret=%{public}d", ret);
        return;
    }
    LNN_LOGI(LNN_STATE, "Server RegDataLevelChangeCb succeed");
}

int32_t UnregDataLevelChangeCbInner(const char *pkgName)
{
    LNN_LOGI(LNN_STATE, "UnregDataLevelChangeCbInner enter");
    g_busCenterClient.dataLevelCb.onDataLevelChanged = NULL;
    int32_t ret = ServerIpcUnregDataLevelChangeCb(pkgName);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server UnregDataLevelChangeCb failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t SetDataLevelInner(const DataLevel *dataLevel)
{
    int32_t ret = ServerIpcSetDataLevel(dataLevel);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server SetDataLevel failed, ret=%{public}d", ret);
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
        LNN_LOGE(LNN_STATE, "join lnn not init");
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
        LNN_LOGE(LNN_STATE, "leave lnn not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock leave lnn cb list in leave");
        return SOFTBUS_LOCK_ERR;
    }
    rc = SOFTBUS_NETWORK_LEAVE_LNN_FAILED;
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
    if ((callback1->events & EVENT_NODE_HICHAIN_PROOF_EXCEPTION) &&
        callback1->onHichainProofException != callback2->onHichainProofException) {
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
    int32_t rc = SOFTBUS_NETWORK_REG_CB_FAILED;

    if (!IsValidString(pkgName, PKG_NAME_SIZE_MAX - 1)) {
        LNN_LOGE(LNN_STATE, "Package name is empty or length exceeds");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "reg node state cb not init");
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
        LNN_LOGE(LNN_STATE, "unreg node state cb not init");
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
    int32_t rc = SOFTBUS_NETWORK_START_TIME_SYNC_FAILED;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "start time sync not init");
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
    int32_t rc = SOFTBUS_NETWORK_STOP_TIME_SYNC_FAILED;
    TimeSyncCallbackItem *item = NULL;

    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "stop time sync cb list not init");
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
        return ret;
    }
    if (AddDiscPublishMsg(pkgName, info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "add publish msg error");
    }
    return SOFTBUS_OK;
}

int32_t StopPublishLNNInner(const char *pkgName, int32_t publishId)
{
    int32_t ret = ServerIpcStopPublishLNN(pkgName, publishId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server StopPublishLNNInner failed, ret=%{public}d", ret);
        return ret;
    }
    if (DeleteDiscPublishMsg(pkgName, publishId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "del publish msg error");
    }
    return SOFTBUS_OK;
}

int32_t RefreshLNNInner(const char *pkgName, const SubscribeInfo *info, const IRefreshCallback *cb)
{
    g_busCenterClient.refreshCb = *cb;
    int32_t ret = ServerIpcRefreshLNN(pkgName, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server RefreshLNNInner failed, ret=%{public}d", ret);
        return ret;
    }
    if (AddDiscSubscribeMsg(pkgName, info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "add subscribe msg error");
    }
    return SOFTBUS_OK;
}

int32_t StopRefreshLNNInner(const char *pkgName, int32_t refreshId)
{
    int32_t ret = ServerIpcStopRefreshLNN(pkgName, refreshId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "Server StopRefreshLNNInner failed, ret=%{public}d", ret);
        return ret;
    }
    if (DeleteDiscSubscribeMsg(pkgName, refreshId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "del subscribe msg error");
    }
    return SOFTBUS_OK;
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

int32_t SyncTrustedRelationShipInner(const char *pkgName, const char *msg, uint32_t msgLen)
{
    return ServerIpcSyncTrustedRelationShip(pkgName, msg, msgLen);
}

int32_t SetDisplayNameInner(const char *pkgName, const char *nameData, uint32_t len)
{
    return ServerIpcSetDisplayName(pkgName, nameData, len);
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
        return SOFTBUS_NETWORK_CLIENT_NOT_INIT;
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
        LNN_LOGE(LNN_STATE, "leave cb not init");
        return SOFTBUS_NETWORK_CLIENT_NOT_INIT;
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
        return SOFTBUS_NETWORK_CLIENT_NOT_INIT;
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
        return SOFTBUS_NETWORK_CLIENT_NOT_INIT;
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

int32_t LnnOnNodeStatusChanged(const char *pkgName, void *info, int32_t type)
{
    if (pkgName == NULL || info == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName or info is null");
        return SOFTBUS_INVALID_PARAM;
    }
    NodeStateCallbackItem *item = NULL;
    NodeStatus *nodeStatus = (NodeStatus *)info;
    ListNode dupList;
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }

    if ((type < 0) || (type > TYPE_STATUS_MAX)) {
        LNN_LOGE(LNN_STATE, "LnnOnNodeStatusChanged invalid type. type=%{public}d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock node status cb list in notify");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock node status cb list in notify");
    }
    char *anonyPkgName = NULL;
    Anonymize(pkgName, &anonyPkgName);
    LNN_LOGI(LNN_STATE, "LnnOnNodeStatusChanged, pkgName=%{public}s, type=%{public}d, screen=%{public}d",
        AnonymizeWrapper(anonyPkgName), type, nodeStatus->reserved[0]);
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
            (item->cb.events & EVENT_NODE_STATUS_CHANGED) != 0 && item->cb.onNodeStatusChanged != NULL) {
            LNN_LOGI(LNN_STATE, "LnnOnNodeStatusChanged, pkgName=%{public}s, type=%{public}d, screen=%{public}d",
                AnonymizeWrapper(anonyPkgName), type, nodeStatus->reserved[0]);
            item->cb.onNodeStatusChanged((NodeStatusType)type, nodeStatus);
        }
    }
    AnonymizeFree(anonyPkgName);
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnLocalNetworkIdChanged(const char *pkgName)
{
    NodeStateCallbackItem *item = NULL;
    ListNode dupList;

    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "info or pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock local networkId cb list in notify");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock local networkId cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
            (item->cb.onLocalNetworkIdChanged) != NULL) {
            item->cb.onLocalNetworkIdChanged();
        }
    }
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnNodeDeviceTrustedChange(const char *pkgName, int32_t type, const char *msg, uint32_t msgLen)
{
    NodeStateCallbackItem *item = NULL;
    ListNode dupList;

    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock local cb list in notify");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock local cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
            (item->cb.onNodeDeviceTrustedChange) != NULL) {
            item->cb.onNodeDeviceTrustedChange((TrustChangeType)type, msg, msgLen);
        }
    }
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnHichainProofException(
    const char *pkgName, const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    NodeStateCallbackItem *item = NULL;
    ListNode dupList;

    if (pkgName == NULL) {
        LNN_LOGE(LNN_STATE, "pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "buscenter client not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "lock auth restrict cb list in notify");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&dupList);
    DuplicateNodeStateCbList(&dupList);
    if (SoftBusMutexUnlock(&g_busCenterClient.lock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "unlock auth restrict cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &dupList, NodeStateCallbackItem, node) {
        if (((strcmp(item->pkgName, pkgName) == 0) || (strlen(pkgName) == 0)) &&
            (item->cb.events & EVENT_NODE_HICHAIN_PROOF_EXCEPTION) != 0 && item->cb.onHichainProofException != NULL) {
            item->cb.onHichainProofException(proofInfo, proofLen, deviceTypeId, errCode);
            char *anonyPkgName = NULL;
            char *anonyProofInfo = NULL;
            Anonymize(pkgName, &anonyPkgName);
            Anonymize(proofInfo, &anonyProofInfo);
            LNN_LOGI(LNN_STATE,
                "onHichainProofException, pkgName=%{public}s, proofInfo=%{public}s, errCode=%{public}d, "
                "type=%{public}hu",
                AnonymizeWrapper(anonyPkgName), AnonymizeWrapper(anonyProofInfo), errCode, deviceTypeId);
            AnonymizeFree(anonyPkgName);
            AnonymizeFree(anonyProofInfo);
        }
    }
    ClearNodeStateCbList(&dupList);
    return SOFTBUS_OK;
}

int32_t LnnOnTimeSyncResult(const void *info, int32_t retCode)
{
    TimeSyncCallbackItem *item = NULL;
    TimeSyncResultInfo *basicInfo = (TimeSyncResultInfo *)info;
    ListNode dupList;

    if (info == NULL) {
        LNN_LOGE(LNN_STATE, "info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_busCenterClient.isInit) {
        LNN_LOGE(LNN_STATE, "time sync cb not init");
        return SOFTBUS_NETWORK_CLIENT_NOT_INIT;
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

void LnnOnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo)
{
    if (g_busCenterClient.dataLevelCb.onDataLevelChanged == NULL) {
        LNN_LOGW(LNN_STATE, "data level callback is null");
        return;
    }
    DataLevel dataLevel = {
        .dynamicLevel = dataLevelInfo->dynamicLevel,
        .staticLevel = dataLevelInfo->staticLevel,
        .switchLevel = dataLevelInfo->switchLevel,
        .switchLength = dataLevelInfo->switchLength
    };
    g_busCenterClient.dataLevelCb.onDataLevelChanged(networkId, dataLevel);
}

int32_t DiscRecoveryPublish()
{
    if (!g_isInited) {
        LNN_LOGI(LNN_STATE, "no need recovery publish");
        return SOFTBUS_OK;
    }
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_publishMsgList->lock)) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock failed");

    DiscPublishMsg *msgNode = NULL;
    int32_t ret = SOFTBUS_OK;
    LIST_FOR_EACH_ENTRY(msgNode, &(g_publishMsgList->list), DiscPublishMsg, node) {
        if (ServerIpcPublishLNN(msgNode->pkgName, msgNode->info) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "recovery publish error, pkgName=%{public}s, capability=%{public}s",
                msgNode->pkgName, msgNode->info->capability);
            ret = SOFTBUS_NETWORK_PUBLISH_LNN_FAILED;
        } else {
            LNN_LOGI(LNN_STATE, "recovery publish success, pkgName=%{public}s, capability=%{public}s",
                msgNode->pkgName, msgNode->info->capability);
        }
    }

    (void)SoftBusMutexUnlock(&(g_publishMsgList->lock));
    return ret;
}

int32_t DiscRecoverySubscribe()
{
    if (!g_isInited) {
        LNN_LOGI(LNN_STATE, "no need recovery subscribe");
        return SOFTBUS_OK;
    }
    LNN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&(g_discoveryMsgList->lock)) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, LNN_STATE, "lock failed");

    DiscSubscribeMsg *msgNode = NULL;
    int32_t ret = SOFTBUS_OK;
    LIST_FOR_EACH_ENTRY(msgNode, &(g_discoveryMsgList->list), DiscSubscribeMsg, node) {
        if (ServerIpcRefreshLNN(msgNode->pkgName, msgNode->info) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "recovery subscribe error, pkgName=%{public}s, capability=%{public}s",
                msgNode->pkgName, msgNode->info->capability);
            ret = SOFTBUS_NETWORK_REFRESH_LNN_FAILED;
        } else {
            LNN_LOGI(LNN_STATE, "recovery subscribe success, pkgName=%{public}s, capability=%{public}s",
                msgNode->pkgName, msgNode->info->capability);
        }
    }

    (void)SoftBusMutexUnlock(&(g_discoveryMsgList->lock));
    return ret;
}

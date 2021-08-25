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
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define DEFAULT_NODE_STATE_CB_CNT 10

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
} NodeStateCallbackItem;

typedef struct {
    SoftBusList *joinLNNCbList;
    SoftBusList *leaveLNNCbList;
    SoftBusList *nodeStateCbList;
    SoftBusList *timeSyncCbList;
    pthread_mutex_t lock;
} BusCenterClient;

static BusCenterClient g_busCenterClient;

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
    return false;
}

static JoinLNNCbListItem *FindJoinLNNCbItem(ConnectionAddr *addr, OnJoinLNNResult cb)
{
    JoinLNNCbListItem *item = NULL;
    SoftBusList *list = g_busCenterClient.joinLNNCbList;

    LIST_FOR_EACH_ENTRY(item, &list->list, JoinLNNCbListItem, node) {
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
    SoftBusList *list = g_busCenterClient.joinLNNCbList;

    item = (JoinLNNCbListItem *)SoftBusMalloc(sizeof(*item));
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: malloc join LNN cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    item->addr = *target;
    item->cb = cb;
    ListAdd(&list->list, &item->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static LeaveLNNCbListItem *FindLeaveLNNCbItem(const char *networkId, OnLeaveLNNResult cb)
{
    LeaveLNNCbListItem *item = NULL;
    SoftBusList *list = g_busCenterClient.leaveLNNCbList;

    LIST_FOR_EACH_ENTRY(item, &list->list, LeaveLNNCbListItem, node) {
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
    SoftBusList *list = g_busCenterClient.leaveLNNCbList;

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
    ListAdd(&list->list, &item->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static TimeSyncCallbackItem *FindTimeSyncCbItem(const char *networkId, ITimeSyncCb *cb)
{
    TimeSyncCallbackItem *item = NULL;
    SoftBusList *list = g_busCenterClient.timeSyncCbList;

    LIST_FOR_EACH_ENTRY(item, &list->list, TimeSyncCallbackItem, node) {
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
    SoftBusList *list = g_busCenterClient.timeSyncCbList;

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
    ListAdd(&list->list, &item->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static void ClearJoinLNNList(void)
{
    JoinLNNCbListItem *item = NULL;
    JoinLNNCbListItem *next = NULL;
    ListNode *list = &g_busCenterClient.joinLNNCbList->list;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, JoinLNNCbListItem, node) {
        ListDelete(&item->node);
        if (g_busCenterClient.joinLNNCbList->cnt > 0) {
            g_busCenterClient.joinLNNCbList->cnt--;
        }
        SoftBusFree(item);
    }
}

static void ClearLeaveLNNList(void)
{
    LeaveLNNCbListItem *item = NULL;
    LeaveLNNCbListItem *next = NULL;
    ListNode *list = &g_busCenterClient.leaveLNNCbList->list;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, LeaveLNNCbListItem, node) {
        ListDelete(&item->node);
        if (g_busCenterClient.leaveLNNCbList->cnt > 0) {
            g_busCenterClient.leaveLNNCbList->cnt--;
        }
        SoftBusFree(item);
    }
}

static void ClearNodeStateCbList(void)
{
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *next = NULL;
    ListNode *list = &g_busCenterClient.nodeStateCbList->list;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, NodeStateCallbackItem, node) {
        ListDelete(&item->node);
        if (g_busCenterClient.nodeStateCbList->cnt > 0) {
            g_busCenterClient.nodeStateCbList->cnt--;
        }
        SoftBusFree(item);
    }
}

void BusCenterClientDeinit(void)
{
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock in deinit");
    }
    if (g_busCenterClient.joinLNNCbList != NULL) {
        ClearJoinLNNList();
        DestroySoftBusList(g_busCenterClient.joinLNNCbList);
        g_busCenterClient.joinLNNCbList = NULL;
    }
    if (g_busCenterClient.leaveLNNCbList != NULL) {
        ClearLeaveLNNList();
        DestroySoftBusList(g_busCenterClient.leaveLNNCbList);
        g_busCenterClient.leaveLNNCbList = NULL;
    }
    if (g_busCenterClient.nodeStateCbList != NULL) {
        ClearNodeStateCbList();
        DestroySoftBusList(g_busCenterClient.nodeStateCbList);
        g_busCenterClient.nodeStateCbList = NULL;
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock in deinit");
    }
    pthread_mutex_destroy(&g_busCenterClient.lock);
}

int BusCenterClientInit(void)
{
    int32_t rc = SOFTBUS_ERR;

    pthread_mutex_init(&g_busCenterClient.lock, NULL);
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_NODE_STATE_CB_CNT,
        (unsigned char*)&g_maxNodeStateCbCount, sizeof(g_maxNodeStateCbCount)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Cannot get NodeStateCbCount from config file");
        g_maxNodeStateCbCount = DEFAULT_NODE_STATE_CB_CNT;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "NodeStateCbCount is %u", g_maxNodeStateCbCount);
    do {
        g_busCenterClient.joinLNNCbList = CreateSoftBusList();
        if (g_busCenterClient.joinLNNCbList == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init fail : joinLNNCbList = null!");
            break;
        }
        g_busCenterClient.leaveLNNCbList = CreateSoftBusList();
        if (g_busCenterClient.leaveLNNCbList == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "int fail : leaveLNNCbList = null!");
            break;
        }
        g_busCenterClient.nodeStateCbList = CreateSoftBusList();
        if (g_busCenterClient.nodeStateCbList == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "int fail : nodeStateCbList = null!");
            break;
        }
        g_busCenterClient.timeSyncCbList = CreateSoftBusList();
        if (g_busCenterClient.timeSyncCbList == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "int fail : timeSyncCbList = null!");
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);

    if (rc != SOFTBUS_OK) {
        BusCenterClientDeinit();
    }
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

int32_t GetNodeKeyInfoInner(const char *pkgName, const char *networkId, NodeDeivceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    int ret = ServerIpcGetNodeKeyInfo(pkgName, networkId, key, info, infoLen);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Server GetNodeKeyInfo failed, ret = %d", ret);
    }
    return ret;
}

int32_t JoinLNNInner(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    int32_t rc;
    SoftBusList *list = g_busCenterClient.joinLNNCbList;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : join lnn cb list = NULL!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join lnn cb list in join");
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindJoinLNNCbItem(target, cb) != NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : join request already exist");
            break;
        }
        rc = ServerIpcJoinLNN(pkgName, target, sizeof(*target));
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : request join lnn");
        } else {
            rc = AddJoinLNNCbItem(target, cb);
        }
    } while (false);
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock join lnn cb list in join");
    }
    return rc;
}

int32_t LeaveLNNInner(const char *pkgName, const char *networkId, OnLeaveLNNResult cb)
{
    int32_t rc;
    SoftBusList *list = g_busCenterClient.leaveLNNCbList;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : leave lnn cb list = NULL!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
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
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave lnn cb list in leave");
    }
    return rc;
}

int32_t RegNodeDeviceStateCbInner(const char *pkgName, INodeStateCb *callback)
{
    NodeStateCallbackItem *item = NULL;
    int32_t rc = SOFTBUS_ERR;
    SoftBusList *list = g_busCenterClient.nodeStateCbList;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: node state cb list is null");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node state cb list in reg");
    }
    do {
        if (list->cnt >= (uint32_t)g_maxNodeStateCbCount) {
            break;
        }
        item = (NodeStateCallbackItem *)SoftBusMalloc(sizeof(*item));
        if (item == NULL) {
            rc = SOFTBUS_MALLOC_ERR;
            break;
        }
        ListInit(&item->node);
        item->cb = *callback;
        ListAdd(&list->list, &item->node);
        list->cnt++;
        rc = SOFTBUS_OK;
        item = NULL;
    } while (false);
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node state cb list");
    }
    if (item != NULL) {
        SoftBusFree(item);
    }
    return rc;
}

int32_t UnregNodeDeviceStateCbInner(INodeStateCb *callback)
{
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *next = NULL;
    SoftBusList *list = g_busCenterClient.nodeStateCbList;
    if (list == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node state cb list in unreg");
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &list->list, NodeStateCallbackItem, node) {
        if (memcmp(&item->cb, callback, sizeof(*callback)) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
            if (list->cnt > 0) {
                list->cnt--;
            }
            break;
        }
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node state cb list in unreg");
    }
    return SOFTBUS_OK;
}

int32_t StartTimeSyncInner(const char *pkgName, const char *targetNetworkId, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period, ITimeSyncCb *cb)
{
    int32_t rc;
    SoftBusList *list = g_busCenterClient.timeSyncCbList;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : time sync cb list = NULL!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
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
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock time sync cb list");
    }
    return rc;
}

int32_t StopTimeSyncInner(const char *pkgName, const char *targetNetworkId)
{
    int32_t rc;
    TimeSyncCallbackItem *item = NULL;
    SoftBusList *list = g_busCenterClient.timeSyncCbList;
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : time sync cb list = NULL!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock time sync cb list");
    }
    rc = SOFTBUS_ERR;
    while ((item = FindTimeSyncCbItem(targetNetworkId, NULL)) != NULL) {
        rc = ServerIpcStopTimeSync(pkgName, targetNetworkId);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail : stop time sync");
        } else {
            ListDelete(&item->node);
            --list->cnt;
            SoftBusFree(item);
        }
    }

    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock time sync cb list");
    }
    return rc;
}

int32_t LnnOnJoinResult(void *addr, const char *networkId, int32_t retCode)
{
    SoftBusList *list = g_busCenterClient.joinLNNCbList;
    JoinLNNCbListItem *item = NULL;
    ConnectionAddr *connAddr = (ConnectionAddr *)addr;

    if (connAddr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (list == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join lnn cb list in join result");
    }
    while ((item = FindJoinLNNCbItem(addr, NULL)) != NULL) {
        ListDelete(&item->node);
        if (item->cb != NULL) {
            item->cb(connAddr, networkId, retCode);
        }
        --list->cnt;
        SoftBusFree(item);
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock join lnn cb list in join result");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode)
{
    SoftBusList *list = g_busCenterClient.leaveLNNCbList;
    LeaveLNNCbListItem *item = NULL;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: leave cb list is null");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock leave lnn cb list in leave result");
    }
    while ((item = FindLeaveLNNCbItem(networkId, NULL)) != NULL) {
        ListDelete(&item->node);
        if (item->cb != NULL) {
            item->cb(networkId, retCode);
        }
        --list->cnt;
        SoftBusFree(item);
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock leave lnn cb list in leave result");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnNodeOnlineStateChanged(bool isOnline, void *info)
{
    SoftBusList *list = g_busCenterClient.nodeStateCbList;
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;

    if (basicInfo == NULL || list == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node state cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &list->list, NodeStateCallbackItem, node) {
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
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node state cb list in notify");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnNodeBasicInfoChanged(void *info, int32_t type)
{
    SoftBusList *list = g_busCenterClient.nodeStateCbList;
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;

    if (basicInfo == NULL || list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (type < 0 || type > TYPE_DEVICE_NAME) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnNodeBasicInfoChanged invalid type: %d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock node basic info cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &list->list, NodeStateCallbackItem, node) {
        if ((item->cb.events & EVENT_NODE_STATE_INFO_CHANGED) != 0) {
            item->cb.onNodeBasicInfoChanged(type, basicInfo);
        }
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock node basic info cb list in notify");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnTimeSyncResult(const void *info, int retCode)
{
    SoftBusList *list = g_busCenterClient.timeSyncCbList;
    TimeSyncCallbackItem *item = NULL;
    TimeSyncResultInfo *basicInfo = (TimeSyncResultInfo *)info;

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: leave cb list is null");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: lock time sync cb list in time sync result");
    }
    LIST_FOR_EACH_ENTRY(item, &list->list, TimeSyncCallbackItem, node) {
        if (strcmp(item->networkId, basicInfo->target.targetNetworkId) == 0 && item->cb.onTimeSyncResult != NULL) {
            item->cb.onTimeSyncResult(info, retCode);
        }
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: unlock time sync cb list in time sync result");
    }
    return SOFTBUS_OK;
}
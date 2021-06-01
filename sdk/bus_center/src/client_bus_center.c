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

#include "client_bus_center.h"

#include <pthread.h>
#include <securec.h>

#include "softbus_client_frame_manager.h"
#include "softbus_errcode.h"
#include "softbus_interface.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_property.h"
#include "softbus_utils.h"

#define GET_MAX_NODE_STATE_CB_CNT "MAX_NODE_STATE_CB_CNT"
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
    INodeStateCb cb;
} NodeStateCallbackItem;

typedef struct {
    SoftBusList *joinLNNCbList;
    SoftBusList *leaveLNNCbList;
    SoftBusList *nodeStateCbList;
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
        return true;
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
        LOG_ERR("fail: malloc join LNN cb list item");
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
        LOG_ERR("fail: malloc join LNN cb list item");
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&item->node);
    if (strncpy_s(item->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LOG_ERR("strcpy network id fail");
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    item->cb = cb;
    ListAdd(&list->list, &item->node);
    list->cnt++;
    return SOFTBUS_OK;
}

static bool IsValidNodeStateCb(INodeStateCb *callback)
{
    if (callback == NULL) {
        return false;
    }
    if (callback->events == 0) {
        return false;
    }
    if ((callback->events & EVENT_NODE_STATE_ONLINE) != 0 &&
        callback->onNodeOnline == NULL) {
        return false;
    }
    if ((callback->events & EVENT_NODE_STATE_OFFLINE) != 0 &&
        callback->onNodeOffline == NULL) {
        return false;
    }
    if ((callback->events & EVENT_NODE_STATE_INFO_CHANGED) != 0 &&
        callback->onNodeBasicInfoChanged == NULL) {
        return false;
    }
    return true;
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
        LOG_ERR("fail: lock in deinit");
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
        LOG_ERR("fail: unlock in deinit");
    }
    pthread_mutex_destroy(&g_busCenterClient.lock);
}

int BusCenterClientInit(void)
{
    int32_t rc = SOFTBUS_ERR;

    pthread_mutex_init(&g_busCenterClient.lock, NULL);
    if (GetPropertyInt(GET_MAX_NODE_STATE_CB_CNT, &g_maxNodeStateCbCount) != SOFTBUS_OK) {
        LOG_ERR("Cannot get NodeStateCbCount from config file");
        g_maxNodeStateCbCount = DEFAULT_NODE_STATE_CB_CNT;
    }
    do {
        g_busCenterClient.joinLNNCbList = CreateSoftBusList();
        if (g_busCenterClient.joinLNNCbList == NULL) {
            LOG_ERR("init fail : joinLNNCbList = null!");
            break;
        }
        g_busCenterClient.leaveLNNCbList = CreateSoftBusList();
        if (g_busCenterClient.leaveLNNCbList == NULL) {
            LOG_ERR("int fail : leaveLNNCbList = null!");
            break;
        }
        g_busCenterClient.nodeStateCbList = CreateSoftBusList();
        if (g_busCenterClient.nodeStateCbList == NULL) {
            LOG_ERR("int fail : nodeStateCbList = null!");
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);

    if (rc != SOFTBUS_OK) {
        BusCenterClientDeinit();
    }
    LOG_INFO("BusCenterClientInit init OK!");
    return SOFTBUS_OK;
}

int32_t GetAllNodeDeviceInfo(const char *pkgName, NodeBasicInfo **info, int32_t *infoNum)
{
    if (pkgName == NULL || info == NULL || infoNum == NULL) {
        LOG_ERR("fail: params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    return GetServerProvideInterface()->getAllOnlineNodeInfo((void **)info, sizeof(NodeBasicInfo), infoNum);
}

void FreeNodeInfo(NodeBasicInfo *info)
{
    if (info == NULL) {
        return;
    }
    SoftBusFree(info);
}

int32_t GetLocalNodeDeviceInfo(const char *pkgName, NodeBasicInfo *info)
{
    if (pkgName == NULL || info == NULL) {
        LOG_ERR("fail: params are null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    return GetServerProvideInterface()->getLocalDeviceInfo(info, sizeof(*info));
}

int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId, NodeDeivceInfoKey key,
    uint8_t *info, int32_t infoLen)
{
    if (pkgName == NULL) {
        LOG_ERR("fail: pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    if (!IsValidString(networkId, NETWORK_ID_BUF_LEN) || info == NULL) {
        LOG_ERR("invalid params");
        return SOFTBUS_INVALID_PARAM;
    }
    return GetServerProvideInterface()->getNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t JoinLNN(const char *pkgName, ConnectionAddr *target, OnJoinLNNResult cb)
{
    int32_t rc;
    SoftBusList *list = NULL;

    if (pkgName == NULL || target == NULL || cb == NULL) {
        LOG_ERR("fail : params are NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    list = g_busCenterClient.joinLNNCbList;
    if (list == NULL) {
        LOG_ERR("fail : join lnn cb list = NULL!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: lock join lnn cb list in join");
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindJoinLNNCbItem(target, cb) != NULL) {
            LOG_ERR("fail : join request already exist");
            break;
        }
        rc = GetServerProvideInterface()->joinLNN(target, sizeof(*target));
        if (rc != SOFTBUS_OK) {
            LOG_ERR("fail : request join lnn");
        } else {
            rc = AddJoinLNNCbItem(target, cb);
        }
    } while (false);
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: unlock join lnn cb list in join");
    }
    return rc;
}

int32_t LeaveLNN(const char *networkId, OnLeaveLNNResult cb)
{
    int32_t rc;
    SoftBusList *list = g_busCenterClient.leaveLNNCbList;

    if (networkId == NULL || cb == NULL) {
        LOG_ERR("fail : networkId or cb is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (list == NULL) {
        LOG_ERR("fail : leave lnn cb list = NULL!");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: lock leave lnn cb list in leave");
    }
    rc = SOFTBUS_ERR;
    do {
        if (FindLeaveLNNCbItem(networkId, cb) != NULL) {
            LOG_ERR("fail : leave request already exist");
            break;
        }
        rc = GetServerProvideInterface()->leaveLNN(networkId);
        if (rc != SOFTBUS_OK) {
            LOG_ERR("fail : request leave lnn");
        } else {
            rc = AddLeaveLNNCbItem(networkId, cb);
        }
    } while (false);
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: unlock leave lnn cb list in leave");
    }
    return rc;
}

int32_t RegNodeDeviceStateCb(const char *pkgName, INodeStateCb *callback)
{
    SoftBusList *list = NULL;
    NodeStateCallbackItem *item = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (pkgName == NULL || IsValidNodeStateCb(callback) == false) {
        LOG_ERR("fail: invalid parameters");
        return SOFTBUS_INVALID_PARAM;
    }
    if (InitSoftBus(pkgName) != SOFTBUS_OK) {
        LOG_ERR("fail: init softbus");
        return SOFTBUS_ERR;
    }
    list = g_busCenterClient.nodeStateCbList;
    if (list == NULL) {
        LOG_ERR("fail: node state cb list is null");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: lock node state cb list in reg");
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
        LOG_ERR("fail: unlock node state cb list");
    }
    if (item != NULL) {
        SoftBusFree(item);
    }
    return rc;
}

int32_t UnregNodeDeviceStateCb(INodeStateCb *callback)
{
    SoftBusList *list = g_busCenterClient.nodeStateCbList;
    NodeStateCallbackItem *item = NULL;
    NodeStateCallbackItem *next = NULL;

    if (callback == NULL) {
        LOG_ERR("para callback = null!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (list == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: lock node state cb list in unreg");
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
        LOG_ERR("fail: unlock node state cb list in unreg");
    }
    return SOFTBUS_OK;
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
        LOG_ERR("fail: lock join lnn cb list in join result");
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
        LOG_ERR("fail: lock join lnn cb list in join result");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnLeaveResult(const char *networkId, int32_t retCode)
{
    SoftBusList *list = g_busCenterClient.leaveLNNCbList;
    LeaveLNNCbListItem *item = NULL;

    if (networkId == NULL) {
        LOG_ERR("fail: networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (list == NULL) {
        LOG_ERR("fail: leave cb list is null");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: lock leave lnn cb list in leave result");
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
        LOG_ERR("fail: unlock leave lnn cb list in leave result");
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
        LOG_ERR("fail: lock node state cb list in notify");
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
        LOG_ERR("fail: unlock node state cb list in notify");
    }
    return SOFTBUS_OK;
}

int32_t LnnOnNodeBasicInfoChanged(void *info, int32_t type)
{
    SoftBusList *list = g_busCenterClient.nodeStateCbList;
    NodeStateCallbackItem *item = NULL;
    NodeBasicInfo *basicInfo = (NodeBasicInfo *)info;

    if (basicInfo == NULL || list == NULL) {
        LOG_ERR("info or list is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (type < 0 || type > TYPE_DEVICE_NAME) {
        LOG_ERR("OnNodeBasicInfoChanged invalid type: %d", type);
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: lock node basic info cb list in notify");
    }
    LIST_FOR_EACH_ENTRY(item, &list->list, NodeStateCallbackItem, node) {
        if ((item->cb.events & EVENT_NODE_STATE_INFO_CHANGED) != 0) {
            item->cb.onNodeBasicInfoChanged(type, basicInfo);
        }
    }
    if (pthread_mutex_unlock(&g_busCenterClient.lock) != 0) {
        LOG_ERR("fail: unlock node basic info cb list in notify");
    }
    return SOFTBUS_OK;
}

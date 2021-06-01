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

#include "softbus_conn_manager.h"

#include <securec.h>

#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager_weak.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_utils.h"

ConnectFuncInterface *g_connManager[CONNECT_TYPE_MAX] = {0};
static SoftBusList *g_listenerList = NULL;
static bool g_isInited = false;

typedef struct TagConnListenerNode {
    ListNode node;
    ConnModule moduleId;
    ConnectCallback callback;
} ConnListenerNode;

static int32_t ModuleCheck(ConnModule moduleId)
{
    ConnModule id[] = {
        MODULE_TRUST_ENGINE, MODULE_HICHAIN, MODULE_AUTH_SDK, MODULE_AUTH_CONNECTION, MODULE_MESSAGE_SERVICE,
        MODULE_BLUETOOTH_MANAGER, MODULE_CONNECTION, MODULE_DIRECT_CHANNEL, MODULE_PROXY_CHANNEL,
        MODULE_DEVICE_AUTH, MODULE_P2P_LINK, MODULE_PKG_VERIFY, MODULE_BLE_NET,
        MODULE_BLE_CONN
    };
    int32_t i;
    int32_t idNum = sizeof(id) / sizeof(ConnModule);

    for (i = 0; i < idNum; i++) {
        if (moduleId == id[i]) {
            return SOFTBUS_OK;
        }
    }
    LOG_ERR("check module fail %d", moduleId);
    return SOFTBUS_ERR;
}

static int32_t ConnTypeCheck(ConnectType type)
{
    if (type >= CONNECT_TYPE_MAX) {
        LOG_ERR("type is over max %d", type);
        return SOFTBUS_ERR;
    }

    if (g_connManager[type] == NULL) {
        LOG_ERR("type is %d", type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetAllListener(ConnListenerNode **node)
{
    ConnListenerNode *listenerNode = NULL;
    int32_t cnt = 0;

    if (g_listenerList == NULL) {
        LOG_ERR("listener list is null");
        return cnt;
    }

    if (g_listenerList->cnt == 0) {
        LOG_ERR("listener cnt is null");
        return cnt;
    }

    if (pthread_mutex_lock(&g_listenerList->lock) != 0) {
        LOG_ERR("lock mutex failed");
        return 0;
    }
    *node = SoftBusCalloc(g_listenerList->cnt * sizeof(ConnListenerNode));
    if (*node == NULL) {
        (void)pthread_mutex_unlock(&g_listenerList->lock);
        return cnt;
    }
    LIST_FOR_EACH_ENTRY(listenerNode, &g_listenerList->list, ConnListenerNode, node) {
        if (memcpy_s(*node + cnt, sizeof(ConnListenerNode), listenerNode, sizeof(ConnListenerNode)) != EOK) {
            LOG_ERR("mem error");
        }
        cnt++;
    }
    (void)pthread_mutex_unlock(&g_listenerList->lock);
    return cnt;
}

static int32_t GetListenerByModuleId(ConnModule moduleId, ConnListenerNode *node)
{
    ConnListenerNode *listenerNode = NULL;

    if (g_listenerList == NULL) {
        return SOFTBUS_ERR;
    }
    int ret = SOFTBUS_OK;
    if (pthread_mutex_lock(&g_listenerList->lock) != 0) {
        LOG_ERR("lock mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH_ENTRY(listenerNode, &g_listenerList->list, ConnListenerNode, node) {
        if (listenerNode->moduleId == moduleId) {
            if (memcpy_s(node, sizeof(ConnListenerNode), listenerNode, sizeof(ConnListenerNode)) != EOK) {
                ret = SOFTBUS_ERR;
            }
            (void)pthread_mutex_unlock(&g_listenerList->lock);
            return ret;
        }
    }
    (void)pthread_mutex_unlock(&g_listenerList->lock);
    return SOFTBUS_ERR;
}

static int32_t AddListener(ConnModule moduleId, const ConnectCallback *callback)
{
    ConnListenerNode *item = NULL;
    ConnListenerNode *listNode = NULL;

    if (g_listenerList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_listenerList->lock) != 0) {
        LOG_ERR("lock mutex failed");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(listNode, &g_listenerList->list, ConnListenerNode, node) {
        if (listNode->moduleId == moduleId) {
            (void)pthread_mutex_unlock(&g_listenerList->lock);
            return SOFTBUS_ERR;
        }
    }

    item = (ConnListenerNode *)SoftBusCalloc(sizeof(ConnListenerNode));
    if (item == NULL) {
        LOG_ERR("malloc fail");
        (void)pthread_mutex_unlock(&g_listenerList->lock);
        return SOFTBUS_ERR;
    }

    item->moduleId = moduleId;
    if (memcpy_s(&(item->callback), sizeof(ConnectCallback), callback, sizeof(ConnectCallback)) != 0) {
        SoftBusFree(item);
        (void)pthread_mutex_unlock(&g_listenerList->lock);
        return SOFTBUS_ERR;
    }
    ListAdd(&(g_listenerList->list), &(item->node));
    g_listenerList->cnt++;
    (void)pthread_mutex_unlock(&g_listenerList->lock);
    return SOFTBUS_OK;
}

static void DelListener(ConnModule moduleId)
{
    ConnListenerNode *removeNode = NULL;
    if (g_listenerList == NULL) {
        LOG_ERR("listenerList is null");
        return;
    }

    if (pthread_mutex_lock(&g_listenerList->lock) != 0) {
        LOG_ERR("lock mutex failed");
        return;
    }

    LIST_FOR_EACH_ENTRY(removeNode, &g_listenerList->list, ConnListenerNode, node) {
        if (removeNode->moduleId == moduleId) {
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            g_listenerList->cnt--;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_listenerList->lock);
    return;
}

uint32_t ConnGetHeadSize()
{
    return sizeof(ConnPktHead);
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
#define REQID_MAX 1000000
    (void)moduleId;
    static uint32_t reqId = 1;
    reqId++;
    reqId = reqId % REQID_MAX + 1;
    return reqId;
}

void ConnManagerRecvData(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    ConnListenerNode listener;
    int32_t ret;
    char* pkt = NULL;
    int32_t pktLen;

    if (data == NULL) {
        return;
    }

    if (len <= (int32_t)sizeof(ConnPktHead)) {
        LOG_ERR("len %d \r\n", len);
        return;
    }

    ret = GetListenerByModuleId(moduleId, &listener);
    if (ret == SOFTBUS_ERR) {
        LOG_ERR("GetListenerByModuleId fail moduleId %d \r\n", moduleId);
        return;
    }

    pktLen = len - sizeof(ConnPktHead);
    pkt = data + sizeof(ConnPktHead);
    listener.callback.OnDataReceived(connectionId, moduleId, seq, pkt, pktLen);
    return;
}

void ConnManagerConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    int32_t i, num;
    ConnListenerNode *node = NULL;
    ConnListenerNode *listener = NULL;

    num = GetAllListener(&node);
    if (num == 0 || node == NULL) {
        LOG_ERR("get node fail connId %u", connectionId);
        return;
    }
    for (i = 0; i < num; i++) {
        listener = node + i;
        listener->callback.OnConnected(connectionId, info);
    }
    SoftBusFree(node);
    return;
}

void ConnManagerDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    int32_t i, num;
    ConnListenerNode *node = NULL;
    ConnListenerNode *listener = NULL;

    num = GetAllListener(&node);
    if (num == 0 || node == NULL) {
        return;
    }
    for (i = 0; i < num; i++) {
        listener = node + i;
        listener->callback.OnDisconnected(connectionId, info);
    }
    SoftBusFree(node);
    return;
}

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    if (ModuleCheck(moduleId) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (callback == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if ((callback->OnConnected == NULL) ||
        (callback->OnDisconnected == NULL) ||
        (callback->OnDataReceived == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return AddListener(moduleId, callback);
}

void ConnUnSetConnectCallback(ConnModule moduleId)
{
    DelListener(moduleId);
    return;
}

int32_t ConnTypeIsSupport(ConnectType type)
{
    return ConnTypeCheck(type);
}

int32_t ConnConnectDevice(const ConnectOption *info, uint32_t requestId, const ConnectResult *result)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ConnTypeCheck(info->type) != SOFTBUS_OK) {
        LOG_ERR("connect type is err %d", info->type);
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[info->type]->ConnectDevice == NULL) {
        return SOFTBUS_ERR;
    }

    return g_connManager[info->type]->ConnectDevice(info, requestId, result);
}

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    uint32_t type;
    ConnPktHead *head = NULL;

    if (data == NULL || data->buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (data->len <= (int32_t)sizeof(ConnPktHead)) {
        SoftBusFree(data->buf);
        return SOFTBUS_CONN_MANAGER_PKT_LEN_INVALID;
    }

    type = (connectionId >> CONNECT_TYPE_SHIFT);
    if (ConnTypeCheck((ConnectType)type) != SOFTBUS_OK) {
        LOG_ERR("connectionId type is err %d", type);
        SoftBusFree(data->buf);
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[type]->PostBytes == NULL) {
        SoftBusFree(data->buf);
        return SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT;
    }

    head = (ConnPktHead *)data->buf;
    head->magic = MAGIC_NUMBER;
    head->flag = data->flag;
    head->module = data->module;
    head->len = data->len - sizeof(ConnPktHead);
    head->seq = data->seq;

    return g_connManager[type]->PostBytes(connectionId, data->buf, data->len, data->pid, data->flag);
}

int32_t ConnDisconnectDevice(uint32_t connectionId)
{
    uint32_t type = (connectionId >> CONNECT_TYPE_SHIFT);
    if (ConnTypeCheck((ConnectType)type) != SOFTBUS_OK) {
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[type]->DisconnectDevice == NULL) {
        return SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT;
    }
    return g_connManager[type]->DisconnectDevice(connectionId);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    if (option == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ConnTypeCheck(option->type) != SOFTBUS_OK) {
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[option->type]->DisconnectDeviceNow == NULL) {
        return SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT;
    }
    return g_connManager[option->type]->DisconnectDeviceNow(option);
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    uint32_t type = (connectionId >> CONNECT_TYPE_SHIFT);
    if (ConnTypeCheck((ConnectType)type) != SOFTBUS_OK) {
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[type]->GetConnectionInfo == NULL) {
        return SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT;
    }

    return g_connManager[type]->GetConnectionInfo(connectionId, info);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ConnTypeCheck(info->type) != SOFTBUS_OK) {
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[info->type]->StartLocalListening == NULL) {
        return SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT;
    }

    return g_connManager[info->type]->StartLocalListening(info);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ConnTypeCheck(info->type) != SOFTBUS_OK) {
        return SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT;
    }

    if (g_connManager[info->type]->StopLocalListening == NULL) {
        return SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT;
    }

    return g_connManager[info->type]->StopLocalListening(info);
}

ConnectCallback g_connManagerCb = {0};

int32_t ConnServerInit(void)
{
    ConnectFuncInterface *connectObj = NULL;

    if (g_isInited) {
        return SOFTBUS_ERR;
    }

    g_connManagerCb.OnConnected = ConnManagerConnected;
    g_connManagerCb.OnDisconnected = ConnManagerDisconnected;
    g_connManagerCb.OnDataReceived = ConnManagerRecvData;

    connectObj = ConnInitTcp(&g_connManagerCb);
    if (connectObj != NULL) {
        g_connManager[CONNECT_TCP] = connectObj;
        LOG_INFO("init tcp ok \r\n");
    }

    connectObj = ConnInitBr(&g_connManagerCb);
    if (connectObj != NULL) {
        g_connManager[CONNECT_BR] = connectObj;
        LOG_INFO("init br ok \r\n");
    }

    connectObj = ConnInitBle(&g_connManagerCb);
    if (connectObj != NULL) {
        g_connManager[CONNECT_BLE] = connectObj;
        LOG_INFO("init ble ok \r\n");
    }

    if (g_listenerList == NULL) {
        g_listenerList = CreateSoftBusList();
        if (g_listenerList == NULL) {
            LOG_ERR("create list fail \r\n");
            return SOFTBUS_ERR;
        }
    }

    g_isInited = true;
    LOG_INFO("connect manager init success. \r\n");
    return SOFTBUS_OK;
}

void ConnServerDeinit(void)
{
    if (!g_isInited) {
        return;
    }

    ConnListenerNode *item = NULL;
    if (g_listenerList != NULL) {
        while (!IsListEmpty(&g_listenerList->list)) {
            item = LIST_ENTRY(&(g_listenerList->list.next), ConnListenerNode, node);
            ListDelete(&item->node);
            SoftBusFree(item);
        }
        DestroySoftBusList(g_listenerList);
        g_listenerList = NULL;
    }

    g_isInited = false;
}


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

#include "softbus_proxychannel_transceiver.h"

#include <securec.h>

#include "message_handler.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_utils.h"

static SoftBusList *g_proxyConnectionList = NULL;
char *g_transProxyLoopName = "transProxyLoopName";
SoftBusHandler g_transLoophandler = {0};
typedef enum {
    LOOP_HANDSHAKE_MSG,
    LOOP_DISCONNECT_MSG,
    LOOP_OPENFAIL_MSG,
    LOOP_OPENCLOSE_MSG,
    LOOP_KEEPALIVE_MSG,
    LOOP_RESETPEER_MSG,
} LoopMsg;

static int32_t TransDelConnByReqId(uint32_t reqId)
{
    ProxyConnInfo *removeNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (removeNode->requestId == reqId && removeNode->state == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            g_proxyConnectionList->cnt--;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return SOFTBUS_OK;
}

void TransDelConnByConnId(uint32_t connId)
{
    ProxyConnInfo *removeNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (removeNode->connId == connId) {
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            LOG_INFO("del conn item");
            g_proxyConnectionList->cnt--;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return;
}

int32_t TransDecConnRefByConnId(uint32_t connId)
{
    ProxyConnInfo *removeNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (removeNode->connId == connId) {
            removeNode->ref--;
            if (removeNode->ref <= 0) {
                ListDelete(&(removeNode->node));
                SoftBusFree(removeNode);
                g_proxyConnectionList->cnt--;
                (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
                LOG_INFO("conn ref is 0");
                return SOFTBUS_OK;
            } else {
                LOG_INFO("removeNode->ref %d", removeNode->ref);
                (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
                return SOFTBUS_ERR;
            }
        }
    }

    LOG_INFO("not find conn item");
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return SOFTBUS_OK;
}

int32_t TransAddConnRefByConnId(uint32_t connId)
{
    ProxyConnInfo *item = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->connId == connId) {
            item->ref++;
            LOG_INFO("add conn ref %d", item->ref);
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return SOFTBUS_OK;
}

static void TransProxyLoopMsgHandler(SoftBusMessage *msg)
{
    int32_t chanId;
    uint32_t connectionId;
    ProxyChannelInfo *chan = NULL;

    if (msg == NULL) {
        return;
    }
    LOG_INFO("trans loop process msg type %d", msg->what);
    switch (msg->what) {
        case LOOP_HANDSHAKE_MSG:
            chanId = *((int32_t *)msg->obj);
            TransProxyOpenProxyChannelSuccess(chanId);
            break;
        case LOOP_DISCONNECT_MSG:
            connectionId = (uint32_t)msg->arg2;
            TransProxyCloseConnChannel(connectionId);
            break;
        case LOOP_OPENFAIL_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            if (chan == NULL) {
                return;
            }
            OnProxyChannelOpenFailed(chan->channelId, &(chan->appInfo));
            break;
        case LOOP_OPENCLOSE_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            if (chan == NULL) {
                return;
            }
            OnProxyChannelClosed(chan->channelId, &(chan->appInfo));
            break;
        case LOOP_KEEPALIVE_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            if (chan == NULL) {
                return;
            }
            TransProxyKeepalive(chan->connId, chan);
            break;
        case LOOP_RESETPEER_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            if (chan == NULL) {
                return;
            }
            TransProxyResetPeer(chan);
            break;
        default:
            break;
    }
}

void TransProxyFreeLoopMsg(SoftBusMessage *msg)
{
    if (msg != NULL) {
        if (msg->obj != NULL) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree((void *)msg);
    }
}
static SoftBusMessage *TransProxyCreateLoopMsg(int32_t what, uint64_t arg1, uint64_t arg2, char *data)
{
    SoftBusMessage *msg = NULL;
    msg = SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_transLoophandler;
    msg->FreeMessage = TransProxyFreeLoopMsg;
    msg->obj = (void *)data;
    return msg;
}

void TransProxyPostResetPeerMsgToLoop(const ProxyChannelInfo *chan)
{
    SoftBusMessage *msg  = TransProxyCreateLoopMsg(LOOP_RESETPEER_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        return;
    }
    g_transLoophandler.looper->PostMessage(g_transLoophandler.looper, msg);
    return;
}

void TransProxyPostHandshakeMsgToLoop(int32_t chanId)
{
    int32_t *chanIdMsg = (int32_t *)SoftBusCalloc(sizeof(int32_t));
    if (chanIdMsg == NULL) {
        return;
    }
    *chanIdMsg = chanId;
    SoftBusMessage *msg  = TransProxyCreateLoopMsg(LOOP_HANDSHAKE_MSG, 0, 0, (char *)chanIdMsg);
    if (msg == NULL) {
        return;
    }
    g_transLoophandler.looper->PostMessage(g_transLoophandler.looper, msg);
    return;
}

void TransProxyPostDisConnectMsgToLoop(uint32_t connId)
{
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_DISCONNECT_MSG, 0, connId, NULL);
    if (msg == NULL) {
        return;
    }
    g_transLoophandler.looper->PostMessage(g_transLoophandler.looper, msg);
    return;
}

void TransProxyPostKeepAliveMsgToLoop(const ProxyChannelInfo *chan)
{
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_KEEPALIVE_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        return;
    }
    g_transLoophandler.looper->PostMessage(g_transLoophandler.looper, msg);
    return;
}

void TransProxyPostOpenFailMsgToLoop(const ProxyChannelInfo *chan)
{
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_OPENFAIL_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        return;
    }
    g_transLoophandler.looper->PostMessage(g_transLoophandler.looper, msg);
    return;
}

void TransProxyPostOpenClosedMsgToLoop(const ProxyChannelInfo *chan)
{
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_OPENCLOSE_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        return;
    }
    g_transLoophandler.looper->PostMessage(g_transLoophandler.looper, msg);
    return;
}

int32_t TransProxyLoopInit()
{
    g_transLoophandler.name = g_transProxyLoopName;
    g_transLoophandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_transLoophandler.looper == NULL) {
        return SOFTBUS_ERR;
    }
    g_transLoophandler.HandleMessage = TransProxyLoopMsgHandler;
    return SOFTBUS_OK;
}
int32_t TransProxyGetConnectOption(uint32_t connectionId, ConnectOption *info)
{
    ConnectionInfo connInfo = {0};

    if (info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ConnGetConnectionInfo(connectionId, &connInfo) != SOFTBUS_OK) {
        LOG_ERR("CONN_GetConnectionInfo fail connectionId %u", connectionId);
        return SOFTBUS_ERR;
    }
    info->type = connInfo.type;
    switch (info->type) {
        case CONNECT_BR: {
            (void)memcpy_s(info->info.brOption.brMac, sizeof(info->info.brOption.brMac),
                connInfo.info.brInfo.brMac, sizeof(connInfo.info.brInfo.brMac));
            break;
        }
        case CONNECT_BLE: {
            (void)memcpy_s(info->info.bleOption.bleMac, sizeof(info->info.bleOption.bleMac),
                connInfo.info.bleInfo.bleMac, sizeof(connInfo.info.bleInfo.bleMac));
            (void)memcpy_s(info->info.bleOption.deviceIdHash, sizeof(info->info.bleOption.deviceIdHash),
                connInfo.info.bleInfo.deviceIdHash, sizeof(connInfo.info.bleInfo.deviceIdHash));
            break;
        }
        case CONNECT_TCP: {
            (void)memcpy_s(info->info.ipOption.ip, sizeof(info->info.ipOption.ip),
                connInfo.info.ipInfo.ip, sizeof(connInfo.info.ipInfo.ip));
            info->info.ipOption.port = connInfo.info.ipInfo.port;
            break;
        }
        default: {
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransProxyTransSendMsg(uint32_t connectionId, char *buf, int32_t len, int32_t priority)
{
    ConnPostData data = {0};
    static uint64_t seq = 1;
    int32_t ret;

    data.module = MODULE_PROXY_CHANNEL;
    data.seq = seq++;
    data.flag = priority;
    data.len = len;
    data.buf = buf;
    LOG_INFO("send buf connid %d len %d seq %llu pri %d", connectionId, len, data.seq, priority);
    ret = ConnPostBytes(connectionId, &data);
    if (ret < 0) {
        LOG_ERR("conn send buf fail %d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void TransProxyOnConnected(uint32_t connId, const ConnectionInfo *connInfo)
{
    (void)connInfo;
    LOG_INFO("connect enabled, connId = %u", connId);
    return;
}

static void TransProxyOnDisConnect(uint32_t connId, const ConnectionInfo *connInfo)
{
    (void)connInfo;
    LOG_INFO("connect disabled, id = %u", connId);
    TransProxyDelByConnId(connId);
    TransDelConnByConnId(connId);
    return;
}

int32_t TransAddConnItem(ProxyConnInfo *chan)
{
    ProxyConnInfo *item = NULL;
    ProxyConnInfo *tmpItem = NULL;
    int find = 0;

    if (g_proxyConnectionList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, tmpItem, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (strcmp(item->connInfo.info.brOption.brMac, chan->connInfo.info.brOption.brMac) == 0) {
            LOG_INFO("conn ref = %d", item->ref);
            find = 1;
            break;
        }
    }
    if (find == 0) {
        LOG_INFO("add conn item");
        ListAdd(&(g_proxyConnectionList->list), &(chan->node));
        g_proxyConnectionList->cnt++;
        (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
        return SOFTBUS_OK;
    } else {
        uint32_t state = item->state;
        uint32_t connId = item->connId;
        (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
        LOG_INFO("conn state %d conn id %d", state, connId);
        if (state == PROXY_CHANNEL_STATUS_PYH_CONNECTED) {
            TransProxyChanProcessByReqId(chan->requestId, connId);
        }
        return SOFTBUS_ERR;
    }
}

void TransCreateConnByConnId(uint32_t connId)
{
    ProxyConnInfo *item = NULL;
    ProxyConnInfo *tmpNode = NULL;
    ConnectionInfo info = {0};

    if (g_proxyConnectionList == NULL) {
        return;
    }

    if (ConnGetConnectionInfo(connId, &info) != SOFTBUS_OK) {
        LOG_ERR("CreateConn get conn info fail %d", connId);
        return;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->connId == connId) {
            item->ref++;
            LOG_INFO("repeat conn ref = %d", item->ref);
            (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
            return;
        }
    }

    item = SoftBusCalloc(sizeof(ProxyConnInfo));
    if (item == NULL) {
        (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
        return;
    }
    item->ref++;
    item->state = PROXY_CHANNEL_STATUS_PYH_CONNECTED;
    LOG_INFO("create conn ref = %d", item->ref);
    item->connId = connId;
    (void)memcpy_s(&(item->connInfo), sizeof(ConnectOption), &info, sizeof(ConnectOption));
    ListAdd(&(g_proxyConnectionList->list), &(item->node));
    g_proxyConnectionList->cnt++;
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return;
}


static int32_t TransGetConnByMac(const char *brMac, ProxyConnInfo *conn)
{
    ProxyConnInfo *getNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(getNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (strcmp(getNode->connInfo.info.brOption.brMac, brMac) == 0) {
            (void)memcpy_s(conn, sizeof(ProxyConnInfo), getNode, sizeof(ProxyConnInfo));
            (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return SOFTBUS_ERR;
}

void TransSetConnStateByReqId(uint32_t reqId, uint32_t connId, uint32_t state)
{
    ProxyConnInfo *getNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return;
    }

    if (pthread_mutex_lock(&g_proxyConnectionList->lock) != 0) {
        LOG_ERR("lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(getNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (getNode->requestId == reqId && getNode->state == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            getNode->state = state;
            getNode->connId = connId;
            getNode->requestId = 0;
            (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
            return;
        }
    }
    (void)pthread_mutex_unlock(&g_proxyConnectionList->lock);
    return;
}

static void TransOnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *connInfo)
{
    LOG_INFO("Connect Successe reqid %d, connectionId %d", requestId, connectionId);
    TransSetConnStateByReqId(requestId,  connectionId, PROXY_CHANNEL_STATUS_PYH_CONNECTED);
    TransProxyChanProcessByReqId(requestId, connectionId);
}

static void TransOnConnectFailed(uint32_t requestId, int32_t reason)
{
    LOG_ERR("Connect fail id %u, reason %d", requestId, reason);
    if (TransDelConnByReqId(requestId) != SOFTBUS_OK) {
        LOG_ERR("Connect fail del reqid %u fail", requestId);
    }

    TransProxyDelChanByReqId(requestId);
}

int32_t TransProxyCloseConnChannel(uint32_t connectionId)
{
    if (TransDecConnRefByConnId(connectionId) == SOFTBUS_OK) {
        LOG_INFO("disconnect device connid %d", connectionId);
    }
    return SOFTBUS_OK;
}

int32_t TransProxyConnExistProc(ProxyConnInfo *conn, const AppInfo *appInfo, int32_t chanNewId)
{
    ProxyChannelInfo *chan = NULL;
    chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        LOG_ERR("SoftBusCalloc fail");
        return SOFTBUS_ERR;
    }

    if (conn->state == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
        chan->reqId = conn->requestId;
        chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
        if (TransProxyCreateChanInfo(chan, chanNewId, appInfo) != SOFTBUS_OK) {
            LOG_ERR("TransProxyCreateChanInfo err");
            SoftBusFree(chan);
            return SOFTBUS_ERR;
        }
    } else {
        chan->connId = conn->connId;
        chan->status = PROXY_CHANNEL_STATUS_HANDSHAKEING;
        if (TransProxyCreateChanInfo(chan, chanNewId, appInfo) != SOFTBUS_OK) {
            LOG_ERR("TransProxyCreateChanInfo err");
            SoftBusFree(chan);
            return SOFTBUS_ERR;
        }
        TransAddConnRefByConnId(conn->connId);
        TransProxyPostHandshakeMsgToLoop(chanNewId);
    }
    return SOFTBUS_OK;
}

int32_t TransProxyOpenConnChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    ConnectResult result = {0};
    ProxyConnInfo conn;
    uint32_t reqId;
    int32_t ret, chanNewId;

    reqId = ConnGetNewRequestId(MODULE_PROXY_CHANNEL);
    chanNewId = TransProxyGetNewMyId();
    if (TransGetConnByMac(connInfo->info.brOption.brMac, &conn) == SOFTBUS_OK) {
        if (TransProxyConnExistProc(&conn, appInfo, chanNewId) == SOFTBUS_ERR) {
            return SOFTBUS_ERR;
        }
        *channelId = chanNewId;
        return SOFTBUS_OK;
    }

    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        LOG_ERR("SoftBusCalloc fail");
        return SOFTBUS_ERR;
    }
    chan->reqId = reqId;
    chan->status = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    if (TransProxyCreateChanInfo(chan, chanNewId, appInfo) != SOFTBUS_OK) {
        SoftBusFree(chan);
        LOG_ERR("TransProxyCreateChanInfo err");
        return SOFTBUS_ERR;
    }

    ProxyConnInfo *connChan = (ProxyConnInfo *)SoftBusCalloc(sizeof(ProxyConnInfo));
    if (connChan == NULL) {
        TransProxyDelChanByChanId(chanNewId);
        return SOFTBUS_ERR;
    }
    connChan->requestId = reqId;
    connChan->state = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    *channelId = chanNewId;

    LOG_INFO("Connect dev reqid %d", reqId);
    (void)memcpy_s(&(connChan->connInfo), sizeof(ConnectOption), connInfo, sizeof(ConnectOption));
    if (TransAddConnItem(connChan) != SOFTBUS_OK) {
        LOG_INFO("conn add repeat");
        SoftBusFree(connChan);
        return SOFTBUS_OK;
    }
    result.OnConnectFailed = TransOnConnectFailed;
    result.OnConnectSuccessed = TransOnConnectSuccessed;
    ret = ConnConnectDevice(connInfo, reqId, &result);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("connect device err");
        TransDelConnByReqId(reqId);
        TransProxyDelChanByChanId(chanNewId);
        return ret;
    }
    return ret;
}

static void TransProxyOnDataReceived(uint32_t connectionId, ConnModule moduleId,
                                     int64_t seq, char *data, int32_t len)
{
    ProxyMessage msg;

    LOG_INFO("data recv connid :%u, moduleId %d, seq : %lld len %d", connectionId, moduleId, seq, len);
    if (data == NULL) {
        LOG_ERR("invalid param");
        return;
    }
    if (moduleId != MODULE_PROXY_CHANNEL) {
        return;
    }
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    msg.connId = connectionId;
    if (TransProxyParseMessage(data, len, &msg) != SOFTBUS_OK) {
        LOG_ERR("parse proxy msg err");
        return;
    }
    TransProxyonMessageReceived(&msg);
}

int32_t TransProxyTransInit(void)
{
    ConnectCallback proxyCallback = {0};

    proxyCallback.OnConnected = TransProxyOnConnected;
    proxyCallback.OnDisconnected = TransProxyOnDisConnect;
    proxyCallback.OnDataReceived = TransProxyOnDataReceived;
    if (ConnSetConnectCallback(MODULE_PROXY_CHANNEL, &proxyCallback) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    g_proxyConnectionList = CreateSoftBusList();
    if (g_proxyConnectionList == NULL) {
        LOG_ERR("create observer list failed");
        return SOFTBUS_ERR;
    }
    if (TransProxyLoopInit() != SOFTBUS_OK) {
        LOG_ERR("create loopInit fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

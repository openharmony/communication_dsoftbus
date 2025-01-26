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

#include "softbus_proxychannel_transceiver.h"

#include <securec.h>

#include "auth_device_common_key.h"
#include "lnn_device_info_recovery.h"
#include "message_handler.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_control.h"
#include "softbus_proxychannel_listener.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_proxychannel_message.h"
#include "softbus_proxychannel_pipeline.h"
#include "softbus_utils.h"
#include "trans_auth_negotiation.h"
#include "trans_channel_common.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_log.h"

#define ID_OFFSET (1)

static SoftBusList *g_proxyConnectionList = NULL;
const char *g_transProxyLoopName = "transProxyLoopName";
SoftBusHandler g_transLoopHandler = { 0 };

typedef enum {
    LOOP_HANDSHAKE_MSG,
    LOOP_DISCONNECT_MSG,
    LOOP_OPENFAIL_MSG,
    LOOP_OPENCLOSE_MSG,
    LOOP_KEEPALIVE_MSG,
    LOOP_RESETPEER_MSG,
    LOOP_AUTHSTATECHECK_MSG,
} LoopMsg;

int32_t TransDelConnByReqId(uint32_t requestId)
{
    ProxyConnInfo *removeNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_proxyConnectionList is null!");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (removeNode->requestId == requestId && removeNode->state == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            ListDelete(&(removeNode->node));
            TRANS_LOGI(TRANS_CTRL, "delete requestId=%{public}u", removeNode->requestId);
            SoftBusFree(removeNode);
            g_proxyConnectionList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    return SOFTBUS_OK;
}

void TransDelConnByConnId(uint32_t connId)
{
    ProxyConnInfo *removeNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if ((g_proxyConnectionList == NULL) || (connId == 0)) {
        TRANS_LOGE(TRANS_CTRL, "g_proxyConnectionList or connId is null");
        return;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (removeNode->connId == connId) {
            ListDelete(&(removeNode->node));
            SoftBusFree(removeNode);
            TRANS_LOGI(TRANS_CTRL, "del conn item. connId=%{public}d", connId);
            g_proxyConnectionList->cnt--;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    return;
}

int32_t TransDecConnRefByConnId(uint32_t connId, bool isServer)
{
    ProxyConnInfo *removeNode = NULL;
    ProxyConnInfo *tmpNode = NULL;

    if ((g_proxyConnectionList == NULL) || (connId == 0)) {
        TRANS_LOGE(TRANS_MSG, "g_proxyConnectionList or connId is null");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (removeNode->connId == connId && removeNode->isServerSide == isServer) {
            removeNode->ref--;
            if (removeNode->ref <= 0) {
                ListDelete(&(removeNode->node));
                SoftBusFree(removeNode);
                g_proxyConnectionList->cnt--;
                (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
                TRANS_LOGI(TRANS_CTRL, "conn ref is 0. connId=%{public}u", connId);
                return SOFTBUS_OK;
            } else {
                TRANS_LOGI(TRANS_CTRL, "connId=%{public}u, proxyConnRef=%{public}d", connId, removeNode->ref);
                (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
                return SOFTBUS_TRANS_NOT_MATCH;
            }
        }
    }

    TRANS_LOGW(TRANS_CTRL, "not find item. connId=%{public}u", connId);
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    return SOFTBUS_OK;
}

int32_t TransAddConnRefByConnId(uint32_t connId, bool isServer)
{
    ProxyConnInfo *item = NULL;

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_MSG, "g_proxyConnectionList is null");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->connId == connId && item->isServerSide == isServer) {
            item->ref++;
            TRANS_LOGI(TRANS_CTRL, "add connId=%{public}u, proxyConnRef=%{public}d.", connId, item->ref);
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    return SOFTBUS_TRANS_PROXY_CONN_ADD_REF_FAILED;
}

static void TransProxyLoopMsgHandler(SoftBusMessage *msg)
{
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_MSG, "param invalid");
    TRANS_LOGD(TRANS_CTRL, "trans loop process msgType=%{public}d", msg->what);
    int32_t channelId;
    ProxyChannelInfo *chan = NULL;
    switch (msg->what) {
        case LOOP_HANDSHAKE_MSG:
            channelId = *((int32_t *)msg->obj);
            TransProxyOpenProxyChannelSuccess(channelId);
            break;
        case LOOP_DISCONNECT_MSG: {
            bool isServer = (bool)msg->arg1;
            uint32_t connectionId = (uint32_t)msg->arg2;
            chan = (ProxyChannelInfo *)msg->obj;
            TRANS_CHECK_AND_RETURN_LOGE(chan != NULL, TRANS_MSG, "LOOP_DISCONNECT_MSG, chan is null");
            TransProxyCloseConnChannelReset(connectionId, (isServer == 0), isServer, chan->deviceTypeIsWinpc);
            break;
        }
        case LOOP_OPENFAIL_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            TRANS_CHECK_AND_RETURN_LOGE(chan != NULL, TRANS_MSG, "LOOP_OPENFAIL_MSG, chan is null");
            TransProxyOpenProxyChannelFail(chan->channelId, &(chan->appInfo), (int32_t)msg->arg1);
            break;
        case LOOP_OPENCLOSE_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            TRANS_CHECK_AND_RETURN_LOGE(chan != NULL, TRANS_MSG, "LOOP_OPENCLOSE_MSG, chan is null");
            OnProxyChannelClosed(chan->channelId, &(chan->appInfo));
            break;
        case LOOP_KEEPALIVE_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            TRANS_CHECK_AND_RETURN_LOGE(chan != NULL, TRANS_MSG, "LOOP_KEEPALIVE_MSG, chan is null");
            TransProxyKeepalive(chan->connId, chan);
            break;
        case LOOP_RESETPEER_MSG:
            chan = (ProxyChannelInfo *)msg->obj;
            TRANS_CHECK_AND_RETURN_LOGE(chan != NULL, TRANS_MSG, "LOOP_RESETPEER_MSG, chan is null");
            TransProxyResetPeer(chan);
            break;
        case LOOP_AUTHSTATECHECK_MSG: {
            uint32_t authRequestId = (uint32_t)msg->arg1;
            channelId = (int32_t)msg->arg2;
            TransAuthNegoTaskManager(authRequestId, channelId);
            break;
        }
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
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg calloc failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_transLoopHandler;
    msg->FreeMessage = TransProxyFreeLoopMsg;
    msg->obj = (void *)data;
    return msg;
}

void TransProxyPostAuthNegoMsgToLooperDelay(uint32_t authRequestId, int32_t channelId, uint32_t delayTime)
{
    SoftBusMessage *msg  = TransProxyCreateLoopMsg(LOOP_AUTHSTATECHECK_MSG, authRequestId, channelId, NULL);
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_MSG, "msg create failed");

    g_transLoopHandler.looper->PostMessageDelay(g_transLoopHandler.looper, msg, delayTime);
}

void TransProxyPostResetPeerMsgToLoop(const ProxyChannelInfo *chan)
{
    SoftBusMessage *msg  = TransProxyCreateLoopMsg(LOOP_RESETPEER_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg create failed");
        if (chan != NULL) {
            (void)memset_s(
                (void *)chan->appInfo.sessionKey,
                sizeof(chan->appInfo.sessionKey), 0, sizeof(chan->appInfo.sessionKey));
            SoftBusFree((void *)chan);
        }
        return;
    }
    g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
}

void TransProxyPostHandshakeMsgToLoop(int32_t channelId)
{
    int32_t *chanIdMsg = (int32_t *)SoftBusCalloc(sizeof(int32_t));
    if (chanIdMsg == NULL) {
        TRANS_LOGE(TRANS_MSG, "chanIdMsg calloc failed");
        return;
    }
    *chanIdMsg = channelId;
    SoftBusMessage *msg  = TransProxyCreateLoopMsg(LOOP_HANDSHAKE_MSG, 0, 0, (char *)chanIdMsg);
    if (msg == NULL) {
        SoftBusFree((void *)chanIdMsg);
        return;
    }
    g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
}

void TransProxyPostDisConnectMsgToLoop(uint32_t connId, bool isServer, const ProxyChannelInfo *chan)
{
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_DISCONNECT_MSG, isServer, connId, (char *)chan);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg create failed");
        SoftBusFree((void *)chan);
        return;
    }
    g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
}

void TransProxyPostKeepAliveMsgToLoop(const ProxyChannelInfo *chan)
{
    if (chan == NULL) {
        TRANS_LOGE(TRANS_MSG, "param invalid");
        return;
    }
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_KEEPALIVE_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg create failed");
        if (chan != NULL) {
            SoftBusFree((void *)chan);
        }
        return;
    }
    g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
}

void TransProxyPostOpenFailMsgToLoop(const ProxyChannelInfo *chan, int32_t errCode)
{
    if (chan == NULL) {
        TRANS_LOGE(TRANS_MSG, "param invalid");
        return;
    }
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_OPENFAIL_MSG, errCode, 0, (char *)chan);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg create failed");
        if (chan != NULL) {
            SoftBusFree((void *)chan);
        }
        return;
    }
    g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
}

void TransProxyPostOpenClosedMsgToLoop(const ProxyChannelInfo *chan)
{
    if (chan == NULL) {
        TRANS_LOGE(TRANS_MSG, "param invalid");
        return;
    }
    SoftBusMessage *msg = TransProxyCreateLoopMsg(LOOP_OPENCLOSE_MSG, 0, 0, (char *)chan);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_MSG, "msg create failed");
        if (chan != NULL) {
            SoftBusFree((void *)chan);
        }
        return;
    }
    g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
}

static int32_t TransProxyLoopInit(void)
{
    g_transLoopHandler.name = (char *)g_transProxyLoopName;
    g_transLoopHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_transLoopHandler.looper == NULL) {
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    g_transLoopHandler.HandleMessage = TransProxyLoopMsgHandler;
    return SOFTBUS_OK;
}

int32_t TransProxyTransSendMsg(uint32_t connectionId, uint8_t *buf, uint32_t len, int32_t priority, int32_t pid)
{
    ConnPostData data = { 0 };
    static uint64_t seq = 1;

    data.module = MODULE_PROXY_CHANNEL;
    data.seq = seq++;
    data.flag = priority;
    data.pid = pid;
    data.len = len;
    data.buf = (char *)buf;
    TRANS_LOGI(TRANS_MSG,
        "send msg connId=%{public}u, len=%{public}u, seq=%{public}" PRIu64 ", priority=%{public}d, pid=%{public}d",
        connectionId, len, data.seq, priority, pid);
    int32_t ret = ConnPostBytes(connectionId, &data);
    if (ret < 0) {
        TRANS_LOGE(TRANS_MSG, "conn send buf fail ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void TransProxyOnConnected(uint32_t connId, const ConnectionInfo *connInfo)
{
    (void)connInfo;
    TRANS_LOGI(TRANS_CTRL, "connect enabled, connId=%{public}u", connId);
}

static void TransProxyOnDisConnect(uint32_t connId, const ConnectionInfo *connInfo)
{
    (void)connInfo;
    TRANS_LOGI(TRANS_CTRL, "connect disabled, connId=%{public}u", connId);
    TransProxyDelByConnId(connId);
    TransDelConnByConnId(connId);
}

static bool CompareConnectOption(const ConnectOption *itemConnInfo, const ConnectOption *connInfo)
{
    if (connInfo->type == CONNECT_TCP) {
        TRANS_LOGI(TRANS_CTRL, "CONNECT_TCP");
        if (connInfo->socketOption.protocol == itemConnInfo->socketOption.protocol &&
            strcasecmp(connInfo->socketOption.addr, itemConnInfo->socketOption.addr) == 0 &&
            connInfo->socketOption.port == itemConnInfo->socketOption.port) {
            return true;
        }
        return false;
    } else if (connInfo->type == CONNECT_BR) {
        TRANS_LOGI(TRANS_CTRL, "CONNECT_BR");
        if (strcasecmp(connInfo->brOption.brMac, itemConnInfo->brOption.brMac) == 0) {
            return true;
        }
        return false;
    } else if (connInfo->type == CONNECT_BLE) {
        TRANS_LOGI(TRANS_CTRL, "CONNECT_BLE");
        if (strcasecmp(connInfo->bleOption.bleMac, itemConnInfo->bleOption.bleMac) == 0 &&
            (connInfo->bleOption.protocol == itemConnInfo->bleOption.protocol) &&
            connInfo->bleOption.psm == itemConnInfo->bleOption.psm) {
            return true;
        }
        return false;
    } else if (connInfo->type == CONNECT_BLE_DIRECT) {
        TRANS_LOGI(TRANS_CTRL, "CONNECT_BLE_DIRECT");
        if ((strcmp(connInfo->bleDirectOption.networkId, itemConnInfo->bleDirectOption.networkId) == 0) &&
            (connInfo->bleDirectOption.protoType == itemConnInfo->bleDirectOption.protoType)) {
            return true;
        }
        return false;
    }
    return false;
}

int32_t TransAddConnItem(ProxyConnInfo *chan)
{
    if (chan == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyConnInfo *item = NULL;
    ProxyConnInfo *tmpItem = NULL;

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_proxyConnectionList is null");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, tmpItem, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->isServerSide == chan->isServerSide &&
            CompareConnectOption(&item->connInfo, &chan->connInfo) == true) {
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_TRANS_NOT_MATCH;
        }
    }
    ListAdd(&(g_proxyConnectionList->list), &(chan->node));
    TRANS_LOGI(TRANS_CTRL, "add requestId=%{public}u", chan->requestId);
    g_proxyConnectionList->cnt++;
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    return SOFTBUS_OK;
}

static void TransConnInfoToConnOpt(ConnectionInfo *connInfo, ConnectOption *connOption)
{
    connOption->type = connInfo->type;
    if (connOption->type == CONNECT_BR) {
        TRANS_LOGI(TRANS_CTRL, "CONNECT_BR");
        (void)memcpy_s(connOption->brOption.brMac, sizeof(char) * BT_MAC_LEN,
            connInfo->brInfo.brMac, sizeof(char) * BT_MAC_LEN);
    } else if (connOption->type == CONNECT_BLE) {
        TRANS_LOGI(TRANS_CTRL, "CONNECT_BLE");
        (void)memcpy_s(connOption->bleOption.bleMac, sizeof(char) * BT_MAC_LEN,
            connInfo->bleInfo.bleMac, sizeof(char) * BT_MAC_LEN);
        (void)memcpy_s(connOption->bleOption.deviceIdHash, sizeof(char) * UDID_HASH_LEN,
            connInfo->bleInfo.deviceIdHash, sizeof(char) * UDID_HASH_LEN);
    } else {
        (void)memcpy_s(connOption->socketOption.addr, sizeof(char) * IP_LEN,
            connInfo->socketInfo.addr, sizeof(char) * IP_LEN);
        connOption->socketOption.protocol = connInfo->socketInfo.protocol;
        connOption->socketOption.port = connInfo->socketInfo.port;
        connOption->socketOption.moduleId = connInfo->socketInfo.moduleId;
    }
}

void TransCreateConnByConnId(uint32_t connId, bool isServer)
{
    ProxyConnInfo *item = NULL;
    ProxyConnInfo *tmpNode = NULL;
    ConnectionInfo info = {0};

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "g_proxyConnectionList is null");
        return;
    }

    if (ConnGetConnectionInfo(connId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "CreateConn get conn info fail connId=%{public}u", connId);
        return;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, tmpNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->connId == connId && item->isServerSide == isServer) {
            item->ref++;
            TRANS_LOGI(TRANS_CTRL, "repeat conn proxyConnRef=%{public}d", item->ref);
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return;
        }
    }

    item = (ProxyConnInfo *)SoftBusCalloc(sizeof(ProxyConnInfo));
    if (item == NULL) {
        TRANS_LOGE(TRANS_CTRL, "item calloc failed");
        (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
        return;
    }
    item->ref++;
    item->state = PROXY_CHANNEL_STATUS_PYH_CONNECTED;
    TRANS_LOGI(TRANS_CTRL, "create conn proxyConnRef=%{public}d", item->ref);
    item->connId = connId;
    item->isServerSide = isServer;
    TransConnInfoToConnOpt(&info, &item->connInfo);
    ListAdd(&(g_proxyConnectionList->list), &(item->node));
    TRANS_LOGI(TRANS_CTRL, "add connId=%{public}u", item->connId);
    g_proxyConnectionList->cnt++;
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    return;
}

static int32_t TransGetConn(const ConnectOption *connInfo, ProxyConnInfo *proxyConn, bool isServer)
{
    ProxyConnInfo *item = NULL;

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "proxy connection list not inited!");
        return SOFTBUS_NO_INIT;
    }

    if (connInfo == NULL || proxyConn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid para in trans get conn.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->connInfo.type != connInfo->type || item->isServerSide != isServer) {
            continue;
        }
        if (CompareConnectOption(&item->connInfo, connInfo)) {
            (void)memcpy_s(proxyConn, sizeof(ProxyConnInfo), item, sizeof(ProxyConnInfo));
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    TRANS_LOGE(TRANS_CTRL, "can not find proxy conn in list.");
    return SOFTBUS_TRANS_NOT_MATCH;
}

static int32_t TransSetConnStateByReqId(uint32_t requestId, uint32_t connId, uint32_t state)
{
    ProxyConnInfo *getNode = NULL;

    if (g_proxyConnectionList == NULL) {
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail!");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(getNode, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (getNode->requestId == requestId && getNode->state == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
            getNode->state = state;
            getNode->connId = connId;
            getNode->requestId = 0;
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    TRANS_LOGE(TRANS_CTRL,
        "can not find proxy conn when set conn state. requestId=%{public}u, connId=%{public}u", requestId, connId);
    (void)ConnDisconnectDevice(connId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

static void TransOnConnectSucceed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *connInfo)
{
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .requestId = (int32_t)requestId,
        .connectionId = (int32_t)connectionId,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    TRANS_LOGI(TRANS_CTRL,
        "Connect Success requestId=%{public}u, connId=%{public}u", requestId, connectionId);
    int32_t ret = TransSetConnStateByReqId(requestId, connectionId, PROXY_CHANNEL_STATUS_PYH_CONNECTED);
    TransProxyChanProcessByReqId((int32_t)requestId, connectionId, ret);
}

static void TransOnConnectFailed(uint32_t requestId, int32_t reason)
{
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .requestId = requestId,
        .errcode = reason,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    TRANS_LOGE(TRANS_CTRL, "Connect fail requestId=%{public}u, reason=%{public}d", requestId, reason);
    if (TransDelConnByReqId(requestId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Connect fail del fail. requestId=%{public}u", requestId);
    }
    TransProxyDelChanByReqId((int32_t)requestId, reason);
}

int32_t TransProxyCloseConnChannel(uint32_t connectionId, bool isServer)
{
    if (TransDecConnRefByConnId(connectionId, isServer) == SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "disconnect device connId=%{public}d", connectionId);
        // BR don't disconnect
        (void)ConnDisconnectDevice(connectionId);
    }
    return SOFTBUS_OK;
}

int32_t TransProxyCloseConnChannelReset(uint32_t connectionId, bool isDisconnect, bool isServer, bool deviceType)
{
    if (TransDecConnRefByConnId(connectionId, isServer) == SOFTBUS_OK) {
        TRANS_LOGI(TRANS_CTRL, "reset dis device. isDisconnect=%{public}d, connId=%{public}u, deviceType=%{public}d",
            isDisconnect, connectionId, deviceType);
        // only client side can disconnect connection
        if (isDisconnect && deviceType != true) {
            (void)ConnDisconnectDevice(connectionId);
        }
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyConnExistProc(bool isServer, int32_t chanNewId, const ConnectOption *connInfo)
{
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(chanNewId + ID_OFFSET));
    TRANS_LOGI(TRANS_CTRL,
        "SoftBusHiTraceChainBegin: set hiTraceId=%{public}" PRIu64, (uint64_t)(chanNewId + ID_OFFSET));
    int32_t ret = GetProxyChannelLock();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "lock mutex fail!");
    ProxyConnInfo conn;
    if (TransGetConn(connInfo, &conn, false) != SOFTBUS_OK) {
        ReleaseProxyChannelLock();
        TRANS_LOGE(TRANS_CTRL, "get connectInfo failed, channelId=%{public}d", chanNewId);
        return SOFTBUS_TRANS_PROXY_CONN_ADD_REF_FAILED;
    }
    ConnectType type = conn.connInfo.type;
    if (conn.state == PROXY_CHANNEL_STATUS_PYH_CONNECTING) {
        ProxyChannelInfo channelInfo = {
            .channelId = chanNewId,
            .reqId = (int32_t)conn.requestId,
            .isServer = -1,
            .type = type,
            .status = PROXY_CHANNEL_STATUS_PYH_CONNECTING,
            .connId = 0
        };

        TransProxySpecialUpdateChanInfo(&channelInfo);
        ReleaseProxyChannelLock();
        TRANS_LOGI(TRANS_CTRL, "reuse connection requestId=%{public}d", channelInfo.reqId);
    } else {
        ReleaseProxyChannelLock();
        ProxyChannelInfo channelInfo = {
            .channelId = chanNewId,
            .reqId = -1,
            .isServer = -1,
            .type = type,
            .status = PROXY_CHANNEL_STATUS_HANDSHAKEING,
            .connId = conn.connId
        };
        if (TransAddConnRefByConnId(conn.connId, isServer) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "TransAddConnRefByConnId: connId=%{public}u err", conn.connId);
            return SOFTBUS_TRANS_PROXY_CONN_ADD_REF_FAILED;
        }
        TransProxySpecialUpdateChanInfo(&channelInfo);
        TransProxyPostHandshakeMsgToLoop(chanNewId);
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyConnectDevice(const ConnectOption *connInfo, uint32_t requestId)
{
    ConnectResult result;
    result.OnConnectFailed = TransOnConnectFailed;
    result.OnConnectSuccessed = TransOnConnectSucceed;
    if (connInfo->type == CONNECT_BLE_DIRECT) {
        return ConnBleDirectConnectDevice(connInfo, requestId, &result);
    } else {
        return ConnConnectDevice(connInfo, requestId, &result);
    }
}

static int32_t TransProxyOpenNewConnChannel(ListenerModule moduleId, const ConnectOption *connInfo, int32_t channelId)
{
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(channelId + ID_OFFSET));
    TRANS_LOGI(TRANS_CTRL,
        "SoftBusHiTraceChainBegin: set hiTraceId=%{public}" PRIu64, (uint64_t)(channelId + ID_OFFSET));
    uint32_t requestId = ConnGetNewRequestId(MODULE_PROXY_CHANNEL);
    ProxyChannelInfo channelInfo = {
        .channelId = channelId,
        .reqId = (int32_t)requestId,
        .isServer = 0,
        .type = CONNECT_TYPE_MAX,
        .status = PROXY_CHANNEL_STATUS_PYH_CONNECTING,
        .connId = 0
    };
    TransProxySpecialUpdateChanInfo(&channelInfo);

    ProxyConnInfo *connChan = (ProxyConnInfo *)SoftBusCalloc(sizeof(ProxyConnInfo));
    if (connChan == NULL) {
        TRANS_LOGE(TRANS_CTRL, "connChan calloc failed");
        TransProxyDelChanByChanId(channelId);
        return SOFTBUS_MALLOC_ERR;
    }
    connChan->requestId = requestId;
    connChan->state = PROXY_CHANNEL_STATUS_PYH_CONNECTING;
    connChan->ref = 0;
    connChan->isServerSide = false;

    TRANS_LOGI(TRANS_CTRL, "Connect dev, channelId=%{public}d, requestId=%{public}u", channelId, requestId);
    connChan->connInfo = (*connInfo);
    if (connInfo->type == CONNECT_TCP) {
        connChan->connInfo.socketOption.moduleId = moduleId;
    }
    if (TransAddConnItem(connChan) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "conn add repeat");
        SoftBusFree(connChan);
        return SOFTBUS_TRANS_PROXY_CONN_REPEAT;
    }
    int32_t ret = TransProxyConnectDevice(&connChan->connInfo, requestId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "connect device err");
        TransDelConnByReqId(requestId);
        TransProxyDelChanByChanId(channelId);
    }
    return ret;
}

static void TransReportStartConnectEvent(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t channelId)
{
    ProxyChannelInfo *channelInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_LOGE(channelInfo != NULL, TRANS_CTRL, "malloc proxyChannelInfo failed");
    if (TransProxyGetChanByChanId(channelId, channelInfo) != SOFTBUS_OK) {
        SoftBusFree(channelInfo);
        TRANS_LOGE(TRANS_CTRL, "TransProxyGetChanByChanId failed, channelId=%{public}d", channelId);
        return;
    }
    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = appInfo->myData.sessionName,
        .channelType = appInfo->appType == APP_TYPE_AUTH ? CHANNEL_TYPE_AUTH : CHANNEL_TYPE_PROXY,
        .channelId = channelId,
        .requestId = channelInfo->reqId,
        .linkType = connInfo->type
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    SoftBusFree(channelInfo);
}

int32_t TransProxyOpenConnChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    if (appInfo == NULL || connInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    ProxyConnInfo conn;
    int32_t chanNewId = INVALID_CHANNEL_ID;
    if (*channelId != INVALID_CHANNEL_ID) {
        chanNewId = *channelId;
    } else {
        chanNewId = GenerateChannelId(false);
    }
    if (chanNewId <= INVALID_CHANNEL_ID) {
        TRANS_LOGE(TRANS_CTRL, "proxy channelId is invalid");
        return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
    }
    ProxyChannelInfo *chan = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    if (chan == NULL) {
        ReleaseProxyChannelId(chanNewId);
        TRANS_LOGE(TRANS_CTRL, "SoftBusCalloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    chan->type = connInfo->type;
    if (TransProxyCreateChanInfo(chan, chanNewId, appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransProxyCreateChanInfo err");
        ReleaseProxyChannelId(chanNewId);
        (void)memset_s(chan->appInfo.sessionKey, sizeof(chan->appInfo.sessionKey), 0, sizeof(chan->appInfo.sessionKey));
        SoftBusFree(chan);
        return SOFTBUS_TRANS_PROXY_CREATE_CHANNEL_FAILED;
    }
    if (TransGetConn(connInfo, &conn, false) == SOFTBUS_OK) {
        ret = TransProxyConnExistProc(false, chanNewId, connInfo);
        if (ret == SOFTBUS_TRANS_PROXY_CONN_ADD_REF_FAILED) {
            ret = TransProxyOpenNewConnChannel(PROXY, connInfo, chanNewId);
        }
    } else {
        ret = TransProxyOpenNewConnChannel(PROXY, connInfo, chanNewId);
        if ((ret == SOFTBUS_TRANS_PROXY_CONN_REPEAT) && (TransGetConn(connInfo, &conn, false) == SOFTBUS_OK)) {
            ret = TransProxyConnExistProc(false, chanNewId, connInfo);
        }
    }
    if (ret == SOFTBUS_OK) {
        *channelId = chanNewId;
    } else if (ret == SOFTBUS_TRANS_PROXY_CONN_ADD_REF_FAILED || ret == SOFTBUS_TRANS_PROXY_CONN_REPEAT) {
        TransProxyDelChanByChanId(chanNewId);
    }
    TransReportStartConnectEvent(appInfo, connInfo, chanNewId);
    return ret;
}

static int32_t TransProxySendBadKeyMessage(ProxyMessage *msg, const AuthHandle *authHandle)
{
    ProxyDataInfo dataInfo;
    dataInfo.inData = (uint8_t *)msg->data;
    dataInfo.inLen = (uint32_t)msg->dateLen;
    dataInfo.outData = NULL;
    dataInfo.outLen = 0;

    msg->msgHead.type = (PROXYCHANNEL_MSG_TYPE_RESET & FOUR_BIT_MASK) | (VERSION << VERSION_SHIFT);
    if (AuthCheckSessionKeyValidByAuthHandle(authHandle) == SOFTBUS_AUTH_SESSION_KEY_INVALID) {
        TRANS_LOGE(TRANS_MSG, "ble single online, send renegotiate msg");
        msg->msgHead.cipher |= AUTH_SINGLE_CIPHER;
    } else {
        msg->msgHead.cipher |= BAD_CIPHER;
    }
    TRANS_LOGW(TRANS_MSG, "send msg is bad key myChannelId=%{public}d, peerChannelId=%{public}d",
        msg->msgHead.myId, msg->msgHead.peerId);

    int32_t ret = PackPlaintextMessage(&msg->msgHead, &dataInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_MSG, "PackPlaintextMessage fail");

    ret = TransProxyTransSendMsg(msg->connId, dataInfo.outData, dataInfo.outLen, CONN_HIGH, 0);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_MSG, "send bad key buf fail");

    return SOFTBUS_OK;
}

static void TransProxyOnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    TRANS_LOGI(TRANS_CTRL, "recv data connId=%{public}u, moduleId=%{public}d, seq=%{public}" PRId64 ", len=%{public}d",
        connectionId, moduleId, seq, len);
    TRANS_CHECK_AND_RETURN_LOGE(data != NULL && moduleId == MODULE_PROXY_CHANNEL, TRANS_CTRL, "invalid param");

    ProxyMessage msg;
    (void)memset_s(&msg, sizeof(ProxyMessage), 0, sizeof(ProxyMessage));
    msg.connId = connectionId;

    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    int32_t ret = TransProxyParseMessage((char *)data, len, &msg, &authHandle);
    if (((ret == SOFTBUS_AUTH_NOT_FOUND) || (ret == SOFTBUS_DECRYPT_ERR)) &&
        (msg.msgHead.type == PROXYCHANNEL_MSG_TYPE_HANDSHAKE)) {
        TransReportBadKeyEvent(ret, connectionId, seq, len);
        if (TransProxySendBadKeyMessage(&msg, &authHandle) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send bad key msg ret=%{public}d", ret);
            return;
        }
        char peerBrMac[BT_MAC_LEN] = {0};
        char udid[UDID_BUF_LEN] = {0};
        if (GetBrMacFromConnInfo(connectionId, peerBrMac, BT_MAC_LEN) == SOFTBUS_OK) {
            if (LnnGetUdidByBrMac(peerBrMac, udid, UDID_BUF_LEN) == SOFTBUS_OK) {
                AuthRemoveDeviceKeyByUdid(udid);
            }
        }
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "parse proxy msg ret=%{public}d", ret);
        return;
    }
    TransProxyOnMessageReceived(&msg);
    SoftBusFree(msg.data);
}

int32_t TransProxyTransInit(void)
{
    ConnectCallback proxyCallback = { 0 };

    proxyCallback.OnConnected = TransProxyOnConnected;
    proxyCallback.OnDisconnected = TransProxyOnDisConnect;
    proxyCallback.OnDataReceived = TransProxyOnDataReceived;
    int32_t ret = ConnSetConnectCallback(MODULE_PROXY_CHANNEL, &proxyCallback);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "ConnSetConnectCallback fail");

    g_proxyConnectionList = CreateSoftBusList();
    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_INIT, "create observer list failed");
        return SOFTBUS_MALLOC_ERR;
    }

    ret = TransProxyLoopInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "create loopInit fail");

    ret = TransProxyPipelineInit();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "init proxy pipeline failed");

    return SOFTBUS_OK;
}

int32_t TransProxyGetConnInfoByConnId(uint32_t connId, ConnectOption *connInfo)
{
    if (connInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "proxy connect list empty.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail.");
        return SOFTBUS_LOCK_ERR;
    }

    ProxyConnInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (item->connId == connId) {
            if (memcpy_s(connInfo, sizeof(ConnectOption), &(item->connInfo), sizeof(ConnectOption)) != EOK) {
                TRANS_LOGE(TRANS_CTRL, "memcpy_s connInfo failed. connId=%{public}u", connId);
                (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    TRANS_LOGE(TRANS_INIT, "proxy conn node not found. connId=%{public}u", connId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t CheckIsProxyAuthChannel(ConnectOption *connInfo)
{
    if (connInfo == NULL) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_proxyConnectionList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "proxy connect list empty.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftBusMutexLock(&g_proxyConnectionList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock mutex fail.");
        return SOFTBUS_LOCK_ERR;
    }

    ProxyConnInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_proxyConnectionList->list, ProxyConnInfo, node) {
        if (memcmp(item->connInfo.bleOption.bleMac, connInfo->bleOption.bleMac,
            sizeof(connInfo->bleOption.bleMac)) == 0 ||
            memcmp(item->connInfo.bleOption.deviceIdHash, connInfo->bleOption.deviceIdHash,
            SHORT_UDID_HASH_LEN) == 0) {
            TRANS_LOGI(TRANS_CTRL, "auth channel type is ble");
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        } else if (memcmp(item->connInfo.brOption.brMac, connInfo->brOption.brMac,
            sizeof(connInfo->brOption.brMac)) == 0) {
            TRANS_LOGI(TRANS_CTRL, "auth channel type is br");
            (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_proxyConnectionList->lock);
    TRANS_LOGE(TRANS_INIT, "proxy conn node not found.");
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

static int32_t TransProxyUdpateNewPeerUdidHash(const char *deviceId, ConnectOption *connOpt)
{
    uint8_t udidHash[UDID_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash((const unsigned char *)deviceId, strlen(deviceId), udidHash);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Generate UDID HexStringHash fail, ret=%{public}d", ret);
        return ret;
    }
    if (memcpy_s(connOpt->bleOption.deviceIdHash, UDID_HASH_LEN, udidHash, UDID_HASH_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s udid hash err");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyGetConnOptionByChanId(int32_t channelId, ConnectOption *connOpt)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(connOpt != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param");
    ProxyChannelInfo chan;
    (void)memset_s(&chan, sizeof(ProxyChannelInfo), 0, sizeof(ProxyChannelInfo));
    int32_t ret = TransProxyGetProxyChannelInfoByChannelId(channelId, &chan);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get proxy channel info fail, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }

    ret = TransProxyGetConnInfoByConnId(chan.connId, connOpt);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get conn optinfo fail, channelId=%{public}d, connId=%{public}d, ret=%{public}d",
            chan.channelId, chan.connId, ret);
        return ret;
    }

    ret = TransProxyUdpateNewPeerUdidHash(chan.appInfo.peerData.deviceId, connOpt);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get new peer udid hash fail, channelId=%{public}d, connId=%{public}d, ret=%{public}d",
            chan.channelId, chan.connId, ret);
        return ret;
    }

    char udidHashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    ret = ConvertBytesToHexString(udidHashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN),
        (unsigned char *)connOpt->bleOption.deviceIdHash, SHORT_UDID_HASH_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_CTRL, "convert udid hash to string fail, channelId=%{public}d, connId=%{public}d, ret=%{public}d",
            chan.channelId, chan.connId, ret);
        return ret;
    }

    char *udidHash = NULL;
    Anonymize(udidHashStr, &udidHash);
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}d, connId=%{public}d, udidHash=%{public}s",
        chan.channelId, chan.connId, AnonymizeWrapper(udidHash));
    AnonymizeFree(udidHash);
    return SOFTBUS_OK;
}

void TransProxyNegoSessionKeyFail(int32_t channelId, int32_t errCode)
{
    ProxyChannelInfo *channelInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_LOGE(channelInfo != NULL, TRANS_CTRL, "malloc proxyChannelInfo failed");

    if (TransProxyGetChanByChanId(channelId, channelInfo) != SOFTBUS_OK) {
        SoftBusFree(channelInfo);
        TRANS_LOGE(TRANS_CTRL, "disconnect device channelId=%{public}d", channelId);
        return;
    }

    (void)TransProxyCloseConnChannel(channelInfo->connId, channelInfo->isServer);
    (void)OnProxyChannelOpenFailed(channelId, &(channelInfo->appInfo), errCode);
    (void)memset_s(channelInfo->appInfo.sessionKey, sizeof(channelInfo->appInfo.sessionKey), 0,
        sizeof(channelInfo->appInfo.sessionKey));
    SoftBusFree(channelInfo);
    TransProxyDelChanByChanId(channelId);
}

void TransProxyNegoSessionKeySucc(int32_t channelId)
{
    ProxyChannelInfo *channelInfo = (ProxyChannelInfo *)SoftBusCalloc(sizeof(ProxyChannelInfo));
    TRANS_CHECK_AND_RETURN_LOGE(channelInfo != NULL, TRANS_CTRL, "malloc proxyChannelInfo failed");

    if (TransProxyGetChanByChanId(channelId, channelInfo) != SOFTBUS_OK) {
        SoftBusFree(channelInfo);
        TRANS_LOGE(TRANS_CTRL, "disconnect device channelId=%{public}d", channelId);
        return;
    }

    channelInfo->appInfo.connectedStart = GetSoftbusRecordTimeMillis();
    int32_t ret = TransProxyHandshake(channelInfo);
    if (ret != SOFTBUS_OK) {
        TransEventExtra extra = {
            .socketName = NULL,
            .peerNetworkId = NULL,
            .calleePkg = NULL,
            .callerPkg = NULL,
            .channelId = channelId,
            .connectionId = channelInfo->connId,
            .errcode = ret,
            .result = EVENT_STAGE_RESULT_FAILED
        };
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
        (void)TransProxyCloseConnChannel(channelInfo->connId, channelInfo->isServer);
        TRANS_LOGE(TRANS_CTRL, "channelId=%{public}d handshake err, ret=%{public}d", channelId, ret);
        TransProxyOpenProxyChannelFail(channelInfo->channelId, &(channelInfo->appInfo), ret);
        TransProxyDelChanByChanId(channelId);
    }
    (void)memset_s(channelInfo->appInfo.sessionKey, sizeof(channelInfo->appInfo.sessionKey), 0,
        sizeof(channelInfo->appInfo.sessionKey));
    SoftBusFree(channelInfo);
}

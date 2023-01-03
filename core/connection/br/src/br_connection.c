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

#include <sys/prctl.h>

#include "br_connection_manager.h"
#include "br_connection_queue.h"
#include "br_pending_packet.h"
#include "br_trans_manager.h"
#include "common_list.h"
#include "message_handler.h"
#include "securec.h"
#include "softbus_hisysevt_connreporter.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_type_def.h"
#include "softbus_utils.h"
#include "stdbool.h"
#include "string.h"
#include "time.h"
#include "unistd.h"
#include "wrapper_br_interface.h"


#define DISCONN_DELAY_TIME 200
#define BR_ACCEPET_WAIT_TIME 1000
#define CONNECT_REF_INCRESE 1
#define CONNECT_REF_DECRESE (-1)
#define BR_SEND_THREAD_STACK 5120
#define BR_RECE_THREAD_STACK 4096
#define MAX_BR_SIZE (40 * 1000)
#define MAX_BR_PEER_SIZE (3*1024)
#define INVALID_LENGTH (-1)
#define INVALID_SOCKET (-1)
#define WINDOWS_ACK_FAILED_TIMES 3
#define WAIT_ACK_TIMES 100

#define BR_SERVER_NAME_LEN 24
#define UUID "8ce255c0-200a-11e0-ac64-0800200c9a66"

#define BR_CLOSE_TIMEOUT (5 * 1000)

static pthread_mutex_t g_brConnLock;
static int32_t g_brMaxConnCount;

static SoftBusHandler g_brAsyncHandler = {
    .name = (char *)"g_brAsyncHandler"
};

static int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

static int32_t DisconnectDevice(uint32_t connectionId);

static int32_t DisconnectDeviceNow(const ConnectOption *option);

static int32_t StartLocalListening(const LocalListenerInfo *info);

static int32_t StopLocalListening(const LocalListenerInfo *info);

static int32_t PostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag);

static ConnectFuncInterface g_brInterface = {
    .ConnectDevice = ConnectDevice,
    .PostBytes = PostBytes,
    .DisconnectDevice = DisconnectDevice,
    .DisconnectDeviceNow = DisconnectDeviceNow,
    .GetConnectionInfo = GetConnectionInfo,
    .StartLocalListening = StartLocalListening,
    .StopLocalListening = StopLocalListening,
    .CheckActiveConnection = BrCheckActiveConnection,
    .UpdateConnection = NULL,
};

static SppSocketDriver *g_sppDriver = NULL;
static ConnectCallback *g_connectCallback = NULL;

static int32_t g_brBuffSize;
static int32_t g_brSendPeerLen;
static int32_t g_brSendQueueMaxLen;

static SoftBusBtStateListener g_sppBrCallback;
static bool g_startListenFlag = false;
static int32_t g_brEnable = SOFTBUS_BR_STATE_TURN_OFF;

static void BrFreeMessage(SoftBusMessage *msg)
{
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
    }
    SoftBusFree((void *)msg);
}

static SoftBusMessage *BrConnCreateLoopMsg(BrConnLoopMsgType what, uint64_t arg1, uint64_t arg2, const char *data)
{
    SoftBusMessage *msg = NULL;
    msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrConnCreateLoopMsg SoftBusCalloc failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_brAsyncHandler;
    msg->FreeMessage = BrFreeMessage;
    msg->obj = (void *)data;
    return msg;
}

static void PostBytesInnerListener(uint32_t connId, uint64_t seq, int32_t module, int32_t result)
{
    if (result != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "PostInner failed, connId:%u, seq:%" PRIu64 ", module:%d, result:%d", connId, seq, module, result);
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PostInner success, connId:%u, seq:%" PRIu64 ", module:%d",
            connId, seq, module);
    }
}

static int32_t PostBytesInner(uint32_t connectionId, int32_t module, const char *data, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "PostBytesInner connectionId=%u,len=%u,module=%d", connectionId, len, module);

    // control message need be sent when closing
    int32_t state = GetBrConnStateByConnectionId(connectionId);
    if (state != BR_CONNECTION_STATE_CLOSING && state != BR_CONNECTION_STATE_CONNECTED) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "connectionId(%u) device is not ready, state: %d",
            connectionId, state);
        SoftBusFree((void *)data);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    SendBrQueueNode *node = (SendBrQueueNode *)SoftBusCalloc(sizeof(SendBrQueueNode));
    if (node == NULL) {
        SoftBusFree((void *)data);
        return SOFTBUS_MALLOC_ERR;
    }
    node->connectionId = connectionId;
    node->len = len;
    node->data = data;
    node->module = module;
    node->isInner = true;
    node->pid = 0;
    node->flag = CONN_HIGH;
    node->listener = PostBytesInnerListener;
    int32_t ret = BrEnqueueNonBlock((const void *)node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Br PostBytesInner enqueue failed, ret: %d", ret);
        SoftBusFree((void *)data);
        SoftBusFree(node);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t PostClosingTimeoutEvent(uint32_t connectionId)
{
    SoftBusMessage *msg = BrConnCreateLoopMsg(ADD_CONN_BR_CLOSING_TIMEOUT_MSG, (uint64_t)connectionId, 0, NULL);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[PostClosingTimeoutEvent] BrConnCreateLoopMsg failed, "
        "connection id: %u", connectionId);
        return SOFTBUS_ERR;
    }
    g_brAsyncHandler.looper->PostMessageDelay(g_brAsyncHandler.looper, msg, BR_CLOSE_TIMEOUT);
    return SOFTBUS_OK;
}

static void PackRequest(int32_t delta, uint32_t connectionId)
{
    int32_t refCount = -1;
    int32_t state = SetRefCountByConnId(delta, &refCount, connectionId);
    if (state != BR_CONNECTION_STATE_CONNECTED && state != BR_CONNECTION_STATE_CLOSING) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br connection %u not connected ever!", connectionId);
        return;
    }

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "br pack request: delta:%d, ref:%d, connectionId:%u, state:%d", delta, refCount, connectionId, state);

    if (state == BR_CONNECTION_STATE_CLOSING) {
        int32_t ret = PostClosingTimeoutEvent(connectionId);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "post close %u connection timeout event, ret: %d",
            connectionId, ret);
        // continue, anyway
    }

    int32_t dataLen = 0;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_REQUEST, delta, refCount, &dataLen);
    if (buf != NULL) {
        (void)PostBytesInner(connectionId, METHOD_NOTIFY_REQUEST, buf, dataLen);
    }
}

static void DeviceConnectPackRequest(int32_t value, uint32_t connectionId)
{
    int32_t data = value;
    while (--data > 0) {
        (void)PackRequest(CONNECT_REF_INCRESE, connectionId);
    }
}

static int32_t ClientOnBrConnectDevice(int32_t connId, int32_t *outSocketFd)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "sppDriver connect start, connId:%d", connId);
    BrConnectionInfo *brConn = GetConnectionRef(connId);
    if (brConn == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BrClient not find connInfo.");
        return SOFTBUS_BRCONNECTION_GETCONNINFO_ERROR;
    }
    if (brConn->sideType != BR_CLIENT_TYPE) {
        ReleaseConnectionRef(brConn);
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t btAddr[BT_ADDR_LEN];
    if (ConvertBtMacToBinary(brConn->mac, BT_MAC_LEN, btAddr, BT_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "convert bt mac to binary fail.");
        ReleaseConnectionRef(brConn);
        return SOFTBUS_ERR;
    }
    int32_t socketFd = SOFTBUS_ERR;
    if (g_sppDriver != NULL) {
        socketFd = g_sppDriver->Connect(UUID, btAddr);
    }
    if (socketFd == SOFTBUS_ERR) {
        ReleaseConnectionRef(brConn);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sppDriver connect failed, connId:%d", connId);
        return SOFTBUS_BRCONNECTION_CONNECTDEVICE_GETSOCKETIDFAIL;
    }
    brConn->socketFd = socketFd;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br connection ok, Id=%d, socket=%d", connId, socketFd);
    if (g_sppDriver->IsConnected(socketFd)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "sppDriver IsConnected true.");
    }
    if (brConn->state == BR_CONNECTION_STATE_CLOSED || brConn->state == BR_CONNECTION_STATE_CLOSING) {
        g_sppDriver->DisConnect(socketFd);
        ReleaseConnectionRef(brConn);
        return SOFTBUS_ERR;
    }
    brConn->state = BR_CONNECTION_STATE_CONNECTED;
    *outSocketFd = socketFd;
    ReleaseConnectionRef(brConn);
    return SOFTBUS_OK;
}

static void ClientNoticeResultBrConnect(uint32_t connId, bool result, int32_t value)
{
    ListNode notifyList;
    ListInit(&notifyList);
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    RequestInfo *requestInfo = NULL;
    ConnectionInfo connectionInfo;
    if (!result) {
        SetBrConnStateByConnId(connId, BR_CONNECTION_STATE_CLOSING);
    }
    int32_t sideType = BR_CLIENT_TYPE;
    int32_t packRequestFlag = GetBrRequestListByConnId(connId, &notifyList, &connectionInfo, &sideType);
    if (packRequestFlag != 0) {
        if (result) {
            connectionInfo.isAvailable = 1;
            DeviceConnectPackRequest(packRequestFlag, connId);
        }
        LIST_FOR_EACH_SAFE(item, itemNext, &notifyList) {
            requestInfo = LIST_ENTRY(item, RequestInfo, node);
            if (result) {
                if (requestInfo->callback.OnConnectSuccessed != NULL) {
                    requestInfo->callback.OnConnectSuccessed(requestInfo->requestId, connId, &connectionInfo);
                }
            } else {
                if (requestInfo->callback.OnConnectFailed != NULL) {
                    requestInfo->callback.OnConnectFailed(requestInfo->requestId, value);
                }
            }
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
                "connnect notify, result:%d, connectionId:%u, requestId:%u", result, connId, requestInfo->requestId);
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
}

static int32_t ClientOnBrConnect(int32_t connId)
{
    int32_t socketFd = INVALID_SOCKET;
    bool isSuccess = true;
    if (ClientOnBrConnectDevice(connId, &socketFd) != SOFTBUS_OK) {
        isSuccess = false;
    }
    ClientNoticeResultBrConnect(connId, isSuccess, socketFd);
    if (!isSuccess) {
        ReleaseConnectionRefByConnId(connId);
    }
    return socketFd;
}

static void NotifyDisconnect(const ListNode *notifyList, int32_t connectionId,
    ConnectionInfo connectionInfo, int32_t value, int32_t sideType)
{
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(notifyList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, notifyList) {
            RequestInfo *requestInfo = LIST_ENTRY(item, RequestInfo, node);
            if (requestInfo->callback.OnConnectFailed != NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "notify disconn connectionId=%d", connectionId);
                requestInfo->callback.OnConnectFailed(requestInfo->requestId, value);
            }
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
    (void)sideType;
    if (g_connectCallback != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ClientOnEvent] disconn connectionId=%d", connectionId);
        g_connectCallback->OnDisconnected(connectionId, &connectionInfo);
    }
}

static int32_t NotifyServerConn(int connectionId, const char *mac, int32_t sideType)
{
    ConnectionInfo connectionInfo;
    connectionInfo.isAvailable = 1;
    connectionInfo.isServer = sideType;
    connectionInfo.type = CONNECT_BR;
    if (strcpy_s(connectionInfo.brInfo.brMac, BT_MAC_LEN, mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "NotifyServerConn scpy error");
        return SOFTBUS_ERR;
    }
    g_connectCallback->OnConnected(connectionId, &connectionInfo);
    return SOFTBUS_OK;
}

static void FreeSendNode(SendBrQueueNode *node)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[FreeSendNode]");
    if (node == NULL) {
        return;
    }
    if (node->data != NULL) {
        SoftBusFree((void *)node->data);
    }
    SoftBusFree((void *)node);
}

static void BrDisconnect(int32_t socketFd, int32_t value)
{
    ListNode notifyList;
    ListInit(&notifyList);
    ListNode pendingList;
    ListInit(&pendingList);
    ConnectionInfo connectionInfo;
    int32_t sideType = BR_CLIENT_TYPE;
    int32_t perState = BR_CONNECTION_STATE_CLOSED;
    uint32_t connectionId = SetBrConnStateBySocket(socketFd, BR_CONNECTION_STATE_CLOSED, &perState);
    if (connectionId != 0) {
        (void)GetBrRequestListByConnId(connectionId, &notifyList, &connectionInfo, &sideType);
        (void)GetAndRemovePendingRequestByConnId(connectionId, &pendingList);
        if (perState != BR_CONNECTION_STATE_CLOSED) {
            NotifyDisconnect(&notifyList, connectionId, connectionInfo, value, sideType);
            ReleaseConnectionRefByConnId(connectionId);
        }

        ConnectOption option;
        option.type = CONNECT_BR;
        option.brOption.sideType = CONN_SIDE_CLIENT;
        if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, connectionInfo.brInfo.brMac) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "restore connection failed, strcpy_s failed, "
                "connectionId: %u", connectionId);
            return;
        }

        ListNode *it = NULL;
        ListNode *itNext = NULL;
        LIST_FOR_EACH_SAFE(it, itNext, &pendingList) {
            RequestInfo *request = LIST_ENTRY(it, RequestInfo, node);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "connection %u closed, restore connect request: %u",
                connectionId, request->requestId);
            ConnConnectDevice(&option, request->requestId, &request->callback);
            ListDelete(&request->node);
            SoftBusFree(request);
        }
    }
}

int32_t ConnBrOnEvent(BrConnLoopMsgType type, int32_t socketFd, int32_t value)
{
    if (type >= ADD_CONN_BR_MAX || type <= ADD_CONN_BR_INVALID) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrOnEvent] type(%d) failed", type);
        return SOFTBUS_ERR;
    }
    if (type == ADD_CONN_BR_CONGEST_MSG) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrOnEvent] ADD_CONN_BR_CONGEST_MSG");
        RfcomCongestEvent(socketFd, value);
        return SOFTBUS_ERR;
    }

    SoftBusMessage *msg = BrConnCreateLoopMsg(type, (uint64_t)socketFd, (uint64_t)value, NULL);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrOnEvent] BrConnCreateLoopMsg failed");
        return SOFTBUS_ERR;
    }
    g_brAsyncHandler.looper->PostMessage(g_brAsyncHandler.looper, msg);
    return SOFTBUS_OK;
}

static void ConnectDeviceExist(uint32_t connId, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ConnectDeviceExit]");
    BrConnectionInfo *connInfo = GetConnectionRef(connId);
    if (connInfo == NULL) {
        return;
    }
    ConnectionInfo connectionInfo;
    connectionInfo.isAvailable = 1;
    connectionInfo.isServer = connInfo->sideType;
    connectionInfo.type = CONNECT_BR;
    if (strcpy_s(connectionInfo.brInfo.brMac, BT_MAC_LEN, connInfo->mac) != EOK) {
        ReleaseConnectionRef(connInfo);
        return;
    }
    ReleaseConnectionRef(connInfo);

    if (result->OnConnectSuccessed != NULL) {
        result->OnConnectSuccessed(requestId, connId, &connectionInfo);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "connnect notify connected, connectionId:%u, requestId:%u", connId, requestId);

    (void)PackRequest(CONNECT_REF_INCRESE, connId);
}

static int32_t ConnectDeviceStateConnecting(uint32_t connId, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ConnectDeviceStateConnecting]");
    RequestInfo *requestInfo = (RequestInfo *)SoftBusMalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(requestInfo, sizeof(RequestInfo), 0, sizeof(RequestInfo));
    ListInit(&requestInfo->node);
    requestInfo->requestId = requestId;
    if (memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "AddRequestByConnId memcpy_s fail");
        SoftBusFree(requestInfo);
        return SOFTBUS_ERR;
    }
    if (AddRequestByConnId(connId, requestInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "AddRequestByConnId failed");
        SoftBusFree(requestInfo);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceStateClosing(uint32_t connId, uint32_t requestId, const ConnectResult *result)
{
    RequestInfo *requestInfo = (RequestInfo *)SoftBusCalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "add pending request %u failed, malloc failed, connection: %u",
            requestId, connId);
        return SOFTBUS_ERR;
    }

    ListInit(&requestInfo->node);
    requestInfo->requestId = requestId;
    requestInfo->callback = *result;
    if (AddPendingRequestByConnId(connId, requestInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "add pending request %u failed, connection: %u",
            requestId, connId);
        SoftBusFree(requestInfo);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceFirstTime(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ConnectDeviceFirstTime]");
    if (g_sppDriver == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[sppDriver null]");
        return SOFTBUS_ERR;
    }
    BrConnectionInfo *newConnInfo = CreateBrconnectionNode(true);
    if (newConnInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[client node create fail]");
        return SOFTBUS_ERR;
    }
    RequestInfo *requestInfo = (RequestInfo *)SoftBusCalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        ReleaseBrconnectionNode(newConnInfo);
        return SOFTBUS_ERR;
    }
    ListInit(&requestInfo->node);
    requestInfo->requestId = requestId;
    if (memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result)) != EOK) {
        ReleaseBrconnectionNode(newConnInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectDeviceFirstTime memcpy_s fail");
        return SOFTBUS_ERR;
    }
    ListAdd(&newConnInfo->requestList, &requestInfo->node);
    if (strcpy_s(newConnInfo->mac, BT_MAC_LEN, option->brOption.brMac) != EOK) {
        ReleaseBrconnectionNode(newConnInfo);
        return SOFTBUS_ERR;
    }
    uint32_t connId = newConnInfo->connectionId;
    if (AddConnectionList(newConnInfo) != SOFTBUS_OK) {
        ReleaseBrconnectionNode(newConnInfo);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectDeviceFirstTime connId:%d, requestId:%d", connId, requestId);
    if (ConnBrOnEvent(ADD_CONN_BR_CLIENT_CONNECTED_MSG, (int32_t)connId, (int32_t)connId) != SOFTBUS_OK) {
        ReleaseConnectionRef(newConnInfo);
        SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_FAIL, 0);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br connect device, requestId:%u", requestId);
    if (HasDiffMacDeviceExit(option)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[has diff mac device]");
    }
    uint32_t connId = 0;
    uint32_t connectingReqId = 0;
    int32_t ret = SOFTBUS_OK;
    if (pthread_mutex_lock(&g_brConnLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    int32_t connState = GetBrConnStateByConnOption(option, &connId, &connectingReqId);
    if (connState == BR_CONNECTION_STATE_CONNECTED) {
        ConnectDeviceExist(connId, requestId, result);
    } else if (connState == BR_CONNECTION_STATE_CONNECTING) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "device is connecting:%u, current:%u, connecting:%u", connId,
            requestId, connectingReqId);
        ret = ConnectDeviceStateConnecting(connId, requestId, result);
    } else if (connState == BR_CONNECTION_STATE_CLOSING) {
        ret = ConnectDeviceStateClosing(connId, requestId, result);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "device is closing:%u, current:%u, try pending request, ret: %d",
            connId, requestId, ret);
    } else if (connState == BR_CONNECTION_STATE_CLOSED) {
        int32_t connCount = GetBrConnectionCount();
        if (connCount == SOFTBUS_ERR || connCount > g_brMaxConnCount) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
                "br connect device failed: connected device %d exceed than limit %d, requestId: %u",
                    connCount, g_brMaxConnCount, requestId);
            result->OnConnectFailed(requestId, 0);
            SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_FAIL, 0);
            ret = SOFTBUS_ERR;
        } else {
            ret = ConnectDeviceFirstTime(option, requestId, result);
        }
    }
    (void)pthread_mutex_unlock(&g_brConnLock);
    return ret;
}

static uint32_t ServerOnBrConnect(int32_t socketFd)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[new connection, socket = %d]", socketFd);
    if (IsExitBrConnectByFd(socketFd)) {
        return SOFTBUS_ERR;
    }
    uint32_t connectionId = 0;
    BrConnectionInfo *newConnectionInfo = CreateBrconnectionNode(false);
    if (newConnectionInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[service node create fail]");
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    RequestInfo *requestInfo = (RequestInfo *)SoftBusCalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    ListInit(&requestInfo->node);
    ListAdd(&newConnectionInfo->requestList, &requestInfo->node);
    BluetoothRemoteDevice deviceInfo;
    if (g_sppDriver->GetRemoteDeviceInfo(socketFd, &deviceInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetRemoteDeviceInfo fail");
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    if (ConvertBtMacToStr(newConnectionInfo->mac, BT_MAC_LEN, (uint8_t *)deviceInfo.mac, BT_ADDR_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrServer convert bt mac to str fail");
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    newConnectionInfo->socketFd = socketFd;
    newConnectionInfo->state = BR_CONNECTION_STATE_CONNECTED;
    connectionId = newConnectionInfo->connectionId;
    char mac[BT_MAC_LEN] = {0};
    if (memcpy_s(mac, BT_MAC_LEN, newConnectionInfo->mac, BT_MAC_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrServer memcpy mac fail");
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return 0;
    }
    if (AddConnectionList(newConnectionInfo) != SOFTBUS_OK) {
        ListDelete(&newConnectionInfo->node);
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    if (NotifyServerConn(connectionId, mac, BR_SERVICE_TYPE) != SOFTBUS_OK) {
        g_sppDriver->DisConnect(socketFd);
        ReleaseConnectionRefByConnId(connectionId);
        connectionId = 0;
    }
    return connectionId;
}

static int32_t PostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "PostBytes connectionId=%u,pid=%d,len=%d flag=%d", connectionId, pid, len, flag);

    int32_t state = GetBrConnStateByConnectionId(connectionId);
    if (state != BR_CONNECTION_STATE_CONNECTED) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "connectionId(%u) device is not ready, state: %d",
            connectionId, state);
        SoftBusFree((void *)data);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    SendBrQueueNode *node = (SendBrQueueNode *)SoftBusCalloc(sizeof(SendBrQueueNode));
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PostBytes SoftBusCalloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    node->connectionId = connectionId;
    node->pid = pid;
    node->flag = flag;
    node->len = (uint32_t)len;
    node->data = data;
    node->isInner = ((pid == 0) ? true : false);
    node->listener = NULL;
    int32_t ret = BrEnqueueNonBlock((const void *)node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Br enqueue failed, ret: %d", ret);
        SoftBusFree((void *)data);
        SoftBusFree(node);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice(uint32_t connectionId)
{
    if (!IsExitConnectionById(connectionId)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "br disconnect device failed: not find connection: %u", connectionId);
        return SOFTBUS_BRCONNECTION_DISCONNECT_NOTFIND;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br disconnect device, connectionId:%u", connectionId);
    (void)PackRequest(CONNECT_REF_DECRESE, connectionId);
    return SOFTBUS_OK;
}

static int32_t DisconnectDeviceNow(const ConnectOption *option)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDeviceNow]");
    if (option == NULL || option->type != CONNECT_BR) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "option check fail");
        return SOFTBUS_ERR;
    }
    int32_t socketFd = INVALID_SOCKET;
    int32_t sideType;
    if (BrClosingByConnOption(option, &socketFd, &sideType) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!IsBrQueueEmpty()) {
        SoftBusSleepMs(DISCONN_DELAY_TIME);
    }
    if (sideType == BR_SERVICE_TYPE) {
        return ConnBrOnEvent(ADD_CONN_BR_SERVICE_DISCONNECTED_MSG, socketFd, socketFd);
    } else {
        return ConnBrOnEvent(ADD_CONN_BR_CLIENT_DISCONNECTED_MSG, socketFd, socketFd);
    }
    return SOFTBUS_ERR;
}

static int32_t SendAck(BrConnectionInfo *brConnInfo, uint32_t windows, uint64_t seq)
{
    int32_t dataLen = 0;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_ACK, (int32_t)windows, seq, &dataLen);
    if (buf == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t ret = CreateBrPendingPacket(brConnInfo->connectionId, seq);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "create pending failed id: %u, seq: %" PRIu64 ", ret: %d",
            brConnInfo->connectionId, seq, ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = BrTransSend(brConnInfo, g_sppDriver, g_brSendPeerLen, buf, dataLen);
    if (ret != SOFTBUS_OK) {
        DelBrPendingPacket(brConnInfo->connectionId, seq);
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "send ack connectId: %u, seq: %" PRIu64 ", result: %d",
        brConnInfo->connectionId, seq, ret);
    SoftBusFree(buf);
    return ret;
}

static void WaitAck(BrConnectionInfo *brConnInfo, uint64_t seq)
{
    char *data = NULL;
    int32_t ret = GetBrPendingPacket(brConnInfo->connectionId, seq, WAIT_ACK_TIMES, (void **)&data);
    if (ret == SOFTBUS_ALREADY_TRIGGERED) {
        brConnInfo->ackTimeoutCount = 0;
        if (brConnInfo->windows < MAX_WINDOWS) {
            brConnInfo->windows = brConnInfo->windows + 1;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GetBrPending(%u) TRIGGERED seq:%" PRIu64 ", windows: %u",
            brConnInfo->connectionId, seq, brConnInfo->windows);
        SoftBusFree(data);
        return;
    } else if (ret == SOFTBUS_TIMOUT) {
        brConnInfo->ackTimeoutCount = brConnInfo->ackTimeoutCount + 1;
        if (brConnInfo->windows > MIN_WINDOWS && ((brConnInfo->ackTimeoutCount & 0x01) == 0)) {
            brConnInfo->windows = brConnInfo->windows - 1;
        }
        if (brConnInfo->ackTimeoutCount > WINDOWS_ACK_FAILED_TIMES && brConnInfo->windows < DEFAULT_WINDOWS) {
            brConnInfo->windows = DEFAULT_WINDOWS;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GetBrPending(%u) TIMOUT seq:%" PRIu64 ", windows: %u",
            brConnInfo->connectionId, seq, brConnInfo->windows);
        return;
    } else if (ret == SOFTBUS_OK) {
        brConnInfo->ackTimeoutCount = 0;
        SoftBusFree(data);
        return;
    }
    brConnInfo->ackTimeoutCount = 0;
}

static uint64_t UpdataSeq(BrConnectionInfo *brConnInfo)
{
    brConnInfo->seq = brConnInfo->seq + 1;
    if (brConnInfo->seq == 0) {
        brConnInfo->seq = 1;
    }
    return brConnInfo->seq;
}

void *SendHandlerLoop(void *arg)
{
#define WAIT_TIME 10
    SendBrQueueNode *sendNode = NULL;
    while (1) {
        int32_t ret = BrDequeueBlock((void **)(&sendNode));
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "br dequeue send node failed, error=%d", ret);
            SoftBusSleepMs(WAIT_TIME);
            continue;
        }
        uint32_t connId = sendNode->connectionId;
        BrConnectionInfo *brConnInfo = GetConnectionRef(connId);
        if (brConnInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "[SendLoop] connId: %u, not fount failed", connId);
            FreeSendNode(sendNode);
            continue;
        }
        if (brConnInfo->socketFd == INVALID_SOCKET) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_WARN, "[SendLoop] connId: %u, invalid socket", connId);
            ReleaseConnectionRef(brConnInfo);
            FreeSendNode(sendNode);
            continue;
        }
        uint64_t seq = UpdataSeq(brConnInfo);
        uint32_t windows = brConnInfo->windows;
        if (seq % windows == 0) {
            if (SendAck(brConnInfo, windows, seq) == SOFTBUS_OK) {
                brConnInfo->waitSeq = seq;
            }
        }
        sendNode->seq = seq;
        if (brConnInfo->waitSeq != 0 && windows > 1 && (seq % windows == (windows - 1))) {
            WaitAck(brConnInfo, brConnInfo->waitSeq);
            brConnInfo->waitSeq = 0;
        }
        ret = BrTransSend(brConnInfo, g_sppDriver, g_brSendPeerLen, sendNode->data, sendNode->len);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrTransSend fail. connId:%u, seq: %" PRIu64, connId, seq);
        }
        ReleaseConnectionRef(brConnInfo);
        if (sendNode->listener != NULL) {
            sendNode->listener(connId, seq, sendNode->module, ret);
        }
        FreeSendNode(sendNode);
        sendNode = NULL;
    }
    return NULL;
}

static int32_t InitDataQueue(void)
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, SendHandlerLoop, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create DeathProcTask failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void *ConnBrAccept(void *arg)
{
#define TRY_OPEN_SERVER_COUNT 5
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnBrAccept start\n");
    int32_t serverId;
    int32_t clientId;
    char name[BR_SERVER_NAME_LEN] = {0};
    int32_t ret;
    int32_t num = 0;
    int32_t tryCount = 0;
    while (tryCount < TRY_OPEN_SERVER_COUNT) {
        if (g_sppDriver == NULL || !g_startListenFlag || g_brEnable != SOFTBUS_BR_STATE_TURN_ON) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "g_sppDriver failed EXIT!");
            break;
        }
        int32_t connCount = GetBrConnectionCount();
        if (connCount == SOFTBUS_ERR || connCount > g_brMaxConnCount) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "connCount: %d", connCount);
            SoftBusSleepMs(BR_ACCEPET_WAIT_TIME);
            continue;
        }
        (void)memset_s(name, sizeof(name), 0, sizeof(name));
        ret = sprintf_s(name, BR_SERVER_NAME_LEN, "SOFTBUS_BR_%d", num);
        if (ret <= 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "ConnBrAccept sprintf_s failed %d", num);
            SoftBusSleepMs(BR_ACCEPET_WAIT_TIME);
            tryCount++;
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "OpenSppServer %s start", name);
        serverId = g_sppDriver->OpenSppServer(name, strlen(name), UUID, 0);
        if (serverId == SOFTBUS_ERR) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenSppServer name %s failed", name);
            SoftBusSleepMs(BR_ACCEPET_WAIT_TIME);
            tryCount++;
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "OpenSppServer ok");
        clientId = g_sppDriver->Accept(serverId);
        if (clientId != SOFTBUS_ERR && g_brEnable == SOFTBUS_BR_STATE_TURN_ON) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Accept ok clientId: %d", clientId);
            ConnBrOnEvent(ADD_CONN_BR_SERVICE_CONNECTED_MSG, clientId, clientId);
        } else {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "spp Accept %s failed, clientId: %d", name, clientId);
        }
        g_sppDriver->CloseSppServer(serverId);
        num++;
        tryCount = 0;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenSppServer failed EXIT!");
    return NULL;
}

static int32_t StartLocalListening(const LocalListenerInfo *info)
{
    if (g_sppDriver == NULL || info->type != CONNECT_BR) {
        return SOFTBUS_ERR;
    }

    if (g_startListenFlag) {
        return SOFTBUS_OK;
    }

    pthread_t tid;
    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    if (pthread_create(&tid, &threadAttr, ConnBrAccept, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create ConnBrAccept failed");
        pthread_attr_destroy(&threadAttr);
        return SOFTBUS_ERR;
    }
    g_startListenFlag = true;
    pthread_attr_destroy(&threadAttr);
    return SOFTBUS_OK;
}

static int32_t StopLocalListening(const LocalListenerInfo *info)
{
    if (g_sppDriver == NULL || info->type != CONNECT_BR) {
        return SOFTBUS_ERR;
    }
    g_startListenFlag = false;
    return SOFTBUS_OK;
}

static int32_t InitProperty()
{
    g_brBuffSize = INVALID_LENGTH;
    g_brSendPeerLen = INVALID_LENGTH;
    g_brMaxConnCount = INVALID_LENGTH;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH,
        (unsigned char*)&g_brBuffSize, sizeof(g_brBuffSize)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get br BuffSize fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br BuffSize is %u", g_brBuffSize);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN,
        (unsigned char*)&g_brSendPeerLen, sizeof(g_brSendPeerLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get br SendPeerLen fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br SendPeerLen is %u", g_brSendPeerLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN,
        (unsigned char*)&g_brSendQueueMaxLen, sizeof(g_brSendQueueMaxLen)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get br SendQueueMaxLen fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br SendQueueMaxLen is %u", g_brSendQueueMaxLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_MAX_CONN_NUM,
        (unsigned char*)&g_brMaxConnCount, sizeof(g_brMaxConnCount)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "get br MaxConnCount fail");
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br MaxConnCount is %d", g_brMaxConnCount);
    if (g_brBuffSize == INVALID_LENGTH || g_brBuffSize > MAX_BR_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brBuffSize");
        return SOFTBUS_ERR;
    }
    if (g_brSendPeerLen == INVALID_LENGTH || g_brSendPeerLen > MAX_BR_PEER_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brSendPeerLen");
        return SOFTBUS_ERR;
    }
    if (g_brSendQueueMaxLen == SOFTBUS_ERR || g_brSendQueueMaxLen > MAX_BR_PEER_SIZE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brSendQueueMaxLen");
        return SOFTBUS_ERR;
    }
    if (g_brMaxConnCount == INVALID_LENGTH) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot get brMaxConnCount");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

typedef struct BrReadThreadParams {
    uint32_t connInfoId;
    int32_t socketFd;
} BrReadThreadParams;

void *ConnBrRead(void *arg)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnBrRead start");
    if (arg == NULL) {
        return NULL;
    }
    BrReadThreadParams *values = (BrReadThreadParams *)arg;
    uint32_t connId = values->connInfoId;
    int32_t socketFd = values->socketFd;
    SoftBusFree(arg);

    if (socketFd == INVALID_SOCKET) {
        socketFd = ClientOnBrConnect(connId);
        if (socketFd == INVALID_SOCKET) {
            return NULL;
        }
    }
    while (1) {
        char *outBuf = NULL;
        int32_t packLen = BrTransReadOneFrame(connId, g_sppDriver, socketFd, &outBuf);
        if (packLen == BR_READ_SOCKET_CLOSED) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrRead] failed socket close");
            g_sppDriver->DisConnect(socketFd);
            BrDisconnect(socketFd, socketFd);
            return NULL;
        }
        if (packLen == BR_READ_FAILED) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrRead] failed");
            g_sppDriver->DisConnect(socketFd);
            BrDisconnect(socketFd, socketFd);
            return NULL;
        }
        if (outBuf == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrRead] outBuf null");
            continue;
        }
        SoftBusMessage *msg = BrConnCreateLoopMsg(ADD_CONN_BR_RECV_MSG, (uint64_t)connId, (uint64_t)packLen, outBuf);
        if (msg == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ConnBrRead] BrConnCreateLoopMsg failed");
            SoftBusFree(outBuf);
            continue;
        }
        g_brAsyncHandler.looper->PostMessage(g_brAsyncHandler.looper, msg);
    }
    return NULL;
}

void BrConnectedEventHandle(bool isClient, uint32_t value)
{
    uint32_t connInfoId;
    int32_t socketFd = INVALID_SOCKET;
    if (isClient) {
        connInfoId = value;
    } else {
        socketFd = (int32_t)value;
        connInfoId = ServerOnBrConnect(socketFd);
    }
    if (connInfoId == 0) {
        return;
    }
    pthread_t tid;
    BrReadThreadParams *args = (BrReadThreadParams *)SoftBusCalloc(sizeof(BrReadThreadParams));
    if (args == NULL) {
        goto EXIT;
    }
    args->connInfoId = connInfoId;
    args->socketFd = socketFd;
    if (pthread_create(&tid, NULL, ConnBrRead, (void *)args) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create ConnBrRead failed");
        SoftBusFree(args);
        goto EXIT;
    }
    return;
EXIT:
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrConnectedEventHandle EXIT");
    if (!isClient) {
        ConnBrOnEvent(ADD_CONN_BR_SERVICE_DISCONNECTED_MSG, socketFd, socketFd);
    } else {
        ClientNoticeResultBrConnect(connInfoId, false, socketFd);
        ReleaseConnectionRefByConnId(connInfoId);
    }
    return;
}

static void Resume(uint32_t connectionId)
{
    ListNode pendings;
    ListInit(&pendings);

    if (ResumeConnection(connectionId, &pendings) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "resume pending connection %u failed", connectionId);
        return;
    }

    ListNode *it = NULL;
    ListNode *itNext = NULL;
    LIST_FOR_EACH_SAFE(it, itNext, &pendings) {
        RequestInfo *request = LIST_ENTRY(it, RequestInfo, node);
        ConnectDeviceExist(connectionId, request->requestId, &request->callback);
        ListDelete(&request->node);
        SoftBusFree(request);
    }
}

static void OnPackResponse(int32_t delta, int32_t peerRef, uint32_t connectionId)
{
    BrConnectionInfo *connInfo = GetConnectionRef(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "br OnPackResponse failed: not find device, connectionId: %u", connectionId);
        return;
    }
    connInfo->refCount += delta;
    int32_t myRefCount = connInfo->refCount;
    int32_t mySocketFd = connInfo->socketFd;
    int32_t sideType = connInfo->sideType;
    ReleaseConnectionRef(connInfo);

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "br OnPackResponse: delta=%d, remoteRef=%d, myRef:%d, connectionId=%u",
            delta, peerRef, myRefCount, connectionId);
    if (peerRef > 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[remote device Ref is > 0, do not reply]");
        // resume connection when peer reference is larger than 0
        Resume(connectionId);
        return;
    }
    if (myRefCount <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
            "br OnPackResponse local device ref <= 0, and remote ref <=0 close connection now");
        SetBrConnStateByConnId(connectionId, BR_CONNECTION_STATE_CLOSING);
        if (sideType == BR_SERVICE_TYPE) {
            ConnBrOnEvent(ADD_CONN_BR_SERVICE_DISCONNECTED_MSG, mySocketFd, mySocketFd);
        } else {
            ConnBrOnEvent(ADD_CONN_BR_CLIENT_DISCONNECTED_MSG, mySocketFd, mySocketFd);
        }
        return;
    }
    int32_t outLen = INVALID_LENGTH;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_RESPONSE, delta, myRefCount, &outLen);
    if (buf == NULL) {
        return;
    }
    (void)PostBytesInner(connectionId, METHOD_NOTIFY_RESPONSE, buf, outLen);
}

static int32_t OnAck(uint32_t connectionId, uint32_t localWindows, uint64_t remoteSeq)
{
    int32_t dataLen = 0;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "send ack seq: %" PRIu64 " respone", remoteSeq);
    char *buf = BrPackRequestOrResponse(METHOD_ACK_RESPONSE, (int32_t)localWindows, remoteSeq, &dataLen);
    if (buf != NULL) {
        return PostBytesInner(connectionId, METHOD_ACK_RESPONSE, buf, dataLen);
    }
    return SOFTBUS_ERR;
}

static void BrConnectedComdHandl(uint32_t connectionId, const cJSON *data)
{
    int32_t keyMethod = 0;
    int32_t keyDelta = 0;
    int32_t keyReferenceNum = 0;

    if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod)) {
        return;
    }
    if (keyMethod == METHOD_NOTIFY_REQUEST) {
        if (!GetJsonObjectSignedNumberItem(data, KEY_DELTA, &keyDelta) ||
            !GetJsonObjectSignedNumberItem(data, KEY_REFERENCE_NUM, &keyReferenceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "REQUEST fail");
            return;
        }
        OnPackResponse(keyDelta, keyReferenceNum, connectionId);
    } else if (keyMethod == METHOD_NOTIFY_RESPONSE) {
        if (!GetJsonObjectSignedNumberItem(data, KEY_REFERENCE_NUM, &keyReferenceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RESPONSE fail");
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
            "br NOTIFY_RESPONSE, connectionId:%u, remote ref:%d", connectionId, keyReferenceNum);
        SetBrConnStateByConnId(connectionId, BR_CONNECTION_STATE_CONNECTED);
    } else if (keyMethod == METHOD_NOTIFY_ACK) {
        int32_t remoteWindows;
        int64_t remoteSeq;
        if (!GetJsonObjectSignedNumberItem(data, KEY_WINDOWS, &remoteWindows) ||
            !GetJsonObjectNumber64Item(data, KEY_ACK_SEQ_NUM, &remoteSeq)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ACK REQUEST fail");
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv ACK REQUEST(%u) remote seq: %" PRIu64 ", windows: %d",
            connectionId, remoteSeq, remoteWindows);
        OnAck(connectionId, GetLocalWindowsByConnId(connectionId), (uint64_t)remoteSeq);
    } else if (keyMethod == METHOD_ACK_RESPONSE) {
        int32_t remoteWindows;
        int64_t remoteSeq;
        if (!GetJsonObjectSignedNumberItem(data, KEY_WINDOWS, &remoteWindows) ||
            !GetJsonObjectNumber64Item(data, KEY_ACK_SEQ_NUM, &remoteSeq)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ACK RESPONSE fail");
            return;
        }
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "recv ACK RESPONSE(%u) remote seq: %" PRId64 ", windows: %d",
            connectionId, remoteSeq, remoteWindows);
        if (SetBrPendingPacket(connectionId, (uint64_t)remoteSeq, NULL) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SetBrPendingPacket(%u) failed seq: %" PRId64,
                connectionId, remoteSeq);
        }
    }
}

static void BrRecvDataHandle(uint32_t connectionId, const char *buf, int32_t len)
{
    if (len - (int32_t)sizeof(ConnPktHead) <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "br recv data illegal data size: %d", len);
        return;
    }
    ConnPktHead *head = (ConnPktHead *)buf;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BrRecvDataHandle module: %d", head->module);
    if (head->module == MODULE_CONNECTION) {
        cJSON *data = NULL;
        data = cJSON_ParseWithLength(buf + sizeof(ConnPktHead), len - (int32_t)sizeof(ConnPktHead));
        if (data == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "br recv data invalid");
            return;
        }
        BrConnectedComdHandl(connectionId, (const cJSON *)data);
        cJSON_Delete(data);
    } else {
        if (g_connectCallback != NULL) {
            g_connectCallback->OnDataReceived(connectionId, (ConnModule)head->module, head->seq, (char *)buf, len);
        }
    }
}

static void BrConnMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br conn loop process msg type %d", msg->what);
    switch (msg->what) {
        case ADD_CONN_BR_CLIENT_CONNECTED_MSG:
            BrConnectedEventHandle(true, msg->arg1);
            break;
        case ADD_CONN_BR_SERVICE_CONNECTED_MSG:
            BrConnectedEventHandle(false, msg->arg1);
            break;
        case ADD_CONN_BR_CLIENT_DISCONNECTED_MSG:
        case ADD_CONN_BR_SERVICE_DISCONNECTED_MSG:
            g_sppDriver->DisConnect(msg->arg1);
            BrDisconnect(msg->arg1, msg->arg2);
            break;
        case ADD_CONN_BR_RECV_MSG: {
            uint32_t connId = (uint32_t)msg->arg1;
            int32_t len = (int32_t)msg->arg2;
            BrRecvDataHandle(connId, (const char *)msg->obj, len);
            SoftBusFree((void *)msg->obj);
            msg->obj = NULL;
            break;
        }
        case ADD_CONN_BR_CLOSING_TIMEOUT_MSG:
            // resume connection when close timeout
            Resume((uint32_t)msg->arg1);
            break;
        default:
            break;
    }
}

static int32_t BrConnLooperInit(void)
{
    g_brAsyncHandler.looper = CreateNewLooper("brRecv_looper");
    if (g_brAsyncHandler.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrConnLooperInit failed");
        return SOFTBUS_ERR;
    }
    g_brAsyncHandler.HandleMessage = BrConnMsgHandler;
    return SOFTBUS_OK;
}

static void StateChangedCallback(int32_t listenerId, int32_t status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StateChanged id: %d, status: %d", listenerId, status);

    LocalListenerInfo info;
    info.type = CONNECT_BR;
    if (status == SOFTBUS_BR_STATE_TURN_ON) {
        g_brEnable = status;
        (void)StartLocalListening(&info);
    } else if (status == SOFTBUS_BR_STATE_TURN_OFF) {
        g_brEnable = status;
        (void)StopLocalListening(&info);
    }
}

static int32_t SppRegisterConnCallback(void)
{
    (void)memset_s(&g_sppBrCallback, sizeof(g_sppBrCallback), 0, sizeof(g_sppBrCallback));
    g_sppBrCallback.OnBtStateChanged = StateChangedCallback;
    return SppGattsRegisterHalCallback(&g_sppBrCallback);
}

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[InitBR]");
    if (InitProperty() != SOFTBUS_OK) {
        return NULL;
    }
    g_sppDriver = InitSppSocketDriver();
    if (g_sppDriver == NULL) {
        return NULL;
    }
    InitBrConnectionManager(g_brBuffSize);
    if (InitBrPendingPacket() != SOFTBUS_OK) {
        return NULL;
    }
    if (BrInnerQueueInit() != SOFTBUS_OK) {
        DestroyBrPendingPacket();
        return NULL;
    }
    if (InitDataQueue() != SOFTBUS_OK) {
        DestroyBrPendingPacket();
        BrInnerQueueDeinit();
        return NULL;
    }
    if (BrConnLooperInit() != SOFTBUS_OK) {
        BrInnerQueueDeinit();
        DestroyBrPendingPacket();
        return NULL;
    }
    if (SppRegisterConnCallback() != SOFTBUS_OK) {
        BrInnerQueueDeinit();
        DestroyBrPendingPacket();
        DestroyLooper(g_brAsyncHandler.looper);
        return NULL;
    }
    pthread_mutex_init(&g_brConnLock, NULL);
    g_connectCallback = (ConnectCallback *)callback;
    return &g_brInterface;
}

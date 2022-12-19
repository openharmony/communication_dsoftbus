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

static SoftBusHandler g_brAsyncHandler = {
    .name = (char *)"g_brAsyncHandler"
};

static int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

static int32_t DisconnectDevice(uint32_t connectionId);

static int32_t DisconnectDeviceNow(const ConnectOption *option);

static int32_t StartLocalListening(const LocalListenerInfo *info);

static int32_t StopLocalListening(const LocalListenerInfo *info);

static int32_t PostBytes(uint32_t connectionId, char *data, int32_t len, int32_t pid, int32_t flag);

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
static volatile int32_t g_brEnable = SOFTBUS_BR_STATE_TURN_OFF;

NO_SANITIZE("cfi") static void BrFreeMessage(SoftBusMessage *msg)
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
        CLOGE("BrConnCreateLoopMsg SoftBusCalloc failed");
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
        CLOGE("PostInner failed, connId:%u, seq:%" PRIu64 ", module:%d, result:%d", connId, seq, module, result);
    } else {
        CLOGE("PostInner success, connId:%u, seq:%" PRIu64 ", module:%d", connId, seq, module);
    }
}

static int32_t PostBytesInner(uint32_t connectionId, int32_t module, const char *data, uint32_t len)
{
    CLOGI("PostBytesInner connectionId=%u,len=%u,module=%d", connectionId, len, module);

    // control message need be sent when closing
    int32_t state = GetBrConnStateByConnectionId(connectionId);
    if (state != BR_CONNECTION_STATE_CLOSING && state != BR_CONNECTION_STATE_CONNECTED) {
        CLOGI("connectionId(%u) device is not ready, state: %d",
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
        CLOGE("Br PostBytesInner enqueue failed, ret: %d", ret);
        SoftBusFree((void *)data);
        SoftBusFree(node);
        return ret;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static int32_t PostClosingTimeoutEvent(uint32_t connectionId)
{
    SoftBusMessage *msg = BrConnCreateLoopMsg(ADD_CONN_BR_CLOSING_TIMEOUT_MSG, (uint64_t)connectionId, 0, NULL);
    if (msg == NULL) {
        CLOGE("[PostClosingTimeoutEvent] BrConnCreateLoopMsg failed, connection id: %u", connectionId);
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
        CLOGI("br connection %u not connected ever!", connectionId);
        return;
    }

    CLOGI("br pack request: delta:%d, ref:%d, connectionId:%u, state:%d", delta, refCount, connectionId, state);

    if (state == BR_CONNECTION_STATE_CLOSING) {
        int32_t ret = PostClosingTimeoutEvent(connectionId);
        CLOGI("post close %u connection timeout event, ret: %d", connectionId, ret);
        // continue, anyway
    }

    int32_t dataLen = 0;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_REQUEST, connectionId, delta, refCount, &dataLen);
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

NO_SANITIZE("cfi") static int32_t ClientOnBrConnectDevice(int32_t connId, int32_t *outSocketFd)
{
    CLOGI("sppDriver connect start, connId:%d", connId);
    BrConnectionInfo *brConn = GetConnectionRef(connId);
    if (brConn == NULL) {
        CLOGI("BrClient not find connInfo.");
        return SOFTBUS_BRCONNECTION_GETCONNINFO_ERROR;
    }
    if (brConn->sideType != BR_CLIENT_TYPE) {
        ReleaseConnectionRef(brConn);
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t btAddr[BT_ADDR_LEN];
    if (ConvertBtMacToBinary(brConn->mac, BT_MAC_LEN, btAddr, BT_ADDR_LEN) != SOFTBUS_OK) {
        CLOGE("convert bt mac to binary fail.");
        ReleaseConnectionRef(brConn);
        return SOFTBUS_ERR;
    }
    int32_t socketFd = SOFTBUS_ERR;
    if (g_sppDriver != NULL) {
        socketFd = g_sppDriver->Connect(UUID, btAddr);
    }
    if (socketFd == SOFTBUS_ERR) {
        ReleaseConnectionRef(brConn);
        CLOGE("sppDriver connect failed, connId:%d", connId);
        return SOFTBUS_BRCONNECTION_CONNECTDEVICE_GETSOCKETIDFAIL;
    }
    brConn->socketFd = socketFd;
    CLOGI("br connection ok, Id=%d, socket=%d", connId, socketFd);
    if (g_sppDriver->IsConnected(socketFd)) {
        CLOGI("sppDriver IsConnected true.");
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

NO_SANITIZE("cfi") static void ClientNoticeResultBrConnect(uint32_t connId, bool result, int32_t value)
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
            CLOGI("connnect notify, result:%d, connectionId:%u, requestId:%u", result, connId, requestInfo->requestId);
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

NO_SANITIZE("cfi") static void NotifyDisconnect(const ListNode *notifyList, int32_t connectionId,
    ConnectionInfo connectionInfo, int32_t value, int32_t sideType)
{
    ListNode *item = NULL;
    ListNode *itemNext = NULL;
    if (IsListEmpty(notifyList) != true) {
        LIST_FOR_EACH_SAFE(item, itemNext, notifyList) {
            RequestInfo *requestInfo = LIST_ENTRY(item, RequestInfo, node);
            if (requestInfo->callback.OnConnectFailed != NULL) {
                CLOGI("notify disconn connectionId=%d", connectionId);
                requestInfo->callback.OnConnectFailed(requestInfo->requestId, value);
            }
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
    (void)sideType;
    if (g_connectCallback != NULL) {
        CLOGI("[ClientOnEvent] disconn connectionId=%d", connectionId);
        g_connectCallback->OnDisconnected(connectionId, &connectionInfo);
    }
}

NO_SANITIZE("cfi") static int32_t NotifyServerConn(int connectionId, const char *mac, int32_t sideType)
{
    ConnectionInfo connectionInfo;
    connectionInfo.isAvailable = 1;
    connectionInfo.isServer = sideType;
    connectionInfo.type = CONNECT_BR;
    if (strcpy_s(connectionInfo.brInfo.brMac, BT_MAC_LEN, mac) != EOK) {
        CLOGE("NotifyServerConn scpy error");
        return SOFTBUS_ERR;
    }
    g_connectCallback->OnConnected(connectionId, &connectionInfo);
    return SOFTBUS_OK;
}

static void FreeSendNode(SendBrQueueNode *node)
{
    CLOGI("[FreeSendNode]");
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
            CLOGE("restore connection failed, strcpy_s failed, connectionId: %u", connectionId);
            return;
        }

        ListNode *it = NULL;
        ListNode *itNext = NULL;
        LIST_FOR_EACH_SAFE(it, itNext, &pendingList) {
            RequestInfo *request = LIST_ENTRY(it, RequestInfo, node);
            CLOGE("connection %u closed, restore connect request: %u", connectionId, request->requestId);
            ConnConnectDevice(&option, request->requestId, &request->callback);
            ListDelete(&request->node);
            SoftBusFree(request);
        }
    }
}

NO_SANITIZE("cfi") int32_t ConnBrOnEvent(BrConnLoopMsgType type, int32_t socketFd, int32_t value)
{
    if (type >= ADD_CONN_BR_MAX || type <= ADD_CONN_BR_INVALID) {
        CLOGE("[ConnBrOnEvent] type(%d) failed", type);
        return SOFTBUS_ERR;
    }
    if (type == ADD_CONN_BR_CONGEST_MSG) {
        CLOGE("[ConnBrOnEvent] ADD_CONN_BR_CONGEST_MSG");
        RfcomCongestEvent(socketFd, value);
        return SOFTBUS_ERR;
    }

    SoftBusMessage *msg = BrConnCreateLoopMsg(type, (uint64_t)socketFd, (uint64_t)value, NULL);
    if (msg == NULL) {
        CLOGE("[ConnBrOnEvent] BrConnCreateLoopMsg failed");
        return SOFTBUS_ERR;
    }
    g_brAsyncHandler.looper->PostMessage(g_brAsyncHandler.looper, msg);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static void ConnectDeviceExist(uint32_t connId, uint32_t requestId, const ConnectResult *result)
{
    CLOGI("[ConnectDeviceExit]");
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
    CLOGI("connnect notify connected, connectionId:%u, requestId:%u", connId, requestId);

    (void)PackRequest(CONNECT_REF_INCRESE, connId);
}

static int32_t ConnectDeviceStateConnecting(uint32_t connId, uint32_t requestId, const ConnectResult *result)
{
    CLOGI("[ConnectDeviceStateConnecting]");
    RequestInfo *requestInfo = (RequestInfo *)SoftBusMalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        CLOGI("SoftBusMalloc failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(requestInfo, sizeof(RequestInfo), 0, sizeof(RequestInfo));
    ListInit(&requestInfo->node);
    requestInfo->requestId = requestId;
    if (memcpy_s(&requestInfo->callback, sizeof(requestInfo->callback), result, sizeof(*result)) != EOK) {
        CLOGI("AddRequestByConnId memcpy_s fail");
        SoftBusFree(requestInfo);
        return SOFTBUS_ERR;
    }
    if (AddRequestByConnId(connId, requestInfo) != SOFTBUS_OK) {
        CLOGI("AddRequestByConnId failed");
        SoftBusFree(requestInfo);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceStateClosing(uint32_t connId, uint32_t requestId, const ConnectResult *result)
{
    RequestInfo *requestInfo = (RequestInfo *)SoftBusCalloc(sizeof(RequestInfo));
    if (requestInfo == NULL) {
        CLOGE("add pending request %u failed, malloc failed, connection: %u", requestId, connId);
        return SOFTBUS_ERR;
    }

    ListInit(&requestInfo->node);
    requestInfo->requestId = requestId;
    requestInfo->callback = *result;
    if (AddPendingRequestByConnId(connId, requestInfo) != SOFTBUS_OK) {
        CLOGI("add pending request %u failed, connection: %u", requestId, connId);
        SoftBusFree(requestInfo);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceFirstTime(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    CLOGI("[ConnectDeviceFirstTime]");
    if (g_sppDriver == NULL) {
        CLOGE("[sppDriver null]");
        return SOFTBUS_ERR;
    }
    BrConnectionInfo *newConnInfo = CreateBrconnectionNode(true);
    if (newConnInfo == NULL) {
        CLOGE("[client node create fail]");
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
        CLOGI("ConnectDeviceFirstTime memcpy_s fail");
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
    CLOGI("ConnectDeviceFirstTime connId:%d, requestId:%d", connId, requestId);
    if (ConnBrOnEvent(ADD_CONN_BR_CLIENT_CONNECTED_MSG, (int32_t)connId, (int32_t)connId) != SOFTBUS_OK) {
        ReleaseConnectionRef(newConnInfo);
        SoftbusRecordConnInfo(SOFTBUS_HISYSEVT_CONN_MEDIUM_BR, SOFTBUS_EVT_CONN_FAIL, 0);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    CLOGI("br connect device, requestId:%u", requestId);
    if (HasDiffMacDeviceExit(option)) {
        CLOGI("[has diff mac device]");
    }
    uint32_t connId = 0;
    uint32_t connectingReqId = 0;
    int32_t ret = SOFTBUS_OK;
    if (pthread_mutex_lock(&g_brConnLock) != 0) {
        CLOGE("lock mutex failed");
        return SOFTBUS_ERR;
    }
    int32_t connState = GetBrConnStateByConnOption(option, &connId, &connectingReqId);
    if (connState == BR_CONNECTION_STATE_CONNECTED) {
        ConnectDeviceExist(connId, requestId, result);
    } else if (connState == BR_CONNECTION_STATE_CONNECTING) {
        CLOGI("device is connecting:%u, current:%u, connecting:%u", connId, requestId, connectingReqId);
        ret = ConnectDeviceStateConnecting(connId, requestId, result);
    } else if (connState == BR_CONNECTION_STATE_CLOSING) {
        ret = ConnectDeviceStateClosing(connId, requestId, result);
        CLOGI("device is closing:%u, current:%u, try pending request, ret: %d", connId, requestId, ret);
    } else if (connState == BR_CONNECTION_STATE_CLOSED) {
        ret = ConnectDeviceFirstTime(option, requestId, result);
    }
    (void)pthread_mutex_unlock(&g_brConnLock);
    return ret;
}

NO_SANITIZE("cfi") static uint32_t ServerOnBrConnect(int32_t socketFd)
{
    CLOGI("[new connection, socket = %d]", socketFd);
    if (IsExitBrConnectByFd(socketFd)) {
        return SOFTBUS_ERR;
    }
    uint32_t connectionId = 0;
    BrConnectionInfo *newConnectionInfo = CreateBrconnectionNode(false);
    if (newConnectionInfo == NULL) {
        CLOGE("[service node create fail]");
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
        CLOGE("GetRemoteDeviceInfo fail");
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    if (ConvertBtMacToStr(newConnectionInfo->mac, BT_MAC_LEN, (uint8_t *)deviceInfo.mac, BT_ADDR_LEN) != SOFTBUS_OK) {
        CLOGE("BrServer convert bt mac to str fail");
        ReleaseBrconnectionNode(newConnectionInfo);
        g_sppDriver->DisConnect(socketFd);
        return connectionId;
    }
    newConnectionInfo->socketFd = socketFd;
    newConnectionInfo->state = BR_CONNECTION_STATE_CONNECTED;
    connectionId = newConnectionInfo->connectionId;
    char mac[BT_MAC_LEN] = {0};
    if (memcpy_s(mac, BT_MAC_LEN, newConnectionInfo->mac, BT_MAC_LEN) != EOK) {
        CLOGE("BrServer memcpy mac fail");
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

static int32_t PostBytes(uint32_t connectionId, char *data, int32_t len, int32_t pid, int32_t flag)
{
    CLOGI("PostBytes connectionId=%u,pid=%d,len=%d flag=%d", connectionId, pid, len, flag);
    int32_t state = GetBrConnStateByConnectionId(connectionId);
    if (state != BR_CONNECTION_STATE_CONNECTED) {
        CLOGI("connectionId(%u) device is not ready, state: %d", connectionId, state);
        SoftBusFree(data);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    SendBrQueueNode *node = (SendBrQueueNode *)SoftBusCalloc(sizeof(SendBrQueueNode));
    if (node == NULL) {
        CLOGE("PostBytes SoftBusCalloc failed");
        SoftBusFree(data);
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
        CLOGE("Br enqueue failed, ret: %d", ret);
        SoftBusFree(data);
        SoftBusFree(node);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice(uint32_t connectionId)
{
    if (!IsExitConnectionById(connectionId)) {
        CLOGE("br disconnect device failed: not find connection: %u", connectionId);
        return SOFTBUS_BRCONNECTION_DISCONNECT_NOTFIND;
    }
    CLOGI("br disconnect device, connectionId:%u", connectionId);
    (void)PackRequest(CONNECT_REF_DECRESE, connectionId);
    return SOFTBUS_OK;
}

static int32_t DisconnectDeviceNow(const ConnectOption *option)
{
    CLOGI("[DisconnectDeviceNow]");
    if (option == NULL || option->type != CONNECT_BR) {
        CLOGE("option check fail");
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
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_ACK, brConnInfo->connectionId, (int32_t)windows, seq, &dataLen);
    if (buf == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t ret = CreateBrPendingPacket(brConnInfo->connectionId, seq);
    if (ret != SOFTBUS_OK) {
        CLOGW("create pending failed id: %u, seq: %" PRIu64 ", ret: %d", brConnInfo->connectionId, seq, ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = BrTransSend(brConnInfo, g_sppDriver, g_brSendPeerLen, buf, dataLen);
    if (ret != SOFTBUS_OK) {
        DelBrPendingPacket(brConnInfo->connectionId, seq);
    }
    CLOGI("send ack connectId: %u, seq: %" PRIu64 ", result: %d", brConnInfo->connectionId, seq, ret);
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
        CLOGI("GetBrPending(%u) TRIGGERED seq:%" PRIu64 ", windows: %u",
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
        CLOGI("GetBrPending(%u) TIMOUT seq:%" PRIu64 ", windows: %u",
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

NO_SANITIZE("cfi") void *SendHandlerLoop(void *arg)
{
#define WAIT_TIME 10
    SendBrQueueNode *sendNode = NULL;
    while (1) {
        int32_t ret = BrDequeueBlock((void **)(&sendNode));
        if (ret != SOFTBUS_OK) {
            CLOGE("ATTENSION: br dequeue send node failed, error=%d", ret);
            SoftBusSleepMs(WAIT_TIME);
            continue;
        }
        uint32_t connId = sendNode->connectionId;
        BrConnectionInfo *brConnInfo = GetConnectionRef(connId);
        if (brConnInfo == NULL) {
            CLOGW("[SendLoop] connId: %u, not fount failed", connId);
            FreeSendNode(sendNode);
            continue;
        }
        if (brConnInfo->socketFd == INVALID_SOCKET) {
            CLOGW("[SendLoop] connId: %u, invalid socket", connId);
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
            CLOGE("BrTransSend fail. connId:%u, seq: %" PRIu64, connId, seq);
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
        CLOGE("create DeathProcTask failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void *ConnBrAccept(void *arg)
{
    CLOGI("br server thread start");
    static const char *name = "SOFTBUS_BR_SERVER";
    while (true) {
        if (!g_startListenFlag || g_brEnable != SOFTBUS_BR_STATE_TURN_ON) {
            CLOGE("it is not ready for listen, as isAccept:%d, g_brEnable:%d", g_startListenFlag, g_brEnable);
            break;
        }
        int32_t serverId = g_sppDriver->OpenSppServer(name, strlen(name), UUID, 0);
        if (serverId == SOFTBUS_ERR) {
            CLOGE("open spp server failed, name: %s", name);
            SoftBusSleepMs(BR_ACCEPET_WAIT_TIME);
            continue;
        }
        CLOGI("open spp server ok, name: %s, serverId:%d", name, serverId);
        while (true) {
            if (!g_startListenFlag || g_brEnable != SOFTBUS_BR_STATE_TURN_ON) {
                break;
            }
            int32_t clientId = g_sppDriver->Accept(serverId);
            if (clientId == SOFTBUS_ERR) {
                CLOGE("accept failed, name:%s, serverId:%d", name, serverId);
                break;
            }
            CLOGI("accept ok clientId: name:%s, serverId:%d, clientId:%d",
                name, serverId, clientId);
            ConnBrOnEvent(ADD_CONN_BR_SERVICE_CONNECTED_MSG, clientId, clientId);
        }
        g_sppDriver->CloseSppServer(serverId);
    }
    g_startListenFlag = false;
    CLOGE("br server thread exit");
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
        CLOGE("create ConnBrAccept failed");
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
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH,
        (unsigned char*)&g_brBuffSize, sizeof(g_brBuffSize)) != SOFTBUS_OK) {
        CLOGE("get br BuffSize fail");
    }
    CLOGI("br BuffSize is %u", g_brBuffSize);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN,
        (unsigned char*)&g_brSendPeerLen, sizeof(g_brSendPeerLen)) != SOFTBUS_OK) {
        CLOGE("get br SendPeerLen fail");
    }
    CLOGI("br SendPeerLen is %u", g_brSendPeerLen);
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_BR_RECEIVE_MAX_LEN,
        (unsigned char*)&g_brSendQueueMaxLen, sizeof(g_brSendQueueMaxLen)) != SOFTBUS_OK) {
        CLOGE("get br SendQueueMaxLen fail");
    }
    CLOGI("br SendQueueMaxLen is %u", g_brSendQueueMaxLen);
    if (g_brBuffSize == INVALID_LENGTH || g_brBuffSize > MAX_BR_SIZE) {
        CLOGE("Cannot get brBuffSize");
        return SOFTBUS_ERR;
    }
    if (g_brSendPeerLen == INVALID_LENGTH || g_brSendPeerLen > MAX_BR_PEER_SIZE) {
        CLOGE("Cannot get brSendPeerLen");
        return SOFTBUS_ERR;
    }
    if (g_brSendQueueMaxLen == SOFTBUS_ERR || g_brSendQueueMaxLen > MAX_BR_PEER_SIZE) {
        CLOGE("Cannot get brSendQueueMaxLen");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

typedef struct BrReadThreadParams {
    uint32_t connInfoId;
    int32_t socketFd;
} BrReadThreadParams;

NO_SANITIZE("cfi") void *ConnBrRead(void *arg)
{
    CLOGI("ConnBrRead start");
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
            CLOGE("[ConnBrRead] failed socket close");
            g_sppDriver->DisConnect(socketFd);
            BrDisconnect(socketFd, socketFd);
            return NULL;
        }
        if (packLen == BR_READ_FAILED) {
            CLOGE("[ConnBrRead] failed");
            g_sppDriver->DisConnect(socketFd);
            BrDisconnect(socketFd, socketFd);
            return NULL;
        }
        if (outBuf == NULL) {
            CLOGE("[ConnBrRead] outBuf null");
            continue;
        }
        SoftBusMessage *msg = BrConnCreateLoopMsg(ADD_CONN_BR_RECV_MSG, (uint64_t)connId, (uint64_t)packLen, outBuf);
        if (msg == NULL) {
            CLOGE("[ConnBrRead] BrConnCreateLoopMsg failed");
            SoftBusFree(outBuf);
            continue;
        }
        g_brAsyncHandler.looper->PostMessage(g_brAsyncHandler.looper, msg);
    }
    return NULL;
}

NO_SANITIZE("cfi") void BrConnectedEventHandle(bool isClient, uint32_t value)
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
        CLOGE("create ConnBrRead failed");
        SoftBusFree(args);
        goto EXIT;
    }
    return;
EXIT:
    CLOGE("BrConnectedEventHandle EXIT");
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
        CLOGE("resume pending connection %u failed", connectionId);
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
        CLOGE("br OnPackResponse failed: not find device, connectionId: %u", connectionId);
        return;
    }
    connInfo->refCount += delta;
    int32_t myRefCount = connInfo->refCount;
    int32_t mySocketFd = connInfo->socketFd;
    int32_t sideType = connInfo->sideType;
    ReleaseConnectionRef(connInfo);

    CLOGI("br OnPackResponse: delta=%d, remoteRef=%d, myRef:%d, connectionId=%u",
        delta, peerRef, myRefCount, connectionId);
    if (peerRef > 0) {
        CLOGI("[remote device Ref is > 0, do not reply]");
        // resume connection when peer reference is larger than 0
        Resume(connectionId);
        return;
    }
    if (myRefCount <= 0) {
        CLOGI("br OnPackResponse local device ref <= 0, and remote ref <=0 close connection now");
        SetBrConnStateByConnId(connectionId, BR_CONNECTION_STATE_CLOSING);
        if (sideType == BR_SERVICE_TYPE) {
            ConnBrOnEvent(ADD_CONN_BR_SERVICE_DISCONNECTED_MSG, mySocketFd, mySocketFd);
        } else {
            ConnBrOnEvent(ADD_CONN_BR_CLIENT_DISCONNECTED_MSG, mySocketFd, mySocketFd);
        }
        return;
    }
    int32_t outLen = INVALID_LENGTH;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_RESPONSE, connectionId, delta, myRefCount, &outLen);
    if (buf == NULL) {
        return;
    }
    (void)PostBytesInner(connectionId, METHOD_NOTIFY_RESPONSE, buf, outLen);
}

static int32_t OnAck(uint32_t connectionId, uint32_t localWindows, uint64_t remoteSeq)
{
    int32_t dataLen = 0;
    CLOGI("send ack seq: %" PRIu64 " respone", remoteSeq);
    char *buf = BrPackRequestOrResponse(METHOD_ACK_RESPONSE, connectionId, (int32_t)localWindows, remoteSeq, &dataLen);
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
    int64_t peerConnectionId = 0;

    if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod)) {
        return;
    }

    if (!GetJsonObjectNumber64Item(data, KEY_TRACE_IDENTIFIER, &peerConnectionId)) {
        CLOGW("parse br connection binding relation failed, maybe it is old version, method: %d", keyMethod);
    } else {
        CLOGI("br connection binding relation, local: %u, peer: %d", connectionId, peerConnectionId);
    }

    if (keyMethod == METHOD_NOTIFY_REQUEST) {
        if (!GetJsonObjectSignedNumberItem(data, KEY_DELTA, &keyDelta) ||
            !GetJsonObjectSignedNumberItem(data, KEY_REFERENCE_NUM, &keyReferenceNum)) {
            CLOGI("REQUEST fail");
            return;
        }
        OnPackResponse(keyDelta, keyReferenceNum, connectionId);
    } else if (keyMethod == METHOD_NOTIFY_RESPONSE) {
        if (!GetJsonObjectSignedNumberItem(data, KEY_REFERENCE_NUM, &keyReferenceNum)) {
            CLOGI("RESPONSE fail");
            return;
        }
        CLOGI("br NOTIFY_RESPONSE, connectionId:%u, remote ref:%d", connectionId, keyReferenceNum);
        SetBrConnStateByConnId(connectionId, BR_CONNECTION_STATE_CONNECTED);
    } else if (keyMethod == METHOD_NOTIFY_ACK) {
        int32_t remoteWindows;
        int64_t remoteSeq;
        if (!GetJsonObjectSignedNumberItem(data, KEY_WINDOWS, &remoteWindows) ||
            !GetJsonObjectNumber64Item(data, KEY_ACK_SEQ_NUM, &remoteSeq)) {
            CLOGI("ACK REQUEST fail");
            return;
        }
        CLOGI("recv ACK REQUEST(%u) remote seq: %" PRIu64 ", windows: %d",
            connectionId, remoteSeq, remoteWindows);
        OnAck(connectionId, GetLocalWindowsByConnId(connectionId), (uint64_t)remoteSeq);
    } else if (keyMethod == METHOD_ACK_RESPONSE) {
        int32_t remoteWindows;
        int64_t remoteSeq;
        if (!GetJsonObjectSignedNumberItem(data, KEY_WINDOWS, &remoteWindows) ||
            !GetJsonObjectNumber64Item(data, KEY_ACK_SEQ_NUM, &remoteSeq)) {
            CLOGI("ACK RESPONSE fail");
            return;
        }
        CLOGI("recv ACK RESPONSE(%u) remote seq: %" PRId64 ", windows: %d",
            connectionId, remoteSeq, remoteWindows);
        if (SetBrPendingPacket(connectionId, (uint64_t)remoteSeq, NULL) != SOFTBUS_OK) {
            CLOGI("SetBrPendingPacket(%u) failed seq: %" PRId64,
                connectionId, remoteSeq);
        }
    }
}

NO_SANITIZE("cfi") static void BrRecvDataHandle(uint32_t connectionId, const char *buf, int32_t len)
{
    if (len - (int32_t)sizeof(ConnPktHead) <= 0) {
        CLOGE("br recv data illegal data size: %d", len);
        return;
    }
    ConnPktHead *head = (ConnPktHead *)buf;
    CLOGI("BrRecvDataHandle module: %d", head->module);
    if (head->module == MODULE_CONNECTION) {
        cJSON *data = NULL;
        data = cJSON_ParseWithLength(buf + sizeof(ConnPktHead), len - (int32_t)sizeof(ConnPktHead));
        if (data == NULL) {
            CLOGE("br recv data invalid");
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

NO_SANITIZE("cfi") static void BrConnMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    CLOGI("br conn loop process msg type %d", msg->what);
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
        CLOGE("BrConnLooperInit failed");
        return SOFTBUS_ERR;
    }
    g_brAsyncHandler.HandleMessage = BrConnMsgHandler;
    return SOFTBUS_OK;
}

static void StateChangedCallback(int32_t listenerId, int32_t status)
{
    CLOGI("StateChanged id: %d, status: %d", listenerId, status);

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

NO_SANITIZE("cfi") ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    CLOGI("[InitBR]");
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
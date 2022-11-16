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
#include "br_trans_manager.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "message_handler.h"
#include "securec.h"
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
#define SEND_WAIT_TIMEOUT 1000
#define DISCONN_DELAY_TIME 200
#define BR_ACCEPET_WAIT_TIME 1000
#define CONNECT_REF_INCRESE 1
#define CONNECT_REF_DECRESE (-1)
#define BR_SEND_THREAD_STACK 5120
#define BR_ACCECT_THREAD_STACK 4096
#define BR_RECE_THREAD_STACK 4096
#define MAX_BR_SIZE (40 * 1000)
#define MAX_BR_PEER_SIZE (3*1024)
#define INVALID_LENGTH (-1)
#define PRIORITY_HIGH 64
#define PRIORITY_MID 8
#define PRIORITY_LOW 1
#define PRIORITY_DAF 1

#define BR_SERVER_NAME_LEN 24
#define UUID "8ce255c0-200a-11e0-ac64-0800200c9a66"

static pthread_mutex_t g_brConnLock;
static int32_t g_brMaxConnCount;

static SoftBusHandler g_brAsyncHandler = {
    .name = "g_brAsyncHandler"
};

typedef struct {
    ListNode node;
    uint32_t connectionId;
    int32_t pid;
    int32_t priority;
    uint32_t dataLen;
    int32_t sendPos;
    char *data;
} SendItemStruct;

typedef struct {
    ListNode node;
    int32_t pid;
    int32_t itemCount;
} DataPidQueueStruct;

typedef struct {
    ListNode sendList;
    ListNode pidList;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    SoftBusHandler *handler;
} DataQueueStruct;

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
    .CheckActiveConnection = BrCheckActiveConnection
};

static DataQueueStruct g_dataQueue;
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

static void PackRequest(int32_t delta, uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[PackRequest: delta=%d, connectionId=%u]", delta, connectionId);
    int32_t refCount = -1;
    int32_t state = SetRefCountByConnId(delta, &refCount, connectionId);
    if (state != BR_CONNECTION_STATE_CONNECTED) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "Br Not Connected!");
        return;
    }
    int32_t dataLen = 0;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_REQUEST, delta, refCount, &dataLen);
    if (buf != NULL) {
        (void)PostBytes(connectionId, buf, dataLen, 0, 0);
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
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "sppDriver connect start.");
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
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "sppDriver connect failed");
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
            ListDelete(&requestInfo->node);
            SoftBusFree(requestInfo);
        }
    }
}

static int32_t ClientOnBrConnect(int32_t connId)
{
    int32_t socketFd = -1;
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
    if (strcpy_s(connectionInfo.info.brInfo.brMac, BT_MAC_LEN, mac) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "NotifyServerConn scpy error");
        return SOFTBUS_ERR;
    }
    g_connectCallback->OnConnected(connectionId, &connectionInfo);
    return SOFTBUS_OK;
}

static void ClearDataPidByPid(int32_t pid)
{
    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_dataQueue.pidList) {
        DataPidQueueStruct *itemNode = LIST_ENTRY(item, DataPidQueueStruct, node);
        if (itemNode->pid == pid) {
            ListDelete(item);
            SoftBusFree(itemNode);
        }
    }
}

static void FreeSendItem(SendItemStruct *sendItem)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[FreeSendItem]");
    if (sendItem == NULL) {
        return;
    }
    if (sendItem->data != NULL) {
        SoftBusFree(sendItem->data);
    }
    SoftBusFree(sendItem);
}

static void ClearSendItemByConnId(uint32_t connectionId)
{
    if (pthread_mutex_lock(&g_dataQueue.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[ClearSendItemByConnId] mutex failed");
        return;
    }
    ListNode *sendItemNode = NULL;
    ListNode *nextItem = NULL;
    SendItemStruct *sendItem = NULL;
    LIST_FOR_EACH_SAFE(sendItemNode, nextItem, &g_dataQueue.sendList) {
        sendItem = LIST_ENTRY(sendItemNode, SendItemStruct, node);
        if (sendItem->connectionId == connectionId) {
            ClearDataPidByPid(sendItem->pid);
            ListDelete(sendItemNode);
            FreeSendItem(sendItem);
        }
    }
    (void)pthread_mutex_unlock(&g_dataQueue.lock);
}

static void BrDisconnect(int32_t socketFd, int32_t value)
{
    ListNode notifyList;
    ListInit(&notifyList);
    ConnectionInfo connectionInfo;
    int32_t sideType = BR_CLIENT_TYPE;
    int32_t perState = BR_CONNECTION_STATE_CLOSED;
    uint32_t connectionId = SetBrConnStateBySocket(socketFd, BR_CONNECTION_STATE_CLOSED, &perState);
    if (connectionId != 0) {
        (void)GetBrRequestListByConnId(connectionId, &notifyList, &connectionInfo, &sideType);
        ClearSendItemByConnId(connectionId);
        if (perState != BR_CONNECTION_STATE_CLOSED) {
            NotifyDisconnect(&notifyList, connectionId, connectionInfo, value, sideType);
            ReleaseConnectionRefByConnId(connectionId);
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

static void ConnectDeviceExit(const uint32_t connId, uint32_t requestId, const ConnectResult *result)
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
    if (strcpy_s(connectionInfo.info.brInfo.brMac, BT_MAC_LEN, connInfo->mac) != EOK) {
        ReleaseConnectionRef(connInfo);
        return;
    }
    ReleaseConnectionRef(connInfo);

    if (result->OnConnectSuccessed != NULL) {
        result->OnConnectSuccessed(requestId, connId, &connectionInfo);
    }

    (void)PackRequest(CONNECT_REF_INCRESE, connId);
}

static int32_t ConnectDeviceStateConnecting(const uint32_t connId, uint32_t requestId, const ConnectResult *result)
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

static int32_t ConnectDeviceFristTime(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ConnectDeviceFristTime]");
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
    if (strcpy_s(newConnInfo->mac, sizeof(newConnInfo->mac), option->info.brOption.brMac) != EOK) {
        ReleaseBrconnectionNode(newConnInfo);
        return SOFTBUS_ERR;
    }
    uint32_t connId = newConnInfo->connectionId;
    if (AddConnectionList(newConnInfo) != SOFTBUS_OK) {
        ReleaseBrconnectionNode(newConnInfo);
        return SOFTBUS_ERR;
    }

    if (ConnBrOnEvent(ADD_CONN_BR_CLIENT_CONNECTED_MSG, (int32_t)connId, (int32_t)connId) != SOFTBUS_OK) {
        ReleaseConnectionRef(newConnInfo);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[ConnectDevice]");
    if (HasDiffMacDeviceExit(option)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[has diff mac device]");
    }
    int32_t connId = -1;
    int32_t ret = SOFTBUS_OK;
    if (pthread_mutex_lock(&g_brConnLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock mutex failed");
        return SOFTBUS_ERR;
    }
    int32_t connState = GetBrConnStateByConnOption(option, &connId);
    if (connState == BR_CONNECTION_STATE_CONNECTED) {
        ConnectDeviceExit(connId, requestId, result);
    } else if (connState == BR_CONNECTION_STATE_CONNECTING) {
        ret = ConnectDeviceStateConnecting((uint32_t)connId, requestId, result);
    } else if (connState == BR_CONNECTION_STATE_CLOSING) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[BR_CONNECTION_STATE_CLOSING]");
        result->OnConnectFailed(requestId, 0);
        ret = SOFTBUS_ERR;
    } else if (connState == BR_CONNECTION_STATE_CLOSED) {
        int32_t connCount = GetBrConnectionCount();
        if (connCount == SOFTBUS_ERR || connCount > g_brMaxConnCount) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectDevice connCount: %d", connCount);
            result->OnConnectFailed(requestId, 0);
            ret = SOFTBUS_ERR;
        } else {
            ret = ConnectDeviceFristTime(option, requestId, result);
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

static int32_t GetPriority(int32_t flag)
{
    int priority;
    switch (flag) {
        case CONN_HIGH: {
            priority = PRIORITY_HIGH;
            break;
        }
        case CONN_MIDDLE: {
            priority = PRIORITY_MID;
            break;
        }
        case CONN_LOW: {
            priority = PRIORITY_LOW;
            break;
        }
        default:
            priority = PRIORITY_DAF;
            break;
    }
    return priority;
}

static int32_t CheckSendQueueLength(void)
{
    int totalSendNum = 0;
    ListNode *sendItemNode = NULL;
    if (pthread_mutex_lock(&g_dataQueue.lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CheckSendQueueLength mutex failed");
        return SOFTBUS_ERR;
    }
    LIST_FOR_EACH(sendItemNode, &g_dataQueue.sendList) {
        totalSendNum++;
    }
    (void)pthread_mutex_unlock(&g_dataQueue.lock);
    if (totalSendNum > g_brSendQueueMaxLen) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL!!!");
        return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
    }
    return SOFTBUS_OK;
}

static DataPidQueueStruct *GetPidQueue(int pid)
{
    ListNode *item = NULL;
    LIST_FOR_EACH(item, &g_dataQueue.pidList) {
        DataPidQueueStruct *itemNode = LIST_ENTRY(item, DataPidQueueStruct, node);
        if (itemNode->pid == pid) {
            return itemNode;
        }
    }

    DataPidQueueStruct *pidQueue = (DataPidQueueStruct *)SoftBusCalloc(sizeof(DataPidQueueStruct));
    if (pidQueue == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Creat New PidNode fail");
        return NULL;
    }

    ListInit(&pidQueue->node);
    pidQueue->pid = pid;
    ListTailInsert(&g_dataQueue.pidList, &pidQueue->node);
    return pidQueue;
}

static int32_t CreateNewSendItem(int pid, int flag, uint32_t connectionId, int len, const char *data)
{
    SendItemStruct *sendItem = (SendItemStruct *)SoftBusCalloc(sizeof(SendItemStruct));
    if (sendItem == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "PostBytes CreateNewSendItem fail");
        return SOFTBUS_ERR;
    }
    ListInit(&sendItem->node);
    sendItem->pid = pid;
    sendItem->priority = GetPriority(flag);
    sendItem->connectionId = connectionId;
    sendItem->dataLen = (uint32_t)len;
    sendItem->data = (char*)data;

    ListNode *item = NULL;
    ListNode *nextItem = NULL;
    SendItemStruct *sendItemInsert = NULL;
    int lastInsertFlag = false;
    LIST_FOR_EACH_SAFE(item, nextItem, &g_dataQueue.sendList) {
        sendItemInsert = LIST_ENTRY(item, SendItemStruct, node);
        if (sendItemInsert->pid == pid && sendItemInsert->priority < sendItem->priority) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem ListAdd");
            ListNode *sendItemNode = item->prev;
            ListAdd(sendItemNode, &sendItem->node);
            lastInsertFlag = true;
            break;
        }
    }
    if (lastInsertFlag != true) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "SendItem ListTailInsert");
        ListTailInsert(&g_dataQueue.sendList, &sendItem->node);
    }
    return SOFTBUS_OK;
}

static int32_t PostBytes(uint32_t connectionId, const char *data, int32_t len, int32_t pid, int32_t flag)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "PostBytes connectionId=%u,pid=%d,len=%d flag=%d", connectionId, pid, len, flag);
    if (CheckSendQueueLength() != SOFTBUS_OK) {
        SoftBusFree((void*)data);
        return SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL;
    }

    if (!IsBrDeviceReady(connectionId)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "connectionId(%u) device is not ready", connectionId);
        SoftBusFree((void*)data);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    (void)pthread_mutex_lock(&g_dataQueue.lock);
    DataPidQueueStruct *pidQueue = GetPidQueue(pid);
    if (pidQueue == NULL) {
        SoftBusFree((void*)data);
        (void)pthread_mutex_unlock(&g_dataQueue.lock);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    pidQueue->itemCount++;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PostBytes pidQueue count=%d", pidQueue->itemCount);
    if (CreateNewSendItem(pid, flag, connectionId, len, data) != SOFTBUS_OK) {
        SoftBusFree((void*)data);
        pidQueue->itemCount--;
        if (pidQueue->itemCount == 0) {
            ListDelete(&pidQueue->node);
            SoftBusFree(pidQueue);
        }
        (void)pthread_mutex_unlock(&g_dataQueue.lock);
        return SOFTBUS_BRCONNECTION_POSTBYTES_ERROR;
    }

    pthread_cond_broadcast(&g_dataQueue.cond);
    (void)pthread_mutex_unlock(&g_dataQueue.lock);
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice(uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDevice]");
    if (!IsExitConnectionById(connectionId)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[not find connectionId: %u]", connectionId);
        return SOFTBUS_BRCONNECTION_DISCONNECT_NOTFIND;
    }
    (void)PackRequest(CONNECT_REF_DECRESE, connectionId);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDevice over]");
    return SOFTBUS_OK;
}

static int32_t DisconnectDeviceNow(const ConnectOption *option)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[DisconnectDeviceNow]");
    if (option == NULL || option->type != CONNECT_BR) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "option check fail");
        return SOFTBUS_ERR;
    }
    int32_t socketFd = -1;
    int32_t sideType = -1;
    if (BrClosingByConnOption(option, &socketFd, &sideType) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!IsListEmpty(&g_dataQueue.sendList)) {
        SoftBusSleepMs(DISCONN_DELAY_TIME);
    }
    if (sideType == BR_SERVICE_TYPE) {
        return ConnBrOnEvent(ADD_CONN_BR_SERVICE_DISCONNECTED_MSG, socketFd, socketFd);
    } else {
        return ConnBrOnEvent(ADD_CONN_BR_CLIENT_DISCONNECTED_MSG, socketFd, socketFd);
    }
    return SOFTBUS_ERR;
}

static void GetTimeDelay(uint32_t delay, struct timespec *tv)
{
#define USECTONSEC 1000LL
    SoftBusSysTime now;
    (void)SoftBusGetTime(&now);
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + SEND_WAIT_TIMEOUT * USECTONSEC;
    tv->tv_sec = time / USECTONSEC / USECTONSEC;
    tv->tv_nsec = time % (USECTONSEC * USECTONSEC) * USECTONSEC;
}

void *SendHandlerLoop(void *arg)
{
    while (1) {
        if (pthread_mutex_lock(&g_dataQueue.lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[SendHandlerLoop] mutex failed");
            break;
        }
        if (IsListEmpty(&g_dataQueue.sendList)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br wait send cond start");
            struct timespec tv;
            GetTimeDelay(SEND_WAIT_TIMEOUT, &tv);
            (void)pthread_cond_timedwait(&g_dataQueue.cond, &g_dataQueue.lock, &tv);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "br wait send cond end");
            (void)pthread_mutex_unlock(&g_dataQueue.lock);
            continue;
        }
        ListNode *item = NULL;
        int32_t sendPid = -1;
        LIST_FOR_EACH(item, &g_dataQueue.pidList) {
            DataPidQueueStruct *itemNode = LIST_ENTRY(item, DataPidQueueStruct, node);
            ListDelete(item);
            itemNode->itemCount--;
            sendPid = itemNode->pid;
            if (itemNode->itemCount == 0) {
                SoftBusFree(itemNode);
            } else {
                ListTailInsert(&g_dataQueue.pidList, &itemNode->node);
            }
            break;
        }
        ListNode *sendItemNode = NULL;
        SendItemStruct *sendItem = NULL;
        LIST_FOR_EACH(sendItemNode, &g_dataQueue.sendList) {
            SendItemStruct *tmpSendItem = LIST_ENTRY(sendItemNode, SendItemStruct, node);
            if (tmpSendItem->pid == sendPid) {
                ListDelete(sendItemNode);
                sendItem = tmpSendItem;
                break;
            }
        }
        (void)pthread_mutex_unlock(&g_dataQueue.lock);
        if (sendItem == NULL) {
            continue;
        }
        if (BrTransSend(sendItem->connectionId, g_sppDriver, g_brSendPeerLen, sendItem->data, sendItem->dataLen)
            != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BrTransSend fail");
        }
        FreeSendItem(sendItem);
    }
    return NULL;
}

static int32_t InitDataQueue(void)
{
    ListInit(&g_dataQueue.sendList);
    ListInit(&g_dataQueue.pidList);
    pthread_mutex_init(&g_dataQueue.lock, NULL);
    pthread_cond_init(&g_dataQueue.cond, NULL);

    pthread_t tid;
    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    pthread_attr_setstacksize(&threadAttr, BR_SEND_THREAD_STACK);
    if (pthread_create(&tid, &threadAttr, SendHandlerLoop, NULL) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "create DeathProcTask failed");
        pthread_attr_destroy(&threadAttr);
        return SOFTBUS_ERR;
    }

    pthread_attr_destroy(&threadAttr);
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
    pthread_attr_setstacksize(&threadAttr, BR_ACCECT_THREAD_STACK);
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

    if (socketFd == -1) {
        socketFd = ClientOnBrConnect(connId);
        if (socketFd == -1) {
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
    int32_t socketFd = -1;
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

static void OnPackResponse(int32_t delta, int32_t peerRef, uint32_t connectionId)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "[OnPackResponse: delta=%d, RemoteRef=%d, connectionIds=%u", delta, peerRef, connectionId);
    BrConnectionInfo *connInfo = GetConnectionRef(connectionId);
    if (connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "[OnPackResponse] not find device");
        return;
    }
    connInfo->refCount += delta;
    int32_t myRefCount = connInfo->refCount;
    int32_t mySocketFd = connInfo->socketFd;
    int32_t sideType = connInfo->sideType;
    ReleaseConnectionRef(connInfo);

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[onPackRequest: myRefCount=%d]", myRefCount);
    if (peerRef > 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[remote device Ref is > 0, do not reply]");
        return;
    }
    if (myRefCount <= 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[local device Ref <= 0, close connection now]");
        SetBrConnStateByConnId(connectionId, BR_CONNECTION_STATE_CLOSING);
        if (sideType == BR_SERVICE_TYPE) {
            ConnBrOnEvent(ADD_CONN_BR_SERVICE_DISCONNECTED_MSG, mySocketFd, mySocketFd);
        } else {
            ConnBrOnEvent(ADD_CONN_BR_CLIENT_DISCONNECTED_MSG, mySocketFd, mySocketFd);
        }
        return;
    }
    int32_t outLen = -1;
    char *buf = BrPackRequestOrResponse(METHOD_NOTIFY_RESPONSE, delta, myRefCount, &outLen);
    if (buf == NULL) {
        return;
    }
    (void)PostBytes(connectionId, buf, outLen, 0, 0);
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
        if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod) ||
            !GetJsonObjectSignedNumberItem(data, KEY_DELTA, &keyDelta) ||
            !GetJsonObjectSignedNumberItem(data, KEY_REFERENCE_NUM, &keyReferenceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "REQUEST fail");
            return;
        }
        OnPackResponse(keyDelta, keyReferenceNum, connectionId);
    }
    if (keyMethod == METHOD_NOTIFY_RESPONSE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "NOTIFY_RESPONSE");
        if (!GetJsonObjectNumberItem(data, KEY_METHOD, &keyMethod) ||
            !GetJsonObjectSignedNumberItem(data, KEY_REFERENCE_NUM, &keyReferenceNum)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RESPONSE fail");
            return;
        }

        SetBrConnStateByConnId(connectionId, BR_CONNECTION_STATE_CONNECTED);
    }
}

static void BrRecvDataHandle(uint32_t connectionId, const char *buf, int32_t len)
{
    ConnPktHead *head = (ConnPktHead *)buf;
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "BrRecvDataHandle module: %d", head->module);
    if (head->module == MODULE_CONNECTION) {
        cJSON *data = NULL;
        data = cJSON_Parse((char *)(buf + sizeof(ConnPktHead)));
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

static void UpdateLocalBtMac(void)
{
    SoftBusBtAddr mac;
    if (SoftBusGetBtMacAddr(&mac) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Get bt mac addr fail");
        return;
    }
    char macStr[BT_MAC_LEN] = {0};
    if (ConvertBtMacToStr(macStr, sizeof(macStr), mac.addr, sizeof(mac.addr)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Convert bt mac to str fail");
        return;
    }
    if (LnnSetLocalStrInfo(STRING_KEY_BT_MAC, macStr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Set bt mac to local fail");
        return;
    }
}

static void StateChangedCallback(int32_t listenerId, int32_t status)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StateChanged id: %d, status: %d", listenerId, status);

    LocalListenerInfo info;
    info.type = CONNECT_BR;
    if (status == SOFTBUS_BR_STATE_TURN_ON) {
        g_brEnable = status;
        UpdateLocalBtMac();
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
    if (InitDataQueue() != SOFTBUS_OK) {
        return NULL;
    }
    if (BrConnLooperInit() != SOFTBUS_OK) {
        return NULL;
    }
    if (SppRegisterConnCallback() != SOFTBUS_OK) {
        DestroyLooper(g_brAsyncHandler.looper);
        return NULL;
    }
    pthread_mutex_init(&g_brConnLock, NULL);
    g_connectCallback = (ConnectCallback*)callback;
    return &g_brInterface;
}

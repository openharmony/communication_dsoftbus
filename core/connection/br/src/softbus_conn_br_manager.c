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

#include "softbus_conn_br_manager.h"

#include <securec.h>

#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_common.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "softbus_utils.h"

enum BrServerState {
    BR_STATE_AVAILABLE,
    BR_STATE_CONNECTING,
    BR_STATE_MAX,
};

enum BrMgrLooperMsg {
    MSG_NEXT_CMD,
    MSG_CONNECT_REQUEST,
    MSG_CONNECT_SUCCESS,
    MSG_CONNECT_TIMEOUT,
    MSG_CONNECT_FAIL,
    MSG_SERVER_ACCEPTED,
    MSG_DATA_RECEIVED,
    MSG_CONNECTION_EXECEPTION,
    MSG_CONNECTION_RESUME,
    MGR_DISCONNECT_REQUEST,
    MSG_UNPEND,
    MSG_RESET,
};

typedef struct {
    uint32_t connectionId;
    int32_t error;
} ErrorContext;

typedef struct {
    ListNode node;
    ConnBrPendInfo *pendInfo;
} BrPending;

typedef struct {
    SoftBusList *connections;
    ConnBrState *state;
    ListNode waitings;
    SoftBusList *pendings;
    ConnBrDevice *connecting;
} ConnBrManager;

typedef int32_t (*DeviceAction)(ConnBrDevice *device, const char *anomizeAddress);
static void TransitionToState(enum BrServerState target);
static void ReceivedControlData(ConnBrConnection *connection, const uint8_t *data, uint32_t dataLen);
static void BrManagerMsgHandler(SoftBusMessage *msg);
static int BrCompareManagerLooperEventFunc(const SoftBusMessage *msg, void *args);
static int32_t PendingDevice(ConnBrDevice *device, const char *anomizeAddress);
static int32_t BrPendConnection(const ConnectOption *option, uint32_t time);
static void ProcessAclCollisionException(ConnBrDevice *device, const char *anomizeAddress);
static void UnpendConnection(const ConnBrPendInfo *unpendInfo);

static ConnBrManager g_brManager = { 0 };
static ConnectCallback g_connectCallback = { 0 };
static SoftBusHandlerWrapper g_brManagerAsyncHandler = {
    .handler = {
        .name = (char *)"BrManagerAsyncHandler",
        .HandleMessage = BrManagerMsgHandler,
        // assign when initiation
        .looper = NULL,

    },
    .eventCompareFunc = BrCompareManagerLooperEventFunc,
};

void __attribute__((weak)) NipRecvDataFromBr(uint32_t connId, const char *buf, int32_t len)
{
    (void)connId;
    (void)buf;
}

void __attribute__((weak)) NipConnectDevice(uint32_t connId, const char *mac)
{
    (void)connId;
    (void)mac;
}

void __attribute__((weak)) NipDisconnectDevice(uint32_t connId)
{
    (void)connId;
}

static void DfxRecordBrConnectFail(uint32_t reqId, uint32_t pId, ConnBrDevice *device,
    const ConnectStatistics *statistics, int32_t reason)
{
    if (statistics == NULL) {
        CLOGE("statistics is null");
        return;
    }

    CLOGI("record br conn fail, connectTraceId=%u, reason=%d", statistics->connectTraceId, reason);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_FAIL, costTime, reason);
}

static void DfxRecordBrConnectSuccess(uint32_t pId, ConnBrConnection *connection, ConnectStatistics *statistics)
{
    if (statistics == NULL) {
        CLOGE("statistics is null");
        return;
    }

    CLOGI("record br conn success, connectTraceId=%u", statistics->connectTraceId);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_SUCC, costTime,
                            SOFTBUS_HISYSEVT_CONN_OK);
}

static int32_t NewDevice(ConnBrDevice **outDevice, const char *addr)
{
    ConnBrDevice *device = SoftBusCalloc(sizeof(ConnBrDevice));
    if (device == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&device->node);
    if (memcpy_s(device->addr, BT_MAC_LEN, addr, BT_MAC_LEN) != EOK) {
        SoftBusFree(device);
        return SOFTBUS_MEM_ERR;
    }
    device->state = BR_DEVICE_STATE_INIT;
    ListInit(&device->requests);
    *outDevice = device;
    return SOFTBUS_OK;
}

static void FreeDevice(ConnBrDevice *device)
{
    ConnBrRequest *it = NULL;
    ConnBrRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &device->requests, ConnBrRequest, node) {
        ListDelete(&it->node);
        SoftBusFree(it);
    }
    ListDelete(&device->node);
    SoftBusFree(device);
}

static int32_t NewRequest(ConnBrRequest **outRequest, uint32_t requestId, ConnectStatistics statistics,
    const ConnectResult *result)
{
    ConnBrRequest *request = SoftBusCalloc(sizeof(ConnBrRequest));
    if (request == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&request->node);
    request->requestId = requestId;
    request->result = *result;
    request->statistics = statistics;

    *outRequest = request;
    return SOFTBUS_OK;
}

static int32_t Convert2ConnectionInfo(ConnBrConnection *connection, ConnectionInfo *info)
{
    info->isAvailable = connection->state == BR_CONNECTION_STATE_CONNECTED ? 1 : 0;
    info->isServer = connection->side == CONN_SIDE_SERVER ? 1 : 0;
    info->type = CONNECT_BR;
    if (strcpy_s(info->brInfo.brMac, BT_MAC_LEN, connection->addr) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConvertCtxToDevice(ConnBrDevice **outDevice, const ConnBrConnectRequestContext *ctx)
{
    ConnBrRequest *request = NULL;
    int32_t status = NewRequest(&request, ctx->requestId, ctx->statistics, &ctx->result);
    if (status != SOFTBUS_OK) {
        return status;
    }
    ConnBrDevice *device = NULL;
    status = NewDevice(&device, ctx->addr);
    if (status != SOFTBUS_OK) {
        SoftBusFree(request);
        return status;
    }
    ListAdd(&device->requests, &request->node);
    *outDevice = device;
    return SOFTBUS_OK;
}

static char *NameAvailableState(void)
{
    return "available state";
}

static char *NameConnectingState(void)
{
    return "connecting state";
}

static void EnterAvailableState(void)
{
    CLOGI("br manager enter avaible state");
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
}

static void EnterConnectingState(void)
{
    CLOGI("br manager enter connecting state");
}

static void ExitAvailableState(void)
{
    CLOGI("br manager exit avaible state");
}

static void ExitConnectingState(void)
{
    CLOGI("br manager exit connecting state");
}

static void NotifyDeviceConnectResult(
    const ConnBrDevice *device, ConnBrConnection *connection, bool isReuse, int32_t reason)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);

    ConnBrRequest *it = NULL;
    if (connection == NULL) {
        LIST_FOR_EACH_ENTRY(it, &device->requests, ConnBrRequest, node) {
            CLOGI("br notify connect request %u failed, address=%s, reason=%d", it->requestId, anomizeAddress, reason);
            DfxRecordBrConnectFail(it->requestId, DEFAULT_PID, (ConnBrDevice *)device, &it->statistics, reason);
            it->result.OnConnectFailed(it->requestId, reason);
            CLOGD("br notify connect request %u failed done, address=%s, reason=%d", it->requestId, anomizeAddress,
                reason);
        }
        return;
    }

    if (reason == 0) {
        NipConnectDevice(connection->connectionId, connection->addr);
    } else {
        NipDisconnectDevice(connection->connectionId);
    }

    ConnectionInfo info = { 0 };
    int32_t status = Convert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION, convert br connection info failed, error=%d. It can not backoff now, just ahead.", status);
    }
    LIST_FOR_EACH_ENTRY(it, &device->requests, ConnBrRequest, node) {
        // not need sync reference count when establish connection, initial reference count is 1
        if (isReuse) {
            ConnBrUpdateConnectionRc(connection, 1);
        }
        isReuse = true;
        CLOGI("br notify connect request %u success, address=%s, connection=%u", it->requestId, anomizeAddress,
            connection->connectionId);
        it->statistics.reqId = it->requestId;
        DfxRecordBrConnectSuccess(DEFAULT_PID, connection, &it->statistics);
        it->result.OnConnectSuccessed(it->requestId, connection->connectionId, &info);
        CLOGD("br notify connect request %u success done, address=%s, connection=%u", it->requestId, anomizeAddress,
            connection->connectionId);
    }
}

static BrPending *GetBrPending(const char *addr)
{
    BrPending *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.pendings->list, BrPending, node) {
        if (StrCmpIgnoreCase(it->pendInfo->addr, addr) == 0) {
            return it;
        }
    }
    return NULL;
}

static void ProcessBleDisconnectedEvent(char *addr)
{
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&g_brManager.pendings->lock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! check pending failed: lock pendings failed");
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, addr, BT_MAC_LEN);
    BrPending *target = GetBrPending(addr);
    if (target == NULL) {
        CLOGD("address is not in pending list, no need to unpend, address=%s", anomizeAddress);
        SoftBusMutexUnlock(&g_brManager.pendings->lock);
        return;
    }
    ConnBrPendInfo *info = SoftBusCalloc(sizeof(ConnBrPendInfo));
    if (info == NULL || strcpy_s(info->addr, BT_MAC_LEN, addr) != EOK) {
        CLOGE("copy addr failed, address=%s", anomizeAddress);
        SoftBusFree(info);
        SoftBusMutexUnlock(&g_brManager.pendings->lock);
        return;
    }
    uint64_t now = SoftBusGetSysTimeMs();
    if (target->pendInfo->firstStartTimestamp + target->pendInfo->firstDuration < now) {
        CLOGD("unpend address=%s", anomizeAddress);
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, info, 0);
    } else {
        CLOGD("do not unpend address=%s", anomizeAddress);
        SoftBusFree(info);
    }
    SoftBusMutexUnlock(&g_brManager.pendings->lock);
}

static void OnAclStateChanged(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState, int32_t hciReason)
{
    CONN_CHECK_AND_RETURN_LOG(addr != NULL, "invalid parameter: addr is NULL");
    char copyMac[BT_MAC_LEN] = { 0 };
    int32_t status = ConvertBtMacToStr(copyMac, BT_MAC_LEN, addr->addr, sizeof(addr->addr));
    if (status != SOFTBUS_OK) {
        CLOGE("convert bt mac to str fail, error=%d", status);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, copyMac, BT_MAC_LEN);
    CLOGD("address=%s, aclState=%d, hciReason=%d", anomizeAddress, aclState, hciReason);
    switch (aclState) {
        case SOFTBUS_ACL_STATE_LE_DISCONNECTED:
            ProcessBleDisconnectedEvent(copyMac);
            break;
        default:
            break;
    }
}

static void PendingIfBleSameAddress(const char *addr)
{
    uint32_t connectionId = 0;
    do {
        ConnBleConnection *bleConnection = ConnBleGetConnectionByAddr(addr, CONN_SIDE_ANY, BLE_GATT);
        CONN_CHECK_AND_RETURN_LOG(bleConnection != NULL, "can not get ble connection, no need to pend BR connection");
        connectionId = bleConnection->connectionId;
        ConnBleReturnConnection(&bleConnection);
    } while (false);
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, addr, BT_MAC_LEN);
    ConnectOption options = { 0 };
    options.type = CONNECT_BR;
    if (strcpy_s(options.brOption.brMac, BT_MAC_LEN, addr) != EOK) {
        CLOGE("copy br mac fail, address = %s", anomizeAddress);
        return;
    }
    int32_t status = BrPendConnection(&options, BR_WAIT_BLE_DISCONNECTED_PEND_MILLIS);
    if (status != SOFTBUS_OK) {
        CLOGE("br pend connection failed, address=%s, error=%d", anomizeAddress, status);
        return;
    }
    CLOGI("there is a ble connection connected with the same address, pending br connection, address=%s, ble "
          "connection id=%u",
        anomizeAddress, connectionId);
    return;
}

static int32_t ConnectDeviceDirectly(ConnBrDevice *device, const char *anomizeAddress)
{
    CLOGI("br manager start schedule connect request, request address=%s", anomizeAddress);
    int32_t status = SOFTBUS_OK;
    ConnBrConnection *connection = ConnBrCreateConnection(device->addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    if (connection == NULL) {
        return SOFTBUS_CONN_BR_INTERNAL_ERR;
    }
    char *address = NULL;
    do {
        address = (char *)SoftBusCalloc(BT_MAC_LEN);
        if (address == NULL || strcpy_s(address, BT_MAC_LEN, device->addr) != EOK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! copy br address for connect timeout event failed, request address=%s",
                anomizeAddress);
            status = SOFTBUS_MEM_ERR;
            break;
        }

        status = ConnBrSaveConnection(connection);
        if (status != SOFTBUS_OK) {
            break;
        }
        status = ConnBrConnect(connection);
        if (status != SOFTBUS_OK) {
            break;
        }
        g_brManager.connecting = device;
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECT_TIMEOUT, connection->connectionId, 0, address,
            BR_CONNECT_TIMEOUT_MILLIS);
        TransitionToState(BR_STATE_CONNECTING);
    } while (false);

    if (status != SOFTBUS_OK) {
        ConnBrRemoveConnection(connection);
        SoftBusFree(address);
    }
    ConnBrReturnConnection(&connection);
    return status;
}

static int32_t PendingDevice(ConnBrDevice *device, const char *anomizeAddress)
{
    CLOGI("br manager pend connect request, request address=%s, device state=%d", anomizeAddress, device->state);
    ConnBrDevice *connectingDevice = g_brManager.connecting;
    char connectingAnomizeAddress[BT_MAC_LEN] = { 0 };
    if (g_brManager.connecting != NULL) {
        ConvertAnonymizeMacAddress(connectingAnomizeAddress, BT_MAC_LEN, connectingDevice->addr, BT_MAC_LEN);
    }

    ConnBrDevice *targetDevice = NULL;
    if (g_brManager.connecting != NULL && StrCmpIgnoreCase(g_brManager.connecting->addr, device->addr) == 0) {
        targetDevice = g_brManager.connecting;
    } else {
        ConnBrDevice *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &g_brManager.waitings, ConnBrDevice, node) {
            if (StrCmpIgnoreCase(it->addr, device->addr) == 0) {
                targetDevice = it;
                break;
            }
        }
    }
    CLOGI("pengding current br connect request, request address=%s, connecting address=%s", anomizeAddress,
        connectingAnomizeAddress);
    if (targetDevice == NULL) {
        ListTailInsert(&g_brManager.waitings, &device->node);
        return SOFTBUS_OK;
    }

    ConnBrRequest *requestIt = NULL;
    ConnBrRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestIt, requestNext, &device->requests, ConnBrRequest, node) {
        ListDelete(&requestIt->node);
        ListAdd(&targetDevice->requests, &requestIt->node);
    }
    FreeDevice(device);
    return SOFTBUS_OK;
}

static bool BrReuseConnection(ConnBrDevice *device, ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, false,
        "ATTENTION UNEXPECTED ERROR! br reuse connection failed: try to lock failed, connection id=%u",
        connection->connectionId);
    enum ConnBrConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (state != BR_CONNECTION_STATE_CONNECTED) {
        return false;
    }
    NotifyDeviceConnectResult(device, connection, true, 0);
    return true;
}

static bool CheckPending(const char *addr)
{
    CONN_CHECK_AND_RETURN_RET_LOG(SoftBusMutexLock(&g_brManager.pendings->lock) == SOFTBUS_OK, false,
        "ATTENTION UNEXPECTED ERROR! check pending failed: lock pendings failed");
    bool pending = false;
    BrPending *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.pendings->list, BrPending, node) {
        if (StrCmpIgnoreCase(it->pendInfo->addr, addr) == 0) {
            pending = true;
            break;
        }
    }
    SoftBusMutexUnlock(&g_brManager.pendings->lock);
    return pending;
}

static void AttempReuseConnect(ConnBrDevice *device, DeviceAction actionIfAbsent)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);

    ConnBrConnection *clientConnection = ConnBrGetConnectionByAddr(device->addr, CONN_SIDE_CLIENT);
    ConnBrConnection *serverConnection = ConnBrGetConnectionByAddr(device->addr, CONN_SIDE_SERVER);
    if (clientConnection == NULL && serverConnection == NULL) {
        PendingIfBleSameAddress(device->addr);
        if (CheckPending(device->addr)) {
            device->state = BR_DEVICE_STATE_PENDING;
            PendingDevice(device, anomizeAddress);
            return;
        }
        device->state = BR_DEVICE_STATE_WAIT_SCHEDULE;
        int32_t status = actionIfAbsent(device, anomizeAddress);
        if (status != SOFTBUS_OK) {
            NotifyDeviceConnectResult(device, NULL, false, status);
            FreeDevice(device);
        }
        return;
    }
    do {
        if (clientConnection != NULL && BrReuseConnection(device, clientConnection)) {
            FreeDevice(device);
            CLOGI("br connect request reuse by client connection done, address=%s, connection id=%u", anomizeAddress,
                clientConnection->connectionId);
            break;
        }
        if (serverConnection != NULL && BrReuseConnection(device, serverConnection)) {
            FreeDevice(device);
            CLOGI("br connect request reuse by server connection done, address=%s, connection id=%u", anomizeAddress,
                serverConnection->connectionId);
            break;
        }
        device->state = BR_DEVICE_STATE_WAIT_EVENT;
        PendingDevice(device, anomizeAddress);
    } while (false);

    if (clientConnection != NULL) {
        ConnBrReturnConnection(&clientConnection);
    }
    if (serverConnection != NULL) {
        ConnBrReturnConnection(&serverConnection);
    }
}

static void ConnectRequestOnAvailableState(const ConnBrConnectRequestContext *ctx)
{
    ConnBrDevice *device = NULL;
    int32_t status = ConvertCtxToDevice(&device, ctx);
    if (status != SOFTBUS_OK) {
        CLOGE("convert br connect request failed, request id=%u, error=%d", ctx->requestId, status);
        DfxRecordBrConnectFail(ctx->requestId, DEFAULT_PID, device, &ctx->statistics, status);
        ctx->result.OnConnectFailed(ctx->requestId, status);
        return;
    }
    AttempReuseConnect(device, ConnectDeviceDirectly);
}

static void ConnectRequestOnConnectingState(const ConnBrConnectRequestContext *ctx)
{
    ConnBrDevice *device = NULL;
    int32_t status = ConvertCtxToDevice(&device, ctx);
    if (status != SOFTBUS_OK) {
        CLOGE("convert br connect request failed, request id=%u, error=%d", ctx->requestId, status);
        DfxRecordBrConnectFail(ctx->requestId, DEFAULT_PID, device, &ctx->statistics, status);
        ctx->result.OnConnectFailed(ctx->requestId, status);
        return;
    }
    AttempReuseConnect(device, PendingDevice);
}

static void HandlePendingRequestOnAvailableState(void)
{
    ConnBrDevice *target = NULL;
    ConnBrDevice *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.waitings, ConnBrDevice, node) {
        if (it->state == BR_DEVICE_STATE_WAIT_SCHEDULE) {
            target = it;
            break;
        }
    }
    if (target == NULL) {
        return;
    }
    ListDelete(&target->node);
    AttempReuseConnect(target, ConnectDeviceDirectly);
}

static void ServerAccepted(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection == NULL) {
        CLOGE("ATTENTION, can not get br connection %u, is it removed? ", connectionId);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CLOGI("br server accept a new connection, connection id=%u, peer address=%s", connectionId, anomizeAddress);

    ConnectionInfo info = { 0 };
    int32_t status = Convert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION, convert connection info failed, error=%d. It can not backoff now, just ahead.", status);
    }
    g_connectCallback.OnConnected(connectionId, &info);
    ConnBrPendInfo *pendInfo = SoftBusCalloc(sizeof(ConnBrPendInfo));
    if (pendInfo == NULL || strcpy_s(pendInfo->addr, BT_MAC_LEN, connection->addr) != EOK) {
        CLOGE("copy addr failed, address=%s", anomizeAddress);
        SoftBusFree(pendInfo);
        return;
    }
    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendInfo);
    UnpendConnection(pendInfo);

    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice != NULL && StrCmpIgnoreCase(connectingDevice->addr, connection->addr) == 0) {
        CLOGW("ATTENTION, both ends request establish connection at the same time, connection id=%u, it will reused "
              "after connect failed, peer address=%s",
            connectionId, anomizeAddress);
        ConnBrReturnConnection(&connection);
        return;
    }

    ConnBrDevice *it = NULL;
    ConnBrDevice *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_brManager.waitings, ConnBrDevice, node) {
        if (StrCmpIgnoreCase(it->addr, connection->addr) == 0 && BrReuseConnection(it, connection)) {
            ListDelete(&it->node);
            FreeDevice(it);
        }
    }
    ConnBrReturnConnection(&connection);
}

static void ClientConnected(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection == NULL) {
        CLOGE("ATTENTION, can not get br connection %u, is it removed? ", connectionId);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, connection->addr) != 0) {
        CLOGE("ATTENTION, br receive an unexpect client connected event as there is no connecting device, "
              "is it connected after timeout? connection id=%u, address=%d",
            connectionId, anomizeAddress);
        ConnBrUpdateConnectionRc(connection, -1);
        ConnBrReturnConnection(&connection);
        return;
    }
    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_CONNECT_TIMEOUT, connectionId, 0, NULL);
    CLOGI("br client connect success, client id=%d, address=%s", connectionId, anomizeAddress);

    NotifyDeviceConnectResult(connectingDevice, connection, false, 0);
    FreeDevice(connectingDevice);
    g_brManager.connecting = NULL;
    TransitionToState(BR_STATE_AVAILABLE);
    ConnBrReturnConnection(&connection);
}

static void ClientConnectFailed(uint32_t connectionId, int32_t error)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection == NULL) {
        CLOGE("ATTENTION, can not get br connection, is it removed? connection id=%u, error=%d", connectionId, error);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);

    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_CONNECT_TIMEOUT, connectionId, 0, NULL);
    CLOGI("br client connect failed, connection id=%u, address=%s, error=%d", connectionId, anomizeAddress, error);
    ConnBrDisconnectNow(connection);

    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, connection->addr) != 0) {
        CLOGE("ATTENTION, receive an unexpect client connect failed event as there is no connecting device, "
              "is it connected after timeout? connection id=%u, address=%s, error=%d",
            connectionId, anomizeAddress, error);
        ConnBrRemoveConnection(connection);
        ConnBrReturnConnection(&connection);
        return;
    }

    do {
        bool reuseServerConnection = false;
        ConnBrConnection *serverConnection = ConnBrGetConnectionByAddr(connection->addr, CONN_SIDE_SERVER);
        if (serverConnection != NULL) {
            if (BrReuseConnection(connectingDevice, serverConnection)) {
                CLOGI(
                    "br client connect failed, but there is a server connection connected, reuse it, connection id=%u, "
                    "address=%s",
                    serverConnection->connectionId, anomizeAddress);
                reuseServerConnection = true;
            }
            ConnBrReturnConnection(&serverConnection);
            if (reuseServerConnection) {
                break;
            }
        }
        if (error != SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL) {
            NotifyDeviceConnectResult(connectingDevice, NULL, false, error);
            break;
        }

        bool collision = false;
        BrUnderlayerStatus *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &connection->connectProcessStatus->list, BrUnderlayerStatus, node) {
            if (it->result == CONN_BR_CONNECT_UNDERLAYER_ERROR_CONNECTION_EXISTS ||
                it->result == CONN_BR_CONNECT_UNDERLAYER_ERROR_CONTROLLER_BUSY ||
                it->result == CONN_BR_CONNECT_UNDERLAYER_ERROR_CONN_SDP_BUSY) {
                collision = true;
                break;
            }
        }
        if (collision) {
            CLOGW("br client connect failed: acl connection collision, not notify failed, wait retry connection id=%u, "
                  "address=%s, result=%d",
                connectionId, anomizeAddress, it->result);
            // NOTICE: assign connecting NULL first to prevent recursively pending in connecting
            g_brManager.connecting = NULL;
            ProcessAclCollisionException(connectingDevice, anomizeAddress);
            break;
        }
        NotifyDeviceConnectResult(connectingDevice, NULL, false, error);
    } while (false);
    ConnBrRemoveConnection(connection);
    ConnBrReturnConnection(&connection);
    if (g_brManager.connecting != NULL) {
        FreeDevice(g_brManager.connecting);
        g_brManager.connecting = NULL;
    }
    TransitionToState(BR_STATE_AVAILABLE);
}

static void ClientConnectTimeoutOnConnectingState(uint32_t connectionId, const char *address)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);

    CLOGI("br connect timeout, address=%s, connection id=%u", anomizeAddress, connectionId);

    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection != NULL) {
        CLOGE("br connect timeout, address=%s, connection id=%u, interrupt connect progress", anomizeAddress,
            connection->connectionId);
        ConnBrDisconnectNow(connection);
        ConnBrRemoveConnection(connection);
        ConnBrReturnConnection(&connection);
    } else {
        CLOGE("ATTENTION, br connect timeout, address=%s, connection id=%u, connection object not exist, skip "
              "interrupt connect progress",
            anomizeAddress, connectionId);
    }
    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, address) != 0) {
        CLOGE("ATTENTION, br connect timeout, address=%s, connection id=%u, connecting device is null or address "
              "mismatch with this event",
            anomizeAddress, connectionId);
        return;
    }
    NotifyDeviceConnectResult(connectingDevice, NULL, false, SOFTBUS_CONN_BLE_CONNECT_TIMEOUT_ERR);
    FreeDevice(connectingDevice);
    g_brManager.connecting = NULL;
    TransitionToState(BR_STATE_AVAILABLE);
}

static void DataReceived(ConnBrDataReceivedContext *ctx)
{
    if (ctx->dataLen < sizeof(ConnPktHead)) {
        CLOGE("dataLength(=%{public}u) is less than header size, connId=%{public}u",
            ctx->dataLen, ctx->connectionId);
        SoftBusFree(ctx->data);
        return;
    }
    ConnPktHead *head = (ConnPktHead *)ctx->data;
    ConnBrConnection *connection = ConnBrGetConnectionById(ctx->connectionId);
    if (connection == NULL) {
        CLOGE("br dispatch receive data failed: connection not exist, connection id=%u, payload "
              "(Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            ctx->connectionId, ctx->dataLen, head->flag, head->module, head->seq);
        SoftBusFree(ctx->data);
        return;
    }
    CLOGI("br dispatch receive data, connection id=%u, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
        ctx->connectionId, ctx->dataLen, head->flag, head->module, head->seq);
    if (head->module == MODULE_CONNECTION) {
        ReceivedControlData(connection, ctx->data + ConnGetHeadSize(), ctx->dataLen - ConnGetHeadSize());
    } else if (head->module == MODULE_NIP_BR_CHANNEL && head->seq == (int64_t)BR_NIP_SEQ) {
        NipRecvDataFromBr(ctx->connectionId, (char *)ctx->data, ctx->dataLen);
    } else {
        g_connectCallback.OnDataReceived(
            ctx->connectionId, (ConnModule)head->module, head->seq, (char *)ctx->data, ctx->dataLen);
    }
    SoftBusFree(ctx->data);
    ctx->data = NULL;
    ConnBrReturnConnection(&connection);
}

static void ReceivedControlData(ConnBrConnection *connection, const uint8_t *data, uint32_t dataLen)
{
    cJSON *json = cJSON_ParseWithLength((const char *)data, dataLen);
    if (json == NULL) {
        CLOGE("br connection control message handle failed: parse json failed, connection id=%u",
            connection->connectionId);
        return;
    }

    int32_t method = 0;
    if (!GetJsonObjectNumberItem(json, KEY_METHOD, &method)) {
        CLOGE("br connection control message handle failed: parse method failed, connection id=%u",
            connection->connectionId);
        return;
    }
    CLOGI("br connection control message, connection id=%u, method=%d", connection->connectionId, method);
    int32_t status = SOFTBUS_OK;
    switch (method) {
        case BR_METHOD_NOTIFY_REQUEST:
            status = ConnBrOnReferenceRequest(connection, json);
            break;
        case BR_METHOD_NOTIFY_RESPONSE:
            status = ConnBrOnReferenceResponse(connection, json);
            break;
        case BR_METHOD_NOTIFY_ACK:
            status = ConnBrOnAckRequest(connection, json);
            break;
        case BR_METHOD_ACK_RESPONSE:
            status = ConnBrOnAckResponse(connection, json);
            break;
        default:
            CLOGE("br connection control message handle failed: UNSUPPORT method, connection id=%u, method=%d",
                connection->connectionId, method);
            break;
    }
    if (status != SOFTBUS_OK) {
        CLOGE("br connection control message handle failed: unexpected error, connection id=%u, method=%d, error=%d",
            connection->connectionId, method, status);
    }
    cJSON_Delete(json);
}

static void ConnectionException(uint32_t connectionId, int32_t error)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(connection != NULL,
        "br connection exception handle failed: connection not exist, connection id=%u", connectionId);

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CLOGI("br connection exception happend, release all resource, connection id=%u, address=%s, error=%d", connectionId,
        anomizeAddress, error);
    ConnBrDisconnectNow(connection);

    ConnBrDevice *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.waitings, ConnBrDevice, node) {
        if (StrCmpIgnoreCase(it->addr, connection->addr) == 0) {
            it->state = BR_DEVICE_STATE_WAIT_SCHEDULE;
            break;
        }
    }
    ConnectionInfo info = { 0 };
    int32_t status = Convert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION, convert br connection info failed, error=%d. It can not backoff now, just ahead.", status);
    }
    ConnBrRemoveConnection(connection);
    ConnBrReturnConnection(&connection);
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
    g_connectCallback.OnDisconnected(connectionId, &info);
}

static void ConnectionResume(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(
        connection != NULL, "br resume connection failed: connection not exist, connection id=%u", connectionId);
    ConnBrDevice *it = NULL;
    ConnBrDevice *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_brManager.waitings, ConnBrDevice, node) {
        if (StrCmpIgnoreCase(it->addr, connection->addr) == 0 && BrReuseConnection(it, connection)) {
            ListDelete(&it->node);
            FreeDevice(it);
        }
    }
    ConnBrReturnConnection(&connection);
}

static void DisconnectRequest(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOG(
        connection != NULL, "br disconnect request failed: connection is not exist, connection id=%u", connectionId);
    ConnBrUpdateConnectionRc(connection, -1);
    ConnBrReturnConnection(&connection);
}

static void UnpendConnection(const ConnBrPendInfo *unpendInfo)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, unpendInfo->addr, BT_MAC_LEN);

    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&g_brManager.pendings->lock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! unpend connection failed: lock prevenets failed, address=%s", anomizeAddress);
    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, (ConnBrPendInfo *)unpendInfo);
    do {
        BrPending *target = NULL;
        BrPending *pendingIt = NULL;
        LIST_FOR_EACH_ENTRY(pendingIt, &g_brManager.pendings->list, BrPending, node) {
            if (StrCmpIgnoreCase(pendingIt->pendInfo->addr, unpendInfo->addr) == 0) {
                target = pendingIt;
                break;
            }
        }
        if (target == NULL) {
            CLOGD("unpend connection, address is not pending, address=%s", anomizeAddress);
            break;
        }
        ListDelete(&target->node);
        SoftBusFree(target);
        g_brManager.pendings->cnt -= 1;
        ConnBrDevice *deviceIt = NULL;
        LIST_FOR_EACH_ENTRY(deviceIt, &g_brManager.waitings, ConnBrDevice, node) {
            if (StrCmpIgnoreCase(deviceIt->addr, unpendInfo->addr) == 0) {
                deviceIt->state = BR_DEVICE_STATE_WAIT_SCHEDULE;
                break;
            }
        }
        CLOGI("unpend connection success, address=%s", anomizeAddress);
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
    } while (false);
    SoftBusMutexUnlock(&g_brManager.pendings->lock);
}

static void Reset(int32_t reason)
{
    CLOGW("br manager start process RESET event, reason=%d", reason);
    if (g_brManager.connecting != NULL) {
        ConnBrConnection *connection = ConnBrGetConnectionByAddr(g_brManager.connecting->addr, CONN_SIDE_CLIENT);
        if (connection != NULL) {
            ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_CONNECT_TIMEOUT, connection->connectionId, 0, NULL);
            ConnBrReturnConnection(&connection);
        }
        NotifyDeviceConnectResult(g_brManager.connecting, NULL, false, SOFTBUS_CONN_BLUETOOTH_OFF);
        FreeDevice(g_brManager.connecting);
        g_brManager.connecting = NULL;
    }
    ConnBrDevice *deviceIt = NULL;
    ConnBrDevice *deviceNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(deviceIt, deviceNext, &g_brManager.waitings, ConnBrDevice, node) {
        ListDelete(&deviceIt->node);
        NotifyDeviceConnectResult(deviceIt, NULL, false, SOFTBUS_CONN_BLUETOOTH_OFF);
        FreeDevice(deviceIt);
    }

    int32_t status = SoftBusMutexLock(&g_brManager.pendings->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! br reset failed: lock pendings failed, error=%d", status);
        return;
    }
    BrPending *pendingIt = NULL;
    BrPending *pendingNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pendingIt, pendingNext, &g_brManager.pendings->list, BrPending, node) {
        ListDelete(&pendingIt->node);
        ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendingIt->pendInfo);
        SoftBusFree(pendingIt);
        g_brManager.pendings->cnt -= 1;
    }
    SoftBusMutexUnlock(&g_brManager.pendings->lock);

    status = SoftBusMutexLock(&g_brManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! br reset failed: try to lock connections failed, error=%d", status);
        return;
    }
    ConnBrConnection *connectionIt = NULL;
    LIST_FOR_EACH_ENTRY(connectionIt, &g_brManager.connections->list, ConnBrConnection, node) {
        // MUST NOT remove connection, connection close notify will cleanup
        ConnBrDisconnectNow(connectionIt);
    }
    SoftBusMutexUnlock(&g_brManager.connections->lock);
    TransitionToState(BR_STATE_AVAILABLE);
}

static void TransitionToState(enum BrServerState target)
{
    static ConnBrState statesTable[BR_STATE_MAX] = {
        [BR_STATE_AVAILABLE] = {
            .name = NameAvailableState,
            .enter = EnterAvailableState,
            .exit = ExitAvailableState,
            .connectRequest = ConnectRequestOnAvailableState,
            .handlePendingRequest = HandlePendingRequestOnAvailableState,
            .serverAccepted = ServerAccepted,
            .clientConnected = ClientConnected,
            .clientConnectFailed = ClientConnectFailed,
            .clientConnectTimeout = NULL,
            .dataReceived = DataReceived,
            .connectionException = ConnectionException,
            .connectionResume = ConnectionResume,
            .disconnectRequest = DisconnectRequest,
            .unpend = UnpendConnection,
            .reset = Reset,
        },
        [BR_STATE_CONNECTING] = {
            .name = NameConnectingState,
            .enter = EnterConnectingState,
            .exit = ExitConnectingState,
            .connectRequest = ConnectRequestOnConnectingState,
            .handlePendingRequest = NULL,
            .serverAccepted = ServerAccepted,
            .clientConnected = ClientConnected,
            .clientConnectFailed = ClientConnectFailed,
            .clientConnectTimeout = ClientConnectTimeoutOnConnectingState,
            .dataReceived = DataReceived,
            .connectionException = ConnectionException,
            .connectionResume = ConnectionResume,
            .disconnectRequest = DisconnectRequest,
            .unpend = UnpendConnection,
            .reset = Reset,
        },
    };

    if (g_brManager.state == statesTable + target) {
        return;
    }
    if (g_brManager.state != NULL) {
        g_brManager.state->exit();
    }
    g_brManager.state = statesTable + target;
    g_brManager.state->enter();
}

// memory management rules in BrManagerMsgHandler
// 1. DO NOT free memory in case of not contain nested dynamic memory;
// 2. MUST free nested dynamic memory which layer large than 1, msg->obj self layer is 1;
static void BrManagerMsgHandler(SoftBusMessage *msg)
{
    CONN_CHECK_AND_RETURN_LOG(msg != NULL, "msg is null");
    CLOGI("br manager looper recieve msg %d, current state is '%s'", msg->what, g_brManager.state->name());
    switch (msg->what) {
        case MSG_NEXT_CMD: {
            if (g_brManager.state->handlePendingRequest != NULL) {
                g_brManager.state->handlePendingRequest();
                return;
            }
            break;
        }
        case MSG_CONNECT_REQUEST: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            ConnBrConnectRequestContext *ctx = msg->obj;
            if (g_brManager.state->connectRequest != NULL) {
                g_brManager.state->connectRequest(ctx);
                return;
            }
            break;
        }
        case MSG_CONNECT_SUCCESS: {
            if (g_brManager.state->clientConnected != NULL) {
                g_brManager.state->clientConnected((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case MSG_CONNECT_TIMEOUT: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            if (g_brManager.state->clientConnectTimeout != NULL) {
                g_brManager.state->clientConnectTimeout((uint32_t)msg->arg1, (char *)msg->obj);
                return;
            }
            break;
        }
        case MSG_CONNECT_FAIL: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            ErrorContext *ctx = msg->obj;
            if (g_brManager.state->clientConnectFailed != NULL) {
                g_brManager.state->clientConnectFailed(ctx->connectionId, ctx->error);
                return;
            }
            break;
        }
        case MSG_SERVER_ACCEPTED: {
            if (g_brManager.state->serverAccepted != NULL) {
                g_brManager.state->serverAccepted((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case MSG_DATA_RECEIVED: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            ConnBrDataReceivedContext *ctx = msg->obj;
            if (g_brManager.state->dataReceived != NULL) {
                g_brManager.state->dataReceived(ctx);
                return;
            }
            SoftBusFree(ctx->data);
            break;
        }
        case MSG_CONNECTION_EXECEPTION: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            ErrorContext *ctx = msg->obj;
            if (g_brManager.state->connectionException != NULL) {
                g_brManager.state->connectionException(ctx->connectionId, ctx->error);
                return;
            }
            break;
        }
        case MSG_CONNECTION_RESUME: {
            if (g_brManager.state->connectionResume != NULL) {
                g_brManager.state->connectionResume((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case MGR_DISCONNECT_REQUEST: {
            if (g_brManager.state->disconnectRequest != NULL) {
                g_brManager.state->disconnectRequest((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case MSG_UNPEND: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            ConnBrPendInfo *info = msg->obj;
            if (g_brManager.state->unpend != NULL) {
                g_brManager.state->unpend(info);
                return;
            }
            break;
        }
        case MSG_RESET: {
            CONN_CHECK_AND_RETURN_LOG(msg->obj != NULL, "obj is null");
            ErrorContext *ctx = msg->obj;
            if (g_brManager.state->reset != NULL) {
                g_brManager.state->reset(ctx->error);
                return;
            }
            break;
        }
        default:
            CLOGE("ATTENTION, br manager looper receive unexpected msg, what=%d, just ignore, FIX it quickly.",
                msg->what);
            break;
    }
    CLOGW("br manager looper ignore handle %d message, current state is '%s'", msg->what, g_brManager.state->name());
}

static int BrCompareManagerLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case MSG_CONNECT_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        case MSG_UNPEND: {
            ConnBrPendInfo *msgInfo = msg->obj;
            ConnBrPendInfo *ctxInfo = ctx->obj;
            if (msgInfo == NULL || ctxInfo == NULL) {
                return COMPARE_SUCCESS;
            }
            if (StrCmpIgnoreCase(msgInfo->addr, ctxInfo->addr) == 0) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CLOGE("br compare manager looper event failed: there is compare context value not use, forgot implement? "
              "compare failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? %d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static void OnServerAccepted(uint32_t connectionId)
{
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_SERVER_ACCEPTED, connectionId, 0, NULL, 0);
}

static void OnClientConnected(uint32_t connectionId)
{
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECT_SUCCESS, connectionId, 0, NULL, 0);
}

static void OnClientConnectFailed(uint32_t connectionId, int32_t error)
{
    CLOGW("receive br client connect failed notify, connection id=%u, error=%d", connectionId, error);
    ErrorContext *ctx = SoftBusCalloc(sizeof(ErrorContext));
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL,
        "ATTENTION, br client connect failed handle failed: callo ctx failed: connection id=%u, error=%d", connectionId,
        error);
    ctx->connectionId = connectionId;
    ctx->error = error;
    if (ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECT_FAIL, connectionId, 0, ctx, 0) != SOFTBUS_OK) {
        SoftBusFree(ctx);
    }
}

static void OnDataReceived(uint32_t connectionId, uint8_t *data, uint32_t dataLen)
{
    ConnBrDataReceivedContext *ctx = SoftBusCalloc(sizeof(ConnBrDataReceivedContext));
    if (ctx == NULL) {
        CLOGE("ATTENTION UNEXPECTED ERROR! br on data received failed: calloc data received context failed, "
              "connection id=%u, data length=%u",
            connectionId, dataLen);
        SoftBusFree(data);
        return;
    }
    ctx->connectionId = connectionId;
    ctx->data = data;
    ctx->dataLen = dataLen;

    int32_t status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_DATA_RECEIVED, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION, br on data received failed: post msg to looper failed, connection id=%u, data length=%u",
            connectionId, dataLen);
        SoftBusFree(data);
        SoftBusFree(ctx);
    }
}

static void OnConnectionException(uint32_t connectionId, int32_t error)
{
    ErrorContext *ctx = SoftBusCalloc(sizeof(ErrorContext));
    CONN_CHECK_AND_RETURN_LOG(ctx != NULL,
        "ATTENTION, br connection exception handle failed: callo ctx failed: connection id=%u, error=%d", connectionId,
        error);
    ctx->connectionId = connectionId;
    ctx->error = error;
    if (ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECTION_EXECEPTION, connectionId, 0, ctx, 0) !=
        SOFTBUS_OK) {
        SoftBusFree(ctx);
    }
}

static void OnConnectionResume(uint32_t connectionId)
{
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECTION_RESUME, connectionId, 0, NULL, 0);
}

static void OnPostByteFinshed(
    uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error)
{
    CLOGI("br post bytes finished, connection id=%u, pid=%u, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64
          "), error=%d",
        connectionId, pid, len, flag, module, seq, error);
    if (error != SOFTBUS_OK) {
        ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
        if (connection == NULL) {
            // maybe fail reason is that connection not exist, so log level is warning
            CLOGW("br post bytes finished, send failed, connection not exist, connection id=%u", connectionId);
            return;
        }
        ConnBrDisconnectNow(connection);
        ConnBrReturnConnection(&connection);
    }
}

static uint32_t AllocateConnectionIdUnsafe()
{
    static uint16_t nextId = 0;

    uint32_t connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + (++nextId);
    ConnBrConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.connections->list, ConnBrConnection, node) {
        if (connectionId == it->connectionId) {
            return 0;
        }
    }
    return connectionId;
}

int32_t ConnBrSaveConnection(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        connection != NULL, SOFTBUS_INVALID_PARAM, "br save connection failed: invalid parameter, connection is null");

    int32_t status = SoftBusMutexLock(&g_brManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! br save connection failed: try to lock manager connections failed, error=%d",
            status);
        return status;
    }
    uint32_t connectionId = 0;
    do {
        connectionId = AllocateConnectionIdUnsafe();
    } while (connectionId == 0);

    connection->connectionId = connectionId;
    connection->objectRc += 1;
    ListAdd(&g_brManager.connections->list, &connection->node);
    (void)SoftBusMutexUnlock(&g_brManager.connections->lock);
    return SOFTBUS_OK;
}

void ConnBrRemoveConnection(ConnBrConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOG(connection != NULL, "br remove connection failed: invalid parameter, connection is null");
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&g_brManager.connections->lock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! br remove connection failed: try to lock manager connections failed, "
        "connection id=%u",
        connection->connectionId);

    ConnBrConnection *it = NULL;
    ConnBrConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.connections->list, ConnBrConnection, node) {
        if (it->connectionId == connection->connectionId) {
            target = it;
            break;
        }
    }
    if (target != NULL) {
        CLOGW("br remove connection, connection id=%u", connection->connectionId);
        ListDelete(&connection->node);
        ConnBrReturnConnection(&connection);
    } else {
        CLOGW("br remove connection, connection %u not exist in global connection list, call remove duplicate?",
            connection->connectionId);
    }
    (void)SoftBusMutexUnlock(&g_brManager.connections->lock);
}

ConnBrConnection *ConnBrGetConnectionByAddr(const char *addr, ConnSideType side)
{
    CONN_CHECK_AND_RETURN_RET_LOG(addr != NULL, NULL, "invalid parameter, addr is null");

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, addr, BT_MAC_LEN);

    int32_t status = SoftBusMutexLock(&g_brManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! br get connection by addr failed: try to lock manager connnections failed, "
              "addr=%s, error=%d",
            animizeAddress, status);
        return NULL;
    }

    ConnBrConnection *it = NULL;
    ConnBrConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.connections->list, ConnBrConnection, node) {
        if (StrCmpIgnoreCase(it->addr, addr) == 0 && (side == CONN_SIDE_ANY ? true : it->side == side)) {
            target = it;
        }
    }
    if (target != NULL) {
        status = SoftBusMutexLock(&target->lock);
        if (status != SOFTBUS_OK) {
            CLOGE(
                "ATTENTION UNEXPECTED ERROR! br get connection by addr failed: try to lock connection failed, error=%d",
                status);
            SoftBusMutexUnlock(&g_brManager.connections->lock);
            return NULL;
        }
        target->objectRc += 1;
        SoftBusMutexUnlock(&target->lock);
    }
    SoftBusMutexUnlock(&g_brManager.connections->lock);
    return target;
}

ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId)
{
    int32_t status = SoftBusMutexLock(&g_brManager.connections->lock);
    CONN_CHECK_AND_RETURN_RET_LOG(status == SOFTBUS_OK, NULL,
        "ATTENTION UNEXPECTED ERROR! br get connection by id failed: try to lock manager connnections failed, "
        "connection id=%u, error=%d",
        connectionId, status);

    ConnBrConnection *it = NULL;
    ConnBrConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.connections->list, ConnBrConnection, node) {
        if (it->connectionId == connectionId) {
            target = it;
            break;
        }
    }
    if (target != NULL) {
        status = SoftBusMutexLock(&target->lock);
        if (status != SOFTBUS_OK) {
            CLOGE("ATTENTION UNEXPECTED ERROR! br get connection by id failed: try to lock connection failed, "
                  "connection id=%u, error=%d",
                connectionId, status);
            SoftBusMutexUnlock(&g_brManager.connections->lock);
            return NULL;
        }
        target->objectRc += 1;
        SoftBusMutexUnlock(&target->lock);
    }
    SoftBusMutexUnlock(&g_brManager.connections->lock);
    return target;
}

void ConnBrReturnConnection(ConnBrConnection **connectionPtr)
{
    CONN_CHECK_AND_RETURN_LOG(
        connectionPtr != NULL, "br return connectiong failed: invalid param, connectionPtr is null");
    CONN_CHECK_AND_RETURN_LOG(
        *connectionPtr != NULL, "br return connectiong failed: invalid param, *connectionPtr is null, repeat return?");

    ConnBrConnection *connection = *connectionPtr;
    CONN_CHECK_AND_RETURN_LOG(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK,
        "ATTENTION UNEXPECTED ERROR! br return connectiong failed: try to lock failed, connection id=%u",
        connection->connectionId);
    connection->objectRc -= 1;
    int32_t objectRc = connection->objectRc;
    SoftBusMutexUnlock(&connection->lock);
    if (objectRc <= 0) {
        CLOGI("release br connection %u", connection->connectionId);
        ConnBrFreeConnection(connection);
    }
    *connectionPtr = NULL;
}

static int32_t BrConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    CONN_CHECK_AND_RETURN_RET_LOG(option != NULL, SOFTBUS_INVALID_PARAM,
        "br connect device failed: invaliad param, option is null, request id=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOG(option->type == CONNECT_BR, SOFTBUS_INVALID_PARAM,
        "br connect device failed: invaliad param, not br connect type, request id=%u, type=%d", requestId,
        option->type);
    CONN_CHECK_AND_RETURN_RET_LOG(result != NULL, SOFTBUS_INVALID_PARAM,
        "br connect device failed: invaliad param, result callback is null, request id=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOG(result->OnConnectSuccessed != NULL, SOFTBUS_INVALID_PARAM,
        "br connect device failed: invaliad param, result callback OnConnectSuccessed is null, request id=%u",
        requestId);
    CONN_CHECK_AND_RETURN_RET_LOG(result->OnConnectFailed != NULL, SOFTBUS_INVALID_PARAM,
        "br connect device failed: invaliad param, result callback OnConnectFailed is null, request id=%u", requestId);

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, option->brOption.brMac, BT_MAC_LEN);

    ConnBrConnectRequestContext *ctx = SoftBusCalloc(sizeof(ConnBrConnectRequestContext));
    CONN_CHECK_AND_RETURN_RET_LOG(ctx != NULL, SOFTBUS_MEM_ERR,
        "br connect device failed: calloc connect request context failed: request id=%u, address=%s", requestId,
        anomizeAddress);
    ctx->statistics.startTime = SoftBusGetSysTimeMs();
    ctx->statistics.connectTraceId = SoftbusGetConnectTraceId();
    ctx->requestId = requestId;
    if (strcpy_s(ctx->addr, BT_MAC_LEN, option->brOption.brMac) != EOK) {
        CLOGE(
            "br connect device failed: strcpy_s address failed, request id=%u, address=%s", requestId, anomizeAddress);
        SoftBusFree(ctx);
        return SOFTBUS_STRCPY_ERR;
    }
    ctx->result = *result;
    int32_t status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECT_REQUEST, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CLOGE("br connect device failed: post msg to state machine failed, request id=%u, address=%s, error=%d",
            requestId, anomizeAddress, status);
        SoftBusFree(ctx);
        return status;
    }
    CLOGI("br connect device, receive connect request, request id=%u, address=%s, connectTraceId=%u",
        requestId, anomizeAddress, ctx->statistics.connectTraceId);
    return SOFTBUS_OK;
}

static int32_t BrDisconnectDevice(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR,
        "br disconnect device failed: connection not exist, connection id=%u", connectionId);
    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    NipDisconnectDevice(connectionId);
    ConnBrReturnConnection(&connection);
    int32_t status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MGR_DISCONNECT_REQUEST, connectionId, 0, NULL, 0);
    CLOGI("br disconnect device, connection id=%u, address=%s, status=%d", connectionId, animizeAddress, status);
    return status;
}

static int32_t BrDisconnectDeviceNow(const ConnectOption *option)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        option != NULL, SOFTBUS_INVALID_PARAM, "br disconnect device now failed: invaliad param, option is null");
    CONN_CHECK_AND_RETURN_RET_LOG(option->type == CONNECT_BR, SOFTBUS_INVALID_PARAM,
        "br disconnect device now failed: invaliad param, not br type, type=%d", option->type);

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, option->brOption.brMac, BT_MAC_LEN);
    CLOGI("br disconnect device now, address=%s, side=%d", animizeAddress, option->brOption.sideType);

    ConnBrConnection *connection = ConnBrGetConnectionByAddr(option->brOption.brMac, option->brOption.sideType);
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR,
        "br disconnect device now failed: connection is not exist, address=%s, side=%d", animizeAddress,
        option->brOption.sideType);
    NipDisconnectDevice(connection->connectionId);
    ConnBrDisconnectNow(connection);
    ConnBrReturnConnection(&connection);
    return SOFTBUS_OK;
}

static int32_t BrGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        info != NULL, SOFTBUS_INVALID_PARAM, "br get connection info failed: invaliad param, info is null");
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR,
        "br get connection info failed: connection is not exist, connection id=%u", connectionId);

    int32_t status = Convert2ConnectionInfo(connection, info);
    ConnBrReturnConnection(&connection);
    return status;
}

static int32_t BrStartLocalListening(const LocalListenerInfo *info)
{
    (void)info;
    return ConnBrStartServer();
}

static int32_t BrStopLocalListening(const LocalListenerInfo *info)
{
    (void)info;
    return ConnBrStopServer();
}

static bool BrCheckActiveConnection(const ConnectOption *option)
{
    CONN_CHECK_AND_RETURN_RET_LOG(
        option != NULL, false, "br check active connection failed: invaliad param, option is null");
    CONN_CHECK_AND_RETURN_RET_LOG(option->type == CONNECT_BR, false,
        "br check active connection failed: invaliad param, not br type, type=%d", option->type);

    ConnBrConnection *connection = ConnBrGetConnectionByAddr(option->brOption.brMac, option->brOption.sideType);
    CONN_CHECK_AND_RETURN_RET_LOG(connection != NULL, false, "br check action connection: connection is not exist");
    bool isActive = (connection->state == BR_CONNECTION_STATE_CONNECTED);
    ConnBrReturnConnection(&connection);
    return isActive;
}

static void ProcessAclCollisionException(ConnBrDevice *device, const char *anomizeAddress)
{
    CLOGI("process acl collision exception, address=%s", anomizeAddress);
    ConnectOption option = { 0 };
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, device->addr) != EOK) {
        CLOGE("process acl collision exception, copy br mac fail, address=%s", anomizeAddress);
        return;
    }
    BrPendConnection(&option, BR_CONNECTION_ACL_CONNECT_COLLISION_MILLIS);
    device->state = BR_DEVICE_STATE_PENDING;
    PendingDevice(device, anomizeAddress);
}

static int32_t BrPendConnection(const ConnectOption *option, uint32_t time)
{
    CONN_CHECK_AND_RETURN_RET_LOG((option != NULL && time != 0 && time <= BR_CONNECTION_PEND_TIMEOUT_MAX_MILLIS),
        SOFTBUS_INVALID_PARAM, "br pend connection failed: invaliad param, option is null or pend time is 0");
    CONN_CHECK_AND_RETURN_RET_LOG(option->type == CONNECT_BR, SOFTBUS_INVALID_PARAM,
        "br pend connection failed: invalid param, not br type, type=%d", option->type);

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, option->brOption.brMac, BT_MAC_LEN);
    CLOGI("br pend connection, address=%s, side=%d", animizeAddress, option->brOption.sideType);

    int32_t status = SoftBusMutexLock(&g_brManager.pendings->lock);
    if (status != SOFTBUS_OK) {
        CLOGE("ATTENTION UNEXPECTED ERROR! br pend connection failed: lock pendings failed: error=%d", status);
        return SOFTBUS_LOCK_ERR;
    }
    do {
        BrPending *target = GetBrPending(option->brOption.brMac);
        ConnBrPendInfo *pendInfo = SoftBusCalloc(sizeof(ConnBrPendInfo));
        if (pendInfo == NULL || strcpy_s(pendInfo->addr, BT_MAC_LEN, option->brOption.brMac) != EOK) {
            CLOGE("calloc pend information or copy addr failed");
            SoftBusFree(pendInfo);
            break;
        }
        uint64_t now = SoftBusGetSysTimeMs();
        pendInfo->firstStartTimestamp = now;
        pendInfo->firstDuration = time;
        pendInfo->startTimestamp = now;
        pendInfo->duration = time;
        if (target != NULL) {
            CLOGD("br pend connection, address pending, refresh timeout only, address=%s", animizeAddress);
            if (target->pendInfo->startTimestamp + target->pendInfo->duration < now + time) {
                pendInfo->firstStartTimestamp = target->pendInfo->firstStartTimestamp;
                pendInfo->firstDuration = target->pendInfo->firstDuration;
                ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendInfo);
                target->pendInfo = pendInfo;
                ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendInfo, time);
            } else {
                SoftBusFree(pendInfo);
            }
            break;
        }

        BrPending *pending = SoftBusCalloc(sizeof(BrPending));
        if (pending == NULL) {
            CLOGE("ATTENTION UNEXPECTED ERROR! br pend connection failed: calloc pending object failed");
            status = SOFTBUS_MALLOC_ERR;
            break;
        }
        ListInit(&pending->node);
        pending->pendInfo = pendInfo;
        ListAdd(&g_brManager.pendings->list, &pending->node);
        g_brManager.pendings->cnt += 1;
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendInfo, time);
        CLOGI("br pend connection success, address=%s", animizeAddress);
    } while (false);
    SoftBusMutexUnlock(&g_brManager.pendings->lock);
    return status;
}

static int32_t BrInitLooper(void)
{
    g_brManagerAsyncHandler.handler.looper = CreateNewLooper("br_looper");
    if (g_brManagerAsyncHandler.handler.looper == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void DumpLocalBtMac(void)
{
    SoftBusBtAddr addr = { 0 };
    int32_t status = SoftBusGetBtMacAddr(&addr);
    if (status != SOFTBUS_OK) {
        CLOGE("SoftBusGetBtMacAddr failed, error=%d", status);
        return;
    }
    char myBtMac[BT_MAC_LEN] = { 0 };
    status = ConvertBtMacToStr(myBtMac, BT_MAC_LEN, addr.addr, sizeof(addr.addr));
    if (status != SOFTBUS_OK) {
        CLOGE("convert bt mac to str fail, error=%d", status);
        return;
    }
    char anomizeMyAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeMyAddress, BT_MAC_LEN, myBtMac, BT_MAC_LEN);
    CLOGI("local bt address is %s", anomizeMyAddress);
}

static void OnBtStateChanged(int listenerId, int state)
{
    (void)listenerId;
    int32_t status = SOFTBUS_OK;
    if (state == SOFTBUS_BR_STATE_TURN_ON) {
        DumpLocalBtMac();
        status = ConnBrStartServer();
        CLOGI("br manager receive bt on event, start server, status=%d", status);
        return;
    }

    if (state == SOFTBUS_BR_STATE_TURN_OFF) {
        status = ConnBrStopServer();
        CLOGI("br manager receive bt off event, stop server, status=%d", status);

        ErrorContext *ctx = SoftBusCalloc(sizeof(ErrorContext));
        if (ctx == NULL) {
            CLOGE("ATTENTION UNEXPECTED ERROR! br manager receive bt off event, send reset event failed: calloc ctx "
                  "object failed");
            return;
        }
        ctx->error = SOFTBUS_CONN_BLUETOOTH_OFF;
        status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_RESET, 0, 0, ctx, 0);
        if (status != SOFTBUS_OK) {
            CLOGE("ATTENTION! br manager receive bt off event, send reset event failed: post msg to looper failed");
            SoftBusFree(ctx);
        }
        return;
    }
}

static int32_t InitBrManager()
{
    SoftBusList *connections = CreateSoftBusList();
    SoftBusList *pendings = CreateSoftBusList();
    CONN_CHECK_AND_RETURN_RET_LOG(
        connections != NULL && pendings != NULL, SOFTBUS_ERR, "init br manager failed: create list failed");
    g_brManager.connections = connections;
    g_brManager.pendings = pendings;
    ListInit(&g_brManager.waitings);
    g_brManager.state = NULL;
    g_brManager.connecting = NULL;

    static SoftBusBtStateListener listener = {
        .OnBtAclStateChanged = OnAclStateChanged,
        .OnBtStateChanged = OnBtStateChanged,
    };
    int32_t listenerId = SoftBusAddBtStateListener(&listener);
    CONN_CHECK_AND_RETURN_RET_LOG(listenerId >= 0, SOFTBUS_ERR,
        "init br manager failed: add bluetooth state change listener failed, invalid listener id=%d", listenerId);
    TransitionToState(BR_STATE_AVAILABLE);
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOG(callback != NULL, NULL, "conn init br failed: invalid param, callback is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        callback->OnConnected != NULL, NULL, "conn init br failed: invalid param, callback OnConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        callback->OnDisconnected != NULL, NULL, "conn init br failed: invalid param, callback OnDisconnected is null");
    CONN_CHECK_AND_RETURN_RET_LOG(
        callback->OnDataReceived != NULL, NULL, "conn init br failed: invalid param, callback OnDataReceived is null");

    int32_t status = BrInitLooper();
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, NULL, "conn init br failed: init looper failed, error=%d", status);
    SppSocketDriver *sppDriver = InitSppSocketDriver();
    CONN_CHECK_AND_RETURN_RET_LOG(sppDriver != NULL, NULL, "conn init br failed: init spp socket driver failed");

    ConnBrEventListener connectionEventListener = {
        .onServerAccepted = OnServerAccepted,
        .onClientConnected = OnClientConnected,
        .onClientConnectFailed = OnClientConnectFailed,
        .onDataReceived = OnDataReceived,
        .onConnectionException = OnConnectionException,
        .onConnectionResume = OnConnectionResume,
    };
    status = ConnBrConnectionMuduleInit(g_brManagerAsyncHandler.handler.looper, sppDriver, &connectionEventListener);
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, NULL, "conn init br failed: init connection failed, error=%d ", status);

    ConnBrTransEventListener transEventListener = {
        .onPostByteFinshed = OnPostByteFinshed,
    };
    status = ConnBrTransMuduleInit(sppDriver, &transEventListener);
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, NULL, "conn init br failed: init trans failed, error=%d", status);

    status = InitBrManager();
    CONN_CHECK_AND_RETURN_RET_LOG(
        status == SOFTBUS_OK, NULL, "conn init br failed: init manager failed, error=%d", status);
    g_connectCallback = *callback;
    static ConnectFuncInterface connectFuncInterface = {
        .ConnectDevice = BrConnectDevice,
        .PostBytes = ConnBrPostBytes,
        .DisconnectDevice = BrDisconnectDevice,
        .DisconnectDeviceNow = BrDisconnectDeviceNow,
        .GetConnectionInfo = BrGetConnectionInfo,
        .StartLocalListening = BrStartLocalListening,
        .StopLocalListening = BrStopLocalListening,
        .CheckActiveConnection = BrCheckActiveConnection,
        .UpdateConnection = NULL,
        .PreventConnection = BrPendConnection,
    };
    CLOGI("conn init br successfully");
    return &connectFuncInterface;
}
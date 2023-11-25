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

#include "bus_center_decision_center.h"
#include "conn_log.h"
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
#include "softbus_utils.h"
#include "conn_event.h"

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
        CONN_LOGW(CONN_BR, "statistics is null");
        return;
    }

    CONN_LOGD(CONN_BR, "traceId=%u, reason=%d", statistics->connectTraceId, reason);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_FAIL, costTime, reason);
    ConnEventExtra extra = {
        .requestId = reqId,
        .linkType = CONNECT_BR,
        .costTime = costTime,
        .errcode = reason
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
}

static void DfxRecordBrConnectSuccess(uint32_t pId, ConnBrConnection *connection, ConnectStatistics *statistics)
{
    if (statistics == NULL) {
        CONN_LOGW(CONN_BR, "statistics is null");
        return;
    }

    CONN_LOGD(CONN_BR, "traceId=%u", statistics->connectTraceId);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, SOFTBUS_HISYSEVT_CONN_TYPE_BR, SOFTBUS_EVT_CONN_SUCC, costTime,
                            SOFTBUS_HISYSEVT_CONN_OK);
    ConnEventExtra extra = {
        .connectionId = connection->connectionId,
        .linkType = CONNECT_BR,
        .costTime = costTime,
        .result = EVENT_STAGE_RESULT_OK };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
}

static int32_t NewDevice(ConnBrDevice **outDevice, const char *addr)
{
    ConnBrDevice *device = (ConnBrDevice *)SoftBusCalloc(sizeof(ConnBrDevice));
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
    ConnBrRequest *request = (ConnBrRequest *)SoftBusCalloc(sizeof(ConnBrRequest));
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
    return (char *)("available state");
}

static char *NameConnectingState(void)
{
    return (char *)("connecting state");
}

static void EnterAvailableState(void)
{
    CONN_LOGD(CONN_BR, "br manager enter avaible state");
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
}

static void EnterConnectingState(void)
{
    CONN_LOGD(CONN_BR, "br manager enter connecting state");
}

static void ExitAvailableState(void)
{
    CONN_LOGD(CONN_BR, "br manager exit avaible state");
}

static void ExitConnectingState(void)
{
    CONN_LOGD(CONN_BR, "br manager exit connecting state");
}

static void NotifyDeviceConnectResult(
    const ConnBrDevice *device, ConnBrConnection *connection, bool isReuse, int32_t reason)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);

    ConnBrRequest *it = NULL;
    if (connection == NULL) {
        LIST_FOR_EACH_ENTRY(it, &device->requests, ConnBrRequest, node) {
            CONN_LOGD(CONN_BR, "br notify connect request %u failed, addr=%s, reason=%d", it->requestId,
                anomizeAddress, reason);
            DfxRecordBrConnectFail(it->requestId, DEFAULT_PID, (ConnBrDevice *)device, &it->statistics, reason);
            it->result.OnConnectFailed(it->requestId, reason);
            CONN_LOGD(CONN_BR, "br notify connect request %u failed done, addr=%s, reason=%d", it->requestId,
                anomizeAddress, reason);
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
        CONN_LOGE(CONN_BR, "convert br connection info failed, error=%d", status);
    }

    ConnectOption option;
    (void)memset_s(&option, sizeof(option), 0, sizeof(option));
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, info.brInfo.brMac) == SOFTBUS_OK) {
        LnnDCClearConnectException(&option);
    }

    LIST_FOR_EACH_ENTRY(it, &device->requests, ConnBrRequest, node) {
        // not need sync reference count when establish connection, initial reference count is 1
        if (isReuse) {
            ConnBrUpdateConnectionRc(connection, 1);
        }
        isReuse = true;
        CONN_LOGD(CONN_BR, "br notify connect request %u success, addr=%s, connection=%u",
            it->requestId, anomizeAddress, connection->connectionId);
        it->statistics.reqId = it->requestId;
        DfxRecordBrConnectSuccess(DEFAULT_PID, connection, &it->statistics);
        it->result.OnConnectSuccessed(it->requestId, connection->connectionId, &info);
        CONN_LOGD(CONN_BR, "br notify connect request %u success done, addr=%s, connection=%u", it->requestId,
            anomizeAddress, connection->connectionId);
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
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_brManager.pendings->lock) == SOFTBUS_OK, CONN_BR,
        "ATTENTION UNEXPECTED ERROR! check pending failed: lock pendings failed");
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, addr, BT_MAC_LEN);
    BrPending *target = GetBrPending(addr);
    if (target == NULL) {
        CONN_LOGD(CONN_BR, "address is not in pending list, no need to unpend, address=%s", anomizeAddress);
        SoftBusMutexUnlock(&g_brManager.pendings->lock);
        return;
    }
    ConnBrPendInfo *info = (ConnBrPendInfo *)SoftBusCalloc(sizeof(ConnBrPendInfo));
    if (info == NULL || strcpy_s(info->addr, BT_MAC_LEN, addr) != EOK) {
        CONN_LOGE(CONN_BR, "copy addr failed, address=%s", anomizeAddress);
        SoftBusFree(info);
        SoftBusMutexUnlock(&g_brManager.pendings->lock);
        return;
    }
    uint64_t now = SoftBusGetSysTimeMs();
    if (target->pendInfo->firstStartTimestamp + target->pendInfo->firstDuration < now) {
        CONN_LOGD(CONN_BR, "unpend address=%s", anomizeAddress);
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, info, 0);
    } else {
        CONN_LOGD(CONN_BR, "do not unpend address=%s", anomizeAddress);
        SoftBusFree(info);
    }
    SoftBusMutexUnlock(&g_brManager.pendings->lock);
}

static void OnAclStateChanged(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState, int32_t hciReason)
{
    CONN_CHECK_AND_RETURN_LOGW(addr != NULL, CONN_BR, "invalid parameter: addr is NULL");
    char copyMac[BT_MAC_LEN] = { 0 };
    int32_t status = ConvertBtMacToStr(copyMac, BT_MAC_LEN, addr->addr, sizeof(addr->addr));
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BR, "convert bt mac to str fail, error=%d", status);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, copyMac, BT_MAC_LEN);
    CONN_LOGD(CONN_BR, "address=%s, aclState=%d, hciReason=%d", anomizeAddress, aclState, hciReason);
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
        CONN_CHECK_AND_RETURN_LOGW(bleConnection != NULL, CONN_BR,
            "can not get ble connection, no need to pend BR connection");
        connectionId = bleConnection->connectionId;
        ConnBleReturnConnection(&bleConnection);
    } while (false);
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, addr, BT_MAC_LEN);
    ConnectOption options;
    (void)memset_s(&options, sizeof(options), 0, sizeof(options));
    options.type = CONNECT_BR;
    if (strcpy_s(options.brOption.brMac, BT_MAC_LEN, addr) != EOK) {
        CONN_LOGE(CONN_BR, "copy br mac fail, address = %s", anomizeAddress);
        return;
    }
    int32_t status = BrPendConnection(&options, BR_WAIT_BLE_DISCONNECTED_PEND_MILLIS);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "br pend connection failed, address=%s, error=%d", anomizeAddress, status);
        return;
    }
    CONN_LOGI(CONN_BR, "there is a ble connection connected with the same address, pending br connection, "
          "address=%s, ble connection id=%u",
        anomizeAddress, connectionId);
    return;
}

static int32_t ConnectDeviceDirectly(ConnBrDevice *device, const char *anomizeAddress)
{
    CONN_LOGI(CONN_BR, "schedule connect request, addr=%s", anomizeAddress);
    int32_t status = SOFTBUS_OK;
    ConnBrConnection *connection = ConnBrCreateConnection(device->addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    if (connection == NULL) {
        return SOFTBUS_CONN_BR_INTERNAL_ERR;
    }
    char *address = NULL;
    do {
        address = (char *)SoftBusCalloc(BT_MAC_LEN);
        if (address == NULL || strcpy_s(address, BT_MAC_LEN, device->addr) != EOK) {
            CONN_LOGW(CONN_BR, "copy br address failed, addr=%s", anomizeAddress);
            status = SOFTBUS_MEM_ERR;
            break;
        }

        status = ConnBrSaveConnection(connection);
        if (status != SOFTBUS_OK) {
            break;
        }
        ConnEventExtra extra = {
            .peerBrMac = device->addr,
            .connectionId = (int32_t)connection->connectionId,
            .result = EVENT_STAGE_RESULT_OK };
        CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_INVOKE_PROTOCOL, extra);
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
    CONN_LOGI(CONN_BR, "pend connect request, addr=%s, device state=%d", anomizeAddress, device->state);
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
    CONN_LOGD(CONN_BR, "pengding current br connect request, addr=%s, connecting address=%s",
        anomizeAddress, connectingAnomizeAddress);
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
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, false, CONN_BR,
        "br reuse connection failed: lock failed, conn id=%u", connection->connectionId);
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
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_brManager.pendings->lock) == SOFTBUS_OK, false, CONN_BR,
        "check pending failed: lock pendings failed");
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
            CONN_LOGI(CONN_BR, "reuse client, addr=%s, connection id=%u", anomizeAddress,
                clientConnection->connectionId);
            break;
        }
        if (serverConnection != NULL && BrReuseConnection(device, serverConnection)) {
            FreeDevice(device);
            CONN_LOGI(CONN_BR, "reuse server, addr=%s, conn id=%u", anomizeAddress,
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
        CONN_LOGE(CONN_BR, "ConvertCtxToDevice failed, request id=%u, error=%d", ctx->requestId, status);
        DfxRecordBrConnectFail(ctx->requestId, DEFAULT_PID, device, &ctx->statistics, status);
        ctx->result.OnConnectFailed(ctx->requestId, status);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);
    device->state = BR_DEVICE_STATE_WAIT_SCHEDULE;
    PendingDevice(device, anomizeAddress);
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
}

static void ConnectRequestOnConnectingState(const ConnBrConnectRequestContext *ctx)
{
    ConnBrDevice *device = NULL;
    int32_t status = ConvertCtxToDevice(&device, ctx);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "ConvertCtxToDevice failed, request id=%u, error=%d", ctx->requestId, status);
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
        CONN_LOGE(CONN_BR, "can not get br connection, id=%u", connectionId);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CONN_LOGI(CONN_BR, "accept new connection, conn id=%u, peer addr=%s", connectionId, anomizeAddress);

    ConnectionInfo info = { 0 };
    int32_t status = Convert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "convert connection info failed, error=%d", status);
    }
    g_connectCallback.OnConnected(connectionId, &info);
    ConnBrPendInfo *pendInfo = (ConnBrPendInfo *)SoftBusCalloc(sizeof(ConnBrPendInfo));
    if (pendInfo == NULL || strcpy_s(pendInfo->addr, BT_MAC_LEN, connection->addr) != EOK) {
        CONN_LOGE(CONN_BR, "copy addr failed, address=%s", anomizeAddress);
        SoftBusFree(pendInfo);
        return;
    }
    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendInfo);
    UnpendConnection(pendInfo);

    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice != NULL && StrCmpIgnoreCase(connectingDevice->addr, connection->addr) == 0) {
        CONN_LOGW(CONN_BR, "both ends request br connection, conn id=%u, peer addr=%s", connectionId, anomizeAddress);
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
        CONN_LOGE(CONN_BR, "can not get br connection %u", connectionId);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, connection->addr) != 0) {
        CONN_LOGE(CONN_BR, "no connecting device, conn id=%u, address=%d", connectionId, anomizeAddress);
        ConnBrUpdateConnectionRc(connection, -1);
        ConnBrReturnConnection(&connection);
        return;
    }
    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_CONNECT_TIMEOUT, connectionId, 0, NULL);
    CONN_LOGI(CONN_BR, "connect ok, id=%d, addr=%s", connectionId, anomizeAddress);

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
        CONN_LOGE(CONN_BR, "can not get br connection, conn id=%u, error=%d", connectionId, error);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);

    ConnRemoveMsgFromLooper(&g_brManagerAsyncHandler, MSG_CONNECT_TIMEOUT, connectionId, 0, NULL);
    CONN_LOGI(CONN_BR, "conn id=%u, addr=%s, error=%d", connectionId, anomizeAddress, error);
    ConnBrDisconnectNow(connection);

    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, connection->addr) != 0) {
        CONN_LOGE(CONN_BR, "no connecting device, conn id=%u, addr=%s, error=%d", connectionId, anomizeAddress, error);
        ConnBrRemoveConnection(connection);
        ConnBrReturnConnection(&connection);
        return;
    }

    do {
        bool reuseServerConnection = false;
        ConnBrConnection *serverConnection = ConnBrGetConnectionByAddr(connection->addr, CONN_SIDE_SERVER);
        if (serverConnection != NULL) {
            if (BrReuseConnection(connectingDevice, serverConnection)) {
                CONN_LOGI(CONN_BR, "reuse server connection, conn id=%u, addr=%s", serverConnection->connectionId,
                    anomizeAddress);
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
            CONN_LOGW(CONN_BR, "acl collision, wait for retry, id=%u, addr=%s, result=%d", connectionId,
                anomizeAddress, it->result);
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

    CONN_LOGI(CONN_BR, "addr=%s, conn id=%u", anomizeAddress, connectionId);

    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    if (connection != NULL) {
        CONN_LOGI(CONN_BR, "addr=%s, conn id=%u, interrupt connect progress", anomizeAddress, connection->connectionId);
        ConnBrDisconnectNow(connection);
        ConnBrRemoveConnection(connection);
        ConnBrReturnConnection(&connection);
    } else {
        CONN_LOGE(CONN_BR, "addr=%s, conn id=%u, connection not exist", anomizeAddress, connectionId);
    }
    ConnBrDevice *connectingDevice = g_brManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, address) != 0) {
        CONN_LOGE(CONN_BR, "addr=%s, conn id=%u, connecting device mismatch", anomizeAddress, connectionId);
        return;
    }
    NotifyDeviceConnectResult(connectingDevice, NULL, false, SOFTBUS_CONN_BLE_CONNECT_TIMEOUT_ERR);
    FreeDevice(connectingDevice);
    g_brManager.connecting = NULL;
    TransitionToState(BR_STATE_AVAILABLE);
}

static void DataReceived(ConnBrDataReceivedContext *ctx)
{
    ConnPktHead *head = (ConnPktHead *)ctx->data;
    ConnBrConnection *connection = ConnBrGetConnectionById(ctx->connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BR, "connection not exist, conn id=%u, payload(Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            ctx->connectionId, ctx->dataLen, head->flag, head->module, head->seq);
        SoftBusFree(ctx->data);
        return;
    }
    CONN_LOGD(CONN_BR, "conn id=%u, payload(Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
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
        CONN_LOGE(CONN_BR, "parse json failed, conn id=%u", connection->connectionId);
        return;
    }

    int32_t method = 0;
    if (!GetJsonObjectNumberItem(json, KEY_METHOD, &method)) {
        CONN_LOGE(CONN_BR, "parse method failed, conn id=%u", connection->connectionId);
        return;
    }
    CONN_LOGD(CONN_BR, "conn id=%u, method=%d", connection->connectionId, method);
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
            CONN_LOGE(CONN_BR, "UNSUPPORT method, conn id=%u, method=%d", connection->connectionId, method);
            break;
    }
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "unexpected error, conn id=%u, method=%d, error=%d", connection->connectionId, method,
            status);
    }
    cJSON_Delete(json);
}

static void ConnectionException(uint32_t connectionId, int32_t error)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR,
        "br connection exception: connection not exist, conn id=%u", connectionId);

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CONN_LOGI(CONN_BR, "release all resource, conn id=%u, addr=%s, error=%d", connectionId, anomizeAddress, error);
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
        CONN_LOGE(CONN_BR, "convert br connection info failed, error=%d", status);
    }
    ConnBrRemoveConnection(connection);
    ConnBrReturnConnection(&connection);
    ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
    g_connectCallback.OnDisconnected(connectionId, &info);
}

static void ConnectionResume(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR,
        "br resume connection failed: connection not exist, conn id=%u", connectionId);
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
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR,
        "br disconnect request failed: connection is not exist, conn id=%u", connectionId);
    ConnBrUpdateConnectionRc(connection, -1);
    ConnBrReturnConnection(&connection);
}

static void UnpendConnection(const ConnBrPendInfo *unpendInfo)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, unpendInfo->addr, BT_MAC_LEN);

    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_brManager.pendings->lock) == SOFTBUS_OK, CONN_BR,
        "unpend connection: lock failed, addr=%s", anomizeAddress);
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
            CONN_LOGD(CONN_BR, "unpend connection, address is not pending, addr=%s", anomizeAddress);
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
        CONN_LOGI(CONN_BR, "ok, addr=%s", anomizeAddress);
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_NEXT_CMD, 0, 0, NULL, 0);
    } while (false);
    SoftBusMutexUnlock(&g_brManager.pendings->lock);
}

static void Reset(int32_t reason)
{
    CONN_LOGW(CONN_BR, "br manager process RESET event, reason=%d", reason);
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
        CONN_LOGE(CONN_BR, "lock pendings failed, error=%d", status);
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
        CONN_LOGE(CONN_BR, "lock connections failed, error=%d", status);
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
    CONN_LOGI(CONN_BR, "recv msg %d, state '%s'", msg->what, g_brManager.state->name());
    switch (msg->what) {
        case MSG_NEXT_CMD: {
            if (g_brManager.state->handlePendingRequest != NULL) {
                g_brManager.state->handlePendingRequest();
                return;
            }
            break;
        }
        case MSG_CONNECT_REQUEST: {
            ConnBrConnectRequestContext *ctx = (ConnBrConnectRequestContext *)(msg->obj);
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
            if (g_brManager.state->clientConnectTimeout != NULL) {
                g_brManager.state->clientConnectTimeout((uint32_t)msg->arg1, (char *)msg->obj);
                return;
            }
            break;
        }
        case MSG_CONNECT_FAIL: {
            ErrorContext *ctx = (ErrorContext *)(msg->obj);
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
            ConnBrDataReceivedContext *ctx = (ConnBrDataReceivedContext *)(msg->obj);
            if (g_brManager.state->dataReceived != NULL) {
                g_brManager.state->dataReceived(ctx);
                return;
            }
            break;
        }
        case MSG_CONNECTION_EXECEPTION: {
            ErrorContext *ctx = (ErrorContext *)(msg->obj);
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
            ConnBrPendInfo *info = (ConnBrPendInfo *)(msg->obj);
            if (g_brManager.state->unpend != NULL) {
                g_brManager.state->unpend(info);
                return;
            }
            break;
        }
        case MSG_RESET: {
            ErrorContext *ctx = (ErrorContext *)(msg->obj);
            if (g_brManager.state->reset != NULL) {
                g_brManager.state->reset(ctx->error);
                return;
            }
            break;
        }
        default:
            CONN_LOGW(CONN_BR, "unexpected msg, %d", msg->what);
            break;
    }
    CONN_LOGW(CONN_BR, "ignore msg %d, state is '%s'", msg->what, g_brManager.state->name());
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
            ConnBrPendInfo *msgInfo = (ConnBrPendInfo *)(msg->obj);
            ConnBrPendInfo *ctxInfo = (ConnBrPendInfo *)(ctx->obj);
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
        CONN_LOGE(CONN_BR, "failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? "
            "%d", ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
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
    CONN_LOGW(CONN_BR, "conn id=%u, error=%d", connectionId, error);
    ErrorContext *ctx = (ErrorContext *)SoftBusCalloc(sizeof(ErrorContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BR, "OnClientConnectFailed: calloc ctx failed, conn id=%u, error=%d",
        connectionId, error);
    ctx->connectionId = connectionId;
    ctx->error = error;
    if (ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECT_FAIL, connectionId, 0, ctx, 0) != SOFTBUS_OK) {
        SoftBusFree(ctx);
    }
}

static void OnDataReceived(uint32_t connectionId, uint8_t *data, uint32_t dataLen)
{
    ConnBrDataReceivedContext *ctx = (ConnBrDataReceivedContext *)SoftBusCalloc(sizeof(ConnBrDataReceivedContext));
    if (ctx == NULL) {
        CONN_LOGE(CONN_BR, "calloc data received context failed, conn id=%u, len=%u", connectionId, dataLen);
        SoftBusFree(data);
        return;
    }
    ctx->connectionId = connectionId;
    ctx->data = data;
    ctx->dataLen = dataLen;

    int32_t status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_DATA_RECEIVED, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "post msg to looper failed, conn id=%u, len=%u",
            connectionId, dataLen);
        SoftBusFree(data);
        SoftBusFree(ctx);
    }
}

static void OnConnectionException(uint32_t connectionId, int32_t error)
{
    ErrorContext *ctx = (ErrorContext *)SoftBusCalloc(sizeof(ErrorContext));
    CONN_CHECK_AND_RETURN_LOGE(ctx != NULL, CONN_BR, "br connection exception: calloc ctx failed, conn id=%u, error=%d",
        connectionId, error);
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
    CONN_LOGI(CONN_BR, "conn id=%u, pid=%u, payload(Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 "), error=%d",
        connectionId, pid, len, flag, module, seq, error);
    if (error != SOFTBUS_OK) {
        ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
        if (connection == NULL) {
            // maybe fail reason is that connection not exist, so log level is warning
            CONN_LOGW(CONN_BR, "connection not exist, conn id=%u", connectionId);
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
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "br save connection: connection is null");

    int32_t status = SoftBusMutexLock(&g_brManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock manager connections failed, error=%d", status);
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
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BR, "br remove connection: connection is null");
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_brManager.connections->lock) == SOFTBUS_OK, CONN_BR,
        "br remove connection: lock manager connections failed, conn id=%u", connection->connectionId);

    ConnBrConnection *it = NULL;
    ConnBrConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_brManager.connections->list, ConnBrConnection, node) {
        if (it->connectionId == connection->connectionId) {
            target = it;
            break;
        }
    }
    if (target != NULL) {
        CONN_LOGW(CONN_BR, "conn id=%u", connection->connectionId);
        ListDelete(&connection->node);
        ConnBrReturnConnection(&connection);
    } else {
        CONN_LOGW(CONN_BR, "connection %u not exist", connection->connectionId);
    }
    (void)SoftBusMutexUnlock(&g_brManager.connections->lock);
}

ConnBrConnection *ConnBrGetConnectionByAddr(const char *addr, ConnSideType side)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(addr != NULL, NULL, CONN_BR, "addr is null");

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, addr, BT_MAC_LEN);

    int32_t status = SoftBusMutexLock(&g_brManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock manager connections failed, addr=%s, error=%d", animizeAddress, status);
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
            CONN_LOGE(CONN_BR, "lock connection failed, error=%d", status);
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
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_BR,
        "br get connection by id: lock manager connections failed, conn id=%u, error=%d", connectionId, status);

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
            CONN_LOGE(CONN_BR, "lock connection failed, conn id=%u, error=%d", connectionId, status);
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
    CONN_CHECK_AND_RETURN_LOGW(connectionPtr != NULL,  CONN_BR,
        "br return connection: connectionPtr is null");
    CONN_CHECK_AND_RETURN_LOGW(*connectionPtr != NULL, CONN_BR,
        "br return connection: *connectionPtr is null");

    ConnBrConnection *connection = *connectionPtr;
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, CONN_BR,
        "br return connection: lock failed, conn id=%u",
        connection->connectionId);
    connection->objectRc -= 1;
    int32_t objectRc = connection->objectRc;
    SoftBusMutexUnlock(&connection->lock);
    if (objectRc <= 0) {
        CONN_LOGI(CONN_BR, "release br connection %u", connection->connectionId);
        ConnBrFreeConnection(connection);
    }
    *connectionPtr = NULL;
}

static int32_t BrConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "BrConnectDevice: option is null, request id=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BR, SOFTBUS_INVALID_PARAM, CONN_BR,
        "BrConnectDevice: not br connect type, request id=%u, type=%d", requestId,
        option->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(result != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "BrConnectDevice: result callback is null, request id=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOGW(result->OnConnectSuccessed != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "BrConnectDevice: result callback OnConnectSuccessed is null, request id=%u",
        requestId);
    CONN_CHECK_AND_RETURN_RET_LOGW(result->OnConnectFailed != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "BrConnectDevice: result callback OnConnectFailed is null, request id=%u", requestId);

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, option->brOption.brMac, BT_MAC_LEN);

    ConnBrConnectRequestContext *ctx = (ConnBrConnectRequestContext *)SoftBusCalloc(sizeof(ConnBrConnectRequestContext));
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx != NULL, SOFTBUS_MEM_ERR, CONN_BR,
        "BrConnectDevice: calloc connect request context failed: request id=%u, addr=%s", requestId, anomizeAddress);
    ctx->statistics.startTime = SoftBusGetSysTimeMs();
    ctx->statistics.connectTraceId = SoftbusGetConnectTraceId();
    ctx->requestId = requestId;
    if (strcpy_s(ctx->addr, BT_MAC_LEN, option->brOption.brMac) != EOK) {
        CONN_LOGE(CONN_BR,
            "copy address failed, request id=%u, address=%s", requestId, anomizeAddress);
        SoftBusFree(ctx);
        return SOFTBUS_STRCPY_ERR;
    }
    ctx->result = *result;
    int32_t status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_CONNECT_REQUEST, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "post msg to looper failed, request id=%u, addr=%s, error=%d", requestId, anomizeAddress,
            status);
        SoftBusFree(ctx);
        return status;
    }
    CONN_LOGI(CONN_BR, "receive connect request, request id=%u, address=%s, connectTraceId=%u",
        requestId, anomizeAddress, ctx->statistics.connectTraceId);
    return SOFTBUS_OK;
}

static int32_t BrDisconnectDevice(uint32_t connectionId)
{
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, CONN_BR,
        "br disconnect device: connection not exist, conn id=%u", connectionId);
    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    NipDisconnectDevice(connectionId);
    ConnBrReturnConnection(&connection);
    int32_t status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MGR_DISCONNECT_REQUEST, connectionId, 0, NULL, 0);
    CONN_LOGI(CONN_BR, "conn id=%u, address=%s, status=%d", connectionId, animizeAddress, status);
    return status;
}

static int32_t BrDisconnectDeviceNow(const ConnectOption *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "br disconnect device now: option is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BR, SOFTBUS_INVALID_PARAM, CONN_BR,
        "br disconnect device now: not br type, type=%d", option->type);

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, option->brOption.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_BR, "addr=%s, side=%d", animizeAddress, option->brOption.sideType);

    ConnBrConnection *connection = ConnBrGetConnectionByAddr(option->brOption.brMac, option->brOption.sideType);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, CONN_BR,
        "br disconnect device now: connection not exist, address=%s, side=%d", animizeAddress,
        option->brOption.sideType);
    NipDisconnectDevice(connection->connectionId);
    ConnBrDisconnectNow(connection);
    ConnBrReturnConnection(&connection);
    return SOFTBUS_OK;
}

static int32_t BrGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(info != NULL, SOFTBUS_INVALID_PARAM, CONN_BR,
        "br get connection info: info is null");
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, CONN_BR,
        "br get connection info: connection not exist, conn id=%u", connectionId);

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
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, false, CONN_BR,
        "BrCheckActiveConnection: option is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BR, false, CONN_BR,
        "BrCheckActiveConnection: not br type, type=%d", option->type);

    ConnBrConnection *connection = ConnBrGetConnectionByAddr(option->brOption.brMac, option->brOption.sideType);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, false, CONN_BR,
        "BrCheckActiveConnection: connection is not exist");
    bool isActive = (connection->state == BR_CONNECTION_STATE_CONNECTED);
    ConnBrReturnConnection(&connection);
    return isActive;
}

static void ProcessAclCollisionException(ConnBrDevice *device, const char *anomizeAddress)
{
    CONN_LOGI(CONN_BR, "addr=%s", anomizeAddress);
    ConnectOption option;
    (void)memset_s(&option, sizeof(option), 0, sizeof(option));
    option.type = CONNECT_BR;
    if (strcpy_s(option.brOption.brMac, BT_MAC_LEN, device->addr) != EOK) {
        CONN_LOGE(CONN_BR, "copy br mac fail, addr=%s", anomizeAddress);
        return;
    }
    BrPendConnection(&option, BR_CONNECTION_ACL_CONNECT_COLLISION_MILLIS);
    device->state = BR_DEVICE_STATE_PENDING;
    PendingDevice(device, anomizeAddress);
}

static int32_t BrPendConnection(const ConnectOption *option, uint32_t time)
{
    CONN_CHECK_AND_RETURN_RET_LOGW((option != NULL && time != 0 && time <= BR_CONNECTION_PEND_TIMEOUT_MAX_MILLIS),
        SOFTBUS_INVALID_PARAM, CONN_BR, "BrPendConnection: option is null or pend time is 0");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BR, SOFTBUS_INVALID_PARAM, CONN_BR,
        "BrPendConnection: not br type, type=%d", option->type);

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, option->brOption.brMac, BT_MAC_LEN);
    CONN_LOGI(CONN_BR, "addr=%s, side=%d", animizeAddress, option->brOption.sideType);

    int32_t status = SoftBusMutexLock(&g_brManager.pendings->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BR, "lock pendings failed: error=%d", status);
        return SOFTBUS_LOCK_ERR;
    }
    do {
        BrPending *target = GetBrPending(option->brOption.brMac);
        ConnBrPendInfo *pendInfo = (ConnBrPendInfo *)SoftBusCalloc(sizeof(ConnBrPendInfo));
        if (pendInfo == NULL || strcpy_s(pendInfo->addr, BT_MAC_LEN, option->brOption.brMac) != EOK) {
            CONN_LOGE(CONN_BR, "copy addr failed, addr=%s", animizeAddress);
            SoftBusFree(pendInfo);
            break;
        }
        uint64_t now = SoftBusGetSysTimeMs();
        pendInfo->firstStartTimestamp = now;
        pendInfo->firstDuration = time;
        pendInfo->startTimestamp = now;
        pendInfo->duration = time;
        if (target != NULL) {
            CONN_LOGD(CONN_BR, "br pend connection, address pending, refresh timeout only, addr=%s", animizeAddress);
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

        BrPending *pending = (BrPending *)SoftBusCalloc(sizeof(BrPending));
        if (pending == NULL) {
            CONN_LOGE(CONN_BR, "calloc pending object failed");
            status = SOFTBUS_MALLOC_ERR;
            break;
        }
        ListInit(&pending->node);
        pending->pendInfo = pendInfo;
        ListAdd(&g_brManager.pendings->list, &pending->node);
        g_brManager.pendings->cnt += 1;
        ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_UNPEND, 0, 0, pendInfo, time);
        CONN_LOGD(CONN_BR, "br pend connection success, address=%s", animizeAddress);
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
        CONN_LOGE(CONN_BR, "get bt Smac failed, error=%d", status);
        return;
    }
    char myBtMac[BT_MAC_LEN] = { 0 };
    status = ConvertBtMacToStr(myBtMac, BT_MAC_LEN, addr.addr, sizeof(addr.addr));
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BR, "convert bt mac to str fail, error=%d", status);
        return;
    }
    char anomizeMyAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeMyAddress, BT_MAC_LEN, myBtMac, BT_MAC_LEN);
    CONN_LOGD(CONN_BR, "local bt address is %s", anomizeMyAddress);
}

static void OnBtStateChanged(int listenerId, int state)
{
    (void)listenerId;
    int32_t status = SOFTBUS_OK;
    if (state == SOFTBUS_BR_STATE_TURN_ON) {
        DumpLocalBtMac();
        status = ConnBrStartServer();
        CONN_LOGI(CONN_BR, "recv bt on, start server, status=%d", status);
        return;
    }

    if (state == SOFTBUS_BR_STATE_TURN_OFF) {
        status = ConnBrStopServer();
        CONN_LOGI(CONN_BR, "recv bt off, stop server, status=%d", status);

        ErrorContext *ctx = (ErrorContext *)SoftBusCalloc(sizeof(ErrorContext));
        if (ctx == NULL) {
            CONN_LOGE(CONN_BR, "calloc ctx object failed");
            return;
        }
        ctx->error = SOFTBUS_CONN_BLUETOOTH_OFF;
        status = ConnPostMsgToLooper(&g_brManagerAsyncHandler, MSG_RESET, 0, 0, ctx, 0);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BR, "post msg to looper failed");
            SoftBusFree(ctx);
        }
        return;
    }
}

static int32_t InitBrManager()
{
    SoftBusList *connections = CreateSoftBusList();
    SoftBusList *pendings = CreateSoftBusList();
    CONN_CHECK_AND_RETURN_RET_LOGE(connections != NULL && pendings != NULL, SOFTBUS_ERR, CONN_INIT,
        "InitBrManager: create list failed");
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
    CONN_CHECK_AND_RETURN_RET_LOGW(listenerId >= 0, SOFTBUS_ERR, CONN_INIT,
        "InitBrManager: add bt state change listener failed, invalid listener id=%d", listenerId);
    TransitionToState(BR_STATE_AVAILABLE);
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(callback != NULL, NULL, CONN_INIT, "ConnInitBr: callback is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback->OnConnected != NULL, NULL, CONN_INIT,
        "ConnInitBr: callback OnConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback->OnDisconnected != NULL, NULL, CONN_INIT,
        "ConnInitBr: callback OnDisconnected is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback->OnDataReceived != NULL, NULL, CONN_INIT,
        "ConnInitBr: callback OnDataReceived is null");

    int32_t status = BrInitLooper();
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_INIT,
        "ConnInitBr: init looper failed, error=%d", status);
    SppSocketDriver *sppDriver = InitSppSocketDriver();
    CONN_CHECK_AND_RETURN_RET_LOGE(sppDriver != NULL, NULL, CONN_INIT, "ConnInitBr: init spp socket driver failed");

    ConnBrEventListener connectionEventListener = {
        .onServerAccepted = OnServerAccepted,
        .onClientConnected = OnClientConnected,
        .onClientConnectFailed = OnClientConnectFailed,
        .onDataReceived = OnDataReceived,
        .onConnectionException = OnConnectionException,
        .onConnectionResume = OnConnectionResume,
    };
    status = ConnBrConnectionMuduleInit(g_brManagerAsyncHandler.handler.looper, sppDriver, &connectionEventListener);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_INIT,
        "ConnInitBr: init connection failed, error=%d ", status);

    ConnBrTransEventListener transEventListener = {
        .onPostByteFinshed = OnPostByteFinshed,
    };
    status = ConnBrTransMuduleInit(sppDriver, &transEventListener);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_INIT,
        "ConnInitBr: init trans failed, error=%d", status);

    status = InitBrManager();
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_INIT,
        "ConnInitBr: init manager failed, error=%d", status);
    status = ConnBrInitBrPendingPacket();
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_INIT,
        "conn init br failed: init pending packet failed, error=%d", status);
    status = ConnBrInitBrPendingPacket();
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_INIT,
        "conn init br failed: init br pending failed, error=%d", status);
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
    CONN_LOGI(CONN_INIT, "ok");
    return &connectFuncInterface;
}
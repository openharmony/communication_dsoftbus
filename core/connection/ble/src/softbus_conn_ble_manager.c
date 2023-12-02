/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbus_conn_ble_manager.h"

#include <ctype.h>
#include <securec.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "conn_log.h"
#include "softbus_adapter_ble_conflict.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_common.h"
#include "softbus_datahead_transform.h"
#include "softbus_utils.h"
#include "conn_event.h"

#define CONFLICT_REUSE_CONNECTING 0
#define SHORT_UDID_HASH_LEN       8

enum BleMgrState {
    BLE_MGR_STATE_AVAILABLE,
    BLE_MGR_STATE_CONNECTING,
    BLE_MGR_STATE_MAX,
};

enum BleMgrLooperMsg {
    BLE_MGR_MSG_NEXT_CMD,
    BLE_MGR_MSG_CONNECT_REQUEST,
    BLE_MGR_MSG_CONNECT_SUCCESS,
    BLE_MGR_MSG_CONNECT_TIMEOUT,
    BLE_MGR_MSG_CONNECT_FAIL,
    BLE_MGR_MSG_SERVER_ACCEPTED,
    BLE_MGR_MSG_DATA_RECEIVED,
    BLE_MGR_MSG_CONNECTION_CLOSED,
    BLE_MGR_MSG_CONNECTION_RESUME,
    BLE_MGR_MSG_DISCONNECT_REQUEST,
    BLE_MGR_MSG_REUSE_CONNECTION_REQUEST,
    BLE_MGR_MSG_PREVENT_TIMEOUT,
    BLE_MGR_MSG_RESET,
};

typedef struct {
    SoftBusList *connections;
    ConnBleState *state;
    ListNode waitings;
    ConnBleDevice *connecting;
    // prevent device connect request
    SoftBusList *prevents;
} BleManager;

typedef struct {
    uint32_t connectionId;
    int32_t status;
} BleStatusContext;

typedef struct {
    ListNode node;
    char udid[UDID_BUF_LEN];
    int32_t timeout;
} BlePrevent;

enum BleConnectionCompareType {
    BLE_CONNECTION_COMPARE_TYPE_CONNECTION_ID,
    BLE_CONNECTION_COMPARE_TYPE_ADDRESS,
    BLE_CONNECTION_COMPARE_TYPE_UNDERLAY_HANDLE,
    BLE_CONNECTION_COMPARE_TYPE_UDID_DIFF_ADDRESS,
    BLE_CONNECTION_COMPARE_TYPE_UDID_CLIENT_SIDE,
};

typedef struct {
    enum BleConnectionCompareType type;
    union {
        struct {
            uint32_t connectionId;
        } connectionIdOption;
        struct {
            const char *addr;
            ConnSideType side;
            ProtocolType protocol;
        } addressOption;
        struct {
            int32_t underlayerHandle;
            ConnSideType side;
            ProtocolType protocol;
        } underlayerHandleOption;
        struct {
            const char *addr;
            const char *udid;
            ProtocolType protocol;
        } udidAddressOption;
        struct {
            const char *udid;
            BleProtocolType protocol;
        } udidClientOption;
    };
} BleConnectionCompareOption;

typedef bool (*BleConnectionCompareFunc)(ConnBleConnection *connection, const BleConnectionCompareOption *option);
static void TransitionToState(enum BleMgrState target);
static int32_t PendingDevice(ConnBleDevice *device, const char *anomizeAddress, const char *anomizeUdid);
static void BleClientConnectFailed(uint32_t connectionId, int32_t error);
static void ReceivedControlData(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen);
static bool IsSameDevice(const char *leftIdentifier, const char *rightIdentifier);
static void BleManagerMsgHandler(SoftBusMessage *msg);
static int BleCompareManagerLooperEventFunc(const SoftBusMessage *msg, void *args);
static void DelayRegisterLnnOnlineListener(void);

static BleManager g_bleManager = { 0 };
static SoftBusHandlerWrapper g_bleManagerSyncHandler = {
    .handler = {
        .name = (char *)"BleManagerAsyncHandler",
        .HandleMessage = BleManagerMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = BleCompareManagerLooperEventFunc,
};
static ConnectCallback g_connectCallback = { 0 };

static char *BleNameAvailableState(void)
{
    return (char *)("avaible state");
}

static char *BleNameConnectingState(void)
{
    return (char *)("connectting state");
}

static void BleEnterAvailableState(void)
{
    CONN_LOGI(CONN_BLE, "ble manager enter avaible state");
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_NEXT_CMD, 0, 0, NULL, 0);
}

static void BleEnterConnectingState(void)
{
    CONN_LOGI(CONN_BLE, "ble manager enter connecting state");
}

static void BleExitAvailableState(void)
{
    CONN_LOGI(CONN_BLE, "ble manager exit avaible state");
}

static void BleExitConnectingState(void)
{
    CONN_LOGI(CONN_BLE, "ble manager exit connecting state");
}

static void DfxRecordBleConnectFail(
    uint32_t reqId, uint32_t pId, ConnBleDevice *device, const ConnectStatistics *statistics, int32_t reason)
{
    if (statistics == NULL) {
        CONN_LOGW(CONN_BLE, "statistics is null");
        return;
    }

    SoftBusConnType connType =
        device->protocol == BLE_GATT ? SOFTBUS_HISYSEVT_CONN_TYPE_BLE : SOFTBUS_HISYSEVT_CONN_TYPE_COC;

    CONN_LOGD(CONN_BLE, "record ble conn fail, connectTraceId=%u, reason=%d", statistics->connectTraceId, reason);
    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, connType, SOFTBUS_EVT_CONN_FAIL, costTime, reason);
    ConnEventExtra extra = {
        .requestId = reqId,
        .linkType = CONNECT_BLE,
        .costTime = costTime,
        .errcode = reason,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
    ConnAlarmExtra extraAlarm = {
        .linkType = CONNECT_BLE,
        .errcode = reason,
    };
    CONN_ALARM(CONNECTION_FAIL_ALARM, MANAGE_ALARM_TYPE, extraAlarm);
}

static void DfxRecordBleConnectSuccess(uint32_t pId, ConnBleConnection *connection, ConnectStatistics *statistics)
{
    if (statistics == NULL) {
        CONN_LOGW(CONN_BLE, "statistics is null");
        return;
    }

    CONN_LOGD(CONN_BLE, "record ble conn succ, connectTraceId=%u", statistics->connectTraceId);
    SoftBusConnType connType =
        connection->protocol == BLE_GATT ? SOFTBUS_HISYSEVT_CONN_TYPE_BLE : SOFTBUS_HISYSEVT_CONN_TYPE_COC;

    uint64_t costTime = SoftBusGetSysTimeMs() - statistics->startTime;
    SoftbusRecordConnResult(pId, connType, SOFTBUS_EVT_CONN_SUCC, costTime, SOFTBUS_HISYSEVT_CONN_OK);
    ConnEventExtra extra = {
        .connectionId = (int32_t)connection->connectionId,
        .linkType = CONNECT_BLE,
        .costTime = (int32_t)costTime,
        .result = EVENT_STAGE_RESULT_OK };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_END, extra);
}

static int32_t NewRequest(ConnBleRequest **outRequest, const ConnBleConnectRequestContext *ctx)
{
    ConnBleRequest *request = (ConnBleRequest *)SoftBusCalloc(sizeof(ConnBleRequest));
    if (request == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&request->node);
    request->requestId = ctx->requestId;
    request->challengeCode = ctx->challengeCode;
    request->result = ctx->result;
    request->protocol = ctx->protocol;

    *outRequest = request;
    return SOFTBUS_OK;
}

static int32_t NewDevice(ConnBleDevice **outDevice, const ConnBleConnectRequestContext *ctx)
{
    ConnBleDevice *device = (ConnBleDevice *)SoftBusCalloc(sizeof(ConnBleDevice));
    if (device == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(&device->node);
    if (strcpy_s(device->addr, BT_MAC_LEN, ctx->addr) != EOK ||
        strcpy_s(device->udid, UDID_BUF_LEN, ctx->udid) != EOK) {
        SoftBusFree(device);
        return SOFTBUS_MEM_ERR;
    }
    device->fastestConnectEnable = ctx->fastestConnectEnable;
    device->state = BLE_DEVICE_STATE_INIT;
    device->protocol = ctx->protocol;
    device->psm = ctx->psm;
    ListInit(&device->requests);
    *outDevice = device;
    return SOFTBUS_OK;
}

static void FreeDevice(ConnBleDevice *device)
{
    ConnBleRequest *it = NULL;
    ConnBleRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &device->requests, ConnBleRequest, node) {
        ListDelete(&it->node);
        SoftBusFree(it);
    }
    ListDelete(&device->node);
    SoftBusFree(device);
}

static int32_t ConvertCtxToDevice(ConnBleDevice **outDevice, const ConnBleConnectRequestContext *ctx)
{
    ConnBleRequest *request = NULL;
    int32_t status = NewRequest(&request, ctx);
    if (status != SOFTBUS_OK) {
        return status;
    }
    ConnBleDevice *device = NULL;
    status = NewDevice(&device, ctx);
    if (status != SOFTBUS_OK) {
        SoftBusFree(request);
        return status;
    }
    ListAdd(&device->requests, &request->node);
    *outDevice = device;
    return SOFTBUS_OK;
}

static int32_t BleConvert2ConnectionInfo(ConnBleConnection *connection, ConnectionInfo *info)
{
    info->isAvailable = connection->state == BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO ? 1 : 0;
    info->isServer = connection->side == CONN_SIDE_SERVER ? 1 : 0;
    info->type = CONNECT_BLE;
    if (strcpy_s(info->bleInfo.bleMac, BT_MAC_LEN, connection->addr) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    info->bleInfo.protocol = connection->protocol;
    info->bleInfo.psm = 0;
    int32_t status = SOFTBUS_OK;
    if (connection->protocol == BLE_COC) {
        info->bleInfo.psm = connection->psm;
        ConnBleInnerComplementDeviceId(connection);
        if (strlen(connection->udid) == 0) {
            CONN_LOGW(CONN_BLE, "generate udid hash failed: device is not lnn online, connId=%d",
                connection->connectionId);
            // it will be complement later on lnn online listener
            return SOFTBUS_OK;
        }
    }
    status = SoftBusGenerateStrHash(
        (unsigned char *)connection->udid, strlen(connection->udid), (unsigned char *)info->bleInfo.deviceIdHash);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert ble connection info failed: generate udid hash failed, connId=%u, err=%d",
            connection->connectionId, status);
        return status;
    }
    return SOFTBUS_OK;
}

static void BleNotifyDeviceConnectResult(const ConnBleDevice *device, ConnBleConnection *connection, int32_t reason)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);

    ConnBleRequest *it = NULL;
    if (connection == NULL) {
        LIST_FOR_EACH_ENTRY(it, &device->requests, ConnBleRequest, node) {
            CONN_LOGI(CONN_BLE, "ble notify connect request %u failed, addr=%s, protocol=%d, reason=%d", it->requestId,
                anomizeAddress, device->protocol, reason);
            DfxRecordBleConnectFail(it->requestId, DEFAULT_PID, (ConnBleDevice *)device, &it->statistics, reason);
            it->result.OnConnectFailed(it->requestId, reason);
        }
        return;
    }

    ConnectionInfo info = { 0 };
    int32_t status = BleConvert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert ble connection info failed, err=%d. It cann't backoff now, just ahead.", status);
    }
    LIST_FOR_EACH_ENTRY(it, &device->requests, ConnBleRequest, node) {
        ConnBleUpdateConnectionRc(connection, it->challengeCode, 1);
        CONN_LOGI(CONN_BLE, "ble notify connect request %u success, addr=%s, connId=%u, protocol=%d, challenge=%u",
            it->requestId, anomizeAddress, connection->connectionId, device->protocol, it->challengeCode);
        it->statistics.reqId = it->requestId;
        DfxRecordBleConnectSuccess(DEFAULT_PID, connection, &it->statistics);
        info.bleInfo.challengeCode = it->challengeCode;
        it->result.OnConnectSuccessed(it->requestId, connection->connectionId, &info);
    }
}

static bool BleReuseConnection(ConnBleDevice *device, ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, false, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! ble reuse connection failed: try to lock failed, connId=%u",
        connection->connectionId);
    enum ConnBleConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (state != BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO) {
        return false;
    }
    BleNotifyDeviceConnectResult(device, connection, 0);
    return true;
}

static bool BleCheckPreventing(const char *udid)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_bleManager.prevents->lock) == SOFTBUS_OK, false, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! ble check preventing failed: try to lock failed");
    bool preventing = false;
    BlePrevent *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleManager.prevents->list, BlePrevent, node) {
        if (IsSameDevice(udid, (char *)it->udid)) {
            preventing = true;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_bleManager.prevents->lock);
    return preventing;
}

typedef int32_t (*DeviceAction)(ConnBleDevice *device, const char *anomizeAddress, const char *anomizeUdid);
static void AttempReuseConnect(ConnBleDevice *device, DeviceAction actionIfAbsent)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);
    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, device->udid);

    // ignore protocol type
    ConnBleConnection *udidConnection = ConnBleGetConnectionByUdid(device->addr, device->udid, BLE_PROTOCOL_ANY);
    ConnBleConnection *clientConnection = ConnBleGetConnectionByAddr(device->addr, CONN_SIDE_CLIENT, BLE_PROTOCOL_ANY);
    ConnBleConnection *serverConnection = ConnBleGetConnectionByAddr(device->addr, CONN_SIDE_SERVER, BLE_PROTOCOL_ANY);
    if (udidConnection == NULL && clientConnection == NULL && serverConnection == NULL) {
        if (BleCheckPreventing(device->udid)) {
            CONN_LOGI(CONN_BLE, "ble manager reject connect request as udid is in prevent list, addr=%s, udid=%s",
                anomizeAddress, anomizeUdid);
            BleNotifyDeviceConnectResult(device, NULL, SOFTBUS_CONN_BLE_CONNECT_PREVENTED_ERR);
            FreeDevice(device);
            return;
        }
        device->state = BLE_DEVICE_STATE_WAIT_SCHEDULE;
        int32_t status = actionIfAbsent(device, anomizeAddress, anomizeUdid);
        if (status != SOFTBUS_OK) {
            BleNotifyDeviceConnectResult(device, NULL, status);
            FreeDevice(device);
        }
        return;
    }
    do {
        if (udidConnection != NULL && BleReuseConnection(device, udidConnection)) {
            CONN_LOGW(CONN_BLE, "reuse ble connection by udid");
            FreeDevice(device);
            break;
        }
        if (clientConnection != NULL && BleReuseConnection(device, clientConnection)) {
            CONN_LOGW(CONN_BLE, "reuse ble client connection by address");
            FreeDevice(device);
            break;
        }
        if (serverConnection != NULL && BleReuseConnection(device, serverConnection)) {
            CONN_LOGW(CONN_BLE, "reuse ble server connection by address");
            FreeDevice(device);
            break;
        }
        device->state = BLE_DEVICE_STATE_WAIT_EVENT;
        PendingDevice(device, anomizeAddress, anomizeUdid);
    } while (false);

    if (udidConnection != NULL) {
        ConnBleReturnConnection(&udidConnection);
    }
    if (clientConnection != NULL) {
        ConnBleReturnConnection(&clientConnection);
    }
    if (serverConnection != NULL) {
        ConnBleReturnConnection(&serverConnection);
    }
}

static int32_t BleConnectDeviceDirectly(ConnBleDevice *device, const char *anomizeAddress, const char *anomizeUdid)
{
    CONN_LOGI(CONN_BLE, "ble manager start schedule connect request, addr=%s, udid=%s", anomizeAddress, anomizeUdid);
    DelayRegisterLnnOnlineListener();
    device->state = BLE_DEVICE_STATE_SCHEDULING;
    int32_t status = SOFTBUS_OK;
    ConnBleConnection *connection = ConnBleCreateConnection(
        device->addr, device->protocol, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, device->fastestConnectEnable);
    if (connection == NULL) {
        return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }

    connection->psm = device->psm;
    char *address = NULL;
    do {
        address = (char *)SoftBusCalloc(BT_MAC_LEN);
        if (address == NULL || strcpy_s(address, BT_MAC_LEN, device->addr) != EOK) {
            CONN_LOGE(CONN_BLE, "copy ble address for connect timeout event failed, request address=%s, udid=%s",
                anomizeAddress, anomizeUdid);
            status = SOFTBUS_MEM_ERR;
            break;
        }

        status = ConnBleSaveConnection(connection);
        if (status != SOFTBUS_OK) {
            break;
        }
        status = ConnBleConnect(connection);
        if (status != SOFTBUS_OK) {
            break;
        }
        g_bleManager.connecting = device;
        ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_TIMEOUT, connection->connectionId, 0, address,
            BLE_CONNECT_TIMEOUT_MILLIS);
        TransitionToState(BLE_MGR_STATE_CONNECTING);
    } while (false);

    if (status != SOFTBUS_OK) {
        ConnBleRemoveConnection(connection);
        SoftBusFree(address);
    }
    ConnBleReturnConnection(&connection);
    return status;
}

static int32_t PendingDevice(ConnBleDevice *device, const char *anomizeAddress, const char *anomizeUdid)
{
    CONN_LOGI(CONN_BLE, "ble manager pend connect request, addr=%s, udid=%s, device state=%d", anomizeAddress,
        anomizeUdid, device->state);
    ConnBleDevice *connecting = g_bleManager.connecting;
    char connectingAnomizeAddress[BT_MAC_LEN] = { 0 };
    if (connecting != NULL) {
        ConvertAnonymizeMacAddress(connectingAnomizeAddress, BT_MAC_LEN, connecting->addr, BT_MAC_LEN);
    }

    ConnBleDevice *target = NULL;
    if (connecting != NULL && StrCmpIgnoreCase(connecting->addr, device->addr) == 0) {
        target = connecting;
    } else {
        ConnBleDevice *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &g_bleManager.waitings, ConnBleDevice, node) {
            if (StrCmpIgnoreCase(it->addr, device->addr) == 0) {
                target = it;
                break;
            }
        }
    }
    CONN_LOGD(CONN_BLE, "pengding current ble connect request, request addr=%s, connecting addr=%s", anomizeAddress,
        connectingAnomizeAddress);
    if (target == NULL) {
        ListTailInsert(&g_bleManager.waitings, &device->node);
        return SOFTBUS_OK;
    }

    ConnBleDevice *requestIt = NULL;
    ConnBleDevice *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestIt, requestNext, &device->requests, ConnBleDevice, node) {
        ListDelete(&requestIt->node);
        ListAdd(&target->requests, &requestIt->node);
    }
    target->fastestConnectEnable = (device->fastestConnectEnable || target->fastestConnectEnable);
    if (strlen(target->udid) == 0 && strlen(device->udid) != 0) {
        if (strcpy_s(target->udid, UDID_BUF_LEN, device->udid) != EOK) {
            CONN_LOGE(CONN_BLE, "copy ble connect request udid to previous request failed, it is not a big deal, just "
                "ahead, addr=%s", anomizeAddress);
        }
    }
    target->state = device->state;
    FreeDevice(device);
    return SOFTBUS_OK;
}

static void BleConnectRequestOnAvailableState(const ConnBleConnectRequestContext *ctx)
{
    ConnBleDevice *device = NULL;
    int32_t status = ConvertCtxToDevice(&device, ctx);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert ble connect request failed, reqId=%u, err=%d", ctx->requestId, status);
        DfxRecordBleConnectFail(ctx->requestId, DEFAULT_PID, device, &ctx->statistics, status);
        ctx->result.OnConnectFailed(ctx->requestId, status);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, device->addr, BT_MAC_LEN);
    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, device->udid);
    device->state = BLE_DEVICE_STATE_WAIT_SCHEDULE;
    PendingDevice(device, anomizeAddress, anomizeUdid);
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_NEXT_CMD, 0, 0, NULL, 0);
}

static void BleConnectRequestOnConnectingState(const ConnBleConnectRequestContext *ctx)
{
    ConnBleDevice *device = NULL;
    int32_t status = ConvertCtxToDevice(&device, ctx);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert ble connect request failed, reqId=%u, err=%d", ctx->requestId, status);
        DfxRecordBleConnectFail(ctx->requestId, DEFAULT_PID, device, &ctx->statistics, status);
        ctx->result.OnConnectFailed(ctx->requestId, status);
        return;
    }
    AttempReuseConnect(device, PendingDevice);
}

// handlePendingRequest
static void BleHandlePendingRequestOnAvailableState(void)
{
    ConnBleDevice *target = NULL;
    ConnBleDevice *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleManager.waitings, ConnBleDevice, node) {
        if (it->state == BLE_DEVICE_STATE_WAIT_SCHEDULE) {
            target = it;
            break;
        }
    }
    if (target == NULL) {
        return;
    }
    ListDelete(&target->node);
    AttempReuseConnect(target, BleConnectDeviceDirectly);
}

// onConnectTimeout
static void BleClientConnectTimeoutOnConnectingState(uint32_t connectionId, const char *address)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);

    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection != NULL) {
        CONN_LOGE(CONN_BLE, "ble connect timeout, addr=%s, connId=%u, interrupt connect progress", anomizeAddress,
            connection->connectionId);
        ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_CONNECT_TIMEOUT);
        ConnBleRemoveConnection(connection);
        ConnBleReturnConnection(&connection);
    } else {
        CONN_LOGE(CONN_BLE, "ble connect timeout, addr=%s, connId=%u, connection object not exist, skip "
              "interrupt connect progress",
            anomizeAddress, connectionId);
    }
    ConnBleDevice *connectingDevice = g_bleManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, address) != 0) {
        CONN_LOGE(CONN_BLE, "ble connect timeout, addr=%s, connId=%u, connecting device is null or address "
              "mismatch with this event",
            anomizeAddress, connectionId);
        return;
    }
    BleNotifyDeviceConnectResult(connectingDevice, NULL, SOFTBUS_CONN_BLE_CONNECT_TIMEOUT_ERR);
    FreeDevice(connectingDevice);
    g_bleManager.connecting = NULL;
    TransitionToState(BLE_MGR_STATE_AVAILABLE);
}
// clientConnected
static void BleClientConnected(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "can not get ble connection %u, is it removed? ", connectionId);
        return;
    }
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    ConnBleDevice *connectingDevice = g_bleManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, connection->addr) != 0) {
        CONN_LOGE(CONN_BLE, "there is no connecting device, is it connected after timeout? connId=%u, addr=%d",
            connectionId, anomizeAddress);
        ConnBleUpdateConnectionRc(connection, 0, -1);
        ConnBleReturnConnection(&connection);
        return;
    }
    ConnRemoveMsgFromLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_TIMEOUT, connectionId, 0, NULL);
    CONN_LOGI(CONN_BLE, "ble client connect success, client id=%d, addr=%s", connectionId, anomizeAddress);

    BleNotifyDeviceConnectResult(connectingDevice, connection, 0);
    FreeDevice(connectingDevice);
    g_bleManager.connecting = NULL;
    TransitionToState(BLE_MGR_STATE_AVAILABLE);
    ConnBleReturnConnection(&connection);
}

// clientConnectFailed
static void BleClientConnectFailed(uint32_t connectionId, int32_t error)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "can not get ble connection, is it removed? connId=%u, err=%d", connectionId, error);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    CONN_LOGI(CONN_BLE, "ble client connect failed, connId=%u, addr=%s, err=%d", connectionId, anomizeAddress, error);
    ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_INTERNAL_ERROR);

    ConnBleDevice *connectingDevice = g_bleManager.connecting;
    if (connectingDevice == NULL || StrCmpIgnoreCase(connectingDevice->addr, connection->addr) != 0) {
        CONN_LOGE(CONN_BLE, "there is no connecting device, is it connected after timeout? connId=%u, addr=%s, err=%d",
            connectionId, anomizeAddress, error);
        ConnBleRemoveConnection(connection);
        ConnBleReturnConnection(&connection);
        return;
    }
    ConnRemoveMsgFromLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_TIMEOUT, connectionId, 0, NULL);

    ConnBleConnection *serverConnection =
        ConnBleGetConnectionByAddr(connection->addr, CONN_SIDE_SERVER, connectingDevice->protocol);
    if (serverConnection != NULL) {
        if (BleReuseConnection(connectingDevice, serverConnection)) {
            CONN_LOGI(CONN_BLE, "ble client connect failed, but there is a server connection connected, reuse it, "
                "connId=%u, addr=%s", serverConnection->connectionId, anomizeAddress);
        } else {
            BleNotifyDeviceConnectResult(connectingDevice, NULL, error);
        }
        ConnBleReturnConnection(&serverConnection);
    } else {
        BleNotifyDeviceConnectResult(connectingDevice, NULL, error);
    }
    FreeDevice(connectingDevice);
    g_bleManager.connecting = NULL;
    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
    TransitionToState(BLE_MGR_STATE_AVAILABLE);
}

static bool IsSameHashId(const char *leftHash, const char *rightHash)
{
    size_t leftLen = strlen(leftHash);
    size_t rightLen = strlen(rightHash);
    size_t min = leftLen < rightLen ? leftLen : rightLen;
    for (size_t i = 0; i < min; i++) {
        if (toupper(leftHash[i]) != toupper(rightHash[i])) {
            return false;
        }
    }
    return true;
}

static bool IsSameDevice(const char *leftIdentifier, const char *rightIdentifier)
{
    if (leftIdentifier == NULL || rightIdentifier == NULL) {
        return false;
    }

    size_t leftLen = strlen(leftIdentifier);
    size_t rightLen = strlen(rightIdentifier);
    if (leftLen == 0 || rightLen == 0) {
        return false;
    }
    if (leftLen == rightLen) {
        return StrCmpIgnoreCase(leftIdentifier, rightIdentifier) == 0;
    }
    unsigned char leftHash[UDID_HASH_LEN] = { 0 };
    unsigned char rightHash[UDID_HASH_LEN] = { 0 };
    if (SoftBusGenerateStrHash((const unsigned char *)leftIdentifier, leftLen, leftHash) != SOFTBUS_OK ||
        SoftBusGenerateStrHash((const unsigned char *)rightIdentifier, rightLen, rightHash) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "generate hash failed");
        return false;
    }
    // only compare first 8 bytes of hash
    char leftHashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    char rightHashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    if (ConvertBytesToHexString(leftHashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN), leftHash, SHORT_UDID_HASH_LEN) !=
            SOFTBUS_OK ||
        ConvertBytesToHexString(rightHashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN), rightHash, SHORT_UDID_HASH_LEN) !=
            SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert bytes to array failed");
        return false;
    }
    if (leftLen == UDID_BUF_LEN - 1) {
        return IsSameHashId(leftHashStr, rightIdentifier);
    } else if (rightLen == UDID_BUF_LEN - 1) {
        return IsSameHashId(leftIdentifier, rightHashStr);
    } else {
        return IsSameHashId(leftHashStr, rightHashStr);
    }
}

// BleServerAccepted
static void BleServerAccepted(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "can not get ble connection %u, is it removed? ", connectionId);
        return;
    }

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);

    ConnectionInfo info = { 0 };
    int32_t status = BleConvert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert connection info failed, err=%d. It can not backoff now, just ahead.", status);
    }
    char udidHashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    status = ConvertBytesToHexString(udidHashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN),
        (unsigned char *)info.bleInfo.deviceIdHash, SHORT_UDID_HASH_LEN);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert peerUdidHash to string failed, connectionId=%u, err=%d.", connectionId, status);
    }
    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, udidHashStr);
    CONN_LOGI(CONN_BLE, "ble server accept a new connection, connId=%u, peer addr=%s, peer udid=%s",
        connectionId, anomizeAddress, anomizeUdid);
    g_connectCallback.OnConnected(connectionId, &info);

    ConnBleDevice *connectingDevice = g_bleManager.connecting;
    if (connectingDevice != NULL && StrCmpIgnoreCase(connectingDevice->addr, connection->addr) == 0) {
        CONN_LOGW(CONN_BLE, "both ends request establish connection at the same time, connId=%u, it will reused "
              "after connect failed, peer addr=%s",
            connectionId, anomizeAddress);
    }

    ConnBleDevice *it = NULL;
    ConnBleDevice *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_bleManager.waitings, ConnBleDevice, node) {
        if ((StrCmpIgnoreCase(it->addr, connection->addr) == 0 || IsSameDevice(it->udid, connection->udid))) {
            if (BleReuseConnection(it, connection)) {
                ListDelete(&it->node);
                FreeDevice(it);
            }
        }
    }
    ConnBleReturnConnection(&connection);
}

// connectionClosed
static void BleConnectionClosed(uint32_t connectionId, int32_t error)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "connection not exist, connId=%u", connectionId);

    ConnBleDevice *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleManager.waitings, ConnBleDevice, node) {
        if (StrCmpIgnoreCase(it->addr, connection->addr) == 0 || IsSameDevice(it->udid, connection->udid)) {
            it->state = BLE_DEVICE_STATE_WAIT_SCHEDULE;
        }
    }
    ConnectionInfo info = { 0 };
    int32_t status = BleConvert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert ble connection info failed, err=%d. It cann't backoff now, just ahead.", status);
    }
    char udidHashStr[HEXIFY_LEN(UDID_HASH_LEN)] = { 0 };
    status = ConvertBytesToHexString(
        udidHashStr, HEXIFY_LEN(UDID_HASH_LEN), (unsigned char *)info.bleInfo.deviceIdHash, UDID_HASH_LEN);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert udid hash to string failed, err=%d. It cann't backoff now, just ahead.", status);
    }
    if (connection->protocol == BLE_GATT) {
        SoftbusBleConflictNotifyDisconnect(connection->addr, udidHashStr);
    }
    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_NEXT_CMD, 0, 0, NULL, 0);
    g_connectCallback.OnDisconnected(connectionId, &info);
}

// connectionResume
static void BleConnectionResume(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "ble connection resume handle failed: connection not exist, connId=%u", connectionId);

    ConnBleDevice *it = NULL;
    ConnBleDevice *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_bleManager.waitings, ConnBleDevice, node) {
        if (it->protocol == connection->protocol &&
            (StrCmpIgnoreCase(it->addr, connection->addr) == 0 || IsSameDevice(it->udid, connection->udid))) {
            if (BleReuseConnection(it, connection)) {
                ListDelete(&it->node);
                FreeDevice(it);
            }
        }
    }

    ConnBleReturnConnection(&connection);
}

// disconnectRequest
static void BleDisconnectRequest(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "connection is not exist, connId=%u", connectionId);
    ConnBleUpdateConnectionRc(connection, 0, -1);
    ConnBleReturnConnection(&connection);
}

// dataReceived
static void BleDataReceived(ConnBleDataReceivedContext *ctx)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(ctx->connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "connection not exist, is it removed? connId=%u",
            ctx->connectionId);
        SoftBusFree(ctx->data);
        return;
    }

    do {
        if (!ctx->isConnCharacteristic) {
            CONN_LOGI(CONN_BLE, "ble dispatch receive data, none conn data, connId=%u, data length=%u",
                connection->connectionId, ctx->dataLen);
            g_connectCallback.OnDataReceived(ctx->connectionId, MODULE_BLE_NET, 0, (char *)ctx->data, ctx->dataLen);
            break;
        }

        ConnPktHead *head = (ConnPktHead *)ctx->data;
        UnpackConnPktHead(head);
        CONN_LOGI(CONN_BLE, "ble dispatch receive data, connId=%u, payload (Len/Flg/Module/Seq)=(%u/%d/%d/%" PRId64 ")",
            connection->connectionId, ctx->dataLen, head->flag, head->module, head->seq);
        uint32_t pktHeadLen = ConnGetHeadSize();
        if (head->module == MODULE_CONNECTION) {
            ReceivedControlData(connection, ctx->data + pktHeadLen, ctx->dataLen - pktHeadLen);
        } else if (head->module == MODULE_OLD_NEARBY) {
            SoftbusBleConflictNotifyDateReceive(
                connection->underlayerHandle, ctx->data + pktHeadLen, ctx->dataLen - pktHeadLen);
        } else {
            g_connectCallback.OnDataReceived(
                ctx->connectionId, (ConnModule)head->module, head->seq, (char *)ctx->data, ctx->dataLen);
        }
    } while (false);

    SoftBusFree(ctx->data);
    ctx->data = NULL;
    ConnBleReturnConnection(&connection);
}

static void ReceivedControlData(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen)
{
    cJSON *json = cJSON_ParseWithLength((const char *)data, dataLen);
    if (json == NULL) {
        CONN_LOGE(CONN_BLE, "connId:%u, parse json failed.", connection->connectionId);
        return;
    }

    int32_t method = 0;
    if (!GetJsonObjectNumberItem(json, CTRL_MSG_KEY_METHOD, &method)) {
        CONN_LOGE(CONN_BLE, "connId:%u, parse method failed", connection->connectionId);
        cJSON_Delete(json);
        return;
    }
    CONN_LOGD(CONN_BLE, "ble receive control data, connId=%u, method=%d", connection->connectionId, method);
    int32_t status = SOFTBUS_OK;
    switch (method) {
        case METHOD_NOTIFY_REQUEST:
            status = ConnBleOnReferenceRequest(connection, json);
            break;
        default:
            CONN_LOGE(CONN_BLE, "connection %u received control message, UNSUPPORT method, method=%d",
                connection->connectionId, method);
            break;
    }
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "connId:%u, unexpected error, method=%d, err=%d", connection->connectionId, method, status);
    }
    cJSON_Delete(json);
}

static int32_t BleReuseConnectionCommon(const char *udid, const char *anomizeAddress, ProtocolType protocol)
{
    ConnBleConnection *connection = ConnBleGetClientConnectionByUdid(udid, (BleProtocolType)protocol);
    if (connection == NULL) {
        return SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR;
    }
    if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock failed, connId=%u, addr=%s", connection->connectionId, anomizeAddress);
        ConnBleReturnConnection(&connection);
        return SOFTBUS_LOCK_ERR;
    }
    enum ConnBleConnectionState state = connection->state;
    int32_t underlayerHandle = connection->underlayerHandle;
    (void)SoftBusMutexUnlock(&connection->lock);
    int32_t status = SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR;
    if (state == BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO) {
        status = ConnBleUpdateConnectionRc(connection, 0, 1); /* no need challenge, set default value 0 */
    }
    CONN_LOGI(CONN_BLE, "reuse connection, connId=%u, state=%d, addr=%s, status=%d", connection->connectionId, state,
        anomizeAddress, status);
    ConnBleReturnConnection(&connection);
    if (status == SOFTBUS_OK) {
        return underlayerHandle;
    }
    return status;
}

static void BleReuseConnectionRequestOnAvailableState(const ConnBleReuseConnectionContext *ctx)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, ctx->addr, BT_MAC_LEN);
    int32_t result = BleReuseConnectionCommon(ctx->udid, anomizeAddress, ctx->protocol);
    ctx->waitResult->result = result;
    sem_post(&ctx->waitResult->wait);
}

static void ConflictOnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "conn not exist, connId=%u", connectionId);
    int32_t underlayHandle = connection->underlayerHandle;
    ConnBleReturnConnection(&connection);
    SoftbusBleConflictNotifyConnectResult(requestId, underlayHandle, true);
}

static void ConflictOnConnectFailed(uint32_t requestId, int32_t reason)
{
    (void)reason;
    SoftbusBleConflictNotifyConnectResult(requestId, INVALID_UNDERLAY_HANDLE, false);
}

static void BleReuseConnectionRequestOnConnectingState(const ConnBleReuseConnectionContext *ctx)
{
    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, ctx->addr, BT_MAC_LEN);
    int32_t result = BleReuseConnectionCommon(ctx->udid, anomizeAddress, ctx->protocol);
    if (result != SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR) {
        ctx->waitResult->result = result;
        sem_post(&ctx->waitResult->wait);
        return;
    }

    if ((BleProtocolType)ctx->protocol != g_bleManager.connecting->protocol ||
        !IsSameDevice(ctx->udid, g_bleManager.connecting->udid)) {
        ctx->waitResult->result = SOFTBUS_ERR;
        sem_post(&ctx->waitResult->wait);
        return;
    }

    // merge connect request
    ConnBleRequest *request = (ConnBleRequest *)SoftBusCalloc(sizeof(ConnBleRequest));
    if (request == NULL) {
        ctx->waitResult->result = SOFTBUS_MALLOC_ERR;
        sem_post(&ctx->waitResult->wait);
        return;
    }
    ListInit(&request->node);
    request->requestId = ctx->requestId;
    request->result.OnConnectSuccessed = ConflictOnConnectSuccessed;
    request->result.OnConnectFailed = ConflictOnConnectFailed;
    ListAdd(&g_bleManager.connecting->requests, &request->node);
    ctx->waitResult->result = CONFLICT_REUSE_CONNECTING;
    sem_post(&ctx->waitResult->wait);
}

static void BlePreventTimeout(const char *udid)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleManager.prevents->lock) == SOFTBUS_OK, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! ble prevent timeout handle failed: try to lock failed");
    do {
        size_t udidLen = strlen(udid);
        BlePrevent *it = NULL;
        BlePrevent *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_bleManager.prevents->list, BlePrevent, node) {
            if (udidLen == strlen((char *)it->udid) && memcmp(udid, it->udid, udidLen) == 0) {
                ListDelete(&it->node);
                SoftBusFree(it);
            }
        }
    } while (false);
    (void)SoftBusMutexUnlock(&g_bleManager.prevents->lock);
}

static void BleReset(int32_t reason)
{
    CONN_LOGW(CONN_BLE, "ble manager start process RESET event, reason=%d", reason);
    if (g_bleManager.connecting != NULL) {
        ConnBleConnection *connection = ConnBleGetConnectionByAddr(
            g_bleManager.connecting->addr, CONN_SIDE_CLIENT, g_bleManager.connecting->protocol);
        if (connection != NULL) {
            ConnRemoveMsgFromLooper(
                &g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_TIMEOUT, connection->connectionId, 0, NULL);
            ConnBleReturnConnection(&connection);
        }
        BleNotifyDeviceConnectResult(g_bleManager.connecting, NULL, SOFTBUS_CONN_BLUETOOTH_OFF);
        FreeDevice(g_bleManager.connecting);
        g_bleManager.connecting = NULL;
    }
    ConnBleDevice *deviceIt = NULL;
    ConnBleDevice *deviceNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(deviceIt, deviceNext, &g_bleManager.waitings, ConnBleDevice, node) {
        ListDelete(&deviceIt->node);
        BleNotifyDeviceConnectResult(deviceIt, NULL, SOFTBUS_CONN_BLUETOOTH_OFF);
        FreeDevice(deviceIt);
    }

    int32_t status = SoftBusMutexLock(&g_bleManager.prevents->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock prevents failed, err=%d", status);
        return;
    }
    BlePrevent *preventIt = NULL;
    BlePrevent *preventNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(preventIt, preventNext, &g_bleManager.prevents->list, BlePrevent, node) {
        ConnRemoveMsgFromLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_PREVENT_TIMEOUT, 0, 0, preventIt->udid);
        ListDelete(&preventIt->node);
        SoftBusFree(preventIt);
        g_bleManager.prevents->cnt--;
    }
    SoftBusMutexUnlock(&g_bleManager.prevents->lock);

    status = SoftBusMutexLock(&g_bleManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock connections failed, err=%d", status);
        return;
    }
    ConnBleConnection *connectionIt = NULL;
    LIST_FOR_EACH_ENTRY(connectionIt, &g_bleManager.connections->list, ConnBleConnection, node) {
        // MUST NOT remove connection, connection close notify will cleanup
        ConnBleDisconnectNow(connectionIt, BLE_DISCONNECT_REASON_RESET);
    }
    SoftBusMutexUnlock(&g_bleManager.connections->lock);
    TransitionToState(BLE_MGR_STATE_AVAILABLE);
}

static uint32_t AllocateConnectionIdUnsafe()
{
    static uint16_t nextId = 0;
    uint32_t connectionId = (CONNECT_BLE << CONNECT_TYPE_SHIFT) + (++nextId);
    ConnBleConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleManager.connections->list, ConnBleConnection, node) {
        if (connectionId == it->connectionId) {
            return 0;
        }
    }
    return connectionId;
}

int32_t ConnBleSaveConnection(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "invalid param, ble connection is null");

    int32_t status = SoftBusMutexLock(&g_bleManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGW(CONN_BLE, "try to get ble manager connections lock failed, err=%d", status);
        return status;
    }
    uint32_t connectionId = 0;
    do {
        connectionId = AllocateConnectionIdUnsafe();
    } while (connectionId == 0);

    connection->connectionId = connectionId;
    connection->objectRc += 1;
    ListAdd(&g_bleManager.connections->list, &connection->node);
    (void)SoftBusMutexUnlock(&g_bleManager.connections->lock);
    return SOFTBUS_OK;
}

void ConnBleRemoveConnection(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "invalid param, connection is null");
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleManager.connections->lock) == SOFTBUS_OK, CONN_BLE,
        "try to get ble manager connections lock failed");
    bool exist = false;
    ConnBleConnection *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleManager.connections->list, ConnBleConnection, node) {
        if (it->connectionId == connection->connectionId) {
            exist = true;
            break;
        }
    }
    if (exist) {
        ListDelete(&connection->node);
        ConnBleReturnConnection(&connection);
    } else {
        CONN_LOGW(CONN_BLE, "ble connection %u is not exist in global connection list, call remove duplicate?",
            connection->connectionId);
    }
    (void)SoftBusMutexUnlock(&g_bleManager.connections->lock);
}

static bool ConnectionCompareByConnectId(ConnBleConnection *connection, const BleConnectionCompareOption *option)
{
    return connection->connectionId == option->connectionIdOption.connectionId;
}

static bool ConnectionCompareByAddress(ConnBleConnection *connection, const BleConnectionCompareOption *option)
{
    return StrCmpIgnoreCase(connection->addr, option->addressOption.addr) == 0 &&
        (option->addressOption.side == CONN_SIDE_ANY ? true : connection->side == option->addressOption.side) &&
        ((BleProtocolType)option->addressOption.protocol == BLE_PROTOCOL_ANY ? true :
            connection->protocol == (BleProtocolType)option->addressOption.protocol);
}

static bool ConnectionCompareByUnderlayHandle(ConnBleConnection *connection, const BleConnectionCompareOption *option)
{
    return connection->underlayerHandle == option->underlayerHandleOption.underlayerHandle &&
        (option->underlayerHandleOption.side == CONN_SIDE_ANY ?
                true :
                connection->side == option->underlayerHandleOption.side) &&
        ((BleProtocolType)option->underlayerHandleOption.protocol == BLE_PROTOCOL_ANY ? true :
        connection->protocol == (BleProtocolType)option->underlayerHandleOption.protocol);
}

static bool ConnectionCompareByUdidDiffAddress(ConnBleConnection *connection, const BleConnectionCompareOption *option)
{
    ConnBleInnerComplementDeviceId(connection);
    return StrCmpIgnoreCase(connection->addr, option->udidAddressOption.addr) != 0 &&
        IsSameDevice(connection->udid, option->udidAddressOption.udid) &&
        ((BleProtocolType)option->udidAddressOption.protocol == BLE_PROTOCOL_ANY ? true :
        connection->protocol == (BleProtocolType)option->udidAddressOption.protocol);
}

static bool ConnectionCompareByUdidClientSide(ConnBleConnection *connection, const BleConnectionCompareOption *option)
{
    ConnBleInnerComplementDeviceId(connection);
    return connection->side == CONN_SIDE_CLIENT && IsSameDevice(connection->udid, option->udidClientOption.udid) &&
        ((BleProtocolType)option->udidClientOption.protocol == BLE_PROTOCOL_ANY ? true :
        connection->protocol == option->udidClientOption.protocol);
}

static ConnBleConnection *GetConnectionByOption(const BleConnectionCompareOption *option)
{
    BleConnectionCompareFunc compareFunc = NULL;
    switch (option->type) {
        case BLE_CONNECTION_COMPARE_TYPE_CONNECTION_ID:
            compareFunc = ConnectionCompareByConnectId;
            break;
        case BLE_CONNECTION_COMPARE_TYPE_ADDRESS:
            compareFunc = ConnectionCompareByAddress;
            break;
        case BLE_CONNECTION_COMPARE_TYPE_UNDERLAY_HANDLE:
            compareFunc = ConnectionCompareByUnderlayHandle;
            break;
        case BLE_CONNECTION_COMPARE_TYPE_UDID_DIFF_ADDRESS:
            compareFunc = ConnectionCompareByUdidDiffAddress;
            break;
        case BLE_CONNECTION_COMPARE_TYPE_UDID_CLIENT_SIDE:
            compareFunc = ConnectionCompareByUdidClientSide;
            break;
        default:
            CONN_LOGW(CONN_BLE, "there is no compare function implement for unkown type, type=%d", option->type);
            return NULL;
    }
    int32_t status = SoftBusMutexLock(&g_bleManager.connections->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to get manager connections lock failed, err=%d", status);
        return NULL;
    }
    ConnBleConnection *it = NULL;
    ConnBleConnection *target = NULL;
    LIST_FOR_EACH_ENTRY(it, &g_bleManager.connections->list, ConnBleConnection, node) {
        if (compareFunc(it, option)) {
            target = it;
            break;
        }
    }
    if (target != NULL) {
        status = SoftBusMutexLock(&target->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to get connection lock failed, err=%d", status);
            SoftBusMutexUnlock(&g_bleManager.connections->lock);
            return NULL;
        }
        target->objectRc += 1;
        SoftBusMutexUnlock(&target->lock);
    }
    SoftBusMutexUnlock(&g_bleManager.connections->lock);
    return target;
}

ConnBleConnection *ConnBleGetConnectionByAddr(const char *addr, ConnSideType side, BleProtocolType protocol)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(addr != NULL, NULL, CONN_BLE, "invalid param, ble addr is null");
    BleConnectionCompareOption option = {
        .type = BLE_CONNECTION_COMPARE_TYPE_ADDRESS,
        .addressOption = {
            .addr = addr,
            .side = side,
            .protocol = protocol,
        },
    };
    return GetConnectionByOption(&option);
}

ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId)
{
    BleConnectionCompareOption option = {
        .type = BLE_CONNECTION_COMPARE_TYPE_CONNECTION_ID,
        .connectionIdOption = {
            .connectionId = connectionId,
        },
    };
    return GetConnectionByOption(&option);
}

ConnBleConnection *ConnBleGetConnectionByHandle(int32_t underlayerHandle, ConnSideType side, BleProtocolType protocol)
{
    BleConnectionCompareOption option = {
        .type = BLE_CONNECTION_COMPARE_TYPE_UNDERLAY_HANDLE,
        .underlayerHandleOption = {.underlayerHandle = underlayerHandle, .side = side, .protocol = protocol},
    };
    return GetConnectionByOption(&option);
}

ConnBleConnection *ConnBleGetConnectionByUdid(const char *addr, const char *udid, BleProtocolType protocol)
{
    BleConnectionCompareOption option = {
        .type = BLE_CONNECTION_COMPARE_TYPE_UDID_DIFF_ADDRESS,
        .udidAddressOption = {
            .addr = addr,
            .udid = udid,
            .protocol = protocol,
        },
    };
    return GetConnectionByOption(&option);
}

ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol)
{
    BleConnectionCompareOption option = {
        .type = BLE_CONNECTION_COMPARE_TYPE_UDID_CLIENT_SIDE,
        .udidClientOption = {
            .udid = udid,
            .protocol = protocol,
        },
    };
    return GetConnectionByOption(&option);
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "invalid param, ble connnetion is null");
    CONN_CHECK_AND_RETURN_LOGW(*connection != NULL, CONN_BLE,
        "invalid param, ble *connnetion is null, use after return or remove action?");

    ConnBleConnection *underlayer = *connection;
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&underlayer->lock) == SOFTBUS_OK, CONN_BLE,
        "ble connection %u lock failed", underlayer->connectionId);
    underlayer->objectRc -= 1;
    int32_t objectRc = underlayer->objectRc;
    SoftBusMutexUnlock(&underlayer->lock);
    if (objectRc <= 0) {
        CONN_LOGI(CONN_BLE, "release ble connection %u", underlayer->connectionId);
        ConnBleFreeConnection(*connection);
    }
    *connection = NULL;
}

void NotifyReusedConnected(uint32_t connectionId, uint16_t challengeCode)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "connection not exist, connId=%u", connectionId);

    ConnectionInfo info = { 0 };
    int32_t status = BleConvert2ConnectionInfo(connection, &info);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert connection info failed, err=%d. It can not backoff now, just ahead.", status);
    }
    info.bleInfo.challengeCode = challengeCode;
    g_connectCallback.OnReusedConnected(connectionId, &info);
}

static void TransitionToState(enum BleMgrState target)
{
    static ConnBleState statesTable[BLE_MGR_STATE_MAX] = {
        [BLE_MGR_STATE_AVAILABLE] = {
            .name = BleNameAvailableState,
            .enter = BleEnterAvailableState,
            .exit = BleExitAvailableState,
            .connectRequest = BleConnectRequestOnAvailableState,
            .handlePendingRequest = BleHandlePendingRequestOnAvailableState,
            .serverAccepted = BleServerAccepted,
            .clientConnected = BleClientConnected,
            .clientConnectFailed = BleClientConnectFailed,
            .clientConnectTimeout = NULL,
            .dataReceived = BleDataReceived,
            .connectionClosed = BleConnectionClosed,
            .connectionResume = BleConnectionResume,
            .disconnectRequest = BleDisconnectRequest,
            .reuseConnectionRequest = BleReuseConnectionRequestOnAvailableState,
            .preventTimeout = BlePreventTimeout,
            .reset = BleReset,
        },
        [BLE_MGR_STATE_CONNECTING] = {
            .name = BleNameConnectingState,
            .enter = BleEnterConnectingState,
            .exit = BleExitConnectingState,
            .connectRequest = BleConnectRequestOnConnectingState,
            .handlePendingRequest = NULL,
            .serverAccepted = BleServerAccepted,
            .clientConnected = BleClientConnected,
            .clientConnectFailed = BleClientConnectFailed,
            .clientConnectTimeout = BleClientConnectTimeoutOnConnectingState,
            .dataReceived = BleDataReceived,
            .connectionClosed = BleConnectionClosed,
            .connectionResume = BleConnectionResume,
            .disconnectRequest = BleDisconnectRequest,
            .reuseConnectionRequest = BleReuseConnectionRequestOnConnectingState,
            .preventTimeout = BlePreventTimeout,
            .reset = BleReset,
        },
    };

    if (g_bleManager.state == statesTable + target) {
        return;
    }
    if (g_bleManager.state != NULL) {
        g_bleManager.state->exit();
    }
    g_bleManager.state = statesTable + target;
    g_bleManager.state->enter();
}

static void BleManagerMsgHandler(SoftBusMessage *msg)
{
    CONN_LOGI(CONN_BLE, "ble manager looper recieve msg %d, current state is '%s'", msg->what,
        g_bleManager.state->name());
    switch (msg->what) {
        case BLE_MGR_MSG_NEXT_CMD: {
            if (g_bleManager.state->handlePendingRequest != NULL) {
                g_bleManager.state->handlePendingRequest();
                return;
            }
            break;
        }
        case BLE_MGR_MSG_CONNECT_REQUEST: {
            ConnBleConnectRequestContext *ctx = (ConnBleConnectRequestContext *)msg->obj;
            if (g_bleManager.state->connectRequest != NULL) {
                g_bleManager.state->connectRequest(ctx);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_CONNECT_SUCCESS: {
            if (g_bleManager.state->clientConnected != NULL) {
                g_bleManager.state->clientConnected((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_CONNECT_TIMEOUT: {
            if (g_bleManager.state->clientConnectTimeout != NULL) {
                g_bleManager.state->clientConnectTimeout((uint32_t)msg->arg1, (char *)msg->obj);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_CONNECT_FAIL: {
            BleStatusContext *ctx = (BleStatusContext *)msg->obj;
            if (g_bleManager.state->clientConnectFailed != NULL) {
                g_bleManager.state->clientConnectFailed(ctx->connectionId, ctx->status);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_SERVER_ACCEPTED: {
            if (g_bleManager.state->serverAccepted != NULL) {
                g_bleManager.state->serverAccepted((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_DATA_RECEIVED: {
            ConnBleDataReceivedContext *ctx = (ConnBleDataReceivedContext *)msg->obj;
            if (g_bleManager.state->dataReceived != NULL) {
                g_bleManager.state->dataReceived(ctx);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_CONNECTION_CLOSED: {
            BleStatusContext *ctx = (BleStatusContext *)msg->obj;
            if (g_bleManager.state->connectionClosed != NULL) {
                g_bleManager.state->connectionClosed(ctx->connectionId, ctx->status);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_CONNECTION_RESUME: {
            if (g_bleManager.state->connectionResume != NULL) {
                g_bleManager.state->connectionResume((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_DISCONNECT_REQUEST: {
            if (g_bleManager.state->disconnectRequest != NULL) {
                g_bleManager.state->disconnectRequest((uint32_t)msg->arg1);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_REUSE_CONNECTION_REQUEST: {
            ConnBleReuseConnectionContext *ctx = (ConnBleReuseConnectionContext *)msg->obj;
            if (g_bleManager.state->reuseConnectionRequest != NULL) {
                g_bleManager.state->reuseConnectionRequest(ctx);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_PREVENT_TIMEOUT: {
            char *udid = (char *)msg->obj;
            if (g_bleManager.state->preventTimeout != NULL) {
                g_bleManager.state->preventTimeout(udid);
                return;
            }
            break;
        }
        case BLE_MGR_MSG_RESET: {
            BleStatusContext *ctx = (BleStatusContext *)msg->obj;
            if (g_bleManager.state->reset != NULL) {
                g_bleManager.state->reset(ctx->status);
                return;
            }
            break;
        }
        default:
            CONN_LOGW(CONN_BLE, "ble manager looper receive unexpected msg, what=%d, just ignore, FIX it quickly.",
                msg->what);
            break;
    }
    CONN_LOGW(CONN_BLE, "ble manager looper ignore handle %d message,  current state is '%s'", msg->what,
        g_bleManager.state->name());
}

static int BleCompareManagerLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case BLE_MGR_MSG_CONNECT_TIMEOUT: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        case BLE_MGR_MSG_PREVENT_TIMEOUT: {
            if (memcmp(msg->obj, ctx->obj, UDID_BUF_LEN) == 0) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CONN_LOGE(CONN_BLE, "there is compare context value not use, forgot implement? "
              "compare failed to avoid fault silence, what=%d, arg1=%" PRIu64 ", arg2=%" PRIu64 ", obj is null? %d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static int32_t BleConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connect device failed: option is null, reqId=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BLE, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connect device failed: not ble connect type, reqId=%u, type: %d", requestId, option->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(result != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connect device failed: result callback is null, reqId=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOGW(result->OnConnectSuccessed != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connect device failed: result callback OnConnectSuccessed is null, reqId=%u", requestId);
    CONN_CHECK_AND_RETURN_RET_LOGW(result->OnConnectFailed != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connect device failed: result callback onConnectFailed is null, reqId=%u", requestId);

    // only use first SHORT_UDID_HASH_LEN bytes hash, keep same with share
    char udidHashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    int32_t status = ConvertBytesToHexString(udidHashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN),
        (unsigned char *)option->bleOption.deviceIdHash, SHORT_UDID_HASH_LEN);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connect device failed: convert device id hash to string failed, reqId=%u, err=%d", requestId, status);

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, option->bleOption.bleMac, BT_MAC_LEN);
    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, udidHashStr);

    ConnBleConnectRequestContext *ctx =
        (ConnBleConnectRequestContext *)SoftBusCalloc(sizeof(ConnBleConnectRequestContext));
    CONN_CHECK_AND_RETURN_RET_LOGE(ctx != NULL, SOFTBUS_MEM_ERR, CONN_BLE,
        "calloc connect request context object failed: reqId=%u, addr=%s, udid=%s", requestId, anomizeAddress,
        anomizeUdid);
    ctx->statistics.startTime = SoftBusGetSysTimeMs();
    ctx->statistics.connectTraceId = SoftbusGetConnectTraceId();
    ctx->requestId = requestId;
    if (strcpy_s(ctx->addr, BT_MAC_LEN, option->bleOption.bleMac) != EOK ||
        strcpy_s(ctx->udid, UDID_BUF_LEN, udidHashStr) != EOK) {
        CONN_LOGE(CONN_BLE, "strcpy_s address or device identifier failed, reqId=%u, addr=%s, udid=%s",
            requestId, anomizeAddress, anomizeUdid);
        SoftBusFree(ctx);
        return SOFTBUS_STRCPY_ERR;
    }
    ctx->fastestConnectEnable = option->bleOption.fastestConnectEnable;
    ctx->result = *result;
    //keep compatibility if protocol is undefined
    if (option->bleOption.protocol != BLE_GATT && option -> bleOption.protocol != BLE_COC) {
        CONN_LOGW(CONN_BLE, "ble connect device warning, protocol=%d is unknown, use GATT forcely",
            option->bleOption.protocol);
        ctx->protocol = BLE_GATT;
        ctx->psm = 0;
    } else {
        ctx->protocol = option->bleOption.protocol;
        ctx->psm = option->bleOption.psm;
    }
    ctx->challengeCode = option->bleOption.challengeCode;
    status = ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_REQUEST, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post connect msg to manager looper failed, reqId=%u, addr=%s, udid=%s, err=%d",
            requestId, anomizeAddress, anomizeUdid, status);
        SoftBusFree(ctx);
        return status;
    }
    CONN_LOGI(CONN_BLE, "ble connect device: receive connect request, reqId=%u, addr=%s, protocol=%d, udid=%s, "
        "fastest connect enable=%d, connectTraceId=%u",
        requestId, anomizeAddress, ctx->protocol, anomizeUdid, ctx->fastestConnectEnable,
        ctx->statistics.connectTraceId);
    return SOFTBUS_OK;
}

static int32_t ConnBlePostBytes(
    uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid, int32_t flag, int32_t module, int64_t seq)
{
    return ConnBlePostBytesInner(connectionId, data, dataLen, pid, flag, module, seq, NULL);
}

static int32_t BleDisconnectDevice(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, CONN_BLE,
        "ble disconnect device failed: connection is not exist, reqId=%u", connectionId);
    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, connection->addr, BT_MAC_LEN);
    ConnBleReturnConnection(&connection);

    int32_t status =
        ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_DISCONNECT_REQUEST, connectionId, 0, NULL, 0);
    CONN_LOGI(CONN_BLE, "ble disconnect device, connId=%u, addr=%s, status=%d", connectionId, animizeAddress, status);
    return status;
}

static int32_t BleDisconnectDeviceNow(const ConnectOption *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble disconnect device now failed: invaliad param, option is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BLE, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble disconnect device now failed: invaliad param, not ble connect type type: %d", option->type);

    char animizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(animizeAddress, BT_MAC_LEN, option->bleOption.bleMac, BT_MAC_LEN);
    CONN_LOGI(CONN_BLE, "ble disconnect device now, addr=%s", animizeAddress);

    ConnBleConnection *connection =
        ConnBleGetConnectionByAddr(option->bleOption.bleMac, CONN_SIDE_ANY, option->bleOption.protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, CONN_BLE,
        "ble disconnect device now failed: connection is not exist");

    int32_t status = ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_FORCELY);
    ConnBleReturnConnection(&connection);
    return status;
}

static int32_t BleGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(info != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "invaliad param, info is null");
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, CONN_BLE,
        "connection is not exist, connId=%u", connectionId);

    int32_t status = BleConvert2ConnectionInfo(connection, info);
    ConnBleReturnConnection(&connection);
    return status;
}

static int32_t BleStartLocalListening(const LocalListenerInfo *info)
{
    (void)info;
    return ConnBleStartServer();
}

static int32_t BleStopLocalListening(const LocalListenerInfo *info)
{
    (void)info;
    return ConnBleStopServer();
}

static bool BleCheckActiveConnection(const ConnectOption *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, false, CONN_BLE, "invaliad param, option is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BLE, false, CONN_BLE,
        "invaliad param, option->type is not ble, type=%d", option->type);
    char hashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    if (ConvertBytesToHexString(hashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN),
        (unsigned char *)option->bleOption.deviceIdHash, SHORT_UDID_HASH_LEN) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "convert bytes to array failed");
        return false;
    }
    ConnBleConnection *connection = ConnBleGetConnectionByUdid(NULL, hashStr, option->bleOption.protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, false, CONN_BLE,
        "ble check action connection: connection is not exist");
    bool isActive = (connection->state == BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO);

    ConnBleReturnConnection(&connection);
    return isActive;
}

static int32_t BleUpdateConnection(uint32_t connectionId, UpdateOption *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "invaliad param, option is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_BLE, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "invaliad param, not ble connect type type: %d", option->type);

    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, CONN_BLE,
        "connection is not exist, connId=%u", connectionId);

    int32_t status = ConnBleUpdateConnectionPriority(connection, option->bleOption.priority);
    ConnBleReturnConnection(&connection);
    return status;
}

static void OnServerAccepted(uint32_t connectionId)
{
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_SERVER_ACCEPTED, connectionId, 0, NULL, 0);
}

static void OnConnected(uint32_t connectionId)
{
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_SUCCESS, connectionId, 0, NULL, 0);
}

static void OnConnectFailed(uint32_t connectionId, int32_t error)
{
    CONN_LOGW(CONN_BLE, "receive ble client connect failed notify, connId=%u, err=%d", connectionId, error);
    BleStatusContext *ctx = (BleStatusContext *)SoftBusCalloc(sizeof(BleStatusContext));
    CONN_CHECK_AND_RETURN_LOGW(ctx != NULL, CONN_BLE, "on connect failed failed, calloc error context failed");
    ctx->connectionId = connectionId;
    ctx->status = error;
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECT_FAIL, 0, 0, ctx, 0);
}

static void OnDataReceived(uint32_t connectionId, bool isConnCharacteristic, uint8_t *data, uint32_t dataLen)
{
    ConnBleDataReceivedContext *ctx = (ConnBleDataReceivedContext *)SoftBusCalloc(sizeof(ConnBleDataReceivedContext));
    if (ctx == NULL) {
        CONN_LOGE(CONN_BLE, "calloc data received context failed, connId=%u, conn characteristic=%d, data len=%u",
            connectionId, isConnCharacteristic, dataLen);
        SoftBusFree(data);
        return;
    }
    ctx->connectionId = connectionId;
    ctx->isConnCharacteristic = isConnCharacteristic;
    ctx->data = data;
    ctx->dataLen = dataLen;
    int32_t status = ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_DATA_RECEIVED, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post msg to looper failed, connId=%u, conn characteristic=%d, data len=%u", connectionId,
            isConnCharacteristic, dataLen);
        SoftBusFree(data);
        SoftBusFree(ctx);
    }
}

static void OnConnectionClosed(uint32_t connectionId, int32_t status)
{
    BleStatusContext *ctx = (BleStatusContext *)SoftBusCalloc(sizeof(BleStatusContext));
    CONN_CHECK_AND_RETURN_LOGW(ctx != NULL, CONN_BLE, "on connect failed failed, calloc error context failed");
    ctx->connectionId = connectionId;
    ctx->status = status;
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECTION_CLOSED, 0, 0, ctx, 0);
}

static void OnConnectionResume(uint32_t connectionId)
{
    ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_CONNECTION_RESUME, connectionId, 0, NULL, 0);
}

static void onPostBytesFinished(
    uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error)
{
    CONN_LOGD(CONN_BLE, "ble post bytes finished, connId=%u, pid=%u, payload (Len/Flg/Module/Seq)="
        "(%u/%d/%d/%" PRId64 "), err=%d", connectionId, pid, len, flag, module, seq, error);

    if (error != SOFTBUS_OK) {
        ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
        if (connection == NULL) {
            // maybe fail reason is that connection not exist, so log level is warning
            CONN_LOGW(CONN_BLE, "ble post bytes finished, send failed, connection not exist, connId=%u",
                connectionId);
            return;
        }
        ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_POST_BYTES_FAILED);
        ConnBleReturnConnection(&connection);
    }
}

static void OnBtStateChanged(int listenerId, int state)
{
    (void)listenerId;
    int32_t status = SOFTBUS_OK;
    if (state == SOFTBUS_BT_STATE_TURN_ON) {
        status = ConnBleStartServer();
        CONN_LOGI(CONN_BLE, "ble manager receive bt on event, start server, status=%d", status);
        return;
    }

    if (state == SOFTBUS_BT_STATE_TURN_OFF) {
        status = ConnBleStopServer();
        CONN_LOGI(CONN_BLE, "ble manager receive bt off event, stop server, status=%d", status);
        BleStatusContext *ctx = (BleStatusContext *)SoftBusCalloc(sizeof(BleStatusContext));
        if (ctx == NULL) {
            CONN_LOGE(CONN_BLE, "ble manager receive bt off event, send reset event failed: calloc ctx object "
                "failed");
            return;
        }
        ctx->status = SOFTBUS_CONN_BLUETOOTH_OFF;
        status = ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_RESET, 0, 0, ctx, 0);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "ble manager receive bt off event, send reset event failed: post msg to looper "
                "failed");
            SoftBusFree(ctx);
        }
        return;
    }
}

// reuse connected or connecting connection, MUST NOT request connect
static int32_t ConflictReuseConnection(const char *address, const char *udid, uint32_t requestId)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(address != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "conflict reuse connection failed: invalid param, address is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(udid != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "conflict reuse connection failed: invalid param, udid is null");

    char anomizeAddress[BT_MAC_LEN] = { 0 };
    ConvertAnonymizeMacAddress(anomizeAddress, BT_MAC_LEN, address, BT_MAC_LEN);
    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, udid);
    CONN_LOGW(CONN_BLE, "conflict reuse connection, receive reuse request, reqId=%u, addr=%s, udid=%s",
        requestId, anomizeAddress, anomizeUdid);

    ConnBleReuseConnectionContext *ctx =
        (ConnBleReuseConnectionContext *)SoftBusCalloc(sizeof(ConnBleReuseConnectionContext));
    ConnBleReuseConnectionWaitResult *waitResult =
        (ConnBleReuseConnectionWaitResult *)SoftBusCalloc(sizeof(ConnBleReuseConnectionWaitResult));
    if (ctx == NULL || waitResult == NULL) {
        CONN_LOGE(CONN_BLE, "calloc reuse connect objects failed, reqId=%u, addr=%s, udid=%s",
            requestId, anomizeAddress, anomizeUdid);
        SoftBusFree(ctx);
        SoftBusFree(waitResult);
        return SOFTBUS_MALLOC_ERR;
    }

    size_t addressLen = strlen(address);
    size_t udidLen = strlen(udid);
    if (memcpy_s(ctx->addr, BT_MAC_LEN - 1, address, addressLen) != EOK ||
        memcpy_s(ctx->udid, UDID_BUF_LEN - 1, udid, udidLen) != EOK) {
        CONN_LOGE(CONN_BLE, "memcpy_s address or udid failed, address len=%u, udid len=%u, reqId=%u, addr=%s, "
            "udid=%s", addressLen, udidLen, requestId, anomizeAddress, anomizeUdid);
        SoftBusFree(ctx);
        SoftBusFree(waitResult);
        return SOFTBUS_MEM_ERR;
    }
    ctx->requestId = requestId;

    if (sem_init(&waitResult->wait, 0, 0) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "init wait semaphore failed, reqId=%u, addr=%s, udid=%s",
            requestId, anomizeAddress, anomizeUdid);
        SoftBusFree(ctx);
        SoftBusFree(waitResult);
        return SOFTBUS_ERR;
    }
    ctx->waitResult = waitResult;
    ctx->protocol = BLE_GATT;
    int32_t status = ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_REUSE_CONNECTION_REQUEST, 0, 0, ctx, 0);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post reuse connection msg to looper failed, reqId=%u, addr=%s, udid=%s",
            requestId, anomizeAddress, anomizeUdid);
        sem_destroy(&waitResult->wait);
        SoftBusFree(ctx);
        SoftBusFree(waitResult);
        return status;
    }
    sem_wait(&waitResult->wait);

    int32_t result = waitResult->result;
    sem_destroy(&waitResult->wait);
    // MUST NOT free ctx here, as ctx is free-ed by message looper
    SoftBusFree(waitResult);
    CONN_LOGE(CONN_BLE, "conflict reuse connection, reqId=%u, addr=%s, udid=%s, result=%d",
        requestId, anomizeAddress, anomizeUdid, result);
    return result;
}

static bool ConflictPostBytes(int32_t underlayHandle, uint8_t *data, uint32_t dataLen)
{
    static int64_t conflictSeqGenerator = 0;

    CONN_CHECK_AND_RETURN_RET_LOGW(data != NULL, false, CONN_BLE, "conflict post bytes failed: data is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(dataLen != 0, false, CONN_BLE, "conflict post bytes failed: data length is 0");

    ConnBleConnection *connection = ConnBleGetConnectionByHandle(underlayHandle, CONN_SIDE_ANY, BLE_GATT);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, false, CONN_BLE,
        "conflict post bytes failed: connection not exist, underlayer handle=%d", underlayHandle);
    uint32_t connectionId = connection->connectionId;
    ConnBleReturnConnection(&connection);

    uint32_t payloadLen = ConnGetHeadSize() + dataLen;
    uint8_t *payload = (uint8_t *)SoftBusCalloc(payloadLen);
    CONN_CHECK_AND_RETURN_RET_LOGE(payload != NULL, false, CONN_BLE,
        "conflict post bytes failed: alloc payload failed, underlayer handle=%d", underlayHandle);

    uint32_t seq = conflictSeqGenerator++;
    ConnPktHead *head = (ConnPktHead *)payload;
    head->magic = MAGIC_NUMBER;
    head->flag = 0;
    head->module = MODULE_OLD_NEARBY;
    head->len = dataLen;
    head->seq = seq;
    PackConnPktHead(head);
    if (memcpy_s(payload + ConnGetHeadSize(), payloadLen - ConnGetHeadSize(), data, dataLen) != EOK) {
        SoftBusFree(payload);
        return false;
    }
    return ConnBlePostBytesInner(connectionId, payload, payloadLen, 0, 0, MODULE_OLD_NEARBY, seq,
        NULL) == SOFTBUS_OK;
}

static void ConflictDisconnect(int32_t handle, bool isForce)
{
    CONN_LOGW(CONN_BLE, "conflict disconnect, receive disconnect request, handle=%d, isForce=%d", handle, isForce);
    ConnBleConnection *connection = ConnBleGetConnectionByHandle(handle, CONN_SIDE_ANY, BLE_GATT);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "conflict disconnect failed: connection not exist, handle=%d", handle);
    if (isForce) {
        ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_CONFLICT);
    } else {
        BleDisconnectDevice(connection->connectionId);
    }
    ConnBleReturnConnection(&connection);
}

static void ConflictOccupy(const char *udid, int32_t timeout)
{
    CONN_CHECK_AND_RETURN_LOGW(udid != NULL, CONN_BLE, "conflict occupy failed: invalid param, udid is null");
    CONN_CHECK_AND_RETURN_LOGW(timeout > 0, CONN_BLE, "conflict occupy failed: invalid param, timeout=%d", timeout);

    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, udid);
    CONN_LOGW(CONN_BLE, "receive conflict occupy, udid=%s, timeout=%d", anomizeUdid, timeout);

    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleManager.prevents->lock) == SOFTBUS_OK, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! conflict occupy failed: try to lock failed, udid=%s", anomizeUdid);
    do {
        char *copyUdid = (char *)SoftBusCalloc(UDID_BUF_LEN);
        if (copyUdid == NULL) {
            CONN_LOGE(CONN_BLE, "calloc udid failed, udid=%s", anomizeUdid);
            break;
        }
        size_t udidLen = strlen(udid);
        if (memcpy_s(copyUdid, UDID_BUF_LEN - 1, udid, udidLen) != EOK) {
            CONN_LOGE(CONN_BLE, "memcpy_s udid failed, source len=%u, destination len=%u, udid=%s",
                udidLen, UDID_BUF_LEN, anomizeUdid);
            SoftBusFree(copyUdid);
            break;
        }
        BlePrevent *exist = NULL;
        BlePrevent *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &g_bleManager.prevents->list, BlePrevent, node) {
            if (udidLen == strlen((char *)it->udid) && memcmp(udid, it->udid, udidLen) == 0) {
                exist = it;
                break;
            }
        }
        if (exist != NULL) {
            CONN_LOGW(CONN_BLE, "dumplicate occupy, refresh timeout, udid=%s", anomizeUdid);
            exist->timeout = timeout;
            ConnRemoveMsgFromLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_PREVENT_TIMEOUT, 0, 0, copyUdid);
            ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_PREVENT_TIMEOUT, 0, 0, copyUdid, timeout);
            break;
        }
        BlePrevent *prevent = (BlePrevent *)SoftBusCalloc(sizeof(BlePrevent));
        if (prevent == NULL) {
            SoftBusFree(copyUdid);
            CONN_LOGE(CONN_BLE, "calloc prevent object failed, udid=%s", anomizeUdid);
            break;
        }
        if (memcpy_s(prevent->udid, UDID_BUF_LEN - 1, udid, udidLen) != EOK) {
            CONN_LOGE(CONN_BLE, "memcpy_s udid to prevent object failed, source length=%u, destination len=%u, "
                "udid=%s", udidLen, UDID_BUF_LEN, anomizeUdid);
            SoftBusFree(copyUdid);
            SoftBusFree(prevent);
            break;
        }
        ListAdd(&g_bleManager.prevents->list, &prevent->node);
        g_bleManager.prevents->cnt++;
        ConnPostMsgToLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_PREVENT_TIMEOUT, 0, 0, copyUdid, timeout);
    } while (false);
    SoftBusMutexUnlock(&g_bleManager.prevents->lock);
    CONN_LOGI(CONN_BLE, "conflict occupy, add udid prevent done, udid=%s", anomizeUdid);
}

static void ConflictCancelOccupy(const char *udid)
{
    CONN_CHECK_AND_RETURN_LOGW(udid != NULL, CONN_BLE, "conflict cancel occupy failed: invalid param, udid is null");

    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, udid);
    CONN_LOGI(CONN_BLE, "conflict cancel occupy, udid=%s", anomizeUdid);

    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_bleManager.prevents->lock) == SOFTBUS_OK, CONN_BLE,
        "ATTENTION UNEXPECTED ERROR! conflict cancel occupy failed: try to lock failed, udid=%s", anomizeUdid);
    size_t udidLen = strlen(udid);
    BlePrevent *it = NULL;
    BlePrevent *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &g_bleManager.prevents->list, BlePrevent, node) {
        if (udidLen == strlen((char *)it->udid) && memcmp(udid, it->udid, udidLen) == 0) {
            g_bleManager.prevents->cnt--;
            ListDelete(&it->node);
            SoftBusFree(it);
            ConnRemoveMsgFromLooper(&g_bleManagerSyncHandler, BLE_MGR_MSG_PREVENT_TIMEOUT, 0, 0, (char *)udid);
            break;
        }
    }
    SoftBusMutexUnlock(&g_bleManager.prevents->lock);
}

static int32_t ConflictGetConnection(const char *udid)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(udid != NULL, SOFTBUS_ERR, CONN_BLE,
        "conflict get connection failed: invalid param, udid is null");

    char anomizeUdid[UDID_BUF_LEN] = { 0 };
    ConvertAnonymizeSensitiveString(anomizeUdid, UDID_BUF_LEN, udid);
    CONN_LOGI(CONN_BLE, "conflict get connection, udid=%s", anomizeUdid);

    ConnBleConnection *connection = ConnBleGetClientConnectionByUdid(udid, BLE_GATT);
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, CONN_BLE,
        "conflict get connection failed: connection not exist, udid=%s", anomizeUdid);
    int32_t result = SOFTBUS_ERR;
    do {
        if (SoftBusMutexLock(&connection->lock) != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to lock failed, connId=%u, udid=%s", connection->connectionId, anomizeUdid);
            result = SOFTBUS_LOCK_ERR;
            break;
        }
        result = connection->underlayerHandle;
        SoftBusMutexUnlock(&connection->lock);
    } while (false);
    CONN_LOGI(CONN_BLE, "conflict get connection, connId=%u, udid=%s, result=%d",
        connection->connectionId, anomizeUdid, result);
    ConnBleReturnConnection(&connection);
    return result;
}

static int32_t BleInitLooper(void)
{
    g_bleManagerSyncHandler.handler.looper = CreateNewLooper("conn_ble_looper");
    if (g_bleManagerSyncHandler.handler.looper == NULL) {
        CONN_LOGE(CONN_INIT, "init conn ble looper failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitBleManager(const ConnectCallback *callback)
{
    SoftBusList *connections = CreateSoftBusList();
    SoftBusList *prevents = CreateSoftBusList();
    CONN_CHECK_AND_RETURN_RET_LOGE(connections != NULL && prevents != NULL, SOFTBUS_ERR, CONN_INIT,
        "init ble manager failed: create list failed");
    g_bleManager.connections = connections;
    g_bleManager.prevents = prevents;
    ListInit(&g_bleManager.waitings);
    g_bleManager.state = NULL;
    g_bleManager.connecting = NULL;

    static SoftBusBtStateListener btStateListener = {
        .OnBtAclStateChanged = NULL,
        .OnBtStateChanged = OnBtStateChanged,
    };
    int32_t listenerId = SoftBusAddBtStateListener(&btStateListener);
    CONN_CHECK_AND_RETURN_RET_LOGW(listenerId >= 0, SOFTBUS_ERR, CONN_INIT,
        "int ble manager failed: add bluetooth state change listener failed, invalid listener id=%d", listenerId);
    static SoftBusBleConflictListener bleConflictListener = {
        .reuseConnection = ConflictReuseConnection,
        .postBytes = ConflictPostBytes,
        .disconnect = ConflictDisconnect,
        .occupy = ConflictOccupy,
        .cancelOccupy = ConflictCancelOccupy,
        .getConnection = ConflictGetConnection,
    };
    SoftbusBleConflictRegisterListener(&bleConflictListener);

    g_connectCallback = *callback;
    TransitionToState(BLE_MGR_STATE_AVAILABLE);
    return SOFTBUS_OK;
}

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(callback != NULL, NULL, CONN_INIT,
        "conn init ble failed: invalid param, callback is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback->OnConnected != NULL, NULL, CONN_INIT,
        "conn init ble failed: invalid param, callback OnConnected  is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback->OnDataReceived != NULL, NULL, CONN_INIT,
        "conn init ble failed: invalid param, callback OnDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(callback->OnDisconnected != NULL, NULL, CONN_INIT,
        "conn init ble failed: invalid param, callback OnDisconnected is null");

    int32_t status = BleInitLooper();
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, NULL, CONN_INIT,
        "conn init ble failed: init ble manager looper failed, err=%d", status);

    ConnBleConnectionEventListener connectionEventListener = {
        .onServerAccepted = OnServerAccepted,
        .onConnected = OnConnected,
        .onConnectFailed = OnConnectFailed,
        .onDataReceived = OnDataReceived,
        .onConnectionClosed = OnConnectionClosed,
        .onConnectionResume = OnConnectionResume,
    };
    status = ConnBleInitConnectionMudule(g_bleManagerSyncHandler.handler.looper, &connectionEventListener);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, NULL, CONN_INIT,
        "conn init ble failed: init ble connection mudule failed, err=%d", status);

    ConnBleTransEventListener transEventListener = {
        .onPostBytesFinished = onPostBytesFinished,
    };
    status = ConnBleInitTransModule(&transEventListener);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, NULL, CONN_INIT,
        "conn init ble failed: init ble trans mudule failed, err=%d", status);
    status = InitBleManager(callback);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, NULL, CONN_INIT,
        "conn init ble failed: init ble manager failed, err=%d", status);

    static ConnectFuncInterface bleFuncInterface = {
        .ConnectDevice = BleConnectDevice,
        .PostBytes = ConnBlePostBytes,
        .DisconnectDevice = BleDisconnectDevice,
        .DisconnectDeviceNow = BleDisconnectDeviceNow,
        .GetConnectionInfo = BleGetConnectionInfo,
        .StartLocalListening = BleStartLocalListening,
        .StopLocalListening = BleStopLocalListening,
        .CheckActiveConnection = BleCheckActiveConnection,
        .UpdateConnection = BleUpdateConnection,
        .PreventConnection = NULL,
    };
    CONN_LOGI(CONN_INIT, "conn init ble successfully");
    return &bleFuncInterface;
}

static void LnnOnlineEventListener(const LnnEventBasicInfo *info)
{
    CONN_CHECK_AND_RETURN_LOGW(info != NULL, CONN_BLE, "receive lnn online event, null info");
    CONN_CHECK_AND_RETURN_LOGW(info->event == LNN_EVENT_NODE_ONLINE_STATE_CHANGED, CONN_BLE,
        "receive lnn online event, unconcerned event=%d", info->event);

    CONN_LOGI(CONN_BLE, "receive lnn online event, start auto-complementation coc connection udid");
    int32_t status = SoftBusMutexLock(&g_bleManager.connections->lock);
    CONN_CHECK_AND_RETURN_LOGE(status == SOFTBUS_OK, CONN_BLE,
        "complementation coc connection udid failed: try to lock connections failed, err=%d", status);

    do {
        ConnBleConnection *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &g_bleManager.connections->list, ConnBleConnection, node) {
            if (it->protocol == BLE_GATT) {
                continue;
            }
            status = SoftBusMutexLock(&it->lock);
            if (status != SOFTBUS_OK) {
                CONN_LOGE(CONN_BLE, "complementation coc connection udid failed: try to get connection "
                      "lock failed, connId=%u, err=%d",
                    it->connectionId, status);
                continue;
            }
            ConnBleInnerComplementDeviceId(it);
            (void)SoftBusMutexUnlock(&it->lock);
        }
    } while (false);
    (void)SoftBusMutexUnlock(&g_bleManager.connections->lock);
}

// register lnn online listener to complementation coc connection udid
static void DelayRegisterLnnOnlineListener(void)
{
    static bool registered = false;
    if (registered) {
        return;
    }

    int32_t status = LnnRegisterEventHandler(LNN_EVENT_NODE_ONLINE_STATE_CHANGED, LnnOnlineEventListener);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "delay register lnn online listener failed, err=%d", status);
        return;
    }
    registered = true;
    CONN_LOGI(CONN_BLE, "delay register lnn online listener successfully");
}
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

#include "softbus_conn_ble_connection.h"

#include <securec.h>

#include "conn_event.h"
#include "conn_log.h"
#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_common.h"
#include "softbus_datahead_transform.h"
#include "softbus_json_utils.h"
#include "ble_protocol_interface_factory.h"
#include "softbus_utils.h"

// basic info json key definition
#define BASIC_INFO_KEY_DEVID   "devid"
#define BASIC_INFO_KEY_ROLE    "type"
#define BASIC_INFO_KEY_DEVTYPE "devtype"
#define BASIC_INFO_KEY_FEATURE "FEATURE_SUPPORT"

enum ConnectionLoopMsgType {
    MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT = 100,
    MSG_CONNECTION_EXCHANGE_BASIC_INFO_TIMEOUT,
    MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
    MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT,
    MSG_CONNECTION_OCCUPY_RELEASE,
    MSG_CONNECTION_UPDATE_REFRENCE,
};

enum BleServerState {
    BLE_SERVER_STATE_STARTING,
    BLE_SERVER_STATE_STARTED,
    BLE_SERVER_STATE_STOPPING,
    BLE_SERVER_STATE_STOPPED,
};

// As bluetooth may be change quickly and ble server start and stop is async,
// we should coordinate and keep this finally state consistent
typedef struct {
    SoftBusMutex lock;
    enum BleServerState expect;
    enum BleServerState actual;
    int32_t status[BLE_PROTOCOL_MAX];
} BleServerCoordination;

typedef struct {
    int32_t delta;
    int32_t peerRc;
    uint16_t challengeCode;
    bool isActiveUpdateLocalRc;
} BleReferenceContext;

typedef struct {
    int32_t delta;
    int32_t localRc;
    int32_t challengeCode;
    uint32_t connId;
    int32_t underlayerHandle;
} RcPackCtlMsgPara;

typedef struct {
    char devId[DEVID_BUFF_LEN];
    int32_t deviceType;
    int32_t feature;
    int32_t type;
} BaseInfo;

static void BleConnectionMsgHandler(SoftBusMessage *msg);
static int BleCompareConnectionLooperEventFunc(const SoftBusMessage *msg, void *args);

static ConnBleConnectionEventListener g_connectionListener;
static SoftBusHandlerWrapper g_bleConnectionAsyncHandler = {
    .handler = {
        .name = (char *)"BleConnectionAsyncHandler",
        .HandleMessage = BleConnectionMsgHandler,
        // assign when initiation
        .looper = NULL,
    },
    .eventCompareFunc = BleCompareConnectionLooperEventFunc,
};
static BleServerCoordination g_serverCoordination = {
    .actual = BLE_SERVER_STATE_STOPPED,
    .expect = BLE_SERVER_STATE_STOPPED,
};
// compatible with old devices, old device not support remote disconnect
static const ConnBleFeatureBitSet g_featureBitSet = (1 << BLE_FEATURE_SUPPORT_REMOTE_DISCONNECT);

ConnBleConnection *ConnBleCreateConnection(
    const char *addr, BleProtocolType protocol, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(addr != NULL, NULL, CONN_BLE, "invalid parameter: ble addr is NULL");

    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, NULL, CONN_BLE, "calloc ble connection failed");
    ListInit(&connection->node);
    // the final connectionId value is allocate on saving global
    connection->connectionId = 0;
    connection->protocol = protocol;
    connection->side = side;
    connection->fastestConnectEnable = fastestConnectEnable;
    if (strcpy_s(connection->addr, BT_MAC_LEN, addr) != EOK) {
        CONN_LOGE(CONN_BLE, "copy address failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->sequence = 0;
    connection->buffer.seq = 0;
    connection->buffer.total = 0;
    ListInit(&connection->buffer.packets);

    if (SoftBusMutexInit(&connection->lock, NULL) != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "init lock failed");
        SoftBusFree(connection);
        return NULL;
    }
    connection->state =
        (side == CONN_SIDE_CLIENT ? BLE_CONNECTION_STATE_CONNECTING : BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO);
    connection->underlayerHandle = underlayerHandle;
    // udid field will be assigned after basic info exchanged
    // the final MTU value will be signed on mtu exchange stage
    connection->mtu = 0;
    // ble connection need exchange connection reference even if establish first time, so the init value is 0
    connection->connectionRc = 0;
    connection->objectRc = 1;
    connection->retrySearchServiceCnt = 0;
    connection->underlayerFastConnectFailedScanFailure = false;
    connection->isOccupied = false;
    SoftBusList *list = CreateSoftBusList();
    if (list == NULL) {
        CONN_LOGE(CONN_BLE, "create softbus list failed");
        SoftBusMutexDestroy(&connection->lock);
        SoftBusFree(connection);
        return NULL;
    }
    connection->connectStatus = list;
    return connection;
}

void ConnBleFreeConnection(ConnBleConnection *connection)
{
    SoftBusMutexDestroy(&connection->lock);
    ConnBlePacket *it = NULL;
    ConnBlePacket *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, &connection->buffer.packets, ConnBlePacket, node) {
        ListDelete(&it->node);
        SoftBusFree(it->data);
        SoftBusFree(it);
    }

    BleUnderlayerStatus *item = NULL;
    BleUnderlayerStatus *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &connection->connectStatus->list, BleUnderlayerStatus, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    DestroySoftBusList(connection->connectStatus);
    SoftBusFree(connection);
}

int32_t ConnBleStartServer(void)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "ble start server failed, try to lock failed");
    g_serverCoordination.expect = BLE_SERVER_STATE_STARTED;
    enum BleServerState actual = g_serverCoordination.actual;
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
    if (actual == BLE_SERVER_STATE_STARTING || actual == BLE_SERVER_STATE_STARTED) {
        return SOFTBUS_OK;
    }
    const BleUnifyInterface *interface;
    for (int i = BLE_GATT; i < BLE_PROTOCOL_MAX; i++) {
        interface = ConnBleGetUnifyInterface(i);
        if (interface == NULL) {
            continue;
        }
        g_serverCoordination.status[i] = interface->bleServerStartService();
    }
    for (int i = BLE_GATT; i < BLE_PROTOCOL_MAX; i++) {
        if (g_serverCoordination.status[i] != SOFTBUS_OK) {
            ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT, 0, 0, NULL,
                RETRY_SERVER_STATE_CONSISTENT_MILLIS);
            return SOFTBUS_OK;
        }
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "ble start server failed, try to lock failed");
    g_serverCoordination.actual = BLE_SERVER_STATE_STARTING;
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
    return SOFTBUS_OK;
}

int32_t ConnBleStopServer(void)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "ble stop server failed, try to lock failed");
    g_serverCoordination.expect = BLE_SERVER_STATE_STOPPED;
    enum BleServerState actual = g_serverCoordination.actual;
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
    if (actual == BLE_SERVER_STATE_STOPPING || actual == BLE_SERVER_STATE_STOPPED) {
        return SOFTBUS_OK;
    }
    const BleUnifyInterface *interface;
    for (int i = BLE_GATT; i < BLE_PROTOCOL_MAX; i++) {
        interface = ConnBleGetUnifyInterface(i);
        if (interface == NULL) {
            continue;
        }
        g_serverCoordination.status[i] = interface->bleServerStopService();
    }
    for (int i = BLE_GATT; i < BLE_PROTOCOL_MAX; i++) {
        if (g_serverCoordination.status[i] != SOFTBUS_OK) {
            ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT, 0, 0, NULL,
                RETRY_SERVER_STATE_CONSISTENT_MILLIS);
            return SOFTBUS_OK;
        }
    }
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR,
        CONN_BLE, "ble close server failed, try to lock failed");
    g_serverCoordination.actual = BLE_SERVER_STATE_STOPPING;
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
    return SOFTBUS_OK;
}

int32_t ConnBleConnect(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connection connect failed, invalid param, connection is null");
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(interface != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble connection connect failed, protocol not support");
    return interface->bleClientConnect(connection);
}

static bool ShouldGrace(enum ConnBleDisconnectReason reason)
{
    switch (reason) {
        case BLE_DISCONNECT_REASON_CONNECT_TIMEOUT:
        case BLE_DISCONNECT_REASON_INTERNAL_ERROR:
        case BLE_DISCONNECT_REASON_POST_BYTES_FAILED:
        case BLE_DISCONNECT_REASON_RESET:
            return false;
        default:
            return true;
    }
}

static bool ShoudRefreshGatt(enum ConnBleDisconnectReason reason)
{
    switch (reason) {
        case BLE_DISCONNECT_REASON_CONNECT_TIMEOUT:
            return true;
        default:
            return false;
    }
}

int32_t ConnBleDisconnectNow(ConnBleConnection *connection, enum ConnBleDisconnectReason reason)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connection disconnect failed, invalid param, connection is null");
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(interface != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble connection disconnect failed, protocol not support");
    CONN_LOGI(CONN_BLE,
        "receive ble disconnect now, connId=%{public}u, side=%{public}d, reason=%{public}d",
        connection->connectionId, connection->side, reason);
    ConnRemoveMsgFromLooper(
        &g_bleConnectionAsyncHandler, MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT, connection->connectionId, 0, NULL);
    if (connection->side == CONN_SIDE_CLIENT) {
        bool grace = ShouldGrace(reason);
        bool refreshGatt = ShoudRefreshGatt(reason);
        return interface->bleClientDisconnect(connection, grace, refreshGatt);
    }
    return interface->bleServerDisconnect(connection);
}

static void OnDisconnectedDataFinished(uint32_t connectionId, int32_t error)
{
    if (error != SOFTBUS_OK) {
        return;
    }
    int32_t status = ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
        connectionId, 0, NULL, WAIT_NEGOTIATION_CLOSING_TIMEOUT_MILLIS);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "post closing timeout event failed, err=%{public}d", status);
    }
}

static int32_t ConnPackCtlMsgRcSendDeltaData(RcPackCtlMsgPara *rcMsgPara)
{
    int32_t flag = CONN_LOW;
    if (rcMsgPara->delta >= 0) {
        flag = CONN_HIGH;
    }
    BleCtlMessageSerializationContext ctx = {
        .connectionId = rcMsgPara->connId,
        .flag = flag,
        .method = CTRL_MSG_METHOD_NOTIFY_REQUEST,
        .referenceRequest = {
            .referenceNumber = rcMsgPara->localRc,
            .delta = rcMsgPara->delta,
        },
        .challengeCode = rcMsgPara->challengeCode,
    };
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int64_t seq = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    if (seq < 0) {
        CONN_LOGE(CONN_BLE, "ble pack notify request message failed, "
            "connId=%{public}u, underlayerHandle=%{public}d, error=%{public}d",
            rcMsgPara->connId, rcMsgPara->underlayerHandle, (int32_t)seq);
        return (int32_t)seq;
    }
    return rcMsgPara->localRc <= 0 ?
        ConnBlePostBytesInner(rcMsgPara->connId, data, dataLen, 0, flag, MODULE_CONNECTION, seq,
            OnDisconnectedDataFinished) :
        ConnBlePostBytesInner(rcMsgPara->connId, data, dataLen, 0, flag, MODULE_CONNECTION, seq, NULL);
}

static bool NeedProccessOccupy(ConnBleConnection *connection, int32_t delta, uint16_t challengeCode,
    bool isActiveUpdateLocalRc, int32_t peerRc)
{
    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, false, CONN_BLE, "lock err");
    bool isOccupied = connection->isOccupied;
    (void)SoftBusMutexUnlock(&connection->lock);
    if (delta > 0 || !isOccupied) {
        return false;
    }

    CONN_LOGI(CONN_BLE, "is occupied, process later, connId=%{public}u", connection->connectionId);
    BleReferenceContext *referenceContext = (BleReferenceContext *)SoftBusMalloc(sizeof(BleReferenceContext));
    CONN_CHECK_AND_RETURN_RET_LOGE(referenceContext != NULL, false, CONN_BLE,
        "malloc buffer failed, connectionId=%{public}u", connection->connectionId);
    referenceContext->delta = delta;
    referenceContext->challengeCode = challengeCode;
    referenceContext->isActiveUpdateLocalRc = isActiveUpdateLocalRc;
    referenceContext->peerRc = peerRc;
    status = ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_UPDATE_REFRENCE,
        connection->connectionId, 0, referenceContext, WAIT_TIMEOUT_TRY_AGAIN);
    if (status != SOFTBUS_OK) {
        SoftBusFree(referenceContext);
        CONN_LOGE(CONN_BLE, "post msg failed, connectionId=%{public}u, error=%{public}d",
            connection->connectionId, status);
        return false;
    }
    return true;
}

int32_t ConnBleUpdateConnectionRc(ConnBleConnection *connection, uint16_t challengeCode, int32_t delta)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "connection is null");
    if (NeedProccessOccupy(connection, delta, challengeCode, true, 0)) {
        return SOFTBUS_OK;
    }
    int32_t status = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGW(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
        "Lock faild, err=%{public}d", status);
    int32_t underlayerHandle = connection->underlayerHandle;
    ConnBleFeatureBitSet featureBitSet = connection->featureBitSet;
    connection->connectionRc += delta;
    int32_t localRc = connection->connectionRc;
    if (localRc <= 0) {
        connection->state = BLE_CONNECTION_STATE_NEGOTIATION_CLOSING;
    } else if (connection->state == BLE_CONNECTION_STATE_NEGOTIATION_CLOSING) {
        ConnRemoveMsgFromLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
            connection->connectionId, 0, NULL);
        connection->state = BLE_CONNECTION_STATE_CONNECTED;
    }
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnEventExtra extra = {
        .connRcDelta = delta,
        .connRc = localRc,
        .linkType = CONNECT_BLE,
        .peerBleMac = connection->addr,
        .connectionId = (int32_t)connection->connectionId,
        .result = EVENT_STAGE_RESULT_OK
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_UPDATE_CONNECTION_RC, extra);
    CONN_LOGI(CONN_BLE, "ble notify refrence, connId=%{public}u, handle=%{public}d, side=%{public}d, "
        "delta=%{public}d, challenge=%{public}u, localRc=%{public}d",
        connection->connectionId, underlayerHandle, connection->side, delta, challengeCode, localRc);

    if (localRc <= 0) {
        if ((featureBitSet & (1 << BLE_FEATURE_SUPPORT_REMOTE_DISCONNECT)) == 0) {
            CONN_LOGW(CONN_BLE, "reference count <= 0 and peer not support negotiation disconnect by notify msg, "
                "disconnect directly after 200 ms, connId=%{public}u, handle=%{public}d, featureBitSet=%{public}u",
                connection->connectionId, underlayerHandle, featureBitSet);
            ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
                connection->connectionId, 0, NULL, CLOSING_TIMEOUT_MILLIS);
            return SOFTBUS_OK;
        }
    }

    RcPackCtlMsgPara rcMsgPara = {
        .delta = delta,
        .localRc = localRc,
        .challengeCode = challengeCode,
        .connId = connection->connectionId,
        .underlayerHandle = underlayerHandle,
    };
    return ConnPackCtlMsgRcSendDeltaData(&rcMsgPara);
}

static int32_t BleOnReferenceRequest(ConnBleConnection *connection, BleReferenceContext *referenceCount)
{
    int32_t delta = referenceCount->delta;
    int32_t peerRc = referenceCount->peerRc;
    uint16_t challengeCode = referenceCount->challengeCode;
    if (NeedProccessOccupy(connection, delta, challengeCode, false, peerRc)) {
        return SOFTBUS_OK;
    }
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u, err=%{public}d", connection->connectionId, status);
        return SOFTBUS_LOCK_ERR;
    }
    connection->connectionRc += delta;
    int32_t localRc = connection->connectionRc;
    CONN_LOGI(CONN_BLE, "ble received reference request, connId=%{public}u, delta=%{public}d, peerRef=%{public}d, "
        "localRc=%{public}d, challenge=%{public}u", connection->connectionId, delta, peerRc, localRc, challengeCode);
    if (peerRc > 0) {
        if (connection->state == BLE_CONNECTION_STATE_NEGOTIATION_CLOSING) {
            ConnRemoveMsgFromLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT,
                connection->connectionId, 0, NULL);
            connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
            g_connectionListener.onConnectionResume(connection->connectionId);
        }
        (void)SoftBusMutexUnlock(&connection->lock);
        NotifyReusedConnected(connection->connectionId, challengeCode);
        return SOFTBUS_OK;
    }
    if (localRc <= 0) {
        connection->state = BLE_CONNECTION_STATE_CLOSING;
        (void)SoftBusMutexUnlock(&connection->lock);
        ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_NEGOTIATION_NO_REFERENCE);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&connection->lock);

    RcPackCtlMsgPara rcMsgPara = {
        .delta = 0,
        .localRc = localRc,
        .challengeCode = challengeCode,
        .connId = connection->connectionId,
        .underlayerHandle = connection->underlayerHandle,
    };
    return ConnPackCtlMsgRcSendDeltaData(&rcMsgPara);
}

int32_t ConnBleOnReferenceRequest(ConnBleConnection *connection, const cJSON *json)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE, "invalid param");
    int32_t delta = 0;
    int32_t peerRc = 0;
    uint16_t challengeCode = 0;
    if (!GetJsonObjectSignedNumberItem(json, CTRL_MSG_KEY_DELTA, &delta) ||
        !GetJsonObjectSignedNumberItem(json, CTRL_MSG_KEY_REF_NUM, &peerRc)) {
        CONN_LOGE(CONN_BLE,
            "parse delta or reference number fields failed, connId=%{public}u, delta=%{public}d, peerRc=%{public}d",
            connection->connectionId, delta, peerRc);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!GetJsonObjectNumber16Item(json, CTRL_MSG_KEY_CHALLENGE, &challengeCode)) {
        CONN_LOGW(CONN_BLE, "old version NOT have KEY_CHALLENGE field. connId=%{public}u", connection->connectionId);
    }

    BleReferenceContext referenceCount = {
        .delta = delta,
        .peerRc = peerRc,
        .challengeCode = challengeCode,
    };
    return BleOnReferenceRequest(connection, &referenceCount);
}

int32_t ConnBleUpdateConnectionPriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connection update connection priority failed, invalid param, connection is null");
    if (connection->side == CONN_SIDE_SERVER) {
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(interface != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble connection update connection priority failed, protocol not support");
    return interface->bleClientUpdatePriority(connection, priority);
}

int32_t ConnBleSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(connection != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connection send data failed, invalid param, connection is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(data != NULL, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connection send data failed, invalid param, data is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(dataLen != 0, SOFTBUS_INVALID_PARAM, CONN_BLE,
        "ble connection send data failed, invalid param, data len is 0");
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(interface != NULL, SOFTBUS_CONN_BLE_INTERNAL_ERR, CONN_BLE,
        "ble connection send data failed, protocol not support");
    return connection->side == CONN_SIDE_SERVER ?
        interface->bleServerSend(connection, data, dataLen, module) :
        interface->bleClientSend(connection, data, dataLen, module);
}

void ConnBleRefreshIdleTimeout(ConnBleConnection *connection)
{
    ConnRemoveMsgFromLooper(
        &g_bleConnectionAsyncHandler, MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT, connection->connectionId, 0, NULL);
    ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT, connection->connectionId,
        0, NULL, CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS);
}

void ConnBleInnerComplementDeviceId(ConnBleConnection *connection)
{
    if (strlen(connection->udid) != 0) {
        CONN_LOGD(CONN_BLE, "udid already exist");
        return;
    }
    if (strlen(connection->networkId) == 0) {
        CONN_LOGW(CONN_BLE,
            "network id not exchange yet, connId=%{public}u, protocol=%{public}d",
            connection->connectionId, connection->protocol);
        return;
    }
    int32_t status = LnnGetRemoteStrInfo(connection->networkId, STRING_KEY_DEV_UDID, connection->udid, UDID_BUF_LEN);
    CONN_LOGD(CONN_BLE,
        "complementation ble connection device id, connId=%{public}u, protocol=%{public}d, status=%{public}d",
        connection->connectionId, connection->protocol, status);
}

static void ConnBlePackCtrlMsgHeader(ConnPktHead *header, uint32_t dataLen)
{
    static int64_t ctlMsgSeqGenerator = 0;
    int64_t seq = ctlMsgSeqGenerator++;

    header->magic = MAGIC_NUMBER;
    header->module = MODULE_CONNECTION;
    header->seq = seq;
    header->flag = CONN_HIGH;
    header->len = dataLen;
    PackConnPktHead(header);
}

// CoC connection exchange 'networdId' as old udid field may disclosure of user privacy and be traced;
// GATT connection keep exchange 'udid' as keeping compatibility
static int32_t SendBasicInfo(ConnBleConnection *connection)
{
    int32_t status = SOFTBUS_CONN_BLE_INTERNAL_ERR;
    char devId[DEVID_BUFF_LEN] = { 0 };
    BleProtocolType protocol = connection->protocol;
    ConnBleFeatureBitSet featureBitSet = connection->featureBitSet;
    bool isSupportNetWorkIdExchange = (featureBitSet &
        (1 << BLE_FEATURE_SUPPORT_SUPPORT_NETWORKID_BASICINFO_EXCAHNGE)) != 0;
    if (protocol == BLE_COC || isSupportNetWorkIdExchange) {
        status = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, devId, DEVID_BUFF_LEN);
    } else if (protocol == BLE_GATT) {
        status = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, devId, DEVID_BUFF_LEN);
    }
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "get devid from net ledger failed, connId=%{public}u, protocol=%{public}d, err=%{public}d",
            connection->connectionId, connection->protocol, status);
        return status;
    }

    int32_t deviceType = 0;
    status = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &deviceType);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE,
            "get device type from net ledger failed, connId=%{public}u, err=%{public}d",
            connection->connectionId, status);
        return status;
    }

    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        CONN_LOGE(CONN_BLE, "create json object failed, connId=%{public}u", connection->connectionId);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    char *payload = NULL;
    featureBitSet |= g_featureBitSet;
    do {
        if (!AddStringToJsonObject(json, BASIC_INFO_KEY_DEVID, devId) ||
            !AddNumberToJsonObject(json, BASIC_INFO_KEY_ROLE, connection->side) ||
            !AddNumberToJsonObject(json, BASIC_INFO_KEY_DEVTYPE, deviceType) ||
            !AddNumberToJsonObject(json, BASIC_INFO_KEY_FEATURE, featureBitSet)) {
            CONN_LOGE(CONN_BLE, "add json info failed, connId=%{public}u", connection->connectionId);
            status = SOFTBUS_CREATE_JSON_ERR;
            break;
        }
        payload = cJSON_PrintUnformatted(json);
        uint32_t payloadLen = strlen(payload);
        uint32_t dataLen = NET_CTRL_MSG_TYPE_HEADER_SIZE + payloadLen + 1;
        uint32_t bufLen = dataLen + (connection->protocol == BLE_COC ? sizeof(ConnPktHead) : 0);
        uint8_t *buf = (uint8_t *)SoftBusCalloc(bufLen);
        if (buf == NULL) {
            CONN_LOGE(CONN_BLE,
                "malloc buf failed, connId=%{public}u, bufLen=%{public}u", connection->connectionId, bufLen);
            status = SOFTBUS_MALLOC_ERR;
            break;
        }

        int32_t offset = 0;
        if (connection->protocol == BLE_COC) {
            ConnPktHead *header = (ConnPktHead *)buf;
            ConnBlePackCtrlMsgHeader(header, dataLen);
            offset += sizeof(ConnPktHead);
        }
        int32_t *netCtrlMsgHeader = (int32_t *)(buf + offset);
        netCtrlMsgHeader[0] = NET_CTRL_MSG_TYPE_BASIC_INFO;
        offset += NET_CTRL_MSG_TYPE_HEADER_SIZE;
        if (memcpy_s(buf + offset, bufLen - offset, payload, payloadLen) != EOK) {
            CONN_LOGE(CONN_BLE,
                "memcpy_s buf failed, connId=%{public}u, bufLen=%{public}u, paylaodLen=%{public}u",
                connection->connectionId, bufLen, payloadLen);
            status = SOFTBUS_MEM_ERR;
            SoftBusFree(buf);
            break;
        }
        status = ConnBlePostBytesInner(connection->connectionId, buf, bufLen, 0, CONN_HIGH, MODULE_BLE_NET, 0, NULL);
        CONN_LOGI(CONN_BLE, "ble send basic info, connId=%{public}u, side=%{public}s, status=%{public}d",
            connection->connectionId, connection->side == CONN_SIDE_CLIENT ? "client" : "server", status);
        if (status != SOFTBUS_OK) {
            break;
        }
    } while (false);
    cJSON_Delete(json);
    if (payload != NULL) {
        cJSON_free(payload);
    }
    ConnEventExtra extra = {
        .connectionId = (int32_t)connection->connectionId,
        .connRole = connection->side,
        .linkType = CONNECT_BLE,
        .peerBleMac = connection->addr,
        .errcode = status,
        .result = status == SOFTBUS_OK ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED
    };
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_SEND_BASIC_INFO, extra);
    return status;
}

static int32_t ParsePeerBasicInfoInner(ConnBleConnection *connection, const uint8_t *data,
    uint32_t dataLen, BaseInfo *baseInfo)
{
    if (dataLen <= NET_CTRL_MSG_TYPE_HEADER_SIZE) {
        CONN_LOGI(CONN_BLE,
            "date len exceed, connId=%{public}u, dataLen=%{public}d", connection->connectionId, dataLen);
        return SOFTBUS_INVALID_PARAM;
    }
    int offset = 0;
    if (connection->protocol == BLE_COC) {
        offset += sizeof(ConnPktHead);
    }
    int32_t *netCtrlMsgHeader = (int32_t *)(data + offset);
    if (netCtrlMsgHeader[0] != NET_CTRL_MSG_TYPE_BASIC_INFO) {
        CONN_LOGI(CONN_BLE,
            "not basic info type, connId=%{public}u, type=%{public}d", connection->connectionId, netCtrlMsgHeader[0]);
        return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }
    offset += NET_CTRL_MSG_TYPE_HEADER_SIZE;
    cJSON *json = cJSON_ParseWithLength((char *)(data + offset), dataLen - offset);
    if (json == NULL) {
        CONN_LOGI(CONN_BLE, "parse json failed, connId=%{public}u", connection->connectionId);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    // mandatory fields
    if (!GetJsonObjectStringItem(json, BASIC_INFO_KEY_DEVID, baseInfo->devId, DEVID_BUFF_LEN) ||
        !GetJsonObjectNumberItem(json, BASIC_INFO_KEY_ROLE, &(baseInfo->type))) {
        cJSON_Delete(json);
        CONN_LOGE(CONN_BLE, "basic info field not exist, connId=%{public}u", connection->connectionId);
        return SOFTBUS_CONN_BLE_INTERNAL_ERR;
    }
    // optional field
    if (!GetJsonObjectNumberItem(json, BASIC_INFO_KEY_DEVTYPE, &(baseInfo->deviceType))) {
        CONN_LOGE(CONN_BLE, "ble parse basic info warning, 'devType' is not exist, connId=%{public}u",
            connection->connectionId);
        // fall through
    }
    if (!GetJsonObjectNumberItem(json, BASIC_INFO_KEY_FEATURE, &(baseInfo->feature))) {
        CONN_LOGE(CONN_BLE, "ble parse basic info warning, 'FEATURE_SUPPORT' is not exist, connId=%{public}u",
            connection->connectionId);
        // fall through
    }
    cJSON_Delete(json);
    return SOFTBUS_OK;
}

static int32_t ParseBasicInfo(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen)
{
    BaseInfo baseInfo = {0};
    int32_t ret = ParsePeerBasicInfoInner(connection, data, dataLen, &baseInfo);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_BLE, "ble parse data failed, error=%{public}d", ret);
    bool isSupportNetWorkIdExchange = ((uint32_t)(baseInfo.feature) &
        (1 << BLE_FEATURE_SUPPORT_SUPPORT_NETWORKID_BASICINFO_EXCAHNGE)) != 0;
    ret = SoftBusMutexLock(&connection->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_BLE,
        "try to lock failed, connId=%{public}u, err=%{public}d", connection->connectionId, ret);

    if (connection->protocol == BLE_COC || isSupportNetWorkIdExchange) {
        if (memcpy_s(connection->networkId, NETWORK_ID_BUF_LEN, baseInfo.devId, DEVID_BUFF_LEN) != EOK) {
            (void)SoftBusMutexUnlock(&connection->lock);
            CONN_LOGE(CONN_BLE, "memcpy_s network id failed, connId=%{public}u", connection->connectionId);
            return SOFTBUS_MEM_ERR;
        }
        ConnBleInnerComplementDeviceId(connection);
    } else if (connection->protocol == BLE_GATT) {
        if (memcpy_s(connection->udid, UDID_BUF_LEN, baseInfo.devId, DEVID_BUFF_LEN) != EOK) {
            (void)SoftBusMutexUnlock(&connection->lock);
            CONN_LOGE(CONN_BLE, "memcpy_s udid failed, connId=%{public}u", connection->connectionId);
            return SOFTBUS_MEM_ERR;
        }
    }
    connection->featureBitSet = (ConnBleFeatureBitSet)(baseInfo.feature);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    (void)SoftBusMutexUnlock(&connection->lock);

    // revert current side role is peer side role
    int32_t expectedPeerType = connection->side == CONN_SIDE_CLIENT ? 2 : 1;
    if (expectedPeerType != baseInfo.type) {
        CONN_LOGW(CONN_BLE, "parse basic info, the role of connection is mismatch, "
            "expectedPeerType=%{public}d, actualPeerType=%{public}d", expectedPeerType, baseInfo.type);
    }
    ConnEventExtra extra = {
        .connectionId = (int32_t)connection->connectionId,
        .connRole = connection->side,
        .supportFeature = baseInfo.feature,
        .linkType = CONNECT_BLE,
        .peerBleMac = connection->addr,
        .result = EVENT_STAGE_RESULT_OK
    };
    char devType[DEVICE_TYPE_MAX_SIZE + 1] = {0};
    if (snprintf_s(devType, DEVICE_TYPE_MAX_SIZE + 1, DEVICE_TYPE_MAX_SIZE, "%03X", baseInfo.deviceType) >= 0) {
        extra.peerDeviceType = devType;
    }
    CONN_EVENT(EVENT_SCENE_CONNECT, EVENT_STAGE_CONNECT_PARSE_BASIC_INFO, extra);
    CONN_LOGI(CONN_BLE, "ble parse basic info, connId=%{public}u, side=%{public}s, deviceType=%{public}d, "
        "supportFeature=%{public}u", connection->connectionId,
        connection->side == CONN_SIDE_CLIENT ? "client" : "server", baseInfo.deviceType, baseInfo.feature);
    return SOFTBUS_OK;
}

void BleOnClientConnected(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "connection not exist, connId=%{public}u", connectionId);
    int32_t status = SOFTBUS_OK;
    do {
        status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u, err=%{public}d", connectionId, status);
            break;
        }
        connection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
        (void)SoftBusMutexUnlock(&connection->lock);
        status = ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_EXCHANGE_BASIC_INFO_TIMEOUT,
            connectionId, 0, NULL, BASIC_INFO_EXCHANGE_TIMEOUT);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE,
                "post basic info exchange timeout event failed, connId=%{public}u, err=%{public}d",
                connectionId, status);
            break;
        }
        status = SendBasicInfo(connection);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE,
                "send basic info message failed, connId=%{public}u, err=%{public}d", connectionId, status);
            break;
        }
    } while (false);
    if (status != SOFTBUS_OK) {
        g_connectionListener.onConnectFailed(connection->connectionId, status);
    }
    ConnBleReturnConnection(&connection);
}

void BleOnClientFailed(uint32_t connectionId, int32_t error)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "connection not exist, connId=%{public}u", connectionId);
    if (connection->protocol == BLE_GATT) {
        g_connectionListener.onConnectFailed(connectionId, error);
        ConnBleReturnConnection(&connection);
        return;
    }

    int32_t status = SoftBusMutexLock(&connection->connectStatus->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "lock failed, connId=%{public}u", connectionId);
        ConnBleReturnConnection(&connection);
        return;
    }
    BleUnderlayerStatus *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &connection->connectStatus->list, BleUnderlayerStatus, node) {
        // to find the last error
        if (it->result != 0) {
            error = it->result;
        }
    }
    (void)SoftBusMutexUnlock(&connection->connectStatus->lock);
    ConnBleReturnConnection(&connection);
    g_connectionListener.onConnectFailed(connectionId, error);
}

static void HandleBasicInfo(ConnBleConnection *connection, uint8_t *data, uint32_t dataLen,
    const BleUnifyInterface *interface)
{
    int32_t ret = ParseBasicInfo(connection, data, dataLen);
    SoftBusFree(data);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "parse basic info failed, connId=%{public}u, side=%{public}d, handle=%{public}d, "
            "err=%{public}d", connection->connectionId, connection->side, connection->underlayerHandle, ret);
        if (connection->side == CONN_SIDE_CLIENT) {
            g_connectionListener.onConnectFailed(connection->connectionId, ret);
        } else {
            interface->bleServerDisconnect(connection);
        }
        return;
    }
    ConnRemoveMsgFromLooper(
        &g_bleConnectionAsyncHandler, MSG_CONNECTION_EXCHANGE_BASIC_INFO_TIMEOUT, connection->connectionId, 0, NULL);
    if (connection->side == CONN_SIDE_SERVER) {
        ret = SendBasicInfo(connection);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "send server side basic info failed, connId=%{public}u, handle=%{public}d, "
                "err=%{public}d", connection->connectionId, connection->underlayerHandle, ret);
            interface->bleServerDisconnect(connection);
            return;
        }
        ret = interface->bleServerConnect(connection);
        CONN_LOGI(CONN_BLE, "server side finish exchange basic info, connId=%{public}u, handle=%{public}d, "
            "serverConnectStatus=%{public}d", connection->connectionId, connection->underlayerHandle, ret);
        ConnBleRefreshIdleTimeout(connection);
        g_connectionListener.onServerAccepted(connection->connectionId);
    } else {
        CONN_LOGI(CONN_BLE, "client side finish exchange basic info, connId=%{public}u, handle=%{public}d",
            connection->connectionId, connection->underlayerHandle);
        ConnBleRefreshIdleTimeout(connection);
        g_connectionListener.onConnected(connection->connectionId);
    }
}

// Memory Management Conventions: MUST free data if dispatch process is intercepted,
// otherwise it is responsibity of uplayer to free data
void BleOnDataReceived(uint32_t connectionId, bool isConnCharacteristic, uint8_t *data, uint32_t dataLen)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    if (connection == NULL) {
        CONN_LOGE(CONN_BLE, "connection not exist, connId=%{public}u", connectionId);
        SoftBusFree(data);
        return;
    }
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    if (interface == NULL) {
        CONN_LOGE(CONN_BLE, "protocol not support, connId=%{public}u", connectionId);
        SoftBusFree(data);
        return;
    }
    int32_t status = SOFTBUS_OK;
    do {
        if (isConnCharacteristic) {
            ConnBleRefreshIdleTimeout(connection);
            g_connectionListener.onDataReceived(connectionId, isConnCharacteristic, data, dataLen);
            break;
        }

        status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            SoftBusFree(data);
            // NOT notify client 'onConnectFailed' or server disconnect as it can not get state safely here,
            // connection will fail after basic info change timeout, all resouces will cleanup in timeout handle method
            CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u, err=%{public}d", connectionId, status);
            break;
        }
        enum ConnBleConnectionState state = connection->state;
        (void)SoftBusMutexUnlock(&connection->lock);
        if (state != BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO) {
            ConnBleRefreshIdleTimeout(connection);
            isConnCharacteristic = (connection->protocol == BLE_COC) ? true : isConnCharacteristic;
            g_connectionListener.onDataReceived(connectionId, isConnCharacteristic, data, dataLen);
            break;
        }

        HandleBasicInfo(connection, data, dataLen, interface);
    } while (false);
    ConnBleReturnConnection(&connection);
}

void BleOnConnectionClosed(uint32_t connectionId, int32_t status)
{
    ConnRemoveMsgFromLooper(
        &g_bleConnectionAsyncHandler, MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT, connectionId, 0, NULL);
    g_connectionListener.onConnectionClosed(connectionId, status);
}

void BleOnServerStarted(BleProtocolType protocol, int32_t status)
{
    CONN_LOGD(CONN_BLE, "receive ble server started event, status=%{public}d", status);

    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, CONN_BLE,
        "on server start event handle failed, try to lock failed");
    g_serverCoordination.status[protocol] = status;
    g_serverCoordination.actual =
        ((g_serverCoordination.status[BLE_GATT] == SOFTBUS_OK) && (g_serverCoordination.status[BLE_COC] == SOFTBUS_OK ?
                BLE_SERVER_STATE_STARTED : BLE_SERVER_STATE_STOPPED));
    if (g_serverCoordination.expect != g_serverCoordination.actual) {
        ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT, 0, 0, NULL,
            RETRY_SERVER_STATE_CONSISTENT_MILLIS);
    }
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
}

void BleOnServerClosed(BleProtocolType protocol, int32_t status)
{
    CONN_LOGD(CONN_BLE, "receive ble server closed event, status=%{public}d", status);

    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, CONN_BLE,
        "on server close event handle failed, try to lock failed");
    g_serverCoordination.status[protocol] = status;
    g_serverCoordination.actual =
        (g_serverCoordination.status[BLE_GATT] == SOFTBUS_OK && g_serverCoordination.status[BLE_COC] == SOFTBUS_OK ?
                BLE_SERVER_STATE_STOPPED : BLE_SERVER_STATE_STARTED);
    if (g_serverCoordination.expect != g_serverCoordination.actual) {
        ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT, 0, 0, NULL,
            RETRY_SERVER_STATE_CONSISTENT_MILLIS);
    }
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
}

void BleOnServerAccepted(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE, "connection not exist, connId=%{public}u", connectionId);
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    CONN_CHECK_AND_RETURN_LOGW(interface != NULL, CONN_BLE,
        "ble server accepted failed, interface not support, connId=%{public}u", connectionId);
    int32_t status = SOFTBUS_OK;
    do {
        status = SoftBusMutexLock(&connection->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u, err=%{public}d", connectionId, status);
            break;
        }
        connection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
        (void)SoftBusMutexUnlock(&connection->lock);
        status = ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_EXCHANGE_BASIC_INFO_TIMEOUT,
            connectionId, 0, NULL, BASIC_INFO_EXCHANGE_TIMEOUT);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_BLE,
                "post basic info exchange timeout event failed, connId=%{public}u, err=%{public}d",
                connectionId, status);
            break;
        }
    } while (false);
    if (status != SOFTBUS_OK) {
        interface->bleServerDisconnect(connection);
    }
    ConnBleReturnConnection(&connection);
}

static int32_t DoRetryAction(enum BleServerState expect)
{
    int32_t statusGatt = SOFTBUS_OK;
    int32_t statusCoc = SOFTBUS_OK;
    if (g_serverCoordination.status[BLE_GATT] != SOFTBUS_OK) {
        const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_GATT);
        if (interface != NULL) {
            statusGatt = (expect == BLE_SERVER_STATE_STARTED) ? interface->bleServerStartService() :
                                 interface->bleServerStopService();
        }
    }

    if (g_serverCoordination.status[BLE_COC] != SOFTBUS_OK) {
        const BleUnifyInterface *interface = ConnBleGetUnifyInterface(BLE_COC);
        if (interface != NULL) {
            statusCoc = (expect == BLE_SERVER_STATE_STARTED) ? interface->bleServerStartService() :
                                interface->bleServerStopService();
        }
    }

    return (statusGatt != SOFTBUS_OK || statusCoc != SOFTBUS_OK) ? SOFTBUS_CONN_BLE_CHECK_STATUS_ERR : SOFTBUS_OK;
}

void ConnBleOccupy(ConnBleConnection *connection)
{
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "conn is NULL");
    ConnRemoveMsgFromLooper(
        &g_bleConnectionAsyncHandler, MSG_CONNECTION_OCCUPY_RELEASE, connection->connectionId, 0, NULL);
    int32_t ret = ConnPostMsgToLooper(&g_bleConnectionAsyncHandler,
        MSG_CONNECTION_OCCUPY_RELEASE, connection->connectionId, 0, NULL, WAIT_TIMEOUT_OCCUPY);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_BLE, "post msg failed, connId=%{public}u, err=%{public}d",
        connection->connectionId, ret);
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&connection->lock) == SOFTBUS_OK, CONN_BLE,
        "lock failed, connId=%{public}u", connection->connectionId);
    connection->isOccupied = true;
    (void)SoftBusMutexUnlock(&connection->lock);
}

static void RetryServerStatConsistentHandler(void)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, CONN_BLE,
        "retry server state consistent msg handle, try to lock failed");
    enum BleServerState expect = g_serverCoordination.expect;
    enum BleServerState actual = g_serverCoordination.actual;
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
    if (expect == actual) {
        // consistent reached
        return;
    }
    if (actual == BLE_SERVER_STATE_STARTING || actual == BLE_SERVER_STATE_STOPPING) {
        // action on the fly, try later
        ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT, 0, 0, NULL,
            RETRY_SERVER_STATE_CONSISTENT_MILLIS);
        return;
    }
    int32_t status = DoRetryAction(expect);
    if (status != SOFTBUS_OK) {
        ConnPostMsgToLooper(&g_bleConnectionAsyncHandler, MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT, 0, 0, NULL,
            RETRY_SERVER_STATE_CONSISTENT_MILLIS);
        return;
    }
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_serverCoordination.lock) == SOFTBUS_OK, CONN_BLE,
        "retry server state consistent msg handle, try to lock failed");
    g_serverCoordination.actual =
        (expect == BLE_SERVER_STATE_STARTED ? BLE_SERVER_STATE_STARTING : BLE_SERVER_STATE_STOPPING);
    (void)SoftBusMutexUnlock(&g_serverCoordination.lock);
}

static void BasicInfoExchangeTimeoutHandler(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "ble basic info exchange timeout handle failed, connection not exist, connId=%{public}u", connectionId);
    const BleUnifyInterface *interface = ConnBleGetUnifyInterface(connection->protocol);
    CONN_CHECK_AND_RETURN_LOGW(interface != NULL, CONN_BLE,
        "ble basic info exchange timeout handle failed, protocol not support, connId=%{public}u", connectionId);
    CONN_LOGW(CONN_BLE, "ble basic info exchange timeout, connId=%{public}u, side=%{public}s", connectionId,
        connection->side == CONN_SIDE_CLIENT ? "client" : "server");
    if (connection->side == CONN_SIDE_CLIENT) {
        g_connectionListener.onConnectFailed(connectionId, SOFTBUS_CONN_BLE_EXCHANGE_BASIC_INFO_TIMEOUT_ERR);
    } else {
        interface->bleServerDisconnect(connection);
    }
    ConnBleReturnConnection(&connection);
}

static void WaitNegotiationClosingTimeoutHandler(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "ble wait negotiation closing timeout handler failed: connection not exist, connId=%{public}u", connectionId);
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "try to lock failed, connId=%{public}u", connectionId);
        ConnBleReturnConnection(&connection);
        return;
    }
    enum ConnBleConnectionState state = connection->state;
    (void)SoftBusMutexUnlock(&connection->lock);
    CONN_LOGW(CONN_BLE,
        "ble wait negotiation closing timeout, connId=%{public}u, state=%{public}d", connectionId, state);
    if (state == BLE_CONNECTION_STATE_NEGOTIATION_CLOSING) {
        ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_NEGOTIATION_WAIT_TIMEOUT);
    }
    ConnBleReturnConnection(&connection);
}

static void ConnectionIdleDisconnectTimeoutHandler(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGW(connection != NULL, CONN_BLE,
        "connection idle disconnect timeout handler failed: connection not exist, connId=%{public}u", connectionId);
    CONN_LOGW(CONN_BLE,
        "connection idle disconnect timeout handler, connection idle exceed forgot call "
        "disconnect? disconnect now, timeoutMillis=%{public}ums, connId=%{public}u",
        CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS, connectionId);
    ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_IDLE_WAIT_TIMEOUT);
    ConnBleReturnConnection(&connection);
}

static void BleOnOccupyRelease(uint32_t connectionId)
{
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "conn not exist, id=%{public}u", connectionId);
    int32_t status = SoftBusMutexLock(&connection->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_BLE, "lock failed, connectionId=%{public}u, error=%{public}d", connectionId, status);
        ConnBleReturnConnection(&connection);
        return;
    }
    connection->isOccupied = false;
    (void)SoftBusMutexUnlock(&connection->lock);
    ConnBleReturnConnection(&connection);
}

static void BleRetryUpdateConnectionRc(uint32_t connectionId, BleReferenceContext *referenceContext)
{
    CONN_CHECK_AND_RETURN_LOGE(referenceContext != NULL, CONN_BLE, "referenceContext is null");
    ConnBleConnection *connection = ConnBleGetConnectionById(connectionId);
    CONN_CHECK_AND_RETURN_LOGE(connection != NULL, CONN_BLE, "conn not exist, id=%{public}u", connectionId);
    if (referenceContext->isActiveUpdateLocalRc) {
        ConnBleUpdateConnectionRc(connection, referenceContext->challengeCode, referenceContext->delta);
    } else {
        BleOnReferenceRequest(connection, referenceContext);
    }
    ConnBleReturnConnection(&connection);
}

static void BleConnectionMsgHandler(SoftBusMessage *msg)
{
    CONN_LOGI(CONN_BLE, "ble connection looper receive msg, msg=%{public}d", msg->what);
    switch (msg->what) {
        case MSG_CONNECTION_RETRY_SERVER_STATE_CONSISTENT:
            RetryServerStatConsistentHandler();
            break;
        case MSG_CONNECTION_EXCHANGE_BASIC_INFO_TIMEOUT:
            BasicInfoExchangeTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT:
            WaitNegotiationClosingTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT:
            ConnectionIdleDisconnectTimeoutHandler((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_OCCUPY_RELEASE:
            BleOnOccupyRelease((uint32_t)msg->arg1);
            break;
        case MSG_CONNECTION_UPDATE_REFRENCE:
            BleRetryUpdateConnectionRc((uint32_t)msg->arg1, (BleReferenceContext *)msg->obj);
            break;
        default:
            CONN_LOGW(CONN_BLE,
                "ATTENTION, ble conn looper receive unexpected msg, just ignore, FIX it quickly. what=%{public}d",
                msg->what);
            break;
    }
}

static int BleCompareConnectionLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what != ctx->what) {
        return COMPARE_FAILED;
    }
    switch (ctx->what) {
        case MSG_CONNECTION_EXCHANGE_BASIC_INFO_TIMEOUT:
        case MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT:
        case MSG_CONNECTION_IDLE_DISCONNECT_TIMEOUT:
        case MSG_CONNECTION_UPDATE_REFRENCE:
        case MSG_CONNECTION_OCCUPY_RELEASE: {
            if (msg->arg1 == ctx->arg1) {
                return COMPARE_SUCCESS;
            }
            return COMPARE_FAILED;
        }
        default:
            break;
    }
    if (ctx->arg1 != 0 || ctx->arg2 != 0 || ctx->obj != NULL) {
        CONN_LOGE(CONN_BLE, "there is compare context value not use, forgot implement? "
                            "compare failed to avoid fault silence, what=%{public}d, arg1=%{public}" PRIu64
                            ", arg2=%{public}" PRIu64 ", objIsNull=%{public}d",
            ctx->what, ctx->arg1, ctx->arg2, ctx->obj == NULL);
        return COMPARE_FAILED;
    }
    return COMPARE_SUCCESS;
}

static int32_t CheckBleInitConnectionPara(SoftBusLooper *looper, ConnBleConnectionEventListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(looper != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, looper is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onServerAccepted != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener onServerAccepted is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnected != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener onConnected is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectFailed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener onConnectFailed is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onDataReceived != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener onDataReceived is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectionClosed != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener onConnectionClosed is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectionResume != NULL, SOFTBUS_INVALID_PARAM, CONN_INIT,
        "init ble connection failed: invalid param, listener onConnectionResume is null");
    return SOFTBUS_OK;
}

int32_t ConnBleInitConnectionMudule(SoftBusLooper *looper, ConnBleConnectionEventListener *listener)
{
    int32_t ret = CheckBleInitConnectionPara(looper, listener);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_INIT, "ConnServerPartInit init failed.");
    ConnBleClientEventListener clientEventListener = {
        .onClientConnected = BleOnClientConnected,
        .onClientFailed = BleOnClientFailed,
        .onClientDataReceived = BleOnDataReceived,
        .onClientConnectionClosed = BleOnConnectionClosed,
    };
    ConnBleServerEventListener serverEventListener = {
        .onServerStarted = BleOnServerStarted,
        .onServerClosed = BleOnServerClosed,
        .onServerAccepted = BleOnServerAccepted,
        .onServerDataReceived = BleOnDataReceived,
        .onServerConnectionClosed = BleOnConnectionClosed,
    };
    ret = SOFTBUS_CONN_BLE_INTERNAL_ERR;
    const BleUnifyInterface *interface;
    for (int i = BLE_GATT; i < BLE_PROTOCOL_MAX; i++) {
        interface = ConnBleGetUnifyInterface(i);
        if (interface == NULL) {
            continue;
        }
        ret = interface->bleClientInitModule(looper, &clientEventListener);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_INIT,
            "init ble connection failed: init ble client failed, i=%{public}d, err=%{public}d", i, ret);
        ret = interface->bleServerInitModule(looper, &serverEventListener);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_INIT,
            "init ble connection failed: init ble server failed, i=%{public}d, err=%{public}d", i, ret);
    }
    ret = SoftBusMutexInit(&g_serverCoordination.lock, NULL);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_INIT,
        "init ble connection failed: init server coordination lock failed, err=%{public}d", ret);
    g_bleConnectionAsyncHandler.handler.looper = looper;
    g_connectionListener = *listener;
    return SOFTBUS_OK;
}

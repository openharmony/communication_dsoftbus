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

#ifndef SOFTBUS_CONN_BLE_CONNECTION_H
#define SOFTBUS_CONN_BLE_CONNECTION_H

#include "common_list.h"
#include "message_handler.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOFTBUS_SERVICE_UUID              "11C8B310-80E4-4276-AFC0-F81590B2177F"
#define SOFTBUS_CHARA_BLENET_UUID         "00002B00-0000-1000-8000-00805F9B34FB"
#define SOFTBUS_CHARA_BLECONN_UUID        "00002B01-0000-1000-8000-00805F9B34FB"
#define SOFTBUS_DESCRIPTOR_CONFIGURE_UUID "00002902-0000-1000-8000-00805F9B34FB"

#define INVALID_UNDERLAY_HANDLE                   (-1)
#define NET_CTRL_MSG_TYPE_HEADER_SIZE             4
#define BLE_CLIENT_MAX_RETRY_SEARCH_SERVICE_TIMES 1
#define WAIT_NEGOTIATION_CLOSING_TIMEOUT_MILLIS   5500

#define RETRY_SERVER_STATE_CONSISTENT_MILLIS      (3 * 1000)
#define BASIC_INFO_EXCHANGE_TIMEOUT               (5 * 1000)
#define UNDERLAY_CONNECTION_DISCONNECT_TIMEOUT    (5 * 1000)
#define CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS (60 * 1000)
#define CLOSING_TIMEOUT_MILLIS                     200
#define DEFAULT_MTU_SIZE                          512

enum BleNetCtrlMsgType {
    NET_CTRL_MSG_TYPE_UNKNOW = -1,
    NET_CTRL_MSG_TYPE_AUTH = 0,
    NET_CTRL_MSG_TYPE_BASIC_INFO = 1,
    NET_CTRL_MSG_TYPE_DEV_INFO = 2,
};

enum ConnBleConnectionState {
    BLE_CONNECTION_STATE_CONNECTING = 0, // client connection init state
    BLE_CONNECTION_STATE_CONNECTED,      // server connection init state
    BLE_CONNECTION_STATE_SERVICE_SEARCHING,
    BLE_CONNECTION_STATE_SERVICE_SEARCHED,
    BLE_CONNECTION_STATE_CONN_NOTIFICATING,
    BLE_CONNECTION_STATE_CONN_NOTIFICATED,
    BLE_CONNECTION_STATE_NET_NOTIFICATING,
    BLE_CONNECTION_STATE_NET_NOTIFICATED,
    BLE_CONNECTION_STATE_MTU_SETTING,
    BLE_CONNECTION_STATE_MTU_SETTED,
    BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO,
    BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO,
    BLE_CONNECTION_STATE_NEGOTIATION_CLOSING,
    BLE_CONNECTION_STATE_CLOSING,
    BLE_CONNECTION_STATE_CLOSED,
    BLE_CONNECTION_STATE_INVALID,
};

enum ConnBleDisconnectReason {
    BLE_DISCONNECT_REASON_CONNECT_TIMEOUT,
    BLE_DISCONNECT_REASON_INTERNAL_ERROR,
    BLE_DISCONNECT_REASON_NO_REFERENCE,
    BLE_DISCONNECT_REASON_NEGOTIATION_NO_REFERENCE,
    BLE_DISCONNECT_REASON_NEGOTIATION_WAIT_TIMEOUT,
    BLE_DISCONNECT_REASON_IDLE_WAIT_TIMEOUT,
    BLE_DISCONNECT_REASON_CONFLICT,
    BLE_DISCONNECT_REASON_FORCELY,
    BLE_DISCONNECT_REASON_POST_BYTES_FAILED,
    BLE_DISCONNECT_REASON_RESET,
};

enum ConnBleFeatureCapability {
    BLE_FEATURE_SUPPORT_REMOTE_DISCONNECT = 1,
    BLE_FEATURE_SUPPORT_DISCONNECT_BY_DEVICEID,
    BLE_FEATURE_SUPPORT_SUPPORT_NETWORKID_BASICINFO_EXCAHNGE,
};
typedef uint32_t ConnBleFeatureBitSet;

typedef struct {
    ListNode node;
    BleProtocolType protocol;
    uint32_t connectionId;
    ConnSideType side;
    bool fastestConnectEnable;
    char addr[BT_MAC_LEN];
    union {
        uint32_t psm;
    };
    // sequence is only read and modify in send thread, no need lock
    uint32_t sequence;
    // ble connection may be devide the data to several packet, so we should assemble them together
    ConnBleReadBuffer buffer;

    // protect variable access below
    SoftBusMutex lock;
    enum ConnBleConnectionState state;
    int32_t underlayerHandle;
    uint32_t mtu;
    char udid[UDID_BUF_LEN];
    char networkId[NETWORK_ID_BUF_LEN];
    ConnBleFeatureBitSet featureBitSet;
    // reference counter that record times required by buziness
    int32_t connectionRc;
    // reference counter that record times for memory management
    int32_t objectRc;

    // NOTICE: fields below are inner ones for helping connect progress, they are invalid after connection established
    int32_t retrySearchServiceCnt;
    SoftBusList *connectStatus;

    // ble Quick connection fails due to scan failures
    bool underlayerFastConnectFailedScanFailure;

    bool isOccupied;
} ConnBleConnection;

typedef struct {
    ListNode node;
    int32_t result;
    int32_t status;
} BleUnderlayerStatus;

typedef struct {
    void (*onServerAccepted)(uint32_t connectionId);
    void (*onConnected)(uint32_t connectionId);
    void (*onConnectFailed)(uint32_t connectionId, int32_t error);
    void (*onDataReceived)(uint32_t connectionId, bool isConnCharacteristic, uint8_t *data, uint32_t dataLen);
    void (*onConnectionClosed)(uint32_t connectionId, int32_t status);
    void (*onConnectionResume)(uint32_t connectionId);
} ConnBleConnectionEventListener;

// client unify listener
typedef struct {
    void (*onClientConnected)(uint32_t connectionId);
    void (*onClientFailed)(uint32_t connectionId, int32_t error);
    void (*onClientDataReceived)(uint32_t connectionId, bool isConnCharacteristic, uint8_t *data, uint32_t dataLen);
    void (*onClientConnectionClosed)(uint32_t connectionId, int32_t status);
} ConnBleClientEventListener;

// server unify listener
typedef struct {
    void (*onServerStarted)(BleProtocolType protocol, int32_t status);
    void (*onServerClosed)(BleProtocolType protocol, int32_t status);
    void (*onServerAccepted)(uint32_t connectionId);
    void (*onServerDataReceived)(uint32_t connectionId, bool isConnCharacteristic, uint8_t *data, uint32_t dataLen);
    void (*onServerConnectionClosed)(uint32_t connectionId, int32_t status);
} ConnBleServerEventListener;

// gatt and coc SHOULD implement
typedef struct {
    int32_t (*bleClientConnect)(ConnBleConnection *connection);
    int32_t (*bleClientDisconnect)(ConnBleConnection *connection, bool grace, bool refreshGatt);
    int32_t (*bleClientSend)(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
    int32_t (*bleClientUpdatePriority)(ConnBleConnection *connection, ConnectBlePriority priority);
    int32_t (*bleServerStartService)(void);
    int32_t (*bleServerStopService)(void);
    int32_t (*bleServerSend)(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
    int32_t (*bleServerConnect)(ConnBleConnection *connection);
    int32_t (*bleServerDisconnect)(ConnBleConnection *connection);
    int32_t (*bleClientInitModule)(SoftBusLooper *looper, const ConnBleClientEventListener *listener);
    int32_t (*bleServerInitModule)(SoftBusLooper *looper, const ConnBleServerEventListener *listener);
} BleUnifyInterface;

ConnBleConnection *ConnBleCreateConnection(
    const char *addr, BleProtocolType protocol, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable);
void ConnBleFreeConnection(ConnBleConnection *connection);
int32_t ConnBleStartServer(void);
int32_t ConnBleStopServer(void);
int32_t ConnBleConnect(ConnBleConnection *connection);
int32_t ConnBleDisconnectNow(ConnBleConnection *connection, enum ConnBleDisconnectReason reason);
int32_t ConnBleUpdateConnectionRc(ConnBleConnection *connection, uint16_t challengeCode, int32_t delta);
int32_t ConnBleOnReferenceRequest(ConnBleConnection *connection, const cJSON *json);
int32_t ConnBleUpdateConnectionPriority(ConnBleConnection *connection, ConnectBlePriority priority);
int32_t ConnBleSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
// connection will be disconnected forcely when idle more than CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS
void ConnBleRefreshIdleTimeout(ConnBleConnection *connection);
void ConnBleOccupy(ConnBleConnection *connection);

// complement connection device id
// NOTICE: MUST ONLY used in ble connection inner module
void ConnBleInnerComplementDeviceId(ConnBleConnection *connection);

int32_t ConnBleInitConnectionMudule(SoftBusLooper *looper, ConnBleConnectionEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_CONNECTION_H */

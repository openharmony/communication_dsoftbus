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

#ifndef SOFTBUS_CONN_BLE_MANAGER_H
#define SOFTBUS_CONN_BLE_MANAGER_H

#include <semaphore.h>

#include "common_list.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_connreporter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_CONNECT_TIMEOUT_MILLIS (10 * 1000)
#define BLE_CONNECT_KEEP_ALIVE_TIMEOUT_MILLIS (10 * 1000)
#define BLE_GATT_CONNECT_MAX_RETRY_COUNT (2)

enum ConnBleDeviceState {
    BLE_DEVICE_STATE_INIT,
    BLE_DEVICE_STATE_WAIT_EVENT,
    BLE_DEVICE_STATE_WAIT_SCHEDULE,
    BLE_DEVICE_STATE_SCHEDULING,
};

typedef struct {
    ListNode node;
    // SHOULD diff requests by protocol type
    BleProtocolType protocol;
    char addr[BT_MAC_LEN];
    // ble address will change over time and different advertisement, so devive is identified by udid first
    char udid[UDID_BUF_LEN];
    bool fastestConnectEnable;
    uint32_t psm;
    bool isSupportNetworkIdExchange;
    enum ConnBleDeviceState state;
    ListNode requests;
    // The ble connection failed to scan the broadcast due to a timeout of 3.1 seconds and was retried
    uint32_t retryCount;
} ConnBleDevice;

typedef struct {
    ListNode node;
    // SHOULD diff requests by protocol type
    BleProtocolType protocol;
    uint32_t requestId;
    uint16_t challengeCode; /* for ble direct */
    ConnectResult result;
    ConnectStatistics statistics;
} ConnBleRequest;

typedef struct {
    char addr[BT_MAC_LEN];
    char udid[UDID_BUF_LEN];
    bool fastestConnectEnable;
    BleProtocolType protocol;
    uint32_t requestId;
    uint32_t psm;
    uint16_t challengeCode; /* for ble direct */
    ConnectResult result;
    ConnectStatistics statistics;
} ConnBleConnectRequestContext;

typedef struct {
    uint32_t connectionId;
    bool isConnCharacteristic;
    uint8_t *data;
    uint32_t dataLen;
} ConnBleDataReceivedContext;

typedef struct {
    char addr[BT_MAC_LEN];
    char udid[UDID_BUF_LEN];
    uint32_t requestId;
    ProtocolType protocol;
} ConnBleReuseConnectionContext;

typedef struct {
    char *(*name)(void);
    void (*enter)(void);
    void (*exit)(void);
    void (*connectRequest)(const ConnBleConnectRequestContext *ctx);
    void (*handlePendingRequest)(void);
    void (*serverAccepted)(uint32_t connectionId);
    void (*clientConnected)(uint32_t connectionId);
    void (*clientConnectFailed)(uint32_t connectionId, int32_t error);
    void (*clientConnectTimeout)(uint32_t connectionId, const char *address);
    void (*dataReceived)(ConnBleDataReceivedContext *ctx);
    void (*connectionClosed)(uint32_t connectionId, int32_t error);
    void (*connectionResume)(uint32_t connectionId);
    void (*disconnectRequest)(uint32_t connectionId);
    int32_t (*reuseConnectionRequest)(const ConnBleReuseConnectionContext *ctx);
    void (*preventTimeout)(const char *udid);
    void (*reset)(int32_t reason);
    void (*keepAliveTimeout)(uint32_t connectionId, uint32_t requestId);
} ConnBleState;

int32_t ConnBleSaveConnection(ConnBleConnection *connection);
void ConnBleRemoveConnection(ConnBleConnection *connection);
ConnBleConnection *ConnBleGetConnectionByAddr(const char *addr, ConnSideType side, BleProtocolType protocol);
ConnBleConnection *ConnBleGetConnectionById(uint32_t connectionId);
ConnBleConnection *ConnBleGetConnectionByHandle(int32_t underlayerHandle, ConnSideType side, BleProtocolType protocol);
// get connection with different address and same udid
ConnBleConnection *ConnBleGetConnectionByUdid(const char *addr, const char *udid, BleProtocolType protocol);
// get connection with same udid and client side
ConnBleConnection *ConnBleGetClientConnectionByUdid(const char *udid, BleProtocolType protocol);
void ConnBleReturnConnection(ConnBleConnection **connection);
void NotifyReusedConnected(uint32_t connectionId, uint16_t challengeCode);
int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time);
int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId);
int32_t ConnBleDumper(ListNode *connectionSnapshots);

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_MANAGER_H */

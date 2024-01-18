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

#ifndef CONN_BR_MANAGER_H
#define CONN_BR_MANAGER_H

#include <stdint.h>

#include "softbus_conn_br_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_hisysevt_connreporter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BR_CONNECT_TIMEOUT_MILLIS                  (10 * 1000)

#define BR_CONNECTION_PEND_TIMEOUT_MAX_MILLIS      (10 * 1000)
#define BR_CONNECTION_ACL_CONNECT_COLLISION_MILLIS (6 * 1000)
#define BR_WAIT_BLE_DISCONNECTED_PEND_MILLIS       (10 * 1000)
#define BR_NIP_SEQ (0xeaddeaddeaddeadd)

enum ConnBrDeviceState {
    BR_DEVICE_STATE_INIT,
    BR_DEVICE_STATE_WAIT_EVENT,
    BR_DEVICE_STATE_PENDING,
    BR_DEVICE_STATE_WAIT_SCHEDULE,
    BR_DEVICE_STATE_SCHEDULING,
};

typedef struct {
    ListNode node;
    char addr[BT_MAC_LEN];
    enum ConnBrDeviceState state;
    ListNode requests;
} ConnBrDevice;

typedef struct {
    ListNode node;
    uint32_t requestId;
    ConnectResult result;
    ConnectStatistics statistics;
} ConnBrRequest;

typedef struct {
    uint32_t requestId;
    char addr[BT_MAC_LEN];
    ConnectResult result;
    ConnectStatistics statistics;
} ConnBrConnectRequestContext;

typedef struct {
    uint32_t connectionId;
    uint8_t *data;
    uint32_t dataLen;
} ConnBrDataReceivedContext;

typedef struct {
    char addr[BT_MAC_LEN];
    uint64_t firstStartTimestamp;
    uint32_t firstDuration;
    uint64_t startTimestamp;
    uint32_t duration;
} ConnBrPendInfo;

typedef struct {
    char *(*name)(void);
    void (*enter)(void);
    void (*exit)(void);
    void (*connectRequest)(const ConnBrConnectRequestContext *ctx);
    void (*handlePendingRequest)(void);
    void (*serverAccepted)(uint32_t connectionId);
    void (*clientConnected)(uint32_t connectionId);
    void (*clientConnectFailed)(uint32_t connectionId, int32_t error);
    void (*clientConnectTimeout)(uint32_t connectionId, const char *address);
    void (*dataReceived)(ConnBrDataReceivedContext *ctx);
    void (*connectionException)(uint32_t connectionId, int32_t error);
    void (*connectionResume)(uint32_t connectionId);
    void (*disconnectRequest)(uint32_t connectionId);
    void (*unpend)(const char *addr);
    void (*reset)(int32_t reason);
} ConnBrState;

int32_t ConnBrSaveConnection(ConnBrConnection *connection);
void ConnBrRemoveConnection(ConnBrConnection *connection);
ConnBrConnection *ConnBrGetConnectionByAddr(const char *addr, ConnSideType side);
ConnBrConnection *ConnBrGetConnectionById(uint32_t connectionId);
void ConnBrReturnConnection(ConnBrConnection **connection);

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback);

#ifdef __cplusplus
}
#endif /* __clpusplus */
#endif /* CONN_BR_MANAGER_H */

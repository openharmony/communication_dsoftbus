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

#ifndef CONN_BR_CONNECTION_H
#define CONN_BR_CONNECTION_H

#include <stdint.h>

#include "message_handler.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "wrapper_br_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_SOCKET_HANDLE                      (-1)
#define MAX_BR_READ_BUFFER_CAPACITY                (40 * 1000)
#define MAX_BR_MTU_SIZE                            (3 * 1024)

#define WAIT_BR_NEGOTIATION_CLOSING_TIMEOUT_MILLIS (3 * 1000)
#define RETRY_NOTIFY_REFERENCE_DELAY_MILLIS        (1 * 1000)

#define MAX_RETRY_COUNT                            (2)

enum ConnBrConnectionState {
    BR_CONNECTION_STATE_CONNECTING = 0,
    BR_CONNECTION_STATE_CONNECTED,
    BR_CONNECTION_STATE_EXCEPTION,
    BR_CONNECTION_STATE_NEGOTIATION_CLOSING,
    BR_CONNECTION_STATE_CLOSING,
    BR_CONNECTION_STATE_CLOSED,
    BR_CONNECTION_STATE_INVALID,
};

typedef struct {
    ListNode node;
    uint32_t connectionId;
    ConnSideType side;
    char addr[BT_MAC_LEN];
    uint32_t mtu;

    uint32_t retryCount;
    // protect variable access below
    SoftBusMutex lock;
    int32_t socketHandle;
    enum ConnBrConnectionState state;
    // reference counter that record times required by buziness
    int32_t connectionRc;
    // reference counter that record times for memory management
    int32_t objectRc;

    bool isOccupied;
    // congestion control
    int32_t window;
    int64_t sequence;
    int64_t waitSequence;
    int32_t ackTimeoutCount;
    // connect process status
    SoftBusList *connectProcessStatus;
} ConnBrConnection;

typedef struct {
    void (*onServerAccepted)(uint32_t connectionId);
    void (*onClientConnected)(uint32_t connectionId);
    void (*onClientConnectFailed)(uint32_t connectionId, int32_t error);
    void (*onDataReceived)(uint32_t connectionId, uint8_t *data, uint32_t dataLen);
    void (*onConnectionException)(uint32_t connectionId, int32_t error);
    void (*onConnectionResume)(uint32_t connectionId);
} ConnBrEventListener;

ConnBrConnection *ConnBrCreateConnection(const char *addr, ConnSideType side, int32_t socketHandle);
void ConnBrFreeConnection(ConnBrConnection *connection);

int32_t ConnBrUpdateConnectionRc(ConnBrConnection *connection, int32_t delta);
int32_t ConnBrOnReferenceRequest(ConnBrConnection *connection, const cJSON *json);
int32_t ConnBrOnReferenceResponse(ConnBrConnection *connection, const cJSON *json);
int32_t ConnBrConnect(ConnBrConnection *connection);
int32_t ConnBrDisconnectNow(ConnBrConnection *connection);
int32_t ConnBrStartServer(void);
int32_t ConnBrStopServer(void);

void ConnBrOccupy(ConnBrConnection *connection);

int32_t ConnBrConnectionMuduleInit(SoftBusLooper *looper, SppSocketDriver *sppDriver, ConnBrEventListener *listener);

#ifdef __cplusplus
}
#endif /* __clpusplus */
#endif /* CONN_BR_CONNECTION_H */

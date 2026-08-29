/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef P2P_API_H
#define P2P_API_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    P2P_STATE_INVALID,
    P2P_STATE_DISCONNECT,
    P2P_STATE_CONNECT,
    P2P_STATE_CONNECTING,
    P2P_STATE_DISCONNECTING,
    P2P_STATE_MAX,
} P2PState;

typedef enum {
    EVENT_INVALID = 0,
    REQ_CONNECT_P2P,
    REQ_DISCONNECT_P2P,
} RemoteEvent;

#define BT_MAC_LEN 17
#define UUID_STRING_LEN 38
typedef struct {
    char brMac[BT_MAC_LEN];
    char uuid[UUID_STRING_LEN];
} DeviceInfo;

typedef void (*RecvMsgCallback)(const DeviceInfo *device, const char *msgBody, uint32_t len);
typedef void (*P2PStateChangeCallback)(const DeviceInfo *device, P2PState state, int32_t reason);
typedef void (*RemoteEventCallback)(const DeviceInfo *device, RemoteEvent event);

typedef struct {
    P2PStateChangeCallback p2pStateCallback;
    RemoteEventCallback remoteEventCallback;
    RecvMsgCallback recvMsgCallback;
} FarFieldCallbackSt;

#define INVALID_SOCKET (-1)

int32_t FarFieldInitProxy(void);
int32_t FarFieldDeinitProxy(void);
bool FarFieldIsDeviceSupport(const DeviceInfo *device);
int32_t FarFieldRegisterCallback(const FarFieldCallbackSt *callback);
int32_t FarFieldOpenP2P(const DeviceInfo *device);
int32_t FarFieldCloseP2P(const DeviceInfo *device);
P2PState FarFieldGetP2PState(const DeviceInfo *device);
int32_t FarFieldSendMsg(const DeviceInfo *device, const uint8_t *data, uint32_t len);
int32_t FarFieldRefresh(const DeviceInfo *device);

#ifdef __cplusplus
}
#endif
#endif // P2P_API_H
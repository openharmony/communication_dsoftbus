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
#ifndef FAR_FIELD_PROXY_ADAPTER_H
#define FAR_FIELD_PROXY_ADAPTER_H

#include "softbus_common.h"
#include "proxy_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

// Enum types (must match p2p_api.h definitions)
typedef enum {
    P2P_STATE_INVALID = 0,
    P2P_STATE_DISCONNECT,
    P2P_STATE_CONNECT,
    P2P_STATE_CONNECTING,
    P2P_STATE_DISCONNECTING,
    P2P_STATE_CONNECTING_BY_PUSH,
    P2P_STATE_MAX,
} P2PState;

typedef enum {
    P2P_STATE_REASON_BT_SWITCH_ON = 0,
    P2P_STATE_REASON_BT_SWITCH_OFF,
    P2P_STATE_REASON_FAR_FIELD_ON,
    P2P_STATE_REASON_FAR_FIELD_OFF,
    P2P_STATE_REASON_NETWORK_ERROR,
    P2P_STATE_REASON_CONNECTING_BY_PUSH,
    P2P_STATE_REASON_SOFTBUS_SWITCH_OPEN,
    P2P_STATE_REASON_SOFTBUS_SWITCH_CLOSE,
    P2P_STATE_REASON_REFRESH,
} P2PStateChangeReason;

typedef enum {
    EVENT_INVALID = 0,
    REQ_CONNECT_P2P,
    REQ_DISCONNECT_P2P,
} RemoteEvent;

// P2PDeviceInfo: device information structure (shared with p2p_api.h)
typedef struct {
    char brMac[BT_MAC_LEN];
    char uuid[UUID_STRING_LEN];
} P2PDeviceInfo;

typedef void (*RecvMsgCallback)(const P2PDeviceInfo *device, const uint8_t *msgBody, uint32_t len);
typedef void (*P2PStateChangeCallback)(const P2PDeviceInfo *device, P2PState state, int32_t reason);
typedef void (*RemoteEventCallback)(const P2PDeviceInfo *device, RemoteEvent event);

typedef struct {
    P2PStateChangeCallback p2pStateCallback;
    RemoteEventCallback remoteEventCallback;
    RecvMsgCallback recvP2PMsgCallback;
} FarFieldCallbackSt;

typedef enum {
    FAR_FIELD_ADAPTER_SO_LOAD_FAILED,
    FAR_FIELD_ADAPTER_SYMBOL_NOT_FOUND,
    FAR_FIELD_ADAPTER_NOT_INITIALIZED,
    FAR_FIELD_ADAPTER_ALREADY_INITIALIZED,
    FAR_FIELD_ADAPTER_ALREADY_LOADED,
    FAR_FIELD_ADAPTER_NOT_LOADED,
    FAR_FIELD_ADAPTER_INVALID_PARAM,
    FAR_FIELD_ADAPTER_ERROR,
    FAR_FIELD_ADAPTER_TIMEOUT,
} FarFieldAdapterResult;

#define FAR_FIELD_P2P_OPEN_TIMEOUT_MS 30000  // 30 seconds timeout for P2P open

int32_t FarFieldAdapterInit(void);
void FarFieldAdapterDeinit(void);
bool FarFieldAdapterIsDeviceSupport(const P2PDeviceInfo *device);
int32_t FarFieldAdapterRegisterCallback(const FarFieldCallbackSt *callback);
int32_t FarFieldAdapterOpenP2P(const P2PDeviceInfo *device);
int32_t FarFieldAdapterCloseP2P(const P2PDeviceInfo *device);
P2PState FarFieldAdapterGetP2PState(const P2PDeviceInfo *device);
int32_t FarFieldAdapterSendMsg(const P2PDeviceInfo *device, const uint8_t *data, uint32_t len);
int32_t FarFieldAdapterRefresh(const P2PDeviceInfo *device);

// Adapter manager initialization (must be called before using the adapter)
int32_t FarFieldAdapterManagerInit(const FarFieldCallbackSt *callback);
void FarFieldAdapterManagerDeinit(void);

#ifdef __cplusplus
}
#endif

#endif // FAR_FIELD_PROXY_ADAPTER_H

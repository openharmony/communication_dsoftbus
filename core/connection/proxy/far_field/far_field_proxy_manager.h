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
#ifndef FAR_FIELD_PROXY_MANAGER_H
#define FAR_FIELD_PROXY_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include "far_field_proxy_adapter.h"
#include "../proxy_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    P2P_AVAILABLE_STATE = 0,
    P2P_REQUEST_CONNECTING,
    P2P_CONNECTING,
    P2P_WAIT_RECONNECTING,
    P2P_RECONNECTING,
    P2P_CONNECTED,
    P2P_REFRESHING,
    P2P_REFRESHING_TIMEOUT,
    P2P_DISCONNECTING,
    P2P_DISCONNECTED,
    FAR_FIELD_STATE_INVALID,
} FarFieldProxyState;

typedef struct {
    P2PDeviceInfo device;
    char srcMac[BT_MAC_MAX_LEN];
    uint32_t requestId;
} FarFieldProxyParam;

typedef struct {
    void (*onFarFieldProxyDataReceived)(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen);
    void (*onFarFieldProxyDisconnected)(struct ProxyChannel *channel, int32_t reason);
    void (*onFarFieldConnected)(uint32_t requestId, struct ProxyChannel *channel);
    void (*onFarFieldOpenFail)(uint32_t requestId, int32_t reason, const char *brMac);
} FarFieldProxyListener;

int32_t RegisterFarFieldProxyListener(FarFieldProxyListener *listener);
int32_t OpenFarFieldProxyChannel(FarFieldProxyParam *param);
void ClearFarFieldProxy(const char *addr);
int32_t FarFieldProxyManagerInit(void);
void FarFieldProxyManagerDeinit(void);
#ifdef __cplusplus
}
#endif

#endif // FAR_FIELD_PROXY_MANAGER_H


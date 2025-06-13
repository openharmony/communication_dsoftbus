/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef PROXY_CHANNEL_BR_CONNECTION_H
#define PROXY_CHANNEL_BR_CONNECTION_H

#include "proxy_manager.h"

#define BR_INVALID_SOCKET_HANDLE (-1)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*onDataReceived)(uint32_t channelId, uint8_t *data, uint32_t dataLen);
    void (*onDisconnected)(uint32_t channelId, int32_t reason);
} ProxyEventListener;

typedef struct {
    void (*onConnectSuccess)(uint32_t channelId);
    void (*onConnectFail)(uint32_t channelId, int32_t errorCode);
} ProxyBrConnectStateCallback;

typedef struct {
    // public methods
    int32_t (*registerEventListener)(const ProxyEventListener *listener);
    int32_t (*connect)(struct ProxyConnection *connection, const ProxyBrConnectStateCallback *callback);
    int32_t (*send)(struct ProxyConnection *connection, const uint8_t *data, uint32_t dataLen);
    int32_t (*disconnect)(struct ProxyConnection *connection);
} ProxyBrConnectionManager;

ProxyBrConnectionManager *GetProxyBrConnectionManager(void);

#ifdef __cplusplus
}
#endif
#endif /* PROXY_CHANNEL_BR_CONNECTION_H */
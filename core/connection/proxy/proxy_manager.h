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
#ifndef PROXY_CHANNEL_MANAGER_H
#define PROXY_CHANNEL_MANAGER_H

#include "common_list.h"
#include "softbus_adapter_thread.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UUID_STRING_LEN 38
// the length of the latter half of the hexString representing the sha256 hash value of mac address
#define BT_MAC_MAX_LEN 33

typedef struct {
    uint32_t requestId;
    char brMac[BT_MAC_MAX_LEN];
    char uuid[UUID_STRING_LEN];
    uint64_t timeoutMs;
} ProxyChannelParam;

typedef enum {
    PROXY_CHANNEL_CONNECTING,
    PROXY_CHANNEL_CONNECTED,
    PROXY_CHANNEL_DISCONNECTING,
    PROXY_CHANNEL_DISCONNECTED,
    PROXY_CHANNEL_MAX_STATE
} ProxyChannelState;

struct ProxyChannel {
    uint32_t requestId;
    uint32_t channelId;
    char brMac[BT_MAC_MAX_LEN];
    char uuid[UUID_STRING_LEN];
    int32_t (*send)(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen);
    void (*close)(struct ProxyChannel *channel, bool isClearReconnectEvent);
};

struct ProxyConnection {
    struct ProxyChannel proxyChannel;
    char brMac[BT_MAC_LEN];
    SoftBusMutex lock;
    uint32_t channelId;
    void (*reference)(struct ProxyConnection *proxyConnection);
    void (*dereference)(struct ProxyConnection *proxyConnection);
    uint32_t refCount;
    ProxyChannelState state;
    int32_t socketHandle;
    ListNode node;
};

typedef struct {
    void (*onProxyChannelDataReceived)(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen);
    void (*onProxyChannelDisconnected)(struct ProxyChannel *channel, int32_t reason);
    void (*onProxyChannelReconnected)(char *addr, struct ProxyChannel *channel);
} ProxyConnectListener;

typedef struct {
    void (*onOpenSuccess)(uint32_t requestId, struct ProxyChannel *channel);
    void (*onOpenFail)(uint32_t requestId, int32_t reason);
} OpenProxyChannelCallback;

typedef struct {
    uint32_t requestId;
    bool isInnerRequest;
    uint32_t innerRetryNum;
    bool isRealMac;
    char brMac[BT_MAC_LEN];
    char brHashMac[BT_MAC_MAX_LEN];
    char uuid[UUID_STRING_LEN];
    uint64_t timeoutMs;
    OpenProxyChannelCallback result;
    bool isAclConnected;
    bool isSupportHfp;
    ListNode node;
} ProxyConnectInfo;

typedef struct {
    uint32_t (*generateRequestId)(void);
    int32_t (*openProxyChannel)(ProxyChannelParam *param, const OpenProxyChannelCallback *callback);
    int32_t (*registerProxyChannelListener)(ProxyConnectListener *listener);

    // inner
    SoftBusList *proxyConnectionList;
    struct ProxyConnection *(*getConnectionById)(uint32_t channelId);
    // current process request info
    ProxyConnectInfo *proxyChannelRequestInfo;
    ListNode reconnectDeviceInfos;
} ProxyChannelManager;

ProxyChannelManager *GetProxyChannelManager(void);
int32_t ProxyChannelManagerInit(void);

#ifdef __cplusplus
}
#endif
#endif /* PROXY_CHANNEL_MANAGER_H */
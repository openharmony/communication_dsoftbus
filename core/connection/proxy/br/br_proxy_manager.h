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
#ifndef BR_PROXY_MANAGER_H
#define BR_PROXY_MANAGER_H

#include <stdint.h>
#include "../proxy_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROXY_CHANNEL_CONNECTING,
    PROXY_CHANNEL_CONNECTED,
    PROXY_CHANNEL_DISCONNECTING,
    PROXY_CHANNEL_DISCONNECTED,
    PROXY_CHANNEL_MAX_STATE
} ProxyChannelState;

typedef struct {
    void (*onProxyChannelDataReceived)(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen);
    void (*onProxyChannelDisconnected)(struct ProxyChannel *channel, int32_t reason);
    void (*onProxyChannelReconnected)(const char *addr, struct ProxyChannel *channel);
    void (*onBrProxyStateChanged)(uint32_t requestId, const char *addr);
} BrProxyListener;

// ProxyConnectInfo and ProxyConnection moved here from proxy_manager.h

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
    SoftBusList *connectProcessStatus;
};

typedef struct {
    uint32_t requestId;
    bool isInnerRequest;
    bool isSupportFarField;
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
    int32_t (*openBrProxyChannel)(ProxyChannelParam *param, bool isRealMac, bool isSupportFarField,
        const OpenProxyChannelCallback *callback);
    int32_t (*registerBrProxyListener)(BrProxyListener *listener);
    //void (*AttemptReconnectDevice)(char *brAddr);
    // inner
    SoftBusList *proxyConnectionList;
    struct ProxyConnection *(*getConnectionById)(uint32_t channelId);
    struct ProxyConnection *(*getProxyChannelByAddr)(char *addr);
    void (*updateDevInfoReqIdUnsafe)(const char *brMac, uint32_t newReqId);
    void (*clearDevInfoUnsafe)(struct ProxyChannel *channel);
    // current process request info
    ProxyConnectInfo *proxyChannelRequestInfo;
    ListNode reconnectDeviceInfos;
} BrProxyChannelManager;

BrProxyChannelManager *GetBrProxyChannelManager(void);
int32_t BrProxyChannelManagerInit(void);
#ifdef __cplusplus
}
#endif

#endif // BR_PROXY_MANAGER_H
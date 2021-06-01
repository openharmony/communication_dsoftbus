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

#ifndef SOFTBUS_INTERFACE_H
#define SOFTBUS_INTERFACE_H

#include "softbus.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SOFT_BUS_IPC_LEN 512
#define MAC_SOFT_BUS_IPC_LEN_EX 1024
#define SOFTBUS_SERVICE "softbus_service"

enum SoftBusFuncId {
    MANAGE_REGISTER_SERVICE = 0,

    SERVER_PUBLISH_SERVICE = 128,
    SERVER_UNPUBLISH_SERVICE,

    SERVER_CREATE_SESSION_SERVER,
    SERVER_REMOVE_SESSION_SERVER,
    SERVER_OPEN_SESSION,
    SERVER_CLOSE_CHANNEL,
    SERVER_SESSION_SENDMSG,

    SERVER_START_DISCOVERY,
    SERVER_STOP_DISCOVERY,

    SERVER_JOIN_LNN,
    SERVER_LEAVE_LNN,
    SERVER_GET_ALL_ONLINE_NODE_INFO,
    SERVER_GET_LOCAL_DEVICE_INFO,
    SERVER_GET_NODE_KEY_INFO,

    CLIENT_ON_CHANNEL_OPENED = 256,
    CLIENT_ON_CHANNEL_OPENFAILED,
    CLIENT_ON_CHANNEL_CLOSED,
    CLIENT_ON_CHANNEL_MSGRECEIVED,

    CLIENT_DISCOVERY_SUCC,
    CLIENT_DISCOVERY_FAIL,
    CLIENT_DISCOVERY_DEVICE_FOUND,
    CLIENT_PUBLISH_SUCC,
    CLIENT_PUBLISH_FAIL,

    CLIENT_ON_JOIN_RESULT,
    CLIENT_ON_LEAVE_RESULT,
    CLIENT_ON_NODE_ONLINE_STATE_CHANGED,
    CLIENT_ON_NODE_BASIC_INFO_CHANGED,
};

struct ServerProvideInterface {
    int (*registerService)(const char *clientPkgName, const void *svcId);

    int (*publishService)(const char *pkgName, const void *info);
    int (*unPublishService)(const char *pkgName, int publishId);

    int (*startDiscovery)(const char *pkgName, const void *info);
    int (*stopDiscovery)(const char *pkgName, int subscribeId);

    int (*createSessionServer)(const char *pkgName, const char *sessionName);
    int (*removeSessionServer)(const char *pkgName, const char *sessionName);
    int32_t (*openSession)(const char *mySessionName, const char *peerSessionName,
                       const char *peerDeviceId, const char *groupId, int flags);
    int (*closeChannel)(int32_t channelId);
    int (*sendMessage)(int32_t channelId, const void *data, uint32_t len, int32_t msgType);

    int (*joinLNN)(void *addr, uint32_t addrTypeLen);
    int (*leaveLNN)(const char *networkId);
    int (*getAllOnlineNodeInfo)(void **info, uint32_t infoTypeLen, int32_t *infoNum);
    int (*getLocalDeviceInfo)(void *info, uint32_t infoTypeLen);
    int (*getNodeKeyInfo)(const char *networkId, int key, unsigned char *buf, uint32_t len);
};

struct ClientProvideInterface {
    int (*onDeviceFound)(const char *pkgName, const void *device);
    int (*onDiscoverFailed)(const char *pkgName, int subscribeId, int failReason);
    int (*onDiscoverySuccess)(const char *pkgName, int subscribeId);
    int (*onPublishSuccess)(const char *pkgName, int publishId);
    int (*onPublishFail)(const char *pkgName, int publishId, int reason);

    int (*onChannelOpened)(const char *pkgName, const char *sessionName, const ChannelInfo *channel);
    int (*onChannelOpenFailed)(const char *pkgName, int32_t channelId);
    int (*onChannelClosed)(const char *pkgName, int32_t channelId);
    int (*onChannelMsgReceived)(const char *pkgName, int32_t channelId, const void *data, unsigned int len,
        int32_t type);

    int (*openChannel)(const char *udid, const char *pkgName, const char *requestId, const char *connectId);
    int (*closeChannel)(const char *connectId);
    int (*sendChannelMsg)(const char *connectId, const void *data, unsigned int len);

    int (*onJoinLNNResult)(const char *pkgName, void *addr, uint32_t addrTypeLen,
        const char *networkId, int32_t retCode);
    int (*onLeaveLNNResult)(const char *pkgName, const char *networkId, int32_t retCode);
    int (*onNodeOnlineStateChanged)(bool isOnline, void *info, uint32_t infoTypeLen);
    int (*onNodeBasicInfoChanged)(void *info, uint32_t infoTypeLen, int32_t type);
};

int ClientProvideInterfaceInit(void);
struct ClientProvideInterface *GetClientProvideInterface(void);
int ClientProvideInterfaceImplInit(void);
void ClientDeathProcTask(void);

int ServerProvideInterfaceInit(void);
struct ServerProvideInterface *GetServerProvideInterface(void);
int ServerProvideInterfaceImplInit(void);

void *SoftBusGetClientProxy(void);
void *SoftBusGetIpcContext(void);

#ifdef __cplusplus
}
#endif
#endif /* SOFTBUS_INTERFACE_H */
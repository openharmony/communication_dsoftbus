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

#ifndef P2PLINK_INTERFACE_H
#define P2PLINK_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#include "p2plink_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    void (*onConnected)(int32_t requestId, const char *myIp, const char *peerIp);
    void (*onConnectFailed)(int32_t requestId, int32_t reason);
} P2pLinkCb;

typedef struct {
    int32_t requestId;
    int64_t authId;
    char peerMac[P2P_MAC_LEN];
    P2pLinkRole expectedRole;
    int pid;
    P2pLinkCb cb;
} P2pLinkConnectInfo;

typedef struct {
    int64_t authId;
    char peerMac[P2P_MAC_LEN];
    int pid;
} P2pLinkDisconnectInfo;

typedef struct {
    void (*onMyRoleChange)(P2pLinkRole myRole);
    void (*onDevOffline)(const char *peerMac);
} P2pLinkPeerDevStateCb;

typedef struct {
    P2pLinkRole peerRole;
    P2pLinkRole expectedRole;
    char peerGoMac[P2P_MAC_LEN];
    char peerMac[P2P_MAC_LEN];
    bool isBridgeSupported;
} RoleIsConflictInfo;

int32_t P2pLinkGetRequestId(void);
int32_t P2pLinkConnectDevice(const P2pLinkConnectInfo *info);
int32_t P2pLinkDisconnectDevice(const P2pLinkDisconnectInfo *info);
int32_t P2pLinkInit(void);

void P2pLinkRegPeerDevStateChange(const P2pLinkPeerDevStateCb *cb);
int32_t P2pLinkGetLocalIp(char *localIp, int32_t localIpLen);

int32_t P2pLinkIsRoleConflict(const RoleIsConflictInfo *info);

int32_t P2pLinkGetPeerMacByPeerIp(const char *peerIp, char *peerMac, int32_t macLen);
int32_t P2pLinkQueryDevIsOnline(const char *peerMac);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_INTERFACE_H */
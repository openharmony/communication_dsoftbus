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

#ifndef P2PLINK_DEVICE_H
#define P2PLINK_DEVICE_H

#include "p2plink_type.h"
#include "p2plink_interface.h"
#include "p2plink_adapter.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    P2PLINK_MANAGER_STATE_NONE,
    P2PLINK_MANAGER_STATE_REUSE,
    P2PLINK_MANAGER_STATE_NEGO_WAITING,
    P2PLINK_MANAGER_STATE_NEGOING,
    P2PLINK_MANAGER_STATE_AUTHBUILD,
    P2PLINK_MANAGER_STATE_HANDSHAKE,
} P2pLinkMangerState;

typedef struct {
    ListNode node;
    P2pLinkConnectInfo connInfo;
    int32_t reTryCnt;
    int32_t state;
    int32_t timeOut;
    char myIp[P2P_IP_LEN];
    char peerIp[P2P_IP_LEN];
    char peerMac[P2P_MAC_LEN];
} ConnectingNode;

typedef enum {
    P2PLINK_AUTHCHAN_UNFINISH,
    P2PLINK_AUTHCHAN_CREATEING,
    P2PLINK_AUTHCHAN_FINISH,
} P2pLinkP2pAuthIdState;

typedef struct {
    int64_t inAuthId;
    int64_t p2pAuthId;
    uint32_t authRequestId;
    P2pLinkP2pAuthIdState p2pAuthIdState;
} P2pLinkAuthId;

typedef struct {
    ListNode node;
    char peerMac[P2P_MAC_LEN];
    char peerIp[P2P_IP_LEN];
    char localIp[P2P_IP_LEN];
    P2pLinkAuthId chanId;
} ConnectedNode;

ConnectedNode *P2pLinkGetConnedDevByMac(const char *peerMac);
void P2pLinkAddConnedDev(ConnectedNode *item);
int32_t P2pLinkConnedIsEmpty(void);
ConnectedNode *P2pLinkGetConnedByAuthReqeustId(uint32_t reqeustId);
void P2pLinkUpdateDeviceByMagicGroups(const P2pLinkGroup *group);

void P2pLinkAddConningDev(ConnectingNode *item);
ConnectingNode *P2pLinkGetConningByPeerMacState(const char *peerMac, int state);
ConnectingNode *P2pLinkGetConningDevByReqId(int32_t reqId);
void P2pLinkDelConning(int32_t reqId);
void P2pLinkConningCallback(const ConnectingNode *item, int32_t ret, int32_t failReason);
void P2pLinkDumpDev(void);
int32_t P2pLinkDevInit(void);
void P2pLinkDevClean(void);

void P2pLinkSetDevStateCallback(const P2pLinkPeerDevStateCb *cb);
void P2pLinkDelConnedByAuthId(int64_t authId);
ConnectedNode *P2pLinkGetConnedDevByPeerIp(const char *peerIp);
void P2pLinkMyRoleChangeNotify(P2pLinkRole myRole);
void P2pLinkUpdateInAuthId(const char *peerMac, int64_t authId);
void P2pLinkDevEnterDiscState(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* __P2PLINK_DEVICE_H */
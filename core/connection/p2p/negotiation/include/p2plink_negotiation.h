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

#ifndef P2PLINK_NEGOTIATION_H
#define P2PLINK_NEGOTIATION_H

#include <stdbool.h>
#include <stdint.h>

#include "cJSON.h"
#include "p2plink_adapter.h"
#include "p2plink_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    CONTENT_TYPE_GO_INFO = 1,
    CONTENT_TYPE_GC_INFO,
    CONTENT_TYPE_RESULT,
} P2pContentType;

typedef struct {
    int32_t cmdType;
    int32_t version;
    int32_t role;
    int32_t expectedRole;
    bool isbridgeSupport;
    P2pContentType contentType;
    char myMac[P2P_MAC_LEN];
    char wifiCfg[WIFI_CONFIG_DATA_LEN];
    char data[0];
} P2pRequestMsg;

typedef struct {
    int32_t cmdType;
    int32_t version;
    int32_t result;
    P2pContentType contentType;
    char myMac[P2P_MAC_LEN];
    char myIp[P2P_IP_LEN];
    char wifiCfg[WIFI_CONFIG_DATA_LEN];
    char data[0];
} P2pRespMsg;

typedef enum {
    P2PLINK_NEG_IDLE = 0,
    P2PLINK_NEG_ROLE_NEGOING,
    P2PLINK_NEG_GROUP_CREATING,
    P2PLINK_NEG_GROUP_WAIT_CONNECTING,
    P2PLINK_NEG_CONNECTING,
    P2PLINK_NEG_DHCP_STATE,
    P2PLINK_NEG_MAX_STATE,
} P2pLinkNegoState;

typedef struct {
    char localIp[P2P_IP_LEN];
    char localMac[P2P_MAC_LEN];
    char peerIp[P2P_IP_LEN];
    char peerMac[P2P_MAC_LEN];
    int32_t goPort;
    int64_t authId;
} P2pLinkNegoConnResult;

typedef struct {
    int64_t authId;
    int32_t requestId;
    int32_t expectRole;
    char peerMac[P2P_MAC_LEN];
} P2pLinkNegoConnInfo;

typedef void (*P2pLinkNegoOnconnected)(int32_t requestId, const P2pLinkNegoConnResult *result);
typedef void (*P2pLinkNegoOnconnectFailed)(int32_t requestId, int32_t reason);
typedef void (*P2pLinkNegoOnPeerConnected)(const P2pLinkNegoConnResult *result);

typedef struct {
    P2pLinkNegoOnconnected onConnected;
    P2pLinkNegoOnconnectFailed onConnectFailed;
    P2pLinkNegoOnPeerConnected onPeerConnected;
} P2pLinkNegoCb;

int32_t P2pLinkNegoInit(const P2pLinkNegoCb *callback);

void P2pLinkNegoStart(const P2pLinkNegoConnInfo *connInfo);
void P2pLinkNegoStop(void);

P2pLinkNegoState GetP2pLinkNegoStatus(void);

void P2pLinkNegoMsgProc(int64_t authId, int32_t cmdType, const cJSON *data);
void P2pLinkNegoOnGroupChanged(const P2pLinkGroup *group);
void P2pLinkNegoOnConnectState(int32_t state);

int32_t P2pLinkNegoGetFinalRole(int32_t peerRole, int32_t peerExpectRole, const char *peerGoMac, bool isSupportBridge);
char *P2pLinkNegoGetCurrentPeerMac(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_NEGOTIATION_H */

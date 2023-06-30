/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_LANE_LINK_H
#define LNN_LANE_LINK_H

#include <stdint.h>
#include "lnn_lane_def.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    char peerBleMac[MAX_MAC_LEN];
    int32_t psm;
    int32_t pid;
    bool networkDelegate;
    bool isReuse;
    LaneTransType transType;
    LaneLinkType linkType;
} LinkRequest;

typedef struct {
    int32_t channel;
    LaneBandwidth bw;
    WlanConnInfo connInfo;
} WlanLinkInfo;

typedef struct {
    int32_t channel;
    LaneBandwidth bw;
    P2pConnInfo connInfo;
} P2pLinkInfo;

typedef struct {
    char brMac[BT_MAC_LEN];
} BrLinkInfo;

// 'GATT' and 'CoC' protocols under BLE use the same definitions
typedef struct {
    char bleMac[BT_MAC_LEN];
    int32_t psm;
} BleLinkInfo;

// 'GATT' and 'CoC' protocols under BLE use the same definitions
typedef struct {
    BleProtocolType protoType;
    int32_t psm; // mark--
    char nodeIdHash[NODEID_SHORT_HASH_LEN];
    char localUdidHash[UDID_SHORT_HASH_LEN];
    char peerUdidHash[SHA_256_HASH_LEN];
} BleDirectInfo;

typedef struct {
    LaneLinkType type;
    union {
        WlanLinkInfo wlan;
        P2pLinkInfo p2p;
        BrLinkInfo br;
        BleLinkInfo ble;
        BleDirectInfo bleDirect;
    } linkInfo;
} LaneLinkInfo;

typedef struct {
    void (*OnLaneLinkSuccess)(uint32_t reqId, const LaneLinkInfo *linkInfo);
    void (*OnLaneLinkFail)(uint32_t reqId, int32_t reason);
    void (*OnLaneLinkException)(uint32_t reqId, int32_t reason);
} LaneLinkCb;

int32_t InitLaneLink(void);
void DeinitLaneLink(void);
int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb);
void DestroyLink(const char *networkId, uint32_t reqId, LaneLinkType type, int32_t pid);

void LaneDeleteP2pAddress(const char *networkId);
void LaneAddP2pAddress(const char *networkId, const char *ipAddr, uint16_t port);

void LaneAddP2pAddressByIp(const char *ipAddr, uint16_t port);
void LaneUpdateP2pAddressByIp(const char *ipAddr, const char *networkId);

#ifdef __cplusplus
}
#endif
#endif /* LNN_LANE_LINK_H */
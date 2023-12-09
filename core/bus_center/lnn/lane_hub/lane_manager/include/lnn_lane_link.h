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
    bool networkDelegate;
    bool p2pOnly;
    LaneLinkType linkType;
    ProtocolType acceptableProtocols;
    int32_t pid;
    //OldInfo
    LaneTransType transType;
    char peerBleMac[MAX_MAC_LEN];
    int32_t psm;
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
    BleProtocolType protoType;
    char bleMac[BT_MAC_LEN];
    char deviceIdHash[UDID_HASH_LEN];
    int32_t psm;
} BleLinkInfo;

// 'GATT' and 'CoC' protocols under BLE use the same definitions
typedef struct {
    BleProtocolType protoType;
    char networkId[NETWORK_ID_BUF_LEN];
} BleDirectInfo;

typedef struct {
    ListNode node;
    LaneLinkType type;
    union {
        WlanLinkInfo wlan;
        P2pLinkInfo p2p;
        BrLinkInfo br;
        BleLinkInfo ble;
        BleDirectInfo bleDirect;
    } linkInfo;
    uint32_t laneId;
} LaneLinkInfo;

typedef struct {
    ListNode node;
    LaneLinkType type;
    union {
        WlanLinkInfo wlan;
        P2pLinkInfo p2p;
        BrLinkInfo br;
        BleLinkInfo ble;
        BleDirectInfo bleDirect;
    } linkInfo;
    bool isReliable;
    uint32_t laneTimeliness;
    uint32_t laneScore;
    uint32_t laneFload;
    uint32_t laneRef;
} LaneResource;

typedef struct {
    void (*OnLaneLinkSuccess)(uint32_t reqId, const LaneLinkInfo *linkInfo);
    void (*OnLaneLinkFail)(uint32_t reqId, int32_t reason);
    void (*OnLaneLinkException)(uint32_t reqId, int32_t reason);
} LaneLinkCb;

int32_t InitLaneLink(void);
void DeinitLaneLink(void);
int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb);
void DestroyLink(const char *networkId, uint32_t reqId, LaneLinkType type, int32_t pid);

void LaneDeleteP2pAddress(const char *networkId, bool isDestroy);
void LaneAddP2pAddress(const char *networkId, const char *ipAddr, uint16_t port);

void LaneAddP2pAddressByIp(const char *ipAddr, uint16_t port);
void LaneUpdateP2pAddressByIp(const char *ipAddr, const char *networkId);

int32_t FindLaneResourceByLinkInfo(const LaneLinkInfo *linkInfoItem, LaneResource *laneResourceItem);
int32_t AddLaneResourceItem(const LaneResource *resourceItem);
int32_t DelLaneResourceItem(const LaneResource *resourceItem);
int32_t AddLinkInfoItem(const LaneLinkInfo *linkInfoItem);
int32_t DelLinkInfoItem(uint32_t laneId);
int32_t FindLaneLinkInfoByLaneId(uint32_t laneId, LaneLinkInfo *linkInfoitem);
int32_t ConvertToLaneResource(const LaneLinkInfo *linkInfo, LaneResource *laneResourceInfo);
int32_t DelLaneResourceItemWithDelay(LaneResource *resourceItem, uint32_t laneId, bool *isDelayDestroy);
void HandleLaneReliabilityTime(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_LANE_LINK_H */
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
#include "lnn_lane_link_conflict.h"
#include "bus_center_info_key.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COC_DIRECT_LATENCY      1200
#define BR_LATENCY              2500
#define WLAN_LATENCY            800
#define P2P_LATENCY             1600
#define BLE_LATENCY             1500
#define HML_LATENCY             1500
#define BR_REUSE_LATENCY        1000

typedef struct {
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    bool networkDelegate;
    bool p2pOnly;
    //OldInfo
    char peerBleMac[MAX_MAC_LEN];
    bool isSupportIpv6;
    bool isInnerCalled; // Indicates whether to select a link for TransOpenNetWorkingChannel
    int32_t psm;
    LaneTransType transType;
    uint32_t actionAddr;

    LaneLinkType linkType;
    ProtocolType acceptableProtocols;
    int32_t pid;
    uint32_t bandWidth;
    uint64_t triggerLinkTime;
    uint64_t availableLinkTime;
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
    char deviceIdHash[UDID_HASH_LEN];
    BleProtocolType protoType;
    int32_t psm;
} BleLinkInfo;

// 'GATT' and 'CoC' protocols under BLE use the same definitions
typedef struct {
    BleProtocolType protoType;
    char networkId[NETWORK_ID_BUF_LEN];
} BleDirectInfo;

typedef struct {
    char peerUdid[UDID_BUF_LEN];
    char netifName[NET_IF_NAME_LEN];
    LaneLinkType type;
    union {
        WlanLinkInfo wlan;
        P2pLinkInfo p2p;
        BrLinkInfo br;
        BleLinkInfo ble;
        BleDirectInfo bleDirect;
        RawWifiDirectConnInfo rawWifiDirect;
    } linkInfo;
} LaneLinkInfo;

typedef struct {
    bool isServerSide;
    uint32_t laneScore;
    uint32_t laneFload;
    uint32_t clientRef;
    LaneLinkInfo link;
    ListNode node;
    uint64_t laneId;
} LaneResource;

typedef struct {
    void (*onLaneLinkSuccess)(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo);
    void (*onLaneLinkFail)(uint32_t reqId, int32_t reason, LaneLinkType linkType);
} LaneLinkCb;

int32_t InitLaneLink(void);
void DeinitLaneLink(void);
int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb);
int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type);

void LaneDeleteP2pAddress(const char *networkId, bool isDestroy);
void LaneAddP2pAddress(const char *networkId, const char *ipAddr, uint16_t port);

void LaneAddP2pAddressByIp(const char *ipAddr, uint16_t port);
void LaneUpdateP2pAddressByIp(const char *ipAddr, const char *networkId);
void DetectEnableWifiDirectApply(void);
void DetectDisableWifiDirectApply(void);

int32_t FindLaneResourceByLinkAddr(const LaneLinkInfo *info, LaneResource *resource);
int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource);
int32_t CheckLaneResourceNumByLinkType(const char *peerUdid, LaneLinkType type, int32_t *laneNum);
int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide);
int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide);
int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource);
int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid);
uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType);
int32_t ClearLaneResourceByLaneId(uint64_t laneId);
int32_t GetAllDevIdWithLinkType(LaneLinkType type, char **devIdList, uint8_t *devIdCnt);
int32_t QueryOtherLaneResource(const DevIdentifyInfo *inputInfo, LaneLinkType type);
bool FindLaneResourceByDevInfo(const DevIdentifyInfo *inputInfo, LaneLinkType type);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_LINK_H
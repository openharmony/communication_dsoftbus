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

#ifndef LNN_LANE_INTERFACE_H
#define LNN_LANE_INTERFACE_H

#include <stdint.h>
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_LANE_REQ_ID 0
#define INVALID_LANE_ID 0
#define DB_MAGIC_NUMBER 0x5A5A5A5A
#define MESH_MAGIC_NUMBER 0xA5A5A5A5

typedef enum {
    LANE_BR = 0x0,
    LANE_BLE,
    LANE_P2P,
    LANE_WLAN_2P4G,
    LANE_WLAN_5G,
    LANE_ETH,
    LANE_P2P_REUSE,
    LANE_BLE_DIRECT,
    LANE_BLE_REUSE,
    LANE_COC,
    LANE_COC_DIRECT,
    LANE_HML,
    LANE_HML_RAW,
    LANE_LINK_TYPE_BUTT,
} LaneLinkType;

typedef enum {
    LANE_T_CTRL = 0x0,
    LANE_T_MIX,
    LANE_T_BYTE,
    LANE_T_MSG,
    LANE_T_FILE,
    LANE_T_RAW_STREAM,
    LANE_T_COMMON_VIDEO,
    LANE_T_COMMON_VOICE,
    LANE_T_BUTT,
} LaneTransType;

typedef enum {
    LANE_STATE_OK = 0,
    LANE_STATE_LINKUP,
    LANE_STATE_LINKDOWN,
} LaneState;

typedef enum {
    LANE_REQUEST_INFO_INVALID,
    LANE_RESOURCE_EXHAUSTED,
    LANE_LINK_FAILED,
} LaneRequestFailReason;

typedef enum {
    LANE_LINK_TYPE_WIFI_WLAN = 1,
    LANE_LINK_TYPE_WIFI_P2P = 2,
    LANE_LINK_TYPE_BR = 3,
    LANE_LINK_TYPE_COC_DIRECT = 4,
    LANE_LINK_TYPE_BLE_DIRECT = 5,
    LANE_LINK_TYPE_HML = 6,
    LANE_LINK_TYPE_MAX,
} LaneSpecifiedLink;

typedef struct {
    char brMac[BT_MAC_LEN];
} BrConnInfo;

typedef struct {
    BleProtocolType protoType;
    char bleMac[BT_MAC_LEN];
    char deviceIdHash[UDID_HASH_LEN];
    int32_t psm;
} BleConnInfo;

typedef struct {
    BleProtocolType protoType;
    char networkId[NETWORK_ID_BUF_LEN];
} BleDirectConnInfo;

typedef struct {
    uint16_t protocol;
    char localIp[IP_LEN];
    char peerIp[IP_LEN];
} P2pConnInfo;

typedef struct {
    ProtocolType protocol;
    char addr[MAX_SOCKET_ADDR_LEN];
    uint16_t port;
} WlanConnInfo;

typedef struct {
    bool isReuse;
    char localIp[IP_LEN];
    char peerIp[IP_LEN];
    uint16_t protocol;
    int32_t port;
    int32_t pid;
} RawWifiDirectConnInfo;

typedef struct {
    uint64_t laneId;
    LaneLinkType type;
    union {
        BrConnInfo br;
        BleConnInfo ble;
        P2pConnInfo p2p;
        WlanConnInfo wlan;
        BleDirectConnInfo bleDirect;
        RawWifiDirectConnInfo rawWifiDirect;
    } connInfo;
} LaneConnInfo;

typedef enum {
    LANE_OWNER_SELF = 0x0,
    LANE_OWNER_OTHER,
    LANE_OWNER_BUTT,
} LaneOwner;

typedef enum {
    LANE_QOS_BW_HIGH = 0x0,
    LANE_QOS_BW_MID,
    LANE_QOS_BW_LOW,
    LANE_QOS_BW_BUTT,
} LaneQosEvent;

typedef struct {
    void (*onLaneAllocSuccess)(uint32_t laneHandle, const LaneConnInfo *info);
    void (*onLaneAllocFail)(uint32_t laneHandle, int32_t errCode);
    void (*onLaneFreeSuccess)(uint32_t laneHandle);
    void (*onLaneFreeFail)(uint32_t laneHandle, int32_t errCode);
    void (*onLaneQosEvent)(uint32_t laneHandle, LaneOwner laneOwner, LaneQosEvent qosEvent);
} LaneAllocListener;

typedef struct {
    void (*onLaneRequestSuccess)(uint32_t laneReqId, const LaneConnInfo *info);
    void (*onLaneRequestFail)(uint32_t laneReqId, int32_t errCode);
} ILaneListener;

typedef enum {
    LANE_TYPE_HDLC = 0x0,
    LANE_TYPE_TRANS,
    LANE_TYPE_CTRL,
    LANE_TYPE_BUTT,
} LaneType;

typedef enum {
    QUERY_RESULT_OK = 0,
    QUERY_RESULT_RESOURCE_LIMIT,
    QUERY_RESULT_UNKNOWN,
    QUERY_RESULT_REQUEST_ILLEGAL,
} QueryResult;

typedef enum {
    LANE_RTT_LEVEL_DEFAULT = 0,
    LANE_RTT_LEVEL_LOW = 1,
} LaneRttLevel;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    LaneTransType transType;
} LaneQueryInfo;

typedef struct {
    uint32_t linkTypeNum;
    LaneLinkType linkType[LANE_LINK_TYPE_BUTT];
} LanePreferredLinkList;

typedef struct {
    uint32_t minBW;
    uint32_t maxLaneLatency;
    uint32_t minLaneLatency;
    LaneRttLevel rttLevel;
    bool continuousTask;
    bool reuseBestEffort;
} QosInfo;

typedef struct {
    char localMac[MAX_MAC_LEN];
    char remoteMac[MAX_MAC_LEN];
} LnnMacInfo;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char peerBleMac[MAX_MAC_LEN];
    bool networkDelegate;
    bool p2pOnly;
    bool isSupportIpv6;
    bool isInnerCalled; // Indicates whether to select a link for TransOpenNetWorkingChannel
    LaneTransType transType;
    ProtocolType acceptableProtocols;
    int32_t pid;
    //'psm' is valid only when 'expectedlink' contains 'LANE_COC'
    int32_t psm;
    uint32_t expectedBw;
    uint32_t actionAddr;
    LanePreferredLinkList expectedLink;
} TransOption;

typedef struct {
    LaneType type;
    union {
        TransOption trans;
    } requestInfo;
} LaneRequestOption;

typedef struct {
    LaneType type;
    LaneTransType transType;
    uint32_t actionAddr;
    QosInfo qosRequire;
} RawLaneAllocInfo;

typedef struct {
    void (*onLaneLinkup)(uint64_t laneId, const char *peerUdid, const LaneConnInfo *laneConnInfo);
    void (*onLaneLinkdown)(uint64_t laneId, const char *peerUdid, const LaneConnInfo *laneConnInfo);
    void (*onLaneStateChange)(uint64_t laneId, LaneState state);
} LaneStatusListener;

typedef struct {
    char peerBleMac[MAX_MAC_LEN];
    bool networkDelegate;
    bool isSpecifiedLink;
    bool isSupportIpv6;
    LaneSpecifiedLink linkType;
    uint32_t actionAddr;
} AllocExtendInfo;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    LaneType type;
    LaneTransType transType;
    int32_t pid;
    ProtocolType acceptableProtocols;
    QosInfo qosRequire;
    AllocExtendInfo extendInfo;
} LaneAllocInfo;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    bool isSupportIpv6;
    LaneTransType transType;
    uint32_t actionAddr;
} LaneAllocCommInfo;

typedef struct {
    LaneType type;
    LanePreferredLinkList linkList;
    LaneAllocCommInfo commInfo;
} LaneAllocInfoExt;

typedef struct {
    int32_t (*lnnQueryLaneResource)(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo);
    uint32_t (*lnnGetLaneHandle)(LaneType type);
    int32_t (*lnnAllocLane)(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener);
    int32_t (*lnnAllocRawLane)(uint32_t laneHandle, const RawLaneAllocInfo *request,
        const LaneAllocListener *listener);
    int32_t (*lnnReAllocLane)(uint32_t laneHandle, uint64_t laneId, const LaneAllocInfo *allocInfo,
        const LaneAllocListener *listener);
    int32_t (*lnnAllocTargetLane)(uint32_t laneHandle, const LaneAllocInfoExt *allocInfo,
        const LaneAllocListener *listener);
    int32_t (*lnnCancelLane)(uint32_t laneHandle);
    int32_t (*lnnFreeLane)(uint32_t laneHandle);
    int32_t (*registerLaneListener)(LaneType type, const LaneStatusListener *listener);
    int32_t (*unRegisterLaneListener)(LaneType type);
} LnnLaneManager;

LnnLaneManager* GetLaneManager(void);

int32_t LnnQueryLaneResource(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo);
uint32_t ApplyLaneReqId(LaneType type);
int32_t LnnRequestLane(uint32_t laneReqId, const LaneRequestOption *request, const ILaneListener *listener);
int32_t LnnFreeLane(uint32_t laneReqId);
int32_t GetMacInfoByLaneId(uint64_t laneId, LnnMacInfo *macInfo);

#ifdef __cplusplus
}
#endif
#endif // LNN_LANE_INTERFACE_H
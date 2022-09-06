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

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_LANE_ID 0

typedef enum {
    LANE_BR = 0x0,
    LANE_BLE,
    LANE_P2P,
    LANE_WLAN_2P4G,
    LANE_WLAN_5G,
    LANE_ETH,
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
    LANE_STATE_EXCEPTION,
} LaneState;

typedef enum {
    LANE_REQUEST_INFO_INVALID,
    LANE_RESOURCE_EXHAUSTED,
    LANE_LINK_FAILED,
} LaneRequestFailReason;

typedef struct {
    char brMac[BT_MAC_LEN];
} BrConnInfo;

typedef struct {
    char bleMac[BT_MAC_LEN];
} BleConnInfo;

typedef struct {
    uint16_t protocol;
    char localIp[IP_LEN];
    char peerIp[IP_LEN];
} P2pConnInfo;

typedef struct {
    uint16_t protocol;
    char addr[MAX_SOCKET_ADDR_LEN];
    uint16_t port;
} WlanConnInfo;

typedef struct {
    LaneLinkType type;
    union {
        BrConnInfo br;
        BleConnInfo ble;
        P2pConnInfo p2p;
        WlanConnInfo wlan;
    } connInfo;
} LaneConnInfo;

typedef struct {
    void (*OnLaneRequestSuccess)(uint32_t laneId, const LaneConnInfo *info);
    void (*OnLaneRequestFail)(uint32_t laneId, LaneRequestFailReason reason);
    void (*OnLaneStateChange)(uint32_t laneId, LaneState state);
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

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    LaneTransType transType;
    uint32_t expectedBw;
} LaneQueryInfo;

typedef struct {
    uint32_t linkTypeNum;
    LaneLinkType linkType[LANE_LINK_TYPE_BUTT];
} LanePreferredLinkList;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    LaneTransType transType;
    uint32_t expectedBw;
    int32_t pid;
    LanePreferredLinkList expectedLink;
} TransOption;

typedef struct {
    LaneType type;
    union {
        TransOption trans;
    } requestInfo;
} LaneRequestOption;

QueryResult LnnQueryLaneResource(const LaneQueryInfo *queryInfo);
uint32_t ApplyLaneId(LaneType type);
int32_t LnnRequestLane(uint32_t laneId, const LaneRequestOption *request, const ILaneListener *listener);
int32_t LnnFreeLane(uint32_t laneId);

#ifdef __cplusplus
}
#endif
#endif
/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_smart_communication.h"

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_info.h"
#include "lnn_lane_link.h"
#include "lnn_net_capability.h"
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static int32_t GetLaneOf5GWlan(const char *netWorkId, int32_t pid, LnnLaneProperty prop);
static int32_t GetLaneOf2P4GWlan(const char *netWorkId, int32_t pid, LnnLaneProperty prop);
static int32_t GetLaneOfBR(const char *netWorkId, int32_t pid, LnnLaneProperty prop);
static int32_t GetLaneOfP2p(const char *netWorkId, int32_t pid, LnnLaneProperty prop);
typedef int32_t (*GetLaneByType)(const char *netWorkId, int32_t pid, LnnLaneProperty prop);

typedef struct {
    uint8_t preferredLinkNum;
    GetLaneByType getLaneByType[LNN_LINK_TYPE_BUTT];
} SmartLaneMapEntry;

SmartLaneMapEntry g_smartLaneMap[LNN_LANE_PROPERTY_BUTT] = {
    [LNN_MESSAGE_LANE] = {3, {GetLaneOf5GWlan, GetLaneOf2P4GWlan, GetLaneOfBR}}, // the preferredLinkNum is 3
    [LNN_BYTES_LANE] = {3, {GetLaneOf5GWlan, GetLaneOf2P4GWlan, GetLaneOfBR}}, // the preferredLinkNum is 3
    [LNN_FILE_LANE] = {4, {GetLaneOf5GWlan, GetLaneOfP2p, GetLaneOf2P4GWlan, GetLaneOfBR}}, // the preferredLinkNum is 4
    [LNN_STREAM_LANE] = {3, {GetLaneOf5GWlan, GetLaneOfP2p, GetLaneOf2P4GWlan}}, // the preferredLinkNum is 3
};

GetLaneByType g_linkLaneTable[LINK_TYPE_MAX + 1] = {
    [LINK_TYPE_WIFI_WLAN_5G] = GetLaneOf5GWlan,
    [LINK_TYPE_WIFI_WLAN_2G] = GetLaneOf2P4GWlan,
    [LINK_TYPE_WIFI_P2P] = GetLaneOfP2p,
    [LINK_TYPE_BR] = GetLaneOfBR,
};

static bool IsSupportUdp(LnnLaneProperty prop)
{
    if (prop == LNN_FILE_LANE || prop == LNN_STREAM_LANE) {
        return true;
    } else {
        return false;
    }
}

static void GetLaneEntryList(const LnnPreferredLinkList *linkList, LnnLaneProperty prop,
    SmartLaneMapEntry *laneEntryList)
{
    uint32_t i = 0;
    if (linkList == NULL || linkList->linkTypeNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "PreferredLinkList not set, prop = %d.", prop);
        goto DEFAULT;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "PreferredLinkList num = %d.", linkList->linkTypeNum);
    if (linkList->linkTypeNum > (sizeof(linkList->linkType) / sizeof(LinkType))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "too many link type, num = %d.", linkList->linkTypeNum);
        goto DEFAULT;
    }
    for (; i < linkList->linkTypeNum; i++) {
        if (linkList->linkType[i] < LINK_TYPE_WIFI_WLAN_5G || linkList->linkType[i] > LINK_TYPE_MAX) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invaild link type: %d", linkList->linkType[i]);
            goto DEFAULT;
        }
        laneEntryList->getLaneByType[i] = g_linkLaneTable[linkList->linkType[i]];
    }
    if (i > 0) {
        laneEntryList->preferredLinkNum = i;
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "select lane with PreferredLinkList.");
        return;
    }

DEFAULT:
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "select lane by SmartCommunication.");
    *laneEntryList = g_smartLaneMap[prop];
}

int32_t LnnGetRightLane(const char *netWorkId, int32_t pid, LnnLaneProperty prop,
    const LnnPreferredLinkList *linkList)
{
    if (prop < LNN_MESSAGE_LANE || prop >= LNN_LANE_PROPERTY_BUTT || netWorkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "param error. prop = %d", prop);
        return SOFTBUS_ERR;
    }
    int32_t lane = SOFTBUS_ERR;
    SmartLaneMapEntry laneEntryList = {0};
    GetLaneEntryList(linkList, prop, &laneEntryList);
    for (uint8_t i = 0; i < laneEntryList.preferredLinkNum; i++) {
        lane = laneEntryList.getLaneByType[i](netWorkId, pid, prop);
        if (lane >= 0 && LnnGetLaneScore(lane) >= THRESHOLD_LANE_QUALITY_SCORE) {
            LnnSetLaneSupportUdp(netWorkId, lane, IsSupportUdp(prop));
            LnnLaneSetNetworkIdAndPid(lane, netWorkId, pid);
            return lane;
        }
    }
    return lane;
}

static bool IsProxyPort(LnnLaneProperty prop, LnnLaneLinkType type)
{
    if (prop == LNN_MESSAGE_LANE) {
        return true;
    }
    if (type == LNN_LINK_TYPE_BR && prop == LNN_FILE_LANE) {
        return true;
    }
    return false;
}

static bool GetNumInfo(const char *netWorkId, int32_t *local, int32_t *remote)
{
    int32_t ret;
    ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, local);
    if (ret < 0 || *local < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetLocalNumInfo err. ret = %d, local = %d", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_NET_CAP, remote);
    if (ret < 0 || *remote < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemoteNumInfo err. ret = %d, remote = %d", ret, *remote);
        return false;
    }
    return true;
}

static int32_t GetLaneOf5GWlan(const char* netWorkId, int32_t pid, LnnLaneProperty prop)
{
    int32_t local, remote;

    (void)pid;
    if (!GetNumInfo(netWorkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNumInfo error.");
        return SOFTBUS_ERR;
    }

    if (((local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH))) &&
        ((remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)))) {
        if (LnnUpdateLaneRemoteInfo(netWorkId, LNN_LINK_TYPE_WLAN_5G, IsProxyPort(prop, LNN_LINK_TYPE_WLAN_5G))) {
            return LNN_LINK_TYPE_WLAN_5G; // the LNN_LINK_TYPE_WLAN_5G is laneID.
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Can't support WIFI WLAN 5G.");
    return SOFTBUS_ERR;
}

static int32_t GetLaneOf2P4GWlan(const char* netWorkId, int32_t pid, LnnLaneProperty prop)
{
    int32_t local, remote;

    (void)pid;
    if (!GetNumInfo(netWorkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLaneOf2P4GWlan error.");
        return SOFTBUS_ERR;
    }

    if (((local & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH))) &&
        ((remote & (1 << BIT_WIFI_24G)) || (remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)))) {
        if (LnnUpdateLaneRemoteInfo(netWorkId, LNN_LINK_TYPE_WLAN_2P4G, IsProxyPort(prop, LNN_LINK_TYPE_WLAN_2P4G))) {
            return LNN_LINK_TYPE_WLAN_2P4G;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Can't support WIFI WLAN 2P4G.");
    return SOFTBUS_ERR;
}

static int32_t GetLaneOfBR(const char *netWorkId, int32_t pid, LnnLaneProperty prop)
{
    int32_t local, remote;

    (void)pid;
    if (!GetNumInfo(netWorkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLaneOfBR error.");
        return SOFTBUS_ERR;
    }

    if ((local & (1 << BIT_BR)) && (remote & (1 << BIT_BR))) {
        if (LnnUpdateLaneRemoteInfo(netWorkId, LNN_LINK_TYPE_BR, IsProxyPort(prop, LNN_LINK_TYPE_BR))) {
            return LNN_LINK_TYPE_BR;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Can't support BR.");
    return SOFTBUS_ERR;
}

static int32_t GetLaneOfP2p(const char *netWorkId, int32_t pid, LnnLaneProperty prop)
{
    int32_t laneId;
    int32_t local, remote;
    LnnLaneP2pInfo p2pInfo;
    (void)memset_s(&p2pInfo, sizeof(p2pInfo), 0, sizeof(p2pInfo));

    (void)prop;
    if (!GetNumInfo(netWorkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNumInfo error.");
        return SOFTBUS_ERR;
    }
    if (((local & (1 << BIT_WIFI_P2P)) == 0) || ((remote & (1 << BIT_WIFI_P2P)) == 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Can't support WIFI P2P.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Both support WIFI P2P.");
    if (LnnConnectP2p(netWorkId, pid, &p2pInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connect p2p fail.");
        return SOFTBUS_ERR;
    }
    laneId = LnnUpdateLaneP2pInfo(&p2pInfo);
    if (laneId < LNN_LINK_TYPE_P2P || laneId > LNN_LINK_TYPE_P2P_MAX) {
        (void)LnnDisconnectP2p(netWorkId, pid, NULL);
        return SOFTBUS_ERR;
    }
    return laneId;
}
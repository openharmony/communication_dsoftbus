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
#include "lnn_lane_info.h"
#include "lnn_net_capability.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static int32_t GetLaneOf5GWlan(const char *netWorkId, LnnLaneProperty prop);
static int32_t GetLaneOf2P4GWlan(const char *netWorkId, LnnLaneProperty prop);
static int32_t GetLaneOfBR(const char *netWorkId, LnnLaneProperty prop);
typedef int32_t (*GetLaneByType)(const char *netWorkId, LnnLaneProperty prop);

typedef struct {
    uint8_t preferredLinkNum;
    GetLaneByType getLaneByType[LNN_LINK_TYPE_BUTT];
} SmartLaneMapEntry;

SmartLaneMapEntry g_smartLaneMap[LNN_LANE_PROPERTY_BUTT] = {
    [LNN_MESSAGE_LANE] = {3, {GetLaneOf5GWlan, GetLaneOf2P4GWlan, GetLaneOfBR}}, // the preferredLinkNum is 3
    [LNN_BYTES_LANE] = {3, {GetLaneOf5GWlan, GetLaneOf2P4GWlan, GetLaneOfBR}}, // the preferredLinkNum is 3
    [LNN_FILE_LANE] = {3, {GetLaneOf5GWlan, GetLaneOf2P4GWlan, GetLaneOfBR}}, // the preferredLinkNum is 3
    [LNN_STREAM_LANE] = {2, {GetLaneOf5GWlan, GetLaneOf2P4GWlan}}, // the preferredLinkNum is 2
};

int32_t LnnGetRightLane(const char *netWorkId, LnnLaneProperty prop)
{
    if (prop < LNN_MESSAGE_LANE || prop >= LNN_LANE_PROPERTY_BUTT || netWorkId == NULL) {
        LOG_ERR("param error. prop = %d", prop);
        return SOFTBUS_ERR;
    }
    int32_t lane = SOFTBUS_ERR;
    for (uint8_t i = 0; i < g_smartLaneMap[prop].preferredLinkNum; i++) {
        lane = g_smartLaneMap[prop].getLaneByType[i](netWorkId, prop);
        if (lane >= 0) {
            return lane;
        }
    }
    return lane;
}

static bool IsProxyPort(LnnLaneProperty prop, LnnLaneLinkType type)
{
    if (prop == LNN_MESSAGE_LANE &&
        (type == LNN_LINK_TYPE_WLAN_5G || type == LNN_LINK_TYPE_WLAN_2P4G || type == LNN_LINK_TYPE_BR)) {
        return true;
    }
    return false;
}

static bool GetNumInfo(const char *netWorkId, int32_t *local, int32_t *remote)
{
    int32_t ret;
    ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, local);
    if (ret < 0 || *local < 0) {
        LOG_ERR("LnnGetLocalNumInfo error. ret = %d, local = %d", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_NET_CAP, remote);
    if (ret < 0 || *remote < 0) {
        LOG_ERR("LnnGetRemoteNumInfo error. ret = %d, remote = %d", ret, *remote);
        return false;
    }
    return true;
}

static int32_t GetLaneOf5GWlan(const char* netWorkId, LnnLaneProperty prop)
{
    int32_t local, remote;
    if (!GetNumInfo(netWorkId, &local, &remote)) {
        LOG_ERR("GetNumInfo error.");
        return SOFTBUS_ERR;
    }

    if (((local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH))) &&
        ((remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)))) {
        if (LnnUpdateLaneRemoteInfo(netWorkId, LNN_LINK_TYPE_WLAN_5G, IsProxyPort(prop, LNN_LINK_TYPE_WLAN_5G))) {
            return LNN_LINK_TYPE_WLAN_5G; // the LNN_LINK_TYPE_WLAN_5G is laneID.
        }
    }
    LOG_INFO("Can't support WIFI WLAN 5G.");
    return SOFTBUS_ERR;
}

static int32_t GetLaneOf2P4GWlan(const char* netWorkId, LnnLaneProperty prop)
{
    int32_t local, remote;
    if (!GetNumInfo(netWorkId, &local, &remote)) {
        LOG_ERR("GetLaneOf2P4GWlan error.");
        return SOFTBUS_ERR;
    }

    if (((local & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH))) &&
        ((remote & (1 << BIT_WIFI_24G)) || (remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)))) {
        if (LnnUpdateLaneRemoteInfo(netWorkId, LNN_LINK_TYPE_WLAN_2P4G, IsProxyPort(prop, LNN_LINK_TYPE_WLAN_2P4G))) {
            return LNN_LINK_TYPE_WLAN_2P4G;
        }
    }
    LOG_INFO("Can't support WIFI WLAN 2P4G.");
    return SOFTBUS_ERR;
}

static int32_t GetLaneOfBR(const char *netWorkId, LnnLaneProperty prop)
{
    int32_t local, remote;

    if (!GetNumInfo(netWorkId, &local, &remote)) {
        LOG_ERR("GetLaneOfBR error.");
        return SOFTBUS_ERR;
    }

    if ((local & (1 << BIT_BR)) &&  (remote & (1 << BIT_BR))) {
        if (LnnUpdateLaneRemoteInfo(netWorkId, LNN_LINK_TYPE_BR, IsProxyPort(prop, LNN_LINK_TYPE_BR))) {
            return LNN_LINK_TYPE_BR;
        }
    }
    LOG_INFO("Can't support BR.");
    return SOFTBUS_ERR;
}

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

#include "lnn_lane_info.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "softbus_log.h"

typedef struct {
    LnnLaneInfo laneInfo;
    int32_t laneId;
    bool isUse;
    pthread_mutex_t lock;
} LaneInfoImpl;

static LaneInfoImpl g_lanes[LNN_LINK_TYPE_BUTT];
void LnnLanesInit(void)
{
    uint32_t firstLaneId = LNN_LINK_TYPE_WLAN_5G;
    for (uint32_t i = firstLaneId; i < LNN_LINK_TYPE_BUTT; i++) {
        g_lanes[i].laneId = firstLaneId++;
        (void)pthread_mutex_init(&g_lanes[i].lock, NULL);
    }
}

static bool IsValidLaneId(int32_t laneId)
{
    if (laneId < LNN_LINK_TYPE_WLAN_5G || laneId >= LNN_LINK_TYPE_BUTT) {
        LOG_ERR("param error. laneId = %d", laneId);
        return false;
    }
    if (pthread_mutex_lock(&g_lanes[laneId].lock) != 0) {
        LOG_ERR("lock failed");
        return false;
    }
    if (!g_lanes[laneId].isUse) {
        LOG_ERR("The laneId cannot be used. laneId: %d.", laneId);
        (void)pthread_mutex_unlock(&g_lanes[laneId].lock);
        return false;
    }
    (void)pthread_mutex_unlock(&g_lanes[laneId].lock);
    return true;
}

void LnnReleaseLane(int32_t laneId)
{
    if (laneId < LNN_LINK_TYPE_WLAN_5G || laneId >= LNN_LINK_TYPE_BUTT) {
        return;
    }
    if (pthread_mutex_lock(&g_lanes[laneId].lock) != 0) {
        LOG_ERR("lock failed");
        return;
    }
    g_lanes[laneId].isUse = false;
    (void)pthread_mutex_unlock(&g_lanes[laneId].lock);
}

ConnectionAddrType LnnGetLaneType(int32_t laneId)
{
    if (!IsValidLaneId(laneId)) {
        return CONNECTION_ADDR_MAX;
    }
    if (laneId == LNN_LINK_TYPE_WLAN_5G || laneId == LNN_LINK_TYPE_WLAN_2P4G) {
        return CONNECTION_ADDR_WLAN;
    }
    return laneId;
}

const LnnLaneInfo *LnnGetConnection(int32_t laneId)
{
    if (!IsValidLaneId(laneId)) {
        return NULL;
    }
    return &g_lanes[laneId].laneInfo;
}

static bool SetPeerIPInfo(const char *netWorkId, LnnLaneLinkType type, bool mode)
{
    int32_t ret;
    int32_t port;
    ret = LnnGetRemoteStrInfo(netWorkId, STRING_KEY_WLAN_IP,
        g_lanes[type].laneInfo.conOption.info.ip.ip, IP_STR_MAX_LEN);
    if (ret < 0 || strncmp(g_lanes[type].laneInfo.conOption.info.ip.ip, "127.0.0.1", strlen("127.0.0.1")) == 0) {
        LOG_ERR("LnnGetRemoteStrInfo error.");
        return false;
    }
    if (mode) {
        ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_PROXY_PORT, &port);
    } else {
        ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_AUTH_PORT, &port);
    }
    if (ret < 0) {
        LOG_ERR("LnnGetRemoteNumInfo error.");
        return false;
    }
    g_lanes[type].laneInfo.conOption.type = CONNECTION_ADDR_WLAN;
    g_lanes[type].laneInfo.conOption.info.ip.port = (uint16_t)port;
    g_lanes[type].laneInfo.isProxy = mode;
    return true;
}

static bool SetPeerMacInfo(const char *netWorkId, LnnLaneLinkType type, bool mode)
{
    int32_t ret;
    ret = LnnGetRemoteStrInfo(netWorkId, STRING_KEY_BT_MAC, g_lanes[type].laneInfo.conOption.info.br.brMac, BT_MAC_LEN);
    if (ret < 0) {
        LOG_ERR("LnnGetRemoteStrInfo error.");
        return false;
    }
    if (type == LNN_LINK_TYPE_BR) {
        g_lanes[type].laneInfo.conOption.type = CONNECTION_ADDR_BR;
        g_lanes[type].laneInfo.isProxy = mode;
    }
    return true;
}

bool LnnUpdateLaneRemoteInfo(const char *netWorkId, LnnLaneLinkType type, bool mode)
{
    if (netWorkId == NULL || type >= LNN_LINK_TYPE_BUTT || type < LNN_LINK_TYPE_WLAN_5G) {
        LOG_ERR("param error. type = %d", type);
        return false;
    }
    if (!g_lanes[type].isUse) {
        if (pthread_mutex_lock(&g_lanes[type].lock) != 0) {
            LOG_ERR("lock failed");
            return false;
        }
        if (g_lanes[type].isUse) {
            (void)pthread_mutex_unlock(&g_lanes[type].lock);
            return true;
        }
    }

    bool ret = false;
    switch (type) {
        case LNN_LINK_TYPE_WLAN_5G:
        case LNN_LINK_TYPE_WLAN_2P4G: // the WLAN_5G and the WLAN_2P4G is same process.
            ret = SetPeerIPInfo(netWorkId, type, mode);
            break;
        case LNN_LINK_TYPE_BR:
            ret = SetPeerMacInfo(netWorkId, type, true);
            break;
        default:
            break;
    }
    g_lanes[type].isUse = true;
    (void)pthread_mutex_unlock(&g_lanes[type].lock);
    return ret;
}

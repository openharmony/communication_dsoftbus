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

#include <securec.h>
#include <stdlib.h>
#include <string.h>

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_link.h"
#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"

typedef struct {
    LnnLaneInfo laneInfo;
    int32_t laneId;
    bool isUse;
    SoftBusMutex lock;
    int32_t score;
    int32_t pid;
    char networkId[NETWORK_ID_BUF_LEN];
} LaneInfoImpl;

static LaneInfoImpl g_lanes[LNN_LINK_TYPE_BUTT];
static LnnLaneMonitorCallback g_callback;

int32_t LnnGetLaneScore(int32_t laneId)
{
    int32_t count = LnnGetLaneCount(laneId);
    if (count == SOFTBUS_ERR) {
        LNN_LOGE(LNN_LANE, "LnnGetLaneCount failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&g_lanes[laneId].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock failed");
        return SOFTBUS_ERR;
    }
    if (count >= LANE_COUNT_THRESHOLD) {
        g_lanes[laneId].score = THRESHOLD_LANE_QUALITY_SCORE;
    } else {
        g_lanes[laneId].score = PASSING_LANE_QUALITY_SCORE;
    }
    (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
    return g_lanes[laneId].score;
}

void TriggerLaneMonitor(void)
{
    for (int32_t laneId = 0; laneId < LNN_LINK_TYPE_BUTT; laneId++) {
        int32_t score = LnnGetLaneScore(laneId);
        if (score < PASSING_LANE_QUALITY_SCORE && g_callback != NULL) {
            g_callback(laneId, score);
        }
    }
}

int32_t LnnLanesInit(void)
{
    uint32_t firstLaneId = LNN_LINK_TYPE_WLAN_5G;
    for (uint32_t i = firstLaneId; i < LNN_LINK_TYPE_BUTT; i++) {
        g_lanes[i].laneId = firstLaneId++;
        (void)SoftBusMutexInit(&g_lanes[i].lock, NULL);
        g_lanes[i].score = MAX_LANE_QUALITY_SCORE;
    }
    g_callback = NULL;
    return SOFTBUS_OK;
}

int32_t LnnRegisterLaneMonitor(LnnLaneMonitorCallback callback)
{
    if (callback == NULL) {
        LNN_LOGE(LNN_LANE, "param error");
        return SOFTBUS_ERR;
    }
    g_callback = callback;
    return SOFTBUS_OK;
}

static bool IsValidLaneId(int32_t laneId)
{
    if (laneId < LNN_LINK_TYPE_WLAN_5G || laneId >= LNN_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "param error. laneId=%{public}d", laneId);
        return false;
    }
    if (SoftBusMutexLock(&g_lanes[laneId].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock failed");
        return false;
    }
    if (!g_lanes[laneId].isUse) {
        LNN_LOGE(LNN_LANE, "The laneId cannot be used. laneId=%{public}d.", laneId);
        (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
        return false;
    }
    (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
    return true;
}

void LnnReleaseLane(int32_t laneId)
{
    if (laneId < LNN_LINK_TYPE_WLAN_5G || laneId >= LNN_LINK_TYPE_BUTT) {
        return;
    }

    if (SoftBusMutexLock(&g_lanes[laneId].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock failed");
        return;
    }
    if (laneId >= LNN_LINK_TYPE_P2P && laneId <= LNN_LINK_TYPE_P2P_MAX) {
        (void)LnnDisconnectP2p(g_lanes[laneId].networkId, g_lanes[laneId].pid, NULL);
    }
    int32_t count = LnnGetLaneCount(laneId);
    if (count != 0) {
        LNN_LOGI(LNN_LANE, "lane already used, count=%{public}d.", count);
        (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
        return;
    }
    if (g_lanes[laneId].laneInfo.p2pInfo != NULL) {
        SoftBusFree(g_lanes[laneId].laneInfo.p2pInfo);
        g_lanes[laneId].laneInfo.p2pInfo = NULL;
    }
    g_lanes[laneId].isUse = false;
    (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
}

ConnectionAddrType LnnGetLaneType(int32_t laneId)
{
    if (!IsValidLaneId(laneId)) {
        return CONNECTION_ADDR_MAX;
    }
    if (laneId == LNN_LINK_TYPE_WLAN_5G || laneId == LNN_LINK_TYPE_WLAN_2P4G) {
        return CONNECTION_ADDR_WLAN;
    }
    return (ConnectionAddrType)laneId;
}

const LnnLaneInfo *LnnGetLaneInfo(int32_t laneId)
{
    if (!IsValidLaneId(laneId)) {
        return NULL;
    }
    return &g_lanes[laneId].laneInfo;
}

static bool SetPeerIPInfo(const char *netWorkId, LnnLaneLinkType type, bool mode)
{
    int32_t ret;
    int32_t port = 0;
    ret = LnnGetRemoteStrInfo(netWorkId, STRING_KEY_WLAN_IP,
        g_lanes[type].laneInfo.conOption.info.ip.ip, IP_STR_MAX_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteStrInfo error, ret=%{public}d", ret);
        return false;
    }
    if (strnlen(g_lanes[type].laneInfo.conOption.info.ip.ip, IP_STR_MAX_LEN) == 0 ||
        strncmp(g_lanes[type].laneInfo.conOption.info.ip.ip, "127.0.0.1", strlen("127.0.0.1")) == 0) {
        LNN_LOGE(LNN_LANE, "Wlan ip not found");
        return false;
    }
    if (mode) {
        ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_PROXY_PORT, &port);
    } else {
        ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_SESSION_PORT, &port);
    }
    if (ret < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo error");
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
        LNN_LOGE(LNN_LANE, "LnnGetRemoteStrInfo error");
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
        LNN_LOGE(LNN_LANE, "param error.type=%{public}d", type);
        return false;
    }
    if (SoftBusMutexLock(&g_lanes[type].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock failed");
        return false;
    }
    if (g_lanes[type].isUse && type >= LNN_LINK_TYPE_P2P && type <= LNN_LINK_TYPE_P2P_MAX) {
        (void)SoftBusMutexUnlock(&g_lanes[type].lock);
        LNN_LOGI(LNN_LANE, "reuse lane, type=%{public}d", type);
        return true;
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
    (void)SoftBusMutexUnlock(&g_lanes[type].lock);
    return ret;
}

void LnnSetLaneSupportUdp(const char *netWorkId, int32_t laneId, bool isSupport)
{
    int32_t ret;
    int32_t port;
    if (networkId == NULL || laneId >= LNN_LINK_TYPE_BUTT || laneId < LNN_LINK_TYPE_WLAN_5G) {
        LNN_LOGE(LNN_LANE, "param error.laneId=%{public}d", laneId);
        return;
    }
    if (SoftBusMutexLock(&g_lanes[laneId].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock failed");
        return;
    }
    if (laneId == LNN_LINK_TYPE_BR) {
        g_lanes[laneId].laneInfo.isSupportUdp = false;
        (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
        return;
    }
    if (isSupport) {
        ret = LnnGetRemoteNumInfo(netWorkId, NUM_KEY_AUTH_PORT, &port);
        if (ret < 0) {
            LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo error, ret=%{public}d", ret);
            (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
            return;
        }
        g_lanes[laneId].laneInfo.conOption.info.ip.port = (uint16_t)port;
    }
    g_lanes[laneId].laneInfo.isSupportUdp = isSupport;
    (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
}

void LnnLaneSetNetworkIdAndPid(int32_t laneId, const char *networkId, int32_t pid)
{
    if (networkId == NULL || laneId >= LNN_LINK_TYPE_BUTT || laneId < LNN_LINK_TYPE_WLAN_5G) {
        LNN_LOGE(LNN_LANE, "param error, laneId=%{public}d", laneId);
        return;
    }
    if (SoftBusMutexLock(&g_lanes[laneId].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock failed");
        return;
    }
    g_lanes[laneId].pid = pid;
    if (strcpy_s(g_lanes[laneId].networkId, sizeof(g_lanes[laneId].networkId), networkId) != EOK) {
        LNN_LOGE(LNN_LANE, "set networkId failed");
    }
    (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
}

int32_t LnnUpdateLaneP2pInfo(const LnnLaneP2pInfo *info)
{
    int32_t i;
    int32_t laneId = LNN_LINK_TYPE_BUTT;
    LnnLaneP2pInfo *p2pInfo = NULL;
    if (info == NULL) {
        return LNN_LINK_TYPE_BUTT;
    }
    for (i = LNN_LINK_TYPE_P2P; i <= LNN_LINK_TYPE_P2P_MAX; i++) {
        if (SoftBusMutexLock(&g_lanes[i].lock) != 0) {
            LNN_LOGE(LNN_LANE, "lock fail");
            return LNN_LINK_TYPE_BUTT;
        }
        if (g_lanes[i].laneInfo.p2pInfo == NULL) {
            laneId = i;
        } else if (memcmp(g_lanes[i].laneInfo.p2pInfo, info, sizeof(LnnLaneP2pInfo)) == 0) {
            (void)SoftBusMutexUnlock(&g_lanes[i].lock);
            LNN_LOGI(LNN_LANE, "reuse p2p lane, id=%{public}d", i);
            return i;
        }
        (void)SoftBusMutexUnlock(&g_lanes[i].lock);
    }
    if (laneId == LNN_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "no free p2p lane");
        return LNN_LINK_TYPE_BUTT;
    }

    p2pInfo = (LnnLaneP2pInfo *)SoftBusCalloc(sizeof(LnnLaneP2pInfo));
    if (p2pInfo == NULL) {
        return LNN_LINK_TYPE_BUTT;
    }
    if (memcpy_s(p2pInfo, sizeof(LnnLaneP2pInfo), info, sizeof(LnnLaneP2pInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "copy p2p ip fail");
        SoftBusFree(p2pInfo);
        return LNN_LINK_TYPE_BUTT;
    }
    if (SoftBusMutexLock(&g_lanes[laneId].lock) != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        SoftBusFree(p2pInfo);
        return LNN_LINK_TYPE_BUTT;
    }
    g_lanes[laneId].laneInfo.p2pInfo = p2pInfo;
    g_lanes[laneId].laneInfo.isProxy = false;
    g_lanes[laneId].isUse = true;
    (void)SoftBusMutexUnlock(&g_lanes[laneId].lock);
    LNN_LOGI(LNN_LANE, "get p2p lane ok, laneId=%{public}d", laneId);
    return laneId;
}
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_lane_common.h"

#include <securec.h>

#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "message_handler.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define UINT_TO_STR_MAX_LEN 11

typedef int32_t (*LinkInfoProc)(const LaneLinkInfo *, LaneConnInfo *, LaneProfile *);

static int32_t BrInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_BR;
    if (memcpy_s(connInfo->connInfo.br.brMac, BT_MAC_LEN,
        linkInfo->linkInfo.br.brMac, BT_MAC_LEN) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    profile->linkType = LANE_BR;
    return SOFTBUS_OK;
}

static int32_t BleInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_BLE;
    if (memcpy_s(connInfo->connInfo.ble.bleMac, BT_MAC_LEN,
        linkInfo->linkInfo.ble.bleMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy btMac fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(connInfo->connInfo.ble.deviceIdHash, UDID_HASH_LEN,
        linkInfo->linkInfo.ble.deviceIdHash, UDID_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy udidHash fail");
        return SOFTBUS_MEM_ERR;
    }
    connInfo->connInfo.ble.protoType = linkInfo->linkInfo.ble.protoType;
    connInfo->connInfo.ble.psm = linkInfo->linkInfo.ble.psm;
    profile->linkType = LANE_BLE;
    return SOFTBUS_OK;
}

static int32_t P2pInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_P2P;
    if (memcpy_s(&connInfo->connInfo.p2p, sizeof(P2pConnInfo),
        &linkInfo->linkInfo.p2p.connInfo, sizeof(P2pConnInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy P2pConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    profile->linkType = LANE_P2P;
    profile->bw = linkInfo->linkInfo.p2p.bw;
    profile->phyChannel = linkInfo->linkInfo.p2p.channel;
    return SOFTBUS_OK;
}

static int32_t HmlInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_HML;
    if (memcpy_s(&connInfo->connInfo.p2p, sizeof(P2pConnInfo),
        &linkInfo->linkInfo.p2p.connInfo, sizeof(P2pConnInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy P2pConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    profile->linkType = LANE_HML;
    profile->bw = linkInfo->linkInfo.p2p.bw;
    profile->phyChannel = linkInfo->linkInfo.p2p.channel;
    return SOFTBUS_OK;
}

static int32_t HmlRawInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_HML_RAW;
    if (memcpy_s(&connInfo->connInfo.rawWifiDirect, sizeof(RawWifiDirectConnInfo),
        &linkInfo->linkInfo.rawWifiDirect, sizeof(RawWifiDirectConnInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t P2pReuseInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_P2P_REUSE;
    connInfo->connInfo.wlan = linkInfo->linkInfo.wlan.connInfo;
    profile->linkType = LANE_P2P_REUSE;
    return SOFTBUS_OK;
}

static int32_t Wlan2P4GInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_WLAN_2P4G;
    if (memcpy_s(&connInfo->connInfo.wlan, sizeof(WlanConnInfo),
        &linkInfo->linkInfo.wlan.connInfo, sizeof(WlanConnInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy WlanConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    profile->linkType = LANE_WLAN_2P4G;
    profile->bw = linkInfo->linkInfo.wlan.bw;
    profile->phyChannel = linkInfo->linkInfo.wlan.channel;
    return SOFTBUS_OK;
}

static int32_t Wlan5GInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_WLAN_5G;
    if (memcpy_s(&connInfo->connInfo.wlan, sizeof(WlanConnInfo),
        &linkInfo->linkInfo.wlan.connInfo, sizeof(WlanConnInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy WlanConnInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    profile->linkType = LANE_WLAN_5G;
    profile->bw = linkInfo->linkInfo.wlan.bw;
    profile->phyChannel = linkInfo->linkInfo.wlan.channel;
    return SOFTBUS_OK;
}

static int32_t BleDirectInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    if (strcpy_s(connInfo->connInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN,
        linkInfo->linkInfo.bleDirect.networkId) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy networkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    connInfo->type = LANE_BLE_DIRECT;
    connInfo->connInfo.bleDirect.protoType = linkInfo->linkInfo.bleDirect.protoType;
    profile->linkType = LANE_BLE_DIRECT;
    return SOFTBUS_OK;
}

static int32_t CocInfoProc(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    connInfo->type = LANE_COC;
    if (memcpy_s(connInfo->connInfo.ble.bleMac, BT_MAC_LEN,
        linkInfo->linkInfo.ble.bleMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy bleMac fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(connInfo->connInfo.ble.deviceIdHash, UDID_HASH_LEN,
        linkInfo->linkInfo.ble.deviceIdHash, UDID_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy deviceIdHash fail");
        return SOFTBUS_MEM_ERR;
    }
    connInfo->connInfo.ble.psm = linkInfo->linkInfo.ble.psm;
    profile->linkType = LANE_COC;
    return SOFTBUS_OK;
}

static LinkInfoProc g_funcList[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = BrInfoProc,
    [LANE_BLE] = BleInfoProc,
    [LANE_P2P] = P2pInfoProc,
    [LANE_HML] = HmlInfoProc,
    [LANE_WLAN_2P4G] = Wlan2P4GInfoProc,
    [LANE_WLAN_5G] = Wlan5GInfoProc,
    [LANE_P2P_REUSE] = P2pReuseInfoProc,
    [LANE_BLE_DIRECT] = BleDirectInfoProc,
    [LANE_COC] = CocInfoProc,
    // CoC reuse gatt direct
    [LANE_COC_DIRECT] = BleDirectInfoProc,
    [LANE_HML_RAW] = HmlRawInfoProc,
};

int32_t LaneInfoProcess(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    if ((linkInfo == NULL) || (connInfo == NULL) || (profile == NULL)) {
        LNN_LOGE(LNN_LANE, "laneInfoProcess param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((linkInfo->type >= LANE_LINK_TYPE_BUTT) || (g_funcList[linkInfo->type] == NULL)) {
        LNN_LOGE(LNN_LANE, "unsupport linkType=%{public}d", linkInfo->type);
        return SOFTBUS_INVALID_PARAM;
    }
    return g_funcList[linkInfo->type](linkInfo, connInfo, profile);
}

int32_t LnnCreateData(Map *map, uint32_t key, const void *value, uint32_t valueSize)
{
    char keyStr[UINT_TO_STR_MAX_LEN] = {0};
    if (sprintf_s(keyStr, UINT_TO_STR_MAX_LEN, "%u", key) < 0) {
        LNN_LOGE(LNN_LANE, "convert dataType fail");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LnnMapSet(map, (const char *)keyStr, value, valueSize);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "save data fail");
        return ret;
    }
    return SOFTBUS_OK;
}

void *LnnReadData(const Map *map, uint32_t key)
{
    char keyStr[UINT_TO_STR_MAX_LEN] = {0};
    if (sprintf_s(keyStr, UINT_TO_STR_MAX_LEN, "%u", key) < 0) {
        LNN_LOGE(LNN_LANE, "convert dataType fail");
        return NULL;
    }
    void *data = LnnMapGet(map, (const char *)keyStr);
    return data;
}

void LnnDeleteData(Map *map, uint32_t key)
{
    char keyStr[UINT_TO_STR_MAX_LEN] = {0};
    if (sprintf_s(keyStr, UINT_TO_STR_MAX_LEN, "%u", key) < 0) {
        LNN_LOGE(LNN_LANE, "convert dataType fail");
        return;
    }
    if (LnnMapErase(map, (const char *)keyStr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "delete data fail");
        return;
    }
}

uint64_t LnnGetSysTimeMs(void)
{
    return SoftBusGetSysTimeMs();
}

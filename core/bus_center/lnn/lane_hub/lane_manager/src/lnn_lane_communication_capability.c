/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_communication_capability.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_log.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

static int32_t StaticNetCapaCalc(const char *networkId, uint32_t netCapaIndex, bool *isAvailable)
{
    uint64_t localStaticCapa = 0;
    uint64_t remoteStaticCapa = 0;
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_NET_STATIC_CAP, &localStaticCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local info fail, key:NET_STATIC_CAP");
        return ret;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_NET_STATIC_CAP, &remoteStaticCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote info fail, key:NET_STATIC_CAP");
        return ret;
    }
    *isAvailable = ((localStaticCapa & remoteStaticCapa & (1 << netCapaIndex)) != 0);
    return SOFTBUS_OK;
}

static int32_t DynamicNetCapaCalc(const char *networkId, uint32_t netCapaIndex, bool *isAvailable)
{
    uint64_t localNetCapa = 0;
    uint64_t remoteNetCapa = 0;
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_NET_CAP, &localNetCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local info fail, key:NET_CAP");
        return ret;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_NET_CAP, &remoteNetCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote info fail, key:NET_CAP");
        return ret;
    }
    *isAvailable = ((localNetCapa & remoteNetCapa & (1 << netCapaIndex)) != 0);
    return SOFTBUS_OK;
}

static bool GetSupportFeature(const char *networkId, uint64_t *local, uint64_t *remote)
{
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, local);
    if (ret != SOFTBUS_OK || *local < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}" PRIu64, ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK || *remote < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}" PRIu64, ret, *remote);
        return false;
    }
    return true;
}

static bool IsTargetFeatureSupport(const char *networkId, FeatureCapability feature)
{
    uint64_t local = 0;
    uint64_t remote = 0;
    if (!GetSupportFeature(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "get support Feature error");
        return false;
    }
    if (((local & (1 << feature)) == 0) || ((remote & (1 << feature)) == 0)) {
        LNN_LOGE(LNN_LANE, "coc capa disable, local=%{public}" PRIu64 ", remote=%{public}" PRIu64,
            local, remote);
        return false;
    }
    return true;
}

static bool BrStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_BR, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "br static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool BrDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_BR, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "br dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool IsDeviceOnlineByTargetType(const char *networkId, DiscoveryType onlineType)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "getRemoteInfo fail, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    return LnnHasDiscoveryType(&node, onlineType);
}

static bool BleStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_BLE, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool BleDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_BLE, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable && IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_BLE);
}

static bool P2pStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_WIFI_P2P, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "p2p static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool P2pDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_P2P, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "p2p dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool WiFiDirectStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_WIFI_DIRECT, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool WiFiDirectDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_DIRECT, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool WlanStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_WIFI, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wlan static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool WlanDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_5G, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wlan dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable && IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_WIFI);
}

static bool EthStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_ETH, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "eth static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool EthDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_ETH, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "eth dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static bool CocStaticCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = StaticNetCapaCalc(networkId, BIT_BLE, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "coc static capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable && IsTargetFeatureSupport(networkId, BIT_COC_CONNECT_CAPABILITY);
}

static bool CocDynamicCommCapa(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, false, LNN_LANE, "networkId is nullptr");
    bool isAvailable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_BLE, &isAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "coc dynamic capa calc err:%{public}d", ret);
        return false;
    }
    return isAvailable;
}

static const LaneCommCapa g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = {BrStaticCommCapa, BrDynamicCommCapa},
    [LANE_BLE] = {BleStaticCommCapa, BleDynamicCommCapa},
    [LANE_P2P] = {P2pStaticCommCapa, P2pDynamicCommCapa},
    [LANE_HML] = {WiFiDirectStaticCommCapa, WiFiDirectDynamicCommCapa},
    [LANE_WLAN_2P4G] = {WlanStaticCommCapa, WlanDynamicCommCapa},
    [LANE_WLAN_5G] = {WlanStaticCommCapa, WlanDynamicCommCapa},
    [LANE_ETH] = {EthStaticCommCapa, EthDynamicCommCapa},
    [LANE_P2P_REUSE] = {P2pStaticCommCapa, P2pDynamicCommCapa},
    [LANE_BLE_DIRECT] = {BleStaticCommCapa, BleDynamicCommCapa},
    [LANE_BLE_REUSE] = {BleStaticCommCapa, BleDynamicCommCapa},
    [LANE_COC] = {CocStaticCommCapa, CocDynamicCommCapa},
    [LANE_COC_DIRECT] = {CocStaticCommCapa, CocDynamicCommCapa},
};

LaneCommCapa *GetLinkCapaByLinkType(LaneLinkType linkType)
{
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
        return NULL;
    }
    if (g_linkTable[linkType].getStaticCommCapa == NULL || g_linkTable[linkType].getDynamicCommCapa == NULL) {
        LNN_LOGE(LNN_LANE, "linkCapa is not support, linkType=%{public}d", linkType);
        return NULL;
    }
    return &g_linkTable[linkType];
}
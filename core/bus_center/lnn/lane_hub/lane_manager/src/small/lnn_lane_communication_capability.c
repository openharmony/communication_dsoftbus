/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "lnn_local_net_ledger_struct.h"
#include "lnn_log.h"
#include "softbus_wifi_api_adapter.h"

typedef struct {
    int32_t (*getStaticCommCapa)(const char *networkId);
    int32_t (*getDynamicCommCapa)(const char *networkId);
    NetCapability netCapaIndex;
} LaneCommCapa;

static int32_t StaticNetCapaCalc(const char *networkId, uint32_t netCapaIndex, bool *localEnable, bool *remoteEnable)
{
    if (localEnable == NULL || remoteEnable == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t localStaticCapa = 0;
    uint32_t remoteStaticCapa = 0;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_STATIC_NET_CAP, &localStaticCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local info fail, key:NET_STATIC_CAP");
        return ret;
    }
    ret = LnnGetRemoteNumU32Info(networkId, NUM_KEY_STATIC_NET_CAP, &remoteStaticCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote info fail, key:NET_STATIC_CAP");
        return ret;
    }
    *localEnable = (localStaticCapa & (1 << netCapaIndex)) > 0;
    *remoteEnable = (remoteStaticCapa & (1 << netCapaIndex)) > 0;
    if (!(*localEnable) || !(*remoteEnable)) {
        LNN_LOGE(LNN_LANE, "static cap disable, local=%{public}u, remote=%{public}u, netCapaIndex=%{public}u",
            localStaticCapa, remoteStaticCapa, netCapaIndex);
    }
    return SOFTBUS_OK;
}

static int32_t DynamicNetCapaCalc(const char *networkId, uint32_t netCapaIndex, bool *localEnable, bool *remoteEnable)
{
    uint32_t localNetCapa = 0;
    uint32_t remoteNetCapa = 0;
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &localNetCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local info fail, key:NET_CAP");
        return ret;
    }
    ret = LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, &remoteNetCapa);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote info fail, key:NET_CAP");
        return ret;
    }
    *localEnable = (localNetCapa & (1 << netCapaIndex)) > 0;
    *remoteEnable = (remoteNetCapa & (1 << netCapaIndex)) > 0;
    if (!(*localEnable) || !(*remoteEnable)) {
        LNN_LOGE(LNN_LANE, "dynamic cap disable, local=%{public}u, remote=%{public}u, netCapaIndex=%{public}u",
            localNetCapa, remoteNetCapa, netCapaIndex);
    }
    return SOFTBUS_OK;
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

static int32_t WlanStaticCommCapa(const char *networkId)
{
    bool localWlanEnable = false;
    bool remoteWlanEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_WIFI, &localWlanEnable, &remoteWlanEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localWlanEnable) {
        return SOFTBUS_LANE_LOCAL_NO_WIFI_STATIC_CAP;
    }
    if (!remoteWlanEnable) {
        return SOFTBUS_LANE_REMOTE_NO_WIFI_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t Wlan2P4DynamicCommCapa(const char *networkId)
{
    if (!IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_WIFI)) {
        LNN_LOGD(LNN_LANE, "WIFI not online");
        return SOFTBUS_LANE_WIFI_NOT_ONLINE;
    }
    bool local2P4Enable = false;
    bool remote2P4Enable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_24G, &local2P4Enable, &remote2P4Enable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    /* dynamic netcap is updated when wifi status changes, check band type by it. */
    if (!local2P4Enable) {
        return SOFTBUS_LANE_WIFI_BAND_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t Wlan5GDynamicCommCapa(const char *networkId)
{
    if (!IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_WIFI)) {
        LNN_LOGD(LNN_LANE, "WIFI not online");
        return SOFTBUS_LANE_WIFI_NOT_ONLINE;
    }
    bool local5GEnable = false;
    bool remote5GEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_5G, &local5GEnable, &remote5GEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    /* dynamic netcap is updated when wifi status changes, check band type by it. */
    if (!local5GEnable) {
        return SOFTBUS_LANE_WIFI_BAND_ERR;
    }
    return SOFTBUS_OK;
}

static LaneCommCapa g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_WLAN_2P4G] = {WlanStaticCommCapa, Wlan2P4DynamicCommCapa, BIT_WIFI_24G},
    [LANE_WLAN_5G] = {WlanStaticCommCapa, Wlan5GDynamicCommCapa, BIT_WIFI_5G},
};

static LaneCommCapa *GetLinkCapaByLinkType(LaneLinkType linkType)
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

int32_t CheckStaticNetCap(const char *networkId, LaneLinkType linkType)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    LaneCommCapa *capaManager = GetLinkCapaByLinkType(linkType);
    if (capaManager == NULL) {
        LNN_LOGE(LNN_LANE, "capaManager is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    return capaManager->getStaticCommCapa(networkId);
}

int32_t CheckDynamicNetCap(const char *networkId, LaneLinkType linkType)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    LaneCommCapa *capaManager = GetLinkCapaByLinkType(linkType);
    if (capaManager == NULL) {
        LNN_LOGE(LNN_LANE, "capaManager is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    return capaManager->getDynamicCommCapa(networkId);
}

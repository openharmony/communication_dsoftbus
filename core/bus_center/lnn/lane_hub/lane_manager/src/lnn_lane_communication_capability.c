/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

static int32_t BrStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_BR, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BR_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BR_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t BrDynamicCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_BR, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BR_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BR_CAP;
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

static int32_t BleStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_BLE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BLE_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BLE_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t BleDynamicCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_BLE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BLE_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BLE_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t P2pStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_P2P, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_P2P_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_P2P_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static void SetLocalDynamicNetCap(NetCapability netCapaIndex)
{
    uint32_t oldCapa = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &oldCapa) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local info fail");
        return;
    }
    if ((oldCapa & (1 << netCapaIndex)) > 0) {
        return;
    }
    uint32_t newCapa = oldCapa;
    (void)LnnSetNetCapability(&newCapa, netCapaIndex);
    int32_t ret = LnnSetLocalNumU32Info(NUM_KEY_NET_CAP, newCapa);
    LNN_LOGI(LNN_LANE, "local capability change:%{public}u->%{public}u, ret=%{public}d", oldCapa, newCapa, ret);
}

static bool IsLocalWifiEnabled(void)
{
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
        return false;
    }
    SetLocalDynamicNetCap(BIT_WIFI_P2P);
    return true;
}

static int32_t P2pDynamicCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_P2P, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable && !IsLocalWifiEnabled()) {
        return SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t WiFiDirectStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_ENHANCED_P2P, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_ENHANCED_P2P_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_ENHANCED_P2P_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t WiFiDirectDynamicCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_P2P, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable && !IsLocalWifiEnabled()) {
        return SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t WlanStaticCommCapa(const char *networkId)
{
    bool localWlanEnable = false;
    bool remoteWlanEnable = false;
    bool localEthEnable = false;
    bool remoteEthEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_WIFI, &localWlanEnable, &remoteWlanEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_ETH, &localEthEnable, &remoteEthEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localWlanEnable && !localEthEnable) {
        return SOFTBUS_LANE_LOCAL_NO_WIFI_STATIC_CAP;
    }
    if (!remoteWlanEnable && !remoteEthEnable) {
        return SOFTBUS_LANE_REMOTE_NO_WIFI_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t Wlan2P4DynamicCommCapa(const char *networkId)
{
    if (!IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_WIFI) &&
        !IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_LSA)) {
        LNN_LOGE(LNN_LANE, "WIFI not online");
        return SOFTBUS_LANE_WIFI_NOT_ONLINE;
    }
    bool local2P4Enable = false;
    bool remote2P4Enable = false;
    bool localEthEnable = false;
    bool remoteEthEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_24G, &local2P4Enable, &remote2P4Enable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    ret = DynamicNetCapaCalc(networkId, BIT_ETH, &localEthEnable, &remoteEthEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    /* dynamic netcap is updated when wifi status changes, check band type by it. */
    if (!local2P4Enable && !localEthEnable) {
        return SOFTBUS_LANE_WIFI_BAND_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t Wlan5GDynamicCommCapa(const char *networkId)
{
    if (!IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_WIFI) &&
        !IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_LSA)) {
        LNN_LOGE(LNN_LANE, "WIFI not online");
        return SOFTBUS_LANE_WIFI_NOT_ONLINE;
    }
    bool local5GEnable = false;
    bool remote5GEnable = false;
    bool localEthEnable = false;
    bool remoteEthEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_WIFI_5G, &local5GEnable, &remote5GEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    ret = DynamicNetCapaCalc(networkId, BIT_ETH, &localEthEnable, &remoteEthEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    /* dynamic netcap is updated when wifi status changes, check band type by it. */
    if (!local5GEnable && !localEthEnable) {
        return SOFTBUS_LANE_WIFI_BAND_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t EthStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_ETH, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_ETH_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_ETH_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t EthDynamicCommCapa(const char *networkId)
{
    if (!IsDeviceOnlineByTargetType(networkId, DISCOVERY_TYPE_LSA)) {
        LNN_LOGE(LNN_LANE, "LSA not online");
        return SOFTBUS_LANE_WIFI_NOT_ONLINE;
    }
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_ETH, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_ETH_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_ETH_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t CocStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_BLE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BLE_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BLE_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t CocDynamicCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_BLE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BLE_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BLE_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t UsbStaticCommCapa(const char *networkId)
{
    bool localUsbEnable = false;
    bool remoteUsbEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_USB, &localUsbEnable, &remoteUsbEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localUsbEnable) {
        return SOFTBUS_LANE_LOCAL_NO_USB_STATIC_CAP;
    }
    if (!remoteUsbEnable) {
        return SOFTBUS_LANE_REMOTE_NO_USB_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t UsbDynamicCommCapa(const char *networkId)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote node info fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_USB)) {
        LNN_LOGE(LNN_LANE, "peer node not USB online");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    return SOFTBUS_OK;
}

static int32_t SleStaticCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = StaticNetCapaCalc(networkId, STATIC_CAP_BIT_SLE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check static net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_SLE_STATIC_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_SLE_STATIC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t SleDynamicCommCapa(const char *networkId)
{
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = DynamicNetCapaCalc(networkId, BIT_SLE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check dynamic net cap fail, ret=%{public}d", ret);
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_SLE_CAP;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_SLE_CAP;
    }
    return SOFTBUS_OK;
}

static LaneCommCapa g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = {BrStaticCommCapa, BrDynamicCommCapa, BIT_BR },
    [LANE_BLE] = {BleStaticCommCapa, BleDynamicCommCapa, BIT_BLE},
    [LANE_P2P] = {P2pStaticCommCapa, P2pDynamicCommCapa, BIT_WIFI_P2P},
    [LANE_HML] = {WiFiDirectStaticCommCapa, WiFiDirectDynamicCommCapa, BIT_WIFI_P2P},
    [LANE_WLAN_2P4G] = {WlanStaticCommCapa, Wlan2P4DynamicCommCapa, BIT_WIFI_24G},
    [LANE_WLAN_5G] = {WlanStaticCommCapa, Wlan5GDynamicCommCapa, BIT_WIFI_5G},
    [LANE_ETH] = {EthStaticCommCapa, EthDynamicCommCapa, BIT_ETH},
    [LANE_P2P_REUSE] = {P2pStaticCommCapa, P2pDynamicCommCapa, BIT_WIFI_P2P},
    [LANE_BLE_DIRECT] = {BleStaticCommCapa, BleDynamicCommCapa, BIT_BLE},
    [LANE_BLE_REUSE] = {BleStaticCommCapa, BleDynamicCommCapa, BIT_BLE},
    [LANE_COC] = {CocStaticCommCapa, CocDynamicCommCapa, BIT_BLE},
    [LANE_COC_DIRECT] = {CocStaticCommCapa, CocDynamicCommCapa, BIT_BLE},
    [LANE_USB] = {UsbStaticCommCapa, UsbDynamicCommCapa, BIT_USB},
    [LANE_SLE] = {SleStaticCommCapa, SleDynamicCommCapa, BIT_SLE},
    [LANE_SLE_DIRECT] = {SleStaticCommCapa, SleDynamicCommCapa, BIT_SLE},
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

static void SetRemoteDynamicNetCapByIdx(const char *networkId, NetCapability netCapaIndex)
{
    uint32_t oldCapa = 0;
    if (LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, &oldCapa) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote info fail");
        return;
    }
    if ((oldCapa & (1 << netCapaIndex)) > 0) {
        return;
    }
    uint32_t newCapa = oldCapa;
    (void)LnnSetNetCapability(&newCapa, netCapaIndex);
    int32_t ret = LnnSetDLConnCapability(networkId, newCapa);
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "networkId=%{public}s capability change:%{public}u->%{public}u, ret=%{public}d",
        AnonymizeWrapper(anonyNetworkId), oldCapa, newCapa, ret);
    AnonymizeFree(anonyNetworkId);
}

void SetRemoteDynamicNetCap(const char *peerUdid, LaneLinkType linkType)
{
    if (peerUdid == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnGetNetworkIdByUdid(peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get networkId fail");
        return;
    }
    LaneCommCapa *capaManager = GetLinkCapaByLinkType(linkType);
    if (capaManager == NULL) {
        LNN_LOGE(LNN_LANE, "capaManager is nullptr");
        return;
    }
    SetRemoteDynamicNetCapByIdx(networkId, capaManager->netCapaIndex);
}
/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "trans_link_listener.h"

#include "securec.h"

#include "bus_center_manager.h"
#include "data_bus_native.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_p2p.h"
#include "wifi_direct_manager.h"

#define NETWORK_ID_LEN                    7
#define COMBINE_TYPE(routeType, connType) ((routeType) | ((uint8_t)(connType) << 8))

static void ClearIpInfo(const char *peerUuid)
{
    if (LnnSetLocalStrInfo(STRING_KEY_P2P_IP, "") != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SVC, "set local p2p ip fail");
    }
    if (LnnSetDLP2pIp(peerUuid, CATEGORY_UUID, "") != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SVC, "set peer p2p ip fail");
    }
}

static int32_t FillNodeInfoAsMeta(const char *metaNodeId, NodeInfo *nodeInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(metaNodeId != NULL, SOFTBUS_INVALID_PARAM, TRANS_SVC, "metaNodeId is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(nodeInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_SVC, "nodeInfo is null");

    int32_t osType = 0;
    int32_t ret = LnnGetOsTypeByNetworkId(metaNodeId, &osType);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SVC, "get osType failed, ret=%{public}d", ret);
    if (osType != OTHER_OS_TYPE) {
        TRANS_LOGW(TRANS_SVC, "invalid osType=%{public}d", osType);
        return SOFTBUS_INVALID_PARAM;
    }
    ret = strcpy_s(nodeInfo->networkId, sizeof(nodeInfo->networkId), metaNodeId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, TRANS_SVC, "strcpy_s netowrkId failed");

    ret = strcpy_s(nodeInfo->uuid, sizeof(nodeInfo->uuid), metaNodeId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, TRANS_SVC, "strcpy_s uuid failed");

    ret = strcpy_s(nodeInfo->masterUdid, sizeof(nodeInfo->masterUdid), metaNodeId);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, TRANS_SVC, "strcpy_s masterUdid failed");

    return SOFTBUS_OK;
}

static void OnWifiDirectDeviceOffline(
    const char *peerMac, const char *peerIp, const char *peerUuid, const char *localIp)
{
    (void)peerMac;
    TRANS_CHECK_AND_RETURN_LOGE(peerUuid != NULL, TRANS_SVC, "peer uuid is null");
    TRANS_CHECK_AND_RETURN_LOGE(localIp != NULL, TRANS_SVC, "local ip is null");

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));

    int32_t ret = LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SVC, "LnnGetRemoteNodeInfoById failed, retry as meta, ret=%{public}d", ret);
        ret = FillNodeInfoAsMeta(peerUuid, &nodeInfo);
        TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "fill as metaNodeId failed, ret=%{public}d", ret);
    }

    TransConnType connType = TRANS_CONN_ALL;
    if (IsHmlIpAddr(localIp)) {
        ClearHmlListenerByUuid(peerUuid);
        connType = TRANS_CONN_HML;
    } else {
        StopP2pListenerByRemoteUuid(peerUuid);
        ClearIpInfo(peerUuid);
        connType = TRANS_CONN_P2P;
    }

    TransOnLinkDown(nodeInfo.networkId, nodeInfo.uuid, nodeInfo.masterUdid, peerIp, COMBINE_TYPE(WIFI_P2P, connType));
    TRANS_LOGI(TRANS_SVC, "Notify Degrade MigrateEvents start");
    ret = NotifyNearByOnMigrateEvents(nodeInfo.networkId, WIFI_P2P, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "Notify Degrade MigrateEvents fail, ret=%{public}d", ret);
        return;
    }
    TRANS_LOGI(TRANS_SVC, "Notify Degrade MigrateEvents success");
}

static void OnWifiDirectRoleChange(enum WifiDirectRole oldRole, enum WifiDirectRole newRole)
{
    (void)oldRole;
    (void)newRole;
}

static void OnWifiDirectDeviceOnline(const char *peerMac, const char *peerIp, const char *peerUuid, bool isSource)
{
    (void)peerMac;
    (void)peerIp;
    (void)isSource;
    TRANS_CHECK_AND_RETURN_LOGE(peerUuid != NULL, TRANS_SVC, "peer uuid is null");

    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));

    int32_t ret = LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, &nodeInfo);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "LnnGetRemoteNodeInfoById failed");

    TRANS_LOGI(TRANS_SVC, "Notify Upgrade MigrateEvents start");
    ret = NotifyNearByOnMigrateEvents(nodeInfo.networkId, WIFI_P2P, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "Notify Upgrade MigrateEvents fail, ret=%{public}d", ret);
        return;
    }
    TRANS_LOGI(TRANS_SVC, "Notify Upgrade MigrateEvents success");
}

void ReqLinkListener(void)
{
    struct WifiDirectStatusListener listener = {
        .onDeviceOffLine = OnWifiDirectDeviceOffline,
        .onLocalRoleChange = OnWifiDirectRoleChange,
        .onDeviceOnLine = OnWifiDirectDeviceOnline,
    };
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr != NULL && mgr->registerStatusListener != NULL) {
        mgr->registerStatusListener(&listener);
    }
}

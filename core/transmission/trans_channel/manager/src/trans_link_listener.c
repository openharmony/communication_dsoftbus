/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "lnn_distributed_net_ledger.h"
#include "securec.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_p2p.h"
#include "wifi_direct_manager.h"
#include "data_bus_native.h"
#include "softbus_conn_interface.h"

#define NETWORK_ID_LEN 7
#define HML_IP_PREFIX "172.30."
#define COMBINE_TYPE(routeType, connType) ((routeType) | ((uint8_t)(connType) << 8))

static void OnWifiDirectDeviceOffLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    TRANS_CHECK_AND_RETURN_LOGW(peerUuid, TRANS_SVC, "peer uuid is null");

    NodeInfo nodeInfo;
    TransConnType connType = TRANS_CONN_ALL;
    memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, &nodeInfo);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "LnnGetRemoteNodeInfoById failed");

    char myIp[IP_LEN] = {0};
    if (GetWifiDirectManager()->getLocalIpByRemoteIp(peerIp, myIp, sizeof(myIp)) == SOFTBUS_OK) {
        if (strncmp(myIp, HML_IP_PREFIX, NETWORK_ID_LEN) == 0) {
            ListenerModule type = GetMoudleByHmlIp(myIp);
            if (type != UNUSE_BUTT) {
                StopHmlListener(type);
                TRANS_LOGI(TRANS_SVC, "StopHmlListener succ");
            }
            connType = TRANS_CONN_HML;
        } else {
            connType = TRANS_CONN_P2P;
        }
    } else {
        TRANS_LOGI(TRANS_SVC, "WifiDirectDeviceOffLine do not get localip");
    }

    TransOnLinkDown(nodeInfo.networkId, nodeInfo.uuid, nodeInfo.masterUdid, peerIp, COMBINE_TYPE(WIFI_P2P, connType));
    TRANS_LOGI(TRANS_SVC, "Notify Degrade MigrateEvents start");
    ret = NotifyNearByOnMigrateEvents(nodeInfo.networkId, WIFI_P2P, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "Notify Degrade MigrateEvents fail");
    }
    TRANS_LOGI(TRANS_SVC, "Notify Degrade MigrateEvents success");
}

static void OnWifiDirectRoleChange(enum WifiDirectRole myRole)
{
    if (myRole == WIFI_DIRECT_ROLE_NONE) {
        TRANS_LOGI(TRANS_SVC, "my role change to NONE");
        StopP2pSessionListener();
        for (int i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
            StopHmlListener(i);
        }
    }
}

static void OnWifiDirectDeviceOnLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    TRANS_CHECK_AND_RETURN_LOGW(peerMac, TRANS_SVC, "peer mac is null");
    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, &nodeInfo);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "LnnGetRemoteNodeInfoById failed");
    TRANS_LOGI(TRANS_SVC, "Notify Upgrade MigrateEvents start");
    ret = NotifyNearByOnMigrateEvents(nodeInfo.networkId, WIFI_P2P, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "Notify Upgrade MigrateEvents fail");
    }
    TRANS_LOGI(TRANS_SVC, "Notify Upgrade MigrateEvents success");
}

void ReqLinkListener(void)
{
    struct WifiDirectStatusListener listener = {
        .onDeviceOffLine = OnWifiDirectDeviceOffLine,
        .onLocalRoleChange = OnWifiDirectRoleChange,
        .onDeviceOnLine = OnWifiDirectDeviceOnLine,
    };
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr != NULL && mgr->registerStatusListener != NULL) {
        mgr->registerStatusListener(&listener);
    }
}

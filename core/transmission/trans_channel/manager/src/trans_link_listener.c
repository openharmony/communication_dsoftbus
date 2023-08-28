/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "softbus_app_info.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_p2p.h"
#include "wifi_direct_manager.h"
#include "data_bus_native.h"
#include "softbus_conn_interface.h"

#define NETWORK_ID_LEN 7
#define HML_IP_PREFIX "172.30."

static void OnWifiDirectDeviceOffLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    TRAN_CHECK_AND_RETURN_LOG(peerUuid, "peer uuid is null");

    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, &nodeInfo);
    TRAN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "LnnGetRemoteNodeInfoById failed");

    char myIp[IP_LEN] = {0};
    if (GetWifiDirectManager()->getLocalIpByRemoteIp(peerIp, myIp, sizeof(myIp)) == SOFTBUS_OK) {
        if (strncmp(myIp, HML_IP_PREFIX, NETWORK_ID_LEN) == 0) {
            ListenerModule type = GetMoudleByHmlIp(myIp);
            if (type != UNUSE_BUTT) {
                StopHmlListener(type);
                SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "StopHmlListener succ");
            }
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "WifiDirectDeviceOffLine do not get localip");
    }

    TransOnLinkDown(nodeInfo.networkId, nodeInfo.uuid, nodeInfo.masterUdid, peerIp, WIFI_P2P);
    TLOGI("Notify Degrade MigrateEvents start");
    ret = NotifyNearByOnMigrateEvents(nodeInfo.networkId, WIFI_P2P, false);
    if (ret != SOFTBUS_OK) {
        TLOGE("Notify Degrade MigrateEvents fail");
    }
    TLOGI("Notify Degrade MigrateEvents success");
}

static void OnWifiDirectRoleChange(enum WifiDirectRole myRole)
{
    if (myRole == WIFI_DIRECT_ROLE_NONE) {
        TLOGI("my role change to NONE");
        StopP2pSessionListener();
        for (int i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
            StopHmlListener(i);
        }
    }
}

static void OnWifiDirectDeviceOnLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    TRAN_CHECK_AND_RETURN_LOG(peerMac, "peer mac is null");
    NodeInfo nodeInfo;
    memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoById(peerUuid, CATEGORY_UUID, &nodeInfo);
    TRAN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, "LnnGetRemoteNodeInfoById failed");
    TLOGI("Notify Upgrade MigrateEvents start");
    ret = NotifyNearByOnMigrateEvents(nodeInfo.networkId, WIFI_P2P, true);
    if (ret != SOFTBUS_OK) {
        TLOGE("Notify Upgrade MigrateEvents fail");
    }
    TLOGI("Notify Upgrade MigrateEvents success");
}

NO_SANITIZE("cfi") void ReqLinkListener(void)
{
    struct WifiDirectStatusListener listener = {
        .onDeviceOffLine = OnWifiDirectDeviceOffLine,
        .onLocalRoleChange = OnWifiDirectRoleChange,
        .onDeviceOnLine = OnWifiDirectDeviceOnLine,
    };
    GetWifiDirectManager()->registerStatusListener(&listener);
}

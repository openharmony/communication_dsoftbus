/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_connection_fsm_process.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "auth_pre_link.h"
#include "auth_deviceprofile.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_ble_lpdevice.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_connId_callback_manager.h"
#include "lnn_decision_db.h"
#include "lnn_devicename_info.h"
#include "lnn_device_info.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_link_finder.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_net_builder_init.h"
#include "lnn_sync_item_info.h"
#include "softbus_adapter_bt_common.h"
#include "lnn_feature_capability.h"
#include "lnn_deviceinfo_to_profile.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "lnn_async_callback_utils.h"
#include "trans_channel_manager.h"

bool CheckInterfaceCommonArgs(const LnnConnectionFsm *connFsm, bool needCheckDead)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is null");
        return false;
    }
    if (needCheckDead && connFsm->isDead) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is already dead. [id=%{public}u]", connFsm->id);
        return false;
    }
    return true;
}

void NotifyJoinResult(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is null");
        return;
    }
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    if ((connInfo->flag & LNN_CONN_INFO_FLAG_JOIN_REQUEST) != 0) {
        LnnNotifyJoinResult(&connInfo->addr, networkId, retCode);
        connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_ACTIVE;
        return;
    }
    NodeInfo *nodeInfo = connInfo->nodeInfo;
    if (retCode == SOFTBUS_OK && nodeInfo != NULL) {
        if (connInfo->addr.type == CONNECTION_ADDR_WLAN || connInfo->addr.type == CONNECTION_ADDR_NCM) {
            int32_t ifIdx = (connInfo->addr.type == CONNECTION_ADDR_NCM) ? USB_IF : WLAN_IF;
            if (connInfo->addr.info.ip.port != nodeInfo->connectInfo.ifInfo[ifIdx].authPort) {
                LNN_LOGI(LNN_BUILDER, "before port =%{public}d, after port=%{public}d",
                    connInfo->addr.info.ip.port, nodeInfo->connectInfo.ifInfo[ifIdx].authPort);
                connInfo->addr.info.ip.port = nodeInfo->connectInfo.ifInfo[ifIdx].authPort;
            }
        }
        LnnNotifyJoinResult(&connInfo->addr, networkId, retCode);
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_ACTIVE;
}

void FreeUnhandledMessage(int32_t msgType, void *para)
{
    LNN_LOGI(LNN_BUILDER, "free unhandled msg. msgType=%{public}d", msgType);
    if (para != NULL) {
        SoftBusFree(para);
    }
}

void ReportDeviceOnlineEvt(const char *udid, NodeBasicInfo *peerDevInfo)
{
    if (peerDevInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "peer deviceinfo is null");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "report device online evt enter");
    int32_t infoNum = 0;
    NodeBasicInfo *basic = NULL;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    OnlineDeviceInfo info;
    (void)memset_s(&info, sizeof(OnlineDeviceInfo), 0, sizeof(OnlineDeviceInfo));
    if (LnnGetAllOnlineNodeInfo(&basic, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get online node fail");
        return;
    }
    if (basic == NULL || infoNum == 0) {
        LNN_LOGI(LNN_BUILDER, "report online evt get none online node");
        return;
    }
    info.onlineDevNum = (uint32_t)infoNum;
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnGetRemoteNodeInfoById(basic[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            continue;
        }
        if (LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_WIFI)) {
            info.wifiOnlineDevNum++;
        }
        if (LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_BLE) || LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_BR)) {
            info.btOnlineDevNum++;
        }
    }
    SoftBusFree(basic);
    info.peerDevType = peerDevInfo->deviceTypeId;
    if (LnnGetRemoteStrInfo(peerDevInfo->networkId, STRING_KEY_DEV_NAME, info.peerDevName,
        SOFTBUS_HISYSEVT_NAME_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote device name fail");
    }
    if (LnnGetRemoteStrInfo(peerDevInfo->networkId, STRING_KEY_HICE_VERSION, info.peerSoftBusVer,
        SOFTBUS_HISYSEVT_NAME_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote softbus version fail");
    }
    info.insertFileResult = true;
    if (SoftBusReportDevOnlineEvt(&info, udid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "report device online evt fail");
    }
}
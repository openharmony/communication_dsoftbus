/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_connection_fsm.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_hichain.h"
#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_ble_lpdevice.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_decision_db.h"
#include "lnn_device_info.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_link_finder.h"
#include "lnn_log.h"
#include "lnn_net_builder.h"
#include "lnn_sync_item_info.h"
#include "softbus_adapter_bt_common.h"
#include "lnn_feature_capability.h"
#include "lnn_deviceinfo_to_profile.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "lnn_async_callback_utils.h"
#include "trans_channel_manager.h"

#define DATA_SIZE 32
#define DISCOVERY_TYPE_MASK 0x7FFF

typedef enum {
    STATE_AUTH_INDEX = 0,
    STATE_CLEAN_INVALID_CONN_INDEX,
    STATE_ONLINE_INDEX,
    STATE_LEAVING_INDEX,
    STATE_NUM_MAX,
} ConnFsmStateIndex;

#define JOIN_LNN_TIMEOUT_LEN  (15 * 1000UL)
#define LEAVE_LNN_TIMEOUT_LEN (5 * 1000UL)

#define TO_CONN_FSM(ptr) CONTAINER_OF(ptr, LnnConnectionFsm, fsm)

#define CONN_CODE_SHIFT 16

typedef enum {
    FSM_MSG_TYPE_JOIN_LNN,
    FSM_MSG_TYPE_AUTH_DONE,
    FSM_MSG_TYPE_LEAVE_INVALID_CONN,
    FSM_MSG_TYPE_LEAVE_LNN,
    FSM_MSG_TYPE_NOT_TRUSTED,
    FSM_MSG_TYPE_DISCONNECT = 5,
    FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
    FSM_MSG_TYPE_SYNC_OFFLINE_DONE,
    FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT,
    FSM_MSG_TYPE_INITIATE_ONLINE,
} StateMessageType;

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool CleanInvalidConnStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void OnlineStateEnter(FsmStateMachine *fsm);
static bool OnlineStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void LeavingStateEnter(FsmStateMachine *fsm);
static bool LeavingStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);

static FsmState g_states[STATE_NUM_MAX] = {
    [STATE_AUTH_INDEX] = {
        .enter = NULL,
        .process = AuthStateProcess,
        .exit = NULL,
    },
    [STATE_CLEAN_INVALID_CONN_INDEX] = {
        .enter = NULL,
        .process = CleanInvalidConnStateProcess,
        .exit = NULL,
    },
    [STATE_ONLINE_INDEX] = {
        .enter = OnlineStateEnter,
        .process = OnlineStateProcess,
        .exit = NULL,
    },
    [STATE_LEAVING_INDEX] = {
        .enter = LeavingStateEnter,
        .process = LeavingStateProcess,
        .exit = NULL,
    },
};

static bool CheckStateMsgCommonArgs(const FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "fsm is null");
        return false;
    }
    if (TO_CONN_FSM(fsm) == NULL) {
        LNN_LOGE(LNN_BUILDER, "connFsm is null");
        return false;
    }
    return true;
}

static bool CheckDeadFlag(const LnnConnectionFsm *connFsm, bool expectDeadFlag)
{
    return connFsm->isDead == expectDeadFlag;
}

static bool CheckInterfaceCommonArgs(const LnnConnectionFsm *connFsm, bool needCheckDead)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is null");
        return false;
    }
    if (needCheckDead && connFsm->isDead) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is already dead. id=%{public}u", connFsm->id);
        return false;
    }
    return true;
}

static void NotifyJoinResult(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if ((connInfo->flag & LNN_CONN_INFO_FLAG_JOIN_REQUEST) != 0) {
        LnnNotifyJoinResult(&connInfo->addr, networkId, retCode);
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_ACTIVE;
}

static void NotifyLeaveResult(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if ((connInfo->flag & LNN_CONN_INFO_FLAG_LEAVE_REQUEST) != 0) {
        LnnNotifyLeaveResult(networkId, retCode);
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_LEAVE_ACTIVE;
}

static void FreeUnhandledMessage(int32_t msgType, void *para)
{
    LNN_LOGI(LNN_BUILDER, "free unhandled msg. msgType=%{public}d", msgType);
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static void ReportDeviceOnlineEvt(const char *udid, NodeBasicInfo *peerDevInfo)
{
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
    info.onlineDevNum = infoNum;
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

static void OnlineTrustGroupProc(const char *udid)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(udid, CATEGORY_UDID, &nodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote info fail");
        return;
    }
    if (((uint32_t)nodeInfo.groupType & GROUP_TYPE_P2P) == 0) {
        LNN_LOGW(LNN_BUILDER, "not nonAccount group relation, don't save deviceUdid");
        return;
    }
    LnnInsertSpecificTrustedDevInfo(udid);
}

static void ReportResult(const char *udid, ReportCategory report)
{
    NodeBasicInfo basic;

    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "GetBasicInfoByUdid fail!");
        return;
    }
    switch (report) {
        case REPORT_CHANGE:
            LnnNotifyBasicInfoChanged(&basic, TYPE_NETWORK_ID);
            break;
        case REPORT_ONLINE:
            LnnNotifyOnlineState(true, &basic);
            OnlineTrustGroupProc(udid);
            ReportDeviceOnlineEvt(udid, &basic);
            break;
        case REPORT_NONE:
            /* fall-through */
        default:
            break;
    }
}

static SoftBusLinkType ConvertAddrTypeToHisysEvtLinkType(ConnectionAddrType type)
{
    if (type < CONNECTION_ADDR_WLAN || type > CONNECTION_ADDR_MAX) {
        return SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
    }
    switch (type) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
            return SOFTBUS_HISYSEVT_LINK_TYPE_WLAN;
        case CONNECTION_ADDR_BR:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BR;
        case CONNECTION_ADDR_BLE:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BLE;
        case CONNECTION_ADDR_SESSION:
        case CONNECTION_ADDR_MAX:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
        default:
            return SOFTBUS_HISYSEVT_LINK_TYPE_BUTT;
    }
}

static void ReportLnnResultEvt(LnnConnectionFsm *connFsm, int32_t retCode)
{
    LNN_LOGI(LNN_BUILDER, "report lnn result evt enter");
    SoftBusLinkType linkType = ConvertAddrTypeToHisysEvtLinkType(connFsm->connInfo.addr.type);
    if (linkType == SOFTBUS_HISYSEVT_LINK_TYPE_BUTT) {
        return;
    }
    if (retCode == SOFTBUS_OK) {
        connFsm->statisticData.beginOnlineTime = LnnUpTimeMs();
        uint64_t constTime = connFsm->statisticData.beginOnlineTime - connFsm->statisticData.beginJoinLnnTime;
        if (SoftBusRecordBusCenterResult(linkType, constTime) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "report static lnn duration fail");
        }
        return;
    }
    SoftBusFaultEvtInfo info;
    (void)memset_s(&info, sizeof(SoftBusFaultEvtInfo), 0, sizeof(SoftBusFaultEvtInfo));
    info.moduleType = MODULE_TYPE_ONLINE;
    info.linkType = linkType;
    info.errorCode = retCode;
    if (SoftBusReportBusCenterFaultEvt(&info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "report buscenter fault evt fail");
    }
}

static bool IsDeviceTypePc(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "nodeInfo is NULL");
        return false;
    }
    return info->deviceInfo.deviceTypeId == TYPE_PC_ID;
}

static void PostPcOnlineUniquely(NodeInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "nodeInfo is NULL");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "pc online");
    bool isPcWithSoftbus = false;
    if (info->deviceInfo.deviceTypeId == TYPE_PC_ID &&
        strcmp(info->networkId, info->deviceInfo.deviceUdid) != 0) {
        isPcWithSoftbus = true;
    }
    if (!isPcWithSoftbus) {
        LNN_LOGI(LNN_BUILDER, "pc without softbus online");
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(nodeInfo), 0, sizeof(nodeInfo));
    char brMacHash[BT_MAC_HASH_STR_LEN] = {0};
    if (LnnGenerateBtMacHash((const char *)info->connectInfo.macAddr, BT_MAC_LEN,
        brMacHash, BT_MAC_HASH_STR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get br mac hash fail");
        return;
    }
    if (LnnGetRemoteNodeInfoById(brMacHash, CATEGORY_UDID, &nodeInfo) == SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "set pc without softbus offline");
        DeleteFromProfile(nodeInfo.deviceInfo.deviceUdid);
        LnnRemoveNode(nodeInfo.deviceInfo.deviceUdid);
    }
}

static void DeviceStateChangeProcess(char *udid, ConnectionAddrType type, bool isOnline)
{
    if (udid == NULL) {
        LNN_LOGE(LNN_BUILDER, "udid is NULL");
        return;
    }
    if (type != CONNECTION_ADDR_BLE) {
        LNN_LOGE(LNN_BUILDER, "send mlps only support ble");
        return;
    }
    char *outUdid = (char *)SoftBusCalloc(UDID_BUF_LEN);
    if (outUdid == NULL) {
        LNN_LOGE(LNN_BUILDER, "calloc outUdid fail");
        return;
    }
    if (strcpy_s(outUdid, UDID_BUF_LEN, udid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy outUdid fail");
        SoftBusFree(outUdid);
        return;
    }
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (isOnline) {
        LNN_LOGI(LNN_BUILDER, "SH ap online");
        if (LnnAsyncCallbackDelayHelper(looper, SendInfoToMlpsBleOnlineProcess, (void *)outUdid, 0) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "async call online process fail");
            SoftBusFree(outUdid);
        }
    } else {
        LNN_LOGI(LNN_BUILDER, "SH ap offline");
        if (LnnAsyncCallbackDelayHelper(looper, SendInfoToMlpsBleOfflineProcess, (void *)outUdid, 0) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "async call online process fail");
            SoftBusFree(outUdid);
        }
    }
}

static void SetLnnConnNodeInfo(
    LnnConntionInfo *connInfo, const char *networkId, LnnConnectionFsm *connFsm, int32_t retCode)
{
    ReportCategory report;
    uint64_t localFeature;
    (void)LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature);
    uint8_t relation[CONNECTION_ADDR_MAX] = { 0 };
    report = LnnAddOnlineNode(connInfo->nodeInfo);
    if (LnnInsertLinkFinderInfo(networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "insert rpa info fail.");
    }
    if (LnnUpdateGroupType(connInfo->nodeInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "update grouptype fail");
    }
    LNN_LOGI(LNN_BUILDER, "peer feature=%{public}" PRIu64 ", local=%{public}" PRIu64 "",
        connInfo->nodeInfo->feature, localFeature);
    if (IsFeatureSupport(connInfo->nodeInfo->feature, BIT_BLE_SUPPORT_SENSORHUB_HEARTBEAT) &&
        IsFeatureSupport(localFeature, BIT_BLE_SUPPORT_SENSORHUB_HEARTBEAT)) {
        DeviceStateChangeProcess(connInfo->nodeInfo->deviceInfo.deviceUdid, connInfo->addr.type, true);
    }
    NotifyJoinResult(connFsm, networkId, retCode);
    ReportResult(connInfo->nodeInfo->deviceInfo.deviceUdid, report);
    connInfo->flag |= LNN_CONN_INFO_FLAG_ONLINE;
    LnnNotifyNodeStateChanged(&connInfo->addr);
    LnnOfflineTimingByHeartbeat(networkId, connInfo->addr.type);
    LnnGetLnnRelation(networkId, CATEGORY_NETWORK_ID, relation, CONNECTION_ADDR_MAX);
    LnnNotifyLnnRelationChanged(
        connInfo->nodeInfo->deviceInfo.deviceUdid, connInfo->addr.type, relation[connInfo->addr.type], true);
}

static void CompleteJoinLNN(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (connInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "CompleteJoinLNN connInfo is NULL");
        return;
    }
    SetWatchdogFlag(true);
    LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    if (IsDeviceTypePc(connInfo->nodeInfo)) {
        PostPcOnlineUniquely(connInfo->nodeInfo);
    }
    ReportLnnResultEvt(connFsm, retCode);
    if (retCode == SOFTBUS_OK && connInfo->nodeInfo != NULL) {
        SetLnnConnNodeInfo(connInfo, networkId, connFsm, retCode);
    } else if (retCode != SOFTBUS_OK) {
        NotifyJoinResult(connFsm, networkId, retCode);
        AuthHandleLeaveLNN(connInfo->authId);
    }
    if (connInfo->nodeInfo != NULL) {
        SoftBusFree(connInfo->nodeInfo);
        connInfo->nodeInfo = NULL;
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    if (retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "join failed, ready clean, id=%{public}u, retCode=%{public}d", connFsm->id, retCode);
        connFsm->isDead = true;
        LnnRequestCleanConnFsm(connFsm->id);
        return;
    }
    LNN_LOGI(LNN_BUILDER, "complete join LNN done. id=%{public}u", connFsm->id);
}

static bool UpdateLeaveToLedger(const LnnConnectionFsm *connFsm, const char *networkId, NodeBasicInfo *basic)
{
    const LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    const char *udid = NULL;
    bool needReportOffline = false;
    bool isMetaAuth = false;
    bool isCleanInfo = connInfo->cleanInfo != NULL ? true : false;
    uint8_t relation[CONNECTION_ADDR_MAX] = {0};
    ReportCategory report;
    const char *findNetworkId = isCleanInfo ? connInfo->cleanInfo->networkId : networkId;
    if (LnnGetRemoteNodeInfoById(findNetworkId, CATEGORY_NETWORK_ID, &info) != SOFTBUS_OK) {
        LNN_LOGW(LNN_BUILDER, "get node info by networkId fail, isCleanInfo=%{public}d", isCleanInfo);
        return needReportOffline;
    }
    isMetaAuth = (info.AuthTypeValue & (1 << ONLINE_METANODE)) != 0;
    udid = LnnGetDeviceUdid(&info);
    report = LnnSetNodeOffline(udid, connInfo->addr.type, (int32_t)connInfo->authId);
    LnnGetLnnRelation(udid, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    LnnNotifyLnnRelationChanged(udid, connInfo->addr.type, relation[connInfo->addr.type], false);
    if (LnnGetBasicInfoByUdid(udid, basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get basic info fail. id=%{public}u", connFsm->id);
        needReportOffline = false;
    }
    if (isCleanInfo) {
        if (strcpy_s(basic->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
            LNN_LOGE(LNN_BUILDER, "get node info by networkId fail, isCleanInfo=%{public}d", isCleanInfo);
            return needReportOffline;
        }
    }
    if (report == REPORT_OFFLINE) {
        needReportOffline = true;
        DeleteFromProfile(udid);
        // just remove node when peer device is not trusted
        if ((connInfo->flag & LNN_CONN_INFO_FLAG_LEAVE_PASSIVE) != 0 && !isMetaAuth) {
            LNN_LOGE(LNN_BUILDER, "remove node. id=%{public}u", connFsm->id);
            LnnRemoveNode(udid);
        }
    }
    return needReportOffline;
}

static void ReportLeaveLNNResultEvt(LnnConnectionFsm *connFsm, int32_t retCode)
{
    LNN_LOGI(LNN_BUILDER, "report leave lnn result evt enter");
    if (retCode == SOFTBUS_OK) {
        connFsm->statisticData.offLineTime = LnnUpTimeMs();
        uint64_t constTime = connFsm->statisticData.offLineTime - connFsm->statisticData.beginOnlineTime;
        if (SoftBusRecordDevOnlineDurResult(constTime) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "report static device online duration fail");
        }
        return;
    }
    SoftBusLinkType linkType = ConvertAddrTypeToHisysEvtLinkType(connFsm->connInfo.addr.type);
    if (linkType == SOFTBUS_HISYSEVT_LINK_TYPE_BUTT) {
        return;
    }
    SoftBusFaultEvtInfo info;
    (void)memset_s(&info, sizeof(SoftBusFaultEvtInfo), 0, sizeof(SoftBusFaultEvtInfo));
    info.moduleType = MODULE_TYPE_ONLINE;
    info.linkType = linkType;
    info.errorCode = retCode;
    if (SoftBusReportBusCenterFaultEvt(&info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "report buscenter fault evt fail");
    }
}

static void CompleteLeaveLNN(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    bool needReportOffline = false;
    ReportLeaveLNNResultEvt(connFsm, retCode);
    if (CheckDeadFlag(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "deadFlag is true");
        return;
    }
    LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT);
    if (retCode == SOFTBUS_OK) {
        needReportOffline = UpdateLeaveToLedger(connFsm, networkId, &basic);
        LnnNotifyNodeStateChanged(&connInfo->addr);
        LnnNotifySingleOffLineEvent(&connInfo->addr, &basic);
    }
    NotifyLeaveResult(connFsm, networkId, retCode);
    if (needReportOffline) {
        LnnNotifyOnlineState(false, &basic);
    } else if (retCode == SOFTBUS_OK) {
        LnnNotifySingleOffLineEvent(&connInfo->addr, &basic);
    }
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &info) == SOFTBUS_OK) {
        DeviceStateChangeProcess(info.deviceInfo.deviceUdid, connInfo->addr.type, false);
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_LEAVE_PASSIVE;
    connFsm->isDead = true;
    LnnNotifyAuthHandleLeaveLNN(connInfo->authId);
    LnnRequestCleanConnFsm(connFsm->id);
    LNN_LOGI(LNN_BUILDER, "complete leave lnn, ready clean. id=%{public}u", connFsm->id);
}

static int32_t OnJoinFail(LnnConnectionFsm *connFsm, int32_t retCode)
{
    if (CheckDeadFlag(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    CompleteJoinLNN(connFsm, NULL, retCode);
    return SOFTBUS_OK;
}

static void TryCancelJoinProcedure(LnnConnectionFsm *connFsm)
{
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_LEAVE_AUTO) != 0) {
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_NETWORK_JOIN_CANCELED);
    } else {
        NotifyJoinResult(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_NETWORK_LEAVE_OFFLINE);
    }
}

static int32_t LnnRecoveryBroadcastKey()
{
    if (LnnLoadLocalBroadcastCipherKey() != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "load BroadcastCipherInfo fail");
        return SOFTBUS_ERR;
    }
    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    if (LnnGetLocalBroadcastCipherKey(&broadcastKey) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local info failed");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY, broadcastKey.cipherInfo.key,
        SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_BUILDER, "set key failed");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV, broadcastKey.cipherInfo.iv,
        BROADCAST_IV_LEN) != SOFTBUS_OK) {
        (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
        LNN_LOGE(LNN_BUILDER, "set iv failed");
        return SOFTBUS_ERR;
    }
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    LNN_LOGI(LNN_BUILDER, "recovery broadcastKey success!");
    return SOFTBUS_OK;
}

static int32_t OnJoinLNN(LnnConnectionFsm *connFsm)
{
    int32_t rc;
    AuthConnInfo authConn;
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (CheckDeadFlag(connFsm, true)) {
        NotifyJoinResult(connFsm, NULL, SOFTBUS_NETWORK_CONN_FSM_DEAD);
        return SOFTBUS_ERR;
    }
    if (connInfo->authId > 0) {
        LNN_LOGI(LNN_BUILDER, "join LNN is ongoing, waiting...id=%{public}u", connFsm->id);
        return SOFTBUS_OK;
    }
    LNN_LOGI(LNN_BUILDER, "begin join request, id=%{public}u, peer%{public}s, isNeedConnect=%{public}d", connFsm->id,
        LnnPrintConnectionAddr(&connInfo->addr), connFsm->isNeedConnect);
    connInfo->requestId = AuthGenRequestId();
    (void)LnnConvertAddrToAuthConnInfo(&connInfo->addr, &authConn);
    if (!connFsm->isNeedConnect && connInfo->addr.type == CONNECTION_ADDR_BLE) {
        // go to online
        LNN_LOGI(LNN_BUILDER, "begin to start ble direct online");
        int32_t ret;
        NodeInfo deviceInfo;
        (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
        int64_t authId = 0;
        char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = {0};
        ret = ConvertBytesToHexString(udidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1,
            (const unsigned char *)connInfo->addr.info.ble.udidHash, HB_SHORT_UDID_HASH_LEN);
        LNN_LOGI(LNN_BUILDER, "join udidHash=%{public}s", udidHash);
        if (ret == EOK) {
            if (LnnRetrieveDeviceInfo(udidHash, &deviceInfo) == SOFTBUS_OK &&
                AuthRestoreAuthManager(udidHash, &authConn, connInfo->requestId, &deviceInfo, &authId) == SOFTBUS_OK &&
                LnnRecoveryBroadcastKey() == SOFTBUS_OK) {
                LnnGetVerifyCallback()->onVerifyPassed(connInfo->requestId, authId, &deviceInfo);
                return SOFTBUS_OK;
            }
        }
    }
    if (AuthStartVerify(&authConn, connInfo->requestId, LnnGetVerifyCallback(), true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "auth verify device failed. id=%{public}u", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
        rc = SOFTBUS_ERR;
    } else {
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, NULL, JOIN_LNN_TIMEOUT_LEN);
        rc = SOFTBUS_OK;
    }
    LNN_LOGI(LNN_BUILDER, "verify request. id=%{public}u, requestId=%{public}u", connFsm->id, connInfo->requestId);
    return rc;
}

static int32_t LnnFillConnInfo(LnnConntionInfo *connInfo)
{
    bool isAuthServer = false;
    SoftBusVersion version;
    NodeInfo *nodeInfo = connInfo->nodeInfo;
    nodeInfo->discoveryType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(connInfo->addr.type);
    nodeInfo->authSeqNum = connInfo->authId;
    (void)AuthGetServerSide(connInfo->authId, &isAuthServer);
    nodeInfo->authChannelId[connInfo->addr.type][isAuthServer ? AUTH_AS_SERVER_SIDE : AUTH_AS_CLIENT_SIDE] =
        (int32_t)connInfo->authId;
    nodeInfo->relation[connInfo->addr.type]++;
    if (AuthGetVersion(connInfo->authId, &version) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fill version fail");
        return SOFTBUS_ERR;
    }
    connInfo->version = version;
    if (AuthGetDeviceUuid(connInfo->authId, nodeInfo->uuid, sizeof(nodeInfo->uuid)) != SOFTBUS_OK ||
        nodeInfo->uuid[0] == '\0') {
        LNN_LOGE(LNN_BUILDER, "fill uuid fail");
        return SOFTBUS_ERR;
    }
    if (connInfo->addr.type == CONNECTION_ADDR_ETH || connInfo->addr.type == CONNECTION_ADDR_WLAN) {
        if (strcpy_s(nodeInfo->connectInfo.deviceIp, MAX_ADDR_LEN, connInfo->addr.info.ip.ip) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fill deviceIp fail");
            return SOFTBUS_MEM_ERR;
        }
    }
    if (strcpy_s(connInfo->peerNetworkId, sizeof(connInfo->peerNetworkId), nodeInfo->networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fill networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OnAuthDone(LnnConnectionFsm *connFsm, int32_t *retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (retCode == NULL) {
        LNN_LOGE(LNN_BUILDER, "auth result is null. id=%{public}u", connFsm->id);
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckDeadFlag(connFsm, true)) {
        SoftBusFree(retCode);
        return SOFTBUS_ERR;
    }

    LNN_LOGI(LNN_BUILDER,
        "auth done, id=%{public}u, authId=%{public}" PRId64 ", result=%{public}d, connType=%{public}d",
        connFsm->id, connInfo->authId, *retCode, connFsm->connInfo.addr.type);
    if (*retCode == SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER,
            "auth passed, id=%{public}u, authId=%{public}" PRId64, connFsm->id, connInfo->authId);
        (void)LnnFillConnInfo(connInfo);
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_CLEAN_INVALID_CONN_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, NULL);
    } else {
        LNN_LOGE(LNN_BUILDER,
            "auth failed, id=%{public}u, authId=%{public}" PRId64 ", requestId=%{public}u, reason=%{public}d, "
            "connType=%{public}d",
            connFsm->id, connInfo->authId, connInfo->requestId, *retCode, connFsm->connInfo.addr.type);
        CompleteJoinLNN(connFsm, NULL, *retCode);
    }
    SoftBusFree(retCode);
    return SOFTBUS_OK;
}

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "auth process. id=%{public}u, msgType=%{public}d", connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            OnJoinLNN(connFsm);
            break;
        case FSM_MSG_TYPE_AUTH_DONE:
            OnAuthDone(connFsm, (int32_t *)para);
            break;
        case FSM_MSG_TYPE_DISCONNECT:
            OnJoinFail(connFsm, SOFTBUS_NETWORK_AUTH_DISCONNECT);
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinFail(connFsm, SOFTBUS_NETWORK_JOIN_TIMEOUT);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            TryCancelJoinProcedure(connFsm);
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static bool IsNodeInfoChanged(const LnnConnectionFsm *connFsm, const NodeInfo *oldNodeInfo,
    const NodeInfo *newNodeInfo, ConnectionAddrType *type)
{
    if (strcmp(newNodeInfo->networkId, oldNodeInfo->networkId) != 0) {
        LNN_LOGI(LNN_BUILDER, "networkId changed. id=%{public}u", connFsm->id);
        *type = CONNECTION_ADDR_MAX;
        return true;
    }
    if (connFsm->connInfo.addr.type != CONNECTION_ADDR_ETH && connFsm->connInfo.addr.type != CONNECTION_ADDR_WLAN) {
        return false;
    }
    if (!LnnHasDiscoveryType(oldNodeInfo, DISCOVERY_TYPE_WIFI)) {
        LNN_LOGI(LNN_BUILDER, "oldNodeInfo not have wifi, id=%{public}u, discoveryType=%{public}u",
            connFsm->id, oldNodeInfo->discoveryType);
        return false;
    }
    if (strcmp(newNodeInfo->connectInfo.deviceIp, oldNodeInfo->connectInfo.deviceIp) != 0) {
        LNN_LOGI(LNN_BUILDER, "peer IP changed. id=%{public}u", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    if (newNodeInfo->connectInfo.authPort != oldNodeInfo->connectInfo.authPort) {
        LNN_LOGI(LNN_BUILDER, "peer auth port changed. id=%{public}u", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    if (newNodeInfo->connectInfo.proxyPort != oldNodeInfo->connectInfo.proxyPort) {
        LNN_LOGI(LNN_BUILDER, "peer proxy port changed. id=%{public}u", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    if (newNodeInfo->connectInfo.sessionPort != oldNodeInfo->connectInfo.sessionPort) {
        LNN_LOGI(LNN_BUILDER, "peer session port changed. id=%{public}u", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    return false;
}

static void OnLeaveInvalidConn(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    if (connInfo->nodeInfo == NULL) {
        return;
    }
    NodeInfo oldNodeInfo;
    (void)memset_s(&oldNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    NodeInfo *newNodeInfo = connInfo->nodeInfo;
    ConnectionAddrType addrType;
    int32_t ret = LnnGetRemoteNodeInfoById(connInfo->nodeInfo->deviceInfo.deviceUdid, CATEGORY_UDID, &oldNodeInfo);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    if (ret == SOFTBUS_OK && LnnIsNodeOnline(&oldNodeInfo)) {
        if (IsNodeInfoChanged(connFsm, &oldNodeInfo, newNodeInfo, &addrType)) {
            LNN_LOGI(LNN_BUILDER, "node info changed, ready clean invalid connection. id=%{public}u",
                connFsm->id);
            LnnRequestLeaveInvalidConn(oldNodeInfo.networkId, addrType, newNodeInfo->networkId);
            return;
        }
    }
    LNN_LOGI(LNN_BUILDER, "no need clean invalid connection fsm. id=%{public}u", connFsm->id);
    LnnFsmTransactState(&connFsm->fsm, g_states + STATE_ONLINE_INDEX);
}

static bool CleanInvalidConnStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "clean invalid state process message. id=%{public}u, msgType=%{public}d",
        connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_LEAVE_LNN:
            TryCancelJoinProcedure(connFsm);
            break;
        case FSM_MSG_TYPE_NOT_TRUSTED:
            OnJoinFail(connFsm, SOFTBUS_NETWORK_DEV_NOT_TRUST);
            break;
        case FSM_MSG_TYPE_DISCONNECT:
            OnJoinFail(connFsm, SOFTBUS_NETWORK_AUTH_DISCONNECT);
            break;
        case FSM_MSG_TYPE_LEAVE_INVALID_CONN:
            OnLeaveInvalidConn(connFsm);
            break;
        case FSM_MSG_TYPE_INITIATE_ONLINE:
            LnnFsmTransactState(&connFsm->fsm, g_states + STATE_ONLINE_INDEX);
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinFail(connFsm, SOFTBUS_NETWORK_JOIN_TIMEOUT);
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static void OnlineStateEnter(FsmStateMachine *fsm)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        return;
    }
    connFsm = TO_CONN_FSM(fsm);
    bool isNodeInfoValid = (connFsm->connInfo.nodeInfo != NULL);
    char *anonyUdid = NULL;
    char *anonyNetworkId = NULL;
    Anonymize(connFsm->connInfo.peerNetworkId, &anonyNetworkId);
    if (isNodeInfoValid) {
        Anonymize(connFsm->connInfo.nodeInfo->deviceInfo.deviceUdid, &anonyUdid);
    }
    LNN_LOGI(LNN_BUILDER,
        "online state enter. id=%{public}u, networkId=%{public}s, udid=%{public}s, deviceName=%{public}s, "
        "peer%{public}s",
        connFsm->id, anonyNetworkId, isNodeInfoValid ? anonyUdid : "",
        isNodeInfoValid ? connFsm->connInfo.nodeInfo->deviceInfo.deviceName : "",
        LnnPrintConnectionAddr(&connFsm->connInfo.addr));
    AnonymizeFree(anonyUdid);
    AnonymizeFree(anonyNetworkId);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    CompleteJoinLNN(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_OK);
}

static void OnJoinLNNInOnline(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    LNN_LOGI(LNN_BUILDER, "request addr is already online. id=%{public}u", connFsm->id);
    NotifyJoinResult(connFsm, connInfo->peerNetworkId, SOFTBUS_OK);
}

static void LeaveLNNInOnline(LnnConnectionFsm *connFsm)
{
    LNN_LOGI(LNN_BUILDER, "transact to leaving state. id=%{public}u", connFsm->id);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    LnnFsmTransactState(&connFsm->fsm, g_states + STATE_LEAVING_INDEX);
}

static bool OnlineStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "online process message. id=%{public}u, msgType=%{public}d", connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            OnJoinLNNInOnline(connFsm);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
        case FSM_MSG_TYPE_NOT_TRUSTED:
        case FSM_MSG_TYPE_DISCONNECT:
            LeaveLNNInOnline(connFsm);
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static int32_t SyncBrOffline(const LnnConnectionFsm *connFsm)
{
    int16_t code;
    uint32_t combinedInt;
    char uuid[UUID_BUF_LEN];

    if (connFsm->connInfo.addr.type != CONNECTION_ADDR_BR) {
        LNN_LOGI(LNN_BUILDER, "just br need send offline");
        return SOFTBUS_ERR;
    }
    if (!((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_LEAVE_REQUEST) != 0)) {
        LNN_LOGI(LNN_BUILDER, "just leave lnn request need send offline");
        return SOFTBUS_ERR;
    }
    (void)LnnConvertDlId(connFsm->connInfo.peerNetworkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    code = LnnGetCnnCode(uuid, DISCOVERY_TYPE_BR);
    if (code == INVALID_CONNECTION_CODE_VALUE) {
        LNN_LOGE(LNN_BUILDER, "uuid not exist!");
        return SOFTBUS_INVALID_PARAM;
    }
    combinedInt = ((uint16_t)code << CONN_CODE_SHIFT) | ((uint16_t)DISCOVERY_TYPE_BR & DISCOVERY_TYPE_MASK);
    combinedInt = SoftBusHtoNl(combinedInt);
    LNN_LOGI(LNN_BUILDER, "GetOfflineMsg combinedInt=0x%{public}04x", combinedInt);
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_OFFLINE, connFsm->connInfo.peerNetworkId,
        (uint8_t *)&combinedInt, sizeof(int32_t), LnnSyncOfflineComplete) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "send sync offline fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void LeavingStateEnter(FsmStateMachine *fsm)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc;
    LnnConntionInfo *connInfo = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        return;
    }
    connFsm = TO_CONN_FSM(fsm);
    connInfo = &connFsm->connInfo;

    bool isNodeInfoValid = (connFsm->connInfo.nodeInfo != NULL);
    char *anonyUdid = NULL;
    char *anonyNetworkId = NULL;
    Anonymize(connFsm->connInfo.peerNetworkId, &anonyNetworkId);
    if (isNodeInfoValid) {
        Anonymize(connFsm->connInfo.nodeInfo->deviceInfo.deviceUdid, &anonyUdid);
    }
    LNN_LOGI(LNN_BUILDER,
        "leaving state enter. id=%{public}u, networkId=%{public}s, udid=%{public}s, deviceName=%{public}s, "
        "peer%{public}s",
        connFsm->id, anonyNetworkId, isNodeInfoValid ? anonyUdid : "",
        isNodeInfoValid ? connFsm->connInfo.nodeInfo->deviceInfo.deviceName : "",
        LnnPrintConnectionAddr(&connFsm->connInfo.addr));
    AnonymizeFree(anonyUdid);
    AnonymizeFree(anonyNetworkId);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    rc = SyncBrOffline(connFsm);
    if (rc == SOFTBUS_OK) {
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT,
            NULL, LEAVE_LNN_TIMEOUT_LEN);
    } else {
        CompleteLeaveLNN(connFsm, connInfo->peerNetworkId, SOFTBUS_OK);
    }
}

static bool LeavingStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "leaving process message. id=%{public}u, msgType=%{public}d", connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            NotifyJoinResult(connFsm, NULL, SOFTBUS_NETWORK_JOIN_LEAVING);
            break;
        case FSM_MSG_TYPE_SYNC_OFFLINE_DONE:
        case FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT:
            CompleteLeaveLNN(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_OK);
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static uint16_t GetNextConnectionFsmId(void)
{
    static uint16_t connFsmId = 0;
    return ++connFsmId;
}

static void ConnectionFsmDinitCallback(FsmStateMachine *fsm)
{
    LnnConnectionFsm *connFsm = NULL;

    LNN_LOGI(LNN_BUILDER, "connection fsm deinit callback enter");
    if (!CheckStateMsgCommonArgs(fsm)) {
        return;
    }
    connFsm = TO_CONN_FSM(fsm);
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connFsm is NULL!");
        return;
    }
    if (connFsm->stopCallback) {
        connFsm->stopCallback(connFsm);
    }
}

static int32_t InitConnectionStateMachine(LnnConnectionFsm *connFsm)
{
    int32_t i;

    if (sprintf_s(connFsm->fsmName, LNN_CONNECTION_FSM_NAME_LEN, "LnnConnFsm-%u", connFsm->id) == -1) {
        LNN_LOGE(LNN_BUILDER, "format lnn connection fsm name failed");
        return SOFTBUS_ERR;
    }
    if (LnnFsmInit(&connFsm->fsm, NULL, connFsm->fsmName, ConnectionFsmDinitCallback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "init fsm failed");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < STATE_NUM_MAX; ++i) {
        LnnFsmAddState(&connFsm->fsm, &g_states[i]);
    }
    return SOFTBUS_OK;
}

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target, const char *pkgName,
    bool isNeedConnect)
{
    LnnConnectionFsm *connFsm = NULL;

    if (target == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection target is null");
        return NULL;
    }
    connFsm = (LnnConnectionFsm *)SoftBusCalloc(sizeof(LnnConnectionFsm));
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc for connection fsm failed");
        return NULL;
    }
    ListInit(&connFsm->node);
    connFsm->id = GetNextConnectionFsmId();
    if (InitConnectionStateMachine(connFsm) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "init connecton fsm failed");
        SoftBusFree(connFsm);
        return NULL;
    }
    connFsm->connInfo.addr = *target;
    if (pkgName != NULL) {
        if (strcpy_s(connFsm->pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
            LNN_LOGE(LNN_BUILDER, "copy pkgName fail");
            SoftBusFree(connFsm);
            return NULL;
        }
    }
    connFsm->isNeedConnect = isNeedConnect;
    LNN_LOGI(LNN_BUILDER, "create a new connection fsm. id=%{public}u, peerAddr=%{public}s, needConnect=%{public}d",
        connFsm->id, LnnPrintConnectionAddr(target), isNeedConnect);
    return connFsm;
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        return;
    }
    LNN_LOGI(LNN_BUILDER, "destroy a connection fsm. id=%{public}u", connFsm->id);
    if (connFsm->connInfo.cleanInfo != NULL) {
        SoftBusFree(connFsm->connInfo.cleanInfo);
    }
    if (connFsm->connInfo.nodeInfo != NULL) {
        SoftBusFree(connFsm->connInfo.nodeInfo);
    }
    SoftBusFree(connFsm);
}

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnFsmStart(&connFsm->fsm, g_states + STATE_AUTH_INDEX) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start connection fsm failed. id=%{public}u", connFsm->id);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_BUILDER, "connection fsm is starting. id=%{public}u", connFsm->id);
    return SOFTBUS_OK;
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    if (connFsm == NULL || callback == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm or stop callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm->stopCallback = callback;
    if (LnnFsmStop(&connFsm->fsm) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "stop connection fsm failed. id=%{public}u", connFsm->id);
        return SOFTBUS_ERR;
    }
    return LnnFsmDeinit(&connFsm->fsm);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_INVALID_PARAM;
    }
    SetWatchdogFlag(false);
    if ((connFsm->connInfo.addr.type == CONNECTION_ADDR_BLE || connFsm->connInfo.addr.type == CONNECTION_ADDR_BR) &&
        SoftBusGetBtState() != BLE_ENABLE) {
        LNN_LOGE(LNN_BUILDER, "send join request while bt is turn off");
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, NULL);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode)
{
    int32_t *para = NULL;

    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_INVALID_PARAM;
    }
    para = (int32_t *)SoftBusMalloc(sizeof(int32_t));
    if (para == NULL) {
        LNN_LOGE(LNN_BUILDER, "malloc auth result msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = retCode;
    if (LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "post auth result message to connFsm fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_NOT_TRUSTED, NULL);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_DISCONNECT, NULL);
}

int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN, NULL);
}

int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_SYNC_OFFLINE_DONE, NULL);
}

int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_INITIATE_ONLINE, NULL);
}

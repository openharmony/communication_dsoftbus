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
#include "lnn_connId_callback_manager.h"
#include "lnn_decision_db.h"
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

#define DATA_SIZE 32
#define DISCOVERY_TYPE_MASK 0x7FFF
#define REASON_OVERFLOW_MAX 255
#define PEER_DEVICE_STATE_VERSION_CHANGE 8
#define BLE_CONNECT_ONLINE_REASON 16

typedef enum {
    STATE_AUTH_INDEX = 0,
    STATE_CLEAN_INVALID_CONN_INDEX,
    STATE_ONLINE_INDEX,
    STATE_LEAVING_INDEX,
    STATE_NUM_MAX,
} ConnFsmStateIndex;

typedef enum {
    ONLINE_TYPE_INVALID = 1,
    ONLINE_TYPE_WIFI = 2,
    ONLINE_TYPE_BLE = 3,
    ONLINE_TYPE_BLE_THREE_STATE = 4,
    ONLINE_TYPE_BR = 5,
} OnlineType;

#define JOIN_LNN_TIMEOUT_LEN  (15 * 1000UL)
#define LEAVE_LNN_TIMEOUT_LEN (5 * 1000UL)

#define TO_CONN_FSM(ptr) CONTAINER_OF(ptr, LnnConnectionFsm, fsm)

#define CONN_CODE_SHIFT 16
#define PC_DEV_TYPE "00C"

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

typedef struct {
    char localUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];
    char peerUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];
    char localDeviceType[DEVICE_TYPE_SIZE_LEN + 1];
    char peerDeviceType[DEVICE_TYPE_SIZE_LEN + 1];
    char netWorkId[NETWORK_ID_BUF_LEN];
    char udidData[UDID_BUF_LEN];
    char bleMacAddr[MAC_LEN];
} LnnDfxReportConnectInfo;

static LnnTriggerInfo g_lnnTriggerInfo = { 0 };
static SoftBusMutex g_lnnTriggerInfoMutex;
static bool g_lnnTriggerInfoIsInit = false;

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool CleanInvalidConnStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void OnlineStateEnter(FsmStateMachine *fsm);
static bool OnlineStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static void LeavingStateEnter(FsmStateMachine *fsm);
static bool LeavingStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool IsBasicNodeInfoChanged(const NodeInfo *oldNodeInfo, const NodeInfo *newNodeInfo, bool isUpdate);

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

static bool LnnTriggerInfoInit(void)
{
    if (SoftBusMutexInit(&g_lnnTriggerInfoMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "lnnTriggerInfo mutex init fail");
        return false;
    }
    g_lnnTriggerInfoIsInit = true;
    return true;
}

static void SetLnnTriggerInfoDeviceCntIncrease(void)
{
    if (!g_lnnTriggerInfoIsInit) {
        LNN_LOGE(LNN_BUILDER, "lnnTriggerInfo is not init");
        return;
    }
    if (SoftBusMutexLock(&g_lnnTriggerInfoMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    g_lnnTriggerInfo.deviceCnt++;
    (void)SoftBusMutexUnlock(&g_lnnTriggerInfoMutex);
}

void SetLnnTriggerInfo(uint64_t triggerTime, int32_t deviceCnt, int32_t triggerReason)
{
    if (!g_lnnTriggerInfoIsInit && !LnnTriggerInfoInit()) {
        LNN_LOGE(LNN_BUILDER, "lnnTriggerInfo is not init");
        return;
    }
    if (SoftBusMutexLock(&g_lnnTriggerInfoMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    g_lnnTriggerInfo.triggerTime = triggerTime;
    g_lnnTriggerInfo.deviceCnt = deviceCnt;
    g_lnnTriggerInfo.triggerReason = triggerReason;
    (void)SoftBusMutexUnlock(&g_lnnTriggerInfoMutex);
}

void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo)
{
    if (triggerInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    if (!g_lnnTriggerInfoIsInit) {
        LNN_LOGE(LNN_BUILDER, "lnnTriggerInfo is not init");
        return;
    }
    if (SoftBusMutexLock(&g_lnnTriggerInfoMutex) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "SoftBusMutexLock fail");
        return;
    }
    triggerInfo->triggerTime = g_lnnTriggerInfo.triggerTime;
    triggerInfo->deviceCnt = g_lnnTriggerInfo.deviceCnt;
    triggerInfo->triggerReason = g_lnnTriggerInfo.triggerReason;
    (void)SoftBusMutexUnlock(&g_lnnTriggerInfoMutex);
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    uint64_t timeStamp = 0;
    LnnEventExtra extra = {0};
    (void)LnnEventExtraInit(&extra);
    timeStamp = SoftBusGetSysTimeMs();
    extra.triggerReason = reason;
    extra.interval = BROADCAST_INTERVAL_DEFAULT;
    LnnTriggerInfo triggerInfo = {0};
    GetLnnTriggerInfo(&triggerInfo);
    if (triggerInfo.triggerTime == 0 || (SoftBusGetSysTimeMs() - triggerInfo.triggerTime) > MAX_TIME_LATENCY) {
        SetLnnTriggerInfo(timeStamp, 1, extra.triggerReason);
    }
    LNN_EVENT(EVENT_SCENE_LNN, stage, extra);
    LNN_LOGI(LNN_HEART_BEAT, "triggerTime=%{public}" PRId64 ", triggerReason=%{public}d, deviceCnt=1",
        timeStamp, extra.triggerReason);
}

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
        LNN_LOGE(LNN_BUILDER, "connection fsm is already dead. [id=%{public}u]", connFsm->id);
        return false;
    }
    return true;
}

static void NotifyJoinResult(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    if ((connInfo->flag & LNN_CONN_INFO_FLAG_JOIN_REQUEST) != 0) {
        LnnNotifyJoinResult(&connInfo->addr, networkId, retCode);
        connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_ACTIVE;
        return;
    }
    NodeInfo *nodeInfo = connInfo->nodeInfo;
    if (retCode == SOFTBUS_OK && nodeInfo != NULL) {
        if (connInfo->addr.type == CONNECTION_ADDR_WLAN &&
            connInfo->addr.info.ip.port != nodeInfo->connectInfo.authPort) {
            LNN_LOGI(LNN_BUILDER, "before port =%{public}d, after port=%{public}d",
                connInfo->addr.info.ip.port, nodeInfo->connectInfo.authPort);
            connInfo->addr.info.ip.port = nodeInfo->connectInfo.authPort;
        }
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
    LNN_LOGD(LNN_BUILDER, "report lnn result evt enter");
    SoftBusLinkType linkType = ConvertAddrTypeToHisysEvtLinkType(connFsm->connInfo.addr.type);
    if (linkType == SOFTBUS_HISYSEVT_LINK_TYPE_BUTT) {
        return;
    }
    if (retCode == SOFTBUS_OK) {
        connFsm->statisticData.beginOnlineTime = LnnUpTimeMs();
        if (connFsm->statisticData.beginOnlineTime < connFsm->statisticData.beginJoinLnnTime) {
            LNN_LOGE(LNN_BUILDER, "report static lnn duration fail");
            return;
        }
        uint64_t constTime =
            (uint64_t)(connFsm->statisticData.beginOnlineTime - connFsm->statisticData.beginJoinLnnTime);
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
    LpDeviceStateInfo *info = (LpDeviceStateInfo *)SoftBusCalloc(sizeof(LpDeviceStateInfo));
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "calloc info fail");
        return;
    }
    if (strcpy_s(info->udid, UDID_BUF_LEN, udid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s outUdid fail");
        SoftBusFree(info);
        return;
    }
    info->isOnline = isOnline;
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (LnnAsyncCallbackDelayHelper(looper, SendDeviceStateToMlps, (void *)info, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "async call online process fail");
        SoftBusFree(info);
    }
}

static void NotifyUserChange(bool isChange, NodeInfo *oldInfo, NodeInfo *newInfo)
{
    uint8_t defaultUserIdCheckSum[USERID_CHECKSUM_LEN] = {0};
    if (memcmp(newInfo->userIdCheckSum, defaultUserIdCheckSum, USERID_CHECKSUM_LEN) == 0) {
        return;
    }
    if (isChange || memcmp(oldInfo->userIdCheckSum, newInfo->userIdCheckSum, USERID_CHECKSUM_LEN) != 0) {
        isChange = true;
    } else {
        isChange = false;
    }
    NotifyForegroundUseridChange(newInfo->networkId, newInfo->discoveryType, isChange);
}

static void SetLnnConnNodeInfo(
    LnnConntionInfo *connInfo, const char *networkId, LnnConnectionFsm *connFsm, int32_t retCode)
{
    ReportCategory report;
    uint64_t localFeature;
    (void)LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature);
    uint8_t relation[CONNECTION_ADDR_MAX] = { 0 };
    NodeInfo oldInfo;
    (void)memset_s(&oldInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnRetrieveDeviceInfoByNetworkId(networkId, &oldInfo);
    if (!connFsm->isNeedConnect && connInfo->addr.type == CONNECTION_ADDR_BLE) {
        connInfo->nodeInfo->isSupportSv = true;
    }
    report = LnnAddOnlineNode(connInfo->nodeInfo);
    LnnOfflineTimingByHeartbeat(networkId, connInfo->addr.type);
    if (LnnInsertLinkFinderInfo(networkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "insert rpa info fail.");
    }
    if (LnnUpdateGroupType(connInfo->nodeInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "update grouptype fail");
    }
    LNN_LOGI(LNN_BUILDER, "peer feature=%{public}" PRIu64 ", local=%{public}" PRIu64 "",
        connInfo->nodeInfo->feature, localFeature);
    if (IsFeatureSupport(connInfo->nodeInfo->feature, BIT_BLE_SUPPORT_LP_HEARTBEAT) &&
        IsFeatureSupport(localFeature, BIT_BLE_SUPPORT_LP_HEARTBEAT)) {
        DeviceStateChangeProcess(connInfo->nodeInfo->deviceInfo.deviceUdid, connInfo->addr.type, true);
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), SetLpKeepAliveState, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "async call online process fail");
    }
    NotifyJoinResult(connFsm, networkId, retCode);
    ReportResult(connInfo->nodeInfo->deviceInfo.deviceUdid, report);
    if (report == REPORT_ONLINE) {
        NotifyUserChange(ret != SOFTBUS_OK, &oldInfo, connInfo->nodeInfo);
    }
    connInfo->flag |= LNN_CONN_INFO_FLAG_ONLINE;
    LnnNotifyNodeStateChanged(&connInfo->addr);
    LnnGetLnnRelation(networkId, CATEGORY_NETWORK_ID, relation, CONNECTION_ADDR_MAX);
    LnnNotifyLnnRelationChanged(
        connInfo->nodeInfo->deviceInfo.deviceUdid, connInfo->addr.type, relation[connInfo->addr.type], true);
    LnnNotifyOnlineNetType(networkId, connInfo->addr.type);
}

static int32_t DfxRecordLnnOnlineType(const NodeInfo *info)
{
    if (info == NULL) {
        return ONLINE_TYPE_INVALID;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_WIFI)) {
        return ONLINE_TYPE_WIFI;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BR)) {
        return ONLINE_TYPE_BR;
    }
    if (LnnHasDiscoveryType(info, DISCOVERY_TYPE_BLE)) {
        uint32_t local;
        if (LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &local) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get cap fail");
            return ONLINE_TYPE_INVALID;
        }
        if (((local & (1 << BIT_BR)) == 0) || (info->netCapacity & (1 << BIT_BR)) == 0) {
            return ONLINE_TYPE_BLE_THREE_STATE;
        } else {
            return ONLINE_TYPE_BLE;
        }
    }
    return ONLINE_TYPE_INVALID;
}

static void GetLnnOnlineType(bool isNeedConnect, ConnectionAddrType type, int32_t *lnnType)
{
    if (!isNeedConnect && type == CONNECTION_ADDR_BLE) {
        *lnnType = LNN_TYPE_BLE_BROADCAST_ONLINE;
    } else if (isNeedConnect && type == CONNECTION_ADDR_BLE) {
        *lnnType = LNN_TYPE_BLE_CONNECT_ONLINE;
    } else if (type == CONNECTION_ADDR_WLAN || type == CONNECTION_ADDR_ETH) {
        *lnnType = LNN_TYPE_WIFI_CONNECT_ONLINE;
    } else if (type == CONNECTION_ADDR_BR) {
        *lnnType = LNN_TYPE_BR_CONNECT_ONLINE;
    } else {
        *lnnType = LNN_TYPE_OTHER_CONNECT_ONLINE;
    }
}

static bool IsEmptyShortHashStr(char *udidHash)
{
    if (strlen(udidHash) == 0) {
        LNN_LOGI(LNN_BUILDER, "udidhash len is 0");
        return true;
    }
    uint8_t emptyHash[HB_SHORT_UDID_HASH_LEN] = { 0 };
    char emptyHashStr[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    if (ConvertBytesToHexString(emptyHashStr, HB_SHORT_UDID_HASH_HEX_LEN + 1, emptyHash, HB_SHORT_UDID_HASH_LEN)
        != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert bytes to string fail");
        return false;
    }
    if (strncmp(emptyHashStr, udidHash, strlen(emptyHashStr)) == 0) {
        LNN_LOGI(LNN_BUILDER, "udidhash is empty");
        return true;
    }
    return false;
}

static int32_t GetUdidHashForDfx(char *localUdidHash, char *peerUdidHash, LnnConntionInfo *connInfo)
{
    int32_t rc = SOFTBUS_OK;
    const NodeInfo *localInfo = LnnGetLocalNodeInfo();
    if (localInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "localInfo is NULL");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    uint8_t hash[UDID_HASH_LEN] = { 0 };
    rc = SoftBusGenerateStrHash((uint8_t *)localInfo->deviceInfo.deviceUdid, strlen(localInfo->deviceInfo.deviceUdid),
        hash);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate udidhash fail");
        return rc;
    }
    rc = ConvertBytesToHexString(localUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, hash, HB_SHORT_UDID_HASH_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert bytes to string fail");
        return rc;
    }
    if (connInfo->addr.type == CONNECTION_ADDR_WLAN) {
        if (strncpy_s(peerUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, (char *)connInfo->addr.info.ip.udidHash,
            HB_SHORT_UDID_HASH_HEX_LEN) != EOK) {
            LNN_LOGE(LNN_BUILDER, "strcpy_s wifi udidhash fail");
            return SOFTBUS_STRCPY_ERR;
        }
    } else if (connInfo->addr.type == CONNECTION_ADDR_BLE) {
        rc = ConvertBytesToHexString(peerUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1,
            (const unsigned char *)connInfo->addr.info.ble.udidHash, HB_SHORT_UDID_HASH_LEN);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get ble udidhash fail");
            return rc;
        }
    }
    return SOFTBUS_OK;
}

static int32_t GetPeerUdidHash(NodeInfo *nodeInfo, char *peerUdidHash)
{
    if (nodeInfo == NULL || peerUdidHash == NULL) {
        LNN_LOGE(LNN_BUILDER, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc = SOFTBUS_OK;
    uint8_t hash[UDID_HASH_LEN] = { 0 };
    rc = SoftBusGenerateStrHash((uint8_t *)nodeInfo->deviceInfo.deviceUdid,
        strlen(nodeInfo->deviceInfo.deviceUdid), hash);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate udidhash fail");
        return rc;
    }
    rc = ConvertBytesToHexString(peerUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, hash, HB_SHORT_UDID_HASH_LEN);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert bytes to string fail");
        return rc;
    }
    return SOFTBUS_OK;
}

static int32_t GetDevTypeForDfx(char *localDeviceType, char *peerDeviceType, LnnConntionInfo *connInfo)
{
    NodeInfo localInfo;
    (void)memset_s(&localInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetLocalNodeInfoSafe(&localInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local device info fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (snprintf_s(localDeviceType, DEVICE_TYPE_SIZE_LEN + 1, DEVICE_TYPE_SIZE_LEN, "%03X",
        localInfo.deviceInfo.deviceTypeId) < 0) {
        LNN_LOGE(LNN_BUILDER, "snprintf_s localDeviceType fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    if (connInfo->nodeInfo == NULL) {
        if (snprintf_s(peerDeviceType, DEVICE_TYPE_SIZE_LEN + 1, DEVICE_TYPE_SIZE_LEN, "%03X",
            (uint16_t)connInfo->infoReport.type) < 0) {
            LNN_LOGE(LNN_BUILDER, "snprintf_s peerDeviceType by infoReport fail");
            return SOFTBUS_SPRINTF_ERR;
        }
    } else {
        if (snprintf_s(peerDeviceType, DEVICE_TYPE_SIZE_LEN + 1, DEVICE_TYPE_SIZE_LEN, "%03X",
            connInfo->nodeInfo->deviceInfo.deviceTypeId) < 0) {
            LNN_LOGE(LNN_BUILDER, "snprintf_s peerDeviceType fail");
            return SOFTBUS_SPRINTF_ERR;
        }
    }
    LNN_LOGI(LNN_BUILDER, "localDeviceType=%{public}s, peerDeviceType=%{public}s", localDeviceType, peerDeviceType);
    return SOFTBUS_OK;
}

static int32_t GetPeerUdidInfo(NodeInfo *nodeInfo, char *udidData, char *peerUdidHash)
{
    int32_t rc = SOFTBUS_OK;
    if (strcpy_s(udidData, UDID_BUF_LEN, nodeInfo->deviceInfo.deviceUdid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s udidData fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (IsEmptyShortHashStr(peerUdidHash) || strlen(peerUdidHash) != HB_SHORT_UDID_HASH_HEX_LEN) {
        rc = GetPeerUdidHash(nodeInfo, peerUdidHash);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get udidhash fail");
            return rc;
        }
    }
    return SOFTBUS_OK;
}

static void SetOnlineType(int32_t reason, NodeInfo *nodeInfo, LnnEventExtra extra)
{
    if (reason == SOFTBUS_OK) {
        extra.onlineType = DfxRecordLnnOnlineType(nodeInfo);
    } else {
        extra.onlineType = ONLINE_TYPE_INVALID;
    }
}

static int32_t FillDeviceBleReportExtra(const LnnEventExtra *extra, LnnBleReportExtra *bleExtra)
{
    if (extra == NULL || bleExtra == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    bleExtra->extra.onlineType = extra->onlineType;
    if (strcpy_s(bleExtra->extra.peerNetworkId, NETWORK_ID_BUF_LEN, extra->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s peerNetworkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(bleExtra->extra.peerUdid, UDID_BUF_LEN, extra->peerUdid) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s peerUdid fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(bleExtra->extra.peerUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, extra->peerUdidHash) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s peerUdidHash fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(bleExtra->extra.peerBleMac, BT_MAC_LEN, extra->peerBleMac) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s peerBleMac fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static void DfxAddBleReportExtra(
    const LnnConntionInfo *connInfo, const LnnEventExtra *extra, LnnBleReportExtra *bleExtra)
{
    if (connInfo == NULL || extra == NULL || bleExtra == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param");
        return;
    }
    bleExtra->extra.onlineNum = extra->onlineNum;
    bleExtra->extra.errcode = extra->errcode;
    bleExtra->extra.lnnType = extra->lnnType;
    bleExtra->extra.result = extra->result;
    bleExtra->extra.osType = extra->osType;
    bleExtra->extra.connOnlineReason = extra->connOnlineReason;
    if (strcpy_s(bleExtra->extra.localUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, extra->localUdidHash) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s localUdidHash fail");
        return;
    }
    if (strcpy_s(bleExtra->extra.peerUdidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1, extra->peerUdidHash) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s peerUdidHash fail");
        return;
    }
    if (strcpy_s(bleExtra->extra.localDeviceType, DEVICE_TYPE_SIZE_LEN + 1, extra->localDeviceType) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s localDeviceType fail");
        return;
    }
    if (strcpy_s(bleExtra->extra.peerDeviceType, DEVICE_TYPE_SIZE_LEN + 1, extra->peerDeviceType) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s peerDeviceType fail");
        return;
    }
    if (extra->errcode == SOFTBUS_AUTH_HICHAIN_NO_CANDIDATE_GROUP &&
        (strncmp(extra->peerDeviceType, PC_DEV_TYPE, strlen(PC_DEV_TYPE)) == 0)) {
        LnnBlePcRestrictMapInit();
        uint32_t count = 0;
        if (GetNodeFromPcRestrictMap(extra->peerUdidHash, &count) == SOFTBUS_OK) {
            UpdateNodeFromPcRestrictMap(extra->peerUdidHash);
        } else {
            AddNodeToPcRestrictMap(extra->peerUdidHash);
        }
    }
    if (connInfo->nodeInfo == NULL) {
        bleExtra->status = BLE_REPORT_EVENT_FAIL;
        AddNodeToLnnBleReportExtraMap(bleExtra->extra.peerUdidHash, bleExtra);
        return;
    }
    if (FillDeviceBleReportExtra(extra, bleExtra) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "FillDeviceBleReportExtra fail");
        return;
    }
    bleExtra->status = BLE_REPORT_EVENT_FAIL;
    AddNodeToLnnBleReportExtraMap(bleExtra->extra.peerUdidHash, bleExtra);
}

static void DfxReportOnlineEvent(LnnConntionInfo *connInfo, int32_t reason, LnnEventExtra extra)
{
    if (connInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "connInfo is NULL");
        return;
    }
    uint64_t timeStamp = 0;
    LnnTriggerInfo triggerInfo = { 0 };
    GetLnnTriggerInfo(&triggerInfo);
    int32_t osType = connInfo->infoReport.osType;
    LNN_LOGI(LNN_BUILDER, "osType=%{public}d, extra.osType=%{public}d", osType, extra.osType);
    if (connInfo->addr.type == CONNECTION_ADDR_BLE) {
        LnnBleReportExtra bleExtra;
        (void)memset_s(&bleExtra, sizeof(LnnBleReportExtra), 0, sizeof(LnnBleReportExtra));
        if (IsExistLnnDfxNodeByUdidHash(extra.peerUdidHash, &bleExtra)) {
            if (reason != SOFTBUS_OK) {
                extra.osType = osType;
                DfxAddBleReportExtra(connInfo, &extra, &bleExtra);
                return;
            }
            if ((SoftBusGetSysTimeMs() - triggerInfo.triggerTime) < MAX_TIME_LATENCY) {
                timeStamp = SoftBusGetSysTimeMs();
                extra.timeLatency = timeStamp - triggerInfo.triggerTime;
                extra.onlineDevCnt = triggerInfo.deviceCnt;
                extra.triggerReason = triggerInfo.triggerReason;
                LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, extra);
                SetLnnTriggerInfoDeviceCntIncrease();
            } else {
                LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, extra);
            }
            bleExtra.status = BLE_REPORT_EVENT_SUCCESS;
            AddNodeToLnnBleReportExtraMap(extra.peerUdidHash, &bleExtra);
        }
        return;
    }
    if (reason == SOFTBUS_OK && (SoftBusGetSysTimeMs() - triggerInfo.triggerTime) < MAX_TIME_LATENCY) {
        timeStamp = SoftBusGetSysTimeMs();
        extra.timeLatency = timeStamp - triggerInfo.triggerTime;
        extra.onlineDevCnt = triggerInfo.deviceCnt;
        extra.triggerReason = triggerInfo.triggerReason;
        SetLnnTriggerInfoDeviceCntIncrease();
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_JOIN_LNN_END, extra);
}

static int32_t GetPeerConnInfo(const LnnConntionInfo *connInfo, char *netWorkId, char *bleMacAddr)
{
    if (strcpy_s(netWorkId, NETWORK_ID_BUF_LEN, connInfo->nodeInfo->networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s netWorkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(bleMacAddr, MAC_LEN, connInfo->nodeInfo->connectInfo.bleMacAddr) != EOK) {
        LNN_LOGE(LNN_BUILDER, "strcpy_s bleMacAddr fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static void GetConnectOnlineReason(LnnConntionInfo *connInfo, uint32_t *connOnlineReason, int32_t reason)
{
    uint8_t connectReason = 0;
    uint8_t localReason = 0;
    uint8_t peerReason = 0;

    NodeInfo localInfo;
    (void)memset_s(&localInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetLocalNodeInfoSafe(&localInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local device info fail");
        return;
    }
    if ((uint32_t)connInfo->infoReport.bleConnectReason > REASON_OVERFLOW_MAX ||
        localInfo.stateVersionReason > REASON_OVERFLOW_MAX ||
        (connInfo->nodeInfo != NULL && connInfo->nodeInfo->stateVersionReason > REASON_OVERFLOW_MAX)) {
        LNN_LOGE(LNN_BUILDER, "reason convert will overflow");
        return;
    }
    connectReason = (uint8_t)connInfo->infoReport.bleConnectReason;
    localReason = (uint8_t)localInfo.stateVersionReason;
    if (connInfo->nodeInfo == NULL) {
        peerReason = 0;
    } else {
        peerReason = (uint8_t)connInfo->nodeInfo->stateVersionReason;
    }

    *connOnlineReason =
        ((connectReason << BLE_CONNECT_ONLINE_REASON) | (peerReason << PEER_DEVICE_STATE_VERSION_CHANGE) | localReason);
    LNN_LOGI(LNN_BUILDER,
        "connOnlineReason=%{public}u, connectReason=%{public}hhu, peerReason=%{public}hhu, localReason=%{public}hhu",
        *connOnlineReason, connectReason, peerReason, localReason);
}

static void NotifyProofExceptionEvent(DeviceType type, int32_t reason, const char *peerDeviceType)
{
    if ((reason == SOFTBUS_AUTH_HICHAIN_NO_CANDIDATE_GROUP || reason == SOFTBUS_AUTH_HICHAIN_PROOF_MISMATCH ||
            reason == PC_PROOF_NON_CONSISTENT_ERRCODE) &&
        (strncmp(peerDeviceType, PC_DEV_TYPE, strlen(PC_DEV_TYPE)) == 0)) {
        LnnNotifyHichainProofException(NULL, 0, (uint16_t)type, reason);
        LNN_LOGE(LNN_BUILDER, "notify hichain proof exception event, reason=%{public}d, type=%{public}hu", reason,
            (uint16_t)type);
    }
}

static void DfxRecordLnnAddOnlineNodeEnd(LnnConntionInfo *connInfo, int32_t onlineNum, int32_t lnnType, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.onlineNum = onlineNum;
    extra.errcode = reason;
    extra.lnnType = lnnType;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    LnnDfxReportConnectInfo dfxConnectInfo = {};
    uint32_t connOnlineReason = 0;
    if (GetUdidHashForDfx(dfxConnectInfo.localUdidHash, dfxConnectInfo.peerUdidHash, connInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get udidhash fail");
        return;
    }
    if (GetDevTypeForDfx(dfxConnectInfo.localDeviceType, dfxConnectInfo.peerDeviceType, connInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get device type fail");
        return;
    }
    if (connInfo->addr.type == CONNECTION_ADDR_BLE) {
        (void)GetConnectOnlineReason(connInfo, &connOnlineReason, reason);
    }
    extra.localUdidHash = dfxConnectInfo.localUdidHash;
    extra.peerUdidHash = dfxConnectInfo.peerUdidHash;
    extra.localDeviceType = dfxConnectInfo.localDeviceType;
    extra.peerDeviceType = dfxConnectInfo.peerDeviceType;
    extra.connOnlineReason = connOnlineReason;
    NotifyProofExceptionEvent(connInfo->infoReport.type, reason, extra.peerDeviceType);
    if (connInfo->nodeInfo == NULL) {
        DfxReportOnlineEvent(connInfo, reason, extra);
        return;
    }
    SetOnlineType(reason, connInfo->nodeInfo, extra);
    if (GetPeerUdidInfo(connInfo->nodeInfo, dfxConnectInfo.udidData, dfxConnectInfo.peerUdidHash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get peer udid fail");
        return;
    }
    if (GetPeerConnInfo(connInfo, dfxConnectInfo.netWorkId, dfxConnectInfo.bleMacAddr) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get peer connInfo fail");
        return;
    }
    if (connInfo->addr.type == CONNECTION_ADDR_BLE) {
        extra.osType = connInfo->nodeInfo->deviceInfo.osType;
    }
    extra.peerNetworkId = dfxConnectInfo.netWorkId;
    extra.peerUdid = dfxConnectInfo.udidData;
    extra.peerUdidHash = dfxConnectInfo.peerUdidHash;
    extra.peerBleMac = dfxConnectInfo.bleMacAddr;
    DfxReportOnlineEvent(connInfo, reason, extra);
}

static void DeletePcRestrictNode(int32_t retCode, NodeInfo *nodeInfo)
{
    char peerUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    uint32_t count = 0;
    if (retCode == SOFTBUS_OK && GetPeerUdidHash(nodeInfo, peerUdidHash) == SOFTBUS_OK) {
        if (GetNodeFromPcRestrictMap(peerUdidHash, &count) == SOFTBUS_OK) {
            DeleteNodeFromPcRestrictMap(peerUdidHash);
        }
    }
}

static void NotifyJoinExtResultProcess(LnnConnectionFsm *connFsm, int32_t retCode)
{
    if (!connFsm->isSession) {
        return;
    }
    if (connFsm->connInfo.nodeInfo != NULL) {
        LnnNotifyStateForSession(connFsm->connInfo.nodeInfo->deviceInfo.deviceUdid, retCode);
        return;
    }
    NotifyStateForSession(&connFsm->connInfo.addr);
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
        connFsm->isDead = true;
        LnnNotifyAuthHandleLeaveLNN(connInfo->authHandle);
    }
    NotifyJoinExtResultProcess(connFsm, retCode);

    int32_t infoNum = 0;
    int32_t lnnType = 0;
    NodeBasicInfo *info = NULL;
    bool isSuccessFlag = true;
    GetLnnOnlineType(connFsm->isNeedConnect, connInfo->addr.type, &lnnType);
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "Lnn get online node fail");
        isSuccessFlag = false;
    }
    if ((connInfo->flag & LNN_CONN_INFO_FLAG_JOIN_REQUEST) == 0 && lnnType == LNN_TYPE_BR_CONNECT_ONLINE) {
        isSuccessFlag = false;
        SoftBusFree(info);
    }
    if (isSuccessFlag) {
        DfxRecordLnnAddOnlineNodeEnd(connInfo, infoNum, lnnType, retCode);
        SoftBusFree(info);
    }
    DeletePcRestrictNode(retCode, connInfo->nodeInfo);
    if (connInfo->nodeInfo != NULL) {
        SoftBusFree(connInfo->nodeInfo);
        connInfo->nodeInfo = NULL;
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    if (retCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "join failed, ready clean, [id=%{public}u], retCode=%{public}d", connFsm->id, retCode);
        LnnRequestCleanConnFsm(connFsm->id);
        return;
    }
    LNN_LOGI(LNN_BUILDER, "complete join LNN done. [id=%{public}u]", connFsm->id);
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
    report = LnnSetNodeOffline(udid, connInfo->addr.type, (int32_t)connInfo->authHandle.authId);
    LnnGetLnnRelation(udid, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    LnnNotifyLnnRelationChanged(udid, connInfo->addr.type, relation[connInfo->addr.type], false);
    if (LnnGetBasicInfoByUdid(udid, basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get basic info fail. [id=%{public}u]", connFsm->id);
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
            LNN_LOGE(LNN_BUILDER, "remove node. [id=%{public}u]", connFsm->id);
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
        if (connFsm->statisticData.offLineTime < connFsm->statisticData.beginOnlineTime) {
            LNN_LOGE(LNN_BUILDER, "report static device online duration fail");
            return;
        }
        uint64_t constTime = (uint64_t)(connFsm->statisticData.offLineTime - connFsm->statisticData.beginOnlineTime);
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
        LnnStopOfflineTimingByHeartbeat(networkId, connInfo->addr.type);
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
    LnnNotifyAuthHandleLeaveLNN(connInfo->authHandle);
    LnnRequestCleanConnFsm(connFsm->id);
    LNN_LOGI(LNN_BUILDER, "complete leave lnn, ready clean. [id=%{public}u]", connFsm->id);
}

static int32_t OnJoinFail(LnnConnectionFsm *connFsm, int32_t retCode)
{
    if (CheckDeadFlag(connFsm, true)) {
        return SOFTBUS_NETWORK_CONN_FSM_DEAD;
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
    NotifyJoinExtResultProcess(connFsm, SOFTBUS_NETWORK_JOIN_CANCELED);
}

static void FilterRetrieveDeviceInfo(NodeInfo *info)
{
    info->authChannelId[CONNECTION_ADDR_BLE][AUTH_AS_CLIENT_SIDE] = 0;
    info->authChannelId[CONNECTION_ADDR_BLE][AUTH_AS_SERVER_SIDE] = 0;
    info->AuthTypeValue = 0;
}

static int32_t LnnRecoveryBroadcastKey()
{
    int32_t ret = LnnLoadLocalBroadcastCipherKey();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "load BroadcastCipherInfo fail");
        return ret;
    }
    BroadcastCipherKey broadcastKey;
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    do {
        ret = LnnGetLocalBroadcastCipherKey(&broadcastKey);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "get local info failed");
            break;
        }
        ret = LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_KEY, broadcastKey.cipherInfo.key, SESSION_KEY_LENGTH);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set key failed");
            break;
        }
        ret = LnnSetLocalByteInfo(BYTE_KEY_BROADCAST_CIPHER_IV, broadcastKey.cipherInfo.iv, BROADCAST_IV_LEN);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "set iv failed");
            break;
        }
        LNN_LOGI(LNN_BUILDER, "recovery broadcastKey success!");
        ret = SOFTBUS_OK;
    } while (0);
    (void)memset_s(&broadcastKey, sizeof(BroadcastCipherKey), 0, sizeof(BroadcastCipherKey));
    LNN_LOGI(LNN_BUILDER, "recovery broadcastKey success!");
    return ret;
}

static void DfxRecordConnAuthStart(const AuthConnInfo *connInfo, LnnConnectionFsm *connFsm, uint32_t requestId)
{
    LnnEventExtra extra = { 0 };
    LnnEventExtraInit(&extra);
    extra.authRequestId = (int32_t)requestId;

    if (connInfo != NULL) {
        extra.authLinkType = connInfo->type;
    }
    if (connFsm != NULL && IsValidString(connFsm->pkgName, PKG_NAME_SIZE_MAX - 1)) {
        extra.callerPkg = connFsm->pkgName;
    }
    LNN_EVENT(EVENT_SCENE_JOIN_LNN, EVENT_STAGE_AUTH, extra);
}

static int32_t BleDirectOnline(LnnConntionInfo *connInfo, AuthConnInfo *authConn, NodeInfo *deviceInfo, bool dupOk)
{
    int32_t ret;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID, .type = AUTH_LINK_TYPE_BLE };
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    ret = ConvertBytesToHexString(udidHash, HB_SHORT_UDID_HASH_HEX_LEN + 1,
        (const unsigned char *)connInfo->addr.info.ble.udidHash, HB_SHORT_UDID_HASH_LEN);
    char *anonyUdidHash = NULL;
    Anonymize(udidHash, &anonyUdidHash);
    LNN_LOGI(LNN_BUILDER, "join udidHash=%{public}s", AnonymizeWrapper(anonyUdidHash));
    AnonymizeFree(anonyUdidHash);
    if (ret == SOFTBUS_OK) {
        if ((dupOk ||
            (LnnRetrieveDeviceInfo(udidHash, deviceInfo) == SOFTBUS_OK && LnnRecoveryBroadcastKey() == SOFTBUS_OK)) &&
            AuthRestoreAuthManager(udidHash, authConn, connInfo->requestId, deviceInfo,
                &authHandle.authId) == SOFTBUS_OK) {
            FilterRetrieveDeviceInfo(deviceInfo);
            LnnGetVerifyCallback()->onVerifyPassed(connInfo->requestId, authHandle, deviceInfo);
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_NETWORK_BLE_DIRECT_FAILED;
}

static int32_t LnnConvertSessionAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *authConn)
{
    if (addr == NULL || authConn == NULL) {
        LNN_LOGE(LNN_BUILDER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    authConn->type = AUTH_LINK_TYPE_SESSION;
    ConnIdCbInfo connIdCbInfo;
    (void)memset_s(&connIdCbInfo, sizeof(ConnIdCbInfo), 0, sizeof(ConnIdCbInfo));
    int32_t ret = GetConnIdCbInfoByAddr(addr, &connIdCbInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get connIdCbInfo fail.");
        return ret;
    }
    if (strncpy_s(authConn->info.sessionInfo.udid, UDID_BUF_LEN, connIdCbInfo.udid, UDID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_BUILDER, "copy udid to authConn fail");
        return SOFTBUS_STRCPY_ERR;
    }
    authConn->info.sessionInfo.connId = connIdCbInfo.connId;
    return SOFTBUS_OK;
}

static int32_t OnJoinLNN(LnnConnectionFsm *connFsm)
{
    int32_t rc;
    AuthConnInfo authConn;
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    if (CheckDeadFlag(connFsm, true)) {
        NotifyJoinResult(connFsm, NULL, SOFTBUS_NETWORK_CONN_FSM_DEAD);
        NotifyJoinExtResultProcess(connFsm, SOFTBUS_NETWORK_CONN_FSM_DEAD);
        return SOFTBUS_NETWORK_CONN_FSM_DEAD;
    }
    LNN_CHECK_AND_RETURN_RET_LOGW(connInfo->authHandle.authId <= 0, SOFTBUS_OK, LNN_BUILDER,
        "[id=%{public}u]join LNN is ongoing, waiting...", connFsm->id);
    LNN_LOGI(LNN_BUILDER, "begin join request, [id=%{public}u], peer%{public}s, isNeedConnect=%{public}d", connFsm->id,
        LnnPrintConnectionAddr(&connInfo->addr), connFsm->isNeedConnect);
    connInfo->requestId = AuthGenRequestId();
    if (connInfo->addr.type == CONNECTION_ADDR_SESSION) {
        rc = LnnConvertSessionAddrToAuthConnInfo(&connInfo->addr, &authConn);
        if (rc != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "convert session addr to auth conn info fail. [id=%{public}u]", connFsm->id);
            CompleteJoinLNN(connFsm, NULL, rc);
            return rc;
        }
    } else {
        (void)LnnConvertAddrToAuthConnInfo(&connInfo->addr, &authConn);
    }
    NodeInfo deviceInfo;
    (void)memset_s(&deviceInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    bool dupOk = false;
    if (connFsm->connInfo.dupInfo != NULL) {
        deviceInfo = *connFsm->connInfo.dupInfo;
        dupOk = true;
        SoftBusFree(connFsm->connInfo.dupInfo);
        connFsm->connInfo.dupInfo = NULL;
        LNN_LOGI(LNN_BUILDER, "join dup node info ok");
    }
    if (!connFsm->isNeedConnect && connInfo->addr.type == CONNECTION_ADDR_BLE) {
        // go to online
        if (BleDirectOnline(connInfo, &authConn, &deviceInfo, dupOk) == SOFTBUS_OK) {
            return SOFTBUS_OK;
        }
    }
    DfxRecordConnAuthStart(&authConn, connFsm, connInfo->requestId);
    rc = AuthStartVerify(&authConn, connInfo->requestId, LnnGetVerifyCallback(), AUTH_MODULE_LNN, true);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "auth verify device failed. [id=%{public}u]", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_AUTH_START_VERIFY_FAIL);
    } else {
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, NULL, JOIN_LNN_TIMEOUT_LEN);
    }
    LNN_LOGI(LNN_BUILDER, "verify request. [id=%{public}u], requestId=%{public}u", connFsm->id, connInfo->requestId);
    return rc;
}

static int32_t LnnFillConnInfo(LnnConntionInfo *connInfo)
{
    if (connInfo->nodeInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "nodeInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    bool isAuthServer = false;
    SoftBusVersion version;
    NodeInfo *nodeInfo = connInfo->nodeInfo;
    nodeInfo->discoveryType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(connInfo->addr.type);
    nodeInfo->authSeqNum = connInfo->authHandle.authId;
    (void)AuthGetServerSide(connInfo->authHandle.authId, &isAuthServer);
    nodeInfo->authChannelId[connInfo->addr.type][isAuthServer ? AUTH_AS_SERVER_SIDE : AUTH_AS_CLIENT_SIDE] =
        (int32_t)connInfo->authHandle.authId;
    nodeInfo->relation[connInfo->addr.type]++;
    int32_t ret = AuthGetVersion(connInfo->authHandle.authId, &version);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fill version fail");
        return ret;
    }
    connInfo->version = version;
    ret = AuthGetDeviceUuid(connInfo->authHandle.authId, nodeInfo->uuid, sizeof(nodeInfo->uuid));
    if (ret != SOFTBUS_OK || nodeInfo->uuid[0] == '\0') {
        LNN_LOGE(LNN_BUILDER, "fill uuid fail");
        return ret;
    }
    if (connInfo->addr.type == CONNECTION_ADDR_ETH || connInfo->addr.type == CONNECTION_ADDR_WLAN) {
        if (strcpy_s(nodeInfo->connectInfo.deviceIp, MAX_ADDR_LEN, connInfo->addr.info.ip.ip) != EOK) {
            LNN_LOGE(LNN_BUILDER, "fill deviceIp fail");
            return SOFTBUS_STRCPY_ERR;
        }
    }
    if (strcpy_s(connInfo->peerNetworkId, sizeof(connInfo->peerNetworkId), nodeInfo->networkId) != EOK) {
        LNN_LOGE(LNN_BUILDER, "fill networkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsSupportFeatureByCapability(uint32_t feature, AuthCapability capaBit)
{
    return ((feature & (1 << (uint32_t)capaBit)) != 0);
}

bool CheckRemoteBasicInfoChanged(const NodeInfo *newNodeInfo)
{
    if (newNodeInfo == NULL) {
        return false;
    }
    NodeInfo oldNodeInfo;
    if (memset_s(&oldNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo)) != EOK) {
        LNN_LOGE(LNN_BUILDER, "memset fail");
        return false;
    }
    if (LnnGetRemoteNodeInfoById(newNodeInfo->deviceInfo.deviceUdid, CATEGORY_UDID, &oldNodeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get remote node info fail");
        return false;
    }
    return IsBasicNodeInfoChanged(&oldNodeInfo, newNodeInfo, false);
}

static int32_t FillBleAddr(ConnectionAddr *addr, const ConnectionAddr *connAddr, NodeInfo *nodeInfo)
{
    uint8_t hash[SHA_256_HASH_LEN] = { 0 };
    addr->type = CONNECTION_ADDR_BLE;
    if (memcpy_s(addr->info.ble.bleMac, BT_MAC_LEN, nodeInfo->connectInfo.macAddr,
        BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_BUILDER, "bt mac memcpy to ble fail");
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusGenerateStrHash((uint8_t *)nodeInfo->deviceInfo.deviceUdid,
        strlen(nodeInfo->deviceInfo.deviceUdid), hash) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "generate udid short hash fail.");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (memcpy_s(addr->info.ble.udidHash, UDID_HASH_LEN, hash, SHORT_UDID_HASH_LEN) != EOK) {
        LNN_LOGE(LNN_BUILDER, "memcpy udid hash fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ProcessBleOnline(NodeInfo *nodeInfo, const ConnectionAddr *connAddr, AuthCapability authCapability)
{
    if (nodeInfo == NULL || connAddr == NULL) {
        LNN_LOGE(LNN_BUILDER, "nodeInfo or connAddr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t localAuthCapability = 0;
    if (LnnGetLocalNumU32Info(NUM_KEY_AUTH_CAP, &localAuthCapability) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get local auth capability fail");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    NodeInfo remoteInfo;
    if (!IsSupportFeatureByCapability(nodeInfo->authCapacity, authCapability) ||
        !IsSupportFeatureByCapability(localAuthCapability, authCapability)) {
        LNN_LOGI(LNN_BUILDER, "local or remote not support, no need to go online");
        return SOFTBUS_FUNC_NOT_SUPPORT;
    }
    if (LnnGetRemoteNodeInfoById(nodeInfo->deviceInfo.deviceUdid, CATEGORY_UDID,
        &remoteInfo) == SOFTBUS_OK && LnnHasDiscoveryType(&remoteInfo, DISCOVERY_TYPE_BLE) &&
        !CheckRemoteBasicInfoChanged(nodeInfo)) {
        if (authCapability == BIT_SUPPORT_SESSION_DUP_BLE) {
            LnnNotifyStateForSession(nodeInfo->deviceInfo.deviceUdid, SOFTBUS_OK);
        }
        LNN_LOGI(LNN_BUILDER, "ble has online, no need to go online");
        return SOFTBUS_OK;
    }
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    int32_t rc = FillBleAddr(&addr, connAddr, nodeInfo);
    if (rc != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "fill ble addr fail");
        return rc;
    }
    bool isSession = (authCapability == BIT_SUPPORT_SESSION_DUP_BLE);
    rc = JoinLnnWithNodeInfo(&addr, nodeInfo, isSession);
    if (rc == SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "join with node info success");
    } else {
        LNN_LOGE(LNN_BUILDER, "join with node info fail");
    }
    return rc;
}

static void ProcessBleOnlineForSession(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    int32_t retCode = ProcessBleOnline(connInfo->nodeInfo, &(connInfo->addr),  BIT_SUPPORT_SESSION_DUP_BLE);
    if (retCode != SOFTBUS_OK) {
        LnnNotifyStateForSession(connFsm->connInfo.nodeInfo->deviceInfo.deviceUdid, retCode);
    }
    LNN_LOGI(LNN_BUILDER, "session online not need notify.");
    AuthRemoveAuthManagerByAuthHandle(connInfo->authHandle);
    LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    (void)LnnRequestCleanConnFsm(connFsm->id);
}

static int32_t OnAuthDone(LnnConnectionFsm *connFsm, int32_t *retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (retCode == NULL) {
        LNN_LOGE(LNN_BUILDER, "auth result is null. [id=%{public}u]", connFsm->id);
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckDeadFlag(connFsm, true)) {
        SoftBusFree(retCode);
        return SOFTBUS_NETWORK_CONN_FSM_DEAD;
    }

    LNN_LOGI(LNN_BUILDER,
        "[id=%{public}u] auth done, authId=%{public}" PRId64 ", result=%{public}d, connType=%{public}d",
        connFsm->id, connInfo->authHandle.authId, *retCode, connFsm->connInfo.addr.type);
    if (*retCode == SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER,
            "[id=%{public}u] auth passed, authId=%{public}" PRId64, connFsm->id, connInfo->authHandle.authId);
        (void)LnnFillConnInfo(connInfo);
        if (connInfo->nodeInfo != NULL) {
            if (connInfo->addr.type == CONNECTION_ADDR_BR) {
                (void)ProcessBleOnline(connInfo->nodeInfo, &(connInfo->addr), BIT_SUPPORT_BR_DUP_BLE);
            } else if (connInfo->addr.type == CONNECTION_ADDR_SESSION) {
                ProcessBleOnlineForSession(connFsm);
                SoftBusFree(retCode);
                return SOFTBUS_OK;
            }
        }
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_CLEAN_INVALID_CONN_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, NULL);
    } else {
        LNN_LOGE(LNN_BUILDER,
            "[id=%{public}u] auth failed, authId=%{public}" PRId64 ", requestId=%{public}u, reason=%{public}d, "
            "connType=%{public}d",
            connFsm->id, connInfo->authHandle.authId, connInfo->requestId, *retCode, connFsm->connInfo.addr.type);
        CompleteJoinLNN(connFsm, NULL, *retCode);
    }
    SoftBusFree(retCode);
    return SOFTBUS_OK;
}

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "auth process. [id=%{public}u], msgType=%{public}d", connFsm->id, msgType);
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

static bool IsBasicNodeInfoChanged(const NodeInfo *oldNodeInfo, const NodeInfo *newNodeInfo, bool isUpdate)
{
    if (strcmp(newNodeInfo->networkId, oldNodeInfo->networkId) != 0) {
        char *newNetworkId = NULL;
        char *oldNetworkId = NULL;
        Anonymize(newNodeInfo->networkId, &newNetworkId);
        Anonymize(oldNodeInfo->networkId, &oldNetworkId);
        LNN_LOGI(LNN_BUILDER, "networkId changed %{public}s -> %{public}s",
            AnonymizeWrapper(oldNetworkId), AnonymizeWrapper(newNetworkId));
        AnonymizeFree(newNetworkId);
        AnonymizeFree(oldNetworkId);
        if (isUpdate) {
            (void)LnnUpdateNetworkId(newNodeInfo);
        }
        return true;
    }
    if (strcmp(newNodeInfo->uuid, oldNodeInfo->uuid) != 0) {
        char *newUuid = NULL;
        char *oldUuid = NULL;
        Anonymize(newNodeInfo->uuid, &newUuid);
        Anonymize(oldNodeInfo->uuid, &oldUuid);
        LNN_LOGI(LNN_BUILDER, "uuid changed %{public}s -> %{public}s",
            AnonymizeWrapper(oldUuid), AnonymizeWrapper(newUuid));
        AnonymizeFree(newUuid);
        AnonymizeFree(oldUuid);
        return true;
    }
    if (strcmp(newNodeInfo->softBusVersion, oldNodeInfo->softBusVersion) != 0) {
        char *newSoftBusVersion = NULL;
        char *oldSoftBusVersion = NULL;
        Anonymize(newNodeInfo->softBusVersion, &newSoftBusVersion);
        Anonymize(oldNodeInfo->softBusVersion, &oldSoftBusVersion);
        LNN_LOGI(LNN_BUILDER, "uuid changed %{public}s -> %{public}s",
            AnonymizeWrapper(oldSoftBusVersion), AnonymizeWrapper(newSoftBusVersion));
        AnonymizeFree(newSoftBusVersion);
        AnonymizeFree(oldSoftBusVersion);
    }
    return false;
}

static bool IsWifiConnectInfoChanged(const NodeInfo *oldNodeInfo, const NodeInfo *newNodeInfo)
{
    if (!LnnHasDiscoveryType(oldNodeInfo, DISCOVERY_TYPE_WIFI)) {
        LNN_LOGI(LNN_BUILDER, "oldNodeInfo not have wifi, discoveryType=%{public}u", oldNodeInfo->discoveryType);
        return false;
    }
    if (strcmp(newNodeInfo->connectInfo.deviceIp, oldNodeInfo->connectInfo.deviceIp) != 0) {
        char *newIp = NULL;
        char *oldIp = NULL;
        Anonymize(newNodeInfo->connectInfo.deviceIp, &newIp);
        Anonymize(oldNodeInfo->connectInfo.deviceIp, &oldIp);
        LNN_LOGI(LNN_BUILDER, "peer ip changed %{public}s -> %{public}s",
            AnonymizeWrapper(oldIp), AnonymizeWrapper(newIp));
        AnonymizeFree(newIp);
        AnonymizeFree(oldIp);
        return true;
    }
    if (newNodeInfo->connectInfo.authPort != oldNodeInfo->connectInfo.authPort) {
        LNN_LOGI(LNN_BUILDER, "peer authPort changed");
        return true;
    }
    if (newNodeInfo->connectInfo.proxyPort != oldNodeInfo->connectInfo.proxyPort) {
        LNN_LOGI(LNN_BUILDER, "peer proxyPort changed");
        return true;
    }
    if (newNodeInfo->connectInfo.sessionPort != oldNodeInfo->connectInfo.sessionPort) {
        LNN_LOGI(LNN_BUILDER, "peer sessionPort changed");
        return true;
    }
    return false;
}

static bool IsNodeInfoChanged(const LnnConnectionFsm *connFsm, const NodeInfo *oldNodeInfo,
    const NodeInfo *newNodeInfo, ConnectionAddrType *type)
{
    if (IsBasicNodeInfoChanged(oldNodeInfo, newNodeInfo, true)) {
        *type = CONNECTION_ADDR_MAX;
        return true;
    }
    if (connFsm->connInfo.addr.type == CONNECTION_ADDR_ETH || connFsm->connInfo.addr.type == CONNECTION_ADDR_WLAN) {
        if (IsWifiConnectInfoChanged(oldNodeInfo, newNodeInfo)) {
            *type = connFsm->connInfo.addr.type;
            return true;
        }
    }
    return false;
}

bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type)
{
    NodeInfo oldNodeInfo ;
    (void)memset_s(&oldNodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));

    int32_t ret = LnnGetRemoteNodeInfoById(nodeInfo->deviceInfo.deviceUdid, CATEGORY_UDID, &oldNodeInfo);
    if (ret != SOFTBUS_OK || !LnnIsNodeOnline(&oldNodeInfo)) {
        LNN_LOGW(LNN_BUILDER, "device is not online, ret=%{public}d", ret);
        return false;
    }
    if (IsBasicNodeInfoChanged(&oldNodeInfo, nodeInfo, false)) {
        return true;
    }
    if (type == CONNECTION_ADDR_ETH || type == CONNECTION_ADDR_WLAN) {
        if (IsWifiConnectInfoChanged(&oldNodeInfo, nodeInfo)) {
            return true;
        }
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
            LNN_LOGI(LNN_BUILDER, "node info changed, ready clean invalid connection. [id=%{public}u]",
                connFsm->id);
            LnnRequestLeaveInvalidConn(oldNodeInfo.networkId, addrType, newNodeInfo->networkId);
            return;
        }
    }
    LNN_LOGI(LNN_BUILDER, "no need clean invalid connection fsm. [id=%{public}u]", connFsm->id);
    LnnFsmTransactState(&connFsm->fsm, g_states + STATE_ONLINE_INDEX);
}

static bool CleanInvalidConnStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "clean invalid state process message. [id=%{public}u], msgType=%{public}d",
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
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return;
    }
    connFsm = TO_CONN_FSM(fsm);
    bool isNodeInfoValid = (connFsm->connInfo.nodeInfo != NULL);
    char *anonyUdid = NULL;
    char *anonyUuid = NULL;
    char *anonyNetworkId = NULL;
    char *anonyDeviceName = NULL;
    Anonymize(connFsm->connInfo.peerNetworkId, &anonyNetworkId);
    if (isNodeInfoValid) {
        Anonymize(connFsm->connInfo.nodeInfo->deviceInfo.deviceUdid, &anonyUdid);
        Anonymize(connFsm->connInfo.nodeInfo->uuid, &anonyUuid);
        Anonymize(connFsm->connInfo.nodeInfo->deviceInfo.deviceName, &anonyDeviceName);
    }
    LNN_LOGI(LNN_BUILDER,
        "online state enter. [id=%{public}u], networkId=%{public}s, udid=%{public}s, "
        "uuid=%{public}s, deviceName=%{public}s, peer%{public}s",
        connFsm->id, AnonymizeWrapper(anonyNetworkId), isNodeInfoValid ? AnonymizeWrapper(anonyUdid) : "",
        isNodeInfoValid ? AnonymizeWrapper(anonyUuid) : "",
        isNodeInfoValid ? AnonymizeWrapper(anonyDeviceName) : "",
        LnnPrintConnectionAddr(&connFsm->connInfo.addr));
    if (isNodeInfoValid) {
        AnonymizeFree(anonyUdid);
        AnonymizeFree(anonyUuid);
        AnonymizeFree(anonyDeviceName);
    } else {
        LNN_LOGI(LNN_BUILDER,
            "online state enter. [id=%{public}u], networkId=%{public}s, peer%{public}s",
            connFsm->id, AnonymizeWrapper(anonyNetworkId), LnnPrintConnectionAddr(&connFsm->connInfo.addr));
    }
    AnonymizeFree(anonyNetworkId);
    LnnNotifyOOBEStateChangeEvent(SOFTBUS_FACK_OOBE_END);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    CompleteJoinLNN(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_OK);
}

static void OnJoinLNNInOnline(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    LNN_LOGI(LNN_BUILDER, "request addr is already online. [id=%{public}u]", connFsm->id);
    NotifyJoinResult(connFsm, connInfo->peerNetworkId, SOFTBUS_OK);
}

static void LeaveLNNInOnline(LnnConnectionFsm *connFsm)
{
    LNN_LOGI(LNN_BUILDER, "transact to leaving state. [id=%{public}u]", connFsm->id);
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

    LNN_LOGI(LNN_BUILDER, "online process message. [id=%{public}u], msgType=%{public}d", connFsm->id, msgType);
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
        return SOFTBUS_NETWORK_LEAVE_OFFLINE;
    }
    if (!((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_LEAVE_REQUEST) != 0)) {
        LNN_LOGI(LNN_BUILDER, "just leave lnn request need send offline");
        return SOFTBUS_NETWORK_LEAVE_OFFLINE;
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
        return SOFTBUS_NETWORK_SEND_SYNC_INFO_FAILED;
    }
    return SOFTBUS_OK;
}

static void LeavingStateEnter(FsmStateMachine *fsm)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc;
    LnnConntionInfo *connInfo = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return;
    }
    connFsm = TO_CONN_FSM(fsm);
    connInfo = &connFsm->connInfo;

    bool isNodeInfoValid = (connFsm->connInfo.nodeInfo != NULL);
    char *anonyUdid = NULL;
    char *anonyNetworkId = NULL;
    char *anonyDeviceName = NULL;
    Anonymize(connFsm->connInfo.peerNetworkId, &anonyNetworkId);
    if (isNodeInfoValid) {
        Anonymize(connFsm->connInfo.nodeInfo->deviceInfo.deviceUdid, &anonyUdid);
        Anonymize(connFsm->connInfo.nodeInfo->deviceInfo.deviceName, &anonyDeviceName);
    }
    LNN_LOGI(LNN_BUILDER,
        "leaving state enter. [id=%{public}u], networkId=%{public}s, udid=%{public}s, deviceName=%{public}s, "
        "peer%{public}s",
        connFsm->id, AnonymizeWrapper(anonyNetworkId), isNodeInfoValid ? AnonymizeWrapper(anonyUdid) : "",
        isNodeInfoValid ? AnonymizeWrapper(anonyDeviceName) : "",
        LnnPrintConnectionAddr(&connFsm->connInfo.addr));
    if (isNodeInfoValid) {
        AnonymizeFree(anonyUdid);
        AnonymizeFree(anonyDeviceName);
    } else {
        LNN_LOGI(LNN_BUILDER,
            "leaving state enter. [id=%{public}u], networkId=%{public}s, peer%{public}s",
            connFsm->id, AnonymizeWrapper(anonyNetworkId), LnnPrintConnectionAddr(&connFsm->connInfo.addr));
    }
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
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    LNN_LOGI(LNN_BUILDER, "leaving process message. [id=%{public}u], msgType=%{public}d", connFsm->id, msgType);
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
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
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
        return SOFTBUS_SPRINTF_ERR;
    }
    if (LnnFsmInit(&connFsm->fsm, NULL, connFsm->fsmName, ConnectionFsmDinitCallback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "init fsm failed");
        return SOFTBUS_NETWORK_FSM_INIT_FAILED;
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
    LNN_LOGI(LNN_BUILDER, "create a new connection fsm. [id=%{public}u], peerAddr=%{public}s, needConnect=%{public}d",
        connFsm->id, LnnPrintConnectionAddr(target), isNeedConnect);
    return connFsm;
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connFsm is null");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "destroy a connection fsm. [id=%{public}u]", connFsm->id);
    if (connFsm->connInfo.cleanInfo != NULL) {
        SoftBusFree(connFsm->connInfo.cleanInfo);
    }
    if (connFsm->connInfo.nodeInfo != NULL) {
        SoftBusFree(connFsm->connInfo.nodeInfo);
    }
    if (connFsm->connInfo.dupInfo != NULL) {
        SoftBusFree(connFsm->connInfo.dupInfo);
    }
    SoftBusFree(connFsm);
}

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LnnFsmStart(&connFsm->fsm, g_states + STATE_AUTH_INDEX);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "start connection fsm failed. [id=%{public}u]", connFsm->id);
        return ret;
    }
    LNN_LOGI(LNN_BUILDER, "connection fsm is starting. [id=%{public}u]", connFsm->id);
    return SOFTBUS_OK;
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    if (connFsm == NULL || callback == NULL) {
        LNN_LOGE(LNN_BUILDER, "connection fsm or stop callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm->stopCallback = callback;
    int32_t ret = LnnFsmStop(&connFsm->fsm);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "stop connection fsm failed. [id=%{public}u]", connFsm->id);
        return ret;
    }
    return LnnFsmDeinit(&connFsm->fsm);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    SetWatchdogFlag(false);
    if ((connFsm->connInfo.addr.type == CONNECTION_ADDR_BLE || connFsm->connInfo.addr.type == CONNECTION_ADDR_BR) &&
        SoftBusGetBtState() != BLE_ENABLE) {
        LNN_LOGE(LNN_BUILDER, "send join request while bt is turn off");
        return SOFTBUS_NETWORK_BLE_DISABLE;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, NULL);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode)
{
    int32_t *para = NULL;

    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
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
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_NOT_TRUSTED, NULL);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_DISCONNECT, NULL);
}

int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN, NULL);
}

int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_SYNC_OFFLINE_DONE, NULL);
}

int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        LNN_LOGE(LNN_BUILDER, "connFsm is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_INITIATE_ONLINE, NULL);
}

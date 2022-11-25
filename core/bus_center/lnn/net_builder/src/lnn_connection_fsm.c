/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_decision_db.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_net_builder.h"
#include "lnn_sync_item_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "lnn_async_callback_utils.h"
#include "trans_channel_manager.h"

#define DATA_SIZE 32

typedef enum {
    STATE_AUTH_INDEX = 0,
    STATE_CLEAN_INVALID_CONN_INDEX,
    STATE_ONLINE_INDEX,
    STATE_LEAVING_INDEX,
    STATE_NUM_MAX,
} ConnFsmStateIndex;

#define SECOND_TO_MSENC 1000
#define MILLISECOND_TO_MICRO 1000

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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fsm is null");
        return false;
    }
    if (TO_CONN_FSM(fsm) == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connFsm is null");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connection fsm is null");
        return false;
    }
    if (needCheckDead && connFsm->isDead) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]connection fsm is already dead", connFsm->id);
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "free unhandled msg: %d", msgType);
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static void ReportResult(const char *udid, ReportCategory report)
{
    NodeBasicInfo basic;

    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetBasicInfoByUdid fail!");
        return;
    }
    switch (report) {
        case REPORT_CHANGE:
            LnnNotifyBasicInfoChanged(&basic, TYPE_NETWORK_ID);
            break;
        case REPORT_ONLINE:
            LnnNotifyOnlineState(true, &basic);
            LnnInsertSpecificTrustedDevInfo(udid);
            break;
        case REPORT_NONE:
            /* fall-through */
        default:
            break;
    }
}

int64_t LnnUpTimeMs(void)
{
    SoftBusSysTime t;
    t.sec = 0;
    t.usec = 0;
    SoftBusGetTime(&t);
    int64_t when = t.sec * SECOND_TO_MSENC + t.usec / MILLISECOND_TO_MICRO;
    return when;
}

static void ReportLnnDfx(LnnConnectionFsm *connFsm, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    connFsm->statisticData.type = connInfo->addr.type;
    connFsm->statisticData.retCode = retCode;
    if (retCode == SOFTBUS_OK) {
        connFsm->statisticData.endTime = LnnUpTimeMs();
        if (AddStatisticDuration(&connFsm->statisticData) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add static duration");
        }
    }
    if (AddStatisticRateOfSuccess(&connFsm->statisticData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add rate success");
    }
    if (retCode != SOFTBUS_OK) {
        SoftBusEvtReportMsg msg;
        (void)memset_s(&msg, sizeof(SoftBusEvtReportMsg), 0, sizeof(SoftBusEvtReportMsg));
        if (CreateBusCenterFaultEvt(&msg, retCode, &connInfo->addr) == SOFTBUS_OK && msg.paramArray != NULL) {
            (void)ReportBusCenterFaultEvt(&msg);
        }
    }
}

static void CompleteJoinLNN(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    ReportCategory report;
    uint8_t relation[CONNECTION_ADDR_MAX] = {0};

    LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    if ((connInfo->flag & LNN_CONN_INFO_FLAG_JOIN_AUTO) != 0) { // only report auto network
        ReportLnnDfx(connFsm, retCode);
    }
    if (retCode == SOFTBUS_OK) {
        report = LnnAddOnlineNode(connInfo->nodeInfo);
        NotifyJoinResult(connFsm, networkId, retCode);
        ReportResult(connInfo->nodeInfo->deviceInfo.deviceUdid, report);
        connInfo->flag |= LNN_CONN_INFO_FLAG_ONLINE;
        LnnNotifyNodeStateChanged(&connInfo->addr);
        LnnOfflineTimingByHeartbeat(networkId, connInfo->addr.type);
        LnnGetLnnRelation(networkId, CATEGORY_NETWORK_ID, relation, CONNECTION_ADDR_MAX);
        LnnNotifyLnnRelationChanged(connInfo->nodeInfo->deviceInfo.deviceUdid, connInfo->addr.type,
            relation[connInfo->addr.type], true);
    } else {
        NotifyJoinResult(connFsm, networkId, retCode);
        AuthHandleLeaveLNN(connInfo->authId);
    }
    if (connInfo->nodeInfo != NULL) {
        SoftBusFree(connInfo->nodeInfo);
        connInfo->nodeInfo = NULL;
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    if (retCode != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]join failed, ready clean", connFsm->id);
        connFsm->isDead = true;
        LnnRequestCleanConnFsm(connFsm->id);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]complete join LNN done", connFsm->id);
}

static bool UpdateLeaveToLedger(const LnnConnectionFsm *connFsm, const char *networkId, NodeBasicInfo *basic)
{
    const LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeInfo *info = NULL;
    const char *udid = NULL;
    bool needReportOffline = false;
    bool isMetaAuth = false;
    uint8_t relation[CONNECTION_ADDR_MAX] = {0};
    ReportCategory report;

    info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        return needReportOffline;
    }
    isMetaAuth = (info->AuthTypeValue & (1 << ONLINE_METANODE)) != 0;
    udid = LnnGetDeviceUdid(info);
    report = LnnSetNodeOffline(udid, connInfo->addr.type, (int32_t)connInfo->authId);
    LnnGetLnnRelation(udid, CATEGORY_UDID, relation, CONNECTION_ADDR_MAX);
    LnnNotifyLnnRelationChanged(udid, connInfo->addr.type, relation[connInfo->addr.type], false);
    if (report == REPORT_OFFLINE) {
        needReportOffline = true;
        (void)memset_s(basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
        if (LnnGetBasicInfoByUdid(udid, basic) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]get basic info fail", connFsm->id);
            needReportOffline = false;
        }
        // just remove node when peer device is not trusted
        if ((connInfo->flag & LNN_CONN_INFO_FLAG_LEAVE_PASSIVE) != 0 && !isMetaAuth) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]remove node", connFsm->id);
            LnnRemoveNode(udid);
        }
    }
    return needReportOffline;
}

static void CompleteLeaveLNN(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeBasicInfo basic;
    bool needReportOffline = false;

    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT);
    if (retCode == SOFTBUS_OK) {
        needReportOffline = UpdateLeaveToLedger(connFsm, networkId, &basic);
        LnnNotifyNodeStateChanged(&connInfo->addr);
    }
    NotifyLeaveResult(connFsm, networkId, retCode);
    if (needReportOffline) {
        LnnNotifyOnlineState(false, &basic);
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_LEAVE_PASSIVE;
    connFsm->isDead = true;
    LnnNotifyAuthHandleLeaveLNN(connInfo->authId);
    LnnRequestCleanConnFsm(connFsm->id);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]complete leave lnn, ready clean", connFsm->id);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]join LNN is ongoing, waiting...", connFsm->id);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]begin join request", connFsm->id);
    connInfo->requestId = AuthGenRequestId();
    (void)LnnConvertAddrToAuthConnInfo(&connInfo->addr, &authConn);
    if (AuthStartVerify(&authConn, connInfo->requestId, LnnGetVerifyCallback()) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]auth verify device failed", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
        rc = SOFTBUS_ERR;
    } else {
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, NULL, JOIN_LNN_TIMEOUT_LEN);
        rc = SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "[id=%u]verify request id=%u", connFsm->id, connInfo->requestId);
    return rc;
}

int32_t OnJoinMetaNode(MetaJoinRequestNode *metaJoinNode, CustomData *customData)
{
    if (metaJoinNode == NULL || customData == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t rc = SOFTBUS_OK;
    int32_t connId = 0;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "channelId: %d, type: %d",
        metaJoinNode->addr.info.session.channelId, metaJoinNode->addr.info.session.type);
    if (metaJoinNode->addr.type == CONNECTION_ADDR_SESSION) {
        rc = TransGetConnByChanId(metaJoinNode->addr.info.session.channelId,
            metaJoinNode->addr.info.session.type, &connId);
        if (rc != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnJoinMetaNode fail");
            return SOFTBUS_ERR;
        }
        metaJoinNode->requestId = AuthGenRequestId();
        if (AuthMetaStartVerify(connId, customData->data, DATA_SIZE,
            metaJoinNode->requestId, LnnGetMetaVerifyCallback()) != SOFTBUS_OK) {
                rc = SOFTBUS_ERR;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "AuthMetaStartVerify resultId=%d, requestId=%u", rc, metaJoinNode->requestId);
    }
    return rc;
}

static int32_t LnnFillConnInfo(LnnConntionInfo *connInfo)
{
    SoftBusSysTime times;
    SoftBusVersion version;
    (void)SoftBusGetTime(&times);
    NodeInfo *nodeInfo = connInfo->nodeInfo;
    nodeInfo->heartbeatTimeStamp = (uint64_t)times.sec * HB_TIME_FACTOR +
        (uint64_t)times.usec / HB_TIME_FACTOR;
    nodeInfo->discoveryType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(connInfo->addr.type);
    nodeInfo->authSeqNum = connInfo->authId;
    connInfo->nodeInfo->authSeq[LnnConvAddrTypeToDiscType(connInfo->addr.type)] = connInfo->authId;
    nodeInfo->authChannelId[connInfo->addr.type] = (int32_t)connInfo->authId;
    nodeInfo->relation[connInfo->addr.type]++;
    if (AuthGetVersion(connInfo->authId, &version) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill version fail");
        return SOFTBUS_ERR;
    }
    connInfo->version = version;
    if (AuthGetDeviceUuid(connInfo->authId, nodeInfo->uuid, sizeof(nodeInfo->uuid)) != SOFTBUS_OK ||
        nodeInfo->uuid[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill uuid fail");
        return SOFTBUS_ERR;
    }
    if (connInfo->addr.type == CONNECTION_ADDR_ETH || connInfo->addr.type == CONNECTION_ADDR_WLAN) {
        if (strcpy_s(nodeInfo->connectInfo.deviceIp, MAX_ADDR_LEN, connInfo->addr.info.ip.ip) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill deviceIp fail");
            return SOFTBUS_MEM_ERR;
        }
    }
    if (strcpy_s(connInfo->peerNetworkId, sizeof(connInfo->peerNetworkId), nodeInfo->networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OnAuthDone(LnnConnectionFsm *connFsm, int32_t *retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (retCode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]auth result is null", connFsm->id);
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckDeadFlag(connFsm, true)) {
        SoftBusFree(retCode);
        return SOFTBUS_ERR;
    }

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth done, authId=%" PRId64 ", result=%d",
        connFsm->id, connInfo->authId, *retCode);
    if (*retCode == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]auth passed, authId=%" PRId64, connFsm->id, connInfo->authId);
        (void)LnnFillConnInfo(connInfo);
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_CLEAN_INVALID_CONN_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, NULL);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]auth failed, requestId=%u, reason=%d", connFsm->id, connInfo->requestId, *retCode);
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth process message: %d", connFsm->id, msgType);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]networkId changed", connFsm->id);
        *type = CONNECTION_ADDR_MAX;
        return true;
    }
    if (connFsm->connInfo.addr.type != CONNECTION_ADDR_ETH && connFsm->connInfo.addr.type != CONNECTION_ADDR_WLAN) {
        return false;
    }
    if (!LnnHasDiscoveryType(oldNodeInfo, DISCOVERY_TYPE_WIFI)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]oldNodeInfo not have wifi, discoveryType = %u",
            connFsm->id, oldNodeInfo->discoveryType);
        return false;
    }
    if (strcmp(newNodeInfo->connectInfo.deviceIp, oldNodeInfo->connectInfo.deviceIp) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]peer IP changed", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    if (newNodeInfo->connectInfo.authPort != oldNodeInfo->connectInfo.authPort) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]peer auth port changed", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    if (newNodeInfo->connectInfo.proxyPort != oldNodeInfo->connectInfo.proxyPort) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]peer proxy port changed", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    if (newNodeInfo->connectInfo.sessionPort != oldNodeInfo->connectInfo.sessionPort) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]peer session port changed", connFsm->id);
        *type = connFsm->connInfo.addr.type;
        return true;
    }
    return false;
}

static void OnLeaveInvalidConn(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeInfo *oldNodeInfo = LnnGetNodeInfoById(connInfo->nodeInfo->deviceInfo.deviceUdid, CATEGORY_UDID);
    NodeInfo *newNodeInfo = connInfo->nodeInfo;
    ConnectionAddrType addrType;

    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    if (oldNodeInfo != NULL && LnnIsNodeOnline(oldNodeInfo)) {
        if (IsNodeInfoChanged(connFsm, oldNodeInfo, newNodeInfo, &addrType)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]node info changed, ready clean invalid connection",
                connFsm->id);
            LnnRequestLeaveInvalidConn(oldNodeInfo->networkId, addrType, newNodeInfo->networkId);
            return;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]no need clean invalid connection fsm", connFsm->id);
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]clean invalid state process message: %d",
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]online state enter", connFsm->id);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    CompleteJoinLNN(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_OK);
}

static void OnJoinLNNInOnline(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]request addr is already online", connFsm->id);
    NotifyJoinResult(connFsm, connInfo->peerNetworkId, SOFTBUS_OK);
}

static void LeaveLNNInOnline(LnnConnectionFsm *connFsm)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]transact to leaving state", connFsm->id);
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]online process message: %d", connFsm->id, msgType);
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

static int32_t SyncOffline(const LnnConnectionFsm *connFsm)
{
    int16_t code;
    uint32_t combinedInt;
    char uuid[UUID_BUF_LEN];

    if (connFsm->connInfo.addr.type != CONNECTION_ADDR_BR) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "just br need send offline");
        return SOFTBUS_ERR;
    }
    if (!((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_LEAVE_REQUEST) != 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "just leave lnn request need send offline");
        return SOFTBUS_ERR;
    }
    (void)LnnConvertDlId(connFsm->connInfo.peerNetworkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    code = LnnGetCnnCode(uuid, DISCOVERY_TYPE_BR);
    if (code == INVALID_CONNECTION_CODE_VALUE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "uuid not exist!");
        return SOFTBUS_INVALID_PARAM;
    }
    combinedInt = ((uint16_t)code << CONN_CODE_SHIFT) | ((uint16_t)DISCOVERY_TYPE_BR & 0x7FFF);
    combinedInt = SoftBusHtoNl(combinedInt);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "GetOfflineMsg combinedInt: 0x%04x", combinedInt);
    if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_OFFLINE, connFsm->connInfo.peerNetworkId,
        (uint8_t *)&combinedInt, sizeof(int32_t), LnnSyncOfflineComplete) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send sync offline fail");
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]leaving state enter", connFsm->id);
    if (CheckDeadFlag(connFsm, true)) {
        return;
    }
    rc = SyncOffline(connFsm);
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]leaving process message: %d", connFsm->id, msgType);
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "connection fsm deinit callback enter");
    if (!CheckStateMsgCommonArgs(fsm)) {
        return;
    }
    connFsm = TO_CONN_FSM(fsm);
    if (connFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connFsm is NULL!");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format lnn connection fsm name failed");
        return SOFTBUS_ERR;
    }
    if (LnnFsmInit(&connFsm->fsm, NULL, connFsm->fsmName, ConnectionFsmDinitCallback) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init fsm failed");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < STATE_NUM_MAX; ++i) {
        LnnFsmAddState(&connFsm->fsm, &g_states[i]);
    }
    return SOFTBUS_OK;
}

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target)
{
    LnnConnectionFsm *connFsm = NULL;

    if (target == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connection target is null");
        return NULL;
    }
    connFsm = SoftBusCalloc(sizeof(LnnConnectionFsm));
    if (connFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc for connection fsm failed");
        return NULL;
    }
    ListInit(&connFsm->node);
    connFsm->id = GetNextConnectionFsmId();
    if (InitConnectionStateMachine(connFsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init connecton fsm failed");
        SoftBusFree(connFsm);
        return NULL;
    }
    connFsm->connInfo.addr = *target;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "create a new connection fsm[id=%u]", connFsm->id);
    return connFsm;
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "destroy a connection fsm[id=%u]", connFsm->id);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connection fsm is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnFsmStart(&connFsm->fsm, g_states + STATE_AUTH_INDEX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start connection fsm[id=%u] failed", connFsm->id);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "connection fsm[id=%u] is starting", connFsm->id);
    return SOFTBUS_OK;
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    if (connFsm == NULL || callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connection fsm or stop callback is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm->stopCallback = callback;
    if (LnnFsmStop(&connFsm->fsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop connection fsm(id=%u) failed", connFsm->id);
        return SOFTBUS_ERR;
    }
    return LnnFsmDeinit(&connFsm->fsm);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_INVALID_PARAM;
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc auth result msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = retCode;
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, para);
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
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
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_exchange_device_info.h"
#include "lnn_net_builder.h"
#include "lnn_sync_item_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define STATE_AUTH_INDEX 0
#define STATE_SYNC_DEVICE_INFO_INDEX 1
#define STATE_CLEAN_INVALID_CONN_INDEX 2
#define STATE_ONLINE_INDEX 3
#define STATE_LEAVING_INDEX 4
#define STATE_NUM_MAX (STATE_LEAVING_INDEX + 1)

#define JOIN_LNN_TIMEOUT_LEN  (15 * 1000UL)
#define LEAVE_LNN_TIMEOUT_LEN (5 * 1000UL)

#define TO_CONN_FSM(ptr) CONTAINER_OF(ptr, LnnConnectionFsm, fsm)

typedef enum {
    FSM_MSG_TYPE_JOIN_LNN,
    FSM_MSG_TYPE_AUTH_KEY_GENERATED,
    FSM_MSG_TYPE_AUTH_DONE,
    FSM_MSG_TYPE_SYNC_DEVICE_INFO,
    FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE,
    FSM_MSG_TYPE_LEAVE_INVALID_CONN = 5,
    FSM_MSG_TYPE_LEAVE_LNN,
    FSM_MSG_TYPE_NOT_TRUSTED,
    FSM_MSG_TYPE_DISCONNECT,
    FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
    FSM_MSG_TYPE_SYNC_OFFLINE_DONE = 10,
    FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT,
    FSM_MSG_TYPE_INITIATE_ONLINE,
} StateMessageType;

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool SyncDeviceInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
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
    [STATE_SYNC_DEVICE_INFO_INDEX] = {
        .enter = NULL,
        .process = SyncDeviceInfoStateProcess,
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
            break;
        case REPORT_NONE:
            /* fall-through */
        default:
            break;
    }
}

static void CompleteJoinLNN(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    if (retCode == SOFTBUS_OK) {
        ReportCategory report = LnnAddOnlineNode(connInfo->nodeInfo);
        NotifyJoinResult(connFsm, networkId, retCode);
        ReportResult(connInfo->nodeInfo->deviceInfo.deviceUdid, report);
        connInfo->flag |= LNN_CONN_INFO_FLAG_ONLINE;
    } else {
        NotifyJoinResult(connFsm, networkId, retCode);
        (void)AuthHandleLeaveLNN(connInfo->authId);
    }
    if (connInfo->nodeInfo != NULL) {
        SoftBusFree(connInfo->nodeInfo);
        connInfo->nodeInfo = NULL;
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    if (retCode != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]join failed, ready clean", connFsm->id);
        connFsm->isDead = true;
        LnnRequestCleanConnFsm(connFsm->id);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]complete join LNN done", connFsm->id);
}

static bool UpdateLeaveToLedger(const LnnConnectionFsm *connFsm, const char *networkId, NodeBasicInfo *basic)
{
    const LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeInfo *info = NULL;
    const char *udid = NULL;
    bool needReportOffline = false;

    info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        return needReportOffline;
    }
    udid = LnnGetDeviceUdid(info);
    if (LnnSetNodeOffline(udid, (int32_t)connInfo->authId) == REPORT_OFFLINE) {
        needReportOffline = true;
        (void)memset_s(basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
        if (LnnGetBasicInfoByUdid(udid, basic) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]get basic info fail", connFsm->id);
            needReportOffline = false;
        }
        // just remove node when peer device is not trusted
        if ((connInfo->flag & LNN_CONN_INFO_FLAG_LEAVE_PASSIVE) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]remove node", connFsm->id);
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
    }
    NotifyLeaveResult(connFsm, networkId, retCode);
    if (needReportOffline) {
        LnnNotifyOnlineState(false, &basic);
    }
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_LEAVE_PASSIVE;
    (void)AuthHandleLeaveLNN(connInfo->authId);
    connFsm->isDead = true;
    connInfo->flag &= ~LNN_CONN_INFO_FLAG_ONLINE;
    LnnRequestCleanConnFsm(connFsm->id);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]complete leave lnn, ready clean", connFsm->id);
}

static int32_t OnJoinFail(LnnConnectionFsm *connFsm)
{
    if (CheckDeadFlag(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
    return SOFTBUS_OK;
}

static void TryCancelJoinProcedure(LnnConnectionFsm *connFsm)
{
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_LEAVE_AUTO) != 0) {
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
    } else {
        NotifyJoinResult(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_ERR);
    }
}

static int32_t OnJoinLNNInAuth(LnnConnectionFsm *connFsm)
{
    int32_t rc;
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (CheckDeadFlag(connFsm, true)) {
        NotifyJoinResult(connFsm, NULL, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    if (connInfo->authId > 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]join LNN is ongoing, waiting...", connFsm->id);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]begin join request", connFsm->id);
    connInfo->authId = AuthVerifyDevice(LNN, &connInfo->addr);
    if (connInfo->authId <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]auth verify device failed", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
        rc = SOFTBUS_ERR;
    } else {
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT, NULL, JOIN_LNN_TIMEOUT_LEN);
        rc = SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]verify request authId=%lld", connFsm->id, connInfo->authId);
    return rc;
}

static int32_t OnAuthKeyGeneratedInAuth(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (CheckDeadFlag(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    if ((connInfo->flag & LNN_CONN_INFO_FLAG_JOIN_ACTIVE) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]active auth success, transact to syn_device_info state, authId=%llu",
            connFsm->id, connInfo->authId);
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO, NULL);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]passive auth success, transact to syn_device_info state, authId=%llu",
            connFsm->id, connInfo->authId);
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO, NULL);
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
            NULL, JOIN_LNN_TIMEOUT_LEN);
    }
    return SOFTBUS_OK;
}

static int32_t OnAuthDoneInAuth(LnnConnectionFsm *connFsm, bool *isSuccess)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (CheckDeadFlag(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    if (isSuccess == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]auth result flag is null", connFsm->id);
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth done, authId=%lld, auth result=%d",
        connFsm->id, connInfo->authId, *isSuccess);
    if (*isSuccess) {
        SoftBusFree(isSuccess);
        return SOFTBUS_ERR;
    }
    CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
    SoftBusFree(isSuccess);
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
            OnJoinLNNInAuth(connFsm);
            break;
        case FSM_MSG_TYPE_AUTH_KEY_GENERATED:
            OnAuthKeyGeneratedInAuth(connFsm);
            break;
        case FSM_MSG_TYPE_AUTH_DONE:
            OnAuthDoneInAuth(connFsm, (bool *)para);
            break;
        case FSM_MSG_TYPE_DISCONNECT:
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinFail(connFsm);
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

static int32_t OnSyncDeviceInfo(LnnConnectionFsm *connFsm)
{
    uint8_t *buf = NULL;
    uint32_t bufSize;
    int32_t rc;
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    AuthDataHead head;
    ConnectOption option;

    if (CheckDeadFlag(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    if (LnnConvertAddrToOption(&connInfo->addr, &option) == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]convert addr to option failed", connFsm->id);
        return SOFTBUS_ERR;
    }
    buf = LnnGetExchangeNodeInfo((int32_t)connInfo->authId, &option, SOFT_BUS_NEW_V1, &bufSize, &head.flag);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]pack local device info fail", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }

    head.dataType = DATA_TYPE_SYNC;
    if (option.type == CONNECT_TCP) {
        head.module = MODULE_AUTH_CONNECTION;
    } else {
        head.module = HICHAIN_SYNC;
    }
    head.authId = connInfo->authId;
    rc = AuthPostData(&head, buf, bufSize);
    if (rc != SOFTBUS_OK) {
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
    }
    SoftBusFree(buf);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]sync device info process result: %d", connFsm->id, rc);
    return rc;
}

static DiscoveryType GetDiscoveryType(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN || type == CONNECTION_ADDR_ETH) {
        return DISCOVERY_TYPE_WIFI;
    } else if (type == CONNECTION_ADDR_BR) {
        return DISCOVERY_TYPE_BR;
    } else if (type == CONNECTION_ADDR_BLE) {
        return DISCOVERY_TYPE_BLE;
    } else {
        return DISCOVERY_TYPE_COUNT;
    }
}

static bool ParsePeerNodeInfo(LnnRecvDeviceInfoMsgPara *para, LnnConntionInfo *connInfo)
{
    ParseBuf parseBuf;
    int32_t rc = SOFTBUS_OK;
    ConnectOption option;
    do {
        if (connInfo->nodeInfo == NULL) {
            connInfo->nodeInfo = SoftBusCalloc(sizeof(NodeInfo));
            if (connInfo->nodeInfo == NULL) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc node info fail");
                rc = SOFTBUS_MALLOC_ERR;
                break;
            }
        }
        if (LnnConvertAddrToOption(&connInfo->addr, &option) == false) {
            rc = SOFTBUS_ERR;
            break;
        }
        parseBuf.buf = para->data;
        parseBuf.len = para->len;
        if (LnnParsePeerNodeInfo(&option, connInfo->nodeInfo, &parseBuf,
            para->side, connInfo->peerVersion) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unpack peer device info fail");
            rc = SOFTBUS_ERR;
            break;
        }
        connInfo->nodeInfo->discoveryType = 1 << (uint32_t)GetDiscoveryType(connInfo->addr.type);
        connInfo->nodeInfo->authSeqNum = connInfo->authId;
        connInfo->nodeInfo->authChannelId = (int32_t)connInfo->authId;
        if (strncpy_s(connInfo->nodeInfo->uuid, UUID_BUF_LEN, para->uuid, strlen(para->uuid)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s uuid failed");
            rc = SOFTBUS_ERR;
            break;
        }
        if (option.type == CONNECT_TCP) {
            if (strncpy_s(connInfo->nodeInfo->connectInfo.deviceIp, IP_LEN, connInfo->addr.info.ip.ip,
                strlen(connInfo->addr.info.ip.ip)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "strncpy_s deviceIp failed");
                rc = SOFTBUS_ERR;
            }
        }
    } while (false);

    if (rc != SOFTBUS_OK) {
        SoftBusFree(connInfo->nodeInfo);
        connInfo->nodeInfo = NULL;
        return false;
    }
    return true;
}

static int32_t OnSyncDeviceInfoDone(LnnConnectionFsm *connFsm, LnnRecvDeviceInfoMsgPara *para)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]peer device info msg para is null", connFsm->id);
        return SOFTBUS_ERR;
    }
    if (CheckDeadFlag(connFsm, true)) {
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    if (!ParsePeerNodeInfo(para, connInfo) || strncpy_s(connInfo->peerNetworkId, NETWORK_ID_BUF_LEN,
        connInfo->nodeInfo->networkId, strlen(connInfo->nodeInfo->networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]ParsePeerNodeInfo error", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    SoftBusFree(para);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]recv peer device info done, wait for auth done",
        connFsm->id);
    return SOFTBUS_OK;
}

static int32_t OnAuthDoneInSyncInfo(LnnConnectionFsm *connFsm, bool *isSuccess)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if (isSuccess == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]auth result flag is null", connFsm->id);
        return SOFTBUS_INVALID_PARAM;
    }
    if (CheckDeadFlag(connFsm, true)) {
        SoftBusFree(isSuccess);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth done, authId=%lld, auth result=%d",
        connFsm->id, connInfo->authId, *isSuccess);
    if (*isSuccess) {
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_CLEAN_INVALID_CONN_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_INVALID_CONN, NULL);
    } else {
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
    }
    SoftBusFree(isSuccess);
    return SOFTBUS_OK;
}

static bool SyncDeviceInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        FreeUnhandledMessage(msgType, para);
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]sync device info process message: %d",
        connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_SYNC_DEVICE_INFO:
            OnSyncDeviceInfo(connFsm);
            break;
        case FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE:
            OnSyncDeviceInfoDone(connFsm, (LnnRecvDeviceInfoMsgPara *)para);
            break;
        case FSM_MSG_TYPE_AUTH_DONE:
            OnAuthDoneInSyncInfo(connFsm, (bool *)para);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            TryCancelJoinProcedure(connFsm);
            break;
        case FSM_MSG_TYPE_NOT_TRUSTED:
        case FSM_MSG_TYPE_DISCONNECT:
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinFail(connFsm);
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
        case FSM_MSG_TYPE_DISCONNECT:
            OnJoinFail(connFsm);
            break;
        case FSM_MSG_TYPE_LEAVE_INVALID_CONN:
            OnLeaveInvalidConn(connFsm);
            break;
        case FSM_MSG_TYPE_INITIATE_ONLINE:
            LnnFsmTransactState(&connFsm->fsm, g_states + STATE_ONLINE_INDEX);
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
    rc = LnnSyncLedgerItemInfo(connInfo->peerNetworkId, GetDiscoveryType(connInfo->addr.type), INFO_TYPE_OFFLINE);
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
            NotifyJoinResult(connFsm, NULL, SOFTBUS_ERR);
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
    if (LnnFsmInit(&connFsm->fsm, connFsm->fsmName, ConnectionFsmDinitCallback) != SOFTBUS_OK) {
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
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN, NULL);
}

int32_t LnnSendAuthKeyGenMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_AUTH_KEY_GENERATED, NULL);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, bool isSuccess)
{
    bool *para = NULL;

    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    para = (bool *)SoftBusMalloc(sizeof(bool));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc auth result msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = isSuccess;
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_AUTH_DONE, para);
}

int32_t LnnSendPeerDevInfoToConnFsm(LnnConnectionFsm *connFsm, const LnnRecvDeviceInfoMsgPara *para)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]recv peer device info is null", connFsm->id);
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE, (void *)para);
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_NOT_TRUSTED, NULL);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    if (!CheckInterfaceCommonArgs(connFsm, true)) {
        return SOFTBUS_ERR;
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
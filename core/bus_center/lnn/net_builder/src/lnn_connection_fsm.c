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
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

#define STATE_AUTH_INDEX 0
#define STATE_SYNC_DEVICE_INFO_INDEX 1
#define STATE_OFFLINE_INDEX 2
#define STATE_ONLINE_INDEX 3
#define STATE_LEAVING_INDEX 4
#define STATE_NUM_MAX (STATE_LEAVING_INDEX + 1)

#define CONN_INFO_FLAG_JOINING_ACTIVE  0x01
#define CONN_INFO_FLAG_JOINING_PASSIVE 0x02
#define CONN_INFO_FLAG_LEAVING_ACTIVE  0x04
#define CONN_INFO_FLAG_LEAVING_PASSIVE 0x08

#define JOIN_LNN_TIMEOUT_LEN  (15 * 1000UL)
#define LEAVE_LNN_TIMEOUT_LEN (5 * 1000UL)

#define TO_CONN_FSM(ptr) CONTAINER_OF(ptr, LnnConnectionFsm, fsm)

typedef enum {
    FSM_MSG_TYPE_JOIN_LNN,
    FSM_MSG_TYPE_AUTH_KEY_GENERATED,
    FSM_MSG_TYPE_AUTH_DONE,
    FSM_MSG_TYPE_SYNC_DEVICE_INFO,
    FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE,
    FSM_MSG_TYPE_EST_HEART_BEAT,
    FSM_MSG_TYPE_LEAVE_LNN,
    FSM_MSG_TYPE_NOT_TRUSTED,
    FSM_MSG_TYPE_DISCONNECT,
    FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
    FSM_MSG_TYPE_SYNC_OFFLINE_DONE,
    FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT,
} StateMessageType;

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool SyncDeviceInfoStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool OfflineStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
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
    [STATE_OFFLINE_INDEX] = {
        .enter = NULL,
        .process = OfflineStateProcess,
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

static void FreeUnhandledMessage(const LnnConnectionFsm *connFsm, int32_t msgType, void *para)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]free unhandled msg: %d", connFsm->id, msgType);
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static void ReportResult(const char *udid, ReportCategory report)
{
    NodeBasicInfo basic;

    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetBasicInfoByUdid?fail!");
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
        if (strncpy_s(connInfo->peerNetworkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) == EOK) {
            ReportCategory report = LnnAddOnlineNode(connInfo->nodeInfo);
            ReportResult(connInfo->nodeInfo->deviceInfo.deviceUdid, report);
            (void)LnnNotifyNodeStateChanged(&connInfo->addr);
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy peer network id error");
        }
    } else {
        (void)AuthHandleLeaveLNN(connInfo->authId);
    }
    if (connInfo->nodeInfo != NULL) {
        SoftBusFree(connInfo->nodeInfo);
        connInfo->nodeInfo = NULL;
    }
    if ((connInfo->flag & CONN_INFO_FLAG_JOINING_ACTIVE) != 0) {
        LnnNotifyJoinResult(&connInfo->addr, networkId, retCode);
    }
    connInfo->flag &= ~CONN_INFO_FLAG_JOINING_ACTIVE;
    connInfo->flag &= ~CONN_INFO_FLAG_JOINING_PASSIVE;
    if (retCode != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]join failed, ready clean", connFsm->id);
        connFsm->isDead = true;
        LnnRequestCleanConnectionFsm(&connInfo->addr);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]complete join LNN done", connFsm->id);
}

static void CompleteLeaveLNN(LnnConnectionFsm *connFsm, const char *networkId, int32_t retCode)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;
    NodeInfo *info = NULL;
    const char *udid = NULL;
    ConnectOption option;

    if (retCode == SOFTBUS_OK) {
        info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
        if (info != NULL) {
            udid = LnnGetDeviceUdid(info);
            if (LnnSetNodeOffline(udid, (int32_t)connInfo->authId) == REPORT_OFFLINE) {
                NodeBasicInfo basic;
                (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
                if (LnnGetBasicInfoByUdid(udid, &basic) == SOFTBUS_OK) {
                    LnnNotifyOnlineState(false, &basic);
                }
                // just remove node when peer device is not trusted
                if ((connInfo->flag & CONN_INFO_FLAG_LEAVING_PASSIVE) != 0) {
                    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]remove node", connFsm->id);
                    LnnRemoveNode(udid);
                }
            }
        }
    }
    if (LnnConvertAddrToOption(&connInfo->addr, &option) == true) {
        ConnDisconnectDeviceAllConn(&option);
    }
    if ((connInfo->flag & CONN_INFO_FLAG_LEAVING_ACTIVE) != 0) {
        LnnNotifyLeaveResult(networkId, retCode);
    }
    connInfo->flag &= ~CONN_INFO_FLAG_LEAVING_ACTIVE;
    connInfo->flag &= ~CONN_INFO_FLAG_LEAVING_PASSIVE;
    (void)AuthHandleLeaveLNN(connInfo->authId);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]complete leave lnn, ready clean", connFsm->id);
    connFsm->isDead = true;
    LnnRequestCleanConnectionFsm(&connInfo->addr);
}

static void OnJoinLNNTimeout(LnnConnectionFsm *connFsm)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]join LNN timeout", connFsm->id);
    CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
}

static int32_t OnJoinLNNInAuth(LnnConnectionFsm *connFsm)
{
    int32_t rc;
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if ((connInfo->flag & (CONN_INFO_FLAG_JOINING_ACTIVE | CONN_INFO_FLAG_JOINING_PASSIVE)) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]join LNN is ongoing, waiting...", connFsm->id);
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]begin join request", connFsm->id);
    connInfo->flag |= CONN_INFO_FLAG_JOINING_ACTIVE;
    connInfo->authId = AuthVerifyDevice(LNN, &connInfo->addr);
    if (connInfo->authId <= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]auth verify device failed", connFsm->id);
        CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
        rc = SOFTBUS_ERR;
    } else {
        LnnFsmPostMessageDelay(&connFsm->fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
            NULL, JOIN_LNN_TIMEOUT_LEN);
        rc = SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]verify request authId=%lld", connFsm->id, connInfo->authId);
    return rc;
}

static int32_t OnAuthKeyGeneratedInAuth(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    if ((connInfo->flag & CONN_INFO_FLAG_JOINING_ACTIVE) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]active auth success, transact to syn_device_info state, authId=%llu",
            connFsm->id, connInfo->authId);
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_SYNC_DEVICE_INFO_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO, NULL);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]passive auth success, transact to syn_device_info state, authId=%llu",
            connFsm->id, connInfo->authId);
        connInfo->flag |= CONN_INFO_FLAG_JOINING_PASSIVE;
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

static int32_t OnAuthDisconnect(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth disconnect, authId=%lld",
        connFsm->id, connInfo->authId);
    CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
    return SOFTBUS_OK;
}

static void OnLeaveLNNIgnore(LnnConnectionFsm *connFsm)
{
    LnnNotifyLeaveResult(connFsm->connInfo.peerNetworkId, SOFTBUS_ERR);
}

static bool AuthStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
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
            OnAuthDisconnect(connFsm);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            OnLeaveLNNIgnore(connFsm);
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinLNNTimeout(connFsm);
            break;
        default:
            FreeUnhandledMessage(connFsm, msgType, para);
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

    if (LnnConvertAddrToOption(&connInfo->addr, &option) == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]convert addr to option failed", connFsm->id);
        return SOFTBUS_ERR;
    }
    buf = LnnGetExchangeNodeInfo(&option, SOFT_BUS_NEW_V1, &bufSize, &head.flag);
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
    if (!ParsePeerNodeInfo(para, connInfo)) {
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth done, authId=%lld, auth result=%d",
        connFsm->id, connInfo->authId, *isSuccess);
    if (*isSuccess) {
        LnnFsmTransactState(&connFsm->fsm, g_states + STATE_OFFLINE_INDEX);
        LnnFsmPostMessage(&connFsm->fsm, FSM_MSG_TYPE_EST_HEART_BEAT, NULL);
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
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]sync device info process message: %d",
        connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            connFsm->connInfo.flag |= CONN_INFO_FLAG_JOINING_ACTIVE;
            break;
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
            OnLeaveLNNIgnore(connFsm);
            break;
        case FSM_MSG_TYPE_NOT_TRUSTED:
            CompleteJoinLNN(connFsm, NULL, SOFTBUS_ERR);
            break;
        case FSM_MSG_TYPE_DISCONNECT:
            OnAuthDisconnect(connFsm);
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinLNNTimeout(connFsm);
            break;
        default:
            FreeUnhandledMessage(connFsm, msgType, para);
            return false;
    }
    return true;
}

static void OnSetupHeartBeat(LnnConnectionFsm *connFsm)
{
    // don't support establish heart beat connection
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "no need setup hb, transact to online");
    LnnFsmTransactState(&connFsm->fsm, g_states + STATE_ONLINE_INDEX);
}

static bool OfflineStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]offline process message: %d", connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_LEAVE_LNN:
            OnLeaveLNNIgnore(connFsm);
            break;
        case FSM_MSG_TYPE_DISCONNECT:
            OnAuthDisconnect(connFsm);
            break;
        case FSM_MSG_TYPE_JOIN_LNN:
        case FSM_MSG_TYPE_NOT_TRUSTED: // JOIN and NOT_TRUSTED is same process.
            LnnFsmPostMessage(&connFsm->fsm, msgType, para);
            break;
        case FSM_MSG_TYPE_EST_HEART_BEAT:
            OnSetupHeartBeat(connFsm);
            break;
        default:
            FreeUnhandledMessage(connFsm, msgType, para);
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
    CompleteJoinLNN(connFsm, connFsm->connInfo.nodeInfo->networkId, SOFTBUS_OK);
}

static void OnJoinLNNInOnline(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]request addr is already online", connFsm->id);
    LnnNotifyJoinResult(&connInfo->addr, connInfo->peerNetworkId, SOFTBUS_OK);
}

static void OnLeaveLNNInOnline(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    connInfo->flag |= CONN_INFO_FLAG_LEAVING_ACTIVE;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]no need close hb, transact to leaving state", connFsm->id);
    LnnFsmTransactState(&connFsm->fsm, g_states + STATE_LEAVING_INDEX);
}

static void OnDeviceNotTrustedInOnline(LnnConnectionFsm *connFsm)
{
    LnnConntionInfo *connInfo = &connFsm->connInfo;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]device not trusted, transact to leaving state",
        connFsm->id);
    connInfo->flag |= CONN_INFO_FLAG_LEAVING_PASSIVE;
    LnnFsmTransactState(&connFsm->fsm, g_states + STATE_LEAVING_INDEX);
}

static bool OnlineStateProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    LnnConnectionFsm *connFsm = NULL;

    if (!CheckStateMsgCommonArgs(fsm)) {
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]online process message: %d", connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            OnJoinLNNInOnline(connFsm);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            OnLeaveLNNInOnline(connFsm);
            break;
        case FSM_MSG_TYPE_DISCONNECT:
            OnLeaveLNNInOnline(connFsm);
            break;
        case FSM_MSG_TYPE_NOT_TRUSTED:
            OnDeviceNotTrustedInOnline(connFsm);
            break;
        default:
            FreeUnhandledMessage(connFsm, msgType, para);
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
        return false;
    }
    connFsm = TO_CONN_FSM(fsm);

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]leaving process message: %d", connFsm->id, msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            LnnNotifyJoinResult(&connFsm->connInfo.addr, NULL, SOFTBUS_ERR);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT:
            CompleteLeaveLNN(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_OK);
            break;
        case FSM_MSG_TYPE_SYNC_OFFLINE_DONE:
            LnnFsmRemoveMessage(&connFsm->fsm, FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT);
            CompleteLeaveLNN(connFsm, connFsm->connInfo.peerNetworkId, SOFTBUS_OK);
            break;
        default:
            FreeUnhandledMessage(connFsm, msgType, para);
            return false;
    }
    return true;
}

static uint16_t GetNextConnectionFsmId()
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
    if (connFsm != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "destroy a connection fsm[id=%u]", connFsm->id);
        SoftBusFree(connFsm);
    }
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
    connFsm->isDead = true;
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
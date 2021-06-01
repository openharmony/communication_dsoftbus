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

#include "lnn_net_builder.h"

#include <stdlib.h>

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_conn_type_hook.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_exchange_ledger_info.h"
#include "lnn_network_id.h"
#include "lnn_state_machine.h"
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

typedef struct {
    ConnectionAddr addr;
    NodeInfo *nodeInfo;
    char peerNetworkId[NETWORK_ID_BUF_LEN];
    int64_t authId;
    SoftBusVersion peerVersion;
    uint32_t flag;
} ConnInfo;

typedef struct {
    NodeType nodeType;
    FsmStateMachine fsm;
    ConnInfo connInfo;
    const ConnTypeHook *hook[CONNECTION_ADDR_MAX];
    bool isInit;
} NetBuilder;

typedef struct {
    bool isSuccess;
    int64_t authId;
    ConnectOption connOp;
    SoftBusVersion peerVersion;
} AuthResultMsgPara;

typedef struct {
    int64_t authId;
    AuthSideFlag side;
    char uuid[UUID_BUF_LEN];
    uint8_t *data;
    uint32_t len;
} RecvDeviceInfoMsgPara;

typedef struct {
    char udid[UDID_BUF_LEN];
    SyncItemInfo *info;
} RecvPeerInfoChangeMsgPara;

static NetBuilder g_netBuilder;

static void AuthStateEnter(void);
static bool AuthStateProcess(int32_t msgType, void *para);
static bool SyncDeviceInfoStateProcess(int32_t msgType, void *para);
static bool OfflineStateProcess(int32_t msgType, void *para);
static void OnlineStateEnter(void);
static bool OnlineStateProcess(int32_t msgType, void *para);
static void LeavingStateEnter(void);
static bool LeavingStateProcess(int32_t msgType, void *para);

static FsmState g_states[STATE_NUM_MAX] = {
    [STATE_AUTH_INDEX] = {
        .enter = AuthStateEnter,
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

void __attribute__ ((weak)) LnnInitIpHook(void)
{
}
static bool ConvertAddrToOption(ConnectionAddr *addr, ConnectOption *option)
{
    if (addr->type == CONNECTION_ADDR_BR) {
        option->type = CONNECT_BR;
        if (strncpy_s(option->info.brOption.brMac, BT_MAC_LEN, addr->info.br.brMac,
            strlen(addr->info.br.brMac)) != EOK) {
            LOG_ERR("copy br mac to addr fail");
            return false;
        }
        return true;
    } else if (addr->type == CONNECTION_ADDR_ETH || addr->type == CONNECTION_ADDR_WLAN) {
        option->type = CONNECT_TCP;
        if (strncpy_s(option->info.ipOption.ip, IP_LEN, addr->info.ip.ip,
            strlen(addr->info.ip.ip)) != EOK) {
            LOG_ERR("copy ip  to addr fail");
            return false;
        }
        option->info.ipOption.port = addr->info.ip.port;
        return true;
    }
    LOG_ERR("not supported type: %d", addr->type);
    return false;
}

static bool ConvertOptionToAddr(ConnectionAddr *addr, ConnectOption *option)
{
    if (option->type == CONNECT_BR) {
        addr->type = CONNECTION_ADDR_BR;
        if (strncpy_s(addr->info.br.brMac, BT_MAC_LEN, option->info.brOption.brMac,
            strlen(option->info.brOption.brMac)) != EOK) {
            LOG_ERR("copy br mac to addr fail");
            return false;
        }
        return true;
    }
    if (option->type == CONNECT_TCP) {
        ConnectionAddr *temp = &g_netBuilder.connInfo.addr;
        addr->type = temp->type;
        if (strncpy_s(addr->info.ip.ip, IP_STR_MAX_LEN, option->info.ipOption.ip,
            strlen(option->info.ipOption.ip)) != EOK) {
            LOG_ERR("copy op ip to addr fail");
            return false;
        }
        return true;
    }
    LOG_ERR("not supported type: %d", option->type);
    return false;
}

static void FreeUnhandledMessage(int32_t msgType, void *para)
{
    RecvPeerInfoChangeMsgPara *peerInfo = NULL;

    LOG_INFO("free unhandled msg: %d", msgType);
    if (msgType == FSM_MSG_TYPE_PEER_INFO_CHANGE) {
        peerInfo = (RecvPeerInfoChangeMsgPara *)para;
        if (peerInfo->info != NULL) {
            LnnDeleteSyncItemInfo(peerInfo->info);
        }
    }
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static void CompleteJoinLNN(const char *networkId, int32_t retCode)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;

    LnnFsmRemoveMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT);
    if (retCode == SOFTBUS_OK) {
        if (strncpy_s(connInfo->peerNetworkId, NETWORK_ID_BUF_LEN,
            networkId, strlen(networkId)) == EOK) {
            LnnAddOnlineNode(connInfo->nodeInfo);
        } else {
            LOG_ERR("copy peer network id error");
        }
    } else {
        if (g_netBuilder.hook[connInfo->addr.type] != NULL &&
            g_netBuilder.hook[connInfo->addr.type]->shutdown != NULL) {
            g_netBuilder.hook[connInfo->addr.type]->shutdown(&connInfo->addr);
        }
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
}

static void CompleteLeaveLNN(const char *networkId, int32_t retCode)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    NodeInfo *info = NULL;
    const char *udid = NULL;
    ConnectOption option;

    if (retCode == SOFTBUS_OK) {
        info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
        if (info != NULL) {
            udid = LnnGetDeviceUdid(info);
            LnnSetNodeOffline(udid);
            // just remove node when peer device is not trusted
            if ((connInfo->flag & CONN_INFO_FLAG_LEAVING_PASSIVE) != 0) {
                LOG_INFO("remove node");
                LnnRemoveNode(udid);
            }
        }
    }
    if (g_netBuilder.hook[connInfo->addr.type] != NULL &&
        g_netBuilder.hook[connInfo->addr.type]->shutdown != NULL) {
        g_netBuilder.hook[connInfo->addr.type]->shutdown(&connInfo->addr);
    }
    if (ConvertAddrToOption(&connInfo->addr, &option) == true) {
        ConnDisconnectDeviceAllConn(&option);
    }
    if ((connInfo->flag & CONN_INFO_FLAG_LEAVING_ACTIVE) != 0) {
        LnnNotifyLeaveResult(networkId, retCode);
    }
    connInfo->flag &= ~CONN_INFO_FLAG_LEAVING_ACTIVE;
    connInfo->flag &= ~CONN_INFO_FLAG_LEAVING_PASSIVE;
    (void)AuthHandleLeaveLNN(g_netBuilder.connInfo.authId);
}

static void OnAuthPassed(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion)
{
    if (option == NULL) {
        LOG_ERR("OnAuthPassed option = null!");
        return;
    }
    AuthResultMsgPara *para = SoftBusCalloc(sizeof(*para));
    if (para == NULL) {
        LOG_ERR("malloc auth result fail");
        return;
    }
    para->connOp = *option;
    para->isSuccess = true;
    para->authId = authId;
    para->peerVersion = peerVersion;
    LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_AUTH_DONE, para);
    LOG_INFO("auth passed: %lld", authId);
}

static void OnAuthFailed(int64_t authId, ConnectOption *option)
{
    if (option == NULL) {
        LOG_ERR("option = null!");
        return;
    }
    AuthResultMsgPara *para = SoftBusCalloc(sizeof(*para));
    if (para == NULL) {
        LOG_ERR("malloc auth result fail");
        return;
    }
    para->connOp = *option;
    para->isSuccess = false;
    para->authId = authId;
    LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_AUTH_DONE, para);
    LOG_INFO("auth failed: %lld", authId);
}

static void OnRecvPeerDeviceInfo(int64_t authId, AuthSideFlag side, const char *peerUuid, uint8_t *data, uint32_t len)
{
    RecvDeviceInfoMsgPara *para = NULL;

    if (peerUuid == NULL || data == NULL) {
        LOG_ERR("invalid para");
        return;
    }
    para = SoftBusCalloc(sizeof(*para) + len);
    if (para == NULL) {
        LOG_ERR("malloc device info para fail");
        return;
    }
    para->authId = authId;
    para->side = side;
    if (strncpy_s(para->uuid, UUID_BUF_LEN, peerUuid, strlen(peerUuid)) != EOK) {
        LOG_ERR("copy uuid fail");
        SoftBusFree(para);
        return;
    }
    para->data = (uint8_t *)para + sizeof(*para);
    if (memcpy_s(para->data, len, data, len) != EOK) {
        LOG_ERR("copy uuid fail");
        SoftBusFree(para);
        return;
    }
    para->len = len;
    LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE, para);
}

static void OnDeviceNotTrusted(const char *peerUdid)
{
    char *udid = NULL;
    int32_t udidLen;

    if (peerUdid == NULL) {
        return;
    }
    udidLen = strlen(peerUdid) + 1;
    udid = (char *)SoftBusMalloc(udidLen);
    if (udid == NULL) {
        LOG_ERR("malloc udid fail");
        return;
    }
    if (strncpy_s(udid, udidLen, peerUdid, udidLen) != EOK) {
        LOG_ERR("copy udid fail");
        SoftBusFree(udid);
        return;
    }
    LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_NOT_TRUSTED, udid);
}

static VerifyCallback g_verifyCb = {
    .onDeviceVerifyPass = OnAuthPassed,
    .onDeviceVerifyFail = OnAuthFailed,
    .onRecvSyncDeviceInfo = OnRecvPeerDeviceInfo,
    .onDeviceNotTrusted = OnDeviceNotTrusted,
};

static int32_t InitNetBuilderStateMachine(void)
{
    int32_t rc, i;

    rc = LnnFsmInit(&g_netBuilder.fsm, "NetBuilderSm", NULL);
    if (rc != SOFTBUS_OK) {
        return rc;
    }
    for (i = 0; i < STATE_NUM_MAX; ++i) {
        LnnFsmAddState(&g_netBuilder.fsm, &g_states[i]);
    }
    return SOFTBUS_OK;
}

static void OnJoinLNNTimeout(void)
{
    LOG_ERR("join LNN timeout : auth time out!");
    CompleteJoinLNN(NULL, SOFTBUS_ERR);
    LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
}

static void OnDiscoveryTimeOut(ConnectionAddrType *para)
{
    LOG_ERR("join LNN timeout : discovery time out!");
    if (para == NULL) {
        LOG_ERR("join LNN timeout : para error!");
        return;
    }
    ConnectionAddr addr;
    (void)memset_s(&addr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    addr.type = *para;
    LnnNotifyJoinResult(&addr, NULL, SOFTBUS_ERR);
    LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
    if (g_netBuilder.hook[*para] != NULL &&
        g_netBuilder.hook[*para]->shutdown != NULL) {
        g_netBuilder.hook[*para]->shutdown(NULL);
    }
    SoftBusFree(para);
}

static void AuthStateEnter(void)
{
    char uuid[UUID_BUF_LEN];
    char networkId[NETWORK_ID_BUF_LEN];

    LOG_INFO("auth state enter");
    if (LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK ||
        LnnGenLocalUuid(uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("get local id fail");
        return;
    }
    LnnSetLocalStrInfo(STRING_KEY_UUID, uuid);
    LnnSetLocalStrInfo(STRING_KEY_NETWORKID, networkId);
    if (AuthRegCallback(LNN, &g_verifyCb) != SOFTBUS_OK) {
        LOG_ERR("register auth cb fail");
    }
}

static int32_t OnJoinLNNInAuth(ConnectionAddr *addr)
{
    int32_t rc;
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    ConnectOption option;

    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (ConvertAddrToOption(addr, &option) == false) {
        SoftBusFree(addr);
        return SOFTBUS_ERR;
    }

    if ((connInfo->flag & (CONN_INFO_FLAG_JOINING_ACTIVE |
        CONN_INFO_FLAG_JOINING_PASSIVE)) != 0) {
        if (LnnIsSameConnectionAddr(addr, &connInfo->addr) == true) {
            LOG_INFO("addr is same, waiting...");
            SoftBusFree(addr);
            return SOFTBUS_OK;
        }
        LOG_ERR("previous request is ongoing, reject it");
        LnnNotifyJoinResult(addr, NULL, SOFTBUS_ERR);
        SoftBusFree(addr);
        return SOFTBUS_OK;
    }
    LOG_INFO("begin a new join request");
    connInfo->addr = *addr;
    connInfo->flag |= CONN_INFO_FLAG_JOINING_ACTIVE;
    (void)AuthVerifyInit();
    LOG_INFO("hichain init ok....");
    rc = AuthVerifyDevice(LNN, &option);
    if (rc != SOFTBUS_OK) {
        CompleteJoinLNN(NULL, SOFTBUS_ERR);
        (void)AuthVerifyDeinit();
    } else {
        LnnFsmPostMessageDelay(&g_netBuilder.fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
            NULL, JOIN_LNN_TIMEOUT_LEN);
    }
    SoftBusFree(addr);
    LOG_INFO("rc = %d", rc);
    return rc;
}

static int32_t OnAuthDoneInAuth(AuthResultMsgPara *para)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;

    if (para == NULL) {
        LOG_ERR("unexpected null result");
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectionAddr addr = {0};
    ConvertOptionToAddr(&addr, &para->connOp);
    LOG_INFO("auth done, authId = %lld", para->authId);
    if ((connInfo->flag & CONN_INFO_FLAG_JOINING_ACTIVE) != 0) {
        if (LnnIsSameConnectionAddr(&connInfo->addr, &addr) == false) {
            LOG_ERR("unexpected auth done when joining");
            SoftBusFree(para);
            return SOFTBUS_OK;
        }
        if (para->isSuccess) {
            LOG_INFO("active auth success, transact to syn_device_info state");
            connInfo->authId = para->authId;
            connInfo->peerVersion = para->peerVersion;
            LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_SYNC_DEVICE_INFO_INDEX);
            LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO, NULL);
        } else {
            LOG_ERR("auth failed");
            CompleteJoinLNN(NULL, SOFTBUS_ERR);
        }
    } else {
        if (para->isSuccess) {
            LOG_INFO("passive auth success, transact to syn_device_info state");
            connInfo->authId = para->authId;
            connInfo->addr = addr;
            connInfo->peerVersion = para->peerVersion;
            connInfo->flag |= CONN_INFO_FLAG_JOINING_PASSIVE;
            LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_SYNC_DEVICE_INFO_INDEX);
            LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_SYNC_DEVICE_INFO, NULL);
            LnnFsmPostMessageDelay(&g_netBuilder.fsm, FSM_MSG_TYPE_JOIN_LNN_TIMEOUT,
                NULL, JOIN_LNN_TIMEOUT_LEN);
        } else {
            LOG_INFO("ignore failure auth result");
        }
    }
    (void)AuthVerifyDeinit();
    SoftBusFree(para);
    return SOFTBUS_OK;
}

static bool AuthStateProcess(int32_t msgType, void *para)
{
    LOG_INFO("auth process message: %d", msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            OnJoinLNNInAuth((ConnectionAddr *)para);
            break;
        case FSM_MSG_TYPE_DISCOVERY_TIMEOUT:
            OnDiscoveryTimeOut((ConnectionAddrType *)para);
            break;
        case FSM_MSG_TYPE_AUTH_DONE:
            OnAuthDoneInAuth((AuthResultMsgPara *)para);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            if (para != NULL) {
                LnnNotifyLeaveResult((char *)para, SOFTBUS_ERR);
                SoftBusFree(para);
            }
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinLNNTimeout();
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static int32_t OnJoinLNNInSynInfo(ConnectionAddr *addr)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    int32_t rc = SOFTBUS_OK;

    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (LnnIsSameConnectionAddr(addr, &connInfo->addr) == false) {
        LOG_ERR("previous request is ongoing, reject now request");
        LnnNotifyJoinResult(addr, NULL, false);
        rc = SOFTBUS_ERR;
    } else {
        LOG_INFO("addr is same, waiting...");
    }
    SoftBusFree(addr);
    return rc;
}

static int32_t OnSyncDeviceInfo(void)
{
    uint8_t *buf = NULL;
    uint32_t bufSize;
    int32_t rc;
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    AuthDataHead head;
    ConnectOption option;

    if (ConvertAddrToOption(&connInfo->addr, &option) == false) {
        return SOFTBUS_ERR;
    }
    buf = LnnGetExchangeNodeInfo(&option, SOFT_BUS_NEW_V1, &bufSize, &head.flag);
    if (buf == NULL) {
        LOG_ERR("pack local device info fail");
        CompleteJoinLNN(NULL, SOFTBUS_ERR);
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
        CompleteJoinLNN(NULL, SOFTBUS_ERR);
    }
    SoftBusFree(buf);
    LOG_INFO("rc = %d", rc);
    return rc;
}

static DiscoveryType GetDiscoveryType(ConnectType type)
{
    if (type == CONNECT_TCP) {
        return DISCOVERY_TYPE_WIFI;
    } else if (type == CONNECT_BR) {
        return DISCOVERY_TYPE_BR;
    } else {
        return DISCOVERY_TYPE_BLE;
    }
}

static bool ParsePeerNodeInfo(RecvDeviceInfoMsgPara *para, ConnInfo *connInfo)
{
    ParseBuf parseBuf;
    int32_t rc = SOFTBUS_OK;
    ConnectOption option;
    do {
        if (connInfo->nodeInfo == NULL) {
            connInfo->nodeInfo = SoftBusCalloc(sizeof(NodeInfo));
            if (connInfo->nodeInfo == NULL) {
                LOG_ERR("malloc node info fail");
                rc = SOFTBUS_MALLOC_ERR;
                break;
            }
        }
        if (ConvertAddrToOption(&connInfo->addr, &option) == false) {
            rc = SOFTBUS_ERR;
            break;
        }
        parseBuf.buf = para->data;
        parseBuf.len = para->len;
        if (LnnParsePeerNodeInfo(&option, connInfo->nodeInfo,
            &parseBuf, para->side, connInfo->peerVersion) != SOFTBUS_OK) {
            CompleteJoinLNN(NULL, SOFTBUS_ERR);
            LOG_ERR("unpack peer device info fail");
            rc = SOFTBUS_ERR;
            break;
        }
        connInfo->nodeInfo->discoveryType = 1 << (uint32_t)GetDiscoveryType(option.type);
        connInfo->nodeInfo->authSeqNum = connInfo->authId;
        if (strncpy_s(connInfo->nodeInfo->uuid, UUID_BUF_LEN, para->uuid, strlen(para->uuid)) != EOK) {
            LOG_ERR("strncpy_s uuid failed");
            rc = SOFTBUS_ERR;
            break;
        }
        if (option.type == CONNECT_TCP) {
            if (strncpy_s(connInfo->nodeInfo->connectInfo.deviceIp, IP_MAX_LEN, connInfo->addr.info.ip.ip,
                strlen(connInfo->addr.info.ip.ip)) != EOK) {
                LOG_ERR("strncpy_s deviceIp failed");
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

static int32_t OnSyncDeviceInfoDone(RecvDeviceInfoMsgPara *para)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    if (para == NULL) {
        LOG_ERR("unexpected para");
        return SOFTBUS_ERR;
    }
    if (para->authId != connInfo->authId) {
        LOG_INFO("unexpected authId:%lld, expected authId:%lld", para->authId, connInfo->authId);
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    if (connInfo->peerVersion >= SOFT_BUS_NEW_V1) {
        LOG_ERR("unexpected peer version: %d", connInfo->peerVersion);
        CompleteJoinLNN(NULL, SOFTBUS_ERR);
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    if (!ParsePeerNodeInfo(para, connInfo)) {
        LOG_ERR("ParsePeerNodeInfo error");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    SoftBusFree(para);
    LOG_INFO("recv peer device info, transact to offline");
    LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_OFFLINE_INDEX);
    LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_EST_HEART_BEAT, NULL);
    return SOFTBUS_OK;
}

static int32_t OnDeviceNotTrustedInSynInfo(char *peerUdid)
{
    const char *udid = NULL;

    if (peerUdid == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_netBuilder.connInfo.nodeInfo != NULL) {
        udid = LnnGetDeviceUdid(g_netBuilder.connInfo.nodeInfo);
        if (udid != NULL && strcmp(peerUdid, udid) == 0) {
            LOG_INFO("peer device is not trusted, complete join process");
            CompleteJoinLNN(NULL, SOFTBUS_ERR);
            LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
        }
    } else {
        LOG_INFO("ignore not trusted peer udid");
    }
    SoftBusFree(peerUdid);
    return SOFTBUS_OK;
}

static bool SyncDeviceInfoStateProcess(int32_t msgType, void *para)
{
    LOG_INFO("sync device info process message: %d", msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            OnJoinLNNInSynInfo((ConnectionAddr *)para);
            break;
        case FSM_MSG_TYPE_SYNC_DEVICE_INFO:
            OnSyncDeviceInfo();
            break;
        case FSM_MSG_TYPE_SYNC_DEVICE_INFO_DONE:
            OnSyncDeviceInfoDone((RecvDeviceInfoMsgPara *)para);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            if (para != NULL) {
                LnnNotifyLeaveResult((char *)para, SOFTBUS_ERR);
                SoftBusFree(para);
            }
            break;
        case FSM_MSG_TYPE_NOT_TRUSTED:
            OnDeviceNotTrustedInSynInfo((char *)para);
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinLNNTimeout();
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static void OnSetupHeartBeat(void)
{
    // don't support establish heart beat connection
    LOG_INFO("no need setup hb, transact to online");
    LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_ONLINE_INDEX);
}

static bool OfflineStateProcess(int32_t msgType, void *para)
{
    LOG_INFO("offline process message: %d", msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
        case FSM_MSG_TYPE_LEAVE_LNN:
        case FSM_MSG_TYPE_NOT_TRUSTED: // JOIN LEAVE and NOT_TRUSTED is same process.
            LnnFsmPostMessage(&g_netBuilder.fsm, msgType, para);
            break;
        case FSM_MSG_TYPE_EST_HEART_BEAT:
            OnSetupHeartBeat();
            break;
        case FSM_MSG_TYPE_JOIN_LNN_TIMEOUT:
            OnJoinLNNTimeout();
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static void OnlineStateEnter(void)
{
    LOG_INFO("online state enter");
    CompleteJoinLNN(g_netBuilder.connInfo.nodeInfo->networkId, SOFTBUS_OK);
}

static int32_t OnJoinLNNInOnline(ConnectionAddr *addr)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    int32_t rc = SOFTBUS_OK;

    if (addr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (LnnIsSameConnectionAddr(addr, &connInfo->addr) == true) {
        LOG_INFO("request addr is already online");
        LnnNotifyJoinResult(addr, connInfo->peerNetworkId, 0);
        rc = SOFTBUS_ERR;
    } else {
        LOG_INFO("previous is online, plz let it leave");
        LnnNotifyJoinResult(addr, NULL, SOFTBUS_ERR);
    }
    SoftBusFree(addr);
    return rc;
}

static bool IsNotNeedToCloseHb(ConnectionAddrType type)
{
    return ((type == CONNECTION_ADDR_BR) || (type == CONNECTION_ADDR_ETH) || (type == CONNECTION_ADDR_WLAN));
}

static int32_t OnLeaveLNNInOnline(char *networkId)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    int32_t rc = SOFTBUS_ERR;

    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (strcmp(networkId, connInfo->peerNetworkId) == 0) {
        connInfo->flag |= CONN_INFO_FLAG_LEAVING_ACTIVE;
        if (IsNotNeedToCloseHb(connInfo->addr.type)) {
            LOG_INFO("no need close hb, transact to auth");
            LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_LEAVING_INDEX);
            rc = SOFTBUS_OK;
        } else {
            LOG_ERR("not support connection type: %d", connInfo->addr.type);
            CompleteLeaveLNN(networkId, SOFTBUS_ERR);
        }
    } else {
        LOG_INFO("invalid leave lnn request, target device is in offline");
        LnnNotifyLeaveResult(networkId, SOFTBUS_ERR);
    }
    SoftBusFree(networkId);
    return rc;
}

static int32_t OnDeviceNotTrustedInOnline(char *peerUdid)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;
    NodeInfo *info = NULL;

    info = LnnGetNodeInfoById(peerUdid, CATEGORY_UDID);
    if (info != NULL) {
        LOG_INFO("device not trusted, transact auth");
        connInfo->flag |= CONN_INFO_FLAG_LEAVING_PASSIVE;
        LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_LEAVING_INDEX);
    } else {
        LOG_INFO("ignore not trusted peer uuid");
    }
    SoftBusFree(peerUdid);
    return SOFTBUS_OK;
}

static int32_t OnPeerDevInfoChanged(RecvPeerInfoChangeMsgPara *para)
{
    int32_t rc = SOFTBUS_ERR;

    if (para == NULL || para->info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (para->info->type == INFO_TYPE_DEVICE_NAME) {
        LOG_INFO("peer device info changed.");
        LnnSetDLDeviceInfoName(para->udid, (char *)para->info->buf);
        rc = SOFTBUS_OK;
    } else {
        LOG_ERR("invalid peer dev info change type: %d", para->info->type);
    }
    LnnDeleteSyncItemInfo(para->info);
    SoftBusFree(para);
    return rc;
}

static bool OnlineStateProcess(int32_t msgType, void *para)
{
    LOG_INFO("online process message: %d", msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            OnJoinLNNInOnline((ConnectionAddr *)para);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            OnLeaveLNNInOnline((char *)para);
            break;
        case FSM_MSG_TYPE_NOT_TRUSTED:
            OnDeviceNotTrustedInOnline((char *)para);
            break;
        case FSM_MSG_TYPE_PEER_INFO_CHANGE:
            OnPeerDevInfoChanged((RecvPeerInfoChangeMsgPara *)para);
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static void LeavingStateEnter(void)
{
    int32_t rc;
    ConnInfo *connInfo = &g_netBuilder.connInfo;

    LOG_INFO("leaving state enter");
    rc = LnnSyncLedgerItemInfo(connInfo->peerNetworkId, DISCOVERY_TYPE_BR, INFO_TYPE_OFFLINE);
    if (rc == SOFTBUS_OK) {
        LnnFsmPostMessageDelay(&g_netBuilder.fsm, FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT,
            NULL, LEAVE_LNN_TIMEOUT_LEN);
    } else {
        LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
        CompleteLeaveLNN(connInfo->peerNetworkId, SOFTBUS_OK);
    }
}

static void OnLeaveLNNInLeaving(char *networkId)
{
    ConnInfo *connInfo = &g_netBuilder.connInfo;

    if (networkId == NULL) {
        LOG_ERR("param error");
        return;
    }

    if (strcmp(networkId, connInfo->peerNetworkId) != 0) {
        LOG_INFO("not compare network id");
        LnnNotifyLeaveResult(networkId, SOFTBUS_ERR);
    } else {
        LOG_INFO("already in leaving, wait result");
    }
    SoftBusFree(networkId);
}

static bool LeavingStateProcess(int32_t msgType, void *para)
{
    LOG_INFO("leaving process message: %d", msgType);
    switch (msgType) {
        case FSM_MSG_TYPE_JOIN_LNN:
            if (para != NULL) {
                LnnNotifyJoinResult((ConnectionAddr *)para, NULL, SOFTBUS_ERR);
                SoftBusFree(para);
            }
            break;
        case FSM_MSG_TYPE_LEAVE_LNN:
            OnLeaveLNNInLeaving((char *)para);
            break;
        case FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT:
            CompleteLeaveLNN(g_netBuilder.connInfo.peerNetworkId, SOFTBUS_OK);
            LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
            break;
        case FSM_MSG_TYPE_SYNC_OFFLINE_DONE:
            LnnFsmRemoveMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_LEAVE_LNN_TIMEOUT);
            CompleteLeaveLNN(g_netBuilder.connInfo.peerNetworkId, SOFTBUS_OK);
            LnnFsmTransactState(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
            break;
        case FSM_MSG_TYPE_SEND_OFFLINE_MESSAGE:
            if (para != NULL) {
                LnnSendMessageToPeer(*(int32_t *)para);
                SoftBusFree(para);
            }
            break;
        default:
            FreeUnhandledMessage(msgType, para);
            return false;
    }
    return true;
}

static int32_t ConnTypeDefaultHook(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;
    para = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (para == NULL) {
        LOG_ERR("malloc init message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = *addr;
    return LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_JOIN_LNN, para);
}

int32_t LnnRegisterConnTypeHook(ConnectionAddrType type, const ConnTypeHook *hook)
{
    if (type < 0 || type >= CONNECTION_ADDR_MAX) {
        LOG_ERR("fail : para error!");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netBuilder.hook[type] != NULL) {
        LOG_INFO("type = %d, already add.", type);
    }
    g_netBuilder.hook[type] = hook;
    return SOFTBUS_OK;
}

int32_t LnnInitNetBuilder(void)
{
    int rc;

    if (g_netBuilder.isInit == true) {
        return SOFTBUS_OK;
    }

    rc = InitNetBuilderStateMachine();
    if (rc == SOFTBUS_OK) {
        rc = LnnFsmStart(&g_netBuilder.fsm, g_states + STATE_AUTH_INDEX);
    }
    (void)memset_s(g_netBuilder.hook, sizeof(g_netBuilder.hook), 0, sizeof(g_netBuilder.hook));
    g_netBuilder.nodeType = NODE_TYPE_L;
    g_netBuilder.isInit = true;
    LnnInitIpHook();
    LOG_INFO("init net builder result: %d", rc);
    return rc;
}

void LnnDeinitNetBuilder(void)
{
    if (g_netBuilder.isInit == true) {
        (void)LnnFsmStop(&g_netBuilder.fsm);
        (void)LnnFsmDeinit(&g_netBuilder.fsm);
        g_netBuilder.isInit = false;
    }
}

int32_t LnnNotifyPeerDevInfoChanged(const char *udid, SyncItemInfo *info)
{
    RecvPeerInfoChangeMsgPara *para = NULL;

    if (udid == NULL || info == NULL || info->buf == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    para = SoftBusCalloc(sizeof(*para));
    if (para == NULL) {
        LOG_ERR("malloc recv peer info change para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para->udid, UDID_BUF_LEN, udid, strlen(udid)) != EOK) {
        LOG_ERR("copy udid fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    para->info = info;
    LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_PEER_INFO_CHANGE, para);
    return SOFTBUS_OK;
}

static int32_t ConvertTypeToNetCap(ConnectionAddrType type, uint32_t *cap)
{
    if (cap == NULL) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (type == CONNECTION_ADDR_WLAN) {
        (void)LnnSetNetCapability(cap, BIT_WIFI);
        (void)LnnSetNetCapability(cap, BIT_WIFI_24G);
    } else if (type == CONNECTION_ADDR_BR) {
        (void)LnnSetNetCapability(cap, BIT_BR);
    } else if (type == CONNECTION_ADDR_BLE) {
        (void)LnnSetNetCapability(cap, BIT_BLE);
    } else if (type == CONNECTION_ADDR_ETH) {
        (void)LnnSetNetCapability(cap, BIT_ETH);
    } else {
        LOG_ERR("type not right: type = %d", type);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnServerJoin(ConnectionAddr *addr)
{
    LOG_INFO("LnnServerJoin enter!");
    if (addr == NULL || addr->type < CONNECTION_ADDR_WLAN || addr->type > CONNECTION_ADDR_ETH) {
        LOG_ERR("para error!");
        return SOFTBUS_ERR;
    }
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }

    uint32_t cap = 0;
    if (ConvertTypeToNetCap(addr->type, &cap) != SOFTBUS_OK) {
        LOG_ERR("ConvertTypeToNetCap error!");
        return SOFTBUS_ERR;
    }
    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t)cap) != SOFTBUS_OK) {
        LOG_ERR("LnnSetLocalNumInfo error!");
        return SOFTBUS_ERR;
    }

    if (g_netBuilder.hook[addr->type] != NULL) {
        LOG_INFO("LnnServerJoin enter hook");
        return g_netBuilder.hook[addr->type]->preprocess(addr, &g_netBuilder.fsm, NETWORK_TYPE_ACTIVE);
    }
    return ConnTypeDefaultHook(addr);
}

int32_t LnnServerLeave(const char *networkId)
{
    char *para = NULL;

    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    para = (char *)SoftBusCalloc(NETWORK_ID_BUF_LEN);
    if (para == NULL) {
        LOG_ERR("malloc init message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LOG_ERR("copy network id fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_LEAVE_LNN, para);
}

int32_t LnnNotifySyncOfflineFinish()
{
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_SYNC_OFFLINE_DONE, NULL);
}

int32_t LnnNotifySendOfflineMessage(int32_t id)
{
    int32_t *para = NULL;

    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    LOG_INFO("LnnNotifySendOfflineMessage enter!");
    para = (int32_t *)SoftBusCalloc(sizeof(int32_t));
    if (para == NULL) {
        LOG_ERR("malloc id message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = id;
    return LnnFsmPostMessage(&g_netBuilder.fsm, FSM_MSG_TYPE_SEND_OFFLINE_MESSAGE, para);
}

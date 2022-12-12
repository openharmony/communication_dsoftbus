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

#include <securec.h>
#include <stdlib.h>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_discovery_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_exchange_device_info.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_ip_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_id.h"
#include "lnn_network_manager.h"
#include "lnn_node_weight.h"
#include "lnn_p2p_info.h"
#include "lnn_sync_info_manager.h"
#include "lnn_topo_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

#define LNN_CONN_CAPABILITY_MSG_LEN 8
#define DEFAULT_MAX_LNN_CONNECTION_COUNT 10
#define JSON_KEY_MASTER_UDID "MasterUdid"
#define JSON_KEY_MASTER_WEIGHT "MasterWeight"

typedef enum {
    LNN_MSG_ID_ELECT,
    LNN_MSG_ID_MAX
} LnnMsgType;

typedef enum {
    MSG_TYPE_JOIN_LNN = 0,
    MSG_TYPE_DISCOVERY_DEVICE,
    MSG_TYPE_CLEAN_CONN_FSM,
    MSG_TYPE_AUTH_KEY_GENERATED,
    MSG_TYPE_AUTH_DONE,
    MSG_TYPE_SYNC_DEVICE_INFO_DONE = 5,
    MSG_TYPE_NOT_TRUSTED,
    MSG_TYPE_DISCONNECT,
    MSG_TYPE_LEAVE_LNN,
    MSG_TYPE_SYNC_OFFLINE_FINISH,
    MSG_TYPE_NODE_STATE_CHANGED = 10,
    MSG_TYPE_MASTER_ELECT,
    MSG_TYPE_LEAVE_INVALID_CONN,
    MSG_TYPE_LEAVE_BY_ADDR_TYPE,
    MSG_TYPE_LEAVE_SPECIFIC,
    MSG_TYPE_MAX,
} NetBuilderMessageType;

typedef int32_t (*NetBuilderMessageProcess)(const void *para);

typedef struct {
    ListNode node;
    ConnectionAddr addr;
    bool needReportFailure;
} PendingJoinRequestNode;

typedef struct {
    NodeType nodeType;

    /* connection fsm list */
    ListNode fsmList;
    ListNode pendingList;
    /* connection count */
    int32_t connCount;

    SoftBusLooper *looper;
    SoftBusHandler handler;

    int32_t maxConnCount;
    int32_t maxConcurrentCount;
    bool isInit;
} NetBuilder;

typedef struct {
    ConnectionAddr addr;
    int64_t authId;
    SoftBusVersion peerVersion;
} AuthKeyGeneratedMsgPara;

typedef struct {
    int32_t retCode;
    int64_t authId;
} AuthResultMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    char masterUdid[UDID_BUF_LEN];
    int32_t masterWeight;
} ElectMsgPara;

typedef struct {
    char oldNetworkId[NETWORK_ID_BUF_LEN];
    ConnectionAddrType addrType;
    char newNetworkId[NETWORK_ID_BUF_LEN];
} LeaveInvalidConnMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    ConnectionAddrType addrType;
} SpecificLeaveMsgPara;

static NetBuilder g_netBuilder;

static void NetBuilderConfigInit(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_LNN_CONNECTION_CNT,
        (unsigned char*)&g_netBuilder.maxConnCount, sizeof(g_netBuilder.maxConnCount)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get lnn max connection count fail, use default value");
        g_netBuilder.maxConnCount = DEFAULT_MAX_LNN_CONNECTION_COUNT;
    }
    if (SoftbusGetConfig(SOFTBUS_INT_LNN_MAX_CONCURENT_NUM,
        (unsigned char*)&g_netBuilder.maxConcurrentCount, sizeof(g_netBuilder.maxConnCount)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get lnn max conncurent count fail, use default value");
        g_netBuilder.maxConcurrentCount = 0;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "lnn config is %d,%d",
        g_netBuilder.maxConnCount, g_netBuilder.maxConcurrentCount);
}

static SoftBusMessage *CreateNetBuilderMessage(int32_t msgType, void *para)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc softbus message failed");
        return NULL;
    }
    msg->what = msgType;
    msg->obj = para;
    msg->handler = &g_netBuilder.handler;
    return msg;
}

static int32_t PostMessageToHandler(int32_t msgType, void *para)
{
    SoftBusMessage *msg = CreateNetBuilderMessage(msgType, para);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create softbus message failed");
        return SOFTBUS_ERR;
    }
    g_netBuilder.looper->PostMessage(g_netBuilder.looper, msg);
    return SOFTBUS_OK;
}

static LnnConnectionFsm *FindConnectionFsmByAddr(const ConnectionAddr *addr)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (LnnIsSameConnectionAddr(addr, &item->connInfo.addr)) {
            return item;
        }
    }
    return NULL;
}

static LnnConnectionFsm *FindConnectionFsmByAuthId(int64_t authId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->connInfo.authId == authId) {
            return item;
        }
    }
    return NULL;
}

static LnnConnectionFsm *FindConnectionFsmByNetworkId(const char *networkId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) == 0) {
            return item;
        }
    }
    return NULL;
}

static LnnConnectionFsm *FindConnectionFsmByUdid(const char *targetUdid)
{
    LnnConnectionFsm *item = NULL;
    const char *udid = NULL;
    NodeInfo *info = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->connInfo.nodeInfo == NULL) {
            continue;
        }
        udid = LnnGetDeviceUdid(item->connInfo.nodeInfo);
        if (udid != NULL && strcmp(targetUdid, udid) == 0) {
            return item;
        }
    }
    // maybe target device is already online, so find it node info from ledger
    info = LnnGetNodeInfoById(targetUdid, CATEGORY_UDID);
    if (info != NULL) {
        return FindConnectionFsmByNetworkId(info->networkId);
    }
    return NULL;
}

static LnnConnectionFsm *FindConnectionFsmByConnFsmId(uint16_t connFsmId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (connFsmId == item->id) {
            return item;
        }
    }
    return NULL;
}

static LnnConnectionFsm *StartNewConnectionFsm(const ConnectionAddr *addr)
{
    LnnConnectionFsm *connFsm = NULL;

    if (g_netBuilder.connCount >= g_netBuilder.maxConnCount) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "current connection is exceed max limit: %d",
            g_netBuilder.connCount);
        return NULL;
    }
    connFsm = LnnCreateConnectionFsm(addr);
    if (connFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create connection fsm failed");
        return NULL;
    }
    if (LnnStartConnectionFsm(connFsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start connection fsm[id=%u] failed", connFsm->id);
        LnnDestroyConnectionFsm(connFsm);
        return NULL;
    }
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    ++g_netBuilder.connCount;
    return connFsm;
}

static bool IsNodeOnline(const char *networkId)
{
    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo != NULL && LnnIsNodeOnline(nodeInfo)) {
        return true;
    }
    return false;
}

static void UpdateLocalMasterNode(const char *masterUdid, int32_t weight)
{
    if (LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local master udid failed");
        return;
    }
    if (LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local master weight failed");
    }
    if (LnnNotifyMasterNodeChanged(masterUdid, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "notify master node change to heartbeat module failed");
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update local master weight=%d", weight);
}

static int32_t SyncElectMessage(const char *networkId)
{
    char masterUdid[UDID_BUF_LEN] = {0};
    int32_t masterWeight;
    char *data = NULL;
    cJSON *json = NULL;
    int32_t rc;

    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &masterWeight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local master node info failed");
        return SOFTBUS_INVALID_PARAM;
    }
    json = cJSON_CreateObject();
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create elect json object failed");
        return SOFTBUS_ERR;
    }
    if (!AddStringToJsonObject(json, JSON_KEY_MASTER_UDID, masterUdid) ||
        !AddNumberToJsonObject(json, JSON_KEY_MASTER_WEIGHT, masterWeight)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "add elect info to json failed");
        cJSON_Delete(json);
        return SOFTBUS_ERR;
    }
    data = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "format elect packet fail");
        return SOFTBUS_ERR;
    }
    rc = LnnSendSyncInfoMsg(LNN_INFO_TYPE_MASTER_ELECT, networkId, (uint8_t *)data, strlen(data) + 1, NULL);
    cJSON_free(data);
    return rc;
}

static void SendElectMessageToAll(const char *skipNetworkId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (skipNetworkId != NULL && strcmp(item->connInfo.peerNetworkId, skipNetworkId) == 0) {
            continue;
        }
        if (!IsNodeOnline(item->connInfo.peerNetworkId)) {
            continue;
        }
        if (SyncElectMessage(item->connInfo.peerNetworkId) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync elect info to connFsm(%u) failed", item->id);
        }
    }
}

static bool NeedPendingJoinRequest(void)
{
    int32_t count = 0;
    LnnConnectionFsm *item = NULL;

    if (g_netBuilder.maxConcurrentCount == 0) { // do not limit concurent
        return false;
    }
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->isDead) {
            continue;
        }
        if ((item->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) != 0) {
            continue;
        }
        ++count;
        if (count >= g_netBuilder.maxConcurrentCount) {
            return true;
        }
    }
    return false;
}

static bool TryPendingJoinRequest(const ConnectionAddr *addr, bool needReportFailure)
{
    PendingJoinRequestNode *request = NULL;

    if (!NeedPendingJoinRequest()) {
        return false;
    }
    request = SoftBusCalloc(sizeof(PendingJoinRequestNode));
    if (request == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc pending join request fail, go on it");
        return false;
    }
    ListInit(&request->node);
    request->addr = *addr;
    request->needReportFailure = needReportFailure;
    ListTailInsert(&g_netBuilder.pendingList, &request->node);
    return true;
}

static int32_t PostJoinRequestToConnFsm(LnnConnectionFsm *connFsm, const ConnectionAddr *addr, bool needReportFailure)
{
    int32_t rc = SOFTBUS_OK;
    bool isCreate = false;

    if (connFsm == NULL) {
        connFsm = FindConnectionFsmByAddr(addr);
    }
    if (connFsm == NULL || connFsm->isDead) {
        connFsm = StartNewConnectionFsm(addr);
        isCreate = true;
    }
    if (connFsm == NULL || LnnSendJoinRequestToConnFsm(connFsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "process join lnn request failed");
        if (needReportFailure) {
            LnnNotifyJoinResult((ConnectionAddr *)addr, NULL, SOFTBUS_ERR);
        }
        if (connFsm != NULL && isCreate) {
            LnnDestroyConnectionFsm(connFsm);
        }
        rc = SOFTBUS_ERR;
    }
    if (rc == SOFTBUS_OK) {
        connFsm->connInfo.flag |=
            (needReportFailure ? LNN_CONN_INFO_FLAG_JOIN_REQUEST : LNN_CONN_INFO_FLAG_JOIN_AUTO);
    }
    return rc;
}

static void TryRemovePendingJoinRequest(void)
{
    PendingJoinRequestNode *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.pendingList, PendingJoinRequestNode, node) {
        if (NeedPendingJoinRequest()) {
            return;
        }
        ListDelete(&item->node);
        if (PostJoinRequestToConnFsm(NULL, &item->addr, item->needReportFailure) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post pending join request failed");
        }
        SoftBusFree(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "remove a pending join request");
        break;
    }
}

static int32_t TrySendJoinLNNRequest(const ConnectionAddr *addr, bool needReportFailure)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc;

    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "addr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByAddr(addr);
    if (connFsm == NULL || connFsm->isDead) {
        if (TryPendingJoinRequest(addr, needReportFailure)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "join request is pending");
            SoftBusFree((void *)addr);
            return SOFTBUS_OK;
        }
    }
    rc = PostJoinRequestToConnFsm(connFsm, addr, needReportFailure);
    SoftBusFree((void *)addr);
    return rc;
}

static int32_t ProcessJoinLNNRequest(const void *para)
{
    return TrySendJoinLNNRequest((const ConnectionAddr *)para, true);
}

static int32_t ProcessDevDiscoveryRequest(const void *para)
{
    return TrySendJoinLNNRequest((const ConnectionAddr *)para, false);
}

static void InitiateNewNetworkOnline(ConnectionAddrType addrType, const char *networkId)
{
    LnnConnectionFsm *item = NULL;
    int32_t rc;

    // find target connfsm, then notify it online
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) != 0) {
            continue;
        }
        if (item->isDead) {
            continue;
        }
        if (addrType != CONNECTION_ADDR_MAX && addrType != item->connInfo.addr.type) {
            continue;
        }
        rc = LnnSendNewNetworkOnlineToConnFsm(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "initiate new network online to connection fsm[id=%u], rc=%d", item->id, rc);
    }
}

static void TryInitiateNewNetworkOnline(const LnnConnectionFsm *connFsm)
{
    LnnConnectionFsm *item = NULL;
    LnnInvalidCleanInfo *cleanInfo = connFsm->connInfo.cleanInfo;

    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_INITIATE_ONLINE) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]no need initiate new network online", connFsm->id);
        return;
    }
    // let last invalid connfsm notify new network online after it clean
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (strcmp(connFsm->connInfo.peerNetworkId, item->connInfo.peerNetworkId) != 0) {
            continue;
        }
        if ((item->connInfo.flag & LNN_CONN_INFO_FLAG_INITIATE_ONLINE) == 0) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]wait last connfsm clean, then initiate new network online", connFsm->id);
        return;
    }
    InitiateNewNetworkOnline(cleanInfo->addrType, cleanInfo->networkId);
}

static void TryDisconnectAllConnection(const LnnConnectionFsm *connFsm)
{
    LnnConnectionFsm *item = NULL;
    const ConnectionAddr *addr1 = &connFsm->connInfo.addr;
    const ConnectionAddr *addr2 = NULL;
    ConnectOption option;

    // Not realy leaving lnn
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) == 0) {
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        addr2 = &item->connInfo.addr;
        if (addr1->type != addr2->type) {
            continue;
        }
        if (addr1->type == CONNECTION_ADDR_BR || addr1->type == CONNECTION_ADDR_BLE) {
            if (strncmp(item->connInfo.addr.info.br.brMac, addr2->info.br.brMac, BT_MAC_LEN) == 0) {
                return;
            }
        } else if (addr1->type == CONNECTION_ADDR_WLAN || addr1->type == CONNECTION_ADDR_ETH) {
            if (strncmp(addr1->info.ip.ip, addr2->info.ip.ip, strlen(addr1->info.ip.ip)) == 0) {
                return;
            }
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]disconnect all connection for type=%d",
        connFsm->id, addr1->type);
    if (LnnConvertAddrToOption(addr1, &option)) {
        ConnDisconnectDeviceAllConn(&option);
    }
}

static void TryNotifyAllTypeOffline(const LnnConnectionFsm *connFsm)
{
    LnnConnectionFsm *item = NULL;
    const ConnectionAddr *addr1 = &connFsm->connInfo.addr;
    const ConnectionAddr *addr2 = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        addr2 = &item->connInfo.addr;
        if (addr1->type == addr2->type) {
            return;
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]notify all connection offline for type=%d",
        connFsm->id, addr1->type);
    (void)LnnNotifyAllTypeOffline(addr1->type);
}

static void CleanConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connection fsm is null");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "connection fsm[id=%u] is cleaned", connFsm->id);
    LnnDestroyConnectionFsm(connFsm);
}

static void StopConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (LnnStopConnectionFsm(connFsm, CleanConnectionFsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop connection fsm[id=%u] failed", connFsm->id);
    }
    ListDelete(&connFsm->node);
    --g_netBuilder.connCount;
}

static int32_t ProcessCleanConnectionFsm(const void *para)
{
    uint16_t connFsmId;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "connFsmId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsmId = *(uint16_t *)para;
    do {
        connFsm = FindConnectionFsmByConnFsmId(connFsmId);
        if (connFsm == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "can not find connection fsm");
            break;
        }
        StopConnectionFsm(connFsm);
        TryInitiateNewNetworkOnline(connFsm);
        TryDisconnectAllConnection(connFsm);
        TryNotifyAllTypeOffline(connFsm);
        TryRemovePendingJoinRequest();
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)para);
    return rc;
}

static int32_t ProcessAuthKeyGenerated(const void *para)
{
    const AuthKeyGeneratedMsgPara *msgPara = (const AuthKeyGeneratedMsgPara *)para;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_OK;
    bool isCreate = false;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByAuthId(msgPara->authId);
    if (connFsm == NULL || connFsm->isDead) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "create and start a new connection fsm as server side");
        connFsm = StartNewConnectionFsm(&msgPara->addr);
        if (connFsm == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start server new connection failed: %llu",
                msgPara->authId);
            SoftBusFree((void *)msgPara);
            return SOFTBUS_ERR;
        }
        isCreate = true;
        connFsm->connInfo.authId = msgPara->authId;
        connFsm->connInfo.flag |= LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    }
    connFsm->connInfo.peerVersion = msgPara->peerVersion;
    if (LnnSendAuthKeyGenMsgToConnFsm(connFsm) != SOFTBUS_OK) {
        if (isCreate) {
            StopConnectionFsm(connFsm);
        }
        rc = SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection fsm auth key generated process done: %llu, %d",
        connFsm->id, msgPara->authId, rc);
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessAuthDone(const void *para)
{
    const AuthResultMsgPara *msgPara = (const AuthResultMsgPara *)para;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        connFsm = FindConnectionFsmByAuthId(msgPara->authId);
        if (connFsm == NULL || connFsm->isDead) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "can not find connection fsm by authId: %lld",
                msgPara->authId);
            break;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection fsm auth done: %llu",
            connFsm->id, msgPara->authId);
        if (LnnSendAuthResultMsgToConnFsm(connFsm, msgPara->retCode) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send auth result to connection fsm[id=%u] failed",
                connFsm->id);
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessSyncDeviceInfoDone(const void *para)
{
    const LnnRecvDeviceInfoMsgPara *msgPara = (const LnnRecvDeviceInfoMsgPara *)para;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "recv device info msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByAuthId(msgPara->authId);
    if (connFsm == NULL || connFsm->isDead) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "can not find connection fsm by authId: %lld",
            msgPara->authId);
        SoftBusFree((void *)msgPara);
        return SOFTBUS_ERR;
    }
    // if send success, the memory of para will be freed by connection fsm
    rc = LnnSendPeerDevInfoToConnFsm(connFsm, msgPara);
    if (rc != SOFTBUS_OK) {
        SoftBusFree((void *)msgPara);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "send peer device info to connection fsm[id=%u] result=%d",
        connFsm->id, rc);
    return rc;
}

static int32_t ProcessDeviceNotTrusted(const void *para)
{
    const char *peerUdid = (const char *)para;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_OK;

    if (peerUdid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "peer udid is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByUdid(peerUdid);
        if (connFsm == NULL || connFsm->isDead) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ignore not trusted peer udid");
            break;
        }
        rc = LnnSendNotTrustedToConnFsm(connFsm);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]send not trusted msg to connection fsm result: %d",
            connFsm->id, rc);
    } while (false);
    SoftBusFree((void *)peerUdid);
    return rc;
}

static int32_t ProcessAuthDisconnect(const void *para)
{
    const int64_t *authId = (const int64_t *)para;
    LnnConnectionFsm *connFsm = NULL;
    int rc = SOFTBUS_OK;

    if (authId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "authId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByAuthId(*authId);
        if (connFsm == NULL || connFsm->isDead) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "can not find connection fsm by authId: %lld", *authId);
            break;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]auth disconnect, authId: %lld", connFsm->id, *authId);
        if (LnnSendDisconnectMsgToConnFsm(connFsm) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send disconnect to connection fsm[id=%u] failed",
                connFsm->id);
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)authId);
    return rc;
}

static int32_t ProcessLeaveLNNRequest(const void *para)
{
    const char *networkId = (const char *)para;
    LnnConnectionFsm *item = NULL;
    int rc = SOFTBUS_ERR;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "leave networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) != 0 || item->isDead) {
            continue;
        }
        if (LnnSendLeaveRequestToConnFsm(item) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send leave LNN msg to connection fsm[id=%u] failed",
                item->id);
        } else {
            rc = SOFTBUS_OK;
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_REQUEST;
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "send leave LNN msg to connection fsm[id=%u] success",
                item->id);
        }
    }
    if (rc != SOFTBUS_OK) {
        LnnNotifyLeaveResult(networkId, SOFTBUS_ERR);
    }
    SoftBusFree((void *)networkId);
    return rc;
}

static int32_t ProcessSyncOfflineFinish(const void *para)
{
    const char *networkId = (const char *)para;
    LnnConnectionFsm *item = NULL;
    int rc = SOFTBUS_OK;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync offline finish networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (strcmp(networkId, item->connInfo.peerNetworkId) != 0 || item->isDead) {
            continue;
        }
        rc = LnnSendSyncOfflineFinishToConnFsm(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "send sync offline msg to connection fsm[id=%u] result: %d",
            item->id, rc);
    }
    SoftBusFree((void *)networkId);
    return rc;
}

static bool IsInvalidConnectionFsm(const LnnConnectionFsm *connFsm, const LeaveInvalidConnMsgPara *msgPara)
{
    if (strcmp(msgPara->oldNetworkId, connFsm->connInfo.peerNetworkId) != 0) {
        return false;
    }
    if (connFsm->isDead) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection is dead", connFsm->id);
        return false;
    }
    if (msgPara->addrType != CONNECTION_ADDR_MAX && msgPara->addrType != connFsm->connInfo.addr.type) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection type not match %d,%d",
            msgPara->addrType, connFsm->connInfo.addr.type);
        return false;
    }
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_ONLINE) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection is not online", connFsm->id);
        return false;
    }
    if ((connFsm->connInfo.flag & LNN_CONN_INFO_FLAG_INITIATE_ONLINE) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection is already in leaving", connFsm->id);
        return false;
    }
    return true;
}

static int32_t ProcessLeaveInvalidConn(const void *para)
{
    LnnConnectionFsm *item = NULL;
    int32_t rc = SOFTBUS_OK;
    int32_t count = 0;
    const LeaveInvalidConnMsgPara *msgPara = (const LeaveInvalidConnMsgPara *)para;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "leave invalid connection msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (!IsInvalidConnectionFsm(item, msgPara)) {
            continue;
        }
        // The new connFsm should timeout when following errors occur
        ++count;
        item->connInfo.cleanInfo = SoftBusMalloc(sizeof(LnnInvalidCleanInfo));
        if (item->connInfo.cleanInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]malloc invalid clena info failed", item->id);
            continue;
        }
        item->connInfo.cleanInfo->addrType = msgPara->addrType;
        if (strncpy_s(item->connInfo.cleanInfo->networkId, NETWORK_ID_BUF_LEN,
            msgPara->newNetworkId, strlen(msgPara->newNetworkId)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[id=%u]copy new networkId failed", item->id);
            rc = SOFTBUS_ERR;
            SoftBusFree(item->connInfo.cleanInfo);
            item->connInfo.cleanInfo = NULL;
            continue;
        }
        rc = LnnSendLeaveRequestToConnFsm(item);
        if (rc == SOFTBUS_OK) {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_INITIATE_ONLINE;
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_AUTO;
        } else {
            SoftBusFree(item->connInfo.cleanInfo);
            item->connInfo.cleanInfo = NULL;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "send leave LNN msg to invalid connection fsm[id=%u] result: %d", item->id, rc);
    }
    if (count == 0) {
        InitiateNewNetworkOnline(msgPara->addrType, msgPara->newNetworkId);
    }
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t TryElectMasterNodeOnline(const LnnConnectionFsm *connFsm)
{
    char peerMasterUdid[UDID_BUF_LEN] = {0};
    char localMasterUdid[UDID_BUF_LEN] = {0};
    int32_t peerMasterWeight, localMasterWeight;
    int32_t rc;

    // get local master node info
    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &localMasterWeight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local master node info from ledger failed");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "local master(%u) weight=%d", connFsm->id, localMasterWeight);
    if (LnnGetRemoteStrInfo(connFsm->connInfo.peerNetworkId, STRING_KEY_MASTER_NODE_UDID,
        peerMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
        LnnGetRemoteNumInfo(connFsm->connInfo.peerNetworkId, NUM_KEY_MASTER_NODE_WEIGHT,
            &peerMasterWeight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "peer node info(%u) is not found", connFsm->id);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "peer master(%u) weight=%d", connFsm->id, peerMasterWeight);
    rc = LnnCompareNodeWeight(localMasterWeight, localMasterUdid, peerMasterWeight, peerMasterUdid);
    if (rc >= 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "online node(%u) weight less than current(compare result: %d), no need elect again",
            connFsm->id, rc);
        return SOFTBUS_OK;
    }
    UpdateLocalMasterNode(peerMasterUdid, peerMasterWeight);
    SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
    return SOFTBUS_OK;
}

static int32_t TryElectMasterNodeOffline(const LnnConnectionFsm *connFsm)
{
    char localUdid[UDID_BUF_LEN] = {0};
    char localMasterUdid[UDID_BUF_LEN] = {0};

    if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local master node info from ledger failed");
        return SOFTBUS_ERR;
    }
    LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN);
    if (strcmp(localMasterUdid, localUdid) == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "local is master node(%u), no need elect again", connFsm->id);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "maybe master node(%u) offline, elect again", connFsm->id);
        UpdateLocalMasterNode(localUdid, LnnGetLocalWeight());
        SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
    }
    return SOFTBUS_OK;
}

static int32_t ProcessNodeStateChanged(const void *para)
{
    const ConnectionAddr *addr = (const ConnectionAddr *)para;
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_ERR;
    bool isOnline = false;

    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "node state changed msg is null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        connFsm = FindConnectionFsmByAddr(addr);
        if (connFsm == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR,
                "can't find connection fsm when node online state changed");
            break;
        }
        if (connFsm->connInfo.peerVersion < SOFT_BUS_NEW_V1) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]peer not support master node elect", connFsm->id);
            rc = SOFTBUS_OK;
            break;
        }
        isOnline = IsNodeOnline(connFsm->connInfo.peerNetworkId);
        rc = isOnline ? TryElectMasterNodeOnline(connFsm) : TryElectMasterNodeOffline(connFsm);
    } while (false);
    SoftBusFree((void *)addr);
    if (isOnline) {
        TryRemovePendingJoinRequest();
    }
    return rc;
}

static int32_t ProcessMasterElect(const void *para)
{
    const ElectMsgPara *msgPara = (const ElectMsgPara *)para;
    LnnConnectionFsm *connFsm = NULL;
    char localMasterUdid[UDID_BUF_LEN] = {0};
    int32_t localMasterWeight, compareRet;
    int32_t rc = SOFTBUS_ERR;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "elect msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        connFsm = FindConnectionFsmByNetworkId(msgPara->networkId);
        if (connFsm == NULL || connFsm->isDead) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "can't find connection fsm when receive elect node");
            break;
        }
        if (!IsNodeOnline(connFsm->connInfo.peerNetworkId)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "peer node(%u) is already offline", connFsm->id);
            break;
        }
        if (LnnGetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, localMasterUdid, UDID_BUF_LEN) != SOFTBUS_OK ||
            LnnGetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, &localMasterWeight) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local master node(%u) info from ledger failed",
                connFsm->id);
            break;
        }
        compareRet = LnnCompareNodeWeight(localMasterWeight, localMasterUdid,
            msgPara->masterWeight, msgPara->masterUdid);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]weight compare result: %d", connFsm->id, compareRet);
        if (compareRet != 0) {
            if (compareRet < 0) {
                UpdateLocalMasterNode(msgPara->masterUdid, msgPara->masterWeight);
                SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
            } else {
                rc = SyncElectMessage(connFsm->connInfo.peerNetworkId);
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "sync elect info to connFsm(%u) result:%d",
                    connFsm->id, rc);
            }
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessLeaveByAddrType(const void *para)
{
    bool *addrType = NULL;
    LnnConnectionFsm *item = NULL;
    int32_t rc;
    bool notify = true;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "leave by addr type msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }

    addrType = (bool *)para;
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (!addrType[item->connInfo.addr.type]) {
            continue;
        }
        // if there are any same addr type, let last one send notify
        notify = false;
        if (item->isDead) {
            continue;
        }
        rc = LnnSendLeaveRequestToConnFsm(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "leave connFsm[id=%u] by addr type rc=%d", item->id, rc);
        if (rc == SOFTBUS_OK) {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_AUTO;
        }
    }
    if (notify) {
        (void)LnnNotifyAllTypeOffline(CONNECTION_ADDR_MAX);
    }
    SoftBusFree((void *)para);
    return SOFTBUS_OK;
}

static int32_t ProcessLeaveSpecific(const void *para)
{
    const SpecificLeaveMsgPara *msgPara = (const SpecificLeaveMsgPara *)para;
    LnnConnectionFsm *item = NULL;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "leave specific msg is null");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t rc;
    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (strcmp(item->connInfo.peerNetworkId, msgPara->networkId) != 0 ||
            item->connInfo.addr.type != msgPara->addrType) {
            continue;
        }
        rc = LnnSendLeaveRequestToConnFsm(item);
        if (rc == SOFTBUS_OK) {
            item->connInfo.flag |= LNN_CONN_INFO_FLAG_LEAVE_AUTO;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "send leave LNN msg to connection fsm[id=%u] result: %d", item->id, rc);
    }
    SoftBusFree((void *)msgPara);
    return SOFTBUS_OK;
}

static NetBuilderMessageProcess g_messageProcessor[MSG_TYPE_MAX] = {
    ProcessJoinLNNRequest,
    ProcessDevDiscoveryRequest,
    ProcessCleanConnectionFsm,
    ProcessAuthKeyGenerated,
    ProcessAuthDone,
    ProcessSyncDeviceInfoDone,
    ProcessDeviceNotTrusted,
    ProcessAuthDisconnect,
    ProcessLeaveLNNRequest,
    ProcessSyncOfflineFinish,
    ProcessNodeStateChanged,
    ProcessMasterElect,
    ProcessLeaveInvalidConn,
    ProcessLeaveByAddrType,
    ProcessLeaveSpecific,
};

static void NetBuilderMessageHandler(SoftBusMessage *msg)
{
    int32_t ret;

    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "msg is null in net builder handler");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "net builder process msg: %d", msg->what);
    if (msg->what >= MSG_TYPE_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid msg type");
        return;
    }
    ret = g_messageProcessor[msg->what](msg->obj);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "net builder process msg(%d) done, ret=%d", msg->what, ret);
}

static int32_t GetCurrentConnectType(ConnectionAddrType *type)
{
    char ifCurrentName[NET_IF_NAME_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifCurrentName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetLocalStrInfo getCurrentConnectType failed");
        return SOFTBUS_ERR;
    }
    if (LnnGetAddrTypeByIfName(ifCurrentName, strlen(ifCurrentName), type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "getCurrentConnectType unknown connect type");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void OnAuthKeyGenerated(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion)
{
    AuthKeyGeneratedMsgPara *para = NULL;
    ConnectionAddrType type = CONNECTION_ADDR_MAX;
    para = SoftBusMalloc(sizeof(AuthKeyGeneratedMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc auth key generated msg para fail");
        return;
    }
    if (GetCurrentConnectType(&type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "getCurrentConnectType failed");
        SoftBusFree(para);
        return;
    }
    if (!LnnConvertOptionToAddr(&para->addr, option, type)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert option to addr failed");
        SoftBusFree(para);
        return;
    }
    para->authId = authId;
    para->peerVersion = peerVersion;
    if (PostMessageToHandler(MSG_TYPE_AUTH_KEY_GENERATED, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post auth key generated message failed");
        SoftBusFree(para);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "auth key generated: %lld", authId);
}

static void OnAuthDone(int64_t authId, int32_t retCode)
{
    AuthResultMsgPara *para = SoftBusMalloc(sizeof(AuthResultMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc auth result fail");
        return;
    }
    para->retCode = retCode;
    para->authId = authId;
    if (PostMessageToHandler(MSG_TYPE_AUTH_DONE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post auth fail message failed");
        SoftBusFree(para);
    }
}

static void OnAuthFailed(int64_t authId, int32_t reason)
{
    OnAuthDone(authId, reason);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "auth failed: %lld", authId);
}

static void OnAuthPassed(int64_t authId)
{
    OnAuthDone(authId, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "auth passed: %lld", authId);
}

static void OnRecvPeerDeviceInfo(int64_t authId, AuthSideFlag side,
    const char *peerUuid, uint8_t *data, uint32_t len)
{
    LnnRecvDeviceInfoMsgPara *para = NULL;

    if (peerUuid == NULL || data == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid peer device info para");
        return;
    }
    para = SoftBusCalloc(sizeof(*para) + len);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc recv device info msg para fail");
        return;
    }
    para->authId = authId;
    para->side = side;
    if (strncpy_s(para->uuid, UUID_BUF_LEN, peerUuid, strlen(peerUuid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy uuid fail");
        SoftBusFree(para);
        return;
    }
    para->data = (uint8_t *)para + sizeof(*para);
    if (memcpy_s(para->data, len, data, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy data buffer fail");
        SoftBusFree(para);
        return;
    }
    para->len = len;
    if (PostMessageToHandler(MSG_TYPE_SYNC_DEVICE_INFO_DONE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post sync device info done message failed");
        SoftBusFree(para);
    }
}

static void OnDeviceNotTrusted(const char *peerUdid)
{
    char *udid = NULL;
    uint32_t udidLen;

    if (peerUdid == NULL) {
        return;
    }
    udidLen = strlen(peerUdid) + 1;

    udid = (char *)SoftBusMalloc(udidLen);
    if (udid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc udid fail");
        return;
    }
    if (strncpy_s(udid, udidLen, peerUdid, udidLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy udid fail");
        SoftBusFree(udid);
        return;
    }
    if (PostMessageToHandler(MSG_TYPE_NOT_TRUSTED, udid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post device not trusted message failed");
        SoftBusFree(udid);
    }
}

static void OnDisconnect(int64_t authId)
{
    int64_t *para = (int64_t *)SoftBusMalloc(sizeof(int64_t));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc authId fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "auth channel disconnect, authId is %lld", authId);
    *para = authId;
    if (PostMessageToHandler(MSG_TYPE_DISCONNECT, (void *)para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post auth disconnect message failed");
        SoftBusFree(para);
    }
}

static VerifyCallback g_verifyCb = {
    .onKeyGenerated = OnAuthKeyGenerated,
    .onDeviceVerifyPass = OnAuthPassed,
    .onDeviceVerifyFail = OnAuthFailed,
    .onRecvSyncDeviceInfo = OnRecvPeerDeviceInfo,
    .onDeviceNotTrusted = OnDeviceNotTrusted,
    .onDisconnect = OnDisconnect,
};

static ConnectionAddr *CreateConnectionAddrMsgPara(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "addr is null");
        return NULL;
    }
    para = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc connecton addr message fail");
        return NULL;
    }
    *para = *addr;
    return para;
}

static char *CreateNetworkIdMsgPara(const char *networkId)
{
    char *para = NULL;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "networkId is null");
        return NULL;
    }
    para = (char *)SoftBusMalloc(NETWORK_ID_BUF_LEN);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc networkId message fail");
        return NULL;
    }
    if (strncpy_s(para, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy network id fail");
        SoftBusFree(para);
        return NULL;
    }
    return para;
}

static int32_t ConifgLocalLedger(void)
{
    char uuid[UUID_BUF_LEN] = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};

    // set local uuid and networkId
    if (LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK ||
        LnnGenLocalUuid(uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local id fail");
        return SOFTBUS_ERR;
    }
    LnnSetLocalStrInfo(STRING_KEY_UUID, uuid);
    LnnSetLocalStrInfo(STRING_KEY_NETWORKID, networkId);
    return SOFTBUS_OK;
}

static int32_t RegisterAuthCallback(void)
{
    if (AuthRegCallback(LNN, &g_verifyCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register auth callback fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void OnReceiveMasterElectMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    cJSON *json = NULL;
    ElectMsgPara *para = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "recv master elect msg, type:%d, len: %d", type, len);
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return;
    }
    if (type != LNN_INFO_TYPE_MASTER_ELECT) {
        return;
    }
    if (strnlen((char *)msg, len) == len) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnReceiveMasterElectMsg msg invalid");
        return;
    }
    json = cJSON_Parse((char *)msg);
    if (json == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse elect msg json fail");
        return;
    }
    para = SoftBusMalloc(sizeof(ElectMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc elect msg para fail");
        cJSON_Delete(json);
        return;
    }
    if (!GetJsonObjectNumberItem(json, JSON_KEY_MASTER_WEIGHT, &para->masterWeight) ||
        !GetJsonObjectStringItem(json, JSON_KEY_MASTER_UDID, para->masterUdid, UDID_BUF_LEN)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "parse master info json fail");
        cJSON_Delete(json);
        SoftBusFree(para);
        return;
    }
    cJSON_Delete(json);
    if (strcpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy network id fail");
        SoftBusFree(para);
        return;
    }
    if (PostMessageToHandler(MSG_TYPE_MASTER_ELECT, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post elect message fail");
        SoftBusFree(para);
    }
}

static void OnReceiveConnCapabilityMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "recv conn capability msg, type:%d, len:%u", type, len);
    if (type != LNN_INFO_TYPE_CAPABILITY || len != LNN_CONN_CAPABILITY_MSG_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid conn capability msg.");
        return;
    }
    uint64_t connCap = *((uint64_t *)msg);
    if (LnnSetDistributedConnCapability(networkId, connCap)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "update conn capability fail.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update conn capability succ.");
}

int32_t LnnInitNetBuilder(void)
{
    if (g_netBuilder.isInit == true) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init net builder repeatly");
        return SOFTBUS_OK;
    }
    if (LnnInitSyncInfoManager() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init sync info manager fail");
        return SOFTBUS_ERR;
    }
    LnnInitTopoManager();
    if (LnnInitP2p() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init lnn p2p fail");
        return SOFTBUS_ERR;
    }
    NetBuilderConfigInit();
    if (RegisterAuthCallback() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register auth callback fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_CAPABILITY, OnReceiveConnCapabilityMsg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register conn capability msg fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_MASTER_ELECT, OnReceiveMasterElectMsg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register sync master elect msg fail");
        return SOFTBUS_ERR;
    }
    if (ConifgLocalLedger() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "config local ledger fail");
        return SOFTBUS_ERR;
    }
    ListInit(&g_netBuilder.fsmList);
    ListInit(&g_netBuilder.pendingList);
    g_netBuilder.nodeType = NODE_TYPE_L;
    g_netBuilder.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_netBuilder.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get default looper fail");
        return SOFTBUS_ERR;
    }
    g_netBuilder.handler.name = "NetBuilderHandler";
    g_netBuilder.handler.looper = g_netBuilder.looper;
    g_netBuilder.handler.HandleMessage = NetBuilderMessageHandler;
    g_netBuilder.isInit = true;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init net builder success");
    return SOFTBUS_OK;
}

int32_t LnnInitNetBuilderDelay(void)
{
    char udid[UDID_BUF_LEN] = {0};
    // set master weight and master udid
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid error!\n");
        return SOFTBUS_ERR;
    }
    LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, udid);
    LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, LnnGetLocalWeight());
    return SOFTBUS_OK;
}

void LnnDeinitNetBuilder(void)
{
    LnnConnectionFsm *item = NULL;
    LnnConnectionFsm *nextItem = NULL;

    if (!g_netBuilder.isInit) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        StopConnectionFsm(item);
    }
    LnnUnregSyncInfoHandler(LNN_INFO_TYPE_MASTER_ELECT, OnReceiveMasterElectMsg);
    LnnDeinitTopoManager();
    LnnDeinitP2p();
    LnnDeinitSyncInfoManager();
    g_netBuilder.isInit = false;
}

int32_t LnnServerJoin(ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnServerJoin enter!");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "prepare join lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_JOIN_LNN, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post join lnn message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnServerLeave(const char *networkId)
{
    char *para = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnServerLeave enter!");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "prepare leave lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_LEAVE_LNN, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post leave lnn message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnNotifyDiscoveryDevice enter!");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc discovery device message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_DISCOVERY_DEVICE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post notify discovery device message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId)
{
    LeaveInvalidConnMsgPara *para = NULL;

    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = SoftBusMalloc(sizeof(LeaveInvalidConnMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "prepare leave invalid connection message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para->oldNetworkId, NETWORK_ID_BUF_LEN, oldNetworkId, strlen(oldNetworkId)) != EOK ||
        strncpy_s(para->newNetworkId, NETWORK_ID_BUF_LEN, newNetworkId, strlen(newNetworkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy old networkId or new networkId fail");
        SoftBusFree(para);
        return SOFTBUS_MALLOC_ERR;
    }
    para->addrType = addrType;
    if (PostMessageToHandler(MSG_TYPE_LEAVE_INVALID_CONN, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post leave invalid connection message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestCleanConnFsm(uint16_t connFsmId)
{
    uint16_t *para = NULL;

    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = SoftBusMalloc(sizeof(uint16_t));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc clean connection fsm msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    *para = connFsmId;
    if (PostMessageToHandler(MSG_TYPE_CLEAN_CONN_FSM, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post request clean connectionlnn message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnSyncOfflineComplete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    char *para = NULL;

    (void)type;
    (void)msg;
    (void)len;
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "prepare notify sync offline message fail");
        return;
    }
    if (PostMessageToHandler(MSG_TYPE_SYNC_OFFLINE_FINISH, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post sync offline finish message failed");
        SoftBusFree(para);
    }
}

int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create node state changed msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_NODE_STATE_CHANGED, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post node state changed message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    ElectMsgPara *para = NULL;

    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    if (networkId == NULL || masterUdid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid elect msg para");
        return SOFTBUS_INVALID_PARAM;
    }
    para = SoftBusMalloc(sizeof(ElectMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc elect msg para failed");
        return SOFTBUS_MEM_ERR;
    }
    if (strncpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK ||
        strncpy_s(para->masterUdid, UDID_BUF_LEN, masterUdid, strlen(masterUdid)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy udid and maser udid failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    para->masterWeight = masterWeight;
    if (PostMessageToHandler(MSG_TYPE_MASTER_ELECT, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post elect message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    bool *para = NULL;
    if (typeLen != CONNECTION_ADDR_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid typeLen");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnRequestLeaveByAddrType");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = SoftBusMalloc(sizeof(bool) * typeLen);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc leave by addr type msg para failed");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(para, sizeof(bool) * typeLen, type, sizeof(bool) * typeLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcopy para fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_LEAVE_BY_ADDR_TYPE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post leave by addr type message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    SpecificLeaveMsgPara *para = NULL;

    if (networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = (SpecificLeaveMsgPara *)SoftBusCalloc(sizeof(SpecificLeaveMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc specific msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    para->addrType = addrType;
    if (PostMessageToHandler(MSG_TYPE_LEAVE_SPECIFIC, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post leave specific msg failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
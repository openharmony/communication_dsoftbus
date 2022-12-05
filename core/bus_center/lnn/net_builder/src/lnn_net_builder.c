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
#include <inttypes.h>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_devicename_info.h"
#include "lnn_discovery_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_fast_offline.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_local_net_ledger.h"
#include "lnn_network_id.h"
#include "lnn_network_info.h"
#include "lnn_network_manager.h"
#include "lnn_node_weight.h"
#include "lnn_p2p_info.h"
#include "lnn_physical_subnet_manager.h"
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
#define NOT_TRUSTED_DEVICE_MSG_DELAY 5000

typedef enum {
    LNN_MSG_ID_ELECT,
    LNN_MSG_ID_MAX
} LnnMsgType;

typedef enum {
    MSG_TYPE_JOIN_LNN = 0,
    MSG_TYPE_DISCOVERY_DEVICE,
    MSG_TYPE_CLEAN_CONN_FSM,
    MSG_TYPE_VERIFY_RESULT,
    MSG_TYPE_DEVICE_VERIFY_PASS,
    MSG_TYPE_DEVICE_DISCONNECT = 5,
    MSG_TYPE_DEVICE_NOT_TRUSTED,
    MSG_TYPE_LEAVE_LNN,
    MSG_TYPE_SYNC_OFFLINE_FINISH,
    MSG_TYPE_NODE_STATE_CHANGED,
    MSG_TYPE_MASTER_ELECT = 10,
    MSG_TYPE_LEAVE_INVALID_CONN,
    MSG_TYPE_LEAVE_BY_ADDR_TYPE,
    MSG_TYPE_LEAVE_SPECIFIC,
    MSG_TYPE_JOIN_METANODE,
    MSG_TYPE_JOIN_METANODE_AUTH_PASS,
    MSG_TYPE_LEAVE_METANODE,
    MSG_TYPE_JOIN_METANODE_AUTH_FAIL,
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
    ListNode metaNodeList;
    /* connection count */
    int32_t connCount;

    SoftBusLooper *looper;
    SoftBusHandler handler;

    int32_t maxConnCount;
    int32_t maxConcurrentCount;
    bool isInit;
} NetBuilder;

typedef struct {
    uint32_t requestId;
    int32_t retCode;
    int64_t authId;
    NodeInfo *nodeInfo;
} VerifyResultMsgPara;

typedef struct {
    ConnectionAddr addr;
    int64_t authId;
    NodeInfo *nodeInfo;
} DeviceVerifyPassMsgPara;

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

typedef struct {
    ConnectionAddr addr;
    CustomData customData;
} ConnectionAddrKey;

typedef struct {
    MetaJoinRequestNode *metaJoinNode;
    int32_t reason;
} MetaReason;

typedef struct {
    MetaJoinRequestNode *metaJoinNode;
    int64_t authMetaId;
    NodeInfo info;
} MetaAuthInfo;

static NetBuilder g_netBuilder;

static void NetBuilderConfigInit(void)
{
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_LNN_CONNECTION_CNT,
        (unsigned char*)&g_netBuilder.maxConnCount, sizeof(g_netBuilder.maxConnCount)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get lnn max connection count fail, use default value");
        g_netBuilder.maxConnCount = DEFAULT_MAX_LNN_CONNECTION_COUNT;
    }
    if (SoftbusGetConfig(SOFTBUS_INT_LNN_MAX_CONCURRENT_NUM,
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

static MetaJoinRequestNode *FindMetaNodeByAddr(const ConnectionAddr *addr)
{
    MetaJoinRequestNode *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.metaNodeList, MetaJoinRequestNode, node) {
        if (LnnIsSameConnectionAddr(addr, &item->addr)) {
            return item;
        }
    }
    return NULL;
}

static MetaJoinRequestNode *FindMetaNodeByRequestId(uint32_t requestId)
{
    MetaJoinRequestNode *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.metaNodeList, MetaJoinRequestNode, node) {
        if (item->requestId == requestId) {
            return item;
        }
    }
    return NULL;
}

static LnnConnectionFsm *FindConnectionFsmByRequestId(uint32_t requestId)
{
    LnnConnectionFsm *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->connInfo.requestId == requestId) {
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
    connFsm->statisticData.beginTime = LnnUpTimeMs();
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

static void UpdateLocalMasterNode(bool isCurrentNode, const char *masterUdid, int32_t weight)
{
    if (LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, masterUdid) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local master udid failed");
        return;
    }
    if (LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, weight) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set local master weight failed");
    }
    LnnNotifyMasterNodeChanged(isCurrentNode, masterUdid, weight);
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
    request = (PendingJoinRequestNode *)SoftBusCalloc(sizeof(PendingJoinRequestNode));
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

static MetaJoinRequestNode *TryJoinRequestMetaNode(const ConnectionAddr *addr, bool needReportFailure)
{
    MetaJoinRequestNode *request = NULL;

    request = (MetaJoinRequestNode *)SoftBusCalloc(sizeof(MetaJoinRequestNode));
    if (request == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc MetaNode join request fail, go on it");
        return NULL;
    }
    ListInit(&request->node);
    request->addr = *addr;
    request->needReportFailure = needReportFailure;
    ListTailInsert(&g_netBuilder.metaNodeList, &request->node);
    return request;
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

static int32_t PostJoinRequestToMetaNode(MetaJoinRequestNode *metaJoinNode, const ConnectionAddr *addr,
    CustomData *customData, bool needReportFailure)
{
    int32_t rc = SOFTBUS_OK;
    if (OnJoinMetaNode(metaJoinNode, customData) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "PostJoin Request To MetaNode failed");
        rc = SOFTBUS_ERR;
        if (needReportFailure) {
            MetaNodeNotifyJoinResult((ConnectionAddr *)addr, NULL, SOFTBUS_ERR);
        }
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

static int32_t TrySendJoinMetaNodeRequest(const ConnectionAddrKey *addrDataKey, bool needReportFailure)
{
    if (addrDataKey == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: addrDataKey is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    const ConnectionAddr *addr = &addrDataKey->addr;
    CustomData customData = addrDataKey->customData;
    MetaJoinRequestNode *metaJoinNode = NULL;
    int32_t rc;
    metaJoinNode = FindMetaNodeByAddr(addr);
    if (metaJoinNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "TrySendJoinMetaNodeRequest not find metaJoinNode");
        metaJoinNode = TryJoinRequestMetaNode(addr, needReportFailure);
        if (metaJoinNode == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "join request is pending");
            SoftBusFree((void *)addrDataKey);
            return SOFTBUS_ERR;
        }
    }
    rc = PostJoinRequestToMetaNode(metaJoinNode, addr, &customData, needReportFailure);
    SoftBusFree((void *)addrDataKey);
    return rc;
}

static int32_t ProcessJoinLNNRequest(const void *para)
{
    return TrySendJoinLNNRequest((const ConnectionAddr *)para, true);
}

static int32_t ProcessJoinMetaNodeRequest(const void *para)
{
    return TrySendJoinMetaNodeRequest((const ConnectionAddrKey *)para, true);
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

static int32_t ProcessVerifyResult(const void *para)
{
    int32_t rc;
    LnnConnectionFsm *connFsm = NULL;
    const VerifyResultMsgPara *msgPara = (const VerifyResultMsgPara *)para;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (msgPara->nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "msgPara node Info is null");
        SoftBusFree((void *)msgPara);
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByRequestId(msgPara->requestId);
        if (connFsm == NULL || connFsm->isDead) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR,
                "can not find connection fsm by requestId: %u", msgPara->requestId);
            rc = SOFTBUS_ERR;
            break;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]connection fsm auth done: retCode=%d",
            connFsm->id, msgPara->retCode);
        if (msgPara->retCode == SOFTBUS_OK) {
            connFsm->connInfo.authId = msgPara->authId;
            connFsm->connInfo.nodeInfo = msgPara->nodeInfo;
        }
        if (LnnSendAuthResultMsgToConnFsm(connFsm, msgPara->retCode) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "send auth result to connection fsm[id=%u] failed",
                connFsm->id);
            connFsm->connInfo.nodeInfo = NULL;
            rc = SOFTBUS_ERR;
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);

    if (rc != SOFTBUS_OK && msgPara->nodeInfo != NULL) {
        SoftBusFree((void *)msgPara->nodeInfo);
    }
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t CreatePassiveConnectionFsm(const DeviceVerifyPassMsgPara *msgPara)
{
    LnnConnectionFsm *connFsm = NULL;
    connFsm = StartNewConnectionFsm(&msgPara->addr);
    if (connFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR,
            "start new connection fsm fail: %" PRId64, msgPara->authId);
        return SOFTBUS_ERR;
    }
    connFsm->connInfo.authId = msgPara->authId;
    connFsm->connInfo.nodeInfo = msgPara->nodeInfo;
    connFsm->connInfo.flag |= LNN_CONN_INFO_FLAG_JOIN_PASSIVE;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "[id=%u]start a passive connection fsm, authId=%" PRId64, connFsm->id, msgPara->authId);
    if (LnnSendAuthResultMsgToConnFsm(connFsm, SOFTBUS_OK) != SOFTBUS_OK) {
        connFsm->connInfo.nodeInfo = NULL;
        StopConnectionFsm(connFsm);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR,
            "[id=%u]post auth result to connection fsm fail: %" PRId64, connFsm->id, msgPara->authId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ProcessDeviceVerifyPass(const void *para)
{
    int32_t rc;
    LnnConnectionFsm *connFsm = NULL;
    const DeviceVerifyPassMsgPara *msgPara = (const DeviceVerifyPassMsgPara *)para;

    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "para is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (msgPara->nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "msgPara nodeInfo is null");
        SoftBusFree((void *)msgPara);
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByAuthId(msgPara->authId);
        if (connFsm == NULL || connFsm->isDead) {
            rc = CreatePassiveConnectionFsm(msgPara);
            break;
        }
        if (strcmp(connFsm->connInfo.peerNetworkId, msgPara->nodeInfo->networkId) != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
                "[id=%u]networkId changed: %" PRId64, connFsm->id, msgPara->authId);
            rc = CreatePassiveConnectionFsm(msgPara);
            break;
        }
        msgPara->nodeInfo->discoveryType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(msgPara->addr.type);
        if (LnnUpdateNodeInfo(msgPara->nodeInfo) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnUpdateNodeInfo failed!");
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]connection fsm exist, ignore VerifyPass event: %" PRId64, connFsm->id, msgPara->authId);
        rc = SOFTBUS_ERR;
    } while (false);

    if (rc != SOFTBUS_OK && msgPara->nodeInfo != NULL) {
        SoftBusFree((void *)msgPara->nodeInfo);
    }
    SoftBusFree((void *)msgPara);
    return rc;
}

static int32_t ProcessDeviceDisconnect(const void *para)
{
    int32_t rc;
    LnnConnectionFsm *connFsm = NULL;
    const int64_t *authId = (const int64_t *)para;

    if (authId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "authId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByAuthId(*authId);
        if (connFsm == NULL || connFsm->isDead) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR,
                "can not find connection fsm by authId: %" PRId64, *authId);
            rc = SOFTBUS_ERR;
            break;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "[id=%u]device disconnect, authId: %" PRId64, connFsm->id, *authId);
        if (LnnSendDisconnectMsgToConnFsm(connFsm) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR,
                "send disconnect to connection fsm[id=%u] failed", connFsm->id);
            rc = SOFTBUS_ERR;
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree((void *)authId);
    return rc;
}

static int32_t ProcessDeviceNotTrusted(const void *para)
{
    int32_t rc;
    const char *udid = NULL;
    LnnConnectionFsm *item = NULL;
    const char *peerUdid = (const char *)para;

    if (peerUdid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "peer udid is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        char networkId[NETWORK_ID_BUF_LEN] = {0};
        if (LnnGetNetworkIdByUdid(peerUdid, networkId, sizeof(networkId)) == SOFTBUS_OK) {
            LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_MAX);
            break;
        }
        LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
            udid = LnnGetDeviceUdid(item->connInfo.nodeInfo);
            if (udid == NULL || strcmp(peerUdid, udid) != 0) {
                continue;
            }
            rc = LnnSendNotTrustedToConnFsm(item);
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
                "[id=%u]send not trusted msg to connection fsm result: %d", item->id, rc);
        }
    } while (false);
    SoftBusFree((void *)peerUdid);
    return SOFTBUS_OK;
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

static void LeaveMetaInfoToLedger(const MetaJoinRequestNode *metaInfo, const char *networkId)
{
    NodeInfo *info = NULL;
    const char *udid = NULL;
    info = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (info == NULL) {
        return;
    }
    udid = LnnGetDeviceUdid(info);
    if (LnnDeleteMetaInfo(udid, metaInfo->addr.type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnDeleteMetaInfo error");
    }
}

static int32_t ProcessLeaveMetaNodeRequest(const void *para)
{
    const char *networkId = (const char *)para;
    MetaJoinRequestNode *item = NULL;
    MetaJoinRequestNode *next = NULL;
    int rc = SOFTBUS_ERR;
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "leave networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_netBuilder.metaNodeList, MetaJoinRequestNode, node) {
        if (strcmp(networkId, item->networkId) != 0) {
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ProcessLeaveMetaNodeRequest can find networkId");
        AuthMetaReleaseVerify(item->authId);
        LeaveMetaInfoToLedger(item, networkId);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    MetaNodeNotifyLeaveResult(networkId, SOFTBUS_OK);
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
            connFsm->id, msgPara->addrType, connFsm->connInfo.addr.type);
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
        item->connInfo.cleanInfo = (LnnInvalidCleanInfo *)SoftBusMalloc(sizeof(LnnInvalidCleanInfo));
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
    UpdateLocalMasterNode(false, peerMasterUdid, peerMasterWeight);
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
        UpdateLocalMasterNode(true, localUdid, LnnGetLocalWeight());
        SendElectMessageToAll(connFsm->connInfo.peerNetworkId);
    }
    return SOFTBUS_OK;
}

static bool IsSupportMasterNodeElect(SoftBusVersion version)
{
    return version >= SOFTBUS_NEW_V1;
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
        isOnline = IsNodeOnline(connFsm->connInfo.peerNetworkId);
        if (!IsSupportMasterNodeElect(connFsm->connInfo.version)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[id=%u]peer not support master node elect", connFsm->id);
            rc = SOFTBUS_OK;
            break;
        }
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
                UpdateLocalMasterNode(false, msgPara->masterUdid, msgPara->masterWeight);
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
            (item->connInfo.addr.type != msgPara->addrType &&
            msgPara->addrType != CONNECTION_ADDR_MAX)) {
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

static NodeInfo *DupNodeInfo(const NodeInfo *nodeInfo)
{
    NodeInfo *node = (NodeInfo *)SoftBusMalloc(sizeof(NodeInfo));
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc NodeInfo fail");
        return NULL;
    }
    if (memcpy_s(node, sizeof(NodeInfo), nodeInfo, sizeof(NodeInfo)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy NodeInfo fail");
        SoftBusFree(node);
        return NULL;
    }
    return node;
}

static int32_t FillNodeInfo(MetaJoinRequestNode *metaNode, NodeInfo *info)
{
    if (metaNode == NULL || info ==NULL) {
        return SOFTBUS_ERR;
    }
    SoftBusSysTime times;
    (void)SoftBusGetTime(&times);
    info->heartbeatTimeStamp = (uint64_t)times.sec * HB_TIME_FACTOR +
        (uint64_t)times.usec / HB_TIME_FACTOR;
    info->discoveryType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(metaNode->addr.type);
    info->authSeqNum = metaNode->authId;
    info->authSeq[LnnConvAddrTypeToDiscType(metaNode->addr.type)] = metaNode->authId;
    info->authChannelId[metaNode->addr.type] = (int32_t)metaNode->authId;
    info->relation[metaNode->addr.type]++;
    if (AuthGetDeviceUuid(metaNode->authId, info->uuid, sizeof(info->uuid)) != SOFTBUS_OK ||
        info->uuid[0] == '\0') {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill uuid fail");
        return SOFTBUS_ERR;
    }
    if (metaNode->addr.type == CONNECTION_ADDR_ETH || metaNode->addr.type == CONNECTION_ADDR_WLAN) {
        if (strcpy_s(info->connectInfo.deviceIp, MAX_ADDR_LEN, metaNode->addr.info.ip.ip) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fill deviceIp fail");
            return SOFTBUS_MEM_ERR;
        }
    }
    info->metaInfo.metaDiscType = 1 << (uint32_t)LnnConvAddrTypeToDiscType(metaNode->addr.type);
    info->metaInfo.isMetaNode = true;
    return SOFTBUS_OK;
}

static int32_t ProcessOnAuthMetaVerifyPassed(const void *para)
{
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para is NULL");
        return SOFTBUS_ERR;
    }
    MetaAuthInfo *meta = (MetaAuthInfo *)para;
    MetaJoinRequestNode *metaNode = meta->metaJoinNode;
    int64_t authMetaId = meta->authMetaId;
    NodeInfo *info = &meta->info;
    int32_t ret = SOFTBUS_ERR;
    do {
        if (strcpy_s(metaNode->networkId, sizeof(metaNode->networkId), info->networkId) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ProcessOnAuthMetaVerifyPassed copy networkId error");
            break;
        }
        metaNode->authId = authMetaId;
        NodeInfo *newInfo = DupNodeInfo(info);
        if (newInfo == NULL) {
            break;
        }
        if (FillNodeInfo(metaNode, newInfo) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ProcessOnAuthMetaVerifyPassed FillNodeInfo error");
            SoftBusFree(newInfo);
            break;
        }
        ret = LnnAddMetaInfo(newInfo);
        SoftBusFree(newInfo);
    } while (0);
    if (ret == SOFTBUS_OK) {
        MetaNodeNotifyJoinResult(&metaNode->addr, info->networkId, SOFTBUS_OK);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ProcessOnAuthMetaVerifyPassed error");
        MetaNodeNotifyJoinResult(&metaNode->addr, NULL, SOFTBUS_ERR);
        ListDelete(&metaNode->node);
        SoftBusFree(metaNode);
    }
    SoftBusFree(meta);
    return ret;
}

static int32_t ProcessOnAuthMetaVerifyFailed(const void *para)
{
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fail: para is NULL");
        return SOFTBUS_ERR;
    }
    MetaReason *mataReason = (MetaReason *)para;
    MetaJoinRequestNode *metaNode = mataReason->metaJoinNode;
    MetaNodeNotifyJoinResult(&metaNode->addr, NULL, mataReason->reason);
    ListDelete(&metaNode->node);
    SoftBusFree(metaNode);
    SoftBusFree(mataReason);
    return SOFTBUS_OK;
}

static NetBuilderMessageProcess g_messageProcessor[MSG_TYPE_MAX] = {
    ProcessJoinLNNRequest,
    ProcessDevDiscoveryRequest,
    ProcessCleanConnectionFsm,
    ProcessVerifyResult,
    ProcessDeviceVerifyPass,
    ProcessDeviceDisconnect,
    ProcessDeviceNotTrusted,
    ProcessLeaveLNNRequest,
    ProcessSyncOfflineFinish,
    ProcessNodeStateChanged,
    ProcessMasterElect,
    ProcessLeaveInvalidConn,
    ProcessLeaveByAddrType,
    ProcessLeaveSpecific,
    ProcessJoinMetaNodeRequest,
    ProcessOnAuthMetaVerifyPassed,
    ProcessLeaveMetaNodeRequest,
    ProcessOnAuthMetaVerifyFailed,
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

static ConnectionAddrType GetCurrentConnectType(void)
{
    char ifCurrentName[NET_IF_NAME_LEN] = {0};
    ConnectionAddrType type = CONNECTION_ADDR_MAX;

    if (LnnGetLocalStrInfo(STRING_KEY_NET_IF_NAME, ifCurrentName, NET_IF_NAME_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetLocalStrInfo getCurrentConnectType failed");
        return type;
    }
    if (LnnGetAddrTypeByIfName(ifCurrentName, &type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "getCurrentConnectType unknown connect type");
    }
    return type;
}

static void OnDeviceVerifyPass(int64_t authId, const NodeInfo *info)
{
    AuthConnInfo connInfo;
    DeviceVerifyPassMsgPara *para = NULL;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "verify passed passively, authId=%" PRId64, authId);
    if (AuthGetConnInfo(authId, &connInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get AuthConnInfo fail, authId: %" PRId64, authId);
        return;
    }
    para = (DeviceVerifyPassMsgPara *)SoftBusMalloc(sizeof(DeviceVerifyPassMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc DeviceVerifyPassMsgPara fail");
        return;
    }
    if (!LnnConvertAuthConnInfoToAddr(&para->addr, &connInfo, GetCurrentConnectType())) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert connInfo to addr fail");
        SoftBusFree(para);
        return;
    }
    para->authId = authId;
    para->nodeInfo = DupNodeInfo(info);
    if (para->nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "dup NodeInfo fail");
        SoftBusFree(para);
        return;
    }
    if (PostMessageToHandler(MSG_TYPE_DEVICE_VERIFY_PASS, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post DEVICE_VERIFY_PASS msg fail");
        SoftBusFree(para->nodeInfo);
        SoftBusFree(para);
    }
}

static void OnDeviceDisconnect(int64_t authId)
{
    int64_t *para = NULL;
    para = (int64_t *)SoftBusMalloc(sizeof(int64_t));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc DeviceDisconnect para fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "auth device disconnect, authId: %" PRId64, authId);
    *para = authId;
    if (PostMessageToHandler(MSG_TYPE_DEVICE_DISCONNECT, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post DEVICE_DISCONNECT msg fail");
        SoftBusFree(para);
    }
}

static void OnLnnProcessNotTrustedMsgDelay(void *para)
{
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid info para");
        return;
    }
    int64_t authSeq[DISCOVERY_TYPE_COUNT] = {0};
    NotTrustedDelayInfo *info = (NotTrustedDelayInfo *)para;
    if (LnnGetAllAuthSeq(info->udid, authSeq, DISCOVERY_TYPE_COUNT) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline]LnnGetAllAuthSeq fail");
        SoftBusFree(info);
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (LnnConvertDlId(info->udid, CATEGORY_UDID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline] convert networkId fail");
        SoftBusFree(info);
        return;
    }
    uint32_t type;
    for (type = DISCOVERY_TYPE_WIFI; type < DISCOVERY_TYPE_P2P; type++) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
            "OnLnnProcessNotTrustedMsgDelay: authSeq %" PRId64 "-> %" PRId64,  info->authSeq[type], authSeq[type]);
    
        if (authSeq[type] == info->authSeq[type] && authSeq[type] != 0 && info->authSeq[type] != 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "[offline] LnnRequestLeaveSpecific type:%d", type);
            LnnRequestLeaveSpecific(networkId, LnnDiscTypeToConnAddrType((DiscoveryType)type));
            continue;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "after 5s authSeq=%" PRId64, authSeq[type]);
    }
    SoftBusFree(info);
}

static void OnDeviceNotTrusted(const char *peerUdid)
{
    if (peerUdid == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "peer udid is NULL");
        return;
    }
    uint32_t udidLen = strlen(peerUdid) + 1;
    if (udidLen > UDID_BUF_LEN) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not trusted udid is too long");
        return;
    }
    if (!LnnGetOnlineStateById(peerUdid, CATEGORY_UDID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "not trusted device has offline!");
        return;
    }
    NotTrustedDelayInfo *info  = (NotTrustedDelayInfo *)SoftBusCalloc(sizeof(NotTrustedDelayInfo));
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc NotTrustedDelayInfo fail");
        return;
    }
    if (LnnGetAllAuthSeq(peerUdid, info->authSeq, DISCOVERY_TYPE_COUNT) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline]LnnGetAllAuthSeq fail");
        SoftBusFree(info);
        return;
    }
    if (strcpy_s(info->udid, UDID_BUF_LEN, peerUdid) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy udid fail");
        SoftBusFree(info);
        return;
    }
    if (LnnSendNotTrustedInfo(info, DISCOVERY_TYPE_COUNT) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[offline]LnnSendNotTrustedInfo fail");
        SoftBusFree(info);
        return;
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), OnLnnProcessNotTrustedMsgDelay,
        info, NOT_TRUSTED_DEVICE_MSG_DELAY) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "async not trusted msg delay fail");
        SoftBusFree(info);
    }
}

static AuthVerifyListener g_verifyListener = {
    .onDeviceVerifyPass = OnDeviceVerifyPass,
    .onDeviceNotTrusted = OnDeviceNotTrusted,
    .onDeviceDisconnect = OnDeviceDisconnect,
};

static void PostVerifyResult(uint32_t requestId, int32_t retCode, int64_t authId, const NodeInfo *info)
{
    VerifyResultMsgPara *para = NULL;
    para = (VerifyResultMsgPara *)SoftBusCalloc(sizeof(VerifyResultMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc verify result msg para fail");
        return;
    }
    para->requestId = requestId;
    para->retCode = retCode;
    if (retCode == SOFTBUS_OK) {
        para->nodeInfo = DupNodeInfo(info);
        if (para->nodeInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "dup NodeInfo fail");
            SoftBusFree(para);
            return;
        }
        para->authId = authId;
    }
    if (PostMessageToHandler(MSG_TYPE_VERIFY_RESULT, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post verify result message failed");
        SoftBusFree(para->nodeInfo);
        SoftBusFree(para);
    }
}

static void OnVerifyPassed(uint32_t requestId, int64_t authId, const NodeInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "verify passed: requestId=%u, authId=%" PRId64, requestId, authId);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post verify result message failed");
        return;
    }
    PostVerifyResult(requestId, SOFTBUS_OK, authId, info);
}

static void OnVerifyFailed(uint32_t requestId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
        "verify failed: requestId=%u, reason=%d", requestId, reason);
    PostVerifyResult(requestId, reason, AUTH_INVALID_ID, NULL);
}

static AuthVerifyCallback g_verifyCallback = {
    .onVerifyPassed = OnVerifyPassed,
    .onVerifyFailed = OnVerifyFailed,
};

AuthVerifyCallback *LnnGetVerifyCallback(void)
{
    return &g_verifyCallback;
}

void OnAuthMetaVerifyPassed(uint32_t requestId, int64_t authMetaId, const NodeInfo *info)
{
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAuthMetaVerifyPassed info = NULL");
        return;
    }
    MetaJoinRequestNode *metaNode = FindMetaNodeByRequestId(requestId);
    if (metaNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAuthMetaVerifyPassed not find metaNode");
        return;
    }
    MetaAuthInfo *meta = (MetaAuthInfo *)SoftBusMalloc(sizeof(MetaAuthInfo));
    if (meta == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAuthMetaVerifyPassed meta = NULL");
        return;
    }
    meta->authMetaId = authMetaId;
    meta->metaJoinNode = metaNode;
    meta->info = *info;
    if (PostMessageToHandler(MSG_TYPE_JOIN_METANODE_AUTH_PASS, meta) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post join metanode authpass message failed");
        SoftBusFree(meta);
        return;
    }
}

void OnAuthMetaVerifyFailed(uint32_t requestId, int32_t reason)
{
    MetaJoinRequestNode *metaJoinNode = FindMetaNodeByRequestId(requestId);
    MetaReason *para = (MetaReason *)SoftBusMalloc(sizeof(MetaReason));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "OnAuthMetaVerifyFailed para = NULL");
        return;
    }
    para->metaJoinNode = metaJoinNode;
    para->reason = reason;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "OnAuthMetaVerifyFailed can find metaNode");
    if (PostMessageToHandler(MSG_TYPE_JOIN_METANODE_AUTH_FAIL, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post join metanode authfail message failed");
        SoftBusFree(para);
        return;
    }
}

static AuthVerifyCallback g_metaVerifyCallback = {
    .onVerifyPassed = OnAuthMetaVerifyPassed,
    .onVerifyFailed = OnAuthMetaVerifyFailed,
};

AuthVerifyCallback *LnnGetMetaVerifyCallback(void)
{
    return &g_metaVerifyCallback;
}

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

static ConnectionAddrKey *CreateConnectionAddrMsgParaKey(const ConnectionAddrKey *addrDataKey)
{
    ConnectionAddrKey *para = NULL;

    if (addrDataKey == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "addrDataKey is null");
        return NULL;
    }
    para = (ConnectionAddrKey *)SoftBusCalloc(sizeof(ConnectionAddrKey));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc connecton addrKey message fail");
        return NULL;
    }
    *para = *addrDataKey;
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
    para = (ElectMsgPara *)SoftBusMalloc(sizeof(ElectMsgPara));
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

static void OnReceiveNodeAddrChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size)
{
    (void)type;
    size_t addrLen = strnlen((const char *)msg, size);
    if (addrLen != size - 1 || addrLen == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:bad addr received!networkId=%s", __func__,
            AnonymizesNetworkID(networkId));
        return;
    }
    int ret = LnnSetDLNodeAddr(networkId, CATEGORY_NETWORK_ID, (const char *)msg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:update node addr failed!networkId=%s,ret=%d", __func__,
            AnonymizesNetworkID(networkId), ret);
    }
}

int32_t LnnUpdateNodeAddr(const char *addr)
{
    if (addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:null ptr!", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    NodeBasicInfo *info = NULL;
    int32_t infoNum, i;
    char localNetworkId[NETWORK_ID_BUF_LEN] = {0};
    char addrHis[SHORT_ADDRESS_MAX_LEN];

    if (LnnGetLocalStrInfo(STRING_KEY_NODE_ADDR, addrHis, SHORT_ADDRESS_MAX_LEN) == SOFTBUS_OK) {
        if (strlen(addr) == strlen(addrHis) && (strcmp(addr, addrHis) == 0)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "%s update the same node addr", __func__);
        }
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "%s start updating node addr", __func__);
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_NETWORKID, localNetworkId, sizeof(localNetworkId));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:get local network id failed!", __func__);
        return SOFTBUS_ERR;
    }

    ret = LnnSetLocalStrInfo(STRING_KEY_NODE_ADDR, addr);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:set local node addr failed!ret=%d", __func__, ret);
        return ret;
    }
    ret = LnnGetAllOnlineNodeInfo(&info, &infoNum);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:get all online node info fail", __func__);
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "%s:online nodes count=%d", __func__, infoNum);
        for (i = 0; i < infoNum; ++i) {
            if (strcmp(localNetworkId, info[i].networkId) == 0) {
                continue;
            }
            SoftBusLog(
                SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "sync node address to %s", AnonymizesNetworkID(info[i].networkId));
            if (LnnSendSyncInfoMsg(LNN_INFO_TYPE_NODE_ADDR, info[i].networkId, (const uint8_t *)addr, strlen(addr) + 1,
                NULL) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync node address to %s failed",
                    AnonymizesNetworkID(info[i].networkId));
            }
        }
        SoftBusFree(info);
    }
    LnnNotifyNodeAddressChanged(addr);
    return SOFTBUS_OK;
}

int32_t NodeInfoSync(void)
{
    if (LnnInitP2p() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init lnn p2p fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitNetworkInfo() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnInitNetworkInfo fail");
        return SOFTBUS_ERR;
    }
    if (LnnInitDevicename() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnInitDeviceName fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
    NodeInfoSync();
    NetBuilderConfigInit();
    if (RegAuthVerifyListener(&g_verifyListener) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register auth verify listener fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_MASTER_ELECT, OnReceiveMasterElectMsg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register sync master elect msg fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_NODE_ADDR, OnReceiveNodeAddrChangedMsg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "register node addr changed msg fail");
        return SOFTBUS_ERR;
    }
    if (ConifgLocalLedger() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "config local ledger fail");
        return SOFTBUS_ERR;
    }
    ListInit(&g_netBuilder.fsmList);
    ListInit(&g_netBuilder.pendingList);
    ListInit(&g_netBuilder.metaNodeList);
    g_netBuilder.nodeType = NODE_TYPE_L;
    g_netBuilder.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_netBuilder.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get default looper fail");
        return SOFTBUS_ERR;
    }
    g_netBuilder.handler.name = (char *)"NetBuilderHandler";
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid error!");
        return SOFTBUS_ERR;
    }
    LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, udid);
    LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, LnnGetLocalWeight());
    if (LnnInitFastOffline() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "fast offline init fail!");
        return SOFTBUS_ERR;
    }
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
    UnregAuthVerifyListener();
    LnnDeinitTopoManager();
    LnnDeinitP2p();
    LnnDeinitSyncInfoManager();
    LnnDeinitFastOffline();
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
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t MetaNodeServerJoin(ConnectionAddr *addr, CustomData *customData)
{
    ConnectionAddrKey addrDataKey = {
        .addr = *addr,
        .customData = *customData,
    };
    ConnectionAddrKey *para = NULL;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "MetaNodeServerJoin enter!");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = CreateConnectionAddrMsgParaKey(&addrDataKey);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "prepare join lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_JOIN_METANODE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post join lnn message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
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
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t MetaNodeServerLeave(const char *networkId)
{
    char *para = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "MetaNodeServerLeave enter!");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_NO_INIT;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "prepare leave lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_LEAVE_METANODE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post leave lnn message failed");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
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

int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType,
    const char *newNetworkId)
{
    LeaveInvalidConnMsgPara *para = NULL;

    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = (LeaveInvalidConnMsgPara *)SoftBusMalloc(sizeof(LeaveInvalidConnMsgPara));
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
    para = (uint16_t *)SoftBusMalloc(sizeof(uint16_t));
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
    para = (ElectMsgPara *)SoftBusMalloc(sizeof(ElectMsgPara));
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

/* Note: must called in connection fsm. */
int32_t LnnNotifyAuthHandleLeaveLNN(int64_t authId)
{
    LnnConnectionFsm *item = NULL;

    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(item, &g_netBuilder.fsmList, LnnConnectionFsm, node) {
        if (item->isDead) {
            continue;
        }
        if (item->connInfo.authId == authId) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO,
                "[id=%u]connection fsm already use authId: %" PRId64, item->id, authId);
            return SOFTBUS_OK;
        }
    }
    AuthHandleLeaveLNN(authId);
    return SOFTBUS_OK;
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen)
{
    bool *para = NULL;
    if (typeLen != CONNECTION_ADDR_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid typeLen");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnRequestLeaveByAddrType");
    if (g_netBuilder.isInit == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no init");
        return SOFTBUS_ERR;
    }
    para = (bool *)SoftBusMalloc(sizeof(bool) * typeLen);
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
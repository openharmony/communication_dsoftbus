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
#include "common_list.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_discovery_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_exchange_ledger_info.h"
#include "lnn_network_id.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_property.h"

#define CONFIG_MAX_LNN_CONNECTION_COUNT_KEY "MAX_LNN_CONNECTION_CNT"
#define DEFAULT_MAX_LNN_CONNECTION_COUNT 10

#define JOIN_DISCOVERY_TIMEOUT_LEN (60 * 1000UL)

typedef enum {
    MSG_TYPE_JOIN_LNN,
    MSG_TYPE_DISCOVERY_DEVICE,
    MSG_TYPE_CLEAN_CONN_FSM,
    MSG_TYPE_AUTH_KEY_GENERATED,
    MSG_TYPE_AUTH_DONE,
    MSG_TYPE_SYNC_DEVICE_INFO_DONE,
    MSG_TYPE_NOT_TRUSTED,
    MSG_TYPE_DISCONNECT,
    MSG_TYPE_LEAVE_LNN,
    MSG_TYPE_SYNC_OFFLINE_FINISH,
} NetBuilderMessageType;

typedef struct {
    NodeType nodeType;

    /* connection fsm list */
    ListNode fsmList;
    /* connection count */
    int32_t connCount;

    SoftBusLooper *looper;
    SoftBusHandler handler;

    int32_t maxConnCount;
    bool isInit;
} NetBuilder;

typedef struct {
    ConnectionAddr addr;
    int64_t authId;
    SoftBusVersion peerVersion;
} AuthKeyGeneratedMsgPara;

typedef struct {
    bool isSuccess;
    int64_t authId;
} AuthResultMsgPara;

typedef struct {
    ConnectionAddr addr;
    char networkId[NETWORK_ID_BUF_LEN];
    int32_t retCode;
} JoinResultMsgPara;

static NetBuilder g_netBuilder;

static void NetBuilderConfigInit(void)
{
    if (GetPropertyInt(CONFIG_MAX_LNN_CONNECTION_COUNT_KEY, &g_netBuilder.maxConnCount) != SOFTBUS_OK) {
        LOG_ERR("get lnn max connection count fail, use default value");
        g_netBuilder.maxConnCount = DEFAULT_MAX_LNN_CONNECTION_COUNT;
    }
}

static SoftBusMessage *CreateNetBuilderMessage(int32_t msgType, void *para)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LOG_ERR("malloc softbus message failed");
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
        LOG_ERR("create softbus message failed");
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
        return FindConnectionFsmByUdid(info->networkId);
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

static LnnConnectionFsm *StartNewConnectionFsm(ConnectionAddr *addr)
{
    LnnConnectionFsm *connFsm = NULL;

    if (g_netBuilder.connCount >= g_netBuilder.maxConnCount) {
        LOG_ERR("current connection is exceed max limit: %d", g_netBuilder.connCount);
        return NULL;
    }
    connFsm = LnnCreateConnectionFsm(addr);
    if (connFsm == NULL) {
        LOG_ERR("create connection fsm failed");
        return NULL;
    }
    if (LnnStartConnectionFsm(connFsm) != SOFTBUS_OK) {
        LOG_ERR("start connection fsm[id=%u] failed", connFsm->id);
        LnnDestroyConnectionFsm(connFsm);
        return NULL;
    }
    if (g_netBuilder.connCount == 0) {
        (void)AuthVerifyInit();
        LOG_INFO("hichain init ok....");
    }
    ListAdd(&g_netBuilder.fsmList, &connFsm->node);
    ++g_netBuilder.connCount;
    return connFsm;
}

static int32_t ProcessJoinLNNRequest(ConnectionAddr *addr, bool needReportFailure)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_OK;
    bool isCreate = false;

    if (addr == NULL) {
        LOG_ERR("addr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByAddr(addr);
    if (connFsm == NULL || connFsm->isDead) {
        LOG_INFO("create and start a new connection fsm");
        connFsm = StartNewConnectionFsm(addr);
        isCreate = true;
    }
    if (connFsm == NULL || LnnSendJoinRequestToConnFsm(connFsm) != SOFTBUS_OK) {
        LOG_ERR("process join lnn request failed");
        if (needReportFailure) {
            LnnNotifyJoinResult(addr, NULL, SOFTBUS_ERR);
        }
        if (connFsm != NULL && isCreate) {
            LnnDestroyConnectionFsm(connFsm);
        }
        rc = SOFTBUS_ERR;
    }
    SoftBusFree(addr);
    return rc;
}

static void CleanConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (connFsm == NULL) {
        LOG_ERR("connection fsm is null");
        return;
    }
    LOG_INFO("connection fsm[id=%u] is cleaned", connFsm->id);
    LnnDestroyConnectionFsm(connFsm);
}

static void StopConnectionFsm(LnnConnectionFsm *connFsm)
{
    if (LnnStopConnectionFsm(connFsm, CleanConnectionFsm) != SOFTBUS_OK) {
        LOG_ERR("stop connection fsm[id=%u] failed", connFsm->id);
    }
    ListDelete(&connFsm->node);
    --g_netBuilder.connCount;
    if (g_netBuilder.connCount == 0) {
        LOG_INFO("all connection disconnect");
        (void)AuthVerifyDeinit();
    }
}

static int32_t ProcessCleanConnectionFsm(ConnectionAddr *addr)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (addr == NULL) {
        LOG_ERR("addr is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByAddr(addr);
        if (connFsm == NULL) {
            LOG_INFO("can not find connection fsm");
            break;
        }
        StopConnectionFsm(connFsm);
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree(addr);
    return rc;
}

static int32_t ProcessAuthKeyGenerated(AuthKeyGeneratedMsgPara *para)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_OK;
    bool isCreate = false;

    if (para == NULL) {
        LOG_ERR("para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByAuthId(para->authId);
    if (connFsm == NULL) {
        LOG_INFO("create and start a new connection fsm as server side");
        connFsm = StartNewConnectionFsm(&para->addr);
        if (connFsm == NULL) {
            LOG_ERR("start server new connection failed: %llu", para->authId);
            SoftBusFree(para);
            return SOFTBUS_ERR;
        }
        isCreate = true;
        connFsm->connInfo.authId = para->authId;
    }
    connFsm->connInfo.peerVersion = para->peerVersion;
    if (LnnSendAuthKeyGenMsgToConnFsm(connFsm) != SOFTBUS_OK) {
        if (isCreate) {
            StopConnectionFsm(connFsm);
        }
        rc = SOFTBUS_ERR;
    }
    LOG_INFO("[id=%u]connection fsm auth key generated process done: %llu, %d",
        connFsm->id, para->authId, rc);
    SoftBusFree(para);
    return rc;
}

static int32_t ProcessAuthDone(AuthResultMsgPara *para)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc = SOFTBUS_ERR;

    if (para == NULL) {
        LOG_ERR("para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        connFsm = FindConnectionFsmByAuthId(para->authId);
        if (connFsm == NULL) {
            LOG_ERR("can not find connection fsm by authId: %lld", para->authId);
            break;
        }
        LOG_INFO("[id=%u]connection fsm auth done: %llu", connFsm->id, para->authId);
        if (LnnSendAuthResultMsgToConnFsm(connFsm, para->isSuccess) != SOFTBUS_OK) {
            LOG_ERR("send auth result to connection fsm[id=%u] failed", connFsm->id);
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree(para);
    return rc;
}

static int32_t ProcessSyncDeviceInfoDone(LnnRecvDeviceInfoMsgPara *para)
{
    LnnConnectionFsm *connFsm = NULL;
    int32_t rc;

    if (para == NULL) {
        LOG_ERR("recv device info msg para is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByAuthId(para->authId);
    if (connFsm == NULL) {
        LOG_ERR("can not find connection fsm by authId: %lld", para->authId);
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    // if send success, the memory of para will be freed by connection fsm
    rc = LnnSendPeerDevInfoToConnFsm(connFsm, para);
    if (rc != SOFTBUS_OK) {
        SoftBusFree(para);
    }
    LOG_INFO("send peer device info to connection fsm[id=%u] result=%d", connFsm->id, rc);
    return rc;
}

static int32_t ProcessDeviceNotTrusted(char *peerUdid)
{
    LnnConnectionFsm *connFsm = NULL;
    int rc = SOFTBUS_OK;

    if (peerUdid == NULL) {
        LOG_ERR("peer udid is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByUdid(peerUdid);
        if (connFsm == NULL) {
            LOG_INFO("ignore not trusted peer udid");
            break;
        }
        rc = LnnSendNotTrustedToConnFsm(connFsm);
        LOG_INFO("[id=%u]send not trusted msg to connection fsm result: %d", connFsm->id, rc);
    } while (false);
    SoftBusFree(peerUdid);
    return rc;
}

static int32_t ProcessAuthDisconnect(int64_t *authId)
{
    LnnConnectionFsm *connFsm = NULL;
    int rc = SOFTBUS_OK;

    if (authId == NULL) {
        LOG_ERR("authId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByAuthId(*authId);
        if (connFsm == NULL) {
            LOG_ERR("can not find connection fsm by authId: %lld", *authId);
            break;
        }
        LOG_INFO("[id=%u]auth disconnect, authId: %lld", connFsm->id, *authId);
        if (LnnSendDisconnectMsgToConnFsm(connFsm) != SOFTBUS_OK) {
            LOG_ERR("send disconnect to connection fsm[id=%u] failed", connFsm->id);
            break;
        }
        rc = SOFTBUS_OK;
    } while (false);
    SoftBusFree(authId);
    return rc;
}

static int32_t ProcessLeaveLNNRequest(char *networkId)
{
    LnnConnectionFsm *connFsm = NULL;
    int rc = SOFTBUS_ERR;

    if (networkId == NULL) {
        LOG_ERR("leave networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    do {
        connFsm = FindConnectionFsmByNetworkId(networkId);
        if (connFsm == NULL) {
            LOG_ERR("ignore invalid networkId");
            break;
        }
        rc = LnnSendLeaveRequestToConnFsm(connFsm);
        LOG_INFO("[id=%u]send leave LNN msg to connection fsm result: %d", connFsm->id, rc);
    } while (false);
    if (rc != SOFTBUS_OK) {
        LnnNotifyLeaveResult(networkId, SOFTBUS_ERR);
    }
    SoftBusFree(networkId);
    return rc;
}

static int32_t ProcessSyncOfflineFinish(char *networkId)
{
    LnnConnectionFsm *connFsm = NULL;
    int rc;

    if (networkId == NULL) {
        LOG_ERR("sync offline finish networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    connFsm = FindConnectionFsmByNetworkId(networkId);
    if (connFsm == NULL) {
        LOG_INFO("no connection fsm");
        SoftBusFree(networkId);
        return SOFTBUS_OK;
    }
    rc = LnnSendSyncOfflineFinishToConnFsm(connFsm);
    LOG_INFO("[id=%u]send sync offline msg to connection fsm result: %d", connFsm->id, rc);
    SoftBusFree(networkId);
    return rc;
}

static void NetBuilderMessageHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LOG_ERR("msg is null in net builder handler");
        return;
    }
    LOG_INFO("net builder process msg: %d", msg->what);
    switch (msg->what) {
        case MSG_TYPE_JOIN_LNN:
            ProcessJoinLNNRequest((ConnectionAddr *)msg->obj, true);
            break;
        case MSG_TYPE_DISCOVERY_DEVICE:
            ProcessJoinLNNRequest((ConnectionAddr *)msg->obj, false);
            break;
        case MSG_TYPE_CLEAN_CONN_FSM:
            ProcessCleanConnectionFsm((ConnectionAddr *)msg->obj);
            break;
        case MSG_TYPE_AUTH_KEY_GENERATED:
            ProcessAuthKeyGenerated((AuthKeyGeneratedMsgPara *)msg->obj);
            break;
        case MSG_TYPE_AUTH_DONE:
            ProcessAuthDone((AuthResultMsgPara *)msg->obj);
            break;
        case MSG_TYPE_SYNC_DEVICE_INFO_DONE:
            ProcessSyncDeviceInfoDone((LnnRecvDeviceInfoMsgPara *)msg->obj);
            break;
        case MSG_TYPE_NOT_TRUSTED:
            ProcessDeviceNotTrusted((char *)msg->obj);
            break;
        case MSG_TYPE_DISCONNECT:
            ProcessAuthDisconnect((int64_t *)msg->obj);
            break;
        case MSG_TYPE_LEAVE_LNN:
            ProcessLeaveLNNRequest((char *)msg->obj);
            break;
        case MSG_TYPE_SYNC_OFFLINE_FINISH:
            ProcessSyncOfflineFinish((char *)msg->obj);
            break;
        default:
            break;
    }
}

static void OnAuthKeyGenerated(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion)
{
    AuthKeyGeneratedMsgPara *para = NULL;

    para = SoftBusMalloc(sizeof(AuthKeyGeneratedMsgPara));
    if (para == NULL) {
        LOG_ERR("malloc auth key generated msg para fail");
        return;
    }
    if (!LnnConvertOptionToAddr(&para->addr, option, CONNECTION_ADDR_ETH)) {
        LOG_ERR("convert option to addr failed");
        SoftBusFree(para);
        return;
    }
    para->authId = authId;
    para->peerVersion = peerVersion;
    if (PostMessageToHandler(MSG_TYPE_AUTH_KEY_GENERATED, para) != SOFTBUS_OK) {
        LOG_ERR("post auth key generated message failed");
        SoftBusFree(para);
    }
    LOG_INFO("auth key generated: %lld", authId);
}

static void OnAuthFailed(int64_t authId)
{
    AuthResultMsgPara *para = SoftBusMalloc(sizeof(AuthResultMsgPara));
    if (para == NULL) {
        LOG_ERR("malloc auth result fail");
        return;
    }
    para->isSuccess = false;
    para->authId = authId;
    if (PostMessageToHandler(MSG_TYPE_AUTH_DONE, para) != SOFTBUS_OK) {
        LOG_ERR("post auth fail message failed");
        SoftBusFree(para);
    }
    LOG_INFO("auth failed: %lld", authId);
}

static void OnAuthPassed(int64_t authId)
{
    AuthResultMsgPara *para = SoftBusMalloc(sizeof(AuthResultMsgPara));
    if (para == NULL) {
        LOG_ERR("malloc auth result fail");
        return;
    }
    para->isSuccess = true;
    para->authId = authId;
    if (PostMessageToHandler(MSG_TYPE_AUTH_DONE, para) != SOFTBUS_OK) {
        LOG_ERR("post auth passed message failed");
        SoftBusFree(para);
    }
    LOG_INFO("auth passed: %lld", authId);
}

static void OnRecvPeerDeviceInfo(int64_t authId, AuthSideFlag side, const char *peerUuid, uint8_t *data, uint32_t len)
{
    LnnRecvDeviceInfoMsgPara *para = NULL;

    if (peerUuid == NULL || data == NULL) {
        LOG_ERR("invalid peer device info para");
        return;
    }
    para = SoftBusCalloc(sizeof(*para) + len);
    if (para == NULL) {
        LOG_ERR("malloc recv device info msg para fail");
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
        LOG_ERR("copy data buffer fail");
        SoftBusFree(para);
        return;
    }
    para->len = len;
    if (PostMessageToHandler(MSG_TYPE_SYNC_DEVICE_INFO_DONE, para) != SOFTBUS_OK) {
        LOG_ERR("post sync device info done message failed");
        SoftBusFree(para);
    }
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
    if (PostMessageToHandler(MSG_TYPE_NOT_TRUSTED, udid) != SOFTBUS_OK) {
        LOG_ERR("post device not trusted message failed");
        SoftBusFree(udid);
    }
}

static void OnDisconnect(int64_t authId)
{
    int64_t *para = (int64_t *)SoftBusMalloc(sizeof(int64_t));
    if (para == NULL) {
        LOG_ERR("malloc authId fail");
        return;
    }
    LOG_INFO("auth channel disconnect, authId is %lld", authId);
    *para = authId;
    if (PostMessageToHandler(MSG_TYPE_DISCONNECT, (void *)para) != SOFTBUS_OK) {
        LOG_ERR("post auth disconnect message failed");
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
        LOG_ERR("addr is null");
        return NULL;
    }
    para = (ConnectionAddr *)SoftBusCalloc(sizeof(ConnectionAddr));
    if (para == NULL) {
        LOG_ERR("malloc connecton addr message fail");
        return NULL;
    }
    *para = *addr;
    return para;
}

static char *CreateNetworkIdMsgPara(const char *networkId)
{
    char *para = NULL;

    if (networkId == NULL) {
        LOG_ERR("networkId is null");
        return NULL;
    }
    para = (char *)SoftBusMalloc(NETWORK_ID_BUF_LEN);
    if (para == NULL) {
        LOG_ERR("malloc networkId message fail");
        return NULL;
    }
    if (strncpy_s(para, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LOG_ERR("copy network id fail");
        SoftBusFree(para);
        return NULL;
    }
    return para;
}

int32_t LnnInitNetBuilder(void)
{
    char uuid[UUID_BUF_LEN];
    char networkId[NETWORK_ID_BUF_LEN];

    if (g_netBuilder.isInit == true) {
        LOG_INFO("init net builder repeatly");
        return SOFTBUS_OK;
    }
    NetBuilderConfigInit();
    if (AuthRegCallback(LNN, &g_verifyCb) != SOFTBUS_OK) {
        LOG_ERR("register auth cb fail");
        return SOFTBUS_ERR;
    }

    if (LnnGenLocalNetworkId(networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK ||
        LnnGenLocalUuid(uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LOG_ERR("get local id fail");
        return SOFTBUS_ERR;
    }
    LnnSetLocalStrInfo(STRING_KEY_UUID, uuid);
    LnnSetLocalStrInfo(STRING_KEY_NETWORKID, networkId);

    ListInit(&g_netBuilder.fsmList);
    g_netBuilder.nodeType = NODE_TYPE_L;
    g_netBuilder.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_netBuilder.looper == NULL) {
        LOG_ERR("get default looper failed");
        return SOFTBUS_ERR;
    }
    g_netBuilder.handler.name = "NetBuilderHandler";
    g_netBuilder.handler.looper = g_netBuilder.looper;
    g_netBuilder.handler.HandleMessage = NetBuilderMessageHandler;
    g_netBuilder.isInit = true;
    LOG_INFO("init net builder success");
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
    g_netBuilder.isInit = false;
}

int32_t LnnServerJoin(ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    LOG_INFO("LnnServerJoin enter!");
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        LOG_ERR("prepare join lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_JOIN_LNN, para) != SOFTBUS_OK) {
        LOG_ERR("post join lnn message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnServerLeave(const char *networkId)
{
    char *para = NULL;

    LOG_INFO("LnnServerLeave enter!");
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        LOG_ERR("prepare leave lnn message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_LEAVE_LNN, para) != SOFTBUS_OK) {
        LOG_ERR("post leave lnn message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    LOG_INFO("LnnNotifyDiscoveryDevice enter!");
    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        LOG_ERR("malloc discovery device message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_DISCOVERY_DEVICE, para) != SOFTBUS_OK) {
        LOG_ERR("post notify discovery device message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnRequestCleanConnectionFsm(const ConnectionAddr *addr)
{
    ConnectionAddr *para = NULL;

    para = CreateConnectionAddrMsgPara(addr);
    if (para == NULL) {
        LOG_ERR("malloc clean connection fsm msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_CLEAN_CONN_FSM, para) != SOFTBUS_OK) {
        LOG_ERR("post request clean connectionlnn message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnNotifySyncOfflineFinish(const char *networkId)
{
    char *para = NULL;

    if (g_netBuilder.isInit == false) {
        LOG_ERR("no init");
        return SOFTBUS_ERR;
    }
    para = CreateNetworkIdMsgPara(networkId);
    if (para == NULL) {
        LOG_ERR("prepare notify sync offline message fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_SYNC_OFFLINE_FINISH, para) != SOFTBUS_OK) {
        LOG_ERR("post sync offline finish message failed");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

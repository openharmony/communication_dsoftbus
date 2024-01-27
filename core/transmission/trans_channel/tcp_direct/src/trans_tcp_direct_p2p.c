/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "trans_tcp_direct_p2p.h"

#include <securec.h>

#include "cJSON.h"

#include "auth_interface.h"
#include "lnn_lane_link.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_proxychannel_pipeline.h"
#include "softbus_socket.h"
#include "trans_lane_pending_ctl.h"
#include "trans_log.h"
#include "trans_tcp_direct_json.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"
#include "wifi_direct_manager.h"

#define ID_OFFSET (1)
#define NETWORK_ID_LEN 7
#define HML_IP_PREFIX "172.30."
#define P2P_VERIFY_REQUEST 0
#define P2P_VERIFY_REPLY 1

static int32_t g_p2pSessionPort = -1;
static char g_p2pSessionIp[IP_LEN] = {0};
static SoftBusMutex g_p2pLock;
static SoftBusList *g_hmlListenerList = NULL;

static int32_t StartNewP2pListener(const char *ip, int32_t *port)
{
    int32_t listenerPort;
    LocalListenerInfo info;
    info.type = CONNECT_P2P;
    (void)memset_s(info.socketOption.addr, sizeof(info.socketOption.addr), 0, sizeof(info.socketOption.addr));
    info.socketOption.port = *port;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    info.socketOption.moduleId = DIRECT_CHANNEL_SERVER_P2P;

    if (strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), ip) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy addr failed!");
        return SOFTBUS_ERR;
    }

    listenerPort = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_P2P, &info);
    if (listenerPort < 0) {
        TRANS_LOGE(TRANS_CTRL, "start listener fail");
        return SOFTBUS_ERR;
    }
    *port = listenerPort;
    g_p2pSessionPort = *port;
    return SOFTBUS_OK;
}

static int32_t StartNewHmlListener(const char *ip, int32_t *port, ListenerModule *moudleType)
{
    int32_t listenerPort = 0;
    LocalListenerInfo info;
    info.type = CONNECT_P2P;
    (void)memset_s(info.socketOption.addr, sizeof(info.socketOption.addr), 0, sizeof(info.socketOption.addr));
    info.socketOption.port = *port;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    if (strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), ip) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy addr failed!");
        return SOFTBUS_ERR;
    }
    for (int32_t i = DIRECT_CHANNEL_SERVER_HML_START; i <= DIRECT_CHANNEL_SERVER_HML_END; i++) {
        info.socketOption.moduleId = (ListenerModule)i;
        listenerPort = TransTdcStartSessionListener((ListenerModule)i, &info);
        if (listenerPort >= 0) {
            *moudleType = (ListenerModule)i;
            break;
        }
    }
    if (listenerPort < 0) {
        TRANS_LOGE(TRANS_CTRL, "listenerPort is invalid!");
        return SOFTBUS_ERR;
    }
    *port = listenerPort;
    return SOFTBUS_OK;
}

static void DelHmlListenerByMoudle(ListenerModule type)
{
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (item->moudleType == type) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_hmlListenerList->cnt--;
            (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
}

void StopHmlListener(ListenerModule module)
{
    if (StopBaseListener(module) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "StopHmlListener stop listener fail. module=%{public}d", module);
    }
    DelHmlListenerByMoudle(module);
}

void StopP2pSessionListener()
{
    if (g_p2pSessionPort > 0) {
        if (StopBaseListener(DIRECT_CHANNEL_SERVER_P2P) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "stop listener fail");
        }
    }

    g_p2pSessionPort = -1;
    g_p2pSessionIp[0] = '\0';
}

static void NotifyP2pSessionConnClear(ListNode *sessionConnList)
{
    if (sessionConnList == NULL) {
        return;
    }

    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, sessionConnList, SessionConn, node) {
        (void)NotifyChannelOpenFailed(item->channelId, SOFTBUS_TRANS_NET_STATE_CHANGED);
        TransSrvDelDataBufNode(item->channelId);
        SoftBusFree(item);
    }
    TRANS_LOGI(TRANS_CTRL, "p2psession conn clear finished");
}

static void ClearP2pSessionConn(void)
{
    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;

    SoftBusList *sessionList = GetSessionConnList();
    if (sessionList == NULL || GetSessionConnLock() != SOFTBUS_OK) {
        return;
    }

    ListNode tempSessionConnList;
    ListInit(&tempSessionConnList);
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &sessionList->list, SessionConn, node) {
        if (item->status < TCP_DIRECT_CHANNEL_STATUS_CONNECTED && item->appInfo.routeType == WIFI_P2P) {
            ListDelete(&item->node);
            sessionList->cnt--;
            ListAdd(&tempSessionConnList, &item->node);
        }
    }
    ReleaseSessonConnLock();

    NotifyP2pSessionConnClear(&tempSessionConnList);
}

static int32_t CreatHmlListenerList(void)
{
    if (g_hmlListenerList == NULL) {
        g_hmlListenerList = CreateSoftBusList();
        if (g_hmlListenerList == NULL) {
            TRANS_LOGE(TRANS_CTRL, "CreateSoftBusList fail");
            return SOFTBUS_MALLOC_ERR;
        }
    }
    return SOFTBUS_OK;
}

ListenerModule GetMoudleByHmlIp(const char *ip)
{
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock fail");
        return UNUSE_BUTT;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (strncmp(item->myIp, ip, IP_LEN) == 0) {
            (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
            return item->moudleType;
        }
    }
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
    return UNUSE_BUTT;
}

static int32_t StartHmlListener(const char *ip, int32_t *port)
{
    TRANS_LOGI(TRANS_CTRL, "port=%{public}d", *port);
    if (g_hmlListenerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "hmlListenerList not init");
        return SOFTBUS_ERR;
    }
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (strncmp(item->myIp, ip, IP_LEN) == 0) {
            *port = item->myPort;
            (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
            TRANS_LOGI(TRANS_CTRL, "succ, port=%{public}d", *port);
            return SOFTBUS_OK;
        }
    }
    ListenerModule moudleType = UNUSE_BUTT;
    if (StartNewHmlListener(ip, port, &moudleType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "create new listener fail");
        (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
        return SOFTBUS_ERR;
    }
    item = (HmlListenerInfo *)SoftBusCalloc(sizeof(HmlListenerInfo));
    if (item == NULL) {
        StopHmlListener(moudleType);
        (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
        TRANS_LOGE(TRANS_CTRL, "HmlListenerInfo malloc fail");
        return SOFTBUS_ERR;
    }
    item->myPort = *port;
    item->moudleType = moudleType;
    if (strncpy_s(item->myIp, IP_LEN, ip, IP_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "HmlListenerInfo copy ip fail");
        SoftBusFree(item);
        StopHmlListener(moudleType);
        (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&(g_hmlListenerList->list), &(item->node));
    g_hmlListenerList->cnt++;
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
    TRANS_LOGI(TRANS_CTRL, "StartHmlListener succ, port=%{public}d", *port);
    return SOFTBUS_OK;
}

static int32_t StartP2pListener(const char *ip, int32_t *port)
{
    if (ip == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ip is null");
        return SOFTBUS_ERR;
    }
    if (strncmp(ip, HML_IP_PREFIX, NETWORK_ID_LEN) == 0) {
        return StartHmlListener(ip, port);
    }
    TRANS_LOGI(TRANS_CTRL, "port=%{public}d", *port);
    if (SoftBusMutexLock(&g_p2pLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_ERR;
    }
    if (g_p2pSessionPort > 0 && strcmp(ip, g_p2pSessionIp) != 0) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        ClearP2pSessionConn();
        StopP2pSessionListener();
    }
    if (g_p2pSessionPort > 0) {
        *port = g_p2pSessionPort;
        (void)SoftBusMutexUnlock(&g_p2pLock);
        return SOFTBUS_OK;
    }

    if (StartNewP2pListener(ip, port) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "start new listener fail");
        (void)SoftBusMutexUnlock(&g_p2pLock);
        return SOFTBUS_ERR;
    }

    g_p2pSessionPort = *port;
    if (strcpy_s(g_p2pSessionIp, sizeof(g_p2pSessionIp), ip) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s fail");
        StopP2pSessionListener();
        (void)SoftBusMutexUnlock(&g_p2pLock);
        return SOFTBUS_MEM_ERR;
    }
    (void)SoftBusMutexUnlock(&g_p2pLock);
    TRANS_LOGI(TRANS_CTRL, "end: port=%{public}d", *port);
    return SOFTBUS_OK;
}

static void OnChannelOpenFail(int32_t channelId, int32_t errCode)
{
    TRANS_LOGW(TRANS_CTRL, "channelId=%{public}d", channelId);
    NotifyChannelOpenFailed(channelId, errCode);
    TransDelSessionConnById(channelId);
    TransSrvDelDataBufNode(channelId);
    TRANS_LOGW(TRANS_CTRL, "ok");
}

static int32_t SendAuthData(int64_t authId, int32_t module, int32_t flag, int64_t seq, const char *data)
{
    TRANS_LOGI(TRANS_CTRL,
        "SendAuthData: authId=%{public}" PRId64 ", model=%{public}d, flag=%{public}d, seq=%{public}" PRId64,
        authId, module, flag, seq);
    AuthTransData dataInfo = {
        .module = module,
        .flag = flag,
        .seq = seq,
        .len = strlen(data) + 1,
        .data = (const uint8_t *)data,
    };
    if (AuthPostTransData(authId, &dataInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "AuthPostTransData failed.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t VerifyP2p(int64_t authId, const char *myIp, const char *peerIp, int32_t myPort, int64_t seq)
{
    TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 ", port=%{public}d", authId, myPort);
    char *msg = NULL;
    int32_t ret;
    msg = VerifyP2pPack(myIp, myPort, peerIp);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "verifyp2p pack fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ret = SendAuthData(authId, MODULE_P2P_LISTEN, MSG_FLAG_REQUEST, (int64_t)seq, msg);
    cJSON_free(msg);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "VerifyP2p send auth data fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnAuthConnOpened(uint32_t requestId, int64_t authId)
{
    TRANS_LOGI(TRANS_CTRL, "reqId=%{public}u, authId=%{public}" PRId64,
        requestId, authId);
    int32_t channelId = INVALID_CHANNEL_ID;
    SessionConn *conn = NULL;

    if (GetSessionConnLock() != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    conn = GetSessionConnByRequestId(requestId);
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "not find session");
        ReleaseSessonConnLock();
        goto EXIT_ERR;
    }
    channelId = conn->channelId;
    conn->authId = authId;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    ReleaseSessonConnLock();

    if (VerifyP2p(authId, conn->appInfo.myData.addr, conn->appInfo.peerData.addr,
        conn->appInfo.myData.port, conn->req) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "verify p2p fail");
        goto EXIT_ERR;
    }
    TRANS_LOGI(TRANS_CTRL, "ok");
    return;
EXIT_ERR:
    if (channelId != INVALID_CHANNEL_ID) {
        OnChannelOpenFail(channelId, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
    }
}

static void OnAuthConnOpenFailed(uint32_t requestId, int32_t reason)
{
    TRANS_LOGW(TRANS_CTRL, "OnAuthConnOpenFailed: reqId=%{public}u, reason=%{public}d", requestId, reason);
    SessionConn *conn = NULL;
    int32_t channelId;

    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get session conn lock fail");
        return;
    }
    conn = GetSessionConnByRequestId(requestId);
    if (conn == NULL) {
        ReleaseSessonConnLock();
        TRANS_LOGE(TRANS_CTRL, "get session conn by requestid fail");
        return;
    }
    channelId = conn->channelId;
    ReleaseSessonConnLock();

    (void)OnChannelOpenFail(channelId, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
    TRANS_LOGW(TRANS_CTRL, "ok");
}

static int32_t OpenAuthConn(const char *uuid, uint32_t reqId, bool isMeta)
{
    TRANS_LOGI(TRANS_CTRL, "reqId=%{public}u", reqId);
    AuthConnInfo auth;
    (void)memset_s(&auth, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));
    int32_t ret = AuthGetP2pConnInfo(uuid, &auth, isMeta);
    if (ret != SOFTBUS_OK && AuthGetPreferConnInfo(uuid, &auth, isMeta) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get auth info fail");
        return SOFTBUS_ERR;
    }
    cb.onConnOpened = OnAuthConnOpened;
    cb.onConnOpenFailed = OnAuthConnOpenFailed;
    if (AuthOpenConn(&auth, reqId, &cb, isMeta) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "open auth conn fail");
        return SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED;
    }

    TRANS_LOGI(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

static void SendVerifyP2pFailRsp(int64_t authId, int64_t seq,
    int32_t code, int32_t errCode, const char *errDesc, bool isAuthLink)
{
    char *reply = VerifyP2pPackError(code, errCode, errDesc);
    if (reply == NULL) {
        TRANS_LOGE(TRANS_CTRL, "verify p2ppack error");
        return;
    }
    if (isAuthLink) {
        if (SendAuthData(authId, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, reply) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send auth data fail");
        }
    } else {
        uint32_t strLen = strlen(reply) + 1;
        char *sendMsg = (char*)SoftBusCalloc(strLen + sizeof(int64_t) + sizeof(int64_t));
        if (sendMsg == NULL) {
            TRANS_LOGE(TRANS_CTRL, "softbuscalloc fail");
            cJSON_free(reply);
            return;
        }
        *(int64_t*)sendMsg = P2P_VERIFY_REPLY;
        *(int64_t*)(sendMsg + sizeof(int64_t)) = seq;
        if (strcpy_s(sendMsg  + sizeof(int64_t) + sizeof(int64_t), strLen, reply) != EOK) {
            cJSON_free(reply);
            SoftBusFree(sendMsg);
            return;
        }
        TransProxyPipelineSendMessage(
            authId, (uint8_t *)sendMsg, strLen + sizeof(int64_t) + sizeof(int64_t), MSG_TYPE_IP_PORT_EXCHANGE);
        SoftBusFree(sendMsg);
    }
    cJSON_free(reply);
}

static int32_t SendVerifyP2pRsp(int64_t authId, int32_t module, int32_t flag, int64_t seq,
    const char *reply, bool isAuthLink)
{
    int32_t ret = SOFTBUS_ERR;
    if (isAuthLink) {
        ret = SendAuthData(authId, module, flag, seq, reply);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send auth data fail");
        }
    } else {
        uint32_t strLen = strlen(reply) + 1;
        char *sendMsg = (char*)SoftBusCalloc(strLen + sizeof(int64_t) + sizeof(int64_t));
        if (sendMsg == NULL) {
            TRANS_LOGE(TRANS_CTRL, "softbuscalloc fail");
            return SOFTBUS_ERR;
        }
        *(int64_t*)sendMsg = P2P_VERIFY_REPLY;
        *(int64_t*)(sendMsg + sizeof(int64_t)) = seq;
        if (strcpy_s(sendMsg  + sizeof(int64_t) + sizeof(int64_t), strLen, reply) != EOK) {
            SoftBusFree(sendMsg);
            return SOFTBUS_ERR;
        }
        ret = TransProxyPipelineSendMessage(
            authId, (uint8_t *)sendMsg, strLen + sizeof(int64_t) + sizeof(int64_t), MSG_TYPE_IP_PORT_EXCHANGE);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "TransProxyPipelineSendMessage fail");
        }
        SoftBusFree(sendMsg);
    }
    return ret;
}

static void OutputAnonymizeIpAddress(const char *myIp, const char *peerIp)
{
    char anonymizedMyIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(anonymizedMyIp, IP_LEN, myIp, IP_LEN);
    char anonymizedPeerIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(anonymizedPeerIp, IP_LEN, peerIp, IP_LEN);
    TRANS_LOGE(TRANS_CTRL, "StartListener failed, myIp=%{public}s peerIp=%{public}s", anonymizedMyIp, anonymizedPeerIp);
}

static int32_t OnVerifyP2pRequest(int64_t authId, int64_t seq, const cJSON *json, bool isAuthLink)
{
    TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 ", seq=%{public}" PRId64, authId, seq);
    int32_t peerPort = 0;
    char peerIp[IP_LEN] = {0};
    int32_t myPort = 0;
    char myIp[IP_LEN] = {0};
    struct WifiDirectManager *pManager = NULL;

    int32_t ret = VerifyP2pUnPack(json, peerIp, IP_LEN, &peerPort);
    if (ret != SOFTBUS_OK) {
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "OnVerifyP2pRequest unpack fail", isAuthLink);
        return ret;
    }

    pManager = GetWifiDirectManager();
    if (pManager == NULL || pManager->getLocalIpByRemoteIp == NULL) {
        TRANS_LOGE(TRANS_CTRL, "get wifidirectmanager or get localipbyremoteip fail");
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, SOFTBUS_ERR,
            "get wifidirectmanager or localip fail", isAuthLink);
        return SOFTBUS_ERR;
    }

    if (pManager->getLocalIpByRemoteIp(peerIp, myIp, sizeof(myIp)) != SOFTBUS_OK) {
        OutputAnonymizeIpAddress(myIp, peerIp);
        TRANS_LOGE(TRANS_CTRL, "OnVerifyP2pRequest get p2p ip fail");
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "get p2p ip fail", isAuthLink);
        return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
    }

    ret = StartP2pListener(myIp, &myPort);
    if (ret != SOFTBUS_OK) {
        OutputAnonymizeIpAddress(myIp, peerIp);
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "invalid p2p port", isAuthLink);
        return SOFTBUS_ERR;
    }

    char *reply = VerifyP2pPack(myIp, myPort, NULL);
    if (reply == NULL) {
        SendVerifyP2pFailRsp(authId, seq, CODE_VERIFY_P2P, ret, "pack reply failed", isAuthLink);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ret = SendVerifyP2pRsp(authId, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, reply, isAuthLink);
    cJSON_free(reply);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    LaneAddP2pAddressByIp(peerIp, peerPort);
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

static int32_t ConnectTcpDirectPeer(const char *addr, int port)
{
    ConnectOption options;
    options.type = CONNECT_P2P;
    (void)memset_s(options.socketOption.addr, sizeof(options.socketOption.addr), 0, sizeof(options.socketOption.addr));
    options.socketOption.port = port;
    options.socketOption.protocol = LNN_PROTOCOL_IP;
    options.socketOption.moduleId = DIRECT_CHANNEL_CLIENT;

    int32_t ret = strcpy_s(options.socketOption.addr, sizeof(options.socketOption.addr), addr);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed! ret=%{public}" PRId32, ret);
        return SOFTBUS_ERR;
    }

    return ConnOpenClientSocket(&options, BIND_ADDR_ALL, true);
}

static int32_t AddHmlTrigger(int32_t fd, const char *myAddr, int64_t seq)
{
    ListenerModule moudleType;
    SessionConn *conn = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != 0) {
        TRANS_LOGE(TRANS_CTRL, "StartHmlListener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (strncmp(item->myIp, myAddr, IP_LEN) == 0) {
            if (AddTrigger(item->moudleType, fd, WRITE_TRIGGER) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "fail");
                (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
                return SOFTBUS_ERR;
            }
            moudleType = item->moudleType;
            (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
            if (GetSessionConnLock() != SOFTBUS_OK) {
                return SOFTBUS_LOCK_ERR;
            }
            conn = GetSessionConnByReq(seq);
            if (conn == NULL) {
                ReleaseSessonConnLock();
                return SOFTBUS_NOT_FIND;
            }
            conn->listenMod = moudleType;
            ReleaseSessonConnLock();
            return SOFTBUS_OK;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "not found correct hml ip");
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
    return SOFTBUS_ERR;
}

static int32_t AddP2pOrHmlTrigger(int32_t fd, const char *myAddr, int64_t seq)
{
    if (strncmp(myAddr, HML_IP_PREFIX, NETWORK_ID_LEN) == 0) {
        return AddHmlTrigger(fd, myAddr, seq);
    } else {
        if (AddTrigger(DIRECT_CHANNEL_SERVER_P2P, fd, WRITE_TRIGGER) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "fail");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t OnVerifyP2pReply(int64_t authId, int64_t seq, const cJSON *json)
{
    TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 ", seq=%{public}" PRId64, authId, seq);
    SessionConn *conn = NULL;
    int32_t ret = SOFTBUS_ERR;
    int32_t channelId = INVALID_CHANNEL_ID;
    int32_t fd = -1;
    char peerNetworkId[DEVICE_ID_SIZE_MAX] = { 0 };
    char peerAddr[IP_LEN] = { 0 };
    char myAddr[IP_LEN] = { 0 };
    int32_t peerPort = -1;

    if (GetSessionConnLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "getsessionconnlock fail");
        return SOFTBUS_LOCK_ERR;
    }
    conn = GetSessionConnByReq(seq);
    if (conn == NULL) {
        ReleaseSessonConnLock();
        return SOFTBUS_NOT_FIND;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(conn->channelId + ID_OFFSET));
    channelId = conn->channelId;

    ret = VerifyP2pUnPack(json, conn->appInfo.peerData.addr, IP_LEN, &conn->appInfo.peerData.port);
    if (ret != SOFTBUS_OK) {
        ReleaseSessonConnLock();
        TRANS_LOGE(TRANS_CTRL, "unpack fail: ret=%{public}d", ret);
        goto EXIT_ERR;
    }
    TRANS_LOGI(TRANS_CTRL, "peer wifi: peerPort=%{public}d", conn->appInfo.peerData.port);

    fd = ConnectTcpDirectPeer(conn->appInfo.peerData.addr, conn->appInfo.peerData.port);
    if (fd <= 0) {
        ReleaseSessonConnLock();
        TRANS_LOGE(TRANS_CTRL, "conn fail: fd=%{public}d", fd);
        goto EXIT_ERR;
    }
    conn->appInfo.fd = fd;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_CONNECTING;
    if (strcpy_s(peerNetworkId, sizeof(peerNetworkId), conn->appInfo.peerNetWorkId) != EOK ||
        strcpy_s(peerAddr, sizeof(peerAddr), conn->appInfo.peerData.addr) != EOK ||
        strcpy_s(myAddr, sizeof(myAddr), conn->appInfo.myData.addr) != EOK) {
        ReleaseSessonConnLock();
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed!");
        goto EXIT_ERR;
    }
    peerPort = conn->appInfo.peerData.port;
    ReleaseSessonConnLock();

    if (TransSrvAddDataBufNode(channelId, fd) != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    if (AddP2pOrHmlTrigger(fd, myAddr, seq) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "AddP2pOrHmlTrigger fail");
        goto EXIT_ERR;
    }

    LaneAddP2pAddress(peerNetworkId, peerAddr, peerPort);

    TRANS_LOGI(TRANS_CTRL, "end: fd=%{public}d", fd);
    return SOFTBUS_OK;
EXIT_ERR:
    TRANS_LOGE(TRANS_CTRL, "fail");
    if (channelId != INVALID_CHANNEL_ID) {
        OnChannelOpenFail(channelId, SOFTBUS_TRANS_HANDSHAKE_ERROR);
    }
    return SOFTBUS_ERR;
}

static void OnAuthMsgProc(int64_t authId, int32_t flags, int64_t seq, const cJSON *json)
{
    int32_t ret = SOFTBUS_ERR;
    if (flags == MSG_FLAG_REQUEST) {
        ret = OnVerifyP2pRequest(authId, seq, json, true);
    } else {
        ret = OnVerifyP2pReply(authId, seq, json);
    }
    TRANS_LOGI(TRANS_CTRL, "result: ret=%{public}d", ret);
    return;
}

static void OnAuthDataRecv(int64_t authId, const AuthTransData *data)
{
    if (data == NULL || data->data == NULL || data->len < 1) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return;
    }
    TRANS_LOGI(TRANS_CTRL, "module=%{public}d, seq=%{public}" PRId64 ", len=%{public}u",
        data->module, data->seq, data->len);
    if (data->module != MODULE_P2P_LISTEN) {
        TRANS_LOGE(TRANS_CTRL, "module is not MODULE_P2P_LISTEN");
        return;
    }

    cJSON *json = cJSON_ParseWithLength((const char *)(data->data), data->len);
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "cjson parse with length failed");
        return;
    }
    OnAuthMsgProc(authId, data->flag, data->seq, json);
    cJSON_Delete(json);
}

static void OnAuthChannelClose(int64_t authId)
{
    TRANS_LOGW(TRANS_CTRL, "authId=%{public}" PRId64, authId);
}

static int32_t OpenNewAuthConn(const AppInfo *appInfo, SessionConn *conn,
    int32_t newChannelId, uint32_t requestId)
{
    int32_t ret = OpenAuthConn(appInfo->peerData.deviceId, requestId, conn->isMeta);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenP2pDirectChannel open auth conn fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnP2pVerifyMsgReceived(int32_t channelId, const char *data, uint32_t len)
{
    TRANS_CHECK_AND_RETURN_LOGW((data != NULL) && (len > sizeof(int64_t) + sizeof(int64_t)),
        TRANS_CTRL, "received data is invalid");
    cJSON *json = cJSON_ParseWithLength((data + sizeof(int64_t) + sizeof(int64_t)),
        len - sizeof(int64_t) - sizeof(int64_t));
    TRANS_CHECK_AND_RETURN_LOGW((json != NULL), TRANS_CTRL, "parse json failed");

    int64_t msgType = *(int64_t*)data;
    if (msgType == P2P_VERIFY_REQUEST) {
        OnVerifyP2pRequest(channelId, *(int64_t*)(data + sizeof(int64_t)), json, false);
    } else if (msgType == P2P_VERIFY_REPLY) {
        OnVerifyP2pReply(channelId, *(int64_t*)(data + sizeof(int64_t)), json);
    } else {
        TRANS_LOGE(TRANS_CTRL, "invalid msgType=%{public}" PRIu64, msgType);
    }
    cJSON_Delete(json);
}

void OnP2pVerifyChannelClosed(int32_t channelId)
{
    TRANS_LOGW(TRANS_CTRL, "receive p2p verify close. channelId=%{public}d", channelId);
}

static int32_t StartVerifyP2pInfo(const AppInfo *appInfo, SessionConn *conn)
{
    int32_t ret = SOFTBUS_ERR;
    int32_t newChannelId = conn->channelId;
    int32_t pipeLineChannelId = TransProxyPipelineGetChannelIdByNetworkId(appInfo->peerNetWorkId);
    if (pipeLineChannelId == INVALID_CHANNEL_ID) {
        TRANS_LOGI(TRANS_CTRL, "can not get channelid by networkid");
        uint32_t requestId = AuthGenRequestId();
        conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
        conn->requestId = requestId;
        ret = OpenNewAuthConn(appInfo, conn, newChannelId, conn->requestId);
    } else {
        ret = TransProxyReuseByChannelId(pipeLineChannelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "channelId can't be repeated. channelId=%{public}d", pipeLineChannelId);
            return SOFTBUS_ERR;
        }
        TransProxyPipelineCloseChannelDelay(pipeLineChannelId);
        conn->authId = AuthGetLatestIdByUuid(conn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_WIFI, false);
        if (conn->authId == AUTH_INVALID_ID) {
            conn->authId = AuthGetLatestIdByUuid(conn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_BR, false);
        }
        TRANS_CHECK_AND_RETURN_RET_LOGW(conn->authId != AUTH_INVALID_ID, SOFTBUS_ERR,
            TRANS_CTRL, "get auth id failed");
        conn->requestId = REQUEST_INVALID;
        char *msg = VerifyP2pPack(conn->appInfo.myData.addr, conn->appInfo.myData.port, NULL);
        if (msg == NULL) {
            TRANS_LOGE(TRANS_CTRL, "verify p2p pack failed");
            return SOFTBUS_ERR;
        }
        uint32_t strLen = strlen(msg) + 1;
        char *sendMsg = (char*)SoftBusCalloc(strLen + sizeof(int64_t) + sizeof(int64_t));
        if (sendMsg == NULL) {
            cJSON_free(msg);
            return SOFTBUS_ERR;
        }
        *(int64_t*)sendMsg = P2P_VERIFY_REQUEST;
        *(int64_t*)(sendMsg + sizeof(int64_t)) = conn->req;
        if (strcpy_s(sendMsg  + sizeof(int64_t) + sizeof(int64_t), strLen, msg) != EOK) {
            cJSON_free(msg);
            SoftBusFree(sendMsg);
            return SOFTBUS_ERR;
        }
        ret = TransProxyPipelineSendMessage(pipeLineChannelId, (uint8_t *)sendMsg,
            strLen + sizeof(int64_t) + sizeof(int64_t), MSG_TYPE_IP_PORT_EXCHANGE);
        cJSON_free(msg);
        SoftBusFree(sendMsg);
    }
    return ret;
}

int32_t OpenP2pDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo,
    int32_t *channelId)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL ||
        (connInfo->type != CONNECT_P2P && connInfo->type != CONNECT_HML)) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionConn *conn = NULL;
    int32_t ret = SOFTBUS_ERR;

    conn = CreateNewSessinConn(DIRECT_CHANNEL_SERVER_P2P, false);
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create new sessin conn fail");
        return SOFTBUS_MEM_ERR;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(conn->channelId + ID_OFFSET));
    TRANS_LOGI(TRANS_CTRL,
        "SoftbusHitraceChainBegin: set HitraceId=%{public}" PRIu64, (uint64_t)(conn->channelId + ID_OFFSET));
    (void)memcpy_s(&conn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo));

    ret = StartP2pListener(conn->appInfo.myData.addr, &conn->appInfo.myData.port);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "start listener fail");
        return ret;
    }

    uint64_t seq = TransTdcGetNewSeqId();
    if (seq == INVALID_SEQ_ID) {
        SoftBusFree(conn);
        return SOFTBUS_ERR;
    }

    conn->req = (int64_t)seq;
    conn->isMeta = TransGetAuthTypeByNetWorkId(appInfo->peerNetWorkId);
    ret = TransTdcAddSessionConn(conn);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(conn);
        return ret;
    }
    ret = StartVerifyP2pInfo(appInfo, conn);
    if (ret != SOFTBUS_OK) {
        TransDelSessionConnById(conn->channelId);
        TRANS_LOGE(TRANS_CTRL, "StartVerifyP2pInfo fail, ret=%{public}d", ret);
        return ret;
    }
    *channelId = conn->channelId;
    TRANS_LOGI(TRANS_CTRL, "end: channelId=%{public}d", conn->channelId);
    return ret;
}

int32_t P2pDirectChannelInit(void)
{
    TRANS_LOGI(TRANS_INIT, "enter.");
    if (SoftBusMutexInit(&g_p2pLock, NULL) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init lock failed");
        return SOFTBUS_ERR;
    }
    if (CreatHmlListenerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "CreatHmlListenerList failed");
        return SOFTBUS_ERR;
    }
    AuthTransListener p2pTransCb = {
        .onDataReceived = OnAuthDataRecv,
        .onDisconnected = OnAuthChannelClose,
    };
    if (RegAuthTransListener(MODULE_P2P_LISTEN, &p2pTransCb) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "P2pDirectChannelInit set cb fail");
        return SOFTBUS_ERR;
    }
    ITransProxyPipelineListener listener = {
        .onDataReceived = OnP2pVerifyMsgReceived,
        .onDisconnected = OnP2pVerifyChannelClosed,
    };
    if (TransProxyPipelineRegisterListener(MSG_TYPE_IP_PORT_EXCHANGE, &listener) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "register listener failed");
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_INIT, "ok");
    return SOFTBUS_OK;
}

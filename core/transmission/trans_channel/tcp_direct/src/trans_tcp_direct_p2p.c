/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_base_listener.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_manager.h"
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
#define P2P_VERIFY_REQUEST 0
#define P2P_VERIFY_REPLY 1

typedef struct {
    ListNode node;
    char peerUuid[UUID_BUF_LEN];
} P2pListenerInfo;

typedef struct {
    char p2pSessionIp[IP_LEN];
    int32_t p2pSessionPort;
    SoftBusList *peerDeviceInfoList;
} P2pSessionInfo;

static P2pSessionInfo g_p2pSessionInfo = {
    .p2pSessionIp = { 0 },
    .p2pSessionPort = -1,
    .peerDeviceInfoList = NULL,
};

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
        return SOFTBUS_STRCPY_ERR;
    }

    listenerPort = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_P2P, &info);
    if (listenerPort < 0) {
        TRANS_LOGE(TRANS_CTRL, "start listener fail");
        return SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED;
    }
    *port = listenerPort;
    g_p2pSessionInfo.p2pSessionPort = *port;
    return SOFTBUS_OK;
}

static int32_t StartNewHmlListener(const char *ip, int32_t *port, ListenerModule *moudleType)
{
    int32_t listenerPort = 0;
    LocalListenerInfo info;
    info.type = CONNECT_HML;
    (void)memset_s(info.socketOption.addr, sizeof(info.socketOption.addr), 0, sizeof(info.socketOption.addr));
    info.socketOption.port = *port;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    if (strcpy_s(info.socketOption.addr, sizeof(info.socketOption.addr), ip) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy addr failed!");
        return SOFTBUS_STRCPY_ERR;
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
        return SOFTBUS_TRANS_TDC_START_SESSION_LISTENER_FAILED;
    }
    *port = listenerPort;
    return SOFTBUS_OK;
}

static void DelHmlListenerByMoudle(ListenerModule type)
{
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (item->moudleType == type) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL,
                "del hmlListener port=%{public}d, listenerModule=%{public}d",
                item->myPort, (int32_t)item->moudleType);
            SoftBusFree(item);
            g_hmlListenerList->cnt--;
            return;
        }
    }
}

void StopHmlListener(ListenerModule module)
{
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock fail");
        return;
    }
    if (StopBaseListener(module) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "StopHmlListener stop listener fail. module=%{public}d", module);
    }
    DelHmlListenerByMoudle(module);
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
}

// need get peerDeviceInfoList->lock before call this function
static void ClearP2pSessionInfo(void)
{
    g_p2pSessionInfo.p2pSessionPort = -1;
    (void)memset_s(
        g_p2pSessionInfo.p2pSessionIp, sizeof(g_p2pSessionInfo.p2pSessionIp), 0, sizeof(g_p2pSessionInfo.p2pSessionIp));

    P2pListenerInfo *item = NULL;
    P2pListenerInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_p2pSessionInfo.peerDeviceInfoList->list, P2pListenerInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }

    g_p2pSessionInfo.peerDeviceInfoList->cnt = 0;
}

// need get peerDeviceInfoList->lock before call this function
void StopP2pSessionListener()
{
    if (g_p2pSessionInfo.p2pSessionPort > 0) {
        if (StopBaseListener(DIRECT_CHANNEL_SERVER_P2P) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "stop listener fail");
        }
    }

    ClearP2pSessionInfo();
}

void StopP2pListenerByRemoteUuid(const char *peerUuid)
{
    if (peerUuid == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param, peerUuid is null");
        return;
    }
    if (g_p2pSessionInfo.peerDeviceInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "peerDeviceInfoList is null");
        return;
    }

    if (SoftBusMutexLock(&g_p2pSessionInfo.peerDeviceInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock peerDeviceInfoList failed");
        return;
    }
    if (IsListEmpty(&g_p2pSessionInfo.peerDeviceInfoList->list)) {
        TRANS_LOGI(TRANS_CTRL, "Empty List, just stop p2p listener");
        ClearP2pSessionInfo();
        (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
        (void)StopBaseListener(DIRECT_CHANNEL_SERVER_P2P);
        return;
    }
    char *anonymizePeerUuid = NULL;
    Anonymize(peerUuid, &anonymizePeerUuid);
    P2pListenerInfo *item = NULL;
    P2pListenerInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_p2pSessionInfo.peerDeviceInfoList->list, P2pListenerInfo, node) {
        if (strcmp(item->peerUuid, peerUuid) == 0) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_CTRL, "del p2p listener peerUuid=%{public}s node", AnonymizeWrapper(anonymizePeerUuid));
            AnonymizeFree(anonymizePeerUuid);
            SoftBusFree(item);
            g_p2pSessionInfo.peerDeviceInfoList->cnt--;
            if (g_p2pSessionInfo.peerDeviceInfoList->cnt <= 0) {
                TRANS_LOGI(TRANS_CTRL, "no device listen on p2p, stop listener");
                (void)StopBaseListener(DIRECT_CHANNEL_SERVER_P2P);
                ClearP2pSessionInfo();
            }
            (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
            return;
        }
    }
    (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
    TRANS_LOGE(TRANS_CTRL, "not found peerUuid=%{public}s in peerDeviceInfoList", AnonymizeWrapper(anonymizePeerUuid));
    AnonymizeFree(anonymizePeerUuid);
}

static void NotifyP2pSessionConnClear(ListNode *sessionConnList)
{
    if (sessionConnList == NULL) {
        return;
    }

    SessionConn *item = NULL;
    SessionConn *nextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, sessionConnList, SessionConn, node) {
        (void)NotifyChannelOpenFailedBySessionConn(item, SOFTBUS_TRANS_NET_STATE_CHANGED);
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
            TRANS_LOGI(TRANS_CTRL,
                "clear sessionConn pkgName=%{public}s, pid=%{public}d, status=%{public}u, channelId=%{public}d",
                item->appInfo.myData.pkgName, item->appInfo.myData.pid, item->status, item->channelId);
            sessionList->cnt--;
            ListAdd(&tempSessionConnList, &item->node);
        }
    }
    ReleaseSessionConnLock();

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

static int32_t CreateP2pListenerList(void)
{
    (void)memset_s(
        g_p2pSessionInfo.p2pSessionIp, sizeof(g_p2pSessionInfo.p2pSessionIp), 0, sizeof(g_p2pSessionInfo.p2pSessionIp));
    g_p2pSessionInfo.p2pSessionPort = -1;
    if (g_p2pSessionInfo.peerDeviceInfoList != NULL) {
        TRANS_LOGI(TRANS_CTRL, "list allready init");
        return SOFTBUS_OK;
    }
    g_p2pSessionInfo.peerDeviceInfoList = CreateSoftBusList();
    if (g_p2pSessionInfo.peerDeviceInfoList == NULL) {
        TRANS_LOGI(TRANS_CTRL, "create peerDeviceInfoList failed");
        return SOFTBUS_MALLOC_ERR;
    }

    return SOFTBUS_OK;
}

ListenerModule GetModuleByHmlIp(const char *ip)
{
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != SOFTBUS_OK) {
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

void ClearHmlListenerByUuid(const char *peerUuid)
{
    if (peerUuid == NULL) {
        TRANS_LOGE(TRANS_CTRL, "peerUuid is null.");
        return;
    }
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (strncmp(item->peerUuid, peerUuid, UUID_BUF_LEN) == 0) {
            int32_t module = item->moudleType; // item will free in StopHmlListener
            StopHmlListener(item->moudleType);
            TRANS_LOGI(TRANS_SVC, "StopHmlListener moudle=%{public}d succ", module);
        }
    }
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
    return;
}

static void AnonymizeLogHmlListenerInfo(const char *ip, const char *peerUuid)
{
    char *tmpIp = NULL;
    char *tmpUuid = NULL;
    Anonymize(ip, &tmpIp);
    Anonymize(peerUuid, &tmpUuid);
    TRANS_LOGI(TRANS_CTRL,
        "StartHmlListener: ip=%{public}s, peerUuid=%{public}s.", AnonymizeWrapper(tmpIp), AnonymizeWrapper(tmpUuid));
    AnonymizeFree(tmpIp);
    AnonymizeFree(tmpUuid);
}

static int32_t StartHmlListener(const char *ip, int32_t *port, const char *peerUuid)
{
    AnonymizeLogHmlListenerInfo(ip, peerUuid);
    if (g_hmlListenerList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "hmlListenerList not init");
        return SOFTBUS_NO_INIT;
    }
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (strncmp(item->myIp, ip, IP_LEN) == 0 && strncmp(item->peerUuid, peerUuid, UUID_BUF_LEN) == 0) {
            *port = item->myPort;
            (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
            TRANS_LOGI(TRANS_CTRL, "succ, port=%{public}d", *port);
            return SOFTBUS_OK;
        }
    }
    ListenerModule moudleType = UNUSE_BUTT;
    int32_t ret = StartNewHmlListener(ip, port, &moudleType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "create new listener fail");
        (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
        return ret;
    }
    item = (HmlListenerInfo *)SoftBusCalloc(sizeof(HmlListenerInfo));
    if (item == NULL) {
        StopHmlListener(moudleType);
        (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
        TRANS_LOGE(TRANS_CTRL, "HmlListenerInfo malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    item->myPort = *port;
    item->moudleType = moudleType;
    if (strncpy_s(item->myIp, IP_LEN, ip, IP_LEN) != EOK ||
        strncpy_s(item->peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "HmlListenerInfo copy ip or peer uuid failed.");
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

static void AnonymizeIp(const char *ip, char *sessionIp, int32_t port)
{
    char *temp = NULL;
    char *anonyP2pIp = NULL;
    Anonymize(ip, &temp);
    Anonymize(sessionIp, &anonyP2pIp);
    TRANS_LOGE(TRANS_CTRL, "param invalid g_p2pSessionPort=%{public}d, ip=%{public}s, g_p2pSessionIp=%{public}s",
        port, AnonymizeWrapper(temp), AnonymizeWrapper(anonyP2pIp));
    AnonymizeFree(temp);
    AnonymizeFree(anonyP2pIp);
}

// need get peerDeviceInfoList->lock before call this function
static void CheckAndAddPeerDeviceInfo(const char *peerUuid)
{
    if (g_p2pSessionInfo.peerDeviceInfoList == NULL) {
        TRANS_LOGE(TRANS_CTRL, "peerDeviceInfoList is null");
        return;
    }
    char *anonymizePeerUuid = NULL;
    Anonymize(peerUuid, &anonymizePeerUuid);
    P2pListenerInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_p2pSessionInfo.peerDeviceInfoList->list, P2pListenerInfo, node) {
        if (strncmp(item->peerUuid, peerUuid, UUID_BUF_LEN) == 0) {
            TRANS_LOGD(TRANS_CTRL, "exit p2pListener with peerUuid=%{public}s", AnonymizeWrapper(anonymizePeerUuid));
            AnonymizeFree(anonymizePeerUuid);
            return;
        }
    }

    P2pListenerInfo *newItem = (P2pListenerInfo *)SoftBusCalloc(sizeof(P2pListenerInfo));
    if (newItem == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc P2pListenerInfo failed");
        AnonymizeFree(anonymizePeerUuid);
        return;
    }
    if (strncpy_s(newItem->peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strncpy_s peerUuid=%{public}s failed", anonymizePeerUuid);
        AnonymizeFree(anonymizePeerUuid);
        SoftBusFree(newItem);
        return;
    }
    ListAdd(&g_p2pSessionInfo.peerDeviceInfoList->list, &newItem->node);
    g_p2pSessionInfo.peerDeviceInfoList->cnt++;
    TRANS_LOGD(TRANS_CTRL, "add peerUuid=%{public}s succeed", anonymizePeerUuid);
    AnonymizeFree(anonymizePeerUuid);
}

static int32_t StartP2pListener(const char *ip, int32_t *port, const char *peerUuid)
{
    if (ip == NULL) {
        TRANS_LOGE(TRANS_CTRL, "ip is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_p2pSessionInfo.peerDeviceInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_p2pSessionInfo.p2pSessionPort > 0 && strcmp(ip, g_p2pSessionInfo.p2pSessionIp) != 0) {
        AnonymizeIp(ip, g_p2pSessionInfo.p2pSessionIp, g_p2pSessionInfo.p2pSessionPort);
        ClearP2pSessionConn();
        StopP2pSessionListener();
    }
    CheckAndAddPeerDeviceInfo(peerUuid);
    if (g_p2pSessionInfo.p2pSessionPort > 0) {
        *port = g_p2pSessionInfo.p2pSessionPort;
        TRANS_LOGI(TRANS_CTRL, "port=%{public}d", *port);
        (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
        return SOFTBUS_OK;
    }

    int32_t ret = StartNewP2pListener(ip, port);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "start new listener fail");
        (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
        return ret;
    }

    g_p2pSessionInfo.p2pSessionPort = *port;
    if (strcpy_s(g_p2pSessionInfo.p2pSessionIp, sizeof(g_p2pSessionInfo.p2pSessionIp), ip) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s fail");
        StopP2pSessionListener();
        (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
        return SOFTBUS_STRCPY_ERR;
    }
    (void)SoftBusMutexUnlock(&g_p2pSessionInfo.peerDeviceInfoList->lock);
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

static int32_t SendAuthData(AuthHandle authHandle, int32_t module, int32_t flag, int64_t seq, const char *data)
{
    TRANS_LOGI(TRANS_CTRL,
        "SendAuthData: authId=%{public}" PRId64 ", model=%{public}d, flag=%{public}d, seq=%{public}" PRId64,
        authHandle.authId, module, flag, seq);
    AuthTransData dataInfo = {
        .module = module,
        .flag = flag,
        .seq = seq,
        .len = strlen(data) + 1,
        .data = (const uint8_t *)data,
    };
    int32_t ret = AuthPostTransData(authHandle, &dataInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "AuthPostTransData failed.");
    return SOFTBUS_OK;
}

static int32_t VerifyP2p(AuthHandle authHandle, const char *myIp, const char *peerIp, int32_t myPort, int64_t seq)
{
    TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 ", port=%{public}d", authHandle.authId, myPort);
    char *msg = NULL;
    int32_t ret;
    msg = VerifyP2pPack(myIp, myPort, peerIp);
    if (msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "verifyp2p pack fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ret = SendAuthData(authHandle, MODULE_P2P_LISTEN, MSG_FLAG_REQUEST, (int64_t)seq, msg);
    cJSON_free(msg);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "VerifyP2p send auth data fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnAuthConnOpened(uint32_t requestId, AuthHandle authHandle)
{
    TRANS_LOGI(TRANS_CTRL, "reqId=%{public}u, authId=%{public}" PRId64,
        requestId, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "authHandle type error");
        return;
    }
    int32_t channelId = INVALID_CHANNEL_ID;
    SessionConn *conn = NULL;
    char myDataAddr[IP_LEN] = {0};
    char peerDataAddr[IP_LEN] = {0};
    int32_t myDataPort = 0;
    int64_t reqNum = 0;
    if (GetSessionConnLock() != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    conn = GetSessionConnByRequestId(requestId);
    if (conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "not find session");
        ReleaseSessionConnLock();
        goto EXIT_ERR;
    }
    channelId = conn->channelId;
    conn->authHandle = authHandle;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P;
    if (strcpy_s(myDataAddr, sizeof(myDataAddr), conn->appInfo.myData.addr) != EOK ||
        strcpy_s(peerDataAddr, sizeof(peerDataAddr), conn->appInfo.peerData.addr) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy failed.");
        ReleaseSessionConnLock();
        goto EXIT_ERR;
    }
    myDataPort = conn->appInfo.myData.port;
    reqNum = conn->req;
    ReleaseSessionConnLock();

    if (VerifyP2p(authHandle, myDataAddr, peerDataAddr, myDataPort, reqNum) != SOFTBUS_OK) {
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
        ReleaseSessionConnLock();
        TRANS_LOGE(TRANS_CTRL, "get session conn by requestid fail");
        return;
    }
    channelId = conn->channelId;
    ReleaseSessionConnLock();

    (void)OnChannelOpenFail(channelId, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED);
    TRANS_LOGW(TRANS_CTRL, "ok");
}

static int32_t OpenAuthConn(const char *uuid, uint32_t reqId, bool isMeta, ConnectType type)
{
    TRANS_LOGI(TRANS_CTRL, "reqId=%{public}u", reqId);
    AuthConnInfo auth;
    (void)memset_s(&auth, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthConnCallback cb;
    (void)memset_s(&cb, sizeof(AuthConnCallback), 0, sizeof(AuthConnCallback));
    int32_t ret = SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED;
    if (type == CONNECT_HML) {
        TRANS_LOGI(TRANS_CTRL, "get AuthConnInfo, linkType=%{public}d", type);
        ret = AuthGetHmlConnInfo(uuid, &auth, isMeta);
    }
    if (ret != SOFTBUS_OK && type == CONNECT_P2P) {
        TRANS_LOGI(TRANS_CTRL, "get AuthConnInfo, linkType=%{public}d", type);
        ret = AuthGetP2pConnInfo(uuid, &auth, isMeta);
    }
    if (ret != SOFTBUS_OK) {
        ret = AuthGetPreferConnInfo(uuid, &auth, isMeta);
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

static void SendVerifyP2pFailRsp(AuthHandle authHandle, int64_t seq,
    int32_t code, int32_t errCode, const char *errDesc, bool isAuthLink)
{
    char *reply = VerifyP2pPackError(code, errCode, errDesc);
    TRANS_CHECK_AND_RETURN_LOGE(reply != NULL, TRANS_CTRL, "verifyP2p pack error");
    if (isAuthLink) {
        if (SendAuthData(authHandle, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, reply) != SOFTBUS_OK) {
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
        *(int64_t*)sendMsg = SoftBusHtoLll((uint64_t)P2P_VERIFY_REPLY);
        *(int64_t*)(sendMsg + sizeof(int64_t)) = SoftBusHtoLll((uint64_t)seq);
        if (strcpy_s(sendMsg  + sizeof(int64_t) + sizeof(int64_t), strLen, reply) != EOK) {
            cJSON_free(reply);
            SoftBusFree(sendMsg);
            return;
        }
        TransProxyPipelineSendMessage(authHandle.authId, (uint8_t *)sendMsg,
            strLen + sizeof(int64_t) + sizeof(int64_t), MSG_TYPE_IP_PORT_EXCHANGE);
        SoftBusFree(sendMsg);
    }
    cJSON_free(reply);
}

static int32_t SendVerifyP2pRsp(AuthHandle authHandle, int32_t module, int32_t flag, int64_t seq,
    const char *reply, bool isAuthLink)
{
    int32_t ret = SOFTBUS_TRANS_VERIFY_P2P_FAILED;
    if (isAuthLink) {
        ret = SendAuthData(authHandle, module, flag, seq, reply);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send auth data fail");
        }
    } else {
        uint32_t strLen = strlen(reply) + 1;
        char *sendMsg = (char *)SoftBusCalloc(strLen + sizeof(int64_t) + sizeof(int64_t));
        TRANS_CHECK_AND_RETURN_RET_LOGE(sendMsg != NULL, SOFTBUS_MALLOC_ERR, TRANS_CTRL, "calloc sendMsg failed");
        *(int64_t *)sendMsg = SoftBusHtoLll((uint64_t)P2P_VERIFY_REPLY);
        *(int64_t *)(sendMsg + sizeof(int64_t)) = SoftBusHtoLll((uint64_t)seq);
        if (strcpy_s(sendMsg  + sizeof(int64_t) + sizeof(int64_t), strLen, reply) != EOK) {
            SoftBusFree(sendMsg);
            return SOFTBUS_STRCPY_ERR;
        }
        ret = TransProxyPipelineSendMessage(authHandle.authId, (uint8_t *)sendMsg,
            strLen + sizeof(int64_t) + sizeof(int64_t), MSG_TYPE_IP_PORT_EXCHANGE);
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

static int32_t PackAndSendVerifyP2pRsp(const char *myIp, int32_t myPort, int64_t seq, bool isAuthLink,
    AuthHandle authHandle)
{
    int32_t ret = SOFTBUS_OK;
    char *reply = VerifyP2pPack(myIp, myPort, NULL);
    if (reply == NULL) {
        SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, ret, "pack reply failed", isAuthLink);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    ret = SendVerifyP2pRsp(authHandle, MODULE_P2P_LISTEN, MES_FLAG_REPLY, seq, reply, isAuthLink);
    cJSON_free(reply);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransGetRemoteUuidByAuthHandle(AuthHandle authHandle, char *peerUuid)
{
    int32_t ret = SOFTBUS_OK;
    if (authHandle.type == AUTH_LINK_TYPE_BLE) {
        AuthHandle authHandleTmp = { 0 };
        ret = TransProxyGetAuthId(authHandle.authId, &authHandleTmp);
        if (ret == SOFTBUS_TRANS_NODE_NOT_FOUND) {
            authHandleTmp.authId = authHandle.authId;
        }
        ret = AuthGetDeviceUuid(authHandleTmp.authId, peerUuid, UUID_BUF_LEN);
    } else {
        ret = AuthGetDeviceUuid(authHandle.authId, peerUuid, UUID_BUF_LEN);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fail to get device uuid by authId=%{public}" PRId64, authHandle.authId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OnVerifyP2pRequest(AuthHandle authHandle, int64_t seq, const cJSON *json, bool isAuthLink)
{
    TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 ", seq=%{public}" PRId64, authHandle.authId, seq);
    int32_t peerPort = 0;
    char peerIp[IP_LEN] = {0};
    int32_t myPort = 0;
    char myIp[IP_LEN] = {0};

    int32_t ret = VerifyP2pUnPack(json, peerIp, IP_LEN, &peerPort);
    if (ret != SOFTBUS_OK) {
        SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, ret, "OnVerifyP2pRequest unpack fail", isAuthLink);
        return ret;
    }

    struct WifiDirectManager *pManager = GetWifiDirectManager();
    if (pManager != NULL && pManager->getLocalIpByRemoteIp != NULL) {
        ret = pManager->getLocalIpByRemoteIp(peerIp, myIp, sizeof(myIp));
        if (ret != SOFTBUS_OK) {
            OutputAnonymizeIpAddress(myIp, peerIp);
            TRANS_LOGE(TRANS_CTRL, "get Local Ip fail, ret = %{public}d", ret);
            SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, ret, "get p2p ip fail", isAuthLink);
            return SOFTBUS_TRANS_GET_P2P_INFO_FAILED;
        }
    } else {
        SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, SOFTBUS_WIFI_DIRECT_INIT_FAILED,
            "get wifidirectmanager or localip fail", isAuthLink);
        return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
    }
    char peerUuid[UUID_BUF_LEN] = { 0 };
    ret = TransGetRemoteUuidByAuthHandle(authHandle, peerUuid);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get remote uuid failed.");
    if (IsHmlIpAddr(myIp)) {
        ret = StartHmlListener(myIp, &myPort, peerUuid);
    } else {
        ret = StartP2pListener(myIp, &myPort, peerUuid);
    }
    if (ret != SOFTBUS_OK) {
        OutputAnonymizeIpAddress(myIp, peerIp);
        SendVerifyP2pFailRsp(authHandle, seq, CODE_VERIFY_P2P, ret, "invalid p2p port", isAuthLink);
        return ret;
    }
    ret = PackAndSendVerifyP2pRsp(myIp, myPort, seq, isAuthLink, authHandle);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "fail to send VerifyP2pRsp.");
    LaneAddP2pAddressByIp(peerIp, peerPort);
    return SOFTBUS_OK;
}

static int32_t ConnectTcpDirectPeer(const char *addr, int port, const char *myIp)
{
    ConnectOption options;
    if (IsHmlIpAddr(addr)) {
        options.type = CONNECT_HML;
    } else {
        options.type = CONNECT_P2P;
    }
    (void)memset_s(options.socketOption.addr, sizeof(options.socketOption.addr), 0, sizeof(options.socketOption.addr));
    options.socketOption.port = port;
    options.socketOption.protocol = LNN_PROTOCOL_IP;
    options.socketOption.moduleId = DIRECT_CHANNEL_CLIENT;

    int32_t ret = strcpy_s(options.socketOption.addr, sizeof(options.socketOption.addr), addr);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed! ret=%{public}" PRId32, ret);
        return SOFTBUS_STRCPY_ERR;
    }

    return ConnOpenClientSocket(&options, myIp, true);
}

static int32_t AddHmlTrigger(int32_t fd, const char *myAddr, int64_t seq)
{
    ListenerModule moudleType;
    SessionConn *conn = NULL;
    if (SoftBusMutexLock(&g_hmlListenerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "StartHmlListener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    HmlListenerInfo *item = NULL;
    HmlListenerInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_hmlListenerList->list, HmlListenerInfo, node) {
        if (strncmp(item->myIp, myAddr, IP_LEN) == 0) {
            int32_t ret = AddTrigger(item->moudleType, fd, WRITE_TRIGGER);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "fail");
                (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
                return ret;
            }
            moudleType = item->moudleType;
            (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
            if (GetSessionConnLock() != SOFTBUS_OK) {
                return SOFTBUS_LOCK_ERR;
            }
            conn = GetSessionConnByReq(seq);
            if (conn == NULL) {
                ReleaseSessionConnLock();
                return SOFTBUS_NOT_FIND;
            }
            conn->listenMod = moudleType;
            ReleaseSessionConnLock();
            return SOFTBUS_OK;
        }
    }
    TRANS_LOGE(TRANS_CTRL, "not found correct hml ip");
    (void)SoftBusMutexUnlock(&g_hmlListenerList->lock);
    return SOFTBUS_TRANS_ADD_HML_TRIGGER_FAILED;
}

static int32_t AddP2pOrHmlTrigger(int32_t fd, const char *myAddr, int64_t seq)
{
    if (IsHmlIpAddr(myAddr)) {
        return AddHmlTrigger(fd, myAddr, seq);
    } else {
        int32_t ret = AddTrigger(DIRECT_CHANNEL_SERVER_P2P, fd, WRITE_TRIGGER);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "AddTrigger fail");
    }
    return SOFTBUS_OK;
}

static int32_t OnVerifyP2pReply(int64_t authId, int64_t seq, const cJSON *json)
{
    TRANS_LOGI(TRANS_CTRL, "authId=%{public}" PRId64 ", seq=%{public}" PRId64, authId, seq);
    SessionConn *conn = NULL;
    int32_t ret = SOFTBUS_TRANS_VERIFY_P2P_FAILED;
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
        ReleaseSessionConnLock();
        return SOFTBUS_NOT_FIND;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(conn->channelId + ID_OFFSET));
    channelId = conn->channelId;

    ret = VerifyP2pUnPack(json, conn->appInfo.peerData.addr, IP_LEN, &conn->appInfo.peerData.port);
    if (ret != SOFTBUS_OK) {
        ReleaseSessionConnLock();
        TRANS_LOGE(TRANS_CTRL, "unpack fail: ret=%{public}d", ret);
        goto EXIT_ERR;
    }
    TRANS_LOGI(TRANS_CTRL, "peer wifi: peerPort=%{public}d", conn->appInfo.peerData.port);

    fd = ConnectTcpDirectPeer(conn->appInfo.peerData.addr, conn->appInfo.peerData.port, conn->appInfo.myData.addr);
    if (fd <= 0) {
        ReleaseSessionConnLock();
        TRANS_LOGE(TRANS_CTRL, "conn fail: fd=%{public}d", fd);
        goto EXIT_ERR;
    }
    conn->appInfo.fd = fd;
    conn->status = TCP_DIRECT_CHANNEL_STATUS_CONNECTING;
    if (strcpy_s(peerNetworkId, sizeof(peerNetworkId), conn->appInfo.peerNetWorkId) != EOK ||
        strcpy_s(peerAddr, sizeof(peerAddr), conn->appInfo.peerData.addr) != EOK ||
        strcpy_s(myAddr, sizeof(myAddr), conn->appInfo.myData.addr) != EOK) {
        ReleaseSessionConnLock();
        TRANS_LOGE(TRANS_CTRL, "strcpy_s failed!");
        goto EXIT_ERR;
    }
    peerPort = conn->appInfo.peerData.port;
    ReleaseSessionConnLock();

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
    return SOFTBUS_TRANS_VERIFY_P2P_FAILED;
}

static void OnAuthMsgProc(AuthHandle authHandle, int32_t flags, int64_t seq, const cJSON *json)
{
    int32_t ret = SOFTBUS_OK;
    if (flags == MSG_FLAG_REQUEST) {
        ret = OnVerifyP2pRequest(authHandle, seq, json, true);
    } else {
        ret = OnVerifyP2pReply(authHandle.authId, seq, json);
    }
    TRANS_LOGI(TRANS_CTRL, "result: ret=%{public}d", ret);
    return;
}

static void OnAuthDataRecv(AuthHandle authHandle, const AuthTransData *data)
{
    if (data == NULL || data->data == NULL || data->len < 1) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return;
    }
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        TRANS_LOGE(TRANS_CTRL, "authHandle type error");
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
    OnAuthMsgProc(authHandle, data->flag, data->seq, json);
    cJSON_Delete(json);
}

static void OnAuthChannelClose(AuthHandle authHandle)
{
    int32_t num = 0;
    int32_t *channelIds = GetChannelIdsByAuthIdAndStatus(&num, &authHandle, TCP_DIRECT_CHANNEL_STATUS_VERIFY_P2P);
    if (channelIds == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Fail to get channel ids with auth id %{public}" PRId64, authHandle.authId);
        return;
    }
    TRANS_LOGW(TRANS_CTRL, "AuthId=%{public}" PRId64 ",channelIds num=%{public}d", authHandle.authId, num);
    int32_t i;
    for (i = 0; i < num; i++) {
        (void)OnChannelOpenFail(channelIds[i], SOFTBUS_TRANS_OPEN_AUTH_CHANNEL_FAILED);
    }
    SoftBusFree(channelIds);
}

static int32_t OpenNewAuthConn(const AppInfo *appInfo, SessionConn *conn,
    int32_t newChannelId, ConnectType type)
{
    int32_t ret = OpenAuthConn(appInfo->peerData.deviceId, conn->requestId, conn->isMeta, type);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenP2pDirectChannel open auth conn fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnP2pVerifyMsgReceived(int32_t channelId, const char *data, uint32_t len)
{
#define MAX_DATA_SIZE 1024
    TRANS_CHECK_AND_RETURN_LOGW((data != NULL) && (len > sizeof(int64_t) + sizeof(int64_t)) && (len <= MAX_DATA_SIZE),
        TRANS_CTRL, "received data is invalid");
    cJSON *json = cJSON_ParseWithLength((data + sizeof(int64_t) + sizeof(int64_t)),
        len - sizeof(int64_t) - sizeof(int64_t));
    TRANS_CHECK_AND_RETURN_LOGW((json != NULL), TRANS_CTRL, "parse json failed");

    int64_t msgType = (int64_t)SoftBusLtoHll((uint64_t)*(int64_t*)data);
    AuthHandle authHandle = { .authId = channelId, .type = AUTH_LINK_TYPE_BLE };
    if (msgType == P2P_VERIFY_REQUEST) {
        OnVerifyP2pRequest(authHandle, SoftBusLtoHll((uint64_t)*(int64_t*)(data + sizeof(int64_t))), json, false);
    } else if (msgType == P2P_VERIFY_REPLY) {
        OnVerifyP2pReply(channelId, SoftBusLtoHll((uint64_t)*(int64_t*)(data + sizeof(int64_t))), json);
    } else {
        TRANS_LOGE(TRANS_CTRL, "invalid msgType=%{public}" PRIu64, msgType);
    }
    cJSON_Delete(json);
}

void OnP2pVerifyChannelClosed(int32_t channelId)
{
    TRANS_LOGW(TRANS_CTRL, "receive p2p verify close. channelId=%{public}d", channelId);
}

static int32_t TransProxyGetAuthIdByUuid(SessionConn *conn)
{
    AuthGetLatestIdByUuid(conn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_WIFI, false, &conn->authHandle);
    if (conn->authHandle.authId == AUTH_INVALID_ID) {
        //get WIFI authManager failed,retry BLE
        AuthGetLatestIdByUuid(conn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_BLE, false, &conn->authHandle);
    }
    if (conn->authHandle.authId == AUTH_INVALID_ID) {
        //get WIFI and BLE authManager failed,retry BR
        AuthGetLatestIdByUuid(conn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_BR, false, &conn->authHandle);
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(conn->authHandle.authId != AUTH_INVALID_ID, SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED,
                                    TRANS_CTRL, "get authManager failed");
    return SOFTBUS_OK;
}


static int32_t StartVerifyP2pInfo(const AppInfo *appInfo, SessionConn *conn, ConnectType type)
{
    int32_t ret = SOFTBUS_TRANS_VERIFY_P2P_FAILED;
    int32_t newChannelId = conn->channelId;
    int32_t pipeLineChannelId = TransProxyPipelineGetChannelIdByNetworkId(appInfo->peerNetWorkId);
    if (pipeLineChannelId == INVALID_CHANNEL_ID) {
        TRANS_LOGI(TRANS_CTRL, "can not get channelid by networkid");
        uint32_t requestId = AuthGenRequestId();
        conn->status = TCP_DIRECT_CHANNEL_STATUS_AUTH_CHANNEL;
        conn->requestId = requestId;
        if (type == CONNECT_P2P_REUSE) {
            type = IsHmlIpAddr(appInfo->myData.addr) ? CONNECT_HML : CONNECT_P2P;
        }
        TRANS_LOGD(TRANS_CTRL, "type=%{public}d", type);
        ret = OpenNewAuthConn(appInfo, conn, newChannelId, type);
    } else {
        ret = TransProxyReuseByChannelId(pipeLineChannelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "channelId can't be repeated. channelId=%{public}d", pipeLineChannelId);
            return ret;
        }
        TransProxyPipelineCloseChannelDelay(pipeLineChannelId);
        ret = TransProxyGetAuthIdByUuid(conn);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get auth id failed");
        conn->requestId = REQUEST_INVALID;
        char *msg = VerifyP2pPack(conn->appInfo.myData.addr, conn->appInfo.myData.port, NULL);
        if (msg == NULL) {
            TRANS_LOGE(TRANS_CTRL, "verify p2p pack failed");
            return SOFTBUS_TRANS_VERIFY_P2P_FAILED;
        }
        uint32_t strLen = strlen(msg) + 1;
        char *sendMsg = (char*)SoftBusCalloc(strLen + sizeof(int64_t) + sizeof(int64_t));
        if (sendMsg == NULL) {
            cJSON_free(msg);
            return SOFTBUS_MALLOC_ERR;
        }
        *(int64_t*)sendMsg = SoftBusHtoLll((uint64_t)P2P_VERIFY_REQUEST);
        *(int64_t*)(sendMsg + sizeof(int64_t)) = SoftBusHtoLll((uint64_t)conn->req);
        if (strcpy_s(sendMsg  + sizeof(int64_t) + sizeof(int64_t), strLen, msg) != EOK) {
            cJSON_free(msg);
            SoftBusFree(sendMsg);
            return SOFTBUS_STRCPY_ERR;
        }
        ret = TransProxyPipelineSendMessage(pipeLineChannelId, (uint8_t *)sendMsg,
            strLen + sizeof(int64_t) + sizeof(int64_t), MSG_TYPE_IP_PORT_EXCHANGE);
        cJSON_free(msg);
        SoftBusFree(sendMsg);
    }
    return ret;
}

static int32_t CopyAppInfoFastTransData(SessionConn *conn, const AppInfo *appInfo)
{
    if (appInfo->fastTransData != NULL && appInfo->fastTransDataSize > 0) {
        uint8_t *fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize);
        if (fastTransData == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s((char *)fastTransData, appInfo->fastTransDataSize, (const char *)appInfo->fastTransData,
            appInfo->fastTransDataSize) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy fastTransData fail");
            SoftBusFree(fastTransData);
            return SOFTBUS_MEM_ERR;
        }
        conn->appInfo.fastTransData = fastTransData;
    }
    return SOFTBUS_OK;
}

static void FreeFastTransData(AppInfo *appInfo)
{
    if (appInfo != NULL && appInfo->fastTransData != NULL) {
        SoftBusFree((void *)(appInfo->fastTransData));
    }
}

static int32_t BuildSessionConn(const AppInfo *appInfo, SessionConn **conn)
{
    int32_t ret = SOFTBUS_TRANS_P2P_DIRECT_FAILED;
    *conn = CreateNewSessinConn(DIRECT_CHANNEL_SERVER_P2P, false);
    if (*conn == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create new sessin conn fail");
        return SOFTBUS_MEM_ERR;
    }

    if (memcpy_s(&((*conn)->appInfo), sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy appInfo fail");
        SoftBusFree(*conn);
        *conn = NULL;
        return SOFTBUS_MEM_ERR;
    }
    ret = CopyAppInfoFastTransData(*conn, appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "copy appinfo fast trans data fail");
        SoftBusFree(*conn);
        *conn = NULL;
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t StartTransP2pDirectListener(ConnectType type, SessionConn *conn, const AppInfo *appInfo)
{
    if (type == CONNECT_P2P) {
        if (IsHmlIpAddr(conn->appInfo.myData.addr)) {
            return StartHmlListener(conn->appInfo.myData.addr, &conn->appInfo.myData.port, appInfo->peerData.deviceId);
        } else {
            return StartP2pListener(conn->appInfo.myData.addr, &conn->appInfo.myData.port, appInfo->peerData.deviceId);
        }
    }
    return StartHmlListener(conn->appInfo.myData.addr, &conn->appInfo.myData.port, appInfo->peerData.deviceId);
}

int32_t OpenP2pDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL ||
        (connInfo->type != CONNECT_P2P && connInfo->type != CONNECT_HML && connInfo->type != CONNECT_P2P_REUSE)) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SessionConn *conn = NULL;
    int32_t ret = BuildSessionConn(appInfo, &conn);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "build new sessin conn fail, ret=%{public}d", ret);
        return ret;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(conn->channelId + (uint64_t)ID_OFFSET));
    TRANS_LOGI(TRANS_CTRL,
        "SoftbusHitraceChainBegin: set HitraceId=%{public}" PRIu64, (uint64_t)(conn->channelId + ID_OFFSET));
    ret = StartTransP2pDirectListener(connInfo->type, conn, appInfo);
    if (ret != SOFTBUS_OK) {
        FreeFastTransData(&(conn->appInfo));
        SoftBusFree(conn);
        TRANS_LOGE(TRANS_CTRL, "start listener fail");
        return ret;
    }
    uint64_t seq = TransTdcGetNewSeqId();
    if (seq == INVALID_SEQ_ID) {
        FreeFastTransData(&(conn->appInfo));
        SoftBusFree(conn);
        return SOFTBUS_TRANS_INVALID_SEQ_ID;
    }
    conn->req = (int64_t)seq;
    conn->isMeta = TransGetAuthTypeByNetWorkId(appInfo->peerNetWorkId);
    ret = TransTdcAddSessionConn(conn);
    if (ret != SOFTBUS_OK) {
        FreeFastTransData(&(conn->appInfo));
        SoftBusFree(conn);
        return ret;
    }
    ret = StartVerifyP2pInfo(appInfo, conn, connInfo->type);
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

    int32_t ret = CreatHmlListenerList();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "CreatHmlListenerList failed");
    ret = CreateP2pListenerList();
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "Init p2p listener list failed");
    AuthTransListener p2pTransCb = {
        .onDataReceived = OnAuthDataRecv,
        .onDisconnected = OnAuthChannelClose,
        .onException = NULL,
    };

    ret = RegAuthTransListener(MODULE_P2P_LISTEN, &p2pTransCb);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "P2pDirectChannelInit set cb fail");

    ITransProxyPipelineListener listener = {
        .onDataReceived = OnP2pVerifyMsgReceived,
        .onDisconnected = OnP2pVerifyChannelClosed,
    };

    ret = TransProxyPipelineRegisterListener(MSG_TYPE_IP_PORT_EXCHANGE, &listener);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_INIT, "register listener failed");

    TRANS_LOGI(TRANS_INIT, "ok");
    return SOFTBUS_OK;
}

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

#include "lnn_lane_link.h"

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_def.h"
#include "lnn_lane_score.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_capability.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_physical_subnet_manager.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_network_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_utils.h"
#include "wifi_device.h"

typedef struct {
    int32_t requestId;
    int32_t pid;
    char networkId[NETWORK_ID_BUF_LEN];
    int64_t authId;
    LaneLinkCb cb;
    uint32_t linkReqId;
    ListNode node;
} ConnRequestItem;

typedef int32_t (*LaneLinkByType)(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback);

static SoftBusList *g_pendingList = NULL;

static bool LinkTypeCheck(LaneLinkType type)
{
    LaneLinkType supportList[] = {LANE_P2P, LANE_WLAN_2P4G, LANE_WLAN_5G, LANE_BR};
    uint32_t size = sizeof(supportList) / sizeof(LaneLinkType);
    for (uint32_t i = 0; i < size; i++) {
        if (supportList[i] == type) {
            return true;
        }
    }
    LLOGE("link type[%d] is not support", type);
    return false;
}

static int32_t IsLinkRequestValid(const LinkRequest *reqInfo)
{
    if (reqInfo == NULL) {
        LLOGE("reqInfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static int32_t LnnLanePendingInit(void)
{
    if (g_pendingList != NULL) {
        return SOFTBUS_OK;
    }
    g_pendingList = CreateSoftBusList();
    if (g_pendingList == NULL) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static void LnnLanePendingDeinit(void)
{
    if (g_pendingList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        LLOGE("lock fail.");
        return;
    }
    ConnRequestItem *item = NULL;
    while (!IsListEmpty(&g_pendingList->list)) {
        item = LIST_ENTRY(GET_LIST_HEAD(&g_pendingList->list), ConnRequestItem, node);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    DestroySoftBusList(g_pendingList);
    g_pendingList = NULL;
}

static int32_t AddConnRequestItem(uint32_t reqId, int32_t requestId,
    const char *networkId, int32_t pid, const LaneLinkCb *callback)
{
    ConnRequestItem *item = (ConnRequestItem *)SoftBusCalloc(sizeof(ConnRequestItem));
    if (item == NULL) {
        LLOGE("malloc conn request item err.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(item->networkId, sizeof(item->networkId), networkId) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    item->requestId = requestId;
    item->pid = pid;
    item->authId = SOFTBUS_ERR;
    if (callback != NULL) {
        item->cb = *callback;
    }
    item->linkReqId = reqId;

    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        SoftBusFree(item);
        LLOGE("lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    ListNodeInsert(&g_pendingList->list, &item->node);
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    return SOFTBUS_OK;
}

static ConnRequestItem *GetConnRequestItem(int32_t requestId)
{
    ConnRequestItem *item = NULL;
    ConnRequestItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_pendingList->list, ConnRequestItem, node) {
        if (item->requestId == requestId) {
            return item;
        }
    }
    LLOGE("conn request item noot found, requestId %d", requestId);
    return NULL;
}

static void DelConnRequestItem(int32_t requestId)
{
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        LLOGE("lock fail.");
        return;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return;
    }
    ListDelete(&item->node);
    SoftBusFree(item);
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
}

static void NotifyLinkFail(int32_t requestId, int32_t reason)
{
    LLOGI("requestId %d, reason %d", requestId, reason);
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        LLOGE("lock fail.");
        return;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    LaneLinkCb cb = item->cb;
    uint32_t linkReqId = item->linkReqId;
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    cb.OnLaneLinkFail(linkReqId, reason);
}

static void NotifyLinkSucc(int32_t requestId, LaneLinkInfo *linkInfo)
{
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        LLOGE("lock fail.");
        return;
    }
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        LLOGE("get connrequest item empty");
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return;
    }
    LaneLinkCb cb = item->cb;
    uint32_t linkReqId = item->linkReqId;
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    cb.OnLaneLinkSuccess(linkReqId, linkInfo);
}

NO_SANITIZE("cfi") static int32_t LaneLinkOfBr(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    int32_t ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_BT_MAC,
        linkInfo.linkInfo.br.brMac, BT_MAC_LEN);
    if (ret != SOFTBUS_OK || strlen(linkInfo.linkInfo.br.brMac) == 0) {
        LLOGE("br mac is failed");
        return SOFTBUS_ERR;
    }
    linkInfo.type = LANE_BR;
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static int32_t GetExpectedP2pRole(void)
{
    return ROLE_AUTO;
}

static int32_t GetP2pMacAndPid(int32_t requestId, char *mac, uint32_t size, int32_t *pid)
{
    ConnRequestItem *item = NULL;
    ConnRequestItem *next = NULL;
    if (SoftBusMutexLock(&g_pendingList->lock) != 0) {
        LLOGE("lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_pendingList->list, ConnRequestItem, node) {
        if (item->requestId != requestId) {
            continue;
        }
        if (LnnGetRemoteStrInfo(item->networkId, STRING_KEY_P2P_MAC, mac, size) != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&g_pendingList->lock);
            LLOGE("p2pMac cpy err");
            return SOFTBUS_ERR;
        }
        *pid = item->pid;
        (void)SoftBusMutexUnlock(&g_pendingList->lock);
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&g_pendingList->lock);
    LLOGE("request item not found, requestId = %d.", requestId);
    return SOFTBUS_ERR;
}

static void OnP2pConnected(int32_t requestId, const char *myIp, const char *peerIp)
{
    LLOGI("requestId %d", requestId);
    __attribute__((unused))int errCode = SOFTBUS_OK;
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        LLOGE("get connrequest item empty");
        return;
    }
    if (myIp == NULL || peerIp ==NULL) {
        LLOGE("p2p info invalid");
        errCode = SOFTBUS_INVALID_PARAM;
        goto FAIL;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_P2P;
    linkInfo.linkInfo.p2p.bw = LANE_BW_RANDOM;
    P2pConnInfo *p2p = (P2pConnInfo *)&(linkInfo.linkInfo.p2p.connInfo);
    if (strcpy_s(p2p->localIp, IP_LEN, myIp) != EOK) {
        LLOGE("strcpy localIp fail");
        errCode = SOFTBUS_MEM_ERR;
        goto FAIL;
    }
    if (strcpy_s(p2p->peerIp, IP_LEN, peerIp) != EOK) {
        LLOGE("strcpy peerIp fail");
        errCode = SOFTBUS_MEM_ERR;
        goto FAIL;
    }
    NotifyLinkSucc(requestId, &linkInfo);
    if (item->authId != SOFTBUS_ERR) {
        AuthCloseConn(item->authId);
    }
    DelConnRequestItem(requestId);
    return;
FAIL:
    if (item->authId != SOFTBUS_ERR) {
        AuthCloseConn(item->authId);
    }
    NotifyLinkFail(requestId, SOFTBUS_ERR);
    DelConnRequestItem(requestId);
}

static void OnP2pConnectFailed(int32_t requestId, int32_t reason)
{
    LLOGE("p2p connect failed, requestId:%d,reason:%d", requestId, reason);
    NotifyLinkFail(requestId, reason);
    ConnRequestItem *item = GetConnRequestItem(requestId);
    if (item == NULL) {
        LLOGE("get connRequest item empty");
        return;
    }
    if (item->authId != SOFTBUS_ERR) {
        AuthCloseConn(item->authId);
    }
    DelConnRequestItem(requestId);
}

static void OnConnOpened(uint32_t requestId, int64_t authId)
{
    LLOGI("OnConnOpened: requestId = %d, authId = %" PRId64 ".", requestId, authId);
    P2pLinkConnectInfo info = {0};
    info.requestId = (int32_t)requestId;
    info.authId = authId;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        LLOGE("get p2p mac fail.");
        goto FAIL;
    }
    info.expectedRole = (P2pLinkRole)GetExpectedP2pRole();
    info.cb.onConnected = OnP2pConnected;
    info.cb.onConnectFailed = OnP2pConnectFailed;
    (void)AuthSetP2pMac(authId, info.peerMac);
    if (P2pLinkConnectDevice(&info) != SOFTBUS_OK) {
        LLOGE("connect p2p device err.");
        goto FAIL;
    }
    return;
FAIL:
    if (authId != SOFTBUS_ERR) {
        AuthCloseConn(authId);
    }
    NotifyLinkFail(requestId, SOFTBUS_ERR);
    DelConnRequestItem(requestId);
}

static void OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    NotifyLinkFail(requestId, reason);
}

static int32_t GetPreferAuthConnInfo(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LLOGE("get peer uuid fail.");
        return SOFTBUS_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
}

static bool GetChannelAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetChannelAuthType fail ,ret=%d", ret);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetChannelAuthType success ,value=%d", value);
    return ((1 << ONLINE_METANODE) == value) ? true : false;
}

static int32_t OpenAuthConnToConnectP2p(uint32_t reqId, const char *networkId, int32_t pid, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    if (GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("no auth conn exist.");
        return SOFTBUS_ERR;
    }
    int32_t requestId = P2pLinkGetRequestId();
    if (AddConnRequestItem(reqId, requestId, networkId, pid, callback) != SOFTBUS_OK) {
        LLOGE("add pending item fail.");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpened,
        .onConnOpenFailed = OnConnOpenFailed
    };
    if (AuthOpenConn(&connInfo, requestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("open auth conn fail.");
        DelConnRequestItem(requestId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LaneLinkOfP2p(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    if (g_pendingList == NULL) {
        LLOGE("pending not init");
        return SOFTBUS_ERR;
    }
    return OpenAuthConnToConnectP2p(reqId, reqInfo->peerNetworkId, reqInfo->pid, callback);
}

static int32_t GetWlanLinkedAttribute(int32_t *channel, bool *is5GBand, bool *isConnected)
{
    LnnWlanLinkedInfo info;
    int32_t ret = LnnGetWlanLinkedInfo(&info);
    if (ret != SOFTBUS_OK) {
        LLOGE("get wlan link info failed, ret:%d", ret);
        return SOFTBUS_ERR;
    }
    *isConnected = info.isConnected;

    if (info.band == 1) {
        *is5GBand =false;
    } else {
        *is5GBand =true;
    }

    *channel = SoftBusFrequencyToChannel(info.frequency);
    LLOGI("wlan current channel is %d", *channel);
    return SOFTBUS_OK;
}

struct SelectProtocolReq {
    LnnNetIfType localIfType;
    ProtocolType selectedProtocol;
    ProtocolType remoteSupporttedProtocol;
    uint8_t currPri;
};

VisitNextChoice FindBestProtocol(const LnnPhysicalSubnet *subnet, void *priv)
{
    if (subnet == NULL || priv == NULL || subnet->protocol == NULL) {
        return CHOICE_FINISH_VISITING;
    }
    struct SelectProtocolReq *req = (struct SelectProtocolReq *)priv;
    if (subnet->status == LNN_SUBNET_RUNNING && (subnet->protocol->supportedNetif & req->localIfType) != 0 &&
        subnet->protocol->pri > req->currPri && (subnet->protocol->id & req->remoteSupporttedProtocol) != 0) {
            req->currPri = subnet->protocol->pri;
            req->selectedProtocol = subnet->protocol->id;
        }

        return CHOICE_VISIT_NEXT;
}

static ProtocolType LnnLaneSelectProtocol(LnnNetIfType ifType, const char *netWorkId, ProtocolType acceptableProtocols)
{
    NodeInfo *remoteNodeInfo = LnnGetNodeInfoById(netWorkId, CATEGORY_NETWORK_ID);
    if (remoteNodeInfo == NULL) {
        LLOGE("no such network id");
        return SOFTBUS_ERR;
    }

    const NodeInfo *localNode = LnnGetLocalNodeInfo();
    if (localNode == NULL) {
        LLOGE("get local node info failed!");
        return SOFTBUS_ERR;
    }

    struct SelectProtocolReq req = {
        .localIfType = ifType,
        .remoteSupporttedProtocol = remoteNodeInfo->supportedProtocols & acceptableProtocols,
        .selectedProtocol = 0,
        .currPri = 0,
    };

    if ((req.remoteSupporttedProtocol & LNN_PROTOCOL_NIP) != 0 &&
        (strcmp(remoteNodeInfo->nodeAddress, NODE_ADDR_LOOPBACK) == 0 ||
            strcmp(localNode->nodeAddress, NODE_ADDR_LOOPBACK) == 0)) {
        LLOGW("newip temporaily unavailable");
        req.remoteSupporttedProtocol ^= LNN_PROTOCOL_NIP;
    }

    (void)LnnVisitPhysicalSubnet(FindBestProtocol, &req);

    LLOGI("protocol = %ld", req.selectedProtocol);
    return LNN_PROTOCOL_IP;
}

static void FillWlanLinkInfo(
    LaneLinkInfo *linkInfo, bool is5GBand, int32_t channel, uint16_t port, ProtocolType protocol)
{
    if (is5GBand) {
        linkInfo->type = LANE_WLAN_5G;
    } else {
        linkInfo->type = LANE_WLAN_2P4G;
    }
    WlanLinkInfo *wlan = &(linkInfo->linkInfo.wlan);
    wlan->channel = channel;
    wlan->bw = LANE_BW_RANDOM;
    wlan->connInfo.protocol = protocol;
    wlan->connInfo.port = port;
}

NO_SANITIZE("cfi") static int32_t LaneLinkOfWlan(uint32_t reqId, const LinkRequest *reqInfo, const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo;
    int32_t port = 0;
    int32_t ret = SOFTBUS_OK;
    ProtocolType acceptableProtocols = LNN_PROTOCOL_ALL;
    if (reqInfo->transType != LANE_T_MSG && reqInfo->transType != LANE_T_BYTE) {
        acceptableProtocols ^= LNN_PROTOCOL_NIP;
    }
    ProtocolType protocol =
        LnnLaneSelectProtocol(LNN_NETIF_TYPE_WLAN | LNN_NETIF_TYPE_ETH, reqInfo->peerNetworkId, acceptableProtocols);
    if (protocol == LNN_PROTOCOL_IP) {
        ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_WLAN_IP, linkInfo.linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo.linkInfo.wlan.connInfo.addr));
        if (ret != SOFTBUS_OK) {
            LLOGE("wlan ip err ,ret:%d", ret);
            return SOFTBUS_ERR;
        }
        if (strnlen(linkInfo.linkInfo.wlan.connInfo.addr, sizeof(linkInfo.linkInfo.wlan.connInfo.addr)) == 0 ||
            strncmp(linkInfo.linkInfo.wlan.connInfo.addr, "127.0.0.1", strlen("127.0.0.1")) == 0) {
                LLOGE("wlan ip not found");
                return SOFTBUS_ERR;
        }
    } else {
        ret = LnnGetRemoteStrInfo(reqInfo->peerNetworkId, STRING_KEY_NODE_ADDR, linkInfo.linkInfo.wlan.connInfo.addr,
            sizeof(linkInfo.linkInfo.wlan.connInfo.addr));
        if (ret != SOFTBUS_OK) {
            LLOGE("wlan addr error ret:%d", ret);
            return SOFTBUS_ERR;
        }
    }
    if (reqInfo->transType ==LANE_T_MSG) {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_PROXY_PORT, &port);
        LLOGI("lnngetremote proxy port");
    } else {
        ret = LnnGetRemoteNumInfo(reqInfo->peerNetworkId, NUM_KEY_SESSION_PORT, &port);
        LLOGI("lnngetremote session port");
    }
    if (ret < 0) {
        LLOGE("LnnGetRemote is failed");
        return SOFTBUS_ERR;
    }
    int32_t channel = -1;
    bool is5GBand = false;
    bool isConnected = false;
    if (GetWlanLinkedAttribute(&channel, &is5GBand, &isConnected) != SOFTBUS_OK) {
        LLOGE("get wlan linked info failed");
    }
    if (!isConnected) {
        LLOGE("wlan is disconnect");
    }

    FillWlanLinkInfo(&linkInfo, is5GBand, channel, (uint16_t)port, protocol);
    callback->OnLaneLinkSuccess(reqId, &linkInfo);
    return SOFTBUS_OK;
}

static LaneLinkByType g_linkTable[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = LaneLinkOfBr,
    [LANE_P2P] = LaneLinkOfP2p,
    [LANE_WLAN_5G] = LaneLinkOfWlan,
    [LANE_WLAN_2P4G] = LaneLinkOfWlan,
};

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    if (IsLinkRequestValid(reqInfo) != SOFTBUS_OK || LinkTypeCheck(reqInfo->linkType) == false) {
        LLOGE("the reInfo or type is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (callback == NULL || callback->OnLaneLinkSuccess == NULL ||
        callback->OnLaneLinkFail == NULL || callback->OnLaneLinkException == NULL) {
        LLOGE("the callback is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LLOGI("build link linktype: %d", reqInfo->linkType);
    if (g_linkTable[reqInfo->linkType](reqId, reqInfo, callback)!= SOFTBUS_OK) {
        LLOGE("lane link is failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void DisconnectP2pWithoutAuthConn(const char *networkId, int32_t pid, const char *mac)
{
    P2pLinkDisconnectInfo info = {0};
    info.authId = -1;
    info.pid = pid;
    if (memcpy_s(info.peerMac, P2P_MAC_LEN, mac, strlen(mac)) != EOK) {
        LLOGE("p2p mac copy err");
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        LLOGE("disconnect p2p device err");
    }
}

static void OnConnOpenFailedForDisconnect(uint32_t requestId, int32_t reason)
{
    LLOGI("onconnopenfailed: request:%d, reason:%d", requestId, reason);
    P2pLinkDisconnectInfo info = {0};
    info.authId = -1;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        LLOGE("get p2p mac fail");
        DelConnRequestItem(requestId);
        return;
    }
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        LLOGE("disconnect p2p device err");
    }
    DelConnRequestItem(requestId);
}

static void OnConnOpenedForDisconnect(uint32_t requestId, int64_t authId)
{
    LLOGI("OnConnOpened: requestId = %d, authId = %" PRId64 ".", requestId, authId);
    P2pLinkDisconnectInfo info = {0};
    info.authId = authId;
    if (GetP2pMacAndPid(requestId, info.peerMac, sizeof(info.peerMac), &info.pid) != SOFTBUS_OK) {
        LLOGE("get p2p mac fail.");
        AuthCloseConn(authId);
        DelConnRequestItem(requestId);
        return;
    }
    (void)AuthSetP2pMac(authId, info.peerMac);
    if (P2pLinkDisconnectDevice(&info) != SOFTBUS_OK) {
        LLOGE("disconnect p2p device err.");
        AuthCloseConn(authId);
    }
    DelConnRequestItem(requestId);
}

static int32_t OpenAuthConnToDisconnectP2p(uint32_t reqId, const char *networkId, int32_t pid)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LLOGE("get peer uuid fail.");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    if (GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("no auth conn exist.");
        return SOFTBUS_ERR;
    }
    int32_t requestId = P2pLinkGetRequestId();
    if (AddConnRequestItem(reqId, requestId, networkId, pid, NULL) != SOFTBUS_OK) {
        LLOGE("add pending item fail.");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForDisconnect
    };
    if (AuthOpenConn(&connInfo, requestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LLOGE("open auth conn fail.");
        DelConnRequestItem(requestId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") static int32_t LnnDisconnectP2p(uint32_t reqId, const char *networkId, int32_t pid, const char *mac)
{
    if (networkId == NULL) {
        LLOGE("invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_pendingList == NULL) {
        LLOGE("pending not init.");
        return SOFTBUS_ERR;
    }
    if (OpenAuthConnToDisconnectP2p(reqId, networkId, pid) != SOFTBUS_OK) {
        DisconnectP2pWithoutAuthConn(networkId, pid, mac);
    }
    return SOFTBUS_OK;
}

void DestroyLink(uint32_t reqId, LaneLinkType type, int32_t pid, const char *mac, const char *networkId)
{
    if (networkId == NULL) {
        LLOGE("networkid is null");
        return;
    }
    if (type == LANE_P2P) {
        (void)LnnDisconnectP2p(reqId, networkId, pid, mac);
    }
}

int32_t InitLaneLink(void)
{
    if (LnnLanePendingInit() != SOFTBUS_OK) {
        LLOGE("pending init failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void DeinitLaneLink(void)
{
    LnnLanePendingDeinit();
    return;
}

/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "auth_manager.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "channel/default_negotiate_channel.h"
#include "channel/fast_connect_negotiate_channel.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_def.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "softbus_proxychannel_pipeline.h"
#include "wifi_direct_manager.h"
#include "utils/wifi_direct_utils.h"

#include "lnn_trans_lane.h"
#include "lnn_lane_interface.h"

typedef struct {
    uint32_t requestId;
    int64_t authId;
} AuthChannel;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    uint32_t laneLinkReqId;
    int32_t pid;
    LaneLinkType laneType;
    LaneLinkCb cb;
} LaneLinkRequestInfo;

typedef struct {
    int32_t p2pRequestId;
    int32_t p2pModuleGenId;
    bool networkDelegate;
    bool p2pOnly;
    uint32_t bandWidth;
    bool isWithQos;
} P2pRequestInfo;

typedef struct {
    int32_t requestId;
    int32_t channelId;
} ProxyChannelInfo;

typedef struct {
    ListNode node;
    LaneLinkRequestInfo laneRequestInfo;
    AuthChannel auth;
    P2pRequestInfo p2pInfo;
    ProxyChannelInfo proxyChannelInfo;
} P2pLinkReqList;

typedef struct {
    ListNode node;
    uint32_t laneLinkReqId;
    char remoteMac[MAX_MAC_LEN];
    int32_t pid;
    int32_t p2pModuleLinkId;
    int32_t p2pLinkDownReqId;
    AuthChannel auth;
} P2pLinkedList;

typedef enum {
    ASYNC_RESULT_P2P,
    ASYNC_RESULT_AUTH,
    ASYNC_RESULT_CHANNEL,
} AsyncResultType;

typedef enum {
    GUIDE_TYPE_BLE = 1,
    GUIDE_TYPE_EXIST_AUTH,
    GUIDE_TYPE_BLE_CONN,
    GUIDE_TYPE_NEW_AUTH,
} WifiDirectGuideType;

static ListNode *g_p2pLinkList = NULL; // process p2p link request
static ListNode *g_p2pLinkedList = NULL; // process p2p unlink request
static SoftBusMutex g_p2pLinkMutex;

#define INVAILD_AUTH_ID (-1)
#define INVALID_P2P_REQUEST_ID (-1)

static int32_t LinkLock(void)
{
    return SoftBusMutexLock(&g_p2pLinkMutex);
}

static void LinkUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_p2pLinkMutex);
}

static int32_t GetPreferAuthConnInfo(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_ERR;
    }
    int32_t ret = AuthGetP2pConnInfo(uuid, connInfo, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        ret = AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
    }
    return ret;
}

static bool GetChannelAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "GetChannelAuthType fail, ret=%{public}d", ret);
    }
    return ((1 << ONLINE_METANODE) == value);
}

static void RecycleLinkedListResource(int32_t requestId)
{
    int64_t authId = INVAILD_AUTH_ID;
    if (LinkLock() != 0) {
        return;
    }
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->p2pLinkDownReqId == requestId) {
            authId = item->auth.authId;
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
}

static void OnWifiDirectDisconnectSuccess(int32_t requestId)
{
    LNN_LOGI(LNN_LANE, "wifidirect linkDown succ, requestId=%{public}d", requestId);
    RecycleLinkedListResource(requestId);
}

static void OnWifiDirectDisconnectFailure(int32_t requestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "wifidirect linkDown fail, requestId=%{public}d, reason=%{public}d", requestId, reason);
    RecycleLinkedListResource(requestId);
}

static void DisconnectP2pWithoutAuthConn(int32_t pid, const char *mac, int32_t linkId)
{
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    info.negoChannel = NULL;
    info.pid = pid;
    info.linkId = linkId;
    if (strcpy_s(info.remoteMac, MAC_ADDR_STR_LEN, mac)!= EOK) {
        LNN_LOGE(LNN_LANE, "p2p mac cpy err");
        return;
    }
    struct WifiDirectConnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGD(LNN_LANE, "disconnect wifiDirect, p2pLinkId=%{public}d", linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
    }
}

static int32_t GetP2pLinkDownParam(uint32_t authRequestId, int32_t p2pRequestId,
    struct WifiDirectConnectInfo *wifiDirectInfo)
{
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->auth.requestId != authRequestId) {
            continue;
        }
        if (strcpy_s(wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac), item->remoteMac) != EOK) {
            LinkUnlock();
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->pid = item->pid;
        wifiDirectInfo->linkId = item->p2pModuleLinkId;
        item->p2pLinkDownReqId = p2pRequestId;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, requestId=%{public}d", authRequestId);
    return SOFTBUS_ERR;
}

static void DelP2pLinkedItem(uint32_t authReqId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->auth.requestId == authReqId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

static void DelP2pLinkedItemByLaneId(uint32_t laneId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneLinkReqId == laneId) {
            LNN_LOGI(LNN_LANE, "delete linkedItem, laneId=%{public}u", laneId);
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

static void OnConnOpenFailedForDisconnect(uint32_t requestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "requestId=%{public}d, reason=%{public}d", requestId, reason);
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    info.negoChannel = NULL;
    if (GetP2pLinkDownParam(requestId, info.requestId, &info) != SOFTBUS_OK) {
        return;
    }
    struct WifiDirectConnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGD(LNN_LANE, "disconnect wifiDirect, p2pLinkId=%{public}d", info.linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
    }
    DelP2pLinkedItem(requestId);
}

static void OnConnOpenedForDisconnect(uint32_t requestId, int64_t authId)
{
    LNN_LOGI(LNN_LANE, "requestId=%{public}d, authId=%{public}" PRId64, requestId, authId);
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, authId);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    if (GetP2pLinkDownParam(requestId, info.requestId, &info) != SOFTBUS_OK) {
        goto FAIL;
    }
    (void)AuthSetP2pMac(authId, info.remoteMac);
    struct WifiDirectConnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGD(LNN_LANE, "disconnect wifiDirect, p2pLinkId=%{public}d", info.linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        goto FAIL;
    }
    DelP2pLinkedItem(requestId);
    return;
FAIL:
    DefaultNegotiateChannelDestructor(&channel);
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
}

static bool GetAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "fail, ret=%{public}d", ret);
    }
    LNN_LOGD(LNN_LANE, "success, value=%{public}d", value);
    return ((1 << ONLINE_METANODE) == value);
}

static int32_t GetPreferAuth(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
}

static int32_t GetP2pLinkReqParamByChannelRequetId(
    int32_t channelRequestId, int32_t channelId, int32_t p2pRequestId, struct WifiDirectConnectInfo *wifiDirectInfo)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }

    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->proxyChannelInfo.requestId != channelRequestId) {
            continue;
        }
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_P2P_MAC, wifiDirectInfo->remoteMac,
                                sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->bandWidth = item->p2pInfo.bandWidth;
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        if (strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
                    item->laneRequestInfo.networkId) != EOK) {
            LNN_LOGE(LNN_LANE, "copy networkId failed");
            LinkUnlock();
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        if (item->p2pInfo.isWithQos) {
            wifiDirectInfo->connectType = ((item->laneRequestInfo.laneType == LANE_HML) ?
                WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P);
        } else {
            wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
        }
        item->p2pInfo.p2pRequestId = p2pRequestId;
        item->proxyChannelInfo.channelId = channelId;
        LinkUnlock();
        return SOFTBUS_OK;
    }

    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, channelId=%{public}d", channelId);
    return SOFTBUS_ERR;
}

static int32_t GetP2pLinkReqParamByAuthId(uint32_t authRequestId, int32_t p2pRequestId,
                                          struct WifiDirectConnectInfo *wifiDirectInfo)
{
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->auth.requestId != authRequestId) {
            continue;
        }
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
            wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        if (strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
                    item->laneRequestInfo.networkId) != EOK) {
            LNN_LOGE(LNN_LANE, "copy networkId failed");
            LinkUnlock();
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->bandWidth = item->p2pInfo.bandWidth;
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        if (item->p2pInfo.isWithQos) {
            wifiDirectInfo->connectType = ((item->laneRequestInfo.laneType == LANE_HML) ?
                WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P);
        } else {
            wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
        }
        item->p2pInfo.p2pRequestId = p2pRequestId;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, requestId=%{public}d", authRequestId);
    return SOFTBUS_ERR;
}

static void NotifyLinkFail(AsyncResultType type, int32_t requestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "type=%{public}d, requestId=%{public}d, reason=%{public}d", type, requestId, reason);
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    uint32_t linkReqId;
    int64_t authId = INVAILD_AUTH_ID;
    LaneLinkCb cb;
    cb.OnLaneLinkFail = NULL;
    bool isNodeExist = false;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if ((type == ASYNC_RESULT_AUTH) &&
            (item->auth.requestId == (uint32_t)requestId)) {
            isNodeExist = true;
            break;
        } else if ((type == ASYNC_RESULT_P2P) &&
            (item->p2pInfo.p2pRequestId == requestId)) {
            isNodeExist = true;
            break;
        } else if (type == ASYNC_RESULT_CHANNEL && item->proxyChannelInfo.requestId == requestId) {
            isNodeExist = true;
            break;
        }
    }
    if (!isNodeExist) {
        LinkUnlock();
        return;
    }
    cb.OnLaneLinkFail = item->laneRequestInfo.cb.OnLaneLinkFail;
    linkReqId = item->laneRequestInfo.laneLinkReqId;
    authId = item->auth.authId;
    int32_t channelId = item->proxyChannelInfo.channelId;
    ListDelete(&item->node); // async request finish, delete nodeInfo;
    SoftBusFree(item);
    LinkUnlock();
    if (cb.OnLaneLinkFail != NULL) {
        cb.OnLaneLinkFail(linkReqId, reason);
    }
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
    if (channelId > 0) {
        TransProxyPipelineCloseChannel(channelId);
    }
}

static void CopyLinkInfoToLinkedList(const P2pLinkReqList *linkReqInfo, P2pLinkedList *linkedInfo)
{
    linkedInfo->pid = linkReqInfo->laneRequestInfo.pid;
    linkedInfo->laneLinkReqId = linkReqInfo->laneRequestInfo.laneLinkReqId;
    linkedInfo->auth.authId = INVAILD_AUTH_ID;
    if (LnnGetRemoteStrInfo(linkReqInfo->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
        linkedInfo->remoteMac, sizeof(linkedInfo->remoteMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
        return;
    }
}

static void NotifyLinkSucc(AsyncResultType type, int32_t requestId, LaneLinkInfo *linkInfo, int32_t linkId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    LaneLinkCb cb;
    cb.OnLaneLinkSuccess = NULL;
    int64_t authId = INVAILD_AUTH_ID;
    uint32_t linkReqId;
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    bool isNodeExist = false;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if ((type == ASYNC_RESULT_AUTH) &&
            (item->auth.requestId == (uint32_t)requestId)) {
            isNodeExist = true;
            break;
        } else if ((type == ASYNC_RESULT_P2P) &&
            (item->p2pInfo.p2pRequestId == requestId)) {
            isNodeExist = true;
            break;
        } else if (type == ASYNC_RESULT_CHANNEL && item->proxyChannelInfo.channelId == requestId) {
            isNodeExist = true;
            break;
        }
    }
    if (!isNodeExist) {
        LinkUnlock();
        return;
    }
    cb.OnLaneLinkSuccess = item->laneRequestInfo.cb.OnLaneLinkSuccess;
    linkReqId = item->laneRequestInfo.laneLinkReqId;
    authId = item->auth.authId;
    P2pLinkedList *newNode = (P2pLinkedList *)SoftBusMalloc(sizeof(P2pLinkedList));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        LinkUnlock();
        goto FAIL;
    }
    newNode->p2pModuleLinkId = linkId;
    CopyLinkInfoToLinkedList(item, newNode);
    ListTailInsert(g_p2pLinkedList, &newNode->node);
    int32_t channelId = item->proxyChannelInfo.channelId;
    ListDelete(&item->node); // async request finish, delete nodeInfo;
    SoftBusFree(item);
    LinkUnlock();
    if (authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authId);
    }
    if (channelId > 0) {
        TransProxyPipelineCloseChannelDelay(channelId);
    }
FAIL:
    if (cb.OnLaneLinkSuccess != NULL) {
        cb.OnLaneLinkSuccess(linkReqId, linkInfo);
    }
}

static void OnWifiDirectConnectSuccess(int32_t p2pRequestId, const struct WifiDirectLink *link)
{
    int errCode = SOFTBUS_OK;
    LaneLinkInfo linkInfo;
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "link is null");
        return;
    }
    LNN_LOGI(LNN_LANE, "wifidirect conn succ, requestId=%{public}d, p2pGenLinkId=%{public}d, linktype=%{public}d",
        p2pRequestId, link->linkId, link->linkType);
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (link->linkType == WIFI_DIRECT_LINK_TYPE_HML) {
        linkInfo.type = LANE_HML;
    } else {
        linkInfo.type = LANE_P2P;
    }
    linkInfo.linkInfo.p2p.bw = LANE_BW_RANDOM;
    P2pConnInfo *p2p = (P2pConnInfo *)&(linkInfo.linkInfo.p2p.connInfo);
    if (strcpy_s(p2p->localIp, IP_LEN, link->localIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy localIp fail");
        errCode = SOFTBUS_MEM_ERR;
        goto FAIL;
    }
    if (strcpy_s(p2p->peerIp, IP_LEN, link->remoteIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerIp fail");
        errCode = SOFTBUS_MEM_ERR;
        goto FAIL;
    }
    NotifyLinkSucc(ASYNC_RESULT_P2P, p2pRequestId, &linkInfo, link->linkId);
    return;
FAIL:
    NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, errCode);
}

static void OnWifiDirectConnectFailure(int32_t p2pRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "wifidirect conn fail, requestId=%{public}d, reason=%{public}d",
        p2pRequestId, reason);
    NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
}

static void OnAuthConnOpened(uint32_t authRequestId, int64_t authId)
{
    LNN_LOGI(LNN_LANE, "auth opened. authRequestId=%{public}u, authId=%{public}" PRId64, authRequestId, authId);
    struct WifiDirectConnectInfo info;
    info.requestId = GetWifiDirectManager()->getRequestId();
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, authId);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;
    if (GetP2pLinkReqParamByAuthId(authRequestId, info.requestId, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set p2p link param fail");
        goto FAIL;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifi direct connectDevice. p2pRequest=%{public}d, connectType=%{public}d",
        info.requestId, info.connectType);
    if (GetWifiDirectManager()->connectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "connect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    DefaultNegotiateChannelDestructor(&channel);
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, SOFTBUS_ERR);
}

static void OnAuthConnOpenFailed(uint32_t authRequestId, int32_t reason)
{
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, reason);
}

static int32_t updataP2pLinkReq(P2pLinkReqList *p2pReqInfo, uint32_t laneLinkReqId)
{
    TransOption reqInfo = {0};
    if (GetTransOptionByLaneId(laneLinkReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get TransReqInfo fail, laneId=%{public}d", laneLinkReqId);
        return SOFTBUS_ERR;
    }
    if (reqInfo.isWithQos) {
        p2pReqInfo->p2pInfo.bandWidth = reqInfo.qosRequire.minBW;
        p2pReqInfo->p2pInfo.isWithQos = true;
    } else {
        p2pReqInfo->p2pInfo.bandWidth = 0;
        p2pReqInfo->p2pInfo.isWithQos = false;
    }
    LNN_LOGI(LNN_LANE, "wifi direct conn, bandWidth=%{public}d, isWithQos=%{public}d, laneId=%{public}d",
        p2pReqInfo->p2pInfo.bandWidth, p2pReqInfo->p2pInfo.isWithQos, laneLinkReqId);
    return SOFTBUS_OK;
}

static int32_t AddConnRequestItem(uint32_t authRequestId, int32_t p2pRequestId, uint32_t laneLinkReqId,
    const LinkRequest *request, int32_t channelRequestId, const LaneLinkCb *callback)
{
    P2pLinkReqList *item = (P2pLinkReqList *)SoftBusCalloc(sizeof(P2pLinkReqList));
    if (item == NULL) {
        LNN_LOGE(LNN_LANE, "malloc conn request item err");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(item->laneRequestInfo.networkId, sizeof(item->laneRequestInfo.networkId),
        request->peerNetworkId) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&item->laneRequestInfo.cb, sizeof(LaneLinkCb), callback, sizeof(LaneLinkCb)) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
    }
    if (updataP2pLinkReq(item, laneLinkReqId) != SOFTBUS_OK) {
        SoftBusFree(item);
        return SOFTBUS_ERR;
    }
    item->laneRequestInfo.laneLinkReqId = laneLinkReqId;
    item->laneRequestInfo.pid = request->pid;
    item->auth.authId = INVAILD_AUTH_ID;
    item->auth.requestId = authRequestId;
    item->p2pInfo.p2pModuleGenId = INVALID_P2P_REQUEST_ID;
    item->p2pInfo.networkDelegate = request->networkDelegate;
    item->p2pInfo.p2pOnly = request->p2pOnly;
    item->p2pInfo.p2pRequestId = p2pRequestId;
    item->proxyChannelInfo.requestId = channelRequestId;
    item->laneRequestInfo.laneType = request->linkType;
    if (LinkLock() != 0) {
        SoftBusFree(item);
        LNN_LOGE(LNN_LANE, "lock fail, add conn request fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(g_p2pLinkList, &item->node);
    LinkUnlock();
    return SOFTBUS_OK;
}

static void DelConnRequestItem(uint32_t authReqId, int32_t p2pRequestId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->auth.requestId == authReqId && item->p2pInfo.p2pRequestId == p2pRequestId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

static int32_t UpdateP2pLinkedList(uint32_t laneLinkReqId, uint32_t authRequestId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_ERR;
    }
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneLinkReqId == laneLinkReqId) {
            item->auth.requestId = authRequestId;
            break;
        }
    }
    LinkUnlock();
    return SOFTBUS_OK;
}

static int32_t OpenAuthToDisconnP2p(const char *networkId, uint32_t laneLinkReqId)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    if (GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return SOFTBUS_ERR;
    }
    uint32_t authRequestId = AuthGenRequestId();
    if (UpdateP2pLinkedList(laneLinkReqId, authRequestId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update linkedInfo fail");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForDisconnect
    };
    if (AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail, laneId=%{public}u", laneLinkReqId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void OnProxyChannelOpened(int32_t channelRequestId, int32_t channelId)
{
    LNN_LOGI(LNN_LANE, "proxy opened. channelRequestId=%{public}d, channelId=%{public}d",
        channelRequestId, channelId);
    struct WifiDirectConnectInfo info;
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;

    struct FastConnectNegotiateChannel channel;
    FastConnectNegotiateChannelConstructor(&channel, channelId);
    info.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;

    if (GetP2pLinkReqParamByChannelRequetId(channelRequestId, channelId, info.requestId, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link param fail");
        FastConnectNegotiateChannelDestructor(&channel);
        TransProxyPipelineCloseChannel(channelId);
        NotifyLinkFail(ASYNC_RESULT_CHANNEL, channelRequestId, SOFTBUS_ERR);
        return;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifi direct connectDevice. p2prequest=%{public}d, connectType=%{public}d",
        info.requestId, info.connectType);
    int32_t ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    FastConnectNegotiateChannelDestructor(&channel);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "connect p2p device fail");
        NotifyLinkFail(ASYNC_RESULT_CHANNEL, channelRequestId, SOFTBUS_ERR);
    }
}

static void OnProxyChannelOpenFailed(int32_t channelRequestId, int32_t reason)
{
    NotifyLinkFail(ASYNC_RESULT_CHANNEL, channelRequestId, reason);
}

static int32_t OpenProxyChannelToConnP2p(const LinkRequest *request,
                                         uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    LNN_LOGD(LNN_LANE, "enter");
    TransProxyPipelineChannelOption option = {
        .bleDirect = true,
    };
    ITransProxyPipelineCallback channelCallback = {
        .onChannelOpened = OnProxyChannelOpened,
        .onChannelOpenFailed = OnProxyChannelOpenFailed,
    };
    int32_t requestId = TransProxyPipelineGenRequestId();
    int32_t ret = AddConnRequestItem(0, INVALID_P2P_REQUEST_ID, laneLinkReqId, request, requestId, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new connect node failed");
        return ret;
    }
    LNN_LOGI(LNN_LANE, "open proxy channel. channelRequestId=%{public}d", requestId);
    ret = TransProxyPipelineOpenChannel(requestId, request->peerNetworkId, &option, &channelCallback);
    if (ret != SOFTBUS_OK) {
        DelConnRequestItem(0, INVALID_P2P_REQUEST_ID);
        LNN_LOGE(LNN_LANE, "open channel failed, ret=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "requestId=%{public}d", requestId);

    return SOFTBUS_OK;
}

static int32_t OpenAuthToConnP2p(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    if (GetPreferAuth(request->peerNetworkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return SOFTBUS_ERR;
    }
    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AddConnRequestItem(authRequestId, INVALID_P2P_REQUEST_ID, laneLinkReqId, request, 0, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "add new connect node failed");

    AuthConnCallback cb = {
        .onConnOpened = OnAuthConnOpened,
        .onConnOpenFailed = OnAuthConnOpenFailed
    };
    LNN_LOGI(LNN_LANE, "open auth with authRequestId=%{public}u", authRequestId);
    if (AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail");
        DelConnRequestItem(authRequestId, INVALID_P2P_REQUEST_ID);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnP2pInit(void)
{
    if (SoftBusMutexInit(&g_p2pLinkMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "mutex init fail");
        return SOFTBUS_ERR;
    }
    g_p2pLinkList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_p2pLinkList == NULL) {
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    g_p2pLinkedList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_p2pLinkedList == NULL) {
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        SoftBusFree(g_p2pLinkList);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_p2pLinkList);
    ListInit(g_p2pLinkedList);
    return SOFTBUS_OK;
}

static int32_t GetFeatureCap(const char *networkId, uint64_t *local, uint64_t *remote)
{
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, local);
    if (ret != SOFTBUS_OK || *local < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}" PRIu64, ret, *local);
        return SOFTBUS_ERR;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK || *remote < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}" PRIu64, ret, *remote);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetAuthTriggerLinkReqParamByAuthId(uint32_t authRequestId, int32_t p2pRequestId,
                                                  struct WifiDirectConnectInfo *wifiDirectInfo)
{
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->auth.requestId != authRequestId) {
            continue;
        }
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_WIFIDIRECT_ADDR,
            wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LNN_LOGE(LNN_LANE, "get remote wifidirect addr fail");
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        int32_t ret = strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
                               item->laneRequestInfo.networkId);
        if (ret != EOK) {
            LNN_LOGE(LNN_LANE, "copy remote networkId fail");
            LinkUnlock();
            return SOFTBUS_ERR;
        }
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        if (item->p2pInfo.isWithQos) {
            wifiDirectInfo->connectType = ((item->laneRequestInfo.laneType == LANE_HML) ?
                WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P);
        } else {
            wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML;
        }
        item->p2pInfo.p2pRequestId = p2pRequestId;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, requestId=%{public}d", authRequestId);
    return SOFTBUS_ERR;
}

static void OnAuthTriggerConnOpened(uint32_t authRequestId, int64_t authId)
{
    LNN_LOGI(LNN_LANE, "auth trigger opened. authRequestId=%{public}u, authId=%{public}" PRId64 "",
        authRequestId, authId);
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    wifiDirectInfo.requestId = GetWifiDirectManager()->getRequestId();
    struct DefaultNegotiateChannel channel;
    DefaultNegotiateChannelConstructor(&channel, authId);
    wifiDirectInfo.negoChannel = (struct WifiDirectNegotiateChannel*)&channel;
    if (GetAuthTriggerLinkReqParamByAuthId(authRequestId, wifiDirectInfo.requestId, &wifiDirectInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set auth trigger link param fail");
        goto FAIL;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifi direct connectDevice. p2pRequest=%{public}d, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    if (GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "auth trigger hml connect device err");
        goto FAIL;
    }
    return;
FAIL:
    DefaultNegotiateChannelDestructor(&channel);
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, SOFTBUS_ERR);
}

static int32_t OpenAuthTriggerToConn(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    if (GetPreferAuth(request->peerNetworkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return SOFTBUS_ERR;
    }
    uint32_t authRequestId = AuthGenRequestId();
    int32_t ret = AddConnRequestItem(authRequestId, INVALID_P2P_REQUEST_ID, laneLinkReqId, request, 0, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new connect node failed");
        return SOFTBUS_ERR;
    }

    AuthConnCallback cb = {
        .onConnOpened = OnAuthTriggerConnOpened,
        .onConnOpenFailed = OnAuthConnOpenFailed
    };
    LNN_LOGI(LNN_LANE, "open auth trigger with authRequestId=%{public}u", authRequestId);
    if (AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail");
        DelConnRequestItem(authRequestId, INVALID_P2P_REQUEST_ID);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CheckTransReqInfo(const LinkRequest *request, uint32_t laneLinkReqId)
{
    TransOption reqInfo = {0};
    if (GetTransOptionByLaneId(laneLinkReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get TransReqInfo fail, laneId=%{public}d", laneLinkReqId);
        return SOFTBUS_ERR;
    }
    if (reqInfo.isWithQos) {
        if (request->linkType == LANE_P2P) {
            LNN_LOGE(LNN_LANE, "request linkType=%{public}d", request->linkType);
            return SOFTBUS_ERR;
        }
    } else {
        if (request->p2pOnly) {
            LNN_LOGE(LNN_LANE, "request p2pOnly=%{public}d", request->p2pOnly);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t OpenBleTriggerToConn(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    if (CheckTransReqInfo(request, laneLinkReqId) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "ble trigger not support p2p");
        return SOFTBUS_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    if (GetPreferAuth(request->peerNetworkId, &connInfo, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return SOFTBUS_ERR;
    }
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    wifiDirectInfo.requestId = GetWifiDirectManager()->getRequestId();
    int32_t ret = AddConnRequestItem(0, wifiDirectInfo.requestId, laneLinkReqId, request, 0, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "add new connect node failed");
    wifiDirectInfo.pid = request->pid;
    wifiDirectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    ret = strcpy_s(wifiDirectInfo.remoteNetworkId, NETWORK_ID_BUF_LEN, request->peerNetworkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "copy networkId failed");
        DelConnRequestItem(0, wifiDirectInfo.requestId);
        return SOFTBUS_ERR;
    }
    wifiDirectInfo.isNetworkDelegate = request->networkDelegate;

    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifidirect connectDevice with p2prequest=%{public}d, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    if (GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble trigger connect device err");
        NotifyLinkFail(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, SOFTBUS_ERR);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool CheckHasBrConnection(const char *peerNetWorkId)
{
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt.type = CONNECT_BR;
    if (LnnGetRemoteStrInfo(peerNetWorkId, STRING_KEY_BT_MAC, connOpt.brOption.brMac, BT_MAC_LEN) != SOFTBUS_OK ||
        connOpt.brOption.brMac[0] == '\0') {
        return false;
    }
    return CheckActiveConnection(&connOpt);
}

static int32_t LnnSelectDirectLink(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    char uuid[UUID_BUF_LEN] = { 0 };
    if (LnnGetRemoteStrInfo(request->peerNetworkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_ERR;
    }
    uint64_t local = 0;
    uint64_t remote = 0;
    if (GetFeatureCap(request->peerNetworkId, &local, &remote) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_ERR;
    if (AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_WIFI, false) ||
        AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_BR, true) ||
        AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_BLE, true)) {
        if ((local & (1 << BIT_BLE_TRIGGER_CONNECTION)) != 0 && (remote & (1 << BIT_BLE_TRIGGER_CONNECTION)) != 0 &&
            GetWifiDirectUtils()->supportHmlTwo()) {
            LNN_LOGI(LNN_LANE, "open auth trigger to connect, laneId=%{public}u", laneLinkReqId);
            ret = OpenAuthTriggerToConn(request, laneLinkReqId, callback);
        }
        if (ret != SOFTBUS_OK) {
            LNN_LOGI(LNN_LANE, "open active auth nego to connect, laneId=%{public}u", laneLinkReqId);
            ret = OpenAuthToConnP2p(request, laneLinkReqId, callback);
        }
    }
    if ((local & (1 << BIT_BLE_TRIGGER_CONNECTION)) != 0 && (remote & (1 << BIT_BLE_TRIGGER_CONNECTION)) != 0 &&
        ret != SOFTBUS_OK && GetWifiDirectUtils()->supportHmlTwo()) {
        LNN_LOGI(LNN_LANE, "open ble trigger to connect, laneId=%{public}u", laneLinkReqId);
        ret = OpenBleTriggerToConn(request, laneLinkReqId, callback);
    }
    if (CheckHasBrConnection(request->peerNetworkId) && ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "open new br auth to connect p2p, laneId=%{public}u", laneLinkReqId);
        ret = OpenAuthToConnP2p(request, laneLinkReqId, callback);
    }
    if (((local & (1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY)) != 0) &&
        ((remote & (1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY)) != 0) &&
          ret != SOFTBUS_OK) {
            LNN_LOGI(LNN_LANE, "open channel to connect p2p, laneId=%{public}u", laneLinkReqId);
            ret = OpenProxyChannelToConnP2p(request, laneLinkReqId, callback);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "open auth to connect p2p, laneId=%{public}u", laneLinkReqId);
        ret = OpenAuthToConnP2p(request, laneLinkReqId, callback);
    }
    return ret;
}

int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    if (request == NULL || callback == NULL) {
        LNN_LOGE(LNN_LANE, "invalid null request or callback");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_p2pLinkList == NULL) {
        LNN_CHECK_AND_RETURN_RET_LOGE(LnnP2pInit() == SOFTBUS_OK, SOFTBUS_ERR, LNN_LANE, "p2p not init");
    }
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    if (isMetaAuth) {
        return OpenAuthToConnP2p(request, laneLinkReqId, callback);
    }
    if (LnnSelectDirectLink(request, laneLinkReqId, callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "select direct link fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnDisconnectP2p(const char *networkId, int32_t pid, uint32_t laneLinkReqId)
{
    if (g_p2pLinkedList == NULL || g_p2pLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "lane link p2p not init, disconn request ignore");
        return;
    }
    char mac[MAX_MAC_LEN];
    int32_t linkId = -1;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, can't exec p2pDisconn");
        return;
    }
    bool isNodeExist = false;
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneLinkReqId == laneLinkReqId &&
            item->pid == pid) {
            isNodeExist = true;
            linkId = item->p2pModuleLinkId;
            break;
        }
    }
    LNN_LOGI(LNN_LANE, "pid=%{public}d, laneId=%{public}u, linkId=%{public}d", pid, laneLinkReqId, linkId);
    if (!isNodeExist) {
        LNN_LOGE(LNN_LANE, "node isn't exist, ignore disconn request, laneId=%{public}u", laneLinkReqId);
        LinkUnlock();
        return;
    }
    if (strcpy_s(mac, MAX_MAC_LEN, item->remoteMac) != EOK) {
        LNN_LOGE(LNN_LANE, "mac addr cpy fail, disconn fail");
        LinkUnlock();
        return;
    }
    LinkUnlock();
    if (OpenAuthToDisconnP2p(networkId, laneLinkReqId) != SOFTBUS_OK) {
        DisconnectP2pWithoutAuthConn(pid, mac, linkId);
        DelP2pLinkedItemByLaneId(laneLinkReqId);
    }
    return;
}

void LnnDestroyP2p(void)
{
    if (g_p2pLinkList == NULL || g_p2pLinkedList == NULL) {
        return;
    }
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkReqList *linkReqItem = NULL;
    P2pLinkReqList *linkReqNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(linkReqItem, linkReqNext, g_p2pLinkList, P2pLinkReqList, node) {
        ListDelete(&linkReqItem->node);
        SoftBusFree(linkReqItem);
    }
    P2pLinkedList *linkedItem = NULL;
    P2pLinkedList *linkedNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(linkedItem, linkedNext, g_p2pLinkedList, P2pLinkedList, node) {
        ListDelete(&linkedItem->node);
        SoftBusFree(linkedItem);
    }
    LinkUnlock();
    SoftBusFree(g_p2pLinkList);
    SoftBusFree(g_p2pLinkedList);
    g_p2pLinkList = NULL;
    g_p2pLinkedList = NULL;
    (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
}
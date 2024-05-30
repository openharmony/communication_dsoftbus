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

#include "lnn_lane_link_p2p.h"

#include <securec.h>

#include "auth_interface.h"
#include "auth_manager.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "softbus_proxychannel_pipeline.h"
#include "wifi_direct_manager.h"

typedef struct {
    uint32_t requestId;
    AuthHandle authHandle;
} AuthChannel;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    uint32_t laneReqId;
    int32_t pid;
    LaneLinkType linkType;
    LaneLinkCb cb;
} LaneLinkRequestInfo;

typedef struct {
    uint32_t p2pRequestId;
    int32_t p2pModuleGenId;
    bool networkDelegate;
    bool p2pOnly;
    uint32_t bandWidth;
    bool isWithQos;
} P2pRequestInfo;

typedef struct {
    uint32_t requestId;
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
    uint32_t laneReqId;
    char remoteMac[MAX_MAC_LEN];
    int32_t pid;
    int32_t p2pModuleLinkId;
    uint32_t p2pLinkDownReqId;
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

typedef enum {
    MSG_TYPE_GUIDE_CHANNEL_TRIGGER,
    MSG_TYPE_GUIDE_CHANNEL_BUTT,
} GuideMsgType;

typedef enum {
    LANE_ACTIVE_AUTH_TRIGGER = 0x0,
    LANE_ACTIVE_BR_TRIGGER,
    LANE_BLE_TRIGGER,
    LANE_NEW_AUTH_TRIGGER,
    LANE_ACTIVE_AUTH_NEGO,
    LANE_ACTIVE_BR_NEGO,
    LANE_PROXY_AUTH_NEGO,
    LANE_NEW_AUTH_NEGO,
    LANE_CHANNEL_BUTT,
} WdGuideType;

typedef struct {
    ListNode node;
    uint32_t laneReqId;
    LinkRequest request;
    LaneLinkCb callback;
    WdGuideType guideList[LANE_CHANNEL_BUTT];
    uint32_t guideNum;
    uint32_t guideIdx;
} WdGuideInfo;

static ListNode *g_p2pLinkList = NULL; // process p2p link request
static ListNode *g_p2pLinkedList = NULL; // process p2p unlink request
static ListNode *g_guideInfoList = NULL;
static SoftBusMutex g_p2pLinkMutex;
static SoftBusHandler g_p2pLoopHandler;

#define INVAILD_AUTH_ID (-1)
#define INVALID_P2P_REQUEST_ID (-1)

typedef int32_t (*GuideLinkByType)(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback);

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

static void RecycleLinkedListResource(uint32_t requestId)
{
    if (LinkLock() != 0) {
        return;
    }
    P2pLinkedList *item = NULL;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->p2pLinkDownReqId == requestId) {
            authHandle.authId = item->auth.authHandle.authId;
            authHandle.type = item->auth.authHandle.type;
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
    if (authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authHandle);
    }
}

static void OnWifiDirectDisconnectSuccess(uint32_t requestId)
{
    LNN_LOGI(LNN_LANE, "wifidirect linkDown succ, requestId=%{public}u", requestId);
    RecycleLinkedListResource(requestId);
}

static void OnWifiDirectDisconnectFailure(uint32_t requestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "wifidirect linkDown fail, requestId=%{public}u, reason=%{public}d", requestId, reason);
    RecycleLinkedListResource(requestId);
}

static void DisconnectP2pWithoutAuthConn(int32_t pid, const char *mac, int32_t linkId)
{
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.pid = pid;
    info.linkId = linkId;
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGD(LNN_LANE, "disconnect wifiDirect, p2pRequestId=%{public}u, linkId=%{public}d", info.requestId, linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
    }
}

static int32_t GetP2pLinkDownParam(uint32_t authRequestId, uint32_t p2pRequestId,
    struct WifiDirectDisconnectInfo *wifiDirectInfo, AuthHandle authHandle)
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
        wifiDirectInfo->pid = item->pid;
        wifiDirectInfo->linkId = item->p2pModuleLinkId;
        item->p2pLinkDownReqId = p2pRequestId;
        item->auth.authHandle = authHandle;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_ERR;
}

static void DelP2pLinkedByAuthReqId(uint32_t authRequestId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->auth.requestId == authRequestId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

static void OnConnOpenFailedForDisconnect(uint32_t authRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "auth open fail to disconnect WD, authRequestId=%{public}u, reason=%{public}d",
        authRequestId, reason);
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    AuthHandle authHandle = { .authId = INVAILD_AUTH_ID };
    if (GetP2pLinkDownParam(authRequestId, info.requestId, &info, authHandle) != SOFTBUS_OK) {
        goto FAIL;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGD(LNN_LANE, "disconnect wifiDirect, p2pRequestId=%{public}u, linkId=%{public}d",
        info.requestId, info.linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    DelP2pLinkedByAuthReqId(authRequestId);
}

static void OnConnOpenedForDisconnect(uint32_t authRequestId, AuthHandle authHandle)
{
    LNN_LOGI(LNN_LANE, "auth opened to disconnect WD, authRequestId=%{public}u, authId=%{public}" PRId64 "",
        authRequestId, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_LANE, "authHandle type error");
        return;
    }
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    info.negoChannel.handle.authHandle = authHandle;
    if (GetP2pLinkDownParam(authRequestId, info.requestId, &info, authHandle) != SOFTBUS_OK) {
        goto FAIL;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGD(LNN_LANE, "disconnect wifiDirect, p2pRequestId=%{public}u, linkId=%{public}d",
        info.requestId, info.linkId);
    if (GetWifiDirectManager()->disconnectDevice(&info, &callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    if (authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authHandle);
    }
    DelP2pLinkedByAuthReqId(authRequestId);
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
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, isMetaAuth);
}

static int32_t GetFeatureCap(const char *networkId, uint64_t *local, uint64_t *remote)
{
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, local);
    if (ret != SOFTBUS_OK || *local == 0) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}" PRIu64, ret, *local);
        return SOFTBUS_ERR;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK || *remote == 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}" PRIu64, ret, *remote);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetP2pLinkReqParamByChannelRequetId(
    int32_t channelRequestId, int32_t channelId, uint32_t p2pRequestId, struct WifiDirectConnectInfo *wifiDirectInfo)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }

    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->proxyChannelInfo.requestId != (uint32_t)channelRequestId) {
            continue;
        }
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_P2P_MAC, wifiDirectInfo->remoteMac,
            sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
        wifiDirectInfo->bandWidth = item->p2pInfo.bandWidth;
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        if (strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
                    item->laneRequestInfo.networkId) != EOK) {
            LNN_LOGE(LNN_LANE, "copy networkId failed");
            LinkUnlock();
            return SOFTBUS_MEM_ERR;
        }
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        wifiDirectInfo->connectType = item->laneRequestInfo.linkType == LANE_HML ?
            WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
        item->p2pInfo.p2pRequestId = p2pRequestId;
        item->proxyChannelInfo.channelId = channelId;
        LinkUnlock();
        return SOFTBUS_OK;
    }

    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, channelRequestId=%{public}d", channelRequestId);
    return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
}

static int32_t GetP2pLinkReqParamByAuthHandle(uint32_t authRequestId, uint32_t p2pRequestId,
    struct WifiDirectConnectInfo *wifiDirectInfo, AuthHandle authHandle)
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
        wifiDirectInfo->connectType = item->laneRequestInfo.linkType == LANE_HML ?
            WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
        item->p2pInfo.p2pRequestId = p2pRequestId;
        item->auth.authHandle = authHandle;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_ERR;
}

static int32_t GetP2pLinkReqByReqId(AsyncResultType type, uint32_t requestId, P2pLinkReqList *info)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if ((type == ASYNC_RESULT_AUTH && item->auth.requestId == requestId) ||
            (type == ASYNC_RESULT_P2P && item->p2pInfo.p2pRequestId == requestId) ||
            (type == ASYNC_RESULT_CHANNEL && item->proxyChannelInfo.requestId == requestId)) {
            if (memcpy_s(info, sizeof(P2pLinkReqList), item, sizeof(P2pLinkReqList)) != EOK) {
                LNN_LOGE(LNN_LANE, "P2pLinkReq memcpy fail.");
                LinkUnlock();
                return SOFTBUS_MEM_ERR;
            }
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "P2pLinkReq item not found, type=%{public}d, requestId=%{public}u.", type, requestId);
    return SOFTBUS_NOT_FIND;
}

static int32_t DelP2pLinkReqByReqId(AsyncResultType type, uint32_t requestId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if ((type == ASYNC_RESULT_AUTH && item->auth.requestId == requestId) ||
            (type == ASYNC_RESULT_P2P && item->p2pInfo.p2pRequestId == requestId) ||
            (type == ASYNC_RESULT_CHANNEL && item->proxyChannelInfo.requestId == requestId)) {
            ListDelete(&item->node);
            SoftBusFree(item);
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGI(LNN_LANE, "P2pLinkReq item not found, type=%{public}d, requestId=%{public}u.", type, requestId);
    return SOFTBUS_OK;
}

static WdGuideInfo *GetGuideNodeWithoutLock(uint32_t laneReqId, LaneLinkType linkType)
{
    WdGuideInfo *guideInfoNode = NULL;
    LIST_FOR_EACH_ENTRY(guideInfoNode, g_guideInfoList, WdGuideInfo, node) {
        if (guideInfoNode->laneReqId == laneReqId && guideInfoNode->request.linkType == linkType) {
            return guideInfoNode;
        }
    }
    return NULL;
}

static int32_t GetGuideInfo(uint32_t laneReqId, LaneLinkType linkType, WdGuideInfo *guideInfo)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, get guide info fail.");
        return SOFTBUS_LOCK_ERR;
    }
    WdGuideInfo *guideItem = NULL;
    WdGuideInfo *guideNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(guideItem, guideNext, g_guideInfoList, WdGuideInfo, node) {
        if (guideItem->laneReqId == laneReqId && guideItem->request.linkType == linkType) {
            if (memcpy_s(guideInfo, sizeof(WdGuideInfo), guideItem, sizeof(WdGuideInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "guideInfo memcpy fail.");
                LinkUnlock();
                return SOFTBUS_MEM_ERR;
            }
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "guideInfo not found, laneReqId=%{public}u, linkType=%{public}d.", laneReqId, linkType);
    return SOFTBUS_ERR;
}

static void DelGuideInfoItem(uint32_t laneReqId, LaneLinkType linkType)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, delete guide info fail.");
        return;
    }
    WdGuideInfo *guideItem = NULL;
    WdGuideInfo *guideNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(guideItem, guideNext, g_guideInfoList, WdGuideInfo, node) {
        if (guideItem->laneReqId == laneReqId && guideItem->request.linkType == linkType) {
            ListDelete(&guideItem->node);
            SoftBusFree(guideItem);
            break;
        }
    }
    LinkUnlock();
}

static void NotifyLinkFail(AsyncResultType type, uint32_t requestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "type=%{public}d, requestId=%{public}u, reason=%{public}d", type, requestId, reason);
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(type, requestId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link req fail, type=%{public}d, requestId=%{public}u", type, requestId);
        return;
    }
    (void)DelP2pLinkReqByReqId(type, requestId);
    DelGuideInfoItem(reqInfo.laneRequestInfo.laneReqId, reqInfo.laneRequestInfo.linkType);
    if (reqInfo.laneRequestInfo.cb.OnLaneLinkFail != NULL) {
        LNN_LOGE(LNN_LANE, "wifidirect conn fail, laneReqId=%{public}u ", reqInfo.laneRequestInfo.laneReqId);
        reqInfo.laneRequestInfo.cb.OnLaneLinkFail(reqInfo.laneRequestInfo.laneReqId, reason,
            reqInfo.laneRequestInfo.linkType);
    }
    if (reqInfo.auth.authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(reqInfo.auth.authHandle);
    }
    if (reqInfo.proxyChannelInfo.channelId > 0) {
        TransProxyPipelineCloseChannel(reqInfo.proxyChannelInfo.channelId);
    }
}

static int32_t AddNewP2pLinkedInfo(const P2pLinkReqList *reqInfo, int32_t linkId)
{
    P2pLinkedList *newNode = (P2pLinkedList *)SoftBusCalloc(sizeof(P2pLinkedList));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    newNode->p2pModuleLinkId = linkId;
    newNode->pid = reqInfo->laneRequestInfo.pid;
    newNode->laneReqId = reqInfo->laneRequestInfo.laneReqId;
    newNode->auth.authHandle.authId = INVAILD_AUTH_ID;
    newNode->auth.requestId = -1;
    newNode->p2pLinkDownReqId = -1;
    if (LnnGetRemoteStrInfo(reqInfo->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
        newNode->remoteMac, sizeof(newNode->remoteMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
        SoftBusFree(newNode);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        SoftBusFree(newNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(g_p2pLinkedList, &newNode->node);
    LinkUnlock();
    return SOFTBUS_OK;
}

static void NotifyLinkSucc(AsyncResultType type, uint32_t requestId, LaneLinkInfo *linkInfo, int32_t linkId)
{
    LNN_LOGI(LNN_LANE, "type=%{public}d, requestId=%{public}u, linkId=%{public}d", type, requestId, linkId);
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(type, requestId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link req fail, type=%{public}d, requestId=%{public}u", type, requestId);
        return;
    }
    (void)DelP2pLinkReqByReqId(type, requestId);
    LaneLinkType throryLinkType = reqInfo.laneRequestInfo.linkType;
    if (reqInfo.laneRequestInfo.linkType != linkInfo->type) {
        LNN_LOGI(LNN_LANE, "not return specified link, requestId=%{public}u", requestId);
    }
    DelGuideInfoItem(reqInfo.laneRequestInfo.laneReqId, throryLinkType);
    int32_t ret = AddNewP2pLinkedInfo(&reqInfo, linkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new p2p linked info fail, laneReqId=%{public}u", reqInfo.laneRequestInfo.laneReqId);
        if (reqInfo.laneRequestInfo.cb.OnLaneLinkFail != NULL) {
            reqInfo.laneRequestInfo.cb.OnLaneLinkFail(reqInfo.laneRequestInfo.laneReqId, ret, throryLinkType);
        }
    } else {
        if (reqInfo.laneRequestInfo.cb.OnLaneLinkSuccess != NULL) {
            LNN_LOGI(LNN_LANE, "wifidirect conn succ, laneReqId=%{public}u, linktype=%{public}d, requestId=%{public}u, "
            "linkId=%{public}d", reqInfo.laneRequestInfo.laneReqId, linkInfo->type, requestId, linkId);
            reqInfo.laneRequestInfo.cb.OnLaneLinkSuccess(reqInfo.laneRequestInfo.laneReqId, throryLinkType, linkInfo);
        }
    }
    if (reqInfo.auth.authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(reqInfo.auth.authHandle);
    }
    if (reqInfo.proxyChannelInfo.channelId > 0) {
        TransProxyPipelineCloseChannelDelay(reqInfo.proxyChannelInfo.channelId);
    }
}

static int32_t CreateWDLinkInfo(uint32_t p2pRequestId, const struct WifiDirectLink *link, LaneLinkInfo *linkInfo)
{
    if (link == NULL || linkInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (link->linkType == WIFI_DIRECT_LINK_TYPE_HML) {
        linkInfo->type = LANE_HML;
    } else {
        linkInfo->type = LANE_P2P;
    }
    linkInfo->linkInfo.p2p.bw = LANE_BW_RANDOM;
    if (strcpy_s(linkInfo->linkInfo.p2p.connInfo.localIp, IP_LEN, link->localIp) != EOK ||
        strcpy_s(linkInfo->linkInfo.p2p.connInfo.peerIp, IP_LEN, link->remoteIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy localIp fail");
        return SOFTBUS_MEM_ERR;
    }
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    int32_t ret = GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &reqInfo);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (LnnGetRemoteStrInfo(reqInfo.laneRequestInfo.networkId, STRING_KEY_DEV_UDID,
        linkInfo->peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static void OnWifiDirectConnectSuccess(uint32_t p2pRequestId, const struct WifiDirectLink *link)
{
    int ret = SOFTBUS_OK;
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "link is null");
        ret = SOFTBUS_INVALID_PARAM;
        goto FAIL;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    ret = CreateWDLinkInfo(p2pRequestId, link, &linkInfo);
    if (ret != SOFTBUS_OK) {
        goto FAIL;
    }
    NotifyLinkSucc(ASYNC_RESULT_P2P, p2pRequestId, &linkInfo, link->linkId);
    return;
FAIL:
    NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, ret);
}

static int32_t PostGuideChannelTriggerMessage(uint32_t laneReqId, LaneLinkType linkType)
{
    LNN_LOGI(LNN_LANE, "post guide channel trigger msg.");
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "create handler msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = MSG_TYPE_GUIDE_CHANNEL_TRIGGER;
    msg->arg1 = laneReqId;
    msg->arg2 = linkType;
    msg->handler = &g_p2pLoopHandler;
    msg->obj = NULL;
    g_p2pLoopHandler.looper->PostMessage(g_p2pLoopHandler.looper, msg);
    return SOFTBUS_OK;
}

static void GuideChannelAsyncRetry(AsyncResultType type, uint32_t requestId, int32_t reason)
{
    P2pLinkReqList p2pLinkReqInfo;
    (void)memset_s(&p2pLinkReqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(type, requestId, &p2pLinkReqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link req fail, type=%{public}d, requestId=%{public}u", type, requestId);
        goto FAIL;
    }
    uint32_t laneReqId = p2pLinkReqInfo.laneRequestInfo.laneReqId;
    LaneLinkType linkType = p2pLinkReqInfo.laneRequestInfo.linkType;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, get guide channel info fail.");
        goto FAIL;
    }
    WdGuideInfo *guideInfoNode = GetGuideNodeWithoutLock(laneReqId, linkType);
    if (guideInfoNode == NULL) {
        LNN_LOGE(LNN_LANE, "get guide info node fail.");
        LinkUnlock();
        goto FAIL;
    }
    guideInfoNode->guideIdx++;
    if (guideInfoNode->guideIdx >= guideInfoNode->guideNum) {
        LNN_LOGE(LNN_LANE, "all guide channel type have been tried.");
        LinkUnlock();
        goto FAIL;
    }
    LinkUnlock();
    (void)DelP2pLinkReqByReqId(type, requestId);
    LNN_LOGI(LNN_LANE, "continue to select guide channel.");
    if (PostGuideChannelTriggerMessage(laneReqId, linkType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post guide channel trigger msg fail.");
        goto FAIL;
    }
    return;
FAIL:
    NotifyLinkFail(type, requestId, reason);
}

static void OnWifiDirectConnectFailure(uint32_t p2pRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "wifidirect conn fail, requestId=%{public}u, reason=%{public}d", p2pRequestId, reason);
    P2pLinkReqList p2pReq;
    (void)memset_s(&p2pReq, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    TransReqInfo tranReq;
    (void)memset_s(&tranReq, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if ((reason == ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT || reason == ERROR_POST_DATA_FAILED) &&
        GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &p2pReq) == SOFTBUS_OK &&
        GetTransReqInfoByLaneReqId(p2pReq.laneRequestInfo.laneReqId, &tranReq) == SOFTBUS_OK &&
        (!tranReq.isWithQos || (tranReq.isWithQos && tranReq.allocInfo.type == LANE_TYPE_TRANS))) {
        LNN_LOGI(LNN_LANE, "guide channel retry, requestId=%{public}u, reason=%{public}d", p2pRequestId, reason);
        GuideChannelAsyncRetry(ASYNC_RESULT_P2P, p2pRequestId, reason);
    } else {
        LNN_LOGI(LNN_LANE, "wifidirect conn fail, requestId=%{public}u, reason=%{public}d", p2pRequestId, reason);
        NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
    }
}

static void OnAuthConnOpened(uint32_t authRequestId, AuthHandle authHandle)
{
    LNN_LOGI(LNN_LANE, "auth opened with authRequestId=%{public}u, authId=%{public}" PRId64 "",
        authRequestId, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_LANE, "authHandle type error");
        return;
    }
    struct WifiDirectConnectInfo info;
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    info.negoChannel.handle.authHandle = authHandle;
    int32_t ret = GetP2pLinkReqParamByAuthHandle(authRequestId, info.requestId, &info, authHandle);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set p2p link param fail");
        goto FAIL;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifi direct connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
        info.requestId, info.connectType);
    ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "connect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, ret);
}

static void OnAuthConnOpenFailed(uint32_t authRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "guide channel failed. authRequestId=%{public}u, reason=%{public}d.", authRequestId, reason);
    GuideChannelAsyncRetry(ASYNC_RESULT_AUTH, authRequestId, reason);
}

static int32_t UpdateP2pLinkReq(P2pLinkReqList *p2pReqInfo, uint32_t laneReqId)
{
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get TransReqInfo fail, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_ERR;
    }
    if (reqInfo.isWithQos) {
        p2pReqInfo->p2pInfo.bandWidth = reqInfo.allocInfo.qosRequire.minBW;
        p2pReqInfo->p2pInfo.isWithQos = true;
    } else {
        p2pReqInfo->p2pInfo.bandWidth = 0;
        p2pReqInfo->p2pInfo.isWithQos = false;
    }
    LNN_LOGI(LNN_LANE, "wifi direct conn, bandWidth=%{public}d, isWithQos=%{public}d, laneReqId=%{public}u",
        p2pReqInfo->p2pInfo.bandWidth, p2pReqInfo->p2pInfo.isWithQos, laneReqId);
    return SOFTBUS_OK;
}

static int32_t AddP2pLinkReqItem(AsyncResultType type, uint32_t requestId, uint32_t laneReqId,
    const LinkRequest *request, const LaneLinkCb *callback)
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
    if (UpdateP2pLinkReq(item, laneReqId) != SOFTBUS_OK) {
        SoftBusFree(item);
        return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
    }
    item->laneRequestInfo.laneReqId = laneReqId;
    item->laneRequestInfo.pid = request->pid;
    item->auth.authHandle.authId = INVAILD_AUTH_ID;
    item->auth.requestId = (type == ASYNC_RESULT_AUTH ? requestId : 0);
    item->p2pInfo.p2pRequestId = (type == ASYNC_RESULT_P2P ? requestId : INVALID_P2P_REQUEST_ID);
    item->proxyChannelInfo.requestId = (type == ASYNC_RESULT_CHANNEL ? requestId : INVALID_CHANNEL_ID);
    item->p2pInfo.p2pModuleGenId = INVALID_P2P_REQUEST_ID;
    item->p2pInfo.networkDelegate = request->networkDelegate;
    item->p2pInfo.p2pOnly = request->p2pOnly;
    item->laneRequestInfo.linkType = request->linkType;
    if (LinkLock() != 0) {
        SoftBusFree(item);
        LNN_LOGE(LNN_LANE, "lock fail, add conn request fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(g_p2pLinkList, &item->node);
    LinkUnlock();
    return SOFTBUS_OK;
}

static int32_t UpdateP2pLinkedList(int32_t linkId, uint32_t authRequestId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_ERR;
    }
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->p2pModuleLinkId == linkId) {
            item->auth.requestId = authRequestId;
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    return SOFTBUS_ERR;
}

static int32_t OpenAuthToDisconnP2p(const char *networkId, int32_t linkId)
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
    if (UpdateP2pLinkedList(linkId, authRequestId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update linkedInfo fail");
        return SOFTBUS_ERR;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForDisconnect
    };
    LNN_LOGI(LNN_LANE, "open auth to disconnect WD, linkId=%{public}d, authRequestId=%{public}u",
        linkId, authRequestId);
    if (AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail, authRequestId=%{public}u", authRequestId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void OnProxyChannelOpened(int32_t channelRequestId, int32_t channelId)
{
    LNN_LOGI(LNN_LANE, "proxy opened. channelRequestId=%{public}d, channelId=%{public}d", channelRequestId, channelId);
    struct WifiDirectConnectInfo info;
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    info.negoChannel.type = NEGO_CHANNEL_COC;
    info.negoChannel.handle.channelId = channelId;

    int32_t ret = GetP2pLinkReqParamByChannelRequetId(channelRequestId, channelId, info.requestId, &info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link param fail");
        TransProxyPipelineCloseChannel(channelId);
        NotifyLinkFail(ASYNC_RESULT_CHANNEL, channelRequestId, ret);
        return;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifi direct connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
        info.requestId, info.connectType);
    ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "connect p2p device fail");
        NotifyLinkFail(ASYNC_RESULT_CHANNEL, channelRequestId, ret);
    }
}

static void OnProxyChannelOpenFailed(int32_t channelRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "guide channel failed. channelRequestId=%{public}d, reason=%{public}d.",
        channelRequestId, reason);
    GuideChannelAsyncRetry(ASYNC_RESULT_CHANNEL, (uint32_t)channelRequestId, reason);
}

static int32_t OpenProxyChannelToConnP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    LNN_LOGD(LNN_LANE, "enter");
    TransProxyPipelineChannelOption option = {
        .bleDirect = true,
    };
    ITransProxyPipelineCallback channelCallback = {
        .onChannelOpened = OnProxyChannelOpened,
        .onChannelOpenFailed = OnProxyChannelOpenFailed,
    };
    int32_t channelRequestId = TransProxyPipelineGenRequestId();
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_CHANNEL, (uint32_t)channelRequestId, laneReqId, request, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new connect node failed");
        return ret;
    }
    LNN_LOGI(LNN_LANE, "open proxy channel. channelRequestId=%{public}d", channelRequestId);
    ret = TransProxyPipelineOpenChannel(channelRequestId, request->peerNetworkId, &option, &channelCallback);
    if (ret != SOFTBUS_OK) {
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_CHANNEL, (uint32_t)channelRequestId);
        LNN_LOGE(LNN_LANE, "open channel failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OpenAuthToConnP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    int32_t ret = GetPreferAuth(request->peerNetworkId, &connInfo, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return ret;
    }
    uint32_t authRequestId = AuthGenRequestId();
    ret = AddP2pLinkReqItem(ASYNC_RESULT_AUTH, authRequestId, laneReqId, request, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "add new connect node failed");

    AuthConnCallback cb = {
        .onConnOpened = OnAuthConnOpened,
        .onConnOpenFailed = OnAuthConnOpenFailed
    };
    LNN_LOGI(LNN_LANE, "open auth with authRequestId=%{public}u", authRequestId);
    ret = AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authRequestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetAuthTriggerLinkReqParamByAuthHandle(uint32_t authRequestId, uint32_t p2pRequestId,
    struct WifiDirectConnectInfo *wifiDirectInfo, AuthHandle authHandle)
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
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        int32_t ret = strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
            item->laneRequestInfo.networkId);
        if (ret != EOK) {
            LNN_LOGE(LNN_LANE, "copy remote networkId fail");
            LinkUnlock();
            return SOFTBUS_MEM_ERR;
        }
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML;
        item->p2pInfo.p2pRequestId = p2pRequestId;
        item->auth.authHandle = authHandle;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
}

static void OnAuthTriggerConnOpened(uint32_t authRequestId, AuthHandle authHandle)
{
    LNN_LOGI(LNN_LANE, "auth trigger opened with authRequestId=%{public}u, authId=%{public}" PRId64 "",
        authRequestId, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_LANE, "authHandle type error");
        return;
    }
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    wifiDirectInfo.requestId = GetWifiDirectManager()->getRequestId();
    wifiDirectInfo.negoChannel.type = NEGO_CHANNEL_AUTH;
    wifiDirectInfo.negoChannel.handle.authHandle = authHandle;
    int32_t ret = GetAuthTriggerLinkReqParamByAuthHandle(authRequestId, wifiDirectInfo.requestId, &wifiDirectInfo,
        authHandle);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set auth trigger link param fail");
        goto FAIL;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifi direct connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    ret = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "auth trigger hml connect device err");
        goto FAIL;
    }
    return;
FAIL:
    NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, ret);
}

static int32_t OpenAuthTriggerToConn(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    int32_t ret = GetPreferAuth(request->peerNetworkId, &connInfo, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return ret;
    }
    uint32_t authRequestId = AuthGenRequestId();
    ret = AddP2pLinkReqItem(ASYNC_RESULT_AUTH, authRequestId, laneReqId, request, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new connect node failed");
        return ret;
    }

    AuthConnCallback cb = {
        .onConnOpened = OnAuthTriggerConnOpened,
        .onConnOpenFailed = OnAuthConnOpenFailed,
    };
    LNN_LOGI(LNN_LANE, "open auth trigger with authRequestId=%{public}u", authRequestId);
    ret = AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authRequestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t CheckTransReqInfo(const LinkRequest *request, uint32_t laneReqId)
{
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get TransReqInfo fail, laneReqId=%{public}u", laneReqId);
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

static int32_t OpenBleTriggerToConn(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    if (CheckTransReqInfo(request, laneReqId) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "ble trigger not support p2p");
        return SOFTBUS_INVALID_PARAM;
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
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, laneReqId, request, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "add new connect node failed");
    wifiDirectInfo.pid = request->pid;
    wifiDirectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    ret = strcpy_s(wifiDirectInfo.remoteNetworkId, NETWORK_ID_BUF_LEN, request->peerNetworkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "copy networkId failed");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return SOFTBUS_MEM_ERR;
    }
    wifiDirectInfo.isNetworkDelegate = request->networkDelegate;

    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifidirect connectDevice with p2pRequestId=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    ret = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble trigger connect device err");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static bool IsSupportHmlTwo(uint64_t local, uint64_t remote)
{
    if (((local & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0) || ((remote & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0)) {
        LNN_LOGE(LNN_LANE, "hml2.0 capa disable, local=%{public}" PRIu64 ", remote=%{public}" PRIu64, local, remote);
        return false;
    }
    return true;
}

static bool IsSupportWifiDirect(const char *networkId)
{
    uint64_t local = 0;
    uint64_t remote = 0;
    if (GetFeatureCap(networkId, &local, &remote) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return false;
    }
    return IsSupportHmlTwo(local, remote) && GetWifiDirectManager()->supportHmlTwo();
}

static bool CheckHasBrConnection(const char *networkId)
{
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt.type = CONNECT_BR;
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_BT_MAC, connOpt.brOption.brMac, BT_MAC_LEN) != SOFTBUS_OK ||
        connOpt.brOption.brMac[0] == '\0') {
        return false;
    }
    return CheckActiveConnection(&connOpt, true);
}

static bool IsHasAuthConnInfo(const char *networkId)
{
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return false;
    }
    if (AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_WIFI, false) ||
        AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_BR, true) ||
        AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_BLE, true)) {
        return true;
    }
    return false;
}

static bool IsSupportProxyNego(const char *networkId)
{
    uint64_t local = 0;
    uint64_t remote = 0;
    if (GetFeatureCap(networkId, &local, &remote) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return false;
    }
    return ((local & (1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY)) != 0) &&
        ((remote & (1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY)) != 0);
}

static int32_t ConnectWifiDirectWithReuse(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    wifiDirectInfo.requestId = GetWifiDirectManager()->getRequestId();
    wifiDirectInfo.pid = request->pid;
    wifiDirectInfo.connectType = GetWifiDirectManager()->supportHmlTwo() ?
        WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    if (strcpy_s(wifiDirectInfo.remoteNetworkId, NETWORK_ID_BUF_LEN, request->peerNetworkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "strcpy fail");
        return SOFTBUS_ERR;
    }
    if (LnnGetRemoteStrInfo(request->peerNetworkId, STRING_KEY_WIFIDIRECT_ADDR,
        wifiDirectInfo.remoteMac, sizeof(wifiDirectInfo.remoteMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote mac fail, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_ERR;
    }
    wifiDirectInfo.isNetworkDelegate = request->networkDelegate;
    if (AddP2pLinkReqItem(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, laneReqId, request, callback) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add p2plinkinfo fail, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_ERR;
    }
    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifidirect reuse connect with p2pRequestId=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    int32_t ret = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb);
    if (ret != SOFTBUS_OK) {
        NotifyLinkFail(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TryWifiDirectReuse(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    if (request->linkType != LANE_HML && request->linkType != LANE_P2P) {
        LNN_LOGE(LNN_LANE, "not support wifi direct reuse");
        return SOFTBUS_ERR;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(request->peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_ERR;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, request->linkType, &resourceItem) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "not find lane resource");
        return SOFTBUS_ERR;
    }
    if (GetWifiDirectManager()->isNegotiateChannelNeeded(request->peerNetworkId, WIFI_DIRECT_LINK_TYPE_HML)) {
        LNN_LOGE(LNN_LANE, "laneId=%{public}" PRIu64 " exist but need nego channel", resourceItem.laneId);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "wifidirect exist reuse link, laneId=%{public}" PRIu64 "", resourceItem.laneId);
    return ConnectWifiDirectWithReuse(request, laneReqId, callback);
}

static int32_t GetGuideChannelInfo(const char *networkId, LaneLinkType linkType, WdGuideType *guideList,
    uint32_t *linksNum)
{
    if (networkId == NULL || guideList == NULL || linksNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    *linksNum = 0;
    if (linkType == LANE_HML && IsSupportWifiDirect(networkId)) {
        if (IsHasAuthConnInfo(networkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_AUTH_TRIGGER;
        }
        guideList[(*linksNum)++] = LANE_BLE_TRIGGER;
        if (CheckHasBrConnection(networkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_BR_TRIGGER;
        }
        guideList[(*linksNum)++] = LANE_NEW_AUTH_TRIGGER;
    } else {
        if (IsHasAuthConnInfo(networkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_AUTH_NEGO;
        }
        if (CheckHasBrConnection(networkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_BR_NEGO;
        }
        if (IsSupportProxyNego(networkId)) {
            guideList[(*linksNum)++] = LANE_PROXY_AUTH_NEGO;
        }
        guideList[(*linksNum)++] = LANE_NEW_AUTH_NEGO;
    }
    return SOFTBUS_OK;
}

static bool GuideNodeIsExist(WdGuideInfo *guideInfo)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, guide node is exist fail.");
        return false;
    }
    WdGuideInfo *guideItem = NULL;
    WdGuideInfo *guideNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(guideItem, guideNext, g_guideInfoList, WdGuideInfo, node) {
        if (guideItem->laneReqId == guideInfo->laneReqId &&
            guideItem->request.linkType == guideInfo->request.linkType) {
            LinkUnlock();
            return true;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "guideInfo not found, laneReqId=%{public}u, linkType=%{public}d.",
        guideInfo->laneReqId, guideInfo->request.linkType);
    return false;
}

static int32_t AddGuideInfoItem(WdGuideInfo *guideInfo)
{
    if (GuideNodeIsExist(guideInfo)) {
        LNN_LOGI(LNN_LANE, "guideInfo is exist, laneReqId=%{public}u, linkType=%{public}d.",
            guideInfo->laneReqId, guideInfo->request.linkType);
        return SOFTBUS_OK;
    }
    WdGuideInfo *newItem = (WdGuideInfo *)SoftBusCalloc(sizeof(WdGuideInfo));
    if (newItem == NULL) {
        LNN_LOGE(LNN_LANE, "malloc newItem fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(newItem, sizeof(WdGuideInfo), guideInfo, sizeof(WdGuideInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "newItem memcpy fail.");
        SoftBusFree(newItem);
        return SOFTBUS_MEM_ERR;
    }
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, add guide info fail.");
        SoftBusFree(newItem);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(g_guideInfoList, &newItem->node);
    LinkUnlock();
    return SOFTBUS_OK;
}

static GuideLinkByType g_channelTable[LANE_CHANNEL_BUTT] = {
    [LANE_ACTIVE_AUTH_TRIGGER] = OpenAuthTriggerToConn,
    [LANE_ACTIVE_BR_TRIGGER] = OpenAuthTriggerToConn,
    [LANE_BLE_TRIGGER] = OpenBleTriggerToConn,
    [LANE_NEW_AUTH_TRIGGER] = OpenAuthTriggerToConn,
    [LANE_ACTIVE_AUTH_NEGO] = OpenAuthToConnP2p,
    [LANE_ACTIVE_BR_NEGO] = OpenAuthToConnP2p,
    [LANE_PROXY_AUTH_NEGO] = OpenProxyChannelToConnP2p,
    [LANE_NEW_AUTH_NEGO] = OpenAuthToConnP2p,
};

static int32_t LnnSelectDirectLink(uint32_t laneReqId, LaneLinkType linkType)
{
    WdGuideInfo guideInfo;
    (void)memset_s(&guideInfo, sizeof(WdGuideInfo), -1, sizeof(WdGuideInfo));
    if (GetGuideInfo(laneReqId, linkType, &guideInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get guide channel info fail.");
        return SOFTBUS_ERR;
    }
    if (guideInfo.guideIdx >= guideInfo.guideNum) {
        LNN_LOGE(LNN_LANE, "all guide channel type have been tried.");
        DelGuideInfoItem(laneReqId, linkType);
        return SOFTBUS_ERR;
    }
    WdGuideType guideType = guideInfo.guideList[guideInfo.guideIdx];
    LNN_LOGI(LNN_LANE, "build guide channel, laneReqId=%{public}u, guideType=%{public}d.", laneReqId, guideType);
    return g_channelTable[guideType](&guideInfo.request, laneReqId, &guideInfo.callback);
}

static int32_t GuideChannelSyncRetry(uint32_t laneReqId, LaneLinkType linkType)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, get guide channel info fail.");
        return SOFTBUS_LOCK_ERR;
    }
    WdGuideInfo *guideInfoNode = GetGuideNodeWithoutLock(laneReqId, linkType);
    if (guideInfoNode == NULL) {
        LNN_LOGE(LNN_LANE, "get guide info node fail.");
        LinkUnlock();
        return SOFTBUS_ERR;
    }
    guideInfoNode->guideIdx++;
    if (guideInfoNode->guideIdx >= guideInfoNode->guideNum) {
        LNN_LOGE(LNN_LANE, "all guide channel type have been tried.");
        if (guideInfoNode->callback.OnLaneLinkFail != NULL) {
            guideInfoNode->callback.OnLaneLinkFail(laneReqId, SOFTBUS_LANE_GUIDE_BUILD_FAIL, linkType);
        }
        LinkUnlock();
        DelGuideInfoItem(laneReqId, linkType);
        return SOFTBUS_ERR;
    }
    LinkUnlock();
    LNN_LOGI(LNN_LANE, "continue to select guide channel.");
    int32_t ret = LnnSelectDirectLink(laneReqId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "select direct link by qos fail.");
        ret = GuideChannelSyncRetry(laneReqId, linkType);
    }
    return ret;
}

static int32_t SelectGuideChannel(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    WdGuideType guideChannelList[LANE_CHANNEL_BUTT];
    (void)memset_s(guideChannelList, sizeof(guideChannelList), -1, sizeof(guideChannelList));
    uint32_t guideChannelNum = 0;
    if (GetGuideChannelInfo(request->peerNetworkId, request->linkType, guideChannelList,
        &guideChannelNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add guideChannelList faile, LinkType=%{public}d", request->linkType);
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < guideChannelNum; i++) {
        LNN_LOGI(LNN_LANE, "add guideChannelType=%{public}d", guideChannelList[i]);
    }
    WdGuideInfo guideInfo;
    (void)memset_s(&guideInfo, sizeof(WdGuideInfo), -1, sizeof(WdGuideInfo));
    guideInfo.laneReqId = laneReqId;
    if (memcpy_s(&guideInfo.request, sizeof(LinkRequest), request, sizeof(LinkRequest)) != EOK) {
        LNN_LOGE(LNN_LANE, "request memcpy fail.");
        return SOFTBUS_MEM_ERR;
    }
    guideInfo.callback = *callback;
    if (memcpy_s(guideInfo.guideList, sizeof(guideInfo.guideList),
        guideChannelList, sizeof(guideChannelList)) != EOK) {
        LNN_LOGE(LNN_LANE, "guideList memcpy fail.");
        return SOFTBUS_MEM_ERR;
    }
    guideInfo.guideNum = guideChannelNum;
    guideInfo.guideIdx = 0;
    if (AddGuideInfoItem(&guideInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add guide channel info fail.");
        return SOFTBUS_ERR;
    }
    int32_t ret = LnnSelectDirectLink(laneReqId, request->linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "select direct link by qos fail.");
        ret = GuideChannelSyncRetry(laneReqId, request->linkType);
    }
    return ret;
}

static void BuildGuideChannel(uint32_t laneReqId, LaneLinkType linkType)
{
    int32_t ret = LnnSelectDirectLink(laneReqId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "select direct link by qos fail.");
        (void)GuideChannelSyncRetry(laneReqId, linkType);
    }
}

static void GuideChannelTrigger(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LaneLinkType linkType = (LaneLinkType)msg->arg2;
    BuildGuideChannel(laneReqId, linkType);
}

static void P2pMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    switch (msg->what) {
        case MSG_TYPE_GUIDE_CHANNEL_TRIGGER:
            GuideChannelTrigger(msg);
            break;
        default:
            LNN_LOGE(LNN_LANE, "msg type=%{public}d cannot found", msg->what);
            break;
    }
    return;
}

static int32_t InitP2pLooper(void)
{
    g_p2pLoopHandler.name = "p2pLooper";
    g_p2pLoopHandler.HandleMessage = P2pMsgHandler;
    g_p2pLoopHandler.looper = GetLooper(LOOP_TYPE_LANE);
    if (g_p2pLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "init p2pLooper fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnP2pInit(void)
{
    if (InitP2pLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init looper fail");
        return SOFTBUS_ERR;
    }
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
    g_guideInfoList = (ListNode *)SoftBusMalloc(sizeof(ListNode));
    if (g_guideInfoList == NULL) {
        LNN_LOGE(LNN_LANE, "g_guideInfoList malloc fail.");
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        SoftBusFree(g_p2pLinkList);
        SoftBusFree(g_p2pLinkedList);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_p2pLinkList);
    ListInit(g_p2pLinkedList);
    ListInit(g_guideInfoList);
    return SOFTBUS_OK;
}

int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
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
        return OpenAuthToConnP2p(request, laneReqId, callback);
    }
    if (TryWifiDirectReuse(request, laneReqId, callback) == SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return SelectGuideChannel(request, laneReqId, callback);
}

static void DelP2pLinkedByLinkId(int32_t linkId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->p2pModuleLinkId == linkId) {
            LNN_LOGI(LNN_LANE, "delete p2plinkedItem, p2pModuleLinkId=%{public}d", linkId);
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    LinkUnlock();
}

void LnnDisconnectP2p(const char *networkId, uint32_t laneReqId)
{
    if (g_p2pLinkedList == NULL || g_p2pLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "lane link p2p not init, disconn request ignore");
        return;
    }
    char mac[MAX_MAC_LEN];
    int32_t linkId = -1;
    int32_t pid = -1;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, can't exec p2pDisconn");
        return;
    }
    bool isNodeExist = false;
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneReqId == laneReqId) {
            pid = item->pid;
            isNodeExist = true;
            linkId = item->p2pModuleLinkId;
            break;
        }
    }
    if (!isNodeExist) {
        LNN_LOGE(LNN_LANE, "node isn't exist, ignore disconn request, laneReqId=%{public}u", laneReqId);
        LinkUnlock();
        return;
    }
    LNN_LOGI(LNN_LANE, "disconnect wifidirect, laneReqId=%{public}u, linkId=%{public}d", laneReqId, linkId);
    if (strcpy_s(mac, MAX_MAC_LEN, item->remoteMac) != EOK) {
        LNN_LOGE(LNN_LANE, "mac addr cpy fail, disconn fail");
        LinkUnlock();
        return;
    }
    LinkUnlock();
    if (OpenAuthToDisconnP2p(networkId, linkId) != SOFTBUS_OK) {
        DisconnectP2pWithoutAuthConn(pid, mac, linkId);
        DelP2pLinkedByLinkId(linkId);
    }
}

void LnnDestroyP2p(void)
{
    if (g_p2pLinkList == NULL || g_p2pLinkedList == NULL || g_guideInfoList == NULL) {
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
    SoftBusFree(g_p2pLinkList);
    g_p2pLinkList = NULL;
    P2pLinkedList *linkedItem = NULL;
    P2pLinkedList *linkedNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(linkedItem, linkedNext, g_p2pLinkedList, P2pLinkedList, node) {
        ListDelete(&linkedItem->node);
        SoftBusFree(linkedItem);
    }
    SoftBusFree(g_p2pLinkedList);
    g_p2pLinkedList = NULL;
    WdGuideInfo *guideItem = NULL;
    WdGuideInfo *guideNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(guideItem, guideNext, g_guideInfoList, WdGuideInfo, node) {
        ListDelete(&guideItem->node);
        SoftBusFree(guideItem);
    }
    SoftBusFree(g_guideInfoList);
    g_guideInfoList = NULL;
    LinkUnlock();
    (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
}
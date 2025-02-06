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

#include "anonymizer.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link_conflict.h"
#include "lnn_lane_link_wifi_direct.h"
#include "lnn_lane_reliability.h"
#include "lnn_lane_vap_info.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
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
    bool isSupportIpv6;
    uint32_t laneReqId;
    int32_t pid;
    LaneLinkType linkType;
    LaneLinkCb cb;
} LaneLinkRequestInfo;

typedef struct {
    bool networkDelegate;
    bool p2pOnly;
    bool reuseOnly;
    uint32_t p2pRequestId;
    int32_t p2pModuleGenId;
    uint32_t actionAddr;
    uint32_t bandWidth;
    uint64_t triggerLinkTime;
    uint64_t availableLinkTime;
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
    char networkId[NETWORK_ID_BUF_LEN];
    char remoteMac[MAX_MAC_LEN];
    uint32_t laneReqId;
    int32_t pid;
    int32_t p2pModuleLinkId;
    uint32_t p2pLinkDownReqId;
    LaneLinkType linkType;
    AuthChannel auth;
    ListNode node;
} P2pLinkedList;

typedef struct {
    ListNode node;
    char peerIp[IP_LEN];
    bool isServer;
} AuthSessionServer;

typedef struct {
    ListNode node;
    LaneLinkInfo laneLinkInfo;
    uint32_t p2pRequestId;
    int32_t linkId;
    int32_t retryTime;
} RawLinkInfoList;

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
    MSG_TYPE_GUIDE_CHANNEL_SELECT,
    MSG_TYPE_GUIDE_CHANNEL_BUTT,
} GuideMsgType;

typedef enum {
    LANE_ACTIVE_AUTH_TRIGGER = 0x0,
    LANE_BLE_TRIGGER,
    LANE_ACTIVE_AUTH_NEGO,
    LANE_ACTIVE_BR_NEGO,
    LANE_PROXY_AUTH_NEGO,
    LANE_NEW_AUTH_NEGO,
    LANE_ACTION_TRIGGER,
    LANE_CHANNEL_BUTT,
} WdGuideType;

typedef enum {
    RAW_LINK_CHECK_INVALID = -1,
    RAW_LINK_CHECK_SUCCESS = 0,
    RAW_LINK_CHECK_RETRY = 1,
    RAW_LINK_CHECK_TIMEOUT = 2,
} CheckResultType;

typedef struct {
    uint32_t laneReqId;
    WdGuideType guideList[LANE_CHANNEL_BUTT];
    uint32_t guideNum;
    uint32_t guideIdx;
    LaneLinkCb callback;
    ListNode node;
    LinkRequest request;
} WdGuideInfo;

static ListNode *g_p2pLinkList = NULL; // process p2p link request
static ListNode *g_p2pLinkedList = NULL; // process p2p unlink request
static ListNode *g_guideInfoList = NULL;
static ListNode *g_rawLinkList = NULL;
static SoftBusMutex g_p2pLinkMutex;
static SoftBusHandler g_guideChannelHandler;
static ListNode *g_authSessionServerList = NULL;
static SoftBusMutex g_AuthTagLock;
static SoftBusMutex g_rawLinkLock;

#define INVAILD_AUTH_ID                (-1)
#define INVALID_P2P_REQUEST_ID         (-1)
#define LANE_REQ_ID_TYPE_SHIFT         28
#define SHORT_RANGE_PTK_NOT_MATCH_CODE 4
#define BLE_TRIGGER_TIMEOUT            5000
#define SOFTBUS_LNN_PTK_NOT_MATCH  (SOFTBUS_ERRNO(SHORT_DISTANCE_MAPPING_MODULE_CODE) + SHORT_RANGE_PTK_NOT_MATCH_CODE)
#define RAW_LINK_CHECK_DELAY           (200)
#define RAW_LINK_CHECK_NUM             (10)

#define DFX_RECORD_LNN_LANE_SELECT_END(lnnLaneId, lnnConnReqId)                    \
    do {                                                                           \
        LnnEventExtra extra = { 0 };                                               \
        LnnEventExtraInit(&extra);                                                 \
        extra.result = EVENT_STAGE_RESULT_OK;                                      \
        extra.laneId = (int32_t)(lnnLaneId);                                       \
        extra.connReqId = (int32_t)(lnnConnReqId);                                 \
        LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);        \
    } while (0)

typedef int32_t (*GuideLinkByType)(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback);

static int32_t LinkLock(void)
{
    return SoftBusMutexLock(&g_p2pLinkMutex);
}

static void LinkUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_p2pLinkMutex);
}

static int32_t AddAuthSessionFlag(const char *peerIp, bool isServer)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid peerIp");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_AuthTagLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return SOFTBUS_LOCK_ERR;
    }
    AuthSessionServer *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_authSessionServerList, AuthSessionServer, node) {
        if (strcmp(peerIp, item->peerIp) == 0) {
            item->isServer = isServer;
            LNN_LOGI(LNN_LANE, "exist server tag, new=%{public}d, old=%{public}d", isServer, item->isServer);
            SoftBusMutexUnlock(&g_AuthTagLock);
            return SOFTBUS_OK;
        }
    }
    char *anonyPeerIp = NULL;
    Anonymize(peerIp, &anonyPeerIp);
    LNN_LOGI(LNN_LANE, "not exist peerIp flag, add new one, peerIp=%{public}s", AnonymizeWrapper(anonyPeerIp));
    AnonymizeFree(anonyPeerIp);
    AuthSessionServer *sessionItem = (AuthSessionServer *)SoftBusCalloc(sizeof(AuthSessionServer));
    if (sessionItem == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        SoftBusMutexUnlock(&g_AuthTagLock);
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(sessionItem->peerIp, IP_LEN, peerIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerIp fail");
        SoftBusFree(sessionItem);
        SoftBusMutexUnlock(&g_AuthTagLock);
        return SOFTBUS_STRCPY_ERR;
    }
    sessionItem->isServer = isServer;
    ListTailInsert(g_authSessionServerList, &sessionItem->node);
    SoftBusMutexUnlock(&g_AuthTagLock);
    return SOFTBUS_OK;
}

int32_t CheckIsAuthSessionServer(const char *peerIp, bool *isServer)
{
    if (peerIp == NULL || isServer == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_AuthTagLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return SOFTBUS_LOCK_ERR;
    }
    AuthSessionServer *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_authSessionServerList, AuthSessionServer, node) {
        if (strcmp(peerIp, item->peerIp) == 0) {
            *isServer = item->isServer;
            LNN_LOGI(LNN_LANE, "get tag=%{public}d", *isServer);
            SoftBusMutexUnlock(&g_AuthTagLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_AuthTagLock);
    char *anonyIp = NULL;
    Anonymize(peerIp, &anonyIp);
    LNN_LOGW(LNN_LANE, "not find correct tag for %{public}s", AnonymizeWrapper(anonyIp));
    AnonymizeFree(anonyIp);
    return SOFTBUS_NOT_FIND;
}

int32_t RemoveAuthSessionServer(const char *peerIp)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_AuthTagLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return SOFTBUS_LOCK_ERR;
    }
    char *anonyIp = NULL;
    Anonymize(peerIp, &anonyIp);
    AuthSessionServer *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_authSessionServerList, AuthSessionServer, node) {
        if (strcmp(peerIp, item->peerIp) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
            LNN_LOGW(LNN_LANE, "remove it peerIp=%{public}s", AnonymizeWrapper(anonyIp));
            AnonymizeFree(anonyIp);
            SoftBusMutexUnlock(&g_AuthTagLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_AuthTagLock);
    LNN_LOGW(LNN_LANE, "not find correct tag, peerIp=%{public}s", AnonymizeWrapper(anonyIp));
    AnonymizeFree(anonyIp);
    return SOFTBUS_NOT_FIND;
}

static int32_t GetPreferAuthConnInfo(const char *networkId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    int32_t ret = AuthGetHmlConnInfo(uuid, connInfo, isMetaAuth);
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

static int32_t GetP2pLinkedReqByReqId(AsyncResultType type, uint32_t requestId, P2pLinkedList *info)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if ((type == ASYNC_RESULT_AUTH && item->auth.requestId == requestId) ||
            (type == ASYNC_RESULT_P2P && item->p2pLinkDownReqId == requestId)) {
            if (memcpy_s(info, sizeof(P2pLinkedList), item, sizeof(P2pLinkedList)) != EOK) {
                LNN_LOGE(LNN_LANE, "P2pLinkReq memcpy fail.");
                LinkUnlock();
                return SOFTBUS_MEM_ERR;
            }
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "P2pLinkedReq item not found, type=%{public}d, requestId=%{public}u.", type, requestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static void RecycleLinkedListResource(uint32_t requestId)
{
    if (LinkLock() != 0) {
        return;
    }
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
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
    P2pLinkedList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkedList), 0, sizeof(P2pLinkedList));
    if (GetP2pLinkedReqByReqId(ASYNC_RESULT_P2P, requestId, &reqInfo) == SOFTBUS_OK) {
        NotifyFreeLaneResult(reqInfo.laneReqId, SOFTBUS_OK);
    }
    RecycleLinkedListResource(requestId);
}

static void OnWifiDirectDisconnectFailure(uint32_t requestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "wifidirect linkDown fail, requestId=%{public}u, reason=%{public}d", requestId, reason);
    P2pLinkedList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkedList), 0, sizeof(P2pLinkedList));
    if (GetP2pLinkedReqByReqId(ASYNC_RESULT_P2P, requestId, &reqInfo) == SOFTBUS_OK) {
        NotifyFreeLaneResult(reqInfo.laneReqId, reason);
    }
    RecycleLinkedListResource(requestId);
}

static int32_t UpdateP2pLinkedReqByLinkId(int32_t linkId, uint32_t requestId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->p2pModuleLinkId == linkId) {
            item->p2pLinkDownReqId = requestId;
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "P2pLinkedReq item not found, linkId=%{public}d", linkId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t DisconnectP2pWithoutAuthConn(int32_t pid, int32_t linkId)
{
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.pid = pid;
    info.linkId = linkId;
    int32_t errCode = UpdateP2pLinkedReqByLinkId(linkId, info.requestId);
    if (errCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "updata p2pLinkedReq by linkId fail");
        return errCode;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGI(LNN_LANE, "disconnect wifiDirect, p2pRequestId=%{public}u, linkId=%{public}d", info.requestId, linkId);
    errCode = GetWifiDirectManager()->disconnectDevice(&info, &callback);
    if (errCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        return errCode;
    }
    return SOFTBUS_OK;
}

static void DisconnectSuccess(uint32_t requestId)
{
    LNN_LOGI(LNN_LANE, "wifidirect linkDown succ, requestId=%{public}u", requestId);
}

static void DisconnectFailure(uint32_t requestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "wifidirect linkDown fail, requestId=%{public}u, reason=%{public}d", requestId, reason);
}

static int32_t DisconnectP2pForLinkNotifyFail(int32_t pid, int32_t linkId)
{
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.pid = pid;
    info.linkId = linkId;
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = DisconnectSuccess,
        .onDisconnectFailure = DisconnectFailure,
    };
    LNN_LOGI(LNN_LANE, "disconnect wifiDirect, requestId=%{public}u, linkId=%{public}d", info.requestId, linkId);
    int32_t errCode = GetWifiDirectManager()->disconnectDevice(&info, &callback);
    if (errCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        return errCode;
    }
    return SOFTBUS_OK;
}

static int32_t GetP2pLinkDownParam(uint32_t authRequestId, uint32_t p2pRequestId,
    struct WifiDirectDisconnectInfo *wifiDirectInfo, AuthHandle authHandle)
{
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LNN_LOGI(LNN_LANE, "get wifidirect info when disconnect, authRequestId=%{public}u", authRequestId);
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
        LNN_LOGI(LNN_LANE, "get wifidirect info succ when disconnect, authRequestId=%{public}u", authRequestId);
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "get wifidirect info fail when disconnect, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
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
    LNN_LOGI(LNN_LANE, "auth open fail to disconnect wifidirect, authRequestId=%{public}u, reason=%{public}d",
        authRequestId, reason);
    int32_t errCode = SOFTBUS_LANE_GUIDE_BUILD_FAIL;
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    P2pLinkedList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkedList), 0, sizeof(P2pLinkedList));
    info.requestId = GetWifiDirectManager()->getRequestId();
    AuthHandle authHandle = { .authId = INVAILD_AUTH_ID };
    if (GetP2pLinkDownParam(authRequestId, info.requestId, &info, authHandle) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p linkdown param fail, authRequestId=%{public}u", authRequestId);
        goto FAIL;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGI(LNN_LANE, "disconnect wifiDirect, p2pRequestId=%{public}u, linkId=%{public}d",
        info.requestId, info.linkId);
    errCode = GetWifiDirectManager()->disconnectDevice(&info, &callback);
    if (errCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    if (GetP2pLinkedReqByReqId(ASYNC_RESULT_AUTH, authRequestId, &reqInfo) == SOFTBUS_OK) {
        NotifyFreeLaneResult(reqInfo.laneReqId, errCode);
    }
    DelP2pLinkedByAuthReqId(authRequestId);
}

static void OnConnOpenedForDisconnect(uint32_t authRequestId, AuthHandle authHandle)
{
    LNN_LOGI(LNN_LANE, "auth opened to disconnect wifidirect, authRequestId=%{public}u, authId=%{public}" PRId64 "",
        authRequestId, authHandle.authId);
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_LANE, "authHandle type error");
        return;
    }
    int32_t errCode = SOFTBUS_LANE_GUIDE_BUILD_FAIL;
    struct WifiDirectDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    P2pLinkedList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkedList), 0, sizeof(P2pLinkedList));
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    info.negoChannel.handle.authHandle = authHandle;
    if (GetP2pLinkDownParam(authRequestId, info.requestId, &info, authHandle) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p linkdown param fail, authRequestId=%{public}u", authRequestId);
        goto FAIL;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectDisconnectFailure,
    };
    LNN_LOGI(LNN_LANE, "disconnect wifidirect, p2pRequestId=%{public}u, linkId=%{public}d",
        info.requestId, info.linkId);
    errCode = GetWifiDirectManager()->disconnectDevice(&info, &callback);
    if (errCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "disconnect p2p device err");
        goto FAIL;
    }
    return;
FAIL:
    if (GetP2pLinkedReqByReqId(ASYNC_RESULT_AUTH, authRequestId, &reqInfo) == SOFTBUS_OK) {
        NotifyFreeLaneResult(reqInfo.laneReqId, errCode);
    }
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
    LNN_LOGI(LNN_LANE, "success, value=%{public}d", value);
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
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK || *remote == 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}" PRIu64, ret, *remote);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
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
        uint64_t currentTime = SoftBusGetSysTimeMs();
        if (currentTime >= item->p2pInfo.triggerLinkTime) {
            uint64_t costTime = currentTime - item->p2pInfo.triggerLinkTime;
            if (costTime >= item->p2pInfo.availableLinkTime) {
                LNN_LOGE(LNN_LANE, "no more time to build wifidirect");
                LinkUnlock();
                return SOFTBUS_LANE_BUILD_LINK_TIMEOUT;
            }
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        if (strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
            item->laneRequestInfo.networkId) != EOK) {
            LNN_LOGE(LNN_LANE, "copy networkId failed");
            LinkUnlock();
            return SOFTBUS_STRCPY_ERR;
        }
        wifiDirectInfo->ipAddrType = item->laneRequestInfo.isSupportIpv6 ? IPV6 : IPV4;
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
    return SOFTBUS_LANE_NOT_FOUND;
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
        item->p2pInfo.p2pRequestId = p2pRequestId;
        item->auth.authHandle = authHandle;
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
            wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        wifiDirectInfo->ipAddrType = item->laneRequestInfo.isSupportIpv6 ? IPV6 : IPV4;
        if (strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
            item->laneRequestInfo.networkId) != EOK) {
            LNN_LOGE(LNN_LANE, "copy networkId failed");
            LinkUnlock();
            return SOFTBUS_STRCPY_ERR;
        }
        wifiDirectInfo->bandWidth = item->p2pInfo.bandWidth;
        uint64_t currentTime = SoftBusGetSysTimeMs();
        if (currentTime >= item->p2pInfo.triggerLinkTime) {
            uint64_t costTime = currentTime - item->p2pInfo.triggerLinkTime;
            if (costTime >= item->p2pInfo.availableLinkTime) {
                LNN_LOGE(LNN_LANE, "no more time to build wifidirect");
                LinkUnlock();
                return SOFTBUS_LANE_BUILD_LINK_TIMEOUT;
            }
        }
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        wifiDirectInfo->connectType = item->laneRequestInfo.linkType == LANE_HML ?
            WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
        LinkUnlock();
        return SOFTBUS_OK;
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "request item not found, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
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
    return SOFTBUS_LANE_NOT_FOUND;
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
    return SOFTBUS_LANE_NOT_FOUND;
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

static int32_t GetCurrentGuideType(uint32_t laneReqId, LaneLinkType linkType, WdGuideType *guideType)
{
    WdGuideInfo guideInfo = { 0 };
    if (GetGuideInfo(laneReqId, linkType, &guideInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get guide channel info fail.");
        return SOFTBUS_LANE_NOT_FOUND;
    }
    *guideType = guideInfo.guideList[guideInfo.guideIdx];
    return SOFTBUS_OK;
}

static int32_t GetFirstGuideType(uint32_t laneReqId, LaneLinkType linkType, WdGuideType *guideType)
{
    WdGuideInfo guideInfo = { 0 };
    if (GetGuideInfo(laneReqId, linkType, &guideInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get guide channel info fail.");
        return SOFTBUS_LANE_NOT_FOUND;
    }
    *guideType = guideInfo.guideList[0];
    return SOFTBUS_OK;
}

static int32_t UpdateReason(const AuthLinkType authType, const WdGuideType guideType, int32_t reason)
{
    if (reason != SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT) {
        return reason;
    }
    if (guideType == LANE_BLE_TRIGGER) {
        return SOFTBUS_CONN_HV2_BLE_TRIGGER_TIMEOUT;
    }
    if (guideType == LANE_ACTIVE_AUTH_TRIGGER) {
        if (authType == AUTH_LINK_TYPE_WIFI) {
            return SOFTBUS_CONN_HV2_AUTH_WIFI_TRIGGER_TIMEOUT;
        }
        if (authType == AUTH_LINK_TYPE_BLE) {
            return SOFTBUS_CONN_HV2_AUTH_BLE_TRIGGER_TIMEOUT;
        }
        if (authType == AUTH_LINK_TYPE_BR) {
            return SOFTBUS_CONN_HV2_AUTH_BR_TRIGGER_TIMEOUT;
        }
    }
    return reason;
}

static void DfxReportWdResult(const P2pLinkReqList *reqInfo, const LaneLinkInfo *linkInfo,
    WdGuideType guideType, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    extra.errcode = reason;
    extra.laneReqId = (int32_t)reqInfo->laneRequestInfo.laneReqId;
    extra.guideType = (int32_t)guideType;
    if (reqInfo->p2pInfo.reuseOnly) {
        extra.isWifiDirectReuse = true;
    }
    if (linkInfo != NULL) {
        extra.bandWidth = (int32_t)linkInfo->linkInfo.p2p.bw;
    }
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
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
    WdGuideType guideType = LANE_CHANNEL_BUTT;
    int32_t result = GetFirstGuideType(reqInfo.laneRequestInfo.laneReqId, reqInfo.laneRequestInfo.linkType, &guideType);
    if (result == SOFTBUS_OK) {
        reason = UpdateReason(reqInfo.auth.authHandle.type, guideType, reason);
    }
    (void)DelP2pLinkReqByReqId(type, requestId);
    DelGuideInfoItem(reqInfo.laneRequestInfo.laneReqId, reqInfo.laneRequestInfo.linkType);
    if (reqInfo.laneRequestInfo.cb.onLaneLinkFail != NULL) {
        LNN_LOGI(LNN_LANE, "wifidirect conn fail, laneReqId=%{public}u, guideType=%{public}d, reason=%{public}d",
            reqInfo.laneRequestInfo.laneReqId, guideType, reason);
        reqInfo.laneRequestInfo.cb.onLaneLinkFail(reqInfo.laneRequestInfo.laneReqId, reason,
            reqInfo.laneRequestInfo.linkType);
    }
    if (reqInfo.auth.authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(reqInfo.auth.authHandle);
    }
    if (reqInfo.proxyChannelInfo.channelId > 0) {
        TransProxyPipelineCloseChannel(reqInfo.proxyChannelInfo.channelId);
    }
    DfxReportWdResult(&reqInfo, NULL, guideType, reason);
}

void NotifyLinkFailForForceDown(uint32_t requestId, int32_t reason)
{
    NotifyLinkFail(ASYNC_RESULT_P2P, requestId, reason);
}

static int32_t AddNewP2pLinkedInfo(const P2pLinkReqList *reqInfo, int32_t linkId, LaneLinkType linkType)
{
    P2pLinkedList *newNode = (P2pLinkedList *)SoftBusCalloc(sizeof(P2pLinkedList));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    newNode->p2pModuleLinkId = linkId;
    newNode->pid = reqInfo->laneRequestInfo.pid;
    newNode->laneReqId = reqInfo->laneRequestInfo.laneReqId;
    newNode->linkType = linkType;
    newNode->auth.authHandle.authId = INVAILD_AUTH_ID;
    newNode->auth.requestId = -1;
    newNode->p2pLinkDownReqId = -1;
    if (strcpy_s(newNode->networkId, sizeof(newNode->networkId), reqInfo->laneRequestInfo.networkId) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy networkId fail");
        SoftBusFree(newNode);
        return SOFTBUS_STRCPY_ERR;
    }
    if (LnnGetRemoteStrInfo(reqInfo->laneRequestInfo.networkId, STRING_KEY_P2P_MAC,
        newNode->remoteMac, sizeof(newNode->remoteMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote p2p mac fail");
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
    WdGuideType guideType = LANE_CHANNEL_BUTT;
    if (GetCurrentGuideType(reqInfo.laneRequestInfo.laneReqId, reqInfo.laneRequestInfo.linkType,
        &guideType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "not found current guide type, requestId=%{public}u", reqInfo.laneRequestInfo.laneReqId);
    }
    (void)DelP2pLinkReqByReqId(type, requestId);
    DelGuideInfoItem(reqInfo.laneRequestInfo.laneReqId, reqInfo.laneRequestInfo.linkType);
    LaneLinkType throryLinkType = reqInfo.laneRequestInfo.linkType;
    if (reqInfo.laneRequestInfo.linkType != linkInfo->type) {
        LNN_LOGI(LNN_LANE, "not return throry linkType=%{public}d, requestId=%{public}u", throryLinkType, requestId);
    }
    int32_t ret = AddNewP2pLinkedInfo(&reqInfo, linkId, linkInfo->type);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new p2p linked info fail, laneReqId=%{public}u", reqInfo.laneRequestInfo.laneReqId);
        if (reqInfo.laneRequestInfo.cb.onLaneLinkFail != NULL) {
            reqInfo.laneRequestInfo.cb.onLaneLinkFail(reqInfo.laneRequestInfo.laneReqId, ret, throryLinkType);
        }
    } else {
        if (reqInfo.laneRequestInfo.cb.onLaneLinkSuccess != NULL) {
            LNN_LOGI(LNN_LANE, "wifidirect conn succ, laneReqId=%{public}u, actual linkType=%{public}d, "
                "requestId=%{public}u, linkId=%{public}d",
                reqInfo.laneRequestInfo.laneReqId, linkInfo->type, requestId, linkId);
            reqInfo.laneRequestInfo.cb.onLaneLinkSuccess(reqInfo.laneRequestInfo.laneReqId, throryLinkType, linkInfo);
        }
    }
    if (reqInfo.auth.authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(reqInfo.auth.authHandle);
    }
    if (reqInfo.proxyChannelInfo.channelId > 0) {
        TransProxyPipelineCloseChannelDelay(reqInfo.proxyChannelInfo.channelId);
    }
    DfxReportWdResult(&reqInfo, linkInfo, guideType, SOFTBUS_OK);
}

static int32_t AddRawLinkInfo(uint32_t p2pRequestId, int32_t linkId, LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkInfo invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    RawLinkInfoList *rawLinkInfo = (RawLinkInfoList *)SoftBusCalloc(sizeof(RawLinkInfoList));
    if (rawLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "calloc rawLinkInfo fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&rawLinkInfo->laneLinkInfo, sizeof(LaneLinkInfo), linkInfo, sizeof(LaneLinkInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "linkInfo memcpy fail.");
        SoftBusFree(rawLinkInfo);
        return SOFTBUS_MEM_ERR;
    }
    rawLinkInfo->linkId = linkId;
    rawLinkInfo->p2pRequestId = p2pRequestId;
    rawLinkInfo->retryTime = RAW_LINK_CHECK_NUM;
    if (SoftBusMutexLock(&g_rawLinkLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail.");
        SoftBusFree(rawLinkInfo);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(g_rawLinkList, &rawLinkInfo->node);
    LNN_LOGI(LNN_LANE, "add rawLinkInfo success, requestId=%{public}u", p2pRequestId);
    SoftBusMutexUnlock(&g_rawLinkLock);
    return SOFTBUS_OK;
}

static int32_t GetRawLinkInfoByReqId(uint32_t p2pRequestId, RawLinkInfoList *rawLinkInfo)
{
    if (SoftBusMutexLock(&g_rawLinkLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    RawLinkInfoList *item = NULL;
    RawLinkInfoList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_rawLinkList, RawLinkInfoList, node) {
        if (item->p2pRequestId == p2pRequestId) {
            if (memcpy_s(rawLinkInfo, sizeof(RawLinkInfoList), item, sizeof(RawLinkInfoList)) != EOK) {
                LNN_LOGE(LNN_LANE, "raw link info memcpy fail.");
                SoftBusMutexUnlock(&g_rawLinkLock);
                return SOFTBUS_MEM_ERR;
            }
            SoftBusMutexUnlock(&g_rawLinkLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_rawLinkLock);
    LNN_LOGI(LNN_LANE, "raw link info not found, requestId=%{public}u.", p2pRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t DelRawLinkInfoByReqId(uint32_t p2pRequestId)
{
    if (SoftBusMutexLock(&g_rawLinkLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail.");
        return SOFTBUS_LOCK_ERR;
    }
    RawLinkInfoList *item = NULL;
    RawLinkInfoList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_rawLinkList, RawLinkInfoList, node) {
        if (item->p2pRequestId == p2pRequestId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            SoftBusMutexUnlock(&g_rawLinkLock);
            return SOFTBUS_OK;
        }
    }
    SoftBusMutexUnlock(&g_rawLinkLock);
    LNN_LOGI(LNN_LANE, "raw link info not found, requestId=%{public}u.", p2pRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
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
    bool isRaw = false;
    linkInfo->linkInfo.p2p.channel = link->channelId;
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    int32_t ret = GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &reqInfo);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (LnnGetRemoteStrInfo(reqInfo.laneRequestInfo.networkId, STRING_KEY_DEV_UDID,
        linkInfo->peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        isRaw = true;
    }

    if (isRaw) {
        linkInfo->type = LANE_HML_RAW;
        if (strcpy_s(linkInfo->linkInfo.rawWifiDirect.peerIp, IP_LEN, link->remoteIp) != EOK) {
            LNN_LOGE(LNN_LANE, "strcpy peerIp fail");
            return SOFTBUS_STRCPY_ERR;
        }
        if (strcpy_s(linkInfo->linkInfo.rawWifiDirect.localIp, IP_LEN, link->localIp) != EOK) {
            LNN_LOGE(LNN_LANE, "strcpy localIp fail");
            return SOFTBUS_STRCPY_ERR;
        }
        linkInfo->linkInfo.rawWifiDirect.port = link->remotePort;
        linkInfo->linkInfo.rawWifiDirect.isReuse = link->isReuse;
        linkInfo->linkInfo.rawWifiDirect.pid = reqInfo.laneRequestInfo.pid;
    } else {
        LNN_LOGI(LNN_LANE, "bandWidth=%{public}d", link->bandWidth);
        linkInfo->linkInfo.p2p.bw = (LaneBandwidth)link->bandWidth;
        if (strcpy_s(linkInfo->linkInfo.p2p.connInfo.localIp, IP_LEN, link->localIp) != EOK ||
            strcpy_s(linkInfo->linkInfo.p2p.connInfo.peerIp, IP_LEN, link->remoteIp) != EOK) {
            LNN_LOGE(LNN_LANE, "strcpy localIp fail");
            return SOFTBUS_STRCPY_ERR;
        }
        linkInfo->linkInfo.p2p.channel = link->channelId;
    }
    return SOFTBUS_OK;
}

static bool IsMetaAuthExist(const char *peerIp)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    connInfo.type = AUTH_LINK_TYPE_WIFI;
    if (strcpy_s(connInfo.info.ipInfo.ip, IP_LEN, peerIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerIp fail");
        return false;
    }
    bool isExist = false;
    if (AuthCheckMetaExist(&connInfo, &isExist) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check meta auth fail");
        return false;
    }
    LNN_LOGI(LNN_LANE, "meta auth isExist=%{public}d", isExist);
    return isExist;
}

static void HandleRawLinkResultWithoutLock(uint32_t p2pRequestId, int32_t reason)
{
    RawLinkInfoList rawLinkInfo;
    (void)memset_s(&rawLinkInfo, sizeof(RawLinkInfoList), 0, sizeof(RawLinkInfoList));
    int32_t ret = GetRawLinkInfoByReqId(p2pRequestId, &rawLinkInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get raw link info fail, requestId=%{public}u", p2pRequestId);
        NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, ret);
        DisconnectP2pForLinkNotifyFail(rawLinkInfo.laneLinkInfo.linkInfo.rawWifiDirect.pid, rawLinkInfo.linkId);
        return;
    }
    if (reason == SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "raw link info check succ, requestId=%{public}u", p2pRequestId);
        (void)AddAuthSessionFlag(rawLinkInfo.laneLinkInfo.linkInfo.rawWifiDirect.peerIp, false);
        NotifyLinkSucc(ASYNC_RESULT_P2P, rawLinkInfo.p2pRequestId, &rawLinkInfo.laneLinkInfo, rawLinkInfo.linkId);
        return;
    }
    LNN_LOGI(LNN_LANE, "raw link info check fail, requestId=%{public}u, reason=%{public}d",
        p2pRequestId, reason);
    NotifyLinkFail(ASYNC_RESULT_P2P, rawLinkInfo.p2pRequestId, reason);
    DisconnectP2pForLinkNotifyFail(rawLinkInfo.laneLinkInfo.linkInfo.rawWifiDirect.pid, rawLinkInfo.linkId);
}

static void HandleRawLinkResult(RawLinkInfoList *rawLinkInfo, int32_t reason)
{
    if (reason == SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "raw link info check succ, requestId=%{public}u", rawLinkInfo->p2pRequestId);
        (void)AddAuthSessionFlag(rawLinkInfo->laneLinkInfo.linkInfo.rawWifiDirect.peerIp, false);
        NotifyLinkSucc(ASYNC_RESULT_P2P, rawLinkInfo->p2pRequestId, &rawLinkInfo->laneLinkInfo, rawLinkInfo->linkId);
        return;
    }
    LNN_LOGI(LNN_LANE, "raw link info check fail, requestId=%{public}u, reason=%{public}d",
        rawLinkInfo->p2pRequestId, reason);
    NotifyLinkFail(ASYNC_RESULT_P2P, rawLinkInfo->p2pRequestId, reason);
    DisconnectP2pForLinkNotifyFail(rawLinkInfo->laneLinkInfo.linkInfo.rawWifiDirect.pid, rawLinkInfo->linkId);
}

static CheckResultType CheckAuthMetaResult(uint32_t p2pRequestId, RawLinkInfoList *rawLinkInfo)
{
    if (SoftBusMutexLock(&g_rawLinkLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail.");
        HandleRawLinkResultWithoutLock(p2pRequestId, SOFTBUS_LOCK_ERR);
        (void)DelRawLinkInfoByReqId(p2pRequestId);
        return RAW_LINK_CHECK_INVALID;
    }
    RawLinkInfoList *item = NULL;
    RawLinkInfoList *next = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_rawLinkList, RawLinkInfoList, node) {
        if (p2pRequestId == item->p2pRequestId) {
            if (memcpy_s(rawLinkInfo, sizeof(RawLinkInfoList), item, sizeof(RawLinkInfoList)) != EOK) {
                LNN_LOGE(LNN_LANE, "raw link info memcpy fail.");
                SoftBusMutexUnlock(&g_rawLinkLock);
                return RAW_LINK_CHECK_INVALID;
            }
            LNN_LOGI(LNN_LANE, "check raw link info, time=%{public}d", item->retryTime);
            bool isExist = IsMetaAuthExist(item->laneLinkInfo.linkInfo.rawWifiDirect.peerIp);
            if (isExist) {
                SoftBusMutexUnlock(&g_rawLinkLock);
                return RAW_LINK_CHECK_SUCCESS;
            }
            if (item->retryTime > 0) {
                item->retryTime--;
                SoftBusMutexUnlock(&g_rawLinkLock);
                return RAW_LINK_CHECK_RETRY;
            }
            if (item->retryTime <= 0) {
                SoftBusMutexUnlock(&g_rawLinkLock);
                return RAW_LINK_CHECK_TIMEOUT;
            }
        }
    }
    SoftBusMutexUnlock(&g_rawLinkLock);
    LNN_LOGI(LNN_LANE, "raw link info not found, requestId=%{public}u.", p2pRequestId);
    return RAW_LINK_CHECK_INVALID;
}

static void CheckRawLinkInfo(void *para)
{
    uint32_t *p2pRequestId = (uint32_t *)para;
    if (p2pRequestId == NULL) {
        LNN_LOGE(LNN_LANE, "para invalid");
        return;
    }
    RawLinkInfoList rawLinkInfo;
    (void)memset_s(&rawLinkInfo, sizeof(RawLinkInfoList), 0, sizeof(RawLinkInfoList));
    CheckResultType ret = CheckAuthMetaResult(*p2pRequestId, &rawLinkInfo);
    LNN_LOGI(LNN_LANE, "check raw link info, requestId=%{public}u, ret=%{public}d", *p2pRequestId, ret);
    if (ret == RAW_LINK_CHECK_SUCCESS) {
        HandleRawLinkResult(&rawLinkInfo, SOFTBUS_OK);
        (void)DelRawLinkInfoByReqId(*p2pRequestId);
        SoftBusFree(p2pRequestId);
        return;
    }
    if (ret == RAW_LINK_CHECK_RETRY) {
        if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_LNN), CheckRawLinkInfo, (void *)p2pRequestId,
                                        RAW_LINK_CHECK_DELAY) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "lnn async fail.");
            HandleRawLinkResult(&rawLinkInfo, SOFTBUS_LANE_ASYNC_FAIL);
            (void)DelRawLinkInfoByReqId(*p2pRequestId);
            SoftBusFree(p2pRequestId);
            return;
        }
        return;
    }
    if (ret == RAW_LINK_CHECK_TIMEOUT) {
        LNN_LOGI(LNN_LANE, "check raw link info time out");
        HandleRawLinkResult(&rawLinkInfo, SOFTBUS_OK);
        (void)DelRawLinkInfoByReqId(*p2pRequestId);
        SoftBusFree(p2pRequestId);
        return;
    }
    LNN_LOGI(LNN_LANE, "raw link info check fail, requestId=%{public}u", *p2pRequestId);
    HandleRawLinkResultWithoutLock(*p2pRequestId, ret);
    (void)DelRawLinkInfoByReqId(*p2pRequestId);
    SoftBusFree(p2pRequestId);
    return;
}

static int32_t NotifyRawLinkSucc(uint32_t p2pRequestId, const struct WifiDirectLink *link, LaneLinkInfo *linkInfo)
{
    if (IsMetaAuthExist(link->remoteIp)) {
        (void)AddAuthSessionFlag(link->remoteIp, false);
        NotifyLinkSucc(ASYNC_RESULT_P2P, p2pRequestId, linkInfo, link->linkId);
        return SOFTBUS_OK;
    }
    if (AddRawLinkInfo(p2pRequestId, link->linkId, linkInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkInfo memcpy fail.");
        return SOFTBUS_LANE_LIST_ERR;
    }

    uint32_t *requestId = (uint32_t *)SoftBusCalloc(sizeof(uint32_t));
    if (requestId == NULL) {
        LNN_LOGE(LNN_LANE, "calloc requestId fail");
        (void)DelRawLinkInfoByReqId(p2pRequestId);
        (void)AddAuthSessionFlag(link->remoteIp, false);
        NotifyLinkSucc(ASYNC_RESULT_P2P, p2pRequestId, linkInfo, link->linkId);
        return SOFTBUS_MALLOC_ERR;
    }
    *requestId = p2pRequestId;
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_LNN), CheckRawLinkInfo, (void *)requestId,
                                    RAW_LINK_CHECK_DELAY) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lnn async fail.");
        (void)DelRawLinkInfoByReqId(p2pRequestId);
        SoftBusFree(requestId);
        return SOFTBUS_LANE_ASYNC_FAIL;
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
    LNN_LOGI(LNN_LANE,
        "wifidirect conn succ, requestId=%{public}u, linkType=%{public}d, linkId=%{public}d, isReuse=%{public}d",
        p2pRequestId, linkInfo.type, link->linkId, link->isReuse);
    if (linkInfo.type == LANE_HML_RAW && link->isReuse) {
        ret = NotifyRawLinkSucc(p2pRequestId, link, &linkInfo);
        if (ret != SOFTBUS_OK && ret != SOFTBUS_MALLOC_ERR) {
            goto FAIL;
        }
    } else {
        if (linkInfo.type == LANE_HML_RAW) {
            (void)AddAuthSessionFlag(link->remoteIp, false);
        }
        NotifyLinkSucc(ASYNC_RESULT_P2P, p2pRequestId, &linkInfo, link->linkId);
    }
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
    msg->handler = &g_guideChannelHandler;
    msg->obj = NULL;
    g_guideChannelHandler.looper->PostMessage(g_guideChannelHandler.looper, msg);
    return SOFTBUS_OK;
}

static int32_t PostGuideChannelSelectMessage(uint32_t laneReqId, const P2pLinkReqList *p2pLinkReqInfo)
{
    LNN_LOGI(LNN_LANE, "post guide channel select msg.");
    if (p2pLinkReqInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    P2pLinkReqList *reqInfo = (P2pLinkReqList *)SoftBusCalloc(sizeof(P2pLinkReqList));
    if (reqInfo == NULL) {
        LNN_LOGE(LNN_LANE, "calloc reqInfo fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(reqInfo, sizeof(P2pLinkReqList), p2pLinkReqInfo, sizeof(P2pLinkReqList)) != EOK) {
        SoftBusFree(reqInfo);
        LNN_LOGE(LNN_LANE, "memcpy p2pLinkReqInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusFree(reqInfo);
        LNN_LOGE(LNN_LANE, "create handler msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = MSG_TYPE_GUIDE_CHANNEL_SELECT;
    msg->arg1 = laneReqId;
    msg->handler = &g_guideChannelHandler;
    msg->obj = reqInfo;
    g_guideChannelHandler.looper->PostMessage(g_guideChannelHandler.looper, msg);
    return SOFTBUS_OK;
}

static bool GuideNodeIsExist(uint32_t laneReqId, LaneLinkType linkType)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, guide node is exist fail.");
        return false;
    }
    WdGuideInfo *guideItem = NULL;
    WdGuideInfo *guideNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(guideItem, guideNext, g_guideInfoList, WdGuideInfo, node) {
        if (guideItem->laneReqId == laneReqId && guideItem->request.linkType == linkType) {
            LinkUnlock();
            return true;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "guideInfo not found, laneReqId=%{public}u, linkType=%{public}d.", laneReqId, linkType);
    return false;
}

static bool IsGuideChnanelReuseFail(bool reuseOnly, uint32_t laneReqId, LaneLinkType linkType)
{
    if (reuseOnly && !GuideNodeIsExist(laneReqId, linkType)) {
        return true;
    }
    return false;
}

static void HandleGuideChannelRetry(uint32_t laneReqId, LaneLinkType linkType, int32_t reason)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, get guide channel info fail.");
        return;
    }
    WdGuideInfo *guideInfoNode = GetGuideNodeWithoutLock(laneReqId, linkType);
    if (guideInfoNode == NULL) {
        LNN_LOGE(LNN_LANE, "get guide info node fail.");
        LinkUnlock();
        return;
    }
    LaneLinkCb callback = guideInfoNode->callback;
    guideInfoNode->guideIdx++;
    if (guideInfoNode->guideIdx >= guideInfoNode->guideNum) {
        LNN_LOGE(LNN_LANE, "all guide channel type have been tried.");
        LinkUnlock();
        goto FAIL;
    }
    LinkUnlock();
    LNN_LOGI(LNN_LANE, "continue to build next guide channel.");
    if (PostGuideChannelTriggerMessage(laneReqId, linkType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post guide channel trigger msg fail.");
        goto FAIL;
    }
    return;
FAIL:
    DelGuideInfoItem(laneReqId, linkType);
    callback.onLaneLinkFail(laneReqId, reason, linkType);
}

static void HandleGuideChannelAsyncFail(AsyncResultType type, uint32_t requestId, int32_t reason)
{
    P2pLinkReqList p2pLinkReqInfo;
    (void)memset_s(&p2pLinkReqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(type, requestId, &p2pLinkReqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link req fail, type=%{public}d, requestId=%{public}u", type, requestId);
        return;
    }
    (void)DelP2pLinkReqByReqId(type, requestId);
    bool reuseOnly = p2pLinkReqInfo.p2pInfo.reuseOnly;
    uint32_t laneReqId = p2pLinkReqInfo.laneRequestInfo.laneReqId;
    LaneLinkType linkType = p2pLinkReqInfo.laneRequestInfo.linkType;
    if (IsGuideChnanelReuseFail(reuseOnly, laneReqId, linkType)) {
        LNN_LOGI(LNN_LANE, "reuse fail, post guide channel select msg, laneReqId=%{public}u, linkType=%{public}d",
            laneReqId, linkType);
        (void)PostGuideChannelSelectMessage(laneReqId, &p2pLinkReqInfo);
        return;
    }
    LNN_LOGI(LNN_LANE, "handle guide channel async fail, type=%{public}d, laneReqId=%{public}u, linkType=%{public}d",
        type, laneReqId, linkType);
    HandleGuideChannelRetry(laneReqId, linkType, reason);
}

static int32_t HandleWifiDirectConflict(uint32_t p2pRequestId, LinkConflictType conflictType)
{
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2pLinkReq fail, type=%{public}d, requestId=%{public}u",
            ASYNC_RESULT_P2P, p2pRequestId);
        return SOFTBUS_LANE_NOT_FOUND;
    }
    int32_t ret = HandleForceDownWifiDirect(reqInfo.laneRequestInfo.networkId, conflictType, p2pRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "force disconnect wifidirect fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void HandleActionTriggerError(uint32_t p2pRequestId)
{
    P2pLinkReqList reqInfo = { 0 };
    if (GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2pLinkReq fail, type=%{public}d, requestId=%{public}u",
            ASYNC_RESULT_P2P, p2pRequestId);
        return;
    }
    WdGuideType guideType = LANE_CHANNEL_BUTT;
    if (GetCurrentGuideType(reqInfo.laneRequestInfo.laneReqId, reqInfo.laneRequestInfo.linkType,
        &guideType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "GetCurrentGuideType fail");
        return;
    }
    LNN_LOGI(LNN_LANE, "current guideType=%{public}d", guideType);
    if (guideType == LANE_ACTION_TRIGGER || guideType == LANE_BLE_TRIGGER) {
        (void)LnnRequestCheckOnlineStatus(reqInfo.laneRequestInfo.networkId, BLE_TRIGGER_TIMEOUT);
    }
}

static bool IsGuideChannelRetryErrcode(int32_t reason)
{
    if (reason == SOFTBUS_CONN_ACTION_SEND_DATA_FAIL ||
        reason == SOFTBUS_CONN_ACTION_STATUS_NO_ACK ||
        reason == SOFTBUS_CONN_ACTION_STATUS_CHBA_SYNC ||
        reason == SOFTBUS_CONN_AUTH_POST_DATA_FAILED ||
        reason == SOFTBUS_CONN_HV2_SEND_TRIGGER_MSG_FAILED ||
        reason == SOFTBUS_CONN_PV1_WAIT_CONNECT_RESPONSE_TIMEOUT ||
        reason == SOFTBUS_CONN_PV2_WAIT_CONNECT_RESPONSE_TIMEOUT ||
        reason == SOFTBUS_CONN_SOURCE_REUSE_LINK_FAILED) {
        return true;
    }
    return false;
}

static void OnWifiDirectConnectFailure(uint32_t p2pRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "wifidirect conn fail, requestId=%{public}u, reason=%{public}d", p2pRequestId, reason);
    if (reason == SOFTBUS_LNN_PTK_NOT_MATCH) {
        LNN_LOGE(LNN_LANE, "connect device fail due to ptk not match, requestId=%{public}u, reason=%{public}d",
            p2pRequestId, reason);
        reason = SOFTBUS_LANE_PTK_NOT_MATCH;
        P2pLinkReqList reqInfo;
        (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
        if (GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &reqInfo) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get p2p link req fail, type=%{public}d, requestId=%{public}d",
                ASYNC_RESULT_P2P, p2pRequestId);
            NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
            return;
        }
        int32_t ret = LnnSyncPtk(reqInfo.laneRequestInfo.networkId);
        LNN_LOGI(LNN_LANE, "syncptk done, ret=%{public}d", ret);
    }
    if (IsGuideChannelRetryErrcode(reason)) {
        LNN_LOGI(LNN_LANE, "guide channel retry, requestId=%{public}u, reason=%{public}d", p2pRequestId, reason);
        HandleGuideChannelAsyncFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
        return;
    }
    if (reason == SOFTBUS_CONN_HV3_WAIT_CONNECTION_TIMEOUT ||
        reason == SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT) {
        HandleActionTriggerError(p2pRequestId);
    }
    LinkConflictType conflictType = GetConflictTypeWithErrcode(reason);
    if (conflictType == CONFLICT_THREE_VAP || conflictType == CONFLICT_ROLE ||
        conflictType == CONFLICT_LINK_NUM_LIMITED) {
        int32_t ret = HandleWifiDirectConflict(p2pRequestId, conflictType);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "handle wifideirect conflict fail, reason=%{public}d", ret);
            NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
        }
        return;
    }
    NotifyLinkFail(ASYNC_RESULT_P2P, p2pRequestId, reason);
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
    info.reuseOnly = false;
    int32_t ret = GetP2pLinkReqParamByAuthHandle(authRequestId, info.requestId, &info, authHandle);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set p2p link param fail");
        goto FAIL;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .authRequestId = (int32_t)authRequestId,
        .connReqId = (int32_t)info.requestId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
    LNN_LOGI(LNN_LANE, "wifidirect connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
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
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authRequestId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link req fail, authRequestId=%{public}u", authRequestId);
        NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, reason);
        return;
    }
    bool isMetaAuth = GetAuthType(reqInfo.laneRequestInfo.networkId);
    if (isMetaAuth) {
        NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, reason);
        return;
    }
    HandleGuideChannelAsyncFail(ASYNC_RESULT_AUTH, authRequestId, reason);
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
        return SOFTBUS_STRCPY_ERR;
    }
    if (memcpy_s(&item->laneRequestInfo.cb, sizeof(LaneLinkCb), callback, sizeof(LaneLinkCb)) != EOK) {
        SoftBusFree(item);
        return SOFTBUS_MEM_ERR;
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
    item->p2pInfo.bandWidth = request->bandWidth;
    item->p2pInfo.triggerLinkTime = request->triggerLinkTime;
    item->p2pInfo.availableLinkTime = request->availableLinkTime;
    item->p2pInfo.reuseOnly = false;
    item->laneRequestInfo.isSupportIpv6 = request->isSupportIpv6 ? IPV6 : IPV4;
    item->p2pInfo.actionAddr = request->actionAddr;
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
        return SOFTBUS_LOCK_ERR;
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
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t OpenAuthToDisconnP2p(const char *networkId, int32_t linkId)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(networkId);
    int32_t ret = GetPreferAuthConnInfo(networkId, &connInfo, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return ret;
    }
    uint32_t authRequestId = AuthGenRequestId();
    ret = UpdateP2pLinkedList(linkId, authRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update linkedInfo fail");
        return ret;
    }
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForDisconnect,
    };
    LNN_LOGI(LNN_LANE, "open auth to disconnect wifidirect, linkId=%{public}d, authRequestId=%{public}u",
        linkId, authRequestId);
    ret = AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail, authRequestId=%{public}u", authRequestId);
        return ret;
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
    info.reuseOnly = false;
    int32_t ret = GetP2pLinkReqParamByChannelRequetId(channelRequestId, channelId, info.requestId, &info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p link param fail");
        TransProxyPipelineCloseChannel(channelId);
        NotifyLinkFail(ASYNC_RESULT_CHANNEL, (uint32_t)channelRequestId, ret);
        return;
    }

    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .chanReqId = channelRequestId,
        .connReqId = (int32_t)info.requestId,
        .connectionId = channelId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
    LNN_LOGI(LNN_LANE, "wifidirect connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
        info.requestId, info.connectType);
    ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "connect p2p device fail");
        NotifyLinkFail(ASYNC_RESULT_CHANNEL, (uint32_t)channelRequestId, ret);
    }
}

static void OnProxyChannelOpenFailed(int32_t channelRequestId, int32_t reason)
{
    LNN_LOGI(LNN_LANE, "guide channel failed. channelRequestId=%{public}d, reason=%{public}d.",
        channelRequestId, reason);
    HandleGuideChannelAsyncFail(ASYNC_RESULT_CHANNEL, (uint32_t)channelRequestId, reason);
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

    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .laneId = (int32_t)laneReqId,
        .chanReqId = channelRequestId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_START, extra);
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
        item->p2pInfo.p2pRequestId = p2pRequestId;
        item->auth.authHandle = authHandle;
        if (LnnGetRemoteStrInfo(item->laneRequestInfo.networkId, STRING_KEY_WIFIDIRECT_ADDR,
            wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
            LinkUnlock();
            LNN_LOGE(LNN_LANE, "get remote wifidirect addr fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
        wifiDirectInfo->bandWidth = item->p2pInfo.bandWidth;
        uint64_t currentTime = SoftBusGetSysTimeMs();
        if (currentTime >= item->p2pInfo.triggerLinkTime) {
            uint64_t costTime = currentTime - item->p2pInfo.triggerLinkTime;
            if (costTime >= item->p2pInfo.availableLinkTime) {
                LNN_LOGE(LNN_LANE, "no more time to build wifidirect");
                LinkUnlock();
                return SOFTBUS_LANE_BUILD_LINK_TIMEOUT;
            }
        }
        wifiDirectInfo->pid = item->laneRequestInfo.pid;
        int32_t ret = strcpy_s(wifiDirectInfo->remoteNetworkId, sizeof(wifiDirectInfo->remoteNetworkId),
            item->laneRequestInfo.networkId);
        if (ret != EOK) {
            LNN_LOGE(LNN_LANE, "copy remote networkId fail");
            LinkUnlock();
            return SOFTBUS_STRCPY_ERR;
        }
        wifiDirectInfo->bandWidth = (int32_t)item->p2pInfo.bandWidth;
        wifiDirectInfo->ipAddrType = item->laneRequestInfo.isSupportIpv6 ? IPV6 : IPV4;
        wifiDirectInfo->isNetworkDelegate = item->p2pInfo.networkDelegate;
        wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML;
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
    wifiDirectInfo.reuseOnly = false;
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
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .authRequestId = (int32_t)authRequestId,
        .connReqId = (int32_t)wifiDirectInfo.requestId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
    LNN_LOGI(LNN_LANE, "wifidirect connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
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

static int32_t UpdateP2pLinkInfoWithAuth(uint32_t authRequestId, AuthHandle authHandle)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    P2pLinkReqList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->auth.requestId == authRequestId) {
            item->auth.authHandle = authHandle;
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "not found p2p link with authRequestId=%{public}u", authRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t GetP2pLinkByLaneReqId(uint32_t laneReqId, P2pLinkReqList *info)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->laneRequestInfo.laneReqId == laneReqId) {
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
    return SOFTBUS_LANE_NOT_FOUND;
}

static void AuthChannelDetectSucc(uint32_t laneReqId, uint32_t authRequestId, AuthHandle authHandle)
{
    P2pLinkReqList p2pLinkReqInfo;
    (void)memset_s(&p2pLinkReqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkByLaneReqId(laneReqId, &p2pLinkReqInfo) != SOFTBUS_OK) {
        NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, SOFTBUS_LANE_GUIDE_BUILD_FAIL);
        return;
    }
    WdGuideInfo guideInfo;
    (void)memset_s(&guideInfo, sizeof(WdGuideInfo), -1, sizeof(WdGuideInfo));
    if (GetGuideInfo(laneReqId, p2pLinkReqInfo.laneRequestInfo.linkType, &guideInfo) != SOFTBUS_OK) {
        NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, SOFTBUS_LANE_GUIDE_BUILD_FAIL);
        return;
    }
    if (guideInfo.guideList[guideInfo.guideIdx] == LANE_ACTIVE_AUTH_TRIGGER) {
        OnAuthTriggerConnOpened(authRequestId, authHandle);
    } else {
        OnAuthConnOpened(authRequestId, authHandle);
    }
}

static void DetectSuccess(uint32_t laneReqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    P2pLinkReqList p2pLinkReqInfo;
    (void)memset_s(&p2pLinkReqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkByLaneReqId(laneReqId, &p2pLinkReqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p request fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .laneId = (int32_t)laneReqId,
        .authRequestId = (int32_t)p2pLinkReqInfo.auth.requestId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_START, extra);
    LNN_LOGI(LNN_LANE, "auth channel detect succ, laneReqId=%{public}u", laneReqId);
    AuthChannelDetectSucc(laneReqId, p2pLinkReqInfo.auth.requestId, p2pLinkReqInfo.auth.authHandle);
}

static void DetectFail(uint32_t laneReqId, int32_t reason, LaneLinkType linkType)
{
    P2pLinkReqList p2pLinkReqInfo;
    (void)memset_s(&p2pLinkReqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkByLaneReqId(laneReqId, &p2pLinkReqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2p request fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    LNN_LOGI(LNN_LANE, "auth channel detect fail, laneReqId=%{public}u", laneReqId);
    OnAuthConnOpenFailed(p2pLinkReqInfo.auth.requestId, reason);
}

static int32_t GetWlanInfo(const char *networkId, LaneLinkInfo *linkInfo)
{
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_WLAN_IP, linkInfo->linkInfo.wlan.connInfo.addr,
        sizeof(linkInfo->linkInfo.wlan.connInfo.addr)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote wlan ip fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    int32_t port;
    if (LnnGetRemoteNumInfo(networkId, NUM_KEY_SESSION_PORT, &port) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote wlan port fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    linkInfo->linkInfo.wlan.connInfo.port = (uint16_t)port;
    if (strncmp(linkInfo->linkInfo.wlan.connInfo.addr, "127.0.0.1", strlen("127.0.0.1")) == 0 ||
        linkInfo->linkInfo.wlan.connInfo.port == 0) {
        LNN_LOGE(LNN_LANE, "invaild addr or port");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static void GuideChannelDetect(uint32_t authRequestId, AuthHandle authHandle)
{
    P2pLinkReqList p2pLinkReqInfo;
    (void)memset_s(&p2pLinkReqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    if (GetP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authRequestId, &p2pLinkReqInfo) != SOFTBUS_OK) {
        NotifyLinkFail(ASYNC_RESULT_AUTH, authRequestId, SOFTBUS_LANE_GUIDE_BUILD_FAIL);
        return;
    }
    bool isMetaAuth = GetAuthType(p2pLinkReqInfo.laneRequestInfo.networkId);
    if (isMetaAuth) {
        OnAuthConnOpened(authRequestId, authHandle);
        return;
    }
    uint32_t laneReqId = p2pLinkReqInfo.laneRequestInfo.laneReqId;
    if (authHandle.type == AUTH_LINK_TYPE_WIFI) {
        LaneLinkInfo linkInfo;
        (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
        if (UpdateP2pLinkInfoWithAuth(authRequestId, authHandle) != SOFTBUS_OK ||
            GetWlanInfo(p2pLinkReqInfo.laneRequestInfo.networkId, &linkInfo) != SOFTBUS_OK) {
            AuthChannelDetectSucc(laneReqId, authRequestId, authHandle);
            return;
        }
        LaneLinkCb cb = {
            .onLaneLinkSuccess = DetectSuccess,
            .onLaneLinkFail = DetectFail,
        };
        linkInfo.type = LANE_WLAN_5G;
        LNN_LOGI(LNN_LANE, "auth channel need detect, laneReqId=%{public}u", laneReqId);
        if (LaneDetectReliability(laneReqId, &linkInfo, &cb) != SOFTBUS_OK) {
            DetectFail(laneReqId, SOFTBUS_LANE_DETECT_FAIL, linkInfo.type);
        }
        return;
    }
    LNN_LOGI(LNN_LANE, "auth channel no need detect, authRequestId=%{public}u", authRequestId);
    AuthChannelDetectSucc(laneReqId, authRequestId, authHandle);
}

static int32_t GetPreferAuthByType(const char *networkId, AuthLinkType type, AuthConnInfo *connInfo, bool isMetaAuth)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return AuthGetConnInfoByType(uuid, type, connInfo, isMetaAuth);
}

static int32_t GetAuthConnInfoWithoutMeta(const LinkRequest *request, uint32_t laneReqId,
    AuthConnInfo *connInfo, bool isMetaAuth)
{
    WdGuideType guideType = LANE_CHANNEL_BUTT;
    int32_t ret = GetCurrentGuideType(laneReqId, request->linkType, &guideType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get current guide channel info fail");
        return ret;
    }
    if (guideType == LANE_ACTIVE_BR_NEGO || guideType == LANE_NEW_AUTH_NEGO) {
        LNN_LOGI(LNN_LANE, "current guideType=%{public}d", guideType);
        ret = GetPreferAuthByType(request->peerNetworkId, AUTH_LINK_TYPE_BR, connInfo, isMetaAuth);
    } else {
        ret = GetPreferAuth(request->peerNetworkId, connInfo, isMetaAuth);
    }
    return ret;
}

static int32_t GetAuthConnInfo(const LinkRequest *request, uint32_t laneReqId, AuthConnInfo *connInfo, bool isMetaAuth)
{
    int32_t ret = SOFTBUS_LANE_NOT_FOUND;
    if (isMetaAuth) {
        ret = GetPreferAuth(request->peerNetworkId, connInfo, isMetaAuth);
    } else {
        ret = GetAuthConnInfoWithoutMeta(request, laneReqId, connInfo, isMetaAuth);
    }
    return ret;
}

static int32_t OpenAuthToConnP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    int32_t ret = GetAuthConnInfo(request, laneReqId, &connInfo, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return ret;
    }
    uint32_t authRequestId = AuthGenRequestId();
    ret = AddP2pLinkReqItem(ASYNC_RESULT_AUTH, authRequestId, laneReqId, request, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "add new connect node failed");

    AuthConnCallback cb = {
        .onConnOpened = GuideChannelDetect,
        .onConnOpenFailed = OnAuthConnOpenFailed,
    };
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .authRequestId = (int32_t)authRequestId,
        .laneId = (int32_t)laneReqId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_START, extra);
    LNN_LOGI(LNN_LANE, "open auth with authRequestId=%{public}u", authRequestId);
    ret = AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authRequestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OpenAuthTriggerToConn(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    int32_t ret = GetAuthConnInfo(request, laneReqId, &connInfo, isMetaAuth);
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
        .onConnOpened = GuideChannelDetect,
        .onConnOpenFailed = OnAuthConnOpenFailed,
    };
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .authRequestId = (int32_t)authRequestId,
        .laneId = (int32_t)laneReqId,
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_START, extra);
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
    int32_t ret = GetTransReqInfoByLaneReqId(laneReqId, &reqInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get TransReqInfo fail, laneReqId=%{public}u", laneReqId);
        return ret;
    }
    if (reqInfo.isWithQos) {
        if (request->linkType == LANE_P2P) {
            LNN_LOGE(LNN_LANE, "request linkType=%{public}d", request->linkType);
            return SOFTBUS_INVALID_PARAM;
        }
    } else {
        if (request->p2pOnly) {
            LNN_LOGE(LNN_LANE, "request p2pOnly=%{public}d", request->p2pOnly);
            return SOFTBUS_INVALID_PARAM;
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
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    wifiDirectInfo.bandWidth = request->bandWidth;
    uint64_t currentTime = SoftBusGetSysTimeMs();
    if (currentTime >= request->triggerLinkTime) {
        uint64_t costTime = currentTime - request->triggerLinkTime;
        if (costTime >= request->availableLinkTime) {
            LNN_LOGE(LNN_LANE, "no more time to build wifidirect");
            return SOFTBUS_LANE_BUILD_LINK_TIMEOUT;
        }
    }
    wifiDirectInfo.requestId = GetWifiDirectManager()->getRequestId();
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, laneReqId, request, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "add new connect node failed");
    wifiDirectInfo.pid = request->pid;
    wifiDirectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    wifiDirectInfo.reuseOnly = false;
    wifiDirectInfo.ipAddrType = request->isSupportIpv6 ? IPV6 : IPV4;
    if (strcpy_s(wifiDirectInfo.remoteNetworkId, NETWORK_ID_BUF_LEN, request->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId failed");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return SOFTBUS_STRCPY_ERR;
    }
    wifiDirectInfo.isNetworkDelegate = request->networkDelegate;

    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    DFX_RECORD_LNN_LANE_SELECT_END(laneReqId, wifiDirectInfo.requestId);
    LNN_LOGI(LNN_LANE, "wifidirect connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    ret = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble trigger connect device err");
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OpenActionToConn(const LinkRequest *request, uint32_t laneLinkReqId, const LaneLinkCb *callback)
{
    if (request == NULL || callback == NULL) {
        LNN_LOGE(LNN_LANE, "invalid null request or callback");
        return SOFTBUS_INVALID_PARAM;
    }
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneLinkReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        return SOFTBUS_NOT_FIND;
    }
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    wifiDirectInfo.requestId = GetWifiDirectManager()->getRequestId();
    int32_t errCode = AddP2pLinkReqItem(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, laneLinkReqId, request, callback);
    LNN_CHECK_AND_RETURN_RET_LOGE(errCode == SOFTBUS_OK, errCode, LNN_LANE, "add new connect node failed");
    wifiDirectInfo.pid = request->pid;
    wifiDirectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML;
    wifiDirectInfo.negoChannel.type = NEGO_CHANNEL_ACTION;
    wifiDirectInfo.negoChannel.handle.actionAddr = request->actionAddr;
    wifiDirectInfo.ipAddrType = request->isSupportIpv6 ? IPV6 : IPV4;
    wifiDirectInfo.bandWidth = (int32_t)reqInfo.allocInfo.qosRequire.minBW;
    if (strcpy_s(wifiDirectInfo.remoteNetworkId, NETWORK_ID_BUF_LEN, request->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId failed");
        DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return SOFTBUS_STRCPY_ERR;
    }
    wifiDirectInfo.isNetworkDelegate = request->networkDelegate;

    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    DFX_RECORD_LNN_LANE_SELECT_END(laneLinkReqId, wifiDirectInfo.requestId);
    LNN_LOGI(LNN_LANE, "wifi direct action connectDevice. p2pRequestId=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    errCode = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb);
    if (errCode != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "action trigger connect device err");
        DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return errCode;
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

static int32_t UpdateP2pReuseInfoByReqId(AsyncResultType type, uint32_t requestId)
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
            item->p2pInfo.reuseOnly = true;
            LinkUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkUnlock();
    LNN_LOGE(LNN_LANE, "P2pLinkReq item not found, type=%{public}d, requestId=%{public}u.", type, requestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t GetWifiDirectParamWithReuse(const LinkRequest *request, struct WifiDirectConnectInfo *wifiDirectInfo)
{
    wifiDirectInfo->requestId = GetWifiDirectManager()->getRequestId();
    wifiDirectInfo->pid = request->pid;
    if (request->linkType == LANE_HML) {
        if (request->actionAddr > 0) {
            wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML;
            wifiDirectInfo->negoChannel.type = NEGO_CHANNEL_ACTION;
            wifiDirectInfo->negoChannel.handle.actionAddr = request->actionAddr;
        } else {
            wifiDirectInfo->connectType = GetWifiDirectManager()->supportHmlTwo() ?
                WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
        }
    } else {
        wifiDirectInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    }
    wifiDirectInfo->reuseOnly = true;
    if (strcpy_s(wifiDirectInfo->remoteNetworkId, NETWORK_ID_BUF_LEN, request->peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (LnnGetRemoteStrInfo(request->peerNetworkId, STRING_KEY_WIFIDIRECT_ADDR,
        wifiDirectInfo->remoteMac, sizeof(wifiDirectInfo->remoteMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote mac fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    wifiDirectInfo->isNetworkDelegate = request->networkDelegate;
    wifiDirectInfo->ipAddrType = request->isSupportIpv6 ? IPV6 : IPV4;
    return SOFTBUS_OK;
}

static int32_t ConnectWifiDirectWithReuse(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    int32_t ret = GetWifiDirectParamWithReuse(request, &wifiDirectInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get wifidirect reuse param fail, laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
        return ret;
    }
    ret = AddP2pLinkReqItem(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, laneReqId, request, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add p2plinkinfo fail, laneReqId=%{public}u", laneReqId);
        return ret;
    }
    ret = UpdateP2pReuseInfoByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update p2p reuse info fail, laneReqId=%{public}u", laneReqId);
        return ret;
    }
    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    DFX_RECORD_LNN_LANE_SELECT_END(laneReqId, wifiDirectInfo.requestId);
    LNN_LOGI(LNN_LANE, "wifidirect reuse connect with p2pRequestId=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    ret = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb);
    if (ret != SOFTBUS_OK) {
        (void)DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, wifiDirectInfo.requestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TryWifiDirectReuse(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    if (request->linkType != LANE_HML && request->linkType != LANE_P2P) {
        LNN_LOGE(LNN_LANE, "not support wifidirect reuse");
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(request->peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    int32_t ret = FindLaneResourceByLinkType(peerUdid, request->linkType, &resourceItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "not find lane resource");
        return ret;
    }
    enum WifiDirectLinkType linkType = (request->linkType == LANE_HML) ? WIFI_DIRECT_LINK_TYPE_HML :
        WIFI_DIRECT_LINK_TYPE_P2P;
    LNN_LOGI(LNN_LANE, "ask wifidirect if need nego channel, linkType=%{public}d", linkType);
    if (GetWifiDirectManager()->isNegotiateChannelNeeded(request->peerNetworkId, linkType)) {
        LNN_LOGE(LNN_LANE, "laneId=%{public}" PRIu64 " exist but need nego channel", resourceItem.laneId);
        return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
    }
    LNN_LOGI(LNN_LANE, "wifidirect exist reuse link, laneId=%{public}" PRIu64 "", resourceItem.laneId);
    return ConnectWifiDirectWithReuse(request, laneReqId, callback);
}

static bool BrAuthIsMostPriority(const char *networkId)
{
    char uuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return false;
    }
    return ((!AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_WIFI, false)) &&
        AuthDeviceCheckConnInfo(uuid, AUTH_LINK_TYPE_BR, true));
}

static int32_t GetGuideChannelInfo(const LinkRequest *request, WdGuideType *guideList, uint32_t *linksNum)
{
    if (request == NULL || guideList == NULL || linksNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if ((request->linkType < 0) || (request->linkType >= LANE_LINK_TYPE_BUTT)) {
        LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", request->linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    *linksNum = 0;
    if ((request->linkType == LANE_HML || request->linkType == LANE_HML_RAW) && request->actionAddr > 0) {
        LNN_LOGI(LNN_LANE, "actionAddr is valid, value=%{public}u, linkType=%{public}d, add actionTrigger",
            request->actionAddr, request->linkType);
        guideList[(*linksNum)++] = LANE_ACTION_TRIGGER;
        return SOFTBUS_OK;
    }
    if (request->linkType == LANE_HML && IsSupportWifiDirect(request->peerNetworkId)) {
        if (IsHasAuthConnInfo(request->peerNetworkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_AUTH_TRIGGER;
        }
        guideList[(*linksNum)++] = LANE_BLE_TRIGGER;
    } else {
        if (IsHasAuthConnInfo(request->peerNetworkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_AUTH_NEGO;
        }
        if ((!BrAuthIsMostPriority(request->peerNetworkId)) && CheckHasBrConnection(request->peerNetworkId)) {
            guideList[(*linksNum)++] = LANE_ACTIVE_BR_NEGO;
        }
        if (IsSupportProxyNego(request->peerNetworkId)) {
            guideList[(*linksNum)++] = LANE_PROXY_AUTH_NEGO;
        }
        if ((!BrAuthIsMostPriority(request->peerNetworkId)) && (!CheckHasBrConnection(request->peerNetworkId))) {
            guideList[(*linksNum)++] = LANE_NEW_AUTH_NEGO;
        }
    }
    return SOFTBUS_OK;
}

static int32_t AddGuideInfoItem(WdGuideInfo *guideInfo)
{
    if (GuideNodeIsExist(guideInfo->laneReqId, guideInfo->request.linkType)) {
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
    [LANE_BLE_TRIGGER] = OpenBleTriggerToConn,
    [LANE_ACTIVE_AUTH_NEGO] = OpenAuthToConnP2p,
    [LANE_ACTIVE_BR_NEGO] = OpenAuthToConnP2p,
    [LANE_PROXY_AUTH_NEGO] = OpenProxyChannelToConnP2p,
    [LANE_NEW_AUTH_NEGO] = OpenAuthToConnP2p,
    [LANE_ACTION_TRIGGER] = OpenActionToConn,
};

static int32_t LnnSelectDirectLink(uint32_t laneReqId, LaneLinkType linkType)
{
    WdGuideInfo guideInfo;
    (void)memset_s(&guideInfo, sizeof(WdGuideInfo), -1, sizeof(WdGuideInfo));
    if (GetGuideInfo(laneReqId, linkType, &guideInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get guide channel info fail.");
        return SOFTBUS_LANE_NOT_FOUND;
    }
    if (guideInfo.guideIdx >= guideInfo.guideNum) {
        LNN_LOGE(LNN_LANE, "all guide channel type have been tried.");
        DelGuideInfoItem(laneReqId, linkType);
        return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
    }
    WdGuideType guideType = guideInfo.guideList[guideInfo.guideIdx];
    LNN_LOGI(LNN_LANE, "build guide channel, laneReqId=%{public}u, guideType=%{public}d.", laneReqId, guideType);
    return g_channelTable[guideType](&guideInfo.request, laneReqId, &guideInfo.callback);
}

static void BuildGuideChannel(uint32_t laneReqId, LaneLinkType linkType)
{
    int32_t ret = LnnSelectDirectLink(laneReqId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "handle guide channel sync fail, laneReqId=%{public}u", laneReqId);
        HandleGuideChannelRetry(laneReqId, linkType, ret);
    }
}

static int32_t SelectGuideChannel(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    WdGuideType guideChannelList[LANE_CHANNEL_BUTT];
    (void)memset_s(guideChannelList, sizeof(guideChannelList), -1, sizeof(guideChannelList));
    uint32_t guideChannelNum = 0;
    if (GetGuideChannelInfo(request, guideChannelList, &guideChannelNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add guideChannelList fail, LinkType=%{public}d", request->linkType);
        return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
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
        return SOFTBUS_LANE_LIST_ERR;
    }
    BuildGuideChannel(laneReqId, request->linkType);
    return SOFTBUS_OK;
}

static void GuideChannelTrigger(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LaneLinkType linkType = (LaneLinkType)msg->arg2;
    LNN_LOGI(LNN_LANE, "handle guide channel trigger msg, laneReqId=%{public}u", laneReqId);
    BuildGuideChannel(laneReqId, linkType);
}

static int32_t GetRequest(P2pLinkReqList *p2pLinkReqInfo, LinkRequest *request)
{
    if (strcpy_s(request->peerNetworkId, sizeof(request->peerNetworkId),
        p2pLinkReqInfo->laneRequestInfo.networkId) != EOK) {
        LNN_LOGE(LNN_LANE, "get peer networkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    request->networkDelegate = p2pLinkReqInfo->p2pInfo.networkDelegate;
    request->p2pOnly = p2pLinkReqInfo->p2pInfo.p2pOnly;
    request->linkType = p2pLinkReqInfo->laneRequestInfo.linkType;
    request->pid = p2pLinkReqInfo->laneRequestInfo.pid;
    request->bandWidth = p2pLinkReqInfo->p2pInfo.bandWidth;
    request->triggerLinkTime = p2pLinkReqInfo->p2pInfo.triggerLinkTime;
    request->availableLinkTime = p2pLinkReqInfo->p2pInfo.availableLinkTime;
    request->isSupportIpv6 = p2pLinkReqInfo->laneRequestInfo.isSupportIpv6 ? IPV6 : IPV4;
    return SOFTBUS_OK;
}

static void GuideChannelSelect(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj, laneReqId=%{public}u", laneReqId);
        return;
    }
    P2pLinkReqList *p2pLinkReqInfo = (P2pLinkReqList *)msg->obj;
    LinkRequest request = {0};
    if (GetRequest(p2pLinkReqInfo, &request) != SOFTBUS_OK) {
        SoftBusFree(p2pLinkReqInfo);
        LNN_LOGE(LNN_LANE, "get request fail");
        return;
    }
    LaneLinkCb callback = {0};
    if (memcpy_s(&callback, sizeof(LaneLinkCb), &p2pLinkReqInfo->laneRequestInfo.cb, sizeof(LaneLinkCb)) != EOK) {
        SoftBusFree(p2pLinkReqInfo);
        LNN_LOGE(LNN_LANE, "memcpy callback fail");
        return;
    }
    SoftBusFree(p2pLinkReqInfo);
    LNN_LOGI(LNN_LANE, "handle guide channel select msg, laneReqId=%{public}u", laneReqId);
    int32_t ret = SelectGuideChannel(&request, laneReqId, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "guide channel select fail, laneReqId=%{public}u", laneReqId);
        callback.onLaneLinkFail(laneReqId, ret, request.linkType);
    }
}

void RecycleP2pLinkedReqByLinkType(const char *peerNetworkId, LaneLinkType linkType)
{
    if (peerNetworkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (g_p2pLinkedList == NULL) {
        LNN_LOGE(LNN_LANE, "p2p not init");
        return;
    }
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    AuthHandle authHandle = { .authId = AUTH_INVALID_ID };
    P2pLinkedList *item = NULL;
    P2pLinkedList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkedList, P2pLinkedList, node) {
        if (strncmp(item->networkId, peerNetworkId, NETWORK_ID_BUF_LEN) == 0 &&
            item->linkType == linkType) {
            authHandle.authId = item->auth.authHandle.authId;
            authHandle.type = item->auth.authHandle.type;
            ListDelete(&item->node);
            SoftBusFree(item);
            if (authHandle.authId != INVAILD_AUTH_ID) {
                AuthCloseConn(authHandle);
            }
        }
    }
    LinkUnlock();
}

static int32_t GenerateWifiDirectNegoChannel(WdGuideType guideType, const P2pLinkReqList *reqInfo,
    struct WifiDirectConnectInfo *info)
{
    switch (guideType) {
        case LANE_ACTIVE_AUTH_NEGO:
        case LANE_ACTIVE_BR_NEGO:
        case LANE_NEW_AUTH_NEGO:
            info->negoChannel.type = NEGO_CHANNEL_AUTH;
            info->negoChannel.handle.authHandle = reqInfo->auth.authHandle;
            info->connectType = reqInfo->laneRequestInfo.linkType == LANE_HML ?
                WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
            break;
        case LANE_PROXY_AUTH_NEGO:
            info->negoChannel.type = NEGO_CHANNEL_COC;
            info->negoChannel.handle.channelId = reqInfo->proxyChannelInfo.channelId;
            info->connectType = reqInfo->laneRequestInfo.linkType == LANE_HML ?
                WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
            break;
        case LANE_ACTIVE_AUTH_TRIGGER:
            info->negoChannel.type = NEGO_CHANNEL_AUTH;
            info->negoChannel.handle.authHandle = reqInfo->auth.authHandle;
            info->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML;
            break;
        case LANE_BLE_TRIGGER:
            info->connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
            break;
        case LANE_ACTION_TRIGGER:
            info->connectType = WIFI_DIRECT_CONNECT_TYPE_ACTION_TRIGGER_HML;
            info->negoChannel.type = NEGO_CHANNEL_ACTION;
            info->negoChannel.handle.actionAddr = reqInfo->p2pInfo.actionAddr;
            break;
        default:
            LNN_LOGE(LNN_LANE, "not support guideType=%{public}d", guideType);
            return SOFTBUS_LANE_GUIDE_BUILD_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t GenerateWifiDirectInfo(const P2pLinkReqList *reqInfo, struct WifiDirectConnectInfo *info)
{
    if (reqInfo == NULL || info == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint64_t currentTime = SoftBusGetSysTimeMs();
    if (currentTime >= reqInfo->p2pInfo.triggerLinkTime) {
        uint64_t costTime = currentTime - reqInfo->p2pInfo.triggerLinkTime;
        if (costTime >= reqInfo->p2pInfo.availableLinkTime) {
            LNN_LOGE(LNN_LANE, "no more time to rebuild wifidirect");
            return SOFTBUS_LANE_BUILD_LINK_TIMEOUT;
        }
    }
    info->requestId = reqInfo->p2pInfo.p2pRequestId;
    info->reuseOnly = false;
    info->pid = reqInfo->laneRequestInfo.pid;
    info->bandWidth = reqInfo->p2pInfo.bandWidth;
    info->isNetworkDelegate = reqInfo->p2pInfo.networkDelegate;
    info->ipAddrType = reqInfo->laneRequestInfo.isSupportIpv6 ? IPV6 : IPV4;
    if (strcpy_s(info->remoteNetworkId, sizeof(info->remoteNetworkId), reqInfo->laneRequestInfo.networkId) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy remote networkId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    WdGuideInfo guideInfo;
    (void)memset_s(&guideInfo, sizeof(WdGuideInfo), -1, sizeof(WdGuideInfo));
    if (GetGuideInfo(reqInfo->laneRequestInfo.laneReqId, reqInfo->laneRequestInfo.linkType,
        &guideInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get guide channel info fail.");
        return SOFTBUS_LANE_NOT_FOUND;
    }
    WdGuideType guideType = guideInfo.guideList[guideInfo.guideIdx];
    if (guideType == LANE_ACTIVE_AUTH_NEGO || guideType == LANE_PROXY_AUTH_NEGO ||
        guideType == LANE_ACTIVE_AUTH_TRIGGER) {
        if (LnnGetRemoteStrInfo(reqInfo->laneRequestInfo.networkId, STRING_KEY_WIFIDIRECT_ADDR,
            info->remoteMac, sizeof(info->remoteMac)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get remote wifidirect addr fail");
            return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        }
    }
    int32_t ret = GenerateWifiDirectNegoChannel(guideType, reqInfo, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "genarate wifidirect nego channel fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t WifiDirectReconnectDevice(uint32_t p2pRequestId)
{
    P2pLinkReqList reqInfo;
    (void)memset_s(&reqInfo, sizeof(P2pLinkReqList), 0, sizeof(P2pLinkReqList));
    int32_t ret = GetP2pLinkReqByReqId(ASYNC_RESULT_P2P, p2pRequestId, &reqInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get p2pLinkReq fail, type=%{public}d, requestId=%{public}u",
            ASYNC_RESULT_P2P, p2pRequestId);
        return ret;
    }
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    ret = GenerateWifiDirectInfo(&reqInfo, &wifiDirectInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ganarate wifidirect info fail, reason=%{public}d", ret);
        return ret;
    }
    struct WifiDirectConnectCallback cb = {
        .onConnectSuccess = OnWifiDirectConnectSuccess,
        .onConnectFailure = OnWifiDirectConnectFailure,
    };
    LNN_LOGI(LNN_LANE, "wifidirect reconnectDevice. p2pRequest=%{public}u, connectType=%{public}d",
        wifiDirectInfo.requestId, wifiDirectInfo.connectType);
    ret = GetWifiDirectManager()->connectDevice(&wifiDirectInfo, &cb);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifidirect reconnectDevice fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void GuideChannelMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    switch (msg->what) {
        case MSG_TYPE_GUIDE_CHANNEL_TRIGGER:
            GuideChannelTrigger(msg);
            break;
        case MSG_TYPE_GUIDE_CHANNEL_SELECT:
            GuideChannelSelect(msg);
            break;
        default:
            LNN_LOGE(LNN_LANE, "msg type=%{public}d cannot found", msg->what);
            break;
    }
    return;
}

static int32_t InitGuideChannelLooper(void)
{
    g_guideChannelHandler.name = "GuideChannelHandler";
    g_guideChannelHandler.HandleMessage = GuideChannelMsgHandler;
    g_guideChannelHandler.looper = GetLooper(LOOP_TYPE_LNN);
    if (g_guideChannelHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "init p2pLooper fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

static int32_t InitWifiDirectInfo(void)
{
    if (SoftBusMutexInit(&g_AuthTagLock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    g_authSessionServerList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_authSessionServerList == NULL) {
        LNN_LOGE(LNN_LANE, "g_authSessionServerList calloc fail.");
        (void)SoftBusMutexDestroy(&g_AuthTagLock);
        return SOFTBUS_MALLOC_ERR;
    }
    g_rawLinkList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_rawLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "g_rawLinkList calloc fail.");
        (void)SoftBusMutexDestroy(&g_AuthTagLock);
        SoftBusFree(g_authSessionServerList);
        return SOFTBUS_MALLOC_ERR;
    }
    if (SoftBusMutexInit(&g_rawLinkLock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "mutex init fail");
        (void)SoftBusMutexDestroy(&g_AuthTagLock);
        SoftBusFree(g_authSessionServerList);
        SoftBusFree(g_rawLinkList);
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

static int32_t LnnP2pInit(void)
{
    if (InitGuideChannelLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init looper fail");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexInit(&g_p2pLinkMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    g_p2pLinkList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_p2pLinkList == NULL) {
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    g_p2pLinkedList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_p2pLinkedList == NULL) {
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        SoftBusFree(g_p2pLinkList);
        return SOFTBUS_MALLOC_ERR;
    }
    g_guideInfoList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_guideInfoList == NULL) {
        LNN_LOGE(LNN_LANE, "g_guideInfoList malloc fail.");
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        SoftBusFree(g_p2pLinkList);
        SoftBusFree(g_p2pLinkedList);
        return SOFTBUS_MALLOC_ERR;
    }
    if (InitWifiDirectInfo() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init wifidirect info fail.");
        (void)SoftBusMutexDestroy(&g_p2pLinkMutex);
        SoftBusFree(g_p2pLinkList);
        SoftBusFree(g_p2pLinkedList);
        SoftBusFree(g_guideInfoList);
        return SOFTBUS_NO_INIT;
    }
    ListInit(g_p2pLinkList);
    ListInit(g_p2pLinkedList);
    ListInit(g_guideInfoList);
    ListInit(g_authSessionServerList);
    ListInit(g_rawLinkList);
    return SOFTBUS_OK;
}

static void DumpHmlPreferChannel(const LinkRequest *request)
{
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(request->peerNetworkId, STRING_KEY_DEV_UDID,
        udid, sizeof(udid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid err");
        return;
    }
    int32_t preferChannel = 0;
    int32_t ret = LnnGetRecommendChannel(udid, &preferChannel);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get recommend channel fail, ret=%{public}d", ret);
        return;
    }
    LNN_LOGI(LNN_LANE, "[HML]prefer channel=%{public}d", preferChannel);
}

int32_t LnnConnectP2p(const LinkRequest *request, uint32_t laneReqId, const LaneLinkCb *callback)
{
    if (request == NULL || callback == NULL) {
        LNN_LOGE(LNN_LANE, "invalid null request or callback");
        return SOFTBUS_INVALID_PARAM;
    }
    DumpHmlPreferChannel(request);
    if (g_p2pLinkList == NULL) {
        int32_t ret = LnnP2pInit();
        LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_LANE, "p2p not init");
    }
    bool isMetaAuth = GetAuthType(request->peerNetworkId);
    if (isMetaAuth && request->actionAddr <= 0) {
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

void LnnDisconnectP2pWithoutLnn(uint32_t laneReqId)
{
    if (g_p2pLinkedList == NULL) {
        LNN_LOGE(LNN_LANE, "lane link p2p not init, disconn request ignore");
        return;
    }
    char mac[MAX_MAC_LEN] = {0};
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
    DisconnectP2pWithoutAuthConn(pid, linkId);
    DelP2pLinkedByLinkId(linkId);
}

int32_t LnnDisconnectP2p(const char *networkId, uint32_t laneReqId)
{
    if (g_p2pLinkedList == NULL || g_p2pLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "lane link p2p not init, disconn request ignore");
        return SOFTBUS_INVALID_PARAM;
    }
    char mac[MAX_MAC_LEN] = {0};
    int32_t linkId = -1;
    int32_t pid = -1;
    LaneLinkType linkType = LANE_LINK_TYPE_BUTT;
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "lock fail, can't exec p2pDisconn");
        return SOFTBUS_LOCK_ERR;
    }
    bool isNodeExist = false;
    P2pLinkedList *item = NULL;
    LIST_FOR_EACH_ENTRY(item, g_p2pLinkedList, P2pLinkedList, node) {
        if (item->laneReqId == laneReqId) {
            pid = item->pid;
            isNodeExist = true;
            linkId = item->p2pModuleLinkId;
            linkType = item->linkType;
            break;
        }
    }
    if (!isNodeExist) {
        LNN_LOGE(LNN_LANE, "node isn't exist, ignore disconn request, laneReqId=%{public}u", laneReqId);
        LinkUnlock();
        return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
    }
    LNN_LOGI(LNN_LANE, "disconnect wifidirect, laneReqId=%{public}u, linkId=%{public}d, linkType=%{public}d",
        laneReqId, linkId, linkType);
    if (strcpy_s(mac, MAX_MAC_LEN, item->remoteMac) != EOK) {
        LNN_LOGE(LNN_LANE, "mac addr cpy fail, disconn fail");
        LinkUnlock();
        return SOFTBUS_STRCPY_ERR;
    }
    LinkUnlock();
    enum WifiDirectLinkType type = (linkType == LANE_P2P) ? WIFI_DIRECT_LINK_TYPE_P2P : WIFI_DIRECT_LINK_TYPE_HML;
    if (linkType == LANE_HML_RAW || !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, type) ||
        OpenAuthToDisconnP2p(networkId, linkId) != SOFTBUS_OK) {
        int32_t errCode = DisconnectP2pWithoutAuthConn(pid, linkId);
        if (errCode != SOFTBUS_OK) {
            DelP2pLinkedByLinkId(linkId);
            return errCode;
        }
    }
    return SOFTBUS_OK;
}

static void LnnDestroyP2pLinkInfo(void)
{
    if (g_p2pLinkList == NULL || g_p2pLinkedList == NULL || g_guideInfoList == NULL) {
        LNN_LOGE(LNN_LANE, "wifi direct info not init");
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

static void LnnDestroyWifiDirectInfo(void)
{
    if (g_authSessionServerList == NULL || g_rawLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "wifi direct info not init");
        return;
    }
    if (SoftBusMutexLock(&g_AuthTagLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock session list fail");
        return;
    }
    AuthSessionServer *sessionItem = NULL;
    AuthSessionServer *sessionNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(sessionItem, sessionNext, g_authSessionServerList, AuthSessionServer, node) {
        ListDelete(&sessionItem->node);
        SoftBusFree(sessionItem);
    }
    SoftBusMutexUnlock(&g_AuthTagLock);
    SoftBusFree(g_authSessionServerList);
    g_authSessionServerList = NULL;
    (void)SoftBusMutexDestroy(&g_AuthTagLock);

    if (SoftBusMutexLock(&g_rawLinkLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return;
    }
    RawLinkInfoList *rawLinkItem = NULL;
    RawLinkInfoList *rawLinkNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(rawLinkItem, rawLinkNext, g_rawLinkList, RawLinkInfoList, node) {
        ListDelete(&rawLinkItem->node);
        SoftBusFree(rawLinkItem);
    }
    SoftBusFree(g_rawLinkList);
    g_rawLinkList = NULL;
    SoftBusMutexUnlock(&g_rawLinkLock);
    (void)SoftBusMutexDestroy(&g_rawLinkLock);
}

void LnnDestroyP2p(void)
{
    LnnDestroyP2pLinkInfo();
    LnnDestroyWifiDirectInfo();
}

void LnnCancelWifiDirect(uint32_t laneReqId)
{
    if (LinkLock() != 0) {
        LNN_LOGE(LNN_LANE, "link lock fail");
        return;
    }
    struct WifiDirectConnectInfo wifiDirectInfo;
    (void)memset_s(&wifiDirectInfo, sizeof(wifiDirectInfo), 0, sizeof(wifiDirectInfo));
    bool isNodeExist = false;
    uint32_t invalidP2pReqId = INVALID_P2P_REQUEST_ID;
    P2pLinkReqList *item = NULL;
    P2pLinkReqList *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_p2pLinkList, P2pLinkReqList, node) {
        if (item->laneRequestInfo.laneReqId == laneReqId && item->p2pInfo.p2pRequestId != invalidP2pReqId) {
            wifiDirectInfo.requestId = item->p2pInfo.p2pRequestId;
            wifiDirectInfo.pid = item->laneRequestInfo.pid;
            isNodeExist = true;
            break;
        }
    }
    LinkUnlock();
    if (!isNodeExist) {
        LNN_LOGI(LNN_LANE, "not build wifidirect, no need cancel, laneRequestId=%{public}u.", laneReqId);
        return;
    }
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr == NULL || mgr->cancelConnectDevice == NULL) {
        LNN_LOGE(LNN_LANE, "get wifiDirect manager null");
        return;
    }
    LNN_LOGI(LNN_LANE, "cancel wifidirect request, p2pRequestId=%{public}u.", wifiDirectInfo.requestId);
    int32_t ret = mgr->cancelConnectDevice(&wifiDirectInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "cancel wifidirect request fail, p2pRequestId=%{public}u, reason=%{public}d.",
            wifiDirectInfo.requestId, ret);
        return;
    }
    NotifyLinkFail(ASYNC_RESULT_P2P, wifiDirectInfo.requestId, SOFTBUS_LANE_BUILD_LINK_FAIL);
}

static void HandlePtkNotMatch(const char *remoteNetworkId, uint32_t len, int32_t result)
{
    if (remoteNetworkId == NULL || len == 0 || len > NETWORK_ID_BUF_LEN) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(remoteNetworkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "handle ptk not match, networkId=%{public}s, result=%{public}d",
        AnonymizeWrapper(anonyNetworkId), result);
    AnonymizeFree(anonyNetworkId);
    if (LnnSyncPtk(remoteNetworkId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "sync ptk fail");
        return;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(remoteNetworkId, STRING_KEY_DEV_UDID, peerUdid, sizeof(peerUdid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer udid fail");
        return;
    }
    LnnEventExtra extra = {0};
    LnnEventExtraInit(&extra);
    extra.result = SOFTBUS_LANE_PTK_NOT_MATCH;
    extra.peerUdid = peerUdid;
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
}

int32_t LnnInitPtkSyncListener(void)
{
    struct WifiDirectManager *pManager = GetWifiDirectManager();
    if (pManager == NULL) {
        LNN_LOGE(LNN_LANE, "get wifi direct manager fail");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pManager->addPtkMismatchListener == NULL) {
        LNN_LOGE(LNN_LANE, "addPtkMismatchListener null");
        return SOFTBUS_INVALID_PARAM;
    }
    pManager->addPtkMismatchListener(HandlePtkNotMatch);
    return SOFTBUS_OK;
}

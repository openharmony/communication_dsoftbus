/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_wifi_direct_link.h"

#include <securec.h>
#include "auth_interface.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_common.h"
#include "lnn_lane_guide_link.h"
#include "lnn_log.h"
#include "wifi_direct_manager.h"

typedef struct {
    LnnWDRequestInfo requestInfo;
    LaneLinkCb cb;
} InputInfo;

typedef struct {
    uint32_t authRequestId;
    int32_t guideRequestId;
    uint32_t connRequestId;
    AuthHandle currentMetaAuth;
    LaneGuideLinkInfo currentGuideInfo;
} ConnInfo;

typedef struct {
    int32_t linkId;
    int32_t bandWidth;
    char localIp[IP_LEN];
    char remoteIp[IP_LEN];
    int32_t port;
} OutputInfo;

typedef struct {
    ListNode node;
    uint32_t laneRequestId;
    InputInfo in;
    ConnInfo conn;
    OutputInfo out;
} WDLinkRequest;

static ListNode *g_linkRequestList = NULL;
static SoftBusMutex g_laneMutex;

static int32_t LaneMutexLock(void)
{
    if ((void *)g_laneMutex == NULL) {
        LNN_LOGW(LNN_LANE, "laneMutex not init");
        if (SoftBusMutexInit(&g_laneMutex, NULL) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "laneMutex init fail");
            return SOFTBUS_LOCK_ERR;
        }
    }
    return SoftBusMutexLock(&g_laneMutex);
}

static void LaneMutexUnlock(void)
{
    int32_t ret = SoftBusMutexUnlock(&g_laneMutex);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "laneMutex unlock fail=%{public}d", ret);
        return;
    }
}

static void LaneMutexDestroy(void)
{
    (void)SoftBusMutexDestroy(&g_laneMutex);
}

static bool IsSupportWifiDirectEnhance(const char *networkId)
{
    uint64_t local = 0;
    uint64_t remote = 0;
    if (LnnGetSupportFeature(networkId, &local, &remote) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get support feature error");
        return false;
    }
    if (((local & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0) || ((remote & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0)) {
        LNN_LOGE(LNN_LANE, "localFeature=%{public}" PRIu64 ", remoteFeature=%{public}" PRIu64, local, remote);
        return false;
    }
    return true;
}

static bool IsMetaOnline(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "getOnlineType fail, ret=%{public}d", ret);
        return false;
    }
    return ((1 << ONLINE_METANODE) == value);
}

static int32_t GetMetaAuth(const char *networkId, AuthConnInfo *connInfo)
{
    char uuid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, uuid, sizeof(uuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return AuthGetPreferConnInfo(uuid, connInfo, true);
}

static int32_t GetRequestObjByConnRequestId(uint32_t connRequestId, WDLinkRequest *request)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->conn.connRequestId == connRequestId) {
            if (memcpy_s(request, sizeof(WDLinkRequest), requestItem, sizeof(WDLinkRequest)) != EOK) {
                ret = SOFTBUS_MEM_ERR;
            }
            LaneMutexUnlock();
            return ret;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "not find node, connRequestId=%{public}u", connRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t GetLaneRequestIdByConnRequestId(uint32_t connRequestId, uint32_t *laneRequestId)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->conn.connRequestId == connRequestId) {
            *laneRequestId = requestItem.laneRequestId;
            LaneMutexUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "not find node, connRequestId=%{public}u", connRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t GetLaneRequestIdByAuthRequestId(uint32_t authRequestId, uint32_t *laneRequestId)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->in.authRequestId == authRequestId) {
            *laneRequestId = requestItem.laneRequestId;
            LaneMutexUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "not find node, authRequestId=%{public}u", authRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t GetLaneRequestIdByGuideRequestId(uint32_t guideRequestId, uint32_t *laneRequestId)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->conn.guideRequestId == guideRequestId) {
            *laneRequestId = requestItem.laneRequestId;
            LaneMutexUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "not find node, guideRequestId=%{public}d", guideRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t SetOutputInfo(const struct WifiDirectLink *link, OutputInfo *out)
{
    out->linkId = link->linkId;
    if (strcpy_s(out->localIp, IP_LEN, link->localIp) != EOK ||
        strcpy_s(out->remoteIp, IP_LEN, link->remoteIp) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    out->port = link->remotePort;
    return SOFTBUS_OK;
}

static void DetectLinkResult(LaneLinkType preferLink, LaneLinkType realityLink)
{
    if (preferLink != realityLink) {
        LNN_LOGW(LNN_LANE, "preferLink=%{public}d, but realityLink=%{public}d", preferLink, realityLink);
    }
}

static int32_t ProcWDLinkInfo(uint32_t laneRequestId, const struct WifiDirectLink *link, LaneLinkInfo *linkInfo)
{
    if (link->linkType == WIFI_DIRECT_LINK_TYPE_HML) {
        linkInfo->type = LANE_HML;
    } else {
        linkInfo->type = LANE_P2P;
    }
    linkInfo->linkInfo.p2p.bw = LANE_BW_RANDOM;
    if (strcpy_s(linkInfo->linkInfo.p2p.connInfo.localIp, IP_LEN, link->localIp) != EOK ||
        strcpy_s(linkInfo->linkInfo.p2p.connInfo.peerIp, IP_LEN, link->remoteIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy localIp fail");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->laneRequestId == laneRequestId) {
            DetectLinkResult(requestItem->in.requestInfo.linkType, linkInfo->type);
            if (LnnGetRemoteStrInfo(requestItem->in.requestInfo.peerNetworkId, STRING_KEY_DEV_UDID,
                linkInfo->peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "get udid error");
                LaneMutexUnlock();
                return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
            }
            ret = SetOutputInfo(link, requestItem->out);
            LaneMutexUnlock();
            return ret;
        }
    }
    LaneMutexUnlock();
    return SOFTBUS_OK;
}

static void NotifyLinkSucc(uint32_t laneRequestId, LaneLinkInfo *linkInfo)
{
    LNN_LOGI(LNN_LANE, "laneRequestId=%{public}u", laneRequestId);
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return;
    }
    bool isNodeExist = false;
    LaneLinkCb cb;
    LaneLinkType linkType;
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->laneRequestId == laneRequestId) {
            cb = requestItem->in.cb;
            linkType = requestItem->in.requestInfo.linkType;
            isNodeExist = true;
            break;
        }
    }
    LaneMutexUnlock();
    if (!isNodeExist) {
        LNN_LOGE(LNN_LANE, "node not found, laneRequestId=%{public}u", laneRequestId);
        return;
    }
    if (cb.onLaneLinkSuccess != NULL) {
        cb.onLaneLinkSuccess(laneRequestId, linkType, linkInfo);
    }
}

static void NotifyLinkFail(uint32_t laneRequestId, int32_t errcode)
{
    LNN_LOGI(LNN_LANE, "laneRequestId=%{public}u, reason=%{public}d", laneRequestId, errcode);
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return;
    }
    bool isNodeExist = false;
    LaneLinkCb cb;
    LaneLinkType linkType;
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->laneRequestId == laneRequestId) {
            cb = requestItem->in.cb;
            linkType = requestItem->in.requestInfo.linkType;
            ListDelete(&requestItem->node);
            SoftBusFree(requestItem);
            isNodeExist = true;
            break;
        }
    }
    LaneMutexUnlock();
    if (!isNodeExist) {
        LNN_LOGE(LNN_LANE, "node not found, laneRequestId=%{public}u", laneRequestId);
        return;
    }
    if (cb.onLaneLinkFail != NULL) {
        cb.onLaneLinkFail(laneRequestId, errcode, linkType);
    }
}

static void ConnectSuccessByMetaAuth(uint32_t connRequestId, const struct WifiDirectLink *link)
{
    uint32_t laneRequestId = 0;
    WDLinkRequest requestObj;
    (void)memset_s(&requestObj, sizeof(WDLinkRequest), 0, sizeof(WDLinkRequest));
    int32_t ret = GetRequestObjByConnRequestId(connRequestId, &requestObj);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "node not found, need proc link_recycle, connRequestId=%{public}d", connRequestId);
        // warn: proc link recycle
        return;
    }
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "WD link is null, connRequestId=%{publiuc}u", connRequestId);
        ret = SOFTBUS_INVALID_PARAM;
        goto FAIL;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    ret = ProcWDLinkInfo(requestObj.laneRequestId, link, &linkInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create link info err, ret=%{public}d", ret);
        goto FAIL;
    }
    AuthCloseConn(requestObj.conn.currentMetaAuth);
    NotifyLinkSucc(requestObj.laneRequestId, &linkInfo);
    return;
FAIL:
    AuthCloseConn(requestObj.conn.currentMetaAuth);
    NotifyLinkFail(requestObj.laneRequestId, ret);
}

static void ConnectFailureByMetaAuth(uint32_t connRequestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "WD conn fail, connRequestId=%{public}u, reason=%{public}d", connRequestId, reason);
    uint32_t laneRequestId = 0;
    int32_t ret = GetLaneRequestIdByConnRequestId(connRequestId, &laneRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "node not found, ret=%{public}d", ret);
        return;
    }
    AuthCloseConn();
    NotifyLinkFail(laneRequestId, reason);
}

static int32_t SetWifiDirectCommParam(WDLinkRequest *request, struct WifiDirectConnectInfo *connInfo)
{
    if (LnnGetRemoteStrInfo(request->in.requestInfo.peerNetworkId, STRING_KEY_P2P_MAC,
        connInfo->remoteMac, sizeof(connInfo->remoteMac)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote WD mac fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    connInfo->pid = request->in.requestInfo.pid;
    if (strcpy_s(connInfo->remoteNetworkId, sizeof(connInfo->remoteNetworkId),
        request->in.requestInfo.peerNetworkId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy networkId failed");
        return SOFTBUS_STRCPY_ERR;
    }
    connInfo->bandWidth = request->in.requestInfo.bandWidth;
    connInfo->isNetworkDelegate = request->in.requestInfo.isNetworkDelegate;
}

static int32_t SetWifiDirectNegoParam(WDLinkRequest *request, struct WifiDirectConnectInfo *connInfo)
{
    connInfo->connectType = (request->in.requestInfo.linkType == LANE_HML) ?
        WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML : WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    return SetWifiDirectCommParam(request, connInfo);
}

static int32_t ProcMetaAuthWifiDirectParam(uint32_t authRequestId, uint32_t connRequestId,
    struct WifiDirectConnectInfo *connInfo, AuthHandle authHandle)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->conn.authRequestId == authRequestId) {
            requestItem->conn.connRequestId = connRequestId;
            requestItem->conn.currentMetaAuth = authHandle;
            ret = SetWifiDirectNegoParam(requestItem, connInfo);
            LaneMutexUnlock();
            return ret;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "node not found, authRequestId=%{public}d", authRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t ProcWifiDirectByMetaAuth(uint32_t authRequestId, AuthHandle authHandle)
{
    struct WifiDirectConnectInfo info;
    info.requestId = GetWifiDirectManager()->getRequestId();
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    info.negoChannel.handle.authHandle = authHandle;
    int32_t ret = ProcMetaAuthWifiDirectParam(authRequestId, info.requestId, &info, authHandle);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set WD link param fail=%{public}d", ret);
        return ret;
    }
    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = ConnectSuccessByMetaAuth,
        .onConnectFailure = ConnectFailureByMetaAuth,
    };
    LNN_LOGI(LNN_LANE, "WD connRequestId=%{public}u, connectType=%{public}d",
        info.requestId, info.connectType);
    ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "WD connect err=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void MetaAuthConnOpened(uint32_t authRequestId, AuthHandle authHandle)
{
    LNN_LOGI(LNN_LANE, "mataAuth opened, authRequestId=%{public}u, authId=%{public}" PRId64 "",
        authRequestId, authHandle.authId);
    int32_t ret = SOFTBUS_OK;
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        LNN_LOGE(LNN_LANE, "authLink type exception=%{public}d", authHandle.type);
        ret = SOFTBUS_INVALID_PARAM;
        goto FAIL;
    }
    ret = ProcWifiDirectByMetaAuth(authRequestId, authHandle);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "WD by metaAuth fail=%{public}d", ret);
        goto FAIL;
    }
    return;
FAIL:
    AuthCloseConn(authHandle);
    uint32_t laneRequestId = 0;
    if (GetLaneRequestIdByAuthRequestId(authRequestId, &laneRequestId) != SOFTBUS_OK) {
        return;
    }
    NotifyLinkFail(laneRequestId, ret);
}

static void MetaAuthConnFailed(uint32_t authRequestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "authRequestId=%{public}u, reason=%{public}d", authRequestId, reason);
    uint32_t laneRequestId = 0;
    if (GetLaneRequestIdByAuthRequestId(authRequestId, &laneRequestId) != SOFTBUS_OK) {
        return;
    }
    NotifyLinkFail(laneRequestId, reason);
}

static int32_t UpdateMetaAuthRequestId(uint32_t laneRequestId, uint32_t authRequestId)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->laneRequestId == laneRequestId) {
            requestItem->conn.authRequestId = authRequestId;
            LaneMutexUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "node not found, laneRequestId=%{public}d, authRequestId=%{public}d",
        laneRequestId, authRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t BuildLinkByMetaAuth(uint32_t requestId, const LnnWDRequestInfo *request)
{
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = GetMetaAuth(request->peerNetworkId, &connInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no metaAuth conn exist");
        return ret;
    }
    uint32_t authRequestId = AuthGenRequestId();
    AuthConnCallback cb = {
        .onConnOpened = MetaAuthConnOpened,
        .onConnOpenFailed = MetaAuthConnFailed,
    };
    LNN_LOGI(LNN_LANE, "open metaAuth with authRequestId=%{public}u", authRequestId);
    ret = UpdateMetaAuthRequestId(requestId, authRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update metaAuth requestId fail=%{public}d", ret);
        return ret;
    }
    ret = AuthOpenConn(&connInfo, authRequestId, &cb, true);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open metaAuth conn fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void PreferGuideLinkFail(int32_t guideRequestId, int32_t errCode)
{
    LNN_LOGE(LNN_LANE, "guideRequestId=%{public}d, errcode=%{public}d", guideRequestId, errCode);
    uint32_t laneRequestId = 0;
    if (GetLaneRequestIdByGuideRequestId(guideRequestId, &laneRequestId) != SOFTBUS_OK) {
        LNN_LOGW(LNN_LANE, "node not found, ignore result, guideRequestId=%{public}d", guideRequestId);
        return;
    }
    NotifyLinkFail(laneRequestId, errCode);
}

static void SetAuthInfo(const LaneGuideLinkInfo *guideInfo,
    bool isSupportWDEnhance, struct WifiDirectConnectInfo *connInfo)
{
    connInfo->connectType = isSupportWDEnhance ? WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML :
        WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    connInfo->negoChannel.type = NEGO_CHANNEL_AUTH;
    connInfo->negoChannel.handle.authHandle = ;
    wifiDirectChannel->handle.authHandle = guideInfo->guideInfo.authGuideInfo;
}

static void SetProxyNegoInfo(const LaneGuideLinkInfo *guideInfo,
    bool isSupportWDEnhance, struct WifiDirectConnectInfo *connInfo)
{
    (void)isSupportWDEnhance;
    connInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    connInfo->negoChannel.type = NEGO_CHANNEL_COC;
    connInfo->negoChannel.handle.channelId = guideInfo->guideInfo.proxyChannel;
}

static void SetBleTriggerInfo(const LaneGuideLinkInfo *guideInfo,
    bool isSupportWDEnhance, struct WifiDirectConnectInfo *connInfo)
{
    connInfo->connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    LNN_LOGD(LNN_LANE, "ble trigger, no need more params");
    if (!isSupportWDEnhance) {
        LNN_LOGE(LNN_LANE, "Error: ble trigger not support");
    }
}

static int32_t SetPreferGuideWifiDirectNego(bool isSupportWDEnhance,
    const LaneGuideLinkInfo *guideInfo, struct WifiDirectConnectInfo *connInfo)
{
    switch (guideInfo->guideType) {
        case GUIDE_LINK_ENHANCE_P2P:
        case GUIDE_LINK_P2P:
        case GUIDE_LINK_WIFI:
        case GUIDE_LINK_BR:
            SetAuthInfo(guideInfo, isSupportWDEnhance, connInfo);
            return SOFTBUS_OK;
        case GUIDE_LINK_BLE_TRIGGER:
            SetBleTriggerInfo(guideInfo, isSupportWDEnhance, connInfo);
            return SOFTBUS_OK;
        case GUIDE_LINK_BLE_DIRECT:
            SetProxyNegoInfo(guideInfo, isSupportWDEnhance, connInfo);
            return SOFTBUS_OK;
        default:
            LNN_LOGE(LNN_LANE, "unexcept guideType=%{public}d", guideInfo->guideType);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t SetPreferGuideWifiDirectParam(WDLinkRequest *requestItem,
    const LaneGuideLinkInfo *guideInfo, struct WifiDirectConnectInfo *connInfo)
{
    bool isSupportWDEnhance = IsSupportWifiDirectEnhance(requestItem->in.requestInfo.peerNetworkId);
    if (memcpy_s(&requestItem->conn.currentGuideInfo, sizeof(LaneGuideLinkInfo),
        guideInfo, sizeof(LaneGuideLinkInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SetPreferGuideWifiDirectNego(isSupportWDEnhance, guideInfo, connInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set WD nego info fail, ret=%{public}d", ret);
        return ret;
    }
    return SetWifiDirectCommParam(requestItem, connInfo);
}

static int32_t ProcPreferGuideWifiDirectParam(int32_t guideRequestId, uint32_t connRequestId,
    struct WifiDirectConnectInfo *connInfo, const LaneGuideLinkInfo *guideInfo)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->conn.guideRequestId == guideRequestId) {
            requestItem->conn.connRequestId = connRequestId;
            ret = SetPreferGuideWifiDirectParam(requestItem, guideInfo, connInfo);
            LaneMutexUnlock();
            return ret;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "node not found, guideRequestId=%{public}d", guideRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static void ConnectSuccessByPreferGuide(uint32_t connRequestId, const struct WifiDirectLink *link)
{
    uint32_t laneRequestId = 0;
    WDLinkRequest requestObj;
    (void)memset_s(&requestObj, sizeof(WDLinkRequest), 0, sizeof(WDLinkRequest));
    int32_t ret = GetRequestObjByConnRequestId(connRequestId, &requestObj);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "node not found, need proc link_recycle, connRequestId=%{public}d", connRequestId);
        // warn: proc link recycle
        return;
    }
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "WD link is null, connRequestId=%{publiuc}u", connRequestId);
        ret = SOFTBUS_INVALID_PARAM;
        goto FAIL;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    ret = ProcWDLinkInfo(requestObj.laneRequestId, link, &linkInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create link info err, ret=%{public}d", ret);
        goto FAIL;
    }
    CloseGuideLink(requestObj.conn.guideRequestId, &requestObj.conn.currentGuideInfo);
    NotifyLinkSucc(requestObj.laneRequestId, &linkInfo);
    return;
FAIL:
    CloseGuideLink(requestObj.conn.guideRequestId, &requestObj.conn.currentGuideInfo);
    NotifyLinkFail(requestObj.laneRequestId, ret);
}

static void RetryGuideLinkFail(int32_t guideRequestId, int32_t errCode)
{
    LNN_LOGE(LNN_LANE, "guideRequestId=%{public}d, errcode=%{public}d", guideRequestId, errCode);
    uint32_t laneRequestId = 0;
    if (GetLaneRequestIdByGuideRequestId(guideRequestId, &laneRequestId) != SOFTBUS_OK) {
        LNN_LOGW(LNN_LANE, "node not found, ignore result, guideRequestId=%{public}d", guideRequestId);
        return;
    }
    NotifyLinkFail(laneRequestId, errCode);
}

static void ConnectSuccessByRetryGuide(uint32_t connRequestId, const struct WifiDirectLink *link)
{
    uint32_t laneRequestId = 0;
    WDLinkRequest requestObj;
    (void)memset_s(&requestObj, sizeof(WDLinkRequest), 0, sizeof(WDLinkRequest));
    int32_t ret = GetRequestObjByConnRequestId(connRequestId, &requestObj);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "node not found, need proc link_recycle, connRequestId=%{public}d", connRequestId);
        return;
    }
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "WD link is null, connRequestId=%{publiuc}u", connRequestId);
        ret = SOFTBUS_INVALID_PARAM;
        goto FAIL;
    }
    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    ret = ProcWDLinkInfo(requestObj.laneRequestId, link, &linkInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create link info err, ret=%{public}d", ret);
        goto FAIL;
    }
    CloseGuideLink(requestObj.conn.guideRequestId, &requestObj.conn.currentGuideInfo);
    NotifyLinkSucc(requestObj.laneRequestId, &linkInfo);
    return;
FAIL:
    CloseGuideLink(requestObj.conn.guideRequestId, &requestObj.conn.currentGuideInfo);
    NotifyLinkFail(requestObj.laneRequestId, ret);
}

static void ConnectFailureByRetryGuide(uint32_t connRequestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "WD conn fail, connRequestId=%{public}u, reason=%{public}d", connRequestId, reason);
    uint32_t laneRequestId = 0;
    int32_t ret = GetLaneRequestIdByConnRequestId(connRequestId, &laneRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "node not found, ret=%{public}d", ret);
        goto CLOSE_LINK;
    }
    if (reason == ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT || reason == ERROR_POST_DATA_FAILED) {
        LNN_LOGI(LNN_LANE, "need retry wifi direct");
        ret = BuildLinkByRetryGuideLink(connRequestId);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "build link by retry guide link fail=%{public}d", ret);
            goto CLOSE_LINK;
        }
    }
CLOSE_LINK:
    NotifyLinkFail(laneRequestId, reason);
}

static int32_t ProcWifiDirectByRetryGuideLink(int32_t guideRequestId, const LaneGuideLinkInfo *guideInfo)
{
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    int32_t ret = ProcPreferGuideWifiDirectParam(guideRequestId, info.requestId, &info, guideInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set WD link param fail=%{public}d", ret);
        return ret;
    }
    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = ConnectSuccessByRetryGuide,
        .onConnectFailure = ConnectFailureByRetryGuide,
    };
    LNN_LOGI(LNN_LANE, "WD connRequestId=%{public}u, connectType=%{public}d",
        info.requestId, info.connectType);
    ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "WD connect err=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void RetryGuideLinkSuccess(int32_t guideRequestId, const LaneGuideLinkInfo *info)
{
    int32_t ret = SOFTBUS_OK;
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "prefer guideLink info is null");
        ret = SOFTBUS_LANE_GUIDE_BUILD_FAIL;
        goto FAIL;
    }
    LNN_LOGI(LNN_LANE, "prefer guideLink opened, guideRequestId=%{public}d, guideType=%{public}d",
        guideRequestId, info->guideType);
    ret = ProcWifiDirectByRetryGuideLink(guideRequestId, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "WD by prefer guideLink fail=%{public}d", ret);
        goto FAIL;
    }
    return;
FAIL:
    if (info != NULL) {
        CloseGuideLink(guideRequestId, info);
    }
    uint32_t laneRequestId = 0;
    if (GetLaneRequestIdByGuideRequestId(guideRequestId, &laneRequestId) != SOFTBUS_OK) {
        LNN_LOGW(LNN_LANE, "node not found, ignore result, guideRequestId=%{public}d", guideRequestId);
        return;
    }
    NotifyLinkFail(laneRequestId, ret);
}

static int32_t BuildLinkByRetryGuideLink(uint32_t connRequestId)
{
    WDLinkRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->conn.connRequestId == connRequestId) {
            ret = memcpy_s(&request, sizeof(WDLinkRequest),
                requestItem, sizeof(WDLinkRequest));
            (void)memset_s(&requestItem->conn.currentGuideInfo,
                sizeof(LaneGuideLinkInfo), 0, sizeof(LaneGuideLinkInfo));
            requestItem->conn.guideRequestId = -1;
            break;
        }
    }
    LaneMutexUnlock();
    CloseGuideLink(request.conn.guideRequestId, &request.conn.currentGuideInfo);
    int32_t guideRequestId = GetGuideLinkRequestId();
    LaneGuideLinkListener listener = {
        .onGuideLinkFail = RetryGuideLinkFail, //PreferGuideLinkFail,
        .onGuideLinkSuccess = RetryGuideLinkSuccess, //PreferGuideLinkSuccess,
    };
    ret = UpdateGuideRequestId(request.laneRequestId, guideRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update retryGuideLinkId fail=%{public}d", ret);
        return ret;
    }
    ret = OpenRetryGuideLink(guideRequestId, request.in.requestInfo.peerNetworkId,
        &request.conn.currentGuideInfo, &listener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open retryGuideLink fail=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void ConnectFailureByPreferGuide(uint32_t connRequestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "WD conn fail, connRequestId=%{public}u, reason=%{public}d", connRequestId, reason);
    uint32_t laneRequestId = 0;
    int32_t ret = GetLaneRequestIdByConnRequestId(connRequestId, &laneRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "node not found, ret=%{public}d", ret);
        goto CLOSE_LINK;
    }
    if (reason == ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT || reason == ERROR_POST_DATA_FAILED) {
        LNN_LOGI(LNN_LANE, "need retry wifi direct");
        ret = BuildLinkByRetryGuideLink(connRequestId);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "build link by retry guide link fail=%{public}d", ret);
            goto CLOSE_LINK;
        }
    }
CLOSE_LINK:
    NotifyLinkFail(laneRequestId, reason);
}

static int32_t ProcWifiDirectByPreferGuideLink(int32_t guideRequestId, const LaneGuideLinkInfo *guideInfo)
{
    struct WifiDirectConnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.requestId = GetWifiDirectManager()->getRequestId();
    int32_t ret = ProcPreferGuideWifiDirectParam(guideRequestId, info.requestId, &info, guideInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "set WD link param fail=%{public}d", ret);
        return ret;
    }
    struct WifiDirectConnectCallback callback = {
        .onConnectSuccess = ConnectSuccessByPreferGuide,
        .onConnectFailure = ConnectFailureByPreferGuide,
    };
    LNN_LOGI(LNN_LANE, "WD connRequestId=%{public}u, connectType=%{public}d",
        info.requestId, info.connectType);
    ret = GetWifiDirectManager()->connectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "WD connect err=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void PreferGuideLinkSuccess(int32_t guideRequestId, const LaneGuideLinkInfo *info)
{
    int32_t ret = SOFTBUS_OK;
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "prefer guideLink info is null");
        ret = SOFTBUS_LANE_GUIDE_BUILD_FAIL;
        goto FAIL;
    }
    LNN_LOGI(LNN_LANE, "prefer guideLink opened, guideRequestId=%{public}d, guideType=%{public}d",
        guideRequestId, info->guideType);
    ret = ProcWifiDirectByPreferGuideLink(guideRequestId, info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "WD by prefer guideLink fail=%{public}d", ret);
        goto FAIL;
    }
    return;
FAIL:
    if (info != NULL) {
        CloseGuideLink(guideRequestId, info);
    }
    uint32_t laneRequestId = 0;
    if (GetLaneRequestIdByGuideRequestId(guideRequestId, &laneRequestId) != SOFTBUS_OK) {
        LNN_LOGW(LNN_LANE, "node not found, ignore result, guideRequestId=%{public}d", guideRequestId);
        return;
    }
    NotifyLinkFail(laneRequestId, ret);
}

static int32_t UpdateGuideRequestId(uint32_t laneRequestId, int32_t guideRequestId)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return SOFTBUS_LOCK_ERR;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->laneRequestId == laneRequestId) {
            requestItem->conn.guideRequestId = guideRequestId;
            LaneMutexUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneMutexUnlock();
    LNN_LOGE(LNN_LANE, "node not found, laneRequestId=%{public}u, guideRequestId=%{public}d",
        laneRequestId, guideRequestId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t BuildLinkByGuideLink(uint32_t requestId, const LnnWDRequestInfo *request)
{
    int32_t guideRequestId = GetGuideLinkRequestId();
    LaneGuideLinkListener listener = {
        .onGuideLinkFail = PreferGuideLinkFail,
        .onGuideLinkSuccess = PreferGuideLinkSuccess,
    };
    int32_t ret = UpdateGuideRequestId(requestId, guideRequestId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update metaAuth requestId fail=%{public}d", ret);
        return ret;
    }
    ret = OpenPreferGuideLink(guideRequestId, request->peerNetworkId, &listener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open prefer guideLink fail=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t BuildWifiDirect(uint32_t requestId, const LnnWDRequestInfo *requestInfo)
{
    bool isMeta = IsMetaOnline(request->peerNetworkId);
    if (isMeta) {
        return BuildLinkByMetaAuth(requestId, requestInfo);
    }
    return BuildLinkByGuideLink(requestId, requestInfo);
}

static int32_t LaneWifiDirectInit(void)
{
    g_linkRequestList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_linkRequestList == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_linkRequestList);
    return SOFTBUS_OK;
}

static void LaneWifiDirectDeinit(void)
{
    if (LaneMutexLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    if (g_linkRequestList == NULL) {
        goto CLEAN;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        ListDelete(&requestItem->node);
        SoftBusFree(requestItem);
    }
    SoftBusFree(g_linkRequestList);
    g_linkRequestList = NULL;
CLEAN:
    LaneMutexUnlock();
    LaneMutexDestroy();
}

static int32_t SetInputParam(uint32_t requestId, const LnnWDRequestInfo *requestInfo,
    const LaneLinkCb *callback, InputInfo *in)
{
    in->cb = *callback;
    in->requestId = requestId;
    if (memcpy_s(in->requestInfo, sizeof(LnnWDRequestInfo),
        requestInfo, sizeof(LnnWDRequestInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AddRequestInfo(uint32_t requestId, const LnnWDRequestInfo *requestInfo,
    const LaneLinkCb *callback)
{
    WDLinkRequest *requestNode = (WDLinkRequest *)SoftBusCalloc(sizeof(WDLinkRequest));
    if (requestNode == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SetInputParam(requestId, requestInfo, callback, &requestNode->in);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "param proc fail=%{public}d", ret);
        goto CLEAN_MEM;
    }
    ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        goto CLEAN_MEM;
    }
    if (g_linkRequestList == NULL) {
        ret = LaneWifiDirectInit();
        if (ret != SOFTBUS_OK) {
            LaneMutexUnlock();
            LNN_LOGE(LNN_LANE, "lane WD not init");
            goto CLEAN_MEM;
        }
    }
    ListTailInsert(g_linkRequestList, &requestNode->node);
    LaneMutexUnlock();
    return SOFTBUS_OK;

CLEAN_MEM:
    SoftBusFree(requestNode);
    requestNode = NULL;
    return ret;
}

static void DeleteRequestInfo(uint32_t requestId)
{
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return;
    }
    WDLinkRequest *requestItem = NULL;
    WDLinkRequest *requestNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestItem, requestNext, g_linkRequestList, WDLinkRequest, node) {
        if (requestItem->requestId == requestId) {
            ListDelete(&requestItem->node);
            SoftBusFree(requestItem);
            break;
        }
    }
    LaneMutexUnlock();
}

int32_t LnnWifiDirectConnect(uint32_t laneRequestId, const LnnWDRequestInfo *requestInfo,
    const LaneLinkCb *callback)
{
    if (requestInfo == NULL || callback == NULL) {
        LNN_LOGE(LNN_LANE, "invalid null request or callback");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = AddRequestInfo(laneRequestId, requestInfo, callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add WD request fail=%{public}d", ret);
        return ret;
    }
    ret = BuildWifiDirect(laneRequestId, requestInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "build wifi direct fail=%{public}d", ret);
        DeleteRequestInfo(laneRequestId);
        return ret;
    }
    return SOFTBUS_OK;
}

void LnnWifiDirectDisconnect(uint32_t laneRequestId, const char *networkId)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "networkId is null, disconn invalid");
        return;
    }
    int32_t ret = LaneMutexLock();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail=%{public}d", ret);
        return;
    }
    if (g_linkRequestList == NULL) {
        LNN_LOGE(LNN_LANE, "WD link not trigger, disconn ignore");
        LaneMutexUnlock();
        return;
    }
    LaneMutexUnlock();
    int32_t ret = DisconnWifiDirectByAuth(laneRequestId, networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth guide link");
        DisconnWifiDirectByLinkSelf(laneRequestId, networkId);
    }
}

void LnnWifiDirectDestroy(void)
{
    LNN_LOGI(LNN_LANE, "WD destroy");
    LaneWifiDirectDeinit();
}
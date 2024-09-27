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

#include "lnn_lane_link_wifi_direct.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_log.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "wifi_direct_manager.h"

static SoftBusMutex g_linkWifiDirectMutex;
static ListNode *g_forceDownList = NULL;

#define INVAILD_AUTH_ID (-1)
#define INVALID_P2P_REQUEST_ID (-1)
#define TRANS_FORCE_DOWN_TIMEOUT 2000
#define USECTONSEC 1000LL

typedef enum {
    INFO_TYPE_P2P = 0,
    INFO_TYPE_AUTH,
    INFO_TYPE_FORCE_DOWN,
    INFO_TYPE_BUTT,
} ForceDisconnectInfoType;

static int32_t LinkWifiDirectLock(void)
{
    return SoftBusMutexLock(&g_linkWifiDirectMutex);
}

static void LinkWifiDirectUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_linkWifiDirectMutex);
}

static bool IsForceDownInfoExists(uint32_t p2pRequestId)
{
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link wifidirect lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ForceDownInfo *item = NULL;
    ForceDownInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_forceDownList, ForceDownInfo, node) {
        if (item->p2pRequestId == p2pRequestId) {
            LinkWifiDirectUnlock();
            return true;
        }
    }
    LinkWifiDirectUnlock();
    return false;
}

static int32_t AddForceDownInfo(const ForceDownInfo *forceDownInfo)
{
    if (forceDownInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (IsForceDownInfoExists(forceDownInfo->p2pRequestId)) {
        LNN_LOGE(LNN_LANE, "forceDownInfo already exists");
        return SOFTBUS_OK;
    }
    ForceDownInfo *newNode = (ForceDownInfo *)SoftBusCalloc(sizeof(ForceDownInfo));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "calloc forceDownInfo fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(newNode, sizeof(ForceDownInfo), forceDownInfo, sizeof(ForceDownInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy forceDownInfo fail");
        SoftBusFree(newNode);
        return SOFTBUS_MEM_ERR;
    }
    if (SoftBusCondInit(&newNode->cond) != SOFTBUS_OK) {
        SoftBusFree(newNode);
        return SOFTBUS_NO_INIT;
    }
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link wifidirect lock fail");
        (void)SoftBusCondDestroy(&newNode->cond);
        SoftBusFree(newNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(g_forceDownList, &newNode->node);
    LinkWifiDirectUnlock();
    char *anonyNetworkId = NULL;
    Anonymize(forceDownInfo->forceDownDevId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "add new forceDownInfo success, p2pRequestId=%{public}u, forceDownDevId=%{public}s, "
        "forceDownReqId=%{public}u, forceDownLink=%{public}d, forceDownType=%{public}d", forceDownInfo->p2pRequestId,
        AnonymizeWrapper(anonyNetworkId), forceDownInfo->forceDownReqId,
        forceDownInfo->forceDownLink, forceDownInfo->downType);
    AnonymizeFree(anonyNetworkId);
    return SOFTBUS_OK;
}

static int32_t DelForceDownInfo(uint32_t forceDownReqId)
{
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LNN_LOGI(LNN_LANE, "start to del forceDownInfo by forceDownReqId=%{public}u", forceDownReqId);
    ForceDownInfo *item = NULL;
    ForceDownInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_forceDownList, ForceDownInfo, node) {
        if (item->forceDownReqId == forceDownReqId) {
            if (item->downType == FORCE_DOWN_TRANS) {
                (void)SoftBusCondSignal(&item->cond);
            }
            ListDelete(&item->node);
            (void)SoftBusCondDestroy(&item->cond);
            SoftBusFree(item);
            LinkWifiDirectUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkWifiDirectUnlock();
    LNN_LOGE(LNN_LANE, "not found forceDownInfo when del");
    return SOFTBUS_LANE_NOT_FOUND;
}

static ForceDownInfo* GetForceDownInfoWithoutLock(ForceDisconnectInfoType type, uint32_t requestId)
{
    ForceDownInfo *item = NULL;
    ForceDownInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_forceDownList, ForceDownInfo, node) {
        if ((type == INFO_TYPE_AUTH && item->authRequestId == requestId) ||
            (type == INFO_TYPE_FORCE_DOWN && item->forceDownReqId == requestId)) {
            return item;
        }
    }
    return NULL;
}

static int32_t FindForceDownInfoByReqId(ForceDisconnectInfoType type, uint32_t requestId,
    ForceDownInfo *info)
{
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link wifidirect lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ForceDownInfo* item = GetForceDownInfoWithoutLock(type, requestId);
    if (item == NULL) {
        LNN_LOGE(LNN_LANE, "not found forceDownInfo by type=%{public}d, requestId=%{public}u", type, requestId);
        LinkWifiDirectUnlock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    if (memcpy_s(info, sizeof(ForceDownInfo), item, sizeof(ForceDownInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy forceDownInfo fail");
        LinkWifiDirectUnlock();
        return SOFTBUS_MEM_ERR;
    }
    LinkWifiDirectUnlock();
    return SOFTBUS_OK;
}

static void FreeResourceForForceDisconnect(ForceDownInfo *forceDownInfo)
{
    if (forceDownInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    (void)DelForceDownInfo(forceDownInfo->forceDownReqId);
    if (forceDownInfo->authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(forceDownInfo->authHandle);
    }
    RecycleP2pLinkedReqByLinkType(forceDownInfo->forceDownDevId, forceDownInfo->forceDownLink);
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(forceDownInfo->forceDownDevId, STRING_KEY_DEV_UDID,
        peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peerUdid error");
        return;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, forceDownInfo->forceDownLink, &resourceItem) == SOFTBUS_OK) {
        if (forceDownInfo->forceDownLink == LANE_HML) {
            RemoveDelayDestroyMessage(resourceItem.laneId);
        }
        DelLogicAndLaneRelationship(resourceItem.laneId);
        ClearLaneResourceByLaneId(resourceItem.laneId);
    }
    if (forceDownInfo->forceDownLink == LANE_HML &&
        FindLaneResourceByLinkType(peerUdid, LANE_HML_RAW, &resourceItem) == SOFTBUS_OK) {
        DelLogicAndLaneRelationship(resourceItem.laneId);
        ClearLaneResourceByLaneId(resourceItem.laneId);
    }
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

static void OnWifiDirectForceDisconnectSuccess(uint32_t requestId)
{
    LNN_LOGI(LNN_LANE, "wifidirect force disconnect succ, requestId=%{public}u", requestId);
    ForceDownInfo forceDownInfo;
    (void)memset_s(&forceDownInfo, sizeof(ForceDownInfo), 0, sizeof(ForceDownInfo));
    int32_t ret = FindForceDownInfoByReqId(INFO_TYPE_FORCE_DOWN, requestId, &forceDownInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find forceDownInfo fail, requestId=%{public}u", requestId);
        return;
    }
    FreeResourceForForceDisconnect(&forceDownInfo);
    if (forceDownInfo.downType == FORCE_DOWN_LANE) {
        ret = WifiDirectReconnectDevice(forceDownInfo.p2pRequestId);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "wifidirect reconnect device fail, p2pRequest=%{public}u",
                forceDownInfo.p2pRequestId);
            NotifyLinkFailForForceDown(forceDownInfo.p2pRequestId, ret);
        }
    }
}

static void OnWifiDirectForceDisconnectFailure(uint32_t requestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "wifidirect force disconnect fail, requestId=%{public}u, reason=%{public}d",
        requestId, reason);
    ForceDownInfo forceDownInfo;
    (void)memset_s(&forceDownInfo, sizeof(ForceDownInfo), 0, sizeof(ForceDownInfo));
    int32_t ret = FindForceDownInfoByReqId(INFO_TYPE_FORCE_DOWN, requestId, &forceDownInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find forceDownInfo fail, requestId=%{public}u", requestId);
        return;
    }
    (void)DelForceDownInfo(requestId);
    if (forceDownInfo.authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(forceDownInfo.authHandle);
    }
    if (forceDownInfo.downType == FORCE_DOWN_LANE) {
        NotifyLinkFailForForceDown(forceDownInfo.p2pRequestId, reason);
    }
}

static int32_t GenerateForceDownWifiDirectInfo(const ForceDownInfo* forceDownInfo,
    struct WifiDirectForceDisconnectInfo *info)
{
    if (forceDownInfo == NULL || info == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    info->requestId = forceDownInfo->forceDownReqId;
    info->linkType = forceDownInfo->forceDownLink == LANE_HML ?
        WIFI_DIRECT_LINK_TYPE_HML : WIFI_DIRECT_LINK_TYPE_P2P;
    char peerUuid[UUID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(forceDownInfo->forceDownDevId, STRING_KEY_UUID, peerUuid,
        sizeof(peerUuid)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer uuid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (strcpy_s(info->remoteUuid, sizeof(info->remoteUuid), peerUuid) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy remote uuid fail");
        return SOFTBUS_STRCMP_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UpdateForceDownInfoParam(uint32_t authRequestId, AuthHandle authHandle, ForceDownInfo *forceDownInfo)
{
    if (forceDownInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link wifidirect lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ForceDownInfo* item = GetForceDownInfoWithoutLock(INFO_TYPE_AUTH, authRequestId);
    if (item == NULL) {
        LNN_LOGE(LNN_LANE, "not found forceDownInfo by authRequestId=%{public}u", authRequestId);
        LinkWifiDirectUnlock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    item->authHandle = authHandle;
    if (memcpy_s(forceDownInfo, sizeof(ForceDownInfo), item, sizeof(ForceDownInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy forceDownInfo fail");
        LinkWifiDirectUnlock();
        return SOFTBUS_MEM_ERR;
    }
    LinkWifiDirectUnlock();
    return SOFTBUS_OK;
}

static void OnConnOpenedForForceDisconnect(uint32_t authRequestId, AuthHandle authHandle)
{
    LNN_LOGI(LNN_LANE, "auth opened for force disconnect wifidirect, authRequestId=%{public}u, "
        "authId=%{public}" PRId64 "", authRequestId, authHandle.authId);
    struct WifiDirectForceDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    info.negoChannel.handle.authHandle = authHandle;
    ForceDownInfo forceDownInfo;
    (void)memset_s(&forceDownInfo, sizeof(ForceDownInfo), 0, sizeof(ForceDownInfo));
    int32_t ret = UpdateForceDownInfoParam(authRequestId, authHandle, &forceDownInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update forceDownInfo param fail");
        goto FAIL;
    }
    ret = GenerateForceDownWifiDirectInfo(&forceDownInfo, &info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get force disconnect wifidirect fail");
        goto FAIL;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectForceDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectForceDisconnectFailure,
    };
    LNN_LOGI(LNN_LANE, "force disconnect wifidirect, p2pRequestId=%{public}u, linkType=%{public}d",
        info.requestId, info.linkType);
    ret = GetWifiDirectManager()->forceDisconnectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "force disconnect device fail, reason=%{public}d", ret);
        goto FAIL;
    }
    return;
FAIL:
    (void)DelForceDownInfo(forceDownInfo.forceDownReqId);
    if (authHandle.authId != INVAILD_AUTH_ID) {
        AuthCloseConn(authHandle);
    }
    if (forceDownInfo.downType == FORCE_DOWN_LANE) {
        NotifyLinkFailForForceDown(forceDownInfo.p2pRequestId, ret);
    }
}

static int32_t ForceDisconnectWifiDirectWithoutAuth(const ForceDownInfo *forceDownInfo)
{
    if (forceDownInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    struct WifiDirectForceDisconnectInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = GenerateForceDownWifiDirectInfo(forceDownInfo, &info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get force disconnect wifidirect fail");
        return ret;
    }
    struct WifiDirectDisconnectCallback callback = {
        .onDisconnectSuccess = OnWifiDirectForceDisconnectSuccess,
        .onDisconnectFailure = OnWifiDirectForceDisconnectFailure,
    };
    LNN_LOGI(LNN_LANE, "force disconnect wifidirect, p2pRequestId=%{public}u, linkType=%{public}d",
        info.requestId, info.linkType);
    ret = GetWifiDirectManager()->forceDisconnectDevice(&info, &callback);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "force disconnect device fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void OnConnOpenFailedForForceDisconnect(uint32_t authRequestId, int32_t reason)
{
    LNN_LOGE(LNN_LANE, "auth open fail for force disconnect wifidirect, authRequestId=%{public}u, reason=%{public}d",
        authRequestId, reason);
    ForceDownInfo forceDownInfo;
    (void)memset_s(&forceDownInfo, sizeof(ForceDownInfo), 0, sizeof(ForceDownInfo));
    if (FindForceDownInfoByReqId(INFO_TYPE_AUTH, authRequestId, &forceDownInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find forceDownInfo fail, authRequestId=%{public}u", authRequestId);
        return;
    }
    int32_t ret = ForceDisconnectWifiDirectWithoutAuth(&forceDownInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "force disconnect device fail, reason=%{public}d", ret);
        (void)DelForceDownInfo(forceDownInfo.forceDownReqId);
        if (forceDownInfo.downType == FORCE_DOWN_LANE) {
            NotifyLinkFailForForceDown(forceDownInfo.p2pRequestId, reason);
        }
    }
    return;
}

static int32_t OpenAuthToForceDisconnect(const char *forceDownDevId, uint32_t forceDownReqId)
{
    if (forceDownDevId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    bool isMetaAuth = GetChannelAuthType(forceDownDevId);
    int32_t ret = GetPreferAuthConnInfo(forceDownDevId, &connInfo, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "no auth conn exist");
        return ret;
    }
    uint32_t authRequestId = AuthGenRequestId();
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link wifidirect lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ForceDownInfo* forceDownInfo = GetForceDownInfoWithoutLock(INFO_TYPE_FORCE_DOWN, forceDownReqId);
    if (forceDownInfo == NULL) {
        LNN_LOGE(LNN_LANE, "not found forceDownInfo by forceDownReqId=%{public}u", forceDownReqId);
        LinkWifiDirectUnlock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    forceDownInfo->authRequestId = authRequestId;
    LinkWifiDirectUnlock();
    AuthConnCallback cb = {
        .onConnOpened = OnConnOpenedForForceDisconnect,
        .onConnOpenFailed = OnConnOpenFailedForForceDisconnect,
    };
    LNN_LOGI(LNN_LANE, "open auth for force disconnect wifidirect, authRequestId=%{public}u", authRequestId);
    ret = AuthOpenConn(&connInfo, authRequestId, &cb, isMetaAuth);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "open auth conn fail, authRequestId=%{public}u", authRequestId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AddNewForceDownInfo(ForceDownType downType, const char *forceDownDevId, LaneLinkType forceDownLink,
    uint32_t p2pRequestId, uint32_t forceDownReqId)
{
    if (forceDownDevId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ForceDownInfo forceDownInfo;
    (void)memset_s(&forceDownInfo, sizeof(ForceDownInfo), 0, sizeof(ForceDownInfo));
    if (strcpy_s(forceDownInfo.forceDownDevId, sizeof(forceDownInfo.forceDownDevId),
        forceDownDevId) != EOK) {
        LNN_LOGE(LNN_LANE, "copy forceDownDevId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    forceDownInfo.p2pRequestId = p2pRequestId;
    forceDownInfo.forceDownLink = forceDownLink;
    forceDownInfo.forceDownReqId = forceDownReqId;
    forceDownInfo.authRequestId = AUTH_INVALID_ID;
    AuthHandle authHandle = { .authId = INVAILD_AUTH_ID };
    forceDownInfo.authHandle = authHandle;
    forceDownInfo.downType = downType;
    int32_t ret = AddForceDownInfo(&forceDownInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new forceDownInfo fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static void FreeLinkConflictDevInfo(LinkConflictInfo *inputItem)
{
    if (inputItem == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (inputItem->devIdCnt > 0) {
        SoftBusFree(inputItem->devIdList);
        inputItem->devIdList = NULL;
    }
    if (inputItem->devIpCnt > 0) {
        SoftBusFree(inputItem->devIpList);
        inputItem->devIpList = NULL;
    }
    inputItem->devIdCnt = 0;
    inputItem->devIpCnt = 0;
}

static void ComputeWaitForceDownTime(uint32_t waitMillis, SoftBusSysTime *outtime)
{
    SoftBusSysTime now;
    (void)SoftBusGetTime(&now);
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + (int64_t)waitMillis * USECTONSEC;
    outtime->sec = time / USECTONSEC / USECTONSEC;
    outtime->usec = time % (USECTONSEC * USECTONSEC);
}

static void ForceDownCondWait(ForceDownType downType, uint32_t forceDownReqId)
{
    if (downType != FORCE_DOWN_TRANS) {
        LNN_LOGI(LNN_LANE, "not support downType=%{public}d", downType);
        return;
    }
    SoftBusSysTime outtime;
    ComputeWaitForceDownTime(TRANS_FORCE_DOWN_TIMEOUT, &outtime);
    LNN_LOGI(LNN_LANE, "set forceDown condWait with %{public}d millis, forceDownReqId=%{public}u",
        TRANS_FORCE_DOWN_TIMEOUT, forceDownReqId);
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock fail");
        return;
    }
    ForceDownInfo *item = NULL;
    ForceDownInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, g_forceDownList, ForceDownInfo, node) {
        if (item->forceDownReqId == forceDownReqId) {
            (void)SoftBusCondWait(&item->cond, &g_linkWifiDirectMutex, &outtime);
            LinkWifiDirectUnlock();
            return;
        }
    }
    LinkWifiDirectUnlock();
    LNN_LOGE(LNN_LANE, "not found forceDownInfo when set condWait");
}

static int32_t ForceDisconnectWifiDirect(ForceDownType downType, const char *forceDownDevId,
    LaneLinkType forceDownLink, uint32_t p2pRequestId)
{
    if (forceDownDevId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t forceDownReqId = GetWifiDirectManager()->getRequestId();
    int32_t ret = AddNewForceDownInfo(downType, forceDownDevId, forceDownLink, p2pRequestId, forceDownReqId);
    if (ret !=SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add new force disconnect info fail");
        return ret;
    }
    enum WifiDirectLinkType linkType = forceDownLink == LANE_HML ?
        WIFI_DIRECT_LINK_TYPE_HML : WIFI_DIRECT_LINK_TYPE_P2P;
    ret = SOFTBUS_OK;
    if (!GetWifiDirectManager()->isNegotiateChannelNeeded(forceDownDevId, linkType) ||
        OpenAuthToForceDisconnect(forceDownDevId, forceDownReqId) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "no need auth or open auth fail, force disconnect without auth");
        ForceDownInfo forceDownInfo;
        (void)memset_s(&forceDownInfo, sizeof(ForceDownInfo), 0, sizeof(ForceDownInfo));
        ret = FindForceDownInfoByReqId(INFO_TYPE_FORCE_DOWN, forceDownReqId, &forceDownInfo);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "find forceDownInfo fail, forceDownReqId=%{public}u", forceDownReqId);
            return ret;
        }
        ret = ForceDisconnectWifiDirectWithoutAuth(&forceDownInfo);
        if (ret != SOFTBUS_OK) {
            (void)DelForceDownInfo(forceDownReqId);
            LNN_LOGE(LNN_LANE, "force disconnect wifidirect without auth fail, reason=%{public}d", ret);
        }
    }
    if (ret == SOFTBUS_OK) {
        ForceDownCondWait(downType, forceDownReqId);
    }
    return ret;
}

int32_t HandleForceDownWifiDirect(const char *networkId, LinkConflictType conflictType, uint32_t p2pRequestId)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LinkConflictInfo conflictItem;
    (void)memset_s(&conflictItem, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    DevIdentifyInfo identifyInfo;
    (void)memset_s(&identifyInfo, sizeof(DevIdentifyInfo), 0, sizeof(DevIdentifyInfo));
    identifyInfo.type = IDENTIFY_TYPE_DEV_ID;
    if (strcpy_s(identifyInfo.devInfo.peerDevId, sizeof(identifyInfo.devInfo.peerDevId), networkId) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerDevId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = FindLinkConflictInfoByDevId(&identifyInfo, conflictType, &conflictItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find link conflict info fail");
        return ret;
    }
    RemoveConflictInfoTimelinessMsg(&(conflictItem.identifyInfo), conflictType);
    (void)DelLinkConflictInfo(&(conflictItem.identifyInfo), conflictType);
    if (conflictItem.devIdCnt > 0) {
        char forceDownDevId[NETWORK_ID_BUF_LEN] = {0};
        if (memcpy_s(forceDownDevId, NETWORK_ID_BUF_LEN, conflictItem.devIdList, NETWORK_ID_BUF_LEN) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy networkId fail");
            FreeLinkConflictDevInfo(&conflictItem);
            return SOFTBUS_MEM_ERR;
        }
        ret = ForceDisconnectWifiDirect(FORCE_DOWN_LANE, forceDownDevId, conflictItem.releaseLink, p2pRequestId);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "force disconnect wifidirect fail");
        }
        FreeLinkConflictDevInfo(&conflictItem);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "link conflict device not exists, no need force disconnect");
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t HandleForceDownWifiDirectTrans(const char *udidhashStr, LinkConflictType conflictType)
{
    if (udidhashStr == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LinkConflictInfo conflictItem;
    (void)memset_s(&conflictItem, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    DevIdentifyInfo identifyInfo;
    (void)memset_s(&identifyInfo, sizeof(DevIdentifyInfo), 0, sizeof(DevIdentifyInfo));
    identifyInfo.type = IDENTIFY_TYPE_UDID_HASH;
    if (strcpy_s(identifyInfo.devInfo.udidHash, sizeof(identifyInfo.devInfo.udidHash), udidhashStr) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerDevId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = FindLinkConflictInfoByDevId(&identifyInfo, conflictType, &conflictItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find link conflict info fail");
        return ret;
    }
    RemoveConflictInfoTimelinessMsg(&(conflictItem.identifyInfo), conflictType);
    (void)DelLinkConflictInfo(&(conflictItem.identifyInfo), conflictType);
    if (conflictItem.devIdCnt > 0) {
        char forceDownDevId[NETWORK_ID_BUF_LEN] = {0};
        if (memcpy_s(forceDownDevId, NETWORK_ID_BUF_LEN, conflictItem.devIdList, NETWORK_ID_BUF_LEN) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy networkId fail");
            FreeLinkConflictDevInfo(&conflictItem);
            return SOFTBUS_MEM_ERR;
        }
        ret = ForceDisconnectWifiDirect(FORCE_DOWN_TRANS, forceDownDevId, conflictItem.releaseLink,
            INVALID_P2P_REQUEST_ID);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "force disconnect wifidirect fail");
        }
        FreeLinkConflictDevInfo(&conflictItem);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "link conflict device not exists, no need force disconnect");
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t InitLinkWifiDirect(void)
{
    if (SoftBusMutexInit(&g_linkWifiDirectMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    g_forceDownList = (ListNode *)SoftBusCalloc(sizeof(ListNode));
    if (g_forceDownList == NULL) {
        LNN_LOGE(LNN_LANE, "malloc g_forceDownList fail");
        (void)SoftBusMutexDestroy(&g_linkWifiDirectMutex);
        return SOFTBUS_MALLOC_ERR;
    }
    ListInit(g_forceDownList);
    return SOFTBUS_OK;
}

void DeInitLinkWifiDirect(void)
{
    if (g_forceDownList == NULL) {
        return;
    }
    if (LinkWifiDirectLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link wifidirect lock fail");
        return;
    }
    ForceDownInfo *relinkItem = NULL;
    ForceDownInfo *relinkNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(relinkItem, relinkNext, g_forceDownList, ForceDownInfo, node) {
        ListDelete(&relinkItem->node);
        SoftBusFree(relinkItem);
    }
    SoftBusFree(g_forceDownList);
    g_forceDownList = NULL;
    LinkWifiDirectUnlock();
    SoftBusMutexUnlock(&g_linkWifiDirectMutex);
    (void)SoftBusMutexDestroy(&g_linkWifiDirectMutex);
}

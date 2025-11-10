/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_listener.h"

#include <securec.h>

#include "anonymizer.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_common.h"
#include "lnn_lane_communication_capability.h"
#include "lnn_lane_link.h"
#include "lnn_lane_link_ledger.h"
#include "lnn_log.h"
#include "lnn_node_info.h"
#include "lnn_trans_lane.h"
#include "bus_center_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "softbus_init_common.h"
#include "wifi_direct_manager.h"

const static LaneType SUPPORT_TYPE_LIST[] = {LANE_TYPE_HDLC, LANE_TYPE_TRANS, LANE_TYPE_CTRL};

typedef struct {
    uint32_t ref;
    LaneType laneType;
    uint64_t laneId;
    ListNode node;
} LaneBusinessInfo;

typedef struct {
    LaneType type;
    ListNode node;
    LaneStatusListener listener;
} LaneListenerInfo;

static SoftBusMutex g_laneStateListenerMutex;
static ListNode g_laneListenerList;
static ListNode g_laneBusinessInfoList;

static int32_t LaneListenerLock(void)
{
    return SoftBusMutexLock(&g_laneStateListenerMutex);
}

static void LaneListenerUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneStateListenerMutex);
}

static bool LaneTypeCheck(LaneType type)
{
    uint32_t size = sizeof(SUPPORT_TYPE_LIST) / sizeof(LaneType);
    for (uint32_t i = 0; i < size; i++) {
        if (SUPPORT_TYPE_LIST[i] == type) {
            return true;
        }
    }
    LNN_LOGE(LNN_LANE, "laneType=%{public}d not supported", type);
    return false;
}

static LaneBusinessInfo *GetLaneBusinessInfoWithoutLock(const LaneBusinessInfo *laneBusinessInfo)
{
    if (laneBusinessInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return NULL;
    }
    LaneBusinessInfo *item = NULL;
    LaneBusinessInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneBusinessInfoList, LaneBusinessInfo, node) {
        if (laneBusinessInfo->laneType == item->laneType &&
            laneBusinessInfo->laneId == item->laneId) {
            return item;
        }
    }
    return NULL;
}

int32_t UpdateLaneBusinessInfoItem(uint64_t oldLaneId, uint64_t newLaneId)
{
    if (oldLaneId == INVALID_LANE_ID || newLaneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneBusinessInfo laneBusinessInfo;
    (void)memset_s(&laneBusinessInfo, sizeof(LaneBusinessInfo), 0, sizeof(LaneBusinessInfo));
    laneBusinessInfo.laneId = oldLaneId;
    laneBusinessInfo.laneType = LANE_TYPE_TRANS;
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneBusinessInfo *item = GetLaneBusinessInfoWithoutLock(&laneBusinessInfo);
    if (item != NULL) {
        item->laneId = newLaneId;
        LNN_LOGI(LNN_LANE, "update oldLaneId=%{public}" PRIu64 ", newLaneId=%{public}" PRIu64, oldLaneId, newLaneId);
        LaneListenerUnlock();
        return SOFTBUS_OK;
    }
    LaneListenerUnlock();
    return SOFTBUS_NOT_FIND;
}

int32_t AddLaneBusinessInfoItem(LaneType laneType, uint64_t laneId)
{
    if (!LaneTypeCheck(laneType) || laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneBusinessInfo laneBusinessInfo;
    (void)memset_s(&laneBusinessInfo, sizeof(LaneBusinessInfo), 0, sizeof(LaneBusinessInfo));
    laneBusinessInfo.laneId = laneId;
    laneBusinessInfo.laneType = laneType;
    laneBusinessInfo.ref = 1;
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneBusinessInfo *item = GetLaneBusinessInfoWithoutLock(&laneBusinessInfo);
    if (item != NULL) {
        item->ref++;
        LNN_LOGI(LNN_LANE, "add laneBusiness succ, laneType=%{public}d, laneId=%{public}" PRIu64 ", ref=%{public}u",
            laneType, laneId, item->ref);
        LaneListenerUnlock();
        return SOFTBUS_OK;
    }
    LaneBusinessInfo *laneBusinessInfoItem = (LaneBusinessInfo *)SoftBusCalloc(sizeof(LaneBusinessInfo));
    if (laneBusinessInfoItem == NULL) {
        LNN_LOGE(LNN_LANE, "calloc laneBusinessInfoItem fail");
        LaneListenerUnlock();
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(laneBusinessInfoItem, sizeof(LaneBusinessInfo), &laneBusinessInfo,
        sizeof(LaneBusinessInfo)) != EOK) {
        SoftBusFree(laneBusinessInfoItem);
        LNN_LOGE(LNN_LANE, "memcpy laneBusinessInfo fail");
        LaneListenerUnlock();
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_laneBusinessInfoList, &laneBusinessInfoItem->node);
    LaneListenerUnlock();
    LNN_LOGI(LNN_LANE, "create new laneBusiness succ, laneType=%{public}d, laneId=%{public}" PRIu64 "",
            laneType, laneId);
    return SOFTBUS_OK;
}

int32_t DelLaneBusinessInfoItem(LaneType laneType, uint64_t laneId)
{
    if (!LaneTypeCheck(laneType)) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneBusinessInfo laneBusinessInfo;
    (void)memset_s(&laneBusinessInfo, sizeof(LaneBusinessInfo), 0, sizeof(LaneBusinessInfo));
    laneBusinessInfo.laneId = laneId;
    laneBusinessInfo.laneType = laneType;
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneBusinessInfo *item = GetLaneBusinessInfoWithoutLock(&laneBusinessInfo);
    if (item != NULL) {
        uint32_t ref = item->ref;
        if (item->ref != 0) {
            ref = --item->ref;
        }
        if (ref == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
        LNN_LOGI(LNN_LANE, "del laneBusiness succ, laneType=%{public}d, laneId=%{public}" PRIu64 ", ref=%{public}u",
            laneType, laneId, ref);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t FindLaneBusinessInfoByLinkInfo(const LaneLinkInfo *laneLinkInfo,
    uint32_t *resNum, LaneBusinessInfo *laneBusinessInfo, uint32_t laneBusinessNum)
{
    if (laneLinkInfo == NULL || laneBusinessInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    uint64_t laneId = GenerateLaneId(localUdid, laneLinkInfo->peerUdid, laneLinkInfo->type);
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    *resNum = 0;
    LaneBusinessInfo *item = NULL;
    LaneBusinessInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneBusinessInfoList, LaneBusinessInfo, node) {
        if (item->laneId == laneId) {
            if (memcpy_s(&laneBusinessInfo[(*resNum)++], sizeof(LaneBusinessInfo),
                item, sizeof(LaneBusinessInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy lane business info fail");
                LaneListenerUnlock();
                return SOFTBUS_MEM_ERR;
            }
        }
        if (*resNum >= laneBusinessNum) {
            LNN_LOGE(LNN_LANE, "find laneBusinessinfo num more than expected");
            break;
        }
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static LaneListenerInfo *LaneListenerIsExist(LaneType type)
{
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        if (type == item->type) {
            return item;
        }
    }
    return NULL;
}

static int32_t FindLaneListenerInfoByLaneType(LaneType type, LaneListenerInfo *laneListenerInfo)
{
    if (!LaneTypeCheck(type) || laneListenerInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo* item = LaneListenerIsExist(type);
    if (item == NULL) {
        LaneListenerUnlock();
        LNN_LOGE(LNN_LANE, "lane listener is not exist");
        return SOFTBUS_LANE_NOT_FOUND;
    }
    laneListenerInfo->type = item->type;
    laneListenerInfo->listener = item->listener;
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t LaneLinkupNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo)
{
    if (peerUdid == NULL || laneLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneProfile profile;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    LaneConnInfo laneConnInfo;
    (void)memset_s(&laneConnInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    int32_t ret = LaneInfoProcess(laneLinkInfo, &laneConnInfo, &profile);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "laneInfo proc fail");
        return ret;
    }
    LaneListenerInfo listenerList[LANE_TYPE_BUTT];
    (void)memset_s(listenerList, sizeof(listenerList), 0, sizeof(listenerList));
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        listenerList[item->type].listener = item->listener;
    }
    LaneListenerUnlock();
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    uint64_t laneId = GenerateLaneId(localUdid, peerUdid, laneLinkInfo->type);
    for (uint32_t i = 0; i < LANE_TYPE_BUTT; i++) {
        if (listenerList[i].listener.onLaneLinkup != NULL) {
            LNN_LOGI(LNN_LANE, "notify lane linkup, laneType=%{public}u", i);
            listenerList[i].listener.onLaneLinkup(laneId, peerUdid, &laneConnInfo);
        }
    }
    return SOFTBUS_OK;
}

int32_t LaneLinkdownNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo)
{
    if (peerUdid == NULL || laneLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, laneLinkInfo->type, &resourceItem) == SOFTBUS_OK) {
        if (laneLinkInfo->type == LANE_HML) {
            RemoveDelayDestroyMessage(resourceItem.laneId);
        }
        DelLogicAndLaneRelationship(resourceItem.laneId);
        ClearLaneResourceByLaneId(resourceItem.laneId);
    }
    if (laneLinkInfo->type == LANE_HML &&
        FindLaneResourceByLinkType(peerUdid, LANE_HML_RAW, &resourceItem) == SOFTBUS_OK) {
        DelLogicAndLaneRelationship(resourceItem.laneId);
        ClearLaneResourceByLaneId(resourceItem.laneId);
    }
    uint32_t resNum;
    LaneBusinessInfo laneBusinessInfo[LANE_TYPE_BUTT];
    if (FindLaneBusinessInfoByLinkInfo(laneLinkInfo, &resNum, laneBusinessInfo, LANE_TYPE_BUTT) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "not found laneBusinessInfo, no need to notify");
        return SOFTBUS_OK;
    }
    LaneListenerInfo laneListener;
    LaneProfile profile;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    LaneConnInfo laneConnInfo;
    (void)memset_s(&laneConnInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    for (uint32_t i = 0; i < resNum; i++) {
        if (FindLaneListenerInfoByLaneType(laneBusinessInfo[i].laneType, &laneListener) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "find lane listener fail, laneType=%{public}d", laneBusinessInfo[i].laneType);
            continue;
        }
        if (laneListener.listener.onLaneLinkdown == NULL) {
            LNN_LOGE(LNN_STATE, "invalid lane status listen");
            continue;
        }
        if (LaneInfoProcess(laneLinkInfo, &laneConnInfo, &profile) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "laneInfo proc fail");
            continue;
        }
        LNN_LOGI(LNN_LANE, "notify lane linkdown, laneType=%{public}d", laneListener.type);
        laneListener.listener.onLaneLinkdown(laneBusinessInfo[i].laneId, peerUdid, &laneConnInfo);
    }
    return SOFTBUS_OK;
}

static int32_t GetRemoteUdidByUuid(const char *peerUuid, char *peerUdid)
{
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUuid(peerUuid, networkId, sizeof(networkId));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get networkId by uuid failed, ret=%{public}d", ret);
        return ret;
    }
    ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetStateNotifyInfo(const char *peerIp, const char *peerUuid, LaneLinkInfo *laneLinkInfo)
{
    if (peerIp == NULL || peerUuid == NULL || laneLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    laneLinkInfo->type = IsHmlIpAddr(peerIp) ? LANE_HML : LANE_P2P;
    if (strncpy_s(laneLinkInfo->linkInfo.p2p.connInfo.peerIp, IP_LEN, peerIp, IP_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "strncpy peerIp fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (GetRemoteUdidByUuid(peerUuid, laneLinkInfo->peerUdid) != SOFTBUS_OK) {
        char *anonyUuid = NULL;
        Anonymize(peerUuid, &anonyUuid);
        LNN_LOGE(LNN_STATE, "get remote udid failed, peerUuid=%{public}s", AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static void LnnOnWifiDirectDeviceOnline(const char *peerMac, const char *peerIp, const char *peerUuid, bool isSource)
{
    LNN_LOGI(LNN_LANE, "lnn wifidirect up");
    if (peerMac == NULL || peerUuid == NULL || peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (GetStateNotifyInfo(peerIp, peerUuid, &laneLinkInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get lane state notify info fail");
        return;
    }
    if (PostLaneStateChangeMessage(LANE_STATE_LINKUP, laneLinkInfo.peerUdid, &laneLinkInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post laneState linkup msg fail");
    }
}

static void LnnOnWifiDirectDeviceOffline(const char *peerMac, const char *peerIp, const char *peerUuid,
    const char *localIp)
{
    LNN_LOGI(LNN_LANE, "lnn wifidirect down");
    if (peerMac == NULL || peerUuid == NULL || peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (GetStateNotifyInfo(peerIp, peerUuid, &laneLinkInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get lane state notify info fail");
        return;
    }
    if (laneLinkInfo.type == LANE_HML && IsPowerControlEnabledPacked()) {
        DetectDisableWifiDirectApply();
    }
    if (PostLaneStateChangeMessage(LANE_STATE_LINKDOWN, laneLinkInfo.peerUdid, &laneLinkInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post laneState linkdown msg fail");
    }
}

static void LnnOnWifiDirectRoleChange(enum WifiDirectRole oldRole, enum WifiDirectRole newRole)
{
    LNN_LOGD(LNN_LANE, "lnn wifiDirect roleChange");
    (void)oldRole;
    (void)newRole;
}

int32_t RegisterLaneListener(LaneType type, const LaneStatusListener *listener)
{
    LNN_LOGI(LNN_LANE, "register lane listener, laneType=%{public}d", type);
    if (!LaneTypeCheck(type) || listener == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo *item = LaneListenerIsExist(type);
    if (item != NULL) {
        LaneListenerUnlock();
        return SOFTBUS_OK;
    }
    LaneListenerInfo *laneListenerItem = (LaneListenerInfo *)SoftBusCalloc(sizeof(LaneListenerInfo));
    if (laneListenerItem == NULL) {
        LNN_LOGE(LNN_LANE, "calloc lane listener fail");
        LaneListenerUnlock();
        return SOFTBUS_MALLOC_ERR;
    }
    laneListenerItem->type = type;
    laneListenerItem->listener = *listener;
    ListAdd(&g_laneListenerList, &laneListenerItem->node);
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t UnRegisterLaneListener(LaneType type)
{
    LNN_LOGI(LNN_LANE, "unregister lane listener, laneType=%{public}d", type);
    if (!LaneTypeCheck(type)) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo *item = LaneListenerIsExist(type);
    if (item != NULL) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t CreateSinkLinkInfo(const struct WifiDirectSinkLink *link, LaneLinkInfo *linkInfo)
{
    if (link == NULL || linkInfo == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    linkInfo->type = link->linkType == WIFI_DIRECT_LINK_TYPE_HML ? LANE_HML : LANE_P2P;
    LNN_LOGI(LNN_LANE, "bandWidth=%{public}d", link->bandWidth);
    linkInfo->linkInfo.p2p.bw = (LaneBandwidth)link->bandWidth;
    if (strcpy_s(linkInfo->linkInfo.p2p.connInfo.localIp, IP_LEN, link->localIp) != EOK ||
        strcpy_s(linkInfo->linkInfo.p2p.connInfo.peerIp, IP_LEN, link->remoteIp) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy Ip fail");
        return SOFTBUS_STRCPY_ERR;
    }
    linkInfo->linkInfo.p2p.channel = link->channelId;
    if (strncmp(link->remoteUuid, link->remoteMac, MAC_ADDR_STR_LEN) == 0) {
        LNN_LOGI(LNN_STATE, "is passive raw, update udid when refresh relationShip");
        if (strcpy_s(linkInfo->linkInfo.p2p.connInfo.remoteMac, MAC_ADDR_STR_LEN, link->remoteMac) != EOK) {
            LNN_LOGE(LNN_LANE, "strcpy udid fail");
            return SOFTBUS_STRCPY_ERR;
        }
        linkInfo->type = LANE_HML_RAW;
        return SOFTBUS_OK;
    }
    if (GetRemoteUdidByUuid(link->remoteUuid, linkInfo->peerUdid) != SOFTBUS_OK) {
        char *anonyUuid = NULL;
        Anonymize(link->remoteUuid, &anonyUuid);
        LNN_LOGE(LNN_STATE, "get remote udid failed, remoteUuid=%{public}s", AnonymizeWrapper(anonyUuid));
        AnonymizeFree(anonyUuid);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    return SOFTBUS_OK;
}

static void LnnOnWifiDirectConnectedForSink(const struct WifiDirectSinkLink *link)
{
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    char *anonyUuid = NULL;
    Anonymize(link->remoteUuid, &anonyUuid);
    LNN_LOGI(LNN_STATE, "on server link=%{public}d connected, uuid=%{public}s",
        link->linkType, AnonymizeWrapper(anonyUuid));
    AnonymizeFree(anonyUuid);
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (CreateSinkLinkInfo(link, &laneLinkInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "generate link info fail");
        return;
    }
    SetRemoteDynamicNetCap(laneLinkInfo.peerUdid, laneLinkInfo.type);
    LnnDeleteLinkLedgerInfo(laneLinkInfo.peerUdid);
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local udid fail");
        return;
    }
    uint64_t laneId = INVALID_LANE_ID;
    if (strlen(laneLinkInfo.peerUdid) != 0) {
        laneId = GenerateLaneId(localUdid, laneLinkInfo.peerUdid, laneLinkInfo.type);
    } else {
        laneId = GenerateLaneId(localUdid, link->remoteIp, laneLinkInfo.type);
    }
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "generate laneid fail");
        return;
    }
    if (AddLaneResourceToPool(&laneLinkInfo, laneId, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add server lane resource fail");
    }
    if (laneLinkInfo.type == LANE_HML && IsPowerControlEnabledPacked()) {
        DetectDisableWifiDirectApply();
    }
    (void)HandleLaneQosChange(&laneLinkInfo);
}

static void TryClearResourceWithoutUdid(const struct WifiDirectSinkLink *link)
{
    if (link->linkType != WIFI_DIRECT_LINK_TYPE_HML) {
        return;
    }
    uint64_t laneId = INVALID_LANE_ID;
    if (FindLaneIdByP2pMac(link->remoteMac, LANE_HML, &laneId) != SOFTBUS_OK &&
        FindLaneIdByP2pMac(link->remoteMac, LANE_HML_RAW, &laneId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "find hml lane resource fail");
        return;
    }
    DelLaneResourceByLaneId(laneId, true);
}

static void LnnOnWifiDirectDisconnectedForSink(const struct WifiDirectSinkLink *link)
{
    if (link == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    char *anonyUuid = NULL;
    Anonymize(link->remoteUuid, &anonyUuid);
    LNN_LOGI(LNN_STATE, "on server link=%{public}d disconnected, uuid=%{public}s",
        link->linkType, AnonymizeWrapper(anonyUuid));
    AnonymizeFree(anonyUuid);
    char remoteUdid[UDID_BUF_LEN] = {0};
    if (GetRemoteUdidByUuid(link->remoteUuid, remoteUdid) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get remote udid failed");
        TryClearResourceWithoutUdid(link);
        return;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (link->linkType == WIFI_DIRECT_LINK_TYPE_HML) {
        if (FindLaneResourceByLinkType(remoteUdid, LANE_HML, &resourceItem) != SOFTBUS_OK &&
            FindLaneResourceByLinkType(remoteUdid, LANE_HML_RAW, &resourceItem) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "find hml lane resource fail");
            return;
        }
    } else {
        if (FindLaneResourceByLinkType(remoteUdid, LANE_P2P, &resourceItem) != SOFTBUS_OK) {
            LNN_LOGE(LNN_STATE, "find p2p lane resource fail");
            return;
        }
    }
    DelLaneResourceByLaneId(resourceItem.laneId, true);
}

static void RegisterWifiDirectListener(void)
{
    struct WifiDirectStatusListener listener = {
        .onDeviceOffLine = LnnOnWifiDirectDeviceOffline,
        .onLocalRoleChange = LnnOnWifiDirectRoleChange,
        .onDeviceOnLine = LnnOnWifiDirectDeviceOnline,
        .onConnectedForSink = LnnOnWifiDirectConnectedForSink,
        .onDisconnectedForSink = LnnOnWifiDirectDisconnectedForSink,
    };
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr == NULL) {
        LNN_LOGE(LNN_LANE, "get wifiDirect manager null");
        return;
    }
    if (mgr->registerStatusListener != NULL) {
        LNN_LOGD(LNN_LANE, "regist listener to wifiDirect");
        mgr->registerStatusListener(&listener);
    }
}

static void ProcessRemoteBrConnected(const ConnectionInfo *info)
{
    LaneLinkInfo laneLinkInfo;
    NodeInfo nodeInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoByKey(info->brInfo.brMac, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote nodeInfo by brMac failed, ret=%{public}d", ret);
        return;
    }
    char *anonyUdid = NULL;
    Anonymize(nodeInfo.deviceInfo.deviceUdid, &anonyUdid);
    LNN_LOGI(LNN_LANE, "peerUdid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);

    laneLinkInfo.type = LANE_BR;
    if (strncpy_s(laneLinkInfo.peerUdid, UDID_BUF_LEN, nodeInfo.deviceInfo.deviceUdid, UDID_BUF_LEN) != EOK ||
        strncpy_s(laneLinkInfo.linkInfo.br.brMac, BT_MAC_LEN, info->brInfo.brMac, BT_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy fail");
        return;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get local udid fail");
        return;
    }
    uint64_t laneId = GenerateLaneId(localUdid, laneLinkInfo.peerUdid, laneLinkInfo.type);
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "generate laneId fail");
        return;
    }
    ret = AddLaneResourceToPool(&laneLinkInfo, laneId, true);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add server lane resource fail, ret=%{public}d", ret);
        return;
    }
}

static void ProcessRemoteBrDisconnected(const ConnectionInfo *info)
{
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnGetRemoteNodeInfoByKey(info->brInfo.brMac, &nodeInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote nodeInfo by brMac failed, ret=%{public}d", ret);
        return;
    }
    char *anonyUdid = NULL;
    Anonymize(nodeInfo.deviceInfo.deviceUdid, &anonyUdid);
    LNN_LOGI(LNN_LANE, "peerUdid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);

    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    ret = FindLaneResourceByLinkType(nodeInfo.deviceInfo.deviceUdid, LANE_BR, &resourceItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find lane resource fail, ret=%{public}d", ret);
        return;
    }
    (void)DelLaneResourceByLaneId(resourceItem.laneId, true);
}

static void OnCommConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "info is null");
        return;
    }
    LNN_LOGI(LNN_LANE, "connectionId=%{public}u, connType=%{public}d, isServer=%{public}d",
        connectionId, info->type, info->isServer);
    if (info->type == CONNECT_BR && info->isServer) {
        ProcessRemoteBrConnected(info);
    }
}

static void OnCommDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "info is null");
        return;
    }
    LNN_LOGI(LNN_LANE, "connectionId=%{public}u, connType=%{public}d, isServer=%{public}d",
        connectionId, info->type, info->isServer);
    if (info->type == CONNECT_BR && info->isServer) {
        ProcessRemoteBrDisconnected(info);
    }
}

static void OnCommDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    LNN_LOGD(LNN_LANE, "connectionId=%{public}u, moduleId=%{public}d, seq=%{public}" PRId64 ", len=%{public}d",
        connectionId, moduleId, seq, len);
    (void)data;
}

static void RegisterConnectListener(void)
{
    ConnectCallback connCb = {
        .OnConnected = OnCommConnected,
        .OnDisconnected = OnCommDisconnected,
        .OnDataReceived = OnCommDataReceived,
    };
    int32_t ret = ConnSetConnectCallback(MODULE_LANE_SELECT, &connCb);
    LNN_LOGI(LNN_LANE, "ConnSetConnectCallback, ret=%{public}d", ret);
}

int32_t InitLaneListener(void)
{
    if (SoftBusMutexInit(&g_laneStateListenerMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "g_laneStateListenerMutex init fail");
        return SOFTBUS_NO_INIT;
    }

    ListInit(&g_laneListenerList);
    ListInit(&g_laneBusinessInfoList);

    RegisterWifiDirectListener();
    RegisterConnectListener();
    return SOFTBUS_OK;
}

void DeinitLaneListener(void)
{
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return;
    }
    LaneBusinessInfo *businessItem = NULL;
    LaneBusinessInfo *businessNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(businessItem, businessNext, &g_laneBusinessInfoList, LaneBusinessInfo, node) {
        ListDelete(&businessItem->node);
        SoftBusFree(businessItem);
    }
    LaneListenerInfo *listenerItem = NULL;
    LaneListenerInfo *listenerNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(listenerItem, listenerNext, &g_laneListenerList, LaneListenerInfo, node) {
        ListDelete(&listenerItem->node);
        SoftBusFree(listenerItem);
    }
    LaneListenerUnlock();
    (void)SoftBusMutexDestroy(&g_laneStateListenerMutex);
}
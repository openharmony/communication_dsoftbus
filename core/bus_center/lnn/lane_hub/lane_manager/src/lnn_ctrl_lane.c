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

#include "lnn_ctrl_lane.h"

#include <securec.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_lane_common.h"
#include "lnn_lane_interface.h"
#include "lnn_log.h"
#include "lnn_lane_select.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "wifi_direct_manager.h"

typedef struct {
    uint32_t laneHandle;
    uint32_t linkListIdx;
    LaneAllocInfo allocInfo;
    uint64_t laneId;
    LanePreferredLinkList linkList;
    ListNode node;
    LaneAllocListener listener;
} CtrlReqInfo;

typedef struct {
    uint32_t cnt;
    ListNode list;
} CtrlLaneList;

static SoftBusMutex g_ctrlLaneMutex;
static CtrlLaneList *g_ctrlReqList = NULL;

static int32_t CtrlTriggerLink(uint32_t laneHandle);

static int32_t Lock(void)
{
    return SoftBusMutexLock(&g_ctrlLaneMutex);
}

static void Unlock(void)
{
    (void)SoftBusMutexUnlock(&g_ctrlLaneMutex);
}

static int32_t ConvertAuthLinkToLaneLink(AuthLinkTypeList *authLinkType, LanePreferredLinkList *laneLinkType)
{
    if (authLinkType == NULL || laneLinkType == NULL) {
        LNN_LOGE(LNN_LANE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    laneLinkType->linkTypeNum = 0;
    for (uint32_t i = 0; i < authLinkType->linkTypeNum; ++i) {
        switch (authLinkType->linkType[i]) {
            case AUTH_LINK_TYPE_WIFI:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_WLAN_5G;
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_WLAN_2P4G;
                break;
            case AUTH_LINK_TYPE_BR:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_BR;
                break;
            case AUTH_LINK_TYPE_BLE:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_BLE;
                break;
            case AUTH_LINK_TYPE_P2P:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_P2P;
                break;
            case AUTH_LINK_TYPE_ENHANCED_P2P:
                laneLinkType->linkType[laneLinkType->linkTypeNum++] = LANE_HML;
                break;
            default:
                break;
        }
    }
    return SOFTBUS_OK;
}

bool IsAuthReuseP2p(const char *networkId, const char *udid, AuthLinkType authType)
{
    LaneResource resoureItem;
    if (memset_s(&resoureItem, sizeof(LaneResource), 0, sizeof(LaneResource)) != EOK) {
        LNN_LOGE(LNN_LANE, "memset_s LaneResource fail");
        return false;
    }
    if (authType == AUTH_LINK_TYPE_ENHANCED_P2P &&
        FindLaneResourceByLinkType(udid, LANE_HML, &resoureItem) == SOFTBUS_OK &&
        !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, WIFI_DIRECT_LINK_TYPE_HML)) {
        LNN_LOGI(LNN_LANE, "can use HML");
        return true;
    } else if (authType == AUTH_LINK_TYPE_P2P &&
        FindLaneResourceByLinkType(udid, LANE_P2P, &resoureItem) == SOFTBUS_OK &&
        !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, WIFI_DIRECT_LINK_TYPE_P2P)) {
        LNN_LOGI(LNN_LANE, "can use P2P");
        return true;
    } else {
        return false;
    }
}

static int32_t GetCtrlReqInfo(uint32_t laneHandle, CtrlReqInfo *reqInfo)
{
    if (reqInfo == NULL || laneHandle == INVALID_LANE_REQ_ID) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    CtrlReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_ctrlReqList->list, CtrlReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            if (memcpy_s(reqInfo, sizeof(CtrlReqInfo), item, sizeof(CtrlReqInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy CtrlReqInfo fail");
                Unlock();
                return SOFTBUS_MEM_ERR;
            }
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    return SOFTBUS_LANE_NOT_FOUND;
}

static void DeleteCtrlRequestNode(uint32_t laneHandle)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    CtrlReqInfo *item = NULL;
    CtrlReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_ctrlReqList->list, CtrlReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_ctrlReqList->cnt--;
            break;
        }
    }
    Unlock();
}

static void CtrlLinkFail(uint32_t laneHandle, int32_t reason, LaneLinkType linkType)
{
    (void)linkType;
    CtrlReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(CtrlReqInfo), 0, sizeof(CtrlReqInfo));
    if (GetCtrlReqInfo(laneHandle, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        return;
    }
    if (reqInfo.linkListIdx >= reqInfo.linkList.linkTypeNum) {
        reqInfo.listener.onLaneAllocFail(laneHandle, reason);
        FreeLaneReqId(laneHandle);
        DeleteCtrlRequestNode(laneHandle);
        return;
    }
    CtrlTriggerLink(laneHandle);
}

static void UpdateCtrlReqInfo(uint32_t laneHandle, uint64_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    CtrlReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_ctrlReqList->list, CtrlReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            item->laneId = laneId;
            Unlock();
            return;
        }
    }
    Unlock();
}

static void CtrlNotifyLaneAllocSuccess(uint32_t laneHandle, uint64_t laneId, const LaneLinkInfo *info)
{
    UpdateCtrlReqInfo(laneHandle, laneId);
    CtrlReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(CtrlReqInfo), 0, sizeof(CtrlReqInfo));
    if (GetCtrlReqInfo(laneHandle, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        return;
    }

    LaneProfile profile;
    LaneConnInfo connInfo;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    if (LaneInfoProcess(info, &connInfo, &profile) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane alloc success, but laneInfo proc fail");
        return;
    }
    LNN_LOGI(LNN_LANE, "ctrl notify laneAlloc succ, laneHandle=%{public}u, linkType=%{public}d, "
        "laneId=%{public}" PRIu64 "", laneHandle, info->type, laneId);
    connInfo.laneId = laneId;
    reqInfo.listener.onLaneAllocSuccess(laneHandle, &connInfo);
}

static void CtrlLinkSuccess(uint32_t laneHandle, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkSuccess param invalid");
        return;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid fail, laneHandle=%{public}u", laneHandle);
        CtrlLinkFail(laneHandle, SOFTBUS_LANE_GET_LEDGER_INFO_ERR, linkType);
        return;
    }
    uint64_t laneId = GenerateLaneId(localUdid, linkInfo->peerUdid, linkInfo->type);
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "generate laneId fail, laneHandle=%{public}u", laneHandle);
        CtrlLinkFail(laneHandle, SOFTBUS_LANE_ID_GENERATE_FAIL, linkType);
        return;
    }
    int32_t ret = AddLaneResourceToPool(linkInfo, laneId, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add linkInfo item fail, laneHandle=%{public}u", laneHandle);
        CtrlLinkFail(laneHandle, ret, linkType);
        return;
    }
    CtrlNotifyLaneAllocSuccess(laneHandle, laneId, linkInfo);
}

static int32_t CreateLinkRequestNode(const LaneAllocInfo *allocInfo, LinkRequest *requestInfo)
{
    requestInfo->networkDelegate = allocInfo->extendInfo.networkDelegate;
    requestInfo->pid = allocInfo->pid;
    requestInfo->acceptableProtocols = allocInfo->acceptableProtocols;
    requestInfo->transType = allocInfo->transType;
    if (memcpy_s(requestInfo->peerNetworkId, NETWORK_ID_BUF_LEN,
        allocInfo->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(requestInfo->peerBleMac, MAX_MAC_LEN, allocInfo->extendInfo.peerBleMac, MAX_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CreateCtrlReqNode(uint32_t laneHandle, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener, LanePreferredLinkList *recommendLinkList)
{
    CtrlReqInfo *newNode = (CtrlReqInfo *)SoftBusCalloc(sizeof(CtrlReqInfo));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(&newNode->allocInfo, sizeof(LaneAllocInfo), allocInfo, sizeof(LaneAllocInfo)) != EOK ||
        memcpy_s(&newNode->listener, sizeof(LaneAllocListener), listener, sizeof(LaneAllocListener)) != EOK ||
        memcpy_s(&newNode->linkList, sizeof(LanePreferredLinkList), recommendLinkList,
            sizeof(LanePreferredLinkList)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for lane alloc listener");
        SoftBusFree(newNode);
        return SOFTBUS_MEM_ERR;
    }
    newNode->laneHandle = laneHandle;
    newNode->linkListIdx = 0;
    ListInit(&newNode->node);
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        SoftBusFree(newNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_ctrlReqList->list, &newNode->node);
    g_ctrlReqList->cnt++;
    Unlock();
    return SOFTBUS_OK;
}

static CtrlReqInfo *GetCtrlReqInfoWithoutLock(uint32_t laneHandle)
{
    CtrlReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_ctrlReqList->list, CtrlReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            return item;
        }
    }
    return NULL;
}

static int32_t CtrlTriggerLink(uint32_t laneHandle)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    CtrlReqInfo *reqInfo = GetCtrlReqInfoWithoutLock(laneHandle);
    if (reqInfo == NULL) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        Unlock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    LaneLinkCb linkCb = {
        .onLaneLinkSuccess = CtrlLinkSuccess,
        .onLaneLinkFail = CtrlLinkFail,
    };
    LinkRequest requestInfo = {0};
    int32_t ret = SOFTBUS_LANE_TRIGGER_LINK_FAIL;
    do {
        ret = CreateLinkRequestNode(&reqInfo->allocInfo, &requestInfo);
        if (ret != SOFTBUS_OK) {
            Unlock();
            LNN_LOGE(LNN_LANE, "Create LinkRequestNode fail.");
            break;
        }
        requestInfo.linkType = reqInfo->linkList.linkType[reqInfo->linkListIdx];
        reqInfo->linkListIdx++;
        Unlock();
        ret = BuildLink(&requestInfo, laneHandle, &linkCb);
        if (ret == SOFTBUS_OK) {
            return SOFTBUS_OK;
        }
    } while (false);
    linkCb.onLaneLinkFail(laneHandle, ret, requestInfo.linkType);
    return ret;
}

static int32_t AllocCtrlLane(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    AuthLinkTypeList authList;
    if (memset_s(&authList, sizeof(AuthLinkTypeList), 0, sizeof(AuthLinkTypeList)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = GetAuthLinkTypeList(allocInfo->networkId, &authList);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get authList fail");
        return ret;
    }
    LanePreferredLinkList request;
    if (memset_s(&request, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList)) != EOK) {
        LNN_LOGE(LNN_LANE, "memset_s request fail");
        return SOFTBUS_MEM_ERR;
    }
    ret = ConvertAuthLinkToLaneLink(&authList, &request);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "convert authLink to laneLink fail");
        return ret;
    }
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "calloc recommendLinkList fail");
        return SOFTBUS_MALLOC_ERR;
    }
    recommendLinkList->linkTypeNum = 0;
    ret = SelectAuthLane(allocInfo->networkId, &request, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "select auth lane fail, laneHandle=%{public}u", laneHandle);
        return ret;
    }
    for (uint32_t i = 0; i < recommendLinkList->linkTypeNum; ++i) {
        LNN_LOGI(LNN_LANE, "auth expect recommendLinkList nums=%{public}u, priority=%{public}u, link=%{public}u",
            recommendLinkList->linkTypeNum, i, recommendLinkList->linkType[i]);
    }
    if (CreateCtrlReqNode(laneHandle, allocInfo, listener, recommendLinkList) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "create ctrlReqInfo node fail.");
        return SOFTBUS_LANE_LIST_ERR;
    }
    ret = CtrlTriggerLink(laneHandle);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        DeleteCtrlRequestNode(laneHandle);
        LNN_LOGE(LNN_LANE, "trigger link fail, laneHandle=%{public}u", laneHandle);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t CtrlAlloc(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if (laneHandle == INVALID_LANE_REQ_ID || allocInfo == NULL || allocInfo->type != LANE_TYPE_CTRL) {
        LNN_LOGE(LNN_LANE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = AllocCtrlLane(laneHandle, allocInfo, listener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc valid lane fail, laneHandle=%{public}u", laneHandle);
        FreeLaneReqId(laneHandle);
        return ret;
    }
    return SOFTBUS_OK;
}

static void CtrlInit(const ILaneIdStateListener *listener)
{
    if (g_ctrlReqList != NULL) {
        LNN_LOGW(LNN_LANE, "already init");
        return;
    }
    if (SoftBusMutexInit(&g_ctrlLaneMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ctrlLane mutex init fail");
        return;
    }
    g_ctrlReqList = (CtrlLaneList *)SoftBusCalloc(sizeof(CtrlLaneList));
    if (g_ctrlReqList == NULL) {
        LNN_LOGE(LNN_LANE, "ctrlLane malloc fail");
        (void)SoftBusMutexDestroy(&g_ctrlLaneMutex);
        return;
    }
    ListInit(&g_ctrlReqList->list);
}

static void CtrlDeinit(void)
{
    if (g_ctrlReqList == NULL) {
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    CtrlReqInfo *item = NULL;
    CtrlReqInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ctrlReqList->list, CtrlReqInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
        g_ctrlReqList->cnt--;
    }
    Unlock();
    (void)SoftBusMutexDestroy(&g_ctrlLaneMutex);
    SoftBusFree(g_ctrlReqList);
    g_ctrlReqList = NULL;
}

static int32_t FreeLaneLink(uint32_t laneHandle, uint64_t laneId)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(laneId, &resourceItem) != SOFTBUS_OK) {
        return SOFTBUS_LANE_RESOURCE_NOT_FOUND;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByUdid(resourceItem.link.peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    DestroyLink(networkId, laneHandle, resourceItem.link.type);
    DelLaneResourceByLaneId(laneId, false);
    return SOFTBUS_OK;
}

static int32_t CtrlFree(uint32_t laneHandle)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    CtrlReqInfo *item = NULL;
    CtrlReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_ctrlReqList->list, CtrlReqInfo, node) {
        if (item->laneHandle == laneHandle) {
            ListDelete(&item->node);
            g_ctrlReqList->cnt--;
            Unlock();
            FreeLaneLink(laneHandle, item->laneId);
            SoftBusFree(item);
            FreeLaneReqId(laneHandle);
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGI(LNN_LANE, "no find lane need free, laneHandle=%{public}u", laneHandle);
    FreeLaneReqId(laneHandle);
    return SOFTBUS_OK;
}

static LaneInterface g_ctrlLaneObject = {
    .init = CtrlInit,
    .allocLaneByQos = CtrlAlloc,
    .freeLane = CtrlFree,
    .deinit = CtrlDeinit,
};

LaneInterface *CtrlLaneGetInstance(void)
{
    return &g_ctrlLaneObject;
}
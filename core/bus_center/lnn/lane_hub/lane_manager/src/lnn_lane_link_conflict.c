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

#include "lnn_lane_link_conflict.h"

#include <securec.h>

#include "anonymizer.h"
#include "lnn_lane_link_wifi_direct.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"

#define CONFLICT_INFO_TIMELINESS 30000

typedef enum {
    MSG_TYPE_CONFLICT_TIMELINESS = 0,
    MSG_TYPE_CONFLICT_BUTT,
} LinkConflictMsgType;

static SoftBusList g_linkConflictList;
static SoftBusHandler g_linkConflictLoopHandler;

static int32_t LinkConflictLock(void)
{
    return SoftBusMutexLock(&g_linkConflictList.lock);
}

static void LinkConflictUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_linkConflictList.lock);
}

static int32_t LinkConflictPostMsgToHandler(int32_t msgType, uint64_t param1, uint64_t param2,
    void *obj, uint64_t delayMillis)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "calloc link conflict handler msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (g_linkConflictLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "linkConflictLoopHandler looper not init");
        SoftBusFree(msg);
        return SOFTBUS_NO_INIT;
    }
    msg->what = msgType;
    msg->arg1 = param1;
    msg->arg2 = param2;
    msg->handler = &g_linkConflictLoopHandler;
    msg->obj = obj;
    if (delayMillis == 0) {
        g_linkConflictLoopHandler.looper->PostMessage(g_linkConflictLoopHandler.looper, msg);
    } else {
        g_linkConflictLoopHandler.looper->PostMessageDelay(g_linkConflictLoopHandler.looper, msg, delayMillis);
    }
    return SOFTBUS_OK;
}

static int32_t PostConflictInfoTimelinessMsg(const char *peerNetworkId, LinkConflictType conflictType)
{
    if (peerNetworkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *anonynetworkId = NULL;
    Anonymize(peerNetworkId, &anonynetworkId);
    LNN_LOGI(LNN_LANE, "post conflict info timeliness msg, peerNetworkId=%{public}s, conflictType=%{public}d",
        anonynetworkId, conflictType);
    AnonymizeFree(anonynetworkId);
    LinkConflictInfo *linkConflictItem = (LinkConflictInfo *)SoftBusCalloc(sizeof(LinkConflictInfo));
    if (linkConflictItem == NULL) {
        LNN_LOGE(LNN_LANE, "calloc linkConflictItem fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(linkConflictItem->peerDevId, NETWORK_ID_BUF_LEN, peerNetworkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerDevId fail");
        SoftBusFree(linkConflictItem);
        return SOFTBUS_STRCPY_ERR;
    }
    linkConflictItem->conflictType = conflictType;
    int32_t ret = LinkConflictPostMsgToHandler(MSG_TYPE_CONFLICT_TIMELINESS, 0, 0,
        linkConflictItem, CONFLICT_INFO_TIMELINESS);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post link conflict msg fail");
        SoftBusFree(linkConflictItem);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t RemoveConflictInfoTimeliness(const SoftBusMessage *msg, void *data)
{
    if (msg == NULL || msg->obj == NULL || data == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LinkConflictInfo *linkConflictSrc = (LinkConflictInfo*)msg->obj;
    LinkConflictInfo *linkConflictDst = (LinkConflictInfo*)data;
    if (msg->what != MSG_TYPE_CONFLICT_TIMELINESS) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (strncmp(linkConflictSrc->peerDevId, linkConflictDst->peerDevId, NETWORK_ID_BUF_LEN) == 0 &&
        linkConflictSrc->conflictType == linkConflictDst->conflictType) {
        LNN_LOGI(LNN_LANE, "remove conflict info timeliness message success");
        SoftBusFree(linkConflictSrc);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

void RemoveConflictInfoTimelinessMsg(const char *peerNetworkId, LinkConflictType conflictType)
{
    if (peerNetworkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    char *anonynetworkId = NULL;
    Anonymize(peerNetworkId, &anonynetworkId);
    LNN_LOGI(LNN_LANE, "remove conflict info timeliness msg, peerNetworkId=%{public}s, conflictType=%{public}d",
        anonynetworkId, conflictType);
    AnonymizeFree(anonynetworkId);
    LinkConflictInfo linkConflictItem;
    (void)memset_s(&linkConflictItem, sizeof(LinkConflictInfo), 0, sizeof(LinkConflictInfo));
    if (strncpy_s(linkConflictItem.peerDevId, NETWORK_ID_BUF_LEN, peerNetworkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "strcpy peerDevId fail");
        return;
    }
    linkConflictItem.conflictType = conflictType;
    g_linkConflictLoopHandler.looper->RemoveMessageCustom(g_linkConflictLoopHandler.looper,
        &g_linkConflictLoopHandler, RemoveConflictInfoTimeliness, &linkConflictItem);
}

LinkConflictType GetConflictTypeWithErrcode(int32_t conflictErrcode)
{
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_P2P_GO_GC_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_PV2_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE) {
        return CONFLICT_ROLE;
    }
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_HML_NUM_LIMITED_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_P2P_NUM_LIMITED_CONFLICT) {
        return CONFLICT_LINK_NUM_LIMITED;
    }
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_55_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_225_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_255_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_525_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_555_CONFLICT) {
        return CONFLICT_THREE_VAP;
    }
    if (conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_HML_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_HML_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_P2P_CHIP_CONFLICT ||
        conflictErrcode == SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_HML_CHIP_CONFLICT) {
        return CONFLICT_SOFTAP;
    }
    return CONFLICT_BUTT;
}

static int32_t GenerateConflictInfo(const LinkConflictInfo *linkConflictSrc, LinkConflictInfo *linkConflictDst)
{
    if (linkConflictSrc == NULL || linkConflictDst == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (linkConflictDst->devIdCnt > 0) {
        SoftBusFree(linkConflictDst->devIdList);
        linkConflictDst->devIdList = NULL;
        linkConflictDst->devIdCnt = 0;
    }
    if (linkConflictSrc->devIdCnt > 0) {
        char (*devIdList)[NETWORK_ID_BUF_LEN] =
            (char (*)[NETWORK_ID_BUF_LEN])SoftBusCalloc(linkConflictSrc->devIdCnt * NETWORK_ID_BUF_LEN);
        if (devIdList == NULL) {
            LNN_LOGE(LNN_LANE, "calloc devIdList fail");
            return SOFTBUS_MALLOC_ERR;
        }
        linkConflictDst->devIdList = devIdList;
        if (memcpy_s(devIdList, linkConflictSrc->devIdCnt * NETWORK_ID_BUF_LEN,
            linkConflictSrc->devIdList, linkConflictSrc->devIdCnt * NETWORK_ID_BUF_LEN) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy devIdList fail");
            SoftBusFree(devIdList);
            linkConflictDst->devIdList = NULL;
            return SOFTBUS_MEM_ERR;
        }
        linkConflictDst->devIdCnt = linkConflictSrc->devIdCnt;
    }

    if (strncpy_s(linkConflictDst->peerDevId, NETWORK_ID_BUF_LEN,
        linkConflictSrc->peerDevId, NETWORK_ID_BUF_LEN) != EOK) {
        if (linkConflictDst->devIdCnt > 0) {
            SoftBusFree(linkConflictDst->devIdList);
            linkConflictDst->devIdList = NULL;
            linkConflictDst->devIdCnt = 0;
        }
        LNN_LOGE(LNN_LANE, "strcpy peerDevId fail");
        return SOFTBUS_STRCPY_ERR;
    }
    linkConflictDst->releaseLink = linkConflictSrc->releaseLink;
    linkConflictDst->conflictType = linkConflictSrc->conflictType;
    return SOFTBUS_OK;
}

static int32_t UpdateExistsLinkConflictInfo(const LinkConflictInfo *linkConflictInfo)
{
    if (linkConflictInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflictInfo lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (strncmp(item->peerDevId, linkConflictInfo->peerDevId, NETWORK_ID_BUF_LEN) == 0 &&
            item->conflictType == linkConflictInfo->conflictType) {
            int32_t ret = GenerateConflictInfo(linkConflictInfo, item);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "generate conflictDevInfo fail");
                LinkConflictUnlock();
                return ret;
            }
            LinkConflictUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    return SOFTBUS_LANE_NOT_FOUND;
}

static int32_t CreateNewLinkConflictInfo(const LinkConflictInfo *linkConflictInfo)
{
    LinkConflictInfo *linkConflictItem = (LinkConflictInfo *)SoftBusCalloc(sizeof(LinkConflictInfo));
    if (linkConflictItem == NULL) {
        LNN_LOGE(LNN_LANE, "calloc linkConflictItem fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = GenerateConflictInfo(linkConflictInfo, linkConflictItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "generate conflictDevInfo fail");
        SoftBusFree(linkConflictItem);
        return ret;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        SoftBusFree(linkConflictItem);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_linkConflictList.list, &linkConflictItem->node);
    g_linkConflictList.cnt++;
    LinkConflictUnlock();
    char *anonyNetworkId = NULL;
    Anonymize(linkConflictInfo->peerDevId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "create new conflict link success, peerNetworkId=%{public}s, conflictType=%{public}d, "
        "releaseLink=%{public}d", anonyNetworkId, linkConflictInfo->conflictType, linkConflictInfo->releaseLink);
    AnonymizeFree(anonyNetworkId);
    return SOFTBUS_OK;
}

int32_t DelLinkConflictInfo(const char *peerNetworkId, LinkConflictType conflictType)
{
    if (peerNetworkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    char *anonyPeerNetworkId = NULL;
    Anonymize(peerNetworkId, &anonyPeerNetworkId);
    LNN_LOGI(LNN_LANE, "start to del link conflict info by peerNetworkId=%{public}s, conflictType=%{public}d",
        anonyPeerNetworkId, conflictType);
    AnonymizeFree(anonyPeerNetworkId);
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (strncmp(item->peerDevId, peerNetworkId, NETWORK_ID_BUF_LEN) == 0 &&
            item->conflictType == conflictType) {
            ListDelete(&item->node);
            if (item->devIdCnt > 0) {
                SoftBusFree(item->devIdList);
                item->devIdList = NULL;
            }
            if (item->devIpCnt > 0) {
                SoftBusFree(item->devIpList);
                item->devIpList = NULL;
            }
            SoftBusFree(item);
            g_linkConflictList.cnt--;
            LinkConflictUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    LNN_LOGE(LNN_LANE, "not found link conflict info when del");
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t AddLinkConflictInfo(const LinkConflictInfo *linkConflictInfo)
{
    if (linkConflictInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = UpdateExistsLinkConflictInfo(linkConflictInfo);
    if (ret == SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update exists link conflict info success, update conflict info timeliness");
        RemoveConflictInfoTimelinessMsg(linkConflictInfo->peerDevId, linkConflictInfo->conflictType);
        ret = PostConflictInfoTimelinessMsg(linkConflictInfo->peerDevId, linkConflictInfo->conflictType);
        if (ret != SOFTBUS_OK) {
            (void)DelLinkConflictInfo(linkConflictInfo->peerDevId, linkConflictInfo->conflictType);
            LNN_LOGE(LNN_LANE, "post conflict info timeliness msg fail, reason=%{public}d", ret);
            return ret;
        }
        return SOFTBUS_OK;
    }
    ret = CreateNewLinkConflictInfo(linkConflictInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create new link conflict info fail, reason=%{public}d", ret);
        return ret;
    }
    ret = PostConflictInfoTimelinessMsg(linkConflictInfo->peerDevId, linkConflictInfo->conflictType);
    if (ret != SOFTBUS_OK) {
        (void)DelLinkConflictInfo(linkConflictInfo->peerDevId, linkConflictInfo->conflictType);
        LNN_LOGE(LNN_LANE, "post conflict info timeliness msg fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t FindLinkConflictInfoByDevId(const char *peerNetworkId, LinkConflictType conflictType,
    LinkConflictInfo *linkConflictInfo)
{
    if (peerNetworkId == NULL || linkConflictInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflict lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        if (strncmp(item->peerDevId, peerNetworkId, NETWORK_ID_BUF_LEN) == 0 &&
            item->conflictType == conflictType) {
            int32_t ret = GenerateConflictInfo(item, linkConflictInfo);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "generate link conflict devInfo fail");
                LinkConflictUnlock();
                return ret;
            }
            LinkConflictUnlock();
            return SOFTBUS_OK;
        }
    }
    LinkConflictUnlock();
    char *anonyPeerNetworkId = NULL;
    Anonymize(peerNetworkId, &anonyPeerNetworkId);
    LNN_LOGE(LNN_LANE, "not found link conflict info by peerNetworkId=%{public}s, conflictType=%{public}d",
        anonyPeerNetworkId, conflictType);
    AnonymizeFree(anonyPeerNetworkId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static void HandleConflictInfoTimeliness(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        return;
    }
    LinkConflictInfo *linkConflictItem = (LinkConflictInfo*)msg->obj;
    LNN_LOGI(LNN_LANE, "handle conflict info timeliness");
    if (DelLinkConflictInfo(linkConflictItem->peerDevId, linkConflictItem->conflictType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "del link conflict info fail");
    }
    SoftBusFree(linkConflictItem);
}

static void MsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg");
        return;
    }
    switch (msg->what) {
        case MSG_TYPE_CONFLICT_TIMELINESS:
            HandleConflictInfoTimeliness(msg);
            break;
        default:
            LNN_LOGE(LNN_LANE, "msg type=%{public}d not support", msg->what);
            break;
    }
    return;
}

static int32_t InitLinkConflictLooper(void)
{
    g_linkConflictLoopHandler.name = "linkConflictLooper";
    g_linkConflictLoopHandler.HandleMessage = MsgHandler;
    g_linkConflictLoopHandler.looper = GetLooper(LOOP_TYPE_LNN);
    if (g_linkConflictLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "link conflict init looper fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

int32_t InitLaneLinkConflict(void)
{
    if (InitLinkConflictLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init link conflict looper fail");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexInit(&g_linkConflictList.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link conflict mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_linkConflictList.list);
    g_linkConflictList.cnt = 0;

    if (InitLinkWifiDirect() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init link wifidirect fail");
        (void)SoftBusMutexDestroy(&g_linkConflictList.lock);
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

void DeinitLaneLinkConflict(void)
{
    DeInitLinkWifiDirect();
    g_linkConflictLoopHandler.HandleMessage = NULL;
    g_linkConflictLoopHandler.looper = NULL;
    if (LinkConflictLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkConflictInfo lock fail");
        return;
    }
    LinkConflictInfo *item = NULL;
    LinkConflictInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_linkConflictList.list, LinkConflictInfo, node) {
        ListDelete(&item->node);
        if (item->devIdCnt > 0) {
            SoftBusFree(item->devIdList);
        }
        if (item->devIpCnt > 0) {
            SoftBusFree(item->devIpList);
        }
        SoftBusFree(item);
        g_linkConflictList.cnt--;
    }
    LinkConflictUnlock();
    (void)SoftBusMutexDestroy(&g_linkConflictList.lock);
}

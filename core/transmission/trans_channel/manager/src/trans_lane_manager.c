/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "trans_lane_manager.h"

#include <securec.h>
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_log.h"
#include "softbus_hidumper_trans.h"

#define CMD_CONCURRENT_SESSION_LIST "concurrent_sessionlist"
typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t channelType;
    char pkgName[PKG_NAME_SIZE_MAX];
    int32_t pid;
    uint32_t laneId;
    LaneConnInfo laneConnInfo;
} TransLaneInfo;

static SoftBusList *g_channelLaneList = NULL;

static void GetTransSessionInfoByLane(TransLaneInfo * laneItem, AppInfo *appInfo)
{
    if (TransGetAppInfoByChanId(laneItem->channelId, laneItem->channelType, appInfo) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "TransGetAppInfoByChanId get appInfo failed");
    }
}

static TransDumpLaneLinkType ConvertLaneLinkTypeToDumper(LaneLinkType type)
{
    switch (type) {
        case LANE_BR:
            return DUMPER_LANE_BR;
        case LANE_BLE:
            return DUMPER_LANE_BLE;
        case LANE_P2P:
            return DUMPER_LANE_P2P;
        case LANE_WLAN_2P4G:
            return DUMPER_LANE_WLAN;
        case LANE_WLAN_5G:
            return DUMPER_LANE_WLAN;
        case LANE_ETH:
            return DUMPER_LANE_ETH;
        default:
            break;
    }
    return DUMPER_LANE_LINK_TYPE_BUTT;
}

static int32_t TransLaneChannelForEachShowInfo(int fd)
{
    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return SOFTBUS_ERR;
    }
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "TransSessionInfoForEach malloc appInfo failed");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        SoftBusFree(appInfo);
        return SOFTBUS_ERR;
    }

    TransLaneInfo *laneItem = NULL;
    LIST_FOR_EACH_ENTRY(laneItem, &(g_channelLaneList->list), TransLaneInfo, node) {
        GetTransSessionInfoByLane(laneItem, appInfo);
        SoftBusTransDumpRunningSession(fd,
            ConvertLaneLinkTypeToDumper(laneItem->laneConnInfo.type), appInfo);
    }

    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    SoftBusFree(appInfo);
    return SOFTBUS_OK;
}

int32_t TransLaneMgrInit(void)
{
    if (g_channelLaneList != NULL) {
        TRANS_LOGI(TRANS_INIT, "trans lane info manager has init.");
        return SOFTBUS_OK;
    }
    g_channelLaneList = CreateSoftBusList();
    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane info manager init failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    
    return SoftBusRegTransVarDump(CMD_CONCURRENT_SESSION_LIST, TransLaneChannelForEachShowInfo);
}

void TransLaneMgrDeinit(void)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (g_channelLaneList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_channelLaneList->lock) != 0) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *nextLaneItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, nextLaneItem, &g_channelLaneList->list, TransLaneInfo, node) {
        ListDelete(&(laneItem->node));
        LnnFreeLane(laneItem->laneId);
        SoftBusFree(laneItem);
    }
    g_channelLaneList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_channelLaneList->lock);
    DestroySoftBusList(g_channelLaneList);
    g_channelLaneList = NULL;
}

int32_t TransLaneMgrAddLane(int32_t channelId, int32_t channelType, LaneConnInfo *connInfo,
    uint32_t laneId, AppInfoData *myData)
{
    if (g_channelLaneList == NULL || connInfo == NULL) {
        return SOFTBUS_ERR;
    }

    TransLaneInfo *newLane = (TransLaneInfo *)SoftBusCalloc(sizeof(TransLaneInfo));
    if (newLane == NULL) {
        return SOFTBUS_MEM_ERR;
    }
    newLane->channelId = channelId;
    newLane->channelType = channelType;
    newLane->laneId = laneId;
    newLane->pid = myData->pid;
    if (memcpy_s(&(newLane->laneConnInfo), sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK) {
        SoftBusFree(newLane);
        TRANS_LOGE(TRANS_SVC, "memcpy failed.");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(newLane->pkgName, sizeof(newLane->pkgName), myData->pkgName) != EOK) {
        SoftBusFree(newLane);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        SoftBusFree(newLane);
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransLaneInfo *laneItem = NULL;
    LIST_FOR_EACH_ENTRY(laneItem, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (laneItem->channelId == channelId && laneItem->channelType == channelType) {
            SoftBusFree(newLane);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            TRANS_LOGI(TRANS_SVC,
                "trans lane info has existed. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
            return SOFTBUS_ERR;
        }
    }
    ListInit(&(newLane->node));
    ListAdd(&(g_channelLaneList->list), &(newLane->node));
    TRANS_LOGI(TRANS_CTRL, "add channelId = %{public}d", newLane->channelId);
    g_channelLaneList->cnt++;
    TRANS_LOGI(TRANS_SVC, "lane count is cnt=%{public}d", g_channelLaneList->cnt);
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_OK;
}

int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType)
{
    TRANS_LOGI(TRANS_SVC, "del trans land mgr. chanId=%{public}d channelType=%{public}d", channelId, channelType);
    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (laneItem->channelId == channelId && laneItem->channelType == channelType) {
            ListDelete(&(laneItem->node));
            TRANS_LOGI(TRANS_CTRL, "delete channelId = %{public}d, channelType = %{public}d",
                laneItem->channelId, laneItem->channelType);
            g_channelLaneList->cnt--;
            LnnFreeLane(laneItem->laneId);
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane not found. channelId=%{public}d, channelType=%{public}d",
        channelId, channelType);
    return SOFTBUS_ERR;
}

void TransLaneMgrDeathCallback(const char *pkgName, int32_t pid)
{
    if (pkgName == NULL || g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return;
    }
    TRANS_LOGW(TRANS_CTRL, "TransLaneMgrDeathCallback: pkgName=%{public}s, pid=%{public}d", pkgName, pid);
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_channelLaneList->list), TransLaneInfo, node) {
        if ((strcmp(laneItem->pkgName, pkgName) == 0) && (laneItem->pid == pid)) {
            ListDelete(&(laneItem->node));
            g_channelLaneList->cnt--;
            TRANS_LOGI(TRANS_SVC, "death del lane. pkgName=%{public}s, channelId=%{public}d, channelType=%{public}d",
                pkgName, laneItem->channelId, laneItem->channelType);
            LnnFreeLane(laneItem->laneId);
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return;
}

int32_t TransGetLaneIdByChannelId(int32_t channelId, uint32_t *laneId)
{
    if ((laneId == NULL) || (g_channelLaneList == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->channelId == channelId) {
            *laneId = item->laneId;
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_ERR;
}

int32_t TransGetChannelInfoByLaneId(uint32_t laneId, int32_t *channelId, int32_t *channelType)
{
    if ((channelId == NULL) || (channelType == NULL) || (g_channelLaneList == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->laneId == laneId) {
            *channelId = item->channelId;
            *channelType = item->channelType;
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_ERR;
}
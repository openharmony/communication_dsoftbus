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
#include <unistd.h>
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "softbus_hidumper_trans.h"

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t channelType;
    char pkgName[PKG_NAME_SIZE_MAX];
    uint32_t laneId;
    LaneConnInfo laneConnInfo;
} TransLaneInfo;

static SoftBusList *g_channelLaneList = NULL;

static void GetTransSessionInfoByLane(TransLaneInfo * laneItem, AppInfo *appInfo)
{
    if (TransGetAppInfoByChanId(laneItem->channelId, laneItem->channelType, appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransGetAppInfoByChanId get appInfo failed");
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

static void TransLaneChannelForEachShowInfo(int fd)
{
    if (g_channelLaneList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane manager hasn't initialized.");
        return;
    }
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "TransSessionInfoForEach malloc appInfo failed");
        return;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        SoftBusFree(appInfo);
        return;
    }
        
    TransLaneInfo *laneItem = NULL;
    LIST_FOR_EACH_ENTRY(laneItem, &(g_channelLaneList->list), TransLaneInfo, node) {
        GetTransSessionInfoByLane(laneItem, appInfo);
        SoftBusTransDumpRunningSession(fd,
            ConvertLaneLinkTypeToDumper(laneItem->laneConnInfo.type), appInfo);
    }
    
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    SoftBusFree(appInfo);
}

int32_t TransLaneMgrInit(void)
{
    if (g_channelLaneList != NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "trans lane info manager hasn't initialized.");
        return SOFTBUS_OK;
    }
    g_channelLaneList = CreateSoftBusList();
    if (g_channelLaneList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane info manager init failed.");
        return SOFTBUS_MALLOC_ERR;
    }

    SetShowRunningSessionInfosFunc(TransLaneChannelForEachShowInfo);
    
    return SOFTBUS_OK;
}

void TransLaneMgrDeinit(void)
{
    if (g_channelLaneList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_channelLaneList->lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
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

int32_t TransLaneMgrAddLane(int32_t channelId, int32_t channelType, LaneConnInfo *connInfo, uint32_t laneId,
    const char *pkgName)
{
    if (g_channelLaneList == NULL) {
        return SOFTBUS_ERR;
    }

    TransLaneInfo *newLane = (TransLaneInfo *)SoftBusCalloc(sizeof(TransLaneInfo));
    if (newLane == NULL) {
        return SOFTBUS_MEM_ERR;
    }
    newLane->channelId = channelId;
    newLane->channelType = channelType;
    newLane->laneId = laneId;
    if (memcpy_s(&(newLane->laneConnInfo), sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK) {
        SoftBusFree(newLane);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy failed.");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(newLane->pkgName, sizeof(newLane->pkgName), pkgName) != EOK) {
        SoftBusFree(newLane);
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        SoftBusFree(newLane);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransLaneInfo *laneItem = NULL;
    LIST_FOR_EACH_ENTRY(laneItem, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (laneItem->channelId == channelId && laneItem->channelType == channelType) {
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO,
                "trans lane info has exited.[channelId = %d, channelType = %d]", channelId, channelType);
            SoftBusFree(newLane);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_ERR;
        }
    }
    ListInit(&(newLane->node));
    ListAdd(&(g_channelLaneList->list), &(newLane->node));
    g_channelLaneList->cnt++;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "lane num is %d", g_channelLaneList->cnt);
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_OK;
}

int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "del trans land mgr.[chanid=%d][type=%d]", channelId, channelType);
    if (g_channelLaneList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane manager hasn't initialized.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (laneItem->channelId == channelId && laneItem->channelType == channelType) {
            ListDelete(&(laneItem->node));
            g_channelLaneList->cnt--;
            LnnFreeLane(laneItem->laneId);
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane not found.[channelId = %d, channelType = %d]",
        channelId, channelType);
    return SOFTBUS_ERR;
}

void TransLaneMgrDeathCallback(const char *pkgName)
{
    if (g_channelLaneList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "trans lane manager hasn't initialized.");
        return;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (strcmp(laneItem->pkgName, pkgName) == 0) {
            ListDelete(&(laneItem->node));
            g_channelLaneList->cnt--;
            LnnFreeLane(laneItem->laneId);
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "%s death del lane[id=%d, type = %d]",
                pkgName, laneItem->channelId, laneItem->channelType);
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
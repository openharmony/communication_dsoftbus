/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "trans_channel_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_log.h"
#include "legacy/softbus_hidumper_trans.h"
#include "trans_session_manager.h"

#define CMD_CONCURRENT_SESSION_LIST "concurrent_sessionlist"

typedef struct {
    ListNode node;
    char sessionName[SESSION_NAME_SIZE_MAX];
    pid_t pid;
    int32_t sessionId;
    int32_t channelId;
    int32_t channelType;
    uint32_t laneHandle;
    CoreSessionState state;
    bool isAsync;
    bool isQosLane;
} SocketWithChannelInfo;

static SoftBusList *g_channelLaneList = NULL;

static SoftBusList *g_socketChannelList = NULL;

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

static int32_t TransLaneChannelForEachShowInfo(int32_t fd)
{
    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "TransSessionInfoForEach malloc appInfo failed");
        return SOFTBUS_MALLOC_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        SoftBusFree(appInfo);
        return SOFTBUS_LOCK_ERR;
    }

    TransLaneInfo *laneItem = NULL;
    LIST_FOR_EACH_ENTRY(laneItem, &(g_channelLaneList->list), TransLaneInfo, node) {
        GetTransSessionInfoByLane(laneItem, appInfo);
        SoftBusTransDumpRunningSession(fd,
            ConvertLaneLinkTypeToDumper(laneItem->laneConnInfo.type), appInfo);
    }

    (void)memset_s(appInfo->sessionKey, sizeof(appInfo->sessionKey), 0, sizeof(appInfo->sessionKey));
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

int32_t TransSocketLaneMgrInit(void)
{
    if (g_socketChannelList != NULL) {
        TRANS_LOGI(TRANS_INIT, "trans lane info manager has init.");
        return SOFTBUS_OK;
    }
    g_socketChannelList = CreateSoftBusList();
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane info manager init failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

void TransLaneMgrDeinit(void)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (g_channelLaneList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_channelLaneList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *nextLaneItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, nextLaneItem, &g_channelLaneList->list, TransLaneInfo, node) {
        ListDelete(&(laneItem->node));
        if (laneItem->isQosLane) {
            TransFreeLaneByLaneHandle(laneItem->laneHandle, true);
        } else {
            LnnFreeLane(laneItem->laneHandle);
        }
        SoftBusFree(laneItem);
    }
    g_channelLaneList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_channelLaneList->lock);
    DestroySoftBusList(g_channelLaneList);
    g_channelLaneList = NULL;
}

void TransSocketLaneMgrDeinit(void)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (g_socketChannelList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&g_socketChannelList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    SocketWithChannelInfo *socketItem = NULL;
    SocketWithChannelInfo *nextSocketItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(socketItem, nextSocketItem, &g_socketChannelList->list, SocketWithChannelInfo, node) {
        ListDelete(&(socketItem->node));
        SoftBusFree(socketItem);
    }
    g_socketChannelList->cnt = 0;
    (void)SoftBusMutexUnlock(&g_socketChannelList->lock);
    DestroySoftBusList(g_socketChannelList);
    g_socketChannelList = NULL;
}

int32_t TransLaneMgrAddLane(
    const TransInfo *transInfo, const LaneConnInfo *connInfo, uint32_t laneHandle, bool isQosLane, AppInfoData *myData)
{
    if (transInfo == NULL || g_channelLaneList == NULL || connInfo == NULL || myData == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    TransLaneInfo *newLane = (TransLaneInfo *)SoftBusCalloc(sizeof(TransLaneInfo));
    TRANS_CHECK_AND_RETURN_RET_LOGE(newLane != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "calloc laneInfo failed.");
    newLane->channelId = transInfo->channelId;
    newLane->channelType = transInfo->channelType;
    newLane->laneHandle = laneHandle;
    newLane->isQosLane = isQosLane;
    newLane->pid = myData->pid;
    if (memcpy_s(&(newLane->laneConnInfo), sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK) {
        SoftBusFree(newLane);
        TRANS_LOGE(TRANS_SVC, "memcpy connInfo failed");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(newLane->pkgName, sizeof(newLane->pkgName), myData->pkgName) != EOK) {
        SoftBusFree(newLane);
        TRANS_LOGE(TRANS_SVC, "strcpy failed.");
        return SOFTBUS_STRCPY_ERR;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        SoftBusFree(newLane);
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransLaneInfo *laneItem = NULL;
    LIST_FOR_EACH_ENTRY(laneItem, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (laneItem->channelId == transInfo->channelId && laneItem->channelType == transInfo->channelType) {
            SoftBusFree(newLane);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            TRANS_LOGI(TRANS_SVC, "trans lane info has existed. channelId=%{public}d, channelType=%{public}d",
                transInfo->channelId, transInfo->channelType);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }
    ListInit(&(newLane->node));
    ListAdd(&(g_channelLaneList->list), &(newLane->node));
    TRANS_LOGI(TRANS_CTRL, "add channelId=%{public}d", newLane->channelId);
    g_channelLaneList->cnt++;
    TRANS_LOGI(TRANS_SVC, "lane count is cnt=%{public}d", g_channelLaneList->cnt);
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_OK;
}

int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType, bool isAsync)
{
    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *next = NULL;
    int32_t ret = SOFTBUS_TRANS_NODE_NOT_FOUND;
    uint32_t laneHandle = 0;
    bool isQos = false;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (laneItem->channelId == channelId && laneItem->channelType == channelType) {
            ListDelete(&(laneItem->node));
            TRANS_LOGI(TRANS_CTRL, "delete channelId=%{public}d, channelType = %{public}d",
                laneItem->channelId, laneItem->channelType);
            g_channelLaneList->cnt--;
            laneHandle = laneItem->laneHandle;
            if (laneItem->isQosLane) {
                isQos = true;
            }
            SoftBusFree(laneItem);
            ret = SOFTBUS_OK;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_SVC, "No lane to be is found. channelId=%{public}d.", channelId);
        return ret;
    }
    if (isQos) {
        TransFreeLaneByLaneHandle(laneHandle, isAsync);
    } else {
        LnnFreeLane(laneHandle);
    }
    return ret;
}

void TransLaneMgrDeathCallback(const char *pkgName, int32_t pid)
{
    (void)TransDeleteSocketChannelInfoByPid(pid);
    if (pkgName == NULL || g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return;
    }
    char *anonymizePkgName = NULL;
    Anonymize(pkgName, &anonymizePkgName);
    TRANS_LOGW(TRANS_CTRL, "pkgName=%{public}s, pid=%{public}d", AnonymizeWrapper(anonymizePkgName), pid);
    AnonymizeFree(anonymizePkgName);
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    TransLaneInfo *laneItem = NULL;
    TransLaneInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_channelLaneList->list), TransLaneInfo, node) {
        if ((strcmp(laneItem->pkgName, pkgName) == 0) && (laneItem->pid == pid)) {
            ListDelete(&(laneItem->node));
            g_channelLaneList->cnt--;
            TRANS_LOGI(TRANS_SVC, "death del lane. channelId=%{public}d, channelType=%{public}d",
                laneItem->channelId, laneItem->channelType);
            if (laneItem->isQosLane) {
                TransFreeLaneByLaneHandle(laneItem->laneHandle, true);
            } else {
                LnnFreeLane(laneItem->laneHandle);
            }
            SoftBusFree(laneItem);
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return;
}

int32_t TransGetLaneHandleByChannelId(int32_t channelId, uint32_t *laneHandle)
{
    if (g_channelLaneList == NULL || laneHandle == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->channelId == channelId) {
            *laneHandle = item->laneHandle;
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransGetLaneIdByChannelId(int32_t channelId, uint64_t *laneId)
{
    if (g_channelLaneList == NULL || laneId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != 0) {
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->channelId == channelId) {
            *laneId = item->laneConnInfo.laneId;
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t TransGetChannelInfoByLaneHandle(uint32_t laneHandle, int32_t *channelId, int32_t *channelType)
{
    if (g_channelLaneList == NULL || channelId == NULL || channelType == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->laneHandle == laneHandle) {
            *channelId = item->channelId;
            *channelType = item->channelType;
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

static SocketWithChannelInfo *GetSocketWithChannelInfoBySession(const char *sessionName, int32_t sessionId)
{
    // need get lock before
    SocketWithChannelInfo *socketItem = NULL;
    LIST_FOR_EACH_ENTRY(socketItem, &(g_socketChannelList->list), SocketWithChannelInfo, node) {
        if (strcmp(socketItem->sessionName, sessionName) == 0 && socketItem->sessionId == sessionId) {
            return socketItem;
        }
    }
    return NULL;
}

static void AnonymizeLogSessionNameWhenNotFound(const char *sessionName, int32_t sessionId)
{
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(
        TRANS_SVC, "socket info not found. sessionName=%{public}s, sessionId=%{public}d",
            AnonymizeWrapper(tmpName), sessionId);
    AnonymizeFree(tmpName);
}

int32_t TransAddSocketChannelInfo(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType, CoreSessionState state)
{
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_SVC, "Invaild param, sessionName is null");
        return SOFTBUS_TRANS_INVALID_SESSION_NAME;
    }
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SVC, "Invaild param, sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_socketChannelList != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "socket info manager hasn't init.");

    SocketWithChannelInfo *newSocket = (SocketWithChannelInfo *)SoftBusCalloc(sizeof(SocketWithChannelInfo));
    TRANS_CHECK_AND_RETURN_RET_LOGE(newSocket != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "socket info calloc failed.");
    if (strcpy_s(newSocket->sessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        SoftBusFree(newSocket);
        return SOFTBUS_STRCPY_ERR;
    }
    newSocket->sessionId = sessionId;
    newSocket->channelId = channelId;
    newSocket->channelType = channelType;
    newSocket->state = state;
    newSocket->laneHandle = INVALID_LANE_REQ_ID;
    newSocket->isQosLane = false;
    newSocket->isAsync = false;
    int32_t tmpUid;
    TransGetUidAndPid(sessionName, &tmpUid, &(newSocket->pid));

    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        SoftBusFree(newSocket);
        return SOFTBUS_LOCK_ERR;
    }

    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        char *tmpName = NULL;
        Anonymize(sessionName, &tmpName);
        TRANS_LOGI(
            TRANS_SVC, "socket lane info has existed. socketId=%{public}d, sessionName=%{public}s",
                sessionId, AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        SoftBusFree(newSocket);
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }

    ListInit(&(newSocket->node));
    ListAdd(&(g_socketChannelList->list), &(newSocket->node));
    g_socketChannelList->cnt++;
    TRANS_LOGI(TRANS_SVC, "socket lane count is cnt=%{public}d", g_socketChannelList->cnt);
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    return SOFTBUS_OK;
}

static int32_t CheckParamIsValid(const char *sessionName, int32_t sessionId)
{
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_SVC, "Invaild param, sessionName is null");
        return SOFTBUS_TRANS_INVALID_SESSION_NAME;
    }
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SVC, "Invaild param, sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    return SOFTBUS_OK;
}

int32_t TransUpdateSocketChannelInfoBySession(
    const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        socketItem->channelId = channelId;
        socketItem->channelType = channelType;
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUpdateSocketChannelLaneInfoBySession(
    const char *sessionName, int32_t sessionId, uint32_t laneHandle, bool isQosLane, bool isAsync)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        socketItem->laneHandle = laneHandle;
        socketItem->isQosLane = isQosLane;
        socketItem->isAsync = isAsync;
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransDeleteSocketChannelInfoBySession(const char *sessionName, int32_t sessionId)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = NULL;
    SocketWithChannelInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(socketItem, next, &(g_socketChannelList->list), SocketWithChannelInfo, node) {
        if (strcmp(socketItem->sessionName, sessionName) == 0 && socketItem->sessionId == sessionId) {
            ListDelete(&(socketItem->node));
            g_socketChannelList->cnt--;
            SoftBusFree(socketItem);
            (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
            char *tmpName = NULL;
            Anonymize(sessionName, &tmpName);
            TRANS_LOGI(TRANS_CTRL, "delete socket channel info, sessionName=%{public}s, sessionId=%{public}d",
                AnonymizeWrapper(tmpName), sessionId);
            AnonymizeFree(tmpName);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransDeleteSocketChannelInfoByChannel(int32_t channelId, int32_t channelType)
{
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = NULL;
    SocketWithChannelInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(socketItem, next, &(g_socketChannelList->list), SocketWithChannelInfo, node) {
        if (socketItem->channelId == channelId && socketItem->channelType == channelType) {
            ListDelete(&(socketItem->node));
            g_socketChannelList->cnt--;
            SoftBusFree(socketItem);
            (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
            TRANS_LOGI(TRANS_CTRL, "delete socket channel info, channelId=%{public}d, channelType=%{public}d",
                channelId, channelType);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    TRANS_LOGD(
        TRANS_SVC, "socket info not found. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_NOT_FIND;
}

int32_t TransDeleteSocketChannelInfoByPid(int32_t pid)
{
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t delCount = 0;
    SocketWithChannelInfo *socketItem = NULL;
    SocketWithChannelInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(socketItem, next, &(g_socketChannelList->list), SocketWithChannelInfo, node) {
        if (socketItem->pid == pid) {
            ListDelete(&(socketItem->node));
            g_socketChannelList->cnt--;
            SoftBusFree(socketItem);
            delCount++;
        }
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    if (delCount > 0) {
        TRANS_LOGI(TRANS_CTRL, "delete socket channel info, pid=%{public}d delete count=%{public}d",
            pid, delCount);
        return SOFTBUS_OK;
    }
    return SOFTBUS_NOT_FIND;
}

int32_t TransSetSocketChannelStateBySession(const char *sessionName, int32_t sessionId, CoreSessionState state)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        socketItem->state = state;
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransSetSocketChannelStateByChannel(int32_t channelId, int32_t channelType, CoreSessionState state)
{
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = NULL;
    LIST_FOR_EACH_ENTRY(socketItem, &(g_socketChannelList->list), SocketWithChannelInfo, node) {
        if (socketItem->channelId == channelId && socketItem->channelType == channelType) {
            socketItem->state = state;
            (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    TRANS_LOGE(
        TRANS_SVC, "socket info not found. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_NOT_FIND;
}

int32_t TransGetSocketChannelStateBySession(const char *sessionName, int32_t sessionId, CoreSessionState *state)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (state == NULL) {
        TRANS_LOGE(TRANS_SVC, "Invaild param, state is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        *state = socketItem->state;
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransGetSocketChannelLaneInfoBySession(
    const char *sessionName, int32_t sessionId, uint32_t *laneHandle, bool *isQosLane, bool *isAsync)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        if (laneHandle != NULL) {
            *laneHandle = socketItem->laneHandle;
        }
        if (isQosLane != NULL) {
            *isQosLane = socketItem->isQosLane;
        }
        if (isAsync != NULL) {
            *isAsync = socketItem->isAsync;
        }
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t TransGetSocketChannelStateByChannel(int32_t channelId, int32_t channelType, CoreSessionState *state)
{
    if (state == NULL) {
        TRANS_LOGE(TRANS_SVC, "Invaild param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = NULL;
    LIST_FOR_EACH_ENTRY(socketItem, &(g_socketChannelList->list), SocketWithChannelInfo, node) {
        if (socketItem->channelId == channelId && socketItem->channelType == channelType) {
            *state = socketItem->state;
            (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    TRANS_LOGE(
        TRANS_SVC, "socket info not found. channelId=%{public}d, channelType=%{public}d", channelId, channelType);
    return SOFTBUS_NOT_FIND;
}

int32_t TransGetPidFromSocketChannelInfoBySession(const char *sessionName, int32_t sessionId, int32_t *pid)
{
    int32_t ret = CheckParamIsValid(sessionName, sessionId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (g_socketChannelList == NULL) {
        TRANS_LOGE(TRANS_INIT, "socket info manager hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (pid == NULL) {
        TRANS_LOGE(TRANS_SVC, "Invaild param, pid is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_socketChannelList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SocketWithChannelInfo *socketItem = GetSocketWithChannelInfoBySession(sessionName, sessionId);
    if (socketItem != NULL) {
        *pid = socketItem->pid;
        (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_socketChannelList->lock));
    AnonymizeLogSessionNameWhenNotFound(sessionName, sessionId);
    return SOFTBUS_NOT_FIND;
}

static ConnectType ConvertLaneLinkTypeToConnectType(LaneLinkType laneLinkType)
{
    switch (laneLinkType) {
        case LANE_BR:
            return CONNECT_BR;
        case LANE_BLE:
        case LANE_COC:
            return CONNECT_BLE;
        case LANE_P2P:
            return CONNECT_P2P;
        case LANE_WLAN_2P4G:
        case LANE_WLAN_5G:
        case LANE_ETH:
            return CONNECT_TCP;
        case LANE_P2P_REUSE:
            return CONNECT_P2P_REUSE;
        case LANE_BLE_DIRECT:
        case LANE_COC_DIRECT:
            return CONNECT_BLE_DIRECT;
        case LANE_HML:
            return CONNECT_HML;
        case LANE_BLE_REUSE:
            return CONNECT_BLE;
        default:
            return CONNECT_TYPE_MAX;
    }
}

int32_t TransGetConnectTypeByChannelId(int32_t channelId, ConnectType *connectType)
{
    if (connectType == NULL) {
        TRANS_LOGE(TRANS_INIT, "connectType is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->channelId != channelId) {
            continue;
        }

        ConnectType connType = ConvertLaneLinkTypeToConnectType(item->laneConnInfo.type);
        if (connType >= CONNECT_TYPE_MAX) {
            TRANS_LOGE(TRANS_SVC, "invalid connectType=%{public}d. linkType=%{public}d, channelId=%{public}d",
                connType, item->laneConnInfo.type, channelId);
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_CONN_INVALID_CONN_TYPE;
        }

        *connectType = connType;
        (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    TRANS_LOGE(TRANS_SVC, "can not find connectType by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_INVALID_CHANNEL_ID;
}

int32_t TransGetTransLaneInfoByLaneHandle(uint32_t laneHandle, TransLaneInfo *laneInfo)
{
    if (laneInfo == NULL) {
        TRANS_LOGE(TRANS_INIT, "laneInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_channelLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans lane manager hasn't init.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&(g_channelLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    TransLaneInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_channelLaneList->list), TransLaneInfo, node) {
        if (item->laneHandle == laneHandle) {
            if (memcpy_s(laneInfo, sizeof(TransLaneInfo), item, sizeof(TransLaneInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_channelLaneList->lock));
    TRANS_LOGE(TRANS_SVC, "can not find laneInfo by laneHandle=%{public}u", laneHandle);
    return SOFTBUS_NOT_FIND;
}
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
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "wifi_direct_manager.h"

static SoftBusMutex g_laneStateListenerMutex;
static ListNode g_laneListenerList;
static ListNode g_laneTypeInfoList;
static ListNode g_laneStatusNotifyStateList;

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
    static const LaneType supportList[] = {LANE_TYPE_HDLC, LANE_TYPE_TRANS, LANE_TYPE_CTRL};
    uint32_t size = sizeof(supportList) / sizeof(LaneType);
    for (uint32_t i = 0; i < size; i++) {
        if (supportList[i] == type) {
            return true;
        }
    }
    LNN_LOGE(LNN_LANE, "LaneType=%{public}d not supported", type);
    return false;
}

static int32_t AddLaneTypeInfoItem(const LaneTypeInfo *inputLaneTypeInfo)
{
    if (inputLaneTypeInfo == NULL) {
        LNN_LOGE(LNN_LANE, "inputLaneTypeInfo is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneTypeInfo *laneTypeInfoItem = (LaneTypeInfo *)SoftBusMalloc(sizeof(LaneTypeInfo));
    if (laneTypeInfoItem == NULL) {
        LNN_LOGE(LNN_LANE, "laneTypeInfoItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(laneTypeInfoItem, sizeof(LaneTypeInfo), inputLaneTypeInfo, sizeof(LaneTypeInfo)) != EOK) {
        SoftBusFree(laneTypeInfoItem);
        LNN_LOGE(LNN_LANE, "memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        SoftBusFree(laneTypeInfoItem);
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_laneTypeInfoList, &laneTypeInfoItem->node);
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t CreateLaneTypeInfoByLaneId(const uint32_t laneId, const LaneLinkInfo *linkInfo)
{
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "[ParseLaneType]invalid laneId");
        return SOFTBUS_ERR;
    }
    LaneType laneType;
    if (ParseLaneTypeByLaneId(laneId, &laneType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "parse lanetype fail");
        return SOFTBUS_ERR;
    }
    LaneTypeInfo inputLaneTypeInfo;
    inputLaneTypeInfo.laneType = laneType;
    if (strncpy_s(inputLaneTypeInfo.peerIp, IP_LEN, linkInfo->linkInfo.p2p.connInfo.peerIp, IP_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerIp fail");
        return SOFTBUS_ERR;
    }
    if (AddLaneTypeInfoItem(&inputLaneTypeInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "add lanetype info fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t DelLaneTypeInfoItem(const char *peerIp)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "peerIp is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneTypeInfo *item = NULL;
    LaneTypeInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneTypeInfoList, LaneTypeInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t FindLaneTypeInfoByPeerIp(const char *peerIp, LaneTypeInfo *laneTypeInfo)
{
    if (peerIp == NULL || laneTypeInfo == NULL) {
        LNN_LOGE(LNN_LANE, "peerIp or linkInfoItem is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneTypeInfo *item = NULL;
    LaneTypeInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneTypeInfoList, LaneTypeInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            if (memcpy_s(laneTypeInfo, sizeof(LaneTypeInfo), item, sizeof(LaneTypeInfo)) != EOK) {
                LaneListenerUnlock();
                return SOFTBUS_MEM_ERR;
            }
            LaneListenerUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneListenerUnlock();
    LNN_LOGE(LNN_LANE, "find laneTypenfo by peerIp fail");
    return SOFTBUS_ERR;
}

static int32_t AddLaneStatusNotifyInfo(const LaneStatusNotifyInfo *inputLaneStatusNotifyInfo)
{
    if (inputLaneStatusNotifyInfo == NULL) {
        LNN_LOGE(LNN_LANE, "inputLaneStatusNotifyInfo is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneStatusNotifyInfo *laneStatusNotifyInfoItem = (LaneStatusNotifyInfo *)SoftBusMalloc(sizeof(LaneStatusNotifyInfo));
    if (laneStatusNotifyInfoItem == NULL) {
        LNN_LOGE(LNN_LANE, "laneStatusNotifyInfoItem malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(laneStatusNotifyInfoItem, sizeof(LaneStatusNotifyInfo), inputLaneStatusNotifyInfo, sizeof(LaneStatusNotifyInfo)) != EOK) {
        SoftBusFree(laneStatusNotifyInfoItem);
        LNN_LOGE(LNN_LANE, "memcpy_s fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        SoftBusFree(laneStatusNotifyInfoItem);
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_laneStatusNotifyStateList, &laneStatusNotifyInfoItem->node);
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t UpdateLaneStatusNotifyState(const char *peerIp, const char *peerUuid, const bool state)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "peerIp is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneStatusNotifyInfo *item = NULL;
    LaneStatusNotifyInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneStatusNotifyStateList, LaneStatusNotifyInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            item->isNeedNotify = state;
            if (strncpy_s(item->peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
                LNN_LOGE(LNN_STATE, "copy peerIp fail");
                LaneListenerUnlock();
                return SOFTBUS_ERR;
            }
            LaneListenerUnlock();
            return SOFTBUS_OK;
        }
    }
    LaneListenerUnlock();
    char *anonyIp = NULL;
    Anonymize(peerIp, &anonyIp);
    LNN_LOGE(LNN_STATE, "lane status notify item not exists, peerIp=%{public}s", anonyIp);
    AnonymizeFree(anonyIp);
    return SOFTBUS_ERR;
}

static int32_t DelLaneStatusNotifyInfo(const char *peerIp)
{
    if (peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "peerIp is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneStatusNotifyInfo *item = NULL;
    LaneStatusNotifyInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneStatusNotifyStateList, LaneStatusNotifyInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
        }
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static LaneStatusNotifyInfo *LaneStatusNotifyIsExist(const char *peerIp)
{
    LaneStatusNotifyInfo *item = NULL;
    LaneStatusNotifyInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneStatusNotifyStateList, LaneStatusNotifyInfo, node) {
        if (strncmp(item->peerIp, peerIp, IP_LEN) == 0) {
            return item;
        }
    }
    return NULL;
}

static LaneListenerInfo *LaneListenerIsExist(const LaneType type)
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

static int32_t FindLaneListenerInfoByLaneType(const LaneType type, LaneListenerInfo *outLaneListener)
{
    if (!LaneTypeCheck(type) || outLaneListener == NULL) {
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
        return SOFTBUS_ERR;
    }
    if (memcpy_s(outLaneListener, sizeof(LaneListenerInfo), item, sizeof(LaneListenerInfo)) != EOK) {
        LaneListenerUnlock();
        return SOFTBUS_MEM_ERR;
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t RegisterLaneListener(const LaneType type, const LaneStatusListener *listener)
{
    if (!LaneTypeCheck(type)) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneListenerInfo *laneListenerItem = (LaneListenerInfo *)SoftBusMalloc(sizeof(LaneListenerInfo));
    if (laneListenerItem == NULL) {
        LNN_LOGE(LNN_LANE, "lane listener malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    laneListenerItem->type = type;
    laneListenerItem->laneStatusListen = *listener;
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo* item = LaneListenerIsExist(laneListenerItem->type);
    if (item != NULL) {
        SoftBusFree(laneListenerItem);
    } else {
        ListAdd(&g_laneListenerList, &laneListenerItem->node);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

int32_t UnRegisterLaneListener(const LaneType type)
{
    if (!LaneTypeCheck(type)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo* item = LaneListenerIsExist(type);
    if (item != NULL) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    LaneListenerUnlock();
    return SOFTBUS_OK;
}

static int32_t GetLaneResourceByPeerIp(const char *peerIp, LaneResource *laneResourceItem)
{
    if (peerIp == NULL || laneResourceItem == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_ERR;
    }
    if (FindLaneResourceByPeerIp(peerIp, laneResourceItem) != SOFTBUS_OK) {
        char *anonyIp = NULL;
        Anonymize(peerIp, &anonyIp);
        LNN_LOGE(LNN_STATE, "find lane resource fail, peerIp=%{public}s", anonyIp);
        AnonymizeFree(anonyIp);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void LnnOnWifiDirectDeviceOffLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    if (peerUuid == NULL || peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }

    LaneResource laneResourceItem;
    (void)memset_s(&laneResourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (GetLaneResourceByPeerIp(peerIp, &laneResourceItem) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get lane resource fail");
        return;
    }

    LaneTypeInfo laneTypeInfo;
    char *anonyIp = NULL;
    (void)memset_s(&laneTypeInfo, sizeof(LaneTypeInfo), 0, sizeof(LaneTypeInfo));
    if (FindLaneTypeInfoByPeerIp(peerIp, &laneTypeInfo) != SOFTBUS_OK) {
        Anonymize(peerIp, &anonyIp);
        LNN_LOGE(LNN_STATE, "find lane type fail, peerIp=%{public}s", anonyIp);
        AnonymizeFree(anonyIp);
        return;
    }
    DelLaneResourceItem(&laneResourceItem);
    DelLaneTypeInfoItem(peerIp);
    DelLaneStatusNotifyInfo(peerIp);

    LaneListenerInfo laneListener;
    LaneStatusListenerInfo laneStatusListenerInfo;
    if (strncpy_s(laneStatusListenerInfo.peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerUuid fail");
        return;
    }
    laneStatusListenerInfo.type = laneResourceItem.type;
    if (FindLaneListenerInfoByLaneType(laneTypeInfo.laneType, &laneListener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "find lane listener fail, laneType=%{public}d", laneTypeInfo.laneType);
        return;
    }
    if (laneListener.laneStatusListen.onLaneOffLine == NULL) {
        LNN_LOGE(LNN_STATE, "invalid lane status listen");
        return;
    }
    laneListener.laneStatusListen.onLaneOffLine(&laneStatusListenerInfo);
}

static void LnnOnWifiDirectRoleChange(enum WifiDirectRole myRole)
{
    LaneStatusListenerInfo laneStatusListenerInfo;
    laneStatusListenerInfo.role = myRole;

    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return;
    }
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        if (item->laneStatusListen.onLaneStateChange != NULL) {
            item->laneStatusListen.onLaneStateChange(&laneStatusListenerInfo);
        }
    }
    LaneListenerUnlock();
}

static void LnnOnWifiDirectDeviceOnLine(const char *peerMac, const char *peerIp, const char *peerUuid)
{
    if (peerUuid == NULL || peerIp == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    LaneStatusNotifyInfo *laneStatusNotifyInfo = LaneStatusNotifyIsExist(peerIp);
    if (laneStatusNotifyInfo != NULL) {
        if (UpdateLaneStatusNotifyState(peerIp, peerUuid, true) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "update lane status notify state err");
            return;
        }
        return;
    }

    LaneStatusNotifyInfo inputLaneStatusNotifyInfo;
    if (strncpy_s(inputLaneStatusNotifyInfo.peerIp, IP_LEN, peerIp, IP_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerIp fail");
        return;
    }
    if (strncpy_s(inputLaneStatusNotifyInfo.peerUuid, UUID_BUF_LEN, peerUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerUuid fail");
        return;
    }
    inputLaneStatusNotifyInfo.isNeedNotify = true;
    if (AddLaneStatusNotifyInfo(&inputLaneStatusNotifyInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add lane status notify info err");
        return;
    }
}

static void LnnReqLinkListener(void)
{
    struct WifiDirectStatusListener listener = {
        .onDeviceOffLine = LnnOnWifiDirectDeviceOffLine,
        .onLocalRoleChange = LnnOnWifiDirectRoleChange,
        .onDeviceOnLine = LnnOnWifiDirectDeviceOnLine,
    };
    struct WifiDirectManager *mgr = GetWifiDirectManager();
    if (mgr != NULL && mgr->registerStatusListener != NULL) {
        mgr->registerStatusListener(LNN_LANE_MODULE, &listener);
    }
}

int32_t LnnOnWifiDirectDeviceOnLineNotify(const char *peerIp, const LaneLinkType linkType)
{
    LaneStatusNotifyInfo *laneStatusNotifyInfo = LaneStatusNotifyIsExist(peerIp);
    if (laneStatusNotifyInfo == NULL || !laneStatusNotifyInfo->isNeedNotify) {
        LNN_LOGI(LNN_LANE, "no need to notify lane status");
        return SOFTBUS_OK;
    }
    LaneStatusListenerInfo laneStatusListenerInfo;
    if (strncpy_s(laneStatusListenerInfo.peerUuid, UUID_BUF_LEN, laneStatusNotifyInfo->peerUuid, UUID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_STATE, "copy peerUuid fail");
        return SOFTBUS_ERR;
    }
    laneStatusListenerInfo.type = linkType;

    if (LaneListenerLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane listener lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneListenerInfo *item = NULL;
    LaneListenerInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList, LaneListenerInfo, node) {
        if (item->laneStatusListen.onLaneOnLine != NULL) {
            item->laneStatusListen.onLaneOnLine(&laneStatusListenerInfo);
        }
    }
    LaneListenerUnlock();
    if (UpdateLaneStatusNotifyState(peerIp, laneStatusNotifyInfo->peerUuid, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update lane status notify state err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t InitLaneListener(void)
{
    if (SoftBusMutexInit(&g_laneStateListenerMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "g_laneStateListenerMutex init fail");
        return SOFTBUS_ERR;
    }
    ListInit(&g_laneListenerList);
    ListInit(&g_laneTypeInfoList);
    ListInit(&g_laneStatusNotifyStateList);

    LnnReqLinkListener();
    return SOFTBUS_OK;
}
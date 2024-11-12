/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_lane_model.h"

#include <securec.h>

#include "common_list.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_log.h"
#include "lnn_map.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define LINK_TYPE_SHIFT 26
#define TRANS_TYPE_SHIFT 22
#define PRIORITY_SHIFT 18

typedef struct {
    ListNode node;
    uint64_t laneId;
} LaneIdInfo;

typedef struct {
    LaneProfile profile;
    uint32_t ref;
    ListNode laneIdList;
} LaneModel;

static Map g_profileMap;
static SoftBusMutex g_laneModelMutex;

static int32_t ModelLock(void)
{
    return SoftBusMutexLock(&g_laneModelMutex);
}

static void ModelUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneModelMutex);
}

/*
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  LinkType |TxType |  Pri  |              Reserved             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
uint32_t GenerateLaneProfileId(const LaneGenerateParam *param)
{
    uint32_t laneProfileId = 0;
    laneProfileId |= ((param->linkType << LINK_TYPE_SHIFT) |
        (param->transType << TRANS_TYPE_SHIFT) | (param->priority << PRIORITY_SHIFT));
    return laneProfileId;
}

static void AddLaneIdNode(uint64_t laneId, LaneModel *laneModel)
{
    LaneIdInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &laneModel->laneIdList, LaneIdInfo, node) {
        if (infoNode->laneId == laneId) {
            LNN_LOGE(LNN_LANE, "laneId has been added");
            return;
        }
    }
    LaneIdInfo *newNode = (LaneIdInfo *)SoftBusCalloc(sizeof(LaneIdInfo));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "laneId add to list fail");
        return;
    }
    ListInit(&newNode->node);
    newNode->laneId = laneId;
    ListAdd(&laneModel->laneIdList, &newNode->node);
    laneModel->ref++;
}

static void DeleteLaneIdNode(uint64_t laneId, LaneModel *laneModel)
{
    LaneIdInfo *item = NULL;
    LaneIdInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &laneModel->laneIdList, LaneIdInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            laneModel->ref--;
            return;
        }
    }
}

static int32_t AddLaneModel(uint64_t laneId, uint32_t profileId, LaneProfile *laneProfile)
{
    if (ModelLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneModel *laneModel = (LaneModel *)LnnReadData(&g_profileMap, profileId);
    if (laneModel != NULL) {
        AddLaneIdNode(laneId, laneModel);
        ModelUnlock();
        return SOFTBUS_OK;
    }

    LaneModel newModel;
    (void)memset_s(&newModel, sizeof(LaneModel), 0, sizeof(LaneModel));
    if (memcpy_s(&newModel.profile, sizeof(LaneProfile), laneProfile, sizeof(LaneProfile)) != EOK) {
        LNN_LOGE(LNN_LANE, "addLaneModel memcpy fail");
        ModelUnlock();
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = LnnCreateData(&g_profileMap, profileId, &newModel, sizeof(LaneModel));
    if (ret != SOFTBUS_OK) {
        ModelUnlock();
        return ret;
    }
    laneModel = (LaneModel *)LnnReadData(&g_profileMap, profileId);
    if (laneModel != NULL) {
        ListInit(&(laneModel->laneIdList));
        AddLaneIdNode(laneId, laneModel);
    }
    ModelUnlock();
    return SOFTBUS_OK;
}

int32_t BindLaneIdToProfile(uint64_t laneId, LaneProfile *profile)
{
    if (profile == NULL) {
        LNN_LOGE(LNN_LANE, "profile is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneGenerateParam param;
    param.linkType = profile->linkType;
    param.transType = profile->content;
    param.priority = profile->priority;
    uint32_t profileId = GenerateLaneProfileId(&param);
    profile->serialNum = profileId;
    int32_t ret = AddLaneModel(laneId, profileId, profile);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return SOFTBUS_OK;
}

void UnbindLaneIdFromProfile(uint64_t laneId, uint32_t profileId)
{
    if (ModelLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneModel *laneModel = (LaneModel *)LnnReadData(&g_profileMap, profileId);
    if (laneModel == NULL) {
        ModelUnlock();
        return;
    }
    DeleteLaneIdNode(laneId, laneModel);
    if (laneModel->ref == 0) {
        LnnDeleteData(&g_profileMap, profileId);
    }
    ModelUnlock();
}

int32_t GetLaneProfile(uint32_t profileId, LaneProfile *profile)
{
    if (profile == NULL) {
        LNN_LOGE(LNN_LANE, "profile is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ModelLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    LaneModel *laneModel = (LaneModel *)LnnReadData(&g_profileMap, profileId);
    if (laneModel == NULL) {
        ModelUnlock();
        LNN_LOGE(LNN_LANE, "read laneModel fail");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(profile, sizeof(LaneProfile), &laneModel->profile, sizeof(LaneProfile)) != EOK) {
        LNN_LOGE(LNN_LANE, "profile memcpy fail");
        ModelUnlock();
        return SOFTBUS_MEM_ERR;
    }
    ModelUnlock();
    return SOFTBUS_OK;
}

int32_t GetLaneIdList(uint32_t profileId, uint64_t **laneIdList, uint32_t *listSize)
{
    if (ModelLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneModel *laneModel = (LaneModel *)LnnReadData(&g_profileMap, profileId);
    if (laneModel == NULL) {
        ModelUnlock();
        LNN_LOGE(LNN_LANE, "read laneModel fail");
        return SOFTBUS_INVALID_PARAM;
    }
    if (laneModel->ref == 0) {
        LNN_LOGE(LNN_LANE, "ref count is zero");
        ModelUnlock();
        return SOFTBUS_INVALID_PARAM;
    }
    *laneIdList = (uint64_t *)SoftBusCalloc(sizeof(uint64_t) * laneModel->ref);
    if (*laneIdList == NULL) {
        LNN_LOGE(LNN_LANE, "laneIdList malloc fail");
        ModelUnlock();
        return SOFTBUS_MALLOC_ERR;
    }
    uint32_t cnt = 0;
    LaneIdInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &laneModel->laneIdList, LaneIdInfo, node) {
        (*laneIdList)[cnt] = infoNode->laneId;
        cnt++;
    }
    *listSize = cnt;
    ModelUnlock();
    return SOFTBUS_OK;
}

uint32_t GetActiveProfileNum(void)
{
    uint32_t num = 0;
    if (ModelLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return num;
    }
    num = g_profileMap.nodeSize;
    ModelUnlock();
    return num;
}

int32_t InitLaneModel(void)
{
    LnnMapInit(&g_profileMap);
    if (SoftBusMutexInit(&g_laneModelMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "laneModel mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

static void ClearProfileMap(void)
{
    MapIterator *it = LnnMapInitIterator(&g_profileMap);
    if (it == NULL) {
        LNN_LOGE(LNN_LANE, "clear profileMap fail");
        return;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL || it->node->value == NULL) {
            break;
        }
        LaneModel *laneModel = (LaneModel *)it->node->value;
        LaneIdInfo *infoNode = NULL;
        LaneIdInfo *nextNode = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(infoNode, nextNode, &laneModel->laneIdList, LaneIdInfo, node) {
            ListDelete(&infoNode->node);
            SoftBusFree(infoNode);
            laneModel->ref--;
        }
    }
    LnnMapDeinitIterator(it);
    LnnMapDelete(&g_profileMap);
}

void DeinitLaneModel(void)
{
    ClearProfileMap();
    (void)SoftBusMutexDestroy(&g_laneModelMutex);
}
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

#include "trans_auth_lane_pending_ctl.h"

#include <securec.h>

#include "trans_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static SoftBusList *g_authWithParaAsyncReqLaneList = NULL;

int32_t TransAuthWithParaReqLanePendingInit(void)
{
    g_authWithParaAsyncReqLaneList = CreateSoftBusList();
    if (g_authWithParaAsyncReqLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_authWithParaAsyncReqLaneList is null.");
        return SOFTBUS_TRANS_LIST_INIT_FAILED;
    }
    return SOFTBUS_OK;
}

void TransAuthWithParaReqLanePendingDeinit(void)
{
    TRANS_LOGI(TRANS_SVC, "enter.");
    TransAuthWithParaNode *item = NULL;
    TransAuthWithParaNode *next = NULL;
    if (g_authWithParaAsyncReqLaneList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_authWithParaAsyncReqLaneList is null.");
        return;
    }

    if (SoftBusMutexLock(&g_authWithParaAsyncReqLaneList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed.");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authWithParaAsyncReqLaneList->list, TransAuthWithParaNode, node) {
        ListDelete(&item->node);
        SoftBusFree(item->sessionName);
        item->sessionName = NULL;
        SoftBusFree(item);
        item = NULL;
    }
    (void)SoftBusMutexUnlock(&g_authWithParaAsyncReqLaneList->lock);
    DestroySoftBusList(g_authWithParaAsyncReqLaneList);
    g_authWithParaAsyncReqLaneList = NULL;
}

static int32_t FillTransAuthWithParaNode(TransAuthWithParaNode *item, uint32_t laneReqId, const char *sessionName,
    bool accountInfo, int32_t channelId)
{
    item->errCode = SOFTBUS_MALLOC_ERR;
    item->laneReqId = laneReqId;
    item->channelId = channelId;
    item->bSucc = false;
    item->isFinished = false;
    item->accountInfo = accountInfo;
    if (strcpy_s(item->sessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        TRANS_LOGE(TRANS_SVC, "TransAuthWithParaAddLaneReqToList: copy sessionName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransAuthWithParaAddLaneReqToList(uint32_t laneReqId, const char *sessionName,
    bool accountInfo, int32_t channelId)
{
    int32_t errCode = SOFTBUS_TRANS_CHANNEL_OPEN_FAILED;
    if (g_authWithParaAsyncReqLaneList == NULL) {
        TRANS_LOGE(TRANS_SVC, "g_authWithParaAsyncReqLaneList no init.");
        return SOFTBUS_NO_INIT;
    }

    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_SVC, "sessionName or linkPara is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    TransAuthWithParaNode *item = (TransAuthWithParaNode *)SoftBusCalloc(sizeof(TransAuthWithParaNode));
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        item != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "SoftBusCalloc item failed");

    item->sessionName = (char *)SoftBusCalloc(sizeof(char) * SESSION_NAME_SIZE_MAX);
    if (item->sessionName == NULL) {
        TRANS_LOGE(TRANS_SVC, "SoftBusCalloc item->sessionName failed.");
        SoftBusFree(item);
        return SOFTBUS_MALLOC_ERR;
    }

    errCode = FillTransAuthWithParaNode(item, laneReqId, sessionName, accountInfo, channelId);
    if (errCode != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "fill trans auth with para node failed. ret=%{public}d", errCode);
        goto ERR_EXIT;
    }

    if (SoftBusMutexLock(&g_authWithParaAsyncReqLaneList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "g_authWithParaAsyncReqLaneList lock failed.");
        errCode = SOFTBUS_LOCK_ERR;
        goto ERR_EXIT;
    }
    ListInit(&(item->node));
    ListAdd(&(g_authWithParaAsyncReqLaneList->list), &(item->node));
    g_authWithParaAsyncReqLaneList->cnt++;
    (void)SoftBusMutexUnlock(&g_authWithParaAsyncReqLaneList->lock);
    TRANS_LOGI(TRANS_SVC, "TransAuthWithParaAddLaneReqToList success laneReqId=%{public}u", laneReqId);
    return SOFTBUS_OK;
ERR_EXIT:
    SoftBusFree(item->sessionName);
    item->sessionName = NULL;
    SoftBusFree(item);
    return errCode;
}

int32_t TransAuthWithParaDelLaneReqById(uint32_t laneReqId)
{
    TRANS_LOGD(TRANS_SVC, "TransAuthWithParaDelLaneReqById laneReqId=%{public}u", laneReqId);
    if (g_authWithParaAsyncReqLaneList == NULL) {
        TRANS_LOGE(TRANS_SVC, "TransAuthWithParaDelLaneReqById: g_authWithParaAsyncReqLaneList no init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_authWithParaAsyncReqLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "g_authWithParaAsyncReqLaneList lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransAuthWithParaNode *laneItem = NULL;
    TransAuthWithParaNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(g_authWithParaAsyncReqLaneList->list), TransAuthWithParaNode, node) {
        if (laneItem->laneReqId == laneReqId) {
            TRANS_LOGI(TRANS_SVC, "delete laneReqId=%{public}u", laneItem->laneReqId);
            ListDelete(&(laneItem->node));
            g_authWithParaAsyncReqLaneList->cnt--;
            SoftBusFree(laneItem->sessionName);
            laneItem->sessionName = NULL;
            SoftBusFree(laneItem);
            laneItem = NULL;
            (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
    TRANS_LOGE(TRANS_SVC, "TransAuthWithParaDelLaneReqById not found, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND;
}

int32_t TransUpdateAuthWithParaLaneConnInfo(uint32_t laneHandle, bool bSucc, const LaneConnInfo *connInfo,
    int32_t errCode)
{
    if (g_authWithParaAsyncReqLaneList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_authWithParaAsyncReqLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransAuthWithParaNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_authWithParaAsyncReqLaneList->list), TransAuthWithParaNode, node) {
        if (item->laneReqId == laneHandle) {
            item->bSucc = bSucc;
            item->errCode = errCode;
            if ((connInfo != NULL) &&
                (memcpy_s(&(item->connInfo), sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK)) {
                (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
                return SOFTBUS_MEM_ERR;
            }
            item->isFinished = true;
            (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneHandle=%{public}u", laneHandle);
    return SOFTBUS_TRANS_NODE_NOT_FOUND;
}

int32_t TransAuthWithParaGetLaneReqByLaneReqId(uint32_t laneReqId, TransAuthWithParaNode *paraNode)
{
    if (paraNode == NULL) {
        TRANS_LOGE(TRANS_CTRL, "TransAuthWithParaGetLaneReqByLaneReqId: invalid paraNode");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_authWithParaAsyncReqLaneList == NULL) {
        TRANS_LOGE(TRANS_SVC, "g_authWithParaAsyncReqLaneList hasn't init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_authWithParaAsyncReqLaneList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "g_authWithParaAsyncReqLaneList lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransAuthWithParaNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_authWithParaAsyncReqLaneList->list), TransAuthWithParaNode, node) {
        if (item->laneReqId == laneReqId) {
            if (memcpy_s(paraNode, sizeof(TransAuthWithParaNode), item, sizeof(TransAuthWithParaNode)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
                TRANS_LOGE(TRANS_SVC, "copy paraNode failed.");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_authWithParaAsyncReqLaneList->lock));
    TRANS_LOGE(TRANS_SVC, "TransAuthWithParaGetLaneReqByLaneReqId not found. laneReqId=%{public}u", laneReqId);
    return SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND;
}
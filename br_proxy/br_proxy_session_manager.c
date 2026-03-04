/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <limits.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>

#include "br_proxy_session_manager.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "trans_log.h"

static SoftBusMutex g_sessionIdLock;
static SoftBusList *g_sessionList = NULL;

int32_t GetSessionId(void)
{
    static int32_t sessionId = 0;
    int32_t id = 0;

    if (SoftBusMutexLock(&g_sessionIdLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] get sessionId lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (sessionId >= INT32_MAX) {
        sessionId = 1;
    }
    id = ++sessionId;
    (void)SoftBusMutexUnlock(&g_sessionIdLock);
    return id;
}

int32_t SessionInit(void)
{
    static bool initSuccess = false;
    if (initSuccess) {
        return SOFTBUS_OK;
    }
    g_sessionList = CreateSoftBusList();
    if (g_sessionList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] init list failed");
        return SOFTBUS_CREATE_LIST_ERR;
    }

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    if (SoftBusMutexInit(&g_sessionIdLock, &mutexAttr) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] init lock failed");
        DestroySoftBusList(g_sessionList);
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    initSuccess = true;
    TRANS_LOGI(TRANS_SDK, "[br_proxy] init trans session success");
    return SOFTBUS_OK;
}

int32_t AddSessionToList(int32_t sessionId)
{
    int32_t ret = SOFTBUS_OK;
    SessionInfo *info = (SessionInfo *)SoftBusCalloc(sizeof(SessionInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] calloc failed");
        return SOFTBUS_MALLOC_ERR;
    }
    info->sessionId = sessionId;
    SoftBusCondInit(&info->cond);
    info->condFlag = false;
    ListInit(&info->node);
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        ret = SOFTBUS_LOCK_ERR;
        goto EXIT_ERR;
    }
    ListAdd(&g_sessionList->list, &info->node);
    g_sessionList->cnt++;
    TRANS_LOGI(TRANS_SDK, "[br_proxy] add session node success, cnt:%{public}d", g_sessionList->cnt);
    (void)SoftBusMutexUnlock(&g_sessionList->lock);
    return SOFTBUS_OK;

EXIT_ERR:
    SoftBusCondDestroy(&info->cond);
    SoftBusFree(info);
    return ret;
}

int32_t UpdateListBySessionId(int32_t sessionId, int32_t channelId, int32_t openResult)
{
    if (g_sessionList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SessionInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_sessionList->list), SessionInfo, node) {
        if (nodeInfo->sessionId != sessionId) {
            continue;
        }
        nodeInfo->channelId = channelId;
        nodeInfo->openResult = openResult;
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find sessionId:%{public}d", sessionId);
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t GetSessionInfoBySessionId(int32_t sessionId, SessionInfo *info)
{
    if (g_sessionList == NULL || info == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SessionInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_sessionList->list), SessionInfo, node) {
        if (nodeInfo->sessionId != sessionId) {
            continue;
        }
        if (memcpy_s(info, sizeof(SessionInfo), nodeInfo, sizeof(SessionInfo)) != EOK) {
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            return SOFTBUS_MEM_ERR;
        }
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find sessionId:%{public}d", sessionId);
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t DeleteSessionById(int32_t sessionId)
{
    if (g_sessionList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SessionInfo *sessionNode = NULL;
    SessionInfo *sessionNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(sessionNode, sessionNodeNext, &(g_sessionList->list), SessionInfo, node) {
        if (sessionNode->sessionId != sessionId) {
            continue;
        }
        SoftBusCondDestroy(&sessionNode->cond);
        TRANS_LOGI(TRANS_SDK, "[br_proxy] by sessionId:%{public}d delete node success, cnt:%{public}d",
            sessionNode->sessionId, g_sessionList->cnt);
        ListDelete(&sessionNode->node);
        SoftBusFree(sessionNode);
        g_sessionList->cnt--;
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t BrProxyWaitCond(int32_t sessionId)
{
#define BR_PROXY_MAX_WAIT_COND_TIME 10 // 10s
    if (g_sessionList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SessionInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_sessionList->list), SessionInfo, node) {
        if (nodeInfo->sessionId != sessionId) {
            continue;
        }
        if (nodeInfo->condFlag) {
            TRANS_LOGI(TRANS_SDK, "[br_proxy] signal has been triggered! sessionId:%{public}d", sessionId);
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            return SOFTBUS_OK;
        }
        SoftBusSysTime absTime = { 0 };
        int32_t ret = SoftBusGetTime(&absTime);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "[br_proxy] failed! sessionId:%{public}d, ret:%{public}d", sessionId, ret);
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            return ret;
        }
        if (absTime.sec > INT64_MAX - BR_PROXY_MAX_WAIT_COND_TIME) {
            TRANS_LOGE(TRANS_SDK, "[br_proxy] time overflow");
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            return SOFTBUS_INVALID_PARAM;
        }
        absTime.sec += BR_PROXY_MAX_WAIT_COND_TIME;
        TRANS_LOGI(TRANS_SDK, "[br_proxy] start wait cond signal! sessionId:%{public}d", sessionId);
        ret = SoftBusCondWait(&nodeInfo->cond, &(g_sessionList->lock), &absTime);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "[br_proxy] cond wait failed! sessionId:%{public}d, ret:%{public}d", sessionId, ret);
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            return SOFTBUS_CONN_OPEN_PROXY_TIMEOUT;  // Operation failed or Connection timed out.
        }
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find sessionId:%{public}d", sessionId);
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    return SOFTBUS_NOT_FIND;
}

int32_t BrProxyPostCond(int32_t sessionId)
{
    if (g_sessionList == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(g_sessionList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SessionInfo *nodeInfo = NULL;
    LIST_FOR_EACH_ENTRY(nodeInfo, &(g_sessionList->list), SessionInfo, node) {
        if (nodeInfo->sessionId != sessionId) {
            continue;
        }
        nodeInfo->condFlag = true;
        int32_t ret = SoftBusCondSignal(&nodeInfo->cond);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "[br_proxy] cond signal failed! sessionId:%{public}d, ret:%{public}d",
                sessionId, ret);
            (void)SoftBusMutexUnlock(&(g_sessionList->lock));
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "[br_proxy] cond signal success! sessionId:%{public}d", sessionId);
        (void)SoftBusMutexUnlock(&(g_sessionList->lock));
        return SOFTBUS_OK;
    }
    TRANS_LOGE(TRANS_SDK, "[br_proxy] not find sessionId:%{public}d", sessionId);
    (void)SoftBusMutexUnlock(&(g_sessionList->lock));
    return SOFTBUS_NOT_FIND;
}

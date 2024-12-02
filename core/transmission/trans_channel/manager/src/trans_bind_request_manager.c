/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "trans_bind_request_manager.h"

#include <securec.h>
#include <stdlib.h>

#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_utils.h"
#include "trans_log.h"

#define DDOS_DETECTION_PERIOD_MS (60 * 1000)    // 60s
#define BIND_PROTECT_PERIOD_MS (60 * 10 * 1000) // 600s
#define BIND_FAILED_COUNT_MAX 10

typedef enum {
    LOOP_DELETE_TIMESTAMP,
    LOOP_RESET_BIND_DENIED_FLAG
} BindRequestLoopMsg;

typedef struct {
    ListNode node;
    uint64_t timestamp;
} BindFailInfo;

typedef struct {
    char mySocketName[SESSION_NAME_SIZE_MAX];
    char peerSocketName[SESSION_NAME_SIZE_MAX];
    char peerNetworkId[NETWORK_ID_BUF_LEN];
} BindRequestParam;

typedef struct {
    ListNode node;
    BindRequestParam bindRequestParam;
    int32_t count;
    bool bindDeniedFlag;
    ListNode timestampList;
} BindRequestManager;

static SoftBusList *g_bindRequestList = NULL;
const char *g_transLoopName = "transBindRequestLoop";
static SoftBusHandler g_transLoopHandler = { 0 };

// need to get g_bindRequestList->lock before calling this function
static BindRequestManager *GetBindRequestManagerByPeer(BindRequestParam *bindRequestParam)
{
    BindRequestManager *item = NULL;
    BindRequestManager *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_bindRequestList->list, BindRequestManager, node) {
        if (strcmp(item->bindRequestParam.mySocketName, bindRequestParam->mySocketName) == 0 &&
            strcmp(item->bindRequestParam.peerSocketName, bindRequestParam->peerSocketName) == 0 &&
            strcmp(item->bindRequestParam.peerNetworkId, bindRequestParam->peerNetworkId) == 0) {
            return item;
        }
    }
    TRANS_LOGI(TRANS_SVC, "session not found");
    return NULL;
}

static uint32_t GenerateParam(
    const char *mySocketName, const char *peerSocketName, const char *peerNetworkId, BindRequestParam *bindRequestParam)
{
    int32_t ret = memcpy_s(bindRequestParam->mySocketName, SESSION_NAME_SIZE_MAX, peerSocketName, SESSION_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_STRCPY_ERR, TRANS_SVC, "memcpy mySocketName failed");

    ret = memcpy_s(bindRequestParam->peerSocketName, SESSION_NAME_SIZE_MAX, peerNetworkId, SESSION_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_STRCPY_ERR, TRANS_SVC, "memcpy peerSocketName failed");

    ret = memcpy_s(bindRequestParam->peerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId, NETWORK_ID_BUF_LEN);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_STRCPY_ERR, TRANS_SVC, "memcpy peerNetworkId failed");
    return SOFTBUS_OK;
}

static BindRequestManager *CreateBindRequestManager(
    const char *mySocketName, const char *peerSocketName, const char *peerNetworkId)
{
    BindRequestManager *bindRequest = (BindRequestManager *)SoftBusCalloc(sizeof(BindRequestManager));
    TRANS_CHECK_AND_RETURN_RET_LOGE(bindRequest != NULL, NULL, TRANS_SVC, "malloc failed");
    bindRequest->bindDeniedFlag = false;
    bindRequest->count = 0;
    int32_t ret = GenerateParam(mySocketName, peerSocketName, peerNetworkId, &bindRequest->bindRequestParam);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, NULL, TRANS_SVC, "genarate param failed");
    ListInit(&bindRequest->node);
    ListInit(&bindRequest->timestampList);
    ListAdd(&g_bindRequestList->list, &bindRequest->node);
    return bindRequest;
}

static void TransBindRequestMsgToLooper(
    int32_t msgType, uint64_t param1, uint64_t param2, BindRequestParam *data, uint64_t delayMillis)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_MSG, "msg create failed");
    msg->what = msgType;
    msg->arg1 = param1;
    msg->arg2 = param2;
    msg->handler = &g_transLoopHandler;
    msg->obj = (void *)data;

    if (delayMillis == 0) {
        g_transLoopHandler.looper->PostMessage(g_transLoopHandler.looper, msg);
    } else {
        g_transLoopHandler.looper->PostMessageDelay(g_transLoopHandler.looper, msg, delayMillis);
    }
}

int32_t TransAddTimestampToList(
    const char *mySocketName, const char *peerSocketName, const char *peerNetworkId, uint64_t timestamp)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_bindRequestList != NULL, SOFTBUS_NO_INIT, TRANS_SVC, "bind request list no init");
    BindRequestParam *bindRequestParam = (BindRequestParam *)SoftBusCalloc(sizeof(BindRequestParam));
    TRANS_CHECK_AND_RETURN_RET_LOGE(bindRequestParam != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "malloc failed");
    int32_t ret = GenerateParam(mySocketName, peerSocketName, peerNetworkId, bindRequestParam);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "genarate param failed");
        goto ERR_EXIT;
    }

    ret = SoftBusMutexLock(&g_bindRequestList->lock);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        goto ERR_EXIT;
    }
    BindRequestManager *bindRequest = GetBindRequestManagerByPeer(bindRequestParam);
    if (bindRequest == NULL) {
        bindRequest = CreateBindRequestManager(mySocketName, peerSocketName, peerNetworkId);
        if (bindRequest == NULL) {
            TRANS_LOGE(TRANS_SVC, "malloc failed");
            (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
            goto ERR_EXIT;
        }
    }

    BindFailInfo *bindFailInfo = (BindFailInfo *)SoftBusCalloc(sizeof(BindFailInfo));
    if (bindFailInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "malloc failed");
        (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
        goto ERR_EXIT;
    }
    bindFailInfo->timestamp = timestamp;
    ListInit(&bindFailInfo->node);
    ListAdd(&bindRequest->timestampList, &bindFailInfo->node);
    bindRequest->count++;
    TRANS_LOGI(TRANS_SVC, "add timestamp to list success, timestamp=%{public}" PRId64, timestamp);

    TransBindRequestMsgToLooper(LOOP_DELETE_TIMESTAMP, timestamp, 0, &bindRequest->bindRequestParam,
        DDOS_DETECTION_PERIOD_MS);
    if (bindRequest->count >= BIND_FAILED_COUNT_MAX) {
        bindRequest->bindDeniedFlag = true;
        TransBindRequestMsgToLooper(LOOP_RESET_BIND_DENIED_FLAG, 0, 0, &bindRequest->bindRequestParam,
            BIND_PROTECT_PERIOD_MS);
    }
    (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
    SoftBusFree(bindRequestParam);
    return SOFTBUS_OK;

ERR_EXIT:
    TRANS_LOGE(TRANS_SVC, "add timestamp to list failed, timestamp=%{public}" PRId64, timestamp);
    SoftBusFree(bindRequestParam);
    return SOFTBUS_MALLOC_ERR;
}

static void TransDelTimestampFormList(BindRequestParam *bindRequestParam, uint64_t timestamp)
{
    TRANS_CHECK_AND_RETURN_LOGE(bindRequestParam != NULL, TRANS_SVC, "bindRequestParam is null");
    TRANS_CHECK_AND_RETURN_LOGE(g_bindRequestList != NULL, TRANS_SVC, "bind request list no init");
    int32_t ret = SoftBusMutexLock(&g_bindRequestList->lock);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "lock bind request list failed");

    BindRequestManager *bindRequest = GetBindRequestManagerByPeer(bindRequestParam);
    BindFailInfo *failItem = NULL;
    BindFailInfo *failNext = NULL;
    if (bindRequest != NULL) {
        LIST_FOR_EACH_ENTRY_SAFE(failItem, failNext, &bindRequest->timestampList, BindFailInfo, node)
        {
            if (failItem->timestamp == timestamp) {
                ListDelete(&failItem->node);
                SoftBusFree(failItem);
                bindRequest->count--;
                TRANS_LOGI(TRANS_SVC, "delete timestamp form list success, timestamp=%{public}" PRId64, timestamp);
                break;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
}

bool GetDeniedFlagByPeer(const char *mySocketName, const char *peerSocketName, const char *peerNetworkId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE((mySocketName != NULL && peerSocketName != NULL && peerNetworkId != NULL), false,
        TRANS_SVC, "mySocketName or peerSocketName or peerNetworkId is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(g_bindRequestList != NULL, false, TRANS_SVC, "bind request list no init");

    BindRequestParam *bindRequestParam = (BindRequestParam *)SoftBusCalloc(sizeof(BindRequestParam));
    TRANS_CHECK_AND_RETURN_RET_LOGE(bindRequestParam != NULL, false, TRANS_SVC, "malloc failed");
    int32_t ret = GenerateParam(mySocketName, peerSocketName, peerNetworkId, bindRequestParam);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, TRANS_SVC, "genarate param failed");
    ret = SoftBusMutexLock(&g_bindRequestList->lock);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, false, TRANS_SVC, "lock bind request list failed");

    bool flag = false;
    BindRequestManager *bindRequest = GetBindRequestManagerByPeer(bindRequestParam);
    if (bindRequest != NULL) {
        flag = bindRequest->bindDeniedFlag;
    }
    (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
    SoftBusFree(bindRequestParam);
    return flag;
}

static void TransResetBindDeniedFlag(BindRequestParam *bindRequestParam)
{
    TRANS_CHECK_AND_RETURN_LOGE(bindRequestParam != NULL, TRANS_SVC, "bindRequestParam is null");
    TRANS_CHECK_AND_RETURN_LOGE(g_bindRequestList != NULL, TRANS_SVC, "bind request list no init");
    int32_t ret = SoftBusMutexLock(&g_bindRequestList->lock);
    TRANS_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, TRANS_SVC, "lock bind request list failed");

    BindRequestManager *bindRequest = GetBindRequestManagerByPeer(bindRequestParam);
    if (bindRequest != NULL) {
        bindRequest->bindDeniedFlag = false;
        TRANS_LOGI(TRANS_SVC, "close bind request protect.");
    }
    (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
}

static void TransBindRequestLoopMsgHandler(SoftBusMessage *msg)
{
    TRANS_CHECK_AND_RETURN_LOGE(msg != NULL, TRANS_MSG, "param invalid");
    TRANS_LOGD(TRANS_SVC, "trans loop process msgType=%{public}d", msg->what);
    BindRequestParam *bindRequestParam = (BindRequestParam *)msg->obj;
    switch (msg->what) {
        case LOOP_DELETE_TIMESTAMP: {
            uint64_t timestamp = msg->arg1;
            TransDelTimestampFormList(bindRequestParam, timestamp);
            break;
        }
        case LOOP_RESET_BIND_DENIED_FLAG: {
            TransResetBindDeniedFlag(bindRequestParam);
            break;
        }
        default: {
            TRANS_LOGE(TRANS_SVC, "msg type=%{public}d not support", msg->what);
            break;
        }
    }
}

int32_t TransBindRequestManagerInit(void)
{
    if (g_bindRequestList != NULL) {
        TRANS_LOGI(TRANS_INIT, "trans bind request manager has init.");
        return SOFTBUS_OK;
    }
    g_bindRequestList = CreateSoftBusList();
    if (g_bindRequestList == NULL) {
        TRANS_LOGE(TRANS_INIT, "create bind request manager failed.");
        return SOFTBUS_MALLOC_ERR;
    }

    g_transLoopHandler.name = (char *)g_transLoopName;
    g_transLoopHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_transLoopHandler.looper == NULL) {
        TRANS_LOGE(TRANS_INIT, "create bind request looper failed.");
        return SOFTBUS_TRANS_INIT_FAILED;
    }
    g_transLoopHandler.HandleMessage = TransBindRequestLoopMsgHandler;
    return SOFTBUS_OK;
}

void TransBindRequestManagerDeinit(void)
{
    if (g_bindRequestList == NULL) {
        return;
    }

    if (SoftBusMutexLock(&g_bindRequestList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return;
    }
    BindRequestManager *bindReqItem = NULL;
    BindRequestManager *bindReqNext = NULL;
    BindFailInfo *bindFailItem = NULL;
    BindFailInfo *bindFailNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(bindReqItem, bindReqNext, &g_bindRequestList->list, BindRequestManager, node)
    {
        LIST_FOR_EACH_ENTRY_SAFE(bindFailItem, bindFailNext, &bindReqItem->timestampList, BindFailInfo, node)
        {
            ListDelete(&bindFailItem->node);
            SoftBusFree(bindFailItem);
        }
        ListDelete(&bindReqItem->node);
        SoftBusFree(bindReqItem);
    }
    (void)SoftBusMutexUnlock(&g_bindRequestList->lock);
    DestroySoftBusList(g_bindRequestList);
    g_bindRequestList = NULL;
    g_transLoopHandler.HandleMessage = NULL;
    g_transLoopHandler.looper = NULL;
}
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_request.h"

#include <securec.h>

#include "auth_common.h"
#include "auth_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

static ListNode g_authRequestList = { &g_authRequestList, &g_authRequestList };

static AuthRequest *FindAuthRequestByRequestId(uint64_t requestId)
{
    AuthRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authRequestList, AuthRequest, node) {
        if (item->requestId == requestId) {
            return item;
        }
    }
    return NULL;
}

static uint32_t GetAuthRequestWaitNum(const AuthRequest *request, ListNode *waitNotifyList)
{
    uint32_t num = 0;
    AuthRequest *item = NULL;
    AuthRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authRequestList, AuthRequest, node) {
        if (item->type != request->type || !CompareConnInfo(&request->connInfo, &item->connInfo, true)) {
            continue;
        }
        if (item->requestId == request->requestId) {
            num++;
            continue;
        }
        if (request->addTime - item->addTime < AUTH_REQUEST_TIMTOUR) {
            AUTH_LOGD(AUTH_CONN, "The two request addr are same. requestId1=%{public}u, requestId2=%{public}u",
                request->requestId, item->requestId);
            num++;
            continue;
        }
        AuthRequest *tmpRequest = (AuthRequest *)SoftBusCalloc(sizeof(AuthRequest));
        if (tmpRequest == NULL) {
            AUTH_LOGI(AUTH_CONN, "malloc fail, notify requested=%{public}d", item->requestId);
            continue;
        }
        tmpRequest->requestId = item->requestId;
        tmpRequest->connCb = item->connCb;
        tmpRequest->verifyCb = item->verifyCb;
        ListTailInsert(waitNotifyList, &tmpRequest->node);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return num;
}

uint32_t AddAuthRequest(const AuthRequest *request)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(request != NULL, 0, AUTH_CONN, "request is NULL");
    AuthRequest *newRequest = SoftBusCalloc(sizeof(AuthRequest));
    if (newRequest == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc AuthRequest fail");
        return 0;
    }
    *newRequest = *request;
    if (!RequireAuthLock()) {
        SoftBusFree(newRequest);
        return 0;
    }
    newRequest->addTime = GetCurrentTimeMs();
    ListTailInsert(&g_authRequestList, &newRequest->node);
    ListNode waitNotifyList = { &waitNotifyList, &waitNotifyList };
    uint32_t waitNum = GetAuthRequestWaitNum(newRequest, &waitNotifyList);
    ReleaseAuthLock();
    AuthRequest *item = NULL;
    AuthRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &waitNotifyList, AuthRequest, node) {
        if (CheckAuthConnCallback(&item->connCb)) {
            item->connCb.onConnOpenFailed(item->requestId, SOFTBUS_AUTH_CONN_FAIL);
        } else if (CheckVerifyCallback(&item->verifyCb)) {
            item->verifyCb.onVerifyFailed(item->requestId, SOFTBUS_AUTH_CONN_FAIL);
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return waitNum;
}

int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(request != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "request is NULL");
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthRequest *item = FindAuthRequestByRequestId(requestId);
    if (item == NULL) {
        ReleaseAuthLock();
        return SOFTBUS_NOT_FIND;
    }
    *request = *item;
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t GetAuthRequestNoLock(uint32_t requestId, AuthRequest *request)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(request != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "request is NULL");
    AuthRequest *item = FindAuthRequestByRequestId(requestId);
    if (item == NULL) {
        AUTH_LOGE(AUTH_CONN, "find auth request failed");
        return SOFTBUS_NOT_FIND;
    }
    *request = *item;
    return SOFTBUS_OK;
}

int32_t FindAuthRequestByConnInfo(const AuthConnInfo *connInfo, AuthRequest *request)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "connInfo is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(request != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "request is NULL");
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authRequestList, AuthRequest, node) {
        if (item->type != REQUEST_TYPE_VERIFY || !CompareConnInfo(&item->connInfo, connInfo, true)) {
            continue;
        }
        *request = *item;
        ReleaseAuthLock();
        return SOFTBUS_OK;
    }
    ReleaseAuthLock();
    return SOFTBUS_NOT_FIND;
}

int32_t FindAndDelAuthRequestByConnInfo(uint32_t requestId, const AuthConnInfo *connInfo)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(connInfo != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "connInfo is NULL");
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthRequest *item = NULL;
    AuthRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authRequestList, AuthRequest, node) {
        if (!CompareConnInfo(&item->connInfo, connInfo, true)) {
            continue;
        }
        if (item->requestId == requestId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            continue;
        }
        if (CheckAuthConnCallback(&item->connCb)) {
            item->connCb.onConnOpenFailed(item->requestId, SOFTBUS_AUTH_CONN_FAIL);
        } else if (CheckVerifyCallback(&item->verifyCb)) {
            item->verifyCb.onVerifyFailed(item->requestId, SOFTBUS_AUTH_CONN_FAIL);
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    ReleaseAuthLock();
    return SOFTBUS_NOT_FIND;
}

void DelAuthRequest(uint32_t requestId)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthRequest *item = FindAuthRequestByRequestId(requestId);
    if (item == NULL) {
        ReleaseAuthLock();
        return;
    }
    AUTH_LOGD(AUTH_CONN, "del auth request requestId=%{public}u", requestId);
    ListDelete(&item->node);
    SoftBusFree(item);
    ReleaseAuthLock();
}

void ClearAuthRequest(void)
{
    if (!RequireAuthLock()) {
        return;
    }
    AuthRequest *item = NULL;
    AuthRequest *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authRequestList, AuthRequest, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    ListInit(&g_authRequestList);
    ReleaseAuthLock();
}

bool CheckVerifyCallback(const AuthVerifyCallback *verifyCb)
{
    if (verifyCb == NULL) {
        AUTH_LOGE(AUTH_CONN, "verifyCb is null");
        return false;
    }
    if (verifyCb->onVerifyPassed == NULL || verifyCb->onVerifyFailed == NULL) {
        AUTH_LOGE(AUTH_CONN, "onVerifyPassed or onVerifyFailed is null");
        return false;
    }
    return true;
}

bool CheckAuthConnCallback(const AuthConnCallback *connCb)
{
    if (connCb == NULL) {
        AUTH_LOGE(AUTH_CONN, "connCb is null");
        return false;
    }
    if (connCb->onConnOpened == NULL || connCb->onConnOpenFailed == NULL) {
        AUTH_LOGE(AUTH_CONN, "onConnOpened or onConnOpenFailed is null");
        return false;
    }
    return true;
}

void PerformVerifyCallback(uint32_t requestId, int32_t result, AuthHandle authHandle, const NodeInfo *info)
{
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        AUTH_LOGE(AUTH_CONN, "authHandle type error");
        return;
    }
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get auth request failed");
        return;
    }
    if (!CheckVerifyCallback(&request.verifyCb)) {
        AUTH_LOGE(AUTH_CONN, "check verifyCb failed");
        return;
    }
    if (result == SOFTBUS_OK) {
        request.verifyCb.onVerifyPassed(request.requestId, authHandle, info);
    } else {
        request.verifyCb.onVerifyFailed(request.requestId, result);
    }
}

void PerformAuthConnCallback(uint32_t requestId, int32_t result, int64_t authId)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get auth request failed");
        return;
    }
    if (!CheckAuthConnCallback(&request.connCb)) {
        AUTH_LOGE(AUTH_CONN, "check connCb failed");
        return;
    }
    AuthHandle authHandle = { .authId = authId, .type = request.connInfo.type };
    if (result == SOFTBUS_OK) {
        request.connCb.onConnOpened(request.requestId, authHandle);
    } else {
        request.connCb.onConnOpenFailed(request.requestId, result);
    }
}

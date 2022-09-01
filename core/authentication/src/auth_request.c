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
#include "softbus_adapter_mem.h"

static ListNode g_authRequestList = {&g_authRequestList, &g_authRequestList};

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

static uint32_t GetAuthRequestWaitNum(AuthRequest *request)
{
    uint32_t num = 0;
    AuthRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authRequestList, AuthRequest, node) {
        if (item->type == request->type &&
            CompareConnInfo(&request->connInfo, &item->connInfo)) {
            num++;
        }
    }
    return num;
}

uint32_t AddAuthRequest(const AuthRequest *request)
{
    CHECK_NULL_PTR_RETURN_VALUE(request, 0);
    AuthRequest *newRequest = SoftBusCalloc(sizeof(AuthRequest));
    if (newRequest == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc AuthRequest fail.");
        return 0;
    }
    *newRequest = *request;
    if (!RequireAuthLock()) {
        SoftBusFree(newRequest);
        return 0;
    }
    ListTailInsert(&g_authRequestList, &newRequest->node);
    uint32_t waitNum = GetAuthRequestWaitNum(newRequest);
    ReleaseAuthLock();
    return waitNum;
}

int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request)
{
    CHECK_NULL_PTR_RETURN_VALUE(request, SOFTBUS_INVALID_PARAM);
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

int32_t UpdateAuthRequestConnInfo(uint32_t requestId, const AuthConnInfo *connInfo)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthRequest *item = FindAuthRequestByRequestId(requestId);
    if (item == NULL) {
        ReleaseAuthLock();
        return SOFTBUS_NOT_FIND;
    }
    if (item->connInfo.type != connInfo->type) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR,
            "verify request(id=%u) unexpected connType: %d -> %d.",
            requestId, item->connInfo.type, connInfo->type);
        ReleaseAuthLock();
        return SOFTBUS_ERR;
    }
    item->connInfo = *connInfo;
    ReleaseAuthLock();
    return SOFTBUS_OK;
}

int32_t FindAuthRequestByConnInfo(const AuthConnInfo *connInfo, AuthRequest *request)
{
    CHECK_NULL_PTR_RETURN_VALUE(connInfo, SOFTBUS_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(request, SOFTBUS_INVALID_PARAM);
    if (!RequireAuthLock()) {
        return SOFTBUS_LOCK_ERR;
    }
    AuthRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authRequestList, AuthRequest, node) {
        if (item->type != REQUEST_TYPE_VERIFY ||
            !CompareConnInfo(&item->connInfo, connInfo)) {
            continue;
        }
        *request = *item;
        ReleaseAuthLock();
        return SOFTBUS_OK;
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
        return false;
    }
    if (verifyCb->onVerifyPassed == NULL || verifyCb->onVerifyFailed == NULL) {
        return false;
    }
    return true;
}

bool CheckAuthConnCallback(const AuthConnCallback *connCb)
{
    if (connCb == NULL) {
        return false;
    }
    if (connCb->onConnOpened == NULL || connCb->onConnOpenFailed == NULL) {
        return false;
    }
    return true;
}

void PerformVerifyCallback(uint32_t requestId, int32_t result, int64_t authId, const NodeInfo *info)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        return;
    }
    if (!CheckVerifyCallback(&request.verifyCb)) {
        return;
    }
    if (result == SOFTBUS_OK) {
        request.verifyCb.onVerifyPassed(request.requestId, authId, info);
    } else {
        request.verifyCb.onVerifyFailed(request.requestId, result);
    }
}

void PerformAuthConnCallback(uint32_t requestId, int32_t result, int64_t authId)
{
    AuthRequest request;
    if (GetAuthRequest(requestId, &request) != SOFTBUS_OK) {
        return;
    }
    if (!CheckAuthConnCallback(&request.connCb)) {
        return;
    }
    if (result == SOFTBUS_OK) {
        request.connCb.onConnOpened(request.requestId, authId);
    } else {
        request.connCb.onConnOpenFailed(request.requestId, result);
    }
}

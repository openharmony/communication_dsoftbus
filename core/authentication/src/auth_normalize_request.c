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

#include "auth_normalize_request.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_common.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

#define UDID_SHORT_HASH_STR 16

static ListNode g_normalizeRequestList = { &g_normalizeRequestList, &g_normalizeRequestList };

static uint32_t GetSameRequestNum(char *udidHash)
{
    uint32_t num = 0;
    NormalizeRequest *item = NULL;
    char *anonyUdidHash = NULL;
    Anonymize(udidHash, &anonyUdidHash);
    AUTH_LOGI(AUTH_HICHAIN, "udidHash=%{public}s", AnonymizeWrapper(anonyUdidHash));
    AnonymizeFree(anonyUdidHash);
    LIST_FOR_EACH_ENTRY(item, &g_normalizeRequestList, NormalizeRequest, node) {
        if (strncmp(item->udidHash, udidHash, UDID_SHORT_HASH_STR) != 0) {
            continue;
        }
        num++;
    }
    return num;
}

static int32_t GetRequestListByUdidHash(char *udidHash, bool isNeedClear, NormalizeRequest **requests, uint32_t *num)
{
    if (udidHash == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "udidHash is null or len < SHORT_HASH_LEN");
        return SOFTBUS_INVALID_PARAM;
    }
    *num = GetSameRequestNum(udidHash);
    if ((*num) == 0) {
        AUTH_LOGI(AUTH_HICHAIN, "no other requests exist.");
        return SOFTBUS_OK;
    }
    *requests = (NormalizeRequest *)SoftBusCalloc(sizeof(NormalizeRequest) * (*num));
    if (*requests == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "malloc fail.");
        return SOFTBUS_MEM_ERR;
    }
    NormalizeRequest *item = NULL;
    NormalizeRequest *next = NULL;
    uint32_t index = 0;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_normalizeRequestList, NormalizeRequest, node) {
        if (strncmp(item->udidHash, udidHash, UDID_SHORT_HASH_STR) != 0 || index >= (*num)) {
            continue;
        }
        (*requests)[index++] = *item;
        if (!isNeedClear) {
            continue;
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return SOFTBUS_OK;
}

static int32_t FindAndDelNormalizeRequest(int64_t authSeq, NormalizeRequest *request)
{
    if (request == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    NormalizeRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_normalizeRequestList, NormalizeRequest, node) {
        if (item->authSeq == authSeq) {
            *request = *item;
            ListDelete(&item->node);
            SoftBusFree(item);
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_AUTH_NOT_FOUND;
}

static int32_t GetNormalizeRequestList(
    int64_t authSeq, bool isNeedClear, NormalizeRequest *request, NormalizeRequest **requests, uint32_t *num)
{
    if (num == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_HICHAIN, "RequireAuthLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (FindAndDelNormalizeRequest(authSeq, request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "not found normalize request");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_INNER_ERR;
    }
    int32_t ret = GetRequestListByUdidHash(request->udidHash, isNeedClear, requests, num);
    ReleaseAuthLock();
    return ret;
}

void DelAuthNormalizeRequest(int64_t authSeq)
{
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_HICHAIN, "RequireAuthLock fail");
        return;
    }
    NormalizeRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_normalizeRequestList, NormalizeRequest, node) {
        if (item->authSeq == authSeq) {
            ListDelete(&item->node);
            SoftBusFree(item);
            AUTH_LOGI(AUTH_HICHAIN, "del normalize request authSeq=%{public}" PRId64, authSeq);
            break;
        }
    }
    ReleaseAuthLock();
}

bool AuthIsRepeatedAuthRequest(int64_t authSeq)
{
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_HICHAIN, "RequireAuthLock fail");
        return false;
    }
    NormalizeRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_normalizeRequestList, NormalizeRequest, node) {
        if (item->authSeq == authSeq) {
            ReleaseAuthLock();
            return true;
        }
    }
    ReleaseAuthLock();
    return false;
}

uint32_t AddNormalizeRequest(const NormalizeRequest *request)
{
    CHECK_NULL_PTR_RETURN_VALUE(request, 0);
    NormalizeRequest *newRequest = SoftBusCalloc(sizeof(NormalizeRequest));
    if (newRequest == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc AuthRequest fail");
        return 0;
    }
    *newRequest = *request;
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_CONN, "lock fail");
        SoftBusFree(newRequest);
        return 0;
    }
    ListTailInsert(&g_normalizeRequestList, &newRequest->node);
    uint32_t waitNum = GetSameRequestNum(newRequest->udidHash);
    ReleaseAuthLock();
    return waitNum;
}

void NotifyNormalizeRequestSuccess(int64_t authSeq, bool isSupportNego)
{
    NormalizeRequest *requests = NULL;
    NormalizeRequest request = { 0 };
    uint32_t num = 0;
    if (GetNormalizeRequestList(authSeq, true, &request, &requests, &num) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_HICHAIN, "get hichain request fail: authSeq=%{public}" PRId64, authSeq);
        return;
    }
    if (num == 0 || requests == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "requests is NULL");
        return;
    }
    AUTH_LOGI(AUTH_HICHAIN, "request num=%{public}d", num);
    for (uint32_t i = 0; i < num; i++) {
        if (isSupportNego && requests[i].connInfo.type == request.connInfo.type) {
            continue;
        }
        AUTH_LOGI(AUTH_HICHAIN, "notify AuthSessionSaveSessionKey: authSeq=%{public}" PRId64, requests[i].authSeq);
        (void)AuthNotifyRequestVerify(requests[i].authSeq);
    }
    SoftBusFree(requests);
}

void NotifyNormalizeRequestFail(int64_t authSeq, int32_t ret)
{
    (void)ret;
    NormalizeRequest *requests = NULL;
    NormalizeRequest request = { 0 };
    uint32_t num = 0;
    if (GetNormalizeRequestList(authSeq, false, &request, &requests, &num) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_HICHAIN, "get hichain request fail: authSeq=%{public}" PRId64, authSeq);
        return;
    }
    if (num == 0 || requests == NULL) {
        return;
    }
    for (uint32_t i = 0; i < num; i++) {
        if (AuthNotifyRequestVerify(requests[i].authSeq) == SOFTBUS_OK) {
            AUTH_LOGI(AUTH_HICHAIN, "continue auth, authSeq=%{public}" PRId64, requests[i].authSeq);
            break;
        }
    }
    SoftBusFree(requests);
}
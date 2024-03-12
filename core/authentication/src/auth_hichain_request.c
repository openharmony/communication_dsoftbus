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

#include "auth_hichain_request.h"

#include <securec.h>

#include "auth_common.h"
#include "auth_hichain.h"
#include "auth_log.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

static ListNode g_hichainClientRequestList = {&g_hichainClientRequestList, &g_hichainClientRequestList};
static ListNode g_hichainServerRequestList = {&g_hichainServerRequestList, &g_hichainServerRequestList};

static uint32_t GetSameRequestNum(char *udid, bool isServer)
{
    ListNode *list = isServer ? &g_hichainServerRequestList : &g_hichainClientRequestList;
    HichainRequest *item = NULL;
    uint32_t num = 0;
    LIST_FOR_EACH_ENTRY(item, list, HichainRequest, node) {
        if (strcmp(item->udid, udid) != 0) {
            continue;
        }
        num++;
    }
    return num;
}

static int32_t GetRequestListByUdid(char *udid, bool isServer, bool isNeedClear,
    HichainRequest **requests, uint32_t *num)
{
    if (udid == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "param is null.");
        return SOFTBUS_AUTH_INNER_ERR;
    }
    *num = GetSameRequestNum(udid, isServer);
    if ((*num) == 0) {
        AUTH_LOGI(AUTH_HICHAIN, "no other requests exist.");
        return SOFTBUS_OK;
    }
    AUTH_LOGI(AUTH_HICHAIN, "hichain request wait num=%{public}d.", (*num));
    ListNode *list = isServer ? &g_hichainServerRequestList : &g_hichainClientRequestList;
    *requests = (HichainRequest *)SoftBusCalloc(sizeof(HichainRequest) * (*num));
    if (*requests == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "malloc fail.");
        return SOFTBUS_MEM_ERR;
    }
    HichainRequest *item = NULL;
    HichainRequest *next = NULL;
    uint32_t index = 0;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, list, HichainRequest, node) {
        if (strcmp(item->udid, udid) != 0 || index >= (*num)) {
            continue;
        }
        *(requests[index++]) = *item;
        if (!isNeedClear) {
            continue;
        }
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    return SOFTBUS_OK;
}

static int32_t FindAndDelHichainRequestByAuthSeq(int64_t authSeq, HichainRequest *request)
{
    if (request == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    HichainRequest *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_hichainClientRequestList, HichainRequest, node) {
        if (item->authSeq == authSeq) {
            *request = *item;
            ListDelete(&item->node);
            SoftBusFree(item);
            return SOFTBUS_OK;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &g_hichainServerRequestList, HichainRequest, node) {
        if (item->authSeq == authSeq) {
            *request = *item;
            ListDelete(&item->node);
            SoftBusFree(item);
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}

static int32_t GetHichainRequestList(int64_t authSeq, bool isNeedClear, HichainRequest **requests, uint32_t *num)
{
    if (num == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!RequireAuthLock()) {
        AUTH_LOGE(AUTH_HICHAIN, "RequireAuthLock fail");
        return SOFTBUS_ERR;
    }
    HichainRequest request = {0};
    if (FindAndDelHichainRequestByAuthSeq(authSeq, &request) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "not found hichain request");
        ReleaseAuthLock();
        return SOFTBUS_AUTH_INNER_ERR;
    }
    int32_t ret = GetRequestListByUdid(request.udid, request.isServer, isNeedClear, requests, num);
    ReleaseAuthLock();
    return ret;
}

uint32_t AddHichainRequest(const HichainRequest *request)
{
    CHECK_NULL_PTR_RETURN_VALUE(request, 0);
    uint32_t waitNum = 0;
    HichainRequest *item = NULL;
    HichainRequest *newRequest = SoftBusCalloc(sizeof(HichainRequest));
    if (newRequest == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc AuthRequest fail");
        return 0;
    }
    *newRequest = *request;
    ListNode *list = newRequest->isServer ? &g_hichainServerRequestList : &g_hichainClientRequestList;
    if (!RequireAuthLock()) {
        SoftBusFree(newRequest);
        return 0;
    }
    ListTailInsert(list, &newRequest->node);
    LIST_FOR_EACH_ENTRY(item, list, HichainRequest, node) {
        if (strcmp(item->udid, newRequest->udid) != 0) {
            continue;
        }
        waitNum++;
    }
    ReleaseAuthLock();
    return waitNum;
}

void NotifyHiChainRequestSuccess(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    HichainRequest *requests = NULL;
    uint32_t num = 0;
    if (GetHichainRequestList(authSeq, true, &requests, &num) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_HICHAIN, "get hichain request fail: authSeq=%{public}" PRId64, authSeq);
        return;
    }
    if (num == 0 || requests == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "requests is NULL");
        return;
    }
    AUTH_LOGI(AUTH_HICHAIN, "request num=%{public}d", num);
    for (uint32_t i = 0; i < num; i++) {
        AUTH_LOGI(AUTH_HICHAIN, "notify save sessionkey: authSeq=%{public}" PRId64 ", isServer=%{public}d",
            requests[i].authSeq, requests[i].isServer);
        SessionKey key = { .len = sessionKeyLen };
        if (memcpy_s(key.value, sizeof(key.value), sessionKey, sessionKeyLen) != EOK ||
            AuthRecoverySessionKey(requests[i].authSeq, key) != SOFTBUS_OK) {
            AUTH_LOGI(AUTH_HICHAIN, "recovery fail, authSeq=%{public}" PRId64 ", isServer=%{public}d",
                requests[i].authSeq, requests[i].isServer);
        }
        (void)memset_s(&key, sizeof(key), 0, sizeof(key));
    }
    SoftBusFree(requests);
}

void NotifyHiChainRequestFail(int64_t authSeq, bool isNeedReAuth)
{
    HichainRequest *requests = NULL;
    uint32_t num = 0;
    if (GetHichainRequestList(authSeq, !isNeedReAuth, &requests, &num) != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_HICHAIN, "get hichain request fail: authSeq=%{public}" PRId64, authSeq);
        return;
    }
    if (num == 0 || requests == NULL) {
        return;
    }
    if (requests[0].isServer || !isNeedReAuth) {
        SoftBusFree(requests);
        return;
    }
    for (uint32_t i = 0; i < num; i++) {
        if (HichainStartAuth(requests[i].authSeq, requests[i].udid, requests[i].peerUid, false) == SOFTBUS_OK) {
            break;
        }
    }
    SoftBusFree(requests);
}

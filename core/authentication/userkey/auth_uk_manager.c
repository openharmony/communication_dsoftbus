/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "auth_uk_manager.h"

#include <securec.h>

#include "anonymizer.h"
#include "auth_log.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_deviceprofile.h"
#include "auth_hichain.h"
#include "auth_hichain_adapter.h"
#include "auth_identity_service_adapter.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "session.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_transmission_interface.h"

#define AUTH_APPID              "softbus_auth"
#define ENCRYPT_INDEX_LEN       4
#define KEY_LENGTH              16
#define AUTH_PKT_HEAD_LEN       24
#define JSON_UK_DATA_TYPE       "ukDataType"
#define UK_NEGO_PKGNAME         "gen_Uk"
#define UK_NEGO_SESSIONNAME     "ohos.genUk.com"
#define IS_SUPPORT_UK_NEGO      "is_support_uk"
#define PEER_ACCOUNT_ID         "peer_account_id"
#define LOCAL_ACCOUNT_ID        "local_account_id"
#define DEFAULT_ACCOUNT_UID     "ohosAnonymousUid"
#define DEFAULT_CHANNEL_ID      0
#define UK_MAX_INSTANCE_CNT     0x2000000
#define UK_NEGO_PROCESS_TIMEOUT (10 * 1000LL)
#define UK_AGING_TIME           (168 * 60 * 60 * 1000L)
#define UK_SEQ_NETWORK_ID_BITS  16
#define SEQ_TIME_STAMP_BITS     8
#define SEQ_TIME_STAMP_MASK     0xFFL
#define UK_SEQ_INTEGER_BITS     7
#define UK_SEQ_INTEGER_MAX      0x0FFFFFFF

static uint32_t g_uniqueId = 0;
static SoftBusList *g_ukNegotiateList = NULL;
static SoftBusMutex g_ukNegotiateListLock;

static void OnGenFailed(uint32_t requestId, int32_t reason);
static void OnGenSuccess(uint32_t requestId);
static int32_t SendUkNegoCloseAckEvent(int32_t channelId, uint32_t requestId);
static HiChainAuthMode GetHichainAuthMode(bool isPeerSupportUkNego, const AuthACLInfo *info);

typedef struct {
    uint32_t requestId;
    bool isGenUkSuccess;
    int32_t reason;
} SyncGenUkResult;

typedef enum {
    GENUK_STATE_WAIT = 1,
    GENUK_STATE_START,
    GENUK_STATE_UNKNOW,
} GenUkStartState;

typedef struct {
    int32_t ukId;
    int32_t channelId;
    uint32_t requestId;
    uint32_t keyLen;
    HiChainAuthMode authMode;
    GenUkStartState state;
    AuthACLInfo info;
    UkNegotiateInfo negoInfo;
    AuthGenUkCallback genCb;
    ListNode node;
} UkNegotiateInstance;

static bool RequireUkNegotiateListLock(void)
{
    if (SoftBusMutexLock(&g_ukNegotiateListLock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "UkNegotiateList lock fail");
        return false;
    }
    return true;
}

static void ReleaseUkNegotiateListLock(void)
{
    if (SoftBusMutexUnlock(&g_ukNegotiateListLock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "UkNegotiateList unlock fail");
    }
}

int32_t InitUkNegoInstanceList(void)
{
    if (g_ukNegotiateList != NULL) {
        return SOFTBUS_OK;
    }
    g_ukNegotiateList = CreateSoftBusList();
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego create instance list fail");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_ukNegotiateList->cnt = 0;
    return SOFTBUS_OK;
}

void DeInitUkNegoInstanceList(void)
{
    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;

    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    AUTH_LOGI(AUTH_CONN, "deinit uknego instance");
    ReleaseUkNegotiateListLock();
    DestroySoftBusList(g_ukNegotiateList);
    g_ukNegotiateList = NULL;
}

static int32_t GetGenUkInstanceByChannel(int32_t channelId, UkNegotiateInstance *instance)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_CONN, "uknego instance is null");
        return SOFTBUS_NO_INIT;
    }

    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;
    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (item->channelId != channelId) {
            continue;
        }
        if (instance != NULL &&
            memcpy_s(instance, sizeof(UkNegotiateInstance), item, sizeof(UkNegotiateInstance)) != EOK) {
            ReleaseUkNegotiateListLock();
            AUTH_LOGE(AUTH_CONN, "uknego memcpy_s instance fail, channelId=%{public}d", channelId);
            return SOFTBUS_MEM_ERR;
        }
        ReleaseUkNegotiateListLock();
        return SOFTBUS_OK;
    }
    ReleaseUkNegotiateListLock();
    AUTH_LOGE(AUTH_CONN, "uknego instance not found, channelId=%{public}d", channelId);
    return SOFTBUS_AUTH_UK_INSTANCE_NOT_FIND;
}

static uint32_t GetSameUkInstanceNum(AuthACLInfo *info)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return 0;
    }

    uint32_t num = 0;
    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;
    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return num;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (!CompareByAllAcl(info, &item->info, info->isServer == item->info.isServer)) {
            continue;
        }
        if (item->state == GENUK_STATE_START) {
            num++;
        }
    }
    AUTH_LOGI(AUTH_CONN, "list has same aclinfo instance num=%{public}u", num);
    ReleaseUkNegotiateListLock();
    return num;
}

static int32_t GetGenUkInstanceByReq(uint32_t requestId, UkNegotiateInstance *instance)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return SOFTBUS_NO_INIT;
    }

    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;
    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        if (instance != NULL &&
            memcpy_s(instance, sizeof(UkNegotiateInstance), item, sizeof(UkNegotiateInstance)) != EOK) {
            ReleaseUkNegotiateListLock();
            AUTH_LOGE(AUTH_CONN, "uknego memcpy_s instance fail, requestId=%{public}u", requestId);
            return SOFTBUS_MEM_ERR;
        }
        ReleaseUkNegotiateListLock();
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_CONN, "uknego req not found, requestId=%{public}u", requestId);
    ReleaseUkNegotiateListLock();
    return SOFTBUS_AUTH_UK_INSTANCE_NOT_FIND;
}

static UkNegotiateInfo *GetUkNegotiateInfo(uint32_t requestId)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return NULL;
    }
    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (item->requestId == requestId) {
            return &item->negoInfo;
        }
    }
    return NULL;
}

static void GenUkTimeoutProcess(void *para)
{
    OnGenFailed((uint32_t)(uintptr_t)para, SOFTBUS_CHANNEL_AUTH_START_TIMEOUT);
}

static void AuthGenUkStartTimeout(uint32_t requestId)
{
    LnnAsyncCallbackDelayHelper(
        GetLooper(LOOP_TYPE_DEFAULT), GenUkTimeoutProcess, (void *)(uintptr_t)requestId, UK_NEGO_PROCESS_TIMEOUT);
}

void PrintfAuthAclInfo(uint32_t requestId, uint32_t channelId, const AuthACLInfo *info)
{
    if (info == NULL) {
        AUTH_LOGE(AUTH_CONN, "AuthACLInfo is null");
        return;
    }

    char *anonySourceUdid = NULL;
    char *anonySinkUdid = NULL;
    char *anonySourceAccountId = NULL;
    char *anonySinkAccountId = NULL;
    Anonymize(info->sourceUdid, &anonySourceUdid);
    Anonymize(info->sinkUdid, &anonySinkUdid);
    Anonymize(info->sourceAccountId, &anonySourceAccountId);
    Anonymize(info->sinkAccountId, &anonySinkAccountId);
    AUTH_LOGI(AUTH_CONN,
        "uknego requestId=%{public}u, channelId=%{public}d, isServer=%{public}d, sourceUdid=%{public}s, "
        "sinkUdid=%{public}s, sourceAccountId=%{public}s, sinkAccountId=%{public}s, sourceUserId=%{public}d, "
        "sinkUserId=%{public}d, sourceTokenId=%{public}" PRIu64 ", sinkTokenId=%{public}" PRIu64,
        requestId, channelId, info->isServer, AnonymizeWrapper(anonySourceUdid), AnonymizeWrapper(anonySinkUdid),
        AnonymizeWrapper(anonySourceAccountId), AnonymizeWrapper(anonySinkAccountId), info->sourceUserId,
        info->sinkUserId, info->sourceTokenId, info->sinkTokenId);
    AnonymizeFree(anonySourceUdid);
    AnonymizeFree(anonySinkUdid);
    AnonymizeFree(anonySourceAccountId);
    AnonymizeFree(anonySinkAccountId);
}

static int32_t CreateUkNegotiateInstance(
    uint32_t requestId, uint32_t channelId, const AuthACLInfo *info, const AuthGenUkCallback *genCb)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return SOFTBUS_NO_INIT;
    }

    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    UkNegotiateInstance *instance = NULL;
    instance = (UkNegotiateInstance *)SoftBusCalloc(sizeof(UkNegotiateInstance));
    if (instance == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc instance fail");
        ReleaseUkNegotiateListLock();
        return SOFTBUS_MEM_ERR;
    }
    instance->channelId = channelId;
    instance->requestId = requestId;
    instance->info = *info;
    instance->authMode = GetHichainAuthMode(true, info);
    instance->state = GENUK_STATE_UNKNOW;
    if (memcpy_s(&instance->genCb, sizeof(AuthGenUkCallback), (uint8_t *)genCb, sizeof(AuthGenUkCallback)) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy_s uknego callback data fail");
        SoftBusFree(instance);
        ReleaseUkNegotiateListLock();
        return SOFTBUS_AUTH_ACL_SET_CHANNEL_FAIL;
    }
    instance->negoInfo.isRecvSessionKeyEvent = false;
    instance->negoInfo.isRecvFinishEvent = false;
    instance->negoInfo.isRecvCloseAckEvent = false;
    ListInit(&instance->node);
    ListAdd(&g_ukNegotiateList->list, &instance->node);
    PrintfAuthAclInfo(requestId, channelId, info);
    ReleaseUkNegotiateListLock();
    AuthGenUkStartTimeout(requestId);
    return SOFTBUS_OK;
}

static int32_t UpdateUkNegotiateInfo(uint32_t requestId, const UkNegotiateInstance *instance)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return SOFTBUS_NO_INIT;
    }

    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;
    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        item->ukId = instance->ukId;
        item->channelId = instance->channelId;
        item->keyLen = instance->keyLen;
        item->authMode = instance->authMode;
        item->state = instance->state;
        item->negoInfo.isRecvSessionKeyEvent = instance->negoInfo.isRecvSessionKeyEvent;
        item->negoInfo.isRecvFinishEvent = instance->negoInfo.isRecvFinishEvent;
        item->negoInfo.isRecvCloseAckEvent = instance->negoInfo.isRecvCloseAckEvent;
        AUTH_LOGI(AUTH_CONN,
            "update uknego requestId=%{public}u, channelId=%{public}d, state=%{public}d, "
            "isCloseAck=%{public}d, isFinish=%{public}d, isSessionKey=%{public}d",
            requestId, item->channelId, item->state, item->negoInfo.isRecvSessionKeyEvent,
            item->negoInfo.isRecvFinishEvent, item->negoInfo.isRecvCloseAckEvent);
        if (memcpy_s(&item->info, sizeof(AuthACLInfo), (uint8_t *)&instance->info, sizeof(AuthACLInfo)) != EOK) {
            AUTH_LOGE(AUTH_CONN, "memcpy_s uknego acl data fail");
            return SOFTBUS_AUTH_ACL_SET_CHANNEL_FAIL;
        }
        ReleaseUkNegotiateListLock();
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_CONN, "uknego req not found, requestId=%{public}u", requestId);
    ReleaseUkNegotiateListLock();
    return SOFTBUS_AUTH_ACL_SET_CHANNEL_FAIL;
}

static void DeleteUkNegotiateInstance(uint32_t requestId)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return;
    }

    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;
    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        AUTH_LOGE(AUTH_CONN, "delete uknego instance, requestId=%{public}u", requestId);
        ListDelete(&(item->node));
        SoftBusFree(item);
        ReleaseUkNegotiateListLock();
        return;
    }
    AUTH_LOGE(AUTH_CONN, "uknego instance not found, requestId=%{public}u", requestId);
    ReleaseUkNegotiateListLock();
}

bool CompareByAllAcl(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    if (oldAcl == NULL || newAcl == NULL) {
        AUTH_LOGE(AUTH_CONN, "acl invalid param");
        return false;
    }

    bool isCompared = false;
    if (isSameSide) {
        if (strcmp(oldAcl->sourceUdid, newAcl->sourceUdid) != 0 || strcmp(oldAcl->sinkUdid, newAcl->sinkUdid) != 0 ||
            oldAcl->sourceUserId != newAcl->sourceUserId || oldAcl->sinkUserId != newAcl->sinkUserId ||
            oldAcl->sourceTokenId != newAcl->sourceTokenId || oldAcl->sinkTokenId != newAcl->sinkTokenId ||
            strcmp(oldAcl->sourceAccountId, newAcl->sourceAccountId) != 0 ||
            strcmp(oldAcl->sinkAccountId, newAcl->sinkAccountId) != 0) {
            AUTH_LOGE(AUTH_CONN, "same side compare fail");
            return false;
        }
        isCompared = true;
    } else {
        if (strcmp(oldAcl->sourceUdid, newAcl->sinkUdid) != 0 || strcmp(oldAcl->sinkUdid, newAcl->sourceUdid) != 0 ||
            oldAcl->sourceUserId != newAcl->sinkUserId || oldAcl->sinkUserId != newAcl->sourceUserId ||
            oldAcl->sourceTokenId != newAcl->sinkTokenId || oldAcl->sinkTokenId != newAcl->sourceTokenId ||
            strcmp(oldAcl->sourceAccountId, newAcl->sinkAccountId) != 0 ||
            strcmp(oldAcl->sinkAccountId, newAcl->sourceAccountId) != 0) {
            AUTH_LOGE(AUTH_CONN, "diff side compare fail");
            return false;
        }
        isCompared = true;
    }
    return isCompared;
}

bool CompareByAclDiffAccount(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    if (oldAcl == NULL || newAcl == NULL) {
        AUTH_LOGE(AUTH_CONN, "acl invalid param");
        return false;
    }

    bool isCompared = false;
    if (isSameSide) {
        if (strcmp(oldAcl->sourceUdid, newAcl->sourceUdid) != 0 || strcmp(oldAcl->sinkUdid, newAcl->sinkUdid) != 0 ||
            oldAcl->sourceUserId != newAcl->sourceUserId || oldAcl->sinkUserId != newAcl->sinkUserId ||
            oldAcl->sourceTokenId != newAcl->sourceTokenId || oldAcl->sinkTokenId != newAcl->sinkTokenId) {
            AUTH_LOGE(AUTH_CONN, "same side compare fail");
            return false;
        }
        isCompared = true;
    } else {
        if (strcmp(oldAcl->sourceUdid, newAcl->sinkUdid) != 0 || strcmp(oldAcl->sinkUdid, newAcl->sourceUdid) != 0 ||
            oldAcl->sourceUserId != newAcl->sinkUserId || oldAcl->sinkUserId != newAcl->sourceUserId ||
            oldAcl->sourceTokenId != newAcl->sinkTokenId || oldAcl->sinkTokenId != newAcl->sourceTokenId) {
            AUTH_LOGE(AUTH_CONN, "diff side compare fail");
            return false;
        }
        isCompared = true;
    }
    return isCompared;
}

bool CompareByAclSameAccount(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    if (oldAcl == NULL || newAcl == NULL) {
        AUTH_LOGE(AUTH_CONN, "acl invalid param");
        return false;
    }

    if (strcmp(DEFAULT_ACCOUNT_UID, newAcl->sourceAccountId) == 0 ||
        strcmp(DEFAULT_ACCOUNT_UID, newAcl->sinkAccountId) == 0 ||
        strcmp(newAcl->sourceAccountId, newAcl->sinkAccountId) != 0) {
        AUTH_LOGE(AUTH_CONN, "acl is not same account");
        return false;
    }
    bool isCompared = false;
    if (isSameSide) {
        if (strcmp(oldAcl->sourceUdid, newAcl->sourceUdid) != 0 || strcmp(oldAcl->sinkUdid, newAcl->sinkUdid) != 0 ||
            oldAcl->sourceUserId != newAcl->sourceUserId || oldAcl->sinkUserId != newAcl->sinkUserId ||
            strcmp(oldAcl->sourceAccountId, newAcl->sourceAccountId) != 0 ||
            strcmp(oldAcl->sinkAccountId, newAcl->sinkAccountId) != 0) {
            AUTH_LOGE(AUTH_CONN, "same side compare fail");
            return false;
        }
        isCompared = true;
    } else {
        if (strcmp(oldAcl->sourceUdid, newAcl->sinkUdid) != 0 || strcmp(oldAcl->sinkUdid, newAcl->sourceUdid) != 0 ||
            oldAcl->sourceUserId != newAcl->sinkUserId || oldAcl->sinkUserId != newAcl->sourceUserId ||
            strcmp(oldAcl->sourceAccountId, newAcl->sinkAccountId) != 0 ||
            strcmp(oldAcl->sinkAccountId, newAcl->sourceAccountId) != 0) {
            AUTH_LOGE(AUTH_CONN, "diff side compare fail");
            return false;
        }
        isCompared = true;
    }
    return isCompared;
}

static void AsyncCallGenUkResultReceived(void *para)
{
    if (para == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }
    SyncGenUkResult *res = (SyncGenUkResult *)para;
    UkNegotiateInstance instance = { 0 };
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(res->requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        SoftBusFree(res);
        return;
    }
    if (res->isGenUkSuccess) {
        AUTH_LOGI(AUTH_CONN, "recv genuk success, requestId=%{public}u", res->requestId);
        if (instance.genCb.onGenSuccess != NULL) {
            AUTH_LOGI(AUTH_CONN, "onGenSuccess callback");
            instance.genCb.onGenSuccess(instance.requestId, instance.ukId);
            TransCloseSessionInner(instance.channelId);
            DeleteUkNegotiateInstance(instance.requestId);
        }
    } else {
        AUTH_LOGI(AUTH_CONN, "recv genuk fail, requestId=%{public}u, reason=%{public}d", res->requestId, res->reason);
        if (instance.genCb.onGenFailed != NULL) {
            AUTH_LOGI(AUTH_CONN, "onGenFailed callback");
            instance.genCb.onGenFailed(instance.requestId, res->reason);
        }
        TransCloseSessionInner(instance.channelId);
        DeleteUkNegotiateInstance(instance.requestId);
    }
    SoftBusFree(res);
}

static void UpdateAllGenCbCallback(const AuthACLInfo *info, bool isSuccess, int32_t reason)
{
    if (g_ukNegotiateList == NULL) {
        AUTH_LOGE(AUTH_INIT, "uknego instance is null");
        return;
    }

    UkNegotiateInstance *item = NULL;
    UkNegotiateInstance *nextItem = NULL;
    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_ukNegotiateList->list, UkNegotiateInstance, node) {
        if (!CompareByAllAcl(info, &item->info, info->isServer == item->info.isServer)) {
            continue;
        }
        if (isSuccess) {
            item->negoInfo.isRecvSessionKeyEvent = true;
            item->negoInfo.isRecvFinishEvent = true;
            item->negoInfo.isRecvCloseAckEvent = true;
        }
        SyncGenUkResult *result = (SyncGenUkResult *)SoftBusCalloc(sizeof(SyncGenUkResult));
        if (result == NULL) {
            AUTH_LOGE(AUTH_CONN, "calloc result fail");
            return;
        }
        result->requestId = item->requestId;
        result->isGenUkSuccess = isSuccess;
        result->reason = reason;
        if (LnnAsyncCallbackDelayHelper(
            GetLooper(LOOP_TYPE_DEFAULT), AsyncCallGenUkResultReceived, (void *)result, 0) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "async uknego success event fail");
            SoftBusFree(result);
        }
    }
    ReleaseUkNegotiateListLock();
}

static void OnGenSuccess(uint32_t requestId)
{
    AUTH_LOGI(AUTH_CONN, "OnGenSuccess, requestId=%{public}u", requestId);
    UkNegotiateInstance instance = { 0 };
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    if (!instance.negoInfo.isRecvSessionKeyEvent || !instance.negoInfo.isRecvFinishEvent ||
        !instance.negoInfo.isRecvCloseAckEvent) {
        AUTH_LOGI(AUTH_CONN,
            "uknego is not complete, recvsessionkey=%{public}d, recvfinish=%{public}d, recvack=%{public}d",
            instance.negoInfo.isRecvSessionKeyEvent, instance.negoInfo.isRecvFinishEvent,
            instance.negoInfo.isRecvCloseAckEvent);
        return;
    }
    UpdateAllGenCbCallback(&instance.info, true, SOFTBUS_OK);
}

static void OnGenFailed(uint32_t requestId, int32_t reason)
{
    AUTH_LOGE(AUTH_CONN, "OnGenFailed, requestId=%{public}u, reason=%{public}d", requestId, reason);
    UkNegotiateInstance instance = { 0 };
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    UpdateAllGenCbCallback(&instance.info, false, reason);
}

static char *PackUkAclParam(const AuthACLInfo *info, bool isClient)
{
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "create json fail");
        return NULL;
    }
    bool isSupportUkNego = false;
    if (LnnGetLocalBoolInfo(BOOL_KEY_SUPPORT_UK_NEGO, &isSupportUkNego, NODE_SCREEN_STATUS_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get uknego info fail");
        cJSON_Delete(msg);
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_PEER_UDID, info->sourceUdid) ||
        !AddStringToJsonObject(msg, FIELD_UDID, info->sinkUdid) ||
        !AddNumberToJsonObject(msg, FIELD_PEER_USER_ID, info->sourceUserId) ||
        !AddNumberToJsonObject(msg, FIELD_USER_ID, info->sinkUserId) ||
        !AddNumber64ToJsonObject(msg, FIELD_PEER_CONN_DEVICE_ID, info->sourceTokenId) ||
        !AddNumber64ToJsonObject(msg, FIELD_DEVICE_ID, info->sinkTokenId) ||
        !AddStringToJsonObject(msg, PEER_ACCOUNT_ID, info->sourceAccountId) ||
        !AddStringToJsonObject(msg, LOCAL_ACCOUNT_ID, info->sinkAccountId) ||
        !AddBoolToJsonObject(msg, FIELD_IS_CLIENT, isClient) ||
        !AddBoolToJsonObject(msg, IS_SUPPORT_UK_NEGO, isSupportUkNego)) {
        AUTH_LOGE(AUTH_CONN, "add json object fail");
        cJSON_Delete(msg);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_PrintUnformatted fail");
    }
    cJSON_Delete(msg);
    return data;
}

static int32_t UnpackUkAclParam(const char *data, uint32_t len, AuthACLInfo *info, bool *isSupportUkNego)
{
    cJSON *msg = cJSON_ParseWithLength((char *)data, len);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_ParseWithLength fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    bool isClient = false;
    if (!GetJsonObjectStringItem(msg, FIELD_PEER_UDID, info->sourceUdid, UDID_BUF_LEN) ||
        !GetJsonObjectStringItem(msg, FIELD_UDID, info->sinkUdid, UDID_BUF_LEN) ||
        !GetJsonObjectNumberItem(msg, FIELD_PEER_USER_ID, &info->sourceUserId) ||
        !GetJsonObjectNumberItem(msg, FIELD_USER_ID, &info->sinkUserId) ||
        !GetJsonObjectNumber64Item(msg, FIELD_PEER_CONN_DEVICE_ID, &info->sourceTokenId) ||
        !GetJsonObjectNumber64Item(msg, FIELD_DEVICE_ID, &info->sinkTokenId) ||
        !GetJsonObjectStringItem(msg, PEER_ACCOUNT_ID, info->sourceAccountId, ACCOUNTID_BUF_LEN) ||
        !GetJsonObjectStringItem(msg, LOCAL_ACCOUNT_ID, info->sinkAccountId, ACCOUNTID_BUF_LEN) ||
        !GetJsonObjectBoolItem(msg, FIELD_IS_CLIENT, &isClient) ||
        !GetJsonObjectBoolItem(msg, IS_SUPPORT_UK_NEGO, isSupportUkNego)) {
        AUTH_LOGE(AUTH_CONN, "get json object fail");
        cJSON_Delete(msg);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    cJSON_Delete(msg);
    info->isServer = !isClient;
    return SOFTBUS_OK;
}

static bool JudgeIsSameAccount(const char *accountHash)
{
    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };
    uint8_t peerAccountHash[SHA_256_HASH_LEN] = { 0 };

    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local account hash fail");
        return false;
    }
    if (ConvertHexStringToBytes(peerAccountHash, SHA_256_HASH_LEN, accountHash, strlen(accountHash)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert peer account hash to bytes fail");
        return false;
    }
    AUTH_LOGI(AUTH_CONN, "local account=%{public}02X%{public}02X, peer account=%{public}02X%{public}02X",
        localAccountHash[0], localAccountHash[1], peerAccountHash[0], peerAccountHash[1]);
    return ((memcmp(localAccountHash, peerAccountHash, SHA_256_HASH_LEN) == EOK) && (!LnnIsDefaultOhosAccount()));
}

static int32_t GetShortUdidHash(char *udid, char *udidHash, uint32_t len)
{
    if (udid == NULL || udidHash == NULL || len < UDID_HASH_LEN) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t hash[UDID_HASH_LEN] = { 0 };
    if (SoftBusGenerateStrHash((unsigned char *)udid, strlen(udid), (unsigned char *)hash) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "generate strhash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (ConvertBytesToHexString(udidHash, len, hash, UDID_SHORT_HASH_LEN_TEMP) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert bytes to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    return SOFTBUS_OK;
}

static char *GetCredIdByIdService(char *localUdidHash, char *remoteUdidHash, char *accountHash, int32_t userId)
{
    char *credList = NULL;
    char *credId = NULL;
    char accountHashStr[SHA_256_HEX_HASH_LEN] = { 0 };

    if (ConvertBytesToHexString(accountHashStr, SHA_256_HEX_HASH_LEN, (unsigned char *)accountHash, SHA_256_HASH_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert account to string fail");
        return credId;
    }
    bool isSameAccount = JudgeIsSameAccount(accountHashStr);
    char *udidShortHash = isSameAccount ? localUdidHash : remoteUdidHash;
    if (IdServiceQueryCredential(userId, udidShortHash, accountHashStr, isSameAccount, &credList) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "query credential fail");
        return credId;
    }
    credId = IdServiceGetCredIdFromCredList(userId, credList);
    if (credId == NULL) {
        AUTH_LOGE(AUTH_CONN, "get cred id fail");
        return credId;
    }
    IdServiceDestroyCredentialList(&credList);
    return credId;
}

static int32_t GetUkNegoAuthParamInfo(char *remoteUdid, HiChainAuthParam *authParam, HiChainAuthMode authMode)
{
    if (remoteUdid == NULL || authParam == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = LnnGetLocalNodeInfoSafe(&nodeInfo);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "get node info fail");
        return ret;
    }
    NodeInfo *remoteNodeInfo = LnnGetNodeInfoById(remoteUdid, CATEGORY_UDID);
    if (remoteNodeInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "remote node info is null");
        return SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR;
    }
    char localUdidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    char remoteUdidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    ret = GetShortUdidHash(nodeInfo.deviceInfo.deviceUdid, localUdidHash, SHA_256_HEX_HASH_LEN);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local udid hash fail");
        return ret;
    }
    ret = GetShortUdidHash(remoteNodeInfo->deviceInfo.deviceUdid, remoteUdidHash, SHA_256_HEX_HASH_LEN);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get remote udid hash fail");
        return ret;
    }
    authParam->udid = remoteUdid;
    authParam->uid = remoteNodeInfo->accountHash;
    authParam->userId = remoteNodeInfo->userId;
    if (authMode == HICHAIN_AUTH_IDENTITY_SERVICE) {
        authParam->credId =
            GetCredIdByIdService(localUdidHash, remoteUdidHash, remoteNodeInfo->accountHash, nodeInfo.userId);
        if (authParam->credId == NULL) {
            AUTH_LOGE(AUTH_CONN, "get cred id fail");
            return SOFTBUS_AUTH_GET_CRED_ID_FAIL;
        }
    }
    return SOFTBUS_OK;
}

static bool OnTransmit(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_CONN, "data is null");
        return false;
    }
    AUTH_LOGI(AUTH_CONN, "uknego OnTransmit: authSeq=%{public}" PRId64 ", len=%{public}u", authSeq, len);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return false;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_AUTH,
        .module = MODULE_HICHAIN,
        .seq = authSeq,
        .flag = 0,
        .len = len,
    };
    uint32_t size = AUTH_PKT_HEAD_LEN + len;
    uint8_t *buf = (uint8_t *)SoftBusMalloc(size);
    if (buf == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        return false;
    }
    ret = PackAuthData(&head, data, buf, size);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "pack data fail=%{public}d", ret);
        SoftBusFree(buf);
        return false;
    }
    ret = TransSendDataInner(instance.channelId, (char *)buf, size);
    SoftBusFree(buf);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "uknego OnTransmit fail: authSeq=%{public}" PRId64, authSeq);
        return false;
    }
    return true;
}

static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    AUTH_LOGI(
        AUTH_CONN, "uknego OnSessionKeyReturned: authSeq=%{public}" PRId64 ", len=%{public}u", authSeq, sessionKeyLen);
    if (sessionKey == NULL || sessionKeyLen > SESSION_KEY_LENGTH) {
        AUTH_LOGE(AUTH_CONN, "invalid sessionKey");
        return;
    }
    int32_t sessionKeyId = 0;
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    bool isSameAccount =
        JudgeIsSameAccount(!instance.info.isServer ? instance.info.sourceAccountId : instance.info.sinkAccountId);
    PrintfAuthAclInfo(instance.requestId, instance.channelId, &instance.info);
    UpdateAssetSessionKeyByAcl(&instance.info, sessionKey, sessionKeyLen, &sessionKeyId, isSameAccount);
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    ret = GetGenUkInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    instance.ukId = sessionKeyId;
    instance.negoInfo.isRecvSessionKeyEvent = true; //优化更新
    AUTH_LOGI(AUTH_CONN, "update instance event. sessionkey=%{public}d", instance.negoInfo.isRecvSessionKeyEvent);
    ret = UpdateUkNegotiateInfo((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "update uknego instance failed! ret=%{public}d", ret);
        return;
    }
}

static void OnFinish(int64_t authSeq, int operationCode, const char *returnData)
{
    AUTH_LOGI(AUTH_CONN, "uknego OnFinish: authSeq=%{public}" PRId64, authSeq);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    if (instance.info.isServer) {
        (void)SendUkNegoCloseAckEvent(instance.channelId, instance.requestId);
    }
    UkNegotiateInfo *negoInfo = NULL;

    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return;
    }
    negoInfo = GetUkNegotiateInfo((uint32_t)authSeq);
    if (negoInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "uknego info not found, requestId=%{public}u", instance.requestId);
        ReleaseUkNegotiateListLock();
        return;
    }
    negoInfo->isRecvFinishEvent = true;
    AUTH_LOGI(AUTH_CONN, "update instance event. finish=%{public}d", negoInfo->isRecvFinishEvent);
    ReleaseUkNegotiateListLock();
    OnGenSuccess((uint32_t)authSeq);
}

static void OnError(int64_t authSeq, int operationCode, int errCode, const char *errorReturn)
{
    (void)operationCode;
    uint32_t authErrCode = 0;
    (void)GetSoftbusHichainAuthErrorCode((uint32_t)errCode, &authErrCode);
    AUTH_LOGE(AUTH_CONN, "uknego OnError: authSeq=%{public}" PRId64 ", errCode=%{public}d authErrCode=%{public}d",
        authSeq, errCode, authErrCode);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    OnGenFailed((uint32_t)authSeq, authErrCode);
}

static int32_t JsonObjectPackAuthBaseInfo(const UkNegotiateInstance *instance, cJSON *json)
{
    int32_t peerUserId = instance->info.isServer ? instance->info.sinkUserId : instance->info.sourceUserId;
    if (!AddNumberToJsonObject(json, FIELD_CONFIRMATION, REQUEST_ACCEPTED) ||
        !AddStringToJsonObject(json, FIELD_SERVICE_PKG_NAME, AUTH_APPID) ||
        !AddStringToJsonObject(json, FIELD_PEER_CONN_DEVICE_ID,
            instance->info.isServer ? instance->info.sinkUdid : instance->info.sourceUdid) ||
        !AddStringToJsonObject(
            json, FIELD_DEVICE_ID, instance->info.isServer ? instance->info.sourceUdid : instance->info.sinkUdid) ||
        !AddBoolToJsonObject(json, FIELD_IS_UDID_HASH, false) ||
        (peerUserId != 0 && !AddNumberToJsonObject(json, "peerOsAccountId", peerUserId))) {
        AUTH_LOGE(AUTH_CONN, "pack request json fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

static char *OnRequest(int64_t authSeq, int operationCode, const char *reqParams)
{
    (void)reqParams;
    AUTH_LOGI(AUTH_CONN, "uknego OnRequest: authSeq=%{public}" PRId64 ", ret=%{public}d", authSeq, operationCode);
    HiChainAuthParam authParam = { 0 };
    UkNegotiateInstance instance;

    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        return NULL;
    }
    if (JsonObjectPackAuthBaseInfo(&instance, msg) != SOFTBUS_OK) {
        cJSON_Delete(msg);
        return NULL;
    }
    if (instance.authMode == HICHAIN_AUTH_IDENTITY_SERVICE) {
        ret = GetUkNegoAuthParamInfo(
            instance.info.isServer ? instance.info.sinkUdid : instance.info.sourceUdid, &authParam, instance.authMode);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "get authparam failed! ret=%{public}d", ret);
            cJSON_Delete(msg);
            return NULL;
        }
        if (!AddStringToJsonObject(msg, FIELD_CRED_ID, authParam.credId)) {
            AUTH_LOGE(AUTH_CONN, "add credid fail");
            SoftBusFree(authParam.credId);
            cJSON_Delete(msg);
            return NULL;
        }
    }
    SoftBusFree(authParam.credId);
    char *msgStr = cJSON_PrintUnformatted(msg);
    if (msgStr == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_PrintUnformatted fail");
        cJSON_Delete(msg);
        return NULL;
    }
    cJSON_Delete(msg);
    return msgStr;
}

static DeviceAuthCallback g_GenUkCallback = {
    .onTransmit = OnTransmit,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinish,
    .onError = OnError,
    .onRequest = OnRequest
};

static HiChainAuthMode GetHichainAuthMode(bool isPeerSupportUkNego, const AuthACLInfo *info)
{
    bool isSupportUkNego = false;
    HiChainAuthMode authMode = HICHAIN_AUTH_IDENTITY_SERVICE;
    int32_t ret = LnnGetLocalBoolInfo(BOOL_KEY_SUPPORT_UK_NEGO, &isSupportUkNego, NODE_SCREEN_STATUS_LEN);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "cannot get local uknego");
        return authMode;
    }
    authMode = (isSupportUkNego & isPeerSupportUkNego) ? HICHAIN_AUTH_IDENTITY_SERVICE : HICHAIN_AUTH_DEVICE;
    AUTH_LOGI(AUTH_CONN, "get authMode=%{public}d", authMode);
    if (!JudgeIsSameAccount(!info->isServer ? info->sourceAccountId : info->sinkAccountId)) {
        AUTH_LOGW(AUTH_CONN, "no same account not support auth identity");
        authMode = HICHAIN_AUTH_DEVICE;
    }
    return authMode;
}

static int32_t ProcessAuthHichainParam(uint32_t requestId, AuthACLInfo *info, HiChainAuthMode authMode)
{
    HiChainAuthParam authParam = { 0 };
    int32_t ret = GetUkNegoAuthParamInfo(!info->isServer ? info->sourceUdid : info->sinkUdid, &authParam, authMode);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "hichain auth parameter invalid");
        SoftBusFree(authParam.credId);
        return ret;
    }
    authParam.cb = &g_GenUkCallback;
    AUTH_LOGI(AUTH_CONN, "start uknego auth");
    return HichainStartAuth(requestId, &authParam, authMode);
}

static int32_t SendUkNegoDeviceId(UkNegotiateInstance *instance)
{
    char *ukParams = PackUkAclParam(&instance->info, instance->info.isServer);
    if (ukParams == NULL) {
        AUTH_LOGE(AUTH_CONN, "generate auth param fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_ID,
        .module = MODULE_HICHAIN,
        .seq = instance->requestId,
        .flag = instance->info.isServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = strlen(ukParams),
    };
    uint32_t size = AUTH_PKT_HEAD_LEN + head.len;
    uint8_t *buf = (uint8_t *)SoftBusMalloc(size);
    if (buf == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        cJSON_free(ukParams);
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = PackAuthData(&head, (uint8_t *)ukParams, buf, size);
    cJSON_free(ukParams);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "pack data fail=%{public}d", ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = TransSendDataInner(instance->channelId, (char *)buf, size);
    SoftBusFree(buf);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "send uknego sync info data fail");
    }
    return SOFTBUS_OK;
}

static int32_t ProcessUkNegoState(AuthACLInfo *info, bool *isGreater)
{
    if (info == NULL) {
        AUTH_LOGE(AUTH_CONN, "find uknego info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char sourceUdidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    char sinkUdidHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (GetShortUdidHash(info->sourceUdid, sourceUdidHash, SHA_256_HEX_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get source udid hash fail");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    if (GetShortUdidHash(info->sinkUdid, sinkUdidHash, SHA_256_HEX_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get sink udid hash fail");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    *isGreater = true;
    if ((info->isServer && memcmp(sourceUdidHash, sinkUdidHash, SHORT_HASH_LEN) < 0) ||
        (!info->isServer && memcmp(sinkUdidHash, sourceUdidHash, SHORT_HASH_LEN) < 0)) {
        *isGreater = false;
        AUTH_LOGW(AUTH_CONN, "peer udid is greater, wait another uknego");
    }
    return SOFTBUS_OK;
}

static int32_t ProcessUkDeviceId(int32_t channelId, uint32_t requestId, const void *data, uint32_t dataLen)
{
    if (data == NULL) {
        AUTH_LOGE(AUTH_CONN, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthACLInfo info = { 0 };
    UkNegotiateInstance instance;
    AuthGenUkCallback cb;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    (void)memset_s(&cb, sizeof(AuthGenUkCallback), 0, sizeof(AuthGenUkCallback));
    bool isPeerSupportUkNego = true;
    bool isLocalUdidGreater = false;
    int32_t ret = UnpackUkAclParam(data, dataLen, &info, &isPeerSupportUkNego);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "UnpackUkAclParam failed! ret=%{public}d", ret);
        return ret;
    }
    ret = GetGenUkInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        ret = CreateUkNegotiateInstance(requestId, channelId, &info, &cb);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "create new uknego instance failed! ret=%{public}d", ret);
            return ret;
        }
    } else {
        instance.channelId = channelId;
        instance.info = info;
        instance.authMode = GetHichainAuthMode(isPeerSupportUkNego, &instance.info);
        ret = UpdateUkNegotiateInfo(requestId, &instance);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "create uknego instance failed! ret=%{public}d", ret);
            return ret;
        }
    }
    ret = ProcessUkNegoState(&info, &isLocalUdidGreater);
    if (ret != SOFTBUS_OK || GetSameUkInstanceNum(&info) > 0) {
        AUTH_LOGW(AUTH_CONN, "wait another uknego");
        return ret;
    }
    if (ret == SOFTBUS_OK && isLocalUdidGreater) {
        ret = GetGenUkInstanceByReq(requestId, &instance);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
            return ret;
        }
        instance.state = GENUK_STATE_START;
        (void)UpdateUkNegotiateInfo(requestId, &instance);
        return ProcessAuthHichainParam(requestId, &info, instance.authMode);
    }
    return ret;
}

static int32_t ProcessUkData(uint32_t requestId, const uint8_t *data, uint32_t dataLen)
{
    AUTH_LOGI(AUTH_CONN, "ProcessUkData enter: requestId=%{public}u, len=%{public}u", requestId, dataLen);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return ret;
    }
    ret = HichainProcessUkNegoData(requestId, data, dataLen, instance.authMode, &g_GenUkCallback);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "uknego processData err=%{public}d", ret);
        return ret;
    }
    return ret;
}

static int32_t SendUkNegoCloseAckEvent(int32_t channelId, uint32_t requestId)
{
    const char *msg = "";
    AuthDataHead head = {
        .dataType = DATA_TYPE_CLOSE_ACK,
        .module = MODULE_HICHAIN,
        .seq = requestId,
        .flag = 0,
        .len = strlen(msg) + 1,
    };
    uint32_t size = AUTH_PKT_HEAD_LEN + head.len;
    uint8_t *buf = (uint8_t *)SoftBusMalloc(size);
    if (buf == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = PackAuthData(&head, (uint8_t *)msg, buf, size);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "pack data fail=%{public}d", ret);
        SoftBusFree(buf);
        return ret;
    }
    ret = TransSendDataInner(channelId, (char *)buf, size);
    SoftBusFree(buf);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "send uknego close ack fail: requestId=%{public}u", requestId);
    }
    return ret;
}

static int32_t ProcessCloseAckData(uint32_t requestId, const uint8_t *data, uint32_t dataLen)
{
    AUTH_LOGI(AUTH_CONN, "close ack, requestId=%{public}u", requestId);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return ret;
    }
    UkNegotiateInfo *negoInfo = NULL;

    if (!RequireUkNegotiateListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireUkNegotiateListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    negoInfo = GetUkNegotiateInfo(requestId);
    if (negoInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "negotiate info not find, requestId=%{public}u", requestId);
        ReleaseUkNegotiateListLock();
        return SOFTBUS_AUTH_UK_NEGOINFO_NOT_FIND;
    }
    negoInfo->isRecvCloseAckEvent = true;
    AUTH_LOGI(AUTH_CONN, "set negotiate info recv closeAck ok, closeAck=%{public}d", negoInfo->isRecvCloseAckEvent);
    ReleaseUkNegotiateListLock();
    OnGenSuccess(requestId);
    if (!instance.info.isServer) {
        (void)SendUkNegoCloseAckEvent(instance.channelId, requestId);
    }
    return SOFTBUS_OK;
}

static int32_t UkMsgHandler(
    int32_t channelId, uint32_t requestId, const AuthDataHead *head, const void *data, uint32_t dataLen)
{
    if (head == NULL || data == NULL) {
        AUTH_LOGE(AUTH_CONN, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    switch (head->dataType) {
        case DATA_TYPE_DEVICE_ID:
            ret = ProcessUkDeviceId(channelId, requestId, data, dataLen);
            break;
        case DATA_TYPE_AUTH:
            ret = ProcessUkData(requestId, data, dataLen);
            break;
        case DATA_TYPE_CLOSE_ACK:
            ret = ProcessCloseAckData(requestId, data, dataLen);
            break;
        default:
            ret = SOFTBUS_CHANNEL_AUTH_HANDLE_DATA_FAIL;
            break;
    }
    if (ret != SOFTBUS_OK) {
        OnGenFailed(requestId, ret);
    }
    AUTH_LOGI(AUTH_CONN, "exit, ret=%{public}d", ret);
    return ret;
}

int32_t AuthFindUkIdByACLInfo(const AuthACLInfo *acl, int32_t *ukId)
{
    if (acl == NULL || ukId == NULL) {
        AUTH_LOGE(AUTH_CONN, "find uknego info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint64_t time = 0;
    *ukId = -1;
    AuthUserKeyInfo userKeyInfo = { 0 };
    AuthACLInfo aclInfo = { 0 };

    aclInfo = *acl;
    aclInfo.isServer = !acl->isServer;
    PrintfAuthAclInfo(0, 0, &aclInfo);
    if (GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo) != SOFTBUS_OK &&
        GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get uk by ukcachelist fail");
        if (GetAccessUkIdSameAccount(&aclInfo, ukId, &time) != SOFTBUS_OK &&
            GetAccessUkIdDiffAccount(&aclInfo, ukId, &time) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "get uk by asset fail");
            return SOFTBUS_AUTH_ACL_NOT_FOUND;
        }
    } else {
        *ukId = userKeyInfo.keyIndex;
        time = userKeyInfo.time;
    }
    AUTH_LOGI(AUTH_CONN, "get user key id=%{public}d, time=%{public}" PRIu64, *ukId, time);
    if (*ukId == -1) {
        return SOFTBUS_AUTH_UK_NOT_FIND;
    }
    return SOFTBUS_OK;
}

uint32_t AuthGetUkEncryptSize(uint32_t inLen)
{
    return inLen + OVERHEAD_LEN;
}

uint32_t AuthGetUkDecryptSize(uint32_t inLen)
{
    if (inLen < OVERHEAD_LEN) {
        return inLen;
    }
    return inLen - OVERHEAD_LEN;
}

int32_t AuthEncryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (inData == NULL || inLen == 0 || outData == NULL || outLen == NULL || *outLen < (inLen + OVERHEAD_LEN)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t *userKey = (uint8_t *)SoftBusMalloc(SESSION_KEY_LENGTH);
    if (userKey == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        return SOFTBUS_MEM_ERR;
    }
    AUTH_LOGI(AUTH_CONN, "get ukid=%{public}d", ukId);
    if (GetUserKeyByUkId(ukId, userKey, SESSION_KEY_LENGTH) != SOFTBUS_OK &&
        GetAccessUkByUkId(ukId, userKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get user key by ukId fail");
        SoftBusFree(userKey);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    AesGcmCipherKey cipherKey = { .keyLen = SESSION_KEY_LENGTH };
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, userKey, SESSION_KEY_LENGTH) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy key fail");
        (void)memset_s(userKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        SoftBusFree(userKey);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(userKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    SoftBusFree(userKey);
    int32_t ret = SoftBusEncryptData(&cipherKey, (unsigned char *)inData, inLen, (unsigned char *)outData, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "AuthEncryptByUkId fail. ret=%{public}d", ret);
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}


int32_t AuthDecryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    if (inData == NULL || inLen < OVERHEAD_LEN || outData == NULL || outLen == NULL ||
        *outLen < (inLen - OVERHEAD_LEN)) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t *userKey = (uint8_t *)SoftBusMalloc(SESSION_KEY_LENGTH);
    if (userKey == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        return SOFTBUS_MEM_ERR;
    }
    AUTH_LOGI(AUTH_CONN, "get ukid=%{public}d", ukId);
    if (GetUserKeyByUkId(ukId, userKey, SESSION_KEY_LENGTH) != SOFTBUS_OK &&
        GetAccessUkByUkId(ukId, userKey, SESSION_KEY_LENGTH) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get user key fail");
        SoftBusFree(userKey);
        return SOFTBUS_AUTH_ACL_NOT_FOUND;
    }
    AesGcmCipherKey cipherKey = { .keyLen = SESSION_KEY_LENGTH };
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, userKey, SESSION_KEY_LENGTH) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy key fail");
        (void)memset_s(userKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        SoftBusFree(userKey);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(userKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
    SoftBusFree(userKey);
    int32_t ret = SoftBusDecryptData(&cipherKey, inData, inLen, outData, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusDecryptData fail. ret=%{public}d", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ProcessDataToEncrypt(
    int32_t ukId, int32_t peerUkId, const AuthTransData *dataInfo, uint8_t *outData, uint32_t outLen)
{
    uint32_t encDataLen = AuthGetUkEncryptSize(dataInfo->len);
    uint8_t *encData = (uint8_t *)SoftBusCalloc(encDataLen);
    if (encData == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc encrypt data fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = AuthEncryptByUkId(ukId, dataInfo->data, dataInfo->len, encData, &encDataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "encrypt trans data fail.");
        SoftBusFree(encData);
        return ret;
    }
    *(int32_t *)outData = (int32_t)SoftBusHtoLl((uint32_t)ukId);
    *(int32_t *)(outData + ENCRYPT_INDEX_LEN) = (int32_t)SoftBusHtoLl((uint32_t)peerUkId);
    if (memcpy_s(outData + UK_ENCRYPT_INDEX_LEN, outLen - UK_ENCRYPT_INDEX_LEN, encData, encDataLen) != EOK) {
        AUTH_LOGE(AUTH_CONN, "copy enc data fail.");
        SoftBusFree(encData);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(encData);
    return SOFTBUS_OK;
}

int32_t AuthPostTransDataByUk(AuthHandle authHandle, int32_t ukId, int32_t peerUkId, const AuthTransData *dataInfo)
{
    if (dataInfo == NULL) {
        AUTH_LOGE(AUTH_CONN, "dataInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthDataHead head;
    head.dataType = DATA_TYPE_UK_CONNECTION;
    head.module = dataInfo->module;
    head.seq = dataInfo->seq;
    head.flag = dataInfo->flag;
    uint32_t outDataLen = AuthGetUkEncryptSize(dataInfo->len) + UK_ENCRYPT_INDEX_LEN;
    uint8_t *outData = (uint8_t *)SoftBusCalloc(outDataLen);

    if (outData == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc out data fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    head.len = outDataLen;
    int32_t ret = ProcessDataToEncrypt(ukId, peerUkId, dataInfo, outData, outDataLen);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post data encrypt fail. ret=%{public}d", ret);
        SoftBusFree(outData);
        return ret;
    }
    AuthManager *auth = GetAuthManagerByAuthId(authHandle.authId);
    if (auth == NULL) {
        SoftBusFree(outData);
        return SOFTBUS_AUTH_NOT_FOUND;
    }
    ret = PostAuthData(auth->connId[authHandle.type], !auth->isServer, &head, outData);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post trans data fail.");
        SoftBusFree(outData);
        DelDupAuthManager(auth);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(outData);
    DelDupAuthManager(auth);
    return SOFTBUS_OK;
}

bool AuthIsUkExpired(uint64_t time)
{
    uint64_t currentTime = SoftBusGetSysTimeMs();
    if (currentTime - time > UK_AGING_TIME) {
        AUTH_LOGE(AUTH_CONN, "UK has expired and cannot be used.");
        return false;
    }
    return true;
}

static int32_t SecurityOnSessionOpened(int32_t channelId, int32_t channelType, char *peerNetworkId, int32_t result)
{
    (void)channelType;
    (void)peerNetworkId;
    AUTH_LOGI(AUTH_CONN, "SecurityOnSessionOpened inner channelId=%{public}d", channelId);
    if (result != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get session open failed! result=%{public}d", result);
        return result;
    }
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByChannel(channelId, &instance);
    if (ret == SOFTBUS_OK) {
        if (instance.info.isServer) {
            AUTH_LOGW(AUTH_CONN, "remove start uknego");
            return ret;
        }
        if (GetSameUkInstanceNum(&instance.info) > 0) {
            AUTH_LOGW(AUTH_CONN, "wait another uknego");
            return ret;
        }
        bool isGreater = false;
        instance.authMode = GetHichainAuthMode(true, &instance.info);
        ret = ProcessUkNegoState(&instance.info, &isGreater);
        if (ret == SOFTBUS_OK && isGreater) {
            AUTH_LOGI(AUTH_CONN, "start uknego auth");
            instance.state = GENUK_STATE_START;
            ret = ProcessAuthHichainParam(instance.requestId, &instance.info, instance.authMode);
        }
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "uknego auth failed! result=%{public}d", ret);
            return ret;
        }
        (void)UpdateUkNegotiateInfo(instance.requestId, &instance);
        return SendUkNegoDeviceId(&instance);
    } else {
        AUTH_LOGW(AUTH_CONN, "uknego not recv acl info");
        return SOFTBUS_OK;
    }
}

static void SecurityOnSessionClosed(int32_t channelId)
{
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t ret = GetGenUkInstanceByChannel(channelId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    DeleteUkNegotiateInstance(instance.requestId);
}

static void SecurityOnBytesReceived(int32_t channelId, const void *data, uint32_t dataLen)
{
    AuthDataHead head = { 0 };
    const uint8_t *body = UnpackAuthData((const uint8_t *)data, (uint32_t)dataLen, &head);
    if (body == NULL) {
        AUTH_LOGE(AUTH_CONN, "empty body");
        return;
    }
    int32_t ret = UkMsgHandler(channelId, head.seq, &head, body, head.len);
    AUTH_LOGI(AUTH_CONN, "recv ret=%{public}d", ret);
}

static int32_t SecuritySetChannelInfoByReqId(uint32_t requestId, int32_t channelId, int32_t channelType)
{
    (void)channelType;
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    AuthACLInfo info = { 0 };
    AuthGenUkCallback cb;
    (void)memset_s(&cb, sizeof(AuthGenUkCallback), 0, sizeof(AuthGenUkCallback));
    int32_t ret = GetGenUkInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        ret = CreateUkNegotiateInstance(requestId, channelId, &info, &cb);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "create uknego instance failed! ret=%{public}d", ret);
            return ret;
        }
    } else {
        AUTH_LOGI(AUTH_CONN, "get instance succ! requestId=%{public}u", requestId);
        instance.channelId = channelId;
        ret = UpdateUkNegotiateInfo(requestId, &instance);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "create uknego instance failed! ret=%{public}d", ret);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static ISessionListenerInner g_sessionListener = {
    .OnSessionOpened = SecurityOnSessionOpened,
    .OnSessionClosed = SecurityOnSessionClosed,
    .OnBytesReceived = SecurityOnBytesReceived,
    .OnLinkDown = NULL,
    .OnSetChannelInfoByReqId = SecuritySetChannelInfoByReqId,
};

static void UpdateUniqueId(void)
{
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_NETWORKID, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local networkId fail");
        return;
    }
    uint8_t hashId[SHA_256_HASH_LEN] = { 0 };
    if (SoftBusGenerateStrHash((uint8_t *)networkId, strlen(networkId), hashId) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "GenerateStrHash fail");
        return;
    }
    for (uint32_t i = 0; i < UK_SEQ_NETWORK_ID_BITS / BYTES_BIT_NUM; i++) {
        g_uniqueId = (g_uniqueId << BYTES_BIT_NUM) | hashId[i];
    }
    uint64_t timeStamp = SoftBusGetSysTimeMs();
    g_uniqueId = (g_uniqueId << SEQ_TIME_STAMP_BITS) | (SEQ_TIME_STAMP_MASK & timeStamp);
}

uint32_t GenUkSeq(void)
{
    static uint32_t integer = 0;
    if (integer >= UK_SEQ_INTEGER_MAX) {
        integer = 0;
    }
    if (integer == 0) {
        UpdateUniqueId();
    }
    integer++;
    /* |----GreaterZero(1)----|----NetworkIdHash(16)----|----TimeStamp(8)----|----AtomicInteger(7)----| */
    uint32_t seq = integer;
    seq = (g_uniqueId << UK_SEQ_INTEGER_BITS) | (seq & UK_SEQ_INTEGER_MAX);
    return seq;
}

int32_t AuthGenUkIdByACLInfo(const AuthACLInfo *acl, uint32_t requestId, const AuthGenUkCallback *genCb)
{
    if (acl == NULL || genCb == NULL) {
        AUTH_LOGE(AUTH_CONN, "generate uknogo info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    AuthACLInfo *info = (AuthACLInfo *)acl;

    info->isServer = !acl->isServer;
    int32_t ret = LnnGetNetworkIdByUdid(acl->sourceUdid, networkId, sizeof(networkId));
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get networkId by udid fail");
        return ret;
    }
    ret = TransOpenSessionInner(UK_NEGO_SESSIONNAME, networkId, requestId);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "uknego open session fail, ret=%{public}d", ret);
        return ret;
    }
    ret = CreateUkNegotiateInstance(requestId, DEFAULT_CHANNEL_ID, info, genCb);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "uk add instance fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t UkNegotiateInit(void)
{
    AUTH_LOGI(AUTH_CONN, "enter.");

    if (SoftBusMutexInit(&g_ukNegotiateListLock, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "UkNegotiate mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (InitUkNegoInstanceList() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "uk nego instance list init err");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    if (AuthUserKeyInit() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "uk list init err");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    AUTH_LOGI(AUTH_CONN, "ok");
    return SOFTBUS_OK;
}

void UkNegotiateDeinit(void)
{
    DeInitUkNegoInstanceList();
    DeinitUserKeyList();
    SoftBusMutexDestroy(&g_ukNegotiateListLock);
}

void UkNegotiateSessionInit(void)
{
    AUTH_LOGI(AUTH_CONN, "enter.");

    int32_t ret = TransCreateSessionServerInner(UK_NEGO_PKGNAME, UK_NEGO_SESSIONNAME, &g_sessionListener);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "create server fail, ret=%{public}d", ret);
        return;
    }
    AUTH_LOGI(AUTH_CONN, "ok");
    return;
}
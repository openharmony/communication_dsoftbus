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
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#include "auth_apply_key_process.h"

#include <securec.h>
#include <stdatomic.h>

#include "anonymizer.h"
#include "auth_apply_key_manager.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_hichain.h"
#include "auth_hichain_adapter.h"
#include "auth_interface.h"
#include "auth_log.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_transmission_interface.h"

#define D2D_ACCOUNT_HASH                "account_auth"
#define D2D_UDID_HASH                   "udid_auth"
#define BUSINESS_TYPE                   "business_type"
#define D2D_APPID                       "d2d_appid"
#define APPLY_KEY_MAX_INSTANCE_CNT      0x2000000
#define APPLY_KEY_NEGO_PROCESS_TIMEOUT  (10 * 1000LL)
#define APPLY_KEY_SEQ_NETWORK_ID_BITS   16
#define SEQ_TIME_STAMP_BITS             8
#define SEQ_TIME_STAMP_MASK             0xFFL
#define APPLY_KEY_SEQ_INTEGER_BITS      7
#define APPLY_KEY_SEQ_INTEGER_MAX       0x0FFFFFFF
#define APPLY_KEY_TRANSMIT_DATA_LEN_MAX 20000

static uint32_t g_uniqueId = 0;
static uint64_t g_applyKeyDecayTime = 15552000000; // 180 * 24 * 60 * 60 * 1000L
static SoftBusList *g_applyKeyNegoList = NULL;
static SoftBusMutex g_applyKeyNegoListLock;

typedef struct {
    uint32_t requestId;
    bool isGenApplyKeySuccess;
    int32_t reason;
} SyncGenApplyKeyResult;

typedef enum {
    GEN_APPLY_KEY_STATE_WAIT = 1,
    GEN_APPLY_KEY_STATE_START,
    GEN_APPLY_KEY_STATE_UNKNOW,
} GenApplyKeyStartState;

typedef struct {
    bool isRecvSessionKeyEvent;
    bool isRecvFinishEvent;
} ApplyKeyNegoInfo;

typedef struct {
    bool isServer;
    int32_t connId;
    uint32_t requestId;
    GenApplyKeyStartState state;
    RequestBusinessInfo info;
    ApplyKeyNegoInfo negoInfo;
    GenApplyKeyCallback genCb;
    ListNode node;
} ApplyKeyNegoInstance;

static bool RequireApplyKeyNegoListLock(void)
{
    if (SoftBusMutexLock(&g_applyKeyNegoListLock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ApplyKeyNegoList lock fail");
        return false;
    }
    return true;
}

static void ReleaseApplyKeyNegoListLock(void)
{
    if (SoftBusMutexUnlock(&g_applyKeyNegoListLock) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ApplyKeyNegoList unlock fail");
    }
}

static int32_t InitApplyKeyNegoInstanceList(void)
{
    if (g_applyKeyNegoList != NULL) {
        return SOFTBUS_OK;
    }
    g_applyKeyNegoList = CreateSoftBusList();
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego create instance list fail");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_applyKeyNegoList->cnt = 0;
    return SOFTBUS_OK;
}

static void DeInitApplyKeyNegoInstanceList(void)
{
    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;

    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_CONN, "g_applyKeyNegoList is null");
        return;
    }
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    AUTH_LOGI(AUTH_CONN, "deinit applyKeynego instance");
    ReleaseApplyKeyNegoListLock();
    DestroySoftBusList(g_applyKeyNegoList);
    g_applyKeyNegoList = NULL;
}

static uint32_t GetSameApplyKeyInstanceNum(const RequestBusinessInfo *info)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return 0;
    }

    uint32_t num = 0;
    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return num;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if ((strcmp(info->accountHash, item->info.accountHash) != 0) ||
            (strcmp(info->udidHash, item->info.udidHash) != 0) || info->type != item->info.type) {
            continue;
        }
        if (item->state == GEN_APPLY_KEY_STATE_START) {
            num++;
        }
    }
    AUTH_LOGI(AUTH_CONN, "list has same aclinfo instance num=%{public}u", num);
    ReleaseApplyKeyNegoListLock();
    return num;
}

static int32_t GetGenApplyKeyInstanceByReq(uint32_t requestId, ApplyKeyNegoInstance *instance)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance list is null");
        return SOFTBUS_NO_INIT;
    }
    if (instance == NULL) {
        AUTH_LOGE(AUTH_INIT, "instance is null");
        return SOFTBUS_INVALID_PARAM;
    }

    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        if (memcpy_s(instance, sizeof(ApplyKeyNegoInstance), item, sizeof(ApplyKeyNegoInstance)) != EOK) {
            ReleaseApplyKeyNegoListLock();
            AUTH_LOGE(AUTH_CONN, "applyKeynego memcpy_s instance fail, requestId=%{public}u", requestId);
            return SOFTBUS_MEM_ERR;
        }
        ReleaseApplyKeyNegoListLock();
        return SOFTBUS_OK;
    }
    AUTH_LOGE(AUTH_CONN, "applyKeynego req not found, requestId=%{public}u", requestId);
    ReleaseApplyKeyNegoListLock();
    return SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND;
}

static int32_t GetGenApplyKeyInstanceByChannel(int32_t channelId, ApplyKeyNegoInstance *instance)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_CONN, "g_applyKeyNegoList is null");
        return SOFTBUS_NO_INIT;
    }
    if (instance == NULL) {
        AUTH_LOGE(AUTH_CONN, "instance is null");
        return SOFTBUS_INVALID_PARAM;
    }

    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if (item->connId != channelId) {
            continue;
        }
        if (memcpy_s(instance, sizeof(ApplyKeyNegoInstance), item, sizeof(ApplyKeyNegoInstance)) != EOK) {
            ReleaseApplyKeyNegoListLock();
            AUTH_LOGE(AUTH_CONN, "applyKeynego memcpy_s instance fail, channelId=%{public}d", channelId);
            return SOFTBUS_MEM_ERR;
        }
        ReleaseApplyKeyNegoListLock();
        return SOFTBUS_OK;
    }
    ReleaseApplyKeyNegoListLock();
    AUTH_LOGE(AUTH_CONN, "applyKeynego instance not found, channelId=%{public}d", channelId);
    return SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND;
}

static int32_t SetApplyKeyNegoInfoRecvSessionKey(uint32_t requestId, bool isRecv)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return SOFTBUS_NO_INIT;
    }

    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if (item->requestId == requestId) {
            item->negoInfo.isRecvSessionKeyEvent = isRecv;
            ReleaseApplyKeyNegoListLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseApplyKeyNegoListLock();
    return SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND;
}

static int32_t SetApplyKeyNegoInfoRecvFinish(uint32_t requestId, bool isRecv)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return SOFTBUS_NO_INIT;
    }

    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if (item->requestId == requestId) {
            item->negoInfo.isRecvFinishEvent = isRecv;
            ReleaseApplyKeyNegoListLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseApplyKeyNegoListLock();
    return SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND;
}

static int32_t SetApplyKeyStartState(uint32_t requestId, const GenApplyKeyStartState state)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return SOFTBUS_NO_INIT;
    }

    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if (item->requestId == requestId) {
            item->state = state;
            ReleaseApplyKeyNegoListLock();
            return SOFTBUS_OK;
        }
    }
    ReleaseApplyKeyNegoListLock();
    return SOFTBUS_AUTH_APPLY_KEY_INSTANCE_NOT_FOUND;
}

static void DeleteApplyKeyNegoInstance(uint32_t requestId)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return;
    }

    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        AUTH_LOGE(AUTH_CONN, "delete applyKeynego instance, requestId=%{public}u", requestId);
        ListDelete(&(item->node));
        SoftBusFree(item);
        ReleaseApplyKeyNegoListLock();
        return;
    }
    AUTH_LOGE(AUTH_CONN, "applyKeynego instance not found, requestId=%{public}u", requestId);
    ReleaseApplyKeyNegoListLock();
}

static void AsyncCallGenApplyKeyResultReceived(void *para)
{
    if (para == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }

    SyncGenApplyKeyResult *res = (SyncGenApplyKeyResult *)para;
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq(res->requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        SoftBusFree(res);
        return;
    }
    if (res->isGenApplyKeySuccess) {
        AUTH_LOGI(AUTH_CONN, "recv genapplyKey success, requestId=%{public}u", res->requestId);
        if (instance.genCb.onGenSuccess != NULL) {
            AUTH_LOGI(AUTH_CONN, "onGenSuccess callback");
            uint8_t applyKey[D2D_APPLY_KEY_LEN] = { 0 };
            if (GetApplyKeyByBusinessInfo(&instance.info, applyKey, D2D_APPLY_KEY_LEN) != SOFTBUS_OK) {
                SoftBusFree(res);
                AUTH_LOGE(AUTH_CONN, "get apply key by instance fail");
                return;
            }
            instance.genCb.onGenSuccess(instance.requestId, applyKey, D2D_APPLY_KEY_LEN);
            DeleteApplyKeyNegoInstance(instance.requestId);
        }
    } else {
        AUTH_LOGI(
            AUTH_CONN, "recv genapplyKey fail, requestId=%{public}u, reason=%{public}d", res->requestId, res->reason);
        if (instance.genCb.onGenFailed != NULL) {
            AUTH_LOGI(AUTH_CONN, "onGenFailed callback");
            instance.genCb.onGenFailed(instance.requestId, res->reason);
        }
        DeleteApplyKeyNegoInstance(instance.requestId);
    }
    SoftBusFree(res);
}

static void UpdateAllGenCbCallback(const RequestBusinessInfo *info, bool isSuccess, int32_t reason)
{
    if (g_applyKeyNegoList == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return;
    }

    if (info == NULL) {
        AUTH_LOGE(AUTH_INIT, "input is valid param");
        return;
    }
    ApplyKeyNegoInstance *item = NULL;
    ApplyKeyNegoInstance *nextItem = NULL;
    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_applyKeyNegoList->list, ApplyKeyNegoInstance, node) {
        if ((strcmp(info->accountHash, item->info.accountHash) != 0) ||
            (strcmp(info->udidHash, item->info.udidHash) != 0) || info->type != item->info.type) {
            continue;
        }
        if (isSuccess) {
            item->negoInfo.isRecvSessionKeyEvent = true;
            item->negoInfo.isRecvFinishEvent = true;
        }
        SyncGenApplyKeyResult *result = (SyncGenApplyKeyResult *)SoftBusCalloc(sizeof(SyncGenApplyKeyResult));
        if (result == NULL) {
            ReleaseApplyKeyNegoListLock();
            AUTH_LOGE(AUTH_CONN, "calloc result fail");
            return;
        }
        result->requestId = item->requestId;
        result->isGenApplyKeySuccess = isSuccess;
        result->reason = reason;
        if (LnnAsyncCallbackDelayHelper(
            GetLooper(LOOP_TYPE_DEFAULT), AsyncCallGenApplyKeyResultReceived, (void *)result, 0) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "async applyKeynego success event fail");
            SoftBusFree(result);
        }
    }
    ReleaseApplyKeyNegoListLock();
}

static void OnGenSuccess(uint32_t requestId)
{
    AUTH_LOGI(AUTH_CONN, "OnGenSuccess, requestId=%{public}u", requestId);
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    if (!instance.negoInfo.isRecvSessionKeyEvent || !instance.negoInfo.isRecvFinishEvent) {
        AUTH_LOGI(AUTH_CONN, "applyKeynego is not complete, recvsession=%{public}d, recvfinish=%{public}d",
            instance.negoInfo.isRecvSessionKeyEvent, instance.negoInfo.isRecvFinishEvent);
        return;
    }
    UpdateAllGenCbCallback(&instance.info, true, SOFTBUS_OK);
}

static void OnGenFailed(uint32_t requestId, int32_t reason)
{
    AUTH_LOGE(AUTH_CONN, "OnGenFailed, requestId=%{public}u, reason=%{public}d", requestId, reason);
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    UpdateAllGenCbCallback(&instance.info, false, reason);
}

static void GenApplyKeyTimeoutProcess(void *para)
{
    OnGenFailed((uint32_t)(uintptr_t)para, SOFTBUS_CHANNEL_AUTH_START_TIMEOUT);
}

static void AuthGenApplyKeyStartTimeout(uint32_t requestId)
{
    LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), GenApplyKeyTimeoutProcess, (void *)(uintptr_t)requestId,
        APPLY_KEY_NEGO_PROCESS_TIMEOUT);
}

static int32_t CreateApplyKeyNegoInstance(const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId,
    bool isServer, const GenApplyKeyCallback *genCb)
{
    if (g_applyKeyNegoList == NULL || info == NULL || genCb == NULL) {
        AUTH_LOGE(AUTH_INIT, "applyKeynego instance is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (!RequireApplyKeyNegoListLock()) {
        AUTH_LOGE(AUTH_CONN, "RequireApplyKeyNegoListLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    ApplyKeyNegoInstance *instance = NULL;
    instance = (ApplyKeyNegoInstance *)SoftBusCalloc(sizeof(ApplyKeyNegoInstance));
    if (instance == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc instance fail");
        ReleaseApplyKeyNegoListLock();
        return SOFTBUS_MEM_ERR;
    }
    instance->isServer = isServer;
    instance->connId = connId;
    instance->requestId = requestId;
    instance->info = *info;
    instance->state = GEN_APPLY_KEY_STATE_UNKNOW;
    instance->genCb = *genCb;
    instance->negoInfo.isRecvSessionKeyEvent = false;
    instance->negoInfo.isRecvFinishEvent = false;
    ListInit(&instance->node);
    ListAdd(&g_applyKeyNegoList->list, &instance->node);
    char *anonyAccountHash = NULL;
    Anonymize(info->accountHash, &anonyAccountHash);
    char *anonyUdidHash = NULL;
    Anonymize(info->udidHash, &anonyUdidHash);
    AUTH_LOGI(AUTH_CONN,
        "applyKeynego requestId=%{public}u, channelId=%{public}d, isServer=%{public}d, accountShortHash=%{public}s, "
        "udidShortHash=%{public}s, type=%{public}d",
        requestId, connId, isServer, AnonymizeWrapper(anonyAccountHash), AnonymizeWrapper(anonyUdidHash), info->type);
    AnonymizeFree(anonyAccountHash);
    AnonymizeFree(anonyUdidHash);
    ReleaseApplyKeyNegoListLock();
    AuthGenApplyKeyStartTimeout(requestId);
    return SOFTBUS_OK;
}

static int32_t PostApplyKeyData(uint32_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    if (head == NULL || data == NULL || GetAuthDataSize(head->len) > APPLY_KEY_TRANSMIT_DATA_LEN_MAX ||
        ConnGetHeadSize() >= APPLY_KEY_TRANSMIT_DATA_LEN_MAX - GetAuthDataSize(head->len)) {
        AUTH_LOGE(AUTH_CONN, "data is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t size = ConnGetHeadSize() + GetAuthDataSize(head->len);
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size);
    if (buf == NULL) {
        AUTH_LOGE(AUTH_CONN, "malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = PackAuthData(head, data, buf + ConnGetHeadSize(), size - ConnGetHeadSize());
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "pack data fail=%{public}d", ret);
        SoftBusFree(buf);
        return ret;
    }
    ConnPostData connData = {
        .module = MODULE_APPLY_KEY_CONNECTION,
        .seq = GenSeq(!toServer),
        .flag = CONN_HIGH,
        .pid = 0,
        .len = size,
        .buf = (char *)buf,
    };
    AUTH_LOGI(AUTH_CONN,
        "dataSeq=%{public}" PRId64 ", dataLen=%{public}u, "
        "connId=%{public}u, connSeq=%{public}" PRId64 ", connLen=%{public}u}",
        head->seq, head->len, connId, connData.seq, connData.len);
    return ConnPostBytes(connId, &connData);
}

static bool OnTransmitted(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        AUTH_LOGE(AUTH_CONN, "input is invalid param");
        return false;
    }
    AUTH_LOGI(AUTH_CONN, "applyKeynego OnTransmit: authSeq=%{public}" PRId64 ", len=%{public}u", authSeq, len);
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return false;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_AUTH,
        .module = MODULE_APPLY_KEY_CONNECTION,
        .seq = authSeq,
        .flag = instance.isServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = len,
    };
    if (PostApplyKeyData(instance.connId, !instance.isServer, &head, data) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post apply key data fail");
        return false;
    }
    return true;
}

static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    AUTH_LOGI(AUTH_CONN, "applyKeynego OnSessionKeyReturned: authSeq=%{public}" PRId64 ", len=%{public}u", authSeq,
        sessionKeyLen);
    if (sessionKey == NULL || sessionKeyLen > D2D_APPLY_KEY_LEN) {
        AUTH_LOGE(AUTH_CONN, "invalid sessionKey");
        return;
    }

    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    uint64_t currentTime = SoftBusGetSysTimeMs();
    ret = AuthInsertApplyKey(&instance.info, sessionKey, sessionKeyLen, currentTime);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "insert apply key failed! ret=%{public}d", ret);
        return;
    }
    if (SetApplyKeyNegoInfoRecvSessionKey(instance.requestId, true) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "applyKeynego info not found, requestId=%{public}u", instance.requestId);
        return;
    }
}

static int32_t GenerateAccountHash(char *accountString, char *accountHashBuf, uint32_t bufLen)
{
    if (accountString == NULL || accountHashBuf == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint8_t accountHash[SHA_256_HASH_LEN] = { 0 };
    int32_t ret = SoftBusGenerateStrHash((uint8_t *)accountString, strlen(accountString), accountHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "accountId hash fail, ret=%{public}d", ret);
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (ConvertBytesToHexString(accountHashBuf, bufLen, accountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_FSM, "convert bytes to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    return SOFTBUS_OK;
}

static void OnFinished(int64_t authSeq, int32_t operationCode, const char *returnData)
{
    AUTH_LOGI(AUTH_CONN, "applyKeynego OnFinish: authSeq=%{public}" PRId64, authSeq);
    if (returnData == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid returnData");
        return;
    }

    ApplyKeyNegoInstance instance;
    char hichainReturnAccountId[SHA_256_HEX_HASH_LEN];
    char hichainReturnAccountHash[SHA_256_HEX_HASH_LEN];
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    (void)memset_s(&hichainReturnAccountId, sizeof(hichainReturnAccountId), 0, sizeof(hichainReturnAccountId));
    (void)memset_s(&hichainReturnAccountHash, sizeof(hichainReturnAccountHash), 0, sizeof(hichainReturnAccountHash));
    cJSON *msg = cJSON_ParseWithLength(returnData, strlen(returnData));
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_ParseWithLength fail");
        return;
    }
    if (!GetJsonObjectStringItem(msg, FIELD_PEER_USER_ID, hichainReturnAccountId, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGE(AUTH_CONN, "get json object fail");
        cJSON_Delete(msg);
        return;
    }
    cJSON_Delete(msg);
    if (GenerateAccountHash(hichainReturnAccountId, hichainReturnAccountHash, SHA_256_HEX_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert local account hash to string fail");
        return;
    }
    int32_t ret = GetGenApplyKeyInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    if (!instance.isServer &&
        strncmp(hichainReturnAccountHash, instance.info.peerAccountHash, SHA_256_HEX_HASH_LEN) != 0) {
        AUTH_LOGE(AUTH_CONN, "peer account hash is not target");
        OnGenFailed((uint32_t)authSeq, SOFTBUS_STRCMP_ERR);
        return;
    }
    if (SetApplyKeyNegoInfoRecvFinish(instance.requestId, true) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "applyKeynego info not found, requestId=%{public}u", instance.requestId);
        return;
    }
    OnGenSuccess((uint32_t)authSeq);
}

static void OnError(int64_t authSeq, int32_t operationCode, int32_t errCode, const char *errorReturn)
{
    (void)operationCode;
    uint32_t authErrCode = 0;
    (void)GetSoftbusHichainAuthErrorCode((uint32_t)errCode, &authErrCode);
    AUTH_LOGE(AUTH_CONN, "applyKeynego OnError: authSeq=%{public}" PRId64 ", errCode=%{public}d authErrCode=%{public}d",
        authSeq, errCode, authErrCode);
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq((uint32_t)authSeq, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return;
    }
    OnGenFailed((uint32_t)authSeq, authErrCode);
}

static char *OnRequest(int64_t authSeq, int operationCode, const char *reqParams)
{
    (void)reqParams;
    AUTH_LOGI(AUTH_CONN, "applyKeynego OnRequest: authSeq=%{public}" PRId64 ", ret=%{public}d", authSeq, operationCode);

    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "create json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_APP_ID, D2D_APPID)) {
        AUTH_LOGE(AUTH_CONN, "add appid fail");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    if (msgStr == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_PrintUnformatted fail");
        return NULL;
    }
    return msgStr;
}

static DeviceAuthCallback g_hichainCallback = { .onTransmit = OnTransmitted,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinished,
    .onError = OnError,
    .onRequest = OnRequest };

static const LightAccountVerifier *ApplyKeyGetLightAccountInstance()
{
    int32_t ret = InitDeviceAuthService();
    if (ret != 0) {
        AUTH_LOGE(AUTH_CONN, "init device auth service fail err=%{public}d", ret);
        return NULL;
    }

    return GetLightAccountVerifierInstance();
}

static int32_t ProcessAuthHichainParam(uint32_t requestId, const DeviceAuthCallback *genCb)
{
    const LightAccountVerifier *lightAccountVerifier = ApplyKeyGetLightAccountInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier != NULL, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FALI, AUTH_CONN,
        "light account verify not initialized");

    int32_t activeUserId = GetActiveOsAccountIds();
    int32_t ret =
        lightAccountVerifier->startLightAccountAuth(activeUserId, (int64_t)requestId, (const char *)D2D_APPID, genCb);
    if (ret != HC_SUCCESS) {
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        AUTH_LOGE(AUTH_CONN,
            "hichain identity service authenticate credential failed, err=%{public}d, authErrCode=%{public}d", ret,
            authErrCode);
        return authErrCode;
    }
    AUTH_LOGI(AUTH_CONN, "start applyKeynego auth");
    return SOFTBUS_OK;
}

static int32_t GetUdidAndAccountShortHash(
    char *localUdidShortHash, uint32_t udidHashLen, char *localAccountShortHash, uint32_t accountHashLen)
{
    if (localUdidShortHash == NULL || localAccountShortHash == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    char localUdid[UDID_BUF_LEN] = { 0 };
    uint8_t hash[UDID_HASH_LEN] = { 0 };
    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };

    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local udid fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (SoftBusGenerateStrHash((unsigned char *)localUdid, strlen(localUdid), (unsigned char *)hash) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "generate strhash fail");
        return SOFTBUS_NETWORK_GENERATE_STR_HASH_ERR;
    }
    if (ConvertBytesToHexString(localUdidShortHash, udidHashLen, hash, D2D_UDID_SHORT_HASH_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert bytes to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local account hash fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (ConvertBytesToHexString(localAccountShortHash, accountHashLen, localAccountHash,
        D2D_ACCOUNT_SHORT_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "convert local account hash to string fail");
        return SOFTBUS_NETWORK_BYTES_TO_HEX_STR_ERR;
    }
    char *anonyAccountHash = NULL;
    Anonymize(localUdidShortHash, &anonyAccountHash);
    char *anonyUdidHash = NULL;
    Anonymize(localAccountShortHash, &anonyUdidHash);
    AUTH_LOGI(AUTH_CONN, "generate accountShortHash=%{public}s, udidShortHash=%{public}s",
        AnonymizeWrapper(anonyAccountHash), AnonymizeWrapper(anonyUdidHash));
    AnonymizeFree(anonyAccountHash);
    AnonymizeFree(anonyUdidHash);
    return SOFTBUS_OK;
}

static char *PackApplyKeyAclParam(RequestBusinessType type)
{
    char localUdidShortHash[D2D_UDID_HASH_STR_LEN] = { 0 };
    char localAccountShortHash[D2D_ACCOUNT_HASH_STR_LEN] = { 0 };
    if (GetUdidAndAccountShortHash(
        localUdidShortHash, D2D_UDID_HASH_STR_LEN, localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN)) {
        AUTH_LOGE(AUTH_CONN, "generate short hash fail");
        return NULL;
    }
    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "create json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, D2D_ACCOUNT_HASH, localAccountShortHash) ||
        !AddStringToJsonObject(msg, D2D_UDID_HASH, localUdidShortHash) ||
        !AddNumberToJsonObject(msg, BUSINESS_TYPE, type)) {
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

static int32_t UnpackApplyKeyAclParam(const char *data, uint32_t len, RequestBusinessInfo *info)
{
    if (data == NULL || info == NULL) {
        AUTH_LOGE(AUTH_CONN, "unpack applyKey info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    cJSON *msg = cJSON_ParseWithLength((char *)data, len);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_ParseWithLength fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    int32_t businessType = 0;
    if (!GetJsonObjectStringItem(msg, D2D_ACCOUNT_HASH, info->accountHash, D2D_ACCOUNT_HASH_STR_LEN) ||
        !GetJsonObjectStringItem(msg, D2D_UDID_HASH, info->udidHash, D2D_UDID_HASH_STR_LEN) ||
        !GetJsonObjectNumberItem(msg, BUSINESS_TYPE, &businessType)) {
        AUTH_LOGE(AUTH_CONN, "get json object fail");
        cJSON_Delete(msg);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    cJSON_Delete(msg);
    info->type = (RequestBusinessType)businessType;
    return SOFTBUS_OK;
}

static int32_t SendApplyKeyNegoDeviceId(uint32_t connId, const RequestBusinessInfo *info, uint32_t requestId)
{
    if (info == NULL) {
        AUTH_LOGE(AUTH_CONN, "unpack applyKey info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    char *applyKeyParams = PackApplyKeyAclParam(info->type);
    if (applyKeyParams == NULL) {
        AUTH_LOGE(AUTH_CONN, "generate auth param fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    AuthDataHead head = {
        .dataType = DATA_TYPE_DEVICE_ID,
        .module = MODULE_APPLY_KEY_CONNECTION,
        .seq = requestId,
        .flag = CLIENT_SIDE_FLAG,
        .len = strlen(applyKeyParams) + 1,
    };
    if (PostApplyKeyData(connId, false, &head, (uint8_t *)applyKeyParams) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "post apply key data fail");
        SoftBusFree(applyKeyParams);
        return SOFTBUS_AUTH_SEND_FAIL;
    }
    SoftBusFree(applyKeyParams);
    return SOFTBUS_OK;
}

static int32_t ProcessApplyKeyNegoState(const RequestBusinessInfo *info, bool *isGreater)
{
    if (info == NULL) {
        AUTH_LOGE(AUTH_CONN, "applyKeynego info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char localUdidShortHash[D2D_UDID_HASH_STR_LEN] = { 0 };
    char localAccountShortHash[D2D_ACCOUNT_HASH_STR_LEN] = { 0 };
    if (GetUdidAndAccountShortHash(
        localUdidShortHash, D2D_UDID_HASH_STR_LEN, localAccountShortHash, D2D_ACCOUNT_HASH_STR_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get local udid and account hash fail");
        return SOFTBUS_NETWORK_GET_NODE_INFO_ERR;
    }
    *isGreater = true;
    if (strcmp(localUdidShortHash, info->udidHash) < 0) {
        *isGreater = false;
        AUTH_LOGW(AUTH_CONN, "peer udid is greater, wait another applyKeynego");
    }
    return SOFTBUS_OK;
}

static int32_t StartApplyKeyHichain(uint32_t connId, const RequestBusinessInfo *info, uint32_t requestId)
{
    if (info == NULL) {
        AUTH_LOGE(AUTH_CONN, "applyKeynego info is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    bool isLocalUdidGreater = false;
    int32_t ret = ProcessApplyKeyNegoState(info, &isLocalUdidGreater);
    if (ret != SOFTBUS_OK || GetSameApplyKeyInstanceNum(info) > 0) {
        AUTH_LOGW(AUTH_CONN, "wait another applyKeynego");
        return ret;
    }
    if (ret == SOFTBUS_OK && isLocalUdidGreater) {
        ret = SetApplyKeyStartState(requestId, GEN_APPLY_KEY_STATE_START);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
            return ret;
        }
        return ProcessAuthHichainParam(requestId, &g_hichainCallback);
    }
    return ret;
}

static int32_t ProcessApplyKeyDeviceId(int32_t channelId, uint32_t requestId, const void *data, uint32_t dataLen)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "data is null");
    RequestBusinessInfo info;
    ApplyKeyNegoInstance instance;
    GenApplyKeyCallback cb;
    (void)memset_s(&info, sizeof(RequestBusinessInfo), 0, sizeof(RequestBusinessInfo));
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    (void)memset_s(&cb, sizeof(GenApplyKeyCallback), 0, sizeof(GenApplyKeyCallback));
    bool isLocalUdidGreater = false;
    int32_t ret = UnpackApplyKeyAclParam((const char *)data, dataLen, &info);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "UnpackApplyKeyAclParam failed! ret=%{public}d", ret);
        return ret;
    }
    ret = CreateApplyKeyNegoInstance(&info, requestId, channelId, true, &cb);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "create new applyKeynego instance failed! ret=%{public}d", ret);
        return ret;
    }
    ret = ProcessApplyKeyNegoState(&info, &isLocalUdidGreater);
    if (ret != SOFTBUS_OK || GetSameApplyKeyInstanceNum(&info) > 0) {
        AUTH_LOGW(AUTH_CONN, "wait another applyKeynego");
        return ret;
    }
    if (ret == SOFTBUS_OK && isLocalUdidGreater) {
        ret = SetApplyKeyStartState(requestId, GEN_APPLY_KEY_STATE_START);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
            return ret;
        }
        return ProcessAuthHichainParam(requestId, &g_hichainCallback);
    }
    return ret;
}

static int32_t ProcessApplyKeyData(uint32_t requestId, const uint8_t *data, uint32_t dataLen)
{
    AUTH_LOGI(AUTH_CONN, "ProcessApplyKeyData enter: requestId=%{public}u, len=%{public}u", requestId, dataLen);
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));
    int32_t ret = GetGenApplyKeyInstanceByReq(requestId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed! ret=%{public}d", ret);
        return ret;
    }
    const LightAccountVerifier *lightAccountVerifier = ApplyKeyGetLightAccountInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier != NULL, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FALI, AUTH_CONN,
        "light account verify not initialized");

    int32_t activeUserId = GetActiveOsAccountIds();
    DataBuff inMsg = { .data = (uint8_t *)data, .length = dataLen };
    int32_t hichainRet =
        lightAccountVerifier->processLightAccountAuth(activeUserId, (int64_t)requestId, &inMsg, &g_hichainCallback);
    if (hichainRet != HC_SUCCESS) {
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)hichainRet, &authErrCode);
        AUTH_LOGE(AUTH_CONN,
            "hichain identity service authenticate credential failed, err=%{public}d, authErrCode=%{public}d",
            hichainRet, authErrCode);
        return authErrCode;
    }
    return SOFTBUS_OK;
}

static int32_t ApplyKeyMsgHandler(
    int32_t channelId, uint32_t requestId, const AuthDataHead *head, const void *data, uint32_t dataLen)
{
    if (head == NULL || data == NULL) {
        AUTH_LOGE(AUTH_CONN, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    switch (head->dataType) {
        case DATA_TYPE_DEVICE_ID:
            ret = ProcessApplyKeyDeviceId(channelId, requestId, data, dataLen);
            break;
        case DATA_TYPE_AUTH:
            ret = ProcessApplyKeyData(requestId, (const uint8_t *)data, dataLen);
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

static void OnCommConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    AUTH_LOGI(AUTH_CONN, "(ignored)OnCommConnected: connectionId=%{public}u", connectionId);
}

static void OnCommDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    AUTH_LOGI(AUTH_CONN, "on connect disconnected, connectionId=%{public}u", connectionId);
    ApplyKeyNegoInstance instance;
    (void)memset_s(&instance, sizeof(ApplyKeyNegoInstance), 0, sizeof(ApplyKeyNegoInstance));

    int32_t ret = GetGenApplyKeyInstanceByChannel(connectionId, &instance);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "get instance failed=%{public}d", ret);
        return;
    }
    DeleteApplyKeyNegoInstance(instance.requestId);
}

static void OnCommDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    if (data == NULL || moduleId != MODULE_APPLY_KEY_CONNECTION || len <= 0) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }
    AuthDataHead head = { 0 };
    const uint8_t *body = UnpackAuthData((const uint8_t *)data, (uint32_t)len, &head);
    if (body == NULL) {
        AUTH_LOGE(AUTH_CONN, "empty body");
        return;
    }
    int32_t ret = ApplyKeyMsgHandler(connectionId, head.seq, &head, body, head.len);
    AUTH_LOGI(AUTH_CONN,
        "ret=%{public}d, connectionId=%{public}u, module=%{public}d, seq=%{public}" PRId64 ", len=%{public}d", ret,
        connectionId, moduleId, head.seq, head.len);
}

static void RegisterD2DConnectListener(void)
{
    ConnectCallback connCb = {
        .OnConnected = OnCommConnected,
        .OnDisconnected = OnCommDisconnected,
        .OnDataReceived = OnCommDataReceived,
    };
    int32_t ret = ConnSetConnectCallback(MODULE_APPLY_KEY_CONNECTION, &connCb);
    AUTH_LOGI(AUTH_CONN, "ConnSetConnectCallback, ret=%{public}d", ret);
}

int32_t AuthFindApplyKey(const RequestBusinessInfo *info, uint8_t *applyKey)
{
    if (info == NULL || applyKey == NULL) {
        AUTH_LOGE(AUTH_CONN, "find apply key nego is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetApplyKeyByBusinessInfo(info, applyKey, D2D_APPLY_KEY_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "find apply key fail");
        return SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND;
    }
    AUTH_LOGE(AUTH_CONN, "find apply key succ");
    return SOFTBUS_OK;
}

int32_t AuthGenApplyKey(
    const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb)
{
    if (info == NULL || genCb == NULL) {
        AUTH_LOGE(AUTH_CONN, "generate apply key nego is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CreateApplyKeyNegoInstance(info, requestId, connId, false, genCb);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "applykey add instance fail, ret=%{public}d", ret);
        return ret;
    }
    ret = SendApplyKeyNegoDeviceId(connId, info, requestId);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "applykey send device id fail, ret=%{public}d", ret);
        DeleteApplyKeyNegoInstance(requestId);
        return ret;
    }
    ret = StartApplyKeyHichain(connId, info, requestId);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "applykey start hichain fail, ret=%{public}d", ret);
        DeleteApplyKeyNegoInstance(requestId);
        return ret;
    }
    return SOFTBUS_OK;
}

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
    for (uint32_t i = 0; i < APPLY_KEY_SEQ_NETWORK_ID_BITS / BYTES_BIT_NUM; i++) {
        g_uniqueId = (g_uniqueId << BYTES_BIT_NUM) | hashId[i];
    }
    uint64_t timeStamp = SoftBusGetSysTimeMs();
    g_uniqueId = (g_uniqueId << SEQ_TIME_STAMP_BITS) | (SEQ_TIME_STAMP_MASK & timeStamp);
}

uint32_t GenApplyKeySeq(void)
{
    static atomic_uint integer = 0;
    if (integer >= APPLY_KEY_SEQ_INTEGER_MAX) {
        integer = 0;
    }
    if (integer == 0) {
        UpdateUniqueId();
    }
    integer++;
    /* |----GreaterZero(1)----|----NetworkIdHash(16)----|----TimeStamp(8)----|----AtomicInteger(7)----| */
    uint32_t seq = integer;
    seq = (g_uniqueId << APPLY_KEY_SEQ_INTEGER_BITS) | (seq & APPLY_KEY_SEQ_INTEGER_MAX);
    return seq;
}

bool AuthIsApplyKeyExpired(uint64_t time)
{
    uint64_t currentTime = SoftBusGetSysTimeMs();
    if (currentTime < time || currentTime - time > g_applyKeyDecayTime) {
        AUTH_LOGE(AUTH_CONN, "apply key is expired cannot be used.");
        return false;
    }
    return true;
}

int32_t ApplyKeyNegoInit(void)
{
    AUTH_LOGI(AUTH_CONN, "enter.");

    if (SoftBusMutexInit(&g_applyKeyNegoListLock, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ApplyKeyNego mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (InitApplyKeyNegoInstanceList() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "applyKey nego instance list init err");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    RegisterD2DConnectListener();
    AUTH_LOGI(AUTH_CONN, "ok");
    return SOFTBUS_OK;
}

void ApplyKeyNegoDeinit(void)
{
    DeInitApplyKeyNegoInstanceList();
    SoftBusMutexDestroy(&g_applyKeyNegoListLock);
}
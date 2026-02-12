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

#include "auth_apply_key_manager.h"

#include <dirent.h>
#include <errno.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "anonymizer.h"
#include "auth_apply_key_process.h"
#include "auth_log.h"
#include "bus_center_event.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_async_callback_utils.h"
#include "lnn_decision_db.h"
#include "lnn_map.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_file.h"
#include "softbus_adapter_mem.h"
#include "softbus_init_common.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define DEFAULT_FILE_PATH     "/data/service/el1/public/dsoftbus/applykey"
#define KEY_LEN               100
#define D2D_APPLY_KEY_HEX_LEN (D2D_APPLY_KEY_LEN * 2 + 1)
#define MAP_KEY               "mapKey"

#define VALUE_APPLY_KEY    "applyKey"
#define VALUE_USER_ID      "userId"
#define VALUE_TIME         "time"
#define VALUE_ACCOUNT_HASH "accountHash"

typedef struct {
    uint8_t applyKey[D2D_APPLY_KEY_LEN];
    int32_t userId;
    uint64_t time;
    char accountHash[SHA_256_HEX_HASH_LEN];
} AuthApplyMapValue;

typedef struct {
    char mapKey[KEY_LEN];
    AuthApplyMapValue value;
} AuthApplyMap;

static Map g_authApplyMap;
static SoftBusMutex g_authApplyMutex;
static bool g_isInit = false;
static bool g_isRecoveryApplyKey = false;

static int32_t AuthApplyMapInit(void)
{
    if (SoftBusMutexInit(&g_authApplyMutex, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "g_authApplyMutex mutex init fail");
        return SOFTBUS_LOCK_ERR;
    }
    LnnMapInit(&g_authApplyMap);
    g_isInit = true;
    return SOFTBUS_OK;
}

static int32_t InsertToAuthApplyMap(
    const char *applyMapKey, const uint8_t *applyKey, int32_t userId, uint64_t time, char *accountHash)
{
    if (applyMapKey == NULL || applyKey == NULL || accountHash == NULL) {
        AUTH_LOGE(AUTH_INIT, "input is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    AuthApplyMapValue value = { .userId = userId, .time = time };
    if (memcpy_s(value.applyKey, D2D_APPLY_KEY_LEN, applyKey, D2D_APPLY_KEY_LEN) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(value.accountHash, SHA_256_HEX_HASH_LEN, accountHash) != EOK) {
        AUTH_LOGE(AUTH_CONN, "strcpy accountHash fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (SoftBusMutexLock(&g_authApplyMutex) != SOFTBUS_OK) {
        (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
        AUTH_LOGE(AUTH_CONN, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = LnnMapSet(&g_authApplyMap, applyMapKey, (const void *)&value, sizeof(AuthApplyMapValue));
    if (ret != SOFTBUS_OK) {
        (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
        (void)SoftBusMutexUnlock(&g_authApplyMutex);
        AUTH_LOGE(AUTH_CONN, "LnnMapSet fail");
        return ret;
    }
    (void)memset_s(&value, sizeof(AuthApplyMapValue), 0, sizeof(AuthApplyMapValue));
    (void)SoftBusMutexUnlock(&g_authApplyMutex);
    return SOFTBUS_OK;
}

static int32_t GetNodeFromAuthApplyMap(const char *applyMapKey, AuthApplyMapValue **value)
{
    if (applyMapKey == NULL) {
        AUTH_LOGE(AUTH_INIT, "input is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authApplyMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    uint64_t *ptr = (uint64_t *)LnnMapGet(&g_authApplyMap, applyMapKey);
    if (ptr == NULL) {
        AUTH_LOGE(AUTH_CONN, "LnnMapGet fail");
        (void)SoftBusMutexUnlock(&g_authApplyMutex);
        return SOFTBUS_AUTH_APPLY_KEY_NOT_FOUND;
    }
    *value = (AuthApplyMapValue *)ptr;
    (void)SoftBusMutexUnlock(&g_authApplyMutex);
    return SOFTBUS_OK;
}

static int32_t DeleteToAuthApplyMap(const char *applyMapKey)
{
    if (applyMapKey == NULL) {
        AUTH_LOGE(AUTH_INIT, "input is invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusMutexLock(&g_authApplyMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusMutexLock fail");
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = LnnMapErase(&g_authApplyMap, applyMapKey);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "delete item fail, ret=%{public}d", ret);
        (void)SoftBusMutexUnlock(&g_authApplyMutex);
        return ret;
    }
    (void)SoftBusMutexUnlock(&g_authApplyMutex);
    return SOFTBUS_OK;
}

static void ClearAuthApplyMap(void)
{
    if (SoftBusMutexLock(&g_authApplyMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusMutexLock fail");
        return;
    }
    LnnMapDelete(&g_authApplyMap);
    AUTH_LOGI(AUTH_CONN, "ClearAuthApplyMap succ");
    (void)SoftBusMutexUnlock(&g_authApplyMutex);
}

static void PrintfRequestBusinessInfo(const RequestBusinessInfo *info, int32_t userId)
{
    char *anonyAccountHash = NULL;
    Anonymize(info->accountHash, &anonyAccountHash);
    char *anonyUdidHash = NULL;
    Anonymize(info->udidHash, &anonyUdidHash);
    AUTH_LOGI(AUTH_CONN, "map key udidHash=%{public}s, accountHash=%{public}s, userId=%{public}d, type=%{public}d",
        AnonymizeWrapper(anonyUdidHash), AnonymizeWrapper(anonyAccountHash), userId, info->type);
    AnonymizeFree(anonyAccountHash);
    AnonymizeFree(anonyUdidHash);
}

int32_t GetApplyKeyByBusinessInfo(
    const RequestBusinessInfo *info, uint8_t *uk, uint32_t ukLen, char *accountHash, uint32_t accountHashLen)
{
    if (!g_isInit) {
        AUTH_LOGE(AUTH_INIT, "apply map init fail");
        return SOFTBUS_NO_INIT;
    }
    if (info == NULL || uk == NULL || accountHash == NULL || accountHashLen != SHA_256_HEX_HASH_LEN) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char key[KEY_LEN] = { 0 };
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (sprintf_s(key, sizeof(key), "%s_%s_%d_%d", info->udidHash, info->accountHash, userId, info->type) < 0) {
        AUTH_LOGE(AUTH_CONN, "sprintf_s key fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    PrintfRequestBusinessInfo(info, userId);
    AuthApplyMapValue *value = NULL;
    int32_t ret = GetNodeFromAuthApplyMap(key, &value);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "GetNodeFromAuthApplyMap fail");
        return ret;
    }
    if (memcpy_s(uk, ukLen, value->applyKey, D2D_APPLY_KEY_LEN) != EOK) {
        AUTH_LOGE(AUTH_CONN, "memcpy key fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(accountHash, SHA_256_HEX_HASH_LEN, value->accountHash) != EOK) {
        AUTH_LOGE(AUTH_CONN, "strcpy accountHash fail");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static bool AuthPackApplyKey(cJSON *json, char *nodeKey, AuthApplyMapValue *value)
{
    if (json == NULL || value == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return false;
    }
    char hexApplyKey[D2D_APPLY_KEY_HEX_LEN] = { 0 };
    if (ConvertBytesToHexString(
        hexApplyKey, D2D_APPLY_KEY_HEX_LEN, (unsigned char *)value->applyKey, D2D_APPLY_KEY_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ConvertBytesToHexString fail");
        return false;
    }
    if (!AddStringToJsonObject(json, MAP_KEY, nodeKey) || !AddStringToJsonObject(json, VALUE_APPLY_KEY, hexApplyKey) ||
        !AddStringToJsonObject(json, VALUE_ACCOUNT_HASH, value->accountHash) ||
        !AddNumberToJsonObject(json, VALUE_USER_ID, value->userId) ||
        !AddNumber64ToJsonObject(json, VALUE_TIME, value->time)) {
        AUTH_LOGE(AUTH_CONN, "add json object fail");
        return false;
    }
    return true;
}

static char *PackAllApplyKey(void)
{
    cJSON *jsonArray = cJSON_CreateArray();
    if (jsonArray == NULL) {
        AUTH_LOGE(AUTH_CONN, "jsonArray is null");
        return NULL;
    }
    MapIterator *it = LnnMapInitIterator(&g_authApplyMap);
    if (it == NULL) {
        AUTH_LOGE(AUTH_CONN, "map is empty");
        cJSON_Delete(jsonArray);
        return NULL;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL || it->node->value == NULL) {
            break;
        }
        cJSON *obj = cJSON_CreateObject();
        if (obj == NULL) {
            AUTH_LOGE(AUTH_CONN, "create json fail");
            break;
        }
        if (!AuthPackApplyKey(obj, (char *)it->node->key, (AuthApplyMapValue *)it->node->value)) {
            AUTH_LOGE(AUTH_CONN, "add json object fail");
            cJSON_Delete(obj);
            break;
        }
        cJSON_AddItemToArray(jsonArray, obj);
    }
    LnnMapDeinitIterator(it);
    char *msg = cJSON_PrintUnformatted(jsonArray);
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_PrintUnformatted fail");
    }
    cJSON_Delete(jsonArray);
    return msg;
}

static void AuthAsyncSaveApplyMapFile(void)
{
    if (SoftBusMutexLock(&g_authApplyMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusMutexLock fail");
        return;
    }
    char *dataStr = PackAllApplyKey();
    (void)SoftBusMutexUnlock(&g_authApplyMutex);
    if (dataStr == NULL) {
        AUTH_LOGE(AUTH_CONN, "PackAllApplyKey fail");
        return;
    }
    if (LnnAsyncSaveDeviceDataPacked((const char *)dataStr, LNN_DATA_TYPE_APPLY_KEY) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "save apply key fail");
    }
    (void)memset_s(dataStr, strlen(dataStr), 0, strlen(dataStr));
    cJSON_free(dataStr);
}

static bool AuthUnpackApplyKey(const cJSON *json, AuthApplyMap *node)
{
    if (json == NULL || node == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return false;
    }
    char hexApplyKey[D2D_APPLY_KEY_HEX_LEN] = {0};
    if (!GetJsonObjectNumber64Item(json, VALUE_TIME, (int64_t *)&node->value.time) ||
        !GetJsonObjectNumberItem(json, VALUE_USER_ID, &node->value.userId) ||
        !GetJsonObjectStringItem(json, MAP_KEY, node->mapKey, KEY_LEN) ||
        !GetJsonObjectStringItem(json, VALUE_APPLY_KEY, hexApplyKey, D2D_APPLY_KEY_HEX_LEN) ||
        !GetJsonObjectStringItem(json, VALUE_ACCOUNT_HASH, node->value.accountHash, SHA_256_HEX_HASH_LEN)) {
        AUTH_LOGE(AUTH_CONN, "unpack apply key fail");
        return false;
    }
    if (ConvertHexStringToBytes(
        (unsigned char *)node->value.applyKey, D2D_APPLY_KEY_LEN, hexApplyKey, strlen(hexApplyKey)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "ConvertHexStringToBytes fail.");
        return false;
    }
    return true;
}

static bool AuthPraseApplyKey(const char *applyKey)
{
    if (applyKey == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return false;
    }

    cJSON *json = cJSON_Parse(applyKey);
    if (json == NULL) {
        AUTH_LOGE(AUTH_CONN, "prase json fail");
        return false;
    }
    int32_t arraySize = cJSON_GetArraySize(json);
    bool res = true;
    AuthApplyMap node = { {0} };
    AuthApplyMapValue value = { {0} };
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        (void)memset_s(&node, sizeof(AuthApplyMap), 0, sizeof(AuthApplyMap));
        if (!AuthUnpackApplyKey(item, &node)) {
            res = false;
            break;
        }
        value = node.value;
        if (AuthIsApplyKeyExpired(value.time) && InsertToAuthApplyMap(node.mapKey, value.applyKey, value.userId,
            value.time, value.accountHash) != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_CONN, "insert apply key fail");
            res = false;
            break;
        }
    }
    cJSON_Delete(json);
    (void)memset_s(&node, sizeof(AuthApplyMap), 0, sizeof(AuthApplyMap));
    return res;
}

void AuthRecoveryApplyKey(void)
{
    if (!g_isInit) {
        AUTH_LOGE(AUTH_INIT, "apply map init fail");
        return;
    }

    char *applyKey = NULL;
    uint32_t applyKeyLen = 0;
    if (SoftBusMutexLock(&g_authApplyMutex) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "SoftBusMutexLock fail");
        return;
    }
    if (g_isRecoveryApplyKey) {
        (void)SoftBusMutexUnlock(&g_authApplyMutex);
        return;
    }
    if (LnnRetrieveDeviceDataPacked(LNN_DATA_TYPE_APPLY_KEY, &applyKey, &applyKeyLen) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_authApplyMutex);
        AUTH_LOGE(AUTH_CONN, "retrieve device fail");
        return;
    }
    g_isRecoveryApplyKey = true;
    (void)SoftBusMutexUnlock(&g_authApplyMutex);
    if (applyKey == NULL) {
        AUTH_LOGE(AUTH_CONN, "applyKey is empty");
        return;
    }
    if (applyKeyLen == 0) {
        AUTH_LOGE(AUTH_CONN, "applyKeyLen is zero");
        (void)memset_s(applyKey, applyKeyLen, 0, applyKeyLen);
        SoftBusFree(applyKey);
        return;
    }
    if (!AuthPraseApplyKey(applyKey)) {
        AUTH_LOGE(AUTH_CONN, "prase applyKey fail");
        (void)LnnDeleteDeviceDataPacked((LnnDataType)LNN_DATA_TYPE_APPLY_KEY);
    }
    (void)memset_s(applyKey, applyKeyLen, 0, applyKeyLen);
    SoftBusFree(applyKey);
}

int32_t AuthInsertApplyKey(
    const RequestBusinessInfo *info, const uint8_t *uk, uint32_t ukLen, uint64_t time, char *accountHash)
{
    if (!g_isInit) {
        AUTH_LOGE(AUTH_INIT, "apply map init fail");
        return SOFTBUS_NO_INIT;
    }
    if (info == NULL || uk == NULL || ukLen != D2D_APPLY_KEY_LEN || accountHash == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char key[KEY_LEN] = { 0 };
    int32_t userId = JudgeDeviceTypeAndGetOsAccountIds();
    if (sprintf_s(key, sizeof(key), "%s_%s_%d_%d", info->udidHash, info->accountHash, userId, info->type) < 0) {
        AUTH_LOGE(AUTH_CONN, "sprintf_s key fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    char *anonyAccountHash = NULL;
    Anonymize(info->accountHash, &anonyAccountHash);
    char *anonyUdidHash = NULL;
    Anonymize(info->udidHash, &anonyUdidHash);
    AUTH_LOGI(AUTH_CONN, "map key udidHash=%{public}s, accountHash=%{public}s, userId=%{public}d, type=%{public}d",
        AnonymizeWrapper(anonyUdidHash), AnonymizeWrapper(anonyAccountHash), userId, info->type);
    AnonymizeFree(anonyAccountHash);
    AnonymizeFree(anonyUdidHash);
    int32_t ret = InsertToAuthApplyMap(key, (const uint8_t *)uk, userId, time, accountHash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "insert apply key fail");
        return ret;
    }
    AuthAsyncSaveApplyMapFile();
    return ret;
}

int32_t AuthDeleteApplyKey(const RequestBusinessInfo *info)
{
    if (!g_isInit) {
        AUTH_LOGE(AUTH_INIT, "apply map init fail");
        return SOFTBUS_NO_INIT;
    }
    if (info == NULL) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char key[KEY_LEN] = { 0 };
    if (sprintf_s(key, sizeof(key), "%s_%s_%d_%d", info->udidHash, info->accountHash,
        JudgeDeviceTypeAndGetOsAccountIds(), info->type) < 0) {
        AUTH_LOGE(AUTH_CONN, "sprintf_s key fail");
        return SOFTBUS_SPRINTF_ERR;
    }
    int32_t ret = DeleteToAuthApplyMap(key);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "delete apply key fail");
        return ret;
    }
    AuthAsyncSaveApplyMapFile();
    return ret;
}

static int32_t AuthRemoveApplyKeyFile()
{
    char *filename = DEFAULT_FILE_PATH;
    return remove(filename);
}

void AuthClearAccountApplyKey(void)
{
    if (!g_isInit) {
        AUTH_LOGE(AUTH_INIT, "apply map init fail");
        return;
    }

    ClearAuthApplyMap();
    AuthRemoveApplyKeyFile();
}

static void AccountStateChangeHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        AUTH_LOGE(AUTH_CONN, "sle state change evt handler get invalid event");
        return;
    }

    const LnnMonitorSleStateChangedEvent *event = (const LnnMonitorSleStateChangedEvent *)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    switch (accountState) {
        case SOFTBUS_ACCOUNT_LOG_IN:
            AUTH_LOGI(AUTH_CONN, "(ignored)HB handle SOFTBUS_ACCOUNT_LOG_IN");
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            AUTH_LOGI(AUTH_CONN, "HB handle SOFTBUS_ACCOUNT_LOG_OUT");
            ClearAuthApplyMap();
            AuthRemoveApplyKeyFile();
            break;
        default:
            return;
    }
}

static void UserSwitchedHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_SWITCHED) {
        AUTH_LOGE(AUTH_CONN, "invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserSwitchState userSwitchState = (SoftBusUserSwitchState)event->status;
    switch (userSwitchState) {
        case SOFTBUS_USER_SWITCHED:
            AUTH_LOGI(AUTH_CONN, "ApplyKeyManager handle SOFTBUS_USER_SWITCHED");
            ClearAuthApplyMap();
            AuthRemoveApplyKeyFile();
            break;
        default:
            return;
    }
}

int32_t InitApplyKeyManager(void)
{
    int32_t ret = AuthApplyMapInit();
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "AuthApplyMapInit failed");
        return ret;
    }
    AuthRecoveryApplyKey();
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, AccountStateChangeHandler) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "regist account change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_USER_SWITCHED, UserSwitchedHandler) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "regist user switch evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    return SOFTBUS_OK;
}

void DeInitApplyKeyManager(void)
{
    if (!g_isInit) {
        AUTH_LOGE(AUTH_INIT, "apply map init fail");
        return;
    }

    ClearAuthApplyMap();
    (void)SoftBusMutexDestroy(&g_authApplyMutex);
    g_isRecoveryApplyKey = false;
}
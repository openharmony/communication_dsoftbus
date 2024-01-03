/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "auth_device_common_key.h"

#include <stdlib.h>
#include <securec.h>

#include "anonymizer.h"
#include "auth_log.h"
#include "auth_interface.h"
#include "lnn_map.h"
#include "lnn_secure_storage.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

#define UDID_SHORT_HASH 8
#define USER_ID_SHORT_HASH 2
#define DEVICE_KEY_SHORT_HASH 2
#define UDID_SHORT_HASH_HEX_STR 17
#define USER_ID_HASH_LEN 5
#define DEVICE_KEY_HASH_LEN 5
#define MAP_KEY_LEN 21
#define DEVICE_KEY_EXPITATION_TIME (48 * 60 * 60 * 1000) //48h
#define INT64_TO_STR_MAX_LEN 21
#define DEVICE_KEY_STRING_LEN 65
#define UDID_HASH_STR_LEN 16
#define STRTOLL_BASE 10

#define DEVICE_KEY_UDID "udid"
#define DEVICE_KEY_UDID_HASH "udidHash"
#define DEVICE_KEY_TYPE "keytype"
#define DEVICE_KEY_ACCOUNT_ID "accountId"
#define DEVICE_KEY_ACCOUNT_HASH "accountHash"
#define DEVICE_KEY_COMMON_KEY "commKey"
#define DEVICE_KEY_COMMON_KEY_HASH "commKeyHash"
#define DEVICE_KEY_INDEX "keyIndex"
#define DEVICE_KEY_COMM_KEY_LEN "keyLen"
#define DEVICE_KEY_CREATE_TIME "createtime"
#define DEVICE_KEY_END_TIME "endtime"
#define DEVICE_KEY_SERVER_SIDE "serversid"

typedef struct {
    int64_t accountId;
    char udid[UDID_BUF_LEN];
    char accountHashStr[USER_ID_HASH_LEN];
    char udidHashStr[UDID_SHORT_HASH_HEX_STR];
    char deviceKeyHashStr[DEVICE_KEY_HASH_LEN];
    uint64_t createTime;
    uint64_t endTime;
    AuthDeviceKeyInfo keyInfo;
} AuthDeviceCommonKey;

static Map g_deviceKeyMap;
static SoftBusMutex g_deviceKeyMutex;
static bool isInit = false;

static bool AuthDeviceKeyInit(void)
{
    if (SoftBusMutexInit(&g_deviceKeyMutex, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "devicekey mutex init fail");
        return false;
    }
    LnnMapInit(&g_deviceKeyMap);
    isInit = true;
    return true;
}

static int32_t KeyLock(void)
{
    if (!isInit) {
        if (!AuthDeviceKeyInit()) {
            return SOFTBUS_ERR;
        }
    }
    return SoftBusMutexLock(&g_deviceKeyMutex);
}

static void KeyUnlock(void)
{
    if (!isInit) {
        (void)AuthDeviceKeyInit();
        return;
    }
    (void)SoftBusMutexUnlock(&g_deviceKeyMutex);
}

static int32_t GetShortHash(const char *src, char *dst, uint32_t dstLen, uint32_t hashUsedLen)
{
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    int ret = SoftBusGenerateStrHash((uint8_t *)src, strlen(src), hash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "generate udidHash fail");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToUpperCaseHexString(dst, dstLen, hash, hashUsedLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "convert bytes to string fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t Int64ToHash(int64_t num, char *dst, uint32_t dstLen, uint32_t hashUsedLen)
{
    char buff[INT64_TO_STR_MAX_LEN] = {0};
    if (sprintf_s(buff, INT64_TO_STR_MAX_LEN, "%" PRIu64"", num) < 0) {
        AUTH_LOGE(AUTH_KEY, "convert int64 to string fail");
        return SOFTBUS_ERR;
    }
    if (buff[INT64_TO_STR_MAX_LEN - 1] != '\0') {
        AUTH_LOGE(AUTH_KEY, "buff is corrupted");
        return SOFTBUS_ERR;
    }
    return GetShortHash((const char *)buff, dst, dstLen, hashUsedLen);
}

static int32_t BytesToShortHash(uint8_t *src, uint32_t srcLen,
    char *dst, uint32_t dstLen, uint32_t hashUsedLen)
{
    uint8_t hash[SHA_256_HASH_LEN] = {0};
    int ret = SoftBusGenerateStrHash(src, srcLen, hash);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "generate udidHash fail");
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToUpperCaseHexString(dst, dstLen, hash, hashUsedLen) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "convert bytes to string fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool Int64ToString(int64_t src, char *buf, uint32_t bufLen)
{
    if (buf == NULL) {
        return false;
    }
    if (sprintf_s(buf, bufLen, "%" PRId64"", src) < 0) {
        AUTH_LOGE(AUTH_KEY, "convert int64 to string fail");
        return false;
    }
    return true;
}

static int64_t StringToInt64(const char *src)
{
    return (int64_t)strtoll(src, NULL, STRTOLL_BASE);
}

static int32_t PackDeviceKey(cJSON *json, AuthDeviceCommonKey *commonKey)
{
    char buff[INT64_TO_STR_MAX_LEN] = {0};
    if (Int64ToString(commonKey->accountId, buff, INT64_TO_STR_MAX_LEN)) {
        AddStringToJsonObject(json, DEVICE_KEY_ACCOUNT_ID, buff);
        (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));
    }
    if (Int64ToString(commonKey->keyInfo.keyIndex, buff, INT64_TO_STR_MAX_LEN)) {
        AddStringToJsonObject(json, DEVICE_KEY_INDEX, buff);
        (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));
    }
    if (Int64ToString(commonKey->createTime, buff, INT64_TO_STR_MAX_LEN)) {
        AddStringToJsonObject(json, DEVICE_KEY_CREATE_TIME, buff);
        (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));
    }
    if (Int64ToString(commonKey->endTime, buff, INT64_TO_STR_MAX_LEN)) {
        AddStringToJsonObject(json, DEVICE_KEY_END_TIME, buff);
        (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));
    }
    char deviceKeyStr[DEVICE_KEY_STRING_LEN] = {0};
    if (ConvertBytesToUpperCaseHexString(deviceKeyStr, DEVICE_KEY_STRING_LEN,
        commonKey->keyInfo.deviceKey, SESSION_KEY_LENGTH) == SOFTBUS_OK) {
        AddStringToJsonObject(json, DEVICE_KEY_COMMON_KEY, deviceKeyStr);
    }

    if (!AddStringToJsonObject(json, DEVICE_KEY_UDID, commonKey->udid) ||
        !AddStringToJsonObject(json, DEVICE_KEY_UDID_HASH, commonKey->udidHashStr) ||
        !AddNumberToJsonObject(json, DEVICE_KEY_TYPE, commonKey->keyInfo.keyType) ||
        !AddNumberToJsonObject(json, DEVICE_KEY_COMM_KEY_LEN, commonKey->keyInfo.keyLen) ||
        !AddStringToJsonObject(json, DEVICE_KEY_ACCOUNT_HASH, commonKey->accountHashStr) ||
        !AddStringToJsonObject(json, DEVICE_KEY_COMMON_KEY_HASH, commonKey->deviceKeyHashStr) ||
        !AddBoolToJsonObject(json, DEVICE_KEY_SERVER_SIDE, commonKey->keyInfo.isServerSide)) {
        AUTH_LOGE(AUTH_KEY, "pack device key fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t UnpackDeviceKey(cJSON *json, AuthDeviceCommonKey *commKey)
{
    char buff[INT64_TO_STR_MAX_LEN] = {0};
    if (GetJsonObjectStringItem(json, DEVICE_KEY_ACCOUNT_ID, buff, INT64_TO_STR_MAX_LEN)) {
        commKey->accountId = StringToInt64(buff);
        (void)memset_s(buff, INT64_TO_STR_MAX_LEN, 0, sizeof(buff));
    }
    if (GetJsonObjectStringItem(json, DEVICE_KEY_INDEX, buff, INT64_TO_STR_MAX_LEN)) {
        commKey->keyInfo.keyIndex = StringToInt64(buff);
        (void)memset_s(buff, INT64_TO_STR_MAX_LEN, 0, sizeof(buff));
    }
    if (GetJsonObjectStringItem(json, DEVICE_KEY_CREATE_TIME, buff, INT64_TO_STR_MAX_LEN)) {
        commKey->createTime = StringToInt64(buff);
        (void)memset_s(buff, INT64_TO_STR_MAX_LEN, 0, sizeof(buff));
    }
    if (GetJsonObjectStringItem(json, DEVICE_KEY_END_TIME, buff, INT64_TO_STR_MAX_LEN)) {
        commKey->endTime = StringToInt64(buff);
        (void)memset_s(buff, INT64_TO_STR_MAX_LEN, 0, sizeof(buff));
    }

    char deviceKeyStr[DEVICE_KEY_STRING_LEN] = {0};
    if (GetJsonObjectStringItem(json, DEVICE_KEY_COMMON_KEY, deviceKeyStr, DEVICE_KEY_STRING_LEN)) {
        (void)ConvertHexStringToBytes(commKey->keyInfo.deviceKey,
            SESSION_KEY_LENGTH, deviceKeyStr, strlen(deviceKeyStr));
    }

    if (!GetJsonObjectStringItem(json, DEVICE_KEY_UDID, commKey->udid, UDID_BUF_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_KEY_UDID_HASH, commKey->udidHashStr, UDID_SHORT_HASH_HEX_STR) ||
        !GetJsonObjectInt32Item(json, DEVICE_KEY_TYPE, &commKey->keyInfo.keyType) ||
        !GetJsonObjectInt32Item(json, DEVICE_KEY_COMM_KEY_LEN, (int32_t *)commKey->keyInfo.keyLen) ||
        !GetJsonObjectStringItem(json, DEVICE_KEY_ACCOUNT_HASH, commKey->accountHashStr, USER_ID_HASH_LEN) ||
        !GetJsonObjectStringItem(json, DEVICE_KEY_COMMON_KEY_HASH, commKey->deviceKeyHashStr, DEVICE_KEY_HASH_LEN) ||
        !GetJsonObjectBoolItem(json, DEVICE_KEY_SERVER_SIDE, &commKey->keyInfo.isServerSide)) {
        AUTH_LOGE(AUTH_KEY, "unpack device key fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char *PackAllDeviceKey(void)
{
    cJSON *jsonArray = cJSON_CreateArray();
    if (jsonArray == NULL) {
        AUTH_LOGE(AUTH_KEY, "jsonArray is null");
        return NULL;
    }
    if (KeyLock() != SOFTBUS_OK) {
        cJSON_Delete(jsonArray);
        return NULL;
    }
    MapIterator *it = LnnMapInitIterator(&g_deviceKeyMap);
    if (it == NULL) {
        AUTH_LOGE(AUTH_KEY, "map is empty");
        KeyUnlock();
        cJSON_Delete(jsonArray);
        return NULL;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL || it->node->value == NULL) {
            break;
        }
        AuthDeviceCommonKey *devicekey = (AuthDeviceCommonKey *)it->node->value;
        if (devicekey == NULL) {
            AUTH_LOGE(AUTH_KEY, "device key is nullptr");
            continue;
        }
        cJSON *obj = cJSON_CreateObject();
        if (obj == NULL) {
            AUTH_LOGE(AUTH_KEY, "jsonObj create fail");
            continue;
        }
        (void)PackDeviceKey(obj, devicekey);
        cJSON_AddItemToArray(jsonArray, obj);
    }
    LnnMapDeinitIterator(it);
    char *msg = cJSON_PrintUnformatted(jsonArray);
    KeyUnlock();
    cJSON_Delete(jsonArray);
    return msg;
}

static void AuthInserToDeviceKeyMap(const AuthDeviceCommonKey *deviceKey)
{
    char keyStr[MAP_KEY_LEN] = {0};
    int32_t ret = sprintf_s(keyStr, MAP_KEY_LEN, "%s-%d",
        deviceKey->udidHashStr, deviceKey->keyInfo.keyType);
    if (ret <= 0) {
        AUTH_LOGE(AUTH_KEY, "generate key fail");
        return;
    }
    if (KeyLock() != SOFTBUS_OK) {
        return;
    }
    if (LnnMapSet(&g_deviceKeyMap, (const char *)keyStr, (const void *)deviceKey,
        sizeof(AuthDeviceCommonKey)) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "save data fail");
        KeyUnlock();
        return;
    }
    KeyUnlock();
}

static void AuthInsertToSecureStorage(void)
{
    char *dataStr = PackAllDeviceKey();
    if (dataStr == NULL) {
        AUTH_LOGE(AUTH_KEY, "pack all deviceKey fail");
        return;
    }
    if (LnnSaveDeviceData((const char *)dataStr, LNN_DATA_TYPE_DEVICE_KEY) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "save device key fail");
        cJSON_free(dataStr);
        return;
    }
    cJSON_free(dataStr);
}

static void AuthSaveDeviceKey(const AuthDeviceCommonKey *deviceKey)
{
    AUTH_LOGD(AUTH_KEY, "save deviceKey");
    AuthInserToDeviceKeyMap(deviceKey);
    AuthInsertToSecureStorage();
}

int32_t AuthInsertDeviceKey(const NodeInfo *deviceInfo, const AuthDeviceKeyInfo *deviceKey)
{
    if (deviceInfo == NULL || deviceKey == NULL) {
        AUTH_LOGW(AUTH_KEY, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthDeviceCommonKey newDeviceKey = {0};
    if (memcpy_s(&newDeviceKey.keyInfo, sizeof(newDeviceKey.keyInfo),
        deviceKey, sizeof(AuthDeviceKeyInfo)) != EOK) {
        AUTH_LOGE(AUTH_KEY, "deviceKey memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(newDeviceKey.udid, UDID_BUF_LEN, deviceInfo->deviceInfo.deviceUdid) != EOK) {
        AUTH_LOGE(AUTH_KEY, "strcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    if (GetShortHash(deviceInfo->deviceInfo.deviceUdid, newDeviceKey.udidHashStr,
        UDID_SHORT_HASH_HEX_STR, UDID_SHORT_HASH) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get udid short hash fail");
        return SOFTBUS_ERR;
    }
    newDeviceKey.accountId = deviceInfo->accountId;
    if (Int64ToHash(deviceInfo->accountId, newDeviceKey.accountHashStr,
        USER_ID_HASH_LEN, USER_ID_SHORT_HASH) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get accont short hash fail");
        return SOFTBUS_ERR;
    }
    if (BytesToShortHash((uint8_t *)deviceKey->deviceKey, deviceKey->keyLen, newDeviceKey.deviceKeyHashStr,
        DEVICE_KEY_HASH_LEN, DEVICE_KEY_SHORT_HASH) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "get udid short hash fail");
        return SOFTBUS_ERR;
    }
    newDeviceKey.createTime = SoftBusGetSysTimeMs();
    newDeviceKey.endTime = SoftBusGetSysTimeMs() + DEVICE_KEY_EXPITATION_TIME;
    AuthSaveDeviceKey(&newDeviceKey);
    return SOFTBUS_OK;
}

void AuthRemoveDeviceKey(const char *udidHash, int32_t keyType)
{
    if (udidHash == NULL) {
        AUTH_LOGW(AUTH_KEY, "param err");
        return;
    }
    if (strlen(udidHash) != UDID_HASH_STR_LEN) {
        AUTH_LOGE(AUTH_KEY, "udidHash length id invalid");
        return;
    }
    char upperCaseHash[UDID_SHORT_HASH_HEX_STR] = {0};
    if (StringToUpperCase(udidHash, upperCaseHash, UDID_SHORT_HASH_HEX_STR) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "udid hash transfer to uppercase fail");
        return;
    }
    char keyStr[MAP_KEY_LEN] = {0};
    int32_t ret = sprintf_s(keyStr, MAP_KEY_LEN, "%s-%d", upperCaseHash, keyType);
    if (ret <= 0) {
        AUTH_LOGE(AUTH_KEY, "generate key fail");
        return;
    }
    if (KeyLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "lock fail");
        return;
    }
    ret = LnnMapErase(&g_deviceKeyMap, (const char *)keyStr);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "delete item fail ret=%d, keyStr=%s", ret, keyStr);
        KeyUnlock();
        return;
    }
    KeyUnlock();
    AuthInsertToSecureStorage();
}

void AuthRemoveDeviceKeyByUdid(const char *udidOrHash)
{
    if (udidOrHash == NULL) {
        AUTH_LOGE(AUTH_KEY, "param err");
        return;
    }
    char *anonyUdid = NULL;
    Anonymize(udidOrHash, &anonyUdid);
    AUTH_LOGE(AUTH_KEY, "remove device key, udid=%s", anonyUdid);
    AnonymizeFree(anonyUdid);
    bool isDeviceKeyMapChange = false;
    if (KeyLock() != SOFTBUS_OK) {
        return;
    }
    MapIterator *it = LnnMapInitIterator(&g_deviceKeyMap);
    if (it == NULL) {
        AUTH_LOGE(AUTH_KEY, "map is empty");
        KeyUnlock();
        return;
    }
    while (LnnMapHasNext(it)) {
        it = LnnMapNext(it);
        if (it == NULL || it->node == NULL) {
            break;
        }
        AuthDeviceCommonKey *deviceKey = (AuthDeviceCommonKey *)it->node->value;
        if (deviceKey == NULL) {
            AUTH_LOGE(AUTH_KEY, "device key is nullptr");
            continue;
        }
        if (StrCmpIgnoreCase(deviceKey->udid, udidOrHash) == 0 ||
            StrCmpIgnoreCase(deviceKey->udidHashStr, udidOrHash) == 0) {
            AUTH_LOGI(AUTH_KEY, "device udidOrHash match, remove");
            if (LnnMapErase(&g_deviceKeyMap, it->node->key) == SOFTBUS_OK) {
                isDeviceKeyMapChange = true;
            }
            continue;
        }
    }
    LnnMapDeinitIterator(it);
    KeyUnlock();
    if (isDeviceKeyMapChange) {
        AuthInsertToSecureStorage();
    }
}

int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo * deviceKey)
{
    if (udidHash == NULL || deviceKey == NULL) {
        AUTH_LOGW(AUTH_KEY, "param error");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strlen(udidHash) != UDID_HASH_STR_LEN) {
        AUTH_LOGE(AUTH_KEY, "udidHash length is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    char upperCaseHash[UDID_SHORT_HASH_HEX_STR] = {0};
    if (StringToUpperCase(udidHash, upperCaseHash, UDID_SHORT_HASH_HEX_STR) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "udid hash transfer to uppercase fail");
        return SOFTBUS_ERR;
    }
    char keyStr[MAP_KEY_LEN] = {0};
    int32_t ret = sprintf_s(keyStr, MAP_KEY_LEN, "%s-%d", upperCaseHash, keyType);
    if (ret <= 0) {
        AUTH_LOGE(AUTH_KEY, "generate key fail");
        return SOFTBUS_ERR;
    }
    if (KeyLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_KEY, "keyLock fail");
        return SOFTBUS_ERR;
    }
    AuthDeviceCommonKey *data = (AuthDeviceCommonKey *)LnnMapGet(&g_deviceKeyMap, (const char *)keyStr);
    if (data == NULL) {
        AUTH_LOGE(AUTH_KEY, "data not foune");
        KeyUnlock();
        return SOFTBUS_ERR;
    }
    if (SoftBusGetSysTimeMs() > data->endTime) {
        AUTH_LOGE(AUTH_KEY, "deviceKey has expired, force delete. currTime=%" PRId64", deviceKeyEndTime=%" PRId64".",
            SoftBusGetSysTimeMs(), data->endTime);
        ret = LnnMapErase(&g_deviceKeyMap, (const char *)keyStr);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_KEY, "delete element fail");
        }
        KeyUnlock();
        AuthInsertToSecureStorage();
        return SOFTBUS_ERR;
    }
    if (memcpy_s(deviceKey, sizeof(AuthDeviceKeyInfo), &data->keyInfo, sizeof(AuthDeviceKeyInfo)) != EOK) {
        KeyUnlock();
        return SOFTBUS_ERR;
    }
    KeyUnlock();
    return SOFTBUS_OK;
}

static bool AuthParseDeviceKey(const char *deviceKey)
{
    cJSON *json = cJSON_Parse(deviceKey);
    if (json == NULL) {
        AUTH_LOGE(AUTH_KEY, "parse json fail");
        return false;
    }
    int32_t arraySize = cJSON_GetArraySize(json);
    if (arraySize <= 0) {
        AUTH_LOGE(AUTH_KEY, "invalid deviceKey log");
        cJSON_Delete(json);
        return false;
    }
    AUTH_LOGD(AUTH_KEY, "jsonArray size:%d", arraySize);
    AuthDeviceCommonKey oldDeviceKey;
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        (void)memset_s(&oldDeviceKey, sizeof(oldDeviceKey), 0, sizeof(oldDeviceKey));
        if (UnpackDeviceKey(item, &oldDeviceKey) != SOFTBUS_OK) {
            continue;
        }
        AuthInserToDeviceKeyMap(&oldDeviceKey);
    }
    cJSON_Delete(json);
    return true;
}

void AuthUpdateKeyIndex(const char *udidHash, int32_t keyType, int64_t index, bool isServer)
{
    if (udidHash == NULL) {
        AUTH_LOGE(AUTH_KEY, "udidiHash log update fail");
        return;
    }
    char keyStr[MAP_KEY_LEN] = {0};
    int32_t ret = sprintf_s(keyStr, MAP_KEY_LEN, "%s-%d", udidHash, keyType);
    if (ret <= 0) {
        AUTH_LOGE(AUTH_KEY, "generate key fail");
        return;
    }
    if (KeyLock() != SOFTBUS_OK) {
        return;
    }
    AuthDeviceCommonKey *data = (AuthDeviceCommonKey *)LnnMapGet(&g_deviceKeyMap, (const char *)keyStr);
    if (data == NULL) {
        AUTH_LOGE(AUTH_KEY, "data is nullptr");
        return;
    }
    data->keyInfo.keyIndex = index;
    data->keyInfo.isServerSide = isServer;
    KeyUnlock();
    AuthInsertToSecureStorage();
}

/*called during initialization*/
void AuthLoadDeviceKey(void)
{
    AUTH_LOGD(AUTH_KEY, "load deviceKey");
    char *deviceKey = NULL;
    uint32_t deviceKeyLen = 0;
    if (LnnRetrieveDeviceData(LNN_DATA_TYPE_DEVICE_KEY, &deviceKey, &deviceKeyLen) != SOFTBUS_OK) {
        AUTH_LOGW(AUTH_KEY, "load deviceKey fail, maybe no device has ever gone online");
        return;
    }
    if (deviceKey == NULL) {
        AUTH_LOGE(AUTH_KEY, "load deviceKey fail,deviceKey is nullptr");
        return;
    }
    if (deviceKeyLen == 0 || strlen(deviceKey) != deviceKeyLen) {
        AUTH_LOGE(AUTH_KEY, "deviceKeyLen is invalid");
        SoftBusFree(deviceKey);
        return;
    }
    if (!AuthParseDeviceKey(deviceKey)) {
        AUTH_LOGE(AUTH_KEY, "parse device key fail");
    }
    SoftBusFree(deviceKey);
    AUTH_LOGD(AUTH_KEY, "load deviceKey finish");
}

void AuthClearDeviceKey(void)
{
    /*need aging mechanism*/
    LnnMapDelete(&g_deviceKeyMap);
}

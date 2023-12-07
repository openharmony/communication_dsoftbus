/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "softbus_json_utils.h"

#include <securec.h>

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

int32_t GetStringItemByJsonObject(const cJSON *json, const char * const string, char *target,
    uint32_t targetLen)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsString(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return SOFTBUS_ERR;
    }
    uint32_t length = strlen(item->valuestring);
    if (length >= targetLen) {
        COMM_LOGE(COMM_UTILS, "the length [%d] is to long for [%s]", length, string);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = strcpy_s(target, targetLen, item->valuestring);
    if (ret != EOK) {
        COMM_LOGE(COMM_UTILS, "strcpy error %d\n", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target,
    uint32_t targetLen)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsString(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    uint32_t length = strlen(item->valuestring);
    if (length >= targetLen) {
        COMM_LOGE(COMM_UTILS, "the length [%d] is to long for [%s]", length, string);
        return false;
    }
    int32_t ret = strcpy_s(target, targetLen, item->valuestring);
    if (ret != EOK) {
        COMM_LOGE(COMM_UTILS, "strcpy error %d\n", ret);
        return false;
    }
    return true;
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int32_t)item->valuedouble;
    return true;
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int32_t)item->valuedouble;
    return true;
}

bool GetJsonObjectDoubleItem(const cJSON *json, const char * const string, double *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON* item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = item->valuedouble;
    return true;
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (uint16_t)item->valuedouble;
    return true;
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int64_t)item->valuedouble;
    return true;
}

bool GetJsonObjectSignedNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int64_t)item->valuedouble;
    return true;
}

bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int32_t)item->valuedouble;
    return true;
}

bool GetJsonObjectBoolItem(const cJSON *json, const char * const string, bool *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsBool(item)) {
        COMM_LOGE(COMM_UTILS, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (bool)item->valueint;
    return true;
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    if (value == NULL || json == NULL || string == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_CreateString(value);
    if (item == NULL) {
        COMM_LOGE(COMM_UTILS, "Cannot create cJSON string object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddStringArrayToJsonObject(cJSON *json, const char * const string, const char * const *strings, int32_t count)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(json != NULL && string != NULL && strings != NULL, false, COMM_EVENT,
        "param is null");
    COMM_CHECK_AND_RETURN_RET_LOGE(count > 0, false, COMM_EVENT, "count <= 0");

    cJSON *item = cJSON_CreateStringArray(strings, count);
    if (item == NULL) {
        COMM_LOGE(COMM_EVENT, "Cannot create cJSON string array object [%s]", string);
        return false;
    }

    if (!cJSON_AddItemToObject(json, string, item)) {
        COMM_LOGE(COMM_EVENT, "Cannot add string array object to json [%s]", string);
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddNumber16ToJsonObject(cJSON *json, const char * const string, uint16_t num)
{
    if (json == NULL || string == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_CreateNumber((double)num);
    if (item == NULL) {
        COMM_LOGE(COMM_UTILS, "Cannot create cJSON number object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        COMM_LOGE(COMM_UTILS, "Cannot add num object to json [%s]", string);
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    if (json == NULL || string == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_CreateNumber((double)num);
    if (item == NULL) {
        COMM_LOGE(COMM_UTILS, "Cannot create cJSON number object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        COMM_LOGE(COMM_UTILS, "Cannot add num object to json [%s]", string);
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num)
{
    if (json == NULL || string == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_CreateNumber((double)num);
    if (item == NULL) {
        COMM_LOGE(COMM_UTILS, "Cannot create cJSON number object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        COMM_LOGE(COMM_UTILS, "Cannot add num64 object to json [%s]", string);
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value)
{
    if (json == NULL || string == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *item = cJSON_CreateBool(value);
    if (item == NULL) {
        COMM_LOGE(COMM_UTILS, "Cannot create cJSON bool object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        COMM_LOGE(COMM_UTILS, "Cannot add bool object to json [%s]", string);
        cJSON_Delete(item);
        return false;
    }
    return true;
}

char *GetDynamicStringItemByJsonObject(const cJSON * const json, const char * const string, uint32_t limit)
{
    if (json == NULL || string == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return NULL;
    }

    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsString(item)) {
        COMM_LOGE(COMM_EVENT, "Cannot find or invalid [%s]", string);
        return NULL;
    }
    uint32_t length = strlen(item->valuestring);
    if (length > limit) {
        COMM_LOGE(COMM_EVENT, "key [%s] length [%u] is large than limit [%u]", string, length, limit);
        return NULL;
    }
    char *value = SoftBusCalloc(length + 1);
    if (value == NULL) {
        COMM_LOGE(COMM_EVENT, "malloc failed, length [%u]", length);
        return NULL;
    }
    if (strcpy_s(value, length + 1, item->valuestring) != EOK) {
        COMM_LOGE(COMM_EVENT, "copy failed, length [%u]", length);
        SoftBusFree(value);
        return NULL;
    }
    return value;
}

bool AddIntArrayToJsonObject(cJSON *json, const char *string, const int32_t *array, int32_t arrayLen)
{
    if (json == NULL || string == NULL || array == NULL || arrayLen <= 0) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *arrayObj = cJSON_CreateIntArray(array, arrayLen);
    if (arrayObj == NULL) {
        COMM_LOGE(COMM_EVENT, "Cannot create cJSON array object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject((cJSON *)json, string, arrayObj)) {
        cJSON_Delete(arrayObj);
        return false;
    }
    return true;
}

bool GetJsonObjectIntArrayItem(const cJSON *json, const char *string, int32_t *array, int32_t arrayLen)
{
    if (json == NULL || string == NULL || array == NULL || arrayLen <= 0) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    cJSON *objValue = cJSON_GetObjectItem(json, string);
    if (objValue == NULL) {
        COMM_LOGE(COMM_EVENT, "Cannot create cJSON objValue [%s]", string);
        return false;
    }
    if (!cJSON_IsArray(objValue)) {
        return false;
    }
    int32_t size = cJSON_GetArraySize(objValue);
    if (size > arrayLen) {
        size = arrayLen;
    }
    uint32_t index = 0;
    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(objValue, i);
        if (item == NULL) {
            return false;
        }
        if (!cJSON_IsNumber(item)) {
            continue;
        }
        array[index++] = item->valueint;
    }
    return true;
}

/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "softbus_def.h"
#include "softbus_error_code.h"

int32_t GetStringItemByJsonObject(const cJSON *json, const char * const string, char *target,
    uint32_t targetLen)
{
    if (json == NULL || string == NULL || target == NULL) {
        return SOFTBUS_ERR;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsString(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return SOFTBUS_ERR;
    }
    uint32_t length = strlen(item->valuestring);
    if (length >= targetLen) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "the length [%d] is to long for [%s]", length, string);
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = strcpy_s(target, targetLen, item->valuestring);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy error %d\n", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target,
    uint32_t targetLen)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsString(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    uint32_t length = strlen(item->valuestring);
    if (length >= targetLen) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "the length [%d] is to long for [%s]", length, string);
        return false;
    }
    int ret = strcpy_s(target, targetLen, item->valuestring);
    if (ret != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "strcpy error %d\n", ret);
        return false;
    }
    return true;
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int)item->valuedouble;
    return true;
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int)item->valuedouble;
    return true;
}

bool GetJsonObjectDoubleItem(const cJSON *json, const char * const string, double *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON* item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = item->valuedouble;
    return true;
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (uint16_t)item->valuedouble;
    return true;
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item) || (item->valuedouble < 0)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int64_t)item->valuedouble;
    return true;
}

bool GetJsonObjectSignedNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int64_t)item->valuedouble;
    return true;
}

bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsNumber(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (int32_t)item->valuedouble;
    return true;
}

bool GetJsonObjectBoolItem(const cJSON *json, const char * const string, bool *target)
{
    if (json == NULL || string == NULL || target == NULL) {
        return false;
    }
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, string);
    if (item == NULL || !cJSON_IsBool(item)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot find or invalid [%s]", string);
        return false;
    }
    *target = (bool)item->valueint;
    return true;
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    if (value == NULL || json == NULL || string == NULL) {
        return false;
    }
    cJSON *item = cJSON_CreateString(value);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot create cJSON string object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int num)
{
    if (json == NULL || string == NULL) {
        return false;
    }
    cJSON *item = cJSON_CreateNumber(num);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot create cJSON number object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num)
{
    if (json == NULL || string == NULL) {
        return false;
    }
    cJSON *item = cJSON_CreateNumber(num);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot create cJSON number object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        cJSON_Delete(item);
        return false;
    }
    return true;
}

bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value)
{
    if (json == NULL || string == NULL) {
        return false;
    }
    cJSON *item = cJSON_CreateBool(value);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Cannot create cJSON bool object [%s]", string);
        return false;
    }
    if (!cJSON_AddItemToObject(json, string, item)) {
        cJSON_Delete(item);
        return false;
    }
    return true;
}
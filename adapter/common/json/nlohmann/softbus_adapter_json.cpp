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

#include "softbus_adapter_json.h"

#include "comm_log.h"
#include "nlohmann/json.hpp"
#include "securec.h"
#include "softbus_adapter_mem.h"

#define JSON_LOGE(fmt, ...) COMM_LOGE(COMM_ADAPTER, "[%s] " fmt, __FUNCTION__, ##__VA_ARGS__)
#define JSON_LOGD(fmt, ...) COMM_LOGD(COMM_ADAPTER, "[%s] " fmt, __FUNCTION__, ##__VA_ARGS__)

JsonObj *JSON_CreateObject(void)
{
    JsonObj *obj = new (std::nothrow) JsonObj();
    if (obj == nullptr) {
        JSON_LOGE("new JsonObj fail");
        return nullptr;
    }
    nlohmann::json *json = new (std::nothrow) nlohmann::json();
    if (json == nullptr) {
        JSON_LOGE("new nlohmann fail");
        delete obj;
        obj = nullptr;
        return nullptr;
    }
    obj->context = reinterpret_cast<void *>(json);
    return obj;
}

void JSON_Delete(JsonObj *obj)
{
    if (obj == nullptr) {
        return;
    }
    if (obj->context != nullptr) {
        nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
        if (json != nullptr) {
            delete json;
        }
        obj->context = nullptr;
    }
    delete obj;
    obj = nullptr;
}

void JSON_Free(void *obj)
{
    if (obj != nullptr) {
        SoftBusFree(obj);
    }
}

char *JSON_PrintUnformatted(const JsonObj *obj)
{
    if (obj == nullptr) {
        JSON_LOGE("invalid param");
        return nullptr;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return nullptr;
    }
    std::string jsonString = json->dump();

    char *result = (char *)SoftBusCalloc(jsonString.length() + 1); /* 1 for '\0' */
    if (result == nullptr) {
        JSON_LOGE("malloc array fail");
        return nullptr;
    }
    if (strcpy_s(result, jsonString.length() + 1, jsonString.c_str()) != EOK) {
        JSON_LOGE("strcpy json string fail");
        SoftBusFree(result);
        return nullptr;
    }
    return result;
}

JsonObj *JSON_Parse(const char *str, uint32_t len)
{
    JsonObj *obj = JSON_CreateObject();
    if (obj == nullptr) {
        JSON_LOGE("create json object fail");
        return nullptr;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_Delete(obj);
        JSON_LOGE("cast json fail");
        return nullptr;
    }
    std::string jsonString(str, len);
    nlohmann::json entity = nlohmann::json::parse(jsonString, nullptr, false);
    if (entity.is_discarded()) {
        JSON_Delete(obj);
        JSON_LOGE("parse json fail");
        return nullptr;
    }
    for (auto &item : entity.items()) {
        (*json)[item.key()] = item.value();
    }
    return obj;
}

bool JSON_AddBoolToObject(JsonObj *obj, const char *key, bool value)
{
    if (obj == nullptr || key == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    (*json)[key] = value;
    return true;
}

bool JSON_GetBoolFromOject(const JsonObj *obj, const char *key, bool *value)
{
    if (obj == nullptr || key == nullptr || value == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    nlohmann::json item = (*json)[key];
    if (!item.is_boolean()) {
        JSON_LOGE("Cannot find or invalid key. key=%{public}s", key);
        return false;
    }
    *value = item.get<bool>();
    return true;
}

template <typename Integer>
static bool JSON_AddIntegerToObject(JsonObj *obj, const char *key, Integer num)
{
    if (obj == nullptr || key == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    (*json)[key] = num;
    return true;
}

template <typename Integer>
static bool JSON_GetIntegerFromObject(const JsonObj *obj, const char *key, Integer &value)
{
    if (obj == nullptr || key == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    nlohmann::json item = (*json)[key];
    if (!item.is_number()) {
        JSON_LOGE("Cannot find or invalid key. key=%{public}s", key);
        return false;
    }
    value = item.get<Integer>();
    return true;
}

bool JSON_AddInt16ToObject(JsonObj *obj, const char *key, int16_t value)
{
    return JSON_AddIntegerToObject(obj, key, value);
}

bool JSON_GetInt16FromOject(const JsonObj *obj, const char *key, int16_t *value)
{
    if (value == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    return JSON_GetIntegerFromObject(obj, key, *value);
}

bool JSON_AddInt32ToObject(JsonObj *obj, const char *key, int32_t value)
{
    return JSON_AddIntegerToObject(obj, key, value);
}

bool JSON_GetInt32FromOject(const JsonObj *obj, const char *key, int32_t *value)
{
    if (value == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    return JSON_GetIntegerFromObject(obj, key, *value);
}

bool JSON_AddInt64ToObject(JsonObj *obj, const char *key, int64_t value)
{
    return JSON_AddIntegerToObject(obj, key, value);
}

bool JSON_GetInt64FromOject(const JsonObj *obj, const char *key, int64_t *value)
{
    if (value == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    return JSON_GetIntegerFromObject(obj, key, *value);
}

bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value)
{
    if (obj == nullptr || key == nullptr || value == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    (*json)[key] = std::string(value);
    return true;
}

bool JSON_GetStringFromOject(const JsonObj *obj, const char *key, char *value, uint32_t size)
{
    if (obj == nullptr || key == nullptr || value == nullptr) {
        JSON_LOGE("invalid param");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    nlohmann::json item = (*json)[key];
    if (!item.is_string()) {
        JSON_LOGD("cannot find or invalid key. key=%{public}s", key);
        return false;
    }
    std::string valueString = item.get<std::string>();
    if (strcpy_s(value, size, valueString.c_str()) != EOK) {
        JSON_LOGE("strcpy value err, key=%{public}s, size=%{public}u, value=%{public}s",
            key, size, valueString.c_str());
        return false;
    }
    return true;
}

bool JSON_AddStringArrayToObject(JsonObj *obj, const char *key, const char **value, int32_t len)
{
    if (value == nullptr || obj == nullptr || key == nullptr || len <= 0) {
        JSON_LOGE("input invalid");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    nlohmann::json valueStringArray = nlohmann::json::array();
    for (int32_t i = 0; i < len; i++) {
        valueStringArray.push_back(value[i]);
    }
    (*json)[key] = valueStringArray;
    return true;
}

bool JSON_GetStringArrayFromOject(const JsonObj *obj, const char *key, char **value, int32_t *len)
{
    if (value == nullptr || obj == nullptr || key == nullptr || len == nullptr || *len <= 0) {
        JSON_LOGE("input invalid");
        return false;
    }
    nlohmann::json *json = reinterpret_cast<nlohmann::json *>(obj->context);
    if (json == nullptr) {
        JSON_LOGE("invaild json param");
        return false;
    }
    nlohmann::json item = (*json)[key];
    if (!item.is_array()) {
        JSON_LOGE("cannot find or invalid key. key=%{public}s", key);
        return false;
    }
    if ((unsigned long)(*len) < (unsigned long)item.size()) {
        JSON_LOGE("item size invalid, size=%{public}lu.", (unsigned long)item.size());
        return false;
    }
    int32_t i = 0;
    for (nlohmann::json::iterator it = item.begin(); it != item.end(); ++it) {
        std::string str = it.value().get<std::string>();
        const char *valueString = str.c_str();
        uint32_t valueLen = strlen(valueString) + 1;
        value[i] = reinterpret_cast<char *>(SoftBusCalloc(valueLen));
        if (value[i] == nullptr) {
            return false;
        }
        if (strcpy_s(value[i], valueLen, valueString) != EOK) {
            JSON_LOGE("strcpy value err. key=%{public}s, value=%{public}s", key, valueString);
            return false;
        }
        i++;
    }
    *len = item.size();
    return true;
}

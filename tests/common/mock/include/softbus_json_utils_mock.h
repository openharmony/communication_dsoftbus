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

#ifndef SOFTBUS_JSON_UTILS_MOCK_H
#define SOFTBUS_JSON_UTILS_MOCK_H

#include "softbus_json_utils.h"

#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class JsonUtilsInterface {
public:
    JsonUtilsInterface() {};
    virtual ~JsonUtilsInterface() {};

    virtual int32_t GetStringItemByJsonObject(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target) = 0;
    virtual bool GetJsonObjectSignedNumber64Item(const cJSON *json, const char * const string, int64_t *target) = 0;
    virtual bool GetJsonObjectDoubleItem(const cJSON *json, const char * const string, double *target) = 0;
    virtual bool GetJsonObjectBoolItem(const cJSON *json, const char * const string, bool *target) = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddStringArrayToJsonObject(
        cJSON *json, const char * const string, const char * const *strings, int32_t count) = 0;
    virtual bool AddNumber16ToJsonObject(cJSON *json, const char * const string, uint16_t num) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num) = 0;
    virtual bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value) = 0;
    virtual bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual char *GetDynamicStringItemByJsonObject(
        const cJSON * const json, const char * const string, uint32_t limit) = 0;
    virtual bool AddIntArrayToJsonObject(cJSON *json, const char *string, const int32_t *array, int32_t arrayLen) = 0;
    virtual bool GetJsonObjectIntArrayItem(const cJSON *json, const char *string, int32_t *array, int32_t arrayLen) = 0;
};
class JsonUtilsInterfaceMock : public JsonUtilsInterface {
public:
    JsonUtilsInterfaceMock();
    ~JsonUtilsInterfaceMock() override;

    MOCK_METHOD4(GetStringItemByJsonObject,
        int32_t(const cJSON *json, const char * const string, char *target, uint32_t targetLen));
    MOCK_METHOD4(
        GetJsonObjectStringItem, bool(const cJSON *json, const char * const string, char *target, uint32_t targetLen));
    MOCK_METHOD3(GetJsonObjectNumber16Item, bool(const cJSON *json, const char * const string, uint16_t *target));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool(const cJSON *json, const char * const string, int32_t *target));
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool(const cJSON *json, const char * const string, int32_t *target));
    MOCK_METHOD3(GetJsonObjectNumber64Item, bool(const cJSON *json, const char * const string, int64_t *target));
    MOCK_METHOD3(GetJsonObjectSignedNumber64Item, bool(const cJSON *json, const char * const string, int64_t *target));
    MOCK_METHOD3(GetJsonObjectDoubleItem, bool(const cJSON *json, const char * const string, double *target));
    MOCK_METHOD3(GetJsonObjectBoolItem, bool(const cJSON *json, const char * const string, bool *target));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *json, const char * const string, const char *value));
    MOCK_METHOD4(AddStringArrayToJsonObject,
        bool(cJSON *json, const char * const string, const char * const *strings, int32_t count));
    MOCK_METHOD3(AddNumber16ToJsonObject, bool(cJSON *json, const char * const string, uint16_t num));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *json, const char * const string, int32_t num));
    MOCK_METHOD3(AddNumber64ToJsonObject, bool(cJSON *json, const char * const string, int64_t num));
    MOCK_METHOD3(AddBoolToJsonObject, bool(cJSON *json, const char * const string, bool value));
    MOCK_METHOD3(GetJsonObjectInt32Item, bool(const cJSON *json, const char * const string, int32_t *target));
    MOCK_METHOD3(
        GetDynamicStringItemByJsonObject, char *(const cJSON * const json, const char * const string, uint32_t limit));
    MOCK_METHOD4(
        AddIntArrayToJsonObject, bool(cJSON *json, const char *string, const int32_t *array, int32_t arrayLen));
    MOCK_METHOD4(
        GetJsonObjectIntArrayItem, bool(const cJSON *json, const char *string, int32_t *array, int32_t arrayLen));
};
} // namespace OHOS
#endif // SOFTBUS_JSON_UTILS_MOCK_H
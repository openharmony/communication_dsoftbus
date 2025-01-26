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

#include "softbus_json_utils_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_jsonUtilsInterface;

JsonUtilsInterfaceMock::JsonUtilsInterfaceMock()
{
    g_jsonUtilsInterface = reinterpret_cast<void *>(this);
}

JsonUtilsInterfaceMock::~JsonUtilsInterfaceMock()
{
    g_jsonUtilsInterface = nullptr;
}

static JsonUtilsInterface *GetJsonUtilsInterface()
{
    return reinterpret_cast<JsonUtilsInterfaceMock *>(g_jsonUtilsInterface);
}

extern "C" {
int32_t GetStringItemByJsonObject(const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return GetJsonUtilsInterface()->GetStringItemByJsonObject(json, string, target, targetLen);
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return GetJsonUtilsInterface()->GetJsonObjectStringItem(json, string, target, targetLen);
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectNumber16Item(json, string, target);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectNumberItem(json, string, target);
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectSignedNumberItem(json, string, target);
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectNumber64Item(json, string, target);
}

bool GetJsonObjectSignedNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectSignedNumber64Item(json, string, target);
}

bool GetJsonObjectDoubleItem(const cJSON *json, const char * const string, double *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectDoubleItem(json, string, target);
}

bool GetJsonObjectBoolItem(const cJSON *json, const char * const string, bool *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectBoolItem(json, string, target);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetJsonUtilsInterface()->AddStringToJsonObject(json, string, value);
}

bool AddStringArrayToJsonObject(cJSON *json, const char * const string, const char * const *strings, int32_t count)
{
    return GetJsonUtilsInterface()->AddStringArrayToJsonObject(json, string, strings, count);
}

bool AddNumber16ToJsonObject(cJSON *json, const char * const string, uint16_t num)
{
    return GetJsonUtilsInterface()->AddNumber16ToJsonObject(json, string, num);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetJsonUtilsInterface()->AddNumberToJsonObject(json, string, num);
}

bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num)
{
    return GetJsonUtilsInterface()->AddNumber64ToJsonObject(json, string, num);
}

bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value)
{
    return GetJsonUtilsInterface()->AddBoolToJsonObject(json, string, value);
}

bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target)
{
    return GetJsonUtilsInterface()->GetJsonObjectInt32Item(json, string, target);
}

char *GetDynamicStringItemByJsonObject(const cJSON * const json, const char * const string, uint32_t limit)
{
    return GetJsonUtilsInterface()->GetDynamicStringItemByJsonObject(json, string, limit);
}

bool AddIntArrayToJsonObject(cJSON *json, const char *string, const int32_t *array, int32_t arrayLen)
{
    return GetJsonUtilsInterface()->AddIntArrayToJsonObject(json, string, array, arrayLen);
}

bool GetJsonObjectIntArrayItem(const cJSON *json, const char *string, int32_t *array, int32_t arrayLen)
{
    return GetJsonUtilsInterface()->GetJsonObjectIntArrayItem(json, string, array, arrayLen);
}
}
} // namespace OHOS
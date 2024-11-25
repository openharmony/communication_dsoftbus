/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "jsonutils_fuzzer.h"

#include <cstddef>
#include <securec.h>
#include <string>
#include "softbus_json_utils.h"

namespace OHOS {
#define TEST_JSON "{\"errcode\":1}"
static constexpr int32_t MSG_BUFF_MAX_LEN = 100;
static void DoJsonUtilsFuzz(const char *data)
{
    char buffer[MSG_BUFF_MAX_LEN] = TEST_JSON;

    cJSON *object = cJSON_Parse(buffer);
    char name[MSG_BUFF_MAX_LEN];
    uint16_t ageU16 = 0;
    int32_t ageS32 = 0;
    int64_t ageS64 = 0;
    double weight = 0.0;
    bool healthy = false;

    GetJsonObjectStringItem(object, data, name, sizeof(name));
    GetJsonObjectNumber16Item(object, data, &ageU16);
    GetJsonObjectNumberItem(object, data, &ageS32);
    GetJsonObjectInt32Item(object, data, &ageS32);
    GetJsonObjectNumber64Item(object, data, &ageS64);
    GetJsonObjectSignedNumber64Item(object, data, &ageS64);
    GetJsonObjectDoubleItem(object, data, &weight);
    GetJsonObjectBoolItem(object, data, &healthy);

    AddStringToJsonObject(object, "name", data);
    int32_t age = *(reinterpret_cast<const int32_t *>(data));
    AddNumberToJsonObject(object, "age", age);
    cJSON_Delete(object);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }

    char buffer[OHOS::MSG_BUFF_MAX_LEN] = { 0 };
    if (memcpy_s(buffer, sizeof(buffer) - 1, data, size) != EOK) {
        return 0;
    }
    OHOS::DoJsonUtilsFuzz(buffer);
    return 0;
}
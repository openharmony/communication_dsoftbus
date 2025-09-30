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

#include "auth_apply_key_manager_mock.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_ohos_account_adapter.h"
#include "softbus_json_utils.h"

using namespace testing;
using namespace testing::ext;

#define MAP_KEY "mapKey"
#define VALUE_ACCOUNT_HASH "accountHash"
#define VALUE_APPLY_KEY "applyKey"
#define VALUE_USER_ID "userId"
#define VALUE_TIME "time"
#define USER_ID 100
#define D2D_TIME 100

namespace OHOS {
AuthApplyKeyManagerMock *AuthApplyKeyManagerMock::gMock;

AuthApplyKeyManagerMock::AuthApplyKeyManagerMock()
{
    gMock = this;
}

AuthApplyKeyManagerMock::~AuthApplyKeyManagerMock()
{
    gMock = nullptr;
}

AuthApplyKeyManagerMock &AuthApplyKeyManagerMock::GetMock()
{
    return *gMock;
}

int32_t LnnAsyncSaveDeviceDataPacked(const char *data, LnnDataType dataType)
{
    printf("LnnAsyncSaveDeviceDataPacked\n");
    return SOFTBUS_OK;
}

int32_t LnnRetrieveDeviceDataPacked(LnnDataType dataType, char **data, uint32_t *dataLen)
{
    printf("LnnRetrieveDeviceDataPacked\n");
    cJSON *jsonArray = cJSON_CreateArray();
    if (jsonArray == NULL) {
        printf("jsonArray is null\n");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        printf("create json fail\n");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!AddStringToJsonObject(obj, MAP_KEY, "nodeKey") || !AddStringToJsonObject(obj, VALUE_APPLY_KEY, "ApplyKey") ||
        !AddStringToJsonObject(obj, VALUE_ACCOUNT_HASH, "accountHash") ||
        !AddNumberToJsonObject(obj, VALUE_USER_ID, USER_ID) ||
        !AddNumber64ToJsonObject(obj, VALUE_TIME, D2D_TIME)) {
        printf("add json object fail\n");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON_AddItemToArray(jsonArray, obj);
    obj = cJSON_CreateObject();
    if (obj == NULL) {
        printf("create json fail\n");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!AddStringToJsonObject(obj, MAP_KEY, "nodeKey1") || !AddStringToJsonObject(obj, VALUE_APPLY_KEY, "ApplyKey1") ||
        !AddStringToJsonObject(obj, VALUE_ACCOUNT_HASH, "accountHash") ||
        !AddNumberToJsonObject(obj, VALUE_USER_ID, USER_ID) ||
        !AddNumber64ToJsonObject(obj, VALUE_TIME, D2D_TIME)) {
        printf("add json object fail\n");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON_AddItemToArray(jsonArray, obj);
    return SOFTBUS_OK;
}

void AuthApplyKeyManagerMockReg(void)
{
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->lnnAsyncSaveDeviceData = (LnnAsyncSaveDeviceDataFunc)LnnAsyncSaveDeviceDataPacked;
    pfnLnnEnhanceFuncList->lnnRetrieveDeviceData = (LnnRetrieveDeviceDataFunc)LnnRetrieveDeviceDataPacked;
}

} // namespace OHOS
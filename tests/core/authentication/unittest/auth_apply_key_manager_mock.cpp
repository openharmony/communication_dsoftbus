/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#define MAP_KEY              "mapKey"
#define MAP_KEY_1            "mapKey1"
#define VALUE_ACCOUNT_HASH   "accountHash"
#define VALUE_ACCOUNT_HASH_1 "accountHash1"
#define VALUE_APPLY_KEY      "applyKey"
#define VALUE_APPLY_KEY_1    "applyKey1"
#define VALUE_USER_ID        "userId"
#define VALUE_TIME           "time"
#define USER_ID              100
#define D2D_TIME             100

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

int32_t AuthApplyKeyManagerMock::LnnRetrieveDeviceDataInner(LnnDataType dataType, char **data, uint32_t *dataLen)
{
    cJSON *jsonArray = cJSON_CreateArray();
    if (jsonArray == NULL) {
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON *obj1 = cJSON_CreateObject();
    if (obj1 == NULL) {
        cJSON_Delete(jsonArray);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!AddStringToJsonObject(obj1, MAP_KEY, MAP_KEY) ||
        !AddStringToJsonObject(obj1, VALUE_APPLY_KEY, VALUE_APPLY_KEY) ||
        !AddStringToJsonObject(obj1, VALUE_ACCOUNT_HASH, VALUE_ACCOUNT_HASH) ||
        !AddNumberToJsonObject(obj1, VALUE_USER_ID, USER_ID) ||
        !AddNumber64ToJsonObject(obj1, VALUE_TIME, D2D_TIME)) {
        cJSON_Delete(jsonArray);
        cJSON_Delete(obj1);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON_AddItemToArray(jsonArray, obj1);
    cJSON *obj2 = cJSON_CreateObject();
    if (obj2 == NULL) {
        cJSON_Delete(jsonArray);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!AddStringToJsonObject(obj2, MAP_KEY, MAP_KEY_1) ||
        !AddStringToJsonObject(obj2, VALUE_APPLY_KEY, VALUE_APPLY_KEY_1) ||
        !AddStringToJsonObject(obj2, VALUE_ACCOUNT_HASH, VALUE_ACCOUNT_HASH_1) ||
        !AddNumberToJsonObject(obj2, VALUE_USER_ID, USER_ID) ||
        !AddNumber64ToJsonObject(obj2, VALUE_TIME, D2D_TIME)) {
        cJSON_Delete(jsonArray);
        cJSON_Delete(obj2);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON_AddItemToArray(jsonArray, obj2);
    char *msg = cJSON_PrintUnformatted(jsonArray);
    if (msg == nullptr) {
        cJSON_Delete(jsonArray);
        return SOFTBUS_CREATE_JSON_ERR;
    }
    cJSON_Delete(jsonArray);
    *data = msg;
    *dataLen = (uint32_t)strlen(msg);
    return SOFTBUS_OK;
}

extern "C" {
int32_t LnnAsyncSaveDeviceDataPacked(const char *data, LnnDataType dataType)
{
    printf("LnnAsyncSaveDeviceDataPacked\n");
    (void)data;
    (void)dataType;
    return SOFTBUS_OK;
}

int32_t GetActiveOsAccountIds(void)
{
    return AuthApplyKeyManagerMock::GetMock().GetActiveOsAccountIds();
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    return AuthApplyKeyManagerMock::GetMock().JudgeDeviceTypeAndGetOsAccountIds();
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return AuthApplyKeyManagerMock::GetMock().LnnRegisterEventHandler(event, handler);
}

int32_t LnnDeleteDeviceDataPacked(LnnDataType dataType)
{
    return AuthApplyKeyManagerMock::GetMock().LnnDeleteDeviceDataPacked(dataType);
}

void LnnDeinitDistributedLedger(void)
{
    AuthApplyKeyManagerMock::GetMock().LnnDeinitDistributedLedger();
}

bool AuthIsApplyKeyExpired(uint64_t time)
{
    return AuthApplyKeyManagerMock::GetMock().AuthIsApplyKeyExpired(time);
}

LnnEnhanceFuncList *LnnEnhanceFuncListGet(void)
{
    return AuthApplyKeyManagerMock::GetMock().LnnEnhanceFuncListGet();
}

int32_t LnnRetrieveDeviceDataPacked(LnnDataType dataType, char **data, uint32_t *dataLen)
{
    return AuthApplyKeyManagerMock::GetMock().LnnRetrieveDeviceDataPacked(dataType, data, dataLen);
}
} // extern "C"
} // namespace OHOS
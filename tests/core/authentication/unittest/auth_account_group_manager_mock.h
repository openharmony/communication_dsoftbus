/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUTH_APPLY_KEY_MANAGER_MOCK_H
#define AUTH_APPLY_KEY_MANAGER_MOCK_H

#include <gmock/gmock.h>

#include "auth_account_group_manager.h"
#include "device_auth.h"
#include "cJSON.h"

namespace OHOS {
class AuthAccountManagerMockInterface {
public:
    AuthAccountManagerMockInterface() {};
    virtual ~AuthAccountManagerMockInterface() {};
    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual void cJSON_Delete(cJSON *json) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
    virtual int32_t InitDeviceAuthService() = 0;
    virtual const LightAccountVerifier *GetLightAccountVerifierInstance() = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds() = 0;
};

class AuthAccountManagerMock : public AuthAccountManagerMockInterface {
public:
    AuthAccountManagerMock();
    ~AuthAccountManagerMock() override;
    MOCK_METHOD0(cJSON_CreateObject, cJSON *());
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *json, const char * const string, const char *value));
    MOCK_METHOD1(cJSON_Delete, void(cJSON *json));
    MOCK_METHOD1(cJSON_PrintUnformatted, char *(const cJSON *json));
    MOCK_METHOD0(InitDeviceAuthService, int32_t());
    MOCK_METHOD0(GetLightAccountVerifierInstance, const LightAccountVerifier *());
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t());

    static AuthAccountManagerMock& GetMock();

private:
    static AuthAccountManagerMock *gMock;
};
}; // namespace OHOS
#endif
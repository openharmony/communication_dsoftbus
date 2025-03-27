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

#ifndef AUTH_HICHAIN_ID_SERVICE_MOCK_H
#define AUTH_HICHAIN_ID_SERVICE_MOCK_H

#include <gmock/gmock.h>

#include "softbus_json_utils.h"
#include "device_auth.h"

namespace OHOS {
class AuthHichainIdServiceInterface {
public:
    AuthHichainIdServiceInterface() {};
    virtual ~AuthHichainIdServiceInterface() {};

    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;

    virtual int32_t InitDeviceAuthService() = 0;
    virtual const CredManager *GetCredMgrInstance() = 0;
    virtual const CredAuthManager *GetCredAuthInstance() = 0;
};

class AuthHichainIdServiceInterfaceMock : public AuthHichainIdServiceInterface {
public:
    AuthHichainIdServiceInterfaceMock();
    ~AuthHichainIdServiceInterfaceMock() override;

    MOCK_METHOD0(cJSON_CreateObject, cJSON * ());
    MOCK_METHOD3(AddStringToJsonObject, bool (cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int32_t));
    MOCK_METHOD1(cJSON_PrintUnformatted, char * (const cJSON *));

    MOCK_METHOD0(InitDeviceAuthService, int32_t ());
    MOCK_METHOD0(GetCredMgrInstance, const CredManager * ());
    MOCK_METHOD0(GetCredAuthInstance, const CredAuthManager * ());
};

} // namespace OHOS
#endif // AUTH_HICHAIN_ID_SERVICE_MOCK_H

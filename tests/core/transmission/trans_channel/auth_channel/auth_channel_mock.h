/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_CHANNEL_MOCK_H
#define AUTH_CHANNEL_MOCK_H

#include <gmock/gmock.h>

#include "lnn_net_builder.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"

namespace OHOS {
class AuthChannelInterface {
public:
    AuthChannelInterface() {};
    virtual ~AuthChannelInterface() {};
    virtual int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num) = 0;
    virtual int32_t GenerateRandomStr(char *str, uint32_t size) = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
};

class AuthChannelInterfaceMock : public AuthChannelInterface {
public:
    AuthChannelInterfaceMock();
    ~AuthChannelInterfaceMock() override;
    MOCK_METHOD2(LnnServerJoinExt, int32_t (ConnectionAddr *, LnnServerJoinExtCallBack *));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int32_t));
    MOCK_METHOD2(GenerateRandomStr, int32_t (char *, uint32_t));
    MOCK_METHOD3(AddStringToJsonObject, bool (cJSON *json, const char * const string, const char *value));
    MOCK_METHOD1(cJSON_PrintUnformatted, char * (const cJSON *json));
};
} // namespace OHOS
#endif // AUTH_CHANNEL_MOCK_H

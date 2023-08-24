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

#ifndef WIFI_DIRECT_MOCK_H
#define WIFI_DIRECT_MOCK_H

#include <gmock/gmock.h>
#include "softbus_json_utils.h"

namespace OHOS {
class WifiDirectInterface {
public:
    WifiDirectInterface() {};
    virtual ~WifiDirectInterface() {};
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int num) = 0;
    virtual bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value) = 0;
};

class WifiDirectMock : public WifiDirectInterface {
public:
    WifiDirectMock();
    ~WifiDirectMock() override;

    MOCK_METHOD3(AddStringToJsonObject, bool (cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int));
    MOCK_METHOD3(AddBoolToJsonObject, bool (cJSON *, const char * const, bool));
};
}; // namespace OHOS

#endif // WIFI_DIRECT_MOCK_H

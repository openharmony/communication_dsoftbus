/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CONNECTION_BR_MOCK_H
#define CONNECTION_BR_MOCK_H

#include <gmock/gmock.h>
#include "cJSON.h"

#include "softbus_adapter_thread.h"
#include "softbus_config_type.h"
#include "softbus_def.h"
#include "softbus_adapter_bt_common.h"

namespace OHOS {
class ConnectionBrInterface {
public:
    ConnectionBrInterface() {};
    virtual ~ConnectionBrInterface() {};
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual bool AddNumber64ToJsonObject(cJSON *json, const char * const string, int64_t num) = 0;
    virtual cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
};

class ConnectionBrInterfaceMock : public ConnectionBrInterface {
public:
    ConnectionBrInterfaceMock();
    ~ConnectionBrInterfaceMock() override;
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool (const cJSON *, const char * const, int32_t *));
    MOCK_METHOD3(GetJsonObjectNumber64Item, bool (const cJSON *, const char * const, int64_t *));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int));
    MOCK_METHOD3(AddNumber64ToJsonObject, bool (cJSON *, const char * const, int64_t));
    MOCK_METHOD2(cJSON_ParseWithLength, cJSON* (const char *, size_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool (const cJSON *, const char * const, int32_t *));
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t (SoftBusBtAddr *));
};
} // namespace OHOS
#endif // CONNECTION_BR_MOCK_H
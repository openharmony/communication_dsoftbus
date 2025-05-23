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

#ifndef TRANS_TCP_DIRECT_JSON_TEST_MOCK_H
#define TRANS_TCP_DIRECT_JSON_TEST_MOCK_H

#include <gmock/gmock.h>

#include "trans_tcp_direct_json.h"

namespace OHOS {
class TransTcpDirectJsonInterface {
public:
    TransTcpDirectJsonInterface() {};
    virtual ~TransTcpDirectJsonInterface() {};
    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target) = 0;
};

class TransTcpDirectJsonInterfaceMock : public TransTcpDirectJsonInterface {
public:
    TransTcpDirectJsonInterfaceMock();
    ~TransTcpDirectJsonInterfaceMock() override;
    MOCK_METHOD0(cJSON_CreateObject, cJSON * ());
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int32_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool(const cJSON *, const char * const, int32_t *));
    MOCK_METHOD4(
        GetJsonObjectStringItem, bool(const cJSON *, const char * const, char *, uint32_t));
    MOCK_METHOD3(GetJsonObjectInt32Item, bool(const cJSON *, const char * const, int32_t *));
};

extern "C" {
    void cJSON_Delete(cJSON *json);
}
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_JSON_TEST_MOCK_H


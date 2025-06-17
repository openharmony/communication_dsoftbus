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

#ifndef GENERAL_NEGOTIATION_MOCK_H
#define GENERAL_NEGOTIATION_MOCK_H

#include <gmock/gmock.h>

#include "softbus_json_utils.h"
#include "conn_log.h"

namespace OHOS {
class GeneralNegotiationInterface {
public:
    GeneralNegotiationInterface() {};
    virtual ~GeneralNegotiationInterface() {};
    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const str, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const str, int32_t num) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
    virtual cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const str, int32_t *target) = 0;
    virtual bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const str, int32_t *target) = 0;
};

class GeneralNegotiationInterfaceMock : public GeneralNegotiationInterface {
public:
    GeneralNegotiationInterfaceMock();
    ~GeneralNegotiationInterfaceMock() override;
    MOCK_METHOD0(cJSON_CreateObject, cJSON * ());
    MOCK_METHOD3(AddStringToJsonObject, bool (cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool (cJSON *, const char * const, int32_t));
    MOCK_METHOD1(cJSON_PrintUnformatted, char *(const cJSON *));
    MOCK_METHOD2(cJSON_ParseWithLength, cJSON *(const char *value, size_t buffer_length));
    MOCK_METHOD4(GetJsonObjectStringItem, bool (const cJSON *, const char * const, char *, uint32_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool (const cJSON *, const char * const, int32_t *));
    MOCK_METHOD3(GetJsonObjectSignedNumberItem, bool(const cJSON *json, const char * const string, int32_t *target));
};
} // namespace OHOS
#endif // GENERAL_NEGOTIATION_MOCK_H
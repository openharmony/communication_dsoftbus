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

#include "general_negotiation_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_generalNegotiationInterface;
GeneralNegotiationInterfaceMock::GeneralNegotiationInterfaceMock()
{
    g_generalNegotiationInterface = reinterpret_cast<void *>(this);
}

GeneralNegotiationInterfaceMock::~GeneralNegotiationInterfaceMock()
{
    g_generalNegotiationInterface = nullptr;
}

static GeneralNegotiationInterface *GetGeneralNegotiationInterface()
{
    return reinterpret_cast<GeneralNegotiationInterface *>(g_generalNegotiationInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetGeneralNegotiationInterface()->cJSON_CreateObject();
}

bool AddStringToJsonObject(cJSON *json, const char * const str, const char *value)
{
    return GetGeneralNegotiationInterface()->AddStringToJsonObject(json, str, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const str, int32_t num)
{
    return GetGeneralNegotiationInterface()->AddNumberToJsonObject(json, str, num);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetGeneralNegotiationInterface()->cJSON_PrintUnformatted(json);
}

cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length)
{
    return GetGeneralNegotiationInterface()->cJSON_ParseWithLength(value, buffer_length);
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const str, char *target, uint32_t targetLen)
{
    return GetGeneralNegotiationInterface()->GetJsonObjectStringItem(json, str, target, targetLen);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const str, int32_t *target)
{
    return GetGeneralNegotiationInterface()->GetJsonObjectNumberItem(json, str, target);
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const str, int32_t *target)
{
    return GetGeneralNegotiationInterface()->GetJsonObjectSignedNumberItem(json, str, target);
}
}
}
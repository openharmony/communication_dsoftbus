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

#include "softbus_message_open_channel_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_messageOpenChannelInterface;
SoftbusMessageOpenChannelInterfaceMock::SoftbusMessageOpenChannelInterfaceMock()
{
    g_messageOpenChannelInterface = reinterpret_cast<void *>(this);
}

SoftbusMessageOpenChannelInterfaceMock::~SoftbusMessageOpenChannelInterfaceMock()
{
    g_messageOpenChannelInterface = nullptr;
}

static SoftbusMessageOpenChannelInterfaceMock *GetMessageOpenChannelInterface()
{
    return reinterpret_cast<SoftbusMessageOpenChannelInterfaceMock *>(g_messageOpenChannelInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetMessageOpenChannelInterface()->cJSON_CreateObject();
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetMessageOpenChannelInterface()->cJSON_PrintUnformatted(json);
}

bool AddNumber16ToJsonObject(cJSON *json, const char *const string, uint16_t num)
{
    return GetMessageOpenChannelInterface()->AddNumber16ToJsonObject(json, string, num);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetMessageOpenChannelInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char *const string, int32_t num)
{
    return GetMessageOpenChannelInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    return GetMessageOpenChannelInterface()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetMessageOpenChannelInterface()->GetJsonObjectNumberItem(json, string, target);
}

bool GetJsonObjectStringItem(
    const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return GetMessageOpenChannelInterface()->GetJsonObjectStringItem(json, string, target, targetLen);
}

bool GetJsonObjectNumber64Item(const cJSON *json, const char * const string, int64_t *target)
{
    return GetMessageOpenChannelInterface()->GetJsonObjectNumber64Item(json, string, target);
}

bool GetJsonObjectInt32Item(const cJSON *json, const char * const string, int32_t *target)
{
    return GetMessageOpenChannelInterface()->GetJsonObjectInt32Item(json, string, target);
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const string, uint16_t *target)
{
    return GetMessageOpenChannelInterface()->GetJsonObjectNumber16Item(json, string, target);
}

void cJSON_Delete(cJSON *json){ }
}
}

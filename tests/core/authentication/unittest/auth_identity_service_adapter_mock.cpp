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

#include "auth_identity_service_adapter_mock.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;
void *g_identityServiceAdapterInterface;
AuthIdentityServiceAdapterInterfaceMock::AuthIdentityServiceAdapterInterfaceMock()
{
    g_identityServiceAdapterInterface = reinterpret_cast<void *>(this);
}

AuthIdentityServiceAdapterInterfaceMock::~AuthIdentityServiceAdapterInterfaceMock()
{
    g_identityServiceAdapterInterface = nullptr;
}

static AuthIdentityServiceAdapterInterface *GetInterfaceMock()
{
    return reinterpret_cast<AuthIdentityServiceAdapterInterfaceMock *>(g_identityServiceAdapterInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetInterfaceMock()->cJSON_CreateObject();
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetInterfaceMock()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetInterfaceMock()->AddNumberToJsonObject(json, string, num);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetInterfaceMock()->cJSON_PrintUnformatted(json);
}

int32_t InitDeviceAuthService()
{
    return GetInterfaceMock()->InitDeviceAuthService();
}

const CredManager *GetCredMgrInstance()
{
    return GetInterfaceMock()->GetCredMgrInstance();
}

const CredAuthManager *GetCredAuthInstance()
{
    return GetInterfaceMock()->GetCredAuthInstance();
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetInterfaceMock()->LnnGetLocalStrInfo(key, info, len);
}

int32_t GetActiveOsAccountIds(void)
{
    return GetInterfaceMock()->GetActiveOsAccountIds();
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId)
{
    return GetInterfaceMock()->LnnDeleteSpecificTrustedDevInfo(udid, localUserId);
}

void LnnHbOnTrustedRelationReduced(void)
{
    return GetInterfaceMock()->LnnHbOnTrustedRelationReduced();
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetInterfaceMock()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetInterfaceMock()->LnnInsertSpecificTrustedDevInfo(udid);
}

void LnnHbOnTrustedRelationIncreased(int32_t groupType)
{
    return GetInterfaceMock()->LnnHbOnTrustedRelationIncreased(groupType);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetInterfaceMock()->LnnGetLocalByteInfo(key, info, len);
}

void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    return GetInterfaceMock()->LnnUpdateHeartbeatInfo(type);
}

const CredManager *IdServiceGetCredMgrInstance()
{
    return GetInterfaceMock()->IdServiceGetCredMgrInstance();
}

int32_t IdServiceQueryCredentialByUdid(int32_t userId, const char *udid, char **credList)
{
    return GetInterfaceMock()->IdServiceQueryCredentialByUdid(userId, udid, credList);
}

void GetSoftbusHichainAuthErrorCode(uint32_t hichainErrCode, uint32_t *softbusErrCode)
{
    return GetInterfaceMock()->GetSoftbusHichainAuthErrorCode(hichainErrCode, softbusErrCode);
}

cJSON *CreateJsonObjectFromString(const char *jsonStr)
{
    return GetInterfaceMock()->CreateJsonObjectFromString(jsonStr);
}

int32_t GetArrayItemNum(const cJSON *jsonObj)
{
    return GetInterfaceMock()->GetArrayItemNum(jsonObj);
}

void cJSON_Delete(cJSON *item)
{
    if (item != nullptr) {
        SoftBusFree(item);
    }
}
} // extern "C"
} // namespace OHOS

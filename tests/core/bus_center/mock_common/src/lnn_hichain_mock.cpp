/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_hichain_mock.h"

#include "auth_interface.h"
#include "auth_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_json.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
const int32_t GRUOP_NUM1 = 10;
const int32_t GRUOP_NUM2 = 12;
const int32_t GRUOP_NUM3 = 100;
bool g_isFlage = false;
bool g_isReturnDeviceNum = false;
bool g_isReturnTrue = false;
const int32_t GROUP_TYPE_POINT_TO_POINT = 256;
const int32_t GROUP_VISIBILITY_INVALID = 26;
void *g_hichainInterface;

LnnHichainInterfaceMock::LnnHichainInterfaceMock()
{
    AUTH_LOGI(AUTH_TEST, "construction");
    g_hichainInterface = reinterpret_cast<void *>(this);
}

LnnHichainInterfaceMock::~LnnHichainInterfaceMock()
{
    AUTH_LOGI(AUTH_TEST, "delete");
    g_hichainInterface = nullptr;
}

static LnnHichainInterface *GetHichainInterface()
{
    return reinterpret_cast<LnnHichainInterfaceMock *>(g_hichainInterface);
}

extern "C" {
int32_t InitDeviceAuthService(void)
{
    return GetHichainInterface()->InitDeviceAuthService();
}

void DestroyDeviceAuthService(void)
{
    return GetHichainInterface()->DestroyDeviceAuthService();
}

const GroupAuthManager *GetGaInstance(void)
{
    return GetHichainInterface()->GetGaInstance();
}

const DeviceGroupManager *GetGmInstance(void)
{
    AUTH_LOGI(AUTH_TEST, "GetGmInstance");
    return GetHichainInterface()->GetGmInstance();
}

void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo)
{
    return GetHichainInterface()->GetLnnTriggerInfo(triggerInfo);
}
}

int32_t LnnHichainInterfaceMock::ActionOfProcessData(
    int64_t authSeq, const uint8_t *data, uint32_t len, const DeviceAuthCallback *gaCallback)
{
    (void)authSeq;
    (void)data;
    (void)len;
    g_devAuthCb.onTransmit = gaCallback->onTransmit;
    g_devAuthCb.onSessionKeyReturned = gaCallback->onSessionKeyReturned;
    g_devAuthCb.onFinish = gaCallback->onFinish;
    g_devAuthCb.onError = gaCallback->onError;
    g_devAuthCb.onRequest = gaCallback->onRequest;
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::InvokeAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::AuthDeviceConnSend(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    AUTH_LOGI(AUTH_TEST, "AuthDeviceConnSend");
    (void)SoftBusCondSignal(&LnnHichainInterfaceMock::cond);
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::InvokeDataChangeListener(const char *appId, const DataChangeListener *listener)
{
    if (appId == nullptr || listener == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    LnnHichainInterfaceMock::g_datachangelistener.emplace(appId, listener);
    return SOFTBUS_OK;
}

int32_t LnnHichainInterfaceMock::InvokeGetJoinedGroups1(int32_t osAccountId, const char *appId, int32_t groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    (void)osAccountId;
    (void)appId;
    *groupNum = 1;

    if (groupType == AUTH_IDENTICAL_ACCOUNT_GROUP) {
        *groupNum = GRUOP_NUM1;
    }
    if (groupType == AUTH_PEER_TO_PEER_GROUP) {
        *groupNum = GRUOP_NUM2;
    }
    *returnGroupVec = reinterpret_cast<char *>(SoftBusCalloc(*groupNum));
    if (*returnGroupVec == NULL) {
        return HC_ERR_INVALID_PARAMS;
    }
    return HC_SUCCESS;
}

int32_t LnnHichainInterfaceMock::InvokeGetJoinedGroups2(int32_t osAccountId, const char *appId, int32_t groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupType;
    (void)returnGroupVec;
    *groupNum = GRUOP_NUM3;

    return HC_ERR_INVALID_PARAMS;
}

int32_t LnnHichainInterfaceMock::InvokeGetJoinedGroups3(int32_t osAccountId, const char *appId, int32_t groupType,
    char **returnGroupVec, uint32_t *groupNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupType;
    (void)returnGroupVec;
    *groupNum = 0;

    return HC_SUCCESS;
}
int32_t LnnHichainInterfaceMock::ActionofunRegDataChangeListener(const char *appId)
{
    (void)appId;
    LnnHichainInterfaceMock::g_datachangelistener.clear();
    return SOFTBUS_OK;
}
int32_t LnnHichainInterfaceMock::getRelatedGroups(
    int32_t accountId, const char *auth_appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum)
{
    (void)accountId;
    (void)auth_appId;
    (void)groupId;
    AUTH_LOGI(AUTH_TEST, "getRelatedGroups test");
    if (!g_isFlage) {
        AUTH_LOGI(AUTH_TEST, "getRelatedGroups test return false");
        g_isFlage = true;
        return SOFTBUS_AUTH_GET_GROUP_TYPE_FAIL;
    }
    char data = 'A';
    if (g_isReturnDeviceNum) {
        char* testChar = &data;
        *deviceNum = strlen(testChar) + 1;
        *returnDevInfoVec = testChar;
        return SOFTBUS_OK;
    }
    g_isReturnDeviceNum = true;
    return SOFTBUS_OK;
}
int32_t LnnHichainInterfaceMock::getRelatedGroups1(
    int32_t accountId, const char *auth_appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum)
{
    (void)accountId;
    (void)auth_appId;
    (void)groupId;
    *deviceNum = 1;
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        AUTH_LOGI(AUTH_TEST, "create jsonObject err");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!JSON_AddStringToObject(obj, "groupName", "mygroup<256>E469") ||
        !JSON_AddStringToObject(obj, "groupId", "1D77EBFF0349B27EED57014DD7B2449A") ||
        !JSON_AddStringToObject(obj, "groupOwner", "com.hhhs.secueity") ||
        !JSON_AddInt32ToObject(obj, "groupType", GROUP_TYPE_POINT_TO_POINT) ||
        !JSON_AddInt32ToObject(obj, "groupVisibility", GROUP_VISIBILITY_INVALID)) {
        JSON_Delete(obj);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    char* jsons = JSON_PrintUnformatted(obj);
    *returnDevInfoVec = jsons;

    AUTH_LOGI(AUTH_TEST, "getRelatedGroups1 test");
    JSON_Delete(obj);
    return SOFTBUS_OK;
}
int32_t LnnHichainInterfaceMock::getTrustedDevices(
    int32_t osAccountId, const char *appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupId;
    *deviceNum = 1;
    JsonObj *obj = JSON_CreateObject();
    if (obj == NULL) {
        AUTH_LOGI(AUTH_TEST, "create jsonObject err");
        return SOFTBUS_CREATE_JSON_ERR;
    }
    if (!JSON_AddStringToObject(obj, "authId", "ABCDEDF00ABCDE0021DD55ACFF")) {
        JSON_Delete(obj);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    char* jsons = JSON_PrintUnformatted(obj);
    *returnDevInfoVec = jsons;
    if (!g_isReturnTrue) {
        g_isReturnTrue = true;
        JSON_Delete(obj);
        return SOFTBUS_PARSE_JSON_ERR;
    }
    JSON_Delete(obj);
    return SOFTBUS_OK;
}

int32_t LnnHichainInterfaceMock::getTrustedDevices1(
    int32_t osAccountId, const char *appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum)
{
    (void)osAccountId;
    (void)appId;
    (void)groupId;
    
    char jsonsStr[] = "{\"groupId\":\"1111\", \"groupType\":1}";
    char* data = jsonsStr;
    *returnDevInfoVec = data;
    AUTH_LOGI(AUTH_TEST, "returnDevInfoVec is invalid");
    if (g_isReturnDeviceNum) {
        g_isReturnDeviceNum = false;
        return SOFTBUS_OK;
    }
    *deviceNum = 1;
    return SOFTBUS_OK;
}

void LnnHichainInterfaceMock::destroyInfo(char **returnDevInfoVec)
{
    (void)returnDevInfoVec;
    AUTH_LOGI(AUTH_TEST, "destroyInfo test");
}
} // namespace OHOS
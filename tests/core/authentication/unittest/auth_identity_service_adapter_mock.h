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

#ifndef AUTH_IDENTITY_SERVICE_ADPATER_MOCK_H
#define AUTH_IDENTITY_SERVICE_ADPATER_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_info_key_struct.h"
#include "device_auth.h"
#include "lnn_heartbeat_utils.h"
#include "softbus_json_utils.h"
namespace OHOS {
class AuthIdentityServiceAdapterInterface {
public:
    AuthIdentityServiceAdapterInterface() {};
    virtual ~AuthIdentityServiceAdapterInterface() {};

    virtual cJSON *cJSON_CreateObject() = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num) = 0;
    virtual char *cJSON_PrintUnformatted(const cJSON *json) = 0;
    virtual int32_t InitDeviceAuthService() = 0;
    virtual const CredManager *GetCredMgrInstance() = 0;
    virtual const CredAuthManager *GetCredAuthInstance() = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId) = 0;
    virtual void LnnHbOnTrustedRelationReduced(void) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnInsertSpecificTrustedDevInfo(const char *udid) = 0;
    virtual void LnnHbOnTrustedRelationIncreased(int32_t groupType) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type);
    virtual const CredManager *IdServiceGetCredMgrInstance() = 0;
    virtual int32_t IdServiceQueryCredentialByUdid(int32_t userId, const char *udid, char **credList) = 0;
    virtual void GetSoftbusHichainAuthErrorCode(uint32_t hichainErrCode, uint32_t *softbusErrCode) = 0;
    virtual cJSON *CreateJsonObjectFromString(const char *jsonStr) = 0;
    virtual int GetArrayItemNum(const cJSON *jsonObj) = 0;
    virtual void cJSON_Delete(cJSON *item) = 0;
    virtual int32_t LnnJudgeDeviceTypeAndGetOsAccountInfo(uint8_t *accountHash, uint32_t len) = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds(void) = 0;
};

class AuthIdentityServiceAdapterInterfaceMock : public AuthIdentityServiceAdapterInterface {
public:
    AuthIdentityServiceAdapterInterfaceMock();
    ~AuthIdentityServiceAdapterInterfaceMock() override;

    MOCK_METHOD0(cJSON_CreateObject, cJSON *());
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int32_t));
    MOCK_METHOD1(cJSON_PrintUnformatted, char *(const cJSON *));
    MOCK_METHOD0(InitDeviceAuthService, int32_t());
    MOCK_METHOD0(GetCredMgrInstance, const CredManager *());
    MOCK_METHOD0(GetCredAuthInstance, const CredAuthManager *());
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t());
    MOCK_METHOD2(LnnDeleteSpecificTrustedDevInfo, int32_t(const char *, int32_t));
    MOCK_METHOD0(LnnHbOnTrustedRelationReduced, void());
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD1(LnnInsertSpecificTrustedDevInfo, int32_t(const char *));
    MOCK_METHOD1(LnnHbOnTrustedRelationIncreased, void(int32_t));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD1(LnnUpdateHeartbeatInfo, void(LnnHeartbeatUpdateInfoType));
    MOCK_METHOD0(IdServiceGetCredMgrInstance, const CredManager *());
    MOCK_METHOD3(IdServiceQueryCredentialByUdid, int32_t(int32_t, const char *, char **));
    MOCK_METHOD2(GetSoftbusHichainAuthErrorCode, void(uint32_t, uint32_t *));
    MOCK_METHOD1(CreateJsonObjectFromString, cJSON *(const char *));
    MOCK_METHOD1(GetArrayItemNum, int(const cJSON *));
    MOCK_METHOD1(cJSON_Delete, void(cJSON *));
    MOCK_METHOD2(LnnJudgeDeviceTypeAndGetOsAccountInfo, int32_t(uint8_t *, uint32_t));
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t(void));
};
} // namespace OHOS
#endif // AUTH_IDENTITY_SERVICE_ADPATER_MOCK_H

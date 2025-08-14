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

#ifndef AUTH_APPLY_KEY_PROCESS_MOCK_H
#define AUTH_APPLY_KEY_PROCESS_MOCK_H

#include <cstdbool>
#include <cstdint>
#include <gmock/gmock.h>

#include "auth_apply_key_struct.h"
#include "auth_common_struct.h"
#include "bus_center_info_key_struct.h"
#include "cJSON.h"
#include "device_auth.h"
#include "lnn_async_callback_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_interface_struct.h"

namespace OHOS {
class AuthApplyKeyProcessInterface {
public:
    AuthApplyKeyProcessInterface() {};
    virtual ~AuthApplyKeyProcessInterface() { };
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int num) = 0;
    virtual uint32_t ConnGetHeadSize(void) = 0;
    virtual uint32_t GetAuthDataSize(uint32_t len) = 0;
    virtual int32_t PackAuthData(const AuthDataHead *head, const uint8_t *data, uint8_t *buf, uint32_t size) = 0;
    virtual int32_t GetApplyKeyByBusinessInfo(
        const RequestBusinessInfo *info, uint8_t *uk, uint32_t ukLen, char *accountHash, uint32_t accountHashLen) = 0;
    virtual const uint8_t *UnpackAuthData(const uint8_t *data, uint32_t len, AuthDataHead *head) = 0;
    virtual cJSON *cJSON_ParseWithLength(const char *string, size_t length) = 0;
    virtual bool GetJsonObjectStringItem(
        const cJSON *json, const char * const string, char *target, uint32_t targetLen) = 0;
    virtual bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target) = 0;
    virtual int32_t InitDeviceAuthService() = 0;
    virtual const LightAccountVerifier *GetLightAccountVerifierInstance(void) = 0;
    virtual int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback) = 0;
    virtual const char *GetAuthSideStr(bool isServer) = 0;
    virtual int32_t AuthInsertApplyKey(
        const RequestBusinessInfo *info, const uint8_t *uk, uint32_t ukLen, uint64_t time, char *accountHash) = 0;
    virtual int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data) = 0;
};

class AuthApplyKeyProcessInterfaceMock : public AuthApplyKeyProcessInterface {
public:
    AuthApplyKeyProcessInterfaceMock();
    ~AuthApplyKeyProcessInterfaceMock() override;

    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey, uint8_t *, uint32_t));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int));
    MOCK_METHOD0(ConnGetHeadSize, uint32_t(void));
    MOCK_METHOD1(GetAuthDataSize, uint32_t(uint32_t));
    MOCK_METHOD4(PackAuthData, int32_t(const AuthDataHead *, const uint8_t *, uint8_t *, uint32_t));
    MOCK_METHOD5(
        GetApplyKeyByBusinessInfo, int32_t(const RequestBusinessInfo *, uint8_t *, uint32_t, char *, uint32_t));
    MOCK_METHOD3(UnpackAuthData, const uint8_t *(const uint8_t *, uint32_t, AuthDataHead *));
    MOCK_METHOD2(cJSON_ParseWithLength, cJSON *(const char *, size_t));
    MOCK_METHOD4(GetJsonObjectStringItem, bool(const cJSON *, const char * const, char *, uint32_t));
    MOCK_METHOD3(GetJsonObjectNumberItem, bool(const cJSON *, const char * const, int32_t *));
    MOCK_METHOD0(InitDeviceAuthService, int32_t());
    MOCK_METHOD0(GetLightAccountVerifierInstance, const LightAccountVerifier *(void));
    MOCK_METHOD2(ConnSetConnectCallback, int32_t(ConnModule, const ConnectCallback *));
    MOCK_METHOD1(GetAuthSideStr, const char *(bool));
    MOCK_METHOD5(AuthInsertApplyKey, int32_t(const RequestBusinessInfo *, const uint8_t *, uint32_t, uint64_t, char *));
    MOCK_METHOD2(ConnPostBytes, int32_t(uint32_t, ConnPostData *));
};

} // namespace OHOS
#endif // AUTH_APPLY_KEY_PROCESS_MOCK_H
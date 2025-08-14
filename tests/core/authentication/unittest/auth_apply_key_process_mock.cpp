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

#include "auth_apply_key_process_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_applyKeyProcMockInterface;
AuthApplyKeyProcessInterfaceMock::AuthApplyKeyProcessInterfaceMock()
{
    g_applyKeyProcMockInterface = reinterpret_cast<void *>(this);
}

AuthApplyKeyProcessInterfaceMock::~AuthApplyKeyProcessInterfaceMock()
{
    g_applyKeyProcMockInterface = nullptr;
}

static AuthApplyKeyProcessInterface *AuthApplyKeyProcessInterfaceMock()
{
    return reinterpret_cast<AuthApplyKeyProcessInterface *>(g_applyKeyProcMockInterface);
}

extern "C" {
int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return AuthApplyKeyProcessInterfaceMock()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return AuthApplyKeyProcessInterfaceMock()->LnnGetLocalStrInfo(key, info, len);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return AuthApplyKeyProcessInterfaceMock()->SoftBusGenerateStrHash(str, len, hash);
}


int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return AuthApplyKeyProcessInterfaceMock()->LnnGetLocalByteInfo(key, info, len);
}

bool AddStringToJsonObject(cJSON *json, const char *const string, const char *value)
{
    return AuthApplyKeyProcessInterfaceMock()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int num)
{
    return  AuthApplyKeyProcessInterfaceMock()->AddNumberToJsonObject(json, string, num);
}

uint32_t ConnGetHeadSize(void)
{
    return AuthApplyKeyProcessInterfaceMock()->ConnGetHeadSize();
}

uint32_t GetAuthDataSize(uint32_t len)
{
    return AuthApplyKeyProcessInterfaceMock()->GetAuthDataSize(len);
}

int32_t PackAuthData(const AuthDataHead *head, const uint8_t *data,
    uint8_t *buf, uint32_t size)
{
    return AuthApplyKeyProcessInterfaceMock()->PackAuthData(head, data, buf, size);
}

int64_t GenSeq(bool isServer)
{
    return 0;
}

int32_t GetApplyKeyByBusinessInfo(
    const RequestBusinessInfo *info, uint8_t *uk, uint32_t ukLen, char *accountHash, uint32_t accountHashLen)
{
    return AuthApplyKeyProcessInterfaceMock()->GetApplyKeyByBusinessInfo(info, uk, ukLen, accountHash, accountHashLen);
}

const uint8_t *UnpackAuthData(const uint8_t *data, uint32_t len, AuthDataHead *head)
{
    return AuthApplyKeyProcessInterfaceMock()->UnpackAuthData(data, len, head);
}

void cJSON_Delete(cJSON* item)
{
    (void)item;
    return;
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return AuthApplyKeyProcessInterfaceMock()->GetJsonObjectStringItem(json, string, target, targetLen);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return AuthApplyKeyProcessInterfaceMock()->GetJsonObjectNumberItem(json, string, target);
}

int32_t InitDeviceAuthService()
{
    return AuthApplyKeyProcessInterfaceMock()->InitDeviceAuthService();
}

const LightAccountVerifier *GetLightAccountVerifierInstance(void)
{
    return AuthApplyKeyProcessInterfaceMock()->GetLightAccountVerifierInstance();
}

int32_t GetActiveOsAccountIds(void)
{
    return 0;
}

void GetSoftbusHichainAuthErrorCode(uint32_t hichainErrCode, uint32_t *softbusErrCode)
{
    *softbusErrCode = hichainErrCode;
    return;
}

int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback)
{
    return AuthApplyKeyProcessInterfaceMock()->ConnSetConnectCallback(moduleId, callback);
}

int32_t AuthInsertApplyKey(const RequestBusinessInfo *info, const uint8_t *uk, uint32_t ukLen,
    uint64_t time, char *accountHash)
{
    return AuthApplyKeyProcessInterfaceMock()->AuthInsertApplyKey(info, uk, ukLen, time, accountHash);
}

const char *GetAuthSideStr(bool isServer)
{
    return AuthApplyKeyProcessInterfaceMock()->GetAuthSideStr(isServer);
}

int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data)
{
    return AuthApplyKeyProcessInterfaceMock()->ConnPostBytes(connectionId, data);
}

} // extern "C"
} // namespace OHOS
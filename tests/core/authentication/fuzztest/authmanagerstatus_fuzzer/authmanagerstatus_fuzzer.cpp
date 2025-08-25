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

#include "authmanagerstatus_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "auth_manager.c"
#include "auth_manager.h"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

using namespace std;

#define UDID_HASH_LEN   32
#define AUTH_TYPE_MIN   AUTH_LINK_TYPE_WIFI
#define AUTH_TYPE_MAX   AUTH_LINK_TYPE_MAX
#define NORMAL_TYPE_MIN NORMALIZED_NOT_SUPPORT
#define NORMAL_TYPE_MAX NORMALIZED_SUPPORT

namespace {

class TestEnv {
public:
    TestEnv()
    {
        AuthCommonInit();
        isInited_ = true;
    }
    ~TestEnv()
    {
        AuthCommonDeinit();
        LnnDeinitNetBuilder();
        isInited_ = false;
    }

    bool IsEnvInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_ = false;
};
} // namespace

namespace OHOS {
static void ProcessFuzzConnInfo(FuzzedDataProvider &provider, AuthSessionInfo *info)
{
    string addr;
    switch (info->connInfo.type) {
        case AUTH_LINK_TYPE_WIFI:
            addr = provider.ConsumeRandomLengthString(IP_LEN);
            if (strcpy_s(info->connInfo.info.ipInfo.ip, IP_LEN, addr.c_str()) != EOK) {
                break;
            }
            break;
        case AUTH_LINK_TYPE_BR:
            addr = provider.ConsumeRandomLengthString(MAC_LEN);
            if (strcpy_s(info->connInfo.info.brInfo.brMac, MAC_LEN, addr.c_str()) != EOK) {
                break;
            }
            break;
        case AUTH_LINK_TYPE_BLE:
            addr = provider.ConsumeRandomLengthString(MAC_LEN);
            if (strcpy_s(info->connInfo.info.bleInfo.bleMac, MAC_LEN, addr.c_str()) != EOK) {
                break;
            }
            break;
        case AUTH_LINK_TYPE_P2P:
        case AUTH_LINK_TYPE_ENHANCED_P2P:
        case AUTH_LINK_TYPE_RAW_ENHANCED_P2P:
        case AUTH_LINK_TYPE_NORMALIZED:
        case AUTH_LINK_TYPE_SESSION:
        case AUTH_LINK_TYPE_SESSION_KEY:
        case AUTH_LINK_TYPE_SLE:
        case AUTH_LINK_TYPE_USB:
            addr = provider.ConsumeRandomLengthString(IP_LEN);
            if (strcpy_s(info->connInfo.info.ipInfo.ip, IP_LEN, addr.c_str()) != EOK) {
                break;
            }
            break;
        default:
            break;
    }
}

static void OnVerifyFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

static void OnVerifyPassed(uint32_t requestId, AuthHandle authHandle, const NodeInfo *info)
{
    (void)requestId;
    (void)authHandle;
    (void)info;
}

static void ProcAuthRequest(FuzzedDataProvider &provider, AuthHandle *authHandle, AuthSessionInfo *info)
{
    AuthRequest request;
    (void)memset_s(&request, sizeof(AuthRequest), 0, sizeof(AuthRequest));
    AuthVerifyCallback verifyCb = {
        .onVerifyFailed = OnVerifyFailed,
        .onVerifyPassed = OnVerifyPassed,
    };
    request.authId = authHandle->authId;
    request.verifyCb = verifyCb;
    request.connInfo = info->connInfo;
    request.requestId = AuthGenRequestId();
    uint8_t udidHash[UDID_HASH_LEN] = { 0 };
    info->requestId = request.requestId;
    GenerateUdidHash(info->udid, udidHash);
    AddAuthRequest(&request);
    BleDisconnectDelay(info->connId, 0);
    AuthNotifyAuthPassed(authHandle->authId, info);
    AuthManagerSetAuthPassed(authHandle->authId, info);
    AuthManagerSetAuthFinished(authHandle->authId, info);
    int32_t reason = provider.ConsumeIntegral<int32_t>();
    AuthManagerSetAuthFailed(authHandle->authId, info, reason);
    int32_t result = provider.ConsumeIntegral<int32_t>();
    HandleReconnectResult(&request, info->connId, result, (int32_t)info->connInfo.type);
    DfxRecordLnnConnectEnd(request.requestId, info->connId, &info->connInfo, result);
    OnConnectResult(request.requestId, info->connId, result, &info->connInfo);
    HandleBleDisconnectDelay(info->uuid);
    DelAuthRequest(request.requestId);
}

bool AuthManagerStatusFuzzTest(FuzzedDataProvider &provider)
{
    int64_t authSeq = provider.ConsumeIntegral<int64_t>();
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = provider.ConsumeBool();
    string udid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    string uuid = provider.ConsumeRandomLengthString(UUID_BUF_LEN);
    if (strcpy_s(info.udid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        return false;
    }
    if (strcpy_s(info.uuid, UUID_BUF_LEN, uuid.c_str()) != EOK) {
        return false;
    }
    info.connInfo.type = (AuthLinkType)provider.ConsumeIntegralInRange<uint32_t>(AUTH_TYPE_MIN, AUTH_TYPE_MAX);
    info.connId = (uint64_t)info.connInfo.type << INT32_BIT_NUM;
    info.isConnectServer = provider.ConsumeBool();
    info.normalizedType = (NormalizedType)provider.ConsumeIntegralInRange<uint32_t>(NORMAL_TYPE_MIN, NORMAL_TYPE_MAX);
    SessionKey key;
    (void)memset_s(&key, sizeof(SessionKey), 0, sizeof(SessionKey));
    vector<uint8_t> value = provider.ConsumeRemainingBytes<uint8_t>();
    if (memcpy_s(key.value, SESSION_KEY_LENGTH, value.data(), value.size()) != EOK) {
        return false;
    }
    key.len = SESSION_KEY_LENGTH;
    bool isConnect = provider.ConsumeBool();
    bool isOldKey = provider.ConsumeBool();
    ProcessFuzzConnInfo(provider, &info);
    AuthManager *auth = NewAuthManager(authSeq, &info);
    if (auth != nullptr) {
        auth->hasAuthPassed[info.connInfo.type] = true;
    }
    AuthManagerSetSessionKey(authSeq, &info, &key, isConnect, isOldKey);
    AuthManagerGetSessionKey(authSeq, &info, &key);
    AuthHandle authHandle = {
        .authId = authSeq,
        .type = info.connInfo.type,
    };
    ProcAuthRequest(provider, &authHandle, &info);
    AuthManagerSetAuthFinished(authHandle.authId, &info);
    auth = FindAuthManagerByAuthId(authSeq);
    if (auth != nullptr) {
        DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
    }
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static TestEnv env;
    if (!env.IsEnvInited()) {
        return -1;
    }
    FuzzedDataProvider provider(data, size);
    /* Run your code on data */
    if (!OHOS::AuthManagerStatusFuzzTest(provider)) {
        return -1;
    }
    return 0;
}
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

#include "authmanagerother_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "auth_manager.h"
#include "auth_manager.c"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

using namespace std;

#define FEATURE_MIN 1
#define FEATURE_MAX 10
#define TYPE_MIN DATA_TYPE_AUTH
#define TYPE_MAX DATA_TYPE_APPLY_KEY_CONNECTION
#define MODULE_MIN MODULE_TRUST_ENGINE
#define MODULE_MAX MODULE_OLD_NEARBY

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
        isInited_ = false;
    }

    bool IsEnvInited(void)
    {
        return isInited_;
    }
private:
    volatile bool isInited_ = false;
};
}

namespace OHOS {
static bool ProcSessionKeyInfo(FuzzedDataProvider &provider, AuthSessionInfo *info, int64_t authSeq)
{
    info->connInfo.type = AUTH_LINK_TYPE_SESSION_KEY;
    info->connId = 1ULL << (uint64_t)info->connInfo.type;
    info->isServer = provider.ConsumeBool();
    info->isConnectServer = provider.ConsumeBool();
    AuthManager *auth = NewAuthManager(authSeq, info);
    if (auth != nullptr) {
        auth->hasAuthPassed[info->connInfo.type] = true;
    }
    RawLinkNeedUpdateAuthManager(info->uuid, info->isServer);
    RawLinkNeedUpdateAuthManager(nullptr, info->isServer);
    FindNormalizedKeyAuthManagerByUdid(info->udid, info->isServer);
    DelAuthManager(auth, info->connInfo.type);
    return true;
}

bool AuthManagerOtherFuzzTest(FuzzedDataProvider &provider)
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
    if (!ProcSessionKeyInfo(provider, &info, authSeq)) {
        return false;
    }
    info.connInfo.type = (AuthLinkType)provider.ConsumeIntegralInRange<uint32_t>(FEATURE_MIN, FEATURE_MAX);
    info.connId = (uint64_t)info.connInfo.type << INT32_BIT_NUM;
    info.isConnectServer = provider.ConsumeBool();
    AuthManager *auth = NewAuthManager(authSeq, &info);
    if (auth != nullptr) {
        auth->hasAuthPassed[info.connInfo.type] = true;
    }
    AuthHandle authHandle = {
        .authId = authSeq,
        .type = info.connInfo.type,
    };
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    GetAuthConnInfoByUuid(uuid.c_str(), info.connInfo.type, &connInfo);
    GetLatestIdByConnInfo(&connInfo);
    GetActiveAuthIdByConnInfo(&info.connInfo, info.isServer);
    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    AuthDataHead head = {
        .dataType = provider.ConsumeIntegralInRange<uint32_t>(TYPE_MIN, TYPE_MAX),
        .module = (int32_t)provider.ConsumeIntegralInRange<int32_t>(MODULE_MIN, MODULE_MAX),
        .seq = authSeq,
        .flag = info.isConnectServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = data.size(),
    };
    IsHaveAuthIdByConnId(info.connId);
    DfxRecordServerRecvPassiveConnTime(&connInfo, &head);
    TryAuthSessionProcessDevIdData(&head, (uint8_t *)data.data(), &connInfo);
    AuthManager *getAuth = GetAuthManagerByAuthId(authSeq);
    RemoveNotPassedAuthManagerByUdid(udid.c_str());
    DelDupAuthManager(getAuth);
    RemoveAuthManagerByAuthId(authHandle);
    return true;
}
}


/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static TestEnv env;
    if (!env.IsEnvInited()) {
        return -1;
    }
    FuzzedDataProvider provider(data, size);
    /* Run your code on data */
    if (!OHOS::AuthManagerOtherFuzzTest(provider)) {
        return -1;
    }
    
    return 0;
}
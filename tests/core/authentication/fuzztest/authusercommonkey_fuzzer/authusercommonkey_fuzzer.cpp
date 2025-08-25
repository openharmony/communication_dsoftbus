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

#include "authusercommonkey_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "auth_manager.h"
#include "auth_user_common_key.c"
#include "auth_user_common_key.h"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

using namespace std;

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
} // namespace

namespace OHOS {
void UpdateUserKeyList(const AuthACLInfo aclInfo, AuthUserKeyInfo userKeyInfo)
{
    UpdateUserKeyListByAcl(&aclInfo, &userKeyInfo);
    UpdateUserKeyListByUkId(&aclInfo, &userKeyInfo);
}

void ProcessInsertrAuthUserCommonKey(const AuthACLInfo aclInfo, AuthUserKeyInfo userKeyInfo)
{
    AuthInsertUserKey(&aclInfo, &userKeyInfo, true);
    AuthInsertUserKey(&aclInfo, &userKeyInfo, true);
    AuthInsertUserKey(&aclInfo, &userKeyInfo, true);
    AuthInsertUserKey(&aclInfo, &userKeyInfo, true);
}

void ProcessGetUserKeyInfo(const AuthACLInfo aclInfo, AuthUserKeyInfo userKeyInfo)
{
    GetUserKeyInfoDiffAccountWithUserLevel(&aclInfo, &userKeyInfo);
    GetUserKeyInfoDiffAccount(&aclInfo, &userKeyInfo);
    GetUserKeyInfoSameAccount(&aclInfo, &userKeyInfo);
}

void ProcessGetUserKeyByUkId(FuzzedDataProvider &provider)
{
    int32_t sessionKeyId = provider.ConsumeIntegral<int32_t>();
    uint32_t ukLen = provider.ConsumeIntegral<uint32_t>();
    string uk = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    GetUserKeyByUkId(sessionKeyId, (uint8_t *)uk.c_str(), ukLen);
}

bool AuthUserCommonkeyFuzzTest(FuzzedDataProvider &provider)
{
    AuthACLInfo aclInfo;
    (void)memset_s(&aclInfo, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    aclInfo.isServer = provider.ConsumeBool();
    string sinkUdid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    if (strcpy_s(aclInfo.sinkUdid, UDID_BUF_LEN, sinkUdid.c_str()) != EOK) {
        return false;
    }
    string sourceAccountId = provider.ConsumeRandomLengthString(ACCOUNT_ID_BUF_LEN);
    if (strcpy_s(aclInfo.sourceAccountId, ACCOUNT_ID_BUF_LEN, sourceAccountId.c_str()) != EOK) {
        return false;
    }
    string sourceUdid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    if (strcpy_s(aclInfo.sourceUdid, UDID_BUF_LEN, sourceUdid.c_str()) != EOK) {
        return false;
    }
    string sinkAccountId = provider.ConsumeRandomLengthString(ACCOUNT_ID_BUF_LEN);
    if (strcpy_s(aclInfo.sinkAccountId, ACCOUNT_ID_BUF_LEN, sinkAccountId.c_str()) != EOK) {
        return false;
    }
    aclInfo.sourceUserId = provider.ConsumeIntegral<int32_t>();
    aclInfo.sinkUserId = provider.ConsumeIntegral<int32_t>();
    aclInfo.sourceTokenId = provider.ConsumeIntegral<int64_t>();
    aclInfo.sinkTokenId = provider.ConsumeIntegral<int64_t>();
    AuthUserKeyInfo userKeyInfo;
    (void)memset_s(&userKeyInfo, sizeof(AuthUserKeyInfo), 0, sizeof(AuthUserKeyInfo));
    userKeyInfo.keyLen = provider.ConsumeIntegral<uint32_t>();
    userKeyInfo.time = provider.ConsumeIntegral<uint64_t>();
    userKeyInfo.keyIndex = provider.ConsumeIntegral<int32_t>();
    vector<uint8_t> deviceKey = provider.ConsumeRemainingBytes<uint8_t>();
    if (memcpy_s(userKeyInfo.deviceKey, SESSION_KEY_LENGTH, deviceKey.data(), deviceKey.size()) != EOK) {
        return false;
    }
    DeinitUserKeyList();
    AuthUserKeyInit();
    ProcessInsertrAuthUserCommonKey(aclInfo, userKeyInfo);
    UpdateUserKeyList(aclInfo, userKeyInfo);
    ProcessGetUserKeyInfo(aclInfo, userKeyInfo);
    ProcessGetUserKeyByUkId(provider);
    ProcessInsertrAuthUserCommonKey(aclInfo, userKeyInfo);
    AuthUserKeyInit();
    ProcessInsertrAuthUserCommonKey(aclInfo, userKeyInfo);
    string networkId = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    DelUserKeyByNetworkId(networkId.c_str());
    ProcessGetUserKeyByUkId(provider);
    ProcessGetUserKeyInfo(aclInfo, userKeyInfo);
    UpdateUserKeyList(aclInfo, userKeyInfo);
    ClearInValidAclFromUserKeyList();
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
    if (!OHOS::AuthUserCommonkeyFuzzTest(provider)) {
        return -1;
    }
    return 0;
}
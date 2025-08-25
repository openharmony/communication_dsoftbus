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

#include "authukmanager_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "auth_uk_manager.c"
#include "fuzz_environment.h"

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
static bool AuthUkManagerFuzzTestPart1(FuzzedDataProvider &provider, uint32_t &requestId, uint32_t &channelId)
{
    AuthACLInfo acl;
    (void)memset_s(&acl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    AuthGenUkCallback cb;
    (void)memset_s(&cb, sizeof(AuthGenUkCallback), 0, sizeof(AuthGenUkCallback));
    string udid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    if (strcpy_s(acl.sourceUdid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        return false;
    }
    if (strcpy_s(acl.sinkUdid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        return false;
    }
    AuthGenUkIdByAclInfo(&acl, requestId, &cb);
    CreateUkNegotiateInstance(requestId, channelId, &acl, &cb);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    GetGenUkInstanceByReq(requestId, &instance);
    GetGenUkInstanceByChannel(channelId, &instance);
    GetUkNegotiateInfo(requestId);
    instance.info.isServer = provider.ConsumeBool();
    UpdateUkNegotiateInfo(requestId, &instance);
    SendUkNegoDeviceId(&instance);

    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    bool isSameSide = provider.ConsumeBool();
    CompareByAllAcl(&acl, &newAcl, isSameSide);
    CompareByAclDiffAccountWithUserLevel(&acl, &newAcl, isSameSide);
    CompareByAclDiffAccount(&acl, &newAcl, isSameSide);
    CompareByAclSameAccount(&acl, &newAcl, isSameSide);

    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    HiChainAuthMode authMode =
        (HiChainAuthMode)provider.ConsumeIntegralInRange<uint32_t>(HICHAIN_AUTH_DEVICE, HICHAIN_AUTH_BUTT);
    HiChainAuthParam authParam;
    (void)memset_s(&authParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    GenerateAuthParam(&nodeInfo, &nodeInfo, &acl, authMode, &authParam);
    int32_t ukId = 0;
    AuthFindUkIdByAclInfo(&acl, &ukId);

    return true;
}

static bool AuthUkManagerFuzzTestPart2(FuzzedDataProvider &provider, uint32_t &requestId, uint32_t &channelId)
{
    SyncGenUkResult *para = (SyncGenUkResult *)SoftBusMalloc(sizeof(SyncGenUkResult));
    if (para == nullptr) {
        return false;
    }
    (void)memset_s(para, sizeof(SyncGenUkResult), 0, sizeof(SyncGenUkResult));
    para->requestId = requestId;
    para->isGenUkSuccess = provider.ConsumeBool();
    AsyncCallGenUkResultReceived(para);

    AuthDataHead head;
    (void)memset_s(&head, sizeof(AuthDataHead), 0, sizeof(AuthDataHead));
    head.dataType =
        (AuthDataType)provider.ConsumeIntegralInRange<uint32_t>(DATA_TYPE_AUTH, DATA_TYPE_APPLY_KEY_CONNECTION);
    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    UkMsgHandler(channelId, requestId, &head, (void *)data.data(), data.size());
    OnGenSuccess(requestId);
    OnGenFailed(requestId, 0);

    int32_t inLen = provider.ConsumeIntegral<int32_t>();
    AuthGetUkDecryptSize(inLen);
    vector<uint8_t> outData(data.size() + OVERHEAD_LEN);
    uint32_t outLen = outData.size();
    int32_t ukId = provider.ConsumeIntegral<int32_t>();
    AuthEncryptByUkId(ukId, data.data(), data.size(), outData.data(), &outLen);
    AuthDecryptByUkId(ukId, data.data(), data.size(), outData.data(), &outLen);

    return true;
}

static void AuthUkManagerFuzzTestPart3(FuzzedDataProvider &provider, uint32_t &requestId, uint32_t &channelId)
{
    uint64_t timeTest = provider.ConsumeIntegral<uint64_t>();
    AuthIsUkExpired(timeTest);
    GenUkSeq();
    uint8_t data[SESSION_KEY_LENGTH] = { 0 };
    int64_t authSeq = provider.ConsumeIntegral<int64_t>();
    OnSessionKeyReturned(authSeq, data, SESSION_KEY_LENGTH);
    OnTransmitted(authSeq, data, SESSION_KEY_LENGTH);
    OnRequest(authSeq, 0, nullptr);
    OnFinished(authSeq, 0, nullptr);
    OnError(authSeq, 0, 0, nullptr);

    SecurityOnSessionOpened(channelId, 0, nullptr, SOFTBUS_OK);
    SecurityOnBytesReceived(channelId, (void *)data, SESSION_KEY_LENGTH);
    SecuritySetChannelInfoByReqId(requestId, channelId, 0);
    SecurityOnSessionClosed(channelId);
}

bool AuthUkManagerFuzzTest(FuzzedDataProvider &provider)
{
    UkNegotiateInit();
    UkNegotiateSessionInit();
    uint32_t requestId = provider.ConsumeIntegral<uint32_t>();
    uint32_t channelId = provider.ConsumeIntegral<uint32_t>();
    if (!AuthUkManagerFuzzTestPart1(provider, requestId, channelId)) {
        return false;
    }
    if (!AuthUkManagerFuzzTestPart2(provider, requestId, channelId)) {
        return false;
    }
    AuthUkManagerFuzzTestPart3(provider, requestId, channelId);

    UkNegotiateDeinit();
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
    if (!OHOS::AuthUkManagerFuzzTest(provider)) {
        return -1;
    }

    return 0;
}
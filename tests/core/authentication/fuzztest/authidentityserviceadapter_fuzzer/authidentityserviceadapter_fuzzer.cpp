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
#include "authidentityserviceadapter_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "auth_common_struct.h"
#include "auth_identity_service_adapter.c"
#include "comm_log.h"
#include "fuzz_environment.h"

#define CREATE_LIST_LEN 65

using namespace std;

namespace {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = true;
    }
    ~TestEnv()
    {
        isInited_ = false;
    }

    bool IsEnvInited()
    {
        return isInited_;
    }
private:
    volatile bool isInited_ = false;
};
}
namespace OHOS {

void ProcessServiceGetCred(FuzzedDataProvider &provider, HiChainAuthParam &hiChainParam, SoftBusCredInfo &credInfo)
{
    IdServiceGenerateAuthParam(&hiChainParam);
    IdServiceCopyCredId(hiChainParam.credId);
    int32_t credType = provider.ConsumeIntegral<int32_t>();
    IdServiceGetCredTypeByCredId(hiChainParam.userId, hiChainParam.credId, &credType);
    string credList = provider.ConsumeRandomLengthString(CREATE_LIST_LEN);
    IdServiceGetCredIdFromCredList(hiChainParam.userId, credList.c_str());
    IsInvalidCredList(credList.c_str());
    string strCredInfo = provider.ConsumeRandomLengthString(CREATE_LIST_LEN);
    OnCredAdd(hiChainParam.credId, strCredInfo.c_str());
    IdServiceHandleCredAdd(strCredInfo.c_str());
    IsLocalCredInfo(hiChainParam.udid);
    OnCredUpdate(hiChainParam.credId, strCredInfo.c_str());
    GetCredInfoFromJson(strCredInfo.c_str(), &credInfo);
    GetCredInfoByUserIdAndCredId(hiChainParam.userId, hiChainParam.credId, &credInfo);
    string shortUdidHash = provider.ConsumeRandomLengthString(UDID_HASH_LEN);
    string shortAccountIdHash = provider.ConsumeRandomLengthString(MAX_ACCOUNT_HASH_LEN);
    IdServiceIsPotentialTrustedDevice(shortUdidHash.c_str(), shortAccountIdHash.c_str(), true);
    string credList1 = provider.ConsumeRandomLengthString(CREATE_LIST_LEN);
    string credList2 = provider.ConsumeRandomLengthString(CREATE_LIST_LEN);
    const char *ptrCredList[] = {credList1.c_str(), credList2.c_str()};
    AuthIdServiceQueryCredential(hiChainParam.userId, shortUdidHash.c_str(), shortAccountIdHash.c_str(),
        true, (char **)ptrCredList);
    IdServiceQueryCredential(hiChainParam.userId, shortUdidHash.c_str(), shortAccountIdHash.c_str(),
        true, (char **)ptrCredList);
    IdServiceGenerateQueryParam(shortUdidHash.c_str(), shortAccountIdHash.c_str(), true);
}

bool AuthIdentityServiceAdapterFuzzTest(FuzzedDataProvider &provider)
{
    HiChainAuthParam hiChainParam;
    (void)memset_s(&hiChainParam, sizeof(HiChainAuthParam), 0, sizeof(HiChainAuthParam));
    hiChainParam.userId = provider.ConsumeIntegral<int32_t>();
    string udid = provider.ConsumeRandomLengthString(UDID_BUF_LEN);
    if (strcpy_s(hiChainParam.udid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s udid failed!");
        return false;
    }
    string uid = provider.ConsumeRandomLengthString(MAX_ACCOUNT_HASH_LEN);
    if (strcpy_s(hiChainParam.uid, MAX_ACCOUNT_HASH_LEN, uid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s uid failed!");
        return false;
    }
    string credId = provider.ConsumeRandomLengthString(MAX_CRED_ID_SIZE);
    if (strcpy_s(hiChainParam.credId, MAX_CRED_ID_SIZE, credId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s credId failed!");
        return false;
    }
    SoftBusCredInfo credInfo;
    credInfo.credIdType = ACCOUNT_SHARE;
    (void)memset_s(&credInfo, sizeof(SoftBusCredInfo), 0, sizeof(SoftBusCredInfo));
    if (strcpy_s(credInfo.udid, UDID_BUF_LEN, udid.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s udid failed!");
        return false;
    }
    string userId = provider.ConsumeRandomLengthString(MAX_ACCOUNT_HASH_LEN);
    if (strcpy_s(credInfo.userId, MAX_ACCOUNT_HASH_LEN, userId.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s uid failed!");
        return false;
    }
    IdServiceGetCredMgrInstance();
    IdServiceGetCredAuthInstance();
    IdServiceRegCredMgr();
    IdServiceUnRegCredMgr();
    ProcessServiceGetCred(provider, hiChainParam, credInfo);
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
    
    if (!OHOS::AuthIdentityServiceAdapterFuzzTest(provider)) {
        return -1;
    }
    return 0;
}
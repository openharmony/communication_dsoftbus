/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "authmanager_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "auth_manager.h"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

#include "auth_manager.c"

using namespace std;

#define AUTH_TYPE_MIN AUTH_LINK_TYPE_WIFI
#define AUTH_TYPE_MAX AUTH_LINK_TYPE_MAX
#define DISC_TYPE_MIN DISCOVERY_TYPE_UNKNOWN
#define DISC_TYPE_MAX DISCOVERY_TYPE_COUNT
#define MODE_MIN 30
#define MODE_MAX 600
#define LIST_LEN DISCOVERY_TYPE_COUNT
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

bool NewAuthManagerFuzzTest(FuzzedDataProvider &provider)
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
    ProcessFuzzConnInfo(provider, &info);
    AuthManager *auth = NewAuthManager(authSeq, &info);
    if (auth != nullptr) {
        auth->hasAuthPassed[info.connInfo.type] = true;
    }
    AuthManager *dupAuth = GetAuthManagerByConnInfo(&info.connInfo, info.isServer);
    DelDupAuthManager(dupAuth);
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    TryGetBrConnInfo(uuid.c_str(), &connInfo);
    int64_t seqList[LIST_LEN] = {0};
    uint64_t verifyTime[LIST_LEN] = {0};
    DiscoveryType type = (DiscoveryType)provider.ConsumeIntegralInRange<uint32_t>(DISC_TYPE_MIN, DISC_TYPE_MAX);
    AuthGetLatestAuthSeqListByType(udid.c_str(), seqList, verifyTime, type);
    AuthGetLatestAuthSeqList(udid.c_str(), seqList, type);
    int32_t num = 0;
    AuthHandle *handle = nullptr;
    GetHmlOrP2pAuthHandle(&handle, &num);
    SoftBusFree(handle);
    string p2pMac = provider.ConsumeRandomLengthString(MAC_LEN);
    AuthDeviceSetP2pMac(authSeq, p2pMac.c_str());
    ModeCycle cycle = (ModeCycle)provider.ConsumeIntegralInRange<uint32_t>(MODE_MIN, MODE_MAX);
    AuthSendKeepaliveOption(uuid.c_str(), cycle);
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));
    authHandle.authId = authSeq;
    authHandle.type = info.connInfo.type;
    AuthHandleLeaveLNN(authHandle);
    auth = FindAuthManagerByAuthId(authSeq);
    if (auth != nullptr) {
        DelAuthManager(auth, AUTH_LINK_TYPE_MAX);
    }
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
    if (!OHOS::NewAuthManagerFuzzTest(provider)) {
        return -1;
    }
    return 0;
}
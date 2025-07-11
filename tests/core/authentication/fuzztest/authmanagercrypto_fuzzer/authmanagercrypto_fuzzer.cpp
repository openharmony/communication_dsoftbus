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

#include "authmanagercrypto_fuzzer.h"

#include <cstddef>
#include <cstring>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "auth_common_struct.h"
#include "auth_manager.h"
#include "auth_manager.c"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

#define AUTH_TYPE_MIN AUTH_LINK_TYPE_WIFI
#define AUTH_TYPE_MAX AUTH_LINK_TYPE_MAX
#define TYPE_MIN DATA_TYPE_AUTH
#define TYPE_MAX DATA_TYPE_APPLY_KEY_CONNECTION
#define MODULE_MIN MODULE_TRUST_ENGINE
#define MODULE_MAX MODULE_OLD_NEARBY

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

    bool IsEnvInited()
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

bool AuthEncryptFuzzTest(FuzzedDataProvider &provider)
{
    int64_t authSeq = provider.ConsumeIntegral<int64_t>();
    uint32_t inLen = provider.ConsumeIntegral<uint32_t>();
    AuthSessionInfo info;
    (void)memset_s(&info, sizeof(AuthSessionInfo), 0, sizeof(AuthSessionInfo));
    info.isServer = provider.ConsumeBool();
    info.connInfo.type = (AuthLinkType)provider.ConsumeIntegralInRange<uint32_t>(AUTH_TYPE_MIN,
        AUTH_TYPE_MAX);
    info.connId = (uint64_t)info.connInfo.type << INT32_BIT_NUM;
    ProcessFuzzConnInfo(provider, &info);
    AuthManager *auth = NewAuthManager(authSeq, &info);
    IsAuthNoNeedDisconnect(auth, &info);
    if (auth != nullptr) {
        auth->hasAuthPassed[info.connInfo.type] = true;
    }
    GetAuthIdByConnInfo(&info.connInfo, info.isServer);
    GetAvailableAuthConnInfoByUuid(info.uuid, info.connInfo.type, &info.connInfo);
    int32_t index = provider.ConsumeIntegral<int32_t>();
    info.module = AUTH_MODULE_TRANS;
    AuthProcessEmptySessionKey(&info, index);
    ModeCycle cycle = (ModeCycle)provider.ConsumeIntegral<uint32_t>();
    AuthGetEncryptSize(authSeq, inLen);
    AuthGetDecryptSize(inLen);
    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    AuthDataHead head = {
        .dataType = provider.ConsumeIntegralInRange<uint32_t>(TYPE_MIN, TYPE_MAX),
        .module = (int32_t)provider.ConsumeIntegralInRange<int32_t>(MODULE_MIN, MODULE_MAX),
        .seq = authSeq,
        .flag = info.isConnectServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG,
        .len = data.size(),
    };
    OnDataReceived(info.connId, &info.connInfo, info.isServer, &head, data.data());
    HandleDeviceInfoData(info.connId, &info.connInfo, info.isServer, &head, data.data());
    HandleCloseAckData(info.connId, &info.connInfo, info.isServer, &head, data.data());
    HandleConnectionDataInner(info.connId, &info.connInfo, info.isServer, &head, data.data());
    HandleDecryptFailData(info.connId, &info.connInfo, info.isServer, &head, data.data());
    head.flag = SERVER_SIDE_FLAG;
    HandleDeviceIdData(info.connId, &info.connInfo, info.isServer, &head, data.data());
    head.flag = info.isConnectServer ? SERVER_SIDE_FLAG : CLIENT_SIDE_FLAG;
    HandleUkConnectionData(info.connId, &info.connInfo, info.isServer, &head, data.data());
    DeviceMessageParse messageParse = { CODE_VERIFY_DEVICE, cycle };
    FlushDeviceProcess(&info.connInfo, info.isServer, &messageParse);
    HandleDisconnectedEvent((void *)&info.connId);
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
    if (!OHOS::AuthEncryptFuzzTest(provider)) {
        return -1;
    }
    return 0;
}

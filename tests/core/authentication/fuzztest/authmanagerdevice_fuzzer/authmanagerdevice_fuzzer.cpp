/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "authmanagerdevice_fuzzer.h"
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
#define NORMALIZED_TYPE_MIN 0
#define NORMALIZED_TYPE_MAX 2

namespace {
static void AuthOnDataReceivedTest(AuthHandle authHandle, const AuthDataHead *head, const uint8_t *data,
    uint32_t len)
{
    (void)authHandle;
    (void)head;
    (void)data;
    (void)len;
}

static void AuthOnDisconnectedTest(AuthHandle authHandle)
{
    (void)authHandle;
}

class TestEnv {
public:
    TestEnv()
    {
        AuthCommonInit();
        AuthTransCallback callBack = {
            .onDataReceived = AuthOnDataReceivedTest,
            .onDisconnected = AuthOnDisconnectedTest,
            .onException = nullptr,
        };
        AuthDeviceInit(&callBack);
        isInited_ = true;
    }

    ~TestEnv()
    {
        AuthDeviceDeinit();
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

bool AuthDeviceManagerFuzzTest(FuzzedDataProvider &provider)
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
    info.connInfo.type = (AuthLinkType)provider.ConsumeIntegralInRange<uint32_t>(FEATURE_MIN, FEATURE_MAX);
    info.connId = (uint64_t)info.connInfo.type << INT32_BIT_NUM;
    info.isConnectServer = provider.ConsumeBool();
    ProcessFuzzConnInfo(provider, &info);
    AuthManager *auth = NewAuthManager(authSeq, &info);
    if (auth != nullptr) {
        auth->hasAuthPassed[info.connInfo.type] = true;
    }
    info.connId += 1;
    bool isNewCreated;
    GetDeviceAuthManager(authSeq, &info, &isNewCreated, authSeq);
    info.connId -= 1;
    AuthConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthDeviceGetPreferConnInfo(udid.c_str(), &connInfo);
    AuthDeviceGetConnInfoByType(uuid.c_str(), info.connInfo.type, &connInfo);
    AuthDeviceGetP2pConnInfo(uuid.c_str(), &connInfo);
    AuthDeviceGetHmlConnInfo(uuid.c_str(), &connInfo);
    AuthDeviceGetUsbConnInfo(uuid.c_str(), &connInfo);
    bool checkConn = provider.ConsumeBool();
    AuthDeviceCheckConnInfo(uuid.c_str(), info.connInfo.type, checkConn);
    AuthHandle authHandle;
    (void)memset_s(&authHandle, sizeof(AuthHandle), 0, sizeof(AuthHandle));
    authHandle.authId = authSeq;
    authHandle.type = info.connInfo.type;
    AuthDeviceGetLatestIdByUuid(udid.c_str(), info.connInfo.type, &authHandle);
    AuthDeviceGetIdByConnInfo(&connInfo, info.isServer);
    AuthDeviceGetIdByUuid(uuid.c_str(), info.connInfo.type, info.isServer);
    int32_t index = provider.ConsumeIntegral<int32_t>();
    AuthDeviceGetAuthHandleByIndex(udid.c_str(), info.isServer, index, &authHandle);
    OnDisconnected(info.connId, &connInfo);
    AuthFlushDevice(uuid.c_str());
    DelAuthManagerByConnectionId(info.connId);
    DelAuthManager(auth, info.connInfo.type);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    /* Run your code on data */
    if (!OHOS::AuthDeviceManagerFuzzTest(provider)) {
        return -1;
    }
    
    return 0;
}

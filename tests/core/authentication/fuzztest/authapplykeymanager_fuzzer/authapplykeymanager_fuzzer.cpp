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

#include "authapplykeymanager_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "auth_apply_key_manager.c"
#include "auth_apply_key_manager.h"
#include "auth_manager.h"
#include "comm_log.h"
#include "fuzz_environment.h"
#include "softbus_access_token_test.h"

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

    bool IsEnvInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_ = false;
};
} // namespace

namespace OHOS {

bool ForInitFailedCase(void)
{
    static bool forOnlyOnce = true;
    if (!forOnlyOnce) {
        return true;
    }
    GetApplyKeyByBusinessInfo(nullptr, nullptr, 0, nullptr, 0);
    AuthRecoveryApplyKey();
    AuthInsertApplyKey(nullptr, nullptr, 0, 0, nullptr);
    AuthDeleteApplyKey(nullptr);
    AuthClearAccountApplyKey();
    DeInitApplyKeyManager();
    forOnlyOnce = false;
    return true;
}

bool ForInvalidParamCase(void)
{
    static bool forOnlyOnce = true;
    if (!forOnlyOnce) {
        return true;
    }
    AccountStateChangeHandler(nullptr);
    AuthDeleteApplyKey(nullptr);
    AuthInsertApplyKey(nullptr, nullptr, 0, 0, nullptr);
    AuthPraseApplyKey(nullptr);
    AuthUnpackApplyKey(nullptr, nullptr);
    AuthPackApplyKey(nullptr, nullptr, nullptr);
    GetApplyKeyByBusinessInfo(nullptr, nullptr, 0, nullptr, 0);
    DeleteToAuthApplyMap(nullptr);
    GetNodeFromAuthApplyMap(nullptr, nullptr);
    InsertToAuthApplyMap(nullptr, nullptr, 0, 0, nullptr);

    forOnlyOnce = false;
    return true;
}

bool AccountStateChangeHandlerFuzzTest(FuzzedDataProvider &provider)
{
    LnnMonitorSleStateChangedEvent info;
    memset_s(&info, sizeof(info), 0, sizeof(info));
    info.basic.event = LNN_EVENT_ACCOUNT_CHANGED;
    info.status = provider.ConsumeIntegralInRange<uint32_t>(SOFTBUS_ACCOUNT_LOG_IN, SOFTBUS_ACCOUNT_UNKNOWN);
    AccountStateChangeHandler((const LnnEventBasicInfo *)&info);
    info.status = SOFTBUS_ACCOUNT_LOG_IN;
    AccountStateChangeHandler((const LnnEventBasicInfo *)&info);
    return true;
}

static bool InitRequestBusinessInfo(FuzzedDataProvider &provider, RequestBusinessInfo &reqBusInfo)
{
    memset_s(&reqBusInfo, sizeof(RequestBusinessInfo), 0, sizeof(RequestBusinessInfo));
    string udidHash = provider.ConsumeRandomLengthString(D2D_UDID_HASH_STR_LEN);
    if (strcpy_s(reqBusInfo.udidHash, D2D_UDID_HASH_STR_LEN, udidHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s udidHash failed !");
        return false;
    }
    string accountHash = provider.ConsumeRandomLengthString(D2D_ACCOUNT_HASH_STR_LEN);
    if (strcpy_s(reqBusInfo.accountHash, D2D_ACCOUNT_HASH_STR_LEN, accountHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s accountHash failed !");
        return false;
    }
    string peerAccountHash = provider.ConsumeRandomLengthString(SHA_256_HEX_HASH_LEN);
    if (strcpy_s(reqBusInfo.peerAccountHash, SHA_256_HEX_HASH_LEN, peerAccountHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s peerAccountHash failed !");
        return false;
    }
    reqBusInfo.type = BUSINESS_TYPE_D2D;
    return true;
}

bool AuthDeleteApplyKeyFuzzTest(FuzzedDataProvider &provider)
{
    RequestBusinessInfo reqBusInfo;
    if (!InitRequestBusinessInfo(provider, reqBusInfo)) {
        return false;
    }
    AuthDeleteApplyKey(&reqBusInfo);

    char key[KEY_LEN] = {0};
    string tmpKey = provider.ConsumeRandomLengthString(KEY_LEN);
    if (strcpy_s(key, KEY_LEN, tmpKey.c_str()) != EOK) {
        return false;
    }

    DeleteToAuthApplyMap(key);
    return true;
}

bool AuthInsertApplyKeyFuzzTest(FuzzedDataProvider &provider)
{
    RequestBusinessInfo reqBusInfo;
    if (!InitRequestBusinessInfo(provider, reqBusInfo)) {
        return false;
    }
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = {0};
    vector<uint8_t> tmpApplyKey = provider.ConsumeBytes<uint8_t>(D2D_APPLY_KEY_LEN);
    if (memcpy_s(applyKey, D2D_APPLY_KEY_LEN, tmpApplyKey.data(), tmpApplyKey.size()) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy_s applyKey failed !");
        return false;
    }
    uint64_t currentTime = provider.ConsumeIntegral<uint64_t>();
    char accountHash[SHA_256_HEX_HASH_LEN] = {0};
    string tmpAccountHash = provider.ConsumeRandomLengthString(SHA_256_HEX_HASH_LEN);
    if (strcpy_s(accountHash, SHA_256_HEX_HASH_LEN, tmpAccountHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s accountHash failed !");
        return false;
    }

    AuthInsertApplyKey(&reqBusInfo, applyKey, tmpApplyKey.size(), currentTime, accountHash);
    AuthInsertApplyKey(&reqBusInfo, applyKey, D2D_APPLY_KEY_LEN, currentTime, accountHash);
    return true;
}

bool InsertToAuthApplyMapFuzzTest(FuzzedDataProvider &provider)
{
    char applyMapKey[KEY_LEN] = {0};
    string tmpApplyMapKey = provider.ConsumeRandomLengthString(KEY_LEN);
    if (strcpy_s(applyMapKey, KEY_LEN, tmpApplyMapKey.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s applyMapKey failed !");
        return false;
    }

    uint8_t applyKey[D2D_APPLY_KEY_LEN] = {0};
    vector<uint8_t> tmpApplyKey = provider.ConsumeBytes<uint8_t>(D2D_APPLY_KEY_LEN);
    if (memcpy_s(applyKey, D2D_APPLY_KEY_LEN, tmpApplyKey.data(), tmpApplyKey.size()) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy_s applyKey failed !");
        return false;
    }
    int32_t userId = provider.ConsumeIntegral<int32_t>();
    uint64_t time = provider.ConsumeIntegral<uint64_t>();
    char accountHash[SHA_256_HEX_HASH_LEN] = {0};
    string tmpAccountHash = provider.ConsumeRandomLengthString(SHA_256_HEX_HASH_LEN);
    if (strcpy_s(accountHash, SHA_256_HEX_HASH_LEN, tmpAccountHash.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s accountHash failed !");
        return false;
    }

    InsertToAuthApplyMap(applyMapKey, applyKey, userId, time, accountHash);
    return true;
}

bool GetApplyKeyByBusinessInfoFuzzTest(FuzzedDataProvider &provider)
{
    RequestBusinessInfo reqBusInfo;
    if (!InitRequestBusinessInfo(provider, reqBusInfo)) {
        return false;
    }
    uint8_t applyKey[D2D_APPLY_KEY_LEN] = {0};
    char accountHash[SHA_256_HEX_HASH_LEN] = {0};

    GetApplyKeyByBusinessInfo(&reqBusInfo, applyKey, D2D_APPLY_KEY_LEN, accountHash, SHA_256_HEX_HASH_LEN);
    return true;
}

bool GetNodeFromAuthApplyMapFuzzTest(FuzzedDataProvider &provider)
{
    char applyMapKey[KEY_LEN] = {0};
    string tmpApplyMapKey = provider.ConsumeRandomLengthString(KEY_LEN);
    if (strcpy_s(applyMapKey, KEY_LEN, tmpApplyMapKey.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s applyMapKey failed !");
        return false;
    }
    AuthApplyMapValue *valuePtr;
    GetNodeFromAuthApplyMap(applyMapKey, &valuePtr);
    return true;
}
bool ForCJsonPackUnpackFuzzTest(FuzzedDataProvider &provider)
{
    cJSON *obj = cJSON_CreateObject();
    if (obj == nullptr) {
        return false;
    }
    AuthApplyMap node = {{0}};

    do {
        string tmpMapKey = provider.ConsumeRandomLengthString(KEY_LEN);
        if (strcpy_s(node.mapKey, KEY_LEN, tmpMapKey.c_str()) != EOK) {
            COMM_LOGE(COMM_TEST, "strcpy_s mapKey failed !");
            break;
        }
        vector<uint8_t> tmpApplyKey = provider.ConsumeBytes<uint8_t>(D2D_APPLY_KEY_LEN);
        if (memcpy_s(node.value.applyKey, D2D_APPLY_KEY_LEN, tmpApplyKey.data(), tmpApplyKey.size()) != EOK) {
            COMM_LOGE(COMM_TEST, "memcpy_s applyKey failed !");
            break;
        }
        node.value.userId = provider.ConsumeIntegral<int32_t>();
        node.value.time = provider.ConsumeIntegral<uint64_t>();
        string tmpAccountHash = provider.ConsumeRandomLengthString(SHA_256_HEX_HASH_LEN);
        if (strcpy_s(node.value.accountHash, SHA_256_HEX_HASH_LEN, tmpAccountHash.c_str()) != EOK) {
            COMM_LOGE(COMM_TEST, "strcpy_s accountHash failed !");
            break;
        }

        AuthPackApplyKey(obj, node.mapKey, &node.value);

        AuthApplyMap resNode = {{0}};
        AuthUnpackApplyKey(obj, &resNode);

        cJSON_Delete(obj);
        return true;
    } while (0);

    cJSON_Delete(obj);
    return false;
}

bool SaveAndRecoveryApplyKeyCase(FuzzedDataProvider &provider)
{
    g_isRecoveryApplyKey = true;
    AuthRecoveryApplyKey();
    g_isRecoveryApplyKey = false;
    AuthRecoveryApplyKey();

    g_isRecoveryApplyKey = false;
    AuthAsyncSaveApplyMapFile();
    AuthRecoveryApplyKey();
    g_isRecoveryApplyKey = true;
    return true;
}

bool AuthApplyKeyManagerFuzzTest(FuzzedDataProvider &provider)
{
    ForInitFailedCase();
    InitApplyKeyManager();
    InitApplyKeyManager();
    ForInvalidParamCase();

    AccountStateChangeHandlerFuzzTest(provider);
    AuthInsertApplyKeyFuzzTest(provider);
    AuthDeleteApplyKeyFuzzTest(provider);
    AuthInsertApplyKeyFuzzTest(provider);
    SaveAndRecoveryApplyKeyCase(provider);
    GetApplyKeyByBusinessInfoFuzzTest(provider);
    GetNodeFromAuthApplyMapFuzzTest(provider);
    InsertToAuthApplyMapFuzzTest(provider);
    ForCJsonPackUnpackFuzzTest(provider);
    SaveAndRecoveryApplyKeyCase(provider);

    DeInitApplyKeyManager();
    DeInitApplyKeyManager();
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
    if (!OHOS::AuthApplyKeyManagerFuzzTest(provider)) {
        return -1;
    }
    return 0;
}
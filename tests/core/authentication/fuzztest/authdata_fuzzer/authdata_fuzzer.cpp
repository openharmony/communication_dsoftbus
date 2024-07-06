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

#include "auth_interface.h"
#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "lnn_net_builder.h"
#include <cstddef>
#include <cstring>
#include "securec.h"

namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;

template <class T> T GetData()
{
    T objetct{};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

bool AuthDataFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint64_t) || size < sizeof(AuthTransData)) {
        COMM_LOGE(COMM_TEST, "data or size is invalid!");
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    AuthLinkType authLinkType = static_cast<AuthLinkType>
    (GetData<int>() % (AUTH_LINK_TYPE_MAX - AUTH_LINK_TYPE_WIFI + 1));
    uint64_t authId = *(reinterpret_cast<const uint64_t*>(data));
    AuthHandle authHandle = { .authId = authId, .type = authLinkType};

    const AuthTransData *outData = reinterpret_cast<const AuthTransData*>(data);
    AuthTransData *dataInfo = (AuthTransData *)SoftBusMalloc(sizeof(AuthTransData));
    if (dataInfo == nullptr) {
        COMM_LOGE(COMM_TEST, "dataInfo is NULL");
        return false;
    }
    if (memcpy_s(dataInfo, sizeof(AuthTransData), outData, sizeof(AuthTransData)) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy_s AuthTransData failed!");
        SoftBusFree(dataInfo);
        return false;
    }
    AuthPostTransData(authHandle, dataInfo);
    SoftBusFree(dataInfo);
    return true;
}

bool AuthCryptFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint64_t)) {
        COMM_LOGE(COMM_TEST, "data or size is invalid!");
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;

    AuthLinkType authLinkType = static_cast<AuthLinkType>
    (GetData<int>() % (AUTH_LINK_TYPE_MAX - AUTH_LINK_TYPE_WIFI + 1));
    uint64_t authId = *(reinterpret_cast<const uint64_t*>(data));
    AuthHandle authHandle = { .authId = authId, .type = authLinkType};
   
    uint8_t *outData = nullptr;
    outData =  (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    if (outData == nullptr) {
        COMM_LOGE(COMM_TEST, "outData is NULL, SoftBusMalloc failed!");
        return false;
    }
    uint32_t outLen = 0;
    AuthDecrypt(&authHandle, data, size, outData, &outLen);
    AuthEncrypt(&authHandle, data, size, outData, &outLen);
    SoftBusFree(outData);
    return true;
}

bool AuthFlushDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > UDID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is invalid!");
        return false;
    }
    const char *outData = reinterpret_cast<const char*>(data);
    char *uuid = (char *)SoftBusMalloc(UDID_BUF_LEN);
    if (uuid == nullptr) {
        COMM_LOGE(COMM_TEST, "uuid is NULL, SoftBusMalloc failed!");
        return false;
    }
    if (memcpy_s(uuid, UDID_BUF_LEN, outData, size) != EOK) {
        SoftBusFree(uuid);
        return false;
    }
    AuthFlushDevice(uuid);
    SoftBusFree(uuid);
    return true;
}

bool AuthStartVerifyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(AuthConnInfo)) {
        COMM_LOGE(COMM_TEST, "data is NULL or size less than authConnInfo");
        return false;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    AuthVerifyCallback *authVerifyCallback = LnnGetVerifyCallback();
    const AuthConnInfo connInfo = *const_cast<AuthConnInfo *>(reinterpret_cast<const AuthConnInfo *>(data));
    uint32_t requestId = GetData<uint32_t>();
    bool isFastAuth = GetData<bool>();
    AuthVerifyModule authVeriFyModule = static_cast<AuthVerifyModule>
    (GetData<int>() % (AUTH_MODULE_BUTT - AUTH_MODULE_LNN + 1));

    AuthStartVerify(&connInfo, requestId, authVerifyCallback, authVeriFyModule, isFastAuth);
    return true;
}

void AuthMetaStartVerifyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size != sizeof(AuthKeyInfo)) {
        COMM_LOGE(COMM_TEST, "data is NULL or size is invalid");
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    uint32_t connectionId = GetData<uint32_t>();
    int32_t callingPid = GetData<int32_t>();
    uint32_t requestId = GetData<uint32_t>();
    AuthVerifyCallback *authVerifyCallback = LnnGetVerifyCallback();
    AuthKeyInfo authKeyInfo = *const_cast<AuthKeyInfo *>(reinterpret_cast<const AuthKeyInfo *>(data));
    AuthMetaStartVerify(connectionId, &authKeyInfo, requestId, callingPid, authVerifyCallback);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AuthDataFuzzTest(data, size);
    OHOS::AuthCryptFuzzTest(data, size);
    OHOS::AuthFlushDeviceFuzzTest(data, size);
    OHOS::AuthStartVerifyFuzzTest(data, size);
    OHOS::AuthMetaStartVerifyFuzzTest(data, size);
    return 0;
}
}
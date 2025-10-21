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

#include "fuzz_data_generator.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "gtest/gtest.h"
#include "softbus_conn_interface_struct.h"

#include "softbus_conn_general_connection.c"

namespace OHOS {
void OnCommDataReceivedTest()
{
    uint32_t connectionId;
    GenerateUint32(connectionId);
    ConnModule moduleId = MODULE_BLE_GENERAL;
    int64_t seq;
    GenerateInt64(seq);
    std::vector<uint8_t> payload;
    GeneratePayload(payload);

    OnCommDataReceived(connectionId, moduleId, seq, reinterpret_cast<char *>(payload.data()), payload.size());
}

void SendTest()
{
    uint32_t generalHandle;
    GenerateUint32(generalHandle);
    std::vector<uint8_t> payload;
    GeneratePayload(payload);
    int32_t pid;
    GenerateInt32(pid);

    Send(generalHandle, payload.data(), payload.size(), pid);
}

void ConnectTest(FuzzedDataProvider &provider)
{
    GeneralConnectionParam param;
    std::string adr = provider.ConsumeRandomLengthString(BT_MAC_LEN - 1);
    char mac[BT_MAC_LEN] = { 0 };
    if (strcpy_s(mac, BT_MAC_LEN, adr.c_str()) != EOK) {
        return;
    }
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName.c_str()) != EOK) {
        return;
    }
    std::string bundleName = provider.ConsumeRandomLengthString(BUNDLE_NAME_MAX - 1);
    if (strcpy_s(param.bundleName, PKG_NAME_SIZE_MAX, bundleName.c_str()) != EOK) {
        return;
    }
    GenerateInt32(param.pid);

    Connect(&param, mac);
}

void CreateServerTest(FuzzedDataProvider &provider)
{
    GeneralConnectionParam param;
    std::string name = provider.ConsumeRandomLengthString(GENERAL_NAME_LEN - 1);
    if (strcpy_s(param.name, GENERAL_NAME_LEN, name.c_str()) != EOK) {
        return;
    }
    std::string pkgName = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX - 1);
    if (strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName.c_str()) != EOK) {
        return;
    }
    std::string bundleName = provider.ConsumeRandomLengthString(BUNDLE_NAME_MAX - 1);
    if (strcpy_s(param.bundleName, PKG_NAME_SIZE_MAX, bundleName.c_str()) != EOK) {
        return;
    }
    GenerateInt32(param.pid);

    CreateServer(&param);
}

void CloseServerTest(FuzzedDataProvider &provider)
{
    GeneralConnectionParam param;
    std::string name = provider.ConsumeRandomLengthString(GENERAL_NAME_LEN - 1);
    if (strcpy_s(param.name, GENERAL_NAME_LEN, name.c_str()) != EOK) {
        return;
    }
    std::string bundleName = provider.ConsumeRandomLengthString(BUNDLE_NAME_MAX - 1);
    if (strcpy_s(param.bundleName, PKG_NAME_SIZE_MAX, bundleName.c_str()) != EOK) {
        return;
    }

    CloseServer(&param);
}

void GetPeerDeviceIdTest(FuzzedDataProvider &provider)
{
    uint32_t generalHandle;
    GenerateUint32(generalHandle);
    std::string adr = provider.ConsumeRandomLengthString(BT_MAC_LEN - 1);
    char mac[BT_MAC_LEN] = { 0 };
    if (strcpy_s(mac, BT_MAC_LEN, adr.c_str()) != EOK) {
        return;
    }
    uint32_t tokenId;
    GenerateUint32(tokenId);
    int32_t pid;
    GenerateInt32(pid);

    GetPeerDeviceId(generalHandle, mac, BT_MAC_LEN, tokenId, pid);
}

void ClearAllGeneralConnectionTest(FuzzedDataProvider &provider)
{
    std::string adr = provider.ConsumeRandomLengthString(BT_MAC_LEN - 1);
    char mac[BT_MAC_LEN] = { 0 };
    if (strcpy_s(mac, BT_MAC_LEN, adr.c_str()) != EOK) {
        return;
    }
    std::string pkgNameStr = provider.ConsumeRandomLengthString(PKG_NAME_SIZE_MAX - 1);
    char pkgName[PKG_NAME_SIZE_MAX];
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX, pkgNameStr.c_str()) != EOK) {
        return;
    }
    int32_t pid;
    GenerateInt32(pid);

    ClearAllGeneralConnection(pkgName, pid);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    DataGenerator::Write(data, size);
    FuzzedDataProvider provider(data, size);

    OHOS::OnCommDataReceivedTest();
    OHOS::SendTest();
    OHOS::ConnectTest(provider);
    OHOS::CreateServerTest(provider);
    OHOS::GetPeerDeviceIdTest(provider);
    OHOS::ClearAllGeneralConnectionTest(provider);

    DataGenerator::Clear();
    return 0;
}
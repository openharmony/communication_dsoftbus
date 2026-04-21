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

#include "fuzzer/FuzzedDataProvider.h"
#include "gtest/gtest.h"
#include "softbus_conn_interface_struct.h"
#include "general_connection_mock.h"
#include "softbus_conn_general_connection.c"
#include "softbus_conn_general_negotiation.c"
#include "softbus_conn_ipc.c"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
static struct GeneralConnection *g_generalConnection = NULL;
static void CreateParam(GeneralConnectionParam &param)
{
    if (strcpy_s(param.name, GENERAL_NAME_LEN, "test")) {
        return;
    }
    if (strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, "testPkgName")) {
        return;
    }
    if (strcpy_s(param.bundleName, BUNDLE_NAME_MAX, "testBundleNameServer")) {
        return;
    }
}

static void PrepareConnection(bool isClient)
{
    GeneralConnectionParam param = {
        .pid = 0,
    };
    CreateParam(param);
    const char *addr = "11:22:33:44:55:66";
    int32_t ret = SOFTBUS_OK;
    g_generalConnection = CreateConnection(&param, addr, 1, isClient, &ret);
    if (ret != SOFTBUS_OK) {
        return;
    }
}

static void DestroyConnection(void)
{
    SoftBusMutexLock(&g_generalManager.connections->lock);
    struct GeneralConnection *item = NULL;
    struct GeneralConnection *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_generalManager.connections->list, struct GeneralConnection, node) {
        if (item->underlayerHandle == g_generalConnection->underlayerHandle) {
            ListDelete(&item->node);
            ConnReturnGeneralConnection(&item);
        }
    }
    g_generalConnection = nullptr;
    (void)SoftBusMutexUnlock(&g_generalManager.connections->lock);
}

void OnConnectSuccessFuzz(GeneralConnectionParam *info, uint32_t generalHandle)
{
    (void)info;
    (void)generalHandle;
}

void OnConnectFailedFuzz(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    (void)info;
    (void)generalHandle;
    (void)reason;
}

void OnAcceptConnectFuzz(GeneralConnectionParam *info, uint32_t generalHandle)
{
    (void)info;
    (void)generalHandle;
}

void OnDataReceivedFuzz(GeneralConnectionParam *info, uint32_t generalHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)info;
    (void)generalHandle;
    (void)data;
    (void)dataLen;
}

void OnConnectionDisconnectedFuzz(GeneralConnectionParam *info, uint32_t generalHandle, int32_t reason)
{
    (void)info;
    (void)generalHandle;
    (void)reason;
}

void OnServerStoppedFuzz(GeneralConnectionParam *info)
{
    (void)info;
}

void OnCommDataReceivedTest(FuzzedDataProvider &provider)
{
    ConnModule moduleId = MODULE_BLE_GENERAL;
    int64_t seq = provider.ConsumeIntegral<int64_t>();
    uint32_t connectionId = provider.ConsumeIntegral<uint32_t>();
    uint32_t size = provider.ConsumeIntegral<uint32_t>();
    auto data = provider.ConsumeBytes<uint8_t>(size);
    OnCommDataReceived(connectionId, moduleId, seq, reinterpret_cast<char *>(data.data()), data.size());
}

void SendTest(FuzzedDataProvider &provider)
{
    uint32_t generalHandle = provider.ConsumeIntegral<uint32_t>();
    uint32_t size = provider.ConsumeIntegral<uint32_t>();
    auto payload = provider.ConsumeBytes<uint8_t>(size);
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    Send(generalHandle, payload.data(), payload.size(), pid);
    PrepareConnection(true);
    if (g_generalConnection == nullptr) {
        return;
    }
    SaveConnection(g_generalConnection);
    GetConnectionByGeneralIdAndCheckPid(g_generalConnection->generalId, 1);
    DestroyConnection();
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
    param.pid = provider.ConsumeIntegral<int32_t>();
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
    param.pid = provider.ConsumeIntegral<int32_t>();

    CreateServer(&param);

    CreateParam(param);
    CreateServer(&param);
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

    CreateParam(param);
    CloseServer(&param);
}

void GetPeerDeviceIdTest(FuzzedDataProvider &provider)
{
    uint32_t generalHandle = provider.ConsumeIntegral<uint32_t>();
    std::string adr = provider.ConsumeRandomLengthString(BT_MAC_LEN - 1);
    char mac[BT_MAC_LEN] = { 0 };
    if (strcpy_s(mac, BT_MAC_LEN, adr.c_str()) != EOK) {
        return;
    }
    uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();

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
    int32_t pid = provider.ConsumeIntegral<int32_t>();

    ClearAllGeneralConnection(pkgName, pid);
}

void ProcessInnerMessageByTypeTest(FuzzedDataProvider &provider)
{
    GeneralConnectionInfo info = {{0}};
    info.peerId = provider.ConsumeIntegral<uint32_t>();
    info.localId = provider.ConsumeIntegral<uint32_t>();
    ProcessInnerMessageByType(0, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE, &info);
    ProcessInnerMessageByType(0, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK, &info);
    ProcessInnerMessageByType(0, GENERAL_CONNECTION_MSG_TYPE_MERGE, &info);
    ProcessInnerMessageByType(0, GENERAL_CONNECTION_MSG_TYPE_RESET, &info);
    ProcessInnerMessageByType(0, GENERAL_CONNECTION_MSG_TYPE_MAX, &info);
}

void OnCommDisconnectedTest(FuzzedDataProvider &provider)
{
    ConnectionInfo info = {0};
    OnCommDisconnected(1, &info);

    PrepareConnection(true);
    if (g_generalConnection == nullptr) {
        return;
    }
    g_generalConnection->underlayerHandle = 1;
    SaveConnection(g_generalConnection);
    OnCommDisconnected(g_generalConnection->underlayerHandle, &info);
    DestroyConnection();

    PrepareConnection(false);
    if (g_generalConnection == nullptr) {
        return;
    }
    g_generalConnection->underlayerHandle = 1;
    g_generalConnection->state = STATE_CONNECTED;
    SaveConnection(g_generalConnection);
    OnCommDisconnected(g_generalConnection->underlayerHandle, &info);
    DestroyConnection();
}

void GeneralConnectionPackMsgTest(FuzzedDataProvider &provider)
{
    GeneralConnectionInfo info;
    std::string name = provider.ConsumeRandomLengthString(GENERAL_NAME_LEN - 1);
    if (strcpy_s(info.name, GENERAL_NAME_LEN, name.c_str()) != EOK) {
        return;
    }
    std::string bundleName = provider.ConsumeRandomLengthString(BUNDLE_NAME_MAX - 1);
    if (strcpy_s(info.bundleName, BUNDLE_NAME_MAX, bundleName.c_str()) != EOK) {
        return;
    }
    info.abilityBitSet = provider.ConsumeIntegral<uint32_t>();
    info.updateHandle = provider.ConsumeIntegral<uint32_t>();
    info.ackStatus = provider.ConsumeIntegral<int32_t>();
    info.localId = provider.ConsumeIntegral<uint32_t>();
    info.peerId = provider.ConsumeIntegral<uint32_t>();
    GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    GeneralConnectionPackMsg(&info, GENERAL_CONNECTION_MSG_TYPE_NORMAL);
}

void GeneralConnectionUnpackTest(FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<uint32_t>();
    auto data = provider.ConsumeBytes<uint8_t>(size);

    GeneralConnectionInfo info = {{0}};
    GeneralConnectionUnpackMsg(data.data(), data.size(), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE);
    GeneralConnectionUnpackMsg(data.data(), data.size(), &info, GENERAL_CONNECTION_MSG_TYPE_HANDSHAKE_ACK);
    GeneralConnectionUnpackMsg(data.data(), data.size(), &info, GENERAL_CONNECTION_MSG_TYPE_RESET);
    GeneralConnectionUnpackMsg(data.data(), data.size(), &info, GENERAL_CONNECTION_MSG_TYPE_MERGE);
    GeneralConnectionUnpackMsg(data.data(), data.size(), &info, GENERAL_CONNECTION_MSG_TYPE_NORMAL);
}

void DisconnectTest(FuzzedDataProvider &provider)
{
    PrepareConnection(true);
    if (g_generalConnection == nullptr) {
        return;
    }

    g_generalConnection->info.pid = provider.ConsumeIntegral<int32_t>();
    SaveConnection(g_generalConnection);
    Disconnect(g_generalConnection->underlayerHandle, 0);
    Disconnect(g_generalConnection->underlayerHandle, g_generalConnection->info.pid);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    static bool runCoverage = true;
    if (runCoverage) {
        testing::InitGoogleTest();
        auto result = RUN_ALL_TESTS();
        CONN_LOGI(COMM_TEST, "result=%{public}d", result);
        runCoverage = false;
    }
    static bool isInit = false;
    if (!isInit) {
        LooperInit();
        ConnServerInit();
        static GeneralConnectionListener listener = {
            .onAcceptConnect = OHOS::OnAcceptConnectFuzz,
            .onConnectFailed = OHOS::OnConnectFailedFuzz,
            .onConnectionDisconnected = OHOS::OnConnectionDisconnectedFuzz,
            .onConnectSuccess = OHOS::OnConnectSuccessFuzz,
            .onDataReceived = OHOS::OnDataReceivedFuzz,
            .onServerStopped =  OHOS::OnServerStoppedFuzz,
        };
        RegisterListener(&listener);
        isInit = true;
    }

    OHOS::GeneralConnectionInterfaceMock mock;
    EXPECT_CALL(mock, BleConnectDeviceMock).WillRepeatedly(Return(SOFTBUS_OK));
    OHOS::OnCommDataReceivedTest(provider);
    OHOS::SendTest(provider);
    OHOS::ConnectTest(provider);
    OHOS::CreateServerTest(provider);
    OHOS::GetPeerDeviceIdTest(provider);
    OHOS::ProcessInnerMessageByTypeTest(provider);
    OHOS::OnCommDisconnectedTest(provider);
    OHOS::ClearAllGeneralConnectionTest(provider);
    OHOS::CloseServerTest(provider);
    OHOS::GeneralConnectionPackMsgTest(provider);
    OHOS::GeneralConnectionUnpackTest(provider);
    OHOS::DisconnectTest(provider);
    sleep(1);
    return 0;
}
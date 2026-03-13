/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstring>

#include <gtest/gtest.h>
#include <securec.h>

#include "ble_protocol_interface_factory.h"
#include "g_enhance_conn_func.h"
#include "softbus_conn_ble_manager_mock.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_ble_conflict_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {

#define SHORT_UDID_HASH_LEN 8
#define MAX_SIZE            100
#define SLEEP_TIME_MS       1000
#define WAIT_UPDATE_TIME_MS 3500

static ConnBleTransEventListener g_transEventListener = { 0 };
static SoftBusBtStateListener g_btListener = { 0 };
static SoftBusBleConflictListener g_conflictListener = { 0 };
static int32_t g_listenerId = 0;
static ConnectFuncInterface *g_bleInterface = nullptr;

void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
}

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
}

void OnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)requestId;
    (void)connectionId;
    (void)info;
}

void OnConnectFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
}

extern "C" {
int32_t ConnBleInitTransModule(ConnBleTransEventListener *listener)
{
    if (listener == nullptr) {
        return (int32_t)SOFTBUS_INVALID_PARAM;
    }
    g_transEventListener = *listener;
    return SOFTBUS_OK;
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
{
    if (listener == nullptr || listenerId == nullptr) {
        return (int32_t)SOFTBUS_INVALID_PARAM;
    }
    g_btListener = *listener;
    if (g_listenerId > MAX_SIZE) {
        g_listenerId = 0;
    }
    *listenerId = g_listenerId++;
    return SOFTBUS_OK;
}

void SoftbusBleConflictNotifyDateReceive(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)underlayerHandle;
    (void)data;
    (void)dataLen;
}

void SoftbusBleConflictNotifyDisconnect(const char *addr, const char *udid)
{
    (void)addr;
    (void)udid;
}

void SoftbusBleConflictNotifyConnectResult(uint32_t requestId, int32_t underlayerHandle, bool status)
{
    (void)requestId;
    (void)underlayerHandle;
    (void)status;
}

void LegacyBleReturnConnection(ConnBleConnection **connection)
{
    (void)connection;
}

void SoftbusBleConflictRegisterListener(SoftBusBleConflictListener *listener)
{
    if (listener == nullptr) {
        return;
    }
    g_conflictListener = *listener;
}
}

class BleManagerUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase();
    void SetUp() override
    {
        ConnEnhanceFuncList *pfnConnEnhanceFuncList = ConnEnhanceFuncListGet();
        pfnConnEnhanceFuncList->softbusBleConflictRegisterListener = SoftbusBleConflictRegisterListener;
        ConnectCallback connectCb = { 0 };
        connectCb.OnConnected = OnConnected;
        connectCb.OnReusedConnected = OnReusedConnected;
        connectCb.OnDisconnected = OnDisconnected;
        connectCb.OnDataReceived = OnDataReceived;

        LooperInit();
        SoftbusConfigInit();

        auto mock = BleManagerTestMock::GetMock();
        if (mock != nullptr) {
            EXPECT_CALL(*mock, ConnGattInitClientModule).WillRepeatedly(Return(SOFTBUS_OK));
            EXPECT_CALL(*mock, ConnGattInitServerModule).WillRepeatedly(Return(SOFTBUS_OK));
        }
        g_bleInterface = ConnInitBle(&connectCb);
        ASSERT_NE(g_bleInterface, nullptr);
    }
    void TearDown() override
    {
        LooperDeinit();
        g_bleInterface = nullptr;
    }
};

void BleManagerUnitTest::TearDownTestCase()
{
    SoftBusSleepMs(SLEEP_TIME_MS);
}

HWTEST_F(BleManagerUnitTest, TestConnBleSaveConnection001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:55";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(0, connection->connectionId);
    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleSaveConnection002, TestSize.Level1)
{
    int32_t ret = ConnBleSaveConnection(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestConnBleGetConnectionByAddr001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:56";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *foundConnection = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_NE(foundConnection, nullptr);
    EXPECT_EQ(connection->connectionId, foundConnection->connectionId);
    ConnBleReturnConnection(&foundConnection);

    foundConnection = ConnBleGetConnectionByAddr(addr, CONN_SIDE_SERVER, BLE_GATT);
    EXPECT_EQ(foundConnection, nullptr);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleGetConnectionById001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:57";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *foundConnection = ConnBleGetConnectionById(connection->connectionId);
    EXPECT_NE(foundConnection, nullptr);
    EXPECT_EQ(connection->connectionId, foundConnection->connectionId);
    ConnBleReturnConnection(&foundConnection);

    foundConnection = ConnBleGetConnectionById(99999);
    EXPECT_EQ(foundConnection, nullptr);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleGetConnectionByHandle001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:58";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    connection->underlayerHandle = 12345;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *foundConnection = ConnBleGetConnectionByHandle(12345, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_NE(foundConnection, nullptr);
    EXPECT_EQ(connection->connectionId, foundConnection->connectionId);
    ConnBleReturnConnection(&foundConnection);

    foundConnection = ConnBleGetConnectionByHandle(99999, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(foundConnection, nullptr);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleGetConnectionByUdid001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:59";
    const char *udid = "1122334455667788";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *foundConnection = ConnBleGetConnectionByUdid(addr, udid, BLE_GATT);
    EXPECT_NE(foundConnection, nullptr);
    EXPECT_EQ(connection->connectionId, foundConnection->connectionId);
    ConnBleReturnConnection(&foundConnection);

    const char *differentAddr = "11:22:33:44:44:60";
    foundConnection = ConnBleGetConnectionByUdid(differentAddr, udid, BLE_GATT);
    EXPECT_NE(foundConnection, nullptr);
    ConnBleReturnConnection(&foundConnection);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleGetClientConnectionByUdid001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:61";
    const char *udid = "1122334455667789";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *foundConnection = ConnBleGetClientConnectionByUdid(udid, BLE_GATT);
    EXPECT_NE(foundConnection, nullptr);
    EXPECT_EQ(connection->connectionId, foundConnection->connectionId);
    ConnBleReturnConnection(&foundConnection);

    ConnBleConnection *serverConnection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_SERVER, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(serverConnection, nullptr);
    ret = strcpy_s(serverConnection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    ret = ConnBleSaveConnection(serverConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    foundConnection = ConnBleGetClientConnectionByUdid(udid, BLE_GATT);
    EXPECT_NE(foundConnection, nullptr);
    EXPECT_NE(foundConnection->connectionId, serverConnection->connectionId);
    ConnBleReturnConnection(&foundConnection);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
    ConnBleRemoveConnection(serverConnection);
    ConnBleReturnConnection(&serverConnection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleReturnConnection001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:62";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleReturnConnection(&connection);
    EXPECT_EQ(connection, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestNotifyReusedConnected001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:63";
    const char *udid = "1122334455667700";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    uint16_t challengeCode = 0x1234;
    NotifyReusedConnected(connection->connectionId, challengeCode);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleKeepAlive001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:64";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    uint32_t connectionId = connection->connectionId;
    uint32_t requestId = 100;
    uint32_t time = 5000;
    ret = ConnBleKeepAlive(connectionId, requestId, time);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleKeepAlive(0, requestId, time);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ConnBleKeepAlive(connectionId, requestId, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleRemoveKeepAlive001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:65";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    uint32_t connectionId = connection->connectionId;
    uint32_t requestId = 101;
    ret = ConnBleRemoveKeepAlive(connectionId, requestId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnBleRemoveConnection001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:66";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);

    ConnBleConnection *foundConnection = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(foundConnection, nullptr);

    ConnBleRemoveConnection(nullptr);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice001, TestSize.Level1)
{
    char deviceId[UDID_HASH_LEN] = "1234567";
    char bleMac[BT_MAC_LEN] = "11:22:33:44:44:67";
    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
        .bleOption.psm = 5,
        .bleOption.challengeCode = 0,
    };
    int32_t ret = strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac);
    ASSERT_EQ(EOK, ret);
    ret = memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, deviceId, UDID_HASH_LEN);
    ASSERT_EQ(EOK, ret);
    uint32_t requestId = 10;
    ConnectResult result = {
        .OnConnectSuccessed = OnConnectSuccessed,
        .OnConnectFailed = OnConnectFailed,
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    }
    ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDevice001, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:44:68";
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = g_bleInterface->DisconnectDevice(connection->connectionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo001, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:44:69";
    const char *udid = "1122334455667701";
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    }
    ConnectionInfo info = { 0 };
    ret = g_bleInterface->GetConnectionInfo(connection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(CONNECT_BLE, info.type);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestBleCheckActiveConnection001, TestSize.Level1)
{
    char bleMac[BT_MAC_LEN] = "11:22:33:44:44:70";
    char udid[UDID_BUF_LEN] = "1122334455667702";
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);

    char hashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    int32_t ret =
        ConvertBytesToHexString(hashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN), (unsigned char *)udid, SHORT_UDID_HASH_LEN);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = strcpy_s(connection->udid, UDID_BUF_LEN, hashStr);
    ASSERT_EQ(EOK, ret);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
        .bleOption.psm = 5,
        .bleOption.challengeCode = 0,
    };
    ret = strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac);
    ASSERT_EQ(EOK, ret);
    ret = memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udid, UDID_HASH_LEN);
    ASSERT_EQ(EOK, ret);

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    }
    bool isActive = g_bleInterface->CheckActiveConnection(&option, false);
    EXPECT_EQ(true, isActive);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection001, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:44:71";
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    UpdateOption option = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_BALANCED,
        }
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattClientUpdatePriority).WillRepeatedly(Return(SOFTBUS_OK));
    }
    ret = g_bleInterface->UpdateConnection(connection->connectionId, &option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestBleStartLocalListening001, TestSize.Level1)
{
    LocalListenerInfo info = {};
    int32_t ret = g_bleInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBlePostBytes001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:74";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    uint8_t data[] = {0x01, 0x02, 0x03};
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    }
    ret = g_bleInterface->PostBytes(connection->connectionId, data, sizeof(data), 0, 0, MODULE_CONNECTION, 100);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDeviceNow001, TestSize.Level1)
{
    char bleMac[BT_MAC_LEN] = "11:22:33:44:44:75";
    char udid[UDID_BUF_LEN] = "1122334455667704";
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
        .bleOption.psm = 5,
        .bleOption.challengeCode = 0,
    };
    ret = strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac);
    ASSERT_EQ(EOK, ret);
    ret = memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udid, UDID_HASH_LEN);
    ASSERT_EQ(EOK, ret);

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattClientDisconnect).WillOnce(Return(SOFTBUS_OK));
    }
    ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}
} // namespace OHOS::SoftBus

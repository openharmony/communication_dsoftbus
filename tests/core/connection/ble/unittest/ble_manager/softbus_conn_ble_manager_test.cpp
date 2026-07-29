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

static ConnBleConnection *CreateAndSaveClientConnection(const char *addr)
{
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    if (connection == nullptr) {
        return nullptr;
    }
    int32_t ret = ConnBleSaveConnection(connection);
    if (ret != SOFTBUS_OK) {
        ConnBleReturnConnection(&connection);
        return nullptr;
    }
    return connection;
}

static ConnBleConnection *CreateAndSaveServerConnection(const char *addr)
{
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_SERVER, INVALID_UNDERLAY_HANDLE, true);
    if (connection == nullptr) {
        return nullptr;
    }
    int32_t ret = ConnBleSaveConnection(connection);
    if (ret != SOFTBUS_OK) {
        ConnBleReturnConnection(&connection);
        return nullptr;
    }
    return connection;
}

static ConnBleConnection *CreateAndSaveClientConnectionWithUdid(const char *addr, const char *udid)
{
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    if (connection == nullptr) {
        return nullptr;
    }
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    if (ret != EOK) {
        ConnBleRemoveConnection(connection);
        ConnBleReturnConnection(&connection);
        return nullptr;
    }
    return connection;
}

static ConnBleConnection *CreateAndSaveServerConnectionWithUdid(const char *addr, const char *udid)
{
    ConnBleConnection *connection = CreateAndSaveServerConnection(addr);
    if (connection == nullptr) {
        return nullptr;
    }
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    if (ret != EOK) {
        ConnBleRemoveConnection(connection);
        ConnBleReturnConnection(&connection);
        return nullptr;
    }
    return connection;
}

static ConnBleConnection *CreateAndSaveCocClientConnectionWithUdid(const char *addr, const char *udid)
{
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_COC, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    if (connection == nullptr) {
        return nullptr;
    }
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    if (ret != EOK) {
        ConnBleReturnConnection(&connection);
        return nullptr;
    }
    ret = ConnBleSaveConnection(connection);
    if (ret != SOFTBUS_OK) {
        ConnBleRemoveConnection(connection);
        ConnBleReturnConnection(&connection);
        return nullptr;
    }
    return connection;
}

static void CleanupConnection(ConnBleConnection *connection)
{
    if (connection != nullptr) {
        ConnBleRemoveConnection(connection);
        ConnBleReturnConnection(&connection);
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

HWTEST_F(BleManagerUnitTest, TestSaveConnection_Normal, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:55";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_NE(0, connection->connectionId);
    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestSaveConnection_NullParam, TestSize.Level1)
{
    int32_t ret = ConnBleSaveConnection(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestSaveConnection_MultipleConnections, TestSize.Level1)
{
    const char *addr1 = "11:22:33:44:55:01";
    const char *addr2 = "11:22:33:44:55:02";
    const char *addr3 = "11:22:33:44:55:03";
    ConnBleConnection *conn1 = CreateAndSaveClientConnection(addr1);
    ConnBleConnection *conn2 = CreateAndSaveClientConnection(addr2);
    ConnBleConnection *conn3 = CreateAndSaveServerConnection(addr3);
    ASSERT_NE(conn1, nullptr);
    ASSERT_NE(conn2, nullptr);
    ASSERT_NE(conn3, nullptr);
    EXPECT_NE(conn1->connectionId, conn2->connectionId);
    EXPECT_NE(conn2->connectionId, conn3->connectionId);
    CleanupConnection(conn1);
    CleanupConnection(conn2);
    CleanupConnection(conn3);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddr_Found, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:56";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(connection->connectionId, found->connectionId);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddr_SideMismatch, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:10";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_SERVER, BLE_GATT);
    EXPECT_EQ(found, nullptr);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddr_ProtocolMismatch, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:11";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_COC);
    EXPECT_EQ(found, nullptr);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddr_NullAddr, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetConnectionByAddr(nullptr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionById_Found, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:57";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionById(connection->connectionId);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(connection->connectionId, found->connectionId);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionById_NotFound, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetConnectionById(99999);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionById_ZeroId, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetConnectionById(0);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByHandle_Found, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:58";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    connection->underlayerHandle = 12345;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *found = ConnBleGetConnectionByHandle(12345, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(connection->connectionId, found->connectionId);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByHandle_NotFound, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetConnectionByHandle(99999, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByHandle_SideMismatch, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:20";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    connection->underlayerHandle = 54321;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *found = ConnBleGetConnectionByHandle(54321, CONN_SIDE_SERVER, BLE_GATT);
    EXPECT_EQ(found, nullptr);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByUdid_Found, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:59";
    const char *udid = "1122334455667788";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByUdid(addr, udid, BLE_GATT);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(connection->connectionId, found->connectionId);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByUdid_DifferentAddr, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:30";
    const char *udid = "1122334455667790";
    const char *differentAddr = "11:22:33:44:55:31";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByUdid(differentAddr, udid, BLE_GATT);
    EXPECT_NE(found, nullptr);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByUdid_UdidMismatch, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:32";
    const char *udid = "1122334455667791";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByUdid(addr, "differentUdid", BLE_GATT);
    EXPECT_EQ(found, nullptr);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetClientConnectionByUdid_ClientOnly, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:61";
    const char *udid = "1122334455667789";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetClientConnectionByUdid(udid, BLE_GATT);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(connection->connectionId, found->connectionId);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetClientConnectionByUdid_ExcludeServer, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:40";
    const char *udid = "1122334455667800";
    ConnBleConnection *clientConn = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ConnBleConnection *serverConn = CreateAndSaveServerConnectionWithUdid(addr, udid);
    ASSERT_NE(clientConn, nullptr);
    ASSERT_NE(serverConn, nullptr);

    ConnBleConnection *found = ConnBleGetClientConnectionByUdid(udid, BLE_GATT);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(clientConn->connectionId, found->connectionId);
    EXPECT_NE(found->connectionId, serverConn->connectionId);
    ConnBleReturnConnection(&found);

    CleanupConnection(clientConn);
    CleanupConnection(serverConn);
}

HWTEST_F(BleManagerUnitTest, TestGetClientConnectionByUdid_NotFound, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetClientConnectionByUdid("nonexistentUdid", BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestReturnConnection_Decrement, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:62";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    ConnBleReturnConnection(&connection);
    EXPECT_EQ(connection, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestReturnConnection_NullPtr, TestSize.Level1)
{
    ConnBleConnection *conn = nullptr;
    ConnBleReturnConnection(&conn);
    EXPECT_EQ(conn, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestNotifyReusedConnected, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:63";
    const char *udid = "1122334455667700";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;

    uint16_t challengeCode = 0x1234;
    NotifyReusedConnected(connection->connectionId, challengeCode);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestKeepAlive_Normal, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:64";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    uint32_t connectionId = connection->connectionId;
    uint32_t requestId = 100;
    uint32_t time = 5000;
    int32_t ret = ConnBleKeepAlive(connectionId, requestId, time);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestKeepAlive_InvalidConnectionId, TestSize.Level1)
{
    int32_t ret = ConnBleKeepAlive(0, 100, 5000);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestKeepAlive_InvalidTime, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:50";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    int32_t ret = ConnBleKeepAlive(connection->connectionId, 100, 0);
    EXPECT_NE(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestRemoveKeepAlive_Normal, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:65";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    uint32_t connectionId = connection->connectionId;
    uint32_t requestId = 101;
    int32_t ret = ConnBleKeepAlive(connectionId, requestId, 3000);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnBleRemoveKeepAlive(connectionId, requestId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestRemoveKeepAlive_InvalidConnectionId, TestSize.Level1)
{
    int32_t ret = ConnBleRemoveKeepAlive(0, 101);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = ConnBleRemoveKeepAlive(99999, 101);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestRemoveConnection_Normal, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:66";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    CleanupConnection(connection);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestRemoveConnection_DoubleRemove, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:60";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    uint32_t connectionId = connection->connectionId;
    int32_t rcBefore = connection->objectRc;

    ConnBleRemoveConnection(connection);
    EXPECT_EQ(connection->objectRc, rcBefore - 1);
    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);

    ConnBleConnection *found = ConnBleGetConnectionById(connectionId);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestCreateConnection_ClientInitState, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:70";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->side, CONN_SIDE_CLIENT);
    EXPECT_EQ(connection->protocol, BLE_GATT);
    EXPECT_EQ(connection->objectRc, 1);
    EXPECT_STREQ(connection->addr, addr);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestCreateConnection_ServerInitState, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:71";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_SERVER, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->side, CONN_SIDE_SERVER);
    EXPECT_EQ(connection->protocol, BLE_GATT);
    EXPECT_EQ(connection->objectRc, 1);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestCreateConnection_CocProtocol, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:72";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_COC, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->protocol, BLE_COC);
    EXPECT_EQ(connection->side, CONN_SIDE_CLIENT);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestCreateConnection_WithUnderlayerHandle, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:73";
    int32_t handle = 777;
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, handle, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->underlayerHandle, handle);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestCreateConnection_FastestConnectDisable, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:74";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->fastestConnectEnable, false);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_Normal, TestSize.Level1)
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
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, deviceId, UDID_HASH_LEN));
    uint32_t requestId = 10;
    ConnectResult result = {
        .OnConnectSuccessed = OnConnectSuccessed,
        .OnConnectFailed = OnConnectFailed,
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_CocProtocol, TestSize.Level1)
{
    char deviceId[UDID_HASH_LEN] = "7654321";
    char bleMac[BT_MAC_LEN] = "11:22:33:44:55:80";
    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_COC,
        .bleOption.psm = 5,
        .bleOption.challengeCode = 0,
    };
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, deviceId, UDID_HASH_LEN));
    uint32_t requestId = 11;
    ConnectResult result = {
        .OnConnectSuccessed = OnConnectSuccessed,
        .OnConnectFailed = OnConnectFailed,
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDevice_Normal, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:44:68";
    ConnBleConnection *connection = CreateAndSaveClientConnection(bleMac);
    ASSERT_NE(connection, nullptr);

    int32_t ret = g_bleInterface->DisconnectDevice(connection->connectionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDevice_InvalidId, TestSize.Level1)
{
    int32_t ret = g_bleInterface->DisconnectDevice(0);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = g_bleInterface->DisconnectDevice(99999);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo_Normal, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:44:69";
    const char *udid = "1122334455667701";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(bleMac, udid);
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    }
    ConnectionInfo info = { 0 };
    int32_t ret = g_bleInterface->GetConnectionInfo(connection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(CONNECT_BLE, info.type);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo_InvalidId, TestSize.Level1)
{
    ConnectionInfo info = { 0 };
    int32_t ret = g_bleInterface->GetConnectionInfo(0, &info);
    EXPECT_NE(SOFTBUS_OK, ret);

    ret = g_bleInterface->GetConnectionInfo(99999, &info);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo_NullInfo, TestSize.Level1)
{
    int32_t ret = g_bleInterface->GetConnectionInfo(1, nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleCheckActiveConnection_Active, TestSize.Level1)
{
    char bleMac[BT_MAC_LEN] = "11:22:33:44:44:70";
    char udid[UDID_BUF_LEN] = "1122334455667702";
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);

    char hashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    int32_t ret = ConvertBytesToHexString(hashStr,
        HEXIFY_LEN(SHORT_UDID_HASH_LEN), reinterpret_cast<unsigned char *>(udid), SHORT_UDID_HASH_LEN);
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
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udid, UDID_HASH_LEN));

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    }
    bool isActive = g_bleInterface->CheckActiveConnection(&option, false);
    EXPECT_EQ(true, isActive);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleCheckActiveConnection_Inactive, TestSize.Level1)
{
    char deviceId[UDID_HASH_LEN] = "9999999";
    char bleMac[BT_MAC_LEN] = "99:99:99:99:99:99";
    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
        .bleOption.psm = 5,
        .bleOption.challengeCode = 0,
    };
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, deviceId, UDID_HASH_LEN));

    bool isActive = g_bleInterface->CheckActiveConnection(&option, false);
    EXPECT_EQ(false, isActive);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_Normal, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:44:71";
    ConnBleConnection *connection = CreateAndSaveClientConnection(bleMac);
    ASSERT_NE(connection, nullptr);

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
    int32_t ret = g_bleInterface->UpdateConnection(connection->connectionId, &option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_HighPriority, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:55:90";
    ConnBleConnection *connection = CreateAndSaveClientConnection(bleMac);
    ASSERT_NE(connection, nullptr);

    UpdateOption option = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_HIGH,
        }
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattClientUpdatePriority).WillRepeatedly(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->UpdateConnection(connection->connectionId, &option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_LowPower, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:55:91";
    ConnBleConnection *connection = CreateAndSaveClientConnection(bleMac);
    ASSERT_NE(connection, nullptr);

    UpdateOption option = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_LOW_POWER,
        }
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattClientUpdatePriority).WillRepeatedly(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->UpdateConnection(connection->connectionId, &option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_InvalidId, TestSize.Level1)
{
    UpdateOption option = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_BALANCED,
        }
    };
    int32_t ret = g_bleInterface->UpdateConnection(0, &option);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleStartLocalListening, TestSize.Level1)
{
    LocalListenerInfo info = {};
    int32_t ret = g_bleInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleStopLocalListening, TestSize.Level1)
{
    LocalListenerInfo info = {};
    int32_t ret = g_bleInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = g_bleInterface->StopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBlePostBytes_Normal, TestSize.Level1)
{
    const char *addr = "11:22:33:44:44:74";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    uint8_t data[] = {0x01, 0x02, 0x03};
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->PostBytes(connection->connectionId, data, sizeof(data), 0, 0, MODULE_CONNECTION, 100);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDeviceNow_Normal, TestSize.Level1)
{
    char bleMac[BT_MAC_LEN] = "11:22:33:44:44:75";
    char udid[UDID_BUF_LEN] = "1122334455667704";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(bleMac, udid);
    ASSERT_NE(connection, nullptr);

    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
        .bleOption.psm = 5,
        .bleOption.challengeCode = 0,
    };
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, bleMac));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udid, UDID_HASH_LEN));

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattClientDisconnect).WillOnce(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDeviceNow_NullOption, TestSize.Level1)
{
    int32_t ret = g_bleInterface->DisconnectDeviceNow(nullptr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestConnInitBle_NullCallback, TestSize.Level1)
{
    ConnectFuncInterface *interface = ConnInitBle(nullptr);
    EXPECT_EQ(interface, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestCreateConnection_NullAddr, TestSize.Level1)
{
    ConnBleConnection *connection =
        ConnBleCreateConnection(nullptr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    EXPECT_EQ(connection, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddrAfterRemove, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:A0";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_NE(found, nullptr);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);

    found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByIdAfterRemove, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:A1";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    uint32_t connectionId = connection->connectionId;

    CleanupConnection(connection);

    ConnBleConnection *found = ConnBleGetConnectionById(connectionId);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByHandleAfterRemove, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:A2";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    connection->underlayerHandle = 88888;
    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *found = ConnBleGetConnectionByHandle(88888, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_NE(found, nullptr);
    ConnBleReturnConnection(&found);

    CleanupConnection(connection);

    found = ConnBleGetConnectionByHandle(88888, CONN_SIDE_CLIENT, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestKeepAliveAndRemoveSequence, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:A3";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    uint32_t connectionId = connection->connectionId;

    int32_t ret = ConnBleKeepAlive(connectionId, 200, 3000);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleKeepAlive(connectionId, 201, 3000);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleRemoveKeepAlive(connectionId, 200);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleRemoveKeepAlive(connectionId, 201);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestRemoveKeepAlive_NotAlive, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:A4";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    int32_t ret = ConnBleRemoveKeepAlive(connection->connectionId, 999);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestMultipleConnectionsSameUdid, TestSize.Level1)
{
    const char *udid = "11223344556677AA";
    const char *clientAddr = "11:22:33:44:55:B0";
    const char *serverAddr = "11:22:33:44:55:B1";
    ConnBleConnection *clientConn = CreateAndSaveClientConnectionWithUdid(clientAddr, udid);
    ConnBleConnection *serverConn = CreateAndSaveServerConnectionWithUdid(serverAddr, udid);
    ASSERT_NE(clientConn, nullptr);
    ASSERT_NE(serverConn, nullptr);

    ConnBleConnection *foundClient = ConnBleGetClientConnectionByUdid(udid, BLE_GATT);
    EXPECT_NE(foundClient, nullptr);
    EXPECT_EQ(clientConn->connectionId, foundClient->connectionId);
    ConnBleReturnConnection(&foundClient);

    ConnBleConnection *foundByUdid = ConnBleGetConnectionByUdid(clientAddr, udid, BLE_GATT);
    EXPECT_NE(foundByUdid, nullptr);
    ConnBleReturnConnection(&foundByUdid);

    CleanupConnection(clientConn);
    CleanupConnection(serverConn);
}

HWTEST_F(BleManagerUnitTest, TestServerConnectionState, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:C0";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_SERVER, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->state, BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestClientConnectionState, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:C1";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->state, BLE_CONNECTION_STATE_CONNECTING);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestConnectionReferenceCount, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:C2";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    int32_t rcBefore = connection->objectRc;

    int32_t ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(connection->objectRc, rcBefore + 1);

    ConnBleConnection *found = ConnBleGetConnectionById(connection->connectionId);
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(found->objectRc, rcBefore + 2);

    ConnBleReturnConnection(&found);
    EXPECT_EQ(connection->objectRc, rcBefore + 1);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBlePostBytes_WithChallengeCode, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:D0";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, "11223344556677CC");
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;

    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->PostBytes(connection->connectionId, data, sizeof(data), 1, 1, MODULE_CONNECTION, 200);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestKeepAlive_ExceedMaxTime, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:E0";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);

    int32_t ret = ConnBleKeepAlive(connection->connectionId, 300, 10001);
    EXPECT_NE(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_ServerSide, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:55:E1";
    ConnBleConnection *connection = CreateAndSaveServerConnection(bleMac);
    ASSERT_NE(connection, nullptr);

    UpdateOption option = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_HIGH,
        }
    };
    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattServerDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->UpdateConnection(connection->connectionId, &option);
    EXPECT_NE(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestConnectionAddrField, TestSize.Level1)
{
    const char *addr = "AA:BB:CC:DD:EE:FF";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_STREQ(connection->addr, addr);
    ConnBleReturnConnection(&connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByUdid_NullParams, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetConnectionByUdid(nullptr, "udid", BLE_GATT);
    EXPECT_EQ(found, nullptr);

    found = ConnBleGetConnectionByUdid("addr", nullptr, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestGetClientConnectionByUdid_NullUdid, TestSize.Level1)
{
    ConnBleConnection *found = ConnBleGetClientConnectionByUdid(nullptr, BLE_GATT);
    EXPECT_EQ(found, nullptr);
}

HWTEST_F(BleManagerUnitTest, TestKeepAliveAndDisconnectInterleave, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:F0";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    uint32_t connectionId = connection->connectionId;

    int32_t ret = ConnBleKeepAlive(connectionId, 400, 5000);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = g_bleInterface->DisconnectDevice(connectionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo_ServerSide, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:55:F1";
    const char *udid = "11223344556677DD";
    ConnBleConnection *connection = CreateAndSaveServerConnectionWithUdid(bleMac, udid);
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    }
    ConnectionInfo info = { 0 };
    int32_t ret = g_bleInterface->GetConnectionInfo(connection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(CONNECT_BLE, info.type);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_NullOption, TestSize.Level1)
{
    ConnectResult result = { .OnConnectSuccessed = OnConnectSuccessed, .OnConnectFailed = OnConnectFailed };
    int32_t ret = g_bleInterface->ConnectDevice(nullptr, 1, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_NonBleType, TestSize.Level1)
{
    ConnectOption option = { .type = CONNECT_BR };
    ConnectResult result = { .OnConnectSuccessed = OnConnectSuccessed, .OnConnectFailed = OnConnectFailed };
    int32_t ret = g_bleInterface->ConnectDevice(&option, 2, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_NullResult, TestSize.Level1)
{
    ConnectOption option = { .type = CONNECT_BLE, .bleOption = { .protocol = BLE_GATT } };
    int32_t ret = g_bleInterface->ConnectDevice(&option, 3, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_NullOnSuccessed, TestSize.Level1)
{
    ConnectOption option = { .type = CONNECT_BLE, .bleOption = { .protocol = BLE_GATT } };
    ConnectResult result = { .OnConnectSuccessed = nullptr, .OnConnectFailed = OnConnectFailed };
    int32_t ret = g_bleInterface->ConnectDevice(&option, 4, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleConnectDevice_NullOnFailed, TestSize.Level1)
{
    ConnectOption option = { .type = CONNECT_BLE, .bleOption = { .protocol = BLE_GATT } };
    ConnectResult result = { .OnConnectSuccessed = OnConnectSuccessed, .OnConnectFailed = nullptr };
    int32_t ret = g_bleInterface->ConnectDevice(&option, 5, &result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDeviceNow_NonBleType, TestSize.Level1)
{
    ConnectOption option = { .type = CONNECT_BR };
    int32_t ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDeviceNow_ConnectionNotExist, TestSize.Level1)
{
    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
    };
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, "11:22:33:44:55:ZZ"));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, "ZZZZZZZZ", SHORT_UDID_HASH_LEN));
    int32_t ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleCheckActiveConnection_NullOption, TestSize.Level1)
{
    bool ret = g_bleInterface->CheckActiveConnection(nullptr, false);
    EXPECT_FALSE(ret);
}

HWTEST_F(BleManagerUnitTest, TestBleCheckActiveConnection_NonBleType, TestSize.Level1)
{
    ConnectOption option = { .type = CONNECT_BR };
    bool ret = g_bleInterface->CheckActiveConnection(&option, false);
    EXPECT_FALSE(ret);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_NullOption, TestSize.Level1)
{
    int32_t ret = g_bleInterface->UpdateConnection(1, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleUpdateConnection_NonBleType, TestSize.Level1)
{
    UpdateOption option = { .type = CONNECT_BR };
    int32_t ret = g_bleInterface->UpdateConnection(1, &option);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo_ConnectingState, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:A1";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_CONNECTING;

    ConnectionInfo info = { 0 };
    int32_t ret = g_bleInterface->GetConnectionInfo(connection->connectionId, &info);
    EXPECT_NE(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddr_AnySide, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:B1";
    ConnBleConnection *serverConn = CreateAndSaveServerConnection(addr);
    ASSERT_NE(serverConn, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_ANY, BLE_GATT);
    EXPECT_NE(found, nullptr);
    if (found != nullptr) {
        EXPECT_EQ(serverConn->connectionId, found->connectionId);
        ConnBleReturnConnection(&found);
    }

    CleanupConnection(serverConn);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByAddr_AnyProtocol, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:B2";
    char udid[UDID_BUF_LEN] = "AABBCCDD";
    ConnBleConnection *cocConn = CreateAndSaveCocClientConnectionWithUdid(addr, udid);
    ASSERT_NE(cocConn, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByAddr(addr, CONN_SIDE_CLIENT, BLE_PROTOCOL_ANY);
    EXPECT_NE(found, nullptr);
    if (found != nullptr) {
        EXPECT_EQ(cocConn->connectionId, found->connectionId);
        ConnBleReturnConnection(&found);
    }

    CleanupConnection(cocConn);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByHandle_AnySideAnyProtocol, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:B3";
    char udid[UDID_BUF_LEN] = "AABBCCDDEE";
    ConnBleConnection *cocConn = CreateAndSaveCocClientConnectionWithUdid(addr, udid);
    ASSERT_NE(cocConn, nullptr);
    cocConn->underlayerHandle = 42;

    ConnBleConnection *found = ConnBleGetConnectionByHandle(42, CONN_SIDE_ANY, BLE_PROTOCOL_ANY);
    EXPECT_NE(found, nullptr);
    if (found != nullptr) {
        EXPECT_EQ(cocConn->connectionId, found->connectionId);
        ConnBleReturnConnection(&found);
    }

    CleanupConnection(cocConn);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByUdid_AnyProtocol, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:B4";
    char udid[UDID_BUF_LEN] = "CCDDEEFF0011";
    ConnBleConnection *cocConn = CreateAndSaveCocClientConnectionWithUdid(addr, udid);
    ASSERT_NE(cocConn, nullptr);

    ConnBleConnection *found = ConnBleGetConnectionByUdid(addr, udid, BLE_PROTOCOL_ANY);
    EXPECT_NE(found, nullptr);
    if (found != nullptr) {
        EXPECT_EQ(cocConn->connectionId, found->connectionId);
        ConnBleReturnConnection(&found);
    }

    CleanupConnection(cocConn);
}

HWTEST_F(BleManagerUnitTest, TestGetClientConnectionByUdid_AnyProtocol, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:B5";
    char udid[UDID_BUF_LEN] = "DDEEFF00112233";
    ConnBleConnection *cocConn = CreateAndSaveCocClientConnectionWithUdid(addr, udid);
    ASSERT_NE(cocConn, nullptr);

    ConnBleConnection *found = ConnBleGetClientConnectionByUdid(udid, BLE_PROTOCOL_ANY);
    EXPECT_NE(found, nullptr);
    if (found != nullptr) {
        EXPECT_EQ(cocConn->connectionId, found->connectionId);
        ConnBleReturnConnection(&found);
    }

    CleanupConnection(cocConn);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDevice_InvalidId2, TestSize.Level1)
{
    int32_t ret = g_bleInterface->DisconnectDevice(99999);
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BleManagerUnitTest, TestBleGetConnectionInfo_CocProtocol, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:D1";
    const char *udid = "11223344556677CC";
    ConnBleConnection *connection = CreateAndSaveCocClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    connection->psm = 123;

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    }
    ConnectionInfo info = { 0 };
    int32_t ret = g_bleInterface->GetConnectionInfo(connection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(CONNECT_BLE, info.type);
    EXPECT_EQ(BLE_COC, info.bleInfo.protocol);
    EXPECT_EQ(123, info.bleInfo.psm);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestBleDisconnectDeviceNow_ByUdidLookup, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:E1";
    const char *udid = "FF00112233445566";
    ConnBleConnection *connection = CreateAndSaveClientConnectionWithUdid(addr, udid);
    ASSERT_NE(connection, nullptr);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;

    ConnectOption option = {
        .type = CONNECT_BLE,
        .bleOption.bleMac = "",
        .bleOption.deviceIdHash = "",
        .bleOption.protocol = BLE_GATT,
    };
    ASSERT_EQ(EOK, strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, addr));
    ASSERT_EQ(EOK, memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, udid, SHORT_UDID_HASH_LEN));

    auto mock = BleManagerTestMock::GetMock();
    if (mock != nullptr) {
        EXPECT_CALL(*mock, ConnGattClientDisconnect).WillOnce(Return(SOFTBUS_OK));
    }
    int32_t ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestRemoveKeepAlive_NotAliveAgain, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:E2";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    int32_t rcBefore = connection->objectRc;

    int32_t ret = ConnBleRemoveKeepAlive(connection->connectionId, 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(rcBefore, connection->objectRc);

    CleanupConnection(connection);
}

HWTEST_F(BleManagerUnitTest, TestGetConnectionByIdAfterMultipleSaves, TestSize.Level1)
{
    const char *addr1 = "11:22:33:44:55:F3";
    const char *addr2 = "11:22:33:44:55:F4";
    ConnBleConnection *conn1 = CreateAndSaveClientConnection(addr1);
    ASSERT_NE(conn1, nullptr);
    ConnBleConnection *conn2 = CreateAndSaveServerConnection(addr2);
    ASSERT_NE(conn2, nullptr);

    ConnBleConnection *found1 = ConnBleGetConnectionById(conn1->connectionId);
    EXPECT_NE(found1, nullptr);
    if (found1 != nullptr) {
        EXPECT_EQ(conn1->connectionId, found1->connectionId);
        ConnBleReturnConnection(&found1);
    }
    ConnBleConnection *found2 = ConnBleGetConnectionById(conn2->connectionId);
    EXPECT_NE(found2, nullptr);
    if (found2 != nullptr) {
        EXPECT_EQ(conn2->connectionId, found2->connectionId);
        ConnBleReturnConnection(&found2);
    }

    CleanupConnection(conn1);
    CleanupConnection(conn2);
}

HWTEST_F(BleManagerUnitTest, TestKeepAlive_BoundaryMaxTime, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:F5";
    ConnBleConnection *connection = CreateAndSaveClientConnection(addr);
    ASSERT_NE(connection, nullptr);
    int32_t rcBefore = connection->connectionRc;

    int32_t ret = ConnBleKeepAlive(connection->connectionId, 1, BLE_CONNECT_KEEP_ALIVE_TIMEOUT_MILLIS);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(rcBefore + 1, connection->connectionRc);

    CleanupConnection(connection);
}

} // namespace OHOS::SoftBus

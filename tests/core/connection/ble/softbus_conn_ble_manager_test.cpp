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

#include <cstdio>
#include <cstring>

#include <gtest/gtest.h>
#include <securec.h>

#include "ble_protocol_interface_factory.h"
#include "softbus_conn_ble_manager_mock.h"
#include "softbus_adapter_ble_conflict.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
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
namespace OHOS {

#define SHORT_UDID_HASH_LEN 8
#define MAX_SIZE            100
#define SLEEP_TIME_MS       1000
#define WAIT_UPDATE_TIME_MS 3500

static ConnBleTransEventListener g_transEventListener = { 0 };
static SoftBusBtStateListener g_btListener = { 0 };
static SoftBusBleConflictListener g_conflictListener = { 0 };
static int32_t g_listenerId = 0;
static ConnectFuncInterface *g_bleInterface = NULL;
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
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_transEventListener = *listener;
    return SOFTBUS_OK;
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_btListener = *listener;
    if (g_listenerId > MAX_SIZE) {
        g_listenerId = 0;
    }
    return g_listenerId++;
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
    if (listener == NULL) {
        return;
    }
    g_conflictListener = *listener;
}
}
class ConnectionBleManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase();
    void SetUp() override
    {
        ConnectCallback connectCb = { 0 };
        connectCb.OnConnected = OnConnected;
        connectCb.OnReusedConnected = OnReusedConnected;
        connectCb.OnDisconnected = OnDisconnected;
        connectCb.OnDataReceived = OnDataReceived;

        LooperInit();
        SoftbusConfigInit();

        NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
        EXPECT_CALL(bleMock, ConnGattInitClientModule).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(bleMock, ConnGattInitServerModule).WillRepeatedly(Return(SOFTBUS_OK));
        g_bleInterface = ConnInitBle(&connectCb);
        ASSERT_NE(g_bleInterface, NULL);
    }
    void TearDown() override
    {
        LooperDeinit();
    }
};

void ConnectionBleManagerTest::TearDownTestCase()
{
    SoftBusSleepMs(SLEEP_TIME_MS);
}
/*
 * @tc.name: TestTransListener001
 * @tc.desc: Test TransListener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestTransListener001, TestSize.Level1)
{
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattClientDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    g_btListener.OnBtStateChanged(g_listenerId, SOFTBUS_BLE_STATE_TURN_OFF);

    EXPECT_CALL(bleMock, ConnGattServerStartService).WillOnce(Return(SOFTBUS_OK));
    g_btListener.OnBtStateChanged(g_listenerId, SOFTBUS_BLE_STATE_TURN_ON);

    uint32_t connectionId = 13000;
    uint32_t len = 100;
    int32_t pid = 0;
    int32_t flag = 1;
    int32_t module = MODULE_CONNECTION;
    int64_t seq = 1000;
    int32_t error = SOFTBUS_INVALID_PARAM;
    g_transEventListener.onPostBytesFinished(connectionId, len, pid, flag, module, seq, error);

    const char *addr = "22:33:44:55:66:77";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, NULL);
    connection->underlayerHandle = 3;
    int32_t ret = ConnBleSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    g_transEventListener.onPostBytesFinished(connection->connectionId, len, pid, flag, module, seq, error);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: TestConflictGetConnection001
 * @tc.desc: Test ConflictGetConnection.
 * @tc.in: Test module, Test number, Test Level
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestConflictGetConnection001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    const char *udid = "1111222233334444";

    g_conflictListener.cancelOccupy(udid);
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, NULL);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);

    connection->underlayerHandle = 2;
    ret = ConnBleSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ret = g_conflictListener.getConnection(udid);
    EXPECT_EQ(2, ret);

    int32_t underlayHandle = 2;
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t));
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    bool res = g_conflictListener.postBytes(underlayHandle, data, sizeof(uint8_t));
    EXPECT_EQ(true, res);

    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    res = g_conflictListener.postBytes(underlayHandle, data, sizeof(uint8_t));
    EXPECT_EQ(false, res);

    g_conflictListener.occupy(udid, 1000);
    g_conflictListener.occupy(udid, 1500);
    g_conflictListener.cancelOccupy(udid);
    char invaildUdid[100] = { 0 };
    (void)memset_s(invaildUdid, 100, '1', 100);
    g_conflictListener.occupy(invaildUdid, 2000);
}

/*
 * @tc.name: TestConflictDisconnect001
 * @tc.desc: Test ConflictDisconnect.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestConflictDisconnect001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    const char *udid = "1111222233334444";
    ConnBleConnection *connection =
        ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(connection, NULL);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);

    connection->underlayerHandle = 1;
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint32_t requestId = 1;
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnBlePackCtlMessage).WillOnce(Return(10));
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    ret = g_conflictListener.reuseConnection(addr, udid, requestId);
    EXPECT_EQ(1, ret);
    const char *invaildAddr = "11:22:33:44:55:66:77:88:99";

    ret = g_conflictListener.reuseConnection(invaildAddr, udid, requestId);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    EXPECT_CALL(bleMock, ConnBlePackCtlMessage).WillOnce(Return(10));
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = g_conflictListener.reuseConnection(addr, udid, requestId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    EXPECT_CALL(bleMock, ConnGattClientDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    g_conflictListener.disconnect(1, true);

    const char *bleAddr = "00:22:33:44:55:66";
    const char *bleUdid = "1100222233334444";
    ConnBleConnection *bleConnection =
        ConnBleCreateConnection(bleAddr, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(NULL, bleConnection);
    ret = strcpy_s(bleConnection->udid, UDID_BUF_LEN, bleUdid);
    ASSERT_EQ(EOK, ret);
    bleConnection->underlayerHandle = 10;
    ret = ConnBleSaveConnection(bleConnection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, ConnGattClientDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    g_conflictListener.disconnect(10, false);
}

/*
 * @tc.name: TestBleInterface001
 * @tc.desc: Test BleInterface.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestBleInterface001, TestSize.Level1)
{
    const char *deviceId = "1234567";
    const char *bleMac = "11:22:33:44:33:00";
    const char *udid = "1119222233334440";
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
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    g_bleInterface->ConnectDevice(&option, requestId, &result);

    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t connectionId = 131001;
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t));
    uint32_t dataLen = sizeof(uint8_t);
    int32_t pid = 0;
    int32_t flag = 2;
    int32_t module = MODULE_CONNECTION;
    int64_t seq = 100;
    ret = g_bleInterface->PostBytes(connectionId, data, dataLen, pid, flag, module, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(connection, NULL);
    ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    ASSERT_EQ(EOK, ret);
    connection->underlayerHandle = 2;
    ret = ConnBleSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = g_bleInterface->DisconnectDevice(connection->connectionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: TestBleInterface002
 * @tc.desc: Test BleInterface.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestBleInterface002, TestSize.Level1)
{
    const char *bleMac = "44:11:33:44:33:00";
    const char *udid = "1119222233334419";

    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    ConnBleConnection *connection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(connection, NULL);
    int32_t ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);

    ASSERT_EQ(EOK, ret);
    connection->underlayerHandle = 10;
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
    EXPECT_CALL(bleMock, ConnGattClientDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *serverConnection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_SERVER, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(serverConnection, NULL);
    serverConnection->underlayerHandle = 50;
    ret = ConnBleSaveConnection(serverConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, ConnGattServerDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_bleInterface->DisconnectDeviceNow(&option);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: TestBleInterface003
 * @tc.desc: Test BleInterface.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestBleInterface003, TestSize.Level1)
{
    const char *bleMac = "77:22:33:44:33:00";
    const char *udid = "1254222233334419";
    const char *invaildMac = "77:22:33:44:33:00999";
    const char *networkId = "testnetworkid123";
    ConnBleConnection *connection =
        ConnBleCreateConnection(invaildMac, BLE_COC, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    EXPECT_EQ(connection, NULL);
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    ConnBleConnection *bleConnection =
        ConnBleCreateConnection(bleMac, BLE_COC, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(bleConnection, NULL);
    bleConnection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    bleConnection->featureBitSet = false;
    bleConnection->psm = 10;
    int32_t ret = strcpy_s(bleConnection->udid, UDID_BUF_LEN, udid);
    EXPECT_EQ(ret, EOK);
    ret = strncpy_s(bleConnection->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId));
    EXPECT_EQ(ret, EOK);
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_CALL(bleMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ConnectionInfo info = { 0 };
    ret = g_bleInterface->GetConnectionInfo(bleConnection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleConnection *invalidConnection =
        ConnBleCreateConnection(bleMac, BLE_COC, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(invalidConnection, NULL);
    invalidConnection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    invalidConnection->featureBitSet = true;
    invalidConnection->psm = 10;
    const char *invaildUdid = "";
    ret = strcpy_s(invalidConnection->udid, UDID_BUF_LEN, invaildUdid);
    EXPECT_EQ(ret, EOK);
    ret = strncpy_s(invalidConnection->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId));
    EXPECT_EQ(ret, EOK);
    ret = ConnBleSaveConnection(invalidConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = g_bleInterface->GetConnectionInfo(invalidConnection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    invalidConnection->featureBitSet = false;
    invalidConnection->protocol = BLE_GATT;
    ret = ConnBleSaveConnection(invalidConnection);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = g_bleInterface->GetConnectionInfo(invalidConnection->connectionId, &info);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: TestBleInterface004
 * @tc.desc: Test BleInterface.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestBleInterface004, TestSize.Level1)
{
    LocalListenerInfo info = {};
    int32_t ret = g_bleInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattServerStopService).WillOnce(Return(SOFTBUS_OK));
    ret = g_bleInterface->StopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = g_bleInterface->StopLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(bleMock, ConnGattServerStartService)
        .WillOnce(Return(SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR));
    ret = g_bleInterface->StartLocalListening(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TestBleInterface005
 * @tc.desc: Test BleInterface.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, TestBleInterface005, TestSize.Level1)
{
    ConnectOption option = {};
    option.type = CONNECT_BLE;
    const char *udid = "1234";

    int32_t ret = memcpy_s(option.bleOption.deviceIdHash, sizeof(udid), udid, sizeof(udid));
    EXPECT_EQ(ret, EOK);
    option.bleOption.protocol = BLE_GATT;
    char hashStr[HEXIFY_LEN(SHORT_UDID_HASH_LEN)] = { 0 };
    ret = ConvertBytesToHexString(
        hashStr, HEXIFY_LEN(SHORT_UDID_HASH_LEN), (unsigned char *)option.bleOption.deviceIdHash, SHORT_UDID_HASH_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);

    const char *bleMac = "77:02:33:44:33:00";
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    ConnBleConnection *bleConnection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(bleConnection, NULL);

    ret = memcpy_s(bleConnection->udid, UDID_HASH_LEN, hashStr, UDID_HASH_LEN);
    EXPECT_EQ(ret, EOK);
    bleConnection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(ret, EOK);

    EXPECT_CALL(bleMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    bool res = g_bleInterface->CheckActiveConnection(&option, false);
    EXPECT_EQ(res, true);

    UpdateOption options = {
        .type = CONNECT_BLE,
        .bleOption = {
            .priority = CONN_BLE_PRIORITY_BALANCED,
        }
    };
    EXPECT_CALL(bleMock, ConnGattClientUpdatePriority).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_bleInterface->UpdateConnection(bleConnection->connectionId, &options);
    EXPECT_EQ(ret, SOFTBUS_OK);
    bleConnection->side = CONN_SIDE_SERVER;
    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(ret, EOK);
    ret = g_bleInterface->UpdateConnection(bleConnection->connectionId, &options);
    EXPECT_EQ(ret, SOFTBUS_FUNC_NOT_SUPPORT);
}

/*
 * @tc.name: NotifyReusedConnected001
 * @tc.desc: Test NotifyReusedConnected.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, NotifyReusedConnected001, TestSize.Level1)
{
    const char *bleMac = "21:12:33:44:33:00";
    const char *udid = "dcba";
    const char *networkId = "testnetworkid123";
    ConnBleConnection *bleConnection =
        ConnBleCreateConnection(bleMac, BLE_GATT, CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, false);
    ASSERT_NE(bleConnection, NULL);
    int32_t ret = memcpy_s(bleConnection->udid, UDID_HASH_LEN, udid, UDID_HASH_LEN);
    EXPECT_EQ(ret, EOK);

    bleConnection->featureBitSet = true;
    bleConnection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    bleConnection->psm = 101;

    ret = ConnBleSaveConnection(bleConnection);
    EXPECT_EQ(ret, EOK);
    uint16_t challengeCode = 0x12;
    NotifyReusedConnected(bleConnection->connectionId, challengeCode);
    ret = strcpy_s(bleConnection->networkId, NETWORK_ID_BUF_LEN, networkId);
    EXPECT_EQ(ret, EOK);
    ConnBleRemoveConnection(bleConnection);
    ConnBleRemoveConnection(bleConnection);
}

/*
 * @tc.name: OnBtStateChanged001
 * @tc.desc: Test OnBtStateChanged.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, OnBtStateChanged001, TestSize.Level1)
{
    const char *deviceId = "1234567";
    const char *bleMac = "11:22:33:44:33:00";
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
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_btListener.OnBtStateChanged(g_listenerId, SOFTBUS_BLE_STATE_TURN_OFF);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: ConnectDevice001
 * @tc.desc: Test ConnectDevice.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnectDevice001, TestSize.Level1)
{
    const char *deviceId = "1234567";
    const char *bleMac = "11:22:33:44:33:00";
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
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: ConnectDevice002
 * @tc.desc: Test ConnectDevice.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnectDevice002, TestSize.Level1)
{
    const char *deviceId = "1234568";
    const char *bleMac = "11:22:33:44:33:56";
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
    uint32_t requestId = 5;
    ConnectResult result = {
        .OnConnectSuccessed = OnConnectSuccessed,
        .OnConnectFailed = OnConnectFailed,
    };
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, LnnGetConnSubFeatureByUdidHashStr).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(bleMock, ConnGattClientConnect).WillRepeatedly(Return(SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR));
    ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(bleMock, ConnGattClientConnect).WillRepeatedly(Return(SOFTBUS_OK));
    requestId = 6;
    const char *mac = "11:33:44:22:33:56";
    const char *bleDeviceId = "1234569";
    ret = strcpy_s(option.bleOption.bleMac, BT_MAC_LEN, mac);
    ASSERT_EQ(EOK, ret);
    ret = memcpy_s(option.bleOption.deviceIdHash, UDID_HASH_LEN, bleDeviceId, UDID_HASH_LEN);
    ASSERT_EQ(EOK, ret);
    ret = g_bleInterface->ConnectDevice(&option, requestId, &result);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(SLEEP_TIME_MS);
}

/*
 * @tc.name: ConnBleUpdateConnectionRc001
 * @tc.desc: Test ConnBleUpdateConnectionRc.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleUpdateConnectionRc001, TestSize.Level1)
{
    ConnBleConnection connection;
    connection.connectionId = 196600;
    connection.side = CONN_SIDE_CLIENT;
    connection.featureBitSet = 0;
    int32_t ret = SoftBusMutexInit(&connection.lock, NULL);
    ASSERT_EQ(EOK, ret);

    connection.underlayerHandle = 10;
    connection.connectionRc = 1;
    const char *bleMac = "11:22:33:44:33:56";
    ret = strcpy_s(connection.addr, BT_MAC_LEN, bleMac);
    ASSERT_EQ(EOK, ret);
    ret = ConnBleUpdateConnectionRc(&connection, 0, -1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connection.connectionId = 196601;
    connection.featureBitSet = 2;
    connection.connectionRc = 1;
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnBlePackCtlMessage).WillOnce(Return(-1)).WillRepeatedly(Return(100));
    ret = ConnBleUpdateConnectionRc(&connection, 0, -1);
    EXPECT_EQ(ret, -1);

    connection.connectionRc = 1;
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnBleUpdateConnectionRc(&connection, 0, -1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    connection.connectionRc = 2;
    ret = ConnBleUpdateConnectionRc(&connection, 0, -1);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnBleOnReferenceRequest001
 * @tc.desc: Test ConnBleOnReferenceRequest.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleOnReferenceRequest001, TestSize.Level1)
{
    ConnBleConnection connection;
    int32_t ret = SoftBusMutexInit(&connection.lock, NULL);
    ASSERT_EQ(EOK, ret);
    connection.connectionRc = 1;
    connection.state = BLE_CONNECTION_STATE_NEGOTIATION_CLOSING;
    cJSON json = { 0 };
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem).WillOnce(Return(false));
    ret = ConnBleOnReferenceRequest(&connection, &json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem).WillOnce(Return(true)).WillOnce(Return(false));
    ret = ConnBleOnReferenceRequest(&connection, &json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBleOnReferenceRequest002
 * @tc.desc: Test ConnBleOnReferenceRequest.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleOnReferenceRequest002, TestSize.Level1)
{
    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    ASSERT_NE(nullptr, connection);
    int32_t ret = SoftBusMutexInit(&connection->lock, NULL);
    ASSERT_EQ(EOK, ret);
    const char *bleMac = "11:22:33:44:33:56";
    const char *udid = "1254222233334419";
    ret = strcpy_s(connection->addr, BT_MAC_LEN, bleMac);
    ASSERT_EQ(EOK, ret);
    ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    EXPECT_EQ(EOK, ret);

    connection->protocol = BLE_GATT;
    connection->connectionRc = 1;
    connection->state = BLE_CONNECTION_STATE_NEGOTIATION_CLOSING;
    connection->side = CONN_SIDE_SERVER;
    ret = ConnBleSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    
    cJSON json = { 0 };
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetdelta)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc1);
    EXPECT_CALL(bleMock, GetJsonObjectNumber16Item).WillOnce(Return(false));
    ret = ConnBleOnReferenceRequest(connection, &json);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetdelta)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc1);
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    EXPECT_CALL(bleMock, GetJsonObjectNumber16Item).WillOnce(Return(true));
    ret = ConnBleOnReferenceRequest(connection, &json);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBleOnReferenceRequest003
 * @tc.desc: Test ConnBleOnReferenceRequest.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleOnReferenceRequest003, TestSize.Level1)
{
    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    ASSERT_NE(nullptr, connection);
    int32_t ret = SoftBusMutexInit(&connection->lock, NULL);
    ASSERT_EQ(EOK, ret);
    const char *bleMac = "11:22:33:44:33:56";
    const char *udid = "1254222233334419";
    ret = strcpy_s(connection->addr, BT_MAC_LEN, bleMac);
    ASSERT_EQ(EOK, ret);
    ret = strcpy_s(connection->udid, UDID_BUF_LEN, udid);
    EXPECT_EQ(EOK, ret);

    connection->protocol = BLE_GATT;
    connection->connectionRc = 1;
    connection->state = BLE_CONNECTION_STATE_NEGOTIATION_CLOSING;
    connection->side = CONN_SIDE_SERVER;
    ret = ConnBleSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    cJSON json = { 0 };

    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetdelta)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc0);

    EXPECT_CALL(bleMock, GetJsonObjectNumber16Item).WillRepeatedly(Return(false));
    EXPECT_CALL(bleMock, ConnGattServerDisconnect).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBleOnReferenceRequest(connection, &json);
    EXPECT_EQ(SOFTBUS_OK, ret);

    connection->connectionRc = 3;
    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetdelta)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc0);
    EXPECT_CALL(bleMock, ConnBlePackCtlMessage).WillOnce(Return(SOFTBUS_CREATE_JSON_ERR));
    ret = ConnBleOnReferenceRequest(connection, &json);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(bleMock, GetJsonObjectSignedNumberItem)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetdelta)
        .WillOnce(ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc0);
    EXPECT_CALL(bleMock, ConnBlePackCtlMessage).WillOnce(Return(100));
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillOnce(Return(SOFTBUS_OK));
    ret = ConnBleOnReferenceRequest(connection, &json);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBleStopServer001
 * @tc.desc: Test ConnBleOccupy.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleStopServer001, TestSize.Level1)
{
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattServerStartService).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnBleStartServer();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(bleMock, ConnGattServerStopService).WillRepeatedly(Return(SOFTBUS_LOCK_ERR));
    ret = ConnBleStopServer();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(3 * 1000); //to call RetryServerStatConsistentHandler function
}

/*
 * @tc.name: ConnBleSend001
 * @tc.desc: Test ConnBleSend.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleSend001, TestSize.Level1)
{
    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    ASSERT_NE(nullptr, connection);
    int32_t ret = SoftBusMutexInit(&connection->lock, NULL);
    ASSERT_EQ(EOK, ret);
    connection->protocol = BLE_GATT;
    connection->side = CONN_SIDE_SERVER;
    uint8_t *data = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    uint32_t dataLen = sizeof(uint8_t);

    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattServerSend).WillOnce(Return(SOFTBUS_OK));
    ret = ConnBleSend(connection, data, dataLen, MODULE_CONNECTION);
    EXPECT_EQ(SOFTBUS_OK, ret);

    connection->side = CONN_SIDE_CLIENT;
    EXPECT_CALL(bleMock, ConnGattClientSend).WillOnce(Return(SOFTBUS_OK));
    ret = ConnBleSend(connection, data, dataLen, MODULE_CONNECTION);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ConnBleRefreshIdleTimeout(connection);
    SoftBusSleepMs(CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS); // sleep 60s to call timout event
}

/*
 * @tc.name: ConnBleOccupy001
 * @tc.desc: Test ConnBleOccupy.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleOccupy001, TestSize.Level1)
{
    const char *bleMac = "11:22:33:44:55:66";
    ConnBleConnection *connection = ConnBleCreateConnection(bleMac, BLE_GATT,
    CONN_SIDE_CLIENT, INVALID_UNDERLAY_HANDLE, true);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBleSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    ConnBleOccupy(connection);
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnBlePackCtlMessage).WillRepeatedly(Return(100));
    EXPECT_CALL(bleMock, ConnBlePostBytesInner).WillRepeatedly(Return(SOFTBUS_OK));
    ret = ConnBleUpdateConnectionRc(connection, 1, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ConnBleUpdateConnectionRc(connection, 1, -1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(WAIT_UPDATE_TIME_MS); // sleep 3.5s to retry update Rc
    EXPECT_EQ(connection->state, BLE_CONNECTION_STATE_NEGOTIATION_CLOSING);
    ConnBleRemoveConnection(connection);
    ConnBleReturnConnection(&connection);
}

/*
 * @tc.name: ConnBleDisconnectNow001
 * @tc.desc: Test ConnBleOccupy.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionBleManagerTest, ConnBleDisconnectNow001, TestSize.Level1)
{
    ConnBleConnection connection = {{0}};
    connection.protocol = BLE_GATT;
    connection.connectionId = 1;
    connection.side = CONN_SIDE_CLIENT;
    NiceMock<ConnectionBleManagerInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnGattClientDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = ConnBleDisconnectNow(&connection, BLE_DISCONNECT_REASON_CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS

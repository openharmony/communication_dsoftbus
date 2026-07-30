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

#include <gtest/gtest.h>
#include <securec.h>
#include <cstring>

#include "ble_protocol_interface_factory.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_ble_connection_mock.h"
#include "softbus_conn_ble_manager.h"
#include "softbus_conn_ble_trans.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS::SoftBus {
class ConnBleConnectionTest : public testing::Test {
public:
    static void SetUpTestCase() { }

    static void TearDownTestCase() { }

    void SetUp() override { }

    void TearDown() override { }

protected:
    ConnBleConnection *CreateTestConnection(const char *addr, BleProtocolType protocol, ConnSideType side)
    {
        ConnBleConnection *conn = (ConnBleConnection *)calloc(1, sizeof(ConnBleConnection));
        if (conn != nullptr) {
            ListInit(&conn->node);
            conn->protocol = protocol;
            conn->side = side;
            conn->underlayerHandle = 0;
            conn->state = (side == CONN_SIDE_CLIENT) ? BLE_CONNECTION_STATE_CONNECTING :
                                                       BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
            conn->connectionRc = 0;
            conn->objectRc = 1;
            conn->isOccupied = false;
            conn->isNeedSetIdleTimeout = true;
            conn->isMtuExchange = false;
            conn->isBasicInfoExchange = false;
            pthread_mutex_init(reinterpret_cast<pthread_mutex_t*>(&conn->lock), nullptr);
            if (addr != nullptr) {
                strcpy_s(conn->addr, BT_MAC_LEN, addr);
            }
            conn->connectStatus = (SoftBusList *)malloc(sizeof(SoftBusList));
            if (conn->connectStatus != nullptr) {
                ListInit(&conn->connectStatus->list);
                pthread_mutex_init(reinterpret_cast<pthread_mutex_t*>(&conn->connectStatus->lock), nullptr);
            } else {
                pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t*>(&conn->lock));
                free(conn);
                return nullptr;
            }
        }
        return conn;
    }

    void FreeTestConnection(ConnBleConnection *conn)
    {
        if (conn != nullptr) {
            pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t*>(&conn->lock));
            if (conn->connectStatus != nullptr) {
                pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t*>(&conn->connectStatus->lock));
                free(conn->connectStatus);
            }
            free(conn);
        }
    }
};

/*
* @tc.name: ConnBleCreateConnectionTest001
* @tc.desc: test ConnBleCreateConnection ble addr is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCreateConnectionTest001, TestSize.Level1)
{
    ConnBleConnection *connection = ConnBleCreateConnection(nullptr, BLE_GATT, CONN_SIDE_CLIENT, 0, false);
    ASSERT_EQ(connection, nullptr);
}

/*
* @tc.name: ConnBleCreateConnectionTest002
* @tc.desc: test ConnBleCreateConnection calloc ble connection fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCreateConnectionTest002, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";

    EXPECT_CALL(mock, SoftBusCallocHook(_)).WillOnce(Return(nullptr));

    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 0, false);
    ASSERT_EQ(connection, nullptr);
}

/*
* @tc.name: ConnBleCreateConnectionTest003
* @tc.desc: test ConnBleCreateConnection init lock fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCreateConnectionTest003, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection testConn;

    EXPECT_CALL(mock, SoftBusCallocHook(_)).WillOnce(Return(&testConn));
    EXPECT_CALL(mock, SoftBusMutexInitHook(_, _)).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusFreeHook(&testConn));

    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 0, false);
    ASSERT_EQ(connection, nullptr);
}

/*
* @tc.name: ConnBleCreateConnectionTest004
* @tc.desc: test ConnBleCreateConnection create softbus list fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCreateConnectionTest004, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection testConn;

    EXPECT_CALL(mock, SoftBusCallocHook(_)).WillOnce(Return(&testConn));
    EXPECT_CALL(mock, SoftBusMutexInitHook(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, CreateSoftBusListHook()).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, SoftBusMutexDestroyHook(_));
    EXPECT_CALL(mock, SoftBusFreeHook(&testConn));

    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 0, false);
    ASSERT_EQ(connection, nullptr);
}

/*
* @tc.name: ConnBleCreateConnectionTest005
* @tc.desc: test ConnBleCreateConnection CONN_SIDE_CLIENT success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCreateConnectionTest005, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection testConn;
    (void)memset_s(&testConn, sizeof(ConnBleConnection), 0, sizeof(ConnBleConnection));
    ListInit(&testConn.node);
    ListInit(&testConn.buffer.packets);
    SoftBusList testList;
    (void)memset_s(&testList, sizeof(SoftBusList), 0, sizeof(SoftBusList));
    ListInit(&testList.list);

    EXPECT_CALL(mock, SoftBusCallocHook(_)).WillOnce(Return(&testConn));
    EXPECT_CALL(mock, SoftBusMutexInitHook(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, CreateSoftBusListHook()).WillOnce(Return(&testList));
    EXPECT_CALL(mock, SoftBusMutexDestroyHook(_));
    EXPECT_CALL(mock, DestroySoftBusListHook(&testList));
    EXPECT_CALL(mock, SoftBusFreeHook(&testConn));

    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_GATT, CONN_SIDE_CLIENT, 0, false);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->protocol, BLE_GATT);
    EXPECT_EQ(connection->side, CONN_SIDE_CLIENT);
    EXPECT_EQ(connection->underlayerHandle, 0);
    EXPECT_EQ(connection->fastestConnectEnable, false);
    EXPECT_EQ(strcmp(connection->addr, addr), 0);
    EXPECT_EQ(connection->state, BLE_CONNECTION_STATE_CONNECTING);
    EXPECT_EQ(connection->connectionRc, 0);
    EXPECT_EQ(connection->objectRc, 1);
    EXPECT_EQ(connection->isOccupied, false);
    EXPECT_EQ(connection->isNeedSetIdleTimeout, true);
    EXPECT_EQ(connection->isMtuExchange, false);
    EXPECT_EQ(connection->isBasicInfoExchange, false);

    ConnBleFreeConnection(connection);
}

/*
* @tc.name: ConnBleCreateConnectionTest006
* @tc.desc: test ConnBleCreateConnection CONN_SIDE_SERVER success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCreateConnectionTest006, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection testConn;
    (void)memset_s(&testConn, sizeof(ConnBleConnection), 0, sizeof(ConnBleConnection));
    ListInit(&testConn.node);
    ListInit(&testConn.buffer.packets);
    SoftBusList testList;
    (void)memset_s(&testList, sizeof(SoftBusList), 0, sizeof(SoftBusList));
    ListInit(&testList.list);

    EXPECT_CALL(mock, SoftBusCallocHook(_)).WillOnce(Return(&testConn));
    EXPECT_CALL(mock, SoftBusMutexInitHook(_, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, CreateSoftBusListHook()).WillOnce(Return(&testList));
    EXPECT_CALL(mock, SoftBusMutexDestroyHook(_));
    EXPECT_CALL(mock, DestroySoftBusListHook(&testList));
    EXPECT_CALL(mock, SoftBusFreeHook(&testConn));

    ConnBleConnection *connection = ConnBleCreateConnection(addr, BLE_COC, CONN_SIDE_SERVER, 1, true);
    ASSERT_NE(connection, nullptr);
    EXPECT_EQ(connection->protocol, BLE_COC);
    EXPECT_EQ(connection->side, CONN_SIDE_SERVER);
    EXPECT_EQ(connection->underlayerHandle, 1);
    EXPECT_EQ(connection->fastestConnectEnable, true);
    EXPECT_EQ(connection->state, BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO);

    ConnBleFreeConnection(connection);
}

/*
* @tc.name: ConnBleConnectTest001
* @tc.desc: test ConnBleConnect connection is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleConnectTest001, TestSize.Level1)
{
    int32_t ret = ConnBleConnect(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ConnBleConnectTest002
* @tc.desc: test ConnBleConnect ble connection connect fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleConnectTest002, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(nullptr));

    int32_t ret = ConnBleConnect(connection);
    EXPECT_EQ(ret, SOFTBUS_CONN_BLE_INTERNAL_ERR);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleConnectTest003
* @tc.desc: test ConnBleConnect ble connection connect success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleConnectTest003, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    BleUnifyInterface interface;
    interface.bleClientConnect = [](ConnBleConnection *conn) -> int32_t { return SOFTBUS_OK; };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(&interface));

    int32_t ret = ConnBleConnect(connection);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleDisconnectNowTest001
* @tc.desc: test ConnBleDisconnectNow connection is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleDisconnectNowTest001, TestSize.Level1)
{
    int32_t ret = ConnBleDisconnectNow(nullptr, BLE_DISCONNECT_REASON_FORCELY);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ConnBleDisconnectNowTest002
* @tc.desc: test ConnBleDisconnectNow protocol not support
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleDisconnectNowTest002, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(nullptr));

    int32_t ret = ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_FORCELY);
    EXPECT_EQ(ret, SOFTBUS_CONN_BLE_INTERNAL_ERR);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleDisconnectNowTest003
* @tc.desc: test ConnBleDisconnectNow CONN_SIDE_CLIENT success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleDisconnectNowTest003, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    BleUnifyInterface interface;
    interface.bleClientDisconnect = [](ConnBleConnection *conn, bool grace, bool refreshGatt) -> int32_t {
        return SOFTBUS_OK;
    };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(&interface));
    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));

    int32_t ret = ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_FORCELY);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleDisconnectNowTest004
* @tc.desc: test ConnBleDisconnectNow CONN_SIDE_SERVER success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleDisconnectNowTest004, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_SERVER);
    ASSERT_NE(connection, nullptr);
    BleUnifyInterface interface;
    interface.bleServerDisconnect = [](ConnBleConnection *conn) -> int32_t { return SOFTBUS_OK; };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(&interface));
    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));

    int32_t ret = ConnBleDisconnectNow(connection, BLE_DISCONNECT_REASON_FORCELY);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleUpdateConnectionRcTest001
* @tc.desc: test ConnBleUpdateConnectionRc connection is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleUpdateConnectionRcTest001, TestSize.Level1)
{
    int32_t ret = ConnBleUpdateConnectionRc(nullptr, 100, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ConnBleUpdateConnectionRcTest002
* @tc.desc: test ConnBleUpdateConnectionRc NeedProccessOccupy
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleUpdateConnectionRcTest002, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    connection->featureBitSet = (1 << BLE_FEATURE_SUPPORT_REMOTE_DISCONNECT);
    connection->isOccupied = true;
    BleUnifyInterface interface;
    interface.bleClientDisconnect = [](ConnBleConnection *conn, bool grace, bool refreshGatt) -> int32_t {
        return SOFTBUS_OK;
    };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillRepeatedly(Return(&interface));
    EXPECT_CALL(mock, SoftBusMutexLockHook(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlockHook(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _)).WillRepeatedly(Return());

    ConnBleUpdateConnectionRc(connection, 100, 1);
    EXPECT_EQ(connection->connectionRc, 0);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleUpdateConnectionPriorityTest001
* @tc.desc: test ConnBleUpdateConnectionPriority connection is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleUpdateConnectionPriorityTest001, TestSize.Level1)
{
    int32_t ret = ConnBleUpdateConnectionPriority(nullptr, CONN_BLE_PRIORITY_HIGH);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ConnBleUpdateConnectionPriorityTest002
* @tc.desc: test ConnBleUpdateConnectionPriority CONN_SIDE_SERVER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleUpdateConnectionPriorityTest002, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_SERVER);
    ASSERT_NE(connection, nullptr);

    int32_t ret = ConnBleUpdateConnectionPriority(connection, CONN_BLE_PRIORITY_HIGH);
    EXPECT_EQ(ret, SOFTBUS_FUNC_NOT_SUPPORT);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleUpdateConnectionPriorityTest003
* @tc.desc: test ConnBleUpdateConnectionPriority ble connection update connection priority fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleUpdateConnectionPriorityTest003, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(nullptr));

    int32_t ret = ConnBleUpdateConnectionPriority(connection, CONN_BLE_PRIORITY_HIGH);
    EXPECT_EQ(ret, SOFTBUS_CONN_BLE_INTERNAL_ERR);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleSendTest001
* @tc.desc: test ConnBleSend connection is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleSendTest001, TestSize.Level1)
{
    uint8_t data[] = {0x01, 0x02, 0x03};
    int32_t ret = ConnBleSend(nullptr, data, sizeof(data), 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ConnBleSendTest002
* @tc.desc: test ConnBleSend data is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleSendTest002, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    int32_t ret = ConnBleSend(connection, nullptr, 10, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleSendTest003
* @tc.desc: test ConnBleSend data len is 0
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleSendTest003, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    uint8_t data[] = {0x01, 0x02, 0x03};
    int32_t ret = ConnBleSend(connection, data, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleSendTest004
* @tc.desc: test ConnBleSend ble connection send data fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleSendTest004, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    uint8_t data[] = {0x01, 0x02, 0x03};
    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(nullptr));

    int32_t ret = ConnBleSend(connection, data, sizeof(data), 0);
    EXPECT_EQ(ret, SOFTBUS_CONN_BLE_INTERNAL_ERR);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleSendTest005
* @tc.desc: test ConnBleSend CONN_SIDE_CLIENT success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleSendTest005, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    BleUnifyInterface interface;
    interface.bleClientSend = [](
        ConnBleConnection *conn, const uint8_t *data, uint32_t dataLen, int32_t module) -> int32_t {
            return SOFTBUS_OK;
        };

    uint8_t data[] = {0x01, 0x02, 0x03};
    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(&interface));

    int32_t ret = ConnBleSend(connection, data, sizeof(data), 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleSendTest006
* @tc.desc: test ConnBleSend CONN_SIDE_SERVER success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleSendTest006, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_SERVER);
    ASSERT_NE(connection, nullptr);
    BleUnifyInterface interface;
    interface.bleServerSend = [](
        ConnBleConnection *conn, const uint8_t *data, uint32_t dataLen, int32_t module) -> int32_t {
            return SOFTBUS_OK;
        };

    uint8_t data[] = {0x01, 0x02, 0x03};
    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillOnce(Return(&interface));

    int32_t ret = ConnBleSend(connection, data, sizeof(data), 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleRefreshIdleTimeoutTest001
* @tc.desc: test ConnBleRefreshIdleTimeout no need refresh idle timeout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleRefreshIdleTimeoutTest001, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    connection->isNeedSetIdleTimeout = false;

    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));

    ConnBleRefreshIdleTimeout(connection);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleRefreshIdleTimeoutTest002
* @tc.desc: test ConnBleRefreshIdleTimeout success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleRefreshIdleTimeoutTest002, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));
    EXPECT_CALL(mock, ConnPostMsgToLooperHook(_, _, _, _, _, _)).WillOnce(Return(SOFTBUS_OK));

    ConnBleRefreshIdleTimeout(connection);
    EXPECT_EQ(connection->isNeedSetIdleTimeout, true);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleCancelIdleTimeoutTest001
* @tc.desc: test ConnBleCancelIdleTimeout fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleCancelIdleTimeoutTest001, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));

    ConnBleCancelIdleTimeout(nullptr);

    ConnBleCancelIdleTimeout(connection);
    EXPECT_EQ(connection->isNeedSetIdleTimeout, true);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleOccupyTest001
* @tc.desc: test ConnBleOccupy fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleOccupyTest001, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));
    EXPECT_CALL(mock, ConnPostMsgToLooperHook(_, _, _, _, _, _)).WillOnce(Return(SOFTBUS_ERR));

    ConnBleOccupy(nullptr);

    ConnBleOccupy(connection);
    EXPECT_EQ(connection->isOccupied, false);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleInnerComplementDeviceIdTest001
* @tc.desc: test ConnBleInnerComplementDeviceId udid already exist
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleInnerComplementDeviceIdTest001, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    strcpy_s(connection->udid, UDID_BUF_LEN, "test_udid");
    ConnBleInnerComplementDeviceId(connection);
    EXPECT_EQ(strcmp(connection->udid, "test_udid"), 0);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleInnerComplementDeviceIdTest002
* @tc.desc: test ConnBleInnerComplementDeviceId network id not exchange yet
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleInnerComplementDeviceIdTest002, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    ConnBleInnerComplementDeviceId(connection);
    EXPECT_EQ(strlen(connection->udid), 0);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleInnerComplementDeviceIdTest003
* @tc.desc: test ConnBleInnerComplementDeviceId get udid success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleInnerComplementDeviceIdTest003, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    strcpy_s(connection->networkId, NETWORK_ID_BUF_LEN, "test_network_id");

    EXPECT_CALL(mock, LnnGetRemoteStrInfoHook(_, STRING_KEY_DEV_UDID, _, _))
        .WillOnce(DoAll([](const char *, InfoKey, char *info, uint32_t len) {
            if (info != nullptr && len > 0) {
                strcpy_s(info, len, "test_udid");
            }
        }, Return(SOFTBUS_OK)));

    ConnBleInnerComplementDeviceId(connection);
    EXPECT_EQ(strcmp(connection->udid, "test_udid"), 0);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleInnerComplementDeviceIdTest004
* @tc.desc: test ConnBleInnerComplementDeviceId LnnGetRemoteStrInfo failed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleInnerComplementDeviceIdTest004, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    strcpy_s(connection->networkId, NETWORK_ID_BUF_LEN, "test_network_id");

    EXPECT_CALL(mock, LnnGetRemoteStrInfoHook(_, STRING_KEY_DEV_UDID, _, _))
        .WillOnce(Return(SOFTBUS_ERR));

    ConnBleInnerComplementDeviceId(connection);
    EXPECT_EQ(strlen(connection->udid), 0);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleOnReferenceRequestTest001
* @tc.desc: test ConnBleOnReferenceRequest invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleOnReferenceRequestTest001, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    int32_t ret = ConnBleOnReferenceRequest(nullptr, json);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    cJSON_Delete(json);
}

/*
* @tc.name: ConnBleOnReferenceRequestTest002
* @tc.desc: test ConnBleOnReferenceRequest parse delta or reference number fields fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleOnReferenceRequestTest002, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    int32_t ret = ConnBleOnReferenceRequest(connection, nullptr);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleOnReferenceRequestTest003
* @tc.desc: test ConnBleOnReferenceRequest
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleOnReferenceRequestTest003, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);
    connection->isOccupied = false;
    BleUnifyInterface interface;
    interface.bleClientDisconnect = [](ConnBleConnection *conn, bool grace, bool refreshGatt) -> int32_t {
        return SOFTBUS_OK;
    };

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "delta", 1);
    cJSON_AddNumberToObject(json, "referenceNumber", 0);
    cJSON_AddNumberToObject(json, "challenge", 100);

    EXPECT_CALL(mock, SoftBusMutexLockHook(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlockHook(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(BLE_GATT)).WillRepeatedly(Return(&interface));
    EXPECT_CALL(mock, GetJsonObjectSignedNumberItemHook(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetJsonObjectNumber16ItemHook(_, _, _)).WillRepeatedly(Return(true));

    ConnBleOnReferenceRequest(connection, json);
    EXPECT_EQ(connection->connectionRc, 0);

    cJSON_Delete(json);
    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleRemoveExchangeBasicInfoTimeoutEventTest001
* @tc.desc: test ConnBleRemoveExchangeBasicInfoTimeoutEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleRemoveExchangeBasicInfoTimeoutEventTest001, TestSize.Level1)
{
    BleConnectionTestMock mock;
    const char *addr = "11:22:33:44:55:66";
    ConnBleConnection *connection = CreateTestConnection(addr, BLE_GATT, CONN_SIDE_CLIENT);
    ASSERT_NE(connection, nullptr);

    EXPECT_CALL(mock, ConnRemoveMsgFromLooperHook(_, _, _, _, _));

    ConnBleRemoveExchangeBasicInfoTimeoutEvent(connection);

    FreeTestConnection(connection);
}

/*
* @tc.name: ConnBleStartServerTest001
* @tc.desc: test ConnBleStartServer
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleStartServerTest001, TestSize.Level1)
{
    BleConnectionTestMock mock;
    BleUnifyInterface interface;
    interface.bleServerStartService = []() -> int32_t { return SOFTBUS_OK; };

    EXPECT_CALL(mock, SoftBusMutexLockHook(_)).WillRepeatedly(Return(SOFTBUS_LOCK_ERR));

    int32_t ret = ConnBleStartServer();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: ConnBleStopServerTest001
* @tc.desc: test ConnBleStopServer
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleStopServerTest001, TestSize.Level1)
{
    BleConnectionTestMock mock;
    BleUnifyInterface interface;
    interface.bleServerStopService = []() -> int32_t { return SOFTBUS_OK; };

    EXPECT_CALL(mock, SoftBusMutexLockHook(_)).WillRepeatedly(Return(SOFTBUS_LOCK_ERR));

    int32_t ret = ConnBleStopServer();
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
* @tc.name: ConnBleInitConnectionMuduleTest001
* @tc.desc: test ConnBleInitConnectionMudule looper is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest001, TestSize.Level1)
{
    ConnBleConnectionEventListener listener = {};
    int32_t ret = ConnBleInitConnectionMudule(nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ConnBleInitConnectionMuduleTest002
* @tc.desc: test ConnBleInitConnectionMudule listener is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest002, TestSize.Level1)
{
    SoftBusLooper looper;
    int32_t ret = ConnBleInitConnectionMudule(&looper, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest003
 * @tc.desc: test ConnBleInitConnectionMudule listener onServerAccepted is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest003, TestSize.Level1)
{
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = nullptr,
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest004
 * @tc.desc: test ConnBleInitConnectionMudule listener onConnected is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest004, TestSize.Level1)
{
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = nullptr,
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest005
 * @tc.desc: test ConnBleInitConnectionMudule listener onConnectFailed is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest005, TestSize.Level1)
{
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = nullptr,
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest006
 * @tc.desc: test ConnBleInitConnectionMudule listener onDataReceived is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest006, TestSize.Level1)
{
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = nullptr,
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest007
 * @tc.desc: test ConnBleInitConnectionMudule listener onConnectionClosed is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest007, TestSize.Level1)
{
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = nullptr,
        .onConnectionResume = [](uint32_t) {}
    };
    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest008
 * @tc.desc: test ConnBleInitConnectionMudule listener onConnectionResume is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest008, TestSize.Level1)
{
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = nullptr
    };
    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest009
 * @tc.desc: test ConnBleInitConnectionMudule success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest009, TestSize.Level1)
{
    BleConnectionTestMock mock;
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    BleUnifyInterface interface;
    interface.bleClientInitModule = [](SoftBusLooper *, const ConnBleClientEventListener *) -> int32_t {
        return SOFTBUS_OK;
    };
    interface.bleServerInitModule = [](SoftBusLooper *, const ConnBleServerEventListener *) -> int32_t {
        return SOFTBUS_OK;
    };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(_)).WillRepeatedly(Return(&interface));
    EXPECT_CALL(mock, SoftBusMutexInitHook(_, _)).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest010
 * @tc.desc: test ConnBleInitConnectionMudule init ble client fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest010, TestSize.Level1)
{
    BleConnectionTestMock mock;
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    BleUnifyInterface interface;
    interface.bleClientInitModule = [](SoftBusLooper *, const ConnBleClientEventListener *) -> int32_t {
        return SOFTBUS_ERR;
    };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(_)).WillRepeatedly(Return(&interface));

    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest011
 * @tc.desc: test ConnBleInitConnectionMudule init ble server fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest011, TestSize.Level1)
{
    BleConnectionTestMock mock;
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    BleUnifyInterface interface;
    interface.bleClientInitModule = [](SoftBusLooper *, const ConnBleClientEventListener *) -> int32_t {
        return SOFTBUS_OK;
    };
    interface.bleServerInitModule = [](SoftBusLooper *, const ConnBleServerEventListener *) -> int32_t {
        return SOFTBUS_ERR;
    };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(_)).WillRepeatedly(Return(&interface));

    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: ConnBleInitConnectionMuduleTest012
 * @tc.desc: test ConnBleInitConnectionMudule init server coordination lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBleConnectionTest, ConnBleInitConnectionMuduleTest012, TestSize.Level1)
{
    BleConnectionTestMock mock;
    SoftBusLooper looper;
    ConnBleConnectionEventListener listener = {
        .onServerAccepted = [](uint32_t) {},
        .onConnected = [](uint32_t) {},
        .onConnectFailed = [](uint32_t, int32_t) {},
        .onDataReceived = [](uint32_t, bool, uint8_t *, uint32_t) {},
        .onConnectionClosed = [](uint32_t, int32_t) {},
        .onConnectionResume = [](uint32_t) {}
    };
    BleUnifyInterface interface;
    interface.bleClientInitModule = [](SoftBusLooper *, const ConnBleClientEventListener *) -> int32_t {
        return SOFTBUS_OK;
    };
    interface.bleServerInitModule = [](SoftBusLooper *, const ConnBleServerEventListener *) -> int32_t {
        return SOFTBUS_OK;
    };

    EXPECT_CALL(mock, ConnBleGetUnifyInterfaceHook(_)).WillRepeatedly(Return(&interface));
    EXPECT_CALL(mock, SoftBusMutexInitHook(_, _)).WillOnce(Return(SOFTBUS_LOCK_ERR));

    int32_t ret = ConnBleInitConnectionMudule(&looper, &listener);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}
} // namespace OHOS::SoftBus
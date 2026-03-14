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

#include "mock/br_connection_mock.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_manager.h"
#include "softbus_conn_br_trans.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "wrapper_br_interface.h"

#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

#define DEFAULT_BR_MTU 990
#define BR_WRITE_FAILED (-1)

namespace OHOS {
extern "C" {
void Init(const struct tagSppSocketDriver *sppDriver)
{
    (void)sppDriver;
    return;
}

int32_t Read(int32_t clientFd, uint8_t *buf, const int32_t length)
{
    (void)clientFd;
    (void)buf;
    if (length <= 0) {
        return BR_READ_SOCKET_CLOSED;
    }
    return length;
}

int32_t Write(int32_t clientFd, const uint8_t *buf, const int32_t length)
{
    (void)clientFd;
    (void)buf;
    if (length <= 1) {
        return BR_WRITE_FAILED;
    }
    if (length == DEFAULT_BR_MTU) {
        return CONN_BR_SEND_DATA_FAIL_UNDERLAYER_ERR_QUEUE_FULL;
    }
    return length;
}

int32_t Apply(struct ConnSlideWindowController *self, int32_t expect)
{
    (void)self;
    return expect;
}

int32_t Enable(struct ConnSlideWindowController *self, int32_t windowInMillis, int32_t quotaInBytes)
{
    (void)self;
    (void)windowInMillis;
    (void)quotaInBytes;
    return SOFTBUS_INVALID_PARAM;
}

int32_t Disable(struct ConnSlideWindowController *self)
{
    (void)self;
    return SOFTBUS_OK;
}

void OnDataReceived(uint32_t connectionId, uint8_t *data, uint32_t dataLen)
{
    (void)connectionId;
    (void)data;
    (void)dataLen;
    return;
}

void OnClientConnected(uint32_t connectionId)
{
    (void)connectionId;
    return;
}

void OnClientConnectFailed(uint32_t connectionId, int32_t reason)
{
    (void)connectionId;
    (void)reason;
    return;
}

void OnServerAccepted(uint32_t connectionId)
{
    (void)connectionId;
    return;
}

void OnConnectionException(uint32_t connectionId, int32_t reason)
{
    (void)connectionId;
    (void)reason;
    return;
}

void OnConnectionResume(uint32_t connectionId)
{
    (void)connectionId;
    return;
}
}

class BrConnectionTest : public testing::Test {
public:
    BrConnectionTest() { }
    ~BrConnectionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BrConnectionTest::SetUpTestCase(void)
{
    LooperInit();
}

void BrConnectionTest::TearDownTestCase(void)
{
    LooperDeinit();
}

void BrConnectionTest::SetUp(void) { }

void BrConnectionTest::TearDown(void) { }

SppSocketDriver g_sppDriver = {
    .Init = Init,
    .Read = Read,
    .Write = Write,
};

struct ConnSlideWindowController g_controller = {
    .apply = Apply,
    .enable = Enable,
    .disable = Disable,
};

ConnBrEventListener g_eventListener = {
    .onServerAccepted = OnServerAccepted,
    .onClientConnected = OnClientConnected,
    .onClientConnectFailed = OnClientConnectFailed,
    .onDataReceived = OnDataReceived,
    .onConnectionException = OnConnectionException,
    .onConnectionResume = OnConnectionResume,
};

HWTEST_F(BrConnectionTest, ConnBrCreateConnectionTest001, TestSize.Level1)
{
    ConnBrConnection *connection = ConnBrCreateConnection(NULL, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    EXPECT_EQ(nullptr, connection);
}

HWTEST_F(BrConnectionTest, ConnBrCreateConnectionTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    EXPECT_NE(nullptr, connection);
    if (connection != nullptr) {
        EXPECT_EQ(CONN_SIDE_CLIENT, connection->side);
        EXPECT_EQ(INVALID_SOCKET_HANDLE, connection->socketHandle);
        EXPECT_EQ(BR_CONNECTION_STATE_CONNECTING, connection->state);
        EXPECT_EQ(1, connection->connectionRc);
        EXPECT_EQ(1, connection->objectRc);
        ConnBrFreeConnection(connection);
    }
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrCreateConnectionTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_SERVER, 100);
    EXPECT_NE(nullptr, connection);
    if (connection != nullptr) {
        EXPECT_EQ(CONN_SIDE_SERVER, connection->side);
        EXPECT_EQ(100, connection->socketHandle);
        EXPECT_EQ(BR_CONNECTION_STATE_CONNECTED, connection->state);
        ConnBrFreeConnection(connection);
    }
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrCreateConnectionTest004, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillOnce(Return(SOFTBUS_LOCK_ERR));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    EXPECT_EQ(nullptr, connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrCreateConnectionTest005, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return((SoftBusList *)NULL));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    EXPECT_EQ(nullptr, connection);
}

HWTEST_F(BrConnectionTest, ConnBrFreeConnectionTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrFreeConnectionTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    connection->connectProcessStatus = NULL;
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrUpdateConnectionRcTest001, TestSize.Level1)
{
    int32_t ret = ConnBrUpdateConnectionRc(NULL, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrUpdateConnectionRcTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return((ConnBrConnection *)NULL));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrUpdateConnectionRc(connection, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrUpdateConnectionRcTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = false;
    testConnection->connectionRc = 1;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrUpdateConnectionRc(connection, 1);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrUpdateConnectionRcTest004, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = true;
    testConnection->connectionRc = 1;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrUpdateConnectionRc(connection, -1);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrUpdateConnectionRcTest005, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = false;
    testConnection->connectionRc = 1;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrUpdateConnectionRc(connection, -1);
    EXPECT_NE(SOFTBUS_OK, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceRequestTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    int32_t ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceRequestTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return((ConnBrConnection *)NULL));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_DELTA, 1);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceRequestTest004, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = false;
    testConnection->connectionRc = 1;
    testConnection->state = BR_CONNECTION_STATE_CONNECTED;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_DELTA, 1);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceRequestTest005, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = false;
    testConnection->connectionRc = 0;
    testConnection->state = BR_CONNECTION_STATE_CONNECTED;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_DELTA, -1);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceRequestTest006, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = true;
    testConnection->connectionRc = 1;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_DELTA, -1);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceRequestTest007, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    ConnBrConnection *testConnection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, testConnection);
    testConnection->connectionId = 1;
    testConnection->isOccupied = false;
    testConnection->connectionRc = 1;
    testConnection->state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
    
    EXPECT_CALL(brMock, ConnBrGetConnectionById).WillOnce(Return(testConnection));
    EXPECT_CALL(brMock, ConnBrReturnConnection).WillOnce(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_DELTA, 1);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(BR_CONNECTION_STATE_NEGOTIATION_CLOSING, testConnection->state);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(testConnection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceResponseTest001, TestSize.Level1)
{
    int32_t ret = ConnBrOnReferenceResponse(NULL, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceResponseTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    int32_t ret = ConnBrOnReferenceResponse(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceResponseTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceResponse(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceResponseTest004, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    connection->state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceResponse(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(BR_CONNECTION_STATE_NEGOTIATION_CLOSING, connection->state);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceResponseTest005, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    connection->state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 0);
    int32_t ret = ConnBrOnReferenceResponse(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(BR_CONNECTION_STATE_NEGOTIATION_CLOSING, connection->state);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOnReferenceResponseTest006, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    connection->state = BR_CONNECTION_STATE_CLOSING;
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_REFERENCE_NUM, 1);
    int32_t ret = ConnBrOnReferenceResponse(connection, json);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(BR_CONNECTION_STATE_CLOSING, connection->state);
    cJSON_Delete(json);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrConnectTest001, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, ConnStartActionAsync).WillOnce(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrConnect(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrConnectTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, ConnStartActionAsync).WillOnce(Return(SOFTBUS_LOCK_ERR));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrConnect(connection);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrConnectTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, ConnStartActionAsync).WillOnce(Return(SOFTBUS_MALLOC_ERR));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrConnect(connection);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrDisconnectNowTest001, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrDisconnectNow(connection);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(BR_CONNECTION_STATE_CONNECTING, connection->state);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrDisconnectNowTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusSleepMs).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, 100);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrDisconnectNow(connection);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(BR_CONNECTION_STATE_CONNECTING, connection->state);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrDisconnectNowTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, 100);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrDisconnectNow(connection);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrStartServerTest001, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrStartServer();
    EXPECT_NE(SOFTBUS_OK, ret);
    
    ret = ConnBrStopServer();
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BrConnectionTest, ConnBrStopServerTest001, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrStopServer();
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(BrConnectionTest, ConnBrStartServerTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrStartServer();
    EXPECT_NE(SOFTBUS_MALLOC_ERR, ret);
}

HWTEST_F(BrConnectionTest, ConnBrRefreshIdleTimeoutTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    ConnBrRefreshIdleTimeout(connection);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrRefreshIdleTimeoutTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    connection->enableIdleCheck = false;
    ConnBrRefreshIdleTimeout(connection);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrSetIdleCheckTest001, TestSize.Level1)
{
    int32_t ret = ConnBrSetIdleCheck(NULL, true);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrSetIdleCheckTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrSetIdleCheck(connection, true);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(true, connection->enableIdleCheck);
    ret = ConnBrSetIdleCheck(connection, false);
    EXPECT_NE(SOFTBUS_OK, ret);
    EXPECT_EQ(true, connection->enableIdleCheck);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrSetIdleCheckTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    int32_t ret = ConnBrSetIdleCheck(connection, true);
    EXPECT_NE(SOFTBUS_LOCK_ERR, ret);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOccupyTest002, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    ConnBrOccupy(connection);
    EXPECT_NE(true, connection->isOccupied);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOccupyTest003, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    ConnBrOccupy(connection);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrOccupyTest004, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    SoftBusList *list = (SoftBusList *)SoftBusCalloc(sizeof(SoftBusList));
    ListInit(&list->list);
    EXPECT_CALL(brMock, CreateSoftBusList).WillOnce(Return(list));
    EXPECT_CALL(brMock, SoftBusMutexDestroy).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, DestroySoftBusList).WillRepeatedly(Return());
    EXPECT_CALL(brMock, SoftBusMutexLockInner).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusMutexUnlockInner).WillRepeatedly(Return(SOFTBUS_OK));
    
    char addr[BT_MAC_LEN] = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ASSERT_NE(nullptr, connection);
    ConnBrOccupy(connection);
    ConnBrFreeConnection(connection);
    SoftBusFree(list);
}

HWTEST_F(BrConnectionTest, ConnBrConnectionMuduleInitTest001, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(BrConnectionInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(BrConnectionInterfaceMock::ActionOfSoftbusGetConfig2);
    
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(nullptr, looper);
    
    int32_t ret = ConnBrConnectionMuduleInit(looper, &g_sppDriver, &g_eventListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(BrConnectionTest, ConnBrConnectionMuduleInitTest002, TestSize.Level1)
{
    int32_t ret = ConnBrConnectionMuduleInit(NULL, &g_sppDriver, &g_eventListener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrConnectionMuduleInitTest003, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(nullptr, looper);
    
    int32_t ret = ConnBrConnectionMuduleInit(looper, NULL, &g_eventListener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrConnectionMuduleInitTest004, TestSize.Level1)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(nullptr, looper);
    
    int32_t ret = ConnBrConnectionMuduleInit(looper, &g_sppDriver, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrConnectionMuduleInitTest006, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_NO_INIT));
    
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(nullptr, looper);
    
    int32_t ret = ConnBrConnectionMuduleInit(looper, &g_sppDriver, &g_eventListener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

HWTEST_F(BrConnectionTest, ConnBrConnectionMuduleInitTest007, TestSize.Level1)
{
    BrConnectionInterfaceMock brMock;
    EXPECT_CALL(brMock, SoftBusMutexInit).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(BrConnectionInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(Return(SOFTBUS_NO_INIT));
    
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    ASSERT_NE(nullptr, looper);
    
    int32_t ret = ConnBrConnectionMuduleInit(looper, &g_sppDriver, &g_eventListener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
}
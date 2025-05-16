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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#include "general_connection_server_proxy.h"
#include "softbus_connection.h"
#include "softbus_error_code.h"
#include "client_connection_mock_test.h"

using namespace testing::ext;
namespace OHOS {
namespace {
class ClientConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ClientConnectionTest::SetUpTestCase()
{
}

void ClientConnectionTest::TearDownTestCase() { }

void ClientConnectionTest::SetUp() { }

void ClientConnectionTest::TearDown() { }

static int32_t OnAcceptConnect(const char *name, uint32_t handle)
{
    printf("OnAcceptConnect called, name: %s, handle: %u\n", name, handle);
    return 0;
}

static int32_t OnConnectionStateChange(uint32_t handle, int32_t state, int32_t reason)
{
    printf("OnConnectionStateChange called, handle: %u, state: %d, reason: %d\n", handle, state, reason);
    return 0;
}

static void OnDataRecevied(uint32_t handle, const uint8_t *data, uint32_t len)
{
    printf("OnDataRecevied called, handle: %u, data: %s, len: %u\n", handle, data, len);
}

static void OnServiceDied(void)
{
    printf("OnServiceDied called\n");
}

static IGeneralListener g_listener = {
    .OnAcceptConnect = OnAcceptConnect,
    .OnConnectionStateChange = OnConnectionStateChange,
    .OnDataReceived = OnDataRecevied,
    .OnServiceDied = OnServiceDied,
};

/*
 * @tc.name: RegisterListenerTest
 * @tc.desc: register listener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, RegisterListenerTest, TestSize.Level0)
{
    int32_t ret = GeneralRegisterListener(nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testing::NiceMock<ClientConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusMutexInit).WillOnce(testing::Return(-1));
    ret = GeneralRegisterListener(&g_listener);
    ASSERT_EQ(ret, SOFTBUS_LOCK_ERR);

    EXPECT_CALL(mock, SoftBusMutexInit).WillOnce(testing::Return(SOFTBUS_OK));
    ret = GeneralRegisterListener(&g_listener);
    ASSERT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: UnregisterListenerTest
 * @tc.desc: unregister listener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, UnregisterListenerTest, TestSize.Level0)
{
    int32_t ret = GeneralUnregisterListener();
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: CreateServerTest
 * @tc.desc: create server test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, CreateServerTest, TestSize.Level0)
{
    int32_t ret = GeneralCreateServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralCreateServer("ohos.distributedschedule.dms", nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralCreateServer("smd", "1234");
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testing::NiceMock<ClientConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, InitSoftBus).WillOnce(testing::Return(-1));
    ret = GeneralCreateServer("ohos.distributedschedule.dms", "1234");
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, InitSoftBus).WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ServerIpcCreateServer).WillOnce(testing::Return(-1));
    ret = GeneralCreateServer("ohos.distributedschedule.dms", "1234");
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, InitSoftBus).WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ServerIpcCreateServer).WillOnce(testing::Return(SOFTBUS_OK));
    ret = GeneralCreateServer("ohos.distributedschedule.dms", "1234");
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: RemoveServerTest
 * @tc.desc: remove server test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, RemoveServerTest, TestSize.Level0)
{
    int32_t ret = GeneralRemoveServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testing::NiceMock<ClientConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, ServerIpcRemoveServer).WillOnce(testing::Return(-1));
    ret = GeneralRemoveServer("ohos.distributedschedule.dms", "1234");
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, ServerIpcRemoveServer).WillOnce(testing::Return(SOFTBUS_OK));
    ret = GeneralRemoveServer("ohos.distributedschedule.dms", "1234");
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectTest
 * @tc.desc: connect test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, ConnectTest, TestSize.Level0)
{
    int32_t ret = GeneralConnect(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralConnect("ohos.distributedschedule.dms", "1234", nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testing::NiceMock<ClientConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, InitSoftBus).WillOnce(testing::Return(-1));
    Address addr;
    ret = GeneralConnect("ohos.distributedschedule.dms", "1234", &addr);
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, InitSoftBus).WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ServerIpcConnect).WillOnce(testing::Return(-1));
    ret = GeneralConnect("ohos.distributedschedule.dms", "1234", &addr);
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, InitSoftBus).WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ServerIpcConnect).WillOnce(testing::Return(SOFTBUS_OK));
    ret = GeneralConnect("ohos.distributedschedule.dms", "1234", &addr);
    ASSERT_EQ(ret, SOFTBUS_OK);

    GeneralDisconnect(-1);
    EXPECT_CALL(mock, ServerIpcDisconnect).WillOnce(testing::Return(-1));
    GeneralDisconnect(1);
    EXPECT_CALL(mock, ServerIpcDisconnect).WillOnce(testing::Return(SOFTBUS_OK));
    GeneralDisconnect(1);
}

/*
 * @tc.name: SendTest
 * @tc.desc: send test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, SendTest, TestSize.Level0)
{
    int32_t ret = GeneralSend(-1, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralSend(1, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralSend(1, (const uint8_t *)"1234", 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralSend(1, (const uint8_t *)"1234", GENERAL_SEND_DATA_MAX_LEN + 1);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testing::NiceMock<ClientConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, ServerIpcSend).WillOnce(testing::Return(-1));
    ret = GeneralSend(1, (const uint8_t *)"1234", 4);
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, ServerIpcSend).WillOnce(testing::Return(SOFTBUS_OK));
    ret = GeneralSend(1, (const uint8_t *)"1234", 4);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnGetPeerDeviceIdTest
 * @tc.desc: conn get peer device id test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientConnectionTest, ConnGetPeerDeviceIdTest, TestSize.Level0)
{
    int32_t ret = GeneralGetPeerDeviceId(-1, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralGetPeerDeviceId(1, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    char deviceId[10] = { 0 };
    ret = GeneralGetPeerDeviceId(1, deviceId, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GeneralGetPeerDeviceId(1, deviceId, BT_MAC_LEN + 1);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testing::NiceMock<ClientConnectionInterfaceMock> mock;
    EXPECT_CALL(mock, ServerIpcGetPeerDeviceId).WillOnce(testing::Return(-1));
    ret = GeneralGetPeerDeviceId(1, deviceId, 10);
    ASSERT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, ServerIpcGetPeerDeviceId).WillOnce(testing::Return(SOFTBUS_OK));
    ret = GeneralGetPeerDeviceId(1, deviceId, 10);
    ASSERT_EQ(ret, SOFTBUS_OK);
}
}
} // namespace OHOS

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

#include "wrapper_br_interface_mock.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include <securec.h>
#include "softbus_common.h"
#include "softbus_utils.h"

using namespace testing;
using namespace testing::ext;
#define TEST_BR_WRAPPER_INTERFACE_UUID "11111111-200a-11e0-ac64-0800200c9a66"

namespace OHOS {
extern "C" {
void TestBrConnectStatusCallback(const BdAddr *bdAddr, BtUuid uuid, int32_t status, int32_t result)
{
    (void)bdAddr;
    (void)uuid;
    (void)status;
    (void)result;
}
}
static SppSocketDriver *g_sppSocketDriver = nullptr;
class WrapperBrInterfaceTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void WrapperBrInterfaceTest::SetUpTestCase(void)
{
    g_sppSocketDriver = InitSppSocketDriver();
    ASSERT_NE(g_sppSocketDriver, nullptr);
}

void WrapperBrInterfaceTest::TearDownTestCase(void) { }

void WrapperBrInterfaceTest::SetUp() { }

void WrapperBrInterfaceTest::TearDown() { }

/*
 * @tc.name: OpenSppServer
 * @tc.desc: OpenSppServer CloseSppServer Accept GetSppServerPort
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(WrapperBrInterfaceTest, OpenSppServer, TestSize.Level1)
{
    int32_t ret = g_sppSocketDriver->OpenSppServer(nullptr, 0, TEST_BR_WRAPPER_INTERFACE_UUID, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const char *name = "TestBrWrapperInterface";
    int32_t serverFd = 1;
    int32_t socketHandle = 1;
    int32_t serverPort = 1;
    NiceMock<WrapperBrInterfaceMock> wrapperBrInterfaceMock;
    EXPECT_CALL(wrapperBrInterfaceMock, SppServerCreate).WillRepeatedly(Return(serverFd));
    ret = g_sppSocketDriver->OpenSppServer(name, (int32_t)strlen(name), TEST_BR_WRAPPER_INTERFACE_UUID, 0);
    EXPECT_EQ(ret, serverFd);

    EXPECT_CALL(wrapperBrInterfaceMock, SppServerAccept).WillOnce(Return(BT_SPP_INVALID_ID));
    ret = g_sppSocketDriver->Accept(serverFd);
    EXPECT_EQ(ret, SOFTBUS_CONN_BR_SPP_SERVER_ERR);
    EXPECT_CALL(wrapperBrInterfaceMock, SppServerAccept).WillRepeatedly(Return(socketHandle));
    ret = g_sppSocketDriver->Accept(serverFd);
    EXPECT_EQ(ret, socketHandle);

    EXPECT_CALL(wrapperBrInterfaceMock, SocketGetScn).WillRepeatedly(Return(serverPort));
    ret = g_sppSocketDriver->GetSppServerPort(serverFd);
    EXPECT_CALL(wrapperBrInterfaceMock, SppServerClose).WillRepeatedly(Return(serverFd));
    g_sppSocketDriver->CloseSppServer(serverFd);
    EXPECT_EQ(ret, serverPort);
}

/*
 * @tc.name: Connect
 * @tc.desc: Connect IsConnected UpdatePriority SppDisconnect DisConnect IsAclConnected
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(WrapperBrInterfaceTest, Connect, TestSize.Level1)
{
    uint8_t binaryAddr[BT_ADDR_LEN] = {0};
    char brMac[BT_MAC_LEN] = {'0'};
    (void)strcpy_s(brMac, BT_MAC_LEN, "11:22:33:44:55:66");
    int32_t clientFd = 1;
    int32_t ret = ConvertBtMacToBinary(brMac, BT_MAC_LEN, binaryAddr, BT_ADDR_LEN);
    ASSERT_EQ(ret, SOFTBUS_OK);
    BtSocketConnectionCallback callback = {
        .connStateCb = TestBrConnectStatusCallback,
    };
    ret = g_sppSocketDriver->Connect(TEST_BR_WRAPPER_INTERFACE_UUID, nullptr, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = g_sppSocketDriver->Connect(nullptr, binaryAddr, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<WrapperBrInterfaceMock> wrapperBrInterfaceMock;
    EXPECT_CALL(wrapperBrInterfaceMock, SocketConnectEx).WillOnce(Return(-1));
    ret = g_sppSocketDriver->Connect(TEST_BR_WRAPPER_INTERFACE_UUID, binaryAddr, &callback);
    EXPECT_EQ(ret, SOFTBUS_CONN_BR_SOCKET_CONNECT_ERR);
    EXPECT_CALL(wrapperBrInterfaceMock, SocketConnectEx).WillOnce(Return(-3));
    ret = g_sppSocketDriver->Connect(TEST_BR_WRAPPER_INTERFACE_UUID, binaryAddr, &callback);
    EXPECT_EQ(ret, SOFTBUS_CONN_BR_SOCKET_LIMITED_RESOURCES);
    EXPECT_CALL(wrapperBrInterfaceMock, SocketConnectEx).WillRepeatedly(Return(clientFd));
    ret = g_sppSocketDriver->Connect(TEST_BR_WRAPPER_INTERFACE_UUID, binaryAddr, &callback);
    EXPECT_EQ(ret, clientFd);

    EXPECT_CALL(wrapperBrInterfaceMock, IsSppConnected).WillRepeatedly(Return(true));
    bool isConnected = g_sppSocketDriver->IsConnected(clientFd);
    EXPECT_EQ(isConnected, true);

    EXPECT_CALL(wrapperBrInterfaceMock, SetConnectionPriority).WillRepeatedly(Return(SOFTBUS_OK));
    g_sppSocketDriver->UpdatePriority(binaryAddr, CONN_BR_CONNECT_PRIORITY_DEFAULT);
    g_sppSocketDriver->UpdatePriority(binaryAddr, CONN_BR_CONNECT_PRIORITY_NON_PREEMPTIBLE);
    g_sppSocketDriver->UpdatePriority(binaryAddr, (ConnBrConnectPriority)-1);
    ret = g_sppSocketDriver->UpdatePriority(binaryAddr, CONN_BR_CONNECT_PRIORITY_NO_REFUSE_FREQUENT_CONNECT);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(wrapperBrInterfaceMock, SppDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_sppSocketDriver->DisConnect(clientFd);
    EXPECT_EQ(ret, SOFTBUS_OK);

    isConnected = IsAclConnected(binaryAddr);
    EXPECT_EQ(isConnected, false);
}

/*
 * @tc.name: Write
 * @tc.desc: Write Read GetRemoteDeviceInfo
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(WrapperBrInterfaceTest, Write, TestSize.Level1)
{
    uint8_t binaryAddr[BT_ADDR_LEN] = {0};
    char brMac[BT_MAC_LEN] = {'0'};
    (void)strcpy_s(brMac, BT_MAC_LEN, "11:22:33:44:55:66");
    int32_t clientFd = 1;
    uint8_t data[1] = {0};
    int32_t ret = ConvertBtMacToBinary(brMac, BT_MAC_LEN, binaryAddr, BT_ADDR_LEN);
    ASSERT_EQ(ret, SOFTBUS_OK);
    BtSocketConnectionCallback callback = {
        .connStateCb = TestBrConnectStatusCallback,
    };
    NiceMock<WrapperBrInterfaceMock> wrapperBrInterfaceMock;
    EXPECT_CALL(wrapperBrInterfaceMock, SocketConnectEx).WillRepeatedly(Return(clientFd));
    ret = g_sppSocketDriver->Connect(TEST_BR_WRAPPER_INTERFACE_UUID, binaryAddr, &callback);
    EXPECT_EQ(ret, clientFd);

    BluetoothRemoteDevice remote;
    (void)memset_s(&remote, sizeof(remote), 0, sizeof(remote));
    EXPECT_CALL(wrapperBrInterfaceMock, SppGetRemoteAddr).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_sppSocketDriver->GetRemoteDeviceInfo(clientFd, &remote);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(wrapperBrInterfaceMock, SppWrite).WillRepeatedly(Return(1));
    ret = g_sppSocketDriver->Write(clientFd, data, 1);
    EXPECT_EQ(ret, 1);

    EXPECT_CALL(wrapperBrInterfaceMock, SppRead).WillRepeatedly(Return(BT_SPP_READ_SOCKET_CLOSED));
    ret = g_sppSocketDriver->Read(clientFd, data, 1);
    EXPECT_EQ(ret, BT_SPP_READ_SOCKET_CLOSED);
    EXPECT_CALL(wrapperBrInterfaceMock, SppRead).WillRepeatedly(Return(BT_SPP_READ_FAILED));
    ret = g_sppSocketDriver->Read(clientFd, data, 1);
    EXPECT_EQ(ret, BT_SPP_READ_FAILED);
    EXPECT_CALL(wrapperBrInterfaceMock, SppRead).WillRepeatedly(Return(1));
    ret = g_sppSocketDriver->Read(clientFd, data, 1);
    EXPECT_EQ(ret, 1);

    EXPECT_CALL(wrapperBrInterfaceMock, SppDisconnect).WillRepeatedly(Return(SOFTBUS_OK));
    ret = g_sppSocketDriver->DisConnect(clientFd);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
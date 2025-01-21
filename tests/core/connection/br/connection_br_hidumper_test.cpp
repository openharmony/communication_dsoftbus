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

#include "mock/softbus_conn_br_connection_mock.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_snapshot.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "wrapper_br_interface.h"

using namespace testing;
using namespace testing::ext;

#define BR_READ_FAILED  (-1)
#define BR_WRITE_FAILED (-2)

namespace OHOS {

ConnectFuncInterface *connectFuncInterface = NULL;
ConnectFuncInterface *g_connectFuncInterface = NULL;

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
    if (length <= 0) {
        return BR_WRITE_FAILED;
    }
    return SOFTBUS_OK;
}

SppSocketDriver g_sppDriver = {
    .Init = Init,
    .Read = Read,
    .Write = Write,
};

void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
    return;
}

class SoftbusConnBrHiDumperTest : public testing::Test {
public:
    SoftbusConnBrHiDumperTest() { }
    ~SoftbusConnBrHiDumperTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SoftbusConnBrHiDumperTest::SetUpTestCase(void)
{
    LooperInit();
    SoftbusConfigInit();
    ConnectionBrInterfaceMock brMock;
    EXPECT_CALL(brMock, InitSppSocketDriver).WillRepeatedly(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig).WillRepeatedly(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1);
    ConnServerInit();
}

void SoftbusConnBrHiDumperTest::TearDownTestCase(void)
{
    LooperDeinit();
}

void SoftbusConnBrHiDumperTest::SetUp(void) { }

void SoftbusConnBrHiDumperTest::TearDown(void) { }

int32_t GetBrConnStateByConnectionId(uint32_t connectId)
{
    (void)connectId;
    return BR_CONNECTION_STATE_CLOSED;
}

ConnectFuncInterface *ConnInit(void)
{
    LooperInit();

    ConnectCallback callback = {
        .OnConnected = OnConnected,
        .OnDisconnected = OnDisconnected,
        .OnDataReceived = OnDataReceived,
    };
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig2);
    EXPECT_CALL(brMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusAddBtStateListener).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, ConnBrInitBrPendingPacket).WillOnce(Return(SOFTBUS_OK));

    connectFuncInterface = ConnInitBr(&callback);
    return connectFuncInterface;
}

/*
 * @tc.name: BrHiDumperTest
 * @tc.desc: test dump method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusConnBrHiDumperTest, BrHiDumperTest, TestSize.Level1)
{
    g_connectFuncInterface = ConnInit();
    const char *addr1 = "11:22:33:44:55:66";
    const char *addr2 = "22:33:44:55:66:77";
    ConnBrConnection *connection1 = ConnBrCreateConnection(addr1, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection1);
    ConnBrConnection *connection2 = ConnBrCreateConnection(addr2, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection2);
    int fd = 1;
    auto ret = BrHiDumper(fd);
    ASSERT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS
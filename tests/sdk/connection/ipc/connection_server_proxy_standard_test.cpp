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

#include "general_connection_server_proxy_standard.h"
#include "softbus_error_code.h"

using namespace testing::ext;
namespace OHOS {
namespace {
class ConnectionServerProxyStandardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConnectionServerProxyStandardTest::SetUpTestCase() { }

void ConnectionServerProxyStandardTest::TearDownTestCase() { }

void ConnectionServerProxyStandardTest::SetUp() { }

void ConnectionServerProxyStandardTest::TearDown() { }

/*
 * @tc.name: ConnectionServerProxyVirtualTest001
 * @tc.desc: test ConnectionServerProxy virtual function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyVirtualTest001, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.SoftbusRegisterService(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.CreateSessionServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.RemoveSessionServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.OpenSession(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.OpenAuthSession(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.NotifyAuthSuccess(0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.ReleaseResources(0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.CloseChannel(nullptr, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.CloseChannelWithStatistics(0, 0, 0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.SendMessage(0, 0, nullptr, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.QosReport(0, 0, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.StreamStats(0, 0, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.RippleStats(0, 0, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.JoinLNN(nullptr, nullptr, 0, false);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.LeaveLNN(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxyVirtualTest002
 * @tc.desc: test ConnectionServerProxy virtual function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyVirtualTest002, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.GetAllOnlineNodeInfo(nullptr, nullptr, 0, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.GetLocalDeviceInfo(nullptr, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.GetNodeKeyInfo(nullptr, nullptr, 0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.SetNodeDataChangeFlag(nullptr, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.RegDataLevelChangeCb(nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.UnregDataLevelChangeCb(nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.SetDataLevel(nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.StartTimeSync(nullptr, nullptr, 0, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.StopTimeSync(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.EvaluateQos(nullptr, DATA_TYPE_MESSAGE, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.ProcessInnerEvent(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = testProxy.PrivilegeCloseChannel(0, 0, nullptr);
    ASSERT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxyCreateServerTest
 * @tc.desc: test ConnectionServerProxy CreateServer function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyCreateServerTest, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.CreateServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = testProxy.CreateServer("test", "test");
    ASSERT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxyRemoveServerTest
 * @tc.desc: test ConnectionServerProxy RemoveServer function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyRemoveServerTest, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.RemoveServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = testProxy.RemoveServer("test", "test");
    ASSERT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxyConnectTest
 * @tc.desc: test ConnectionServerProxy Connect function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyConnectTest, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.Connect(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = testProxy.Connect("test", nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = testProxy.Connect("test", "test", nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    Address address;
    ret = testProxy.Connect("test", "test", &address);
    ASSERT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxyDisconnectTest
 * @tc.desc: test ConnectionServerProxy Disconnect function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyDisconnectTest, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.Disconnect(0);
    ASSERT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxySendTest
 * @tc.desc: test ConnectionServerProxy Send function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxySendTest, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.Send(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const uint8_t *data = reinterpret_cast<const uint8_t *>("test");
    uint32_t len = strlen("test");
    ret = testProxy.Send(0, data, len);
    ASSERT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnectionServerProxyConnGetPeerDeviceIdTest
 * @tc.desc: test ConnectionServerProxy ConnGetPeerDeviceId function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyStandardTest, ConnectionServerProxyConnGetPeerDeviceIdTest, TestSize.Level0)
{
    const sptr<IRemoteObject> impl = nullptr;
    ConnectionServerProxy testProxy(impl);
    int32_t ret = testProxy.ConnGetPeerDeviceId(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);
    const uint8_t *deviceId = reinterpret_cast<const uint8_t *>("test");
    uint32_t len = strlen("test");
    ret = testProxy.Send(0, deviceId, len);
    ASSERT_NE(ret, SOFTBUS_OK);
}
}
} // namespace OHOS

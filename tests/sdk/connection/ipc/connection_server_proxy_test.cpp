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

#include "general_connection_server_proxy.h"
#include "softbus_error_code.h"

using namespace testing::ext;
namespace OHOS {
namespace {
class ConnectionServerProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConnectionServerProxyTest::SetUpTestCase() { }

void ConnectionServerProxyTest::TearDownTestCase() { }

void ConnectionServerProxyTest::SetUp() { }

void ConnectionServerProxyTest::TearDown() { }

/*
 * @tc.name: ConnectionServerProxyNotInitTest
 * @tc.desc: test g_serverProxy is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyTest, ConnectionServerProxyNotInitTest, TestSize.Level0)
{
    int32_t ret = ServerIpcCreateServer("test", "test");
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);

    ret = ServerIpcRemoveServer("test", "test");
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);

    ret = ServerIpcConnect("test", "test", nullptr);
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);

    ret = ServerIpcDisconnect(0);
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);

    ret = ServerIpcSend(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);

    ret = ServerIpcGetPeerDeviceId(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: ConnectionServerProxyInitTest001
 * @tc.desc: test connection server proxy init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyTest, ConnectionServerProxyInitTest001, TestSize.Level0)
{
    int32_t ret = ConnectionServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ConnectionServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ConnectionServerProxyDeInit(); // g_serverProxy is not null
    ConnectionServerProxyDeInit(); // g_serverProxy is null
}

/*
 * @tc.name: ConnectionServerProxyInitTest002
 * @tc.desc: test g_serverProxy is not null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnectionServerProxyTest, ConnectionServerProxyInitTest002, TestSize.Level0)
{
    int32_t ret = ConnectionServerProxyInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = ServerIpcCreateServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ServerIpcRemoveServer(nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ServerIpcConnect(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ServerIpcDisconnect(0);
    ASSERT_NE(ret, SOFTBUS_OK);

    ret = ServerIpcSend(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ServerIpcGetPeerDeviceId(0, nullptr, 0);
    ASSERT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ConnectionServerProxyDeInit();
}
}
} // namespace OHOS

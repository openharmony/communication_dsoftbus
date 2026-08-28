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

// Management-layer UT: core/connection/proxy/proxy_manager.c.

#include <gtest/gtest.h>
#include <set>

#include "mock/proxy_manager_mock.h"
#include "mock/far_field_adapter_mock.h"
#include "proxy_manager.h"
#include "br_proxy_manager.h"
#include "far_field_proxy_manager.h"

using namespace testing::ext;
using testing::Return;
using testing::Invoke;

namespace {
constexpr uint32_t INVALID_CHANNEL_ID = 0;

int32_t g_openFailReason = 0;
uint32_t g_openSuccessChannelId = 0;

void ResetManagerGlobals()
{
    g_openFailReason = 0;
    g_openSuccessChannelId = 0;
}

void TestOnOpenSuccess(uint32_t requestId, ProxyChannel *channel)
{
    (void)requestId;
    g_openSuccessChannelId = channel->channelId;
}

void TestOnOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    (void)requestId;
    (void)brMac;
    g_openFailReason = reason;
}
} // namespace

class ProxyManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        LooperInit();
    }

    static void TearDownTestCase()
    {
        LooperDeinit();
    }

    void SetUp() override
    {
        ProxyChannelMock::InjectProxyConfigDisableRetryConnect();
        ResetManagerGlobals();
    }

    void TearDown() override
    {
        ProxyChannelMock::InjectProxyConfigRestoreRetryConnect();
    }
};

namespace {
// (Init of the management-layer stack happens in ProxyManagerTest001, which runs first;
// subsequent tests rely on that initialized state.)
} // namespace

/*
 * @tc.name: ProxyManagerTest001
 * @tc.desc: test ProxyChannelManagerInit retry (BR SoftBusAddBtStateListener / RegisterHfpListener fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest001 in");
    ProxyChannelMock brMock;
    FarFieldAdapterMock farFieldMock;
    // 1st: SoftBusAddBtStateListener fails -> BrProxyChannelManagerInit fails
    EXPECT_CALL(brMock, SoftBusAddBtStateListener).WillOnce(Return(-1))
        .WillRepeatedly(ProxyChannelMock::ActionOfAddBtStateListener);
    // 2nd: RegisterHfpListener fails
    EXPECT_CALL(brMock, RegisterHfpListener).WillOnce(Return(-1))
        .WillRepeatedly(ProxyChannelMock::ActionOfRegisterHfpListener);
    EXPECT_CALL(brMock, InitSppSocketDriver).WillRepeatedly(ProxyChannelMock::ActionOfInitSppSocketDriver);
    EXPECT_CALL(farFieldMock, ManagerInit).WillRepeatedly(FarFieldAdapterMock::ActionOfManagerInit);
    EXPECT_CALL(farFieldMock, ManagerDeinit).WillRepeatedly(Return());
    EXPECT_CALL(farFieldMock, Init).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(farFieldMock, Deinit).WillRepeatedly(Return());
    EXPECT_CALL(farFieldMock, IsDeviceSupport).WillRepeatedly(Return(false));
    EXPECT_CALL(farFieldMock, OpenP2P).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(farFieldMock, CloseP2P).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(farFieldMock, SendMsg).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(farFieldMock, Refresh).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = ProxyChannelManagerInit();
    EXPECT_EQ(ret, -1);
    ret = ProxyChannelManagerInit();
    EXPECT_EQ(ret, -1);
    ret = ProxyChannelManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest001 out");
}

/*
 * @tc.name: ProxyManagerTest002
 * @tc.desc: test openProxyChannel invalid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest002 in");
    int32_t ret = GetProxyChannelManager()->openProxyChannel(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ProxyChannelParam param = {};
    ret = GetProxyChannelManager()->openProxyChannel(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    param = { .brMac = "11:22:33:44:55:66" };
    ret = GetProxyChannelManager()->openProxyChannel(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    param = {
        .requestId = 1,
        .timeoutMs = 1,
        .uuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    };
    ret = GetProxyChannelManager()->openProxyChannel(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    OpenProxyChannelCallback callback = {};
    ret = GetProxyChannelManager()->openProxyChannel(&param, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    callback = { .onOpenFail = TestOnOpenFail };
    ret = GetProxyChannelManager()->openProxyChannel(&param, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest002 out");
}

/*
 * @tc.name: ProxyManagerTest003
 * @tc.desc: test generateRequestId uniqueness
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest003 in");
    std::set<uint32_t> requestIds;
    for (int i = 0; i < 100; ++i) {
        uint32_t reqId = GetProxyChannelManager()->generateRequestId();
        EXPECT_NE(reqId, INVALID_CHANNEL_ID);
        requestIds.insert(reqId);
    }
    EXPECT_EQ(requestIds.size(), 100u);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest003 out");
}

/*
 * @tc.name: ProxyManagerTest004
 * @tc.desc: test registerProxyChannelListener missing onProxyChannelReconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest004 in");
    ProxyConnectListener listener = {
        .onProxyChannelDataReceived = nullptr,
        .onProxyChannelDisconnected = nullptr,
    };
    int32_t ret = GetProxyChannelManager()->registerProxyChannelListener(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest004 out");
}

/*
 * @tc.name: ProxyManagerTest005
 * @tc.desc: test registerProxyChannelListener missing onProxyChannelDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest005 in");
    ProxyConnectListener listener = {
        .onProxyChannelDataReceived = nullptr,
        .onProxyChannelReconnected = nullptr,
    };
    int32_t ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest005 out");
}

/*
 * @tc.name: ProxyManagerTest006
 * @tc.desc: test IsRealMac=false path: invalid format mac triggers GetRealMac, failure returns err
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest006 in");
    ProxyChannelMock brMock;
    // IsRealMac("11-22-33-44-55-66") is false (bad separator); CreateProxyChannelInfo then calls
    // GetRealMac. With GetRealMac failing, CreateProxyChannelInfo returns NULL and openProxyChannel
    // short-circuits with SOFTBUS_MALLOC_ERR before dispatching to BR.
    EXPECT_CALL(brMock, GetRealMac).WillRepeatedly(Return(-1));

    ProxyChannelParam param = {};
    strcpy_s(param.brMac, BT_MAC_MAX_LEN, "11-22-33-44-55-66");
    param.requestId = 1;
    param.timeoutMs = 1000;
    strcpy_s(param.uuid, UUID_STRING_LEN, "0000FEEA-0000-1000-8000-00805F9B34FB");
    OpenProxyChannelCallback callback = { .onOpenFail = TestOnOpenFail, .onOpenSuccess = TestOnOpenSuccess };
    int32_t ret = GetProxyChannelManager()->openProxyChannel(&param, &callback);
    EXPECT_EQ(ret, SOFTBUS_MALLOC_ERR);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest006 out");
}

/*
 * @tc.name: ProxyManagerTest007
 * @tc.desc: test registerProxyChannelListener with all callbacks set succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest007 in");
    ProxyConnectListener listener = {
        .onProxyChannelDataReceived = [](ProxyChannel *channel, const uint8_t *data, uint32_t dataLen) {
            (void)channel;
            (void)data;
            (void)dataLen;
        },
        .onProxyChannelDisconnected = [](ProxyChannel *channel, int32_t reason) {
            (void)channel;
            (void)reason;
        },
        .onProxyChannelReconnected = [](char *addr, ProxyChannel *channel) {
            (void)addr;
            (void)channel;
        },
    };
    int32_t ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest007 out");
}

/*
 * @tc.name: ProxyManagerTest008
 * @tc.desc: test generateChannelId uniqueness and proxy channel id base
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyManagerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest008 in");
    std::set<uint32_t> channelIds;
    for (int i = 0; i < 100; ++i) {
        uint32_t channelId = GetProxyChannelManager()->generateChannelId();
        EXPECT_NE(channelId, INVALID_CHANNEL_ID);
        channelIds.insert(channelId);
    }
    EXPECT_EQ(channelIds.size(), 100u);
    CONN_LOGI(CONN_PROXY, "ProxyManagerTest008 out");
}

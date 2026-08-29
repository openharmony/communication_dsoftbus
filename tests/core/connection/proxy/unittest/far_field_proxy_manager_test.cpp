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
#include <vector>

#include "mock/far_field_adapter_mock.h"
#include "mock/proxy_manager_mock.h"
#include "proxy_config.h"
#include "proxy_manager.h"
#include "far_field_proxy_manager.h"

using namespace testing::ext;
using testing::Return;
using testing::_;
using testing::Invoke;

namespace {
constexpr const char *TEST_BR_MAC = "11:22:33:44:55:66";
constexpr const char *TEST_UUID = "0000FEEA-0000-1000-8000-00805F9B34FB";
constexpr const char *TEST_SRC_MAC = "11:22:33:44:55:66";
constexpr uint32_t TEST_REQUEST_ID = 100;
constexpr uint32_t FAR_FIELD_SLEEP_MS = 1000;

uint32_t g_farFieldChannelId = 0;
int32_t g_farFieldOpenFailReason = 0;
int32_t g_farFieldDisconnectReason = 0;
uint32_t g_farFieldRecvDataLen = 0;
bool g_farFieldReconnected = false;
bool g_farFieldOpenSuccess = false;

void ResetFarFieldGlobals()
{
    g_farFieldChannelId = 0;
    g_farFieldOpenFailReason = 0;
    g_farFieldDisconnectReason = 0;
    g_farFieldRecvDataLen = 0;
    g_farFieldReconnected = false;
    g_farFieldOpenSuccess = false;
}

void TestOnFarFieldOpenSuccess(uint32_t requestId, ProxyChannel *channel)
{
    g_farFieldChannelId = channel->channelId;
    g_farFieldOpenSuccess = true;
}

void TestOnFarFieldOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    g_farFieldOpenFailReason = reason;
}

void TestOnFarFieldDisconnected(ProxyChannel *channel, int32_t reason)
{
    g_farFieldDisconnectReason = reason;
}

void TestOnFarFieldDataReceived(ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    g_farFieldRecvDataLen = dataLen;
}

void TestOnFarFieldReconnected(char *addr, ProxyChannel *channel)
{
    g_farFieldReconnected = true;
    g_farFieldChannelId = channel->channelId;
}

FarFieldProxyListener BuildTestListener()
{
    return {
        .onFarFieldProxyDataReceived = TestOnFarFieldDataReceived,
        .onFarFieldProxyDisconnected = TestOnFarFieldDisconnected,
        .onFarFieldConnected = TestOnFarFieldOpenSuccess,
        .onFarFieldOpenFail = TestOnFarFieldOpenFail,
    };
}

FarFieldProxyParam BuildTestParam(uint32_t requestId = TEST_REQUEST_ID)
{
    FarFieldProxyParam param = {};
    strcpy_s(param.device.brMac, BT_MAC_LEN, TEST_BR_MAC);
    strcpy_s(param.device.uuid, UUID_STRING_LEN, TEST_UUID);
    strcpy_s(param.srcMac, BT_MAC_MAX_LEN, TEST_SRC_MAC);
    param.requestId = requestId;
    return param;
}

P2PDeviceInfo BuildTestDevice()
{
    P2PDeviceInfo device = {};
    strcpy_s(device.brMac, BT_MAC_LEN, TEST_BR_MAC);
    strcpy_s(device.uuid, UUID_STRING_LEN, TEST_UUID);
    return device;
}
}

class FarFieldProxyManagerTest : public testing::Test {
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
        ResetFarFieldGlobals();
        SetupProxyManagerInit();
    }

    void TearDown() override
    {
        FarFieldProxyManagerDeinit();
        ProxyChannelMock::InjectProxyConfigRestoreRetryConnect();
    }

private:
    void SetupProxyManagerInit()
    {
        ProxyChannelMock brMock;
        EXPECT_CALL(brMock, RegisterHfpListener)
            .WillRepeatedly(ProxyChannelMock::ActionOfRegisterHfpListener);
        EXPECT_CALL(brMock, SoftBusAddBtStateListener)
            .WillRepeatedly(ProxyChannelMock::ActionOfAddBtStateListener);
        EXPECT_CALL(brMock, InitSppSocketDriver)
            .WillRepeatedly(ProxyChannelMock::ActionOfInitSppSocketDriver);
        EXPECT_CALL(brMock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
        EXPECT_CALL(brMock, Read).WillRepeatedly(Return(-1));
        EXPECT_CALL(brMock, IsPairedDevice).WillRepeatedly(Return(true));

        EXPECT_CALL(adapterMock_, ManagerInit)
            .WillRepeatedly(FarFieldAdapterMock::ActionOfManagerInit);
        EXPECT_CALL(adapterMock_, ManagerDeinit).WillRepeatedly(Return());
        EXPECT_CALL(adapterMock_, Init).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(adapterMock_, Deinit).WillRepeatedly(Return());
        EXPECT_CALL(adapterMock_, IsDeviceSupport).WillRepeatedly(Return(true));
        EXPECT_CALL(adapterMock_, OpenP2P).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(adapterMock_, CloseP2P).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(adapterMock_, SendMsg).WillRepeatedly(Return(SOFTBUS_OK));
        EXPECT_CALL(adapterMock_, Refresh).WillRepeatedly(Return(SOFTBUS_OK));

        ProxyChannelManagerInit();
        FarFieldProxyListener listener = BuildTestListener();
        RegisterFarFieldProxyListener(&listener);
    }

    FarFieldAdapterMock adapterMock_;
};

/*
 * @tc.name: FarFieldProxyManagerTest001
 * @tc.desc: test FarFieldProxyManagerInit and Deinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest001 in");
    int32_t ret = FarFieldProxyManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    FarFieldProxyManagerDeinit();
    ret = FarFieldProxyManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest001 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest002
 * @tc.desc: test RegisterFarFieldProxyListener with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest002 in");
    int32_t ret = RegisterFarFieldProxyListener(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest002 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest003
 * @tc.desc: test OpenFarFieldProxyChannel with null param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest003 in");
    int32_t ret = OpenFarFieldProxyChannel(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest003 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest004
 * @tc.desc: test OpenFarFieldProxyChannel with empty brMac or uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest004 in");
    FarFieldProxyParam param = {};
    param.requestId = TEST_REQUEST_ID;
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    strcpy_s(param.device.brMac, BT_MAC_LEN, TEST_BR_MAC);
    ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest004 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest005
 * @tc.desc: test OpenFarFieldProxyChannel success then P2P connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest005 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    EXPECT_NE(g_farFieldChannelId, 0);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest005 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest006
 * @tc.desc: test OpenFarFieldProxyChannel then P2P disconnected during connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest006 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_DISCONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_NE(g_farFieldOpenFailReason, 0);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest006 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest007
 * @tc.desc: test OpenFarFieldProxyChannel then reuse connected connection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest007 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    ResetFarFieldGlobals();

    param.requestId = TEST_REQUEST_ID + 1;
    ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest007 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest008
 * @tc.desc: test reuse connection while connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest008 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    ResetFarFieldGlobals();
    param.requestId = TEST_REQUEST_ID + 1;
    ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_FALSE(g_farFieldOpenSuccess);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest008 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest009
 * @tc.desc: test connected then P2P disconnected notifies onFarFieldProxyDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest009 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    ResetFarFieldGlobals();

    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_DISCONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_NE(g_farFieldDisconnectReason, 0);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest009 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest010
 * @tc.desc: test FarFieldProxySend with null channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest010, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest010 in");
    const uint8_t data[] = {0x01, 0x02, 0x03};
    ProxyChannel channel = {.channelId = 99999};
    int32_t ret = channel.send != nullptr ? channel.send(nullptr, data, sizeof(data)) : SOFTBUS_INVALID_PARAM;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest010 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest011
 * @tc.desc: test FarFieldProxySend with not connected state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest011, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest011 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    ProxyChannel channel = {.channelId = g_farFieldChannelId};
    const uint8_t data[] = {0x01, 0x02, 0x03};
    int32_t sendRet = SOFTBUS_OK;
    if (channel.send != nullptr) {
        sendRet = channel.send(&channel, data, sizeof(data));
    }
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest011 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest012
 * @tc.desc: test FarFieldProxySend success when connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest012, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest012 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);

    ProxyChannel channel = {.channelId = g_farFieldChannelId};
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    if (channel.send != nullptr) {
        ret = channel.send(&channel, data, sizeof(data));
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest012 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest013
 * @tc.desc: test FarFieldProxyClose with null channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest013, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest013 in");
    ProxyChannel channel = {.channelId = 99999};
    if (channel.close != nullptr) {
        channel.close(nullptr, true);
    }
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest013 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest014
 * @tc.desc: test FarFieldProxyClose success after connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest014, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest014 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);

    ProxyChannel channel = {.channelId = g_farFieldChannelId};
    if (channel.close != nullptr) {
        channel.close(&channel, true);
    }
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest014 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest015
 * @tc.desc: test ClearFarFieldProxy with null addr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest015, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest015 in");
    ClearFarFieldProxy(nullptr);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest015 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest016
 * @tc.desc: test ClearFarFieldProxy with not found addr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest016, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest016 in");
    ClearFarFieldProxy("99:88:77:66:55:44");
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest016 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest017
 * @tc.desc: test ClearFarFieldProxy success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest017, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest017 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);

    ClearFarFieldProxy(TEST_BR_MAC);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest017 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest018
 * @tc.desc: test OnRecvP2PMsg delivers data to listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest018, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest018 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    ResetFarFieldGlobals();

    uint8_t msg[] = {0x01, 0x02, 0x03, 0x04};
    FarFieldAdapterMock::InjectRecvP2PMsg(&device, msg, sizeof(msg));
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_EQ(g_farFieldRecvDataLen, sizeof(msg));
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest018 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest019
 * @tc.desc: test OnP2PStateChanged with invalid state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest019, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest019 in");
    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECTING, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_FALSE(g_farFieldOpenSuccess);
    EXPECT_EQ(g_farFieldOpenFailReason, 0);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest019 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest020
 * @tc.desc: test FarFieldAdapterIsDeviceSupport returns false when not initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest020, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest020 in");
    FarFieldAdapterMock::GetMock();
    EXPECT_CALL(adapterMock_, IsDeviceSupport).WillRepeatedly(Return(false));
    P2PDeviceInfo device = BuildTestDevice();
    bool supported = FarFieldAdapterIsDeviceSupport(&device);
    EXPECT_FALSE(supported);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest020 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest021
 * @tc.desc: test FarFieldProxyRefresh with null channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest021, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest021 in");
    OpenProxyChannelCallback callback = {
        .onOpenFail = TestOnFarFieldOpenFail,
        .onOpenSuccess = TestOnFarFieldOpenSuccess,
    };
    ProxyChannel channel = {.channelId = 99999};
    if (channel.refresh != nullptr) {
        channel.refresh(nullptr, 1, &callback);
    }
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest021 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest022
 * @tc.desc: test FarFieldProxyRefresh success after connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest022, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest022 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    ResetFarFieldGlobals();

    ProxyChannel channel = {.channelId = g_farFieldChannelId};
    OpenProxyChannelCallback callback = {
        .onOpenFail = TestOnFarFieldOpenFail,
        .onOpenSuccess = TestOnFarFieldOpenSuccess,
    };
    if (channel.refresh != nullptr) {
        channel.refresh(&channel, TEST_REQUEST_ID + 10, &callback);
    }
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest022 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest023
 * @tc.desc: test OnRemoteEvent with invalid event is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest023, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest023 in");
    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectRemoteEvent(&device, EVENT_INVALID);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_FALSE(g_farFieldOpenSuccess);
    EXPECT_EQ(g_farFieldOpenFailReason, 0);
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest023 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest024
 * @tc.desc: test FarFieldProxySend with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest024, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest024 in");
    FarFieldProxyParam param = BuildTestParam();
    int32_t ret = OpenFarFieldProxyChannel(&param);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);

    P2PDeviceInfo device = BuildTestDevice();
    FarFieldAdapterMock::InjectP2PStateChanged(&device, P2P_STATE_CONNECT, 0);
    SoftBusSleepMs(FAR_FIELD_SLEEP_MS);
    EXPECT_TRUE(g_farFieldOpenSuccess);

    ProxyChannel channel = {.channelId = g_farFieldChannelId};
    if (channel.send != nullptr) {
        ret = channel.send(&channel, nullptr, 5);
        EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    }
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest024 out");
}

/*
 * @tc.name: FarFieldProxyManagerTest025
 * @tc.desc: test FarFieldProxySend with invalid channelId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FarFieldProxyManagerTest, FarFieldProxyManagerTest025, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest025 in");
    ProxyChannel channel = {.channelId = 99999};
    const uint8_t data[] = {0x01, 0x02, 0x03};
    if (channel.send != nullptr) {
        int32_t ret = channel.send(&channel, data, sizeof(data));
        EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    }
    CONN_LOGI(CONN_PROXY, "FarFieldProxyManagerTest025 out");
}

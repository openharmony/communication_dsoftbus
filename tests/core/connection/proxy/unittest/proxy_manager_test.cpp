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

#include "mock/proxy_manager_mock.h"
#include "proxy_manager.h"

using namespace testing::ext;

using testing::Return;
using testing::_;
using testing::NotNull;
using testing::NiceMock;

static int32_t g_channelId = 0;
static int32_t g_connectFailedReason = 0;
static uint32_t g_recvDataLen = 0;
static int32_t g_disconnectReason = 0;
static struct ProxyChannel *g_channel = nullptr;
namespace OHOS {
static void ResetGlobalVariables(void)
{
    g_channelId = 0;
    g_connectFailedReason = 0;
    g_recvDataLen = 0;
    g_disconnectReason = 0;
}

class ProxyManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        LooperInit();
    }

    static void TearDownTestCase()
    {
        LooperDeinit();
        if (g_channel != nullptr) {
            SoftBusFree(g_channel);
        }
    }

    void SetUp() override
    {
        ResetGlobalVariables();
    }
    void TearDown() override {}
};

static void TestOnOpenSuccess(uint32_t requestId, struct ProxyChannel *channel)
{
    CONN_LOGI(CONN_PROXY, "TestOnOpenSuccess, reqId=%{public}u, channelId=%{public}u",
        requestId, channel->channelId);
    g_channelId = channel->channelId;
    if (g_channel != nullptr) {
        return;
    }
    g_channel = (struct ProxyChannel *)SoftBusCalloc(sizeof(struct ProxyChannel));
    ASSERT_TRUE(g_channel != nullptr);
    (void)memcpy_s(g_channel, sizeof(struct ProxyChannel), channel, sizeof(struct ProxyChannel));
}

static void TestOnOpenFail(uint32_t requestId, int32_t reason)
{
    g_connectFailedReason = reason;
}

static void TestOnProxyChannelDataReceived(struct ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    CONN_LOGI(CONN_PROXY, "TestOnDataReceived, dataLen=%{public}u, channelId=%{public}u",
        dataLen, channel->channelId);
    g_recvDataLen = dataLen;
}

static void TestOnProxyChannelDisconnected(struct ProxyChannel *channel, int32_t reason)
{
    CONN_LOGI(CONN_PROXY, "test disconnected reason=%{public}d", reason);
    ProxyConnectInfo *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        if (!it->isInnerRequest) {
            it->isAclConnected = false;
        }
    }
    g_disconnectReason = reason;
}

static void TestOnProxyChannelReconnected(char *addr, struct ProxyChannel *channel)
{
    CONN_LOGI(CONN_PROXY, "test reconnected channelId=%{public}u", channel->channelId);
    g_channelId = channel->channelId;
}

static int32_t ConstructParamAndOpenProxyChannel(uint32_t requestId, uint64_t timeoutMs)
{
    ProxyChannelParam param = {
        .brMac = "11:22:33:44:55:66",
        .requestId = requestId,
        .timeoutMs = timeoutMs,
        .uuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    };
    OpenProxyChannelCallback callback = {
        .onOpenFail = TestOnOpenFail,
        .onOpenSuccess = TestOnOpenSuccess,
    };
    return GetProxyChannelManager()->openProxyChannel(&param, &callback);
}

/*
 * @tc.name: ProxyChannelManagerTest001
 * @tc.desc: test init ProxyChannelManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest001 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, RegisterHfpListener).WillOnce(Return(-1))
        .WillRepeatedly(ProxyChannelMock::ActionOfRegisterHfpListener);
    EXPECT_CALL(mock, SoftBusAddBtStateListener).WillOnce(Return(-1))
        .WillRepeatedly(ProxyChannelMock::ActionOfAddBtStateListener);
    EXPECT_CALL(mock, InitSppSocketDriver).WillRepeatedly(ProxyChannelMock::ActionOfInitSppSocketDriver);

    int32_t ret = ProxyChannelManagerInit();
    EXPECT_EQ(ret, -1);
    ret = ProxyChannelManagerInit();
    EXPECT_EQ(ret, -1);
    ret = ProxyChannelManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetProxyChannelManager()->generateRequestId();
    EXPECT_NE(ret, -1);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest001 out");
}

/*
 * @tc.name: ProxyChannelManagerTest002
 * @tc.desc: test open ProxyChannel failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest002 in");
    int32_t ret = GetProxyChannelManager()->openProxyChannel(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ProxyChannelParam param = { 0 };
    ret = GetProxyChannelManager()->openProxyChannel(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    param = {
        .brMac = "11:22:33:44:55:66",
    };
    ret = GetProxyChannelManager()->openProxyChannel(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    param = {
        .requestId = 1,
        .timeoutMs = 1,
        .uuid = "0000FEEA-0000-1000-8000-00805F9B34FB",
    };
    ret = GetProxyChannelManager()->openProxyChannel(&param, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    OpenProxyChannelCallback callback = { 0 };
    ret = GetProxyChannelManager()->openProxyChannel(&param, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    callback = {
        .onOpenFail = TestOnOpenFail,
    };
    ret = GetProxyChannelManager()->openProxyChannel(&param, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest002 out");
}

/*
 * @tc.name: ProxyChannelManagerTest003
 * @tc.desc: test registerProxyChannelListener and openProxyChannel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest003 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Read).WillOnce(ProxyChannelMock::ActionOfRead).WillOnce(Return(-1));
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    int32_t ret = GetProxyChannelManager()->registerProxyChannelListener(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ProxyConnectListener listener = {
        .onProxyChannelDataReceived = TestOnProxyChannelDataReceived,
    };
    ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.onProxyChannelDisconnected = TestOnProxyChannelDisconnected;
    listener.onProxyChannelReconnected = TestOnProxyChannelReconnected;
    ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(CONNECT_SLEEP_TIME_MS);
    // test reuse already connected connection
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(CONNECT_SLEEP_TIME_MS1);
    EXPECT_NE(g_channelId, 0);
    EXPECT_NE(g_recvDataLen, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest003 out");
}

/*
 * @tc.name: ProxyChannelManagerTest004
 * @tc.desc: test open proxy channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(Return(-1)).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillOnce(Return(-1)).WillOnce(Return(BR_READ_SOCKET_CLOSED))
        .WillOnce(ProxyChannelMock::ActionOfRead).WillOnce(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004----01");
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_NE(g_channelId, 0);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004----02");
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004----03");
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(2);
    EXPECT_NE(g_recvDataLen, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004 out");
}

/*
 * @tc.name: ProxyChannelManagerTest005
 * @tc.desc: test reuse proxychannel and send data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest005 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillOnce(ProxyChannelMock::ActionOfRead1);
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // open proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_NE(g_channelId, 0);
    // test repeat reconnect
    std::string addr = "00:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);

    // test reuse is not null
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    // test send and close failed
    const uint8_t data[] = {0x02, 0x01, 0x02, 0x15, 0x16};
    struct ProxyChannel proxyChannel = {
        .channelId = 1,
    };
    EXPECT_CALL(mock, Write).WillOnce(Return(sizeof(data)));
    CONN_LOGI(CONN_PROXY, "=================");
    ret = g_channel->send(&proxyChannel, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    g_channel->close(&proxyChannel, true);
    sleep(1);
    proxyChannel.channelId = g_channelId;
    ret = g_channel->send(&proxyChannel, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_channel->close(&proxyChannel, true);
    sleep(2);
    // test reconnect device is null
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    sleep(1);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest005 out");
}

/*
 * @tc.name: ProxyChannelManagerTest006
 * @tc.desc: test HfpConnectionChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest006 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    uint32_t channelId = g_channelId;
    EXPECT_NE(g_channelId, 0);
    std::string addr = "00:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    
    SoftBusBtAddr btAddr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    // test reconnect device failed and retry
    EXPECT_CALL(mock, Connect).WillOnce(Return(-1)).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    sleep(2);
    EXPECT_NE(g_channelId, channelId);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest006 out");
}

/*
 * @tc.name: ProxyChannelManagerTest007
 * @tc.desc: test btAclStateChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest007 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // open new proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    uint32_t channelId1 = g_channelId;
    EXPECT_NE(g_channelId, 0);
    SoftBusBtAddr btAddr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);

    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    btAddr = {
        .addr = {0x00, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    sleep(1);
    EXPECT_NE(g_channelId, channelId1);

    g_channelId = 0;
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    btAddr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };

    // construct acl disconnect and not retry connect
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_DISCONNECTED, 0);
    sleep(1);
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    sleep(1);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest007 out");
}

static void ProxyChannelDereference(struct ProxyConnection *proxyConnection)
{
    SoftBusMutexDestroy(&proxyConnection->lock);
    SoftBusFree(proxyConnection);
}

static void ProxyChannelReference(struct ProxyConnection *proxyConnection)
{
    (void)proxyConnection;
}

static void ConstructProxyChannelRequestInfo(void)
{
    ProxyConnectInfo *connectInfo = (ProxyConnectInfo *)SoftBusCalloc(sizeof(ProxyConnectInfo));
    ASSERT_TRUE(connectInfo != nullptr);
    if (strcpy_s(connectInfo->brMac, BT_MAC_LEN, "11:22:33:44:55:66") != EOK) {
        SoftBusFree(connectInfo);
        return;
    }
    connectInfo->requestId = 1;
    connectInfo->result.onOpenFail = TestOnOpenFail;
    connectInfo->result.onOpenSuccess = TestOnOpenSuccess;
    GetProxyChannelManager()->proxyChannelRequestInfo = connectInfo;
}

static void ConstructProxyConnectionList(void)
{
    struct ProxyConnection *proxyConnection = (struct ProxyConnection *)SoftBusCalloc(sizeof(struct ProxyConnection));
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != NULL, CONN_PROXY, "proxyConnection is NULL");
    ListInit(&proxyConnection->node);
    if (SoftBusMutexInit(&proxyConnection->lock, NULL)!= SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "init lock fail");
        SoftBusFree(proxyConnection);
        return;
    }
    proxyConnection->state = PROXY_CHANNEL_CONNECTED;
    proxyConnection->reference = ProxyChannelReference;
    proxyConnection->dereference = ProxyChannelDereference;
    int32_t ret = SoftBusMutexLock(&GetProxyChannelManager()->proxyConnectionList->lock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "lock proxyConnectionList fail");
        SoftBusMutexDestroy(&proxyConnection->lock);
        SoftBusFree(proxyConnection);
        return;
    }
    proxyConnection->refCount = 1;
    ListAdd(&GetProxyChannelManager()->proxyConnectionList->list, &proxyConnection->node);
    SoftBusMutexUnlock(&GetProxyChannelManager()->proxyConnectionList->lock);
}

/*
 * @tc.name: ProxyChannelManagerTest008
 * @tc.desc: test btStateChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008 in");
    ConstructProxyChannelRequestInfo();
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BLE_STATE_TURN_OFF);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_EQ(g_disconnectReason, 0);
    EXPECT_NE(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    // test connectingdevice is not null and proxyConnectionList is null
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(g_disconnectReason, 0);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    ResetGlobalVariables();

    ConstructProxyChannelRequestInfo();
    EXPECT_NE(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    ConstructProxyConnectionList();

    // test connectingdevice is not null, and test proxyConnectionList is not null
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), true);
    ResetGlobalVariables();
    // test proxyConnectionList is not null and connectingdevice is null
    ConstructProxyConnectionList();
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008 out");
}

/*
 * @tc.name: ProxyChannelManagerTest009
 * @tc.desc: test disconnected reason is device upaired and clear retry connect device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest009 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillOnce(Return(true)).WillRepeatedly(Return(false));

    // open new proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_NE(g_channelId, 0);
    SoftBusBtAddr btAddr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    sleep(1);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BR_UNPAIRED);
    ResetGlobalVariables();

    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    sleep(1);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest009 out");
}

/*
 * @tc.name: ProxyChannelManagerTest010
 * @tc.desc: test device uparied not retry connect and notify disconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest010, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest010 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillOnce(Return(true)).WillRepeatedly(Return(false));

    // open new proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    SoftBusBtAddr btAddr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);

    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    sleep(1);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest010 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011
 * @tc.desc: test connect timeout and unpaired conenct failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect).
        WillOnce(ProxyChannelMock::ActionOfConnect1).WillOnce(ProxyChannelMock::ActionOfConnect2).
        WillOnce(ProxyChannelMock::ActionOfConnect);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // open new proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(2);
    EXPECT_EQ(g_channelId, 0);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_OPEN_PROXY_TIMEOUT);
    // test open timeout connecting is null
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(2);
    EXPECT_EQ(g_channelId, 0);
    // test open timeout connecting device is unexpected
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(2);
    EXPECT_EQ(g_channelId, 0);

    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR);
    SoftBusFree(GetProxyChannelManager()->proxyChannelRequestInfo);
    GetProxyChannelManager()->proxyChannelRequestInfo = nullptr;

    // open new proxy channel
    ret = ConstructParamAndOpenProxyChannel(1, 3 * CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    sleep(2);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BR_UNPAIRED);
    EXPECT_EQ(g_disconnectReason, SOFTBUS_CONN_BR_UNPAIRED);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    ResetGlobalVariables();

    ConstructProxyChannelRequestInfo();
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    sleep(1);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BR_UNPAIRED);
    EXPECT_NE(g_disconnectReason, SOFTBUS_CONN_BR_UNPAIRED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011 out");
}

/*
 * @tc.name: ProxyChannelManagerTest012
 * @tc.desc: test retry after last connect ends
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest012, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest012 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect1).
        WillOnce(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // open new proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    sleep(1);
    EXPECT_EQ(g_channelId, 0);
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    sleep(1);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest012 out");
}
}
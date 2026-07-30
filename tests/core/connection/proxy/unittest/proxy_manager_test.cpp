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
#include <set>
#include <vector>

#include "mock/proxy_manager_mock.h"
#include "proxy_config.h"
#include "proxy_manager.h"

using namespace testing::ext;

using testing::Return;
using testing::Invoke;

namespace {
constexpr int32_t CHANNELID = 100;
constexpr int32_t CHANNELNUM = 200;
constexpr uint64_t CONNECT_TIMEOUT_LONG = 5000;
constexpr uint8_t DEFAULT_BT_ADDR[BT_ADDR_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

int32_t g_channelId = 0;
int32_t g_connectFailedReason = 0;
uint32_t g_recvDataLen = 0;
std::vector<int32_t> g_disconnectReason;
ProxyChannel *g_channel = nullptr;
}
namespace OHOS {
namespace {
void ResetGlobalVariables()
{
    g_channelId = 0;
    g_connectFailedReason = 0;
    g_recvDataLen = 0;
    g_disconnectReason.clear();

    SoftBusFree(g_channel);
    g_channel = nullptr;
}

void CleanupProxyChannelRequestInfo()
{
    if (GetProxyChannelManager()->proxyChannelRequestInfo != nullptr) {
        SoftBusFree(GetProxyChannelManager()->proxyChannelRequestInfo);
        GetProxyChannelManager()->proxyChannelRequestInfo = nullptr;
    }
}
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
    }

    void SetUp() override
    {
        ProxyChannelMock::InjectProxyConfigDisableRetryConnect();
        ResetGlobalVariables();
    }

    void TearDown() override
    {
        ProxyChannelMock::InjectProxyConfigRestoreRetryConnect();
    }
};

namespace {
void TestOnOpenSuccess(uint32_t requestId, ProxyChannel *channel)
{
    CONN_LOGI(CONN_PROXY, "TestOnOpenSuccess, reqId=%{public}u, channelId=%{public}u",
        requestId, channel->channelId);
    g_channelId = channel->channelId;
    SoftBusFree(g_channel);
    g_channel = static_cast<ProxyChannel *>(SoftBusCalloc(sizeof(ProxyChannel)));
    ASSERT_TRUE(g_channel != nullptr);
    (void)memcpy_s(g_channel, sizeof(ProxyChannel), channel, sizeof(ProxyChannel));
}

void TestOnOpenFail(uint32_t requestId, int32_t reason, const char *brMac)
{
    g_connectFailedReason = reason;
}

void ConstructProxyConnectInfo(const char *brMac, int32_t requestId = CHANNELID, bool isInnerRequest = false)
{
    ProxyConnectInfo *connectInfo = static_cast<ProxyConnectInfo *>(SoftBusCalloc(sizeof(ProxyConnectInfo)));
    ASSERT_TRUE(connectInfo != nullptr);
    if (strcpy_s(connectInfo->brMac, BT_MAC_LEN, brMac) != EOK) {
        SoftBusFree(connectInfo);
        return;
    }
    connectInfo->requestId = requestId;
    connectInfo->isInnerRequest = isInnerRequest;
    connectInfo->result.onOpenFail = TestOnOpenFail;
    connectInfo->result.onOpenSuccess = TestOnOpenSuccess;
    ListInit(&connectInfo->node);
    GetProxyChannelManager()->proxyChannelRequestInfo = connectInfo;
}

void TestOnProxyChannelDataReceived(ProxyChannel *channel, const uint8_t *data, uint32_t dataLen)
{
    CONN_LOGI(CONN_PROXY, "TestOnDataReceived, dataLen=%{public}u, channelId=%{public}u",
        dataLen, channel->channelId);
    g_recvDataLen = dataLen;
}

void TestOnProxyChannelDisconnected(ProxyChannel *channel, int32_t reason)
{
    CONN_LOGI(CONN_PROXY, "test disconnected reason=%{public}d", reason);
    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        if (!it->isInnerRequest) {
            it->isAclConnected = false;
        }
    }
    g_disconnectReason.push_back(reason);
}

void TestOnProxyChannelReconnected(char *addr, ProxyChannel *channel)
{
    CONN_LOGI(CONN_PROXY, "test reconnected channelId=%{public}u", channel->channelId);
    g_channelId = channel->channelId;
}

int32_t ConstructParamAndOpenProxyChannel(uint32_t requestId, uint64_t timeoutMs)
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

int32_t OpenProxyChannelWithMac(const char *brMac, uint32_t requestId = 1,
    uint64_t timeoutMs = CONNECT_TIMEOUT)
{
    ProxyChannelParam param = {};
    if (strcpy_s(param.brMac, BT_MAC_MAX_LEN, brMac) != EOK) {
        return SOFTBUS_ERR;
    }
    param.requestId = requestId;
    param.timeoutMs = timeoutMs;
    if (strcpy_s(param.uuid, UUID_STRING_LEN, "0000FEEA-0000-1000-8000-00805F9B34FB") != EOK) {
        return SOFTBUS_ERR;
    }
    OpenProxyChannelCallback callback = {
        .onOpenFail = TestOnOpenFail,
        .onOpenSuccess = TestOnOpenSuccess,
    };
    return GetProxyChannelManager()->openProxyChannel(&param, &callback);
}

SoftBusBtAddr MakeBtAddr(const uint8_t (&bytes)[BT_ADDR_LEN])
{
    return SoftBusBtAddr{ .addr = {bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]} };
}

void MakeDefaultBtSocketAddr(BdAddr &bdAddr, BtUuid &btUuid)
{
    bdAddr = { .addr = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } };
    const char *uuid = "0000FEEA-0000-1000-8000-00805F9B34FB";
    btUuid = { .uuidLen = strlen(uuid), .uuid = const_cast<char *>(uuid) };
}

bool HasReconnectDevice()
{
    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        (void)it;
        return true;
    }
    return false;
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

    ProxyChannelParam param = {};
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

    OpenProxyChannelCallback callback = {};
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
 * @tc.desc: test open proxy channel - connect fail then ACL not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(Return(-1)).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_BR_ACL_NOT_EXIST);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004 out");
}

/*
 * @tc.name: ProxyChannelManagerTest004_1
 * @tc.desc: test open proxy channel - read fail then disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest004_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillOnce(Return(-1)).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest004_2
 * @tc.desc: test open proxy channel - socket closed then disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest004_2, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004_2 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillOnce(Return(BR_READ_SOCKET_CLOSED)).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004_2 out");
}

/*
 * @tc.name: ProxyChannelManagerTest004_3
 * @tc.desc: test open proxy channel - read success then data received then disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest004_3, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004_3 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillOnce(ProxyChannelMock::ActionOfRead).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_NE(g_channelId, 0);
    EXPECT_NE(g_recvDataLen, 0);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest004_3 out");
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
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    uint32_t channelId = g_channelId;
    EXPECT_NE(g_channelId, 0);

    std::string addr = "00:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);

    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);
    // test reconnect device failed and retry
    EXPECT_CALL(mock, Connect).WillOnce(Return(-1)).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    // wait acl async event handle first, otherwise acl event and hfp will be disorder
    SoftBusSleepMs(1000);
    addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    SoftBusSleepMs(2000);
    EXPECT_NE(g_channelId, channelId);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest006 out");
}

void ProxyChannelDereference(ProxyConnection *proxyConnection)
{
    SoftBusMutexDestroy(&proxyConnection->lock);
    SoftBusFree(proxyConnection);
}

void ProxyChannelReference(ProxyConnection *proxyConnection)
{
    (void)proxyConnection;
}

void ProxyChannelDereferenceSafe(ProxyConnection *proxyConnection)
{
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != nullptr, CONN_PROXY, "proxyConnection is null");
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY,
        "lock channel fail. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    proxyConnection->refCount -= 1;
    bool destruct = (proxyConnection->refCount <= 0);
    SoftBusMutexUnlock(&proxyConnection->lock);
    if (destruct) {
        CONN_LOGW(CONN_PROXY, "destory proxy channel=%{public}u", proxyConnection->channelId);
        SoftBusMutexDestroy(&proxyConnection->lock);
        SoftBusFree(proxyConnection);
    }
}

void ProxyChannelReferenceSafe(ProxyConnection *proxyConnection)
{
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != nullptr, CONN_PROXY, "proxyConnection is null");
    int32_t ret = SoftBusMutexLock(&proxyConnection->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_PROXY,
        "lock channel fail. channelId=%{public}u, error=%{public}d", proxyConnection->channelId, ret);
    proxyConnection->refCount += 1;
    SoftBusMutexUnlock(&proxyConnection->lock);
}

void AddProxyConnectionToList(ProxyChannelState state,
    void (*refFunc)(ProxyConnection *), void (*derefFunc)(ProxyConnection *),
    int32_t channelId = 0, const char *brMac = nullptr)
{
    ProxyConnection *proxyConnection =
        static_cast<ProxyConnection *>(SoftBusCalloc(sizeof(ProxyConnection)));
    CONN_CHECK_AND_RETURN_LOGE(proxyConnection != nullptr, CONN_PROXY, "proxyConnection is NULL");
    ListInit(&proxyConnection->node);
    if (SoftBusMutexInit(&proxyConnection->lock, nullptr) != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "init lock fail");
        SoftBusFree(proxyConnection);
        return;
    }
    proxyConnection->state = state;
    proxyConnection->reference = refFunc;
    proxyConnection->dereference = derefFunc;
    if (channelId != 0) {
        proxyConnection->channelId = channelId;
        proxyConnection->proxyChannel.channelId = channelId;
        proxyConnection->proxyChannel.requestId = channelId;
    }
    if (brMac != nullptr && strcpy_s(proxyConnection->brMac, BT_MAC_LEN, brMac) != EOK) {
        CONN_LOGE(CONN_PROXY, "cpy brMac err");
        SoftBusMutexDestroy(&proxyConnection->lock);
        SoftBusFree(proxyConnection);
        return;
    }
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

void ConstructProxyConnectionListDisconnecting()
{
    AddProxyConnectionToList(PROXY_CHANNEL_DISCONNECTING,
        ProxyChannelReferenceSafe, ProxyChannelDereferenceSafe, CHANNELNUM, "11:22:33:44:55:66");
}

void ConstructProxyChannelRequestInfo()
{
    ConstructProxyConnectInfo("11:22:33:44:55:66", 1);
}

void ConstructProxyConnectionList()
{
    AddProxyConnectionToList(PROXY_CHANNEL_CONNECTED,
        ProxyChannelReference, ProxyChannelDereference);
}

void ConstructProxyConnectionListConnecting()
{
    AddProxyConnectionToList(PROXY_CHANNEL_CONNECTING,
        ProxyChannelReference, ProxyChannelDereference, CHANNELID, "11:22:33:44:55:66");
}
}

/*
 * @tc.name: ProxyChannelManagerTest008
 * @tc.desc: test btStateChanged - BLE state ignored, BR off with requestInfo only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    ConstructProxyChannelRequestInfo();
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BLE_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_NE(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008 out");
}

/*
 * @tc.name: ProxyChannelManagerTest008_1
 * @tc.desc: test btStateChanged - BR off with requestInfo and connectionList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest008_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    ConstructProxyChannelRequestInfo();
    EXPECT_NE(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    ConstructProxyConnectionList();

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest008_2
 * @tc.desc: test btStateChanged - BR off with connectionList only, no requestInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest008_2, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008_2 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    ConstructProxyConnectionList();
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest008_2 out");
}

/*
 * @tc.name: ProxyChannelManagerTest009
 * @tc.desc: test disconnected reason is device unpaired
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

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(1000);
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(1000);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BR_UNPAIRED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest009 out");
}

/*
 * @tc.name: ProxyChannelManagerTest009_1
 * @tc.desc: test unpaired device should not reconnect on HFP connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest009_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest009_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(false));

    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest009_1 out");
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
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);

    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest010 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011
 * @tc.desc: test connect timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_OPEN_PROXY_TIMEOUT);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011_1
 * @tc.desc: test connect timeout with null connecting device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect1);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011_2
 * @tc.desc: test connect timeout with unexpected connecting device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011_2, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_2 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect2);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_2 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011_3
 * @tc.desc: test concurrent connect operation error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011_3, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_3 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(ProxyChannelMock::ActionOfConnect);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_3 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011_4
 * @tc.desc: test unpaired during connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011_4, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_4 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, 3 * CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BR_UNPAIRED);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BR_UNPAIRED);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_4 out");
}

/*
 * @tc.name: ProxyChannelManagerTest011_5
 * @tc.desc: test unpaired with requestInfo but no matching connecting channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest011_5, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_5 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyChannelRequestInfo();
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest011_5 out");
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
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest012 out");
}

/*
 * @tc.name: ProxyChannelManagerTest013
 * @tc.desc: test proxy connect callback with ActionOfConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest013, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest013 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, Connect).WillRepeatedly(ProxyChannelMock::ActionOfConnect);
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead1);

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    BdAddr bdAddr = {};
    BtUuid testBtUuid = {};
    MakeDefaultBtSocketAddr(bdAddr, testBtUuid);
    ProxyChannelMock::TestBtSocketConnectionCallback(&bdAddr, testBtUuid, 0, 0);
    SoftBusSleepMs(4000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest013 out");
}

/*
 * @tc.name: ProxyChannelManagerTest013_1
 * @tc.desc: test proxy connect callback with ActionOfConnect3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest013_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest013_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, Connect).WillRepeatedly(ProxyChannelMock::ActionOfConnect3);
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead1);

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    BdAddr bdAddr = {};
    BtUuid testBtUuid = {};
    MakeDefaultBtSocketAddr(bdAddr, testBtUuid);
    ProxyChannelMock::TestBtSocketConnectionCallback(&bdAddr, testBtUuid, 1, 4);
    SoftBusSleepMs(4000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest013_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest014
 * @tc.desc: test close not reset reconnect event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest014, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest014 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);

    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);
    ProxyChannel proxyChannel = {
        .channelId = g_channelId,
    };
    g_channelId = 0;
    g_channel->close(&proxyChannel, false);
    SoftBusSleepMs(1000);
    EXPECT_TRUE(HasReconnectDevice());
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest014 out");
}

/*
 * @tc.name: ProxyChannelManagerTest014_1
 * @tc.desc: test ACL reconnect after channel close triggers reconnection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest014_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest014_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);

    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);
    ProxyChannel proxyChannel = {
        .channelId = g_channelId,
    };
    g_channelId = 0;
    g_channel->close(&proxyChannel, false);
    SoftBusSleepMs(1000);

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest014_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest015
 * @tc.desc: test IsRealMac with various MAC address formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest015, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest015 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest015 out");
}

/*
 * @tc.name: ProxyChannelManagerTest017
 * @tc.desc: test MAC address with invalid separator
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest017, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest017 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11-22-33-44-55-66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest017 out");
}

/*
 * @tc.name: ProxyChannelManagerTest018
 * @tc.desc: test MAC address with invalid characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest018, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest018 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:GG");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest018 out");
}

/*
 * @tc.name: ProxyChannelManagerTest019
 * @tc.desc: test reconnect device info management
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest019, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest019 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    EXPECT_TRUE(HasReconnectDevice());
    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        EXPECT_EQ(it->innerRetryNum, 0);
    }
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest019 out");
}

/*
 * @tc.name: ProxyChannelManagerTest019_1
 * @tc.desc: test updating existing reconnect device info resets innerRetryNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest019_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest019_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);

    ret = ConstructParamAndOpenProxyChannel(2, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);

    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        EXPECT_EQ(it->innerRetryNum, 0);
    }
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest019_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest020
 * @tc.desc: test disconnect while connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest020, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest020 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(ProxyChannelMock::ActionOfConnect);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66", 1, CONNECT_TIMEOUT_LONG);
    EXPECT_EQ(ret, SOFTBUS_OK);

    // Immediately close without waiting
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(2000);

    // Should fail due to unpaired
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BR_UNPAIRED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest020 out");
}

/*
 * @tc.name: ProxyChannelManagerTest021
 * @tc.desc: test connection state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest021, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest021 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead);
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, Write).WillRepeatedly(Return(5));

    // Test CONNECTING -> CONNECTED transition
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);

    // Verify channel is in CONNECTED state by checking if we can send data
    ProxyChannel proxyChannel = {
        .channelId = g_channelId,
    };
    const uint8_t data[] = {0x02, 0x01, 0x02, 0x15, 0x16};
    ret = g_channel->send(&proxyChannel, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_OK);

    // Test CONNECTED -> DISCONNECTING transition
    g_channel->close(&proxyChannel, true);
    SoftBusSleepMs(1000);
    EXPECT_GE(g_disconnectReason.size(), 1);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest021 out");
}

/*
 * @tc.name: ProxyChannelManagerTest022
 * @tc.desc: test single device reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest022, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest022 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest022 out");
}

/*
 * @tc.name: ProxyChannelManagerTest022_1
 * @tc.desc: test multiple devices reconnect management
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest022_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest022_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    uint32_t channelId1 = g_channelId;
    EXPECT_NE(channelId1, 0);

    ResetGlobalVariables();
    ret = OpenProxyChannelWithMac("AA:BB:CC:DD:EE:FF", 2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    uint32_t channelId2 = g_channelId;
    EXPECT_NE(channelId2, 0);
    EXPECT_NE(channelId1, channelId2);

    int reconnectCount = 0;
    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        reconnectCount++;
    }
    EXPECT_EQ(reconnectCount, 2);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest022_1 out");
}

/*
 * @tc.name: ProxyChannelManagerTest023
 * @tc.desc: test request ID generation and wraparound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest023, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest023 in");
    // Generate multiple request IDs to verify uniqueness
    std::set<uint32_t> requestIds;
    for (int i = 0; i < 100; ++i) {
        uint32_t reqId = GetProxyChannelManager()->generateRequestId();
        EXPECT_NE(reqId, 0);
        requestIds.insert(reqId);
    }
    // All request IDs should be unique
    EXPECT_EQ(requestIds.size(), 100);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest023 out");
}

/*
 * @tc.name: ProxyChannelManagerTest024
 * @tc.desc: test ACL disconnected state handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest024, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest024 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    // Open proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    // Test ACL disconnected
    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_DISCONNECTED, 0);
    SoftBusSleepMs(1000);

    // Verify reconnect device info still exists but isAclConnected is false
    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        EXPECT_FALSE(it->isAclConnected);
    }
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest024 out");
}

/*
 * @tc.name: ProxyChannelManagerTest025
 * @tc.desc: test get channel by address functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest025, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest025 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // Test getConnectionById with invalid ID
    ProxyConnection *conn = GetProxyChannelManager()->getConnectionById(99999);
    EXPECT_EQ(conn, nullptr);

    // Test getProxyChannelByAddr with non-existent address
    conn = GetProxyChannelManager()->getProxyChannelByAddr(const_cast<char*>("FF:EE:DD:CC:BB:AA"));
    EXPECT_EQ(conn, nullptr);

    // Open a channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest025 out");
}

/*
 * @tc.name: ProxyChannelManagerTest027
 * @tc.desc: test Bluetooth state ON triggers reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest027, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest027 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    // Open proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    // Turn off Bluetooth
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);

    // Turn on Bluetooth - should trigger reconnect
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_ON);
    SoftBusSleepMs(2000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest027 out");
}

/*
 * @tc.name: ProxyChannelManagerTest028
 * @tc.desc: test retry limit reached
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest028, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest028 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    // Open proxy channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    ResetGlobalVariables();

    // Set custom retry times
    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);

    // Trigger disconnect
    std::string addr = "11:22:33:44:55:66";
    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(1000);
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);

    // Wait for retry attempts to exhaust
    SoftBusSleepMs(3000);

    // Verify retry limit was reached and disconnect was notified
    EXPECT_GE(g_disconnectReason.size(), 1);
    bool foundRetryFailed = false;
    for (const auto& reason : g_disconnectReason) {
        if (reason == SOFTBUS_CONN_PROXY_RETRY_FAILED) {
            foundRetryFailed = true;
            break;
        }
    }
    EXPECT_TRUE(foundRetryFailed);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest028 out");
}

/*
 * @tc.name: ProxyChannelManagerTest029
 * @tc.desc: test ProxyChannelSend with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest029, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest029 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // Open proxy channel first
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);

    // Test send with null channel
    const uint8_t data[] = {0x02, 0x01, 0x02, 0x15, 0x16};
    ret = g_channel->send(nullptr, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    // Test send with null data
    ProxyChannel proxyChannel = {
        .channelId = g_channelId,
    };
    ret = g_channel->send(&proxyChannel, nullptr, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    // Test send with invalid channel ID
    proxyChannel.channelId = 99999;
    ret = g_channel->send(&proxyChannel, data, sizeof(data));
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    g_channel->close(&proxyChannel, true);
    SoftBusSleepMs(1000);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest029 out");
}

/*
 * @tc.name: ProxyChannelManagerTest030
 * @tc.desc: test IsRealMac with uppercase hex MAC address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest030, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest030 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest030 out");
}

/*
 * @tc.name: ProxyChannelManagerTest031
 * @tc.desc: test IsRealMac with short MAC address treated as hash MAC
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest031, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest031 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRealMac).WillRepeatedly(Invoke(
        [](char *realAddr, uint32_t realAddrLen, const char *hashAddr) {
            return (strcpy_s(realAddr, realAddrLen, "11:22:33:44:55:66") == EOK) ? SOFTBUS_OK : -1;
        }));

    int32_t ret = OpenProxyChannelWithMac("11:22:33");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest031 out");
}

/*
 * @tc.name: ProxyChannelManagerTest032
 * @tc.desc: test ProxyChannelClose with null channel pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest032, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest032 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    EXPECT_NE(g_channel, nullptr);

    g_channel->close(nullptr, true);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest032 out");
}

/*
 * @tc.name: ProxyChannelManagerTest033
 * @tc.desc: test ProxyChannelSend with underlying send error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest033, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest033 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, Write).WillRepeatedly(Return(-1));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);

    const uint8_t data[] = {0x02, 0x01, 0x02, 0x15, 0x16};
    ProxyChannel proxyChannel = {
        .channelId = g_channelId,
    };
    ret = g_channel->send(&proxyChannel, data, sizeof(data));
    EXPECT_NE(ret, SOFTBUS_OK);
    g_channel->close(&proxyChannel, true);
    SoftBusSleepMs(1000);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest033 out");
}

/*
 * @tc.name: ProxyChannelManagerTest034
 * @tc.desc: test hash MAC path with GetRealMac failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest034, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest034 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, GetRealMac).WillRepeatedly(Return(-1));

    int32_t ret = OpenProxyChannelWithMac("invalidHashMac");
    EXPECT_EQ(ret, SOFTBUS_CONN_PROXY_INTERNAL_ERR);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest034 out");
}

/*
 * @tc.name: ProxyChannelManagerTest035
 * @tc.desc: test RegisterProxyChannelListener missing onProxyChannelReconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest035, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest035 in");
    ProxyConnectListener listener = {
        .onProxyChannelDataReceived = TestOnProxyChannelDataReceived,
        .onProxyChannelDisconnected = TestOnProxyChannelDisconnected,
    };
    int32_t ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest035 out");
}

/*
 * @tc.name: ProxyChannelManagerTest036
 * @tc.desc: test RegisterProxyChannelListener missing onProxyChannelDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest036, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest036 in");
    ProxyConnectListener listener = {
        .onProxyChannelDataReceived = TestOnProxyChannelDataReceived,
        .onProxyChannelReconnected = TestOnProxyChannelReconnected,
    };
    int32_t ret = GetProxyChannelManager()->registerProxyChannelListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest036 out");
}

/*
 * @tc.name: ProxyChannelManagerTest037
 * @tc.desc: test ProxyDeviceUnpaired with no reconnect device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest037, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest037 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    std::string unknownAddr = "99:88:77:66:55:44";
    ProxyChannelMock::InjectHfpConnectionChanged(unknownAddr, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    EXPECT_EQ(g_connectFailedReason, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest037 out");
}

/*
 * @tc.name: ProxyChannelManagerTest038
 * @tc.desc: test AclStateChangedHandler with isSupportHfp=false triggers immediate reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest038, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest038 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    uint32_t firstChannelId = g_channelId;
    EXPECT_NE(firstChannelId, 0);

    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        it->isSupportHfp = false;
    }
    ResetGlobalVariables();

    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);
    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(3000);
    EXPECT_NE(g_channelId, firstChannelId);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest038 out");
}

/*
 * @tc.name: ProxyChannelManagerTest039
 * @tc.desc: test ProxyResetHandler skips NotifyDisconnected for CONNECTING state channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest039, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest039 in");
    CleanupProxyChannelRequestInfo();
    ConstructProxyConnectionListConnecting();
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), false);

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest039 out");
}

/*
 * @tc.name: ProxyChannelManagerTest040
 * @tc.desc: test OnProxyBtStateChanged with invalid state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest040, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest040 in");
    ProxyChannelMock mock;

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BLE_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest040 out");
}

/*
 * @tc.name: ProxyChannelManagerTest041
 * @tc.desc: test IsRealMac with all zeros MAC address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest041, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest041 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    CleanupProxyChannelRequestInfo();

    int32_t ret = OpenProxyChannelWithMac("00:00:00:00:00:00");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest041 out");
}

/*
 * @tc.name: ProxyChannelManagerTest042
 * @tc.desc: test ACL state change for device not in reconnect list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest042, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest042 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    SoftBusBtAddr unknownAddr = MakeBtAddr({0x99, 0x88, 0x77, 0x66, 0x55, 0x44});
    ProxyChannelMock::InjectBtAclStateChanged(1, &unknownAddr, SOFTBUS_ACL_STATE_DISCONNECTED, 0);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    EXPECT_EQ(g_connectFailedReason, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest042 out");
}

/*
 * @tc.name: ProxyChannelManagerTest043
 * @tc.desc: test OpenProxyChannel with unpaired device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest043, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest043 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(false));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_CONN_BR_UNPAIRED);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest043 out");
}

/*
 * @tc.name: ProxyChannelManagerTest044
 * @tc.desc: test HandleConcurrentConnect - inner request replaced by external request
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest044, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest044 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyConnectInfo("11:22:33:44:55:66", CHANNELID, true);

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest044 out");
}

/*
 * @tc.name: ProxyChannelManagerTest045
 * @tc.desc: test HandleConcurrentConnect - different device rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest045, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest045 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyConnectInfo("AA:BB:CC:DD:EE:FF");

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CUCURRENT_OPRATION_ERR);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest045 out");
}

/*
 * @tc.name: ProxyChannelManagerTest046
 * @tc.desc: test ProxyDeviceUnpaired with connectingChannel mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest046, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest046 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyConnectInfo("AA:BB:CC:DD:EE:FF");

    std::string addrB = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addrB, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest046 out");
}

/*
 * @tc.name: ProxyChannelManagerTest047
 * @tc.desc: test AttemptReconnectDevice - device already connected, CheckNeedToRetry returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest047, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest047 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillOnce(ProxyChannelMock::ActionOfRead).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    uint32_t originalChannelId = g_channelId;
    EXPECT_NE(originalChannelId, 0);

    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        it->isSupportHfp = false;
    }

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(2000);
    EXPECT_EQ(GetProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest047 out");
}

/*
 * @tc.name: ProxyChannelManagerTest048
 * @tc.desc: test OnProxyAclStateChanged with invalid acl state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest048, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest048 in");
    ProxyChannelMock mock;

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, 99, 0);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest048 out");
}

/*
 * @tc.name: ProxyChannelManagerTest049
 * @tc.desc: test OnObserverStateChanged with invalid state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest049, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest049 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();

    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, 99);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    EXPECT_EQ(g_connectFailedReason, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest049 out");
}

/*
 * @tc.name: ProxyChannelManagerTest050
 * @tc.desc: test IsRealMac with mixed case hex MAC address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest050, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest050 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("aA:bB:cC:dD:eE:fF");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest050 out");
}

/*
 * @tc.name: ProxyChannelManagerTest051
 * @tc.desc: test IsNeedReuseOrWait with DISCONNECTING state returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest051, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest051 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    CleanupProxyChannelRequestInfo();
    ConstructProxyConnectionListDisconnecting();
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), false);

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest051 out");
}

/*
 * @tc.name: ProxyChannelManagerTest052
 * @tc.desc: test ProxyResetHandler with both CONNECTING and CONNECTED connections
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyManagerTest, ProxyChannelManagerTest052, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest052 in");
    CleanupProxyChannelRequestInfo();
    ConstructProxyConnectionListConnecting();
    ConstructProxyConnectionList();
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), false);

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(2000);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(IsListEmpty(&GetProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "ProxyChannelManagerTest052 out");
}
}
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

// Near-field (BR) proxy manager UT: core/connection/proxy/br/br_proxy_manager.c.

#include <gtest/gtest.h>
#include <set>
#include <vector>

#include "mock/proxy_manager_mock.h"
#include "proxy_config.h"
#include "proxy_manager.h"
#include "br_proxy_manager.h"

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
    if (GetBrProxyChannelManager()->proxyChannelRequestInfo != nullptr) {
        SoftBusFree(GetBrProxyChannelManager()->proxyChannelRequestInfo);
        GetBrProxyChannelManager()->proxyChannelRequestInfo = nullptr;
    }
}
}

class BrProxyManagerTest : public testing::Test {
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
    GetBrProxyChannelManager()->proxyChannelRequestInfo = connectInfo;
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        if (!it->isInnerRequest) {
            it->isAclConnected = false;
        }
    }
    g_disconnectReason.push_back(reason);
}

void TestOnProxyChannelReconnected(const char *addr, ProxyChannel *channel)
{
    CONN_LOGI(CONN_PROXY, "test reconnected channelId=%{public}u", channel->channelId);
    g_channelId = channel->channelId;
}

void TestOnBrProxyStateChanged(uint32_t requestId, const char *addr)
{
    (void)requestId;
    (void)addr;
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
    return GetBrProxyChannelManager()->openBrProxyChannel(&param, true, false, &callback);
}

bool IsRealBrMac(const char *brMac)
{
    constexpr int32_t BT_MAC_SEGMENT_LEN = 3;
    for (int32_t i = 0; i < BT_MAC_LEN - 1; i++) {
        if (brMac[i] == '\0') {
            return false;
        }
        if ((i + 1) % BT_MAC_SEGMENT_LEN == 0) {
            if (brMac[i] != ':') {
                return false;
            }
        } else if (!((brMac[i] >= '0' && brMac[i] <= '9') ||
                    (brMac[i] >= 'a' && brMac[i] <= 'f') ||
                    (brMac[i] >= 'A' && brMac[i] <= 'F'))) {
            return false;
        }
    }
    return brMac[BT_MAC_LEN - 1] == '\0';
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
    return GetBrProxyChannelManager()->openBrProxyChannel(&param, IsRealBrMac(brMac), false, &callback);
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        (void)it;
        return true;
    }
    return false;
}

/*
 * @tc.name: BrProxyManagerTest001
 * @tc.desc: test BrProxyChannelManagerInit retry (SoftBusAddBtStateListener / RegisterHfpListener fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest001 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, RegisterHfpListener).WillOnce(Return(-1))
        .WillRepeatedly(ProxyChannelMock::ActionOfRegisterHfpListener);
    EXPECT_CALL(mock, SoftBusAddBtStateListener).WillOnce(Return(-1))
        .WillRepeatedly(ProxyChannelMock::ActionOfAddBtStateListener);
    EXPECT_CALL(mock, InitSppSocketDriver).WillRepeatedly(ProxyChannelMock::ActionOfInitSppSocketDriver);

    int32_t ret = BrProxyChannelManagerInit();
    EXPECT_EQ(ret, -1);
    ret = BrProxyChannelManagerInit();
    EXPECT_EQ(ret, -1);
    ret = BrProxyChannelManagerInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest001 out");
}

/*
 * @tc.name: BrProxyManagerTest003
 * @tc.desc: test registerBrProxyListener and openBrProxyChannel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest003 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Read).WillOnce(ProxyChannelMock::ActionOfRead).WillOnce(Return(-1));
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));
    int32_t ret = GetBrProxyChannelManager()->registerBrProxyListener(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    BrProxyListener listener = {
        .onProxyChannelDataReceived = TestOnProxyChannelDataReceived,
    };
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.onProxyChannelDisconnected = TestOnProxyChannelDisconnected;
    listener.onProxyChannelReconnected = TestOnProxyChannelReconnected;
    listener.onBrProxyStateChanged = TestOnBrProxyStateChanged;
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest003 out");
}

/*
 * @tc.name: BrProxyManagerTest004
 * @tc.desc: test open proxy channel - connect fail then ACL not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(Return(-1)).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_BR_ACL_NOT_EXIST);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004 out");
}

/*
 * @tc.name: BrProxyManagerTest004_1
 * @tc.desc: test open proxy channel - read fail then disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest004_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004_1 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004_1 out");
}

/*
 * @tc.name: BrProxyManagerTest004_2
 * @tc.desc: test open proxy channel - socket closed then disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest004_2, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004_2 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004_2 out");
}

/*
 * @tc.name: BrProxyManagerTest004_3
 * @tc.desc: test open proxy channel - read success then data received then disconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest004_3, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004_3 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest004_3 out");
}

/*
 * @tc.name: BrProxyManagerTest006
 * @tc.desc: test HfpConnectionChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest006 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest006 out");
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
        CONN_LOGW(CONN_PROXY, "destroy proxy channel=%{public}u", proxyConnection->channelId);
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
    int32_t ret = SoftBusMutexLock(&GetBrProxyChannelManager()->proxyConnectionList->lock);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_PROXY, "lock proxyConnectionList fail");
        SoftBusMutexDestroy(&proxyConnection->lock);
        SoftBusFree(proxyConnection);
        return;
    }
    proxyConnection->refCount = 1;
    ListAdd(&GetBrProxyChannelManager()->proxyConnectionList->list, &proxyConnection->node);
    SoftBusMutexUnlock(&GetBrProxyChannelManager()->proxyConnectionList->lock);
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
 * @tc.name: BrProxyManagerTest008
 * @tc.desc: test btStateChanged - BLE state ignored, BR off with requestInfo only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest008 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    ConstructProxyChannelRequestInfo();
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BLE_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_NE(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest008 out");
}

/*
 * @tc.name: BrProxyManagerTest008_1
 * @tc.desc: test btStateChanged - BR off with requestInfo and connectionList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest008_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest008_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(ProxyChannelMock::ActionOfIsPairedDevice);

    ConstructProxyChannelRequestInfo();
    EXPECT_NE(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    ConstructProxyConnectionList();

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest008_1 out");
}

/*
 * @tc.name: BrProxyManagerTest008_2
 * @tc.desc: test btStateChanged - BR off with connectionList only, no requestInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest008_2, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest008_2 in");
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
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest008_2 out");
}

/*
 * @tc.name: BrProxyManagerTest009
 * @tc.desc: test disconnected reason is device unpaired
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest009 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest009 out");
}

/*
 * @tc.name: BrProxyManagerTest009_1
 * @tc.desc: test unpaired device should not reconnect on HFP connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest009_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest009_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(false));

    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_HFP_CONNECTED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest009_1 out");
}

/*
 * @tc.name: BrProxyManagerTest010
 * @tc.desc: test device uparied not retry connect and notify disconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest010, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest010 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest010 out");
}

/*
 * @tc.name: BrProxyManagerTest011
 * @tc.desc: test connect timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest011, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_OPEN_PROXY_TIMEOUT);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011 out");
}

/*
 * @tc.name: BrProxyManagerTest011_1
 * @tc.desc: test connect timeout with null connecting device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest011_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_1 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect1);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_1 out");
}

/*
 * @tc.name: BrProxyManagerTest011_2
 * @tc.desc: test connect timeout with unexpected connecting device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest011_2, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_2 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillOnce(ProxyChannelMock::ActionOfConnect2);
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_2 out");
}

/*
 * @tc.name: BrProxyManagerTest011_3
 * @tc.desc: test concurrent connect operation error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest011_3, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_3 in");
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
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CONCURRENT_OPERATION_ERR);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_3 out");
}

/*
 * @tc.name: BrProxyManagerTest011_4
 * @tc.desc: test unpaired during connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest011_4, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_4 in");
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
    EXPECT_EQ(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_4 out");
}

/*
 * @tc.name: BrProxyManagerTest011_5
 * @tc.desc: test unpaired with requestInfo but no matching connecting channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest011_5, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_5 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyChannelRequestInfo();
    std::string addr = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addr, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest011_5 out");
}

/*
 * @tc.name: BrProxyManagerTest012
 * @tc.desc: test retry after last connect ends
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest012, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest012 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest012 out");
}

/*
 * @tc.name: BrProxyManagerTest013
 * @tc.desc: test proxy connect callback with ActionOfConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest013, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest013 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest013 out");
}

/*
 * @tc.name: BrProxyManagerTest013_1
 * @tc.desc: test proxy connect callback with ActionOfConnect3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest013_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest013_1 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest013_1 out");
}

/*
 * @tc.name: BrProxyManagerTest014
 * @tc.desc: test close not reset reconnect event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest014, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest014 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest014 out");
}

/*
 * @tc.name: BrProxyManagerTest014_1
 * @tc.desc: test ACL reconnect after channel close triggers reconnection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest014_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest014_1 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest014_1 out");
}

/*
 * @tc.name: BrProxyManagerTest015
 * @tc.desc: test IsRealMac with various MAC address formats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest015, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest015 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    ResetGlobalVariables();
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest015 out");
}

/*
 * @tc.name: BrProxyManagerTest017
 * @tc.desc: test MAC address with invalid separator
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest017, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest017 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11-22-33-44-55-66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest017 out");
}

/*
 * @tc.name: BrProxyManagerTest018
 * @tc.desc: test MAC address with invalid characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest018, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest018 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:GG");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest018 out");
}

/*
 * @tc.name: BrProxyManagerTest019
 * @tc.desc: test reconnect device info management
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest019, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest019 in");
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        EXPECT_EQ(it->innerRetryNum, 0);
    }
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest019 out");
}

/*
 * @tc.name: BrProxyManagerTest019_1
 * @tc.desc: test updating existing reconnect device info resets innerRetryNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest019_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest019_1 in");
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        EXPECT_EQ(it->innerRetryNum, 0);
    }
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest019_1 out");
}

/*
 * @tc.name: BrProxyManagerTest020
 * @tc.desc: test disconnect while connecting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest020, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest020 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest020 out");
}

/*
 * @tc.name: BrProxyManagerTest021
 * @tc.desc: test connection state transitions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest021, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest021 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest021 out");
}

/*
 * @tc.name: BrProxyManagerTest022
 * @tc.desc: test single device reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest022, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest022 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest022 out");
}

/*
 * @tc.name: BrProxyManagerTest022_1
 * @tc.desc: test multiple devices reconnect management
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest022_1, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest022_1 in");
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        reconnectCount++;
    }
    EXPECT_EQ(reconnectCount, 2);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest022_1 out");
}

/*
 * @tc.name: BrProxyManagerTest024
 * @tc.desc: test ACL disconnected state handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest024, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest024 in");
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        EXPECT_FALSE(it->isAclConnected);
    }
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest024 out");
}

/*
 * @tc.name: BrProxyManagerTest025
 * @tc.desc: test get channel by address functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest025, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest025 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    // Test getConnectionById with invalid ID
    ProxyConnection *conn = GetBrProxyChannelManager()->getConnectionById(99999);
    EXPECT_EQ(conn, nullptr);

    // Test getProxyChannelByAddr with non-existent address
    conn = GetBrProxyChannelManager()->getProxyChannelByAddr(const_cast<char*>("FF:EE:DD:CC:BB:AA"));
    EXPECT_EQ(conn, nullptr);

    // Open a channel
    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest025 out");
}

/*
 * @tc.name: BrProxyManagerTest027
 * @tc.desc: test Bluetooth state ON triggers reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest027, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest027 in");
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
    EXPECT_EQ(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);

    // Turn on Bluetooth - should trigger reconnect
    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_ON);
    SoftBusSleepMs(2000);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest027 out");
}

/*
 * @tc.name: BrProxyManagerTest028
 * @tc.desc: test retry limit reached
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest028, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest028 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest028 out");
}

/*
 * @tc.name: BrProxyManagerTest029
 * @tc.desc: test ProxyChannelSend with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest029, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest029 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest029 out");
}

/*
 * @tc.name: BrProxyManagerTest032
 * @tc.desc: test ProxyChannelClose with null channel pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest032, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest032 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest032 out");
}

/*
 * @tc.name: BrProxyManagerTest033
 * @tc.desc: test ProxyChannelSend with underlying send error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest033, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest033 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest033 out");
}

/*
 * @tc.name: BrProxyManagerTest037
 * @tc.desc: test ProxyDeviceUnpaired with no reconnect device info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest037, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest037 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest037 out");
}

/*
 * @tc.name: BrProxyManagerTest038
 * @tc.desc: test AclStateChangedHandler with isSupportHfp=false triggers immediate reconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest038, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest038 in");
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        it->isSupportHfp = false;
    }
    ResetGlobalVariables();

    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);
    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(3000);
    EXPECT_NE(g_channelId, firstChannelId);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest038 out");
}

/*
 * @tc.name: BrProxyManagerTest039
 * @tc.desc: test ProxyResetHandler skips NotifyDisconnected for CONNECTING state channel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest039, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest039 in");
    CleanupProxyChannelRequestInfo();
    ConstructProxyConnectionListConnecting();
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), false);

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(2000);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest039 out");
}

/*
 * @tc.name: BrProxyManagerTest040
 * @tc.desc: test OnProxyBtStateChanged with invalid state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest040, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest040 in");
    ProxyChannelMock mock;

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BLE_STATE_TURN_OFF);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest040 out");
}

/*
 * @tc.name: BrProxyManagerTest042
 * @tc.desc: test ACL state change for device not in reconnect list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest042, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest042 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest042 out");
}

/*
 * @tc.name: BrProxyManagerTest043
 * @tc.desc: test OpenProxyChannel with unpaired device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest043, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest043 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(false));

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_CONN_BR_UNPAIRED);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest043 out");
}

/*
 * @tc.name: BrProxyManagerTest044
 * @tc.desc: test HandleConcurrentConnect - inner request replaced by external request
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest044, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest044 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyConnectInfo("11:22:33:44:55:66", CHANNELID, true);

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CONCURRENT_OPERATION_ERR);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest044 out");
}

/*
 * @tc.name: BrProxyManagerTest045
 * @tc.desc: test HandleConcurrentConnect - different device rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest045, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest045 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyConnectInfo("AA:BB:CC:DD:EE:FF");

    int32_t ret = OpenProxyChannelWithMac("11:22:33:44:55:66");
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, SOFTBUS_CONN_PROXY_CONCURRENT_OPERATION_ERR);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest045 out");
}

/*
 * @tc.name: BrProxyManagerTest046
 * @tc.desc: test ProxyDeviceUnpaired with connectingChannel mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest046, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest046 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    ConstructProxyConnectInfo("AA:BB:CC:DD:EE:FF");

    std::string addrB = "11:22:33:44:55:66";
    ProxyChannelMock::InjectHfpConnectionChanged(addrB, SOFTBUS_DEVICE_UNPAIRED);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    CleanupProxyChannelRequestInfo();
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest046 out");
}

/*
 * @tc.name: BrProxyManagerTest047
 * @tc.desc: test AttemptReconnectDevice - device already connected, CheckNeedToRetry returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest047, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest047 in");
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
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        it->isSupportHfp = false;
    }

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, SOFTBUS_ACL_STATE_CONNECTED, 0);
    SoftBusSleepMs(2000);
    EXPECT_EQ(GetBrProxyChannelManager()->proxyChannelRequestInfo, nullptr);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest047 out");
}

/*
 * @tc.name: BrProxyManagerTest048
 * @tc.desc: test OnProxyAclStateChanged with invalid acl state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest048, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest048 in");
    ProxyChannelMock mock;

    SoftBusBtAddr btAddr = MakeBtAddr(DEFAULT_BT_ADDR);
    ProxyChannelMock::InjectBtAclStateChanged(1, &btAddr, 99, 0);
    SoftBusSleepMs(1000);
    EXPECT_EQ(g_connectFailedReason, 0);
    EXPECT_EQ(g_disconnectReason.size(), 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest048 out");
}

/*
 * @tc.name: BrProxyManagerTest049
 * @tc.desc: test OnObserverStateChanged with invalid state is ignored
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest049, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest049 in");
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
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest049 out");
}

/*
 * @tc.name: BrProxyManagerTest051
 * @tc.desc: test IsNeedReuseOrWait with DISCONNECTING state returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest051, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest051 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(Return(-1));
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    CleanupProxyChannelRequestInfo();
    ConstructProxyConnectionListDisconnecting();
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), false);

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(2000);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest051 out");
}

/*
 * @tc.name: BrProxyManagerTest052
 * @tc.desc: test ProxyResetHandler with both CONNECTING and CONNECTED connections
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest052, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest052 in");
    CleanupProxyChannelRequestInfo();
    ConstructProxyConnectionListConnecting();
    ConstructProxyConnectionList();
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), false);

    ProxyChannelMock::InjectBtStateChanged(0, SOFTBUS_BR_STATE_TURN_OFF);
    SoftBusSleepMs(2000);
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_EQ(g_disconnectReason[0], SOFTBUS_CONN_BLUETOOTH_OFF);
    EXPECT_EQ(IsListEmpty(&GetBrProxyChannelManager()->proxyConnectionList->list), true);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest052 out");
}

/*
 * @tc.name: BrProxyManagerTest053
 * @tc.desc: test getConnectionById returns the live connection and increments refcount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest053, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest053 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead);
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    ASSERT_NE(g_channelId, 0);

    ProxyConnection *conn = GetBrProxyChannelManager()->getConnectionById(g_channelId);
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(conn->channelId, g_channelId);
    conn->dereference(conn);

    ProxyChannel proxyChannel = { .channelId = g_channelId };
    g_channel->close(&proxyChannel, true);
    SoftBusSleepMs(1000);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest053 out");
}

/*
 * @tc.name: BrProxyManagerTest054
 * @tc.desc: test getProxyChannelByAddr returns the live connection by mac address
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest054, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest054 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead);
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    ASSERT_NE(g_channelId, 0);

    ProxyConnection *conn = GetBrProxyChannelManager()->getProxyChannelByAddr(
        const_cast<char *>("11:22:33:44:55:66"));
    ASSERT_NE(conn, nullptr);
    conn->dereference(conn);

    ProxyChannel proxyChannel = { .channelId = g_channelId };
    g_channel->close(&proxyChannel, true);
    SoftBusSleepMs(1000);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest054 out");
}

/*
 * @tc.name: BrProxyManagerTest055
 * @tc.desc: test updateDevInfoReqIdUnsafe updates reconnect device requestId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest055, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest055 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead);
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    ASSERT_NE(g_channelId, 0);
    ASSERT_TRUE(HasReconnectDevice());

    constexpr uint32_t NEW_REQ_ID = 8888;
    GetBrProxyChannelManager()->updateDevInfoReqIdUnsafe("11:22:33:44:55:66", NEW_REQ_ID);
    SoftBusSleepMs(500);
    uint32_t gotReqId = 0;
    ProxyConnectInfo *it = nullptr;
    LIST_FOR_EACH_ENTRY(it, &GetBrProxyChannelManager()->reconnectDeviceInfos, ProxyConnectInfo, node) {
        gotReqId = it->requestId;
    }
    EXPECT_EQ(gotReqId, NEW_REQ_ID);

    ProxyChannel proxyChannel = { .channelId = g_channelId };
    g_channel->close(&proxyChannel, true);
    SoftBusSleepMs(1000);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest055 out");
}

/*
 * @tc.name: BrProxyManagerTest056
 * @tc.desc: test ProxyChannelRefresh closes the old channel and re-establishes a new one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest056, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest056 in");
    ProxyChannelMock mock;
    EXPECT_CALL(mock, Connect).WillRepeatedly(Return(UNDERLAYER_HANDLE));
    EXPECT_CALL(mock, Read).WillRepeatedly(ProxyChannelMock::ActionOfRead);
    EXPECT_CALL(mock, IsPairedDevice).WillRepeatedly(Return(true));

    int32_t ret = ConstructParamAndOpenProxyChannel(1, CONNECT_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusSleepMs(1000);
    ASSERT_NE(g_channelId, 0);
    ASSERT_NE(g_channel, nullptr);
    uint32_t oldChannelId = g_channelId;

    ProxyChannelMock::InjectProxyConfigRetryCustomTimes(2);
    OpenProxyChannelCallback callback = {
        .onOpenFail = TestOnOpenFail,
        .onOpenSuccess = TestOnOpenSuccess,
    };
    // refresh closes the existing channel and posts a reconnect with the new callback
    g_channel->refresh(g_channel, 9999, &callback);
    SoftBusSleepMs(3000);
    // refresh triggers a close -> disconnect notification, and a reconnect -> new channel
    EXPECT_GE(g_disconnectReason.size(), 1);
    EXPECT_NE(g_channelId, 0);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest056 out, old=%{public}u, new=%{public}u", oldChannelId, g_channelId);
}

/*
 * @tc.name: BrProxyManagerTest057
 * @tc.desc: test registerBrProxyListener param validation (null / missing callbacks) and success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyManagerTest, BrProxyManagerTest057, TestSize.Level1)
{
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest057 in");
    int32_t ret = GetBrProxyChannelManager()->registerBrProxyListener(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    BrProxyListener listener = {};
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.onProxyChannelDisconnected = [](ProxyChannel *channel, int32_t reason) {
        (void)channel;
        (void)reason;
    };
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.onProxyChannelDataReceived = [](ProxyChannel *channel, const uint8_t *data, uint32_t dataLen) {
        (void)channel;
        (void)data;
        (void)dataLen;
    };
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.onProxyChannelReconnected = [](const char *addr, ProxyChannel *channel) {
        (void)addr;
        (void)channel;
    };
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listener.onBrProxyStateChanged = [](uint32_t requestId, const char *addr) {
        (void)requestId;
        (void)addr;
    };
    ret = GetBrProxyChannelManager()->registerBrProxyListener(&listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CONN_LOGI(CONN_PROXY, "BrProxyManagerTest057 out");
}
}
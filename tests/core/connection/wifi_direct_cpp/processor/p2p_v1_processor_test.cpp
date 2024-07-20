/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define private   public
#define protected public
#include "processor/p2p_v1_processor.h"
#undef protected
#undef private

#include <future>
#include <memory>

#include <securec.h>

#include <gtest/gtest.h>

#include "kits/c/wifi_device.h"

#include "channel/proxy_negotiate_channel.h"
#include "command/command_factory.h"
#include "data/interface_manager.h"
#include "data/link_manager.h"
#include "wifi_direct_scheduler.h"
#include "wifi_direct_scheduler_factory.h"

#include "entity/p2p_entity.h"
#include "wifi_direct_mock.h"
#include "net_conn_client.h"
#include "wifi_direct_test_context.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;

namespace OHOS::SoftBus {
class P2pV1ProcessorTest : public testing::Test {
public:
    static OHOS::NetManagerStandard::MockNetConnClient netClientMocker_;
    static void SetUpTestCase() {
        EXPECT_CALL(netClientMocker_, RemoveNetworkRoute).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelInterfaceAddress).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelStaticArp).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, RemoveNetworkRoute).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelInterfaceAddress).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelStaticArp).WillRepeatedly(Return(0));
        // do not care about result, so define mocker global and allow leak check
        Mock::AllowLeak(&netClientMocker_);
    }

    static void TearDownTestCase() { }
    void SetUp() override
    {
        PrepareContext();
    }
    void TearDown() override
    {
        context_.Reset();
    }

protected:
    void PrepareContext();
    void InjectData(WifiDirectInterfaceMock &mock);
    void InjectCommonMock(WifiDirectInterfaceMock &mock);
    void InjectEntityMock(P2pEntity &mock);
    void PrepareConnectParameter(WifiDirectConnectInfo &info, WifiDirectConnectCallback &callback);
    void InjectChannel(WifiDirectInterfaceMock &mock);

    WifiDirectTestContext<TestContextKey> context_;
};

OHOS::NetManagerStandard::MockNetConnClient P2pV1ProcessorTest::netClientMocker_;

void P2pV1ProcessorTest::PrepareContext()
{
    context_.Set(TestContextKey::LOCAL_NETWORK_ID, std::string("local_network_id_0123456789ABCDEFGH"));
    context_.Set(TestContextKey::LOCAL_UUID, std::string("local_uuid_0123456789ABCDEFGH"));
    context_.Set(TestContextKey::LOCAL_MAC, std::string("11:11:11:11:11"));
    context_.Set(TestContextKey::LOCAL_IPV4, std::string("192.168.49.1"));

    context_.Set(TestContextKey::REMOTE_NETWORK_ID, std::string("remote_network_id_0123456789ABCDEFGH"));
    context_.Set(TestContextKey::REMOTE_UUID, std::string("remote_uuid_0123456789ABCDEFGH"));
    context_.Set(TestContextKey::REMOTE_MAC, std::string("11:22:33:44:55"));
    context_.Set(TestContextKey::REMOTE_IPV4, std::string("192.168.49.3"));

    // request param
    context_.Set(TestContextKey::CONNECT_REQUEST_ID, uint32_t(111));
    context_.Set(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(333));
    context_.Set(TestContextKey::CONNECT_REUSE_ONLY, false);
    context_.Set(TestContextKey::CONNECT_EXPECT_API_ROLE, WifiDirectApiRole(WIFI_DIRECT_API_ROLE_NONE));

    // device state
    context_.Set(TestContextKey::WIFI_P2P_STATE, P2pState(P2P_STATE_STARTED));
    context_.Set(TestContextKey::WIFI_5G_CHANNEL_LIST,
        std::pair<WifiErrorCode, std::vector<int>>(WIFI_SUCCESS, std::vector<int> { 36, 48, 149 }));
    context_.Set(TestContextKey::WIFI_GET_SELF_CONFIG, WifiErrorCode(WIFI_SUCCESS));
    context_.Set(TestContextKey::WIFI_WIDE_BAND_WIDTH_SUPPORT, true);
    context_.Set(TestContextKey::WIFI_STA_FREQUENCY, int(2417));
    context_.Set(TestContextKey::WIFI_RECOMMEND_FREQUENCY, int(2417));
    context_.Set(TestContextKey::WIFI_REQUEST_GC_IP,
        std::pair<WifiErrorCode, std::vector<int>>(WIFI_SUCCESS, std::vector<int> { 192, 168, 1, 1 }));

    context_.Set(TestContextKey::CHANNEL_SEND_MESSAGE, int(SOFTBUS_OK));

    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, false);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);
}

void P2pV1ProcessorTest::InjectData(WifiDirectInterfaceMock &mock)
{
    EXPECT_CALL(mock, GetP2pEnableStatus(_)).WillRepeatedly([this](P2pState *state) {
        auto value = context_.Get(TestContextKey::WIFI_P2P_STATE, P2pState(P2P_STATE_NONE));
        *state = value;
        return WIFI_SUCCESS;
    });
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([this](int *chanList, int len) {
        auto value = context_.Get(TestContextKey::WIFI_5G_CHANNEL_LIST, std::pair<WifiErrorCode, std::vector<int>>());
        for (size_t i = 0; i < len && i < value.second.size(); i++) {
            chanList[i] = value.second[i];
        }
        return value.first;
    });
    EXPECT_CALL(mock, Hid2dGetSelfWifiCfgInfo(TYPE_OF_GET_SELF_CONFIG, _, _))
        .WillRepeatedly(Return(context_.Get(TestContextKey::WIFI_GET_SELF_CONFIG, WifiErrorCode(WIFI_SUCCESS))));

    EXPECT_CALL(mock, Hid2dIsWideBandwidthSupported())
        .WillRepeatedly(Return(context_.Get(TestContextKey::WIFI_WIDE_BAND_WIDTH_SUPPORT, true)));

    EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly([this](WifiLinkedInfo *result) {
        result->frequency = context_.Get(TestContextKey::WIFI_STA_FREQUENCY, int(0));
        return WIFI_SUCCESS;
    });
    EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _))
        .WillRepeatedly([this](const RecommendChannelRequest *request, RecommendChannelResponse *response) {
            response->centerFreq = context_.Get(TestContextKey::WIFI_RECOMMEND_FREQUENCY, int(0));
            return WIFI_SUCCESS;
        });
    EXPECT_CALL(mock, Hid2dRequestGcIp(_, _))
        .WillRepeatedly([this](const unsigned char gcMac[MAC_LEN], unsigned int ipAddr[IPV4_ARRAY_LEN]) {
            auto value = context_.Get(TestContextKey::WIFI_REQUEST_GC_IP, std::pair<WifiErrorCode, std::vector<int>>());
            for (size_t i = 0; i < IPV4_ARRAY_LEN && i < value.second.size(); i++) {
                ipAddr[i] = value.second[i];
            }
            return value.first;
        });

    InterfaceManager::GetInstance().InitInterface(InterfaceInfo::InterfaceType::P2P);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
    auto injectLocal = context_.Get(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, false);
    auto injectRemote = context_.Get(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);
    if (injectLocal || injectRemote) {
        auto remoteDeviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
        LinkManager::GetInstance().ProcessIfAbsent(
            InnerLink::LinkType::P2P, remoteDeviceId, [this, injectLocal, injectRemote](InnerLink &link) {
                link.SetState(InnerLink::LinkState::CONNECTED);
                link.SetLocalIpv4(context_.Get(TestContextKey::LOCAL_IPV4, std::string("")));
                link.SetRemoteIpv4(context_.Get(TestContextKey::REMOTE_IPV4, std::string("")));
                link.SetLocalBaseMac(context_.Get(TestContextKey::LOCAL_MAC, std::string("")));
                link.SetRemoteBaseMac(context_.Get(TestContextKey::REMOTE_MAC, std::string("")));
                if (injectLocal) {
                    link.AddId(1, 1, 1);
                }
                if (injectRemote) {
                    link.SetBeingUsedByRemote(true);
                }
            });
    }
}

void P2pV1ProcessorTest::InjectEntityMock(P2pEntity &mock)
{
    EXPECT_CALL(mock, CreateGroup(_)).WillRepeatedly([](const P2pCreateGroupParam &param) {
        P2pOperationResult result {};
        result.errorCode_ = SOFTBUS_OK;
        return result;
    });
    EXPECT_CALL(mock, Connect(_)).WillRepeatedly([](const P2pConnectParam &param) {
        P2pOperationResult result {};
        result.errorCode_ = SOFTBUS_OK;
        return result;
    });
    EXPECT_CALL(mock, DestroyGroup(_)).WillRepeatedly([](const P2pDestroyGroupParam &param) {
        P2pOperationResult result {};
        result.errorCode_ = SOFTBUS_OK;
        return result;
    });
    EXPECT_CALL(mock, ReuseLink()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, Disconnect(_)).WillRepeatedly([](const P2pDestroyGroupParam &param) {
        P2pOperationResult result {};
        result.errorCode_ = SOFTBUS_OK;
        return result;
    });
    EXPECT_CALL(mock, NotifyNewClientJoining(_)).WillRepeatedly([](const std::string &remoteMac) {});
}

void P2pV1ProcessorTest::InjectCommonMock(WifiDirectInterfaceMock &mock)
{
    auto networkId = context_.Get(TestContextKey::REMOTE_NETWORK_ID, std::string(""));
    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo(networkId, STRING_KEY_UUID, _, _))
        .WillRepeatedly([this](const std::string &networkId, InfoKey key, char *info, uint32_t len) {
            auto id = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
            (void)strcpy_s(info, len, id.c_str());
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid(deviceId, _, _))
        .WillRepeatedly([this](const std::string &uuid, char *buf, uint32_t len) {
            auto id = context_.Get(TestContextKey::REMOTE_NETWORK_ID, std::string(""));
            (void)strcpy_s(buf, len, id.c_str());
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, LnnGetRemoteBoolInfo(networkId, BOOL_KEY_TLV_NEGOTIATION, _))
        .WillRepeatedly([](const std::string &networkId, InfoKey key, bool *info) {
            *info = false;
            return SOFTBUS_OK;
        });
    // 0x177C2 from LNN_SUPPORT_FEATURE softbus_feature_config.c, which not support BIT_WIFI_DIRECT_TLV_NEGOTIATION
    EXPECT_CALL(mock, LnnGetFeatureCapabilty()).WillRepeatedly(Return(0x177C2));
    EXPECT_CALL(mock, LnnGetLocalStrInfo(STRING_KEY_UUID, _, _))
        .WillRepeatedly([this](InfoKey key, char *info, uint32_t len) {
            auto id = context_.Get(TestContextKey::LOCAL_UUID, std::string(""));
            (void)strcpy_s(info, len, id.c_str());
            return SOFTBUS_OK;
        });
    EXPECT_CALL(mock, LnnGetLocalStrInfo(STRING_KEY_NETWORKID, _, _))
        .WillRepeatedly([this](InfoKey key, char *info, uint32_t len) {
            auto id = context_.Get(TestContextKey::LOCAL_NETWORK_ID, std::string(""));
            (void)strcpy_s(info, len, id.c_str());
            return SOFTBUS_OK;
        });
    EXPECT_CALL(
        mock, ProxyNegotiateChannelGetRemoteDeviceId(context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0))))
        .WillRepeatedly(Return(context_.Get(TestContextKey::REMOTE_UUID, std::string(""))));
}

void P2pV1ProcessorTest::PrepareConnectParameter(WifiDirectConnectInfo &info, WifiDirectConnectCallback &callback)
{
    info.requestId = context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0));
    info.pid = 222;
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    info.negoChannel.type = NEGO_CHANNEL_COC;
    info.negoChannel.handle.channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));

    info.reuseOnly = false;
    info.expectApiRole = WIFI_DIRECT_API_ROLE_NONE;
    info.isStrict = false;
    (void)strcpy_s(info.remoteNetworkId, sizeof(info.remoteNetworkId),
        context_.Get(TestContextKey::REMOTE_NETWORK_ID, std::string("")).c_str());

    (void)strcpy_s(
        info.remoteMac, sizeof(info.remoteMac), context_.Get(TestContextKey::REMOTE_MAC, std::string("")).c_str());
    info.isNetworkDelegate = false;
    info.bandWidth = 0;
    info.ipAddrType = IpAddrType::IPV4;

    WifiDirectInterfaceMock::InjectWifiDirectConnectCallbackMock(callback);
}

void P2pV1ProcessorTest::InjectChannel(WifiDirectInterfaceMock &mock)
{
    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    auto uuid = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    EXPECT_CALL(mock, ProxyNegotiateChannelGetRemoteDeviceId(channelId)).WillRepeatedly(Return(uuid));

    auto ret = context_.Get(TestContextKey::CHANNEL_SEND_MESSAGE, int(0));
    EXPECT_CALL(mock, ProxyNegotiateChannelSendMessage(channelId, _)).WillRepeatedly(Return(ret));

    EXPECT_CALL(mock, AuthStartListeningForWifiDirect(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
}

/*
 * @tc.name: GetStateName
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, GetStateName, TestSize.Level1)
{
    auto value = P2pV1Processor::GetStateName(&P2pV1Processor::AvailableState);
    EXPECT_EQ(value, "AvailableState");

    value = P2pV1Processor::GetStateName(&P2pV1Processor::OnWaitReqResponseTimeoutEvent);
    EXPECT_EQ(value, "UNKNOWN_STATE");
}

/*
 * @tc.name: IsNeedDhcp
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, IsNeedDhcp, TestSize.Level1)
{
    std::string enableDhcpGroupCfg = "DIRECT-XXX\n11:22:33:44:55:66\n12345678\n5170\n1";
    auto value = P2pV1Processor::IsNeedDhcp("", enableDhcpGroupCfg);
    EXPECT_EQ(value, true);

    value = P2pV1Processor::IsNeedDhcp("192.168.1.1", enableDhcpGroupCfg);
    EXPECT_EQ(value, true);

    std::string disableDhcpGroupCfg = "DIRECT-XXX\n11:22:33:44:55:66\n12345678\n5170\n0";
    value = P2pV1Processor::IsNeedDhcp("192.168.1.1", disableDhcpGroupCfg);
    EXPECT_EQ(value, false);
}

/*
 * @tc.name: ChooseFrequency
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ChooseFrequency, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    auto doMock = [&mock](int stationFreq, int recommendFreq, std::vector<int> channels) {
        EXPECT_CALL(mock, GetLinkedInfo(_)).WillRepeatedly([stationFreq](WifiLinkedInfo *result) {
            result->frequency = stationFreq;
            return WIFI_SUCCESS;
        });
        EXPECT_CALL(mock, Hid2dGetRecommendChannel(_, _))
            .WillRepeatedly(
                [recommendFreq](const RecommendChannelRequest *request, RecommendChannelResponse *response) {
                    response->centerFreq = recommendFreq;
                    return WIFI_SUCCESS;
                });
        EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([channels](int *chanList, int len) {
            for (int i = 0; i < channels.size() && i < len; ++i) {
                chanList[i] = channels[i];
            }
            return WIFI_SUCCESS;
        });
    };
    std::vector<int> gcChannels;

    doMock(2412, 2412, std::vector<int>());
    auto value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2412);

    doMock(-1, 2417, std::vector<int>());
    value = P2pV1Processor::ChooseFrequency(2417, gcChannels);
    EXPECT_EQ(value, 2417);

    doMock(-1, -1, std::vector<int> { 2, 13 });
    gcChannels.push_back(1);
    gcChannels.push_back(2);
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2417);

    doMock(2412, -1, std::vector<int>());
    gcChannels.clear();
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2412);

    doMock(-1, -1, std::vector<int>());
    value = P2pV1Processor::ChooseFrequency(2417, gcChannels);
    EXPECT_EQ(value, 2417);

    doMock(-1, -1, std::vector<int>());
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, 2412);

    doMock(-1, -1, std::vector<int>());
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([](int *chanList, int len) {
        return ERROR_WIFI_IFACE_INVALID;
    });
    value = P2pV1Processor::ChooseFrequency(-1, gcChannels);
    EXPECT_EQ(value, ToSoftBusErrorCode(ERROR_WIFI_IFACE_INVALID));
}

/*
 * @tc.name: CreateAsTimeout
 * @tc.desc: whole process test, wait response timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, CreateAsTimeout, TestSize.Level1)
{
    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<int> result;
    EXPECT_CALL(mock, OnConnectFailure(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, int32_t reason) {
            result.set_value(reason);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(P2pV1Processor::P2P_V1_WAITING_RESPONSE_TIME_MS + 1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_EQ(value, SOFTBUS_CONN_PV1_WAIT_CONNECT_RESPONSE_TIMEOUT);
}

/*
 * @tc.name: CreateWhenNoneAsGo
 * @tc.desc: whole process test,
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, CreateWhenNoneAsGo, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("a6:3b:0e:78:29:dd"));
    context_.Set(TestContextKey::WIFI_STA_FREQUENCY, int(5180));
    context_.Set(TestContextKey::WIFI_RECOMMEND_FREQUENCY, int(5180));
    context_.Set(TestContextKey::WIFI_REQUEST_GC_IP,
        std::pair<WifiErrorCode, std::vector<int>>(WIFI_SUCCESS, std::vector<int> { 192, 168, 49, 3 }));

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    EXPECT_CALL(mock, ProxyNegotiateChannelSendMessage(channelId, _))
        .WillOnce([](int32_t channelId, const NegotiateMessage &msg) {
            std::string message =
                R"({"KEY_COMMAND_TYPE":9,"KEY_CONTENT_TYPE":2,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"a6:3b:0e:78:29:dd","KEY_GO_MAC":"42:dc:a5:f3:4c:14","KEY_IP":"","KEY_MAC":"a6:3b:0e:78:29:dd","KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})";
            CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);
            return SOFTBUS_OK;
        })
        .WillOnce([](int32_t channelId, const NegotiateMessage &msg) {
            std::string message =
                R"({"KEY_COMMAND_TYPE":9,"KEY_CONTENT_TYPE":3,"KEY_IP":"192.168.49.3","KEY_MAC":"a6:3b:0e:78:29:dd","KEY_RESULT":0,"KEY_VERSION":2})";
            CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);

            std::string handShake = R"({"KEY_COMMAND_TYPE":13,"KEY_IP":"192.168.49.3","KEY_MAC":"a6:3b:0e:78:29:dd"})";
            CoCProxyNegotiateChannel::InjectReceiveData(channelId, handShake);
            return SOFTBUS_OK;
        })
        .WillRepeatedly(Return(context_.Get(TestContextKey::CHANNEL_SEND_MESSAGE, int(0))));

    EXPECT_CALL(entityMock, NotifyNewClientJoining(_)).WillRepeatedly([this](const std::string &remoteMac) {
        auto remoteDeviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
        ClientJoinEvent event { SOFTBUS_OK, remoteDeviceId, remoteMac };
        WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
    });

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<bool> result;
    EXPECT_CALL(mock, OnConnectSuccess(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, const struct WifiDirectLink *link) {
            result.set_value(true);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_TRUE(value);

    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: ReuseLocalLinkSuccess
 * @tc.desc: reuse local link success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ReuseLocalLinkSuccess, TestSize.Level1)
{
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<bool> result;
    EXPECT_CALL(mock, OnConnectSuccess(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, const struct WifiDirectLink *link) {
            result.set_value(true);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_TRUE(value);

    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: ReuseRemoteLinkSuccess
 * @tc.desc: reuse remote link success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ReuseRemoteLinkSuccess, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("a6:3b:0e:78:29:dd"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, false);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, true);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    EXPECT_CALL(mock, ProxyNegotiateChannelSendMessage(channelId, _))
        .WillOnce([](int32_t channelId, const NegotiateMessage &msg) {
            std::string message = R"({"KEY_COMMAND_TYPE":19,"KEY_RESULT":0, "KEY_MAC":"a6:3b:0e:78:29:dd"})";
            CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);
            return SOFTBUS_OK;
        });

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<bool> result;
    EXPECT_CALL(mock, OnConnectSuccess(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, const struct WifiDirectLink *link) {
            result.set_value(true);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_TRUE(value);

    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: ReuseRemoteLinkTimeout
 * @tc.desc: reuse remote link timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ReuseRemoteLinkTimeout, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("a6:3b:0e:78:29:dd"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, false);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, true);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<int> result;
    EXPECT_CALL(mock, OnConnectFailure(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, int32_t reason) {
            result.set_value(reason);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status =
        future.wait_for(std::chrono::milliseconds(P2pV1Processor::P2P_V1_WAITING_REUSE_RESPONSE_TIME_MS + 1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_EQ(value, SOFTBUS_CONN_SOURCE_REUSE_LINK_FAILED);

    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}
} // namespace OHOS::SoftBus

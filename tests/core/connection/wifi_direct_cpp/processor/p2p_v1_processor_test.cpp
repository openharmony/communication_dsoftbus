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
#include "net_conn_client.h"
#include "wifi_direct_mock.h"
#include "wifi_direct_test_context.h"

// for fuzz test
#include "fuzz_data_generator.h"
#include "fuzz_environment.h"
#include "p2p_v1_fuzz_helper.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;

namespace OHOS::SoftBus {
class P2pV1ProcessorTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override
    {
        PrepareContext();

        // do not care about result
        EXPECT_CALL(netClientMocker_, RemoveNetworkRoute).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelInterfaceAddress).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelStaticArp).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, RemoveNetworkRoute).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelInterfaceAddress).WillRepeatedly(Return(0));
        EXPECT_CALL(netClientMocker_, DelStaticArp).WillRepeatedly(Return(0));
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
    void PrepareDisconnectParameter(WifiDirectDisconnectInfo &info, WifiDirectForceDisconnectInfo &forceInfo,
        WifiDirectDisconnectCallback &callback);
    void InjectChannel(WifiDirectInterfaceMock &mock);

    WifiDirectTestContext<TestContextKey> context_;
    OHOS::NetManagerStandard::MockNetConnClient netClientMocker_;
};

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

    context_.Set(TestContextKey::INTERFACE_ROLE, LinkInfo::LinkMode::NONE);
}

void P2pV1ProcessorTest::InjectData(WifiDirectInterfaceMock &mock)
{
    EXPECT_CALL(mock, GetP2pEnableStatus(_)).WillRepeatedly([this](P2pState *state) {
        auto value = context_.Get(TestContextKey::WIFI_P2P_STATE, P2pState(P2P_STATE_NONE));
        *state = value;
        return WIFI_SUCCESS;
    });
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([this](int32_t *chanList, int32_t len) {
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
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [this](InterfaceInfo &interface) {
        interface.SetReuseCount(0);
        auto role = context_.Get(TestContextKey::INTERFACE_ROLE, LinkInfo::LinkMode::NONE);
        interface.SetRole(role);
        return SOFTBUS_OK;
    });

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
        auto reuseCount = (injectLocal ? 1 : 0) + (injectRemote ? 1 : 0);
        InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [reuseCount](InterfaceInfo &interface) {
            interface.SetReuseCount(reuseCount);
            return SOFTBUS_OK;
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
    EXPECT_CALL(mock, CancelNewClientJoining(_)).WillRepeatedly([](const std::string &remoteMac) {});
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
    EXPECT_CALL(mock, LnnGetRemoteBoolInfoIgnoreOnline(networkId, BOOL_KEY_TLV_NEGOTIATION, _))
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
    EXPECT_CALL(mock, LnnSetLocalNumInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnSetLocalStrInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnSyncP2pInfo()).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthGenRequestId()).WillRepeatedly(Return(0));
    EXPECT_CALL(mock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly([this](int64_t authId, char *uuid, uint16_t size) {
        auto id = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
        (void)strcpy_s(uuid, size, id.c_str());
        return SOFTBUS_OK;
    });
    EXPECT_CALL(mock, AuthPostTransData(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, IsFeatureSupport(_, _)).WillRepeatedly([](uint64_t feature, FeatureCapability capaBit) {
        return ((feature & (1 << (uint64_t)capaBit)) != 0);
    });
    EXPECT_CALL(mock, AuthCloseConn(_)).WillRepeatedly([](AuthHandle authHandle) {});
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
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

void P2pV1ProcessorTest::PrepareDisconnectParameter(
    WifiDirectDisconnectInfo &info, WifiDirectForceDisconnectInfo &forceInfo, WifiDirectDisconnectCallback &callback)
{
    info.requestId = context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0));
    info.pid = 222;
    info.linkId = 1;
    info.negoChannel.type = NEGO_CHANNEL_COC;
    info.negoChannel.handle.channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));

    forceInfo.requestId = info.requestId;
    forceInfo.pid = info.pid;
    auto uuid = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    (void)strcpy_s(forceInfo.remoteUuid, sizeof(forceInfo.remoteUuid), uuid.c_str());
    forceInfo.linkType = WifiDirectLinkType::WIFI_DIRECT_LINK_TYPE_P2P;
    forceInfo.negoChannel.type = info.negoChannel.type;
    forceInfo.negoChannel.handle.channelId = info.negoChannel.handle.channelId;

    WifiDirectInterfaceMock::InjectWifiDirectDisconnectCallbackMock(callback);
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
 * @tc.name: ErrorCodeConverter
 * @tc.desc: static method test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ErrorCodeConverter, TestSize.Level1)
{
    struct {
        int32_t softbusErrorCode;
        int32_t protocolErrorCode;
    } caseTable[] = {
        {SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE,                     V1_ERROR_IF_NOT_AVAILABLE - V1_ERROR_START    },
        { SOFTBUS_CONN_PV1_BOTH_GO_ERR,                         V1_ERROR_BOTH_GO - V1_ERROR_START             },
        { SOFTBUS_CONN_PV1_REUSE_FAIL,                          V1_ERROR_REUSE_FAILED - V1_ERROR_START        },
        { SOFTBUS_CONN_PV1_CONNECT_GROUP_FAIL,                  V1_ERROR_CONNECT_GROUP_FAILED - V1_ERROR_START},
        { SOFTBUS_CONN_PV1_BUSY_ERR,                            V1_ERROR_BUSY - V1_ERROR_START                },
        { SOFTBUS_CONN_PV1_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE,
         V1_ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE - V1_ERROR_START                                        },
    };

    for (const auto &ct : caseTable) {
        auto code = P2pV1Processor::ErrorCodeToV1ProtocolCode(ct.softbusErrorCode);
        ASSERT_EQ(code, ct.protocolErrorCode);

        code = P2pV1Processor::ErrorCodeFromV1ProtocolCode(ct.protocolErrorCode);
        ASSERT_EQ(code, ct.softbusErrorCode);
    }

    // match but not p2pv1 error case
    auto code = P2pV1Processor::ErrorCodeToV1ProtocolCode(SOFTBUS_CONN_PV1_APPLY_GC_IP_FAIL);
    ASSERT_EQ(code, ERROR_P2P_APPLY_GC_IP_FAIL);

    // not match case
    code = P2pV1Processor::ErrorCodeToV1ProtocolCode(SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(code, SOFTBUS_INVALID_PARAM);

    // p2pv1 error but not match case
    code = P2pV1Processor::ErrorCodeFromV1ProtocolCode(V1_ERROR_UNKNOWN - V1_ERROR_START);
    ASSERT_EQ(code, V1_ERROR_UNKNOWN);

    // not match case
    code = P2pV1Processor::ErrorCodeFromV1ProtocolCode(SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(code, SOFTBUS_INVALID_PARAM);
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
    auto doMock = [&mock](int32_t stationFreq, int32_t recommendFreq, std::vector<int> channels) {
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
        EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([channels](int32_t *chanList, int32_t len) {
            for (int32_t i = 0; i < channels.size() && i < len; ++i) {
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
    EXPECT_CALL(mock, Hid2dGetChannelListFor5G(_, _)).WillRepeatedly([](int32_t *chanList, int32_t len) {
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
 * @tc.name: CreateWhenGoTimeout
 * @tc.desc: create link when go,
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, CreateWhenGoTimeout, TestSize.Level1)
{
    context_.Set(TestContextKey::CONNECT_REQUEST_ID, uint32_t(1));
    context_.Set(TestContextKey::INTERFACE_ROLE, LinkInfo::LinkMode::GO);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    EXPECT_CALL(entityMock, NotifyNewClientJoining(_)).WillRepeatedly([this](const std::string &remoteMac) {
        auto remoteDeviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
        ClientJoinEvent event { SOFTBUS_CONN_PV1_CONNECT_GROUP_TIMEOUT, remoteDeviceId, remoteMac };
        WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
    });

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<int32_t> result;
    EXPECT_CALL(mock, OnConnectFailure(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, int32_t reason) {
            result.set_value(reason);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_EQ(value, SOFTBUS_CONN_PV1_CONNECT_GROUP_TIMEOUT);

    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: CreateWhenGc
 * @tc.desc: create link when gc,
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, CreateWhenGc, TestSize.Level1)
{
    context_.Set(TestContextKey::CONNECT_REQUEST_ID, uint32_t(2));
    context_.Set(TestContextKey::INTERFACE_ROLE, LinkInfo::LinkMode::GC);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    WifiDirectConnectInfo info = { 0 };
    WifiDirectConnectCallback callback { 0 };
    PrepareConnectParameter(info, callback);
    std::promise<int32_t> result;
    EXPECT_CALL(mock, OnConnectFailure(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0)), _))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId, int32_t reason) {
            result.set_value(reason);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ConnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_EQ(value, SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE);

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

static bool InspectProcessorState(const std::string &remoteDeviceId, uint32_t timeoutMs, uint32_t deltaMs)
{
    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    // expect executor run and terminate
    bool expected[] = { true, false };
    int32_t index = 0;
    auto times = timeoutMs / deltaMs;
    for (auto i = 0; i < times && index < ARRAY_SIZE(expected); i++) {
        auto status = scheduler.CheckExecutorRunning(remoteDeviceId);
        if (status == expected[index]) {
            index += 1;
            continue;
        }
        SoftBusSleepMs(deltaMs);
    }
    return index == ARRAY_SIZE(expected);
}

/*
 * @tc.name: PassiveConnectTimeoutWhenNone
 * @tc.desc: passive connect timeout when none
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, PassiveConnectTimeoutWhenNone, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
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
    std::string message =
        R"({"KEY_BRIDGE_SUPPORTED":false,"KEY_COMMAND_TYPE":8,"KEY_CONTENT_TYPE":2,"KEY_EXPECTED_ROLE":1,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"42:dc:a5:f3:4c:14","KEY_GO_MAC":"","KEY_MAC":"42:dc:a5:f3:4c:14","KEY_ROLE":5,"KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})";
    CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    ASSERT_TRUE(InspectProcessorState(deviceId, P2pV1Processor::P2P_V1_WAITING_REQUEST_TIME_MS + 1000, 200));
}

/*
 * @tc.name: PassiveConnectTimeoutWhenGo
 * @tc.desc: passive connect timeout when go
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, PassiveConnectTimeoutWhenGo, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
    context_.Set(TestContextKey::INTERFACE_ROLE, LinkInfo::LinkMode::GO);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    EXPECT_CALL(entityMock, NotifyNewClientJoining(_)).WillRepeatedly([this](const std::string &remoteMac) {
        // sleep 100ms to make sure processor state can be inspected by InspectProcessorState
        SoftBusSleepMs(100);
        auto remoteDeviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
        ClientJoinEvent event { SOFTBUS_CONN_PV1_CONNECT_GROUP_TIMEOUT, remoteDeviceId, remoteMac };
        WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
    });

    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    std::string message =
        R"({"KEY_BRIDGE_SUPPORTED":false,"KEY_COMMAND_TYPE":8,"KEY_CONTENT_TYPE":2,"KEY_EXPECTED_ROLE":1,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"42:dc:a5:f3:4c:14","KEY_GO_MAC":"","KEY_MAC":"42:dc:a5:f3:4c:14","KEY_ROLE":5,"KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})";
    CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    ASSERT_TRUE(InspectProcessorState(deviceId, 2000, 10));
}

/*
 * @tc.name: PassiveConnectSuccessWhenNone
 * @tc.desc: passive connect success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, PassiveConnectSuccessWhenNone, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
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
                R"({"KEY_BRIDGE_SUPPORTED":false,"KEY_COMMAND_TYPE":8,"KEY_CONTENT_TYPE":1,"KEY_EXPECTED_ROLE":2,"KEY_GC_IP":"192.168.49.3","KEY_GC_MAC":"a6:3b:0e:78:29:dd","KEY_GO_IP":"192.168.49.1","KEY_GO_MAC":"42:dc:a5:f3:4c:14","KEY_GO_PORT":43267,"KEY_GROUP_CONFIG":"DIRECT-ja-OHOS_0u31\n4e:e8:d0:45:8f:10\nulKjGU9T\n5180","KEY_MAC":"42:dc:a5:f3:4c:14","KEY_ROLE":2,"KEY_SELF_WIFI_CONFIG":"","KEY_VERSION":2})";
            CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);
            return SOFTBUS_OK;
        })
        .WillRepeatedly(Return(context_.Get(TestContextKey::CHANNEL_SEND_MESSAGE, int(0))));
    EXPECT_CALL(mock, AuthOpenConn(_, _, _, _))
        .WillOnce([](const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta) {
            // sleep 100ms to make sure processor state can be inspected by InspectProcessorState
            SoftBusSleepMs(100);
            AuthHandle handle = { 0 };
            callback->onConnOpened(requestId, handle);
            return SOFTBUS_OK;
        });

    std::string message =
        R"({"KEY_BRIDGE_SUPPORTED":false,"KEY_COMMAND_TYPE":8,"KEY_CONTENT_TYPE":2,"KEY_EXPECTED_ROLE":1,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"42:dc:a5:f3:4c:14","KEY_GO_MAC":"","KEY_MAC":"42:dc:a5:f3:4c:14","KEY_ROLE":5,"KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})";
    CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    ASSERT_TRUE(InspectProcessorState(deviceId, 2000, 10));

    auto remoteMac = context_.Get(TestContextKey::REMOTE_MAC, std::string(""));
    InnerLink::LinkState state = InnerLink::LinkState::INVALID_STATE;
    LinkManager::GetInstance().ProcessIfPresent(remoteMac, [&state](InnerLink &link) {
        state = link.GetState();
    });
    ASSERT_EQ(state, InnerLink::LinkState::CONNECTED);
}

/*
 * @tc.name: DisconnectWhenLocalUsing
 * @tc.desc: disconnect link when local using
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, DisconnectWhenLocalUsing, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    WifiDirectDisconnectInfo info = { 0 };
    WifiDirectDisconnectCallback callback { 0 };
    WifiDirectForceDisconnectInfo ignore { 0 };
    PrepareDisconnectParameter(info, ignore, callback);
    std::promise<bool> result;
    EXPECT_CALL(mock, OnDisconnectSuccess(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0))))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId) {
            result.set_value(true);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.DisconnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(P2pV1Processor::DISCONNECT_WAIT_POST_REQUEST_MS + 1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_EQ(value, true);
    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: PassiveDisconnectWhenLocalUsing
 * @tc.desc: passive disconnect link when local using
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, PassiveDisconnectWhenLocalUsing, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, true);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    EXPECT_CALL(entityMock, Disconnect(_))
        .WillOnce([](const P2pDestroyGroupParam &param) {
            // sleep 100ms to make sure processor state can be inspected by InspectProcessorState
            SoftBusSleepMs(100);
            P2pOperationResult result {};
            result.errorCode_ = SOFTBUS_OK;
            return result;
        })
        .WillRepeatedly([](const P2pDestroyGroupParam &param) {
            P2pOperationResult result {};
            result.errorCode_ = SOFTBUS_OK;
            return result;
        });

    std::string raw = R"({"KEY_COMMAND_TYPE":5,"KEY_MAC":"42:dc:a5:f3:4c:14"})";
    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    CoCProxyNegotiateChannel::InjectReceiveData(channelId, raw);

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    ASSERT_TRUE(InspectProcessorState(deviceId, 2000, 10));
    auto value = InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [](const InterfaceInfo &interface) {
        return interface.GetReuseCount();
    });
    ASSERT_EQ(value, 1);
    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: ForceDisconnectWhenLocalUsing
 * @tc.desc: force disconnect link when local using
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, ForceDisconnectWhenLocalUsing, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    WifiDirectDisconnectInfo ignore = { 0 };
    WifiDirectForceDisconnectInfo info = { 0 };
    WifiDirectDisconnectCallback callback { 0 };
    PrepareDisconnectParameter(ignore, info, callback);
    std::promise<bool> result;
    EXPECT_CALL(mock, OnDisconnectSuccess(context_.Get(TestContextKey::CONNECT_REQUEST_ID, uint32_t(0))))
        .Times(1)
        .WillOnce<>([&result](uint32_t requestId) {
            result.set_value(true);
        });

    WifiDirectScheduler &scheduler = WifiDirectSchedulerFactory::GetInstance().GetScheduler();
    auto ret = scheduler.ForceDisconnectDevice(info, callback);
    ASSERT_EQ(ret, SOFTBUS_OK);

    auto future = result.get_future();
    auto status = future.wait_for(std::chrono::milliseconds(P2pV1Processor::DISCONNECT_WAIT_POST_REQUEST_MS + 1000));
    ASSERT_EQ(status, std::future_status::ready);
    auto value = future.get();
    ASSERT_EQ(value, true);
    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: PassiveForceDisconnectWhenLocalUsing
 * @tc.desc: passive force disconnect link when local using
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, PassiveForceDisconnectWhenLocalUsing, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    EXPECT_CALL(entityMock, DestroyGroup(_)).WillRepeatedly([](const P2pDestroyGroupParam &param) {
        // sleep 100ms to make sure processor state can be inspected by InspectProcessorState
        SoftBusSleepMs(100);
        P2pOperationResult result {};
        result.errorCode_ = SOFTBUS_OK;
        return result;
    });

    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    std::string message = R"({"KEY_COMMAND_TYPE":32,"KEY_MAC":"42:dc:a5:f3:4c:14"})";
    CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    ASSERT_TRUE(InspectProcessorState(deviceId, 2000, 10));

    LinkManager::GetInstance().ForEach([&deviceId](InnerLink &link) {
        if (link.GetLinkType() == InnerLink::LinkType::P2P && link.GetRemoteDeviceId() == deviceId) {
            ADD_FAILURE() << "p2p link is not empty after force disconnect";
        }
        return false;
    });
    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: PassiveReuse
 * @tc.desc: passive reuse link
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, PassiveReuse, TestSize.Level1)
{
    context_.Set(TestContextKey::REMOTE_MAC, std::string("42:dc:a5:f3:4c:14"));
    context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
    context_.Set(TestContextKey::SWITCH_INJECT_REMOTE_INNER_LINK, false);

    WifiDirectInterfaceMock mock;
    InjectCommonMock(mock);
    InjectData(mock);
    P2pEntity entityMock;
    InjectEntityMock(entityMock);
    InjectChannel(mock);

    EXPECT_CALL(entityMock, ReuseLink())
        .WillOnce([]() {
            // sleep 100ms to make sure processor state can be inspected by InspectProcessorState
            SoftBusSleepMs(100);
            return SOFTBUS_OK;
        })
        .WillRepeatedly(Return(SOFTBUS_OK));

    std::string raw = R"({"KEY_COMMAND_TYPE":12,"KEY_MAC":"42:dc:a5:f3:4c:14"})";
    auto channelId = context_.Get(TestContextKey::CONNECT_NEGO_CHANNEL_ID, int32_t(0));
    CoCProxyNegotiateChannel::InjectReceiveData(channelId, raw);

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    ASSERT_TRUE(InspectProcessorState(deviceId, 2000, 10));

    bool beingUsedByRemote = false;
    LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::P2P, deviceId, [&beingUsedByRemote](InnerLink &link) {
            beingUsedByRemote = link.IsBeingUsedByRemote();
        });
    ASSERT_TRUE(beingUsedByRemote);
    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}

/*
 * @tc.name: GetGoMac
 * @tc.desc: test role decision
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, GetGoMac, TestSize.Level1)
{
    struct {
        // parameter
        LinkInfo::LinkMode myRole;
        // context
        string interfaceBaseMac;
        string linkRemoteBaseMac;

        string result;
    } caseTable[] = {
        {LinkInfo::LinkMode::NONE, "",                  "",                  ""                 },
        { LinkInfo::LinkMode::GO,  "11:22:33:44:55:66", "",                  "11:22:33:44:55:66"},
        { LinkInfo::LinkMode::GC,  "11:22:33:44:55:66", "22:33:44:55:66:77", "22:33:44:55:66:77"},
        { LinkInfo::LinkMode::GC,  "11:22:33:44:55:66", "",                  ""                 },
    };

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    P2pV1Processor processor(deviceId);
    for (const auto &ct : caseTable) {
        PrepareContext();
        WifiDirectInterfaceMock mock;
        if (ct.linkRemoteBaseMac.empty()) {
            context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, false);
            InjectData(mock);
        } else {
            context_.Set(TestContextKey::SWITCH_INJECT_LOCAL_INNER_LINK, true);
            InjectData(mock);
            LinkManager::GetInstance().ProcessIfPresent(InnerLink::LinkType::P2P, deviceId, [ct](InnerLink &link) {
                link.SetRemoteBaseMac(ct.linkRemoteBaseMac);
            });
        }
        InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [ct](InterfaceInfo &interface) {
            interface.SetBaseMac(ct.interfaceBaseMac);
            return SOFTBUS_OK;
        });

        auto goMac = processor.GetGoMac(ct.myRole);
        ASSERT_EQ(goMac, ct.result) << "my role: " << static_cast<int>(ct.myRole)
                                    << ", interface base mac: " << ct.interfaceBaseMac
                                    << ",  link remote base mac: " << ct.linkRemoteBaseMac << ", result: " << ct.result;
        testing::Mock::VerifyAndClearExpectations(&mock);
    }
}

/*
 * @tc.name: RoleDecision
 * @tc.desc: test role decision
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, RoleDecision, TestSize.Level1)
{
    struct {
        WifiDirectRole myRole;
        WifiDirectRole peerRole;
        WifiDirectRole expectRole;
        std::string localGoMac;
        std::string remoteGoMac;

        int32_t result;
    } caseTable[] = {
        {WIFI_DIRECT_ROLE_GO,       WIFI_DIRECT_ROLE_GC, WIFI_DIRECT_ROLE_GC, "11:22:33:44:55:66", "11:22:33:44:55:66",
         WIFI_DIRECT_ROLE_GO  },
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GO, WIFI_DIRECT_ROLE_GO, "11:22:33:44:55:66", "11:22:33:44:55:66",
         WIFI_DIRECT_ROLE_GC  },
        { WIFI_DIRECT_ROLE_NONE,    WIFI_DIRECT_ROLE_GO, WIFI_DIRECT_ROLE_GO, "",                  "11:22:33:44:55:66",
         WIFI_DIRECT_ROLE_GC  },
        { WIFI_DIRECT_ROLE_INVALID, WIFI_DIRECT_ROLE_GO, WIFI_DIRECT_ROLE_GO, "",                  "11:22:33:44:55:66",
         SOFTBUS_INVALID_PARAM},
    };

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    P2pV1Processor processor(deviceId);
    for (const auto &ct : caseTable) {
        auto role = processor.GetFinalRoleWithPeerExpectedRole(
            ct.myRole, ct.peerRole, ct.expectRole, ct.localGoMac, ct.remoteGoMac);
        ASSERT_EQ(role, ct.result) << "my role: " << ct.myRole << ", peer role: " << ct.peerRole
                                   << ", expect role: " << ct.expectRole << "local go mac: " << ct.localGoMac
                                   << ", remote go mac: " << ct.remoteGoMac;
    }
}

/*
 * @tc.name: RoleDecisionAsGo
 * @tc.desc: test role decision as Go
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, RoleDecisionAsGo, TestSize.Level1)
{
    struct {
        WifiDirectRole peerRole;
        WifiDirectRole expectRole;
        std::string localGoMac;
        std::string remoteGoMac;

        int32_t result;
    } caseTable[] = {
        {WIFI_DIRECT_ROLE_GO,       WIFI_DIRECT_ROLE_GO,      "11:22:33:44:55:66", "22:33:44:55::66:77",
         SOFTBUS_CONN_PV1_BOTH_GO_ERR                                                                                       },
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GC,      "11:22:33:44:55:66", "",
         SOFTBUS_CONN_PV1_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE                                                               },
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GC,      "11:22:33:44:55:66", "22:33:44:55::66:77",
         SOFTBUS_CONN_PV1_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE                                                               },
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GO,      "11:22:33:44:55:66", "11:22:33:44:55:66",
         SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR                                                             },
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GC,      "11:22:33:44:55:66", "11:22:33:44:55:66",  WIFI_DIRECT_ROLE_GO},
        { WIFI_DIRECT_ROLE_NONE,    WIFI_DIRECT_ROLE_GO,      "11:22:33:44:55:66", "",
         SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR                                                             },
        { WIFI_DIRECT_ROLE_NONE,    WIFI_DIRECT_ROLE_NONE,    "11:22:33:44:55:66", "",                   WIFI_DIRECT_ROLE_GO},
        { WIFI_DIRECT_ROLE_INVALID, WIFI_DIRECT_ROLE_INVALID, "11:22:33:44:55:66", "",
         SOFTBUS_CONN_PV1_PEER_ROLE_INVALID                                                                                 },
    };

    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    P2pV1Processor processor(deviceId);
    for (const auto &ct : caseTable) {
        auto role = processor.GetFinalRoleAsGo(ct.peerRole, ct.expectRole, ct.localGoMac, ct.remoteGoMac);
        ASSERT_EQ(role, ct.result) << "peer role: " << ct.peerRole << ", expect role: " << ct.expectRole
                                   << "local go mac: " << ct.localGoMac << ", remote go mac: " << ct.remoteGoMac;
    }
}

/*
 * @tc.name: RoleDecisionAsGc
 * @tc.desc: test role decision as Gc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, RoleDecisionAsGc, TestSize.Level1)
{
    struct {
        WifiDirectRole peerRole;
        WifiDirectRole expectRole;
        std::string localGoMac;
        std::string remoteGoMac;

        int32_t result;
    } caseTable[] = {
        {WIFI_DIRECT_ROLE_GO,    WIFI_DIRECT_ROLE_GO,   "11:22:33:44:55:66", "11:22:33:44:55:66", WIFI_DIRECT_ROLE_GC              },
        { WIFI_DIRECT_ROLE_GO,   WIFI_DIRECT_ROLE_GO,   "",                  "11:22:33:44:55:66",
         SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE                                                                           },
        { WIFI_DIRECT_ROLE_GO,   WIFI_DIRECT_ROLE_GO,   "11:22:33:44:55:66", "22:33:44:55:66:77",
         SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE                                                                           },
        { WIFI_DIRECT_ROLE_NONE, WIFI_DIRECT_ROLE_NONE, "11:22:33:44:55:66", "",                  SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE},
        { WIFI_DIRECT_ROLE_GC,   WIFI_DIRECT_ROLE_GC,   "11:22:33:44:55:66", "22:33:44:55:66:77",
         SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE                                                                           },
    };
    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    P2pV1Processor processor(deviceId);
    for (const auto &ct : caseTable) {
        auto role = processor.GetFinalRoleAsGc(ct.peerRole, ct.expectRole, ct.localGoMac, ct.remoteGoMac);
        ASSERT_EQ(role, ct.result) << "peer role: " << ct.peerRole << ", expect role: " << ct.expectRole
                                   << "local go mac: " << ct.localGoMac << ", remote go mac: " << ct.remoteGoMac;
    }
}

/*
 * @tc.name: RoleDecisionAsNone
 * @tc.desc: test role decision as none
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, RoleDecisionAsNone, TestSize.Level1)
{
    struct {
        WifiDirectRole peerRole;
        WifiDirectRole expectRole;

        int32_t result;
    } caseTable[] = {
        {WIFI_DIRECT_ROLE_GO,       WIFI_DIRECT_ROLE_GC,      SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR},
        { WIFI_DIRECT_ROLE_GO,      WIFI_DIRECT_ROLE_GO,      WIFI_DIRECT_ROLE_GC                                   },
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GO,      SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR},
        { WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GC,      SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE       },
        { WIFI_DIRECT_ROLE_NONE,    WIFI_DIRECT_ROLE_GC,      WIFI_DIRECT_ROLE_GO                                   },
        { WIFI_DIRECT_ROLE_NONE,    WIFI_DIRECT_ROLE_GO,      WIFI_DIRECT_ROLE_GC                                   },
        { WIFI_DIRECT_ROLE_INVALID, WIFI_DIRECT_ROLE_INVALID, SOFTBUS_INVALID_PARAM                                 },
    };
    auto deviceId = context_.Get(TestContextKey::REMOTE_UUID, std::string(""));
    P2pV1Processor processor(deviceId);
    for (const auto &ct : caseTable) {
        auto role = processor.GetFinalRoleAsNone(ct.peerRole, ct.expectRole);
        ASSERT_EQ(role, ct.result) << "peer role: " << ct.peerRole << ", expect role: " << ct.expectRole;
    }
}

static P2pV1FuzzHelper::FuzzInjector g_fuzzInjectorTable[] = {
    P2pV1FuzzHelper::FuzzContentType,
    P2pV1FuzzHelper::FuzzGcChannelList,
    P2pV1FuzzHelper::FuzzGcMac,
    P2pV1FuzzHelper::FuzzGoMac,
    P2pV1FuzzHelper::FuzzIP,
    P2pV1FuzzHelper::FuzzMac,
    P2pV1FuzzHelper::FuzzSelfWifiCfg,
    P2pV1FuzzHelper::FuzzStationFrequency,
    P2pV1FuzzHelper::FuzzVersion,
    P2pV1FuzzHelper::FuzzWideBandSupport,
};
static std::string GenerateCmdConnV1Req()
{
    static uint32_t counter = 0;
    counter += 1;

    std::string raw =
        R"({"KEY_COMMAND_TYPE":9,"KEY_CONTENT_TYPE":2,"KEY_GC_CHANNEL_LIST":"36##40##44##48##149##153##157##161##165","KEY_GC_MAC":"a6:3b:0e:78:29:dd","KEY_GO_MAC":"42:dc:a5:f3:4c:14","KEY_IP":"","KEY_MAC":"a6:3b:0e:78:29:dd","KEY_SELF_WIFI_CONFIG":"","KEY_STATION_FREQUENCY":5180,"KEY_VERSION":2,"KEY_WIDE_BAND_SUPPORTED":false})";
    std::vector<uint8_t> input;
    input.insert(input.end(), raw.c_str(), raw.c_str() + raw.size());
    auto unmarshalProtocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    NegotiateMessage message;
    message.Unmarshalling(*unmarshalProtocol, input);

    auto index = counter % ARRAY_SIZE(g_fuzzInjectorTable);
    g_fuzzInjectorTable[index](message);

    std::vector<uint8_t> output;
    auto marshalProtocol = WifiDirectProtocolFactory::CreateProtocol(ProtocolType::JSON);
    message.Marshalling(*marshalProtocol, output);
    return std::string((char *)output.data(), output.size());
}

/*
 * @tc.name: ReuseRemoteLinkTimeout
 * @tc.desc: reuse remote link timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(P2pV1ProcessorTest, FuzzTestChannelData, TestSize.Level1)
{
    if (!FuzzEnvironment::IsFuzzEnable()) {
        GTEST_SKIP() << "only support in fuzz test";
    }

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
            auto message = GenerateCmdConnV1Req();
            CoCProxyNegotiateChannel::InjectReceiveData(channelId, message);
            return SOFTBUS_OK;
        })
        .WillRepeatedly([](int32_t channelId, const NegotiateMessage &msg) {
            return SOFTBUS_NOT_IMPLEMENT;
        });

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
    ASSERT_NE(value, SOFTBUS_OK);

    // ugly way (sleep 1s) to wait processor terminate, as mock environment will be cleanup before processor terminate.
    sleep(1);
}
} // namespace OHOS::SoftBus

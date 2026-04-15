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

#include <functional>
#include <gtest/gtest.h>
#include <string>

#include "dummy_negotiate_channel.h"
#include "net_conn_client.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "wifi_direct_manager.cpp"
#include "wifi_direct_manager.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using testing::_;
using ::testing::Return;

namespace OHOS::SoftBus {

// RAII guard to restore global listener state automatically
template <typename ListenerType, ListenerType* GlobalListener>
class ListenerGuard {
public:
    explicit ListenerGuard(const ListenerType& original) : original_(original) {}
    ~ListenerGuard() { *GlobalListener = original_; }
    ListenerGuard(const ListenerGuard&) = delete;
    ListenerGuard& operator=(const ListenerGuard&) = delete;
private:
    ListenerType original_;
};

// Type aliases for specific guards
using PtkMismatchListenerGuard = ListenerGuard<PtkMismatchListener, &g_ptkMismatchListener>;
using HmlStateListenerGuard = ListenerGuard<HmlStateListener, &g_hmlStateListener>;
using SyncPtkListenerGuard = ListenerGuard<SyncPtkListener, &g_syncPtkListener>;

class WifiDirectManagerCppTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: AllocateListenerModuleIdTest
 * @tc.desc: check AllocateListenerModuleId method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, AllocateListenerModuleIdTest, TestSize.Level1)
{
    auto moduleId1 = GetWifiDirectManager()->allocateListenerModuleId();
    EXPECT_EQ(moduleId1, AUTH_ENHANCED_P2P_START);

    auto moduleId2 = GetWifiDirectManager()->allocateListenerModuleId();
    EXPECT_EQ(moduleId2, AUTH_ENHANCED_P2P_START + 1);
    GetWifiDirectManager()->freeListenerModuleId(moduleId1);
    GetWifiDirectManager()->freeListenerModuleId(moduleId2);
}

/*
 * @tc.name: SavePtkTest
 * @tc.desc: check SavePtk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, SavePtkTest, TestSize.Level1)
{
    std::string remoteDeviceId("123");
    std::string ptk("ptk");
    auto ret = SavePtk(remoteDeviceId.c_str(), ptk.c_str());
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    g_enhanceManager.savePTK = [](const char *remoteDeviceId, const char *ptk) -> int32_t {
        return SOFTBUS_OK;
    };
    ret = SavePtk(remoteDeviceId.c_str(), ptk.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SyncPtkTest
 * @tc.desc: check SyncPtk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, SyncPtkTest, TestSize.Level1)
{
    std::string remoteDeviceId("123");
    auto ret = SyncPtk(remoteDeviceId.c_str());
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    g_enhanceManager.syncPTK = [](const char *remoteDeviceId) -> int32_t {
        return SOFTBUS_OK;
    };
    ret = SyncPtk(remoteDeviceId.c_str());
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IsDeviceOnlineTest
 * @tc.desc: check IsDeviceOnline method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsDeviceOnlineTest, TestSize.Level1)
{
    std::string remoteMac("28:11:05:5e:ee:d3");
    auto ret = IsDeviceOnline(remoteMac.c_str());
    EXPECT_EQ(ret, false);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, "0123456789ABCDEF", [](InnerLink &link) {
        link.SetRemoteBaseMac("28:11:05:5e:ee:d3");
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    ret = IsDeviceOnline(remoteMac.c_str());
    EXPECT_EQ(ret, true);
    LinkManager::GetInstance().RemoveLink(remoteMac);
}

/*
 * @tc.name: GetLocalIpByUuidTest
 * @tc.desc: check GetLocalIpByUuid method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetLocalIpByUuidTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string uuid2("11111111111");
    char myIp[IP_LEN] = { 0 };
    auto ret = GetLocalIpByUuid(uuid.c_str(), myIp, sizeof(myIp));
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv4("192.168.1.100");
    });

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid2, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv4("192.168.1.100");
    });

    ret = GetLocalIpByUuid(uuid.c_str(), myIp, sizeof(myIp));
    EXPECT_EQ(ret, SOFTBUS_OK);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: GetLocalIpByRemoteIpOnceTest
 * @tc.desc: check GetLocalIpByRemoteIpOnce method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetLocalIpByRemoteIpOnceTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string uuid2("0123456789ABCDE8");
    std::string uuid3("0123456789ABCDE7");
    std::string remoteIp("172.30.1.2");
    std::string remoteIpv6("fe80::a446:b4ff:fec1:7323");
    char localIp[IP_LEN] = { 0 };
    auto ret = GetLocalIpByRemoteIpOnce(remoteIp.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid3, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    ret = GetLocalIpByRemoteIpOnce(remoteIp.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteIp](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv4("170.30.1.1");
        link.SetRemoteIpv4(remoteIp);
    });
    ret = GetLocalIpByRemoteIpOnce(remoteIp.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_OK);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid2, [&remoteIpv6](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv6("fe80::200:22ff:fe6b:262d");
        link.SetRemoteIpv6(remoteIpv6);
    });
    ret = GetLocalIpByRemoteIpOnce(remoteIpv6.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_OK);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: GetLocalIpByRemoteIpTest
 * @tc.desc: check GetLocalIpByRemoteIp method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetLocalIpByRemoteIpTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string remoteIp("172.30.1.2");
    char localIp[IP_LEN] = { 0 };
    auto ret = GetLocalIpByRemoteIp(remoteIp.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_CONN_GET_LOCAL_IP_BY_REMOTE_IP_FAILED);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteIp](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv4("170.30.1.1");
        link.SetRemoteIpv4(remoteIp);
    });
    ret = GetLocalIpByRemoteIp(remoteIp.c_str(), localIp, sizeof(localIp));
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: GetRemoteUuidByIpTest
 * @tc.desc: check GetRemoteUuidByIp method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetRemoteUuidByIpTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string uuid2("0123456789ABCDE8");
    std::string remoteIp("172.30.1.2");
    char localIp[IP_LEN] = { 0 };

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid2, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });

    auto ret = GetRemoteUuidByIp(remoteIp.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteIp](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv4("170.30.1.1");
        link.SetRemoteIpv4(remoteIp);
    });
    ret = GetRemoteUuidByIp(remoteIp.c_str(), localIp, sizeof(localIp));
    EXPECT_EQ(ret, SOFTBUS_OK);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: GetLocalAndRemoteMacByLocalIpTest
 * @tc.desc: check GetLocalAndRemoteMacByLocalIp method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetLocalAndRemoteMacByLocalIpTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string uuid2("0123456789ABCDE8");
    std::string localIp("172.30.1.2");
    int32_t macLen = 18;
    char localMac[macLen];
    char remoteMac[macLen];

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });

    auto ret = GetLocalAndRemoteMacByLocalIp(localIp.c_str(), localMac, macLen, remoteMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid2, [&localIp](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv4(localIp);
    });
    ret = GetLocalAndRemoteMacByLocalIp(localIp.c_str(), localMac, macLen, remoteMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: WifiDirectStatusListenerTest
 * @tc.desc: check NotifyOnline,NotifyOffline,NotifyRoleChange,NotifyConnectedForSink, NotifyDisconnectedForSink, method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, WifiDirectStatusListenerTest, TestSize.Level1)
{
    std::string remoteMac("10:dc:b6:90:84:82");
    std::string remoteIp("170.30.1.2");
    std::string remoteUuid("0123456789ABCDEF");
    bool isSource = true;
    std::string localIp("170.30.1.1");
    struct WifiDirectSinkLink sinkLink { };
    struct WifiDirectStatusListener listener1 = { 0 };
    g_listeners.push_back(listener1);
    EXPECT_NO_FATAL_FAILURE(NotifyOnline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), isSource));
    EXPECT_NO_FATAL_FAILURE(NotifyOffline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), localIp.c_str()));
    EXPECT_NO_FATAL_FAILURE(NotifyRoleChange(WIFI_DIRECT_ROLE_GO, WIFI_DIRECT_ROLE_GC));
    EXPECT_NO_FATAL_FAILURE(NotifyConnectedForSink(&sinkLink));
    EXPECT_NO_FATAL_FAILURE(NotifyDisconnectedForSink(&sinkLink));
    EXPECT_NO_FATAL_FAILURE(NotifyVirtualLinkStateChange(CONN_VIRTUAL_LINK_STATE_ENTER_VIRTUAL, remoteUuid.c_str()));

    struct WifiDirectStatusListener listener2 = {
        .onDeviceOnLine = [](const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource) {},
        .onDeviceOffLine = [](const char *remoteMac, const char *remoteIp, const char *remoteUuid,
                               const char *localIp) {},
        .onLocalRoleChange = [](enum WifiDirectRole oldRole, enum WifiDirectRole newRole) {},
        .onConnectedForSink = [](const struct WifiDirectSinkLink *link) {},
        .onDisconnectedForSink = [](const struct WifiDirectSinkLink *link) {},
        .onVirtualLinkStateChange = [](VirtualLinkState virtualLinkState, const char *remoteUuid) {},
    };
    g_listeners.push_back(listener2);
    EXPECT_NO_FATAL_FAILURE(NotifyOnline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), isSource));
    EXPECT_NO_FATAL_FAILURE(NotifyOffline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), localIp.c_str()));
    EXPECT_NO_FATAL_FAILURE(NotifyRoleChange(WIFI_DIRECT_ROLE_GO, WIFI_DIRECT_ROLE_GC));
    EXPECT_NO_FATAL_FAILURE(NotifyConnectedForSink(&sinkLink));
    EXPECT_NO_FATAL_FAILURE(NotifyDisconnectedForSink(&sinkLink));
    EXPECT_NO_FATAL_FAILURE(NotifyVirtualLinkStateChange(CONN_VIRTUAL_LINK_STATE_ENTER_VIRTUAL, remoteUuid.c_str()));
}

/*
 * @tc.name: IsNegotiateChannelNeededTest
 * @tc.desc: check IsNegotiateChannelNeeded method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsNegotiateChannelNeededTest, TestSize.Level1)
{
    std::string remoteNetworkId("1234567890");
    std::string remoteMac("10:dc:b6:90:84:82");
    char uuid[UUID_BUF_LEN] = "0123456789ABCDEF";
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo(_, _, _, _))
        .WillRepeatedly([&uuid](const std::string &netWorkId, InfoKey key, char *info, uint32_t len) {
            if (strcpy_s(info, UUID_BUF_LEN, uuid) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        });
    auto ret = IsNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(ret, true);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteMac](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetRemoteBaseMac(remoteMac);
    });
    ret = IsNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(ret, true);

    LinkManager::GetInstance().ProcessIfPresent(remoteMac.c_str(), [&remoteMac](InnerLink &link) {
        link.SetNegotiateChannel(std::make_shared<DummyNegotiateChannel>());
    });
    ret = IsNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: NotifyPtkSyncResultTest
 * @tc.desc: check NotifyPtkSyncResult method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, NotifyPtkSyncResultTest, TestSize.Level1)
{
    std::string remoteUuid("0123456789ABCDEF");
    int32_t result = 0;
    EXPECT_NO_FATAL_FAILURE(NotifyPtkSyncResult(remoteUuid.c_str(), result));

    g_syncPtkListener = [](const char *remoteDeviceId, int32_t result) {};
    EXPECT_NO_FATAL_FAILURE(NotifyPtkSyncResult(remoteUuid.c_str(), result));
}

/*
 * @tc.name: RefreshRelationShipTest001
 * @tc.desc: check RefreshRelationShip method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, RefreshRelationShipTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 in");
    std::string remoteUuid("0123456789ABCDEF");
    std::string remoteMac("11:11:11:11:11:11");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteMac, [&remoteMac](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetRemoteBaseMac(remoteMac);
    });

    RefreshRelationShip(remoteUuid.c_str(), remoteMac.c_str());
    auto link = LinkManager::GetInstance().GetReuseLink(WIFI_DIRECT_LINK_TYPE_HML, remoteMac);

    EXPECT_EQ(link, nullptr);
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 out");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: RefreshRelationShipTest002
 * @tc.desc: check RefreshRelationShip method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, RefreshRelationShipTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest002 in");
    std::string remoteUuid("0123456789ABCDEF");
    std::string remoteMac("11:11:11:11:11:11");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);

    LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, remoteMac, [&remoteMac, &remoteUuid](InnerLink &link) {
            link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
            link.SetRemoteBaseMac(remoteMac);
            link.SetRemoteDeviceId(remoteUuid);
        });

    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteUuid, [&remoteMac](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTING);
        link.SetRemoteBaseMac(remoteMac);
    });

    RefreshRelationShip(remoteUuid.c_str(), remoteMac.c_str());
    auto link = LinkManager::GetInstance().GetReuseLink(WIFI_DIRECT_LINK_TYPE_HML, remoteMac);

    EXPECT_NE(link, nullptr);
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest002 out");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: ForceDisconnectDeviceSync001
 * @tc.desc: check ForceDisconnectDeviceSync001 method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, ForceDisconnectDeviceSync001, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 in");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    auto result = ForceDisconnectDeviceSync(WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(result, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 out");
}

static int g_frequency = -1;
static void FrequencyChangedListener(int32_t frequency)
{
    g_frequency = frequency;
}

/*
 * @tc.name: NotifyFrequencyChanged
 * @tc.desc: check NotifyFrequencyChanged method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, NotifyFrequencyChanged, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "NotifyFrequencyChanged in");
    NotifyFrequencyChanged(0);
    EXPECT_EQ(g_frequency, -1);

    AddFrequencyChangedListener(FrequencyChangedListener);
    NotifyFrequencyChanged(0);
    EXPECT_EQ(g_frequency, 0);
    CONN_LOGI(CONN_WIFI_DIRECT, "NotifyFrequencyChanged out");
}

/*
 * @tc.name: GetHmlLinkCount
 * @tc.desc: check GetHmlLinkCount method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetHmlLinkCount, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "GetHmlLinkCount in");
    std::string remoteDeviceIdConnected("0123456789ABCDEF");
    LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, remoteDeviceIdConnected, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    std::string remoteDeviceIdConnecting("012");
    LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, remoteDeviceIdConnecting, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTING);
    });
    std::string remoteUuid("123");
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::P2P, remoteUuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTING);
    });

    auto ret = GetHmlLinkCount();
    EXPECT_EQ(ret, 1);
    CONN_LOGI(CONN_WIFI_DIRECT, "GetHmlLinkCount out");
}

/*
 * @tc.name: PreferNegotiateChannelTest
 * @tc.desc: PreferNegotiateChannel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, PreferNegotiateChannelTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "PreferNegotiateChannelTest in");
    std::string remoteNetworkId("1234567890");
    char uuid[UUID_BUF_LEN] = "0123456789ABCDEF";
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo(_, _, _, _))
        .WillRepeatedly([&uuid](const std::string &netWorkId, InfoKey key, char *info, uint32_t len) {
            if (strcpy_s(info, UUID_BUF_LEN, uuid) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        });

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [](InnerLink &link) {
        link.SetNegotiateChannel(std::make_shared<AuthNegotiateChannel>(AuthHandle {0, 0}));
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    LinkManager::GetInstance().Dump();

    WifiDirectConnectInfo info;
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    info.negoChannel.handle.authHandle.type = AUTH_LINK_TYPE_BR;
    (void)strcpy_s(info.remoteNetworkId, sizeof(info.remoteNetworkId), remoteNetworkId.c_str());
    WifiDirectConnectCallback callback;
    callback.onConnectFailure = nullptr;
    callback.onConnectSuccess = nullptr;

    ConnectCommand connectCommand1(info, callback);
    EXPECT_NO_FATAL_FAILURE(connectCommand1.PreferNegotiateChannel());

    info.negoChannel.handle.authHandle.type = AUTH_LINK_TYPE_BLE;
    ConnectCommand connectCommand2(info, callback);
    EXPECT_NO_FATAL_FAILURE(connectCommand2.PreferNegotiateChannel());

    info.negoChannel.type = NEGO_CHANNEL_ACTION;
    info.negoChannel.handle.authHandle.type = AUTH_LINK_TYPE_BLE;
    ConnectCommand connectCommand3(info, callback);
    EXPECT_NO_FATAL_FAILURE(connectCommand3.PreferNegotiateChannel());

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    CONN_LOGI(CONN_WIFI_DIRECT, "PreferNegotiateChannelTest out");
}

/*
 * @tc.name: IsNegotiateChannelNeedTest
 * @tc.desc: IsNegotiateChannelNeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsNegotiateChannelNeedTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "IsNegotiateChannelNeedTest in");
    std::string remoteNetworkId("1234567890");
    char uuid[UUID_BUF_LEN] = "0123456789ABCDEF";
    std::string remoteMac("10:dc:b6:90:84:82");
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo(_, _, _, _))
        .WillRepeatedly([&uuid](const std::string &netWorkId, InfoKey key, char *info, uint32_t len) {
            if (strcpy_s(info, UUID_BUF_LEN, uuid) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        });
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteMac](InnerLink &link) {
        link.SetLinkPowerMode(DEFAULT_POWER);
        link.SetRemoteBaseMac(remoteMac);
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    auto ret = GetWifiDirectManager()->isNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_TRUE(ret);

    LinkManager::GetInstance().ProcessIfPresent(remoteMac.c_str(), [](InnerLink &link) {
        link.SetLinkPowerMode(LOW_POWER);
    });
    ret = GetWifiDirectManager()->isNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_TRUE(ret);

    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<1>(TYPE_GLASS_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<2>(TYPE_GLASS_ID), Return(SOFTBUS_INVALID_PARAM)));
    ret = GetWifiDirectManager()->isNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_TRUE(ret);

    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<1>(TYPE_GLASS_ID), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<2>(TYPE_GLASS_ID), Return(SOFTBUS_OK)));
    ret = GetWifiDirectManager()->isNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_TRUE(ret);

    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<1>(TYPE_GLASS_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<2>(TYPE_GLASS_ID), Return(SOFTBUS_OK)));
    ret = GetWifiDirectManager()->isNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_TRUE(ret);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    CONN_LOGI(CONN_WIFI_DIRECT, "IsNegotiateChannelNeedTest out");
}

/*
 * @tc.name: GetRequestIdTest
 * @tc.desc: check GetRequestId method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetRequestIdTest, TestSize.Level1)
{
    auto requestId1 = GetWifiDirectManager()->getRequestId();
    auto requestId2 = GetWifiDirectManager()->getRequestId();
    EXPECT_GT(requestId2, requestId1);
}

/*
 * @tc.name: FreeListenerModuleIdTest
 * @tc.desc: check FreeListenerModuleId method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, FreeListenerModuleIdTest, TestSize.Level1)
{
    auto moduleId1 = GetWifiDirectManager()->allocateListenerModuleId();
    auto moduleId2 = GetWifiDirectManager()->allocateListenerModuleId();
    EXPECT_EQ(moduleId1, AUTH_ENHANCED_P2P_START);
    EXPECT_EQ(moduleId2, AUTH_ENHANCED_P2P_START + 1);

    GetWifiDirectManager()->freeListenerModuleId(moduleId1);
    auto moduleId3 = GetWifiDirectManager()->allocateListenerModuleId();
    EXPECT_EQ(moduleId3, AUTH_ENHANCED_P2P_START);

    GetWifiDirectManager()->freeListenerModuleId(moduleId2);
    GetWifiDirectManager()->freeListenerModuleId(moduleId3);
}

/*
 * @tc.name: LinkHasPtkTest
 * @tc.desc: check LinkHasPtk method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, LinkHasPtkTest, TestSize.Level1)
{
    std::string remoteDeviceId("0123456789ABCDEF");

    // Test with no link - should return false
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    auto hasPtk = GetWifiDirectManager()->linkHasPtk(remoteDeviceId.c_str());
    EXPECT_EQ(hasPtk, false);

    // Test with link without PTK
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteDeviceId, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetPtk(false);
    });
    hasPtk = GetWifiDirectManager()->linkHasPtk(remoteDeviceId.c_str());
    EXPECT_EQ(hasPtk, false);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteDeviceId, [](InnerLink &link) {
        link.SetPtk(true);
    });
    hasPtk = GetWifiDirectManager()->linkHasPtk(remoteDeviceId.c_str());
    EXPECT_EQ(hasPtk, true);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: GetLocalAndRemoteMacByRemoteIpTest
 * @tc.desc: check GetLocalAndRemoteMacByRemoteIp method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetLocalAndRemoteMacByRemoteIpTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string remoteIp("172.30.1.2");
    std::string remoteIpv6("fe80::a446:b4ff:fec1:7323");
    constexpr int32_t macLen = 18;
    char localMac[macLen] = {0};
    char remoteMac[macLen] = {0};

    // Test with no links
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    auto ret =
        GetWifiDirectManager()->getLocalAndRemoteMacByRemoteIp(remoteIp.c_str(), localMac, macLen, remoteMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    // Test with IPv4 link
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteIp](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalDynamicMac("aa:bb:cc:dd:ee:ff");
        link.SetRemoteDynamicMac("11:22:33:44:55:66");
        link.SetRemoteIpv4(remoteIp);
    });
    ret = GetWifiDirectManager()->getLocalAndRemoteMacByRemoteIp(remoteIp.c_str(), localMac, macLen, remoteMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: GetRemoteIpByRemoteMacTest
 * @tc.desc: check GetRemoteIpByRemoteMac method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetRemoteIpByRemoteMacTest, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string remoteMac("11:22:33:44:55:66");
    std::string remoteIp("172.30.1.2");
    char ip[IP_LEN] = { 0 };

    // Test with no links
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    auto ret = GetWifiDirectManager()->getRemoteIpByRemoteMac(remoteMac.c_str(), ip, sizeof(ip));
    EXPECT_EQ(ret, SOFTBUS_CONN_NOT_FOUND_FAILED);

    // Test with remote dynamic mac
    LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, uuid, [&remoteMac, &remoteIp](InnerLink &link) {
            link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
            link.SetRemoteDynamicMac(remoteMac);
            link.SetRemoteIpv4(remoteIp);
        });
    ret = GetWifiDirectManager()->getRemoteIpByRemoteMac(remoteMac.c_str(), ip, sizeof(ip));
    EXPECT_EQ(ret, SOFTBUS_OK);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: NotifyPtkMismatchTest
 * @tc.desc: check NotifyPtkMismatch method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, NotifyPtkMismatchTest, TestSize.Level1)
{
    std::string remoteNetworkId("1234567890");
    uint32_t len = 32;
    int32_t reason = 0;
    // RAII guard ensures global listener is restored even if test fails
    PtkMismatchListenerGuard guard(g_ptkMismatchListener);

    // Test with no listener
    EXPECT_NO_FATAL_FAILURE(GetWifiDirectManager()->notifyPtkMismatch(remoteNetworkId.c_str(), len, reason));

    // Test with listener using a function pointer (no lambda capture)
    static bool ptkMismatchListenerCalled = false;
    ptkMismatchListenerCalled = false;
    auto testPtkMismatchListener = [](const char *networkId, uint32_t length, int32_t errReason) {
        ptkMismatchListenerCalled = true;
    };
    PtkMismatchListener listener = testPtkMismatchListener;
    GetWifiDirectManager()->addPtkMismatchListener(listener);
    EXPECT_NO_FATAL_FAILURE(GetWifiDirectManager()->notifyPtkMismatch(remoteNetworkId.c_str(), len, reason));
    EXPECT_EQ(ptkMismatchListenerCalled, true);
    // Guard automatically restores g_ptkMismatchListener on destruction
}

/*
 * @tc.name: NotifyHmlStateTest
 * @tc.desc: check NotifyHmlState method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, NotifyHmlStateTest, TestSize.Level1)
{
    SoftBusHmlState state = CONN_HML_ENABLED;
    // RAII guard ensures global listener is restored even if test fails
    HmlStateListenerGuard guard(g_hmlStateListener);

    // Test with no listener
    EXPECT_NO_FATAL_FAILURE(GetWifiDirectManager()->notifyHmlState(state));

    // Test with listener using a function pointer (no lambda capture)
    static bool hmlStateListenerCalled = false;
    hmlStateListenerCalled = false;
    auto testHmlStateListener = [](SoftBusHmlState hmlState) { hmlStateListenerCalled = true; };
    HmlStateListener listener = testHmlStateListener;
    GetWifiDirectManager()->addHmlStateListener(listener);
    EXPECT_NO_FATAL_FAILURE(GetWifiDirectManager()->notifyHmlState(state));
    EXPECT_EQ(hmlStateListenerCalled, true);
    // Guard automatically restores g_hmlStateListener on destruction
}

/*
 * @tc.name: IsNoneLinkByTypeTest
 * @tc.desc: check IsNoneLinkByType method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsNoneLinkByTypeTest, TestSize.Level1)
{
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);

    // Test with no HML links
    auto isNone = GetWifiDirectManager()->isNoneLinkByType(WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(isNone, true);

    // Test with HML link
    std::string uuid("0123456789ABCDEF");
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    isNone = GetWifiDirectManager()->isNoneLinkByType(WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(isNone, false);

    // Test with only P2P link (HML should be none)
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::P2P, uuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    isNone = GetWifiDirectManager()->isNoneLinkByType(WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(isNone, true);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
}

/*
 * @tc.name: RegisterStatusListenerTest
 * @tc.desc: check RegisterStatusListener method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, RegisterStatusListenerTest, TestSize.Level1)
{
    std::string remoteMac("10:dc:b6:90:84:82");
    std::string remoteIp("170.30.1.2");
    std::string remoteUuid("0123456789ABCDEF");
    bool isSource = true;

    // Use static flag to track listener invocation
    static bool statusListenerCalled = false;
    statusListenerCalled = false;
    // Use static storage to ensure listener pointer remains valid
    static struct WifiDirectStatusListener staticListener = {};

    // Configure the listener with the callback
    staticListener.onDeviceOnLine = [](const char *mac, const char *ip, const char *uuid, bool source) {
        statusListenerCalled = true;
    };

    GetWifiDirectManager()->registerStatusListener(&staticListener);
    EXPECT_NO_FATAL_FAILURE(
        GetWifiDirectManager()->notifyOnline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), isSource));
    EXPECT_EQ(statusListenerCalled, true);

    // Clean up: find and remove the listener by pointer comparison
    for (auto it = g_listeners.begin(); it != g_listeners.end(); ++it) {
        if (&(*it) == &staticListener) {
            g_listeners.erase(it);
            break;
        }
    }
}

/*
 * @tc.name: IsNegotiateChannelNeededWithNullNetworkIdTest
 * @tc.desc: check IsNegotiateChannelNeeded with null networkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsNegotiateChannelNeededWithNullNetworkIdTest, TestSize.Level1)
{
    auto ret = GetWifiDirectManager()->isNegotiateChannelNeeded(nullptr, WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: IsNegotiateChannelNeededWithGlassesLowPowerTest
 * @tc.desc: check IsNegotiateChannelNeeded with glasses scenario and low power
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsNegotiateChannelNeededWithGlassesLowPowerTest, TestSize.Level1)
{
    std::string remoteNetworkId("1234567890");
    char uuid[UUID_BUF_LEN] = "0123456789ABCDEF";
    std::string remoteMac("10:dc:b6:90:84:82");
    WifiDirectInterfaceMock mock;

    EXPECT_CALL(mock, LnnGetRemoteStrInfo(_, _, _, _))
        .WillRepeatedly([&uuid](const std::string &netWorkId, InfoKey key, char *info, uint32_t len) {
            if (strcpy_s(info, UUID_BUF_LEN, uuid) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            return SOFTBUS_OK;
        });

    // Test with glasses scenario and low power
    EXPECT_CALL(mock, LnnGetLocalNumInfo(_, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<1>(TYPE_GLASS_ID), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo(_, _, _))
        .WillRepeatedly(testing::DoAll(testing::SetArgPointee<2>(TYPE_PAD_ID), Return(SOFTBUS_OK)));

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteMac](InnerLink &link) {
        link.SetLinkPowerMode(LOW_POWER);
        link.SetRemoteBaseMac(remoteMac);
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });

    auto ret = GetWifiDirectManager()->isNegotiateChannelNeeded(remoteNetworkId.c_str(), WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_TRUE(ret);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: SavePtkWithNullParamTest
 * @tc.desc: check SavePtk with null parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, SavePtkWithNullParamTest, TestSize.Level1)
{
    std::string remoteDeviceId("123");
    std::string ptk("ptk");

    // Test with null remoteDeviceId
    auto ret = GetWifiDirectManager()->savePTK(nullptr, ptk.c_str());
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    // Test with null ptk
    ret = GetWifiDirectManager()->savePTK(remoteDeviceId.c_str(), nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    // Test with both null
    ret = GetWifiDirectManager()->savePTK(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: IsHmlConnectedTest
 * @tc.desc: check IsHmlConnected method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, IsHmlConnectedTest, TestSize.Level1)
{
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);

    // Test with no HML links
    auto isConnected = GetWifiDirectManager()->isHmlConnected();
    EXPECT_EQ(isConnected, false);

    // Test with HML link connected
    std::string uuid("0123456789ABCDEF");
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    isConnected = GetWifiDirectManager()->isHmlConnected();
    EXPECT_EQ(isConnected, true);

    // Test with only P2P link
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::P2P, uuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    isConnected = GetWifiDirectManager()->isHmlConnected();
    EXPECT_EQ(isConnected, false);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::P2P);
}

/*
 * @tc.name: ForceDisconnectDeviceSyncWithConnectedDeviceTest
 * @tc.desc: check ForceDisconnectDeviceSync with connected device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, ForceDisconnectDeviceSyncWithConnectedDeviceTest, TestSize.Level1)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ForceDisconnectDeviceSyncWithConnectedDeviceTest in");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetNetworkIdByUuid).WillRepeatedly(Return(SOFTBUS_OK));

    // Create a connected HML link
    std::string remoteUuid("0123456789ABCDEF");
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteUuid, [](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });

    // Force disconnect with connected device - verify it doesn't crash
    EXPECT_NO_FATAL_FAILURE(GetWifiDirectManager()->forceDisconnectDeviceSync(WIFI_DIRECT_LINK_TYPE_HML));

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    CONN_LOGI(CONN_WIFI_DIRECT, "ForceDisconnectDeviceSyncWithConnectedDeviceTest out");
}

/*
 * @tc.name: GetLocalAndRemoteMacByLocalIpWithIpv6Test
 * @tc.desc: check GetLocalAndRemoteMacByLocalIp with IPv6
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetLocalAndRemoteMacByLocalIpWithIpv6Test, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string localIpv6("fe80::200:22ff:fe6b:262d");
    constexpr int32_t macLen = 18;
    char localMac[macLen] = {0};
    char remoteMac[macLen] = {0};

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);

    // Test with IPv6 local address
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&localIpv6](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetLocalIpv6(localIpv6);
        link.SetLocalDynamicMac("aa:bb:cc:dd:ee:ff");
        link.SetRemoteDynamicMac("11:22:33:44:55:66");
    });

    auto ret = GetLocalAndRemoteMacByLocalIp(localIpv6.c_str(), localMac, macLen, remoteMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: GetRemoteUuidByIpWithIpv6Test
 * @tc.desc: check GetRemoteUuidByIp with IPv6
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, GetRemoteUuidByIpWithIpv6Test, TestSize.Level1)
{
    std::string uuid("0123456789ABCDE9");
    std::string remoteIpv6("fe80::a446:b4ff:fec1:7323");
    char resultUuid[UUID_BUF_LEN] = { 0 };

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);

    // Test with IPv6 address
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, uuid, [&remoteIpv6](InnerLink &link) {
        link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
        link.SetRemoteIpv6(remoteIpv6);
    });

    auto ret = GetRemoteUuidByIp(remoteIpv6.c_str(), resultUuid, sizeof(resultUuid));
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(resultUuid, uuid.c_str());

    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}

/*
 * @tc.name: AddSyncPtkListenerTest
 * @tc.desc: check AddSyncPtkListener method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, AddSyncPtkListenerTest, TestSize.Level1)
{
    std::string remoteDeviceId("0123456789ABCDEF");
    int32_t result = 0;
    // RAII guard ensures global listener is restored even if test fails
    SyncPtkListenerGuard guard(g_syncPtkListener);

    // Test with no listener
    EXPECT_NO_FATAL_FAILURE(NotifyPtkSyncResult(remoteDeviceId.c_str(), result));

    // Test with listener
    static bool syncPtkListenerCalled = false;
    syncPtkListenerCalled = false;
    SyncPtkListener listener = [](const char *deviceId, int32_t res) { syncPtkListenerCalled = true; };
    GetWifiDirectManager()->addSyncPtkListener(listener);
    EXPECT_NO_FATAL_FAILURE(NotifyPtkSyncResult(remoteDeviceId.c_str(), result));
    EXPECT_EQ(syncPtkListenerCalled, true);
}
} // namespace OHOS::SoftBus
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
 * @tc.name: SetElementTypeTest
 * @tc.desc: check SetElementType method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WifiDirectManagerCppTest, SetElementTypeTest, TestSize.Level1)
{
    struct WifiDirectConnectInfo info = { 0 };
    ConnEventExtra extra = { 0 };
    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P;
    info.negoChannel.type = NEGO_CHANNEL_AUTH;
    SetElementTypeExtra(&info, &extra);
    EXPECT_EQ(info.dfxInfo.linkType, STATISTIC_P2P);
    EXPECT_EQ(info.dfxInfo.bootLinkType, STATISTIC_NONE);

    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_HML;
    info.negoChannel.type = NEGO_CHANNEL_COC;
    SetElementTypeExtra(&info, &extra);
    EXPECT_EQ(info.dfxInfo.linkType, STATISTIC_HML);
    EXPECT_EQ(info.dfxInfo.bootLinkType, STATISTIC_COC);

    info.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    info.negoChannel.type = NEGO_CHANNEL_NULL;
    SetElementTypeExtra(&info, &extra);
    EXPECT_EQ(info.dfxInfo.linkType, STATISTIC_TRIGGER_HML);
    EXPECT_EQ(info.dfxInfo.bootLinkType, STATISTIC_NONE);

    info.connectType = WIFI_DIRECT_CONNECT_TYPE_AUTH_TRIGGER_HML;
    info.dfxInfo.linkType = STATISTIC_P2P;
    SetElementTypeExtra(&info, &extra);
    EXPECT_EQ(info.dfxInfo.linkType, STATISTIC_TRIGGER_HML);
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

    struct WifiDirectStatusListener listener2 = {
        .onDeviceOnLine = [](const char *remoteMac, const char *remoteIp, const char *remoteUuid, bool isSource) {},
        .onDeviceOffLine = [](const char *remoteMac, const char *remoteIp, const char *remoteUuid,
                               const char *localIp) {},
        .onLocalRoleChange = [](enum WifiDirectRole oldRole, enum WifiDirectRole newRole) {},
        .onConnectedForSink = [](const struct WifiDirectSinkLink *link) {},
        .onDisconnectedForSink = [](const struct WifiDirectSinkLink *link) {},
    };
    g_listeners.push_back(listener2);
    EXPECT_NO_FATAL_FAILURE(NotifyOnline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), isSource));

    EXPECT_NO_FATAL_FAILURE(NotifyOffline(remoteMac.c_str(), remoteIp.c_str(), remoteUuid.c_str(), localIp.c_str()));

    EXPECT_NO_FATAL_FAILURE(NotifyRoleChange(WIFI_DIRECT_ROLE_GO, WIFI_DIRECT_ROLE_GC));

    EXPECT_NO_FATAL_FAILURE(NotifyConnectedForSink(&sinkLink));

    EXPECT_NO_FATAL_FAILURE(NotifyDisconnectedForSink(&sinkLink));
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
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 enter");
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
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 exit");
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
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest002 enter");
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
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest002 exit");
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
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 enter");
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
    auto result = ForceDisconnectDeviceSync(WIFI_DIRECT_LINK_TYPE_HML);
    EXPECT_EQ(result, SOFTBUS_OK);
    CONN_LOGI(CONN_WIFI_DIRECT, "RefreshRelationShipTest001 exit");
}

} // namespace OHOS::SoftBus
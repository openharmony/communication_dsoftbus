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

#include <gtest/gtest.h>
#include <set>
#include "data/link_manager.h"

using namespace testing::ext;

namespace OHOS::SoftBus {
class LinkManagerTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/*
 * @tc.name: AllocateLinkId
 * @tc.desc: check AllocateLinkId method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, AllocateLinkId, TestSize.Level1)
{
    std::set<int> ids;
    for (int32_t i = 0; i < 100; ++i) {
        auto id = LinkManager::GetInstance().AllocateLinkId();
        EXPECT_TRUE(ids.find(id) == ids.end());
        ids.insert(id);
    }
}

/*
 * @tc.name: ProcessIfXXXByRemoteDeviceId
 * @tc.desc: check ProcessIfAbsent and ProcessIfPresent by remote device id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, ProcessIfXXXByRemoteDeviceId, TestSize.Level1)
{
    std::string remoteDeviceId("7001005458323933328a013ce3153800");

    auto result = LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::HML, remoteDeviceId, [](InnerLink &innerLink) {});
    EXPECT_FALSE(result);

    result = LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, remoteDeviceId, [remoteDeviceId](InnerLink &innerLink) {
            innerLink.SetRemoteDeviceId(remoteDeviceId);
        });
    EXPECT_TRUE(result);

    result = LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::HML, remoteDeviceId, [](InnerLink &innerLink) {});
    EXPECT_TRUE(result);

    auto innerLink = LinkManager::GetInstance().GetReuseLink(WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML, remoteDeviceId);
    EXPECT_EQ(innerLink, nullptr);

    LinkManager::GetInstance().RemoveLink(InnerLink::LinkType::HML, remoteDeviceId);
    result = LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::HML, remoteDeviceId, [](InnerLink &innerLink) {});
    EXPECT_FALSE(result);

    innerLink = LinkManager::GetInstance().GetReuseLink(WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML, remoteDeviceId);
    EXPECT_EQ(innerLink, nullptr);
}

/*
 * @tc.name: ProcessIfXXXByRemoteMac
 * @tc.desc: check ProcessIfAbsent and ProcessIfPresent by remote mac
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, ProcessIfXXXByRemoteMac, TestSize.Level1)
{
    std::string remoteMac("11:22:33:44:55:66");
    bool result = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [](InnerLink &innerLink) {});
    EXPECT_FALSE(result);

    result = LinkManager::GetInstance().ProcessIfAbsent(remoteMac, [remoteMac](InnerLink &innerLink) {
        innerLink.SetRemoteBaseMac(remoteMac);
    });
    EXPECT_TRUE(result);
    result = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [](InnerLink &innerLink) {});
    EXPECT_TRUE(result);

    WifiDirectLink link {};
    result = LinkManager::GetInstance().ProcessIfPresent(link.linkId, [](InnerLink &innerLink) {});
    EXPECT_FALSE(result);
    auto innerLink = LinkManager::GetInstance().GetLinkById(link.linkId);
    EXPECT_EQ(innerLink, nullptr);
    LinkManager::GetInstance().ProcessIfPresent(link.linkId, [link](InnerLink &innerLink) {
        innerLink.RemoveId(link.linkId);
    });
    innerLink = LinkManager::GetInstance().GetLinkById(link.linkId);
    EXPECT_EQ(innerLink, nullptr);
}

/*
 * @tc.name: AllocateLinkIdTest
 * @tc.desc: test method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, AllocateLinkIdTest, TestSize.Level1)
{
    LinkManager linkManager;
    linkManager.currentLinkId_ = -1;
    int32_t newId = linkManager.AllocateLinkId();
    EXPECT_EQ(newId, 0);
    linkManager.currentLinkId_ = 1;
    newId = linkManager.AllocateLinkId();
    ASSERT_EQ(newId, 1);
}

/*
 * @tc.name: GetAllLinksBasicInfo
 * @tc.desc: test GetAllLinksBasicInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, GetAllLinksBasicInfo, TestSize.Level1)
{
    LinkManager linkManager;
    std::string remoteDeviceId("C86C******58BC");
    int32_t result = LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::HML, remoteDeviceId, [remoteDeviceId](InnerLink &innerLink) {
            innerLink.SetRemoteDeviceId(remoteDeviceId);
        });
    std::vector<InnerLinkBasicInfo> infos;
    linkManager.GetAllLinksBasicInfo(infos);
    EXPECT_NE(result, false);
}

/*
 * @tc.name: GetReuseLink
 * @tc.desc: test GetReuseLink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, GetReuseLink, TestSize.Level1)
{
    LinkManager linkManager;
    std::string remoteMac("127.0.0.93");
    auto reuseResult = linkManager.GetReuseLink(remoteMac);
    EXPECT_EQ(reuseResult, nullptr);

    int32_t result = LinkManager::GetInstance().ProcessIfAbsent(remoteMac, [remoteMac](InnerLink &innerLink) {
        innerLink.SetRemoteBaseMac(remoteMac);
    });
    EXPECT_NE(result, false);
    reuseResult = linkManager.GetReuseLink(remoteMac);
    EXPECT_EQ(reuseResult, nullptr);
}

/*
 * @tc.name: RefreshRelationShip
 * @tc.desc: test RefreshRelationShip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, RefreshRelationShip, TestSize.Level1)
{
    LinkManager linkManager;
    std::string remoteDeviceId("C86C******58BC");
    std::string remoteMac("127.0.0.93");
    linkManager.RefreshRelationShip(remoteDeviceId, remoteMac);

    int32_t result = LinkManager::GetInstance().ProcessIfAbsent(remoteMac, [remoteMac](InnerLink &innerLink) {
        innerLink.SetLinkType(InnerLink::LinkType::HML);
        innerLink.SetRemoteBaseMac(remoteMac);
    });
    linkManager.RefreshRelationShip(remoteDeviceId, remoteMac);
    linkManager.Dump();
    EXPECT_NE(result, false);
}

/*
 * @tc.name: RemoveLinks
 * @tc.desc: test RemoveLinks --true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LinkManagerTest, RemoveLinks, TestSize.Level1)
{
    std::string remoteDeviceId1("0123456789ABCDEF");
    std::string remoteMac1("11:11:**:**:11:11");
    std::string remoteDeviceId2("0223456789ABCDEF");
    std::string remoteMac2("22:22:**:**:22:22");
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteDeviceId1,
        [&remoteMac1](InnerLink &link) {
            link.SetRemoteBaseMac(remoteMac1);
            link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    });
    LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::HML, remoteDeviceId2,
        [&remoteMac2](InnerLink &link) {
            link.SetRemoteBaseMac(remoteMac2);
            link.SetState(OHOS::SoftBus::InnerLink::LinkState::CONNECTING);
    });

    InnerLink::LinkState innerlinkState;
    auto result = LinkManager::GetInstance().ProcessIfPresent(remoteMac1,
        [&innerlinkState] (InnerLink &innerLink) {
            innerlinkState = innerLink.GetState();
        });
    EXPECT_TRUE(result);
    EXPECT_EQ(innerlinkState, OHOS::SoftBus::InnerLink::LinkState::CONNECTED);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML, true);
    result = LinkManager::GetInstance().ProcessIfPresent(remoteMac1, [] (InnerLink &innerLink) {});
    EXPECT_FALSE(result);
    result = LinkManager::GetInstance().ProcessIfPresent(remoteMac2,
        [&innerlinkState] (InnerLink &innerLink) {
            innerlinkState = innerLink.GetState();
        });
    EXPECT_TRUE(result);
    EXPECT_EQ(innerlinkState, OHOS::SoftBus::InnerLink::LinkState::CONNECTING);
    LinkManager::GetInstance().RemoveLinks(InnerLink::LinkType::HML);
}
} // namespace OHOS::SoftBus
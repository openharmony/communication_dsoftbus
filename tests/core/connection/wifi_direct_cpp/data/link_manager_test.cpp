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
#include <set>

#include <gtest/gtest.h>

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
    for (int i = 0; i < 100; ++i) {
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
    EXPECT_NE(innerLink, nullptr);

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
    std::string localIp("192.168.0.1");
    std::string remoteIp("192.168.0.2");
    LinkManager::GetInstance().ProcessIfPresent(remoteMac, [localIp, remoteIp, &link](InnerLink &innerLink) {
        innerLink.SetLocalIpv4(localIp);
        innerLink.SetRemoteIpv4(remoteIp);
        innerLink.SetLinkType(InnerLink::LinkType::HML);

        innerLink.GenerateLink(888, 666, link);
    });
    EXPECT_NE(link.linkId, 0);
    EXPECT_EQ(link.localIp, localIp);
    EXPECT_EQ(link.remoteIp, remoteIp);
    EXPECT_EQ(link.linkType, WIFI_DIRECT_LINK_TYPE_HML);

    result = LinkManager::GetInstance().ProcessIfPresent(link.linkId, [](InnerLink &innerLink) {});
    EXPECT_TRUE(result);

    auto innerLink = LinkManager::GetInstance().GetLinkById(link.linkId);
    EXPECT_NE(innerLink, nullptr);

    LinkManager::GetInstance().ProcessIfPresent(link.linkId, [link](InnerLink &innerLink) {
        innerLink.RemoveId(link.linkId);
    });
    innerLink = LinkManager::GetInstance().GetLinkById(link.linkId);
    EXPECT_EQ(innerLink, nullptr);
}

} // namespace OHOS::SoftBus
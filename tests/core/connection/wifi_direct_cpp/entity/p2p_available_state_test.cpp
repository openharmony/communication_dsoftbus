/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <cstring>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>

#include "entity/p2p_entity.h"
#include "data/interface_manager.h"
#include "entity/p2p_available_state.h"
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
OHOS::SoftBus::P2pAvailableState *g_p2pAvailableStateInstance;
namespace OHOS::SoftBus {
class P2pAvailableStateTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_p2pAvailableStateInstance = P2pAvailableState::Instance();
        ASSERT_TRUE(g_p2pAvailableStateInstance != nullptr);
    }
    static void TearDownTestCase()
    {
        g_p2pAvailableStateInstance = nullptr;
    }
    void SetUp() override {}
    void TearDown() override {}
    void InjectData();
};

void P2pAvailableStateTest::InjectData()
{
    P2pEntity::GetInstance().NotifyNewClientJoining("00:01:01:01:02:02");
    EXPECT_TRUE(P2pEntity::GetInstance().GetJoiningClientCount() >= 0);
}

/*
* @tc.name: GetName
* @tc.desc: check GetName
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAvailableStateTest, GetName, TestSize.Level1)
{
    g_p2pAvailableStateInstance->OnP2pStateChangeEvent(P2P_STATE_STARTED);
    std::string name = g_p2pAvailableStateInstance->GetName();
    EXPECT_EQ(name, "P2pAvailableState");
}

/*
* @tc.name: OnP2pConnectionChangeEvent001
* @tc.desc: check group info param is null in OnP2pConnectionChangeEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAvailableStateTest, OnP2pConnectionChangeEvent001, TestSize.Level1)
{
    P2pAvailableStateTest::InjectData();
    WifiP2pLinkedInfo info;
    g_p2pAvailableStateInstance->OnP2pConnectionChangeEvent(info, nullptr);
    EXPECT_TRUE(P2pEntity::GetInstance().GetJoiningClientCount() == 0);
}

/*
* @tc.name: OnP2pConnectionChangeEvent001
* @tc.desc: check group owner is false in OnP2pConnectionChangeEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAvailableStateTest, OnP2pConnectionChangeEvent002, TestSize.Level1)
{
    WifiP2pLinkedInfo info;
    P2pAdapter::WifiDirectP2pGroupInfo groupInfo;
    groupInfo.isGroupOwner = false;
    std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> pGroupInfo =
        std::make_shared<P2pAdapter::WifiDirectP2pGroupInfo>(groupInfo);
    P2pAvailableStateTest::InjectData();
    g_p2pAvailableStateInstance->OnP2pConnectionChangeEvent(info, pGroupInfo);
    EXPECT_TRUE(P2pEntity::GetInstance().GetJoiningClientCount() >= 0);
}

/*
* @tc.name: OnP2pConnectionChangeEvent001
* @tc.desc: check group owner is true in OnP2pConnectionChangeEvent
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pAvailableStateTest, OnP2pConnectionChangeEvent003, TestSize.Level1)
{
    InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::InterfaceType::P2P,
        [](InterfaceInfo &info) {
            info. SetReuseCount(1);
            return SOFTBUS_OK;
        });

    WifiDirectInterfaceMock mock;
    WifiP2pLinkedInfo info;
    P2pAdapter::WifiDirectP2pGroupInfo groupInfo;
    groupInfo.isGroupOwner = true;
    P2pEntity::GetInstance().ClearJoiningClient();
    std::shared_ptr<P2pAdapter::WifiDirectP2pGroupInfo> pGroupInfo =
        std::make_shared<P2pAdapter::WifiDirectP2pGroupInfo>(groupInfo);
    EXPECT_CALL(mock, Hid2dSharedlinkDecrease).Times(1).WillOnce(Return(WIFI_SUCCESS));
    g_p2pAvailableStateInstance->OnP2pConnectionChangeEvent(info, pGroupInfo);
}
}

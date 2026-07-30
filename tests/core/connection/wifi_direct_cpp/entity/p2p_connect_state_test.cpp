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
#define private   public
#include "entity/p2p_connect_state.h"
#undef private
#include "wifi_direct_mock.h"

using namespace testing::ext;
using namespace testing;
using ::testing::_;
using ::testing::Invoke;
OHOS::SoftBus::P2pConnectState *g_p2pConnectStateInstance;
namespace OHOS::SoftBus {
class P2pConnectStateTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_p2pConnectStateInstance = P2pConnectState::Instance();
        ASSERT_TRUE(g_p2pConnectStateInstance != nullptr);
    }
    static void TearDownTestCase()
    {
        g_p2pConnectStateInstance->Exit();
        g_p2pConnectStateInstance = nullptr;
    }
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: ConnectStateTest
* @tc.desc: check ConnectState
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pConnectStateTest, ConnectStateTest, TestSize.Level1)
{
    P2pConnectParam connectParam{"test", true, true, "test"};
    WifiP2pLinkedInfo info{};
    WifiDirectInterfaceMock mock;
    EXPECT_CALL(mock, GetCurrentGroup(_)).WillRepeatedly(Return(WIFI_SUCCESS));
    g_p2pConnectStateInstance->OnP2pConnectionChangeEvent(info, nullptr);
    g_p2pConnectStateInstance->OnTimeout();

    info.connectState = P2pConnectionState::P2P_CONNECTED;
    auto connectOp =
        std::make_shared<P2pOperationWrapper<P2pConnectParam>>(connectParam, P2pOperationType::CONNECT);
    g_p2pConnectStateInstance->Enter(connectOp);

    auto operation =
        std::dynamic_pointer_cast<P2pOperationWrapper<P2pConnectParam>>(g_p2pConnectStateInstance->operation_);
    g_p2pConnectStateInstance->PreprocessP2pConnectionChangeEvent(info, nullptr);
    operation->content_.isNeedDhcp = false;
    g_p2pConnectStateInstance->PreprocessP2pConnectionChangeEvent(info, nullptr);
    P2pEntity::GetInstance().ClearPendingOperation();
    bool ret = P2pEntity::GetInstance().HasPendingOperation();
    EXPECT_EQ(ret, false);
}
}
